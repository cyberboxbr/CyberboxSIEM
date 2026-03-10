param(
  [string]$ApiBase = "http://127.0.0.1:8080",
  [int]$DurationSeconds = 120,
  [string[]]$ConcurrencyLevels = @("24", "32", "48", "64"),
  [int]$BatchSize = 100,
  [string]$TenantId = "tenant-a",
  [string]$UserId = "soc-admin",
  [int]$CooldownSeconds = 15,
  [int]$MaxConcurrencyPerRun = 4096,
  [switch]$SkipPersistenceCheck
)

$ErrorActionPreference = "Stop"

if ($DurationSeconds -lt 1) {
  throw "DurationSeconds must be >= 1"
}
if ($BatchSize -lt 1) {
  throw "BatchSize must be >= 1"
}
if ($CooldownSeconds -lt 0) {
  throw "CooldownSeconds must be >= 0"
}
function Parse-ConcurrencyLevels {
  param(
    [string[]]$RawLevels,
    [int]$MaxAllowed
  )

  if (-not $RawLevels -or $RawLevels.Count -eq 0) {
    throw "ConcurrencyLevels must contain at least one value"
  }
  if ($MaxAllowed -lt 1) {
    throw "MaxConcurrencyPerRun must be >= 1"
  }

  $parsedLevels = New-Object System.Collections.Generic.List[int]
  foreach ($raw in $RawLevels) {
    if ($null -eq $raw) { continue }
    foreach ($token in ($raw -split '[,\s;]+')) {
      $trimmed = $token.Trim()
      if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

      $parsed = 0
      $ok = [int]::TryParse(
        $trimmed,
        [System.Globalization.NumberStyles]::Integer,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$parsed
      )
      if (-not $ok) {
        throw "Invalid concurrency value '$trimmed'. Use integers like 24 32 48 64."
      }
      if ($parsed -lt 1) {
        throw "All ConcurrencyLevels values must be >= 1"
      }
      if ($parsed -gt $MaxAllowed) {
        throw "Concurrency level $parsed exceeds MaxConcurrencyPerRun ($MaxAllowed)."
      }
      $parsedLevels.Add($parsed)
    }
  }

  if ($parsedLevels.Count -eq 0) {
    throw "No valid concurrency levels were parsed."
  }

  return @($parsedLevels)
}

function Resolve-CargoCommand {
  $command = Get-Command cargo -ErrorAction SilentlyContinue
  if ($null -ne $command) {
    return $command.Source
  }

  if ($env:USERPROFILE) {
    $fallback = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
    if (Test-Path $fallback) {
      return $fallback
    }
  }

  if ($env:HOME) {
    $fallback = Join-Path $env:HOME ".cargo/bin/cargo"
    if (Test-Path $fallback) {
      return $fallback
    }
  }

  throw "cargo command not found. Install Rust toolchain or add cargo to PATH."
}

function Round-Nullable {
  param(
    [object]$Value,
    [int]$Digits = 4
  )
  if ($null -eq $Value) {
    return $null
  }
  return [Math]::Round([double]$Value, $Digits)
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $repoRoot

try {
  $parsedConcurrencyLevels = Parse-ConcurrencyLevels -RawLevels $ConcurrencyLevels -MaxAllowed $MaxConcurrencyPerRun

  $healthHeaders = @{
    "x-tenant-id" = $TenantId
    "x-user-id" = $UserId
    "x-roles" = "admin,analyst,viewer,ingestor"
  }
  $health = Invoke-RestMethod -Method "GET" -Uri "$ApiBase/healthz" -Headers $healthHeaders
  if ($health.status -ne "ok") {
    throw "API health check failed: $($health | ConvertTo-Json -Depth 10)"
  }

  $cargoCommand = Resolve-CargoCommand
  $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
  $outputDir = Join-Path $repoRoot "logs/load-max-eps-$timestamp"
  New-Item -Path $outputDir -ItemType Directory -Force | Out-Null

  $results = New-Object System.Collections.Generic.List[object]
  $runIndex = 0
  $totalRuns = $parsedConcurrencyLevels.Count

  foreach ($concurrency in $parsedConcurrencyLevels) {
    $runIndex += 1
    $reportPath = Join-Path $outputDir ("max-c{0}-b{1}.json" -f $concurrency, $BatchSize)

    Write-Output ("[{0}/{1}] starting max-throughput run: concurrency={2} batch={3} duration={4}s" -f `
      $runIndex, $totalRuns, $concurrency, $BatchSize, $DurationSeconds)

    $cargoArgs = @(
      "run", "--release", "-p", "cyberbox-loadgen", "--",
      "--api-base", $ApiBase,
      "--duration-seconds", "$DurationSeconds",
      "--concurrency", "$concurrency",
      "--batch-size", "$BatchSize",
      "--tenant-id", $TenantId,
      "--user-id", $UserId,
      "--report-path", $reportPath
    )
    if ($SkipPersistenceCheck.IsPresent) {
      $cargoArgs += "--skip-persist-check"
    }

    & $cargoCommand @cargoArgs
    if ($LASTEXITCODE -ne 0) {
      throw ("cyberbox-loadgen failed for concurrency={0} with exit code {1}" -f $concurrency, $LASTEXITCODE)
    }

    if (-not (Test-Path $reportPath)) {
      throw "expected load report not found at $reportPath"
    }

    $report = Get-Content -Path $reportPath -Raw | ConvertFrom-Json
    $result = [PSCustomObject]@{
      run_index = $runIndex
      concurrency = [int]$concurrency
      batch_size = [int]$BatchSize
      duration_seconds = [int]$DurationSeconds
      accepted_eps = Round-Nullable -Value $report.accepted_eps_target_window -Digits 2
      attempted_eps = Round-Nullable -Value $report.attempted_eps_target_window -Digits 2
      rejected_eps = Round-Nullable -Value $report.rejected_eps_target_window -Digits 2
      api_rejection_loss_pct = Round-Nullable -Value $report.api_rejection_loss_pct -Digits 4
      request_latency_p95_ms = Round-Nullable -Value $report.request_latency_p95_ms -Digits 2
      request_latency_p99_ms = Round-Nullable -Value $report.request_latency_p99_ms -Digits 2
      persisted_events = $report.persisted_events
      persisted_loss_pct_vs_accepted = Round-Nullable -Value $report.persisted_loss_pct_vs_accepted -Digits 4
      report_path = $reportPath
    }
    $results.Add($result)

    if ($runIndex -lt $totalRuns -and $CooldownSeconds -gt 0) {
      Start-Sleep -Seconds $CooldownSeconds
    }
  }

  $sorted = @($results | Sort-Object `
      @{ Expression = { [double]$_.accepted_eps }; Descending = $true }, `
      @{ Expression = { [double]$_.api_rejection_loss_pct }; Descending = $false })
  $bestOverall = $sorted | Select-Object -First 1
  $bestClean = @($sorted | Where-Object { [double]$_.api_rejection_loss_pct -le 0.5 }) | Select-Object -First 1

  $summary = [ordered]@{
    run_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    api_base = $ApiBase
    duration_seconds = $DurationSeconds
    batch_size = $BatchSize
    skip_persistence_check = $SkipPersistenceCheck.IsPresent
    best_overall = $bestOverall
    best_clean = $bestClean
    results = $results
  }

  $summaryPath = Join-Path $outputDir "summary.json"
  $summary | ConvertTo-Json -Depth 20 | Set-Content -Path $summaryPath -Encoding utf8

  Write-Output "Max EPS sweep summary written to $summaryPath"
  $results | Format-Table -AutoSize | Out-String | Write-Output
}
finally {
  Pop-Location
}
