param(
  [string]$ApiBase = "http://127.0.0.1:8080",
  [int]$DurationSeconds = 60,
  [int]$Concurrency = 12,
  [int]$BatchSize = 100,
  [string]$TenantId = "tenant-a",
  [string]$UserId = "soc-admin",
  [switch]$SkipPersistenceCheck
)

$ErrorActionPreference = "Stop"

$healthHeaders = @{
  "x-tenant-id" = $TenantId
  "x-user-id" = $UserId
  "x-roles" = "admin,analyst,viewer,ingestor"
}
$jsonHeaders = @{
  "content-type" = "application/json"
  "x-tenant-id" = $TenantId
  "x-user-id" = $UserId
  "x-roles" = "admin,analyst,viewer,ingestor"
}

function Get-P95 {
  param([double[]]$Values)
  if (-not $Values -or $Values.Count -eq 0) {
    return 0.0
  }
  $sorted = $Values | Sort-Object
  $index = [Math]::Ceiling($sorted.Count * 0.95) - 1
  if ($index -lt 0) { $index = 0 }
  if ($index -ge $sorted.Count) { $index = $sorted.Count - 1 }
  return [double]$sorted[$index]
}

function Invoke-Json {
  param(
    [string]$Method,
    [string]$Path,
    [hashtable]$Headers,
    $Body
  )

  $uri = "$ApiBase$Path"
  if ($PSBoundParameters.ContainsKey("Body") -and -not [string]::IsNullOrEmpty([string]$Body)) {
    return Invoke-RestMethod -Method $Method -Uri $uri -Headers $Headers -Body $Body
  }
  return Invoke-RestMethod -Method $Method -Uri $uri -Headers $Headers
}

function New-EventBatchJson {
  param(
    [int]$WorkerId,
    [string]$RunId,
    [int]$Count
  )

  $events = New-Object System.Collections.Generic.List[object]
  for ($i = 0; $i -lt $Count; $i++) {
    $nonce = [Guid]::NewGuid().ToString("N")
    $events.Add(@{
        tenant_id = $TenantId
        source = "windows_sysmon"
        event_time = (Get-Date).ToUniversalTime().ToString("o")
        raw_payload = @{
          event_code = 1
          process_name = "powershell.exe"
          cmdline = "powershell -enc load-eps-$nonce"
          message = "load-eps-run=$RunId worker=$WorkerId nonce=$nonce"
          run_id = $RunId
          worker_id = $WorkerId
          nonce = $nonce
        }
      })
  }

  return @{ events = $events } | ConvertTo-Json -Depth 8 -Compress
}

function Get-PersistedCount {
  param(
    [string]$RunId,
    [datetime]$StartUtc
  )

  $startIso = $StartUtc.AddMinutes(-1).ToUniversalTime().ToString("o")
  $endIso = (Get-Date).ToUniversalTime().AddMinutes(2).ToString("o")
  $sql = "SELECT uniqExact(event_id) AS unique_events FROM events_hot WHERE position(raw_payload, '$RunId') > 0"
  $body = @{
    tenant_id = $TenantId
    sql = $sql
    time_range = @{
      start = $startIso
      end = $endIso
    }
    filters = @()
    pagination = @{
      page = 1
      page_size = 1
    }
  } | ConvertTo-Json -Depth 8 -Compress

  $response = Invoke-Json -Method "POST" -Path "/api/v1/search:query" -Headers $jsonHeaders -Body $body
  if ($null -ne $response.rows -and $response.rows.Count -gt 0 -and $null -ne $response.rows[0].unique_events) {
    return [long]$response.rows[0].unique_events
  }
  return [long]$response.total
}

# API health check
$health = Invoke-Json -Method "GET" -Path "/healthz" -Headers $healthHeaders
if ($health.status -ne "ok") {
  throw "API health check failed: $($health | ConvertTo-Json -Depth 5)"
}

$runId = "eps-$([Guid]::NewGuid().ToString('N').Substring(0, 12))"
$jobs = @()
$startUtc = (Get-Date).ToUniversalTime()
$wallClock = [System.Diagnostics.Stopwatch]::StartNew()

for ($worker = 0; $worker -lt $Concurrency; $worker++) {
  $workerId = $worker
  $jobs += Start-Job -ScriptBlock {
    param($WorkerId, $DurationSec, $BatchSz, $RunMarker, $ApiRoot, $Headers, $Tenant)

    $local = New-Object System.Collections.Generic.List[object]
    $endAt = (Get-Date).ToUniversalTime().AddSeconds($DurationSec)
    while ((Get-Date).ToUniversalTime() -lt $endAt) {
      $requestStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
      try {
        $events = New-Object System.Collections.Generic.List[object]
        for ($index = 0; $index -lt $BatchSz; $index++) {
          $nonce = [Guid]::NewGuid().ToString("N")
          $events.Add(@{
              tenant_id = $Tenant
              source = "windows_sysmon"
              event_time = (Get-Date).ToUniversalTime().ToString("o")
              raw_payload = @{
                event_code = 1
                process_name = "powershell.exe"
                cmdline = "powershell -enc load-eps-$nonce"
                message = "load-eps-run=$RunMarker worker=$WorkerId nonce=$nonce"
                run_id = $RunMarker
                worker_id = $WorkerId
                nonce = $nonce
              }
            })
        }
        $jsonBody = @{ events = $events } | ConvertTo-Json -Depth 8 -Compress
        $response = Invoke-RestMethod -Method "POST" -Uri "$ApiRoot/api/v1/events:ingest" -Headers $Headers -Body $jsonBody
        $requestStopwatch.Stop()
        $local.Add([PSCustomObject]@{
            status = "ok"
            http_status = 200
            latency_ms = [double]$requestStopwatch.Elapsed.TotalMilliseconds
            accepted = [long]$response.accepted
            rejected = [long]$response.rejected
            error = $null
          })
      }
      catch {
        $requestStopwatch.Stop()
        $statusCode = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
          $statusCode = [int]$_.Exception.Response.StatusCode
        }
        $local.Add([PSCustomObject]@{
            status = "error"
            http_status = $statusCode
            latency_ms = [double]$requestStopwatch.Elapsed.TotalMilliseconds
            accepted = [long]0
            rejected = [long]$BatchSz
            error = $_.Exception.Message
          })
      }
    }

    return $local
  } -ArgumentList @($workerId, $DurationSeconds, $BatchSize, $runId, $ApiBase, $jsonHeaders, $TenantId)
}

Wait-Job -Job $jobs | Out-Null
$wallClock.Stop()
$items = @()
foreach ($job in $jobs) {
  $items += Receive-Job -Job $job
}
Remove-Job -Job $jobs -Force
$totalRequests = [long]$items.Count
$successRequests = [long]($items | Where-Object { $_.status -eq "ok" }).Count
$errorRequests = [long]($items | Where-Object { $_.status -eq "error" }).Count
$http429Requests = [long]($items | Where-Object { $_.http_status -eq 429 }).Count
$http5xxRequests = [long]($items | Where-Object { $_.http_status -ge 500 -and $_.http_status -lt 600 }).Count
$accepted = [long](($items | Measure-Object -Property accepted -Sum).Sum)
$rejected = [long](($items | Measure-Object -Property rejected -Sum).Sum)
$totalAttempted = $accepted + $rejected
$latencyValues = @($items | ForEach-Object { [double]$_.latency_ms })
$p95RequestLatencyMs = [Math]::Round((Get-P95 -Values $latencyValues), 2)
$elapsedSeconds = [Math]::Max(0.001, [double]$wallClock.Elapsed.TotalSeconds)
$attemptedEps = [Math]::Round($totalAttempted / $elapsedSeconds, 2)
$acceptedEps = [Math]::Round($accepted / $elapsedSeconds, 2)
$rejectedEps = [Math]::Round($rejected / $elapsedSeconds, 2)
$targetWindowSeconds = [Math]::Max(0.001, [double]$DurationSeconds)
$attemptedEpsTargetWindow = [Math]::Round($totalAttempted / $targetWindowSeconds, 2)
$acceptedEpsTargetWindow = [Math]::Round($accepted / $targetWindowSeconds, 2)
$rejectedEpsTargetWindow = [Math]::Round($rejected / $targetWindowSeconds, 2)
$apiLossRatePct = if ($totalAttempted -gt 0) {
  [Math]::Round((100.0 * $rejected / $totalAttempted), 4)
}
else { 0.0 }

$persistedCount = $null
$persistedLossPct = $null
$persistenceAttempts = @()
if (-not $SkipPersistenceCheck.IsPresent) {
  for ($retry = 0; $retry -lt 15; $retry++) {
    try {
      $count = Get-PersistedCount -RunId $runId -StartUtc $startUtc
      $persistedCount = [long]$count
      $persistenceAttempts += $count
      if ($accepted -eq 0 -or $count -ge $accepted) {
        break
      }
    }
    catch {
      $persistenceAttempts += -1
    }
    Start-Sleep -Seconds 2
  }

  if ($null -ne $persistedCount -and $accepted -gt 0) {
    $persistedLossPct = [Math]::Round((100.0 * [Math]::Max(0, ($accepted - $persistedCount)) / $accepted), 4)
  }
}

$errors = @($items | Where-Object { $_.status -eq "error" } | Select-Object -First 10 -ExpandProperty error)
$report = [PSCustomObject]@{
  run_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  api_base = $ApiBase
  run_id = $runId
  duration_seconds = $DurationSeconds
  concurrency = $Concurrency
  batch_size = $BatchSize
  elapsed_seconds = [Math]::Round($elapsedSeconds, 3)
  requests_total = $totalRequests
  requests_success = $successRequests
  requests_error = $errorRequests
  requests_http_429 = $http429Requests
  requests_http_5xx = $http5xxRequests
  events_attempted = $totalAttempted
  events_accepted = $accepted
  events_rejected = $rejected
  attempted_eps = $attemptedEps
  accepted_eps = $acceptedEps
  rejected_eps = $rejectedEps
  attempted_eps_target_window = $attemptedEpsTargetWindow
  accepted_eps_target_window = $acceptedEpsTargetWindow
  rejected_eps_target_window = $rejectedEpsTargetWindow
  api_rejection_loss_pct = $apiLossRatePct
  request_latency_p95_ms = $p95RequestLatencyMs
  persisted_events = $persistedCount
  persisted_loss_pct_vs_accepted = $persistedLossPct
  persistence_probe_attempts = $persistenceAttempts
  sample_errors = $errors
}

$outputDir = Join-Path $PSScriptRoot "..\\logs"
if (-not (Test-Path $outputDir)) {
  New-Item -Path $outputDir -ItemType Directory | Out-Null
}
$outputPath = Join-Path $outputDir "eps-load.json"
$report | ConvertTo-Json -Depth 20 | Set-Content -Path $outputPath -Encoding utf8

Write-Output "EPS report written to $outputPath"
$report | ConvertTo-Json -Depth 20
