param(
  [string]$ApiBase = "http://127.0.0.1:8080",
  [string]$MatrixPath = "config/load-matrix.json",
  [string]$OutputRoot = "logs/load-matrix",
  [string]$UserId = "soc-admin",
  [switch]$SkipPersistenceCheck
)

$ErrorActionPreference = "Stop"

function Resolve-CargoCommand {
  $command = Get-Command cargo -ErrorAction SilentlyContinue
  if ($null -ne $command) {
    return $command.Source
  }

  $fallback = Join-Path $env:USERPROFILE ".cargo\\bin\\cargo.exe"
  if (Test-Path $fallback) {
    return $fallback
  }

  throw "cargo command not found. Install Rust toolchain or add cargo to PATH."
}

function Resolve-AbsolutePath {
  param([string]$PathValue, [string]$BasePath)

  if ([System.IO.Path]::IsPathRooted($PathValue)) {
    return [System.IO.Path]::GetFullPath($PathValue)
  }

  return [System.IO.Path]::GetFullPath((Join-Path $BasePath $PathValue))
}

function New-WorkloadPlan {
  param($Scenario)

  $mix = @($Scenario.tenant_mix)
  if ($mix.Count -eq 0) {
    throw "Scenario '$($Scenario.name)' has no tenant_mix entries"
  }

  $targetEpsTotal = [int]$Scenario.target_eps_total
  $concurrencyTotal = [int]$Scenario.concurrency_total
  $batchSize = [int]$Scenario.batch_size
  $durationSeconds = [int]$Scenario.duration_seconds

  if ($targetEpsTotal -le 0) { throw "Scenario '$($Scenario.name)' target_eps_total must be > 0" }
  if ($concurrencyTotal -le 0) { throw "Scenario '$($Scenario.name)' concurrency_total must be > 0" }
  if ($batchSize -le 0) { throw "Scenario '$($Scenario.name)' batch_size must be > 0" }
  if ($durationSeconds -le 0) { throw "Scenario '$($Scenario.name)' duration_seconds must be > 0" }

  $ageMin = [long]$Scenario.retention_profile.event_age_min_seconds
  $ageMax = [long]$Scenario.retention_profile.event_age_max_seconds
  if ($ageMin -lt 0 -or $ageMax -lt 0 -or $ageMin -gt $ageMax) {
    throw "Scenario '$($Scenario.name)' has invalid retention profile age range"
  }

  $totalWeight = [double](($mix | Measure-Object -Property weight_pct -Sum).Sum)
  if ($totalWeight -le 0) {
    throw "Scenario '$($Scenario.name)' tenant mix weights must sum to > 0"
  }

  $plan = New-Object System.Collections.Generic.List[object]
  foreach ($tenant in $mix) {
    $ratio = [double]$tenant.weight_pct / $totalWeight
    $plannedEps = [Math]::Max(1, [int][Math]::Round($targetEpsTotal * $ratio))
    $plannedConcurrency = [Math]::Max(1, [int][Math]::Round($concurrencyTotal * $ratio))
    $plan.Add([PSCustomObject]@{
        tenant_id = [string]$tenant.tenant_id
        weight_pct = [double]$tenant.weight_pct
        target_eps = $plannedEps
        concurrency = $plannedConcurrency
        duration_seconds = $durationSeconds
        batch_size = $batchSize
        event_age_min_seconds = $ageMin
        event_age_max_seconds = $ageMax
      })
  }

  $epsSum = [int](($plan | Measure-Object -Property target_eps -Sum).Sum)
  $concurrencySum = [int](($plan | Measure-Object -Property concurrency -Sum).Sum)

  $heaviest = $plan | Sort-Object -Property weight_pct -Descending | Select-Object -First 1
  if ($null -eq $heaviest) {
    throw "Scenario '$($Scenario.name)' could not determine heaviest tenant"
  }

  $epsDelta = $targetEpsTotal - $epsSum
  if ($epsDelta -ne 0) {
    $heaviest.target_eps = [Math]::Max(1, $heaviest.target_eps + $epsDelta)
  }

  $concurrencyDelta = $concurrencyTotal - $concurrencySum
  if ($concurrencyDelta -ne 0) {
    $heaviest.concurrency = [Math]::Max(1, $heaviest.concurrency + $concurrencyDelta)
  }

  return @($plan)
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$cargoCommand = Resolve-CargoCommand
$matrixPathAbsolute = Resolve-AbsolutePath -PathValue $MatrixPath -BasePath $repoRoot
$outputRootAbsolute = Resolve-AbsolutePath -PathValue $OutputRoot -BasePath $repoRoot

if (-not (Test-Path $matrixPathAbsolute)) {
  throw "Matrix file not found: $matrixPathAbsolute"
}

$matrix = Get-Content -Path $matrixPathAbsolute -Raw | ConvertFrom-Json
if ($null -eq $matrix -or $null -eq $matrix.scenarios -or @($matrix.scenarios).Count -eq 0) {
  throw "Matrix file has no scenarios: $matrixPathAbsolute"
}

$runStamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$runDir = Join-Path $outputRootAbsolute "matrix-$runStamp"
New-Item -Path $runDir -ItemType Directory -Force | Out-Null

$scenarioSummaries = New-Object System.Collections.Generic.List[object]

foreach ($scenario in @($matrix.scenarios)) {
  $scenarioName = [string]$scenario.name
  if ([string]::IsNullOrWhiteSpace($scenarioName)) {
    throw "Scenario name is required for all scenarios"
  }

  $safeScenarioName = ($scenarioName -replace '[^a-zA-Z0-9\-_.]', '-')
  $scenarioDir = Join-Path $runDir $safeScenarioName
  New-Item -Path $scenarioDir -ItemType Directory -Force | Out-Null

  Write-Output "Running scenario: $scenarioName"
  $plan = New-WorkloadPlan -Scenario $scenario

  $jobs = @()
  foreach ($workload in $plan) {
    $tenantReportPath = Join-Path $scenarioDir ("tenant-{0}.json" -f $workload.tenant_id)

    $jobs += Start-Job -ScriptBlock {
      param(
        $Repo,
        $Cargo,
        $Api,
        $Duration,
        $Concurrency,
        $Batch,
        $Tenant,
        $User,
        $TargetEps,
        $ReportPath,
        $AgeMin,
        $AgeMax,
        $SkipPersist
      )

      $ErrorActionPreference = "Stop"
      Push-Location $Repo
      try {
        $args = @(
          "run", "--release", "-p", "cyberbox-loadgen", "--",
          "--api-base", $Api,
          "--duration-seconds", "$Duration",
          "--concurrency", "$Concurrency",
          "--batch-size", "$Batch",
          "--tenant-id", $Tenant,
          "--user-id", $User,
          "--target-eps", "$TargetEps",
          "--event-age-min-seconds", "$AgeMin",
          "--event-age-max-seconds", "$AgeMax",
          "--report-path", $ReportPath
        )

        if ($SkipPersist) {
          $args += "--skip-persist-check"
        }

        & $Cargo @args
        if ($LASTEXITCODE -ne 0) {
          throw "loadgen failed for tenant '$Tenant' with exit code $LASTEXITCODE"
        }

        return [PSCustomObject]@{
          tenant_id = $Tenant
          report_path = $ReportPath
          status = "ok"
        }
      }
      finally {
        Pop-Location
      }
    } -ArgumentList @(
      $repoRoot,
      $cargoCommand,
      $ApiBase,
      $workload.duration_seconds,
      $workload.concurrency,
      $workload.batch_size,
      $workload.tenant_id,
      $UserId,
      $workload.target_eps,
      $tenantReportPath,
      $workload.event_age_min_seconds,
      $workload.event_age_max_seconds,
      $SkipPersistenceCheck.IsPresent
    )
  }

  Wait-Job -Job $jobs | Out-Null

  $jobFailures = @($jobs | Where-Object { $_.State -ne "Completed" })
  foreach ($job in $jobs) {
    [void](Receive-Job -Job $job -Keep)
  }
  Remove-Job -Job $jobs -Force

  if ($jobFailures.Count -gt 0) {
    $failureNames = ($jobFailures | ForEach-Object { $_.Name }) -join ", "
    throw "Scenario '$scenarioName' has failed jobs: $failureNames"
  }

  $tenantReports = New-Object System.Collections.Generic.List[object]
  foreach ($item in $plan) {
    $path = Join-Path $scenarioDir ("tenant-{0}.json" -f $item.tenant_id)
    if (-not (Test-Path $path)) {
      throw "Expected tenant report not found for scenario '$scenarioName': $path"
    }
    $tenantReport = Get-Content -Path $path -Raw | ConvertFrom-Json
    $tenantReports.Add($tenantReport)
  }

  $acceptedEps = [double](($tenantReports | Measure-Object -Property accepted_eps_target_window -Sum).Sum)
  $attemptedEps = [double](($tenantReports | Measure-Object -Property attempted_eps_target_window -Sum).Sum)
  $rejectedEps = [double](($tenantReports | Measure-Object -Property rejected_eps_target_window -Sum).Sum)
  $requestsError = [long](($tenantReports | Measure-Object -Property requests_error -Sum).Sum)
  $eventsAccepted = [long](($tenantReports | Measure-Object -Property events_accepted -Sum).Sum)
  $eventsRejected = [long](($tenantReports | Measure-Object -Property events_rejected -Sum).Sum)
  $p95Max = [double](($tenantReports | Measure-Object -Property request_latency_p95_ms -Maximum).Maximum)
  $p99Max = [double](($tenantReports | Measure-Object -Property request_latency_p99_ms -Maximum).Maximum)

  $targetTotal = [double]$scenario.target_eps_total
  $targetAchievedPct = if ($targetTotal -gt 0) {
    [Math]::Round((100.0 * $acceptedEps / $targetTotal), 2)
  }
  else {
    0.0
  }

  $scenarioSummary = [PSCustomObject]@{
    name = $scenarioName
    run_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    retention_profile = $scenario.retention_profile
    duration_seconds = [int]$scenario.duration_seconds
    batch_size = [int]$scenario.batch_size
    target_eps_total = [int]$scenario.target_eps_total
    concurrency_total = [int]$scenario.concurrency_total
    tenant_mix = $scenario.tenant_mix
    workload_plan = $plan
    accepted_eps_target_window = [Math]::Round($acceptedEps, 2)
    attempted_eps_target_window = [Math]::Round($attemptedEps, 2)
    rejected_eps_target_window = [Math]::Round($rejectedEps, 2)
    target_achieved_pct = $targetAchievedPct
    request_latency_p95_ms_max = [Math]::Round($p95Max, 2)
    request_latency_p99_ms_max = [Math]::Round($p99Max, 2)
    requests_error_total = $requestsError
    events_accepted_total = $eventsAccepted
    events_rejected_total = $eventsRejected
    output_dir = $scenarioDir
    tenant_reports = @($tenantReports | ForEach-Object {
        [PSCustomObject]@{
          tenant_id = $_.tenant_id
          report = $_
        }
      })
  }

  $scenarioSummaryPath = Join-Path $scenarioDir "scenario-summary.json"
  $scenarioSummary | ConvertTo-Json -Depth 40 | Set-Content -Path $scenarioSummaryPath -Encoding utf8
  $scenarioSummaries.Add($scenarioSummary)

  Write-Output ("Scenario complete: {0} | accepted_eps={1} target_pct={2}" -f $scenarioName, $scenarioSummary.accepted_eps_target_window, $scenarioSummary.target_achieved_pct)
}

$matrixSummary = [PSCustomObject]@{
  run_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  matrix_file = $matrixPathAbsolute
  output_dir = $runDir
  scenario_count = $scenarioSummaries.Count
  scenarios = @($scenarioSummaries)
}

$summaryPath = Join-Path $runDir "matrix-summary.json"
$matrixSummary | ConvertTo-Json -Depth 50 | Set-Content -Path $summaryPath -Encoding utf8

Write-Output "Load matrix summary written to $summaryPath"
$matrixSummary | ConvertTo-Json -Depth 50
