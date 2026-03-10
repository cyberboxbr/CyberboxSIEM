param(
  [string]$ApiBase = "http://127.0.0.1:8080",
  [string]$ApiMetricsUrl = "http://127.0.0.1:8080/metrics",
  [string]$WorkerMetricsUrl = "http://127.0.0.1:9091/metrics",
  [int]$DurationSeconds = 300,
  [int]$TargetEps = 15000,
  [int]$Concurrency = 24,
  [int]$BatchSize = 100,
  [int]$PersistProbeAttempts = 60,
  [int]$PersistProbeIntervalMs = 2000,
  [string]$TenantId = "tenant-a",
  [string]$UserId = "soc-admin",
  [switch]$SkipPersistenceCheck
)

$ErrorActionPreference = "Stop"

function Invoke-MetricsText {
  param([string]$Url)
  return (Invoke-WebRequest -Uri $Url -UseBasicParsing).Content
}

function Get-MetricValue {
  param(
    [string]$MetricsText,
    [string]$MetricName,
    [string[]]$LabelFilters
  )

  $sum = 0.0
  $escapedMetric = [regex]::Escape($MetricName)
  $pattern = "^${escapedMetric}(?:\{([^}]*)\})?\s+([+-]?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?)$"
  $lines = $MetricsText -split "`r?`n"

  foreach ($line in $lines) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line.StartsWith("#")) { continue }
    if ($line -notmatch $pattern) { continue }

    $labels = $Matches[1]
    $value = [double]$Matches[2]
    $include = $true
    foreach ($filter in $LabelFilters) {
      if ([string]::IsNullOrEmpty($filter)) { continue }
      if ($labels -notlike "*$filter*") {
        $include = $false
        break
      }
    }
    if ($include) {
      $sum += $value
    }
  }

  return [double]$sum
}

function Get-MetricsSnapshot {
  param(
    [string]$ApiMetricsEndpoint,
    [string]$WorkerMetricsEndpoint
  )

  $apiText = Invoke-MetricsText -Url $ApiMetricsEndpoint
  $workerText = Invoke-MetricsText -Url $WorkerMetricsEndpoint

  return [ordered]@{
    api_raw_enqueue_attempt = Get-MetricValue -MetricsText $apiText -MetricName "kafka_producer_enqueue_attempt_total" -LabelFilters @('publisher="api_raw"')
    api_raw_enqueue_success = Get-MetricValue -MetricsText $apiText -MetricName "kafka_producer_enqueue_success_total" -LabelFilters @('publisher="api_raw"')
    api_raw_queue_full = Get-MetricValue -MetricsText $apiText -MetricName "kafka_producer_queue_full_total" -LabelFilters @('publisher="api_raw"')
    api_raw_enqueue_error = Get-MetricValue -MetricsText $apiText -MetricName "kafka_producer_enqueue_error_total" -LabelFilters @('publisher="api_raw"')
    api_raw_delivery_success = Get-MetricValue -MetricsText $apiText -MetricName "kafka_producer_delivery_success_total" -LabelFilters @('publisher="api_raw"')
    api_raw_delivery_error = Get-MetricValue -MetricsText $apiText -MetricName "kafka_producer_delivery_error_total" -LabelFilters @('publisher="api_raw"')
    api_raw_delivery_canceled = Get-MetricValue -MetricsText $apiText -MetricName "kafka_producer_delivery_canceled_total" -LabelFilters @('publisher="api_raw"')
    api_raw_delivery_future_enqueued = Get-MetricValue -MetricsText $apiText -MetricName "kafka_producer_delivery_future_enqueued_total" -LabelFilters @('publisher="api_raw"')
    api_raw_delivery_future_drop = Get-MetricValue -MetricsText $apiText -MetricName "kafka_producer_delivery_future_drop_total" -LabelFilters @('publisher="api_raw"')

    worker_norm_enqueue_attempt = Get-MetricValue -MetricsText $workerText -MetricName "kafka_producer_enqueue_attempt_total" -LabelFilters @('publisher="worker_normalized"')
    worker_norm_enqueue_success = Get-MetricValue -MetricsText $workerText -MetricName "kafka_producer_enqueue_success_total" -LabelFilters @('publisher="worker_normalized"')
    worker_norm_queue_full = Get-MetricValue -MetricsText $workerText -MetricName "kafka_producer_queue_full_total" -LabelFilters @('publisher="worker_normalized"')
    worker_norm_enqueue_error = Get-MetricValue -MetricsText $workerText -MetricName "kafka_producer_enqueue_error_total" -LabelFilters @('publisher="worker_normalized"')
    worker_norm_delivery_success = Get-MetricValue -MetricsText $workerText -MetricName "kafka_producer_delivery_success_total" -LabelFilters @('publisher="worker_normalized"')
    worker_norm_delivery_error = Get-MetricValue -MetricsText $workerText -MetricName "kafka_producer_delivery_error_total" -LabelFilters @('publisher="worker_normalized"')
    worker_norm_delivery_canceled = Get-MetricValue -MetricsText $workerText -MetricName "kafka_producer_delivery_canceled_total" -LabelFilters @('publisher="worker_normalized"')
    worker_norm_delivery_future_enqueued = Get-MetricValue -MetricsText $workerText -MetricName "kafka_producer_delivery_future_enqueued_total" -LabelFilters @('publisher="worker_normalized"')
    worker_norm_delivery_future_drop = Get-MetricValue -MetricsText $workerText -MetricName "kafka_producer_delivery_future_drop_total" -LabelFilters @('publisher="worker_normalized"')
  }
}

function Get-SnapshotDelta {
  param(
    [hashtable]$Before,
    [hashtable]$After
  )

  $delta = [ordered]@{}
  foreach ($name in $Before.Keys) {
    $beforeValue = [double]$Before[$name]
    $afterValue = [double]$After[$name]
    $delta[$name] = [Math]::Round(($afterValue - $beforeValue), 4)
  }
  return $delta
}

function Get-RatioPct {
  param(
    [double]$Numerator,
    [double]$Denominator
  )
  if ($Denominator -le 0) {
    return $null
  }
  return [Math]::Round((100.0 * $Numerator / $Denominator), 4)
}

function Resolve-CargoCommand {
  $command = Get-Command cargo -ErrorAction SilentlyContinue
  if ($null -ne $command) {
    return $command.Source
  }

  $fallback = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
  if (Test-Path $fallback) {
    return $fallback
  }

  throw "cargo command not found. Install Rust toolchain or add cargo to PATH."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $repoRoot

try {
  if ($PersistProbeAttempts -lt 1) {
    throw "PersistProbeAttempts must be >= 1"
  }
  if ($PersistProbeIntervalMs -lt 1) {
    throw "PersistProbeIntervalMs must be >= 1"
  }

  $before = Get-MetricsSnapshot -ApiMetricsEndpoint $ApiMetricsUrl -WorkerMetricsEndpoint $WorkerMetricsUrl
  $cargoCommand = Resolve-CargoCommand

  $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
  $loadReportRelativePath = "logs/eps-load-soak-$timestamp.json"

  $cargoArgs = @(
    "run", "--release", "-p", "cyberbox-loadgen", "--",
    "--api-base", $ApiBase,
    "--duration-seconds", "$DurationSeconds",
    "--concurrency", "$Concurrency",
    "--batch-size", "$BatchSize",
    "--tenant-id", $TenantId,
    "--user-id", $UserId,
    "--target-eps", "$TargetEps",
    "--persist-probe-attempts", "$PersistProbeAttempts",
    "--persist-probe-interval-ms", "$PersistProbeIntervalMs",
    "--report-path", $loadReportRelativePath
  )
  if ($SkipPersistenceCheck.IsPresent) {
    $cargoArgs += "--skip-persist-check"
  }

  & $cargoCommand @cargoArgs
  if ($LASTEXITCODE -ne 0) {
    throw "load generator failed with exit code $LASTEXITCODE"
  }

  $after = Get-MetricsSnapshot -ApiMetricsEndpoint $ApiMetricsUrl -WorkerMetricsEndpoint $WorkerMetricsUrl
  $delta = Get-SnapshotDelta -Before $before -After $after

  $loadReportPath = Join-Path $repoRoot $loadReportRelativePath
  if (-not (Test-Path $loadReportPath)) {
    throw "load report not found at $loadReportPath"
  }
  $loadReport = Get-Content -Path $loadReportPath -Raw | ConvertFrom-Json

  $summary = [ordered]@{
    run_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    mode = $loadReport.mode
    target_eps = $loadReport.target_eps
    accepted_eps_target_window = $loadReport.accepted_eps_target_window
    target_achieved_pct = $loadReport.target_achieved_pct
    request_latency_p95_ms = $loadReport.request_latency_p95_ms
    request_latency_p99_ms = $loadReport.request_latency_p99_ms

    api_raw_delivery_success_ratio_pct = Get-RatioPct -Numerator $delta.api_raw_delivery_success -Denominator $delta.api_raw_enqueue_success
    api_raw_delivery_error_ratio_pct = Get-RatioPct -Numerator $delta.api_raw_delivery_error -Denominator $delta.api_raw_enqueue_success
    api_raw_delivery_future_drop_ratio_pct = Get-RatioPct -Numerator $delta.api_raw_delivery_future_drop -Denominator $delta.api_raw_enqueue_success

    worker_norm_delivery_success_ratio_pct = Get-RatioPct -Numerator $delta.worker_norm_delivery_success -Denominator $delta.worker_norm_enqueue_success
    worker_norm_delivery_error_ratio_pct = Get-RatioPct -Numerator $delta.worker_norm_delivery_error -Denominator $delta.worker_norm_enqueue_success
    worker_norm_delivery_future_drop_ratio_pct = Get-RatioPct -Numerator $delta.worker_norm_delivery_future_drop -Denominator $delta.worker_norm_enqueue_success
  }

  $combined = [ordered]@{
    run_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    api_base = $ApiBase
    api_metrics_url = $ApiMetricsUrl
    worker_metrics_url = $WorkerMetricsUrl
    load_report_path = $loadReportRelativePath
    load_report = $loadReport
    metrics_before = $before
    metrics_after = $after
    metrics_delta = $delta
    summary = $summary
  }

  $outputPath = Join-Path $repoRoot "logs/load-soak-baseline-$timestamp.json"
  $combined | ConvertTo-Json -Depth 30 | Set-Content -Path $outputPath -Encoding utf8

  Write-Output "Soak baseline written to $outputPath"
  $combined | ConvertTo-Json -Depth 30
}
finally {
  Pop-Location
}
