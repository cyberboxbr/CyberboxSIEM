param(
  [string]$ApiBase = "http://127.0.0.1:8080",
  [string]$ApiMetricsUrl = "http://127.0.0.1:8080/metrics",
  [int]$DurationSeconds = 45,
  [int]$Concurrency = 96,
  [int]$BatchSize = 200,
  [switch]$RestartApiWithStrictProfile
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

function Get-ApiSnapshot {
  param([string]$Url)
  $text = Invoke-MetricsText -Url $Url
  return [ordered]@{
    api_enqueue_attempt_total = Get-MetricValue -MetricsText $text -MetricName "kafka_producer_enqueue_attempt_total" -LabelFilters @('publisher="api_raw"')
    api_enqueue_success_total = Get-MetricValue -MetricsText $text -MetricName "kafka_producer_enqueue_success_total" -LabelFilters @('publisher="api_raw"')
    api_queue_full_total = Get-MetricValue -MetricsText $text -MetricName "kafka_producer_queue_full_total" -LabelFilters @('publisher="api_raw"')
    api_queue_full_exhausted_total = Get-MetricValue -MetricsText $text -MetricName "kafka_producer_queue_full_exhausted_total" -LabelFilters @('publisher="api_raw"')
    api_enqueue_error_queue_full_total = Get-MetricValue -MetricsText $text -MetricName "kafka_producer_enqueue_error_total" -LabelFilters @('publisher="api_raw"', 'kind="queue_full"')
    api_delivery_future_drop_full_total = Get-MetricValue -MetricsText $text -MetricName "kafka_producer_delivery_future_drop_total" -LabelFilters @('publisher="api_raw"', 'reason="full"')
  }
}

function Get-SnapshotDelta {
  param(
    [hashtable]$Before,
    [hashtable]$After
  )

  $delta = [ordered]@{}
  foreach ($name in $Before.Keys) {
    $delta[$name] = [Math]::Round(([double]$After[$name] - [double]$Before[$name]), 4)
  }
  return $delta
}

function Wait-ApiHealth {
  param(
    [string]$HealthUrl,
    [int]$TimeoutSeconds = 240
  )
  $deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
  while ((Get-Date).ToUniversalTime() -lt $deadline) {
    try {
      $health = Invoke-RestMethod -Method "GET" -Uri $HealthUrl -TimeoutSec 5
      if ($health.status -eq "ok") {
        return
      }
    }
    catch {
      Start-Sleep -Seconds 2
      continue
    }
    Start-Sleep -Seconds 2
  }
  throw "API health check did not become ready in time"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ($RestartApiWithStrictProfile.IsPresent) {
  & (Join-Path $PSScriptRoot "start-api-dev-container.ps1") -StrictOverloadProfile
  if ($LASTEXITCODE -ne 0) {
    throw "failed to restart API with strict overload profile"
  }
  Wait-ApiHealth -HealthUrl "$ApiBase/healthz"
}

$before = Get-ApiSnapshot -Url $ApiMetricsUrl

& powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "load-eps.ps1") `
  -ApiBase $ApiBase `
  -DurationSeconds $DurationSeconds `
  -Concurrency $Concurrency `
  -BatchSize $BatchSize `
  -SkipPersistenceCheck
if ($LASTEXITCODE -ne 0) {
  throw "load-eps.ps1 failed with exit code $LASTEXITCODE"
}

$after = Get-ApiSnapshot -Url $ApiMetricsUrl
$delta = Get-SnapshotDelta -Before $before -After $after

$epsReportPath = Join-Path $repoRoot "logs/eps-load.json"
if (-not (Test-Path $epsReportPath)) {
  throw "eps report not found at $epsReportPath"
}
$epsReport = Get-Content -Path $epsReportPath -Raw | ConvertFrom-Json

$backpressureTriggered = ($epsReport.requests_http_429 -gt 0) -or `
  ($delta.api_queue_full_exhausted_total -gt 0) -or `
  ($delta.api_enqueue_error_queue_full_total -gt 0)

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$outputPath = Join-Path $repoRoot ("logs/overload-429-{0}.json" -f $timestamp)
$result = [ordered]@{
  run_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  api_base = $ApiBase
  duration_seconds = $DurationSeconds
  concurrency = $Concurrency
  batch_size = $BatchSize
  strict_profile_restarted = $RestartApiWithStrictProfile.IsPresent
  backpressure_triggered = $backpressureTriggered
  eps_report = $epsReport
  metrics_before = $before
  metrics_after = $after
  metrics_delta = $delta
}
$result | ConvertTo-Json -Depth 30 | Set-Content -Path $outputPath -Encoding utf8

Write-Output ("Overload report written to {0}" -f $outputPath)
$result | ConvertTo-Json -Depth 30
