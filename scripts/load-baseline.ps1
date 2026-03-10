param(
  [string]$ApiBase = "http://127.0.0.1:8080",
  [int]$SmallEvents = 100,
  [int]$ScaleEvents = 1000,
  [int]$BatchSize = 20,
  [int]$DetectionProbes = 20,
  [int]$QueryProbes = 50,
  [string]$TenantId = "tenant-a",
  [string]$UserId = "soc-admin"
)

$ErrorActionPreference = "Stop"

$headers = @{
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
    [object]$Body
  )
  $uri = "$ApiBase$Path"
  $json = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 20 -Compress } else { $null }
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  if ($null -ne $json) {
    $response = Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -Body $json
  } else {
    $response = Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
  }
  $sw.Stop()
  return [PSCustomObject]@{
    Body = $response
    DurationMs = [double]$sw.Elapsed.TotalMilliseconds
  }
}

function New-Event {
  param(
    [string]$Token,
    [string]$MessageSuffix
  )
  return @{
    tenant_id = $TenantId
    source = "windows_sysmon"
    event_time = (Get-Date).ToUniversalTime().ToString("o")
    raw_payload = @{
      event_code = 1
      cmdline = "powershell -enc $Token $MessageSuffix"
      message = "powershell -enc $Token $MessageSuffix"
      host = "loadgen-01"
    }
  }
}

function Run-IngestPhase {
  param(
    [string]$PhaseName,
    [int]$EventCount,
    [int]$PhaseBatchSize,
    [string]$Token
  )
  $samples = New-Object System.Collections.Generic.List[Double]
  for ($i = 0; $i -lt $EventCount; $i += $PhaseBatchSize) {
    $batchEvents = @()
    $batchEnd = [Math]::Min($EventCount, $i + $PhaseBatchSize)
    for ($j = $i; $j -lt $batchEnd; $j++) {
      $batchEvents += New-Event -Token $Token -MessageSuffix "$PhaseName-$j"
    }
    $response = Invoke-Json -Method "POST" -Path "/api/v1/events:ingest" -Body @{ events = $batchEvents }
    $samples.Add($response.DurationMs)
  }
  return @{
    phase = $PhaseName
    request_count = $samples.Count
    p95_ms = [Math]::Round((Get-P95 -Values $samples.ToArray()), 2)
  }
}

function Get-AlertCount {
  $alerts = Invoke-Json -Method "GET" -Path "/api/v1/alerts" -Body $null
  if ($alerts.Body -is [System.Array]) {
    return @($alerts.Body).Count
  }
  if ($null -eq $alerts.Body) {
    return 0
  }
  return 1
}

function Run-DetectionProbe {
  param(
    [string]$Token,
    [int]$ProbeCount
  )
  $samples = New-Object System.Collections.Generic.List[Double]
  for ($i = 0; $i -lt $ProbeCount; $i++) {
    $before = Get-AlertCount
    $event = New-Event -Token $Token -MessageSuffix "detect-$i"
    $start = [DateTimeOffset]::UtcNow
    [void](Invoke-Json -Method "POST" -Path "/api/v1/events:ingest" -Body @{ events = @($event) })
    $found = $false
    for ($poll = 0; $poll -lt 100; $poll++) {
      $after = Get-AlertCount
      if ($after -gt $before) {
        $latency = ([DateTimeOffset]::UtcNow - $start).TotalMilliseconds
        $samples.Add([double]$latency)
        $found = $true
        break
      }
      Start-Sleep -Milliseconds 50
    }
    if (-not $found) {
      $samples.Add(10000.0)
    }
  }

  return @{
    probes = $ProbeCount
    p95_ms = [Math]::Round((Get-P95 -Values $samples.ToArray()), 2)
  }
}

function Run-QueryProbe {
  param([int]$ProbeCount)
  $samples = New-Object System.Collections.Generic.List[Double]
  for ($i = 0; $i -lt $ProbeCount; $i++) {
    $now = (Get-Date).ToUniversalTime()
    $start = $now.AddHours(-1)
    $response = Invoke-Json -Method "POST" -Path "/api/v1/search:query" -Body @{
      tenant_id = $TenantId
      sql = "SELECT event_id, tenant_id, source, event_time FROM events_hot ORDER BY event_time DESC LIMIT 50"
      time_range = @{
        start = $start.ToString("o")
        end = $now.ToString("o")
      }
      filters = @()
      pagination = @{
        page = 1
        page_size = 50
      }
    }
    $samples.Add($response.DurationMs)
  }
  return @{
    probes = $ProbeCount
    p95_ms = [Math]::Round((Get-P95 -Values $samples.ToArray()), 2)
  }
}

$health = Invoke-Json -Method "GET" -Path "/healthz" -Body $null
if ($health.Body.status -ne "ok") {
  throw "API health check failed"
}

$token = "load-token-$([Guid]::NewGuid().ToString('N').Substring(0, 10))"
$ruleBody = @{
  sigma_source = "title: load-baseline`ndetection:`n  selection:`n    - $token"
  schedule_or_stream = "stream"
  severity = "high"
  enabled = $true
}
$ruleResponse = Invoke-Json -Method "POST" -Path "/api/v1/rules" -Body $ruleBody

$small = Run-IngestPhase -PhaseName "small" -EventCount $SmallEvents -PhaseBatchSize $BatchSize -Token $token
$scale = Run-IngestPhase -PhaseName "scale" -EventCount $ScaleEvents -PhaseBatchSize $BatchSize -Token $token
$detection = Run-DetectionProbe -Token $token -ProbeCount $DetectionProbes
$query = Run-QueryProbe -ProbeCount $QueryProbes

$result = [PSCustomObject]@{
  run_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  api_base = $ApiBase
  rule_id = $ruleResponse.Body.rule_id
  small_ingest = $small
  scale_ingest = $scale
  detection_latency = $detection
  query_latency = $query
}

$outputDir = Join-Path $PSScriptRoot "..\\logs"
if (-not (Test-Path $outputDir)) {
  New-Item -Path $outputDir -ItemType Directory | Out-Null
}
$outputPath = Join-Path $outputDir "baseline-latency.json"
$result | ConvertTo-Json -Depth 20 | Set-Content -Path $outputPath -Encoding utf8

Write-Output "Baseline written to $outputPath"
$result | ConvertTo-Json -Depth 20
