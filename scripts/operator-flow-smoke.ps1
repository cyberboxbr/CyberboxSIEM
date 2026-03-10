param(
  [string]$ApiBase = "http://127.0.0.1:8080",
  [string]$TenantId = "tenant-a",
  [string]$UserId = "soc-admin",
  [int]$RuleWarmupSeconds = 20,
  [int]$AlertWaitSeconds = 120
)

$ErrorActionPreference = "Stop"

$headers = @{
  "content-type" = "application/json"
  "x-tenant-id" = $TenantId
  "x-user-id" = $UserId
  "x-roles" = "admin,analyst,viewer,ingestor"
}

$health = Invoke-RestMethod -Method "GET" -Uri "$ApiBase/healthz" -Headers $headers
if ($health.status -ne "ok") {
  throw "healthz failed"
}

$token = "opflow-$([Guid]::NewGuid().ToString('N').Substring(0, 10))"
$createRuleBody = @{
  sigma_source = "title: operator-flow-smoke`ndetection:`n  selection:`n    - $token"
  schedule_or_stream = "stream"
  severity = "high"
  enabled = $true
} | ConvertTo-Json -Depth 10
$rule = Invoke-RestMethod -Method "POST" -Uri "$ApiBase/api/v1/rules" -Headers $headers -Body $createRuleBody

if ($RuleWarmupSeconds -gt 0) {
  Start-Sleep -Seconds $RuleWarmupSeconds
}

$eventBody = @{
  events = @(
    @{
      tenant_id = $TenantId
      source = "windows_sysmon"
      event_time = (Get-Date).ToUniversalTime().ToString("o")
      raw_payload = @{
        event_code = 1
        message = "powershell -enc $token"
        cmdline = "powershell -enc $token"
        host = "operator-flow-smoke"
      }
    }
  )
} | ConvertTo-Json -Depth 10
$ingest = Invoke-RestMethod -Method "POST" -Uri "$ApiBase/api/v1/events:ingest" -Headers $headers -Body $eventBody

$alert = $null
$deadline = (Get-Date).ToUniversalTime().AddSeconds($AlertWaitSeconds)
while ((Get-Date).ToUniversalTime() -lt $deadline) {
  $alertsResponse = Invoke-RestMethod -Method "GET" -Uri "$ApiBase/api/v1/alerts" -Headers $headers
  $alerts = if ($alertsResponse -is [System.Array]) {
    $alertsResponse
  }
  elseif ($null -ne $alertsResponse) {
    @($alertsResponse)
  }
  else {
    @()
  }
  $alert = $alerts | Where-Object { $_.rule_id -eq $rule.rule_id } | Select-Object -First 1
  if ($null -ne $alert) {
    break
  }
  Start-Sleep -Milliseconds 500
}

if ($null -eq $alert) {
  throw "no alert found for rule_id=$($rule.rule_id)"
}

$assignBody = @{
  actor = $UserId
  assignee = "tier1-analyst"
} | ConvertTo-Json -Compress
$assigned = Invoke-RestMethod -Method "POST" -Uri "$ApiBase/api/v1/alerts/$($alert.alert_id):assign" -Headers $headers -Body $assignBody

$ackBody = @{
  actor = $UserId
} | ConvertTo-Json -Compress
$acked = Invoke-RestMethod -Method "POST" -Uri "$ApiBase/api/v1/alerts/$($alert.alert_id):ack" -Headers $headers -Body $ackBody

$audit = Invoke-RestMethod -Method "GET" -Uri "$ApiBase/api/v1/audit-logs?entity_type=alert&limit=300" -Headers $headers
$entries = if ($audit.entries -is [System.Array]) {
  $audit.entries
}
elseif ($null -ne $audit.entries) {
  @($audit.entries)
}
else {
  @()
}
$hasAssign = @($entries | Where-Object { $_.action -eq "alert.assign" -and $_.entity_id -eq $alert.alert_id }).Count -gt 0
$hasAck = @($entries | Where-Object { $_.action -eq "alert.ack" -and $_.entity_id -eq $alert.alert_id }).Count -gt 0

$result = [ordered]@{
  run_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  api_base = $ApiBase
  token = $token
  rule_id = $rule.rule_id
  ingest_accepted = $ingest.accepted
  ingest_rejected = $ingest.rejected
  alert_id = $alert.alert_id
  assign_status = $assigned.status
  ack_status = $acked.status
  audit_assign_found = $hasAssign
  audit_ack_found = $hasAck
}

$outputDir = Join-Path $PSScriptRoot "..\\logs"
if (-not (Test-Path $outputDir)) {
  New-Item -Path $outputDir -ItemType Directory | Out-Null
}
$outputPath = Join-Path $outputDir "operator-flow-smoke.json"
$result | ConvertTo-Json -Depth 10 | Set-Content -Path $outputPath -Encoding utf8

Write-Output "Operator flow smoke written to $outputPath"
$result | ConvertTo-Json -Depth 10
