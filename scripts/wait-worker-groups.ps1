param(
  [string]$Broker = "localhost:19092",
  [string]$GroupBase = "cyberbox-worker-v3",
  [string]$RedpandaContainer = "docker-redpanda-1",
  [int]$MinNormalizerMembers = 1,
  [int]$MinStreamDetectMembers = 1,
  [int]$MinSinkMembers = 1,
  [int]$TimeoutSeconds = 1800,
  [int]$PollIntervalSeconds = 15
)

$ErrorActionPreference = "Stop"

if ($TimeoutSeconds -lt 1) {
  throw "TimeoutSeconds must be >= 1"
}
if ($PollIntervalSeconds -lt 1) {
  throw "PollIntervalSeconds must be >= 1"
}

$deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
$checkScript = Join-Path $PSScriptRoot "check-worker-groups.ps1"

while ((Get-Date).ToUniversalTime() -lt $deadline) {
  $output = & $checkScript `
    -Broker $Broker `
    -GroupBase $GroupBase `
    -RedpandaContainer $RedpandaContainer `
    -MinNormalizerMembers $MinNormalizerMembers `
    -MinStreamDetectMembers $MinStreamDetectMembers `
    -MinSinkMembers $MinSinkMembers 2>&1
  $jsonText = ($output | Out-String).Trim()

  try {
    $summary = $jsonText | ConvertFrom-Json
  }
  catch {
    Write-Output "failed to parse group health output"
    Write-Output $jsonText
    exit 3
  }

  Write-Output ($summary | ConvertTo-Json -Depth 10)

  if ($summary.all_healthy) {
    Write-Output "worker groups are healthy"
    exit 0
  }

  Start-Sleep -Seconds $PollIntervalSeconds
}

Write-Output ("timed out waiting for healthy worker groups: {0}" -f $GroupBase)
exit 4
