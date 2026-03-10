param(
  [string]$Broker = "localhost:19092",
  [string]$GroupBase = "cyberbox-worker-v3",
  [string]$RedpandaContainer = "docker-redpanda-1",
  [int]$MinNormalizerMembers = 1,
  [int]$MinStreamDetectMembers = 1,
  [int]$MinSinkMembers = 1
)

$ErrorActionPreference = "Stop"

$groups = @(
  [PSCustomObject]@{ Name = ("{0}-normalizer" -f $GroupBase); MinMembers = $MinNormalizerMembers },
  [PSCustomObject]@{ Name = ("{0}-stream-detect" -f $GroupBase); MinMembers = $MinStreamDetectMembers },
  [PSCustomObject]@{ Name = ("{0}-clickhouse-sink" -f $GroupBase); MinMembers = $MinSinkMembers }
)

$results = New-Object System.Collections.Generic.List[object]

foreach ($groupSpec in $groups) {
  $group = $groupSpec.Name
  $output = docker exec $RedpandaContainer rpk group describe $group -X "brokers=$Broker" 2>&1
  $text = $output | Out-String
  if ($LASTEXITCODE -ne 0) {
    $results.Add([PSCustomObject]@{
        group = $group
        state = "unknown"
        members = -1
        min_members = $groupSpec.MinMembers
        total_lag = -1
        healthy = $false
        error = $text.Trim()
      })
    continue
  }

  $state = "unknown"
  $members = -1
  $totalLag = -1

  if ($text -match "STATE\s+([^\r\n]+)") {
    $state = $Matches[1].Trim()
  }
  if ($text -match "MEMBERS\s+(\d+)") {
    $members = [int]$Matches[1]
  }
  if ($text -match "TOTAL-LAG\s+(\d+)") {
    $totalLag = [long]$Matches[1]
  }

  $healthy = ($state -eq "Stable" -and $members -ge $groupSpec.MinMembers)
  $results.Add([PSCustomObject]@{
      group = $group
      state = $state
      members = $members
      min_members = $groupSpec.MinMembers
      total_lag = $totalLag
      healthy = $healthy
      error = $null
    })
}

$summary = [PSCustomObject]@{
  checked_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  broker = $Broker
  group_base = $GroupBase
  min_members = @{
    normalizer = $MinNormalizerMembers
    stream_detect = $MinStreamDetectMembers
    sink = $MinSinkMembers
  }
  groups = $results
  all_healthy = @($results | Where-Object { -not $_.healthy }).Count -eq 0
}

$summary | ConvertTo-Json -Depth 10
if (-not $summary.all_healthy) {
  exit 2
}
