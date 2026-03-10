param(
  [string]$Broker = "localhost:19092",
  [string]$ComposeFile = "infra/docker/docker-compose.yml",
  [string]$Service = "redpanda",
  [switch]$SkipDelete,
  [int]$ApiReplicas = 1,
  [int]$NormalizerReplicas = 3,
  [int]$StreamDetectReplicas = 3,
  [int]$SinkReplicas = 4,
  [int]$SinkWorkersPerReplica = 6,
  [int]$RawMinPartitions = 24,
  [int]$NormalizedMinPartitions = 64,
  [int]$AlertsMinPartitions = 12
)

$ErrorActionPreference = "Stop"

$topics = @(
  "cyberbox.events.raw",
  "cyberbox.events.normalized",
  "cyberbox.alerts"
)

if (-not $SkipDelete.IsPresent) {
  foreach ($topic in $topics) {
    $deleteOutput = docker compose -f $ComposeFile exec -T $Service rpk topic delete $topic -X "brokers=$Broker" 2>&1
    $deleteText = $deleteOutput | Out-String
    if ($LASTEXITCODE -ne 0 -and $deleteText -notmatch "TOPIC_NOT_FOUND" -and $deleteText -notmatch "topic not found") {
      throw "failed to delete topic '$topic': $deleteText"
    }
    Write-Output "deleted topic (if existed): $topic"
  }
}

$createTopicsScript = Join-Path $PSScriptRoot "create-topics.ps1"
& $createTopicsScript `
  -Broker $Broker `
  -ComposeFile $ComposeFile `
  -Service $Service `
  -ApiReplicas $ApiReplicas `
  -NormalizerReplicas $NormalizerReplicas `
  -StreamDetectReplicas $StreamDetectReplicas `
  -SinkReplicas $SinkReplicas `
  -SinkWorkersPerReplica $SinkWorkersPerReplica `
  -RawMinPartitions $RawMinPartitions `
  -NormalizedMinPartitions $NormalizedMinPartitions `
  -AlertsMinPartitions $AlertsMinPartitions

if ($LASTEXITCODE -ne 0) {
  throw "failed to recreate topics"
}

Write-Output "topic reset and recreation complete"
