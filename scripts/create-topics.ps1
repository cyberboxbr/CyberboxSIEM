param(
  [string]$Broker = "localhost:19092",
  [string]$ComposeFile = "infra/docker/docker-compose.yml",
  [string]$Service = "redpanda",
  [int]$ApiReplicas = 4,
  [int]$WorkerReplicas = 4,
  [int]$NormalizerReplicas = 0,
  [int]$StreamDetectReplicas = 0,
  [int]$SinkReplicas = 0,
  [int]$SinkWorkersPerReplica = 8,
  [int]$AlertConsumerParallelism = 4,
  [int]$RawMinPartitions = 24,
  [int]$NormalizedMinPartitions = 64,
  [int]$AlertsMinPartitions = 12
)

$ErrorActionPreference = "Stop"

$effectiveNormalizerReplicas = if ($NormalizerReplicas -gt 0) { $NormalizerReplicas } else { [Math]::Max($WorkerReplicas, 1) }
$effectiveStreamDetectReplicas = if ($StreamDetectReplicas -gt 0) { $StreamDetectReplicas } else { [Math]::Max($WorkerReplicas, 1) }
$effectiveSinkReplicas = if ($SinkReplicas -gt 0) { $SinkReplicas } else { [Math]::Max($WorkerReplicas, 1) }

$rawProducerParallelism = [Math]::Max($ApiReplicas, 1)
$rawConsumerParallelism = [Math]::Max($effectiveNormalizerReplicas, 1)
$rawParallelism = [Math]::Max($rawProducerParallelism, $rawConsumerParallelism)

$normalizedProducerParallelism = [Math]::Max($effectiveNormalizerReplicas, 1)
$normalizedConsumerParallelism = [Math]::Max(
  [Math]::Max($effectiveStreamDetectReplicas, 1),
  [Math]::Max($effectiveSinkReplicas, 1) * [Math]::Max($SinkWorkersPerReplica, 1)
)
$normalizedParallelism = [Math]::Max($normalizedProducerParallelism, $normalizedConsumerParallelism)
$alertParallelism = [Math]::Max($AlertConsumerParallelism, 1)

$topics = @(
  @{ Name = "cyberbox.events.raw"; Partitions = [Math]::Max($RawMinPartitions, $rawParallelism) },
  @{ Name = "cyberbox.events.normalized"; Partitions = [Math]::Max($NormalizedMinPartitions, $normalizedParallelism) },
  @{ Name = "cyberbox.alerts"; Partitions = [Math]::Max($AlertsMinPartitions, $alertParallelism) }
)

Write-Host ("topic parallelism plan: raw_producers={0} raw_consumers={1} normalized_producers={2} normalized_consumers={3} sink_workers_per_replica={4}" -f `
  $rawProducerParallelism, $rawConsumerParallelism, $normalizedProducerParallelism, $normalizedConsumerParallelism, $SinkWorkersPerReplica)

foreach ($topicSpec in $topics) {
  $topic = $topicSpec.Name
  $targetPartitions = [int]$topicSpec.Partitions

  $createOutput = docker compose -f $ComposeFile exec -T $Service `
    rpk topic create $topic --partitions $targetPartitions -X "brokers=$Broker" 2>&1
  $createOutputText = $createOutput | Out-String

  if ($LASTEXITCODE -ne 0 -and $createOutputText -notmatch "TOPIC_ALREADY_EXISTS") {
    throw "failed to ensure topic '$topic': $createOutputText"
  }

  $describeOutput = docker compose -f $ComposeFile exec -T $Service `
    rpk topic describe $topic -X "brokers=$Broker" 2>&1
  $describeOutputText = $describeOutput | Out-String
  if ($LASTEXITCODE -ne 0) {
    throw "failed to describe topic '$topic': $describeOutputText"
  }

  $currentPartitions = 0
  if ($describeOutputText -match "PARTITIONS\s+(\d+)") {
    $currentPartitions = [int]$Matches[1]
  } else {
    throw "unable to parse partition count for topic '$topic': $describeOutputText"
  }

  if ($currentPartitions -lt $targetPartitions) {
    $toAdd = $targetPartitions - $currentPartitions
    $addOutput = docker compose -f $ComposeFile exec -T $Service `
      rpk topic add-partitions $topic --num $toAdd -X "brokers=$Broker" 2>&1
    $addOutputText = $addOutput | Out-String
    if ($LASTEXITCODE -ne 0) {
      throw "failed to add partitions to topic '$topic': $addOutputText"
    }
    $currentPartitions = $targetPartitions
  }

  Write-Host "ensured topic: $topic partitions=$currentPartitions"
}
