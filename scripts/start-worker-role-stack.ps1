param(
  [string]$Network = "docker_default",
  [string]$Brokers = "redpanda:9092",
  [string]$ClickHouseUrl = "http://clickhouse:8123",
  [string]$WorkerGroupId = "cyberbox-worker-v3",
  [int]$NormalizerReplicas = 3,
  [int]$StreamDetectReplicas = 3,
  [int]$SchedulerReplicas = 1,
  [int]$SinkReplicas = 4,
  [string]$ProducerAcks = "all",
  [bool]$ProducerEnableIdempotence = $true,
  [int]$ProducerMaxInFlightRequestsPerConnection = 5,
  [int]$ProducerMessageTimeoutMs = 30000,
  [int]$SinkWorkerCount = 6,
  [int]$SinkBatchSize = 10000,
  [int]$SinkBatchMaxBytes = 16777216,
  [int]$SinkFlushIntervalMs = 400,
  [int]$SinkMaxRetries = 8,
  [int]$SinkRetryBackoffBaseMs = 250,
  [int]$SinkRetryBackoffJitterMs = 200,
  [bool]$ClickHouseInsertAsyncEnabled = $true,
  [bool]$ClickHouseInsertWaitForAsync = $true,
  [bool]$ClickHouseInsertAsyncDeduplicateEnabled = $true,
  [bool]$ClickHouseInsertDeduplicationTokenEnabled = $true,
  [int]$SchedulerTickIntervalSeconds = 5,
  [bool]$RemoveLegacyContainers = $true,
  [switch]$ExposeRoleMetrics
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$roleSpecs = @(
  [PSCustomObject]@{ Role = "normalizer"; NamePrefix = "cyberbox-worker-normalizer-dev"; Replicas = $NormalizerReplicas; MetricsPort = 19191 },
  [PSCustomObject]@{ Role = "stream-detect"; NamePrefix = "cyberbox-worker-stream-detect-dev"; Replicas = $StreamDetectReplicas; MetricsPort = 19192 },
  [PSCustomObject]@{ Role = "scheduler"; NamePrefix = "cyberbox-worker-scheduler-dev"; Replicas = $SchedulerReplicas; MetricsPort = 19193 },
  [PSCustomObject]@{ Role = "sink"; NamePrefix = "cyberbox-worker-sink-dev"; Replicas = $SinkReplicas; MetricsPort = 19194 }
)

foreach ($spec in $roleSpecs) {
  if ($spec.Replicas -lt 0) {
    throw "Replicas must be >= 0 for role $($spec.Role)"
  }
}

if ($SinkWorkerCount -lt 1) {
  throw "SinkWorkerCount must be >= 1"
}
if ($SinkBatchSize -lt 1) {
  throw "SinkBatchSize must be >= 1"
}
if ($SinkFlushIntervalMs -lt 10) {
  throw "SinkFlushIntervalMs must be >= 10"
}
if ($SchedulerTickIntervalSeconds -lt 1) {
  throw "SchedulerTickIntervalSeconds must be >= 1"
}

$allPrefixes = $roleSpecs | ForEach-Object { $_.NamePrefix }
$existingNames = docker ps -a --format "{{.Names}}" | Where-Object {
  $name = $_
  $allPrefixes | Where-Object { $name -eq $_ -or $name -like ("{0}-*" -f $_) }
}
foreach ($name in $existingNames) {
  docker rm -f $name *>$null
}

if ($RemoveLegacyContainers) {
  $legacyNames = docker ps -a --format "{{.Names}}" | Where-Object {
    $_ -eq "cyberbox-worker-dev" -or $_ -like "cyberbox-worker-dev-*"
  }
  foreach ($name in $legacyNames) {
    docker rm -f $name *>$null
  }
}

$started = New-Object System.Collections.Generic.List[string]

function Get-RoleEnv {
  param([string]$Role)

  switch ($Role) {
    "normalizer" {
      return @(
        "-e", "CYBERBOX__CLICKHOUSE_SEARCH_ENABLED=false",
        "-e", "CYBERBOX__CLICKHOUSE_SINK_ENABLED=false"
      )
    }
    "stream-detect" {
      return @(
        "-e", "CYBERBOX__CLICKHOUSE_SEARCH_ENABLED=true",
        "-e", "CYBERBOX__CLICKHOUSE_SINK_ENABLED=false"
      )
    }
    "scheduler" {
      return @(
        "-e", "CYBERBOX__CLICKHOUSE_SEARCH_ENABLED=true",
        "-e", "CYBERBOX__CLICKHOUSE_SINK_ENABLED=false"
      )
    }
    "sink" {
      return @(
        "-e", "CYBERBOX__CLICKHOUSE_SEARCH_ENABLED=false",
        "-e", "CYBERBOX__CLICKHOUSE_SINK_ENABLED=true"
      )
    }
    default {
      throw "Unsupported role $Role"
    }
  }
}

foreach ($spec in $roleSpecs) {
  for ($i = 0; $i -lt $spec.Replicas; $i++) {
    $name = if ($i -eq 0) { $spec.NamePrefix } else { "{0}-{1}" -f $spec.NamePrefix, $i }

    $runArgs = @("run", "-d", "--name", $name, "--network", $Network)
    if ($ExposeRoleMetrics.IsPresent -and $i -eq 0) {
      $runArgs += @("-p", ("{0}:9091" -f $spec.MetricsPort))
    }

    $runArgs += @(
      "-e", ("CYBERBOX__REDPANDA_BROKERS={0}" -f $Brokers),
      "-e", ("CYBERBOX__CLICKHOUSE_URL={0}" -f $ClickHouseUrl),
      "-e", ("CYBERBOX__KAFKA_PRODUCER_ACKS={0}" -f $ProducerAcks),
      "-e", ("CYBERBOX__KAFKA_PRODUCER_ENABLE_IDEMPOTENCE={0}" -f $ProducerEnableIdempotence.ToString().ToLowerInvariant()),
      "-e", ("CYBERBOX__KAFKA_PRODUCER_MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION={0}" -f $ProducerMaxInFlightRequestsPerConnection),
      "-e", ("CYBERBOX__KAFKA_PRODUCER_MESSAGE_TIMEOUT_MS={0}" -f $ProducerMessageTimeoutMs),
      "-e", ("CYBERBOX__CLICKHOUSE_INSERT_ASYNC_ENABLED={0}" -f $ClickHouseInsertAsyncEnabled.ToString().ToLowerInvariant()),
      "-e", ("CYBERBOX__CLICKHOUSE_INSERT_WAIT_FOR_ASYNC={0}" -f $ClickHouseInsertWaitForAsync.ToString().ToLowerInvariant()),
      "-e", ("CYBERBOX__CLICKHOUSE_INSERT_ASYNC_DEDUPLICATE_ENABLED={0}" -f $ClickHouseInsertAsyncDeduplicateEnabled.ToString().ToLowerInvariant()),
      "-e", ("CYBERBOX__CLICKHOUSE_INSERT_DEDUPLICATION_TOKEN_ENABLED={0}" -f $ClickHouseInsertDeduplicationTokenEnabled.ToString().ToLowerInvariant()),
      "-e", ("CYBERBOX__KAFKA_WORKER_GROUP_ID={0}" -f $WorkerGroupId),
      "-e", ("CYBERBOX__WORKER_ROLE={0}" -f $spec.Role),
      "-e", ("CYBERBOX__WORKER_METRICS_BIND_ADDR=0.0.0.0:9091"),
      "-e", ("CYBERBOX__CLICKHOUSE_SINK_WORKER_COUNT={0}" -f $SinkWorkerCount),
      "-e", ("CYBERBOX__CLICKHOUSE_SINK_BATCH_SIZE={0}" -f $SinkBatchSize),
      "-e", ("CYBERBOX__CLICKHOUSE_SINK_BATCH_MAX_BYTES={0}" -f $SinkBatchMaxBytes),
      "-e", ("CYBERBOX__CLICKHOUSE_SINK_FLUSH_INTERVAL_MS={0}" -f $SinkFlushIntervalMs),
      "-e", ("CYBERBOX__CLICKHOUSE_SINK_MAX_RETRIES={0}" -f $SinkMaxRetries),
      "-e", ("CYBERBOX__CLICKHOUSE_SINK_RETRY_BACKOFF_BASE_MS={0}" -f $SinkRetryBackoffBaseMs),
      "-e", ("CYBERBOX__CLICKHOUSE_SINK_RETRY_BACKOFF_JITTER_MS={0}" -f $SinkRetryBackoffJitterMs),
      "-e", ("CYBERBOX__SCHEDULER_TICK_INTERVAL_SECONDS={0}" -f $SchedulerTickIntervalSeconds),
      "-e", ("RUSTUP_SKIP_UPDATE_CHECK=1"),
      "-v", "cyberbox-cargo-registry:/usr/local/cargo/registry",
      "-v", "cyberbox-cargo-git:/usr/local/cargo/git",
      "-v", ("{0}:/workspace" -f $repoRoot),
      "-w", "/workspace"
    )

    $runArgs += Get-RoleEnv -Role $spec.Role

    $runArgs += @(
      "rust:1.93",
      "sh", "-lc",
      "/usr/bin/apt-get update && /usr/bin/apt-get install -y --no-install-recommends cmake pkg-config build-essential && /usr/local/cargo/bin/cargo run -p cyberbox-worker --features kafka-native"
    )

    & docker @runArgs | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw ("failed to start worker role container {0}" -f $name)
    }

    $started.Add($name)
  }
}

Write-Output ("Started role-based worker stack ({0} containers): {1}" -f $started.Count, ($started -join ", "))
Write-Output ("Worker group base: {0}" -f $WorkerGroupId)
if ($ExposeRoleMetrics.IsPresent) {
  Write-Output "Role metrics host ports: normalizer=19191 stream-detect=19192 scheduler=19193 sink=19194"
}
Write-Output ("Next: run ./scripts/check-worker-groups.ps1 -GroupBase {0} until all_healthy=true" -f $WorkerGroupId)
