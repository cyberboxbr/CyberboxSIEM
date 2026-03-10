param(
  [int]$Replicas = 1,
  [string]$NamePrefix = "cyberbox-worker-dev",
  [string]$Network = "docker_default",
  [string]$Brokers = "redpanda:9092",
  [string]$ClickHouseUrl = "http://clickhouse:8123",
  [string]$WorkerGroupId = "cyberbox-worker-v1",
  [string]$Role = "all",
  [string]$ProducerAcks = "all",
  [bool]$ProducerEnableIdempotence = $true,
  [int]$ProducerMaxInFlightRequestsPerConnection = 5,
  [int]$ProducerMessageTimeoutMs = 30000,
  [int]$SinkWorkerCount = 8,
  [int]$SinkBatchSize = 10000,
  [int]$SinkBatchMaxBytes = 8388608,
  [int]$SinkFlushIntervalMs = 400,
  [int]$SinkMaxRetries = 8,
  [int]$SinkRetryBackoffBaseMs = 250,
  [int]$SinkRetryBackoffJitterMs = 200,
  [bool]$ClickHouseInsertAsyncEnabled = $true,
  [bool]$ClickHouseInsertWaitForAsync = $true,
  [bool]$ClickHouseInsertAsyncDeduplicateEnabled = $true,
  [bool]$ClickHouseInsertDeduplicationTokenEnabled = $true,
  [int]$SchedulerTickIntervalSeconds = 5,
  [int]$MetricsPort = 9091
)

$ErrorActionPreference = "Stop"

if ($Replicas -lt 1) {
  throw "Replicas must be >= 1"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$existingNames = docker ps -a --format "{{.Names}}" | Where-Object {
  $_ -eq $NamePrefix -or $_ -like ("{0}-*" -f $NamePrefix)
}
foreach ($name in $existingNames) {
  docker rm -f $name *>$null
}

$started = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $Replicas; $i++) {
  $name = if ($i -eq 0) { $NamePrefix } else { "{0}-{1}" -f $NamePrefix, $i }
  $runArgs = @("run", "-d", "--name", $name, "--network", $Network)
  if ($i -eq 0) {
    $runArgs += @("-p", ("{0}:9091" -f $MetricsPort))
  }

  $roleEnv = @()
  if ($Role -eq "normalizer") {
    $roleEnv = @("-e", "CYBERBOX__CLICKHOUSE_SEARCH_ENABLED=false", "-e", "CYBERBOX__CLICKHOUSE_SINK_ENABLED=false")
  } elseif ($Role -eq "stream-detect" -or $Role -eq "stream_detect") {
    $roleEnv = @("-e", "CYBERBOX__CLICKHOUSE_SEARCH_ENABLED=true", "-e", "CYBERBOX__CLICKHOUSE_SINK_ENABLED=false")
  } elseif ($Role -eq "scheduler") {
    $roleEnv = @("-e", "CYBERBOX__CLICKHOUSE_SEARCH_ENABLED=true", "-e", "CYBERBOX__CLICKHOUSE_SINK_ENABLED=false")
  } elseif ($Role -eq "sink") {
    $roleEnv = @("-e", "CYBERBOX__CLICKHOUSE_SEARCH_ENABLED=false", "-e", "CYBERBOX__CLICKHOUSE_SINK_ENABLED=true")
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
    "-e", ("CYBERBOX__WORKER_ROLE={0}" -f $Role),
    "-e", ("CYBERBOX__CLICKHOUSE_SINK_WORKER_COUNT={0}" -f $SinkWorkerCount),
    "-e", ("CYBERBOX__CLICKHOUSE_SINK_BATCH_SIZE={0}" -f $SinkBatchSize),
    "-e", ("CYBERBOX__CLICKHOUSE_SINK_BATCH_MAX_BYTES={0}" -f $SinkBatchMaxBytes),
    "-e", ("CYBERBOX__CLICKHOUSE_SINK_FLUSH_INTERVAL_MS={0}" -f $SinkFlushIntervalMs),
    "-e", ("CYBERBOX__CLICKHOUSE_SINK_MAX_RETRIES={0}" -f $SinkMaxRetries),
    "-e", ("CYBERBOX__CLICKHOUSE_SINK_RETRY_BACKOFF_BASE_MS={0}" -f $SinkRetryBackoffBaseMs),
    "-e", ("CYBERBOX__CLICKHOUSE_SINK_RETRY_BACKOFF_JITTER_MS={0}" -f $SinkRetryBackoffJitterMs),
    "-e", ("CYBERBOX__SCHEDULER_TICK_INTERVAL_SECONDS={0}" -f $SchedulerTickIntervalSeconds),
    "-e", ("CYBERBOX__WORKER_METRICS_BIND_ADDR=0.0.0.0:9091"),
    "-e", ("RUSTUP_SKIP_UPDATE_CHECK=1")
  )

  $runArgs += $roleEnv

  $runArgs += @(
    "-v", "cyberbox-cargo-registry:/usr/local/cargo/registry",
    "-v", "cyberbox-cargo-git:/usr/local/cargo/git",
    "-v", ("{0}:/workspace" -f $repoRoot),
    "-w", "/workspace",
    "rust:1.93",
    "sh", "-lc",
    "/usr/bin/apt-get update && /usr/bin/apt-get install -y --no-install-recommends cmake pkg-config build-essential && /usr/local/cargo/bin/cargo run -p cyberbox-worker --features kafka-native"
  )

  & docker @runArgs | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw ("failed to start worker container {0}" -f $name)
  }
  $started.Add($name)
}

Write-Output ("Started worker replicas: {0}" -f ($started -join ", "))
