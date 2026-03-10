param(
  [string]$Name = "cyberbox-api-dev",
  [string]$Network = "docker_default",
  [int]$ApiPort = 8080,
  [string]$Brokers = "redpanda:9092",
  [string]$ClickHouseUrl = "http://clickhouse:8123",
  [int]$IngestMaxEventsPerRequest = 5000,
  [int]$IngestMaxBodyBytes = 4194304,
  [string]$ProducerAcks = "all",
  [bool]$ProducerEnableIdempotence = $true,
  [int]$ProducerMaxInFlightRequestsPerConnection = 5,
  [int]$ProducerMessageTimeoutMs = 30000,
  [int]$QueueFullMaxRetries = 3,
  [int]$QueueFullBackoffMs = 5,
  [int]$OverloadRetryAfterSeconds = 1,
  [int]$DeliveryTrackerQueueSize = 100000,
  [int]$QueueBufferingMaxMessages = 50000,
  [int]$QueueBufferingMaxKbytes = 262144,
  [bool]$ClickHouseInsertAsyncEnabled = $true,
  [bool]$ClickHouseInsertWaitForAsync = $true,
  [bool]$ClickHouseInsertAsyncDeduplicateEnabled = $true,
  [bool]$ClickHouseInsertDeduplicationTokenEnabled = $true,
  [switch]$StrictOverloadProfile
)

$ErrorActionPreference = "Stop"

if ($StrictOverloadProfile.IsPresent) {
  $QueueFullMaxRetries = 0
  $QueueFullBackoffMs = 1
  $OverloadRetryAfterSeconds = 2
  $DeliveryTrackerQueueSize = 2000
  $QueueBufferingMaxMessages = 1000
  $QueueBufferingMaxKbytes = 4096
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

docker rm -f $Name *>$null

$runArgs = @(
  "run", "-d",
  "--name", $Name,
  "--network", $Network,
  "-p", ("{0}:8080" -f $ApiPort),
  "-e", ("CYBERBOX__BIND_ADDR=0.0.0.0:8080"),
  "-e", ("CYBERBOX__REDPANDA_BROKERS={0}" -f $Brokers),
  "-e", ("CYBERBOX__CLICKHOUSE_URL={0}" -f $ClickHouseUrl),
  "-e", ("CYBERBOX__INGEST_MAX_EVENTS_PER_REQUEST={0}" -f $IngestMaxEventsPerRequest),
  "-e", ("CYBERBOX__INGEST_MAX_BODY_BYTES={0}" -f $IngestMaxBodyBytes),
  "-e", ("CYBERBOX__KAFKA_PRODUCER_ACKS={0}" -f $ProducerAcks),
  "-e", ("CYBERBOX__KAFKA_PRODUCER_ENABLE_IDEMPOTENCE={0}" -f $ProducerEnableIdempotence.ToString().ToLowerInvariant()),
  "-e", ("CYBERBOX__KAFKA_PRODUCER_MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION={0}" -f $ProducerMaxInFlightRequestsPerConnection),
  "-e", ("CYBERBOX__KAFKA_PRODUCER_MESSAGE_TIMEOUT_MS={0}" -f $ProducerMessageTimeoutMs),
  "-e", ("CYBERBOX__CLICKHOUSE_INSERT_ASYNC_ENABLED={0}" -f $ClickHouseInsertAsyncEnabled.ToString().ToLowerInvariant()),
  "-e", ("CYBERBOX__CLICKHOUSE_INSERT_WAIT_FOR_ASYNC={0}" -f $ClickHouseInsertWaitForAsync.ToString().ToLowerInvariant()),
  "-e", ("CYBERBOX__CLICKHOUSE_INSERT_ASYNC_DEDUPLICATE_ENABLED={0}" -f $ClickHouseInsertAsyncDeduplicateEnabled.ToString().ToLowerInvariant()),
  "-e", ("CYBERBOX__CLICKHOUSE_INSERT_DEDUPLICATION_TOKEN_ENABLED={0}" -f $ClickHouseInsertDeduplicationTokenEnabled.ToString().ToLowerInvariant()),
  "-e", ("CYBERBOX__KAFKA_PUBLISH_RAW_ENABLED=true"),
  "-e", ("CYBERBOX__KAFKA_PRODUCER_QUEUE_FULL_MAX_RETRIES={0}" -f $QueueFullMaxRetries),
  "-e", ("CYBERBOX__KAFKA_PRODUCER_QUEUE_FULL_BACKOFF_MS={0}" -f $QueueFullBackoffMs),
  "-e", ("CYBERBOX__KAFKA_PRODUCER_OVERLOAD_RETRY_AFTER_SECONDS={0}" -f $OverloadRetryAfterSeconds),
  "-e", ("CYBERBOX__KAFKA_PRODUCER_DELIVERY_TRACKER_QUEUE_SIZE={0}" -f $DeliveryTrackerQueueSize),
  "-e", ("CYBERBOX__KAFKA_PRODUCER_QUEUE_BUFFERING_MAX_MESSAGES={0}" -f $QueueBufferingMaxMessages),
  "-e", ("CYBERBOX__KAFKA_PRODUCER_QUEUE_BUFFERING_MAX_KBYTES={0}" -f $QueueBufferingMaxKbytes),
  "-e", ("RUSTUP_SKIP_UPDATE_CHECK=1"),
  "-v", "cyberbox-cargo-registry:/usr/local/cargo/registry",
  "-v", "cyberbox-cargo-git:/usr/local/cargo/git",
  "-v", ("{0}:/workspace" -f $repoRoot),
  "-w", "/workspace",
  "rust:1.93",
  "sh", "-lc",
  "/usr/bin/apt-get update && /usr/bin/apt-get install -y --no-install-recommends cmake pkg-config build-essential && /usr/local/cargo/bin/cargo run -p cyberbox-api --features kafka-native"
)

& docker @runArgs | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "failed to start api container"
}

Write-Output ("Started {0} on port {1} (strict_overload={2})" -f $Name, $ApiPort, $StrictOverloadProfile.IsPresent)
