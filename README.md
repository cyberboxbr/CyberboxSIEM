# CyberboxSIEM

High-performance, detection-first SIEM foundation in Rust + React.

## What is implemented in this baseline

- Rust workspace with API service, worker service, and core domain crates
- API contracts for event ingest, rules, search, and alerts
- OCSF-style normalized event model with tenant-aware records
- Sigma-compatible rule storage and lightweight compilation placeholder
- Stream-oriented pipeline wiring (Redpanda raw/normalized topics) and real ClickHouse event persistence/search path
- Custom React web app shell for detections, alerts, investigations, and pipeline health
- Local development stack using Docker Compose (Redpanda, ClickHouse, MinIO, Grafana, Prometheus)
- Kubernetes manifests for base and production profiles (role-based workers, autoscaling, replicated data plane)

## Quick start

### Prerequisites

- Docker Desktop
- Node.js 22+
- Rust 1.85+ (or use dockerized cargo commands)
- CMake (needed for `kafka-native` feature in API/worker)
- If `cmake` is still not found after install on Windows, restart the terminal session.

### Start infra

```powershell
docker compose -f infra/docker/docker-compose.yml up -d
```

Redpanda listeners:
- Internal (containers): `redpanda:9092`
- External (host): `localhost:19092`

### Run API (dockerized cargo)

```powershell
docker run --rm -it --network docker_default `
  -e CYBERBOX__REDPANDA_BROKERS=redpanda:9092 `
  -e CYBERBOX__CLICKHOUSE_URL=http://clickhouse:8123 `
  -v ${PWD}:/workspace -w /workspace/apps/cyberbox-api rust:1.93 `
  cargo run --features kafka-native
```

### Run worker (dockerized cargo)

```powershell
docker run --rm -it --network docker_default `
  -e CYBERBOX__REDPANDA_BROKERS=redpanda:9092 `
  -e CYBERBOX__CLICKHOUSE_URL=http://clickhouse:8123 `
  -v ${PWD}:/workspace -w /workspace/apps/cyberbox-worker rust:1.93 `
  cargo run --features kafka-native
```

### Run API with native Kafka raw-event producer

```powershell
cargo run -p cyberbox-api --features kafka-native
```

### Run worker with native Kafka raw->normalized pipeline

```powershell
cargo run -p cyberbox-worker --features kafka-native
```

### Ensure stream topics

```powershell
./scripts/create-topics.ps1 -Broker localhost:19092
```

The topic script computes partition counts from replica/worker parallelism and enforces minimums:
- `cyberbox.events.raw`: `max(raw_min_partitions, max(api_replicas, normalizer_replicas))`
- `cyberbox.events.normalized`: `max(normalized_min_partitions, max(normalizer_replicas, stream_detect_replicas, sink_replicas * sink_workers_per_replica))`
- `cyberbox.alerts`: `max(alerts_min_partitions, alert_consumer_parallelism)`

Role-split tuned example:

```powershell
./scripts/create-topics.ps1 -Broker localhost:19092 -ApiReplicas 1 -NormalizerReplicas 3 -StreamDetectReplicas 3 -SinkReplicas 4 -SinkWorkersPerReplica 6 -RawMinPartitions 24 -NormalizedMinPartitions 64
```

Reset and recreate topics (clean baseline before long soak):

```powershell
./scripts/reset-load-topics.ps1 -Broker localhost:19092 -ApiReplicas 1 -NormalizerReplicas 3 -StreamDetectReplicas 3 -SinkReplicas 4 -SinkWorkersPerReplica 6 -RawMinPartitions 24 -NormalizedMinPartitions 64
```

### Run web app

```powershell
cd web/cyberbox-ui
npm install
npm run dev
```

## API surface

- `POST /api/v1/events:ingest`
- `POST /api/v1/rules`
- `GET /api/v1/rules`
- `PATCH /api/v1/rules/{id}`
- `DELETE /api/v1/rules/{id}`
- `POST /api/v1/rules/{id}/test`
- `POST /api/v1/search:query`
- `GET /api/v1/alerts`
- `POST /api/v1/alerts/{id}:ack`
- `POST /api/v1/alerts/{id}:assign`
- `GET /api/v1/audit-logs?action=&entity_type=&actor=&from=&to=&cursor=&limit=`

### Scheduled rule payload example

```json
{
  "sigma_source": "title: Scheduled sample\nproduct: windows\ndetection:\n  selection:\n    - whoami",
  "schedule_or_stream": "scheduled",
  "schedule": {
    "interval_seconds": 20,
    "lookback_seconds": 45
  },
  "severity": "medium",
  "enabled": true
}
```

## Notes

- This repository is an implementation baseline for v1, not the full six-month finished product.
- Current fixed-rate performance target for local/prototype validation is 15,000 EPS.
- Detection execution, OIDC provider integration, and full persistence backends are intentionally scaffolded with clear extension points.
- API ingest fast path is Kafka-only (`POST /api/v1/events:ingest` validates tenant + enqueues raw event only).
- On producer saturation, ingest returns `429 Too Many Requests` with `Retry-After`.
- Oversized ingest batches are rejected with `413 Payload Too Large` (`CYBERBOX__INGEST_MAX_EVENTS_PER_REQUEST`, `CYBERBOX__INGEST_MAX_BODY_BYTES`).
- With `kafka-native` and default config, normalized events are written to ClickHouse and `/api/v1/search:query` uses ClickHouse (with in-memory fallback on query failure).
- Worker executes stream detections and scheduled detections; API request path does not run detections.
- Worker runtime supports role-based mode via `CYBERBOX__WORKER_ROLE`:
  - `normalizer`, `stream-detect`, `scheduler`, `sink`, `all`
- Worker scheduled detections are enabled for rules with `schedule_or_stream = scheduled` and per-rule schedules.
- Alert routing is Teams-only in this baseline. Enable with:
  - `CYBERBOX__TEAMS_ROUTING_ENABLED=true`
  - `CYBERBOX__TEAMS_WEBHOOK_URL=<your teams incoming webhook URL>`
- Local Docker defaults: ClickHouse user/password are `cyberbox` / `cyberbox`.
- Rules are persisted in ClickHouse table `events_hot_rules`.
- Alert state (`open` -> `acknowledged` -> `in_progress`) is persisted in ClickHouse table `events_hot_alerts`.
- Audit logs for rule and alert actions are persisted in ClickHouse table `events_hot_audit_logs`.
- `/api/v1/audit-logs` returns `{ entries, next_cursor, has_more }` for cursor-based paging.
- Scheduled rule health is persisted in `events_hot_rule_health` and included in rule rows as `scheduler_health`.
- Worker metrics endpoint is exposed at `http://localhost:9091/metrics` by default.
- ClickHouse sink tuning knobs:
  - `CYBERBOX__CLICKHOUSE_SINK_BATCH_SIZE` (default `5000`)
  - `CYBERBOX__CLICKHOUSE_SINK_BATCH_MAX_BYTES` (default `8388608`)
  - `CYBERBOX__CLICKHOUSE_SINK_FLUSH_INTERVAL_MS` (default `500`)
  - `CYBERBOX__CLICKHOUSE_SINK_MAX_RETRIES` (default `6`)
  - `CYBERBOX__CLICKHOUSE_SINK_RETRY_BACKOFF_BASE_MS` (default `250`)
  - `CYBERBOX__CLICKHOUSE_SINK_RETRY_BACKOFF_JITTER_MS` (default `200`)
  - `CYBERBOX__CLICKHOUSE_SINK_WORKER_COUNT` (default `8`)
  - `CYBERBOX__CLICKHOUSE_INSERT_ASYNC_ENABLED` (default `true`)
  - `CYBERBOX__CLICKHOUSE_INSERT_WAIT_FOR_ASYNC` (default `true`)
  - `CYBERBOX__CLICKHOUSE_INSERT_ASYNC_DEDUPLICATE_ENABLED` (default `true`)
  - `CYBERBOX__CLICKHOUSE_INSERT_DEDUPLICATION_TOKEN_ENABLED` (default `true`)
  - `CYBERBOX__STREAM_RULE_CACHE_REFRESH_INTERVAL_SECONDS` (default `15`)
  - `CYBERBOX__CLICKHOUSE_REPLICATED_TABLES_ENABLED` (default `false`, set `true` for keeper-backed replicated tables)
- Kafka producer backpressure knobs:
  - `CYBERBOX__KAFKA_PRODUCER_ACKS` (default `all`)
  - `CYBERBOX__KAFKA_PRODUCER_ENABLE_IDEMPOTENCE` (default `true`)
  - `CYBERBOX__KAFKA_PRODUCER_MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION` (default `5`)
  - `CYBERBOX__KAFKA_PRODUCER_MESSAGE_TIMEOUT_MS` (default `30000`)
  - `CYBERBOX__KAFKA_PRODUCER_QUEUE_FULL_MAX_RETRIES` (default `3`)
  - `CYBERBOX__KAFKA_PRODUCER_QUEUE_FULL_BACKOFF_MS` (default `5`)
  - `CYBERBOX__KAFKA_PRODUCER_OVERLOAD_RETRY_AFTER_SECONDS` (default `1`)
  - `CYBERBOX__KAFKA_PRODUCER_DELIVERY_TRACKER_QUEUE_SIZE` (default `100000`)
  - `CYBERBOX__KAFKA_PRODUCER_QUEUE_BUFFERING_MAX_MESSAGES` (default `50000`)
  - `CYBERBOX__KAFKA_PRODUCER_QUEUE_BUFFERING_MAX_KBYTES` (default `262144`)
- Ingest request guardrails:
  - `CYBERBOX__INGEST_MAX_EVENTS_PER_REQUEST` (default `5000`)
  - `CYBERBOX__INGEST_MAX_BODY_BYTES` (default `4194304`)
- Producer telemetry is exported on `/metrics` with enqueue counters/gauge and delivery-result counters:
  - enqueue: `kafka_producer_enqueue_*`, `kafka_producer_in_flight_count`
  - delivery: `kafka_producer_delivery_success_total`, `kafka_producer_delivery_error_total`, `kafka_producer_delivery_canceled_total`, `kafka_producer_delivery_duration_seconds`, `kafka_producer_delivery_tracker_queue_depth`
- Kafka producer records are sent without a fixed key so partitioning can scale with topic partitions.
- Sink flushes commit offsets with retries and keeps the consumer paused while pending commits are retried.
- Sink ClickHouse inserts now include per-batch deduplication tokens to reduce duplicate rows on retry/replay.
- Production ClickHouse storage guidance:
  - Use NVMe-backed volumes for hot data path.
  - Set `background_pool_size` and `background_schedule_pool_size` to match vCPU and ingestion concurrency.
  - Keep `max_bytes_to_merge_at_max_space_in_pool` high enough to avoid tiny-merge churn during sustained ingest.
- Loadgen supports `--target-eps` for fixed-rate mode and reports both p95 and p99 request latency.
- Persistence probes in load tests use `uniqExact(event_id)` for duplicate-aware accounting.
- Persistence probe controls:
  - `--persist-probe-attempts` (default `60`)
  - `--persist-probe-interval-ms` (default `2000`)
- Loadgen supports retention-window simulation:
  - `--event-age-min-seconds`
  - `--event-age-max-seconds`

## Production Kubernetes profile

Prerequisites:
- ClickHouse Operator (Altinity)
- KEDA
- Metrics Server

Apply production manifests:

```powershell
kubectl apply -k infra/k8s/prod
```

This deploys:
- 3-node Redpanda StatefulSet + replicated topics bootstrap job
- 3-node ClickHouse Keeper + ClickHouseInstallation (1 shard x 3 replicas)
- API deployment + HPA
- role-based worker deployments (`normalizer`, `stream-detect`, `scheduler`, `sink`)
- lag-based KEDA autoscaling for normalizer/stream-detect/sink roles
- PodSecurity Admission labels, default-deny app network policy, and dedicated service accounts with token mount disabled
- HPA/KEDA scale behavior tuning to reduce scale flapping during bursty ingest
- host+zone topology spread constraints and Redpanda rack-aware scheduling inputs

## Smoke and baseline

```powershell
just smoke
```

```powershell
./scripts/load-baseline.ps1
```

```powershell
./scripts/operator-flow-smoke.ps1
```

`operator-flow-smoke.ps1` waits for rule-cache warmup (`-RuleWarmupSeconds`, default `20`) before ingesting the probe event.

```powershell
cargo run --release -p cyberbox-loadgen -- --duration-seconds 30 --concurrency 12 --batch-size 100
```

Fixed-rate mode (target EPS):

```powershell
cargo run --release -p cyberbox-loadgen -- --duration-seconds 300 --concurrency 24 --batch-size 100 --target-eps 15000 --skip-persist-check
```

Max-throughput mode (no target cap):

```powershell
cargo run --release -p cyberbox-loadgen -- --duration-seconds 120 --concurrency 48 --batch-size 100 --skip-persist-check
```

Peak EPS sweep helper:

```powershell
./scripts/load-max-eps.ps1 -DurationSeconds 120 -ConcurrencyLevels 24 32 48 64 -BatchSize 100 -SkipPersistenceCheck
```

Fixed-rate soak with producer metric deltas (API + worker):

```powershell
./scripts/load-soak.ps1 -DurationSeconds 300 -TargetEps 15000 -Concurrency 24 -BatchSize 100
```

Repeatable tenant-mix + retention-profile load matrix:

```powershell
./scripts/load-matrix.ps1 -MatrixPath config/load-matrix.json
```

Use `--skip-persist-check` for faster front-door API saturation tests.

Strict overload profile to force queue saturation and validate `429` backpressure:

```powershell
./scripts/start-api-dev-container.ps1 -StrictOverloadProfile
./scripts/load-overload-429.ps1 -DurationSeconds 45 -Concurrency 96 -BatchSize 200
```

Scale raw consumers by running multiple worker replicas in one consumer group:

```powershell
./scripts/start-worker-dev-replicas.ps1 -Replicas 4 -WorkerGroupId cyberbox-worker-v1-r2
```

Role-based local worker stack (recommended):

```powershell
./scripts/start-worker-role-stack.ps1 -WorkerGroupId cyberbox-worker-v3 -ExposeRoleMetrics
./scripts/check-worker-groups.ps1 -GroupBase cyberbox-worker-v3 -MinNormalizerMembers 3 -MinStreamDetectMembers 3 -MinSinkMembers 24
./scripts/wait-worker-groups.ps1 -GroupBase cyberbox-worker-v3 -MinNormalizerMembers 3 -MinStreamDetectMembers 3 -MinSinkMembers 24 -TimeoutSeconds 1800
```

6-hour soak test:

```powershell
./scripts/load-soak.ps1 -DurationSeconds 21600 -TargetEps 15000 -Concurrency 24 -BatchSize 100 -WorkerMetricsUrl http://127.0.0.1:19191/metrics
```
