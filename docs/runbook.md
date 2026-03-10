# Operations Runbook (Baseline)

## Local startup

1. Start infra stack:
   - `docker compose -f infra/docker/docker-compose.yml up -d`
2. Ensure stream topics:
   - `./scripts/create-topics.ps1 -Broker localhost:19092`
   - For role-split worker throughput tuning (recommended):
     - `./scripts/create-topics.ps1 -Broker localhost:19092 -ApiReplicas 1 -NormalizerReplicas 3 -StreamDetectReplicas 3 -SinkReplicas 4 -SinkWorkersPerReplica 6 -RawMinPartitions 24 -NormalizedMinPartitions 64`
3. Start API and worker with Kafka features:
   - `cargo run -p cyberbox-api --features kafka-native`
   - `cargo run -p cyberbox-worker --features kafka-native`
   - Or dockerized dev containers:
     - `./scripts/start-api-dev-container.ps1`
     - `./scripts/start-worker-dev-replicas.ps1 -Replicas 1`
   - Preferred role-split worker stack:
     - `./scripts/start-worker-role-stack.ps1 -WorkerGroupId cyberbox-worker-v3 -ExposeRoleMetrics`
   - If Cargo fails with `is cmake not installed?`, restart terminal or prepend `C:\Program Files\CMake\bin` to `PATH` in that shell.
   - Optional Teams routing:
     - `setx CYBERBOX__TEAMS_ROUTING_ENABLED true`
     - `setx CYBERBOX__TEAMS_WEBHOOK_URL "<teams webhook url>"`
4. Start web app with `npm run dev` under `web/cyberbox-ui`.
5. Open UI at `http://localhost:5173`.

## Production-style Kubernetes startup

1. Install cluster prerequisites:
   - ClickHouse Operator (Altinity CRDs/controllers)
   - KEDA (for Kafka lag autoscaling)
   - Metrics Server (for HPA CPU/memory signals)
2. Build and push `siem-api` and `siem-worker` images.
3. Update runtime secrets in `infra/k8s/prod/app/runtime-secrets.yaml`:
   - `CYBERBOX__CLICKHOUSE_PASSWORD`
   - `CYBERBOX__OIDC_ISSUER`
   - `CYBERBOX__OIDC_AUDIENCE`
   - `CYBERBOX__TEAMS_WEBHOOK_URL` (if used)
4. Apply the production kustomization:
   - `kubectl apply -k infra/k8s/prod`
5. Verify platform quorum:
   - `kubectl -n cyberbox get pods -l app=redpanda`
   - `kubectl -n cyberbox get pods -l app=clickhouse-keeper`
   - `kubectl -n cyberbox get chi`
6. Verify app deployments:
   - `kubectl -n cyberbox get deploy cyberbox-api cyberbox-worker-normalizer cyberbox-worker-stream-detect cyberbox-worker-scheduler cyberbox-worker-sink`
7. Verify autoscaling objects:
   - `kubectl -n cyberbox get hpa`
   - `kubectl -n cyberbox get scaledobject`
8. Verify security controls:
   - `kubectl -n cyberbox get networkpolicy`
   - `kubectl -n cyberbox get sa cyberbox-api cyberbox-worker -o yaml | findstr automountServiceAccountToken`

## Worker role map (prod profile)

1. `cyberbox-worker-normalizer`:
   - consumes `cyberbox.events.raw`
   - produces `cyberbox.events.normalized`
   - autoscaled by lag of consumer group `cyberbox-worker-prod-normalizer`
2. `cyberbox-worker-stream-detect`:
   - consumes `cyberbox.events.normalized`
   - evaluates stream detections
   - autoscaled by lag of consumer group `cyberbox-worker-prod-stream-detect`
3. `cyberbox-worker-sink`:
   - consumes `cyberbox.events.normalized`
   - writes batches to ClickHouse
   - autoscaled by lag of consumer group `cyberbox-worker-prod-clickhouse-sink`
4. `cyberbox-worker-scheduler`:
   - executes scheduled rules
   - intentionally fixed at one replica to avoid duplicate scheduled executions

## Smoke test sequence

1. `GET /healthz` returns `{"status":"ok"...}`.
2. `POST /api/v1/rules` with a Sigma rule succeeds.
3. `POST /api/v1/events:ingest` with matching payload succeeds.
4. Verify Redpanda receives records in both raw and normalized topics:
   - `docker exec docker-redpanda-1 rpk topic describe cyberbox.events.raw -p -X brokers=localhost:9092`
   - `docker exec docker-redpanda-1 rpk topic describe cyberbox.events.normalized -p -X brokers=localhost:9092`
5. Verify ClickHouse receives normalized records:
   - `docker exec docker-clickhouse-1 clickhouse-client --user cyberbox --password cyberbox --query "SELECT count() FROM cyberbox.events_hot"`
6. `POST /api/v1/search:query` returns rows from ClickHouse.
7. Verify alert persistence in ClickHouse:
   - `docker exec docker-clickhouse-1 clickhouse-client --user cyberbox --password cyberbox --query "SELECT alert_id, status, assignee FROM cyberbox.events_hot_alerts FINAL ORDER BY updated_at DESC LIMIT 5"`
8. Verify rollup MV output:
   - `docker exec docker-clickhouse-1 clickhouse-client --user cyberbox --password cyberbox --query "SELECT bucket_start, tenant_id, source, sum(events_count) FROM cyberbox.events_hot_hourly_rollup GROUP BY bucket_start, tenant_id, source ORDER BY bucket_start DESC LIMIT 5"`
9. `GET /api/v1/alerts` shows at least one alert.
10. UI dashboard updates counters after refresh.
11. Scheduled detection smoke:
   - Create a rule with `schedule_or_stream = scheduled` and `schedule.interval_seconds` / `schedule.lookback_seconds`.
   - Ingest a matching event.
   - Verify events older than lookback are not alerted.
   - Verify events are evaluated according to rule interval.
12. Rule management smoke:
   - `PATCH /api/v1/rules/{id}` with `{ "enabled": false }`, then re-enable with `true`.
   - `PATCH /api/v1/rules/{id}` with updated `schedule`.
   - `DELETE /api/v1/rules/{id}` and confirm it no longer appears in `GET /api/v1/rules`.
13. Teams routing smoke (if enabled):
   - Trigger a detection that creates an alert.
   - Verify a Teams message arrives for that alert ID.
14. Audit log verification:
   - `docker exec docker-clickhouse-1 clickhouse-client --user cyberbox --password cyberbox --query "SELECT action, actor, entity_type, entity_id, event_time FROM cyberbox.events_hot_audit_logs ORDER BY event_time DESC LIMIT 20"`
15. Scheduler metrics verification:
   - `curl http://localhost:9091/metrics | findstr scheduler_rule_`
16. Strict overload/backpressure smoke:
   - `./scripts/start-api-dev-container.ps1 -StrictOverloadProfile`
   - `./scripts/load-overload-429.ps1 -DurationSeconds 45 -Concurrency 96 -BatchSize 200`

## Repeatable tenant/retention matrix

1. Review or edit `config/load-matrix.json`.
2. Run matrix:
   - `./scripts/load-matrix.ps1 -MatrixPath config/load-matrix.json`
3. Optional faster API-front-door tests:
   - `./scripts/load-matrix.ps1 -MatrixPath config/load-matrix.json -SkipPersistenceCheck`
4. Output location:
   - `logs/load-matrix/matrix-<timestamp>/matrix-summary.json`
   - one subfolder per scenario with per-tenant reports

## 6-hour soak procedure (local)

1. Start infrastructure:
   - `docker compose -f infra/docker/docker-compose.yml up -d`
2. Start API:
   - `./scripts/start-api-dev-container.ps1`
3. Start role-based workers:
   - `./scripts/start-worker-role-stack.ps1 -WorkerGroupId cyberbox-worker-v3 -NormalizerReplicas 3 -StreamDetectReplicas 3 -SchedulerReplicas 1 -SinkReplicas 4 -SinkWorkerCount 6 -SinkBatchSize 10000 -SinkFlushIntervalMs 400 -ExposeRoleMetrics`
4. Ensure topic partitioning for the role topology:
   - `./scripts/create-topics.ps1 -Broker localhost:19092 -ApiReplicas 1 -NormalizerReplicas 3 -StreamDetectReplicas 3 -SinkReplicas 4 -SinkWorkersPerReplica 6 -RawMinPartitions 24 -NormalizedMinPartitions 64`
   - for clean long-run baselines, reset topics first:
     - `./scripts/reset-load-topics.ps1 -Broker localhost:19092 -ApiReplicas 1 -NormalizerReplicas 3 -StreamDetectReplicas 3 -SinkReplicas 4 -SinkWorkersPerReplica 6 -RawMinPartitions 24 -NormalizedMinPartitions 64`
5. Verify consumer-group health before load:
   - `./scripts/check-worker-groups.ps1 -GroupBase cyberbox-worker-v3 -MinNormalizerMembers 3 -MinStreamDetectMembers 3 -MinSinkMembers 24`
   - expected: `all_healthy=true`
   - optional wait helper:
     - `./scripts/wait-worker-groups.ps1 -GroupBase cyberbox-worker-v3 -MinNormalizerMembers 3 -MinStreamDetectMembers 3 -MinSinkMembers 24 -TimeoutSeconds 1800`
6. Run 6-hour soak:
- `./scripts/load-soak.ps1 -DurationSeconds 21600 -TargetEps 15000 -Concurrency 24 -BatchSize 100 -WorkerMetricsUrl http://127.0.0.1:19191/metrics`
7. Verify consumer-group health and lag after load:
   - `./scripts/check-worker-groups.ps1 -GroupBase cyberbox-worker-v3 -MinNormalizerMembers 3 -MinStreamDetectMembers 3 -MinSinkMembers 24`
8. Review reports:
   - `logs/eps-load-soak-*.json`
   - `logs/load-soak-baseline-*.json`

## Known baseline limits

- Stream consumers require a reachable internal broker address (`redpanda:9092`) in containerized runs.
- OIDC is represented through trusted headers in local/dev mode.
