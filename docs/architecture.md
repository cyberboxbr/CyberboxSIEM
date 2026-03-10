# Architecture Overview

## v1 Design Spine

- API service (`apps/cyberbox-api`): ingest, rules, search, alerts, RBAC, audit trail.
- Worker runtime (`apps/cyberbox-worker`) split into role-based deployments:
  - `normalizer`: raw topic -> normalized topic
  - `stream-detect`: near-real-time rule evaluation on normalized stream
  - `scheduler`: scheduled rule execution loop (single replica)
  - `sink`: normalized topic -> ClickHouse hot store
- Core crates:
  - `cyberbox-models`: canonical API/domain types.
  - `cyberbox-core`: config, errors, normalization, telemetry.
  - `cyberbox-detection`: Sigma compiler + rule execution + dedupe/suppression.
  - `cyberbox-storage`: storage traits + in-memory implementation + ClickHouse adapter boundary.
  - `cyberbox-auth`: tenant-aware auth extraction + role checks.
- UI (`web/cyberbox-ui`): custom SOC web app for rule authoring, event ingestion tests, alert triage, and query-driven investigations.

## Data flow

1. Collectors forward events to API ingest endpoint.
2. API publishes raw events to `cyberbox.events.raw` on Redpanda.
3. `normalizer` workers consume raw events, normalize to OCSF envelope, and publish to `cyberbox.events.normalized`.
4. `stream-detect` workers consume normalized events, evaluate stream rules, and upsert alerts.
5. `sink` workers consume normalized events and persist them into ClickHouse hot storage (`cyberbox.events_hot` by default).
6. `scheduler` worker executes scheduled detections using per-rule interval and lookback controls against recent ClickHouse events.
7. Analysts investigate via search API (ClickHouse-backed with fallback) and act on alerts.
8. Alert notifications are routed to Microsoft Teams webhook when enabled.
9. API and workers expose Prometheus metrics; Kafka lag drives autoscaling for consumer roles.

## ClickHouse structures

- Events table: `cyberbox.events_hot`
- Rules table: `cyberbox.events_hot_rules` (ReplacingMergeTree for rule versioning)
- Alerts table: `cyberbox.events_hot_alerts` (ReplacingMergeTree for state transitions)
- Audit logs table: `cyberbox.events_hot_audit_logs` (rule/alert control-plane history)
- Rollup table: `cyberbox.events_hot_hourly_rollup`
- Materialized view: `cyberbox.events_hot_hourly_rollup_mv` (hourly source/tenant event counts)

## SaaS-ready single-tenant model

- Every major record type carries `tenant_id`.
- Authorization denies cross-tenant access regardless of deployment mode.
- Current runtime is single-tenant operationally but logically tenant-isolated.

## Production Kubernetes profile

- Redpanda runs as a 3-node StatefulSet with topic replication factor 3.
- ClickHouse runs as a 1-shard x 3-replica cluster (operator-managed) with a 3-node ClickHouse Keeper quorum.
- Worker roles are deployed independently with role-specific resource sizing.
- KEDA scales normalizer/stream-detect/sink from Kafka lag per consumer group.
