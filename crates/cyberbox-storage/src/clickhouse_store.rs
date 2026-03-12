use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use cyberbox_core::CyberboxError;
use cyberbox_models::{
    AlertRecord, AlertStatus, AssignAlertRequest, AuditLogRecord, CaseRecord, CaseStatus,
    CloseAlertRequest, DetectionMode, DetectionRule, EnrichmentMetadata, EventEnvelope,
    EventSource, RuleScheduleConfig, RuleSchedulerHealth, SearchQueryRequest, SearchQueryResponse,
    Severity, UpdateCaseRequest,
};

use crate::traits::{AlertStore, CaseStore, EventStore, RuleStore};

#[derive(Clone)]
pub struct ClickHouseEventStore {
    client: reqwest::Client,
    /// Bounds the number of in-flight ClickHouse HTTP requests to prevent
    /// thundering-herd during burst ingest.  Equivalent to
    /// `tower::ServiceBuilder::concurrency_limit()` but applied directly to
    /// the reqwest call site rather than a tower Service chain.
    ///
    /// Default: 64 concurrent requests.  Override via `with_concurrency_limit`.
    concurrency_limiter: std::sync::Arc<tokio::sync::Semaphore>,
    base_url: String,
    user: String,
    password: String,
    database: String,
    table: String,
    insert_async_enabled: bool,
    insert_wait_for_async: bool,
    insert_async_deduplicate_enabled: bool,
    insert_deduplication_token_enabled: bool,
    replicated_tables_enabled: bool,
    retention_days_hot: u32,
    rules_table: String,
    alerts_table: String,
    audits_table: String,
    rule_health_table: String,
    hourly_rollup_table: String,
    hourly_rollup_mv: String,
    watermarks_table: String,
    cases_table: String,
}

#[derive(Debug, Deserialize)]
struct ClickHouseJsonResponse {
    data: Vec<Value>,
}

impl ClickHouseEventStore {
    /// Default maximum concurrency for ClickHouse HTTP requests.
    const DEFAULT_CONCURRENCY_LIMIT: usize = 64;

    pub fn new(url: &str, user: &str, password: &str, database: &str, table: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            concurrency_limiter: std::sync::Arc::new(tokio::sync::Semaphore::new(
                Self::DEFAULT_CONCURRENCY_LIMIT,
            )),
            base_url: url.trim_end_matches('/').to_string(),
            user: user.to_string(),
            password: password.to_string(),
            database: database.to_string(),
            table: table.to_string(),
            insert_async_enabled: true,
            insert_wait_for_async: true,
            insert_async_deduplicate_enabled: true,
            insert_deduplication_token_enabled: true,
            replicated_tables_enabled: false,
            retention_days_hot: 0,
            rules_table: format!("{}_rules", table),
            alerts_table: format!("{}_alerts", table),
            audits_table: format!("{}_audit_logs", table),
            rule_health_table: format!("{}_rule_health", table),
            hourly_rollup_table: format!("{}_hourly_rollup", table),
            hourly_rollup_mv: format!("{}_hourly_rollup_mv", table),
            watermarks_table: format!("{}_rule_watermarks", table),
            cases_table: format!("{}_cases", table),
        }
    }

    /// Override the maximum number of concurrent ClickHouse HTTP requests.
    ///
    /// Lower values protect ClickHouse from thundering-herd bursts at the cost
    /// of higher tail latency under saturation.  Default: 64.
    pub fn with_concurrency_limit(mut self, limit: usize) -> Self {
        self.concurrency_limiter = std::sync::Arc::new(tokio::sync::Semaphore::new(limit.max(1)));
        self
    }

    pub fn with_replicated_tables_enabled(mut self, enabled: bool) -> Self {
        self.replicated_tables_enabled = enabled;
        self
    }

    /// Set the hot-tier retention TTL.  Days = 0 disables the TTL clause.
    pub fn with_retention_days_hot(mut self, days: u32) -> Self {
        self.retention_days_hot = days;
        self
    }

    pub fn with_insert_settings(mut self, async_enabled: bool, wait_for_async: bool) -> Self {
        self.insert_async_enabled = async_enabled;
        self.insert_wait_for_async = wait_for_async;
        self
    }

    pub fn with_insert_deduplication_settings(
        mut self,
        async_deduplicate_enabled: bool,
        deduplication_token_enabled: bool,
    ) -> Self {
        self.insert_async_deduplicate_enabled = async_deduplicate_enabled;
        self.insert_deduplication_token_enabled = deduplication_token_enabled;
        self
    }

    pub async fn insert_events_with_deduplication_token(
        &self,
        events: &[EventEnvelope],
        deduplication_token: Option<&str>,
    ) -> Result<(), CyberboxError> {
        if events.is_empty() {
            return Ok(());
        }

        let mut query = format!(
            "INSERT INTO {}.{} \
             (event_id, tenant_id, source, event_time, ingest_time, \
              class_uid, severity_id, \
              computer_name, event_code, actor_user, process_image, \
              src_ip, dst_ip, dst_port, \
              raw_payload, ocsf_record, enrichment, integrity_hash)",
            self.database, self.table
        );
        query.push_str(" SETTINGS async_insert=");
        query.push_str(if self.insert_async_enabled { "1" } else { "0" });
        query.push_str(", wait_for_async_insert=");
        query.push_str(if self.insert_wait_for_async { "1" } else { "0" });
        query.push_str(", async_insert_deduplicate=");
        query.push_str(if self.insert_async_deduplicate_enabled {
            "1"
        } else {
            "0"
        });
        if self.insert_deduplication_token_enabled {
            if let Some(token) = deduplication_token {
                query.push_str(", insert_deduplication_token='");
                query.push_str(&escape_sql_literal(token));
                query.push('\'');
            }
        }
        query.push_str(" FORMAT JSONEachRow\n");

        for event in events {
            // Extract typed fields from the raw payload.  Each field tries a list
            // of key names used by different log sources (Windows, Linux, CEF, etc.)
            // so the same column is populated regardless of the source format.
            let raw = &event.raw_payload;
            let computer_name = extract_str(
                raw,
                &[
                    "ComputerName",
                    "computer_name",
                    "Hostname",
                    "hostname",
                    "host",
                    "host.name",
                ],
            );
            let event_code = extract_str(
                raw,
                &[
                    "EventID",
                    "event_code",
                    "EventCode",
                    "winlog.event_id",
                    "event.code",
                ],
            );
            let actor_user = extract_str(
                raw,
                &[
                    "User",
                    "SubjectUserName",
                    "TargetUserName",
                    "user",
                    "user.name",
                    "Username",
                    "username",
                    "AccountName",
                ],
            );
            let process_image = extract_str(
                raw,
                &[
                    "Image",
                    "process.name",
                    "process.executable",
                    "ProcessName",
                    "CommandLine",
                ],
            );
            let src_ip = extract_str(
                raw,
                &[
                    "SourceIp",
                    "source.ip",
                    "src_ip",
                    "SrcAddr",
                    "IpAddress",
                    "ipAddress",
                    "client_ip",
                ],
            );
            let dst_ip = extract_str(
                raw,
                &[
                    "DestinationIp",
                    "destination.ip",
                    "dst_ip",
                    "DstAddr",
                    "DestAddress",
                ],
            );
            let dst_port = extract_u16(
                raw,
                &[
                    "DestinationPort",
                    "destination.port",
                    "dst_port",
                    "DstPort",
                    "DestPort",
                ],
            );
            // class_uid and severity_id come from the OCSF record, not raw payload.
            let class_uid = event
                .ocsf_record
                .get("class_uid")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            // Map class_uid ranges to a OCSF severity_id (0 = unknown by default;
            // rules that emit severity override this at alert time).
            let severity_id: u8 = 0;

            let row = json!({
                "event_id": event.event_id.to_string(),
                "tenant_id": event.tenant_id,
                "source": source_to_string(&event.source),
                "event_time": format_clickhouse_datetime(event.event_time),
                "ingest_time": format_clickhouse_datetime(event.ingest_time),
                "class_uid": class_uid,
                "severity_id": severity_id,
                "computer_name": computer_name,
                "event_code": event_code,
                "actor_user": actor_user,
                "process_image": process_image,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "raw_payload": event.raw_payload.to_string(),
                "ocsf_record": event.ocsf_record.to_string(),
                "enrichment": serde_json::to_string(&event.enrichment).map_err(|err| CyberboxError::Internal(format!("enrichment serialization failed: {err}")))?,
                "integrity_hash": event.integrity_hash,
            });

            query.push_str(&serde_json::to_string(&row).map_err(|err| {
                CyberboxError::Internal(format!("row serialization failed: {err}"))
            })?);
            query.push('\n');
        }

        self.execute_sql(&query).await.map(|_| ())
    }

    fn merge_tree_engine(&self, table_name: &str) -> String {
        if self.replicated_tables_enabled {
            format!(
                "ReplicatedMergeTree('/clickhouse/tables/{{shard}}/{table_name}', '{{replica}}')"
            )
        } else {
            "MergeTree".to_string()
        }
    }

    fn replacing_merge_tree_engine(&self, table_name: &str, version_column: &str) -> String {
        if self.replicated_tables_enabled {
            format!(
                "ReplicatedReplacingMergeTree('/clickhouse/tables/{{shard}}/{table_name}', '{{replica}}', {version_column})"
            )
        } else {
            format!("ReplacingMergeTree({version_column})")
        }
    }

    fn summing_merge_tree_engine(&self, table_name: &str) -> String {
        if self.replicated_tables_enabled {
            format!(
                "ReplicatedSummingMergeTree('/clickhouse/tables/{{shard}}/{table_name}', '{{replica}}')"
            )
        } else {
            "SummingMergeTree".to_string()
        }
    }

    pub async fn ensure_schema(&self) -> Result<(), CyberboxError> {
        let ensure_db = format!("CREATE DATABASE IF NOT EXISTS {}", self.database);
        self.execute_sql(&ensure_db).await?;

        let events_engine = self.merge_tree_engine(&self.table);
        let alerts_engine = self.replacing_merge_tree_engine(&self.alerts_table, "version");
        let audits_engine = self.merge_tree_engine(&self.audits_table);
        let rules_engine = self.replacing_merge_tree_engine(&self.rules_table, "version");
        let rule_health_engine =
            self.replacing_merge_tree_engine(&self.rule_health_table, "version");
        let rollup_engine = self.summing_merge_tree_engine(&self.hourly_rollup_table);

        // ── Events table ────────────────────────────────────────────────────────
        // tenant_id / source use LowCardinality for dictionary compression
        // (~4x storage reduction for typical cardinalities < 10k unique values).
        //
        // Raw string columns use ZSTD(3) codec — good balance of compression
        // ratio vs CPU cost for JSON payloads.
        //
        // Extracted typed columns (computer_name, actor_user, etc.) are indexed
        // with bloom_filter skip indexes so queries on those fields avoid full
        // partition scans.  event_code uses set() because it has low cardinality
        // (Windows EventIDs are a bounded set).
        let event_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{} (
                -- Core identity columns
                event_id     UUID,
                tenant_id    LowCardinality(String),
                source       LowCardinality(String),
                event_time   DateTime64(3, 'UTC'),
                ingest_time  DateTime64(3, 'UTC'),
                -- OCSF classification
                class_uid    UInt32 DEFAULT 0,
                severity_id  UInt8  DEFAULT 0,
                -- Extracted event fields (populated at ingest from raw_payload).
                -- Kept as String / LowCardinality for simplicity across log formats.
                computer_name LowCardinality(String) DEFAULT '',
                event_code    String DEFAULT '',
                actor_user    LowCardinality(String) DEFAULT '',
                process_image String DEFAULT '',
                src_ip        String DEFAULT '',
                dst_ip        String DEFAULT '',
                dst_port      UInt16 DEFAULT 0,
                -- Raw payloads: compressed JSON blobs kept for full-text search
                -- and rule evaluation; ZSTD(3) cuts storage ~60-70 % vs plain.
                raw_payload   String CODEC(ZSTD(3)),
                ocsf_record   String CODEC(ZSTD(3)),
                enrichment    String CODEC(ZSTD(3)),
                integrity_hash String,
                -- Skip indexes: let ClickHouse skip granules that can't match.
                -- bloom_filter gives ~1 % false-positive rate on string fields.
                INDEX idx_computer_name computer_name TYPE bloom_filter(0.01) GRANULARITY 4,
                INDEX idx_actor_user    actor_user    TYPE bloom_filter(0.01) GRANULARITY 4,
                INDEX idx_src_ip        src_ip        TYPE bloom_filter(0.01) GRANULARITY 4,
                INDEX idx_dst_ip        dst_ip        TYPE bloom_filter(0.01) GRANULARITY 4,
                INDEX idx_event_code    event_code    TYPE set(200)           GRANULARITY 4
            )
            ENGINE = {}
            PARTITION BY toDate(event_time)
            ORDER BY (tenant_id, event_time, event_id)
            SETTINGS index_granularity = 8192
            "#,
            self.database, self.table, events_engine
        );

        self.execute_sql(&event_ddl).await?;

        // ── Events table: forward-migration for existing deployments ─────────
        // ADD COLUMN IF NOT EXISTS is idempotent — safe to run on every startup.
        // New deployments get the columns from CREATE TABLE above; existing ones
        // pick them up here without manual intervention.
        let event_migrations: &[(&str, &str)] = &[
            ("class_uid", "UInt32 DEFAULT 0"),
            ("severity_id", "UInt8 DEFAULT 0"),
            ("computer_name", "LowCardinality(String) DEFAULT ''"),
            ("event_code", "String DEFAULT ''"),
            ("actor_user", "LowCardinality(String) DEFAULT ''"),
            ("process_image", "String DEFAULT ''"),
            ("src_ip", "String DEFAULT ''"),
            ("dst_ip", "String DEFAULT ''"),
            ("dst_port", "UInt16 DEFAULT 0"),
        ];
        for (col, ty) in event_migrations {
            let stmt = format!(
                "ALTER TABLE {}.{} ADD COLUMN IF NOT EXISTS {} {}",
                self.database, self.table, col, ty
            );
            self.execute_sql(&stmt).await?;
        }

        // ── Events table: TTL (hot-tier retention) ───────────────────────────
        // MODIFY TTL is idempotent — ClickHouse no-ops if the TTL expression
        // matches the one already stored.  Running at every startup is safe.
        // TTL = 0 means "no expiry"; skip the ALTER entirely in that case.
        if self.retention_days_hot > 0 {
            let ttl_stmt = format!(
                "ALTER TABLE {}.{} MODIFY TTL toDate(event_time) + INTERVAL {} DAY",
                self.database, self.table, self.retention_days_hot
            );
            self.execute_sql(&ttl_stmt).await?;
            tracing::info!(
                retention_days = self.retention_days_hot,
                table = %self.table,
                "ClickHouse hot-tier TTL set"
            );
        }

        let alerts_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{} (
                alert_id UUID,
                tenant_id String,
                rule_id UUID,
                first_seen DateTime64(3, 'UTC'),
                last_seen DateTime64(3, 'UTC'),
                status String,
                evidence_refs String,
                routing_state String,
                assignee Nullable(String),
                hit_count UInt64,
                mitre_attack String,
                resolution Nullable(String),
                close_note Nullable(String),
                updated_at DateTime64(3, 'UTC'),
                version UInt64
            )
            ENGINE = {}
            PARTITION BY toDate(first_seen)
            ORDER BY (tenant_id, alert_id)
            "#,
            self.database, self.alerts_table, alerts_engine
        );
        self.execute_sql(&alerts_ddl).await?;

        let audits_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{} (
                audit_id UUID,
                tenant_id String,
                actor String,
                action String,
                entity_type String,
                entity_id String,
                event_time DateTime64(3, 'UTC'),
                before_state String,
                after_state String
            )
            ENGINE = {}
            PARTITION BY toDate(event_time)
            ORDER BY (tenant_id, event_time, audit_id)
            "#,
            self.database, self.audits_table, audits_engine
        );
        self.execute_sql(&audits_ddl).await?;

        let rules_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{} (
                rule_id UUID,
                tenant_id String,
                sigma_source String,
                compiled_plan String,
                schedule_or_stream String,
                schedule_interval_seconds UInt32,
                schedule_lookback_seconds UInt32,
                severity String,
                enabled UInt8,
                deleted UInt8,
                updated_at DateTime64(3, 'UTC'),
                version UInt64
            )
            ENGINE = {}
            PARTITION BY cityHash64(tenant_id) % 8
            ORDER BY (tenant_id, rule_id)
            "#,
            self.database, self.rules_table, rules_engine
        );
        self.execute_sql(&rules_ddl).await?;
        let rules_alter_interval = format!(
            "ALTER TABLE {}.{} ADD COLUMN IF NOT EXISTS schedule_interval_seconds UInt32 DEFAULT 0",
            self.database, self.rules_table
        );
        self.execute_sql(&rules_alter_interval).await?;
        let rules_alter_lookback = format!(
            "ALTER TABLE {}.{} ADD COLUMN IF NOT EXISTS schedule_lookback_seconds UInt32 DEFAULT 0",
            self.database, self.rules_table
        );
        self.execute_sql(&rules_alter_lookback).await?;
        let rules_alter_deleted = format!(
            "ALTER TABLE {}.{} ADD COLUMN IF NOT EXISTS deleted UInt8 DEFAULT 0",
            self.database, self.rules_table
        );
        self.execute_sql(&rules_alter_deleted).await?;

        let rule_health_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{} (
                rule_id UUID,
                tenant_id String,
                run_count UInt64,
                skipped_by_interval_count UInt64,
                match_count UInt64,
                error_count UInt64,
                last_run_duration_seconds Float64,
                updated_at DateTime64(3, 'UTC'),
                version UInt64
            )
            ENGINE = {}
            PARTITION BY cityHash64(tenant_id) % 8
            ORDER BY (tenant_id, rule_id)
            "#,
            self.database, self.rule_health_table, rule_health_engine
        );
        self.execute_sql(&rule_health_ddl).await?;

        let rollup_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{} (
                bucket_start DateTime('UTC'),
                tenant_id String,
                source String,
                events_count UInt64
            )
            ENGINE = {}
            ORDER BY (tenant_id, source, bucket_start)
            "#,
            self.database, self.hourly_rollup_table, rollup_engine
        );
        self.execute_sql(&rollup_ddl).await?;

        let rollup_mv = format!(
            r#"
            CREATE MATERIALIZED VIEW IF NOT EXISTS {}.{}
            TO {}.{}
            AS
            SELECT
                toStartOfHour(event_time) AS bucket_start,
                tenant_id,
                source,
                count() AS events_count
            FROM {}.{}
            GROUP BY bucket_start, tenant_id, source
            "#,
            self.database,
            self.hourly_rollup_mv,
            self.database,
            self.hourly_rollup_table,
            self.database,
            self.table
        );
        self.execute_sql(&rollup_mv).await?;

        // Scheduler watermarks — one row per (tenant_id, rule_id), last-write-wins via
        // ReplacingMergeTree(updated_at).  Always query with FINAL.
        let watermarks_engine = if self.replicated_tables_enabled {
            format!(
                "ReplicatedReplacingMergeTree('/clickhouse/tables/{{shard}}/{db}/{tbl}', '{{replica}}', updated_at)",
                db = self.database,
                tbl = self.watermarks_table
            )
        } else {
            "ReplacingMergeTree(updated_at)".to_string()
        };
        let watermarks_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{} (
                rule_id     UUID,
                tenant_id   String,
                last_run_at DateTime64(3, 'UTC'),
                updated_at  DateTime64(3, 'UTC')
            )
            ENGINE = {}
            ORDER BY (tenant_id, rule_id)
            "#,
            self.database, self.watermarks_table, watermarks_engine
        );
        self.execute_sql(&watermarks_ddl).await?;

        let cases_engine = self.replacing_merge_tree_engine(&self.cases_table, "version");
        let cases_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{} (
                case_id     UUID,
                tenant_id   String,
                title       String,
                description String DEFAULT '',
                status      String,
                severity    String,
                alert_ids   String,
                assignee    Nullable(String),
                created_by  String,
                created_at  DateTime64(3, 'UTC'),
                updated_at  DateTime64(3, 'UTC'),
                sla_due_at  Nullable(DateTime64(3, 'UTC')),
                closed_at   Nullable(DateTime64(3, 'UTC')),
                tags        String,
                version     UInt64
            )
            ENGINE = {}
            PARTITION BY toDate(created_at)
            ORDER BY (tenant_id, case_id)
            "#,
            self.database, self.cases_table, cases_engine
        );
        self.execute_sql(&cases_ddl).await?;

        Ok(())
    }

    pub async fn append_audit_log(&self, audit: &AuditLogRecord) -> Result<(), CyberboxError> {
        let row = json!({
            "audit_id": audit.audit_id.to_string(),
            "tenant_id": audit.tenant_id,
            "actor": audit.actor,
            "action": audit.action,
            "entity_type": audit.entity_type,
            "entity_id": audit.entity_id,
            "event_time": format_clickhouse_datetime(audit.timestamp),
            "before_state": audit.before.to_string(),
            "after_state": audit.after.to_string()
        });

        let query = format!(
            "INSERT INTO {}.{} (audit_id, tenant_id, actor, action, entity_type, entity_id, event_time, before_state, after_state) FORMAT JSONEachRow\n{}\n",
            self.database,
            self.audits_table,
            serde_json::to_string(&row)
                .map_err(|err| CyberboxError::Internal(format!("audit row serialization failed: {err}")))?
        );
        self.execute_sql(&query).await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_audit_logs(
        &self,
        tenant_id: &str,
        action: Option<&str>,
        entity_type: Option<&str>,
        actor: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        cursor: Option<(DateTime<Utc>, Uuid)>,
        limit: u64,
    ) -> Result<Vec<AuditLogRecord>, CyberboxError> {
        let mut filters = vec![format!("tenant_id = '{}'", escape_sql_literal(tenant_id))];
        if let Some(value) = action {
            filters.push(format!("action = '{}'", escape_sql_literal(value)));
        }
        if let Some(value) = entity_type {
            filters.push(format!("entity_type = '{}'", escape_sql_literal(value)));
        }
        if let Some(value) = actor {
            filters.push(format!("actor = '{}'", escape_sql_literal(value)));
        }
        if let Some(value) = from {
            filters.push(format!(
                "event_time >= toDateTime64('{}', 3, 'UTC')",
                format_clickhouse_datetime(value)
            ));
        }
        if let Some(value) = to {
            filters.push(format!(
                "event_time <= toDateTime64('{}', 3, 'UTC')",
                format_clickhouse_datetime(value)
            ));
        }
        if let Some((cursor_ts, cursor_id)) = cursor {
            let timestamp = format_clickhouse_datetime(cursor_ts);
            filters.push(format!(
                "(event_time < toDateTime64('{timestamp}', 3, 'UTC') OR (event_time = toDateTime64('{timestamp}', 3, 'UTC') AND audit_id < toUUID('{cursor_id}')))"
            ));
        }

        let query = format!(
            "SELECT audit_id, tenant_id, actor, action, entity_type, entity_id, event_time, before_state, after_state \
             FROM {}.{} \
             WHERE {} \
             ORDER BY event_time DESC, audit_id DESC \
             LIMIT {} \
             FORMAT JSON",
            self.database,
            self.audits_table,
            filters.join(" AND "),
            limit.max(1)
        );

        let response = self.execute_sql_json(&query).await?;
        response
            .data
            .iter()
            .map(parse_audit_row)
            .collect::<Result<Vec<_>, _>>()
    }

    pub async fn upsert_rule_scheduler_health(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
        health: &RuleSchedulerHealth,
    ) -> Result<(), CyberboxError> {
        let now = Utc::now();
        let version = now.timestamp_millis().max(0) as u64;
        let row = json!({
            "rule_id": rule_id.to_string(),
            "tenant_id": tenant_id,
            "run_count": health.run_count,
            "skipped_by_interval_count": health.skipped_by_interval_count,
            "match_count": health.match_count,
            "error_count": health.error_count,
            "last_run_duration_seconds": health.last_run_duration_seconds,
            "updated_at": format_clickhouse_datetime(now),
            "version": version
        });

        let query = format!(
            "INSERT INTO {}.{} (rule_id, tenant_id, run_count, skipped_by_interval_count, match_count, error_count, last_run_duration_seconds, updated_at, version) FORMAT JSONEachRow\n{}\n",
            self.database,
            self.rule_health_table,
            serde_json::to_string(&row)
                .map_err(|err| CyberboxError::Internal(format!("rule health row serialization failed: {err}")))?,
        );
        self.execute_sql(&query).await?;
        Ok(())
    }

    pub async fn list_rule_scheduler_health(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<(Uuid, RuleSchedulerHealth)>, CyberboxError> {
        let query = format!(
            "SELECT rule_id, run_count, skipped_by_interval_count, match_count, error_count, last_run_duration_seconds \
             FROM {}.{} FINAL \
             WHERE tenant_id = '{}' \
             ORDER BY rule_id \
             FORMAT JSON",
            self.database,
            self.rule_health_table,
            escape_sql_literal(tenant_id)
        );
        let response = self.execute_sql_json(&query).await?;
        response
            .data
            .iter()
            .map(parse_rule_scheduler_health_row)
            .collect::<Result<Vec<_>, _>>()
    }

    /// Purge all events for a tenant from the hot-tier events table.
    ///
    /// Uses a ClickHouse lightweight DELETE mutation.  Mutations are eventually
    /// consistent — the rows are logically deleted immediately but the underlying
    /// part files are merged/cleaned up asynchronously by the MergeTree engine.
    /// This is appropriate for GDPR right-to-erasure: the rows become invisible
    /// to all queries immediately after the mutation is enqueued.
    pub async fn delete_tenant_events(&self, tenant_id: &str) -> Result<u64, CyberboxError> {
        // Count first so we can return how many rows were affected.
        let count_sql = format!(
            "SELECT count() AS n FROM {}.{} WHERE tenant_id = '{}' FORMAT JSON",
            self.database,
            self.table,
            escape_sql_literal(tenant_id)
        );
        let resp = self.execute_sql_json(&count_sql).await?;
        let count: u64 = resp
            .data
            .first()
            .and_then(|r| r.get("n"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let delete_sql = format!(
            "DELETE FROM {}.{} WHERE tenant_id = '{}'",
            self.database,
            self.table,
            escape_sql_literal(tenant_id)
        );
        self.execute_sql(&delete_sql).await?;

        tracing::info!(
            tenant_id,
            deleted_rows = count,
            "GDPR purge: tenant events deleted from ClickHouse"
        );
        Ok(count)
    }

    async fn execute_sql(&self, sql: &str) -> Result<String, CyberboxError> {
        // Acquire a concurrency permit before sending.  The permit is held
        // until the response body has been read, then dropped automatically.
        // This is the async equivalent of tower::ServiceBuilder::concurrency_limit().
        let _permit = self
            .concurrency_limiter
            .acquire()
            .await
            .map_err(|_| CyberboxError::Internal("clickhouse semaphore closed".to_string()))?;

        let endpoint = format!("{}/?database={}", self.base_url, self.database);
        let response = self
            .client
            .post(endpoint)
            .basic_auth(&self.user, Some(&self.password))
            .body(sql.to_string())
            .send()
            .await
            .map_err(|err| CyberboxError::Internal(format!("clickhouse request failed: {err}")))?;

        let status = response.status();
        let body = response.text().await.map_err(|err| {
            CyberboxError::Internal(format!("clickhouse body read failed: {err}"))
        })?;

        if !status.is_success() {
            return Err(CyberboxError::Internal(format!(
                "clickhouse query failed (status {}): {}",
                status, body
            )));
        }

        Ok(body)
    }

    async fn execute_sql_json(&self, sql: &str) -> Result<ClickHouseJsonResponse, CyberboxError> {
        let body = self.execute_sql(sql).await?;
        serde_json::from_str::<ClickHouseJsonResponse>(&body).map_err(|err| {
            CyberboxError::Internal(format!("clickhouse JSON decode failed: {err}; body={body}"))
        })
    }

    /// Dashboard stats: total events, events by source, hourly counts for a tenant.
    pub async fn dashboard_stats(&self, tenant_id: &str) -> Result<Value, CyberboxError> {
        let safe_tenant = escape_sql_literal(tenant_id);

        // Total events
        let total_sql = format!(
            "SELECT count() as c FROM {}.{} WHERE tenant_id = '{safe_tenant}'",
            self.database, self.table
        );
        let total_body = self.execute_sql(&total_sql).await?;
        let total_events: i64 = total_body.trim().parse().unwrap_or(0);

        // Events by source (top 10)
        let by_source_sql = format!(
            "SELECT computer_name as source, count() as count \
             FROM {db}.{tbl} WHERE tenant_id = '{t}' \
             GROUP BY computer_name ORDER BY count DESC LIMIT 10 FORMAT JSON",
            db = self.database,
            tbl = self.table,
            t = safe_tenant
        );
        let by_source = self
            .execute_sql_json(&by_source_sql)
            .await
            .map(|r| r.data)
            .unwrap_or_default();

        // Hourly event counts (last 24h)
        let hourly_sql = format!(
            "SELECT toStartOfHour(event_time) as hour, count() as count \
             FROM {db}.{tbl} \
             WHERE tenant_id = '{t}' AND event_time >= now() - INTERVAL 24 HOUR \
             GROUP BY hour ORDER BY hour FORMAT JSON",
            db = self.database,
            tbl = self.table,
            t = safe_tenant
        );
        let hourly = self
            .execute_sql_json(&hourly_sql)
            .await
            .map(|r| r.data)
            .unwrap_or_default();

        Ok(json!({
            "total_events": total_events,
            "events_by_source": by_source,
            "hourly_events": hourly,
        }))
    }

    pub async fn list_scheduled_rules(&self) -> Result<Vec<DetectionRule>, CyberboxError> {
        let query = format!(
            "SELECT rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled \
             FROM {}.{} FINAL \
             WHERE enabled = 1 AND deleted = 0 AND schedule_or_stream = 'scheduled' \
             ORDER BY tenant_id, rule_id \
             FORMAT JSON",
            self.database, self.rules_table
        );
        let response = self.execute_sql_json(&query).await?;
        response
            .data
            .iter()
            .map(parse_rule_row)
            .collect::<Result<Vec<_>, _>>()
    }

    pub async fn list_stream_rules(&self) -> Result<Vec<DetectionRule>, CyberboxError> {
        let query = format!(
            "SELECT rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled \
             FROM {}.{} FINAL \
             WHERE enabled = 1 AND deleted = 0 AND schedule_or_stream = 'stream' \
             ORDER BY tenant_id, rule_id \
             FORMAT JSON",
            self.database, self.rules_table
        );
        let response = self.execute_sql_json(&query).await?;
        response
            .data
            .iter()
            .map(parse_rule_row)
            .collect::<Result<Vec<_>, _>>()
    }

    /// Persist (or overwrite) the last-successful-run timestamp for a scheduled rule.
    /// Uses INSERT + ReplacingMergeTree so repeated upserts are idempotent.
    pub async fn upsert_rule_watermark(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
        last_run_at: DateTime<Utc>,
    ) -> Result<(), CyberboxError> {
        let now = Utc::now();
        let row = json!({
            "rule_id":     rule_id.to_string(),
            "tenant_id":   tenant_id,
            "last_run_at": format_clickhouse_datetime(last_run_at),
            "updated_at":  format_clickhouse_datetime(now),
        });
        let query = format!(
            "INSERT INTO {}.{} (rule_id, tenant_id, last_run_at, updated_at) FORMAT JSONEachRow\n{}\n",
            self.database,
            self.watermarks_table,
            serde_json::to_string(&row)
                .map_err(|e| CyberboxError::Internal(format!("serialize watermark row: {e}")))?
        );
        self.execute_sql(&query).await?;
        Ok(())
    }

    /// Load all rule watermarks into a `HashMap<rule_id, last_run_at>`.
    /// Called once on scheduler startup to restore state across restarts.
    pub async fn load_rule_watermarks(
        &self,
    ) -> Result<std::collections::HashMap<Uuid, DateTime<Utc>>, CyberboxError> {
        let query = format!(
            "SELECT rule_id, last_run_at \
             FROM {}.{} FINAL \
             FORMAT JSON",
            self.database, self.watermarks_table
        );
        let response = self.execute_sql_json(&query).await?;
        let mut map = std::collections::HashMap::new();
        for row in &response.data {
            let rule_id = row
                .get("rule_id")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Uuid>().ok());
            let last_run_at = row
                .get("last_run_at")
                .and_then(|v| v.as_str())
                .and_then(|s| parse_clickhouse_datetime(s).ok());
            if let (Some(id), Some(ts)) = (rule_id, last_run_at) {
                map.insert(id, ts);
            }
        }
        Ok(map)
    }

    /// Fetch events for a tenant in the half-open interval `[from, to)`.
    /// Used by the scheduler when a persistent watermark is available so that
    /// it scans exactly the window it missed — no more, no less.
    pub async fn list_events_in_range(
        &self,
        tenant_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: u64,
    ) -> Result<Vec<EventEnvelope>, CyberboxError> {
        let query = format!(
            "SELECT event_id, tenant_id, source, event_time, ingest_time, \
                    raw_payload, ocsf_record, enrichment, integrity_hash \
             FROM {}.{} \
             WHERE tenant_id = '{}' \
               AND event_time >= toDateTime64('{}', 3, 'UTC') \
               AND event_time <  toDateTime64('{}', 3, 'UTC') \
             ORDER BY event_time ASC \
             LIMIT {} \
             FORMAT JSON",
            self.database,
            self.table,
            escape_sql_literal(tenant_id),
            format_clickhouse_datetime(from),
            format_clickhouse_datetime(to),
            limit.max(1)
        );
        let response = self.execute_sql_json(&query).await?;
        response
            .data
            .iter()
            .map(parse_event_row)
            .collect::<Result<Vec<_>, _>>()
    }

    pub async fn list_recent_events(
        &self,
        tenant_id: &str,
        lookback_seconds: u64,
        limit: u64,
    ) -> Result<Vec<EventEnvelope>, CyberboxError> {
        let query = format!(
            "SELECT event_id, tenant_id, source, event_time, ingest_time, raw_payload, ocsf_record, enrichment, integrity_hash \
             FROM {}.{} \
             WHERE tenant_id = '{}' \
             AND event_time >= (now64(3, 'UTC') - INTERVAL {} SECOND) \
             ORDER BY event_time DESC \
             LIMIT {} \
             FORMAT JSON",
            self.database,
            self.table,
            escape_sql_literal(tenant_id),
            lookback_seconds.max(1),
            limit.max(1)
        );
        let response = self.execute_sql_json(&query).await?;
        response
            .data
            .iter()
            .map(parse_event_row)
            .collect::<Result<Vec<_>, _>>()
    }
}

#[async_trait]
impl EventStore for ClickHouseEventStore {
    async fn insert_events(&self, events: &[EventEnvelope]) -> Result<(), CyberboxError> {
        self.insert_events_with_deduplication_token(events, None)
            .await
    }

    async fn search(
        &self,
        query: &SearchQueryRequest,
    ) -> Result<SearchQueryResponse, CyberboxError> {
        let base_query = normalize_base_query(
            &query.sql,
            &format!(
                "SELECT event_id, tenant_id, source, event_time, ingest_time, raw_payload, ocsf_record, enrichment, integrity_hash FROM {}.{}",
                self.database, self.table
            ),
        )?;

        let tenant_id = escape_sql_literal(&query.tenant_id);
        let start = format_clickhouse_datetime(query.time_range.start);
        let end = format_clickhouse_datetime(query.time_range.end);
        let page_size = query.pagination.page_size.max(1);
        let offset = pagination_offset(query.pagination.page, page_size);

        let mut wrapped_filter = format!(
            "q.tenant_id = '{}' AND q.event_time >= toDateTime64('{}', 3, 'UTC') AND q.event_time <= toDateTime64('{}', 3, 'UTC')",
            tenant_id, start, end
        );
        if let Some(extra) = &query.extra_where {
            let safe = extra.trim();
            if !safe.is_empty() {
                wrapped_filter = format!("{wrapped_filter} AND ({safe})");
            }
        }

        let rows_query = format!(
            "SELECT * FROM ({}) AS q WHERE {} ORDER BY q.event_time DESC LIMIT {} OFFSET {} FORMAT JSON",
            base_query, wrapped_filter, page_size, offset
        );
        let count_query = format!(
            "SELECT count() AS total FROM ({}) AS q WHERE {} FORMAT JSON",
            base_query, wrapped_filter
        );

        let rows_response = self.execute_sql_json(&rows_query).await?;
        let count_response = self.execute_sql_json(&count_query).await?;

        let total = count_response
            .data
            .first()
            .and_then(|row| row.get("total"))
            .and_then(parse_u64_value)
            .unwrap_or(0);

        let has_more = total > offset + page_size as u64;
        let next_page = query.pagination.page.max(1) + 1;
        Ok(SearchQueryResponse {
            rows: rows_response.data,
            total,
            has_more,
            next_cursor: has_more.then(|| next_page.to_string()),
        })
    }
}

#[async_trait]
impl RuleStore for ClickHouseEventStore {
    async fn upsert_rule(&self, rule: DetectionRule) -> Result<DetectionRule, CyberboxError> {
        let now = Utc::now();
        let version = now.timestamp_millis().max(0) as u64;
        let (interval_seconds, lookback_seconds) = schedule_columns_from_rule(&rule);

        let row = json!({
            "rule_id": rule.rule_id.to_string(),
            "tenant_id": rule.tenant_id,
            "sigma_source": rule.sigma_source,
            "compiled_plan": rule.compiled_plan.to_string(),
            "schedule_or_stream": detection_mode_to_string(&rule.schedule_or_stream),
            "schedule_interval_seconds": interval_seconds,
            "schedule_lookback_seconds": lookback_seconds,
            "severity": severity_to_string(&rule.severity),
            "enabled": if rule.enabled { 1 } else { 0 },
            "deleted": 0,
            "updated_at": format_clickhouse_datetime(now),
            "version": version
        });

        let query = format!(
            "INSERT INTO {}.{} (rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled, deleted, updated_at, version) FORMAT JSONEachRow\n{}\n",
            self.database,
            self.rules_table,
            serde_json::to_string(&row)
                .map_err(|err| CyberboxError::Internal(format!("rule row serialization failed: {err}")))?
        );
        self.execute_sql(&query).await?;

        Ok(rule)
    }

    async fn list_rules(&self, tenant_id: &str) -> Result<Vec<DetectionRule>, CyberboxError> {
        let scheduler_health: std::collections::HashMap<Uuid, RuleSchedulerHealth> = self
            .list_rule_scheduler_health(tenant_id)
            .await?
            .into_iter()
            .collect();
        let query = format!(
            "SELECT rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled \
             FROM {}.{} FINAL \
             WHERE tenant_id = '{}' AND deleted = 0 \
             ORDER BY rule_id \
             FORMAT JSON",
            self.database,
            self.rules_table,
            escape_sql_literal(tenant_id)
        );
        let response = self.execute_sql_json(&query).await?;
        response
            .data
            .iter()
            .map(parse_rule_row)
            .map(|result| {
                let mut rule = result?;
                rule.scheduler_health = scheduler_health.get(&rule.rule_id).cloned();
                Ok(rule)
            })
            .collect::<Result<Vec<_>, _>>()
    }

    async fn get_rule(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
    ) -> Result<DetectionRule, CyberboxError> {
        let query = format!(
            "SELECT rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled \
             FROM {}.{} FINAL \
             WHERE tenant_id = '{}' AND rule_id = '{}' AND deleted = 0 \
             LIMIT 1 \
             FORMAT JSON",
            self.database,
            self.rules_table,
            escape_sql_literal(tenant_id),
            rule_id
        );

        let response = self.execute_sql_json(&query).await?;
        let row = response.data.first().ok_or(CyberboxError::NotFound)?;
        let mut rule = parse_rule_row(row)?;
        if let Some((_, health)) = self
            .list_rule_scheduler_health(tenant_id)
            .await?
            .into_iter()
            .find(|(health_rule_id, _)| *health_rule_id == rule_id)
        {
            rule.scheduler_health = Some(health);
        }
        Ok(rule)
    }

    async fn delete_rule(&self, tenant_id: &str, rule_id: Uuid) -> Result<(), CyberboxError> {
        let existing = self.get_rule(tenant_id, rule_id).await?;
        let now = Utc::now();
        let version = now.timestamp_millis().max(0) as u64;

        let row = json!({
            "rule_id": rule_id.to_string(),
            "tenant_id": tenant_id,
            "sigma_source": existing.sigma_source,
            "compiled_plan": existing.compiled_plan.to_string(),
            "schedule_or_stream": detection_mode_to_string(&existing.schedule_or_stream),
            "schedule_interval_seconds": existing.schedule.as_ref().map(|s| s.interval_seconds).unwrap_or(0),
            "schedule_lookback_seconds": existing.schedule.as_ref().map(|s| s.lookback_seconds).unwrap_or(0),
            "severity": severity_to_string(&existing.severity),
            "enabled": if existing.enabled { 1 } else { 0 },
            "deleted": 1,
            "updated_at": format_clickhouse_datetime(now),
            "version": version
        });

        let query = format!(
            "INSERT INTO {}.{} (rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled, deleted, updated_at, version) FORMAT JSONEachRow\n{}\n",
            self.database,
            self.rules_table,
            serde_json::to_string(&row)
                .map_err(|err| CyberboxError::Internal(format!("rule tombstone serialization failed: {err}")))?
        );
        self.execute_sql(&query).await?;
        Ok(())
    }
}

#[async_trait]
impl AlertStore for ClickHouseEventStore {
    async fn upsert_alert(&self, alert: AlertRecord) -> Result<AlertRecord, CyberboxError> {
        let now = Utc::now();
        let version = now.timestamp_millis().max(0) as u64;

        let row = json!({
            "alert_id": alert.alert_id.to_string(),
            "tenant_id": alert.tenant_id,
            "rule_id": alert.rule_id.to_string(),
            "first_seen": format_clickhouse_datetime(alert.first_seen),
            "last_seen": format_clickhouse_datetime(alert.last_seen),
            "status": alert_status_to_string(&alert.status),
            "evidence_refs": serde_json::to_string(&alert.evidence_refs).map_err(|err| CyberboxError::Internal(format!("evidence_refs serialization failed: {err}")))?,
            "routing_state": serde_json::to_string(&alert.routing_state).map_err(|err| CyberboxError::Internal(format!("routing_state serialization failed: {err}")))?,
            "assignee": alert.assignee,
            "hit_count": alert.hit_count,
            "mitre_attack": serde_json::to_string(&alert.mitre_attack).map_err(|err| CyberboxError::Internal(format!("mitre_attack serialization failed: {err}")))?,
            "resolution": alert.resolution.as_ref().and_then(|r| serde_json::to_string(r).ok()),
            "close_note": alert.close_note,
            "updated_at": format_clickhouse_datetime(now),
            "version": version
        });

        let query = format!(
            "INSERT INTO {}.{} (alert_id, tenant_id, rule_id, first_seen, last_seen, status, evidence_refs, routing_state, assignee, hit_count, mitre_attack, resolution, close_note, updated_at, version) FORMAT JSONEachRow\n{}\n",
            self.database,
            self.alerts_table,
            serde_json::to_string(&row)
                .map_err(|err| CyberboxError::Internal(format!("alert row serialization failed: {err}")))?
        );

        self.execute_sql(&query).await?;
        Ok(alert)
    }

    async fn list_alerts(&self, tenant_id: &str) -> Result<Vec<AlertRecord>, CyberboxError> {
        let query = format!(
            "SELECT alert_id, tenant_id, rule_id, first_seen, last_seen, status, evidence_refs, routing_state, assignee, hit_count, mitre_attack, resolution, close_note \
             FROM {}.{} FINAL \
             WHERE tenant_id = '{}' \
             ORDER BY last_seen DESC \
             FORMAT JSON",
            self.database,
            self.alerts_table,
            escape_sql_literal(tenant_id)
        );

        let response = self.execute_sql_json(&query).await?;
        response
            .data
            .iter()
            .map(parse_alert_row)
            .collect::<Result<Vec<_>, _>>()
    }

    async fn acknowledge(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        _actor: &str,
    ) -> Result<AlertRecord, CyberboxError> {
        let mut alert = self
            .fetch_alert(tenant_id, alert_id)
            .await?
            .ok_or(CyberboxError::NotFound)?;
        alert.status = AlertStatus::Acknowledged;
        alert.last_seen = Utc::now();
        self.upsert_alert(alert).await
    }

    async fn assign(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        assignment: &AssignAlertRequest,
    ) -> Result<AlertRecord, CyberboxError> {
        let mut alert = self
            .fetch_alert(tenant_id, alert_id)
            .await?
            .ok_or(CyberboxError::NotFound)?;
        alert.assignee = Some(assignment.assignee.clone());
        alert.status = AlertStatus::InProgress;
        alert.last_seen = Utc::now();
        self.upsert_alert(alert).await
    }

    async fn close(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        request: &CloseAlertRequest,
    ) -> Result<AlertRecord, CyberboxError> {
        let mut alert = self
            .fetch_alert(tenant_id, alert_id)
            .await?
            .ok_or(CyberboxError::NotFound)?;
        alert.status = AlertStatus::Closed;
        alert.resolution = Some(request.resolution.clone());
        alert.close_note = request.note.clone();
        alert.last_seen = Utc::now();
        self.upsert_alert(alert).await
    }
}

#[async_trait]
impl CaseStore for ClickHouseEventStore {
    async fn upsert_case(&self, case: CaseRecord) -> Result<CaseRecord, CyberboxError> {
        let now = Utc::now();
        let version = now.timestamp_millis().max(0) as u64;
        let row = json!({
            "case_id":     case.case_id.to_string(),
            "tenant_id":   case.tenant_id,
            "title":       case.title,
            "description": case.description,
            "status":      case_status_to_string(&case.status),
            "severity":    severity_to_string(&case.severity),
            "alert_ids":   serde_json::to_string(&case.alert_ids).map_err(|e| CyberboxError::Internal(format!("alert_ids: {e}")))?,
            "assignee":    case.assignee,
            "created_by":  case.created_by,
            "created_at":  format_clickhouse_datetime(case.created_at),
            "updated_at":  format_clickhouse_datetime(case.updated_at),
            "sla_due_at":  case.sla_due_at.map(format_clickhouse_datetime),
            "closed_at":   case.closed_at.map(format_clickhouse_datetime),
            "tags":        serde_json::to_string(&case.tags).map_err(|e| CyberboxError::Internal(format!("tags: {e}")))?,
            "version":     version,
        });
        let query = format!(
            "INSERT INTO {}.{} (case_id, tenant_id, title, description, status, severity, alert_ids, assignee, created_by, created_at, updated_at, sla_due_at, closed_at, tags, version) FORMAT JSONEachRow\n{}\n",
            self.database, self.cases_table,
            serde_json::to_string(&row).map_err(|e| CyberboxError::Internal(format!("case row: {e}")))?
        );
        self.execute_sql(&query).await?;
        Ok(case)
    }

    async fn get_case(&self, tenant_id: &str, case_id: Uuid) -> Result<CaseRecord, CyberboxError> {
        let query = format!(
            "SELECT case_id, tenant_id, title, description, status, severity, alert_ids, assignee, created_by, created_at, updated_at, sla_due_at, closed_at, tags \
             FROM {}.{} FINAL \
             WHERE tenant_id = '{}' AND case_id = '{}' \
             LIMIT 1 FORMAT JSON",
            self.database, self.cases_table,
            escape_sql_literal(tenant_id), case_id
        );
        let resp = self.execute_sql_json(&query).await?;
        resp.data
            .first()
            .ok_or(CyberboxError::NotFound)
            .and_then(parse_case_row)
    }

    async fn list_cases(&self, tenant_id: &str) -> Result<Vec<CaseRecord>, CyberboxError> {
        let query = format!(
            "SELECT case_id, tenant_id, title, description, status, severity, alert_ids, assignee, created_by, created_at, updated_at, sla_due_at, closed_at, tags \
             FROM {}.{} FINAL \
             WHERE tenant_id = '{}' \
             ORDER BY created_at DESC FORMAT JSON",
            self.database, self.cases_table, escape_sql_literal(tenant_id)
        );
        let resp = self.execute_sql_json(&query).await?;
        resp.data
            .iter()
            .map(parse_case_row)
            .collect::<Result<Vec<_>, _>>()
    }

    async fn update_case(
        &self,
        tenant_id: &str,
        case_id: Uuid,
        patch: &UpdateCaseRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<CaseRecord, CyberboxError> {
        let mut case = self.get_case(tenant_id, case_id).await?;
        if let Some(t) = &patch.title {
            case.title = t.clone();
        }
        if let Some(d) = &patch.description {
            case.description = d.clone();
        }
        if let Some(s) = &patch.status {
            case.status = s.clone();
        }
        if let Some(s) = &patch.severity {
            case.severity = s.clone();
        }
        if let Some(a) = &patch.assignee {
            case.assignee = Some(a.clone());
        }
        if let Some(t) = &patch.tags {
            case.tags = t.clone();
        }
        case.updated_at = now;
        if matches!(case.status, CaseStatus::Resolved | CaseStatus::Closed)
            && case.closed_at.is_none()
        {
            case.closed_at = Some(now);
        }
        self.upsert_case(case).await
    }

    async fn delete_case(&self, tenant_id: &str, case_id: Uuid) -> Result<(), CyberboxError> {
        let case = self.get_case(tenant_id, case_id).await?;
        // Soft-delete: mark as Closed with a tombstone version.
        let mut tombstone = case;
        tombstone.status = CaseStatus::Closed;
        tombstone.updated_at = Utc::now();
        self.upsert_case(tombstone).await?;
        Ok(())
    }
}

fn case_status_to_string(status: &CaseStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|v| v.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "open".to_string())
}

fn parse_case_row(row: &Value) -> Result<CaseRecord, CyberboxError> {
    let case_id = parse_uuid_field(row, "case_id")?;
    let tenant_id = parse_string_field(row, "tenant_id")?;
    let title = parse_string_field(row, "title")?;
    let description = row
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let status: CaseStatus =
        serde_json::from_value(Value::String(parse_string_field(row, "status")?))
            .map_err(|e| CyberboxError::Internal(format!("invalid case status: {e}")))?;
    let severity: Severity =
        serde_json::from_value(Value::String(parse_string_field(row, "severity")?))
            .map_err(|e| CyberboxError::Internal(format!("invalid severity: {e}")))?;
    let alert_ids: Vec<Uuid> =
        serde_json::from_str(&parse_string_field(row, "alert_ids")?).unwrap_or_default();
    let assignee = row
        .get("assignee")
        .and_then(|v| v.as_str().map(ToOwned::to_owned));
    let created_by = parse_string_field(row, "created_by")?;
    let created_at = parse_datetime_field(row, "created_at")?;
    let updated_at = parse_datetime_field(row, "updated_at")?;
    let sla_due_at = row
        .get("sla_due_at")
        .and_then(|v| v.as_str())
        .and_then(|s| parse_clickhouse_datetime(s).ok());
    let closed_at = row
        .get("closed_at")
        .and_then(|v| v.as_str())
        .and_then(|s| parse_clickhouse_datetime(s).ok());
    let tags: Vec<String> =
        serde_json::from_str(&parse_string_field(row, "tags")?).unwrap_or_default();

    Ok(CaseRecord {
        case_id,
        tenant_id,
        title,
        description,
        status,
        severity,
        alert_ids,
        assignee,
        created_by,
        created_at,
        updated_at,
        sla_due_at,
        closed_at,
        tags,
    })
}

impl ClickHouseEventStore {
    async fn fetch_alert(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
    ) -> Result<Option<AlertRecord>, CyberboxError> {
        let query = format!(
            "SELECT alert_id, tenant_id, rule_id, first_seen, last_seen, status, evidence_refs, routing_state, assignee, hit_count, mitre_attack, resolution, close_note \
             FROM {}.{} FINAL \
             WHERE tenant_id = '{}' AND alert_id = '{}' \
             LIMIT 1 \
             FORMAT JSON",
            self.database,
            self.alerts_table,
            escape_sql_literal(tenant_id),
            alert_id
        );

        let response = self.execute_sql_json(&query).await?;
        match response.data.first() {
            Some(row) => Ok(Some(parse_alert_row(row)?)),
            None => Ok(None),
        }
    }
}

fn source_to_string(source: &EventSource) -> String {
    serde_json::to_value(source)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_string())
}

fn format_clickhouse_datetime(datetime: DateTime<Utc>) -> String {
    datetime.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

fn normalize_base_query(input: &str, fallback: &str) -> Result<String, CyberboxError> {
    let candidate = input.trim().trim_end_matches(';');
    if candidate.is_empty() {
        return Ok(fallback.to_string());
    }

    let lower = candidate.to_ascii_lowercase();
    if !lower.starts_with("select ") {
        return Err(CyberboxError::BadRequest(
            "search:query sql must be a SELECT statement".to_string(),
        ));
    }
    if lower.contains(" format ") {
        return Err(CyberboxError::BadRequest(
            "search:query sql must not include FORMAT clause".to_string(),
        ));
    }

    Ok(candidate.to_string())
}

fn escape_sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

// ─── Field extraction helpers for typed ClickHouse columns ───────────────────

/// Try each key in `keys` against `raw` (a parsed JSON Value) and return the
/// first non-empty string found.  Supports one level of dot-notation nesting
/// (e.g. `"host.name"` → `raw["host"]["name"]`).  Returns `""` when nothing
/// matches — ClickHouse stores it as an empty string with DEFAULT ''.
fn extract_str(raw: &Value, keys: &[&str]) -> String {
    for key in keys {
        // Direct lookup.
        if let Some(val) = raw.get(*key) {
            let s = match val {
                Value::String(s) => s.as_str(),
                Value::Number(n) => {
                    // Numeric fields (e.g. EventID) — convert to string for the
                    // typed column so analysts can filter with '=' predicates.
                    return n.to_string();
                }
                _ => continue,
            };
            if !s.is_empty() {
                return s.to_string();
            }
        }
        // One-level dot-notation (e.g. "host.name" → raw["host"]["name"]).
        if let Some(dot) = key.find('.') {
            let (parent, child) = key.split_at(dot);
            let child = &child[1..]; // skip the '.'
            if let Some(s) = raw
                .get(parent)
                .and_then(|v| v.get(child))
                .and_then(|v| v.as_str())
            {
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    String::new()
}

/// Same as `extract_str` but parses the result as a `u16` port / code value.
/// Returns `0` when nothing matches or the value is out of range.
fn extract_u16(raw: &Value, keys: &[&str]) -> u16 {
    for key in keys {
        if let Some(val) = raw.get(*key) {
            let maybe: Option<u64> = match val {
                Value::Number(n) => n.as_u64(),
                Value::String(s) => s.parse().ok(),
                _ => None,
            };
            if let Some(n) = maybe {
                return n.min(65535) as u16;
            }
        }
    }
    0
}

fn parse_u64_value(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|v| u64::try_from(v).ok()))
        .or_else(|| value.as_str().and_then(|v| v.parse::<u64>().ok()))
}

fn parse_f64_value(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_i64().map(|v| v as f64))
        .or_else(|| value.as_u64().map(|v| v as f64))
        .or_else(|| value.as_str().and_then(|v| v.parse::<f64>().ok()))
}

fn parse_u32_field(row: &Value, field: &str) -> Option<u32> {
    row.get(field).and_then(|value| {
        value
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .or_else(|| value.as_i64().and_then(|v| u32::try_from(v).ok()))
            .or_else(|| value.as_str().and_then(|v| v.parse::<u32>().ok()))
    })
}

fn parse_u64_field(row: &Value, field: &str) -> Result<u64, CyberboxError> {
    row.get(field).and_then(parse_u64_value).ok_or_else(|| {
        CyberboxError::Internal(format!(
            "missing or invalid u64 field '{field}' in clickhouse response"
        ))
    })
}

fn parse_f64_field(row: &Value, field: &str) -> Result<f64, CyberboxError> {
    row.get(field).and_then(parse_f64_value).ok_or_else(|| {
        CyberboxError::Internal(format!(
            "missing or invalid f64 field '{field}' in clickhouse response"
        ))
    })
}

fn detection_mode_to_string(mode: &DetectionMode) -> String {
    serde_json::to_value(mode)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "stream".to_string())
}

fn severity_to_string(severity: &Severity) -> String {
    serde_json::to_value(severity)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "medium".to_string())
}

fn parse_rule_row(row: &Value) -> Result<DetectionRule, CyberboxError> {
    let rule_id = parse_uuid_field(row, "rule_id")?;
    let tenant_id = parse_string_field(row, "tenant_id")?;
    let sigma_source = parse_string_field(row, "sigma_source")?;
    let compiled_plan_raw = parse_string_field(row, "compiled_plan")?;
    let compiled_plan = serde_json::from_str::<Value>(&compiled_plan_raw).map_err(|err| {
        CyberboxError::Internal(format!(
            "invalid compiled_plan JSON for rule {rule_id}: {err}"
        ))
    })?;
    let schedule_or_stream = serde_json::from_value::<DetectionMode>(Value::String(
        parse_string_field(row, "schedule_or_stream")?,
    ))
    .map_err(|err| CyberboxError::Internal(format!("invalid detection mode: {err}")))?;
    let schedule = match schedule_or_stream {
        DetectionMode::Scheduled => Some(RuleScheduleConfig {
            interval_seconds: parse_u32_field(row, "schedule_interval_seconds")
                .filter(|value| *value > 0)
                .unwrap_or(30)
                .max(1),
            lookback_seconds: parse_u32_field(row, "schedule_lookback_seconds")
                .filter(|value| *value > 0)
                .unwrap_or(300)
                .max(1),
        }),
        DetectionMode::Stream => None,
    };
    let severity =
        serde_json::from_value::<Severity>(Value::String(parse_string_field(row, "severity")?))
            .map_err(|err| CyberboxError::Internal(format!("invalid severity: {err}")))?;
    let enabled = parse_bool_field(row, "enabled")?;

    Ok(DetectionRule {
        rule_id,
        tenant_id,
        sigma_source,
        compiled_plan,
        schedule_or_stream,
        schedule,
        severity,
        enabled,
        scheduler_health: None,
        threshold_count: None,
        threshold_group_by: None,
        suppression_window_secs: None,
    })
}

fn schedule_columns_from_rule(rule: &DetectionRule) -> (u32, u32) {
    match &rule.schedule {
        Some(schedule) => (schedule.interval_seconds, schedule.lookback_seconds),
        None => (0, 0),
    }
}

fn parse_rule_scheduler_health_row(
    row: &Value,
) -> Result<(Uuid, RuleSchedulerHealth), CyberboxError> {
    let rule_id = parse_uuid_field(row, "rule_id")?;
    let health = RuleSchedulerHealth {
        run_count: parse_u64_field(row, "run_count")?,
        skipped_by_interval_count: parse_u64_field(row, "skipped_by_interval_count")?,
        match_count: parse_u64_field(row, "match_count")?,
        error_count: parse_u64_field(row, "error_count")?,
        last_run_duration_seconds: parse_f64_field(row, "last_run_duration_seconds")?,
    };
    Ok((rule_id, health))
}

fn parse_event_source(value: &str) -> EventSource {
    serde_json::from_value::<EventSource>(Value::String(value.to_string()))
        .unwrap_or(EventSource::Unknown)
}

fn parse_event_row(row: &Value) -> Result<EventEnvelope, CyberboxError> {
    let event_id = parse_uuid_field(row, "event_id")?;
    let tenant_id = parse_string_field(row, "tenant_id")?;
    let source = parse_event_source(&parse_string_field(row, "source")?);
    let event_time = parse_datetime_field(row, "event_time")?;
    let ingest_time = parse_datetime_field(row, "ingest_time")?;
    let raw_payload = serde_json::from_str::<Value>(&parse_string_field(row, "raw_payload")?)
        .map_err(|err| CyberboxError::Internal(format!("invalid raw_payload JSON: {err}")))?;
    let ocsf_record = serde_json::from_str::<Value>(&parse_string_field(row, "ocsf_record")?)
        .map_err(|err| CyberboxError::Internal(format!("invalid ocsf_record JSON: {err}")))?;
    let enrichment =
        serde_json::from_str::<EnrichmentMetadata>(&parse_string_field(row, "enrichment")?)
            .map_err(|err| CyberboxError::Internal(format!("invalid enrichment JSON: {err}")))?;
    let integrity_hash = parse_string_field(row, "integrity_hash")?;

    Ok(EventEnvelope {
        event_id,
        tenant_id,
        source,
        event_time,
        ingest_time,
        raw_payload,
        ocsf_record,
        enrichment,
        integrity_hash,
    })
}

fn alert_status_to_string(status: &AlertStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "open".to_string())
}

fn parse_alert_status(value: &str) -> AlertStatus {
    serde_json::from_value(Value::String(value.to_string())).unwrap_or(AlertStatus::Open)
}

fn parse_alert_row(row: &Value) -> Result<AlertRecord, CyberboxError> {
    let alert_id = parse_uuid_field(row, "alert_id")?;
    let tenant_id = parse_string_field(row, "tenant_id")?;
    let rule_id = parse_uuid_field(row, "rule_id")?;
    let first_seen = parse_datetime_field(row, "first_seen")?;
    let last_seen = parse_datetime_field(row, "last_seen")?;
    let status = parse_alert_status(&parse_string_field(row, "status")?);
    let evidence_refs =
        serde_json::from_str::<Vec<String>>(&parse_string_field(row, "evidence_refs")?)
            .map_err(|err| CyberboxError::Internal(format!("invalid evidence_refs JSON: {err}")))?;
    let routing_state = serde_json::from_str(&parse_string_field(row, "routing_state")?)
        .map_err(|err| CyberboxError::Internal(format!("invalid routing_state JSON: {err}")))?;
    let assignee = row
        .get("assignee")
        .and_then(|value| value.as_str().map(ToOwned::to_owned));
    let hit_count = row.get("hit_count").and_then(|v| v.as_u64()).unwrap_or(1);
    let mitre_attack = row
        .get("mitre_attack")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let resolution = row
        .get("resolution")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok());
    let close_note = row
        .get("close_note")
        .and_then(|v| v.as_str().map(ToOwned::to_owned));

    let severity = row
        .get("severity")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_value(Value::String(s.to_string())).ok())
        .unwrap_or_default();
    let rule_title = row
        .get("rule_title")
        .and_then(|v| v.as_str().map(ToOwned::to_owned))
        .unwrap_or_default();

    Ok(AlertRecord {
        alert_id,
        tenant_id,
        rule_id,
        severity,
        rule_title,
        first_seen,
        last_seen,
        status,
        evidence_refs,
        routing_state,
        assignee,
        hit_count,
        mitre_attack,
        resolution,
        close_note,
        agent_meta: None,
    })
}

fn parse_audit_row(row: &Value) -> Result<AuditLogRecord, CyberboxError> {
    let audit_id = parse_uuid_field(row, "audit_id")?;
    let tenant_id = parse_string_field(row, "tenant_id")?;
    let actor = parse_string_field(row, "actor")?;
    let action = parse_string_field(row, "action")?;
    let entity_type = parse_string_field(row, "entity_type")?;
    let entity_id = parse_string_field(row, "entity_id")?;
    let timestamp = parse_datetime_field(row, "event_time")?;
    let before = parse_json_field(row, "before_state")?;
    let after = parse_json_field(row, "after_state")?;

    Ok(AuditLogRecord {
        audit_id,
        tenant_id,
        actor,
        action,
        entity_type,
        entity_id,
        timestamp,
        before,
        after,
    })
}

fn parse_json_field(row: &Value, field: &str) -> Result<Value, CyberboxError> {
    let raw = parse_string_field(row, field)?;
    match serde_json::from_str::<Value>(&raw) {
        Ok(value) => Ok(value),
        Err(_) => Ok(Value::String(raw)),
    }
}

fn parse_string_field(row: &Value, field: &str) -> Result<String, CyberboxError> {
    row.get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            CyberboxError::Internal(format!(
                "missing or invalid field '{field}' in clickhouse response"
            ))
        })
}

fn parse_bool_field(row: &Value, field: &str) -> Result<bool, CyberboxError> {
    let value = row.get(field).ok_or_else(|| {
        CyberboxError::Internal(format!(
            "missing or invalid field '{field}' in clickhouse response"
        ))
    })?;

    if let Some(boolean) = value.as_bool() {
        return Ok(boolean);
    }
    if let Some(number) = value.as_u64() {
        return Ok(number != 0);
    }
    if let Some(number) = value.as_i64() {
        return Ok(number != 0);
    }
    if let Some(text) = value.as_str() {
        return match text.trim() {
            "1" | "true" | "TRUE" => Ok(true),
            "0" | "false" | "FALSE" => Ok(false),
            _ => Err(CyberboxError::Internal(format!(
                "invalid bool field '{field}': {text}"
            ))),
        };
    }

    Err(CyberboxError::Internal(format!(
        "invalid bool field '{field}'"
    )))
}

fn parse_uuid_field(row: &Value, field: &str) -> Result<Uuid, CyberboxError> {
    Uuid::parse_str(&parse_string_field(row, field)?)
        .map_err(|err| CyberboxError::Internal(format!("invalid UUID field '{field}': {err}")))
}

fn parse_datetime_field(row: &Value, field: &str) -> Result<DateTime<Utc>, CyberboxError> {
    let raw = parse_string_field(row, field)?;
    parse_clickhouse_datetime(&raw)
}

fn parse_clickhouse_datetime(raw: &str) -> Result<DateTime<Utc>, CyberboxError> {
    let naive = NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.3f")
        .or_else(|_| NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S"))
        .map_err(|err| {
            CyberboxError::Internal(format!("invalid clickhouse datetime '{raw}': {err}"))
        })?;
    Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

fn pagination_offset(page: u32, page_size: u32) -> u64 {
    if page <= 1 {
        return 0;
    }

    page.saturating_sub(1).saturating_mul(page_size) as u64
}

#[cfg(test)]
mod tests {
    use super::pagination_offset;

    #[test]
    fn pagination_offset_uses_one_based_pages() {
        assert_eq!(pagination_offset(0, 10), 0);
        assert_eq!(pagination_offset(1, 10), 0);
        assert_eq!(pagination_offset(2, 10), 10);
        assert_eq!(pagination_offset(3, 10), 20);
    }
}
