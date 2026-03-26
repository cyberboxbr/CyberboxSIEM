use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use cyberbox_core::CyberboxError;
use cyberbox_models::{
    AgentRecord, AlertRecord, AlertStatus, AssignAlertRequest, AuditLogRecord, CaseRecord,
    CaseStatus, CloseAlertRequest, DetectionMode, DetectionRule, EnrichmentMetadata, EventEnvelope,
    EventSource, RuleScheduleConfig, RuleSchedulerHealth, RuleVersion, SearchQueryRequest,
    SearchQueryResponse, Severity, UpdateCaseRequest,
};

use crate::traits::{apply_case_patch, AlertStore, CaseStore, EventStore, RuleStore};

/// Validate that a ClickHouse identifier (table name, database name) contains only
/// safe characters: alphanumerics, underscores, dots, and hyphens.
fn validate_identifier(name: &str, label: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(format!("{label} contains invalid characters: {name}"));
    }
    Ok(())
}

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
    rule_versions_table: String,
    alerts_table: String,
    audits_table: String,
    rule_health_table: String,
    hourly_rollup_table: String,
    hourly_rollup_mv: String,
    watermarks_table: String,
    cases_table: String,
    agents_table: String,
}

#[derive(Debug, Deserialize)]
struct ClickHouseJsonResponse {
    data: Vec<Value>,
}

impl ClickHouseEventStore {
    /// Default maximum concurrency for ClickHouse HTTP requests.
    const DEFAULT_CONCURRENCY_LIMIT: usize = 64;

    pub fn new(url: &str, user: &str, password: &str, database: &str, table: &str) -> Self {
        validate_identifier(database, "database").expect("invalid ClickHouse database name");
        validate_identifier(table, "table").expect("invalid ClickHouse table name");
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("reqwest client build"),
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
            rule_versions_table: format!("{}_rule_versions", table),
            alerts_table: format!("{}_alerts", table),
            audits_table: format!("{}_audit_logs", table),
            rule_health_table: format!("{}_rule_health", table),
            hourly_rollup_table: format!("{}_hourly_rollup", table),
            hourly_rollup_mv: format!("{}_hourly_rollup_mv", table),
            watermarks_table: format!("{}_rule_watermarks", table),
            cases_table: format!("{}_cases", table),
            agents_table: format!("{}_agents", table),
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
        let rule_versions_engine = self.merge_tree_engine(&self.rule_versions_table);
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
                severity String DEFAULT 'medium',
                rule_title String DEFAULT '',
                first_seen DateTime64(3, 'UTC'),
                last_seen DateTime64(3, 'UTC'),
                status String,
                evidence_refs String,
                routing_state String,
                assignee Nullable(String),
                case_id Nullable(UUID),
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

        // Forward-migration for existing alerts tables: add severity + rule_title columns.
        let alerts_migrations: &[(&str, &str)] = &[
            ("severity", "String DEFAULT 'medium'"),
            ("rule_title", "String DEFAULT ''"),
            ("case_id", "Nullable(UUID)"),
        ];
        for (col, ty) in alerts_migrations {
            let stmt = format!(
                "ALTER TABLE {}.{} ADD COLUMN IF NOT EXISTS {} {}",
                self.database, self.alerts_table, col, ty
            );
            self.execute_sql(&stmt).await?;
        }

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
                threshold_count UInt32,
                threshold_group_by String,
                suppression_window_secs UInt64,
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
        let rules_alter_threshold_count = format!(
            "ALTER TABLE {}.{} ADD COLUMN IF NOT EXISTS threshold_count UInt32 DEFAULT 0",
            self.database, self.rules_table
        );
        self.execute_sql(&rules_alter_threshold_count).await?;
        let rules_alter_threshold_group_by = format!(
            "ALTER TABLE {}.{} ADD COLUMN IF NOT EXISTS threshold_group_by String DEFAULT ''",
            self.database, self.rules_table
        );
        self.execute_sql(&rules_alter_threshold_group_by).await?;
        let rules_alter_suppression = format!(
            "ALTER TABLE {}.{} ADD COLUMN IF NOT EXISTS suppression_window_secs UInt64 DEFAULT 0",
            self.database, self.rules_table
        );
        self.execute_sql(&rules_alter_suppression).await?;

        let rule_versions_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{} (
                rule_id UUID,
                tenant_id String,
                version UInt32,
                sigma_source String,
                compiled_plan String,
                severity String,
                created_at DateTime64(3, 'UTC')
            )
            ENGINE = {}
            PARTITION BY cityHash64(tenant_id) % 8
            ORDER BY (tenant_id, rule_id, version)
            "#,
            self.database, self.rule_versions_table, rule_versions_engine
        );
        self.execute_sql(&rule_versions_ddl).await?;

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
                resolution  Nullable(String),
                close_note  Nullable(String),
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
        let case_migrations: &[(&str, &str)] = &[
            ("resolution", "Nullable(String)"),
            ("close_note", "Nullable(String)"),
        ];
        for (col, ty) in case_migrations {
            let stmt = format!(
                "ALTER TABLE {}.{} ADD COLUMN IF NOT EXISTS {} {}",
                self.database, self.cases_table, col, ty
            );
            self.execute_sql(&stmt).await?;
        }

        let agents_engine = self.replacing_merge_tree_engine(&self.agents_table, "version_col");
        let agents_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{} (
                agent_id       String,
                tenant_id      String,
                hostname       String,
                os             LowCardinality(String),
                version        String,
                ip             Nullable(String),
                registered_at  DateTime64(3, 'UTC'),
                last_seen      DateTime64(3, 'UTC'),
                group_name     Nullable(String),
                tags           String DEFAULT '[]',
                pending_config Nullable(String),
                updated_at     DateTime64(3, 'UTC'),
                version_col    UInt64
            )
            ENGINE = {}
            ORDER BY (tenant_id, agent_id)
            "#,
            self.database, self.agents_table, agents_engine
        );
        self.execute_sql(&agents_ddl).await?;

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
    pub async fn dashboard_stats(
        &self,
        tenant_id: &str,
        range_seconds: i64,
    ) -> Result<Value, CyberboxError> {
        let safe_tenant = escape_sql_literal(tenant_id);
        let interval = format!("{range_seconds} SECOND");

        // Total events (within selected range)
        let total_sql = format!(
            "SELECT count() as c FROM {db}.{tbl} \
             WHERE tenant_id = '{t}' AND event_time >= now() - INTERVAL {iv}",
            db = self.database,
            tbl = self.table,
            t = safe_tenant,
            iv = interval
        );
        let total_body = self.execute_sql(&total_sql).await?;
        let total_events: i64 = total_body.trim().parse().unwrap_or(0);

        // Events by source type (top 10, using actual source column)
        let by_source_sql = format!(
            "SELECT source, count() as count \
             FROM {db}.{tbl} WHERE tenant_id = '{t}' AND event_time >= now() - INTERVAL {iv} \
             GROUP BY source ORDER BY count DESC LIMIT 10 FORMAT JSON",
            db = self.database,
            tbl = self.table,
            t = safe_tenant,
            iv = interval
        );
        let by_source = self
            .execute_sql_json(&by_source_sql)
            .await
            .map(|r| r.data)
            .unwrap_or_default();

        // Events by hostname (top 10)
        let by_host_sql = format!(
            "SELECT if(computer_name = '', 'unknown', computer_name) as hostname, count() as count \
             FROM {db}.{tbl} WHERE tenant_id = '{t}' AND event_time >= now() - INTERVAL {iv} \
             GROUP BY hostname ORDER BY count DESC LIMIT 10 FORMAT JSON",
            db = self.database, tbl = self.table, t = safe_tenant, iv = interval
        );
        let by_host = self
            .execute_sql_json(&by_host_sql)
            .await
            .map(|r| r.data)
            .unwrap_or_default();

        // Adaptive bucket: <=4h→5min, <=24h→1h, <=7d→6h, >7d→1day
        let (bucket_fn, bucket_interval) = if range_seconds <= 4 * 3600 {
            ("toStartOfFiveMinutes", "5 MINUTE")
        } else if range_seconds <= 24 * 3600 {
            ("toStartOfHour", "1 HOUR")
        } else if range_seconds <= 7 * 24 * 3600 {
            (
                "toStartOfInterval(event_time, INTERVAL 6 HOUR) as",
                "6 HOUR",
            )
        } else {
            ("toStartOfDay", "1 DAY")
        };

        // Hourly/bucketed event counts
        let hourly_sql = if bucket_fn.contains("toStartOfInterval") {
            format!(
                "SELECT {bucket_fn} bucket, count() as count \
                 FROM {db}.{tbl} \
                 WHERE tenant_id = '{t}' AND event_time >= now() - INTERVAL {iv} \
                 GROUP BY bucket ORDER BY bucket FORMAT JSON",
                db = self.database,
                tbl = self.table,
                t = safe_tenant,
                iv = interval,
                bucket_fn = bucket_fn
            )
        } else {
            format!(
                "SELECT {bucket_fn}(event_time) as bucket, count() as count \
                 FROM {db}.{tbl} \
                 WHERE tenant_id = '{t}' AND event_time >= now() - INTERVAL {iv} \
                 GROUP BY bucket ORDER BY bucket FORMAT JSON",
                db = self.database,
                tbl = self.table,
                t = safe_tenant,
                iv = interval,
                bucket_fn = bucket_fn
            )
        };
        let hourly = self
            .execute_sql_json(&hourly_sql)
            .await
            .map(|r| r.data)
            .unwrap_or_default();

        // Current EPS (events in last 60 seconds)
        let eps_sql = format!(
            "SELECT count() as c FROM {db}.{tbl} \
             WHERE tenant_id = '{t}' AND event_time >= now() - INTERVAL 60 SECOND",
            db = self.database,
            tbl = self.table,
            t = safe_tenant
        );
        let eps_body = self.execute_sql(&eps_sql).await?;
        let events_last_60s: f64 = eps_body.trim().parse().unwrap_or(0.0);
        let current_eps = events_last_60s / 60.0;

        // EPS trend (same bucket size as volume chart)
        let eps_trend_sql = if bucket_fn.contains("toStartOfInterval") {
            format!(
                "SELECT {bucket_fn} bucket, \
                 count() / {bucket_secs} as eps \
                 FROM {db}.{tbl} \
                 WHERE tenant_id = '{t}' AND event_time >= now() - INTERVAL {iv} \
                 GROUP BY bucket ORDER BY bucket FORMAT JSON",
                db = self.database,
                tbl = self.table,
                t = safe_tenant,
                iv = interval,
                bucket_fn = bucket_fn,
                bucket_secs = Self::bucket_seconds(bucket_interval)
            )
        } else {
            format!(
                "SELECT {bucket_fn}(event_time) as bucket, \
                 count() / {bucket_secs} as eps \
                 FROM {db}.{tbl} \
                 WHERE tenant_id = '{t}' AND event_time >= now() - INTERVAL {iv} \
                 GROUP BY bucket ORDER BY bucket FORMAT JSON",
                db = self.database,
                tbl = self.table,
                t = safe_tenant,
                iv = interval,
                bucket_fn = bucket_fn,
                bucket_secs = Self::bucket_seconds(bucket_interval)
            )
        };
        let eps_trend = self
            .execute_sql_json(&eps_trend_sql)
            .await
            .map(|r| r.data)
            .unwrap_or_default();

        Ok(json!({
            "total_events": total_events,
            "events_by_source": by_source,
            "events_by_host": by_host,
            "hourly_events": hourly,
            "current_eps": (current_eps * 100.0).round() / 100.0,
            "eps_trend": eps_trend,
        }))
    }

    fn bucket_seconds(interval: &str) -> i64 {
        match interval {
            "5 MINUTE" => 300,
            "1 HOUR" => 3600,
            "6 HOUR" => 21600,
            "1 DAY" => 86400,
            _ => 3600,
        }
    }

    // ── Agent persistence ─────────────────────────────────────────────────

    /// Upsert an agent record (insert or replace via ReplacingMergeTree).
    pub async fn upsert_agent(&self, agent: &AgentRecord) -> Result<(), CyberboxError> {
        let now = Utc::now();
        let version_col = now.timestamp_millis().max(0) as u64;
        let row = json!({
            "agent_id":       agent.agent_id,
            "tenant_id":      agent.tenant_id,
            "hostname":       agent.hostname,
            "os":             agent.os,
            "version":        agent.version,
            "ip":             agent.ip,
            "registered_at":  agent.registered_at.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            "last_seen":      agent.last_seen.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            "group_name":     agent.group,
            "tags":           serde_json::to_string(&agent.tags).unwrap_or_else(|_| "[]".into()),
            "pending_config": agent.pending_config,
            "updated_at":     now.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            "version_col":    version_col,
        });
        let json_line =
            serde_json::to_string(&row).map_err(|e| CyberboxError::Internal(e.to_string()))?;
        let query = format!(
            "INSERT INTO {}.{} FORMAT JSONEachRow\n{}\n",
            self.database, self.agents_table, json_line
        );
        self.execute_sql(&query).await?;
        Ok(())
    }

    /// Load all persisted agents (for startup reload into DashMap).
    pub async fn list_agents_all(&self) -> Result<Vec<AgentRecord>, CyberboxError> {
        let query = format!(
            "SELECT agent_id, tenant_id, hostname, os, version, ip, \
             registered_at, last_seen, group_name, tags, pending_config \
             FROM {}.{} FINAL \
             ORDER BY tenant_id, agent_id \
             FORMAT JSON",
            self.database, self.agents_table
        );
        let resp = self.execute_sql_json(&query).await?;
        resp.data.iter().map(parse_agent_row).collect()
    }

    /// Load all persisted alerts across all tenants (for startup reload into DashMap).
    pub async fn list_alerts_all(&self) -> Result<Vec<AlertRecord>, CyberboxError> {
        let query = format!(
            "SELECT alert_id, tenant_id, rule_id, severity, rule_title, first_seen, last_seen, \
             status, evidence_refs, routing_state, assignee, case_id, hit_count, mitre_attack, resolution, close_note \
             FROM {}.{} FINAL \
             ORDER BY tenant_id, last_seen DESC \
             FORMAT JSON",
            self.database, self.alerts_table
        );
        let resp = self.execute_sql_json(&query).await?;
        resp.data.iter().map(parse_alert_row).collect()
    }

    /// Load all persisted cases across all tenants (for startup reload into DashMap).
    pub async fn list_cases_all(&self) -> Result<Vec<CaseRecord>, CyberboxError> {
        let query = format!(
            "SELECT case_id, tenant_id, title, description, status, severity, alert_ids, \
             assignee, created_by, created_at, updated_at, sla_due_at, closed_at, tags \
             FROM {}.{} FINAL \
             ORDER BY tenant_id, created_at DESC \
             FORMAT JSON",
            self.database, self.cases_table
        );
        let resp = self.execute_sql_json(&query).await?;
        resp.data.iter().map(parse_case_row).collect()
    }

    pub async fn delete_agent(&self, tenant_id: &str, agent_id: &str) -> Result<(), CyberboxError> {
        let sql = format!(
            "ALTER TABLE {}.{} DELETE WHERE tenant_id = '{}' AND agent_id = '{}'",
            self.database,
            self.agents_table,
            tenant_id.replace('\'', "\\'"),
            agent_id.replace('\'', "\\'"),
        );
        self.execute_sql(&sql).await?;
        Ok(())
    }

    pub async fn list_scheduled_rules(&self) -> Result<Vec<DetectionRule>, CyberboxError> {
        let query = format!(
            "SELECT rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled, threshold_count, threshold_group_by, suppression_window_secs \
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
            "SELECT rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled, threshold_count, threshold_group_by, suppression_window_secs \
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
        self.list_events_in_range_after_cursor(tenant_id, from, to, None, limit)
            .await
    }

    pub async fn list_events_in_range_after_cursor(
        &self,
        tenant_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        after: Option<(DateTime<Utc>, Uuid)>,
        limit: u64,
    ) -> Result<Vec<EventEnvelope>, CyberboxError> {
        let after_clause = after
            .map(|(after_time, after_event_id)| {
                let after_time = format_clickhouse_datetime(after_time);
                format!(
                    " AND (event_time > toDateTime64('{after_time}', 3, 'UTC') \
                      OR (event_time = toDateTime64('{after_time}', 3, 'UTC') \
                      AND event_id > toUUID('{after_event_id}')))"
                )
            })
            .unwrap_or_default();
        let query = format!(
            "SELECT event_id, tenant_id, source, event_time, ingest_time, \
                    raw_payload, ocsf_record, enrichment, integrity_hash \
             FROM {}.{} \
             WHERE tenant_id = '{}' \
               AND event_time >= toDateTime64('{}', 3, 'UTC') \
               AND event_time <  toDateTime64('{}', 3, 'UTC') \
             {} \
             ORDER BY event_time ASC, event_id ASC \
             LIMIT {} \
             FORMAT JSON",
            self.database,
            self.table,
            escape_sql_literal(tenant_id),
            format_clickhouse_datetime(from),
            format_clickhouse_datetime(to),
            after_clause,
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
        let filter = sanitize_search_filter(&query.sql, "sql")?;
        let extra_filter = query
            .extra_where
            .as_deref()
            .map(|value| sanitize_search_filter(value, "extra_where"))
            .transpose()?
            .flatten();

        let tenant_id = escape_sql_literal(&query.tenant_id);
        let start = format_clickhouse_datetime(query.time_range.start);
        let end = format_clickhouse_datetime(query.time_range.end);
        let page_size = query.pagination.page_size.max(1);
        let offset = pagination_offset(query.pagination.page, page_size);

        let mut where_clauses = vec![format!(
            "tenant_id = '{}' AND event_time >= toDateTime64('{}', 3, 'UTC') AND event_time <= toDateTime64('{}', 3, 'UTC')",
            tenant_id, start, end
        )];
        if let Some(filter) = filter {
            where_clauses.push(format!("({filter})"));
        }
        if let Some(extra_filter) = extra_filter {
            where_clauses.push(format!("({extra_filter})"));
        }
        let wrapped_filter = where_clauses.join(" AND ");

        let rows_query = format!(
            "SELECT event_id, tenant_id, source, event_time, ingest_time, raw_payload, ocsf_record, enrichment, integrity_hash \
             FROM {}.{} \
             WHERE {} \
             ORDER BY event_time DESC LIMIT {} OFFSET {} FORMAT JSON",
            self.database, self.table, wrapped_filter, page_size, offset
        );
        let count_query = format!(
            "SELECT count() AS total FROM {}.{} WHERE {} FORMAT JSON",
            self.database, self.table, wrapped_filter
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

impl ClickHouseEventStore {
    async fn next_rule_version(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
    ) -> Result<u32, CyberboxError> {
        let query = format!(
            "SELECT max(version) AS version FROM {}.{} \
             WHERE tenant_id = '{}' AND rule_id = '{}' \
             FORMAT JSON",
            self.database,
            self.rule_versions_table,
            escape_sql_literal(tenant_id),
            rule_id
        );
        let response = self.execute_sql_json(&query).await?;
        let current = response
            .data
            .first()
            .and_then(|row| row.get("version"))
            .and_then(parse_u64_value)
            .unwrap_or(0);
        let current = u32::try_from(current)
            .map_err(|_| CyberboxError::Internal("rule version overflow".to_string()))?;
        Ok(current.saturating_add(1))
    }

    async fn append_rule_version_snapshot(
        &self,
        rule: &DetectionRule,
        created_at: DateTime<Utc>,
    ) -> Result<(), CyberboxError> {
        let version = self
            .next_rule_version(&rule.tenant_id, rule.rule_id)
            .await?;
        let row = json!({
            "rule_id": rule.rule_id.to_string(),
            "tenant_id": rule.tenant_id.clone(),
            "version": version,
            "sigma_source": rule.sigma_source.clone(),
            "compiled_plan": rule.compiled_plan.to_string(),
            "severity": severity_to_string(&rule.severity),
            "created_at": format_clickhouse_datetime(created_at),
        });
        let query = format!(
            "INSERT INTO {}.{} (rule_id, tenant_id, version, sigma_source, compiled_plan, severity, created_at) FORMAT JSONEachRow\n{}\n",
            self.database,
            self.rule_versions_table,
            serde_json::to_string(&row).map_err(|err| {
                CyberboxError::Internal(format!("rule version row serialization failed: {err}"))
            })?
        );
        self.execute_sql(&query).await.map(|_| ())
    }

    async fn current_rule_snapshot(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
    ) -> Result<Option<RuleVersion>, CyberboxError> {
        let query = format!(
            "SELECT rule_id, tenant_id, sigma_source, compiled_plan, severity, updated_at AS created_at \
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
        response
            .data
            .first()
            .map(|row| parse_rule_version_row_with_version(row, 1))
            .transpose()
    }

    pub async fn list_rule_versions(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
    ) -> Result<Vec<RuleVersion>, CyberboxError> {
        let query = format!(
            "SELECT rule_id, tenant_id, version, sigma_source, compiled_plan, severity, created_at \
             FROM {}.{} \
             WHERE tenant_id = '{}' AND rule_id = '{}' \
             ORDER BY version ASC \
             FORMAT JSON",
            self.database,
            self.rule_versions_table,
            escape_sql_literal(tenant_id),
            rule_id
        );
        let response = self.execute_sql_json(&query).await?;
        let mut versions = response
            .data
            .iter()
            .map(parse_rule_version_row)
            .collect::<Result<Vec<_>, _>>()?;
        if versions.is_empty() {
            if let Some(current) = self.current_rule_snapshot(tenant_id, rule_id).await? {
                versions.push(current);
            }
        }
        Ok(versions)
    }

    pub async fn get_rule_version(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
        version: u32,
    ) -> Result<Option<RuleVersion>, CyberboxError> {
        let query = format!(
            "SELECT rule_id, tenant_id, version, sigma_source, compiled_plan, severity, created_at \
             FROM {}.{} \
             WHERE tenant_id = '{}' AND rule_id = '{}' AND version = {} \
             LIMIT 1 \
             FORMAT JSON",
            self.database,
            self.rule_versions_table,
            escape_sql_literal(tenant_id),
            rule_id,
            version
        );
        let response = self.execute_sql_json(&query).await?;
        let version = response
            .data
            .first()
            .map(parse_rule_version_row)
            .transpose()?;
        Ok(version)
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
            "tenant_id": rule.tenant_id.clone(),
            "sigma_source": rule.sigma_source.clone(),
            "compiled_plan": rule.compiled_plan.to_string(),
            "schedule_or_stream": detection_mode_to_string(&rule.schedule_or_stream),
            "schedule_interval_seconds": interval_seconds,
            "schedule_lookback_seconds": lookback_seconds,
            "severity": severity_to_string(&rule.severity),
            "enabled": if rule.enabled { 1 } else { 0 },
            "threshold_count": rule.threshold_count.unwrap_or(0),
            "threshold_group_by": rule.threshold_group_by.clone().unwrap_or_default(),
            "suppression_window_secs": rule.suppression_window_secs.unwrap_or(0),
            "deleted": 0,
            "updated_at": format_clickhouse_datetime(now),
            "version": version
        });

        let query = format!(
            "INSERT INTO {}.{} (rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled, threshold_count, threshold_group_by, suppression_window_secs, deleted, updated_at, version) FORMAT JSONEachRow\n{}\n",
            self.database,
            self.rules_table,
            serde_json::to_string(&row)
                .map_err(|err| CyberboxError::Internal(format!("rule row serialization failed: {err}")))? 
        );
        self.execute_sql(&query).await?;
        self.append_rule_version_snapshot(&rule, now).await?;

        Ok(rule)
    }

    async fn list_rules(&self, tenant_id: &str) -> Result<Vec<DetectionRule>, CyberboxError> {
        let scheduler_health: std::collections::HashMap<Uuid, RuleSchedulerHealth> = self
            .list_rule_scheduler_health(tenant_id)
            .await?
            .into_iter()
            .collect();
        let query = format!(
            "SELECT rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled, threshold_count, threshold_group_by, suppression_window_secs \
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
            "SELECT rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled, threshold_count, threshold_group_by, suppression_window_secs \
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
            "threshold_count": existing.threshold_count.unwrap_or(0),
            "threshold_group_by": existing.threshold_group_by.clone().unwrap_or_default(),
            "suppression_window_secs": existing.suppression_window_secs.unwrap_or(0),
            "deleted": 1,
            "updated_at": format_clickhouse_datetime(now),
            "version": version
        });

        let query = format!(
            "INSERT INTO {}.{} (rule_id, tenant_id, sigma_source, compiled_plan, schedule_or_stream, schedule_interval_seconds, schedule_lookback_seconds, severity, enabled, threshold_count, threshold_group_by, suppression_window_secs, deleted, updated_at, version) FORMAT JSONEachRow\n{}\n",
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
            "severity": severity_to_string(&alert.severity),
            "rule_title": alert.rule_title,
            "first_seen": format_clickhouse_datetime(alert.first_seen),
            "last_seen": format_clickhouse_datetime(alert.last_seen),
            "status": alert_status_to_string(&alert.status),
            "evidence_refs": serde_json::to_string(&alert.evidence_refs).map_err(|err| CyberboxError::Internal(format!("evidence_refs serialization failed: {err}")))?,
            "routing_state": serde_json::to_string(&alert.routing_state).map_err(|err| CyberboxError::Internal(format!("routing_state serialization failed: {err}")))?,
            "assignee": alert.assignee,
            "case_id": alert.case_id.map(|case_id| case_id.to_string()),
            "hit_count": alert.hit_count,
            "mitre_attack": serde_json::to_string(&alert.mitre_attack).map_err(|err| CyberboxError::Internal(format!("mitre_attack serialization failed: {err}")))?,
            "resolution": alert.resolution.as_ref().and_then(|r| serde_json::to_string(r).ok()),
            "close_note": alert.close_note,
            "updated_at": format_clickhouse_datetime(now),
            "version": version
        });

        let query = format!(
            "INSERT INTO {}.{} (alert_id, tenant_id, rule_id, severity, rule_title, first_seen, last_seen, status, evidence_refs, routing_state, assignee, case_id, hit_count, mitre_attack, resolution, close_note, updated_at, version) FORMAT JSONEachRow\n{}\n",
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
            "SELECT alert_id, tenant_id, rule_id, severity, rule_title, first_seen, last_seen, status, evidence_refs, routing_state, assignee, case_id, hit_count, mitre_attack, resolution, close_note \
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
        if matches!(alert.status, AlertStatus::Closed) {
            return Err(crate::traits::closed_alert_assignment_error(alert_id));
        }
        let Some(assignee_patch) = assignment.assignee.as_ref() else {
            return Err(crate::traits::missing_alert_assignment_error());
        };
        let next_assignee = crate::traits::normalize_optional_string(assignee_patch.as_ref());
        alert.assignee = next_assignee;
        alert.status = if alert.assignee.is_some() {
            AlertStatus::InProgress
        } else if matches!(alert.status, AlertStatus::InProgress) {
            AlertStatus::Acknowledged
        } else {
            alert.status.clone()
        };
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
            "resolution":  case.resolution.as_ref().and_then(|r| serde_json::to_string(r).ok()),
            "close_note":  case.close_note,
            "tags":        serde_json::to_string(&case.tags).map_err(|e| CyberboxError::Internal(format!("tags: {e}")))?,
            "version":     version,
        });
        let query = format!(
            "INSERT INTO {}.{} (case_id, tenant_id, title, description, status, severity, alert_ids, assignee, created_by, created_at, updated_at, sla_due_at, closed_at, resolution, close_note, tags, version) FORMAT JSONEachRow\n{}\n",
            self.database, self.cases_table,
            serde_json::to_string(&row).map_err(|e| CyberboxError::Internal(format!("case row: {e}")))?
        );
        self.execute_sql(&query).await?;
        Ok(case)
    }

    async fn get_case(&self, tenant_id: &str, case_id: Uuid) -> Result<CaseRecord, CyberboxError> {
        let query = format!(
            "SELECT case_id, tenant_id, title, description, status, severity, alert_ids, assignee, created_by, created_at, updated_at, sla_due_at, closed_at, resolution, close_note, tags \
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
            "SELECT case_id, tenant_id, title, description, status, severity, alert_ids, assignee, created_by, created_at, updated_at, sla_due_at, closed_at, resolution, close_note, tags \
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
        apply_case_patch(&mut case, patch, now);
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

fn parse_agent_row(row: &Value) -> Result<AgentRecord, CyberboxError> {
    let agent_id = parse_string_field(row, "agent_id")?;
    let tenant_id = parse_string_field(row, "tenant_id")?;
    let hostname = parse_string_field(row, "hostname")?;
    let os = parse_string_field(row, "os")?;
    let version = parse_string_field(row, "version")?;
    let ip = row
        .get("ip")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    let registered_at = parse_datetime_field(row, "registered_at")?;
    let last_seen = parse_datetime_field(row, "last_seen")?;
    let group = row
        .get("group_name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    let tags: Vec<String> = row
        .get("tags")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let pending_config = row
        .get("pending_config")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    Ok(AgentRecord {
        agent_id,
        tenant_id,
        hostname,
        os,
        version,
        ip,
        registered_at,
        last_seen,
        group,
        tags,
        pending_config,
        enrolled_at: None,
        credential_version: 0,
        credential_hash: None,
        credential_rotated_at: None,
        device_certificate_serial: None,
        device_certificate_expires_at: None,
        revoked_at: None,
        revoked_reason: None,
    })
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
    let resolution = row
        .get("resolution")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok());
    let close_note = row
        .get("close_note")
        .and_then(|v| v.as_str().map(ToOwned::to_owned));
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
        resolution,
        close_note,
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
            "SELECT alert_id, tenant_id, rule_id, severity, rule_title, first_seen, last_seen, status, evidence_refs, routing_state, assignee, case_id, hit_count, mitre_attack, resolution, close_note \
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

fn sanitize_search_filter(input: &str, field_name: &str) -> Result<Option<String>, CyberboxError> {
    let candidate = input.trim();
    if candidate.is_empty() {
        return Ok(None);
    }

    let inspected = mask_quoted_text(candidate);
    for pattern in [";", "--", "/*", "*/"] {
        if inspected.contains(pattern) {
            return Err(CyberboxError::BadRequest(format!(
                "search:query {field_name} must be a filter expression, not raw SQL"
            )));
        }
    }
    for keyword in [
        "select", "from", "union", "join", "insert", "update", "delete", "alter", "create", "drop",
        "truncate", "system", "optimize", "format", "describe", "show", "attach", "detach",
    ] {
        if contains_sql_keyword(&inspected, keyword) {
            return Err(CyberboxError::BadRequest(format!(
                "search:query {field_name} must be a filter expression, not raw SQL"
            )));
        }
    }

    Ok(Some(candidate.to_string()))
}

fn mask_quoted_text(input: &str) -> String {
    let mut masked = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut idx = 0;
    let mut in_single = false;
    let mut in_double = false;

    while idx < chars.len() {
        let ch = chars[idx];
        if in_single {
            if ch == '\'' {
                if chars.get(idx + 1) == Some(&'\'') {
                    masked.push(' ');
                    masked.push(' ');
                    idx += 2;
                    continue;
                }
                in_single = false;
            }
            masked.push(' ');
            idx += 1;
            continue;
        }
        if in_double {
            if ch == '"' {
                if chars.get(idx + 1) == Some(&'"') {
                    masked.push(' ');
                    masked.push(' ');
                    idx += 2;
                    continue;
                }
                in_double = false;
            }
            masked.push(' ');
            idx += 1;
            continue;
        }

        match ch {
            '\'' => {
                in_single = true;
                masked.push(' ');
            }
            '"' => {
                in_double = true;
                masked.push(' ');
            }
            _ => masked.push(ch.to_ascii_lowercase()),
        }
        idx += 1;
    }

    masked
}

fn contains_sql_keyword(input: &str, keyword: &str) -> bool {
    let bytes = input.as_bytes();
    let keyword = keyword.as_bytes();
    let mut idx = 0;

    while idx + keyword.len() <= bytes.len() {
        if &bytes[idx..idx + keyword.len()] == keyword {
            let before = idx == 0 || !is_identifier_byte(bytes[idx - 1]);
            let after = idx + keyword.len() == bytes.len()
                || !is_identifier_byte(bytes[idx + keyword.len()]);
            if before && after {
                return true;
            }
        }
        idx += 1;
    }

    false
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
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
    let threshold_count = row
        .get("threshold_count")
        .and_then(parse_u64_value)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0);
    let threshold_group_by = row
        .get("threshold_group_by")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let suppression_window_secs = row
        .get("suppression_window_secs")
        .and_then(parse_u64_value)
        .filter(|value| *value > 0);

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
        threshold_count,
        threshold_group_by,
        suppression_window_secs,
    })
}

fn parse_rule_version_row(row: &Value) -> Result<RuleVersion, CyberboxError> {
    let version = parse_u32_field(row, "version")
        .ok_or_else(|| CyberboxError::Internal("missing or invalid rule version".to_string()))?;
    parse_rule_version_row_with_version(row, version)
}

fn parse_rule_version_row_with_version(
    row: &Value,
    version: u32,
) -> Result<RuleVersion, CyberboxError> {
    let rule_id = parse_uuid_field(row, "rule_id")?;
    let tenant_id = parse_string_field(row, "tenant_id")?;
    let sigma_source = parse_string_field(row, "sigma_source")?;
    let compiled_plan_raw = parse_string_field(row, "compiled_plan")?;
    let compiled_plan = serde_json::from_str::<Value>(&compiled_plan_raw).map_err(|err| {
        CyberboxError::Internal(format!(
            "invalid compiled_plan JSON for rule version {rule_id}: {err}"
        ))
    })?;
    let severity =
        serde_json::from_value::<Severity>(Value::String(parse_string_field(row, "severity")?))
            .map_err(|err| CyberboxError::Internal(format!("invalid severity: {err}")))?;
    let created_at = parse_datetime_field(row, "created_at")?;

    Ok(RuleVersion {
        rule_id,
        tenant_id,
        version,
        sigma_source,
        compiled_plan,
        severity,
        created_at,
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
    let case_id = row
        .get("case_id")
        .and_then(|value| value.as_str())
        .and_then(|value| Uuid::parse_str(value).ok());
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
        case_id,
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
    use super::{pagination_offset, sanitize_search_filter};
    use cyberbox_core::CyberboxError;

    #[test]
    fn pagination_offset_uses_one_based_pages() {
        assert_eq!(pagination_offset(0, 10), 0);
        assert_eq!(pagination_offset(1, 10), 0);
        assert_eq!(pagination_offset(2, 10), 10);
        assert_eq!(pagination_offset(3, 10), 20);
    }

    #[test]
    fn sanitize_search_filter_accepts_plain_filter_expressions() {
        let query = sanitize_search_filter("event_id = 'abc123'", "sql")
            .expect("filter shorthand should normalize");

        assert_eq!(query, Some("event_id = 'abc123'".to_string()));
    }

    #[test]
    fn sanitize_search_filter_rejects_raw_selects() {
        let err = sanitize_search_filter("SELECT * FROM cyberbox.events_hot LIMIT 5", "sql")
            .expect_err("raw select should be rejected");
        assert!(matches!(err, CyberboxError::BadRequest(_)));
    }

    #[test]
    fn sanitize_search_filter_allows_keywords_inside_string_literals() {
        let query = sanitize_search_filter("raw_payload LIKE '%select from union%'", "sql")
            .expect("keywords inside strings should be allowed");
        assert_eq!(
            query,
            Some("raw_payload LIKE '%select from union%'".to_string())
        );
    }

    #[test]
    fn sanitize_search_filter_rejects_comments_and_statement_terminators() {
        let err = sanitize_search_filter("event_id = 'abc123';", "sql")
            .expect_err("terminators should be rejected");
        assert!(matches!(err, CyberboxError::BadRequest(_)));

        let err = sanitize_search_filter("event_id = 'abc123' -- comment", "sql")
            .expect_err("comments should be rejected");
        assert!(matches!(err, CyberboxError::BadRequest(_)));
    }
}
