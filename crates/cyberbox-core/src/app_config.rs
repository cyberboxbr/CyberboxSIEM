use config::{Config, Environment};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub bind_addr: String,
    pub redpanda_brokers: String,
    pub kafka_raw_topic: String,
    pub kafka_normalized_topic: String,
    pub kafka_alerts_topic: String,
    pub kafka_raw_dlq_topic: String,
    pub kafka_normalized_dlq_topic: String,
    pub kafka_alerts_dlq_topic: String,
    pub kafka_replay_topic: String,
    pub kafka_replay_dlq_topic: String,
    pub kafka_worker_group_id: String,
    pub worker_role: String,
    pub scheduler_tick_interval_seconds: u64,
    pub ingest_max_events_per_request: usize,
    pub ingest_max_body_bytes: usize,
    pub kafka_publish_raw_enabled: bool,
    pub kafka_producer_acks: String,
    pub kafka_producer_enable_idempotence: bool,
    pub kafka_producer_max_in_flight_requests_per_connection: u32,
    pub kafka_producer_message_timeout_ms: u64,
    pub kafka_producer_queue_full_max_retries: u32,
    pub kafka_producer_queue_full_backoff_ms: u64,
    pub kafka_producer_overload_retry_after_seconds: u64,
    pub kafka_producer_delivery_tracker_queue_size: usize,
    pub kafka_producer_queue_buffering_max_messages: usize,
    pub kafka_producer_queue_buffering_max_kbytes: usize,
    pub clickhouse_search_enabled: bool,
    pub clickhouse_sink_enabled: bool,
    pub clickhouse_sink_batch_size: usize,
    pub clickhouse_sink_batch_max_bytes: usize,
    pub clickhouse_sink_flush_interval_ms: u64,
    pub clickhouse_sink_max_retries: u32,
    pub clickhouse_sink_retry_backoff_base_ms: u64,
    pub clickhouse_sink_retry_backoff_jitter_ms: u64,
    pub clickhouse_sink_worker_count: usize,
    pub stream_rule_cache_refresh_interval_seconds: u64,
    pub clickhouse_url: String,
    pub clickhouse_user: String,
    pub clickhouse_password: String,
    pub clickhouse_database: String,
    pub clickhouse_table: String,
    pub clickhouse_insert_async_enabled: bool,
    pub clickhouse_insert_wait_for_async: bool,
    pub clickhouse_insert_async_deduplicate_enabled: bool,
    pub clickhouse_insert_deduplication_token_enabled: bool,
    pub clickhouse_replicated_tables_enabled: bool,
    pub minio_endpoint: String,
    pub minio_bucket: String,
    pub oidc_issuer: String,
    pub oidc_audience: String,
    pub worker_metrics_bind_addr: String,
    pub teams_routing_enabled: bool,
    pub teams_webhook_url: String,
    /// Enable offline GeoIP enrichment via MaxMind GeoLite2.
    pub geoip_enabled: bool,
    /// Absolute path to the GeoLite2-City.mmdb file.
    pub geoip_db_path: String,
    /// Skip JWT validation and read identity from plain headers.
    /// Set to `false` in production; keep `true` for local dev / tests.
    pub auth_disabled: bool,
    /// Maximum sustained ingest rate per tenant (events/second).
    pub eps_limit_per_tenant: u64,
    /// Burst window in seconds.  Burst capacity = eps_limit × burst_seconds.
    pub eps_burst_seconds: u64,
    /// Hot-tier event retention in days.  ClickHouse rows older than this are
    /// automatically deleted by the TTL engine.  Set to 0 to disable TTL
    /// (keep data forever).  Applies only when `clickhouse_sink_enabled = true`.
    pub clickhouse_retention_days_hot: u32,
    // ── Syslog receiver ──────────────────────────────────────────────────────
    /// Enable the syslog UDP listener.
    pub syslog_udp_enabled: bool,
    /// Enable the syslog TCP listener (newline-framed).
    pub syslog_tcp_enabled: bool,
    /// Bind address for both UDP and TCP syslog listeners.
    pub syslog_bind_addr: String,
    /// UDP syslog port (default 514; use 5514 in unprivileged containers).
    pub syslog_udp_port: u16,
    /// TCP syslog port (default 514; use 5514 in unprivileged containers).
    pub syslog_tcp_port: u16,
    /// Tenant ID assigned to events arriving via syslog when no tenant header
    /// is present (syslog has no native multi-tenancy concept).
    pub syslog_default_tenant_id: String,
    // ── LGPD (Lei 13.709/2018) compliance ────────────────────────────────────
    /// E-mail of the Data Protection Officer (Encarregado) — Art. 41.
    /// Included in data subject export responses so requestors know who to contact.
    pub lgpd_dpo_email: String,
    /// Legal basis for processing personal data in security events — Art. 7.
    /// Common values: "legitimate_interest" (security monitoring), "legal_obligation".
    pub lgpd_legal_basis: String,
    /// Organisation name shown in data-subject export reports.
    pub lgpd_controller_name: String,
    // ── Scheduled reports ─────────────────────────────────────────────────────
    /// How often (in seconds) to send a digest to the Teams webhook. 0 = disabled.
    pub report_interval_secs: u64,
    // ── Event deduplication ───────────────────────────────────────────────────
    /// Dedup window in seconds. Events with the same integrity_hash seen within
    /// this window are dropped at ingest. `0` disables deduplication.
    pub event_dedup_window_secs: u64,
    // ── Natural Language Query ────────────────────────────────────────────────
    /// Enable POST /api/v1/events/nlq.  Requires at least one LLM API key.
    pub nlq_enabled: bool,
    /// Anthropic API key used by the NLQ engine to call Claude.
    /// Set via environment variable `CYBERBOX__ANTHROPIC_API_KEY`.
    pub anthropic_api_key: String,
    /// OpenAI API key used by the NLQ engine as an alternative to Claude.
    /// Set via environment variable `CYBERBOX__OPENAI_API_KEY`.
    pub openai_api_key: String,
    /// Which LLM provider to use: "anthropic", "openai", or "auto" (default).
    /// "auto" prefers Anthropic when both keys are set.
    /// Set via environment variable `CYBERBOX__NLQ_PROVIDER`.
    pub nlq_provider: String,
    // ── State persistence ─────────────────────────────────────────────────────
    /// Directory for persistent JSON state (feeds, RBAC). Empty = in-memory only.
    pub state_dir: String,
    /// Workflow storage backend: `file` or `postgres`.
    pub workflow_store_backend: String,
    /// PostgreSQL connection string for workflow storage.
    pub workflow_store_postgres_url: String,
    /// PostgreSQL schema for workflow tables.
    pub workflow_store_postgres_schema: String,
    /// Correlation-state backend: `memory` or `postgres`.
    pub correlation_state_backend: String,
    /// Optional PostgreSQL connection string for correlation state.
    /// Falls back to `workflow_store_postgres_url` when empty.
    pub correlation_state_postgres_url: String,
    /// PostgreSQL schema for correlation-state tables.
    pub correlation_state_postgres_schema: String,
    // ── Auth hardening ────────────────────────────────────────────────────────
    /// Background JWKS refresh interval in seconds. `0` = on-demand only.
    pub jwks_refresh_interval_secs: u64,
    /// HMAC signing secret used for signed agent device certificates.
    pub agent_device_certificate_signing_secret: String,
    /// Signed agent device certificate lifetime in seconds.
    pub agent_device_certificate_ttl_secs: u64,
    // ── OpenTelemetry ─────────────────────────────────────────────────────────
    /// OTLP gRPC endpoint (e.g. `http://jaeger:4317`). Empty = OTel disabled.
    pub otlp_endpoint: String,
    // ── Single-tenant mode ────────────────────────────────────────────────────
    /// When non-empty, all authenticated requests are forced to this tenant,
    /// ignoring whatever the JWT or bypass headers say.
    /// Set `CYBERBOX__TENANT_ID_OVERRIDE=safebox` for a single-tenant deployment.
    pub tenant_id_override: String,
    /// Static API key for machine-to-machine ingestion (agents, collectors, scripts).
    /// When set, requests with `X-Api-Key: <key>` or `Authorization: ApiKey <key>`
    /// are accepted with the `ingestor` role, bypassing JWT validation.
    /// Set `CYBERBOX__INGEST_API_KEY=<random-secret>` in production.
    pub ingest_api_key: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".to_string(),
            redpanda_brokers: "localhost:19092".to_string(),
            kafka_raw_topic: "cyberbox.events.raw".to_string(),
            kafka_normalized_topic: "cyberbox.events.normalized".to_string(),
            kafka_alerts_topic: "cyberbox.alerts".to_string(),
            kafka_raw_dlq_topic: "cyberbox.events.raw.dlq".to_string(),
            kafka_normalized_dlq_topic: "cyberbox.events.normalized.dlq".to_string(),
            kafka_alerts_dlq_topic: "cyberbox.alerts.dlq".to_string(),
            kafka_replay_topic: "cyberbox.replay".to_string(),
            kafka_replay_dlq_topic: "cyberbox.replay.dlq".to_string(),
            kafka_worker_group_id: "cyberbox-worker-v1".to_string(),
            worker_role: "all".to_string(),
            scheduler_tick_interval_seconds: 5,
            ingest_max_events_per_request: 5000,
            ingest_max_body_bytes: 4 * 1024 * 1024,
            kafka_publish_raw_enabled: true,
            kafka_producer_acks: "all".to_string(),
            kafka_producer_enable_idempotence: true,
            kafka_producer_max_in_flight_requests_per_connection: 5,
            kafka_producer_message_timeout_ms: 30000,
            kafka_producer_queue_full_max_retries: 3,
            kafka_producer_queue_full_backoff_ms: 5,
            kafka_producer_overload_retry_after_seconds: 1,
            kafka_producer_delivery_tracker_queue_size: 100000,
            kafka_producer_queue_buffering_max_messages: 50000,
            kafka_producer_queue_buffering_max_kbytes: 262144,
            clickhouse_search_enabled: true,
            clickhouse_sink_enabled: true,
            clickhouse_sink_batch_size: 5000,
            clickhouse_sink_batch_max_bytes: 8 * 1024 * 1024,
            clickhouse_sink_flush_interval_ms: 500,
            clickhouse_sink_max_retries: 6,
            clickhouse_sink_retry_backoff_base_ms: 250,
            clickhouse_sink_retry_backoff_jitter_ms: 200,
            clickhouse_sink_worker_count: 8,
            stream_rule_cache_refresh_interval_seconds: 15,
            clickhouse_url: "http://localhost:8123".to_string(),
            clickhouse_user: "cyberbox".to_string(),
            clickhouse_password: "cyberbox".to_string(),
            clickhouse_database: "cyberbox".to_string(),
            clickhouse_table: "events_hot".to_string(),
            clickhouse_insert_async_enabled: true,
            clickhouse_insert_wait_for_async: true,
            clickhouse_insert_async_deduplicate_enabled: true,
            clickhouse_insert_deduplication_token_enabled: true,
            clickhouse_replicated_tables_enabled: false,
            minio_endpoint: "http://localhost:9000".to_string(),
            minio_bucket: "cyberbox-cold".to_string(),
            oidc_issuer: "http://localhost:8081/realms/cyberbox".to_string(),
            oidc_audience: "cyberbox-api".to_string(),
            worker_metrics_bind_addr: "0.0.0.0:9091".to_string(),
            teams_routing_enabled: false,
            teams_webhook_url: String::new(),
            geoip_enabled: false,
            geoip_db_path: String::new(),
            auth_disabled: true,
            eps_limit_per_tenant: 10_000,
            eps_burst_seconds: 5,
            clickhouse_retention_days_hot: 30,
            syslog_udp_enabled: false,
            syslog_tcp_enabled: false,
            syslog_bind_addr: "0.0.0.0".to_string(),
            syslog_udp_port: 5514,
            syslog_tcp_port: 5514,
            syslog_default_tenant_id: "default".to_string(),
            lgpd_dpo_email: String::new(),
            lgpd_legal_basis: "legitimate_interest".to_string(),
            lgpd_controller_name: String::new(),
            report_interval_secs: 0,
            event_dedup_window_secs: 0,
            nlq_enabled: false,
            anthropic_api_key: String::new(),
            openai_api_key: String::new(),
            nlq_provider: "auto".to_string(),
            state_dir: "data".to_string(),
            workflow_store_backend: "file".to_string(),
            workflow_store_postgres_url: String::new(),
            workflow_store_postgres_schema: "public".to_string(),
            correlation_state_backend: "memory".to_string(),
            correlation_state_postgres_url: String::new(),
            correlation_state_postgres_schema: "public".to_string(),
            jwks_refresh_interval_secs: 300,
            agent_device_certificate_signing_secret: String::new(),
            agent_device_certificate_ttl_secs: 604_800,
            otlp_endpoint: String::new(),
            tenant_id_override: String::new(),
            ingest_api_key: String::new(),
        }
    }
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let cfg = Config::builder()
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(Environment::with_prefix("CYBERBOX").separator("__"))
            .build()?;

        Ok(cfg.try_deserialize().unwrap_or_default())
    }
}
