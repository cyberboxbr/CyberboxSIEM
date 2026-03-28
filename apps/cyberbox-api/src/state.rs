use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

/// Disk usage samples: (timestamp, used_bytes, total_bytes).
pub type DiskUsageSamples = Arc<Mutex<Vec<(chrono::DateTime<chrono::Utc>, u64, u64)>>>;

use arc_swap::ArcSwap;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::sync::broadcast;

use chrono::{DateTime, Utc};
use cyberbox_auth::JwtValidator;
use cyberbox_core::{
    threatintel::ThreatIntelFeed, AppConfig, CyberboxError, EpsLimiter, GeoIpEnricher, LookupStore,
    TeamsNotifier,
};
use cyberbox_detection::{RuleExecutor, SharedCorrelationState, SigmaCompiler};
use cyberbox_models::{
    AgentRecord, AlertRecord, DetectionMode, DetectionRule, EventEnvelope, RuleVersion, SourceInfo,
};
use cyberbox_storage::{
    ClickHouseEventStore, ClickHouseWriteBuffer, InMemoryStore, RuleStore, WorkflowStore,
};
use serde::{Deserialize, Serialize};

use crate::stream::{RawEventPublisher, ReplayRequestPublisher};

/// O(1) event deduplication cache with amortised O(1) eviction.
///
/// Replaces the previous `DashMap<String, Instant>` + full `retain()` scan (O(n) per event).
/// Design:
///   - `present`: DashMap for O(1) membership check (hash → expiry).
///   - `queue`: VecDeque of `(hash, expiry)` in insertion order.
///     Entries at the front are always oldest → expired entries are drained from the
///     front in O(k) where k = number of entries that expired since the last call.
///     Under steady-state traffic k ≈ 1–3 per call (vs O(total entries) for retain).
#[derive(Clone)]
pub struct DedupCache {
    inner: Arc<DedupCacheInner>,
}

struct DedupCacheInner {
    queue: Mutex<VecDeque<(String, Instant)>>,
    present: DashMap<String, Instant>,
    window: Duration,
}

impl DedupCache {
    pub fn new(window: Duration) -> Self {
        Self {
            inner: Arc::new(DedupCacheInner {
                queue: Mutex::new(VecDeque::new()),
                present: DashMap::new(),
                window,
            }),
        }
    }

    pub fn disabled() -> Self {
        Self::new(Duration::ZERO)
    }

    /// Returns `true` when `hash` was seen within the dedup window.
    /// Inserts the hash and evicts expired front-of-queue entries as a side effect.
    pub fn is_duplicate(&self, hash: &str) -> bool {
        if self.inner.window.is_zero() {
            return false;
        }
        let now = Instant::now();
        let expiry = now + self.inner.window;

        // Fast path: O(1) membership check.
        if let Some(exp) = self.inner.present.get(hash) {
            if now < *exp {
                return true; // Seen within window.
            }
            // Entry exists but expired — fall through to refresh it.
            drop(exp);
            self.inner.present.remove(hash);
        }

        // Slow path: acquire queue lock, evict expired front entries (amortised O(1)),
        // then push the new entry.
        let mut queue = self.inner.queue.lock().unwrap();
        while let Some((front_hash, front_exp)) = queue.front() {
            if now >= *front_exp {
                let h = front_hash.clone();
                queue.pop_front();
                // Remove from present only if it hasn't been refreshed (expiry matches).
                self.inner.present.remove_if(&h, |_, exp| now >= *exp);
            } else {
                break; // Queue is ordered by insertion time; no older entries remain.
            }
        }
        queue.push_back((hash.to_string(), expiry));
        self.inner.present.insert(hash.to_string(), expiry);
        false
    }
}

/// Lock-free snapshot cache of per-tenant enabled stream rules for the ingest hot path.
///
/// `load()` is a single atomic pointer load (~1 ns) — no locking, no DashMap traversal.
/// `refresh()` is a clone-on-write swap: copy the tenant map, update one entry, swap pointer.
/// Called only on rule mutations (rare vs ingest frequency).
#[derive(Default)]
pub struct StreamRuleCache {
    inner: ArcSwap<HashMap<String, Arc<Vec<DetectionRule>>>>,
}

impl StreamRuleCache {
    /// Return the cached stream rules for `tenant_id`. Empty if not yet populated.
    pub fn load(&self, tenant_id: &str) -> Arc<Vec<DetectionRule>> {
        self.inner
            .load()
            .get(tenant_id)
            .cloned()
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    /// Rebuild the cache entry for `tenant_id` from the full post-mutation rule list.
    /// Only enabled stream rules are kept — the ingest path doesn't evaluate scheduled rules.
    pub fn refresh(&self, tenant_id: &str, all_rules: Vec<DetectionRule>) {
        let stream_rules: Vec<DetectionRule> = all_rules
            .into_iter()
            .filter(|r| r.enabled && matches!(r.schedule_or_stream, DetectionMode::Stream))
            .collect();
        let mut map = (**self.inner.load()).clone();
        map.insert(tenant_id.to_string(), Arc::new(stream_rules));
        self.inner.store(Arc::new(map));
    }
}

/// Admin-managed API key record. The plaintext key is never stored — only its SHA-256 hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub key_id: String,
    pub name: String,
    pub key_prefix: String, // first 8 hex chars after "cb_" for display
    pub key_hash: String,   // SHA-256 hex of the full plaintext key
    pub tenant_id: String,
    pub roles: Vec<cyberbox_auth::Role>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<InMemoryStore>,
    pub workflow_store: Arc<WorkflowStore>,
    pub sigma_compiler: SigmaCompiler,
    pub rule_executor: RuleExecutor,
    pub raw_event_publisher: RawEventPublisher,
    pub replay_request_publisher: ReplayRequestPublisher,
    pub clickhouse_event_store: Option<Arc<ClickHouseEventStore>>,
    pub max_ingest_events_per_request: usize,
    pub max_ingest_body_bytes: usize,
    pub teams_notifier: TeamsNotifier,
    pub metrics: PrometheusHandle,
    /// Validated JWT validator. Present when `auth_disabled = false` and the
    /// OIDC issuer was reachable at startup.
    pub jwt_validator: Option<Arc<JwtValidator>>,
    /// When `true` the router injects `AuthBypass` and skips JWT validation.
    pub auth_disabled: bool,
    /// Per-tenant token-bucket EPS limiter.
    pub eps_limiter: Arc<EpsLimiter>,
    /// Lock-free stream-rule cache for the ingest hot path.
    pub stream_rule_cache: Arc<StreamRuleCache>,
    /// Async write buffer for durable ClickHouse event persistence.
    ///
    /// `send_events()` is non-blocking (~1 µs) — the background flush task
    /// handles batching and retries independently of the ingest hot path.
    /// `None` when `clickhouse_sink_enabled = false` or ClickHouse is not
    /// configured.
    pub clickhouse_write_buffer: Option<ClickHouseWriteBuffer>,
    // ── LGPD (Lei 13.709/2018) — Art. 37 / 41 ───────────────────────────────
    pub lgpd_dpo_email: String,
    pub lgpd_legal_basis: String,
    pub lgpd_controller_name: String,
    /// In-memory lookup table store for IOC matching via the `|lookup` Sigma modifier.
    pub lookup_store: Arc<LookupStore>,
    /// Configured TAXII threat intelligence feeds. feed_id → feed config.
    pub threat_intel_feeds: Arc<DashMap<Uuid, ThreatIntelFeed>>,
    /// Shared reqwest HTTP client for TAXII feed sync and NLQ API calls.
    pub http_client: reqwest::Client,
    /// Offline GeoIP enricher (MaxMind GeoLite2). `None` when `geoip_enabled = false`.
    pub geoip_enricher: Option<Arc<GeoIpEnricher>>,
    /// Enable the POST /api/v1/events/nlq endpoint.
    pub nlq_enabled: bool,
    /// Resolved NLQ provider + API key. `None` when `nlq_enabled = false` or no key configured.
    pub nlq_provider: Option<(cyberbox_core::nlq::NlqProvider, String)>,
    /// Short-window event deduplication cache.
    /// Duplicate events (same integrity_hash within the configured window) are dropped at ingest.
    /// Uses VecDeque-based amortised O(1) eviction instead of O(n) DashMap::retain().
    pub event_dedup_cache: DedupCache,
    /// How long (seconds) to remember a seen event hash. 0 = dedup disabled.
    pub event_dedup_window_secs: u64,
    /// Threshold hit counters for stream rules: "{rule_id}:{entity_value}" → count.
    /// Counts are never evicted — resets happen when the rule fires and count resets to 0.
    pub threshold_counters: Arc<DashMap<String, u32>>,
    /// How often (seconds) to send a scheduled digest to Teams. 0 = disabled.
    pub report_interval_secs: u64,
    /// Tracks when the last digest was sent so the scheduler can decide when to send next.
    pub last_report_sent_at: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    /// Per-tenant RBAC overrides: "{tenant_id}:{user_id}" → assigned roles.
    /// Merged with JWT-derived roles so admins can grant or restrict access without
    /// reissuing tokens. Managed via POST /api/v1/rbac/users.
    pub rbac_store: Arc<DashMap<String, Vec<cyberbox_auth::Role>>>,
    /// Broadcast channel for live alert events (SSE stream `/api/v1/alerts/stream`).
    /// Capacity 1024 — lagging receivers drop old messages silently.
    pub alert_tx: broadcast::Sender<AlertRecord>,
    /// Broadcast channel for live event tail (SSE stream `/api/v1/events/stream`).
    /// Capacity 4096 — lagging receivers drop old messages silently.
    pub event_tx: broadcast::Sender<EventEnvelope>,
    /// Per-(rule_id, entity) suppression expiry: key → Instant when suppression expires.
    pub suppression_map: Arc<DashMap<String, std::time::Instant>>,
    /// Directory where persistent JSON state (feeds, RBAC) is saved. Empty = disabled.
    pub state_dir: String,
    /// Per-rule_id mutex for auto-case correlation.
    /// Prevents concurrent `auto_correlate_alert` tasks from creating duplicate cases
    /// when multiple alerts for the same rule fire simultaneously.
    pub case_correlation_locks: Arc<DashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
    /// Short-lived WebSocket auth tokens: opaque token string → (tenant_id, expiry Instant).
    /// Tokens are issued by `GET /api/v1/alerts/ws-token` and validated on WebSocket upgrade.
    pub ws_tokens: Arc<DashMap<String, (String, std::time::Instant)>>,
    /// Per-(tenant_id, source_type) ingestion statistics for `GET /api/v1/sources`.
    /// Updated on every accepted event batch in the ingest hot path.
    pub sources: Arc<DashMap<String, SourceInfo>>,
    /// Registered cyberbox-agent instances: agent_id → AgentRecord.
    pub agents: Arc<DashMap<String, AgentRecord>>,
    /// When `Some`, all requests are forced to this tenant (single-tenant mode).
    pub tenant_id_override: Option<String>,
    /// Static API key for machine-to-machine ingestion. `None` when not configured.
    pub ingest_api_key: Option<String>,
    /// Admin-managed API keys: key_hash → ApiKeyRecord.
    pub api_key_store: Arc<DashMap<String, ApiKeyRecord>>,
    /// Parallel auth-layer view of the API key store for the `ApiKeyAuthStore` extension.
    /// Kept in sync with `api_key_store` on create/revoke.
    pub api_key_auth_entries: Arc<DashMap<String, cyberbox_auth::ApiKeyAuthEntry>>,
    /// HMAC secret used to sign and verify agent device certificates.
    pub agent_device_certificate_signing_secret: String,
    /// Signed agent device certificate lifetime.
    pub agent_device_certificate_ttl_secs: u64,
    /// Per-tenant mutation rate limiter: "tenant_id:endpoint" -> (count, window_start).
    pub mutation_rate_limiter: Arc<DashMap<String, (u32, std::time::Instant)>>,
    /// AbuseIPDB API key for on-demand IP reputation lookups.
    pub abuseipdb_api_key: String,
    /// VirusTotal API key for on-demand IOC lookups (IP, domain, hash).
    pub virustotal_api_key: String,
    /// Whether AbuseIPDB enrichment is enabled (toggled via UI).
    pub abuseipdb_enabled: Arc<AtomicBool>,
    /// Whether VirusTotal enrichment is enabled (toggled via UI).
    pub virustotal_enabled: Arc<AtomicBool>,
    /// Timestamp of the last AbuseIPDB blacklist sync.
    pub abuseipdb_last_sync: Arc<std::sync::Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
    /// Number of IPs in the current AbuseIPDB blacklist.
    pub abuseipdb_blacklist_count: Arc<AtomicUsize>,
    /// Ring buffer of disk usage samples (timestamp, used_bytes, total_bytes).
    /// Sampled every 30 minutes, kept for 7 days (336 samples max).
    pub disk_usage_samples: DiskUsageSamples,
}

impl AppState {
    pub async fn list_rules_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<DetectionRule>, CyberboxError> {
        if let Some(clickhouse_store) = &self.clickhouse_event_store {
            clickhouse_store.list_rules(tenant_id).await
        } else {
            self.storage.list_rules(tenant_id).await
        }
    }

    pub async fn get_rule_for_tenant(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
    ) -> Result<DetectionRule, CyberboxError> {
        if let Some(clickhouse_store) = &self.clickhouse_event_store {
            clickhouse_store.get_rule(tenant_id, rule_id).await
        } else {
            self.storage.get_rule(tenant_id, rule_id).await
        }
    }

    pub async fn refresh_stream_rules(&self, tenant_id: &str) -> Result<(), CyberboxError> {
        let fresh = self.list_rules_for_tenant(tenant_id).await?;
        self.stream_rule_cache.refresh(tenant_id, fresh);
        Ok(())
    }

    pub async fn list_rule_versions_for_tenant(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
    ) -> Result<Vec<RuleVersion>, CyberboxError> {
        if let Some(clickhouse_store) = &self.clickhouse_event_store {
            clickhouse_store
                .list_rule_versions(tenant_id, rule_id)
                .await
        } else {
            Ok(self.storage.list_rule_versions(tenant_id, rule_id))
        }
    }

    pub async fn get_rule_version_for_tenant(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
        version: u32,
    ) -> Result<RuleVersion, CyberboxError> {
        if let Some(clickhouse_store) = &self.clickhouse_event_store {
            if let Some(snapshot) = clickhouse_store
                .get_rule_version(tenant_id, rule_id, version)
                .await?
            {
                Ok(snapshot)
            } else {
                clickhouse_store
                    .list_rule_versions(tenant_id, rule_id)
                    .await?
                    .into_iter()
                    .find(|snapshot| snapshot.version == version)
                    .ok_or(CyberboxError::NotFound)
            }
        } else {
            self.storage
                .get_rule_version(tenant_id, rule_id, version)
                .ok_or(CyberboxError::NotFound)
        }
    }

    pub fn is_duplicate(&self, hash: &str) -> bool {
        self.event_dedup_cache.is_duplicate(hash)
    }

    pub fn new(metrics: PrometheusHandle) -> Self {
        let defaults = AppConfig::default();
        Self {
            storage: Arc::new(InMemoryStore::default()),
            workflow_store: Arc::new(
                WorkflowStore::open_file_blocking(&defaults.state_dir)
                    .expect("workflow store should initialise"),
            ),
            sigma_compiler: SigmaCompiler,
            rule_executor: RuleExecutor::default(),
            raw_event_publisher: RawEventPublisher::default(),
            replay_request_publisher: ReplayRequestPublisher::default(),
            clickhouse_event_store: None,
            max_ingest_events_per_request: defaults.ingest_max_events_per_request.max(1),
            max_ingest_body_bytes: defaults.ingest_max_body_bytes.max(1024),
            teams_notifier: TeamsNotifier::from_config(&defaults),
            metrics,
            jwt_validator: None,
            auth_disabled: true,
            eps_limiter: Arc::new(EpsLimiter::new(
                defaults.eps_limit_per_tenant,
                defaults.eps_burst_seconds,
            )),
            stream_rule_cache: Arc::new(StreamRuleCache::default()),
            clickhouse_write_buffer: None,
            lgpd_dpo_email: defaults.lgpd_dpo_email,
            lgpd_legal_basis: defaults.lgpd_legal_basis,
            lgpd_controller_name: defaults.lgpd_controller_name,
            lookup_store: Arc::new(LookupStore::new()),
            threat_intel_feeds: Arc::new(DashMap::new()),
            http_client: reqwest::Client::new(),
            geoip_enricher: None,
            nlq_enabled: false,
            nlq_provider: None,
            event_dedup_cache: DedupCache::disabled(),
            event_dedup_window_secs: 0,
            threshold_counters: Arc::new(DashMap::new()),
            report_interval_secs: 0,
            last_report_sent_at: Arc::new(std::sync::Mutex::new(None)),
            rbac_store: Arc::new(DashMap::new()),
            alert_tx: broadcast::channel(1024).0,
            event_tx: broadcast::channel(4096).0,
            suppression_map: Arc::new(DashMap::new()),
            state_dir: "data".to_string(),
            case_correlation_locks: Arc::new(DashMap::new()),
            ws_tokens: Arc::new(DashMap::new()),
            sources: Arc::new(DashMap::new()),
            agents: Arc::new(DashMap::new()),
            tenant_id_override: None,
            ingest_api_key: None,
            api_key_store: Arc::new(DashMap::new()),
            api_key_auth_entries: Arc::new(DashMap::new()),
            agent_device_certificate_signing_secret: format!("dev-device-cert-{}", Uuid::new_v4()),
            agent_device_certificate_ttl_secs: defaults.agent_device_certificate_ttl_secs.max(60),
            mutation_rate_limiter: Arc::new(DashMap::new()),
            abuseipdb_api_key: String::new(),
            virustotal_api_key: String::new(),
            abuseipdb_enabled: Arc::new(AtomicBool::new(false)),
            virustotal_enabled: Arc::new(AtomicBool::new(false)),
            abuseipdb_last_sync: Arc::new(std::sync::Mutex::new(None)),
            abuseipdb_blacklist_count: Arc::new(AtomicUsize::new(0)),
            disk_usage_samples: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn from_config(
        metrics: PrometheusHandle,
        config: &AppConfig,
        jwt_validator: Option<Arc<JwtValidator>>,
    ) -> Result<Self, CyberboxError> {
        let correlation_postgres_url = if config.correlation_state_postgres_url.trim().is_empty() {
            config.workflow_store_postgres_url.as_str()
        } else {
            config.correlation_state_postgres_url.as_str()
        };
        let correlation_state = Arc::new(SharedCorrelationState::from_backend(
            &config.correlation_state_backend,
            correlation_postgres_url,
            &config.correlation_state_postgres_schema,
        )?);
        let agent_device_certificate_signing_secret = if config
            .agent_device_certificate_signing_secret
            .trim()
            .is_empty()
        {
            if !config.auth_disabled {
                tracing::error!(
                    "agent_device_certificate_signing_secret is empty but auth is enabled! \
                         Agent enrollment will use an ephemeral key that is lost on restart. \
                         Set CYBERBOX__AGENT_DEVICE_CERTIFICATE_SIGNING_SECRET for production."
                );
            }
            tracing::warn!(
                    "agent_device_certificate_signing_secret is empty; using an ephemeral dev secret for this process"
                );
            format!("dev-device-cert-{}", Uuid::new_v4())
        } else {
            config.agent_device_certificate_signing_secret.clone()
        };
        Ok(Self {
            storage: Arc::new(InMemoryStore::default()),
            workflow_store: Arc::new(WorkflowStore::from_config(config)?),
            sigma_compiler: SigmaCompiler,
            rule_executor: RuleExecutor::default().with_correlation_state(correlation_state),
            raw_event_publisher: RawEventPublisher::from_config(config)?,
            replay_request_publisher: ReplayRequestPublisher::from_config(config)?,
            clickhouse_event_store: config.clickhouse_search_enabled.then(|| {
                Arc::new(
                    ClickHouseEventStore::new(
                        &config.clickhouse_url,
                        &config.clickhouse_user,
                        &config.clickhouse_password,
                        &config.clickhouse_database,
                        &config.clickhouse_table,
                    )
                    .with_insert_settings(
                        config.clickhouse_insert_async_enabled,
                        config.clickhouse_insert_wait_for_async,
                    )
                    .with_insert_deduplication_settings(
                        config.clickhouse_insert_async_deduplicate_enabled,
                        config.clickhouse_insert_deduplication_token_enabled,
                    )
                    .with_replicated_tables_enabled(config.clickhouse_replicated_tables_enabled)
                    .with_retention_days_hot(config.clickhouse_retention_days_hot),
                )
            }),
            max_ingest_events_per_request: config.ingest_max_events_per_request.max(1),
            max_ingest_body_bytes: config.ingest_max_body_bytes.max(1024),
            teams_notifier: TeamsNotifier::from_config(config),
            metrics,
            jwt_validator,
            auth_disabled: config.auth_disabled,
            eps_limiter: Arc::new(EpsLimiter::new(
                config.eps_limit_per_tenant,
                config.eps_burst_seconds,
            )),
            stream_rule_cache: Arc::new(StreamRuleCache::default()),
            clickhouse_write_buffer: None,
            lgpd_dpo_email: config.lgpd_dpo_email.clone(),
            lgpd_legal_basis: config.lgpd_legal_basis.clone(),
            lgpd_controller_name: config.lgpd_controller_name.clone(),
            lookup_store: Arc::new(LookupStore::new()),
            threat_intel_feeds: Arc::new(DashMap::new()),
            http_client: reqwest::Client::new(),
            geoip_enricher: if config.geoip_enabled && !config.geoip_db_path.is_empty() {
                match GeoIpEnricher::open(&config.geoip_db_path) {
                    Ok(e) => {
                        tracing::info!(db = %config.geoip_db_path, "GeoIP enricher loaded");
                        Some(Arc::new(e))
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "GeoIP enricher failed to load — enrichment disabled");
                        None
                    }
                }
            } else {
                None
            },
            event_dedup_cache: DedupCache::new(Duration::from_secs(config.event_dedup_window_secs)),
            event_dedup_window_secs: config.event_dedup_window_secs,
            threshold_counters: Arc::new(DashMap::new()),
            report_interval_secs: config.report_interval_secs,
            last_report_sent_at: Arc::new(std::sync::Mutex::new(None)),
            rbac_store: Arc::new(DashMap::new()),
            nlq_enabled: config.nlq_enabled,
            nlq_provider: if config.nlq_enabled {
                cyberbox_core::nlq::NlqProvider::from_config(
                    &config.nlq_provider,
                    &config.anthropic_api_key,
                    &config.openai_api_key,
                )
                .map(|p| {
                    let key = match p {
                        cyberbox_core::nlq::NlqProvider::Anthropic => {
                            config.anthropic_api_key.clone()
                        }
                        cyberbox_core::nlq::NlqProvider::OpenAI => config.openai_api_key.clone(),
                    };
                    (p, key)
                })
            } else {
                None
            },
            alert_tx: broadcast::channel(1024).0,
            event_tx: broadcast::channel(4096).0,
            suppression_map: Arc::new(DashMap::new()),
            state_dir: config.state_dir.clone(),
            case_correlation_locks: Arc::new(DashMap::new()),
            ws_tokens: Arc::new(DashMap::new()),
            sources: Arc::new(DashMap::new()),
            agents: Arc::new(DashMap::new()),
            tenant_id_override: if config.tenant_id_override.is_empty() {
                None
            } else {
                Some(config.tenant_id_override.clone())
            },
            ingest_api_key: if config.ingest_api_key.is_empty() {
                None
            } else {
                Some(config.ingest_api_key.clone())
            },
            api_key_store: Arc::new(DashMap::new()),
            api_key_auth_entries: Arc::new(DashMap::new()),
            agent_device_certificate_signing_secret,
            agent_device_certificate_ttl_secs: config.agent_device_certificate_ttl_secs.max(60),
            mutation_rate_limiter: Arc::new(DashMap::new()),
            abuseipdb_api_key: config.abuseipdb_api_key.clone(),
            virustotal_api_key: config.virustotal_api_key.clone(),
            abuseipdb_enabled: Arc::new(AtomicBool::new(!config.abuseipdb_api_key.is_empty())),
            virustotal_enabled: Arc::new(AtomicBool::new(!config.virustotal_api_key.is_empty())),
            abuseipdb_last_sync: Arc::new(std::sync::Mutex::new(None)),
            abuseipdb_blacklist_count: Arc::new(AtomicUsize::new(0)),
            disk_usage_samples: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
    }
}
