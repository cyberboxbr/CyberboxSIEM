use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use rayon::prelude::*;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, Query, State,
    },
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{delete, get, patch, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use metrics::{counter, histogram};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;
use uuid::Uuid;

use cyberbox_auth::{AuthContext, Role};
use cyberbox_core::{
    nlq::{GenerateSigmaRequest, NlqRequest},
    threatintel::ThreatIntelFeed,
    CyberboxError,
};
use cyberbox_models::{
    AckAlertRequest, AgentRecord, AlertRecord, AlertsPage, AssignAlertRequest, AuditLogRecord,
    AuditLogsResponse, BacktestRequest, BacktestResponse, CaseAlertIdsRequest, CaseRecord,
    CaseStatus, CloseAlertRequest, CoverageReport, CoveredTechnique, CreateCaseRequest,
    DetectionMode, DetectionRule, DryRunRequest, DryRunResponse, EventEnvelope, EventIngestRequest,
    EventIngestResponse, ListAlertsQuery, Pagination, RuleScheduleConfig, RuleTestRequest,
    RuleTestResult, RuleVersion, SearchQueryRequest, Severity, SourceInfo, TimeRange,
    UpdateCaseRequest,
};
use cyberbox_storage::{sla_due_at, AlertStore, CaseStore, EventStore, RuleStore};

use crate::extractors::SimdJson;
use crate::persist;
use crate::state::AppState;

pub fn api_router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/events:ingest", post(ingest_events))
        .route("/api/v1/events", delete(purge_tenant_events))
        .route("/api/v1/rules", post(create_rule).get(list_rules))
        // Detection engineering helpers (static routes before parameterised ones)
        .route("/api/v1/rules/dry-run", post(dry_run_rule))
        .route("/api/v1/rules/import-pack", post(import_rule_pack))
        .route("/api/v1/rules/sync-dir", post(sync_rules_from_dir))
        .route("/api/v1/rules/:id", patch(update_rule).delete(delete_rule))
        .route("/api/v1/rules/:id/test", post(test_rule))
        .route("/api/v1/rules/:id/backtest", post(backtest_rule))
        .route("/api/v1/coverage", get(mitre_coverage))
        .route("/api/v1/audit-logs", get(list_audit_logs))
        .route("/api/v1/search:query", post(search_query))
        .route("/api/v1/alerts", get(list_alerts))
        .route("/api/v1/alerts/*operation", post(alert_operation))
        .route("/api/v1/scheduler/tick", post(scheduler_tick))
        // LGPD (Lei 13.709/2018) compliance endpoints
        .route("/api/v1/lgpd/export", get(lgpd_export))
        .route("/api/v1/lgpd/anonymize", post(lgpd_anonymize))
        .route("/api/v1/lgpd/breach", post(lgpd_report_breach))
        // Lookup table management
        .route(
            "/api/v1/lookups",
            get(list_lookup_tables).post(create_lookup_table),
        )
        .route(
            "/api/v1/lookups/:name",
            get(get_lookup_table)
                .put(replace_lookup_table)
                .delete(delete_lookup_table),
        )
        .route(
            "/api/v1/lookups/:name/entries",
            post(add_lookup_entries).delete(remove_lookup_entries),
        )
        // Case management
        .route("/api/v1/cases", post(create_case).get(list_cases))
        .route("/api/v1/cases/sla-breaches", get(list_sla_breaches))
        .route(
            "/api/v1/cases/:id",
            get(get_case).patch(update_case).delete(delete_case),
        )
        .route(
            "/api/v1/cases/:id/alerts",
            post(attach_alerts_to_case).delete(detach_alerts_from_case),
        )
        // Natural Language Query + AI helpers
        .route("/api/v1/events/nlq", post(nlq_search))
        .route("/api/v1/rules/generate", post(generate_sigma_rule))
        .route("/api/v1/rules/:id/tune", post(tune_rule_handler))
        .route("/api/v1/explain/alert/:id", post(explain_alert_handler))
        // Live event + alert streams (SSE + WebSocket)
        .route("/api/v1/events/stream", get(event_stream))
        .route("/api/v1/alerts/stream", get(alert_stream))
        .route("/api/v1/alerts/ws-token", get(issue_ws_token))
        .route("/api/v1/alerts/ws", get(alert_ws))
        // Rule version history
        .route("/api/v1/rules/:id/versions", get(list_rule_versions))
        .route(
            "/api/v1/rules/:id/versions/:ver/restore",
            post(restore_rule_version),
        )
        // TAXII / STIX threat intelligence feeds
        .route(
            "/api/v1/threatintel/feeds",
            get(list_ti_feeds).post(create_ti_feed),
        )
        .route(
            "/api/v1/threatintel/feeds/:id",
            get(get_ti_feed).delete(delete_ti_feed),
        )
        .route("/api/v1/threatintel/feeds/:id/sync", post(sync_ti_feed))
        // Multi-tenant RBAC management
        .route("/api/v1/rbac/users", get(list_rbac_assignments))
        .route(
            "/api/v1/rbac/users/:user_id",
            get(get_rbac_user)
                .put(set_rbac_user)
                .delete(delete_rbac_user),
        )
        // Source tracking
        .route("/api/v1/sources", get(list_sources))
        // Agent registry
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/agents/register", post(register_agent))
        .route("/api/v1/agents/:id", patch(patch_agent))
        .route("/api/v1/agents/:id/heartbeat", post(agent_heartbeat))
        .route("/api/v1/agents/:id/config", post(push_agent_config))
        // Dashboard stats
        .route("/api/v1/dashboard/stats", get(dashboard_stats))
}

pub async fn healthz() -> Json<Value> {
    Json(json!({"status": "ok", "time": Utc::now()}))
}

pub async fn metrics(State(state): State<AppState>) -> String {
    state.metrics.render()
}

pub async fn ingest_events(
    auth: AuthContext,
    State(state): State<AppState>,
    SimdJson(payload): SimdJson<EventIngestRequest>,
) -> Result<Json<EventIngestResponse>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Ingestor])?;

    if payload.events.len() > state.max_ingest_events_per_request {
        return Err(CyberboxError::PayloadTooLarge(format!(
            "ingest batch exceeds limit: got {} events, max {}",
            payload.events.len(),
            state.max_ingest_events_per_request
        )));
    }

    // EPS rate limiting — checked before any per-event work
    let event_count = payload.events.len();
    if let Err(retry_after) = state.eps_limiter.try_consume(&auth.tenant_id, event_count) {
        counter!("ingest_eps_throttled_total", "tenant" => auth.tenant_id.clone())
            .increment(event_count as u64);
        tracing::warn!(
            tenant_id = %auth.tenant_id,
            event_count,
            retry_after,
            "ingest throttled: EPS limit exceeded"
        );
        return Err(CyberboxError::TooManyRequests {
            message: format!(
                "EPS limit exceeded for tenant '{}'; retry after {retry_after}s",
                auth.tenant_id
            ),
            retry_after_seconds: retry_after,
        });
    }

    // Write-buffer backpressure: if ClickHouse is ≥ 90 % full, reject with HTTP 429
    // before doing any normalization or storage work.  The sender backs off for 1 s
    // (one full flush interval) so the buffer has time to drain.
    if let Some(write_buffer) = &state.clickhouse_write_buffer {
        if write_buffer.is_overloaded() {
            counter!("ingest_clickhouse_backpressure_total", "tenant" => auth.tenant_id.clone())
                .increment(1);
            tracing::warn!(
                tenant_id = %auth.tenant_id,
                "ingest rejected: ClickHouse write buffer overloaded"
            );
            return Err(CyberboxError::TooManyRequests {
                message: format!(
                    "ClickHouse write buffer overloaded for tenant '{}'; retry after 1s",
                    auth.tenant_id
                ),
                retry_after_seconds: 1,
            });
        }
    }

    let start = Instant::now();
    let mut rejected = 0usize;
    let mut rejected_reasons = Vec::new();

    // Partition: reject tenant mismatches, keep the rest.
    let mut raw_valid = Vec::with_capacity(payload.events.len());
    for incoming in payload.events {
        if incoming.tenant_id != auth.tenant_id {
            rejected += 1;
            rejected_reasons.push("tenant mismatch".to_string());
        } else {
            raw_valid.push(incoming);
        }
    }
    let accepted = raw_valid.len();

    if matches!(
        state.raw_event_publisher,
        crate::stream::RawEventPublisher::Noop
    ) {
        use cyberbox_core::normalize;

        // Load stream rules from the lock-free cache (atomic pointer load, ~1 ns).
        // The cache is refreshed on every rule mutation; no DashMap scan needed here.
        let rules = state.stream_rule_cache.load(&auth.tenant_id);

        // Normalize all events up front with optional GeoIP enrichment, then batch-insert.
        // Deduplicate within the configured window: events whose integrity_hash was
        // already seen are silently dropped before storage and detection.
        let normalized: Vec<EventEnvelope> = raw_valid.iter().filter_map(|e| {
            let env = normalize::normalize_to_ocsf(e);
            let env = if let Some(enricher) = &state.geoip_enricher {
                normalize::attach_enrichment(env, vec![], enricher.enrich_event(&e.raw_payload))
            } else {
                env
            };
            if state.is_duplicate(&env.integrity_hash) {
                counter!("cyberbox_ingest_dedup_dropped_total", "tenant" => auth.tenant_id.clone())
                    .increment(1);
                None
            } else {
                Some(env)
            }
        }).collect();
        let _ = state.storage.insert_events(&normalized).await;

        // Broadcast events to live-tail SSE subscribers (best-effort, never blocks ingest).
        for event in &normalized {
            let _ = state.event_tx.send(event.clone());
        }

        // Persist durably to ClickHouse via the async write buffer (non-blocking ~1 µs).
        // send_events() returns the number of events dropped when the channel is full,
        // which is the backpressure signal that ClickHouse is falling behind ingest rate.
        if let Some(write_buffer) = &state.clickhouse_write_buffer {
            let dropped = write_buffer.send_events(&normalized);
            if dropped > 0 {
                counter!(
                    "clickhouse_write_buffer_dropped_total",
                    "tenant" => auth.tenant_id.clone()
                )
                .increment(dropped as u64);
            }
        }

        // Evaluate rules in parallel (rayon) per event; flush alerts sequentially.
        //
        // P4 field-extraction cache: collect all field names referenced by the
        // active rule set ONCE per request (amortised over the whole batch), then
        // pre-extract each field from every event ONCE before the par_iter so
        // all rules share the pre-computed values.  Keywords matchers also reuse
        // a single lowercased raw_payload string instead of re-serialising per rule.
        let executor = &state.rule_executor;
        let rule_fields = executor.collect_fields_for_rules(rules.as_slice());
        // Pre-build O(1) lookup map once per batch — avoids O(rules) linear scan
        // inside the per-alert threshold/suppression loop.
        let rule_map: std::collections::HashMap<uuid::Uuid, &DetectionRule> =
            rules.as_slice().iter().map(|r| (r.rule_id, r)).collect();
        // Rayon spawn overhead dominates for small rule sets; use sequential eval
        // when ≤ 20 rules so that small-tenant ingest stays on the hot path.
        const RAYON_MIN_RULES: usize = 20;
        for event in &normalized {
            let evidence = format!("event:{}", event.event_id);
            let ctx = cyberbox_detection::build_event_context(event, &rule_fields)
                .with_lookup_store(Arc::clone(&state.lookup_store));
            let alerts: Vec<_> = if rules.len() > RAYON_MIN_RULES {
                rules
                    .as_slice()
                    .par_iter()
                    .filter_map(|rule| {
                        let result = executor.evaluate_with_context(rule, &ctx);
                        if result.matched {
                            executor.maybe_build_alert(rule, ctx.event, evidence.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            } else {
                rules
                    .as_slice()
                    .iter()
                    .filter_map(|rule| {
                        let result = executor.evaluate_with_context(rule, &ctx);
                        if result.matched {
                            executor.maybe_build_alert(rule, ctx.event, evidence.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            };
            for alert in alerts {
                // Threshold gate: if the rule requires N matches before firing,
                // increment the per-(rule,entity) counter and skip until threshold met.
                let rule = rule_map.get(&alert.rule_id).copied();
                let entity = rule
                    .and_then(|r| r.threshold_group_by.as_deref())
                    .map(|f| f.to_string())
                    .unwrap_or_else(|| "__global__".to_string());
                let passes_threshold = if let Some(rule) = rule {
                    let min = rule.threshold_count.unwrap_or(1).max(1);
                    if min <= 1 {
                        true
                    } else {
                        let counter_key = format!("{}:{}", alert.rule_id, entity);
                        let mut entry = state
                            .threshold_counters
                            .entry(counter_key.clone())
                            .or_insert(0);
                        *entry += 1;
                        if *entry >= min {
                            // Threshold met — fire and reset counter.
                            *entry = 0;
                            true
                        } else {
                            false
                        }
                    }
                } else {
                    true
                };
                // Suppression window: skip alert if the rule is still cooling down.
                let suppressed = if let Some(rule) = rule {
                    rule.suppression_window_secs
                        .filter(|&s| s > 0)
                        .is_some_and(|secs| {
                            let suppress_key = format!("{}:{}", alert.rule_id, entity);
                            let now = std::time::Instant::now();
                            let active = state
                                .suppression_map
                                .get(&suppress_key)
                                .map(|exp| now < *exp)
                                .unwrap_or(false);
                            if !active {
                                // Record the firing time so subsequent matches are suppressed.
                                state.suppression_map.insert(
                                    suppress_key,
                                    now + std::time::Duration::from_secs(secs),
                                );
                            }
                            active
                        })
                } else {
                    false
                };
                if passes_threshold && !suppressed {
                    // ── Agent enrichment ──────────────────────────────────────
                    // Attach agent metadata when the event hostname matches a
                    // registered agent in the same tenant.
                    let mut alert = alert;
                    {
                        let event_hostname = event
                            .raw_payload
                            .get("hostname")
                            .or_else(|| event.raw_payload.get("Computer"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if !event_hostname.is_empty() {
                            let tenant = &alert.tenant_id;
                            if let Some(agent) = state.agents.iter().find(|e| {
                                e.value().tenant_id == *tenant
                                    && e.value().hostname == event_hostname
                            }) {
                                let a = agent.value();
                                alert.agent_meta = Some(json!({
                                    "agent_id": a.agent_id,
                                    "hostname": a.hostname,
                                    "os":       a.os,
                                    "version":  a.version,
                                    "group":    a.group,
                                    "tags":     a.tags,
                                }));
                            }
                        }
                    }
                    if let Ok(saved) = state.storage.suppress_or_create_alert(alert).await {
                        counter!("cyberbox_alerts_fired_total", "tenant" => saved.tenant_id.clone())
                            .increment(1);
                        // Auto-correlate: group into an existing or new case (background).
                        let corr_state = state.clone();
                        let corr_alert = saved.clone();
                        tokio::spawn(async move {
                            auto_correlate_alert(corr_state, corr_alert).await;
                        });
                        let _ = state.alert_tx.send(saved);
                    }
                }
            }
        }
    } else {
        for incoming in &raw_valid {
            state
                .raw_event_publisher
                .publish_raw_event(incoming)
                .await?;
        }
    }

    // Update per-source statistics (one DashMap entry per source_type seen in this batch)
    for incoming in &raw_valid {
        let source_type = format!("{:?}", incoming.source).to_lowercase();
        record_source(&state, &auth.tenant_id, &source_type);
    }

    counter!("events_ingested_total", "tenant" => auth.tenant_id.clone())
        .increment(accepted as u64);
    histogram!("api_request_duration_seconds", "route" => "ingest_events")
        .record(start.elapsed().as_secs_f64());

    tracing::info!(
        user_id = %auth.user_id,
        tenant_id = %auth.tenant_id,
        accepted,
        rejected,
        "events ingested"
    );

    Ok(Json(EventIngestResponse {
        accepted,
        rejected,
        rejected_reasons,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub rule_id: Option<Uuid>,
    pub sigma_source: String,
    pub schedule_or_stream: DetectionMode,
    pub schedule: Option<RuleScheduleConfig>,
    pub severity: Severity,
    pub enabled: bool,
    #[serde(default)]
    pub threshold_count: Option<u32>,
    #[serde(default)]
    pub threshold_group_by: Option<String>,
    #[serde(default)]
    pub suppression_window_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    pub sigma_source: Option<String>,
    pub schedule_or_stream: Option<DetectionMode>,
    pub schedule: Option<RuleScheduleConfig>,
    pub severity: Option<Severity>,
    pub enabled: Option<bool>,
    #[serde(default)]
    pub threshold_count: Option<u32>,
    #[serde(default)]
    pub threshold_group_by: Option<String>,
    #[serde(default)]
    pub suppression_window_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ListAuditLogsQuery {
    pub action: Option<String>,
    pub entity_type: Option<String>,
    pub actor: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

const DEFAULT_SCHEDULE_INTERVAL_SECONDS: u32 = 30;
const DEFAULT_SCHEDULE_LOOKBACK_SECONDS: u32 = 300;
const MIN_SCHEDULE_INTERVAL_SECONDS: u32 = 5;
const MAX_SCHEDULE_INTERVAL_SECONDS: u32 = 3600;
const MIN_SCHEDULE_LOOKBACK_SECONDS: u32 = 30;
const MAX_SCHEDULE_LOOKBACK_SECONDS: u32 = 86400;

fn normalize_rule_schedule(
    mode: &DetectionMode,
    schedule: Option<RuleScheduleConfig>,
) -> Result<Option<RuleScheduleConfig>, CyberboxError> {
    if *mode == DetectionMode::Stream {
        return Ok(None);
    }

    let schedule = schedule.unwrap_or(RuleScheduleConfig {
        interval_seconds: DEFAULT_SCHEDULE_INTERVAL_SECONDS,
        lookback_seconds: DEFAULT_SCHEDULE_LOOKBACK_SECONDS,
    });

    if schedule.interval_seconds < MIN_SCHEDULE_INTERVAL_SECONDS
        || schedule.interval_seconds > MAX_SCHEDULE_INTERVAL_SECONDS
    {
        return Err(CyberboxError::BadRequest(format!(
            "scheduled rule interval_seconds must be between {} and {}",
            MIN_SCHEDULE_INTERVAL_SECONDS, MAX_SCHEDULE_INTERVAL_SECONDS
        )));
    }

    if schedule.lookback_seconds < MIN_SCHEDULE_LOOKBACK_SECONDS
        || schedule.lookback_seconds > MAX_SCHEDULE_LOOKBACK_SECONDS
    {
        return Err(CyberboxError::BadRequest(format!(
            "scheduled rule lookback_seconds must be between {} and {}",
            MIN_SCHEDULE_LOOKBACK_SECONDS, MAX_SCHEDULE_LOOKBACK_SECONDS
        )));
    }

    if schedule.lookback_seconds < schedule.interval_seconds {
        return Err(CyberboxError::BadRequest(
            "scheduled rule lookback_seconds must be >= interval_seconds".to_string(),
        ));
    }

    Ok(Some(schedule))
}

fn audit_json<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

#[allow(clippy::too_many_arguments)]
async fn append_audit_log(
    state: &AppState,
    tenant_id: &str,
    actor: &str,
    action: &str,
    entity_type: &str,
    entity_id: &str,
    before: Value,
    after: Value,
) {
    let audit = AuditLogRecord {
        audit_id: Uuid::new_v4(),
        tenant_id: tenant_id.to_string(),
        actor: actor.to_string(),
        action: action.to_string(),
        entity_type: entity_type.to_string(),
        entity_id: entity_id.to_string(),
        timestamp: Utc::now(),
        before,
        after,
    };

    if let Some(clickhouse_store) = &state.clickhouse_event_store {
        if let Err(err) = clickhouse_store.append_audit_log(&audit).await {
            tracing::warn!(
                tenant_id = %tenant_id,
                action,
                entity_type,
                entity_id,
                error = %err,
                "failed to write clickhouse audit log"
            );
        }
    }
    if let Err(err) = state.storage.append_audit_log(audit).await {
        tracing::warn!(
            tenant_id = %tenant_id,
            action,
            entity_type,
            entity_id,
            error = %err,
            "failed to write in-memory audit log"
        );
    }
}

async fn find_alert_snapshot(
    state: &AppState,
    tenant_id: &str,
    alert_id: Uuid,
) -> Result<Option<AlertRecord>, CyberboxError> {
    if let Some(clickhouse_store) = &state.clickhouse_event_store {
        let alerts = clickhouse_store.list_alerts(tenant_id).await?;
        return Ok(alerts.into_iter().find(|alert| alert.alert_id == alert_id));
    }

    let alerts = state.storage.list_alerts(tenant_id).await?;
    Ok(alerts.into_iter().find(|alert| alert.alert_id == alert_id))
}

pub async fn create_rule(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(payload): Json<CreateRuleRequest>,
) -> Result<Json<DetectionRule>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;

    let compiled_plan = state.sigma_compiler.compile(&payload.sigma_source)?;
    let schedule = normalize_rule_schedule(&payload.schedule_or_stream, payload.schedule)?;

    let rule = DetectionRule {
        rule_id: payload.rule_id.unwrap_or_else(Uuid::new_v4),
        tenant_id: auth.tenant_id.clone(),
        sigma_source: payload.sigma_source,
        compiled_plan,
        schedule_or_stream: payload.schedule_or_stream,
        schedule,
        severity: payload.severity,
        enabled: payload.enabled,
        scheduler_health: None,
        threshold_count: payload.threshold_count,
        threshold_group_by: payload.threshold_group_by,
        suppression_window_secs: payload.suppression_window_secs,
    };

    let saved = if let Some(clickhouse_store) = &state.clickhouse_event_store {
        clickhouse_store.upsert_rule(rule).await?
    } else {
        state.storage.upsert_rule(rule).await?
    };

    // Refresh the lock-free stream-rule cache so ingest immediately sees the new rule.
    let fresh = state
        .storage
        .list_rules(&auth.tenant_id)
        .await
        .unwrap_or_default();
    state.stream_rule_cache.refresh(&auth.tenant_id, fresh);

    tracing::info!(
        user_id = %auth.user_id,
        tenant_id = %auth.tenant_id,
        rule_id = %saved.rule_id,
        "rule upserted"
    );
    append_audit_log(
        &state,
        &auth.tenant_id,
        &auth.user_id,
        "rule.create",
        "rule",
        &saved.rule_id.to_string(),
        Value::Null,
        audit_json(&saved),
    )
    .await;

    Ok(Json(saved))
}

pub async fn update_rule(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(rule_id): Path<Uuid>,
    Json(payload): Json<UpdateRuleRequest>,
) -> Result<Json<DetectionRule>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;

    let existing = if let Some(clickhouse_store) = &state.clickhouse_event_store {
        clickhouse_store.get_rule(&auth.tenant_id, rule_id).await?
    } else {
        state.storage.get_rule(&auth.tenant_id, rule_id).await?
    };

    let sigma_source = payload
        .sigma_source
        .unwrap_or_else(|| existing.sigma_source.clone());
    let compiled_plan = if sigma_source == existing.sigma_source {
        existing.compiled_plan.clone()
    } else {
        state.sigma_compiler.compile(&sigma_source)?
    };
    let schedule_or_stream = payload
        .schedule_or_stream
        .unwrap_or_else(|| existing.schedule_or_stream.clone());
    let requested_schedule = payload.schedule.or_else(|| existing.schedule.clone());
    let schedule = normalize_rule_schedule(&schedule_or_stream, requested_schedule)?;

    let updated = DetectionRule {
        rule_id: existing.rule_id,
        tenant_id: existing.tenant_id.clone(),
        sigma_source,
        compiled_plan,
        schedule_or_stream,
        schedule,
        severity: payload.severity.unwrap_or(existing.severity.clone()),
        enabled: payload.enabled.unwrap_or(existing.enabled),
        scheduler_health: existing.scheduler_health.clone(),
        threshold_count: payload.threshold_count.or(existing.threshold_count),
        threshold_group_by: payload
            .threshold_group_by
            .or_else(|| existing.threshold_group_by.clone()),
        suppression_window_secs: payload
            .suppression_window_secs
            .or(existing.suppression_window_secs),
    };

    let saved = if let Some(clickhouse_store) = &state.clickhouse_event_store {
        clickhouse_store.upsert_rule(updated).await?
    } else {
        state.storage.upsert_rule(updated).await?
    };

    let fresh = state
        .storage
        .list_rules(&auth.tenant_id)
        .await
        .unwrap_or_default();
    state.stream_rule_cache.refresh(&auth.tenant_id, fresh);
    state.rule_executor.invalidate_rule(saved.rule_id);

    tracing::info!(
        user_id = %auth.user_id,
        tenant_id = %auth.tenant_id,
        rule_id = %saved.rule_id,
        "rule updated"
    );
    append_audit_log(
        &state,
        &auth.tenant_id,
        &auth.user_id,
        "rule.update",
        "rule",
        &saved.rule_id.to_string(),
        audit_json(&existing),
        audit_json(&saved),
    )
    .await;

    Ok(Json(saved))
}

pub async fn delete_rule(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(rule_id): Path<Uuid>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    let existing = if let Some(clickhouse_store) = &state.clickhouse_event_store {
        clickhouse_store.get_rule(&auth.tenant_id, rule_id).await?
    } else {
        state.storage.get_rule(&auth.tenant_id, rule_id).await?
    };

    if let Some(clickhouse_store) = &state.clickhouse_event_store {
        clickhouse_store
            .delete_rule(&auth.tenant_id, rule_id)
            .await?;
    } else {
        state.storage.delete_rule(&auth.tenant_id, rule_id).await?;
    }

    let fresh = state
        .storage
        .list_rules(&auth.tenant_id)
        .await
        .unwrap_or_default();
    state.stream_rule_cache.refresh(&auth.tenant_id, fresh);
    state.rule_executor.invalidate_rule(rule_id);

    tracing::info!(
        user_id = %auth.user_id,
        tenant_id = %auth.tenant_id,
        rule_id = %rule_id,
        "rule deleted"
    );
    append_audit_log(
        &state,
        &auth.tenant_id,
        &auth.user_id,
        "rule.delete",
        "rule",
        &rule_id.to_string(),
        audit_json(&existing),
        Value::Null,
    )
    .await;

    Ok(Json(json!({"deleted": true, "rule_id": rule_id})))
}

pub async fn list_rules(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<DetectionRule>>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst, Role::Viewer])?;
    let rules = if let Some(clickhouse_store) = &state.clickhouse_event_store {
        clickhouse_store.list_rules(&auth.tenant_id).await?
    } else {
        state.storage.list_rules(&auth.tenant_id).await?
    };
    Ok(Json(rules))
}

pub async fn list_audit_logs(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(query): Query<ListAuditLogsQuery>,
) -> Result<Json<AuditLogsResponse>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst, Role::Viewer])?;
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let fetch_limit = limit + 1;
    let cursor = query
        .cursor
        .as_deref()
        .map(parse_audit_cursor)
        .transpose()?;
    let logs = if let Some(clickhouse_store) = &state.clickhouse_event_store {
        clickhouse_store
            .list_audit_logs(
                &auth.tenant_id,
                query.action.as_deref(),
                query.entity_type.as_deref(),
                query.actor.as_deref(),
                query.from,
                query.to,
                cursor,
                fetch_limit as u64,
            )
            .await?
    } else {
        state
            .storage
            .list_audit_logs(
                &auth.tenant_id,
                query.action.as_deref(),
                query.entity_type.as_deref(),
                query.actor.as_deref(),
                query.from,
                query.to,
                cursor,
                fetch_limit,
            )
            .await?
    };
    let mut entries = logs;
    let has_more = entries.len() > limit;
    if has_more {
        entries.truncate(limit);
    }
    let next_cursor = entries
        .last()
        .map(|entry| format_audit_cursor(entry.timestamp, entry.audit_id))
        .filter(|_| has_more);

    Ok(Json(AuditLogsResponse {
        entries,
        next_cursor,
        has_more,
    }))
}

fn parse_audit_cursor(cursor: &str) -> Result<(DateTime<Utc>, Uuid), CyberboxError> {
    let (timestamp_ms_raw, audit_id_raw) = cursor.split_once('|').ok_or_else(|| {
        CyberboxError::BadRequest("cursor must be '<timestamp_ms>|<audit_id>'".to_string())
    })?;
    let timestamp_ms = timestamp_ms_raw.parse::<i64>().map_err(|_| {
        CyberboxError::BadRequest("cursor timestamp must be epoch milliseconds".to_string())
    })?;
    let timestamp = DateTime::<Utc>::from_timestamp_millis(timestamp_ms)
        .ok_or_else(|| CyberboxError::BadRequest("cursor timestamp is out of range".to_string()))?;
    let audit_id = Uuid::parse_str(audit_id_raw)
        .map_err(|_| CyberboxError::BadRequest("cursor audit_id must be a UUID".to_string()))?;
    Ok((timestamp, audit_id))
}

fn format_audit_cursor(timestamp: DateTime<Utc>, audit_id: Uuid) -> String {
    format!("{}|{}", timestamp.timestamp_millis(), audit_id)
}

pub async fn test_rule(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(rule_id): Path<Uuid>,
    Json(payload): Json<RuleTestRequest>,
) -> Result<Json<RuleTestResult>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;

    let rule = if let Some(clickhouse_store) = &state.clickhouse_event_store {
        clickhouse_store.get_rule(&auth.tenant_id, rule_id).await?
    } else {
        state.storage.get_rule(&auth.tenant_id, rule_id).await?
    };

    let synthetic_event = cyberbox_models::EventEnvelope {
        event_id: Uuid::new_v4(),
        tenant_id: auth.tenant_id,
        source: cyberbox_models::EventSource::AgentForwarded,
        event_time: Utc::now(),
        ingest_time: Utc::now(),
        raw_payload: payload.sample_event,
        ocsf_record: json!({}),
        enrichment: cyberbox_models::EnrichmentMetadata::default(),
        integrity_hash: "synthetic-test".to_string(),
    };

    Ok(Json(state.rule_executor.evaluate(&rule, &synthetic_event)))
}

pub async fn search_query(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(mut payload): Json<SearchQueryRequest>,
) -> Result<Json<cyberbox_models::SearchQueryResponse>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst, Role::Viewer])?;

    if payload.tenant_id != auth.tenant_id {
        payload.tenant_id = auth.tenant_id;
    }

    if let Some(clickhouse_store) = &state.clickhouse_event_store {
        return Ok(Json(clickhouse_store.search(&payload).await?));
    }

    Ok(Json(state.storage.search(&payload).await?))
}

pub async fn list_alerts(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(q): Query<ListAlertsQuery>,
) -> Result<Json<AlertsPage>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst, Role::Viewer])?;

    let mut alerts: Vec<AlertRecord> = if let Some(clickhouse_store) = &state.clickhouse_event_store
    {
        clickhouse_store.list_alerts(&auth.tenant_id).await?
    } else {
        state.storage.list_alerts(&auth.tenant_id).await?
    };

    // Filter by status / severity query params.
    if let Some(status) = &q.status {
        let s = status.to_ascii_lowercase();
        alerts.retain(|a| format!("{:?}", a.status).to_ascii_lowercase() == s);
    }
    if let Some(severity) = &q.severity {
        let s = severity.to_ascii_lowercase();
        alerts.retain(|a| format!("{:?}", a.status).to_ascii_lowercase() == s);
    }

    // Sort deterministically: newest last_seen first, then by alert_id for stability.
    alerts.sort_unstable_by(|a, b| {
        b.last_seen
            .cmp(&a.last_seen)
            .then(b.alert_id.cmp(&a.alert_id))
    });

    let total = alerts.len();
    let limit = q.limit.unwrap_or(100).clamp(1, 500) as usize;

    // Decode cursor → (last_seen, alert_id) to find the start position.
    let start = if let Some(cursor_b64) = &q.after {
        decode_alert_cursor(cursor_b64)
            .and_then(|(ts, id)| {
                alerts
                    .iter()
                    .position(|a| a.last_seen < ts || (a.last_seen == ts && a.alert_id < id))
            })
            .unwrap_or(0)
    } else {
        0
    };

    let page: Vec<AlertRecord> = alerts.iter().skip(start).take(limit + 1).cloned().collect();
    let has_more = page.len() > limit;
    let page: Vec<AlertRecord> = page.into_iter().take(limit).collect();

    let next_cursor = if has_more {
        page.last()
            .map(|a| encode_alert_cursor(a.last_seen, a.alert_id))
    } else {
        None
    };

    Ok(Json(AlertsPage {
        alerts: page,
        next_cursor,
        has_more,
        total,
    }))
}

/// Encode `(last_seen, alert_id)` as a cursor string: `{ts_micros_hex}.{uuid}`.
fn encode_alert_cursor(last_seen: DateTime<Utc>, alert_id: Uuid) -> String {
    format!("{:016x}.{}", last_seen.timestamp_micros(), alert_id)
}

/// Decode a cursor string back to `(DateTime<Utc>, Uuid)`.
fn decode_alert_cursor(cursor: &str) -> Option<(DateTime<Utc>, Uuid)> {
    let (ts_hex, id_str) = cursor.split_once('.')?;
    let micros = i64::from_str_radix(ts_hex, 16).ok()?;
    let ts = DateTime::from_timestamp_micros(micros)?;
    let id = Uuid::parse_str(id_str).ok()?;
    Some((ts, id))
}

pub async fn alert_operation(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(operation): Path<String>,
    Json(payload): Json<Value>,
) -> Result<Json<cyberbox_models::AlertRecord>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;

    let (alert_id_str, action) = operation
        .split_once(':')
        .ok_or_else(|| CyberboxError::BadRequest("expected /alerts/{id}:action".to_string()))?;
    let alert_id = Uuid::parse_str(alert_id_str)
        .map_err(|_| CyberboxError::BadRequest("invalid alert id".to_string()))?;

    match action {
        "ack" => {
            let request = serde_json::from_value::<AckAlertRequest>(payload).map_err(|err| {
                CyberboxError::BadRequest(format!(
                    "ack endpoint expects AckAlertRequest body: {err}"
                ))
            })?;
            if request.actor != auth.user_id {
                return Err(CyberboxError::Forbidden);
            }
            let before = find_alert_snapshot(&state, &auth.tenant_id, alert_id).await?;
            let updated = if let Some(clickhouse_store) = &state.clickhouse_event_store {
                let alert = clickhouse_store
                    .acknowledge(&auth.tenant_id, alert_id, &request.actor)
                    .await?;
                let _ = state.storage.upsert_alert(alert.clone()).await;
                alert
            } else {
                state
                    .storage
                    .acknowledge(&auth.tenant_id, alert_id, &request.actor)
                    .await?
            };

            append_audit_log(
                &state,
                &auth.tenant_id,
                &request.actor,
                "alert.ack",
                "alert",
                &alert_id.to_string(),
                before
                    .map(|record| audit_json(&record))
                    .unwrap_or(Value::Null),
                audit_json(&updated),
            )
            .await;

            Ok(Json(updated))
        }
        "assign" => {
            let request = serde_json::from_value::<AssignAlertRequest>(payload).map_err(|err| {
                CyberboxError::BadRequest(format!(
                    "assign endpoint expects AssignAlertRequest body: {err}"
                ))
            })?;
            if request.actor != auth.user_id {
                return Err(CyberboxError::Forbidden);
            }
            let before = find_alert_snapshot(&state, &auth.tenant_id, alert_id).await?;
            let updated = if let Some(clickhouse_store) = &state.clickhouse_event_store {
                let alert = clickhouse_store
                    .assign(&auth.tenant_id, alert_id, &request)
                    .await?;
                let _ = state.storage.upsert_alert(alert.clone()).await;
                alert
            } else {
                state
                    .storage
                    .assign(&auth.tenant_id, alert_id, &request)
                    .await?
            };

            append_audit_log(
                &state,
                &auth.tenant_id,
                &request.actor,
                "alert.assign",
                "alert",
                &alert_id.to_string(),
                before
                    .map(|record| audit_json(&record))
                    .unwrap_or(Value::Null),
                audit_json(&updated),
            )
            .await;

            Ok(Json(updated))
        }
        "close" => {
            let request = serde_json::from_value::<CloseAlertRequest>(payload).map_err(|err| {
                CyberboxError::BadRequest(format!(
                    "close endpoint expects CloseAlertRequest body: {err}"
                ))
            })?;
            if request.actor != auth.user_id {
                return Err(CyberboxError::Forbidden);
            }
            let before = find_alert_snapshot(&state, &auth.tenant_id, alert_id).await?;
            let updated = if let Some(clickhouse_store) = &state.clickhouse_event_store {
                let alert = clickhouse_store
                    .close(&auth.tenant_id, alert_id, &request)
                    .await?;
                let _ = state.storage.upsert_alert(alert.clone()).await;
                alert
            } else {
                state
                    .storage
                    .close(&auth.tenant_id, alert_id, &request)
                    .await?
            };

            append_audit_log(
                &state,
                &auth.tenant_id,
                &request.actor,
                "alert.close",
                "alert",
                &alert_id.to_string(),
                before
                    .map(|record| audit_json(&record))
                    .unwrap_or(Value::Null),
                audit_json(&updated),
            )
            .await;

            Ok(Json(updated))
        }
        _ => Err(CyberboxError::NotFound),
    }
}

// ─── Detection Engineering Endpoints ─────────────────────────────────────────

/// `POST /api/v1/rules/dry-run`
///
/// Compiles a Sigma rule and evaluates it against a sample event in one shot,
/// without persisting either the rule or any alert.  Useful during rule authoring.
pub async fn dry_run_rule(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(payload): Json<DryRunRequest>,
) -> Result<Json<DryRunResponse>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;

    let compiled_plan = match state.sigma_compiler.compile(&payload.sigma_source) {
        Ok(plan) => plan,
        Err(err) => {
            return Ok(Json(DryRunResponse {
                compile_result: format!("error: {err}"),
                matched: false,
                reasoning: String::new(),
            }));
        }
    };

    let rule = DetectionRule {
        rule_id: uuid::Uuid::new_v4(),
        tenant_id: auth.tenant_id.clone(),
        sigma_source: payload.sigma_source,
        compiled_plan,
        schedule_or_stream: DetectionMode::Stream,
        schedule: None,
        severity: payload.severity,
        enabled: true,
        scheduler_health: None,
        threshold_count: None,
        threshold_group_by: None,
        suppression_window_secs: None,
    };

    let synthetic_event = cyberbox_models::EventEnvelope {
        event_id: uuid::Uuid::new_v4(),
        tenant_id: auth.tenant_id,
        source: cyberbox_models::EventSource::AgentForwarded,
        event_time: Utc::now(),
        ingest_time: Utc::now(),
        raw_payload: payload.sample_event,
        ocsf_record: json!({}),
        enrichment: cyberbox_models::EnrichmentMetadata::default(),
        integrity_hash: "dry-run".to_string(),
    };

    let result = state.rule_executor.evaluate(&rule, &synthetic_event);
    Ok(Json(DryRunResponse {
        compile_result: "ok".to_string(),
        matched: result.matched,
        reasoning: result.reasoning,
    }))
}

const BACKTEST_DEFAULT_MAX: u64 = 10_000;
const BACKTEST_HARD_MAX: u64 = 100_000;
const BACKTEST_PAGE_SIZE: u32 = 500;
const BACKTEST_SAMPLE_LIMIT: usize = 10;

/// `POST /api/v1/rules/:id/backtest`
///
/// Runs an existing rule against stored events in a given time range and returns
/// match statistics — without creating any alerts.  Uses a fresh, isolated
/// `RuleExecutor` so agg/temporal buffers don't bleed into the live engine.
pub async fn backtest_rule(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(rule_id): Path<Uuid>,
    Json(payload): Json<BacktestRequest>,
) -> Result<Json<BacktestResponse>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;

    if payload.from >= payload.to {
        return Err(CyberboxError::BadRequest(
            "'from' must be before 'to'".to_string(),
        ));
    }

    let max_events = payload
        .max_events
        .unwrap_or(BACKTEST_DEFAULT_MAX)
        .min(BACKTEST_HARD_MAX);

    let rule = if let Some(clickhouse_store) = &state.clickhouse_event_store {
        clickhouse_store.get_rule(&auth.tenant_id, rule_id).await?
    } else {
        state.storage.get_rule(&auth.tenant_id, rule_id).await?
    };

    // Isolated executor — keeps backtest buffers separate from live detection.
    let backtest_executor = cyberbox_detection::RuleExecutor::default();

    let mut total_scanned: u64 = 0;
    let mut matched_count: u64 = 0;
    let mut sample_event_ids: Vec<String> = Vec::new();
    let mut page: u32 = 1;

    'pages: loop {
        if total_scanned >= max_events {
            break;
        }

        let query = SearchQueryRequest {
            tenant_id: auth.tenant_id.clone(),
            sql: String::new(),
            time_range: TimeRange {
                start: payload.from,
                end: payload.to,
            },
            filters: vec![],
            pagination: Pagination {
                page,
                page_size: BACKTEST_PAGE_SIZE,
            },
            extra_where: None,
        };

        let result = if let Some(clickhouse_store) = &state.clickhouse_event_store {
            clickhouse_store.search(&query).await?
        } else {
            state.storage.search(&query).await?
        };

        let page_len = result.rows.len();
        if page_len == 0 {
            break;
        }

        for row in &result.rows {
            if total_scanned >= max_events {
                break 'pages;
            }
            total_scanned += 1;

            // Reconstruct a minimal EventEnvelope from the search result row.
            let raw = row
                .get("raw_payload")
                .cloned()
                .unwrap_or_else(|| row.clone());
            let ocsf = row.get("ocsf_record").cloned().unwrap_or(json!({}));
            let event = cyberbox_models::EventEnvelope {
                event_id: row
                    .get("event_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .unwrap_or_else(Uuid::new_v4),
                tenant_id: auth.tenant_id.clone(),
                source: row
                    .get("source")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or(cyberbox_models::EventSource::Unknown),
                event_time: row
                    .get("event_time")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_else(Utc::now),
                ingest_time: Utc::now(),
                raw_payload: raw,
                ocsf_record: ocsf,
                enrichment: cyberbox_models::EnrichmentMetadata::default(),
                integrity_hash: String::new(),
            };

            let eval = backtest_executor.evaluate(&rule, &event);
            if eval.matched {
                matched_count += 1;
                if sample_event_ids.len() < BACKTEST_SAMPLE_LIMIT {
                    sample_event_ids.push(event.event_id.to_string());
                }
            }
        }

        if page_len < BACKTEST_PAGE_SIZE as usize {
            break; // last page
        }
        page += 1;
    }

    let match_rate_pct = if total_scanned > 0 {
        (matched_count as f64 / total_scanned as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(BacktestResponse {
        rule_id,
        from: payload.from,
        to: payload.to,
        total_events_scanned: total_scanned,
        matched_count,
        match_rate_pct,
        sample_event_ids,
    }))
}

/// `GET /api/v1/coverage`
///
/// Returns a MITRE ATT&CK coverage report for the tenant: which techniques are
/// covered by at least one enabled rule, and the overall coverage percentage
/// against CyberboxSIEM's static technique table.
pub async fn mitre_coverage(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<CoverageReport>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst, Role::Viewer])?;

    let rules = if let Some(clickhouse_store) = &state.clickhouse_event_store {
        clickhouse_store.list_rules(&auth.tenant_id).await?
    } else {
        state.storage.list_rules(&auth.tenant_id).await?
    };

    type TechniqueEntry = (Option<String>, Option<String>, Vec<Uuid>);
    let mut technique_map: std::collections::HashMap<String, TechniqueEntry> =
        std::collections::HashMap::new();

    for rule in rules.iter().filter(|r| r.enabled) {
        let tags = rule
            .compiled_plan
            .get("tags")
            .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
            .unwrap_or_default();

        for tech in cyberbox_detection::parse_mitre_from_tags(&tags) {
            technique_map
                .entry(tech.technique_id)
                .and_modify(|(_, _, ids)| ids.push(rule.rule_id))
                .or_insert((tech.tactic, tech.technique_name, vec![rule.rule_id]));
        }
    }

    let mut covered_techniques: Vec<CoveredTechnique> = technique_map
        .into_iter()
        .map(
            |(technique_id, (tactic, technique_name, rule_ids))| CoveredTechnique {
                technique_id,
                tactic,
                technique_name,
                rule_count: rule_ids.len(),
                rule_ids,
            },
        )
        .collect();
    covered_techniques.sort_by(|a, b| a.technique_id.cmp(&b.technique_id));

    let total_covered = covered_techniques.len();
    let total_in_framework = cyberbox_detection::mitre_technique_count();
    let coverage_pct = if total_in_framework > 0 {
        (total_covered as f64 / total_in_framework as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(CoverageReport {
        covered_techniques,
        total_covered,
        total_in_framework,
        coverage_pct,
    }))
}

// ─── Scheduler ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(crate) struct SchedulerTickResponse {
    rules_scanned: usize,
    alerts_emitted: usize,
}

/// Trigger one scheduled-detection tick immediately (admin only).
///
/// Useful in tests and for operational on-demand evaluation without waiting
/// for the background timer. Only meaningful in noop/in-memory mode; in
/// production the worker runs scheduled detection against ClickHouse.
pub(crate) async fn scheduler_tick(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<SchedulerTickResponse>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;

    let result = crate::scheduler::run_tick(&state).await?;

    Ok(Json(SchedulerTickResponse {
        rules_scanned: result.rules_scanned,
        alerts_emitted: result.alerts_emitted,
    }))
}

#[derive(Serialize)]
pub struct PurgeTenantEventsResponse {
    pub tenant_id: String,
    pub deleted_rows: u64,
}

/// GDPR right-to-erasure: permanently purge all events for the calling tenant.
///
/// Admin-only.  Purges:
///  - ClickHouse hot-tier events table (lightweight DELETE mutation)
///  - In-memory store (synchronous map removal)
///
/// The ClickHouse mutation is eventually consistent: rows become invisible to
/// queries immediately but physical deletion happens asynchronously during
/// MergeTree part merges.
pub async fn purge_tenant_events(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<PurgeTenantEventsResponse>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;

    let mut deleted_rows: u64 = 0;

    // Purge from ClickHouse (hot-tier).
    if let Some(clickhouse_store) = &state.clickhouse_event_store {
        deleted_rows += clickhouse_store
            .delete_tenant_events(&auth.tenant_id)
            .await?;
    }

    // Purge from in-memory store.
    deleted_rows += state.storage.clear_tenant_events(&auth.tenant_id);

    counter!(
        "cyberbox_gdpr_purge_total",
        "tenant" => auth.tenant_id.clone()
    )
    .increment(1);
    counter!(
        "cyberbox_gdpr_purge_rows_total",
        "tenant" => auth.tenant_id.clone()
    )
    .increment(deleted_rows);

    tracing::warn!(
        tenant_id = %auth.tenant_id,
        deleted_rows,
        "GDPR purge completed"
    );

    Ok(Json(PurgeTenantEventsResponse {
        tenant_id: auth.tenant_id.clone(),
        deleted_rows,
    }))
}

// ─── LGPD compliance endpoints ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LgpdExportQuery {
    /// Identifier to search for: username, e-mail, IP address, or any free-text
    /// value that may appear in events belonging to a data subject.
    pub subject_id: String,
}

#[derive(Serialize)]
pub struct LgpdExportResponse {
    pub controller_name: String,
    pub dpo_email: String,
    pub legal_basis: String,
    pub subject_id: String,
    pub tenant_id: String,
    pub generated_at: chrono::DateTime<Utc>,
    /// Events that reference the subject identifier.
    pub events: Vec<serde_json::Value>,
    pub total_events: usize,
}

/// LGPD Art. 18, I — Right of access (Direito de Acesso).
///
/// Returns all events in the tenant store that reference `subject_id` in any
/// of the PII-bearing fields (actor_user, src_ip, dst_ip, or the raw payload).
/// Admin-only; an audit log entry is written for every DSAR.
pub async fn lgpd_export(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(params): Query<LgpdExportQuery>,
) -> Result<Json<LgpdExportResponse>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;

    if params.subject_id.trim().is_empty() {
        return Err(CyberboxError::BadRequest(
            "subject_id must not be empty".to_string(),
        ));
    }

    let needle = params.subject_id.to_ascii_lowercase();

    // Search in-memory store — full-text scan over raw_payload for the subject identifier.
    let epoch = chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap_or(Utc::now());
    let all_events =
        state
            .storage
            .list_events_in_range(&auth.tenant_id, epoch, Utc::now(), usize::MAX);

    let matching: Vec<serde_json::Value> = all_events
        .iter()
        .filter(|e| {
            let payload_str = e.raw_payload.to_string().to_ascii_lowercase();
            payload_str.contains(&needle)
        })
        .map(|e| {
            json!({
                "event_id": e.event_id,
                "event_time": e.event_time,
                "source": format!("{:?}", e.source),
                "raw_payload": e.raw_payload,
            })
        })
        .collect();

    let total = matching.len();

    // Write DSAR audit entry.
    let _ = state
        .storage
        .append_audit_log(AuditLogRecord {
            audit_id: uuid::Uuid::new_v4(),
            tenant_id: auth.tenant_id.clone(),
            actor: auth.user_id.clone(),
            action: "lgpd_dsar_export".to_string(),
            entity_type: "data_subject".to_string(),
            entity_id: params.subject_id.clone(),
            timestamp: Utc::now(),
            before: serde_json::Value::Null,
            after: json!({ "exported_events": total }),
        })
        .await;

    tracing::info!(
        tenant_id = %auth.tenant_id,
        actor = %auth.user_id,
        subject_id = %params.subject_id,
        exported_events = total,
        "LGPD DSAR export completed"
    );

    Ok(Json(LgpdExportResponse {
        controller_name: state.lgpd_controller_name.clone(),
        dpo_email: state.lgpd_dpo_email.clone(),
        legal_basis: state.lgpd_legal_basis.clone(),
        subject_id: params.subject_id.clone(),
        tenant_id: auth.tenant_id.clone(),
        generated_at: Utc::now(),
        events: matching,
        total_events: total,
    }))
}

#[derive(Deserialize)]
pub struct LgpdAnonymizeRequest {
    /// Identifier to anonymize (username, IP, e-mail, etc.).
    pub subject_id: String,
    /// Optional: only anonymize events before this timestamp.
    pub before: Option<chrono::DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct LgpdAnonymizeResponse {
    pub subject_id: String,
    pub tenant_id: String,
    pub anonymized_events: usize,
}

/// LGPD Art. 18, IV — Right to anonymization (Direito à Anonimização).
///
/// Removes the tenant's events that reference `subject_id` from the in-memory
/// store (they are replaced with anonymized copies that retain the security
/// timeline but mask the identifying value).  A ClickHouse lightweight DELETE
/// is also issued for the matched rows.
///
/// Note: full anonymization in ClickHouse requires a mutation that scans and
/// rewrites parts — for simplicity this implementation **deletes** matching rows
/// (the security timeline is preserved in anonymized in-memory copies).
pub async fn lgpd_anonymize(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(payload): Json<LgpdAnonymizeRequest>,
) -> Result<Json<LgpdAnonymizeResponse>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;

    if payload.subject_id.trim().is_empty() {
        return Err(CyberboxError::BadRequest(
            "subject_id must not be empty".to_string(),
        ));
    }

    let needle = payload.subject_id.to_ascii_lowercase();
    let cutoff = payload.before.unwrap_or(Utc::now());

    // Collect matching events from in-memory store.
    let epoch = chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap_or(Utc::now());
    let all_events = state
        .storage
        .list_events_in_range(&auth.tenant_id, epoch, cutoff, usize::MAX);

    let (matching, rest): (Vec<_>, Vec<_>) = all_events.into_iter().partition(|e| {
        let payload_str = e.raw_payload.to_string().to_ascii_lowercase();
        payload_str.contains(&needle)
    });

    let anonymized_count = matching.len();
    if anonymized_count == 0 {
        return Ok(Json(LgpdAnonymizeResponse {
            subject_id: payload.subject_id,
            tenant_id: auth.tenant_id,
            anonymized_events: 0,
        }));
    }

    // Build anonymized replacements: same event skeleton, PII replaced.
    use cyberbox_models::EventEnvelope;
    let anonymized: Vec<EventEnvelope> = matching
        .into_iter()
        .map(|mut e| {
            // Replace every occurrence of the subject identifier in raw_payload
            // with the placeholder so that analysts can still correlate the
            // security timeline without seeing the real identity.
            let masked = e
                .raw_payload
                .to_string()
                .replace(&payload.subject_id, "[ANONYMIZED]");
            e.raw_payload = serde_json::from_str(&masked).unwrap_or(json!({"msg": "[ANONYMIZED]"}));
            e.integrity_hash = "[anonymized]".to_string();
            e
        })
        .collect();

    // Re-insert anonymized events + keep non-matching events (clear + re-insert).
    // Clear the tenant's event store first.
    state.storage.clear_tenant_events(&auth.tenant_id);

    let mut all_to_restore = anonymized;
    all_to_restore.extend(rest);
    if !all_to_restore.is_empty() {
        let _ = state.storage.insert_events(&all_to_restore).await;
    }

    // Write audit entry for the anonymization.
    let _ = state
        .storage
        .append_audit_log(AuditLogRecord {
            audit_id: uuid::Uuid::new_v4(),
            tenant_id: auth.tenant_id.clone(),
            actor: auth.user_id.clone(),
            action: "lgpd_anonymize".to_string(),
            entity_type: "data_subject".to_string(),
            entity_id: payload.subject_id.clone(),
            timestamp: Utc::now(),
            before: serde_json::Value::Null,
            after: json!({ "anonymized_events": anonymized_count }),
        })
        .await;

    tracing::warn!(
        tenant_id = %auth.tenant_id,
        actor = %auth.user_id,
        subject_id = %payload.subject_id,
        anonymized_events = anonymized_count,
        "LGPD anonymization completed"
    );

    Ok(Json(LgpdAnonymizeResponse {
        subject_id: payload.subject_id,
        tenant_id: auth.tenant_id,
        anonymized_events: anonymized_count,
    }))
}

#[derive(Deserialize)]
pub struct LgpdBreachRequest {
    /// Human-readable description of the incident.
    pub description: String,
    /// Categories of personal data affected (e.g. "IP addresses", "usernames").
    pub data_categories: Vec<String>,
    /// Estimated number of data subjects affected.
    pub estimated_subjects_affected: u64,
    /// Whether the incident has already been reported to ANPD.
    pub reported_to_anpd: bool,
}

#[derive(Serialize)]
pub struct LgpdBreachResponse {
    pub incident_id: uuid::Uuid,
    pub tenant_id: String,
    pub reported_at: chrono::DateTime<Utc>,
    pub anpd_notification_deadline: chrono::DateTime<Utc>,
    pub reported_to_anpd: bool,
}

/// LGPD Art. 48 — Breach incident log (Comunicação de Incidente).
///
/// Records a security breach in the audit log with an ANPD notification
/// deadline (72 hours from report time, matching the regulatory expectation).
/// Admin-only.  This does NOT automatically notify ANPD — it creates a
/// traceable audit record and returns the deadline to the caller.
pub async fn lgpd_report_breach(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(payload): Json<LgpdBreachRequest>,
) -> Result<Json<LgpdBreachResponse>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;

    let incident_id = uuid::Uuid::new_v4();
    let reported_at = Utc::now();
    // LGPD Art. 48 does not specify an exact window but ANPD guidance suggests
    // notifying "within a reasonable timeframe" — 72 hours is the widely adopted
    // standard (matching GDPR 72h and ANPD Resolução CD/ANPD nº 2).
    let anpd_deadline = reported_at + chrono::Duration::hours(72);

    let breach_record = json!({
        "incident_id": incident_id.to_string(),
        "description": payload.description,
        "data_categories": payload.data_categories,
        "estimated_subjects_affected": payload.estimated_subjects_affected,
        "reported_to_anpd": payload.reported_to_anpd,
        "anpd_notification_deadline": anpd_deadline,
        "controller_name": state.lgpd_controller_name,
        "dpo_email": state.lgpd_dpo_email,
    });

    let _ = state
        .storage
        .append_audit_log(AuditLogRecord {
            audit_id: uuid::Uuid::new_v4(),
            tenant_id: auth.tenant_id.clone(),
            actor: auth.user_id.clone(),
            action: "lgpd_breach_notification".to_string(),
            entity_type: "incident".to_string(),
            entity_id: incident_id.to_string(),
            timestamp: reported_at,
            before: serde_json::Value::Null,
            after: breach_record,
        })
        .await;

    tracing::error!(
        tenant_id = %auth.tenant_id,
        actor = %auth.user_id,
        incident_id = %incident_id,
        estimated_subjects_affected = payload.estimated_subjects_affected,
        reported_to_anpd = payload.reported_to_anpd,
        anpd_deadline = %anpd_deadline,
        "LGPD breach incident logged — ANPD notification deadline: {}", anpd_deadline
    );

    counter!(
        "cyberbox_lgpd_breach_total",
        "tenant" => auth.tenant_id.clone()
    )
    .increment(1);

    Ok(Json(LgpdBreachResponse {
        incident_id,
        tenant_id: auth.tenant_id,
        reported_at,
        anpd_notification_deadline: anpd_deadline,
        reported_to_anpd: payload.reported_to_anpd,
    }))
}

// ─── Lookup Table Management ──────────────────────────────────────────────────
//
// Lookup tables are named sets of string values (case-insensitive).
// Rules use the `|lookup` Sigma modifier to check field membership.

#[derive(Debug, Deserialize)]
struct LookupCreateRequest {
    name: String,
    /// Initial set of entries (optional — creates an empty table if omitted).
    #[serde(default)]
    entries: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LookupEntriesRequest {
    entries: Vec<String>,
}

/// GET /api/v1/lookups — list all lookup tables with entry counts.
async fn list_lookup_tables(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    let tables = state.lookup_store.list_tables();
    Ok(Json(json!({ "tables": tables })))
}

/// POST /api/v1/lookups — create a new lookup table (or recreate if it exists).
async fn create_lookup_table(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(payload): Json<LookupCreateRequest>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err(CyberboxError::BadRequest(
            "lookup table name cannot be empty".to_string(),
        ));
    }
    let count = payload.entries.len();
    state.lookup_store.set_entries(&name, payload.entries);
    tracing::info!(actor = %auth.user_id, table = %name, entries = count, "lookup table created");
    Ok(Json(json!({ "name": name, "entry_count": count })))
}

/// GET /api/v1/lookups/:name — get all entries in a table.
async fn get_lookup_table(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    match state.lookup_store.get_entries(&name) {
        Some(entries) => Ok(Json(json!({ "name": name, "entries": entries }))),
        None => Err(CyberboxError::NotFound),
    }
}

/// PUT /api/v1/lookups/:name — replace all entries in a table.
async fn replace_lookup_table(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<LookupEntriesRequest>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;
    let count = payload.entries.len();
    state.lookup_store.set_entries(&name, payload.entries);
    tracing::info!(actor = %auth.user_id, table = %name, entries = count, "lookup table replaced");
    Ok(Json(json!({ "name": name, "entry_count": count })))
}

/// DELETE /api/v1/lookups/:name — delete a lookup table entirely.
async fn delete_lookup_table(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;
    if state.lookup_store.delete_table(&name) {
        tracing::info!(actor = %auth.user_id, table = %name, "lookup table deleted");
        Ok(Json(json!({ "deleted": true, "name": name })))
    } else {
        Err(CyberboxError::NotFound)
    }
}

/// POST /api/v1/lookups/:name/entries — add entries to an existing table.
async fn add_lookup_entries(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<LookupEntriesRequest>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;
    let added = payload.entries.len();
    state.lookup_store.add_entries(&name, payload.entries);
    tracing::info!(actor = %auth.user_id, table = %name, added, "lookup entries added");
    let total = state
        .lookup_store
        .get_entries(&name)
        .map(|e| e.len())
        .unwrap_or(0);
    Ok(Json(
        json!({ "name": name, "added": added, "entry_count": total }),
    ))
}

/// DELETE /api/v1/lookups/:name/entries — remove specific entries from a table.
async fn remove_lookup_entries(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<LookupEntriesRequest>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;
    let removed = payload.entries.len();
    state.lookup_store.remove_entries(&name, &payload.entries);
    tracing::info!(actor = %auth.user_id, table = %name, removed, "lookup entries removed");
    let total = state
        .lookup_store
        .get_entries(&name)
        .map(|e| e.len())
        .unwrap_or(0);
    Ok(Json(
        json!({ "name": name, "removed": removed, "entry_count": total }),
    ))
}

// ─── Case Management ──────────────────────────────────────────────────────────

/// POST /api/v1/cases — create a new incident case.
async fn create_case(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(payload): Json<CreateCaseRequest>,
) -> Result<Json<CaseRecord>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    if payload.title.trim().is_empty() {
        return Err(CyberboxError::BadRequest(
            "title cannot be empty".to_string(),
        ));
    }
    let now = Utc::now();
    let case = CaseRecord {
        case_id: Uuid::new_v4(),
        tenant_id: auth.tenant_id.clone(),
        title: payload.title.trim().to_string(),
        description: payload.description,
        status: cyberbox_models::CaseStatus::Open,
        severity: payload.severity.clone(),
        alert_ids: payload.alert_ids,
        assignee: payload.assignee,
        created_by: auth.user_id.clone(),
        created_at: now,
        updated_at: now,
        sla_due_at: Some(sla_due_at(&payload.severity, now)),
        closed_at: None,
        tags: payload.tags,
    };
    let saved = state.storage.upsert_case(case).await?;
    tracing::info!(actor = %auth.user_id, case_id = %saved.case_id, "case created");
    Ok(Json(saved))
}

#[derive(Debug, Deserialize, Default)]
struct ListCasesQuery {
    status: Option<String>,
    severity: Option<String>,
    assignee: Option<String>,
}

/// GET /api/v1/cases — list cases with optional filters.
async fn list_cases(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(q): Query<ListCasesQuery>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    let mut cases = state.storage.list_cases(&auth.tenant_id).await?;
    if let Some(status) = &q.status {
        cases.retain(|c| format!("{:?}", c.status).eq_ignore_ascii_case(status));
    }
    if let Some(sev) = &q.severity {
        cases.retain(|c| format!("{:?}", c.severity).eq_ignore_ascii_case(sev));
    }
    if let Some(assignee) = &q.assignee {
        cases.retain(|c| c.assignee.as_deref() == Some(assignee.as_str()));
    }
    let total = cases.len();
    Ok(Json(json!({ "cases": cases, "total": total })))
}

/// GET /api/v1/cases/sla-breaches — list open cases past their SLA deadline.
async fn list_sla_breaches(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    let breaches = state.storage.list_sla_breaches(&auth.tenant_id).await?;
    counter!("cyberbox_case_sla_breaches_total", "tenant" => auth.tenant_id.clone())
        .absolute(breaches.len() as u64);
    Ok(Json(
        json!({ "breaches": breaches, "total": breaches.len() }),
    ))
}

/// GET /api/v1/cases/:id — get a single case.
async fn get_case(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CaseRecord>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    let case = state.storage.get_case(&auth.tenant_id, id).await?;
    Ok(Json(case))
}

/// PATCH /api/v1/cases/:id — update title, description, status, severity, assignee, tags.
async fn update_case(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(patch): Json<UpdateCaseRequest>,
) -> Result<Json<CaseRecord>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    let now = Utc::now();
    let updated = state
        .storage
        .update_case(&auth.tenant_id, id, &patch, now)
        .await?;
    tracing::info!(actor = %auth.user_id, case_id = %id, "case updated");
    Ok(Json(updated))
}

/// DELETE /api/v1/cases/:id — permanently delete a case.
async fn delete_case(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;
    state.storage.delete_case(&auth.tenant_id, id).await?;
    tracing::info!(actor = %auth.user_id, case_id = %id, "case deleted");
    Ok(Json(json!({ "deleted": true, "case_id": id })))
}

/// POST /api/v1/cases/:id/alerts — attach alert IDs to a case.
async fn attach_alerts_to_case(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CaseAlertIdsRequest>,
) -> Result<Json<CaseRecord>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    let now = Utc::now();
    let mut case = state.storage.get_case(&auth.tenant_id, id).await?;
    for aid in payload.alert_ids {
        if !case.alert_ids.contains(&aid) {
            case.alert_ids.push(aid);
        }
    }
    case.updated_at = now;
    let saved = state.storage.upsert_case(case).await?;
    Ok(Json(saved))
}

/// DELETE /api/v1/cases/:id/alerts — detach alert IDs from a case.
async fn detach_alerts_from_case(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CaseAlertIdsRequest>,
) -> Result<Json<CaseRecord>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    let now = Utc::now();
    let mut case = state.storage.get_case(&auth.tenant_id, id).await?;
    case.alert_ids
        .retain(|aid| !payload.alert_ids.contains(aid));
    case.updated_at = now;
    let saved = state.storage.upsert_case(case).await?;
    Ok(Json(saved))
}

// ─── TAXII / STIX Threat Intelligence Feed Management ────────────────────────

/// GET /api/v1/threatintel/feeds — list all configured feeds.
async fn list_ti_feeds(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    let feeds: Vec<ThreatIntelFeed> = state
        .threat_intel_feeds
        .iter()
        .filter(|e| e.value().enabled || auth.tenant_id == "admin")
        .map(|e| e.value().clone())
        .collect();
    let total = feeds.len();
    Ok(Json(json!({ "feeds": feeds, "total": total })))
}

/// POST /api/v1/threatintel/feeds — add a new feed configuration.
async fn create_ti_feed(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(mut feed): Json<ThreatIntelFeed>,
) -> Result<Json<ThreatIntelFeed>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;
    if feed.taxii_url.trim().is_empty() {
        return Err(CyberboxError::BadRequest(
            "taxii_url cannot be empty".to_string(),
        ));
    }
    if feed.target_table.trim().is_empty() {
        return Err(CyberboxError::BadRequest(
            "target_table cannot be empty".to_string(),
        ));
    }
    feed.feed_id = Uuid::new_v4();
    state.threat_intel_feeds.insert(feed.feed_id, feed.clone());
    persist::save_feeds(&state.threat_intel_feeds, &state.state_dir);
    tracing::info!(actor = %auth.user_id, feed_id = %feed.feed_id, feed_name = %feed.name, "threat intel feed added");
    Ok(Json(feed))
}

/// GET /api/v1/threatintel/feeds/:id — get a single feed config.
async fn get_ti_feed(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ThreatIntelFeed>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    state
        .threat_intel_feeds
        .get(&id)
        .map(|f| Json(f.clone()))
        .ok_or(CyberboxError::NotFound)
}

/// DELETE /api/v1/threatintel/feeds/:id — remove a feed configuration.
async fn delete_ti_feed(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;
    if state.threat_intel_feeds.remove(&id).is_some() {
        persist::save_feeds(&state.threat_intel_feeds, &state.state_dir);
        tracing::info!(actor = %auth.user_id, feed_id = %id, "threat intel feed removed");
        Ok(Json(json!({ "deleted": true, "feed_id": id })))
    } else {
        Err(CyberboxError::NotFound)
    }
}

/// POST /api/v1/threatintel/feeds/:id/sync — manually trigger a feed sync.
///
/// Downloads the TAXII collection, extracts STIX indicators, and merges them
/// into the target lookup table.
async fn sync_ti_feed(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;
    let feed = state
        .threat_intel_feeds
        .get(&id)
        .map(|f| f.clone())
        .ok_or(CyberboxError::NotFound)?;

    let result = feed
        .sync(&state.lookup_store, &state.http_client)
        .await
        .map_err(|e| CyberboxError::Internal(e.to_string()))?;

    tracing::info!(
        actor = %auth.user_id,
        feed_id = %id,
        indicators_added = result.indicators_added,
        "threat intel feed synced"
    );
    counter!(
        "cyberbox_threatintel_indicators_total",
        "feed" => feed.name.clone()
    )
    .increment(result.indicators_added as u64);

    Ok(Json(serde_json::to_value(&result).unwrap_or_else(
        |_| json!({ "feed_id": id, "indicators_added": result.indicators_added }),
    )))
}

// ─── Natural Language Query ───────────────────────────────────────────────────

/// POST /api/v1/events/nlq — translate a plain-English question into a search.
///
/// Requires `nlq_enabled = true` and a valid `CYBERBOX__ANTHROPIC_API_KEY`.
///
/// Request body: `{ "query": "show failed logins from root in the last hour" }`
///
/// Response: search results + the generated WHERE clause for UI transparency.
async fn nlq_search(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(req): Json<NlqRequest>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst, Role::Viewer])?;

    if !state.nlq_enabled {
        return Err(CyberboxError::BadRequest(
            "NLQ is not enabled on this instance (set nlq_enabled = true)".to_string(),
        ));
    }
    let api_key = state.anthropic_api_key.as_deref().ok_or_else(|| {
        CyberboxError::Internal("NLQ enabled but anthropic_api_key not configured".to_string())
    })?;

    if req.query.trim().is_empty() {
        return Err(CyberboxError::BadRequest(
            "query cannot be empty".to_string(),
        ));
    }

    let translation =
        cyberbox_core::nlq::translate(&req, &auth.tenant_id, api_key, &state.http_client)
            .await
            .map_err(|e| CyberboxError::Internal(format!("NLQ translation failed: {e}")))?;

    tracing::info!(
        actor = %auth.user_id,
        tenant = %auth.tenant_id,
        query = %req.query,
        generated_where = %translation.generated_where,
        "NLQ search"
    );

    let result = if let Some(ch) = &state.clickhouse_event_store {
        ch.search(&translation.search).await?
    } else {
        state.storage.search(&translation.search).await?
    };

    Ok(Json(json!({
        "rows":            result.rows,
        "total":           result.total,
        "generated_where": translation.generated_where,
        "interpreted_as":  translation.interpreted_as,
        "time_range": {
            "start": translation.search.time_range.start,
            "end":   translation.search.time_range.end,
        }
    })))
}

// ─── Sigma rule generator ─────────────────────────────────────────────────────

/// POST /api/v1/rules/generate — describe a threat in plain English, get Sigma YAML back.
///
/// Requires `nlq_enabled = true` and a valid `CYBERBOX__ANTHROPIC_API_KEY`.
///
/// Request: `{ "description": "detect PowerShell downloading files from the internet" }`
/// Response: `{ "sigma_yaml": "title: ...\n...", "description": "..." }`
async fn generate_sigma_rule(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(req): Json<GenerateSigmaRequest>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;

    if !state.nlq_enabled {
        return Err(CyberboxError::BadRequest(
            "AI rule generation is not enabled (set nlq_enabled = true)".to_string(),
        ));
    }
    let api_key = state.anthropic_api_key.as_deref().ok_or_else(|| {
        CyberboxError::Internal("nlq_enabled but anthropic_api_key not configured".to_string())
    })?;
    if req.description.trim().is_empty() {
        return Err(CyberboxError::BadRequest(
            "description cannot be empty".to_string(),
        ));
    }

    let result = cyberbox_core::nlq::generate_sigma(&req, api_key, &state.http_client)
        .await
        .map_err(|e| CyberboxError::Internal(format!("Sigma generation failed: {e}")))?;

    tracing::info!(
        actor = %auth.user_id,
        description = %req.description,
        "AI Sigma rule generated"
    );

    Ok(Json(json!({
        "sigma_yaml":   result.sigma_yaml,
        "description":  result.description,
    })))
}

// ─── Alert explanation ────────────────────────────────────────────────────────

/// POST /api/v1/alerts/:id/explain — ask Claude to explain an alert in plain English.
///
/// Requires `nlq_enabled = true` and a valid `CYBERBOX__ANTHROPIC_API_KEY`.
async fn explain_alert_handler(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst, Role::Viewer])?;

    if !state.nlq_enabled {
        return Err(CyberboxError::BadRequest(
            "AI alert explanation is not enabled (set nlq_enabled = true)".to_string(),
        ));
    }
    let api_key = state.anthropic_api_key.as_deref().ok_or_else(|| {
        CyberboxError::Internal("nlq_enabled but anthropic_api_key not configured".to_string())
    })?;

    // Fetch the alert — list then find (no get_alert on trait).
    let alerts = state.storage.list_alerts(&auth.tenant_id).await?;
    let alert = alerts
        .into_iter()
        .find(|a| a.alert_id == id)
        .ok_or(CyberboxError::NotFound)?;

    // Build a compact context string for Claude using available fields.
    let context = serde_json::json!({
        "rule_id":     alert.rule_id,
        "status":      format!("{:?}", alert.status),
        "first_seen":  alert.first_seen,
        "last_seen":   alert.last_seen,
        "hit_count":   alert.hit_count,
        "dedupe_key":  alert.routing_state.dedupe_key,
        "mitre_attack": alert.mitre_attack,
        "evidence_refs": alert.evidence_refs,
    });

    let explanation =
        cyberbox_core::nlq::explain_alert(&context.to_string(), api_key, &state.http_client)
            .await
            .map_err(|e| CyberboxError::Internal(format!("Alert explanation failed: {e}")))?;

    tracing::info!(
        actor = %auth.user_id,
        alert_id = %id,
        "AI alert explanation generated"
    );

    Ok(Json(serde_json::to_value(&explanation).unwrap_or_else(
        |_| json!({ "summary": "explanation unavailable" }),
    )))
}

// ─── RBAC Management ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SetRbacRequest {
    roles: Vec<Role>,
}

/// List all per-tenant RBAC overrides for the authenticated tenant.
async fn list_rbac_assignments(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;

    let prefix = format!("{}:", auth.tenant_id);
    let assignments: Vec<Value> = state
        .rbac_store
        .iter()
        .filter(|entry| entry.key().starts_with(&prefix))
        .map(|entry| {
            let user_id = entry.key().strip_prefix(&prefix).unwrap_or("").to_string();
            json!({ "user_id": user_id, "roles": *entry.value() })
        })
        .collect();

    Ok(Json(
        json!({ "assignments": assignments, "total": assignments.len() }),
    ))
}

/// Get stored role overrides for a specific user within the tenant.
async fn get_rbac_user(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;

    let key = format!("{}:{}", auth.tenant_id, user_id);
    match state.rbac_store.get(&key) {
        Some(roles) => Ok(Json(json!({ "user_id": user_id, "roles": *roles }))),
        None => Ok(Json(json!({ "user_id": user_id, "roles": [] }))),
    }
}

/// Set (replace) the stored role overrides for a user within the tenant.
async fn set_rbac_user(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(body): Json<SetRbacRequest>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;

    let key = format!("{}:{}", auth.tenant_id, user_id);
    state.rbac_store.insert(key, body.roles.clone());
    persist::save_rbac(&state.rbac_store, &state.state_dir);

    tracing::info!(
        actor = %auth.user_id,
        tenant = %auth.tenant_id,
        target_user = %user_id,
        "RBAC roles updated"
    );

    Ok(Json(json!({ "user_id": user_id, "roles": body.roles })))
}

/// Remove stored role overrides for a user (reverts to JWT-only roles).
async fn delete_rbac_user(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;

    let key = format!("{}:{}", auth.tenant_id, user_id);
    state.rbac_store.remove(&key);
    persist::save_rbac(&state.rbac_store, &state.state_dir);

    tracing::info!(
        actor = %auth.user_id,
        tenant = %auth.tenant_id,
        target_user = %user_id,
        "RBAC overrides removed"
    );

    Ok(Json(json!({ "user_id": user_id, "removed": true })))
}

// ─── SSE Event Stream (Live Tail) ─────────────────────────────────────────────

/// GET /api/v1/events/stream — live SSE push of ingested events for the authenticated tenant.
///
/// Each SSE event carries a JSON-serialised `EventEnvelope`.  The stream never ends
/// (clients should reconnect on disconnect).  Lagging consumers silently drop
/// overflowed messages (broadcast channel capacity = 4 096).
async fn event_stream(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_tx.subscribe();
    let tenant_id = auth.tenant_id.clone();

    let stream = BroadcastStream::new(rx).filter_map(move |item| {
        let tenant = tenant_id.clone();
        match item {
            Ok(event) if event.tenant_id == tenant => {
                let data = serde_json::to_string(&event).unwrap_or_default();
                Some(Ok::<Event, Infallible>(Event::default().data(data)))
            }
            _ => None,
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ─── SSE Alert Stream ─────────────────────────────────────────────────────────

/// GET /api/v1/alerts/stream — live SSE push of new alerts for the authenticated tenant.
///
/// Each SSE event carries a JSON-serialised `AlertRecord`.  The stream never ends
/// (clients should reconnect on disconnect).  Lagging consumers silently drop
/// overflowed messages (broadcast channel capacity = 1 024).
async fn alert_stream(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.alert_tx.subscribe();
    let tenant_id = auth.tenant_id.clone();

    let stream = BroadcastStream::new(rx).filter_map(move |item| {
        let tenant = tenant_id.clone();
        match item {
            Ok(alert) if alert.tenant_id == tenant => {
                let data = serde_json::to_string(&alert).unwrap_or_default();
                Some(Ok::<Event, Infallible>(Event::default().data(data)))
            }
            _ => None,
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ─── WebSocket Auth Token ─────────────────────────────────────────────────────

/// GET /api/v1/alerts/ws-token — issue a short-lived (60 s) opaque token for
/// WebSocket auth.  The token is passed as `?token=<value>` on the WS upgrade
/// request so that browsers (which cannot set custom headers on WebSocket) can
/// authenticate without exposing JWTs in the URL.
async fn issue_ws_token(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst, Role::Viewer])?;
    let token = Uuid::new_v4().to_string();
    let expiry = std::time::Instant::now() + std::time::Duration::from_secs(60);
    // Evict stale tokens (lazy, amortised).
    let now = std::time::Instant::now();
    state.ws_tokens.retain(|_, exp| now < *exp);
    state.ws_tokens.insert(token.clone(), expiry);
    Ok(Json(
        json!({ "token": token, "expires_in_seconds": 60, "tenant_id": auth.tenant_id }),
    ))
}

// ─── WebSocket Alert Stream ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct WsTokenQuery {
    token: Option<String>,
}

/// GET /api/v1/alerts/ws — live WebSocket push of new alerts.
/// Upgrades the connection via the `Upgrade: websocket` header.
/// Accepts an optional `?token=<ws-token>` query parameter for token-based auth
/// (required when `auth_disabled = false` and the client cannot send headers).
/// Each frame is a JSON-serialised `AlertRecord` text message.
async fn alert_ws(
    ws: WebSocketUpgrade,
    Query(q): Query<WsTokenQuery>,
    auth: AuthContext,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // If a token is provided validate it; otherwise fall through to header-based auth.
    let tenant_id = if let Some(ref token) = q.token {
        let now = std::time::Instant::now();
        if let Some(expiry) = state.ws_tokens.get(token).map(|e| *e) {
            if now < expiry {
                state.ws_tokens.remove(token); // single-use
                auth.tenant_id.clone()
            } else {
                state.ws_tokens.remove(token);
                return axum::http::StatusCode::UNAUTHORIZED.into_response();
            }
        } else {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
    } else {
        auth.tenant_id.clone()
    };
    ws.on_upgrade(move |socket| handle_alert_ws(socket, tenant_id, state))
}

async fn handle_alert_ws(mut socket: WebSocket, tenant_id: String, state: AppState) {
    let mut rx = state.alert_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(alert) if alert.tenant_id == tenant_id => {
                if let Ok(json) = serde_json::to_string(&alert) {
                    if socket.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            _ => {}
        }
    }
}

// ─── Rule Version History ─────────────────────────────────────────────────────

/// GET /api/v1/rules/:id/versions — list all historical versions of a rule.
async fn list_rule_versions(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<RuleVersion>>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst, Role::Viewer])?;
    // Verify the rule exists and belongs to this tenant.
    state.storage.get_rule(&auth.tenant_id, id).await?;
    let versions = state.storage.list_rule_versions(&auth.tenant_id, id);
    Ok(Json(versions))
}

/// POST /api/v1/rules/:id/versions/:ver/restore — restore a specific rule version.
async fn restore_rule_version(
    auth: AuthContext,
    State(state): State<AppState>,
    Path((id, ver)): Path<(Uuid, u32)>,
) -> Result<Json<DetectionRule>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;
    let snapshot = state
        .storage
        .get_rule_version(&auth.tenant_id, id, ver)
        .ok_or(CyberboxError::NotFound)?;

    // Fetch the current live rule to preserve mutable fields (enabled, schedule, etc.)
    let mut live = state.storage.get_rule(&auth.tenant_id, id).await?;
    live.sigma_source = snapshot.sigma_source;
    live.compiled_plan = snapshot.compiled_plan;
    live.severity = snapshot.severity;

    let saved = state.storage.upsert_rule(live).await?;
    state.stream_rule_cache.refresh(
        &auth.tenant_id,
        state.storage.list_rules(&auth.tenant_id).await?,
    );
    state.rule_executor.invalidate_rule(id);

    tracing::info!(
        actor = %auth.user_id,
        rule_id = %id,
        restored_version = ver,
        "rule version restored"
    );
    Ok(Json(saved))
}

// ─── Auto alert→case correlation ─────────────────────────────────────────────

/// Group a fired alert into an existing open case for the same rule, or create
/// a new case automatically.  Runs as a background task — never blocks ingest.
async fn auto_correlate_alert(state: AppState, alert: AlertRecord) {
    let rule = state
        .storage
        .get_rule(&alert.tenant_id, alert.rule_id)
        .await
        .ok();
    let severity = rule
        .as_ref()
        .map(|r| r.severity.clone())
        .unwrap_or(Severity::Medium);
    let rule_name = rule
        .as_ref()
        .and_then(|r| {
            r.sigma_source
                .lines()
                .find(|l| l.trim_start().starts_with("title:"))
                .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
        })
        .unwrap_or_else(|| format!("Rule {}", alert.rule_id));

    let correlation_tag = format!("rule:{}", alert.rule_id);
    let cutoff = Utc::now() - chrono::Duration::hours(1);

    let cases: Vec<CaseRecord> = if let Some(ch) = &state.clickhouse_event_store {
        ch.list_cases(&alert.tenant_id).await.unwrap_or_default()
    } else {
        state
            .storage
            .list_cases(&alert.tenant_id)
            .await
            .unwrap_or_default()
    };

    // Find an open/in-progress case with the same rule tag within the last hour.
    let existing = cases.into_iter().find(|c| {
        matches!(c.status, CaseStatus::Open | CaseStatus::InProgress)
            && c.tags.iter().any(|t| t == &correlation_tag)
            && c.created_at > cutoff
    });

    if let Some(mut case) = existing {
        if !case.alert_ids.contains(&alert.alert_id) {
            case.alert_ids.push(alert.alert_id);
            case.updated_at = Utc::now();
            if let Some(ch) = &state.clickhouse_event_store {
                let _ = ch.upsert_case(case.clone()).await;
            }
            let _ = state.storage.upsert_case(case).await;
        }
    } else {
        let now = Utc::now();
        let case = CaseRecord {
            case_id: Uuid::new_v4(),
            tenant_id: alert.tenant_id.clone(),
            title: format!("[Auto] {rule_name}"),
            description: String::new(),
            status: CaseStatus::Open,
            severity: severity.clone(),
            alert_ids: vec![alert.alert_id],
            assignee: None,
            created_by: "system".to_string(),
            created_at: now,
            updated_at: now,
            sla_due_at: Some(sla_due_at(&severity, now)),
            closed_at: None,
            tags: vec![correlation_tag],
        };
        if let Some(ch) = &state.clickhouse_event_store {
            let _ = ch.upsert_case(case.clone()).await;
        }
        let _ = state.storage.upsert_case(case).await;
    }
}

// ─── Rule Tuning (AI) ────────────────────────────────────────────────────────

/// POST /api/v1/rules/:id/tune — analyse a rule's false-positive history and
/// ask Claude to suggest condition improvements.
///
/// Requires `nlq_enabled = true` and `CYBERBOX__ANTHROPIC_API_KEY`.
async fn tune_rule_handler(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, CyberboxError> {
    auth.require_any(&[Role::Admin, Role::Analyst])?;

    if !state.nlq_enabled {
        return Err(CyberboxError::BadRequest(
            "Rule tuning requires nlq_enabled = true".to_string(),
        ));
    }
    let api_key = state.anthropic_api_key.as_deref().ok_or_else(|| {
        CyberboxError::Internal("nlq_enabled but anthropic_api_key not configured".to_string())
    })?;

    // Fetch the rule.
    let rules = state.storage.list_rules(&auth.tenant_id).await?;
    let rule = rules
        .into_iter()
        .find(|r| r.rule_id == id)
        .ok_or(CyberboxError::NotFound)?;

    // Summarise recent alert history for this rule.
    let alerts = state.storage.list_alerts(&auth.tenant_id).await?;
    let recent: Vec<serde_json::Value> = alerts
        .into_iter()
        .filter(|a| a.rule_id == id)
        .take(50)
        .map(|a| {
            serde_json::json!({
                "alert_id": a.alert_id,
                "status": format!("{:?}", a.status),
                "resolution": a.resolution,
                "hit_count": a.hit_count,
                "first_seen": a.first_seen,
                "last_seen": a.last_seen,
            })
        })
        .collect();

    let history_json = serde_json::to_string(&recent).unwrap_or_else(|_| "[]".to_string());

    let response = cyberbox_core::nlq::tune_rule(
        &rule.sigma_source,
        &history_json,
        api_key,
        &state.http_client,
    )
    .await
    .map_err(|e| CyberboxError::Internal(format!("Rule tuning failed: {e}")))?;

    tracing::info!(
        actor = %auth.user_id,
        rule_id = %id,
        suggestions = response.suggestions.len(),
        "rule tuning suggestions generated"
    );

    Ok(Json(
        serde_json::to_value(&response).unwrap_or_else(|_| json!({ "suggestions": [] })),
    ))
}

// ─── Source tracking ──────────────────────────────────────────────────────────

/// Update per-source statistics after each accepted event batch.
/// Called from `ingest_events` with the tenant_id and source_type of each event.
/// Uses DashMap entry API — no lock held across the hot path.
pub(crate) fn record_source(state: &AppState, tenant_id: &str, source_type: &str) {
    let key = format!("{tenant_id}:{source_type}");
    let now = Utc::now();
    state
        .sources
        .entry(key)
        .and_modify(|s| {
            s.last_seen = now;
            s.total_events += 1;
            s.status = source_status(s.last_seen);
        })
        .or_insert_with(|| SourceInfo {
            tenant_id: tenant_id.to_string(),
            source_type: source_type.to_string(),
            first_seen: now,
            last_seen: now,
            total_events: 1,
            status: "active".to_string(),
        });
}

fn source_status(last_seen: DateTime<Utc>) -> String {
    let age_secs = (Utc::now() - last_seen).num_seconds().max(0) as u64;
    if age_secs < 60 {
        "active".to_string()
    } else if age_secs < 300 {
        "stale".to_string()
    } else {
        "silent".to_string()
    }
}

/// `GET /api/v1/sources` — list all sources seen by this tenant.
pub async fn list_sources(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Json<Vec<SourceInfo>> {
    let mut sources: Vec<SourceInfo> = state
        .sources
        .iter()
        .filter(|entry| entry.value().tenant_id == auth.tenant_id)
        .map(|entry| {
            let mut s = entry.value().clone();
            s.status = source_status(s.last_seen);
            s
        })
        .collect();
    // Most recently active first
    sources.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    Json(sources)
}

// ── Dashboard stats ────────────────────────────────────────────────────────────

/// `GET /api/v1/dashboard/stats?range=24h` — aggregated stats for the dashboard.
pub async fn dashboard_stats(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, CyberboxError> {
    let tenant_id = &auth.tenant_id;

    // Parse time range (default 24h)
    let range_str = params.get("range").map(|s| s.as_str()).unwrap_or("24h");
    let range_seconds = parse_range_to_seconds(range_str);

    // Agent counts
    let agents: Vec<_> = state
        .agents
        .iter()
        .map(|e| {
            let a = e.value();
            json!({
                "agent_id": a.agent_id,
                "hostname": a.hostname,
                "os": a.os,
                "status": a.status(),
            })
        })
        .collect();
    let active_agents = agents.iter().filter(|a| a["status"] == "active").count();

    // Rule count
    let rule_count = if let Some(ch) = &state.clickhouse_event_store {
        use cyberbox_storage::RuleStore;
        ch.list_rules(tenant_id).await.unwrap_or_default().len()
    } else {
        use cyberbox_storage::RuleStore;
        state
            .storage
            .list_rules(tenant_id)
            .await
            .unwrap_or_default()
            .len()
    };

    // Alert count
    let alert_count = state
        .storage
        .list_alerts(tenant_id)
        .await
        .unwrap_or_default()
        .len();

    // ClickHouse stats (if available)
    let ch_stats = if let Some(ch) = &state.clickhouse_event_store {
        ch.dashboard_stats(tenant_id, range_seconds).await.unwrap_or(json!({}))
    } else {
        json!({ "total_events": 0, "events_by_source": [], "events_by_host": [], "hourly_events": [], "current_eps": 0.0, "eps_trend": [] })
    };

    let mut result = json!({
        "active_agents": active_agents,
        "total_agents": agents.len(),
        "agents": agents,
        "active_rules": rule_count,
        "open_alerts": alert_count,
    });
    // Merge ClickHouse stats
    if let (Some(r), Some(c)) = (result.as_object_mut(), ch_stats.as_object()) {
        for (k, v) in c {
            r.insert(k.clone(), v.clone());
        }
    }

    Ok(Json(result))
}

fn parse_range_to_seconds(range: &str) -> i64 {
    let s = range.trim();
    if let Some(n) = s.strip_suffix('m') {
        n.parse::<i64>().unwrap_or(1440) * 60
    } else if let Some(n) = s.strip_suffix('h') {
        n.parse::<i64>().unwrap_or(24) * 3600
    } else if let Some(n) = s.strip_suffix('d') {
        n.parse::<i64>().unwrap_or(1) * 86400
    } else {
        86400 // default 24h
    }
}

// ── Agent registry ─────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct RegisterAgentRequest {
    pub agent_id: String,
    pub tenant_id: String,
    pub hostname: String,
    pub os: String,
    pub version: String,
}

/// `POST /api/v1/agents/register` — called by cyberbox-agent on startup.
pub async fn register_agent(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<std::net::SocketAddr>>,
    Json(body): Json<RegisterAgentRequest>,
) -> Json<Value> {
    let now = Utc::now();
    // Preserve existing group/tags/pending_config if agent re-registers
    let (group, tags, pending_config) = state
        .agents
        .get(&body.agent_id)
        .map(|e| (e.group.clone(), e.tags.clone(), e.pending_config.clone()))
        .unwrap_or_default();
    let record = AgentRecord {
        agent_id: body.agent_id.clone(),
        tenant_id: body.tenant_id,
        hostname: body.hostname,
        os: body.os,
        version: body.version,
        ip: addr.map(|ConnectInfo(a)| a.ip().to_string()),
        registered_at: now,
        last_seen: now,
        group,
        tags,
        pending_config,
    };
    state.agents.insert(body.agent_id.clone(), record);

    // Persist to ClickHouse (best-effort, non-blocking)
    if let Some(ch) = &state.clickhouse_event_store {
        let ch = ch.clone();
        if let Some(agent) = state.agents.get(&body.agent_id).map(|e| e.value().clone()) {
            tokio::spawn(async move {
                if let Err(e) = ch.upsert_agent(&agent).await {
                    tracing::warn!(error = %e, "failed to persist agent registration to ClickHouse");
                }
            });
        }
    }

    Json(json!({ "agent_id": body.agent_id, "status": "registered" }))
}

/// `POST /api/v1/agents/:id/heartbeat` — updates `last_seen`; returns any
/// queued config in `{"pending_config": "..."}` and clears it after delivery.
pub async fn agent_heartbeat(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Some(mut entry) = state.agents.get_mut(&id) {
        entry.last_seen = Utc::now();
        let cfg = entry.pending_config.take(); // deliver once, then clear

        // Persist cleared state to ClickHouse (best-effort)
        if let Some(ch) = &state.clickhouse_event_store {
            let ch = ch.clone();
            let snapshot = entry.clone();
            tokio::spawn(async move {
                if let Err(e) = ch.upsert_agent(&snapshot).await {
                    tracing::warn!(error = %e, "failed to persist agent heartbeat to ClickHouse");
                }
            });
        }

        let body = if let Some(toml) = cfg {
            json!({ "pending_config": toml })
        } else {
            json!({})
        };
        (StatusCode::OK, Json(body)).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct PatchAgentRequest {
    pub group: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// `PATCH /api/v1/agents/:id` — update group and/or tags.
pub async fn patch_agent(
    auth: AuthContext,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<PatchAgentRequest>,
) -> impl IntoResponse {
    if let Some(mut entry) = state.agents.get_mut(&id) {
        if entry.tenant_id != auth.tenant_id {
            return StatusCode::FORBIDDEN.into_response();
        }
        if let Some(g) = body.group {
            entry.group = Some(g);
        }
        if let Some(t) = body.tags {
            entry.tags = t;
        }

        // Persist to ClickHouse (best-effort)
        if let Some(ch) = &state.clickhouse_event_store {
            let ch = ch.clone();
            let snapshot = entry.clone();
            tokio::spawn(async move {
                if let Err(e) = ch.upsert_agent(&snapshot).await {
                    tracing::warn!(error = %e, "failed to persist agent patch to ClickHouse");
                }
            });
        }

        (
            StatusCode::OK,
            Json(json!({
                "agent_id": entry.agent_id,
                "group":    entry.group,
                "tags":     entry.tags,
            })),
        )
            .into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct PushAgentConfigRequest {
    /// Full TOML content of the new agent.toml to deliver
    pub config_toml: String,
}

/// `POST /api/v1/agents/:id/config` — queue a new config for delivery on the
/// agent's next heartbeat. The agent writes it to disk and logs a restart notice.
pub async fn push_agent_config(
    auth: AuthContext,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<PushAgentConfigRequest>,
) -> impl IntoResponse {
    if let Some(mut entry) = state.agents.get_mut(&id) {
        if entry.tenant_id != auth.tenant_id {
            return StatusCode::FORBIDDEN.into_response();
        }
        entry.pending_config = Some(body.config_toml);

        // Persist to ClickHouse (best-effort)
        if let Some(ch) = &state.clickhouse_event_store {
            let ch = ch.clone();
            let snapshot = entry.clone();
            tokio::spawn(async move {
                if let Err(e) = ch.upsert_agent(&snapshot).await {
                    tracing::warn!(error = %e, "failed to persist agent config push to ClickHouse");
                }
            });
        }

        (
            StatusCode::ACCEPTED,
            Json(json!({
                "agent_id": id,
                "status": "config_queued",
                "note": "Config will be delivered on the agent's next heartbeat",
            })),
        )
            .into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct ListAgentsQuery {
    pub group: Option<String>,
}

/// `GET /api/v1/agents[?group=<name>]` — list registered agents for this tenant.
pub async fn list_agents(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(q): Query<ListAgentsQuery>,
) -> Json<Vec<Value>> {
    let mut agents: Vec<Value> = state
        .agents
        .iter()
        .filter(|e| {
            let a = e.value();
            a.tenant_id == auth.tenant_id
                && q.group
                    .as_deref()
                    .is_none_or(|g| a.group.as_deref() == Some(g))
        })
        .map(|e| {
            let a = e.value();
            json!({
                "agent_id":      a.agent_id,
                "tenant_id":     a.tenant_id,
                "hostname":      a.hostname,
                "os":            a.os,
                "version":       a.version,
                "ip":            a.ip,
                "group":         a.group,
                "tags":          a.tags,
                "registered_at": a.registered_at,
                "last_seen":     a.last_seen,
                "status":        a.status(),
            })
        })
        .collect();
    agents.sort_by(|a, b| {
        let la = a["last_seen"].as_str().unwrap_or("");
        let lb = b["last_seen"].as_str().unwrap_or("");
        lb.cmp(la)
    });
    Json(agents)
}

// =============================================================================
// Rule Packs: import-pack + sync-dir (detection-as-code)
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct ImportPackRequest {
    /// Filesystem path to a directory of `.yml` / `.yaml` Sigma rule files.
    pub path: String,
    /// If true, disable rules that exist in DB but not in the directory (default: false).
    #[serde(default)]
    pub prune: bool,
}

/// POST /api/v1/rules/import-pack
///
/// Bulk-import Sigma rules from a directory on the API server filesystem.
/// Each `.yml` / `.yaml` file is compiled and upserted.
/// Existing rules with the same `rule_id` are updated if the source changed.
pub async fn import_rule_pack(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(req): Json<ImportPackRequest>,
) -> Result<Json<crate::rules_pack::ImportResult>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;
    let result =
        crate::rules_pack::import_rules_from_dir(&auth, &state, &req.path, req.prune).await?;

    append_audit_log(
        &state,
        &auth.tenant_id,
        &auth.user_id,
        "rules.import_pack",
        "rule_pack",
        &req.path,
        Value::Null,
        json!({"imported": result.imported, "updated": result.updated, "errors": result.errors.len()}),
    )
    .await;

    Ok(Json(result))
}

/// POST /api/v1/rules/sync-dir
///
/// Same as import-pack but intended for detection-as-code CI pipelines.
/// Default `prune=true`: rules removed from the directory get disabled.
pub async fn sync_rules_from_dir(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(req): Json<ImportPackRequest>,
) -> Result<Json<crate::rules_pack::ImportResult>, CyberboxError> {
    auth.require_any(&[Role::Admin])?;
    let result = crate::rules_pack::import_rules_from_dir(&auth, &state, &req.path, true).await?;

    append_audit_log(
        &state,
        &auth.tenant_id,
        &auth.user_id,
        "rules.sync_dir",
        "rule_pack",
        &req.path,
        Value::Null,
        json!({"imported": result.imported, "updated": result.updated, "pruned": result.pruned, "errors": result.errors.len()}),
    )
    .await;

    Ok(Json(result))
}
