use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cyberbox_api::{build_router, install_metrics_exporter, persist, scheduler, state::AppState};
use cyberbox_auth::JwtValidator;
use cyberbox_core::{telemetry, AppConfig};
use cyberbox_storage::{ClickHouseWriteBuffer, WriteBufferConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AppConfig::from_env()?;
    let otlp = (!config.otlp_endpoint.is_empty()).then_some(config.otlp_endpoint.as_str());
    telemetry::init("cyberbox_api", otlp);
    let metrics_handle = install_metrics_exporter()?;

    // Initialise JWT validator when auth is enabled.  If the OIDC issuer is
    // unreachable at startup we log a warning and fall back to bypass mode
    // rather than refusing to start — useful during infra bring-up.
    let jwt_validator: Option<Arc<JwtValidator>> = if !config.auth_disabled {
        match JwtValidator::from_discovery(&config.oidc_issuer, &config.oidc_audience).await {
            Ok(v) => {
                tracing::info!(
                    issuer = %config.oidc_issuer,
                    audience = %config.oidc_audience,
                    "JWT validator initialised — auth enabled"
                );
                Some(Arc::new(v))
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "JWT validator init failed; falling back to header-based bypass mode"
                );
                None
            }
        }
    } else {
        tracing::info!("auth_disabled=true; using header-based bypass mode");
        None
    };

    let mut state = AppState::from_config(metrics_handle, &config, jwt_validator.clone())
        .map_err(anyhow::Error::msg)?;

    // Load persisted feeds and RBAC overrides from disk (best-effort).
    persist::load_feeds(&state.threat_intel_feeds, &state.state_dir);
    persist::load_rbac(&state.rbac_store, &state.state_dir);

    if let Some(clickhouse_store) = &state.clickhouse_event_store {
        match clickhouse_store.ensure_schema().await {
            Ok(()) => tracing::info!("ClickHouse schema ensured"),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "ClickHouse schema init failed — will retry on first query; \
                     this is expected during infra bring-up"
                );
            }
        }

        // Reload persisted agent registrations into the in-memory DashMap
        match clickhouse_store.list_agents_all().await {
            Ok(agents) => {
                let count = agents.len();
                for agent in agents {
                    state.agents.insert(agent.agent_id.clone(), agent);
                }
                if count > 0 {
                    tracing::info!(count, "loaded agent registrations from ClickHouse");
                }
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to load agents from ClickHouse — agent list will start empty"
                );
            }
        }

        // Reload persisted alerts into the in-memory DashMap
        match clickhouse_store.list_alerts_all().await {
            Ok(alerts) => {
                let count = alerts.len();
                for alert in alerts {
                    use cyberbox_storage::AlertStore as _;
                    let _ = state.storage.upsert_alert(alert).await;
                }
                if count > 0 {
                    tracing::info!(count, "loaded alerts from ClickHouse");
                }
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to load alerts from ClickHouse — alert list will start empty"
                );
            }
        }

        // Reload persisted cases into the in-memory DashMap
        match clickhouse_store.list_cases_all().await {
            Ok(cases) => {
                let count = cases.len();
                for case in cases {
                    use cyberbox_storage::CaseStore as _;
                    let _ = state.storage.upsert_case(case).await;
                }
                if count > 0 {
                    tracing::info!(count, "loaded cases from ClickHouse");
                }
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to load cases from ClickHouse — case list will start empty"
                );
            }
        }
    }

    // Start the ClickHouse async write buffer if the sink is enabled.
    // This spawns a background Tokio task that accumulates events and flushes
    // in large batches (batch_size OR flush_interval_ms, whichever comes first).
    if config.clickhouse_sink_enabled {
        if let Some(clickhouse_store) = &state.clickhouse_event_store {
            let buf_config = WriteBufferConfig::from_app_config(&config);
            tracing::info!(
                batch_size = buf_config.batch_size,
                flush_interval_ms = buf_config.flush_interval_ms,
                channel_capacity = buf_config.channel_capacity,
                max_retries = buf_config.max_retries,
                "starting ClickHouse async write buffer"
            );
            state.clickhouse_write_buffer = Some(ClickHouseWriteBuffer::start(
                clickhouse_store.clone(),
                buf_config,
            ));
        }
    }

    // Spawn background JWKS refresh task (keeps keys current ahead of rotation).
    if let Some(validator) = &jwt_validator {
        let refresh_secs = config.jwks_refresh_interval_secs;
        if refresh_secs > 0 {
            let validator = Arc::clone(validator);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                interval.tick().await; // skip the immediate first tick
                loop {
                    interval.tick().await;
                    if let Err(e) = validator.refresh_keys().await {
                        tracing::warn!(error = %e, "periodic JWKS refresh failed");
                    } else {
                        tracing::debug!("JWKS keys refreshed proactively");
                    }
                }
            });
            tracing::info!(refresh_secs, "periodic JWKS refresh task spawned");
        }
    }

    // In noop/in-memory mode (no Kafka) spawn the in-process scheduler so
    // scheduled rules are evaluated against stored events on a timer.
    if matches!(
        state.raw_event_publisher,
        cyberbox_api::stream::RawEventPublisher::Noop
    ) {
        let sched_state = state.clone();
        let tick_secs = config.scheduler_tick_interval_seconds;
        tokio::spawn(async move {
            scheduler::run_scheduler_loop(sched_state, tick_secs).await;
        });
        tracing::info!(tick_secs, "in-memory scheduler spawned");
    }

    // Spawn background threat-intel auto-sync task.
    // Iterates all configured feeds every 60 s and triggers a sync when a
    // feed's `auto_sync_interval_secs` has elapsed since its `last_synced_at`.
    {
        let ti_feeds = Arc::clone(&state.threat_intel_feeds);
        let ti_lookup = Arc::clone(&state.lookup_store);
        let ti_http_client = state.http_client.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let now = chrono::Utc::now();
                let feed_ids: Vec<_> = ti_feeds.iter().map(|e| *e.key()).collect();
                for fid in feed_ids {
                    let feed = match ti_feeds.get(&fid) {
                        Some(f) => f.clone(),
                        None => continue,
                    };
                    if feed.auto_sync_interval_secs == 0 || !feed.enabled {
                        continue;
                    }
                    let due = feed.last_synced_at.is_none_or(|last| {
                        let elapsed = now.signed_duration_since(last).num_seconds().max(0) as u64;
                        elapsed >= feed.auto_sync_interval_secs
                    });
                    if !due {
                        continue;
                    }
                    let feed_name = feed.name.clone();
                    match feed.sync(&ti_lookup, &ti_http_client).await {
                        Ok(result) => {
                            tracing::info!(
                                feed = %feed_name,
                                added = result.indicators_added,
                                "threat-intel auto-sync completed"
                            );
                            // Update last_synced_at timestamp in the map.
                            if let Some(mut entry) = ti_feeds.get_mut(&fid) {
                                entry.last_synced_at = Some(now);
                            }
                        }
                        Err(err) => {
                            tracing::warn!(feed = %feed_name, error = %err, "threat-intel auto-sync failed");
                        }
                    }
                }
            }
        });
        tracing::info!("threat-intel auto-sync task spawned (poll interval: 60s)");
    }

    // Start syslog UDP/TCP receivers if enabled.
    // They feed into the same in-memory store and ClickHouse write buffer as
    // the REST ingest endpoint, with `EventSource::Syslog` and the configured
    // default tenant ID.
    if config.syslog_udp_enabled || config.syslog_tcp_enabled {
        cyberbox_api::syslog_receiver::start(state.clone(), &config);
    }

    // Auto-import bundled Sigma rules from CYBERBOX__RULES_DIR (if set or default exists).
    {
        let rules_dir = std::env::var("CYBERBOX__RULES_DIR").ok().or_else(|| {
            let default = std::path::PathBuf::from("rules/bundled");
            if default.is_dir() {
                Some(default.to_string_lossy().to_string())
            } else {
                None
            }
        });
        if let Some(dir) = rules_dir {
            let s = state.clone();
            tokio::spawn(async move {
                // Use a system auth context for the import.
                // When tenant_id_override is set, import under that tenant
                // so detection rules match events forced to the same tenant.
                let tenant_id = s
                    .tenant_id_override
                    .clone()
                    .unwrap_or_else(|| "default".to_string());
                let auth = cyberbox_auth::AuthContext {
                    tenant_id,
                    user_id: "system".to_string(),
                    roles: vec![cyberbox_auth::Role::Admin],
                };
                match cyberbox_api::rules_pack::import_rules_from_dir(&auth, &s, &dir, false).await
                {
                    Ok(result) => {
                        if result.imported > 0 || result.updated > 0 {
                            tracing::info!(
                                dir = %dir,
                                imported = result.imported,
                                updated  = result.updated,
                                skipped  = result.skipped,
                                errors   = result.errors.len(),
                                "bundled rules auto-imported on startup"
                            );
                            // Refresh detection engine cache so rules are active immediately.
                            use cyberbox_storage::RuleStore as _;
                            let fresh: Vec<cyberbox_models::DetectionRule> =
                                if let Some(ch) = &s.clickhouse_event_store {
                                    ch.list_rules(&auth.tenant_id).await.unwrap_or_default()
                                } else {
                                    s.storage
                                        .list_rules(&auth.tenant_id)
                                        .await
                                        .unwrap_or_default()
                                };
                            s.stream_rule_cache.refresh(&auth.tenant_id, fresh);
                        } else {
                            tracing::debug!(dir = %dir, skipped = result.skipped, "bundled rules already up to date");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(dir = %dir, error = %e, "bundled rules auto-import failed");
                    }
                }
            });
        }
    }

    let app = build_router(state);

    let addr: SocketAddr = config.bind_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "cyberbox api listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
