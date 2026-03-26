use std::{
    env, fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{sync::mpsc, task::JoinSet};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct Config {
    api_base: String,
    duration_seconds: u64,
    concurrency: usize,
    batch_size: usize,
    tenant_id: String,
    user_id: String,
    event_age_min_seconds: u64,
    event_age_max_seconds: u64,
    persist_check: bool,
    persistence_probe_attempts: usize,
    persistence_probe_interval_ms: u64,
    target_eps: Option<u64>,
    report_path: Option<String>,
    api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct IncomingEvent {
    tenant_id: String,
    source: String,
    event_time: String,
    raw_payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
struct EventIngestRequest {
    events: Vec<IncomingEvent>,
}

#[derive(Debug, Clone, Deserialize)]
struct EventIngestResponse {
    accepted: usize,
    rejected: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct HealthResponse {
    status: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SearchResponse {
    rows: Vec<serde_json::Value>,
    total: u64,
}

#[derive(Debug, Default)]
struct WorkerResult {
    requests_total: u64,
    requests_error: u64,
    accepted: u64,
    rejected: u64,
    latencies_ms: Vec<f64>,
    errors: Vec<String>,
}

#[derive(Debug)]
struct RequestOutcome {
    latency_ms: f64,
    request_error: bool,
    accepted: u64,
    rejected: u64,
    error: Option<String>,
}

#[derive(Debug)]
struct LoadExecution {
    aggregate: WorkerResult,
    scheduled_requests: Option<u64>,
}

#[derive(Debug, Serialize)]
struct LoadReport {
    run_at_utc: String,
    api_base: String,
    run_id: String,
    tenant_id: String,
    mode: String,
    target_eps: Option<u64>,
    duration_seconds: u64,
    concurrency: usize,
    batch_size: usize,
    event_age_min_seconds: u64,
    event_age_max_seconds: u64,
    elapsed_seconds: f64,
    scheduled_requests: Option<u64>,
    requests_total: u64,
    requests_success: u64,
    requests_error: u64,
    events_attempted: u64,
    events_accepted: u64,
    events_rejected: u64,
    attempted_eps: f64,
    accepted_eps: f64,
    rejected_eps: f64,
    attempted_eps_target_window: f64,
    accepted_eps_target_window: f64,
    rejected_eps_target_window: f64,
    target_achieved_pct: Option<f64>,
    api_rejection_loss_pct: f64,
    request_latency_p95_ms: f64,
    request_latency_p99_ms: f64,
    persisted_events: Option<u64>,
    persisted_loss_pct_vs_accepted: Option<f64>,
    persistence_probe_attempts: Vec<i64>,
    sample_errors: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_args()?;
    config.validate()?;

    let headers = build_headers(&config)?;
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .pool_max_idle_per_host(config.concurrency.saturating_mul(2).max(8))
        .tcp_nodelay(true)
        .build()
        .context("failed to build reqwest client")?;

    check_health(&client, &config).await?;

    let run_id = format!("async-{}", Uuid::new_v4().simple());
    let started_at = Utc::now();
    let wall = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(config.duration_seconds);

    let execution = if config.target_eps.is_some() {
        run_fixed_rate_mode(client.clone(), &config, &run_id, deadline).await?
    } else {
        run_max_throughput_mode(client.clone(), &config, &run_id, deadline).await?
    };

    let mut aggregate = execution.aggregate;
    let elapsed_seconds = wall.elapsed().as_secs_f64().max(0.001);
    let requests_success = aggregate
        .requests_total
        .saturating_sub(aggregate.requests_error);
    let events_attempted = aggregate.accepted.saturating_add(aggregate.rejected);
    let attempted_eps = round2(events_attempted as f64 / elapsed_seconds);
    let accepted_eps = round2(aggregate.accepted as f64 / elapsed_seconds);
    let rejected_eps = round2(aggregate.rejected as f64 / elapsed_seconds);
    let target_window_seconds = config.duration_seconds.max(1) as f64;
    let attempted_eps_target_window = round2(events_attempted as f64 / target_window_seconds);
    let accepted_eps_target_window = round2(aggregate.accepted as f64 / target_window_seconds);
    let rejected_eps_target_window = round2(aggregate.rejected as f64 / target_window_seconds);
    let target_achieved_pct = config.target_eps.map(|target| {
        if target == 0 {
            0.0
        } else {
            round2(100.0 * accepted_eps_target_window / target as f64)
        }
    });
    let api_rejection_loss_pct = if events_attempted == 0 {
        0.0
    } else {
        round4(100.0 * aggregate.rejected as f64 / events_attempted as f64)
    };
    let request_latency_p95_ms = round2(quantile(&mut aggregate.latencies_ms, 0.95));
    let request_latency_p99_ms = round2(quantile(&mut aggregate.latencies_ms, 0.99));

    let (persisted_events, persistence_probe_attempts) = if config.persist_check {
        let (count, attempts) =
            persistence_probe(&client, &config, &run_id, started_at, aggregate.accepted).await?;
        (count, attempts)
    } else {
        (None, Vec::new())
    };
    let persisted_loss_pct_vs_accepted = persisted_events.map(|persisted| {
        if aggregate.accepted == 0 {
            0.0
        } else {
            let diff = aggregate.accepted.saturating_sub(persisted);
            round4(100.0 * diff as f64 / aggregate.accepted as f64)
        }
    });

    let report = LoadReport {
        run_at_utc: Utc::now().to_rfc3339(),
        api_base: config.api_base.clone(),
        run_id,
        tenant_id: config.tenant_id.clone(),
        mode: if config.target_eps.is_some() {
            "fixed-rate".to_string()
        } else {
            "max-throughput".to_string()
        },
        target_eps: config.target_eps,
        duration_seconds: config.duration_seconds,
        concurrency: config.concurrency,
        batch_size: config.batch_size,
        event_age_min_seconds: config.event_age_min_seconds,
        event_age_max_seconds: config.event_age_max_seconds,
        elapsed_seconds: round3(elapsed_seconds),
        scheduled_requests: execution.scheduled_requests,
        requests_total: aggregate.requests_total,
        requests_success,
        requests_error: aggregate.requests_error,
        events_attempted,
        events_accepted: aggregate.accepted,
        events_rejected: aggregate.rejected,
        attempted_eps,
        accepted_eps,
        rejected_eps,
        attempted_eps_target_window,
        accepted_eps_target_window,
        rejected_eps_target_window,
        target_achieved_pct,
        api_rejection_loss_pct,
        request_latency_p95_ms,
        request_latency_p99_ms,
        persisted_events,
        persisted_loss_pct_vs_accepted,
        persistence_probe_attempts,
        sample_errors: aggregate.errors.into_iter().take(10).collect(),
    };

    let output = serde_json::to_string_pretty(&report).context("failed to serialize report")?;
    let output_path = write_report(&config, &output)?;

    println!("EPS async report written to {}", output_path.display());
    println!("{output}");
    Ok(())
}

async fn run_max_throughput_mode(
    client: reqwest::Client,
    config: &Config,
    run_id: &str,
    deadline: Instant,
) -> Result<LoadExecution> {
    let mut join_set = JoinSet::new();
    for worker_index in 0..config.concurrency {
        let worker_client = client.clone();
        let worker_config = config.clone();
        let worker_run_id = run_id.to_string();
        join_set.spawn(async move {
            run_worker_max(
                worker_client,
                &worker_config,
                worker_index,
                &worker_run_id,
                deadline,
            )
            .await
        });
    }

    let aggregate = collect_worker_results(&mut join_set).await?;
    Ok(LoadExecution {
        aggregate,
        scheduled_requests: None,
    })
}

async fn run_fixed_rate_mode(
    client: reqwest::Client,
    config: &Config,
    run_id: &str,
    deadline: Instant,
) -> Result<LoadExecution> {
    let target_eps = config.target_eps.unwrap_or(0);
    if target_eps == 0 {
        anyhow::bail!("target eps must be > 0 for fixed-rate mode");
    }

    let request_interval_seconds = config.batch_size as f64 / target_eps as f64;
    let request_interval = Duration::from_secs_f64(request_interval_seconds.max(0.000_001));
    let channel_capacity = config.concurrency.saturating_mul(8).max(64);

    let mut senders = Vec::with_capacity(config.concurrency);
    let mut join_set = JoinSet::new();
    for worker_index in 0..config.concurrency {
        let (tx, rx) = mpsc::channel::<()>(channel_capacity);
        senders.push(tx);

        let worker_client = client.clone();
        let worker_config = config.clone();
        let worker_run_id = run_id.to_string();
        join_set.spawn(async move {
            run_worker_paced(
                worker_client,
                &worker_config,
                worker_index,
                &worker_run_id,
                rx,
            )
            .await
        });
    }

    let mut scheduled_requests = 0u64;
    let mut worker_cursor = 0usize;
    let mut next_send_at = Instant::now();
    while Instant::now() < deadline {
        if let Some(wait) = next_send_at.checked_duration_since(Instant::now()) {
            tokio::time::sleep(wait).await;
        }

        let sender = &senders[worker_cursor % senders.len()];
        if sender.send(()).await.is_err() {
            break;
        }

        scheduled_requests = scheduled_requests.saturating_add(1);
        worker_cursor = worker_cursor.wrapping_add(1);
        next_send_at = next_send_at
            .checked_add(request_interval)
            .unwrap_or_else(Instant::now);
    }

    drop(senders);

    let aggregate = collect_worker_results(&mut join_set).await?;
    Ok(LoadExecution {
        aggregate,
        scheduled_requests: Some(scheduled_requests),
    })
}

async fn collect_worker_results(
    join_set: &mut JoinSet<Result<WorkerResult>>,
) -> Result<WorkerResult> {
    let mut aggregate = WorkerResult::default();
    while let Some(worker_result) = join_set.join_next().await {
        let result = worker_result.context("worker join failed")??;
        aggregate.requests_total = aggregate
            .requests_total
            .saturating_add(result.requests_total);
        aggregate.requests_error = aggregate
            .requests_error
            .saturating_add(result.requests_error);
        aggregate.accepted = aggregate.accepted.saturating_add(result.accepted);
        aggregate.rejected = aggregate.rejected.saturating_add(result.rejected);
        aggregate.latencies_ms.extend(result.latencies_ms);
        aggregate.errors.extend(result.errors.into_iter().take(10));
    }
    Ok(aggregate)
}

async fn run_worker_max(
    client: reqwest::Client,
    config: &Config,
    worker_index: usize,
    run_id: &str,
    deadline: Instant,
) -> Result<WorkerResult> {
    let mut result = WorkerResult::default();
    while Instant::now() < deadline {
        let body = build_ingest_body(config, run_id, worker_index);
        let outcome = send_ingest_request(&client, config, &body).await;
        record_outcome(&mut result, config, outcome);
    }
    Ok(result)
}

async fn run_worker_paced(
    client: reqwest::Client,
    config: &Config,
    worker_index: usize,
    run_id: &str,
    mut receiver: mpsc::Receiver<()>,
) -> Result<WorkerResult> {
    let mut result = WorkerResult::default();
    while receiver.recv().await.is_some() {
        let body = build_ingest_body(config, run_id, worker_index);
        let outcome = send_ingest_request(&client, config, &body).await;
        record_outcome(&mut result, config, outcome);
    }
    Ok(result)
}

async fn send_ingest_request(
    client: &reqwest::Client,
    config: &Config,
    body: &EventIngestRequest,
) -> RequestOutcome {
    let started = Instant::now();
    let request = client
        .post(format!("{}/api/v1/events:ingest", config.api_base))
        .json(body)
        .send()
        .await;
    let latency_ms = started.elapsed().as_secs_f64() * 1000.0;

    match request {
        Ok(response) if response.status().is_success() => {
            match response.json::<EventIngestResponse>().await {
                Ok(ingest) => RequestOutcome {
                    latency_ms,
                    request_error: false,
                    accepted: ingest.accepted as u64,
                    rejected: ingest.rejected as u64,
                    error: None,
                },
                Err(err) => RequestOutcome {
                    latency_ms,
                    request_error: true,
                    accepted: 0,
                    rejected: config.batch_size as u64,
                    error: Some(format!("decode ingest response failed: {err}")),
                },
            }
        }
        Ok(response) => {
            let status = response.status();
            let text = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            RequestOutcome {
                latency_ms,
                request_error: true,
                accepted: 0,
                rejected: config.batch_size as u64,
                error: Some(format!("status {status}: {text}")),
            }
        }
        Err(err) => RequestOutcome {
            latency_ms,
            request_error: true,
            accepted: 0,
            rejected: config.batch_size as u64,
            error: Some(err.to_string()),
        },
    }
}

fn record_outcome(result: &mut WorkerResult, _config: &Config, outcome: RequestOutcome) {
    result.requests_total = result.requests_total.saturating_add(1);
    if outcome.request_error {
        result.requests_error = result.requests_error.saturating_add(1);
    }
    result.accepted = result.accepted.saturating_add(outcome.accepted);
    result.rejected = result.rejected.saturating_add(outcome.rejected);
    result.latencies_ms.push(outcome.latency_ms);
    if let Some(error) = outcome.error {
        if result.errors.len() < 10 {
            result.errors.push(error);
        }
    }
}

fn build_ingest_body(config: &Config, run_id: &str, worker_index: usize) -> EventIngestRequest {
    let mut events = Vec::with_capacity(config.batch_size);
    let now = Utc::now();
    let age_range = config
        .event_age_max_seconds
        .saturating_sub(config.event_age_min_seconds);
    for _ in 0..config.batch_size {
        let nonce_uuid = Uuid::new_v4();
        let nonce = nonce_uuid.simple().to_string();
        let event_age_seconds = if age_range == 0 {
            config.event_age_min_seconds
        } else {
            config
                .event_age_min_seconds
                .saturating_add((nonce_uuid.as_u128() as u64) % age_range.saturating_add(1))
        };
        let event_time = (now
            - chrono::Duration::seconds(std::cmp::min(event_age_seconds, i64::MAX as u64) as i64))
        .to_rfc3339();
        events.push(IncomingEvent {
            tenant_id: config.tenant_id.clone(),
            source: "windows_sysmon".to_string(),
            event_time,
            raw_payload: json!({
                "event_code": 1,
                "process_name": "powershell.exe",
                "cmdline": format!("powershell -enc load-async-{nonce}"),
                "message": format!("load-eps-run={run_id} worker={worker_index} nonce={nonce}"),
                "run_id": run_id,
                "worker_id": worker_index,
                "nonce": nonce,
                "event_age_seconds": event_age_seconds,
            }),
        });
    }
    EventIngestRequest { events }
}

async fn check_health(client: &reqwest::Client, config: &Config) -> Result<()> {
    let response = client
        .get(format!("{}/healthz", config.api_base))
        .send()
        .await
        .context("health check request failed")?;
    if !response.status().is_success() {
        anyhow::bail!("health check failed with status {}", response.status());
    }
    let health: HealthResponse = response
        .json()
        .await
        .context("failed to decode health response")?;
    if health.status != "ok" {
        anyhow::bail!("health status is not ok: {}", health.status);
    }
    Ok(())
}

async fn persistence_probe(
    client: &reqwest::Client,
    config: &Config,
    run_id: &str,
    started_at: DateTime<Utc>,
    accepted: u64,
) -> Result<(Option<u64>, Vec<i64>)> {
    let mut attempts = Vec::new();
    let mut last_count = None;
    for attempt in 0..config.persistence_probe_attempts.max(1) {
        match query_persisted_count(client, config, run_id, started_at).await {
            Ok(count) => {
                attempts.push(count as i64);
                last_count = Some(count);
                if accepted == 0 || count >= accepted {
                    break;
                }
            }
            Err(_) => attempts.push(-1),
        }
        if attempt + 1 < config.persistence_probe_attempts.max(1) {
            tokio::time::sleep(Duration::from_millis(
                config.persistence_probe_interval_ms.max(1),
            ))
            .await;
        }
    }
    Ok((last_count, attempts))
}

async fn query_persisted_count(
    client: &reqwest::Client,
    config: &Config,
    run_id: &str,
    started_at: DateTime<Utc>,
) -> Result<u64> {
    let escaped_run_id = run_id.replace('\'', "''");
    let sql = format!(
        "SELECT event_id, any(tenant_id) AS tenant_id, max(event_time) AS event_time \
         FROM events_hot \
         WHERE position(raw_payload, '{escaped_run_id}') > 0 \
         GROUP BY event_id"
    );
    let body = json!({
        "tenant_id": config.tenant_id,
        "sql": sql,
        "time_range": {
            "start": (started_at - chrono::Duration::minutes(1)).to_rfc3339(),
            "end": (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
        },
        "filters": [],
        "pagination": {
            "page": 1,
            "page_size": 1
        }
    });
    let response = client
        .post(format!("{}/api/v1/search:query", config.api_base))
        .json(&body)
        .send()
        .await
        .context("search query request failed")?;
    if !response.status().is_success() {
        anyhow::bail!("search query failed with status {}", response.status());
    }
    let search: SearchResponse = response
        .json()
        .await
        .context("failed to decode search query response")?;
    let unique_events = search.rows.first().and_then(|row| {
        row.get("unique_events").and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|raw| raw.parse::<u64>().ok()))
        })
    });
    Ok(unique_events.unwrap_or(search.total))
}

fn build_headers(config: &Config) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        "x-tenant-id",
        HeaderValue::from_str(&config.tenant_id).context("invalid tenant header value")?,
    );
    headers.insert(
        "x-user-id",
        HeaderValue::from_str(&config.user_id).context("invalid user header value")?,
    );
    headers.insert(
        "x-roles",
        HeaderValue::from_static("admin,analyst,viewer,ingestor"),
    );
    if let Ok(key) = std::env::var("LOADGEN_API_KEY") {
        headers.insert(
            "x-api-key",
            HeaderValue::from_str(&key).context("invalid api key header value")?,
        );
    }
    Ok(headers)
}

impl Config {
    fn from_args() -> Result<Self> {
        let args = env::args().collect::<Vec<_>>();
        Ok(Self {
            api_base: parse_string_arg(&args, "--api-base")
                .unwrap_or_else(|| "http://127.0.0.1:8080".to_string()),
            duration_seconds: parse_u64_arg(&args, "--duration-seconds").unwrap_or(30),
            concurrency: parse_usize_arg(&args, "--concurrency").unwrap_or(12),
            batch_size: parse_usize_arg(&args, "--batch-size").unwrap_or(100),
            tenant_id: parse_string_arg(&args, "--tenant-id")
                .unwrap_or_else(|| "tenant-a".to_string()),
            user_id: parse_string_arg(&args, "--user-id")
                .unwrap_or_else(|| "soc-admin".to_string()),
            event_age_min_seconds: parse_u64_arg(&args, "--event-age-min-seconds").unwrap_or(0),
            event_age_max_seconds: parse_u64_arg(&args, "--event-age-max-seconds").unwrap_or(0),
            persist_check: !args.iter().any(|arg| arg == "--skip-persist-check"),
            persistence_probe_attempts: parse_usize_arg(&args, "--persist-probe-attempts")
                .unwrap_or(60),
            persistence_probe_interval_ms: parse_u64_arg(&args, "--persist-probe-interval-ms")
                .unwrap_or(2000),
            target_eps: parse_u64_arg(&args, "--target-eps"),
            report_path: parse_string_arg(&args, "--report-path"),
            api_key: parse_string_arg(&args, "--api-key"),
        })
    }

    fn validate(&self) -> Result<()> {
        if self.duration_seconds == 0 {
            anyhow::bail!("--duration-seconds must be > 0");
        }
        if self.concurrency == 0 {
            anyhow::bail!("--concurrency must be > 0");
        }
        if self.batch_size == 0 {
            anyhow::bail!("--batch-size must be > 0");
        }
        if let Some(target_eps) = self.target_eps {
            if target_eps == 0 {
                anyhow::bail!("--target-eps must be > 0");
            }
        }
        if self.event_age_min_seconds > self.event_age_max_seconds {
            anyhow::bail!("--event-age-min-seconds must be <= --event-age-max-seconds");
        }
        if self.persistence_probe_attempts == 0 {
            anyhow::bail!("--persist-probe-attempts must be > 0");
        }
        if self.persistence_probe_interval_ms == 0 {
            anyhow::bail!("--persist-probe-interval-ms must be > 0");
        }
        Ok(())
    }
}

fn parse_string_arg(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find_map(|pair| (pair[0] == flag).then(|| pair[1].clone()))
}

fn parse_u64_arg(args: &[String], flag: &str) -> Option<u64> {
    parse_string_arg(args, flag).and_then(|value| value.parse::<u64>().ok())
}

fn parse_usize_arg(args: &[String], flag: &str) -> Option<usize> {
    parse_string_arg(args, flag).and_then(|value| value.parse::<usize>().ok())
}

fn quantile(values: &mut [f64], quantile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.total_cmp(b));
    let clamped = quantile.clamp(0.0, 1.0);
    let index = ((values.len() as f64 * clamped).ceil() as usize).saturating_sub(1);
    values[index.min(values.len() - 1)]
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn write_report(config: &Config, output: &str) -> Result<PathBuf> {
    let cwd = env::current_dir().context("failed to resolve current directory")?;
    let output_path = if let Some(path_arg) = &config.report_path {
        let raw = PathBuf::from(path_arg);
        if raw.is_absolute() {
            raw
        } else {
            cwd.join(raw)
        }
    } else {
        cwd.join("logs").join("eps-load-async.json")
    };

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).context("failed to create report parent directory")?;
    }
    fs::write(&output_path, output).context("failed to write load report")?;
    Ok(output_path)
}
