//! Cloud source polling: AWS S3, Okta System Log, Microsoft 365 Management Activity API.
//!
//! Each source is independently configurable and runs as its own async task.
//! All tasks honour a shared shutdown signal (`tokio::sync::watch`) so they
//! exit cleanly on SIGTERM / Ctrl-C without leaking threads.
//! Consecutive API errors trigger exponential back-off (5 s → 10 s → 20 s …
//! capped at 300 s or the configured poll interval, whichever is smaller).
//!
//! # S3
//! | Variable | Default | Description |
//! |---|---|---|
//! | `COLLECTOR_S3_ENABLED` | `false` | Enable S3 polling |
//! | `COLLECTOR_S3_BUCKET` | *(req)* | S3 bucket name |
//! | `COLLECTOR_S3_PREFIX` | *(empty)* | Key prefix filter |
//! | `COLLECTOR_S3_REGION` | `us-east-1` | AWS region |
//! | `AWS_ACCESS_KEY_ID` | *(req)* | AWS credentials |
//! | `AWS_SECRET_ACCESS_KEY` | *(req)* | AWS credentials |
//! | `COLLECTOR_S3_POLL_SECS` | `60` | Poll interval |
//!
//! # Okta
//! | Variable | Default | Description |
//! |---|---|---|
//! | `COLLECTOR_OKTA_ENABLED` | `false` | Enable Okta polling |
//! | `COLLECTOR_OKTA_DOMAIN` | *(req)* | e.g. `company.okta.com` |
//! | `COLLECTOR_OKTA_API_TOKEN` | *(req)* | SSWS token |
//! | `COLLECTOR_OKTA_POLL_SECS` | `30` | Poll interval |
//!
//! # Microsoft 365
//! | Variable | Default | Description |
//! |---|---|---|
//! | `COLLECTOR_O365_ENABLED` | `false` | Enable O365 polling |
//! | `COLLECTOR_O365_TENANT_ID` | *(req)* | AAD tenant UUID |
//! | `COLLECTOR_O365_CLIENT_ID` | *(req)* | App registration client_id |
//! | `COLLECTOR_O365_CLIENT_SECRET` | *(req)* | App registration secret |
//! | `COLLECTOR_O365_CONTENT_TYPES` | `Audit.AzureActiveDirectory,Audit.Exchange` | Comma-separated |
//! | `COLLECTOR_O365_POLL_SECS` | `300` | Poll interval (API has ~5 min delay) |

use std::{
    collections::HashSet,
    sync::{atomic::Ordering::Relaxed, Arc},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::metrics::CollectorMetrics;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn env_bool(key: &str) -> bool {
    matches!(
        std::env::var(key).as_deref(),
        Ok("true") | Ok("1") | Ok("yes")
    )
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Exponential back-off: 5 s × 2^(n-1), capped at min(300 s, poll_secs).
fn backoff(consecutive_errors: u32, poll_secs: u64) -> Duration {
    let secs = 5u64
        .saturating_mul(2u64.saturating_pow(consecutive_errors.saturating_sub(1)))
        .min(300)
        .min(poll_secs);
    Duration::from_secs(secs)
}

/// Wait for `dur` or until shutdown fires; returns `true` if shutdown.
async fn sleep_or_shutdown(dur: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(dur) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

// ─── Spawn all enabled cloud sources ─────────────────────────────────────────

/// `shutdown` is a watch receiver; when its value flips to `true` every cloud
/// task exits its poll loop within one poll interval (or backoff sleep).
pub async fn spawn_all(
    client: reqwest::Client,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    metrics: Arc<CollectorMetrics>,
    shutdown: watch::Receiver<bool>,
) {
    if env_bool("COLLECTOR_S3_ENABLED") {
        let (c2, t2, tx2, m2, sd) = (
            client.clone(),
            Arc::clone(&tenant_id),
            tx.clone(),
            Arc::clone(&metrics),
            shutdown.clone(),
        );
        tokio::spawn(async move {
            run_s3(c2, t2, tx2, m2, sd).await;
        });
    }
    if env_bool("COLLECTOR_OKTA_ENABLED") {
        let (c2, t2, tx2, m2, sd) = (
            client.clone(),
            Arc::clone(&tenant_id),
            tx.clone(),
            Arc::clone(&metrics),
            shutdown.clone(),
        );
        tokio::spawn(async move {
            run_okta(c2, t2, tx2, m2, sd).await;
        });
    }
    if env_bool("COLLECTOR_O365_ENABLED") {
        let (c2, t2, tx2, m2, sd) = (
            client.clone(),
            Arc::clone(&tenant_id),
            tx.clone(),
            Arc::clone(&metrics),
            shutdown.clone(),
        );
        tokio::spawn(async move {
            run_o365(c2, t2, tx2, m2, sd).await;
        });
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// S3 SOURCE
// ════════════════════════════════════════════════════════════════════════════════

async fn run_s3(
    client: reqwest::Client,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    metrics: Arc<CollectorMetrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let bucket = env_str("COLLECTOR_S3_BUCKET", "");
    let prefix = env_str("COLLECTOR_S3_PREFIX", "");
    let region = env_str("COLLECTOR_S3_REGION", "us-east-1");
    let access_key = env_str("AWS_ACCESS_KEY_ID", "");
    let secret_key = env_str("AWS_SECRET_ACCESS_KEY", "");
    let poll_secs: u64 = env_str("COLLECTOR_S3_POLL_SECS", "60")
        .parse()
        .unwrap_or(60);
    let max_objects: usize = env_str("COLLECTOR_S3_MAX_OBJECTS_PER_POLL", "100")
        .parse()
        .unwrap_or(100);

    if bucket.is_empty() || access_key.is_empty() {
        error!("S3 source enabled but COLLECTOR_S3_BUCKET or AWS_ACCESS_KEY_ID is not set");
        return;
    }

    info!(
        bucket,
        prefix, region, poll_secs, max_objects, "S3 source started"
    );

    let signer = AwsSigV4::new(&access_key, &secret_key, &region, "s3");
    let mut seen: HashSet<String> = HashSet::new();
    let poll_dur = Duration::from_secs(poll_secs);
    let mut consecutive_errors: u32 = 0;

    loop {
        if sleep_or_shutdown(poll_dur, &mut shutdown).await {
            return;
        }

        match poll_s3(
            &client,
            &signer,
            &bucket,
            &prefix,
            &region,
            &tenant_id,
            &mut seen,
            &tx,
            max_objects,
            &metrics,
        )
        .await
        {
            Ok(n) => {
                consecutive_errors = 0;
                if n > 0 {
                    info!(events = n, "S3: processed new objects");
                }
            }
            Err(e) => {
                consecutive_errors += 1;
                let delay = backoff(consecutive_errors, poll_secs);
                warn!(%e, consecutive_errors, backoff_secs = delay.as_secs(), "S3 poll error — backing off");
                if sleep_or_shutdown(delay, &mut shutdown).await {
                    return;
                }
            }
        }
    }
}

async fn poll_s3(
    client: &reqwest::Client,
    signer: &AwsSigV4,
    bucket: &str,
    prefix: &str,
    region: &str,
    tenant_id: &str,
    seen: &mut HashSet<String>,
    tx: &mpsc::Sender<Value>,
    max_objects: usize,
    metrics: &CollectorMetrics,
) -> Result<usize> {
    let host = format!("{bucket}.s3.{region}.amazonaws.com");
    let mut continuation: Option<String> = None;
    let mut total = 0usize;
    let mut objects_processed = 0usize;

    'outer: loop {
        let mut qs_parts = vec![
            "list-type=2".to_string(),
            format!("prefix={}", url_encode(prefix)),
        ];
        if let Some(ref tok) = continuation {
            qs_parts.push(format!("continuation-token={}", url_encode(tok)));
        }
        qs_parts.sort();
        let qs = qs_parts.join("&");

        let (amz_date, auth) = signer.sign_get(&host, "/", &qs);
        let url = format!("https://{host}/?{qs}");

        let resp_text = client
            .get(&url)
            .header("host", &host)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .header("Authorization", &auth)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        let keys = extract_xml_values(&resp_text, "Key");
        let truncated = extract_xml_value(&resp_text, "IsTruncated") == "true";
        continuation = extract_xml_value_opt(&resp_text, "NextContinuationToken");

        for key in &keys {
            if seen.contains(key.as_str()) {
                continue;
            }
            seen.insert(key.clone());
            objects_processed += 1;

            match download_and_parse_s3(client, signer, &host, region, key, tenant_id).await {
                Ok(events) => {
                    let n = events.len() as u64;
                    total += events.len();
                    for ev in events {
                        if tx.send(ev).await.is_err() {
                            return Ok(total);
                        }
                    }
                    metrics.cloud_received.fetch_add(n, Relaxed);
                }
                Err(err) => warn!(key, %err, "S3: failed to process object"),
            }

            if objects_processed >= max_objects {
                warn!(
                    max_objects,
                    "S3: per-poll object limit reached — deferring remainder to next poll"
                );
                break 'outer;
            }
        }

        if !truncated {
            break;
        }
    }
    Ok(total)
}

async fn download_and_parse_s3(
    client: &reqwest::Client,
    signer: &AwsSigV4,
    host: &str,
    _region: &str,
    key: &str,
    tenant_id: &str,
) -> Result<Vec<Value>> {
    let path = format!("/{}", url_encode(key));
    let (amz_date, auth) = signer.sign_get(host, &path, "");
    let url = format!("https://{host}{path}");

    let bytes = client
        .get(&url)
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .header("Authorization", &auth)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let content = if bytes.starts_with(&[0x1f, 0x8b]) {
        use std::io::Read;
        let mut gz = flate2::read::GzDecoder::new(bytes.as_ref());
        let mut out = String::new();
        gz.read_to_string(&mut out).context("S3 gzip decompress")?;
        out
    } else {
        String::from_utf8_lossy(&bytes).to_string()
    };

    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
        if let Some(records) = parsed.get("Records").and_then(|r| r.as_array()) {
            return Ok(records
                .iter()
                .map(|r| {
                    json!({
                        "tenant_id":  tenant_id,
                        "source":     "s3",
                        "event_time": r.get("eventTime").and_then(|t| t.as_str()).unwrap_or(""),
                        "raw_payload": r,
                    })
                })
                .collect());
        }
    }

    Ok(content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let payload =
                serde_json::from_str::<Value>(line).unwrap_or(Value::String(line.to_string()));
            json!({
                "tenant_id":  tenant_id,
                "source":     "s3",
                "event_time": Utc::now().to_rfc3339(),
                "raw_payload": { "message": payload, "s3_key": key },
            })
        })
        .collect())
}

// ════════════════════════════════════════════════════════════════════════════════
// OKTA SOURCE
// ════════════════════════════════════════════════════════════════════════════════

async fn run_okta(
    client: reqwest::Client,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    metrics: Arc<CollectorMetrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let domain = env_str("COLLECTOR_OKTA_DOMAIN", "");
    let api_token = env_str("COLLECTOR_OKTA_API_TOKEN", "");
    let poll_secs: u64 = env_str("COLLECTOR_OKTA_POLL_SECS", "30")
        .parse()
        .unwrap_or(30);

    if domain.is_empty() || api_token.is_empty() {
        error!(
            "Okta source enabled but COLLECTOR_OKTA_DOMAIN or COLLECTOR_OKTA_API_TOKEN is not set"
        );
        return;
    }

    info!(domain, poll_secs, "Okta System Log source started");

    let poll_dur = Duration::from_secs(poll_secs);
    let mut last_time = Utc::now();
    let mut consecutive_errors: u32 = 0;

    loop {
        if sleep_or_shutdown(poll_dur, &mut shutdown).await {
            return;
        }

        let since = last_time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let url =
            format!("https://{domain}/api/v1/logs?since={since}&limit=1000&sortOrder=ASCENDING");

        match client
            .get(&url)
            .header("Authorization", format!("SSWS {api_token}"))
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => match resp.json::<Vec<Value>>().await {
                Ok(logs) if !logs.is_empty() => {
                    consecutive_errors = 0;
                    info!(count = logs.len(), "Okta: received events");

                    if let Some(last) = logs.last() {
                        if let Some(ts) = last.get("published").and_then(|t| t.as_str()) {
                            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                                last_time =
                                    dt.with_timezone(&Utc) + chrono::Duration::milliseconds(1);
                            }
                        }
                    }

                    let count = logs.len() as u64;
                    for log in logs {
                        let ts = log
                            .get("published")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string();
                        let ev = json!({
                            "tenant_id":  *tenant_id,
                            "source":     "okta",
                            "event_time": ts,
                            "raw_payload": log,
                        });
                        if tx.send(ev).await.is_err() {
                            return;
                        }
                    }
                    metrics.cloud_received.fetch_add(count, Relaxed);
                }
                Ok(_) => {
                    consecutive_errors = 0;
                    debug!("Okta: no new events");
                }
                Err(e) => {
                    consecutive_errors += 1;
                    let delay = backoff(consecutive_errors, poll_secs);
                    warn!(%e, consecutive_errors, backoff_secs = delay.as_secs(), "Okta: JSON parse error — backing off");
                    if sleep_or_shutdown(delay, &mut shutdown).await {
                        return;
                    }
                }
            },
            Ok(resp) => {
                consecutive_errors += 1;
                let delay = backoff(consecutive_errors, poll_secs);
                warn!(status = %resp.status(), consecutive_errors, backoff_secs = delay.as_secs(),
                      "Okta API rejected request — backing off");
                if sleep_or_shutdown(delay, &mut shutdown).await {
                    return;
                }
            }
            Err(err) => {
                consecutive_errors += 1;
                let delay = backoff(consecutive_errors, poll_secs);
                warn!(%err, consecutive_errors, backoff_secs = delay.as_secs(), "Okta: request failed — backing off");
                if sleep_or_shutdown(delay, &mut shutdown).await {
                    return;
                }
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MICROSOFT 365 SOURCE
// ════════════════════════════════════════════════════════════════════════════════

async fn run_o365(
    client: reqwest::Client,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    metrics: Arc<CollectorMetrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let aad_tenant = env_str("COLLECTOR_O365_TENANT_ID", "");
    let client_id = env_str("COLLECTOR_O365_CLIENT_ID", "");
    let client_secret = env_str("COLLECTOR_O365_CLIENT_SECRET", "");
    let content_types = env_str(
        "COLLECTOR_O365_CONTENT_TYPES",
        "Audit.AzureActiveDirectory,Audit.Exchange",
    );
    let poll_secs: u64 = env_str("COLLECTOR_O365_POLL_SECS", "300")
        .parse()
        .unwrap_or(300);

    if aad_tenant.is_empty() || client_id.is_empty() {
        error!("O365 source enabled but required credentials are missing");
        return;
    }

    info!(aad_tenant, poll_secs, "Microsoft 365 source started");

    let types: Vec<String> = content_types
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    let poll_dur = Duration::from_secs(poll_secs);
    let mut consecutive_errors: u32 = 0;

    // Ensure subscriptions are active before entering the poll loop.
    if let Ok(tok) = get_o365_token(&client, &aad_tenant, &client_id, &client_secret).await {
        for ct in &types {
            let _ = ensure_subscription(&client, &tok, &aad_tenant, ct).await;
        }
    }

    loop {
        if sleep_or_shutdown(poll_dur, &mut shutdown).await {
            return;
        }

        let token = match get_o365_token(&client, &aad_tenant, &client_id, &client_secret).await {
            Ok(t) => {
                consecutive_errors = 0;
                t
            }
            Err(e) => {
                consecutive_errors += 1;
                let delay = backoff(consecutive_errors, poll_secs);
                warn!(%e, consecutive_errors, backoff_secs = delay.as_secs(), "O365: token request failed — backing off");
                if sleep_or_shutdown(delay, &mut shutdown).await {
                    return;
                }
                continue;
            }
        };

        let end_time = Utc::now();
        let start_time = end_time - chrono::Duration::seconds(poll_secs as i64 + 60);
        let start_str = start_time.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let end_str = end_time.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let mut any_error = false;
        for ct in &types {
            match fetch_o365_content(
                &client,
                &token,
                &aad_tenant,
                ct,
                &start_str,
                &end_str,
                &tenant_id,
                &tx,
                &metrics,
            )
            .await
            {
                Ok(n) => {
                    if n > 0 {
                        info!(
                            content_type = ct.as_str(),
                            events = n,
                            "O365: received events"
                        );
                    }
                }
                Err(e) => {
                    warn!(content_type = ct.as_str(), %e, "O365: fetch error");
                    any_error = true;
                }
            }
        }

        if any_error {
            consecutive_errors += 1;
            let delay = backoff(consecutive_errors, poll_secs);
            warn!(
                consecutive_errors,
                backoff_secs = delay.as_secs(),
                "O365: partial errors — backing off before next poll"
            );
            if sleep_or_shutdown(delay, &mut shutdown).await {
                return;
            }
        } else {
            consecutive_errors = 0;
        }
    }
}

async fn get_o365_token(
    client: &reqwest::Client,
    tenant: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String> {
    let url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let body = [
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", "https://manage.office.com/.default"),
    ];

    let resp: serde_json::Value = client
        .post(&url)
        .form(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    resp["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .context("O365 token response missing access_token")
}

async fn ensure_subscription(
    client: &reqwest::Client,
    token: &str,
    tenant: &str,
    ct: &str,
) -> Result<()> {
    let url = format!(
        "https://manage.office.com/api/v1.0/{tenant}/activity/feed/subscriptions/start?contentType={ct}"
    );
    client
        .post(&url)
        .bearer_auth(token)
        .json(&json!({"webhook": null}))
        .send()
        .await?;
    Ok(())
}

async fn fetch_o365_content(
    client: &reqwest::Client,
    token: &str,
    aad_tenant: &str,
    ct: &str,
    start: &str,
    end: &str,
    tenant_id: &str,
    tx: &mpsc::Sender<Value>,
    metrics: &CollectorMetrics,
) -> Result<usize> {
    let url = format!(
        "https://manage.office.com/api/v1.0/{aad_tenant}/activity/feed/subscriptions/content\
        ?contentType={ct}&startTime={start}&endTime={end}"
    );

    let blobs: Vec<Value> = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut total = 0usize;
    for blob in &blobs {
        let content_uri = match blob.get("contentUri").and_then(|u| u.as_str()) {
            Some(u) => u.to_string(),
            None => continue,
        };

        let events: Vec<Value> = client
            .get(&content_uri)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let batch_count = events.len() as u64;
        for ev in events {
            let ts = ev
                .get("CreationTime")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let wrapped = json!({
                "tenant_id":  tenant_id,
                "source":     "o365",
                "event_time": ts,
                "raw_payload": ev,
            });
            if tx.send(wrapped).await.is_err() {
                return Ok(total);
            }
            total += 1;
        }
        metrics.cloud_received.fetch_add(batch_count, Relaxed);
    }
    Ok(total)
}

// ════════════════════════════════════════════════════════════════════════════════
// AWS SigV4 signing (minimal: GET requests, UNSIGNED-PAYLOAD)
// ════════════════════════════════════════════════════════════════════════════════

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub struct AwsSigV4 {
    access_key: String,
    secret_key: String,
    region: String,
    service: String,
}

impl AwsSigV4 {
    pub fn new(access_key: &str, secret_key: &str, region: &str, service: &str) -> Self {
        Self {
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            region: region.to_string(),
            service: service.to_string(),
        }
    }

    pub fn sign_get(&self, host: &str, path: &str, query: &str) -> (String, String) {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let payload_hash = "UNSIGNED-PAYLOAD";
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let canonical_hdrs =
            format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");

        let canonical_request =
            format!("GET\n{path}\n{query}\n{canonical_hdrs}\n{signed_headers}\n{payload_hash}");

        let credential_scope =
            format!("{date_stamp}/{}/{}/aws4_request", self.region, self.service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );

        let k_date = hmac256(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac256(&k_date, self.region.as_bytes());
        let k_service = hmac256(&k_region, self.service.as_bytes());
        let k_signing = hmac256(&k_service, b"aws4_request");
        let signature = hex::encode(hmac256(&k_signing, string_to_sign.as_bytes()));

        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope},SignedHeaders={signed_headers},Signature={signature}",
            self.access_key
        );
        (amz_date, auth)
    }
}

fn hmac256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("valid HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn extract_xml_values(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut results = Vec::new();
    let mut pos = 0;
    while let Some(start) = xml[pos..].find(&open) {
        let abs = pos + start + open.len();
        if let Some(end) = xml[abs..].find(&close) {
            results.push(xml[abs..abs + end].to_string());
            pos = abs + end + close.len();
        } else {
            break;
        }
    }
    results
}

fn extract_xml_value(xml: &str, tag: &str) -> String {
    extract_xml_value_opt(xml, tag).unwrap_or_default()
}

fn extract_xml_value_opt(xml: &str, tag: &str) -> Option<String> {
    extract_xml_values(xml, tag).into_iter().next()
}
