//! On-demand IOC enrichment via VirusTotal and AbuseIPDB.

use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    pub indicator: String,
    pub indicator_type: String, // "ip", "domain", "hash"
    pub abuseipdb: Option<AbuseIpDbResult>,
    pub virustotal: Option<VirusTotalResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseIpDbResult {
    pub abuse_confidence_score: u32,
    pub country_code: String,
    pub isp: String,
    pub domain: String,
    pub total_reports: u32,
    pub last_reported_at: Option<String>,
    pub is_whitelisted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalResult {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub reputation: i64,
    pub tags: Vec<String>,
    pub last_analysis_date: Option<String>,
}

fn detect_indicator_type(indicator: &str) -> &'static str {
    let trimmed = indicator.trim();
    // Check if it looks like an IP (v4)
    if trimmed.split('.').count() == 4 && trimmed.split('.').all(|p| p.parse::<u8>().is_ok()) {
        return "ip";
    }
    // Check if it looks like a hash (32, 40, 64 hex chars)
    if (trimmed.len() == 32 || trimmed.len() == 40 || trimmed.len() == 64)
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        return "hash";
    }
    // Check if it contains dots (domain)
    if trimmed.contains('.') && !trimmed.contains('/') {
        return "domain";
    }
    "unknown"
}

pub async fn enrich_ioc(
    indicator: &str,
    abuseipdb_key: Option<&str>,
    virustotal_key: Option<&str>,
    client: &reqwest::Client,
) -> EnrichmentResult {
    let indicator_type = detect_indicator_type(indicator);

    let (abuse_result, vt_result) = tokio::join!(
        query_abuseipdb(indicator, indicator_type, abuseipdb_key, client),
        query_virustotal(indicator, indicator_type, virustotal_key, client),
    );

    EnrichmentResult {
        indicator: indicator.to_string(),
        indicator_type: indicator_type.to_string(),
        abuseipdb: abuse_result,
        virustotal: vt_result,
    }
}

async fn query_abuseipdb(
    indicator: &str,
    indicator_type: &str,
    api_key: Option<&str>,
    client: &reqwest::Client,
) -> Option<AbuseIpDbResult> {
    let key = api_key?;
    // AbuseIPDB only supports IP lookups
    if indicator_type != "ip" {
        return None;
    }

    let response = client
        .get("https://api.abuseipdb.com/api/v2/check")
        .header("Key", key)
        .header("Accept", "application/json")
        .query(&[("ipAddress", indicator), ("maxAgeInDays", "90")])
        .send()
        .await;

    match response {
        Ok(resp) => {
            if !resp.status().is_success() {
                warn!(indicator, status = %resp.status(), "AbuseIPDB query failed");
                return None;
            }
            let body: serde_json::Value = resp.json().await.ok()?;
            let data = body.get("data")?;
            Some(AbuseIpDbResult {
                abuse_confidence_score: data.get("abuseConfidenceScore")?.as_u64()? as u32,
                country_code: data
                    .get("countryCode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                isp: data
                    .get("isp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                domain: data
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                total_reports: data
                    .get("totalReports")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                last_reported_at: data
                    .get("lastReportedAt")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                is_whitelisted: data
                    .get("isWhitelisted")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            })
        }
        Err(err) => {
            warn!(indicator, error = %err, "AbuseIPDB request failed");
            None
        }
    }
}

async fn query_virustotal(
    indicator: &str,
    indicator_type: &str,
    api_key: Option<&str>,
    client: &reqwest::Client,
) -> Option<VirusTotalResult> {
    let key = api_key?;

    let url = match indicator_type {
        "ip" => format!(
            "https://www.virustotal.com/api/v3/ip_addresses/{}",
            indicator
        ),
        "domain" => format!("https://www.virustotal.com/api/v3/domains/{}", indicator),
        "hash" => format!("https://www.virustotal.com/api/v3/files/{}", indicator),
        _ => return None,
    };

    let response = client
        .get(&url)
        .header("x-apikey", key)
        .header("Accept", "application/json")
        .send()
        .await;

    match response {
        Ok(resp) => {
            if !resp.status().is_success() {
                warn!(indicator, status = %resp.status(), "VirusTotal query failed");
                return None;
            }
            let body: serde_json::Value = resp.json().await.ok()?;
            let attrs = body.get("data")?.get("attributes")?;
            let stats = attrs.get("last_analysis_stats")?;
            Some(VirusTotalResult {
                malicious: stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                suspicious: stats
                    .get("suspicious")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                harmless: stats.get("harmless").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                undetected: stats
                    .get("undetected")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                reputation: attrs
                    .get("reputation")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0),
                tags: attrs
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                last_analysis_date: attrs
                    .get("last_analysis_date")
                    .and_then(|v| v.as_i64())
                    .map(|ts| {
                        chrono::DateTime::from_timestamp(ts, 0)
                            .map(|dt| dt.to_rfc3339())
                            .unwrap_or_default()
                    }),
            })
        }
        Err(err) => {
            warn!(indicator, error = %err, "VirusTotal request failed");
            None
        }
    }
}

/// Download the AbuseIPDB blacklist and return a list of malicious IPs.
pub async fn fetch_abuseipdb_blacklist(
    api_key: &str,
    confidence_minimum: u32,
    limit: u32,
    client: &reqwest::Client,
) -> anyhow::Result<Vec<String>> {
    let response = client
        .get("https://api.abuseipdb.com/api/v2/blacklist")
        .header("Key", api_key)
        .header("Accept", "application/json")
        .query(&[
            ("confidenceMinimum", confidence_minimum.to_string()),
            ("limit", limit.to_string()),
        ])
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("AbuseIPDB blacklist request failed: {}", response.status());
    }

    let body: serde_json::Value = response.json().await?;
    let ips = body
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    item.get("ipAddress")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(ips)
}
