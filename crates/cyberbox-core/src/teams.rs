use serde_json::json;

use cyberbox_models::AlertRecord;

use crate::{AppConfig, CyberboxError};

#[derive(Clone)]
pub struct TeamsNotifier {
    client: reqwest::Client,
    enabled: bool,
    webhook_url: Option<String>,
}

impl TeamsNotifier {
    pub fn from_config(config: &AppConfig) -> Self {
        let webhook_url = normalize_webhook_url(&config.teams_webhook_url);
        Self {
            client: reqwest::Client::new(),
            enabled: config.teams_routing_enabled,
            webhook_url,
        }
    }

    pub async fn send_alert(&self, alert: &AlertRecord) -> Result<(), CyberboxError> {
        if !self.enabled {
            return Ok(());
        }

        let webhook_url = match &self.webhook_url {
            Some(url) => url,
            None => {
                tracing::warn!("teams routing enabled but teams_webhook_url is empty");
                return Ok(());
            }
        };

        let payload = json!({
            "text": format!(
                "CyberboxSIEM alert: id={} tenant={} rule={} status={} routing={}",
                alert.alert_id,
                alert.tenant_id,
                alert.rule_id,
                alert_status_to_str(alert),
                alert.routing_state.destinations.join(",")
            )
        });

        let response = self
            .client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|err| {
                CyberboxError::Internal(format!("teams webhook request failed: {err}"))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<response body unavailable>".to_string());
            return Err(CyberboxError::Internal(format!(
                "teams webhook failed (status {}): {}",
                status, body
            )));
        }

        Ok(())
    }

    /// Send a periodic digest (scheduled report) to the Teams channel.
    ///
    /// Summarises alert and case counts across all tenants for the given period.
    pub async fn send_digest(
        &self,
        period_label: &str,
        open_alerts: usize,
        total_alerts: usize,
        open_cases: usize,
        sla_breaches: usize,
    ) -> Result<(), CyberboxError> {
        if !self.enabled {
            return Ok(());
        }
        let webhook_url = match &self.webhook_url {
            Some(url) => url,
            None => return Ok(()),
        };

        let payload = json!({
            "text": format!(
                "📊 CyberboxSIEM Scheduled Report ({period_label})\n\
                • Open alerts:   {open_alerts} / {total_alerts} total\n\
                • Open cases:    {open_cases}\n\
                • SLA breaches:  {sla_breaches}",
            )
        });

        let response = self
            .client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|err| CyberboxError::Internal(format!("teams digest failed: {err}")))?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(CyberboxError::Internal(format!(
                "teams digest HTTP error: {body}"
            )));
        }
        Ok(())
    }
}

fn alert_status_to_str(alert: &AlertRecord) -> &'static str {
    match alert.status {
        cyberbox_models::AlertStatus::Open => "open",
        cyberbox_models::AlertStatus::Acknowledged => "acknowledged",
        cyberbox_models::AlertStatus::InProgress => "in_progress",
        cyberbox_models::AlertStatus::Closed => "closed",
    }
}

fn normalize_webhook_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::normalize_webhook_url;

    #[test]
    fn normalize_webhook_url_strips_empty_values() {
        assert!(normalize_webhook_url("").is_none());
        assert!(normalize_webhook_url("   ").is_none());
        assert_eq!(
            normalize_webhook_url(" https://example.test/hook "),
            Some("https://example.test/hook".to_string())
        );
    }
}
