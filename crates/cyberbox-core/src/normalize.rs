use chrono::Utc;
use cyberbox_models::{EnrichmentMetadata, EventEnvelope, EventSource, IncomingEvent};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn normalize_to_ocsf(input: &IncomingEvent) -> EventEnvelope {
    let ingest_time = Utc::now();
    let ocsf_record = build_ocsf_record(&input.source, &input.raw_payload, ingest_time);
    let integrity_hash = hash_event(
        &input.tenant_id,
        &input.raw_payload,
        ingest_time.timestamp_millis(),
    );

    EventEnvelope {
        event_id: Uuid::new_v4(),
        tenant_id: input.tenant_id.clone(),
        source: input.source.clone(),
        event_time: input.event_time,
        ingest_time,
        raw_payload: input.raw_payload.clone(),
        ocsf_record,
        enrichment: EnrichmentMetadata::default(),
        integrity_hash,
    }
}

pub fn attach_enrichment(
    mut envelope: EventEnvelope,
    asset_tags: Vec<String>,
    geoip: Option<crate::geoip::GeoIpResult>,
) -> EventEnvelope {
    envelope.enrichment.asset_tags = asset_tags;
    envelope.enrichment.geoip = geoip.map(|g| cyberbox_models::GeoIpContext {
        country: if g.country_name.is_empty() {
            None
        } else {
            Some(g.country_name)
        },
        city: if g.city.is_empty() {
            None
        } else {
            Some(g.city)
        },
        latitude: Some(g.latitude),
        longitude: Some(g.longitude),
    });
    envelope
}

fn build_ocsf_record(
    source: &EventSource,
    raw: &Value,
    ingest_time: chrono::DateTime<Utc>,
) -> Value {
    let class_uid = match source {
        EventSource::WindowsSysmon | EventSource::LinuxAudit | EventSource::LinuxAuth => 1001,
        EventSource::Firewall => 4003,
        EventSource::CloudAudit => 6003,
        _ => 0,
    };

    json!({
        "metadata": {
            "version": "1.0.0",
            "product": {"name": "CyberboxSIEM"},
            "ingest_time": ingest_time,
        },
        "class_uid": class_uid,
        "source_name": format!("{:?}", source),
        "unmapped": raw,
    })
}

fn hash_event(tenant_id: &str, payload: &Value, ingest_ms: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tenant_id.as_bytes());
    hasher.update(payload.to_string().as_bytes());
    hasher.update(ingest_ms.to_be_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use cyberbox_models::{EventSource, IncomingEvent};
    use serde_json::json;

    #[test]
    fn normalize_generates_integrity_hash() {
        let input = IncomingEvent {
            tenant_id: "tenant-a".to_string(),
            source: EventSource::WindowsSysmon,
            raw_payload: json!({"event_code": 1}),
            event_time: Utc::now(),
        };

        let normalized = normalize_to_ocsf(&input);
        assert!(!normalized.integrity_hash.is_empty());
        assert_eq!(normalized.tenant_id, "tenant-a");
    }
}
