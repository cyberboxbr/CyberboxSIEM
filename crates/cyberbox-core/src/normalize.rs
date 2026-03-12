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

    let mut record = json!({
        "metadata": {
            "version": "1.0.0",
            "product": {"name": "CyberboxSIEM"},
            "ingest_time": ingest_time,
        },
        "class_uid": class_uid,
        "source_name": format!("{:?}", source),
        "unmapped": raw,
    });

    // Derive event_type from Sysmon EventID so bundled Sigma rules can match
    // on human-readable event type names (ProcessCreate, DnsQuery, etc.).
    // Set at BOTH locations so the detection engine finds it regardless of
    // how the Sigma rule references the field:
    //   - Top-level `event_type`: found by direct ocsf_record field lookup
    //     (for rules using `event_type:` — note: underscore differs from `EventType`)
    //   - `metadata.event_type`: found via SIGMA_TO_OCSF mapping for `EventType`
    if matches!(source, EventSource::WindowsSysmon) {
        if let Some(event_type) = sysmon_event_type(raw) {
            let val = Value::String(event_type.to_string());
            record["event_type"] = val.clone();
            record["metadata"]["event_type"] = val;
        }
    }

    record
}

/// Map Sysmon numeric EventID to the canonical event-type string used in Sigma rules.
fn sysmon_event_type(raw: &Value) -> Option<&'static str> {
    let eid = raw
        .get("EventID")
        .or_else(|| raw.get("eventid"))
        .or_else(|| raw.get("event_id"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })?;
    Some(match eid {
        1 => "ProcessCreate",
        2 => "FileCreateTime",
        3 => "NetworkConnect",
        4 => "SysmonServiceStateChanged",
        5 => "ProcessTerminate",
        6 => "DriverLoad",
        7 => "ImageLoad",
        8 => "CreateRemoteThread",
        9 => "RawAccessRead",
        10 => "ProcessAccess",
        11 => "FileCreate",
        12 => "RegistryEventCreate",
        13 => "RegistryEventValue",
        14 => "RegistryEventRename",
        15 => "FileCreateStreamHash",
        17 => "PipeCreate",
        18 => "PipeConnect",
        19 => "WmiEventFilter",
        20 => "WmiEventConsumer",
        21 => "WmiEventConsumerToFilter",
        22 => "DnsQuery",
        23 => "FileDelete",
        24 => "ClipboardChange",
        25 => "ProcessTampering",
        26 => "FileDeleteDetected",
        27 => "FileBlockExecutable",
        28 => "FileBlockShredding",
        29 => "FileExecutableDetected",
        4624 | 4625 => "LogonEvent",
        4688 => "ProcessCreate",
        4720 => "UserAccountCreated",
        4732 => "GroupMemberAdded",
        7045 => "ServiceInstalled",
        _ => return None,
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

    #[test]
    fn sysmon_event_type_injected_into_ocsf() {
        let input = IncomingEvent {
            tenant_id: "t".to_string(),
            source: EventSource::WindowsSysmon,
            raw_payload: json!({"EventID": 1, "Image": "cmd.exe"}),
            event_time: Utc::now(),
        };
        let env = normalize_to_ocsf(&input);
        assert_eq!(env.ocsf_record["event_type"], "ProcessCreate");
        assert_eq!(env.ocsf_record["metadata"]["event_type"], "ProcessCreate");
    }

    #[test]
    fn sysmon_event_type_not_set_for_unknown_id() {
        let input = IncomingEvent {
            tenant_id: "t".to_string(),
            source: EventSource::WindowsSysmon,
            raw_payload: json!({"EventID": 9999}),
            event_time: Utc::now(),
        };
        let env = normalize_to_ocsf(&input);
        assert!(env.ocsf_record["metadata"].get("event_type").is_none());
    }

    #[test]
    fn non_sysmon_source_no_event_type() {
        let input = IncomingEvent {
            tenant_id: "t".to_string(),
            source: EventSource::Syslog,
            raw_payload: json!({"EventID": 1}),
            event_time: Utc::now(),
        };
        let env = normalize_to_ocsf(&input);
        assert!(env.ocsf_record["metadata"].get("event_type").is_none());
    }
}
