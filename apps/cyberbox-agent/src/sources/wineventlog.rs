//! Windows Event Log source — polling mode using EvtQuery.
//!
//! Polls each channel every few seconds for new events using XPath record-id filters.
//! Simple and reliable across all Windows Server versions.

use std::sync::Arc;

use chrono::Utc;
use serde_json::{json, Map, Value};
use tokio::sync::mpsc;
use tracing::{info, warn};

use windows::{
    core::PCWSTR,
    Win32::Foundation::ERROR_NO_MORE_ITEMS,
    Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
        EvtRenderEventXml, EVT_HANDLE,
    },
};

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(
    channels: Vec<String>,
    tenant_id: Arc<String>,
    hostname: Arc<String>,
    tx: mpsc::Sender<Value>,
) {
    for channel in channels {
        let tx2 = tx.clone();
        let tid = Arc::clone(&tenant_id);
        let host = Arc::clone(&hostname);
        let ch = channel.clone();
        tokio::task::spawn_blocking(move || poll_channel(&ch, tid, host, tx2));
        info!(channel, "Windows Event Log polling started");
    }
}

// ── Per-channel polling loop ─────────────────────────────────────────────────

fn poll_channel(
    channel: &str,
    tenant_id: Arc<String>,
    hostname: Arc<String>,
    tx: mpsc::Sender<Value>,
) {
    let channel_w: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();
    let mut last_record_id = latest_record_id(channel, &channel_w).unwrap_or(0);
    info!(channel, last_record_id, "polling from latest record id");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(2));

        let query = build_event_record_query(last_record_id);
        info!(channel, query = %query, "polling");

        let query_w: Vec<u16> = query.encode_utf16().chain(std::iter::once(0)).collect();

        let result_set = unsafe {
            EvtQuery(
                EVT_HANDLE::default(),
                PCWSTR(channel_w.as_ptr()),
                PCWSTR(query_w.as_ptr()),
                EvtQueryChannelPath.0,
            )
        };

        let result_set = match result_set {
            Ok(h) => h,
            Err(e) => {
                warn!(channel, error = %e, query = %query, "EvtQuery failed");
                continue;
            }
        };

        let mut events = [0isize; 64];
        let mut total = 0u32;
        let mut max_record_id = last_record_id;

        loop {
            let mut returned = 0u32;
            let res = unsafe { EvtNext(result_set, &mut events, 1000, 0, &mut returned) };

            info!(channel, returned, ok = res.is_ok(), "EvtNext result");

            if returned == 0 {
                if let Err(e) = res {
                    let code = e.code().0 as u32;
                    if code != ERROR_NO_MORE_ITEMS.0 {
                        warn!(channel, error = %e, code = format!("0x{:08X}", code), "EvtNext error");
                    }
                }
                break;
            }

            for raw in events.iter().take(returned as usize) {
                let h = EVT_HANDLE(*raw);
                let xml = render_to_xml(h);
                if xml.is_none() {
                    warn!(channel, "render_to_xml returned None");
                }
                if let Some(xml) = xml {
                    info!(channel, xml_len = xml.len(), "rendered event XML");
                    let record_id = extract_event_record_id(&xml);
                    if let Some(record_id) = record_id {
                        max_record_id = max_record_id.max(record_id);
                    }
                    let ev = parse_event_xml(&xml, channel, &tenant_id, &hostname, record_id);
                    if ev.is_none() {
                        warn!(
                            channel,
                            xml = &xml[..xml.len().min(200)],
                            "parse_event_xml returned None"
                        );
                    }
                    if let Some(ev) = ev {
                        total += 1;
                        if tx.blocking_send(ev).is_err() {
                            unsafe {
                                let _ = EvtClose(h);
                                let _ = EvtClose(result_set);
                            }
                            return;
                        }
                    }
                }
                unsafe {
                    let _ = EvtClose(h);
                }
            }
        }

        unsafe {
            let _ = EvtClose(result_set);
        }

        if total > 0 {
            info!(channel, events = total, "forwarded events");
        }
        last_record_id = max_record_id;
    }
}

// ── Render XML ────────────────────────────────────────────────────────────────

fn render_to_xml(event: EVT_HANDLE) -> Option<String> {
    let mut buf_used = 0u32;
    let mut prop_count = 0u32;
    let _ = unsafe {
        EvtRender(
            EVT_HANDLE::default(),
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut buf_used,
            &mut prop_count,
        )
    };
    if buf_used == 0 {
        return None;
    }

    let cap = (buf_used as usize / 2) + 1;
    let mut buf: Vec<u16> = vec![0u16; cap];
    let ok = unsafe {
        EvtRender(
            EVT_HANDLE::default(),
            event,
            EvtRenderEventXml.0,
            buf_used,
            Some(buf.as_mut_ptr() as *mut _),
            &mut buf_used,
            &mut prop_count,
        )
    };
    if ok.is_err() {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16(&buf[..len]).ok()
}

// ── XML → event ───────────────────────────────────────────────────────────────

fn parse_event_xml(
    xml: &str,
    channel: &str,
    tenant_id: &str,
    hostname: &str,
    record_id: Option<u64>,
) -> Option<Value> {
    let event_id = xml_value(xml, "EventID")?;
    let time_created =
        xml_attr(xml, "TimeCreated", "SystemTime").unwrap_or_else(|| Utc::now().to_rfc3339());
    let computer = xml_value(xml, "Computer").unwrap_or_else(|| hostname.to_string());
    let level = xml_value(xml, "Level").unwrap_or_else(|| "4".into());
    let provider = xml_attr(xml, "Provider", "Name").unwrap_or_default();
    let severity = level_to_severity(&level);

    let mut event_data = Map::new();
    extract_event_data(xml, &mut event_data);

    Some(json!({
        "tenant_id":  tenant_id,
        "source":     "wineventlog",
        "event_time": time_created,
        "raw_payload": {
            "hostname":      computer,
            "event_id":      event_id,
            "record_id":     record_id,
            "channel":       channel,
            "provider":      provider,
            "level":         level,
            "severity":      severity,
            "severity_name": severity_name(severity),
            "event_data":    Value::Object(event_data),
        }
    }))
}

fn xml_value(xml: &str, tag: &str) -> Option<String> {
    // Find opening tag — may have attributes: <EventID Qualifiers='0'>
    let tag_start = xml.find(&format!("<{tag}"))?;
    let after_tag = &xml[tag_start..];
    let gt = after_tag.find('>')?;
    let value_start = tag_start + gt + 1;
    let close = format!("</{tag}>");
    let end = xml[value_start..].find(&close).map(|p| value_start + p)?;
    Some(xml[value_start..end].to_string())
}

fn xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_open = xml.find(&format!("<{tag}"))?;
    let tag_end = xml[tag_open..].find('>')? + tag_open;
    let tag_slice = &xml[tag_open..tag_end];
    let attr_eq = tag_slice.find(&format!("{attr}="))?;
    let val_off = attr_eq + attr.len() + 1;
    let quote = tag_slice.as_bytes().get(val_off)?;
    let val_start = val_off + 1;
    let end_char = *quote as char;
    let val_end = tag_slice[val_start..].find(end_char)?;
    Some(tag_slice[val_start..val_start + val_end].to_string())
}

fn extract_event_record_id(xml: &str) -> Option<u64> {
    xml_value(xml, "EventRecordID")?.parse().ok()
}

fn build_event_record_query(last_record_id: u64) -> String {
    format!("*[System[EventRecordID > {last_record_id}]]")
}

fn latest_record_id(channel: &str, channel_w: &[u16]) -> Option<u64> {
    let query_w: Vec<u16> = "*".encode_utf16().chain(std::iter::once(0)).collect();
    let result_set = unsafe {
        EvtQuery(
            EVT_HANDLE::default(),
            PCWSTR(channel_w.as_ptr()),
            PCWSTR(query_w.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
    };

    let result_set = match result_set {
        Ok(handle) => handle,
        Err(err) => {
            warn!(channel, error = %err, "failed to query latest event record id");
            return None;
        }
    };

    let mut events = [0isize; 1];
    let mut returned = 0u32;
    let next_result = unsafe { EvtNext(result_set, &mut events, 0, 0, &mut returned) };

    let latest = if returned == 0 {
        if let Err(err) = next_result {
            let code = err.code().0 as u32;
            if code != ERROR_NO_MORE_ITEMS.0 {
                warn!(
                    channel,
                    error = %err,
                    code = format!("0x{:08X}", code),
                    "failed to fetch latest event record id"
                );
            }
        }
        Some(0)
    } else {
        let event = EVT_HANDLE(events[0]);
        let xml = render_to_xml(event);
        unsafe {
            let _ = EvtClose(event);
        }
        xml.as_deref().and_then(extract_event_record_id)
    };

    unsafe {
        let _ = EvtClose(result_set);
    }

    latest
}

fn extract_event_data(xml: &str, map: &mut Map<String, Value>) {
    let mut pos = 0;
    while let Some(rel) = xml[pos..].find("<Data Name=") {
        let abs = pos + rel;
        let name_start = abs + "<Data Name=".len() + 1;
        let q_char = xml
            .as_bytes()
            .get(abs + "<Data Name=".len())
            .copied()
            .unwrap_or(b'\'') as char;
        if let Some(name_end) = xml[name_start..].find(q_char) {
            let name = xml[name_start..name_start + name_end].to_string();
            if let Some(gt) = xml[abs..].find('>') {
                let val_start = abs + gt + 1;
                if let Some(close) = xml[val_start..].find("</Data>") {
                    if !name.is_empty() {
                        map.insert(
                            name,
                            Value::String(xml[val_start..val_start + close].to_string()),
                        );
                    }
                }
            }
        }
        pos = abs + 1;
    }
}

fn level_to_severity(level: &str) -> u8 {
    match level {
        "1" => 2,
        "2" => 3,
        "3" => 4,
        "4" => 6,
        "5" => 7,
        _ => 6,
    }
}

fn severity_name(s: u8) -> &'static str {
    match s {
        0 => "emergency",
        1 => "alert",
        2 => "critical",
        3 => "error",
        4 => "warning",
        5 => "notice",
        6 => "info",
        7 => "debug",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{build_event_record_query, extract_event_record_id};

    #[test]
    fn record_query_uses_strict_greater_than_cursor() {
        assert_eq!(
            build_event_record_query(42),
            "*[System[EventRecordID > 42]]"
        );
    }

    #[test]
    fn extract_event_record_id_parses_xml_value() {
        let xml = r#"
            <Event>
              <System>
                <Provider Name="Microsoft-Windows-Security-Auditing" />
                <EventID>4624</EventID>
                <EventRecordID>123456</EventRecordID>
              </System>
            </Event>
        "#;

        assert_eq!(extract_event_record_id(xml), Some(123456));
    }
}
