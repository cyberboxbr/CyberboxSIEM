//! Windows Event Log source — adapted from cyberbox-collector.
//!
//! Subscribes to future events on each configured channel using the EvtXxx API
//! (Vista+).  Each channel runs in its own blocking OS thread.

use std::sync::Arc;

use chrono::Utc;
use serde_json::{json, Map, Value};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use windows::{
    core::PCWSTR,
    Win32::Foundation::{ERROR_NO_MORE_ITEMS, HANDLE},
    Win32::System::EventLog::{
        EvtClose, EvtNext, EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeToFutureEvents,
        EVT_HANDLE,
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
        tokio::task::spawn_blocking(move || subscribe_channel(&ch, tid, host, tx2));
        info!(channel, "Windows Event Log subscription started");
    }
}

// ── Per-channel blocking loop ─────────────────────────────────────────────────

fn subscribe_channel(
    channel: &str,
    tenant_id: Arc<String>,
    hostname: Arc<String>,
    tx: mpsc::Sender<Value>,
) {
    let channel_w: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();
    let query_w: Vec<u16> = "*\0".encode_utf16().collect();

    let subscription = unsafe {
        match EvtSubscribe(
            EVT_HANDLE::default(),
            HANDLE::default(),
            PCWSTR(channel_w.as_ptr()),
            PCWSTR(query_w.as_ptr()),
            EVT_HANDLE::default(),
            None,
            None,
            EvtSubscribeToFutureEvents.0,
        ) {
            Ok(h) => h,
            Err(e) => {
                error!(channel, error = %e, "EvtSubscribe failed");
                return;
            }
        }
    };

    let mut event_raw = [0isize; 64];
    loop {
        let mut returned = 0u32;
        let result = unsafe { EvtNext(subscription, &mut event_raw, 500, 0, &mut returned) };

        if returned > 0 {
            for raw_handle in event_raw.iter().take(returned as usize) {
                let h = EVT_HANDLE(*raw_handle);
                if let Some(xml) = render_to_xml(h) {
                    if let Some(ev) = parse_event_xml(&xml, channel, &tenant_id, &hostname) {
                        if tx.blocking_send(ev).is_err() {
                            unsafe {
                                let _ = EvtClose(subscription);
                            }
                            return;
                        }
                    }
                }
                unsafe {
                    let _ = EvtClose(h);
                }
            }
        } else if let Err(e) = result {
            let code = e.code().0 as u32;
            if code != ERROR_NO_MORE_ITEMS.0 {
                warn!(channel, error = %e, "EvtNext error");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
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

fn parse_event_xml(xml: &str, channel: &str, tenant_id: &str, hostname: &str) -> Option<Value> {
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
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close).map(|p| start + p)?;
    Some(xml[start..end].to_string())
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
