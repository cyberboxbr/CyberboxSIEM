//! Sysmon source — Windows only.
//!
//! Subscribes to the `Microsoft-Windows-Sysmon/Operational` event log channel
//! and emits normalized JSON events for every Sysmon EventID.
//!
//! ## EventID mapping
//! | ID | Type                     | Key MITRE technique         |
//! |----|--------------------------|------------------------------|
//! |  1 | ProcessCreate            | T1059 (Execution)            |
//! |  2 | FileCreationTimeChanged  | T1070.006 (Timestomp)        |
//! |  3 | NetworkConnect           | T1071 (C2 over app layer)    |
//! |  5 | ProcessTerminate         | —                            |
//! |  6 | DriverLoad               | T1014 (Rootkit)              |
//! |  7 | ImageLoad                | T1574 (DLL Hijack)           |
//! |  8 | CreateRemoteThread       | T1055 (Process Injection)    |
//! |  9 | RawAccessRead            | T1006 (Direct Volume Access) |
//! | 10 | ProcessAccess            | T1055 (Process Injection)    |
//! | 11 | FileCreate               | T1105 (Ingress Tool Transfer)|
//! | 12 | RegistryEventCreate      | T1547 (Boot Autostart)       |
//! | 13 | RegistryEventValue       | T1547                        |
//! | 14 | RegistryEventRename      | T1547                        |
//! | 15 | FileCreateStreamHash     | T1564.004 (NTFS Streams)     |
//! | 16 | ServiceConfigChange      | T1543 (Create/Modify Service)|
//! | 17 | PipeCreate               | T1559 (IPC)                  |
//! | 18 | PipeConnect              | T1559                        |
//! | 22 | DnsQuery                 | T1071.004 (DNS C2)           |
//! | 23 | FileDelete               | T1070.004 (File Deletion)    |
//! | 25 | ProcessTampering         | T1055                        |
//!
//! Requires Sysmon to be installed and running on the host.
//! Download: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

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

const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(tenant_id: Arc<String>, hostname: Arc<String>, tx: mpsc::Sender<Value>) {
    let tx2 = tx.clone();
    let tid = Arc::clone(&tenant_id);
    let host = Arc::clone(&hostname);

    info!(channel = SYSMON_CHANNEL, "Sysmon source started");
    tokio::task::spawn_blocking(move || subscribe_sysmon(tid, host, tx2));
}

// ── Blocking subscription loop ────────────────────────────────────────────────

fn subscribe_sysmon(tenant_id: Arc<String>, hostname: Arc<String>, tx: mpsc::Sender<Value>) {
    let channel_w: Vec<u16> = SYSMON_CHANNEL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let query_w: Vec<u16> = "*".encode_utf16().chain(std::iter::once(0)).collect();

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
                error!(
                    channel = SYSMON_CHANNEL,
                    error   = %e,
                    "EvtSubscribe failed — is Sysmon installed and running?"
                );
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
                    if let Some(ev) = parse_sysmon_xml(&xml, &tenant_id, &hostname) {
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
                warn!(channel = SYSMON_CHANNEL, error = %e, "EvtNext error");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}

// ── XML rendering (same as wineventlog.rs) ────────────────────────────────────

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

// ── Parse Sysmon XML → normalized event ──────────────────────────────────────

fn parse_sysmon_xml(xml: &str, tenant_id: &str, hostname: &str) -> Option<Value> {
    let event_id_str = xml_value(xml, "EventID")?;
    let event_id: u32 = event_id_str.parse().ok()?;
    let time_created =
        xml_attr(xml, "TimeCreated", "SystemTime").unwrap_or_else(|| Utc::now().to_rfc3339());
    let computer = xml_value(xml, "Computer").unwrap_or_else(|| hostname.to_string());

    // Parse all EventData fields into a flat map
    let mut data = Map::new();
    extract_event_data(xml, &mut data);

    // Derive a human-readable event type + MITRE technique
    let (event_type, mitre_technique) = event_id_meta(event_id);

    // Build a normalized payload with top-level promoted fields
    // for the most security-relevant data so rules can match directly.
    let mut payload = json!({
        "hostname":        computer,
        "event_id":        event_id,
        "event_type":      event_type,
        "channel":         SYSMON_CHANNEL,
        "mitre_technique": mitre_technique,
    });

    // Promote common high-value fields to the top of raw_payload
    promote_fields(&mut payload, &data, event_id);

    // Attach full EventData under "event_data" for rules that need it
    payload["event_data"] = Value::Object(data);

    Some(json!({
        "tenant_id":  tenant_id,
        "source":     "sysmon",
        "event_time": time_created,
        "raw_payload": payload,
    }))
}

/// Promote key Sysmon fields to the top level of raw_payload so Sigma rules
/// can match them with simple `FieldName: value` selectors.
fn promote_fields(payload: &mut Value, data: &Map<String, Value>, event_id: u32) {
    // Fields present across many event types
    for field in &[
        "Image",
        "CommandLine",
        "User",
        "ProcessGuid",
        "ProcessId",
        "ParentImage",
        "ParentCommandLine",
        "ParentProcessGuid",
        "TargetFilename",
        "TargetObject",
        "Details",
        "DestinationIp",
        "DestinationPort",
        "DestinationHostname",
        "Protocol",
        "SourceIp",
        "SourcePort",
        "ImageLoaded",
        "Signature",
        "SignatureStatus",
        "Signed",
        "Hashes",
        "SourceProcessGuid",
        "TargetProcessGuid",
        "StartAddress",
        "StartModule",
        "GrantedAccess",
        "CallTrace",
        "PipeName",
        "QueryName",
        "QueryResults",
    ] {
        if let Some(v) = data.get(*field) {
            payload[*field] = v.clone();
        }
    }

    // Extract just the SHA256 from "sha256=XXXX,md5=YYYY" Hashes field
    if let Some(hashes_str) = data.get("Hashes").and_then(|v| v.as_str()) {
        if let Some(sha256) = extract_hash(hashes_str, "SHA256") {
            payload["sha256"] = Value::String(sha256);
        }
        if let Some(md5) = extract_hash(hashes_str, "MD5") {
            payload["md5"] = Value::String(md5);
        }
    }

    // Event-specific promoted fields
    match event_id {
        1 => {
            // ProcessCreate: promote CurrentDirectory, IntegrityLevel
            for f in &["CurrentDirectory", "IntegrityLevel", "LogonId", "LogonGuid"] {
                if let Some(v) = data.get(*f) {
                    payload[*f] = v.clone();
                }
            }
        }
        3 => {
            // NetworkConnect: promote Initiated (true = outbound)
            if let Some(v) = data.get("Initiated") {
                payload["Initiated"] = v.clone();
            }
        }
        7 => {
            // ImageLoad: promote whether the DLL is signed
            for f in &["SignatureStatus", "Signed", "ImageLoaded"] {
                if let Some(v) = data.get(*f) {
                    payload[*f] = v.clone();
                }
            }
        }
        12..=14 => {
            // Registry events: promote EventType (SetValue, CreateKey, etc.)
            if let Some(v) = data.get("EventType") {
                payload["EventType"] = v.clone();
            }
        }
        _ => {}
    }
}

/// Extract a named hash from Sysmon's `"SHA256=XXXX,MD5=YYYY"` format.
fn extract_hash(hashes: &str, algo: &str) -> Option<String> {
    let prefix = format!("{algo}=");
    let start = hashes.to_uppercase().find(&prefix.to_uppercase())? + prefix.len();
    let end = hashes[start..]
        .find(',')
        .map(|p| start + p)
        .unwrap_or(hashes.len());
    Some(hashes[start..end].to_string())
}

/// Map Sysmon EventID → (event_type_name, mitre_technique_id).
fn event_id_meta(id: u32) -> (&'static str, &'static str) {
    match id {
        1 => ("ProcessCreate", "T1059"),
        2 => ("FileCreationTimeChanged", "T1070.006"),
        3 => ("NetworkConnect", "T1071"),
        4 => ("SysmonServiceStateChange", ""),
        5 => ("ProcessTerminate", ""),
        6 => ("DriverLoad", "T1014"),
        7 => ("ImageLoad", "T1574"),
        8 => ("CreateRemoteThread", "T1055"),
        9 => ("RawAccessRead", "T1006"),
        10 => ("ProcessAccess", "T1055"),
        11 => ("FileCreate", "T1105"),
        12 => ("RegistryEventCreate", "T1547"),
        13 => ("RegistryEventValue", "T1547"),
        14 => ("RegistryEventRename", "T1547"),
        15 => ("FileCreateStreamHash", "T1564.004"),
        16 => ("ServiceConfigChange", "T1543"),
        17 => ("PipeCreate", "T1559"),
        18 => ("PipeConnect", "T1559"),
        19 => ("WmiEventFilter", "T1546.003"),
        20 => ("WmiEventConsumer", "T1546.003"),
        21 => ("WmiEventConsumerToFilter", "T1546.003"),
        22 => ("DnsQuery", "T1071.004"),
        23 => ("FileDelete", "T1070.004"),
        24 => ("ClipboardChange", "T1115"),
        25 => ("ProcessTampering", "T1055"),
        26 => ("FileDeleteDetected", "T1070.004"),
        _ => ("SysmonUnknown", ""),
    }
}

// ── XML helpers (mirrors wineventlog.rs) ─────────────────────────────────────

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
