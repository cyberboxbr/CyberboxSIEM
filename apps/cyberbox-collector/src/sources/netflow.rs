//! NetFlow v5 / v9 / IPFIX (v10) collector — UDP listener.
//!
//! ## Protocol support
//! | Version | Status  | Notes |
//! |---------|---------|-------|
//! | v5      | Full    | Fixed 48-byte records; no templates |
//! | v9      | Full    | Template caching per (source_id, template_id) |
//! | v10 (IPFIX) | Full | Same template model as v9 with enterprise fields |
//!
//! Default bind port: `0.0.0.0:2055` (`COLLECTOR_NETFLOW_BIND`)

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use tokio::{net::UdpSocket, sync::mpsc};
use tracing::{debug, error, info};

use crate::metrics::CollectorMetrics;

// ─── Entry point ──────────────────────────────────────────────────────────────

pub async fn run(
    bind:      SocketAddr,
    tenant_id: Arc<String>,
    tx:        mpsc::Sender<Value>,
    metrics:   Arc<CollectorMetrics>,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;

    let sock = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("bind NetFlow UDP {bind}"))?;
    info!(%bind, "NetFlow/IPFIX listener ready (v5 + v9 + v10)");

    // Template cache: (source_id, template_id) → Vec<(field_type, field_len)>
    let mut templates: HashMap<(u32, u16), Vec<(u16, u16)>> = HashMap::new();

    let mut buf = vec![0u8; 65_535];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let data      = &buf[..len];
                let source_ip = peer.ip().to_string();
                let events    = parse_packet(data, &source_ip, &tenant_id, &mut templates);
                let n         = events.len() as u64;
                for ev in events {
                    if tx.send(ev).await.is_err() { return Ok(()); }
                }
                if n > 0 { metrics.netflow_received.fetch_add(n, Relaxed); }
            }
            Err(err) => error!(%err, "NetFlow recv_from error"),
        }
    }
}

// ─── Packet dispatch ──────────────────────────────────────────────────────────

fn parse_packet(
    data:      &[u8],
    source_ip: &str,
    tenant_id: &str,
    templates: &mut HashMap<(u32, u16), Vec<(u16, u16)>>,
) -> Vec<Value> {
    if data.len() < 2 { return vec![]; }
    let version = u16::from_be_bytes([data[0], data[1]]);
    match version {
        5  => parse_v5(data, source_ip, tenant_id),
        9  => parse_v9_ipfix(data, source_ip, tenant_id, templates, 9),
        10 => parse_v9_ipfix(data, source_ip, tenant_id, templates, 10),
        v  => { debug!(version = v, "unknown NetFlow version — skipping"); vec![] }
    }
}

// ─── NetFlow v5 ───────────────────────────────────────────────────────────────

fn parse_v5(data: &[u8], source_ip: &str, tenant_id: &str) -> Vec<Value> {
    if data.len() < 24 { return vec![]; }

    let count     = u16::from_be_bytes([data[2], data[3]]) as usize;
    let unix_secs = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let export_ts = chrono::DateTime::from_timestamp(unix_secs as i64, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let mut events = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 24 + i * 48;
        if offset + 48 > data.len() { break; }
        let rec = &data[offset..offset + 48];

        let src_addr = Ipv4Addr::new(rec[0], rec[1], rec[2], rec[3]).to_string();
        let dst_addr = Ipv4Addr::new(rec[4], rec[5], rec[6], rec[7]).to_string();
        let nexthop  = Ipv4Addr::new(rec[8], rec[9], rec[10], rec[11]).to_string();
        let pkts     = u32::from_be_bytes([rec[16], rec[17], rec[18], rec[19]]);
        let bytes    = u32::from_be_bytes([rec[20], rec[21], rec[22], rec[23]]);
        let src_port = u16::from_be_bytes([rec[32], rec[33]]);
        let dst_port = u16::from_be_bytes([rec[34], rec[35]]);
        let protocol = rec[38];
        let tcp_flags = rec[37];
        let src_as   = u16::from_be_bytes([rec[40], rec[41]]);
        let dst_as   = u16::from_be_bytes([rec[42], rec[43]]);

        events.push(json!({
            "tenant_id":  tenant_id,
            "source":     "netflow",
            "event_time": export_ts,
            "raw_payload": {
                "netflow_version": 5,
                "exporter_ip":     source_ip,
                "src_ip":          src_addr,
                "dst_ip":          dst_addr,
                "nexthop":         nexthop,
                "src_port":        src_port,
                "dst_port":        dst_port,
                "protocol":        protocol,
                "protocol_name":   proto_name(protocol),
                "tcp_flags":       tcp_flags,
                "packets":         pkts,
                "bytes":           bytes,
                "src_as":          src_as,
                "dst_as":          dst_as,
                "severity":        6,
                "severity_name":   "info",
            }
        }));
    }
    events
}

// ─── NetFlow v9 / IPFIX (v10) ─────────────────────────────────────────────────

fn parse_v9_ipfix(
    data:      &[u8],
    source_ip: &str,
    tenant_id: &str,
    templates: &mut HashMap<(u32, u16), Vec<(u16, u16)>>,
    version:   u16,
) -> Vec<Value> {
    if data.len() < 20 { return vec![]; }

    // v9  header: version(2) count(2) uptime(4) unix_secs(4) seq(4) source_id(4) = 20 bytes
    // v10 header: version(2) length(2) export_time(4) seq(4) obs_domain_id(4) = 16 bytes
    let (source_id, unix_secs, hdr_len) = if version == 9 {
        let src = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let ts  = u32::from_be_bytes([data[8],  data[9],  data[10], data[11]]);
        (src, ts, 20usize)
    } else {
        let src = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let ts  = u32::from_be_bytes([data[4],  data[5],  data[6],  data[7]]);
        (src, ts, 16usize)
    };

    let export_ts = chrono::DateTime::from_timestamp(unix_secs as i64, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let mut events = Vec::new();
    let mut pos    = hdr_len;

    while pos + 4 <= data.len() {
        let set_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let set_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if set_len < 4 || pos + set_len > data.len() { break; }

        let set_data = &data[pos + 4..pos + set_len];

        match set_id {
            // Template FlowSet (v9=0, IPFIX=2)
            0 | 2 => parse_template_set(set_data, source_id, templates),
            // Options Template FlowSet — skip for now
            1 | 3 => {}
            // Data FlowSet (template_id ≥ 256)
            id if id >= 256 => {
                let template_id = id;
                let evs = parse_data_set(
                    set_data, source_ip, tenant_id, &export_ts,
                    source_id, template_id, version, templates,
                );
                events.extend(evs);
            }
            _ => {}
        }
        pos += set_len;
    }
    events
}

fn parse_template_set(
    data:      &[u8],
    source_id: u32,
    templates: &mut HashMap<(u32, u16), Vec<(u16, u16)>>,
) {
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let template_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let field_count = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + field_count * 4 > data.len() { break; }

        let mut fields = Vec::with_capacity(field_count);
        for _ in 0..field_count {
            let ftype = u16::from_be_bytes([data[pos],     data[pos + 1]]) & 0x7FFF; // mask enterprise bit
            let flen  = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            fields.push((ftype, flen));
            pos += 4;
        }

        templates.insert((source_id, template_id), fields);
        debug!(source_id, template_id, fields = field_count, "NetFlow template registered");
    }
}

fn parse_data_set(
    data:        &[u8],
    source_ip:   &str,
    tenant_id:   &str,
    export_ts:   &str,
    source_id:   u32,
    template_id: u16,
    version:     u16,
    templates:   &HashMap<(u32, u16), Vec<(u16, u16)>>,
) -> Vec<Value> {
    let fields = match templates.get(&(source_id, template_id)) {
        Some(f) => f,
        None    => { debug!(source_id, template_id, "unknown NetFlow template — dropping"); return vec![]; }
    };

    // Calculate record size
    let record_size: usize = fields.iter().map(|(_, l)| *l as usize).sum();
    if record_size == 0 { return vec![]; }

    let mut events = Vec::new();
    let mut pos    = 0;

    while pos + record_size <= data.len() {
        let rec = &data[pos..pos + record_size];
        let mut map = serde_json::Map::new();
        let mut fpos = 0usize;

        for &(ftype, flen) in fields {
            if fpos + flen as usize > rec.len() { break; }
            let field_data = &rec[fpos..fpos + flen as usize];
            if let Some((key, val)) = decode_field(ftype, flen, field_data) {
                map.insert(key, val);
            }
            fpos += flen as usize;
        }

        map.insert("netflow_version".into(), Value::Number(version.into()));
        map.insert("exporter_ip".into(),     Value::String(source_ip.to_string()));
        map.insert("template_id".into(),     Value::Number(template_id.into()));
        map.insert("severity".into(),        Value::Number(6u8.into()));
        map.insert("severity_name".into(),   Value::String("info".into()));

        events.push(json!({
            "tenant_id":  tenant_id,
            "source":     "netflow",
            "event_time": export_ts,
            "raw_payload": Value::Object(map),
        }));
        pos += record_size;
        // Padding: IPFIX data sets may be padded to 4-byte boundaries
        if pos % 4 != 0 { pos += 4 - (pos % 4); }
    }
    events
}

/// Decode a single NetFlow/IPFIX field into a (key, JSON value) pair.
fn decode_field(ftype: u16, flen: u16, data: &[u8]) -> Option<(String, Value)> {
    let (key, val): (&str, Value) = match (ftype, flen) {
        // Common v9/IPFIX fields
        (1,  4) => ("in_bytes",      Value::Number(read_u32(data).into())),
        (2,  4) => ("in_pkts",       Value::Number(read_u32(data).into())),
        (4,  1) => ("protocol",      Value::Number(data[0].into())),
        (5,  1) => ("tos",           Value::Number(data[0].into())),
        (6,  1) => ("tcp_flags",     Value::Number(data[0].into())),
        (7,  2) => ("src_port",      Value::Number(read_u16(data).into())),
        (8,  4) => ("src_ip",        Value::String(Ipv4Addr::from(read_u32(data)).to_string())),
        (11, 2) => ("dst_port",      Value::Number(read_u16(data).into())),
        (12, 4) => ("dst_ip",        Value::String(Ipv4Addr::from(read_u32(data)).to_string())),
        (15, 4) => ("nexthop",       Value::String(Ipv4Addr::from(read_u32(data)).to_string())),
        (17, 2) => ("src_as",        Value::Number(read_u16(data).into())),
        (16, 2) => ("dst_as",        Value::Number(read_u16(data).into())),
        (21, 4) => ("last_switched", Value::Number(read_u32(data).into())),
        (22, 4) => ("first_switched",Value::Number(read_u32(data).into())),
        (23, 4) => ("out_bytes",     Value::Number(read_u32(data).into())),
        (24, 4) => ("out_pkts",      Value::Number(read_u32(data).into())),
        (32, 2) => ("icmp_type",     Value::Number(read_u16(data).into())),
        // IPv6
        (27, 16) => ("src_ipv6",     Value::String(read_ipv6(data))),
        (28, 16) => ("dst_ipv6",     Value::String(read_ipv6(data))),
        // IPFIX timestamps (epoch ms)
        (150, 4) => ("flow_start_sec",  Value::Number(read_u32(data).into())),
        (151, 4) => ("flow_end_sec",    Value::Number(read_u32(data).into())),
        (152, 8) => ("flow_start_ms",   Value::Number((read_u64(data) as i64).into())),
        (153, 8) => ("flow_end_ms",     Value::Number((read_u64(data) as i64).into())),
        // Unknown: encode as hex
        (t, _l) => {
            let key_str = format!("field_{t}");
            (Box::leak(key_str.into_boxed_str()), Value::String(hex::encode(data)))
        }
    };
    Some((key.to_string(), val))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn read_u16(b: &[u8]) -> u16 { u16::from_be_bytes([b[0], b[1]]) }
fn read_u32(b: &[u8]) -> u32 { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) }
fn read_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]])
}
fn read_ipv6(b: &[u8]) -> String {
    std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&b[..16]).unwrap_or([0u8; 16])
    ).to_string()
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        1   => "ICMP", 6   => "TCP",  17 => "UDP",
        47  => "GRE",  50  => "ESP",  51 => "AH",
        58  => "ICMPv6", 89 => "OSPF", 132 => "SCTP",
        _   => "OTHER",
    }
}
