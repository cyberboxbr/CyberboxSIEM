//! Syslog (RFC 3164 + RFC 5424), CEF, and LEEF parsing.

use std::collections::HashMap;

use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use serde_json::{json, Map, Value};

// ─── Syslog types ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SyslogVersion {
    Rfc3164,
    Rfc5424,
}

#[derive(Debug)]
pub struct SyslogMsg {
    pub facility: u8,
    pub severity: u8,
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub app_name: String,
    pub pid: Option<String>,
    pub message: String,
    pub source_ip: String,
    pub version: SyslogVersion,
    /// RFC 5424 Structured Data: SD-ID → { param-name → param-value }
    pub structured_data: HashMap<String, HashMap<String, String>>,
}

// ─── Facility / severity names ────────────────────────────────────────────────

pub fn facility_name(f: u8) -> &'static str {
    match f {
        0 => "kern",
        1 => "user",
        2 => "mail",
        3 => "daemon",
        4 => "auth",
        5 => "syslog",
        6 => "lpr",
        7 => "news",
        8 => "uucp",
        9 => "cron",
        10 => "authpriv",
        11 => "ftp",
        16 => "local0",
        17 => "local1",
        18 => "local2",
        19 => "local3",
        20 => "local4",
        21 => "local5",
        22 => "local6",
        23 => "local7",
        _ => "unknown",
    }
}

pub fn severity_name(s: u8) -> &'static str {
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

// ─── Entry point ──────────────────────────────────────────────────────────────

/// Parse a raw syslog byte buffer from `source_ip`. Returns `None` if the
/// message cannot be decoded at all.
pub fn parse_syslog(data: &[u8], source_ip: &str) -> Option<SyslogMsg> {
    let raw = std::str::from_utf8(data)
        .ok()?
        .trim_end_matches(['\n', '\r']);
    let raw = strip_octet_count(raw);

    if !raw.starts_with('<') {
        return Some(SyslogMsg {
            facility: 1,
            severity: 6,
            timestamp: Utc::now(),
            hostname: source_ip.to_string(),
            app_name: String::new(),
            pid: None,
            message: raw.to_string(),
            source_ip: source_ip.to_string(),
            version: SyslogVersion::Rfc3164,
            structured_data: HashMap::new(),
        });
    }

    let close = raw.find('>')?;
    let pri: u16 = raw[1..close].parse().ok()?;
    let facility = (pri >> 3) as u8;
    let severity = (pri & 7) as u8;
    let rest = &raw[close + 1..];

    if rest.starts_with('1') && rest.len() > 1 && rest.as_bytes().get(1) == Some(&b' ') {
        parse_rfc5424(&rest[2..], facility, severity, source_ip)
    } else {
        parse_rfc3164(rest, facility, severity, source_ip)
    }
}

/// Strip RFC 5425 octet-count prefix: `<N> <msg>`
pub fn strip_octet_count(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i > 0 && bytes.get(i) == Some(&b' ') && bytes.get(i + 1) == Some(&b'<') {
        &s[i + 1..]
    } else {
        s
    }
}

fn parse_rfc5424(rest: &str, facility: u8, severity: u8, source_ip: &str) -> Option<SyslogMsg> {
    let mut iter = rest.splitn(6, ' ');
    let ts_str = iter.next()?;
    let hostname = iter.next().unwrap_or("-").to_string();
    let app_name = iter.next().unwrap_or("-").to_string();
    let pid_str = iter.next().unwrap_or("-");
    let _msgid = iter.next();
    let sd_and_msg = iter.next().unwrap_or("").trim_start();

    let timestamp = DateTime::parse_from_rfc3339(ts_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let (structured_data, message) = if sd_and_msg.starts_with('[') {
        let (sd, after_sd) = parse_structured_data(sd_and_msg);
        let msg = after_sd.trim_start_matches('\u{feff}').to_string();
        (sd, msg)
    } else if let Some(rest_msg) = sd_and_msg.strip_prefix("- ") {
        (
            HashMap::new(),
            rest_msg.trim_start_matches('\u{feff}').to_string(),
        )
    } else if sd_and_msg == "-" || sd_and_msg.is_empty() {
        (HashMap::new(), String::new())
    } else {
        (
            HashMap::new(),
            sd_and_msg.trim_start_matches('\u{feff}').to_string(),
        )
    };

    Some(SyslogMsg {
        facility,
        severity,
        timestamp,
        hostname: nilval(hostname),
        app_name: nilval(app_name),
        pid: if pid_str == "-" {
            None
        } else {
            Some(pid_str.to_string())
        },
        message,
        source_ip: source_ip.to_string(),
        version: SyslogVersion::Rfc5424,
        structured_data,
    })
}

fn parse_rfc3164(rest: &str, facility: u8, severity: u8, source_ip: &str) -> Option<SyslogMsg> {
    let (timestamp, after_ts) = if rest.len() >= 16 && is_bsd_month(&rest[..3]) {
        let year = Utc::now().year();
        let ts_raw = rest[..15].trim().to_string();
        let ts_str = format!("{year} {ts_raw}");
        let dt = NaiveDateTime::parse_from_str(&ts_str, "%Y %b %e %H:%M:%S")
            .or_else(|_| NaiveDateTime::parse_from_str(&ts_str, "%Y %b  %e %H:%M:%S"))
            .map(|ndt| ndt.and_utc())
            .unwrap_or_else(|_| Utc::now());
        (dt, rest[16..].trim_start())
    } else {
        (Utc::now(), rest)
    };

    let (hostname, rest2) = first_word(after_ts);
    let (app_name, pid, message) = parse_tag(rest2);

    Some(SyslogMsg {
        facility,
        severity,
        timestamp,
        hostname,
        app_name,
        pid,
        message,
        source_ip: source_ip.to_string(),
        version: SyslogVersion::Rfc3164,
        structured_data: HashMap::new(),
    })
}

fn nilval(s: String) -> String {
    if s == "-" {
        String::new()
    } else {
        s
    }
}

fn is_bsd_month(s: &str) -> bool {
    matches!(
        s,
        "Jan"
            | "Feb"
            | "Mar"
            | "Apr"
            | "May"
            | "Jun"
            | "Jul"
            | "Aug"
            | "Sep"
            | "Oct"
            | "Nov"
            | "Dec"
    )
}

fn first_word(s: &str) -> (String, &str) {
    match s.find(' ') {
        Some(i) => (s[..i].to_string(), s[i + 1..].trim_start()),
        None => (s.to_string(), ""),
    }
}

fn parse_tag(s: &str) -> (String, Option<String>, String) {
    if let Some(colon) = s.find(':') {
        let tag_part = &s[..colon];
        let msg = s[colon + 1..].trim_start().to_string();
        if let (Some(lb), Some(rb)) = (tag_part.find('['), tag_part.find(']')) {
            return (
                tag_part[..lb].to_string(),
                Some(tag_part[lb + 1..rb].to_string()),
                msg,
            );
        }
        return (tag_part.to_string(), None, msg);
    }
    (String::new(), None, s.to_string())
}

// ─── RFC 5424 Structured Data parser ─────────────────────────────────────────

/// Parse one or more SD elements (`[SD-ID key="val" ...]`) at the start of
/// `s`.  Returns the extracted map and the remaining message text after all SD
/// elements.
fn parse_structured_data(s: &str) -> (HashMap<String, HashMap<String, String>>, &str) {
    let mut result: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut rest = s;

    while rest.starts_with('[') {
        // Find matching ']' respecting backslash escapes.
        let close = find_sd_close(rest);
        let close = match close {
            Some(i) => i,
            None => break,
        };

        let element = &rest[1..close];
        rest = rest[close + 1..].trim_start();

        // First token = SD-ID, rest = space-separated param=value pairs.
        let (sd_id, params_str) = match element.find(' ') {
            Some(i) => (element[..i].to_string(), &element[i + 1..]),
            None => (element.to_string(), ""),
        };
        if sd_id.is_empty() {
            continue;
        }

        let mut params: HashMap<String, String> = HashMap::new();
        parse_sd_params(params_str, &mut params);
        result.insert(sd_id, params);
    }

    (result, rest)
}

/// Return the index of the closing `]` of the first SD element in `s`,
/// honouring backslash escapes for `]`, `"`, and `\`.  Returns `None` if
/// `s` does not start with `[` or the element is unterminated.
fn find_sd_close(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 1; // skip opening '['
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2, // skip escaped char
            b']' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Parse space-separated `key="value"` param pairs into `out`.
/// Handles backslash escapes inside quoted values (`\"`, `\\`, `\]`).
fn parse_sd_params(s: &str, out: &mut HashMap<String, String>) {
    let mut rest = s.trim();

    while !rest.is_empty() {
        // Find '='
        let eq = match rest.find('=') {
            Some(i) => i,
            None => break,
        };
        let key = rest[..eq].trim().to_string();
        rest = rest[eq + 1..].trim_start();

        // Value must be quoted.
        if !rest.starts_with('"') {
            break;
        }
        rest = &rest[1..];

        // Collect chars until closing unescaped '"'.
        let mut val = String::new();
        let mut bytes = rest.as_bytes().iter().enumerate();
        let mut end_byte = rest.len();
        let mut consumed = rest.len();
        while let Some((i, &b)) = bytes.next() {
            if b == b'\\' {
                if let Some((_, &nb)) = bytes.next() {
                    val.push(nb as char);
                }
            } else if b == b'"' {
                end_byte = i;
                consumed = i + 1;
                break;
            } else {
                val.push(b as char);
            }
        }
        let _ = end_byte; // consumed is what we care about

        rest = rest[consumed..].trim_start();
        if !key.is_empty() {
            out.insert(key, val);
        }
    }
}

// ─── CEF parsing ──────────────────────────────────────────────────────────────
// Format: CEF:Version|Vendor|Product|DevVersion|SignatureID|Name|Severity|Extensions

pub fn parse_cef(msg: &str) -> Option<Map<String, Value>> {
    let body = msg.strip_prefix("CEF:")?;
    let parts: Vec<&str> = body.splitn(8, '|').collect();
    if parts.len() < 7 {
        return None;
    }

    let mut map = Map::new();
    map.insert("event_format".into(), Value::String("CEF".into()));
    map.insert("cef_version".into(), Value::String(parts[0].into()));
    map.insert("cef_vendor".into(), Value::String(parts[1].into()));
    map.insert("cef_product".into(), Value::String(parts[2].into()));
    map.insert("cef_dev_version".into(), Value::String(parts[3].into()));
    map.insert("cef_signature_id".into(), Value::String(parts[4].into()));
    map.insert("cef_name".into(), Value::String(parts[5].into()));
    map.insert("cef_severity".into(), Value::String(parts[6].into()));

    if let Some(ext) = parts.get(7) {
        parse_kv_extensions(ext, "cef_", &mut map);
    }
    Some(map)
}

// ─── LEEF parsing ─────────────────────────────────────────────────────────────
// LEEF:1.0|Vendor|Product|Version|EventID|tab-separated k=v
// LEEF:2.0|Vendor|Product|Version|EventID|delimiter|k=v...

pub fn parse_leef(msg: &str) -> Option<Map<String, Value>> {
    let body = msg.strip_prefix("LEEF:")?;
    let parts: Vec<&str> = body.splitn(7, '|').collect();
    if parts.len() < 5 {
        return None;
    }

    let version = parts[0];
    let delimiter = if version.starts_with('2') && parts.len() >= 6 {
        parts[5].chars().next().unwrap_or('\t')
    } else {
        '\t'
    };

    let ext_part = if version.starts_with('2') {
        parts.get(6)
    } else {
        parts.get(5)
    };

    let mut map = Map::new();
    map.insert("event_format".into(), Value::String("LEEF".into()));
    map.insert("leef_version".into(), Value::String(version.into()));
    map.insert("leef_vendor".into(), Value::String(parts[1].into()));
    map.insert("leef_product".into(), Value::String(parts[2].into()));
    map.insert("leef_dev_version".into(), Value::String(parts[3].into()));
    map.insert("leef_event_id".into(), Value::String(parts[4].into()));

    if let Some(ext) = ext_part {
        parse_leef_extensions(ext, delimiter, &mut map);
    }
    Some(map)
}

/// Parse tab-delimited (or custom-delimiter) `key=value` LEEF extension pairs.
fn parse_leef_extensions(ext: &str, delim: char, map: &mut Map<String, Value>) {
    for pair in ext.split(delim) {
        if let Some(eq) = pair.find('=') {
            let key = pair[..eq].trim().to_string();
            let val = pair[eq + 1..].to_string();
            if !key.is_empty() {
                map.insert(format!("leef_{key}"), Value::String(val));
            }
        }
    }
}

/// Parse space-separated `key=value` CEF extension pairs.
/// Values can contain spaces; a new key starts at the next `word=` token.
fn parse_kv_extensions(ext: &str, prefix: &str, map: &mut Map<String, Value>) {
    let mut current_key: Option<String> = None;
    let mut val_parts: Vec<&str> = Vec::new();

    for token in ext.split(' ') {
        if let Some(eq) = token.find('=') {
            let key_candidate = &token[..eq];
            if !key_candidate.is_empty()
                && key_candidate
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_')
            {
                // Flush previous key
                if let Some(k) = current_key.take() {
                    map.insert(format!("{prefix}{k}"), Value::String(val_parts.join(" ")));
                    val_parts.clear();
                }
                current_key = Some(key_candidate.to_string());
                val_parts.push(&token[eq + 1..]);
                continue;
            }
        }
        val_parts.push(token);
    }
    if let Some(k) = current_key {
        map.insert(format!("{prefix}{k}"), Value::String(val_parts.join(" ")));
    }
}

// ─── Normalise to IncomingEvent JSON ─────────────────────────────────────────

pub fn to_incoming_event(msg: &SyslogMsg, tenant_id: &str) -> Value {
    let mut raw = Map::new();
    raw.insert("hostname".into(), Value::String(msg.hostname.clone()));
    raw.insert("app_name".into(), Value::String(msg.app_name.clone()));
    raw.insert(
        "pid".into(),
        msg.pid
            .as_deref()
            .map(|s| Value::String(s.into()))
            .unwrap_or(Value::Null),
    );
    raw.insert("message".into(), Value::String(msg.message.clone()));
    raw.insert("facility".into(), Value::Number(msg.facility.into()));
    raw.insert(
        "facility_name".into(),
        Value::String(facility_name(msg.facility).into()),
    );
    raw.insert("severity".into(), Value::Number(msg.severity.into()));
    raw.insert(
        "severity_name".into(),
        Value::String(severity_name(msg.severity).into()),
    );
    raw.insert("source_ip".into(), Value::String(msg.source_ip.clone()));
    raw.insert(
        "syslog_version".into(),
        Value::String(match msg.version {
            SyslogVersion::Rfc3164 => "RFC3164".into(),
            SyslogVersion::Rfc5424 => "RFC5424".into(),
        }),
    );

    // RFC 5424 Structured Data → nested map: { "sd_<ID>": { "key": "val" } }
    if !msg.structured_data.is_empty() {
        for (sd_id, params) in &msg.structured_data {
            let params_val: Map<String, Value> = params
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            // Sanitise SD-ID: replace '@' and '.' which appear in IANA IDs.
            let key = format!("sd_{}", sd_id.replace(['@', '.'], "_"));
            raw.insert(key, Value::Object(params_val));
        }
    }

    // CEF / LEEF detection in the message body
    if let Some(cef) = parse_cef(&msg.message) {
        for (k, v) in cef {
            raw.insert(k, v);
        }
    } else if let Some(leef) = parse_leef(&msg.message) {
        for (k, v) in leef {
            raw.insert(k, v);
        }
    }

    json!({
        "tenant_id":  tenant_id,
        "source":     "syslog",
        "event_time": msg.timestamp.to_rfc3339(),
        "raw_payload": Value::Object(raw),
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc5424() {
        let raw = b"<34>1 2026-03-10T10:15:30.123Z web-01 nginx 1234 - - GET /health HTTP/1.1";
        let msg = parse_syslog(raw, "10.0.0.1").unwrap();
        assert_eq!(msg.facility, 4);
        assert_eq!(msg.severity, 2);
        assert_eq!(msg.hostname, "web-01");
        assert_eq!(msg.app_name, "nginx");
        assert_eq!(msg.pid.as_deref(), Some("1234"));
        assert!(msg.message.contains("GET /health"));
    }

    #[test]
    fn parses_rfc3164() {
        let raw = b"<13>Mar 10 12:34:56 firewall-01 kernel: Firewall: IN=eth0 SRC=1.2.3.4";
        let msg = parse_syslog(raw, "192.168.1.1").unwrap();
        assert_eq!(msg.facility, 1);
        assert_eq!(msg.severity, 5);
        assert_eq!(msg.hostname, "firewall-01");
        assert_eq!(msg.app_name, "kernel");
        assert!(msg.message.contains("SRC=1.2.3.4"));
    }

    #[test]
    fn parses_rfc3164_with_pid() {
        let raw = b"<30>Mar 10 08:00:00 myhost sshd[4321]: Accepted publickey for root";
        let msg = parse_syslog(raw, "10.10.0.5").unwrap();
        assert_eq!(msg.app_name, "sshd");
        assert_eq!(msg.pid.as_deref(), Some("4321"));
        assert!(msg.message.contains("Accepted publickey"));
    }

    #[test]
    fn handles_bare_message() {
        let raw = b"hello world no pri";
        let msg = parse_syslog(raw, "1.2.3.4").unwrap();
        assert_eq!(msg.message, "hello world no pri");
    }

    #[test]
    fn strips_octet_count_prefix() {
        let raw = b"47 <34>1 2026-03-10T10:00:00Z host app - - - msg";
        let msg = parse_syslog(raw, "1.2.3.4").unwrap();
        assert_eq!(msg.hostname, "host");
    }

    #[test]
    fn severity_and_facility_names() {
        assert_eq!(severity_name(0), "emergency");
        assert_eq!(severity_name(6), "info");
        assert_eq!(facility_name(4), "auth");
        assert_eq!(facility_name(16), "local0");
    }

    #[test]
    fn normalises_to_incoming_event_shape() {
        let raw = b"<165>1 2026-03-10T10:00:00Z db-01 postgres 999 - - connection received";
        let msg = parse_syslog(raw, "10.0.0.2").unwrap();
        let ev = to_incoming_event(&msg, "acme-corp");
        assert_eq!(ev["tenant_id"], "acme-corp");
        assert_eq!(ev["source"], "syslog");
        assert_eq!(ev["raw_payload"]["hostname"], "db-01");
        assert_eq!(ev["raw_payload"]["app_name"], "postgres");
        assert_eq!(ev["raw_payload"]["severity_name"], "notice");
    }

    #[test]
    fn parses_cef_message() {
        let cef = "CEF:0|ArcSight|Logger|6.0|100|Login Success|5|src=10.0.0.1 dst=192.168.1.1 act=blocked";
        let map = parse_cef(cef).unwrap();
        assert_eq!(map["cef_vendor"], Value::String("ArcSight".into()));
        assert_eq!(map["cef_name"], Value::String("Login Success".into()));
        assert_eq!(map["cef_severity"], Value::String("5".into()));
        assert_eq!(map["cef_src"], Value::String("10.0.0.1".into()));
        assert_eq!(map["cef_dst"], Value::String("192.168.1.1".into()));
        assert_eq!(map["cef_act"], Value::String("blocked".into()));
        assert_eq!(map["event_format"], Value::String("CEF".into()));
    }

    #[test]
    fn parses_cef_in_syslog_body() {
        let raw = b"<134>1 2026-03-10T10:00:00Z fw01 CEF - - - CEF:0|Check Point|SmartDefense|R80|00000001|Port Scan|8|src=203.0.113.1 dst=10.0.0.5 proto=TCP";
        let msg = parse_syslog(raw, "10.0.0.1").unwrap();
        let ev = to_incoming_event(&msg, "t1");
        assert_eq!(ev["raw_payload"]["event_format"], "CEF");
        assert_eq!(ev["raw_payload"]["cef_vendor"], "Check Point");
        assert_eq!(ev["raw_payload"]["cef_src"], "203.0.113.1");
    }

    #[test]
    fn parses_leef_10() {
        let leef = "LEEF:1.0|IBM|QRadar|7.0|ADMIN_LOGIN|src=10.0.0.1\tdst=10.0.0.2\taction=login";
        let map = parse_leef(leef).unwrap();
        assert_eq!(map["leef_vendor"], Value::String("IBM".into()));
        assert_eq!(map["leef_event_id"], Value::String("ADMIN_LOGIN".into()));
        assert_eq!(map["leef_src"], Value::String("10.0.0.1".into()));
        assert_eq!(map["leef_action"], Value::String("login".into()));
    }

    #[test]
    fn parses_leef_20_custom_delimiter() {
        let leef = "LEEF:2.0|Vendor|Product|1.0|EventID|^|src=10.0.0.1^dst=10.0.0.2^proto=TCP";
        let map = parse_leef(leef).unwrap();
        assert_eq!(map["leef_src"], Value::String("10.0.0.1".into()));
        assert_eq!(map["leef_dst"], Value::String("10.0.0.2".into()));
        assert_eq!(map["leef_proto"], Value::String("TCP".into()));
    }

    // ── RFC 5424 Structured Data ──────────────────────────────────────────────

    #[test]
    fn parses_rfc5424_with_structured_data() {
        // Single SD element with two params
        let raw = b"<134>1 2026-03-10T10:00:00Z fw01 app - - [exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] Login event";
        let msg = parse_syslog(raw, "10.0.0.1").unwrap();
        assert_eq!(msg.message, "Login event");
        let sd = &msg.structured_data;
        assert_eq!(sd.len(), 1);
        let params = sd.get("exampleSDID@32473").unwrap();
        assert_eq!(params.get("iut").unwrap(), "3");
        assert_eq!(params.get("eventSource").unwrap(), "Application");
    }

    #[test]
    fn parses_rfc5424_multiple_sd_elements() {
        let raw = b"<165>1 2026-03-10T10:00:00Z host app - - [meta sequenceId=\"1\"][origin ip=\"192.0.2.1\"] msg";
        let msg = parse_syslog(raw, "1.2.3.4").unwrap();
        assert_eq!(msg.message, "msg");
        let sd = &msg.structured_data;
        assert_eq!(sd.len(), 2);
        assert_eq!(sd.get("meta").unwrap().get("sequenceId").unwrap(), "1");
        assert_eq!(sd.get("origin").unwrap().get("ip").unwrap(), "192.0.2.1");
    }

    #[test]
    fn sd_exposed_in_incoming_event() {
        let raw = b"<165>1 2026-03-10T10:00:00Z host app - - [mySD key=\"val\"] hello";
        let msg = parse_syslog(raw, "1.2.3.4").unwrap();
        let ev = to_incoming_event(&msg, "t1");
        // SD-ID "mySD" should appear as "sd_mySD" in raw_payload
        assert_eq!(ev["raw_payload"]["sd_mySD"]["key"], "val");
        assert_eq!(ev["raw_payload"]["message"], "hello");
    }

    #[test]
    fn sd_escaped_value() {
        // Backslash-escaped quote inside param value
        let (sd, rest) = parse_structured_data("[id val=\"he said \\\"hi\\\"\"] after");
        assert_eq!(rest, "after");
        assert_eq!(sd.get("id").unwrap().get("val").unwrap(), "he said \"hi\"");
    }

    #[test]
    fn rfc3164_has_empty_structured_data() {
        let raw = b"<13>Mar 10 12:34:56 host app: plain message";
        let msg = parse_syslog(raw, "1.2.3.4").unwrap();
        assert!(msg.structured_data.is_empty());
    }
}
