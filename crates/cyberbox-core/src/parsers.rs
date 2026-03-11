//! Structured log format parsers for common event formats.
//!
//! Auto-detects and parses the following formats into `serde_json::Value` objects:
//!
//! | Format | Detection | Example |
//! |--------|-----------|---------|
//! | JSON   | starts with `{` | `{"EventID":4625,"user":"bob"}` |
//! | CEF    | `CEF:` prefix | `CEF:0\|vendor\|product\|...\|key=val` |
//! | LEEF   | `LEEF:` prefix | `LEEF:1.0\|vendor\|product\|...\|key=val` |
//! | KV     | contains `=`  | `src=1.2.3.4 dst=10.0.0.1 msg=login` |
//!
//! If no format matches the raw line is returned as `{"msg": "<line>"}`.
//!
//! ## CEF format (RFC-like)
//! ```text
//! CEF:0|Security|ArcSight|6.0|100|Login|7|src=1.2.3.4 dst=10.0.0.1
//! ```
//! Header fields become top-level keys; the extension key=value pairs are merged in.
//!
//! ## LEEF format (IBM QRadar)
//! ```text
//! LEEF:1.0|Microsoft|MSExchange|4.0.3|18|src=1.2.3.4\tdst=10.0.0.1
//! ```
//! Header fields become top-level keys; tab-separated key=value pairs are merged.
//!
//! ## KV format
//! ```text
//! src=1.2.3.4 dst=10.0.0.1 proto=TCP dpt=443
//! ```
//! Splits on whitespace, then on `=` for each token.

use serde_json::{json, Map, Value};

// ─── Public API ────────────────────────────────────────────────────────────────

/// Parse a raw log line into a structured JSON `Value`.
///
/// Tries JSON → CEF → LEEF → KV → raw `{"msg": line}` in order.
pub fn parse_log_line(line: &str) -> Value {
    let trimmed = line.trim();

    // JSON — already structured
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
            return v;
        }
    }

    // CEF
    if trimmed.to_ascii_uppercase().starts_with("CEF:") {
        if let Some(v) = try_parse_cef(trimmed) {
            return v;
        }
    }

    // LEEF
    if trimmed.to_ascii_uppercase().starts_with("LEEF:") {
        if let Some(v) = try_parse_leef(trimmed) {
            return v;
        }
    }

    // KV (must contain at least one `=` surrounded by non-space chars)
    if trimmed.contains('=') && !trimmed.contains('<') {
        let kv = parse_kv(trimmed);
        if !kv.is_empty() {
            let mut map = Map::new();
            map.insert("log_format".to_string(), json!("kv"));
            for (k, v) in kv {
                map.insert(k, json!(v));
            }
            return Value::Object(map);
        }
    }

    json!({ "msg": trimmed })
}

// ─── CEF ─────────────────────────────────────────────────────────────────────

/// Parse a CEF log line.
///
/// Format: `CEF:version|vendor|product|version|sig_id|name|severity|extensions`
///
/// Extension field: whitespace-separated `key=value` pairs where values may
/// contain spaces if quoted. Unquoted values end at the next whitespace+`word=`.
fn try_parse_cef(line: &str) -> Option<Value> {
    // CEF:0|... — split after the "CEF:" prefix
    let after_cef = if line.len() > 4 {
        &line[4..]
    } else {
        return None;
    };
    // after_cef = "0|vendor|product|devVersion|sigId|name|severity|extensions"
    let parts: Vec<&str> = after_cef.splitn(8, '|').collect();
    if parts.len() < 7 {
        return None;
    }

    let mut map = Map::new();
    map.insert("log_format".to_string(), json!("cef"));
    map.insert("cef_version".to_string(), json!(parts[0].trim()));
    map.insert("device_vendor".to_string(), json!(parts[1].trim()));
    map.insert("device_product".to_string(), json!(parts[2].trim()));
    map.insert("device_version".to_string(), json!(parts[3].trim()));
    map.insert("signature_id".to_string(), json!(parts[4].trim()));
    map.insert("name".to_string(), json!(parts[5].trim()));
    map.insert("severity".to_string(), json!(parts[6].trim()));

    // Extension key=value pairs
    if let Some(ext) = parts.get(7) {
        for (k, v) in parse_cef_extensions(ext) {
            map.insert(k, json!(v));
        }
    }

    Some(Value::Object(map))
}

/// Parse CEF extension field: `key=value key2=value2 ...`
///
/// Values may contain spaces; the next `word=` boundary ends the value.
fn parse_cef_extensions(ext: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    // Split on `<key>=` boundaries using a greedy scan
    let mut remaining = ext.trim();
    while !remaining.is_empty() {
        // Find the key (up to the first '=')
        let eq = match remaining.find('=') {
            Some(i) => i,
            None => break,
        };
        let key = remaining[..eq].trim();
        if key.is_empty() {
            break;
        }
        remaining = &remaining[eq + 1..];

        // Value ends at the next `<space><identifier>=` pattern or end of string
        let value = if let Some(end) = find_next_kv_boundary(remaining) {
            let v = remaining[..end].trim().to_string();
            remaining = remaining[end..].trim_start();
            v
        } else {
            let v = remaining.trim().to_string();
            remaining = "";
            v
        };
        result.push((key.to_string(), value));
    }
    result
}

/// Find position of next `<space><word>=` boundary in `s`.
fn find_next_kv_boundary(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b' ' || bytes[i] == b'\t' {
            // Look for `<word>=` after the space
            let rest = &s[i + 1..];
            if let Some(eq) = rest.find('=') {
                let candidate = &rest[..eq];
                // key must be non-empty and contain only word chars
                if !candidate.trim().is_empty()
                    && candidate
                        .trim()
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_')
                {
                    return Some(i);
                }
            }
        }
    }
    None
}

// ─── LEEF ────────────────────────────────────────────────────────────────────

/// Parse a LEEF log line.
///
/// Format: `LEEF:version|vendor|product|version|event_id|extensions`
/// Extensions may be tab-separated (`\t`) or space-separated.
fn try_parse_leef(line: &str) -> Option<Value> {
    // Skip "LEEF:" prefix
    let after_leef = if line.len() > 5 {
        &line[5..]
    } else {
        return None;
    };
    // Split header (5 pipe-separated fields) from extensions
    let parts: Vec<&str> = after_leef.splitn(6, '|').collect();
    if parts.len() < 5 {
        return None;
    }

    let mut map = Map::new();
    map.insert("log_format".to_string(), json!("leef"));
    map.insert("leef_version".to_string(), json!(parts[0].trim()));
    map.insert("device_vendor".to_string(), json!(parts[1].trim()));
    map.insert("device_product".to_string(), json!(parts[2].trim()));
    map.insert("device_version".to_string(), json!(parts[3].trim()));
    map.insert("event_id".to_string(), json!(parts[4].trim()));

    if let Some(ext) = parts.get(5) {
        // LEEF uses tab-delimited key=value pairs
        let sep = if ext.contains('\t') { '\t' } else { ' ' };
        for token in ext.split(sep) {
            if let Some(eq) = token.find('=') {
                let k = token[..eq].trim();
                let v = token[eq + 1..].trim();
                if !k.is_empty() {
                    map.insert(k.to_string(), json!(v));
                }
            }
        }
    }

    Some(Value::Object(map))
}

// ─── KV ──────────────────────────────────────────────────────────────────────

/// Parse a key=value log line (space-separated tokens).
fn parse_kv(line: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for token in line.split_whitespace() {
        if let Some(eq) = token.find('=') {
            let k = token[..eq].trim();
            let v = token[eq + 1..].trim();
            if !k.is_empty() {
                result.push((k.to_string(), v.to_string()));
            }
        }
    }
    result
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json() {
        let v = parse_log_line(r#"{"EventID":4625,"user":"bob"}"#);
        assert_eq!(v["EventID"], 4625);
        assert_eq!(v["user"], "bob");
    }

    #[test]
    fn parses_cef() {
        let line = "CEF:0|Security|ArcSight|6.0|100|Failed Login|7|src=1.2.3.4 dst=10.0.0.1 dpt=22";
        let v = parse_log_line(line);
        assert_eq!(v["log_format"], "cef");
        assert_eq!(v["device_vendor"], "Security");
        assert_eq!(v["name"], "Failed Login");
        assert_eq!(v["severity"], "7");
        assert_eq!(v["src"], "1.2.3.4");
        assert_eq!(v["dst"], "10.0.0.1");
        assert_eq!(v["dpt"], "22");
    }

    #[test]
    fn parses_leef() {
        let line = "LEEF:1.0|Microsoft|MSExchange|4.0|18|src=1.2.3.4\tdst=10.0.0.1\tusrName=admin";
        let v = parse_log_line(line);
        assert_eq!(v["log_format"], "leef");
        assert_eq!(v["device_vendor"], "Microsoft");
        assert_eq!(v["event_id"], "18");
        assert_eq!(v["src"], "1.2.3.4");
        assert_eq!(v["usrName"], "admin");
    }

    #[test]
    fn parses_kv() {
        let line = "src=1.2.3.4 dst=10.0.0.1 proto=TCP dpt=443 action=allow";
        let v = parse_log_line(line);
        assert_eq!(v["log_format"], "kv");
        assert_eq!(v["src"], "1.2.3.4");
        assert_eq!(v["dpt"], "443");
        assert_eq!(v["action"], "allow");
    }

    #[test]
    fn falls_back_to_raw_msg() {
        let v = parse_log_line("just a plain log line with nothing structured");
        assert_eq!(v["msg"], "just a plain log line with nothing structured");
    }

    #[test]
    fn cef_value_with_spaces() {
        let line = "CEF:0|vendor|product|1.0|sig|name|5|msg=hello world dpt=443";
        let v = parse_log_line(line);
        assert_eq!(v["msg"], "hello world");
        assert_eq!(v["dpt"], "443");
    }
}
