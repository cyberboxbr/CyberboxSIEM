//! MaxMind GeoLite2 enrichment.
//!
//! Wraps the maxminddb reader in an `Arc` so it can be cheaply cloned and
//! shared across Tokio tasks without extra synchronisation overhead.

use std::net::IpAddr;
use std::sync::Arc;

use maxminddb::{geoip2, Reader};
use serde_json::Value;
use tracing::debug;

/// Result of a successful GeoIP lookup.
#[derive(Debug, Clone)]
pub struct GeoIpResult {
    /// Resolved IP address (as string, for logging / storage).
    pub ip: String,
    /// ISO 3166-1 alpha-2 country code, e.g. `"US"`.
    pub country_iso: String,
    /// Human-readable country name in English, e.g. `"United States"`.
    pub country_name: String,
    /// City name in English, may be empty if unavailable.
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// Thread-safe GeoIP enricher backed by a MaxMind `.mmdb` database file.
///
/// # Example
/// ```no_run
/// use cyberbox_core::geoip::GeoIpEnricher;
///
/// let enricher = GeoIpEnricher::open("/var/lib/cyberbox/GeoLite2-City.mmdb").unwrap();
/// if let Some(result) = enricher.lookup_str("8.8.8.8") {
///     println!("{} -> {}, {}", result.ip, result.country_name, result.city);
/// }
/// ```
#[derive(Clone)]
pub struct GeoIpEnricher {
    reader: Arc<Reader<Vec<u8>>>,
}

impl GeoIpEnricher {
    /// Open a MaxMind `.mmdb` database file and build the enricher.
    pub fn open(db_path: &str) -> anyhow::Result<Self> {
        let reader = Reader::open_readfile(db_path)
            .map_err(|e| anyhow::anyhow!("failed to open GeoIP db '{}': {}", db_path, e))?;
        Ok(Self {
            reader: Arc::new(reader),
        })
    }

    /// Scan common IP field names in a raw event payload and return the first
    /// successful public-IP lookup.
    pub fn enrich_event(&self, payload: &Value) -> Option<GeoIpResult> {
        for field in IP_FIELD_NAMES {
            if let Some(ip_str) = payload.get(*field).and_then(|v| v.as_str()) {
                if let Some(result) = self.lookup_str(ip_str) {
                    return Some(result);
                }
            }
        }
        None
    }

    /// Look up an IP address string.  Returns `None` for private/loopback
    /// addresses, malformed strings, or IPs absent from the database.
    pub fn lookup_str(&self, ip_str: &str) -> Option<GeoIpResult> {
        let ip: IpAddr = ip_str.trim().parse().ok()?;
        if is_private(&ip) {
            debug!(ip = %ip, "GeoIP: skipping private/reserved address");
            return None;
        }
        self.lookup_ip(ip)
    }

    fn lookup_ip(&self, ip: IpAddr) -> Option<GeoIpResult> {
        let record: geoip2::City = self.reader.lookup(ip).ok()?;

        let country_iso = record
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .map(|s| s.to_string())
            .unwrap_or_default();

        let country_name = record
            .country
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string())
            .unwrap_or_else(|| country_iso.clone());

        let city = record
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let (latitude, longitude) = record
            .location
            .as_ref()
            .and_then(|loc| Some((loc.latitude?, loc.longitude?)))
            .unwrap_or((0.0, 0.0));

        Some(GeoIpResult {
            ip: ip.to_string(),
            country_iso,
            country_name,
            city,
            latitude,
            longitude,
        })
    }
}

/// Common field names that might carry a routable IP address in raw event
/// payloads.  Checked in order; the first match wins.
static IP_FIELD_NAMES: &[&str] = &[
    "src_ip",
    "source_ip",
    "dst_ip",
    "dest_ip",
    "destination_ip",
    "ip",
    "remote_addr",
    "client_ip",
    "peer_ip",
    "srcip",
    "dstip",
    "initiator_ip",
    "responder_ip",
];

/// Returns `true` for addresses that should be skipped during GeoIP lookup
/// (RFC 1918 private ranges, loopback, link-local, and the unspecified
/// address).
fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10                                          // 10.0.0.0/8
                || (o[0] == 172 && (16..=31).contains(&o[1])) // 172.16.0.0/12
                || (o[0] == 192 && o[1] == 168)                // 192.168.0.0/16
                || o[0] == 127                                  // 127.0.0.0/8
                || (o[0] == 169 && o[1] == 254)                // 169.254.0.0/16
                || o == [0, 0, 0, 0] // 0.0.0.0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
            // fe80::/10
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ipv4_ranges_are_skipped() {
        for ip_str in &[
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
        ] {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(is_private(&ip), "{ip_str} should be private");
        }
    }

    #[test]
    fn public_ipv4_is_not_private() {
        for ip_str in &["8.8.8.8", "1.1.1.1", "203.0.113.1", "185.199.108.153"] {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(!is_private(&ip), "{ip_str} should be public");
        }
    }

    #[test]
    fn loopback_ipv6_is_private() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(is_private(&ip));
    }

    #[test]
    fn link_local_ipv6_is_private() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private(&ip));
    }
}
