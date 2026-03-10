//! Per-source-IP token-bucket rate limiter for UDP / TCP sources.
//!
//! Enabled via `COLLECTOR_SOURCE_RATE_EPS > 0` (events per second per source IP).
//! Uses `Mutex::try_lock` so receiver tasks never block each other — if the lock
//! is contended the packet is allowed through (conservative policy).
//!
//! Call `cleanup()` from a background task every ~60 s to evict stale buckets.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::Instant,
};

pub struct SourceRateLimiter {
    /// Tokens replenished per second. 0.0 = rate limiting disabled.
    max_eps: f64,
    /// Maximum token accumulation (burst capacity).
    burst:   f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

struct Bucket {
    tokens:      f64,
    last_refill: Instant,
}

impl SourceRateLimiter {
    /// `max_eps_per_source = 0` disables rate limiting entirely.
    /// `burst_multiplier` sets burst = max_eps × multiplier.
    pub fn new(max_eps_per_source: u64, burst_multiplier: u32) -> Self {
        let max_eps = max_eps_per_source as f64;
        let burst   = if max_eps > 0.0 {
            (max_eps * burst_multiplier as f64).max(1.0)
        } else {
            0.0
        };
        Self { max_eps, burst, buckets: Mutex::new(HashMap::new()) }
    }

    /// Returns `true` → allow the event; `false` → drop (rate exceeded).
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.max_eps == 0.0 { return true; }

        // try_lock: prefer allowing the packet over blocking a hot receiver task.
        let Ok(mut map) = self.buckets.try_lock() else { return true; };

        let now    = Instant::now();
        let bucket = map.entry(ip).or_insert(Bucket {
            tokens:      self.burst,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.max_eps).min(self.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Evict buckets that haven't received a packet in the last 2 minutes.
    /// Call periodically; skips gracefully under lock contention.
    pub fn cleanup(&self) {
        if self.max_eps == 0.0 { return; }
        if let Ok(mut map) = self.buckets.try_lock() {
            let now = Instant::now();
            map.retain(|_, b| now.duration_since(b.last_refill).as_secs() < 120);
        }
    }
}
