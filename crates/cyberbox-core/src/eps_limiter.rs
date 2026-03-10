//! Per-tenant token-bucket EPS (events per second) rate limiter.
//!
//! Each tenant gets an independent bucket pre-filled to `burst_capacity`
//! tokens.  Tokens refill continuously at `eps_limit` per second (capped at
//! `burst_capacity`).  Consuming `n` events atomically deducts `n` tokens or
//! returns the number of seconds the caller should wait before retrying.
//!
//! The implementation uses `DashMap` for lock-free per-tenant sharding.  The
//! per-bucket write lock is held only for the brief arithmetic update, never
//! across I/O.

use std::time::Instant;

use dashmap::DashMap;

// ── Bucket ────────────────────────────────────────────────────────────────────

struct TenantBucket {
    tokens: f64,
    last_refill: Instant,
}

// ── EpsLimiter ────────────────────────────────────────────────────────────────

/// Shared, `Clone`-able EPS limiter.  Wrap in `Arc` and store on `AppState`.
pub struct EpsLimiter {
    buckets: DashMap<String, TenantBucket>,
    /// Maximum sustained rate per tenant (tokens/second).
    eps_limit: f64,
    /// Maximum burst capacity per tenant (tokens).
    burst_capacity: f64,
}

impl EpsLimiter {
    /// Create a new limiter.
    ///
    /// - `eps_limit_per_tenant`: maximum sustained events per second per tenant.
    /// - `burst_seconds`: how many seconds of burst capacity each tenant gets.
    ///   E.g. `eps=10_000, burst_seconds=5` → burst of 50 000 events.
    pub fn new(eps_limit_per_tenant: u64, burst_seconds: u64) -> Self {
        let eps_limit = eps_limit_per_tenant as f64;
        let burst_capacity = eps_limit * burst_seconds.max(1) as f64;
        Self {
            buckets: DashMap::new(),
            eps_limit,
            burst_capacity,
        }
    }

    /// Try to consume `count` tokens for `tenant_id`.
    ///
    /// Returns `Ok(())` on success.
    /// Returns `Err(retry_after_seconds)` when the tenant is throttled.
    pub fn try_consume(&self, tenant_id: &str, count: usize) -> Result<(), u64> {
        let mut bucket = self
            .buckets
            .entry(tenant_id.to_string())
            .or_insert_with(|| TenantBucket {
                tokens: self.burst_capacity,
                last_refill: Instant::now(),
            });

        // Refill tokens based on elapsed time since last call
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.eps_limit).min(self.burst_capacity);
        bucket.last_refill = now;

        let needed = count as f64;
        if bucket.tokens >= needed {
            bucket.tokens -= needed;
            Ok(())
        } else {
            let deficit = needed - bucket.tokens;
            Err((deficit / self.eps_limit).ceil() as u64)
        }
    }

    /// Current number of active tenant buckets (useful for metrics/debugging).
    pub fn tenant_count(&self) -> usize {
        self.buckets.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_traffic_within_burst_capacity() {
        let limiter = EpsLimiter::new(1_000, 5); // 1k eps, 5s burst = 5k cap
        assert!(limiter.try_consume("tenant-a", 1_000).is_ok());
        assert!(limiter.try_consume("tenant-a", 4_000).is_ok()); // 5k total = cap
    }

    #[test]
    fn rejects_when_burst_drained() {
        let limiter = EpsLimiter::new(100, 1); // 100 eps, 100 cap
        assert!(limiter.try_consume("tenant-a", 100).is_ok()); // drain
        let err = limiter.try_consume("tenant-a", 1).unwrap_err();
        assert!(err >= 1, "retry_after must be at least 1s");
    }

    #[test]
    fn retry_after_scales_with_deficit() {
        let limiter = EpsLimiter::new(100, 10); // 100 eps, 1000 cap
        assert!(limiter.try_consume("tenant-a", 1_000).is_ok()); // drain 1000
        // 100 more needed → 100 / 100 eps = 1s
        let err = limiter.try_consume("tenant-a", 100).unwrap_err();
        assert_eq!(err, 1);
    }

    #[test]
    fn tenants_are_fully_isolated() {
        let limiter = EpsLimiter::new(10, 1); // 10 cap each
        assert!(limiter.try_consume("tenant-a", 10).is_ok()); // drain a
        assert!(limiter.try_consume("tenant-b", 10).is_ok()); // b unaffected
        assert!(limiter.try_consume("tenant-a", 1).is_err()); // a throttled
    }

    #[test]
    fn oversized_single_batch_rejected() {
        let limiter = EpsLimiter::new(1_000, 5); // 5k cap
        assert!(limiter.try_consume("t", 5_001).is_err());
    }

    #[test]
    fn tenant_count_tracks_active_buckets() {
        let limiter = EpsLimiter::new(1_000, 5);
        assert_eq!(limiter.tenant_count(), 0);
        let _ = limiter.try_consume("a", 1);
        let _ = limiter.try_consume("b", 1);
        assert_eq!(limiter.tenant_count(), 2);
    }
}
