//! Syslog UDP listener — multi-reader with SO_REUSEPORT on Linux.
//!
//! **Linux**: binds N independent sockets each with `SO_REUSEPORT`; the kernel
//! distributes incoming datagrams using a consistent hash of the source 4-tuple,
//! giving true kernel-level load balancing with zero userspace lock contention.
//!
//! **Other platforms**: a single `Arc<UdpSocket>` is shared across N reader
//! tasks (tokio serialises `recv_from` internally); still saturates multi-core
//! better than a single task.
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `COLLECTOR_UDP_BIND` | `0.0.0.0:514` | Bind address |
//! | `COLLECTOR_UDP_READERS` | CPU cores | Concurrent recv tasks |

use std::{
    net::SocketAddr,
    sync::{atomic::Ordering::Relaxed, Arc},
};

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
    task::JoinSet,
};
use tracing::{debug, error, info};

use crate::metrics::CollectorMetrics;
use crate::parser::{parse_syslog, to_incoming_event};
use crate::ratelimit::SourceRateLimiter;
use crate::source_registry::SourceRegistry;

// ─── Shared per-datagram processor ────────────────────────────────────────────

/// Inner receive loop. `sock` is `Arc<UdpSocket>` so both the Linux path
/// (each task wraps its own independently-bound socket) and the non-Linux path
/// (N tasks share one socket) can use the same code.
#[allow(clippy::too_many_arguments)]
async fn run_reader(
    sock: Arc<UdpSocket>,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    max_msg_bytes: usize,
    metrics: Arc<CollectorMetrics>,
    rate_limiter: Arc<SourceRateLimiter>,
    mut shutdown: watch::Receiver<bool>,
    registry: Arc<SourceRegistry>,
) {
    use tokio::sync::mpsc::error::TrySendError;
    let mut buf = vec![0u8; max_msg_bytes];
    loop {
        let res = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            r = sock.recv_from(&mut buf) => r,
        };
        match res {
            Ok((len, peer)) => {
                let ip = peer.ip();
                let source_ip = ip.to_string();

                if !rate_limiter.check(ip) {
                    metrics.rate_limit_drops.fetch_add(1, Relaxed);
                    debug!(source_ip, "UDP datagram rate-limited");
                    continue;
                }

                match parse_syslog(&buf[..len], &source_ip) {
                    Some(msg) => {
                        registry.observe(&source_ip, &msg.hostname, &msg.app_name, &msg.message);
                        let ev = to_incoming_event(&msg, &tenant_id);
                        match tx.try_send(ev) {
                            Ok(_) => {
                                metrics.udp_received.fetch_add(1, Relaxed);
                            }
                            Err(TrySendError::Full(_)) => {
                                metrics.channel_drops.fetch_add(1, Relaxed);
                                debug!(source_ip, "UDP event dropped — ingest channel full");
                            }
                            Err(TrySendError::Closed(_)) => return,
                        }
                    }
                    None => {
                        metrics.parse_errors.fetch_add(1, Relaxed);
                        debug!(source_ip, "could not parse syslog UDP datagram");
                    }
                }
            }
            Err(err) => error!(%err, "UDP recv_from error"),
        }
    }
    debug!("UDP reader exiting on shutdown signal");
}

// ─── SO_REUSEPORT socket factory (Linux only) ────────────────────────────────

/// Create a non-blocking UDP socket with `SO_REUSEPORT` set.  Multiple sockets
/// bound to the same address let the kernel distribute datagrams across them.
#[cfg(target_os = "linux")]
fn make_reuseport_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("socket2 new UDP")?;
    sock.set_reuse_port(true).context("SO_REUSEPORT")?;
    sock.set_nonblocking(true).context("set_nonblocking")?;
    sock.bind(&addr.into())
        .with_context(|| format!("bind SO_REUSEPORT UDP {addr}"))?;
    Ok(sock.into())
}

// ─── Public entry point ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn run(
    bind: SocketAddr,
    readers: usize,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    max_msg_bytes: usize,
    metrics: Arc<CollectorMetrics>,
    rate_limiter: Arc<SourceRateLimiter>,
    shutdown: watch::Receiver<bool>,
    registry: Arc<SourceRegistry>,
) -> Result<()> {
    // ── Linux: N independent SO_REUSEPORT sockets (true kernel load-balancing) ─
    #[cfg(target_os = "linux")]
    {
        info!(%bind, readers, "syslog UDP listener ready (SO_REUSEPORT — kernel load-balanced)");
        let mut set = JoinSet::new();
        for _ in 0..readers {
            let std_sock = make_reuseport_socket(bind)?;
            let sock = Arc::new(
                UdpSocket::from_std(std_sock)
                    .context("tokio UdpSocket from SO_REUSEPORT socket")?,
            );
            let tx2 = tx.clone();
            let tid = Arc::clone(&tenant_id);
            let m = Arc::clone(&metrics);
            let rl = Arc::clone(&rate_limiter);
            let sd = shutdown.clone();
            let reg = Arc::clone(&registry);
            set.spawn(run_reader(sock, tid, tx2, max_msg_bytes, m, rl, sd, reg));
        }
        while let Some(res) = set.join_next().await {
            if let Err(e) = res {
                error!(err = %e, "UDP reader task panicked");
            }
        }
        Ok(())
    }

    // ── Non-Linux: shared Arc<UdpSocket> across N reader tasks ─────────────────
    #[cfg(not(target_os = "linux"))]
    {
        let sock = Arc::new(
            UdpSocket::bind(bind)
                .await
                .with_context(|| format!("bind UDP {bind}"))?,
        );
        info!(%bind, readers, "syslog UDP listener ready (shared socket, multi-reader)");
        let mut set = JoinSet::new();
        for _ in 0..readers {
            let sock2 = Arc::clone(&sock);
            let tx2 = tx.clone();
            let tid = Arc::clone(&tenant_id);
            let m = Arc::clone(&metrics);
            let rl = Arc::clone(&rate_limiter);
            let sd = shutdown.clone();
            let reg = Arc::clone(&registry);
            set.spawn(run_reader(sock2, tid, tx2, max_msg_bytes, m, rl, sd, reg));
        }
        while let Some(res) = set.join_next().await {
            if let Err(e) = res {
                error!(err = %e, "UDP reader task panicked");
            }
        }
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Ensure a simple syslog datagram is received, parsed, and forwarded.
    #[tokio::test]
    async fn roundtrip_syslog_datagram() {
        let (tx, mut rx) = mpsc::channel(16);
        let metrics = CollectorMetrics::new("test-udp-queue.jsonl".into());
        let rl = Arc::new(SourceRateLimiter::new(0, 3)); // disabled
        let tenant = Arc::new("test-tenant".to_string());

        // Bind source on OS-assigned port, retrieve address.
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bound_addr = std_sock.local_addr().unwrap();
        std_sock.set_nonblocking(true).unwrap();
        let listener = Arc::new(UdpSocket::from_std(std_sock).unwrap());

        let m2 = Arc::clone(&metrics);
        let rl2 = Arc::clone(&rl);
        let tx2 = tx.clone();
        let tid2 = Arc::clone(&tenant);
        let sock2 = Arc::clone(&listener);
        let (_sd_tx, sd_rx) = tokio::sync::watch::channel(false);
        let reg = Arc::new(SourceRegistry::new());
        let handle = tokio::spawn(run_reader(sock2, tid2, tx2, 65535, m2, rl2, sd_rx, reg));

        // Send a syslog datagram.
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(
                b"<13>Jan  1 00:00:00 testhost myapp: hello from udp test",
                bound_addr,
            )
            .await
            .unwrap();

        let ev = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
            .await
            .expect("timeout waiting for event")
            .expect("channel closed");

        assert_eq!(ev["tenant_id"], "test-tenant");
        assert_eq!(ev["source"], "syslog");
        assert!(
            ev["raw_payload"]["hostname"].as_str().unwrap_or("") == "testhost"
                || ev["raw_payload"]["source_ip"].as_str().is_some()
        );

        handle.abort();
        drop(metrics); // silence unused warning
        drop(rl); // silence unused warning
        let _ = Ipv4Addr::LOCALHOST; // suppress unused import lint
    }
}
