//! Collector performance bench tool.
//!
//! ## Subcommands
//! | Command | Purpose |
//! |---------|---------|
//! | `mock-api` | Minimal HTTP server that accepts ingest batches and returns 200 OK |
//! | `send`     | Flood the collector with UDP or TCP syslog events |
//! | `snapshot` | Fetch /healthz and print key counters as a tab-separated line |
//!
//! ## Typical usage
//! ```text
//! # Terminal 1 — mock API
//! collector-bench mock-api --bind 127.0.0.1:8888
//!
//! # Terminal 2 — collector (configured to forward to 8888, healthz on 9999)
//! COLLECTOR_HEALTHZ_BIND=127.0.0.1:9999 \
//! COLLECTOR_API_ENDPOINT=http://127.0.0.1:8888 \
//!   cyberbox-collector
//!
//! # Terminal 3 — sender (max throughput)
//! collector-bench send --target 127.0.0.1:5514 --concurrency 8
//!
//! # Terminal 4 — metrics
//! collector-bench snapshot --url http://127.0.0.1:9999
//! ```

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use clap::{Parser, Subcommand, ValueEnum};
use tokio::{net::UdpSocket, time};

// ── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(about = "Collector perf bench — mock-api / send / snapshot")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start a mock API server that accepts ingest POSTs and returns 200 OK
    MockApi {
        /// Address to bind (e.g. 127.0.0.1:8888)
        #[arg(long, default_value = "127.0.0.1:8888")]
        bind: String,

        /// Artificial per-request delay in ms (simulates a slow upstream API)
        #[arg(long, default_value = "0")]
        delay_ms: u64,
    },

    /// Send UDP or TCP syslog events to the collector as fast as possible
    Send {
        /// Collector syslog UDP or TCP address (e.g. 127.0.0.1:5514)
        #[arg(long, default_value = "127.0.0.1:5514")]
        target: String,

        /// Transport protocol
        #[arg(long, default_value = "udp", value_enum)]
        protocol: Protocol,

        /// Number of concurrent sender tasks
        #[arg(short, long, default_value = "8")]
        concurrency: usize,

        /// Target EPS per task (0 = max throughput, no rate limiting)
        #[arg(long, default_value = "0")]
        rate: u64,

        /// Duration to run (seconds)
        #[arg(short, long, default_value = "30")]
        duration: u64,
    },

    /// Fetch /healthz and print counters as a tab-separated single line
    ///
    /// Format: udp_rx  tcp_rx  forwarded  channel_full  batches_ok  batches_err  channel_depth
    Snapshot {
        /// healthz URL (e.g. http://127.0.0.1:9999)
        #[arg(long, default_value = "http://127.0.0.1:9999")]
        url: String,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum Protocol {
    Udp,
    Tcp,
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::MockApi { bind, delay_ms } => mock_api(bind, delay_ms).await,
        Cmd::Send {
            target,
            protocol,
            concurrency,
            rate,
            duration,
        } => {
            send(target, protocol, concurrency, rate, duration).await;
        }
        Cmd::Snapshot { url } => snapshot(url).await,
    }
}

// ── Mock API ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct MockState {
    batches: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
    delay_ms: u64,
}

async fn mock_api(bind: String, delay_ms: u64) {
    let state = MockState {
        batches: Arc::new(AtomicU64::new(0)),
        bytes_rx: Arc::new(AtomicU64::new(0)),
        delay_ms,
    };

    let app = Router::new()
        .route("/api/v1/events:ingest", post(ingest_handler))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("mock-api: cannot bind {bind}: {e}"));

    eprintln!("[mock-api] listening on {bind} (delay={delay_ms}ms)");

    // Background stats printer
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(5));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let b = state.batches.load(Relaxed);
            let mb = state.bytes_rx.load(Relaxed) / 1024 / 1024;
            eprintln!("[mock-api] batches={b}  bytes_rx={mb}MB");
        }
    });

    axum::serve(listener, app).await.unwrap();
}

async fn ingest_handler(State(state): State<MockState>, req: Request<Body>) -> impl IntoResponse {
    let content_len = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    // Consume body to avoid connection reset errors in the client
    let _ = axum::body::to_bytes(req.into_body(), usize::MAX).await;

    state.batches.fetch_add(1, Relaxed);
    state.bytes_rx.fetch_add(content_len, Relaxed);

    if state.delay_ms > 0 {
        time::sleep(Duration::from_millis(state.delay_ms)).await;
    }

    (StatusCode::OK, r#"{"status":"ok","ingested":100}"#)
}

// ── Sender ───────────────────────────────────────────────────────────────────

/// Standard syslog RFC3164 datagram — ~105 bytes, realistic payload.
const SYSLOG_MSG: &[u8] = b"<134>Jan  1 00:00:00 perfhost cyberbox-bench: benchmark event payload \
      for collector performance testing run AAAAAAAAAAAAAAAAAAAAAAAAAAAA";

async fn send(target: String, protocol: Protocol, concurrency: usize, rate: u64, duration: u64) {
    let addr: SocketAddr = target
        .parse()
        .unwrap_or_else(|_| panic!("invalid target address: {target}"));

    let sent = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let sent2 = Arc::clone(&sent);
        let stop2 = Arc::clone(&stop);

        let handle = match protocol {
            Protocol::Udp => tokio::spawn(async move {
                send_udp_task(addr, rate, sent2, stop2).await;
            }),
            Protocol::Tcp => tokio::spawn(async move {
                send_tcp_task(addr, rate, sent2, stop2).await;
            }),
        };
        handles.push(handle);
    }

    // Per-second EPS reporter
    let sent3 = Arc::clone(&sent);
    let t_start = Instant::now();
    let mut last = 0u64;
    let mut ticker = time::interval(Duration::from_secs(1));
    ticker.tick().await; // skip immediate tick

    for elapsed in 1..=duration {
        ticker.tick().await;
        let now = sent3.load(Relaxed);
        let delta = now - last;
        last = now;
        eprintln!("[sender] t={elapsed:3}s  eps={delta:>9}  total={now}");
    }

    stop.store(true, Relaxed);
    for h in handles {
        let _ = h.await;
    }

    let total = sent.load(Relaxed);
    let secs = t_start.elapsed().as_secs_f64();
    eprintln!(
        "[sender] done  total={total}  avg_eps={:.0}",
        total as f64 / secs
    );
}

async fn send_udp_task(target: SocketAddr, rate: u64, sent: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();

    // If rate==0 we spin; otherwise we pace per task.
    // delay_ns = 1_000_000_000 / rate  (rate is per-task, not total)
    let delay_ns = if rate == 0 {
        0u64
    } else {
        1_000_000_000 / rate
    };

    loop {
        if stop.load(Relaxed) {
            break;
        }
        let _ = sock.send_to(SYSLOG_MSG, target).await;
        sent.fetch_add(1, Relaxed);
        if delay_ns > 0 {
            time::sleep(Duration::from_nanos(delay_ns)).await;
        }
    }
}

async fn send_tcp_task(target: SocketAddr, rate: u64, sent: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    use tokio::io::AsyncWriteExt;

    let delay_ns = if rate == 0 {
        0u64
    } else {
        1_000_000_000 / rate
    };
    // A newline-terminated syslog line for TCP framing
    let mut msg = SYSLOG_MSG.to_vec();
    msg.push(b'\n');

    loop {
        if stop.load(Relaxed) {
            break;
        }

        let mut stream = match tokio::net::TcpStream::connect(target).await {
            Ok(s) => s,
            Err(_) => {
                time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        // Write until connection drops or stop is set
        loop {
            if stop.load(Relaxed) {
                return;
            }
            match stream.write_all(&msg).await {
                Ok(_) => {
                    sent.fetch_add(1, Relaxed);
                    if delay_ns > 0 {
                        time::sleep(Duration::from_nanos(delay_ns)).await;
                    }
                }
                Err(_) => break, // reconnect
            }
        }
    }
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

async fn snapshot(url: String) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();

    let resp = client
        .get(&url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("snapshot: cannot reach {url}: {e}"));

    let json: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("snapshot: invalid JSON from {url}: {e}"));

    let udp_rx = json["events_received"]["udp"].as_u64().unwrap_or(0);
    let tcp_rx = json["events_received"]["tcp"].as_u64().unwrap_or(0);
    let forwarded = json["events_forwarded"].as_u64().unwrap_or(0);
    let channel_full = json["events_dropped"]["channel_full"].as_u64().unwrap_or(0);
    let batches_ok = json["batches_ok"].as_u64().unwrap_or(0);
    let batches_err = json["batches_err"].as_u64().unwrap_or(0);
    let channel_depth = json["channel_depth"].as_u64().unwrap_or(0);

    // Tab-separated for easy shell consumption
    println!("{udp_rx}\t{tcp_rx}\t{forwarded}\t{channel_full}\t{batches_ok}\t{batches_err}\t{channel_depth}");
}
