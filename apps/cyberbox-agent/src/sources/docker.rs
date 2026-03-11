//! Docker container event source (Linux only).
//!
//! Connects to the Docker daemon via `/var/run/docker.sock` and subscribes
//! to the event stream.  Emits structured JSON events for container lifecycle
//! actions (start, stop, die, kill, exec, oom, etc.).
//!
//! ## Events emitted
//! | `docker_action` | Description                      | MITRE        |
//! |-----------------|----------------------------------|--------------|
//! | `start`         | Container started                | T1610        |
//! | `die`           | Container exited                 |              |
//! | `kill`          | Container killed (signal)        | T1489        |
//! | `stop`          | Container stopped                |              |
//! | `exec_start`    | Exec session started in container| T1059        |
//! | `exec_die`      | Exec session ended               |              |
//! | `oom`           | Out of memory killed             |              |
//! | `create`        | Container created                |              |
//! | `destroy`       | Container removed                | T1070.004    |
//! | `attach`        | Attached to container            |              |
//! | `pause`/`unpause`| Container paused/resumed        |              |
//!
//! ## Configuration
//! ```toml
//! [[source]]
//! type        = "docker"
//! socket_path = "/var/run/docker.sock"   # default
//! ```
//!
//! Requires the Docker socket to be mounted (see packaging/docker/Dockerfile).

use std::io::{BufRead, BufReader, Read, Write as IoWrite};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use chrono::Utc;
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

// -- Entry point --------------------------------------------------------------

pub async fn run(
    socket_path: String,
    tenant_id:   String,
    hostname:    String,
    tx:          mpsc::Sender<Value>,
    mut shutdown: watch::Receiver<bool>,
) {
    info!(socket = %socket_path, "docker event source starting");

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }

        // Run the blocking docker event stream in a spawn_blocking
        let sp   = socket_path.clone();
        let tid  = tenant_id.clone();
        let host = hostname.clone();
        let tx2  = tx.clone();
        let sd   = shutdown.clone();

        let handle = tokio::task::spawn_blocking(move || {
            stream_events(&sp, &tid, &host, &tx2, &sd);
        });

        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = handle => {
                warn!("docker event stream disconnected -- reconnecting in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

// -- Event stream via raw HTTP over Unix socket --------------------------------
// We use raw HTTP instead of bollard to avoid a heavy dependency.
// The Docker API events endpoint is simple enough for raw HTTP/1.1.

fn stream_events(
    socket_path: &str,
    tenant_id:   &str,
    hostname:    &str,
    tx:          &mpsc::Sender<Value>,
    shutdown:    &watch::Receiver<bool>,
) {
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(e) => {
            error!(socket = socket_path, %e, "cannot connect to Docker socket");
            return;
        }
    };

    // Set a read timeout so we can check shutdown periodically
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    // Send HTTP request for streaming events
    let request = "GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
    if stream.write_all(request.as_bytes()).is_err() {
        return;
    }

    let mut reader = BufReader::new(stream);

    // Skip HTTP response headers
    let mut header_line = String::new();
    loop {
        header_line.clear();
        match reader.read_line(&mut header_line) {
            Ok(0) => return,
            Ok(_) => {
                if header_line.trim().is_empty() {
                    break; // end of headers
                }
            }
            Err(_) => return,
        }
    }

    info!(socket = socket_path, "connected to Docker event stream");

    // Docker streams chunked transfer encoding: read chunk-size then chunk-data
    loop {
        if *shutdown.borrow() {
            return;
        }

        // Read chunk size line
        let mut size_line = String::new();
        match reader.read_line(&mut size_line) {
            Ok(0) => return,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    continue; // timeout, check shutdown and retry
                }
                debug!(%e, "docker stream read error");
                return;
            }
            Ok(_) => {}
        }

        let chunk_size = match usize::from_str_radix(size_line.trim(), 16) {
            Ok(0) => return, // stream ended
            Ok(n) => n,
            Err(_) => continue,
        };

        // Read chunk data
        let mut chunk = vec![0u8; chunk_size];
        if reader.read_exact(&mut chunk).is_err() {
            return;
        }

        // Consume trailing \r\n
        let mut trail = [0u8; 2];
        let _ = reader.read_exact(&mut trail);

        // Parse the JSON event
        if let Ok(docker_ev) = serde_json::from_slice::<Value>(&chunk) {
            if let Some(ev) = normalize_docker_event(&docker_ev, tenant_id, hostname) {
                if tx.blocking_send(ev).is_err() {
                    return;
                }
            }
        }
    }
}

// -- Normalize Docker event to CyberboxSIEM format ----------------------------

fn normalize_docker_event(raw: &Value, tenant_id: &str, hostname: &str) -> Option<Value> {
    let action = raw.get("Action").or_else(|| raw.get("status"))?.as_str()?;
    let ev_type = raw.get("Type").and_then(|v| v.as_str()).unwrap_or("container");

    // Only emit container events (skip image/network/volume events)
    if ev_type != "container" {
        return None;
    }

    let actor = raw.get("Actor").or_else(|| raw.get("actor")).cloned().unwrap_or(json!({}));
    let attrs = actor.get("Attributes").or_else(|| actor.get("attributes"))
        .cloned().unwrap_or(json!({}));

    let container_id = actor.get("ID").or_else(|| actor.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars().take(12).collect::<String>();

    let image = attrs.get("image").and_then(|v| v.as_str()).unwrap_or("");
    let name  = attrs.get("name").and_then(|v| v.as_str()).unwrap_or("");

    let timestamp = raw.get("time").or_else(|| raw.get("timeNano"))
        .and_then(|v| v.as_i64())
        .map(|t| chrono::DateTime::from_timestamp(t, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| Utc::now().to_rfc3339()))
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let mitre = match action {
        "start"                    => "T1610",
        "exec_start" | "exec_die" => "T1059",
        "kill"                     => "T1489",
        "destroy"                  => "T1070.004",
        _                          => "",
    };

    // Extract exec command if present
    let exec_command = attrs.get("execID").and_then(|v| v.as_str()).unwrap_or("");

    // Extract exit code for die events
    let exit_code = attrs.get("exitCode").and_then(|v| v.as_str()).unwrap_or("");

    // Extract signal for kill events
    let signal = attrs.get("signal").and_then(|v| v.as_str()).unwrap_or("");

    Some(json!({
        "tenant_id":  tenant_id,
        "source":     "docker",
        "event_time": timestamp,
        "raw_payload": {
            "hostname":         hostname,
            "docker_action":    action,
            "docker_type":      ev_type,
            "container_id":     container_id,
            "container_name":   name,
            "Image":            image,
            "mitre_technique":  mitre,
            "exit_code":        exit_code,
            "signal":           signal,
            "exec_id":          exec_command,
            "attributes":       attrs,
        }
    }))
}
