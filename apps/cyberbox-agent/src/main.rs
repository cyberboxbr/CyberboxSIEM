//! # cyberbox-agent
//!
//! Lightweight log-forwarding agent for CyberboxSIEM.
//! Collects local logs and forwards them to a central `cyberbox-collector`.
//!
//! ## Usage
//! ```text
//! cyberbox-agent run      [--config agent.toml]  # start collecting
//! cyberbox-agent validate [--config agent.toml]  # parse config and exit
//! cyberbox-agent install  [--config agent.toml]  # register as OS service
//! cyberbox-agent uninstall                       # remove OS service
//! ```
//!
//! ## Default config search path
//! 1. `--config <path>` argument
//! 2. `./agent.toml`                    (same dir as the executable)
//! 3. `/etc/cyberbox/agent.toml`        (Linux)
//! 4. `%ProgramData%\Cyberbox\agent.toml` (Windows)
//!
//! ## Sources (configured in `agent.toml`)
//! | type | platforms | description |
//! |------|-----------|-------------|
//! | `file` | all | tail one or more log files |
//! | `wineventlog` | Windows | Windows Event Log channels |
//! | `sysmon` | Windows | Sysmon (26 event types, MITRE-tagged) |
//! | `journald` | Linux | systemd journal via `journalctl` |
//! | `procmon` | Linux | /proc process create/terminate |
//! | `fim` | all | file integrity monitoring |
//!
//! ## Output
//! Connects to the collector's JSON TCP port (`COLLECTOR_JSON_TCP_BIND`) or
//! syslog TCP port (`COLLECTOR_TCP_BIND`).  Reconnects automatically on
//! failure and persists events to a disk-backed queue (sled).

use std::path::PathBuf;
#[cfg(windows)]
use std::sync::Arc;

use clap::{Parser, Subcommand};
use serde_json::Value;
use tokio::sync::{mpsc, watch};
use tracing::{error, info};

mod config;
mod disk_queue;
mod output;
mod registration;
#[cfg(windows)]
mod service_windows;
mod sources;
mod updater;

use config::{AgentConfig, SourceConfig};

#[allow(dead_code)] // used in platform-specific install/uninstall functions
const SERVICE_NAME: &str = "CyberboxAgent";
#[allow(dead_code)]
const SERVICE_DISPLAY: &str = "Cyberbox SIEM Agent";
const CHANNEL_CAPACITY: usize = 10_000;

// -- CLI ----------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "cyberbox-agent",
    about = "Cyberbox SIEM log-forwarding agent",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the agent (foreground; use `install` to run as a service)
    Run {
        #[arg(long, short, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Validate configuration and exit
    Validate {
        #[arg(long, short, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Install and start as a system service (Windows Service / systemd)
    Install {
        #[arg(long, short, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Stop and remove the system service
    Uninstall,
}

// -- Entry point --------------------------------------------------------------

fn main() {
    // On Windows, try starting as a Windows service first.
    // If the process was launched by SCM, `try_dispatch()` blocks until the
    // service stops, then returns `RanAsService`.  If launched from the
    // console, it returns `NotAService` and we fall through to normal CLI.
    #[cfg(windows)]
    {
        use service_windows::DispatchResult;
        match service_windows::try_dispatch() {
            DispatchResult::RanAsService => return,
            DispatchResult::NotAService => { /* fall through to CLI */ }
        }
    }

    // Console / CLI mode
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async_main());
}

async fn async_main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cyberbox_agent=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { config } => cmd_run(config).await,
        Cmd::Validate { config } => cmd_validate(config),
        Cmd::Install { config } => cmd_install(config),
        Cmd::Uninstall => cmd_uninstall(),
    }
}

// -- `run` --------------------------------------------------------------------

async fn cmd_run(config_path: Option<PathBuf>) {
    let path = resolve_config(config_path);
    let cfg = config::load(&path).unwrap_or_else(|e| {
        error!("{e}");
        std::process::exit(1);
    });

    info!(
        host     = %cfg.collector.host,
        port     = cfg.collector.port,
        protocol = %cfg.collector.protocol,
        tenant   = %cfg.agent.tenant_id,
        sources  = cfg.source.len(),
        "cyberbox-agent starting",
    );

    let hostname = cfg.agent.hostname.clone().unwrap_or_else(detect_hostname);

    let (tx, rx) = mpsc::channel::<Value>(CHANNEL_CAPACITY);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // -- Spawn sources --------------------------------------------------------
    for src in &cfg.source {
        spawn_source(src, &cfg, hostname.clone(), tx.clone(), shutdown_rx.clone());
    }

    if cfg.source.is_empty() {
        error!("no sources configured -- add at least one [[source]] block to agent.toml");
        std::process::exit(1);
    }

    // -- Spawn output ---------------------------------------------------------
    // Token: config file > CYBERBOX_AGENT_TOKEN env var
    let token = cfg
        .collector
        .token
        .clone()
        .or_else(|| std::env::var("CYBERBOX_AGENT_TOKEN").ok());

    // Resolve disk queue path: config > platform default
    let queue_path = cfg
        .collector
        .queue_path
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(default_queue_path);

    let out_cfg = output::OutputConfig {
        host: cfg.collector.host.clone(),
        port: cfg.collector.port,
        protocol: cfg.collector.protocol.clone(),
        tls: cfg.collector.tls,
        tls_ca: cfg.collector.tls_ca.clone(),
        token,
        backoff_max_secs: cfg.collector.backoff_max_secs,
        buffer_size: cfg.collector.buffer_size,
        hostname: hostname.clone(),
        app_name: cfg.agent.app_name.clone(),
        tenant_id: cfg.agent.tenant_id.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        queue_path,
    };

    let out_sd = shutdown_rx.clone();
    let output_handle = tokio::spawn(output::run(rx, out_cfg, out_sd));

    // -- Reload channel (signalled by heartbeat when pending_config arrives) ---
    let (reload_tx, mut reload_rx) = watch::channel(false);

    // -- Agent registration + heartbeat (optional) ----------------------------
    if let Some(api_cfg) = &cfg.api {
        let reg_cfg = registration::RegistrationConfig {
            api_url: api_cfg.url.clone(),
            token: api_cfg.token.clone(),
            enrollment_token: api_cfg.enrollment_token.clone(),
            agent_secret: api_cfg.agent_secret.clone(),
            device_certificate: api_cfg.device_certificate.clone(),
            heartbeat_secs: api_cfg.heartbeat_secs,
            credential_rotation_secs: api_cfg.credential_rotation_secs,
            agent_id: hostname.clone(),
            hostname: hostname.clone(),
            tenant_id: cfg.agent.tenant_id.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            config_path: path.clone(),
            reload_tx: Some(reload_tx),
        };
        tokio::spawn(registration::run(reg_cfg, shutdown_rx.clone()));
    }

    // -- Main event loop: handle Ctrl-C and live-reload -----------------------
    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                let _ = shutdown_tx.send(true);
                let _ = output_handle.await;
                info!("cyberbox-agent stopped");
                return;
            }
            _ = reload_rx.changed() => {
                info!("live config reload triggered -- re-reading agent.toml");
                match config::load(&path) {
                    Ok(new_cfg) => {
                        info!(
                            sources = new_cfg.source.len(),
                            "config reloaded -- spawning new sources"
                        );
                        for src in &new_cfg.source {
                            spawn_source(
                                src, &new_cfg,
                                hostname.clone(),
                                tx.clone(),
                                shutdown_rx.clone(),
                            );
                        }
                    }
                    Err(e) => {
                        error!(%e, "config reload failed -- keeping current config");
                    }
                }
            }
        }
    }
}

// -- `validate` ---------------------------------------------------------------

fn cmd_validate(config_path: Option<PathBuf>) {
    let path = resolve_config(config_path);
    match config::load(&path) {
        Ok(cfg) => {
            println!(
                "Config OK: {} source(s), collector={}:{}",
                cfg.source.len(),
                cfg.collector.host,
                cfg.collector.port
            );
        }
        Err(e) => {
            eprintln!("Config error: {e}");
            std::process::exit(1);
        }
    }
}

// -- `install` / `uninstall` --------------------------------------------------

fn cmd_install(config_path: Option<PathBuf>) {
    let config_abs = resolve_config(config_path);
    let config_abs = config_abs.canonicalize().unwrap_or(config_abs);
    let exe = std::env::current_exe().expect("cannot determine executable path");

    #[cfg(windows)]
    install_windows(&exe, &config_abs);

    #[cfg(target_os = "linux")]
    install_linux(&exe, &config_abs);

    #[cfg(not(any(windows, target_os = "linux")))]
    eprintln!("Service installation is only supported on Windows and Linux.");
}

fn cmd_uninstall() {
    #[cfg(windows)]
    uninstall_windows();

    #[cfg(target_os = "linux")]
    uninstall_linux();

    #[cfg(not(any(windows, target_os = "linux")))]
    eprintln!("Service removal is only supported on Windows and Linux.");
}

// -- Windows service management -----------------------------------------------

#[cfg(windows)]
fn install_windows(exe: &std::path::Path, config: &std::path::Path) {
    use std::process::Command;

    let bin_path = format!(
        "\"{}\" run --config \"{}\"",
        exe.display(),
        config.display()
    );

    println!("Installing Windows Service '{SERVICE_NAME}'...");

    let status = Command::new("sc")
        .args([
            "create",
            SERVICE_NAME,
            "binPath=",
            &bin_path,
            "DisplayName=",
            SERVICE_DISPLAY,
            "start=",
            "auto",
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("Service created.  Starting...");
            let _ = Command::new("sc").args(["start", SERVICE_NAME]).status();
            println!("Done.  Check status with: sc query {SERVICE_NAME}");
        }
        Ok(_) => eprintln!("sc create failed -- try running as Administrator"),
        Err(e) => eprintln!("Failed to run sc.exe: {e}"),
    }
}

#[cfg(windows)]
fn uninstall_windows() {
    use std::process::Command;
    println!("Stopping and removing Windows Service '{SERVICE_NAME}'...");
    let _ = Command::new("sc").args(["stop", SERVICE_NAME]).status();
    let _ = Command::new("sc").args(["delete", SERVICE_NAME]).status();
    println!("Done.");
}

// -- Linux systemd management -------------------------------------------------

#[cfg(target_os = "linux")]
fn install_linux(exe: &std::path::Path, config: &std::path::Path) {
    use std::process::Command;

    let unit = format!(
        "[Unit]\n\
         Description={SERVICE_DISPLAY}\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} run --config {config}\n\
         Restart=always\n\
         RestartSec=5\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe = exe.display(),
        config = config.display(),
    );

    let unit_path = "/etc/systemd/system/cyberbox-agent.service";
    println!("Writing {unit_path}...");

    if let Err(e) = std::fs::write(unit_path, &unit) {
        eprintln!("Cannot write {unit_path}: {e} -- try running as root");
        return;
    }

    println!("Running systemctl daemon-reload + enable --now...");
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    let _ = Command::new("systemctl")
        .args(["enable", "--now", "cyberbox-agent"])
        .status();
    println!("Done.  Check status with: systemctl status cyberbox-agent");
}

#[cfg(target_os = "linux")]
fn uninstall_linux() {
    use std::process::Command;
    println!("Stopping and disabling cyberbox-agent...");
    let _ = Command::new("systemctl")
        .args(["stop", "cyberbox-agent"])
        .status();
    let _ = Command::new("systemctl")
        .args(["disable", "cyberbox-agent"])
        .status();
    let _ = std::fs::remove_file("/etc/systemd/system/cyberbox-agent.service");
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    println!("Done.");
}

// -- Source spawning ----------------------------------------------------------

pub(crate) fn spawn_source(
    src: &SourceConfig,
    cfg: &AgentConfig,
    hostname: String,
    tx: mpsc::Sender<Value>,
    sd: watch::Receiver<bool>,
) {
    let tenant = cfg.agent.tenant_id.clone();

    match src.clone() {
        SourceConfig::File {
            paths,
            poll_ms,
            bookmark_path,
        } => {
            let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
            let bookmark = PathBuf::from(bookmark_path);
            tokio::spawn(sources::file::run(
                paths, poll_ms, bookmark, tenant, hostname, tx, sd,
            ));
            info!("file tail source started");
        }

        #[cfg(windows)]
        SourceConfig::Wineventlog { channels } => {
            let tid = Arc::new(tenant);
            let host = Arc::new(hostname);
            tokio::spawn(sources::wineventlog::run(channels, tid, host, tx));
            info!("Windows Event Log source started");
        }

        #[cfg(not(windows))]
        SourceConfig::Wineventlog { .. } => {
            error!("wineventlog source is only supported on Windows -- skipping");
        }

        #[cfg(target_os = "linux")]
        SourceConfig::Journald { units } => {
            tokio::spawn(sources::journald::run(units, tenant, hostname, tx, sd));
            info!("journald source started");
        }

        #[cfg(not(target_os = "linux"))]
        SourceConfig::Journald { .. } => {
            error!("journald source is only supported on Linux -- skipping");
        }

        SourceConfig::Fim {
            paths,
            scan_interval_secs,
            recursive,
            baseline_path,
        } => {
            let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
            let baseline = PathBuf::from(baseline_path);
            tokio::spawn(sources::fim::run(
                paths,
                scan_interval_secs,
                recursive,
                baseline,
                tenant,
                hostname,
                tx,
                sd,
            ));
            info!("FIM source started");
        }

        #[cfg(windows)]
        SourceConfig::Sysmon => {
            let tid = Arc::new(tenant);
            let host = Arc::new(hostname);
            tokio::spawn(sources::sysmon::run(tid, host, tx));
            info!("Sysmon source started");
        }

        #[cfg(not(windows))]
        SourceConfig::Sysmon => {
            error!("sysmon source is only supported on Windows -- skipping");
        }

        #[cfg(target_os = "linux")]
        SourceConfig::Procmon { poll_ms } => {
            tokio::spawn(sources::procmon::run(poll_ms, tenant, hostname, tx, sd));
            info!("procmon source started");
        }

        #[cfg(not(target_os = "linux"))]
        SourceConfig::Procmon { .. } => {
            error!("procmon source is only supported on Linux -- skipping");
        }

        #[cfg(target_os = "linux")]
        SourceConfig::Docker { socket_path } => {
            tokio::spawn(sources::docker::run(socket_path, tenant, hostname, tx, sd));
            info!("docker events source started");
        }

        #[cfg(not(target_os = "linux"))]
        SourceConfig::Docker { .. } => {
            error!("docker source is only supported on Linux -- skipping");
        }

        #[cfg(target_os = "linux")]
        SourceConfig::Netconn { poll_ms } => {
            tokio::spawn(sources::netconn::run(poll_ms, tenant, hostname, tx, sd));
            info!("netconn source started");
        }

        #[cfg(not(target_os = "linux"))]
        SourceConfig::Netconn { .. } => {
            error!("netconn source is only supported on Linux -- skipping");
        }
    }
}

// -- Utilities ----------------------------------------------------------------

pub(crate) fn resolve_config(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }

    // Same directory as the executable
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe.parent().unwrap_or(&exe).join("agent.toml");
        if candidate.exists() {
            return candidate;
        }
    }

    // Current working directory
    let cwd = PathBuf::from("agent.toml");
    if cwd.exists() {
        return cwd;
    }

    // Platform-specific system path
    #[cfg(target_os = "linux")]
    {
        let sys = PathBuf::from("/etc/cyberbox/agent.toml");
        if sys.exists() {
            return sys;
        }
    }

    #[cfg(windows)]
    {
        if let Some(pd) = std::env::var_os("ProgramData") {
            let sys = PathBuf::from(pd).join("Cyberbox").join("agent.toml");
            if sys.exists() {
                return sys;
            }
        }
    }

    // Fallback
    PathBuf::from("agent.toml")
}

pub(crate) fn default_queue_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(pd) = std::env::var_os("ProgramData") {
            return PathBuf::from(pd).join("Cyberbox").join("queue");
        }
    }
    #[cfg(target_os = "linux")]
    return PathBuf::from("/var/lib/cyberbox/queue");

    // Fallback: next to the executable (used on Windows when ProgramData is unset,
    // and on non-Linux/non-Windows platforms)
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.join("cyberbox-queue")))
            .unwrap_or_else(|| PathBuf::from("cyberbox-queue"))
    }
}

pub(crate) fn detect_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown-host".to_string())
        })
}
