//! Windows Service integration via the `windows-service` crate.
//!
//! When launched by the Service Control Manager (SCM), the process calls
//! `service_dispatcher::start` which blocks the calling thread.  SCM then
//! invokes `service_main` on a new thread where we:
//!   1. Parse the config path from the service arguments
//!   2. Register a control handler (Stop / Shutdown)
//!   3. Report SERVICE_RUNNING
//!   4. Run the normal agent logic inside a tokio runtime
//!   5. On stop signal, shut down gracefully and report SERVICE_STOPPED

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::SERVICE_NAME;

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Result of trying to start via the SCM dispatcher.
pub enum DispatchResult {
    /// We were started by SCM; service ran to completion.
    RanAsService,
    /// Process was NOT started by SCM — fall through to CLI mode.
    NotAService,
}

/// Attempt to connect to SCM.  Returns `RanAsService` if SCM started us,
/// or `NotAService` if we're running as a console app.
pub fn try_dispatch() -> DispatchResult {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => DispatchResult::RanAsService,
        Err(_) => {
            // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063) means we're not
            // running as a service — this is the expected case for console mode.
            // Any other error also means we should fall through to CLI.
            DispatchResult::NotAService
        }
    }
}

// The macro creates the FFI-safe `ffi_service_main` function that bridges
// to our `service_main`.
define_windows_service!(ffi_service_main, service_main);

/// Static to pass the shutdown sender into the control handler closure.
static SHUTDOWN: OnceLock<tokio::sync::watch::Sender<bool>> = OnceLock::new();

fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        tracing::error!(%e, "service_main failed");
    }
}

fn run_service(arguments: Vec<OsString>) -> Result<(), Box<dyn std::error::Error>> {
    // ── Parse config path from service arguments ─────────────────────────
    // SCM passes the args from the binPath registration:
    //   ["CyberboxAgent", "run", "--config", "C:\ProgramData\Cyberbox\agent.toml"]
    let config_path = parse_config_from_args(&arguments);

    // ── Shutdown channel ─────────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let _ = SHUTDOWN.set(shutdown_tx);

    // ── Register the service control handler ─────────────────────────────
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(tx) = SHUTDOWN.get() {
                    let _ = tx.send(true);
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // ── Report SERVICE_RUNNING ───────────────────────────────────────────
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // ── Build and run the tokio runtime ──────────────────────────────────
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_agent(config_path, shutdown_rx));

    // ── Report SERVICE_STOPPED ───────────────────────────────────────────
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

/// Run the agent logic (same as `cmd_run` but wired to the SCM shutdown signal).
async fn run_agent(
    config_path: Option<PathBuf>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    // Initialize tracing (to Windows Event Log would be ideal, but stderr/file for now)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cyberbox_agent=info".parse().unwrap()),
        )
        .init();

    let path = crate::resolve_config(config_path);
    let cfg = match crate::config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(%e, "failed to load config");
            return;
        }
    };

    tracing::info!(
        host     = %cfg.collector.host,
        port     = cfg.collector.port,
        protocol = %cfg.collector.protocol,
        tenant   = %cfg.agent.tenant_id,
        sources  = cfg.source.len(),
        "cyberbox-agent starting (Windows service)",
    );

    if cfg.source.is_empty() {
        tracing::error!("no sources configured -- add at least one [[source]] block to agent.toml");
        return;
    }

    let hostname = cfg
        .agent
        .hostname
        .clone()
        .unwrap_or_else(crate::detect_hostname);

    let (tx, rx) = tokio::sync::mpsc::channel::<serde_json::Value>(crate::CHANNEL_CAPACITY);
    // Create our own shutdown watch that merges the SCM signal
    let (agent_shutdown_tx, agent_shutdown_rx) = tokio::sync::watch::channel(false);

    // Forward SCM shutdown → agent shutdown
    let mut scm_rx = shutdown_rx.clone();
    let fwd_tx = agent_shutdown_tx.clone();
    tokio::spawn(async move {
        let _ = scm_rx.changed().await;
        let _ = fwd_tx.send(true);
    });

    // Spawn sources
    for src in &cfg.source {
        crate::spawn_source(
            src,
            &cfg,
            hostname.clone(),
            tx.clone(),
            agent_shutdown_rx.clone(),
        );
    }

    // Spawn output
    let token = cfg
        .collector
        .token
        .clone()
        .or_else(|| std::env::var("CYBERBOX_AGENT_TOKEN").ok());

    let queue_path = cfg
        .collector
        .queue_path
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(crate::default_queue_path);

    let out_cfg = crate::output::OutputConfig {
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

    let out_sd = agent_shutdown_rx.clone();
    let output_handle = tokio::spawn(crate::output::run(rx, out_cfg, out_sd));

    // Agent registration + heartbeat (optional)
    if let Some(api_cfg) = &cfg.api {
        let reg_cfg = crate::registration::RegistrationConfig {
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
            reload_tx: None,
        };
        tokio::spawn(crate::registration::run(reg_cfg, agent_shutdown_rx.clone()));
    }

    // Wait for SCM stop signal
    let _ = shutdown_rx.changed().await;
    tracing::info!("SCM stop signal received — shutting down");
    let _ = agent_shutdown_tx.send(true);
    let _ = output_handle.await;
    tracing::info!("cyberbox-agent stopped");
}

/// Parse `--config <path>` from the service arguments.
/// SCM passes: ["ServiceName", "run", "--config", "C:\path\to\agent.toml"]
fn parse_config_from_args(args: &[OsString]) -> Option<PathBuf> {
    let strs: Vec<String> = args
        .iter()
        .filter_map(|a| a.to_str().map(String::from))
        .collect();

    for (i, arg) in strs.iter().enumerate() {
        if (arg == "--config" || arg == "-c") && i + 1 < strs.len() {
            return Some(PathBuf::from(&strs[i + 1]));
        }
    }
    None
}
