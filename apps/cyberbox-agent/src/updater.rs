//! Agent self-update from GitHub Releases.
//!
//! ## Flow
//! 1. Heartbeat response (or periodic check) includes `latest_version` field.
//! 2. If `latest_version` > current version, download the platform binary from
//!    the GitHub Release asset URL.
//! 3. Write to a temp file next to the current binary, then atomically rename.
//! 4. On Windows: write to `<exe>.update` and schedule a swap on next restart
//!    (in-place rename is blocked while the process is running).
//!    On Linux: rename directly over the running binary (exec can pick it up).
//! 5. Log a notice; the service manager (systemd / Windows SCM) will restart
//!    the agent automatically via `Restart=always`.
//!
//! ## Configuration
//! Set `CYBERBOX_AGENT_UPDATE_URL` to override the default GitHub Releases URL.
//! Default: `https://github.com/<owner>/<repo>/releases/download/v{version}/cyberbox-agent-{target}`

use std::path::PathBuf;

use tracing::{error, info, warn};

const DEFAULT_REPO: &str = "cyberboxsiem/CyberboxSIEM";

/// Check whether `latest` is newer than `current` using simple semver comparison.
pub fn is_newer(current: &str, latest: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.trim_start_matches('v')
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect()
    };
    let c = parse(current);
    let l = parse(latest);
    l > c
}

/// Target triple for the current platform's release asset name.
fn target_asset() -> &'static str {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "cyberbox-agent-x86_64-pc-windows-msvc.exe"
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "cyberbox-agent-x86_64-unknown-linux-musl"
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "cyberbox-agent-aarch64-unknown-linux-musl"
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
    )))]
    {
        "cyberbox-agent-unknown"
    }
}

/// Build the download URL for a specific version.
fn download_url(version: &str) -> String {
    let base = std::env::var("CYBERBOX_AGENT_UPDATE_URL")
        .unwrap_or_else(|_| format!("https://github.com/{DEFAULT_REPO}/releases/download"));
    let tag = if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    };
    format!("{base}/{tag}/{}", target_asset())
}

/// Download and install the new binary. Returns `Ok(true)` if updated.
pub async fn self_update(latest_version: &str) -> anyhow::Result<bool> {
    let current = env!("CARGO_PKG_VERSION");
    if !is_newer(current, latest_version) {
        return Ok(false);
    }

    info!(
        current,
        latest = latest_version,
        "newer agent version available -- downloading"
    );

    let url = download_url(latest_version);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        warn!(status = %resp.status(), %url, "update download failed");
        return Ok(false);
    }

    let bytes = resp.bytes().await?;
    if bytes.len() < 1024 {
        warn!(
            len = bytes.len(),
            "downloaded binary too small -- aborting update"
        );
        return Ok(false);
    }

    let exe = std::env::current_exe()?;

    #[cfg(target_os = "linux")]
    {
        apply_linux(&exe, &bytes, latest_version)?;
    }

    #[cfg(windows)]
    {
        apply_windows(&exe, &bytes, latest_version)?;
    }

    Ok(true)
}

#[cfg(target_os = "linux")]
fn apply_linux(exe: &std::path::Path, bytes: &[u8], version: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let tmp = exe.with_extension("update");
    std::fs::write(&tmp, bytes)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;

    // Atomic rename over the running binary
    std::fs::rename(&tmp, exe)?;
    info!(
        version,
        "agent binary updated -- service manager will restart"
    );
    Ok(())
}

#[cfg(windows)]
fn apply_windows(exe: &std::path::Path, bytes: &[u8], version: &str) -> anyhow::Result<()> {
    // On Windows we can't overwrite a running exe directly.
    // Strategy: rename current → .old, write new → current path.
    let old = exe.with_extension("exe.old");
    let _ = std::fs::remove_file(&old); // clean up previous .old

    // Rename running exe to .old (Windows allows rename of running exe)
    std::fs::rename(exe, &old)?;
    std::fs::write(exe, bytes)?;

    info!(
        version,
        "agent binary updated -- restart the service to apply"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer() {
        assert!(is_newer("0.1.0", "0.2.0"));
        assert!(is_newer("0.1.0", "0.1.1"));
        assert!(is_newer("0.1.0", "1.0.0"));
        assert!(!is_newer("0.2.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(is_newer("v0.1.0", "v0.2.0"));
    }

    #[test]
    fn test_target_asset() {
        let asset = target_asset();
        assert!(asset.starts_with("cyberbox-agent-"));
    }
}
