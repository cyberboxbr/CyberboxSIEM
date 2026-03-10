pub mod file;

#[cfg(windows)]
pub mod wineventlog;

#[cfg(target_os = "linux")]
pub mod journald;
