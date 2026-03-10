pub mod cloud;
pub mod gelf;
pub mod json_input;
pub mod netflow;
pub mod otlp;
pub mod tail;
pub mod tcp;
pub mod udp;

#[cfg(feature = "kafka")]
pub mod kafka;

#[cfg(windows)]
pub mod wineventlog;
