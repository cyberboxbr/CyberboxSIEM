//! CyberboxSIEM Collector — library façade.
//!
//! Exposes collector internals for integration tests and external tooling.
//! The binary (`main.rs`) compiles its own private copies of these modules;
//! this crate provides a stable public surface for `cargo test --test …`.

pub mod dlq;
pub mod metrics;
pub mod multiline;
pub mod parser;
pub mod ratelimit;
pub mod sources;
