//! Multiline event accumulator.
//!
//! Coalesces successive log lines into a single event according to a regex
//! continuation rule — useful for Java stack traces, Python tracebacks, and
//! any log format where a single logical event spans multiple physical lines.
//!
//! # Continuation modes
//!
//! | `negate` | Pattern matches start-of-line | Behaviour |
//! |----------|-------------------------------|-----------|
//! | `false`  | New event starts              | Default — any line matching the pattern begins a fresh event |
//! | `true`   | Continuation line             | Any line that does *not* match is appended to the current event |
//!
//! # Common patterns
//!
//! | Use case | Pattern | Negate |
//! |---|---|---|
//! | Java stack traces | `^\s+at ` | `true` (lines starting with whitespace are continuations) |
//! | Syslog (new event = `<PRI>`) | `^<\d+>` | `false` |
//! | RFC 5424 | `^<\d+>1 ` | `false` |
//! | Python tracebacks | `^Traceback` | `false` |

use std::time::{Duration, Instant};
use regex::Regex;

// ─── Config ───────────────────────────────────────────────────────────────────

pub struct MultilineConfig {
    /// When `Some`, drives multiline logic.  `None` = pass-through (disabled).
    pub pattern:    Option<Regex>,
    /// When `true`, a line that does NOT match starts a new event (continuation mode).
    pub negate:     bool,
    /// Flush accumulated buffer if it reaches this many lines.
    pub max_lines:  usize,
    /// Flush incomplete buffer after this many ms of silence.
    pub timeout_ms: u64,
}

impl Default for MultilineConfig {
    fn default() -> Self {
        Self { pattern: None, negate: false, max_lines: 500, timeout_ms: 2_000 }
    }
}

impl MultilineConfig {
    pub fn is_enabled(&self) -> bool { self.pattern.is_some() }
}

// ─── Accumulator ──────────────────────────────────────────────────────────────

pub struct MultilineAccumulator {
    cfg:       MultilineConfig,
    buf:       Vec<String>,
    last_seen: Option<Instant>,
}

impl MultilineAccumulator {
    pub fn new(cfg: MultilineConfig) -> Self {
        Self { cfg, buf: Vec::new(), last_seen: None }
    }

    /// Feed one log line. Returns `Some(complete_event_string)` when a complete
    /// multi-line event is ready; returns `None` when more lines are needed.
    pub fn feed(&mut self, line: String) -> Option<String> {
        // Passthrough when multiline is disabled
        if !self.cfg.is_enabled() {
            return Some(line);
        }

        let pat       = self.cfg.pattern.as_ref().unwrap();
        let matches   = pat.is_match(&line);
        let is_new    = if self.cfg.negate { !matches } else { matches };

        self.last_seen = Some(Instant::now());

        if is_new && !self.buf.is_empty() {
            // Current buffer is complete — flush it, start new event
            let complete = self.drain();
            self.buf.push(line);
            return Some(complete);
        }

        self.buf.push(line);

        // Safety cap: flush if we hit max_lines
        if self.buf.len() >= self.cfg.max_lines {
            return Some(self.drain());
        }

        None
    }

    /// Call periodically (e.g. every flush tick) to surface events that have
    /// been silent for longer than `timeout_ms`.
    pub fn tick(&mut self) -> Option<String> {
        if self.buf.is_empty() { return None; }
        let timeout = Duration::from_millis(self.cfg.timeout_ms);
        if self.last_seen.map(|t| t.elapsed() >= timeout).unwrap_or(false) {
            return Some(self.drain());
        }
        None
    }

    fn drain(&mut self) -> String {
        let out = self.buf.join("\n");
        self.buf.clear();
        out
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn acc_with_pattern(pattern: &str, negate: bool) -> MultilineAccumulator {
        MultilineAccumulator::new(MultilineConfig {
            pattern:    Some(Regex::new(pattern).unwrap()),
            negate,
            max_lines:  500,
            timeout_ms: 2_000,
        })
    }

    #[test]
    fn passthrough_when_disabled() {
        let mut acc = MultilineAccumulator::new(MultilineConfig::default());
        assert_eq!(acc.feed("line1".into()), Some("line1".into()));
        assert_eq!(acc.feed("line2".into()), Some("line2".into()));
    }

    #[test]
    fn java_stacktrace_continuation() {
        // negate=true, pattern=`^\s` — lines NOT starting with whitespace begin a new event
        let mut acc = acc_with_pattern(r"^\s", true);

        // Exception line = start of new event
        assert_eq!(acc.feed("java.lang.NullPointerException".into()), None);
        assert_eq!(acc.feed("\tat com.example.Foo.bar(Foo.java:42)".into()), None);
        assert_eq!(acc.feed("\tat com.example.App.main(App.java:10)".into()), None);
        // Next non-whitespace line flushes the buffer and starts a new event
        let complete = acc.feed("INFO: startup complete".into()).unwrap();
        assert!(complete.contains("NullPointerException"));
        assert!(complete.contains("Foo.java:42"));
    }

    #[test]
    fn syslog_pri_as_new_event_boundary() {
        let mut acc = acc_with_pattern(r"^<\d+>", false);

        assert_eq!(acc.feed("<30>first event".into()), None);
        // Second PRI flushes first event
        let complete = acc.feed("<31>second event".into()).unwrap();
        assert_eq!(complete, "<30>first event");
    }

    #[test]
    fn max_lines_cap() {
        let mut acc = MultilineAccumulator::new(MultilineConfig {
            pattern:    Some(Regex::new(r"^START").unwrap()),
            negate:     false,
            max_lines:  3,
            timeout_ms: 9_999,
        });

        acc.feed("START".into());
        acc.feed("line2".into());
        // Third line hits cap → flushes
        let out = acc.feed("line3".into()).unwrap();
        assert_eq!(out, "START\nline2\nline3");
    }

    #[test]
    fn tick_flushes_after_timeout() {
        let mut acc = MultilineAccumulator::new(MultilineConfig {
            pattern:    Some(Regex::new(r"^START").unwrap()),
            negate:     false,
            max_lines:  500,
            timeout_ms: 0, // immediate timeout
        });
        acc.feed("START".into());
        acc.feed("cont".into());
        // With timeout_ms=0 any elapsed time qualifies
        assert!(acc.tick().is_some());
    }
}
