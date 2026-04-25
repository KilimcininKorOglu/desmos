//! Structured logger with a bounded ring buffer for Web UI tailing.
//!
//! Entries are emitted via the [`log!`] macro. Each entry is filtered
//! by the configured minimum level, written to every registered
//! [`sink::Sink`], and stored in a bounded [`ring::LogRing`] so the
//! Web UI can stream recent history.
//!
//! The logger is process-global. Use [`set_min_level`], [`set_sinks`],
//! and [`snapshot_ring`] to configure and inspect it.

pub mod broadcast_sink;
pub mod redact;
pub mod ring;
pub mod sink;

use core::fmt;
use std::sync::Mutex;
use std::sync::OnceLock;

use self::ring::LogRing;
use self::sink::Sink;
use self::sink::StderrSink;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub level: Level,
    pub target: &'static str,
    pub msg: &'static str,
    pub fields: Vec<(&'static str, String)>,
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "level={} target={} msg={}", self.level.as_str(), self.target, self.msg)?;
        for (k, v) in &self.fields {
            let redacted = redact::redact(k, v);
            write!(f, " {k}={redacted}")?;
        }
        Ok(())
    }
}

struct Logger {
    sinks: Mutex<Vec<Box<dyn Sink>>>,
    ring: Mutex<LogRing>,
    min_level: Mutex<Level>,
}

impl Logger {
    fn new() -> Self {
        Self {
            sinks: Mutex::new(vec![Box::new(StderrSink::new())]),
            ring: Mutex::new(LogRing::with_capacity(500)),
            min_level: Mutex::new(Level::Info),
        }
    }

    fn emit(&self, entry: Entry) {
        if entry.level < *self.min_level.lock().expect("log min_level poisoned") {
            return;
        }
        if let Ok(mut sinks) = self.sinks.lock() {
            for s in sinks.iter_mut() {
                s.write(&entry);
            }
        }
        if let Ok(mut ring) = self.ring.lock() {
            ring.push(entry);
        }
    }
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

fn logger() -> &'static Logger {
    LOGGER.get_or_init(Logger::new)
}

/// Emit a prepared log entry. Normally called by the [`log!`] macro.
pub fn emit(entry: Entry) {
    logger().emit(entry);
}

/// Set the minimum level that will be forwarded to sinks and the ring.
pub fn set_min_level(level: Level) {
    *logger().min_level.lock().expect("log min_level poisoned") = level;
}

/// Replace the sink list. Useful for tests and for wiring an additional
/// Web UI broadcast sink at startup.
pub fn set_sinks(sinks: Vec<Box<dyn Sink>>) {
    *logger().sinks.lock().expect("log sinks poisoned") = sinks;
}

/// Snapshot the current ring buffer contents (oldest first).
pub fn snapshot_ring() -> Vec<Entry> {
    logger().ring.lock().expect("log ring poisoned").snapshot()
}

/// Emit a structured log record.
///
/// ```ignore
/// use desmos_core::log::Level;
/// desmos_core::log!(Level::Info, "tunnel", "up", iface = "eth0", count = 3);
/// ```
#[macro_export]
macro_rules! log {
    ($level:expr, $target:expr, $msg:expr $(, $key:ident = $val:expr)* $(,)?) => {{
        let entry = $crate::log::Entry {
            level: $level,
            target: $target,
            msg: $msg,
            fields: ::std::vec![
                $(
                    (::core::stringify!($key), ::std::format!("{}", $val)),
                )*
            ],
        };
        $crate::log::emit(entry);
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn entry_display_matches_expected_format() {
        let e = Entry {
            level: Level::Info,
            target: "tunnel",
            msg: "up",
            fields: vec![("iface", "eth0".to_string())],
        };
        let s = e.to_string();
        assert!(
            s.contains("level=info target=tunnel msg=up iface=eth0"),
            "unexpected Display output: {s}"
        );
    }

    #[test]
    fn macro_emits_entry_into_ring() {
        let _guard = SERIAL.lock().unwrap();
        set_min_level(Level::Trace);
        set_sinks(vec![]);
        let before = snapshot_ring().len();
        crate::log!(Level::Info, "tunnel", "up", iface = "eth0");
        let snap = snapshot_ring();
        assert!(snap.len() > before, "macro did not push into ring");
        let last = snap.last().unwrap();
        assert_eq!(last.level, Level::Info);
        assert_eq!(last.target, "tunnel");
        assert_eq!(last.msg, "up");
        assert_eq!(last.fields, vec![("iface", "eth0".to_string())]);
    }

    #[test]
    fn min_level_filters_below_threshold() {
        let _guard = SERIAL.lock().unwrap();
        set_sinks(vec![]);
        set_min_level(Level::Warn);
        let before = snapshot_ring().len();
        crate::log!(Level::Info, "tunnel", "suppressed");
        assert_eq!(snapshot_ring().len(), before);
        crate::log!(Level::Error, "tunnel", "passthrough");
        assert!(snapshot_ring().len() > before);
        set_min_level(Level::Trace);
    }
}
