//! Minimal structured logger modelled after the zerolog console format used
//! by the original Go implementation:
//!
//! `LVL TIMESTAMP TRACE_ID [scope] local_scope; message; key=value ...`

use std::fmt;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Disabled = 5,
}

pub const LEVEL_VALUES: &[&str] = &["info", "warn", "trace", "error", "debug", "disabled"];

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        match s {
            "trace" => Some(Level::Trace),
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" => Some(Level::Warn),
            "error" => Some(Level::Error),
            "disabled" => Some(Level::Disabled),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "trace",
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
            Level::Disabled => "disabled",
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Level::Trace => "TRC",
            Level::Debug => "DBG",
            Level::Info => "INF",
            Level::Warn => "WRN",
            Level::Error => "ERR",
            Level::Disabled => "???",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Level::Trace => "\x1b[35m",
            Level::Debug => "\x1b[33m",
            Level::Info => "\x1b[32m",
            Level::Warn => "\x1b[31m",
            Level::Error => "\x1b[1;31m",
            Level::Disabled => "",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static WRITE_DELAY_MS: AtomicU64 = AtomicU64::new(0);

enum Sink {
    Stdout { color: bool },
    Channel(mpsc::Sender<String>),
}

fn sink() -> &'static Mutex<Sink> {
    static SINK: OnceLock<Mutex<Sink>> = OnceLock::new();
    SINK.get_or_init(|| Mutex::new(Sink::Stdout { color: false }))
}

pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn level() -> Level {
    match LEVEL.load(Ordering::Relaxed) {
        0 => Level::Trace,
        1 => Level::Debug,
        2 => Level::Info,
        3 => Level::Warn,
        4 => Level::Error,
        _ => Level::Disabled,
    }
}

/// Sends log lines to stdout. ANSI colors are used only when stdout is a
/// terminal that understands them.
pub fn use_stdout() {
    #[cfg(windows)]
    let ansi = crossterm::ansi_support::supports_ansi();
    #[cfg(not(windows))]
    let ansi = true;
    let color = std::io::stdout().is_terminal() && ansi;
    *sink().lock().unwrap() = Sink::Stdout { color };
}

/// Sends plain (uncolored) log lines to the given channel, e.g. the TUI.
pub fn use_channel(tx: mpsc::Sender<String>) {
    *sink().lock().unwrap() = Sink::Channel(tx);
}

/// Delays every log write, used for the start-up "typing" effect.
pub fn set_write_delay(d: Duration) {
    WRITE_DELAY_MS.store(d.as_millis() as u64, Ordering::Relaxed);
}

pub fn new_trace_id() -> Arc<str> {
    let v: u64 = rand::random();
    Arc::from(format!("{v:016x}"))
}

#[derive(Clone)]
pub struct Logger {
    scope: &'static str,
    trace: Option<Arc<str>>,
    local: Option<&'static str>,
}

impl Logger {
    pub fn new(scope: &'static str) -> Self {
        Self {
            scope,
            trace: None,
            local: None,
        }
    }

    pub fn scoped(&self, scope: &'static str) -> Self {
        Self {
            scope,
            trace: self.trace.clone(),
            local: self.local,
        }
    }

    pub fn with_trace(&self, trace: &Arc<str>) -> Self {
        Self {
            scope: self.scope,
            trace: Some(trace.clone()),
            local: self.local,
        }
    }

    pub fn local(&self, local: &'static str) -> Self {
        Self {
            scope: self.scope,
            trace: self.trace.clone(),
            local: Some(local),
        }
    }

    #[inline]
    pub fn enabled(&self, lvl: Level) -> bool {
        lvl != Level::Disabled && lvl >= level()
    }

    pub fn emit(&self, lvl: Level, msg: fmt::Arguments<'_>, fields: &[(&str, String)]) {
        if !self.enabled(lvl) {
            return;
        }

        let ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z");
        let trace = self.trace.as_deref().unwrap_or("0000000000000000");
        let mut body = String::with_capacity(128);
        use fmt::Write as _;
        if let Some(local) = self.local {
            let _ = write!(body, "{local}; ");
        }
        let msg = msg.to_string();
        if !msg.is_empty() {
            let _ = write!(body, "{msg};");
        }

        let delay = WRITE_DELAY_MS.load(Ordering::Relaxed);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }

        let guard = sink().lock().unwrap();
        match &*guard {
            Sink::Stdout { color } => {
                let mut line = String::with_capacity(body.len() + 64);
                if *color {
                    let _ = write!(
                        line,
                        "{}{}\x1b[0m \x1b[90m{ts}\x1b[0m {trace} [{}] {body}",
                        lvl.color(),
                        lvl.tag(),
                        self.scope
                    );
                    for (k, v) in fields {
                        let _ = write!(line, " \x1b[36m{k}=\x1b[0m{v}");
                    }
                } else {
                    let _ = write!(line, "{} {ts} {trace} [{}] {body}", lvl.tag(), self.scope);
                    for (k, v) in fields {
                        let _ = write!(line, " {k}={v}");
                    }
                }
                let mut out = std::io::stdout().lock();
                let _ = writeln!(out, "{line}");
            }
            Sink::Channel(tx) => {
                let mut line = format!("{} {ts} {trace} [{}] {body}", lvl.tag(), self.scope);
                for (k, v) in fields {
                    let _ = write!(line, " {k}={v}");
                }
                let _ = tx.send(line);
            }
        }
    }
}

/// `log_at!(level, logger, ["key" => value, ...], "format {}", args)`
#[macro_export]
macro_rules! log_at {
    ($lvl:expr, $logger:expr, [$($k:literal => $v:expr),* $(,)?], $($arg:tt)+) => {{
        let __l = &$logger;
        if __l.enabled($lvl) {
            __l.emit($lvl, format_args!($($arg)+), &[$(($k, format!("{}", $v))),*]);
        }
    }};
    ($lvl:expr, $logger:expr, $($arg:tt)+) => {
        $crate::log_at!($lvl, $logger, [], $($arg)+)
    };
}

#[macro_export]
macro_rules! trace {
    ($($t:tt)+) => { $crate::log_at!($crate::logging::Level::Trace, $($t)+) };
}
#[macro_export]
macro_rules! debug {
    ($($t:tt)+) => { $crate::log_at!($crate::logging::Level::Debug, $($t)+) };
}
#[macro_export]
macro_rules! info {
    ($($t:tt)+) => { $crate::log_at!($crate::logging::Level::Info, $($t)+) };
}
#[macro_export]
macro_rules! warn {
    ($($t:tt)+) => { $crate::log_at!($crate::logging::Level::Warn, $($t)+) };
}
#[macro_export]
macro_rules! error {
    ($($t:tt)+) => { $crate::log_at!($crate::logging::Level::Error, $($t)+) };
}
