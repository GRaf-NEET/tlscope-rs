use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex, OnceLock},
};

use tracing::{
    field::{Field, Visit},
    Event, Level, Subscriber,
};
use tracing_subscriber::{layer::Context, Layer};

static ACTIVE_LOG_STORE: OnceLock<Mutex<Option<Arc<Mutex<TlscopeLogStore>>>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlscopeLogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl TlscopeLogLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }

    fn from_tracing(level: &Level) -> Self {
        if *level == Level::ERROR {
            Self::Error
        } else if *level == Level::WARN {
            Self::Warn
        } else if *level == Level::INFO {
            Self::Info
        } else if *level == Level::DEBUG {
            Self::Debug
        } else {
            Self::Trace
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlscopeLogLine {
    pub level: TlscopeLogLevel,
    pub target: String,
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct TlscopeLogSnapshot {
    pub lines: Vec<TlscopeLogLine>,
    pub dropped: usize,
    pub total: usize,
}

impl TlscopeLogSnapshot {
    pub fn clipboard_text(&self) -> String {
        let mut text = String::new();
        if self.dropped > 0 {
            text.push_str(&format!(
                "[{} older TLScope log lines dropped]\n",
                self.dropped
            ));
        }

        for (index, line) in self.lines.iter().enumerate() {
            if index > 0 {
                text.push('\n');
            }
            text.push_str(&format!(
                "[{} {}] {}",
                line.level.label(),
                line.target,
                line.text
            ));
        }
        text
    }
}

#[derive(Debug, Clone)]
pub struct TlscopeLogStore {
    lines: VecDeque<TlscopeLogLine>,
    max_lines: usize,
    dropped: usize,
    total: usize,
}

impl TlscopeLogStore {
    pub fn new(max_lines: usize) -> Self {
        Self {
            lines: VecDeque::with_capacity(max_lines.min(1024)),
            max_lines,
            dropped: 0,
            total: 0,
        }
    }

    pub fn push(
        &mut self,
        level: TlscopeLogLevel,
        target: impl Into<String>,
        text: impl Into<String>,
    ) {
        if self.max_lines == 0 {
            self.dropped += 1;
            self.total += 1;
            return;
        }
        if self.lines.len() == self.max_lines {
            self.lines.pop_front();
            self.dropped += 1;
        }
        self.lines.push_back(TlscopeLogLine {
            level,
            target: target.into(),
            text: text.into(),
        });
        self.total += 1;
    }

    pub fn snapshot(&self) -> TlscopeLogSnapshot {
        TlscopeLogSnapshot {
            lines: self.lines.iter().cloned().collect(),
            dropped: self.dropped,
            total: self.total,
        }
    }
}

impl Default for TlscopeLogStore {
    fn default() -> Self {
        Self::new(2_000)
    }
}

#[derive(Debug)]
pub struct ActiveTlscopeLogCapture;

pub fn activate_tlscope_log_capture(store: Arc<Mutex<TlscopeLogStore>>) -> ActiveTlscopeLogCapture {
    if let Ok(mut guard) = ACTIVE_LOG_STORE.get_or_init(default_active_store).lock() {
        *guard = Some(store);
    }
    ActiveTlscopeLogCapture
}

impl Drop for ActiveTlscopeLogCapture {
    fn drop(&mut self) {
        if let Some(slot) = ACTIVE_LOG_STORE.get() {
            if let Ok(mut guard) = slot.lock() {
                *guard = None;
            }
        }
    }
}

pub fn push_tlscope_log(
    store: &Arc<Mutex<TlscopeLogStore>>,
    level: TlscopeLogLevel,
    target: impl Into<String>,
    text: impl Into<String>,
) {
    if let Ok(mut guard) = store.lock() {
        guard.push(level, target, text);
    }
}

pub struct TlscopeLogLayer;

impl<S> Layer<S> for TlscopeLogLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        if !is_tlscope_target(metadata.target()) {
            return;
        }

        let Some(store) = active_store() else {
            return;
        };

        let mut visitor = LogEventVisitor::default();
        event.record(&mut visitor);
        if let Ok(mut guard) = store.lock() {
            guard.push(
                TlscopeLogLevel::from_tracing(metadata.level()),
                short_target(metadata.target()),
                visitor.finish(),
            );
        };
    }
}

fn default_active_store() -> Mutex<Option<Arc<Mutex<TlscopeLogStore>>>> {
    Mutex::new(None)
}

fn active_store() -> Option<Arc<Mutex<TlscopeLogStore>>> {
    ACTIVE_LOG_STORE
        .get()
        .and_then(|slot| slot.lock().ok().and_then(|guard| guard.clone()))
}

fn is_tlscope_target(target: &str) -> bool {
    target == "tlscope"
        || target.starts_with("tlscope::")
        || target == "TLScope"
        || target.starts_with("TLScope::")
}

fn short_target(target: &str) -> String {
    target
        .strip_prefix("tlscope::")
        .or_else(|| target.strip_prefix("TLScope::"))
        .unwrap_or(target)
        .to_string()
}

#[derive(Default)]
struct LogEventVisitor {
    message: Option<String>,
    fields: Vec<String>,
}

impl LogEventVisitor {
    fn record_value(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.fields.push(format!("{}={}", field.name(), value));
        }
    }

    fn finish(self) -> String {
        let mut text = self.message.unwrap_or_default();
        if !self.fields.is_empty() {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(&self.fields.join(" "));
        }
        if text.is_empty() {
            "event".to_string()
        } else {
            text
        }
    }
}

impl Visit for LogEventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_value(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_recent_tlscope_lines() {
        let mut store = TlscopeLogStore::new(2);
        store.push(TlscopeLogLevel::Info, "app", "one");
        store.push(TlscopeLogLevel::Warn, "proxy", "two");
        store.push(TlscopeLogLevel::Debug, "proxy", "three");

        let snapshot = store.snapshot();
        assert_eq!(snapshot.dropped, 1);
        assert_eq!(snapshot.total, 3);
        assert_eq!(snapshot.lines.len(), 2);
        assert_eq!(snapshot.lines[0].text, "two");
        assert_eq!(snapshot.lines[1].text, "three");
    }

    #[test]
    fn formats_tlscope_snapshot_for_clipboard() {
        let mut store = TlscopeLogStore::new(1);
        store.push(TlscopeLogLevel::Info, "app", "first");
        store.push(TlscopeLogLevel::Warn, "proxy", "second");

        assert_eq!(
            store.snapshot().clipboard_text(),
            "[1 older TLScope log lines dropped]\n[WARN proxy] second"
        );
    }
}
