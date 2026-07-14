use crate::{
    capture::store::TrafficFilter, diagnostics::logs::TlscopeLogStore,
    process::logs::ChildLogStore, tui::filter::FilterEditorState,
};
use std::sync::{atomic::AtomicBool, Arc, Mutex};

#[derive(Debug, Clone)]
pub struct TuiRuntime {
    pub child_label: Option<String>,
    pub child_pid: Option<u32>,
    pub proxy_addr: String,
    pub https_inspection: bool,
    pub child_running: Option<Arc<AtomicBool>>,
    pub child_logs: Arc<Mutex<ChildLogStore>>,
    pub tlscope_logs: Arc<Mutex<TlscopeLogStore>>,
    pub auto_exit_when_child_done: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiExit {
    Quit,
    TerminateChild,
    LeaveChildRunning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    List,
    Details,
    Logs,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogTab {
    Process,
    Tlscope,
}

impl LogTab {
    pub fn title(self) -> &'static str {
        match self {
            Self::Process => "Process",
            Self::Tlscope => "TLScope",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Tlscope => "TLScope",
        }
    }

    pub fn empty_message(self) -> &'static str {
        match self {
            Self::Process => "No process logs captured yet.",
            Self::Tlscope => "No TLScope logs captured yet.",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Self::Process => Self::Tlscope,
            Self::Tlscope => Self::Process,
        }
    }

    pub fn previous(self) -> Self {
        self.next()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    Overview,
    Request,
    Response,
    Tls,
    Timing,
    Raw,
}

impl DetailTab {
    pub fn title(self) -> &'static str {
        match self {
            DetailTab::Overview => "Overview",
            DetailTab::Request => "Request",
            DetailTab::Response => "Response",
            DetailTab::Tls => "TLS",
            DetailTab::Timing => "Timing",
            DetailTab::Raw => "Raw",
        }
    }

    pub fn next(self) -> Self {
        match self {
            DetailTab::Overview => DetailTab::Request,
            DetailTab::Request => DetailTab::Response,
            DetailTab::Response => DetailTab::Tls,
            DetailTab::Tls => DetailTab::Timing,
            DetailTab::Timing => DetailTab::Raw,
            DetailTab::Raw => DetailTab::Overview,
        }
    }

    pub fn previous(self) -> Self {
        match self {
            DetailTab::Overview => DetailTab::Raw,
            DetailTab::Request => DetailTab::Overview,
            DetailTab::Response => DetailTab::Request,
            DetailTab::Tls => DetailTab::Response,
            DetailTab::Timing => DetailTab::Tls,
            DetailTab::Raw => DetailTab::Timing,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClipboardRequest {
    pub label: &'static str,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct TuiState {
    pub selected: usize,
    pub paused: bool,
    pub screen: Screen,
    pub tab: DetailTab,
    pub applied_filter_text: String,
    pub applied_filter: TrafficFilter,
    pub filter_editor: FilterEditorState,
    pub entering_filter: bool,
    pub message: String,
    pub confirm_quit: bool,
    pub log_tab: LogTab,
    pub log_scroll_offset: usize,
    pub detail_scroll_offset: usize,
    pub clipboard_request: Option<ClipboardRequest>,
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            selected: 0,
            paused: false,
            screen: Screen::List,
            tab: DetailTab::Overview,
            applied_filter_text: String::new(),
            applied_filter: TrafficFilter::default(),
            filter_editor: FilterEditorState::default(),
            entering_filter: false,
            message: String::new(),
            confirm_quit: false,
            log_tab: LogTab::Process,
            log_scroll_offset: 0,
            detail_scroll_offset: 0,
            clipboard_request: None,
        }
    }
}
