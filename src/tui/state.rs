use crate::process::logs::ChildLogStore;
use std::sync::{atomic::AtomicBool, Arc, Mutex};

#[derive(Debug, Clone)]
pub struct TuiRuntime {
    pub child_label: Option<String>,
    pub child_pid: Option<u32>,
    pub proxy_addr: String,
    pub https_inspection: bool,
    pub child_running: Option<Arc<AtomicBool>>,
    pub child_logs: Arc<Mutex<ChildLogStore>>,
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
pub struct TuiState {
    pub selected: usize,
    pub paused: bool,
    pub screen: Screen,
    pub tab: DetailTab,
    pub filter: String,
    pub entering_filter: bool,
    pub message: String,
    pub confirm_quit: bool,
    pub log_scroll_offset: usize,
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            selected: 0,
            paused: false,
            screen: Screen::List,
            tab: DetailTab::Overview,
            filter: String::new(),
            entering_filter: false,
            message: String::new(),
            confirm_quit: false,
            log_scroll_offset: 0,
        }
    }
}
