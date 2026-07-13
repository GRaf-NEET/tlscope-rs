use crate::{
    capture::{
        export::export_session_json, model::TrafficEntry, redact::RedactionConfig,
        store::TrafficStore,
    },
    tui::{
        state::{Screen, TuiExit, TuiState},
        widgets::{request_details, response_details},
    },
};
use anyhow::{Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::sync::{Arc, Mutex};

const DETAIL_SCROLL_ESTIMATE_WIDTH: usize = 40;

pub fn handle_key(
    key: KeyEvent,
    state: &mut TuiState,
    store: &Arc<Mutex<TrafficStore>>,
    entries: &[TrafficEntry],
    log_count: usize,
    redaction: &RedactionConfig,
) -> Result<Option<TuiExit>> {
    if state.confirm_quit {
        return Ok(handle_quit_choice(key, state));
    }

    if state.entering_filter {
        match key.code {
            KeyCode::Enter => {
                state.entering_filter = false;
                state.selected = 0;
                state.detail_scroll_offset = 0;
                state.message = "filter applied".to_string();
            }
            KeyCode::Esc => {
                state.entering_filter = false;
                state.message = "filter editing cancelled".to_string();
            }
            KeyCode::Backspace => {
                state.filter.pop();
            }
            KeyCode::Char(c) => state.filter.push(c),
            _ => unavailable(state, "Filter mode: type text, Backspace, Enter or Esc."),
        }
        return Ok(None);
    }

    match key.code {
        KeyCode::Char('q') => {
            state.confirm_quit = true;
            return Ok(None);
        }
        KeyCode::Char('?') => {
            state.screen = Screen::Help;
            state.message.clear();
            return Ok(None);
        }
        KeyCode::Char('l') => {
            if state.screen == Screen::Logs {
                state.screen = Screen::List;
                state.message = "request list".to_string();
            } else {
                state.screen = Screen::Logs;
                state.log_scroll_offset = 0;
                state.message = "process logs".to_string();
            }
            return Ok(None);
        }
        _ => {}
    }

    match state.screen {
        Screen::Logs => handle_log_key(key, state, store, log_count, redaction),
        Screen::Details => handle_detail_key(key, state, store, entries, redaction),
        Screen::Help => {
            handle_help_key(key, state);
            Ok(None)
        }
        Screen::List => handle_list_key(key, state, store, entries, redaction),
    }
}

fn handle_list_key(
    key: KeyEvent,
    state: &mut TuiState,
    store: &Arc<Mutex<TrafficStore>>,
    entries: &[TrafficEntry],
    redaction: &RedactionConfig,
) -> Result<Option<TuiExit>> {
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => select_next_request(state, entries, 1),
        KeyCode::Up | KeyCode::Char('k') => select_previous_request(state, entries, 1),
        KeyCode::PageDown => select_next_request(state, entries, 10),
        KeyCode::PageUp => select_previous_request(state, entries, 10),
        KeyCode::Home => select_first_request(state, entries),
        KeyCode::End => select_last_request(state, entries),
        KeyCode::Enter => {
            if !entries.is_empty() {
                state.selected = state.selected.min(entries.len().saturating_sub(1));
                state.screen = Screen::Details;
                state.detail_scroll_offset = 0;
                state.message.clear();
            } else {
                unavailable(state, "No captured request to inspect yet.");
            }
        }
        KeyCode::Esc => unavailable(state, "Already on the request list. Press q to quit."),
        KeyCode::Tab | KeyCode::BackTab => unavailable(
            state,
            "Tabs are available only in request details. Press Enter first.",
        ),
        KeyCode::Char('/') => {
            state.entering_filter = true;
            state.message = "filter mode".to_string();
        }
        KeyCode::Char(' ') => toggle_pause(state),
        KeyCode::Char('c') => clear_session(state, store),
        KeyCode::Char('e') => export_current_session(state, store, redaction)?,
        KeyCode::Char('r') => state.message = "filter reapplied".to_string(),
        KeyCode::Char('y') => show_selected_url(state, entries),
        _ => unavailable(state, "This key is not available here. Press ? for help."),
    }
    Ok(None)
}

fn handle_detail_key(
    key: KeyEvent,
    state: &mut TuiState,
    store: &Arc<Mutex<TrafficStore>>,
    entries: &[TrafficEntry],
    redaction: &RedactionConfig,
) -> Result<Option<TuiExit>> {
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => scroll_details_down(state, entries, 1),
        KeyCode::Up | KeyCode::Char('k') => scroll_details_up(state, 1),
        KeyCode::PageDown => scroll_details_down(state, entries, 10),
        KeyCode::PageUp => scroll_details_up(state, 10),
        KeyCode::Home => {
            state.detail_scroll_offset = 0;
            state.message = "top of details".to_string();
        }
        KeyCode::End => {
            state.detail_scroll_offset = detail_scroll_limit(state, entries);
            state.message = "bottom of details".to_string();
        }
        KeyCode::Esc => {
            state.screen = Screen::List;
            state.message.clear();
        }
        KeyCode::Tab => {
            state.tab = if key.modifiers.contains(KeyModifiers::SHIFT) {
                state.tab.previous()
            } else {
                state.tab.next()
            };
            state.detail_scroll_offset = 0;
            state.message = format!("tab: {}", state.tab.title());
        }
        KeyCode::BackTab => {
            state.tab = state.tab.previous();
            state.detail_scroll_offset = 0;
            state.message = format!("tab: {}", state.tab.title());
        }
        KeyCode::Char('/') => {
            state.entering_filter = true;
            state.message = "filter mode".to_string();
        }
        KeyCode::Char(' ') => toggle_pause(state),
        KeyCode::Char('c') => clear_session(state, store),
        KeyCode::Char('e') => export_current_session(state, store, redaction)?,
        KeyCode::Char('r') => state.message = "filter reapplied".to_string(),
        KeyCode::Char('y') => show_selected_url(state, entries),
        _ => unavailable(
            state,
            "Details: Up/Down scroll, PgUp/PgDn page, Home/End jump, Esc list.",
        ),
    }
    Ok(None)
}

fn handle_help_key(key: KeyEvent, state: &mut TuiState) {
    match key.code {
        KeyCode::Esc => {
            state.screen = Screen::List;
            state.message.clear();
        }
        _ => unavailable(state, "Help: Esc back, l logs, q quit."),
    }
}

fn handle_log_key(
    key: KeyEvent,
    state: &mut TuiState,
    store: &Arc<Mutex<TrafficStore>>,
    log_count: usize,
    redaction: &RedactionConfig,
) -> Result<Option<TuiExit>> {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => scroll_logs_older(state, log_count, 1),
        KeyCode::Down | KeyCode::Char('j') => scroll_logs_newer(state, 1),
        KeyCode::PageUp => scroll_logs_older(state, log_count, 10),
        KeyCode::PageDown => scroll_logs_newer(state, 10),
        KeyCode::Home => {
            if log_count == 0 {
                unavailable(state, "No process logs captured yet.");
            } else {
                state.log_scroll_offset = log_count.saturating_sub(1);
                state.message = "oldest logs".to_string();
            }
        }
        KeyCode::End => {
            state.log_scroll_offset = 0;
            state.message = "following logs".to_string();
        }
        KeyCode::Esc => {
            state.screen = Screen::List;
            state.message.clear();
        }
        KeyCode::Char(' ') => toggle_pause(state),
        KeyCode::Char('c') => clear_session(state, store),
        KeyCode::Char('e') => export_current_session(state, store, redaction)?,
        _ => unavailable(
            state,
            "Log mode: Up/Down scroll, Home/End jump, Esc or l back.",
        ),
    }
    Ok(None)
}

fn select_next_request(state: &mut TuiState, entries: &[TrafficEntry], amount: usize) {
    let Some(last) = entries.len().checked_sub(1) else {
        unavailable(state, "No captured request to select yet.");
        return;
    };
    state.selected = state.selected.min(last);
    if state.selected == last {
        unavailable(state, "Already at the last request.");
    } else {
        state.selected = state.selected.saturating_add(amount).min(last);
        state.detail_scroll_offset = 0;
        state.message.clear();
    }
}

fn select_previous_request(state: &mut TuiState, entries: &[TrafficEntry], amount: usize) {
    if entries.is_empty() {
        unavailable(state, "No captured request to select yet.");
        return;
    }
    state.selected = state.selected.min(entries.len().saturating_sub(1));
    if state.selected == 0 {
        unavailable(state, "Already at the first request.");
    } else {
        state.selected = state.selected.saturating_sub(amount);
        state.detail_scroll_offset = 0;
        state.message.clear();
    }
}

fn select_first_request(state: &mut TuiState, entries: &[TrafficEntry]) {
    if entries.is_empty() {
        unavailable(state, "No captured request to select yet.");
    } else {
        state.selected = 0;
        state.detail_scroll_offset = 0;
        state.message = "first request".to_string();
    }
}

fn select_last_request(state: &mut TuiState, entries: &[TrafficEntry]) {
    if let Some(last) = entries.len().checked_sub(1) {
        state.selected = last;
        state.detail_scroll_offset = 0;
        state.message = "last request".to_string();
    } else {
        unavailable(state, "No captured request to select yet.");
    }
}

fn scroll_details_down(state: &mut TuiState, entries: &[TrafficEntry], amount: usize) {
    let max_scroll = detail_scroll_limit(state, entries);
    if max_scroll == 0 {
        unavailable(state, "Current detail tab fits on screen.");
        return;
    }
    if state.detail_scroll_offset >= max_scroll {
        unavailable(state, "Already at the bottom of details.");
    } else {
        state.detail_scroll_offset = state
            .detail_scroll_offset
            .saturating_add(amount)
            .min(max_scroll);
        state.message = "details down".to_string();
    }
}

fn scroll_details_up(state: &mut TuiState, amount: usize) {
    if state.detail_scroll_offset == 0 {
        unavailable(state, "Already at the top of details.");
    } else {
        state.detail_scroll_offset = state.detail_scroll_offset.saturating_sub(amount);
        state.message = if state.detail_scroll_offset == 0 {
            "top of details".to_string()
        } else {
            "details up".to_string()
        };
    }
}

fn detail_scroll_limit(state: &TuiState, entries: &[TrafficEntry]) -> usize {
    let Some(entry) = selected_entry(state, entries) else {
        return 0;
    };
    let text = match state.tab {
        crate::tui::state::DetailTab::Overview => request_details::overview_text(entry),
        crate::tui::state::DetailTab::Request => request_details::request_text(entry),
        crate::tui::state::DetailTab::Response => response_details::response_text(entry),
        crate::tui::state::DetailTab::Tls => response_details::tls_text(entry),
        crate::tui::state::DetailTab::Timing => response_details::timing_text(entry),
        crate::tui::state::DetailTab::Raw => response_details::raw_text(entry),
    };
    estimated_visual_lines(&text).saturating_sub(1)
}

fn estimated_visual_lines(text: &str) -> usize {
    text.lines()
        .map(|line| {
            line.chars()
                .count()
                .max(1)
                .div_ceil(DETAIL_SCROLL_ESTIMATE_WIDTH)
        })
        .sum::<usize>()
        .max(1)
}

fn selected_entry<'a>(state: &TuiState, entries: &'a [TrafficEntry]) -> Option<&'a TrafficEntry> {
    entries.get(state.selected.min(entries.len().saturating_sub(1)))
}

fn scroll_logs_older(state: &mut TuiState, log_count: usize, amount: usize) {
    if log_count == 0 {
        unavailable(state, "No process logs captured yet.");
        return;
    }
    let max_offset = log_count.saturating_sub(1);
    if state.log_scroll_offset >= max_offset {
        unavailable(state, "Already at the oldest log line.");
    } else {
        state.log_scroll_offset = state
            .log_scroll_offset
            .saturating_add(amount)
            .min(max_offset);
        state.message = "older logs".to_string();
    }
}

fn scroll_logs_newer(state: &mut TuiState, amount: usize) {
    if state.log_scroll_offset == 0 {
        unavailable(state, "Already following the latest logs.");
    } else {
        state.log_scroll_offset = state.log_scroll_offset.saturating_sub(amount);
        state.message = if state.log_scroll_offset == 0 {
            "following logs".to_string()
        } else {
            "newer logs".to_string()
        };
    }
}

fn toggle_pause(state: &mut TuiState) {
    state.paused = !state.paused;
    state.message = if state.paused { "paused" } else { "live" }.to_string();
}

fn clear_session(state: &mut TuiState, store: &Arc<Mutex<TrafficStore>>) {
    if let Ok(mut guard) = store.lock() {
        guard.clear();
    }
    state.selected = 0;
    state.detail_scroll_offset = 0;
    state.log_scroll_offset = 0;
    state.message = "session cleared".to_string();
}

fn export_current_session(
    state: &mut TuiState,
    store: &Arc<Mutex<TrafficStore>>,
    redaction: &RedactionConfig,
) -> Result<()> {
    let entries = store
        .lock()
        .map(|guard| guard.entries().to_vec())
        .unwrap_or_default();
    export_session_json("TLScope-export.json", &entries, redaction)
        .context("failed to export current session")?;
    state.message = "exported TLScope-export.json".to_string();
    Ok(())
}

fn show_selected_url(state: &mut TuiState, entries: &[TrafficEntry]) {
    if let Some(entry) = selected_entry(state, entries) {
        state.message = format!("selected URL: {}", entry.url());
    } else {
        unavailable(state, "No selected request.");
    }
}

fn handle_quit_choice(key: KeyEvent, state: &mut TuiState) -> Option<TuiExit> {
    match key.code {
        KeyCode::Char('1') => Some(TuiExit::TerminateChild),
        KeyCode::Char('2') => Some(TuiExit::LeaveChildRunning),
        KeyCode::Char('3') | KeyCode::Esc => {
            state.confirm_quit = false;
            state.message = "quit cancelled".to_string();
            None
        }
        _ => {
            unavailable(state, "Choose 1, 2, 3 or Esc.");
            None
        }
    }
}

fn unavailable(state: &mut TuiState, message: impl Into<String>) {
    state.message = message.into();
}
