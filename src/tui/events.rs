use crate::{
    capture::{
        export::export_session_json, model::TrafficEntry, redact::RedactionConfig,
        store::TrafficStore,
    },
    tui::state::{Screen, TuiExit, TuiState},
};
use anyhow::{Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::sync::{Arc, Mutex};

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

    if state.screen == Screen::Logs {
        return handle_log_key(key, state, store, log_count, redaction);
    }

    match key.code {
        KeyCode::Down | KeyCode::Char('j') => {
            if state.selected + 1 < entries.len() {
                state.selected += 1;
                state.message.clear();
            } else {
                unavailable(state, "Already at the last request.");
            }
            Ok(None)
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if state.selected > 0 {
                state.selected -= 1;
                state.message.clear();
            } else {
                unavailable(state, "Already at the first request.");
            }
            Ok(None)
        }
        KeyCode::Enter => {
            if !entries.is_empty() {
                state.screen = Screen::Details;
                state.message.clear();
            } else {
                unavailable(state, "No captured request to inspect yet.");
            }
            Ok(None)
        }
        KeyCode::Esc => {
            if state.screen == Screen::List {
                unavailable(state, "Already on the request list. Press q to quit.");
            } else {
                state.screen = Screen::List;
                state.message.clear();
            }
            Ok(None)
        }
        KeyCode::Tab => {
            if state.screen == Screen::Details {
                state.tab = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    state.tab.previous()
                } else {
                    state.tab.next()
                };
                state.message = format!("tab: {}", state.tab.title());
            } else {
                unavailable(
                    state,
                    "Tabs are available only in request details. Press Enter first.",
                );
            }
            Ok(None)
        }
        KeyCode::Char('/') => {
            state.entering_filter = true;
            state.message = "filter mode".to_string();
            Ok(None)
        }
        KeyCode::Char(' ') => {
            toggle_pause(state);
            Ok(None)
        }
        KeyCode::Char('c') => {
            clear_session(state, store);
            Ok(None)
        }
        KeyCode::Char('e') => {
            export_current_session(state, store, redaction)?;
            Ok(None)
        }
        KeyCode::Char('r') => {
            state.message = "filter reapplied".to_string();
            Ok(None)
        }
        KeyCode::Char('y') => {
            if let Some(entry) = entries.get(state.selected) {
                state.message = format!("selected URL: {}", entry.url());
            } else {
                unavailable(state, "No selected request.");
            }
            Ok(None)
        }
        _ => {
            unavailable(state, "This key is not available here. Press ? for help.");
            Ok(None)
        }
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
