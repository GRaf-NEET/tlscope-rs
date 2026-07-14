use crate::{
    capture::{
        details,
        export::export_session_json,
        filter_suggestions::FilterParseState,
        model::TrafficEntry,
        redact::RedactionConfig,
        store::{FilterIndex, TrafficFilter, TrafficStore},
    },
    diagnostics::logs::TlscopeLogSnapshot,
    process::logs::ChildLogSnapshot,
    tui::{
        filter,
        state::{ClipboardRequest, Screen, TuiExit, TuiState},
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
    process_logs: &ChildLogSnapshot,
    tlscope_logs: &TlscopeLogSnapshot,
    redaction: &RedactionConfig,
) -> Result<Option<TuiExit>> {
    if state.confirm_quit {
        return Ok(handle_quit_choice(key, state));
    }

    if state.entering_filter {
        handle_filter_key(key, state, store)?;
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
                state.message = format!("{} logs", state.log_tab.label());
            }
            return Ok(None);
        }
        _ => {}
    }

    match state.screen {
        Screen::Logs => handle_log_key(key, state, store, process_logs, tlscope_logs, redaction),
        Screen::Details => handle_detail_key(key, state, store, entries, redaction),
        Screen::Help => {
            handle_help_key(key, state);
            Ok(None)
        }
        Screen::List => handle_list_key(key, state, store, entries, redaction),
    }
}

fn handle_filter_key(
    key: KeyEvent,
    state: &mut TuiState,
    store: &Arc<Mutex<TrafficStore>>,
) -> Result<()> {
    let index = filter_index_snapshot(store);
    filter::refresh(&mut state.filter_editor, &index);

    match key.code {
        KeyCode::Enter => apply_filter(state),
        KeyCode::Esc => {
            state
                .filter_editor
                .reset_to(&state.applied_filter_text, &index);
            state.entering_filter = false;
            state.message = "filter editing cancelled".to_string();
        }
        KeyCode::Backspace => filter::backspace(&mut state.filter_editor, &index),
        KeyCode::Delete => filter::delete(&mut state.filter_editor, &index),
        KeyCode::Left => filter::move_left(&mut state.filter_editor),
        KeyCode::Right => filter::move_right(&mut state.filter_editor),
        KeyCode::Home => filter::move_home(&mut state.filter_editor),
        KeyCode::End => filter::move_end(&mut state.filter_editor),
        KeyCode::Up => filter::select_previous_suggestion(&mut state.filter_editor),
        KeyCode::Down => filter::select_next_suggestion(&mut state.filter_editor),
        KeyCode::Tab => {
            filter::apply_selected_suggestion(&mut state.filter_editor, &index);
        }
        KeyCode::BackTab => filter::select_previous_suggestion(&mut state.filter_editor),
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            filter::clear(&mut state.filter_editor, &index)
        }
        KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            filter::delete_current_token(&mut state.filter_editor, &index)
        }
        KeyCode::Char(c) => filter::insert_char(&mut state.filter_editor, &index, c),
        _ => unavailable(
            state,
            "Filter mode: type, arrows, Tab suggestion, Enter apply, Esc cancel.",
        ),
    }
    Ok(())
}

fn apply_filter(state: &mut TuiState) {
    match &state.filter_editor.parse_state {
        FilterParseState::Incomplete => {
            state.filter_editor.error = Some("incomplete filter token".to_string());
            state.message = "filter is incomplete".to_string();
            return;
        }
        FilterParseState::Invalid(error) => {
            state.filter_editor.error = Some(error.clone());
            state.message = "filter has errors".to_string();
            return;
        }
        FilterParseState::Valid => {}
    }

    match TrafficFilter::parse(&state.filter_editor.text) {
        Ok(parsed) => {
            state.applied_filter_text = state.filter_editor.text.clone();
            state.applied_filter = parsed;
            state.entering_filter = false;
            state.filter_editor.error = None;
            state.selected = 0;
            state.detail_scroll_offset = 0;
            state.message = if state.applied_filter_text.is_empty() {
                "filter cleared".to_string()
            } else {
                "filter applied".to_string()
            };
        }
        Err(error) => {
            state.filter_editor.error = Some(error);
            state.message = "filter has errors".to_string();
        }
    }
}

fn begin_filter_edit(state: &mut TuiState, store: &Arc<Mutex<TrafficStore>>) {
    let index = filter_index_snapshot(store);
    state
        .filter_editor
        .reset_to(&state.applied_filter_text, &index);
    state.entering_filter = true;
    state.message = "filter mode".to_string();
}

fn filter_index_snapshot(store: &Arc<Mutex<TrafficStore>>) -> FilterIndex {
    store
        .lock()
        .map(|guard| guard.filter_index().clone())
        .unwrap_or_default()
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
        KeyCode::Char('/') => begin_filter_edit(state, store),
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
        KeyCode::Char('/') => begin_filter_edit(state, store),
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
    process_logs: &ChildLogSnapshot,
    tlscope_logs: &TlscopeLogSnapshot,
    redaction: &RedactionConfig,
) -> Result<Option<TuiExit>> {
    let log_count = current_log_count(state, process_logs, tlscope_logs);
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => scroll_logs_older(state, log_count, 1),
        KeyCode::Down | KeyCode::Char('j') => scroll_logs_newer(state, 1),
        KeyCode::PageUp => scroll_logs_older(state, log_count, 10),
        KeyCode::PageDown => scroll_logs_newer(state, 10),
        KeyCode::Home => {
            if log_count == 0 {
                unavailable(state, state.log_tab.empty_message());
            } else {
                state.log_scroll_offset = log_count.saturating_sub(1);
                state.message = format!("oldest {} logs", state.log_tab.label());
            }
        }
        KeyCode::End => {
            state.log_scroll_offset = 0;
            state.message = format!("following {} logs", state.log_tab.label());
        }
        KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => switch_log_tab(state, true),
        KeyCode::Tab => switch_log_tab(state, false),
        KeyCode::BackTab => switch_log_tab(state, true),
        KeyCode::Esc => {
            state.screen = Screen::List;
            state.message.clear();
        }
        KeyCode::Char(' ') => toggle_pause(state),
        KeyCode::Char('c') => clear_session(state, store),
        KeyCode::Char('e') => export_current_session(state, store, redaction)?,
        KeyCode::Char('y') => copy_current_logs(state, process_logs, tlscope_logs),
        _ => unavailable(
            state,
            "Log mode: Up/Down scroll, Tab page, y copy logs, Esc or l back.",
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
        crate::tui::state::DetailTab::Overview => details::overview_text(entry),
        crate::tui::state::DetailTab::Request => details::request_text(entry),
        crate::tui::state::DetailTab::Response => details::response_text(entry),
        crate::tui::state::DetailTab::Tls => details::tls_text(entry),
        crate::tui::state::DetailTab::Timing => details::timing_text(entry),
        crate::tui::state::DetailTab::Raw => details::raw_text(entry),
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

fn current_log_count(
    state: &TuiState,
    process_logs: &ChildLogSnapshot,
    tlscope_logs: &TlscopeLogSnapshot,
) -> usize {
    match state.log_tab {
        crate::tui::state::LogTab::Process => process_logs.lines.len(),
        crate::tui::state::LogTab::Tlscope => tlscope_logs.lines.len(),
    }
}

fn switch_log_tab(state: &mut TuiState, previous: bool) {
    state.log_tab = if previous {
        state.log_tab.previous()
    } else {
        state.log_tab.next()
    };
    state.log_scroll_offset = 0;
    state.message = format!("{} logs", state.log_tab.label());
}

fn copy_current_logs(
    state: &mut TuiState,
    process_logs: &ChildLogSnapshot,
    tlscope_logs: &TlscopeLogSnapshot,
) {
    let text = match state.log_tab {
        crate::tui::state::LogTab::Process => process_logs.clipboard_text(),
        crate::tui::state::LogTab::Tlscope => tlscope_logs.clipboard_text(),
    };

    if text.is_empty() {
        unavailable(state, state.log_tab.empty_message());
    } else {
        state.clipboard_request = Some(ClipboardRequest {
            label: state.log_tab.label(),
            text,
        });
    }
}
fn scroll_logs_older(state: &mut TuiState, log_count: usize, amount: usize) {
    if log_count == 0 {
        unavailable(state, state.log_tab.empty_message());
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
        state.message = format!("older {} logs", state.log_tab.label());
    }
}

fn scroll_logs_newer(state: &mut TuiState, amount: usize) {
    if state.log_scroll_offset == 0 {
        unavailable(state, "Already following the latest log line.");
    } else {
        state.log_scroll_offset = state.log_scroll_offset.saturating_sub(amount);
        state.message = if state.log_scroll_offset == 0 {
            format!("following {} logs", state.log_tab.label())
        } else {
            format!("newer {} logs", state.log_tab.label())
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
