use crate::{
    capture::store::TrafficStore,
    tui::state::{Screen, TuiRuntime, TuiState},
};
use ratatui::{
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn render_header(
    frame: &mut Frame<'_>,
    area: Rect,
    store: &TrafficStore,
    runtime: &TuiRuntime,
) {
    let child = runtime.child_label.as_deref().unwrap_or("none");
    let pid = runtime
        .child_pid
        .map(|v| v.to_string())
        .unwrap_or_else(|| "N/A".to_string());
    let https = if runtime.https_inspection {
        "ON"
    } else {
        "OFF"
    };
    let log_count = runtime
        .child_logs
        .lock()
        .map(|guard| guard.snapshot().total)
        .unwrap_or(0);
    let text = vec![
        Line::from(format!(
            "Child: {child}    PID: {pid}    Proxy: {}",
            runtime.proxy_addr
        )),
        Line::from(format!(
            "HTTPS inspection: {https}    Captured: {}    Errors: {}    Logs: {log_count}",
            store.entries().len(),
            store.error_count()
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("TLScope")),
        area,
    );
}

pub fn render_footer(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let mode = if state.paused { "PAUSED" } else { "LIVE" };
    let hint = footer_hint(state);
    let text = if state.message.is_empty() {
        format!("{mode} | {hint}")
    } else {
        format!("{mode} | {} | {hint}", state.message)
    };
    frame.render_widget(Paragraph::new(text), area);
}

fn footer_hint(state: &TuiState) -> &'static str {
    if state.confirm_quit {
        return "1 stop child | 2 leave child | 3/Esc cancel";
    }
    if state.entering_filter {
        return "type filter | Backspace delete | Enter apply | Esc cancel";
    }
    match state.screen {
        Screen::List => "Up/Down/j/k select | PgUp/PgDn page | Home/End jump | Enter inspect | ? help | q quit",
        Screen::Details => "Up/Down scroll | PgUp/PgDn page | Home/End jump | Tab switch | Esc list | ? help | q quit",
        Screen::Logs => "Up/Down/j/k scroll | PgUp/PgDn page | Home/End jump | Esc/l list | ? help | q quit",
        Screen::Help => "Esc back | l logs | ? help | q quit",
    }
}
