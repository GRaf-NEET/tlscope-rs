pub mod events;
pub mod filter;
pub mod layout;
pub mod state;
pub mod widgets;

use crate::{
    capture::{redact::RedactionConfig, store::TrafficStore},
    proxy::server::ProxyEvent,
    tui::{
        events::handle_key,
        layout::draw_ui,
        state::{TuiExit, TuiRuntime, TuiState},
    },
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use crossterm::{
    event, execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    io::{self, Write},
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;

pub async fn run_tui(
    store: Arc<Mutex<TrafficStore>>,
    mut events_rx: mpsc::UnboundedReceiver<ProxyEvent>,
    runtime: TuiRuntime,
    redaction: RedactionConfig,
) -> Result<TuiExit> {
    enable_raw_mode().context("cannot enable terminal raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("cannot enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("cannot create TUI terminal")?;
    let mut state = TuiState::default();
    let result = run_loop(
        &mut terminal,
        &store,
        &mut events_rx,
        runtime,
        redaction,
        &mut state,
    )
    .await;
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    store: &Arc<Mutex<TrafficStore>>,
    events_rx: &mut mpsc::UnboundedReceiver<ProxyEvent>,
    runtime: TuiRuntime,
    redaction: RedactionConfig,
    state: &mut TuiState,
) -> Result<TuiExit> {
    loop {
        while events_rx.try_recv().is_ok() {
            if !state.paused {
                state.message = "captured".to_string();
            }
        }

        if runtime.auto_exit_when_child_done {
            if let Some(child_running) = &runtime.child_running {
                if !child_running.load(Ordering::SeqCst) {
                    return Ok(TuiExit::Quit);
                }
            }
        }

        let snapshot = store.lock().map(|guard| guard.clone()).unwrap_or_default();
        let log_snapshot = runtime
            .child_logs
            .lock()
            .map(|guard| guard.snapshot())
            .unwrap_or_default();
        let tlscope_log_snapshot = runtime
            .tlscope_logs
            .lock()
            .map(|guard| guard.snapshot())
            .unwrap_or_default();
        if state.entering_filter {
            crate::tui::filter::refresh(&mut state.filter_editor, snapshot.filter_index());
        }
        let entries = snapshot.filtered(&state.applied_filter);
        terminal
            .draw(|frame| {
                draw_ui(
                    frame,
                    &snapshot,
                    &entries,
                    &log_snapshot,
                    &tlscope_log_snapshot,
                    state,
                    &runtime,
                )
            })
            .context("failed to draw TUI")?;

        if event::poll(Duration::from_millis(100)).context("failed to poll terminal events")? {
            if let event::Event::Key(key) =
                event::read().context("failed to read terminal event")?
            {
                if key.kind != event::KeyEventKind::Press {
                    continue;
                }
                if let Some(exit) = handle_key(
                    key,
                    state,
                    store,
                    &entries,
                    &log_snapshot,
                    &tlscope_log_snapshot,
                    &redaction,
                )? {
                    return Ok(exit);
                }
                flush_clipboard_request(terminal, state);
            }
        }
    }
}

fn flush_clipboard_request(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut TuiState,
) {
    let Some(request) = state.clipboard_request.take() else {
        return;
    };

    match copy_to_terminal_clipboard(terminal, &request.text) {
        Ok(()) => state.message = format!("copied {} logs", request.label),
        Err(error) => state.message = format!("failed to copy {} logs: {error}", request.label),
    }
}

fn copy_to_terminal_clipboard(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    text: &str,
) -> io::Result<()> {
    let encoded = STANDARD.encode(text.as_bytes());
    write!(terminal.backend_mut(), "\x1b]52;c;{}\x07", encoded)?;
    terminal.backend_mut().flush()
}
