use crate::{
    capture::{model::TrafficEntry, store::TrafficStore},
    process::logs::ChildLogSnapshot,
    tui::{
        state::{Screen, TuiRuntime, TuiState},
        widgets::{
            help, process_logs, request_details, request_list, response_details, status_bar,
        },
    },
};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph, Tabs},
    Frame,
};

pub fn draw_ui(
    frame: &mut Frame<'_>,
    store: &TrafficStore,
    entries: &[TrafficEntry],
    logs: &ChildLogSnapshot,
    state: &TuiState,
    runtime: &TuiRuntime,
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);

    status_bar::render_header(frame, chunks[0], store, runtime);
    render_filter(frame, chunks[1], state);

    match state.screen {
        Screen::List => request_list::render(frame, chunks[2], entries, state.selected),
        Screen::Details => render_details(frame, chunks[2], entries, state),
        Screen::Logs => process_logs::render(frame, chunks[2], logs, state.log_scroll_offset),
        Screen::Help => help::render(frame, chunks[2]),
    }

    status_bar::render_footer(frame, chunks[3], state);

    if state.confirm_quit {
        render_quit_dialog(frame, area, runtime.child_running.is_some());
    }
}

fn render_filter(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let title = if state.entering_filter {
        "Filter (editing)"
    } else {
        "Filter"
    };
    let text = if state.filter.is_empty() {
        "method:POST host:api.example.com status:>=400".to_string()
    } else {
        state.filter.clone()
    };
    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(title))
        .style(if state.entering_filter {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        });
    frame.render_widget(paragraph, area);
}

fn render_details(frame: &mut Frame<'_>, area: Rect, entries: &[TrafficEntry], state: &TuiState) {
    let Some(entry) = entries.get(state.selected.min(entries.len().saturating_sub(1))) else {
        frame.render_widget(Paragraph::new("No request selected"), area);
        return;
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)])
        .split(area);
    let titles = ["Overview", "Request", "Response", "TLS", "Timing", "Raw"]
        .into_iter()
        .map(Line::from)
        .collect::<Vec<_>>();
    let selected = match state.tab {
        crate::tui::state::DetailTab::Overview => 0,
        crate::tui::state::DetailTab::Request => 1,
        crate::tui::state::DetailTab::Response => 2,
        crate::tui::state::DetailTab::Tls => 3,
        crate::tui::state::DetailTab::Timing => 4,
        crate::tui::state::DetailTab::Raw => 5,
    };
    let tabs = Tabs::new(titles)
        .select(selected)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("#{}", entry.id)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, chunks[0]);

    match state.tab {
        crate::tui::state::DetailTab::Overview => {
            request_details::render_overview(frame, chunks[1], entry, state.detail_scroll_offset)
        }
        crate::tui::state::DetailTab::Request => {
            request_details::render_request(frame, chunks[1], entry, state.detail_scroll_offset)
        }
        crate::tui::state::DetailTab::Response => {
            response_details::render_response(frame, chunks[1], entry, state.detail_scroll_offset)
        }
        crate::tui::state::DetailTab::Tls => {
            response_details::render_tls(frame, chunks[1], entry, state.detail_scroll_offset)
        }
        crate::tui::state::DetailTab::Timing => {
            response_details::render_timing(frame, chunks[1], entry, state.detail_scroll_offset)
        }
        crate::tui::state::DetailTab::Raw => {
            response_details::render_raw(frame, chunks[1], entry, state.detail_scroll_offset)
        }
    }
}

fn render_quit_dialog(frame: &mut Frame<'_>, area: Rect, has_child: bool) {
    let width = area.width.min(64);
    let height = if has_child { 7 } else { 5 };
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let popup = Rect::new(x, y, width, height);
    frame.render_widget(Clear, popup);
    let text = if has_child {
        vec![
            Line::from("The child process is still running."),
            Line::from(""),
            Line::from("[1] Stop proxy and terminate child"),
            Line::from("[2] Stop UI but leave child running"),
            Line::from("[3] Cancel"),
        ]
    } else {
        vec![
            Line::from("Quit TLScope?"),
            Line::from("[1] Quit  [3] Cancel"),
        ]
    };
    let paragraph = Paragraph::new(text)
        .alignment(Alignment::Left)
        .block(Block::default().borders(Borders::ALL).title("Quit"));
    frame.render_widget(paragraph, popup);
}
