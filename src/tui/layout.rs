use crate::{
    capture::{filter_suggestions::FilterParseState, model::TrafficEntry, store::TrafficStore},
    diagnostics::logs::TlscopeLogSnapshot,
    process::logs::ChildLogSnapshot,
    tui::{
        filter,
        state::{Screen, TuiRuntime, TuiState},
        widgets::{
            help, process_logs, request_details, request_list, response_details, status_bar,
        },
    },
};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Position, Rect},
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
    tlscope_logs: &TlscopeLogSnapshot,
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
        Screen::Logs => process_logs::render(
            frame,
            chunks[2],
            logs,
            tlscope_logs,
            state.log_tab,
            state.log_scroll_offset,
        ),
        Screen::Help => help::render(frame, chunks[2]),
    }

    render_filter_suggestions(frame, chunks[2], state);
    status_bar::render_footer(frame, chunks[3], state);

    if state.confirm_quit {
        render_quit_dialog(frame, area, runtime.child_running.is_some());
    }
}

fn render_filter(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let title = if state.entering_filter {
        match &state.filter_editor.error {
            Some(_) => "Filter (editing, error)",
            None => match state.filter_editor.parse_state {
                FilterParseState::Valid => "Filter (editing)",
                FilterParseState::Incomplete => "Filter (editing, incomplete)",
                FilterParseState::Invalid(_) => "Filter (editing, invalid)",
            },
        }
    } else {
        "Filter"
    };

    let style = if state.entering_filter {
        if state.filter_editor.error.is_some()
            || matches!(
                state.filter_editor.parse_state,
                FilterParseState::Invalid(_)
            )
        {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Yellow)
        }
    } else {
        Style::default()
    };

    let text = if state.entering_filter {
        let width = area.width.saturating_sub(2) as usize;
        filter::visible_text(&state.filter_editor.text, state.filter_editor.cursor, width).text
    } else if state.applied_filter_text.is_empty() {
        "method:POST host:api.example.com status:>=400".to_string()
    } else {
        state.applied_filter_text.clone()
    };

    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(title))
        .style(style);
    frame.render_widget(paragraph, area);

    if state.entering_filter {
        let width = area.width.saturating_sub(2) as usize;
        let view =
            filter::visible_text(&state.filter_editor.text, state.filter_editor.cursor, width);
        let cursor_x = area
            .x
            .saturating_add(1)
            .saturating_add(view.cursor_column.min(area.width.saturating_sub(2)));
        frame.set_cursor_position(Position {
            x: cursor_x,
            y: area.y.saturating_add(1),
        });
    }
}

fn render_filter_suggestions(frame: &mut Frame<'_>, content_area: Rect, state: &TuiState) {
    if !state.entering_filter {
        return;
    }

    let error = state.filter_editor.error.as_ref().cloned().or_else(|| {
        if state.filter_editor.suggestions.is_empty() {
            if let FilterParseState::Invalid(error) = &state.filter_editor.parse_state {
                return Some(error.clone());
            }
        }
        None
    });

    let error_rows = usize::from(error.is_some());
    let suggestion_slots = 7usize.saturating_sub(error_rows);
    let visible_suggestions = state
        .filter_editor
        .suggestions
        .len()
        .saturating_sub(state.filter_editor.suggestion_scroll)
        .min(suggestion_slots);
    let height = error_rows + visible_suggestions;
    if height == 0 {
        return;
    }

    let area = Rect {
        x: content_area.x,
        y: content_area.y,
        width: content_area.width,
        height: height.min(7) as u16,
    };
    frame.render_widget(Clear, area);

    let mut lines = Vec::new();
    if let Some(error) = error {
        lines.push(Line::styled(
            format!("! {error}"),
            Style::default().fg(Color::Red),
        ));
    }

    for (offset, suggestion) in state
        .filter_editor
        .suggestions
        .iter()
        .skip(state.filter_editor.suggestion_scroll)
        .take(visible_suggestions)
        .enumerate()
    {
        let index = state.filter_editor.suggestion_scroll + offset;
        let marker = if index == state.filter_editor.selected_suggestion {
            "> "
        } else {
            "  "
        };
        let style = if index == state.filter_editor.selected_suggestion {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::styled(
            format!("{marker}{}", suggestion.display),
            style,
        ));
    }

    frame.render_widget(Paragraph::new(lines), area);
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
