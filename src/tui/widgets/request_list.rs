use crate::capture::{export::format_size, model::TrafficEntry};
use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
    Frame,
};

pub fn render(frame: &mut Frame<'_>, area: Rect, entries: &[TrafficEntry], selected: usize) {
    let header = Row::new(["ID", "Method", "Status", "Host / Path", "Time", "Size"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let visible_rows = area.height.saturating_sub(3).max(1) as usize;
    let safe_selected = selected.min(entries.len().saturating_sub(1));
    let first_visible = if entries.is_empty() || safe_selected < visible_rows {
        0
    } else {
        safe_selected + 1 - visible_rows
    };
    let rows = entries
        .iter()
        .enumerate()
        .skip(first_visible)
        .take(visible_rows)
        .map(|(index, entry)| {
            let status = entry.status_label();
            let style = row_style(entry, index == safe_selected);
            Row::new([
                Cell::from(entry.id.to_string()),
                Cell::from(entry.method.clone()),
                Cell::from(status),
                Cell::from(entry.display_target()),
                Cell::from(format!("{}ms", entry.duration.as_millis())),
                Cell::from(format_size(entry.response_size)),
            ])
            .style(style)
        });
    let title = if entries.is_empty() {
        "Requests".to_string()
    } else {
        format!("Requests {}/{}", safe_selected + 1, entries.len())
    };
    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Percentage(55),
            Constraint::Length(9),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(table, area);
}

fn row_style(entry: &TrafficEntry, selected: bool) -> Style {
    let base = if entry.error.is_some() {
        Style::default().fg(Color::Red)
    } else if let Some(status) = entry.response_status {
        match status {
            200..=299 => Style::default().fg(Color::Green),
            300..=399 => Style::default().fg(Color::Cyan),
            400..=499 => Style::default().fg(Color::Yellow),
            500..=599 => Style::default().fg(Color::Red),
            _ => Style::default(),
        }
    } else {
        Style::default().fg(Color::Blue)
    };
    if selected {
        base.add_modifier(Modifier::REVERSED)
    } else {
        base
    }
}
