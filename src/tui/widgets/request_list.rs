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
    let rows = entries.iter().enumerate().map(|(index, entry)| {
        let status = entry.status_label();
        let style = row_style(entry, index == selected);
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
    .block(Block::default().borders(Borders::ALL).title("Requests"));
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
