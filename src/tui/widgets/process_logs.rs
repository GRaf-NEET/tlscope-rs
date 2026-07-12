use crate::process::logs::{ChildLogSnapshot, ChildOutputStream};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn render(frame: &mut Frame<'_>, area: Rect, logs: &ChildLogSnapshot, scroll_offset: usize) {
    let title = if logs.dropped > 0 {
        format!(
            "Process logs ({} shown / {} total, {} dropped)",
            logs.lines.len(),
            logs.total,
            logs.dropped
        )
    } else {
        format!("Process logs ({} lines)", logs.lines.len())
    };

    let lines = if logs.lines.is_empty() {
        vec![Line::styled(
            "No process logs captured yet.",
            Style::default().fg(Color::DarkGray),
        )]
    } else {
        logs.lines
            .iter()
            .map(|entry| {
                let label_style = stream_label_style(entry.stream);
                let text_style = stream_text_style(entry.stream);
                Line::from(vec![
                    Span::styled(format!("{:>6} ", entry.stream.label()), label_style),
                    Span::styled(entry.text.clone(), text_style),
                ])
            })
            .collect()
    };

    let visible_rows = area.height.saturating_sub(2) as usize;
    let max_top = lines.len().saturating_sub(visible_rows);
    let top = max_top.saturating_sub(scroll_offset.min(max_top));

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .scroll((top.min(u16::MAX as usize) as u16, 0));
    frame.render_widget(paragraph, area);
}

fn stream_label_style(stream: ChildOutputStream) -> Style {
    match stream {
        ChildOutputStream::Stdout => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
        ChildOutputStream::Stderr => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

fn stream_text_style(stream: ChildOutputStream) -> Style {
    match stream {
        ChildOutputStream::Stdout => Style::default(),
        ChildOutputStream::Stderr => Style::default().fg(Color::Red),
    }
}
