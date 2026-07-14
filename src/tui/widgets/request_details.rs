use crate::capture::{details, model::TrafficEntry};
use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

pub fn render_overview(
    frame: &mut Frame<'_>,
    area: Rect,
    entry: &TrafficEntry,
    scroll_offset: usize,
) {
    render_panel(
        frame,
        area,
        "Overview",
        details::overview_text(entry),
        scroll_offset,
    );
}

pub fn render_request(
    frame: &mut Frame<'_>,
    area: Rect,
    entry: &TrafficEntry,
    scroll_offset: usize,
) {
    render_panel(
        frame,
        area,
        "Request",
        details::request_text(entry),
        scroll_offset,
    );
}

pub fn render_panel(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &'static str,
    text: String,
    scroll_offset: usize,
) {
    let paragraph = panel(title, text, area, scroll_offset);
    frame.render_widget(paragraph, area);
}

fn panel(
    title: &'static str,
    text: String,
    area: Rect,
    scroll_offset: usize,
) -> Paragraph<'static> {
    let max_scroll = max_scroll_offset(&text, area);
    let scroll = scroll_offset.min(max_scroll).min(u16::MAX as usize) as u16;
    Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
}

pub fn max_scroll_offset(text: &str, area: Rect) -> usize {
    let inner_width = area.width.saturating_sub(2).max(1) as usize;
    let inner_height = area.height.saturating_sub(2).max(1) as usize;
    let visual_lines = text
        .lines()
        .map(|line| wrapped_line_count(line, inner_width))
        .sum::<usize>()
        .max(1);
    visual_lines.saturating_sub(inner_height)
}

fn wrapped_line_count(line: &str, width: usize) -> usize {
    let len = line.chars().count().max(1);
    len.div_ceil(width)
}
