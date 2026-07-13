use crate::{
    process::logs::{ChildLogSnapshot, ChildOutputStream},
    tui::{
        logs::{TlscopeLogLevel, TlscopeLogSnapshot},
        state::LogTab,
    },
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
    Frame,
};

pub fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    process_logs: &ChildLogSnapshot,
    tlscope_logs: &TlscopeLogSnapshot,
    selected_tab: LogTab,
    scroll_offset: usize,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(2)])
        .split(area);

    let titles = [LogTab::Process.title(), LogTab::Tlscope.title()]
        .into_iter()
        .map(Line::from)
        .collect::<Vec<_>>();
    let selected = match selected_tab {
        LogTab::Process => 0,
        LogTab::Tlscope => 1,
    };
    let tabs = Tabs::new(titles)
        .select(selected)
        .block(Block::default().borders(Borders::ALL).title("Logs"))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, chunks[0]);

    match selected_tab {
        LogTab::Process => render_process_logs(frame, chunks[1], process_logs, scroll_offset),
        LogTab::Tlscope => render_tlscope_logs(frame, chunks[1], tlscope_logs, scroll_offset),
    }
}

fn render_process_logs(
    frame: &mut Frame<'_>,
    area: Rect,
    logs: &ChildLogSnapshot,
    scroll_offset: usize,
) {
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

    render_log_lines(frame, area, title, lines, scroll_offset);
}

fn render_tlscope_logs(
    frame: &mut Frame<'_>,
    area: Rect,
    logs: &TlscopeLogSnapshot,
    scroll_offset: usize,
) {
    let title = if logs.dropped > 0 {
        format!(
            "TLScope logs ({} shown / {} total, {} dropped)",
            logs.lines.len(),
            logs.total,
            logs.dropped
        )
    } else {
        format!("TLScope logs ({} lines)", logs.lines.len())
    };

    let lines = if logs.lines.is_empty() {
        vec![Line::styled(
            "No TLScope logs captured yet.",
            Style::default().fg(Color::DarkGray),
        )]
    } else {
        logs.lines
            .iter()
            .map(|entry| {
                Line::from(vec![
                    Span::styled(
                        format!("{:>5} ", entry.level.label()),
                        level_label_style(entry.level),
                    ),
                    Span::styled(
                        format!("{} ", entry.target),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(entry.text.clone(), level_text_style(entry.level)),
                ])
            })
            .collect()
    };

    render_log_lines(frame, area, title, lines, scroll_offset);
}

fn render_log_lines(
    frame: &mut Frame<'_>,
    area: Rect,
    title: String,
    lines: Vec<Line<'_>>,
    scroll_offset: usize,
) {
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

fn level_label_style(level: TlscopeLogLevel) -> Style {
    match level {
        TlscopeLogLevel::Error => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        TlscopeLogLevel::Warn => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        TlscopeLogLevel::Info => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
        TlscopeLogLevel::Debug => Style::default().fg(Color::Blue),
        TlscopeLogLevel::Trace => Style::default().fg(Color::DarkGray),
    }
}

fn level_text_style(level: TlscopeLogLevel) -> Style {
    match level {
        TlscopeLogLevel::Error => Style::default().fg(Color::Red),
        TlscopeLogLevel::Warn => Style::default().fg(Color::Yellow),
        TlscopeLogLevel::Info | TlscopeLogLevel::Debug | TlscopeLogLevel::Trace => Style::default(),
    }
}
