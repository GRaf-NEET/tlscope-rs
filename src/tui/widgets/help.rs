use ratatui::{
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn render(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from("List: Up/Down or j/k select request, PgUp/PgDn page, Home/End jump"),
        Line::from("Details: Up/Down or j/k scroll, PgUp/PgDn page, Home/End jump"),
        Line::from("Enter: details    Esc: back    Tab / Shift+Tab: switch detail tab"),
        Line::from("Filter: / edit    Tab accept suggestion    Enter apply    Esc cancel"),
        Line::from("Filter edit: Left/Right, Delete, Ctrl+U clear, Ctrl+W delete token"),
        Line::from("l: logs    Tab: process/TLScope logs    y: copy current logs"),
        Line::from("Space: pause/live    c: clear    e: export JSON"),
        Line::from("Keys: method host path status type has error tls duration"),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Help")),
        area,
    );
}
