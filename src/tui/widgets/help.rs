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
        Line::from("l: process logs    Home/End: oldest/latest log    PgUp/PgDn: page logs"),
        Line::from("/: filter    Space: pause/live    c: clear    e: export JSON"),
        Line::from("r: reapply filter    y: show selected URL    ?: help    q: quit"),
        Line::from("Filters: method:POST host:api.example.com path:/v1 status:>=400 type:json has:request-body error:true tls:false duration:>500ms"),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Help")),
        area,
    );
}
