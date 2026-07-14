use crate::{
    capture::{details, model::TrafficEntry},
    tui::widgets::request_details::render_panel,
};
use ratatui::{layout::Rect, Frame};

pub fn render_response(
    frame: &mut Frame<'_>,
    area: Rect,
    entry: &TrafficEntry,
    scroll_offset: usize,
) {
    render_panel(
        frame,
        area,
        "Response",
        details::response_text(entry),
        scroll_offset,
    );
}

pub fn render_tls(frame: &mut Frame<'_>, area: Rect, entry: &TrafficEntry, scroll_offset: usize) {
    render_panel(frame, area, "TLS", details::tls_text(entry), scroll_offset);
}

pub fn render_timing(
    frame: &mut Frame<'_>,
    area: Rect,
    entry: &TrafficEntry,
    scroll_offset: usize,
) {
    render_panel(
        frame,
        area,
        "Timing",
        details::timing_text(entry),
        scroll_offset,
    );
}

pub fn render_raw(frame: &mut Frame<'_>, area: Rect, entry: &TrafficEntry, scroll_offset: usize) {
    render_panel(frame, area, "Raw", details::raw_text(entry), scroll_offset);
}
