use crate::capture::{
    decode::decode_body_for_preview,
    export::format_size,
    model::{CapturedBody, TrafficEntry},
};
use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};
use url::Url;

pub fn render_overview(frame: &mut Frame<'_>, area: Rect, entry: &TrafficEntry) {
    let content_type = header(entry.response_headers.as_slice(), "content-type")
        .or_else(|| header(entry.request_headers.as_slice(), "content-type"))
        .unwrap_or_else(|| "N/A".to_string());
    let text = [
        format!("URL: {}", entry.url()),
        format!("Method: {}", entry.method),
        format!("Status: {}", entry.status_label()),
        format!("Duration: {}ms", entry.duration.as_millis()),
        format!("Request size: {}", format_size(entry.request_size)),
        format!("Response size: {}", format_size(entry.response_size)),
        format!("Content-Type: {content_type}"),
        "Remote IP: N/A".to_string(),
        format!(
            "PID: {}",
            entry
                .process_id
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string())
        ),
        format!("Started: {:?}", entry.started_at),
        format!("Completed: {:?}", entry.started_at + entry.duration),
        format!(
            "Error: {}",
            entry.error.clone().unwrap_or_else(|| "N/A".to_string())
        ),
    ]
    .join("\n");
    frame.render_widget(panel("Overview", text), area);
}

pub fn render_request(frame: &mut Frame<'_>, area: Rect, entry: &TrafficEntry) {
    let mut text = String::new();
    text.push_str("Headers:\n");
    for (name, value) in &entry.request_headers {
        text.push_str(&format!("{name}: {value}\n"));
    }
    text.push_str("\nQuery parameters:\n");
    text.push_str(&query_params(entry));
    text.push_str("\nCookies:\n");
    text.push_str(&header(&entry.request_headers, "cookie").unwrap_or_else(|| "N/A".to_string()));
    text.push_str("\n\nBody:\n");
    text.push_str(&body_preview(&entry.request_body));
    frame.render_widget(panel("Request", text), area);
}

pub fn body_preview(body: &CapturedBody) -> String {
    if body.original_size == 0 {
        return "N/A".to_string();
    }

    let decoded = decode_body_for_preview(body);
    let mut out = String::new();
    out.push_str(&format!(
        "stored={} original={} decoded={} truncated={} transfer={} encoding={}\n",
        format_size(body.bytes.len() as u64),
        format_size(body.original_size),
        format_size(decoded.bytes.len() as u64),
        body.truncated,
        body.transfer_encoding.as_deref().unwrap_or("identity"),
        body.content_encoding.as_deref().unwrap_or("identity")
    ));
    for warning in &decoded.warnings {
        out.push_str(&format!("decode warning: {warning}\n"));
    }

    if let Ok(text) = std::str::from_utf8(&decoded.bytes) {
        if body
            .content_type
            .as_deref()
            .unwrap_or_default()
            .contains("json")
        {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
                if let Ok(pretty) = serde_json::to_string_pretty(&json) {
                    out.push_str(&pretty);
                    return out;
                }
            }
        }
        out.push_str(text);
    } else {
        out.push_str(&hex_preview(&decoded.bytes));
    }
    out
}
fn query_params(entry: &TrafficEntry) -> String {
    let url = entry.url();
    match Url::parse(&url) {
        Ok(url) => {
            let pairs = url.query_pairs().collect::<Vec<_>>();
            if pairs.is_empty() {
                "N/A".to_string()
            } else {
                pairs
                    .into_iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
        Err(_) => "N/A".to_string(),
    }
}

pub fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

pub fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(512)
        .enumerate()
        .map(|(index, byte)| {
            if index > 0 && index % 16 == 0 {
                format!("\n{byte:02X}")
            } else {
                format!("{byte:02X} ")
            }
        })
        .collect::<String>()
}

fn panel(title: &'static str, text: String) -> Paragraph<'static> {
    Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false })
}
