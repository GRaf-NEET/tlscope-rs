use crate::{
    capture::model::TrafficEntry,
    tui::widgets::request_details::{body_preview, header, hex_preview},
};
use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

pub fn render_response(frame: &mut Frame<'_>, area: Rect, entry: &TrafficEntry) {
    let mut text = String::new();
    text.push_str(&format!("Status: {}\n\n", entry.status_label()));
    text.push_str("Headers:\n");
    for (name, value) in &entry.response_headers {
        text.push_str(&format!("{name}: {value}\n"));
    }
    text.push_str("\nCookies:\n");
    text.push_str(
        &header(&entry.response_headers, "set-cookie").unwrap_or_else(|| "N/A".to_string()),
    );
    text.push_str("\n\nBody:\n");
    text.push_str(&body_preview(&entry.response_body));
    frame.render_widget(panel("Response", text), area);
}

pub fn render_tls(frame: &mut Frame<'_>, area: Rect, entry: &TrafficEntry) {
    let text = if let Some(tls) = &entry.tls {
        let cert = tls.certificate.as_ref();
        format!(
            "Host: {}\nTLS: {}\nALPN: {}\nSubject: {}\nIssuer: {}\nSAN: {}\nValid from: {}\nValid until: {}\nSHA-256: {}\nVerification: {}\n\n{}",
            tls.host,
            tls.tls_version.as_deref().unwrap_or("N/A"),
            tls.alpn.as_deref().unwrap_or("N/A"),
            cert.map(|c| c.subject.as_str()).unwrap_or("N/A"),
            cert.map(|c| c.issuer.as_str()).unwrap_or("N/A"),
            cert.map(|c| c.san.join(", ")).unwrap_or_else(|| "N/A".to_string()),
            cert.map(|c| c.valid_from.as_str()).unwrap_or("N/A"),
            cert.map(|c| c.valid_until.as_str()).unwrap_or("N/A"),
            cert.map(|c| c.sha256_fingerprint.as_str()).unwrap_or("N/A"),
            tls.verification,
            tls.child_certificate_note,
        )
    } else {
        "No decrypted TLS information. CONNECT may be tunneled or this was plain HTTP.".to_string()
    };
    frame.render_widget(panel("TLS", text), area);
}

pub fn render_timing(frame: &mut Frame<'_>, area: Rect, entry: &TrafficEntry) {
    let text = format!(
        "Local proxy connection: N/A\nDNS: N/A\nTCP connect: N/A\nTLS handshake: N/A\nRequest send: N/A\nFirst byte wait: N/A\nResponse download: N/A\nTotal: {}ms",
        entry.duration.as_millis()
    );
    frame.render_widget(panel("Timing", text), area);
}

pub fn render_raw(frame: &mut Frame<'_>, area: Rect, entry: &TrafficEntry) {
    let mut text = String::new();
    text.push_str(&format!(
        "{} {} {}\n",
        entry.method, entry.path, entry.http_version
    ));
    for (name, value) in &entry.request_headers {
        text.push_str(&format!("{name}: {value}\n"));
    }
    text.push('\n');
    if let Some(body) = entry.request_body.text_preview() {
        text.push_str(&body);
    } else {
        text.push_str(&hex_preview(&entry.request_body.bytes));
    }
    text.push_str("\n\n--- response ---\n");
    text.push_str(&format!("Status: {}\n", entry.status_label()));
    for (name, value) in &entry.response_headers {
        text.push_str(&format!("{name}: {value}\n"));
    }
    text.push('\n');
    if let Some(body) = entry.response_body.text_preview() {
        text.push_str(&body);
    } else {
        text.push_str(&hex_preview(&entry.response_body.bytes));
    }
    frame.render_widget(panel("Raw", text), area);
}

fn panel(title: &'static str, text: String) -> Paragraph<'static> {
    Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false })
}
