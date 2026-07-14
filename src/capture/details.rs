use crate::capture::{
    decode::decode_body_for_preview,
    export::format_size,
    model::{CapturedBody, TrafficEntry},
};
use url::Url;

pub fn overview_text(entry: &TrafficEntry) -> String {
    let content_type = header(entry.response_headers.as_slice(), "content-type")
        .or_else(|| header(entry.request_headers.as_slice(), "content-type"))
        .unwrap_or_else(|| "N/A".to_string());
    [
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
    .join("\n")
}

pub fn request_text(entry: &TrafficEntry) -> String {
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
    text
}

pub fn response_text(entry: &TrafficEntry) -> String {
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
    text
}

pub fn tls_text(entry: &TrafficEntry) -> String {
    if let Some(tls) = &entry.tls {
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
    }
}

pub fn timing_text(entry: &TrafficEntry) -> String {
    format!(
        "Local proxy connection: N/A\nDNS: N/A\nTCP connect: N/A\nTLS handshake: N/A\nRequest send: N/A\nFirst byte wait: N/A\nResponse download: N/A\nTotal: {}ms",
        entry.duration.as_millis()
    )
}

pub fn raw_text(entry: &TrafficEntry) -> String {
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
    text
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
