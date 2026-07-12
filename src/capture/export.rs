use crate::capture::{
    model::TrafficEntry,
    redact::{redact_headers, redacted_entry, RedactionConfig},
};
use anyhow::{Context, Result};
use base64::Engine;
use serde_json::json;
use std::{fs, path::Path};

pub fn export_session_json(
    path: impl AsRef<Path>,
    entries: &[TrafficEntry],
    redaction: &RedactionConfig,
) -> Result<()> {
    let redacted = entries
        .iter()
        .map(|entry| redacted_entry(entry, redaction))
        .collect::<Vec<_>>();
    let data = serde_json::to_vec_pretty(&redacted)?;
    fs::write(path.as_ref(), data)
        .with_context(|| format!("failed to write JSON export to {}", path.as_ref().display()))
}

pub fn export_har(
    path: impl AsRef<Path>,
    entries: &[TrafficEntry],
    redaction: &RedactionConfig,
) -> Result<()> {
    let har_entries = entries
        .iter()
        .map(|entry| {
            let entry = redacted_entry(entry, redaction);
            json!({
                "startedDateTime": format!("{:?}", entry.started_at),
                "time": entry.duration.as_millis(),
                "request": {
                    "method": entry.method,
                    "url": entry.url(),
                    "httpVersion": entry.http_version,
                    "headers": headers_to_har(&entry.request_headers),
                    "bodySize": entry.request_body.original_size,
                },
                "response": {
                    "status": entry.response_status.unwrap_or(0),
                    "statusText": entry.status_label(),
                    "httpVersion": "HTTP/1.1",
                    "headers": headers_to_har(&entry.response_headers),
                    "bodySize": entry.response_body.original_size,
                },
                "cache": {},
                "timings": { "send": -1, "wait": -1, "receive": -1 },
            })
        })
        .collect::<Vec<_>>();
    let har = json!({
        "log": {
            "version": "1.2",
            "creator": {"name": "TLScope", "version": env!("CARGO_PKG_VERSION")},
            "entries": har_entries,
        }
    });
    fs::write(path.as_ref(), serde_json::to_vec_pretty(&har)?)
        .with_context(|| format!("failed to write HAR export to {}", path.as_ref().display()))
}

pub fn export_text_report(
    path: impl AsRef<Path>,
    entries: &[TrafficEntry],
    redaction: &RedactionConfig,
) -> Result<()> {
    let mut out = String::new();
    for entry in entries {
        let entry = redacted_entry(entry, redaction);
        out.push_str(&format!(
            "#{} {} {} {} {}\n",
            entry.id,
            entry.method,
            entry.url(),
            entry.status_label(),
            format_size(entry.response_size)
        ));
        if let Some(error) = &entry.error {
            out.push_str(&format!("error: {error}\n"));
        }
        out.push('\n');
    }
    fs::write(path.as_ref(), out)
        .with_context(|| format!("failed to write text export to {}", path.as_ref().display()))
}

pub fn export_curl(entry: &TrafficEntry, redaction: &RedactionConfig) -> String {
    let headers = redact_headers(&entry.request_headers, redaction);
    let mut parts = vec![
        "curl".to_string(),
        "-X".to_string(),
        shell_quote(&entry.method),
        shell_quote(&entry.url()),
    ];
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        parts.push("-H".to_string());
        parts.push(shell_quote(&format!("{name}: {value}")));
    }
    if !entry.request_body.bytes.is_empty() {
        if let Ok(text) = std::str::from_utf8(&entry.request_body.bytes) {
            parts.push("--data-binary".to_string());
            parts.push(shell_quote(text));
        } else {
            parts.push("--data-binary".to_string());
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(&entry.request_body.bytes);
            parts.push(shell_quote(&format!("@<(base64 -d <<<'{encoded}')")));
        }
    }
    parts.join(" ")
}

pub fn format_size(size: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    if size < 1024 {
        format!("{size} B")
    } else if (size as f64) < MB {
        format!("{:.1} KB", size as f64 / KB)
    } else {
        format!("{:.1} MB", size as f64 / MB)
    }
}

fn headers_to_har(headers: &[(String, String)]) -> Vec<serde_json::Value> {
    headers
        .iter()
        .map(|(name, value)| json!({"name": name, "value": value}))
        .collect()
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./:=?&%+".contains(c))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::model::{CapturedBody, TrafficEntry};
    use std::time::{Duration, SystemTime};

    #[test]
    fn exports_json_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.json");
        let entry = TrafficEntry {
            id: 1,
            started_at: SystemTime::UNIX_EPOCH,
            duration: Duration::from_millis(10),
            process_id: None,
            scheme: "http".to_string(),
            host: "example.com".to_string(),
            port: 80,
            method: "GET".to_string(),
            path: "/".to_string(),
            http_version: "HTTP/1.1".to_string(),
            request_headers: vec![("Authorization".to_string(), "secret".to_string())],
            request_body: CapturedBody::empty(),
            response_status: Some(200),
            response_headers: Vec::new(),
            response_body: CapturedBody::empty(),
            request_size: 0,
            response_size: 0,
            tls: None,
            error: None,
        };
        export_session_json(&path, &[entry], &RedactionConfig::new(false, false)).expect("export");
        let content = fs::read_to_string(path).expect("read");
        assert!(content.contains("<redacted>"));
        assert!(!content.contains("secret"));
    }
}
