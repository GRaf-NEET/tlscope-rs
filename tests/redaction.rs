use std::time::{Duration, SystemTime};

use tlscope::capture::{
    export::{export_curl, export_session_json},
    model::{CapturedBody, TrafficEntry},
    redact::{redact_body, redact_headers, RedactionConfig},
};

#[test]
fn redacts_headers_json_and_curl_by_default() {
    let config = RedactionConfig::new(true, false);
    let headers = vec![
        ("Authorization".to_string(), "Bearer secret".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let redacted_headers = redact_headers(&headers, &config);
    assert_eq!(redacted_headers[0].1, "<redacted>");

    let body = CapturedBody::from_bytes(
        br#"{"password":"secret","name":"alice"}"#,
        1024,
        Some("application/json".to_string()),
        None,
    );
    let redacted_body = redact_body(&body, &config);
    let text = String::from_utf8(redacted_body.bytes).unwrap();
    assert!(text.contains("<redacted>"));
    assert!(!text.contains("secret"));

    let entry = sample_entry(headers, body);
    let curl = export_curl(&entry, &config);
    assert!(curl.contains("<redacted>"));
    assert!(!curl.contains("Bearer secret"));
}

#[test]
fn exports_redacted_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.json");
    let entry = sample_entry(
        vec![("Authorization".to_string(), "Bearer secret".to_string())],
        CapturedBody::empty(),
    );
    export_session_json(&path, &[entry], &RedactionConfig::new(false, false)).unwrap();
    let json = std::fs::read_to_string(path).unwrap();
    assert!(json.contains("<redacted>"));
    assert!(!json.contains("Bearer secret"));
}

fn sample_entry(headers: Vec<(String, String)>, body: CapturedBody) -> TrafficEntry {
    TrafficEntry {
        id: 1,
        started_at: SystemTime::UNIX_EPOCH,
        duration: Duration::from_millis(25),
        process_id: Some(42),
        scheme: "https".to_string(),
        host: "api.example.com".to_string(),
        port: 443,
        method: "POST".to_string(),
        path: "/login".to_string(),
        http_version: "HTTP/1.1".to_string(),
        request_headers: headers,
        request_body: body,
        response_status: Some(200),
        response_headers: Vec::new(),
        response_body: CapturedBody::empty(),
        request_size: 0,
        response_size: 0,
        tls: None,
        error: None,
    }
}
