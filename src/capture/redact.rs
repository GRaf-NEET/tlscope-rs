use crate::capture::model::{CapturedBody, TrafficEntry};
use serde_json::Value;
use std::collections::HashSet;
use url::form_urlencoded;

const DEFAULT_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
];

const DEFAULT_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "api_key",
    "client_secret",
    "credit_card",
    "card_number",
    "cvv",
];

#[derive(Debug, Clone)]
pub struct RedactionConfig {
    pub redact_body_fields: bool,
    pub show_secrets: bool,
    headers: HashSet<String>,
    fields: HashSet<String>,
}

impl RedactionConfig {
    pub fn new(redact_body_fields: bool, show_secrets: bool) -> Self {
        Self {
            redact_body_fields,
            show_secrets,
            headers: DEFAULT_HEADERS.iter().map(|v| (*v).to_string()).collect(),
            fields: DEFAULT_FIELDS.iter().map(|v| (*v).to_string()).collect(),
        }
    }

    pub fn add_header(&mut self, header: impl Into<String>) {
        self.headers.insert(header.into().to_ascii_lowercase());
    }

    pub fn add_field(&mut self, field: impl Into<String>) {
        self.fields.insert(field.into().to_ascii_lowercase());
    }

    pub fn should_redact_header(&self, name: &str) -> bool {
        !self.show_secrets && self.headers.contains(&name.to_ascii_lowercase())
    }

    pub fn should_redact_field(&self, name: &str) -> bool {
        !self.show_secrets
            && self.redact_body_fields
            && self.fields.contains(&name.to_ascii_lowercase())
    }
}

pub fn redact_headers(
    headers: &[(String, String)],
    config: &RedactionConfig,
) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            if config.should_redact_header(name) {
                (name.clone(), "<redacted>".to_string())
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect()
}

pub fn redact_body(body: &CapturedBody, config: &RedactionConfig) -> CapturedBody {
    if config.show_secrets || !config.redact_body_fields {
        return body.clone();
    }

    let content_type = body
        .content_type
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if content_type.contains("application/json") {
        if let Ok(mut value) = serde_json::from_slice::<Value>(&body.bytes) {
            redact_json_value(&mut value, config);
            if let Ok(bytes) = serde_json::to_vec_pretty(&value) {
                let mut redacted = body.clone();
                redacted.bytes = bytes;
                redacted.decoded_size = Some(redacted.bytes.len() as u64);
                return redacted;
            }
        }
    }

    if content_type.contains("application/x-www-form-urlencoded") {
        let pairs = form_urlencoded::parse(&body.bytes)
            .map(|(key, value)| {
                if config.should_redact_field(&key) {
                    (key.into_owned(), "<redacted>".to_string())
                } else {
                    (key.into_owned(), value.into_owned())
                }
            })
            .collect::<Vec<_>>();
        let mut encoded = form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            encoded.append_pair(&key, &value);
        }
        let mut redacted = body.clone();
        redacted.bytes = encoded.finish().into_bytes();
        redacted.decoded_size = Some(redacted.bytes.len() as u64);
        return redacted;
    }

    body.clone()
}

pub fn redacted_entry(entry: &TrafficEntry, config: &RedactionConfig) -> TrafficEntry {
    let mut copy = entry.clone();
    copy.request_headers = redact_headers(&copy.request_headers, config);
    copy.response_headers = redact_headers(&copy.response_headers, config);
    copy.request_body = redact_body(&copy.request_body, config);
    copy.response_body = redact_body(&copy.response_body, config);
    copy
}

fn redact_json_value(value: &mut Value, config: &RedactionConfig) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if config.should_redact_field(key) {
                    *child = Value::String("<redacted>".to_string());
                } else {
                    redact_json_value(child, config);
                }
            }
        }
        Value::Array(items) => {
            for child in items {
                redact_json_value(child, config);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_default_headers() {
        let headers = vec![
            ("Authorization".to_string(), "Bearer abc".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let redacted = redact_headers(&headers, &RedactionConfig::new(false, false));
        assert_eq!(redacted[0].1, "<redacted>");
        assert_eq!(redacted[1].1, "application/json");
    }

    #[test]
    fn redacts_json_fields_when_enabled() {
        let body = CapturedBody::from_bytes(
            br#"{"user":"a","password":"secret","nested":{"token":"x"}}"#,
            1024,
            Some("application/json".to_string()),
            None,
        );
        let redacted = redact_body(&body, &RedactionConfig::new(true, false));
        let text = String::from_utf8(redacted.bytes).unwrap_or_default();
        assert!(text.contains("<redacted>"));
        assert!(!text.contains("secret"));
        assert!(!text.contains("\"x\""));
    }
}
