use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedBody {
    pub bytes: Vec<u8>,
    pub original_size: u64,
    pub decoded_size: Option<u64>,
    pub truncated: bool,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    #[serde(default)]
    pub transfer_encoding: Option<String>,
}

impl CapturedBody {
    pub fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            original_size: 0,
            decoded_size: None,
            truncated: false,
            content_type: None,
            content_encoding: None,
            transfer_encoding: None,
        }
    }

    pub fn from_bytes(
        bytes: &[u8],
        max_body_size: usize,
        content_type: Option<String>,
        content_encoding: Option<String>,
    ) -> Self {
        let keep = bytes.len().min(max_body_size);
        Self {
            bytes: bytes[..keep].to_vec(),
            original_size: bytes.len() as u64,
            decoded_size: None,
            truncated: bytes.len() > keep,
            content_type,
            content_encoding,
            transfer_encoding: None,
        }
    }

    pub fn push_capture(&mut self, chunk: &[u8], max_body_size: usize) {
        self.original_size = self.original_size.saturating_add(chunk.len() as u64);
        let remaining = max_body_size.saturating_sub(self.bytes.len());
        if remaining > 0 {
            let keep = remaining.min(chunk.len());
            self.bytes.extend_from_slice(&chunk[..keep]);
            if keep < chunk.len() {
                self.truncated = true;
            }
        } else if !chunk.is_empty() {
            self.truncated = true;
        }
    }

    pub fn text_preview(&self) -> Option<String> {
        std::str::from_utf8(&self.bytes).ok().map(ToOwned::to_owned)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsInformation {
    pub host: String,
    pub tls_version: Option<String>,
    pub alpn: Option<String>,
    pub certificate: Option<CertificateInformation>,
    pub verification: String,
    pub child_certificate_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateInformation {
    pub issuer: String,
    pub subject: String,
    pub san: Vec<String>,
    pub valid_from: String,
    pub valid_until: String,
    pub sha256_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEntry {
    pub id: u64,
    pub started_at: SystemTime,
    pub duration: Duration,
    pub process_id: Option<u32>,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub http_version: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: CapturedBody,
    pub response_status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub response_body: CapturedBody,
    pub request_size: u64,
    pub response_size: u64,
    pub tls: Option<TlsInformation>,
    pub error: Option<String>,
}

impl TrafficEntry {
    pub fn url(&self) -> String {
        if self.is_connect() {
            return format!("{}://{}", self.scheme, self.authority(true));
        }
        format!("{}://{}{}", self.scheme, self.authority(false), self.path)
    }

    pub fn display_target(&self) -> String {
        if self.is_connect() {
            self.authority(true)
        } else {
            format!("{}{}", self.host, self.path)
        }
    }

    pub fn status_label(&self) -> String {
        if let Some(error) = &self.error {
            return format!("ERR {error}");
        }
        match self.response_status {
            Some(status) if (200..300).contains(&status) => format!("OK {status}"),
            Some(status) if (300..400).contains(&status) => format!("REDIR {status}"),
            Some(status) if (400..500).contains(&status) => format!("CLIENT {status}"),
            Some(status) if status >= 500 => format!("SERVER {status}"),
            Some(status) => status.to_string(),
            None => "OPEN".to_string(),
        }
    }

    fn is_connect(&self) -> bool {
        self.method.eq_ignore_ascii_case("CONNECT")
    }

    fn authority(&self, include_default_port: bool) -> String {
        let default_port = (self.scheme == "http" && self.port == 80)
            || (self.scheme == "https" && self.port == 443);
        let host = if self.host.parse::<IpAddr>().is_ok() && self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if include_default_port || !default_port {
            format!("{}:{}", host, self.port)
        } else {
            host
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_connect_target_without_duplicating_host() {
        let entry = sample_entry("CONNECT", "https", "github.com", 443, "github.com:443");

        assert_eq!(entry.display_target(), "github.com:443");
        assert_eq!(entry.url(), "https://github.com:443");
    }

    #[test]
    fn formats_regular_request_target_as_host_and_path() {
        let entry = sample_entry("GET", "https", "github.com", 443, "/repos");

        assert_eq!(entry.display_target(), "github.com/repos");
        assert_eq!(entry.url(), "https://github.com/repos");
    }

    fn sample_entry(method: &str, scheme: &str, host: &str, port: u16, path: &str) -> TrafficEntry {
        TrafficEntry {
            id: 1,
            started_at: SystemTime::UNIX_EPOCH,
            duration: Duration::from_millis(10),
            process_id: None,
            scheme: scheme.to_string(),
            host: host.to_string(),
            port,
            method: method.to_string(),
            path: path.to_string(),
            http_version: "HTTP/1.1".to_string(),
            request_headers: Vec::new(),
            request_body: CapturedBody::empty(),
            response_status: Some(200),
            response_headers: Vec::new(),
            response_body: CapturedBody::empty(),
            request_size: 0,
            response_size: 0,
            tls: None,
            error: None,
        }
    }
}
