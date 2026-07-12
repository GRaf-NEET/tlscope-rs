use crate::capture::model::{CapturedBody, TrafficEntry};
use crate::proxy::upstream::parse_connect_authority;
use anyhow::Result;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
}

impl ConnectTarget {
    pub fn parse(authority: &str) -> Result<Self> {
        let (host, port) = parse_connect_authority(authority)?;
        Ok(Self { host, port })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn connect_entry(
    id: u64,
    started_at: SystemTime,
    duration: Duration,
    process_id: Option<u32>,
    target: &ConnectTarget,
    response_status: Option<u16>,
    bytes: (u64, u64),
    error: Option<String>,
) -> TrafficEntry {
    TrafficEntry {
        id,
        started_at,
        duration,
        process_id,
        scheme: "https".to_string(),
        host: target.host.clone(),
        port: target.port,
        method: "CONNECT".to_string(),
        path: format!("{}:{}", target.host, target.port),
        http_version: "HTTP/1.1".to_string(),
        request_headers: Vec::new(),
        request_body: CapturedBody::empty(),
        response_status,
        response_headers: Vec::new(),
        response_body: CapturedBody::empty(),
        request_size: bytes.0,
        response_size: bytes.1,
        tls: None,
        error,
    }
}
