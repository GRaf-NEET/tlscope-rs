use crate::capture::model::TrafficEntry;
use std::time::Duration;

#[derive(Debug, Default, Clone)]
pub struct TrafficStore {
    entries: Vec<TrafficEntry>,
}

impl TrafficStore {
    pub fn push(&mut self, entry: TrafficEntry) {
        self.entries.push(entry);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn entries(&self) -> &[TrafficEntry] {
        &self.entries
    }

    pub fn filtered(&self, filter: &TrafficFilter) -> Vec<TrafficEntry> {
        self.entries
            .iter()
            .filter(|entry| filter.matches(entry))
            .cloned()
            .collect()
    }

    pub fn error_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.error.is_some())
            .count()
    }
}

#[derive(Debug, Clone, Default)]
pub struct TrafficFilter {
    conditions: Vec<Condition>,
}

impl TrafficFilter {
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut conditions = Vec::new();
        for token in input.split_whitespace() {
            let (key, value) = token
                .split_once(':')
                .ok_or_else(|| format!("invalid filter token '{token}'"))?;
            let condition = match key {
                "method" => Condition::Method(value.to_ascii_uppercase()),
                "host" => Condition::Host(value.to_ascii_lowercase()),
                "path" => Condition::Path(value.to_string()),
                "status" => Condition::Status(parse_comparison_u16(value)?),
                "type" => Condition::ContentType(value.to_ascii_lowercase()),
                "has" => match value {
                    "request-body" => Condition::HasRequestBody,
                    "response-body" => Condition::HasResponseBody,
                    _ => return Err(format!("unsupported has:{value}")),
                },
                "error" => Condition::Error(parse_bool(value)?),
                "tls" => Condition::Tls(parse_bool(value)?),
                "duration" => Condition::Duration(parse_comparison_duration(value)?),
                _ => return Err(format!("unsupported filter key '{key}'")),
            };
            conditions.push(condition);
        }
        Ok(Self { conditions })
    }

    pub fn matches(&self, entry: &TrafficEntry) -> bool {
        self.conditions
            .iter()
            .all(|condition| condition.matches(entry))
    }
}

#[derive(Debug, Clone)]
enum Condition {
    Method(String),
    Host(String),
    Path(String),
    Status(Comparison<u16>),
    ContentType(String),
    HasRequestBody,
    HasResponseBody,
    Error(bool),
    Tls(bool),
    Duration(Comparison<Duration>),
}

impl Condition {
    fn matches(&self, entry: &TrafficEntry) -> bool {
        match self {
            Condition::Method(method) => entry.method.eq_ignore_ascii_case(method),
            Condition::Host(host) => entry.host.to_ascii_lowercase().contains(host),
            Condition::Path(path) => entry.path.contains(path),
            Condition::Status(cmp) => entry.response_status.is_some_and(|s| cmp.matches(s)),
            Condition::ContentType(kind) => {
                let request = entry
                    .request_body
                    .content_type
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let response = entry
                    .response_body
                    .content_type
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                request.contains(kind) || response.contains(kind)
            }
            Condition::HasRequestBody => entry.request_body.original_size > 0,
            Condition::HasResponseBody => entry.response_body.original_size > 0,
            Condition::Error(expected) => entry.error.is_some() == *expected,
            Condition::Tls(expected) => entry.tls.is_some() == *expected,
            Condition::Duration(cmp) => cmp.matches(entry.duration),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Operator {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug, Clone, Copy)]
struct Comparison<T> {
    op: Operator,
    value: T,
}

impl<T: PartialOrd + PartialEq + Copy> Comparison<T> {
    fn matches(&self, actual: T) -> bool {
        match self.op {
            Operator::Eq => actual == self.value,
            Operator::Gt => actual > self.value,
            Operator::Gte => actual >= self.value,
            Operator::Lt => actual < self.value,
            Operator::Lte => actual <= self.value,
        }
    }
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("expected true or false, got '{value}'")),
    }
}

fn parse_comparison_u16(value: &str) -> Result<Comparison<u16>, String> {
    let (op, raw) = parse_operator(value);
    let value = raw
        .parse::<u16>()
        .map_err(|_| format!("invalid status code '{raw}'"))?;
    Ok(Comparison { op, value })
}

fn parse_comparison_duration(value: &str) -> Result<Comparison<Duration>, String> {
    let (op, raw) = parse_operator(value);
    let duration = if let Some(ms) = raw.strip_suffix("ms") {
        Duration::from_millis(
            ms.parse()
                .map_err(|_| format!("invalid duration '{raw}'"))?,
        )
    } else if let Some(seconds) = raw.strip_suffix('s') {
        Duration::from_secs(
            seconds
                .parse()
                .map_err(|_| format!("invalid duration '{raw}'"))?,
        )
    } else {
        Duration::from_millis(
            raw.parse()
                .map_err(|_| format!("invalid duration '{raw}'"))?,
        )
    };
    Ok(Comparison {
        op,
        value: duration,
    })
}

fn parse_operator(value: &str) -> (Operator, &str) {
    if let Some(rest) = value.strip_prefix(">=") {
        (Operator::Gte, rest)
    } else if let Some(rest) = value.strip_prefix("<=") {
        (Operator::Lte, rest)
    } else if let Some(rest) = value.strip_prefix('>') {
        (Operator::Gt, rest)
    } else if let Some(rest) = value.strip_prefix('<') {
        (Operator::Lt, rest)
    } else {
        (Operator::Eq, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::model::{CapturedBody, TrafficEntry};
    use std::time::{Duration, SystemTime};

    fn entry() -> TrafficEntry {
        TrafficEntry {
            id: 1,
            started_at: SystemTime::UNIX_EPOCH,
            duration: Duration::from_millis(750),
            process_id: Some(10),
            scheme: "https".to_string(),
            host: "api.example.com".to_string(),
            port: 443,
            method: "POST".to_string(),
            path: "/v1/users".to_string(),
            http_version: "HTTP/1.1".to_string(),
            request_headers: Vec::new(),
            request_body: CapturedBody::from_bytes(
                b"{}",
                1024,
                Some("application/json".to_string()),
                None,
            ),
            response_status: Some(404),
            response_headers: Vec::new(),
            response_body: CapturedBody::empty(),
            request_size: 2,
            response_size: 0,
            tls: None,
            error: None,
        }
    }

    #[test]
    fn parses_and_matches_and_filters() {
        let filter = TrafficFilter::parse(
            "method:POST host:api.example.com path:/v1 status:>=400 type:json has:request-body duration:>500ms error:false tls:false",
        )
        .unwrap_or_default();
        assert!(filter.matches(&entry()));
    }

    #[test]
    fn rejects_unknown_filter() {
        assert!(TrafficFilter::parse("thread:main").is_err());
    }
}
