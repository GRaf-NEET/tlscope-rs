use crate::capture::store::{FilterIndex, TrafficFilter};

const FILTER_KEYS: &[&str] = &[
    "duration:",
    "error:",
    "has:",
    "host:",
    "method:",
    "path:",
    "status:",
    "tls:",
    "type:",
];
const METHODS: &[&str] = &[
    "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE",
];
const BOOLEANS: &[&str] = &["false", "true"];
const HAS_VALUES: &[&str] = &["request-body", "response-body"];
const OPERATORS: &[&str] = &["<", "<=", "=", ">", ">="];
const DURATION_PRESETS: &[&str] = &["100ms", "250ms", "500ms", "1s", "2s", "5s", "10s"];
const CONTENT_TYPE_ALIASES: &[&str] = &["html", "json", "text", "xml"];
const COMMON_STATUS_BUCKETS: &[u16] = &[200, 300, 400, 500];

#[derive(Debug, Clone)]
pub struct FilterSuggestion {
    pub replacement: String,
    pub display: String,
    pub kind: SuggestionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuggestionKind {
    Key,
    Method,
    Host,
    Status,
    ContentType,
    Boolean,
    HasValue,
    Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterParseState {
    Valid,
    Incomplete,
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenRange {
    pub start: usize,
    pub end: usize,
}

pub fn current_token(text: &str, cursor: usize) -> TokenRange {
    let cursor = clamp_to_char_boundary(text, cursor.min(text.len()));
    let start = text[..cursor]
        .char_indices()
        .rev()
        .find(|(_, ch)| ch.is_whitespace())
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let end = text[cursor..]
        .char_indices()
        .find(|(_, ch)| ch.is_whitespace())
        .map(|(index, _)| cursor + index)
        .unwrap_or(text.len());
    TokenRange { start, end }
}

pub fn build_filter_suggestions(
    text: &str,
    cursor: usize,
    index: &FilterIndex,
) -> Vec<FilterSuggestion> {
    let token = current_token(text, cursor);
    let cursor = clamp_to_char_boundary(text, cursor.min(text.len()));
    let before_cursor = &text[token.start..cursor];
    let Some((key, value_prefix)) = before_cursor.split_once(':') else {
        return key_suggestions(before_cursor);
    };

    match key {
        "method" => {
            static_value_suggestions("method", value_prefix, METHODS, SuggestionKind::Method)
        }
        "host" => {
            dynamic_value_suggestions("host", value_prefix, index.hosts(), SuggestionKind::Host)
        }
        "path" => Vec::new(),
        "status" => status_suggestions(value_prefix, index.statuses()),
        "type" => content_type_suggestions(value_prefix, index.content_types()),
        "has" => {
            static_value_suggestions("has", value_prefix, HAS_VALUES, SuggestionKind::HasValue)
        }
        "error" => {
            static_value_suggestions("error", value_prefix, BOOLEANS, SuggestionKind::Boolean)
        }
        "tls" => static_value_suggestions("tls", value_prefix, BOOLEANS, SuggestionKind::Boolean),
        "duration" => duration_suggestions(value_prefix),
        _ => key_suggestions(key),
    }
}

pub fn filter_parse_state(text: &str) -> FilterParseState {
    if text.trim().is_empty() {
        return FilterParseState::Valid;
    }
    for token in text.split_whitespace() {
        if is_incomplete_token(token) {
            return FilterParseState::Incomplete;
        }
    }
    match TrafficFilter::parse(text) {
        Ok(_) => FilterParseState::Valid,
        Err(error) => FilterParseState::Invalid(error),
    }
}

fn key_suggestions(prefix: &str) -> Vec<FilterSuggestion> {
    let prefix = prefix.to_ascii_lowercase();
    FILTER_KEYS
        .iter()
        .filter(|key| key.starts_with(&prefix))
        .map(|key| FilterSuggestion {
            replacement: (*key).to_string(),
            display: (*key).to_string(),
            kind: SuggestionKind::Key,
        })
        .collect()
}

fn static_value_suggestions(
    key: &str,
    prefix: &str,
    values: &[&str],
    kind: SuggestionKind,
) -> Vec<FilterSuggestion> {
    let prefix_lower = prefix.to_ascii_lowercase();
    values
        .iter()
        .filter(|value| value.to_ascii_lowercase().starts_with(&prefix_lower))
        .map(|value| value_suggestion(key, value, kind))
        .collect()
}

fn dynamic_value_suggestions(
    key: &str,
    prefix: &str,
    values: &[String],
    kind: SuggestionKind,
) -> Vec<FilterSuggestion> {
    prefix_suggestions(values, &prefix.to_ascii_lowercase(), 64)
        .into_iter()
        .map(|value| value_suggestion(key, value, kind))
        .collect()
}

fn status_suggestions(prefix: &str, statuses: &[u16]) -> Vec<FilterSuggestion> {
    let mut values = statuses.to_vec();
    if values.is_empty() {
        values.extend_from_slice(COMMON_STATUS_BUCKETS);
    }
    values.sort_unstable();
    values.dedup();

    let (operator, number_prefix) = split_operator_prefix(prefix);
    let mut suggestions = Vec::new();
    if number_prefix.is_empty() {
        suggestions.extend(operator_suggestions(
            "status",
            prefix,
            SuggestionKind::Status,
        ));
    }
    suggestions.extend(values.into_iter().filter_map(|status| {
        let status = status.to_string();
        if status.starts_with(number_prefix) {
            let value = format!("{operator}{status}");
            Some(value_suggestion("status", &value, SuggestionKind::Status))
        } else {
            None
        }
    }));
    sort_and_dedup(suggestions)
}

fn duration_suggestions(prefix: &str) -> Vec<FilterSuggestion> {
    let (operator, duration_prefix) = split_operator_prefix(prefix);
    let mut suggestions = Vec::new();
    if duration_prefix.is_empty() {
        suggestions.extend(operator_suggestions(
            "duration",
            prefix,
            SuggestionKind::Duration,
        ));
    }
    suggestions.extend(DURATION_PRESETS.iter().filter_map(|preset| {
        if preset.starts_with(duration_prefix) {
            let value = format!("{operator}{preset}");
            Some(value_suggestion(
                "duration",
                &value,
                SuggestionKind::Duration,
            ))
        } else {
            None
        }
    }));
    sort_and_dedup(suggestions)
}

fn content_type_suggestions(prefix: &str, content_types: &[String]) -> Vec<FilterSuggestion> {
    let mut suggestions = static_value_suggestions(
        "type",
        prefix,
        CONTENT_TYPE_ALIASES,
        SuggestionKind::ContentType,
    );
    suggestions.extend(dynamic_value_suggestions(
        "type",
        prefix,
        content_types,
        SuggestionKind::ContentType,
    ));
    sort_and_dedup(suggestions)
}

fn operator_suggestions(key: &str, prefix: &str, kind: SuggestionKind) -> Vec<FilterSuggestion> {
    OPERATORS
        .iter()
        .filter(|operator| operator.starts_with(prefix))
        .map(|operator| value_suggestion(key, operator, kind))
        .collect()
}

fn value_suggestion(key: &str, value: &str, kind: SuggestionKind) -> FilterSuggestion {
    FilterSuggestion {
        replacement: format!("{key}:{value}"),
        display: value.to_string(),
        kind,
    }
}

fn prefix_suggestions<'a>(values: &'a [String], prefix: &str, limit: usize) -> Vec<&'a str> {
    let start = values.partition_point(|value| value.as_str() < prefix);
    values[start..]
        .iter()
        .take_while(|value| value.starts_with(prefix))
        .take(limit)
        .map(String::as_str)
        .collect()
}

fn sort_and_dedup(mut suggestions: Vec<FilterSuggestion>) -> Vec<FilterSuggestion> {
    suggestions.sort_by(|left, right| left.display.cmp(&right.display));
    suggestions.dedup_by(|left, right| left.display == right.display);
    suggestions
}

fn split_operator_prefix(value: &str) -> (&str, &str) {
    for operator in [">=", "<=", ">", "<", "="] {
        if let Some(rest) = value.strip_prefix(operator) {
            return (operator, rest);
        }
    }
    ("", value)
}

fn is_incomplete_token(token: &str) -> bool {
    let Some((key, value)) = token.split_once(':') else {
        let prefix = token.to_ascii_lowercase();
        return !prefix.is_empty() && FILTER_KEYS.iter().any(|key| key.starts_with(&prefix));
    };
    match key {
        "method" => value.is_empty() || prefixed_by(value, METHODS),
        "host" | "path" | "type" => value.is_empty(),
        "status" | "duration" => matches!(value, "" | "<" | "<=" | ">" | ">=" | "="),
        "has" => value.is_empty() || prefixed_by(value, HAS_VALUES),
        "error" | "tls" => value.is_empty() || prefixed_by(value, BOOLEANS),
        _ => false,
    }
}

fn prefixed_by(value: &str, candidates: &[&str]) -> bool {
    let value = value.to_ascii_lowercase();
    !candidates
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(&value))
        && candidates
            .iter()
            .any(|candidate| candidate.to_ascii_lowercase().starts_with(&value))
}

fn clamp_to_char_boundary(text: &str, mut cursor: usize) -> usize {
    while cursor > 0 && !text.is_char_boundary(cursor) {
        cursor -= 1;
    }
    cursor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_current_token_around_cursor() {
        let text = "method:POST host:api";
        let range = current_token(text, text.len());
        assert_eq!(&text[range.start..range.end], "host:api");
    }

    #[test]
    fn suggests_keys_by_prefix() {
        let suggestions = build_filter_suggestions("st", 2, &FilterIndex::default());
        assert_eq!(suggestions[0].replacement, "status:");
    }
}
