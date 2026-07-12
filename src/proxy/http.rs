use crate::capture::model::CapturedBody;
use anyhow::{anyhow, Context, Result};
use httparse::Status;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const HEADER_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub transfer_encoding: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedResponse {
    pub status: u16,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub transfer_encoding: Option<String>,
}

pub async fn read_header_block<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buffer = Vec::with_capacity(8192);
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .context("failed to read HTTP header")?;
        if read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(anyhow!("connection closed before complete HTTP header"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > HEADER_LIMIT {
            return Err(anyhow!("HTTP header is too large"));
        }
        if let Some(end) = find_header_end(&buffer) {
            let body = buffer.split_off(end);
            return Ok(Some((buffer, body)));
        }
    }
}

pub fn parse_request(header: &[u8]) -> Result<ParsedRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut headers);
    match request
        .parse(header)
        .context("failed to parse HTTP request")?
    {
        Status::Complete(_) => {}
        Status::Partial => return Err(anyhow!("incomplete HTTP request header")),
    }
    let method = request
        .method
        .ok_or_else(|| anyhow!("HTTP request has no method"))?
        .to_string();
    let path = request
        .path
        .ok_or_else(|| anyhow!("HTTP request has no path"))?
        .to_string();
    let version = format!("HTTP/1.{}", request.version.unwrap_or(1));
    let headers = copy_headers(request.headers);
    Ok(ParsedRequest {
        method,
        path,
        version,
        content_length: content_length(&headers),
        content_type: header_value(&headers, "content-type"),
        content_encoding: header_value(&headers, "content-encoding"),
        transfer_encoding: header_value(&headers, "transfer-encoding"),
        headers,
    })
}

pub fn parse_response(header: &[u8]) -> Result<ParsedResponse> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut headers);
    match response
        .parse(header)
        .context("failed to parse HTTP response")?
    {
        Status::Complete(_) => {}
        Status::Partial => return Err(anyhow!("incomplete HTTP response header")),
    }
    let status = response
        .code
        .ok_or_else(|| anyhow!("HTTP response has no status"))?;
    let version = format!("HTTP/1.{}", response.version.unwrap_or(1));
    let headers = copy_headers(response.headers);
    Ok(ParsedResponse {
        status,
        version,
        content_length: content_length(&headers),
        content_type: header_value(&headers, "content-type"),
        content_encoding: header_value(&headers, "content-encoding"),
        transfer_encoding: header_value(&headers, "transfer-encoding"),
        headers,
    })
}

pub async fn write_simple_response<S: AsyncWrite + Unpin + ?Sized>(
    stream: &mut S,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("failed to write proxy error response")
}

pub async fn forward_known_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    initial: &[u8],
    content_length: u64,
    max_body_size: usize,
    content_type: Option<String>,
    content_encoding: Option<String>,
    transfer_encoding: Option<String>,
) -> Result<(CapturedBody, u64)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut captured = CapturedBody {
        bytes: Vec::new(),
        original_size: 0,
        decoded_size: None,
        truncated: false,
        content_type,
        content_encoding,
        transfer_encoding,
    };
    let mut written = 0_u64;
    let initial_len = initial.len().min(content_length as usize);
    if initial_len > 0 {
        writer
            .write_all(&initial[..initial_len])
            .await
            .context("failed to forward request body")?;
        captured.push_capture(&initial[..initial_len], max_body_size);
        written += initial_len as u64;
    }

    let mut remaining = content_length.saturating_sub(written);
    let mut buffer = [0_u8; 16 * 1024];
    while remaining > 0 {
        let want = buffer.len().min(remaining as usize);
        let read = reader
            .read(&mut buffer[..want])
            .await
            .context("failed to read request body")?;
        if read == 0 {
            return Err(anyhow!(
                "connection closed before full request body was sent"
            ));
        }
        writer
            .write_all(&buffer[..read])
            .await
            .context("failed to forward request body")?;
        captured.push_capture(&buffer[..read], max_body_size);
        written += read as u64;
        remaining = remaining.saturating_sub(read as u64);
    }
    Ok((captured, written))
}

pub async fn forward_response_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    initial: &[u8],
    content_length: Option<u64>,
    max_body_size: usize,
    content_type: Option<String>,
    content_encoding: Option<String>,
    transfer_encoding: Option<String>,
) -> Result<(CapturedBody, u64)>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin,
{
    let mut captured = CapturedBody {
        bytes: Vec::new(),
        original_size: 0,
        decoded_size: None,
        truncated: false,
        content_type,
        content_encoding,
        transfer_encoding,
    };
    let mut written = 0_u64;
    match content_length {
        Some(length) => {
            let initial_len = initial.len().min(length as usize);
            if initial_len > 0 {
                writer
                    .write_all(&initial[..initial_len])
                    .await
                    .context("failed to forward response body")?;
                captured.push_capture(&initial[..initial_len], max_body_size);
                written += initial_len as u64;
            }
            let mut remaining = length.saturating_sub(written);
            let mut buffer = [0_u8; 16 * 1024];
            while remaining > 0 {
                let want = buffer.len().min(remaining as usize);
                let read = reader
                    .read(&mut buffer[..want])
                    .await
                    .context("failed to read response body")?;
                if read == 0 {
                    return Err(anyhow!(
                        "upstream closed before full response body was sent"
                    ));
                }
                writer
                    .write_all(&buffer[..read])
                    .await
                    .context("failed to forward response body")?;
                captured.push_capture(&buffer[..read], max_body_size);
                written += read as u64;
                remaining = remaining.saturating_sub(read as u64);
            }
        }
        None => {
            if !initial.is_empty() {
                writer
                    .write_all(initial)
                    .await
                    .context("failed to forward response body")?;
                captured.push_capture(initial, max_body_size);
                written += initial.len() as u64;
            }
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let read = reader
                    .read(&mut buffer)
                    .await
                    .context("failed to read response body")?;
                if read == 0 {
                    break;
                }
                writer
                    .write_all(&buffer[..read])
                    .await
                    .context("failed to forward response body")?;
                captured.push_capture(&buffer[..read], max_body_size);
                written += read as u64;
            }
        }
    }
    Ok((captured, written))
}

pub fn is_websocket_upgrade_request(request: &ParsedRequest) -> bool {
    request.method.eq_ignore_ascii_case("GET")
        && header_value(&request.headers, "upgrade")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
        && header_tokens_contain(&header_value(&request.headers, "connection"), "upgrade")
}

pub fn is_websocket_upgrade_response(response: &ParsedResponse) -> bool {
    response.status == 101
        && header_value(&response.headers, "upgrade")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
        && header_tokens_contain(&header_value(&response.headers, "connection"), "upgrade")
}

fn header_tokens_contain(value: &Option<String>, needle: &str) -> bool {
    value
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(needle))
}

pub fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

pub fn has_chunked_transfer(value: &Option<String>) -> bool {
    value
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
}

fn copy_headers(headers: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|header| {
            (
                header.name.to_string(),
                String::from_utf8_lossy(header.value).into_owned(),
            )
        })
        .collect()
}

fn content_length(headers: &[(String, String)]) -> Option<u64> {
    header_value(headers, "content-length").and_then(|value| value.trim().parse().ok())
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}
