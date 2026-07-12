use crate::{
    capture::model::{CapturedBody, TrafficEntry},
    proxy::{connect::ConnectTarget, server::ProxyServerConfig, tls},
};
use anyhow::{Context, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, Version};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Instant, SystemTime},
};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tracing::debug;

pub async fn handle_h2_connection(
    client_tls: ServerTlsStream<TcpStream>,
    target: ConnectTarget,
    config: ProxyServerConfig,
    next_id: Arc<AtomicU64>,
) -> Result<()> {
    let mut server = ::h2::server::handshake(client_tls)
        .await
        .context("failed to start HTTP/2 server handshake with child")?;

    while let Some(accepted) = server.accept().await {
        let (request, respond) = accepted.context("failed to accept HTTP/2 stream from child")?;
        let config = config.clone();
        let target = target.clone();
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let entry = handle_h2_stream(request, respond, target, config.clone(), id).await;
            crate::proxy::server::record_entry(&config, entry);
        });
    }

    Ok(())
}

async fn handle_h2_stream(
    request: Request<::h2::RecvStream>,
    mut respond: ::h2::server::SendResponse<Bytes>,
    target: ConnectTarget,
    config: ProxyServerConfig,
    id: u64,
) -> TrafficEntry {
    let started_at = SystemTime::now();
    let started = Instant::now();
    let (parts, body) = request.into_parts();
    let summary = H2RequestSummary::new(&parts, &target);

    match try_h2_stream(
        parts,
        body,
        &mut respond,
        &target,
        &config,
        id,
        started_at,
        started,
    )
    .await
    {
        Ok(entry) => entry,
        Err(error) => {
            send_h2_error(&mut respond, &error);
            summary.error_entry(id, started_at, started.elapsed(), config.process_id, error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn try_h2_stream(
    parts: http::request::Parts,
    mut request_body_stream: ::h2::RecvStream,
    respond: &mut ::h2::server::SendResponse<Bytes>,
    target: &ConnectTarget,
    config: &ProxyServerConfig,
    id: u64,
    started_at: SystemTime,
    started: Instant,
) -> Result<TrafficEntry> {
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("cannot connect to upstream {}:{}", target.host, target.port))?;
    let (upstream_tls, tls_info) =
        tls::connect_upstream_h2_tls(tcp, &target.host, &config.upstream_roots).await?;
    let (send_request, connection) = ::h2::client::handshake(upstream_tls)
        .await
        .context("failed to start HTTP/2 client handshake with upstream")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            debug!(%error, "upstream HTTP/2 connection failed");
        }
    });
    let mut send_request = send_request
        .ready()
        .await
        .context("upstream HTTP/2 connection is not ready for a request")?;

    let outbound_request = build_upstream_request(&parts)?;
    let request_end = request_body_stream.is_end_stream();
    let (response_future, mut upstream_request_body) = send_request
        .send_request(outbound_request, request_end)
        .context("failed to send HTTP/2 request headers upstream")?;

    let mut request_body = CapturedBody {
        bytes: Vec::new(),
        original_size: 0,
        decoded_size: None,
        truncated: false,
        content_type: header_value(&parts.headers, "content-type"),
        content_encoding: header_value(&parts.headers, "content-encoding"),
        transfer_encoding: None,
    };
    let mut request_body_size = 0_u64;
    if !request_end {
        while let Some(chunk) = request_body_stream.data().await {
            let chunk = chunk.context("failed to read HTTP/2 request body from child")?;
            let len = chunk.len();
            request_body.push_capture(&chunk, config.max_body_size);
            request_body_size = request_body_size.saturating_add(len as u64);
            upstream_request_body
                .send_data(chunk, false)
                .context("failed to send HTTP/2 request body upstream")?;
            request_body_stream
                .flow_control()
                .release_capacity(len)
                .context("failed to release HTTP/2 request flow-control capacity")?;
        }
        upstream_request_body
            .send_data(Bytes::new(), true)
            .context("failed to finish HTTP/2 request body upstream")?;
    }

    let response = response_future
        .await
        .context("failed to receive HTTP/2 response from upstream")?;
    let (response_parts, mut upstream_response_body) = response.into_parts();
    let response_end = upstream_response_body.is_end_stream();
    let downstream_response = build_downstream_response(&response_parts)?;
    let mut downstream_body = respond
        .send_response(downstream_response, response_end)
        .context("failed to send HTTP/2 response headers to child")?;

    let mut response_body = CapturedBody {
        bytes: Vec::new(),
        original_size: 0,
        decoded_size: None,
        truncated: false,
        content_type: header_value(&response_parts.headers, "content-type"),
        content_encoding: header_value(&response_parts.headers, "content-encoding"),
        transfer_encoding: None,
    };
    let mut response_body_size = 0_u64;
    if !response_end {
        while let Some(chunk) = upstream_response_body.data().await {
            let chunk = chunk.context("failed to read HTTP/2 response body from upstream")?;
            let len = chunk.len();
            response_body.push_capture(&chunk, config.max_body_size);
            response_body_size = response_body_size.saturating_add(len as u64);
            downstream_body
                .send_data(chunk, false)
                .context("failed to send HTTP/2 response body to child")?;
            upstream_response_body
                .flow_control()
                .release_capacity(len)
                .context("failed to release HTTP/2 response flow-control capacity")?;
        }
        downstream_body
            .send_data(Bytes::new(), true)
            .context("failed to finish HTTP/2 response body to child")?;
    }

    let request_headers = capture_request_headers(&parts);
    let response_headers = capture_headers(&response_parts.headers);
    Ok(TrafficEntry {
        id,
        started_at,
        duration: started.elapsed(),
        process_id: config.process_id,
        scheme: "https".to_string(),
        host: target.host.clone(),
        port: target.port,
        method: parts.method.as_str().to_string(),
        path: path_from_uri(&parts.uri),
        http_version: "HTTP/2".to_string(),
        request_headers: request_headers.clone(),
        request_body,
        response_status: Some(response_parts.status.as_u16()),
        response_headers: response_headers.clone(),
        response_body,
        request_size: approx_headers_size(&request_headers).saturating_add(request_body_size),
        response_size: approx_headers_size(&response_headers).saturating_add(response_body_size),
        tls: Some(tls_info),
        error: None,
    })
}

fn build_upstream_request(parts: &http::request::Parts) -> Result<Request<()>> {
    let mut builder = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone())
        .version(Version::HTTP_2);
    for (name, value) in &parts.headers {
        if forwardable_h2_header(name) {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(())
        .context("failed to build upstream HTTP/2 request")
}

fn build_downstream_response(parts: &http::response::Parts) -> Result<Response<()>> {
    let mut builder = Response::builder()
        .status(parts.status)
        .version(Version::HTTP_2);
    for (name, value) in &parts.headers {
        if forwardable_h2_header(name) {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(())
        .context("failed to build downstream HTTP/2 response")
}

fn send_h2_error(respond: &mut ::h2::server::SendResponse<Bytes>, error: &anyhow::Error) {
    let body = Bytes::from(format!("{error:#}"));
    let response = Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .version(Version::HTTP_2)
        .header("content-type", "text/plain; charset=utf-8")
        .body(());
    if let Ok(response) = response {
        if let Ok(mut stream) = respond.send_response(response, false) {
            let _ = stream.send_data(body, true);
        }
    }
}

fn forwardable_h2_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

fn header_value(headers: &HeaderMap<HeaderValue>, name: &str) -> Option<String> {
    headers
        .get(name)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn capture_request_headers(parts: &http::request::Parts) -> Vec<(String, String)> {
    let mut headers = vec![
        (":method".to_string(), parts.method.as_str().to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":path".to_string(), path_from_uri(&parts.uri)),
    ];
    if let Some(authority) = parts.uri.authority() {
        headers.push((":authority".to_string(), authority.as_str().to_string()));
    }
    headers.extend(capture_headers(&parts.headers));
    headers
}

fn capture_headers(headers: &HeaderMap<HeaderValue>) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

fn path_from_uri(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|path| path.as_str().to_string())
        .unwrap_or_else(|| "/".to_string())
}

fn approx_headers_size(headers: &[(String, String)]) -> u64 {
    headers
        .iter()
        .map(|(name, value)| name.len() as u64 + value.len() as u64 + 4)
        .sum()
}

struct H2RequestSummary {
    method: String,
    path: String,
    request_headers: Vec<(String, String)>,
    target: ConnectTarget,
}

impl H2RequestSummary {
    fn new(parts: &http::request::Parts, target: &ConnectTarget) -> Self {
        Self {
            method: parts.method.as_str().to_string(),
            path: path_from_uri(&parts.uri),
            request_headers: capture_request_headers(parts),
            target: target.clone(),
        }
    }

    fn error_entry(
        self,
        id: u64,
        started_at: SystemTime,
        duration: std::time::Duration,
        process_id: Option<u32>,
        error: anyhow::Error,
    ) -> TrafficEntry {
        TrafficEntry {
            id,
            started_at,
            duration,
            process_id,
            scheme: "https".to_string(),
            host: self.target.host,
            port: self.target.port,
            method: self.method,
            path: self.path,
            http_version: "HTTP/2".to_string(),
            request_headers: self.request_headers,
            request_body: CapturedBody::empty(),
            response_status: Some(StatusCode::BAD_GATEWAY.as_u16()),
            response_headers: Vec::new(),
            response_body: CapturedBody::empty(),
            request_size: 0,
            response_size: 0,
            tls: None,
            error: Some(format!("{error:#}")),
        }
    }
}
