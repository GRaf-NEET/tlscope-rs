use crate::{
    capture::{
        model::{CapturedBody, TlsInformation, TrafficEntry},
        store::TrafficStore,
    },
    certificates::authority::LocalAuthority,
    proxy::{
        connect::{connect_entry, ConnectTarget},
        h2::handle_h2_connection,
        http::{
            forward_known_body, forward_response_body, has_chunked_transfer,
            is_websocket_upgrade_request, is_websocket_upgrade_response, parse_request,
            parse_response, read_header_block, write_simple_response, ParsedRequest,
        },
        tls,
        upstream::{
            build_upstream_header, build_upstream_upgrade_header, target_from_request,
            UpstreamTarget,
        },
    },
};
use anyhow::{anyhow, Context, Result};
use rustls::pki_types::CertificateDer;
use std::{
    io::ErrorKind,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, warn};

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}
type BoxIo = Box<dyn AsyncIo>;

#[derive(Debug, Clone)]
pub enum ProxyEvent {
    EntryCaptured(u64),
}

#[derive(Clone)]
pub struct ProxyServerConfig {
    pub listen: SocketAddr,
    pub tls_decryption: bool,
    pub authority: Option<Arc<LocalAuthority>>,
    pub max_body_size: usize,
    pub store: Arc<Mutex<TrafficStore>>,
    pub events: mpsc::UnboundedSender<ProxyEvent>,
    pub process_id: Option<u32>,
    pub upstream_roots: Vec<CertificateDer<'static>>,
}

pub struct ProxyHandle {
    pub local_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    join: JoinHandle<Result<()>>,
}

impl ProxyHandle {
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.join
            .await
            .context("proxy task join failed")?
            .context("proxy task failed")
    }
}

pub async fn start_proxy(config: ProxyServerConfig) -> Result<ProxyHandle> {
    let listener = TcpListener::bind(config.listen).await.with_context(|| {
        format!(
            "cannot listen on {}; port may already be occupied",
            config.listen
        )
    })?;
    let local_addr = listener
        .local_addr()
        .context("cannot get proxy listener address")?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let next_id = Arc::new(AtomicU64::new(1));
    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("proxy shutdown requested");
                    break;
                }
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.context("failed to accept proxy client")?;
                    let config = config.clone();
                    let id = next_id.fetch_add(1, Ordering::Relaxed);
                    let next_id = next_id.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_client(stream, peer, config, id, next_id).await {
                            if is_benign_client_disconnect(&error) {
                                debug!(%peer, %error, "proxy client disconnected before request completed");
                            } else {
                                warn!(%peer, %error, "proxy client handler failed");
                            }
                        }
                    });
                }
            }
        }
        Ok(())
    });

    Ok(ProxyHandle {
        local_addr,
        shutdown: Some(shutdown_tx),
        join,
    })
}

async fn handle_client(
    mut client: TcpStream,
    _peer: SocketAddr,
    config: ProxyServerConfig,
    id: u64,
    next_id: Arc<AtomicU64>,
) -> Result<()> {
    let started_at = SystemTime::now();
    let started = Instant::now();
    let Some((header, initial_body)) = read_header_block(&mut client).await? else {
        return Ok(());
    };
    let request = match parse_request(&header) {
        Ok(request) => request,
        Err(error) => {
            write_simple_response(&mut client, 400, "Bad Request", &error.to_string()).await?;
            return Ok(());
        }
    };

    if request.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(client, request, config, id, next_id, started_at, started).await
    } else {
        let entry = handle_http_exchange(
            &mut client,
            request,
            initial_body,
            ExchangeMode::PlainFromRequest,
            &config,
            id,
            started_at,
            started,
        )
        .await;
        record_entry(&config, entry);
        Ok(())
    }
}

async fn handle_connect(
    mut client: TcpStream,
    request: ParsedRequest,
    config: ProxyServerConfig,
    id: u64,
    next_id: Arc<AtomicU64>,
    started_at: SystemTime,
    started: Instant,
) -> Result<()> {
    let target = match ConnectTarget::parse(&request.path) {
        Ok(target) => target,
        Err(error) => {
            write_simple_response(&mut client, 400, "Bad CONNECT", &error.to_string()).await?;
            return Ok(());
        }
    };

    if !config.tls_decryption {
        let entry = tunnel_connect(client, &target, &config, id, started_at, started).await;
        record_entry(&config, entry);
        return Ok(());
    }

    let Some(authority) = &config.authority else {
        write_simple_response(
            &mut client,
            502,
            "TLS Inspection Disabled",
            "local CA is not available for HTTPS inspection",
        )
        .await?;
        let entry = connect_entry(
            id,
            started_at,
            started.elapsed(),
            config.process_id,
            &target,
            Some(502),
            (0, 0),
            Some("local CA is not available for HTTPS inspection".to_string()),
        );
        record_entry(&config, entry);
        return Ok(());
    };

    let leaf = match authority.leaf_for_host(&target.host) {
        Ok(leaf) => leaf,
        Err(error) => {
            write_simple_response(&mut client, 502, "CA Error", &error.to_string()).await?;
            let entry = connect_entry(
                id,
                started_at,
                started.elapsed(),
                config.process_id,
                &target,
                Some(502),
                (0, 0),
                Some(format!("cannot create local leaf certificate: {error}")),
            );
            record_entry(&config, entry);
            return Ok(());
        }
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("failed to acknowledge CONNECT")?;
    let mut client_tls = match tls::accept_client_tls(client, leaf).await {
        Ok(stream) => stream,
        Err(error) => {
            let entry = connect_entry(
                id,
                started_at,
                started.elapsed(),
                config.process_id,
                &target,
                Some(502),
                (0, 0),
                Some(error.to_string()),
            );
            record_entry(&config, entry);
            return Ok(());
        }
    };

    if tls::negotiated_server_alpn(&client_tls).as_deref() == Some("h2") {
        handle_h2_connection(client_tls, target, config, next_id).await?;
        return Ok(());
    }
    let (header, initial_body) = match read_header_block(&mut client_tls).await {
        Ok(Some(parts)) => parts,
        Ok(None) => {
            let entry = connect_entry(
                id,
                started_at,
                started.elapsed(),
                config.process_id,
                &target,
                Some(200),
                (0, 0),
                Some(
                    "client closed inspected TLS tunnel before sending an HTTP request".to_string(),
                ),
            );
            record_entry(&config, entry);
            return Ok(());
        }
        Err(error) if is_benign_client_disconnect(&error) => {
            let entry = connect_entry(
                id,
                started_at,
                started.elapsed(),
                config.process_id,
                &target,
                Some(200),
                (0, 0),
                Some(format!(
                    "client closed inspected TLS tunnel before sending an HTTP request: {error}"
                )),
            );
            record_entry(&config, entry);
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let request = match parse_request(&header) {
        Ok(request) => request,
        Err(error) => {
            write_simple_response(&mut client_tls, 400, "Bad Request", &error.to_string()).await?;
            return Ok(());
        }
    };
    let entry = handle_http_exchange(
        &mut client_tls,
        request,
        initial_body,
        ExchangeMode::TlsTo {
            host: target.host,
            port: target.port,
        },
        &config,
        id,
        started_at,
        started,
    )
    .await;
    record_entry(&config, entry);
    Ok(())
}

async fn tunnel_connect(
    mut client: TcpStream,
    target: &ConnectTarget,
    config: &ProxyServerConfig,
    id: u64,
    started_at: SystemTime,
    started: Instant,
) -> TrafficEntry {
    let mut upstream = match TcpStream::connect((target.host.as_str(), target.port)).await {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ =
                write_simple_response(&mut client, 502, "Bad Gateway", &error.to_string()).await;
            return connect_entry(
                id,
                started_at,
                started.elapsed(),
                config.process_id,
                target,
                Some(502),
                (0, 0),
                Some(format!("cannot connect upstream: {error}")),
            );
        }
    };
    if let Err(error) = client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
    {
        return connect_entry(
            id,
            started_at,
            started.elapsed(),
            config.process_id,
            target,
            Some(502),
            (0, 0),
            Some(format!("cannot acknowledge CONNECT: {error}")),
        );
    }
    match copy_bidirectional(&mut client, &mut upstream).await {
        Ok((from_client, from_upstream)) => connect_entry(
            id,
            started_at,
            started.elapsed(),
            config.process_id,
            target,
            Some(200),
            (from_client, from_upstream),
            None,
        ),
        Err(error) => connect_entry(
            id,
            started_at,
            started.elapsed(),
            config.process_id,
            target,
            Some(200),
            (0, 0),
            Some(format!("CONNECT tunnel failed: {error}")),
        ),
    }
}

enum ExchangeMode {
    PlainFromRequest,
    TlsTo { host: String, port: u16 },
}

#[allow(clippy::too_many_arguments)]
async fn handle_http_exchange<C>(
    client: &mut C,
    request: ParsedRequest,
    initial_body: Vec<u8>,
    mode: ExchangeMode,
    config: &ProxyServerConfig,
    id: u64,
    started_at: SystemTime,
    started: Instant,
) -> TrafficEntry
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    match try_http_exchange(
        client,
        &request,
        initial_body,
        mode,
        config,
        id,
        started_at,
        started,
    )
    .await
    {
        Ok(entry) => entry,
        Err(error) => {
            let _ = write_simple_response(client, 502, "Bad Gateway", &error.to_string()).await;
            error_entry(
                id,
                started_at,
                started.elapsed(),
                config.process_id,
                &request,
                error,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn try_http_exchange<C>(
    client: &mut C,
    request: &ParsedRequest,
    initial_body: Vec<u8>,
    mode: ExchangeMode,
    config: &ProxyServerConfig,
    id: u64,
    started_at: SystemTime,
    started: Instant,
) -> Result<TrafficEntry>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    if has_chunked_transfer(&request.transfer_encoding) {
        write_simple_response(
            client,
            501,
            "Not Implemented",
            "chunked request bodies are not supported by this HTTP/1.1 MVP",
        )
        .await?;
        let mut entry = error_entry(
            id,
            started_at,
            started.elapsed(),
            config.process_id,
            request,
            anyhow!("unsupported HTTP feature: chunked request body"),
        );
        entry.response_status = Some(501);
        return Ok(entry);
    }

    let websocket_upgrade = is_websocket_upgrade_request(request);
    let (target, mut upstream, tls_info) = connect_upstream(request, &mode, config).await?;
    let upstream_header = if websocket_upgrade {
        build_upstream_upgrade_header(request, &target)
    } else {
        build_upstream_header(request, &target)
    };
    upstream
        .write_all(&upstream_header)
        .await
        .context("failed to write upstream request header")?;

    let content_length = request.content_length.unwrap_or(0);
    let (request_body, request_body_size) =
        if websocket_upgrade && content_length == 0 && !initial_body.is_empty() {
            upstream
                .write_all(&initial_body)
                .await
                .context("failed to forward early WebSocket bytes")?;
            (CapturedBody::empty(), initial_body.len() as u64)
        } else {
            forward_known_body(
                client,
                upstream.as_mut(),
                &initial_body,
                content_length,
                config.max_body_size,
                request.content_type.clone(),
                request.content_encoding.clone(),
                request.transfer_encoding.clone(),
            )
            .await?
        };
    upstream
        .flush()
        .await
        .context("failed to flush upstream request")?;

    let Some((response_header, response_initial_body)) =
        read_header_block(upstream.as_mut()).await?
    else {
        return Err(anyhow!("upstream closed without an HTTP response"));
    };
    let response = parse_response(&response_header)?;
    client
        .write_all(&response_header)
        .await
        .context("failed to forward response header to client")?;

    if websocket_upgrade && is_websocket_upgrade_response(&response) {
        let mut response_tunnel_size = 0_u64;
        if !response_initial_body.is_empty() {
            client
                .write_all(&response_initial_body)
                .await
                .context("failed to forward early WebSocket response bytes")?;
            response_tunnel_size += response_initial_body.len() as u64;
        }
        client
            .flush()
            .await
            .context("failed to flush WebSocket handshake to client")?;

        let (request_tunnel_size, response_tunnel_size, error) =
            match copy_bidirectional(client, upstream.as_mut()).await {
                Ok((from_client, from_upstream)) => (
                    from_client,
                    response_tunnel_size.saturating_add(from_upstream),
                    None,
                ),
                Err(error) => (
                    0,
                    response_tunnel_size,
                    Some(format!("WebSocket tunnel failed: {error}")),
                ),
            };

        return Ok(TrafficEntry {
            id,
            started_at,
            duration: started.elapsed(),
            process_id: config.process_id,
            scheme: target.scheme,
            host: target.host,
            port: target.port,
            method: request.method.clone(),
            path: target.path,
            http_version: request.version.clone(),
            request_headers: request.headers.clone(),
            request_body,
            response_status: Some(response.status),
            response_headers: response.headers,
            response_body: CapturedBody::empty(),
            request_size: upstream_header.len() as u64 + request_body_size + request_tunnel_size,
            response_size: response_header.len() as u64 + response_tunnel_size,
            tls: tls_info,
            error,
        });
    }

    let (response_body, response_body_size) = forward_response_body(
        upstream.as_mut(),
        client,
        &response_initial_body,
        response.content_length,
        config.max_body_size,
        response.content_type.clone(),
        response.content_encoding.clone(),
        response.transfer_encoding.clone(),
    )
    .await?;
    client
        .flush()
        .await
        .context("failed to flush response to client")?;

    Ok(TrafficEntry {
        id,
        started_at,
        duration: started.elapsed(),
        process_id: config.process_id,
        scheme: target.scheme,
        host: target.host,
        port: target.port,
        method: request.method.clone(),
        path: target.path,
        http_version: request.version.clone(),
        request_headers: request.headers.clone(),
        request_body,
        response_status: Some(response.status),
        response_headers: response.headers,
        response_body,
        request_size: upstream_header.len() as u64 + request_body_size,
        response_size: response_header.len() as u64 + response_body_size,
        tls: tls_info,
        error: None,
    })
}
async fn connect_upstream(
    request: &ParsedRequest,
    mode: &ExchangeMode,
    config: &ProxyServerConfig,
) -> Result<(UpstreamTarget, BoxIo, Option<TlsInformation>)> {
    match mode {
        ExchangeMode::PlainFromRequest => {
            let target = target_from_request(request, None)?;
            if target.scheme != "http" {
                return Err(anyhow!(
                    "HTTPS without CONNECT is not supported; configure the client to use CONNECT"
                ));
            }
            let stream = TcpStream::connect((target.host.as_str(), target.port))
                .await
                .with_context(|| {
                    format!("cannot connect to upstream {}:{}", target.host, target.port)
                })?;
            Ok((target, Box::new(stream), None))
        }
        ExchangeMode::TlsTo { host, port } => {
            let target = target_from_request(request, Some(("https", host, *port)))?;
            let tcp = TcpStream::connect((host.as_str(), *port))
                .await
                .with_context(|| format!("cannot connect to upstream {host}:{port}"))?;
            let (tls_stream, info) =
                tls::connect_upstream_tls(tcp, host, &config.upstream_roots).await?;
            Ok((target, Box::new(tls_stream), Some(info)))
        }
    }
}

fn is_benign_client_disconnect(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_error| {
                matches!(
                    io_error.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                        | ErrorKind::UnexpectedEof
                )
            })
    })
}
fn error_entry(
    id: u64,
    started_at: SystemTime,
    duration: Duration,
    process_id: Option<u32>,
    request: &ParsedRequest,
    error: anyhow::Error,
) -> TrafficEntry {
    let fallback_target = target_from_request(request, None).ok();
    TrafficEntry {
        id,
        started_at,
        duration,
        process_id,
        scheme: fallback_target
            .as_ref()
            .map(|target| target.scheme.clone())
            .unwrap_or_else(|| "http".to_string()),
        host: fallback_target
            .as_ref()
            .map(|target| target.host.clone())
            .unwrap_or_default(),
        port: fallback_target
            .as_ref()
            .map(|target| target.port)
            .unwrap_or(0),
        method: request.method.clone(),
        path: fallback_target
            .as_ref()
            .map(|target| target.path.clone())
            .unwrap_or_else(|| request.path.clone()),
        http_version: request.version.clone(),
        request_headers: request.headers.clone(),
        request_body: CapturedBody::empty(),
        response_status: None,
        response_headers: Vec::new(),
        response_body: CapturedBody::empty(),
        request_size: 0,
        response_size: 0,
        tls: None,
        error: Some(error.to_string()),
    }
}

pub(super) fn record_entry(config: &ProxyServerConfig, entry: TrafficEntry) {
    let id = entry.id;
    if let Ok(mut store) = config.store.lock() {
        store.push(entry);
    }
    let _ = config.events.send(ProxyEvent::EntryCaptured(id));
}
