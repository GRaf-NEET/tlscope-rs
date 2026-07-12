use bytes::Bytes;
use std::time::Duration;
use std::{
    io::ErrorKind,
    sync::{Arc, Mutex},
};

use rustls::{ClientConfig, RootCertStore};
use tlscope::{
    capture::store::TrafficStore,
    certificates::authority::LocalAuthority,
    proxy::{
        server::{start_proxy, ProxyServerConfig},
        tls::ca_der_from_pem,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn inspects_https_connect_with_local_test_server() {
    let upstream_ca_dir = tempfile::tempdir().unwrap();
    let upstream_ca = LocalAuthority::load_or_create(upstream_ca_dir.path()).unwrap();
    let upstream = start_tls_server(&upstream_ca).await;

    let proxy_ca_dir = tempfile::tempdir().unwrap();
    let proxy_ca = Arc::new(LocalAuthority::load_or_create(proxy_ca_dir.path()).unwrap());
    let store = Arc::new(Mutex::new(TrafficStore::default()));
    let (tx, _rx) = mpsc::unbounded_channel();
    let proxy = start_proxy(ProxyServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls_decryption: true,
        authority: Some(proxy_ca.clone()),
        max_body_size: 2048,
        store: store.clone(),
        events: tx,
        process_id: None,
        upstream_roots: vec![ca_der_from_pem(upstream_ca.cert_pem()).unwrap()],
    })
    .await
    .unwrap();

    let mut tcp = TcpStream::connect(proxy.local_addr).await.unwrap();
    let connect = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        upstream.port(),
        upstream.port()
    );
    tcp.write_all(connect.as_bytes()).await.unwrap();
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await.unwrap();
        header.push(byte[0]);
    }
    assert!(String::from_utf8_lossy(&header).contains("200"));

    let mut roots = RootCertStore::empty();
    roots
        .add(ca_der_from_pem(proxy_ca.cert_pem()).unwrap())
        .unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = TlsConnector::from(Arc::new(client_config))
        .connect(server_name, tcp)
        .await
        .unwrap();
    tls.write_all(b"GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    match tls.read_to_end(&mut response).await {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {}
        Err(error) => panic!("failed to read TLS response: {error}"),
    }
    assert!(String::from_utf8_lossy(&response).contains("secure-ok"));

    wait_for_entries(&store, 1).await;
    let entry = store.lock().unwrap().entries()[0].clone();
    assert_eq!(entry.scheme, "https");
    assert_eq!(entry.path, "/secure");
    assert!(entry.tls.is_some());
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn inspects_http2_connect_with_local_test_server() {
    let upstream_ca_dir = tempfile::tempdir().unwrap();
    let upstream_ca = LocalAuthority::load_or_create(upstream_ca_dir.path()).unwrap();
    let upstream = start_h2_tls_server(&upstream_ca).await;

    let proxy_ca_dir = tempfile::tempdir().unwrap();
    let proxy_ca = Arc::new(LocalAuthority::load_or_create(proxy_ca_dir.path()).unwrap());
    let store = Arc::new(Mutex::new(TrafficStore::default()));
    let (tx, _rx) = mpsc::unbounded_channel();
    let proxy = start_proxy(ProxyServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls_decryption: true,
        authority: Some(proxy_ca.clone()),
        max_body_size: 2048,
        store: store.clone(),
        events: tx,
        process_id: None,
        upstream_roots: vec![ca_der_from_pem(upstream_ca.cert_pem()).unwrap()],
    })
    .await
    .unwrap();

    let mut tcp = TcpStream::connect(proxy.local_addr).await.unwrap();
    let connect = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        upstream.port(),
        upstream.port()
    );
    tcp.write_all(connect.as_bytes()).await.unwrap();
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await.unwrap();
        header.push(byte[0]);
    }
    assert!(String::from_utf8_lossy(&header).contains("200"));

    let mut roots = RootCertStore::empty();
    roots
        .add(ca_der_from_pem(proxy_ca.cert_pem()).unwrap())
        .unwrap();
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls = TlsConnector::from(Arc::new(client_config))
        .connect(server_name, tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

    let (send_request, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let mut send_request = send_request.ready().await.unwrap();
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://localhost:{}/h2", upstream.port()))
        .body(())
        .unwrap();
    let (response, _) = send_request.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    let status = response.status();
    let mut body = response.into_body();
    let mut response_body = Vec::new();
    while let Some(chunk) = body.data().await {
        response_body.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(
        status,
        http::StatusCode::OK,
        "unexpected HTTP/2 response body: {}",
        String::from_utf8_lossy(&response_body)
    );
    assert_eq!(response_body, b"h2-ok");

    wait_for_entries(&store, 1).await;
    let entry = store.lock().unwrap().entries()[0].clone();
    assert_eq!(entry.scheme, "https");
    assert_eq!(entry.path, "/h2");
    assert_eq!(entry.http_version, "HTTP/2");
    assert_eq!(entry.response_status, Some(200));
    assert_eq!(entry.response_body.bytes, b"h2-ok");
    assert_eq!(entry.tls.and_then(|tls| tls.alpn), Some("h2".to_string()));
    proxy.shutdown().await.unwrap();
}

async fn start_tls_server(ca: &LocalAuthority) -> std::net::SocketAddr {
    let leaf = ca.leaf_for_host("localhost").unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(leaf.cert_chain, leaf.private_key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(stream).await.unwrap();
        let mut buffer = [0_u8; 4096];
        let _ = tls.read(&mut buffer).await.unwrap();
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nsecure-ok")
            .await
            .unwrap();
    });
    addr
}

async fn start_h2_tls_server(ca: &LocalAuthority) -> std::net::SocketAddr {
    let leaf = ca.leaf_for_host("localhost").unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(leaf.cert_chain, leaf.private_key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(stream).await.unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let mut server = h2::server::handshake(tls).await.unwrap();
        let mut handled = false;
        while let Some(accepted) = server.accept().await {
            let (request, mut respond) = accepted.unwrap();
            if handled {
                continue;
            }
            handled = true;
            assert_eq!(request.uri().path(), "/h2");
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("content-type", "text/plain")
                .body(())
                .unwrap();
            let mut stream = respond.send_response(response, false).unwrap();
            stream
                .send_data(Bytes::from_static(b"h2-ok"), true)
                .unwrap();
        }
    });
    addr
}

async fn wait_for_entries(store: &Arc<Mutex<TrafficStore>>, expected: usize) {
    for _ in 0..100 {
        if store.lock().unwrap().entries().len() >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for captured entries");
}
