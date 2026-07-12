use std::sync::{Arc, Mutex};
use std::time::Duration;

use tlscope::{
    capture::store::TrafficStore,
    proxy::server::{start_proxy, ProxyServerConfig},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

#[tokio::test]
async fn proxies_plain_http_and_captures_entry() {
    let upstream = start_plain_server(b"hello".to_vec()).await;
    let store = Arc::new(Mutex::new(TrafficStore::default()));
    let (tx, _rx) = mpsc::unbounded_channel();
    let proxy = start_proxy(ProxyServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls_decryption: false,
        authority: None,
        max_body_size: 1024,
        store: store.clone(),
        events: tx,
        process_id: None,
        upstream_roots: Vec::new(),
    })
    .await
    .unwrap();

    let mut client = TcpStream::connect(proxy.local_addr).await.unwrap();
    let request = format!(
        "GET http://127.0.0.1:{}/hello?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        upstream.port(), upstream.port()
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).contains("200 OK"));
    assert!(String::from_utf8_lossy(&response).contains("hello"));

    wait_for_entries(&store, 1).await;
    let entries = store.lock().unwrap().entries().to_vec();
    assert_eq!(entries[0].method, "GET");
    assert_eq!(entries[0].path, "/hello?x=1");
    assert_eq!(entries[0].response_status, Some(200));
    assert_eq!(entries[0].response_body.bytes, b"hello");
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn truncates_captured_response_body_without_truncating_proxy_response() {
    let upstream = start_plain_server(b"0123456789".to_vec()).await;
    let store = Arc::new(Mutex::new(TrafficStore::default()));
    let (tx, _rx) = mpsc::unbounded_channel();
    let proxy = start_proxy(ProxyServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls_decryption: false,
        authority: None,
        max_body_size: 4,
        store: store.clone(),
        events: tx,
        process_id: None,
        upstream_roots: Vec::new(),
    })
    .await
    .unwrap();

    let mut client = TcpStream::connect(proxy.local_addr).await.unwrap();
    let request = format!(
        "GET http://127.0.0.1:{}/large HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        upstream.port(),
        upstream.port()
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).contains("0123456789"));

    wait_for_entries(&store, 1).await;
    let entry = store.lock().unwrap().entries()[0].clone();
    assert_eq!(entry.response_body.bytes, b"0123");
    assert_eq!(entry.response_body.original_size, 10);
    assert!(entry.response_body.truncated);
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn tunnels_plain_websocket_upgrade_and_captures_handshake() {
    let upstream = start_websocket_server().await;
    let store = Arc::new(Mutex::new(TrafficStore::default()));
    let (tx, _rx) = mpsc::unbounded_channel();
    let proxy = start_proxy(ProxyServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls_decryption: false,
        authority: None,
        max_body_size: 1024,
        store: store.clone(),
        events: tx,
        process_id: None,
        upstream_roots: Vec::new(),
    })
    .await
    .unwrap();

    let mut client = TcpStream::connect(proxy.local_addr).await.unwrap();
    let request = format!(
        "GET http://127.0.0.1:{}/socket HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        upstream.port(),
        upstream.port()
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let response_header = read_test_header(&mut client).await;
    let response_text = String::from_utf8_lossy(&response_header);
    assert!(response_text.contains("101 Switching Protocols"));
    assert!(response_text.contains("Upgrade: websocket"));

    client.write_all(b"ping").await.unwrap();
    let mut response = [0_u8; 4];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    client.shutdown().await.unwrap();

    wait_for_entries(&store, 1).await;
    let entry = store.lock().unwrap().entries()[0].clone();
    assert_eq!(entry.method, "GET");
    assert_eq!(entry.path, "/socket");
    assert_eq!(entry.response_status, Some(101));
    assert!(entry.error.is_none());
    assert!(entry.request_size >= 4);
    assert!(entry.response_size >= 4);
    proxy.shutdown().await.unwrap();
}

async fn start_plain_server(body: Vec<u8>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 4096];
        let _ = stream.read(&mut buffer).await.unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
    });
    addr
}

async fn start_websocket_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let header = read_test_header(&mut stream).await;
        let header_text = String::from_utf8_lossy(&header);
        assert!(header_text.starts_with("GET /socket HTTP/1.1"));
        assert!(header_text.contains("Connection: keep-alive, Upgrade"));
        assert!(header_text.contains("Upgrade: websocket"));
        stream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .await
            .unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });
    addr
}

async fn read_test_header(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        header.push(byte[0]);
    }
    header
}

async fn wait_for_entries(store: &Arc<Mutex<TrafficStore>>, expected: usize) {
    for _ in 0..50 {
        if store.lock().unwrap().entries().len() >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for captured entries");
}
