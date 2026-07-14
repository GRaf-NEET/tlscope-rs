use crate::{
    capture::model::{CertificateInformation, TlsInformation},
    certificates::authority::LeafCertificate,
};
use anyhow::{anyhow, Context, Result};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};
use sha2::{Digest, Sha256};
use std::{io::BufReader, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::{
    client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream, TlsAcceptor,
    TlsConnector,
};
use x509_parser::prelude::*;

pub fn ca_der_from_pem(pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());
    let cert = {
        let mut certs = rustls_pemfile::certs(&mut reader);
        certs
            .next()
            .transpose()
            .context("cannot parse CA certificate PEM")?
            .ok_or_else(|| anyhow!("CA PEM contains no certificate"))?
    };
    Ok(cert)
}

pub async fn accept_client_tls(
    stream: TcpStream,
    leaf: LeafCertificate,
    only_http1: bool,
) -> Result<ServerTlsStream<TcpStream>> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(leaf.cert_chain, leaf.private_key)
        .context("cannot build local TLS server config")?;
    config.alpn_protocols = if only_http1 {
        vec![b"http/1.1".to_vec()]
    } else {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    };
    TlsAcceptor::from(Arc::new(config))
        .accept(stream)
        .await
        .context(
            "TLS handshake with child failed; the application may not trust the local CA or may use certificate pinning",
        )
}

pub fn negotiated_server_alpn(stream: &ServerTlsStream<TcpStream>) -> Option<String> {
    let (_, connection) = stream.get_ref();
    connection
        .alpn_protocol()
        .map(|value| String::from_utf8_lossy(value).into_owned())
}

pub async fn connect_upstream_tls(
    stream: TcpStream,
    host: &str,
    extra_roots: &[CertificateDer<'static>],
) -> Result<(ClientTlsStream<TcpStream>, TlsInformation)> {
    connect_upstream_tls_with_alpn(stream, host, extra_roots, Vec::new()).await
}

pub async fn connect_upstream_h2_tls(
    stream: TcpStream,
    host: &str,
    extra_roots: &[CertificateDer<'static>],
) -> Result<(ClientTlsStream<TcpStream>, TlsInformation)> {
    let (tls, info) =
        connect_upstream_tls_with_alpn(stream, host, extra_roots, vec![b"h2".to_vec()]).await?;
    if info.alpn.as_deref() == Some("h2") {
        Ok((tls, info))
    } else {
        Err(anyhow!(
            "upstream TLS for {host} did not negotiate HTTP/2 via ALPN"
        ))
    }
}

async fn connect_upstream_tls_with_alpn(
    stream: TcpStream,
    host: &str,
    extra_roots: &[CertificateDer<'static>],
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<(ClientTlsStream<TcpStream>, TlsInformation)> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(build_root_store(extra_roots)?)
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols;
    let server_name = ServerName::try_from(host.to_string())
        .with_context(|| format!("invalid TLS server name '{host}'"))?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .with_context(|| {
            format!(
                "upstream TLS handshake failed for {host}; certificate may be invalid or DNS/TCP may be failing"
            )
        })?;
    let info = upstream_tls_information(host, &tls);
    Ok((tls, info))
}

fn build_root_store(extra_roots: &[CertificateDer<'static>]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for root in extra_roots {
        roots
            .add(root.clone())
            .context("cannot add configured upstream root certificate")?;
    }
    Ok(roots)
}

fn upstream_tls_information(host: &str, stream: &ClientTlsStream<TcpStream>) -> TlsInformation {
    let (_, connection) = stream.get_ref();
    let tls_version = connection
        .protocol_version()
        .map(|version| format!("{version:?}"));
    let alpn = connection
        .alpn_protocol()
        .map(|value| String::from_utf8_lossy(value).into_owned());
    let certificate = connection
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(certificate_information)
        .transpose()
        .ok()
        .flatten();
    TlsInformation {
        host: host.to_string(),
        tls_version,
        alpn,
        certificate,
        verification: "valid".to_string(),
        child_certificate_note:
            "The child application sees a certificate issued by the local TLScope debugging CA."
                .to_string(),
    }
}

fn certificate_information(cert: &CertificateDer<'_>) -> Result<CertificateInformation> {
    let fingerprint = hex::encode_upper(Sha256::digest(cert.as_ref()));
    let (_, parsed) =
        X509Certificate::from_der(cert.as_ref()).context("cannot parse upstream certificate")?;
    let san = parsed
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .map(|name| format!("{name}"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(CertificateInformation {
        issuer: parsed.issuer().to_string(),
        subject: parsed.subject().to_string(),
        san,
        valid_from: parsed.validity().not_before.to_string(),
        valid_until: parsed.validity().not_after.to_string(),
        sha256_fingerprint: fingerprint,
    })
}
