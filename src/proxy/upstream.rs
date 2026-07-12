use crate::proxy::http::{header_value, ParsedRequest};
use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, ToSocketAddrs};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl UpstreamTarget {
    pub fn authority(&self) -> String {
        let default_port = (self.scheme == "http" && self.port == 80)
            || (self.scheme == "https" && self.port == 443);
        if default_port {
            self.host.clone()
        } else if self.host.parse::<IpAddr>().is_ok() && self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

pub fn target_from_request(
    request: &ParsedRequest,
    fixed_scheme_host_port: Option<(&str, &str, u16)>,
) -> Result<UpstreamTarget> {
    if let Some((scheme, host, port)) = fixed_scheme_host_port {
        return Ok(UpstreamTarget {
            scheme: scheme.to_string(),
            host: host.to_string(),
            port,
            path: origin_path(&request.path)?,
        });
    }

    if request.path.starts_with("http://") || request.path.starts_with("https://") {
        let url = Url::parse(&request.path).context("invalid absolute request URL")?;
        let scheme = url.scheme().to_string();
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("absolute request URL has no host"))?
            .to_string();
        let port = url.port_or_known_default().ok_or_else(|| {
            anyhow!("absolute request URL has no port and no known default for scheme")
        })?;
        let mut path = url.path().to_string();
        if path.is_empty() {
            path.push('/');
        }
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        return Ok(UpstreamTarget {
            scheme,
            host,
            port,
            path,
        });
    }

    let host_header = header_value(&request.headers, "host")
        .ok_or_else(|| anyhow!("HTTP request has no Host header"))?;
    let (host, port) = split_host_port(&host_header, 80)?;
    Ok(UpstreamTarget {
        scheme: "http".to_string(),
        host,
        port,
        path: origin_path(&request.path)?,
    })
}

pub fn parse_connect_authority(value: &str) -> Result<(String, u16)> {
    split_host_port(value, 443)
}

pub fn build_upstream_header(request: &ParsedRequest, target: &UpstreamTarget) -> Vec<u8> {
    build_upstream_header_inner(request, target, false)
}

pub fn build_upstream_upgrade_header(request: &ParsedRequest, target: &UpstreamTarget) -> Vec<u8> {
    build_upstream_header_inner(request, target, true)
}

fn build_upstream_header_inner(
    request: &ParsedRequest,
    target: &UpstreamTarget,
    preserve_connection_headers: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(
        format!("{} {} {}\r\n", request.method, target.path, request.version).as_bytes(),
    );
    let mut has_host = false;
    let mut has_connection = false;
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if lower == "proxy-connection" || lower == "proxy-authorization" {
            continue;
        }
        if !preserve_connection_headers && (lower == "connection" || lower == "keep-alive") {
            continue;
        }
        if lower == "host" {
            has_host = true;
            out.extend_from_slice(format!("Host: {}\r\n", target.authority()).as_bytes());
        } else {
            if lower == "connection" {
                has_connection = true;
            }
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
    }
    if !has_host {
        out.extend_from_slice(format!("Host: {}\r\n", target.authority()).as_bytes());
    }
    if !preserve_connection_headers {
        out.extend_from_slice(b"Connection: close\r\n");
    } else if !has_connection {
        out.extend_from_slice(b"Connection: Upgrade\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}
pub async fn resolve_remote_ip(host: &str, port: u16) -> Option<String> {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || {
        (host.as_str(), port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|addr| addr.ip().to_string())
    })
    .await
    .ok()
    .flatten()
}

fn origin_path(path: &str) -> Result<String> {
    if path.starts_with("http://") || path.starts_with("https://") {
        let url = Url::parse(path).context("invalid absolute request URL")?;
        let mut origin = url.path().to_string();
        if origin.is_empty() {
            origin.push('/');
        }
        if let Some(query) = url.query() {
            origin.push('?');
            origin.push_str(query);
        }
        Ok(origin)
    } else if path.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(path.to_string())
    }
}

fn split_host_port(value: &str, default_port: u16) -> Result<(String, u16)> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("empty host"));
    }

    if let Some(rest) = value.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid bracketed IPv6 host '{value}'"))?;
        let port = if let Some(port) = after.strip_prefix(':') {
            port.parse()
                .with_context(|| format!("invalid port in authority '{value}'"))?
        } else {
            default_port
        };
        return Ok((host.to_string(), port));
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(':') {
            let port = port
                .parse()
                .with_context(|| format!("invalid port in authority '{value}'"))?;
            return Ok((host.to_string(), port));
        }
    }

    Ok((value.to_string(), default_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_absolute_url_target() {
        let request = ParsedRequest {
            method: "GET".to_string(),
            path: "http://example.com:8080/a?b=1".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            content_length: None,
            content_type: None,
            content_encoding: None,
            transfer_encoding: None,
        };
        let target = target_from_request(&request, None).expect("target");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8080);
        assert_eq!(target.path, "/a?b=1");
    }
}
