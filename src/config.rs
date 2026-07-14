use crate::{
    capture::redact::RedactionConfig,
    cli::{CommonProxyArgs, RunArgs},
    process::tracking::ProcessTrackingConfig,
};
use anyhow::{anyhow, Context, Result};
use std::{
    ffi::{OsStr, OsString},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen: SocketAddr,
    pub tls_decryption: bool,
    pub only_http1: bool,
    pub ca_dir: PathBuf,
    pub max_body_size: usize,
    pub redaction: RedactionConfig,
    pub save_session: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ChildConfig {
    pub command: Vec<OsString>,
    pub workdir: Option<PathBuf>,
    pub env: Vec<(OsString, OsString)>,
    pub no_extra_ca_env: bool,
    pub process_tracking: ProcessTrackingConfig,
}

impl AppConfig {
    pub fn from_common(args: &CommonProxyArgs) -> Result<Self> {
        validate_listen(args.listen, args.allow_external)?;
        if args.show_secrets {
            eprintln!(
                "Warning: sensitive headers and body fields will be shown in UI and exports."
            );
        }

        Ok(Self {
            listen: args.listen,
            tls_decryption: !args.no_tls_decryption,
            only_http1: args.only_http1,
            ca_dir: args.ca_dir.clone().unwrap_or_else(default_ca_dir),
            max_body_size: args.max_body_size,
            redaction: RedactionConfig::new(args.redact, args.show_secrets),
            save_session: args.save_session.clone(),
        })
    }
}

impl ChildConfig {
    pub fn from_run(args: &RunArgs) -> Result<Self> {
        let env = parse_env_overrides(&args.env)?;
        Ok(Self {
            command: args.command.clone(),
            workdir: args.workdir.clone(),
            env,
            no_extra_ca_env: args.no_extra_ca_env,
            process_tracking: args.process_tracking.clone(),
        })
    }
}

pub fn default_ca_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("TLScope")
        .join("ca")
}

pub fn validate_listen(addr: SocketAddr, allow_external: bool) -> Result<()> {
    let is_loopback = match addr.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    };
    if !is_loopback && !allow_external {
        return Err(anyhow!(
            "refusing to listen on {addr}; use --allow-external only for an explicitly trusted test network"
        ));
    }
    if !is_loopback {
        eprintln!("Warning: proxy is listening on {addr}. Other hosts may be able to connect.");
    }
    Ok(())
}

fn parse_env_overrides(items: &[String]) -> Result<Vec<(OsString, OsString)>> {
    items
        .iter()
        .map(|item| {
            let (key, value) = item
                .split_once('=')
                .with_context(|| format!("invalid --env value '{item}', expected KEY=VALUE"))?;
            if key.is_empty() || key.contains('\0') {
                return Err(anyhow!("invalid environment key '{key}'"));
            }
            Ok((OsString::from(key), OsString::from(value)))
        })
        .collect()
}

pub fn os_string_to_display(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}
