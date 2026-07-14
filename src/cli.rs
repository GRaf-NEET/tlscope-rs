use crate::process::tracking::ProcessTrackingConfig;
use clap::{Args, Parser, Subcommand};
use std::{ffi::OsString, net::SocketAddr, path::PathBuf};

#[derive(Debug, Parser)]
#[command(name = "TLScope")]
#[command(about = "Local explicit HTTP/HTTPS debugging proxy for child processes")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run a child program with proxy environment variables.
    Run(RunArgs),
    /// Run only the local proxy.
    Proxy(ProxyArgs),
    /// Manage the local debugging certificate authority.
    Ca {
        #[command(subcommand)]
        command: CaCommand,
        #[arg(long)]
        ca_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Args, Clone)]
pub struct CommonProxyArgs {
    /// Address for the explicit proxy listener.
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,

    /// Do not decrypt HTTPS CONNECT streams; tunnel them only.
    #[arg(long)]
    pub no_tls_decryption: bool,

    /// Force inspected HTTPS connections to HTTP/1.1 by not negotiating HTTP/2 with child clients.
    #[arg(long)]
    pub only_http1: bool,

    /// Directory where the local debugging CA is stored.
    #[arg(long)]
    pub ca_dir: Option<PathBuf>,

    /// Maximum captured body bytes kept in memory per request/response.
    #[arg(long, default_value_t = 1_048_576)]
    pub max_body_size: usize,

    /// Enable JSON/form field redaction in bodies in addition to default header redaction.
    #[arg(long)]
    pub redact: bool,

    /// Show sensitive values in UI/export. Requires an explicit flag and prints a warning.
    #[arg(long)]
    pub show_secrets: bool,

    /// Save the captured session as JSON when the program exits.
    #[arg(long)]
    pub save_session: Option<PathBuf>,

    /// Allow listening on a non-loopback address after warning the user.
    #[arg(long)]
    pub allow_external: bool,
}

#[derive(Debug, Args, Clone)]
pub struct RunArgs {
    #[command(flatten)]
    pub common: CommonProxyArgs,

    /// Child process working directory.
    #[arg(long)]
    pub workdir: Option<PathBuf>,

    /// Extra environment variable for the child process, KEY=VALUE.
    #[arg(long = "env")]
    pub env: Vec<String>,

    /// Do not pass SSL_CERT_FILE/REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE/NODE_EXTRA_CA_CERTS.
    #[arg(long)]
    pub no_extra_ca_env: bool,

    #[arg(skip)]
    pub tls_confirmed: bool,

    /// Program and arguments after '--'.
    #[arg(required = true, last = true)]
    pub command: Vec<OsString>,

    #[arg(skip)]
    pub process_tracking: ProcessTrackingConfig,
}

#[derive(Debug, Args, Clone)]
pub struct ProxyArgs {
    #[command(flatten)]
    pub common: CommonProxyArgs,
}

#[derive(Debug, Subcommand, Clone)]
pub enum CaCommand {
    /// Create the local debugging CA if it does not exist.
    Create,
    /// Print the local CA certificate path.
    Path,
    /// Print the SHA-256 fingerprint of the local CA certificate.
    Fingerprint,
    /// Install the local CA certificate into the current user's trust store.
    Install {
        /// Skip the interactive safety confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Remove only CA files created by this program, after confirmation.
    Remove,
}
