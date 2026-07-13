use anyhow::Result;
use clap::Parser;
use tlscope::{app, cli::Cli, tui::logs::TlscopeLogLayer};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("tlscope=info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(TlscopeLogLayer)
        .init();

    app::run(Cli::parse()).await
}
