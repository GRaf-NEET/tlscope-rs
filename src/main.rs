use anyhow::Result;
use clap::Parser;
use tlscope::{app, cli::Cli};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("tlscope=info")),
        )
        .with_writer(std::io::stderr)
        .init();

    app::run(Cli::parse()).await
}
