use crate::{
    capture::{export::export_session_json, store::TrafficStore},
    certificates::{
        authority::{ca_cert_path, ca_fingerprint_from_dir, LocalAuthority},
        trust_store,
    },
    cli::{CaCommand, Cli, Commands},
    config::{AppConfig, ChildConfig},
    interactive,
    process::{
        launcher::{spawn_child, ChildExit, ChildStdio, LaunchRequest},
        logs::{sanitize_output_line, ChildLogStore, ChildOutputStream},
    },
    proxy::server::{start_proxy, ProxyServerConfig},
    tui::{
        self,
        logs::{activate_tlscope_log_capture, push_tlscope_log, TlscopeLogLevel, TlscopeLogStore},
        state::{TuiExit, TuiRuntime},
    },
};
use anyhow::{anyhow, Context, Result};
use std::{
    io::{self, IsTerminal, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    sync::{mpsc, oneshot},
};

const CHILD_LOG_LIMIT: usize = 2_000;
const CHILD_LOG_LINE_LIMIT: usize = 4_000;
const TLSCOPE_LOG_LIMIT: usize = 2_000;

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::Run(args)) => run_child(args).await,
        Some(Commands::Proxy(args)) => run_proxy_only(args).await,
        Some(Commands::Ca { command, ca_dir }) => run_ca(command, ca_dir).await,
        None => run_child(interactive::prompt_run_args()?).await,
    }
}

async fn run_child(args: crate::cli::RunArgs) -> Result<()> {
    let mut app_config = AppConfig::from_common(&args.common)?;
    let tls_confirmed = args.tls_confirmed;
    let mut child_config = ChildConfig::from_run(&args)?;
    child_config.command = interactive::resolve_command_target(child_config.command)?;
    let authority = prepare_authority(&mut app_config, tls_confirmed)?;
    let store = Arc::new(Mutex::new(TrafficStore::default()));
    let child_logs = Arc::new(Mutex::new(ChildLogStore::new(CHILD_LOG_LIMIT)));
    let tlscope_logs = Arc::new(Mutex::new(TlscopeLogStore::new(TLSCOPE_LOG_LIMIT)));
    let _tlscope_log_capture = activate_tlscope_log_capture(tlscope_logs.clone());
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let proxy = start_proxy(ProxyServerConfig {
        listen: app_config.listen,
        tls_decryption: app_config.tls_decryption,
        authority: authority.clone(),
        max_body_size: app_config.max_body_size,
        store: store.clone(),
        events: events_tx,
        process_id: None,
        upstream_roots: Vec::new(),
    })
    .await?;
    push_tlscope_log(
        &tlscope_logs,
        TlscopeLogLevel::Info,
        "app",
        format!("proxy listening on {}", proxy.local_addr),
    );

    let ca_path = authority.as_ref().map(|ca| ca.cert_path().to_path_buf());
    let mut child = spawn_child(LaunchRequest {
        command: child_config.command.clone(),
        workdir: child_config.workdir,
        env: child_config.env,
        proxy_addr: proxy.local_addr,
        ca_cert_path: ca_path,
        no_extra_ca_env: child_config.no_extra_ca_env,
        stdio: ChildStdio::Piped,
    })?;
    let child_pid = child.pid();
    if let Some(stdout) = child.take_stdout() {
        spawn_child_output_reader(stdout, ChildOutputStream::Stdout, child_logs.clone());
    }
    if let Some(stderr) = child.take_stderr() {
        spawn_child_output_reader(stderr, ChildOutputStream::Stderr, child_logs.clone());
    }
    let child_label = child_config
        .command
        .first()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "child".to_string());
    push_tlscope_log(
        &tlscope_logs,
        TlscopeLogLevel::Info,
        "app",
        format!(
            "spawned child {} pid {}",
            child_label,
            child_pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "N/A".to_string())
        ),
    );

    let child_running = Arc::new(AtomicBool::new(true));
    let (control_tx, control_rx) = oneshot::channel();
    let supervisor_running = child_running.clone();
    let supervisor =
        tokio::spawn(
            async move { child_supervisor(&mut child, supervisor_running, control_rx).await },
        );

    let runtime = TuiRuntime {
        child_label: Some(child_label),
        child_pid,
        proxy_addr: proxy.local_addr.to_string(),
        https_inspection: app_config.tls_decryption,
        child_running: Some(child_running.clone()),
        child_logs: child_logs.clone(),
        tlscope_logs: tlscope_logs.clone(),
        auto_exit_when_child_done: true,
    };

    let tui_exit = tui::run_tui(
        store.clone(),
        events_rx,
        runtime,
        app_config.redaction.clone(),
    )
    .await?;
    match tui_exit {
        TuiExit::TerminateChild => {
            let _ = control_tx.send(ChildControl::Terminate(Duration::from_secs(5)));
        }
        TuiExit::LeaveChildRunning => {
            let _ = control_tx.send(ChildControl::Detach);
        }
        TuiExit::Quit => {
            let _ = control_tx.send(ChildControl::Detach);
        }
    }

    let child_exit = supervisor.await.context("child supervisor task failed")??;
    if let Some(exit) = child_exit {
        report_child_exit(&exit);
    }

    proxy.shutdown().await?;
    save_session_if_requested(&app_config, &store)?;
    Ok(())
}

async fn run_proxy_only(args: crate::cli::ProxyArgs) -> Result<()> {
    let mut app_config = AppConfig::from_common(&args.common)?;
    let authority = prepare_authority(&mut app_config, false)?;
    let store = Arc::new(Mutex::new(TrafficStore::default()));
    let child_logs = Arc::new(Mutex::new(ChildLogStore::new(CHILD_LOG_LIMIT)));
    let tlscope_logs = Arc::new(Mutex::new(TlscopeLogStore::new(TLSCOPE_LOG_LIMIT)));
    let _tlscope_log_capture = activate_tlscope_log_capture(tlscope_logs.clone());
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let proxy = start_proxy(ProxyServerConfig {
        listen: app_config.listen,
        tls_decryption: app_config.tls_decryption,
        authority,
        max_body_size: app_config.max_body_size,
        store: store.clone(),
        events: events_tx,
        process_id: None,
        upstream_roots: Vec::new(),
    })
    .await?;
    push_tlscope_log(
        &tlscope_logs,
        TlscopeLogLevel::Info,
        "app",
        format!("proxy listening on {}", proxy.local_addr),
    );
    let runtime = TuiRuntime {
        child_label: None,
        child_pid: None,
        proxy_addr: proxy.local_addr.to_string(),
        https_inspection: app_config.tls_decryption,
        child_running: None,
        child_logs: child_logs.clone(),
        tlscope_logs: tlscope_logs.clone(),
        auto_exit_when_child_done: false,
    };
    let _ = tui::run_tui(
        store.clone(),
        events_rx,
        runtime,
        app_config.redaction.clone(),
    )
    .await?;
    proxy.shutdown().await?;
    save_session_if_requested(&app_config, &store)?;
    Ok(())
}

async fn run_ca(command: CaCommand, ca_dir: Option<std::path::PathBuf>) -> Result<()> {
    let ca_dir = ca_dir.unwrap_or_else(crate::config::default_ca_dir);
    match command {
        CaCommand::Create => {
            let ca = LocalAuthority::load_or_create(&ca_dir)?;
            println!("CA certificate: {}", ca.cert_path().display());
            println!("SHA-256 fingerprint: {}", ca.fingerprint()?);
            print_manual_install_instructions(ca.cert_path());
        }
        CaCommand::Path => {
            println!("{}", ca_cert_path(&ca_dir).display());
        }
        CaCommand::Fingerprint => {
            println!("{}", ca_fingerprint_from_dir(&ca_dir)?);
        }
        CaCommand::Install { yes } => {
            let ca = LocalAuthority::load_or_create(&ca_dir)?;
            println!("CA certificate: {}", ca.cert_path().display());
            println!("SHA-256 fingerprint: {}", ca.fingerprint()?);
            if yes || confirm_ca_trust_install(ca.cert_path())? {
                trust_store::install_current_user_root(ca.cert_path())?;
                println!(
                    "Installed TLScope CA into the current user's Windows Root trust store. Restart the target application before retrying HTTPS inspection."
                );
            } else {
                println!("CA trust installation cancelled.");
            }
        }
        CaCommand::Remove => {
            let confirmed = LocalAuthority::prompt_remove_confirmation(&ca_dir)?;
            if LocalAuthority::remove_created_files(&ca_dir, confirmed)? {
                println!("Removed local CA files from {}", ca_dir.display());
            } else {
                println!("No CA files were removed.");
            }
        }
    }
    Ok(())
}

fn prepare_authority(
    app_config: &mut AppConfig,
    tls_already_confirmed: bool,
) -> Result<Option<Arc<LocalAuthority>>> {
    if !app_config.tls_decryption {
        return Ok(None);
    }
    if !tls_already_confirmed && !confirm_https_inspection()? {
        app_config.tls_decryption = false;
        println!("HTTPS inspection disabled; CONNECT streams will be tunneled without decryption.");
        return Ok(None);
    }
    let ca = LocalAuthority::load_or_create(&app_config.ca_dir)?;
    println!("Local debugging CA: {}", ca.cert_path().display());
    println!("Fingerprint: {}", ca.fingerprint()?);
    print_manual_install_instructions(ca.cert_path());
    Ok(Some(Arc::new(ca)))
}

fn confirm_https_inspection() -> Result<bool> {
    eprintln!(
        "Warning: HTTPS inspection reveals the plaintext contents of encrypted requests from the configured child process."
    );
    eprintln!(
        "The local CA will not be installed automatically. Type 'inspect' to enable HTTPS inspection, or press Enter to tunnel CONNECT without decryption."
    );
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("Enable HTTPS inspection? ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("cannot read HTTPS inspection confirmation")?;
    Ok(input.trim() == "inspect")
}

fn confirm_ca_trust_install(path: &std::path::Path) -> Result<bool> {
    eprintln!(
        "Installing a local debugging CA lets TLScope decrypt HTTPS from applications that trust your Windows user root store."
    );
    eprintln!(
        "Install this certificate only in a controlled test environment: {}",
        path.display()
    );
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("Install TLScope CA into CurrentUser Root? Type 'install' to confirm: ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("cannot read CA installation confirmation")?;
    Ok(input.trim() == "install")
}

fn print_manual_install_instructions(path: &std::path::Path) {
    println!("Manual CA installation is required for test clients that trust custom roots.");
    println!(
        "Install this certificate only in a controlled test environment: {}",
        path.display()
    );
    println!("On Windows, use `TLScope ca install` to trust it for the current user.");
    println!("If the application uses certificate pinning or ignores proxy variables, TLScope will not bypass it.");
}

fn save_session_if_requested(
    app_config: &AppConfig,
    store: &Arc<Mutex<TrafficStore>>,
) -> Result<()> {
    if let Some(path) = &app_config.save_session {
        let entries = store
            .lock()
            .map_err(|_| anyhow!("capture store lock is poisoned"))?
            .entries()
            .to_vec();
        export_session_json(path, &entries, &app_config.redaction)?;
    }
    Ok(())
}

fn spawn_child_output_reader<R>(
    reader: R,
    stream: ChildOutputStream,
    logs: Arc<Mutex<ChildLogStore>>,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        let mut bytes = Vec::new();
        loop {
            bytes.clear();
            match reader.read_until(b'\n', &mut bytes).await {
                Ok(0) => break,
                Ok(_) => {
                    let line = sanitize_output_line(&bytes, CHILD_LOG_LINE_LIMIT);
                    push_child_log(&logs, stream, line);
                }
                Err(error) => {
                    push_child_log(
                        &logs,
                        stream,
                        format!("[TLScope] failed to read child {}: {error}", stream.label()),
                    );
                    break;
                }
            }
        }
    });
}

fn push_child_log(
    logs: &Arc<Mutex<ChildLogStore>>,
    stream: ChildOutputStream,
    line: impl Into<String>,
) {
    if let Ok(mut guard) = logs.lock() {
        guard.push(stream, line);
    }
}
fn report_child_exit(exit: &ChildExit) {
    if exit.success {
        eprintln!(
            "Child process {:?} exited successfully with code {:?}",
            exit.pid, exit.code
        );
    } else {
        eprintln!(
            "Child process {:?} exited with non-zero code {:?}",
            exit.pid, exit.code
        );
    }
}

enum ChildControl {
    Terminate(Duration),
    Detach,
}

async fn child_supervisor(
    child: &mut crate::process::launcher::ChildHandle,
    running: Arc<AtomicBool>,
    control_rx: oneshot::Receiver<ChildControl>,
) -> Result<Option<ChildExit>> {
    tokio::pin!(control_rx);
    let result = tokio::select! {
        exit = child.wait_ref() => Some(exit?),
        control = &mut control_rx => {
            match control {
                Ok(ChildControl::Terminate(grace)) => Some(child.terminate_ref(grace).await?),
                Ok(ChildControl::Detach) | Err(_) => None,
            }
        }
    };
    running.store(false, Ordering::SeqCst);
    Ok(result)
}
