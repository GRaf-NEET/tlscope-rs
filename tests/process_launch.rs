use std::{ffi::OsString, path::PathBuf, time::Duration};

use tlscope::process::launcher::{spawn_child, ChildStdio, LaunchRequest};
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn launches_child_with_proxy_environment() {
    let command = proxy_echo_command();
    let mut child = spawn_child(LaunchRequest {
        command,
        workdir: None,
        env: Vec::new(),
        proxy_addr: "127.0.0.1:18080".parse().unwrap(),
        ca_cert_path: Some(PathBuf::from("ca.pem")),
        no_extra_ca_env: false,
        stdio: ChildStdio::Piped,
    })
    .unwrap();
    let mut stdout = child.take_stdout().unwrap();
    let mut output = String::new();
    stdout.read_to_string(&mut output).await.unwrap();
    let exit = child.wait_ref().await.unwrap();
    assert!(exit.success);
    assert!(output.contains("http://127.0.0.1:18080"));
}

#[cfg(not(windows))]
#[tokio::test]
async fn terminates_child_process() {
    let mut child = spawn_child(LaunchRequest {
        command: sleep_command(),
        workdir: None,
        env: Vec::new(),
        proxy_addr: "127.0.0.1:18080".parse().unwrap(),
        ca_cert_path: None,
        no_extra_ca_env: true,
        stdio: ChildStdio::Piped,
    })
    .unwrap();
    let exit = child
        .terminate_ref(Duration::from_millis(200))
        .await
        .unwrap();
    assert!(!exit.success);
}

#[cfg(windows)]
#[tokio::test]
async fn terminate_ref_reports_already_exited_child_on_windows() {
    let mut child = spawn_child(LaunchRequest {
        command: vec!["cmd".into(), "/C".into(), "exit /B 7".into()],
        workdir: None,
        env: Vec::new(),
        proxy_addr: "127.0.0.1:18080".parse().unwrap(),
        ca_cert_path: None,
        no_extra_ca_env: true,
        stdio: ChildStdio::Piped,
    })
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let exit = child
        .terminate_ref(Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(exit.code, Some(7));
    assert!(!exit.success);
}

#[cfg(windows)]
fn proxy_echo_command() -> Vec<OsString> {
    vec!["cmd".into(), "/C".into(), "echo %HTTP_PROXY%".into()]
}

#[cfg(not(windows))]
fn proxy_echo_command() -> Vec<OsString> {
    vec!["sh".into(), "-c".into(), "printf %s \"$HTTP_PROXY\"".into()]
}

#[cfg(not(windows))]
fn sleep_command() -> Vec<OsString> {
    vec!["sh".into(), "-c".into(), "sleep 30".into()]
}
