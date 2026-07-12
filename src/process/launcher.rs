use anyhow::{anyhow, Context, Result};
use std::{
    ffi::{OsStr, OsString},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::process::{Child, Command};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildStdio {
    Inherit,
    Piped,
}

#[derive(Debug)]
pub struct LaunchRequest {
    pub command: Vec<OsString>,
    pub workdir: Option<PathBuf>,
    pub env: Vec<(OsString, OsString)>,
    pub proxy_addr: SocketAddr,
    pub ca_cert_path: Option<PathBuf>,
    pub no_extra_ca_env: bool,
    pub stdio: ChildStdio,
}

#[derive(Debug)]
pub struct ChildHandle {
    child: Child,
    pid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildExit {
    pub pid: Option<u32>,
    pub code: Option<i32>,
    pub success: bool,
}

impl ChildHandle {
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub async fn wait_ref(&mut self) -> Result<ChildExit> {
        wait_child(&mut self.child, self.pid).await
    }

    pub async fn terminate_ref(&mut self, grace: Duration) -> Result<ChildExit> {
        terminate_child(&mut self.child, self.pid, grace).await
    }

    pub async fn wait(mut self) -> Result<ChildExit> {
        wait_child(&mut self.child, self.pid).await
    }

    pub async fn terminate(mut self, grace: Duration) -> Result<ChildExit> {
        terminate_child(&mut self.child, self.pid, grace).await
    }

    pub fn take_stdout(&mut self) -> Option<tokio::process::ChildStdout> {
        self.child.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<tokio::process::ChildStderr> {
        self.child.stderr.take()
    }
}

pub fn build_proxy_environment(
    proxy_addr: SocketAddr,
    ca_cert_path: Option<&Path>,
    no_extra_ca_env: bool,
) -> Vec<(OsString, OsString)> {
    let proxy = format!("http://{proxy_addr}");
    let mut env = vec![
        ("HTTP_PROXY".into(), proxy.clone().into()),
        ("HTTPS_PROXY".into(), proxy.clone().into()),
        ("ALL_PROXY".into(), proxy.clone().into()),
        ("http_proxy".into(), proxy.clone().into()),
        ("https_proxy".into(), proxy.clone().into()),
        ("all_proxy".into(), proxy.into()),
    ];

    if !no_extra_ca_env {
        if let Some(path) = ca_cert_path {
            let path = path.as_os_str().to_os_string();
            env.extend([
                ("SSL_CERT_FILE".into(), path.clone()),
                ("REQUESTS_CA_BUNDLE".into(), path.clone()),
                ("CURL_CA_BUNDLE".into(), path.clone()),
                ("NODE_EXTRA_CA_CERTS".into(), path),
            ]);
        }
    }
    env
}

pub fn spawn_child(request: LaunchRequest) -> Result<ChildHandle> {
    let program = request
        .command
        .first()
        .ok_or_else(|| anyhow!("child process not specified"))?;
    let mut command = Command::new(program);
    command.args(request.command.iter().skip(1));
    if let Some(workdir) = &request.workdir {
        command.current_dir(workdir);
    }
    for (key, value) in build_proxy_environment(
        request.proxy_addr,
        request.ca_cert_path.as_deref(),
        request.no_extra_ca_env,
    ) {
        command.env(key, value);
    }
    for (key, value) in request.env {
        command.env(key, value);
    }
    match request.stdio {
        ChildStdio::Inherit => {
            command.stdin(Stdio::inherit());
            command.stdout(Stdio::inherit());
            command.stderr(Stdio::inherit());
        }
        ChildStdio::Piped => {
            command.stdin(Stdio::null());
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
        }
    }

    let child = command.spawn().with_context(|| {
        format!(
            "child process '{}' was not found or could not be started",
            display_os(program)
        )
    })?;
    let pid = child.id();
    Ok(ChildHandle { child, pid })
}

async fn wait_child(child: &mut Child, pid: Option<u32>) -> Result<ChildExit> {
    let status = child
        .wait()
        .await
        .context("failed while waiting for child process")?;
    Ok(ChildExit {
        pid,
        code: status.code(),
        success: status.success(),
    })
}

async fn terminate_child(
    child: &mut Child,
    pid: Option<u32>,
    grace: Duration,
) -> Result<ChildExit> {
    if let Some(status) = child
        .try_wait()
        .context("failed to inspect child process status")?
    {
        return Ok(ChildExit {
            pid,
            code: status.code(),
            success: status.success(),
        });
    }

    if let Some(pid) = pid {
        soft_terminate(pid).await?;
    }

    let sleep = tokio::time::sleep(grace);
    tokio::pin!(sleep);
    tokio::select! {
        _ = &mut sleep => {
            child.start_kill().context("failed to force-kill child process")?;
            let status = child.wait().await.context("failed to wait for force-killed child process")?;
            Ok(ChildExit { pid, code: status.code(), success: status.success() })
        }
        status = child.wait() => {
            let status = status.context("failed to wait for child process after termination signal")?;
            Ok(ChildExit { pid, code: status.code(), success: status.success() })
        }
    }
}

fn display_os(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}

#[cfg(unix)]
async fn soft_terminate(pid: u32) -> Result<()> {
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "failed to send SIGTERM to child process {pid}: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(windows)]
async fn soft_terminate(pid: u32) -> Result<()> {
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("failed to run taskkill for child process")?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("taskkill could not terminate child process {pid}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_proxy_environment_with_extra_ca() {
        let addr = "127.0.0.1:18080".parse().expect("addr");
        let env = build_proxy_environment(addr, Some(Path::new("ca.pem")), false);
        assert!(env
            .iter()
            .any(|(k, v)| k == "HTTP_PROXY" && v == "http://127.0.0.1:18080"));
        assert!(env.iter().any(|(k, _)| k == "NODE_EXTRA_CA_CERTS"));
    }

    #[test]
    fn can_disable_extra_ca_environment() {
        let addr = "127.0.0.1:18080".parse().expect("addr");
        let env = build_proxy_environment(addr, Some(Path::new("ca.pem")), true);
        assert!(!env.iter().any(|(k, _)| k == "NODE_EXTRA_CA_CERTS"));
    }
}
