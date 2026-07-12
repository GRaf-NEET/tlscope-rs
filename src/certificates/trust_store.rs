use anyhow::{anyhow, Context, Result};
use std::{path::Path, process::Command};

#[cfg(windows)]
pub fn is_current_user_root_installed(cert_path: &Path) -> Result<bool> {
    let output = Command::new("certutil")
        .args(["-user", "-verifystore", "Root"])
        .arg(cert_path)
        .output()
        .context("failed to run certutil; cannot inspect Windows CurrentUser Root store")?;
    Ok(output.status.success())
}

#[cfg(not(windows))]
pub fn is_current_user_root_installed(_cert_path: &Path) -> Result<bool> {
    Ok(false)
}
#[cfg(windows)]
pub fn install_current_user_root(cert_path: &Path) -> Result<()> {
    let output = Command::new("certutil")
        .args(["-user", "-addstore", "Root"])
        .arg(cert_path)
        .output()
        .context("failed to run certutil; cannot install CA into Windows CurrentUser Root store")?;
    if output.status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "certutil failed while installing CA into Windows CurrentUser Root store: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[cfg(not(windows))]
pub fn install_current_user_root(_cert_path: &Path) -> Result<()> {
    Err(anyhow!(
        "automatic CA trust installation is currently implemented only for Windows CurrentUser Root store"
    ))
}
