use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_EXIT_SETTLE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct ProcessTrackingConfig {
    executable_paths: Vec<PathBuf>,
    process_names: Vec<String>,
    label: Option<String>,
    poll_interval: Duration,
    exit_settle: Duration,
}

impl Default for ProcessTrackingConfig {
    fn default() -> Self {
        Self {
            executable_paths: Vec::new(),
            process_names: Vec::new(),
            label: None,
            poll_interval: DEFAULT_POLL_INTERVAL,
            exit_settle: DEFAULT_EXIT_SETTLE,
        }
    }
}

impl ProcessTrackingConfig {
    pub fn for_command(command: &[OsString]) -> Self {
        let mut config = Self::default();
        if let Some(program) = command.first() {
            config.add_target_path(Path::new(program));
        }
        config
    }

    pub fn add_target_path(&mut self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        if !path.as_os_str().is_empty() {
            push_unique_path(&mut self.executable_paths, path.to_path_buf());
            self.add_process_names_from_path(path);
            if self.label.is_none() {
                self.label = path
                    .file_stem()
                    .map(|name| name.to_string_lossy().into_owned())
                    .filter(|name| !name.is_empty());
            }
        }
    }

    pub fn add_process_names_from_path(&mut self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        if let Some(file_name) = path.file_name().and_then(OsStr::to_str) {
            self.add_process_name(file_name);
        }
        if let Some(stem) = path.file_stem().and_then(OsStr::to_str) {
            self.add_process_name(stem);
        }
    }

    pub fn add_process_name(&mut self, name: impl AsRef<str>) {
        let name = normalize_process_name(name.as_ref());
        if name.is_empty() {
            return;
        }
        if !self.process_names.iter().any(|item| item == &name) {
            self.process_names.push(name);
        }
    }

    pub fn set_label(&mut self, label: impl Into<String>) {
        let label = label.into();
        if !label.trim().is_empty() {
            self.label = Some(label);
        }
    }

    pub fn merge(&mut self, other: ProcessTrackingConfig) {
        for path in other.executable_paths {
            push_unique_path(&mut self.executable_paths, path);
        }
        for name in other.process_names {
            if !self.process_names.iter().any(|item| item == &name) {
                self.process_names.push(name);
            }
        }
        if self.label.is_none() {
            self.label = other.label;
        }
        self.poll_interval = other.poll_interval;
        self.exit_settle = other.exit_settle;
    }

    pub fn is_empty(&self) -> bool {
        self.executable_paths.is_empty() && self.process_names.is_empty()
    }

    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    pub fn exit_settle(&self) -> Duration {
        self.exit_settle
    }

    fn matches(&self, process: &ProcessInfo) -> bool {
        let path_matches = process.executable_path.as_ref().is_some_and(|path| {
            self.executable_paths
                .iter()
                .any(|candidate| same_process_path(candidate, path))
        });
        let name_matches = self
            .process_names
            .iter()
            .any(|candidate| process.name_matches(candidate));
        path_matches || name_matches
    }
}

#[derive(Debug, Clone)]
pub struct TrackedProcess {
    pub pid: u32,
    pub name: String,
    pub executable_path: Option<PathBuf>,
}

impl TrackedProcess {
    pub fn display_label(&self) -> String {
        self.executable_path
            .as_ref()
            .and_then(|path| path.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| self.name.clone())
    }
}

#[derive(Debug, Clone)]
pub struct TrackingSummary {
    pub observed_process_count: usize,
    pub quiet_for: Duration,
}

#[derive(Debug, Clone)]
pub struct ProcessTracker {
    config: ProcessTrackingConfig,
    baseline_pids: HashSet<u32>,
    child_pid: Option<u32>,
    observed_pids: HashSet<u32>,
}

impl ProcessTracker {
    pub async fn prepare(config: ProcessTrackingConfig) -> Result<Self> {
        let snapshot = current_process_snapshot().await?;
        let baseline_pids = matching_processes(&config, None, &HashSet::new(), &snapshot)
            .into_iter()
            .map(|process| process.pid)
            .collect();
        Ok(Self {
            config,
            baseline_pids,
            child_pid: None,
            observed_pids: HashSet::new(),
        })
    }

    pub fn without_baseline(config: ProcessTrackingConfig) -> Self {
        Self {
            config,
            baseline_pids: HashSet::new(),
            child_pid: None,
            observed_pids: HashSet::new(),
        }
    }

    pub fn set_child_pid(&mut self, pid: Option<u32>) {
        self.child_pid = pid;
        if let Some(pid) = pid {
            self.observed_pids.insert(pid);
        }
    }

    pub fn config(&self) -> &ProcessTrackingConfig {
        &self.config
    }

    pub async fn active_processes(&mut self) -> Result<Vec<TrackedProcess>> {
        let snapshot = current_process_snapshot().await?;
        let active =
            matching_processes(&self.config, self.child_pid, &self.baseline_pids, &snapshot);
        for process in &active {
            self.observed_pids.insert(process.pid);
        }
        Ok(active
            .into_iter()
            .map(|process| TrackedProcess {
                pid: process.pid,
                name: process.name,
                executable_path: process.executable_path,
            })
            .collect())
    }

    pub async fn wait_for_quiet_after_exit(&mut self) -> Result<TrackingSummary> {
        let settle = self.config.exit_settle;
        let mut quiet_since: Option<Instant> = None;
        loop {
            let active = self.active_processes().await?;
            if active.is_empty() {
                let quiet_start = quiet_since.get_or_insert_with(Instant::now);
                let quiet_for = quiet_start.elapsed();
                if quiet_for >= settle {
                    return Ok(TrackingSummary {
                        observed_process_count: self.observed_pids.len(),
                        quiet_for,
                    });
                }
            } else {
                quiet_since = None;
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessInfo {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    executable_path: Option<PathBuf>,
}

impl ProcessInfo {
    fn name_matches(&self, candidate: &str) -> bool {
        let name = normalize_process_name(&self.name);
        if name == candidate {
            return true;
        }
        Path::new(&self.name)
            .file_stem()
            .and_then(OsStr::to_str)
            .map(normalize_process_name)
            .is_some_and(|stem| stem == candidate)
    }
}

fn matching_processes(
    config: &ProcessTrackingConfig,
    child_pid: Option<u32>,
    baseline_pids: &HashSet<u32>,
    snapshot: &[ProcessInfo],
) -> Vec<ProcessInfo> {
    let parents = snapshot
        .iter()
        .filter_map(|process| process.parent_pid.map(|parent| (process.pid, parent)))
        .collect::<HashMap<_, _>>();

    snapshot
        .iter()
        .filter(|process| {
            let child_related = child_pid.is_some_and(|pid| {
                process.pid == pid || is_descendant_of(process.pid, pid, &parents)
            });
            child_related || (config.matches(process) && !baseline_pids.contains(&process.pid))
        })
        .cloned()
        .collect()
}

fn is_descendant_of(pid: u32, ancestor: u32, parents: &HashMap<u32, u32>) -> bool {
    let mut current = pid;
    let mut visited = HashSet::new();
    while let Some(parent) = parents.get(&current).copied() {
        if parent == ancestor {
            return true;
        }
        if !visited.insert(current) {
            return false;
        }
        current = parent;
    }
    false
}

async fn current_process_snapshot() -> Result<Vec<ProcessInfo>> {
    tokio::task::spawn_blocking(current_process_snapshot_blocking)
        .await
        .context("process snapshot task failed")?
}

#[cfg(windows)]
fn current_process_snapshot_blocking() -> Result<Vec<ProcessInfo>> {
    use serde_json::Value;
    use std::process::Command;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct WindowsProcessInfo {
        process_id: u32,
        parent_process_id: Option<u32>,
        name: Option<String>,
        executable_path: Option<String>,
    }

    let script = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Get-CimInstance Win32_Process |
    Select-Object ProcessId,ParentProcessId,Name,ExecutablePath |
    ConvertTo-Json -Compress
"#;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .context("cannot query Windows process list")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "cannot query Windows process list: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let value: Value =
        serde_json::from_str(trimmed).context("cannot parse Windows process list")?;
    let items = match value {
        Value::Array(items) => items,
        Value::Null => Vec::new(),
        item => vec![item],
    };
    items
        .into_iter()
        .map(|item| {
            let item: WindowsProcessInfo =
                serde_json::from_value(item).context("cannot parse Windows process item")?;
            Ok(ProcessInfo {
                pid: item.process_id,
                parent_pid: item.parent_process_id,
                name: item.name.unwrap_or_default(),
                executable_path: item.executable_path.map(PathBuf::from),
            })
        })
        .collect()
}

#[cfg(all(unix, not(windows)))]
fn current_process_snapshot_blocking() -> Result<Vec<ProcessInfo>> {
    let mut processes = Vec::new();
    for entry in std::fs::read_dir("/proc").context("cannot read /proc")? {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let dir = entry.path();
        let name = std::fs::read_to_string(dir.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let executable_path = std::fs::read_link(dir.join("exe")).ok();
        let parent_pid = read_linux_parent_pid(&dir);
        processes.push(ProcessInfo {
            pid,
            parent_pid,
            name,
            executable_path,
        });
    }
    Ok(processes)
}

#[cfg(all(unix, not(windows)))]
fn read_linux_parent_pid(dir: &Path) -> Option<u32> {
    let stat = std::fs::read_to_string(dir.join("stat")).ok()?;
    let rest = stat.rsplit_once(") ")?.1;
    rest.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(not(any(windows, unix)))]
fn current_process_snapshot_blocking() -> Result<Vec<ProcessInfo>> {
    Ok(Vec::new())
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths
        .iter()
        .any(|candidate| same_process_path(candidate, &path))
    {
        paths.push(path);
    }
}

fn same_process_path(left: &Path, right: &Path) -> bool {
    normalize_process_path(left) == normalize_process_path(right)
}

fn normalize_process_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_matches('"')
        .to_ascii_lowercase()
}

fn normalize_process_name(name: &str) -> String {
    name.trim().trim_matches('"').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_descendants_of_child_process() {
        let snapshot = vec![
            ProcessInfo {
                pid: 10,
                parent_pid: None,
                name: "parent.exe".to_string(),
                executable_path: None,
            },
            ProcessInfo {
                pid: 11,
                parent_pid: Some(10),
                name: "worker.exe".to_string(),
                executable_path: None,
            },
        ];

        let matches = matching_processes(
            &ProcessTrackingConfig::default(),
            Some(10),
            &HashSet::new(),
            &snapshot,
        );

        assert_eq!(
            matches
                .iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>(),
            [10, 11]
        );
    }

    #[test]
    fn ignores_baseline_matching_processes_but_tracks_new_ones() {
        let mut config = ProcessTrackingConfig::default();
        config.add_process_name("game.exe");
        let baseline = HashSet::from([1]);
        let snapshot = vec![
            ProcessInfo {
                pid: 1,
                parent_pid: None,
                name: "game.exe".to_string(),
                executable_path: None,
            },
            ProcessInfo {
                pid: 2,
                parent_pid: None,
                name: "game.exe".to_string(),
                executable_path: None,
            },
        ];

        let matches = matching_processes(&config, None, &baseline, &snapshot);

        assert_eq!(
            matches
                .iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>(),
            [2]
        );
    }

    #[test]
    fn matches_process_by_file_stem() {
        let mut config = ProcessTrackingConfig::default();
        config.add_process_name("The Farmer Was Replaced");
        let snapshot = vec![ProcessInfo {
            pid: 7,
            parent_pid: None,
            name: "The Farmer Was Replaced.exe".to_string(),
            executable_path: None,
        }];

        let matches = matching_processes(&config, None, &HashSet::new(), &snapshot);

        assert_eq!(
            matches
                .iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>(),
            [7]
        );
    }
}
