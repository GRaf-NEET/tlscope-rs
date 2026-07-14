use crate::{
    certificates::{
        authority::{ca_cert_path, ca_fingerprint_from_dir, LocalAuthority},
        trust_store,
    },
    cli::{CommonProxyArgs, RunArgs},
    config::default_ca_dir,
    process::tracking::ProcessTrackingConfig,
};
use anyhow::{anyhow, bail, Context, Result};
use crossterm::{
    event::{self, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame, Terminal,
};
#[cfg(windows)]
use serde::Deserialize;
#[cfg(windows)]
use std::process::Command;
use std::{
    ffi::OsString,
    fs,
    io::{self, IsTerminal},
    net::SocketAddr,
    path::{Path, PathBuf, MAIN_SEPARATOR},
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Target,
    Arguments,
    Workdir,
    Start,
    Listen,
    MaxBody,
    Env,
    SaveSession,
    HttpsInspection,
    OnlyHttp1,
    ExtraCaEnv,
    Redact,
    ShowSecrets,
    CaDir,
    CaStatus,
    CreateCa,
    InstallCaTrust,
    CaPath,
    CaFingerprint,
    RemoveCa,
}

const PROGRAM_FIELDS: &[Field] = &[Field::Target, Field::Arguments, Field::Workdir];
const RUN_FIELDS: &[Field] = &[
    Field::Listen,
    Field::MaxBody,
    Field::Env,
    Field::SaveSession,
    Field::HttpsInspection,
    Field::OnlyHttp1,
    Field::ExtraCaEnv,
    Field::Redact,
    Field::ShowSecrets,
];
const CA_FIELDS: &[Field] = &[
    Field::CaDir,
    Field::CaStatus,
    Field::CreateCa,
    Field::InstallCaTrust,
    Field::CaPath,
    Field::CaFingerprint,
    Field::RemoveCa,
];
const START_FIELDS: &[Field] = &[Field::Start];
const FIELD_ROWS: &[&[Field]] = &[
    &[Field::Target],
    &[Field::Arguments],
    &[Field::Workdir],
    &[Field::Listen, Field::CaDir],
    &[Field::MaxBody, Field::CaStatus],
    &[Field::Env, Field::CreateCa],
    &[Field::SaveSession, Field::InstallCaTrust],
    &[Field::HttpsInspection, Field::CaPath],
    &[Field::OnlyHttp1, Field::CaFingerprint],
    &[Field::ExtraCaEnv, Field::RemoveCa],
    &[Field::Redact],
    &[Field::ShowSecrets],
    &[Field::Start],
];
const FIELDS: &[Field] = &[
    Field::Target,
    Field::Arguments,
    Field::Workdir,
    Field::Listen,
    Field::MaxBody,
    Field::Env,
    Field::SaveSession,
    Field::HttpsInspection,
    Field::OnlyHttp1,
    Field::ExtraCaEnv,
    Field::Redact,
    Field::ShowSecrets,
    Field::CaDir,
    Field::CaStatus,
    Field::CreateCa,
    Field::InstallCaTrust,
    Field::CaPath,
    Field::CaFingerprint,
    Field::RemoveCa,
    Field::Start,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LauncherScreen {
    Form,
    LaunchSelect,
}

#[derive(Debug, Clone)]
struct LaunchOption {
    path: PathBuf,
    kind: &'static str,
}

#[derive(Debug)]
struct LauncherState {
    screen: LauncherScreen,
    selected: usize,
    editing: Option<Field>,
    edit_buffer: String,
    target: String,
    arguments: String,
    workdir: String,
    listen: String,
    ca_dir: String,
    max_body_size: String,
    env: String,
    save_session: String,
    https_inspection: bool,
    only_http1: bool,
    extra_ca_env: bool,
    redact: bool,
    show_secrets: bool,
    ca_trust_status: String,
    confirm_remove_ca: bool,
    launch_options: Vec<LaunchOption>,
    launch_selected: usize,
    launch_filter: String,
    message: String,
}

impl Default for LauncherState {
    fn default() -> Self {
        Self {
            screen: LauncherScreen::Form,
            selected: 0,
            editing: None,
            edit_buffer: String::new(),
            target: String::new(),
            arguments: String::new(),
            workdir: String::new(),
            listen: "127.0.0.1:8080".to_string(),
            ca_dir: String::new(),
            max_body_size: "1048576".to_string(),
            env: String::new(),
            save_session: String::new(),
            https_inspection: false,
            only_http1: false,
            extra_ca_env: true,
            redact: true,
            show_secrets: false,
            ca_trust_status: "not checked".to_string(),
            confirm_remove_ca: false,
            launch_options: Vec::new(),
            launch_selected: 0,
            launch_filter: String::new(),
            message: "Choose a program, tune launch settings, then start.".to_string(),
        }
    }
}
pub fn prompt_run_args() -> Result<RunArgs> {
    if !io::stdin().is_terminal() {
        bail!("interactive launch requires a terminal; use `TLScope run -- <program>` instead");
    }
    run_launcher_tui()
}

#[derive(Debug, Clone)]
pub struct ResolvedCommandTarget {
    pub command: Vec<OsString>,
    pub process_tracking: ProcessTrackingConfig,
}

pub fn resolve_command_target(
    mut command: Vec<OsString>,
    mut process_tracking: ProcessTrackingConfig,
) -> Result<ResolvedCommandTarget> {
    let Some(first) = command.first() else {
        bail!("child process not specified");
    };
    let path = PathBuf::from(first);
    if path.is_dir() {
        if !io::stdin().is_terminal() {
            bail!(
                "program path points to a folder; run TLScope in a terminal to choose a launch file, or pass the file path directly"
            );
        }
        let selected = choose_launch_target_tui(&path)?;
        command[0] = selected.into_os_string();
    }
    let resolved = resolve_shortcut_command(command)?;
    command = resolved.command;
    if process_tracking.is_empty() {
        process_tracking = resolved.process_tracking;
    }
    Ok(ResolvedCommandTarget {
        command,
        process_tracking,
    })
}

fn run_launcher_tui() -> Result<RunArgs> {
    enable_raw_mode().context("cannot enable terminal raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("cannot enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("cannot create launcher terminal")?;
    let mut state = LauncherState::default();

    let result = launcher_loop(&mut terminal, &mut state);

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

fn launcher_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut LauncherState,
) -> Result<RunArgs> {
    loop {
        terminal
            .draw(|frame| draw_launcher(frame, state))
            .context("failed to draw launcher")?;

        if !event::poll(Duration::from_millis(100)).context("failed to poll launcher events")? {
            continue;
        }
        let event::Event::Key(key) = event::read().context("failed to read launcher event")? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if let Some(args) = handle_launcher_key(state, key)? {
            return Ok(args);
        }
    }
}

fn draw_launcher(frame: &mut Frame<'_>, state: &LauncherState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(4),
        ])
        .split(area);

    let title = Paragraph::new(vec![
        Line::from(Span::styled(
            "TLScope launcher",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("Program selection, launch options, and local CA management."),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    match state.screen {
        LauncherScreen::Form => draw_form(frame, chunks[1], state),
        LauncherScreen::LaunchSelect => draw_launch_select(frame, chunks[1], state),
    }

    let hint = match (state.screen, state.editing, state.confirm_remove_ca) {
        (_, _, true) => "Enter/y remove local CA files | Esc/n cancel",
        (_, Some(field), _) if completion_mode(field).is_some() => {
            "Type value | Tab complete path | Enter save | Esc cancel edit"
        }
        (_, Some(_), _) => "Type value | Enter save | Esc cancel edit",
        (LauncherScreen::Form, None, _) => {
            "Up/Down select | Left/Right paired fields | Enter edit/toggle/action | Esc/q cancel"
        }
        (LauncherScreen::LaunchSelect, None, _) => {
            "Type filter | Arrows select | Enter launch selected | Backspace edit | Esc back"
        }
    };
    let footer = Paragraph::new(vec![
        Line::from(state.message.clone()),
        Line::from(Span::styled(hint, Style::default().fg(Color::Yellow))),
    ])
    .block(Block::default().borders(Borders::ALL).title("Help"));
    frame.render_widget(footer, chunks[2]);
}

fn draw_form(frame: &mut Frame<'_>, area: Rect, state: &LauncherState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    draw_field_group(frame, rows[0], "Program", PROGRAM_FIELDS, state);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);

    draw_field_group(frame, columns[0], "Launch settings", RUN_FIELDS, state);
    draw_field_group(frame, columns[1], "Certificate", CA_FIELDS, state);
    draw_field_group(frame, rows[2], "Start", START_FIELDS, state);
}

fn draw_field_group(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &'static str,
    fields: &[Field],
    state: &LauncherState,
) {
    let lines = fields
        .iter()
        .map(|field| field_line(state, *field))
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}
fn field_line(state: &LauncherState, field: Field) -> Line<'static> {
    let selected = selected_field(state) == field;
    let marker = if selected { "> " } else { "  " };
    let mut marker_style = Style::default();
    let mut label_style = Style::default();
    if selected {
        marker_style = marker_style.fg(Color::Yellow).add_modifier(Modifier::BOLD);
        label_style = label_style.fg(Color::Yellow).add_modifier(Modifier::BOLD);
    }

    let value_style = if selected {
        field_value_style(state, field).add_modifier(Modifier::BOLD)
    } else {
        field_value_style(state, field)
    };

    Line::from(vec![
        Span::styled(marker, marker_style),
        Span::styled(format!("{:<17}", field_label(field)), label_style),
        Span::styled(field_value(state, field), value_style),
    ])
}

fn draw_launch_select(frame: &mut Frame<'_>, area: Rect, state: &LauncherState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(area);
    let filter_text = if state.launch_filter.is_empty() {
        "<type to filter>".to_string()
    } else {
        format!("{}_", state.launch_filter)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Name  ", Style::default().fg(Color::Cyan)),
            Span::raw(filter_text),
        ]))
        .block(Block::default().borders(Borders::ALL).title("Search")),
        rows[0],
    );

    let filtered = filtered_launch_indices(state);
    if filtered.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from("No launchable files match the filter."))
                .block(Block::default().borders(Borders::ALL).title("Files")),
            rows[1],
        );
        return;
    }

    let groups = launch_group_indices(state, &filtered);
    let constraints = vec![Constraint::Ratio(1, groups.len() as u32); groups.len()];
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(rows[1]);

    for (group, area) in groups.iter().zip(columns.iter()) {
        let lines = group
            .indices
            .iter()
            .map(|filtered_index| {
                let option_index = filtered[*filtered_index];
                let option = &state.launch_options[option_index];
                let selected = state.launch_selected == *filtered_index;
                let marker = if selected { "> " } else { "  " };
                let style = if selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Line::from(vec![
                    Span::styled(marker, style),
                    Span::styled(format!("{}. ", filtered_index + 1), style),
                    Span::raw(launch_option_name(option)),
                ])
            })
            .collect::<Vec<_>>();
        frame.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(launch_group_title(group.kind)),
            ),
            *area,
        );
    }
}

fn handle_launcher_key(state: &mut LauncherState, key: KeyEvent) -> Result<Option<RunArgs>> {
    if state.confirm_remove_ca {
        return handle_ca_remove_confirmation(state, key);
    }

    if let Some(field) = state.editing {
        match key.code {
            KeyCode::Enter => {
                apply_edit(state, field);
                state.editing = None;
                state.message = "Value saved.".to_string();
            }
            KeyCode::Esc => {
                state.editing = None;
                state.message = "Edit cancelled.".to_string();
            }
            KeyCode::Backspace => {
                state.edit_buffer.pop();
            }
            KeyCode::Tab => complete_edit_buffer(state, field),
            KeyCode::Char(ch) => state.edit_buffer.push(ch),
            _ => state.message = "This key is not available while editing.".to_string(),
        }
        return Ok(None);
    }

    match state.screen {
        LauncherScreen::Form => handle_form_key(state, key),
        LauncherScreen::LaunchSelect => handle_launch_select_key(state, key),
    }
}

fn handle_form_key(state: &mut LauncherState, key: KeyEvent) -> Result<Option<RunArgs>> {
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => {
            move_selection_vertical(state, 1);
            Ok(None)
        }
        KeyCode::Up | KeyCode::Char('k') => {
            move_selection_vertical(state, -1);
            Ok(None)
        }
        KeyCode::Right | KeyCode::Char('l') => {
            move_selection_horizontal(state, 1);
            Ok(None)
        }
        KeyCode::Left | KeyCode::Char('h') => {
            move_selection_horizontal(state, -1);
            Ok(None)
        }
        KeyCode::Enter => activate_field(state),
        KeyCode::Esc | KeyCode::Char('q') => bail!("launch cancelled"),
        _ => {
            state.message = "This key is not available here.".to_string();
            Ok(None)
        }
    }
}

fn handle_launch_select_key(state: &mut LauncherState, key: KeyEvent) -> Result<Option<RunArgs>> {
    match key.code {
        KeyCode::Down => {
            move_launch_selection_vertical(state, 1);
            Ok(None)
        }
        KeyCode::Up => {
            move_launch_selection_vertical(state, -1);
            Ok(None)
        }
        KeyCode::Right => {
            move_launch_selection_horizontal(state, 1);
            Ok(None)
        }
        KeyCode::Left => {
            move_launch_selection_horizontal(state, -1);
            Ok(None)
        }
        KeyCode::Home => {
            state.launch_selected = 0;
            state.message.clear();
            Ok(None)
        }
        KeyCode::End => {
            let filtered = filtered_launch_indices(state);
            state.launch_selected = filtered.len().saturating_sub(1);
            state.message.clear();
            Ok(None)
        }
        KeyCode::Backspace => {
            state.launch_filter.pop();
            clamp_launch_selection(state);
            state.message = launch_filter_message(state);
            Ok(None)
        }
        KeyCode::Delete => {
            state.launch_filter.clear();
            clamp_launch_selection(state);
            state.message = launch_filter_message(state);
            Ok(None)
        }
        KeyCode::Char(ch) => {
            state.launch_filter.push(ch);
            clamp_launch_selection(state);
            state.message = launch_filter_message(state);
            Ok(None)
        }
        KeyCode::Enter => {
            let filtered = filtered_launch_indices(state);
            let Some(option_index) = filtered.get(state.launch_selected).copied() else {
                state.message = "No launchable file selected.".to_string();
                return Ok(None);
            };
            let path = state.launch_options[option_index].path.clone();
            state.target = path.display().to_string();
            Ok(match build_run_args(state) {
                Ok(args) => Some(args),
                Err(error) => {
                    state.message = error.to_string();
                    None
                }
            })
        }
        KeyCode::Esc => {
            state.screen = LauncherScreen::Form;
            state.message = "Program selection cancelled.".to_string();
            Ok(None)
        }
        _ => {
            state.message = "Choose a launchable file with Enter, or press Esc.".to_string();
            Ok(None)
        }
    }
}
fn activate_field(state: &mut LauncherState) -> Result<Option<RunArgs>> {
    match selected_field(state) {
        Field::HttpsInspection => {
            state.https_inspection = !state.https_inspection;
            state.message = if state.https_inspection {
                "HTTPS inspection enabled. Make sure the TLScope CA is trusted.".to_string()
            } else {
                "HTTPS inspection disabled; CONNECT will be tunneled.".to_string()
            };
            Ok(None)
        }
        Field::OnlyHttp1 => {
            state.only_http1 = !state.only_http1;
            state.message = if state.only_http1 {
                "HTTP/2 ALPN disabled; inspected HTTPS will stay on HTTP/1.1.".to_string()
            } else {
                "HTTP/2 ALPN enabled for inspected HTTPS.".to_string()
            };
            Ok(None)
        }
        Field::ExtraCaEnv => {
            state.extra_ca_env = !state.extra_ca_env;
            state.message = if state.extra_ca_env {
                "Extra CA environment variables will be passed to the child.".to_string()
            } else {
                "Extra CA environment variables disabled.".to_string()
            };
            Ok(None)
        }
        Field::Redact => {
            state.redact = !state.redact;
            state.message = if state.redact {
                "JSON/form sensitive fields will be redacted.".to_string()
            } else {
                "Only default sensitive headers will be redacted.".to_string()
            };
            Ok(None)
        }
        Field::ShowSecrets => {
            state.show_secrets = !state.show_secrets;
            state.message = if state.show_secrets {
                "Sensitive values will be visible in UI and exports.".to_string()
            } else {
                "Sensitive values will be redacted.".to_string()
            };
            Ok(None)
        }
        Field::Start => start_from_form(state),
        Field::CaStatus => check_ca_status_from_launcher(state),
        Field::CreateCa => create_ca_from_launcher(state),
        Field::InstallCaTrust => install_ca_trust_from_launcher(state),
        Field::CaPath => show_ca_path_from_launcher(state),
        Field::CaFingerprint => show_ca_fingerprint_from_launcher(state),
        Field::RemoveCa => begin_ca_remove_from_launcher(state),
        field => {
            state.editing = Some(field);
            state.edit_buffer = editable_value(state, field);
            state.message = format!("Editing {}.", field_label(field));
            Ok(None)
        }
    }
}

fn selected_field(state: &LauncherState) -> Field {
    FIELDS.get(state.selected).copied().unwrap_or(Field::Target)
}

fn select_field(state: &mut LauncherState, field: Field) {
    if let Some(index) = FIELDS.iter().position(|item| *item == field) {
        state.selected = index;
        state.message.clear();
    }
}

fn field_position(field: Field) -> (usize, usize) {
    FIELD_ROWS
        .iter()
        .enumerate()
        .find_map(|(row, fields)| {
            fields
                .iter()
                .position(|candidate| *candidate == field)
                .map(|column| (row, column))
        })
        .unwrap_or((0, 0))
}

fn move_selection_vertical(state: &mut LauncherState, direction: isize) {
    let field = selected_field(state);
    let (row, column) = field_position(field);
    let next = if direction < 0 {
        row.saturating_sub(1)
    } else {
        (row + 1).min(FIELD_ROWS.len().saturating_sub(1))
    };
    if next == row {
        state.message = if direction < 0 {
            "Already at the first row.".to_string()
        } else {
            "Already at the last row.".to_string()
        };
    } else {
        let fields = FIELD_ROWS[next];
        select_field(state, fields[column.min(fields.len().saturating_sub(1))]);
    }
}

fn move_selection_horizontal(state: &mut LauncherState, direction: isize) {
    let field = selected_field(state);
    let (row, column) = field_position(field);
    let fields = FIELD_ROWS[row];
    let next_column = if direction < 0 {
        column.saturating_sub(1)
    } else {
        (column + 1).min(fields.len().saturating_sub(1))
    };
    if next_column == column {
        state.message = if direction < 0 {
            "No field to the left.".to_string()
        } else {
            "No field to the right.".to_string()
        };
        return;
    }
    select_field(state, fields[next_column]);
}

fn check_ca_status_from_launcher(state: &mut LauncherState) -> Result<Option<RunArgs>> {
    let ca_dir = launcher_ca_dir(state);
    let cert_path = ca_cert_path(&ca_dir);
    if !cert_path.exists() {
        state.ca_trust_status = "not created".to_string();
        state.message = format!(
            "No TLScope CA at {}. Choose Create CA.",
            cert_path.display()
        );
        return Ok(None);
    }

    let fingerprint = ca_fingerprint_from_dir(&ca_dir).unwrap_or_else(|_| "unknown".to_string());
    match trust_store::is_current_user_root_installed(&cert_path) {
        Ok(true) => {
            state.ca_trust_status = "trusted".to_string();
            state.message = format!("CA is trusted. SHA-256 {fingerprint}");
        }
        Ok(false) => {
            state.ca_trust_status = "not trusted".to_string();
            state.message = format!("CA exists but is not trusted. SHA-256 {fingerprint}");
        }
        Err(error) => {
            state.ca_trust_status = "check failed".to_string();
            state.message = format!("Cannot inspect OS trust store: {error}");
        }
    }
    Ok(None)
}

fn create_ca_from_launcher(state: &mut LauncherState) -> Result<Option<RunArgs>> {
    let ca_dir = launcher_ca_dir(state);
    match LocalAuthority::load_or_create(&ca_dir) {
        Ok(ca) => {
            state.ca_trust_status = "not checked".to_string();
            let fingerprint = ca.fingerprint().unwrap_or_else(|_| "unknown".to_string());
            state.message = format!(
                "CA ready at {}. SHA-256 {fingerprint}",
                ca.cert_path().display()
            );
        }
        Err(error) => {
            state.ca_trust_status = "CA error".to_string();
            state.message = format!("Cannot create/load TLScope CA: {error}");
        }
    }
    Ok(None)
}
fn install_ca_trust_from_launcher(state: &mut LauncherState) -> Result<Option<RunArgs>> {
    let ca_dir = launcher_ca_dir(state);
    match LocalAuthority::load_or_create(&ca_dir) {
        Ok(ca) => {
            let fingerprint = ca.fingerprint().unwrap_or_else(|_| "unknown".to_string());
            match trust_store::is_current_user_root_installed(ca.cert_path()) {
                Ok(true) => {
                    state.ca_trust_status = "trusted".to_string();
                    state.message = format!("TLScope CA is already trusted. SHA-256 {fingerprint}");
                }
                Ok(false) => match trust_store::install_current_user_root(ca.cert_path()) {
                    Ok(()) => {
                        state.ca_trust_status = "trusted".to_string();
                        state.message = format!(
                            "Installed TLScope CA into CurrentUser Root. SHA-256 {fingerprint}"
                        );
                    }
                    Err(error) => {
                        state.ca_trust_status = "install failed".to_string();
                        state.message = format!("CA install failed: {error}");
                    }
                },
                Err(error) => {
                    state.ca_trust_status = "check failed".to_string();
                    state.message = format!("Cannot inspect CurrentUser Root store: {error}");
                }
            }
        }
        Err(error) => {
            state.ca_trust_status = "CA error".to_string();
            state.message = format!("Cannot create/load TLScope CA: {error}");
        }
    }
    Ok(None)
}

fn show_ca_path_from_launcher(state: &mut LauncherState) -> Result<Option<RunArgs>> {
    let ca_dir = launcher_ca_dir(state);
    let cert_path = ca_cert_path(&ca_dir);
    let note = if cert_path.exists() {
        "certificate"
    } else {
        "planned certificate path"
    };
    state.message = format!("CA {note}: {}", cert_path.display());
    Ok(None)
}

fn show_ca_fingerprint_from_launcher(state: &mut LauncherState) -> Result<Option<RunArgs>> {
    let ca_dir = launcher_ca_dir(state);
    match ca_fingerprint_from_dir(&ca_dir) {
        Ok(fingerprint) => state.message = format!("CA SHA-256 fingerprint: {fingerprint}"),
        Err(error) => state.message = format!("Cannot read CA fingerprint: {error}"),
    }
    Ok(None)
}

fn begin_ca_remove_from_launcher(state: &mut LauncherState) -> Result<Option<RunArgs>> {
    state.confirm_remove_ca = true;
    state.message = format!(
        "Remove local CA files in {}? Enter/y confirms. This does not remove OS trust.",
        launcher_ca_dir(state).display()
    );
    Ok(None)
}

fn handle_ca_remove_confirmation(
    state: &mut LauncherState,
    key: KeyEvent,
) -> Result<Option<RunArgs>> {
    match key.code {
        KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => remove_ca_files(state),
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            state.confirm_remove_ca = false;
            state.message = "CA removal cancelled.".to_string();
            Ok(None)
        }
        _ => {
            state.message = "Confirm CA removal with Enter/y, or cancel with Esc/n.".to_string();
            Ok(None)
        }
    }
}

fn remove_ca_files(state: &mut LauncherState) -> Result<Option<RunArgs>> {
    state.confirm_remove_ca = false;
    let ca_dir = launcher_ca_dir(state);
    match LocalAuthority::remove_created_files(&ca_dir, true) {
        Ok(true) => {
            state.ca_trust_status = "not created".to_string();
            state.message = format!(
                "Removed local CA files from {}. Remove OS trust manually if it was installed.",
                ca_dir.display()
            );
        }
        Ok(false) => {
            state.ca_trust_status = "not created".to_string();
            state.message = "No TLScope-created CA files were removed.".to_string();
        }
        Err(error) => {
            state.ca_trust_status = "remove failed".to_string();
            state.message = format!("Cannot remove local CA files: {error}");
        }
    }
    Ok(None)
}

fn ca_status_value(state: &LauncherState) -> String {
    let ca_dir = launcher_ca_dir(state);
    let cert_path = ca_cert_path(&ca_dir);
    if cert_path.exists() {
        format!("created | trust: {}", state.ca_trust_status)
    } else {
        "not created".to_string()
    }
}

fn ca_trust_value(state: &LauncherState) -> String {
    format!("{} | Enter install/check", state.ca_trust_status)
}

fn launcher_ca_dir(state: &LauncherState) -> PathBuf {
    optional_path(&state.ca_dir).unwrap_or_else(default_ca_dir)
}
fn start_from_form(state: &mut LauncherState) -> Result<Option<RunArgs>> {
    let target = normalize_path(&state.target);
    if !target.exists() {
        state.message = format!("Path does not exist: {}", target.display());
        return Ok(None);
    }
    if target.is_dir() {
        match list_launch_options(&target) {
            Ok(options) if options.is_empty() => {
                state.message = format!(
                    "No supported launch files ({}) found in {}.",
                    supported_launch_formats_label(),
                    target.display()
                );
            }
            Ok(options) => {
                state.launch_options = options;
                state.launch_selected = 0;
                state.launch_filter.clear();
                state.screen = LauncherScreen::LaunchSelect;
                state.message = "Folder selected. Filter by name, then launch a file.".to_string();
            }
            Err(error) => state.message = error.to_string(),
        }
        return Ok(None);
    }
    if !is_launchable_file(&target) {
        state.message = format!(
            "Target must be a supported launch file ({}) or a folder.",
            supported_launch_formats_label()
        );
        return Ok(None);
    }
    Ok(match build_run_args(state) {
        Ok(args) => Some(args),
        Err(error) => {
            state.message = error.to_string();
            None
        }
    })
}

fn build_run_args(state: &LauncherState) -> Result<RunArgs> {
    let target = normalize_path(&state.target);
    if !is_launchable_file(&target) {
        bail!(
            "target is not a supported launch file ({}): {}",
            supported_launch_formats_label(),
            target.display()
        );
    }
    let resolved = resolve_launch_target(&target)?;
    let listen = state
        .listen
        .trim()
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid proxy listen address '{}'", state.listen.trim()))?;
    let max_body_size = state
        .max_body_size
        .trim()
        .parse::<usize>()
        .with_context(|| format!("invalid max body size '{}'", state.max_body_size.trim()))?;
    let command = build_resolved_command(&resolved, &state.arguments)?;
    let default_workdir = resolved
        .workdir
        .clone()
        .or_else(|| resolved.program.parent().map(Path::to_path_buf))
        .or_else(|| target.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let workdir = if state.workdir.trim().is_empty() {
        Some(default_workdir)
    } else {
        Some(normalize_path(&state.workdir))
    };

    Ok(RunArgs {
        common: CommonProxyArgs {
            listen,
            no_tls_decryption: !state.https_inspection,
            only_http1: state.only_http1,
            ca_dir: optional_path(&state.ca_dir),
            max_body_size,
            redact: state.redact,
            show_secrets: state.show_secrets,
            save_session: optional_path(&state.save_session),
            allow_external: false,
        },
        workdir,
        env: parse_env_overrides(&state.env),
        no_extra_ca_env: !state.extra_ca_env,
        tls_confirmed: state.https_inspection,
        command,
        process_tracking: resolved.process_tracking,
    })
}

#[derive(Debug)]
struct ResolvedLaunchTarget {
    program: PathBuf,
    arguments: Vec<OsString>,
    workdir: Option<PathBuf>,
    process_tracking: ProcessTrackingConfig,
}

fn resolve_launch_target(target: &Path) -> Result<ResolvedLaunchTarget> {
    if is_shortcut_path(target) {
        return resolve_shortcut_target(target);
    }
    Ok(ResolvedLaunchTarget {
        program: target.to_path_buf(),
        arguments: Vec::new(),
        workdir: target.parent().map(Path::to_path_buf),
        process_tracking: tracking_for_target_path(target),
    })
}

fn resolve_shortcut_command(command: Vec<OsString>) -> Result<ResolvedCommandTarget> {
    let Some(first) = command.first() else {
        bail!("child process not specified");
    };
    let shortcut = PathBuf::from(first);
    if !is_shortcut_path(&shortcut) {
        return Ok(ResolvedCommandTarget {
            process_tracking: ProcessTrackingConfig::for_command(&command),
            command,
        });
    }
    if !shortcut.is_file() {
        bail!("shortcut is not a file: {}", shortcut.display());
    }
    let resolved = resolve_shortcut_target(&shortcut)?;
    let mut resolved_command = vec![resolved.program.into_os_string()];
    resolved_command.extend(resolved.arguments);
    resolved_command.extend(command.into_iter().skip(1));
    Ok(ResolvedCommandTarget {
        command: resolved_command,
        process_tracking: resolved.process_tracking,
    })
}

fn build_resolved_command(
    resolved: &ResolvedLaunchTarget,
    user_args: &str,
) -> Result<Vec<OsString>> {
    let mut command = vec![resolved.program.as_os_str().to_os_string()];
    command.extend(resolved.arguments.iter().cloned());
    command.extend(split_args(user_args)?.into_iter().map(OsString::from));
    Ok(command)
}

fn tracking_for_target_path(path: &Path) -> ProcessTrackingConfig {
    let mut tracking = ProcessTrackingConfig::default();
    tracking.add_target_path(path);
    tracking
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WindowsShortcutTarget {
    target_path: String,
    arguments: Option<String>,
    working_directory: Option<String>,
}

#[cfg(windows)]
fn resolve_shortcut_target(shortcut: &Path) -> Result<ResolvedLaunchTarget> {
    if is_url_shortcut_path(shortcut) {
        return resolve_internet_shortcut_target(shortcut);
    }

    let shortcut_path = powershell_single_quoted_literal(&shortcut.display().to_string());
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$shortcutPath = {shortcut_path}
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
[pscustomobject]@{{
    TargetPath = $shortcut.TargetPath
    Arguments = $shortcut.Arguments
    WorkingDirectory = $shortcut.WorkingDirectory
}} | ConvertTo-Json -Compress
"#
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(script)
        .output()
        .with_context(|| format!("cannot inspect shortcut {}", shortcut.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "cannot inspect shortcut {}: {}",
            shortcut.display(),
            stderr.trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let info: WindowsShortcutTarget = serde_json::from_str(stdout.trim())
        .with_context(|| format!("cannot parse shortcut metadata for {}", shortcut.display()))?;
    let program = PathBuf::from(info.target_path.trim());
    if program.as_os_str().is_empty() {
        bail!("shortcut has no target path: {}", shortcut.display());
    }
    let arguments = split_args(&info.arguments.unwrap_or_default())
        .with_context(|| format!("cannot parse shortcut arguments for {}", shortcut.display()))?
        .into_iter()
        .map(OsString::from)
        .collect();
    Ok(ResolvedLaunchTarget {
        program,
        arguments,
        workdir: non_empty_path(info.working_directory),
        process_tracking: {
            let mut tracking = tracking_for_target_path(Path::new(info.target_path.trim()));
            tracking.add_process_names_from_path(shortcut);
            tracking
        },
    })
}

#[cfg(windows)]
fn resolve_internet_shortcut_target(shortcut: &Path) -> Result<ResolvedLaunchTarget> {
    let contents = read_shortcut_text(shortcut)?;
    let url = parse_internet_shortcut_url(&contents)
        .ok_or_else(|| anyhow!("internet shortcut has no URL: {}", shortcut.display()))?;
    Ok(ResolvedLaunchTarget {
        program: PathBuf::from("rundll32.exe"),
        arguments: vec![
            OsString::from("url.dll,FileProtocolHandler"),
            OsString::from(url),
        ],
        workdir: shortcut.parent().map(Path::to_path_buf),
        process_tracking: {
            let mut tracking = ProcessTrackingConfig::default();
            tracking.add_process_names_from_path(shortcut);
            if let Some(label) = shortcut
                .file_stem()
                .map(|name| name.to_string_lossy().into_owned())
            {
                tracking.set_label(label);
            }
            tracking
        },
    })
}

#[cfg(windows)]
fn read_shortcut_text(path: &Path) -> Result<String> {
    let bytes =
        fs::read(path).with_context(|| format!("cannot read shortcut {}", path.display()))?;
    if bytes.starts_with(&[0xff, 0xfe]) {
        let words = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        return String::from_utf16(&words)
            .with_context(|| format!("cannot decode UTF-16 shortcut {}", path.display()));
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Ok(String::from_utf8_lossy(&bytes[3..]).into_owned());
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(windows)]
fn parse_internet_shortcut_url(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let line = line.trim().trim_start_matches('\u{feff}');
        let (key, value) = line.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("URL")
            .then(|| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

#[cfg(windows)]
fn powershell_single_quoted_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(not(windows))]
fn resolve_shortcut_target(shortcut: &Path) -> Result<ResolvedLaunchTarget> {
    bail!(
        "shortcuts are not supported on this platform: {}",
        shortcut.display()
    )
}

fn non_empty_path(value: Option<String>) -> Option<PathBuf> {
    let value = value?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn is_shortcut_path(path: &Path) -> bool {
    shortcut_extension_matches(path)
}

#[cfg(windows)]
fn is_url_shortcut_path(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("url"))
}

#[cfg(windows)]
fn shortcut_extension_matches(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("lnk") || extension.eq_ignore_ascii_case("url")
    })
}

#[cfg(not(windows))]
fn shortcut_extension_matches(_path: &Path) -> bool {
    false
}

fn choose_launch_target_tui(folder: &Path) -> Result<PathBuf> {
    enable_raw_mode().context("cannot enable terminal raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("cannot enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("cannot create executable selector")?;
    let result = choose_launch_target_loop(&mut terminal, folder);
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    result
}

fn choose_launch_target_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    folder: &Path,
) -> Result<PathBuf> {
    let mut state = LauncherState {
        screen: LauncherScreen::LaunchSelect,
        launch_options: list_launch_options(folder)?,
        message: format!(
            "Choose a launch file ({}) from {}.",
            supported_launch_formats_label(),
            folder.display()
        ),
        ..LauncherState::default()
    };
    if state.launch_options.is_empty() {
        bail!(
            "no supported launch files ({}) found in {}",
            supported_launch_formats_label(),
            folder.display()
        );
    }
    loop {
        terminal
            .draw(|frame| draw_launcher(frame, &state))
            .context("failed to draw executable selector")?;
        if !event::poll(Duration::from_millis(100)).context("failed to poll selector events")? {
            continue;
        }
        let event::Event::Key(key) = event::read().context("failed to read selector event")? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Enter => {
                let filtered = filtered_launch_indices(&state);
                if let Some(option_index) = filtered.get(state.launch_selected).copied() {
                    return Ok(state.launch_options[option_index].path.clone());
                }
            }
            KeyCode::Esc => bail!("launch cancelled"),
            KeyCode::Down => move_launch_selection_vertical(&mut state, 1),
            KeyCode::Up => move_launch_selection_vertical(&mut state, -1),
            KeyCode::Right => move_launch_selection_horizontal(&mut state, 1),
            KeyCode::Left => move_launch_selection_horizontal(&mut state, -1),
            KeyCode::Backspace => {
                state.launch_filter.pop();
                clamp_launch_selection(&mut state);
                state.message = launch_filter_message(&state);
            }
            KeyCode::Delete => {
                state.launch_filter.clear();
                clamp_launch_selection(&mut state);
                state.message = launch_filter_message(&state);
            }
            KeyCode::Char(ch) => {
                state.launch_filter.push(ch);
                clamp_launch_selection(&mut state);
                state.message = launch_filter_message(&state);
            }
            _ => state.message = "Choose with Enter, or cancel with Esc.".to_string(),
        }
    }
}

fn list_launch_options(folder: &Path) -> Result<Vec<LaunchOption>> {
    let mut options = fs::read_dir(folder)
        .with_context(|| format!("cannot read folder {}", folder.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter_map(|path| launch_file_kind(&path).map(|kind| LaunchOption { path, kind }))
        .collect::<Vec<_>>();
    options.sort_by_key(|option| {
        (
            launch_format_order(option.kind),
            option
                .path
                .file_name()
                .map(|name| name.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default(),
        )
    });
    Ok(options)
}

#[derive(Debug)]
struct LaunchGroupIndices {
    kind: &'static str,
    indices: Vec<usize>,
}

fn filtered_launch_indices(state: &LauncherState) -> Vec<usize> {
    let needle = state.launch_filter.to_ascii_lowercase();
    state
        .launch_options
        .iter()
        .enumerate()
        .filter(|(_, option)| {
            needle.is_empty()
                || launch_option_name(option)
                    .to_ascii_lowercase()
                    .contains(&needle)
        })
        .map(|(index, _)| index)
        .collect()
}

fn launch_group_indices(state: &LauncherState, filtered: &[usize]) -> Vec<LaunchGroupIndices> {
    LAUNCH_FORMATS
        .iter()
        .filter_map(|kind| {
            let indices = filtered
                .iter()
                .enumerate()
                .filter_map(|(filtered_index, option_index)| {
                    (state.launch_options[*option_index].kind == *kind).then_some(filtered_index)
                })
                .collect::<Vec<_>>();
            (!indices.is_empty()).then_some(LaunchGroupIndices {
                kind: *kind,
                indices,
            })
        })
        .collect()
}

fn clamp_launch_selection(state: &mut LauncherState) {
    let filtered_len = filtered_launch_indices(state).len();
    if filtered_len == 0 {
        state.launch_selected = 0;
    } else if state.launch_selected >= filtered_len {
        state.launch_selected = filtered_len - 1;
    }
}

fn launch_filter_message(state: &LauncherState) -> String {
    let count = filtered_launch_indices(state).len();
    if state.launch_filter.is_empty() {
        format!("{count} launchable files.")
    } else {
        format!("{count} matches for '{}'.", state.launch_filter)
    }
}

fn move_launch_selection_vertical(state: &mut LauncherState, direction: isize) {
    let filtered = filtered_launch_indices(state);
    if filtered.is_empty() {
        state.message = "No launchable files match the filter.".to_string();
        state.launch_selected = 0;
        return;
    }
    let groups = launch_group_indices(state, &filtered);
    let Some((group_index, row_index)) = launch_selection_position(&groups, state.launch_selected)
    else {
        state.launch_selected = 0;
        return;
    };
    let group = &groups[group_index];
    let next_row = if direction < 0 {
        row_index.saturating_sub(1)
    } else {
        (row_index + 1).min(group.indices.len().saturating_sub(1))
    };
    if next_row == row_index {
        state.message = if direction < 0 {
            "Already at the first file in this column.".to_string()
        } else {
            "Already at the last file in this column.".to_string()
        };
    } else {
        state.launch_selected = group.indices[next_row];
        state.message.clear();
    }
}

fn move_launch_selection_horizontal(state: &mut LauncherState, direction: isize) {
    let filtered = filtered_launch_indices(state);
    if filtered.is_empty() {
        state.message = "No launchable files match the filter.".to_string();
        state.launch_selected = 0;
        return;
    }
    let groups = launch_group_indices(state, &filtered);
    let Some((group_index, row_index)) = launch_selection_position(&groups, state.launch_selected)
    else {
        state.launch_selected = 0;
        return;
    };
    let next_group = if direction < 0 {
        group_index.saturating_sub(1)
    } else {
        (group_index + 1).min(groups.len().saturating_sub(1))
    };
    if next_group == group_index {
        state.message = if direction < 0 {
            "No file column to the left.".to_string()
        } else {
            "No file column to the right.".to_string()
        };
        return;
    }
    let target_group = &groups[next_group];
    let target_row = row_index.min(target_group.indices.len().saturating_sub(1));
    state.launch_selected = target_group.indices[target_row];
    state.message.clear();
}

fn launch_selection_position(
    groups: &[LaunchGroupIndices],
    selected: usize,
) -> Option<(usize, usize)> {
    groups.iter().enumerate().find_map(|(group_index, group)| {
        group
            .indices
            .iter()
            .position(|index| *index == selected)
            .map(|row_index| (group_index, row_index))
    })
}

fn launch_option_name(option: &LaunchOption) -> String {
    option
        .path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| option.path.display().to_string())
}

fn launch_group_title(kind: &str) -> String {
    if kind == "file" {
        "files".to_string()
    } else {
        format!(".{kind}")
    }
}

fn supported_launch_formats_label() -> String {
    LAUNCH_FORMATS
        .iter()
        .map(|kind| launch_group_title(kind))
        .collect::<Vec<_>>()
        .join(", ")
}

fn launch_format_order(kind: &str) -> usize {
    LAUNCH_FORMATS
        .iter()
        .position(|candidate| *candidate == kind)
        .unwrap_or(usize::MAX)
}

#[cfg(windows)]
const LAUNCH_FORMATS: &[&str] = &["exe", "lnk", "url"];

#[cfg(not(windows))]
const LAUNCH_FORMATS: &[&str] = &["file"];

fn launch_file_kind(path: &Path) -> Option<&'static str> {
    if !path.is_file() {
        return None;
    }
    launch_kind_for_path(path)
}

#[cfg(windows)]
fn launch_kind_for_path(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_string_lossy();
    if extension.eq_ignore_ascii_case("exe") {
        Some("exe")
    } else if extension.eq_ignore_ascii_case("lnk") {
        Some("lnk")
    } else if extension.eq_ignore_ascii_case("url") {
        Some("url")
    } else {
        None
    }
}

#[cfg(not(windows))]
fn launch_kind_for_path(_path: &Path) -> Option<&'static str> {
    Some("file")
}

fn is_launchable_file(path: &Path) -> bool {
    launch_file_kind(path).is_some()
}
fn field_label(field: Field) -> &'static str {
    match field {
        Field::Target => "Program path",
        Field::Arguments => "Arguments",
        Field::Workdir => "Workdir",
        Field::Start => "Start",
        Field::Listen => "Proxy listen",
        Field::MaxBody => "Max body bytes",
        Field::Env => "Extra env",
        Field::SaveSession => "Save JSON",
        Field::HttpsInspection => "HTTPS inspect",
        Field::OnlyHttp1 => "Only HTTP/1.1",
        Field::ExtraCaEnv => "CA env vars",
        Field::Redact => "Redact body",
        Field::ShowSecrets => "Show secrets",
        Field::CaDir => "CA directory",
        Field::CaStatus => "CA status",
        Field::CreateCa => "Create/load CA",
        Field::InstallCaTrust => "Trust in OS",
        Field::CaPath => "Show path",
        Field::CaFingerprint => "Fingerprint",
        Field::RemoveCa => "Remove files",
    }
}

fn field_value(state: &LauncherState, field: Field) -> String {
    if state.editing == Some(field) {
        return format!("{}_", state.edit_buffer);
    }
    match field {
        Field::Target => display_empty(&state.target, "file/folder, Tab completes"),
        Field::Arguments => display_empty(&state.arguments, "optional"),
        Field::Workdir => display_empty(&state.workdir, "auto"),
        Field::Start => "Enter to launch".to_string(),
        Field::Listen => state.listen.clone(),
        Field::MaxBody => state.max_body_size.clone(),
        Field::Env => display_empty(&state.env, "KEY=VALUE;KEY2=VALUE"),
        Field::SaveSession => display_empty(&state.save_session, "off"),
        Field::HttpsInspection => on_off(state.https_inspection),
        Field::OnlyHttp1 => on_off(state.only_http1),
        Field::ExtraCaEnv => on_off(state.extra_ca_env),
        Field::Redact => on_off(state.redact),
        Field::ShowSecrets => on_off(state.show_secrets),
        Field::CaDir => display_empty(&state.ca_dir, "default"),
        Field::CaStatus => ca_status_value(state),
        Field::CreateCa => "Enter".to_string(),
        Field::InstallCaTrust => ca_trust_value(state),
        Field::CaPath => "Enter".to_string(),
        Field::CaFingerprint => "Enter".to_string(),
        Field::RemoveCa => "Enter".to_string(),
    }
}

fn field_value_style(state: &LauncherState, field: Field) -> Style {
    if state.editing == Some(field) {
        return Style::default().fg(Color::Yellow);
    }
    match field {
        Field::HttpsInspection => toggle_style(state.https_inspection),
        Field::OnlyHttp1 => toggle_style(state.only_http1),
        Field::ExtraCaEnv => toggle_style(state.extra_ca_env),
        Field::Redact => toggle_style(state.redact),
        Field::ShowSecrets => {
            if state.show_secrets {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Green)
            }
        }
        Field::CaStatus | Field::InstallCaTrust => ca_status_style(&state.ca_trust_status),
        Field::CreateCa | Field::CaPath | Field::CaFingerprint => Style::default().fg(Color::Cyan),
        Field::RemoveCa => Style::default().fg(Color::Red),
        Field::Start => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        _ => Style::default(),
    }
}

fn toggle_style(enabled: bool) -> Style {
    if enabled {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn ca_status_style(status: &str) -> Style {
    if status.contains("trusted") && !status.contains("not trusted") {
        Style::default().fg(Color::Green)
    } else if status.contains("failed") || status.contains("error") {
        Style::default().fg(Color::Red)
    } else if status.contains("not created") || status.contains("not trusted") {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Cyan)
    }
}

fn editable_value(state: &LauncherState, field: Field) -> String {
    match field {
        Field::Target => state.target.clone(),
        Field::Arguments => state.arguments.clone(),
        Field::Workdir => state.workdir.clone(),
        Field::Listen => state.listen.clone(),
        Field::CaDir => state.ca_dir.clone(),
        Field::MaxBody => state.max_body_size.clone(),
        Field::Env => state.env.clone(),
        Field::SaveSession => state.save_session.clone(),
        Field::HttpsInspection
        | Field::OnlyHttp1
        | Field::ExtraCaEnv
        | Field::Redact
        | Field::ShowSecrets
        | Field::Start
        | Field::CaStatus
        | Field::CreateCa
        | Field::InstallCaTrust
        | Field::CaPath
        | Field::CaFingerprint
        | Field::RemoveCa => String::new(),
    }
}

fn apply_edit(state: &mut LauncherState, field: Field) {
    let value = state.edit_buffer.trim().to_string();
    match field {
        Field::Target => state.target = value,
        Field::Arguments => state.arguments = value,
        Field::Workdir => state.workdir = value,
        Field::Listen => state.listen = value,
        Field::CaDir => {
            state.ca_dir = value;
            state.ca_trust_status = "not checked".to_string();
        }
        Field::MaxBody => state.max_body_size = value,
        Field::Env => state.env = value,
        Field::SaveSession => state.save_session = value,
        Field::HttpsInspection
        | Field::OnlyHttp1
        | Field::ExtraCaEnv
        | Field::Redact
        | Field::ShowSecrets
        | Field::Start
        | Field::CaStatus
        | Field::CreateCa
        | Field::InstallCaTrust
        | Field::CaPath
        | Field::CaFingerprint
        | Field::RemoveCa => {}
    }
}
#[derive(Debug, Clone, Copy)]
enum CompletionMode {
    ExecutableOrDir,
    Directory,
    Any,
}

#[derive(Debug, PartialEq, Eq)]
enum CompletionOutcome {
    Completed(String, String),
    Choices(String),
    NoMatch(String),
}

#[derive(Debug)]
struct CompletionCandidate {
    name: String,
    is_dir: bool,
}

fn completion_mode(field: Field) -> Option<CompletionMode> {
    match field {
        Field::Target => Some(CompletionMode::ExecutableOrDir),
        Field::Workdir | Field::CaDir => Some(CompletionMode::Directory),
        Field::SaveSession => Some(CompletionMode::Any),
        _ => None,
    }
}

fn complete_edit_buffer(state: &mut LauncherState, field: Field) {
    let Some(mode) = completion_mode(field) else {
        state.message = "Path completion is not available for this field.".to_string();
        return;
    };
    match complete_path_input(&state.edit_buffer, mode) {
        Ok(CompletionOutcome::Completed(value, message)) => {
            state.edit_buffer = value;
            state.message = message;
        }
        Ok(CompletionOutcome::Choices(message) | CompletionOutcome::NoMatch(message)) => {
            state.message = message;
        }
        Err(error) => state.message = error,
    }
}

fn complete_path_input(
    input: &str,
    mode: CompletionMode,
) -> std::result::Result<CompletionOutcome, String> {
    let (raw, quoted) = strip_optional_quote(input.trim());
    let (base_dir, prefix) = completion_base_and_prefix(&raw);
    let prefix_cmp = prefix.to_ascii_lowercase();
    let mut candidates = fs::read_dir(&base_dir)
        .map_err(|error| format!("cannot read {}: {error}", base_dir.display()))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if !completion_candidate_allowed(&path, mode) {
                return None;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.to_ascii_lowercase().starts_with(&prefix_cmp) {
                return None;
            }
            Some(CompletionCandidate {
                name,
                is_dir: path.is_dir(),
            })
        })
        .collect::<Vec<_>>();

    candidates.sort_by_key(|candidate| candidate.name.to_ascii_lowercase());

    if candidates.is_empty() {
        return Ok(CompletionOutcome::NoMatch(format!(
            "No path matches '{}' in {}.",
            prefix,
            base_dir.display()
        )));
    }

    if candidates.len() == 1 {
        let candidate = &candidates[0];
        let completed = completion_join(&base_dir, &candidate.name);
        let value = format_path_for_edit(&completed, candidate.is_dir, quoted);
        return Ok(CompletionOutcome::Completed(
            value,
            format!("Completed {}.", candidate.name),
        ));
    }

    let names = candidates
        .iter()
        .map(|candidate| candidate.name.clone())
        .collect::<Vec<_>>();
    let common = common_prefix(&names);
    if common.len() > prefix.len() {
        let completed = completion_join(&base_dir, &common);
        let value = format_path_for_edit(&completed, false, quoted);
        return Ok(CompletionOutcome::Completed(
            value,
            format!("Completed common prefix; {} matches.", candidates.len()),
        ));
    }

    let preview = names.into_iter().take(5).collect::<Vec<_>>().join(", ");
    Ok(CompletionOutcome::Choices(format!(
        "{} matches: {}",
        candidates.len(),
        preview
    )))
}

fn strip_optional_quote(input: &str) -> (String, bool) {
    let quoted = input.starts_with('"');
    let value = input.trim_matches('"').to_string();
    (value, quoted)
}

fn completion_base_and_prefix(input: &str) -> (PathBuf, String) {
    if input.is_empty() {
        return (PathBuf::from("."), String::new());
    }
    let path = PathBuf::from(input);
    if input.ends_with(['\\', '/']) || path.is_dir() {
        return (path, String::new());
    }
    let prefix = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    (base, prefix)
}

fn completion_join(base_dir: &Path, name: &str) -> PathBuf {
    if base_dir == Path::new(".") {
        PathBuf::from(name)
    } else {
        base_dir.join(name)
    }
}
fn completion_candidate_allowed(path: &Path, mode: CompletionMode) -> bool {
    match mode {
        CompletionMode::Any => true,
        CompletionMode::Directory => path.is_dir(),
        CompletionMode::ExecutableOrDir => path.is_dir() || is_launchable_file(path),
    }
}

fn format_path_for_edit(path: &Path, append_separator: bool, force_quote: bool) -> String {
    let mut value = path.display().to_string();
    if append_separator && !value.ends_with(['\\', '/']) {
        value.push(MAIN_SEPARATOR);
    }
    if force_quote || value.contains(' ') {
        format!("\"{value}\"")
    } else {
        value
    }
}

fn common_prefix(values: &[String]) -> String {
    let Some(first) = values.first() else {
        return String::new();
    };
    let mut common = String::new();
    for (index, ch) in first.chars().enumerate() {
        let matches = values.iter().all(|value| {
            value
                .chars()
                .nth(index)
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(&ch))
        });
        if matches {
            common.push(ch);
        } else {
            break;
        }
    }
    common
}

fn display_empty(value: &str, placeholder: &str) -> String {
    if value.trim().is_empty() {
        format!("<{placeholder}>")
    } else {
        value.to_string()
    }
}

fn on_off(value: bool) -> String {
    if value {
        "ON".to_string()
    } else {
        "OFF".to_string()
    }
}

fn split_args(input: &str) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(ch) = chars.next() {
        match ch {
            '"' | '\'' if quote.is_none() => quote = Some(ch),
            ch if Some(ch) == quote => quote = None,
            '\\' if quote == Some('"') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                } else {
                    current.push('\\');
                }
            }
            ch if ch.is_whitespace() && quote.is_none() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            ch => current.push(ch),
        }
    }

    if let Some(quote) = quote {
        return Err(anyhow!("unclosed quote {quote} in arguments"));
    }
    if !current.is_empty() {
        args.push(current);
    }
    Ok(args)
}

fn parse_env_overrides(input: &str) -> Vec<String> {
    input
        .split(';')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn optional_path(input: &str) -> Option<PathBuf> {
    if input.trim().is_empty() {
        None
    } else {
        Some(normalize_path(input))
    }
}

fn normalize_path(input: &str) -> PathBuf {
    let trimmed = input.trim().trim_matches('"');
    PathBuf::from(trimmed)
}

#[cfg(test)]
mod tests {
    use super::{
        ca_trust_value, complete_path_input, filtered_launch_indices, list_launch_options,
        split_args, CompletionMode, CompletionOutcome, LaunchOption, LauncherState, LAUNCH_FORMATS,
    };
    use std::fs;

    #[test]
    fn shows_ca_trust_action_without_requiring_https_inspection() {
        let state = LauncherState::default();
        assert!(ca_trust_value(&state).contains("install/check"));
    }

    #[test]
    fn splits_quoted_arguments() {
        let args = split_args(r#"--name "Geometry Dash" --flag 'two words'"#).expect("split");
        assert_eq!(args, ["--name", "Geometry Dash", "--flag", "two words"]);
    }

    #[test]
    fn completes_program_path_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = dir.path().join("DemoApp.exe");
        fs::write(&exe, b"").expect("write exe");
        let prefix = dir.path().join("Demo").display().to_string();

        let completed =
            complete_path_input(&prefix, CompletionMode::ExecutableOrDir).expect("completion");

        match completed {
            CompletionOutcome::Completed(value, _) => assert!(value.ends_with("DemoApp.exe")),
            other => panic!("unexpected completion result: {other:?}"),
        }
    }

    #[test]
    fn filters_launch_options_by_name() {
        let state = LauncherState {
            launch_options: vec![
                LaunchOption {
                    path: "AlphaTool.exe".into(),
                    kind: LAUNCH_FORMATS[0],
                },
                LaunchOption {
                    path: "BetaTool.exe".into(),
                    kind: LAUNCH_FORMATS[0],
                },
            ],
            launch_filter: "alpha".to_string(),
            ..LauncherState::default()
        };

        assert_eq!(filtered_launch_indices(&state), vec![0]);
    }

    #[cfg(windows)]
    #[test]
    fn lists_windows_launch_files_by_supported_format() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("Beta.lnk"), b"").expect("write lnk");
        fs::write(dir.path().join("Alpha.exe"), b"").expect("write exe");
        fs::write(
            dir.path().join("The Farmer Was Replaced.url"),
            b"[InternetShortcut]\nURL=steam://rungameid/2060160\n",
        )
        .expect("write url");
        fs::write(dir.path().join("notes.txt"), b"").expect("write ignored");

        let options = list_launch_options(dir.path()).expect("list");
        let names = options
            .iter()
            .map(|option| {
                option
                    .path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        let kinds = options.iter().map(|option| option.kind).collect::<Vec<_>>();

        assert_eq!(
            names,
            ["Alpha.exe", "Beta.lnk", "The Farmer Was Replaced.url"]
        );
        assert_eq!(kinds, ["exe", "lnk", "url"]);
    }

    #[cfg(windows)]
    #[test]
    fn completes_shortcut_path_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shortcut = dir.path().join("DemoShortcut.lnk");
        fs::write(&shortcut, b"").expect("write lnk");
        let prefix = dir.path().join("Demo").display().to_string();

        let completed =
            complete_path_input(&prefix, CompletionMode::ExecutableOrDir).expect("completion");

        match completed {
            CompletionOutcome::Completed(value, _) => assert!(value.ends_with("DemoShortcut.lnk")),
            other => panic!("unexpected completion result: {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn completes_internet_shortcut_path_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shortcut = dir.path().join("DemoSteam.url");
        fs::write(&shortcut, b"[InternetShortcut]\nURL=steam://rungameid/1\n").expect("write url");
        let prefix = dir.path().join("Demo").display().to_string();

        let completed =
            complete_path_input(&prefix, CompletionMode::ExecutableOrDir).expect("completion");

        match completed {
            CompletionOutcome::Completed(value, _) => assert!(value.ends_with("DemoSteam.url")),
            other => panic!("unexpected completion result: {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn resolves_internet_shortcut_to_protocol_handler() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shortcut = dir.path().join("SteamGame.url");
        fs::write(
            &shortcut,
            b"[InternetShortcut]\nURL=steam://rungameid/2060160\n",
        )
        .expect("write url");

        let resolved = super::resolve_internet_shortcut_target(&shortcut).expect("resolve");

        assert_eq!(resolved.program, std::path::PathBuf::from("rundll32.exe"));
        assert_eq!(
            resolved.arguments,
            [
                std::ffi::OsString::from("url.dll,FileProtocolHandler"),
                std::ffi::OsString::from("steam://rungameid/2060160")
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn internet_shortcut_tracking_uses_shortcut_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shortcut = dir.path().join("The Farmer Was Replaced.url");
        fs::write(
            &shortcut,
            b"[InternetShortcut]\nURL=steam://rungameid/2060160\n",
        )
        .expect("write url");

        let resolved = super::resolve_internet_shortcut_target(&shortcut).expect("resolve");

        assert_eq!(
            resolved.process_tracking.label(),
            Some("The Farmer Was Replaced")
        );
    }

    #[cfg(windows)]
    #[test]
    fn quotes_powershell_shortcut_paths() {
        assert_eq!(
            super::powershell_single_quoted_literal(r"C:\Apps\Bob's Tool.lnk"),
            r"'C:\Apps\Bob''s Tool.lnk'"
        );
    }
}
