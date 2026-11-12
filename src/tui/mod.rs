use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::backup::{BackupSnapshot, list_backup_files, rollback_snapshot};
use crate::cli::EXIT_NO_CONSOLE;
use crate::config::{FeedbackFrequency, PowerAction, ProfileConfig, TaskbarAlignment};
use crate::engine::report::{CheckReport, CheckStatus, RuleCheck, RuleOutcome, RunReport};
use crate::engine::{ApplyOptions, Rule, UserTargetOptions, apply_rules, check_rules};
use crate::platform::{LocalUserInfo, SystemOps};
use crate::update::{
    UpdateChannel, check_for_update, current_channel, current_display_version, default_github_repo,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiEffect {
    Continue,
    Quit(i32),
}

#[derive(Debug, Clone)]
pub enum Modal {
    None,
    EditFields {
        rule_id: String,
        fields: Vec<EditableField>,
        cursor: usize,
        editing_text: Option<String>,
    },
    UserPicker {
        users: Vec<LocalUserInfo>,
        cursor: usize,
        create_name: String,
        temp_password: String,
        clear_dont_expire: bool,
        focus: UserPickerFocus,
        typing: bool,
    },
    ConfirmApply,
    ElevationPrompt,
    RollbackPicker {
        files: Vec<PathBuf>,
        cursor: usize,
    },
    ReportView {
        title: String,
        lines: Vec<String>,
        scroll: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPickerFocus {
    ExistingList,
    NewUsername,
    TempPassword,
    ClearDontExpire,
}

#[derive(Debug, Clone)]
pub enum FieldKind {
    Bool(bool),
    Text(String),
    U32(u32),
    Alignment(TaskbarAlignment),
    Feedback(FeedbackFrequency),
    PowerAct(PowerAction),
}

#[derive(Debug, Clone)]
pub struct EditableField {
    pub key: &'static str,
    pub label: &'static str,
    pub kind: FieldKind,
}

pub struct TuiApp {
    pub cfg: ProfileConfig,
    pub config_path: PathBuf,
    pub exe_dir: PathBuf,
    pub config_dirty: bool,
    pub check_report: CheckReport,
    pub selected_idx: usize,
    pub status_banner: String,
    pub modal: Modal,
    pub user_target: Option<UserTargetOptions>,
    pub relaunch_args: Vec<String>,
}

impl TuiApp {
    pub fn new(
        ops: &dyn SystemOps,
        rules: &[Box<dyn Rule>],
        cfg: ProfileConfig,
        config_path: PathBuf,
        exe_dir: PathBuf,
        relaunch_args: Vec<String>,
    ) -> Result<Self> {
        let check_report = check_all(ops, &cfg, rules)?;
        Ok(Self {
            cfg,
            config_path,
            exe_dir,
            config_dirty: false,
            check_report,
            selected_idx: 0,
            status_banner: "Ready. [Space] Toggle  [e] Edit  [u] User  [p] Dry-Run  [a] Apply  [s] Save  [b] Rollback  [v] Updates  [q] Quit".into(),
            modal: Modal::None,
            user_target: None,
            relaunch_args,
        })
    }

    pub fn refresh_check(&mut self, ops: &dyn SystemOps, rules: &[Box<dyn Rule>]) -> Result<()> {
        self.check_report = check_all(ops, &self.cfg, rules)?;
        Ok(())
    }

    pub fn current_rule_id<'a>(&self, rules: &'a [Box<dyn Rule>]) -> Option<&'a str> {
        rules.get(self.selected_idx).map(|r| r.id())
    }

    pub fn handle_key(
        &mut self,
        code: KeyCode,
        ops: &dyn SystemOps,
        rules: &[Box<dyn Rule>],
    ) -> Result<TuiEffect> {
        let modal = std::mem::replace(&mut self.modal, Modal::None);
        match modal {
            Modal::None => self.handle_main_key(code, ops, rules),
            Modal::EditFields {
                rule_id,
                mut fields,
                mut cursor,
                editing_text,
            } => {
                if let Some(mut buf) = editing_text {
                    match code {
                        KeyCode::Esc => {
                            self.modal = Modal::EditFields {
                                rule_id,
                                fields,
                                cursor,
                                editing_text: None,
                            };
                        }
                        KeyCode::Enter => {
                            if let Some(f) = fields.get_mut(cursor) {
                                apply_text_to_field(f, &buf);
                                apply_fields_to_config(&mut self.cfg, &rule_id, &fields);
                                self.config_dirty = true;
                                self.refresh_check(ops, rules)?;
                            }
                            self.modal = Modal::EditFields {
                                rule_id,
                                fields,
                                cursor,
                                editing_text: None,
                            };
                        }
                        KeyCode::Backspace => {
                            buf.pop();
                            self.modal = Modal::EditFields {
                                rule_id,
                                fields,
                                cursor,
                                editing_text: Some(buf),
                            };
                        }
                        KeyCode::Char(c) => {
                            buf.push(c);
                            self.modal = Modal::EditFields {
                                rule_id,
                                fields,
                                cursor,
                                editing_text: Some(buf),
                            };
                        }
                        _ => {
                            self.modal = Modal::EditFields {
                                rule_id,
                                fields,
                                cursor,
                                editing_text: Some(buf),
                            };
                        }
                    }
                    return Ok(TuiEffect::Continue);
                }

                match code {
                    KeyCode::Esc | KeyCode::Char('q') => {}
                    KeyCode::Up | KeyCode::Char('k') => {
                        cursor = cursor.saturating_sub(1);
                        self.modal = Modal::EditFields {
                            rule_id,
                            fields,
                            cursor,
                            editing_text: None,
                        };
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if cursor + 1 < fields.len() {
                            cursor += 1;
                        }
                        self.modal = Modal::EditFields {
                            rule_id,
                            fields,
                            cursor,
                            editing_text: None,
                        };
                    }
                    KeyCode::Char(' ') | KeyCode::Enter => {
                        if let Some(f) = fields.get_mut(cursor) {
                            match &mut f.kind {
                                FieldKind::Bool(b) => {
                                    *b = !*b;
                                    apply_fields_to_config(&mut self.cfg, &rule_id, &fields);
                                    self.config_dirty = true;
                                    self.refresh_check(ops, rules)?;
                                    self.modal = Modal::EditFields {
                                        rule_id,
                                        fields,
                                        cursor,
                                        editing_text: None,
                                    };
                                }
                                FieldKind::Alignment(a) => {
                                    *a = match a {
                                        TaskbarAlignment::Left => TaskbarAlignment::Center,
                                        TaskbarAlignment::Center => TaskbarAlignment::Left,
                                    };
                                    apply_fields_to_config(&mut self.cfg, &rule_id, &fields);
                                    self.config_dirty = true;
                                    self.refresh_check(ops, rules)?;
                                    self.modal = Modal::EditFields {
                                        rule_id,
                                        fields,
                                        cursor,
                                        editing_text: None,
                                    };
                                }
                                FieldKind::Feedback(fb) => {
                                    *fb = match fb {
                                        FeedbackFrequency::Never => FeedbackFrequency::OnceADay,
                                        FeedbackFrequency::OnceADay => FeedbackFrequency::OnceAWeek,
                                        FeedbackFrequency::OnceAWeek => FeedbackFrequency::Always,
                                        FeedbackFrequency::Always => FeedbackFrequency::Auto,
                                        FeedbackFrequency::Auto => FeedbackFrequency::Never,
                                    };
                                    apply_fields_to_config(&mut self.cfg, &rule_id, &fields);
                                    self.config_dirty = true;
                                    self.refresh_check(ops, rules)?;
                                    self.modal = Modal::EditFields {
                                        rule_id,
                                        fields,
                                        cursor,
                                        editing_text: None,
                                    };
                                }
                                FieldKind::PowerAct(pa) => {
                                    *pa = match pa {
                                        PowerAction::Nothing => PowerAction::Sleep,
                                        PowerAction::Sleep => PowerAction::Hibernate,
                                        PowerAction::Hibernate => PowerAction::Shutdown,
                                        PowerAction::Shutdown => PowerAction::Nothing,
                                    };
                                    apply_fields_to_config(&mut self.cfg, &rule_id, &fields);
                                    self.config_dirty = true;
                                    self.refresh_check(ops, rules)?;
                                    self.modal = Modal::EditFields {
                                        rule_id,
                                        fields,
                                        cursor,
                                        editing_text: None,
                                    };
                                }
                                FieldKind::Text(s) => {
                                    let seed = s.clone();
                                    self.modal = Modal::EditFields {
                                        rule_id,
                                        fields,
                                        cursor,
                                        editing_text: Some(seed),
                                    };
                                }
                                FieldKind::U32(n) => {
                                    let seed = n.to_string();
                                    self.modal = Modal::EditFields {
                                        rule_id,
                                        fields,
                                        cursor,
                                        editing_text: Some(seed),
                                    };
                                }
                            }
                        }
                    }
                    _ => {
                        self.modal = Modal::EditFields {
                            rule_id,
                            fields,
                            cursor,
                            editing_text: None,
                        };
                    }
                }
                Ok(TuiEffect::Continue)
            }
            Modal::UserPicker {
                users,
                mut cursor,
                mut create_name,
                mut temp_password,
                mut clear_dont_expire,
                mut focus,
                mut typing,
            } => {
                if typing {
                    match code {
                        KeyCode::Esc | KeyCode::Enter => typing = false,
                        KeyCode::Backspace => {
                            if focus == UserPickerFocus::NewUsername {
                                create_name.pop();
                            } else if focus == UserPickerFocus::TempPassword {
                                temp_password.pop();
                            }
                        }
                        KeyCode::Char(c) => {
                            if focus == UserPickerFocus::NewUsername {
                                create_name.push(c);
                            } else if focus == UserPickerFocus::TempPassword {
                                temp_password.push(c);
                            }
                        }
                        _ => {}
                    }
                    self.modal = Modal::UserPicker {
                        users,
                        cursor,
                        create_name,
                        temp_password,
                        clear_dont_expire,
                        focus,
                        typing,
                    };
                    return Ok(TuiEffect::Continue);
                }

                match code {
                    KeyCode::Esc => {}
                    KeyCode::Tab => {
                        focus = match focus {
                            UserPickerFocus::ExistingList => UserPickerFocus::NewUsername,
                            UserPickerFocus::NewUsername => UserPickerFocus::TempPassword,
                            UserPickerFocus::TempPassword => UserPickerFocus::ClearDontExpire,
                            UserPickerFocus::ClearDontExpire => UserPickerFocus::ExistingList,
                        };
                        self.modal = Modal::UserPicker {
                            users,
                            cursor,
                            create_name,
                            temp_password,
                            clear_dont_expire,
                            focus,
                            typing: false,
                        };
                    }
                    KeyCode::Up | KeyCode::Char('k') if focus == UserPickerFocus::ExistingList => {
                        cursor = cursor.saturating_sub(1);
                        self.modal = Modal::UserPicker {
                            users,
                            cursor,
                            create_name,
                            temp_password,
                            clear_dont_expire,
                            focus,
                            typing: false,
                        };
                    }
                    KeyCode::Down | KeyCode::Char('j')
                        if focus == UserPickerFocus::ExistingList =>
                    {
                        if cursor + 1 < users.len() {
                            cursor += 1;
                        }
                        self.modal = Modal::UserPicker {
                            users,
                            cursor,
                            create_name,
                            temp_password,
                            clear_dont_expire,
                            focus,
                            typing: false,
                        };
                    }
                    KeyCode::Char(' ') if focus == UserPickerFocus::ClearDontExpire => {
                        clear_dont_expire = !clear_dont_expire;
                        self.modal = Modal::UserPicker {
                            users,
                            cursor,
                            create_name,
                            temp_password,
                            clear_dont_expire,
                            focus,
                            typing: false,
                        };
                    }
                    KeyCode::Char('c') => {
                        self.user_target = None;
                        self.status_banner = "Cleared opt-in user target.".into();
                    }
                    KeyCode::Enter => {
                        if matches!(
                            focus,
                            UserPickerFocus::NewUsername | UserPickerFocus::TempPassword
                        ) {
                            typing = true;
                            self.modal = Modal::UserPicker {
                                users,
                                cursor,
                                create_name,
                                temp_password,
                                clear_dont_expire,
                                focus,
                                typing,
                            };
                        } else {
                            let pw_opt = if temp_password.is_empty() {
                                None
                            } else {
                                Some(temp_password.clone())
                            };
                            if !create_name.trim().is_empty() {
                                if pw_opt.is_none() {
                                    self.status_banner =
                                        "New user requires non-empty temporary password.".into();
                                    self.modal = Modal::UserPicker {
                                        users,
                                        cursor,
                                        create_name,
                                        temp_password,
                                        clear_dont_expire,
                                        focus: UserPickerFocus::TempPassword,
                                        typing: false,
                                    };
                                    return Ok(TuiEffect::Continue);
                                }
                                self.user_target = Some(UserTargetOptions {
                                    username: create_name.trim().to_string(),
                                    create_if_missing: true,
                                    clear_dont_expire,
                                    temp_password: pw_opt,
                                });
                                self.status_banner =
                                    format!("User target: create '{}'", create_name.trim());
                            } else if let Some(u) = users.get(cursor) {
                                self.user_target = Some(UserTargetOptions {
                                    username: u.name.clone(),
                                    create_if_missing: false,
                                    clear_dont_expire,
                                    temp_password: pw_opt,
                                });
                                self.status_banner = format!("User target: '{}'", u.name);
                            }
                        }
                    }
                    _ => {
                        self.modal = Modal::UserPicker {
                            users,
                            cursor,
                            create_name,
                            temp_password,
                            clear_dont_expire,
                            focus,
                            typing: false,
                        };
                    }
                }
                Ok(TuiEffect::Continue)
            }
            Modal::ConfirmApply => match code {
                KeyCode::Enter | KeyCode::Char('y') => {
                    self.execute_apply(ops, rules, false)?;
                    Ok(TuiEffect::Continue)
                }
                KeyCode::Esc | KeyCode::Char('n') => Ok(TuiEffect::Continue),
                _ => {
                    self.modal = Modal::ConfirmApply;
                    Ok(TuiEffect::Continue)
                }
            },
            Modal::ElevationPrompt => match code {
                KeyCode::Char('e') | KeyCode::Char('E') | KeyCode::Enter => {
                    if self.config_dirty {
                        let _ = self.cfg.save_toml(&self.config_path);
                    }
                    ops.relaunch_as_admin(&self.relaunch_args)?;
                    Ok(TuiEffect::Quit(0))
                }
                KeyCode::Char('o') | KeyCode::Char('O') => {
                    let hkcu_only: Vec<String> = rules
                        .iter()
                        .filter(|r| !r.requires_admin() && r.is_enabled(&self.cfg))
                        .map(|r| r.id().to_string())
                        .collect();
                    let opts = ApplyOptions {
                        only: hkcu_only,
                        user_target: None,
                        ..Default::default()
                    };
                    let report = apply_rules(ops, &self.cfg, rules, &opts, &self.exe_dir)?;
                    self.show_run_report("Apply (HKCU-Only)", &report);
                    self.refresh_check(ops, rules)?;
                    Ok(TuiEffect::Continue)
                }
                KeyCode::Esc => Ok(TuiEffect::Continue),
                _ => {
                    self.modal = Modal::ElevationPrompt;
                    Ok(TuiEffect::Continue)
                }
            },
            Modal::RollbackPicker { files, mut cursor } => match code {
                KeyCode::Esc => Ok(TuiEffect::Continue),
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    self.modal = Modal::RollbackPicker { files, cursor };
                    Ok(TuiEffect::Continue)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if cursor + 1 < files.len() {
                        cursor += 1;
                    }
                    self.modal = Modal::RollbackPicker { files, cursor };
                    Ok(TuiEffect::Continue)
                }
                KeyCode::Enter => {
                    if let Some(path) = files.get(cursor) {
                        let snap = BackupSnapshot::load_from_file(path)?;
                        let actions = rollback_snapshot(ops, &snap)?;
                        self.modal = Modal::ReportView {
                            title: format!("Rollback: {}", path.display()),
                            lines: actions,
                            scroll: 0,
                        };
                        self.refresh_check(ops, rules)?;
                    }
                    Ok(TuiEffect::Continue)
                }
                _ => {
                    self.modal = Modal::RollbackPicker { files, cursor };
                    Ok(TuiEffect::Continue)
                }
            },
            Modal::ReportView {
                title,
                lines,
                mut scroll,
            } => match code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => Ok(TuiEffect::Continue),
                KeyCode::Up | KeyCode::Char('k') => {
                    scroll = scroll.saturating_sub(1);
                    self.modal = Modal::ReportView {
                        title,
                        lines,
                        scroll,
                    };
                    Ok(TuiEffect::Continue)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if (scroll as usize) + 1 < lines.len() {
                        scroll += 1;
                    }
                    self.modal = Modal::ReportView {
                        title,
                        lines,
                        scroll,
                    };
                    Ok(TuiEffect::Continue)
                }
                _ => {
                    self.modal = Modal::ReportView {
                        title,
                        lines,
                        scroll,
                    };
                    Ok(TuiEffect::Continue)
                }
            },
        }
    }

    fn handle_main_key(
        &mut self,
        code: KeyCode,
        ops: &dyn SystemOps,
        rules: &[Box<dyn Rule>],
    ) -> Result<TuiEffect> {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(TuiEffect::Quit(0)),
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_idx = self.selected_idx.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_idx + 1 < rules.len() {
                    self.selected_idx += 1;
                }
            }
            KeyCode::Char(' ') => {
                if let Some(id) = self.current_rule_id(rules).map(str::to_string) {
                    toggle_rule_enabled(&mut self.cfg, &id);
                    self.config_dirty = true;
                    self.refresh_check(ops, rules)?;
                    self.status_banner = format!(
                        "Toggled '{id}' enabled={}.",
                        is_rule_enabled(&self.cfg, &id)
                    );
                }
            }
            KeyCode::Char('e') | KeyCode::Enter => {
                if let Some(id) = self.current_rule_id(rules).map(str::to_string) {
                    let fields = fields_for_rule(&self.cfg, &id);
                    self.modal = Modal::EditFields {
                        rule_id: id,
                        fields,
                        cursor: 0,
                        editing_text: None,
                    };
                }
            }
            KeyCode::Char('u') => {
                let users = ops.list_local_users().unwrap_or_default();
                self.modal = Modal::UserPicker {
                    users,
                    cursor: 0,
                    create_name: String::new(),
                    temp_password: String::new(),
                    clear_dont_expire: true,
                    focus: UserPickerFocus::ExistingList,
                    typing: false,
                };
            }
            KeyCode::Char('s') => {
                self.cfg.validate()?;
                self.cfg.save_toml(&self.config_path)?;
                self.config_dirty = false;
                self.status_banner = format!("Saved config to {}", self.config_path.display());
            }
            KeyCode::Char('r') => {
                self.refresh_check(ops, rules)?;
                self.status_banner = "Compliance check refreshed.".into();
            }
            KeyCode::Char('p') => {
                let opts = ApplyOptions {
                    dry_run: true,
                    user_target: self.user_target.clone(),
                    ..Default::default()
                };
                let rep = apply_rules(ops, &self.cfg, rules, &opts, &self.exe_dir)?;
                self.show_run_report("Dry-Run Diff Preview", &rep);
            }
            KeyCode::Char('a') => {
                let needs_admin = rules
                    .iter()
                    .any(|r| r.requires_admin() && r.is_enabled(&self.cfg));
                if needs_admin && !ops.is_admin() {
                    self.modal = Modal::ElevationPrompt;
                } else {
                    self.modal = Modal::ConfirmApply;
                }
            }
            KeyCode::Char('b') => {
                let files = list_backup_files(&self.exe_dir)?;
                if files.is_empty() {
                    self.status_banner = "No it-tools.backup.*.json files found beside exe.".into();
                } else {
                    self.modal = Modal::RollbackPicker { files, cursor: 0 };
                }
            }
            KeyCode::Char('v') => {
                self.check_updates_modal(ops);
            }
            _ => {}
        }
        Ok(TuiEffect::Continue)
    }

    fn check_updates_modal(&mut self, ops: &dyn SystemOps) {
        let cur = current_display_version();
        let ch = if self.cfg.update.allow_beta || current_channel() == UpdateChannel::Beta {
            UpdateChannel::Beta
        } else {
            UpdateChannel::Stable
        };
        let Some(repo) = self
            .cfg
            .update
            .repo
            .as_deref()
            .or(default_github_repo())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
        else {
            self.modal = Modal::ReportView {
                title: "Version & Updates".into(),
                lines: vec![
                    format!("Installed Version : {cur}"),
                    format!("Release Channel   : {ch}"),
                    String::new(),
                    "No GitHub repository configured in this build.".into(),
                    "Set [update] repo = \"owner/repo\" in it-tools.toml or run:".into(),
                    "  it-tools update --check --repo owner/repo".into(),
                ],
                scroll: 0,
            };
            return;
        };

        match check_for_update(ops, &repo, ch) {
            Ok(res) => {
                let mut lines = vec![
                    format!("Repository        : {repo}"),
                    format!("Installed Version : {}", res.current_version),
                    format!("Latest ({:<6})   : {}", res.channel, res.latest_version),
                    format!(
                        "Status            : {}",
                        if res.update_available {
                            "UPDATE AVAILABLE (run `it-tools update` in terminal)"
                        } else {
                            "UP TO DATE"
                        }
                    ),
                ];
                if !res.html_url.is_empty() {
                    lines.push(format!("URL               : {}", res.html_url));
                }
                if !res.release_notes.trim().is_empty() {
                    lines.push(String::new());
                    lines.push("--- Release Notes ---".into());
                    lines.extend(res.release_notes.lines().map(str::to_string));
                }
                self.modal = Modal::ReportView {
                    title: "Version & Updates".into(),
                    lines,
                    scroll: 0,
                };
            }
            Err(e) => {
                self.modal = Modal::ReportView {
                    title: "Version & Updates (Check Failed)".into(),
                    lines: vec![
                        format!("Installed Version : {cur}"),
                        format!("Repository        : {repo}"),
                        format!("Error             : {e:#}"),
                    ],
                    scroll: 0,
                };
            }
        }
    }

    fn execute_apply(
        &mut self,
        ops: &dyn SystemOps,
        rules: &[Box<dyn Rule>],
        dry_run: bool,
    ) -> Result<()> {
        let opts = ApplyOptions {
            dry_run,
            user_target: self.user_target.clone(),
            ..Default::default()
        };
        let rep = apply_rules(ops, &self.cfg, rules, &opts, &self.exe_dir)?;
        self.show_run_report("Apply Results", &rep);
        self.refresh_check(ops, rules)?;
        Ok(())
    }

    fn show_run_report(&mut self, title: &str, rep: &RunReport) {
        let mut lines = Vec::new();
        if let Some(bk) = &rep.backup_file {
            lines.push(format!("Backup saved: {}", bk.display()));
            lines.push(String::new());
        }
        for e in &rep.entries {
            let tag = match &e.outcome {
                RuleOutcome::Applied => "APPLIED".into(),
                RuleOutcome::AlreadyCompliant => "COMPLIANT".into(),
                RuleOutcome::WarnTamperProtected { detail } => format!("WARN TAMPER: {detail}"),
                RuleOutcome::WarnFirmwareLocked { detail } => format!("WARN FIRMWARE: {detail}"),
                RuleOutcome::WarnEdgeRunning { detail } => format!("WARN EDGE: {detail}"),
                RuleOutcome::Skipped { reason } => format!("SKIPPED: {reason}"),
                RuleOutcome::Failed { error } => format!("FAILED: {error}"),
            };
            lines.push(format!("[{}] {}", e.id, tag));
            for c in &e.changes {
                lines.push(format!("   * {c}"));
            }
        }
        self.modal = Modal::ReportView {
            title: title.to_string(),
            lines,
            scroll: 0,
        };
    }

    fn check_for(&self, id: &str) -> Option<&RuleCheck> {
        self.check_report.checks.iter().find(|c| c.id == id)
    }
}

pub fn run_tui(
    ops: &dyn SystemOps,
    rules: &[Box<dyn Rule>],
    cfg: ProfileConfig,
    config_path: PathBuf,
    exe_dir: PathBuf,
    relaunch_args: Vec<String>,
) -> Result<i32> {
    if !ops.is_console_tty() {
        eprintln!(
            "TUI requires Windows Console / Windows Terminal. Use CLI subcommands (check, apply, rollback, config) or run via winpty / Windows Terminal."
        );
        return Ok(EXIT_NO_CONSOLE);
    }

    let mut app = TuiApp::new(ops, rules, cfg, config_path, exe_dir, relaunch_args)?;
    let mut terminal = ratatui::try_init()?;
    let res = tui_event_loop(&mut terminal, &mut app, ops, rules);
    let _ = ratatui::try_restore();
    res
}

fn tui_event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut TuiApp,
    ops: &dyn SystemOps,
    rules: &[Box<dyn Rule>],
) -> Result<i32> {
    loop {
        terminal.draw(|frame| draw_ui(frame, app, rules))?;
        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && let TuiEffect::Quit(code) = app.handle_key(key.code, ops, rules)?
        {
            return Ok(code);
        }
    }
}

fn draw_ui(frame: &mut ratatui::Frame, app: &TuiApp, rules: &[Box<dyn Rule>]) {
    let area = frame.area();
    let show_ascii = area.height >= 22 && area.width >= crate::APP_BANNER_WIDTH as u16;
    let (header_area, body_area, footer_area) = if show_ascii {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(9),
                Constraint::Length(3),
                Constraint::Min(7),
                Constraint::Length(3),
            ])
            .split(area);
        let banner = Paragraph::new(crate::APP_BANNER)
            .alignment(Alignment::Center)
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );
        frame.render_widget(banner, chunks[0]);
        (chunks[1], chunks[2], chunks[3])
    } else {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(3),
            ])
            .split(area);
        (chunks[0], chunks[1], chunks[2])
    };

    let admin_badge = if app.check_report.is_admin {
        Span::styled(
            " ADMIN ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " STANDARD USER ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    };
    let dirty_mark = if app.config_dirty { " [UNSAVED *]" } else { "" };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" IT-Tools v{} ", current_display_version()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        admin_badge,
        Span::raw(format!(
            "  {}  |  Config: {}{}",
            app.check_report.os_caption,
            app.config_path.display(),
            dirty_mark
        )),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("System & Profile"),
    );
    frame.render_widget(header, header_area);

    let main_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(44), Constraint::Percentage(56)])
        .split(body_area);

    let items: Vec<ListItem> = rules
        .iter()
        .map(|r| {
            let enabled = is_rule_enabled(&app.cfg, r.id());
            let mark = if enabled { "[x]" } else { "[ ]" };
            let status_span = if !enabled {
                Span::styled("DISABLED", Style::default().fg(Color::DarkGray))
            } else if let Some(chk) = app.check_for(r.id()) {
                match chk.status {
                    CheckStatus::Compliant => Span::styled("OK", Style::default().fg(Color::Green)),
                    CheckStatus::Drifted => {
                        Span::styled("DRIFT", Style::default().fg(Color::Yellow))
                    }
                    CheckStatus::NeedsAdmin => {
                        Span::styled("ADMIN", Style::default().fg(Color::Red))
                    }
                    CheckStatus::Unsupported => {
                        Span::styled("WARN", Style::default().fg(Color::Magenta))
                    }
                }
            } else {
                Span::raw("-")
            };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{mark} {:<19} ", r.id())),
                status_span,
            ]))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(app.selected_idx));
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Hardening Modules (13)"),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(list, main_cols[0], &mut state);

    let mut detail_lines = Vec::new();
    if let Some(r) = rules.get(app.selected_idx) {
        detail_lines.push(Line::from(Span::styled(
            format!("{} ({})", r.title(), r.id()),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        detail_lines.push(Line::from(format!(
            "Scope: {} | Enabled: {}",
            if r.requires_admin() {
                "Admin (HKLM/System)"
            } else {
                "Standard (HKCU)"
            },
            is_rule_enabled(&app.cfg, r.id())
        )));
        if let Some(ut) = &app.user_target {
            detail_lines.push(Line::from(format!(
                "Opt-In User Target: {} ({})",
                ut.username,
                if ut.create_if_missing {
                    "create"
                } else {
                    "existing"
                }
            )));
        }
        detail_lines.push(Line::from(""));
        detail_lines.push(Line::from(Span::styled(
            "Current Diffs:",
            Style::default().fg(Color::Cyan),
        )));
        if let Some(chk) = app.check_for(r.id()) {
            if chk.diffs.is_empty() {
                detail_lines.push(Line::from("  (none - compliant)"));
            } else {
                for d in &chk.diffs {
                    detail_lines.push(Line::from(format!(
                        "  - {}: {} -> {}",
                        d.field, d.current, d.target
                    )));
                }
            }
            if let Some(note) = &chk.note {
                detail_lines.push(Line::from(format!("Note: {note}")));
            }
        } else {
            detail_lines.push(Line::from("  (rule disabled in config)"));
        }
    }
    let detail = Paragraph::new(detail_lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Module Inspector"),
        );
    frame.render_widget(detail, main_cols[1]);

    let footer = Paragraph::new(app.status_banner.as_str())
        .block(Block::default().borders(Borders::ALL).title("Controls"));
    frame.render_widget(footer, footer_area);

    draw_modal(frame, app);
}

fn draw_modal(frame: &mut ratatui::Frame, app: &TuiApp) {
    match &app.modal {
        Modal::None => {}
        Modal::ConfirmApply => {
            let area = centered_rect(60, 30, frame.area());
            frame.render_widget(Clear, area);
            let p = Paragraph::new(
                "Create automatic JSON backup snapshot beside exe and apply enabled rules?\n\n[Enter / y] Apply Now    [Esc / n] Cancel",
            )
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title("Confirm Apply"));
            frame.render_widget(p, area);
        }
        Modal::ElevationPrompt => {
            let area = centered_rect(65, 36, frame.area());
            frame.render_widget(Clear, area);
            let p = Paragraph::new(
                "One or more selected rules modify HKLM / Windows policies and require Administrator privileges.\n\n[E] Relaunch as Administrator (UAC)\n[O] Apply HKCU-only User Rules Now\n[Esc] Cancel",
            )
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title("Elevation Required"));
            frame.render_widget(p, area);
        }
        Modal::EditFields {
            rule_id,
            fields,
            cursor,
            editing_text,
        } => {
            let area = centered_rect(70, 65, frame.area());
            frame.render_widget(Clear, area);
            let items: Vec<ListItem> = fields
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    let val_str = if i == *cursor {
                        if let Some(buf) = editing_text {
                            format!("{buf}_")
                        } else {
                            format_field_value(&f.kind)
                        }
                    } else {
                        format_field_value(&f.kind)
                    };
                    ListItem::new(format!("{:<28} = {}", f.label, val_str))
                })
                .collect();
            let mut st = ListState::default();
            st.select(Some(*cursor));
            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!("Edit {rule_id} ([Space/Enter] edit, [Esc] close)")),
                )
                .highlight_style(Style::default().bg(Color::Blue).fg(Color::White));
            frame.render_stateful_widget(list, area, &mut st);
        }
        Modal::UserPicker {
            users,
            cursor,
            create_name,
            temp_password,
            clear_dont_expire,
            focus,
            typing,
        } => {
            let area = centered_rect(72, 70, frame.area());
            frame.render_widget(Clear, area);
            let mut lines = vec![
                Line::from(
                    "Opt-in local account selection ([Tab] cycle field, [Enter] select/edit, [c] clear, [Esc] close):",
                ),
                Line::from(""),
                Line::from(format!(
                    "{} New Username: {}{}",
                    if *focus == UserPickerFocus::NewUsername {
                        ">"
                    } else {
                        " "
                    },
                    create_name,
                    if *typing && *focus == UserPickerFocus::NewUsername {
                        "_"
                    } else {
                        ""
                    }
                )),
                Line::from(format!(
                    "{} Temp Password (RAM only): {}{}",
                    if *focus == UserPickerFocus::TempPassword {
                        ">"
                    } else {
                        " "
                    },
                    "*".repeat(temp_password.len()),
                    if *typing && *focus == UserPickerFocus::TempPassword {
                        "_"
                    } else {
                        ""
                    }
                )),
                Line::from(format!(
                    "{} Clear PasswordNeverExpires ([Space]): {}",
                    if *focus == UserPickerFocus::ClearDontExpire {
                        ">"
                    } else {
                        " "
                    },
                    clear_dont_expire
                )),
                Line::from(""),
                Line::from(format!(
                    "{} Existing Local Users:",
                    if *focus == UserPickerFocus::ExistingList {
                        ">"
                    } else {
                        " "
                    }
                )),
            ];
            for (idx, u) in users.iter().enumerate() {
                let mark = if idx == *cursor { "*" } else { " " };
                lines.push(Line::from(format!(
                    "  {mark} {} (disabled={}, never_expires={})",
                    u.name, u.disabled, u.dont_expire_password
                )));
            }
            let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Local Account & Temp Password"),
            );
            frame.render_widget(p, area);
        }
        Modal::RollbackPicker { files, cursor } => {
            let area = centered_rect(70, 50, frame.area());
            frame.render_widget(Clear, area);
            let items: Vec<ListItem> = files
                .iter()
                .map(|p| {
                    ListItem::new(
                        p.file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned(),
                    )
                })
                .collect();
            let mut st = ListState::default();
            st.select(Some(*cursor));
            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Rollback Backup ([Enter] restore, [Esc] cancel)"),
                )
                .highlight_style(Style::default().bg(Color::Blue).fg(Color::White));
            frame.render_stateful_widget(list, area, &mut st);
        }
        Modal::ReportView {
            title,
            lines,
            scroll,
        } => {
            let area = centered_rect(82, 78, frame.area());
            frame.render_widget(Clear, area);
            let text: Vec<Line> = lines.iter().map(|s| Line::from(s.as_str())).collect();
            let p = Paragraph::new(text)
                .scroll((*scroll, 0))
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!("{title} ([j/k] scroll, [Esc] close)")),
                );
            frame.render_widget(p, area);
        }
    }
}

fn centered_rect(pct_x: u16, pct_y: u16, r: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(v[1])[1]
}

fn check_all(
    ops: &dyn SystemOps,
    cfg: &ProfileConfig,
    rules: &[Box<dyn Rule>],
) -> Result<CheckReport> {
    let all_ids: Vec<String> = rules.iter().map(|r| r.id().to_string()).collect();
    check_rules(ops, cfg, rules, &all_ids, &[])
}

pub fn is_rule_enabled(cfg: &ProfileConfig, id: &str) -> bool {
    match id {
        "visual_effects" => cfg.rules.visual_effects.enabled,
        "diagnostics" => cfg.rules.diagnostics.enabled,
        "search" => cfg.rules.search.enabled,
        "typing" => cfg.rules.typing.enabled,
        "taskbar" => cfg.rules.taskbar.enabled,
        "power" => cfg.rules.power.enabled,
        "screensaver" => cfg.rules.screensaver.enabled,
        "accessibility" => cfg.rules.accessibility.enabled,
        "edge" => cfg.rules.edge.enabled,
        "system_restore" => cfg.rules.system_restore.enabled,
        "password_policy" => cfg.rules.password_policy.enabled,
        "defender_firewall" => cfg.rules.defender_firewall.enabled,
        "startup_apps" => cfg.rules.startup_apps.enabled,
        _ => false,
    }
}

pub fn toggle_rule_enabled(cfg: &mut ProfileConfig, id: &str) {
    match id {
        "visual_effects" => cfg.rules.visual_effects.enabled = !cfg.rules.visual_effects.enabled,
        "diagnostics" => cfg.rules.diagnostics.enabled = !cfg.rules.diagnostics.enabled,
        "search" => cfg.rules.search.enabled = !cfg.rules.search.enabled,
        "typing" => cfg.rules.typing.enabled = !cfg.rules.typing.enabled,
        "taskbar" => cfg.rules.taskbar.enabled = !cfg.rules.taskbar.enabled,
        "power" => cfg.rules.power.enabled = !cfg.rules.power.enabled,
        "screensaver" => cfg.rules.screensaver.enabled = !cfg.rules.screensaver.enabled,
        "accessibility" => cfg.rules.accessibility.enabled = !cfg.rules.accessibility.enabled,
        "edge" => cfg.rules.edge.enabled = !cfg.rules.edge.enabled,
        "system_restore" => cfg.rules.system_restore.enabled = !cfg.rules.system_restore.enabled,
        "password_policy" => cfg.rules.password_policy.enabled = !cfg.rules.password_policy.enabled,
        "defender_firewall" => {
            cfg.rules.defender_firewall.enabled = !cfg.rules.defender_firewall.enabled
        }
        "startup_apps" => cfg.rules.startup_apps.enabled = !cfg.rules.startup_apps.enabled,
        _ => {}
    }
}

fn format_field_value(kind: &FieldKind) -> String {
    match kind {
        FieldKind::Bool(b) => b.to_string(),
        FieldKind::Text(s) => s.clone(),
        FieldKind::U32(n) => n.to_string(),
        FieldKind::Alignment(a) => format!("{a:?}"),
        FieldKind::Feedback(f) => format!("{f:?}"),
        FieldKind::PowerAct(p) => format!("{p:?}"),
    }
}

fn apply_text_to_field(f: &mut EditableField, text: &str) {
    match &mut f.kind {
        FieldKind::Text(s) => *s = text.trim().to_string(),
        FieldKind::U32(n) => {
            if let Ok(parsed) = text.trim().parse::<u32>() {
                *n = parsed;
            }
        }
        _ => {}
    }
}

fn fields_for_rule(cfg: &ProfileConfig, id: &str) -> Vec<EditableField> {
    let r = &cfg.rules;
    match id {
        "visual_effects" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.visual_effects.enabled),
            },
            EditableField {
                key: "animations",
                label: "Animations",
                kind: FieldKind::Bool(r.visual_effects.animations),
            },
            EditableField {
                key: "transparency",
                label: "Transparency",
                kind: FieldKind::Bool(r.visual_effects.transparency),
            },
        ],
        "diagnostics" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.diagnostics.enabled),
            },
            EditableField {
                key: "optional_data",
                label: "Optional Data",
                kind: FieldKind::Bool(r.diagnostics.optional_data),
            },
            EditableField {
                key: "feedback",
                label: "Feedback Frequency",
                kind: FieldKind::Feedback(r.diagnostics.feedback_frequency),
            },
        ],
        "search" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.search.enabled),
            },
            EditableField {
                key: "msa",
                label: "MSA Cloud Search",
                kind: FieldKind::Bool(r.search.msa_cloud_search),
            },
            EditableField {
                key: "aad",
                label: "Work/School Search",
                kind: FieldKind::Bool(r.search.work_school_search),
            },
            EditableField {
                key: "highlights",
                label: "Search Highlights",
                kind: FieldKind::Bool(r.search.search_highlights),
            },
        ],
        "typing" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.typing.enabled),
            },
            EditableField {
                key: "autocorrect",
                label: "Autocorrect",
                kind: FieldKind::Bool(r.typing.autocorrect),
            },
            EditableField {
                key: "highlight",
                label: "Highlight Misspelled",
                kind: FieldKind::Bool(r.typing.highlight_misspelled),
            },
            EditableField {
                key: "prediction",
                label: "Text Prediction",
                kind: FieldKind::Bool(r.typing.text_prediction),
            },
            EditableField {
                key: "insights",
                label: "Typing Insights",
                kind: FieldKind::Bool(r.typing.typing_insights),
            },
            EditableField {
                key: "voice",
                label: "Voice Typing Key",
                kind: FieldKind::Bool(r.typing.voice_typing_key),
            },
            EditableField {
                key: "multi",
                label: "Multilingual",
                kind: FieldKind::Bool(r.typing.multilingual),
            },
            EditableField {
                key: "shift",
                label: "Auto Shift",
                kind: FieldKind::Bool(r.typing.auto_shift),
            },
            EditableField {
                key: "space",
                label: "Double-tap Space",
                kind: FieldKind::Bool(r.typing.double_tap_space),
            },
        ],
        "taskbar" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.taskbar.enabled),
            },
            EditableField {
                key: "widgets",
                label: "Widgets",
                kind: FieldKind::Bool(r.taskbar.widgets),
            },
            EditableField {
                key: "alignment",
                label: "Alignment",
                kind: FieldKind::Alignment(r.taskbar.alignment),
            },
            EditableField {
                key: "auto_hide",
                label: "Auto-hide",
                kind: FieldKind::Bool(r.taskbar.auto_hide),
            },
            EditableField {
                key: "badges",
                label: "Show Badges",
                kind: FieldKind::Bool(r.taskbar.show_badges),
            },
            EditableField {
                key: "flashing",
                label: "Show Flashing",
                kind: FieldKind::Bool(r.taskbar.show_flashing),
            },
        ],
        "power" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.power.enabled),
            },
            EditableField {
                key: "hibernate",
                label: "Hibernate",
                kind: FieldKind::Bool(r.power.hibernate),
            },
            EditableField {
                key: "scheme",
                label: "Scheme",
                kind: FieldKind::Text(r.power.scheme.clone()),
            },
            EditableField {
                key: "min_cpu_ac",
                label: "Min CPU AC %",
                kind: FieldKind::U32(r.power.min_cpu_ac_pct.into()),
            },
            EditableField {
                key: "min_cpu_dc",
                label: "Min CPU DC %",
                kind: FieldKind::U32(r.power.min_cpu_dc_pct.into()),
            },
            EditableField {
                key: "pbtn_ac",
                label: "Power Button AC",
                kind: FieldKind::PowerAct(r.power.power_button_ac),
            },
            EditableField {
                key: "lid_ac",
                label: "Lid Close AC",
                kind: FieldKind::PowerAct(r.power.lid_close_ac),
            },
            EditableField {
                key: "disp_ac",
                label: "Display AC (min)",
                kind: FieldKind::U32(r.power.display_timeout_ac_min),
            },
            EditableField {
                key: "disp_dc",
                label: "Display DC (min)",
                kind: FieldKind::U32(r.power.display_timeout_dc_min),
            },
            EditableField {
                key: "sleep_ac",
                label: "Sleep AC (min)",
                kind: FieldKind::U32(r.power.sleep_timeout_ac_min),
            },
            EditableField {
                key: "sleep_dc",
                label: "Sleep DC (min)",
                kind: FieldKind::U32(r.power.sleep_timeout_dc_min),
            },
        ],
        "screensaver" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.screensaver.enabled),
            },
            EditableField {
                key: "active",
                label: "Active",
                kind: FieldKind::Bool(r.screensaver.active),
            },
            EditableField {
                key: "scr_exe",
                label: "SCR Executable",
                kind: FieldKind::Text(r.screensaver.scr_exe.clone()),
            },
            EditableField {
                key: "timeout",
                label: "Timeout (sec)",
                kind: FieldKind::U32(r.screensaver.timeout_sec),
            },
            EditableField {
                key: "logon",
                label: "Require Logon",
                kind: FieldKind::Bool(r.screensaver.require_logon),
            },
        ],
        "accessibility" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.accessibility.enabled),
            },
            EditableField {
                key: "snipping",
                label: "PrintScreen Snipping",
                kind: FieldKind::Bool(r.accessibility.printscreen_snipping),
            },
        ],
        "edge" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.edge.enabled),
            },
            EditableField {
                key: "ntp",
                label: "Preload New Tab",
                kind: FieldKind::Bool(r.edge.preload_new_tab),
            },
            EditableField {
                key: "startup",
                label: "Prelaunch Startup",
                kind: FieldKind::Bool(r.edge.prelaunch_startup),
            },
            EditableField {
                key: "tab",
                label: "Tab Preloading",
                kind: FieldKind::Bool(r.edge.tab_preloading),
            },
            EditableField {
                key: "pua",
                label: "Block PUA",
                kind: FieldKind::Bool(r.edge.block_pua),
            },
        ],
        "system_restore" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.system_restore.enabled),
            },
            EditableField {
                key: "drive",
                label: "Drive",
                kind: FieldKind::Text(r.system_restore.drive.clone()),
            },
            EditableField {
                key: "enable",
                label: "Enable Protection",
                kind: FieldKind::Bool(r.system_restore.enable),
            },
            EditableField {
                key: "max_size",
                label: "Max Size",
                kind: FieldKind::Text(r.system_restore.max_size.clone()),
            },
        ],
        "password_policy" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.password_policy.enabled),
            },
            EditableField {
                key: "history",
                label: "Password History",
                kind: FieldKind::U32(r.password_policy.password_history.into()),
            },
            EditableField {
                key: "max_age",
                label: "Max Age (days)",
                kind: FieldKind::U32(r.password_policy.max_password_age_days.into()),
            },
            EditableField {
                key: "min_len",
                label: "Min Length",
                kind: FieldKind::U32(r.password_policy.min_password_length.into()),
            },
            EditableField {
                key: "complex",
                label: "Complexity",
                kind: FieldKind::Bool(r.password_policy.complexity_enabled),
            },
            EditableField {
                key: "lock_thr",
                label: "Lockout Threshold",
                kind: FieldKind::U32(r.password_policy.lockout_threshold.into()),
            },
            EditableField {
                key: "lock_dur",
                label: "Lockout Duration",
                kind: FieldKind::U32(r.password_policy.lockout_duration_min),
            },
            EditableField {
                key: "lock_rst",
                label: "Lockout Reset",
                kind: FieldKind::U32(r.password_policy.lockout_reset_min),
            },
            EditableField {
                key: "adm_lock",
                label: "Allow Admin Lockout",
                kind: FieldKind::Bool(r.password_policy.allow_admin_lockout),
            },
        ],
        "defender_firewall" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.defender_firewall.enabled),
            },
            EditableField {
                key: "headless",
                label: "Headless Defender UI",
                kind: FieldKind::Bool(r.defender_firewall.defender_headless_ui),
            },
            EditableField {
                key: "def_on",
                label: "Defender Enabled",
                kind: FieldKind::Bool(r.defender_firewall.defender_enabled),
            },
            EditableField {
                key: "profiles",
                label: "Profiles (csv)",
                kind: FieldKind::Text(r.defender_firewall.firewall_profiles.join(",")),
            },
            EditableField {
                key: "icmp_echo",
                label: "Allow ICMP Echo",
                kind: FieldKind::Bool(r.defender_firewall.allow_icmp_echo),
            },
            EditableField {
                key: "icmp_rtr",
                label: "Allow ICMP Router",
                kind: FieldKind::Bool(r.defender_firewall.allow_icmp_router),
            },
        ],
        "startup_apps" => vec![
            EditableField {
                key: "enabled",
                label: "Enabled",
                kind: FieldKind::Bool(r.startup_apps.enabled),
            },
            EditableField {
                key: "allowlist",
                label: "Allowlist (csv)",
                kind: FieldKind::Text(r.startup_apps.allowlist.join(",")),
            },
        ],
        _ => Vec::new(),
    }
}

fn apply_fields_to_config(cfg: &mut ProfileConfig, id: &str, fields: &[EditableField]) {
    let get_b = |k: &str| -> Option<bool> {
        fields
            .iter()
            .find(|f| f.key == k)
            .and_then(|f| match f.kind {
                FieldKind::Bool(b) => Some(b),
                _ => None,
            })
    };
    let get_u = |k: &str| -> Option<u32> {
        fields
            .iter()
            .find(|f| f.key == k)
            .and_then(|f| match f.kind {
                FieldKind::U32(n) => Some(n),
                _ => None,
            })
    };
    let get_s = |k: &str| -> Option<String> {
        fields
            .iter()
            .find(|f| f.key == k)
            .and_then(|f| match &f.kind {
                FieldKind::Text(s) => Some(s.clone()),
                _ => None,
            })
    };
    let r = &mut cfg.rules;
    match id {
        "visual_effects" => {
            if let Some(v) = get_b("enabled") {
                r.visual_effects.enabled = v;
            }
            if let Some(v) = get_b("animations") {
                r.visual_effects.animations = v;
            }
            if let Some(v) = get_b("transparency") {
                r.visual_effects.transparency = v;
            }
        }
        "diagnostics" => {
            if let Some(v) = get_b("enabled") {
                r.diagnostics.enabled = v;
            }
            if let Some(v) = get_b("optional_data") {
                r.diagnostics.optional_data = v;
            }
            if let Some(FieldKind::Feedback(fb)) =
                fields.iter().find(|f| f.key == "feedback").map(|f| &f.kind)
            {
                r.diagnostics.feedback_frequency = *fb;
            }
        }
        "search" => {
            if let Some(v) = get_b("enabled") {
                r.search.enabled = v;
            }
            if let Some(v) = get_b("msa") {
                r.search.msa_cloud_search = v;
            }
            if let Some(v) = get_b("aad") {
                r.search.work_school_search = v;
            }
            if let Some(v) = get_b("highlights") {
                r.search.search_highlights = v;
            }
        }
        "typing" => {
            if let Some(v) = get_b("enabled") {
                r.typing.enabled = v;
            }
            if let Some(v) = get_b("autocorrect") {
                r.typing.autocorrect = v;
            }
            if let Some(v) = get_b("highlight") {
                r.typing.highlight_misspelled = v;
            }
            if let Some(v) = get_b("prediction") {
                r.typing.text_prediction = v;
            }
            if let Some(v) = get_b("insights") {
                r.typing.typing_insights = v;
            }
            if let Some(v) = get_b("voice") {
                r.typing.voice_typing_key = v;
            }
            if let Some(v) = get_b("multi") {
                r.typing.multilingual = v;
            }
            if let Some(v) = get_b("shift") {
                r.typing.auto_shift = v;
            }
            if let Some(v) = get_b("space") {
                r.typing.double_tap_space = v;
            }
        }
        "taskbar" => {
            if let Some(v) = get_b("enabled") {
                r.taskbar.enabled = v;
            }
            if let Some(v) = get_b("widgets") {
                r.taskbar.widgets = v;
            }
            if let Some(FieldKind::Alignment(a)) = fields
                .iter()
                .find(|f| f.key == "alignment")
                .map(|f| &f.kind)
            {
                r.taskbar.alignment = *a;
            }
            if let Some(v) = get_b("auto_hide") {
                r.taskbar.auto_hide = v;
            }
            if let Some(v) = get_b("badges") {
                r.taskbar.show_badges = v;
            }
            if let Some(v) = get_b("flashing") {
                r.taskbar.show_flashing = v;
            }
        }
        "power" => {
            if let Some(v) = get_b("enabled") {
                r.power.enabled = v;
            }
            if let Some(v) = get_b("hibernate") {
                r.power.hibernate = v;
            }
            if let Some(s) = get_s("scheme") {
                r.power.scheme = s;
            }
            if let Some(n) = get_u("min_cpu_ac") {
                r.power.min_cpu_ac_pct = n.min(100) as u8;
            }
            if let Some(n) = get_u("min_cpu_dc") {
                r.power.min_cpu_dc_pct = n.min(100) as u8;
            }
            if let Some(FieldKind::PowerAct(p)) =
                fields.iter().find(|f| f.key == "pbtn_ac").map(|f| &f.kind)
            {
                r.power.power_button_ac = *p;
            }
            if let Some(FieldKind::PowerAct(p)) =
                fields.iter().find(|f| f.key == "lid_ac").map(|f| &f.kind)
            {
                r.power.lid_close_ac = *p;
            }
            if let Some(n) = get_u("disp_ac") {
                r.power.display_timeout_ac_min = n;
            }
            if let Some(n) = get_u("disp_dc") {
                r.power.display_timeout_dc_min = n;
            }
            if let Some(n) = get_u("sleep_ac") {
                r.power.sleep_timeout_ac_min = n;
            }
            if let Some(n) = get_u("sleep_dc") {
                r.power.sleep_timeout_dc_min = n;
            }
        }
        "screensaver" => {
            if let Some(v) = get_b("enabled") {
                r.screensaver.enabled = v;
            }
            if let Some(v) = get_b("active") {
                r.screensaver.active = v;
            }
            if let Some(s) = get_s("scr_exe") {
                r.screensaver.scr_exe = s;
            }
            if let Some(n) = get_u("timeout") {
                r.screensaver.timeout_sec = n;
            }
            if let Some(v) = get_b("logon") {
                r.screensaver.require_logon = v;
            }
        }
        "accessibility" => {
            if let Some(v) = get_b("enabled") {
                r.accessibility.enabled = v;
            }
            if let Some(v) = get_b("snipping") {
                r.accessibility.printscreen_snipping = v;
            }
        }
        "edge" => {
            if let Some(v) = get_b("enabled") {
                r.edge.enabled = v;
            }
            if let Some(v) = get_b("ntp") {
                r.edge.preload_new_tab = v;
            }
            if let Some(v) = get_b("startup") {
                r.edge.prelaunch_startup = v;
            }
            if let Some(v) = get_b("tab") {
                r.edge.tab_preloading = v;
            }
            if let Some(v) = get_b("pua") {
                r.edge.block_pua = v;
            }
        }
        "system_restore" => {
            if let Some(v) = get_b("enabled") {
                r.system_restore.enabled = v;
            }
            if let Some(s) = get_s("drive") {
                r.system_restore.drive = s;
            }
            if let Some(v) = get_b("enable") {
                r.system_restore.enable = v;
            }
            if let Some(s) = get_s("max_size") {
                r.system_restore.max_size = s;
            }
        }
        "password_policy" => {
            if let Some(v) = get_b("enabled") {
                r.password_policy.enabled = v;
            }
            if let Some(n) = get_u("history") {
                r.password_policy.password_history = n.min(u16::MAX as u32) as u16;
            }
            if let Some(n) = get_u("max_age") {
                r.password_policy.max_password_age_days = n.min(u16::MAX as u32) as u16;
            }
            if let Some(n) = get_u("min_len") {
                r.password_policy.min_password_length = n.min(u16::MAX as u32) as u16;
            }
            if let Some(v) = get_b("complex") {
                r.password_policy.complexity_enabled = v;
            }
            if let Some(n) = get_u("lock_thr") {
                r.password_policy.lockout_threshold = n.min(u16::MAX as u32) as u16;
            }
            if let Some(n) = get_u("lock_dur") {
                r.password_policy.lockout_duration_min = n;
            }
            if let Some(n) = get_u("lock_rst") {
                r.password_policy.lockout_reset_min = n;
            }
            if let Some(v) = get_b("adm_lock") {
                r.password_policy.allow_admin_lockout = v;
            }
        }
        "defender_firewall" => {
            if let Some(v) = get_b("enabled") {
                r.defender_firewall.enabled = v;
            }
            if let Some(v) = get_b("headless") {
                r.defender_firewall.defender_headless_ui = v;
            }
            if let Some(v) = get_b("def_on") {
                r.defender_firewall.defender_enabled = v;
            }
            if let Some(s) = get_s("profiles") {
                r.defender_firewall.firewall_profiles = s
                    .split(',')
                    .map(|p| p.trim().to_ascii_lowercase())
                    .filter(|p| !p.is_empty())
                    .collect();
            }
            if let Some(v) = get_b("icmp_echo") {
                r.defender_firewall.allow_icmp_echo = v;
            }
            if let Some(v) = get_b("icmp_rtr") {
                r.defender_firewall.allow_icmp_router = v;
            }
        }
        "startup_apps" => {
            if let Some(v) = get_b("enabled") {
                r.startup_apps.enabled = v;
            }
            if let Some(s) = get_s("allowlist") {
                r.startup_apps.allowlist = s
                    .split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect();
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::fake::FakeSystemOps;

    #[test]
    fn non_console_tty_returns_exit_code_3_without_panicking() {
        let ops = FakeSystemOps::default();
        ops.state.borrow_mut().console_tty = false;
        let dir = std::env::temp_dir().join(format!("it-tools-tui-notty-{}", std::process::id()));
        let code = run_tui(
            &ops,
            &[],
            ProfileConfig::embedded_default(),
            dir.join("it-tools.toml"),
            dir,
            vec![],
        )
        .unwrap();
        assert_eq!(code, EXIT_NO_CONSOLE);
    }

    #[test]
    fn tui_app_toggle_and_uac_relaunch_flow_work_headlessly() {
        struct NeedsAdminRule;
        impl Rule for NeedsAdminRule {
            fn id(&self) -> &'static str {
                "diagnostics"
            }
            fn title(&self) -> &'static str {
                "Diagnostics"
            }
            fn requires_admin(&self) -> bool {
                true
            }
            fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
                cfg.rules.diagnostics.enabled
            }
            fn check(&self, _ops: &dyn SystemOps, _cfg: &ProfileConfig) -> Result<RuleCheck> {
                Ok(RuleCheck {
                    id: "diagnostics".into(),
                    title: "Diagnostics".into(),
                    requires_admin: true,
                    enabled_in_config: true,
                    status: CheckStatus::Drifted,
                    diffs: vec![],
                    note: None,
                })
            }
            fn apply(
                &self,
                _ops: &dyn SystemOps,
                _cfg: &ProfileConfig,
                _opts: &ApplyOptions,
                _snap: &mut BackupSnapshot,
            ) -> Result<(RuleOutcome, Vec<String>)> {
                Ok((RuleOutcome::Applied, vec![]))
            }
        }

        let ops = FakeSystemOps::default();
        ops.state.borrow_mut().admin = false;
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(NeedsAdminRule)];
        let dir = std::env::temp_dir().join(format!("it-tools-tui-uac-{}", std::process::id()));
        let mut app = TuiApp::new(
            &ops,
            &rules,
            ProfileConfig::embedded_default(),
            dir.join("it-tools.toml"),
            dir.clone(),
            vec!["--config".into(), "custom.toml".into()],
        )
        .unwrap();

        assert!(app.cfg.rules.diagnostics.enabled);
        app.handle_key(KeyCode::Char(' '), &ops, &rules).unwrap();
        assert!(!app.cfg.rules.diagnostics.enabled);
        assert!(app.config_dirty);
        app.handle_key(KeyCode::Char(' '), &ops, &rules).unwrap();
        assert!(app.cfg.rules.diagnostics.enabled);

        app.handle_key(KeyCode::Char('a'), &ops, &rules).unwrap();
        assert!(matches!(app.modal, Modal::ElevationPrompt));
        let eff = app.handle_key(KeyCode::Char('e'), &ops, &rules).unwrap();
        assert_eq!(eff, TuiEffect::Quit(0));
        assert_eq!(ops.state.borrow().relaunched_args.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tui_v_key_opens_update_check_modal() {
        let ops = FakeSystemOps::default();
        let release_json = r#"{"tag_name":"v99.0.0","prerelease":false,"published_at":"2026-11-11T00:00:00Z","html_url":"https://github.com/acme/it-tools/releases/tag/v99.0.0","body":"New features","assets":[]}"#;
        {
            let mut st = ops.state.borrow_mut();
            st.http_responses.insert(
                "https://api.github.com/repos/acme/it-tools/releases/latest".into(),
                (200, release_json.as_bytes().to_vec()),
            );
            st.http_responses.insert(
                "https://api.github.com/repos/acme/it-tools/releases?per_page=20".into(),
                (200, format!("[{release_json}]").into_bytes()),
            );
        }
        let mut cfg = ProfileConfig::embedded_default();
        cfg.update.repo = Some("acme/it-tools".into());
        let dir = std::env::temp_dir().join(format!("it-tools-tui-upd-{}", std::process::id()));
        let mut app = TuiApp::new(&ops, &[], cfg, dir.join("it-tools.toml"), dir, vec![]).unwrap();
        app.handle_key(KeyCode::Char('v'), &ops, &[]).unwrap();
        match &app.modal {
            Modal::ReportView { title, lines, .. } => {
                assert_eq!(title, "Version & Updates");
                assert!(lines.iter().any(|l| l.contains("UPDATE AVAILABLE")));
                assert!(lines.iter().any(|l| l.contains("99.0.0")));
            }
            other => panic!("expected ReportView modal, got {other:?}"),
        }
    }

    #[test]
    fn tui_draws_ascii_banner_on_standard_terminal_and_compacts_on_tiny_terminal() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let ops = FakeSystemOps::default();
        let dir = std::env::temp_dir().join(format!("it-tools-tui-bnr-{}", std::process::id()));
        let app = TuiApp::new(
            &ops,
            &[],
            ProfileConfig::embedded_default(),
            dir.join("it-tools.toml"),
            dir,
            vec![],
        )
        .unwrap();

        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        term.draw(|f| draw_ui(f, &app, &[])).unwrap();
        let buf = term.backend().buffer().clone();
        let row_text = |y: u16| -> String {
            (0..buf.area.width)
                .map(|x| buf[(x, y)].symbol())
                .collect::<String>()
        };
        let top_rows: String = (0..9).map(row_text).collect::<Vec<_>>().join("\n");
        assert!(top_rows.contains("$$$$$$/ $$$$$$$$/"));
        assert!(top_rows.contains("$$$$$$$$/______"));

        let mut tiny = Terminal::new(TestBackend::new(60, 18)).unwrap();
        tiny.draw(|f| draw_ui(f, &app, &[])).unwrap();
        let tiny_buf = tiny.backend().buffer().clone();
        let tiny_all: String = (0..tiny_buf.area.height)
            .map(|y| {
                (0..tiny_buf.area.width)
                    .map(|x| tiny_buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!tiny_all.contains("$$$$$$/"));
        assert!(tiny_all.contains("Hardening Modules"));
    }
}
