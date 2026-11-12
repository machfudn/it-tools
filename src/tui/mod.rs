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
    UpdateChannel, UpdateCheckResult, check_for_update, current_channel, current_display_version,
    default_github_repo, perform_update,
};

const CONTROLS_BAR: &str = "[Spasi] Aktif [e] Ubah [u] Akun [p] Simulasi [a] Terapkan [s] Simpan [b] Pulih [v] Update [d] Dok [q] Keluar";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationLevel {
    Info,
    Success,
    Warning,
    Error,
}
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
        update: Option<Box<UpdateCheckResult>>,
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
    pub notification_level: NotificationLevel,
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
            status_banner:
                "Siap. Pilih modul lalu tekan tombol di Kontrol, atau [d] untuk dokumentasi.".into(),
            notification_level: NotificationLevel::Info,
            modal: Modal::None,
            user_target: None,
            relaunch_args,
        })
    }

    pub fn set_notification(&mut self, level: NotificationLevel, msg: impl Into<String>) {
        self.notification_level = level;
        self.status_banner = msg.into();
    }

    fn notify_run_report(&mut self, prefix: &str, rep: &RunReport) {
        let mut applied = 0usize;
        let mut compliant = 0usize;
        let mut warned = 0usize;
        let mut failed = 0usize;
        for e in &rep.entries {
            match e.outcome {
                RuleOutcome::Applied => applied += 1,
                RuleOutcome::AlreadyCompliant => compliant += 1,
                RuleOutcome::WarnTamperProtected { .. }
                | RuleOutcome::WarnFirmwareLocked { .. }
                | RuleOutcome::WarnEdgeRunning { .. } => warned += 1,
                RuleOutcome::Skipped { .. } => {}
                RuleOutcome::Failed { .. } => failed += 1,
            }
        }
        let level = if failed > 0 {
            NotificationLevel::Error
        } else if warned > 0 {
            NotificationLevel::Warning
        } else {
            NotificationLevel::Success
        };
        let backup_note = rep
            .backup_file
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| format!(" | backup: {}", n.to_string_lossy()))
            .unwrap_or_default();
        self.set_notification(
            level,
            format!(
                "{prefix}: {applied} diterapkan, {compliant} sesuai, {warned} peringatan, {failed} gagal{backup_note}."
            ),
        );
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
                                self.set_notification(
                                    NotificationLevel::Info,
                                    format!(
                                        "Parameter '{rule_id}' diubah (tekan [s] untuk simpan)."
                                    ),
                                );
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
                                    self.set_notification(
                                        NotificationLevel::Info,
                                        format!(
                                            "Parameter '{rule_id}' diubah (tekan [s] untuk simpan)."
                                        ),
                                    );
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
                                    self.set_notification(
                                        NotificationLevel::Info,
                                        format!(
                                            "Parameter '{rule_id}' diubah (tekan [s] untuk simpan)."
                                        ),
                                    );
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
                                    self.set_notification(
                                        NotificationLevel::Info,
                                        format!(
                                            "Parameter '{rule_id}' diubah (tekan [s] untuk simpan)."
                                        ),
                                    );
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
                                    self.set_notification(
                                        NotificationLevel::Info,
                                        format!(
                                            "Parameter '{rule_id}' diubah (tekan [s] untuk simpan)."
                                        ),
                                    );
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
                        self.set_notification(
                            NotificationLevel::Info,
                            "Target akun opsional dikosongkan.",
                        );
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
                                    self.set_notification(
                                        NotificationLevel::Warning,
                                        "Akun baru wajib memiliki kata sandi sementara yang tidak kosong.",
                                    );
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
                                self.set_notification(
                                    NotificationLevel::Success,
                                    format!("Target akun disetel: buat '{}'.", create_name.trim()),
                                );
                            } else if let Some(u) = users.get(cursor) {
                                self.user_target = Some(UserTargetOptions {
                                    username: u.name.clone(),
                                    create_if_missing: false,
                                    clear_dont_expire,
                                    temp_password: pw_opt,
                                });
                                self.set_notification(
                                    NotificationLevel::Success,
                                    format!("Target akun disetel: '{}'.", u.name),
                                );
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
                    self.show_run_report("Terapkan (Khusus HKCU)", &report);
                    self.notify_run_report("Penerapan khusus HKCU selesai", &report);
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
                        let count = actions.len();
                        self.modal = Modal::ReportView {
                            title: format!("Pemulihan: {}", path.display()),
                            lines: actions,
                            scroll: 0,
                            update: None,
                        };
                        let name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| path.display().to_string());
                        self.set_notification(
                            NotificationLevel::Success,
                            format!("Pemulihan berhasil dari {name} ({count} aksi)."),
                        );
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
                update,
            } => match code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => Ok(TuiEffect::Continue),
                KeyCode::Char('u') | KeyCode::Char('U') => {
                    if let Some(check) = update {
                        self.install_update_from_modal(ops, &check);
                    } else {
                        self.modal = Modal::ReportView {
                            title,
                            lines,
                            scroll,
                            update: None,
                        };
                    }
                    Ok(TuiEffect::Continue)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    scroll = scroll.saturating_sub(1);
                    self.modal = Modal::ReportView {
                        title,
                        lines,
                        scroll,
                        update,
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
                        update,
                    };
                    Ok(TuiEffect::Continue)
                }
                KeyCode::PageUp => {
                    scroll = scroll.saturating_sub(10);
                    self.modal = Modal::ReportView {
                        title,
                        lines,
                        scroll,
                        update,
                    };
                    Ok(TuiEffect::Continue)
                }
                KeyCode::PageDown => {
                    let max_scroll = lines.len().saturating_sub(1) as u16;
                    scroll = (scroll.saturating_add(10)).min(max_scroll);
                    self.modal = Modal::ReportView {
                        title,
                        lines,
                        scroll,
                        update,
                    };
                    Ok(TuiEffect::Continue)
                }
                _ => {
                    self.modal = Modal::ReportView {
                        title,
                        lines,
                        scroll,
                        update,
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
                    let state_lbl = if is_rule_enabled(&self.cfg, &id) {
                        "diaktifkan"
                    } else {
                        "dinonaktifkan"
                    };
                    self.set_notification(
                        NotificationLevel::Info,
                        format!("Modul '{id}' {state_lbl} (tekan [s] untuk simpan)."),
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
                self.set_notification(
                    NotificationLevel::Success,
                    format!(
                        "Konfigurasi berhasil disimpan ke {}.",
                        self.config_path.display()
                    ),
                );
            }
            KeyCode::Char('r') => {
                self.refresh_check(ops, rules)?;
                self.set_notification(
                    NotificationLevel::Success,
                    "Pemeriksaan kepatuhan berhasil disegarkan.",
                );
            }
            KeyCode::Char('p') => {
                let opts = ApplyOptions {
                    dry_run: true,
                    user_target: self.user_target.clone(),
                    ..Default::default()
                };
                let rep = apply_rules(ops, &self.cfg, rules, &opts, &self.exe_dir)?;
                self.show_run_report("Pratinjau Perubahan (Simulasi)", &rep);
                self.set_notification(
                    NotificationLevel::Info,
                    "Simulasi (Dry-Run) selesai; tidak ada perubahan ke Windows.",
                );
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
                    self.set_notification(
                        NotificationLevel::Warning,
                        "File backup it-tools.backup.*.json tidak ditemukan di dekat exe.",
                    );
                } else {
                    self.modal = Modal::RollbackPicker { files, cursor: 0 };
                }
            }
            KeyCode::Char('v') => {
                self.check_updates_modal(ops);
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                self.open_docs_modal();
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
                title: "Versi & Pembaruan".into(),
                lines: vec![
                    format!("Versi Terpasang : {cur}"),
                    format!("Kanal Rilis     : {ch}"),
                    String::new(),
                    "Repositori GitHub belum dikonfigurasi pada build ini.".into(),
                    "Atur [update] repo = \"owner/repo\" di it-tools.toml atau jalankan:".into(),
                    "  it-tools update --check --repo owner/repo".into(),
                ],
                scroll: 0,
                update: None,
            };
            self.set_notification(
                NotificationLevel::Warning,
                "Repositori pembaruan belum dikonfigurasi pada build ini.",
            );
            return;
        };

        match check_for_update(ops, &repo, ch) {
            Ok(res) => {
                let can_install = res.update_available && res.asset_url.is_some();
                let mut lines = vec![
                    format!("Repositori      : {repo}"),
                    format!("Versi Terpasang : {}", res.current_version),
                    format!("Terbaru ({:<6}): {}", res.channel, res.latest_version),
                    format!(
                        "Status          : {}",
                        if can_install {
                            "PEMBARUAN TERSEDIA — tekan [u] untuk unduh & pasang sekarang"
                        } else if res.update_available {
                            "PEMBARUAN TERSEDIA (aset .exe belum tersedia pada rilis ini)"
                        } else {
                            "SUDAH MUTAKHIR"
                        }
                    ),
                ];
                if let Some(asset) = &res.asset_name {
                    lines.push(format!("Aset            : {asset}"));
                }
                if !res.html_url.is_empty() {
                    lines.push(format!("URL             : {}", res.html_url));
                }
                if !res.release_notes.trim().is_empty() {
                    lines.push(String::new());
                    lines.push("--- Catatan Rilis ---".into());
                    lines.extend(res.release_notes.lines().map(str::to_string));
                }
                let (lvl, msg) = if can_install {
                    (
                        NotificationLevel::Info,
                        format!(
                            "Pembaruan tersedia: v{} ({}) — tekan [u] di modal untuk pasang.",
                            res.latest_version, res.channel
                        ),
                    )
                } else if res.update_available {
                    (
                        NotificationLevel::Warning,
                        format!(
                            "Pembaruan v{} ({}) ditemukan, tetapi aset .exe belum tersedia.",
                            res.latest_version, res.channel
                        ),
                    )
                } else {
                    (
                        NotificationLevel::Success,
                        format!("Aplikasi sudah versi terbaru (v{}).", res.current_version),
                    )
                };
                let pending = can_install.then(|| Box::new(res));
                self.modal = Modal::ReportView {
                    title: "Versi & Pembaruan".into(),
                    lines,
                    scroll: 0,
                    update: pending,
                };
                self.set_notification(lvl, msg);
            }
            Err(e) => {
                self.set_notification(
                    NotificationLevel::Error,
                    format!("Gagal cek pembaruan: {e}"),
                );
                self.modal = Modal::ReportView {
                    title: "Versi & Pembaruan (Gagal Cek)".into(),
                    lines: vec![
                        format!("Versi Terpasang : {cur}"),
                        format!("Repositori      : {repo}"),
                        format!("Galat           : {e:#}"),
                    ],
                    scroll: 0,
                    update: None,
                };
            }
        }
    }

    fn install_update_from_modal(&mut self, ops: &dyn SystemOps, check: &UpdateCheckResult) {
        match perform_update(ops, check) {
            Ok(applied) => {
                let sha_status = if applied.sha256_verified {
                    "terverifikasi SHA256SUMS"
                } else {
                    "dihitung tanpa SHA256SUMS"
                };
                self.set_notification(
                    NotificationLevel::Success,
                    format!(
                        "Berhasil diperbarui ke v{}! Tutup lalu buka ulang it-tools.exe.",
                        applied.new_version
                    ),
                );
                self.modal = Modal::ReportView {
                    title: "Pembaruan Berhasil Dipasang".into(),
                    lines: vec![
                        format!("Versi Lama    : {}", applied.previous_version),
                        format!("Versi Baru    : {}", applied.new_version),
                        format!("Lokasi Binary : {}", applied.exe_path),
                        format!("Backup Lama   : {}", applied.backup_path),
                        format!("SHA-256       : {} ({sha_status})", applied.sha256),
                        String::new(),
                        "Langkah selanjutnya:".into(),
                        "  Tutup aplikasi ([Esc]/[q]) lalu buka ulang it-tools.exe agar versi baru berjalan.".into(),
                    ],
                    scroll: 0,
                    update: None,
                };
            }
            Err(e) => {
                self.set_notification(
                    NotificationLevel::Error,
                    format!("Gagal memasang pembaruan: {e:#}"),
                );
                self.modal = Modal::ReportView {
                    title: "Pembaruan Gagal".into(),
                    lines: vec![
                        format!("Versi Target : {}", check.latest_version),
                        format!("Galat        : {e:#}"),
                    ],
                    scroll: 0,
                    update: None,
                };
            }
        }
    }

    fn open_docs_modal(&mut self) {
        self.modal = Modal::ReportView {
            title: "Dokumentasi & Glosarium Istilah".into(),
            lines: documentation_lines(),
            scroll: 0,
            update: None,
        };
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
        self.show_run_report("Hasil Penerapan", &rep);
        self.notify_run_report("Penerapan selesai", &rep);
        self.refresh_check(ops, rules)?;
        Ok(())
    }

    fn show_run_report(&mut self, title: &str, rep: &RunReport) {
        let mut lines = Vec::new();
        if let Some(bk) = &rep.backup_file {
            lines.push(format!("Backup tersimpan: {}", bk.display()));
            lines.push(String::new());
        }
        for e in &rep.entries {
            let tag = match &e.outcome {
                RuleOutcome::Applied => "DITERAPKAN".into(),
                RuleOutcome::AlreadyCompliant => "SUDAH SESUAI".into(),
                RuleOutcome::WarnTamperProtected { detail } => {
                    format!("PERINGATAN TAMPER: {detail}")
                }
                RuleOutcome::WarnFirmwareLocked { detail } => {
                    format!("PERINGATAN FIRMWARE: {detail}")
                }
                RuleOutcome::WarnEdgeRunning { detail } => format!("PERINGATAN EDGE: {detail}"),
                RuleOutcome::Skipped { reason } => format!("DILEWATI: {reason}"),
                RuleOutcome::Failed { error } => format!("GAGAL: {error}"),
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
            update: None,
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
            "TUI membutuhkan Windows Console / Windows Terminal. Gunakan subcommand CLI (check, apply, rollback, config) atau jalankan lewat winpty / Windows Terminal."
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
        {
            match app.handle_key(key.code, ops, rules) {
                Ok(TuiEffect::Quit(code)) => return Ok(code),
                Ok(TuiEffect::Continue) => {}
                Err(err) => {
                    app.set_notification(NotificationLevel::Error, format!("Galat: {err:#}"));
                }
            }
        }
    }
}

fn draw_ui(frame: &mut ratatui::Frame, app: &TuiApp, rules: &[Box<dyn Rule>]) {
    let area = frame.area();
    let show_ascii = area.height >= 25 && area.width >= crate::APP_BANNER_WIDTH as u16;
    let (header_area, notif_area, body_area, footer_area) = if show_ascii {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(9),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(6),
                Constraint::Length(4),
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
        (chunks[1], chunks[2], chunks[3], chunks[4])
    } else {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(4),
            ])
            .split(area);
        (chunks[0], chunks[1], chunks[2], chunks[3])
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
            " PENGGUNA STANDAR ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    };
    let dirty_mark = if app.config_dirty {
        " [BELUM DISIMPAN *]"
    } else {
        ""
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" IT-Tools v{} ", current_display_version()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        admin_badge,
        Span::raw(format!(
            "  {}  |  Konfigurasi: {}{}",
            app.check_report.os_caption,
            app.config_path.display(),
            dirty_mark
        )),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Sistem & Profil"),
    );
    frame.render_widget(header, header_area);

    let (notif_tag, notif_style) = match app.notification_level {
        NotificationLevel::Info => (
            " INFO ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        NotificationLevel::Success => (
            " BERHASIL ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        NotificationLevel::Warning => (
            " PERINGATAN ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        NotificationLevel::Error => (
            " GALAT ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
    };
    let notif = Paragraph::new(Line::from(vec![
        Span::styled(notif_tag, notif_style),
        Span::raw(format!(" {}", app.status_banner)),
    ]))
    .wrap(Wrap { trim: false })
    .block(Block::default().borders(Borders::ALL).title("Notifikasi"));
    frame.render_widget(notif, notif_area);

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
                Span::styled("NONAKTIF", Style::default().fg(Color::DarkGray))
            } else if let Some(chk) = app.check_for(r.id()) {
                match chk.status {
                    CheckStatus::Compliant => {
                        Span::styled("SESUAI", Style::default().fg(Color::Green))
                    }
                    CheckStatus::Drifted => {
                        Span::styled("BERUBAH", Style::default().fg(Color::Yellow))
                    }
                    CheckStatus::NeedsAdmin => {
                        Span::styled("ADMIN", Style::default().fg(Color::Red))
                    }
                    CheckStatus::Unsupported => {
                        Span::styled("KENDALA", Style::default().fg(Color::Magenta))
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
                .title("Modul Pengamanan (13)"),
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
            "Cakupan: {} | Aktif: {}",
            if r.requires_admin() {
                "Admin (HKLM/Sistem)"
            } else {
                "Standar (HKCU)"
            },
            if is_rule_enabled(&app.cfg, r.id()) {
                "Ya"
            } else {
                "Tidak"
            }
        )));
        if let Some(ut) = &app.user_target {
            detail_lines.push(Line::from(format!(
                "Target Akun Opsional: {} ({})",
                ut.username,
                if ut.create_if_missing {
                    "buat baru"
                } else {
                    "sudah ada"
                }
            )));
        }
        detail_lines.push(Line::from(""));
        detail_lines.push(Line::from(Span::styled(
            "Perbedaan Saat Ini:",
            Style::default().fg(Color::Cyan),
        )));
        if let Some(chk) = app.check_for(r.id()) {
            if chk.diffs.is_empty() {
                detail_lines.push(Line::from("  (tidak ada - sudah sesuai)"));
            } else {
                for d in &chk.diffs {
                    detail_lines.push(Line::from(format!(
                        "  - {}: {} -> {}",
                        d.field, d.current, d.target
                    )));
                }
            }
            if let Some(note) = &chk.note {
                detail_lines.push(Line::from(format!("Catatan: {note}")));
            }
        } else {
            detail_lines.push(Line::from("  (modul dinonaktifkan di konfigurasi)"));
        }
    }
    let detail = Paragraph::new(detail_lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Inspektor Modul"),
        );
    frame.render_widget(detail, main_cols[1]);

    let footer = Paragraph::new(CONTROLS_BAR)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title("Kontrol"));
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
                "Buat snapshot backup JSON otomatis di sebelah exe lalu terapkan modul yang aktif?\n\n[Enter / y] Terapkan Sekarang    [Esc / n] Batal",
            )
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title("Konfirmasi Penerapan"));
            frame.render_widget(p, area);
        }
        Modal::ElevationPrompt => {
            let area = centered_rect(65, 36, frame.area());
            frame.render_widget(Clear, area);
            let p = Paragraph::new(
                "Satu atau lebih modul yang dipilih mengubah HKLM / kebijakan Windows dan membutuhkan hak Administrator.\n\n[E] Jalankan Ulang sebagai Administrator (UAC)\n[O] Terapkan Modul Pengguna (HKCU) Saja Sekarang\n[Esc] Batal",
            )
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title("Butuh Hak Administrator"));
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
                        .title(format!("Ubah {rule_id} ([Spasi/Enter] ubah, [Esc] tutup)")),
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
                    "Pemilihan akun lokal opsional ([Tab] pindah kolom, [Enter] pilih/ubah, [c] kosongkan, [Esc] tutup):",
                ),
                Line::from(""),
                Line::from(format!(
                    "{} Nama Akun Baru: {}{}",
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
                    "{} Sandi Sementara (hanya di RAM): {}{}",
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
                    "{} Hapus PasswordNeverExpires ([Spasi]): {}",
                    if *focus == UserPickerFocus::ClearDontExpire {
                        ">"
                    } else {
                        " "
                    },
                    if *clear_dont_expire { "Ya" } else { "Tidak" }
                )),
                Line::from(""),
                Line::from(format!(
                    "{} Daftar Akun Lokal yang Ada:",
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
                    "  {mark} {} (nonaktif={}, sandi_tanpa_kadaluarsa={})",
                    u.name,
                    if u.disabled { "ya" } else { "tidak" },
                    if u.dont_expire_password {
                        "ya"
                    } else {
                        "tidak"
                    }
                )));
            }
            let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Akun Lokal & Sandi Sementara"),
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
                        .title("Pulihkan Backup ([Enter] pulihkan, [Esc] batal)"),
                )
                .highlight_style(Style::default().bg(Color::Blue).fg(Color::White));
            frame.render_stateful_widget(list, area, &mut st);
        }
        Modal::ReportView {
            title,
            lines,
            scroll,
            update,
        } => {
            let area = centered_rect(82, 78, frame.area());
            frame.render_widget(Clear, area);
            let text: Vec<Line> = lines.iter().map(|s| Line::from(s.as_str())).collect();
            let footer_hint = if update.is_some() {
                "[u] Unduh & Pasang, [j/k/PgUp/PgDn] gulir, [Esc] tutup"
            } else {
                "[j/k/PgUp/PgDn] gulir, [Esc] tutup"
            };
            let p = Paragraph::new(text)
                .scroll((*scroll, 0))
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!("{title} ({footer_hint})")),
                );
            frame.render_widget(p, area);
        }
    }
}

fn documentation_lines() -> Vec<String> {
    [
        "=== PANDUAN SINGKAT & NAVIGASI ===",
        "Alur aman: [r] Periksa -> [p] Simulasi -> [a] Terapkan -> [b] Pulihkan.",
        "",
        "Tombol Navigasi Utama:",
        "  Up/Down atau j/k : Pindah pilihan modul",
        "  Spasi            : Aktif/nonaktifkan modul terpilih",
        "  e atau Enter     : Ubah parameter konfigurasi modul",
        "  u                : Pilih/buat akun lokal target & sandi sementara",
        "  p                : Simulasi (Dry-Run) tanpa mengubah Windows",
        "  a                : Terapkan modul aktif (otomatis buat backup JSON)",
        "  s                : Simpan konfigurasi ke it-tools.toml",
        "  r                : Segarkan pemeriksaan status kepatuhan OS",
        "  b                : Pulihkan kondisi dari file backup JSON (Rollback)",
        "  v                : Cek & pasang pembaruan versi (Stable/Beta) di GitHub",
        "  d                : Buka dokumentasi & glosarium istilah ini",
        "  q atau Esc       : Keluar dari aplikasi",
        "",
        "=== ARTI STATUS & LENCANA MODUL ===",
        "  SESUAI   (Compliant)  : Pengaturan Windows sudah cocok dengan target profil.",
        "  BERUBAH  (Drifted)    : Kondisi Windows saat ini berbeda dari target profil.",
        "  ADMIN    (NeedsAdmin) : Butuh hak Administrator (UAC) untuk cek/terapkan.",
        "  KENDALA  (Unsupported): Fitur tidak tersedia/terkunci oleh OS atau VM.",
        "  NONAKTIF              : Modul dimatikan di konfigurasi (tidak diterapkan).",
        "  [BELUM DISIMPAN *]    : Ada ubahan di TUI yang belum disimpan dengan [s].",
        "",
        "=== GLOSARIUM ISTILAH TEKNIS ===",
        "  Hardening",
        "    Proses memperketat pengaturan sistem operasi untuk mengurangi celah",
        "    keamanan, telemetri berlebih, dan kebijakan bawaan yang berisiko.",
        "",
        "  HKCU (HKEY_CURRENT_USER)",
        "    Cabang Windows Registry khusus akun pengguna aktif saat ini.",
        "    Dapat dibaca & diubah tanpa hak Administrator.",
        "",
        "  HKLM (HKEY_LOCAL_MACHINE)",
        "    Cabang Windows Registry global untuk seluruh perangkat dan pengguna.",
        "    Wajib hak Administrator (Elevated / UAC) untuk menerapkannya.",
        "",
        "  UAC (User Account Control)",
        "    Mekanisme izin Windows untuk menjalankan ulang aplikasi sebagai",
        "    Administrator saat modul HKLM/kebijakan sistem akan diterapkan.",
        "",
        "  Simulasi / Dry-Run ([p])",
        "    Menampilkan daftar perubahan yang akan dilakukan tanpa menyentuh",
        "    Registry/OS maupun membuat file backup.",
        "",
        "  Backup Snapshot & Rollback ([b])",
        "    Sebelum mutasi live, nilai awal disimpan ke file JSON bernama",
        "    it-tools.backup.<waktu>.json di folder yang sama dengan exe.",
        "    Menu [b] membaca file itu untuk mengembalikan OS ke kondisi semula.",
        "",
        "  Idempoten",
        "    Aman dijalankan berulang kali: bila pengaturan sudah sesuai target,",
        "    tidak ada penulisan ulang maupun file backup ganda.",
        "",
        "  Telemetry & Diagnostic Data",
        "    Data diagnostik penggunaan Windows yang dikirim ke Microsoft",
        "    (AllowTelemetry = 0 membatasi ke tingkat minimal/Required).",
        "",
        "  Cloud Search & Search Highlights",
        "    Integrasi pencarian Bing, akun Microsoft (MSA), Work/School (AAD),",
        "    serta gambar/sorotan harian pada kotak pencarian Windows.",
        "",
        "  Hibernasi (hibernate) & Modern Standby (S0)",
        "    Hibernasi menyimpan isi RAM ke hiberfil.sys di disk; menonaktifkannya",
        "    menghemat ruang disk. Pada laptop Modern Standby (S0), sebagian opsi",
        "    powercfg seperti tombol daya/tutup layar bisa dikunci oleh firmware.",
        "",
        "  PUA (Potentially Unwanted Application)",
        "    Aplikasi tidak diinginkan (adware/bundler) yang dapat diblokir",
        "    otomatis oleh fitur SmartScreen Microsoft Edge.",
        "",
        "  System Restore & VSS (Volume Shadow Copy Service)",
        "    Titik pemulihan Windows untuk memulihkan berkas sistem, dikelola",
        "    melalui vssadmin (misalnya batas ruang shadow storage 5GB).",
        "",
        "  Secedit & Password Policy",
        "    Utilitas keamanan lokal Windows (secedit) untuk panjang sandi",
        "    minimal, kompleksitas, riwayat sandi, masa berlaku, dan lockout.",
        "",
        "  PasswordNeverExpires & Sandi Sementara ([u])",
        "    Flag akun lokal agar sandi tidak pernah kadaluarsa. Sandi sementara",
        "    pada menu [u] hanya disimpan di RAM dan tidak ditulis ke disk/log.",
        "",
        "  Tamper Protection",
        "    Proteksi anti-ubah Microsoft Defender; saat aktif di Windows Security,",
        "    sebagian kunci Registry Defender dilindungi OS dari perubahan script.",
        "",
        "  ICMP Echo / Router (Firewall)",
        "    Aturan Windows Defender Firewall untuk lalu lintas ping (Echo) dan",
        "    penemuan router (Router) pada jaringan IPv4/IPv6.",
        "",
        "  StartupApproved",
        "    Kunci Registry Windows yang menonaktifkan/mengaktifkan aplikasi",
        "    startup secara bersih tanpa menghapus entri Run/Startup asli.",
        "",
        "  Kanal Rilis (Stable vs Beta)",
        "    Stable mengikuti rilis produksi final; Beta mengikuti prarilis UAT",
        "    untuk uji coba fitur sebelum dipromosikan ke Stable.",
        "",
        "=== DAFTAR 13 MODUL PENGAMANAN ===",
        "  [HKCU] visual_effects    : Animasi jendela & transparansi tampilan",
        "  [HKLM] diagnostics       : Pembatasan telemetri & frekuensi umpan balik",
        "  [HKLM] search            : Nonaktif Bing/MSA/AAD cloud search & highlights",
        "  [HKCU] typing            : Nonaktif koreksi otomatis, prediksi & insights",
        "  [HKCU] taskbar           : Perataan taskbar, widget, auto-hide & lencana",
        "  [HKLM] power             : Skema daya High Performance, timeout & hibernasi",
        "  [HKCU] screensaver       : Pengunci layar otomatis & wajib login ulang",
        "  [HKCU] accessibility     : Perilaku klasik tombol PrintScreen",
        "  [HKLM] edge              : Nonaktif preload Edge & aktifkan blokir PUA",
        "  [HKLM] system_restore    : Aktifkan titik pemulihan C: & batas ukuran VSS",
        "  [HKLM] password_policy   : Panjang, kompleksitas, masa berlaku & lockout",
        "  [HKLM] defender_firewall : Defender, profil Firewall & aturan ICMP",
        "  [HKLM] startup_apps      : Nonaktifkan startup non-allowlist (StartupApproved)",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
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
        FieldKind::Bool(true) => "Ya".into(),
        FieldKind::Bool(false) => "Tidak".into(),
        FieldKind::Text(s) => s.clone(),
        FieldKind::U32(n) => n.to_string(),
        FieldKind::Alignment(TaskbarAlignment::Left) => "Kiri (Left)".into(),
        FieldKind::Alignment(TaskbarAlignment::Center) => "Tengah (Center)".into(),
        FieldKind::Feedback(FeedbackFrequency::Never) => "Tidak Pernah (Never)".into(),
        FieldKind::Feedback(FeedbackFrequency::OnceADay) => "Sekali Sehari (OnceADay)".into(),
        FieldKind::Feedback(FeedbackFrequency::OnceAWeek) => "Sekali Seminggu (OnceAWeek)".into(),
        FieldKind::Feedback(FeedbackFrequency::Always) => "Selalu (Always)".into(),
        FieldKind::Feedback(FeedbackFrequency::Auto) => "Otomatis (Auto)".into(),
        FieldKind::PowerAct(PowerAction::Nothing) => "Tidak Ada (Nothing)".into(),
        FieldKind::PowerAct(PowerAction::Sleep) => "Tidur (Sleep)".into(),
        FieldKind::PowerAct(PowerAction::Hibernate) => "Hibernasi (Hibernate)".into(),
        FieldKind::PowerAct(PowerAction::Shutdown) => "Matikan (Shutdown)".into(),
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
                label: "Aktif",
                kind: FieldKind::Bool(r.visual_effects.enabled),
            },
            EditableField {
                key: "animations",
                label: "Animasi",
                kind: FieldKind::Bool(r.visual_effects.animations),
            },
            EditableField {
                key: "transparency",
                label: "Transparansi",
                kind: FieldKind::Bool(r.visual_effects.transparency),
            },
        ],
        "diagnostics" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.diagnostics.enabled),
            },
            EditableField {
                key: "optional_data",
                label: "Data Opsional",
                kind: FieldKind::Bool(r.diagnostics.optional_data),
            },
            EditableField {
                key: "feedback",
                label: "Frekuensi Umpan Balik",
                kind: FieldKind::Feedback(r.diagnostics.feedback_frequency),
            },
        ],
        "search" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.search.enabled),
            },
            EditableField {
                key: "msa",
                label: "Pencarian Cloud MSA",
                kind: FieldKind::Bool(r.search.msa_cloud_search),
            },
            EditableField {
                key: "aad",
                label: "Pencarian Kantor/Sekolah",
                kind: FieldKind::Bool(r.search.work_school_search),
            },
            EditableField {
                key: "highlights",
                label: "Sorotan Pencarian",
                kind: FieldKind::Bool(r.search.search_highlights),
            },
        ],
        "typing" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.typing.enabled),
            },
            EditableField {
                key: "autocorrect",
                label: "Koreksi Otomatis",
                kind: FieldKind::Bool(r.typing.autocorrect),
            },
            EditableField {
                key: "highlight",
                label: "Sorot Salah Ketik",
                kind: FieldKind::Bool(r.typing.highlight_misspelled),
            },
            EditableField {
                key: "prediction",
                label: "Prediksi Teks",
                kind: FieldKind::Bool(r.typing.text_prediction),
            },
            EditableField {
                key: "insights",
                label: "Wawasan Mengetik",
                kind: FieldKind::Bool(r.typing.typing_insights),
            },
            EditableField {
                key: "voice",
                label: "Tombol Ketik Suara",
                kind: FieldKind::Bool(r.typing.voice_typing_key),
            },
            EditableField {
                key: "multi",
                label: "Multibahasa",
                kind: FieldKind::Bool(r.typing.multilingual),
            },
            EditableField {
                key: "shift",
                label: "Kapital Otomatis",
                kind: FieldKind::Bool(r.typing.auto_shift),
            },
            EditableField {
                key: "space",
                label: "Spasi Ganda Titik",
                kind: FieldKind::Bool(r.typing.double_tap_space),
            },
        ],
        "taskbar" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.taskbar.enabled),
            },
            EditableField {
                key: "widgets",
                label: "Widget",
                kind: FieldKind::Bool(r.taskbar.widgets),
            },
            EditableField {
                key: "alignment",
                label: "Perataan Taskbar",
                kind: FieldKind::Alignment(r.taskbar.alignment),
            },
            EditableField {
                key: "auto_hide",
                label: "Sembunyikan Otomatis",
                kind: FieldKind::Bool(r.taskbar.auto_hide),
            },
            EditableField {
                key: "badges",
                label: "Tampilkan Lencana",
                kind: FieldKind::Bool(r.taskbar.show_badges),
            },
            EditableField {
                key: "flashing",
                label: "Kedipan Ikon",
                kind: FieldKind::Bool(r.taskbar.show_flashing),
            },
        ],
        "power" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.power.enabled),
            },
            EditableField {
                key: "hibernate",
                label: "Hibernasi",
                kind: FieldKind::Bool(r.power.hibernate),
            },
            EditableField {
                key: "scheme",
                label: "Skema Daya",
                kind: FieldKind::Text(r.power.scheme.clone()),
            },
            EditableField {
                key: "min_cpu_ac",
                label: "CPU Min AC (%)",
                kind: FieldKind::U32(r.power.min_cpu_ac_pct.into()),
            },
            EditableField {
                key: "min_cpu_dc",
                label: "CPU Min DC (%)",
                kind: FieldKind::U32(r.power.min_cpu_dc_pct.into()),
            },
            EditableField {
                key: "pbtn_ac",
                label: "Tombol Daya AC",
                kind: FieldKind::PowerAct(r.power.power_button_ac),
            },
            EditableField {
                key: "lid_ac",
                label: "Tutup Layar AC",
                kind: FieldKind::PowerAct(r.power.lid_close_ac),
            },
            EditableField {
                key: "disp_ac",
                label: "Layar Mati AC (mnt)",
                kind: FieldKind::U32(r.power.display_timeout_ac_min),
            },
            EditableField {
                key: "disp_dc",
                label: "Layar Mati DC (mnt)",
                kind: FieldKind::U32(r.power.display_timeout_dc_min),
            },
            EditableField {
                key: "sleep_ac",
                label: "Tidur AC (mnt)",
                kind: FieldKind::U32(r.power.sleep_timeout_ac_min),
            },
            EditableField {
                key: "sleep_dc",
                label: "Tidur DC (mnt)",
                kind: FieldKind::U32(r.power.sleep_timeout_dc_min),
            },
        ],
        "screensaver" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.screensaver.enabled),
            },
            EditableField {
                key: "active",
                label: "Screen Saver Aktif",
                kind: FieldKind::Bool(r.screensaver.active),
            },
            EditableField {
                key: "scr_exe",
                label: "File SCR",
                kind: FieldKind::Text(r.screensaver.scr_exe.clone()),
            },
            EditableField {
                key: "timeout",
                label: "Batas Waktu (dtk)",
                kind: FieldKind::U32(r.screensaver.timeout_sec),
            },
            EditableField {
                key: "logon",
                label: "Wajib Login Ulang",
                kind: FieldKind::Bool(r.screensaver.require_logon),
            },
        ],
        "accessibility" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.accessibility.enabled),
            },
            EditableField {
                key: "snipping",
                label: "PrintScreen ke Snipping",
                kind: FieldKind::Bool(r.accessibility.printscreen_snipping),
            },
        ],
        "edge" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.edge.enabled),
            },
            EditableField {
                key: "ntp",
                label: "Pra-muat Tab Baru",
                kind: FieldKind::Bool(r.edge.preload_new_tab),
            },
            EditableField {
                key: "startup",
                label: "Pra-luncur Startup",
                kind: FieldKind::Bool(r.edge.prelaunch_startup),
            },
            EditableField {
                key: "tab",
                label: "Pra-muat Tab",
                kind: FieldKind::Bool(r.edge.tab_preloading),
            },
            EditableField {
                key: "pua",
                label: "Blokir PUA",
                kind: FieldKind::Bool(r.edge.block_pua),
            },
        ],
        "system_restore" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.system_restore.enabled),
            },
            EditableField {
                key: "drive",
                label: "Drive",
                kind: FieldKind::Text(r.system_restore.drive.clone()),
            },
            EditableField {
                key: "enable",
                label: "Aktifkan Proteksi",
                kind: FieldKind::Bool(r.system_restore.enable),
            },
            EditableField {
                key: "max_size",
                label: "Ukuran Maksimal",
                kind: FieldKind::Text(r.system_restore.max_size.clone()),
            },
        ],
        "password_policy" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.password_policy.enabled),
            },
            EditableField {
                key: "history",
                label: "Riwayat Sandi",
                kind: FieldKind::U32(r.password_policy.password_history.into()),
            },
            EditableField {
                key: "max_age",
                label: "Masa Berlaku (hari)",
                kind: FieldKind::U32(r.password_policy.max_password_age_days.into()),
            },
            EditableField {
                key: "min_len",
                label: "Panjang Minimal",
                kind: FieldKind::U32(r.password_policy.min_password_length.into()),
            },
            EditableField {
                key: "complex",
                label: "Kompleksitas Sandi",
                kind: FieldKind::Bool(r.password_policy.complexity_enabled),
            },
            EditableField {
                key: "lock_thr",
                label: "Ambang Kunci Akun",
                kind: FieldKind::U32(r.password_policy.lockout_threshold.into()),
            },
            EditableField {
                key: "lock_dur",
                label: "Durasi Kunci (mnt)",
                kind: FieldKind::U32(r.password_policy.lockout_duration_min),
            },
            EditableField {
                key: "lock_rst",
                label: "Reset Kunci (mnt)",
                kind: FieldKind::U32(r.password_policy.lockout_reset_min),
            },
            EditableField {
                key: "adm_lock",
                label: "Izinkan Kunci Admin",
                kind: FieldKind::Bool(r.password_policy.allow_admin_lockout),
            },
        ],
        "defender_firewall" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.defender_firewall.enabled),
            },
            EditableField {
                key: "headless",
                label: "UI Defender Tanpa Tampilan",
                kind: FieldKind::Bool(r.defender_firewall.defender_headless_ui),
            },
            EditableField {
                key: "def_on",
                label: "Defender Aktif",
                kind: FieldKind::Bool(r.defender_firewall.defender_enabled),
            },
            EditableField {
                key: "profiles",
                label: "Profil Firewall (csv)",
                kind: FieldKind::Text(r.defender_firewall.firewall_profiles.join(",")),
            },
            EditableField {
                key: "icmp_echo",
                label: "Izinkan ICMP Echo",
                kind: FieldKind::Bool(r.defender_firewall.allow_icmp_echo),
            },
            EditableField {
                key: "icmp_rtr",
                label: "Izinkan ICMP Router",
                kind: FieldKind::Bool(r.defender_firewall.allow_icmp_router),
            },
        ],
        "startup_apps" => vec![
            EditableField {
                key: "enabled",
                label: "Aktif",
                kind: FieldKind::Bool(r.startup_apps.enabled),
            },
            EditableField {
                key: "allowlist",
                label: "Daftar Pengecualian (csv)",
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
                assert_eq!(title, "Versi & Pembaruan");
                assert!(lines.iter().any(|l| l.contains("PEMBARUAN TERSEDIA")));
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
        assert!(tiny_all.contains("Modul Pengamanan"));
        assert!(tiny_all.contains("[d] Dok"));
    }

    #[test]
    fn tui_d_key_opens_indonesian_documentation_and_glossary_modal() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let ops = FakeSystemOps::default();
        let dir = std::env::temp_dir().join(format!("it-tools-tui-doc-{}", std::process::id()));
        let mut app = TuiApp::new(
            &ops,
            &[],
            ProfileConfig::embedded_default(),
            dir.join("it-tools.toml"),
            dir,
            vec![],
        )
        .unwrap();
        assert!(CONTROLS_BAR.contains("[d] Dok"));
        assert!(app.status_banner.contains("Siap."));

        app.handle_key(KeyCode::Char('d'), &ops, &[]).unwrap();
        match &app.modal {
            Modal::ReportView {
                title,
                lines,
                scroll,
                ..
            } => {
                assert_eq!(title, "Dokumentasi & Glosarium Istilah");
                assert_eq!(*scroll, 0);
                let joined = lines.join("\n");
                for term in [
                    "SESUAI",
                    "BERUBAH",
                    "HKCU",
                    "HKLM",
                    "UAC",
                    "Dry-Run",
                    "Rollback",
                    "Tamper Protection",
                    "StartupApproved",
                ] {
                    assert!(joined.contains(term), "missing glossary term `{term}`");
                }
            }
            other => panic!("expected ReportView modal, got {other:?}"),
        }

        app.handle_key(KeyCode::PageDown, &ops, &[]).unwrap();
        match &app.modal {
            Modal::ReportView { scroll, .. } => assert_eq!(*scroll, 10),
            other => panic!("expected ReportView modal after PageDown, got {other:?}"),
        }
        app.handle_key(KeyCode::PageUp, &ops, &[]).unwrap();
        match &app.modal {
            Modal::ReportView { scroll, .. } => assert_eq!(*scroll, 0),
            other => panic!("expected ReportView modal after PageUp, got {other:?}"),
        }

        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        term.draw(|f| draw_ui(f, &app, &[])).unwrap();

        app.handle_key(KeyCode::Esc, &ops, &[]).unwrap();
        assert!(matches!(app.modal, Modal::None));
    }

    #[test]
    fn tui_notifications_render_below_system_profile_without_overwriting_controls() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let ops = FakeSystemOps::default();
        let dir = std::env::temp_dir().join(format!("it-tools-tui-notif-{}", std::process::id()));
        let rules = crate::rules::all_rules();
        let mut app = TuiApp::new(
            &ops,
            &rules,
            ProfileConfig::embedded_default(),
            dir.join("it-tools.toml"),
            dir.clone(),
            vec![],
        )
        .unwrap();

        app.handle_key(KeyCode::Char('r'), &ops, &rules).unwrap();
        assert_eq!(app.notification_level, NotificationLevel::Success);

        let mut term = Terminal::new(TestBackend::new(110, 32)).unwrap();
        term.draw(|f| draw_ui(f, &app, &rules)).unwrap();
        let buf = term.backend().buffer().clone();
        let rows: Vec<String> = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        let find_row = |needle: &str| -> usize {
            rows.iter()
                .position(|r| r.contains(needle))
                .unwrap_or_else(|| {
                    panic!("missing `{needle}` in rendered UI:\n{}", rows.join("\n"))
                })
        };
        let sys_y = find_row("Sistem & Profil");
        let notif_y = find_row("Notifikasi");
        let mod_y = find_row("Modul Pengamanan");
        let ctrl_y = find_row("Kontrol");
        assert!(sys_y < notif_y && notif_y < mod_y && mod_y < ctrl_y);
        assert!(rows[notif_y + 1].contains("BERHASIL"));
        assert!(rows[notif_y + 1].contains("Pemeriksaan kepatuhan berhasil disegarkan."));

        let ctrl_block = rows[ctrl_y..].join("\n");
        assert!(ctrl_block.contains("[Spasi] Aktif"));
        assert!(ctrl_block.contains("[d] Dok"));
        assert!(ctrl_block.contains("[q] Keluar"));

        app.handle_key(KeyCode::Char(' '), &ops, &rules).unwrap();
        assert_eq!(app.notification_level, NotificationLevel::Info);
        term.draw(|f| draw_ui(f, &app, &rules)).unwrap();
        let buf2 = term.backend().buffer().clone();
        let rows2: Vec<String> = (0..buf2.area.height)
            .map(|y| {
                (0..buf2.area.width)
                    .map(|x| buf2[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        assert!(rows2[notif_y + 1].contains("INFO"));
        assert!(rows2[notif_y + 1].contains("dinonaktifkan"));
        assert!(rows2[ctrl_y..].join("\n").contains("[Spasi] Aktif"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tui_v_then_u_downloads_verifies_sha256_and_installs_update_on_beta_channel() {
        use crate::update::{backup_exe_path, sha256_hex};
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let ops = FakeSystemOps::default();
        let exe_path = ops.current_exe_path().unwrap();
        let old_exe = b"MZ_OLD_BETA_EXE_PAYLOAD_1234567890_PADDING_PADDING_PADDING_PADDING";
        ops.write_file(&exe_path, old_exe).unwrap();

        let mut new_exe = b"MZ_NEW_BETA_EXE_PORTABLE_V99".to_vec();
        new_exe.resize(128, 0x90);
        let new_sha = sha256_hex(&new_exe);
        let sums = format!("{new_sha}  it-tools.exe\n");
        let releases_json = r#"[{
            "tag_name": "v99.1.0-beta.5",
            "prerelease": true,
            "published_at": "2026-11-12T00:00:00Z",
            "html_url": "https://github.com/acme/it-tools/releases/tag/v99.1.0-beta.5",
            "body": "Beta 5 UAT build",
            "assets": [
                {"name": "it-tools.exe", "browser_download_url": "https://dl.example/beta5/it-tools.exe"},
                {"name": "SHA256SUMS.txt", "browser_download_url": "https://dl.example/beta5/SHA256SUMS.txt"}
            ]
        }]"#;
        {
            let mut st = ops.state.borrow_mut();
            st.http_responses.insert(
                "https://api.github.com/repos/acme/it-tools/releases?per_page=20".into(),
                (200, releases_json.as_bytes().to_vec()),
            );
            st.http_responses.insert(
                "https://dl.example/beta5/it-tools.exe".into(),
                (200, new_exe.clone()),
            );
            st.http_responses.insert(
                "https://dl.example/beta5/SHA256SUMS.txt".into(),
                (200, sums.into_bytes()),
            );
        }

        let mut cfg = ProfileConfig::embedded_default();
        cfg.update.repo = Some("acme/it-tools".into());
        cfg.update.allow_beta = true;
        let dir =
            std::env::temp_dir().join(format!("it-tools-tui-beta-upd-{}", std::process::id()));
        let mut app = TuiApp::new(&ops, &[], cfg, dir.join("it-tools.toml"), dir, vec![]).unwrap();

        app.handle_key(KeyCode::Char('v'), &ops, &[]).unwrap();
        assert_eq!(app.notification_level, NotificationLevel::Info);
        match &app.modal {
            Modal::ReportView {
                title,
                lines,
                update,
                ..
            } => {
                assert_eq!(title, "Versi & Pembaruan");
                assert!(update.is_some());
                assert!(lines.iter().any(|l| l.contains("99.1.0-beta.5")));
            }
            other => panic!("expected ReportView modal, got {other:?}"),
        }

        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        term.draw(|f| draw_ui(f, &app, &[])).unwrap();
        let buf = term.backend().buffer().clone();
        let rendered: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("[u] Unduh & Pasang"));

        app.handle_key(KeyCode::Char('u'), &ops, &[]).unwrap();
        assert_eq!(app.notification_level, NotificationLevel::Success);
        assert!(app.status_banner.contains("99.1.0-beta.5"));
        assert_eq!(ops.read_file_opt(&exe_path).unwrap().unwrap(), new_exe);
        assert_eq!(
            ops.read_file_opt(&backup_exe_path(&exe_path))
                .unwrap()
                .unwrap(),
            old_exe
        );
        match &app.modal {
            Modal::ReportView {
                title,
                lines,
                update,
                ..
            } => {
                assert_eq!(title, "Pembaruan Berhasil Dipasang");
                assert!(update.is_none());
                assert!(lines.iter().any(|l| l.contains("terverifikasi SHA256SUMS")));
            }
            other => panic!("expected installed ReportView modal, got {other:?}"),
        }

        app.handle_key(KeyCode::Esc, &ops, &[]).unwrap();
        assert!(matches!(app.modal, Modal::None));
    }

    #[test]
    fn tui_v_then_u_aborts_on_sha256_mismatch_and_keeps_existing_exe() {
        let ops = FakeSystemOps::default();
        let exe_path = ops.current_exe_path().unwrap();
        let original = b"MZ_ORIGINAL_SAFE_TUI_EXE_PADDING_PADDING_PADDING_PADDING_PADDING";
        ops.write_file(&exe_path, original).unwrap();

        let mut bad_exe = b"MZ_CORRUPTED".to_vec();
        bad_exe.resize(128, 0xAA);
        let wrong_sums =
            "0000000000000000000000000000000000000000000000000000000000000000  it-tools.exe\n";
        let release_json = r#"{
            "tag_name": "v99.0.0",
            "prerelease": false,
            "published_at": "2026-11-11T00:00:00Z",
            "html_url": "https://github.com/acme/it-tools/releases/tag/v99.0.0",
            "body": "Release notes",
            "assets": [
                {"name": "it-tools.exe", "browser_download_url": "https://dl.example/bad/it-tools.exe"},
                {"name": "SHA256SUMS.txt", "browser_download_url": "https://dl.example/bad/SHA256SUMS.txt"}
            ]
        }"#;
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
            st.http_responses
                .insert("https://dl.example/bad/it-tools.exe".into(), (200, bad_exe));
            st.http_responses.insert(
                "https://dl.example/bad/SHA256SUMS.txt".into(),
                (200, wrong_sums.as_bytes().to_vec()),
            );
        }

        let mut cfg = ProfileConfig::embedded_default();
        cfg.update.repo = Some("acme/it-tools".into());
        let dir = std::env::temp_dir().join(format!("it-tools-tui-bad-upd-{}", std::process::id()));
        let mut app = TuiApp::new(&ops, &[], cfg, dir.join("it-tools.toml"), dir, vec![]).unwrap();

        app.handle_key(KeyCode::Char('v'), &ops, &[]).unwrap();
        app.handle_key(KeyCode::Char('u'), &ops, &[]).unwrap();

        assert_eq!(app.notification_level, NotificationLevel::Error);
        assert!(app.status_banner.contains("SHA-256 verification failed"));
        assert_eq!(ops.read_file_opt(&exe_path).unwrap().unwrap(), original);
        match &app.modal {
            Modal::ReportView { title, lines, .. } => {
                assert_eq!(title, "Pembaruan Gagal");
                assert!(
                    lines
                        .iter()
                        .any(|l| l.contains("SHA-256 verification failed"))
                );
            }
            other => panic!("expected failed ReportView modal, got {other:?}"),
        }
    }
}
