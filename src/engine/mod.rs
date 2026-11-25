pub mod report;

use std::path::Path;

use anyhow::Result;
use thiserror::Error;

use crate::backup::{BackupSnapshot, default_backup_path};
use crate::config::ProfileConfig;
use crate::platform::SystemOps;
use report::{CheckReport, CheckStatus, RuleCheck, RuleOutcome, RuleRunEntry, RunReport};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error(
        "Administrator privileges required to apply elevated rules (re-run from an elevated shell)"
    )]
    ElevationRequired,
}

#[derive(Debug, Clone, Default)]
pub struct UserTargetOptions {
    pub username: String,
    pub create_if_missing: bool,
    pub clear_dont_expire: bool,
    pub temp_password: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    pub dry_run: bool,
    pub strict: bool,
    pub no_backup: bool,
    pub restart_explorer: bool,
    pub only: Vec<String>,
    pub skip: Vec<String>,
    pub user_target: Option<UserTargetOptions>,
}

pub trait Rule {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn description(&self) -> &'static str {
        ""
    }
    fn requires_admin(&self) -> bool;
    fn is_enabled(&self, cfg: &ProfileConfig) -> bool;
    fn handles_user_target(&self) -> bool {
        false
    }
    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck>;
    fn apply(
        &self,
        ops: &dyn SystemOps,
        cfg: &ProfileConfig,
        opts: &ApplyOptions,
        snap: &mut BackupSnapshot,
    ) -> Result<(RuleOutcome, Vec<String>)>;
}

pub fn rule_selected(id: &str, cfg_enabled: bool, only: &[String], skip: &[String]) -> bool {
    if !only.is_empty() {
        return only.iter().any(|x| x.eq_ignore_ascii_case(id));
    }
    if skip.iter().any(|x| x.eq_ignore_ascii_case(id)) {
        return false;
    }
    cfg_enabled
}

pub fn check_rules(
    ops: &dyn SystemOps,
    cfg: &ProfileConfig,
    rules: &[Box<dyn Rule>],
    only: &[String],
    skip: &[String],
) -> Result<CheckReport> {
    let mut checks = Vec::new();
    let is_admin = ops.is_admin();
    for rule in rules {
        let enabled = rule_selected(rule.id(), rule.is_enabled(cfg), only, skip);
        if !enabled {
            continue;
        }
        let mut rc = match rule.check(ops, cfg) {
            Ok(c) => c,
            Err(err) => RuleCheck {
                id: rule.id().to_string(),
                title: rule.title().to_string(),
                requires_admin: rule.requires_admin(),
                enabled_in_config: true,
                status: if rule.requires_admin() && !is_admin {
                    CheckStatus::NeedsAdmin
                } else {
                    CheckStatus::Unsupported
                },
                diffs: Vec::new(),
                note: Some(err.to_string()),
            },
        };
        if rule.requires_admin() && !is_admin && rc.status != CheckStatus::Compliant {
            rc.status = CheckStatus::NeedsAdmin;
        }
        checks.push(rc);
    }
    Ok(CheckReport {
        os_caption: ops.os_caption(),
        is_admin,
        checks,
    })
}

pub fn apply_rules(
    ops: &dyn SystemOps,
    cfg: &ProfileConfig,
    rules: &[Box<dyn Rule>],
    opts: &ApplyOptions,
    backup_dir: &Path,
) -> Result<RunReport> {
    let selected: Vec<&Box<dyn Rule>> = rules
        .iter()
        .filter(|r| rule_selected(r.id(), r.is_enabled(cfg), &opts.only, &opts.skip))
        .collect();

    if opts.dry_run {
        let report = check_rules(ops, cfg, rules, &opts.only, &opts.skip)?;
        let entries = report
            .checks
            .into_iter()
            .map(|check| {
                let outcome = match check.status {
                    CheckStatus::Compliant => RuleOutcome::AlreadyCompliant,
                    CheckStatus::Drifted => RuleOutcome::Skipped {
                        reason: format!("dry-run ({} diffs)", check.diffs.len()),
                    },
                    CheckStatus::NeedsAdmin => RuleOutcome::Skipped {
                        reason: if check.diffs.is_empty() {
                            "dry-run (requires Administrator)".into()
                        } else {
                            format!(
                                "dry-run ({} diffs; requires Administrator)",
                                check.diffs.len()
                            )
                        },
                    },
                    CheckStatus::Unsupported => RuleOutcome::Skipped {
                        reason: check.note.unwrap_or_else(|| "dry-run (unsupported)".into()),
                    },
                };
                let changes = check
                    .diffs
                    .into_iter()
                    .map(|d| format!("{}: {} -> {}", d.field, d.current, d.target))
                    .collect();
                RuleRunEntry {
                    id: check.id,
                    title: check.title,
                    outcome,
                    changes,
                }
            })
            .collect();
        return Ok(RunReport {
            mode: "dry-run".into(),
            os_caption: report.os_caption,
            backup_file: None,
            entries,
        });
    }

    if opts.user_target.is_some() && !selected.iter().any(|r| r.handles_user_target()) {
        anyhow::bail!(
            "Target akun lokal (--target-user / --create-user / [u]) membutuhkan modul 'password_policy' dalam keadaan aktif dan termasuk dalam cakupan eksekusi."
        );
    }

    if !ops.is_admin() && selected.iter().any(|r| r.requires_admin()) {
        return Err(EngineError::ElevationRequired.into());
    }

    let mut snap = BackupSnapshot::new(ops);
    let snap_path = default_backup_path(backup_dir, &ops.local_timestamp_compact());
    let mut entries = Vec::new();
    let mut touched_ui = false;
    let mut touched_taskbar = false;

    for rule in selected {
        match rule.apply(ops, cfg, opts, &mut snap) {
            Ok((outcome, mut changes)) => {
                if matches!(outcome, RuleOutcome::Applied) {
                    if matches!(
                        rule.id(),
                        "visual_effects" | "screensaver" | "accessibility" | "typing" | "search"
                    ) {
                        touched_ui = true;
                    }
                    if matches!(rule.id(), "taskbar" | "search") {
                        touched_ui = true;
                        touched_taskbar = true;
                        if rule.id() == "taskbar" && !opts.restart_explorer {
                            changes.push(
                                "catatan: aktifkan [RESTART: ON] / --restart-explorer atau muat ulang explorer.exe agar perubahan taskbar langsung terlihat"
                                    .into(),
                            );
                        }
                    }
                }
                if !opts.no_backup && !snap.is_empty() {
                    snap.save_to_path(&snap_path)?;
                }
                entries.push(RuleRunEntry {
                    id: rule.id().to_string(),
                    title: rule.title().to_string(),
                    outcome,
                    changes,
                });
            }
            Err(err) => {
                if !opts.no_backup && !snap.is_empty() {
                    let _ = snap.save_to_path(&snap_path);
                }
                entries.push(RuleRunEntry {
                    id: rule.id().to_string(),
                    title: rule.title().to_string(),
                    outcome: RuleOutcome::Failed {
                        error: err.to_string(),
                    },
                    changes: Vec::new(),
                });
                if opts.strict {
                    break;
                }
            }
        }
    }

    if touched_ui {
        let _ = ops.broadcast_setting_change();
    }
    if touched_taskbar && opts.restart_explorer {
        let _ = ops.restart_explorer();
    }

    let saved_backup = if !opts.no_backup && !snap.is_empty() {
        snap.save_to_path(&snap_path)?;
        Some(snap_path)
    } else {
        None
    };

    Ok(RunReport {
        mode: "apply".into(),
        os_caption: ops.os_caption(),
        backup_file: saved_backup,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProfileConfig;
    use crate::platform::fake::FakeSystemOps;
    use crate::platform::{RegHive, RegValue, SystemOps};

    #[test]
    fn dry_run_does_not_mutate_ops_or_write_backup_file() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let dir = std::env::temp_dir().join(format!("it-tools-eng-dry-{}", std::process::id()));
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(DummyRegRule { needs_admin: false })];
        let report = apply_rules(
            &ops,
            &cfg,
            &rules,
            &ApplyOptions {
                dry_run: true,
                ..Default::default()
            },
            &dir,
        )
        .unwrap();
        assert_eq!(report.entries.len(), 1);
        assert!(!dir.exists());
        assert!(
            ops.reg_read(RegHive::Hkcu, "Software\\Dummy", "Val")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn non_admin_rejects_elevated_rule_but_allows_hkcu_only_rule() {
        let ops = FakeSystemOps::default();
        ops.state.borrow_mut().admin = false;
        let cfg = ProfileConfig::embedded_default();
        let dir = std::env::temp_dir().join(format!("it-tools-eng-uac-{}", std::process::id()));

        let elevated: Vec<Box<dyn Rule>> = vec![Box::new(DummyRegRule { needs_admin: true })];
        let err = apply_rules(&ops, &cfg, &elevated, &ApplyOptions::default(), &dir).unwrap_err();
        assert!(err.downcast_ref::<EngineError>().is_some());

        let hkcu_only: Vec<Box<dyn Rule>> = vec![Box::new(DummyRegRule { needs_admin: false })];
        let rep = apply_rules(&ops, &cfg, &hkcu_only, &ApplyOptions::default(), &dir).unwrap();
        assert_eq!(rep.exit_code(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_then_rollback_restores_absent_and_present_values() {
        let ops = FakeSystemOps::default();
        ops.seed_reg(
            RegHive::Hkcu,
            "Software\\Dummy",
            "Existing",
            RegValue::Dword(99),
        );
        let cfg = ProfileConfig::embedded_default();
        let dir = std::env::temp_dir().join(format!("it-tools-eng-rb-{}", std::process::id()));
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(DummyRegRule { needs_admin: false })];

        let report = apply_rules(&ops, &cfg, &rules, &ApplyOptions::default(), &dir).unwrap();
        let snap_path = report.backup_file.clone().expect("backup file saved");
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, "Software\\Dummy", "Existing")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, "Software\\Dummy", "Val")
                .unwrap(),
            Some(RegValue::Dword(1))
        );

        let snap = crate::backup::BackupSnapshot::load_from_file(&snap_path).unwrap();
        crate::backup::rollback_snapshot(&ops, &snap).unwrap();
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, "Software\\Dummy", "Existing")
                .unwrap(),
            Some(RegValue::Dword(99))
        );
        assert!(
            ops.reg_read(RegHive::Hkcu, "Software\\Dummy", "Val")
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct DummyRegRule {
        needs_admin: bool,
    }

    impl Rule for DummyRegRule {
        fn id(&self) -> &'static str {
            "dummy"
        }
        fn title(&self) -> &'static str {
            "Dummy Rule"
        }
        fn requires_admin(&self) -> bool {
            self.needs_admin
        }
        fn is_enabled(&self, _cfg: &ProfileConfig) -> bool {
            true
        }
        fn check(
            &self,
            ops: &dyn SystemOps,
            _cfg: &ProfileConfig,
        ) -> anyhow::Result<report::RuleCheck> {
            let v = ops.reg_read(RegHive::Hkcu, "Software\\Dummy", "Val")?;
            let drifted = v != Some(RegValue::Dword(1));
            Ok(report::RuleCheck {
                id: self.id().to_string(),
                title: self.title().to_string(),
                requires_admin: self.needs_admin,
                enabled_in_config: true,
                status: if drifted {
                    report::CheckStatus::Drifted
                } else {
                    report::CheckStatus::Compliant
                },
                diffs: vec![],
                note: None,
            })
        }
        fn apply(
            &self,
            ops: &dyn SystemOps,
            _cfg: &ProfileConfig,
            _opts: &ApplyOptions,
            snap: &mut crate::backup::BackupSnapshot,
        ) -> anyhow::Result<(report::RuleOutcome, Vec<String>)> {
            snap.write_reg_with_backup(
                ops,
                RegHive::Hkcu,
                "Software\\Dummy",
                "Existing",
                RegValue::Dword(0),
            )?;
            snap.write_reg_with_backup(
                ops,
                RegHive::Hkcu,
                "Software\\Dummy",
                "Val",
                RegValue::Dword(1),
            )?;
            Ok((report::RuleOutcome::Applied, vec!["set Val=1".into()]))
        }
    }

    #[test]
    fn user_target_errors_when_no_selected_rule_handles_it() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let dir = std::env::temp_dir().join(format!("it-tools-eng-ut-{}", std::process::id()));
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(DummyRegRule { needs_admin: false })];
        let opts = ApplyOptions {
            user_target: Some(UserTargetOptions {
                username: "StaffUser".into(),
                create_if_missing: true,
                clear_dont_expire: true,
                temp_password: Some("TempPass!1".into()),
            }),
            ..Default::default()
        };
        let err = apply_rules(&ops, &cfg, &rules, &opts, &dir).unwrap_err();
        assert!(err.to_string().contains("password_policy"));
    }

    #[test]
    fn typing_and_search_trigger_broadcast_and_search_restarts_explorer_when_enabled() {
        let ops = FakeSystemOps::default();
        ops.state.borrow_mut().admin = true;
        let cfg = ProfileConfig::embedded_default();
        let dir = std::env::temp_dir().join(format!("it-tools-eng-ui-{}", std::process::id()));
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(crate::rules::typing::TypingRule),
            Box::new(crate::rules::search::SearchRule),
        ];

        let typing_opts = ApplyOptions {
            no_backup: true,
            only: vec!["typing".into()],
            ..Default::default()
        };
        apply_rules(&ops, &cfg, &rules, &typing_opts, &dir).unwrap();
        assert_eq!(ops.state.borrow().broadcasts, 1);
        assert_eq!(ops.state.borrow().explorer_restarts, 0);

        let search_opts = ApplyOptions {
            no_backup: true,
            restart_explorer: true,
            only: vec!["search".into()],
            ..Default::default()
        };
        apply_rules(&ops, &cfg, &rules, &search_opts, &dir).unwrap();
        assert_eq!(ops.state.borrow().broadcasts, 2);
        assert_eq!(ops.state.borrow().explorer_restarts, 1);
    }

    #[test]
    fn taskbar_without_restart_explorer_skips_restart_and_adds_hint() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let dir = std::env::temp_dir().join(format!("it-tools-eng-tb-{}", std::process::id()));
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(crate::rules::taskbar::TaskbarRule)];

        let opts = ApplyOptions {
            no_backup: true,
            restart_explorer: false,
            only: vec!["taskbar".into()],
            ..Default::default()
        };
        let report = apply_rules(&ops, &cfg, &rules, &opts, &dir).unwrap();
        assert_eq!(ops.state.borrow().broadcasts, 1);
        assert_eq!(ops.state.borrow().explorer_restarts, 0);
        let entry = report.entries.iter().find(|e| e.id == "taskbar").unwrap();
        assert!(
            entry
                .changes
                .iter()
                .any(|c| c.to_ascii_lowercase().contains("explorer"))
        );
    }
}
