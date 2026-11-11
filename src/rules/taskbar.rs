use anyhow::Result;

use crate::backup::BackupSnapshot;
use crate::config::{ProfileConfig, TaskbarAlignment};
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, RegValue, SystemOps, encode_hex};

const ADVANCED_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
const STUCK_RECTS_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3";

pub struct TaskbarRule;

impl TaskbarRule {
    fn desired_dwords(cfg: &ProfileConfig) -> [(&'static str, u32); 4] {
        let tb = &cfg.rules.taskbar;
        let b = |v: bool| if v { 1 } else { 0 };
        let align = match tb.alignment {
            TaskbarAlignment::Left => 0,
            TaskbarAlignment::Center => 1,
        };
        [
            ("TaskbarDa", b(tb.widgets)),
            ("TaskbarAl", align),
            ("TaskbarBadges", b(tb.show_badges)),
            ("TaskbarFlashing", b(tb.show_flashing)),
        ]
    }

    fn desired_stuck_rects(current: Option<&RegValue>, auto_hide: bool) -> Option<Vec<u8>> {
        if let Some(bytes) = current.and_then(|v| v.as_bytes()) {
            let mut next = bytes.clone();
            if next.len() < 9 {
                next.resize(9, 0);
            }
            if auto_hide {
                next[8] |= 0x01;
            } else {
                next[8] &= !0x01;
            }
            if next == bytes { None } else { Some(next) }
        } else {
            let mut next = vec![0u8; 48];
            next[0] = 0x30;
            next[4] = 0xfe;
            next[5] = 0xff;
            next[6] = 0xff;
            next[7] = 0xff;
            next[8] = if auto_hide { 0x03 } else { 0x02 };
            Some(next)
        }
    }
}

fn fmt_reg(val: Option<&RegValue>) -> String {
    match val {
        None => "(absent)".to_string(),
        Some(RegValue::Dword(v)) => v.to_string(),
        Some(RegValue::Sz(s)) | Some(RegValue::ExpandSz(s)) => s.clone(),
        Some(RegValue::BinaryHex(h)) => format!("hex:{h}"),
    }
}

impl Rule for TaskbarRule {
    fn id(&self) -> &'static str {
        "taskbar"
    }

    fn title(&self) -> &'static str {
        "Taskbar"
    }

    fn requires_admin(&self) -> bool {
        false
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.taskbar.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let mut diffs = Vec::new();
        for (name, target_num) in Self::desired_dwords(cfg) {
            let target = RegValue::Dword(target_num);
            let current = ops.reg_read(RegHive::Hkcu, ADVANCED_PATH, name)?;
            if current.as_ref() != Some(&target) {
                diffs.push(DiffItem {
                    field: format!(r"HKCU\{ADVANCED_PATH}\{name}"),
                    current: fmt_reg(current.as_ref()),
                    target: target_num.to_string(),
                });
            }
        }

        let cur_rects = ops.reg_read(RegHive::Hkcu, STUCK_RECTS_PATH, "Settings")?;
        if let Some(target_bytes) =
            Self::desired_stuck_rects(cur_rects.as_ref(), cfg.rules.taskbar.auto_hide)
        {
            diffs.push(DiffItem {
                field: format!(r"HKCU\{STUCK_RECTS_PATH}\Settings"),
                current: fmt_reg(cur_rects.as_ref()),
                target: format!("hex:{}", encode_hex(&target_bytes)),
            });
        }

        Ok(RuleCheck {
            id: self.id().to_string(),
            title: self.title().to_string(),
            requires_admin: self.requires_admin(),
            enabled_in_config: self.is_enabled(cfg),
            status: if diffs.is_empty() {
                CheckStatus::Compliant
            } else {
                CheckStatus::Drifted
            },
            diffs,
            note: None,
        })
    }

    fn apply(
        &self,
        ops: &dyn SystemOps,
        cfg: &ProfileConfig,
        _opts: &ApplyOptions,
        snap: &mut BackupSnapshot,
    ) -> Result<(RuleOutcome, Vec<String>)> {
        let mut changes = Vec::new();
        for (name, target_num) in Self::desired_dwords(cfg) {
            if snap.write_reg_with_backup(
                ops,
                RegHive::Hkcu,
                ADVANCED_PATH,
                name,
                RegValue::Dword(target_num),
            )? {
                changes.push(format!(r"HKCU\{ADVANCED_PATH}\{name} = {target_num}"));
            }
        }

        let cur_rects = ops.reg_read(RegHive::Hkcu, STUCK_RECTS_PATH, "Settings")?;
        if let Some(target_bytes) =
            Self::desired_stuck_rects(cur_rects.as_ref(), cfg.rules.taskbar.auto_hide)
        {
            let target_val = RegValue::binary(&target_bytes);
            let desc = fmt_reg(Some(&target_val));
            if snap.write_reg_with_backup(
                ops,
                RegHive::Hkcu,
                STUCK_RECTS_PATH,
                "Settings",
                target_val,
            )? {
                changes.push(format!(r"HKCU\{STUCK_RECTS_PATH}\Settings = {desc}"));
            }
        }

        if changes.is_empty() {
            Ok((RuleOutcome::AlreadyCompliant, Vec::new()))
        } else {
            Ok((RuleOutcome::Applied, changes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::rollback_snapshot;
    use crate::platform::fake::FakeSystemOps;

    #[test]
    fn check_apply_idempotent_and_rollback_absent_stuck_rects() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let rule = TaskbarRule;

        assert!(!rule.requires_admin());
        assert_eq!(rule.id(), "taskbar");
        assert!(rule.is_enabled(&cfg));

        let chk1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(chk1.status, CheckStatus::Drifted);
        assert_eq!(chk1.diffs.len(), 5);

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(changes.len(), 5);

        assert_eq!(
            ops.reg_read(RegHive::Hkcu, ADVANCED_PATH, "TaskbarDa")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, ADVANCED_PATH, "TaskbarAl")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, ADVANCED_PATH, "TaskbarBadges")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, ADVANCED_PATH, "TaskbarFlashing")
                .unwrap(),
            Some(RegValue::Dword(0))
        );

        let rects = ops
            .reg_read(RegHive::Hkcu, STUCK_RECTS_PATH, "Settings")
            .unwrap()
            .unwrap()
            .as_bytes()
            .unwrap();
        assert_eq!(rects.len(), 48);
        assert_eq!(&rects[..9], &[0x30, 0, 0, 0, 0xfe, 0xff, 0xff, 0xff, 0x03]);
        assert!(rects[9..].iter().all(|&b| b == 0));

        assert_eq!(
            rule.check(&ops, &cfg).unwrap().status,
            CheckStatus::Compliant
        );

        let (outcome2, changes2) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome2, RuleOutcome::AlreadyCompliant);
        assert!(changes2.is_empty());

        rollback_snapshot(&ops, &snap).unwrap();
        assert!(
            ops.reg_read(RegHive::Hkcu, STUCK_RECTS_PATH, "Settings")
                .unwrap()
                .is_none()
        );
        assert!(
            ops.reg_read(RegHive::Hkcu, ADVANCED_PATH, "TaskbarAl")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn existing_stuck_rects_preserves_other_bytes_and_handles_center_no_autohide() {
        let ops = FakeSystemOps::default();
        let mut cfg = ProfileConfig::embedded_default();
        cfg.rules.taskbar.alignment = TaskbarAlignment::Center;
        cfg.rules.taskbar.auto_hide = false;
        cfg.rules.taskbar.widgets = true;
        let rule = TaskbarRule;

        let mut existing = vec![0u8; 48];
        existing[0] = 0x30;
        existing[8] = 0x7B; // bit 0x01 set alongside other flags
        existing[12] = 0x2A;
        ops.seed_reg(
            RegHive::Hkcu,
            STUCK_RECTS_PATH,
            "Settings",
            RegValue::binary(&existing),
        );

        let mut snap = BackupSnapshot::new(&ops);
        rule.apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();

        assert_eq!(
            ops.reg_read(RegHive::Hkcu, ADVANCED_PATH, "TaskbarAl")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, ADVANCED_PATH, "TaskbarDa")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        let updated = ops
            .reg_read(RegHive::Hkcu, STUCK_RECTS_PATH, "Settings")
            .unwrap()
            .unwrap()
            .as_bytes()
            .unwrap();
        assert_eq!(updated[8], 0x7A);
        assert_eq!(updated[12], 0x2A);
        assert_eq!(
            rule.check(&ops, &cfg).unwrap().status,
            CheckStatus::Compliant
        );

        rollback_snapshot(&ops, &snap).unwrap();
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, STUCK_RECTS_PATH, "Settings")
                .unwrap(),
            Some(RegValue::binary(&existing))
        );
    }

    #[test]
    fn short_stuck_rects_is_extended_to_at_least_9_bytes() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let rule = TaskbarRule;

        ops.seed_reg(
            RegHive::Hkcu,
            STUCK_RECTS_PATH,
            "Settings",
            RegValue::binary(&[0x30, 0x00, 0x00, 0x00]),
        );

        let mut snap = BackupSnapshot::new(&ops);
        rule.apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        let updated = ops
            .reg_read(RegHive::Hkcu, STUCK_RECTS_PATH, "Settings")
            .unwrap()
            .unwrap()
            .as_bytes()
            .unwrap();
        assert_eq!(updated.len(), 9);
        assert_eq!(updated[8], 0x01);
        assert_eq!(
            rule.check(&ops, &cfg).unwrap().status,
            CheckStatus::Compliant
        );
    }
}
