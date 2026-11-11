use anyhow::Result;

use crate::backup::BackupSnapshot;
use crate::config::ProfileConfig;
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, RegValue, SystemOps};

const DESKTOP_PATH: &str = r"Control Panel\Desktop";

pub struct ScreensaverRule;

impl ScreensaverRule {
    fn desired_values(cfg: &ProfileConfig) -> [(&'static str, String); 4] {
        let ss = &cfg.rules.screensaver;
        [
            ("SCRNSAVE.EXE", ss.scr_exe.clone()),
            (
                "ScreenSaveActive",
                if ss.active { "1" } else { "0" }.to_string(),
            ),
            ("ScreenSaveTimeOut", ss.timeout_sec.to_string()),
            (
                "ScreenSaverIsSecure",
                if ss.require_logon { "1" } else { "0" }.to_string(),
            ),
        ]
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

impl Rule for ScreensaverRule {
    fn id(&self) -> &'static str {
        "screensaver"
    }

    fn title(&self) -> &'static str {
        "Screen Saver"
    }

    fn requires_admin(&self) -> bool {
        false
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.screensaver.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let mut diffs = Vec::new();
        for (name, target_str) in Self::desired_values(cfg) {
            let target = RegValue::Sz(target_str.clone());
            let current = ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, name)?;
            if current.as_ref() != Some(&target) {
                diffs.push(DiffItem {
                    field: format!(r"HKCU\{DESKTOP_PATH}\{name}"),
                    current: fmt_reg(current.as_ref()),
                    target: target_str,
                });
            }
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
        for (name, target_str) in Self::desired_values(cfg) {
            if snap.write_reg_with_backup(
                ops,
                RegHive::Hkcu,
                DESKTOP_PATH,
                name,
                RegValue::Sz(target_str.clone()),
            )? {
                changes.push(format!(r"HKCU\{DESKTOP_PATH}\{name} = {target_str}"));
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
    fn check_apply_idempotent_and_rollback() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let rule = ScreensaverRule;

        assert!(!rule.requires_admin());
        assert_eq!(rule.id(), "screensaver");
        assert!(rule.is_enabled(&cfg));

        ops.seed_reg(
            RegHive::Hkcu,
            DESKTOP_PATH,
            "ScreenSaveTimeOut",
            RegValue::Sz("900".into()),
        );

        let chk1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(chk1.status, CheckStatus::Drifted);
        assert_eq!(chk1.diffs.len(), 4);

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(changes.len(), 4);

        assert_eq!(
            ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, "SCRNSAVE.EXE")
                .unwrap(),
            Some(RegValue::Sz(r"%SystemRoot%\System32\scrnsave.scr".into()))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, "ScreenSaveActive")
                .unwrap(),
            Some(RegValue::Sz("1".into()))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, "ScreenSaveTimeOut")
                .unwrap(),
            Some(RegValue::Sz("300".into()))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, "ScreenSaverIsSecure")
                .unwrap(),
            Some(RegValue::Sz("1".into()))
        );

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
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, "ScreenSaveTimeOut")
                .unwrap(),
            Some(RegValue::Sz("900".into()))
        );
        assert!(
            ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, "SCRNSAVE.EXE")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn inactive_screensaver_sets_and_checks_zero() {
        let ops = FakeSystemOps::default();
        let mut cfg = ProfileConfig::embedded_default();
        cfg.rules.screensaver.active = false;
        cfg.rules.screensaver.require_logon = false;
        let rule = ScreensaverRule;

        let chk1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(chk1.status, CheckStatus::Drifted);

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, _) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);

        assert_eq!(
            ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, "ScreenSaveActive")
                .unwrap(),
            Some(RegValue::Sz("0".into()))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, "ScreenSaverIsSecure")
                .unwrap(),
            Some(RegValue::Sz("0".into()))
        );
        assert_eq!(
            rule.check(&ops, &cfg).unwrap().status,
            CheckStatus::Compliant
        );

        // Drift only ScreenSaveActive back to "1" and verify check detects it
        ops.seed_reg(
            RegHive::Hkcu,
            DESKTOP_PATH,
            "ScreenSaveActive",
            RegValue::Sz("1".into()),
        );
        let chk2 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(chk2.status, CheckStatus::Drifted);
        assert_eq!(chk2.diffs.len(), 1);
    }
}
