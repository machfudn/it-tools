use anyhow::Result;

use crate::backup::BackupSnapshot;
use crate::config::ProfileConfig;
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, RegValue, SystemOps};

const KEYBOARD_PATH: &str = r"Control Panel\Keyboard";
const PRINTSCREEN_VAL: &str = "PrintScreenKeyForSnippingEnabled";

pub struct AccessibilityRule;

fn fmt_reg(val: Option<&RegValue>) -> String {
    match val {
        None => "(absent)".to_string(),
        Some(RegValue::Dword(v)) => v.to_string(),
        Some(RegValue::Sz(s)) | Some(RegValue::ExpandSz(s)) => s.clone(),
        Some(RegValue::BinaryHex(h)) => format!("hex:{h}"),
    }
}

impl Rule for AccessibilityRule {
    fn id(&self) -> &'static str {
        "accessibility"
    }

    fn title(&self) -> &'static str {
        "Accessibility"
    }

    fn requires_admin(&self) -> bool {
        false
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.accessibility.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let target_num = if cfg.rules.accessibility.printscreen_snipping {
            1
        } else {
            0
        };
        let target = RegValue::Dword(target_num);
        let current = ops.reg_read(RegHive::Hkcu, KEYBOARD_PATH, PRINTSCREEN_VAL)?;
        let diffs = if current.as_ref() != Some(&target) {
            vec![DiffItem {
                field: format!(r"HKCU\{KEYBOARD_PATH}\{PRINTSCREEN_VAL}"),
                current: fmt_reg(current.as_ref()),
                target: target_num.to_string(),
            }]
        } else {
            Vec::new()
        };

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
        let target_num = if cfg.rules.accessibility.printscreen_snipping {
            1
        } else {
            0
        };
        let mut changes = Vec::new();
        if snap.write_reg_with_backup(
            ops,
            RegHive::Hkcu,
            KEYBOARD_PATH,
            PRINTSCREEN_VAL,
            RegValue::Dword(target_num),
        )? {
            changes.push(format!(
                r"HKCU\{KEYBOARD_PATH}\{PRINTSCREEN_VAL} = {target_num}"
            ));
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
        let rule = AccessibilityRule;

        assert!(!rule.requires_admin());
        assert_eq!(rule.id(), "accessibility");
        assert!(rule.is_enabled(&cfg));

        ops.seed_reg(
            RegHive::Hkcu,
            KEYBOARD_PATH,
            PRINTSCREEN_VAL,
            RegValue::Dword(1),
        );

        let chk1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(chk1.status, CheckStatus::Drifted);
        assert_eq!(chk1.diffs.len(), 1);

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(changes.len(), 1);
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, KEYBOARD_PATH, PRINTSCREEN_VAL)
                .unwrap(),
            Some(RegValue::Dword(0))
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
            ops.reg_read(RegHive::Hkcu, KEYBOARD_PATH, PRINTSCREEN_VAL)
                .unwrap(),
            Some(RegValue::Dword(1))
        );
    }

    #[test]
    fn enables_printscreen_snipping_when_configured() {
        let ops = FakeSystemOps::default();
        let mut cfg = ProfileConfig::embedded_default();
        cfg.rules.accessibility.printscreen_snipping = true;
        let rule = AccessibilityRule;

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, _) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, KEYBOARD_PATH, PRINTSCREEN_VAL)
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            rule.check(&ops, &cfg).unwrap().status,
            CheckStatus::Compliant
        );

        rollback_snapshot(&ops, &snap).unwrap();
        assert!(
            ops.reg_read(RegHive::Hkcu, KEYBOARD_PATH, PRINTSCREEN_VAL)
                .unwrap()
                .is_none()
        );
    }
}
