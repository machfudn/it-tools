use anyhow::Result;

use crate::backup::BackupSnapshot;
use crate::config::ProfileConfig;
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, RegValue, SystemOps, encode_hex};

const TABLET_TIP_PATH: &str = r"Software\Microsoft\TabletTip\1.7";
const INPUT_SETTINGS_PATH: &str = r"Software\Microsoft\input\Settings";
const INPUT_TIPC_PATH: &str = r"Software\Microsoft\Input\TIPC";
const INPUT_PERS_PATH: &str = r"Software\Microsoft\InputPersonalization";
const TRAINED_STORE_PATH: &str = r"Software\Microsoft\InputPersonalization\TrainedDataStore";
const TYPING_INSIGHTS_PATH: &str = r"Software\Microsoft\input\TypingInsights";

pub struct TypingRule;

impl TypingRule {
    fn desired_dwords(cfg: &ProfileConfig) -> Vec<(&'static str, &'static str, u32)> {
        let t = &cfg.rules.typing;
        let b = |v: bool| if v { 1 } else { 0 };
        vec![
            (TABLET_TIP_PATH, "EnableAutocorrection", b(t.autocorrect)),
            (
                INPUT_SETTINGS_PATH,
                "EnableAutocorrection",
                b(t.autocorrect),
            ),
            (
                INPUT_SETTINGS_PATH,
                "EnableHwkbTextPrediction",
                b(t.text_prediction),
            ),
            (
                INPUT_SETTINGS_PATH,
                "IsVoiceTypingKeyEnabled",
                b(t.voice_typing_key),
            ),
            (
                INPUT_SETTINGS_PATH,
                "MultilingualEnabled",
                b(t.multilingual),
            ),
            (
                INPUT_SETTINGS_PATH,
                "EnableAutoShiftEngage",
                b(t.auto_shift),
            ),
            (
                INPUT_SETTINGS_PATH,
                "EnableDoubleTapSpace",
                b(t.double_tap_space),
            ),
            (
                INPUT_TIPC_PATH,
                "Enabled",
                b(t.highlight_misspelled || t.autocorrect),
            ),
            (
                INPUT_PERS_PATH,
                "RestrictImplicitInkCollection",
                b(!t.typing_insights),
            ),
            (
                INPUT_PERS_PATH,
                "RestrictImplicitTextCollection",
                b(!t.typing_insights),
            ),
            (TRAINED_STORE_PATH, "HarvestContacts", b(t.typing_insights)),
        ]
    }

    fn desired_insights_bytes(
        current: Option<&RegValue>,
        typing_insights: bool,
    ) -> Option<Vec<u8>> {
        if typing_insights {
            return None;
        }
        match current.and_then(|v| v.as_bytes()) {
            Some(bytes) if !bytes.is_empty() => {
                if bytes[0] == 0 {
                    None
                } else {
                    let mut next = bytes;
                    next[0] = 0;
                    Some(next)
                }
            }
            _ => Some(vec![0, 0, 0, 0]),
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

impl Rule for TypingRule {
    fn id(&self) -> &'static str {
        "typing"
    }

    fn title(&self) -> &'static str {
        "Typing"
    }

    fn requires_admin(&self) -> bool {
        false
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.typing.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let mut diffs = Vec::new();
        for (path, name, target_num) in Self::desired_dwords(cfg) {
            let target = RegValue::Dword(target_num);
            let current = ops.reg_read(RegHive::Hkcu, path, name)?;
            if current.as_ref() != Some(&target) {
                diffs.push(DiffItem {
                    field: format!(r"HKCU\{path}\{name}"),
                    current: fmt_reg(current.as_ref()),
                    target: target_num.to_string(),
                });
            }
        }

        let cur_insights = ops.reg_read(RegHive::Hkcu, TYPING_INSIGHTS_PATH, "Insights")?;
        if let Some(target_bytes) =
            Self::desired_insights_bytes(cur_insights.as_ref(), cfg.rules.typing.typing_insights)
        {
            diffs.push(DiffItem {
                field: format!(r"HKCU\{TYPING_INSIGHTS_PATH}\Insights"),
                current: fmt_reg(cur_insights.as_ref()),
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
        for (path, name, target_num) in Self::desired_dwords(cfg) {
            if snap.write_reg_with_backup(
                ops,
                RegHive::Hkcu,
                path,
                name,
                RegValue::Dword(target_num),
            )? {
                changes.push(format!(r"HKCU\{path}\{name} = {target_num}"));
            }
        }

        let cur_insights = ops.reg_read(RegHive::Hkcu, TYPING_INSIGHTS_PATH, "Insights")?;
        if let Some(target_bytes) =
            Self::desired_insights_bytes(cur_insights.as_ref(), cfg.rules.typing.typing_insights)
        {
            let target_val = RegValue::binary(&target_bytes);
            let desc = fmt_reg(Some(&target_val));
            if snap.write_reg_with_backup(
                ops,
                RegHive::Hkcu,
                TYPING_INSIGHTS_PATH,
                "Insights",
                target_val,
            )? {
                changes.push(format!(r"HKCU\{TYPING_INSIGHTS_PATH}\Insights = {desc}"));
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
    fn check_apply_idempotent_and_rollback_with_existing_insights() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let rule = TypingRule;

        assert!(!rule.requires_admin());
        assert_eq!(rule.id(), "typing");
        assert!(rule.is_enabled(&cfg));

        ops.seed_reg(
            RegHive::Hkcu,
            TYPING_INSIGHTS_PATH,
            "Insights",
            RegValue::binary(&[0x01, 0x05, 0x00, 0x00]),
        );
        ops.seed_reg(
            RegHive::Hkcu,
            INPUT_SETTINGS_PATH,
            "EnableAutocorrection",
            RegValue::Dword(1),
        );

        let chk1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(chk1.status, CheckStatus::Drifted);
        assert_eq!(chk1.diffs.len(), 12);

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(changes.len(), 12);

        assert_eq!(
            ops.reg_read(RegHive::Hkcu, TABLET_TIP_PATH, "EnableAutocorrection")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, INPUT_TIPC_PATH, "Enabled")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(
                RegHive::Hkcu,
                INPUT_PERS_PATH,
                "RestrictImplicitInkCollection"
            )
            .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(
                RegHive::Hkcu,
                INPUT_PERS_PATH,
                "RestrictImplicitTextCollection"
            )
            .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, TRAINED_STORE_PATH, "HarvestContacts")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, TYPING_INSIGHTS_PATH, "Insights")
                .unwrap()
                .unwrap()
                .as_bytes()
                .unwrap(),
            vec![0x00, 0x05, 0x00, 0x00]
        );

        let chk2 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(chk2.status, CheckStatus::Compliant);
        assert!(chk2.diffs.is_empty());

        let (outcome2, changes2) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome2, RuleOutcome::AlreadyCompliant);
        assert!(changes2.is_empty());

        rollback_snapshot(&ops, &snap).unwrap();
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, TYPING_INSIGHTS_PATH, "Insights")
                .unwrap(),
            Some(RegValue::binary(&[0x01, 0x05, 0x00, 0x00]))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, INPUT_SETTINGS_PATH, "EnableAutocorrection")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert!(
            ops.reg_read(RegHive::Hkcu, INPUT_TIPC_PATH, "Enabled")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn absent_insights_writes_zeros_and_highlight_enables_tipc() {
        let ops = FakeSystemOps::default();
        let mut cfg = ProfileConfig::embedded_default();
        cfg.rules.typing.highlight_misspelled = true;
        let rule = TypingRule;

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, _) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);

        assert_eq!(
            ops.reg_read(RegHive::Hkcu, INPUT_TIPC_PATH, "Enabled")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, TYPING_INSIGHTS_PATH, "Insights")
                .unwrap(),
            Some(RegValue::binary(&[0, 0, 0, 0]))
        );
        assert_eq!(
            rule.check(&ops, &cfg).unwrap().status,
            CheckStatus::Compliant
        );
    }

    #[test]
    fn typing_insights_true_leaves_insights_untouched() {
        let ops = FakeSystemOps::default();
        let mut cfg = ProfileConfig::embedded_default();
        cfg.rules.typing.typing_insights = true;
        let rule = TypingRule;

        let mut snap = BackupSnapshot::new(&ops);
        rule.apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();

        assert!(
            ops.reg_read(RegHive::Hkcu, TYPING_INSIGHTS_PATH, "Insights")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, TRAINED_STORE_PATH, "HarvestContacts")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(
                RegHive::Hkcu,
                INPUT_PERS_PATH,
                "RestrictImplicitInkCollection"
            )
            .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            rule.check(&ops, &cfg).unwrap().status,
            CheckStatus::Compliant
        );
    }
}
