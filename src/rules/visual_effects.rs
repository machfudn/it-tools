use anyhow::Result;

use crate::backup::BackupSnapshot;
use crate::config::ProfileConfig;
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, RegValue, SystemOps, encode_hex};

const PERSONALIZE_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
const VISUAL_FX_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects";
const WINDOW_METRICS_PATH: &str = r"Control Panel\Desktop\WindowMetrics";
const ADVANCED_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
const DESKTOP_PATH: &str = r"Control Panel\Desktop";

const VISUAL_FX_SUBKEYS: &[&str] = &[
    "AnimateMinMax",
    "ControlAnimations",
    "MenuAnimation",
    "SelectionFade",
    "TaskbarAnimations",
    "TooltipAnimation",
    "ComboBoxAnimation",
    "ListBoxSmoothScrolling",
];

const DEFAULT_USER_PREF_MASK: [u8; 8] = [0x9E, 0x3E, 0x07, 0x80, 0x12, 0x00, 0x00, 0x00];

pub struct VisualEffectsRule;

impl VisualEffectsRule {
    fn desired_values(cfg: &ProfileConfig) -> Vec<(String, &'static str, RegValue)> {
        let ve = &cfg.rules.visual_effects;
        let anim_dword = if ve.animations { 1 } else { 0 };
        let mut entries = vec![
            (
                PERSONALIZE_PATH.to_string(),
                "EnableTransparency",
                RegValue::Dword(if ve.transparency { 1 } else { 0 }),
            ),
            (
                VISUAL_FX_PATH.to_string(),
                "VisualFXSetting",
                RegValue::Dword(if ve.animations { 0 } else { 3 }),
            ),
            (
                WINDOW_METRICS_PATH.to_string(),
                "MinAnimate",
                RegValue::Sz(if ve.animations { "1" } else { "0" }.to_string()),
            ),
            (
                ADVANCED_PATH.to_string(),
                "TaskbarAnimations",
                RegValue::Dword(anim_dword),
            ),
        ];

        for sub in VISUAL_FX_SUBKEYS {
            entries.push((
                format!(r"{VISUAL_FX_PATH}\{sub}"),
                "DefaultApplied",
                RegValue::Dword(anim_dword),
            ));
        }

        entries
    }

    fn desired_user_pref_mask(current: Option<&RegValue>, animations: bool) -> Option<Vec<u8>> {
        if let Some(bytes) = current.and_then(|v| v.as_bytes()).filter(|b| b.len() >= 2) {
            let mut next = bytes.clone();
            apply_mask_bits(&mut next, animations);
            if next == bytes { None } else { Some(next) }
        } else {
            let mut next = DEFAULT_USER_PREF_MASK.to_vec();
            apply_mask_bits(&mut next, animations);
            Some(next)
        }
    }
}

fn apply_mask_bits(bytes: &mut [u8], animations: bool) {
    if animations {
        bytes[0] |= 0x0E;
        bytes[1] |= 0x0E;
        if bytes.len() > 4 {
            bytes[4] |= 0x02;
        }
    } else {
        bytes[0] &= !0x0E;
        bytes[1] &= !0x0E;
        if bytes.len() > 4 {
            bytes[4] &= !0x02;
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

impl Rule for VisualEffectsRule {
    fn id(&self) -> &'static str {
        "visual_effects"
    }

    fn title(&self) -> &'static str {
        "Visual Effects"
    }

    fn requires_admin(&self) -> bool {
        false
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.visual_effects.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let mut diffs = Vec::new();
        for (path, name, target) in Self::desired_values(cfg) {
            let current = ops.reg_read(RegHive::Hkcu, &path, name)?;
            if current.as_ref() != Some(&target) {
                diffs.push(DiffItem {
                    field: format!(r"HKCU\{path}\{name}"),
                    current: fmt_reg(current.as_ref()),
                    target: fmt_reg(Some(&target)),
                });
            }
        }

        let mask_cur = ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, "UserPreferencesMask")?;
        if let Some(target_bytes) =
            Self::desired_user_pref_mask(mask_cur.as_ref(), cfg.rules.visual_effects.animations)
        {
            diffs.push(DiffItem {
                field: format!(r"HKCU\{DESKTOP_PATH}\UserPreferencesMask"),
                current: fmt_reg(mask_cur.as_ref()),
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
        for (path, name, target) in Self::desired_values(cfg) {
            let desc = fmt_reg(Some(&target));
            if snap.write_reg_with_backup(ops, RegHive::Hkcu, &path, name, target)? {
                changes.push(format!(r"HKCU\{path}\{name} = {desc}"));
            }
        }

        let mask_cur = ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, "UserPreferencesMask")?;
        if let Some(target_bytes) =
            Self::desired_user_pref_mask(mask_cur.as_ref(), cfg.rules.visual_effects.animations)
        {
            let target_val = RegValue::binary(&target_bytes);
            let desc = fmt_reg(Some(&target_val));
            if snap.write_reg_with_backup(
                ops,
                RegHive::Hkcu,
                DESKTOP_PATH,
                "UserPreferencesMask",
                target_val,
            )? {
                changes.push(format!(r"HKCU\{DESKTOP_PATH}\UserPreferencesMask = {desc}"));
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
    fn check_apply_idempotent_and_rollback_disable_animations() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let rule = VisualEffectsRule;

        assert!(!rule.requires_admin());
        assert_eq!(rule.id(), "visual_effects");
        assert!(rule.is_enabled(&cfg));

        // Seed non-default mask and existing value to verify bit preservation & rollback
        let orig_mask = [0xFFu8, 0xFF, 0x07, 0x80, 0xFF, 0x00, 0x00, 0x00];
        ops.seed_reg(
            RegHive::Hkcu,
            DESKTOP_PATH,
            "UserPreferencesMask",
            RegValue::binary(&orig_mask),
        );
        ops.seed_reg(
            RegHive::Hkcu,
            PERSONALIZE_PATH,
            "EnableTransparency",
            RegValue::Dword(1),
        );

        let chk1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(chk1.status, CheckStatus::Drifted);
        assert!(!chk1.diffs.is_empty());

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert!(!changes.is_empty());

        assert_eq!(
            ops.reg_read(RegHive::Hkcu, PERSONALIZE_PATH, "EnableTransparency")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, VISUAL_FX_PATH, "VisualFXSetting")
                .unwrap(),
            Some(RegValue::Dword(3))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, WINDOW_METRICS_PATH, "MinAnimate")
                .unwrap(),
            Some(RegValue::Sz("0".into()))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, ADVANCED_PATH, "TaskbarAnimations")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        for sub in VISUAL_FX_SUBKEYS {
            let sub_path = format!(r"{VISUAL_FX_PATH}\{sub}");
            assert_eq!(
                ops.reg_read(RegHive::Hkcu, &sub_path, "DefaultApplied")
                    .unwrap(),
                Some(RegValue::Dword(0))
            );
        }
        let updated_mask = ops
            .reg_read(RegHive::Hkcu, DESKTOP_PATH, "UserPreferencesMask")
            .unwrap()
            .unwrap()
            .as_bytes()
            .unwrap();
        assert_eq!(
            updated_mask,
            vec![0xF1, 0xF1, 0x07, 0x80, 0xFD, 0x00, 0x00, 0x00]
        );

        // Compliant + idempotent
        let chk2 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(chk2.status, CheckStatus::Compliant);
        assert!(chk2.diffs.is_empty());

        let snap_len = snap.registry.len();
        let (outcome2, changes2) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome2, RuleOutcome::AlreadyCompliant);
        assert!(changes2.is_empty());
        assert_eq!(snap.registry.len(), snap_len);

        // Rollback restores seeded values and removes newly created ones
        rollback_snapshot(&ops, &snap).unwrap();
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, PERSONALIZE_PATH, "EnableTransparency")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, DESKTOP_PATH, "UserPreferencesMask")
                .unwrap(),
            Some(RegValue::binary(&orig_mask))
        );
        assert!(
            ops.reg_read(RegHive::Hkcu, VISUAL_FX_PATH, "VisualFXSetting")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn enable_animations_and_transparency_restores_bits() {
        let ops = FakeSystemOps::default();
        let mut cfg = ProfileConfig::embedded_default();
        cfg.rules.visual_effects.animations = true;
        cfg.rules.visual_effects.transparency = true;
        let rule = VisualEffectsRule;

        ops.seed_reg(
            RegHive::Hkcu,
            DESKTOP_PATH,
            "UserPreferencesMask",
            RegValue::binary(&[0x90, 0x30, 0x07, 0x80, 0x10, 0x00, 0x00, 0x00]),
        );

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, _) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);

        assert_eq!(
            ops.reg_read(RegHive::Hkcu, PERSONALIZE_PATH, "EnableTransparency")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, VISUAL_FX_PATH, "VisualFXSetting")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, WINDOW_METRICS_PATH, "MinAnimate")
                .unwrap(),
            Some(RegValue::Sz("1".into()))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, ADVANCED_PATH, "TaskbarAnimations")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        let mask = ops
            .reg_read(RegHive::Hkcu, DESKTOP_PATH, "UserPreferencesMask")
            .unwrap()
            .unwrap()
            .as_bytes()
            .unwrap();
        assert_eq!(mask, vec![0x9E, 0x3E, 0x07, 0x80, 0x12, 0x00, 0x00, 0x00]);
        assert_eq!(
            rule.check(&ops, &cfg).unwrap().status,
            CheckStatus::Compliant
        );
    }
}
