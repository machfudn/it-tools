use std::collections::BTreeMap;

use anyhow::Result;

use crate::backup::BackupSnapshot;
use crate::config::ProfileConfig;
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, RegValue, SystemOps, encode_hex};

pub struct StartupAppsRule;

const RUN_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVED_RUN_PATH: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
const APPROVED_FOLDER_PATH: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

struct StartupEntry {
    hive: RegHive,
    approved_path: &'static str,
    target_name: String,
    command: Option<String>,
    approved_val: Option<RegValue>,
}

fn hive_label(hive: RegHive) -> &'static str {
    match hive {
        RegHive::Hkcu => "HKCU",
        RegHive::Hklm => "HKLM",
    }
}

fn compact_norm(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-' && *c != '_')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn matches_pattern(haystack: &str, pattern: &str) -> bool {
    let pat_trim = pattern.trim();
    if pat_trim.is_empty() {
        return false;
    }
    if haystack.to_lowercase().contains(&pat_trim.to_lowercase()) {
        return true;
    }
    let pat_compact = compact_norm(pat_trim);
    !pat_compact.is_empty() && compact_norm(haystack).contains(&pat_compact)
}

fn is_allowlisted(allowlist: &[String], name: &str, command: Option<&str>) -> bool {
    allowlist.iter().any(|pat| {
        matches_pattern(name, pat) || command.is_some_and(|cmd| matches_pattern(cmd, pat))
    })
}

fn build_startup_bytes(flag: u8, existing: Option<&[u8]>) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = flag;
    if let Some(prev) = existing
        && prev.len() >= 12
    {
        out[4..12].copy_from_slice(&prev[4..12]);
    }
    out
}

fn collect_entries(ops: &dyn SystemOps) -> Result<Vec<StartupEntry>> {
    let mut out = Vec::new();

    for hive in [RegHive::Hkcu, RegHive::Hklm] {
        let mut run_map: BTreeMap<String, StartupEntry> = BTreeMap::new();

        for (name, val) in ops.reg_list_values(hive, RUN_PATH)? {
            if name.is_empty() {
                continue;
            }
            let key = name.to_ascii_lowercase();
            let cmd = val.as_str().map(str::to_string);
            run_map.insert(
                key,
                StartupEntry {
                    hive,
                    approved_path: APPROVED_RUN_PATH,
                    target_name: name,
                    command: cmd,
                    approved_val: None,
                },
            );
        }

        for (name, val) in ops.reg_list_values(hive, APPROVED_RUN_PATH)? {
            if name.is_empty() {
                continue;
            }
            let key = name.to_ascii_lowercase();
            match run_map.get_mut(&key) {
                Some(existing) => {
                    existing.target_name = name;
                    existing.approved_val = Some(val);
                }
                None => {
                    run_map.insert(
                        key,
                        StartupEntry {
                            hive,
                            approved_path: APPROVED_RUN_PATH,
                            target_name: name,
                            command: None,
                            approved_val: Some(val),
                        },
                    );
                }
            }
        }

        out.extend(run_map.into_values());

        let mut folder_entries: Vec<(String, RegValue)> = ops
            .reg_list_values(hive, APPROVED_FOLDER_PATH)?
            .into_iter()
            .filter(|(n, _)| !n.is_empty())
            .collect();
        folder_entries.sort_by_key(|a| a.0.to_ascii_lowercase());

        for (name, val) in folder_entries {
            out.push(StartupEntry {
                hive,
                approved_path: APPROVED_FOLDER_PATH,
                target_name: name,
                command: None,
                approved_val: Some(val),
            });
        }
    }

    Ok(out)
}

fn desired_update(entry: &StartupEntry, allowlist: &[String]) -> Option<[u8; 12]> {
    let allowed = is_allowlisted(allowlist, &entry.target_name, entry.command.as_deref());
    let existing_bytes = entry.approved_val.as_ref().and_then(|v| v.as_bytes());

    if allowed {
        let bytes = existing_bytes?;
        if !bytes.is_empty() && (bytes[0] & 1 == 1) {
            Some(build_startup_bytes(0x02, Some(&bytes)))
        } else {
            None
        }
    } else {
        let already_disabled = existing_bytes
            .as_ref()
            .is_some_and(|b| b.len() == 12 && (b[0] & 1 == 1));
        if already_disabled {
            None
        } else {
            Some(build_startup_bytes(0x03, existing_bytes.as_deref()))
        }
    }
}

fn fmt_startup_state(val: Option<&RegValue>) -> String {
    match val {
        None => "<absent>".into(),
        Some(v) => match v.as_bytes() {
            Some(b) if !b.is_empty() && (b[0] & 1 == 1) => {
                format!("disabled ({})", encode_hex(&b))
            }
            Some(b) if !b.is_empty() => format!("enabled ({})", encode_hex(&b)),
            Some(_) => "empty binary".into(),
            None => "non-binary".into(),
        },
    }
}

impl Rule for StartupAppsRule {
    fn id(&self) -> &'static str {
        "startup_apps"
    }

    fn title(&self) -> &'static str {
        "Startup Apps"
    }

    fn requires_admin(&self) -> bool {
        true
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.startup_apps.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let allowlist = &cfg.rules.startup_apps.allowlist;
        let mut diffs = Vec::new();

        for entry in collect_entries(ops)? {
            if let Some(target_bytes) = desired_update(&entry, allowlist) {
                let target_label = if target_bytes[0] & 1 == 1 {
                    format!("disabled ({})", encode_hex(&target_bytes))
                } else {
                    format!("enabled ({})", encode_hex(&target_bytes))
                };
                diffs.push(DiffItem {
                    field: format!(
                        "{}\\{}\\{}",
                        hive_label(entry.hive),
                        entry.approved_path,
                        entry.target_name
                    ),
                    current: fmt_startup_state(entry.approved_val.as_ref()),
                    target: target_label,
                });
            }
        }

        Ok(RuleCheck {
            id: self.id().into(),
            title: self.title().into(),
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
        let allowlist = &cfg.rules.startup_apps.allowlist;
        let mut changes = Vec::new();

        for entry in collect_entries(ops)? {
            if let Some(target_bytes) = desired_update(&entry, allowlist) {
                snap.record_startup_once(ops, entry.hive, entry.approved_path, &entry.target_name)?;
                ops.reg_write(
                    entry.hive,
                    entry.approved_path,
                    &entry.target_name,
                    RegValue::binary(&target_bytes),
                )?;
                let action = if target_bytes[0] & 1 == 1 {
                    "disabled"
                } else {
                    "enabled"
                };
                changes.push(format!(
                    "{} {}\\{}\\{}",
                    action,
                    hive_label(entry.hive),
                    entry.approved_path,
                    entry.target_name
                ));
            }
        }

        let outcome = if changes.is_empty() {
            RuleOutcome::AlreadyCompliant
        } else {
            RuleOutcome::Applied
        };
        Ok((outcome, changes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::rollback_snapshot;
    use crate::platform::fake::FakeSystemOps;

    #[test]
    fn disables_non_allowlisted_preserves_run_and_rolls_back() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();

        // Allowlisted via name separator normalization ("OpenVPN GUI" vs "OpenVPN-GUI")
        ops.seed_reg(
            RegHive::Hkcu,
            RUN_PATH,
            "OpenVPN-GUI",
            RegValue::Sz(r"C:\Program Files\OpenVPN\bin\openvpn-gui.exe".into()),
        );
        // Allowlisted via command substring ("SecurityHealth" in SecurityHealthSystray.exe)
        ops.seed_reg(
            RegHive::Hklm,
            RUN_PATH,
            "SecurityTray",
            RegValue::ExpandSz(r"%windir%\system32\SecurityHealthSystray.exe".into()),
        );
        // Non-allowlisted Run entry with no StartupApproved entry yet
        ops.seed_reg(
            RegHive::Hkcu,
            RUN_PATH,
            "Discord",
            RegValue::Sz(r"C:\Users\Admin\AppData\Local\Discord\Update.exe".into()),
        );
        // Non-allowlisted Run entry currently enabled with non-zero timestamp bytes 4..12
        let enabled_with_ts = [
            0x02, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        ops.seed_reg(
            RegHive::Hklm,
            RUN_PATH,
            "Updater",
            RegValue::Sz(r"C:\Program Files\Updater\upd.exe".into()),
        );
        ops.seed_reg(
            RegHive::Hklm,
            APPROVED_RUN_PATH,
            "Updater",
            RegValue::binary(&enabled_with_ts),
        );

        let rule = StartupAppsRule;
        let c1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(c1.status, CheckStatus::Drifted);
        assert_eq!(c1.diffs.len(), 2);

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(changes.len(), 2);

        // Allowlisted absent StartupApproved stays absent
        assert!(
            ops.reg_read(RegHive::Hkcu, APPROVED_RUN_PATH, "OpenVPN-GUI")
                .unwrap()
                .is_none()
        );
        assert!(
            ops.reg_read(RegHive::Hklm, APPROVED_RUN_PATH, "SecurityTray")
                .unwrap()
                .is_none()
        );

        // Run entries must never be deleted
        assert!(
            ops.reg_read(RegHive::Hkcu, RUN_PATH, "Discord")
                .unwrap()
                .is_some()
        );
        assert!(
            ops.reg_read(RegHive::Hklm, RUN_PATH, "Updater")
                .unwrap()
                .is_some()
        );

        // Non-allowlisted entries disabled with 12-byte 0x03 preserving bytes 4..12
        let discord_bytes = ops
            .reg_read(RegHive::Hkcu, APPROVED_RUN_PATH, "Discord")
            .unwrap()
            .unwrap()
            .as_bytes()
            .unwrap();
        assert_eq!(discord_bytes, vec![0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let updater_bytes = ops
            .reg_read(RegHive::Hklm, APPROVED_RUN_PATH, "Updater")
            .unwrap()
            .unwrap()
            .as_bytes()
            .unwrap();
        assert_eq!(
            updater_bytes,
            vec![
                0x03, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
            ]
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
        assert!(
            ops.reg_read(RegHive::Hkcu, APPROVED_RUN_PATH, "Discord")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            ops.reg_read(RegHive::Hklm, APPROVED_RUN_PATH, "Updater")
                .unwrap()
                .unwrap()
                .as_bytes()
                .unwrap(),
            enabled_with_ts.to_vec()
        );
    }

    #[test]
    fn reenables_disabled_allowlisted_and_handles_startup_folder() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();

        let disabled_with_ts = [0x03, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4];
        ops.seed_reg(
            RegHive::Hkcu,
            APPROVED_FOLDER_PATH,
            "OpenVPN GUI.lnk",
            RegValue::binary(&disabled_with_ts),
        );
        let enabled_folder = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        ops.seed_reg(
            RegHive::Hklm,
            APPROVED_FOLDER_PATH,
            "OneDrive.lnk",
            RegValue::binary(&enabled_folder),
        );

        let rule = StartupAppsRule;
        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(changes.len(), 2);

        assert_eq!(
            ops.reg_read(RegHive::Hkcu, APPROVED_FOLDER_PATH, "OpenVPN GUI.lnk")
                .unwrap()
                .unwrap()
                .as_bytes()
                .unwrap(),
            vec![0x02, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4]
        );
        assert_eq!(
            ops.reg_read(RegHive::Hklm, APPROVED_FOLDER_PATH, "OneDrive.lnk")
                .unwrap()
                .unwrap()
                .as_bytes()
                .unwrap(),
            vec![0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        rollback_snapshot(&ops, &snap).unwrap();
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, APPROVED_FOLDER_PATH, "OpenVPN GUI.lnk")
                .unwrap()
                .unwrap()
                .as_bytes()
                .unwrap(),
            disabled_with_ts.to_vec()
        );
        assert_eq!(
            ops.reg_read(RegHive::Hklm, APPROVED_FOLDER_PATH, "OneDrive.lnk")
                .unwrap()
                .unwrap()
                .as_bytes()
                .unwrap(),
            enabled_folder.to_vec()
        );
    }
}
