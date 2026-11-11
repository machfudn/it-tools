use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

use crate::backup::{BackupSnapshot, UserFlagBackup};
use crate::config::{PasswordPolicyConfig, ProfileConfig};
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::SystemOps;

const RULE_ID: &str = "password_policy";
const RULE_TITLE: &str = "Password & Lockout Policy";

pub struct PasswordPolicyRule;

impl Rule for PasswordPolicyRule {
    fn id(&self) -> &'static str {
        RULE_ID
    }

    fn title(&self) -> &'static str {
        RULE_TITLE
    }

    fn requires_admin(&self) -> bool {
        true
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.password_policy.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let pp = &cfg.rules.password_policy;
        if !ops.is_admin() {
            return Ok(RuleCheck {
                id: RULE_ID.into(),
                title: RULE_TITLE.into(),
                requires_admin: true,
                enabled_in_config: pp.enabled,
                status: CheckStatus::NeedsAdmin,
                diffs: Vec::new(),
                note: Some(
                    "Administrator privileges required to query security policy via secedit".into(),
                ),
            });
        }

        let inf_text = export_secpol_inf(ops)?;
        let current = parse_system_access(&inf_text);
        let desired = desired_system_access(pp);
        let diffs = compute_diffs(&current, &desired);

        Ok(RuleCheck {
            id: RULE_ID.into(),
            title: RULE_TITLE.into(),
            requires_admin: true,
            enabled_in_config: pp.enabled,
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
        opts: &ApplyOptions,
        snap: &mut BackupSnapshot,
    ) -> Result<(RuleOutcome, Vec<String>)> {
        if !ops.is_admin() {
            bail!("Administrator privileges required to apply password & lockout policy");
        }

        let pp = &cfg.rules.password_policy;
        let inf_text = export_secpol_inf(ops)?;
        let current = parse_system_access(&inf_text);
        let desired = desired_system_access(pp);
        let diffs = compute_diffs(&current, &desired);

        let mut changes = Vec::new();
        if !diffs.is_empty() {
            if snap.secedit_inf.is_none() {
                snap.secedit_inf = Some(inf_text.clone());
            }
            let patched = patch_system_access_inf(&inf_text, &desired);
            configure_secpol_inf(ops, &patched)?;
            for d in diffs {
                changes.push(format!(
                    "secedit [System Access] {}: {} -> {}",
                    d.field, d.current, d.target
                ));
            }
        }

        if let Some(ut) = &opts.user_target {
            let username = ut.username.trim();
            if username.is_empty() {
                bail!("user_target username cannot be empty");
            }
            let users = ops.list_local_users()?;
            let existing = users.iter().find(|u| u.name.eq_ignore_ascii_case(username));

            match existing {
                None => {
                    if !ut.create_if_missing {
                        bail!(
                            "local user '{username}' does not exist (pass create_if_missing to create)"
                        );
                    }
                    let pw = ut.temp_password.as_deref().with_context(|| {
                        format!("creating missing local user '{username}' requires temp_password")
                    })?;
                    ops.create_local_user(username, pw)?;
                    changes.push(format!("created local user '{username}' (password set)"));
                }
                Some(user) => {
                    if !snap
                        .user_flags
                        .iter()
                        .any(|u| u.username.eq_ignore_ascii_case(&user.name))
                        && ut.clear_dont_expire
                        && user.dont_expire_password
                    {
                        snap.user_flags.push(UserFlagBackup {
                            username: user.name.clone(),
                            prior_dont_expire: user.dont_expire_password,
                        });
                    }
                    if ut.clear_dont_expire && user.dont_expire_password {
                        ops.set_user_dont_expire(&user.name, false)?;
                        changes.push(format!(
                            "cleared PasswordNeverExpires on local user '{}'",
                            user.name
                        ));
                    }
                    if let Some(pw) = ut.temp_password.as_deref() {
                        ops.set_user_password(&user.name, pw)?;
                        changes.push(format!(
                            "updated temporary password for local user '{}'",
                            user.name
                        ));
                    }
                }
            }
        }

        if changes.is_empty() {
            Ok((RuleOutcome::AlreadyCompliant, changes))
        } else {
            Ok((RuleOutcome::Applied, changes))
        }
    }
}

fn desired_system_access(pp: &PasswordPolicyConfig) -> [(&'static str, String); 8] {
    let max_age = if pp.max_password_age_days == 0 {
        "-1".to_string()
    } else {
        pp.max_password_age_days.to_string()
    };
    [
        ("PasswordHistorySize", pp.password_history.to_string()),
        ("MaximumPasswordAge", max_age),
        ("MinimumPasswordLength", pp.min_password_length.to_string()),
        (
            "PasswordComplexity",
            if pp.complexity_enabled { "1" } else { "0" }.into(),
        ),
        ("LockoutBadCount", pp.lockout_threshold.to_string()),
        ("LockoutDuration", pp.lockout_duration_min.to_string()),
        ("ResetLockoutCount", pp.lockout_reset_min.to_string()),
        (
            "AllowAdministratorLockout",
            if pp.allow_admin_lockout { "1" } else { "0" }.into(),
        ),
    ]
}

fn compute_diffs(
    current: &BTreeMap<String, String>,
    desired: &[(&'static str, String); 8],
) -> Vec<DiffItem> {
    let mut diffs = Vec::new();
    for (key, target) in desired {
        let cur = current.get(&key.to_ascii_lowercase());
        if cur.map(String::as_str) != Some(target.as_str()) {
            diffs.push(DiffItem {
                field: (*key).to_string(),
                current: cur.cloned().unwrap_or_else(|| "<unset>".into()),
                target: target.clone(),
            });
        }
    }
    diffs
}

fn export_secpol_inf(ops: &dyn SystemOps) -> Result<String> {
    let tmp_inf = ops
        .temp_dir()
        .join(format!("it-tools-secpol-export-{}.inf", std::process::id()));
    let inf_s = tmp_inf.to_string_lossy().into_owned();
    let out = ops.run_tool(
        "secedit",
        &["/export", "/cfg", &inf_s, "/areas", "SECURITYPOLICY"],
    );
    let raw = match out {
        Ok(o) if o.exit_code == 0 => ops.read_file_opt(&tmp_inf),
        Ok(o) => {
            let _ = ops.remove_file_opt(&tmp_inf);
            bail!(
                "secedit /export failed (exit {}): {} {}",
                o.exit_code,
                o.stdout.trim(),
                o.stderr.trim()
            );
        }
        Err(e) => {
            let _ = ops.remove_file_opt(&tmp_inf);
            return Err(e);
        }
    };
    let _ = ops.remove_file_opt(&tmp_inf);
    let bytes = raw?.context("secedit /export did not produce INF output file")?;
    Ok(decode_utf16le_or_utf8(&bytes))
}

fn configure_secpol_inf(ops: &dyn SystemOps, patched_inf: &str) -> Result<()> {
    let pid = std::process::id();
    let tmp_inf = ops
        .temp_dir()
        .join(format!("it-tools-secpol-apply-{pid}.inf"));
    let tmp_sdb = ops
        .temp_dir()
        .join(format!("it-tools-secpol-apply-{pid}.sdb"));
    let inf_s = tmp_inf.to_string_lossy().into_owned();
    let sdb_s = tmp_sdb.to_string_lossy().into_owned();

    ops.write_file(&tmp_inf, &encode_utf16le_bom(patched_inf))?;
    let res = ops.run_tool(
        "secedit",
        &[
            "/configure",
            "/db",
            &sdb_s,
            "/cfg",
            &inf_s,
            "/areas",
            "SECURITYPOLICY",
            "/quiet",
        ],
    );
    let _ = ops.remove_file_opt(&tmp_inf);
    let _ = ops.remove_file_opt(&tmp_sdb);

    let out = res?;
    if out.exit_code != 0 {
        bail!(
            "secedit /configure failed (exit {}): {} {}",
            out.exit_code,
            out.stdout.trim(),
            out.stderr.trim()
        );
    }
    Ok(())
}

fn parse_system_access(inf: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut in_sys = false;
    for line in inf.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_sys = trimmed.eq_ignore_ascii_case("[System Access]");
            continue;
        }
        if !in_sys || trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    map
}

fn patch_system_access_inf(inf: &str, desired: &[(&'static str, String); 8]) -> String {
    let mut out_lines: Vec<String> = Vec::new();
    let mut written = [false; 8];
    let mut in_sys = false;
    let mut saw_sys = false;

    for line in inf.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_sys {
                append_missing_keys(&mut out_lines, desired, &mut written);
            }
            in_sys = trimmed.eq_ignore_ascii_case("[System Access]");
            if in_sys {
                saw_sys = true;
            }
            out_lines.push(line.to_string());
            continue;
        }

        if in_sys
            && !trimmed.is_empty()
            && !trimmed.starts_with(';')
            && let Some((k, _)) = trimmed.split_once('=')
        {
            let k_trim = k.trim();
            if let Some((idx, (canon, val))) = desired
                .iter()
                .enumerate()
                .find(|(_, (dk, _))| dk.eq_ignore_ascii_case(k_trim))
            {
                if !written[idx] {
                    out_lines.push(format!("{canon} = {val}"));
                    written[idx] = true;
                }
                continue;
            }
        }

        out_lines.push(line.to_string());
    }

    if in_sys {
        append_missing_keys(&mut out_lines, desired, &mut written);
    } else if !saw_sys {
        out_lines.push("[System Access]".to_string());
        append_missing_keys(&mut out_lines, desired, &mut written);
    }

    let mut joined = out_lines.join("\r\n");
    joined.push_str("\r\n");
    joined
}

fn append_missing_keys(
    out_lines: &mut Vec<String>,
    desired: &[(&'static str, String); 8],
    written: &mut [bool; 8],
) {
    for (idx, (k, v)) in desired.iter().enumerate() {
        if !written[idx] {
            out_lines.push(format!("{k} = {v}"));
            written[idx] = true;
        }
    }
}

fn encode_utf16le_bom(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + text.len() * 2);
    out.push(0xFF);
    out.push(0xFE);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn decode_utf16le_or_utf8(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(rest).into_owned()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::rollback_snapshot;
    use crate::engine::UserTargetOptions;
    use crate::platform::fake::FakeSystemOps;

    #[test]
    fn non_admin_check_returns_needs_admin_without_calling_secedit() {
        let ops = FakeSystemOps::default();
        ops.state.borrow_mut().admin = false;
        let cfg = ProfileConfig::embedded_default();

        let check = PasswordPolicyRule.check(&ops, &cfg).unwrap();
        assert_eq!(check.status, CheckStatus::NeedsAdmin);
        assert!(ops.state.borrow().recorded_commands.is_empty());
    }

    #[test]
    fn check_apply_idempotency_and_rollback_with_utf16_inf_roundtrip() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();

        let c1 = PasswordPolicyRule.check(&ops, &cfg).unwrap();
        assert_eq!(c1.status, CheckStatus::Drifted);
        assert!(
            c1.diffs
                .iter()
                .any(|d| d.field == "AllowAdministratorLockout" && d.target == "1")
        );

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = PasswordPolicyRule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert!(!changes.is_empty());
        assert!(snap.secedit_inf.is_some());

        {
            let st = ops.state.borrow();
            assert_eq!(
                st.system_access
                    .get("PasswordHistorySize")
                    .map(String::as_str),
                Some("2")
            );
            assert_eq!(
                st.system_access
                    .get("MaximumPasswordAge")
                    .map(String::as_str),
                Some("90")
            );
            assert_eq!(
                st.system_access
                    .get("MinimumPasswordLength")
                    .map(String::as_str),
                Some("8")
            );
            assert_eq!(
                st.system_access
                    .get("PasswordComplexity")
                    .map(String::as_str),
                Some("1")
            );
            assert_eq!(
                st.system_access.get("LockoutBadCount").map(String::as_str),
                Some("7")
            );
            assert_eq!(
                st.system_access.get("LockoutDuration").map(String::as_str),
                Some("10")
            );
            assert_eq!(
                st.system_access
                    .get("ResetLockoutCount")
                    .map(String::as_str),
                Some("10")
            );
            assert_eq!(
                st.system_access
                    .get("AllowAdministratorLockout")
                    .map(String::as_str),
                Some("1")
            );
            assert!(
                st.files.is_empty(),
                "temp INF/SDB files should be cleaned up"
            );
        }

        let c2 = PasswordPolicyRule.check(&ops, &cfg).unwrap();
        assert_eq!(c2.status, CheckStatus::Compliant);
        assert!(c2.diffs.is_empty());

        let mut snap2 = BackupSnapshot::new(&ops);
        let (outcome2, changes2) = PasswordPolicyRule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap2)
            .unwrap();
        assert_eq!(outcome2, RuleOutcome::AlreadyCompliant);
        assert!(changes2.is_empty());
        assert!(snap2.is_empty());

        rollback_snapshot(&ops, &snap).unwrap();
        let c3 = PasswordPolicyRule.check(&ops, &cfg).unwrap();
        assert_eq!(c3.status, CheckStatus::Drifted);
        assert_eq!(
            ops.state
                .borrow()
                .system_access
                .get("AllowAdministratorLockout")
                .map(String::as_str),
            Some("0")
        );
    }

    #[test]
    fn zero_max_password_age_maps_to_minus_one_and_preserves_other_sections() {
        let raw = "[Unicode]\r\nUnicode=yes\r\n[System Access]\r\nMinimumPasswordAge = 3\r\nMaximumPasswordAge = 42\r\n[Event Audit]\r\nAuditSystemEvents = 1\r\n";
        let mut cfg = ProfileConfig::embedded_default();
        cfg.rules.password_policy.max_password_age_days = 0;
        let desired = desired_system_access(&cfg.rules.password_policy);
        let patched = patch_system_access_inf(raw, &desired);

        assert!(patched.contains("MinimumPasswordAge = 3"));
        assert!(patched.contains("MaximumPasswordAge = -1"));
        assert!(patched.contains("AllowAdministratorLockout = 1"));
        assert!(patched.contains("[Event Audit]\r\nAuditSystemEvents = 1"));

        let bytes = encode_utf16le_bom(&patched);
        assert!(bytes.starts_with(&[0xFF, 0xFE]));
        let decoded = decode_utf16le_or_utf8(&bytes);
        let parsed = parse_system_access(&decoded);
        assert_eq!(
            parsed.get("maximumpasswordage").map(String::as_str),
            Some("-1")
        );
        assert_eq!(
            parsed.get("allowadministratorlockout").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn opt_in_user_target_clears_dont_expire_sets_password_without_leaking_secret() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let secret = "Sup3rS3cret!Pw#99";
        let opts = ApplyOptions {
            user_target: Some(UserTargetOptions {
                username: "Admin".into(),
                create_if_missing: false,
                clear_dont_expire: true,
                temp_password: Some(secret.into()),
            }),
            ..Default::default()
        };

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = PasswordPolicyRule
            .apply(&ops, &cfg, &opts, &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        for line in &changes {
            assert!(
                !line.contains(secret),
                "password must never be logged in changes"
            );
        }
        assert_eq!(snap.user_flags.len(), 1);
        assert_eq!(snap.user_flags[0].username, "Admin");
        assert!(snap.user_flags[0].prior_dont_expire);

        {
            let st = ops.state.borrow();
            let (info, pw) = st.users.get("admin").unwrap();
            assert!(!info.dont_expire_password);
            assert_eq!(pw, secret);
        }

        rollback_snapshot(&ops, &snap).unwrap();
        assert!(
            ops.state
                .borrow()
                .users
                .get("admin")
                .unwrap()
                .0
                .dont_expire_password
        );
    }

    #[test]
    fn opt_in_user_target_creates_missing_user_and_requires_password() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();

        let missing_pw_opts = ApplyOptions {
            user_target: Some(UserTargetOptions {
                username: "Operator".into(),
                create_if_missing: true,
                clear_dont_expire: true,
                temp_password: None,
            }),
            ..Default::default()
        };
        let mut snap_err = BackupSnapshot::new(&ops);
        assert!(
            PasswordPolicyRule
                .apply(&ops, &cfg, &missing_pw_opts, &mut snap_err)
                .is_err()
        );

        let create_pw = "InitPass!2026";
        let create_opts = ApplyOptions {
            user_target: Some(UserTargetOptions {
                username: "Operator".into(),
                create_if_missing: true,
                clear_dont_expire: true,
                temp_password: Some(create_pw.into()),
            }),
            ..Default::default()
        };
        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = PasswordPolicyRule
            .apply(&ops, &cfg, &create_opts, &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert!(changes.iter().all(|c| !c.contains(create_pw)));
        assert!(snap.user_flags.is_empty());

        let st = ops.state.borrow();
        let (info, pw) = st.users.get("operator").unwrap();
        assert_eq!(info.name, "Operator");
        assert!(!info.dont_expire_password);
        assert_eq!(pw, create_pw);
    }
}
