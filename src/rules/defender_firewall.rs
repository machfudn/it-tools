use std::collections::BTreeMap;

use anyhow::{Result, bail};

use crate::backup::{BackupSnapshot, FirewallBackup};
use crate::config::{DefenderFirewallConfig, ProfileConfig};
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, RegValue, SystemOps};

const RULE_ID: &str = "defender_firewall";
const RULE_TITLE: &str = "Microsoft Defender & Firewall";

const DEFENDER_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender";
const DEFENDER_POLICY_UX_KEY: &str =
    r"SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration";
const DEFENDER_UX_KEY: &str = r"SOFTWARE\Microsoft\Windows Defender\UX Configuration";
const DEFENDER_FEATURES_KEY: &str = r"SOFTWARE\Microsoft\Windows Defender\Features";

const ICMP_V4_ECHO_RULE: &str = "IT-Tools: Allow ICMPv4 Echo In";
const ICMP_V6_ECHO_RULE: &str = "IT-Tools: Allow ICMPv6 Echo In";
const ICMP_V6_ROUTER_RULE: &str = "IT-Tools: Allow ICMPv6 Router Adv In";

pub struct DefenderFirewallRule;

impl Rule for DefenderFirewallRule {
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
        cfg.rules.defender_firewall.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let df = &cfg.rules.defender_firewall;
        let mut diffs = Vec::new();

        for (path, name, target) in defender_targets(df) {
            let cur = ops.reg_read(RegHive::Hklm, path, name)?;
            if cur.as_ref() != Some(&RegValue::Dword(target)) {
                diffs.push(DiffItem {
                    field: format!(r"HKLM\{path}\{name}"),
                    current: format_reg_dword(cur.as_ref()),
                    target: target.to_string(),
                });
            }
        }

        let prof_states = query_firewall_profile_states(ops)?;
        for prof in &df.firewall_profiles {
            let key = prof.to_ascii_lowercase();
            let cur = prof_states.get(&key).copied();
            if cur != Some(true) {
                diffs.push(DiffItem {
                    field: format!("Firewall Profile ({key})"),
                    current: match cur {
                        Some(true) => "ON".into(),
                        Some(false) => "OFF".into(),
                        None => "<unknown>".into(),
                    },
                    target: "ON".into(),
                });
            }
        }

        if !ops.is_admin() {
            return Ok(RuleCheck {
                id: RULE_ID.into(),
                title: RULE_TITLE.into(),
                requires_admin: true,
                enabled_in_config: df.enabled,
                status: CheckStatus::NeedsAdmin,
                diffs,
                note: Some(
                    "Administrator privileges required to inspect firewall rules and configure Defender/Firewall".into(),
                ),
            });
        }

        let existing_rules = query_firewall_rule_names(ops)?;
        for (rule_name, proto) in enabled_icmp_rules(df) {
            if !existing_rules
                .iter()
                .any(|r| r.eq_ignore_ascii_case(rule_name))
            {
                diffs.push(DiffItem {
                    field: format!("Firewall Rule: {rule_name}"),
                    current: "missing".into(),
                    target: format!("allow in ({proto})"),
                });
            }
        }

        Ok(RuleCheck {
            id: RULE_ID.into(),
            title: RULE_TITLE.into(),
            requires_admin: true,
            enabled_in_config: df.enabled,
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
        if !ops.is_admin() {
            bail!("Administrator privileges required to configure Microsoft Defender & Firewall");
        }

        let df = &cfg.rules.defender_firewall;
        let mut changes = Vec::new();

        // Apply Firewall first so it always takes effect even if Defender Tamper Protection warns.
        let prof_states = query_firewall_profile_states(ops)?;
        let existing_rules = query_firewall_rule_names(ops)?;

        let profiles_to_enable: Vec<String> = df
            .firewall_profiles
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .filter(|p| prof_states.get(p).copied() != Some(true))
            .collect();

        let rules_to_add: Vec<(&'static str, &'static str)> = enabled_icmp_rules(df)
            .into_iter()
            .filter(|(name, _)| !existing_rules.iter().any(|r| r.eq_ignore_ascii_case(name)))
            .collect();

        if !profiles_to_enable.is_empty() || !rules_to_add.is_empty() {
            let fw_backup = snap.firewall.get_or_insert_with(|| FirewallBackup {
                prior_profiles: prof_states.clone(),
                created_rules: Vec::new(),
            });

            for prof in &profiles_to_enable {
                let prof_arg = match prof.as_str() {
                    "domain" => "domainprofile",
                    "private" => "privateprofile",
                    "public" => "publicprofile",
                    other => bail!("unsupported firewall profile '{other}'"),
                };
                let out =
                    ops.run_tool("netsh", &["advfirewall", "set", prof_arg, "state", "on"])?;
                if out.exit_code != 0 {
                    bail!(
                        "netsh failed enabling {prof_arg} (exit {}): {} {}",
                        out.exit_code,
                        out.stdout.trim(),
                        out.stderr.trim()
                    );
                }
                changes.push(format!(
                    "enabled Windows Defender Firewall profile '{prof}'"
                ));
            }

            let joined_profiles = join_firewall_profiles(&df.firewall_profiles);
            for (rule_name, proto) in rules_to_add {
                let name_arg = format!("name={rule_name}");
                let proto_arg = format!("protocol={proto}");
                let profile_arg = format!("profile={joined_profiles}");
                let out = ops.run_tool(
                    "netsh",
                    &[
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        &name_arg,
                        "dir=in",
                        "action=allow",
                        &proto_arg,
                        &profile_arg,
                    ],
                )?;
                if out.exit_code != 0 {
                    bail!(
                        "netsh failed adding firewall rule '{rule_name}' (exit {}): {} {}",
                        out.exit_code,
                        out.stdout.trim(),
                        out.stderr.trim()
                    );
                }
                if !fw_backup
                    .created_rules
                    .iter()
                    .any(|r| r.eq_ignore_ascii_case(rule_name))
                {
                    fw_backup.created_rules.push(rule_name.to_string());
                }
                changes.push(format!("added firewall rule '{rule_name}' ({proto})"));
            }
        }

        // Apply Defender configuration (gracefully warn on Tamper Protection).
        let tp_val = ops
            .reg_read(RegHive::Hklm, DEFENDER_FEATURES_KEY, "TamperProtection")?
            .and_then(|v| v.as_dword());

        let mut defender_drifted = false;
        let mut tamper_notes = Vec::new();

        for (path, name, target) in defender_targets(df) {
            let cur = ops.reg_read(RegHive::Hklm, path, name)?;
            if cur.as_ref() == Some(&RegValue::Dword(target)) {
                continue;
            }
            defender_drifted = true;
            let prev_len = snap.registry.len();
            match snap.write_reg_with_backup(
                ops,
                RegHive::Hklm,
                path,
                name,
                RegValue::Dword(target),
            ) {
                Ok(true) => {
                    changes.push(format!(
                        r"set HKLM\{path}\{name} = {target} (was {})",
                        format_reg_dword(cur.as_ref())
                    ));
                }
                Ok(false) => {}
                Err(err) => {
                    snap.registry.truncate(prev_len);
                    let msg = err.to_string();
                    if is_tamper_error(ops, &msg, tp_val) {
                        tamper_notes.push(format!(r"HKLM\{path}\{name}: {msg}"));
                    } else {
                        return Err(err);
                    }
                }
            }
        }

        if defender_drifted {
            let ui_flag = if df.defender_headless_ui {
                "$true"
            } else {
                "$false"
            };
            let ps_cmd = format!("Set-MpPreference -UILockdown {ui_flag}");
            let ps_out = ops.run_tool(
                "powershell.exe",
                &["-NoProfile", "-NonInteractive", "-Command", &ps_cmd],
            )?;
            if ps_out.exit_code != 0 {
                let err_detail = if !ps_out.stderr.trim().is_empty() {
                    ps_out.stderr.trim().to_string()
                } else {
                    ps_out.stdout.trim().to_string()
                };
                if is_tamper_error(ops, &err_detail, tp_val) {
                    tamper_notes.push(format!("Set-MpPreference: {err_detail}"));
                } else {
                    bail!(
                        "Set-MpPreference failed (exit {}): {}",
                        ps_out.exit_code,
                        err_detail
                    );
                }
            } else {
                changes.push(format!("applied Set-MpPreference -UILockdown {ui_flag}"));
            }
        }

        if !tamper_notes.is_empty() {
            return Ok((
                RuleOutcome::WarnTamperProtected {
                    detail: tamper_notes.join("; "),
                },
                changes,
            ));
        }

        if changes.is_empty() {
            Ok((RuleOutcome::AlreadyCompliant, changes))
        } else {
            Ok((RuleOutcome::Applied, changes))
        }
    }
}

fn defender_targets(df: &DefenderFirewallConfig) -> [(&'static str, &'static str, u32); 3] {
    let disable_anti_spyware = if df.defender_enabled { 0 } else { 1 };
    let ui_lockdown = if df.defender_headless_ui { 1 } else { 0 };
    [
        (
            DEFENDER_POLICY_KEY,
            "DisableAntiSpyware",
            disable_anti_spyware,
        ),
        (DEFENDER_POLICY_UX_KEY, "UILockdown", ui_lockdown),
        (DEFENDER_UX_KEY, "UILockdown", ui_lockdown),
    ]
}

fn enabled_icmp_rules(df: &DefenderFirewallConfig) -> Vec<(&'static str, &'static str)> {
    let mut rules = Vec::new();
    if df.allow_icmp_echo {
        rules.push((ICMP_V4_ECHO_RULE, "icmpv4:8,any"));
        rules.push((ICMP_V6_ECHO_RULE, "icmpv6:128,any"));
    }
    if df.allow_icmp_router {
        rules.push((ICMP_V6_ROUTER_RULE, "icmpv6:134,any"));
    }
    rules
}

fn join_firewall_profiles(profiles: &[String]) -> String {
    if profiles.is_empty() {
        return "any".into();
    }
    let mut normalized = Vec::with_capacity(profiles.len());
    for p in profiles {
        let lower = p.to_ascii_lowercase();
        if !normalized.contains(&lower) {
            normalized.push(lower);
        }
    }
    normalized.join(",")
}

fn query_firewall_profile_states(ops: &dyn SystemOps) -> Result<BTreeMap<String, bool>> {
    let out = ops.run_tool("netsh", &["advfirewall", "show", "allprofiles", "state"])?;
    if out.exit_code != 0 {
        bail!(
            "netsh advfirewall show allprofiles state failed (exit {}): {} {}",
            out.exit_code,
            out.stdout.trim(),
            out.stderr.trim()
        );
    }
    Ok(parse_firewall_profile_states(&out.stdout))
}

fn parse_firewall_profile_states(stdout: &str) -> BTreeMap<String, bool> {
    let mut map = BTreeMap::new();
    let mut current: Option<&'static str> = None;
    for line in stdout.lines() {
        let lower = line.trim().to_ascii_lowercase();
        if lower.starts_with("domain profile settings") {
            current = Some("domain");
        } else if lower.starts_with("private profile settings") {
            current = Some("private");
        } else if lower.starts_with("public profile settings") {
            current = Some("public");
        } else if let Some(prof) = current
            && let Some(rest) = lower.strip_prefix("state")
        {
            match rest.trim() {
                "on" => {
                    map.insert(prof.to_string(), true);
                    current = None;
                }
                "off" => {
                    map.insert(prof.to_string(), false);
                    current = None;
                }
                _ => {}
            }
        }
    }
    map
}

fn query_firewall_rule_names(ops: &dyn SystemOps) -> Result<Vec<String>> {
    let out = ops.run_tool(
        "netsh",
        &["advfirewall", "firewall", "show", "rule", "name=all"],
    )?;
    if out.exit_code != 0 {
        let combined = format!("{} {}", out.stdout, out.stderr).to_ascii_lowercase();
        if combined.contains("no rules match") {
            return Ok(Vec::new());
        }
        bail!(
            "netsh advfirewall firewall show rule failed (exit {}): {} {}",
            out.exit_code,
            out.stdout.trim(),
            out.stderr.trim()
        );
    }
    Ok(parse_firewall_rule_names(&out.stdout))
}

fn parse_firewall_rule_names(stdout: &str) -> Vec<String> {
    let mut rules = Vec::new();
    let mut pending_name: Option<String> = None;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if let Some(name) = pending_name.take() {
                rules.push(name);
            }
            continue;
        }
        if let Some((key, val)) = trimmed.split_once(':') {
            let k_lower = key.trim().to_ascii_lowercase();
            let v_trim = val.trim();
            if k_lower == "rule name" {
                if let Some(prev) = pending_name.take() {
                    rules.push(prev);
                }
                if !v_trim.is_empty() {
                    pending_name = Some(v_trim.to_string());
                }
            } else if k_lower == "enabled" {
                if v_trim.eq_ignore_ascii_case("no") {
                    pending_name = None;
                } else if let Some(name) = pending_name.take() {
                    rules.push(name);
                }
            }
        }
    }
    if let Some(name) = pending_name {
        rules.push(name);
    }
    rules
}

fn is_tamper_error(ops: &dyn SystemOps, err_msg: &str, tp_val: Option<u32>) -> bool {
    if !ops.is_admin() {
        return false;
    }
    let lower = err_msg.to_ascii_lowercase();
    if lower.contains("tamper") {
        return true;
    }
    tp_val.is_some_and(|v| v == 5 || v != 0)
}

fn format_reg_dword(val: Option<&RegValue>) -> String {
    match val.and_then(RegValue::as_dword) {
        Some(n) => n.to_string(),
        None if val.is_some() => "<non-dword>".into(),
        None => "<unset>".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::rollback_snapshot;
    use crate::platform::fake::FakeSystemOps;

    #[test]
    fn non_admin_check_returns_needs_admin_without_erroring() {
        let ops = FakeSystemOps::default();
        ops.state.borrow_mut().admin = false;
        let cfg = ProfileConfig::embedded_default();

        let check = DefenderFirewallRule.check(&ops, &cfg).unwrap();
        assert_eq!(check.status, CheckStatus::NeedsAdmin);
    }

    #[test]
    fn check_apply_idempotency_and_rollback() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();

        let c1 = DefenderFirewallRule.check(&ops, &cfg).unwrap();
        assert_eq!(c1.status, CheckStatus::Drifted);
        assert!(
            c1.diffs
                .iter()
                .any(|d| d.field == "Firewall Profile (domain)")
        );
        assert!(
            c1.diffs
                .iter()
                .any(|d| d.field.contains("IT-Tools: Allow ICMPv4 Echo In"))
        );

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = DefenderFirewallRule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert!(!changes.is_empty());

        assert_eq!(
            ops.reg_read(RegHive::Hklm, DEFENDER_POLICY_KEY, "DisableAntiSpyware")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hklm, DEFENDER_POLICY_UX_KEY, "UILockdown")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hklm, DEFENDER_UX_KEY, "UILockdown")
                .unwrap(),
            Some(RegValue::Dword(1))
        );

        {
            let st = ops.state.borrow();
            assert_eq!(st.firewall_profiles.get("domain"), Some(&true));
            assert_eq!(st.firewall_rules.len(), 3);
            assert!(
                st.recorded_commands
                    .iter()
                    .any(|c| c.contains("Set-MpPreference -UILockdown $true"))
            );
        }

        let c2 = DefenderFirewallRule.check(&ops, &cfg).unwrap();
        assert_eq!(c2.status, CheckStatus::Compliant);
        assert!(c2.diffs.is_empty());

        let mut snap2 = BackupSnapshot::new(&ops);
        let (outcome2, changes2) = DefenderFirewallRule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap2)
            .unwrap();
        assert_eq!(outcome2, RuleOutcome::AlreadyCompliant);
        assert!(changes2.is_empty());
        assert!(snap2.is_empty());

        rollback_snapshot(&ops, &snap).unwrap();
        let c3 = DefenderFirewallRule.check(&ops, &cfg).unwrap();
        assert_eq!(c3.status, CheckStatus::Drifted);
        assert_eq!(
            ops.state.borrow().firewall_profiles.get("domain"),
            Some(&false)
        );
        assert!(ops.state.borrow().firewall_rules.is_empty());
        assert!(
            ops.reg_read(RegHive::Hklm, DEFENDER_UX_KEY, "UILockdown")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn tamper_protection_warns_while_still_applying_firewall_and_supporting_rollback() {
        let ops = FakeSystemOps::default();
        ops.seed_reg(
            RegHive::Hklm,
            DEFENDER_FEATURES_KEY,
            "TamperProtection",
            RegValue::Dword(5),
        );
        ops.state.borrow_mut().tamper_protected = true;
        let cfg = ProfileConfig::embedded_default();

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = DefenderFirewallRule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();

        match outcome {
            RuleOutcome::WarnTamperProtected { detail } => {
                assert!(detail.to_ascii_lowercase().contains("tamper"));
            }
            other => panic!("expected WarnTamperProtected, got {other:?}"),
        }

        // Firewall MUST still have been applied and backed up!
        assert!(changes.iter().any(|c| c.contains("domain")));
        assert!(changes.iter().any(|c| c.contains(ICMP_V4_ECHO_RULE)));
        assert!(snap.firewall.is_some());
        assert!(
            snap.registry.is_empty(),
            "failed Defender writes must not pollute snap.registry"
        );

        {
            let st = ops.state.borrow();
            assert_eq!(st.firewall_profiles.get("domain"), Some(&true));
            assert_eq!(st.firewall_rules.len(), 3);
        }

        rollback_snapshot(&ops, &snap).unwrap();
        assert_eq!(
            ops.state.borrow().firewall_profiles.get("domain"),
            Some(&false)
        );
        assert!(ops.state.borrow().firewall_rules.is_empty());
    }
}
