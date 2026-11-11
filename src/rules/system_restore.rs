use anyhow::{Result, bail};

use crate::backup::{BackupSnapshot, SystemRestoreBackup};
use crate::config::ProfileConfig;
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, SystemOps};

const SR_REG_PATH: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore";
const VAL_RP_SESSION: &str = "RPSessionInterval";
const VAL_DISABLE_SR: &str = "DisableSR";

pub struct SystemRestoreRule;

#[derive(Debug, Clone, PartialEq)]
enum VssSize {
    Mib(f64),
    Percent(u32),
    Unbounded,
}

#[derive(Debug, Clone)]
struct VssParsedValue {
    primary: VssSize,
    pct_hint: Option<u32>,
}

impl Rule for SystemRestoreRule {
    fn id(&self) -> &'static str {
        "system_restore"
    }

    fn title(&self) -> &'static str {
        "System Restore"
    }

    fn requires_admin(&self) -> bool {
        true
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.system_restore.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let sr = &cfg.rules.system_restore;
        if !ops.is_admin() {
            return Ok(RuleCheck {
                id: self.id().into(),
                title: self.title().into(),
                requires_admin: true,
                enabled_in_config: sr.enabled,
                status: CheckStatus::NeedsAdmin,
                diffs: Vec::new(),
                note: Some("Administrator privileges required to query Volume Shadow Copy storage via vssadmin".into()),
            });
        }
        let drive = normalize_drive(&sr.drive);
        let (cur_enabled, cur_max_raw) = inspect_system_restore(ops, &drive)?;

        let mut diffs = Vec::new();
        if cur_enabled != sr.enable {
            diffs.push(DiffItem {
                field: format!("restore_{drive}"),
                current: enabled_label(cur_enabled).into(),
                target: enabled_label(sr.enable).into(),
            });
        }

        if sr.enable {
            let target_size = sr.max_size.trim();
            let size_ok = cur_max_raw
                .as_deref()
                .is_some_and(|raw| vss_sizes_match(raw, target_size));
            if !size_ok {
                diffs.push(DiffItem {
                    field: format!("shadowstorage_{drive}"),
                    current: cur_max_raw.unwrap_or_else(|| "none".into()),
                    target: target_size.into(),
                });
            }
        }

        Ok(RuleCheck {
            id: self.id().into(),
            title: self.title().into(),
            requires_admin: self.requires_admin(),
            enabled_in_config: sr.enabled,
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
        let sr = &cfg.rules.system_restore;
        let drive = normalize_drive(&sr.drive);
        let (cur_enabled, cur_max_raw) = inspect_system_restore(ops, &drive)?;
        let target_size = sr.max_size.trim();

        let size_ok = !sr.enable
            || cur_max_raw
                .as_deref()
                .is_some_and(|raw| vss_sizes_match(raw, target_size));

        if cur_enabled == sr.enable && size_ok {
            return Ok((RuleOutcome::AlreadyCompliant, Vec::new()));
        }

        if snap.system_restore.is_none() {
            snap.system_restore = Some(SystemRestoreBackup {
                drive: drive.clone(),
                prior_enabled: cur_enabled,
                prior_max_size: cur_max_raw.as_deref().map(format_vss_maxsize_for_restore),
            });
        }

        let mut changes = Vec::new();
        if sr.enable {
            if !cur_enabled {
                let ps_cmd = format!("Enable-ComputerRestore -Drive '{drive}\\'");
                let out = ops.run_tool(
                    "powershell.exe",
                    &["-NoProfile", "-NonInteractive", "-Command", &ps_cmd],
                )?;
                if out.exit_code != 0 {
                    bail!(
                        "Enable-ComputerRestore -Drive '{drive}\\' failed: {}",
                        detail_from_cmd(&out.stderr, &out.stdout, out.exit_code)
                    );
                }
                changes.push(format!("enabled System Restore on {drive}"));
            }

            if !size_ok {
                let for_arg = format!("/for={drive}");
                let on_arg = format!("/on={drive}");
                let max_arg = format!("/maxsize={target_size}");
                let resize = ops.run_tool(
                    "vssadmin",
                    &["resize", "shadowstorage", &for_arg, &on_arg, &max_arg],
                )?;
                if resize.exit_code != 0 {
                    let add = ops.run_tool(
                        "vssadmin",
                        &["add", "shadowstorage", &for_arg, &on_arg, &max_arg],
                    )?;
                    if add.exit_code != 0 {
                        bail!(
                            "vssadmin resize/add shadowstorage on {drive} failed: resize='{}'; add='{}'",
                            detail_from_cmd(&resize.stderr, &resize.stdout, resize.exit_code),
                            detail_from_cmd(&add.stderr, &add.stdout, add.exit_code),
                        );
                    }
                }
                changes.push(format!(
                    "set shadowstorage max size on {drive} to {target_size}"
                ));
            }
        } else {
            let ps_cmd = format!("Disable-ComputerRestore -Drive '{drive}\\'");
            let out = ops.run_tool(
                "powershell.exe",
                &["-NoProfile", "-NonInteractive", "-Command", &ps_cmd],
            )?;
            if out.exit_code != 0 {
                bail!(
                    "Disable-ComputerRestore -Drive '{drive}\\' failed: {}",
                    detail_from_cmd(&out.stderr, &out.stdout, out.exit_code)
                );
            }
            changes.push(format!("disabled System Restore on {drive}"));
        }

        Ok((RuleOutcome::Applied, changes))
    }
}

fn inspect_system_restore(ops: &dyn SystemOps, drive: &str) -> Result<(bool, Option<String>)> {
    let disable_sr = ops
        .reg_read(RegHive::Hklm, SR_REG_PATH, VAL_DISABLE_SR)?
        .and_then(|v| v.as_dword());
    let rp_session = ops
        .reg_read(RegHive::Hklm, SR_REG_PATH, VAL_RP_SESSION)?
        .and_then(|v| v.as_dword());

    let out = ops.run_tool("vssadmin", &["list", "shadowstorage"])?;
    let max_size = parse_shadowstorage_for_drive(&out.stdout, drive);

    if out.exit_code != 0 && max_size.is_none() && !is_empty_vss_query(&out.stdout, &out.stderr) {
        bail!(
            "vssadmin list shadowstorage failed: {}",
            detail_from_cmd(&out.stderr, &out.stdout, out.exit_code)
        );
    }

    let enabled = if disable_sr == Some(1) || rp_session == Some(0) {
        false
    } else {
        max_size.is_some()
    };

    Ok((enabled, max_size))
}

fn is_empty_vss_query(stdout: &str, stderr: &str) -> bool {
    let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    combined.contains("no items found")
}

fn parse_shadowstorage_for_drive(stdout: &str, drive: &str) -> Option<String> {
    let paren_drive = format!("({})", drive.to_ascii_uppercase());
    let slash_drive = format!("{}\\", drive.to_ascii_uppercase());
    let mut in_matching_block = false;

    for raw in stdout.lines() {
        let trimmed = raw.trim();
        let lower = trimmed.to_ascii_lowercase();

        if lower.starts_with("shadow copy storage association") {
            in_matching_block = false;
            continue;
        }
        if lower.starts_with("for volume:") {
            let rhs = trimmed
                .split_once(':')
                .map_or("", |x| x.1)
                .to_ascii_uppercase();
            in_matching_block = rhs.contains(&paren_drive) || rhs.contains(&slash_drive);
            continue;
        }
        if in_matching_block
            && lower.starts_with("maximum shadow copy storage space:")
            && let Some((_, rhs)) = trimmed.split_once(':')
        {
            let val = rhs.trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn vss_sizes_match(current_raw: &str, target_raw: &str) -> bool {
    let Some(cur) = parse_vss_value(current_raw) else {
        return current_raw.trim().eq_ignore_ascii_case(target_raw.trim());
    };
    let Some(tgt) = parse_vss_value(target_raw) else {
        return current_raw.trim().eq_ignore_ascii_case(target_raw.trim());
    };

    match (&cur.primary, &tgt.primary) {
        (VssSize::Mib(c), VssSize::Mib(t)) => {
            let tol = (t * 0.02).max(2.0);
            (c - t).abs() <= tol
        }
        (VssSize::Percent(c), VssSize::Percent(t)) => c == t,
        (VssSize::Mib(_), VssSize::Percent(t)) => cur.pct_hint == Some(*t),
        (VssSize::Unbounded, VssSize::Unbounded) => true,
        _ => false,
    }
}

fn parse_vss_value(raw: &str) -> Option<VssParsedValue> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut pct_hint = None;
    let main_part = if let Some(open) = trimmed.rfind('(') {
        if let Some(close) = trimmed[open..].find(')') {
            let inner = trimmed[open + 1..open + close].trim();
            if let Some(num) = inner.strip_suffix('%') {
                pct_hint = num.trim().parse::<u32>().ok();
            }
            trimmed[..open].trim()
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    let upper = main_part.to_ascii_uppercase();
    if upper.starts_with("UNBOUNDED") {
        return Some(VssParsedValue {
            primary: VssSize::Unbounded,
            pct_hint,
        });
    }

    if let Some(num) = upper.strip_suffix('%') {
        let pct = num.trim().parse::<u32>().ok()?;
        return Some(VssParsedValue {
            primary: VssSize::Percent(pct),
            pct_hint: Some(pct),
        });
    }

    let bytes_or_mib = parse_size_to_mib(&upper)?;
    Some(VssParsedValue {
        primary: VssSize::Mib(bytes_or_mib),
        pct_hint,
    })
}

fn parse_size_to_mib(upper: &str) -> Option<f64> {
    let (num_str, mult) = if let Some(r) = upper.strip_suffix("TB") {
        (r, 1024.0 * 1024.0)
    } else if let Some(r) = upper.strip_suffix("GB") {
        (r, 1024.0)
    } else if let Some(r) = upper.strip_suffix("MB") {
        (r, 1.0)
    } else if let Some(r) = upper.strip_suffix("KB") {
        (r, 1.0 / 1024.0)
    } else if let Some(r) = upper.strip_suffix("BYTES") {
        (r, 1.0 / (1024.0 * 1024.0))
    } else if let Some(r) = upper.strip_suffix("BYTE") {
        (r, 1.0 / (1024.0 * 1024.0))
    } else {
        let r = upper.strip_suffix('B')?;
        (r, 1.0 / (1024.0 * 1024.0))
    };

    let normalized_num = num_str.trim().replace(',', "");
    let val = normalized_num.parse::<f64>().ok()?;
    Some(val * mult)
}

fn format_vss_maxsize_for_restore(raw: &str) -> String {
    let trimmed = raw.trim();
    // Preserve clean tokens like "10GB", "5120MB", "5%", "UNBOUNDED".
    let no_paren = trimmed
        .split('(')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .replace(' ', "");
    if let Some(parsed) = parse_vss_value(trimmed) {
        match parsed.primary {
            VssSize::Unbounded => return "UNBOUNDED".into(),
            VssSize::Percent(p) => return format!("{p}%"),
            VssSize::Mib(mib) => {
                if !no_paren.contains('.') && no_paren.to_ascii_uppercase().ends_with("GB") {
                    return no_paren.to_ascii_uppercase();
                }
                if !no_paren.contains('.') && no_paren.to_ascii_uppercase().ends_with("MB") {
                    return no_paren.to_ascii_uppercase();
                }
                let rounded_mb = mib.round().max(1.0) as u64;
                if rounded_mb.is_multiple_of(1024) {
                    return format!("{}GB", rounded_mb / 1024);
                }
                return format!("{rounded_mb}MB");
            }
        }
    }
    no_paren
}

fn normalize_drive(drive: &str) -> String {
    let trimmed = drive.trim().trim_end_matches(['\\', '/']);
    trimmed.to_ascii_uppercase()
}

fn enabled_label(v: bool) -> &'static str {
    if v { "enabled" } else { "disabled" }
}

fn detail_from_cmd(stderr: &str, stdout: &str, code: i32) -> String {
    let s = stderr.trim();
    if !s.is_empty() {
        return s.to_string();
    }
    let o = stdout.trim();
    if !o.is_empty() {
        return o.to_string();
    }
    format!("exit code {code}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::rollback_snapshot;
    use crate::platform::CmdOutput;
    use crate::platform::RegValue;
    use crate::platform::fake::FakeSystemOps;
    use std::cell::RefCell;

    #[test]
    fn normal_flow_enable_resize_idempotent_and_rollback() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let rule = SystemRestoreRule;
        let opts = ApplyOptions::default();

        let check1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(check1.status, CheckStatus::Drifted);
        assert!(check1.diffs.iter().any(|d| d.field == "restore_C:"));
        assert!(check1.diffs.iter().any(|d| d.field == "shadowstorage_C:"));

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome1, changes1) = rule.apply(&ops, &cfg, &opts, &mut snap).unwrap();
        assert_eq!(outcome1, RuleOutcome::Applied);
        assert_eq!(changes1.len(), 2);

        {
            let st = ops.state.borrow();
            assert!(st.restore_enabled);
            assert_eq!(st.shadow_max_size.as_deref(), Some("5GB"));
        }
        let srb = snap
            .system_restore
            .as_ref()
            .expect("SystemRestoreBackup recorded");
        assert_eq!(srb.drive, "C:");
        assert!(!srb.prior_enabled);
        assert_eq!(srb.prior_max_size, None);

        let check2 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(check2.status, CheckStatus::Compliant);
        assert!(check2.diffs.is_empty());

        let mut snap2 = BackupSnapshot::new(&ops);
        let (outcome2, changes2) = rule.apply(&ops, &cfg, &opts, &mut snap2).unwrap();
        assert_eq!(outcome2, RuleOutcome::AlreadyCompliant);
        assert!(changes2.is_empty());
        assert!(snap2.system_restore.is_none());

        rollback_snapshot(&ops, &snap).unwrap();
        assert!(!ops.state.borrow().restore_enabled);
    }

    #[test]
    fn resize_from_existing_size_rolls_back_prior_max_size() {
        let ops = FakeSystemOps::default();
        {
            let mut st = ops.state.borrow_mut();
            st.restore_enabled = true;
            st.shadow_max_size = Some("10GB".into());
        }
        let cfg = ProfileConfig::embedded_default();
        let rule = SystemRestoreRule;
        let opts = ApplyOptions::default();

        let check1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(check1.status, CheckStatus::Drifted);
        assert_eq!(check1.diffs.len(), 1);
        assert_eq!(check1.diffs[0].field, "shadowstorage_C:");

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, _) = rule.apply(&ops, &cfg, &opts, &mut snap).unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(ops.state.borrow().shadow_max_size.as_deref(), Some("5GB"));

        let srb = snap.system_restore.as_ref().unwrap();
        assert!(srb.prior_enabled);
        assert_eq!(srb.prior_max_size.as_deref(), Some("10GB"));

        rollback_snapshot(&ops, &snap).unwrap();
        assert_eq!(ops.state.borrow().shadow_max_size.as_deref(), Some("10GB"));
    }

    #[test]
    fn registry_disabled_state_triggers_drift_even_with_shadowstorage() {
        let ops = FakeSystemOps::default();
        ops.state.borrow_mut().shadow_max_size = Some("5.00 GB (1%)".into());
        ops.seed_reg(
            RegHive::Hklm,
            SR_REG_PATH,
            VAL_RP_SESSION,
            RegValue::Dword(0),
        );

        let cfg = ProfileConfig::embedded_default();
        let rule = SystemRestoreRule;
        let check = rule.check(&ops, &cfg).unwrap();
        assert_eq!(check.status, CheckStatus::Drifted);
        assert_eq!(check.diffs.len(), 1);
        assert_eq!(check.diffs[0].field, "restore_C:");
    }

    #[test]
    fn shadowstorage_parsing_and_size_normalization() {
        let vss_out = "\
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\r\n\
\r\n\
Shadow Copy Storage association\r\n\
   For volume: (D:)\\\\?\\Volume{aaaa}\\\r\n\
   Shadow Copy Storage volume: (D:)\\\\?\\Volume{aaaa}\\\r\n\
   Used Shadow Copy Storage space: 0 bytes (0%)\r\n\
   Allocated Shadow Copy Storage space: 0 bytes (0%)\r\n\
   Maximum Shadow Copy Storage space: 20.00 GB (2%)\r\n\
\r\n\
Shadow Copy Storage association\r\n\
   For volume: (C:)\\\\?\\Volume{bbbb}\\\r\n\
   Shadow Copy Storage volume: (C:)\\\\?\\Volume{bbbb}\\\r\n\
   Used Shadow Copy Storage space: 120 MB (0%)\r\n\
   Allocated Shadow Copy Storage space: 300 MB (0%)\r\n\
   Maximum Shadow Copy Storage space: 5.00 GB (1%)\r\n";

        assert_eq!(
            parse_shadowstorage_for_drive(vss_out, "C:").as_deref(),
            Some("5.00 GB (1%)")
        );
        assert_eq!(
            parse_shadowstorage_for_drive(vss_out, "D:").as_deref(),
            Some("20.00 GB (2%)")
        );
        assert_eq!(parse_shadowstorage_for_drive(vss_out, "E:"), None);

        assert!(vss_sizes_match("5.00 GB (1%)", "5GB"));
        assert!(vss_sizes_match("5120 MB", "5GB"));
        assert!(vss_sizes_match("23.78 GB (5%)", "5%"));
        assert!(!vss_sizes_match("10.00 GB (2%)", "5GB"));
        assert!(!vss_sizes_match("UNBOUNDED", "5GB"));
        assert_eq!(format_vss_maxsize_for_restore("10.00 GB (2%)"), "10GB");
    }

    #[test]
    fn resize_failure_falls_back_to_vssadmin_add() {
        struct AddFallbackOps {
            inner: FakeSystemOps,
            saw_add: RefCell<bool>,
        }
        impl SystemOps for AddFallbackOps {
            fn reg_read(
                &self,
                h: RegHive,
                p: &str,
                n: &str,
            ) -> Result<Option<crate::platform::RegValue>> {
                self.inner.reg_read(h, p, n)
            }
            fn reg_write(
                &self,
                h: RegHive,
                p: &str,
                n: &str,
                v: crate::platform::RegValue,
            ) -> Result<()> {
                self.inner.reg_write(h, p, n, v)
            }
            fn reg_delete_value(&self, h: RegHive, p: &str, n: &str) -> Result<()> {
                self.inner.reg_delete_value(h, p, n)
            }
            fn reg_list_values(
                &self,
                h: RegHive,
                p: &str,
            ) -> Result<Vec<(String, crate::platform::RegValue)>> {
                self.inner.reg_list_values(h, p)
            }
            fn reg_list_subkeys(&self, h: RegHive, p: &str) -> Result<Vec<String>> {
                self.inner.reg_list_subkeys(h, p)
            }
            fn local_appdata_dir(&self) -> Option<std::path::PathBuf> {
                self.inner.local_appdata_dir()
            }
            fn startup_folders(&self) -> Vec<(String, std::path::PathBuf)> {
                self.inner.startup_folders()
            }
            fn read_file_opt(&self, p: &std::path::Path) -> Result<Option<Vec<u8>>> {
                self.inner.read_file_opt(p)
            }
            fn write_file(&self, p: &std::path::Path, b: &[u8]) -> Result<()> {
                self.inner.write_file(p, b)
            }
            fn remove_file_opt(&self, p: &std::path::Path) -> Result<()> {
                self.inner.remove_file_opt(p)
            }
            fn temp_dir(&self) -> std::path::PathBuf {
                self.inner.temp_dir()
            }
            fn is_process_running(&self, e: &str) -> bool {
                self.inner.is_process_running(e)
            }
            fn is_admin(&self) -> bool {
                self.inner.is_admin()
            }
            fn is_console_tty(&self) -> bool {
                self.inner.is_console_tty()
            }
            fn current_username(&self) -> String {
                self.inner.current_username()
            }
            fn os_caption(&self) -> String {
                self.inner.os_caption()
            }
            fn local_timestamp_compact(&self) -> String {
                self.inner.local_timestamp_compact()
            }
            fn local_timestamp_iso(&self) -> String {
                self.inner.local_timestamp_iso()
            }
            fn relaunch_as_admin(&self, a: &[String]) -> Result<()> {
                self.inner.relaunch_as_admin(a)
            }
            fn list_local_users(&self) -> Result<Vec<crate::platform::LocalUserInfo>> {
                self.inner.list_local_users()
            }
            fn create_local_user(&self, n: &str, pw: &str) -> Result<()> {
                self.inner.create_local_user(n, pw)
            }
            fn set_user_dont_expire(&self, n: &str, d: bool) -> Result<()> {
                self.inner.set_user_dont_expire(n, d)
            }
            fn set_user_password(&self, n: &str, pw: &str) -> Result<()> {
                self.inner.set_user_password(n, pw)
            }
            fn http_get(&self, u: &str, a: Option<&str>) -> Result<Vec<u8>> {
                self.inner.http_get(u, a)
            }
            fn current_exe_path(&self) -> Result<std::path::PathBuf> {
                self.inner.current_exe_path()
            }
            fn rename_file(&self, f: &std::path::Path, t: &std::path::Path) -> Result<()> {
                self.inner.rename_file(f, t)
            }
            fn run_tool(&self, program: &str, args: &[&str]) -> Result<CmdOutput> {
                if program.eq_ignore_ascii_case("vssadmin") && args.first() == Some(&"resize") {
                    return Ok(CmdOutput {
                        exit_code: 1,
                        stdout: String::new(),
                        stderr: "Error: The specified volume does not have shadow copy storage association.".into(),
                    });
                }
                if program.eq_ignore_ascii_case("vssadmin") && args.first() == Some(&"add") {
                    *self.saw_add.borrow_mut() = true;
                    return Ok(CmdOutput {
                        exit_code: 0,
                        stdout: "Successfully added the shadow copy storage association.".into(),
                        stderr: String::new(),
                    });
                }
                self.inner.run_tool(program, args)
            }
            fn broadcast_setting_change(&self) -> Result<()> {
                self.inner.broadcast_setting_change()
            }
            fn restart_explorer(&self) -> Result<()> {
                self.inner.restart_explorer()
            }
        }

        let ops = AddFallbackOps {
            inner: FakeSystemOps::default(),
            saw_add: RefCell::new(false),
        };
        let cfg = ProfileConfig::embedded_default();
        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, _) = SystemRestoreRule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert!(*ops.saw_add.borrow());
    }
}
