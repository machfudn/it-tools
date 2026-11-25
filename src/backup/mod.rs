use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::platform::{RegHive, RegValue, SystemOps, decode_hex, encode_hex};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "data", rename_all = "snake_case")]
pub enum PriorRegValue {
    Absent,
    Present(RegValue),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegBackupEntry {
    pub hive: RegHive,
    pub path: String,
    pub name: String,
    pub prior: PriorRegValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerValueEntry {
    pub scheme_guid: String,
    pub subgroup: String,
    pub setting: String,
    pub ac: u32,
    pub dc: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerBackup {
    pub prior_active_guid: String,
    pub created_scheme_guid: Option<String>,
    pub prior_hibernate_enabled: bool,
    pub prior_values: Vec<PowerValueEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallBackup {
    pub prior_profiles: BTreeMap<String, bool>,
    pub created_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemRestoreBackup {
    pub drive: String,
    pub prior_enabled: bool,
    pub prior_max_size: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserFlagBackup {
    pub username: String,
    pub prior_dont_expire: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeLocalStateBackup {
    pub path: String,
    pub key_existed: bool,
    pub prior_pua_enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWriteBackup {
    pub path: String,
    pub prior_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSnapshot {
    pub version: u32,
    pub created_at: String,
    pub os_caption: String,
    pub registry: Vec<RegBackupEntry>,
    pub power: Option<PowerBackup>,
    pub secedit_inf: Option<String>,
    pub firewall: Option<FirewallBackup>,
    pub system_restore: Option<SystemRestoreBackup>,
    pub user_flags: Vec<UserFlagBackup>,
    pub startup_approved: Vec<RegBackupEntry>,
    pub edge_local_state: Option<EdgeLocalStateBackup>,
    #[serde(default)]
    pub created_dirs: Vec<String>,
    #[serde(default)]
    pub file_writes: Vec<FileWriteBackup>,
}

impl BackupSnapshot {
    pub fn new(ops: &dyn SystemOps) -> Self {
        Self {
            version: 1,
            created_at: ops.local_timestamp_iso(),
            os_caption: ops.os_caption(),
            registry: Vec::new(),
            power: None,
            secedit_inf: None,
            firewall: None,
            system_restore: None,
            user_flags: Vec::new(),
            startup_approved: Vec::new(),
            edge_local_state: None,
            created_dirs: Vec::new(),
            file_writes: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.registry.is_empty()
            && self.power.is_none()
            && self.secedit_inf.is_none()
            && self.firewall.is_none()
            && self.system_restore.is_none()
            && self.user_flags.is_empty()
            && self.startup_approved.is_empty()
            && self.edge_local_state.is_none()
            && self.created_dirs.is_empty()
            && self.file_writes.is_empty()
    }

    pub fn requires_admin(&self) -> bool {
        self.registry.iter().any(|r| r.hive != RegHive::Hkcu)
            || self
                .startup_approved
                .iter()
                .any(|r| r.hive != RegHive::Hkcu)
            || self.power.is_some()
            || self.secedit_inf.is_some()
            || self.firewall.is_some()
            || self.system_restore.is_some()
            || !self.user_flags.is_empty()
    }

    pub fn record_reg_once(
        &mut self,
        ops: &dyn SystemOps,
        hive: RegHive,
        path: &str,
        name: &str,
    ) -> Result<()> {
        if self.registry.iter().any(|e| {
            e.hive == hive && e.path.eq_ignore_ascii_case(path) && e.name.eq_ignore_ascii_case(name)
        }) {
            return Ok(());
        }
        let prior = match ops.reg_read(hive, path, name)? {
            Some(v) => PriorRegValue::Present(v),
            None => PriorRegValue::Absent,
        };
        self.registry.push(RegBackupEntry {
            hive,
            path: path.to_string(),
            name: name.to_string(),
            prior,
        });
        Ok(())
    }

    pub fn record_startup_once(
        &mut self,
        ops: &dyn SystemOps,
        hive: RegHive,
        path: &str,
        name: &str,
    ) -> Result<()> {
        if self.startup_approved.iter().any(|e| {
            e.hive == hive && e.path.eq_ignore_ascii_case(path) && e.name.eq_ignore_ascii_case(name)
        }) {
            return Ok(());
        }
        let prior = match ops.reg_read(hive, path, name)? {
            Some(v) => PriorRegValue::Present(v),
            None => PriorRegValue::Absent,
        };
        self.startup_approved.push(RegBackupEntry {
            hive,
            path: path.to_string(),
            name: name.to_string(),
            prior,
        });
        Ok(())
    }

    pub fn write_reg_with_backup(
        &mut self,
        ops: &dyn SystemOps,
        hive: RegHive,
        path: &str,
        name: &str,
        value: RegValue,
    ) -> Result<bool> {
        let current = ops.reg_read(hive, path, name)?;
        if current.as_ref() == Some(&value) {
            return Ok(false);
        }
        self.record_reg_once(ops, hive, path, name)?;
        ops.reg_write(hive, path, name, value)?;
        Ok(true)
    }

    pub fn delete_reg_with_backup(
        &mut self,
        ops: &dyn SystemOps,
        hive: RegHive,
        path: &str,
        name: &str,
    ) -> Result<bool> {
        let current = ops.reg_read(hive, path, name)?;
        if current.is_none() {
            return Ok(false);
        }
        self.record_reg_once(ops, hive, path, name)?;
        ops.reg_delete_value(hive, path, name)?;
        Ok(true)
    }

    pub fn record_dir_created_once(&mut self, dir: &Path) {
        let s = dir.to_string_lossy().into_owned();
        if !self.created_dirs.iter().any(|d| d.eq_ignore_ascii_case(&s)) {
            self.created_dirs.push(s);
        }
    }

    pub fn record_file_write_once(&mut self, path: &Path, prior_bytes: Option<&[u8]>) {
        let s = path.to_string_lossy().into_owned();
        if self
            .file_writes
            .iter()
            .any(|f| f.path.eq_ignore_ascii_case(&s))
        {
            return;
        }
        self.file_writes.push(FileWriteBackup {
            path: s,
            prior_hex: prior_bytes.map(encode_hex),
        });
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let json =
            serde_json::to_string_pretty(self).context("failed to serialize backup snapshot")?;
        fs::write(path, json)
            .with_context(|| format!("failed to write backup snapshot: {}", path.display()))?;
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read backup snapshot: {}", path.display()))?;
        let snap: Self = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse backup snapshot JSON: {}", path.display()))?;
        if snap.version != 1 {
            anyhow::bail!("unsupported backup snapshot version {}", snap.version);
        }
        Ok(snap)
    }
}

pub fn default_backup_path(dir: &Path, compact_ts: &str) -> PathBuf {
    dir.join(format!("it-tools.backup.{compact_ts}.json"))
}

pub fn list_backup_files(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|x| x.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("it-tools.backup.") && n.ends_with(".json"))
        })
        .collect();
    files.sort();
    files.reverse();
    Ok(files)
}

fn run_rollback_cmd(
    ops: &dyn SystemOps,
    program: &str,
    args: &[&str],
    label: &str,
    warnings: &mut Vec<String>,
) {
    match ops.run_tool(program, args) {
        Ok(out) if out.exit_code == 0 => {}
        Ok(out) => {
            let detail = if !out.stderr.trim().is_empty() {
                out.stderr.trim()
            } else {
                out.stdout.trim()
            };
            warnings.push(format!("{label} (exit {}): {detail}", out.exit_code));
        }
        Err(err) => warnings.push(format!("{label}: {err}")),
    }
}

pub fn rollback_snapshot(ops: &dyn SystemOps, snap: &BackupSnapshot) -> Result<Vec<String>> {
    if snap.requires_admin() && !ops.is_admin() {
        anyhow::bail!("Hak Administrator diperlukan untuk memulihkan snapshot ini.");
    }

    let mut actions = Vec::new();

    for entry in snap.registry.iter().rev() {
        restore_reg_entry(ops, entry)?;
        actions.push(format!(
            "restored {:?}\\{}\\{}",
            entry.hive, entry.path, entry.name
        ));
    }

    for entry in snap.startup_approved.iter().rev() {
        restore_reg_entry(ops, entry)?;
        actions.push(format!("restored startup {:?}\\{}", entry.hive, entry.name));
    }

    if let Some(power) = &snap.power {
        let mut pw_warns = Vec::new();
        for pv in &power.prior_values {
            let ac = pv.ac.to_string();
            let dc = pv.dc.to_string();
            run_rollback_cmd(
                ops,
                "powercfg",
                &[
                    "/setacvalueindex",
                    &pv.scheme_guid,
                    &pv.subgroup,
                    &pv.setting,
                    &ac,
                ],
                "powercfg /setacvalueindex",
                &mut pw_warns,
            );
            run_rollback_cmd(
                ops,
                "powercfg",
                &[
                    "/setdcvalueindex",
                    &pv.scheme_guid,
                    &pv.subgroup,
                    &pv.setting,
                    &dc,
                ],
                "powercfg /setdcvalueindex",
                &mut pw_warns,
            );
        }
        run_rollback_cmd(
            ops,
            "powercfg",
            &["/setactive", &power.prior_active_guid],
            "powercfg /setactive",
            &mut pw_warns,
        );
        if let Some(created) = &power.created_scheme_guid {
            run_rollback_cmd(
                ops,
                "powercfg",
                &["/delete", created],
                "powercfg /delete",
                &mut pw_warns,
            );
        }
        let h_flag = if power.prior_hibernate_enabled {
            "on"
        } else {
            "off"
        };
        run_rollback_cmd(
            ops,
            "powercfg",
            &["/h", h_flag],
            "powercfg /h",
            &mut pw_warns,
        );
        let warn_note = if pw_warns.is_empty() {
            String::new()
        } else {
            format!(" (peringatan: {})", pw_warns.join("; "))
        };
        actions.push(format!(
            "restored power scheme {}{warn_note}",
            power.prior_active_guid
        ));
    }

    if let Some(inf) = &snap.secedit_inf {
        let pid = std::process::id();
        let tmp_inf = ops
            .temp_dir()
            .join(format!("it-tools-rollback-sec-{pid}.inf"));
        let tmp_sdb = ops
            .temp_dir()
            .join(format!("it-tools-rollback-sec-{pid}.sdb"));
        let mut utf16 = Vec::with_capacity(2 + inf.len() * 2);
        utf16.push(0xFF);
        utf16.push(0xFE);
        for unit in inf.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        ops.write_file(&tmp_inf, &utf16)?;
        let inf_s = tmp_inf.to_string_lossy().into_owned();
        let sdb_s = tmp_sdb.to_string_lossy().into_owned();
        let out = ops.run_tool(
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
        )?;
        let _ = ops.remove_file_opt(&tmp_inf);
        let _ = ops.remove_file_opt(&tmp_sdb);
        if out.exit_code != 0 {
            anyhow::bail!("secedit rollback failed: {}", out.stderr);
        }
        actions.push("restored security policy via secedit".into());
    }

    if let Some(fw) = &snap.firewall {
        let mut fw_warns = Vec::new();
        for rule in &fw.created_rules {
            let arg = format!("name={rule}");
            run_rollback_cmd(
                ops,
                "netsh",
                &["advfirewall", "firewall", "delete", "rule", &arg],
                "netsh delete rule",
                &mut fw_warns,
            );
        }
        for (prof, enabled) in &fw.prior_profiles {
            let prof_arg = match prof.as_str() {
                "domain" => "domainprofile",
                "private" => "privateprofile",
                "public" => "publicprofile",
                other => other,
            };
            let state = if *enabled { "on" } else { "off" };
            run_rollback_cmd(
                ops,
                "netsh",
                &["advfirewall", "set", prof_arg, "state", state],
                "netsh set profile",
                &mut fw_warns,
            );
        }
        let warn_note = if fw_warns.is_empty() {
            String::new()
        } else {
            format!(" (peringatan: {})", fw_warns.join("; "))
        };
        actions.push(format!(
            "restored Windows Defender Firewall state & removed IT-Tools rules{warn_note}"
        ));
    }

    if let Some(sr) = &snap.system_restore {
        let mut sr_warns = Vec::new();
        if !sr.prior_enabled {
            let cmd = format!("Disable-ComputerRestore -Drive '{}\\'", sr.drive);
            run_rollback_cmd(
                ops,
                "powershell.exe",
                &["-NoProfile", "-NonInteractive", "-Command", &cmd],
                "Disable-ComputerRestore",
                &mut sr_warns,
            );
        } else if let Some(max) = &sr.prior_max_size {
            let for_arg = format!("/for={}", sr.drive);
            let on_arg = format!("/on={}", sr.drive);
            let max_arg = format!("/maxsize={max}");
            run_rollback_cmd(
                ops,
                "vssadmin",
                &["resize", "shadowstorage", &for_arg, &on_arg, &max_arg],
                "vssadmin resize shadowstorage",
                &mut sr_warns,
            );
        }
        let warn_note = if sr_warns.is_empty() {
            String::new()
        } else {
            format!(" (peringatan: {})", sr_warns.join("; "))
        };
        actions.push(format!(
            "restored System Restore on {}{warn_note}",
            sr.drive
        ));
    }

    if let Some(edge) = &snap.edge_local_state
        && !ops.is_process_running("msedge.exe")
    {
        let p = PathBuf::from(&edge.path);
        if let Some(raw) = ops.read_file_opt(&p)?
            && let Ok(mut doc) = serde_json::from_slice::<serde_json::Value>(&raw)
            && let Some(obj) = doc.get_mut("smartscreen").and_then(|v| v.as_object_mut())
        {
            if !edge.key_existed {
                obj.remove("pua_protection_enabled");
            } else if let Some(prev) = edge.prior_pua_enabled {
                obj.insert(
                    "pua_protection_enabled".into(),
                    serde_json::Value::Bool(prev),
                );
            }
            if let Ok(new_bytes) = serde_json::to_vec(&doc) {
                ops.write_file(&p, &new_bytes)?;
                actions.push("restored Edge Local State smartscreen.pua_protection_enabled".into());
            }
        }
    }

    for uf in &snap.user_flags {
        ops.set_user_dont_expire(&uf.username, uf.prior_dont_expire)?;
        actions.push(format!(
            "restored user '{}' PasswordNeverExpires={}",
            uf.username, uf.prior_dont_expire
        ));
    }

    for fw in snap.file_writes.iter().rev() {
        let p = PathBuf::from(&fw.path);
        match &fw.prior_hex {
            None => {
                ops.remove_file_opt(&p)?;
                actions.push(format!("removed created file {}", fw.path));
            }
            Some(hex) => {
                let bytes = decode_hex(hex)
                    .with_context(|| format!("decode backup bytes for {}", fw.path))?;
                ops.write_file(&p, &bytes)?;
                actions.push(format!("restored overwritten file {}", fw.path));
            }
        }
    }

    for dir in snap.created_dirs.iter().rev() {
        let p = PathBuf::from(dir);
        if ops.remove_empty_dir(&p)? {
            actions.push(format!("removed empty directory {dir}"));
        } else {
            actions.push(format!(
                "skipped removing directory {dir} (tidak kosong atau sudah dihapus)"
            ));
        }
    }

    let _ = ops.broadcast_setting_change();
    Ok(actions)
}

fn restore_reg_entry(ops: &dyn SystemOps, entry: &RegBackupEntry) -> Result<()> {
    match &entry.prior {
        PriorRegValue::Absent => ops.reg_delete_value(entry.hive, &entry.path, &entry.name),
        PriorRegValue::Present(val) => {
            ops.reg_write(entry.hive, &entry.path, &entry.name, val.clone())
        }
    }
}
