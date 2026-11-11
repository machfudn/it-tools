use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::platform::{RegHive, RegValue, SystemOps};

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

pub fn rollback_snapshot(ops: &dyn SystemOps, snap: &BackupSnapshot) -> Result<Vec<String>> {
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
        for pv in &power.prior_values {
            let ac = pv.ac.to_string();
            let dc = pv.dc.to_string();
            let _ = ops.run_tool(
                "powercfg",
                &[
                    "/setacvalueindex",
                    &pv.scheme_guid,
                    &pv.subgroup,
                    &pv.setting,
                    &ac,
                ],
            );
            let _ = ops.run_tool(
                "powercfg",
                &[
                    "/setdcvalueindex",
                    &pv.scheme_guid,
                    &pv.subgroup,
                    &pv.setting,
                    &dc,
                ],
            );
        }
        let _ = ops.run_tool("powercfg", &["/setactive", &power.prior_active_guid]);
        if let Some(created) = &power.created_scheme_guid {
            let _ = ops.run_tool("powercfg", &["/delete", created]);
        }
        let h_flag = if power.prior_hibernate_enabled {
            "on"
        } else {
            "off"
        };
        let _ = ops.run_tool("powercfg", &["/h", h_flag]);
        actions.push(format!("restored power scheme {}", power.prior_active_guid));
    }

    if let Some(inf) = &snap.secedit_inf {
        let tmp_inf = ops.temp_dir().join("it-tools-rollback-sec.inf");
        let tmp_sdb = ops.temp_dir().join("it-tools-rollback-sec.sdb");
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
        for rule in &fw.created_rules {
            let arg = format!("name={rule}");
            let _ = ops.run_tool(
                "netsh",
                &["advfirewall", "firewall", "delete", "rule", &arg],
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
            let _ = ops.run_tool("netsh", &["advfirewall", "set", prof_arg, "state", state]);
        }
        actions.push("restored Windows Defender Firewall state & removed IT-Tools rules".into());
    }

    if let Some(sr) = &snap.system_restore {
        if !sr.prior_enabled {
            let cmd = format!("Disable-ComputerRestore -Drive '{}\\'", sr.drive);
            let _ = ops.run_tool(
                "powershell.exe",
                &["-NoProfile", "-NonInteractive", "-Command", &cmd],
            );
        } else if let Some(max) = &sr.prior_max_size {
            let for_arg = format!("/for={}", sr.drive);
            let on_arg = format!("/on={}", sr.drive);
            let max_arg = format!("/maxsize={max}");
            let _ = ops.run_tool(
                "vssadmin",
                &["resize", "shadowstorage", &for_arg, &on_arg, &max_arg],
            );
        }
        actions.push(format!("restored System Restore on {}", sr.drive));
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
