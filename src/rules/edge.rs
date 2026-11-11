use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::backup::{BackupSnapshot, EdgeLocalStateBackup};
use crate::config::ProfileConfig;
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, RegValue, SystemOps};

pub struct EdgeRule;

const EDGE_POLICY_PATH: &str = r"SOFTWARE\Policies\Microsoft\Edge";
const LEGACY_EDGE_MAIN_PATH: &str = r"SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main";
const HKCU_EDGE_PUA_PATH: &str = r"Software\Microsoft\Edge\SmartScreenPuaEnabled";

struct RegSpec {
    hive: RegHive,
    path: &'static str,
    name: &'static str,
    value: RegValue,
}

fn bool_dword(v: bool) -> RegValue {
    RegValue::Dword(u32::from(v))
}

fn build_specs(cfg: &ProfileConfig) -> Vec<RegSpec> {
    let e = &cfg.rules.edge;
    vec![
        RegSpec {
            hive: RegHive::Hklm,
            path: EDGE_POLICY_PATH,
            name: "NewTabPagePrerenderEnabled",
            value: bool_dword(e.preload_new_tab),
        },
        RegSpec {
            hive: RegHive::Hklm,
            path: EDGE_POLICY_PATH,
            name: "StartupBoostEnabled",
            value: bool_dword(e.prelaunch_startup),
        },
        RegSpec {
            hive: RegHive::Hklm,
            path: EDGE_POLICY_PATH,
            name: "BackgroundModeEnabled",
            value: bool_dword(e.prelaunch_startup),
        },
        RegSpec {
            hive: RegHive::Hklm,
            path: EDGE_POLICY_PATH,
            name: "SmartScreenPuaEnabled",
            value: bool_dword(e.block_pua),
        },
        RegSpec {
            hive: RegHive::Hklm,
            path: LEGACY_EDGE_MAIN_PATH,
            name: "AllowPrelaunch",
            value: bool_dword(e.prelaunch_startup),
        },
        RegSpec {
            hive: RegHive::Hklm,
            path: LEGACY_EDGE_MAIN_PATH,
            name: "AllowTabPreloading",
            value: bool_dword(e.tab_preloading),
        },
        RegSpec {
            hive: RegHive::Hkcu,
            path: HKCU_EDGE_PUA_PATH,
            name: "",
            value: bool_dword(e.block_pua),
        },
    ]
}

fn edge_local_state_path(local_appdata: &Path) -> PathBuf {
    local_appdata
        .join("Microsoft")
        .join("Edge")
        .join("User Data")
        .join("Local State")
}

fn hive_label(hive: RegHive) -> &'static str {
    match hive {
        RegHive::Hkcu => "HKCU",
        RegHive::Hklm => "HKLM",
    }
}

fn reg_field_name(hive: RegHive, path: &str, name: &str) -> String {
    let display_name = if name.is_empty() { "(Default)" } else { name };
    format!("{}\\{}\\{}", hive_label(hive), path, display_name)
}

fn fmt_reg_value(val: Option<&RegValue>) -> String {
    match val {
        None => "<absent>".into(),
        Some(RegValue::Dword(v)) => v.to_string(),
        Some(RegValue::Sz(s)) | Some(RegValue::ExpandSz(s)) => s.clone(),
        Some(RegValue::BinaryHex(h)) => format!("hex:{h}"),
    }
}

impl Rule for EdgeRule {
    fn id(&self) -> &'static str {
        "edge"
    }

    fn title(&self) -> &'static str {
        "Microsoft Edge"
    }

    fn requires_admin(&self) -> bool {
        true
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.edge.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let mut diffs = Vec::new();
        let mut note = None;

        for spec in build_specs(cfg) {
            let current = ops.reg_read(spec.hive, spec.path, spec.name)?;
            if current.as_ref() != Some(&spec.value) {
                diffs.push(DiffItem {
                    field: reg_field_name(spec.hive, spec.path, spec.name),
                    current: fmt_reg_value(current.as_ref()),
                    target: fmt_reg_value(Some(&spec.value)),
                });
            }
        }

        if let Some(local_appdata) = ops.local_appdata_dir() {
            let ls_path = edge_local_state_path(&local_appdata);
            if let Some(raw) = ops.read_file_opt(&ls_path)? {
                let doc: serde_json::Value = serde_json::from_slice(&raw).with_context(|| {
                    format!("failed to parse Edge Local State: {}", ls_path.display())
                })?;
                let cur_pua = doc
                    .get("smartscreen")
                    .and_then(|v| v.get("pua_protection_enabled"))
                    .and_then(|v| v.as_bool());
                let want_pua = cfg.rules.edge.block_pua;
                if cur_pua != Some(want_pua) {
                    diffs.push(DiffItem {
                        field: "Edge Local State smartscreen.pua_protection_enabled".into(),
                        current: cur_pua.map_or_else(|| "<absent>".into(), |b| b.to_string()),
                        target: want_pua.to_string(),
                    });
                    if ops.is_process_running("msedge.exe") {
                        note = Some(
                            "msedge.exe is running; Local State update requires closing Edge"
                                .into(),
                        );
                    }
                }
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
            note,
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
        for spec in build_specs(cfg) {
            let display = fmt_reg_value(Some(&spec.value));
            if snap.write_reg_with_backup(ops, spec.hive, spec.path, spec.name, spec.value)? {
                changes.push(format!(
                    "set {} = {}",
                    reg_field_name(spec.hive, spec.path, spec.name),
                    display
                ));
            }
        }

        if let Some(local_appdata) = ops.local_appdata_dir() {
            let ls_path = edge_local_state_path(&local_appdata);
            if let Some(raw) = ops.read_file_opt(&ls_path)? {
                let mut doc: serde_json::Value =
                    serde_json::from_slice(&raw).with_context(|| {
                        format!("failed to parse Edge Local State: {}", ls_path.display())
                    })?;
                let want_pua = cfg.rules.edge.block_pua;
                let cur_pua = doc
                    .get("smartscreen")
                    .and_then(|v| v.get("pua_protection_enabled"))
                    .and_then(|v| v.as_bool());

                if cur_pua != Some(want_pua) {
                    if ops.is_process_running("msedge.exe") {
                        return Ok((
                            RuleOutcome::WarnEdgeRunning {
                                detail: "msedge.exe is running; applied registry policies, skipped Edge Local State update".into(),
                            },
                            changes,
                        ));
                    }

                    let smartscreen_obj = doc.get("smartscreen").and_then(|v| v.as_object());
                    let key_existed =
                        smartscreen_obj.is_some_and(|o| o.contains_key("pua_protection_enabled"));
                    let prior_pua_enabled = smartscreen_obj
                        .and_then(|o| o.get("pua_protection_enabled"))
                        .and_then(|v| v.as_bool());

                    let root = doc
                        .as_object_mut()
                        .context("Edge Local State JSON root must be an object")?;
                    if !root.get("smartscreen").is_some_and(|v| v.is_object()) {
                        root.insert("smartscreen".into(), serde_json::json!({}));
                    }
                    let ss = root
                        .get_mut("smartscreen")
                        .and_then(|v| v.as_object_mut())
                        .expect("smartscreen object was ensured above");
                    ss.insert(
                        "pua_protection_enabled".into(),
                        serde_json::Value::Bool(want_pua),
                    );

                    let encoded = serde_json::to_vec(&doc)
                        .context("failed to serialize Edge Local State JSON")?;
                    if snap.edge_local_state.is_none() {
                        snap.edge_local_state = Some(EdgeLocalStateBackup {
                            path: ls_path.to_string_lossy().into_owned(),
                            key_existed,
                            prior_pua_enabled,
                        });
                    }
                    ops.write_file(&ls_path, &encoded)?;
                    changes.push(format!(
                        "set Edge Local State smartscreen.pua_protection_enabled = {want_pua}"
                    ));
                }
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
    fn registry_policies_and_home_fallback_apply_and_rollback() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();

        let ls_path = edge_local_state_path(&ops.local_appdata_dir().unwrap());
        ops.seed_file(
            &ls_path,
            br#"{"profile":{"name":"Default"},"smartscreen":{"other":42}}"#,
        );

        let rule = EdgeRule;
        let c1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(c1.status, CheckStatus::Drifted);
        assert_eq!(c1.diffs.len(), 8);

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(changes.len(), 8);

        assert_eq!(
            ops.reg_read(
                RegHive::Hklm,
                EDGE_POLICY_PATH,
                "NewTabPagePrerenderEnabled"
            )
            .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hklm, EDGE_POLICY_PATH, "StartupBoostEnabled")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hklm, EDGE_POLICY_PATH, "BackgroundModeEnabled")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hklm, EDGE_POLICY_PATH, "SmartScreenPuaEnabled")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hklm, LEGACY_EDGE_MAIN_PATH, "AllowPrelaunch")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hklm, LEGACY_EDGE_MAIN_PATH, "AllowTabPreloading")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, HKCU_EDGE_PUA_PATH, "").unwrap(),
            Some(RegValue::Dword(1))
        );

        let updated_doc: serde_json::Value =
            serde_json::from_slice(&ops.read_file_opt(&ls_path).unwrap().unwrap()).unwrap();
        assert_eq!(updated_doc["smartscreen"]["pua_protection_enabled"], true);
        assert_eq!(updated_doc["smartscreen"]["other"], 42);
        assert_eq!(updated_doc["profile"]["name"], "Default");

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
            ops.reg_read(RegHive::Hkcu, HKCU_EDGE_PUA_PATH, "")
                .unwrap()
                .is_none()
        );
        let rolled_doc: serde_json::Value =
            serde_json::from_slice(&ops.read_file_opt(&ls_path).unwrap().unwrap()).unwrap();
        assert!(
            rolled_doc["smartscreen"]
                .get("pua_protection_enabled")
                .is_none()
        );
        assert_eq!(rolled_doc["smartscreen"]["other"], 42);
    }

    #[test]
    fn warns_when_msedge_running_and_preserves_local_state() {
        let ops = FakeSystemOps::default();
        ops.state
            .borrow_mut()
            .running_processes
            .insert("msedge.exe".into());

        let ls_path = edge_local_state_path(&ops.local_appdata_dir().unwrap());
        let initial_json = br#"{"smartscreen":{"pua_protection_enabled":false}}"#;
        ops.seed_file(&ls_path, initial_json);

        let cfg = ProfileConfig::embedded_default();
        let rule = EdgeRule;
        let c1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(c1.status, CheckStatus::Drifted);
        assert!(c1.note.is_some());

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert!(matches!(outcome, RuleOutcome::WarnEdgeRunning { .. }));
        assert_eq!(changes.len(), 7);
        assert!(snap.edge_local_state.is_none());

        assert_eq!(
            ops.reg_read(RegHive::Hklm, EDGE_POLICY_PATH, "SmartScreenPuaEnabled")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, HKCU_EDGE_PUA_PATH, "").unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.read_file_opt(&ls_path).unwrap().as_deref(),
            Some(&initial_json[..])
        );
    }

    #[test]
    fn rollback_restores_existing_local_state_boolean() {
        let ops = FakeSystemOps::default();
        let ls_path = edge_local_state_path(&ops.local_appdata_dir().unwrap());
        ops.seed_file(
            &ls_path,
            br#"{"smartscreen":{"pua_protection_enabled":false}}"#,
        );

        let cfg = ProfileConfig::embedded_default();
        let rule = EdgeRule;
        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, _) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);

        rollback_snapshot(&ops, &snap).unwrap();
        let doc: serde_json::Value =
            serde_json::from_slice(&ops.read_file_opt(&ls_path).unwrap().unwrap()).unwrap();
        assert_eq!(doc["smartscreen"]["pua_protection_enabled"], false);
    }
}
