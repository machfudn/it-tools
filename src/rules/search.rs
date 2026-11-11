use anyhow::Result;

use crate::backup::BackupSnapshot;
use crate::config::ProfileConfig;
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, RegValue, SystemOps};

pub struct SearchRule;

const SEARCH_SETTINGS_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\SearchSettings";
const WINDOWS_SEARCH_POLICY_PATH: &str = r"SOFTWARE\Policies\Microsoft\Windows\Windows Search";

enum RegTarget {
    Set(RegValue),
    Delete,
}

struct RegSpec {
    hive: RegHive,
    path: &'static str,
    name: &'static str,
    target: RegTarget,
}

fn bool_dword(v: bool) -> RegValue {
    RegValue::Dword(u32::from(v))
}

fn build_specs(cfg: &ProfileConfig) -> Vec<RegSpec> {
    let s = &cfg.rules.search;
    let allow_cloud_target = if !s.msa_cloud_search && !s.work_school_search {
        RegTarget::Set(RegValue::Dword(0))
    } else {
        RegTarget::Delete
    };

    vec![
        RegSpec {
            hive: RegHive::Hkcu,
            path: SEARCH_SETTINGS_PATH,
            name: "IsMSACloudSearchEnabled",
            target: RegTarget::Set(bool_dword(s.msa_cloud_search)),
        },
        RegSpec {
            hive: RegHive::Hkcu,
            path: SEARCH_SETTINGS_PATH,
            name: "IsAADCloudSearchEnabled",
            target: RegTarget::Set(bool_dword(s.work_school_search)),
        },
        RegSpec {
            hive: RegHive::Hkcu,
            path: SEARCH_SETTINGS_PATH,
            name: "IsDynamicSearchBoxEnabled",
            target: RegTarget::Set(bool_dword(s.search_highlights)),
        },
        RegSpec {
            hive: RegHive::Hklm,
            path: WINDOWS_SEARCH_POLICY_PATH,
            name: "EnableDynamicContentInWSB",
            target: RegTarget::Set(bool_dword(s.search_highlights)),
        },
        RegSpec {
            hive: RegHive::Hklm,
            path: WINDOWS_SEARCH_POLICY_PATH,
            name: "AllowCloudSearch",
            target: allow_cloud_target,
        },
    ]
}

fn hive_label(hive: RegHive) -> &'static str {
    match hive {
        RegHive::Hkcu => "HKCU",
        RegHive::Hklm => "HKLM",
    }
}

fn fmt_reg_value(val: Option<&RegValue>) -> String {
    match val {
        None => "<absent>".into(),
        Some(RegValue::Dword(v)) => v.to_string(),
        Some(RegValue::Sz(s)) | Some(RegValue::ExpandSz(s)) => s.clone(),
        Some(RegValue::BinaryHex(h)) => format!("hex:{h}"),
    }
}

impl Rule for SearchRule {
    fn id(&self) -> &'static str {
        "search"
    }

    fn title(&self) -> &'static str {
        "Search Permission"
    }

    fn requires_admin(&self) -> bool {
        true
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.search.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let mut diffs = Vec::new();
        for spec in build_specs(cfg) {
            let current = ops.reg_read(spec.hive, spec.path, spec.name)?;
            match &spec.target {
                RegTarget::Set(want) => {
                    if current.as_ref() != Some(want) {
                        diffs.push(DiffItem {
                            field: format!(
                                "{}\\{}\\{}",
                                hive_label(spec.hive),
                                spec.path,
                                spec.name
                            ),
                            current: fmt_reg_value(current.as_ref()),
                            target: fmt_reg_value(Some(want)),
                        });
                    }
                }
                RegTarget::Delete => {
                    if let Some(existing) = current {
                        diffs.push(DiffItem {
                            field: format!(
                                "{}\\{}\\{}",
                                hive_label(spec.hive),
                                spec.path,
                                spec.name
                            ),
                            current: fmt_reg_value(Some(&existing)),
                            target: "<absent>".into(),
                        });
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
        for spec in build_specs(cfg) {
            match spec.target {
                RegTarget::Set(want) => {
                    let display = fmt_reg_value(Some(&want));
                    if snap.write_reg_with_backup(ops, spec.hive, spec.path, spec.name, want)? {
                        changes.push(format!(
                            "set {}\\{}\\{} = {}",
                            hive_label(spec.hive),
                            spec.path,
                            spec.name,
                            display
                        ));
                    }
                }
                RegTarget::Delete => {
                    if snap.delete_reg_with_backup(ops, spec.hive, spec.path, spec.name)? {
                        changes.push(format!(
                            "deleted {}\\{}\\{}",
                            hive_label(spec.hive),
                            spec.path,
                            spec.name
                        ));
                    }
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
    fn check_apply_idempotent_and_rollback_defaults() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();

        ops.seed_reg(
            RegHive::Hkcu,
            SEARCH_SETTINGS_PATH,
            "IsMSACloudSearchEnabled",
            RegValue::Dword(1),
        );

        let rule = SearchRule;
        let c1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(c1.status, CheckStatus::Drifted);
        assert_eq!(c1.diffs.len(), 5);

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(changes.len(), 5);

        assert_eq!(
            ops.reg_read(
                RegHive::Hkcu,
                SEARCH_SETTINGS_PATH,
                "IsMSACloudSearchEnabled"
            )
            .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(
                RegHive::Hkcu,
                SEARCH_SETTINGS_PATH,
                "IsAADCloudSearchEnabled"
            )
            .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(
                RegHive::Hkcu,
                SEARCH_SETTINGS_PATH,
                "IsDynamicSearchBoxEnabled",
            )
            .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(
                RegHive::Hklm,
                WINDOWS_SEARCH_POLICY_PATH,
                "EnableDynamicContentInWSB",
            )
            .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(
                RegHive::Hklm,
                WINDOWS_SEARCH_POLICY_PATH,
                "AllowCloudSearch"
            )
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
            ops.reg_read(
                RegHive::Hkcu,
                SEARCH_SETTINGS_PATH,
                "IsMSACloudSearchEnabled"
            )
            .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert!(
            ops.reg_read(
                RegHive::Hklm,
                WINDOWS_SEARCH_POLICY_PATH,
                "AllowCloudSearch"
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn cloud_search_enabled_deletes_allow_cloud_search_policy_with_backup() {
        let ops = FakeSystemOps::default();
        let mut cfg = ProfileConfig::embedded_default();
        cfg.rules.search.msa_cloud_search = true;
        cfg.rules.search.search_highlights = true;

        ops.seed_reg(
            RegHive::Hklm,
            WINDOWS_SEARCH_POLICY_PATH,
            "AllowCloudSearch",
            RegValue::Dword(0),
        );

        let rule = SearchRule;
        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, _) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);

        assert!(
            ops.reg_read(
                RegHive::Hklm,
                WINDOWS_SEARCH_POLICY_PATH,
                "AllowCloudSearch"
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            ops.reg_read(
                RegHive::Hkcu,
                SEARCH_SETTINGS_PATH,
                "IsDynamicSearchBoxEnabled"
            )
            .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(
                RegHive::Hklm,
                WINDOWS_SEARCH_POLICY_PATH,
                "EnableDynamicContentInWSB",
            )
            .unwrap(),
            Some(RegValue::Dword(1))
        );

        rollback_snapshot(&ops, &snap).unwrap();
        assert_eq!(
            ops.reg_read(
                RegHive::Hklm,
                WINDOWS_SEARCH_POLICY_PATH,
                "AllowCloudSearch"
            )
            .unwrap(),
            Some(RegValue::Dword(0))
        );
    }
}
