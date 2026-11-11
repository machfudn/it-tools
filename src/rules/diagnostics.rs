use anyhow::Result;

use crate::backup::BackupSnapshot;
use crate::config::{FeedbackFrequency, ProfileConfig};
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, RegValue, SystemOps};

pub struct DiagnosticsRule;

const POLICY_DC_1: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection";
const POLICY_DC_2: &str = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection";
const PRIVACY_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Privacy";
const SIUF_PATH: &str = r"Software\Microsoft\Siuf\Rules";

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

fn build_specs(cfg: &ProfileConfig) -> Vec<RegSpec> {
    let d = &cfg.rules.diagnostics;
    let telemetry = if d.optional_data { 3 } else { 0 };
    let tailored = if d.optional_data { 1 } else { 0 };

    let mut specs = vec![
        RegSpec {
            hive: RegHive::Hklm,
            path: POLICY_DC_1,
            name: "AllowTelemetry",
            target: RegTarget::Set(RegValue::Dword(telemetry)),
        },
        RegSpec {
            hive: RegHive::Hklm,
            path: POLICY_DC_2,
            name: "AllowTelemetry",
            target: RegTarget::Set(RegValue::Dword(telemetry)),
        },
        RegSpec {
            hive: RegHive::Hkcu,
            path: PRIVACY_PATH,
            name: "TailoredExperiencesWithDiagnosticDataEnabled",
            target: RegTarget::Set(RegValue::Dword(tailored)),
        },
    ];

    match d.feedback_frequency {
        FeedbackFrequency::Never => {
            specs.push(RegSpec {
                hive: RegHive::Hkcu,
                path: SIUF_PATH,
                name: "NumberOfSIUFInPeriod",
                target: RegTarget::Set(RegValue::Dword(0)),
            });
            specs.push(RegSpec {
                hive: RegHive::Hkcu,
                path: SIUF_PATH,
                name: "PeriodInNanoSeconds",
                target: RegTarget::Delete,
            });
        }
        FeedbackFrequency::Always => {
            specs.push(RegSpec {
                hive: RegHive::Hkcu,
                path: SIUF_PATH,
                name: "NumberOfSIUFInPeriod",
                target: RegTarget::Set(RegValue::Dword(1)),
            });
            specs.push(RegSpec {
                hive: RegHive::Hkcu,
                path: SIUF_PATH,
                name: "PeriodInNanoSeconds",
                target: RegTarget::Set(RegValue::Dword(0)),
            });
        }
        FeedbackFrequency::OnceADay | FeedbackFrequency::OnceAWeek => {
            specs.push(RegSpec {
                hive: RegHive::Hkcu,
                path: SIUF_PATH,
                name: "NumberOfSIUFInPeriod",
                target: RegTarget::Set(RegValue::Dword(1)),
            });
            specs.push(RegSpec {
                hive: RegHive::Hkcu,
                path: SIUF_PATH,
                name: "PeriodInNanoSeconds",
                target: RegTarget::Delete,
            });
        }
        FeedbackFrequency::Auto => {
            specs.push(RegSpec {
                hive: RegHive::Hkcu,
                path: SIUF_PATH,
                name: "NumberOfSIUFInPeriod",
                target: RegTarget::Delete,
            });
            specs.push(RegSpec {
                hive: RegHive::Hkcu,
                path: SIUF_PATH,
                name: "PeriodInNanoSeconds",
                target: RegTarget::Delete,
            });
        }
    }

    specs
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

impl Rule for DiagnosticsRule {
    fn id(&self) -> &'static str {
        "diagnostics"
    }

    fn title(&self) -> &'static str {
        "Diagnostic & Feedback"
    }

    fn requires_admin(&self) -> bool {
        true
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.diagnostics.enabled
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
            RegHive::Hklm,
            POLICY_DC_1,
            "AllowTelemetry",
            RegValue::Dword(3),
        );
        ops.seed_reg(
            RegHive::Hkcu,
            SIUF_PATH,
            "PeriodInNanoSeconds",
            RegValue::Dword(12345),
        );

        let rule = DiagnosticsRule;
        let check1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(check1.status, CheckStatus::Drifted);
        assert_eq!(check1.diffs.len(), 5);

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(changes.len(), 5);

        assert_eq!(
            ops.reg_read(RegHive::Hklm, POLICY_DC_1, "AllowTelemetry")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hklm, POLICY_DC_2, "AllowTelemetry")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(
                RegHive::Hkcu,
                PRIVACY_PATH,
                "TailoredExperiencesWithDiagnosticDataEnabled",
            )
            .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, SIUF_PATH, "NumberOfSIUFInPeriod")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        assert!(
            ops.reg_read(RegHive::Hkcu, SIUF_PATH, "PeriodInNanoSeconds")
                .unwrap()
                .is_none()
        );

        let check2 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(check2.status, CheckStatus::Compliant);
        assert!(check2.diffs.is_empty());

        let (outcome2, changes2) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome2, RuleOutcome::AlreadyCompliant);
        assert!(changes2.is_empty());

        rollback_snapshot(&ops, &snap).unwrap();
        assert_eq!(
            ops.reg_read(RegHive::Hklm, POLICY_DC_1, "AllowTelemetry")
                .unwrap(),
            Some(RegValue::Dword(3))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, SIUF_PATH, "PeriodInNanoSeconds")
                .unwrap(),
            Some(RegValue::Dword(12345))
        );
        assert!(
            ops.reg_read(RegHive::Hklm, POLICY_DC_2, "AllowTelemetry")
                .unwrap()
                .is_none()
        );
        assert!(
            ops.reg_read(RegHive::Hkcu, SIUF_PATH, "NumberOfSIUFInPeriod")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn feedback_frequencies_always_daily_and_auto() {
        let ops = FakeSystemOps::default();
        let mut cfg = ProfileConfig::embedded_default();
        cfg.rules.diagnostics.optional_data = true;
        cfg.rules.diagnostics.feedback_frequency = FeedbackFrequency::Always;

        let rule = DiagnosticsRule;
        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, _) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap)
            .unwrap();
        assert_eq!(outcome, RuleOutcome::Applied);
        assert_eq!(
            ops.reg_read(RegHive::Hklm, POLICY_DC_1, "AllowTelemetry")
                .unwrap(),
            Some(RegValue::Dword(3))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, SIUF_PATH, "NumberOfSIUFInPeriod")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, SIUF_PATH, "PeriodInNanoSeconds")
                .unwrap(),
            Some(RegValue::Dword(0))
        );

        cfg.rules.diagnostics.feedback_frequency = FeedbackFrequency::OnceADay;
        let mut snap_daily = BackupSnapshot::new(&ops);
        let (outcome_daily, _) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap_daily)
            .unwrap();
        assert_eq!(outcome_daily, RuleOutcome::Applied);
        assert!(
            ops.reg_read(RegHive::Hkcu, SIUF_PATH, "PeriodInNanoSeconds")
                .unwrap()
                .is_none()
        );

        cfg.rules.diagnostics.feedback_frequency = FeedbackFrequency::Auto;
        let mut snap_auto = BackupSnapshot::new(&ops);
        let (outcome_auto, _) = rule
            .apply(&ops, &cfg, &ApplyOptions::default(), &mut snap_auto)
            .unwrap();
        assert_eq!(outcome_auto, RuleOutcome::Applied);
        assert!(
            ops.reg_read(RegHive::Hkcu, SIUF_PATH, "NumberOfSIUFInPeriod")
                .unwrap()
                .is_none()
        );

        rollback_snapshot(&ops, &snap_auto).unwrap();
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, SIUF_PATH, "NumberOfSIUFInPeriod")
                .unwrap(),
            Some(RegValue::Dword(1))
        );
    }
}
