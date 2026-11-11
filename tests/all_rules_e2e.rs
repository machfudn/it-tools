use std::collections::BTreeSet;

use it_tools::backup::{BackupSnapshot, rollback_snapshot};
use it_tools::cli::{EXIT_ELEVATION_REQUIRED, EXIT_OK, parse_args, run_subcommand};
use it_tools::config::ProfileConfig;
use it_tools::engine::report::{CheckStatus, RuleOutcome};
use it_tools::engine::{ApplyOptions, apply_rules, check_rules};
use it_tools::platform::fake::FakeSystemOps;
use it_tools::platform::{RegHive, RegValue, SystemOps};
use it_tools::rules::all_rules;

#[test]
fn all_13_rules_apply_idempotency_and_full_rollback_e2e() {
    let ops = FakeSystemOps::default();
    ops.seed_reg(
        RegHive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "SomeBloat",
        RegValue::Sz(r"C:\Program Files\Bloat\bloat.exe".into()),
    );
    ops.seed_reg(
        RegHive::Hkcu,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "OpenVPN-GUI",
        RegValue::Sz(r"C:\Program Files\OpenVPN\bin\openvpn-gui.exe".into()),
    );
    let local_state = ops
        .local_appdata_dir()
        .unwrap()
        .join("Microsoft")
        .join("Edge")
        .join("User Data")
        .join("Local State");
    ops.seed_file(
        &local_state,
        br#"{"smartscreen":{"pua_protection_enabled":false}}"#,
    );

    let rules = all_rules();
    assert_eq!(rules.len(), 13);
    let unique_ids: BTreeSet<&str> = rules.iter().map(|r| r.id()).collect();
    assert_eq!(unique_ids.len(), 13);

    let cfg = ProfileConfig::embedded_default();
    let dir = std::env::temp_dir().join(format!("it-tools-e2e-all-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let initial_check = check_rules(&ops, &cfg, &rules, &[], &[]).unwrap();
    assert_eq!(initial_check.checks.len(), 13);
    assert!(
        initial_check
            .checks
            .iter()
            .all(|c| c.status == CheckStatus::Drifted)
    );

    let dry_report = apply_rules(
        &ops,
        &cfg,
        &rules,
        &ApplyOptions {
            dry_run: true,
            ..Default::default()
        },
        &dir,
    )
    .unwrap();
    assert_eq!(dry_report.entries.len(), 13);
    assert!(dry_report.backup_file.is_none());
    assert!(!dir.exists());

    let apply_report = apply_rules(&ops, &cfg, &rules, &ApplyOptions::default(), &dir).unwrap();
    assert_eq!(apply_report.exit_code(), 0);
    assert_eq!(apply_report.entries.len(), 13);
    assert!(
        apply_report
            .entries
            .iter()
            .all(|e| matches!(e.outcome, RuleOutcome::Applied))
    );
    let backup_path = apply_report.backup_file.expect("backup saved");
    assert!(backup_path.is_file());

    let post_check = check_rules(&ops, &cfg, &rules, &[], &[]).unwrap();
    assert!(
        post_check
            .checks
            .iter()
            .all(|c| c.status == CheckStatus::Compliant),
        "non-compliant after apply: {:?}",
        post_check
            .checks
            .iter()
            .filter(|c| c.status != CheckStatus::Compliant)
            .collect::<Vec<_>>()
    );

    let second_apply = apply_rules(&ops, &cfg, &rules, &ApplyOptions::default(), &dir).unwrap();
    assert!(second_apply.backup_file.is_none());
    assert!(
        second_apply
            .entries
            .iter()
            .all(|e| matches!(e.outcome, RuleOutcome::AlreadyCompliant))
    );

    let snap = BackupSnapshot::load_from_file(&backup_path).unwrap();
    let rb_actions = rollback_snapshot(&ops, &snap).unwrap();
    assert!(!rb_actions.is_empty());

    let after_rb = check_rules(&ops, &cfg, &rules, &[], &[]).unwrap();
    assert!(
        after_rb
            .checks
            .iter()
            .any(|c| c.status == CheckStatus::Drifted)
    );
    assert_eq!(
        ops.reg_read(
            RegHive::Hklm,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "SomeBloat"
        )
        .unwrap(),
        Some(RegValue::Sz(r"C:\Program Files\Bloat\bloat.exe".into()))
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn non_admin_cli_allows_pure_hkcu_rules_and_blocks_hklm_rules() {
    let ops = FakeSystemOps::default();
    ops.state.borrow_mut().admin = false;
    let rules = all_rules();
    let dir = std::env::temp_dir().join(format!("it-tools-e2e-uac-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cli_dry = parse_args(["it-tools", "apply", "--dry-run", "--json"]).unwrap();
    let mut out_dry = Vec::new();
    let mut err_dry = Vec::new();
    let code_dry = run_subcommand(
        cli_dry.command.unwrap(),
        None,
        &ops,
        &rules,
        &dir,
        &mut out_dry,
        &mut err_dry,
    )
    .unwrap();
    assert_eq!(code_dry, EXIT_OK);

    let cli_all = parse_args(["it-tools", "apply", "--yes"]).unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code_all = run_subcommand(
        cli_all.command.unwrap(),
        None,
        &ops,
        &rules,
        &dir,
        &mut out,
        &mut err,
    )
    .unwrap();
    assert_eq!(code_all, EXIT_ELEVATION_REQUIRED);

    let cli_hkcu = parse_args([
        "it-tools",
        "apply",
        "--yes",
        "--only",
        "visual_effects,typing,taskbar,screensaver,accessibility",
        "--json",
    ])
    .unwrap();
    let mut out2 = Vec::new();
    let mut err2 = Vec::new();
    let code_hkcu = run_subcommand(
        cli_hkcu.command.unwrap(),
        None,
        &ops,
        &rules,
        &dir,
        &mut out2,
        &mut err2,
    )
    .unwrap();
    assert_eq!(code_hkcu, EXIT_OK);
    let _ = std::fs::remove_dir_all(&dir);
}
