use std::ffi::OsString;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};

use crate::{APP_BANNER, APP_BANNER_WIDTH};

use crate::backup::{BackupSnapshot, rollback_snapshot};
use crate::config::{ProfileConfig, write_default_template};
use crate::engine::report::{CheckReport, CheckStatus, RuleOutcome, RunReport};
use crate::engine::{ApplyOptions, EngineError, Rule, UserTargetOptions, apply_rules, check_rules};
use crate::platform::{LocalUserInfo, RegHive, SystemOps};
use crate::update::{
    UpdateChannel, check_for_update, current_channel, current_display_version, default_github_repo,
    perform_update,
};
pub const EXIT_OK: i32 = 0;
pub const EXIT_ERR: i32 = 1;
pub const EXIT_ELEVATION_REQUIRED: i32 = 2;
pub const EXIT_NO_CONSOLE: i32 = 3;

#[derive(Debug, Parser)]
#[command(
    name = "it-tools",
    version = current_display_version(),
    about = "Portable Windows 10/11 hardening & provisioning CLI/TUI"
)]
pub struct Cli {
    /// Optional path to portable TOML configuration file
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Inspect current OS compliance against configured profile (read-only)
    Check(CheckArgs),
    /// Apply selected hardening rules (creates automatic JSON backup first)
    Apply(ApplyArgs),
    /// Restore OS state from a previously saved backup JSON snapshot
    Rollback(RollbackArgs),
    /// Manage portable it-tools.toml configuration files
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Inspect local Windows user accounts
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Check GitHub Releases for updates or self-update this portable binary
    Update(UpdateArgs),
}
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Comma-separated or repeated rule IDs to include
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    /// Comma-separated or repeated rule IDs to skip
    #[arg(long, value_delimiter = ',')]
    pub skip: Vec<String>,
    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ApplyArgs {
    /// Comma-separated or repeated rule IDs to include
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    /// Comma-separated or repeated rule IDs to skip
    #[arg(long, value_delimiter = ',')]
    pub skip: Vec<String>,
    /// Preview planned changes without mutating OS state or creating backups
    #[arg(long)]
    pub dry_run: bool,
    /// Skip interactive confirmation prompt on live apply
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Abort immediately if any rule returns an error
    #[arg(long)]
    pub strict: bool,
    /// Do not save pre-apply backup snapshot
    #[arg(long)]
    pub no_backup: bool,
    /// Restart explorer.exe automatically when taskbar settings change
    #[arg(long)]
    pub restart_explorer: bool,
    /// Existing local user account to configure (opt-in)
    #[arg(long, conflicts_with = "create_user")]
    pub target_user: Option<String>,
    /// New local user account to create if absent (opt-in)
    #[arg(long, conflicts_with = "target_user")]
    pub create_user: Option<String>,
    /// Temporary password for selected/created user (never written to disk/logs)
    #[arg(long, conflicts_with = "prompt_password")]
    pub temp_password: Option<String>,
    /// Prompt securely with masked input for the user's temporary password
    #[arg(long, conflicts_with = "temp_password")]
    pub prompt_password: bool,
    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    /// Path to backup JSON file (it-tools.backup.<timestamp>.json)
    pub backup_file: PathBuf,
    /// Skip interactive confirmation prompt
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Write editable baseline it-tools.toml beside executable (or --out)
    Init {
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Show active merged configuration (embedded defaults + overrides)
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Validate configuration file syntax and value ranges
    Validate,
}

#[derive(Debug, Subcommand)]
pub enum UserAction {
    /// List local Windows user accounts
    List {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Check only; do not download or replace executable
    #[arg(long)]
    pub check: bool,
    /// Include Beta / pre-release builds when checking for updates
    #[arg(long, conflicts_with = "stable")]
    pub beta: bool,
    /// Force Stable release channel only
    #[arg(long, conflicts_with = "beta")]
    pub stable: bool,
    /// GitHub repository in owner/repo format (overrides config and build default)
    #[arg(long, value_name = "OWNER/REPO")]
    pub repo: Option<String>,
    /// Skip confirmation prompt before replacing executable
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}
fn attach_banner_recursive(cmd: clap::Command) -> clap::Command {
    let mut cmd = cmd.before_help(APP_BANNER);
    for sub in cmd.get_subcommands_mut() {
        let taken = std::mem::take(sub);
        *sub = attach_banner_recursive(taken);
    }
    cmd
}

pub fn parse_args<I, T>(args: I) -> std::result::Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut matches = attach_banner_recursive(Cli::command()).try_get_matches_from(args)?;
    Cli::from_arg_matches_mut(&mut matches)
}

pub fn write_cli_banner(out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{APP_BANNER}")?;
    writeln!(
        out,
        "  Windows 10/11 Hardening & Provisioning | v{}",
        current_display_version()
    )?;
    writeln!(out, "{}", "-".repeat(APP_BANNER_WIDTH))
}

fn write_cli_toml_banner(out: &mut dyn Write) -> io::Result<()> {
    for line in APP_BANNER.lines() {
        writeln!(out, "# {line}")?;
    }
    writeln!(
        out,
        "# Windows 10/11 Hardening & Provisioning | v{}",
        current_display_version()
    )
}

pub fn run_subcommand(
    cmd: Commands,
    config_override: Option<&Path>,
    ops: &dyn SystemOps,
    rules: &[Box<dyn Rule>],
    exe_dir: &Path,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32> {
    match cmd {
        Commands::Check(args) => {
            let (cfg, _) = ProfileConfig::resolve_from_disk(config_override, exe_dir)?;
            let report = check_rules(ops, &cfg, rules, &args.only, &args.skip)?;
            if args.json {
                writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
            } else {
                write_cli_banner(out)?;
                write!(out, "{}", format_check_table(&report))?;
            }
            Ok(EXIT_OK)
        }
        Commands::Apply(args) => {
            let (cfg, _) = ProfileConfig::resolve_from_disk(config_override, exe_dir)?;
            if args.create_user.is_some() && args.temp_password.is_none() && !args.prompt_password {
                bail!("--create-user requires --temp-password or --prompt-password");
            }
            if (args.temp_password.is_some() || args.prompt_password)
                && args.target_user.is_none()
                && args.create_user.is_none()
            {
                bail!("--temp-password/--prompt-password requires --target-user or --create-user");
            }

            let temp_pw = if args.prompt_password && !args.dry_run {
                Some(prompt_password_masked(err)?)
            } else {
                args.temp_password.clone()
            };

            let user_target = if let Some(u) = args.create_user.as_ref() {
                Some(UserTargetOptions {
                    username: u.clone(),
                    create_if_missing: true,
                    clear_dont_expire: true,
                    temp_password: temp_pw,
                })
            } else {
                args.target_user.as_ref().map(|u| UserTargetOptions {
                    username: u.clone(),
                    create_if_missing: false,
                    clear_dont_expire: true,
                    temp_password: temp_pw,
                })
            };
            if !args.json {
                write_cli_banner(out)?;
                out.flush()?;
            }

            if !args.dry_run && !args.yes {
                if !ops.is_console_tty() {
                    writeln!(
                        err,
                        "Non-interactive apply requires --yes (or pass --dry-run to preview)."
                    )?;
                    return Ok(EXIT_ERR);
                }
                if !confirm_prompt("Apply selected Windows rules now? [y/N]: ", err)? {
                    writeln!(err, "Aborted by user.")?;
                    return Ok(EXIT_ERR);
                }
            }

            let opts = ApplyOptions {
                dry_run: args.dry_run,
                strict: args.strict,
                no_backup: args.no_backup,
                restart_explorer: args.restart_explorer,
                only: args.only,
                skip: args.skip,
                user_target,
            };

            match apply_rules(ops, &cfg, rules, &opts, exe_dir) {
                Ok(report) => {
                    if args.json {
                        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
                    } else {
                        write!(out, "{}", format_run_table(&report))?;
                    }
                    Ok(report.exit_code())
                }
                Err(e) if e.downcast_ref::<EngineError>().is_some() => {
                    writeln!(err, "Error: {e}")?;
                    Ok(EXIT_ELEVATION_REQUIRED)
                }
                Err(e) => Err(e),
            }
        }
        Commands::Rollback(args) => {
            let snap = BackupSnapshot::load_from_file(&args.backup_file)?;
            let needs_admin = snapshot_requires_admin(&snap);
            if needs_admin && !ops.is_admin() {
                writeln!(
                    err,
                    "Error: Administrator privileges required to roll back elevated settings."
                )?;
                return Ok(EXIT_ELEVATION_REQUIRED);
            }
            if !args.json {
                write_cli_banner(out)?;
                out.flush()?;
            }
            if !args.yes {
                if !ops.is_console_tty() {
                    writeln!(err, "Non-interactive rollback requires --yes.")?;
                    return Ok(EXIT_ERR);
                }
                if !confirm_prompt("Restore snapshot backup to OS now? [y/N]: ", err)? {
                    writeln!(err, "Aborted by user.")?;
                    return Ok(EXIT_ERR);
                }
            }
            let actions = rollback_snapshot(ops, &snap)?;
            if args.json {
                writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "restored_from": args.backup_file,
                        "actions": actions,
                    }))?
                )?;
            } else {
                writeln!(
                    out,
                    "Rollback completed from {}:",
                    args.backup_file.display()
                )?;
                for a in actions {
                    writeln!(out, "  - {a}")?;
                }
            }
            Ok(EXIT_OK)
        }
        Commands::Config { action } => match action {
            ConfigAction::Init {
                out: out_path,
                force,
            } => {
                let target = out_path.unwrap_or_else(|| exe_dir.join("it-tools.toml"));
                write_default_template(&target, force)?;
                write_cli_banner(out)?;
                writeln!(out, "Wrote config template: {}", target.display())?;
                Ok(EXIT_OK)
            }
            ConfigAction::Show { json } => {
                let (cfg, src) = ProfileConfig::resolve_from_disk(config_override, exe_dir)?;
                if json {
                    writeln!(out, "{}", serde_json::to_string_pretty(&cfg)?)?;
                } else {
                    write_cli_toml_banner(out)?;
                    writeln!(
                        out,
                        "# Active config source: {}",
                        src.as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "embedded defaults".into())
                    )?;
                    write!(out, "{}", toml::to_string_pretty(&cfg)?)?;
                }
                Ok(EXIT_OK)
            }
            ConfigAction::Validate => {
                let (_, src) = ProfileConfig::resolve_from_disk(config_override, exe_dir)?;
                write_cli_banner(out)?;
                writeln!(
                    out,
                    "Configuration valid (source: {}).",
                    src.as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "embedded defaults".into())
                )?;
                Ok(EXIT_OK)
            }
        },
        Commands::User { action } => match action {
            UserAction::List { json } => {
                let users = ops.list_local_users()?;
                if json {
                    writeln!(out, "{}", serde_json::to_string_pretty(&users)?)?;
                } else {
                    write_cli_banner(out)?;
                    write!(out, "{}", format_users_table(&users))?;
                }
                Ok(EXIT_OK)
            }
        },
        Commands::Update(args) => run_update_cmd(args, config_override, ops, exe_dir, out, err),
    }
}

fn run_update_cmd(
    args: UpdateArgs,
    config_override: Option<&Path>,
    ops: &dyn SystemOps,
    exe_dir: &Path,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32> {
    let (cfg, _) = ProfileConfig::resolve_from_disk(config_override, exe_dir)?;
    let repo = args
        .repo
        .as_deref()
        .or(cfg.update.repo.as_deref())
        .or(default_github_repo())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no GitHub repository configured for updates; pass `--repo owner/repo` or set `[update] repo = \"owner/repo\"` in it-tools.toml"
            )
        })?;

    let channel = if args.beta {
        UpdateChannel::Beta
    } else if args.stable {
        UpdateChannel::Stable
    } else if cfg.update.allow_beta || current_channel() == UpdateChannel::Beta {
        UpdateChannel::Beta
    } else {
        UpdateChannel::Stable
    };

    let check = check_for_update(ops, repo, channel)?;
    if !args.json {
        write_cli_banner(out)?;
        out.flush()?;
    }
    if args.check || !check.update_available {
        if args.json {
            writeln!(out, "{}", serde_json::to_string_pretty(&check)?)?;
        } else {
            writeln!(
                out,
                "Current: {} | Latest ({}): {} | Status: {}",
                check.current_version,
                check.channel,
                check.latest_version,
                if check.update_available {
                    "UPDATE AVAILABLE"
                } else {
                    "UP TO DATE"
                }
            )?;
            if !check.html_url.is_empty() {
                writeln!(out, "Release: {}", check.html_url)?;
            }
            if check.update_available && !check.release_notes.trim().is_empty() {
                writeln!(out, "\n{}", check.release_notes.trim())?;
            }
        }
        return Ok(EXIT_OK);
    }

    if !args.yes {
        if !ops.is_console_tty() {
            writeln!(
                err,
                "Non-interactive update requires --yes (or pass --check to inspect)."
            )?;
            return Ok(EXIT_ERR);
        }
        if !confirm_prompt(
            &format!(
                "Download and replace it-tools.exe {} -> {}? [y/N]: ",
                check.current_version, check.latest_version
            ),
            err,
        )? {
            writeln!(err, "Update aborted by user.")?;
            return Ok(EXIT_ERR);
        }
    }

    let applied = perform_update(ops, &check)?;
    if args.json {
        writeln!(out, "{}", serde_json::to_string_pretty(&applied)?)?;
    } else {
        writeln!(
            out,
            "Updated {} -> {} at {} (SHA-256 {}: {}). Previous binary saved as {}.",
            applied.previous_version,
            applied.new_version,
            applied.exe_path,
            if applied.sha256_verified {
                "verified"
            } else {
                "computed"
            },
            applied.sha256,
            applied.backup_path
        )?;
    }
    Ok(EXIT_OK)
}

pub fn snapshot_requires_admin(snap: &BackupSnapshot) -> bool {
    snap.registry.iter().any(|r| r.hive != RegHive::Hkcu)
        || snap
            .startup_approved
            .iter()
            .any(|r| r.hive != RegHive::Hkcu)
        || snap.power.is_some()
        || snap.secedit_inf.is_some()
        || snap.firewall.is_some()
        || snap.system_restore.is_some()
        || !snap.user_flags.is_empty()
}

pub fn format_check_table(report: &CheckReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "OS: {} | Admin: {}\n",
        report.os_caption,
        if report.is_admin { "Yes" } else { "No" }
    ));
    out.push_str(&format!(
        "{:<20} {:<13} {:<6} {}\n",
        "RULE", "STATUS", "ADMIN", "DETAILS"
    ));
    out.push_str(&"-".repeat(72));
    out.push('\n');
    for c in &report.checks {
        let status = match c.status {
            CheckStatus::Compliant => "COMPLIANT",
            CheckStatus::Drifted => "DRIFTED",
            CheckStatus::NeedsAdmin => "NEEDS_ADMIN",
            CheckStatus::Unsupported => "UNSUPPORTED",
        };
        let detail = if let Some(note) = &c.note {
            note.clone()
        } else if c.diffs.is_empty() {
            "OK".into()
        } else {
            format!("{} diffs", c.diffs.len())
        };
        out.push_str(&format!(
            "{:<20} {:<13} {:<6} {}\n",
            c.id,
            status,
            if c.requires_admin { "yes" } else { "no" },
            detail
        ));
        for d in &c.diffs {
            out.push_str(&format!(
                "    - {}: '{}' -> '{}'\n",
                d.field, d.current, d.target
            ));
        }
    }
    out
}

pub fn format_run_table(report: &RunReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Mode: {} | OS: {}\n",
        report.mode, report.os_caption
    ));
    if let Some(bk) = &report.backup_file {
        out.push_str(&format!("Backup: {}\n", bk.display()));
    }
    out.push_str(&format!("{:<20} {:<20} {}\n", "RULE", "OUTCOME", "DETAIL"));
    out.push_str(&"-".repeat(72));
    out.push('\n');
    for e in &report.entries {
        let (tag, detail) = match &e.outcome {
            RuleOutcome::Applied => ("APPLIED", format!("{} change(s)", e.changes.len())),
            RuleOutcome::AlreadyCompliant => ("COMPLIANT", "already matches target".into()),
            RuleOutcome::WarnTamperProtected { detail } => ("WARN_TAMPER", detail.clone()),
            RuleOutcome::WarnFirmwareLocked { detail } => ("WARN_FIRMWARE", detail.clone()),
            RuleOutcome::WarnEdgeRunning { detail } => ("WARN_EDGE_RUNNING", detail.clone()),
            RuleOutcome::Skipped { reason } => ("SKIPPED", reason.clone()),
            RuleOutcome::Failed { error } => ("FAILED", error.clone()),
        };
        out.push_str(&format!("{:<20} {:<20} {}\n", e.id, tag, detail));
        for ch in &e.changes {
            out.push_str(&format!("    * {ch}\n"));
        }
    }
    out
}

pub fn format_users_table(users: &[LocalUserInfo]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<24} {:<10} {}\n",
        "USERNAME", "ENABLED", "PASSWORD_NEVER_EXPIRES"
    ));
    out.push_str(&"-".repeat(60));
    out.push('\n');
    for u in users {
        out.push_str(&format!(
            "{:<24} {:<10} {}\n",
            u.name,
            if u.disabled { "No" } else { "Yes" },
            if u.dont_expire_password { "Yes" } else { "No" }
        ));
    }
    out
}

fn confirm_prompt(msg: &str, err: &mut dyn Write) -> Result<bool> {
    write!(err, "{msg}")?;
    err.flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let ans = line.trim().to_ascii_lowercase();
    Ok(ans == "y" || ans == "yes")
}

fn prompt_password_masked(err: &mut dyn Write) -> Result<String> {
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    };

    write!(err, "Temporary password for local account: ")?;
    err.flush()?;

    let hin = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut orig_mode: u32 = 0;
    let is_con = unsafe { GetConsoleMode(hin, &mut orig_mode) } != 0;

    struct ModeRestore(windows_sys::Win32::Foundation::HANDLE, u32, bool);
    impl Drop for ModeRestore {
        fn drop(&mut self) {
            if self.2 {
                unsafe { SetConsoleMode(self.0, self.1) };
            }
        }
    }

    if is_con {
        unsafe { SetConsoleMode(hin, orig_mode & !ENABLE_ECHO_INPUT) };
    }
    let _guard = ModeRestore(hin, orig_mode, is_con);

    let mut pw = String::new();
    io::stdin()
        .lock()
        .read_line(&mut pw)
        .context("failed to read password")?;
    writeln!(err)?;
    let trimmed = pw.trim_end_matches(&['\r', '\n'][..]).to_string();
    if trimmed.is_empty() {
        bail!("temporary password cannot be empty");
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::fake::FakeSystemOps;
    use crate::platform::{RegHive, RegValue};

    #[test]
    fn non_elevated_apply_returns_exit_code_2_for_admin_rule() {
        let ops = FakeSystemOps::default();
        ops.state.borrow_mut().admin = false;
        let rules = fake_rules();
        let dir = std::env::temp_dir().join(format!("it-tools-cli-uac-{}", std::process::id()));
        let cli = parse_args(["it-tools", "apply", "--yes"]).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_subcommand(
            cli.command.unwrap(),
            None,
            &ops,
            &rules,
            &dir,
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(code, EXIT_ELEVATION_REQUIRED);
    }

    #[test]
    fn temp_password_never_appears_in_json_or_table_output() {
        let ops = FakeSystemOps::default();
        let rules = fake_rules();
        let dir = std::env::temp_dir().join(format!("it-tools-cli-pw-{}", std::process::id()));
        let cli = parse_args([
            "it-tools",
            "apply",
            "--yes",
            "--create-user",
            "NewStaff",
            "--temp-password",
            "SuperSecret99!",
            "--json",
        ])
        .unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_subcommand(
            cli.command.unwrap(),
            None,
            &ops,
            &rules,
            &dir,
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(code, EXIT_OK);
        let stdout_s = String::from_utf8(out).unwrap();
        assert!(!stdout_s.contains("SuperSecret99!"));
    }

    #[test]
    fn config_init_and_validate_work_without_admin() {
        let ops = FakeSystemOps::default();
        ops.state.borrow_mut().admin = false;
        let rules = fake_rules();
        let dir = std::env::temp_dir().join(format!("it-tools-cli-cfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg_path = dir.join("custom.toml");

        let cli = parse_args([
            "it-tools",
            "config",
            "init",
            "--out",
            cfg_path.to_str().unwrap(),
            "--force",
        ])
        .unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_subcommand(
            cli.command.unwrap(),
            None,
            &ops,
            &rules,
            &dir,
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(code, EXIT_OK);
        assert!(cfg_path.is_file());

        let cli2 = parse_args([
            "it-tools",
            "--config",
            cfg_path.to_str().unwrap(),
            "config",
            "validate",
        ])
        .unwrap();
        let mut out2 = Vec::new();
        let code2 = run_subcommand(
            cli2.command.unwrap(),
            cli2.config.as_deref(),
            &ops,
            &rules,
            &dir,
            &mut out2,
            &mut err,
        )
        .unwrap();
        assert_eq!(code2, EXIT_OK);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_update_check_and_apply_via_fake_http() {
        let ops = FakeSystemOps::default();
        let exe_path = ops.current_exe_path().unwrap();
        ops.write_file(&exe_path, b"MZ_OLD_CLI_BIN_PADDING_PADDING_PADDING")
            .unwrap();

        let mut new_bin = b"MZ_NEW_CLI_BIN_V99".to_vec();
        new_bin.resize(128, 0xCC);
        let sum = crate::update::sha256_hex(&new_bin);
        let release_json = r#"{
            "tag_name": "v99.0.0",
            "prerelease": false,
            "published_at": "2026-11-11T00:00:00Z",
            "html_url": "https://github.com/acme/it-tools/releases/tag/v99.0.0",
            "body": "UAT tested release",
            "assets": [
                {"name": "it-tools.exe", "browser_download_url": "https://dl.example/it-tools.exe"},
                {"name": "SHA256SUMS.txt", "browser_download_url": "https://dl.example/SHA256SUMS.txt"}
            ]
        }"#;
        {
            let mut st = ops.state.borrow_mut();
            st.http_responses.insert(
                "https://api.github.com/repos/acme/it-tools/releases/latest".into(),
                (200, release_json.as_bytes().to_vec()),
            );
            st.http_responses.insert(
                "https://api.github.com/repos/acme/it-tools/releases?per_page=20".into(),
                (200, format!("[{release_json}]").into_bytes()),
            );
            st.http_responses.insert(
                "https://dl.example/it-tools.exe".into(),
                (200, new_bin.clone()),
            );
            st.http_responses.insert(
                "https://dl.example/SHA256SUMS.txt".into(),
                (200, format!("{sum}  it-tools.exe\n").into_bytes()),
            );
        }

        let dir = std::env::temp_dir().join(format!("it-tools-cli-upd-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let rules = fake_rules();

        let check_cli = parse_args([
            "it-tools",
            "update",
            "--check",
            "--repo",
            "acme/it-tools",
            "--json",
        ])
        .unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_subcommand(
            check_cli.command.unwrap(),
            None,
            &ops,
            &rules,
            &dir,
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(code, EXIT_OK);
        let check_json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(check_json["update_available"], true);
        assert_eq!(check_json["latest_version"], "99.0.0");

        let apply_cli = parse_args([
            "it-tools",
            "update",
            "--yes",
            "--repo",
            "acme/it-tools",
            "--json",
        ])
        .unwrap();
        let mut out2 = Vec::new();
        let code2 = run_subcommand(
            apply_cli.command.unwrap(),
            None,
            &ops,
            &rules,
            &dir,
            &mut out2,
            &mut err,
        )
        .unwrap();
        assert_eq!(code2, EXIT_OK);
        assert_eq!(ops.read_file_opt(&exe_path).unwrap().unwrap(), new_bin);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn fake_rules() -> Vec<Box<dyn Rule>> {
        vec![Box::new(FakeAdminDummy)]
    }

    struct FakeAdminDummy;
    impl Rule for FakeAdminDummy {
        fn id(&self) -> &'static str {
            "dummy_admin"
        }
        fn title(&self) -> &'static str {
            "Dummy Admin"
        }
        fn requires_admin(&self) -> bool {
            true
        }
        fn is_enabled(&self, _cfg: &ProfileConfig) -> bool {
            true
        }
        fn check(
            &self,
            _ops: &dyn SystemOps,
            _cfg: &ProfileConfig,
        ) -> Result<crate::engine::report::RuleCheck> {
            Ok(crate::engine::report::RuleCheck {
                id: self.id().into(),
                title: self.title().into(),
                requires_admin: true,
                enabled_in_config: true,
                status: CheckStatus::Drifted,
                diffs: vec![],
                note: None,
            })
        }
        fn apply(
            &self,
            ops: &dyn SystemOps,
            _cfg: &ProfileConfig,
            opts: &ApplyOptions,
            snap: &mut BackupSnapshot,
        ) -> Result<(RuleOutcome, Vec<String>)> {
            let mut changes = vec![];
            if let Some(u) = &opts.user_target
                && u.create_if_missing
            {
                let pw = u.temp_password.as_deref().unwrap();
                ops.create_local_user(&u.username, pw)?;
                changes.push(format!("created user '{}'", u.username));
            }
            snap.write_reg_with_backup(
                ops,
                RegHive::Hklm,
                "SOFTWARE\\Dummy",
                "Ok",
                RegValue::Dword(1),
            )?;
            Ok((RuleOutcome::Applied, changes))
        }
    }

    #[test]
    fn cli_help_and_human_outputs_include_banner_while_json_and_version_stay_clean() {
        let err = parse_args(["it-tools", "--help"]).unwrap_err();
        assert!(err.to_string().contains("$$$$$$/ $$$$$$$$/"));

        let sub_err = parse_args(["it-tools", "check", "--help"]).unwrap_err();
        assert!(sub_err.to_string().contains("$$$$$$/ $$$$$$$$/"));

        let ver_err = parse_args(["it-tools", "--version"]).unwrap_err();
        assert!(!ver_err.to_string().contains("$$$$$$/"));

        let ops = FakeSystemOps::default();
        let rules = fake_rules();
        let dir = std::env::temp_dir().join(format!("it-tools-cli-bnr-{}", std::process::id()));

        let cli_human = parse_args(["it-tools", "check"]).unwrap();
        let mut out_human = Vec::new();
        let mut err_buf = Vec::new();
        let code = run_subcommand(
            cli_human.command.unwrap(),
            None,
            &ops,
            &rules,
            &dir,
            &mut out_human,
            &mut err_buf,
        )
        .unwrap();
        assert_eq!(code, EXIT_OK);
        let human_s = String::from_utf8(out_human).unwrap();
        assert!(human_s.starts_with(" ______  ________"));
        assert!(human_s.contains("dummy_admin"));

        let cli_json = parse_args(["it-tools", "check", "--json"]).unwrap();
        let mut out_json = Vec::new();
        let code_j = run_subcommand(
            cli_json.command.unwrap(),
            None,
            &ops,
            &rules,
            &dir,
            &mut out_json,
            &mut err_buf,
        )
        .unwrap();
        assert_eq!(code_j, EXIT_OK);
        let parsed: serde_json::Value = serde_json::from_slice(&out_json).unwrap();
        assert!(parsed.get("checks").is_some());

        let cli_cfg = parse_args(["it-tools", "config", "show"]).unwrap();
        let mut out_cfg = Vec::new();
        run_subcommand(
            cli_cfg.command.unwrap(),
            None,
            &ops,
            &rules,
            &dir,
            &mut out_cfg,
            &mut err_buf,
        )
        .unwrap();
        let cfg_s = String::from_utf8(out_cfg).unwrap();
        assert!(cfg_s.contains("$$$$$$/ $$$$$$$$/"));
        let _: toml::Value = toml::from_str(&cfg_s).unwrap();
    }
}
