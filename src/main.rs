use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::error::ErrorKind;

use it_tools::cli::{EXIT_ERR, parse_args, run_subcommand};
use it_tools::config::ProfileConfig;
use it_tools::platform::win32::Win32SystemOps;
use it_tools::rules::all_rules;
use it_tools::tui::run_tui;

fn main() -> ExitCode {
    let code = match run() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e:#}");
            EXIT_ERR
        }
    };
    ExitCode::from(code as u8)
}

fn run() -> anyhow::Result<i32> {
    let raw_args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let cli = match parse_args(&raw_args) {
        Ok(c) => c,
        Err(e) => {
            let is_help_or_ver =
                matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion);
            let _ = e.print();
            return Ok(if is_help_or_ver { 0 } else { EXIT_ERR });
        }
    };

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let ops = Win32SystemOps;
    it_tools::update::cleanup_old_exe_backup(&ops);
    let rules = all_rules();

    match cli.command {
        Some(cmd) => {
            let mut out = io::stdout().lock();
            let mut err = io::stderr().lock();
            run_subcommand(
                cmd,
                cli.config.as_deref(),
                &ops,
                &rules,
                &exe_dir,
                &mut out,
                &mut err,
            )
        }
        None => {
            let (cfg, src) = ProfileConfig::resolve_from_disk(cli.config.as_deref(), &exe_dir)?;
            let config_path = cli
                .config
                .clone()
                .or(src)
                .unwrap_or_else(|| exe_dir.join("it-tools.toml"));
            let mut relaunch_args = Vec::new();
            if let Some(cfg_p) = &cli.config {
                relaunch_args.push("--config".into());
                relaunch_args.push(cfg_p.to_string_lossy().into_owned());
            }
            run_tui(&ops, &rules, cfg, config_path, exe_dir, relaunch_args)
        }
    }
}
