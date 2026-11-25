use std::path::Path;

use anyhow::{Result, bail};

use crate::backup::BackupSnapshot;
use crate::config::ProfileConfig;
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule, ScriptConflictPolicy};
use crate::platform::SystemOps;

pub struct ScriptsFolderRule;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptsFolderInspection {
    pub target_path: String,
    pub folder_exists: bool,
    pub occupied_by_file: bool,
    pub existing_txt_files: Vec<String>,
    pub conflicting_scripts: Vec<String>,
}

pub fn inspect_scripts_folder(
    ops: &dyn SystemOps,
    cfg: &ProfileConfig,
) -> Result<ScriptsFolderInspection> {
    let target_path = cfg.rules.scripts_folder.path.trim().to_string();
    let target = Path::new(&target_path);
    let occupied_by_file = ops.read_file_opt(target)?.is_some();
    let folder_exists = !occupied_by_file && ops.dir_exists(target)?;

    let mut existing_txt_files = if folder_exists {
        ops.list_dir_files(target)?
            .into_iter()
            .filter(|name| name.to_ascii_lowercase().ends_with(".txt"))
            .collect()
    } else {
        Vec::new()
    };
    existing_txt_files.sort_by_key(|a| a.to_ascii_lowercase());

    let mut conflicting_scripts = Vec::new();
    if folder_exists {
        for spec in &cfg.rules.scripts_folder.scripts {
            let name = spec.name.trim();
            let full = target.join(name);
            if let Some(existing_bytes) = ops.read_file_opt(&full)?
                && existing_bytes != spec.content.as_bytes()
            {
                conflicting_scripts.push(name.to_string());
            }
        }
    }

    Ok(ScriptsFolderInspection {
        target_path,
        folder_exists,
        occupied_by_file,
        existing_txt_files,
        conflicting_scripts,
    })
}

fn format_inspection_note(insp: &ScriptsFolderInspection) -> String {
    if insp.occupied_by_file {
        return format!(
            "Path {} sudah ditempati berkas reguler, bukan folder.",
            insp.target_path
        );
    }
    if !insp.folder_exists {
        return format!(
            "Folder {} belum ada dan akan dibuat saat diterapkan.",
            insp.target_path
        );
    }
    if insp.existing_txt_files.is_empty() {
        format!(
            "Folder {} sudah ada (belum ada berkas .txt di dalamnya).",
            insp.target_path
        )
    } else {
        format!(
            "Folder {} sudah ada. Berkas .txt terdeteksi: {}.",
            insp.target_path,
            insp.existing_txt_files.join(", ")
        )
    }
}

impl Rule for ScriptsFolderRule {
    fn id(&self) -> &'static str {
        "scripts_folder"
    }

    fn title(&self) -> &'static str {
        "Folder Skrip"
    }

    fn description(&self) -> &'static str {
        "Membuat & memantau folder C:\\Skrip serta memeriksa konflik berkas skrip .txt."
    }

    fn requires_admin(&self) -> bool {
        false
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.scripts_folder.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let insp = inspect_scripts_folder(ops, cfg)?;
        let note = Some(format_inspection_note(&insp));
        if insp.occupied_by_file {
            return Ok(RuleCheck {
                id: self.id().to_string(),
                title: self.title().to_string(),
                requires_admin: self.requires_admin(),
                enabled_in_config: self.is_enabled(cfg),
                status: CheckStatus::Unsupported,
                diffs: Vec::new(),
                note,
            });
        }

        let target = Path::new(&insp.target_path);
        let mut diffs = Vec::new();
        if !insp.folder_exists {
            diffs.push(DiffItem {
                field: format!("folder:{}", insp.target_path),
                current: "(belum ada)".to_string(),
                target: insp.target_path.clone(),
            });
        }

        for spec in &cfg.rules.scripts_folder.scripts {
            let name = spec.name.trim();
            let full = target.join(name);
            match ops.read_file_opt(&full)? {
                None => diffs.push(DiffItem {
                    field: format!("script:{name}"),
                    current: "(belum ada)".to_string(),
                    target: format!("buat {}", full.display()),
                }),
                Some(bytes) if bytes != spec.content.as_bytes() => diffs.push(DiffItem {
                    field: format!("script:{name}"),
                    current: format!("sudah ada ({name}, isi berbeda)"),
                    target: "timpa / lewati sesuai pilihan".to_string(),
                }),
                Some(_) => {}
            }
        }

        Ok(RuleCheck {
            id: self.id().to_string(),
            title: self.title().to_string(),
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
        opts: &ApplyOptions,
        snap: &mut BackupSnapshot,
    ) -> Result<(RuleOutcome, Vec<String>)> {
        let insp = inspect_scripts_folder(ops, cfg)?;
        if insp.occupied_by_file {
            bail!(
                "Path '{}' sudah ada sebagai berkas biasa, tidak dapat membuat folder.",
                insp.target_path
            );
        }

        let target = Path::new(&insp.target_path);
        let mut changes = Vec::new();
        let mut skipped_conflicts = Vec::new();
        let mut did_mutate = false;

        if !insp.folder_exists {
            ops.create_dir_all(target)?;
            snap.record_dir_created_once(target);
            changes.push(format!("created directory {}", insp.target_path));
            did_mutate = true;
        }

        for spec in &cfg.rules.scripts_folder.scripts {
            let name = spec.name.trim();
            let full = target.join(name);
            let new_bytes = spec.content.as_bytes();
            match ops.read_file_opt(&full)? {
                None => {
                    snap.record_file_write_once(&full, None);
                    ops.write_file(&full, new_bytes)?;
                    changes.push(format!("created script {}", full.display()));
                    did_mutate = true;
                }
                Some(old_bytes) if old_bytes == new_bytes => {}
                Some(old_bytes) => match opts.script_conflict {
                    ScriptConflictPolicy::Overwrite => {
                        snap.record_file_write_once(&full, Some(&old_bytes));
                        ops.write_file(&full, new_bytes)?;
                        changes.push(format!("overwrote script {}", full.display()));
                        did_mutate = true;
                    }
                    ScriptConflictPolicy::Skip => {
                        skipped_conflicts.push(name.to_string());
                        changes.push(format!(
                            "skipped existing script {} (berkas lama dipertahankan)",
                            full.display()
                        ));
                    }
                },
            }
        }

        if did_mutate {
            Ok((RuleOutcome::Applied, changes))
        } else if !skipped_conflicts.is_empty() {
            Ok((
                RuleOutcome::Skipped {
                    reason: format!(
                        "berkas .txt sudah ada dan dipertahankan: {}",
                        skipped_conflicts.join(", ")
                    ),
                },
                changes,
            ))
        } else {
            Ok((RuleOutcome::AlreadyCompliant, Vec::new()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::rollback_snapshot;
    use crate::config::ScriptFileSpec;
    use crate::platform::fake::FakeSystemOps;

    #[test]
    fn check_lists_existing_txt_files_and_detects_missing_dir() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let rule = ScriptsFolderRule;

        let init = rule.check(&ops, &cfg).unwrap();
        assert_eq!(init.status, CheckStatus::Drifted);
        assert!(init.note.unwrap().contains("belum ada"));

        ops.create_dir_all(Path::new(r"C:\Skrip")).unwrap();
        ops.seed_file(Path::new(r"C:\Skrip\zeta.txt"), b"hello");
        ops.seed_file(Path::new(r"C:\Skrip\alpha.TXT"), b"world");
        ops.seed_file(Path::new(r"C:\Skrip\ignore.log"), b"log");

        let present = rule.check(&ops, &cfg).unwrap();
        assert_eq!(present.status, CheckStatus::Compliant);
        let note = present.note.unwrap();
        assert!(note.to_ascii_lowercase().contains("alpha.txt, zeta.txt"));
        assert!(!note.contains("ignore.log"));
    }

    #[test]
    fn apply_creates_dir_idempotent_and_rollback_removes_empty_dir() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let rule = ScriptsFolderRule;
        let opts = ApplyOptions::default();

        let mut snap = BackupSnapshot::new(&ops);
        let (out1, changes1) = rule.apply(&ops, &cfg, &opts, &mut snap).unwrap();
        assert_eq!(out1, RuleOutcome::Applied);
        assert_eq!(changes1.len(), 1);
        assert!(ops.dir_exists(Path::new(r"C:\Skrip")).unwrap());

        let mut snap2 = BackupSnapshot::new(&ops);
        let (out2, _) = rule.apply(&ops, &cfg, &opts, &mut snap2).unwrap();
        assert_eq!(out2, RuleOutcome::AlreadyCompliant);
        assert!(snap2.is_empty());

        rollback_snapshot(&ops, &snap).unwrap();
        assert!(!ops.dir_exists(Path::new(r"C:\Skrip")).unwrap());
    }

    #[test]
    fn apply_handles_script_conflict_overwrite_vs_skip_and_rollback() {
        let ops = FakeSystemOps::default();
        ops.create_dir_all(Path::new(r"C:\Skrip")).unwrap();
        let script_path = Path::new(r"C:\Skrip\setup.txt");
        ops.seed_file(script_path, b"old-content");

        let mut cfg = ProfileConfig::embedded_default();
        cfg.rules.scripts_folder.scripts = vec![ScriptFileSpec {
            name: "setup.txt".into(),
            content: "new-content".into(),
        }];
        let rule = ScriptsFolderRule;

        let insp = inspect_scripts_folder(&ops, &cfg).unwrap();
        assert!(insp.folder_exists);
        assert_eq!(insp.existing_txt_files, vec!["setup.txt"]);
        assert_eq!(insp.conflicting_scripts, vec!["setup.txt"]);

        let mut snap_skip = BackupSnapshot::new(&ops);
        let (out_skip, _) = rule
            .apply(
                &ops,
                &cfg,
                &ApplyOptions {
                    script_conflict: ScriptConflictPolicy::Skip,
                    ..Default::default()
                },
                &mut snap_skip,
            )
            .unwrap();
        assert!(matches!(out_skip, RuleOutcome::Skipped { .. }));
        assert_eq!(
            ops.read_file_opt(script_path).unwrap().unwrap(),
            b"old-content"
        );

        let mut snap_overwrite = BackupSnapshot::new(&ops);
        let (out_ow, _) = rule
            .apply(
                &ops,
                &cfg,
                &ApplyOptions {
                    script_conflict: ScriptConflictPolicy::Overwrite,
                    ..Default::default()
                },
                &mut snap_overwrite,
            )
            .unwrap();
        assert_eq!(out_ow, RuleOutcome::Applied);
        assert_eq!(
            ops.read_file_opt(script_path).unwrap().unwrap(),
            b"new-content"
        );

        rollback_snapshot(&ops, &snap_overwrite).unwrap();
        assert_eq!(
            ops.read_file_opt(script_path).unwrap().unwrap(),
            b"old-content"
        );
    }

    #[test]
    fn rollback_preserves_non_empty_directory() {
        let ops = FakeSystemOps::default();
        let cfg = ProfileConfig::embedded_default();
        let rule = ScriptsFolderRule;
        let opts = ApplyOptions::default();

        let mut snap = BackupSnapshot::new(&ops);
        rule.apply(&ops, &cfg, &opts, &mut snap).unwrap();

        let user_file = Path::new(r"C:\Skrip\milik_user.txt");
        ops.write_file(user_file, b"penting").unwrap();

        let actions = rollback_snapshot(&ops, &snap).unwrap();
        assert!(ops.dir_exists(Path::new(r"C:\Skrip")).unwrap());
        assert_eq!(ops.read_file_opt(user_file).unwrap().unwrap(), b"penting");
        assert!(
            actions
                .iter()
                .any(|a| a.contains("skipped removing directory"))
        );
    }
}
