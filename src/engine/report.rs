use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Compliant,
    Drifted,
    NeedsAdmin,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffItem {
    pub field: String,
    pub current: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCheck {
    pub id: String,
    pub title: String,
    pub requires_admin: bool,
    pub enabled_in_config: bool,
    pub status: CheckStatus,
    pub diffs: Vec<DiffItem>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuleOutcome {
    Applied,
    AlreadyCompliant,
    WarnTamperProtected { detail: String },
    WarnFirmwareLocked { detail: String },
    WarnEdgeRunning { detail: String },
    Skipped { reason: String },
    Failed { error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRunEntry {
    pub id: String,
    pub title: String,
    pub outcome: RuleOutcome,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReport {
    pub os_caption: String,
    pub is_admin: bool,
    pub checks: Vec<RuleCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunReport {
    pub mode: String,
    pub os_caption: String,
    pub backup_file: Option<PathBuf>,
    pub entries: Vec<RuleRunEntry>,
}

impl RunReport {
    pub fn has_failures(&self) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e.outcome, RuleOutcome::Failed { .. }))
    }

    pub fn exit_code(&self) -> i32 {
        if self.has_failures() { 1 } else { 0 }
    }
}
