use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_TOML: &str = include_str!("defaults.toml");
pub const DEFAULT_CONFIG_FILENAME: &str = "it-tools.toml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileConfig {
    pub version: u32,
    #[serde(default)]
    pub update: UpdateConfig,
    pub rules: RulesConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UpdateConfig {
    #[serde(default)]
    pub allow_beta: bool,
    #[serde(default)]
    pub repo: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RulesConfig {
    pub visual_effects: VisualEffectsConfig,
    pub diagnostics: DiagnosticsConfig,
    pub search: SearchConfig,
    pub typing: TypingConfig,
    pub taskbar: TaskbarConfig,
    pub power: PowerConfig,
    pub screensaver: ScreensaverConfig,
    pub accessibility: AccessibilityConfig,
    pub edge: EdgeConfig,
    pub system_restore: SystemRestoreConfig,
    pub password_policy: PasswordPolicyConfig,
    pub defender_firewall: DefenderFirewallConfig,
    pub startup_apps: StartupAppsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VisualEffectsConfig {
    pub enabled: bool,
    pub animations: bool,
    pub transparency: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackFrequency {
    Never,
    Always,
    OnceADay,
    OnceAWeek,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiagnosticsConfig {
    pub enabled: bool,
    pub optional_data: bool,
    pub feedback_frequency: FeedbackFrequency,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SearchConfig {
    pub enabled: bool,
    pub msa_cloud_search: bool,
    pub work_school_search: bool,
    pub search_highlights: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TypingConfig {
    pub enabled: bool,
    pub autocorrect: bool,
    pub highlight_misspelled: bool,
    pub text_prediction: bool,
    pub typing_insights: bool,
    pub voice_typing_key: bool,
    pub multilingual: bool,
    pub auto_shift: bool,
    pub double_tap_space: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskbarAlignment {
    Left,
    Center,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskbarConfig {
    pub enabled: bool,
    pub widgets: bool,
    pub alignment: TaskbarAlignment,
    pub auto_hide: bool,
    pub show_badges: bool,
    pub show_flashing: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PowerAction {
    Nothing,
    Sleep,
    Hibernate,
    Shutdown,
}

impl PowerAction {
    pub fn as_powercfg_index(self) -> u32 {
        match self {
            PowerAction::Nothing => 0,
            PowerAction::Sleep => 1,
            PowerAction::Hibernate => 2,
            PowerAction::Shutdown => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PowerConfig {
    pub enabled: bool,
    pub hibernate: bool,
    pub scheme: String,
    pub disk_timeout_ac_min: u32,
    pub disk_timeout_dc_min: u32,
    pub min_cpu_ac_pct: u8,
    pub min_cpu_dc_pct: u8,
    pub power_button_ac: PowerAction,
    pub power_button_dc: PowerAction,
    pub lid_close_ac: PowerAction,
    pub lid_close_dc: PowerAction,
    pub display_timeout_ac_min: u32,
    pub display_timeout_dc_min: u32,
    pub sleep_timeout_ac_min: u32,
    pub sleep_timeout_dc_min: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScreensaverConfig {
    pub enabled: bool,
    pub active: bool,
    pub scr_exe: String,
    pub timeout_sec: u32,
    pub require_logon: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessibilityConfig {
    pub enabled: bool,
    pub printscreen_snipping: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EdgeConfig {
    pub enabled: bool,
    pub preload_new_tab: bool,
    pub prelaunch_startup: bool,
    pub tab_preloading: bool,
    pub block_pua: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemRestoreConfig {
    pub enabled: bool,
    pub drive: String,
    pub enable: bool,
    pub max_size: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasswordPolicyConfig {
    pub enabled: bool,
    pub password_history: u16,
    pub max_password_age_days: u16,
    pub min_password_length: u16,
    pub complexity_enabled: bool,
    pub lockout_threshold: u16,
    pub lockout_duration_min: u32,
    pub lockout_reset_min: u32,
    pub allow_admin_lockout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DefenderFirewallConfig {
    pub enabled: bool,
    pub defender_headless_ui: bool,
    pub defender_enabled: bool,
    pub firewall_profiles: Vec<String>,
    pub allow_icmp_echo: bool,
    pub allow_icmp_router: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StartupAppsConfig {
    pub enabled: bool,
    pub allowlist: Vec<String>,
}

impl ProfileConfig {
    pub fn embedded_default() -> Self {
        toml::from_str(DEFAULT_TOML).expect("embedded defaults.toml must be valid")
    }

    pub fn from_toml_merged(override_toml: &str) -> Result<Self> {
        let mut base: toml::Value =
            toml::from_str(DEFAULT_TOML).expect("embedded defaults.toml must parse as Value");
        let overlay: toml::Value =
            toml::from_str(override_toml).context("failed to parse TOML configuration")?;
        merge_toml(&mut base, overlay);
        let cfg: Self = base
            .try_into()
            .context("configuration does not match expected schema")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn resolve_from_disk(
        explicit: Option<&Path>,
        exe_dir: &Path,
    ) -> Result<(Self, Option<PathBuf>)> {
        if let Some(path) = explicit {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read config file: {}", path.display()))?;
            let cfg = Self::from_toml_merged(&content)?;
            return Ok((cfg, Some(path.to_path_buf())));
        }

        let local = exe_dir.join(DEFAULT_CONFIG_FILENAME);
        if local.is_file() {
            let content = fs::read_to_string(&local)
                .with_context(|| format!("failed to read config file: {}", local.display()))?;
            let cfg = Self::from_toml_merged(&content)?;
            return Ok((cfg, Some(local)));
        }

        Ok((Self::embedded_default(), None))
    }

    pub fn save_toml(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let encoded = toml::to_string_pretty(self).context("failed to serialize config")?;
        fs::write(path, encoded)
            .with_context(|| format!("failed to write config file: {}", path.display()))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported config version {} (expected 1)", self.version);
        }
        let p = &self.rules.power;
        if p.min_cpu_ac_pct > 100 {
            bail!("rules.power.min_cpu_ac_pct must be 0..=100");
        }
        if p.min_cpu_dc_pct > 100 {
            bail!("rules.power.min_cpu_dc_pct must be 0..=100");
        }
        if self.rules.screensaver.active && self.rules.screensaver.timeout_sec == 0 {
            bail!("rules.screensaver.timeout_sec must be >= 1 when active");
        }
        let sr = &self.rules.system_restore;
        if !is_valid_drive_spec(&sr.drive) {
            bail!("rules.system_restore.drive must look like 'C:'");
        }
        if !is_valid_vss_size(&sr.max_size) {
            bail!("rules.system_restore.max_size must end with MB, GB, or % (e.g. '5GB' or '5%')");
        }
        let pp = &self.rules.password_policy;
        if pp.password_history > 24 {
            bail!("rules.password_policy.password_history must be 0..=24");
        }
        if pp.max_password_age_days > 999 {
            bail!("rules.password_policy.max_password_age_days must be 0..=999");
        }
        if pp.min_password_length > 128 {
            bail!("rules.password_policy.min_password_length must be 0..=128");
        }
        if pp.lockout_threshold > 0
            && pp.lockout_duration_min > 0
            && pp.lockout_duration_min < pp.lockout_reset_min
        {
            bail!("rules.password_policy.lockout_duration_min must be >= lockout_reset_min");
        }
        let df = &self.rules.defender_firewall;
        for prof in &df.firewall_profiles {
            match prof.to_ascii_lowercase().as_str() {
                "domain" | "private" | "public" => {}
                other => bail!(
                    "invalid firewall profile '{other}' (expected domain, private, or public)"
                ),
            }
        }
        Ok(())
    }
}

pub fn write_default_template(dest: &Path, force: bool) -> Result<()> {
    if dest.exists() && !force {
        bail!(
            "config file already exists at {} (pass --force to overwrite)",
            dest.display()
        );
    }
    if let Some(parent) = dest.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(dest, DEFAULT_TOML)
        .with_context(|| format!("failed to write template to {}", dest.display()))?;
    Ok(())
}

fn merge_toml(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base_map), toml::Value::Table(overlay_map)) => {
            for (k, v) in overlay_map {
                match base_map.get_mut(&k) {
                    Some(existing) => merge_toml(existing, v),
                    None => {
                        base_map.insert(k, v);
                    }
                }
            }
        }
        (base_slot, overlay_val) => {
            *base_slot = overlay_val;
        }
    }
}

fn is_valid_drive_spec(drive: &str) -> bool {
    let bytes = drive.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_valid_vss_size(size: &str) -> bool {
    let upper = size.trim().to_ascii_uppercase();
    let digits = if let Some(rest) = upper.strip_suffix("GB") {
        rest
    } else if let Some(rest) = upper.strip_suffix("MB") {
        rest
    } else if let Some(rest) = upper.strip_suffix('%') {
        rest
    } else {
        return false;
    };
    !digits.is_empty() && digits.parse::<u64>().ok().is_some_and(|n| n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_defaults_parse_with_expected_values() {
        let cfg = ProfileConfig::embedded_default();
        assert_eq!(cfg.rules.power.min_cpu_dc_pct, 50);
        assert_eq!(cfg.rules.power.min_cpu_ac_pct, 100);
        assert_eq!(cfg.rules.password_policy.lockout_threshold, 7);
        assert_eq!(
            cfg.rules.startup_apps.allowlist,
            vec!["OpenVPN GUI", "SecurityHealth"]
        );
        assert_eq!(
            cfg.rules.defender_firewall.firewall_profiles,
            vec!["domain", "private"]
        );
    }

    #[test]
    fn partial_override_file_merges_over_defaults() {
        let custom = r#"
[rules.power]
sleep_timeout_dc_min = 20
[rules.taskbar]
alignment = "center"
"#;
        let cfg = ProfileConfig::from_toml_merged(custom).unwrap();
        assert_eq!(cfg.rules.power.sleep_timeout_dc_min, 20);
        assert_eq!(cfg.rules.power.min_cpu_dc_pct, 50);
        assert_eq!(cfg.rules.taskbar.alignment, TaskbarAlignment::Center);
    }

    #[test]
    fn validation_rejects_invalid_cpu_or_password_ranges() {
        let bad = "[rules.power]\nmin_cpu_dc_pct = 150\n";
        let err = ProfileConfig::from_toml_merged(bad).unwrap_err();
        assert!(err.to_string().contains("min_cpu_dc_pct"));
    }

    #[test]
    fn resolve_from_disk_prefers_explicit_then_exe_dir_then_embedded() {
        let dir = std::env::temp_dir().join(format!("it-tools-cfg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (cfg, src) = ProfileConfig::resolve_from_disk(None, &dir).unwrap();
        assert!(src.is_none());
        assert_eq!(cfg.rules.power.display_timeout_ac_min, 5);

        let local = dir.join(DEFAULT_CONFIG_FILENAME);
        fs::write(&local, "[rules.power]\ndisplay_timeout_ac_min = 12\n").unwrap();
        let (cfg2, src2) = ProfileConfig::resolve_from_disk(None, &dir).unwrap();
        assert_eq!(src2.as_deref(), Some(local.as_path()));
        assert_eq!(cfg2.rules.power.display_timeout_ac_min, 12);

        let explicit = dir.join("custom.toml");
        fs::write(&explicit, "[rules.power]\ndisplay_timeout_ac_min = 25\n").unwrap();
        let (cfg3, src3) = ProfileConfig::resolve_from_disk(Some(&explicit), &dir).unwrap();
        assert_eq!(src3.as_deref(), Some(explicit.as_path()));
        assert_eq!(cfg3.rules.power.display_timeout_ac_min, 25);

        let _ = fs::remove_dir_all(&dir);
    }
}
