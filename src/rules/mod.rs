pub mod accessibility;
pub mod defender_firewall;
pub mod diagnostics;
pub mod edge;
pub mod password_policy;
pub mod power;
pub mod screensaver;
pub mod search;
pub mod startup_apps;
pub mod system_restore;
pub mod taskbar;
pub mod typing;
pub mod visual_effects;

use crate::engine::Rule;

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(visual_effects::VisualEffectsRule),
        Box::new(diagnostics::DiagnosticsRule),
        Box::new(search::SearchRule),
        Box::new(typing::TypingRule),
        Box::new(taskbar::TaskbarRule),
        Box::new(power::PowerRule),
        Box::new(screensaver::ScreensaverRule),
        Box::new(accessibility::AccessibilityRule),
        Box::new(edge::EdgeRule),
        Box::new(system_restore::SystemRestoreRule),
        Box::new(password_policy::PasswordPolicyRule),
        Box::new(defender_firewall::DefenderFirewallRule),
        Box::new(startup_apps::StartupAppsRule),
    ]
}
