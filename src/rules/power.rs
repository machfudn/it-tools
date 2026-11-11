use std::collections::BTreeMap;

use anyhow::{Result, bail};

use crate::backup::{BackupSnapshot, PowerBackup, PowerValueEntry};
use crate::config::{PowerConfig, ProfileConfig};
use crate::engine::report::{CheckStatus, DiffItem, RuleCheck, RuleOutcome};
use crate::engine::{ApplyOptions, Rule};
use crate::platform::{RegHive, RegValue, SystemOps};

const POWER_REG_PATH: &str = r"SYSTEM\CurrentControlSet\Control\Power";
const HIBERNATE_VALUE: &str = "HibernateEnabled";

const GUID_HIGH_PERFORMANCE: &str = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
const GUID_BALANCED: &str = "381b4222-f694-41f0-9685-ff5bb260df2e";
const GUID_POWER_SAVER: &str = "a1841308-3541-4fab-bc81-f71556f20b4a";

const SUB_DISK_GUID: &str = "0012ee47-9041-4b5d-9b77-535fba8b1442";
const SUB_PROCESSOR_GUID: &str = "54533251-82be-4824-96c1-47b60b740d00";
const SUB_BUTTONS_GUID: &str = "4f971e89-eebd-4455-a8de-9e59040e7347";
const SUB_VIDEO_GUID: &str = "7516b95f-f776-4464-8c53-06167f40cc99";
const SUB_SLEEP_GUID: &str = "238c9fa8-0aad-41ed-83f4-97be242c8f20";

const SET_DISKIDLE_GUID: &str = "6738e2c4-e8a5-4a42-b16a-e040e769756e";
const SET_PROCTHROTTLEMIN_GUID: &str = "893dee8e-2bef-41e0-89c6-b55d0929964c";
const SET_PBUTTONACTION_GUID: &str = "7648efa3-dd9c-4e3e-b566-50f929386280";
const SET_LIDACTION_GUID: &str = "5ca83367-6e45-459f-a27b-476b1d01c936";
const SET_VIDEOIDLE_GUID: &str = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e";
const SET_STANDBYIDLE_GUID: &str = "29f6c1db-86da-48c5-9fdb-f2b67b1f44da";

pub struct PowerRule;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PowerSchemeInfo {
    guid: String,
    name: String,
    is_active: bool,
}

#[derive(Debug, Clone, Copy)]
struct PowerSettingSpec {
    field: &'static str,
    subgroup: &'static str,
    setting: &'static str,
    target_ac: u32,
    target_dc: u32,
    unit: &'static str,
}

impl Rule for PowerRule {
    fn id(&self) -> &'static str {
        "power"
    }

    fn title(&self) -> &'static str {
        "Power Settings"
    }

    fn requires_admin(&self) -> bool {
        true
    }

    fn is_enabled(&self, cfg: &ProfileConfig) -> bool {
        cfg.rules.power.enabled
    }

    fn check(&self, ops: &dyn SystemOps, cfg: &ProfileConfig) -> Result<RuleCheck> {
        let p = &cfg.rules.power;
        let schemes = list_power_schemes(ops)?;
        let active = schemes
            .iter()
            .find(|s| s.is_active)
            .ok_or_else(|| anyhow::anyhow!("no active power scheme found in powercfg /L"))?;

        let (target_guid, expected_name) = resolve_target_scheme(&p.scheme);
        let matched = find_matching_scheme(&schemes, &target_guid, expected_name);

        let mut diffs = Vec::new();
        let mut notes = Vec::new();

        if let Some(cur_hib) = read_hibernate_state(ops)? {
            if cur_hib != p.hibernate {
                diffs.push(DiffItem {
                    field: "hibernate".into(),
                    current: enabled_label(cur_hib).into(),
                    target: enabled_label(p.hibernate).into(),
                });
            }
        } else {
            notes.push("hibernate state unavailable from registry or powercfg /a".to_string());
        }

        let query_guid = match matched {
            Some(s) => {
                if !s.is_active {
                    diffs.push(DiffItem {
                        field: "scheme".into(),
                        current: format!("{} ({})", active.guid, active.name),
                        target: format!("{} ({})", s.guid, s.name),
                    });
                }
                s.guid.as_str()
            }
            None => {
                diffs.push(DiffItem {
                    field: "scheme".into(),
                    current: format!("{} ({})", active.guid, active.name),
                    target: expected_name.map_or_else(
                        || target_guid.clone(),
                        |name| format!("{target_guid} ({name})"),
                    ),
                });
                active.guid.as_str()
            }
        };

        let values = query_power_scheme(ops, query_guid)?;
        let mut missing_fields = Vec::new();
        for spec in build_setting_specs(p) {
            match values.get(&(spec.subgroup, spec.setting)) {
                Some(&(cur_ac, cur_dc)) => {
                    if cur_ac != spec.target_ac || cur_dc != spec.target_dc {
                        diffs.push(DiffItem {
                            field: spec.field.into(),
                            current: format_pair(cur_ac, cur_dc, spec.unit),
                            target: format_pair(spec.target_ac, spec.target_dc, spec.unit),
                        });
                    }
                }
                None => {
                    missing_fields.push(spec.field);
                    diffs.push(DiffItem {
                        field: spec.field.into(),
                        current: "absent / firmware-locked".into(),
                        target: format_pair(spec.target_ac, spec.target_dc, spec.unit),
                    });
                }
            }
        }

        if !missing_fields.is_empty() {
            notes.push(format!(
                "settings absent from powercfg /q (possible Modern Standby S0 lock): {}",
                missing_fields.join(", ")
            ));
        }

        let status = if diffs.is_empty() {
            CheckStatus::Compliant
        } else {
            CheckStatus::Drifted
        };

        Ok(RuleCheck {
            id: self.id().into(),
            title: self.title().into(),
            requires_admin: self.requires_admin(),
            enabled_in_config: p.enabled,
            status,
            diffs,
            note: (!notes.is_empty()).then(|| notes.join("; ")),
        })
    }

    fn apply(
        &self,
        ops: &dyn SystemOps,
        cfg: &ProfileConfig,
        _opts: &ApplyOptions,
        snap: &mut BackupSnapshot,
    ) -> Result<(RuleOutcome, Vec<String>)> {
        let p = &cfg.rules.power;
        let schemes = list_power_schemes(ops)?;
        let prior_active_guid = schemes
            .iter()
            .find(|s| s.is_active)
            .map(|s| s.guid.clone())
            .ok_or_else(|| anyhow::anyhow!("no active power scheme found in powercfg /L"))?;

        let (target_guid, expected_name) = resolve_target_scheme(&p.scheme);
        let matched = find_matching_scheme(&schemes, &target_guid, expected_name);
        let cur_hib = read_hibernate_state(ops)?;

        let pre_values = match matched {
            Some(s) => query_power_scheme(ops, &s.guid)?,
            None => query_power_scheme(ops, &prior_active_guid)?,
        };
        let specs = build_setting_specs(p);

        let scheme_compliant = matched.is_some_and(|s| s.is_active);
        let hib_compliant = cur_hib.is_none_or(|b| b == p.hibernate);
        let values_compliant = specs.iter().all(|spec| {
            pre_values
                .get(&(spec.subgroup, spec.setting))
                .is_some_and(|&(ac, dc)| ac == spec.target_ac && dc == spec.target_dc)
        });

        if scheme_compliant && hib_compliant && values_compliant {
            return Ok((RuleOutcome::AlreadyCompliant, Vec::new()));
        }

        let any_unlocked_drifted = specs.iter().any(|spec| {
            pre_values
                .get(&(spec.subgroup, spec.setting))
                .is_some_and(|&(ac, dc)| ac != spec.target_ac || dc != spec.target_dc)
        });
        let need_hibernate = match cur_hib {
            Some(b) => b != p.hibernate,
            None => !scheme_compliant || any_unlocked_drifted,
        };

        let mut changes = Vec::new();
        let mut warnings = Vec::new();

        let prior_hibernate_enabled = cur_hib.unwrap_or(!p.hibernate);
        let mut hibernate_changed = false;
        if need_hibernate {
            let mode = if p.hibernate { "on" } else { "off" };
            let out = ops.run_tool("powercfg", &["/h", mode])?;
            if out.exit_code != 0 {
                let err = detail_from_cmd(&out.stderr, &out.stdout, out.exit_code);
                if err.to_ascii_lowercase().contains("access") {
                    bail!("powercfg /h {mode} failed: {err}");
                }
                warnings.push(format!("powercfg /h {mode} failed: {err}"));
            } else {
                // On real Windows `powercfg /h` updates HibernateEnabled; sync only if a seeded key stayed stale.
                if let Ok(Some(RegValue::Dword(cur))) =
                    ops.reg_read(RegHive::Hklm, POWER_REG_PATH, HIBERNATE_VALUE)
                {
                    let desired = u32::from(p.hibernate);
                    if cur != desired {
                        snap.write_reg_with_backup(
                            ops,
                            RegHive::Hklm,
                            POWER_REG_PATH,
                            HIBERNATE_VALUE,
                            RegValue::Dword(desired),
                        )?;
                    }
                }
                hibernate_changed = true;
                changes.push(format!("set hibernate={}", p.hibernate));
            }
        }

        let mut created_scheme_guid = None;
        let mut scheme_switched = false;
        let work_guid = match matched {
            Some(s) => {
                if !s.is_active {
                    let out = ops.run_tool("powercfg", &["/setactive", &s.guid])?;
                    if out.exit_code != 0 {
                        bail!(
                            "powercfg /setactive {} failed: {}",
                            s.guid,
                            detail_from_cmd(&out.stderr, &out.stdout, out.exit_code)
                        );
                    }
                    scheme_switched = true;
                    changes.push(format!("activated power scheme {} ({})", s.guid, s.name));
                }
                s.guid.clone()
            }
            None => {
                let dup = ops.run_tool("powercfg", &["/duplicatescheme", &target_guid])?;
                if dup.exit_code == 0 {
                    let new_guid = extract_guid(&dup.stdout).ok_or_else(|| {
                        anyhow::anyhow!(
                            "powercfg /duplicatescheme {} did not return a GUID: {}",
                            target_guid,
                            dup.stdout.trim()
                        )
                    })?;
                    let act = ops.run_tool("powercfg", &["/setactive", &new_guid])?;
                    if act.exit_code != 0 {
                        bail!(
                            "powercfg /setactive {} failed: {}",
                            new_guid,
                            detail_from_cmd(&act.stderr, &act.stdout, act.exit_code)
                        );
                    }
                    created_scheme_guid = Some(new_guid.clone());
                    scheme_switched = true;
                    changes.push(format!(
                        "duplicated scheme {target_guid} as {new_guid} and activated it"
                    ));
                    new_guid
                } else if expected_name.is_some() {
                    let err = detail_from_cmd(&dup.stderr, &dup.stdout, dup.exit_code);
                    if err.to_ascii_lowercase().contains("access") {
                        bail!("powercfg /duplicatescheme {target_guid} failed: {err}");
                    }
                    warnings.push(format!(
                        "unable to duplicate scheme {target_guid} ({err}); applying settings to active scheme {prior_active_guid}"
                    ));
                    prior_active_guid.clone()
                } else {
                    bail!(
                        "powercfg /duplicatescheme {target_guid} failed: {}",
                        detail_from_cmd(&dup.stderr, &dup.stdout, dup.exit_code)
                    );
                }
            }
        };

        let work_values = if (work_guid == prior_active_guid && created_scheme_guid.is_none())
            || matched.is_some_and(|s| s.guid == work_guid)
        {
            pre_values
        } else {
            query_power_scheme(ops, &work_guid)?
        };

        let mut prior_values = Vec::new();
        for spec in specs {
            let ac_str = spec.target_ac.to_string();
            let dc_str = spec.target_dc.to_string();

            match work_values.get(&(spec.subgroup, spec.setting)) {
                Some(&(cur_ac, cur_dc)) => {
                    if cur_ac == spec.target_ac && cur_dc == spec.target_dc {
                        continue;
                    }
                    let mut ac_ok = true;
                    let mut dc_ok = true;
                    let mut err_msgs = Vec::new();

                    if cur_ac != spec.target_ac {
                        let out = ops.run_tool(
                            "powercfg",
                            &[
                                "/setacvalueindex",
                                &work_guid,
                                spec.subgroup,
                                spec.setting,
                                &ac_str,
                            ],
                        )?;
                        if out.exit_code != 0 {
                            ac_ok = false;
                            err_msgs.push(format!(
                                "AC: {}",
                                detail_from_cmd(&out.stderr, &out.stdout, out.exit_code)
                            ));
                        }
                    }

                    if cur_dc != spec.target_dc {
                        let out = ops.run_tool(
                            "powercfg",
                            &[
                                "/setdcvalueindex",
                                &work_guid,
                                spec.subgroup,
                                spec.setting,
                                &dc_str,
                            ],
                        )?;
                        if out.exit_code != 0 {
                            dc_ok = false;
                            err_msgs.push(format!(
                                "DC: {}",
                                detail_from_cmd(&out.stderr, &out.stdout, out.exit_code)
                            ));
                        }
                    }

                    if !ac_ok || !dc_ok {
                        warnings.push(format!(
                            "{} ({}/{}) locked/failed ({})",
                            spec.field,
                            spec.subgroup,
                            spec.setting,
                            err_msgs.join(", ")
                        ));
                    }
                    if ac_ok && dc_ok {
                        prior_values.push(PowerValueEntry {
                            scheme_guid: work_guid.clone(),
                            subgroup: spec.subgroup.into(),
                            setting: spec.setting.into(),
                            ac: cur_ac,
                            dc: cur_dc,
                        });
                        changes.push(format!(
                            "set {} ({}/{}) -> {}",
                            spec.field,
                            spec.subgroup,
                            spec.setting,
                            format_pair(spec.target_ac, spec.target_dc, spec.unit)
                        ));
                    }
                }
                None => {
                    let ac_out = ops.run_tool(
                        "powercfg",
                        &[
                            "/setacvalueindex",
                            &work_guid,
                            spec.subgroup,
                            spec.setting,
                            &ac_str,
                        ],
                    )?;
                    let dc_out = ops.run_tool(
                        "powercfg",
                        &[
                            "/setdcvalueindex",
                            &work_guid,
                            spec.subgroup,
                            spec.setting,
                            &dc_str,
                        ],
                    )?;
                    if ac_out.exit_code != 0 || dc_out.exit_code != 0 {
                        let msg = if ac_out.exit_code != 0 {
                            detail_from_cmd(&ac_out.stderr, &ac_out.stdout, ac_out.exit_code)
                        } else {
                            detail_from_cmd(&dc_out.stderr, &dc_out.stdout, dc_out.exit_code)
                        };
                        warnings.push(format!(
                            "{} ({}/{}) absent from /q and rejected ({msg})",
                            spec.field, spec.subgroup, spec.setting
                        ));
                    } else {
                        warnings.push(format!(
                            "{} ({}/{}) absent from powercfg /q (firmware-hidden)",
                            spec.field, spec.subgroup, spec.setting
                        ));
                    }
                }
            }
        }

        let mutated = created_scheme_guid.is_some()
            || scheme_switched
            || hibernate_changed
            || !prior_values.is_empty();

        if mutated {
            let reload = ops.run_tool("powercfg", &["/setactive", &work_guid])?;
            if reload.exit_code != 0 {
                bail!(
                    "powercfg /setactive {} reload failed: {}",
                    work_guid,
                    detail_from_cmd(&reload.stderr, &reload.stdout, reload.exit_code)
                );
            }
            if snap.power.is_none() {
                snap.power = Some(PowerBackup {
                    prior_active_guid,
                    created_scheme_guid,
                    prior_hibernate_enabled,
                    prior_values,
                });
            }
        }

        if !warnings.is_empty() {
            return Ok((
                RuleOutcome::WarnFirmwareLocked {
                    detail: warnings.join("; "),
                },
                changes,
            ));
        }

        if changes.is_empty() {
            Ok((RuleOutcome::AlreadyCompliant, changes))
        } else {
            Ok((RuleOutcome::Applied, changes))
        }
    }
}

fn build_setting_specs(p: &PowerConfig) -> [PowerSettingSpec; 6] {
    [
        PowerSettingSpec {
            field: "disk_timeout",
            subgroup: "SUB_DISK",
            setting: "DISKIDLE",
            target_ac: p.disk_timeout_ac_min.saturating_mul(60),
            target_dc: p.disk_timeout_dc_min.saturating_mul(60),
            unit: "s",
        },
        PowerSettingSpec {
            field: "min_cpu",
            subgroup: "SUB_PROCESSOR",
            setting: "PROCTHROTTLEMIN",
            target_ac: u32::from(p.min_cpu_ac_pct),
            target_dc: u32::from(p.min_cpu_dc_pct),
            unit: "%",
        },
        PowerSettingSpec {
            field: "power_button",
            subgroup: "SUB_BUTTONS",
            setting: "PBUTTONACTION",
            target_ac: p.power_button_ac.as_powercfg_index(),
            target_dc: p.power_button_dc.as_powercfg_index(),
            unit: "",
        },
        PowerSettingSpec {
            field: "lid_close",
            subgroup: "SUB_BUTTONS",
            setting: "LIDACTION",
            target_ac: p.lid_close_ac.as_powercfg_index(),
            target_dc: p.lid_close_dc.as_powercfg_index(),
            unit: "",
        },
        PowerSettingSpec {
            field: "display_timeout",
            subgroup: "SUB_VIDEO",
            setting: "VIDEOIDLE",
            target_ac: p.display_timeout_ac_min.saturating_mul(60),
            target_dc: p.display_timeout_dc_min.saturating_mul(60),
            unit: "s",
        },
        PowerSettingSpec {
            field: "sleep_timeout",
            subgroup: "SUB_SLEEP",
            setting: "STANDBYIDLE",
            target_ac: p.sleep_timeout_ac_min.saturating_mul(60),
            target_dc: p.sleep_timeout_dc_min.saturating_mul(60),
            unit: "s",
        },
    ]
}

fn resolve_target_scheme(scheme: &str) -> (String, Option<&'static str>) {
    let norm = scheme
        .trim()
        .trim_matches(|c| c == '{' || c == '}')
        .to_ascii_lowercase();
    match norm.as_str() {
        "high_performance" | GUID_HIGH_PERFORMANCE => {
            (GUID_HIGH_PERFORMANCE.into(), Some("High performance"))
        }
        "balanced" | GUID_BALANCED => (GUID_BALANCED.into(), Some("Balanced")),
        "power_saver" | GUID_POWER_SAVER => (GUID_POWER_SAVER.into(), Some("Power saver")),
        _ => (norm, None),
    }
}

fn find_matching_scheme<'a>(
    schemes: &'a [PowerSchemeInfo],
    target_guid: &str,
    expected_name: Option<&str>,
) -> Option<&'a PowerSchemeInfo> {
    if let Some(exact) = schemes
        .iter()
        .find(|s| s.guid.eq_ignore_ascii_case(target_guid))
    {
        return Some(exact);
    }
    if let Some(name) = expected_name {
        if let Some(active_named) = schemes
            .iter()
            .find(|s| s.is_active && s.name.eq_ignore_ascii_case(name))
        {
            return Some(active_named);
        }
        return schemes.iter().find(|s| s.name.eq_ignore_ascii_case(name));
    }
    None
}

fn read_hibernate_state(ops: &dyn SystemOps) -> Result<Option<bool>> {
    if let Some(val) = ops.reg_read(RegHive::Hklm, POWER_REG_PATH, HIBERNATE_VALUE)?
        && let Some(dw) = val.as_dword()
    {
        return Ok(Some(dw != 0));
    }
    let out = ops.run_tool("powercfg", &["/a"])?;
    if out.exit_code == 0 && !out.stdout.trim().is_empty() {
        return Ok(parse_powercfg_a_hibernate(&out.stdout));
    }
    Ok(None)
}

fn parse_powercfg_a_hibernate(stdout: &str) -> Option<bool> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        None,
        Available,
        Unavailable,
    }
    let mut section = Section::None;
    for raw in stdout.lines() {
        let trimmed = raw.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("not available on this system") {
            section = Section::Unavailable;
            continue;
        }
        if lower.contains("available on this system") {
            section = Section::Available;
            continue;
        }
        if trimmed.eq_ignore_ascii_case("hibernate") {
            match section {
                Section::Available => return Some(true),
                Section::Unavailable => return Some(false),
                Section::None => {}
            }
        }
    }
    None
}

fn list_power_schemes(ops: &dyn SystemOps) -> Result<Vec<PowerSchemeInfo>> {
    let out = ops.run_tool("powercfg", &["/L"])?;
    if out.exit_code != 0 {
        bail!(
            "powercfg /L failed: {}",
            detail_from_cmd(&out.stderr, &out.stdout, out.exit_code)
        );
    }
    Ok(parse_powercfg_list(&out.stdout))
}

fn parse_powercfg_list(stdout: &str) -> Vec<PowerSchemeInfo> {
    let mut schemes = Vec::new();
    for line in stdout.lines() {
        let Some((guid, end_idx)) = extract_guid_with_span(line) else {
            continue;
        };
        let tail = &line[end_idx..];
        let name = match (tail.find('('), tail.rfind(')')) {
            (Some(open), Some(close)) if open < close => tail[open + 1..close].trim().to_string(),
            _ => String::new(),
        };
        let is_active = tail.trim_end().ends_with('*');
        schemes.push(PowerSchemeInfo {
            guid,
            name,
            is_active,
        });
    }
    schemes
}

type PowerValueMap = BTreeMap<(&'static str, &'static str), (u32, u32)>;

fn query_power_scheme(ops: &dyn SystemOps, guid: &str) -> Result<PowerValueMap> {
    let out = ops.run_tool("powercfg", &["/q", guid])?;
    if out.exit_code != 0 {
        bail!(
            "powercfg /q {guid} failed: {}",
            detail_from_cmd(&out.stderr, &out.stdout, out.exit_code)
        );
    }
    Ok(parse_powercfg_query(&out.stdout))
}

fn parse_powercfg_query(stdout: &str) -> PowerValueMap {
    let mut parsed = BTreeMap::new();
    let mut cur_sub: Option<&'static str> = None;
    let mut cur_set: Option<&'static str> = None;
    let mut cur_ac: Option<u32> = None;
    let mut cur_dc: Option<u32> = None;

    let flush = |sub: Option<&'static str>,
                 set: Option<&'static str>,
                 ac: &mut Option<u32>,
                 dc: &mut Option<u32>,
                 out: &mut PowerValueMap| {
        if let (Some(sub), Some(set), Some(a), Some(d)) = (sub, set, *ac, *dc) {
            out.insert((sub, set), (a, d));
        }
        *ac = None;
        *dc = None;
    };

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();

        if let Some((guid, end_idx)) = extract_guid_with_span(trimmed) {
            if lower.starts_with("power scheme guid") || raw_indent(line) == 0 {
                continue;
            }
            if let Some(sub) = subgroup_from_guid(&guid) {
                flush(cur_sub, cur_set, &mut cur_ac, &mut cur_dc, &mut parsed);
                cur_sub = Some(sub);
                cur_set = None;
                continue;
            }
            if let Some(set) = setting_from_guid(&guid) {
                flush(cur_sub, cur_set, &mut cur_ac, &mut cur_dc, &mut parsed);
                cur_set = Some(set);
                continue;
            }
            let parens = extract_paren_text(&trimmed[end_idx..]);
            if lower.contains("subgroup guid") {
                flush(cur_sub, cur_set, &mut cur_ac, &mut cur_dc, &mut parsed);
                cur_sub = parens.and_then(subgroup_from_alias);
                cur_set = None;
            } else {
                // Unknown or fake-GUID Power Setting line: flush and wait for GUID Alias / parens.
                flush(cur_sub, cur_set, &mut cur_ac, &mut cur_dc, &mut parsed);
                cur_set = parens.and_then(setting_from_alias);
            }
            continue;
        }

        if let Some((_, rhs)) = trimmed.split_once(':') {
            let token = rhs.trim();
            if let Some(sub) = subgroup_from_alias(token) {
                flush(cur_sub, cur_set, &mut cur_ac, &mut cur_dc, &mut parsed);
                cur_sub = Some(sub);
                cur_set = None;
                continue;
            }
            if let Some(set) = setting_from_alias(token) {
                cur_set = Some(set);
                continue;
            }
            if let Some(val) = parse_hex_index(token) {
                let lhs = lower.split(':').next().unwrap_or("");
                if is_ac_index_label(lhs) {
                    cur_ac = Some(val);
                } else if is_dc_index_label(lhs) {
                    cur_dc = Some(val);
                }
            }
        }
    }

    flush(cur_sub, cur_set, &mut cur_ac, &mut cur_dc, &mut parsed);
    parsed
}

fn raw_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn extract_paren_text(s: &str) -> Option<&str> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    (open < close).then(|| s[open + 1..close].trim())
}

fn subgroup_from_guid(guid: &str) -> Option<&'static str> {
    match guid {
        SUB_DISK_GUID => Some("SUB_DISK"),
        SUB_PROCESSOR_GUID => Some("SUB_PROCESSOR"),
        SUB_BUTTONS_GUID => Some("SUB_BUTTONS"),
        SUB_VIDEO_GUID => Some("SUB_VIDEO"),
        SUB_SLEEP_GUID => Some("SUB_SLEEP"),
        _ => None,
    }
}

fn setting_from_guid(guid: &str) -> Option<&'static str> {
    match guid {
        SET_DISKIDLE_GUID => Some("DISKIDLE"),
        SET_PROCTHROTTLEMIN_GUID => Some("PROCTHROTTLEMIN"),
        SET_PBUTTONACTION_GUID => Some("PBUTTONACTION"),
        SET_LIDACTION_GUID => Some("LIDACTION"),
        SET_VIDEOIDLE_GUID => Some("VIDEOIDLE"),
        SET_STANDBYIDLE_GUID => Some("STANDBYIDLE"),
        _ => None,
    }
}

fn subgroup_from_alias(token: &str) -> Option<&'static str> {
    match token.trim().to_ascii_uppercase().as_str() {
        "SUB_DISK" => Some("SUB_DISK"),
        "SUB_PROCESSOR" => Some("SUB_PROCESSOR"),
        "SUB_BUTTONS" => Some("SUB_BUTTONS"),
        "SUB_VIDEO" => Some("SUB_VIDEO"),
        "SUB_SLEEP" => Some("SUB_SLEEP"),
        _ => None,
    }
}

fn setting_from_alias(token: &str) -> Option<&'static str> {
    match token.trim().to_ascii_uppercase().as_str() {
        "DISKIDLE" => Some("DISKIDLE"),
        "PROCTHROTTLEMIN" => Some("PROCTHROTTLEMIN"),
        "PBUTTONACTION" => Some("PBUTTONACTION"),
        "LIDACTION" => Some("LIDACTION"),
        "VIDEOIDLE" => Some("VIDEOIDLE"),
        "STANDBYIDLE" => Some("STANDBYIDLE"),
        _ => None,
    }
}

fn is_ac_index_label(lhs_lower: &str) -> bool {
    lhs_lower.contains("current ac")
        || lhs_lower
            .split_whitespace()
            .any(|w| w == "ac" || w == "(ac)")
}

fn is_dc_index_label(lhs_lower: &str) -> bool {
    lhs_lower.contains("current dc")
        || lhs_lower
            .split_whitespace()
            .any(|w| w == "dc" || w == "(dc)")
}

fn parse_hex_index(rhs: &str) -> Option<u32> {
    let tok = rhs.split_whitespace().next()?;
    let hex = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X"))?;
    u32::from_str_radix(hex, 16).ok()
}

fn extract_guid(s: &str) -> Option<String> {
    extract_guid_with_span(s).map(|(g, _)| g)
}

fn extract_guid_with_span(s: &str) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    if bytes.len() < 36 {
        return None;
    }
    for i in 0..=bytes.len() - 36 {
        if i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
            continue;
        }
        let cand = &bytes[i..i + 36];
        if i + 36 < bytes.len() && bytes[i + 36].is_ascii_alphanumeric() {
            continue;
        }
        if is_guid_bytes(cand) {
            let guid = std::str::from_utf8(cand).ok()?.to_ascii_lowercase();
            return Some((guid, i + 36));
        }
    }
    None
}

fn is_guid_bytes(b: &[u8]) -> bool {
    if b.len() != 36 {
        return false;
    }
    for (idx, &ch) in b.iter().enumerate() {
        let is_dash = matches!(idx, 8 | 13 | 18 | 23);
        if is_dash {
            if ch != b'-' {
                return false;
            }
        } else if !ch.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn enabled_label(v: bool) -> &'static str {
    if v { "enabled" } else { "disabled" }
}

fn format_pair(ac: u32, dc: u32, unit: &str) -> String {
    format!("AC {ac}{unit} / DC {dc}{unit}")
}

fn detail_from_cmd(stderr: &str, stdout: &str, code: i32) -> String {
    let s = stderr.trim();
    if !s.is_empty() {
        return s.to_string();
    }
    let o = stdout.trim();
    if !o.is_empty() {
        return o.to_string();
    }
    format!("exit code {code}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::rollback_snapshot;
    use crate::platform::fake::FakeSystemOps;

    #[test]
    fn normal_flow_check_apply_idempotent_and_rollback() {
        let ops = FakeSystemOps::default();
        ops.seed_reg(
            RegHive::Hklm,
            POWER_REG_PATH,
            HIBERNATE_VALUE,
            RegValue::Dword(1),
        );
        let cfg = ProfileConfig::embedded_default();
        let rule = PowerRule;
        let opts = ApplyOptions::default();

        let check1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(check1.status, CheckStatus::Drifted);
        assert!(check1.diffs.iter().any(|d| d.field == "hibernate"));
        assert!(check1.diffs.iter().any(|d| d.field == "scheme"));
        assert!(check1.diffs.iter().any(|d| d.field == "sleep_timeout"));

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome1, changes1) = rule.apply(&ops, &cfg, &opts, &mut snap).unwrap();
        assert_eq!(outcome1, RuleOutcome::Applied);
        assert!(!changes1.is_empty());

        let pb = snap.power.as_ref().expect("PowerBackup captured");
        assert_eq!(pb.prior_active_guid, GUID_BALANCED);
        assert_eq!(pb.created_scheme_guid, None);
        assert!(pb.prior_hibernate_enabled);

        {
            let st = ops.state.borrow();
            assert!(!st.hibernate_enabled);
            assert_eq!(st.active_scheme, GUID_HIGH_PERFORMANCE);
            let hp = &st.power_schemes[GUID_HIGH_PERFORMANCE];
            assert_eq!(hp.values[&("sub_disk".into(), "diskidle".into())], (0, 0));
            assert_eq!(
                hp.values[&("sub_processor".into(), "procthrottlemin".into())],
                (100, 50)
            );
            assert_eq!(
                hp.values[&("sub_buttons".into(), "pbuttonaction".into())],
                (3, 3)
            );
            assert_eq!(
                hp.values[&("sub_buttons".into(), "lidaction".into())],
                (1, 1)
            );
            assert_eq!(
                hp.values[&("sub_video".into(), "videoidle".into())],
                (300, 300)
            );
            assert_eq!(
                hp.values[&("sub_sleep".into(), "standbyidle".into())],
                (0, 600)
            );
        }

        let check2 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(check2.status, CheckStatus::Compliant);
        assert!(check2.diffs.is_empty());

        let mut snap2 = BackupSnapshot::new(&ops);
        let (outcome2, changes2) = rule.apply(&ops, &cfg, &opts, &mut snap2).unwrap();
        assert_eq!(outcome2, RuleOutcome::AlreadyCompliant);
        assert!(changes2.is_empty());
        assert!(snap2.power.is_none());

        rollback_snapshot(&ops, &snap).unwrap();
        let st = ops.state.borrow();
        assert!(st.hibernate_enabled);
        assert_eq!(st.active_scheme, GUID_BALANCED);
        let hp = &st.power_schemes[GUID_HIGH_PERFORMANCE];
        assert_eq!(
            hp.values[&("sub_processor".into(), "procthrottlemin".into())],
            (100, 100)
        );
        assert_eq!(
            hp.values[&("sub_sleep".into(), "standbyidle".into())],
            (1800, 900)
        );
    }

    #[test]
    fn modern_standby_s0_duplicates_missing_scheme_and_warns_firmware_locked() {
        let ops = FakeSystemOps::default();
        {
            let mut st = ops.state.borrow_mut();
            st.power_schemes.remove(GUID_HIGH_PERFORMANCE);
            st.locked_power_subgroups.insert("sub_processor".into());
        }
        let cfg = ProfileConfig::embedded_default();
        let rule = PowerRule;
        let opts = ApplyOptions::default();

        let check1 = rule.check(&ops, &cfg).unwrap();
        assert_eq!(check1.status, CheckStatus::Drifted);
        assert!(check1.note.as_deref().unwrap_or("").contains("min_cpu"));

        let mut snap = BackupSnapshot::new(&ops);
        let (outcome, changes) = rule.apply(&ops, &cfg, &opts, &mut snap).unwrap();
        match outcome {
            RuleOutcome::WarnFirmwareLocked { detail } => {
                assert!(detail.contains("PROCTHROTTLEMIN"));
            }
            other => panic!("expected WarnFirmwareLocked, got {other:?}"),
        }
        assert!(!changes.is_empty());

        let pb = snap.power.as_ref().expect("PowerBackup captured");
        assert_eq!(pb.prior_active_guid, GUID_BALANCED);
        let created = pb
            .created_scheme_guid
            .clone()
            .expect("created_scheme_guid recorded");
        assert_eq!(ops.state.borrow().active_scheme, created);
        assert!(!ops.state.borrow().hibernate_enabled);
        assert_eq!(
            ops.state.borrow().power_schemes[&created].values
                [&("sub_sleep".into(), "standbyidle".into())],
            (0, 600)
        );

        // Second apply reuses duplicated scheme without creating another duplicate.
        let count_before = ops.state.borrow().power_schemes.len();
        let mut snap2 = BackupSnapshot::new(&ops);
        let (outcome2, changes2) = rule.apply(&ops, &cfg, &opts, &mut snap2).unwrap();
        assert!(matches!(outcome2, RuleOutcome::WarnFirmwareLocked { .. }));
        assert!(changes2.is_empty());
        assert_eq!(ops.state.borrow().power_schemes.len(), count_before);
        assert!(snap2.power.is_none());

        rollback_snapshot(&ops, &snap).unwrap();
        let st = ops.state.borrow();
        assert_eq!(st.active_scheme, GUID_BALANCED);
        assert!(!st.power_schemes.contains_key(&created));
        assert!(st.hibernate_enabled);
    }

    #[test]
    fn parses_real_windows_powercfg_outputs() {
        let list_out = "\
Existing Power Schemes (* Active)\r\n\
-----------------------------------\r\n\
Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced) *\r\n\
Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)\r\n";
        let schemes = parse_powercfg_list(list_out);
        assert_eq!(schemes.len(), 2);
        assert!(schemes[0].is_active);
        assert_eq!(schemes[0].name, "Balanced");
        assert!(!schemes[1].is_active);
        assert_eq!(schemes[1].guid, GUID_HIGH_PERFORMANCE);

        let q_out = "\
Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)
  Subgroup GUID: 0012ee47-9041-4b5d-9b77-535fba8b1442  (Hard disk)
    GUID Alias: SUB_DISK
    Power Setting GUID: 6738e2c4-e8a5-4a42-b16a-e040e769756e  (Turn off hard disk after)
      GUID Alias: DISKIDLE
      Minimum Possible Setting: 0x00000000
      Maximum Possible Setting: 0xffffffff
    Current AC Power Setting Index: 0x000004b0
    Current DC Power Setting Index: 0x00000258
  Subgroup GUID: 4f971e89-eebd-4455-a8de-9e59040e7347  (Power buttons and lid)
    GUID Alias: SUB_BUTTONS
    Power Setting GUID: 5ca83367-6e45-459f-a27b-476b1d01c936  (Lid close action)
      GUID Alias: LIDACTION
    Current AC Power Setting Index: 0x00000001
    Current DC Power Setting Index: 0x00000002
    Power Setting GUID: a7066653-8d6c-40a8-910e-a1f54b84c7e5  (Start menu power button)
      GUID Alias: UIBUTTON_ACTION
    Current AC Power Setting Index: 0x00000003
    Current DC Power Setting Index: 0x00000003
";
        let parsed = parse_powercfg_query(q_out);
        assert_eq!(parsed[&("SUB_DISK", "DISKIDLE")], (1200, 600));
        assert_eq!(parsed[&("SUB_BUTTONS", "LIDACTION")], (1, 2));
        assert_eq!(parsed.len(), 2);

        let a_enabled = "\
The following sleep states are available on this system:\n\
    Standby (S3)\n\
    Hibernate\n";
        assert_eq!(parse_powercfg_a_hibernate(a_enabled), Some(true));

        let a_disabled = "\
The following sleep states are available on this system:\n\
    Standby (S0 Low Power Idle) Network Connected\n\
The following sleep states are not available on this system:\n\
    Hibernate\n\
        Hibernation has not been enabled.\n";
        assert_eq!(parse_powercfg_a_hibernate(a_disabled), Some(false));
    }
}
