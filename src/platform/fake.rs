use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::platform::{CmdOutput, LocalUserInfo, RegHive, RegValue, SystemOps};

#[derive(Debug, Clone)]
pub struct FakePowerScheme {
    pub guid: String,
    pub name: String,
    pub values: BTreeMap<(String, String), (u32, u32)>,
}

#[derive(Debug, Clone)]
pub struct FakeFirewallRule {
    pub name: String,
    pub dir: String,
    pub action: String,
    pub protocol: String,
    pub profile: String,
}

#[derive(Debug, Clone)]
pub struct FakeState {
    pub admin: bool,
    pub console_tty: bool,
    pub current_user: String,
    pub os_caption: String,
    pub local_appdata: PathBuf,
    pub user_startup_dir: PathBuf,
    pub common_startup_dir: PathBuf,
    pub temp_dir: PathBuf,
    pub tamper_protected: bool,
    pub running_processes: BTreeSet<String>,
    pub registry: BTreeMap<(RegHive, String), BTreeMap<String, (String, RegValue)>>,
    pub files: BTreeMap<String, Vec<u8>>,
    pub users: BTreeMap<String, (LocalUserInfo, String)>,
    pub power_schemes: BTreeMap<String, FakePowerScheme>,
    pub active_scheme: String,
    pub hibernate_enabled: bool,
    pub locked_power_subgroups: BTreeSet<String>,
    pub next_dup_counter: u32,
    pub system_access: BTreeMap<String, String>,
    pub firewall_profiles: BTreeMap<String, bool>,
    pub firewall_rules: Vec<FakeFirewallRule>,
    pub restore_enabled: bool,
    pub shadow_max_size: Option<String>,
    pub shadow_allocated: String,
    pub exe_path: PathBuf,
    pub http_responses: BTreeMap<String, (u16, Vec<u8>)>,
    pub recorded_commands: Vec<String>,
    pub broadcasts: u32,
    pub explorer_restarts: u32,
    pub relaunched_args: Vec<Vec<String>>,
}

impl Default for FakeState {
    fn default() -> Self {
        let mut power_schemes = BTreeMap::new();
        let balanced = "381b4222-f694-41f0-9685-ff5bb260df2e".to_string();
        let high_perf = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c".to_string();
        power_schemes.insert(
            balanced.clone(),
            FakePowerScheme {
                guid: balanced.clone(),
                name: "Balanced".to_string(),
                values: default_power_values(false),
            },
        );
        power_schemes.insert(
            high_perf.clone(),
            FakePowerScheme {
                guid: high_perf,
                name: "High performance".to_string(),
                values: default_power_values(true),
            },
        );

        let mut system_access = BTreeMap::new();
        system_access.insert("MinimumPasswordAge".into(), "0".into());
        system_access.insert("MaximumPasswordAge".into(), "42".into());
        system_access.insert("MinimumPasswordLength".into(), "0".into());
        system_access.insert("PasswordComplexity".into(), "0".into());
        system_access.insert("PasswordHistorySize".into(), "0".into());
        system_access.insert("LockoutBadCount".into(), "0".into());
        system_access.insert("ResetLockoutCount".into(), "10".into());
        system_access.insert("LockoutDuration".into(), "10".into());
        system_access.insert("AllowAdministratorLockout".into(), "0".into());

        let mut firewall_profiles = BTreeMap::new();
        firewall_profiles.insert("domain".into(), false);
        firewall_profiles.insert("private".into(), true);
        firewall_profiles.insert("public".into(), true);

        let mut users = BTreeMap::new();
        users.insert(
            "admin".into(),
            (
                LocalUserInfo {
                    name: "Admin".into(),
                    disabled: false,
                    dont_expire_password: true,
                },
                "OldPass1!".into(),
            ),
        );

        Self {
            admin: true,
            console_tty: true,
            current_user: "Admin".into(),
            os_caption: "Microsoft Windows 11 Pro (Fake 26200)".into(),
            local_appdata: PathBuf::from(r"C:\FakeUsers\Admin\AppData\Local"),
            user_startup_dir: PathBuf::from(
                r"C:\FakeUsers\Admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            ),
            common_startup_dir: PathBuf::from(
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            ),
            temp_dir: PathBuf::from(r"C:\FakeTemp"),
            tamper_protected: false,
            running_processes: BTreeSet::new(),
            registry: BTreeMap::new(),
            files: BTreeMap::new(),
            users,
            power_schemes,
            active_scheme: balanced,
            hibernate_enabled: true,
            locked_power_subgroups: BTreeSet::new(),
            next_dup_counter: 1,
            system_access,
            firewall_profiles,
            firewall_rules: Vec::new(),
            restore_enabled: false,
            shadow_max_size: None,
            shadow_allocated: "0 bytes".into(),
            exe_path: PathBuf::from(r"C:\FakeBin\it-tools.exe"),
            http_responses: BTreeMap::new(),
            recorded_commands: Vec::new(),
            broadcasts: 0,
            explorer_restarts: 0,
            relaunched_args: Vec::new(),
        }
    }
}

fn default_power_values(high_perf: bool) -> BTreeMap<(String, String), (u32, u32)> {
    let mut m = BTreeMap::new();
    m.insert(("sub_disk".into(), "diskidle".into()), (1200, 600));
    m.insert(
        ("sub_processor".into(), "procthrottlemin".into()),
        if high_perf { (100, 100) } else { (5, 5) },
    );
    m.insert(("sub_buttons".into(), "pbuttonaction".into()), (1, 1));
    m.insert(("sub_buttons".into(), "lidaction".into()), (1, 1));
    m.insert(("sub_video".into(), "videoidle".into()), (600, 300));
    m.insert(("sub_sleep".into(), "standbyidle".into()), (1800, 900));
    m
}

#[derive(Debug, Default)]
pub struct FakeSystemOps {
    pub state: RefCell<FakeState>,
}

impl FakeSystemOps {
    pub fn with_state(state: FakeState) -> Self {
        Self {
            state: RefCell::new(state),
        }
    }

    pub fn seed_reg(&self, hive: RegHive, path: &str, name: &str, value: RegValue) {
        self.reg_write(hive, path, name, value).unwrap();
    }

    pub fn seed_file(&self, path: &Path, bytes: &[u8]) {
        self.write_file(path, bytes).unwrap();
    }

    fn norm_path(p: &str) -> String {
        p.trim_matches('\\').to_ascii_lowercase()
    }

    fn norm_file(p: &Path) -> String {
        p.to_string_lossy().replace('/', "\\").to_ascii_lowercase()
    }
}

impl SystemOps for FakeSystemOps {
    fn reg_read(&self, hive: RegHive, path: &str, name: &str) -> Result<Option<RegValue>> {
        let st = self.state.borrow();
        let key = (hive, Self::norm_path(path));
        Ok(st
            .registry
            .get(&key)
            .and_then(|vals| vals.get(&name.to_ascii_lowercase()))
            .map(|(_, v)| v.clone()))
    }

    fn reg_write(&self, hive: RegHive, path: &str, name: &str, value: RegValue) -> Result<()> {
        let mut st = self.state.borrow_mut();
        let norm = Self::norm_path(path);
        if !st.admin && hive == RegHive::Hklm {
            bail!("Access is denied (HKLM requires Administrator)");
        }
        if st.tamper_protected && hive == RegHive::Hklm && norm.contains("windows defender") {
            bail!("Access is denied (Protected by Windows Defender Tamper Protection)");
        }
        let bucket = st.registry.entry((hive, norm)).or_default();
        bucket.insert(name.to_ascii_lowercase(), (name.to_string(), value));
        Ok(())
    }

    fn reg_delete_value(&self, hive: RegHive, path: &str, name: &str) -> Result<()> {
        let mut st = self.state.borrow_mut();
        if !st.admin && hive == RegHive::Hklm {
            bail!("Access is denied (HKLM requires Administrator)");
        }
        if let Some(bucket) = st.registry.get_mut(&(hive, Self::norm_path(path))) {
            bucket.remove(&name.to_ascii_lowercase());
        }
        Ok(())
    }

    fn reg_list_values(&self, hive: RegHive, path: &str) -> Result<Vec<(String, RegValue)>> {
        let st = self.state.borrow();
        let Some(bucket) = st.registry.get(&(hive, Self::norm_path(path))) else {
            return Ok(Vec::new());
        };
        Ok(bucket
            .values()
            .map(|(orig, val)| (orig.clone(), val.clone()))
            .collect())
    }

    fn reg_list_subkeys(&self, hive: RegHive, path: &str) -> Result<Vec<String>> {
        let st = self.state.borrow();
        let prefix = Self::norm_path(path);
        let prefix_slash = format!("{prefix}\\");
        let mut subs = BTreeSet::new();
        for (h, k) in st.registry.keys() {
            if *h == hive
                && let Some(rest) = k.strip_prefix(&prefix_slash)
                && let Some(first) = rest.split('\\').next()
                && !first.is_empty()
            {
                subs.insert(first.to_string());
            }
        }
        Ok(subs.into_iter().collect())
    }

    fn local_appdata_dir(&self) -> Option<PathBuf> {
        Some(self.state.borrow().local_appdata.clone())
    }

    fn startup_folders(&self) -> Vec<(String, PathBuf)> {
        let st = self.state.borrow();
        vec![
            ("user".into(), st.user_startup_dir.clone()),
            ("common".into(), st.common_startup_dir.clone()),
        ]
    }

    fn read_file_opt(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        let st = self.state.borrow();
        Ok(st.files.get(&Self::norm_file(path)).cloned())
    }

    fn write_file(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        self.state
            .borrow_mut()
            .files
            .insert(Self::norm_file(path), bytes.to_vec());
        Ok(())
    }

    fn remove_file_opt(&self, path: &Path) -> Result<()> {
        self.state.borrow_mut().files.remove(&Self::norm_file(path));
        Ok(())
    }

    fn temp_dir(&self) -> PathBuf {
        self.state.borrow().temp_dir.clone()
    }

    fn is_process_running(&self, exe_name: &str) -> bool {
        let target = exe_name.to_ascii_lowercase();
        self.state
            .borrow()
            .running_processes
            .iter()
            .any(|p| p.to_ascii_lowercase() == target)
    }

    fn is_admin(&self) -> bool {
        self.state.borrow().admin
    }

    fn is_console_tty(&self) -> bool {
        self.state.borrow().console_tty
    }

    fn current_username(&self) -> String {
        self.state.borrow().current_user.clone()
    }

    fn os_caption(&self) -> String {
        self.state.borrow().os_caption.clone()
    }

    fn local_timestamp_compact(&self) -> String {
        "20261111-120000".into()
    }

    fn local_timestamp_iso(&self) -> String {
        "2026-11-11T12:00:00".into()
    }

    fn relaunch_as_admin(&self, args: &[String]) -> Result<()> {
        self.state.borrow_mut().relaunched_args.push(args.to_vec());
        Ok(())
    }

    fn list_local_users(&self) -> Result<Vec<LocalUserInfo>> {
        Ok(self
            .state
            .borrow()
            .users
            .values()
            .map(|(info, _)| info.clone())
            .collect())
    }

    fn create_local_user(&self, name: &str, password: &str) -> Result<()> {
        let mut st = self.state.borrow_mut();
        if !st.admin {
            bail!("Access is denied");
        }
        let key = name.to_ascii_lowercase();
        if st.users.contains_key(&key) {
            bail!("User '{name}' already exists");
        }
        st.users.insert(
            key,
            (
                LocalUserInfo {
                    name: name.to_string(),
                    disabled: false,
                    dont_expire_password: false,
                },
                password.to_string(),
            ),
        );
        Ok(())
    }

    fn set_user_dont_expire(&self, name: &str, dont_expire: bool) -> Result<()> {
        let mut st = self.state.borrow_mut();
        if !st.admin {
            bail!("Access is denied");
        }
        let key = name.to_ascii_lowercase();
        let Some((info, _)) = st.users.get_mut(&key) else {
            bail!("User '{name}' not found");
        };
        info.dont_expire_password = dont_expire;
        Ok(())
    }

    fn set_user_password(&self, name: &str, password: &str) -> Result<()> {
        let mut st = self.state.borrow_mut();
        if !st.admin {
            bail!("Access is denied");
        }
        let key = name.to_ascii_lowercase();
        let Some((_, pw)) = st.users.get_mut(&key) else {
            bail!("User '{name}' not found");
        };
        *pw = password.to_string();
        Ok(())
    }

    fn run_tool(&self, program: &str, args: &[&str]) -> Result<CmdOutput> {
        let mut st = self.state.borrow_mut();
        st.recorded_commands
            .push(format!("{} {}", program, args.join(" ")));
        let prog = program.to_ascii_lowercase();
        match prog.as_str() {
            "powercfg" | "powercfg.exe" => handle_fake_powercfg(&mut st, args),
            "secedit" | "secedit.exe" => handle_fake_secedit(&mut st, args),
            "netsh" | "netsh.exe" => handle_fake_netsh(&mut st, args),
            "vssadmin" | "vssadmin.exe" => handle_fake_vssadmin(&mut st, args),
            "powershell" | "powershell.exe" => handle_fake_powershell(&mut st, args),
            _ => bail!("FakeSystemOps: unsupported tool '{program}'"),
        }
    }

    fn broadcast_setting_change(&self) -> Result<()> {
        self.state.borrow_mut().broadcasts += 1;
        Ok(())
    }

    fn http_get(&self, url: &str, _accept: Option<&str>) -> Result<Vec<u8>> {
        let st = self.state.borrow();
        match st.http_responses.get(url) {
            Some((status, body)) if (200..300).contains(status) => Ok(body.clone()),
            Some((status, _)) => bail!("HTTP {status} fetching {url}"),
            None => bail!("no fake HTTP response registered for {url}"),
        }
    }

    fn current_exe_path(&self) -> Result<PathBuf> {
        Ok(self.state.borrow().exe_path.clone())
    }

    fn rename_file(&self, from: &Path, to: &Path) -> Result<()> {
        let from_k = Self::norm_file(from);
        let to_k = Self::norm_file(to);
        let mut st = self.state.borrow_mut();
        let bytes = st
            .files
            .remove(&from_k)
            .ok_or_else(|| anyhow::anyhow!("fake rename source not found: {}", from.display()))?;
        st.files.insert(to_k, bytes);
        Ok(())
    }

    fn restart_explorer(&self) -> Result<()> {
        self.state.borrow_mut().explorer_restarts += 1;
        Ok(())
    }
}

fn handle_fake_powercfg(st: &mut FakeState, args: &[&str]) -> Result<CmdOutput> {
    if !st.admin && !matches!(args.first().copied(), Some("/L" | "/l" | "/q" | "/Q")) {
        return Ok(CmdOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "Access denied".into(),
        });
    }
    match args {
        ["/L"] | ["/l"] => {
            let mut out = String::from(
                "Existing Power Schemes (* Active)\n-----------------------------------\n",
            );
            for scheme in st.power_schemes.values() {
                let mark = if scheme.guid.eq_ignore_ascii_case(&st.active_scheme) {
                    " *"
                } else {
                    ""
                };
                out.push_str(&format!(
                    "Power Scheme GUID: {}  ({}){}\n",
                    scheme.guid, scheme.name, mark
                ));
            }
            Ok(CmdOutput {
                exit_code: 0,
                stdout: out,
                stderr: String::new(),
            })
        }
        ["/h", mode] | ["/H", mode] => {
            st.hibernate_enabled = mode.eq_ignore_ascii_case("on");
            Ok(CmdOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
        ["/duplicatescheme", base_guid] => {
            let new_guid = format!("aaaaaaaa-0000-0000-0000-{:012}", st.next_dup_counter);
            st.next_dup_counter += 1;
            let values = st
                .power_schemes
                .get(&base_guid.to_ascii_lowercase())
                .map(|s| s.values.clone())
                .unwrap_or_else(|| default_power_values(true));
            st.power_schemes.insert(
                new_guid.clone(),
                FakePowerScheme {
                    guid: new_guid.clone(),
                    name: "High performance".into(),
                    values,
                },
            );
            Ok(CmdOutput {
                exit_code: 0,
                stdout: format!("Power Scheme GUID: {new_guid}  (High performance)\n"),
                stderr: String::new(),
            })
        }
        ["/setactive", guid] => {
            let g = resolve_scheme_guid(st, guid);
            if st.power_schemes.contains_key(&g) {
                st.active_scheme = g;
                Ok(CmdOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            } else {
                Ok(CmdOutput {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "Invalid Parameters".into(),
                })
            }
        }
        ["/delete", guid] => {
            st.power_schemes.remove(&guid.to_ascii_lowercase());
            Ok(CmdOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
        ["/setacvalueindex", guid, sub, setting, val]
        | ["/setdcvalueindex", guid, sub, setting, val] => {
            let is_ac = args[0].eq_ignore_ascii_case("/setacvalueindex");
            let sub_low = sub.to_ascii_lowercase();
            if st.locked_power_subgroups.contains(&sub_low) {
                return Ok(CmdOutput {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "Setting hidden or locked by Modern Standby firmware".into(),
                });
            }
            let g = resolve_scheme_guid(st, guid);
            let parsed_val: u32 = val.parse().unwrap_or(0);
            if let Some(scheme) = st.power_schemes.get_mut(&g) {
                let entry = scheme
                    .values
                    .entry((sub_low, setting.to_ascii_lowercase()))
                    .or_insert((0, 0));
                if is_ac {
                    entry.0 = parsed_val;
                } else {
                    entry.1 = parsed_val;
                }
                Ok(CmdOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            } else {
                Ok(CmdOutput {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "Scheme not found".into(),
                })
            }
        }
        ["/q", guid] | ["/Q", guid] => {
            let g = resolve_scheme_guid(st, guid);
            let Some(scheme) = st.power_schemes.get(&g) else {
                return Ok(CmdOutput {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "Scheme not found".into(),
                });
            };
            let mut out = format!("Power Scheme GUID: {}  ({})\n", scheme.guid, scheme.name);
            for ((sub, setting), (ac, dc)) in &scheme.values {
                if st.locked_power_subgroups.contains(sub) {
                    continue;
                }
                out.push_str(&format!(
                    "  Subgroup GUID: 00000000-0000-0000-0000-000000000000  ({sub})\n    GUID Alias: {}\n    Power Setting GUID: 11111111-1111-1111-1111-111111111111  ({setting})\n      GUID Alias: {}\n    Current AC Power Setting Index: 0x{ac:08x}\n    Current DC Power Setting Index: 0x{dc:08x}\n",
                    sub.to_ascii_uppercase(),
                    setting.to_ascii_uppercase()
                ));
            }
            Ok(CmdOutput {
                exit_code: 0,
                stdout: out,
                stderr: String::new(),
            })
        }
        _ => Ok(CmdOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        }),
    }
}

fn resolve_scheme_guid(st: &FakeState, guid: &str) -> String {
    if guid.eq_ignore_ascii_case("SCHEME_CURRENT") {
        st.active_scheme.clone()
    } else if guid.eq_ignore_ascii_case("SCHEME_MIN") {
        "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c".into()
    } else {
        guid.to_ascii_lowercase()
    }
}

fn handle_fake_secedit(st: &mut FakeState, args: &[&str]) -> Result<CmdOutput> {
    if !st.admin {
        return Ok(CmdOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "Access is denied".into(),
        });
    }
    if args.first().copied() == Some("/export") {
        let cfg_idx = args.iter().position(|&a| a == "/cfg").unwrap();
        let path = FakeSystemOps::norm_file(Path::new(args[cfg_idx + 1]));
        let mut ini = String::from("[Unicode]\r\nUnicode=yes\r\n[System Access]\r\n");
        for (k, v) in &st.system_access {
            ini.push_str(&format!("{k} = {v}\r\n"));
        }
        let bytes = encode_utf16le_bom(&ini);
        st.files.insert(path, bytes);
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: "The task has completed successfully.".into(),
            stderr: String::new(),
        });
    }
    if args.first().copied() == Some("/configure") {
        let cfg_idx = args.iter().position(|&a| a == "/cfg").unwrap();
        let path = FakeSystemOps::norm_file(Path::new(args[cfg_idx + 1]));
        let Some(bytes) = st.files.get(&path) else {
            return Ok(CmdOutput {
                exit_code: 1,
                stdout: String::new(),
                stderr: "INF not found".into(),
            });
        };
        let text = decode_utf16_or_utf8(bytes);
        let mut in_sys = false;
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                in_sys = t.eq_ignore_ascii_case("[System Access]");
                continue;
            }
            if in_sys && let Some((k, v)) = t.split_once('=') {
                st.system_access
                    .insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: "The task has completed successfully.".into(),
            stderr: String::new(),
        });
    }
    Ok(CmdOutput {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
    })
}

fn handle_fake_netsh(st: &mut FakeState, args: &[&str]) -> Result<CmdOutput> {
    if args == ["advfirewall", "show", "allprofiles", "state"] {
        let mut out = String::new();
        for (prof, label) in [
            ("domain", "Domain Profile Settings"),
            ("private", "Private Profile Settings"),
            ("public", "Public Profile Settings"),
        ] {
            let state = if *st.firewall_profiles.get(prof).unwrap_or(&false) {
                "ON"
            } else {
                "OFF"
            };
            out.push_str(&format!(
                "{label}:\nState                                 {state}\n\n"
            ));
        }
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: out,
            stderr: String::new(),
        });
    }
    if !st.admin {
        return Ok(CmdOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "The requested operation requires elevation".into(),
        });
    }
    if args.len() == 5 && args[0] == "advfirewall" && args[1] == "set" && args[3] == "state" {
        let prof = args[2].trim_end_matches("profile").to_ascii_lowercase();
        let on = args[4].eq_ignore_ascii_case("on");
        st.firewall_profiles.insert(prof, on);
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: "Ok.".into(),
            stderr: String::new(),
        });
    }
    if args.starts_with(&["advfirewall", "firewall", "show", "rule"]) {
        let name_arg = args
            .iter()
            .find_map(|a| a.strip_prefix("name="))
            .unwrap_or("");
        let matching: Vec<&FakeFirewallRule> = st
            .firewall_rules
            .iter()
            .filter(|r| name_arg == "all" || r.name == name_arg)
            .collect();
        if matching.is_empty() {
            return Ok(CmdOutput {
                exit_code: 1,
                stdout: "No rules match the specified criteria.".into(),
                stderr: String::new(),
            });
        }
        let mut out = String::new();
        for r in matching {
            out.push_str(&format!(
                "Rule Name: {}\nEnabled: Yes\nDirection: {}\nProfiles: {}\nAction: {}\nProtocol: {}\n\n",
                r.name, r.dir, r.profile, r.action, r.protocol
            ));
        }
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: out,
            stderr: String::new(),
        });
    }
    if args.starts_with(&["advfirewall", "firewall", "add", "rule"]) {
        let mut rule = FakeFirewallRule {
            name: String::new(),
            dir: "In".into(),
            action: "Allow".into(),
            protocol: String::new(),
            profile: "domain,private".into(),
        };
        for a in args {
            if let Some(v) = a.strip_prefix("name=") {
                rule.name = v.to_string();
            } else if let Some(v) = a.strip_prefix("dir=") {
                rule.dir = v.to_string();
            } else if let Some(v) = a.strip_prefix("action=") {
                rule.action = v.to_string();
            } else if let Some(v) = a.strip_prefix("protocol=") {
                rule.protocol = v.to_string();
            } else if let Some(v) = a.strip_prefix("profile=") {
                rule.profile = v.to_string();
            }
        }
        st.firewall_rules.push(rule);
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: "Ok.".into(),
            stderr: String::new(),
        });
    }
    if args.starts_with(&["advfirewall", "firewall", "delete", "rule"]) {
        let name_arg = args
            .iter()
            .find_map(|a| a.strip_prefix("name="))
            .unwrap_or("");
        st.firewall_rules.retain(|r| r.name != name_arg);
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: "Ok.".into(),
            stderr: String::new(),
        });
    }
    Ok(CmdOutput {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
    })
}

fn handle_fake_vssadmin(st: &mut FakeState, args: &[&str]) -> Result<CmdOutput> {
    if !st.admin {
        return Ok(CmdOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "Error: You don't have the correct permissions to run this command.".into(),
        });
    }
    if args == ["list", "shadowstorage"] {
        if let Some(max) = &st.shadow_max_size {
            return Ok(CmdOutput {
                exit_code: 0,
                stdout: format!(
                    "Shadow Copy Storage association\n   For volume: (C:)\\\\?\\Volume{{fake}}\\\n   Shadow Copy Storage volume: (C:)\\\\?\\Volume{{fake}}\\\n   Used Shadow Copy Storage space: 0 bytes (0%)\n   Allocated Shadow Copy Storage space: {} (0%)\n   Maximum Shadow Copy Storage space: {max}\n",
                    st.shadow_allocated
                ),
                stderr: String::new(),
            });
        }
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: "No items found that satisfy the query.\n".into(),
            stderr: String::new(),
        });
    }
    if args.first().copied() == Some("resize") {
        let max = args
            .iter()
            .find_map(|a| a.strip_prefix("/maxsize="))
            .unwrap_or("5GB");
        st.shadow_max_size = Some(max.to_string());
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: "Successfully resized the shadow copy storage association.".into(),
            stderr: String::new(),
        });
    }
    Ok(CmdOutput {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
    })
}

fn handle_fake_powershell(st: &mut FakeState, args: &[&str]) -> Result<CmdOutput> {
    let joined = args.join(" ");
    if joined.contains("Enable-ComputerRestore") {
        if !st.admin {
            return Ok(CmdOutput {
                exit_code: 1,
                stdout: String::new(),
                stderr: "Access is denied".into(),
            });
        }
        st.restore_enabled = true;
        if st.shadow_max_size.is_none() {
            st.shadow_max_size = Some("UNBOUNDED".into());
        }
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        });
    }
    if joined.contains("Disable-ComputerRestore") {
        st.restore_enabled = false;
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        });
    }
    if joined.contains("Set-MpPreference") {
        if st.tamper_protected {
            return Ok(CmdOutput {
                exit_code: 1,
                stdout: String::new(),
                stderr: "Operation blocked by Tamper Protection".into(),
            });
        }
        return Ok(CmdOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        });
    }
    Ok(CmdOutput {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
    })
}

pub fn encode_utf16le_bom(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + text.len() * 2);
    out.push(0xFF);
    out.push(0xFE);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

pub fn decode_utf16_or_utf8(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_registry_tracks_absent_and_present_values() {
        let ops = FakeSystemOps::default();
        assert!(
            ops.reg_read(RegHive::Hkcu, "Software\\Test", "Flag")
                .unwrap()
                .is_none()
        );
        ops.reg_write(RegHive::Hkcu, "Software\\Test", "Flag", RegValue::Dword(0))
            .unwrap();
        assert_eq!(
            ops.reg_read(RegHive::Hkcu, "Software\\Test", "Flag")
                .unwrap(),
            Some(RegValue::Dword(0))
        );
        ops.reg_delete_value(RegHive::Hkcu, "Software\\Test", "Flag")
            .unwrap();
        assert!(
            ops.reg_read(RegHive::Hkcu, "Software\\Test", "Flag")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn fake_secedit_roundtrips_utf16_inf() {
        let ops = FakeSystemOps::default();
        let tmp = ops.temp_dir().join("sec.inf");
        let tmp_str = tmp.to_string_lossy().into_owned();
        let out = ops
            .run_tool(
                "secedit",
                &["/export", "/cfg", &tmp_str, "/areas", "SECURITYPOLICY"],
            )
            .unwrap();
        assert_eq!(out.exit_code, 0);
        let bytes = ops.read_file_opt(&tmp).unwrap().unwrap();
        let text = decode_utf16_or_utf8(&bytes);
        assert!(text.contains("LockoutBadCount = 0"));
    }
}
