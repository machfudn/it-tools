use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr::{null, null_mut};

use anyhow::{Context, Result, bail};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, RegType};
use winreg::types::{FromRegValue, ToRegValue};
use winreg::{RegKey, RegValue as WinRegValue};

use windows_sys::Win32::Foundation::{
    CloseHandle, HWND, INVALID_HANDLE_VALUE, LPARAM, SYSTEMTIME, WPARAM,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    FILTER_NORMAL_ACCOUNT, MAX_PREFERRED_LENGTH, NERR_Success, NetApiBufferFree, NetUserAdd,
    NetUserEnum, NetUserSetInfo, UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1,
    USER_INFO_1003, USER_INFO_1008,
};
use windows_sys::Win32::Networking::WinHttp::{
    URL_COMPONENTS, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE,
    WINHTTP_INTERNET_SCHEME_HTTPS, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
    WinHttpCloseHandle, WinHttpConnect, WinHttpCrackUrl, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryDataAvailable, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetOption,
};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, CheckTokenMembership, FreeSid, PSID, SID_IDENTIFIER_AUTHORITY,
};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SW_SHOWNORMAL, SendMessageTimeoutW, WM_SETTINGCHANGE,
};

use crate::platform::{CmdOutput, LocalUserInfo, RegHive, RegValue, SystemOps};

#[derive(Debug, Default, Clone, Copy)]
pub struct Win32SystemOps;

impl Win32SystemOps {
    fn predef(hive: RegHive) -> RegKey {
        match hive {
            RegHive::Hkcu => RegKey::predef(HKEY_CURRENT_USER),
            RegHive::Hklm => RegKey::predef(HKEY_LOCAL_MACHINE),
        }
    }

    fn from_winreg(raw: &WinRegValue) -> Option<RegValue> {
        match raw.vtype {
            RegType::REG_DWORD => u32::from_reg_value(raw).ok().map(RegValue::Dword),
            RegType::REG_SZ => String::from_reg_value(raw).ok().map(RegValue::Sz),
            RegType::REG_EXPAND_SZ => String::from_reg_value(raw).ok().map(RegValue::ExpandSz),
            RegType::REG_BINARY => Some(RegValue::binary(&raw.bytes)),
            _ => None,
        }
    }

    fn local_time_parts() -> SYSTEMTIME {
        let mut st = unsafe { std::mem::zeroed::<SYSTEMTIME>() };
        unsafe { GetLocalTime(&mut st) };
        st
    }
}

impl SystemOps for Win32SystemOps {
    fn reg_read(&self, hive: RegHive, path: &str, name: &str) -> Result<Option<RegValue>> {
        let root = Self::predef(hive);
        let key = match root.open_subkey_with_flags(path, KEY_READ) {
            Ok(k) => k,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("open reg {:?}\\{path}", hive)),
        };
        match key.get_raw_value(name) {
            Ok(raw) => Ok(Self::from_winreg(&raw)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read reg {:?}\\{path}\\{name}", hive)),
        }
    }

    fn reg_write(&self, hive: RegHive, path: &str, name: &str, value: RegValue) -> Result<()> {
        let root = Self::predef(hive);
        let (key, _) = root
            .create_subkey_with_flags(path, KEY_READ | KEY_WRITE)
            .with_context(|| format!("create/open reg {:?}\\{path}", hive))?;
        match value {
            RegValue::Dword(v) => key.set_value(name, &v)?,
            RegValue::Sz(s) => key.set_value(name, &s)?,
            RegValue::ExpandSz(s) => {
                let mut raw = s.to_reg_value();
                raw.vtype = RegType::REG_EXPAND_SZ;
                key.set_raw_value(name, &raw)?;
            }
            RegValue::BinaryHex(_) => {
                let bytes = value.as_bytes().unwrap_or_default();
                let raw = WinRegValue {
                    bytes: bytes.into(),
                    vtype: RegType::REG_BINARY,
                };
                key.set_raw_value(name, &raw)?;
            }
        }
        Ok(())
    }

    fn reg_delete_value(&self, hive: RegHive, path: &str, name: &str) -> Result<()> {
        let root = Self::predef(hive);
        let key = match root.open_subkey_with_flags(path, KEY_WRITE) {
            Ok(k) => k,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("open reg {:?}\\{path}", hive)),
        };
        match key.delete_value(name) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("delete reg {:?}\\{path}\\{name}", hive)),
        }
    }

    fn reg_list_values(&self, hive: RegHive, path: &str) -> Result<Vec<(String, RegValue)>> {
        let root = Self::predef(hive);
        let key = match root.open_subkey_with_flags(path, KEY_READ) {
            Ok(k) => k,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("list reg {:?}\\{path}", hive)),
        };
        let mut out = Vec::new();
        for item in key.enum_values() {
            if let Ok((name, raw)) = item
                && let Some(val) = Self::from_winreg(&raw)
            {
                out.push((name, val));
            }
        }
        Ok(out)
    }

    fn reg_list_subkeys(&self, hive: RegHive, path: &str) -> Result<Vec<String>> {
        let root = Self::predef(hive);
        let key = match root.open_subkey_with_flags(path, KEY_READ) {
            Ok(k) => k,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("list subkeys {:?}\\{path}", hive)),
        };
        Ok(key.enum_keys().filter_map(|k| k.ok()).collect())
    }

    fn local_appdata_dir(&self) -> Option<PathBuf> {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    }

    fn startup_folders(&self) -> Vec<(String, PathBuf)> {
        let mut dirs = Vec::new();
        if let Some(appdata) = std::env::var_os("APPDATA") {
            dirs.push((
                "user".into(),
                PathBuf::from(appdata)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Startup"),
            ));
        }
        if let Some(pd) = std::env::var_os("ProgramData") {
            dirs.push((
                "common".into(),
                PathBuf::from(pd)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Startup"),
            ));
        }
        dirs
    }

    fn read_file_opt(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        match fs::read(path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read file {}", path.display())),
        }
    }

    fn write_file(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes).with_context(|| format!("write file {}", path.display()))
    }

    fn remove_file_opt(&self, path: &Path) -> Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("remove file {}", path.display())),
        }
    }

    fn http_get(&self, url: &str, accept: Option<&str>) -> Result<Vec<u8>> {
        winhttp_get(url, accept)
    }

    fn current_exe_path(&self) -> Result<PathBuf> {
        std::env::current_exe().context("resolve current executable path")
    }

    fn rename_file(&self, from: &Path, to: &Path) -> Result<()> {
        if let Some(parent) = to.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::rename(from, to)
            .with_context(|| format!("rename {} -> {}", from.display(), to.display()))
    }
    fn temp_dir(&self) -> PathBuf {
        std::env::temp_dir()
    }

    fn is_process_running(&self, exe_name: &str) -> bool {
        let target = exe_name.to_ascii_lowercase();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return false;
            }
            let mut pe = std::mem::zeroed::<PROCESSENTRY32W>();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut found = false;
            if Process32FirstW(snap, &mut pe) != 0 {
                loop {
                    let end = pe
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(pe.szExeFile.len());
                    let name = String::from_utf16_lossy(&pe.szExeFile[..end]).to_ascii_lowercase();
                    if name == target {
                        found = true;
                        break;
                    }
                    if Process32NextW(snap, &mut pe) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            found
        }
    }

    fn is_admin(&self) -> bool {
        unsafe {
            let nt_authority = SID_IDENTIFIER_AUTHORITY {
                Value: [0, 0, 0, 0, 0, 5],
            };
            let mut admin_sid: PSID = null_mut();
            let ok = AllocateAndInitializeSid(
                &nt_authority,
                2,
                32,  // SECURITY_BUILTIN_DOMAIN_RID
                544, // DOMAIN_ALIAS_RID_ADMINS
                0,
                0,
                0,
                0,
                0,
                0,
                &mut admin_sid,
            );
            if ok == 0 {
                return false;
            }
            let mut member: i32 = 0;
            let checked = CheckTokenMembership(null_mut(), admin_sid, &mut member);
            FreeSid(admin_sid);
            checked != 0 && member != 0
        }
    }

    fn is_console_tty(&self) -> bool {
        unsafe {
            let mut mode_in: u32 = 0;
            let mut mode_out: u32 = 0;
            let hin = GetStdHandle(STD_INPUT_HANDLE);
            let hout = GetStdHandle(STD_OUTPUT_HANDLE);
            GetConsoleMode(hin, &mut mode_in) != 0 && GetConsoleMode(hout, &mut mode_out) != 0
        }
    }

    fn current_username(&self) -> String {
        std::env::var("USERNAME").unwrap_or_else(|_| "CurrentUser".into())
    }

    fn os_caption(&self) -> String {
        let product = self
            .reg_read(
                RegHive::Hklm,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "ProductName",
            )
            .ok()
            .flatten()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "Windows".into());
        let display_ver = self
            .reg_read(
                RegHive::Hklm,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "DisplayVersion",
            )
            .ok()
            .flatten()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let build = self
            .reg_read(
                RegHive::Hklm,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "CurrentBuildNumber",
            )
            .ok()
            .flatten()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        format_windows_caption(&product, &display_ver, &build)
    }

    fn local_timestamp_compact(&self) -> String {
        let st = Self::local_time_parts();
        format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        )
    }

    fn local_timestamp_iso(&self) -> String {
        let st = Self::local_time_parts();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        )
    }

    fn relaunch_as_admin(&self, args: &[String]) -> Result<()> {
        let exe = std::env::current_exe()?;
        let exe_w = to_wide_null(exe.as_os_str());
        let params = join_windows_args(args);
        let params_w = to_wide_null(params.as_str());
        let verb_w = to_wide_null("runas");
        let dir_w = exe
            .parent()
            .map(|p| to_wide_null(p.as_os_str()))
            .unwrap_or_else(|| to_wide_null(""));

        let hinst = unsafe {
            ShellExecuteW(
                null_mut() as HWND,
                verb_w.as_ptr(),
                exe_w.as_ptr(),
                if params.is_empty() {
                    null()
                } else {
                    params_w.as_ptr()
                },
                dir_w.as_ptr(),
                SW_SHOWNORMAL,
            )
        };
        if (hinst as usize) <= 32 {
            bail!(
                "UAC elevation cancelled or failed (ShellExecuteW code {})",
                hinst as usize
            );
        }
        Ok(())
    }

    fn list_local_users(&self) -> Result<Vec<LocalUserInfo>> {
        let mut users = Vec::new();
        let mut resume_handle: u32 = 0;
        loop {
            let mut buf_ptr: *mut u8 = null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;
            let status = unsafe {
                NetUserEnum(
                    null(),
                    1,
                    FILTER_NORMAL_ACCOUNT,
                    &mut buf_ptr,
                    MAX_PREFERRED_LENGTH,
                    &mut entries_read,
                    &mut total_entries,
                    &mut resume_handle,
                )
            };
            if !buf_ptr.is_null() {
                if status == NERR_Success || status == 234 {
                    let slice = unsafe {
                        std::slice::from_raw_parts(
                            buf_ptr as *const USER_INFO_1,
                            entries_read as usize,
                        )
                    };
                    for item in slice {
                        let name = unsafe { pwstr_to_string(item.usri1_name) };
                        users.push(LocalUserInfo {
                            name,
                            disabled: (item.usri1_flags & UF_ACCOUNTDISABLE) != 0,
                            dont_expire_password: (item.usri1_flags & UF_DONT_EXPIRE_PASSWD) != 0,
                        });
                    }
                }
                unsafe { NetApiBufferFree(buf_ptr as *const _) };
            }
            if status == NERR_Success {
                break;
            }
            if status != 234 {
                bail!("NetUserEnum failed with Win32 status {status}");
            }
        }
        Ok(users)
    }

    fn create_local_user(&self, name: &str, password: &str) -> Result<()> {
        let mut name_w = to_wide_null(name);
        let mut pass_w = to_wide_null(password);
        let info = USER_INFO_1 {
            usri1_name: name_w.as_mut_ptr(),
            usri1_password: pass_w.as_mut_ptr(),
            usri1_password_age: 0,
            usri1_priv: 1, // USER_PRIV_USER
            usri1_home_dir: null_mut(),
            usri1_comment: null_mut(),
            usri1_flags: UF_SCRIPT,
            usri1_script_path: null_mut(),
        };
        let mut parm_err: u32 = 0;
        let status =
            unsafe { NetUserAdd(null(), 1, &info as *const _ as *const u8, &mut parm_err) };
        if status != NERR_Success {
            bail!("NetUserAdd failed for '{name}' (status {status}, param {parm_err})");
        }
        Ok(())
    }

    fn set_user_dont_expire(&self, name: &str, dont_expire: bool) -> Result<()> {
        let users = self.list_local_users()?;
        let current = users
            .into_iter()
            .find(|u| u.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| anyhow::anyhow!("local user '{name}' not found"))?;
        let mut flags = UF_SCRIPT;
        if current.disabled {
            flags |= UF_ACCOUNTDISABLE;
        }
        if dont_expire {
            flags |= UF_DONT_EXPIRE_PASSWD;
        }
        let name_w = to_wide_null(name);
        let info = USER_INFO_1008 {
            usri1008_flags: flags,
        };
        let mut parm_err: u32 = 0;
        let status = unsafe {
            NetUserSetInfo(
                null(),
                name_w.as_ptr(),
                1008,
                &info as *const _ as *const u8,
                &mut parm_err,
            )
        };
        if status != NERR_Success {
            bail!("NetUserSetInfo(1008) failed for '{name}' (status {status})");
        }
        Ok(())
    }

    fn set_user_password(&self, name: &str, password: &str) -> Result<()> {
        let name_w = to_wide_null(name);
        let mut pass_w = to_wide_null(password);
        let info = USER_INFO_1003 {
            usri1003_password: pass_w.as_mut_ptr(),
        };
        let mut parm_err: u32 = 0;
        let status = unsafe {
            NetUserSetInfo(
                null(),
                name_w.as_ptr(),
                1003,
                &info as *const _ as *const u8,
                &mut parm_err,
            )
        };
        if status != NERR_Success {
            bail!("NetUserSetInfo(1003) failed for '{name}' (status {status})");
        }
        Ok(())
    }

    fn run_tool(&self, program: &str, args: &[&str]) -> Result<CmdOutput> {
        let output = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("failed to execute {program}"))?;
        Ok(CmdOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn broadcast_setting_change(&self) -> Result<()> {
        let area = to_wide_null("Environment");
        let mut result: usize = 0;
        unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0 as WPARAM,
                area.as_ptr() as LPARAM,
                SMTO_ABORTIFHUNG,
                500,
                &mut result,
            );
            let policy = to_wide_null("Policy");
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0 as WPARAM,
                policy.as_ptr() as LPARAM,
                SMTO_ABORTIFHUNG,
                500,
                &mut result,
            );
        }
        Ok(())
    }

    fn restart_explorer(&self) -> Result<()> {
        let _ = self.run_tool("taskkill.exe", &["/F", "/IM", "explorer.exe"]);
        let _ = Command::new("explorer.exe").spawn();
        Ok(())
    }
}

pub fn format_windows_caption(product: &str, display_ver: &str, build: &str) -> String {
    let build_num: u32 = build.trim().parse().unwrap_or(0);
    let normalized = if build_num >= 22000 && product.contains("Windows 10") {
        product.replace("Windows 10", "Windows 11")
    } else {
        product.to_string()
    };
    let mut parts = vec![normalized];
    if !display_ver.trim().is_empty() {
        parts.push(display_ver.trim().to_string());
    }
    if !build.trim().is_empty() {
        parts.push(format!("(Build {})", build.trim()));
    }
    parts.join(" ")
}

struct WinHttpHandle(*mut core::ffi::c_void);

impl Drop for WinHttpHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                WinHttpCloseHandle(self.0);
            }
        }
    }
}

fn winhttp_get(url: &str, accept: Option<&str>) -> Result<Vec<u8>> {
    const MAX_DOWNLOAD_BYTES: usize = 128 * 1024 * 1024;
    let wide_url = to_wide_null(url);
    let mut host_buf = [0u16; 256];
    let mut path_buf = [0u16; 2048];
    let mut extra_buf = [0u16; 1024];
    let mut comps = URL_COMPONENTS {
        dwStructSize: std::mem::size_of::<URL_COMPONENTS>() as u32,
        lpszHostName: host_buf.as_mut_ptr(),
        dwHostNameLength: host_buf.len() as u32,
        lpszUrlPath: path_buf.as_mut_ptr(),
        dwUrlPathLength: path_buf.len() as u32,
        lpszExtraInfo: extra_buf.as_mut_ptr(),
        dwExtraInfoLength: extra_buf.len() as u32,
        ..Default::default()
    };
    unsafe {
        if WinHttpCrackUrl(
            wide_url.as_ptr(),
            (wide_url.len() - 1) as u32,
            0,
            &mut comps,
        ) == 0
        {
            bail!("invalid URL `{url}`: {}", std::io::Error::last_os_error());
        }
    }
    let host = String::from_utf16_lossy(&host_buf[..comps.dwHostNameLength as usize]);
    let mut object_name = String::from_utf16_lossy(&path_buf[..comps.dwUrlPathLength as usize]);
    if comps.dwExtraInfoLength > 0 {
        object_name.push_str(&String::from_utf16_lossy(
            &extra_buf[..comps.dwExtraInfoLength as usize],
        ));
    }
    if object_name.is_empty() {
        object_name.push('/');
    }

    let ua = to_wide_null(format!("it-tools/{}", env!("CARGO_PKG_VERSION")));
    let session = WinHttpHandle(unsafe {
        WinHttpOpen(
            ua.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            null(),
            null(),
            0,
        )
    });
    if session.0.is_null() {
        bail!("WinHttpOpen failed: {}", std::io::Error::last_os_error());
    }

    let host_w = to_wide_null(&host);
    let connect =
        WinHttpHandle(unsafe { WinHttpConnect(session.0, host_w.as_ptr(), comps.nPort, 0) });
    if connect.0.is_null() {
        bail!(
            "WinHttpConnect({host}) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let verb = to_wide_null("GET");
    let obj_w = to_wide_null(&object_name);
    let flags = if comps.nScheme == WINHTTP_INTERNET_SCHEME_HTTPS {
        WINHTTP_FLAG_SECURE
    } else {
        0
    };
    let request = WinHttpHandle(unsafe {
        WinHttpOpenRequest(
            connect.0,
            verb.as_ptr(),
            obj_w.as_ptr(),
            null(),
            null(),
            null(),
            flags,
        )
    });
    if request.0.is_null() {
        bail!(
            "WinHttpOpenRequest failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    unsafe {
        WinHttpSetOption(
            request.0,
            WINHTTP_OPTION_REDIRECT_POLICY,
            (&redirect_policy as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
        );
    }

    let headers_w = accept.map(|a| to_wide_null(format!("Accept: {a}\r\n")));
    let (hdr_ptr, hdr_len) = match &headers_w {
        Some(h) => (h.as_ptr(), (h.len() - 1) as u32),
        None => (null(), 0),
    };
    unsafe {
        if WinHttpSendRequest(request.0, hdr_ptr, hdr_len, null(), 0, 0, 0) == 0 {
            bail!(
                "WinHttpSendRequest({url}) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        if WinHttpReceiveResponse(request.0, null_mut()) == 0 {
            bail!(
                "WinHttpReceiveResponse({url}) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    let mut status: u32 = 0;
    let mut status_len = std::mem::size_of::<u32>() as u32;
    unsafe {
        if WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&mut status as *mut u32).cast(),
            &mut status_len,
            null_mut(),
        ) == 0
        {
            bail!(
                "WinHttpQueryHeaders failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    if !(200..300).contains(&status) {
        if status == 404 {
            bail!("HTTP 404 Not Found from {url}");
        }
        if status == 403 || status == 429 {
            bail!("HTTP {status} (rate limited or forbidden) from {url}");
        }
        bail!("HTTP {status} from {url}");
    }

    let mut body = Vec::new();
    loop {
        let mut avail: u32 = 0;
        unsafe {
            if WinHttpQueryDataAvailable(request.0, &mut avail) == 0 {
                bail!(
                    "WinHttpQueryDataAvailable failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        if avail == 0 {
            break;
        }
        if body.len().saturating_add(avail as usize) > MAX_DOWNLOAD_BYTES {
            bail!("download exceeded {MAX_DOWNLOAD_BYTES} bytes limit");
        }
        let mut chunk = vec![0u8; avail as usize];
        let mut read: u32 = 0;
        unsafe {
            if WinHttpReadData(request.0, chunk.as_mut_ptr().cast(), avail, &mut read) == 0 {
                bail!(
                    "WinHttpReadData failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        body.extend_from_slice(&chunk[..read as usize]);
    }
    Ok(body)
}

fn to_wide_null<S: AsRef<std::ffi::OsStr>>(s: S) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

unsafe fn pwstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}

fn join_windows_args(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.is_empty() || a.contains([' ', '\t', '"']) {
                format!("\"{}\"", a.replace('"', "\\\""))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_11_build_normalizes_product_name() {
        assert_eq!(
            format_windows_caption("Windows 10 Pro", "25H2", "26200"),
            "Windows 11 Pro 25H2 (Build 26200)"
        );
        assert_eq!(
            format_windows_caption("Windows 10 Home", "22H2", "19045"),
            "Windows 10 Home 22H2 (Build 19045)"
        );
    }
}
