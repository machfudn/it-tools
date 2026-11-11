pub mod fake;
pub mod win32;

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegHive {
    Hkcu,
    Hklm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RegValue {
    Dword(u32),
    Sz(String),
    ExpandSz(String),
    BinaryHex(String),
}

impl RegValue {
    pub fn binary(bytes: &[u8]) -> Self {
        Self::BinaryHex(encode_hex(bytes))
    }

    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::BinaryHex(hex) => decode_hex(hex).ok(),
            _ => None,
        }
    }

    pub fn as_dword(&self) -> Option<u32> {
        match self {
            Self::Dword(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Sz(s) | Self::ExpandSz(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalUserInfo {
    pub name: String,
    pub disabled: bool,
    pub dont_expire_password: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub trait SystemOps {
    fn reg_read(&self, hive: RegHive, path: &str, name: &str) -> Result<Option<RegValue>>;
    fn reg_write(&self, hive: RegHive, path: &str, name: &str, value: RegValue) -> Result<()>;
    fn reg_delete_value(&self, hive: RegHive, path: &str, name: &str) -> Result<()>;
    fn reg_list_values(&self, hive: RegHive, path: &str) -> Result<Vec<(String, RegValue)>>;
    fn reg_list_subkeys(&self, hive: RegHive, path: &str) -> Result<Vec<String>>;

    fn local_appdata_dir(&self) -> Option<PathBuf>;
    fn startup_folders(&self) -> Vec<(String, PathBuf)>;
    fn read_file_opt(&self, path: &Path) -> Result<Option<Vec<u8>>>;
    fn write_file(&self, path: &Path, bytes: &[u8]) -> Result<()>;
    fn remove_file_opt(&self, path: &Path) -> Result<()>;
    fn temp_dir(&self) -> PathBuf;
    fn is_process_running(&self, exe_name: &str) -> bool;

    fn is_admin(&self) -> bool;
    fn is_console_tty(&self) -> bool;
    fn current_username(&self) -> String;
    fn os_caption(&self) -> String;
    fn local_timestamp_compact(&self) -> String;
    fn local_timestamp_iso(&self) -> String;
    fn relaunch_as_admin(&self, args: &[String]) -> Result<()>;

    fn list_local_users(&self) -> Result<Vec<LocalUserInfo>>;
    fn create_local_user(&self, name: &str, password: &str) -> Result<()>;
    fn set_user_dont_expire(&self, name: &str, dont_expire: bool) -> Result<()>;
    fn set_user_password(&self, name: &str, password: &str) -> Result<()>;

    fn http_get(&self, url: &str, accept: Option<&str>) -> Result<Vec<u8>>;
    fn current_exe_path(&self) -> Result<PathBuf>;
    fn rename_file(&self, from: &Path, to: &Path) -> Result<()>;
    fn run_tool(&self, program: &str, args: &[&str]) -> Result<CmdOutput>;
    fn broadcast_setting_change(&self) -> Result<()>;
    fn restart_explorer(&self) -> Result<()>;
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        anyhow::bail!("odd hex string length");
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let hi = from_hex_nibble(pair[0])?;
        let lo = from_hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn from_hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => anyhow::bail!("invalid hex byte '{c}'"),
    }
}
