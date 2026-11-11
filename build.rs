use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
    println!("cargo:rerun-if-env-changed=IT_TOOLS_DISPLAY_VERSION");
    println!("cargo:rerun-if-env-changed=IT_TOOLS_BUILD_NUMBER");
    println!("cargo:rerun-if-env-changed=IT_TOOLS_GITHUB_REPO");
    println!("cargo:rerun-if-env-changed=IT_TOOLS_COMPANY");
    println!("cargo:rerun-if-env-changed=IT_TOOLS_CHANNEL");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let pkg_ver = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".into());
    let display_ver = env::var("IT_TOOLS_DISPLAY_VERSION")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| pkg_ver.clone());
    let build_num: u16 = env::var("IT_TOOLS_BUILD_NUMBER")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let company = env::var("IT_TOOLS_COMPANY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "IT-Tools Open Source".into());
    let channel = env::var("IT_TOOLS_CHANNEL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            if display_ver.contains('-') {
                "beta".into()
            } else {
                "stable".into()
            }
        });
    let desc = env::var("CARGO_PKG_DESCRIPTION")
        .unwrap_or_else(|_| "Portable Windows 10/11 Hardening & Provisioning CLI/TUI".into());

    let (maj, min, pat) = parse_numeric_triplet(&pkg_ver);
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let rc_path = out_dir.join("it_tools_version.rc");
    let res_path = out_dir.join("it_tools_version.res");

    let rc = format!(
        r#"1 VERSIONINFO
FILEVERSION {maj},{min},{pat},{build_num}
PRODUCTVERSION {maj},{min},{pat},{build_num}
FILEFLAGSMASK 0x3fL
FILEFLAGS {file_flags}
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName", "{company}\0"
            VALUE "FileDescription", "{desc}\0"
            VALUE "FileVersion", "{maj}.{min}.{pat}.{build_num}\0"
            VALUE "InternalName", "it-tools\0"
            VALUE "LegalCopyright", "MIT License\0"
            VALUE "OriginalFilename", "it-tools.exe\0"
            VALUE "ProductName", "IT-Tools\0"
            VALUE "ProductVersion", "{display_ver}\0"
            VALUE "Comments", "Channel: {channel}\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
"#,
        company = escape_rc(&company),
        desc = escape_rc(&desc),
        display_ver = escape_rc(&display_ver),
        channel = escape_rc(&channel),
        file_flags = if channel == "beta" { "0x2L" } else { "0x0L" },
    );

    fs::write(&rc_path, rc).expect("failed to write version.rc");

    let rc_exe = find_rc_exe().unwrap_or_else(|| {
        panic!("Windows SDK rc.exe not found in PATH or Windows Kits\\10\\bin");
    });

    let status = Command::new(&rc_exe)
        .args(["/nologo", "/fo"])
        .arg(&res_path)
        .arg(&rc_path)
        .status()
        .expect("failed to execute rc.exe");
    assert!(status.success(), "rc.exe exited with {status}");

    println!("cargo:rustc-link-arg-bins={}", res_path.display());
}

fn parse_numeric_triplet(v: &str) -> (u16, u16, u16) {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let mut parts = core.split('.');
    let maj = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let min = parts.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    let pat = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (maj, min, pat)
}

fn escape_rc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\"\"")
}

fn find_rc_exe() -> Option<PathBuf> {
    if Command::new("rc.exe").arg("/?").output().is_ok() {
        return Some(PathBuf::from("rc.exe"));
    }
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86") => "x86",
        _ => "x64",
    };
    let mut candidates = Vec::new();
    for env_key in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(pf) = env::var_os(env_key) {
            let kit_bin = Path::new(&pf).join("Windows Kits").join("10").join("bin");
            if let Ok(entries) = fs::read_dir(&kit_bin) {
                for entry in entries.flatten() {
                    let candidate = entry.path().join(arch).join("rc.exe");
                    if candidate.is_file() {
                        candidates.push(candidate);
                    }
                }
            }
        }
    }
    candidates.sort();
    candidates.pop()
}
