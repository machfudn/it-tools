use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::platform::SystemOps;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    Stable,
    Beta,
}

impl std::fmt::Display for UpdateChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stable => f.write_str("stable"),
            Self::Beta => f.write_str("beta"),
        }
    }
}

pub fn current_display_version() -> &'static str {
    option_env!("IT_TOOLS_DISPLAY_VERSION")
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(env!("CARGO_PKG_VERSION"))
}

pub fn current_channel() -> UpdateChannel {
    let ch = option_env!("IT_TOOLS_CHANNEL").unwrap_or("");
    if ch.eq_ignore_ascii_case("beta") || current_display_version().contains('-') {
        UpdateChannel::Beta
    } else {
        UpdateChannel::Stable
    }
}

pub fn default_github_repo() -> Option<&'static str> {
    option_env!("IT_TOOLS_GITHUB_REPO").filter(|s| !s.trim().is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<String>,
}

impl SemVer {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim().trim_start_matches(['v', 'V']);
        let no_build = trimmed.split('+').next().unwrap_or(trimmed);
        let (core, pre) = match no_build.split_once('-') {
            Some((c, p)) if !p.is_empty() => (c, Some(p.to_string())),
            Some((c, _)) => (c, None),
            None => (no_build, None),
        };
        let mut parts = core.split('.');
        let major: u64 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("invalid semver `{raw}`"))?;
        let minor: u64 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("invalid semver `{raw}`"))?;
        let patch: u64 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("invalid semver `{raw}`"))?;
        if parts.next().is_some() {
            bail!("invalid semver `{raw}`");
        }
        Ok(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => compare_prerelease(a, b),
            })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_prerelease(a: &str, b: &str) -> Ordering {
    let mut pa = a.split('.');
    let mut pb = b.split('.');
    loop {
        match (pa.next(), pb.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(sa), Some(sb)) => {
                let ord = match (sa.parse::<u64>(), sb.parse::<u64>()) {
                    (Ok(na), Ok(nb)) => na.cmp(&nb),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => sa.cmp(sb),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    published_at: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    pub current_version: String,
    pub latest_version: String,
    pub channel: UpdateChannel,
    pub update_available: bool,
    pub prerelease: bool,
    pub published_at: String,
    pub html_url: String,
    pub release_notes: String,
    pub asset_name: Option<String>,
    pub asset_url: Option<String>,
    pub sha256sums_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateApplyResult {
    pub previous_version: String,
    pub new_version: String,
    pub exe_path: String,
    pub backup_path: String,
    pub sha256: String,
    pub sha256_verified: bool,
}

pub fn check_for_update(
    ops: &dyn SystemOps,
    repo: &str,
    channel: UpdateChannel,
) -> Result<UpdateCheckResult> {
    let repo = validate_repo_slug(repo)?;
    let current_ver_str = current_display_version().to_string();
    let current_sv = SemVer::parse(&current_ver_str)?;

    let release = match channel {
        UpdateChannel::Stable => {
            let url = format!("https://api.github.com/repos/{repo}/releases/latest");
            let raw = ops
                .http_get(&url, Some("application/vnd.github+json"))
                .with_context(|| format!("fetch latest stable release for `{repo}`"))?;
            serde_json::from_slice::<GitHubRelease>(&raw)
                .context("parse GitHub latest release JSON")?
        }
        UpdateChannel::Beta => {
            let url = format!("https://api.github.com/repos/{repo}/releases?per_page=20");
            let raw = ops
                .http_get(&url, Some("application/vnd.github+json"))
                .with_context(|| format!("fetch releases list for `{repo}`"))?;
            let list = serde_json::from_slice::<Vec<GitHubRelease>>(&raw)
                .context("parse GitHub releases list JSON")?;
            select_newest_release(list)?
        }
    };

    let latest_sv = SemVer::parse(&release.tag_name)?;
    let latest_ver_str = release
        .tag_name
        .trim()
        .trim_start_matches(['v', 'V'])
        .to_string();
    let update_available = latest_sv > current_sv;

    let exe_asset = find_exe_asset(&release.assets);
    let sha_asset = find_sha_asset(&release.assets);

    Ok(UpdateCheckResult {
        current_version: current_ver_str,
        latest_version: latest_ver_str,
        channel,
        update_available,
        prerelease: release.prerelease,
        published_at: release.published_at,
        html_url: release.html_url,
        release_notes: release.body,
        asset_name: exe_asset.as_ref().map(|a| a.name.clone()),
        asset_url: exe_asset.map(|a| a.browser_download_url.clone()),
        sha256sums_url: sha_asset.map(|a| a.browser_download_url.clone()),
    })
}

pub fn perform_update(ops: &dyn SystemOps, check: &UpdateCheckResult) -> Result<UpdateApplyResult> {
    let asset_url = check.asset_url.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "release `{}` has no portable .exe asset",
            check.latest_version
        )
    })?;
    let asset_name = check.asset_name.as_deref().unwrap_or("it-tools.exe");

    let new_bytes = ops
        .http_get(asset_url, Some("application/octet-stream"))
        .with_context(|| format!("download `{asset_name}`"))?;
    if new_bytes.len() < 64 || !new_bytes.starts_with(b"MZ") {
        bail!("downloaded file `{asset_name}` is not a valid Windows executable");
    }

    let actual_sha = sha256_hex(&new_bytes);
    let mut sha256_verified = false;
    if let Some(sums_url) = &check.sha256sums_url {
        let sums_bytes = ops
            .http_get(sums_url, Some("text/plain"))
            .context("download SHA256SUMS.txt")?;
        let sums_text = String::from_utf8_lossy(&sums_bytes);
        let expected = parse_sha256_for_asset(&sums_text, asset_name).ok_or_else(|| {
            anyhow::anyhow!("SHA256SUMS.txt missing checksum entry for `{asset_name}`")
        })?;
        if !expected.eq_ignore_ascii_case(&actual_sha) {
            bail!(
                "SHA-256 verification failed for `{asset_name}`: expected {expected}, got {actual_sha}"
            );
        }
        sha256_verified = true;
    }

    let exe_path = ops.current_exe_path()?;
    let old_path = backup_exe_path(&exe_path);
    ops.remove_file_opt(&old_path)?;
    ops.rename_file(&exe_path, &old_path)?;

    if let Err(err) = ops.write_file(&exe_path, &new_bytes) {
        let _ = ops.rename_file(&old_path, &exe_path);
        return Err(err).context("write updated executable (rolled back to previous binary)");
    }

    Ok(UpdateApplyResult {
        previous_version: check.current_version.clone(),
        new_version: check.latest_version.clone(),
        exe_path: exe_path.to_string_lossy().into_owned(),
        backup_path: old_path.to_string_lossy().into_owned(),
        sha256: actual_sha,
        sha256_verified,
    })
}

pub fn cleanup_old_exe_backup(ops: &dyn SystemOps) {
    if let Ok(exe_path) = ops.current_exe_path() {
        let old_path = backup_exe_path(&exe_path);
        let _ = ops.remove_file_opt(&old_path);
    }
}

pub fn backup_exe_path(exe_path: &Path) -> PathBuf {
    let mut os = exe_path.as_os_str().to_os_string();
    os.push(".old");
    PathBuf::from(os)
}

fn validate_repo_slug(repo: &str) -> Result<&str> {
    let trimmed = repo.trim().trim_matches('/');
    let Some((owner, name)) = trimmed.split_once('/') else {
        bail!("invalid GitHub repository `{repo}`; expected `owner/repo`");
    };
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        bail!("invalid GitHub repository `{repo}`; expected `owner/repo`");
    }
    Ok(trimmed)
}

fn select_newest_release(releases: Vec<GitHubRelease>) -> Result<GitHubRelease> {
    releases
        .into_iter()
        .filter(|r| !r.draft)
        .filter_map(|r| SemVer::parse(&r.tag_name).ok().map(|sv| (sv, r)))
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, r)| r)
        .ok_or_else(|| anyhow::anyhow!("no published releases found on GitHub"))
}

fn find_exe_asset(assets: &[GitHubAsset]) -> Option<&GitHubAsset> {
    assets
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("it-tools.exe"))
        .or_else(|| {
            assets.iter().find(|a| {
                let low = a.name.to_ascii_lowercase();
                low.starts_with("it-tools") && low.ends_with(".exe")
            })
        })
}

fn find_sha_asset(assets: &[GitHubAsset]) -> Option<&GitHubAsset> {
    assets
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("SHA256SUMS.txt"))
        .or_else(|| {
            assets
                .iter()
                .find(|a| a.name.to_ascii_lowercase().ends_with(".sha256"))
        })
}

pub fn parse_sha256_for_asset(sums_text: &str, asset_name: &str) -> Option<String> {
    let mut bare_candidate = None;
    for raw_line in sums_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(hash) = parts.next() else { continue };
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        match parts.next() {
            Some(file) => {
                let clean = file.trim_start_matches('*');
                let base = clean.rsplit(['/', '\\']).next().unwrap_or(clean);
                if base.eq_ignore_ascii_case(asset_name) {
                    return Some(hash.to_ascii_lowercase());
                }
            }
            None => {
                bare_candidate = Some(hash.to_ascii_lowercase());
            }
        }
    }
    bare_candidate
}

pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (dst, chunk) in w[..16].iter_mut().zip(block.as_chunks::<4>().0) {
            *dst = u32::from_be_bytes(*chunk);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let delta = [a, b, c, d, e, f, g, hh];
        for (acc, val) in h.iter_mut().zip(delta) {
            *acc = acc.wrapping_add(val);
        }
    }

    let mut hex = String::with_capacity(64);
    for word in h {
        hex.push_str(&format!("{word:08x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::fake::FakeSystemOps;

    #[test]
    fn sha256_matches_nist_test_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn semver_orders_stable_above_beta_and_numeric_prereleases() {
        let v010 = SemVer::parse("0.1.0").unwrap();
        let b2 = SemVer::parse("v0.2.0-beta.2").unwrap();
        let b10 = SemVer::parse("v0.2.0-beta.10").unwrap();
        let rc1 = SemVer::parse("0.2.0-rc.1").unwrap();
        let s020 = SemVer::parse("0.2.0").unwrap();
        assert!(v010 < b2);
        assert!(b2 < b10);
        assert!(b10 < rc1);
        assert!(rc1 < s020);
    }

    #[test]
    fn check_for_update_distinguishes_stable_and_beta_channels() {
        let ops = FakeSystemOps::default();
        {
            let mut st = ops.state.borrow_mut();
            st.http_responses.insert(
                "https://api.github.com/repos/acme/it-tools/releases/latest".into(),
                (
                    200,
                    br#"{
                        "tag_name": "v99.0.0",
                        "prerelease": false,
                        "published_at": "2026-11-11T00:00:00Z",
                        "html_url": "https://github.com/acme/it-tools/releases/tag/v99.0.0",
                        "body": "Stable release notes",
                        "assets": [
                            {"name": "it-tools.exe", "browser_download_url": "https://dl.example/stable/it-tools.exe"},
                            {"name": "SHA256SUMS.txt", "browser_download_url": "https://dl.example/stable/SHA256SUMS.txt"}
                        ]
                    }"#.to_vec(),
                ),
            );
            st.http_responses.insert(
                "https://api.github.com/repos/acme/it-tools/releases?per_page=20".into(),
                (
                    200,
                    br#"[
                        {
                            "tag_name": "v99.1.0-beta.2",
                            "prerelease": true,
                            "published_at": "2026-11-12T00:00:00Z",
                            "html_url": "https://github.com/acme/it-tools/releases/tag/v99.1.0-beta.2",
                            "body": "Beta 2 notes",
                            "assets": [
                                {"name": "it-tools.exe", "browser_download_url": "https://dl.example/beta/it-tools.exe"}
                            ]
                        },
                        {
                            "tag_name": "v99.0.0",
                            "prerelease": false,
                            "published_at": "2026-11-11T00:00:00Z",
                            "html_url": "https://github.com/acme/it-tools/releases/tag/v99.0.0",
                            "body": "Stable release notes",
                            "assets": []
                        }
                    ]"#.to_vec(),
                ),
            );
        }

        let stable = check_for_update(&ops, "acme/it-tools", UpdateChannel::Stable).unwrap();
        assert!(stable.update_available);
        assert_eq!(stable.latest_version, "99.0.0");
        assert!(!stable.prerelease);
        assert_eq!(
            stable.sha256sums_url.as_deref(),
            Some("https://dl.example/stable/SHA256SUMS.txt")
        );

        let beta = check_for_update(&ops, "acme/it-tools", UpdateChannel::Beta).unwrap();
        assert!(beta.update_available);
        assert_eq!(beta.latest_version, "99.1.0-beta.2");
        assert!(beta.prerelease);
    }

    #[test]
    fn perform_update_verifies_sha256_and_swaps_exe_preserving_old_backup() {
        let ops = FakeSystemOps::default();
        let exe_path = ops.current_exe_path().unwrap();
        let old_exe = b"MZ_OLD_EXE_BINARY_PAYLOAD_1234567890_PADDING_PADDING_PADDING_PADDING";
        ops.write_file(&exe_path, old_exe).unwrap();

        let mut new_exe = b"MZ_NEW_EXE_PORTABLE_V99".to_vec();
        new_exe.resize(128, 0x90);
        let new_sha = sha256_hex(&new_exe);
        let sums = format!("{new_sha}  it-tools.exe\n");

        {
            let mut st = ops.state.borrow_mut();
            st.http_responses.insert(
                "https://dl.example/it-tools.exe".into(),
                (200, new_exe.clone()),
            );
            st.http_responses.insert(
                "https://dl.example/SHA256SUMS.txt".into(),
                (200, sums.into_bytes()),
            );
        }

        let check = UpdateCheckResult {
            current_version: "0.1.0".into(),
            latest_version: "99.0.0".into(),
            channel: UpdateChannel::Stable,
            update_available: true,
            prerelease: false,
            published_at: "2026-11-11T00:00:00Z".into(),
            html_url: String::new(),
            release_notes: String::new(),
            asset_name: Some("it-tools.exe".into()),
            asset_url: Some("https://dl.example/it-tools.exe".into()),
            sha256sums_url: Some("https://dl.example/SHA256SUMS.txt".into()),
        };

        let applied = perform_update(&ops, &check).unwrap();
        assert!(applied.sha256_verified);
        assert_eq!(applied.sha256, new_sha);
        assert_eq!(ops.read_file_opt(&exe_path).unwrap().unwrap(), new_exe);
        assert_eq!(
            ops.read_file_opt(&backup_exe_path(&exe_path))
                .unwrap()
                .unwrap(),
            old_exe
        );

        cleanup_old_exe_backup(&ops);
        assert!(
            ops.read_file_opt(&backup_exe_path(&exe_path))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn perform_update_aborts_on_sha256_mismatch_without_touching_exe() {
        let ops = FakeSystemOps::default();
        let exe_path = ops.current_exe_path().unwrap();
        let original = b"MZ_ORIGINAL_SAFE_BINARY_PADDING_PADDING_PADDING_PADDING_PADDING_PADDING";
        ops.write_file(&exe_path, original).unwrap();

        let mut bad_exe = b"MZ_CORRUPTED".to_vec();
        bad_exe.resize(128, 0xAA);
        let wrong_sums =
            "0000000000000000000000000000000000000000000000000000000000000000  it-tools.exe\n";

        {
            let mut st = ops.state.borrow_mut();
            st.http_responses
                .insert("https://dl.example/it-tools.exe".into(), (200, bad_exe));
            st.http_responses.insert(
                "https://dl.example/SHA256SUMS.txt".into(),
                (200, wrong_sums.as_bytes().to_vec()),
            );
        }

        let check = UpdateCheckResult {
            current_version: "0.1.0".into(),
            latest_version: "99.0.0".into(),
            channel: UpdateChannel::Stable,
            update_available: true,
            prerelease: false,
            published_at: String::new(),
            html_url: String::new(),
            release_notes: String::new(),
            asset_name: Some("it-tools.exe".into()),
            asset_url: Some("https://dl.example/it-tools.exe".into()),
            sha256sums_url: Some("https://dl.example/SHA256SUMS.txt".into()),
        };

        let err = perform_update(&ops, &check).unwrap_err();
        assert!(err.to_string().contains("SHA-256 verification failed"));
        assert_eq!(ops.read_file_opt(&exe_path).unwrap().unwrap(), original);
    }
}
