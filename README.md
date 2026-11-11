# IT-Tools

Portable single-file Windows 10/11 workstation hardening, tuning, and provisioning utility with an interactive Terminal UI (TUI) and automation-ready CLI.

> [!NOTE]
> **Zero installation required.** `it-tools.exe` is compiled with a fully static C/C++ runtime and has no external DLL, `.NET`, or VC++ Redistributable dependencies. Copy it to any folder or USB drive and run directly on Windows 10 or Windows 11 (Home, Pro, Enterprise, and Education).

---

## Download from GitHub Releases

Prebuilt executables are published automatically via GitHub Actions on the repository's **Releases** page:

1. Open the **Releases** tab on GitHub.
2. Choose your release channel:
   - **Stable** (recommended for production workstations): tagged `vX.Y.Z` and marked as **Latest**.
   - **Beta / Pre-release** (for UAT & staging testing): tagged `vX.Y.Z-beta.N` and marked as **Pre-release**.
3. Download one of the release assets:
   - **`it-tools.exe`** — standalone portable executable ready to run immediately.
   - **`it-tools-vX.Y.Z-windows-x64.zip`** — portable bundle containing `it-tools.exe`, a default `it-tools.toml` template, and this guide.
   - **`SHA256SUMS.txt`** — SHA-256 checksums for verifying download integrity.

### Verify File Integrity & Version Properties

Verify the SHA-256 hash in PowerShell after downloading:

```powershell
Get-FileHash .\it-tools.exe -Algorithm SHA256
# Compare output against SHA256SUMS.txt from the same release
```

Check embedded Windows PE **Version Properties** (also visible via **Right-click → Properties → Details**):

```powershell
(Get-Item .\it-tools.exe).VersionInfo | Format-List ProductName, ProductVersion, FileVersion, FileDescription, Comments
```

---

## Features & Capabilities

IT-Tools inspects and configures **13 Windows hardening & provisioning modules**, creates automatic **JSON rollback snapshots** before any system change, and includes a built-in **GitHub Releases updater**.

| Category | Module ID | Scope | What It Configures |
|---|---|---|---|
| **UI & UX** | `visual_effects` | Standard User | Disables window animations & UI transparency for snappy desktop responsiveness |
| **Privacy** | `diagnostics` | Mixed / Admin | Restricts Windows diagnostic telemetry to Required-only and disables feedback prompts |
| **Privacy** | `search` | Mixed / Admin | Disables Bing/MSA cloud search, Work/School search, and Search Highlights |
| **Input** | `typing` | Standard User | Disables autocorrect, spell-highlight, text prediction, typing insights, and touch-keyboard nudges |
| **Shell** | `taskbar` | Standard User | Configures Taskbar alignment (`left`/`center`), auto-hide, disables Widgets, badges, and flashing |
| **Power** | `power` | Admin | Activates High Performance plan, disables hibernation, tunes AC/DC CPU min %, disk/display/sleep timeouts, and lid/power buttons |
| **Security** | `screensaver` | Standard User | Enables `scrnsave.scr` screensaver lock after 5 minutes with logon resume required |
| **Input** | `accessibility` | Standard User | Preserves classic `PrintScreen` key behavior instead of Snipping Tool intercept |
| **Browser** | `edge` | Admin | Disables Microsoft Edge startup boost, prelaunch, NTP preload, and enforces SmartScreen PUA blocking |
| **Recovery** | `system_restore` | Admin | Enables System Restore on `C:` and caps shadow storage at `5GB` |
| **Account** | `password_policy` | Admin | Enforces password history, max age, min length, complexity, and lockout thresholds via `secedit` (plus opt-in local user provisioning) |
| **Network** | `defender_firewall` | Admin | Enables Microsoft Defender (with optional headless UI), Windows Firewall profiles, and configurable ICMP echo/router rules |
| **Startup** | `startup_apps` | Mixed / Admin | Disables non-allowlisted startup apps across `HKCU`, `HKLM`, and Startup folders using `StartupApproved` |
| **Updates** | `update` | Standard User | Checks GitHub Releases (Stable or Beta), verifies `SHA256SUMS.txt`, and safely swaps `it-tools.exe` in place |
| **Recovery** | `rollback` | Standard / Admin | Restores previous Windows registry values, power scheme, `secedit` policy, firewall state, and startup entries from `it-tools.backup.*.json` |

---

## Usage

### 1. Interactive TUI Mode

Double-click `it-tools.exe` or run it without arguments in **Windows Terminal** / **Command Prompt** / **PowerShell**:

```powershell
.\it-tools.exe
```

**Keyboard Shortcuts inside TUI:**
- `↑` / `↓` (or `j` / `k`) — Browse modules and view live system compliance diffs
- `Space` — Enable or disable the selected module in the session profile
- `e` / `Enter` — Edit module parameters (timeouts, allowlists, policies, etc.)
- `u` — Optional local user target picker (clear password expiration or provision a new local account)
- `p` — Preview **Dry-Run** diff across all enabled modules (zero OS changes)
- `a` — Apply enabled modules (prompts for confirmation; offers one-click UAC elevation or HKCU-only mode if not Administrator)
- `s` — Save customized settings to `it-tools.toml` beside `it-tools.exe`
- `b` — Open Rollback Picker to restore from any `it-tools.backup.*.json` snapshot
- `v` — Check for new Stable or Beta releases on GitHub
- `q` / `Esc` — Quit

> [!TIP]
> Running from Git Bash (`mintty`) without a Win32 console? Either launch `winpty ./it-tools.exe` for TUI or pass CLI subcommands directly.

### 2. CLI Commands (Automation & Scripting)

**Read-only compliance check (safe for non-admin inspection):**
```powershell
.\it-tools.exe check
.\it-tools.exe check --json
.\it-tools.exe check --only power,defender_firewall
```

**Preview changes without modifying Windows (`--dry-run`):**
```powershell
.\it-tools.exe apply --dry-run
.\it-tools.exe apply --dry-run --json
```

**Apply hardening rules (creates `it-tools.backup.<timestamp>.json` automatically):**
```powershell
# Interactive confirmation prompt
.\it-tools.exe apply

# Unattended deployment (skips confirmation prompt; run from elevated prompt for HKLM/Admin rules)
.\it-tools.exe apply --yes

# Apply only specific rules or skip specific rules
.\it-tools.exe apply --only visual_effects,typing,taskbar --yes
.\it-tools.exe apply --skip edge,startup_apps --yes

# Opt-in: create or configure a local account during provisioning (password is never logged)
.\it-tools.exe apply --yes --create-user StaffUser --prompt-password
```

**Rollback from a saved backup snapshot:**
```powershell
.\it-tools.exe rollback .\it-tools.backup.20261111-120000.json
.\it-tools.exe rollback .\it-tools.backup.20261111-120000.json --yes
```

**Manage portable configuration (`it-tools.toml`):**
```powershell
# Generate an editable it-tools.toml beside it-tools.exe
.\it-tools.exe config init

# Inspect active merged settings (embedded defaults + overrides)
.\it-tools.exe config show

# Validate syntax and allowed value ranges in a custom config
.\it-tools.exe --config C:\Setup\lab.toml config validate
```

**Inspect local Windows accounts:**
```powershell
.\it-tools.exe user list
```

---

## Check for Updates & Self-Update

`it-tools.exe` can check GitHub Releases and upgrade itself directly over HTTPS using native Windows WinHTTP and SHA-256 verification:

```powershell
# Check for newer Stable release (read-only)
.\it-tools.exe update --check

# Check including Beta pre-releases
.\it-tools.exe update --check --beta

# Download, verify SHA-256 against SHA256SUMS.txt, and replace it-tools.exe in place
.\it-tools.exe update
.\it-tools.exe update --yes
```

> [!NOTE]
> Official builds from GitHub Actions automatically embed the repository slug. If you use a custom fork or offline mirror, pass `--repo owner/repo` or configure `[update]` inside `it-tools.toml`. During self-update, the previous binary is safely moved to `it-tools.exe.old` and cleaned up automatically on the next launch.

---

## Configuration Customization (`it-tools.toml`)

Configuration loads in this order:
1. Explicit `--config <PATH>` CLI argument
2. `it-tools.toml` located in the same folder as `it-tools.exe`
3. Built-in default profile (if no file is present)

Only changed keys need to be placed in `it-tools.toml`; unspecified settings inherit embedded defaults:

```toml
version = 1

[update]
allow_beta = false

[rules.taskbar]
alignment = "left"
auto_hide = true

[rules.power]
scheme = "high_performance"
sleep_timeout_dc_min = 15

[rules.startup_apps]
allowlist = ["OpenVPN GUI", "SecurityHealth", "OneDrive"]
```

---

## Exit Codes & Operational Notes

| Exit Code | Meaning |
|---|---|
| `0` | Success (or all selected modules already compliant / reported cleanly) |
| `1` | Runtime error, validation failure, or one or more rules failed during live `apply` |
| `2` | Elevation required — run from an Administrator terminal for `HKLM`/policy rules or use `--only` with Standard User (`HKCU`) rules |
| `3` | TUI invoked without a Windows Console TTY (e.g., redirected pipe) |

> [!WARNING]
> **Windows Behavior Notes:**
> - **Defender Tamper Protection:** If Tamper Protection is enabled by policy or local security settings, `defender_firewall` reports a non-fatal warning rather than failing the entire provisioning run.
> - **Modern Standby (S0 Low Power Idle):** Some laptops hide legacy sleep/processor subgroups; `power` skips locked subgroups with a warning and continues configuring remaining settings.
> - **Microsoft Edge:** Edge settings apply via policy registry keys cleanly, and a warning reminds you to restart running `msedge.exe` instances if Edge is open.
