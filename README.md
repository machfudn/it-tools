# IT-Tools

Utilitas portabel satu berkas untuk hardening, penyesuaian performa, dan provisioning workstation Windows 10/11 dengan antarmuka Terminal Interaktif (TUI) dan antarmuka baris perintah (CLI) yang siap untuk otomatisasi.

> [!NOTE]
> **Tanpa perlu instalasi.** Berkas `it-tools.exe` dikompilasi secara statis tanpa ketergantungan DLL eksternal, runtime `.NET`, maupun dependensi Visual C++ Redistributable. Cukup salin ke folder mana saja atau flashdisk USB dan jalankan langsung di Windows 10 maupun Windows 11 (edisi Home, Pro, Enterprise, dan Education).

---

## Unduh dari GitHub Releases

Binary siap pakai dipublikasikan secara otomatis melalui GitHub Actions pada halaman **Releases** repositori:

1. Buka tab **Releases** di GitHub.
2. Pilih kanal rilis yang diinginkan:
   - **Stable** (disarankan untuk workstation produksi): ditandai dengan tag `vX.Y.Z` dan berlabel **Latest**.
   - **Beta / Pra-rilis** (untuk uji coba staging & UAT): ditandai dengan tag `vX.Y.Z-beta.N` dan berlabel **Pre-release**.
3. Unduh berkas rilis:
   - **`it-tools.exe`**: binary mandiri portabel yang siap langsung dijalankan.
   - **`it-tools-vX.Y.Z-windows-x64.zip`**: arsip portabel berisi `it-tools.exe`, templat konfigurasi `it-tools.toml`, dan panduan ini.
   - **`SHA256SUMS.txt`**: berkas checksum SHA-256 untuk memverifikasi keaslian dan integritas berkas unduhan.

### Verifikasi Integritas Berkas & Properti Versi

Verifikasi hash SHA-256 menggunakan PowerShell setelah mengunduh:

```powershell
Get-FileHash .\it-tools.exe -Algorithm SHA256
# Bandingkan hasilnya dengan nilai di berkas SHA256SUMS.txt dari rilis yang sama
```

Periksa properti versi PE Windows yang tertanam di binary (dapat juga dilihat lewat **Klik Kanan → Properties → Details**):

```powershell
(Get-Item .\it-tools.exe).VersionInfo | Format-List ProductName, ProductVersion, FileVersion, FileDescription, Comments
```

---

## Fitur & Kapabilitas

IT-Tools memeriksa dan mengonfigurasi **13 modul hardening & provisioning Windows**, membuat **snapshot backup JSON** otomatis sebelum menerapkan perubahan sistem, serta menyertakan **updater GitHub Releases** terintegrasi.

| Kategori | ID Modul | Hak Akses | Deskripsi Konfigurasi |
|---|---|---|---|
| **UI & UX** | `visual_effects` | Pengguna Standar | Menonaktifkan animasi jendela dan transparansi antarmuka untuk respon desktop yang lebih cepat |
| **Privasi** | `diagnostics` | Campuran / Admin | Membatasi data diagnostik telemetri Windows ke tingkat minimal (Required) dan menonaktifkan prompt survei umpan balik |
| **Privasi** | `search` | Campuran / Admin | Menonaktifkan pencarian cloud Bing/MSA, integrasi akun kantor/sekolah (AAD), dan sorotan harian (Search Highlights) |
| **Input** | `typing` | Pengguna Standar | Menonaktifkan koreksi otomatis, penyorot salah ketik, prediksi teks, wawasan mengetik, dan tombol pintas input suara |
| **Shell** | `taskbar` | Pengguna Standar | Mengatur perataan taskbar (`left`/`center`), sembunyikan otomatis (auto-hide), serta menonaktifkan Widget, lencana, dan kedipan aplikasi |
| **Daya** | `power` | Admin | Mengaktifkan skema High Performance, mematikan hibernasi, mengatur batas minimal CPU AC/DC, waktu tunggu layar/disk/tidur, dan tombol daya/tutup layar |
| **Keamanan** | `screensaver` | Pengguna Standar | Mengaktifkan screensaver pengunci layar `scrnsave.scr` setelah 5 menit dengan kewajiban login ulang saat dilanjutkan |
| **Input** | `accessibility` | Pengguna Standar | Mempertahankan perilaku klasik tombol `PrintScreen` tanpa pemotongan paksa Snipping Tool |
| **Browser** | `edge` | Admin | Menonaktifkan fitur startup boost, pra-muat tab baru (NTP), pra-luncur Edge, dan mengaktifkan proteksi pemblokiran PUA |
| **Pemulihan** | `system_restore` | Admin | Mengaktifkan titik pemulihan sistem (System Restore) pada drive `C:` dan membatasi alokasi ruang shadow storage sebesar `5GB` |
| **Akun** | `password_policy` | Admin | Menetapkan riwayat sandi, usia maksimal, panjang minimal, kompleksitas, dan ambang batas lockout akun via `secedit` (termasuk opsi pembuatan akun lokal) |
| **Jaringan** | `defender_firewall` | Admin | Mengaktifkan proteksi antivirus Microsoft Defender (dengan opsi headless UI), profil Windows Firewall, dan aturan ICMP echo/router |
| **Startup** | `startup_apps` | Campuran / Admin | Menonaktifkan aplikasi startup di luar daftar izin (allowlist) pada `HKCU`, `HKLM`, dan folder Startup menggunakan `StartupApproved` |
| **Pembaruan** | `update` | Pengguna Standar | Memeriksa GitHub Releases (Stable atau Beta), memverifikasi `SHA256SUMS.txt`, dan menukar binary `it-tools.exe` secara aman di tempat |
| **Pemulihan** | `rollback` | Standar / Admin | Mengembalikan nilai registry Windows, skema daya, kebijakan `secedit`, status firewall, dan entri startup ke kondisi semula dari `it-tools.backup.*.json` |

---

## Panduan Penggunaan

### 1. Mode TUI Interaktif (Terminal UI)

Cukup klik ganda berkas `it-tools.exe` atau jalankan tanpa argumen di **Windows Terminal**, **Command Prompt**, atau **PowerShell**:

```powershell
.\it-tools.exe
```

> [!TIP]
> **Elevasi Administrator Otomatis (Auto-Elevation):** Saat dibuka dalam mode TUI interaktif (klik ganda atau dipanggil tanpa sub-perintah), `it-tools.exe` secara otomatis memicu dialog persetujuan Windows UAC agar langsung berjalan sebagai Administrator. Jika sengaja ingin membuka aplikasi dalam mode pengguna standar tanpa elevasi, tambahkan flag `--no-elevate`:
> ```powershell
> .\it-tools.exe --no-elevate
> ```

#### Indikator Status HUD (Heads-Up Display)
Bagian atas antarmuka TUI menampilkan status sistem secara langsung:
- **Lencana Hak Akses**: `[ADMINISTRATOR]` (latar hijau), `[STANDAR (DIBATASI)]` (latar kuning), atau `[PENGGUNA STANDAR]` (latar kuning).
- **Lencana Mode Eksekusi**: `[MODE: LIVE]` (eksekusi langsung) atau `[MODE: SIMULASI]` (dry-run aman tanpa perubahan OS).
- **Lencana Opsi Eksekusi**: `[BACKUP: ON/OFF]`, `[STRICT: ON/OFF]`, `[RESTART: ON/OFF]`, `[CAKUPAN: HKCU/HKLM]`, `[TARGET: <user>]`.
- **Ringkasan Kepatuhan**: Jumlah aturan yang `✔ Sesuai`, `⚠ Berubah`, `🔒 Butuh Admin`, dan `✖ Kendala`.

#### Tombol Pintas Keyboard di Dalam TUI:
- `↑` / `↓` (atau `j` / `k`) : Menavigasi modul dan melihat rincian perbandingan status sistem saat ini
- `Spasi` : Mengaktifkan atau menonaktifkan modul terpilih dalam profil sesi aktif
- `e` / `Enter` : Mengubah parameter konfigurasi modul (waktu tunggu, daftar izin, kebijakan sandi, dll.)
- `x` : Mengalihkan hak akses secara realtime (berpindah instan antara **Administrator** dan **Pengguna Standar** di memori tanpa perlu restart, atau memicu UAC jika proses non-admin)
- `m` : Mengalihkan mode eksekusi cepat antara **Penerapan Langsung (Live)** dan **Simulasi (Dry-Run)**
- `o` : Membuka dialog **Opsi & Sub-Perintah Eksekusi** (mengatur backup, mode ketat, restart explorer otomatis, cakupan filter HKCU/HKLM, dan hak akses)
- `u` : Memilih akun target lokal opsional (menghapus status PasswordNeverExpires atau membuat akun lokal baru dengan sandi sementara di RAM)
- `p` : Menjalankan simulasi instan (**Dry-Run**) untuk melihat semua perubahan yang akan terjadi tanpa menyentuh Windows
- `a` : Menjalankan eksekusi modul aktif berdasarkan mode, opsi, dan hak akses yang dipilih (menampilkan dialog konfirmasi transparan)
- `s` : Menyimpan konfigurasi aktif ke berkas `it-tools.toml` di samping berkas `it-tools.exe`
- `r` : Menyegarkan pemeriksaan kepatuhan konfigurasi terhadap kondisi Windows saat ini
- `b` : Membuka menu pemulihan (**Rollback Picker**) untuk memulihkan sistem dari berkas snapshot `it-tools.backup.*.json`
- `v` : Memeriksa pembaruan versi (Stable atau Beta) langsung dari GitHub Releases
- `d` : Membuka dokumentasi interaktif dan glosarium istilah teknis lengkap
- `q` / `Esc` : Keluar dari aplikasi

> [!TIP]
> Menjalankan dari Git Bash (`mintty`) tanpa konsol Win32 murni? Gunakan `winpty ./it-tools.exe` untuk antarmuka TUI, atau panggil sub-perintah CLI secara langsung.

---

### 2. Perintah CLI (Otomatisasi & Skrip)

IT-Tools menyediakan antarmuka baris perintah yang lengkap untuk provisioning tanpa pengawasan (unattended deployment) dan skrip IT support:

**Pemeriksaan kepatuhan sistem (read-only, aman untuk inspeksi non-admin):**
```powershell
.\it-tools.exe check
.\it-tools.exe check --json
.\it-tools.exe check --only power,defender_firewall
```

**Simulasi perubahan tanpa mengubah konfigurasi Windows (`--dry-run`):**
```powershell
.\it-tools.exe apply --dry-run
.\it-tools.exe apply --dry-run --json
```

**Menerapkan aturan hardening (otomatis membuat snapshot backup JSON terlebih dahulu):**
```powershell
# Penerapan interaktif dengan konfirmasi visual
.\it-tools.exe apply

# Penerapan tanpa pengawasan (lewati konfirmasi, jalankan di terminal Administrator untuk aturan HKLM)
.\it-tools.exe apply --yes

# Terapkan hanya modul tertentu atau lewati modul tertentu
.\it-tools.exe apply --only visual_effects,typing,taskbar --yes
.\it-tools.exe apply --skip edge,startup_apps --yes

# Opsi provisioning: buat atau konfigurasi akun lokal pengguna baru (kata sandi tidak pernah dicatat ke disk atau log)
.\it-tools.exe apply --yes --create-user StaffUser --prompt-password
```

**Pemulihan sistem dari snapshot backup sebelumnya:**
```powershell
.\it-tools.exe rollback .\it-tools.backup.20261111-120000.json
.\it-tools.exe rollback .\it-tools.backup.20261111-120000.json --yes
```

**Mengelola berkas konfigurasi portabel (`it-tools.toml`):**
```powershell
# Buat templat berkas it-tools.toml standar di samping it-tools.exe
.\it-tools.exe config init

# Tampilkan konfigurasi aktif gabungan (nilai bawaan tertanam + berkas override)
.\it-tools.exe config show

# Validasi sintaks dan batasan rentang nilai konfigurasi kustom
.\it-tools.exe --config C:\Setup\lab.toml config validate
```

**Memeriksa daftar akun pengguna lokal Windows:**
```powershell
.\it-tools.exe user list
```

---

## Pemeriksaan & Pemasangan Pembaruan Mandiri

`it-tools.exe` dapat memeriksa rilis terbaru di GitHub dan memperbarui dirinya sendiri langsung melalui koneksi HTTPS menggunakan Windows WinHTTP bawaan serta verifikasi hash SHA-256:

```powershell
# Periksa apakah ada rilis Stable yang lebih baru (hanya memeriksa)
.\it-tools.exe update --check

# Periksa rilis termasuk kanal Beta (pra-rilis)
.\it-tools.exe update --check --beta

# Unduh, verifikasi integritas SHA-256 terhadap SHA256SUMS.txt, dan pasang pembaruan otomatis
.\it-tools.exe update
.\it-tools.exe update --yes
```

> [!NOTE]
> Build resmi dari GitHub Actions menyertakan identitas repositori secara otomatis. Jika Anda menggunakan fork kustom atau cermin lokal, gunakan argumen `--repo owner/repo` atau atur parameter `[update]` di `it-tools.toml`. Selama proses pembaruan mandiri, binary lama dipindahkan dengan aman ke `it-tools.exe.old` dan dibersihkan otomatis pada peluncuran berikutnya.

---

## Kustomisasi Konfigurasi (`it-tools.toml`)

Konfigurasi dimuat dengan urutan prioritas berikut:
1. Argumen eksplisit CLI `--config <JALUR>`
2. Berkas `it-tools.toml` yang berada di folder yang sama dengan `it-tools.exe`
3. Profil bawaan sistem yang tertanam di dalam aplikasi (bila berkas tidak ditemukan)

Hanya kunci yang ingin diubah yang perlu dituliskan ke dalam `it-tools.toml`; pengaturan lainnya akan otomatis mewarisi nilai bawaan:

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

## Kode Keluar (Exit Codes) & Catatan Operasional

| Kode Keluar | Arti / Kondisi |
|---|---|
| `0` | Sukses (atau semua modul yang dipilih sudah sesuai dengan target profil) |
| `1` | Galat runtime, kegagalan validasi, atau satu atau lebih modul gagal saat proses penerapan langsung |
| `2` | Butuh elevasi hak akses (jalankan terminal sebagai Administrator untuk modul `HKLM` atau gunakan `--only` untuk modul `HKCU`) |
| `3` | Antarmuka TUI dipanggil tanpa Windows Console TTY (misalnya melalui pipe atau redirection) |

> [!WARNING]
> **Catatan Perilaku Sistem Windows:**
> - **Defender Tamper Protection:** Jika proteksi Tamper aktif pada Windows Security, modul `defender_firewall` akan mencatat peringatan non-fatal tanpa membatalkan modul lainnya.
> - **Modern Standby (S0 Low Power Idle):** Sebagian laptop modern mengunci subgrup daya lawas pada tingkat firmware; modul `power` akan melewati subgrup yang terkunci dengan peringatan dan melanjutkan konfigurasi daya lainnya.
> - **Microsoft Edge:** Kebijakan Edge diterapkan secara bersih melalui Registry Windows Policy; peringatan akan mengingatkan Anda untuk memuat ulang peramban jika proses `msedge.exe` sedang berjalan aktif.
