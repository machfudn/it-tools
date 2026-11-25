# Catatan Perubahan (Changelog)

Seluruh perubahan penting pada proyek **IT-Tools** dicatat pada berkas ini.
Format mengacu pada konvensi [Keep a Changelog](https://keepachangelog.com/id/1.0.0/) dan menggunakan [Semantic Versioning](https://semver.org/).

---

## [0.1.0] - Kandidat Promosi Rilis Stabil (Seri 0.1.0)

Merangkum keseluruhan fitur inti dari fase pra-rilis Beta (`v0.1.0-beta.2` hingga `v0.1.0-beta.5`) serta seluruh penyempurnaan TUI, manajemen hak akses, dan otomatisasi peluncuran sebelum promosi penuh ke rilis **Latest (Stabil)**.

### Ditambahkan
- **Auto-Elevation Saat Membuka `it-tools.exe`**: Aplikasi otomatis meminta elevasi Administrator Windows (UAC) saat dibuka dalam mode TUI interaktif (klik ganda atau tanpa sub-perintah), disertai fallback aman ke Pengguna Standar jika dibatalkan dan flag `--no-elevate` untuk melewatinya.
- **Pengalihan Hak Akses (Privilege) Realtime (`[x]`)**: Berpindah instan secara in-memory antara status `[ADMINISTRATOR]` dan `[STANDAR (DIBATASI)]` tanpa menutup atau me-restart aplikasi, atau memicu UAC satu tombol saat berjalan sebagai pengguna standar.
- **Mode Eksekusi & Dialog Opsi Sub-Perintah Terpadu (`[m]`, `[o]`)**: Kendali langsung di dalam TUI untuk memilih mode Live vs Simulasi (Dry-Run), Snapshot Backup JSON on/off, Mode Ketat (Strict) on/off, Auto-Restart Explorer on/off, Cakupan modul (`AllEnabled` / `HkcuOnly` / `HklmOnly`), serta penggantian privilege.
- **Indikator Status HUD & KPI Chip**: Header dua baris dengan lencana status hak akses, mode eksekusi, opsi aktif, serta ringkasan kepatuhan modul (`Sesuai`, `Berubah`, `Butuh Admin`, `Kendala`).
- **Dokumentasi & Glosarium Bawaan (`[d]`)**: Panduan navigasi lengkap dan glosarium istilah teknis Windows langsung di dalam antarmuka TUI.
- **Metadata Ringkas Aturan**: Deskripsi informatif pada ke-13 modul hardening di panel rincian TUI.
- **Pembaruan Mandiri dari TUI (`[v]`)**: Pemeriksaan versi GitHub Releases (Stable/Beta), verifikasi `SHA256SUMS.txt`, dan instalasi pembaruan langsung dari modal laporan pembaruan.

### Diubah
- **Lokalisasi Penuh Bahasa Indonesia**: `README.md`, antarmuka TUI, pesan status, serta templat catatan rilis otomatis (`.github/workflows/release.yml`) kini berbahasa Indonesia yang alami dan konsisten.
- **Pemformatan Kode**: Seluruh berkas sumber Rust mematuhi standar `cargo fmt --all -- --check` dan `cargo clippy --all-targets -- -D warnings`.

---

## [0.1.0-beta.2 - 0.1.0-beta.5] - Pra-rilis UAT Beta

### Fitur Dasar yang Hadir Sejak Pra-rilis
- **13 Modul Hardening & Provisioning Windows 10/11**:
  `visual_effects`, `diagnostics`, `search`, `typing`, `taskbar`, `power`, `screensaver`, `accessibility`, `edge`, `system_restore`, `password_policy`, `defender_firewall`, dan `startup_apps`.
- **Engine Idempoten dengan Backup & Rollback Otomatis**: Penyimpanan snapshot JSON (`it-tools.backup.<timestamp>.json`) sebelum mutasi langsung dan pemulihan satu langkah melalui menu `[b]` maupun perintah CLI `rollback`.
- **CLI Lengkap untuk Otomatisasi**: Mendukung `check`, `apply`, `rollback`, `config (init/show/validate)`, `user list`, dan `update` dengan keluaran JSON terstruktur.
- **Binary Statis Portabel**: Kompilasi `x86_64-pc-windows-msvc` statis tanpa ketergantungan `.NET` atau Visual C++ Redistributable, lengkap dengan properti versi Windows PE dan pipeline GitHub Actions.
