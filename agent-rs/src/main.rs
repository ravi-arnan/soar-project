use anyhow::Result;
use clap::Parser;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use sysinfo::System;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "soar-agent", about = "Agen ringan SOAR Rust - alternatif Wazuh Agent")]
struct Args {
    #[arg(long, default_value = "http://100.73.91.17:5678/webhook/wazuh-alert")]
    webhook: String,

    /// Webhook n8n Deteksi Phishing (sensor URL dari file .url/.html).
    #[arg(long, default_value = "http://100.73.91.17:5678/webhook/wazuh-phishing")]
    phishing_webhook: String,

    #[arg(long, default_value = "003")]
    agent_id: String,

    #[arg(long, default_value = "rust-agent-ravi")]
    agent_name: String,

    #[arg(long, value_delimiter = ',')]
    watch: Option<Vec<String>>,

    #[arg(long, default_value = "8787")]
    listen_port: u16,

    #[arg(long, default_value = "http://100.73.91.17:8080/api/heartbeat")]
    fleet_url: String,

    #[arg(long, default_value = "")]
    fleet_poll_token_file: String,

    #[arg(long, default_value = "60")]
    heartbeat_secs: u64,

    /// Interval scan terjadwal (detik). 0 = mati. FIM hanya melihat event
    /// baru, jadi file lama / file yang masuk saat agent mati tidak pernah
    /// ter-scan. Task ini memindai `--scan-roots` tiap interval.
    #[arg(long, default_value = "0")]
    scan_interval_secs: u64,

    /// Root scan terjadwal, dipisah koma. Default = daftar `--watch`.
    #[arg(long, value_delimiter = ',')]
    scan_roots: Option<Vec<String>>,
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn get_perm(path: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| format!("{:o}", m.permissions().mode() & 0o777))
            .unwrap_or_else(|_| "644".to_string())
    }
    #[cfg(windows)]
    {
        let _ = path;
        "644".to_string()
    }
}

/// Deteksi penyamaran ekstensi ganda (MITRE ATT&CK T1036.007 Masquerading: Double Extension).
/// Penyerang sering menyamarkan file eksekutabel berbahaya sebagai dokumen atau media,
/// misalnya: `invoice.pdf.exe`, `pembayaran.docx.vbs`, `foto.jpg.bat`, `order.xlsx.scr`.
fn has_deceptive_double_extension(path: &Path) -> bool {
    let lower_raw = path.to_string_lossy().to_lowercase();
    let lower = lower_raw.replace('\\', "/");
    let fname = match lower.split('/').last() {
        Some(f) => f,
        None => return false,
    };

    const DANGEROUS_EXT: &[&str] = &[
        ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".ps1", ".scr", ".pif", ".hta", ".cpl", ".msi",
    ];
    const DECEPTIVE_DOC_EXT: &[&str] = &[
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".txt", ".zip", ".rar",
    ];

    if let Some(&ext) = DANGEROUS_EXT.iter().find(|&&e| fname.ends_with(e)) {
        let stem = &fname[..fname.len() - ext.len()];
        if DECEPTIVE_DOC_EXT.iter().any(|&doc| stem.ends_with(doc)) {
            return true;
        }
    }
    false
}

fn build_payload(args: &Args, path: &Path, hash: &str) -> serde_json::Value {
    let perm = get_perm(path);
    let size = std::fs::metadata(path)
        .map(|m| m.len().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let is_double_ext = has_deceptive_double_extension(path);

    serde_json::json!({
        "rule": {
            "id": if is_double_ext { "100003" } else { "554" },
            "level": if is_double_ext { 8 } else { 5 },
            "description": if is_double_ext {
                "Deceptive double extension detected (T1036.007)."
            } else {
                "File added to the system."
            }
        },
        "agent": {"id": args.agent_id, "name": args.agent_name},
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "data": {
            "sha256_after": hash,
            "path": path.to_string_lossy(),
            "srcip": "0.0.0.0",
            "is_double_extension": is_double_ext
        },
        "syscheck": {
            "path": path.to_string_lossy(),
            "sha256_after": hash,
            "event": "added",
            "size_after": size,
            "perm_after": perm,
            "mode": "realtime"
        }
    })
}

/// Payload darurat ransomware: terpicu saat berkas umpan (canary decoy) termodifikasi/terenkripsi.
/// Rule 100004 Level 12 (CRITICAL) langsung mengaktifkan isolasi darurat sebelum berkas lain terenkripsi.
fn build_canary_ransomware_payload(args: &Args, path: &Path, hash: &str) -> serde_json::Value {
    serde_json::json!({
        "rule": {
            "id": "100004",
            "level": 12,
            "description": "Ransomware canary file tampered (T1486 Data Encrypted for Impact)."
        },
        "agent": {"id": args.agent_id, "name": args.agent_name},
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "data": {
            "sha256_after": hash,
            "path": path.to_string_lossy(),
            "srcip": "0.0.0.0",
            "is_canary_tampered": true,
            "attack_technique": "T1486"
        },
        "syscheck": {
            "path": path.to_string_lossy(),
            "sha256_after": hash,
            "event": "modified",
            "mode": "realtime"
        }
    })
}

/// Inisialisasi berkas umpan (decoy canary file) di seluruh direktori pantau.
/// Mengembalikan mapping path canary ke hash sha256 resminya.
fn init_canaries(watch_paths: &[PathBuf]) -> HashMap<PathBuf, String> {
    let mut map = HashMap::new();
    const CANARY_NAME: &str = ".soar-canary.docx";
    const CANARY_BYTES: &[u8] = b"PK\x03\x04\x14\x00\x06\x00SOAR-CANARY-DECOY-BALI-HANDMADE-EARLY-WARNING\x00";

    for root in watch_paths {
        if !root.is_dir() {
            continue;
        }
        let canary_path = root.join(CANARY_NAME);
        if !canary_path.exists() {
            let _ = std::fs::write(&canary_path, CANARY_BYTES);
        }
        if let Ok(hash) = sha256_file(&canary_path) {
            info!(path = %canary_path.display(), hash = %hash, "canary ransomware aktif");
            map.insert(canary_path, hash);
        }
    }
    map
}

/// Sensor URL phishing: ekstrak http(s) dari file pointer/attachment.
/// Phishing TA sering masuk sebagai lampiran (.url shortcut, .html invoice
/// palsu). Tanpa regex crate: pindai substring, hentikan di delimiter.
/// Baca dibatasi 256KB, maks 5 URL unik per file (hemat kuota GSB/URLScan).
fn extract_urls(path: &Path) -> Vec<String> {
    const MAX_READ: u64 = 256 * 1024;
    const MAX_URLS: usize = 5;
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };
    let mut buf = Vec::new();
    if file.take(MAX_READ).read_to_end(&mut buf).is_err() {
        return vec![];
    }
    let text = String::from_utf8_lossy(&buf);
    let mut out: Vec<String> = vec![];
    let mut i = 0;
    while i < text.len() && out.len() < MAX_URLS {
        let rest = &text[i..];
        // Ambil kemunculan paling awal dari kedua skema (jangan prioritaskan
        // https: http://a lalu https://b harus kena dua-duanya).
        let start = rest
            .find("https://")
            .into_iter()
            .chain(rest.find("http://"))
            .min()
            .map(|s| i + s);
        let start = match start {
            Some(s) => s,
            None => break,
        };
        let mut end = start;
        for (j, c) in text[start..].char_indices() {
            if c.is_whitespace() || "\"'<>(),;\\".contains(c) {
                break;
            }
            end = start + j + c.len_utf8();
        }
        let url = text[start..end].trim_end_matches(|c| c == '.' || c == ')' || c == ',').to_string();
        if url.len() > 10 && !out.contains(&url) {
            out.push(url);
        }
        i = end.max(start + 1);
    }
    out
}

/// Ekstensi yang memicu sensor phishing (selain tetap/divert jalur malware).
/// Bentuk sama dengan payload uji E3 (rule 100002) yang dipakai benchmark.
fn build_phishing_payload(args: &Args, path: &Path, url: &str) -> serde_json::Value {
    serde_json::json!({
        "rule": {"id": "100002", "level": 10, "description": "Phishing URL detected."},
        "agent": {"id": args.agent_id, "name": args.agent_name},
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "data": {
            "url": url,
            "srcip": "0.0.0.0",
            "event_type": "phishing_url",
            "source_file": path.to_string_lossy()
        }
    })
}

/// Retry 3x backoff dipakai jalur malware maupun phishing.
/// ponytail: client dipakai ulang (satu connection pool). Dulu tiap POST
/// bikin Client baru (rebuild TLS config + pool) = CPU + alokasi sia-sia,
/// apalagi saat event storm.
async fn post_with_retry(
    client: &reqwest::Client,
    webhook: &str,
    payload: &serde_json::Value,
    path: &Path,
) -> bool {
    for attempt in 1..=3 {
        match post_to_n8n(client, webhook, payload).await {
            Ok(_) => return true,
            Err(e) => {
                warn!(attempt, error = %e, "POST gagal, retry");
                tokio::time::sleep(Duration::from_secs(attempt)).await;
            }
        }
    }
    error!(path = %path.display(), "POST gagal 3x, drop event");
    false
}

async fn post_to_n8n(
    client: &reqwest::Client,
    webhook: &str,
    payload: &serde_json::Value,
) -> Result<()> {
    let resp = client
        .post(webhook)
        .json(payload)
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("n8n webhook {} -> {} body: {}", webhook, status, body);
    }
    info!(status = %status, "POST ok ke n8n");
    Ok(())
}

fn should_ignore(path: &Path) -> bool {
    // ponytail: filter sama dengan scripts/custom-n8n.py noise filter
    // jangan kirim /tmp, /var/cache, dll biar hemat VT quota
    // Juga filter ekstensi noise: file ISO installer, DS_Store, thumbs.db, desktop.ini
    let lower_raw = path.to_string_lossy().to_lowercase();
    let lower = lower_raw.replace('\\', "/");

    // File name spesifik Windows / macOS yang sering jadi noise FIM
    let fname = lower.split('/').last().unwrap_or("");
    if fname == "desktop.ini" || fname == "thumbs.db" || fname == ".ds_store" {
        return true;
    }
    const NOISY_EXT: &[&str] = &[
        ".iso",
        ".ds_store",
        ".thumbs.db",
        ".dmg",
        // ponytail: sqlite WAL/SHM (browser, opencode, dsb) churn tiap detik
        // dan tidak pernah jadi vektor malware -> jangan hash + jangan POST.
        ".db-wal",
        ".db-shm",
        ".db-journal",
        ".tmp",
        ".log",
        ".swp",
        // ponytail: download parsial browser (FP 18 Sep: *.zip.part masuk
        // Security Events 4x). File belum lengkap -> hash tak bermakna.
        // Rename .part -> nama final memicu event Create baru (beda path)
        // jadi file lengkap tetap lolos.
        ".part",
        ".crdownload",
        ".download",
        ".opdownload",
        ".filepart",
        ".partial",
    ];
    if NOISY_EXT.iter().any(|e| lower.ends_with(e)) {
        return true;
    }
    if lower.ends_with('~') {
        return true;
    }
    const NOISY_PREFIXES: &[&str] = &[
        "/tmp/",
        "/var/cache/",
        "/var/log/",
        "/var/tmp/",
        "/tmp/runc-process",
        "/tmp/claude-",
        "/tmp/.vscode-",
        "/tmp/node-compile-cache",
        "/tmp/v8-compile-cache",
        "/tmp/.bun/",
        "/tmp/org.chromium",
        "/tmp/com.brave",
        "/tmp/mozilla-",
    ];
    NOISY_PREFIXES.iter().any(|p| lower.starts_with(p))
        || {
            // ponytail: FP 14 Sep — USB watcher recursive masuk ke mirror Wine
            // (/run/media/.../dosdevices/z:/home/...) + repo/tooling (/.git/,
            // /node_modules/, /__pycache__/, /cache/). File di sini (git objects,
            // db snapshot, browser cache) bukan vektor infeksi workstation.
            // Ditambah $recycle.bin & system volume information untuk Windows.
            // Upgrade path: hapus pengecualian ini kalau scope diperluas ke
            // server-side FIM penuh (saat itu pakai allowlist, bukan denylist).
            const NOISY_CONTAINS: &[&str] = &[
                "/dosdevices/",
                "/.git/",
                "/node_modules/",
                "/__pycache__/",
                "/.cache/",
                "/cache/",
                "/$recycle.bin/",
                "/system volume information/",
            ];
            NOISY_CONTAINS.iter().any(|p| lower.contains(p))
        }
}

/// File dianggap selesai ditulis kalau ukurannya stabil 2x poll berurutan.
/// Tunggu maksimal ~8 detik; lewat itu skip (event modify berikutnya retrigger).
///
/// ponytail: FP 18 Sep — browser/Telegram tulis file bertahap (chunk per
/// detik); sleep 300ms bikin tiap chunk di-hash + POST (duplikat, hash
/// parsial, bahkan hash file kosong e3b0c44...). Tunggu stabil dulu.
/// Upgrade path: coalescing event per-path kalau volume tinggi.
const SETTLE_POLL_MS: u64 = 500;
const SETTLE_STABLE_NEEDED: u32 = 2;
const SETTLE_MAX_POLLS: u32 = 16;

/// Debounce per path: chunk duplikat dalam 60 detik = satu file yang sama.
/// Rename (.part -> final) beda path jadi tetap lolos.
const DEBOUNCE_SECS: u64 = 60;

async fn wait_settled(path: &Path) -> bool {
    let mut last_len: Option<u64> = None;
    let mut stable = 0u32;
    for _ in 0..SETTLE_MAX_POLLS {
        let len = match std::fs::metadata(path) {
            Ok(m) => m.len(),
            Err(_) => return false, // hilang di tengah tulis (rename/unlink)
        };
        if Some(len) == last_len {
            stable += 1;
            if stable >= SETTLE_STABLE_NEEDED {
                return true;
            }
        } else {
            stable = 0;
            last_len = Some(len);
        }
        tokio::time::sleep(Duration::from_millis(SETTLE_POLL_MS)).await;
    }
    false
}

/// Hitung jumlah direktori di bawah root TANPA mengikuti symlink, berhenti
/// setelah `limit` (hemat: cuma butuh tahu "kegedean atau tidak").
///
/// ponytail: gotcha 16 Sep 2026 — notify RecursiveMode::Recursive masuk ke
/// symlink Wine (dosdevices/z: -> /) di disk /run/media, bikin 515 ribu
/// inotify watch + RSS 490MB + CPU 95%. Walk ini pakai symlink_metadata
/// (tidak follow) supaya symlink tidak dihitung dan tidak dimasuki.
/// Upgrade path: allowlist mount removable kalau batas kasar ini kepentok.
fn count_dirs_bounded(root: &Path, limit: usize) -> usize {
    let mut count = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            // symlink_metadata: symlink tidak di-follow, jadi dosdevices/z:
            // terhitung sebagai 1 file dan TIDAK dimasuki.
            let meta = match std::fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_dir() {
                count += 1;
                if count >= limit {
                    return count;
                }
                stack.push(p);
            }
        }
    }
    count
}

/// Batas direktori per watch root. Flashdisk asli isinya ratusan direktori;
/// disk game/Wine (GamesRavi) ratusan ribu -> tolak dengan warn, bukan hang.
const MAX_WATCH_DIRS: usize = 5000;

/// Kandidat mount yang dipantau real-time (di luar watch path tetap).
/// Parity drive/watcher: Linux punya `/run/media/<user>` (flashdisk), Windows
/// tidak punya padanan sampai 15 Okt (Ramnit di G:\ lolos). Windows enumerasi
/// disk non-system (removable + HDD eksternal) via `sysinfo::Disks` (dependensi
/// yang sudah ada, tanpa crate baru).
#[cfg(unix)]
fn candidate_mounts() -> Vec<PathBuf> {
    let user = std::env::var("USER").unwrap_or_else(|_| "ravi".to_string());
    let usb_root = PathBuf::from(format!("/run/media/{}", user));
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&usb_root) {
        for entry in entries.flatten() {
            let p = entry.path();
            // symlink_metadata: entry mount berupa symlink, jangan di-follow.
            let is_real_dir = std::fs::symlink_metadata(&p)
                .map(|m| m.file_type().is_dir())
                .unwrap_or(false);
            if is_real_dir {
                out.push(p);
            }
        }
    }
    out
}

#[cfg(windows)]
fn candidate_mounts() -> Vec<PathBuf> {
    use sysinfo::Disks;
    let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let system = system.to_ascii_uppercase();
    Disks::new_with_refreshed_list()
        .list()
        .iter()
        .filter(|d| {
            let mp = d.mount_point().to_string_lossy().to_ascii_uppercase();
            !mp.starts_with(&system) && d.is_removable()
        })
        .map(|d| d.mount_point().to_path_buf())
        .collect()
}

/// Root scan terjadwal: pakai `--scan-roots` kalau diisi, kalau tidak ikut
/// `--watch`. Dipisah jadi fungsi murni supaya bisa diuji tanpa spawn task.
fn resolve_scan_roots(scan_roots: &Option<Vec<String>>, watch: &[PathBuf]) -> Vec<String> {
    scan_roots
        .clone()
        .unwrap_or_else(|| watch.iter().map(|p| p.display().to_string()).collect())
}

fn command_target_allowed(target: &Path, roots: &[PathBuf], action: &str) -> bool {
    if action == "restore" || action == "unquarantine" {
        return target.is_absolute()
            && !target.components().any(|c| matches!(c, std::path::Component::ParentDir));
    }
    let Ok(metadata) = std::fs::symlink_metadata(target) else {
        return false;
    };
    if metadata.file_type().is_symlink() {
        return false;
    }
    if action == "quarantine" && !metadata.is_file() {
        return false;
    }
    if action == "scan" && !metadata.is_dir() {
        return false;
    }
    let Ok(resolved_target) = std::fs::canonicalize(target) else {
        return false;
    };
    // ponytail: scan boleh ke path absolut mana pun (termasuk drive root dan
    // folder spesifik di drive eksternal — bukti Ramnit 15 Okt: walk root G:\
    // berhenti di cap 2000 sebelum mencapai folder yang terinfeksi, jadi
    // analis butuh memindai subfolder langsung). Aman karena scan cuma
    // hash read-only + laporan ringkasan (tanpa karantina per-file), dibatasi
    // MAX_SCAN_FILES, dan server memvalidasi ulang absolut + tanpa `..`.
    // Quarantine TETAP harus di watch root (aksi destruktif).
    // Upgrade path: allowlist per-drive kalau batas ini kepentok.
    if action == "scan" {
        return target.is_absolute()
            && !target.components().any(|c| {
                matches!(c, std::path::Component::ParentDir)
            });
    }
    roots.iter().any(|root| {
        std::fs::canonicalize(root)
            .map(|resolved_root| resolved_target.starts_with(resolved_root))
            .unwrap_or(false)
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    // Watch paths default: ~/Downloads + ~/Desktop (USB /run/media ditangani terpisah, ponytail: jangan recursive di autofs)
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/ravi".to_string());
    let default_watch = vec![
        format!("{}/Downloads", home),
        format!("{}/Desktop", home),
    ];
    // USB path /run/media/<user> ditangani khusus non-recursive biar tidak hang autofs, lihat bawah
    let watch_paths: Vec<PathBuf> = args
        .watch
        .clone()
        .unwrap_or(default_watch)
        .into_iter()
        .map(PathBuf::from)
        .collect();

    // Filter hanya yang ada, tapi log yang tidak ada (USB belum colok itu normal)
    let (existing, missing): (Vec<PathBuf>, Vec<PathBuf>) =
        watch_paths.into_iter().partition(|p| p.exists());
    if !missing.is_empty() {
        warn!(?missing, "watch path tidak ada, skip (USB belum colok?)");
    }
    let watch_paths = existing;
    if watch_paths.is_empty() {
        anyhow::bail!("tidak ada watch path yang ada: {:?}", args.watch);
    }

    info!(?watch_paths, webhook = %args.webhook, agent = %args.agent_name, "soar-agent Rust start");

    // Debounce: jangan kirim dua kali untuk file yang sama dalam 2 detik (FIM delete loop)
    // ponytail: HashMap ini tidak pernah di-evict; saat event storm (watch
    // nyasar ke seluruh /) dia ikut membengkak. Cap 10k, penuh = reset.
    let mut last_sent: HashMap<PathBuf, std::time::Instant> = HashMap::new();

    let (tx, rx) = channel();
    let watcher = Arc::new(Mutex::new(notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            let _ = tx.send(event);
        }
    })?));

    for p in &watch_paths {
        match watcher.lock().unwrap().watch(p, RecursiveMode::Recursive) {
            Ok(_) => info!(path = %p.display(), "watching"),
            Err(e) => warn!(path = %p.display(), error = %e, "gagal watch, skip"),
        }
    }

    let mut canaries = init_canaries(&watch_paths);

    // Drive/mount watcher (saran dospem: deteksi file malware dipindah dari
    // flashdisk). Parity lintas OS via `candidate_mounts()`: Linux `/run/media/
    // <user>`, Windows disk non-system. Mount baru otomatis di-watch RECURSIVE.
    // Ini nutup dua kelemahan lama: (1) flashdisk/drive colok belakangan tidak
    // ke-detect, (2) file di subfolder mount tidak ke-detect.
    // Upgrade path: udev/WM_DEVICECHANGE kalau polling 2s dirasa lambat.
    let watched_mounts: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
    // Mount yang ditolak karena kegedean: ingat supaya tidak di-scan ulang
    // (dan tidak spam log) tiap poll 2 detik. Dibersihkan saat dicabut.
    let rejected_mounts: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let watcher = watcher.clone();
        let watched_mounts = watched_mounts.clone();
        let rejected_mounts = rejected_mounts.clone();
        tokio::spawn(async move {
            loop {
                for p in candidate_mounts() {
                    if watched_mounts.lock().unwrap().contains(&p)
                        || rejected_mounts.lock().unwrap().contains(&p)
                    {
                        continue;
                    }
                    // Tolak mount raksasa SEBELUM watch: disk game/Wine
                    // isinya ratusan ribu direktori (notify men-follow
                    // symlink dosdevices/z: -> /). Cek murah (<1 detik
                    // untuk flashdisk normal, berhenti di limit).
                    let n_dirs = count_dirs_bounded(&p, MAX_WATCH_DIRS + 1);
                    if n_dirs > MAX_WATCH_DIRS {
                        warn!(path = %p.display(), n_dirs, "mount terlalu besar, skip watch (bukan flashdisk?)");
                        rejected_mounts.lock().unwrap().push(p.clone());
                        continue;
                    }
                    match watcher.lock().unwrap().watch(&p, RecursiveMode::Recursive) {
                        Ok(_) => {
                            watched_mounts.lock().unwrap().push(p.clone());
                            info!(path = %p.display(), n_dirs, "drive mounted, watching (recursive)");
                        }
                        Err(e) => warn!(path = %p.display(), error = %e, "gagal watch mount"),
                    }
                }
                // Bersihkan mount yang sudah dicabut (unwatch beneran:
                // retain saja tidak melepas kernel watch = leak).
                let mounted = candidate_mounts();
                {
                    let mut wm = watched_mounts.lock().unwrap();
                    wm.retain(|p| {
                        if mounted.contains(p) {
                            true
                        } else {
                            info!(path = %p.display(), "drive dicabut, unwatch");
                            let _ = watcher.lock().unwrap().unwatch(p);
                            false
                        }
                    });
                }
                // Bersihkan juga daftar tolak untuk mount yang sudah pergi
                // (nama mount dipakai ulang oleh media lain).
                rejected_mounts.lock().unwrap().retain(|p| mounted.contains(p));
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }

    // Quarantine HTTP endpoint (alternatif Wazuh Active Response)
    // ponytail: minimal, tidak pakai axum dulu, pakai tokio mpsc sederhana
    // Untuk POC minggu ini cukup, nanti bisa ganti axum jika butuh.
    let fleet_poll_token_file = if args.fleet_poll_token_file.is_empty() {
        std::env::var("SOAR_FLEET_POLL_TOKEN_FILE")
            .map_err(|_| anyhow::anyhow!("SOAR_FLEET_POLL_TOKEN_FILE wajib diisi"))?
    } else {
        args.fleet_poll_token_file.clone()
    };
    let fleet_poll_token = std::fs::read_to_string(&fleet_poll_token_file)
        .map_err(|e| anyhow::anyhow!("gagal baca {}: {}", fleet_poll_token_file, e))?
        .trim()
        .to_string();
    if fleet_poll_token.len() < 32 {
        anyhow::bail!("SOAR_FLEET_POLL_TOKEN_FILE kosong atau terlalu pendek");
    }
    let quarantine_port = args.listen_port;
    let command_roots = watch_paths.clone();
    let command_mounts = watched_mounts.clone();
    let local_roots = command_roots.clone();
    let local_mounts = command_mounts.clone();
    let local_quarantine_token = fleet_poll_token.clone();
    tokio::spawn(async move {
        if let Err(e) = quarantine_server(
            quarantine_port,
            local_quarantine_token,
            local_roots,
            local_mounts,
        )
        .await
        {
            warn!(error = %e, "quarantine server gagal bind (port sudah dipakai?), agent tetap jalan tanpa quarantine HTTP");
        }
    });

    // Client khusus scan: hashing + POST laporan besar bisa lama, jadi timeout
    // jauh lebih panjang dari client heartbeat (5s).
    let scan_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;

    // Heartbeat ke fleet-monitor (custom monitoring 100 PC, desain Wazuh, arahan dospem)
    // ponytail: satu task tokio, interval 60s, best-effort (jangan crash kalau fleet down)
    let fleet_url = args.fleet_url.clone();
    let hb_id = args.agent_id.clone();
    let hb_name = args.agent_name.clone();
    let hb_interval = args.heartbeat_secs;
    let hb_scan_client = scan_client.clone();
    let hb_watch_paths: Vec<String> = watch_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    tokio::spawn(async move {
        let poll_token = fleet_poll_token.clone();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build();
        let client = match client {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut sys = System::new_all();
        loop {
            let os = if cfg!(target_os = "windows") {
                "windows"
            } else if cfg!(target_os = "macos") {
                "macos"
            } else {
                "linux"
            };

            // ponytail: sysinfo 0.30 cross-platform (Linux + Windows).
            // refresh tiap heartbeat 60 dtk; cpu_usage butuh 2x refresh
            // berurutan jadi tick pertama 0 (server skip 0, tick berikut nyata).
            sys.refresh_cpu();
            sys.refresh_memory();

            let cpu_pct = sys.global_cpu_info().cpu_usage();

            // sysinfo 0.30 total_memory() = bytes -> GB
            let ram_total_gb = sys.total_memory() as f64 / 1_073_741_824.0;
            let ram_used_gb = sys.used_memory() as f64 / 1_073_741_824.0;

            let payload = serde_json::json!({
                "id": hb_id,
                "name": hb_name,
                "version": env!("CARGO_PKG_VERSION"),
                "os": os,
                "ip": "",
                "watch_paths": hb_watch_paths,
                "cpu_pct": (cpu_pct * 100.0).round() / 100.0,
                "ram_gb": {
                    "total": (ram_total_gb * 100.0).round() / 100.0,
                    "used": (ram_used_gb * 100.0).round() / 100.0,
                },
            });
            if let Err(e) = client.post(&fleet_url).json(&payload).send().await {
                warn!(error = %e, fleet_url = %fleet_url, "heartbeat fleet gagal");
            } else {
                info!(fleet_url = %fleet_url, "heartbeat fleet ok");
            }
            // ponytail: command queue di-poll bareng heartbeat (keluar-saja,
            // aman NAT, tanpa port inbound baru). Perintah dari tombol
            // dashboard dieksekusi lokal di sini.
            let base = fleet_url
                .trim_end_matches("/api/heartbeat")
                .trim_end_matches('/');
            let commands_url = format!("{}/api/commands?agent_id={}", base, hb_id);
            match client
                .get(&commands_url)
                .bearer_auth(poll_token.as_str())
                .send()
                .await
            {
                Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    warn!("poll commands ditolak: token agent tidak valid")
                }
                Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
                    Ok(v) => {
                        if let Some(cmds) = v.get("commands").and_then(|c| c.as_array()) {
                            for cmd in cmds {
                                let action = cmd.get("action").and_then(|a| a.as_str()).unwrap_or("");
                                let target = cmd.get("target").and_then(|t| t.as_str()).unwrap_or("");
                                if target.is_empty() {
                                    continue;
                                }
                                if action == "quarantine" || action == "scan" || action == "restore" || action == "unquarantine" {
                                    let mut roots = command_roots.clone();
                                    roots.extend(command_mounts.lock().unwrap().iter().cloned());
                                    if !command_target_allowed(Path::new(target), &roots, action) {
                                        warn!(action = %action, target = %target, "target command ditolak (bukan absolut / traversal / di luar watch root)");
                                        continue;
                                    }
                                }
                                match action {
                                    "quarantine" => match do_quarantine(target) {
                                        Ok(d) => info!(action = %action, target = %target, dest = %d, "perintah dashboard OK"),
                                        Err(e) => warn!(action = %action, target = %target, error = %e, "perintah dashboard gagal"),
                                    },
                                    "restore" | "unquarantine" => match do_restore(target) {
                                        Ok(d) => info!(action = %action, target = %target, detail = %d, "perintah restore OK"),
                                        Err(e) => warn!(action = %action, target = %target, error = %e, "perintah restore gagal"),
                                    },
                                    "sinkhole" => match do_sinkhole(target) {
                                        Ok(d) => info!(action = %action, target = %target, dest = %d, "perintah dashboard OK"),
                                        Err(e) => warn!(action = %action, target = %target, error = %e, "perintah dashboard gagal"),
                                    },
                                    "scan" => {
                                        let c = hb_scan_client.clone();
                                        let b = base.to_string();
                                        let id = hb_id.clone();
                                        let nm = hb_name.clone();
                                        let tgt = target.to_string();
                                        tokio::spawn(async move {
                                            match do_scan(&c, &b, &id, &nm, &tgt, "on-demand").await {
                                                Ok(d) => info!(action = "scan", target = %tgt, detail = %d, "perintah dashboard OK"),
                                                Err(e) => warn!(action = "scan", target = %tgt, error = %e, "perintah dashboard gagal"),
                                            }
                                        });
                                    }
                                    _ => warn!(action = %action, "aksi queue tak dikenal, lewati"),
                                }
                            }
                        }
                    }
                    Err(e) => warn!(error = %e, "parse commands gagal"),
                },
                Ok(resp) => warn!(status = %resp.status(), "poll commands ditolak"),
                Err(e) => warn!(error = %e, "poll commands gagal"),
            }
            tokio::time::sleep(Duration::from_secs(hb_interval)).await;
        }
    });

    // Scan terjadwal: menutup celah yang TIDAK bisa ditutup FIM, yaitu file
    // yang sudah ada di disk sebelum agent jalan, atau file yang masuk saat
    // agent mati (FIM hanya melihat event baru). Root default = watch path.
    // 0 = mati (default), supaya tidak mengagetkan agent existing.
    if args.scan_interval_secs > 0 {
        let roots = resolve_scan_roots(&args.scan_roots, &watch_paths);
        let base = args
            .fleet_url
            .trim_end_matches("/api/heartbeat")
            .trim_end_matches('/')
            .to_string();
        let id = args.agent_id.clone();
        let nm = args.agent_name.clone();
        let interval = args.scan_interval_secs;
        let client = scan_client.clone();
        info!(?roots, interval, "scan terjadwal aktif");
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(interval)).await;
                for root in &roots {
                    if !Path::new(root).is_dir() {
                        continue;
                    }
                    match do_scan(&client, &base, &id, &nm, root, "scheduled").await {
                        Ok(d) => info!(root = %root, detail = %d, "scan terjadwal OK"),
                        Err(e) => warn!(root = %root, error = %e, "scan terjadwal gagal"),
                    }
                    // Jeda antar-root: hindari spike CPU/panas saat hashing.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        });
    }

    // Satu HTTP client untuk semua POST jalur file (lihat post_with_retry).
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    loop {
        let event = match rx.recv() {
            Ok(e) => e,
            Err(_) => break,
        };

        // Hanya proses Create / Modify, abaikan Remove (hindari loop deleted di docs/arsitektur/FLOW.md:198)
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {}
            _ => continue,
        }

        for path in event.paths {
            if path.is_dir() || should_ignore(&path) {
                continue;
            }
            // Tunggu tulis selesai (stabil) sebelum hash: download bertahap
            // memicu event per chunk; tanpa ini tiap chunk jadi 1 POST FP.
            if !wait_settled(&path).await {
                continue;
            }

            if !path.exists() {
                continue;
            }

            // File kosong tidak di-hash: hash-nya selalu e3b0c44... (FP 18 Sep)
            // dan VT tidak bisa menilai apa-apa. Event modify saat isi datang
            // akan retrigger jalur ini lagi.
            if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) == 0 {
                info!(path = %path.display(), "file kosong, skip (tunggu isi)");
                continue;
            }

            // Debounce 60 detik per path (chunk duplikat = satu file yang sama)
            let now = std::time::Instant::now();
            if let Some(last) = last_sent.get(&path) {
                if now.duration_since(*last) < Duration::from_secs(DEBOUNCE_SECS) {
                    continue;
                }
            }
            if last_sent.len() > 10_000 {
                last_sent.clear();
            }
            last_sent.insert(path.clone(), now);

            // Deteksi dini Ransomware (Canary Decoy File Tampering - MITRE T1486)
            if let Some(expected_hash) = canaries.get(&path) {
                let current_hash = sha256_file(&path).unwrap_or_default();
                if current_hash != *expected_hash {
                    error!(path = %path.display(), "CANARY FILE TAMPERED! Indikasi serangan ransomware (MITRE T1486)");
                    let payload = build_canary_ransomware_payload(&args, &path, &current_hash);
                    post_with_retry(&http, &args.webhook, &payload, &path).await;
                    // Reset canary kembali ke konten awal agar siap mendeteksi serangan lanjutan
                    let _ = std::fs::write(&path, b"PK\x03\x04\x14\x00\x06\x00SOAR-CANARY-DECOY-BALI-HANDMADE-EARLY-WARNING\x00");
                    if let Ok(new_h) = sha256_file(&path) {
                        canaries.insert(path.clone(), new_h);
                    }
                }
                continue;
            }

            info!(path = %path.display(), "file event -> cek sensor phishing");

            let lower = path.to_string_lossy().to_lowercase();
            let is_url_file = lower.ends_with(".url")
                || lower.ends_with(".desktop")
                || lower.ends_with(".webloc");
            let is_html = lower.ends_with(".html") || lower.ends_with(".htm");

            // Sensor URL phishing (jalur reaktif Deteksi Phishing): ekstrak
            // http(s) dari shortcut/attachment (.url, .desktop, .webloc, .html)
            // lalu POST per URL.
            // Shortcut file = pointer saja -> phishing only jika URL ditemukan.
            // .html/.htm = attachment -> dua jalur (hash + URL).
            if is_url_file || is_html {
                let urls = extract_urls(&path);
                for url in &urls {
                    info!(url = %url, path = %path.display(), "URL -> webhook phishing");
                    let payload = build_phishing_payload(&args, &path, url);
                    post_with_retry(&http, &args.phishing_webhook, &payload, &path).await;
                }
                if is_url_file && !urls.is_empty() {
                    continue;
                }
            }

            if has_deceptive_double_extension(&path) {
                warn!(path = %path.display(), "terdeteksi penyamaran ekstensi ganda (T1036.007)");
            }

            info!(path = %path.display(), "file event -> hitung hash");

            let hash = match sha256_file(&path) {
                Ok(h) => h,
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "gagal hash, skip");
                    continue;
                }
            };

            let payload = build_payload(&args, &path, &hash);
            info!(hash = %hash, path = %path.display(), "POST ke n8n");
            post_with_retry(&http, &args.webhook, &payload, &path).await;
        }
    }

    Ok(())
}

async fn quarantine_server(
    port: u16,
    token: String,
    allowed_roots: Vec<PathBuf>,
    watched_mounts: Arc<Mutex<Vec<PathBuf>>>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!(addr = %addr, "quarantine HTTP listen");

    loop {
        let (mut socket, _) = listener.accept().await?;
        let request_token = token.clone();
        let request_roots = allowed_roots.clone();
        let request_mounts = watched_mounts.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match socket.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let (status, body) = if !request_has_bearer(&req, &request_token) {
                (
                    "401 Unauthorized",
                    serde_json::json!({"error": "unauthorized"}).to_string(),
                )
            } else {
                let (action_opt, path_opt) = extract_action_and_path(&req);
                let action = action_opt.unwrap_or_else(|| "quarantine".to_string());
                match path_opt {
                    Some(p) if {
                        let mut roots = request_roots.clone();
                        roots.extend(request_mounts.lock().unwrap().iter().cloned());
                        command_target_allowed(Path::new(&p), &roots, &action)
                    } => {
                        if action == "restore" || action == "unquarantine" {
                            match do_restore(&p) {
                                Ok(detail) => (
                                    "200 OK",
                                    serde_json::json!({"status": "restored", "detail": detail}).to_string(),
                                ),
                                Err(e) => (
                                    "500 Internal Server Error",
                                    serde_json::json!({"error": e.to_string()}).to_string(),
                                ),
                            }
                        } else {
                            match do_quarantine(&p) {
                                Ok(dest) => (
                                    "200 OK",
                                    serde_json::json!({"status": "quarantined", "dest": dest}).to_string(),
                                ),
                                Err(e) => (
                                    "500 Internal Server Error",
                                    serde_json::json!({"error": e.to_string()}).to_string(),
                                ),
                            }
                        }
                    }
                    Some(_) => (
                        "400 Bad Request",
                        serde_json::json!({"error": "target di luar watch root"}).to_string(),
                    ),
                    None => (
                        "400 Bad Request",
                        serde_json::json!({"error": "need {\"path\": \"...\"}"}).to_string(),
                    ),
                }
            };
            let resp = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        });
    }
}

fn request_has_bearer(request: &str, token: &str) -> bool {
    request.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case("authorization") && value.trim() == format!("Bearer {token}")
    })
}

fn extract_action_and_path(req: &str) -> (Option<String>, Option<String>) {
    let body_start = match req.find("\r\n\r\n").map(|i| i + 4) {
        Some(s) => s,
        None => return (None, None),
    };
    let body = &req[body_start..];
    let v: serde_json::Value = match serde_json::from_str(body.trim()) {
        Ok(val) => val,
        Err(_) => return (None, None),
    };
    let action = v.get("action").and_then(|a| a.as_str()).map(ToString::to_string);
    let path = v.get("path").and_then(|p| p.as_str()).map(ToString::to_string);
    (action, path)
}

#[allow(dead_code)]
fn extract_path(req: &str) -> Option<String> {
    extract_action_and_path(req).1
}

/// Sinkhole domain ke 0.0.0.0 di hosts file (perintah dashboard via queue).
/// Idempoten: entry ganda tidak ditulis ulang. Butuh privilege tulis hosts.
fn do_sinkhole(domain: &str) -> Result<String> {
    // Validasi ketat: satu label domain saja, tanpa spasi/karakter shell.
    if domain.is_empty()
        || domain.len() > 253
        || domain.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        || domain.parse::<std::net::IpAddr>().is_ok()
        || !domain.contains('.')
    {
        anyhow::bail!("domain tidak valid: {}", domain);
    }
    #[cfg(unix)]
    let hosts_path = "/etc/hosts";
    #[cfg(windows)]
    let hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    let entry = format!("0.0.0.0 {} # soar-sinkhole", domain);
    let content = std::fs::read_to_string(hosts_path).unwrap_or_default();
    if content.lines().any(|l| l.trim() == entry) {
        info!(domain = %domain, "sinkhole sudah ada, lewati");
        return Ok(entry);
    }
    // Backup sekali per hari (murah, tanpa lib tambahan).
    let backup = format!("{}.soar-bak", hosts_path);
    if !Path::new(&backup).exists() {
        let _ = std::fs::copy(hosts_path, &backup);
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(hosts_path)?;
    writeln!(f, "{}", entry)?;
    info!(domain = %domain, "sinkholed via hosts");
    Ok(entry)
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct QuarantineRecord {
    quarantined: String,
    original: String,
    timestamp: i64,
}

fn is_writable_dir(p: &Path) -> bool {
    if std::fs::create_dir_all(p).is_err() {
        return false;
    }
    let probe = p.join(format!(".write-probe-{}", std::process::id()));
    if std::fs::write(&probe, b"").is_ok() {
        let _ = std::fs::remove_file(probe);
        true
    } else {
        false
    }
}

fn get_quarantine_dir() -> PathBuf {
    #[cfg(unix)]
    let candidates = {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let fallback = format!("{}/.soar-quarantine", home);
        vec![
            PathBuf::from("/var/ossec/quarantine"),
            PathBuf::from(&fallback),
            PathBuf::from("/tmp/soar-quarantine"),
        ]
    };
    #[cfg(windows)]
    let candidates = {
        let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string());
        let fallback = format!("{}\\AppData\\Local\\soar-quarantine", home);
        vec![
            PathBuf::from(&fallback),
            PathBuf::from("C:\\ProgramData\\soar-quarantine"),
        ]
    };
    candidates
        .into_iter()
        .find(|p| is_writable_dir(p))
        .unwrap_or_else(|| PathBuf::from("/tmp/soar-quarantine"))
}

fn read_quarantine_manifest(qdir: &Path) -> Vec<QuarantineRecord> {
    let mpath = qdir.join("manifest.json");
    if let Ok(content) = std::fs::read_to_string(&mpath) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        vec![]
    }
}

fn write_quarantine_manifest(qdir: &Path, records: &[QuarantineRecord]) -> Result<()> {
    let mpath = qdir.join("manifest.json");
    let content = serde_json::to_string_pretty(records)?;
    std::fs::write(mpath, content)?;
    Ok(())
}

fn do_quarantine(path: &str) -> Result<String> {
    let src = Path::new(path);
    if !src.exists() {
        anyhow::bail!("file tidak ada: {}", path);
    }
    let quarantine_dir = get_quarantine_dir();
    std::fs::create_dir_all(&quarantine_dir)?;
    let filename = src.file_name().unwrap_or_default().to_string_lossy();
    let ts = chrono::Utc::now().timestamp();
    let dest = quarantine_dir.join(format!("{}.{}.quarantined", filename, ts));
    std::fs::rename(src, &dest).or_else(|e: std::io::Error| {
        if e.raw_os_error() != Some(18) {
            return Err(e);
        }
        std::fs::copy(src, &dest)?;
        std::fs::remove_file(src)?;
        Ok(())
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o000));
    }

    // Catat ke manifest untuk mendukung pemulihan (unquarantine / restore)
    let mut records = read_quarantine_manifest(&quarantine_dir);
    records.retain(|r| r.original != path);
    records.push(QuarantineRecord {
        quarantined: dest.to_string_lossy().to_string(),
        original: path.to_string(),
        timestamp: ts,
    });
    let _ = write_quarantine_manifest(&quarantine_dir, &records);

    info!(src = %path, dest = %dest.display(), "quarantined");
    Ok(dest.to_string_lossy().to_string())
}

/// Memulihkan berkas dari karantina kembali ke lokasi aslinya.
/// Mendukung pencarian via original_path atau quarantined_path di manifest,
/// dengan fallback pemulihan berkas berakhiran .quarantined langsung.
fn do_restore(target: &str) -> Result<String> {
    let quarantine_dir = get_quarantine_dir();
    let mut records = read_quarantine_manifest(&quarantine_dir);

    let record_idx = records.iter().position(|r| r.original == target || r.quarantined == target);
    if let Some(idx) = record_idx {
        let record = records.remove(idx);
        let qpath = Path::new(&record.quarantined);
        let orig_path = Path::new(&record.original);

        if !qpath.exists() {
            anyhow::bail!("berkas karantina tidak ditemukan: {}", record.quarantined);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(qpath, std::fs::Permissions::from_mode(0o644));
        }

        if let Some(parent) = orig_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::rename(qpath, orig_path).or_else(|e: std::io::Error| {
            if e.raw_os_error() != Some(18) {
                return Err(e);
            }
            std::fs::copy(qpath, orig_path)?;
            std::fs::remove_file(qpath)?;
            Ok(())
        })?;

        let _ = write_quarantine_manifest(&quarantine_dir, &records);
        info!(quarantined = %record.quarantined, original = %record.original, "restored");
        return Ok(format!("restored {} to {}", record.quarantined, record.original));
    }

    // Fallback: jika target adalah path berkas .quarantined langsung
    let qpath = Path::new(target);
    if qpath.exists() && target.ends_with(".quarantined") {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(qpath, std::fs::Permissions::from_mode(0o644));
        }
        let fname = qpath.file_name().unwrap_or_default().to_string_lossy();
        let stripped = if let Some(last_dot) = fname.rfind(".quarantined") {
            let without_ext = &fname[..last_dot];
            if let Some(ts_dot) = without_ext.rfind('.') {
                &without_ext[..ts_dot]
            } else {
                without_ext
            }
        } else {
            &fname
        };
        let orig = qpath.with_file_name(stripped);
        std::fs::rename(qpath, &orig)?;
        return Ok(format!("restored {} to {}", target, orig.display()));
    }

    anyhow::bail!("tidak ditemukan catatan karantina untuk target: {}", target)
}

/// Batas file per scan on-demand. Folder pilihan (bukan full disk): cukup besar
/// untuk Downloads/USB, tetap kecil biar waktu hash + payload tidak meledak.
const MAX_SCAN_FILES: usize = 2000;

/// Satu scan pada satu waktu (on-demand vs terjadwal). Serialisasi ini
/// mencegah dua walk hashing bareng yang bikin CPU/laptop panas.
static SCAN_BUSY: AtomicBool = AtomicBool::new(false);

struct ScanGuard;
impl Drop for ScanGuard {
    fn drop(&mut self) {
        SCAN_BUSY.store(false, Ordering::SeqCst);
    }
}

/// Kumpulkan file target scan di bawah `root` (rekursif, TANPA follow symlink).
/// Melewati file yang di-ignore sensor, file 0-byte, dan non-file. Bounded:
/// berhenti setelah `max` file -> (paths, truncated).
fn collect_scan_targets(root: &Path, max: usize) -> (Vec<PathBuf>, bool) {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut truncated = false;
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            // symlink_metadata: symlink tidak di-follow (gotcha Wine dosdevices/z:).
            let meta = match std::fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let ft = meta.file_type();
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(p);
                continue;
            }
            if !ft.is_file() || meta.len() == 0 || should_ignore(&p) {
                continue;
            }
            if out.len() >= max {
                truncated = true;
                break;
            }
            out.push(p);
        }
        if truncated {
            break;
        }
    }
    (out, truncated)
}

/// Scan on-demand: hash semua file di folder pilihan lalu kirim SATU laporan
/// ringkasan ke fleet (`POST /api/scan-result`) — bukan alert per-file, biar
/// Telegram & dedup tidak kebanjiran. Cache-first: fleet yang menandai hash
/// baru vs sudah dikenal.
async fn do_scan(
    client: &reqwest::Client,
    base: &str,
    agent_id: &str,
    agent_name: &str,
    path: &str,
    trigger: &str,
) -> Result<String> {
    let root = Path::new(path);
    if !root.is_dir() {
        anyhow::bail!("folder tidak ada atau bukan direktori: {}", path);
    }
    if SCAN_BUSY.swap(true, Ordering::SeqCst) {
        anyhow::bail!("scan lain sedang berjalan, lewati");
    }
    let _guard = ScanGuard;
    let started = std::time::Instant::now();
    let (targets, truncated) = collect_scan_targets(root, MAX_SCAN_FILES);
    let mut files = Vec::with_capacity(targets.len());
    let mut total_bytes: u64 = 0;
    for p in &targets {
        let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        match sha256_file(p) {
            Ok(h) => {
                total_bytes += size;
                files.push(serde_json::json!({
                    "path": p.to_string_lossy(),
                    "size": size,
                    "sha256": h,
                }));
            }
            Err(e) => warn!(path = %p.display(), error = %e, "scan: gagal hash, skip"),
        }
    }
    let n = files.len();
    let report = serde_json::json!({
        "agent_id": agent_id,
        "agent_name": agent_name,
        "path": path,
        "trigger": trigger,
        "started": chrono::Utc::now().to_rfc3339(),
        "elapsed_ms": started.elapsed().as_millis() as u64,
        "scanned": n,
        "truncated": truncated,
        "total_bytes": total_bytes,
        "files": files,
    });
    let url = format!("{}/api/scan-result", base);
    let resp = client.post(&url).json(&report).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("fleet {} -> {}", url, resp.status());
    }
    info!(path = %path, files = n, truncated, trigger = %trigger, "scan terkirim");
    Ok(format!(
        "{} file, {} byte{}",
        n,
        total_bytes,
        if truncated { ", dipotong di batas" } else { "" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn ignore_fp_noise_14sep() {
        // FP nyata 14 Sep: mirror Wine + git objects + sqlite WAL + cache
        for p in [
            "/run/media/ravi/GamesRavi/anime-game-launcher/prefix/dosdevices/z:/home/ravi/.local/share/opencode/opencode-stable.db-wal",
            "/run/media/ravi/X/prefix/dosdevices/c:/Cols distribution/setup.exe",
            "/home/ravi/Projects/soar-project/.git/objects/39/5b802d685e32b69fbfca5202df78c907366d53",
            "/home/ravi/x/node_modules/.bin/jest",
            "/home/ravi/x/__pycache__/a.pyc",
            "/home/ravi/.cache/mozilla/firefox/1.cache",
            "/home/ravi/Downloads/app.iso",
            "/tmp/.vscode-server/x",
            "/home/ravi/doc.txt~",
            "/home/ravi/a.db-shm",
            r"I:\$RECYCLE.BIN\S-1-5-21-2998944698-2190097625-1310765221-1001\desktop.ini",
            r"C:\$Recycle.Bin\desktop.ini",
            r"C:\Users\Bapak\Downloads\desktop.ini",
            r"C:\Users\Bapak\Downloads\thumbs.db",
            r"D:\System Volume Information\WPSettings.dat",
        ] {
            assert!(should_ignore(Path::new(p)), "harus diabaikan: {p}");
        }
        // Vektor asli tetap lolos: exe/zip/script di Downloads, Desktop, USB non-mirror
        for p in [
            "/home/ravi/Downloads/invoice.exe",
            "/home/ravi/Desktop/update.zip",
            "/run/media/ravi/FLASHDISK/crack.bat",
            "C:\\Users\\Bapak\\Downloads\\doc.pdf.exe",
        ] {
            assert!(!should_ignore(Path::new(p)), "jangan diabaikan: {p}");
        }
    }

    #[test]
    fn ignore_partial_download_18sep() {
        // FP 18 Sep: download belum lengkap (hash parsial/duplikat di Events).
        for p in [
            "C:\\Users\\Toshiba L735\\Downloads\\qHzgjWFa.zip.part",
            "/home/ravi/Downloads/file.crdownload",
            "/home/ravi/Downloads/video.download",
            "/home/ravi/Downloads/a.opdownload",
            "/home/ravi/Downloads/b.filepart",
        ] {
            assert!(should_ignore(Path::new(p)), "harus diabaikan: {p}");
        }
        // File final (hasil rename) tetap lolos.
        for p in [
            "C:\\Users\\Toshiba L735\\Downloads\\qHzgjWFa.zip",
            "/home/ravi/Downloads/garuda.jpg",
            "/home/ravi/Downloads/laporan.xlsx",
        ] {
            assert!(!should_ignore(Path::new(p)), "jangan diabaikan: {p}");
        }
    }

    #[tokio::test]
    async fn wait_settled_stabil_dan_hilang() {
        let dir = std::env::temp_dir().join("soar-test-settled");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("lengkap.bin");
        std::fs::write(&f, vec![7u8; 1024]).unwrap();
        assert!(wait_settled(&f).await); // stabil -> true (~1 detik)
        assert!(!wait_settled(&dir.join("tidak-ada.bin")).await); // hilang -> false
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn count_dirs_tidak_follow_symlink_dan_berhenti_di_limit() {
        let dir = std::env::temp_dir().join("soar-test-countdirs");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::create_dir_all(dir.join("c")).unwrap();
        // Symlink ke / (tiruan dosdevices/z:): tidak boleh dimasuki.
        #[cfg(unix)]
        std::os::unix::fs::symlink("/", dir.join("z")).ok();
        assert_eq!(count_dirs_bounded(&dir, 100), 3); // a, a/b, c (z bukan dir)
        assert_eq!(count_dirs_bounded(&dir, 2), 2); // berhenti di limit
        // Root tidak ada = 0, bukan panic.
        assert_eq!(count_dirs_bounded(Path::new("/tidak-ada-xyz"), 100), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extract_urls_dari_shortcut_dan_html() {
        let dir = std::env::temp_dir();
        let url_path = dir.join("soar-test-invoice.url");
        std::fs::write(
            &url_path,
            "[InternetShortcut]\nURL=https://phish.example.com/login?u=1\nIconFile=x\n",
        )
        .unwrap();
        assert_eq!(
            extract_urls(&url_path),
            vec!["https://phish.example.com/login?u=1".to_string()]
        );

        let html_path = dir.join("soar-test-faktur.html");
        std::fs::write(
            &html_path,
            "<html><a href=\"http://a.example/x\">klik</a> dan http://a.example/x lagi, lalu https://b.example/y.</html>",
        )
        .unwrap();
        // Duplikat dibuang, trailing titik dibuang
        assert_eq!(
            extract_urls(&html_path),
            vec!["http://a.example/x".to_string(), "https://b.example/y".to_string()]
        );

        let kosong = dir.join("soar-test-kosong.html");
        std::fs::write(&kosong, "<html>tidak ada link</html>").unwrap();
        assert!(extract_urls(&kosong).is_empty());

        std::fs::remove_file(&url_path).ok();
        std::fs::remove_file(&html_path).ok();
        std::fs::remove_file(&kosong).ok();
    }

    #[test]
    fn collect_scan_targets_skip_noise_dan_batas() {
        // Simpan di target/ (BUKAN /tmp): should_ignore memfilter prefix /tmp/.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/soar-test-scanwalk");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.bin"), b"x").unwrap();
        std::fs::write(dir.join("sub/b.exe"), b"y").unwrap();
        std::fs::write(dir.join("noise.log"), b"z").unwrap(); // NOISY_EXT
        std::fs::write(dir.join("empty.txt"), b"").unwrap(); // 0-byte
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("a.bin"), dir.join("link.bin")).ok();

        let (files, truncated) = collect_scan_targets(&dir, 100);
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"a.bin".to_string()), "file normal harus ikut");
        assert!(names.contains(&"b.exe".to_string()), "file di subfolder harus ikut");
        assert!(!names.contains(&"noise.log".to_string()), "ekstensi noise harus diabaikan");
        assert!(!names.contains(&"empty.txt".to_string()), "file 0-byte harus diabaikan");
        assert!(!names.contains(&"link.bin".to_string()), "symlink tidak di-follow");
        assert!(!truncated, "di bawah batas -> tidak terpotong");

        // Batas: minta 1 file -> tepat 1 + truncated.
        let (one, trunc1) = collect_scan_targets(&dir, 1);
        assert_eq!(one.len(), 1);
        assert!(trunc1, "melewati batas -> truncated true");

        // Root tidak ada = kosong, bukan panic.
        let (none, _) = collect_scan_targets(Path::new("/tidak-ada-xyz-scan"), 100);
        assert!(none.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn local_quarantine_request_memerlukan_bearer() {
        let request = "POST /quarantine HTTP/1.1\r\nAuthorization: Bearer token-123\r\n\r\n{}";
        assert!(request_has_bearer(request, "token-123"));
        assert!(!request_has_bearer(request, "token-456"));
        assert!(!request_has_bearer("POST /quarantine HTTP/1.1\r\n\r\n{}", "token-123"));
    }

    #[test]
    fn command_target_hanya_boleh_di_watch_root() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/soar-test-command-root");
        let outside = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/soar-test-command-outside");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("sample.bin");
        std::fs::write(&file, b"x").unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("x.bin"), b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&file, root.join("link.bin")).ok();

        let roots = vec![root.clone()];
        assert!(command_target_allowed(&file, &roots, "quarantine"));
        assert!(command_target_allowed(&root, &roots, "scan"));
        assert!(!command_target_allowed(&outside, &roots, "quarantine"));
        assert!(!command_target_allowed(&root, &roots, "quarantine"));
        // Scan boleh ke path absolut mana pun (bukti Ramnit 15 Okt: subfolder
        // drive eksternal), quarantine tetap tidak boleh.
        // Traversal `..` selalu ditolak (server memvalidasi ulang juga).
        #[cfg(unix)]
        {
            assert!(command_target_allowed(Path::new("/"), &roots, "scan"));
            assert!(!command_target_allowed(Path::new("/"), &roots, "quarantine"));
            assert!(command_target_allowed(&outside, &roots, "scan"));
            assert!(!command_target_allowed(
                Path::new("/tmp/../etc"),
                &roots,
                "scan"
            ));
        }
        #[cfg(unix)]
        assert!(!command_target_allowed(&root.join("link.bin"), &roots, "quarantine"));

        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn resolve_scan_roots_default_ikut_watch_dan_override() {
        let watch = vec![PathBuf::from("/home/ravi/Downloads")];
        // Tanpa --scan-roots: ikut watch path.
        assert_eq!(
            resolve_scan_roots(&None, &watch),
            vec!["/home/ravi/Downloads".to_string()]
        );
        // Dengan --scan-roots: pakai itu, watch diabaikan.
        let explicit = Some(vec!["C:\\".to_string(), "D:\\data".to_string()]);
        assert_eq!(
            resolve_scan_roots(&explicit, &watch),
            vec!["C:\\".to_string(), "D:\\data".to_string()]
        );
    }

    #[test]
    fn extract_urls_dari_desktop_dan_webloc() {
        let dir = std::env::temp_dir();

        // 1. Linux .desktop shortcut
        let desktop_path = dir.join("soar-test-login.desktop");
        std::fs::write(
            &desktop_path,
            "[Desktop Entry]\nEncoding=UTF-8\nType=Link\nName=HRD Portal\nURL=https://phish-portal.example.com/hrd\n",
        )
        .unwrap();
        assert_eq!(
            extract_urls(&desktop_path),
            vec!["https://phish-portal.example.com/hrd".to_string()]
        );

        // 2. macOS .webloc XML plist
        let webloc_path = dir.join("soar-test-doc.webloc");
        std::fs::write(
            &webloc_path,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>URL</key><string>https://verify.appleid-phish.net/login</string></dict></plist>",
        )
        .unwrap();
        assert_eq!(
            extract_urls(&webloc_path),
            vec!["https://verify.appleid-phish.net/login".to_string()]
        );

        std::fs::remove_file(&desktop_path).ok();
        std::fs::remove_file(&webloc_path).ok();
    }

    #[test]
    fn deceptive_double_extension_detection() {
        // Positif terdeteksi (T1036.007 Masquerading)
        for p in [
            "invoice.pdf.exe",
            "pembayaran.docx.vbs",
            "foto_karyawan.jpg.bat",
            "daftar_gaji.xlsx.scr",
            "tagihan.pdf.cmd",
            "faktur.png.pif",
            "C:\\Users\\User\\Downloads\\surat.doc.exe",
            "/home/user/Downloads/slip.pdf.js",
        ] {
            assert!(
                has_deceptive_double_extension(Path::new(p)),
                "harus terdeteksi ekstensi ganda: {p}"
            );
        }

        // Negatif / bersih (bukan penyamaran berbahaya)
        for p in [
            "dokumen.pdf",
            "laporan.docx",
            "program.exe",
            "arsip.tar.gz",
            "catatan.doc.txt",
            "style.min.js",
            "/usr/bin/python3",
            "C:\\Windows\\notepad.exe",
        ] {
            assert!(
                !has_deceptive_double_extension(Path::new(p)),
                "jangan terdeteksi sebagai ekstensi ganda berbahaya: {p}"
            );
        }

        // Verifikasi integrasi build_payload
        let args = Args {
            agent_id: "009".to_string(),
            agent_name: "test-agent".to_string(),
            webhook: "http://127.0.0.1:5678/webhook/test".to_string(),
            phishing_webhook: "http://127.0.0.1:5678/webhook/phish".to_string(),
            fleet_url: "http://127.0.0.1:8080/api/heartbeat".to_string(),
            watch: None,
            listen_port: 8787,
            fleet_poll_token_file: "".to_string(),
            heartbeat_secs: 60,
            scan_interval_secs: 0,
            scan_roots: None,
        };

        let normal_payload = build_payload(&args, Path::new("/tmp/test.exe"), "abc123hash");
        assert_eq!(normal_payload["rule"]["id"], "554");
        assert_eq!(normal_payload["rule"]["level"], 5);
        assert_eq!(normal_payload["data"]["is_double_extension"], false);

        let deceptive_payload = build_payload(&args, Path::new("/tmp/invoice.pdf.exe"), "bad123hash");
        assert_eq!(deceptive_payload["rule"]["id"], "100003");
        assert_eq!(deceptive_payload["rule"]["level"], 8);
        assert_eq!(deceptive_payload["data"]["is_double_extension"], true);
    }

    #[test]
    fn quarantine_manifest_and_restore_cycle() {
        let dir = std::env::temp_dir().join("soar-test-quar-restore");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let sample_file = dir.join("malicious_test.exe");
        std::fs::write(&sample_file, b"DUMMY_MALWARE_PAYLOAD").unwrap();
        assert!(sample_file.exists());

        // Jalankan karantina
        let q_dest = do_quarantine(&sample_file.to_string_lossy()).unwrap();
        assert!(!sample_file.exists(), "file sumber harus dipindahkan");
        assert!(Path::new(&q_dest).exists(), "file tujuan karantina harus ada");

        // Periksa manifest karantina
        let qdir = get_quarantine_dir();
        let records = read_quarantine_manifest(&qdir);
        let found = records.iter().any(|r| r.original == sample_file.to_string_lossy());
        assert!(found, "manifest harus mencatat path asal");

        // Jalankan pemulihan (restore) via original path
        let restore_res = do_restore(&sample_file.to_string_lossy()).unwrap();
        assert!(restore_res.contains("restored"));
        assert!(sample_file.exists(), "file harus kembali ke lokasi asal");
        assert!(!Path::new(&q_dest).exists(), "file karantina harus sudah dipindahkan");

        // Entri harus terhapus dari manifest setelah restore
        let records_after = read_quarantine_manifest(&qdir);
        assert!(!records_after.iter().any(|r| r.original == sample_file.to_string_lossy()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn canary_ransomware_tampering() {
        let dir = std::env::temp_dir().join("soar-test-canary");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let canaries = init_canaries(&[dir.clone()]);
        let canary_path = dir.join(".soar-canary.docx");
        assert!(canary_path.exists());
        assert!(canaries.contains_key(&canary_path));

        let initial_hash = canaries.get(&canary_path).unwrap();
        assert_eq!(sha256_file(&canary_path).unwrap(), *initial_hash);

        // Simulasi ransomware: modifikasi/enkripsi file canary
        std::fs::write(&canary_path, b"ENCRYPTED_BY_RANSOMWARE_LOCKED").unwrap();
        let tampered_hash = sha256_file(&canary_path).unwrap();
        assert_ne!(tampered_hash, *initial_hash);

        let args = Args {
            agent_id: "009".to_string(),
            agent_name: "test-agent".to_string(),
            webhook: "http://127.0.0.1:5678/webhook/test".to_string(),
            phishing_webhook: "http://127.0.0.1:5678/webhook/phish".to_string(),
            fleet_url: "http://127.0.0.1:8080/api/heartbeat".to_string(),
            watch: None,
            listen_port: 8787,
            fleet_poll_token_file: "".to_string(),
            heartbeat_secs: 60,
            scan_interval_secs: 0,
            scan_roots: None,
        };

        let canary_payload = build_canary_ransomware_payload(&args, &canary_path, &tampered_hash);
        assert_eq!(canary_payload["rule"]["id"], "100004");
        assert_eq!(canary_payload["rule"]["level"], 12);
        assert_eq!(canary_payload["data"]["is_canary_tampered"], true);
        assert_eq!(canary_payload["data"]["attack_technique"], "T1486");

        std::fs::remove_dir_all(&dir).ok();
    }
}
