use anyhow::Result;
use clap::Parser;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
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

    #[arg(long, default_value = "60")]
    heartbeat_secs: u64,
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

fn build_payload(args: &Args, path: &Path, hash: &str) -> serde_json::Value {
    let perm = get_perm(path);
    let size = std::fs::metadata(path)
        .map(|m| m.len().to_string())
        .unwrap_or_else(|_| "0".to_string());

    serde_json::json!({
        "rule": {"id": "554", "level": 5, "description": "File added to the system."},
        "agent": {"id": args.agent_id, "name": args.agent_name},
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "data": {
            "sha256_after": hash,
            "path": path.to_string_lossy(),
            "srcip": "0.0.0.0"
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
    let s = path.to_string_lossy();
    // ponytail: filter sama dengan scripts/custom-n8n.py noise filter
    // jangan kirim /tmp, /var/cache, dll biar hemat VT quota
    // Juga filter ekstensi noise: file ISO installer, DS_Store, thumbs.db
    let lower = path.to_string_lossy().to_lowercase();
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
    NOISY_PREFIXES.iter().any(|p| s.starts_with(p))
        || {
            // ponytail: FP 14 Sep — USB watcher recursive masuk ke mirror Wine
            // (/run/media/.../dosdevices/z:/home/...) + repo/tooling (/.git/,
            // /node_modules/, /__pycache__/, /cache/). File di sini (git objects,
            // db snapshot, browser cache) bukan vektor infeksi workstation.
            // Upgrade path: hapus pengecualian ini kalau scope diperluas ke
            // server-side FIM penuh (saat itu pakai allowlist, bukan denylist).
            const NOISY_CONTAINS: &[&str] = &[
                "/dosdevices/",
                "/.git/",
                "/node_modules/",
                "/__pycache__/",
                "/.cache/",
                "/cache/",
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

    // USB dynamic scanner (saran dospem: deteksi file malware dipindah dari flashdisk)
    // ponytail: scan /run/media/<user> tiap 2s; mount baru otomatis di-watch RECURSIVE.
    // Ini nutup dua kelemahan lama: (1) flashdisk colok belakangan tidak ke-detect,
    // (2) file di subfolder mount tidak ke-detect (non-recursive lama).
    // Upgrade path: udev/kernel inotify pada mount event kalau polling 2s dirasa lambat.
    let user = std::env::var("USER").unwrap_or_else(|_| "ravi".to_string());
    let usb_root = PathBuf::from(format!("/run/media/{}", user));
    let watched_mounts: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
    // Mount yang ditolak karena kegedean: ingat supaya tidak di-scan ulang
    // (dan tidak spam log) tiap poll 2 detik. Dibersihkan saat dicabut.
    let rejected_mounts: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let watcher = watcher.clone();
        let watched_mounts = watched_mounts.clone();
        let rejected_mounts = rejected_mounts.clone();
        let usb_root = usb_root.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(entries) = std::fs::read_dir(&usb_root) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        // symlink_metadata dulu: mount entry berupa symlink
                        // jangan di-watch (is_dir() mem-follow symlink).
                        let is_real_dir = std::fs::symlink_metadata(&p)
                            .map(|m| m.file_type().is_dir())
                            .unwrap_or(false);
                        if !is_real_dir
                            || watched_mounts.lock().unwrap().contains(&p)
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
                                info!(path = %p.display(), n_dirs, "USB mounted, watching (recursive)");
                            }
                            Err(e) => warn!(path = %p.display(), error = %e, "gagal watch USB mount"),
                        }
                    }
                    // Bersihkan mount yang sudah dicabut (unwatch beneran:
                    // retain saja tidak melepas kernel watch = leak).
                    let mounted: Vec<PathBuf> = std::fs::read_dir(&usb_root)
                        .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect())
                        .unwrap_or_default();
                    let mut wm = watched_mounts.lock().unwrap();
                    wm.retain(|p| {
                        if mounted.contains(p) {
                            true
                        } else {
                            info!(path = %p.display(), "USB dicabut, unwatch");
                            let _ = watcher.lock().unwrap().unwatch(p);
                            false
                        }
                    });
                    // Bersihkan juga daftar tolak untuk mount yang sudah pergi
                    // (nama mount dipakai ulang oleh media lain).
                    rejected_mounts.lock().unwrap().retain(|p| mounted.contains(p));
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }

    // Quarantine HTTP endpoint (alternatif Wazuh Active Response)
    // ponytail: minimal, tidak pakai axum dulu, pakai tokio mpsc sederhana
    // Untuk POC minggu ini cukup, nanti bisa ganti axum jika butuh.
    let quarantine_port = args.listen_port;
    tokio::spawn(async move {
        if let Err(e) = quarantine_server(quarantine_port).await {
            warn!(error = %e, "quarantine server gagal bind (port sudah dipakai?), agent tetap jalan tanpa quarantine HTTP");
        }
    });

    // Heartbeat ke fleet-monitor (custom monitoring 100 PC, desain Wazuh, arahan dospem)
    // ponytail: satu task tokio, interval 60s, best-effort (jangan crash kalau fleet down)
    let fleet_url = args.fleet_url.clone();
    let hb_id = args.agent_id.clone();
    let hb_name = args.agent_name.clone();
    let hb_interval = args.heartbeat_secs;
    tokio::spawn(async move {
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
            match client.get(&commands_url).send().await {
                Ok(resp) => match resp.json::<serde_json::Value>().await {
                    Ok(v) => {
                        if let Some(cmds) = v.get("commands").and_then(|c| c.as_array()) {
                            for cmd in cmds {
                                let action = cmd.get("action").and_then(|a| a.as_str()).unwrap_or("");
                                let target = cmd.get("target").and_then(|t| t.as_str()).unwrap_or("");
                                if target.is_empty() {
                                    continue;
                                }
                                let res = match action {
                                    "quarantine" => do_quarantine(target).map(|d| d),
                                    "sinkhole" => do_sinkhole(target).map(|d| d),
                                    _ => {
                                        warn!(action = %action, "aksi queue tak dikenal, lewati");
                                        continue;
                                    }
                                };
                                match res {
                                    Ok(d) => info!(action = %action, target = %target, dest = %d, "perintah dashboard OK"),
                                    Err(e) => warn!(action = %action, target = %target, error = %e, "perintah dashboard gagal"),
                                }
                            }
                        }
                    }
                    Err(e) => warn!(error = %e, "parse commands gagal"),
                },
                Err(e) => warn!(error = %e, "poll commands gagal"),
            }
            tokio::time::sleep(Duration::from_secs(hb_interval)).await;
        }
    });

    // Satu HTTP client untuk semua POST jalur file (lihat post_with_retry).
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    loop {
        let event = match rx.recv() {
            Ok(e) => e,
            Err(_) => break,
        };

        // Hanya proses Create / Modify, abaikan Remove (hindari loop deleted di docs/FLOW.md:198)
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

            info!(path = %path.display(), "file event -> cek sensor phishing");

            let lower = path.to_string_lossy().to_lowercase();
            let is_url_file = lower.ends_with(".url");
            let is_html = lower.ends_with(".html") || lower.ends_with(".htm");

            // Sensor URL phishing (jalur reaktif Deteksi Phishing): ekstrak
            // http(s) dari shortcut/attachment lalu POST per URL.
            // .url = pointer saja -> phishing only (hash file-nya tak bermakna
            // buat VT). .html/.htm = attachment -> dua jalur (hash + URL).
            if is_url_file || is_html {
                for url in extract_urls(&path) {
                    info!(url = %url, path = %path.display(), "URL -> webhook phishing");
                    let payload = build_phishing_payload(&args, &path, &url);
                    post_with_retry(&http, &args.phishing_webhook, &payload, &path).await;
                }
                if is_url_file {
                    continue;
                }
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

async fn quarantine_server(port: u16) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!(addr = %addr, "quarantine HTTP listen");

    loop {
        let (mut socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match socket.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            // Cari path dari body JSON {"path": "..."}
            let path_opt = extract_path(&req);
            let (status, body) = match path_opt {
                Some(p) => match do_quarantine(&p) {
                    Ok(dest) => (
                        "200 OK",
                        serde_json::json!({"status": "quarantined", "dest": dest}).to_string(),
                    ),
                    Err(e) => (
                        "500 Internal Server Error",
                        serde_json::json!({"error": e.to_string()}).to_string(),
                    ),
                },
                None => (
                    "400 Bad Request",
                    serde_json::json!({"error": "need {\"path\": \"...\"}"}).to_string(),
                ),
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

fn extract_path(req: &str) -> Option<String> {
    // Cari body setelah \r\n\r\n
    let body_start = req.find("\r\n\r\n").map(|i| i + 4)?;
    let body = &req[body_start..];
    let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    v.get("path")?.as_str().map(|s| s.to_string())
}

/// Sinkhole domain ke 0.0.0.0 di hosts file (perintah dashboard via queue).
/// Idempoten: entry ganda tidak ditulis ulang. Butuh privilege tulis hosts.
fn do_sinkhole(domain: &str) -> Result<String> {
    // Validasi ketat: satu label domain saja, tanpa spasi/karakter shell.
    if domain.is_empty()
        || domain.len() > 253
        || domain.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
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

fn do_quarantine(path: &str) -> Result<String> {    let src = Path::new(path);
    if !src.exists() {
        anyhow::bail!("file tidak ada: {}", path);
    }
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
    let quarantine_dir = candidates.iter().find(|p| {
        std::fs::create_dir_all(p).is_ok()
    }).unwrap_or(&candidates[0]);
    std::fs::create_dir_all(quarantine_dir)?;
    let filename = src.file_name().unwrap_or_default().to_string_lossy();
    let dest = quarantine_dir.join(format!("{}.{}.quarantined", filename, chrono::Utc::now().timestamp()));
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
    info!(src = %path, dest = %dest.display(), "quarantined");
    Ok(dest.to_string_lossy().to_string())
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
}
