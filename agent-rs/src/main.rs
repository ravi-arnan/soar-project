use anyhow::Result;
use clap::Parser;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "soar-agent", about = "Agen ringan SOAR Rust - alternatif Wazuh Agent")]
struct Args {
    #[arg(long, default_value = "http://100.95.198.108:5678/webhook/wazuh-alert")]
    webhook: String,

    #[arg(long, default_value = "003")]
    agent_id: String,

    #[arg(long, default_value = "rust-agent-ravi")]
    agent_name: String,

    #[arg(long, value_delimiter = ',')]
    watch: Option<Vec<String>>,

    #[arg(long, default_value = "8787")]
    listen_port: u16,

    #[arg(long, default_value = "http://127.0.0.1:8080/api/heartbeat")]
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

fn build_payload(args: &Args, path: &Path, hash: &str) -> serde_json::Value {
    let perm = std::fs::metadata(path)
        .map(|m| format!("{:o}", m.mode() & 0o777))
        .unwrap_or_else(|_| "644".to_string());
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

async fn post_to_n8n(webhook: &str, payload: &serde_json::Value) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
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
    {
        let watcher = watcher.clone();
        let watched_mounts = watched_mounts.clone();
        let usb_root = usb_root.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(entries) = std::fs::read_dir(&usb_root) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_dir() && !watched_mounts.lock().unwrap().contains(&p) {
                            match watcher.lock().unwrap().watch(&p, RecursiveMode::Recursive) {
                                Ok(_) => {
                                    watched_mounts.lock().unwrap().push(p.clone());
                                    info!(path = %p.display(), "USB mounted, watching (recursive)");
                                }
                                Err(e) => warn!(path = %p.display(), error = %e, "gagal watch USB mount"),
                            }
                        }
                    }
                    // Bersihkan mount yang sudah dicabut (unwatch supaya tidak leak)
                    let mounted: Vec<PathBuf> = std::fs::read_dir(&usb_root)
                        .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect())
                        .unwrap_or_default();
                    let mut wm = watched_mounts.lock().unwrap();
                    wm.retain(|p| {
                        if mounted.contains(p) {
                            true
                        } else {
                            info!(path = %p.display(), "USB dicabut, unwatch");
                            false
                        }
                    });
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
        loop {
            let payload = serde_json::json!({
                "id": hb_id,
                "name": hb_name,
                "version": env!("CARGO_PKG_VERSION"),
                "ip": "127.0.0.1",
            });
            if let Err(e) = client.post(&fleet_url).json(&payload).send().await {
                warn!(error = %e, fleet_url = %fleet_url, "heartbeat fleet gagal (fleet-monitor belum jalan?)");
            } else {
                info!(fleet_url = %fleet_url, "heartbeat fleet ok");
            }
            tokio::time::sleep(Duration::from_secs(hb_interval)).await;
        }
    });

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
            // Tunggu file selesai ditulis (simple debounce 300ms)
            tokio::time::sleep(Duration::from_millis(300)).await;

            if !path.exists() {
                continue;
            }

            // Debounce 2 detik
            let now = std::time::Instant::now();
            if let Some(last) = last_sent.get(&path) {
                if now.duration_since(*last) < Duration::from_secs(2) {
                    continue;
                }
            }
            last_sent.insert(path.clone(), now);

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

            // Retry 3x dengan backoff
            let mut ok = false;
            for attempt in 1..=3 {
                match post_to_n8n(&args.webhook, &payload).await {
                    Ok(_) => {
                        ok = true;
                        break;
                    }
                    Err(e) => {
                        warn!(attempt, error = %e, "POST gagal, retry");
                        tokio::time::sleep(Duration::from_secs(attempt)).await;
                    }
                }
            }
            if !ok {
                error!(path = %path.display(), "POST gagal 3x, drop event");
            }
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

fn do_quarantine(path: &str) -> Result<String> {
    let src = Path::new(path);
    if !src.exists() {
        anyhow::bail!("file tidak ada: {}", path);
    }
    // ponytail: coba /var/ossec/quarantine dulu (kompatibel Wazuh), fallback ke ~/.soar-quarantine (same filesystem dengan Downloads)
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let fallback = format!("{}/.soar-quarantine", home);
    let fallback_path = PathBuf::from(fallback);
    let candidates = [
        Path::new("/var/ossec/quarantine"),
        fallback_path.as_path(),
        Path::new("/tmp/soar-quarantine"),
    ];
    let quarantine_dir = candidates.iter().find(|p| {
        std::fs::create_dir_all(p).is_ok() && std::fs::metadata(p).map(|m| !m.permissions().readonly()).unwrap_or(true)
    }).unwrap_or(&candidates[1]);
    std::fs::create_dir_all(quarantine_dir)?;
    let filename = src.file_name().unwrap_or_default().to_string_lossy();
    let dest = quarantine_dir.join(format!("{}.{}.quarantined", filename, chrono::Utc::now().timestamp()));
    // ponytail: rename gagal jika beda filesystem (Invalid cross-device link), fallback copy+remove
    if let Err(e) = std::fs::rename(src, &dest) {
        if e.raw_os_error() == Some(18) {
            std::fs::copy(src, &dest)?;
            std::fs::remove_file(src)?;
        } else {
            return Err(e.into());
        }
    }
    // chmod 000
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o000));
    info!(src = %path, dest = %dest.display(), "quarantined");
    Ok(dest.to_string_lossy().to_string())
}
