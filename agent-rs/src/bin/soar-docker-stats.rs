use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "soar-docker-stats",
    about = "Collector ringan memori container Docker ke JSON statis untuk SOAR Fleet Monitor"
)]
struct Args {
    /// Path output file JSON (ditulis secara atomik via tmp + rename)
    #[arg(
        long,
        default_value = "/home/ravi/Projects/soar-project/state/container-stats.json"
    )]
    output: PathBuf,
}

#[derive(Deserialize, Debug)]
struct DockerStatsRow {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "MemUsage")]
    mem_usage: String,
    #[serde(rename = "MemPerc")]
    mem_perc: String,
    #[serde(rename = "CPUPerc", default)]
    cpu_perc: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct ContainerMemStat {
    mem_used_mb: f64,
    mem_limit_mb: f64,
    mem_pct: f64,
    cpu_pct: f64,
}

#[derive(Serialize, Deserialize, Debug)]
struct ContainerStatsPayload {
    updated_at: String,
    containers: BTreeMap<String, ContainerMemStat>,
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Konversi token ukuran memori Docker (`412.3MiB`, `1.5GiB`, `512MB`, `0B`) ke MiB (1024^2 bytes).
fn parse_size_to_mib(raw: &str) -> Option<f64> {
    let s = raw.trim();
    if s.is_empty() || s == "--" {
        return None;
    }
    let idx = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let num: f64 = s[..idx].parse().ok()?;
    let unit = s[idx..].trim().to_ascii_lowercase();
    let bytes = match unit.as_str() {
        "" | "b" => num,
        "kib" => num * 1024.0,
        "mib" => num * 1024.0 * 1024.0,
        "gib" => num * 1024.0 * 1024.0 * 1024.0,
        "tib" => num * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "kb" => num * 1000.0,
        "mb" => num * 1000.0 * 1000.0,
        "gb" => num * 1000.0 * 1000.0 * 1000.0,
        "tb" => num * 1000.0 * 1000.0 * 1000.0 * 1000.0,
        _ => return None,
    };
    Some(bytes / (1024.0 * 1024.0))
}

fn parse_percent(raw: &str) -> Option<f64> {
    let cleaned = raw.trim().trim_end_matches('%').trim();
    if cleaned.is_empty() || cleaned == "--" {
        return None;
    }
    cleaned.parse::<f64>().ok()
}

fn parse_mem_usage_pair(raw: &str) -> Option<(f64, f64)> {
    let (used_raw, limit_raw) = raw.split_once('/')?;
    let used = parse_size_to_mib(used_raw)?;
    let limit = parse_size_to_mib(limit_raw)?;
    Some((used, limit))
}

fn parse_docker_stats_lines(stdout: &str) -> BTreeMap<String, ContainerMemStat> {
    let mut containers = BTreeMap::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(row) = serde_json::from_str::<DockerStatsRow>(trimmed) else {
            continue;
        };
        let clean_name = row.name.trim().trim_start_matches('/').to_string();
        if clean_name.is_empty() {
            continue;
        }
        let Some((used_mb, limit_mb)) = parse_mem_usage_pair(&row.mem_usage) else {
            continue;
        };
        let mem_pct = parse_percent(&row.mem_perc).unwrap_or_else(|| {
            if limit_mb > 0.0 {
                (used_mb / limit_mb) * 100.0
            } else {
                0.0
            }
        });
        let cpu_pct = parse_percent(&row.cpu_perc).unwrap_or(0.0);
        containers.insert(
            clean_name,
            ContainerMemStat {
                mem_used_mb: round1(used_mb),
                mem_limit_mb: round1(limit_mb),
                mem_pct: round2(mem_pct),
                cpu_pct: round2(cpu_pct),
            },
        );
    }
    containers
}

fn write_atomic_json(path: &Path, payload: &ContainerStatsPayload) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("gagal membuat direktori {}", parent.display()))?;
        }
    }
    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("container-stats.json"),
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);
    let body = serde_json::to_vec_pretty(payload)?;
    fs::write(&tmp_path, body)
        .with_context(|| format!("gagal menulis tmp {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path).with_context(|| {
        let _ = fs::remove_file(&tmp_path);
        format!("gagal rename ke {}", path.display())
    })?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let output = Command::new("docker")
        .args(["stats", "--no-stream", "--format", "{{json .}}"])
        .output()
        .context("gagal menjalankan `docker stats --no-stream`")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("docker stats exit {}: {}", output.status, stderr.trim());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let containers = parse_docker_stats_lines(&stdout);
    let payload = ContainerStatsPayload {
        updated_at: chrono::Utc::now().to_rfc3339(),
        containers,
    };
    write_atomic_json(&args.output, &payload)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binary_and_decimal_memory_units() {
        assert!((parse_size_to_mib("512MiB").unwrap() - 512.0).abs() < 0.01);
        assert!((parse_size_to_mib("1GiB").unwrap() - 1024.0).abs() < 0.01);
        assert!((parse_size_to_mib("2048KiB").unwrap() - 2.0).abs() < 0.01);
        assert!((parse_size_to_mib("1048576B").unwrap() - 1.0).abs() < 0.01);
        assert!(parse_size_to_mib("--").is_none());
    }

    #[test]
    fn parses_docker_stats_json_lines() {
        let sample = r#"{"Name":"fleet-monitor","MemUsage":"48.5MiB / 512MiB","MemPerc":"9.47%","CPUPerc":"0.35%"}
{"Name":"single-node-wazuh.indexer-1","MemUsage":"1.25GiB / 7.7GiB","MemPerc":"16.23%","CPUPerc":"2.10%"}
{"Name":"broken","MemUsage":"-- / --","MemPerc":"--","CPUPerc":"--"}
"#;
        let parsed = parse_docker_stats_lines(sample);
        assert_eq!(parsed.len(), 2);
        let fm = &parsed["fleet-monitor"];
        assert_eq!(fm.mem_used_mb, 48.5);
        assert_eq!(fm.mem_limit_mb, 512.0);
        assert_eq!(fm.mem_pct, 9.47);
        assert_eq!(fm.cpu_pct, 0.35);

        let idx = &parsed["single-node-wazuh.indexer-1"];
        assert_eq!(idx.mem_used_mb, 1280.0);
        assert!((idx.mem_limit_mb - 7884.8).abs() < 0.2);
    }

    #[test]
    fn writes_atomic_json_file() {
        let dir = std::env::temp_dir().join(format!("soar-docker-stats-test-{}", std::process::id()));
        let out = dir.join("container-stats.json");
        let mut containers = BTreeMap::new();
        containers.insert(
            "n8n".to_string(),
            ContainerMemStat {
                mem_used_mb: 210.4,
                mem_limit_mb: 1024.0,
                mem_pct: 20.55,
                cpu_pct: 0.8,
            },
        );
        let payload = ContainerStatsPayload {
            updated_at: "2026-11-20T00:32:00Z".to_string(),
            containers,
        };
        write_atomic_json(&out, &payload).unwrap();
        let read_back: ContainerStatsPayload =
            serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        assert_eq!(read_back.containers["n8n"].mem_used_mb, 210.4);
        let _ = fs::remove_dir_all(&dir);
    }
}
