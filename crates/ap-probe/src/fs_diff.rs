use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileMeta {
    pub size: u64,
    pub mtime_ms: u64,
    pub quick_hash: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsDiffReport {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

const SKIP_DIRS: [&str; 8] = [
    ".git",
    "node_modules",
    "target",
    ".venv",
    "__pycache__",
    ".next",
    "dist_cache",
    ".agents",
];

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn snap_store_dir() -> PathBuf {
    if let Ok(ah) = std::env::var("AP_HOME") {
        if !ah.trim().is_empty() {
            return PathBuf::from(ah).join("fs_snaps");
        }
    }
    std::env::temp_dir().join("ap_fs_snaps")
}

fn sanitize_snap_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.is_empty() {
        "default".to_string()
    } else {
        clean
    }
}

fn walk_snapshot(root: &Path, dir: &Path, depth: usize, out: &mut BTreeMap<String, FileMeta>) {
    if depth > 12 || out.len() >= 25_000 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        if out.len() >= 25_000 {
            break;
        }
        let p = ent.path();
        let Ok(ft) = ent.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            let nm = ent.file_name().to_string_lossy().to_string();
            if SKIP_DIRS.iter().any(|&s| s.eq_ignore_ascii_case(&nm)) {
                continue;
            }
            walk_snapshot(root, &p, depth + 1, out);
        } else if ft.is_file() {
            let Ok(md) = ent.metadata() else {
                continue;
            };
            let size = md.len();
            let mtime_ms = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let quick_hash = if size <= 256 * 1024 {
                fs::read(&p).map(|b| fnv1a_64(&b)).unwrap_or(0)
            } else {
                size ^ mtime_ms
            };
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(
                rel,
                FileMeta {
                    size,
                    mtime_ms,
                    quick_hash,
                },
            );
        }
    }
}

pub fn capture_dir_snapshot(root: &Path) -> BTreeMap<String, FileMeta> {
    let mut map = BTreeMap::new();
    walk_snapshot(root, root, 0, &mut map);
    map
}

pub fn diff_snapshots(
    before: &BTreeMap<String, FileMeta>,
    after: &BTreeMap<String, FileMeta>,
) -> FsDiffReport {
    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();
    for (k, av) in after {
        match before.get(k) {
            None => added.push(format!("{k} (+{}B)", av.size)),
            Some(bv) => {
                if bv.size != av.size || bv.quick_hash != av.quick_hash {
                    let delta = av.size as i64 - bv.size as i64;
                    let sign = if delta >= 0 { "+" } else { "" };
                    modified.push(format!(
                        "{k} ({}B -> {}B, {sign}{delta}B)",
                        bv.size, av.size
                    ));
                }
            }
        }
    }
    for (k, bv) in before {
        if !after.contains_key(k) {
            deleted.push(format!("{k} (-{}B)", bv.size));
        }
    }
    FsDiffReport {
        added,
        modified,
        deleted,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_fs_cli(
    dir: &Path,
    recent_secs: u64,
    snapshot_name: Option<&str>,
    diff_name: Option<&str>,
    run_cmd: Option<&str>,
    limit: usize,
    as_json: bool,
) -> i32 {
    if !dir.is_dir() {
        let msg = format!("[probe fs] directory not found: {}", dir.display());
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "ok": false, "error": msg }))
                    .unwrap_or_default()
            );
        } else {
            eprintln!("{msg}");
        }
        return 2;
    }
    let t0 = Instant::now();
    let lim = limit.clamp(1, 200);

    // Mode 1: Atomic before/after `--run "<cmd>"`
    if let Some(cmd_str) = run_cmd.filter(|s| !s.trim().is_empty()) {
        let before = capture_dir_snapshot(dir);
        let cmd_out = if cfg!(windows) {
            Command::new("pwsh.exe")
                .args(["-NoLogo", "-NoProfile", "-Command", cmd_str])
                .current_dir(dir)
                .output()
                .or_else(|_| {
                    Command::new("powershell.exe")
                        .args(["-NoLogo", "-NoProfile", "-Command", cmd_str])
                        .current_dir(dir)
                        .output()
                })
        } else {
            Command::new("sh")
                .args(["-c", cmd_str])
                .current_dir(dir)
                .output()
        };
        let (cmd_code, cmd_preview) = match cmd_out {
            Ok(o) => {
                let code = o.status.code().unwrap_or(-1);
                let mut combined = String::from_utf8_lossy(&o.stdout).to_string();
                let err = String::from_utf8_lossy(&o.stderr);
                if !err.trim().is_empty() {
                    combined.push('\n');
                    combined.push_str(&err);
                }
                let prev: String = combined.trim().chars().take(600).collect();
                (code, prev)
            }
            Err(e) => (-1, format!("spawn error: {e}")),
        };
        let after = capture_dir_snapshot(dir);
        let diff = diff_snapshots(&before, &after);
        let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": cmd_code == 0,
                    "mode": "run-diff",
                    "dir": dir.to_string_lossy(),
                    "cmd_exit": cmd_code,
                    "cmd_output": cmd_preview,
                    "elapsed_ms": elapsed_ms,
                    "added": diff.added,
                    "modified": diff.modified,
                    "deleted": diff.deleted,
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "[probe fs] run-diff on `{}` (cmd exit={cmd_code} | {}ms): +{} added, ~{} modified, -{} deleted",
                dir.display(),
                elapsed_ms,
                diff.added.len(),
                diff.modified.len(),
                diff.deleted.len()
            );
            for a in diff.added.iter().take(lim) {
                println!("  [ADDED]    {a}");
            }
            for m in diff.modified.iter().take(lim) {
                println!("  [MODIFIED] {m}");
            }
            for d in diff.deleted.iter().take(lim) {
                println!("  [DELETED]  {d}");
            }
        }
        return if cmd_code == 0 { 0 } else { 1 };
    }

    // Mode 2: Save named snapshot
    if let Some(sname) = snapshot_name.filter(|s| !s.trim().is_empty()) {
        let snap = capture_dir_snapshot(dir);
        let store = snap_store_dir();
        let _ = fs::create_dir_all(&store);
        let sp = store.join(format!("{}.json", sanitize_snap_name(sname)));
        let _ = fs::write(&sp, serde_json::to_string(&snap).unwrap_or_default());
        let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "mode": "snapshot",
                    "name": sname,
                    "files": snap.len(),
                    "elapsed_ms": elapsed_ms,
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "[probe fs] Saved snapshot `{sname}` ({} files in `{}` | {}ms)",
                snap.len(),
                dir.display(),
                elapsed_ms
            );
        }
        return 0;
    }

    // Mode 3: Diff against named snapshot
    if let Some(dname) = diff_name.filter(|s| !s.trim().is_empty()) {
        let sp = snap_store_dir().join(format!("{}.json", sanitize_snap_name(dname)));
        let Ok(raw) = fs::read_to_string(&sp) else {
            eprintln!(
                "[probe fs] snapshot `{dname}` not found (take one first via `--snapshot {dname}`)"
            );
            return 2;
        };
        let before: BTreeMap<String, FileMeta> = serde_json::from_str(&raw).unwrap_or_default();
        let after = capture_dir_snapshot(dir);
        let diff = diff_snapshots(&before, &after);
        let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "mode": "diff",
                    "snapshot": dname,
                    "elapsed_ms": elapsed_ms,
                    "added": diff.added,
                    "modified": diff.modified,
                    "deleted": diff.deleted,
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "[probe fs] Diff vs `{dname}` ({}ms): +{} added, ~{} modified, -{} deleted",
                elapsed_ms,
                diff.added.len(),
                diff.modified.len(),
                diff.deleted.len()
            );
            for a in diff.added.iter().take(lim) {
                println!("  [ADDED]    {a}");
            }
            for m in diff.modified.iter().take(lim) {
                println!("  [MODIFIED] {m}");
            }
            for d in diff.deleted.iter().take(lim) {
                println!("  [DELETED]  {d}");
            }
        }
        return 0;
    }

    // Mode 4: Recent modified files sorted newest-first
    let snap = capture_dir_snapshot(dir);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let cutoff_ms = if recent_secs > 0 {
        now_ms.saturating_sub(recent_secs.saturating_mul(1000))
    } else {
        0
    };
    let mut rows: Vec<(String, FileMeta)> = snap
        .into_iter()
        .filter(|(_, m)| m.mtime_ms >= cutoff_ms)
        .collect();
    rows.sort_by_key(|a| std::cmp::Reverse(a.1.mtime_ms));
    let total = rows.len();
    rows.truncate(lim);
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();

    if as_json {
        let jrows: Vec<serde_json::Value> = rows
            .iter()
            .map(|(p, m)| {
                json!({
                    "path": p,
                    "size": m.size,
                    "age_sec": now_ms.saturating_sub(m.mtime_ms) / 1000,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "mode": "recent",
                "total": total,
                "elapsed_ms": elapsed_ms,
                "files": jrows,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[probe fs] {} newest file(s) (of {} matched in `{}` | {}ms):",
            rows.len(),
            total,
            dir.display(),
            elapsed_ms
        );
        for (p, m) in &rows {
            let age_s = now_ms.saturating_sub(m.mtime_ms) / 1000;
            let age_str = if age_s < 60 {
                format!("-{age_s}s")
            } else if age_s < 3600 {
                format!("-{}m", age_s / 60)
            } else {
                format!("-{}h", age_s / 3600)
            };
            println!("  - {:>7}  {:>9} B  {}", age_str, m.size, p);
        }
    }
    0
}
