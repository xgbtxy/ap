use crate::audit::default_home_dir;
use base64::Engine;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBackupEntry {
    pub path: String,
    pub existed: bool,
    pub orig_lines: usize,
    pub orig_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoTx {
    pub id: String,
    pub ts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub files: Vec<FileBackupEntry>,
}

#[derive(Parser, Debug)]
#[command(
    name = "undo",
    about = "Named checkpoints, diff preview & atomic file restore (works even outside Git!)"
)]
struct UndoCli {
    /// List saved undo checkpoints without restoring
    #[arg(long)]
    list: bool,
    /// Save an explicit named checkpoint before risky edits or experiments
    #[arg(long)]
    save: Option<String>,
    /// Working directory used when resolving `--save` file paths or dirty git files
    #[arg(long, default_value = ".")]
    cwd: PathBuf,
    /// Preview file changes vs a saved checkpoint without modifying disk
    #[arg(long)]
    diff: bool,
    /// Select checkpoint by ID prefix or exact label (default: newest)
    #[arg(long)]
    id: Option<String>,
    /// Keep the checkpoint after restoring instead of consuming it
    #[arg(long)]
    keep: bool,
    /// Emit structured JSON output
    #[arg(long)]
    json: bool,
    /// File paths to include when using `--save` (defaults to modified git files in `--cwd`)
    files: Vec<String>,
}

pub fn undo_dir() -> PathBuf {
    if let Ok(ap_home) = std::env::var("AP_HOME") {
        if !ap_home.trim().is_empty() {
            return PathBuf::from(ap_home).join("undo");
        }
    }
    default_home_dir().join(".agent-primitives").join("undo")
}

fn sorted_tx_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    files.sort();
    files
}

pub fn record_named_snapshot(
    cwd: &Path,
    label: Option<&str>,
    rel_or_abs_paths: &[String],
) -> Option<UndoTx> {
    if rel_or_abs_paths.is_empty() {
        return None;
    }
    let cwd_canon = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let mut entries = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for raw in rel_or_abs_paths {
        let p = Path::new(raw);
        let full = if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd_canon.join(p)
        };
        let key = full.to_string_lossy().replace('\\', "/");
        if !seen.insert(key.clone()) {
            continue;
        }
        if full.is_file() {
            let bytes = fs::read(&full).unwrap_or_default();
            let orig_lines = bytes.iter().filter(|&&b| b == b'\n').count() + 1;
            let orig_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            entries.push(FileBackupEntry {
                path: key,
                existed: true,
                orig_lines,
                orig_b64,
            });
        } else {
            entries.push(FileBackupEntry {
                path: key,
                existed: false,
                orig_lines: 0,
                orig_b64: String::new(),
            });
        }
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let ts = (now_ms / 1000) as u64;
    let clean_label = label
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let id = format!("{now_ms:015}_{}", std::process::id());
    let tx = UndoTx {
        id: id.clone(),
        ts,
        label: clean_label,
        files: entries,
    };

    let dir = undo_dir();
    if fs::create_dir_all(&dir).is_ok() {
        let dst = dir.join(format!("tx_{id}.json"));
        if let Ok(txt) = serde_json::to_string(&tx) {
            let _ = fs::write(dst, txt);
        }
        let all = sorted_tx_files(&dir);
        if all.len() > 25 {
            for old in &all[..all.len() - 25] {
                let _ = fs::remove_file(old);
            }
        }
    }
    Some(tx)
}

pub fn record_pre_edit_snapshot(cwd: &Path, rel_or_abs_paths: &[String]) -> Option<UndoTx> {
    record_named_snapshot(cwd, None, rel_or_abs_paths)
}

fn collect_git_dirty_paths(cwd: &Path) -> Vec<String> {
    let Ok(out) = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(cwd)
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let mut paths = Vec::new();
    for ln in String::from_utf8_lossy(&out.stdout).lines() {
        if ln.len() < 4 {
            continue;
        }
        let rel = ln[3..].trim();
        let target = rel.split(" -> ").last().unwrap_or(rel).trim_matches('"');
        if !target.is_empty() {
            paths.push(target.to_string());
        }
    }
    paths
}

pub fn resolve_checkpoint(dir: &Path, selector: Option<&str>) -> Option<(PathBuf, UndoTx)> {
    let files = sorted_tx_files(dir);
    let sel = selector.map(str::trim).filter(|s| !s.is_empty());
    let mut loaded: Vec<(PathBuf, UndoTx)> = Vec::new();
    for f in files.into_iter().rev() {
        if let Ok(raw) = fs::read_to_string(&f) {
            if let Ok(tx) = serde_json::from_str::<UndoTx>(&raw) {
                loaded.push((f, tx));
            }
        }
    }
    let Some(q) = sel else {
        return loaded.into_iter().next();
    };
    // Priority: exact label -> exact id -> id prefix
    if let Some(hit) = loaded.iter().find(|(_, tx)| tx.label.as_deref() == Some(q)) {
        return Some(hit.clone());
    }
    if let Some(hit) = loaded.iter().find(|(_, tx)| tx.id == q) {
        return Some(hit.clone());
    }
    loaded.into_iter().find(|(_, tx)| tx.id.starts_with(q))
}

pub fn compute_checkpoint_diff(tx: &UndoTx) -> Value {
    let mut file_diffs = Vec::new();
    let mut changed_count = 0usize;
    for entry in &tx.files {
        let p = Path::new(&entry.path);
        let orig_bytes = if entry.existed {
            base64::engine::general_purpose::STANDARD
                .decode(&entry.orig_b64)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let cur_bytes = if p.is_file() {
            Some(fs::read(p).unwrap_or_default())
        } else {
            None
        };
        let (status, cur_lines, changed) = match (entry.existed, &cur_bytes) {
            (true, None) => ("deleted", 0usize, true),
            (false, None) => ("absent", 0usize, false),
            (false, Some(cb)) => (
                "created",
                cb.iter().filter(|&&b| b == b'\n').count() + 1,
                true,
            ),
            (true, Some(cb)) => {
                let lc = cb.iter().filter(|&&b| b == b'\n').count() + 1;
                if cb == &orig_bytes {
                    ("unchanged", lc, false)
                } else {
                    ("modified", lc, true)
                }
            }
        };
        if changed {
            changed_count += 1;
        }
        let line_delta = cur_lines as isize - entry.orig_lines as isize;
        file_diffs.push(json!({
            "path": entry.path,
            "status": status,
            "saved_lines": entry.orig_lines,
            "current_lines": cur_lines,
            "line_delta": line_delta,
            "changed": changed,
        }));
    }
    json!({
        "ok": true,
        "id": tx.id,
        "label": tx.label,
        "changed_files": changed_count,
        "files": file_diffs,
    })
}

pub fn check_truncation_warnings(tx: &UndoTx) -> Vec<String> {
    let mut warns = Vec::new();
    for f in &tx.files {
        if !f.existed || f.orig_lines < 60 {
            continue;
        }
        if let Ok(after) = fs::read(&f.path) {
            let new_lines = after.iter().filter(|&&b| b == b'\n').count() + 1;
            if new_lines * 4 < f.orig_lines {
                warns.push(format!(
                    "[TRUNCATION WARNING] `{}` shrunk from {} -> {} lines (>75% loss). Run `ap undo` immediately if unintended!",
                    f.path, f.orig_lines, new_lines
                ));
            }
        }
    }
    warns
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match UndoCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    let dir = undo_dir();

    if let Some(ref lbl) = cli.save {
        let targets = if cli.files.is_empty() {
            collect_git_dirty_paths(&cli.cwd)
        } else {
            cli.files.clone()
        };
        if targets.is_empty() {
            if cli.json {
                println!("{}", json!({"ok": false, "error": "no_files_to_snapshot"}));
            } else {
                eprintln!("[ap undo] --save requires file paths or dirty git files in cwd.");
            }
            return 1;
        }
        let Some(tx) = record_named_snapshot(&cli.cwd, Some(lbl), &targets) else {
            return 1;
        };
        if cli.json {
            let saved_paths: Vec<&str> = tx.files.iter().map(|f| f.path.as_str()).collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "id": tx.id,
                    "label": tx.label,
                    "files": saved_paths,
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "[ap undo] Saved checkpoint `{}` (id={}, {} file(s)).",
                tx.label.as_deref().unwrap_or(""),
                tx.id,
                tx.files.len()
            );
        }
        return 0;
    }

    let files = sorted_tx_files(&dir);
    if cli.list {
        let mut items = Vec::new();
        for f in files.iter().rev().take(15) {
            if let Ok(txt) = fs::read_to_string(f) {
                if let Ok(tx) = serde_json::from_str::<UndoTx>(&txt) {
                    let paths: Vec<String> = tx.files.iter().map(|e| e.path.clone()).collect();
                    items
                        .push(json!({"id": tx.id, "label": tx.label, "ts": tx.ts, "files": paths}));
                }
            }
        }
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&items).unwrap_or_default()
            );
        } else if items.is_empty() {
            println!("[ap undo] No undo checkpoints recorded yet.");
        } else {
            println!("[ap undo] Saved safety checkpoints (newest first):");
            for it in items {
                let lbl = it["label"]
                    .as_str()
                    .map(|l| format!(" [{l}]"))
                    .unwrap_or_default();
                println!(
                    "  - {}{} -> {:?}",
                    it["id"].as_str().unwrap_or(""),
                    lbl,
                    it["files"]
                );
            }
        }
        return 0;
    }

    let Some((tx_path, tx)) = resolve_checkpoint(&dir, cli.id.as_deref()) else {
        if cli.json {
            println!("{}", json!({"ok": false, "error": "checkpoint_not_found"}));
        } else {
            eprintln!("[ap undo] Nothing matched (no checkpoints found).");
        }
        return 1;
    };

    if cli.diff {
        let diff_v = compute_checkpoint_diff(&tx);
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&diff_v).unwrap_or_default()
            );
        } else {
            let lbl = tx
                .label
                .as_deref()
                .map(|l| format!(" [{l}]"))
                .unwrap_or_default();
            println!(
                "[ap undo] Diff vs checkpoint {}{} ({} changed file(s)):",
                tx.id,
                lbl,
                diff_v["changed_files"].as_u64().unwrap_or(0)
            );
            if let Some(arr) = diff_v["files"].as_array() {
                for f in arr {
                    println!(
                        "  - {} [{} | {:+} lines]",
                        f["path"].as_str().unwrap_or(""),
                        f["status"].as_str().unwrap_or(""),
                        f["line_delta"].as_i64().unwrap_or(0)
                    );
                }
            }
        }
        return 0;
    }

    let mut restored = Vec::new();
    for entry in &tx.files {
        let p = Path::new(&entry.path);
        if entry.existed {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&entry.orig_b64) {
                if let Some(parent) = p.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if fs::write(p, bytes).is_ok() {
                    restored.push(format!("restored {}", entry.path));
                }
            }
        } else if p.exists() && fs::remove_file(p).is_ok() {
            restored.push(format!("removed newly-created {}", entry.path));
        }
    }
    if !cli.keep {
        let _ = fs::remove_file(tx_path);
    }

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"ok": true, "id": tx.id, "label": tx.label, "kept": cli.keep, "actions": restored})
            )
            .unwrap_or_default()
        );
    } else {
        println!(
            "[ap undo] Restored checkpoint {}{} ({} file(s)):\n  - {}",
            tx.id,
            tx.label
                .as_deref()
                .map(|l| format!(" [{l}]"))
                .unwrap_or_default(),
            restored.len(),
            restored.join("\n  - ")
        );
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_checkpoint_resolve_diff_and_keep() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let td = std::env::temp_dir().join(format!("ap_undo_test_{n}"));
        let ap_home = td.join("ap_home");
        fs::create_dir_all(&td).unwrap();
        let target = td.join("demo.txt");
        fs::write(&target, "line1\nline2\n").unwrap();

        let _ap_home_guard = crate::stats::ApHomeTestGuard::set(&ap_home);

        let tx =
            record_named_snapshot(&td, Some("pre-refactor"), &["demo.txt".to_string()]).unwrap();
        assert_eq!(tx.label.as_deref(), Some("pre-refactor"));

        let (_, found_lbl) = resolve_checkpoint(&undo_dir(), Some("pre-refactor")).unwrap();
        assert_eq!(found_lbl.id, tx.id);
        let (_, found_pfx) = resolve_checkpoint(&undo_dir(), Some(&tx.id[..8])).unwrap();
        assert_eq!(found_pfx.id, tx.id);

        fs::write(&target, "line1\nline2\nline3\n").unwrap();
        let diff_v = compute_checkpoint_diff(&tx);
        assert_eq!(diff_v["changed_files"], 1);
        assert_eq!(diff_v["files"][0]["status"], "modified");
        assert_eq!(diff_v["files"][0]["line_delta"], 1);

        let rc = run_cli(&[
            "undo".into(),
            "--id".into(),
            "pre-refactor".into(),
            "--keep".into(),
        ]);
        assert_eq!(rc, 0);
        assert_eq!(fs::read_to_string(&target).unwrap(), "line1\nline2\n");
        assert!(resolve_checkpoint(&undo_dir(), Some("pre-refactor")).is_some());

        let _ = fs::remove_dir_all(&td);
    }
}
