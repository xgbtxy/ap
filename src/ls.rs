use crate::stats::record_event;
use clap::Parser;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{Instant, UNIX_EPOCH};

const PRUNE_RECURSIVE_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".next",
];

#[derive(Parser, Debug)]
#[command(
    name = "ls",
    about = "Fast, token-efficient directory listing with depth, sorting, filters & Windows/Git-Bash path support"
)]
struct LsCli {
    /// Directory or file path (supports Windows, POSIX & MSYS2 `/c/...` paths)
    #[arg(default_value = ".")]
    path: String,
    /// Optional extra files or directories (used in `--lines`/`--hash`/`--du`/`--stat` metrics mode)
    extra_paths: Vec<String>,
    /// Recursion depth (1 = direct children, max 5)
    #[arg(short = 'L', long, default_value_t = 1)]
    depth: usize,
    /// Sort order: name (default), size, or mtime
    #[arg(long, default_value = "name")]
    sort: String,
    /// Shortcut for `--sort mtime` (newest first)
    #[arg(short = 't', long)]
    sort_mtime: bool,
    /// Shortcut for `--sort size` (largest first)
    #[arg(short = 'S', long)]
    sort_size: bool,
    /// Filter by comma-separated file extensions, e.g. `rs,ts`
    #[arg(short = 'e', long = "ext", default_value = "")]
    ext: String,
    /// Show files only
    #[arg(short = 'f', long)]
    files_only: bool,
    /// Show directories only
    #[arg(short = 'd', long)]
    dirs_only: bool,
    /// Include dotfiles and build/vendor dirs (`node_modules`, `target`, `.git`) when recursing
    #[arg(short = 'a', long)]
    all: bool,
    /// Count exact lines & bytes for files (`ap wc` compatible)
    #[arg(long)]
    lines: bool,
    /// Compute SHA-256 hex digests for files (`ap sha256` compatible)
    #[arg(long, alias = "sha256")]
    hash: bool,
    /// Compute recursive directory disk usage (`ap du` compatible, skips vendor dirs unless `-a`)
    #[arg(long, alias = "summary")]
    du: bool,
    /// Emit compact metadata (`bytes`, UTC `mtime`, `lines` / `du`, optional `--hash`) for 1+ paths
    #[arg(long)]
    stat: bool,
    /// Maximum entries to display
    #[arg(long, alias = "max", default_value_t = 120)]
    limit: usize,
    /// Emit structured JSON output
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Serialize)]
struct LsEntry {
    path: String,
    kind: &'static str,
    size: u64,
    mtime_secs: u64,
}

/// Converts MSYS2 / Git-Bash paths (`/c/Program Files/...` or `/d`) to `C:/Program Files/...` on Windows.
pub fn normalize_msys_drive_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() {
        let drive = (bytes[1] as char).to_ascii_uppercase();
        if bytes.len() == 2 {
            return format!("{drive}:/");
        }
        if bytes[2] == b'/' || bytes[2] == b'\\' {
            let tail = raw[3..].replace('\\', "/");
            return format!("{drive}:/{tail}");
        }
    }
    raw.to_string()
}

/// Translates POSIX `/tmp` and `/tmp/...` paths into a Windows temp directory path when present.
pub fn normalize_windows_tmp_path(raw: &str, temp_dir: &str) -> Option<String> {
    let trimmed = raw.trim();
    let base = temp_dir.trim_end_matches(['/', '\\']).replace('\\', "/");
    if trimmed == "/tmp" || trimmed == "/tmp/" {
        return Some(base);
    }
    trimmed
        .strip_prefix("/tmp/")
        .map(|rest| format!("{base}/{}", rest.replace('\\', "/")))
}

/// Normalizes CLI paths on Windows so Git-Bash `/c/...` or `/tmp/...` paths resolve seamlessly.
pub fn normalize_cli_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    #[cfg(windows)]
    {
        if Path::new(trimmed).exists() {
            return trimmed.to_string();
        }
        if let Some(tmp_norm) =
            normalize_windows_tmp_path(trimmed, &std::env::temp_dir().to_string_lossy())
        {
            return tmp_norm;
        }
        let converted = normalize_msys_drive_path(trimmed);
        if converted != trimmed {
            return converted;
        }
    }
    trimmed.to_string()
}

fn format_bytes(n: u64) -> String {
    if n >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if n >= 1024 * 1024 {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn format_date_utc(secs: u64) -> String {
    if secs == 0 {
        return "---- -- --".to_string();
    }
    // Howard Hinnant civil-from-days algorithm (0 dependencies, UTC)
    let z = (secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let yr = y + if m <= 2 { 1 } else { 0 };
    format!("{yr:04}-{m:02}-{d:02}")
}

fn collect_entries_recursive(
    root: &Path,
    dir: &Path,
    cur_depth: usize,
    max_depth: usize,
    show_all: bool,
    ext_allow: &[String],
    out: &mut Vec<LsEntry>,
) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for item in rd.flatten() {
        let p = item.path();
        let name = item.file_name().to_string_lossy().to_string();
        if !show_all && name.starts_with('.') && cur_depth > 1 {
            continue;
        }
        let Ok(meta) = item.metadata() else {
            continue;
        };
        let is_dir = meta.is_dir();
        let mtime_secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");

        if is_dir {
            if ext_allow.is_empty() {
                out.push(LsEntry {
                    path: format!("{rel}/"),
                    kind: "dir",
                    size: 0,
                    mtime_secs,
                });
            }
            if cur_depth < max_depth {
                let skip_recurse = !show_all && PRUNE_RECURSIVE_DIRS.contains(&name.as_str());
                if !skip_recurse {
                    collect_entries_recursive(
                        root,
                        &p,
                        cur_depth + 1,
                        max_depth,
                        show_all,
                        ext_allow,
                        out,
                    );
                }
            }
        } else {
            let ext_ok = if ext_allow.is_empty() {
                true
            } else {
                let fext = p
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                ext_allow.iter().any(|e| e == &fext)
            };
            if ext_ok {
                out.push(LsEntry {
                    path: rel,
                    kind: "file",
                    size: meta.len(),
                    mtime_secs,
                });
            }
        }
    }
}

fn count_file_lines_bytes(path: &Path) -> std::io::Result<(usize, u64)> {
    let f = fs::File::open(path)?;
    let mut reader = BufReader::new(f);
    let mut buf = [0u8; 64 * 1024];
    let mut bytes = 0u64;
    let mut lines = 0usize;
    let mut last_byte = b'\n';
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        for &b in &buf[..n] {
            if b == b'\n' {
                lines += 1;
            }
        }
        last_byte = buf[n - 1];
    }
    if bytes > 0 && last_byte != b'\n' {
        lines += 1;
    }
    Ok((lines, bytes))
}

fn compute_file_sha256(path: &Path) -> std::io::Result<String> {
    let f = fs::File::open(path)?;
    let mut reader = BufReader::new(f);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn compute_dir_usage(dir: &Path, show_all: bool) -> (u64, usize, usize) {
    let mut bytes = 0u64;
    let mut files = 0usize;
    let mut dirs = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let Ok(rd) = fs::read_dir(&cur) else {
            continue;
        };
        for item in rd.flatten() {
            let name = item.file_name().to_string_lossy().to_string();
            if !show_all && name.starts_with('.') {
                continue;
            }
            let Ok(meta) = item.metadata() else {
                continue;
            };
            if meta.is_dir() {
                dirs += 1;
                if show_all || !PRUNE_RECURSIVE_DIRS.contains(&name.as_str()) {
                    stack.push(item.path());
                }
            } else {
                files += 1;
                bytes = bytes.saturating_add(meta.len());
            }
        }
    }
    (bytes, files, dirs)
}

fn run_metrics_mode(cli: &LsCli) -> i32 {
    let t0 = Instant::now();
    let mut entries_json: Vec<serde_json::Value> = Vec::new();
    let mut text_lines: Vec<String> = Vec::new();
    let mut total_bytes = 0u64;
    let mut total_lines = 0usize;
    let mut valid_count = 0usize;

    for raw_t in std::iter::once(&cli.path).chain(cli.extra_paths.iter()) {
        let norm = normalize_cli_path(raw_t);
        let p = Path::new(&norm);
        if !p.exists() {
            if !cli.extra_paths.is_empty() {
                eprintln!("[ap ls] warning: path not found: {norm}");
            }
            continue;
        }
        valid_count += 1;
        let disp = norm.replace('\\', "/");
        let meta = fs::metadata(p).ok();
        let mtime_secs = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mtime_utc = format_date_utc(mtime_secs);
        if p.is_file() {
            let (lines, bytes) = if cli.lines || cli.stat {
                count_file_lines_bytes(p)
                    .unwrap_or((0, meta.as_ref().map(|m| m.len()).unwrap_or(0)))
            } else {
                (0, meta.as_ref().map(|m| m.len()).unwrap_or(0))
            };
            let sha = if cli.hash {
                compute_file_sha256(p).unwrap_or_default()
            } else {
                String::new()
            };
            total_bytes = total_bytes.saturating_add(bytes);
            total_lines += lines;
            let human = format_bytes(bytes);
            let mut obj = json!({
                "path": disp,
                "kind": "file",
                "bytes": bytes,
                "human_size": human,
                "mtime_utc": mtime_utc,
            });
            if cli.lines || cli.stat {
                obj["lines"] = json!(lines);
            }
            if cli.hash {
                obj["sha256"] = json!(sha);
            }
            entries_json.push(obj);
            let line_tag = if cli.lines || cli.stat {
                format!(" lines={lines}")
            } else {
                String::new()
            };
            let sha_tag = if cli.hash {
                format!(" sha256={sha}")
            } else {
                String::new()
            };
            text_lines.push(format!(
                "f {bytes:>10} ({human:>8})  {mtime_utc}  {disp}{line_tag}{sha_tag}"
            ));
        } else {
            let (bytes, files, dirs) = compute_dir_usage(p, cli.all);
            total_bytes = total_bytes.saturating_add(bytes);
            let human = format_bytes(bytes);
            entries_json.push(json!({
                "path": disp,
                "kind": "dir",
                "bytes": bytes,
                "human_size": human,
                "files": files,
                "dirs": dirs,
                "mtime_utc": mtime_utc,
            }));
            text_lines.push(format!(
                "d {bytes:>10} ({human:>8})  {mtime_utc}  {disp}  ({files} files, {dirs} dirs)"
            ));
        }
    }

    if valid_count == 0 {
        eprintln!("[ap ls] path not found: {}", normalize_cli_path(&cli.path));
        return 1;
    }

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
    let mode = if cli.stat && cli.hash {
        "stat+hash"
    } else if cli.stat {
        "stat"
    } else if cli.hash {
        "hash"
    } else if cli.du {
        "du"
    } else if cli.lines {
        "lines"
    } else {
        "multi"
    };

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "mode": mode,
                "elapsed_ms": elapsed_ms,
                "total_bytes": total_bytes,
                "total_lines": total_lines,
                "entries": entries_json,
            }))
            .unwrap_or_default()
        );
    } else {
        if valid_count > 1 || cli.stat || cli.lines {
            text_lines.push(format!(
                "# TOTAL: {} ({total_bytes} B){} across {valid_count} path(s) in {elapsed_ms}ms",
                format_bytes(total_bytes),
                if total_lines > 0 {
                    format!(", {total_lines} lines")
                } else {
                    String::new()
                }
            ));
        }
        let out = text_lines.join("\n");
        record_event("ls", total_bytes, out.len() as u64, 0, 0, mode);
        println!("{out}");
    }
    0
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match LsCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };

    if cli.stat || cli.lines || cli.hash || cli.du || !cli.extra_paths.is_empty() {
        return run_metrics_mode(&cli);
    }

    let t0 = Instant::now();
    let norm_path = normalize_cli_path(&cli.path);
    let root = Path::new(&norm_path);
    if !root.exists() {
        eprintln!("[ap ls] path not found: {norm_path}");
        return 1;
    }

    if root.is_file() {
        let meta = fs::metadata(root).ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let mtime_secs = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let entry = LsEntry {
            path: root.to_string_lossy().replace('\\', "/"),
            kind: "file",
            size,
            mtime_secs,
        };
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "path": entry.path,
                    "total": 1,
                    "shown": 1,
                    "dirs": 0,
                    "files": 1,
                    "total_bytes": size,
                    "entries": [entry],
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "f {:>8}  {}  {}",
                format_bytes(size),
                format_date_utc(mtime_secs),
                entry.path
            );
        }
        return 0;
    }

    let max_depth = cli.depth.clamp(1, 5);
    let ext_allow: Vec<String> = cli
        .ext
        .split(',')
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let mut entries = Vec::new();
    collect_entries_recursive(root, root, 1, max_depth, cli.all, &ext_allow, &mut entries);

    if cli.files_only {
        entries.retain(|e| e.kind == "file");
    } else if cli.dirs_only {
        entries.retain(|e| e.kind == "dir");
    }

    let sort_mode = if cli.sort_mtime {
        "mtime"
    } else if cli.sort_size {
        "size"
    } else {
        cli.sort.trim()
    };

    match sort_mode {
        "mtime" | "time" => entries.sort_by(|a, b| {
            b.mtime_secs
                .cmp(&a.mtime_secs)
                .then_with(|| a.path.cmp(&b.path))
        }),
        "size" => entries.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path))),
        _ => entries.sort_by(|a, b| {
            let ak = u8::from(a.kind != "dir");
            let bk = u8::from(b.kind != "dir");
            ak.cmp(&bk).then_with(|| {
                a.path
                    .to_ascii_lowercase()
                    .cmp(&b.path.to_ascii_lowercase())
            })
        }),
    }

    let total = entries.len();
    let dirs = entries.iter().filter(|e| e.kind == "dir").count();
    let files = total.saturating_sub(dirs);
    let total_bytes: u64 = entries.iter().map(|e| e.size).sum();
    let cap = cli.limit.max(1);
    let shown = total.min(cap);
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;

    let display_root: PathBuf = root.to_path_buf();
    let root_lbl = display_root.to_string_lossy().replace('\\', "/");

    if cli.json {
        let sliced: Vec<&LsEntry> = entries.iter().take(shown).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "path": root_lbl,
                "elapsed_ms": elapsed_ms,
                "total": total,
                "shown": shown,
                "dirs": dirs,
                "files": files,
                "total_bytes": total_bytes,
                "entries": sliced,
            }))
            .unwrap_or_default()
        );
    } else {
        let mut lines = vec![format!(
            "# LS `{root_lbl}` ({shown}/{total} shown: {dirs} dirs, {files} files, {} in {elapsed_ms}ms)",
            format_bytes(total_bytes)
        )];
        for e in entries.iter().take(shown) {
            let tag = if e.kind == "dir" { 'd' } else { 'f' };
            let sz = if e.kind == "dir" {
                "-".to_string()
            } else {
                format_bytes(e.size)
            };
            lines.push(format!(
                "{tag} {:>8}  {}  {}",
                sz,
                format_date_utc(e.mtime_secs),
                e.path
            ));
        }
        if total > shown {
            lines.push(format!(
                "... (+{} more; pass `--limit {total}` or `--ext <ext>`)",
                total - shown
            ));
        }
        let rendered = lines.join("\n");
        record_event("ls", total_bytes, rendered.len() as u64, 0, 0, "ap-ls");
        println!("{rendered}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msys2_drive_path_normalizes_cleanly_without_touching_posix_paths() {
        assert_eq!(
            normalize_msys_drive_path("/c/Program Files/ExampleApp/bin"),
            "C:/Program Files/ExampleApp/bin"
        );
        assert_eq!(normalize_msys_drive_path("/d"), "D:/");
        assert_eq!(
            normalize_msys_drive_path("/usr/local/bin"),
            "/usr/local/bin"
        );
        assert_eq!(normalize_msys_drive_path("src/main.rs"), "src/main.rs");
    }

    #[test]
    fn windows_tmp_path_normalizes_to_env_temp_preserving_non_tmp() {
        assert_eq!(
            normalize_windows_tmp_path("/tmp/ap_wave74_probe.txt", r"C:\Users\demo\Temp\"),
            Some("C:/Users/demo/Temp/ap_wave74_probe.txt".to_string())
        );
        assert_eq!(
            normalize_windows_tmp_path("/tmp", r"C:\Users\demo\Temp"),
            Some("C:/Users/demo/Temp".to_string())
        );
        assert_eq!(
            normalize_windows_tmp_path("/tmp/", "C:/Temp/"),
            Some("C:/Temp".to_string())
        );
        assert_eq!(
            normalize_windows_tmp_path("/usr/local/bin", "C:/Temp"),
            None
        );
        assert_eq!(
            normalize_windows_tmp_path("C:/tmp/local.txt", "C:/Temp"),
            None
        );
    }

    #[test]
    fn file_lines_sha256_and_dir_usage_metrics_are_exact() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let fp = root.join("data.txt");
        fs::write(&fp, b"one\ntwo\nthree").unwrap();
        let (lines, bytes) = count_file_lines_bytes(&fp).unwrap();
        assert_eq!((lines, bytes), (3, 13));
        let hex = compute_file_sha256(&fp).unwrap();
        assert_eq!(hex.len(), 64);

        let vendor = root.join("node_modules");
        fs::create_dir_all(&vendor).unwrap();
        fs::write(vendor.join("big.js"), vec![b'x'; 200]).unwrap();
        let (pruned_b, pruned_f, _) = compute_dir_usage(root, false);
        assert_eq!((pruned_b, pruned_f), (13, 1));
        let (all_b, all_f, _) = compute_dir_usage(root, true);
        assert_eq!((all_b, all_f), (213, 2));
    }
}
