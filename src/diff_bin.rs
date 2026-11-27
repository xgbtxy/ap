use clap::Parser;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(
    name = "diff",
    about = "Pure-Rust structural version-diff for PE/ELF/Go binaries, .asar/.zip/.whl archives, JS bundles & configs"
)]
struct DiffCli {
    /// Older baseline binary, archive, JS bundle, or config path (`v1`)
    old_path: String,
    /// Newer target binary, archive, JS bundle, or config path (`v2`)
    new_path: String,
    /// Perform deep archive member unpacking (JS routes/IPC/preload & Python hunks) — default true
    #[arg(long, default_value_t = true)]
    deep: bool,
    /// Maximum added/removed/changed entries per bucket (default: 25, max: 100)
    #[arg(long, default_value_t = 25)]
    max: usize,
    /// AST-normalized semantic patch-diff (JS/ASAR/dir & PE/ELF normalized function signatures)
    #[arg(long)]
    semantic: bool,
    /// Emit structured compact JSON (`<= 16 KB`)
    #[arg(long)]
    json: bool,
}

fn bound_diff_json(mut v: Value, max_bytes: usize) -> Value {
    let serialized = serde_json::to_string(&v).unwrap_or_default();
    if serialized.len() <= max_bytes {
        return v;
    }
    if let Some(obj) = v.as_object_mut() {
        if let Some(members) = obj
            .get_mut("changed_code_members")
            .and_then(Value::as_array_mut)
        {
            for m in members.iter_mut() {
                if let Some(mo) = m.as_object_mut() {
                    if let Some(hp) = mo.get("hunk_preview").and_then(Value::as_str) {
                        let clipped: String = hp.chars().take(240).collect();
                        mo.insert("hunk_preview".to_string(), json!(clipped));
                    }
                }
            }
            members.truncate(6);
        }
        for key in [
            "exports_added",
            "exports_removed",
            "imports_added",
            "imports_removed",
            "symbols_added",
            "symbols_removed",
            "strings_added",
            "strings_removed",
        ] {
            if let Some(arr) = obj.get_mut(key).and_then(Value::as_array_mut) {
                arr.truncate(15);
            }
        }
        obj.insert("truncated_for_budget".to_string(), json!(true));
    }
    v
}

fn hash_file_streaming(path: &Path) -> Result<(u64, String), String> {
    let mut f = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 32768];
    let mut total = 0u64;
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    Ok((total, hex))
}

fn collect_dir_manifest(
    root: &Path,
    rel_prefix: &str,
    out: &mut BTreeMap<String, (u64, String)>,
    max_files: usize,
) -> Result<(), String> {
    if out.len() >= max_files {
        return Ok(());
    }
    let dir = if rel_prefix.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel_prefix)
    };
    let rd = fs::read_dir(&dir)
        .map_err(|e| format!("[ap diff] failed to read dir `{}`: {e}", dir.display()))?;
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        if out.len() >= max_files {
            break;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let rel = if rel_prefix.is_empty() {
            name.clone()
        } else {
            format!("{rel_prefix}/{name}")
        };
        if ft.is_dir() {
            if matches!(
                name.as_str(),
                ".git" | ".hg" | ".svn" | "node_modules" | "__pycache__" | "target"
            ) {
                continue;
            }
            collect_dir_manifest(root, &rel, out, max_files)?;
        } else if ft.is_file() {
            if let Ok(meta) = hash_file_streaming(&entry.path()) {
                out.insert(rel, meta);
            }
        }
    }
    Ok(())
}

fn diff_directories(
    old_root: &Path,
    new_root: &Path,
    old_label: &str,
    new_label: &str,
    max_items: usize,
) -> Result<(String, Value), String> {
    const MAX_WALK_FILES: usize = 20_000;
    let mut old_map = BTreeMap::new();
    let mut new_map = BTreeMap::new();
    collect_dir_manifest(old_root, "", &mut old_map, MAX_WALK_FILES)?;
    collect_dir_manifest(new_root, "", &mut new_map, MAX_WALK_FILES)?;

    let mut added_all: Vec<Value> = Vec::new();
    let mut removed_all: Vec<Value> = Vec::new();
    let mut modified_all: Vec<Value> = Vec::new();
    let mut unchanged_count = 0usize;

    for (rel, (old_sz, old_sha)) in &old_map {
        match new_map.get(rel) {
            None => removed_all.push(json!({
                "path": rel,
                "old_size": old_sz,
                "old_sha256": old_sha,
            })),
            Some((new_sz, new_sha)) => {
                if old_sz == new_sz && old_sha == new_sha {
                    unchanged_count += 1;
                } else {
                    modified_all.push(json!({
                        "path": rel,
                        "old_size": old_sz,
                        "new_size": new_sz,
                        "size_delta": (*new_sz as i64) - (*old_sz as i64),
                        "old_sha256": old_sha,
                        "new_sha256": new_sha,
                    }));
                }
            }
        }
    }
    for (rel, (new_sz, new_sha)) in &new_map {
        if !old_map.contains_key(rel) {
            added_all.push(json!({
                "path": rel,
                "new_size": new_sz,
                "new_sha256": new_sha,
            }));
        }
    }

    let total_added = added_all.len();
    let total_removed = removed_all.len();
    let total_modified = modified_all.len();
    let truncated =
        total_added > max_items || total_removed > max_items || total_modified > max_items;
    let added: Vec<Value> = added_all.into_iter().take(max_items).collect();
    let removed: Vec<Value> = removed_all.into_iter().take(max_items).collect();
    let modified: Vec<Value> = modified_all.into_iter().take(max_items).collect();

    let mut md_lines = vec![format!(
        "# DIR DIFF `{old_label}` -> `{new_label}` (+{total_added} added, -{total_removed} removed, ~{total_modified} modified, ={unchanged_count} unchanged)"
    )];
    if !added.is_empty() {
        md_lines.push("\n## Added".to_string());
        for a in &added {
            md_lines.push(format!(
                "+ {} ({}B)",
                a["path"].as_str().unwrap_or(""),
                a["new_size"].as_u64().unwrap_or(0)
            ));
        }
    }
    if !removed.is_empty() {
        md_lines.push("\n## Removed".to_string());
        for r in &removed {
            md_lines.push(format!(
                "- {} ({}B)",
                r["path"].as_str().unwrap_or(""),
                r["old_size"].as_u64().unwrap_or(0)
            ));
        }
    }
    if !modified.is_empty() {
        md_lines.push("\n## Modified".to_string());
        for m in &modified {
            md_lines.push(format!(
                "~ {} ({}B -> {}B, delta {:+})",
                m["path"].as_str().unwrap_or(""),
                m["old_size"].as_u64().unwrap_or(0),
                m["new_size"].as_u64().unwrap_or(0),
                m["size_delta"].as_i64().unwrap_or(0),
            ));
        }
    }

    let jv = json!({
        "ok": true,
        "format": "dir-diff",
        "mode": "version-diff",
        "kind": "directory",
        "old": old_label,
        "new": new_label,
        "added": added,
        "removed": removed,
        "modified": modified,
        "unchanged_count": unchanged_count,
        "summary": {
            "old_files": old_map.len(),
            "new_files": new_map.len(),
            "added_count": total_added,
            "removed_count": total_removed,
            "modified_count": total_modified,
            "unchanged_count": unchanged_count,
            "truncated": truncated,
        },
    });
    Ok((md_lines.join("\n"), bound_diff_json(jv, 16_000)))
}

pub fn run_diff_paths(
    old_raw: &str,
    new_raw: &str,
    deep: bool,
    max_items: usize,
) -> Result<(String, Value), String> {
    run_diff_paths_opts(old_raw, new_raw, deep, max_items, false)
}

pub fn run_diff_paths_opts(
    old_raw: &str,
    new_raw: &str,
    deep: bool,
    max_items: usize,
    semantic: bool,
) -> Result<(String, Value), String> {
    let old_norm = crate::ls::normalize_cli_path(old_raw);
    let new_norm = crate::ls::normalize_cli_path(new_raw);
    let old_p = Path::new(&old_norm);
    let new_p = Path::new(&new_norm);
    if semantic {
        let (md, mut jv) = crate::semantic_diff::diff_semantic_paths_both(old_p, new_p)
            .map_err(|e| format!("[ap diff --semantic] {e}"))?;
        if let Some(m) = jv.as_object_mut() {
            m.insert("ok".to_string(), json!(true));
            m.insert("format".to_string(), json!("semantic-diff"));
        }
        return Ok((md, jv));
    }
    if old_p.is_dir() && new_p.is_dir() {
        return diff_directories(old_p, new_p, &old_norm, &new_norm, max_items.clamp(1, 100));
    }
    if old_p.is_dir() != new_p.is_dir() && old_p.exists() && new_p.exists() {
        return Err(format!(
            "[ap diff] cannot diff directory against file (`{old_raw}` vs `{new_raw}`)"
        ));
    }
    let new_ext = new_p
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let old_ext = old_p
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let eff_ext = if !new_ext.is_empty() {
        new_ext.as_str()
    } else {
        old_ext.as_str()
    };

    if eff_ext == "asar" && old_p.is_file() && new_p.is_file() {
        let (md, jv) = crate::binary::diff_asar_files_streaming(
            new_p,
            old_p,
            &new_norm,
            &old_norm,
            deep,
            max_items.clamp(1, 100),
        )?;
        return Ok((md, bound_diff_json(jv, 16_000)));
    }

    let old_bytes =
        fs::read(old_p).map_err(|e| format!("[ap diff] failed to read old `{old_raw}`: {e}"))?;
    let new_bytes =
        fs::read(new_p).map_err(|e| format!("[ap diff] failed to read new `{new_raw}`: {e}"))?;

    if !crate::binary::is_binary_magic(&new_bytes) && !crate::binary::is_binary_magic(&old_bytes) {
        if let (Ok(new_v), Ok(old_v)) = (
            serde_json::from_slice::<Value>(&new_bytes),
            serde_json::from_slice::<Value>(&old_bytes),
        ) {
            if matches!(new_v, Value::Object(_) | Value::Array(_))
                && matches!(old_v, Value::Object(_) | Value::Array(_))
            {
                let (md, jdiff) =
                    crate::inspect::diff_json_structural_md(&new_v, &old_v, &new_norm, &old_norm);
                let out = json!({
                    "ok": true,
                    "mode": "version-diff",
                    "kind": "json",
                    "old_target": old_norm,
                    "new_target": new_norm,
                    "old_sha256": crate::binary::sha256_hex(&old_bytes),
                    "new_sha256": crate::binary::sha256_hex(&new_bytes),
                    "size_delta": (new_bytes.len() as i64) - (old_bytes.len() as i64),
                    "json_diff": jdiff,
                });
                return Ok((md, bound_diff_json(out, 16_000)));
            }
        }
        if matches!(
            eff_ext,
            "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "html" | "htm"
        ) {
            let new_txt = String::from_utf8_lossy(&new_bytes);
            let old_txt = String::from_utf8_lossy(&old_bytes);
            let (md, jv) = crate::inspect::extract_js_routes_diff_md(
                &new_txt, &new_norm, None, &old_txt, &old_norm,
            );
            let hunks = crate::binary::compact_text_hunk(&old_txt, &new_txt, 18);
            let out = json!({
                "ok": true,
                "mode": "version-diff",
                "kind": "js-bundle",
                "old_target": old_norm,
                "new_target": new_norm,
                "old_sha256": crate::binary::sha256_hex(&old_bytes),
                "new_sha256": crate::binary::sha256_hex(&new_bytes),
                "size_delta": (new_bytes.len() as i64) - (old_bytes.len() as i64),
                "routes_diff": jv.get("diff").cloned().unwrap_or(Value::Null),
                "counts": jv.get("counts").cloned().unwrap_or(Value::Null),
                "hunk_preview": hunks,
            });
            return Ok((md, bound_diff_json(out, 16_000)));
        }
    }

    let (md, jv) = crate::binary::diff_binaries_or_archives(
        &new_bytes,
        &old_bytes,
        &new_norm,
        &old_norm,
        eff_ext,
        deep,
        max_items.clamp(1, 100),
    );
    Ok((md, bound_diff_json(jv, 16_000)))
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match DiffCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    match run_diff_paths_opts(
        &cli.old_path,
        &cli.new_path,
        cli.deep,
        cli.max,
        cli.semantic,
    ) {
        Ok((md, jv)) => {
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&jv).unwrap_or_default());
            } else {
                println!("{md}");
            }
            0
        }
        Err(e) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "ok": false, "error": e }))
                        .unwrap_or_default()
                );
            } else {
                eprintln!("{e}");
            }
            1
        }
    }
}
