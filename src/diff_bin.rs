use clap::Parser;
use serde_json::{json, Value};
use std::fs;
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

pub fn run_diff_paths(
    old_raw: &str,
    new_raw: &str,
    deep: bool,
    max_items: usize,
) -> Result<(String, Value), String> {
    let old_norm = crate::ls::normalize_cli_path(old_raw);
    let new_norm = crate::ls::normalize_cli_path(new_raw);
    let old_p = Path::new(&old_norm);
    let new_p = Path::new(&new_norm);
    let old_bytes =
        fs::read(old_p).map_err(|e| format!("[ap diff] failed to read old `{old_raw}`: {e}"))?;
    let new_bytes =
        fs::read(new_p).map_err(|e| format!("[ap diff] failed to read new `{new_raw}`: {e}"))?;

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
    match run_diff_paths(&cli.old_path, &cli.new_path, cli.deep, cli.max) {
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
