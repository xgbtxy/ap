pub mod ast;
pub mod ast_search;
pub mod blast;
pub mod check;
pub mod patch;
pub mod rename;
pub mod rewrite;

use ast::{find_symbol_span, scan_symbols, verify_syntax};
use base64::Engine;
use check::{collect_check_payload, CheckPayload};
use clap::{Parser, Subcommand};
use patch::{dedent_and_reindent, parse_edit_spec, replace_crlf_tolerant_with_hint};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

static SPLICE_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceEncoding {
    Utf8,
    Utf8Bom,
    Utf16LeBom,
    Utf16BeBom,
}

fn emit_err(as_json: bool, msg: &str) {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "ok": false, "error": msg })).unwrap_or_default()
        );
    } else {
        eprintln!("{msg}");
    }
}

#[cfg(windows)]
fn replace_atomic_os(src: &Path, dst: &Path) -> std::io::Result<()> {
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(src: *const u16, dst: *const u16, flags: u32) -> i32;
        fn GetLastError() -> u32;
    }
    let src_w: Vec<u16> = src
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let dst_w: Vec<u16> = dst
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    for attempt in 0..12u64 {
        let ok = unsafe {
            MoveFileExW(
                src_w.as_ptr(),
                dst_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let err = unsafe { GetLastError() };
        if (err == 5 || err == 32) && attempt < 11 {
            std::thread::sleep(std::time::Duration::from_millis(4 + attempt * 4));
            continue;
        }
        return Err(std::io::Error::from_raw_os_error(err as i32));
    }
    Err(std::io::Error::other("MoveFileExW failed after retries"))
}

#[cfg(not(windows))]
fn replace_atomic_os(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::rename(src, dst)
}

pub(crate) fn write_file_atomic(dst: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    let seq = SPLICE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let fname = dst.file_name().and_then(|s| s.to_str()).unwrap_or("splice");
    let tmp = parent.join(format!(".{fname}.ap_tmp.{}.{seq}", std::process::id()));
    let mut f = fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    drop(f);
    if let Err(e) = replace_atomic_os(&tmp, dst) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

pub(crate) fn encode_source_bytes(content_lf: &str, nl_sep: &str, enc: SourceEncoding) -> Vec<u8> {
    let body = if nl_sep == "\n" {
        std::borrow::Cow::Borrowed(content_lf)
    } else {
        std::borrow::Cow::Owned(content_lf.replace('\n', nl_sep))
    };
    match enc {
        SourceEncoding::Utf8 => body.as_bytes().to_vec(),
        SourceEncoding::Utf8Bom => {
            let mut out = Vec::with_capacity(3 + body.len());
            out.extend_from_slice(b"\xEF\xBB\xBF");
            out.extend_from_slice(body.as_bytes());
            out
        }
        SourceEncoding::Utf16LeBom => {
            let mut out = Vec::with_capacity(2 + body.len() * 2);
            out.extend_from_slice(b"\xFF\xFE");
            for u in body.encode_utf16() {
                out.extend_from_slice(&u.to_le_bytes());
            }
            out
        }
        SourceEncoding::Utf16BeBom => {
            let mut out = Vec::with_capacity(2 + body.len() * 2);
            out.extend_from_slice(b"\xFE\xFF");
            for u in body.encode_utf16() {
                out.extend_from_slice(&u.to_be_bytes());
            }
            out
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewBlock {
    pub selector: String,
    pub start_line: usize,
    pub end_line: usize,
    pub numbered_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewFileResult {
    pub display_path: String,
    pub path: String,
    pub blocks: Vec<ViewBlock>,
}

#[derive(Parser, Debug)]
#[command(
    name = "splice",
    about = "Tree-sitter AST symbol surgeon, atomic patcher & auto-test gate"
)]
struct Cli {
    #[command(subcommand)]
    cmd: SubCmd,
}

#[derive(Subcommand, Debug)]
enum SubCmd {
    /// Read exact symbol/method (Py/TS/JS/Go/Rust/C), line range, or Markdown heading across 1+ files
    View {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(long = "symbol")]
        symbols: Vec<String>,
        #[arg(long, default_value = "")]
        heading: String,
        #[arg(long, default_value = "")]
        lines: String,
        #[arg(long)]
        json: bool,
    },
    /// Atomically apply UTF-8/CRLF-safe, Tree-sitter syntax-verified multi-file edits
    Apply {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        b64: Option<String>,
        #[arg(long)]
        spec: Option<PathBuf>,
        #[arg(long)]
        unlink_spec: bool,
        #[arg(long)]
        test: bool,
        #[arg(long, default_value = "")]
        test_cmd: String,
        #[arg(long)]
        rollback_on_test_fail: bool,
        #[arg(long)]
        json: bool,
    },
    /// Sub-50ms UTF-8, Tree-sitter syntax, conflict-marker & local-import verifier (+ optional --test or --hook)
    Check {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        test: bool,
        #[arg(long, default_value = "")]
        test_cmd: String,
        /// PostToolUse hook mode: reads Claude/Codex/Antigravity stdin JSON and checks edited file syntax in <10ms
        #[arg(long)]
        hook: bool,
        #[arg(long)]
        json: bool,
    },
    /// Tree-sitter AST-exact workspace symbol rename across Py/TS/JS/Go/Rust/C (ignores comments & strings)
    Rename {
        old_name: String,
        new_name: String,
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        test: bool,
        #[arg(long, default_value = "")]
        test_cmd: String,
        #[arg(long)]
        rollback_on_test_fail: bool,
        #[arg(long)]
        json: bool,
    },
    /// Tree-sitter structural AST pattern codemod/rewrite across Py/TS/JS/Go/Rust/C (supports $VAR & $$$ARGS)
    Rewrite {
        pattern: String,
        replacement: String,
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value = "")]
        ext: String,
        #[arg(long)]
        no_tests: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        test: bool,
        #[arg(long, default_value = "")]
        test_cmd: String,
        #[arg(long)]
        rollback_on_test_fail: bool,
        #[arg(long)]
        json: bool,
    },
}

fn md_heading_re() -> &'static (Regex, Regex) {
    static RE: OnceLock<(Regex, Regex)> = OnceLock::new();
    RE.get_or_init(|| {
        let md = Regex::new(r"^(#{1,6})\s+(.+?)\s*$").unwrap();
        let lr = Regex::new(r"(?i)^\s*L?(\d+)\s*[-:]\s*L?(\d+)\s*$").unwrap();
        (md, lr)
    })
}

fn find_md_section_span(lines: &[&str], heading_query: &str) -> Option<(usize, usize)> {
    let (md_re, _) = md_heading_re();
    let q = heading_query
        .trim()
        .trim_start_matches('#')
        .trim()
        .to_lowercase();
    let mut start_idx: Option<usize> = None;
    let mut start_lvl = 0usize;
    for (idx, &ln) in lines.iter().enumerate() {
        if let Some(cap) = md_re.captures(ln) {
            let lvl = cap[1].len();
            let title = cap[2].trim().to_lowercase();
            if let Some(s) = start_idx {
                if lvl <= start_lvl {
                    return Some((s + 1, idx));
                }
            } else if title.contains(&q) {
                start_idx = Some(idx);
                start_lvl = lvl;
            }
        }
    }
    start_idx.map(|s| (s + 1, lines.len()))
}

fn parse_line_range(spec: &str, total_lines: usize) -> Option<(usize, usize)> {
    let (_, lr_re) = md_heading_re();
    let cap = lr_re.captures(spec)?;
    let s = cap[1].parse::<usize>().ok()?.max(1);
    let e = cap[2].parse::<usize>().ok()?.max(s).min(total_lines);
    Some((s, e))
}

fn format_numbered(lines: &[&str], s_1idx: usize, e_1idx: usize) -> String {
    if lines.is_empty() || s_1idx > lines.len() {
        return String::new();
    }
    let end = e_1idx.min(lines.len());
    (s_1idx..=end)
        .map(|ln_no| format!("{ln_no:4}: {}", lines[ln_no - 1]))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn decode_source_bytes_with_encoding(
    raw_b: &[u8],
    label: &str,
) -> Result<(String, &'static str, SourceEncoding), String> {
    let (text, enc) = if let Some(rest) = raw_b.strip_prefix(b"\xEF\xBB\xBF") {
        (
            std::str::from_utf8(rest)
                .map_err(|e| format!("`{label}` is not valid UTF-8: {e}"))?
                .to_string(),
            SourceEncoding::Utf8Bom,
        )
    } else if let Some(rest) = raw_b.strip_prefix(b"\xFF\xFE") {
        if rest.len() % 2 != 0 {
            return Err(format!("`{label}` has truncated UTF-16LE byte length"));
        }
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        (
            char::decode_utf16(units)
                .collect::<Result<String, _>>()
                .map_err(|e| format!("`{label}` invalid UTF-16LE: {e}"))?,
            SourceEncoding::Utf16LeBom,
        )
    } else if let Some(rest) = raw_b.strip_prefix(b"\xFE\xFF") {
        if rest.len() % 2 != 0 {
            return Err(format!("`{label}` has truncated UTF-16BE byte length"));
        }
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        (
            char::decode_utf16(units)
                .collect::<Result<String, _>>()
                .map_err(|e| format!("`{label}` invalid UTF-16BE: {e}"))?,
            SourceEncoding::Utf16BeBom,
        )
    } else {
        (
            std::str::from_utf8(raw_b)
                .map_err(|e| format!("`{label}` is not valid UTF-8: {e}"))?
                .to_string(),
            SourceEncoding::Utf8,
        )
    };
    let nl = if text.contains("\r\n") { "\r\n" } else { "\n" };
    Ok((
        text.trim_start_matches('\u{FEFF}').replace("\r\n", "\n"),
        nl,
        enc,
    ))
}

pub(crate) fn decode_source_bytes_clean(
    raw_b: &[u8],
    label: &str,
) -> Result<(String, &'static str), String> {
    decode_source_bytes_with_encoding(raw_b, label).map(|(s, nl, _)| (s, nl))
}

pub fn view_single_file(
    target: &Path,
    symbols: &[String],
    heading: &str,
    line_range: &str,
) -> Result<ViewFileResult, String> {
    if !target.exists() {
        return Err(format!(
            "[splice view] file not found: {}",
            target.display()
        ));
    }
    let canon = fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    let raw_b = fs::read(&canon).map_err(|e| e.to_string())?;
    let raw = decode_source_bytes_clean(&raw_b, &target.to_string_lossy())
        .map(|(s, _)| s)
        .unwrap_or_else(|_| String::from_utf8_lossy(&raw_b).to_string());
    let lines: Vec<&str> = raw.lines().collect();
    let ext = canon
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut blocks = Vec::new();

    if !line_range.is_empty() {
        let Some((s_ln, e_ln)) = parse_line_range(line_range, lines.len().max(1)) else {
            return Err(format!(
                "[splice view] invalid --lines '{line_range}' (expected START-END, e.g. 10-45)"
            ));
        };
        blocks.push(ViewBlock {
            selector: format!("L{s_ln}-L{e_ln}"),
            start_line: s_ln,
            end_line: e_ln,
            numbered_source: format_numbered(&lines, s_ln, e_ln),
        });
    } else if !heading.is_empty() {
        let Some((s_ln, e_ln)) = find_md_section_span(&lines, heading) else {
            return Err(format!(
                "[splice view] heading '{heading}' not found in {}",
                target.display()
            ));
        };
        blocks.push(ViewBlock {
            selector: heading.to_string(),
            start_line: s_ln,
            end_line: e_ln,
            numbered_source: format_numbered(&lines, s_ln, e_ln),
        });
    } else if !symbols.is_empty() {
        for sym in symbols {
            let Some(sp) = find_symbol_span(&raw, &ext, sym) else {
                return Err(format!(
                    "[splice view] symbol '{sym}' not found in {}",
                    target.display()
                ));
            };
            blocks.push(ViewBlock {
                selector: sym.clone(),
                start_line: sp.start_line,
                end_line: sp.end_line,
                numbered_source: format_numbered(&lines, sp.start_line, sp.end_line),
            });
        }
    } else if ast::language_for_ext(&ext).is_some() && (ext == "py" || lines.len() > 140) {
        let items = scan_symbols(&raw, &ext);
        let outline = items
            .iter()
            .map(|it| {
                let pad = if it.qual.contains('.') { "  " } else { "" };
                format!(
                    "{pad}L{}-L{}: {} {}",
                    it.start_line, it.end_line, it.kind, it.qual
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        blocks.push(ViewBlock {
            selector: "<outline>".to_string(),
            start_line: 1,
            end_line: lines.len(),
            numbered_source: outline,
        });
    } else {
        let cap = lines.len().min(160);
        let sel = if cap == lines.len() {
            "<full>"
        } else {
            "<head>"
        };
        blocks.push(ViewBlock {
            selector: sel.to_string(),
            start_line: 1,
            end_line: cap,
            numbered_source: format_numbered(&lines, 1, cap),
        });
    }

    Ok(ViewFileResult {
        display_path: target.to_string_lossy().to_string(),
        path: canon.to_string_lossy().replace('\\', "/"),
        blocks,
    })
}

pub(crate) fn purge_stale_pyc(py_file: &Path) {
    let Some(parent) = py_file.parent() else {
        return;
    };
    let cache_dir = parent.join("__pycache__");
    if !cache_dir.is_dir() {
        return;
    }
    let stem = format!(
        "{}.",
        py_file.file_stem().and_then(|s| s.to_str()).unwrap_or("")
    );
    if let Ok(rd) = fs::read_dir(&cache_dir) {
        for entry in rd.flatten() {
            let nm = entry.file_name().to_string_lossy().to_string();
            if nm.starts_with(&stem) && (nm.ends_with(".pyc") || nm.ends_with(".pyo")) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

fn restore_backups(backups: &HashMap<PathBuf, Option<Vec<u8>>>) {
    for (p, orig) in backups {
        match orig {
            None => {
                let _ = fs::remove_file(p);
            }
            Some(bytes) => {
                let _ = write_file_atomic(p, bytes).or_else(|_| fs::write(p, bytes));
                if p.extension().and_then(|e| e.to_str()) == Some("py") {
                    purge_stale_pyc(p);
                }
            }
        }
    }
}

fn emit_check_human(payload: &CheckPayload) {
    let counts = format!(
        "{} py, {} ts/js, {} rs/go/c",
        payload.checked_py_files, payload.checked_ts_js_files, payload.checked_rs_go_c_files
    );
    if payload.ok {
        let mut msg =
            format!("[splice check] OK — ({counts}) UTF-8, Tree-sitter AST & local-import clean");
        if let Some(tr) = &payload.test_result {
            msg.push_str(&format!(" + tests PASSED (`{}`)", tr.command));
        }
        println!("{msg} in {} ms", payload.elapsed_ms);
        if let Some(tr) = &payload.test_result {
            if !tr.output.is_empty() {
                let lines: Vec<&str> = tr.output.lines().collect();
                let start = lines.len().saturating_sub(6);
                println!("{}", lines[start..].join("\n"));
            }
        }
    } else {
        println!(
            "[splice check] FAILED ({} issue(s)) in {} ms:\n{}",
            payload.issues.len(),
            payload.elapsed_ms,
            payload
                .issues
                .iter()
                .map(|x| format!("  - {x}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        if let Some(tr) = &payload.test_result {
            if !tr.ok && !tr.output.is_empty() {
                println!("\n## Failing Test Output\n{}", tr.output);
            }
        }
    }
}

pub fn apply_spec_silent(cwd: &Path, raw_spec: &str) -> i32 {
    apply_spec_inner(cwd, raw_spec, false, "", false, false, false)
}

pub fn apply_spec_str(
    cwd: &Path,
    raw_spec: &str,
    run_tests: bool,
    test_cmd_override: &str,
    rollback_on_test_fail: bool,
    as_json: bool,
) -> i32 {
    apply_spec_inner(
        cwd,
        raw_spec,
        run_tests,
        test_cmd_override,
        rollback_on_test_fail,
        as_json,
        true,
    )
}

fn lexical_normalize_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !matches!(
                    out.components().next_back(),
                    Some(std::path::Component::RootDir | std::path::Component::Prefix(_))
                ) {
                    out.pop();
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn resolve_tx_path(cwd_canon: &Path, raw_path: &str) -> PathBuf {
    let rel_p = Path::new(raw_path);
    let joined = if rel_p.is_absolute() {
        rel_p.to_path_buf()
    } else {
        cwd_canon.join(rel_p)
    };
    let clean = lexical_normalize_path(&joined);
    if clean.exists() {
        return fs::canonicalize(&clean).unwrap_or(clean);
    }
    // Canonicalize the deepest existing ancestor so symlinks / Windows drive-letter casing match.
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut probe = clean.as_path();
    while let Some(name) = probe.file_name() {
        tail.push(name.to_os_string());
        let Some(parent) = probe.parent() else {
            break;
        };
        if parent.exists() {
            let mut base = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
            for seg in tail.into_iter().rev() {
                base.push(seg);
            }
            return base;
        }
        probe = parent;
    }
    clean
}

fn tx_path_key(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    #[cfg(windows)]
    {
        s.to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        s
    }
}

fn apply_spec_inner(
    cwd: &Path,
    raw_spec: &str,
    run_tests: bool,
    test_cmd_override: &str,
    rollback_on_test_fail: bool,
    as_json: bool,
    emit_stdout: bool,
) -> i32 {
    let t0 = Instant::now();
    let cwd_canon = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let ops = match parse_edit_spec(raw_spec) {
        Ok(o) if !o.is_empty() => o,
        Ok(_) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "rolled_back": false,
                        "error": "[splice apply] expected a non-empty edit transaction."
                    }))
                    .unwrap_or_default()
                );
            } else {
                eprintln!("[splice apply] expected a non-empty edit transaction.");
            }
            return 1;
        }
        Err(e) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"ok": false, "rolled_back": false, "error": format!("Spec parse error: {e}")})).unwrap_or_default()
                );
            } else {
                eprintln!("[splice apply] Spec parse error: {e}");
            }
            return 1;
        }
    };

    let mut touched_paths: Vec<PathBuf> = Vec::new();
    let mut key_to_path: HashMap<String, PathBuf> = HashMap::new();
    let mut backups: HashMap<PathBuf, Option<Vec<u8>>> = HashMap::new();
    let mut working_text: HashMap<PathBuf, (String, &'static str)> = HashMap::new();
    let mut file_encodings: HashMap<PathBuf, SourceEncoding> = HashMap::new();
    let mut staged_bytes: HashMap<PathBuf, Vec<u8>> = HashMap::new();
    let mut applied_summary: Vec<serde_json::Value> = Vec::new();

    let tx_res: Result<(), String> = (|| {
        for (idx, item) in ops.iter().enumerate() {
            let resolved = resolve_tx_path(&cwd_canon, &item.path);
            let pkey = tx_path_key(&resolved);
            let p = key_to_path.entry(pkey).or_insert(resolved).clone();
            if !backups.contains_key(&p) {
                if p.exists() {
                    let raw_b = fs::read(&p).map_err(|e| e.to_string())?;
                    let (clean_lf, nl, enc) =
                        decode_source_bytes_with_encoding(&raw_b, &item.path)?;
                    working_text.insert(p.clone(), (clean_lf, nl));
                    file_encodings.insert(p.clone(), enc);
                    backups.insert(p.clone(), Some(raw_b));
                } else {
                    working_text.insert(p.clone(), (String::new(), "\n"));
                    file_encodings.insert(p.clone(), SourceEncoding::Utf8);
                    backups.insert(p.clone(), None);
                }
                touched_paths.push(p.clone());
            }

            let (cur_lf, nl_sep) = working_text.get(&p).cloned().unwrap();
            let op_kind = if item.op.is_empty() {
                "replace"
            } else {
                item.op.as_str()
            };
            match op_kind {
                "write" => {
                    let body = item
                        .content
                        .as_deref()
                        .unwrap_or(&item.new)
                        .trim_start_matches('\u{FEFF}');
                    working_text.insert(p.clone(), (body.replace("\r\n", "\n"), nl_sep));
                    applied_summary.push(json!({"index": idx, "path": item.path, "op": "write"}));
                }
                "append" => {
                    let body = item
                        .content
                        .as_deref()
                        .unwrap_or(&item.new)
                        .trim_start_matches('\u{FEFF}')
                        .replace("\r\n", "\n");
                    let merged = if cur_lf.is_empty() {
                        body
                    } else if cur_lf.ends_with('\n') {
                        format!("{cur_lf}{body}")
                    } else {
                        format!("{cur_lf}\n{body}")
                    };
                    working_text.insert(p.clone(), (merged, nl_sep));
                    applied_summary.push(json!({"index": idx, "path": item.path, "op": "append"}));
                }
                "prepend" => {
                    let body = item
                        .content
                        .as_deref()
                        .unwrap_or(&item.new)
                        .trim_start_matches('\u{FEFF}')
                        .replace("\r\n", "\n");
                    let merged = if cur_lf.is_empty() {
                        body
                    } else if body.ends_with('\n') {
                        format!("{body}{cur_lf}")
                    } else {
                        format!("{body}\n{cur_lf}")
                    };
                    working_text.insert(p.clone(), (merged, nl_sep));
                    applied_summary.push(json!({"index": idx, "path": item.path, "op": "prepend"}));
                }
                "replace" => {
                    let old_lf = item
                        .old
                        .trim_start_matches('\u{FEFF}')
                        .replace("\r\n", "\n");
                    let new_lf = item
                        .new
                        .trim_start_matches('\u{FEFF}')
                        .replace("\r\n", "\n");
                    let (updated, cnt) = replace_crlf_tolerant_with_hint(
                        &cur_lf,
                        &old_lf,
                        &new_lf,
                        item.all,
                        item.line_hint.as_deref(),
                    )
                    .map_err(|e| format!("`{}`: {e}", item.path))?;
                    working_text.insert(p.clone(), (updated, nl_sep));
                    applied_summary.push(
                        json!({"index": idx, "path": item.path, "op": "replace", "matches": cnt}),
                    );
                }
                "replace_symbol" => {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                    let sp = find_symbol_span(&cur_lf, ext, &item.symbol).ok_or_else(|| {
                        format!("Symbol `{}` not found in `{}`.", item.symbol, item.path)
                    })?;
                    let indented = dedent_and_reindent(&item.new, sp.indent_col);
                    let src_lines: Vec<&str> = cur_lf.split('\n').collect();
                    let mut updated_lines: Vec<String> = src_lines[..sp.start_line - 1]
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect();
                    updated_lines.extend(indented);
                    if sp.end_line < src_lines.len() {
                        updated_lines
                            .extend(src_lines[sp.end_line..].iter().map(|s| (*s).to_string()));
                    }
                    working_text.insert(p.clone(), (updated_lines.join("\n"), nl_sep));
                    applied_summary.push(json!({
                        "index": idx,
                        "path": item.path,
                        "op": "replace_symbol",
                        "symbol": item.symbol,
                        "lines": format!("L{}-L{}", sp.start_line, sp.end_line)
                    }));
                }
                "insert_after_symbol" => {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                    let sp = find_symbol_span(&cur_lf, ext, &item.symbol).ok_or_else(|| {
                        format!("Symbol `{}` not found in `{}`.", item.symbol, item.path)
                    })?;
                    let raw_body = if !item.new.is_empty() {
                        item.new.as_str()
                    } else {
                        item.content.as_deref().unwrap_or("")
                    };
                    let indented = dedent_and_reindent(raw_body, sp.indent_col);
                    let src_lines: Vec<&str> = cur_lf.split('\n').collect();
                    let mut updated_lines: Vec<String> = src_lines[..sp.end_line]
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect();
                    let prev_nonempty = updated_lines
                        .last()
                        .map(|l| !l.trim().is_empty())
                        .unwrap_or(false);
                    let first_nonempty = indented
                        .first()
                        .map(|l| !l.trim().is_empty())
                        .unwrap_or(false);
                    if prev_nonempty && first_nonempty {
                        updated_lines.push(String::new());
                    }
                    updated_lines.extend(indented);
                    if sp.end_line < src_lines.len() {
                        updated_lines
                            .extend(src_lines[sp.end_line..].iter().map(|s| (*s).to_string()));
                    }
                    working_text.insert(p.clone(), (updated_lines.join("\n"), nl_sep));
                    applied_summary.push(json!({
                        "index": idx,
                        "path": item.path,
                        "op": "insert_after_symbol",
                        "symbol": item.symbol,
                        "after_line": sp.end_line
                    }));
                }
                "insert_before_symbol" => {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                    let sp = find_symbol_span(&cur_lf, ext, &item.symbol).ok_or_else(|| {
                        format!("Symbol `{}` not found in `{}`.", item.symbol, item.path)
                    })?;
                    let raw_body = if !item.new.is_empty() {
                        item.new.as_str()
                    } else {
                        item.content.as_deref().unwrap_or("")
                    };
                    let indented = dedent_and_reindent(raw_body, sp.indent_col);
                    let src_lines: Vec<&str> = cur_lf.split('\n').collect();
                    let mut updated_lines: Vec<String> = src_lines[..sp.start_line - 1]
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect();
                    let last_ins_nonempty = indented
                        .last()
                        .map(|l| !l.trim().is_empty())
                        .unwrap_or(false);
                    updated_lines.extend(indented);
                    if sp.start_line - 1 < src_lines.len() {
                        let next_nonempty = !src_lines[sp.start_line - 1].trim().is_empty();
                        if last_ins_nonempty && next_nonempty {
                            updated_lines.push(String::new());
                        }
                        updated_lines.extend(
                            src_lines[sp.start_line - 1..]
                                .iter()
                                .map(|s| (*s).to_string()),
                        );
                    }
                    working_text.insert(p.clone(), (updated_lines.join("\n"), nl_sep));
                    applied_summary.push(json!({
                        "index": idx,
                        "path": item.path,
                        "op": "insert_before_symbol",
                        "symbol": item.symbol,
                        "before_line": sp.start_line
                    }));
                }
                "delete_symbol" => {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                    let sp = find_symbol_span(&cur_lf, ext, &item.symbol).ok_or_else(|| {
                        format!("Symbol `{}` not found in `{}`.", item.symbol, item.path)
                    })?;
                    let src_lines: Vec<&str> = cur_lf.split('\n').collect();
                    let mut updated_lines: Vec<String> = src_lines[..sp.start_line - 1]
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect();
                    let mut tail_start = sp.end_line;
                    if updated_lines
                        .last()
                        .map(|l| l.trim().is_empty())
                        .unwrap_or(false)
                        && src_lines
                            .get(tail_start)
                            .map(|l| l.trim().is_empty())
                            .unwrap_or(false)
                    {
                        tail_start += 1;
                    }
                    if tail_start < src_lines.len() {
                        updated_lines
                            .extend(src_lines[tail_start..].iter().map(|s| (*s).to_string()));
                    }
                    working_text.insert(p.clone(), (updated_lines.join("\n"), nl_sep));
                    applied_summary.push(json!({
                        "index": idx,
                        "path": item.path,
                        "op": "delete_symbol",
                        "symbol": item.symbol,
                        "lines": format!("L{}-L{}", sp.start_line, sp.end_line)
                    }));
                }
                other => return Err(format!("Unsupported op `{other}` at index {idx}")),
            }
        }

        for p in &touched_paths {
            let (final_lf, nl_sep) = working_text.get(p).unwrap();
            let enc = file_encodings
                .get(p)
                .copied()
                .unwrap_or(SourceEncoding::Utf8);
            let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !fname.ends_with(".d.ts") {
                verify_syntax(final_lf, ext).map_err(|e| format!("in `{fname}`: {e}"))?;
            }
            staged_bytes.insert(p.clone(), encode_source_bytes(final_lf, nl_sep, enc));
        }

        for p in &touched_paths {
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            write_file_atomic(p, staged_bytes.get(p).unwrap()).map_err(|e| e.to_string())?;
            if p.extension().and_then(|e| e.to_str()) == Some("py") {
                purge_stale_pyc(p);
            }
        }
        Ok(())
    })();

    if let Err(err) = tx_res {
        restore_backups(&backups);
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"ok": false, "rolled_back": true, "error": err})
                )
                .unwrap_or_default()
            );
        } else {
            eprintln!("[splice apply] ABORTED & ROLLED BACK: {err}");
        }
        return 1;
    }

    let check_opt = if run_tests || !test_cmd_override.trim().is_empty() {
        let cp = collect_check_payload(&cwd_canon, run_tests, test_cmd_override);
        if !cp.ok && rollback_on_test_fail {
            restore_backups(&backups);
            let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "rolled_back": true,
                        "reason": "post_apply_check_or_test_failed",
                        "ops_attempted": applied_summary,
                        "check": cp,
                        "elapsed_ms": elapsed_ms,
                    }))
                    .unwrap_or_default()
                );
            } else {
                eprintln!(
                    "[splice apply] TEST/CHECK FAILED -> ATOMICALLY ROLLED BACK {} file(s) in {elapsed_ms} ms:\n{}",
                    touched_paths.len(),
                    cp.issues.iter().map(|x| format!("  - {x}")).collect::<Vec<_>>().join("\n")
                );
                if let Some(tr) = &cp.test_result {
                    if !tr.ok && !tr.output.is_empty() {
                        eprintln!("\n## Failing Test Output\n{}", tr.output);
                    }
                }
            }
            return 1;
        }
        Some(cp)
    } else {
        None
    };

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
    let overall_ok = check_opt.as_ref().map(|c| c.ok).unwrap_or(true);
    if !emit_stdout {
        return if overall_ok { 0 } else { 1 };
    }
    let blast_hits =
        blast::detect_untouched_blast_radius(&cwd_canon, &touched_paths, &backups, &working_text);
    let contract_warnings = if check_opt.is_none() {
        collect_check_payload(&cwd_canon, false, "").issues
    } else {
        Vec::new()
    };
    if as_json {
        let mut obj = json!({
            "ok": overall_ok,
            "rolled_back": false,
            "files_updated": touched_paths.len(),
            "ops_applied": applied_summary,
            "blast_radius": blast_hits,
            "contract_warnings": contract_warnings,
            "elapsed_ms": elapsed_ms,
        });
        if let Some(cp) = check_opt {
            obj["check"] = serde_json::to_value(cp).unwrap_or_default();
        }
        println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
    } else {
        println!(
            "[splice apply] OK — atomically updated {} file(s) ({} ops, UTF-8 & Tree-sitter AST verified) in {elapsed_ms} ms",
            touched_paths.len(),
            applied_summary.len()
        );
        if !blast_hits.is_empty() {
            println!(
                "[BLAST RADIUS] Modified symbol signature(s) still referenced in {} untouched site(s) — verify callers:",
                blast_hits.len()
            );
            for bh in &blast_hits {
                println!(
                    "  - {}:{} ({}) — {}",
                    bh.file, bh.line, bh.symbol, bh.snippet
                );
            }
        }
        if !contract_warnings.is_empty() {
            println!(
                "[CONTRACT WARNING] {} cross-file import/export/arity mismatch(es) detected — fix before running:",
                contract_warnings.len()
            );
            for cw in contract_warnings.iter().take(8) {
                println!("  - {cw}");
            }
        }
        if let Some(cp) = &check_opt {
            emit_check_human(cp);
        }
    }
    if overall_ok {
        0
    } else {
        1
    }
}

fn push_unique_candidate_path(out: &mut Vec<PathBuf>, base_dir: &Path, raw: &str) {
    let t = raw.trim();
    if t.is_empty() || t.contains('\n') || t.contains('\r') {
        return;
    }
    let p = Path::new(t);
    let resolved = if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    };
    if !out.contains(&resolved) {
        out.push(resolved);
    }
}

fn collect_hook_paths_from_value(v: &serde_json::Value, base_dir: &Path, out: &mut Vec<PathBuf>) {
    let Some(obj) = v.as_object() else {
        return;
    };
    for key in ["file_path", "path", "TargetFile", "Path"] {
        if let Some(s) = obj.get(key).and_then(|x| x.as_str()) {
            push_unique_candidate_path(out, base_dir, s);
        }
    }
    if let Some(arr) = obj.get("paths").and_then(|x| x.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                push_unique_candidate_path(out, base_dir, s);
            }
        }
    }
    if let Some(edits) = obj.get("edits").and_then(|x| x.as_array()) {
        for ed in edits {
            if let Some(eo) = ed.as_object() {
                for key in ["file_path", "path", "TargetFile", "Path"] {
                    if let Some(s) = eo.get(key).and_then(|x| x.as_str()) {
                        push_unique_candidate_path(out, base_dir, s);
                    }
                }
            }
        }
    }
    for key in ["patch", "input"] {
        if let Some(txt) = obj.get(key).and_then(|x| x.as_str()) {
            for ln in txt.lines() {
                let lt = ln.trim();
                if let Some(rest) = lt
                    .strip_prefix("*** Update File:")
                    .or_else(|| lt.strip_prefix("*** Add File:"))
                {
                    push_unique_candidate_path(out, base_dir, rest);
                }
            }
        }
    }
}

fn is_post_edit_supported_ext(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "py" | "ts"
            | "mts"
            | "cts"
            | "tsx"
            | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "go"
            | "rs"
            | "c"
            | "h"
            | "json"
            | "jsonc"
            | "toml"
    )
}

fn run_post_edit_hook(explicit_root: &Path) -> i32 {
    let mut payload = String::new();
    if !std::io::stdin().is_terminal() {
        let _ = std::io::stdin().read_to_string(&mut payload);
    }
    let trimmed = payload.trim();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut candidates: Vec<PathBuf> = Vec::new();
    let mut mode = "cli";

    if trimmed.starts_with('{') {
        if let Ok(serde_json::Value::Object(map)) =
            serde_json::from_str::<serde_json::Value>(trimmed)
        {
            let hook_cwd = map
                .get("cwd")
                .and_then(|x| x.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| cwd.clone());
            if map.contains_key("hookEventName") || map.contains_key("toolCall") {
                mode = "antigravity";
                if let Some(args) = map.get("toolCall").and_then(|tc| tc.get("args")) {
                    collect_hook_paths_from_value(args, &hook_cwd, &mut candidates);
                }
            } else if map.contains_key("hook_event_name") || map.contains_key("tool_input") {
                mode = "claude";
                if let Some(ti) = map.get("tool_input") {
                    collect_hook_paths_from_value(ti, &hook_cwd, &mut candidates);
                }
            }
        }
    } else if !trimmed.is_empty() {
        push_unique_candidate_path(&mut candidates, &cwd, trimmed);
    }
    if candidates.is_empty() && explicit_root.is_file() {
        candidates.push(explicit_root.to_path_buf());
    }

    let mut issues: Vec<String> = Vec::new();
    for path in candidates {
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.len() >= 2_000_000 {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !is_post_edit_supported_ext(ext) {
            continue;
        }
        let Ok(raw) = fs::read(&path) else {
            continue;
        };
        let Ok(raw_text) = std::str::from_utf8(&raw) else {
            issues.push(format!("{}: non-UTF-8 bytes after edit", path.display()));
            continue;
        };
        let text = raw_text.strip_prefix('\u{FEFF}').unwrap_or(raw_text);
        if text.lines().any(|l| {
            l.starts_with("<<<<<<< ") || l.trim_end() == "=======" || l.starts_with(">>>>>>> ")
        }) {
            issues.push(format!(
                "{}: unresolved git conflict marker (`<<<<<<<` / `=======` / `>>>>>>>`)",
                path.display()
            ));
            continue;
        }
        if let Err(err) = verify_syntax(text, ext) {
            let disp = path.to_string_lossy().replace('\\', "/");
            issues.push(format!("{disp}: {err}"));
        }
    }

    match mode {
        "claude" => {
            if !issues.is_empty() {
                let ctx = format!(
                    "[ap splice check] Syntax issue detected immediately after edit:\n- {}\nFix before proceeding.",
                    issues.join("\n- ")
                );
                println!(
                    "{}",
                    json!({
                        "hookSpecificOutput": {
                            "hookEventName": "PostToolUse",
                            "additionalContext": ctx
                        }
                    })
                );
            }
            0
        }
        "antigravity" => {
            println!("{{}}");
            if !issues.is_empty() {
                eprintln!("[ap splice check] {}", issues.join("; "));
            }
            0
        }
        _ => {
            if issues.is_empty() {
                0
            } else {
                for iss in &issues {
                    eprintln!("[ap splice check] {iss}");
                }
                2
            }
        }
    }
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    match cli.cmd {
        SubCmd::View {
            paths,
            symbols,
            heading,
            lines,
            json: as_json,
        } => {
            let mut results = Vec::new();
            for p in &paths {
                match view_single_file(p, &symbols, &heading, &lines) {
                    Ok(r) => results.push(r),
                    Err(e) => {
                        emit_err(as_json, &e);
                        return 1;
                    }
                }
            }
            if as_json {
                if results.len() == 1 {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "path": results[0].path,
                            "blocks": results[0].blocks,
                        }))
                        .unwrap_or_default()
                    );
                } else {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "path": results[0].path,
                            "blocks": results[0].blocks,
                            "files": results,
                        }))
                        .unwrap_or_default()
                    );
                }
            } else {
                for r in results {
                    for b in r.blocks {
                        println!(
                            "# {} :: {} [L{}-L{}]\n{}\n",
                            r.display_path, b.selector, b.start_line, b.end_line, b.numbered_source
                        );
                    }
                }
            }
            0
        }
        SubCmd::Apply {
            cwd,
            stdin,
            b64,
            spec,
            unlink_spec,
            test,
            test_cmd,
            rollback_on_test_fail,
            json: as_json,
        } => {
            let mut spec_file_to_unlink: Option<PathBuf> = None;
            let raw_spec = if stdin {
                let mut s = String::new();
                let _ = std::io::stdin().read_to_string(&mut s);
                s
            } else if let Some(b) = b64 {
                match base64::engine::general_purpose::STANDARD.decode(b.trim()) {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                    Err(e) => {
                        emit_err(
                            as_json,
                            &format!("[splice apply] invalid --b64 payload: {e}"),
                        );
                        return 1;
                    }
                }
            } else if let Some(sp) = spec {
                let resolved = if sp.is_absolute() {
                    sp
                } else if cwd.join(&sp).exists() {
                    cwd.join(&sp)
                } else {
                    sp
                };
                let Ok(s) = fs::read_to_string(&resolved) else {
                    emit_err(
                        as_json,
                        &format!("[splice apply] spec file not found: {}", resolved.display()),
                    );
                    return 1;
                };
                if unlink_spec {
                    spec_file_to_unlink = Some(resolved);
                }
                s
            } else {
                emit_err(
                    as_json,
                    "[splice apply] must pass one of --stdin, --b64, or --spec",
                );
                return 2;
            };

            let rc = apply_spec_str(
                &cwd,
                &raw_spec,
                test,
                &test_cmd,
                rollback_on_test_fail,
                as_json,
            );
            if rc == 0 {
                if let Some(sf) = spec_file_to_unlink {
                    let _ = fs::remove_file(sf);
                }
            }
            rc
        }
        SubCmd::Check {
            root,
            test,
            test_cmd,
            hook,
            json: as_json,
        } => {
            if hook {
                return run_post_edit_hook(&root);
            }
            if !root.exists() {
                emit_err(
                    as_json,
                    &format!("[splice check] path not found: {}", root.display()),
                );
                return 1;
            }
            let payload = collect_check_payload(&root, test, &test_cmd);
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                emit_check_human(&payload);
            }
            if payload.ok {
                0
            } else {
                1
            }
        }
        SubCmd::Rename {
            old_name,
            new_name,
            root,
            dry_run,
            test,
            test_cmd,
            rollback_on_test_fail,
            json: as_json,
        } => {
            let rep = rename::rename_symbol_workspace(
                &root,
                &old_name,
                &new_name,
                dry_run,
                test,
                &test_cmd,
                rollback_on_test_fail,
            );
            if as_json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            } else if rep.ok {
                println!("{}", rename::render_rename_human(&rep));
            } else {
                eprintln!("{}", rename::render_rename_human(&rep));
            }
            if rep.ok {
                0
            } else {
                1
            }
        }
        SubCmd::Rewrite {
            pattern,
            replacement,
            root,
            ext,
            no_tests,
            dry_run,
            test,
            test_cmd,
            rollback_on_test_fail,
            json: as_json,
        } => {
            let rep = rewrite::rewrite_pattern_workspace(
                &root,
                &pattern,
                &replacement,
                &ext,
                no_tests,
                dry_run,
                test,
                &test_cmd,
                rollback_on_test_fail,
            );
            if as_json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            } else if rep.ok {
                println!("{}", rewrite::render_rewrite_human(&rep));
            } else {
                eprintln!("{}", rewrite::render_rewrite_human(&rep));
            }
            if rep.ok {
                0
            } else {
                1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_op_transaction_merges_aliased_paths_without_clobbering() {
        let dir = std::env::temp_dir().join(format!("ap_splice_alias_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        let fp = dir.join("src/sample.rs");
        fs::write(&fp, "pub fn a() -> i32 { 1 }\npub fn b() -> i32 { 2 }\n").unwrap();

        let alias_second = if cfg!(windows) {
            "src/Sample.rs"
        } else {
            "src/../src/sample.rs"
        };
        let spec = serde_json::json!([
            {"op": "replace", "path": "./src/sample.rs", "old": "pub fn a() -> i32 { 1 }", "new": "pub fn a() -> i32 { 10 }"},
            {"op": "replace", "path": alias_second, "old": "pub fn b() -> i32 { 2 }", "new": "pub fn b() -> i32 { 20 }"}
        ])
        .to_string();

        let rc = apply_spec_silent(&dir, &spec);
        assert_eq!(rc, 0);
        let after = fs::read_to_string(&fp).unwrap();
        assert!(after.contains("10"), "first edit lost: {after}");
        assert!(after.contains("20"), "second edit lost: {after}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn preserves_utf8_bom_utf16_bom_and_crlf_across_apply_rename_rewrite_and_bom_json_check() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("ap_splice_bom_{}_{}", std::process::id(), nanos));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let p_utf8_bom = dir.join("bom.py");
        let p_u16le = dir.join("u16le.py");
        let p_u16be = dir.join("u16be.py");
        let p_json_bom = dir.join("cfg.json");

        let mut u16le_bytes = vec![0xFFu8, 0xFEu8];
        for u in "def old_sym():\r\n    return old_call(1)\r\n".encode_utf16() {
            u16le_bytes.extend_from_slice(&u.to_le_bytes());
        }
        let mut u16be_bytes = vec![0xFEu8, 0xFFu8];
        for u in "def keep_be():\r\n    return 1\r\n".encode_utf16() {
            u16be_bytes.extend_from_slice(&u.to_be_bytes());
        }
        fs::write(
            &p_utf8_bom,
            b"\xEF\xBB\xBFdef old_sym():\r\n    return old_call(1)\r\n",
        )
        .unwrap();
        fs::write(&p_u16le, &u16le_bytes).unwrap();
        fs::write(&p_u16be, &u16be_bytes).unwrap();
        fs::write(&p_json_bom, b"\xEF\xBB\xBF{\"ok\": true}\r\n").unwrap();

        // 1. `apply` preserves UTF-8 BOM, UTF-16LE BOM, UTF-16BE BOM, and CRLF
        let spec = "@@ FILE: bom.py\n<<<\n    return old_call(1)\n===\n    return old_call(2)\n>>>\n\
                    @@ FILE: u16le.py\n<<<\n    return old_call(1)\n===\n    return old_call(2)\n>>>\n\
                    @@ FILE: u16be.py\n<<<\n    return 1\n===\n    return 2\n>>>\n";
        assert_eq!(apply_spec_silent(&dir, spec), 0);
        let b_u8 = fs::read(&p_utf8_bom).unwrap();
        assert!(
            b_u8.starts_with(b"\xEF\xBB\xBF"),
            "UTF-8 BOM lost: {b_u8:?}"
        );
        assert!(b_u8.windows(2).any(|w| w == b"\r\n"), "CRLF lost");
        let b_le = fs::read(&p_u16le).unwrap();
        assert!(b_le.starts_with(b"\xFF\xFE"), "UTF-16LE BOM lost: {b_le:?}");
        let (dec_le, nl_le, enc_le) = decode_source_bytes_with_encoding(&b_le, "u16le.py").unwrap();
        assert_eq!(enc_le, SourceEncoding::Utf16LeBom);
        assert_eq!(nl_le, "\r\n");
        assert!(dec_le.contains("old_call(2)"), "{dec_le}");
        let b_be = fs::read(&p_u16be).unwrap();
        assert!(b_be.starts_with(b"\xFE\xFF"), "UTF-16BE BOM lost: {b_be:?}");
        let (dec_be, nl_be, enc_be) = decode_source_bytes_with_encoding(&b_be, "u16be.py").unwrap();
        assert_eq!(enc_be, SourceEncoding::Utf16BeBom);
        assert_eq!(nl_be, "\r\n");
        assert!(dec_be.contains("return 2"), "{dec_be}");

        // 2. `rename` preserves UTF-8 BOM & UTF-16LE BOM
        let r_rep =
            rename::rename_symbol_workspace(&dir, "old_sym", "new_sym", false, false, "", false);
        assert!(r_rep.ok && r_rep.files_changed == 2, "{r_rep:?}");
        assert!(fs::read(&p_utf8_bom).unwrap().starts_with(b"\xEF\xBB\xBF"));
        assert!(fs::read(&p_u16le).unwrap().starts_with(b"\xFF\xFE"));

        // 3. `rewrite` preserves UTF-8 BOM & UTF-16LE BOM
        let rw_rep = rewrite::rewrite_pattern_workspace(
            &dir,
            "old_call($X)",
            "new_call($X)",
            "py",
            false,
            false,
            false,
            "",
            false,
        );
        assert!(rw_rep.ok && rw_rep.files_changed == 2, "{rw_rep:?}");
        let rw_u8 = fs::read(&p_utf8_bom).unwrap();
        assert!(rw_u8.starts_with(b"\xEF\xBB\xBF"));
        assert!(String::from_utf8_lossy(&rw_u8).contains("new_call(2)"));
        let rw_le = fs::read(&p_u16le).unwrap();
        assert!(rw_le.starts_with(b"\xFF\xFE"));
        let (rw_le_txt, _, _) = decode_source_bytes_with_encoding(&rw_le, "u16le.py").unwrap();
        assert!(rw_le_txt.contains("new_call(2)"), "{rw_le_txt}");

        // 4. `splice check` passes cleanly on UTF-8 BOM JSON file
        let _ = fs::remove_file(&p_u16le);
        let _ = fs::remove_file(&p_u16be);
        let chk = collect_check_payload(&dir, false, "");
        let _ = fs::remove_dir_all(&dir);
        assert!(
            chk.ok,
            "UTF-8 BOM json/py must pass check: {:?}",
            chk.issues
        );
    }
}
