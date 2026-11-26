use crate::ast::{language_for_ext, verify_syntax};
use crate::check::{collect_check_payload, TestRunResult};
use crate::{
    decode_source_bytes_with_encoding, encode_source_bytes, purge_stale_pyc, write_file_atomic,
};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tree_sitter::{Node, Parser};

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "target",
    ".next",
    ".nuxt",
    ".sieve",
    ".baton",
    ".recall",
    ".guard",
    ".probe",
    ".splice",
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    ".pi",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRenameChange {
    pub path: String,
    pub replacements: usize,
    pub lines: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameReport {
    pub ok: bool,
    pub dry_run: bool,
    pub rolled_back: bool,
    pub old_name: String,
    pub new_name: String,
    pub scanned_files: usize,
    pub files_changed: usize,
    pub total_replacements: usize,
    pub elapsed_ms: f64,
    pub changes: Vec<FileRenameChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_result: Option<TestRunResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn is_valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_renameable_ident_kind(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "type_identifier"
            | "field_identifier"
            | "property_identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern"
            | "package_identifier"
            | "statement_identifier"
    )
}

fn collect_ident_spans(
    node: Node,
    src: &[u8],
    old_name: &str,
    out: &mut Vec<(usize, usize, usize)>,
) {
    let kind = node.kind();
    if kind.contains("comment")
        || kind.contains("string")
        || kind.contains("regex")
        || kind == "char_literal"
    {
        return;
    }
    if node.child_count() == 0 && is_renameable_ident_kind(kind) {
        if let Ok(txt) = node.utf8_text(src) {
            if txt == old_name {
                out.push((
                    node.start_byte(),
                    node.end_byte(),
                    node.start_position().row + 1,
                ));
            }
        }
        return;
    }
    let mut walk = node.walk();
    for ch in node.children(&mut walk) {
        collect_ident_spans(ch, src, old_name, out);
    }
}

pub fn rename_symbol_workspace(
    root: &Path,
    old_name: &str,
    new_name: &str,
    dry_run: bool,
    run_tests: bool,
    test_cmd_override: &str,
    rollback_on_test_fail: bool,
) -> RenameReport {
    let t0 = Instant::now();
    let mk_err = |msg: String| RenameReport {
        ok: false,
        dry_run,
        rolled_back: false,
        old_name: old_name.to_string(),
        new_name: new_name.to_string(),
        scanned_files: 0,
        files_changed: 0,
        total_replacements: 0,
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
        changes: Vec::new(),
        test_result: None,
        error: Some(msg),
    };

    if !is_valid_ident(old_name) {
        return mk_err(format!("Invalid source identifier `{old_name}`."));
    }
    if !is_valid_ident(new_name) {
        return mk_err(format!("Invalid target identifier `{new_name}`."));
    }
    if old_name == new_name {
        return mk_err(format!(
            "Source and target identifier are identical (`{old_name}`)."
        ));
    }
    if !root.exists() {
        return mk_err(format!("Path not found: {}", root.display()));
    }

    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let skip_set: HashSet<&str> = SKIP_DIRS.iter().copied().collect();

    let mut scanned_files = 0usize;
    let mut staged: Vec<(PathBuf, Vec<u8>, Vec<u8>, FileRenameChange)> = Vec::new();

    let walker = WalkBuilder::new(&root_canon)
        .hidden(false)
        .git_ignore(true)
        .filter_entry(move |e| {
            if e.depth() == 0 {
                return true;
            }
            let nm = e.file_name().to_str().unwrap_or("");
            !skip_set.contains(nm)
        })
        .build();

    let mut candidate_paths: Vec<PathBuf> = Vec::new();
    for entry in walker.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        if language_for_ext(ext).is_some() {
            candidate_paths.push(p.to_path_buf());
        }
    }
    candidate_paths.sort();

    for p in candidate_paths {
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let Some(lang) = language_for_ext(&ext) else {
            continue;
        };
        scanned_files += 1;
        let Ok(raw_b) = fs::read(&p) else {
            continue;
        };
        let rel = p
            .strip_prefix(&root_canon)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok((clean_lf, nl_sep, enc)) = decode_source_bytes_with_encoding(&raw_b, &rel) else {
            continue;
        };
        if !clean_lf.contains(old_name) {
            continue;
        }

        let mut parser = Parser::new();
        if parser.set_language(&lang).is_err() {
            continue;
        }
        let Some(tree) = parser.parse(&clean_lf, None) else {
            continue;
        };
        let mut spans: Vec<(usize, usize, usize)> = Vec::new();
        collect_ident_spans(tree.root_node(), clean_lf.as_bytes(), old_name, &mut spans);
        if spans.is_empty() {
            continue;
        }

        // Deduplicate & sort descending by start_byte for safe in-place splicing
        spans.sort_by_key(|a| std::cmp::Reverse(a.0));
        spans.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

        let mut lines: Vec<usize> = spans.iter().map(|s| s.2).collect();
        lines.sort_unstable();
        lines.dedup();
        let count = spans.len();

        let mut updated = clean_lf.clone();
        for (start, end, _) in spans {
            if start <= end && end <= updated.len() {
                updated.replace_range(start..end, new_name);
            }
        }

        if let Err(syn_err) = verify_syntax(&updated, &ext) {
            return RenameReport {
                ok: false,
                dry_run,
                rolled_back: false,
                old_name: old_name.to_string(),
                new_name: new_name.to_string(),
                scanned_files,
                files_changed: 0,
                total_replacements: 0,
                elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
                changes: Vec::new(),
                test_result: None,
                error: Some(format!(
                    "Aborted before write: renaming `{old_name}` -> `{new_name}` caused AST {syn_err} in `{rel}`"
                )),
            };
        }

        let out_bytes = encode_source_bytes(&updated, nl_sep, enc);
        staged.push((
            p,
            raw_b,
            out_bytes,
            FileRenameChange {
                path: rel,
                replacements: count,
                lines,
            },
        ));
    }

    let files_changed = staged.len();
    let total_replacements: usize = staged.iter().map(|s| s.3.replacements).sum();
    let changes: Vec<FileRenameChange> = staged.iter().map(|s| s.3.clone()).collect();

    if dry_run || staged.is_empty() {
        return RenameReport {
            ok: true,
            dry_run,
            rolled_back: false,
            old_name: old_name.to_string(),
            new_name: new_name.to_string(),
            scanned_files,
            files_changed,
            total_replacements,
            elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
            changes,
            test_result: None,
            error: None,
        };
    }

    let mut backups: HashMap<PathBuf, Vec<u8>> = HashMap::new();
    for (p, orig_b, new_b, _) in &staged {
        backups.insert(p.clone(), orig_b.clone());
        if let Err(e) = write_file_atomic(p, new_b) {
            for (bp, ob) in &backups {
                let _ = write_file_atomic(bp, ob).or_else(|_| fs::write(bp, ob));
            }
            return RenameReport {
                ok: false,
                dry_run: false,
                rolled_back: true,
                old_name: old_name.to_string(),
                new_name: new_name.to_string(),
                scanned_files,
                files_changed: 0,
                total_replacements: 0,
                elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
                changes: Vec::new(),
                test_result: None,
                error: Some(format!(
                    "Write failed on {} ({e}); rolled back.",
                    p.display()
                )),
            };
        }
        if p.extension().and_then(|e| e.to_str()) == Some("py") {
            purge_stale_pyc(p);
        }
    }

    let mut test_result = None;
    let mut rolled_back = false;
    let mut ok = true;
    let mut err_msg = None;

    if run_tests {
        let chk = collect_check_payload(&root_canon, true, test_cmd_override);
        let tests_ok = chk.ok;
        test_result = chk.test_result;
        if !tests_ok {
            ok = false;
            if rollback_on_test_fail {
                for (bp, ob) in &backups {
                    let _ = write_file_atomic(bp, ob).or_else(|_| fs::write(bp, ob));
                    if bp.extension().and_then(|e| e.to_str()) == Some("py") {
                        purge_stale_pyc(bp);
                    }
                }
                rolled_back = true;
            }
            err_msg = Some(if !chk.issues.is_empty() {
                chk.issues.join("; ")
            } else {
                "Post-rename check/tests failed".to_string()
            });
        }
    }

    RenameReport {
        ok,
        dry_run: false,
        rolled_back,
        old_name: old_name.to_string(),
        new_name: new_name.to_string(),
        scanned_files,
        files_changed,
        total_replacements,
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
        changes,
        test_result,
        error: err_msg,
    }
}

pub fn render_rename_human(rep: &RenameReport) -> String {
    if !rep.ok {
        let rb = if rep.rolled_back {
            " (rolled back)"
        } else {
            ""
        };
        return format!(
            "[splice rename] FAILED{rb}: {}",
            rep.error.as_deref().unwrap_or("unknown error")
        );
    }
    let tag = if rep.dry_run { "DRY-RUN" } else { "OK" };
    if rep.total_replacements == 0 {
        return format!(
            "[splice rename] {tag} — 0 AST occurrences of `{}` across {} file(s) in {} ms (comments & strings ignored).",
            rep.old_name, rep.scanned_files, rep.elapsed_ms
        );
    }
    let mut out = vec![format!(
        "[splice rename] {tag} — `{}` -> `{}`: {} AST identifier(s) across {} file(s) ({} scanned) in {} ms",
        rep.old_name,
        rep.new_name,
        rep.total_replacements,
        rep.files_changed,
        rep.scanned_files,
        rep.elapsed_ms
    )];
    for ch in &rep.changes {
        let ln_preview: Vec<String> = ch.lines.iter().take(12).map(|l| format!("L{l}")).collect();
        let more = if ch.lines.len() > 12 {
            format!(" (+{} more)", ch.lines.len() - 12)
        } else {
            String::new()
        };
        out.push(format!(
            "  - {} ({} hit(s): {}{more})",
            ch.path,
            ch.replacements,
            ln_preview.join(", ")
        ));
    }
    if let Some(ref tr) = rep.test_result {
        out.push(format!(
            "  - Tests: {} (`{}`)",
            if tr.ok { "PASSED" } else { "FAILED" },
            tr.command
        ));
    }
    out.join("\n")
}
