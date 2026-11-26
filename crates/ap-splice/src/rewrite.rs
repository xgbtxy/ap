use crate::ast::{language_for_ext, verify_syntax};
use crate::ast_search::{search_ast_source, AstQuery};
use crate::check::{collect_check_payload, TestRunResult};
use crate::{
    decode_source_bytes_with_encoding, encode_source_bytes, purge_stale_pyc, write_file_atomic,
};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

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
    ".ap-undo",
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    ".pi",
    "vendor",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteFileChange {
    pub path: String,
    pub replacements: usize,
    pub lines: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteReport {
    pub ok: bool,
    pub dry_run: bool,
    pub pattern: String,
    pub replacement: String,
    pub files_scanned: usize,
    pub files_changed: usize,
    pub total_replacements: usize,
    pub changes: Vec<RewriteFileChange>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub syntax_errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_result: Option<TestRunResult>,
    pub rolled_back: bool,
    pub elapsed_ms: f64,
}

fn is_test_file_rel(rel: &str) -> bool {
    let norm = rel.replace('\\', "/").to_ascii_lowercase();
    if norm.starts_with("tests/")
        || norm.starts_with("test/")
        || norm.contains("/tests/")
        || norm.contains("/test/")
        || norm.contains("/__tests__/")
    {
        return true;
    }
    let fname = norm.rsplit('/').next().unwrap_or(norm.as_str());
    fname.starts_with("test_")
        || fname.contains("_test.")
        || fname.contains(".test.")
        || fname.contains(".spec.")
}

/// Expand a rewrite template containing `$NAME` and `$$$NAME` captures in a single pass
/// so `$A` never corrupts `$ARGS`, and cleanly elide commas adjacent to an empty `$$$NAME`.
pub fn render_ast_replacement(
    template: &str,
    raw_captures: &BTreeMap<String, String>,
    norm_captures: &BTreeMap<String, String>,
) -> String {
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len() + 32);
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'$' {
            if template[i..].starts_with("$$$") {
                let mut name_end = i + 3;
                while name_end < bytes.len()
                    && (bytes[name_end].is_ascii_alphanumeric() || bytes[name_end] == b'_')
                {
                    name_end += 1;
                }
                if name_end > i + 3 {
                    let name = &template[i + 3..name_end];
                    let val = raw_captures
                        .get(name)
                        .or_else(|| norm_captures.get(name))
                        .map(String::as_str)
                        .unwrap_or("");
                    if val.is_empty() {
                        // Trim preceding `,` (+ surrounding spaces/tabs) or following `,` (+ single space)
                        let trimmed_end_len = out.trim_end_matches([' ', '\t']).len();
                        if trimmed_end_len > 0 && out.as_bytes()[trimmed_end_len - 1] == b',' {
                            let before_comma = out[..trimmed_end_len - 1]
                                .trim_end_matches([' ', '\t'])
                                .len();
                            out.truncate(before_comma);
                            i = name_end;
                            continue;
                        }
                        let rest = &template[name_end..];
                        let after_ws = rest.trim_start_matches([' ', '\t']);
                        if let Some(after_comma) = after_ws.strip_prefix(',') {
                            let consumed_comma_offset = template.len() - after_comma.len();
                            let after_comma_ws =
                                template[consumed_comma_offset..].trim_start_matches([' ', '\t']);
                            i = template.len() - after_comma_ws.len();
                            continue;
                        }
                        i = name_end;
                        continue;
                    }
                    out.push_str(val);
                    i = name_end;
                    continue;
                }
            } else if i + 1 < bytes.len()
                && (bytes[i + 1].is_ascii_alphabetic() || bytes[i + 1] == b'_')
            {
                let mut name_end = i + 2;
                while name_end < bytes.len()
                    && (bytes[name_end].is_ascii_alphanumeric() || bytes[name_end] == b'_')
                {
                    name_end += 1;
                }
                let name = &template[i + 1..name_end];
                if let Some(val) = raw_captures.get(name).or_else(|| norm_captures.get(name)) {
                    out.push_str(val);
                } else {
                    out.push_str(&template[i..name_end]);
                }
                i = name_end;
                continue;
            }
        }
        let ch = template[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

pub fn rewrite_source_with_ast(
    source: &str,
    ext: &str,
    query: &AstQuery,
    replacement: &str,
) -> Result<(String, usize, Vec<usize>), String> {
    if !matches!(query, AstQuery::Pattern(_)) {
        return Err(
            "[splice rewrite] pattern must be a structural AST pattern (not `kind:...`)"
                .to_string(),
        );
    }
    let mut hits = search_ast_source(source, ext, query, 50_000);
    if hits.is_empty() {
        return Ok((source.to_string(), 0, Vec::new()));
    }
    hits.sort_by_key(|h| h.start_byte);

    // Filter out any unexpected overlapping ranges safely before right-to-left splice
    let mut non_overlap = Vec::with_capacity(hits.len());
    let mut last_end = 0usize;
    for h in hits {
        if h.start_byte >= last_end && h.start_byte <= h.end_byte && h.end_byte <= source.len() {
            last_end = h.end_byte;
            non_overlap.push(h);
        }
    }
    if non_overlap.is_empty() {
        return Ok((source.to_string(), 0, Vec::new()));
    }

    let mut lines: Vec<usize> = non_overlap.iter().map(|m| m.line).collect();
    lines.sort_unstable();
    lines.dedup();
    let count = non_overlap.len();

    let mut out = source.to_string();
    for m in non_overlap.iter().rev() {
        let rendered = render_ast_replacement(replacement, &m.raw_captures, &m.captures);
        if out.is_char_boundary(m.start_byte) && out.is_char_boundary(m.end_byte) {
            out.replace_range(m.start_byte..m.end_byte, &rendered);
        }
    }
    Ok((out, count, lines))
}

#[allow(clippy::too_many_arguments)]
pub fn rewrite_pattern_workspace(
    root: &Path,
    pattern: &str,
    replacement: &str,
    ext_filter: &str,
    no_tests: bool,
    dry_run: bool,
    run_tests: bool,
    test_cmd_override: &str,
    rollback_on_test_fail: bool,
) -> RewriteReport {
    let t0 = Instant::now();
    let mk_err = |errs: Vec<String>| RewriteReport {
        ok: false,
        dry_run,
        pattern: pattern.to_string(),
        replacement: replacement.to_string(),
        files_scanned: 0,
        files_changed: 0,
        total_replacements: 0,
        changes: Vec::new(),
        syntax_errors: errs,
        test_ok: None,
        test_summary: None,
        test_result: None,
        rolled_back: false,
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
    };

    let query = match AstQuery::parse(pattern) {
        Ok(q @ AstQuery::Pattern(_)) => q,
        Ok(AstQuery::Kinds(_)) => {
            return mk_err(vec![
                "[splice rewrite] pattern must be a structural AST pattern (not `kind:...`)"
                    .to_string(),
            ]);
        }
        Err(e) => return mk_err(vec![e]),
    };

    if !root.exists() {
        return mk_err(vec![format!("Path not found: {}", root.display())]);
    }

    let allowed_exts: HashSet<String> = ext_filter
        .split(',')
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let root_display_base = if root_canon.is_file() {
        root_canon.parent().unwrap_or(&root_canon).to_path_buf()
    } else {
        root_canon.clone()
    };
    let skip_set: HashSet<&str> = SKIP_DIRS.iter().copied().collect();

    let mut candidate_paths: Vec<PathBuf> = Vec::new();
    if root_canon.is_file() {
        candidate_paths.push(root_canon.clone());
    } else {
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
        for entry in walker.flatten() {
            let p = entry.path();
            if p.is_file() {
                candidate_paths.push(p.to_path_buf());
            }
        }
        candidate_paths.sort();
    }

    let mut files_scanned = 0usize;
    let mut staged: Vec<(PathBuf, Vec<u8>, Vec<u8>, RewriteFileChange)> = Vec::new();
    let mut syntax_errors: Vec<String> = Vec::new();

    for p in candidate_paths {
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if language_for_ext(&ext).is_none() {
            continue;
        }
        if !allowed_exts.is_empty() && !allowed_exts.contains(&ext) {
            continue;
        }
        let rel = p
            .strip_prefix(&root_display_base)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        if no_tests && is_test_file_rel(&rel) {
            continue;
        }
        files_scanned += 1;

        let Ok(raw_b) = fs::read(&p) else {
            continue;
        };
        if raw_b.contains(&0) && !raw_b.starts_with(b"\xFF\xFE") && !raw_b.starts_with(b"\xFE\xFF")
        {
            continue;
        }
        let Ok((clean_lf, nl_sep, enc)) = decode_source_bytes_with_encoding(&raw_b, &rel) else {
            continue;
        };

        let Ok((updated_lf, count, lines)) =
            rewrite_source_with_ast(&clean_lf, &ext, &query, replacement)
        else {
            continue;
        };
        if count == 0 || updated_lf == clean_lf {
            continue;
        }

        if let Err(syn_err) = verify_syntax(&updated_lf, &ext) {
            syntax_errors.push(format!("`{rel}`: AST {syn_err}"));
            continue;
        }

        let out_bytes = encode_source_bytes(&updated_lf, nl_sep, enc);
        staged.push((
            p,
            raw_b,
            out_bytes,
            RewriteFileChange {
                path: rel,
                replacements: count,
                lines,
            },
        ));
    }

    if !syntax_errors.is_empty() {
        return RewriteReport {
            ok: false,
            dry_run,
            pattern: pattern.to_string(),
            replacement: replacement.to_string(),
            files_scanned,
            files_changed: 0,
            total_replacements: 0,
            changes: Vec::new(),
            syntax_errors,
            test_ok: None,
            test_summary: None,
            test_result: None,
            rolled_back: false,
            elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
        };
    }

    let files_changed = staged.len();
    let total_replacements: usize = staged.iter().map(|s| s.3.replacements).sum();
    let changes: Vec<RewriteFileChange> = staged.iter().map(|s| s.3.clone()).collect();

    if dry_run || staged.is_empty() {
        return RewriteReport {
            ok: true,
            dry_run,
            pattern: pattern.to_string(),
            replacement: replacement.to_string(),
            files_scanned,
            files_changed,
            total_replacements,
            changes,
            syntax_errors: Vec::new(),
            test_ok: None,
            test_summary: None,
            test_result: None,
            rolled_back: false,
            elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
        };
    }

    let mut backups: HashMap<PathBuf, Vec<u8>> = HashMap::new();
    for (p, orig_b, new_b, _) in &staged {
        backups.insert(p.clone(), orig_b.clone());
        if let Err(e) = write_file_atomic(p, new_b) {
            for (bp, ob) in &backups {
                let _ = write_file_atomic(bp, ob).or_else(|_| fs::write(bp, ob));
            }
            return RewriteReport {
                ok: false,
                dry_run: false,
                pattern: pattern.to_string(),
                replacement: replacement.to_string(),
                files_scanned,
                files_changed: 0,
                total_replacements: 0,
                changes: Vec::new(),
                syntax_errors: vec![format!(
                    "Write failed on {} ({e}); rolled back.",
                    p.display()
                )],
                test_ok: None,
                test_summary: None,
                test_result: None,
                rolled_back: true,
                elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
            };
        }
        if p.extension().and_then(|e| e.to_str()) == Some("py") {
            purge_stale_pyc(p);
        }
    }

    let mut test_result = None;
    let mut test_ok = None;
    let mut test_summary = None;
    let mut rolled_back = false;
    let mut ok = true;

    if run_tests {
        let chk = collect_check_payload(&root_display_base, true, test_cmd_override);
        ok = chk.ok;
        test_ok = Some(chk.ok);
        if let Some(ref tr) = chk.test_result {
            test_summary = Some(format!(
                "{} (`{}`)",
                if tr.ok { "PASSED" } else { "FAILED" },
                tr.command
            ));
        } else if !chk.issues.is_empty() {
            test_summary = Some(chk.issues.join("; "));
        }
        test_result = chk.test_result;
        if !ok && rollback_on_test_fail {
            for (bp, ob) in &backups {
                let _ = write_file_atomic(bp, ob).or_else(|_| fs::write(bp, ob));
                if bp.extension().and_then(|e| e.to_str()) == Some("py") {
                    purge_stale_pyc(bp);
                }
            }
            rolled_back = true;
        }
    }

    RewriteReport {
        ok,
        dry_run: false,
        pattern: pattern.to_string(),
        replacement: replacement.to_string(),
        files_scanned,
        files_changed,
        total_replacements,
        changes,
        syntax_errors: Vec::new(),
        test_ok,
        test_summary,
        test_result,
        rolled_back,
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
    }
}

pub fn render_rewrite_human(rep: &RewriteReport) -> String {
    if !rep.ok {
        let rb = if rep.rolled_back {
            " (rolled back)"
        } else {
            ""
        };
        let detail = if !rep.syntax_errors.is_empty() {
            rep.syntax_errors.join("; ")
        } else if let Some(ref ts) = rep.test_summary {
            ts.clone()
        } else {
            "unknown error".to_string()
        };
        return format!("[splice rewrite] FAILED{rb}: {detail}");
    }
    let tag = if rep.dry_run { "DRY-RUN" } else { "OK" };
    if rep.total_replacements == 0 {
        return format!(
            "[splice rewrite] {tag} — 0 AST matches for `{}` across {} file(s) in {} ms (comments & strings ignored).",
            rep.pattern, rep.files_scanned, rep.elapsed_ms
        );
    }
    let mut out = vec![format!(
        "[splice rewrite] {tag} — `{}` -> `{}`: {} replacement(s) across {} file(s) ({} scanned) in {} ms",
        rep.pattern,
        rep.replacement,
        rep.total_replacements,
        rep.files_changed,
        rep.files_scanned,
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
    if let Some(ref ts) = rep.test_summary {
        out.push(format!("  - Tests: {ts}"));
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDirClean(PathBuf);
    impl Drop for TempDirClean {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mk_temp_dir(label: &str) -> TempDirClean {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ap_splice_rewrite_{label}_{n}"));
        fs::create_dir_all(&dir).unwrap();
        TempDirClean(dir)
    }

    #[test]
    fn multifile_structural_rewrite_ignores_comments_strings_and_preserves_multiline() {
        let td = mk_temp_dir("multifile");
        let a = td.0.join("client.ts");
        let b = td.0.join("nested").join("service.js");
        fs::create_dir_all(b.parent().unwrap()).unwrap();

        let orig_a = r#"// oldFetch("ignored", opts)
const doc = "oldFetch(url, opts)";
export async function load() {
  return oldFetch(
    "/api/v1",
    {
      method: "POST",
      keepalive: true
    }
  );
}
"#;
        let orig_b = "function ping(u, o) { return oldFetch(u, o); }\n";
        fs::write(&a, orig_a).unwrap();
        fs::write(&b, orig_b).unwrap();

        let rep = rewrite_pattern_workspace(
            &td.0,
            "oldFetch($URL, $OPTS)",
            "apiClient.request($URL, $OPTS)",
            "",
            false,
            false,
            false,
            "",
            false,
        );
        assert!(rep.ok, "{rep:?}");
        assert_eq!(rep.files_changed, 2);
        assert_eq!(rep.total_replacements, 2);

        let got_a = fs::read_to_string(&a).unwrap();
        assert!(got_a.contains(r#"// oldFetch("ignored", opts)"#));
        assert!(got_a.contains(r#"const doc = "oldFetch(url, opts)";"#));
        assert!(got_a.contains("apiClient.request(\"/api/v1\", {\n      method: \"POST\","));

        let got_b = fs::read_to_string(&b).unwrap();
        assert_eq!(
            got_b,
            "function ping(u, o) { return apiClient.request(u, o); }\n"
        );
    }

    #[test]
    fn variadic_empty_elision_and_repeated_metavar_rewrite() {
        let src = r#"
function demo(user) {
  fetch("/a");
  fetch("/b", { retry: 2 }, true);
  return user.auth && user.auth();
}
"#;
        let q1 = AstQuery::parse("fetch($URL, $$$ARGS)").unwrap();
        let (step1, cnt1, _) =
            rewrite_source_with_ast(src, "js", &q1, "httpGet($URL, $$$ARGS)").unwrap();
        assert_eq!(cnt1, 2);
        assert!(step1.contains("httpGet(\"/a\");"), "{step1}");
        assert!(
            step1.contains("httpGet(\"/b\", { retry: 2 }, true);"),
            "{step1}"
        );

        let q2 = AstQuery::parse("$X && $X()").unwrap();
        let (step2, cnt2, _) = rewrite_source_with_ast(&step1, "js", &q2, "$X?.()").unwrap();
        assert_eq!(cnt2, 1);
        assert!(step2.contains("return user.auth?.();"), "{step2}");
    }

    #[test]
    fn syntax_gate_aborts_atomically_and_dry_run_writes_nothing() {
        let td = mk_temp_dir("gate");
        let f1 = td.0.join("one.js");
        let f2 = td.0.join("two.js");
        let s1 = "oldCall(x);\n";
        let s2 = "oldCall(y);\n";
        fs::write(&f1, s1).unwrap();
        fs::write(&f2, s2).unwrap();

        let dry = rewrite_pattern_workspace(
            &td.0,
            "oldCall($X)",
            "newCall($X)",
            "",
            false,
            true,
            false,
            "",
            false,
        );
        assert!(dry.ok && dry.dry_run && dry.total_replacements == 2);
        assert_eq!(fs::read_to_string(&f1).unwrap(), s1);
        assert_eq!(fs::read_to_string(&f2).unwrap(), s2);

        let broken = rewrite_pattern_workspace(
            &td.0,
            "oldCall($X)",
            "broken(((($X",
            "",
            false,
            false,
            false,
            "",
            false,
        );
        assert!(!broken.ok);
        assert!(!broken.syntax_errors.is_empty());
        assert_eq!(broken.files_changed, 0);
        assert_eq!(fs::read_to_string(&f1).unwrap(), s1);
        assert_eq!(fs::read_to_string(&f2).unwrap(), s2);
    }
}
