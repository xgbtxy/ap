use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffFinding {
    pub kind: String,
    pub file: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiShift {
    pub kind: String,
    pub file: String,
    pub symbol: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffAuditReport {
    pub is_git_repo: bool,
    pub files_changed: usize,
    pub lines_added: usize,
    pub lines_deleted: usize,
    pub findings: Vec<DiffFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_changes: Vec<ApiShift>,
}

fn is_test_path(p: &str) -> bool {
    let low = p.to_ascii_lowercase();
    low.starts_with("test/")
        || low.starts_with("tests/")
        || low.contains(".test.")
        || low.contains(".spec.")
        || low.contains("/test_")
        || low.starts_with("test_")
        || low.ends_with("_test.go")
        || low.ends_with("_test.rs")
}

fn strip_comments_and_strings(s: &str) -> String {
    let trim = s.trim();
    if trim.starts_with("//")
        || (trim.starts_with('#') && !trim.starts_with("#["))
        || trim.starts_with('*')
        || trim.starts_with("/*")
    {
        return String::new();
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
                out.push('"');
            }
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            break;
        }
        if b == b'"' || b == b'\'' || b == b'`' {
            quote = Some(b);
            out.push('"');
            i += 1;
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn is_assertion_line(s: &str) -> bool {
    let code = strip_comments_and_strings(s);
    if code.is_empty() {
        return false;
    }
    let low = code.to_ascii_lowercase();
    low.contains("assert")
        || low.contains("expect(")
        || low.contains(".should")
        || low.contains("t.error")
        || low.contains("t.fatal")
}

fn is_parameterized_loop_line(s: &str) -> bool {
    let code = strip_comments_and_strings(s);
    if code.is_empty() {
        return false;
    }
    let low = code.to_ascii_lowercase();
    low.contains("for ")
        || low.contains(".foreach(")
        || low.contains(".each(")
        || low.contains("@pytest.mark.parametrize")
}

fn has_debug_leftover(s: &str) -> Option<&'static str> {
    let code = strip_comments_and_strings(s);
    let trim = code.trim();
    if trim.is_empty() {
        return None;
    }
    if trim == "debugger;" || trim == "debugger" || trim.contains(" debugger;") {
        return Some("debugger;");
    }
    if trim.contains("breakpoint()") {
        return Some("breakpoint()");
    }
    if trim.contains("pdb.set_trace()") {
        return Some("pdb.set_trace()");
    }
    if trim.contains("dbg!(") {
        return Some("dbg!(");
    }
    None
}

fn has_test_skip_marker(s: &str) -> Option<&'static str> {
    let code = strip_comments_and_strings(s);
    let trim = code.trim();
    if trim.is_empty() {
        return None;
    }
    if trim.contains(".only(") {
        return Some(".only(");
    }
    if trim.contains(".skip(") {
        return Some(".skip(");
    }
    if trim.contains("#[ignore") {
        return Some("#[ignore]");
    }
    if s.trim().contains("@pytest.mark.skip") {
        return Some("@pytest.mark.skip");
    }
    if trim.contains("t.Skip(") || trim.contains("t.SkipNow(") {
        return Some("t.Skip()");
    }
    None
}

fn has_incomplete_stub(s: &str) -> Option<&'static str> {
    let code = strip_comments_and_strings(s);
    let trim = code.trim();
    if !trim.is_empty() {
        if trim.contains("todo!(") {
            return Some("todo!()");
        }
        if trim.contains("unimplemented!(") {
            return Some("unimplemented!()");
        }
        if trim.contains("raise NotImplementedError") {
            return Some("raise NotImplementedError");
        }
    }
    let raw_trim = s.trim();
    if !raw_trim.starts_with("//") && !raw_trim.starts_with('#') && !raw_trim.starts_with('*') {
        let low = raw_trim.to_ascii_lowercase();
        if low.contains("throw new error(\"not implemented")
            || low.contains("throw new error('not implemented")
        {
            return Some("throw new Error('not implemented')");
        }
    }
    None
}

fn norm_sig_params(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn extract_public_decl(file: &str, line: &str) -> Option<(String, Option<String>)> {
    struct ApiRes {
        rs_fn: Regex,
        rs_type: Regex,
        jsts_fn: Regex,
        jsts_type: Regex,
        py_fn: Regex,
        py_cls: Regex,
        go_fn: Regex,
        go_type: Regex,
    }
    static RE: OnceLock<ApiRes> = OnceLock::new();
    let re = RE.get_or_init(|| ApiRes {
        rs_fn: Regex::new(r"^\s*pub\s+(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)").unwrap(),
        rs_type: Regex::new(r"^\s*pub\s+(?:struct|enum|trait|type)\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap(),
        jsts_fn: Regex::new(r"^\s*export\s+(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)").unwrap(),
        jsts_type: Regex::new(r"^\s*export\s+(?:declare\s+)?(?:class|interface|type|const|enum)\s+([A-Za-z_$][A-Za-z0-9_$]*)").unwrap(),
        py_fn: Regex::new(r"^(?:async\s+)?def\s+([A-Za-z][A-Za-z0-9_]*)\s*\(([^)]*)\)").unwrap(),
        py_cls: Regex::new(r"^class\s+([A-Za-z][A-Za-z0-9_]*)").unwrap(),
        go_fn: Regex::new(r"^func\s+(?:\([^)]+\)\s*)?([A-Z][A-Za-z0-9_]*)\s*\(([^)]*)\)").unwrap(),
        go_type: Regex::new(r"^type\s+([A-Z][A-Za-z0-9_]*)\s+(?:struct|interface)\b").unwrap(),
    });

    let ext = Path::new(file)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "rs" => {
            if let Some(c) = re.rs_fn.captures(line) {
                return Some((c[1].to_string(), Some(norm_sig_params(&c[2]))));
            }
            if let Some(c) = re.rs_type.captures(line) {
                return Some((c[1].to_string(), None));
            }
        }
        "ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs" => {
            if let Some(c) = re.jsts_fn.captures(line) {
                return Some((c[1].to_string(), Some(norm_sig_params(&c[2]))));
            }
            if let Some(c) = re.jsts_type.captures(line) {
                return Some((c[1].to_string(), None));
            }
        }
        "py" => {
            if let Some(c) = re.py_fn.captures(line) {
                if !c[1].starts_with('_') {
                    return Some((c[1].to_string(), Some(norm_sig_params(&c[2]))));
                }
            }
            if let Some(c) = re.py_cls.captures(line) {
                if !c[1].starts_with('_') {
                    return Some((c[1].to_string(), None));
                }
            }
        }
        "go" => {
            if let Some(c) = re.go_fn.captures(line) {
                return Some((c[1].to_string(), Some(norm_sig_params(&c[2]))));
            }
            if let Some(c) = re.go_type.captures(line) {
                return Some((c[1].to_string(), None));
            }
        }
        _ => {}
    }
    None
}

pub fn audit_git_diff(root: &Path) -> DiffAuditReport {
    let check_git = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(root)
        .output();
    let is_git = check_git.map(|o| o.status.success()).unwrap_or(false);
    if !is_git {
        return DiffAuditReport {
            is_git_repo: false,
            files_changed: 0,
            lines_added: 0,
            lines_deleted: 0,
            findings: Vec::new(),
            api_changes: Vec::new(),
        };
    }

    let diff_out = Command::new("git")
        .args(["diff", "-U0", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .or_else(|| {
            Command::new("git")
                .args(["diff", "-U0"])
                .current_dir(root)
                .output()
                .ok()
        });
    let diff_txt = diff_out
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let mut cur_file = String::new();
    let mut per_file_add: HashMap<String, usize> = HashMap::new();
    let mut per_file_del: HashMap<String, usize> = HashMap::new();
    let mut per_file_assert_add: HashMap<String, usize> = HashMap::new();
    let mut per_file_assert_del: HashMap<String, usize> = HashMap::new();
    let mut per_file_param_loop_add: HashMap<String, bool> = HashMap::new();
    let mut per_file_del_decls: BTreeMap<String, BTreeMap<String, Option<String>>> =
        BTreeMap::new();
    let mut per_file_add_decls: BTreeMap<String, BTreeMap<String, Option<String>>> =
        BTreeMap::new();
    let mut findings: Vec<DiffFinding> = Vec::new();
    let mut total_add = 0usize;
    let mut total_del = 0usize;

    for ln in diff_txt.lines() {
        if let Some(rest) = ln.strip_prefix("+++ b/") {
            cur_file = rest.trim().to_string();
            per_file_add.entry(cur_file.clone()).or_insert(0);
            per_file_del.entry(cur_file.clone()).or_insert(0);
            continue;
        }
        if cur_file.is_empty()
            || ln.starts_with("+++")
            || ln.starts_with("---")
            || ln.starts_with("@@")
        {
            continue;
        }
        if let Some(added) = ln.strip_prefix('+') {
            total_add += 1;
            *per_file_add.entry(cur_file.clone()).or_insert(0) += 1;
            if is_test_path(&cur_file) {
                if is_assertion_line(added) {
                    *per_file_assert_add.entry(cur_file.clone()).or_insert(0) += 1;
                }
                if is_parameterized_loop_line(added) {
                    per_file_param_loop_add.insert(cur_file.clone(), true);
                }
                if let Some(tok) = has_test_skip_marker(added) {
                    findings.push(DiffFinding {
                        kind: "TEST-SKIPPED".to_string(),
                        file: cur_file.clone(),
                        detail: format!(
                            "Added test focus/skip `{tok}` in `{}`: `{}`",
                            cur_file,
                            added.trim().chars().take(100).collect::<String>()
                        ),
                    });
                }
            } else {
                if let Some((sym, params)) = extract_public_decl(&cur_file, added) {
                    per_file_add_decls
                        .entry(cur_file.clone())
                        .or_default()
                        .insert(sym, params);
                }
                if let Some(tok) = has_debug_leftover(added) {
                    findings.push(DiffFinding {
                        kind: "DEBUG-LEFTOVER".to_string(),
                        file: cur_file.clone(),
                        detail: format!(
                            "Added `{tok}` in `{}`: `{}`",
                            cur_file,
                            added.trim().chars().take(100).collect::<String>()
                        ),
                    });
                }
                if let Some(tok) = has_incomplete_stub(added) {
                    findings.push(DiffFinding {
                        kind: "INCOMPLETE-STUB".to_string(),
                        file: cur_file.clone(),
                        detail: format!(
                            "Added unfinished stub `{tok}` in `{}`: `{}`",
                            cur_file,
                            added.trim().chars().take(100).collect::<String>()
                        ),
                    });
                }
                for sec_hit in crate::inspect_secret_safety(added) {
                    if sec_hit.starts_with("Credential/secret") {
                        findings.push(DiffFinding {
                            kind: "SECRET-ADDED".to_string(),
                            file: cur_file.clone(),
                            detail: format!("{sec_hit} in `{cur_file}`"),
                        });
                    }
                }
            }
        } else if let Some(deleted) = ln.strip_prefix('-') {
            total_del += 1;
            *per_file_del.entry(cur_file.clone()).or_insert(0) += 1;
            if is_test_path(&cur_file) {
                if is_assertion_line(deleted) {
                    *per_file_assert_del.entry(cur_file.clone()).or_insert(0) += 1;
                }
            } else if let Some((sym, params)) = extract_public_decl(&cur_file, deleted) {
                per_file_del_decls
                    .entry(cur_file.clone())
                    .or_default()
                    .insert(sym, params);
            }
        }
    }

    let mut api_changes: Vec<ApiShift> = Vec::new();
    for (file, del_map) in &per_file_del_decls {
        let add_map = per_file_add_decls.get(file);
        for (sym, del_params) in del_map {
            match add_map.and_then(|m| m.get(sym)) {
                None => {
                    api_changes.push(ApiShift {
                        kind: "BREAKING-API-REMOVED".to_string(),
                        file: file.clone(),
                        symbol: sym.clone(),
                        detail: format!(
                            "Public declaration `{sym}` removed/renamed in `{file}` — run `ap atlas impact {sym}` to verify callers."
                        ),
                    });
                }
                Some(Some(add_p)) => {
                    if let Some(del_p) = del_params {
                        if del_p != add_p {
                            api_changes.push(ApiShift {
                                kind: "BREAKING-API-SIGNATURE".to_string(),
                                file: file.clone(),
                                symbol: sym.clone(),
                                detail: format!(
                                    "Signature changed `({del_p})` -> `({add_p})` for `{sym}` in `{file}` — run `ap atlas impact {sym}` to verify callers."
                                ),
                            });
                        }
                    }
                }
                Some(None) => {}
            }
        }
    }

    let mut files: Vec<String> = per_file_add.keys().cloned().collect();
    files.sort();
    for f in &files {
        let a = *per_file_add.get(f).unwrap_or(&0);
        let d = *per_file_del.get(f).unwrap_or(&0);
        let aa = *per_file_assert_add.get(f).unwrap_or(&0);
        let ad = *per_file_assert_del.get(f).unwrap_or(&0);
        let has_param_loop = *per_file_param_loop_add.get(f).unwrap_or(&false);
        if is_test_path(f) && ad > aa && !(aa >= 1 && has_param_loop) {
            findings.push(DiffFinding {
                kind: "TEST-WEAKENING".to_string(),
                file: f.clone(),
                detail: format!(
                    "Removed {ad} assertion(s) in `{f}` while adding only {aa} — verify you did not delete tests to force a green build."
                ),
            });
        }
        if d >= 25 && d > a.saturating_mul(3) {
            findings.push(DiffFinding {
                kind: "MASS-DELETION".to_string(),
                file: f.clone(),
                detail: format!(
                    "Deleted {d} lines vs +{a} added in `{f}` — verify no accidental truncation or unintended action-bias deletion."
                ),
            });
        }
    }

    DiffAuditReport {
        is_git_repo: true,
        files_changed: files.len(),
        lines_added: total_add,
        lines_deleted: total_del,
        findings,
        api_changes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn detects_removed_export_and_changed_signature_as_advisory_api_changes() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ap_diff_api_{n}"));
        fs::create_dir_all(dir.join("src")).unwrap();
        let ok_git = Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok_git {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        let _ = Command::new("git")
            .args(["config", "user.email", "t@example.com"])
            .current_dir(&dir)
            .status();
        let _ = Command::new("git")
            .args(["config", "user.name", "T"])
            .current_dir(&dir)
            .status();
        fs::write(
            dir.join("src/api.ts"),
            "export function charge(amount: number) { return amount; }\nexport function legacyDrop() { return 0; }\n",
        )
        .unwrap();
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .status();
        let _ = Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&dir)
            .status();

        fs::write(
            dir.join("src/api.ts"),
            "export function charge(amount: number, currency: string) { return `${amount}${currency}`; }\n",
        )
        .unwrap();

        let rep = audit_git_diff(&dir);
        assert!(rep.is_git_repo);
        assert!(rep.findings.is_empty(), "{:?}", rep.findings);
        assert!(
            rep.api_changes
                .iter()
                .any(|c| c.kind == "BREAKING-API-SIGNATURE" && c.symbol == "charge"),
            "{:?}",
            rep.api_changes
        );
        assert!(
            rep.api_changes
                .iter()
                .any(|c| c.kind == "BREAKING-API-REMOVED" && c.symbol == "legacyDrop"),
            "{:?}",
            rep.api_changes
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ignores_comments_strings_placeholders_and_parameterized_refactors() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ap_diff_fp_{n}"));
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join("tests")).unwrap();
        let ok_git = Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok_git {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        let _ = Command::new("git")
            .args(["config", "user.email", "t@example.com"])
            .current_dir(&dir)
            .status();
        let _ = Command::new("git")
            .args(["config", "user.name", "T"])
            .current_dir(&dir)
            .status();
        fs::write(dir.join("src/rules.rs"), "pub fn init() -> bool { true }\n").unwrap();
        fs::write(
            dir.join("tests/calc_test.rs"),
            "fn checks() {\n  assert_eq!(1, 1);\n  assert_eq!(2, 2);\n  assert_eq!(3, 3);\n}\n",
        )
        .unwrap();
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .status();
        let _ = Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&dir)
            .status();

        // Add string constants mentioning "breakpoint()" / "todo!(" / placeholder key + parameterize 3 asserts into a loop
        let placeholder_tok = ["sk", "ant", "example_placeholder_key_123456"].join("-");
        let rule_src = format!(
            "pub fn init() -> &'static str {{\n  // todo!(explain)\n  let _tok = \"{placeholder_tok}\";\n  if _tok.contains(\"breakpoint()\") {{ return \"todo!(\"; }}\n  \"debugger;\"\n}}\n"
        );
        fs::write(dir.join("src/rules.rs"), rule_src).unwrap();
        fs::write(
            dir.join("tests/calc_test.rs"),
            "fn checks() {\n  for x in [1, 2, 3] { assert_eq!(x, x); }\n}\n",
        )
        .unwrap();

        let rep = audit_git_diff(&dir);
        assert!(
            rep.findings.is_empty(),
            "unexpected false findings: {:?}",
            rep.findings
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
