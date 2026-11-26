use crate::ast::verify_syntax;
use ignore::WalkBuilder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
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
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".sieve",
    ".baton",
    ".recall",
    ".guard",
    ".probe",
    ".splice",
    ".agents",
    ".claude",
    ".grok",
    ".cursor",
    ".codex",
    ".openclaw",
    ".hermes",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRunResult {
    pub ok: bool,
    pub command: String,
    pub returncode: i32,
    pub elapsed_ms: f64,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckPayload {
    pub ok: bool,
    pub checked_py_files: usize,
    pub checked_ts_js_files: usize,
    pub checked_rs_go_c_files: usize,
    pub issues: Vec<String>,
    pub elapsed_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_result: Option<TestRunResult>,
}

fn check_regexes() -> &'static (Regex, Regex, Regex) {
    static RE: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    RE.get_or_init(|| {
        let conflict = Regex::new(r"(?m)^(?:<<<<<<<|=======|>>>>>>>)\s").unwrap();
        let ts_rel = Regex::new(
            r#"(?m)(?:import|export)\s+(?:type\s+)?(?:[^'"]*?\s+from\s+)?['"](\.[^'"]+)['"]|require\(\s*['"](\.[^'"]+)['"]\s*\)"#,
        )
        .unwrap();
        let py_from = Regex::new(r"(?m)^\s*from\s+(\.*)\s*([A-Za-z0-9_.]*)\s+import\b").unwrap();
        (conflict, ts_rel, py_from)
    })
}

fn which_exists(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn find_python_bin(root: &Path) -> Option<String> {
    #[cfg(windows)]
    let venv_cands = [
        root.join(".venv").join("Scripts").join("python.exe"),
        root.join("venv").join("Scripts").join("python.exe"),
    ];
    #[cfg(not(windows))]
    let venv_cands = [
        root.join(".venv").join("bin").join("python"),
        root.join("venv").join("bin").join("python"),
    ];
    for c in venv_cands {
        if c.is_file() {
            return Some(c.to_string_lossy().to_string());
        }
    }
    for bin in ["python3", "python"] {
        if which_exists(bin) {
            return Some(bin.to_string());
        }
    }
    None
}

fn resolve_ts_rel_target(
    from_file: &Path,
    spec: &str,
    all_code_set: &HashSet<PathBuf>,
) -> Option<PathBuf> {
    let parent = from_file.parent().unwrap_or_else(|| Path::new("."));
    let base = parent.join(spec);
    let mut cands = vec![base.clone()];
    if let Some(ext) = base.extension().and_then(|e| e.to_str()) {
        if matches!(ext, "js" | "mjs" | "cjs") {
            let stem = base.with_extension("");
            cands.push(stem.with_extension("ts"));
            cands.push(stem.with_extension("tsx"));
        }
    } else {
        for ext in ["ts", "tsx", "js", "jsx", "mjs", "json"] {
            cands.push(PathBuf::from(format!("{}.{ext}", base.display())));
        }
        for ext in ["ts", "tsx", "js", "mjs"] {
            cands.push(base.join(format!("index.{ext}")));
        }
    }
    for c in cands {
        if let Ok(cc) = fs::canonicalize(&c) {
            if all_code_set.contains(&cc) || cc.is_file() {
                return Some(cc);
            }
        }
        if c.is_file() {
            return Some(c);
        }
    }
    None
}

struct TsModuleInterface {
    exports: HashSet<String>,
    has_wildcard_export: bool,
    fn_arities: HashMap<String, (usize, usize)>,
}

fn ts_export_regexes() -> &'static (Regex, Regex, Regex, Regex, Regex) {
    static RE: OnceLock<(Regex, Regex, Regex, Regex, Regex)> = OnceLock::new();
    RE.get_or_init(|| {
        let fn_re = Regex::new(
            r"(?m)^\s*export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)",
        )
        .unwrap();
        let decl_re = Regex::new(
            r"(?m)^\s*export\s+(?:declare\s+)?(?:const|let|var|class|interface|type|enum)\s+([A-Za-z_$][\w$]*)",
        )
        .unwrap();
        let list_re = Regex::new(r"(?m)^\s*export\s+(?:type\s+)?\{([^}]+)\}").unwrap();
        let star_re = Regex::new(r"(?m)^\s*export\s+\*\s+from\s+").unwrap();
        let named_imp_re = Regex::new(
            r#"(?m)^\s*import\s+\{([^}]+)\}\s+from\s+['"](\.[^'"]+)['"]"#,
        )
        .unwrap();
        (fn_re, decl_re, list_re, star_re, named_imp_re)
    })
}

fn parse_param_arity(params_raw: &str) -> (usize, usize) {
    let p = params_raw.trim();
    if p.is_empty() {
        return (0, 0);
    }
    let mut min_a = 0usize;
    let mut max_a = 0usize;
    let mut depth = 0i32;
    let mut seg = String::new();
    let mut parts = Vec::new();
    for ch in p.chars() {
        match ch {
            '(' | '[' | '{' | '<' => {
                depth += 1;
                seg.push(ch);
            }
            ')' | ']' | '}' | '>' => {
                depth -= 1;
                seg.push(ch);
            }
            ',' if depth == 0 => {
                parts.push(seg.trim().to_string());
                seg.clear();
            }
            _ => seg.push(ch),
        }
    }
    if !seg.trim().is_empty() {
        parts.push(seg.trim().to_string());
    }
    for item in parts {
        if item.starts_with("this:") || item.starts_with("this ") {
            continue;
        }
        if item.starts_with("...") {
            return (min_a, usize::MAX);
        }
        max_a += 1;
        let head = item.split(':').next().unwrap_or(&item).trim();
        if !item.contains('=') && !head.ends_with('?') {
            min_a += 1;
        }
    }
    (min_a, max_a)
}

fn extract_ts_interface(txt: &str) -> TsModuleInterface {
    let (fn_re, decl_re, list_re, star_re, _) = ts_export_regexes();
    let mut exports = HashSet::new();
    let mut fn_arities = HashMap::new();
    let has_wildcard_export =
        star_re.is_match(txt) || txt.contains("module.exports") || txt.contains("exports.");
    if txt.contains("export default ") {
        exports.insert("default".to_string());
    }
    for cap in fn_re.captures_iter(txt) {
        let name = cap[1].to_string();
        let arity = parse_param_arity(&cap[2]);
        exports.insert(name.clone());
        fn_arities.insert(name, arity);
    }
    for cap in decl_re.captures_iter(txt) {
        exports.insert(cap[1].to_string());
    }
    for cap in list_re.captures_iter(txt) {
        for raw_item in cap[1].split(',') {
            let clean = raw_item.trim().trim_start_matches("type ").trim();
            if clean.is_empty() {
                continue;
            }
            let exported = clean
                .rsplit_once(" as ")
                .map(|(_, alias)| alias.trim())
                .unwrap_or(clean);
            exports.insert(exported.to_string());
        }
    }
    TsModuleInterface {
        exports,
        has_wildcard_export,
        fn_arities,
    }
}

fn count_top_level_args(inside: &str) -> Option<usize> {
    let t = inside.trim();
    if t.is_empty() {
        return Some(0);
    }
    if t.contains("...") {
        return None;
    }
    let mut depth = 0i32;
    let mut in_str: Option<char> = None;
    let mut prev = '\0';
    let mut commas = 0usize;
    for ch in t.chars() {
        if let Some(q) = in_str {
            if ch == q && prev != '\\' {
                in_str = None;
            }
        } else {
            match ch {
                '\'' | '"' | '`' => in_str = Some(ch),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => commas += 1,
                _ => {}
            }
        }
        prev = ch;
    }
    if depth != 0 {
        return None;
    }
    Some(commas + 1)
}

fn detect_test_command(
    root: &Path,
    py_files: &[PathBuf],
    ts_js_files: &[PathBuf],
) -> Option<Vec<String>> {
    if root.join("Cargo.toml").is_file() && which_exists("cargo") {
        return Some(vec!["cargo".into(), "test".into(), "--quiet".into()]);
    }
    if root.join("go.mod").is_file() && which_exists("go") {
        return Some(vec!["go".into(), "test".into(), "./...".into()]);
    }

    let py_tests: Vec<&PathBuf> = py_files
        .iter()
        .filter(|f| {
            let rel = f.strip_prefix(root).unwrap_or(f);
            let top = rel
                .components()
                .next()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .unwrap_or_default();
            let nm = f.file_name().and_then(|s| s.to_str()).unwrap_or("");
            matches!(top.as_str(), "tests" | "test")
                || nm.starts_with("test_")
                || nm.ends_with("_test.py")
        })
        .collect();
    if !py_tests.is_empty() {
        if let Some(py) = find_python_bin(root) {
            let pyproject = fs::read_to_string(root.join("pyproject.toml")).unwrap_or_default();
            let wants_pytest = root.join("pytest.ini").is_file()
                || root.join("conftest.py").is_file()
                || pyproject.contains("[tool.pytest");
            if wants_pytest
                && Command::new(&py)
                    .args(["-c", "import pytest"])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            {
                return Some(vec![py, "-m".into(), "pytest".into(), "-q".into()]);
            }
            let start_dir = if root.join("tests").is_dir() {
                "tests"
            } else if root.join("test").is_dir() {
                "test"
            } else {
                "."
            };
            if start_dir != "." && root.join(start_dir).join("__init__.py").is_file() {
                return Some(vec![
                    py,
                    "-m".into(),
                    "unittest".into(),
                    "discover".into(),
                    "-s".into(),
                    start_dir.into(),
                    "-t".into(),
                    ".".into(),
                ]);
            }
            return Some(vec![
                py,
                "-m".into(),
                "unittest".into(),
                "discover".into(),
                "-s".into(),
                start_dir.into(),
            ]);
        }
    }

    let ts_test_files: Vec<String> = ts_js_files
        .iter()
        .filter_map(|f| {
            let rel = f.strip_prefix(root).ok()?;
            let rel_s = rel.to_string_lossy().replace('\\', "/");
            let low = rel_s.to_ascii_lowercase();
            if low.contains(".test.")
                || low.contains(".spec.")
                || low.starts_with("tests/")
                || low.starts_with("test/")
                || low.starts_with("__tests__/")
            {
                Some(rel_s)
            } else {
                None
            }
        })
        .collect();
    if !ts_test_files.is_empty() && which_exists("node") {
        let has_ts = ts_test_files
            .iter()
            .any(|p| p.ends_with(".ts") || p.ends_with(".tsx"))
            || ts_js_files
                .iter()
                .any(|f| matches!(f.extension().and_then(|e| e.to_str()), Some("ts" | "tsx")));
        let mut cmd = vec!["node".to_string()];
        if has_ts {
            cmd.push("--experimental-strip-types".to_string());
        }
        cmd.push("--test".to_string());
        cmd.extend(ts_test_files);
        return Some(cmd);
    }
    None
}

fn bound_test_output(raw: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = raw.lines().collect();
    if lines.len() <= max_lines {
        return lines.join("\n").trim().to_string();
    }
    let head = &lines[..35.min(lines.len())];
    let tail_n = max_lines.saturating_sub(35);
    let tail = &lines[lines.len().saturating_sub(tail_n)..];
    let mid_msg = format!(
        "... [{} middle test log lines omitted] ...",
        lines.len() - max_lines
    );
    let mut s = head.join("\n");
    s.push('\n');
    s.push_str(&mid_msg);
    s.push('\n');
    s.push_str(&tail.join("\n"));
    s.trim().to_string()
}

pub fn collect_check_payload(
    root: &Path,
    run_tests: bool,
    test_cmd_override: &str,
) -> CheckPayload {
    let t0 = Instant::now();
    let (conflict_re, ts_rel_re, py_from_re) = check_regexes();
    let raw_canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let root_canon = {
        let s = raw_canon.to_string_lossy();
        if let Some(st) = s.strip_prefix(r"\\?\") {
            if st.len() >= 2 && st.as_bytes()[1] == b':' {
                PathBuf::from(st)
            } else {
                raw_canon
            }
        } else {
            raw_canon
        }
    };
    let mut issues: Vec<String> = Vec::new();
    let mut py_files: Vec<PathBuf> = Vec::new();
    let mut ts_js_files: Vec<PathBuf> = Vec::new();
    let mut rs_go_c_files = 0usize;
    let mut all_code_files: HashSet<PathBuf> = HashSet::new();
    let mut py_mod_names: HashSet<String> = HashSet::new();

    let walker = WalkBuilder::new(&root_canon)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            let nm = e.file_name().to_string_lossy();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                return !SKIP_DIRS.contains(&nm.as_ref()) && !nm.starts_with(".git");
            }
            true
        })
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let p = entry.path().to_path_buf();
        let fname = entry.file_name().to_string_lossy().to_string();
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(
            ext.as_str(),
            "py" | "json"
                | "toml"
                | "md"
                | "yml"
                | "yaml"
                | "go"
                | "rs"
                | "c"
                | "h"
                | "ts"
                | "tsx"
                | "js"
                | "jsx"
                | "mjs"
                | "cjs"
        ) {
            continue;
        }
        let rel_s = p
            .strip_prefix(&root_canon)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(raw_b) = fs::read(&p) else { continue };
        let raw_txt = match std::str::from_utf8(&raw_b) {
            Ok(s) => s,
            Err(uerr) => {
                issues.push(format!("{rel_s}: Invalid UTF-8 encoding ({uerr})"));
                continue;
            }
        };
        let txt = raw_txt.strip_prefix('\u{FEFF}').unwrap_or(raw_txt);
        if conflict_re.is_match(txt) {
            issues.push(format!("{rel_s}: Unresolved git merge conflict marker"));
        }
        all_code_files.insert(p.clone());

        if matches!(
            ext.as_str(),
            "py" | "json" | "go" | "rs" | "c" | "h" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs"
        ) && !fname.ends_with(".d.ts")
        {
            if let Err(syn_err) = verify_syntax(txt, &ext) {
                issues.push(format!("{rel_s}: {syn_err}"));
                continue;
            }
        }

        match ext.as_str() {
            "py" => {
                py_files.push(p.clone());
                if let Ok(rel_p) = p.strip_prefix(&root_canon) {
                    let mut parts: Vec<String> = rel_p
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy().to_string())
                        .collect();
                    if parts.first().map(String::as_str) == Some("src") && parts.len() > 1 {
                        parts.remove(0);
                    }
                    let mname = if parts.last().map(String::as_str) == Some("__init__.py") {
                        parts[..parts.len() - 1].join(".")
                    } else if let Some(last) = parts.last_mut() {
                        *last = last.trim_end_matches(".py").to_string();
                        parts.join(".")
                    } else {
                        String::new()
                    };
                    if !mname.is_empty() {
                        if let Some(top) = mname.split('.').next() {
                            py_mod_names.insert(top.to_string());
                        }
                        py_mod_names.insert(mname);
                    }
                }
            }
            "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" if !fname.ends_with(".d.ts") => {
                ts_js_files.push(p);
            }
            "rs" | "go" | "c" | "h" => {
                rs_go_c_files += 1;
            }
            _ => {}
        }
    }

    let local_top_pkgs: HashSet<String> = py_mod_names
        .iter()
        .filter_map(|m| m.split('.').next().map(String::from))
        .collect();

    for pf in &py_files {
        let rel_s = pf
            .strip_prefix(&root_canon)
            .unwrap_or(pf)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(txt) = fs::read_to_string(pf) else {
            continue;
        };
        let parts: Vec<String> = pf
            .strip_prefix(&root_canon)
            .unwrap_or(pf)
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect();
        let pkg_parts = if parts.first().map(String::as_str) == Some("src") && parts.len() > 1 {
            &parts[1..parts.len() - 1]
        } else {
            &parts[..parts.len().saturating_sub(1)]
        };
        for cap in py_from_re.captures_iter(&txt) {
            let dots = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let base = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let lineno = txt[..cap.get(0).unwrap().start()]
                .bytes()
                .filter(|&b| b == b'\n')
                .count()
                + 1;
            let full_m = if !dots.is_empty() {
                let level = dots.len();
                if level - 1 > pkg_parts.len() {
                    issues.push(format!(
                        "{rel_s}:L{lineno}: Relative import beyond top-level package"
                    ));
                    continue;
                }
                let cut = pkg_parts.len() - (level - 1);
                let mut segs: Vec<&str> = pkg_parts[..cut].iter().map(String::as_str).collect();
                if !base.is_empty() {
                    segs.push(base);
                }
                segs.join(".")
            } else {
                base.to_string()
            };
            let top = full_m.split('.').next().unwrap_or("");
            if !top.is_empty() && local_top_pkgs.contains(top) && !py_mod_names.contains(&full_m) {
                issues.push(format!("{rel_s}:L{lineno}: Broken local import `{full_m}`"));
            }
        }
    }

    let mut ts_interfaces: HashMap<PathBuf, TsModuleInterface> = HashMap::new();
    for tf in &ts_js_files {
        if let Ok(txt) = fs::read_to_string(tf) {
            let key = fs::canonicalize(tf).unwrap_or_else(|_| tf.clone());
            ts_interfaces.insert(key, extract_ts_interface(&txt));
        }
    }
    let (_, _, _, _, named_imp_re) = ts_export_regexes();

    for tf in &ts_js_files {
        let rel_s = tf
            .strip_prefix(&root_canon)
            .unwrap_or(tf)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(txt) = fs::read_to_string(tf) else {
            continue;
        };
        for cap in ts_rel_re.captures_iter(&txt) {
            let spec = cap
                .get(1)
                .or_else(|| cap.get(2))
                .map(|m| m.as_str())
                .unwrap_or("");
            if !spec.is_empty() && resolve_ts_rel_target(tf, spec, &all_code_files).is_none() {
                let lineno = txt[..cap.get(0).unwrap().start()]
                    .bytes()
                    .filter(|&b| b == b'\n')
                    .count()
                    + 1;
                issues.push(format!(
                    "{rel_s}:L{lineno}: Broken relative import `{spec}`"
                ));
            }
        }
        for cap in named_imp_re.captures_iter(&txt) {
            let raw_names = &cap[1];
            let spec = &cap[2];
            let Some(target_p) = resolve_ts_rel_target(tf, spec, &all_code_files) else {
                continue;
            };
            let ext_t = target_p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext_t == "json" {
                continue;
            }
            let Some(iface) = ts_interfaces.get(&target_p) else {
                continue;
            };
            if iface.has_wildcard_export || iface.exports.is_empty() {
                continue;
            }
            let lineno = txt[..cap.get(0).unwrap().start()]
                .bytes()
                .filter(|&b| b == b'\n')
                .count()
                + 1;
            for item in raw_names.split(',') {
                let clean = item.trim().trim_start_matches("type ").trim();
                if clean.is_empty() {
                    continue;
                }
                let (orig, local_alias) = clean
                    .split_once(" as ")
                    .map(|(o, a)| (o.trim(), a.trim()))
                    .unwrap_or((clean, clean));
                if !iface.exports.contains(orig) {
                    let mut avail: Vec<&str> = iface.exports.iter().map(String::as_str).collect();
                    avail.sort();
                    issues.push(format!(
                        "{rel_s}:L{lineno}: Phantom named import `{orig}` from `{spec}` (exported: {})",
                        avail.into_iter().take(8).collect::<Vec<_>>().join(", ")
                    ));
                } else if let Some(&(min_a, max_a)) = iface.fn_arities.get(orig) {
                    let call_pat = format!("{local_alias}(");
                    for (l_idx, ln) in txt.lines().enumerate() {
                        if ln.trim_start().starts_with("import ")
                            || ln.trim_start().starts_with("//")
                        {
                            continue;
                        }
                        if let Some(pos) = ln.find(&call_pat) {
                            let prev_ok = pos == 0
                                || !ln.as_bytes()[pos - 1].is_ascii_alphanumeric()
                                    && ln.as_bytes()[pos - 1] != b'.'
                                    && ln.as_bytes()[pos - 1] != b'_';
                            if !prev_ok {
                                continue;
                            }
                            let after = &ln[pos + call_pat.len()..];
                            let mut depth = 1i32;
                            let mut end_off = None;
                            for (ci, ch) in after.char_indices() {
                                if ch == '(' {
                                    depth += 1;
                                } else if ch == ')' {
                                    depth -= 1;
                                    if depth == 0 {
                                        end_off = Some(ci);
                                        break;
                                    }
                                }
                            }
                            if let Some(eo) = end_off {
                                if let Some(argc) = count_top_level_args(&after[..eo]) {
                                    if argc < min_a || argc > max_a {
                                        let exp = if min_a == max_a {
                                            format!("{min_a}")
                                        } else if max_a == usize::MAX {
                                            format!(">={min_a}")
                                        } else {
                                            format!("{min_a}..={max_a}")
                                        };
                                        issues.push(format!(
                                            "{rel_s}:L{}: Call arity mismatch `{local_alias}(...{argc} args)` — `{spec}::{orig}` expects {exp} arg(s)",
                                            l_idx + 1
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut test_result = None;
    if issues.is_empty() && (run_tests || !test_cmd_override.trim().is_empty()) {
        let t_test0 = Instant::now();
        let mut py_paths = vec![root_canon.to_string_lossy().to_string()];
        if root_canon.join("src").is_dir() {
            py_paths.insert(0, root_canon.join("src").to_string_lossy().to_string());
        }
        if let Ok(existing_py) = std::env::var("PYTHONPATH") {
            if !existing_py.is_empty() {
                py_paths.push(existing_py);
            }
        }
        let sep = if cfg!(windows) { ";" } else { ":" };
        let py_path_joined = py_paths.join(sep);

        let (cmd_disp, out_opt) = if !test_cmd_override.trim().is_empty() {
            #[cfg(windows)]
            let o = Command::new("cmd")
                .args(["/C", test_cmd_override])
                .current_dir(&root_canon)
                .env("PYTHONPATH", &py_path_joined)
                .output();
            #[cfg(not(windows))]
            let o = Command::new("sh")
                .args(["-c", test_cmd_override])
                .current_dir(&root_canon)
                .env("PYTHONPATH", &py_path_joined)
                .output();
            (test_cmd_override.to_string(), o.ok())
        } else if let Some(auto_cmd) = detect_test_command(&root_canon, &py_files, &ts_js_files) {
            let disp = auto_cmd
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    if i == 0 {
                        Path::new(s)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(s)
                            .to_string()
                    } else {
                        s.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            let o = match Command::new(&auto_cmd[0])
                .args(&auto_cmd[1..])
                .current_dir(&root_canon)
                .env("PYTHONPATH", &py_path_joined)
                .output()
            {
                Ok(res) => Some(res),
                #[cfg(windows)]
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Command::new("cmd")
                    .arg("/C")
                    .args(&auto_cmd)
                    .current_dir(&root_canon)
                    .env("PYTHONPATH", &py_path_joined)
                    .output()
                    .ok(),
                Err(_) => None,
            };
            (disp, o)
        } else {
            ("<none detected>".to_string(), None)
        };

        if let Some(proc_out) = out_opt {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&proc_out.stdout),
                String::from_utf8_lossy(&proc_out.stderr)
            );
            let t_ms = (t_test0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
            let code = proc_out.status.code().unwrap_or(1);
            let test_ok = code == 0;
            if !test_ok {
                issues.push(format!("Test suite failed (exit {code}): `{cmd_disp}`"));
            }
            test_result = Some(TestRunResult {
                ok: test_ok,
                command: cmd_disp,
                returncode: code,
                elapsed_ms: t_ms,
                output: bound_test_output(&combined, if test_ok { 25 } else { 95 }),
            });
        }
    }

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
    CheckPayload {
        ok: issues.is_empty(),
        checked_py_files: py_files.len(),
        checked_ts_js_files: ts_js_files.len(),
        checked_rs_go_c_files: rs_go_c_files,
        issues,
        elapsed_ms,
        test_result,
    }
}
