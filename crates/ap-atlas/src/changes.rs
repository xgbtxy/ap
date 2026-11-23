use crate::impact::{analyze_symbol_impact, ImpactSite};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;
use tree_sitter::{Language, Node, Parser};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangedFileStat {
    pub path: String,
    pub added: usize,
    pub deleted: usize,
    pub modified_symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesReport {
    pub is_git_repo: bool,
    pub base_ref: String,
    pub elapsed_ms: f64,
    pub files: Vec<ChangedFileStat>,
    pub modified_symbols: Vec<String>,
    pub external_callers: Vec<ImpactSite>,
    pub related_tests: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggested_test_cmds: Vec<String>,
}

pub(crate) fn lang_for_ext(ext: &str) -> Option<Language> {
    match ext.to_ascii_lowercase().as_str() {
        "py" => Some(tree_sitter_python::LANGUAGE.into()),
        "ts" | "mts" | "cts" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        "js" | "jsx" | "mjs" | "cjs" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "rs" => Some(tree_sitter_rust::LANGUAGE.into()),
        "c" | "h" => Some(tree_sitter_c::LANGUAGE.into()),
        _ => None,
    }
}

fn extract_node_name<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    if let Some(n) = node.child_by_field_name("name") {
        if let Ok(s) = n.utf8_text(src) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t);
            }
        }
    }
    if let Some(d) = node.child_by_field_name("declarator") {
        if d.kind() == "identifier" {
            return d.utf8_text(src).ok().map(str::trim);
        }
        return extract_node_name(d, src);
    }
    None
}

pub(crate) fn collect_symbol_spans(node: Node, src: &[u8], out: &mut Vec<(String, usize, usize)>) {
    let k = node.kind();
    let is_decl = matches!(
        k,
        "function_declaration"
            | "function_definition"
            | "function_item"
            | "method_definition"
            | "method_declaration"
            | "class_declaration"
            | "class_definition"
            | "struct_item"
            | "enum_item"
            | "trait_item"
            | "interface_declaration"
            | "type_alias_declaration"
            | "type_item"
            | "type_spec"
    );
    if is_decl {
        if let Some(nm) = extract_node_name(node, src) {
            let s = node.start_position().row + 1;
            let e = (node.end_position().row + 1).max(s);
            out.push((nm.to_string(), s, e));
        }
    }
    let mut walk = node.walk();
    for ch in node.children(&mut walk) {
        collect_symbol_spans(ch, src, out);
    }
}

fn hunk_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@").unwrap())
}

fn is_py_test_rel(norm: &str) -> bool {
    let fname = norm.rsplit('/').next().unwrap_or(norm);
    norm.ends_with(".py") && (fname.starts_with("test_") || fname.ends_with("_test.py"))
}

fn is_jsts_test_rel(norm: &str) -> bool {
    let fname = norm.rsplit('/').next().unwrap_or(norm);
    (fname.contains(".test.") || fname.contains(".spec."))
        && matches!(
            fname.rsplit('.').next().unwrap_or(""),
            "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts"
        )
}

fn push_unique(out: &mut Vec<String>, cmd: String) {
    if !cmd.is_empty() && !out.iter().any(|existing| existing == &cmd) {
        out.push(cmd);
    }
}

pub fn build_suggested_test_cmds(
    root: &Path,
    related_tests: &[String],
    files: &[ChangedFileStat],
) -> Vec<String> {
    let mut all_paths: Vec<String> = Vec::new();
    let mut seen_paths: HashSet<String> = HashSet::new();
    for t in related_tests {
        let norm = t.replace('\\', "/");
        if seen_paths.insert(norm.clone()) {
            all_paths.push(norm);
        }
    }
    for f in files {
        let norm = f.path.replace('\\', "/");
        let low = norm.to_ascii_lowercase();
        let is_test = is_py_test_rel(&low)
            || is_jsts_test_rel(&low)
            || low.ends_with("_test.go")
            || (low.starts_with("tests/") && low.ends_with(".rs"));
        if is_test && seen_paths.insert(norm.clone()) {
            all_paths.push(norm);
        }
    }

    let mut py_tests: Vec<String> = Vec::new();
    let mut rust_int_tests: Vec<String> = Vec::new();
    let mut rust_crates: Vec<String> = Vec::new();
    let mut jsts_tests: Vec<String> = Vec::new();
    let mut go_dirs: Vec<String> = Vec::new();

    for p in &all_paths {
        let low = p.to_ascii_lowercase();
        if is_py_test_rel(&low) && py_tests.len() < 6 {
            py_tests.push(p.clone());
        } else if low.starts_with("tests/") && low.ends_with(".rs") && rust_int_tests.len() < 4 {
            if let Some(stem) = Path::new(p).file_stem().and_then(|s| s.to_str()) {
                rust_int_tests.push(stem.to_string());
            }
        } else if is_jsts_test_rel(&low) && jsts_tests.len() < 6 {
            jsts_tests.push(p.clone());
        } else if low.ends_with("_test.go") && go_dirs.len() < 4 {
            let dir = Path::new(p)
                .parent()
                .map(|d| d.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            let pkg = if dir.is_empty() || dir == "." {
                ".".to_string()
            } else {
                format!("./{dir}...")
            };
            if !go_dirs.contains(&pkg) {
                go_dirs.push(pkg);
            }
        }
    }

    for f in files {
        let norm = f.path.replace('\\', "/");
        if let Some(rest) = norm.strip_prefix("crates/") {
            if let Some(crate_dir) = rest.split('/').next() {
                if !crate_dir.is_empty()
                    && root
                        .join("crates")
                        .join(crate_dir)
                        .join("Cargo.toml")
                        .is_file()
                    && !rust_crates.contains(&crate_dir.to_string())
                    && rust_crates.len() < 3
                {
                    rust_crates.push(crate_dir.to_string());
                }
            }
        }
    }

    let mut cmds: Vec<String> = Vec::new();
    if !py_tests.is_empty() {
        push_unique(&mut cmds, format!("pytest -q {}", py_tests.join(" ")));
    }
    for stem in rust_int_tests {
        push_unique(&mut cmds, format!("cargo test --test {stem}"));
    }
    for krate in rust_crates {
        push_unique(&mut cmds, format!("cargo test -p {krate}"));
    }
    if !jsts_tests.is_empty() {
        let pkg_json = fs::read_to_string(root.join("package.json")).unwrap_or_default();
        let pkg_low = pkg_json.to_ascii_lowercase();
        let runner = if pkg_low.contains("\"vitest\"") {
            "npx vitest run"
        } else if pkg_low.contains("\"jest\"") {
            "npx jest"
        } else {
            "node --test"
        };
        push_unique(&mut cmds, format!("{runner} {}", jsts_tests.join(" ")));
    }
    for pkg in go_dirs {
        push_unique(&mut cmds, format!("go test {pkg}"));
    }
    cmds
}

pub fn analyze_git_changes(
    root: &Path,
    base_opt: Option<&str>,
    skip_dirs: &'static [&'static str],
) -> ChangesReport {
    let t0 = Instant::now();
    let base_ref = base_opt
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("HEAD")
        .to_string();

    let is_git = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(root)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !is_git {
        return ChangesReport {
            is_git_repo: false,
            base_ref,
            elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
            files: Vec::new(),
            modified_symbols: Vec::new(),
            external_callers: Vec::new(),
            related_tests: Vec::new(),
            suggested_test_cmds: Vec::new(),
        };
    }

    let diff_out = Command::new("git")
        .args(["diff", "-U0", &base_ref])
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

    let mut per_file_add: BTreeMap<String, usize> = BTreeMap::new();
    let mut per_file_del: BTreeMap<String, usize> = BTreeMap::new();
    let mut per_file_ranges: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
    let mut cur_file = String::new();
    let hre = hunk_re();

    for ln in diff_txt.lines() {
        if let Some(rest) = ln.strip_prefix("+++ b/") {
            cur_file = rest.trim().to_string();
            per_file_add.entry(cur_file.clone()).or_insert(0);
            per_file_del.entry(cur_file.clone()).or_insert(0);
            per_file_ranges.entry(cur_file.clone()).or_default();
            continue;
        }
        if cur_file.is_empty() {
            continue;
        }
        if let Some(cap) = hre.captures(ln) {
            let start: usize = cap[1].parse().unwrap_or(1).max(1);
            let count: usize = cap
                .get(2)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(1);
            let end = if count == 0 { start } else { start + count - 1 };
            per_file_ranges
                .entry(cur_file.clone())
                .or_default()
                .push((start, end));
            continue;
        }
        if ln.starts_with("+++") || ln.starts_with("---") {
            continue;
        }
        if ln.starts_with('+') {
            *per_file_add.entry(cur_file.clone()).or_insert(0) += 1;
        } else if ln.starts_with('-') {
            *per_file_del.entry(cur_file.clone()).or_insert(0) += 1;
        }
    }

    let mut file_stats: Vec<ChangedFileStat> = Vec::new();
    let mut all_syms: BTreeSet<String> = BTreeSet::new();
    let mut changed_path_set: HashSet<String> = HashSet::new();

    for (rel, ranges) in &per_file_ranges {
        changed_path_set.insert(rel.clone());
        let full_p = root.join(rel);
        let mut syms_here: Vec<String> = Vec::new();
        if full_p.is_file() {
            let ext = full_p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if let Some(lang) = lang_for_ext(ext) {
                if let Ok(bytes) = fs::read(&full_p) {
                    let body = String::from_utf8_lossy(&bytes);
                    let mut parser = Parser::new();
                    if parser.set_language(&lang).is_ok() {
                        if let Some(tree) = parser.parse(body.as_ref(), None) {
                            let mut spans = Vec::new();
                            collect_symbol_spans(tree.root_node(), body.as_bytes(), &mut spans);
                            let mut seen_local = HashSet::new();
                            for (nm, s, e) in spans {
                                let overlaps = ranges.iter().any(|&(rs, re)| rs <= e && re >= s);
                                if overlaps
                                    && nm.len() >= 2
                                    && !matches!(nm.as_str(), "main" | "new" | "default" | "run")
                                    && seen_local.insert(nm.clone())
                                {
                                    all_syms.insert(nm.clone());
                                    syms_here.push(nm);
                                }
                            }
                        }
                    }
                }
            }
        }
        file_stats.push(ChangedFileStat {
            path: rel.clone(),
            added: *per_file_add.get(rel).unwrap_or(&0),
            deleted: *per_file_del.get(rel).unwrap_or(&0),
            modified_symbols: syms_here,
        });
    }

    let modified_symbols: Vec<String> = all_syms.into_iter().take(24).collect();
    let mut external_callers: Vec<ImpactSite> = Vec::new();
    let mut related_test_set: BTreeSet<String> = BTreeSet::new();

    if !modified_symbols.is_empty() {
        let imp = analyze_symbol_impact(root, &modified_symbols, skip_dirs);
        for c in imp.callers_and_refs {
            if !changed_path_set.contains(&c.file) {
                external_callers.push(c);
            }
        }
        for t in imp.test_refs {
            related_test_set.insert(t.file);
        }
    }

    let related_tests: Vec<String> = related_test_set.into_iter().collect();
    let suggested_test_cmds = build_suggested_test_cmds(root, &related_tests, &file_stats);
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
    ChangesReport {
        is_git_repo: true,
        base_ref,
        elapsed_ms,
        files: file_stats,
        modified_symbols,
        external_callers,
        related_tests,
        suggested_test_cmds,
    }
}

pub fn render_changes_md(rep: &ChangesReport) -> String {
    if !rep.is_git_repo {
        return "[atlas changes] Not a git repository (skipped).".to_string();
    }
    if rep.files.is_empty() {
        return format!(
            "# CHANGE IMPACT BRIEF (base=`{}` | 0 modified files | {}ms)\nWorking tree is clean.",
            rep.base_ref, rep.elapsed_ms
        );
    }
    let mut out = vec![format!(
        "# CHANGE IMPACT BRIEF (base=`{}` | {} file(s), {} modified AST symbol(s) in {}ms)",
        rep.base_ref,
        rep.files.len(),
        rep.modified_symbols.len(),
        rep.elapsed_ms
    )];
    out.push("\n## Modified Files & AST Symbols".to_string());
    for f in rep.files.iter().take(25) {
        let sym_txt = if f.modified_symbols.is_empty() {
            String::new()
        } else {
            format!(" -> `{}`", f.modified_symbols.join("`, `"))
        };
        out.push(format!(
            "- `{}` (+{}/-{}){sym_txt}",
            f.path, f.added, f.deleted
        ));
    }
    if !rep.external_callers.is_empty() {
        out.push(format!(
            "\n## Untouched Downstream Callers to Verify ({})",
            rep.external_callers.len()
        ));
        for c in rep.external_callers.iter().take(25) {
            out.push(format!(
                "- `{}:{}` [{} `{}`] — `{}`",
                c.file, c.line, c.kind, c.symbol, c.snippet
            ));
        }
    }
    if !rep.related_tests.is_empty() {
        out.push(format!(
            "\n## Related Test Files ({})",
            rep.related_tests.len()
        ));
        for t in rep.related_tests.iter().take(15) {
            out.push(format!("- `{t}`"));
        }
    }
    if !rep.suggested_test_cmds.is_empty() {
        out.push(format!(
            "\n## Suggested Selective Test Commands ({})",
            rep.suggested_test_cmds.len()
        ));
        for cmd in &rep.suggested_test_cmds {
            out.push(format!("- `{cmd}`"));
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDirClean(PathBuf);
    impl Drop for TempDirClean {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mk_tmp(label: &str) -> TempDirClean {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("ap_atlas_changes_{label}_{n}"));
        fs::create_dir_all(&d).unwrap();
        TempDirClean(d)
    }

    #[test]
    fn suggested_test_cmds_covers_py_rust_jsts_and_go() {
        let td = mk_tmp("selective");
        fs::create_dir_all(td.0.join("crates/ap-demo")).unwrap();
        fs::write(
            td.0.join("crates/ap-demo/Cargo.toml"),
            "[package]\nname = \"ap-demo\"\n",
        )
        .unwrap();
        fs::write(
            td.0.join("package.json"),
            r#"{"name":"web","devDependencies":{"vitest":"^2.0.0"}}"#,
        )
        .unwrap();

        let files = vec![
            ChangedFileStat {
                path: "crates/ap-demo/src/lib.rs".into(),
                added: 4,
                deleted: 1,
                modified_symbols: vec!["solve".into()],
            },
            ChangedFileStat {
                path: "tests/integration_primitives.rs".into(),
                added: 10,
                deleted: 0,
                modified_symbols: vec![],
            },
        ];
        let related = vec![
            "tests/test_billing.py".into(),
            "web/auth.test.ts".into(),
            "pkg/cache/store_test.go".into(),
        ];

        let cmds = build_suggested_test_cmds(&td.0, &related, &files);
        assert!(
            cmds.iter().any(|c| c == "pytest -q tests/test_billing.py"),
            "{cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c == "cargo test --test integration_primitives"),
            "{cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c == "cargo test -p ap-demo"),
            "{cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c == "npx vitest run web/auth.test.ts"),
            "{cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c == "go test ./pkg/cache..."),
            "{cmds:?}"
        );

        // Without vitest/jest in package.json, defaults to `node --test`
        fs::remove_file(td.0.join("package.json")).unwrap();
        let cmds_node = build_suggested_test_cmds(&td.0, &["web/auth.test.mjs".into()], &[]);
        assert_eq!(cmds_node, vec!["node --test web/auth.test.mjs"]);
    }
}
