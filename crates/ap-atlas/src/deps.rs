use crate::changes::{collect_symbol_spans, lang_for_ext};
use ignore::WalkBuilder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;
use tree_sitter::Parser;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepHop {
    pub depth: usize,
    pub file: String,
    pub via: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnusedExport {
    pub file: String,
    pub line: usize,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepsReport {
    pub target: String,
    pub root: String,
    pub elapsed_ms: f64,
    pub scanned_files: usize,
    pub total_edges: usize,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub exported_symbols: Vec<String>,
    pub outbound_imports: Vec<DepHop>,
    pub inbound_importers: Vec<DepHop>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cycles: Vec<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub orphan_files: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub unused_exports: Vec<UnusedExport>,
}

struct DepRegexes {
    js_from: Regex,
    js_bare: Regex,
    js_req: Regex,
    py_from: Regex,
    py_imp: Regex,
    rs_mod: Regex,
    rs_use: Regex,
    go_mod: Regex,
    go_imp_block: Regex,
    go_imp_single: Regex,
    c_inc: Regex,
}

fn dep_re() -> &'static DepRegexes {
    static RE: OnceLock<DepRegexes> = OnceLock::new();
    RE.get_or_init(|| DepRegexes {
        js_from: Regex::new(
            r#"(?m)^\s*(?:import|export)\s+(?:type\s+)?[\s\S]{0,200}?\sfrom\s*['"]([^'"]+)['"]"#,
        )
        .unwrap(),
        js_bare: Regex::new(r#"(?m)^\s*import\s*['"]([^'"]+)['"]"#).unwrap(),
        js_req: Regex::new(r#"\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap(),
        py_from: Regex::new(r"(?m)^\s*from\s+(\.*)([A-Za-z0-9_.]*)\s+import\s+([^\r\n#]+)")
            .unwrap(),
        py_imp: Regex::new(r"(?m)^\s*import\s+([A-Za-z0-9_.,\s]+)").unwrap(),
        rs_mod: Regex::new(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
            .unwrap(),
        rs_use: Regex::new(
            r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+crate::([A-Za-z_][A-Za-z0-9_]*)(?:::([A-Za-z_][A-Za-z0-9_]*))?",
        )
        .unwrap(),
        go_mod: Regex::new(r"(?m)^\s*module\s+(\S+)").unwrap(),
        go_imp_block: Regex::new(r#"(?s)\bimport\s*\(([^)]*)\)"#).unwrap(),
        go_imp_single: Regex::new(r#"(?m)^\s*import\s+(?:[A-Za-z_.]\w*\s+)?"([^"]+)""#).unwrap(),
        c_inc: Regex::new(r#"(?m)^\s*#\s*include\s*"([^"]+)""#).unwrap(),
    })
}

fn is_source_ext(ext: &str) -> bool {
    matches!(
        ext,
        "py" | "ts"
            | "tsx"
            | "mts"
            | "cts"
            | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "rs"
            | "go"
            | "c"
            | "h"
    )
}

fn norm_rel_join(base_dir: &str, rel_spec: &str) -> Option<String> {
    let joined = if base_dir.is_empty() || base_dir == "." {
        PathBuf::from(rel_spec)
    } else {
        Path::new(base_dir).join(rel_spec)
    };
    let mut stack: Vec<String> = Vec::new();
    for comp in joined.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                stack.pop()?;
            }
            Component::Normal(s) => {
                stack.push(s.to_string_lossy().to_string());
            }
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(stack.join("/"))
}

fn parent_rel(rel: &str) -> &str {
    rel.rsplit_once('/').map(|(d, _)| d).unwrap_or("")
}

fn resolve_js_ts(base_dir: &str, spec: &str, known: &HashSet<String>) -> Option<String> {
    if !spec.starts_with("./") && !spec.starts_with("../") && spec != "." && spec != ".." {
        return None;
    }
    let norm = norm_rel_join(base_dir, spec)?;
    if known.contains(&norm) {
        return Some(norm);
    }
    const EXTS: &[&str] = &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];
    // Handle TS ESM imports that write `./foo.js` pointing at `foo.ts` / `foo.tsx`
    let stem = if let Some((s, ext)) = norm.rsplit_once('.') {
        if EXTS.contains(&ext) {
            s
        } else {
            norm.as_str()
        }
    } else {
        norm.as_str()
    };
    for ext in EXTS {
        let cand = format!("{stem}.{ext}");
        if known.contains(&cand) {
            return Some(cand);
        }
    }
    for ext in EXTS {
        let cand = format!("{norm}/index.{ext}");
        if known.contains(&cand) {
            return Some(cand);
        }
    }
    None
}

fn resolve_py_path(cand_base: &str, known: &HashSet<String>) -> Option<String> {
    if cand_base.is_empty() {
        return None;
    }
    let file_cand = format!("{cand_base}.py");
    if known.contains(&file_cand) {
        return Some(file_cand);
    }
    let init_cand = format!("{cand_base}/__init__.py");
    if known.contains(&init_cand) {
        return Some(init_cand);
    }
    None
}

fn resolve_py_dotted(dotted: &str, cur_file_dir: &str, known: &HashSet<String>) -> Option<String> {
    let slash_path = dotted.trim().replace('.', "/");
    if slash_path.is_empty() {
        return None;
    }
    for cand in [
        slash_path.clone(),
        format!("src/{slash_path}"),
        if cur_file_dir.is_empty() {
            slash_path.clone()
        } else {
            format!("{cur_file_dir}/{slash_path}")
        },
    ] {
        if let Some(hit) = resolve_py_path(&cand, known) {
            return Some(hit);
        }
    }
    // Check parent package when `import pkg.sub.Symbol` imports a symbol from `pkg/sub.py`
    if let Some((parent_mod, _)) = slash_path.rsplit_once('/') {
        for cand in [parent_mod.to_string(), format!("src/{parent_mod}")] {
            if let Some(hit) = resolve_py_path(&cand, known) {
                return Some(hit);
            }
        }
    }
    None
}

fn crate_src_dir(root: &Path, rel_file: &str) -> String {
    let mut cur = Path::new(rel_file).parent();
    while let Some(d) = cur {
        let cargo = root.join(d).join("Cargo.toml");
        if cargo.is_file() {
            let s = d.to_string_lossy().replace('\\', "/");
            return if s.is_empty() || s == "." {
                "src".to_string()
            } else {
                format!("{s}/src")
            };
        }
        cur = d.parent();
    }
    "src".to_string()
}

fn resolve_rust_mod(base_dir: &str, name: &str, known: &HashSet<String>) -> Option<String> {
    let prefix = if base_dir.is_empty() {
        String::new()
    } else {
        format!("{base_dir}/")
    };
    [
        format!("{prefix}{name}.rs"),
        format!("{prefix}{name}/mod.rs"),
    ]
    .into_iter()
    .find(|cand| known.contains(cand))
}

fn collect_file_edges(
    root: &Path,
    rel: &str,
    ext: &str,
    text: &str,
    go_mod_prefix: Option<&str>,
    known: &HashSet<String>,
) -> Vec<(String, String)> {
    let re = dep_re();
    let dir = parent_rel(rel);
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut push_edge = |target: String, via: String| {
        if target != rel && seen.insert(target.clone()) {
            edges.push((target, via));
        }
    };

    match ext {
        "ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs" => {
            for cap in re.js_from.captures_iter(text) {
                let spec = cap[1].trim();
                if let Some(t) = resolve_js_ts(dir, spec, known) {
                    push_edge(t, format!("import {spec}"));
                }
            }
            for cap in re.js_bare.captures_iter(text) {
                let spec = cap[1].trim();
                if let Some(t) = resolve_js_ts(dir, spec, known) {
                    push_edge(t, format!("import {spec}"));
                }
            }
            for cap in re.js_req.captures_iter(text) {
                let spec = cap[1].trim();
                if let Some(t) = resolve_js_ts(dir, spec, known) {
                    push_edge(t, format!("require {spec}"));
                }
            }
        }
        "py" => {
            for cap in re.py_from.captures_iter(text) {
                let dots = cap[1].len();
                let mod_name = cap[2].trim();
                let items = cap[3].trim();
                if dots > 0 {
                    let mut base = dir.to_string();
                    let mut up_ok = true;
                    for _ in 1..dots {
                        if base.is_empty() {
                            up_ok = false;
                            break;
                        }
                        base = parent_rel(&base).to_string();
                    }
                    if up_ok {
                        if mod_name.is_empty() {
                            for item in items.split(',') {
                                let name = item.split_whitespace().next().unwrap_or("").trim();
                                if name.is_empty() || name == "*" {
                                    continue;
                                }
                                let rel_cand = if base.is_empty() {
                                    name.to_string()
                                } else {
                                    format!("{base}/{name}")
                                };
                                if let Some(t) = resolve_py_path(&rel_cand, known) {
                                    push_edge(t, format!("from .{name}"));
                                }
                            }
                        } else {
                            let sub = mod_name.replace('.', "/");
                            let rel_cand = if base.is_empty() {
                                sub.clone()
                            } else {
                                format!("{base}/{sub}")
                            };
                            if let Some(t) = resolve_py_path(&rel_cand, known) {
                                push_edge(t, format!("from {}{mod_name}", ".".repeat(dots)));
                            }
                        }
                    }
                } else if let Some(t) = resolve_py_dotted(mod_name, dir, known) {
                    push_edge(t, format!("from {mod_name}"));
                }
            }
            for cap in re.py_imp.captures_iter(text) {
                for part in cap[1].split(',') {
                    let mod_name = part.split_whitespace().next().unwrap_or("").trim();
                    if mod_name.is_empty() {
                        continue;
                    }
                    if let Some(t) = resolve_py_dotted(mod_name, dir, known) {
                        push_edge(t, format!("import {mod_name}"));
                    }
                }
            }
        }
        "rs" => {
            let src_dir = crate_src_dir(root, rel);
            for cap in re.rs_mod.captures_iter(text) {
                let m = &cap[1];
                let hit = resolve_rust_mod(dir, m, known).or_else(|| {
                    if rel.ends_with("/lib.rs")
                        || rel.ends_with("/main.rs")
                        || rel == "src/lib.rs"
                        || rel == "src/main.rs"
                    {
                        resolve_rust_mod(&src_dir, m, known)
                    } else {
                        None
                    }
                });
                if let Some(t) = hit {
                    push_edge(t, format!("mod {m}"));
                }
            }
            for cap in re.rs_use.captures_iter(text) {
                let top = &cap[1];
                let sub = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                let sub_dir = format!("{src_dir}/{top}");
                let hit = if !sub.is_empty() {
                    resolve_rust_mod(&sub_dir, sub, known)
                        .or_else(|| resolve_rust_mod(&src_dir, top, known))
                } else {
                    resolve_rust_mod(&src_dir, top, known)
                };
                if let Some(t) = hit {
                    push_edge(t, format!("use crate::{top}"));
                }
            }
        }
        "go" => {
            if let Some(mod_pfx) = go_mod_prefix {
                let mut imp_specs: Vec<String> = Vec::new();
                for cap in re.go_imp_block.captures_iter(text) {
                    for line in cap[1].lines() {
                        if let Some(q1) = line.find('"') {
                            if let Some(q2) = line[q1 + 1..].find('"') {
                                imp_specs.push(line[q1 + 1..q1 + 1 + q2].to_string());
                            }
                        }
                    }
                }
                for cap in re.go_imp_single.captures_iter(text) {
                    imp_specs.push(cap[1].to_string());
                }
                for spec in imp_specs {
                    if let Some(sub_pkg) = spec
                        .strip_prefix(mod_pfx)
                        .map(|s| s.trim_start_matches('/'))
                    {
                        let mut pkg_files: Vec<String> = known
                            .iter()
                            .filter(|kf| {
                                kf.ends_with(".go")
                                    && !kf.ends_with("_test.go")
                                    && parent_rel(kf) == sub_pkg
                            })
                            .cloned()
                            .collect();
                        pkg_files.sort();
                        if let Some(first) = pkg_files.into_iter().next() {
                            push_edge(first, format!("import \"{spec}\""));
                        }
                    }
                }
            }
        }
        "c" | "h" => {
            for cap in re.c_inc.captures_iter(text) {
                let inc = cap[1].trim();
                let hit = norm_rel_join(dir, inc)
                    .filter(|p| known.contains(p))
                    .or_else(|| known.contains(inc).then(|| inc.to_string()))
                    .or_else(|| {
                        let inc_p = format!("include/{inc}");
                        known.contains(&inc_p).then_some(inc_p)
                    });
                if let Some(t) = hit {
                    push_edge(t, format!("#include \"{inc}\""));
                }
            }
        }
        _ => {}
    }

    edges
}

fn normalize_cycle(nodes: &[String]) -> Vec<String> {
    if nodes.is_empty() {
        return Vec::new();
    }
    let min_pos = nodes
        .iter()
        .enumerate()
        .min_by(|a, b| a.1.cmp(b.1))
        .map(|x| x.0)
        .unwrap_or(0);
    let mut ring: Vec<String> = nodes[min_pos..]
        .iter()
        .chain(nodes[..min_pos].iter())
        .cloned()
        .collect();
    ring.push(ring[0].clone());
    ring
}

struct CycleSearch<'a> {
    adj: &'a BTreeMap<String, Vec<(String, String)>>,
    path: Vec<String>,
    on_path: HashSet<String>,
    seen_sigs: HashSet<String>,
    cycles: Vec<Vec<String>>,
    max_cycles: usize,
}

fn find_cycles(
    adj: &BTreeMap<String, Vec<(String, String)>>,
    focus: Option<&str>,
    max_cycles: usize,
) -> Vec<Vec<String>> {
    fn dfs(u: &str, start: &str, st: &mut CycleSearch<'_>) {
        if st.cycles.len() >= st.max_cycles || st.path.len() > 8 {
            return;
        }
        let Some(nbrs) = st.adj.get(u) else { return };
        for (v, _) in nbrs {
            if v == start && st.path.len() >= 2 {
                let norm = normalize_cycle(&st.path);
                let sig = norm.join("->");
                if st.seen_sigs.insert(sig) {
                    st.cycles.push(norm);
                    if st.cycles.len() >= st.max_cycles {
                        return;
                    }
                }
            } else if v.as_str() > start && !st.on_path.contains(v) {
                st.on_path.insert(v.clone());
                st.path.push(v.clone());
                dfs(v, start, st);
                st.path.pop();
                st.on_path.remove(v);
            }
        }
    }

    let mut st = CycleSearch {
        adj,
        path: Vec::new(),
        on_path: HashSet::new(),
        seen_sigs: HashSet::new(),
        cycles: Vec::new(),
        max_cycles: max_cycles * 2,
    };

    for node in adj.keys() {
        st.path.clear();
        st.path.push(node.clone());
        st.on_path.clear();
        st.on_path.insert(node.clone());
        dfs(node, node, &mut st);
    }

    if let Some(tgt) = focus {
        let focused: Vec<Vec<String>> = st
            .cycles
            .iter()
            .filter(|c| c.iter().any(|n| n == tgt))
            .cloned()
            .collect();
        if !focused.is_empty() {
            return focused.into_iter().take(max_cycles).collect();
        }
    }
    st.cycles.into_iter().take(max_cycles).collect()
}

fn bfs_hops(
    start: &str,
    adj: &BTreeMap<String, Vec<(String, String)>>,
    max_depth: usize,
) -> Vec<DepHop> {
    let mut visited: HashSet<String> = HashSet::from([start.to_string()]);
    let mut q: VecDeque<(String, usize)> = VecDeque::from([(start.to_string(), 0)]);
    let mut hops = Vec::new();
    while let Some((cur, d)) = q.pop_front() {
        if d >= max_depth {
            continue;
        }
        if let Some(nbrs) = adj.get(&cur) {
            for (nxt, via) in nbrs {
                if visited.insert(nxt.clone()) {
                    let nd = d + 1;
                    hops.push(DepHop {
                        depth: nd,
                        file: nxt.clone(),
                        via: via.clone(),
                    });
                    if hops.len() >= 60 {
                        return hops;
                    }
                    q.push_back((nxt.clone(), nd));
                }
            }
        }
    }
    hops
}

fn extract_exported_symbols(full_path: &Path, ext: &str) -> Vec<String> {
    let Some(lang) = lang_for_ext(ext) else {
        return Vec::new();
    };
    let Ok(bytes) = fs::read(full_path) else {
        return Vec::new();
    };
    let body = String::from_utf8_lossy(&bytes);
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(body.as_ref(), None) else {
        return Vec::new();
    };
    let mut spans = Vec::new();
    collect_symbol_spans(tree.root_node(), body.as_bytes(), &mut spans);
    let mut syms = Vec::new();
    let mut seen = BTreeSet::new();
    for (nm, _, _) in spans {
        if seen.insert(nm.clone()) {
            syms.push(nm);
            if syms.len() >= 24 {
                break;
            }
        }
    }
    syms
}

fn is_test_or_entry_rel(rel: &str) -> bool {
    let low = rel.to_ascii_lowercase();
    if low.starts_with("tests/")
        || low.starts_with("test/")
        || low.contains("/tests/")
        || low.contains("/test/")
        || low.contains("/__tests__/")
        || low.contains(".test.")
        || low.contains(".spec.")
        || low.ends_with(".d.ts")
        || low.contains(".config.")
    {
        return true;
    }
    let fname = low.rsplit('/').next().unwrap_or(low.as_str());
    let stem = fname.split('.').next().unwrap_or(fname);
    fname.starts_with("test_")
        || fname.ends_with("_test.go")
        || fname.ends_with("_test.py")
        || matches!(
            stem,
            "main"
                | "index"
                | "lib"
                | "mod"
                | "build"
                | "__init__"
                | "__main__"
                | "app"
                | "cli"
                | "server"
                | "manage"
                | "setup"
                | "conftest"
        )
}

fn load_manifest_blob(root: &Path) -> String {
    let mut out = String::new();
    for cand in ["package.json", "Cargo.toml", "pyproject.toml", "index.html"] {
        let p = root.join(cand);
        if let Ok(bytes) = fs::read(p) {
            let take = bytes.len().min(256 * 1024);
            out.push_str(&String::from_utf8_lossy(&bytes[..take]));
            out.push('\n');
        }
    }
    out
}

fn collect_code_ident_counts(text: &str, ext: &str) -> HashMap<String, usize> {
    let b = text.as_bytes();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let is_py = ext == "py";
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
            continue;
        }
        if is_py && b[i] == b'#' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if matches!(b[i], b'"' | b'\'' | b'`') {
            let q = b[i];
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' && i + 1 < b.len() {
                    i += 2;
                    continue;
                }
                if b[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if b[i].is_ascii_alphabetic() || b[i] == b'_' {
            let start = i;
            i += 1;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let ident = &text[start..i];
            if ident.len() >= 4 {
                *counts.entry(ident.to_string()).or_insert(0) += 1;
            }
            continue;
        }
        i += 1;
    }
    counts
}

fn extract_symbol_lines(full_path: &Path, ext: &str) -> Vec<(String, usize)> {
    let Some(lang) = lang_for_ext(ext) else {
        return Vec::new();
    };
    let Ok(bytes) = fs::read(full_path) else {
        return Vec::new();
    };
    let body = String::from_utf8_lossy(&bytes);
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(body.as_ref(), None) else {
        return Vec::new();
    };
    let mut spans = Vec::new();
    collect_symbol_spans(tree.root_node(), body.as_bytes(), &mut spans);
    spans.into_iter().map(|(nm, s, _)| (nm, s)).collect()
}

fn collect_dead_code(
    root: &Path,
    file_bodies: &[(String, String, String)],
    file_map: &HashMap<String, (PathBuf, String)>,
    inbound_adj: &BTreeMap<String, Vec<(String, String)>>,
    focus_rel: Option<&str>,
) -> (Vec<String>, Vec<UnusedExport>) {
    let manifest_blob = load_manifest_blob(root);
    let mut orphan_files: Vec<String> = Vec::new();
    for (rel, _, _) in file_bodies {
        if orphan_files.len() >= 40 {
            break;
        }
        if is_test_or_entry_rel(rel) {
            continue;
        }
        let has_inbound = inbound_adj.get(rel).map(|v| !v.is_empty()).unwrap_or(false);
        if has_inbound {
            continue;
        }
        let fname = rel.rsplit('/').next().unwrap_or(rel.as_str());
        if !manifest_blob.is_empty()
            && (manifest_blob.contains(rel.as_str()) || manifest_blob.contains(fname))
        {
            continue;
        }
        orphan_files.push(rel.clone());
    }

    let mut per_file_counts: HashMap<&str, HashMap<String, usize>> = HashMap::new();
    let mut ident_file_count: HashMap<String, usize> = HashMap::new();
    for (rel, ext, body) in file_bodies {
        let counts = collect_code_ident_counts(body, ext);
        for k in counts.keys() {
            *ident_file_count.entry(k.clone()).or_insert(0) += 1;
        }
        per_file_counts.insert(rel.as_str(), counts);
    }

    const LIFECYCLE_SKIP: &[&str] = &[
        "main",
        "init",
        "default",
        "drop",
        "clone",
        "from",
        "into",
        "render",
        "setup",
        "teardown",
        "constructor",
        "toString",
        "valueOf",
        "serialize",
        "deserialize",
        "index",
        "handler",
        "middleware",
        "test",
    ];

    let mut unused_exports: Vec<UnusedExport> = Vec::new();
    let mut seen_decl: HashSet<(String, String)> = HashSet::new();
    for (rel, ext, _) in file_bodies {
        if unused_exports.len() >= 40 {
            break;
        }
        if let Some(tgt) = focus_rel {
            if rel != tgt {
                continue;
            }
        }
        if is_test_or_entry_rel(rel) && focus_rel.is_none() {
            continue;
        }
        let Some((fp, _)) = file_map.get(rel) else {
            continue;
        };
        let Some(local_counts) = per_file_counts.get(rel.as_str()) else {
            continue;
        };
        for (sym, line) in extract_symbol_lines(fp, ext) {
            if sym.len() < 4 || sym.starts_with('_') || LIFECYCLE_SKIP.contains(&sym.as_str()) {
                continue;
            }
            let global_files = ident_file_count.get(&sym).copied().unwrap_or(0);
            let local_hits = local_counts.get(&sym).copied().unwrap_or(0);
            if global_files <= 1 && local_hits <= 1 && seen_decl.insert((rel.clone(), sym.clone()))
            {
                unused_exports.push(UnusedExport {
                    file: rel.clone(),
                    line,
                    symbol: sym,
                });
                if unused_exports.len() >= 40 {
                    break;
                }
            }
        }
    }

    (orphan_files, unused_exports)
}

pub fn analyze_module_deps(
    root: &Path,
    target: &str,
    max_depth: usize,
    skip_dirs: &'static [&'static str],
) -> DepsReport {
    analyze_module_deps_with_opts(root, target, max_depth, false, skip_dirs)
}

pub fn analyze_module_deps_with_opts(
    root: &Path,
    target: &str,
    max_depth: usize,
    include_dead: bool,
    skip_dirs: &'static [&'static str],
) -> DepsReport {
    let t0 = Instant::now();
    let depth = max_depth.clamp(1, 5);
    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let root_str = root_canon.to_string_lossy().replace('\\', "/");
    let skip_set: HashSet<&str> = skip_dirs.iter().copied().collect();

    let go_mod_prefix = fs::read_to_string(root_canon.join("go.mod"))
        .ok()
        .and_then(|s| {
            dep_re()
                .go_mod
                .captures(&s)
                .map(|c| c[1].trim().to_string())
        });

    let mut files: Vec<PathBuf> = Vec::new();
    let mut known: HashSet<String> = HashSet::new();
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
        if !p.is_file() {
            continue;
        }
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if is_source_ext(&ext) {
            if let Ok(rel_p) = p.strip_prefix(&root_canon) {
                let rel = rel_p.to_string_lossy().replace('\\', "/");
                known.insert(rel);
                files.push(p.to_path_buf());
            }
        }
    }
    files.sort();

    let target_norm = {
        let tgt_p = Path::new(target);
        if tgt_p.is_absolute() {
            let t_can = fs::canonicalize(tgt_p).unwrap_or_else(|_| tgt_p.to_path_buf());
            t_can
                .strip_prefix(&root_canon)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| target.replace('\\', "/"))
        } else {
            let trimmed = target.trim().replace('\\', "/");
            trimmed
                .strip_prefix("./")
                .unwrap_or(&trimmed)
                .trim_end_matches('/')
                .to_string()
        }
    };

    let resolved_target = if known.contains(&target_norm) {
        Some(target_norm.clone())
    } else if !target_norm.is_empty() && target_norm != "." {
        known
            .iter()
            .find(|kf| kf.ends_with(&format!("/{target_norm}")) || *kf == &target_norm)
            .cloned()
    } else {
        None
    };

    let mut outbound_adj: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut inbound_adj: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut total_edges = 0usize;
    let mut file_map: HashMap<String, (PathBuf, String)> = HashMap::new();
    let mut file_bodies: Vec<(String, String, String)> = Vec::new();

    for p in &files {
        let Ok(rel_p) = p.strip_prefix(&root_canon) else {
            continue;
        };
        let rel = rel_p.to_string_lossy().replace('\\', "/");
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        file_map.insert(rel.clone(), (p.clone(), ext.clone()));
        let Ok(bytes) = fs::read(p) else {
            continue;
        };
        if bytes.contains(&0) {
            continue;
        }
        let body = String::from_utf8_lossy(&bytes).into_owned();
        let edges = collect_file_edges(
            &root_canon,
            &rel,
            &ext,
            &body,
            go_mod_prefix.as_deref(),
            &known,
        );
        total_edges += edges.len();
        for (dst, via) in &edges {
            inbound_adj
                .entry(dst.clone())
                .or_default()
                .push((rel.clone(), format!("via `{rel}` ({via})")));
        }
        outbound_adj.insert(rel.clone(), edges);
        if include_dead {
            file_bodies.push((rel, ext, body));
        }
    }

    let (exported_symbols, outbound_imports, inbound_importers, focus_rel) =
        if let Some(ref tgt) = resolved_target {
            let syms = file_map
                .get(tgt)
                .map(|(fp, ext)| extract_exported_symbols(fp, ext))
                .unwrap_or_default();
            let out_h = bfs_hops(tgt, &outbound_adj, depth);
            let in_h = bfs_hops(tgt, &inbound_adj, depth);
            (syms, out_h, in_h, Some(tgt.as_str()))
        } else {
            (Vec::new(), Vec::new(), Vec::new(), None)
        };

    let cycles = find_cycles(&outbound_adj, focus_rel, 12);
    let (orphan_files, unused_exports) = if include_dead {
        collect_dead_code(
            &root_canon,
            &file_bodies,
            &file_map,
            &inbound_adj,
            focus_rel,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;

    DepsReport {
        target: resolved_target.unwrap_or(target_norm),
        root: root_str,
        elapsed_ms,
        scanned_files: files.len(),
        total_edges,
        exported_symbols,
        outbound_imports,
        inbound_importers,
        cycles,
        orphan_files,
        unused_exports,
    }
}

pub fn render_deps_md(rep: &DepsReport) -> String {
    let mut out = vec![format!(
        "# MODULE DEPENDENCY GRAPH `{}` ({} files, {} edges in {} ms)",
        rep.target, rep.scanned_files, rep.total_edges, rep.elapsed_ms
    )];
    if !rep.exported_symbols.is_empty() {
        out.push(format!(
            "\n## Declared Symbols ({})\n`{}`",
            rep.exported_symbols.len(),
            rep.exported_symbols.join("`, `")
        ));
    }
    if !rep.outbound_imports.is_empty() {
        out.push(format!(
            "\n## Outbound Imports ({})",
            rep.outbound_imports.len()
        ));
        for h in &rep.outbound_imports {
            out.push(format!("- [hop {}] `{}` — {}", h.depth, h.file, h.via));
        }
    }
    if !rep.inbound_importers.is_empty() {
        out.push(format!(
            "\n## Inbound Importers / Dependents ({})",
            rep.inbound_importers.len()
        ));
        for h in &rep.inbound_importers {
            out.push(format!("- [hop {}] `{}` — {}", h.depth, h.file, h.via));
        }
    }
    if !rep.cycles.is_empty() {
        out.push(format!("\n## Circular Dependencies ({})", rep.cycles.len()));
        for cyc in &rep.cycles {
            out.push(format!("- `{}`", cyc.join(" -> ")));
        }
    }
    if !rep.orphan_files.is_empty() {
        out.push(format!(
            "\n## Orphan Source Modules ({})",
            rep.orphan_files.len()
        ));
        for f in &rep.orphan_files {
            out.push(format!("- `{f}` (0 inbound imports)"));
        }
    }
    if !rep.unused_exports.is_empty() {
        out.push(format!(
            "\n## Unused Declared Symbols / Ghost Exports ({})",
            rep.unused_exports.len()
        ));
        for u in &rep.unused_exports {
            out.push(format!("- `{}:{}` `{}`", u.file, u.line, u.symbol));
        }
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

    fn mk_tmp(label: &str) -> TempDirClean {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("ap_atlas_deps_{label}_{n}"));
        fs::create_dir_all(&d).unwrap();
        TempDirClean(d)
    }

    #[test]
    fn ts_multihop_deps_inbound_blast_and_cycles() {
        let td = mk_tmp("ts_cycle");
        fs::create_dir_all(td.0.join("src")).unwrap();
        fs::write(
            td.0.join("src/a.ts"),
            "import { helperB } from './b';\nexport function entryA() { return helperB(); }\n",
        )
        .unwrap();
        fs::write(
            td.0.join("src/b.ts"),
            "import { entryA } from './a';\nimport { utilC } from './c';\nexport function helperB() { return utilC() + (entryA ? 1 : 0); }\n",
        )
        .unwrap();
        fs::write(
            td.0.join("src/c.ts"),
            "export function utilC() { return 42; }\n",
        )
        .unwrap();

        let rep = analyze_module_deps(&td.0, "src/a.ts", 3, crate::SKIP_DIRS);
        assert_eq!(rep.target, "src/a.ts");
        assert!(rep.exported_symbols.contains(&"entryA".to_string()));
        assert!(rep
            .outbound_imports
            .iter()
            .any(|h| h.depth == 1 && h.file == "src/b.ts"));
        assert!(rep
            .outbound_imports
            .iter()
            .any(|h| h.depth == 2 && h.file == "src/c.ts"));
        assert!(!rep.cycles.is_empty(), "{rep:?}");
        assert!(rep
            .cycles
            .iter()
            .any(|c| c.contains(&"src/a.ts".to_string()) && c.contains(&"src/b.ts".to_string())));

        let rep_c = analyze_module_deps(&td.0, "src/c.ts", 2, crate::SKIP_DIRS);
        assert!(rep_c
            .inbound_importers
            .iter()
            .any(|h| h.depth == 1 && h.file == "src/b.ts"));
        assert!(rep_c
            .inbound_importers
            .iter()
            .any(|h| h.depth == 2 && h.file == "src/a.ts"));
    }

    #[test]
    fn python_and_rust_module_deps_resolve_cleanly() {
        let td = mk_tmp("py_rs");
        fs::create_dir_all(td.0.join("pkg")).unwrap();
        fs::create_dir_all(td.0.join("tests")).unwrap();
        fs::create_dir_all(td.0.join("src")).unwrap();
        fs::write(
            td.0.join("Cargo.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n",
        )
        .unwrap();
        fs::write(td.0.join("pkg/__init__.py"), "").unwrap();
        fs::write(td.0.join("pkg/core.py"), "def calc():\n    return 7\n").unwrap();
        fs::write(
            td.0.join("pkg/service.py"),
            "from .core import calc\ndef run():\n    return calc()\n",
        )
        .unwrap();
        fs::write(
            td.0.join("tests/test_service.py"),
            "from pkg.service import run\ndef test_ok():\n    assert run() == 7\n",
        )
        .unwrap();
        fs::write(
            td.0.join("src/auth.rs"),
            "pub fn verify() -> bool { true }\n",
        )
        .unwrap();
        fs::write(
            td.0.join("src/lib.rs"),
            "pub mod auth;\nuse crate::auth::verify;\npub fn boot() -> bool { verify() }\n",
        )
        .unwrap();

        let py_rep = analyze_module_deps(&td.0, "pkg/core.py", 2, crate::SKIP_DIRS);
        assert!(py_rep
            .inbound_importers
            .iter()
            .any(|h| h.depth == 1 && h.file == "pkg/service.py"));
        assert!(py_rep
            .inbound_importers
            .iter()
            .any(|h| h.depth == 2 && h.file == "tests/test_service.py"));

        let rs_rep = analyze_module_deps(&td.0, "src/lib.rs", 2, crate::SKIP_DIRS);
        assert!(rs_rep
            .outbound_imports
            .iter()
            .any(|h| h.depth == 1 && h.file == "src/auth.rs"));
    }

    #[test]
    fn dead_code_audit_finds_orphan_modules_and_unused_exports() {
        let td = mk_tmp("dead_audit");
        fs::create_dir_all(td.0.join("src")).unwrap();
        fs::create_dir_all(td.0.join("tests")).unwrap();
        fs::write(
            td.0.join("src/index.ts"),
            "import { liveHelper } from './used';\nexport function start() { return liveHelper(); }\n",
        )
        .unwrap();
        fs::write(
            td.0.join("src/used.ts"),
            "export function liveHelper() { return 1; }\nexport function ghostHelper() { return 2; }\n",
        )
        .unwrap();
        fs::write(
            td.0.join("src/orphan.ts"),
            "export function orphanFn() { return 99; }\n",
        )
        .unwrap();
        fs::write(
            td.0.join("tests/app.test.ts"),
            "import { liveHelper } from '../src/used';\nif (liveHelper() !== 1) throw new Error('bad');\n",
        )
        .unwrap();

        let rep = analyze_module_deps_with_opts(&td.0, ".", 2, true, crate::SKIP_DIRS);
        assert!(
            rep.orphan_files.iter().any(|f| f == "src/orphan.ts"),
            "{rep:?}"
        );
        assert!(!rep.orphan_files.iter().any(|f| f == "src/index.ts"));
        assert!(!rep.orphan_files.iter().any(|f| f == "src/used.ts"));
        assert!(!rep.orphan_files.iter().any(|f| f == "tests/app.test.ts"));
        assert!(
            rep.unused_exports
                .iter()
                .any(|u| u.file == "src/used.ts" && u.symbol == "ghostHelper"),
            "{rep:?}"
        );
        assert!(!rep.unused_exports.iter().any(|u| u.symbol == "liveHelper"));
    }
}
