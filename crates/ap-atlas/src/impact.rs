use ignore::{WalkBuilder, WalkState};
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tree_sitter::{Language, Node, Parser};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactSite {
    pub symbol: String,
    pub kind: String,
    pub file: String,
    pub line: usize,
    pub snippet: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enclosing: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactReport {
    pub symbols: Vec<String>,
    pub elapsed_ms: f64,
    pub scanned_files: usize,
    pub definitions: Vec<ImpactSite>,
    pub callers_and_refs: Vec<ImpactSite>,
    pub test_refs: Vec<ImpactSite>,
}

fn lang_for_ext(ext: &str) -> Option<Language> {
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

fn is_test_path(rel: &str) -> bool {
    let low = rel.to_ascii_lowercase();
    low.starts_with("tests/")
        || low.starts_with("test/")
        || low.contains("/tests/")
        || low.contains("/__tests__/")
        || low.contains(".test.")
        || low.contains(".spec.")
        || low.rsplit('/').next().unwrap_or("").starts_with("test_")
        || low.ends_with("_test.go")
        || low.ends_with("_test.py")
}

fn classify_ident_node(node: Node) -> &'static str {
    let mut cur = node.parent();
    let mut depth = 0usize;
    while let Some(p) = cur {
        let pk = p.kind();
        if pk.contains("import") || pk == "use_declaration" {
            return "import";
        }
        if matches!(
            pk,
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
        ) {
            if let Some(nm) = p.child_by_field_name("name") {
                if nm.id() == node.id()
                    || (nm.start_byte() <= node.start_byte() && node.end_byte() <= nm.end_byte())
                {
                    return "definition";
                }
            }
        }
        if pk == "variable_declarator" || pk == "const_item" || pk == "static_item" {
            if let Some(nm) = p.child_by_field_name("name") {
                if nm.id() == node.id() {
                    return "definition";
                }
            }
        }
        if depth <= 2
            && matches!(
                pk,
                "call_expression" | "new_expression" | "macro_invocation"
            )
        {
            if let Some(func_n) = p.child_by_field_name("function").or_else(|| p.child(0)) {
                if func_n.start_byte() <= node.start_byte() && node.end_byte() <= func_n.end_byte()
                {
                    return "call";
                }
            }
        }
        cur = p.parent();
        depth += 1;
        if depth > 5 {
            break;
        }
    }
    "ref"
}

fn find_enclosing_symbol(node: Node, src: &[u8]) -> String {
    let mut fn_name: Option<String> = None;
    let mut owner_name: Option<String> = None;
    let mut cur = node.parent();
    while let Some(p) = cur {
        let pk = p.kind();
        let is_own_decl_name = |decl: Node| -> bool {
            decl.child_by_field_name("name")
                .map(|nm| nm.start_byte() <= node.start_byte() && node.end_byte() <= nm.end_byte())
                .unwrap_or(false)
        };
        if fn_name.is_none()
            && matches!(
                pk,
                "function_declaration"
                    | "function_definition"
                    | "function_item"
                    | "method_definition"
                    | "method_declaration"
            )
            && !is_own_decl_name(p)
        {
            if let Some(nm) = p
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(src).ok())
            {
                let clean = nm.trim();
                if !clean.is_empty() {
                    fn_name = Some(clean.to_string());
                }
            }
        } else if fn_name.is_none() && pk == "variable_declarator" && !is_own_decl_name(p) {
            if let (Some(nm), Some(val)) = (
                p.child_by_field_name("name"),
                p.child_by_field_name("value"),
            ) {
                if matches!(
                    val.kind(),
                    "arrow_function" | "function_expression" | "function"
                ) {
                    if let Ok(s) = nm.utf8_text(src) {
                        let clean = s.trim();
                        if !clean.is_empty() {
                            fn_name = Some(clean.to_string());
                        }
                    }
                }
            }
        } else if owner_name.is_none()
            && matches!(
                pk,
                "class_declaration" | "class_definition" | "struct_item" | "impl_item"
            )
            && !is_own_decl_name(p)
        {
            let owner_node = p
                .child_by_field_name("name")
                .or_else(|| p.child_by_field_name("type"));
            if let Some(s) = owner_node.and_then(|n| n.utf8_text(src).ok()) {
                let clean = s.trim();
                if !clean.is_empty() {
                    owner_name = Some(clean.to_string());
                }
            }
        }
        cur = p.parent();
    }
    match (owner_name, fn_name) {
        (Some(o), Some(f)) => format!("{o}.{f}"),
        (None, Some(f)) => f,
        (Some(o), None) => o,
        (None, None) => String::new(),
    }
}

fn collect_ast_hits(
    node: Node,
    src: &[u8],
    lines: &[&str],
    targets: &HashSet<&str>,
    rel_file: &str,
    seen_line_sym: &mut HashSet<(usize, String)>,
    out: &mut Vec<ImpactSite>,
) {
    let kind = node.kind();
    if kind.contains("comment") || kind.contains("string") {
        return;
    }
    if kind.contains("identifier") && node.child_count() == 0 {
        if let Ok(txt) = node.utf8_text(src) {
            if targets.contains(txt) {
                let ln = node.start_position().row + 1;
                if seen_line_sym.insert((ln, txt.to_string())) {
                    let role = classify_ident_node(node);
                    let enclosing = find_enclosing_symbol(node, src);
                    let raw_ln = lines.get(ln - 1).copied().unwrap_or("").trim();
                    let snip: String = raw_ln.chars().take(140).collect();
                    out.push(ImpactSite {
                        symbol: txt.to_string(),
                        kind: role.to_string(),
                        file: rel_file.to_string(),
                        line: ln,
                        snippet: snip,
                        enclosing,
                    });
                }
            }
        }
        return;
    }
    let mut walk = node.walk();
    for ch in node.children(&mut walk) {
        collect_ast_hits(ch, src, lines, targets, rel_file, seen_line_sym, out);
    }
}

pub fn analyze_symbol_impact(
    root: &Path,
    raw_symbols: &[String],
    skip_dirs: &'static [&'static str],
) -> ImpactReport {
    let t0 = Instant::now();
    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let syms: Vec<String> = raw_symbols
        .iter()
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if syms.is_empty() {
        return ImpactReport {
            symbols: syms,
            elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
            scanned_files: 0,
            definitions: Vec::new(),
            callers_and_refs: Vec::new(),
            test_refs: Vec::new(),
        };
    }

    let pat_set = RegexSet::new(syms.iter().map(|s| regex::escape(s))).ok();
    let syms_arc = Arc::new(syms);
    let pat_set_arc = Arc::new(pat_set);
    let root_arc = Arc::new(root_canon.clone());
    let skip_set: HashSet<&'static str> = skip_dirs.iter().copied().collect();

    let scanned_cnt = Arc::new(AtomicUsize::new(0));
    let defs_mx: Arc<Mutex<Vec<ImpactSite>>> = Arc::new(Mutex::new(Vec::new()));
    let callers_mx: Arc<Mutex<Vec<ImpactSite>>> = Arc::new(Mutex::new(Vec::new()));
    let tests_mx: Arc<Mutex<Vec<ImpactSite>>> = Arc::new(Mutex::new(Vec::new()));

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
        .build_parallel();

    walker.run(|| {
        let syms_c = Arc::clone(&syms_arc);
        let pat_c = Arc::clone(&pat_set_arc);
        let root_c = Arc::clone(&root_arc);
        let scanned_c = Arc::clone(&scanned_cnt);
        let defs_c = Arc::clone(&defs_mx);
        let callers_c = Arc::clone(&callers_mx);
        let tests_c = Arc::clone(&tests_mx);
        let mut parsers: HashMap<String, Parser> = HashMap::new();

        Box::new(move |res| {
            let Ok(entry) = res else {
                return WalkState::Continue;
            };
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                return WalkState::Continue;
            }
            let p = entry.path();
            let ext_raw = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            let Some(lang) = lang_for_ext(ext_raw) else {
                return WalkState::Continue;
            };
            if let Ok(meta) = entry.metadata() {
                if meta.len() > 2 * 1024 * 1024 {
                    return WalkState::Continue;
                }
            }
            scanned_c.fetch_add(1, Ordering::Relaxed);
            let Ok(bytes) = fs::read(p) else {
                return WalkState::Continue;
            };
            let body = String::from_utf8_lossy(&bytes);
            let matched = match pat_c.as_ref() {
                Some(rs) => rs.is_match(body.as_ref()),
                None => syms_c.iter().any(|s| body.contains(s.as_str())),
            };
            if !matched {
                return WalkState::Continue;
            }
            let ext_key = ext_raw.to_ascii_lowercase();
            let parser = parsers.entry(ext_key).or_insert_with(|| {
                let mut pr = Parser::new();
                let _ = pr.set_language(&lang);
                pr
            });
            let Some(tree) = parser.parse(body.as_ref(), None) else {
                return WalkState::Continue;
            };
            let rel = p
                .strip_prefix(root_c.as_path())
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/");
            let lines: Vec<&str> = body.lines().collect();
            let target_set: HashSet<&str> = syms_c.iter().map(String::as_str).collect();
            let mut seen = HashSet::new();
            let mut file_hits = Vec::new();
            collect_ast_hits(
                tree.root_node(),
                body.as_bytes(),
                &lines,
                &target_set,
                &rel,
                &mut seen,
                &mut file_hits,
            );
            if !file_hits.is_empty() {
                let is_test = is_test_path(&rel);
                let mut l_defs = Vec::new();
                let mut l_callers = Vec::new();
                let mut l_tests = Vec::new();
                for h in file_hits {
                    if h.kind == "definition" && !is_test {
                        l_defs.push(h);
                    } else if is_test {
                        l_tests.push(h);
                    } else {
                        l_callers.push(h);
                    }
                }
                if !l_defs.is_empty() {
                    if let Ok(mut g) = defs_c.lock() {
                        g.extend(l_defs);
                    }
                }
                if !l_callers.is_empty() {
                    if let Ok(mut g) = callers_c.lock() {
                        g.extend(l_callers);
                    }
                }
                if !l_tests.is_empty() {
                    if let Ok(mut g) = tests_c.lock() {
                        g.extend(l_tests);
                    }
                }
            }
            WalkState::Continue
        })
    });

    let scanned_files = scanned_cnt.load(Ordering::Relaxed);
    let mut definitions = Arc::try_unwrap(defs_mx)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_else(|a| a.lock().map(|g| g.clone()).unwrap_or_default());
    let mut callers_and_refs = Arc::try_unwrap(callers_mx)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_else(|a| a.lock().map(|g| g.clone()).unwrap_or_default());
    let mut test_refs = Arc::try_unwrap(tests_mx)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_else(|a| a.lock().map(|g| g.clone()).unwrap_or_default());

    let cmp_site = |a: &ImpactSite, b: &ImpactSite| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.symbol.cmp(&b.symbol))
            .then_with(|| a.kind.cmp(&b.kind))
    };
    definitions.sort_by(cmp_site);
    callers_and_refs.sort_by(cmp_site);
    test_refs.sort_by(cmp_site);

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
    ImpactReport {
        symbols: Arc::try_unwrap(syms_arc).unwrap_or_else(|a| (*a).clone()),
        elapsed_ms,
        scanned_files,
        definitions,
        callers_and_refs,
        test_refs,
    }
}

pub fn render_impact_md(rep: &ImpactReport) -> String {
    let mut out = vec![format!(
        "# AST IMPACT & BLAST RADIUS: `{}` ({} files scanned in {}ms)",
        rep.symbols.join(", "),
        rep.scanned_files,
        rep.elapsed_ms
    )];
    if rep.definitions.is_empty() && rep.callers_and_refs.is_empty() && rep.test_refs.is_empty() {
        out.push(
            "No AST symbol definitions or references found (comments & string literals ignored)."
                .to_string(),
        );
        return out.join("\n");
    }
    if !rep.definitions.is_empty() {
        out.push(format!("\n## Definitions ({})", rep.definitions.len()));
        for d in &rep.definitions {
            out.push(format!("- `{}:{}` — `{}`", d.file, d.line, d.snippet));
        }
    }
    if !rep.callers_and_refs.is_empty() {
        out.push(format!(
            "\n## Downstream Callers & References ({} — update all on signature change!)",
            rep.callers_and_refs.len()
        ));
        for c in rep.callers_and_refs.iter().take(40) {
            let enc = if c.enclosing.is_empty() {
                String::new()
            } else {
                format!(" (in `{}`)", c.enclosing)
            };
            out.push(format!(
                "- `{}:{}` [{}]{enc} — `{}`",
                c.file, c.line, c.kind, c.snippet
            ));
        }
    }
    if !rep.test_refs.is_empty() {
        out.push(format!("\n## Related Tests ({})", rep.test_refs.len()));
        for t in rep.test_refs.iter().take(20) {
            let enc = if t.enclosing.is_empty() {
                String::new()
            } else {
                format!(" (in `{}`)", t.enclosing)
            };
            out.push(format!(
                "- `{}:{}` [{}]{enc} — `{}`",
                t.file, t.line, t.kind, t.snippet
            ));
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impact_attributes_enclosing_method_and_impl_while_ignoring_comments() {
        let dir = std::env::temp_dir().join(format!("ap_impact_enc_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/auth.ts"),
            "export function verifyToken(t: string) { return t.length > 0; }\n\
             export class AuthHandler {\n\
               handleLogin(tok: string) {\n\
                 // verifyToken comment\n\
                 return verifyToken(tok);\n\
               }\n\
             }\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/engine.rs"),
            "pub struct Engine;\n\
             impl Engine {\n\
               pub fn run(&self) { verifyToken(); }\n\
             }\n",
        )
        .unwrap();

        let rep = analyze_symbol_impact(&dir, &["verifyToken".to_string()], &[]);
        assert_eq!(rep.definitions.len(), 1);
        assert!(rep.definitions[0].enclosing.is_empty());
        assert!(
            rep.callers_and_refs
                .iter()
                .any(|c| c.file == "src/auth.ts" && c.enclosing == "AuthHandler.handleLogin"),
            "{:?}",
            rep.callers_and_refs
        );
        assert!(
            rep.callers_and_refs
                .iter()
                .any(|c| c.file == "src/engine.rs" && c.enclosing == "Engine.run"),
            "{:?}",
            rep.callers_and_refs
        );
        let md = render_impact_md(&rep);
        assert!(md.contains("(in `AuthHandler.handleLogin`)"), "{md}");
        let _ = fs::remove_dir_all(&dir);
    }
}
