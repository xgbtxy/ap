use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::Instant;
use tree_sitter::{Node, Parser};

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".next",
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    "vendor",
];

const NOTABLE_SINKS: &[&str] = &[
    "exec",
    "execSync",
    "execFile",
    "spawn",
    "spawnSync",
    "eval",
    "Function",
    "innerHTML",
    "readFile",
    "readFileSync",
    "writeFile",
    "writeFileSync",
    "createReadStream",
    "sendFile",
    "prepare",
    "query",
    "execute",
    "fetch",
    "postMessage",
    "openExternal",
    "sendSync",
    "invoke",
    "system",
    "popen",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FnDef {
    pub name: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub called_idents: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEdge {
    pub depth: usize,
    pub symbol: String,
    pub file: String,
    pub line: usize,
    pub path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceReport {
    pub target: String,
    pub elapsed_ms: f64,
    pub scanned_functions: usize,
    pub definitions: Vec<(String, usize, usize)>,
    pub upstream_callers: Vec<TraceEdge>,
    pub downstream_callees: Vec<TraceEdge>,
    pub notable_sinks: Vec<(String, usize)>,
}

fn parser_for_ext(ext: &str) -> Option<Parser> {
    let mut p = Parser::new();
    let lang = match ext {
        "py" => tree_sitter_python::LANGUAGE.into(),
        "ts" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "js" | "jsx" | "mjs" | "cjs" => tree_sitter_javascript::LANGUAGE.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "rs" => tree_sitter_rust::LANGUAGE.into(),
        "c" | "h" => tree_sitter_c::LANGUAGE.into(),
        _ => return None,
    };
    p.set_language(&lang).ok()?;
    Some(p)
}

fn node_name(node: Node, src: &[u8]) -> Option<String> {
    if let Some(n) = node.child_by_field_name("name") {
        if let Ok(s) = n.utf8_text(src) {
            return Some(s.trim().to_string());
        }
    }
    if let Some(d) = node.child_by_field_name("declarator") {
        return node_name(d, src).or_else(|| d.utf8_text(src).ok().map(str::to_string));
    }
    None
}

fn collect_called_idents(node: Node, src: &[u8], out: &mut Vec<(String, usize)>) {
    let k = node.kind();
    if k.contains("comment") || k.contains("string") || k == "template_string" {
        return;
    }
    if matches!(k, "identifier" | "property_identifier" | "field_identifier") {
        if let Ok(s) = node.utf8_text(src) {
            let trimmed = s.trim();
            if trimmed.len() >= 2 {
                out.push((trimmed.to_string(), node.start_position().row + 1));
            }
        }
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        collect_called_idents(ch, src, out);
    }
}

fn extract_fns(node: Node, src: &str, rel: &str, out: &mut Vec<FnDef>) {
    let is_fn = matches!(
        node.kind(),
        "function_definition"
            | "function_declaration"
            | "method_definition"
            | "function_item"
            | "method_declaration"
    );
    if is_fn {
        if let Some(name) = node_name(node, src.as_bytes()) {
            let mut idents = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                collect_called_idents(body, src.as_bytes(), &mut idents);
            } else {
                collect_called_idents(node, src.as_bytes(), &mut idents);
            }
            out.push(FnDef {
                name,
                file: rel.to_string(),
                start_line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
                called_idents: idents,
            });
        }
    } else if node.kind() == "variable_declarator" {
        if let (Some(nm_n), Some(val_n)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        ) {
            if matches!(
                val_n.kind(),
                "arrow_function" | "function_expression" | "function"
            ) {
                if let Ok(name) = nm_n.utf8_text(src.as_bytes()) {
                    let clean_name = name.trim();
                    if !clean_name.is_empty() {
                        let mut idents = Vec::new();
                        if let Some(body) = val_n.child_by_field_name("body") {
                            collect_called_idents(body, src.as_bytes(), &mut idents);
                        } else {
                            collect_called_idents(val_n, src.as_bytes(), &mut idents);
                        }
                        out.push(FnDef {
                            name: clean_name.to_string(),
                            file: rel.to_string(),
                            start_line: node.start_position().row + 1,
                            end_line: val_n.end_position().row + 1,
                            called_idents: idents,
                        });
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        extract_fns(ch, src, rel, out);
    }
}

pub fn trace_symbol_chain(root: &Path, target: &str, max_depth: usize) -> TraceReport {
    let t0 = Instant::now();
    let mut all_fns: Vec<FnDef> = Vec::new();
    let walker = WalkBuilder::new(root)
        .git_ignore(true)
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            let nm = e.file_name().to_string_lossy();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                return !SKIP_DIRS.contains(&nm.as_ref());
            }
            true
        })
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let p = entry.path();
        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        let Some(mut parser) = parser_for_ext(ext) else {
            continue;
        };
        let rel = p
            .strip_prefix(root)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(src) = fs::read_to_string(p) else {
            continue;
        };
        let Some(tree) = parser.parse(&src, None) else {
            continue;
        };
        extract_fns(tree.root_node(), &src, &rel, &mut all_fns);
    }

    let defined_names: HashSet<&str> = all_fns.iter().map(|f| f.name.as_str()).collect();
    let mut callers_of: HashMap<&str, Vec<(&FnDef, usize)>> = HashMap::new();
    let mut callees_of: HashMap<&str, Vec<(&str, usize)>> = HashMap::new();

    for f in &all_fns {
        let mut seen_callee: HashSet<&str> = HashSet::new();
        for (ident, ln) in &f.called_idents {
            let id_s = ident.as_str();
            if id_s != f.name.as_str() && defined_names.contains(id_s) && seen_callee.insert(id_s) {
                callers_of.entry(id_s).or_default().push((f, *ln));
                callees_of
                    .entry(f.name.as_str())
                    .or_default()
                    .push((id_s, *ln));
            }
        }
    }

    let defs: Vec<(String, usize, usize)> = all_fns
        .iter()
        .filter(|f| f.name == target)
        .map(|f| (f.file.clone(), f.start_line, f.end_line))
        .collect();

    // Upstream BFS (callers -> callers of callers)
    let mut upstream = Vec::new();
    let mut visited_up: HashSet<String> = HashSet::from([target.to_string()]);
    let mut frontier: Vec<(String, Vec<String>)> =
        vec![(target.to_string(), vec![target.to_string()])];
    for d in 1..=max_depth.clamp(1, 5) {
        let mut next_frontier = Vec::new();
        for (cur, chain) in frontier {
            if let Some(cands) = callers_of.get(cur.as_str()) {
                for (caller_fn, call_ln) in cands {
                    if !visited_up.insert(caller_fn.name.clone()) {
                        continue;
                    }
                    let mut p = vec![caller_fn.name.clone()];
                    p.extend(chain.clone());
                    upstream.push(TraceEdge {
                        depth: d,
                        symbol: caller_fn.name.clone(),
                        file: caller_fn.file.clone(),
                        line: *call_ln,
                        path: p.clone(),
                    });
                    next_frontier.push((caller_fn.name.clone(), p));
                }
            }
        }
        frontier = next_frontier;
        if frontier.is_empty() {
            break;
        }
    }

    // Downstream callees (depth 1..2) + notable I/O/exec/DOM/SQL sinks inside target
    let mut downstream = Vec::new();
    let mut visited_dn: HashSet<String> = HashSet::from([target.to_string()]);
    let mut dn_front: Vec<(String, Vec<String>)> =
        vec![(target.to_string(), vec![target.to_string()])];
    for d in 1..=2 {
        let mut next_dn = Vec::new();
        for (cur, chain) in dn_front {
            if let Some(cands) = callees_of.get(cur.as_str()) {
                for (callee_nm, ln) in cands {
                    if !visited_dn.insert((*callee_nm).to_string()) {
                        continue;
                    }
                    let f_file = all_fns
                        .iter()
                        .find(|f| f.name == *callee_nm)
                        .map(|f| f.file.clone())
                        .unwrap_or_default();
                    let mut p = chain.clone();
                    p.push((*callee_nm).to_string());
                    downstream.push(TraceEdge {
                        depth: d,
                        symbol: (*callee_nm).to_string(),
                        file: f_file,
                        line: *ln,
                        path: p.clone(),
                    });
                    next_dn.push(((*callee_nm).to_string(), p));
                }
            }
        }
        dn_front = next_dn;
    }

    let mut sinks = Vec::new();
    let mut seen_sinks = HashSet::new();
    for f in all_fns.iter().filter(|f| f.name == target) {
        for (id, ln) in &f.called_idents {
            if NOTABLE_SINKS.contains(&id.as_str()) && seen_sinks.insert((id.clone(), *ln)) {
                sinks.push((id.clone(), *ln));
            }
        }
    }

    TraceReport {
        target: target.to_string(),
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
        scanned_functions: all_fns.len(),
        definitions: defs,
        upstream_callers: upstream,
        downstream_callees: downstream,
        notable_sinks: sinks,
    }
}

pub fn render_trace_md(rep: &TraceReport) -> String {
    let mut out = vec![format!(
        "# ATLAS TRACE `{}` ({} scanned fns in {}ms)",
        rep.target, rep.scanned_functions, rep.elapsed_ms
    )];
    if rep.definitions.is_empty() {
        out.push("Definitions: *(none found — check symbol spelling)*".to_string());
    } else {
        let ds: Vec<String> = rep
            .definitions
            .iter()
            .map(|(f, s, e)| format!("`{f}:L{s}-L{e}`"))
            .collect();
        out.push(format!("Definitions: {}", ds.join(", ")));
    }
    out.push(format!(
        "\n## Upstream Callers Chain ({} reachable caller(s))",
        rep.upstream_callers.len()
    ));
    if rep.upstream_callers.is_empty() {
        out.push("  *(no project callers found — likely top-level entrypoint or callback)*".into());
    } else {
        for e in &rep.upstream_callers {
            let pad = "  ".repeat(e.depth);
            out.push(format!(
                "{pad}- [hop {}] `{}` (`{}:L{}`) -> `{}`",
                e.depth,
                e.symbol,
                e.file,
                e.line,
                e.path.join(" -> ")
            ));
        }
    }
    out.push(format!(
        "\n## Downstream Callees ({} hop-1..2) & Notable Sinks ({})",
        rep.downstream_callees.len(),
        rep.notable_sinks.len()
    ));
    for e in &rep.downstream_callees {
        let pad = "  ".repeat(e.depth);
        out.push(format!(
            "{pad}- [hop {}] `{}` (`{}`) via `{}`",
            e.depth,
            e.symbol,
            e.file,
            e.path.join(" -> ")
        ));
    }
    if !rep.notable_sinks.is_empty() {
        let sk: Vec<String> = rep
            .notable_sinks
            .iter()
            .map(|(s, l)| format!("`{s}`@L{l}"))
            .collect();
        out.push(format!(
            "  - Notable I/O/Exec/DOM/SQL Sinks: {}",
            sk.join(", ")
        ));
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_resolves_arrow_callers_and_ignores_string_comment_mentions() {
        let dir = std::env::temp_dir().join(format!("ap_trace_arrow_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("app.ts"),
            "export function leafCheck(x: number) { return fetch('/api') ? x : 0; }\n\
             export const arrowCaller = (n: number) => leafCheck(n);\n\
             export const decoyFn = () => { const msg = 'leafCheck'; // leafCheck\n  return msg; };\n",
        )
        .unwrap();

        let rep = trace_symbol_chain(&dir, "leafCheck", 3);
        assert_eq!(rep.definitions.len(), 1);
        assert!(
            rep.upstream_callers
                .iter()
                .any(|e| e.symbol == "arrowCaller"),
            "{:?}",
            rep.upstream_callers
        );
        assert!(
            !rep.upstream_callers.iter().any(|e| e.symbol == "decoyFn"),
            "{:?}",
            rep.upstream_callers
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
