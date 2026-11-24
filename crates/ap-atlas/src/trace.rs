use ignore::WalkBuilder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
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

pub(crate) const NOTABLE_SINKS: &[&str] = &[
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
    "execv",
    "execve",
    "ShellExecute",
    "CreateProcess",
    "dangerouslySetInnerHTML",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallArgInfo {
    pub callee: String,
    pub line: usize,
    pub arg_taint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arg_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FnDef {
    pub name: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub called_idents: Vec<(String, usize)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guard_lines: Vec<(usize, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_args: Vec<CallArgInfo>,
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
pub struct ReachabilityHop {
    pub caller: String,
    pub callee: String,
    pub file: String,
    pub line: usize,
    pub guard_placement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub guard_note: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arg_taint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arg_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityPath {
    pub source: String,
    pub sink: String,
    pub guarded: bool,
    pub hops: Vec<ReachabilityHop>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_target: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reachability_paths: Vec<ReachabilityPath>,
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
        "c" | "h" | "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => tree_sitter_c::LANGUAGE.into(),
        _ => return None,
    };
    p.set_language(&lang).ok()?;
    Some(p)
}

fn extract_guard_lines(
    src_lines: &[&str],
    start_line: usize,
    end_line: usize,
) -> Vec<(usize, String)> {
    let gre = crate::surface::guard_re();
    let scan_start = if end_line > start_line {
        start_line + 1
    } else {
        start_line
    };
    let mut out = Vec::new();
    for ln in scan_start..=end_line {
        if let Some(raw) = src_lines.get(ln.saturating_sub(1)) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() && gre.is_match(trimmed) {
                out.push((ln, trimmed.chars().take(90).collect()));
            }
        }
    }
    out
}

pub(crate) fn clean_fn_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(idx) = trimmed.rfind("::") {
        let tail = trimmed[idx + 2..].trim();
        if !tail.is_empty() {
            return tail.to_string();
        }
    }
    trimmed.to_string()
}

fn node_name(node: Node, src: &[u8]) -> Option<String> {
    if let Some(n) = node.child_by_field_name("name") {
        if let Ok(s) = n.utf8_text(src) {
            let cleaned = clean_fn_name(s);
            if !cleaned.is_empty() {
                return Some(cleaned);
            }
        }
    }
    if let Some(d) = node.child_by_field_name("declarator") {
        return node_name(d, src).or_else(|| d.utf8_text(src).ok().map(clean_fn_name));
    }
    None
}

fn collect_param_idents(node: Node, src: &[u8], out: &mut HashSet<String>) {
    let k = node.kind();
    if k.contains("type") && k != "typed_parameter" && k != "typed_default_parameter" {
        return;
    }
    if matches!(k, "identifier" | "shorthand_property_identifier_pattern") {
        if let Ok(s) = node.utf8_text(src) {
            let t = s.trim();
            if !t.is_empty() && t != "self" && t != "this" {
                out.insert(t.to_string());
            }
        }
        return;
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        if ch.kind().contains("type_annotation") || ch.kind() == "type" {
            continue;
        }
        collect_param_idents(ch, src, out);
    }
}

fn find_param_names(fn_node: Node, src: &[u8]) -> HashSet<String> {
    let mut params = HashSet::new();
    for field in ["parameters", "parameter_list", "formal_parameters"] {
        if let Some(pn) = fn_node.child_by_field_name(field) {
            collect_param_idents(pn, src, &mut params);
        }
    }
    if params.is_empty() {
        if let Some(decl) = fn_node.child_by_field_name("declarator") {
            for field in ["parameters", "parameter_list"] {
                if let Some(pn) = decl.child_by_field_name(field) {
                    collect_param_idents(pn, src, &mut params);
                }
            }
        }
    }
    params
}

fn is_const_literal_expr(node: Node, src: &[u8], const_vars: &HashSet<String>) -> bool {
    let k = node.kind();
    if matches!(
        k,
        "string"
            | "string_literal"
            | "raw_string_literal"
            | "interpreted_string_literal"
            | "number"
            | "integer"
            | "float"
            | "integer_literal"
            | "float_literal"
            | "number_literal"
            | "true"
            | "false"
            | "boolean_literal"
            | "null"
            | "none"
            | "nil"
            | "char_literal"
    ) {
        return true;
    }
    if k == "template_string" {
        let mut cur = node.walk();
        for ch in node.children(&mut cur) {
            if ch.kind() == "template_substitution" {
                return false;
            }
        }
        return true;
    }
    if matches!(k, "identifier" | "field_identifier" | "property_identifier") {
        if let Ok(s) = node.utf8_text(src) {
            return const_vars.contains(s.trim());
        }
        return false;
    }
    if matches!(k, "parenthesized_expression" | "unary_expression") {
        let mut cur = node.walk();
        let mut has_child = false;
        for ch in node.children(&mut cur) {
            if matches!(ch.kind(), "(" | ")" | "-" | "+" | "!" | "~") {
                continue;
            }
            has_child = true;
            if !is_const_literal_expr(ch, src, const_vars) {
                return false;
            }
        }
        return has_child;
    }
    if matches!(k, "binary_expression" | "concatenation") {
        let mut cur = node.walk();
        let mut has_operand = false;
        for ch in node.children(&mut cur) {
            if matches!(ch.kind(), "+" | "-" | "*" | "/" | "%") {
                continue;
            }
            has_operand = true;
            if !is_const_literal_expr(ch, src, const_vars) {
                return false;
            }
        }
        return has_operand;
    }
    false
}

fn expr_contains_param(node: Node, src: &[u8], params: &HashSet<String>) -> bool {
    let k = node.kind();
    if k.contains("comment") || k.contains("string") && k != "template_string" {
        return false;
    }
    if matches!(k, "identifier" | "field_identifier" | "property_identifier") {
        if let Ok(s) = node.utf8_text(src) {
            if params.contains(s.trim()) {
                return true;
            }
        }
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        if expr_contains_param(ch, src, params) {
            return true;
        }
    }
    false
}

fn extract_callee_short_name(fn_expr: Node, src: &[u8]) -> Option<String> {
    let k = fn_expr.kind();
    if matches!(k, "identifier" | "property_identifier" | "field_identifier") {
        return fn_expr
            .utf8_text(src)
            .ok()
            .map(clean_fn_name)
            .filter(|s| !s.is_empty());
    }
    for field in ["property", "field", "name", "attribute"] {
        if let Some(ch) = fn_expr.child_by_field_name(field) {
            if let Some(nm) = extract_callee_short_name(ch, src) {
                return Some(nm);
            }
        }
    }
    let mut cur = fn_expr.walk();
    let mut last = None;
    for ch in fn_expr.children(&mut cur) {
        if let Some(nm) = extract_callee_short_name(ch, src) {
            last = Some(nm);
        }
    }
    last
}

fn update_local_const_binding(node: Node, src: &[u8], const_vars: &mut HashSet<String>) {
    let k = node.kind();
    if matches!(
        k,
        "variable_declarator" | "init_declarator" | "let_declaration"
    ) {
        let lhs = node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("pattern"))
            .or_else(|| node.child_by_field_name("declarator"));
        let rhs = node.child_by_field_name("value");
        if let (Some(ln), Some(rn)) = (lhs, rhs) {
            if let Ok(nm) = ln.utf8_text(src) {
                let id = nm.trim();
                if !id.is_empty() && !id.contains(' ') {
                    if is_const_literal_expr(rn, src, const_vars) {
                        const_vars.insert(id.to_string());
                    } else {
                        const_vars.remove(id);
                    }
                }
            }
        }
    } else if matches!(k, "assignment_expression" | "assignment") {
        if let (Some(ln), Some(rn)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            if let Ok(nm) = ln.utf8_text(src) {
                let id = nm.trim();
                if !id.is_empty() && !id.contains(' ') {
                    if is_const_literal_expr(rn, src, const_vars) {
                        const_vars.insert(id.to_string());
                    } else {
                        const_vars.remove(id);
                    }
                }
            }
        }
    }
}

fn collect_called_idents(
    node: Node,
    src: &[u8],
    params: &HashSet<String>,
    const_vars: &mut HashSet<String>,
    out: &mut Vec<(String, usize)>,
    call_args: &mut Vec<CallArgInfo>,
) {
    let k = node.kind();
    if k.contains("comment") || k.contains("string") || k == "template_string" {
        return;
    }
    update_local_const_binding(node, src, const_vars);

    if matches!(k, "call_expression" | "call" | "new_expression") {
        let callee_node = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("constructor"))
            .or_else(|| node.named_child(0));
        let args_node = node
            .child_by_field_name("arguments")
            .or_else(|| node.child_by_field_name("argument_list"));
        if let (Some(cn), Some(an)) = (callee_node, args_node) {
            if let Some(callee_nm) = extract_callee_short_name(cn, src) {
                let mut value_args: Vec<Node> = Vec::new();
                let mut acur = an.walk();
                for ch in an.children(&mut acur) {
                    if !matches!(ch.kind(), "(" | ")" | "," | ";") && !ch.kind().contains("comment")
                    {
                        value_args.push(ch);
                    }
                }
                let taint = if value_args.is_empty()
                    || value_args
                        .iter()
                        .all(|a| is_const_literal_expr(*a, src, const_vars))
                {
                    "CONST_LITERAL"
                } else if value_args
                    .iter()
                    .any(|a| expr_contains_param(*a, src, params))
                {
                    "PARAM_TAINTED"
                } else {
                    "VAR_DYNAMIC"
                };
                let arg_preview = an
                    .utf8_text(src)
                    .ok()
                    .map(|s| {
                        s.split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ")
                            .chars()
                            .take(72)
                            .collect::<String>()
                    })
                    .unwrap_or_default();
                call_args.push(CallArgInfo {
                    callee: callee_nm,
                    line: node.start_position().row + 1,
                    arg_taint: taint.to_string(),
                    arg_preview,
                });
            }
        }
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
        collect_called_idents(ch, src, params, const_vars, out, call_args);
    }
}

pub(crate) fn lookup_call_taint(f: &FnDef, callee: &str, line: usize) -> (String, String) {
    if let Some(hit) = f
        .call_args
        .iter()
        .find(|c| c.callee == callee && c.line == line)
        .or_else(|| f.call_args.iter().find(|c| c.callee == callee))
    {
        return (hit.arg_taint.clone(), hit.arg_preview.clone());
    }
    (String::new(), String::new())
}

fn is_cpp_ext(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx"
    )
}

fn cpp_method_sig_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\s*(?:[\w:<>*&\s]+?\s+)?([A-Za-z_~]\w*::)+([A-Za-z_~]\w*)\s*\([^;]*$")
            .unwrap()
    })
}

fn cpp_ident_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([A-Za-z_]\w{1,})\b").unwrap())
}

fn extract_cpp_fallback_fns(src: &str, src_lines: &[&str], rel: &str, out: &mut Vec<FnDef>) {
    let existing: HashSet<(String, usize)> =
        out.iter().map(|f| (f.name.clone(), f.start_line)).collect();
    let sig_re = cpp_method_sig_re();
    let id_re = cpp_ident_re();
    let mut i = 0usize;
    while i < src_lines.len() {
        let line = src_lines[i];
        if let Some(cap) = sig_re.captures(line) {
            let method = cap.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if !method.is_empty() && !matches!(method, "if" | "for" | "while" | "switch" | "catch")
            {
                // Find opening `{` on this or next 2 lines and track brace balance
                let mut open_idx = None;
                for (j, sig_ln) in src_lines
                    .iter()
                    .enumerate()
                    .take((i + 3).min(src_lines.len()))
                    .skip(i)
                {
                    if sig_ln.contains('{') {
                        open_idx = Some(j);
                        break;
                    }
                    if sig_ln.contains(';') {
                        break;
                    }
                }
                if let Some(start_brace) = open_idx {
                    let mut depth = 0i32;
                    let mut end_idx = start_brace;
                    for (j, ltxt) in src_lines.iter().enumerate().skip(start_brace) {
                        for ch in ltxt.chars() {
                            if ch == '{' {
                                depth += 1;
                            } else if ch == '}' {
                                depth -= 1;
                            }
                        }
                        end_idx = j;
                        if depth <= 0 {
                            break;
                        }
                    }
                    let start_line = i + 1;
                    let end_line = end_idx + 1;
                    if !existing.contains(&(method.to_string(), start_line)) {
                        let mut idents = Vec::new();
                        for (off, b_line) in src_lines[start_brace..=end_idx].iter().enumerate() {
                            let stripped = b_line.split("//").next().unwrap_or(b_line);
                            for m in id_re.captures_iter(stripped) {
                                if let Some(id) = m.get(1) {
                                    idents.push((id.as_str().to_string(), start_brace + off + 1));
                                }
                            }
                        }
                        out.push(FnDef {
                            name: method.to_string(),
                            file: rel.to_string(),
                            start_line,
                            end_line,
                            called_idents: idents,
                            guard_lines: extract_guard_lines(src_lines, start_line, end_line),
                            call_args: Vec::new(),
                        });
                    }
                    i = end_idx + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    let _ = src;
}

fn extract_fns(node: Node, src: &str, src_lines: &[&str], rel: &str, out: &mut Vec<FnDef>) {
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
            let params = find_param_names(node, src.as_bytes());
            let mut const_vars = HashSet::new();
            let mut idents = Vec::new();
            let mut call_args = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                collect_called_idents(
                    body,
                    src.as_bytes(),
                    &params,
                    &mut const_vars,
                    &mut idents,
                    &mut call_args,
                );
            } else {
                collect_called_idents(
                    node,
                    src.as_bytes(),
                    &params,
                    &mut const_vars,
                    &mut idents,
                    &mut call_args,
                );
            }
            let start_line = node.start_position().row + 1;
            let end_line = node.end_position().row + 1;
            out.push(FnDef {
                name,
                file: rel.to_string(),
                start_line,
                end_line,
                called_idents: idents,
                guard_lines: extract_guard_lines(src_lines, start_line, end_line),
                call_args,
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
                        let params = find_param_names(val_n, src.as_bytes());
                        let mut const_vars = HashSet::new();
                        let mut idents = Vec::new();
                        let mut call_args = Vec::new();
                        if let Some(body) = val_n.child_by_field_name("body") {
                            collect_called_idents(
                                body,
                                src.as_bytes(),
                                &params,
                                &mut const_vars,
                                &mut idents,
                                &mut call_args,
                            );
                        } else {
                            collect_called_idents(
                                val_n,
                                src.as_bytes(),
                                &params,
                                &mut const_vars,
                                &mut idents,
                                &mut call_args,
                            );
                        }
                        let start_line = node.start_position().row + 1;
                        let end_line = val_n.end_position().row + 1;
                        out.push(FnDef {
                            name: clean_name.to_string(),
                            file: rel.to_string(),
                            start_line,
                            end_line,
                            called_idents: idents,
                            guard_lines: extract_guard_lines(src_lines, start_line, end_line),
                            call_args,
                        });
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        extract_fns(ch, src, src_lines, rel, out);
    }
}

pub(crate) fn classify_hop_guard(caller: &FnDef, call_line: usize) -> (String, String) {
    if let Some((ln, snippet)) = caller.guard_lines.iter().rfind(|(ln, _)| *ln < call_line) {
        return ("GUARD_BEFORE".to_string(), format!("L{ln}: {snippet}"));
    }
    if let Some((ln, snippet)) = caller.guard_lines.iter().find(|(ln, _)| *ln > call_line) {
        return ("GUARD_AFTER".to_string(), format!("L{ln}: {snippet}"));
    }
    ("UNGUARDED".to_string(), String::new())
}

fn sink_matches_query(ident: &str, query_norm: &str) -> bool {
    if ident == query_norm {
        return true;
    }
    if query_norm.len() >= 3 {
        let id_low = ident.to_ascii_lowercase();
        let q_low = query_norm.to_ascii_lowercase();
        return id_low == q_low || id_low.contains(&q_low);
    }
    false
}

fn compute_reachability_paths(
    all_fns: &[FnDef],
    target_norm: &str,
    to_sink: Option<&str>,
    include_sinks: bool,
    tainted_only: bool,
    max_depth: usize,
) -> Vec<ReachabilityPath> {
    let sink_query = to_sink.map(clean_fn_name).filter(|s| !s.is_empty());
    if sink_query.is_none() && !include_sinks {
        return Vec::new();
    }

    let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (idx, f) in all_fns.iter().enumerate() {
        by_name.entry(f.name.as_str()).or_default().push(idx);
    }

    let start_indices: Vec<usize> = all_fns
        .iter()
        .enumerate()
        .filter(|(_, f)| f.name == target_norm)
        .map(|(i, _)| i)
        .collect();
    if start_indices.is_empty() {
        return Vec::new();
    }

    let limit = max_depth.clamp(1, 8);
    let mut queue: VecDeque<(usize, Vec<ReachabilityHop>)> = VecDeque::new();
    let mut visited_depth: HashMap<usize, usize> = HashMap::new();
    for s_idx in &start_indices {
        visited_depth.insert(*s_idx, 0);
        queue.push_back((*s_idx, Vec::new()));
    }

    let mut paths: Vec<ReachabilityPath> = Vec::new();
    let mut seen_signatures: HashSet<String> = HashSet::new();

    while let Some((cur_idx, hops)) = queue.pop_front() {
        let cur_fn = &all_fns[cur_idx];
        let mut seen_edge: HashSet<(&str, usize)> = HashSet::new();

        for (ident, ln) in &cur_fn.called_idents {
            let id_s = ident.as_str();
            if id_s == cur_fn.name.as_str() || !seen_edge.insert((id_s, *ln)) {
                continue;
            }
            let (guard_placement, guard_note) = classify_hop_guard(cur_fn, *ln);
            let (arg_taint, arg_preview) = lookup_call_taint(cur_fn, id_s, *ln);
            let hop = ReachabilityHop {
                caller: cur_fn.name.clone(),
                callee: id_s.to_string(),
                file: cur_fn.file.clone(),
                line: *ln,
                guard_placement,
                guard_note,
                arg_taint: arg_taint.clone(),
                arg_preview,
            };

            let is_sink_hit = if let Some(ref q) = sink_query {
                sink_matches_query(id_s, q)
            } else {
                NOTABLE_SINKS.contains(&id_s)
            };

            if is_sink_hit && !(tainted_only && arg_taint == "CONST_LITERAL") {
                let mut full_hops = hops.clone();
                full_hops.push(hop.clone());
                let sig = format!(
                    "{}=>{}",
                    full_hops
                        .iter()
                        .map(|h| format!("{}:{}", h.caller, h.line))
                        .collect::<Vec<_>>()
                        .join("->"),
                    id_s
                );
                if seen_signatures.insert(sig) {
                    let guarded = full_hops
                        .iter()
                        .any(|h| h.guard_placement == "GUARD_BEFORE");
                    paths.push(ReachabilityPath {
                        source: target_norm.to_string(),
                        sink: id_s.to_string(),
                        guarded,
                        hops: full_hops,
                    });
                }
            }

            if hops.len() + 1 < limit {
                if let Some(callees) = by_name.get(id_s) {
                    for &next_idx in callees {
                        let already_in_chain =
                            hops.iter().any(|h| h.caller == all_fns[next_idx].name)
                                || next_idx == cur_idx;
                        if already_in_chain {
                            continue;
                        }
                        let next_depth = hops.len() + 1;
                        let best_prev = visited_depth.get(&next_idx).copied().unwrap_or(usize::MAX);
                        if next_depth <= best_prev {
                            visited_depth.insert(next_idx, next_depth);
                            let mut next_hops = hops.clone();
                            next_hops.push(hop.clone());
                            queue.push_back((next_idx, next_hops));
                        }
                    }
                }
            }
        }
    }

    paths.sort_by(|a, b| {
        a.guarded
            .cmp(&b.guarded)
            .then_with(|| a.hops.len().cmp(&b.hops.len()))
            .then_with(|| a.sink.cmp(&b.sink))
    });
    paths.truncate(16);
    paths
}

pub fn trace_symbol_chain(root: &Path, target: &str, max_depth: usize) -> TraceReport {
    trace_symbol_chain_to(root, target, None, false, max_depth)
}

pub(crate) fn collect_project_fns(root: &Path) -> Vec<FnDef> {
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
        let src_lines: Vec<&str> = src.lines().collect();
        extract_fns(tree.root_node(), &src, &src_lines, &rel, &mut all_fns);
        if is_cpp_ext(ext) {
            extract_cpp_fallback_fns(&src, &src_lines, &rel, &mut all_fns);
        }
    }
    all_fns
}

pub fn trace_symbol_chain_to(
    root: &Path,
    target: &str,
    to_sink: Option<&str>,
    include_sinks: bool,
    max_depth: usize,
) -> TraceReport {
    trace_symbol_chain_to_opts(root, target, to_sink, include_sinks, false, max_depth)
}

pub fn trace_symbol_chain_to_opts(
    root: &Path,
    target: &str,
    to_sink: Option<&str>,
    include_sinks: bool,
    tainted_only: bool,
    max_depth: usize,
) -> TraceReport {
    let t0 = Instant::now();
    let target_clean = clean_fn_name(target);
    let target_ref = target_clean.as_str();
    let all_fns = collect_project_fns(root);

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
        .filter(|f| f.name == target_ref)
        .map(|f| (f.file.clone(), f.start_line, f.end_line))
        .collect();

    // Upstream BFS (callers -> callers of callers)
    let mut upstream = Vec::new();
    let mut visited_up: HashSet<String> = HashSet::from([target_clean.clone()]);
    let mut frontier: Vec<(String, Vec<String>)> =
        vec![(target_clean.clone(), vec![target_clean.clone()])];
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
    let mut visited_dn: HashSet<String> = HashSet::from([target_clean.clone()]);
    let mut dn_front: Vec<(String, Vec<String>)> =
        vec![(target_clean.clone(), vec![target_clean.clone()])];
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
    for f in all_fns.iter().filter(|f| f.name == target_ref) {
        for (id, ln) in &f.called_idents {
            if NOTABLE_SINKS.contains(&id.as_str()) && seen_sinks.insert((id.clone(), *ln)) {
                sinks.push((id.clone(), *ln));
            }
        }
    }

    let reachability_paths = compute_reachability_paths(
        &all_fns,
        target_ref,
        to_sink,
        include_sinks,
        tainted_only,
        max_depth,
    );

    TraceReport {
        target: target_clean,
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
        scanned_functions: all_fns.len(),
        definitions: defs,
        upstream_callers: upstream,
        downstream_callees: downstream,
        notable_sinks: sinks,
        to_target: to_sink
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        reachability_paths,
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
    if !rep.reachability_paths.is_empty() || rep.to_target.is_some() {
        out.push(format!(
            "\n## Reachability Paths ({} path(s){})",
            rep.reachability_paths.len(),
            rep.to_target
                .as_deref()
                .map(|t| format!(" to `{t}`"))
                .unwrap_or_default()
        ));
        if rep.reachability_paths.is_empty() {
            out.push("  *(no reachable path found within max depth)*".to_string());
        } else {
            for p in &rep.reachability_paths {
                let badge = if p.guarded {
                    "[GUARDED]"
                } else {
                    "[UNGUARDED]"
                };
                let hop_str: Vec<String> = p
                    .hops
                    .iter()
                    .map(|h| {
                        let taint = if h.arg_taint.is_empty() {
                            String::new()
                        } else {
                            format!(", {}", h.arg_taint)
                        };
                        if h.guard_note.is_empty() {
                            format!(
                                "`{}` -> `{}` ({}:L{}, {}{})",
                                h.caller, h.callee, h.file, h.line, h.guard_placement, taint
                            )
                        } else {
                            format!(
                                "`{}` -> `{}` ({}:L{}, {} `{}`{})",
                                h.caller,
                                h.callee,
                                h.file,
                                h.line,
                                h.guard_placement,
                                h.guard_note,
                                taint
                            )
                        }
                    })
                    .collect();
                out.push(format!(
                    "  - {badge} `{}` => `{}` ({} hop(s)): {}",
                    p.source,
                    p.sink,
                    p.hops.len(),
                    hop_str.join(" | ")
                ));
            }
        }
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

    #[test]
    fn trace_source_to_sink_reachability_and_guard_placement() {
        let dir = std::env::temp_dir().join(format!("ap_trace_reach_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("routes.ts"),
            "export function handleRaw(req: any) {\n\
               return runUnsafe(req.cmd);\n\
             }\n\
             export function runUnsafe(cmd: string) {\n\
               return execSync(cmd);\n\
             }\n\
             export function handleChecked(req: any) {\n\
               if (!authorize(req.user)) return 403;\n\
               return runUnsafe(req.cmd);\n\
             }\n\
             export function handlePostCheck(req: any) {\n\
               const out = runUnsafe(req.cmd);\n\
               if (!verify(out)) return null;\n\
               return out;\n\
             }\n",
        )
        .unwrap();

        let rep_open = trace_symbol_chain_to(&dir, "handleRaw", Some("execSync"), false, 4);
        assert_eq!(rep_open.reachability_paths.len(), 1);
        assert!(!rep_open.reachability_paths[0].guarded);
        assert_eq!(rep_open.reachability_paths[0].hops.len(), 2);
        assert_eq!(
            rep_open.reachability_paths[0].hops[0].guard_placement,
            "UNGUARDED"
        );

        let rep_guarded = trace_symbol_chain_to(&dir, "handleChecked", Some("execSync"), false, 4);
        assert_eq!(rep_guarded.reachability_paths.len(), 1);
        assert!(rep_guarded.reachability_paths[0].guarded);
        assert_eq!(
            rep_guarded.reachability_paths[0].hops[0].guard_placement,
            "GUARD_BEFORE"
        );

        let rep_after = trace_symbol_chain_to(&dir, "handlePostCheck", None, true, 4);
        assert_eq!(rep_after.reachability_paths.len(), 1);
        assert!(!rep_after.reachability_paths[0].guarded);
        assert_eq!(
            rep_after.reachability_paths[0].hops[0].guard_placement,
            "GUARD_AFTER"
        );
        let md = render_trace_md(&rep_after);
        assert!(
            md.contains("[UNGUARDED]") && md.contains("GUARD_AFTER"),
            "{md}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn trace_supports_cpp_qualified_methods_and_sinks() {
        let dir = std::env::temp_dir().join(format!("ap_trace_cpp_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("worker.cpp"),
            "int Runner::dispatch(const char* arg) {\n\
               return Runner::launch(arg);\n\
             }\n\
             int Runner::launch(const char* cmd) {\n\
               return system(cmd);\n\
             }\n",
        )
        .unwrap();

        let rep = trace_symbol_chain_to(&dir, "Runner::dispatch", Some("system"), false, 4);
        assert!(!rep.definitions.is_empty(), "missing C++ definition");
        assert!(
            !rep.reachability_paths.is_empty(),
            "expected C++ Runner::dispatch -> launch -> system path: {:?}",
            rep.reachability_paths
        );
        assert_eq!(rep.reachability_paths[0].sink, "system");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn trace_classifies_param_taint_vs_const_literal_and_filters_tainted_only() {
        let dir = std::env::temp_dir().join(format!("ap_trace_taint_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("taint.ts"),
            "export function handleUser(cmd: string) {\n\
               return execSync(cmd);\n\
             }\n\
             export function handleConst() {\n\
               const fixed = 'git status';\n\
               return execSync(fixed);\n\
             }\n",
        )
        .unwrap();

        let tainted =
            trace_symbol_chain_to_opts(&dir, "handleUser", Some("execSync"), false, true, 3);
        assert_eq!(tainted.reachability_paths.len(), 1);
        assert_eq!(
            tainted.reachability_paths[0].hops[0].arg_taint,
            "PARAM_TAINTED"
        );

        let filtered =
            trace_symbol_chain_to_opts(&dir, "handleConst", Some("execSync"), false, true, 3);
        assert!(
            filtered.reachability_paths.is_empty(),
            "CONST_LITERAL should be filtered when tainted_only=true: {:?}",
            filtered.reachability_paths
        );

        let unfiltered =
            trace_symbol_chain_to_opts(&dir, "handleConst", Some("execSync"), false, false, 3);
        assert_eq!(unfiltered.reachability_paths.len(), 1);
        assert_eq!(
            unfiltered.reachability_paths[0].hops[0].arg_taint,
            "CONST_LITERAL"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
