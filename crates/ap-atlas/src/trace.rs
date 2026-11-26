use ignore::{WalkBuilder, WalkState};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
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

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallArgInfo {
    pub callee: String,
    pub line: usize,
    pub arg_taint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arg_preview: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arg_param_masks: Vec<u32>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub arg_const_mask: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arg_call_deps: Vec<(usize, String, Vec<u32>)>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub return_param_mask: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub direct_return_param_mask: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub return_calls: Vec<(String, Vec<u32>)>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FnSummary {
    pub param_to_return: u32,
    pub param_to_sinks: HashMap<String, u32>,
    pub any_sink_mask: u32,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SummaryIndex {
    pub by_file_fn: HashMap<(String, String), FnSummary>,
    pub by_name_files: HashMap<String, Vec<String>>,
}

impl SummaryIndex {
    pub(crate) fn resolve(&self, caller_file: &str, callee: &str) -> Option<&FnSummary> {
        if let Some(exact) = self
            .by_file_fn
            .get(&(caller_file.to_string(), callee.to_string()))
        {
            return Some(exact);
        }
        if let Some(files) = self.by_name_files.get(callee) {
            if files.len() == 1 {
                return self.by_file_fn.get(&(files[0].clone(), callee.to_string()));
            }
        }
        None
    }
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
    #[serde(default, skip_serializing_if = "is_false")]
    pub taint_via_summary: bool,
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

pub(crate) fn strip_guard_comment_line(raw: &str, in_block: &mut bool) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        if *in_block {
            if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                *in_block = false;
                i += 2;
            } else {
                let ch = raw[i..].chars().next().unwrap();
                i += ch.len_utf8();
            }
            continue;
        }
        let b = bytes[i];
        if let Some(q) = quote {
            let ch = raw[i..].chars().next().unwrap();
            out.push(ch);
            if b == b'\\' && i + 1 < bytes.len() {
                if let Some(next_ch) = raw[i + 1..].chars().next() {
                    out.push(next_ch);
                    i += 1 + next_ch.len_utf8();
                    continue;
                }
            }
            if b == q {
                quote = None;
            }
            i += ch.len_utf8();
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            break;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            *in_block = true;
            i += 2;
            continue;
        }
        if b == b'#' && out.trim().is_empty() && !raw[i..].trim_start().starts_with("#[") {
            break;
        }
        if b == b'"' || b == b'\'' || b == b'`' {
            quote = Some(b);
        }
        let ch = raw[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
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
    let mut in_block = false;
    for ln in scan_start..=end_line {
        if let Some(raw) = src_lines.get(ln.saturating_sub(1)) {
            let code = strip_guard_comment_line(raw, &mut in_block);
            let trimmed = code.trim();
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

fn collect_param_idents_ordered(node: Node, src: &[u8], out: &mut Vec<String>) {
    let k = node.kind();
    if k.contains("type") && k != "typed_parameter" && k != "typed_default_parameter" {
        return;
    }
    if matches!(k, "identifier" | "shorthand_property_identifier_pattern") {
        if let Ok(s) = node.utf8_text(src) {
            let t = s.trim();
            if !t.is_empty()
                && t != "self"
                && t != "this"
                && out.len() < 32
                && !out.iter().any(|existing| existing == t)
            {
                out.push(t.to_string());
            }
        }
        return;
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        if ch.kind().contains("type_annotation") || ch.kind() == "type" {
            continue;
        }
        collect_param_idents_ordered(ch, src, out);
    }
}

fn find_param_names(fn_node: Node, src: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    for field in ["parameters", "parameter_list", "formal_parameters"] {
        if let Some(pn) = fn_node.child_by_field_name(field) {
            collect_param_idents_ordered(pn, src, &mut params);
        }
    }
    if params.is_empty() {
        if let Some(decl) = fn_node.child_by_field_name("declarator") {
            for field in ["parameters", "parameter_list"] {
                if let Some(pn) = decl.child_by_field_name(field) {
                    collect_param_idents_ordered(pn, src, &mut params);
                }
            }
        }
    }
    params
}

fn param_bit(ident: &str, params: &[String]) -> u32 {
    params
        .iter()
        .position(|p| p == ident)
        .filter(|&i| i < 32)
        .map(|i| 1u32 << i)
        .unwrap_or(0)
}

fn is_sanitizer_callee(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    low.starts_with("escape")
        || low.starts_with("sanitize")
        || low.starts_with("validate")
        || matches!(
            low.as_str(),
            "parseint" | "parsefloat" | "number" | "boolean" | "string" | "encodeuricomponent"
        )
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

fn expr_param_mask(
    node: Node,
    src: &[u8],
    params: &[String],
    tainted_vars: &HashMap<String, u32>,
) -> u32 {
    let k = node.kind();
    if k.contains("comment") || (k.contains("string") && k != "template_string") {
        return 0;
    }
    if matches!(k, "call_expression" | "call") {
        if let Some(fn_node) = node
            .child_by_field_name("function")
            .or_else(|| node.named_child(0))
        {
            if let Some(nm) = extract_callee_short_name(fn_node, src) {
                if is_sanitizer_callee(&nm) {
                    return 0;
                }
            }
        }
    }
    if matches!(
        k,
        "identifier" | "shorthand_property_identifier" | "field_identifier" | "property_identifier"
    ) {
        if let Ok(s) = node.utf8_text(src) {
            let trimmed = s.trim();
            let pb = param_bit(trimmed, params);
            if pb != 0 {
                return pb;
            }
            if let Some(&tb) = tainted_vars.get(trimmed) {
                return tb;
            }
        }
        return 0;
    }
    let mut mask = 0u32;
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        mask |= expr_param_mask(ch, src, params, tainted_vars);
    }
    mask
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

type CallDepList = Vec<(String, Vec<u32>)>;

fn collect_expr_call_deps(
    node: Node,
    src: &[u8],
    params: &[String],
    tainted_vars: &HashMap<String, u32>,
    var_call_deps: &HashMap<String, (CallDepList, u32)>,
    out_calls: &mut CallDepList,
    direct_mask: &mut u32,
) {
    let k = node.kind();
    if k.contains("comment") || (k.contains("string") && k != "template_string") {
        return;
    }
    if matches!(k, "call_expression" | "call") {
        if let Some(fn_node) = node
            .child_by_field_name("function")
            .or_else(|| node.named_child(0))
        {
            if let Some(nm) = extract_callee_short_name(fn_node, src) {
                if is_sanitizer_callee(&nm) {
                    return;
                }
                if let Some(an) = node
                    .child_by_field_name("arguments")
                    .or_else(|| node.child_by_field_name("argument_list"))
                {
                    let mut dep_masks = Vec::new();
                    let mut acur = an.walk();
                    for ch in an.children(&mut acur) {
                        if !matches!(ch.kind(), "(" | ")" | "," | ";")
                            && !ch.kind().contains("comment")
                        {
                            dep_masks.push(expr_param_mask(ch, src, params, tainted_vars));
                        }
                    }
                    out_calls.push((nm, dep_masks));
                    return;
                }
            }
        }
    }
    if matches!(
        k,
        "identifier" | "shorthand_property_identifier" | "field_identifier" | "property_identifier"
    ) {
        if let Ok(s) = node.utf8_text(src) {
            let trimmed = s.trim();
            let pb = param_bit(trimmed, params);
            if pb != 0 {
                *direct_mask |= pb;
                return;
            }
            if let Some((calls, dir_m)) = var_call_deps.get(trimmed) {
                out_calls.extend(calls.iter().cloned());
                *direct_mask |= *dir_m;
                return;
            }
            if let Some(&tb) = tainted_vars.get(trimmed) {
                *direct_mask |= tb;
            }
        }
        return;
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        collect_expr_call_deps(
            ch,
            src,
            params,
            tainted_vars,
            var_call_deps,
            out_calls,
            direct_mask,
        );
    }
}

fn update_local_bindings(
    node: Node,
    src: &[u8],
    params: &[String],
    const_vars: &mut HashSet<String>,
    tainted_vars: &mut HashMap<String, u32>,
    var_call_deps: &mut HashMap<String, (CallDepList, u32)>,
) {
    let k = node.kind();
    let (lhs, rhs) = if matches!(
        k,
        "variable_declarator" | "init_declarator" | "let_declaration"
    ) {
        let l = node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("pattern"))
            .or_else(|| node.child_by_field_name("declarator"));
        let r = node.child_by_field_name("value");
        (l, r)
    } else if matches!(k, "assignment_expression" | "assignment") {
        (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        )
    } else {
        return;
    };

    if let (Some(ln), Some(rn)) = (lhs, rhs) {
        if let Ok(nm) = ln.utf8_text(src) {
            let id = nm.trim();
            if !id.is_empty() && !id.contains(' ') {
                if is_const_literal_expr(rn, src, const_vars) {
                    const_vars.insert(id.to_string());
                    tainted_vars.remove(id);
                    var_call_deps.remove(id);
                } else {
                    const_vars.remove(id);
                    let mut deps = Vec::new();
                    let mut dir_m = 0u32;
                    collect_expr_call_deps(
                        rn,
                        src,
                        params,
                        tainted_vars,
                        var_call_deps,
                        &mut deps,
                        &mut dir_m,
                    );
                    if deps.is_empty() {
                        var_call_deps.remove(id);
                    } else {
                        var_call_deps.insert(id.to_string(), (deps, dir_m));
                    }
                    let m = expr_param_mask(rn, src, params, tainted_vars);
                    if m != 0 {
                        tainted_vars.insert(id.to_string(), m);
                    } else {
                        tainted_vars.remove(id);
                    }
                }
            }
        }
    }
}

struct FnBodyState<'a> {
    params: &'a [String],
    const_vars: HashSet<String>,
    tainted_vars: HashMap<String, u32>,
    var_call_deps: HashMap<String, (CallDepList, u32)>,
    return_param_mask: u32,
    direct_return_param_mask: u32,
    return_calls: CallDepList,
    idents: Vec<(String, usize)>,
    call_args: Vec<CallArgInfo>,
}

fn collect_called_idents(node: Node, src: &[u8], st: &mut FnBodyState<'_>) {
    let k = node.kind();
    if k.contains("comment") || k.contains("string") || k == "template_string" {
        return;
    }
    update_local_bindings(
        node,
        src,
        st.params,
        &mut st.const_vars,
        &mut st.tainted_vars,
        &mut st.var_call_deps,
    );
    if matches!(k, "return_statement" | "return_expression") {
        st.return_param_mask |= expr_param_mask(node, src, st.params, &st.tainted_vars);
        collect_expr_call_deps(
            node,
            src,
            st.params,
            &st.tainted_vars,
            &st.var_call_deps,
            &mut st.return_calls,
            &mut st.direct_return_param_mask,
        );
    }

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
                let mut arg_param_masks = Vec::with_capacity(value_args.len().min(32));
                let mut arg_const_mask = 0u32;
                let mut combined_param_mask = 0u32;
                let mut arg_call_deps: Vec<(usize, String, Vec<u32>)> = Vec::new();
                for (idx, arg) in value_args.iter().enumerate() {
                    let pm = expr_param_mask(*arg, src, st.params, &st.tainted_vars);
                    if idx < 32 {
                        arg_param_masks.push(pm);
                        if pm == 0 && is_const_literal_expr(*arg, src, &st.const_vars) {
                            arg_const_mask |= 1u32 << idx;
                        }
                        let mut deps = Vec::new();
                        let mut dir_m = 0u32;
                        collect_expr_call_deps(
                            *arg,
                            src,
                            st.params,
                            &st.tainted_vars,
                            &st.var_call_deps,
                            &mut deps,
                            &mut dir_m,
                        );
                        if dir_m == 0 {
                            for (dc, dm) in deps {
                                arg_call_deps.push((idx, dc, dm));
                            }
                        }
                    }
                    combined_param_mask |= pm;
                }
                let taint = if value_args.is_empty()
                    || value_args
                        .iter()
                        .all(|a| is_const_literal_expr(*a, src, &st.const_vars))
                {
                    "CONST_LITERAL"
                } else if combined_param_mask != 0 {
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
                st.call_args.push(CallArgInfo {
                    callee: callee_nm,
                    line: node.start_position().row + 1,
                    arg_taint: taint.to_string(),
                    arg_preview,
                    arg_param_masks,
                    arg_const_mask,
                    arg_call_deps,
                });
            }
        }
    }

    if matches!(k, "identifier" | "property_identifier" | "field_identifier") {
        if let Ok(s) = node.utf8_text(src) {
            let trimmed = s.trim();
            if trimmed.len() >= 2 {
                st.idents
                    .push((trimmed.to_string(), node.start_position().row + 1));
            }
        }
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        collect_called_idents(ch, src, st);
    }
}

pub(crate) fn compute_callee_summaries(all_fns: &[FnDef]) -> SummaryIndex {
    let mut index = SummaryIndex::default();
    for f in all_fns {
        let key = (f.file.clone(), f.name.clone());
        index
            .by_name_files
            .entry(f.name.clone())
            .or_default()
            .push(f.file.clone());
        let entry = index.by_file_fn.entry(key).or_default();
        // Initialize return mask from direct returns or calls to external (non-defined) functions
        entry.param_to_return |= f.direct_return_param_mask;
        for c in &f.call_args {
            if NOTABLE_SINKS.contains(&c.callee.as_str()) {
                let m = c.arg_param_masks.iter().copied().fold(0u32, |a, b| a | b);
                if m != 0 {
                    *entry.param_to_sinks.entry(c.callee.clone()).or_insert(0) |= m;
                    entry.any_sink_mask |= m;
                }
            }
        }
    }
    for files in index.by_name_files.values_mut() {
        files.sort();
        files.dedup();
    }
    // Seed return_param_mask for external return calls (callees not defined in project)
    for f in all_fns {
        let mut ext_ret = 0u32;
        for (rc_callee, rc_args) in &f.return_calls {
            if index.resolve(&f.file, rc_callee).is_none() {
                ext_ret |= rc_args.iter().copied().fold(0u32, |a, b| a | b);
            }
        }
        if ext_ret != 0 {
            if let Some(entry) = index.by_file_fn.get_mut(&(f.file.clone(), f.name.clone())) {
                entry.param_to_return |= ext_ret;
            }
        }
    }
    // 2-pass bottom-up interprocedural propagation for BOTH param_to_sinks and param_to_return
    for _ in 0..2 {
        let prev = index.clone();
        for f in all_fns {
            let mut add_ret_mask = 0u32;
            for (rc_callee, rc_args) in &f.return_calls {
                if let Some(callee_sum) = prev.resolve(&f.file, rc_callee) {
                    for (idx, &arg_pm) in rc_args.iter().enumerate() {
                        if idx < 32 && (callee_sum.param_to_return & (1u32 << idx)) != 0 {
                            add_ret_mask |= arg_pm;
                        }
                    }
                }
            }
            if add_ret_mask != 0 {
                if let Some(s) = index.by_file_fn.get_mut(&(f.file.clone(), f.name.clone())) {
                    s.param_to_return |= add_ret_mask;
                }
            }
            for c in &f.call_args {
                let Some(callee_sum) = prev.resolve(&f.file, &c.callee) else {
                    continue;
                };
                if callee_sum.param_to_sinks.is_empty() && callee_sum.param_to_return == 0 {
                    continue;
                }
                for (sink, &sink_pm) in &callee_sum.param_to_sinks {
                    let mut caller_pm = 0u32;
                    for (idx, &arg_pm) in c.arg_param_masks.iter().enumerate() {
                        if idx < 32 && (sink_pm & (1u32 << idx)) != 0 {
                            caller_pm |= arg_pm;
                        }
                    }
                    if caller_pm != 0 {
                        if let Some(s) = index.by_file_fn.get_mut(&(f.file.clone(), f.name.clone()))
                        {
                            *s.param_to_sinks.entry(sink.clone()).or_insert(0) |= caller_pm;
                            s.any_sink_mask |= caller_pm;
                        }
                    }
                }
            }
        }
    }
    index
}

pub(crate) fn lookup_call_arg<'a>(
    f: &'a FnDef,
    callee: &str,
    line: usize,
) -> Option<&'a CallArgInfo> {
    f.call_args
        .iter()
        .find(|c| c.callee == callee && c.line == line)
        .or_else(|| f.call_args.iter().find(|c| c.callee == callee))
}

pub(crate) fn lookup_call_taint_with_summary(
    f: &FnDef,
    callee: &str,
    line: usize,
    sink_filter: Option<&str>,
    summaries: &SummaryIndex,
    active_param_mask: Option<u32>,
    active_dynamic_mask: Option<u32>,
) -> (String, String, bool) {
    let Some(hit) = lookup_call_arg(f, callee, line) else {
        return (String::new(), String::new(), false);
    };

    let mut via_summary = false;
    let mut taint = hit.arg_taint.clone();
    let mut eff_arg_masks = hit.arg_param_masks.clone();
    let mut eff_const_mask = hit.arg_const_mask;

    if !hit.arg_call_deps.is_empty() && !eff_arg_masks.is_empty() {
        let mut by_slot: HashMap<usize, Vec<(&str, &[u32])>> = HashMap::new();
        for (slot, dc, dm) in &hit.arg_call_deps {
            by_slot
                .entry(*slot)
                .or_default()
                .push((dc.as_str(), dm.as_slice()));
        }
        let mut resolved_any = false;
        for (slot, deps) in by_slot {
            if slot >= eff_arg_masks.len() || slot >= 32 {
                continue;
            }
            if deps
                .iter()
                .all(|(dc, _)| summaries.resolve(&f.file, dc).is_some())
            {
                let mut ret_pm = 0u32;
                for (dc, dm) in deps {
                    if let Some(dsum) = summaries.resolve(&f.file, dc) {
                        for (di, &arg_pm) in dm.iter().enumerate() {
                            if di < 32 && (dsum.param_to_return & (1u32 << di)) != 0 {
                                ret_pm |= arg_pm;
                            }
                        }
                    }
                }
                eff_arg_masks[slot] = ret_pm;
                if ret_pm == 0 {
                    eff_const_mask |= 1u32 << slot;
                }
                resolved_any = true;
            }
        }
        if resolved_any {
            via_summary = true;
            if eff_arg_masks.iter().any(|&m| m != 0) {
                taint = "PARAM_TAINTED".to_string();
            } else if !eff_arg_masks.is_empty()
                && (0..eff_arg_masks.len().min(32)).all(|i| (eff_const_mask & (1u32 << i)) != 0)
            {
                taint = "CONST_LITERAL".to_string();
            }
        }
    }

    if let Some(active_pm) = active_param_mask {
        let dyn_pm = active_dynamic_mask.unwrap_or(0);
        if !eff_arg_masks.is_empty() {
            let mut relevant_pm = 0u32;
            let mut relevant_dyn = 0u32;
            let mut all_slots_known_safe = true;
            for (i, &pm) in eff_arg_masks.iter().enumerate() {
                let is_const_slot = i < 32 && (eff_const_mask & (1u32 << i)) != 0;
                if is_const_slot {
                    continue;
                }
                let pm_taint = pm & active_pm;
                let pm_dyn = pm & dyn_pm;
                relevant_pm |= pm_taint;
                relevant_dyn |= pm_dyn;
                if pm == 0 || pm_taint != 0 || pm_dyn != 0 {
                    all_slots_known_safe = false;
                }
            }
            if relevant_pm != 0 {
                taint = "PARAM_TAINTED".to_string();
                if active_pm != u32::MAX {
                    via_summary = true;
                }
            } else if relevant_dyn != 0 {
                taint = "VAR_DYNAMIC".to_string();
                via_summary = true;
            } else if all_slots_known_safe && taint != "CONST_LITERAL" {
                taint = "CONST_LITERAL".to_string();
                via_summary = true;
            }
        }
    }

    if let Some(sum) = summaries.resolve(&f.file, callee) {
        let sink_param_mask = if let Some(sq) = sink_filter {
            let sq_norm = clean_fn_name(sq);
            if sink_matches_query(callee, &sq_norm) {
                sum.any_sink_mask
            } else {
                sum.param_to_sinks
                    .iter()
                    .filter(|(sk, _)| sink_matches_query(sk, &sq_norm))
                    .fold(0u32, |acc, (_, &m)| acc | m)
            }
        } else {
            sum.any_sink_mask
        };
        if sink_param_mask != 0 && !eff_arg_masks.is_empty() {
            let gate = active_param_mask.unwrap_or(u32::MAX);
            let dyn_gate = active_dynamic_mask.unwrap_or(0);
            let mut taint_hits = 0u32;
            let mut dyn_hits = 0u32;
            let mut all_sinking_const = true;
            let mut any_sinking_checked = false;
            for (i, &pm) in eff_arg_masks.iter().enumerate() {
                if i >= 32 || (sink_param_mask & (1u32 << i)) == 0 {
                    continue;
                }
                any_sinking_checked = true;
                let eff_pm = pm & gate;
                let eff_dyn = pm & dyn_gate;
                taint_hits |= eff_pm;
                dyn_hits |= eff_dyn;
                let is_const =
                    (eff_const_mask & (1u32 << i)) != 0 || (pm != 0 && eff_pm == 0 && eff_dyn == 0);
                if !is_const {
                    all_sinking_const = false;
                }
            }
            if any_sinking_checked {
                if taint_hits != 0 {
                    taint = "PARAM_TAINTED".to_string();
                    via_summary = true;
                } else if dyn_hits != 0 {
                    taint = "VAR_DYNAMIC".to_string();
                    via_summary = true;
                } else if all_sinking_const {
                    taint = "CONST_LITERAL".to_string();
                    via_summary = true;
                }
            }
        }
    }

    (taint, hit.arg_preview.clone(), via_summary)
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
                            params: Vec::new(),
                            return_param_mask: 0,
                            direct_return_param_mask: 0,
                            return_calls: Vec::new(),
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

struct FnBodyFacts {
    params: Vec<String>,
    idents: Vec<(String, usize)>,
    call_args: Vec<CallArgInfo>,
    return_param_mask: u32,
    direct_return_param_mask: u32,
    return_calls: CallDepList,
}

fn collect_fn_body_facts(fn_node: Node, src: &[u8]) -> FnBodyFacts {
    let params = find_param_names(fn_node, src);
    let mut st = FnBodyState {
        params: &params,
        const_vars: HashSet::new(),
        tainted_vars: HashMap::new(),
        var_call_deps: HashMap::new(),
        return_param_mask: 0,
        direct_return_param_mask: 0,
        return_calls: Vec::new(),
        idents: Vec::new(),
        call_args: Vec::new(),
    };
    let target = fn_node.child_by_field_name("body").unwrap_or(fn_node);
    collect_called_idents(target, src, &mut st);
    if fn_node.kind() == "arrow_function"
        && fn_node
            .child_by_field_name("body")
            .is_some_and(|b| b.kind() != "statement_block")
    {
        st.return_param_mask |= expr_param_mask(target, src, st.params, &st.tainted_vars);
        collect_expr_call_deps(
            target,
            src,
            st.params,
            &st.tainted_vars,
            &st.var_call_deps,
            &mut st.return_calls,
            &mut st.direct_return_param_mask,
        );
    }
    let idents = st.idents;
    let call_args = st.call_args;
    let return_param_mask = st.return_param_mask;
    let direct_return_param_mask = st.direct_return_param_mask;
    let return_calls = st.return_calls;
    FnBodyFacts {
        params,
        idents,
        call_args,
        return_param_mask,
        direct_return_param_mask,
        return_calls,
    }
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
            let facts = collect_fn_body_facts(node, src.as_bytes());
            let start_line = node.start_position().row + 1;
            let end_line = node.end_position().row + 1;
            out.push(FnDef {
                name,
                file: rel.to_string(),
                start_line,
                end_line,
                called_idents: facts.idents,
                guard_lines: extract_guard_lines(src_lines, start_line, end_line),
                call_args: facts.call_args,
                params: facts.params,
                return_param_mask: facts.return_param_mask,
                direct_return_param_mask: facts.direct_return_param_mask,
                return_calls: facts.return_calls,
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
                        let facts = collect_fn_body_facts(val_n, src.as_bytes());
                        let start_line = node.start_position().row + 1;
                        let end_line = val_n.end_position().row + 1;
                        out.push(FnDef {
                            name: clean_name.to_string(),
                            file: rel.to_string(),
                            start_line,
                            end_line,
                            called_idents: facts.idents,
                            guard_lines: extract_guard_lines(src_lines, start_line, end_line),
                            call_args: facts.call_args,
                            params: facts.params,
                            return_param_mask: facts.return_param_mask,
                            direct_return_param_mask: facts.direct_return_param_mask,
                            return_calls: facts.return_calls,
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
    summaries: &SummaryIndex,
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
    // Queue carries (fn_idx, hops, active_param_mask, active_dynamic_mask)
    let mut queue: VecDeque<(usize, Vec<ReachabilityHop>, u32, u32)> = VecDeque::new();
    let mut visited_depth: HashMap<(usize, u32), usize> = HashMap::new();
    for s_idx in &start_indices {
        let init_mask = if all_fns[*s_idx].params.is_empty() {
            0
        } else if all_fns[*s_idx].params.len() >= 32 {
            u32::MAX
        } else {
            (1u32 << all_fns[*s_idx].params.len()) - 1
        };
        visited_depth.insert((*s_idx, init_mask), 0);
        queue.push_back((*s_idx, Vec::new(), init_mask, 0));
    }

    let mut paths: Vec<ReachabilityPath> = Vec::new();
    let mut seen_signatures: HashSet<String> = HashSet::new();

    while let Some((cur_idx, hops, active_pm, active_dyn)) = queue.pop_front() {
        let cur_fn = &all_fns[cur_idx];
        let mut seen_edge: HashSet<(&str, usize)> = HashSet::new();
        let active_opt = if hops.is_empty() {
            None
        } else {
            Some(active_pm)
        };
        let dyn_opt = if hops.is_empty() {
            None
        } else {
            Some(active_dyn)
        };

        for (ident, ln) in &cur_fn.called_idents {
            let id_s = ident.as_str();
            if id_s == cur_fn.name.as_str() || !seen_edge.insert((id_s, *ln)) {
                continue;
            }
            let (guard_placement, guard_note) = classify_hop_guard(cur_fn, *ln);
            let (arg_taint, arg_preview, taint_via_summary) = lookup_call_taint_with_summary(
                cur_fn,
                id_s,
                *ln,
                sink_query.as_deref(),
                summaries,
                active_opt,
                dyn_opt,
            );
            let hop = ReachabilityHop {
                caller: cur_fn.name.clone(),
                callee: id_s.to_string(),
                file: cur_fn.file.clone(),
                line: *ln,
                guard_placement,
                guard_note,
                arg_taint: arg_taint.clone(),
                arg_preview,
                taint_via_summary,
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
                    let same_file_callees: Vec<usize> = callees
                        .iter()
                        .copied()
                        .filter(|&idx| all_fns[idx].file == cur_fn.file)
                        .collect();
                    let scoped_callees: Vec<usize> = if !same_file_callees.is_empty() {
                        same_file_callees
                    } else if callees.len() == 1 {
                        callees.clone()
                    } else {
                        Vec::new()
                    };
                    let call_info = lookup_call_arg(cur_fn, id_s, *ln);
                    let (next_pm, next_dyn) = if let Some(ci) = call_info {
                        let mut pm = 0u32;
                        let mut dm = 0u32;
                        for (i, &arg_m) in ci.arg_param_masks.iter().enumerate() {
                            if i >= 32 {
                                break;
                            }
                            let is_const = (ci.arg_const_mask & (1u32 << i)) != 0;
                            if (arg_m & active_pm) != 0 {
                                pm |= 1u32 << i;
                            } else if !is_const && ((arg_m & active_dyn) != 0 || arg_m == 0) {
                                dm |= 1u32 << i;
                            }
                        }
                        (pm, dm)
                    } else {
                        (u32::MAX, 0)
                    };
                    for next_idx in scoped_callees {
                        let already_in_chain = hops.iter().any(|h| {
                            h.caller == all_fns[next_idx].name && h.file == all_fns[next_idx].file
                        }) || next_idx == cur_idx;
                        if already_in_chain {
                            continue;
                        }
                        let next_depth = hops.len() + 1;
                        let best_prev = visited_depth
                            .get(&(next_idx, next_pm))
                            .copied()
                            .unwrap_or(usize::MAX);
                        if next_depth <= best_prev {
                            visited_depth.insert((next_idx, next_pm), next_depth);
                            let mut next_hops = hops.clone();
                            next_hops.push(hop.clone());
                            queue.push_back((next_idx, next_hops, next_pm, next_dyn));
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
    let all_fns_mx: Arc<Mutex<Vec<FnDef>>> = Arc::new(Mutex::new(Vec::new()));
    let root_arc = Arc::new(root.to_path_buf());
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
        .build_parallel();

    walker.run(|| {
        let out_c = Arc::clone(&all_fns_mx);
        let root_c = Arc::clone(&root_arc);
        let mut parsers: HashMap<String, Option<Parser>> = HashMap::new();

        Box::new(move |res| {
            let Ok(entry) = res else {
                return WalkState::Continue;
            };
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                return WalkState::Continue;
            }
            let p = entry.path();
            let ext_raw = p.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext_raw.is_empty() {
                return WalkState::Continue;
            }
            let ext_key = ext_raw.to_ascii_lowercase();
            let parser_opt = parsers
                .entry(ext_key.clone())
                .or_insert_with(|| parser_for_ext(&ext_key));
            let Some(parser) = parser_opt.as_mut() else {
                return WalkState::Continue;
            };
            if let Ok(meta) = entry.metadata() {
                if meta.len() > 2 * 1024 * 1024 {
                    return WalkState::Continue;
                }
            }
            let rel = p
                .strip_prefix(root_c.as_path())
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/");
            let Ok(src) = fs::read_to_string(p) else {
                return WalkState::Continue;
            };
            let Some(tree) = parser.parse(&src, None) else {
                return WalkState::Continue;
            };
            let src_lines: Vec<&str> = src.lines().collect();
            let mut local_fns: Vec<FnDef> = Vec::new();
            extract_fns(tree.root_node(), &src, &src_lines, &rel, &mut local_fns);
            if is_cpp_ext(&ext_key) {
                extract_cpp_fallback_fns(&src, &src_lines, &rel, &mut local_fns);
            }
            if !local_fns.is_empty() {
                if let Ok(mut g) = out_c.lock() {
                    g.extend(local_fns);
                }
            }
            WalkState::Continue
        })
    });

    let mut all_fns = Arc::try_unwrap(all_fns_mx)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_else(|a| a.lock().map(|g| g.clone()).unwrap_or_default());
    all_fns.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.start_line.cmp(&b.start_line))
            .then_with(|| a.end_line.cmp(&b.end_line))
            .then_with(|| a.name.cmp(&b.name))
    });
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

    let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (idx, f) in all_fns.iter().enumerate() {
        by_name.entry(f.name.as_str()).or_default().push(idx);
    }
    let mut callers_of: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();
    let mut callees_of: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();

    for (caller_idx, f) in all_fns.iter().enumerate() {
        let mut seen_callee: HashSet<usize> = HashSet::new();
        for (ident, ln) in &f.called_idents {
            let id_s = ident.as_str();
            if id_s == f.name.as_str() {
                continue;
            }
            if let Some(cands) = by_name.get(id_s) {
                let same_file: Vec<usize> = cands
                    .iter()
                    .copied()
                    .filter(|&i| all_fns[i].file == f.file)
                    .collect();
                let resolved: Vec<usize> = if !same_file.is_empty() {
                    same_file
                } else if cands.len() == 1 {
                    cands.clone()
                } else {
                    Vec::new()
                };
                for target_idx in resolved {
                    if target_idx != caller_idx && seen_callee.insert(target_idx) {
                        callers_of
                            .entry(target_idx)
                            .or_default()
                            .push((caller_idx, *ln));
                        callees_of
                            .entry(caller_idx)
                            .or_default()
                            .push((target_idx, *ln));
                    }
                }
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
    let target_indices: Vec<usize> = by_name.get(target_ref).cloned().unwrap_or_default();
    let mut visited_up: HashSet<usize> = target_indices.iter().copied().collect();
    let mut frontier: Vec<(usize, Vec<String>)> = target_indices
        .iter()
        .map(|&idx| (idx, vec![all_fns[idx].name.clone()]))
        .collect();
    for d in 1..=max_depth.clamp(1, 5) {
        let mut next_frontier = Vec::new();
        for (cur_idx, chain) in frontier {
            if let Some(cands) = callers_of.get(&cur_idx) {
                for &(caller_idx, call_ln) in cands {
                    if !visited_up.insert(caller_idx) {
                        continue;
                    }
                    let caller_fn = &all_fns[caller_idx];
                    let mut p = vec![caller_fn.name.clone()];
                    p.extend(chain.clone());
                    upstream.push(TraceEdge {
                        depth: d,
                        symbol: caller_fn.name.clone(),
                        file: caller_fn.file.clone(),
                        line: call_ln,
                        path: p.clone(),
                    });
                    next_frontier.push((caller_idx, p));
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
    let mut visited_dn: HashSet<usize> = target_indices.iter().copied().collect();
    let mut dn_front: Vec<(usize, Vec<String>)> = target_indices
        .iter()
        .map(|&idx| (idx, vec![all_fns[idx].name.clone()]))
        .collect();
    for d in 1..=2 {
        let mut next_dn = Vec::new();
        for (cur_idx, chain) in dn_front {
            if let Some(cands) = callees_of.get(&cur_idx) {
                for &(callee_idx, ln) in cands {
                    if !visited_dn.insert(callee_idx) {
                        continue;
                    }
                    let callee_fn = &all_fns[callee_idx];
                    let mut p = chain.clone();
                    p.push(callee_fn.name.clone());
                    downstream.push(TraceEdge {
                        depth: d,
                        symbol: callee_fn.name.clone(),
                        file: callee_fn.file.clone(),
                        line: ln,
                        path: p.clone(),
                    });
                    next_dn.push((callee_idx, p));
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

    let summaries = compute_callee_summaries(&all_fns);
    let reachability_paths = compute_reachability_paths(
        &all_fns,
        &summaries,
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

    #[test]
    fn trace_two_hop_callee_summary_propagates_param_taint_and_downgrades_const() {
        let dir = std::env::temp_dir().join(format!("ap_trace_interproc_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("flow.ts"),
            "export function leafExec(cmdArg: string, note: string) {\n\
               console.log(note);\n\
               return execSync(cmdArg);\n\
             }\n\
             export function midWrap(pathIn: string) {\n\
               const cmd = 'tool ' + pathIn;\n\
               return leafExec(cmd, 'tag');\n\
             }\n\
             export function entryTainted(input: any) {\n\
               return midWrap(input.path);\n\
             }\n\
             export function entryConst(req: any) {\n\
               return leafExec('git status', req.x);\n\
             }\n\
             export function entrySanitized(req: any) {\n\
               const clean = sanitizeInput(req.cmd);\n\
               return execSync(clean);\n\
             }\n",
        )
        .unwrap();

        let tainted =
            trace_symbol_chain_to_opts(&dir, "entryTainted", Some("execSync"), false, true, 4);
        assert_eq!(tainted.reachability_paths.len(), 1);
        let path = &tainted.reachability_paths[0];
        assert_eq!(path.hops.len(), 3);
        assert!(path.hops.iter().all(|h| h.arg_taint == "PARAM_TAINTED"));
        assert!(path.hops.iter().all(|h| h.taint_via_summary));

        let const_filtered =
            trace_symbol_chain_to_opts(&dir, "entryConst", Some("execSync"), false, true, 4);
        assert!(
            const_filtered.reachability_paths.is_empty(),
            "only sinking param[0] got const literal, so tainted_only must drop it: {:?}",
            const_filtered.reachability_paths
        );

        let sanitized =
            trace_symbol_chain_to_opts(&dir, "entrySanitized", Some("execSync"), false, true, 3);
        assert_eq!(sanitized.reachability_paths.len(), 1);
        assert_ne!(
            sanitized.reachability_paths[0].hops[0].arg_taint,
            "PARAM_TAINTED"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn trace_propagates_param_to_return_and_isolates_same_named_helpers_by_file() {
        let dir = std::env::temp_dir().join(format!("ap_trace_ret_qual_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("wrap.ts"),
            "export function passFirst(a: string, _tag: string) { return a; }\n\
             export function midPass(x: string) { return passFirst(x, 'ok'); }\n\
             export function midDrop(x: string) { return passFirst('fixed', x); }\n\
             export function callPass(req: any) { const c = midPass(req.cmd); return execSync(c); }\n\
             export function callDrop(req: any) { const c = midDrop(req.cmd); return execSync(c); }\n",
        )
        .unwrap();
        fs::write(
            dir.join("safe.ts"),
            "function handleSame(x: string) { return execSync('status'); }\n\
             export function entrySafe(req: any) { return handleSame(req.cmd); }\n",
        )
        .unwrap();
        fs::write(
            dir.join("vuln.ts"),
            "function handleSame(x: string) { return execSync(x); }\n\
             export function entryVuln(req: any) { return handleSame(req.cmd); }\n",
        )
        .unwrap();

        let p_pass = trace_symbol_chain_to_opts(&dir, "callPass", Some("execSync"), false, true, 3);
        assert_eq!(p_pass.reachability_paths.len(), 1);
        assert_eq!(
            p_pass.reachability_paths[0].hops[0].arg_taint,
            "PARAM_TAINTED"
        );
        assert!(p_pass.reachability_paths[0].hops[0].taint_via_summary);

        let p_drop = trace_symbol_chain_to_opts(&dir, "callDrop", Some("execSync"), false, true, 3);
        assert!(
            p_drop.reachability_paths.is_empty(),
            "midDrop dropped tainted param, expected filtered: {:?}",
            p_drop.reachability_paths
        );

        let p_safe =
            trace_symbol_chain_to_opts(&dir, "entrySafe", Some("execSync"), false, true, 3);
        assert!(
            p_safe.reachability_paths.is_empty(),
            "safe.ts handleSame must stay isolated from vuln.ts: {:?}",
            p_safe.reachability_paths
        );

        let p_vuln =
            trace_symbol_chain_to_opts(&dir, "entryVuln", Some("execSync"), false, true, 3);
        assert_eq!(p_vuln.reachability_paths.len(), 1);
        assert!(p_vuln.reachability_paths[0]
            .hops
            .iter()
            .all(|h| h.file == "vuln.ts"));
        let _ = fs::remove_dir_all(&dir);
    }
}
