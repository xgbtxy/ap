use crate::ast::{language_for_ext, scan_symbols, SymbolSpan};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use tree_sitter::{Node, Parser};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstSearchMatch {
    pub line: usize,
    pub end_line: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub kind: String,
    pub scope: String,
    pub snippet: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub captures: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub raw_captures: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatTok {
    Lit(String),
    MetaVar(String),
    MultiWild(Option<String>),
}

#[derive(Debug, Clone)]
pub enum AstQuery {
    Kinds(Vec<String>),
    Pattern(Vec<PatTok>),
}

fn expand_kind_alias(raw: &str) -> Vec<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "call" | "calls" => vec!["call_expression", "call", "invocation_expression"],
        "fn" | "func" | "function" | "method" => vec![
            "function_item",
            "function_definition",
            "function_declaration",
            "method_definition",
            "method_declaration",
            "arrow_function",
        ],
        "class" | "struct" | "type" => vec![
            "class_definition",
            "class_declaration",
            "struct_item",
            "enum_item",
            "trait_item",
            "interface_declaration",
            "type_spec",
            "type_alias_declaration",
            "type_item",
        ],
        "import" | "imports" | "use" => vec![
            "import_statement",
            "import_from_statement",
            "use_declaration",
            "import_declaration",
            "preproc_include",
        ],
        "try" | "catch" | "except" => vec!["try_statement", "catch_clause", "except_clause"],
        "assign" | "assignment" => vec![
            "assignment_expression",
            "assignment",
            "augmented_assignment",
            "short_var_declaration",
        ],
        "if" => vec!["if_statement", "if_expression"],
        "loop" | "for" | "while" => vec![
            "for_statement",
            "for_expression",
            "while_statement",
            "while_expression",
            "loop_expression",
        ],
        _ => Vec::new(),
    }
}

fn tokenize_pattern(raw: &str) -> Result<Vec<PatTok>, String> {
    let bytes = raw.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0usize;
    const MULTI_OPS: &[&str] = &[
        "===", "!==", "..=", "::", "==", "!=", "<=", ">=", "=>", "->", "&&", "||", "+=", "-=",
        "*=", "/=", "%=", "??", "?.", "..", "<<", ">>", "**",
    ];

    while i < bytes.len() {
        let ch = raw[i..].chars().next().unwrap();
        if ch.is_whitespace() {
            i += ch.len_utf8();
            continue;
        }
        // Quoted string literal token
        if ch == '"' || ch == '\'' || ch == '`' {
            let q = ch;
            let start = i;
            i += q.len_utf8();
            while i < bytes.len() {
                let c = raw[i..].chars().next().unwrap();
                i += c.len_utf8();
                if c == '\\' && i < bytes.len() {
                    let esc = raw[i..].chars().next().unwrap();
                    i += esc.len_utf8();
                    continue;
                }
                if c == q {
                    break;
                }
            }
            toks.push(PatTok::Lit(raw[start..i].to_string()));
            continue;
        }
        // Variadic wildcard `$$$` or `$$$NAME`, or metavariable `$NAME`
        if bytes[i] == b'$' {
            if raw[i..].starts_with("$$$") {
                i += 3;
                let nstart = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let name = if i > nstart {
                    Some(raw[nstart..i].to_string())
                } else {
                    None
                };
                toks.push(PatTok::MultiWild(name));
                continue;
            }
            if i + 1 < bytes.len() && (bytes[i + 1].is_ascii_alphabetic() || bytes[i + 1] == b'_') {
                i += 1;
                let nstart = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                toks.push(PatTok::MetaVar(raw[nstart..i].to_string()));
                continue;
            }
        }
        // Identifiers / keywords
        if ch.is_ascii_alphabetic() || ch == '_' {
            let start = i;
            i += ch.len_utf8();
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            toks.push(PatTok::Lit(raw[start..i].to_string()));
            continue;
        }
        // Numeric literals
        if ch.is_ascii_digit() {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'.'))
            {
                i += 1;
            }
            toks.push(PatTok::Lit(raw[start..i].to_string()));
            continue;
        }
        // Multi-char operators
        let rest = &raw[i..];
        if let Some(op) = MULTI_OPS.iter().find(|&&op| rest.starts_with(op)) {
            toks.push(PatTok::Lit((*op).to_string()));
            i += op.len();
            continue;
        }
        // Single-char punctuation / operator
        toks.push(PatTok::Lit(ch.to_string()));
        i += ch.len_utf8();
    }

    if toks.is_empty() {
        return Err("[ap search --ast] empty AST pattern".to_string());
    }
    Ok(toks)
}

impl AstQuery {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let t = raw.trim();
        if t.is_empty() {
            return Err("[ap search --ast] query cannot be empty".to_string());
        }
        if t.len() >= 5 && t[..5].eq_ignore_ascii_case("kind:") {
            let rest = &t[5..];
            let mut kinds: Vec<String> = Vec::new();
            for part in rest.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let expanded = expand_kind_alias(part);
                if expanded.is_empty() {
                    if !kinds.iter().any(|k| k == part) {
                        kinds.push(part.to_string());
                    }
                } else {
                    for ex in expanded {
                        if !kinds.iter().any(|k| k == ex) {
                            kinds.push(ex.to_string());
                        }
                    }
                }
            }
            if kinds.is_empty() {
                return Err(
                    "[ap search --ast] specify kind after `kind:` (e.g. kind:call, kind:fn)"
                        .to_string(),
                );
            }
            return Ok(Self::Kinds(kinds));
        }
        let toks = tokenize_pattern(t)?;
        Ok(Self::Pattern(toks))
    }
}

#[derive(Debug, Clone)]
struct AstLeaf {
    text: String,
    start_byte: usize,
    end_byte: usize,
    start_line: usize,
    end_line: usize,
    is_comment: bool,
}

fn is_comment_kind(kind: &str) -> bool {
    matches!(
        kind,
        "comment" | "line_comment" | "block_comment" | "doc_comment"
    )
}

fn is_atomic_literal_kind(kind: &str) -> bool {
    matches!(
        kind,
        "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "template_string"
            | "char_literal"
            | "system_lib_string"
    )
}

fn collect_leaves(root: Node, src: &[u8]) -> Vec<AstLeaf> {
    let mut leaves = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if is_comment_kind(kind) {
            continue;
        }
        if node.child_count() == 0 || is_atomic_literal_kind(kind) {
            if let Ok(txt) = node.utf8_text(src) {
                let trimmed = txt.trim();
                if !trimmed.is_empty() {
                    leaves.push(AstLeaf {
                        text: trimmed.to_string(),
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        start_line: node.start_position().row + 1,
                        end_line: (node.end_position().row + 1).max(node.start_position().row + 1),
                        is_comment: false,
                    });
                }
            }
            continue;
        }
        let mut cur = node.walk();
        let children: Vec<Node> = node.children(&mut cur).collect();
        for ch in children.into_iter().rev() {
            stack.push(ch);
        }
    }
    let _ = leaves.iter().all(|l| !l.is_comment);
    leaves
}

fn enclosing_scope(spans: &[SymbolSpan], line: usize) -> String {
    spans
        .iter()
        .filter(|sp| sp.start_line <= line && line <= sp.end_line)
        .min_by_key(|sp| sp.end_line.saturating_sub(sp.start_line))
        .map(|sp| {
            format!(
                "{} {} L{}-L{}",
                sp.kind, sp.qual, sp.start_line, sp.end_line
            )
        })
        .unwrap_or_default()
}

fn compact_snippet(raw: &str, max_chars: usize) -> String {
    let collapsed: String = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    collapsed.chars().take(max_chars).collect()
}

fn normalized_capture_text(slice: &[AstLeaf]) -> String {
    let mut out = String::new();
    for (idx, lf) in slice.iter().enumerate() {
        if idx > 0 {
            let prev = slice[idx - 1].text.as_str();
            let cur = lf.text.as_str();
            let tight = matches!(cur, "(" | ")" | "[" | "]" | "." | "," | ";" | "::" | ":")
                || matches!(prev, "(" | "[" | "." | "::");
            if !tight {
                out.push(' ');
            }
        }
        out.push_str(&lf.text);
    }
    out
}

fn is_open_delim(t: &str) -> bool {
    matches!(t, "(" | "[" | "{")
}

fn is_close_delim(t: &str) -> bool {
    matches!(t, ")" | "]" | "}")
}

fn match_tokens_at(
    leaves: &[AstLeaf],
    li: usize,
    pats: &[PatTok],
    pi: usize,
    bindings: &mut BTreeMap<String, (String, usize, usize)>,
    steps: &mut usize,
) -> Option<usize> {
    *steps += 1;
    if *steps > 512 {
        return None;
    }
    if pi == pats.len() {
        return Some(li);
    }
    match &pats[pi] {
        PatTok::Lit(expected) => {
            // Treat `, $$$` cleanly as 0-or-more trailing comma-separated arguments (e.g. `fetch($URL, $$$)` matches `fetch(u)` & `fetch(u, opts)`)
            if expected == ","
                && matches!(pats.get(pi + 1), Some(PatTok::MultiWild(_)))
                && leaves.get(li).map(|lf| lf.text != ",").unwrap_or(false)
            {
                if let Some(res_end) = match_tokens_at(leaves, li, pats, pi + 1, bindings, steps) {
                    return Some(res_end);
                }
            }
            let lf = leaves.get(li)?;
            if &lf.text == expected {
                match_tokens_at(leaves, li + 1, pats, pi + 1, bindings, steps)
            } else {
                None
            }
        }
        PatTok::MetaVar(name) => {
            let first = leaves.get(li)?;
            if is_close_delim(&first.text) || matches!(first.text.as_str(), "," | ";") {
                return None;
            }
            let max_end = (li + 32).min(leaves.len());
            let mut depth = 0i32;
            let mut end_idx = li;
            while end_idx < max_end {
                let tok = leaves[end_idx].text.as_str();
                if is_open_delim(tok) {
                    depth += 1;
                } else if is_close_delim(tok) {
                    depth -= 1;
                    if depth < 0 {
                        break;
                    }
                } else if depth == 0 && end_idx > li && matches!(tok, "," | ";") {
                    break;
                }
                end_idx += 1;
                if depth == 0 {
                    let cand = normalized_capture_text(&leaves[li..end_idx]);
                    if name != "_" {
                        if let Some(prev_val) = bindings.get(name) {
                            if prev_val.0 != cand {
                                continue;
                            }
                            if let Some(res_end) =
                                match_tokens_at(leaves, end_idx, pats, pi + 1, bindings, steps)
                            {
                                return Some(res_end);
                            }
                            continue;
                        }
                    }
                    let had = if name != "_" {
                        bindings.insert(name.clone(), (cand, li, end_idx))
                    } else {
                        None
                    };
                    if let Some(res_end) =
                        match_tokens_at(leaves, end_idx, pats, pi + 1, bindings, steps)
                    {
                        return Some(res_end);
                    }
                    if name != "_" {
                        if let Some(old) = had {
                            bindings.insert(name.clone(), old);
                        } else {
                            bindings.remove(name);
                        }
                    }
                }
            }
            None
        }
        PatTok::MultiWild(opt_name) => {
            let max_end = (li + 64).min(leaves.len());
            let mut depth = 0i32;
            let mut candidates: Vec<usize> = Vec::new();
            let mut scan = li;
            loop {
                if depth == 0 {
                    candidates.push(scan);
                }
                if scan >= max_end {
                    break;
                }
                let tok = leaves[scan].text.as_str();
                if is_open_delim(tok) {
                    depth += 1;
                } else if is_close_delim(tok) {
                    depth -= 1;
                    if depth < 0 {
                        break;
                    }
                }
                scan += 1;
            }
            for end_idx in candidates {
                let cand = normalized_capture_text(&leaves[li..end_idx]);
                let mut inserted = false;
                let mut old_val = None;
                if let Some(name) = opt_name.as_ref().filter(|n| n.as_str() != "_") {
                    if let Some(prev) = bindings.get(name) {
                        if prev.0 != cand {
                            continue;
                        }
                    } else {
                        old_val = bindings.insert(name.clone(), (cand, li, end_idx));
                        inserted = true;
                    }
                }
                if let Some(res_end) =
                    match_tokens_at(leaves, end_idx, pats, pi + 1, bindings, steps)
                {
                    return Some(res_end);
                }
                if inserted {
                    if let Some(name) = opt_name {
                        if let Some(ov) = old_val {
                            bindings.insert(name.clone(), ov);
                        } else {
                            bindings.remove(name);
                        }
                    }
                }
            }
            None
        }
    }
}

pub fn search_ast_source(
    source: &str,
    ext: &str,
    query: &AstQuery,
    max_hits: usize,
) -> Vec<AstSearchMatch> {
    if source.len() > 2 * 1024 * 1024 {
        return Vec::new();
    }
    let Some(lang) = language_for_ext(ext) else {
        return Vec::new();
    };
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let src = source.as_bytes();
    let spans = scan_symbols(source, ext);
    let mut results = Vec::new();

    match query {
        AstQuery::Kinds(kinds) => {
            let kind_set: HashSet<&str> = kinds.iter().map(String::as_str).collect();
            let mut stack = vec![tree.root_node()];
            while let Some(node) = stack.pop() {
                let k = node.kind();
                if is_comment_kind(k) {
                    continue;
                }
                if kind_set.contains(k) {
                    let s_byte = node.start_byte();
                    let e_byte = node.end_byte().min(source.len());
                    let s_line = node.start_position().row + 1;
                    let e_line = (node.end_position().row + 1).max(s_line);
                    let raw_slice = &source[s_byte..e_byte];
                    results.push(AstSearchMatch {
                        line: s_line,
                        end_line: e_line,
                        start_byte: s_byte,
                        end_byte: e_byte,
                        kind: k.to_string(),
                        scope: enclosing_scope(&spans, s_line),
                        snippet: compact_snippet(raw_slice, 200),
                        captures: BTreeMap::new(),
                        raw_captures: BTreeMap::new(),
                    });
                    if results.len() >= max_hits {
                        return results;
                    }
                }
                let mut cur = node.walk();
                let children: Vec<Node> = node.children(&mut cur).collect();
                for ch in children.into_iter().rev() {
                    stack.push(ch);
                }
            }
        }
        AstQuery::Pattern(pats) => {
            let leaves = collect_leaves(tree.root_node(), src);
            let mut idx = 0usize;
            while idx < leaves.len() {
                let mut bindings = BTreeMap::new();
                let mut steps = 0usize;
                if let Some(end_leaf_idx) =
                    match_tokens_at(&leaves, idx, pats, 0, &mut bindings, &mut steps)
                {
                    if end_leaf_idx > idx {
                        let s_byte = leaves[idx].start_byte;
                        let e_byte = leaves[end_leaf_idx - 1].end_byte.min(source.len());
                        let s_line = leaves[idx].start_line;
                        let e_line = leaves[end_leaf_idx - 1].end_line.max(s_line);
                        let raw_slice = &source[s_byte..e_byte];
                        let mut captures = BTreeMap::new();
                        let mut raw_captures = BTreeMap::new();
                        for (k, (norm_val, sl, el)) in bindings {
                            let raw_val = if el > sl && el <= leaves.len() {
                                let sb = leaves[sl].start_byte;
                                let eb = leaves[el - 1].end_byte.min(source.len());
                                source.get(sb..eb).unwrap_or(&norm_val).to_string()
                            } else {
                                String::new()
                            };
                            captures.insert(k.clone(), norm_val);
                            raw_captures.insert(k, raw_val);
                        }
                        results.push(AstSearchMatch {
                            line: s_line,
                            end_line: e_line,
                            start_byte: s_byte,
                            end_byte: e_byte,
                            kind: "ast_pattern".to_string(),
                            scope: enclosing_scope(&spans, s_line),
                            snippet: compact_snippet(raw_slice, 200),
                            captures,
                            raw_captures,
                        });
                        if results.len() >= max_hits {
                            return results;
                        }
                        idx = end_leaf_idx;
                        continue;
                    }
                }
                idx += 1;
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ast_pattern_matches_calls_ignores_comments_and_strings() {
        let js = r#"
// eval(commented_out)
const literal = "eval(inside_string)";
function run(userInput) {
    return eval(
        userInput
    );
}
"#;
        let q = AstQuery::parse("eval($ARG)").unwrap();
        let hits = search_ast_source(js, "js", &q, 20);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(
            hits[0].captures.get("ARG").map(String::as_str),
            Some("userInput")
        );
        assert!(hits[0].scope.contains("run"), "{:?}", hits[0].scope);

        let multiline_ts = r#"
function load() {
    return oldFetch("/x", {
        method: "POST",
        keepalive: true
    });
}
"#;
        let mq = AstQuery::parse("oldFetch($URL, $OPTS)").unwrap();
        let mhits = search_ast_source(multiline_ts, "ts", &mq, 10);
        assert_eq!(mhits.len(), 1, "{mhits:?}");
        assert!(
            mhits[0]
                .raw_captures
                .get("OPTS")
                .map(|s| s.contains('\n') && s.contains("keepalive: true"))
                .unwrap_or(false),
            "{:?}",
            mhits[0].raw_captures
        );

        let rust_src = r#"
use std::process::Command;
fn spawn_git() {
    // Command::new("fake")
    let _msg = "Command::new(fake2)";
    let _cmd = Command::new("git");
}
"#;
        let rq = AstQuery::parse("Command::new($BIN)").unwrap();
        let rhits = search_ast_source(rust_src, "rs", &rq, 20);
        assert_eq!(rhits.len(), 1, "{rhits:?}");
        assert_eq!(
            rhits[0].captures.get("BIN").map(String::as_str),
            Some("\"git\"")
        );
    }

    #[test]
    fn ast_pattern_unifies_repeated_metavars_and_variadic() {
        let py = r#"
def check(foo, bar):
    if foo.val == foo.val:
        pass
    if foo.val == bar.val:
        pass

def req():
    fetch("https://a.test/1")
    fetch("https://a.test/2", method="POST", timeout=5)
"#;
        let eq_q = AstQuery::parse("$X == $X").unwrap();
        let eq_hits = search_ast_source(py, "py", &eq_q, 20);
        assert_eq!(eq_hits.len(), 1, "{eq_hits:?}");
        assert_eq!(
            eq_hits[0].captures.get("X").map(String::as_str),
            Some("foo.val")
        );

        let fq = AstQuery::parse("fetch($URL, $$$)").unwrap();
        let fhits = search_ast_source(py, "py", &fq, 20);
        assert_eq!(fhits.len(), 2, "{fhits:?}");
        assert_eq!(
            fhits[1].captures.get("URL").map(String::as_str),
            Some("\"https://a.test/2\"")
        );
    }

    #[test]
    fn ast_kind_query_matches_aliases_and_exact_kinds() {
        let ts = r#"
// function ignored_comment() {}
export function alpha(x: number) { return helper(x); }
function helper(v: number) { return v + 1; }
"#;
        let kfn = AstQuery::parse("kind:fn").unwrap();
        let fhits = search_ast_source(ts, "ts", &kfn, 20);
        assert_eq!(fhits.len(), 2, "{fhits:?}");

        let kcall = AstQuery::parse("kind:call").unwrap();
        let chits = search_ast_source(ts, "ts", &kcall, 20);
        assert_eq!(chits.len(), 1, "{chits:?}");
        assert!(chits[0].snippet.contains("helper(x)"));
    }
}
