use serde::{Deserialize, Serialize};
use tree_sitter::{Language, Node, Parser};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolSpan {
    pub qual: String,
    pub short: String,
    pub kind: String,
    pub start_line: usize,
    pub end_line: usize,
    pub indent_col: usize,
}

pub fn language_for_ext(ext: &str) -> Option<Language> {
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

fn find_first_error(node: Node) -> Option<Node> {
    if node.is_error() || node.is_missing() {
        return Some(node);
    }
    if !node.has_error() {
        return None;
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        if let Some(err) = find_first_error(ch) {
            return Some(err);
        }
    }
    Some(node)
}

fn strip_jsonc_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0usize;
    let mut in_str = false;
    while i < bytes.len() {
        if in_str {
            let ch = source[i..].chars().next().unwrap();
            out.push(ch);
            if ch == '\\' && i + 1 < bytes.len() {
                i += 1;
                let nxt = source[i..].chars().next().unwrap();
                out.push(nxt);
                i += nxt.len_utf8();
                continue;
            }
            if ch == '"' {
                in_str = false;
            }
            i += ch.len_utf8();
            continue;
        }
        if bytes[i] == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
        } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else {
            let ch = source[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn verify_toml_basic(source: &str) -> Result<(), String> {
    let mut bracket_depth: i32 = 0;
    let mut brace_depth: i32 = 0;
    let mut in_ml_basic = false;
    let mut in_ml_lit = false;

    for (idx, raw_ln) in source.lines().enumerate() {
        let ln_no = idx + 1;
        let ln = raw_ln.trim();
        if !in_ml_basic && !in_ml_lit {
            if ln.is_empty() || ln.starts_with('#') {
                continue;
            }
            if ln.starts_with('[') && bracket_depth == 0 && brace_depth == 0 {
                let head = ln.split('#').next().unwrap_or(ln).trim();
                let valid_arr = head.starts_with("[[") && head.ends_with("]]") && head.len() > 4;
                let valid_tbl = !head.starts_with("[[")
                    && head.starts_with('[')
                    && head.ends_with(']')
                    && head.len() > 2;
                if !valid_arr && !valid_tbl {
                    return Err(format!(
                        "Invalid TOML table header at L{ln_no}: `{}`",
                        head.chars().take(60).collect::<String>()
                    ));
                }
                continue;
            }
        }

        let b = raw_ln.as_bytes();
        let mut i = 0usize;
        let mut in_dq = false;
        let mut in_sq = false;
        while i < b.len() {
            if in_ml_basic {
                if b[i..].starts_with(b"\"\"\"") {
                    in_ml_basic = false;
                    i += 3;
                } else if b[i] == b'\\' {
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if in_ml_lit {
                if b[i..].starts_with(b"'''") {
                    in_ml_lit = false;
                    i += 3;
                } else {
                    i += 1;
                }
                continue;
            }
            if in_dq {
                if b[i] == b'\\' {
                    i += 2;
                } else if b[i] == b'"' {
                    in_dq = false;
                    i += 1;
                } else {
                    i += 1;
                }
                continue;
            }
            if in_sq {
                if b[i] == b'\'' {
                    in_sq = false;
                }
                i += 1;
                continue;
            }
            if b[i] == b'#' {
                break;
            } else if b[i..].starts_with(b"\"\"\"") {
                in_ml_basic = true;
                i += 3;
            } else if b[i..].starts_with(b"'''") {
                in_ml_lit = true;
                i += 3;
            } else if b[i] == b'"' {
                in_dq = true;
                i += 1;
            } else if b[i] == b'\'' {
                in_sq = true;
                i += 1;
            } else {
                match b[i] {
                    b'[' => bracket_depth += 1,
                    b']' => bracket_depth -= 1,
                    b'{' => brace_depth += 1,
                    b'}' => brace_depth -= 1,
                    _ => {}
                }
                if bracket_depth < 0 || brace_depth < 0 {
                    return Err(format!("Unbalanced TOML delimiter at L{ln_no}"));
                }
                i += 1;
            }
        }
        if in_dq || in_sq {
            return Err(format!("Unterminated TOML string literal at L{ln_no}"));
        }
    }
    if in_ml_basic || in_ml_lit {
        return Err("Unterminated multiline TOML string".to_string());
    }
    if bracket_depth != 0 || brace_depth != 0 {
        return Err("Unclosed TOML array or inline table".to_string());
    }
    Ok(())
}

pub fn verify_syntax(source: &str, ext: &str) -> Result<(), String> {
    let ext_l = ext.trim_start_matches('.').to_ascii_lowercase();
    if ext_l == "json" {
        return serde_json::from_str::<serde_json::Value>(source)
            .map(|_| ())
            .map_err(|e| format!("Invalid JSON: {e}"));
    }
    if ext_l == "jsonc" {
        let stripped = strip_jsonc_comments(source);
        return serde_json::from_str::<serde_json::Value>(&stripped)
            .map(|_| ())
            .map_err(|e| format!("Invalid JSONC: {e}"));
    }
    if ext_l == "toml" {
        return verify_toml_basic(source);
    }
    let Some(lang) = language_for_ext(&ext_l) else {
        return Ok(());
    };
    let mut parser = Parser::new();
    let _ = parser.set_language(&lang);
    let Some(tree) = parser.parse(source, None) else {
        return Ok(());
    };
    let root = tree.root_node();
    if root.has_error() {
        if let Some(err_n) = find_first_error(root) {
            let pos = err_n.start_position();
            let snippet: String = err_n
                .utf8_text(source.as_bytes())
                .unwrap_or("")
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .chars()
                .take(60)
                .collect();
            return Err(format!(
                "SyntaxError at L{}:{} near `{}`",
                pos.row + 1,
                pos.column + 1,
                snippet
            ));
        }
        return Err("SyntaxError detected in AST".to_string());
    }
    Ok(())
}

fn node_text<'a>(n: Node<'a>, src: &'a [u8]) -> &'a str {
    n.utf8_text(src).unwrap_or("")
}

fn line_indent(lines: &[&str], zero_idx: usize) -> usize {
    lines
        .get(zero_idx)
        .map(|l| l.chars().take_while(|c| *c == ' ' || *c == '\t').count())
        .unwrap_or(0)
}

fn expand_leading_attrs(lines: &[&str], mut start_zero: usize) -> usize {
    while start_zero > 0 {
        let prev = lines[start_zero - 1].trim_start();
        if prev.starts_with('@') || prev.starts_with("#[") {
            start_zero -= 1;
        } else {
            break;
        }
    }
    start_zero
}

fn end_line_1idx(node: Node) -> usize {
    let ep = node.end_position();
    if ep.column == 0 && ep.row > node.start_position().row {
        ep.row
    } else {
        ep.row + 1
    }
}

fn find_c_ident<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" => Some(node_text(node, src)),
        _ => {
            if let Some(d) = node.child_by_field_name("declarator") {
                if let Some(id) = find_c_ident(d, src) {
                    return Some(id);
                }
            }
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if matches!(ch.kind(), "identifier" | "type_identifier") {
                    return Some(node_text(ch, src));
                }
            }
            None
        }
    }
}

pub fn scan_symbols(source: &str, ext: &str) -> Vec<SymbolSpan> {
    let ext_l = ext.trim_start_matches('.').to_ascii_lowercase();
    let Some(lang) = language_for_ext(&ext_l) else {
        return Vec::new();
    };
    let mut parser = Parser::new();
    let _ = parser.set_language(&lang);
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let src = source.as_bytes();
    let lines: Vec<&str> = source.lines().collect();
    let root = tree.root_node();
    let mut items = Vec::new();

    match ext_l.as_str() {
        "py" => {
            let mut cur = root.walk();
            for child in root.children(&mut cur) {
                let (outer, inner) = if child.kind() == "decorated_definition" {
                    (
                        child,
                        child.child_by_field_name("definition").unwrap_or(child),
                    )
                } else {
                    (child, child)
                };
                match inner.kind() {
                    "function_definition" => {
                        if let Some(nn) = inner.child_by_field_name("name") {
                            let nm = node_text(nn, src).to_string();
                            let s0 = outer.start_position().row;
                            items.push(SymbolSpan {
                                qual: nm.clone(),
                                short: nm,
                                kind: "def".to_string(),
                                start_line: s0 + 1,
                                end_line: end_line_1idx(outer),
                                indent_col: inner.start_position().column,
                            });
                        }
                    }
                    "class_definition" => {
                        let Some(nn) = inner.child_by_field_name("name") else {
                            continue;
                        };
                        let cname = node_text(nn, src).to_string();
                        let s0 = outer.start_position().row;
                        items.push(SymbolSpan {
                            qual: cname.clone(),
                            short: cname.clone(),
                            kind: "class".to_string(),
                            start_line: s0 + 1,
                            end_line: end_line_1idx(outer),
                            indent_col: inner.start_position().column,
                        });
                        if let Some(body) = inner.child_by_field_name("body") {
                            let mut bcur = body.walk();
                            for sub in body.children(&mut bcur) {
                                let (m_outer, m_in) = if sub.kind() == "decorated_definition" {
                                    (sub, sub.child_by_field_name("definition").unwrap_or(sub))
                                } else {
                                    (sub, sub)
                                };
                                if m_in.kind() == "function_definition" {
                                    if let Some(mn) = m_in.child_by_field_name("name") {
                                        let mname = node_text(mn, src).to_string();
                                        items.push(SymbolSpan {
                                            qual: format!("{cname}.{mname}"),
                                            short: mname,
                                            kind: "def".to_string(),
                                            start_line: m_outer.start_position().row + 1,
                                            end_line: end_line_1idx(m_outer),
                                            indent_col: m_in.start_position().column,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        "ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs" => {
            let mut cur = root.walk();
            for child in root.children(&mut cur) {
                let (outer, decl) = if child.kind() == "export_statement" {
                    (
                        child,
                        child.child_by_field_name("declaration").unwrap_or(child),
                    )
                } else {
                    (child, child)
                };
                let s0 = expand_leading_attrs(&lines, outer.start_position().row);
                let indent = line_indent(&lines, s0);
                match decl.kind() {
                    "class_declaration" | "abstract_class_declaration" => {
                        let Some(nn) = decl.child_by_field_name("name") else {
                            continue;
                        };
                        let cname = node_text(nn, src).to_string();
                        items.push(SymbolSpan {
                            qual: cname.clone(),
                            short: cname.clone(),
                            kind: "class".to_string(),
                            start_line: s0 + 1,
                            end_line: end_line_1idx(outer),
                            indent_col: indent,
                        });
                        if let Some(body) = decl.child_by_field_name("body") {
                            let mut bcur = body.walk();
                            for sub in body.children(&mut bcur) {
                                if sub.kind() == "method_definition" {
                                    if let Some(mn) = sub.child_by_field_name("name") {
                                        let mname = node_text(mn, src).to_string();
                                        let ms0 =
                                            expand_leading_attrs(&lines, sub.start_position().row);
                                        items.push(SymbolSpan {
                                            qual: format!("{cname}.{mname}"),
                                            short: mname,
                                            kind: "method".to_string(),
                                            start_line: ms0 + 1,
                                            end_line: end_line_1idx(sub),
                                            indent_col: line_indent(&lines, ms0),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    "function_declaration"
                    | "generator_function_declaration"
                    | "interface_declaration"
                    | "type_alias_declaration"
                    | "enum_declaration" => {
                        if let Some(nn) = decl.child_by_field_name("name") {
                            let nm = node_text(nn, src).to_string();
                            let kind = decl.kind().split('_').next().unwrap_or("fn").to_string();
                            items.push(SymbolSpan {
                                qual: nm.clone(),
                                short: nm,
                                kind,
                                start_line: s0 + 1,
                                end_line: end_line_1idx(outer),
                                indent_col: indent,
                            });
                        }
                    }
                    "lexical_declaration" | "variable_declaration" => {
                        let mut dcur = decl.walk();
                        for vd in decl.children(&mut dcur) {
                            if vd.kind() == "variable_declarator" {
                                if let (Some(nn), Some(vn)) = (
                                    vd.child_by_field_name("name"),
                                    vd.child_by_field_name("value"),
                                ) {
                                    if matches!(
                                        vn.kind(),
                                        "arrow_function" | "function_expression" | "function"
                                    ) {
                                        let nm = node_text(nn, src).to_string();
                                        items.push(SymbolSpan {
                                            qual: nm.clone(),
                                            short: nm,
                                            kind: "const_fn".to_string(),
                                            start_line: s0 + 1,
                                            end_line: end_line_1idx(outer),
                                            indent_col: indent,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        "go" => {
            let mut cur = root.walk();
            for child in root.children(&mut cur) {
                let s0 = child.start_position().row;
                let indent = line_indent(&lines, s0);
                match child.kind() {
                    "function_declaration" => {
                        if let Some(nn) = child.child_by_field_name("name") {
                            let nm = node_text(nn, src).to_string();
                            items.push(SymbolSpan {
                                qual: nm.clone(),
                                short: nm,
                                kind: "func".to_string(),
                                start_line: s0 + 1,
                                end_line: end_line_1idx(child),
                                indent_col: indent,
                            });
                        }
                    }
                    "method_declaration" => {
                        let Some(nn) = child.child_by_field_name("name") else {
                            continue;
                        };
                        let mname = node_text(nn, src).to_string();
                        let recv = child
                            .child_by_field_name("receiver")
                            .map(|r| {
                                node_text(r, src)
                                    .trim_matches(|c| c == '(' || c == ')')
                                    .split_whitespace()
                                    .last()
                                    .unwrap_or("")
                                    .trim_start_matches('*')
                                    .to_string()
                            })
                            .unwrap_or_default();
                        let qual = if recv.is_empty() {
                            mname.clone()
                        } else {
                            format!("{recv}.{mname}")
                        };
                        items.push(SymbolSpan {
                            qual,
                            short: mname,
                            kind: "func".to_string(),
                            start_line: s0 + 1,
                            end_line: end_line_1idx(child),
                            indent_col: indent,
                        });
                    }
                    "type_declaration" => {
                        let mut tc = child.walk();
                        for sub in child.children(&mut tc) {
                            if sub.kind() == "type_spec" {
                                if let Some(nn) = sub.child_by_field_name("name") {
                                    let nm = node_text(nn, src).to_string();
                                    items.push(SymbolSpan {
                                        qual: nm.clone(),
                                        short: nm,
                                        kind: "type".to_string(),
                                        start_line: s0 + 1,
                                        end_line: end_line_1idx(child),
                                        indent_col: indent,
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        "rs" => {
            let mut cur = root.walk();
            for child in root.children(&mut cur) {
                let s0 = expand_leading_attrs(&lines, child.start_position().row);
                let indent = line_indent(&lines, s0);
                match child.kind() {
                    "function_item" | "struct_item" | "enum_item" | "trait_item" | "type_item" => {
                        if let Some(nn) = child.child_by_field_name("name") {
                            let nm = node_text(nn, src).to_string();
                            let kind = child.kind().trim_end_matches("_item").to_string();
                            items.push(SymbolSpan {
                                qual: nm.clone(),
                                short: nm,
                                kind,
                                start_line: s0 + 1,
                                end_line: end_line_1idx(child),
                                indent_col: indent,
                            });
                        }
                    }
                    "impl_item" => {
                        let Some(tn) = child.child_by_field_name("type") else {
                            continue;
                        };
                        let raw_t = node_text(tn, src);
                        let owner = raw_t
                            .split('<')
                            .next()
                            .unwrap_or(raw_t)
                            .rsplit("::")
                            .next()
                            .unwrap_or(raw_t)
                            .trim()
                            .to_string();
                        if let Some(body) = child.child_by_field_name("body") {
                            let mut bc = body.walk();
                            for sub in body.children(&mut bc) {
                                if sub.kind() == "function_item" {
                                    if let Some(mn) = sub.child_by_field_name("name") {
                                        let mname = node_text(mn, src).to_string();
                                        let ms0 =
                                            expand_leading_attrs(&lines, sub.start_position().row);
                                        items.push(SymbolSpan {
                                            qual: format!("{owner}.{mname}"),
                                            short: mname,
                                            kind: "fn".to_string(),
                                            start_line: ms0 + 1,
                                            end_line: end_line_1idx(sub),
                                            indent_col: line_indent(&lines, ms0),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        "c" | "h" => {
            let mut cur = root.walk();
            for child in root.children(&mut cur) {
                let s0 = child.start_position().row;
                let indent = line_indent(&lines, s0);
                match child.kind() {
                    "function_definition" => {
                        if let Some(decl) = child.child_by_field_name("declarator") {
                            if let Some(nm) = find_c_ident(decl, src) {
                                items.push(SymbolSpan {
                                    qual: nm.to_string(),
                                    short: nm.to_string(),
                                    kind: "fn".to_string(),
                                    start_line: s0 + 1,
                                    end_line: end_line_1idx(child),
                                    indent_col: indent,
                                });
                            }
                        }
                    }
                    "struct_specifier" | "enum_specifier" => {
                        if let Some(nn) = child.child_by_field_name("name") {
                            let nm = node_text(nn, src).to_string();
                            let kind = child.kind().trim_end_matches("_specifier").to_string();
                            items.push(SymbolSpan {
                                qual: nm.clone(),
                                short: nm,
                                kind,
                                start_line: s0 + 1,
                                end_line: end_line_1idx(child),
                                indent_col: indent,
                            });
                        }
                    }
                    "type_definition" => {
                        if let Some(decl) = child.child_by_field_name("declarator") {
                            if let Some(nm) = find_c_ident(decl, src) {
                                items.push(SymbolSpan {
                                    qual: nm.to_string(),
                                    short: nm.to_string(),
                                    kind: "typedef".to_string(),
                                    start_line: s0 + 1,
                                    end_line: end_line_1idx(child),
                                    indent_col: indent,
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    items
}

pub fn find_symbol_span(source: &str, ext: &str, symbol: &str) -> Option<SymbolSpan> {
    let items = scan_symbols(source, ext);
    if let Some(exact) = items.iter().find(|it| it.qual == symbol) {
        return Some(exact.clone());
    }
    let short_hits: Vec<&SymbolSpan> = items.iter().filter(|it| it.short == symbol).collect();
    if short_hits.len() == 1 {
        return Some(short_hits[0].clone());
    }
    None
}

fn merge_byte_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        merged.push((s, e));
    }
    merged
}

/// Returns sorted, non-overlapping UTF-8 byte ranges for comments and string literals
/// across Python, TypeScript/TSX, JavaScript, Go, Rust, and C.
pub fn collect_non_code_ranges(source: &str, ext: &str) -> Vec<(usize, usize)> {
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
    let mut ranges = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "comment"
            | "line_comment"
            | "block_comment"
            | "string"
            | "string_literal"
            | "raw_string_literal"
            | "raw_byte_string_literal"
            | "interpreted_string_literal"
            | "char_literal"
            | "byte_string_literal"
            | "concatenated_string"
            | "string_fragment" => {
                let s = node.start_byte();
                let e = node.end_byte();
                if s < e {
                    ranges.push((s, e));
                }
            }
            _ => {
                let mut cur = node.walk();
                for ch in node.children(&mut cur) {
                    stack.push(ch);
                }
            }
        }
    }
    merge_byte_ranges(ranges)
}

/// Returns sorted, non-overlapping UTF-8 byte ranges for inline test modules/functions
/// (e.g. Rust `#[cfg(test)] mod ...` / `#[test] fn ...`, Python `def test_*` / `class Test*`).
pub fn collect_test_block_ranges(source: &str, ext: &str) -> Vec<(usize, usize)> {
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
    let ext_low = ext.to_ascii_lowercase();
    let mut ranges = Vec::new();
    let mut stack = vec![tree.root_node()];

    if ext_low == "rs" {
        while let Some(node) = stack.pop() {
            let mut cur = node.walk();
            let mut pending_test_attr_start: Option<usize> = None;
            for ch in node.children(&mut cur) {
                match ch.kind() {
                    "attribute_item" => {
                        let txt = node_text(ch, src);
                        let compact: String = txt.chars().filter(|c| !c.is_whitespace()).collect();
                        if compact.contains("cfg(test)")
                            || compact.contains("#[test]")
                            || compact.contains("::test]")
                        {
                            pending_test_attr_start.get_or_insert(ch.start_byte());
                        } else if pending_test_attr_start.is_none() {
                            // Keep unrelated attributes clear unless chained onto an active test attr
                            pending_test_attr_start = None;
                        }
                    }
                    "mod_item" | "function_item" => {
                        if let Some(attr_start) = pending_test_attr_start.take() {
                            ranges.push((attr_start, ch.end_byte()));
                            continue;
                        }
                        if ch.kind() == "mod_item" {
                            stack.push(ch);
                        }
                    }
                    "line_comment" | "block_comment" => {}
                    "declaration_list" => {
                        pending_test_attr_start = None;
                        stack.push(ch);
                    }
                    _ => {
                        pending_test_attr_start = None;
                    }
                }
            }
        }
    } else if ext_low == "py" {
        while let Some(node) = stack.pop() {
            match node.kind() {
                "function_definition" => {
                    let is_test = node
                        .child_by_field_name("name")
                        .map(|n| node_text(n, src).starts_with("test_"))
                        .unwrap_or(false);
                    if is_test {
                        let s = if node.parent().map(|p| p.kind()) == Some("decorated_definition") {
                            node.parent().unwrap().start_byte()
                        } else {
                            node.start_byte()
                        };
                        ranges.push((s, node.end_byte()));
                        continue;
                    }
                }
                "class_definition" => {
                    let is_test_cls = node
                        .child_by_field_name("name")
                        .map(|n| node_text(n, src).starts_with("Test"))
                        .unwrap_or(false);
                    if is_test_cls {
                        let s = if node.parent().map(|p| p.kind()) == Some("decorated_definition") {
                            node.parent().unwrap().start_byte()
                        } else {
                            node.start_byte()
                        };
                        ranges.push((s, node.end_byte()));
                        continue;
                    }
                }
                _ => {}
            }
            let mut cur = node.walk();
            for ch in node.children(&mut cur) {
                stack.push(ch);
            }
        }
    }
    merge_byte_ranges(ranges)
}

/// Returns true when `[start, end)` falls strictly inside any sorted merged range.
pub fn range_is_covered(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    if ranges.is_empty() {
        return false;
    }
    let idx = ranges.partition_point(|&(s, _)| s <= start);
    if idx == 0 {
        return false;
    }
    let (s, e) = ranges[idx - 1];
    s <= start && end <= e
}
