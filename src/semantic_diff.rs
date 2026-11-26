use serde_json::{json, Value};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, String>;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use tree_sitter::{Node, Parser};

const SKIP_DIRS: [&str; 6] = [
    "node_modules",
    ".git",
    "dist_backup",
    "__pycache__",
    "target",
    ".venv",
];

const GUARD_KEYWORDS: [&str; 24] = [
    "origin",
    "senderFrame",
    "allowlist",
    "whitelist",
    "startsWith",
    "endsWith",
    "realpath",
    "realpathSync",
    "normalize",
    "resolve",
    "validate",
    "verify",
    "sanitize",
    "escape",
    "isSafe",
    "checkAuth",
    "hasPermission",
    "isAllowed",
    "auth",
    "token",
    "csrf",
    "hmac",
    "signature",
    "URL",
];

const SINK_KEYWORDS: [&str; 25] = [
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
    "fork",
    "eval",
    "Function",
    "executeJavaScript",
    "openExternal",
    "openPath",
    "showItemInFolder",
    "loadURL",
    "writeFile",
    "writeFileSync",
    "unlink",
    "unlinkSync",
    "rmSync",
    "readFile",
    "readFileSync",
    "dlopen",
    "innerHTML",
    "fetch",
    "createWriteStream",
];

const KNOWN_JS_NON_MANGLED: [&str; 32] = [
    "window",
    "document",
    "globalThis",
    "process",
    "Buffer",
    "require",
    "module",
    "exports",
    "Promise",
    "Array",
    "Object",
    "String",
    "Number",
    "Boolean",
    "Error",
    "URL",
    "RegExp",
    "JSON",
    "Math",
    "console",
    "fetch",
    "ipcMain",
    "ipcRenderer",
    "contextBridge",
    "app",
    "shell",
    "dialog",
    "fs",
    "path",
    "child_process",
    "eval",
    "Function",
];

#[derive(Debug, Clone)]
struct FnFeature {
    key: String,
    display_name: String,
    line: usize,
    ast_hash: String,
    branch_count: usize,
    guards: BTreeSet<String>,
    sinks: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct JsSemanticDiffEntry {
    file: String,
    fn_name: String,
    status: String,
    severity: String,
    old_line: Option<usize>,
    new_line: Option<usize>,
    added_guards: Vec<String>,
    removed_guards: Vec<String>,
    added_sinks: Vec<String>,
    removed_sinks: Vec<String>,
    branch_delta: isize,
}

pub fn is_js_or_ts_path(name: &str) -> bool {
    js_lang_for_name(name).is_some()
}

fn js_lang_for_name(name: &str) -> Option<tree_sitter::Language> {
    let low = name.to_ascii_lowercase();
    if low.ends_with(".tsx") {
        Some(tree_sitter_typescript::LANGUAGE_TSX.into())
    } else if low.ends_with(".ts") || low.ends_with(".mts") || low.ends_with(".cts") {
        Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
    } else if low.ends_with(".js")
        || low.ends_with(".mjs")
        || low.ends_with(".cjs")
        || low.ends_with(".jsx")
    {
        Some(tree_sitter_javascript::LANGUAGE.into())
    } else {
        None
    }
}

/// Normalize webpack/vite chunk hashes in relative asset paths so builds with changed
/// content hashes still align across versions (e.g. `main.8a9f12c4.js` -> `main.<hash>.js`).
pub fn normalize_chunk_path(rel: &str) -> String {
    let clean = rel.replace('\\', "/");
    let parts: Vec<&str> = clean.split('/').collect();
    let last_idx = parts.len().saturating_sub(1);
    let norm_parts: Vec<String> = parts
        .iter()
        .enumerate()
        .map(|(idx, seg)| {
            if idx == last_idx {
                normalize_hashed_filename(seg)
            } else {
                (*seg).to_string()
            }
        })
        .collect();
    norm_parts.join("/")
}

fn normalize_hashed_filename(name: &str) -> String {
    let tokens: Vec<&str> = name.split('.').collect();
    if tokens.len() >= 3 {
        let out: Vec<String> = tokens
            .iter()
            .enumerate()
            .map(|(i, tok)| {
                if i > 0 && i + 1 < tokens.len() && is_hex_hash_token(tok) {
                    "<hash>".to_string()
                } else {
                    strip_dash_hash_suffix(tok)
                }
            })
            .collect();
        return out.join(".");
    }
    if let Some((stem, ext)) = name.rsplit_once('.') {
        format!("{}.{}", strip_dash_hash_suffix(stem), ext)
    } else {
        name.to_string()
    }
}

fn strip_dash_hash_suffix(stem: &str) -> String {
    for sep in ['-', '_'] {
        if let Some((head, tail)) = stem.rsplit_once(sep) {
            if !head.is_empty() && is_hex_hash_token(tail) {
                return format!("{head}{sep}<hash>");
            }
        }
    }
    stem.to_string()
}

fn is_hex_hash_token(tok: &str) -> bool {
    tok.len() >= 6
        && tok.len() <= 40
        && tok.bytes().all(|b| b.is_ascii_hexdigit())
        && tok.bytes().any(|b| b.is_ascii_digit())
}

fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn unquote_js_str(raw: &str) -> String {
    let t = raw.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"'))
            || (t.starts_with('\'') && t.ends_with('\''))
            || (t.starts_with('`') && t.ends_with('`')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

fn should_alpha_rename_ident(name: &str) -> bool {
    if KNOWN_JS_NON_MANGLED.contains(&name)
        || GUARD_KEYWORDS.contains(&name)
        || SINK_KEYWORDS.contains(&name)
    {
        return false;
    }
    if name.starts_with("_0x") || name.starts_with("__webpack") {
        return true;
    }
    // Single/two-char identifiers and `_x` style minifier names are alpha-renamed;
    // longer domain names stay intact so genuine symbol renames show up if desired.
    name.len() <= 2
}

struct AstNormalizer<'a> {
    src: &'a [u8],
    renames: HashMap<String, String>,
    next_id: usize,
    tokens: Vec<String>,
    branch_count: usize,
    guards: BTreeSet<String>,
    sinks: BTreeSet<String>,
    calls: BTreeSet<String>,
}

impl<'a> AstNormalizer<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            renames: HashMap::new(),
            next_id: 0,
            tokens: Vec::new(),
            branch_count: 0,
            guards: BTreeSet::new(),
            sinks: BTreeSet::new(),
            calls: BTreeSet::new(),
        }
    }

    fn map_ident(&mut self, raw: &str) -> String {
        if !should_alpha_rename_ident(raw) {
            return raw.to_string();
        }
        if let Some(existing) = self.renames.get(raw) {
            return existing.clone();
        }
        let assigned = format!("$v{}", self.next_id);
        self.next_id += 1;
        self.renames.insert(raw.to_string(), assigned.clone());
        assigned
    }

    fn record_keyword_hits(&mut self, text: &str) {
        for kw in GUARD_KEYWORDS {
            if text == kw || text.contains(kw) {
                self.guards.insert(kw.to_string());
            }
        }
        for sk in SINK_KEYWORDS {
            if text == sk || text.ends_with(&format!(".{sk}")) {
                self.sinks.insert(sk.to_string());
            }
        }
    }

    fn visit(&mut self, node: Node) {
        let kind = node.kind();
        match kind {
            "comment" => return,
            "if_statement" | "conditional_expression" | "switch_case" | "throw_statement" => {
                self.branch_count += 1;
                self.tokens.push(format!("({kind}"));
            }
            "identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern" => {
                let raw = node_text(node, self.src);
                self.record_keyword_hits(raw);
                let norm = self.map_ident(raw);
                self.tokens.push(format!("id:{norm}"));
                return;
            }
            "property_identifier" => {
                let raw = node_text(node, self.src);
                self.record_keyword_hits(raw);
                self.tokens.push(format!("prop:{raw}"));
                return;
            }
            "string" | "template_string" => {
                let raw = unquote_js_str(node_text(node, self.src));
                if raw.contains("..") {
                    self.guards.insert("traversal_dotdot".to_string());
                }
                self.record_keyword_hits(&raw);
                self.tokens.push(format!("str:{raw}"));
                return;
            }
            "number" => {
                let raw = node_text(node, self.src);
                self.tokens.push(format!("num:{raw}"));
                return;
            }
            "call_expression" => {
                if let Some(callee) = node.child_by_field_name("function") {
                    let c_txt = node_text(callee, self.src).trim();
                    let short = c_txt.rsplit('.').next().unwrap_or(c_txt);
                    if !short.is_empty() && short.len() <= 48 {
                        self.calls.insert(short.to_string());
                    }
                    self.record_keyword_hits(c_txt);
                }
                self.tokens.push("(call".to_string());
            }
            "formal_parameters" => {
                // Pre-register parameter identifiers left-to-right so parameter alpha-renaming
                // stays canonical regardless of body order.
                let mut cur = node.walk();
                for ch in node.named_children(&mut cur) {
                    if ch.kind() == "identifier" {
                        let raw = node_text(ch, self.src);
                        let _ = self.map_ident(raw);
                    }
                }
                self.tokens.push("(params".to_string());
            }
            _ => {
                if node.is_named() {
                    self.tokens.push(format!("({kind}"));
                } else {
                    let lit = node_text(node, self.src).trim();
                    if !lit.is_empty() && lit != ";" {
                        self.tokens.push(lit.to_string());
                    }
                    return;
                }
            }
        }

        let mut cur = node.walk();
        for ch in node.children(&mut cur) {
            self.visit(ch);
        }
        if node.is_named() {
            self.tokens.push(")".to_string());
        }
    }
}

fn hash_tokens(tokens: &[String]) -> String {
    let mut h = Sha256::new();
    for tok in tokens {
        h.update(tok.as_bytes());
        h.update(b"\x1f");
    }
    h.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn summarize_node_feature(node: Node, src: &[u8], key: String, display_name: String) -> FnFeature {
    let mut norm = AstNormalizer::new(src);
    norm.visit(node);
    let ast_hash = hash_tokens(&norm.tokens);
    FnFeature {
        key,
        display_name,
        line: node.start_position().row + 1,
        ast_hash,
        branch_count: norm.branch_count,
        guards: norm.guards,
        sinks: norm.sinks,
    }
}

fn extract_js_functions(src: &[u8], lang_hint: &str) -> Vec<FnFeature> {
    let Some(lang) = js_lang_for_name(lang_hint) else {
        return Vec::new();
    };
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(src, None) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut seen_keys = HashMap::<String, usize>::new();
    let mut stack = vec![tree.root_node()];

    while let Some(n) = stack.pop() {
        match n.kind() {
            "function_declaration" => {
                if let Some(nm) = n.child_by_field_name("name") {
                    let raw = node_text(nm, src).trim().to_string();
                    if !raw.is_empty() {
                        let count = seen_keys.entry(raw.clone()).or_insert(0);
                        *count += 1;
                        let key = if *count == 1 {
                            raw.clone()
                        } else {
                            format!("{raw}#{}", *count)
                        };
                        out.push(summarize_node_feature(n, src, key, raw));
                        continue;
                    }
                }
            }
            "method_definition" => {
                if let Some(nm) = n.child_by_field_name("name") {
                    let raw = unquote_js_str(node_text(nm, src));
                    if !raw.is_empty() {
                        let count = seen_keys.entry(raw.clone()).or_insert(0);
                        *count += 1;
                        let key = if *count == 1 {
                            format!("method:{raw}")
                        } else {
                            format!("method:{raw}#{}", *count)
                        };
                        out.push(summarize_node_feature(n, src, key, raw));
                        continue;
                    }
                }
            }
            "variable_declarator" => {
                if let (Some(nm), Some(val)) = (
                    n.child_by_field_name("name"),
                    n.child_by_field_name("value"),
                ) {
                    if matches!(
                        val.kind(),
                        "arrow_function" | "function_expression" | "function"
                    ) {
                        let raw = node_text(nm, src).trim().to_string();
                        if !raw.is_empty() {
                            let count = seen_keys.entry(raw.clone()).or_insert(0);
                            *count += 1;
                            let key = if *count == 1 {
                                raw.clone()
                            } else {
                                format!("{raw}#{}", *count)
                            };
                            out.push(summarize_node_feature(val, src, key, raw));
                            continue;
                        }
                    }
                }
            }
            "call_expression" => {
                // Anchor IPC handlers and Express/Fastify routes by literal channel/route string
                // so bundled/minified anonymous callbacks still align reliably across versions.
                if let (Some(callee), Some(args)) = (
                    n.child_by_field_name("function"),
                    n.child_by_field_name("arguments"),
                ) {
                    let c_txt = node_text(callee, src).trim();
                    let short = c_txt.rsplit('.').next().unwrap_or(c_txt);
                    if matches!(
                        short,
                        "handle" | "handleOnce" | "on" | "get" | "post" | "put" | "delete" | "use"
                    ) {
                        let mut acur = args.walk();
                        let named: Vec<Node> = args.named_children(&mut acur).collect();
                        if named.len() >= 2
                            && matches!(named[0].kind(), "string" | "template_string")
                            && matches!(
                                named[1].kind(),
                                "arrow_function" | "function_expression" | "function"
                            )
                        {
                            let ch = unquote_js_str(node_text(named[0], src));
                            let base_key = format!("handler:{short}:{ch}");
                            let count = seen_keys.entry(base_key.clone()).or_insert(0);
                            *count += 1;
                            let key = if *count == 1 {
                                base_key
                            } else {
                                format!("handler:{short}:{ch}#{}", *count)
                            };
                            out.push(summarize_node_feature(
                                named[1],
                                src,
                                key,
                                format!("{short}(\"{ch}\")"),
                            ));
                            continue;
                        }
                    }
                }
            }
            _ => {}
        }

        let mut cur = n.walk();
        let children: Vec<Node> = n.children(&mut cur).collect();
        for ch in children.into_iter().rev() {
            stack.push(ch);
        }
    }

    if out.is_empty() && !src.is_empty() {
        out.push(summarize_node_feature(
            tree.root_node(),
            src,
            "<module>".to_string(),
            "<module>".to_string(),
        ));
    }
    out
}

fn diff_js_pair(
    file_label: &str,
    old_src: &[u8],
    new_src: &[u8],
    lang_hint: &str,
) -> (Vec<JsSemanticDiffEntry>, usize) {
    let old_fns = extract_js_functions(old_src, lang_hint);
    let new_fns = extract_js_functions(new_src, lang_hint);

    let mut old_map: BTreeMap<String, FnFeature> = BTreeMap::new();
    for f in old_fns {
        old_map.insert(f.key.clone(), f);
    }
    let mut new_map: BTreeMap<String, FnFeature> = BTreeMap::new();
    for f in new_fns {
        new_map.insert(f.key.clone(), f);
    }

    let mut unchanged_norm_count = 0usize;
    let mut diffs = Vec::new();

    for (k, nf) in &new_map {
        match old_map.get(k) {
            None => {
                let sev = if !nf.sinks.is_empty() && nf.guards.is_empty() {
                    "HIGH"
                } else if !nf.sinks.is_empty() {
                    "MEDIUM"
                } else {
                    "INFO"
                };
                diffs.push(JsSemanticDiffEntry {
                    file: file_label.to_string(),
                    fn_name: nf.display_name.clone(),
                    status: "FN_ADDED".to_string(),
                    severity: sev.to_string(),
                    old_line: None,
                    new_line: Some(nf.line),
                    added_guards: nf.guards.iter().cloned().collect(),
                    removed_guards: Vec::new(),
                    added_sinks: nf.sinks.iter().cloned().collect(),
                    removed_sinks: Vec::new(),
                    branch_delta: nf.branch_count as isize,
                });
            }
            Some(of) => {
                if of.ast_hash == nf.ast_hash {
                    unchanged_norm_count += 1;
                    continue;
                }
                let added_guards: Vec<String> = nf.guards.difference(&of.guards).cloned().collect();
                let removed_guards: Vec<String> =
                    of.guards.difference(&nf.guards).cloned().collect();
                let added_sinks: Vec<String> = nf.sinks.difference(&of.sinks).cloned().collect();
                let removed_sinks: Vec<String> = of.sinks.difference(&nf.sinks).cloned().collect();
                let branch_delta = nf.branch_count as isize - of.branch_count as isize;

                let (status, severity) = if !removed_guards.is_empty()
                    || (branch_delta < 0 && !nf.sinks.is_empty())
                {
                    ("GUARD_REMOVED", "HIGH")
                } else if !added_guards.is_empty() || (branch_delta > 0 && !nf.sinks.is_empty()) {
                    ("GUARD_ADDED", "INFO")
                } else if !added_sinks.is_empty() {
                    ("SINK_ADDED", "MEDIUM")
                } else {
                    ("LOGIC_CHANGED", "LOW")
                };

                diffs.push(JsSemanticDiffEntry {
                    file: file_label.to_string(),
                    fn_name: nf.display_name.clone(),
                    status: status.to_string(),
                    severity: severity.to_string(),
                    old_line: Some(of.line),
                    new_line: Some(nf.line),
                    added_guards,
                    removed_guards,
                    added_sinks,
                    removed_sinks,
                    branch_delta,
                });
            }
        }
    }

    for (k, of) in &old_map {
        if !new_map.contains_key(k) {
            diffs.push(JsSemanticDiffEntry {
                file: file_label.to_string(),
                fn_name: of.display_name.clone(),
                status: "FN_REMOVED".to_string(),
                severity: "INFO".to_string(),
                old_line: Some(of.line),
                new_line: None,
                added_guards: Vec::new(),
                removed_guards: of.guards.iter().cloned().collect(),
                added_sinks: Vec::new(),
                removed_sinks: of.sinks.iter().cloned().collect(),
                branch_delta: -(of.branch_count as isize),
            });
        }
    }

    (diffs, unchanged_norm_count)
}

fn format_js_semantic_both(
    kind_label: &str,
    old_label: &str,
    new_label: &str,
    diffs: &[JsSemanticDiffEntry],
    unchanged_fns: usize,
    matched_files: usize,
) -> (String, Value) {
    let jv = json!({
        "ok": true,
        "format": "semantic-diff",
        "kind": kind_label,
        "old": old_label,
        "new": new_label,
        "matched_files": matched_files,
        "unchanged_normalized_functions": unchanged_fns,
        "changed_entries": diffs.iter().map(|d| json!({
            "file": d.file,
            "function": d.fn_name,
            "status": d.status,
            "severity": d.severity,
            "old_line": d.old_line,
            "new_line": d.new_line,
            "added_guards": d.added_guards,
            "removed_guards": d.removed_guards,
            "added_sinks": d.added_sinks,
            "removed_sinks": d.removed_sinks,
            "branch_delta": d.branch_delta,
        })).collect::<Vec<_>>(),
    });

    let mut md = vec![
        format!("# Semantic Patch-Diff (`{kind_label}`)"),
        String::new(),
        format!("- Old: `{old_label}`"),
        format!("- New: `{new_label}`"),
        format!("- Files compared: `{matched_files}` | Unchanged after AST/hash normalization: `{unchanged_fns}` function(s) | Semantic deltas: `{}`", diffs.len()),
        String::new(),
    ];

    if diffs.is_empty() {
        md.push("_No semantic security or control-flow deltas detected (all differences normalized out as chunk hashes or mangled identifiers)._".to_string());
        return (md.join("\n"), jv);
    }

    md.push("| Severity | Status | File | Function | Guard / Sink / Branch Delta |".to_string());
    md.push("|---|---|---|---|---|".to_string());
    for d in diffs.iter().take(120) {
        let mut details = Vec::new();
        if !d.added_guards.is_empty() {
            details.push(format!("+guard:[{}]", d.added_guards.join(",")));
        }
        if !d.removed_guards.is_empty() {
            details.push(format!("-guard:[{}]", d.removed_guards.join(",")));
        }
        if !d.added_sinks.is_empty() {
            details.push(format!("+sink:[{}]", d.added_sinks.join(",")));
        }
        if !d.removed_sinks.is_empty() {
            details.push(format!("-sink:[{}]", d.removed_sinks.join(",")));
        }
        if d.branch_delta != 0 {
            details.push(format!("branches:{:+}", d.branch_delta));
        }
        if details.is_empty() {
            details.push("AST structure changed".to_string());
        }
        let loc = match (d.old_line, d.new_line) {
            (Some(ol), Some(nl)) => format!("{} (L{}->L{})", d.fn_name, ol, nl),
            (None, Some(nl)) => format!("{} (L{})", d.fn_name, nl),
            (Some(ol), None) => format!("{} (L{})", d.fn_name, ol),
            _ => d.fn_name.clone(),
        };
        md.push(format!(
            "| `{}` | `{}` | `{}` | `{}` | {} |",
            d.severity,
            d.status,
            d.file,
            loc,
            details.join("; ")
        ));
    }
    if diffs.len() > 120 {
        md.push(format!(
            "\n_... {} more semantic deltas omitted._",
            diffs.len() - 120
        ));
    }
    (md.join("\n"), jv)
}

fn load_asar_js_map(path: &Path) -> Result<BTreeMap<String, (String, Vec<u8>)>> {
    let mut r = BufReader::new(fs::File::open(path).map_err(|e| e.to_string())?);
    let (base, entries) = crate::binary::parse_asar_index_reader(&mut r)
        .map_err(|e| format!("ASAR parse error for `{}`: {e}", path.display()))?;
    let mut map = BTreeMap::new();
    for ent in entries {
        if ent.unpacked || ent.size == 0 || ent.size > 4 * 1024 * 1024 {
            continue;
        }
        if !is_js_or_ts_path(&ent.path) {
            continue;
        }
        let pos = (base as u64)
            .checked_add(ent.offset as u64)
            .ok_or_else(|| "ASAR offset overflow".to_string())?;
        r.seek(SeekFrom::Start(pos)).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; ent.size];
        r.read_exact(&mut buf).map_err(|e| e.to_string())?;
        let norm = normalize_chunk_path(&ent.path);
        map.insert(norm, (ent.path, buf));
    }
    Ok(map)
}

fn collect_dir_js_map(root: &Path) -> Result<BTreeMap<String, (String, Vec<u8>)>> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, (String, Vec<u8>)>) {
        if out.len() >= 400 {
            return;
        }
        let Ok(rd) = fs::read_dir(dir) else {
            return;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let nm = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if p.is_dir() {
                if !SKIP_DIRS.contains(&nm) {
                    walk(&p, root, out);
                }
            } else if p.is_file() && is_js_or_ts_path(nm) {
                if let Ok(md) = p.metadata() {
                    if md.len() > 0 && md.len() <= 4 * 1024 * 1024 {
                        if let Ok(bytes) = fs::read(&p) {
                            let rel = p
                                .strip_prefix(root)
                                .unwrap_or(&p)
                                .to_string_lossy()
                                .replace('\\', "/");
                            let norm = normalize_chunk_path(&rel);
                            out.insert(norm, (rel, bytes));
                        }
                    }
                }
            }
        }
    }
    let mut map = BTreeMap::new();
    walk(root, root, &mut map);
    Ok(map)
}

fn diff_js_collections_both(
    kind_label: &str,
    old_label: &str,
    new_label: &str,
    old_map: BTreeMap<String, (String, Vec<u8>)>,
    new_map: BTreeMap<String, (String, Vec<u8>)>,
) -> (String, Value) {
    let mut all_diffs = Vec::new();
    let mut unchanged_fns = 0usize;
    let mut matched_files = 0usize;

    let keys: BTreeSet<String> = old_map.keys().chain(new_map.keys()).cloned().collect();
    for k in keys {
        match (old_map.get(&k), new_map.get(&k)) {
            (Some((_op, ob)), Some((np, nb))) => {
                matched_files += 1;
                if ob == nb {
                    unchanged_fns += 1;
                    continue;
                }
                let (mut d, unc) = diff_js_pair(np, ob, nb, np);
                unchanged_fns += unc;
                all_diffs.append(&mut d);
            }
            (None, Some((np, nb))) => {
                matched_files += 1;
                let (mut d, _) = diff_js_pair(np, b"", nb, np);
                all_diffs.append(&mut d);
            }
            (Some((op, ob)), None) => {
                matched_files += 1;
                let (mut d, _) = diff_js_pair(op, ob, b"", op);
                all_diffs.append(&mut d);
            }
            (None, None) => {}
        }
    }
    format_js_semantic_both(
        kind_label,
        old_label,
        new_label,
        &all_diffs,
        unchanged_fns,
        matched_files,
    )
}

#[derive(Debug, Clone)]
struct NativeFnSig {
    rva: u32,
    anchor_id: String,
    calls: usize,
    branches: usize,
    imports: BTreeSet<String>,
    strings: BTreeSet<String>,
}

fn is_security_native_api(name: &str) -> bool {
    const PATTERNS: [&str; 22] = [
        "ProbeForRead",
        "ProbeForWrite",
        "SeSinglePrivilegeCheck",
        "SeAccessCheck",
        "CheckTokenMembership",
        "RtlCopyMemory",
        "RtlZeroMemory",
        "ExAllocatePool",
        "IoCreateDevice",
        "CreateProcess",
        "ShellExecute",
        "VirtualProtect",
        "HeapAlloc",
        "memcpy",
        "memmove",
        "strcpy",
        "strncpy",
        "sprintf",
        "snprintf",
        "SafeInt",
        "Impersonate",
        "AccessCheck",
    ];
    PATTERNS.iter().any(|p| name.contains(p))
}

fn extract_pe64_ascii_strings(bytes: &[u8], pe: &crate::binary::PeContext) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for sec in &pe.secs {
        // Skip executable code unless small/readonly, focus on data/rdata/text constants
        let start = sec.raw_ptr as usize;
        let len = (sec.raw_size as usize).min(bytes.len().saturating_sub(start));
        if len < 5 {
            continue;
        }
        let slice = &bytes[start..start + len];
        let mut i = 0usize;
        while i < slice.len() {
            if slice[i].is_ascii_graphic() || slice[i] == b' ' {
                let s0 = i;
                while i < slice.len()
                    && (slice[i].is_ascii_graphic() || slice[i] == b' ')
                    && i - s0 < 160
                {
                    i += 1;
                }
                if i - s0 >= 5 && slice.get(i) == Some(&0) {
                    if let Some((rva, _)) = crate::binary::file_offset_to_rva(start + s0, &pe.secs)
                    {
                        if let Ok(s) = std::str::from_utf8(&slice[s0..i]) {
                            out.push((rva, s.to_string()));
                        }
                    }
                }
            }
            i += 1;
            if out.len() >= 4000 {
                return out;
            }
        }
    }
    out
}

fn build_pe64_fn_signatures(bytes: &[u8]) -> Result<(Vec<NativeFnSig>, BTreeSet<String>)> {
    let pe_off = crate::binary::read_u32_le(bytes, 0x3C)
        .ok_or_else(|| "missing PE header offset".to_string())? as usize;
    let mut info_lines = Vec::new();
    let pe = crate::binary::parse_pe_details(bytes, pe_off, &mut info_lines);
    let exports = crate::binary::extract_pe_exports_set(bytes);
    if !pe.is_pe64 {
        return Ok((Vec::new(), exports));
    }

    let pdata = crate::binary::extract_pe64_pdata_ranges(bytes, pe_off, &pe.secs);
    let strings = extract_pe64_ascii_strings(bytes, &pe);
    let mut str_lookup: HashMap<u32, String> = HashMap::new();
    for (rva, s) in strings {
        str_lookup.insert(rva, s);
    }
    let mut iat_lookup: HashMap<u32, String> = HashMap::new();
    for (rva, name) in &pe.iat_map {
        iat_lookup.insert(*rva, name.clone());
    }

    // Fallback: if no .pdata entries (e.g. tiny synthetic PE without Exception dir), treat executable
    // sections as single normalized code windows so CFG/XRef summary still works.
    let ranges: Vec<(u32, u32)> = if !pdata.is_empty() {
        pdata
    } else {
        pe.secs
            .iter()
            .filter(|s| s.chars & 0x2000_0000 != 0 && s.raw_size > 0)
            .map(|s| (s.vaddr, s.vaddr.saturating_add(s.raw_size)))
            .collect()
    };

    let mut sigs = Vec::new();
    for (idx, (start_rva, end_rva)) in ranges.into_iter().take(600).enumerate() {
        let Some(start_off) = crate::binary::rva_to_file_offset(start_rva, &pe.secs) else {
            continue;
        };
        let fn_len = (end_rva.saturating_sub(start_rva) as usize).min(16 * 1024);
        let Some(code) = bytes.get(start_off..start_off.saturating_add(fn_len)) else {
            continue;
        };

        let mut calls = 0usize;
        let mut branches = 0usize;
        let mut insn_count = 0usize;
        let mut imports = BTreeSet::new();
        let mut fn_strings = BTreeSet::new();

        // Scan x86-64 instructions + RIP-relative references to IAT/strings.
        let mut pos = 0usize;
        while pos < code.len() && insn_count < 2000 {
            // Detect 0xFF 0x15 disp32 (call [rip+disp32]) and 0x48/0x4C 0x8D disp32 (lea r, [rip+disp32])
            if pos + 6 <= code.len() && code[pos] == 0xFF && code[pos + 1] == 0x15 {
                let disp = i32::from_le_bytes([
                    code[pos + 2],
                    code[pos + 3],
                    code[pos + 4],
                    code[pos + 5],
                ]);
                let target_rva = (start_rva as i64 + pos as i64 + 6 + disp as i64) as u32;
                if let Some(imp) = iat_lookup.get(&target_rva) {
                    imports.insert(imp.clone());
                }
                calls += 1;
            }
            if pos + 7 <= code.len()
                && (code[pos] == 0x48 || code[pos] == 0x4C)
                && code[pos + 1] == 0x8D
                && (code[pos + 2] & 0xC7) == 0x05
            {
                let disp = i32::from_le_bytes([
                    code[pos + 3],
                    code[pos + 4],
                    code[pos + 5],
                    code[pos + 6],
                ]);
                let target_rva = (start_rva as i64 + pos as i64 + 7 + disp as i64) as u32;
                if let Some(st) = str_lookup.get(&target_rva) {
                    fn_strings.insert(st.clone());
                }
            }

            match crate::binary::decode_x86_insn(code, pos, true) {
                Some(dec) if dec.len > 0 => {
                    insn_count += 1;
                    match dec.kind {
                        crate::binary::X86InsnKind::Call => calls += 1,
                        crate::binary::X86InsnKind::Jcc
                        | crate::binary::X86InsnKind::Jne { .. } => branches += 1,
                        _ => {}
                    }
                    pos += dec.len;
                }
                _ => pos += 1,
            }
        }

        let anchor_id = if let Some(first_str) = fn_strings.iter().next() {
            format!("str:{first_str}")
        } else if !imports.is_empty() {
            let imps: Vec<&str> = imports.iter().take(3).map(|s| s.as_str()).collect();
            format!("iat:{}", imps.join("+"))
        } else {
            format!("fn#{idx}")
        };

        sigs.push(NativeFnSig {
            rva: start_rva,
            anchor_id,
            calls,
            branches,
            imports,
            strings: fn_strings,
        });
    }

    Ok((sigs, exports))
}

fn diff_native_semantic_files_both(
    old_path: &Path,
    new_path: &Path,
    old_bytes: &[u8],
    new_bytes: &[u8],
) -> Result<(String, Value)> {
    let old_label = old_path.display().to_string();
    let new_label = new_path.display().to_string();

    if old_bytes.starts_with(b"MZ") && new_bytes.starts_with(b"MZ") {
        let (old_fns, old_exp) = build_pe64_fn_signatures(old_bytes)?;
        let (new_fns, new_exp) = build_pe64_fn_signatures(new_bytes)?;

        let added_exports: Vec<String> = new_exp.difference(&old_exp).cloned().collect();
        let removed_exports: Vec<String> = old_exp.difference(&new_exp).cloned().collect();

        let mut old_by_anchor: BTreeMap<String, Vec<NativeFnSig>> = BTreeMap::new();
        for f in old_fns {
            old_by_anchor
                .entry(f.anchor_id.clone())
                .or_default()
                .push(f);
        }
        let mut new_by_anchor: BTreeMap<String, Vec<NativeFnSig>> = BTreeMap::new();
        for f in new_fns {
            new_by_anchor
                .entry(f.anchor_id.clone())
                .or_default()
                .push(f);
        }

        let mut deltas = Vec::new();
        let mut unchanged = 0usize;
        for (anchor, new_list) in &new_by_anchor {
            if let Some(old_list) = old_by_anchor.get(anchor) {
                for (of, nf) in old_list.iter().zip(new_list.iter()) {
                    let add_imp: Vec<String> =
                        nf.imports.difference(&of.imports).cloned().collect();
                    let rem_imp: Vec<String> =
                        of.imports.difference(&nf.imports).cloned().collect();
                    let add_str: Vec<String> =
                        nf.strings.difference(&of.strings).cloned().collect();
                    let rem_str: Vec<String> =
                        of.strings.difference(&nf.strings).cloned().collect();
                    let br_delta = nf.branches as isize - of.branches as isize;
                    let call_delta = nf.calls as isize - of.calls as isize;

                    if add_imp.is_empty()
                        && rem_imp.is_empty()
                        && add_str.is_empty()
                        && rem_str.is_empty()
                        && br_delta == 0
                        && call_delta == 0
                    {
                        unchanged += 1;
                        continue;
                    }

                    let sec_added = add_imp.iter().any(|i| is_security_native_api(i));
                    let sec_removed = rem_imp.iter().any(|i| is_security_native_api(i));
                    let status = if sec_removed {
                        "SECURITY_IMPORT_REMOVED"
                    } else if sec_added {
                        "SECURITY_IMPORT_ADDED"
                    } else if br_delta > 0 {
                        "CFG_CHECKS_ADDED"
                    } else if br_delta < 0 {
                        "CFG_CHECKS_REMOVED"
                    } else {
                        "CFG_IAT_CHANGED"
                    };

                    deltas.push(json!({
                        "anchor": anchor,
                        "old_rva": format!("0x{:x}", of.rva),
                        "new_rva": format!("0x{:x}", nf.rva),
                        "status": status,
                        "branch_delta": br_delta,
                        "call_delta": call_delta,
                        "added_imports": add_imp,
                        "removed_imports": rem_imp,
                        "added_strings": add_str,
                        "removed_strings": rem_str,
                    }));
                }
            } else {
                for nf in new_list {
                    deltas.push(json!({
                        "anchor": anchor,
                        "old_rva": Value::Null,
                        "new_rva": format!("0x{:x}", nf.rva),
                        "status": "FN_ADDED",
                        "branch_delta": nf.branches,
                        "call_delta": nf.calls,
                        "added_imports": nf.imports.iter().cloned().collect::<Vec<_>>(),
                        "removed_imports": [],
                        "added_strings": nf.strings.iter().cloned().collect::<Vec<_>>(),
                        "removed_strings": [],
                    }));
                }
            }
        }

        let jv = json!({
            "ok": true,
            "format": "semantic-diff",
            "kind": "pe64-semantic",
            "old": old_label,
            "new": new_label,
            "added_exports": added_exports,
            "removed_exports": removed_exports,
            "unchanged_normalized_functions": unchanged,
            "function_deltas": deltas,
        });

        let mut md = vec![
            "# Semantic Patch-Diff (`PE64`)".to_string(),
            String::new(),
            format!("- Old: `{old_label}`"),
            format!("- New: `{new_label}`"),
            format!("- Exports: +{} / -{} | Unchanged functions (normalized): `{unchanged}` | Deltas: `{}`", added_exports.len(), removed_exports.len(), deltas.len()),
            String::new(),
        ];
        if !added_exports.is_empty() {
            md.push(format!(
                "- Added exports: {}",
                added_exports
                    .iter()
                    .take(20)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !removed_exports.is_empty() {
            md.push(format!(
                "- Removed exports: {}",
                removed_exports
                    .iter()
                    .take(20)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !deltas.is_empty() {
            md.push(String::new());
            md.push("| Anchor | Status | Old->New RVA | Delta Summary |".to_string());
            md.push("|---|---|---|---|".to_string());
            for d in deltas.iter().take(80) {
                let anchor = d["anchor"].as_str().unwrap_or("");
                let status = d["status"].as_str().unwrap_or("");
                let rva_span = format!(
                    "{} -> {}",
                    d["old_rva"].as_str().unwrap_or("-"),
                    d["new_rva"].as_str().unwrap_or("-")
                );
                let mut parts = Vec::new();
                if let Some(bd) = d["branch_delta"].as_i64().filter(|x| *x != 0) {
                    parts.push(format!("branches:{bd:+}"));
                }
                if let Some(cd) = d["call_delta"].as_i64().filter(|x| *x != 0) {
                    parts.push(format!("calls:{cd:+}"));
                }
                if let Some(ai) = d["added_imports"].as_array().filter(|a| !a.is_empty()) {
                    let s: Vec<&str> = ai.iter().filter_map(Value::as_str).collect();
                    parts.push(format!("+iat:[{}]", s.join(",")));
                }
                if let Some(ri) = d["removed_imports"].as_array().filter(|a| !a.is_empty()) {
                    let s: Vec<&str> = ri.iter().filter_map(Value::as_str).collect();
                    parts.push(format!("-iat:[{}]", s.join(",")));
                }
                if let Some(astr) = d["added_strings"].as_array().filter(|a| !a.is_empty()) {
                    let s: Vec<&str> = astr.iter().filter_map(Value::as_str).take(3).collect();
                    parts.push(format!("+str:[{}]", s.join(",")));
                }
                md.push(format!(
                    "| `{anchor}` | `{status}` | `{rva_span}` | {} |",
                    parts.join("; ")
                ));
            }
        }
        return Ok((md.join("\n"), jv));
    }

    if old_bytes.starts_with(b"\x7FELF") && new_bytes.starts_with(b"\x7FELF") {
        let old_syms = crate::binary::extract_elf_dynsyms_set(old_bytes);
        let new_syms = crate::binary::extract_elf_dynsyms_set(new_bytes);
        let added: Vec<String> = new_syms.difference(&old_syms).cloned().collect();
        let removed: Vec<String> = old_syms.difference(&new_syms).cloned().collect();
        let jv = json!({
            "ok": true,
            "format": "semantic-diff",
            "kind": "elf-semantic",
            "old": old_label,
            "new": new_label,
            "added_dynsyms": added,
            "removed_dynsyms": removed,
            "unchanged_dynsyms": old_syms.intersection(&new_syms).count(),
        });
        let md = format!(
            "# Semantic Patch-Diff (`ELF`)\n\n- Old: `{old_label}`\n- New: `{new_label}`\n- Unchanged `.dynsym`: `{}`\n- Added `.dynsym` ({}): {}\n- Removed `.dynsym` ({}): {}",
            old_syms.intersection(&new_syms).count(),
            added.len(),
            added.iter().take(30).cloned().collect::<Vec<_>>().join(", "),
            removed.len(),
            removed.iter().take(30).cloned().collect::<Vec<_>>().join(", "),
        );
        return Ok((md, jv));
    }

    Err(
        "semantic diff expects JS/TS files, ASAR archives, directories, or PE/ELF binaries"
            .to_string(),
    )
}

pub fn diff_semantic_paths_both(old_path: &Path, new_path: &Path) -> Result<(String, Value)> {
    if old_path.is_dir() && new_path.is_dir() {
        let om = collect_dir_js_map(old_path)?;
        let nm = collect_dir_js_map(new_path)?;
        return Ok(diff_js_collections_both(
            "dir-js-semantic",
            &old_path.display().to_string(),
            &new_path.display().to_string(),
            om,
            nm,
        ));
    }

    let ext_old = old_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let ext_new = new_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if ext_old == "asar" && ext_new == "asar" {
        let om = load_asar_js_map(old_path)?;
        let nm = load_asar_js_map(new_path)?;
        return Ok(diff_js_collections_both(
            "asar-js-semantic",
            &old_path.display().to_string(),
            &new_path.display().to_string(),
            om,
            nm,
        ));
    }

    if is_js_or_ts_path(&old_path.to_string_lossy())
        && is_js_or_ts_path(&new_path.to_string_lossy())
    {
        let ob = fs::read(old_path).map_err(|e| e.to_string())?;
        let nb = fs::read(new_path).map_err(|e| e.to_string())?;
        let hint = new_path.to_string_lossy();
        let (diffs, unc) = diff_js_pair(
            new_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("file.js"),
            &ob,
            &nb,
            &hint,
        );
        return Ok(format_js_semantic_both(
            "js-ast-semantic",
            &old_path.display().to_string(),
            &new_path.display().to_string(),
            &diffs,
            unc,
            1,
        ));
    }

    let ob = fs::read(old_path).map_err(|e| e.to_string())?;
    let nb = fs::read(new_path).map_err(|e| e.to_string())?;
    diff_native_semantic_files_both(old_path, new_path, &ob, &nb)
}

#[cfg(test)]
pub fn diff_semantic_paths(old_path: &Path, new_path: &Path, as_json: bool) -> Result<String> {
    let (md, jv) = diff_semantic_paths_both(old_path, new_path)?;
    if as_json {
        serde_json::to_string_pretty(&jv).map_err(|e| e.to_string())
    } else {
        Ok(md)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_diff_ignores_chunk_hashes_and_mangled_identifiers_but_catches_guard_delta() {
        assert_eq!(
            normalize_chunk_path("dist/main.8a9f12c4.js"),
            "dist/main.<hash>.js"
        );
        assert_eq!(
            normalize_chunk_path("dist/vendor-a1b2c3d4.chunk.js"),
            "dist/vendor-<hash>.chunk.js"
        );

        let old_js = br#"
function pureHelper(e, t) {
  return e.startsWith("https://") && t > 0;
}
function handleOpen(e, t) {
  return shell.openExternal(t);
}
"#;
        // Identical pureHelper with mangled parameters (n, r) -> MUST hash identically!
        // Modified handleOpen gained origin + allowlist guard!
        let new_js = br#"
function pureHelper(n, r) {
  return n.startsWith("https://") && r > 0;
}
function handleOpen(n, r) {
  if (!r.startsWith("https://")) return false;
  return shell.openExternal(r);
}
"#;
        let (diffs, unchanged) = diff_js_pair("renderer.js", old_js, new_js, "renderer.js");
        assert_eq!(
            unchanged, 1,
            "pureHelper with renamed mangled params should normalize identically"
        );
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].fn_name, "handleOpen");
        assert_eq!(diffs[0].status, "GUARD_ADDED");
        assert!(diffs[0].added_guards.iter().any(|g| g == "startsWith"));
        assert!(diffs[0].branch_delta > 0);
    }
}
