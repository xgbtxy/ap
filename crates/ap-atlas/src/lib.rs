use clap::{Parser, Subcommand};
use ignore::WalkBuilder;
pub mod changes;
pub mod deps;
pub mod history;
pub mod impact;
pub mod locate;
pub mod product;
pub mod surface;
pub mod trace;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tree_sitter::{Node, Parser as TsParser};

pub const SKIP_DIRS: &[&str] = &[
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
    ".next",
    ".nuxt",
    ".sieve",
    ".baton",
    ".recall",
    ".guard",
    ".probe",
    ".splice",
    ".agents",
    ".claude",
    ".grok",
    ".codex",
    ".cursor",
    ".openclaw",
    ".hermes",
    "vendor",
    "coverage",
    ".idea",
    ".vscode",
];

const ENTRYPOINT_NAMES: &[&str] = &[
    "main.py",
    "app.py",
    "cli.py",
    "__main__.py",
    "server.py",
    "manage.py",
    "index.ts",
    "index.tsx",
    "index.js",
    "main.ts",
    "server.ts",
    "app.ts",
    "main.go",
    "main.rs",
    "lib.rs",
    "main.c",
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "CMakeLists.txt",
    "Makefile",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeRecord {
    pub path: String,
    pub stem: String,
    pub lines: usize,
    pub mtime: u64,
    pub dirty: bool,
    pub symbols: Vec<String>,
    pub hub_refs: usize,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocRecord {
    pub path: String,
    pub lines: usize,
    pub mtime: u64,
    pub headings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRecord {
    pub path: String,
    pub bytes: u64,
    pub mtime: u64,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasData {
    pub root: String,
    pub elapsed_ms: f64,
    pub scanned_files: usize,
    pub raw_bytes: u64,
    pub raw_tokens_if_read_all: u64,
    pub top_dirs: Vec<(String, usize)>,
    pub entrypoints: Vec<String>,
    pub top_code: Vec<CodeRecord>,
    pub top_docs: Vec<DocRecord>,
    #[serde(default)]
    pub top_data: Vec<DataRecord>,
    pub stale_todo_traps: Vec<String>,
}

#[derive(Parser, Debug)]
#[command(
    name = "atlas",
    about = "Sub-50ms Tree-sitter structural map for codebases & knowledge vaults"
)]
struct Cli {
    #[command(subcommand)]
    subcmd: Option<SubCmd>,
    /// Optional workspace path when `map` subcommand is omitted
    #[arg(default_value = ".")]
    root: String,
    #[arg(long, default_value = "")]
    focus: String,
    #[arg(long, default_value_t = 18)]
    max_files: usize,
    #[arg(long, default_value_t = 90)]
    stale_days: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum SubCmd {
    /// Generate structural map of codebase or personal vault
    Map {
        #[arg(default_value = ".")]
        root: String,
        #[arg(long, default_value = "")]
        focus: String,
        #[arg(long, default_value_t = 18)]
        max_files: usize,
        #[arg(long, default_value_t = 90)]
        stale_days: u64,
        #[arg(long)]
        json: bool,
    },
    /// Extract UI pages, controls, API routes, frontend<->backend broken links & slop radar
    Product {
        #[arg(default_value = ".")]
        root: String,
        #[arg(long, default_value = "")]
        write: String,
        #[arg(long)]
        json: bool,
    },
    /// Map exact Tree-sitter AST definitions, downstream callers & tests for symbol(s) in <15ms
    Impact {
        /// Symbol name (or comma-separated symbols, e.g. `computeTotal,OrderItem`)
        symbol: String,
        #[arg(default_value = ".")]
        root: String,
        #[arg(long)]
        json: bool,
    },
    /// Hierarchical Agentless/AutoCodeRover fault localizer: ranks Top-K suspect functions + numbered source in <25ms
    Locate {
        /// Bug description, symptom keywords, or stack trace text
        query: String,
        #[arg(default_value = ".")]
        root: String,
        #[arg(short = 'k', long, default_value_t = 5)]
        top_k: usize,
        #[arg(long)]
        json: bool,
    },
    /// Multi-hop Tree-sitter call-chain tracer (<30ms): maps upstream callers (1..depth hops), downstream callees, source-to-sink reachability & guard placement
    Trace {
        /// Function or method symbol name to trace
        symbol: String,
        #[arg(default_value = ".")]
        root: String,
        #[arg(short = 'd', long, default_value_t = 3)]
        depth: usize,
        /// Target sink or symbol name for shortest-path reachability + guard-placement classification
        #[arg(long)]
        to: Option<String>,
        /// Also compute multi-hop reachability paths to all notable I/O/exec/DOM/SQL sinks
        #[arg(long)]
        sinks: bool,
        #[arg(long)]
        json: bool,
    },
    /// Git-diff-aware change impact brief: extracts modified AST symbols, untouched downstream callers & related tests in 1 pass
    Changes {
        #[arg(default_value = ".")]
        root: String,
        #[arg(long, default_value = "HEAD")]
        base: String,
        #[arg(long)]
        json: bool,
    },
    /// Git symbol/line history, blame authorship & temporal co-change coupling in <50ms
    History {
        /// File path inside git repository
        file: String,
        #[arg(long, default_value = "")]
        symbol: String,
        #[arg(long, default_value = "")]
        lines: String,
        #[arg(long, default_value_t = 8)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Cross-file module dependency, reverse importer blast radius & circular-import detector (<40ms)
    Deps {
        /// File path or '.' for workspace cycle detection
        target: String,
        #[arg(default_value = ".")]
        root: String,
        #[arg(short = 'd', long, default_value_t = 2)]
        depth: usize,
        /// Also audit orphan source modules and unused/ghost exports
        #[arg(long)]
        dead: bool,
        #[arg(long)]
        json: bool,
    },
    /// Multi-axis entrypoint & sink surface map across source code, manifests, virtual archives (.asar/.vsix/.zip/.jar) & optional native binaries
    Surface {
        #[arg(default_value = ".")]
        root: String,
        #[arg(long, default_value_t = 1500)]
        max_files: usize,
        #[arg(long, default_value_t = 12)]
        max_per_axis: usize,
        #[arg(long)]
        include_vendor: bool,
        #[arg(long)]
        include_binaries: bool,
        #[arg(long)]
        json: bool,
    },
}

fn atlas_regexes() -> &'static (Regex, Regex, Regex, Regex) {
    static RE: OnceLock<(Regex, Regex, Regex, Regex)> = OnceLock::new();
    RE.get_or_init(|| {
        let md_re = Regex::new(r"(?m)^(#{1,2})\s+(.+?)\s*$").unwrap();
        let todo_re = Regex::new(r"\b(TODO|FIXME|HACK|XXX)\b[:\s]*([^\r\n]{0,90})").unwrap();
        let go_mod_re = Regex::new(r"(?m)^\s*module\s+(\S+)").unwrap();
        let c_inc_re = Regex::new(r#"(?m)^\s*#\s*include\s*"([^"]+)""#).unwrap();
        (md_re, todo_re, go_mod_re, c_inc_re)
    })
}

fn node_text<'a>(node: Node<'a>, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn extract_py_ast(text: &str) -> (Vec<String>, Vec<String>) {
    let mut parser = TsParser::new();
    let _ = parser.set_language(&tree_sitter_python::LANGUAGE.into());
    let Some(tree) = parser.parse(text, None) else {
        return (Vec::new(), Vec::new());
    };
    let src = text.as_bytes();
    let root = tree.root_node();
    let mut symbols = Vec::new();
    let mut imports = Vec::new();

    let mut cur = root.walk();
    for child in root.children(&mut cur) {
        let target = if child.kind() == "decorated_definition" {
            child.child_by_field_name("definition").unwrap_or(child)
        } else {
            child
        };
        match target.kind() {
            "class_definition" => {
                let Some(name_n) = target.child_by_field_name("name") else {
                    continue;
                };
                let cname = node_text(name_n, src);
                let mut methods = Vec::new();
                if let Some(body) = target.child_by_field_name("body") {
                    let mut bcur = body.walk();
                    for sub in body.children(&mut bcur) {
                        let mnode = if sub.kind() == "decorated_definition" {
                            sub.child_by_field_name("definition").unwrap_or(sub)
                        } else {
                            sub
                        };
                        if mnode.kind() == "function_definition" {
                            if let Some(mn) = mnode.child_by_field_name("name") {
                                let mname = node_text(mn, src);
                                if !mname.starts_with('_') && methods.len() < 4 {
                                    methods.push(mname.to_string());
                                }
                            }
                        }
                    }
                }
                let m_str = if methods.is_empty() {
                    String::new()
                } else {
                    format!("({})", methods.join(","))
                };
                if symbols.len() < 8 {
                    symbols.push(format!("class {cname}{m_str}"));
                }
            }
            "function_definition" => {
                if let Some(name_n) = target.child_by_field_name("name") {
                    let fname = node_text(name_n, src);
                    if (!fname.starts_with('_') || fname == "__main__") && symbols.len() < 8 {
                        symbols.push(format!("def {fname}()"));
                    }
                }
            }
            _ => {}
        }
    }

    fn walk_py_imports(n: Node, src: &[u8], out: &mut Vec<String>) {
        match n.kind() {
            "import_from_statement" => {
                if let Some(mn) = n.child_by_field_name("module_name") {
                    let s = node_text(mn, src).trim();
                    if !s.is_empty() {
                        out.push(s.to_string());
                    }
                }
            }
            "import_statement" => {
                let mut c = n.walk();
                for ch in n.children(&mut c) {
                    if ch.kind() == "dotted_name" {
                        out.push(node_text(ch, src).to_string());
                    } else if ch.kind() == "aliased_import" {
                        if let Some(dn) = ch.child_by_field_name("name") {
                            out.push(node_text(dn, src).to_string());
                        }
                    }
                }
            }
            _ => {
                let mut c = n.walk();
                for ch in n.children(&mut c) {
                    walk_py_imports(ch, src, out);
                }
            }
        }
    }
    walk_py_imports(root, src, &mut imports);
    (symbols, imports)
}

fn extract_ts_js_ast(text: &str, ext: &str) -> (Vec<String>, Vec<String>) {
    let mut parser = TsParser::new();
    let lang = match ext {
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "ts" | "mts" | "cts" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        _ => tree_sitter_javascript::LANGUAGE.into(),
    };
    let _ = parser.set_language(&lang);
    let Some(tree) = parser.parse(text, None) else {
        return (Vec::new(), Vec::new());
    };
    let src = text.as_bytes();
    let root = tree.root_node();
    let mut symbols = Vec::new();
    let mut imports = Vec::new();

    let mut cur = root.walk();
    for child in root.children(&mut cur) {
        if child.kind() == "import_statement" || child.kind() == "export_statement" {
            if let Some(snode) = child.child_by_field_name("source") {
                let raw_s = node_text(snode, src).trim_matches(|c| c == '\'' || c == '"');
                if raw_s.starts_with('.') {
                    imports.push(raw_s.to_string());
                }
            }
        }
        let decl = if child.kind() == "export_statement" {
            child.child_by_field_name("declaration").unwrap_or(child)
        } else {
            child
        };
        if symbols.len() >= 8 {
            continue;
        }
        match decl.kind() {
            "class_declaration" | "abstract_class_declaration" => {
                let Some(nn) = decl.child_by_field_name("name") else {
                    continue;
                };
                let cname = node_text(nn, src);
                let mut methods = Vec::new();
                if let Some(body) = decl.child_by_field_name("body") {
                    let mut bcur = body.walk();
                    for sub in body.children(&mut bcur) {
                        if sub.kind() == "method_definition" {
                            if let Some(mn) = sub.child_by_field_name("name") {
                                let mname = node_text(mn, src);
                                if mname != "constructor"
                                    && !mname.starts_with('_')
                                    && methods.len() < 4
                                {
                                    methods.push(mname.to_string());
                                }
                            }
                        }
                    }
                }
                let m_str = if methods.is_empty() {
                    String::new()
                } else {
                    format!("({})", methods.join(","))
                };
                symbols.push(format!("class {cname}{m_str}"));
            }
            "function_declaration" | "generator_function_declaration" => {
                if let Some(nn) = decl.child_by_field_name("name") {
                    symbols.push(format!("fn {}()", node_text(nn, src)));
                }
            }
            "interface_declaration" => {
                if let Some(nn) = decl.child_by_field_name("name") {
                    symbols.push(format!("interface {}", node_text(nn, src)));
                }
            }
            "type_alias_declaration" => {
                if let Some(nn) = decl.child_by_field_name("name") {
                    symbols.push(format!("type {}", node_text(nn, src)));
                }
            }
            "enum_declaration" => {
                if let Some(nn) = decl.child_by_field_name("name") {
                    symbols.push(format!("enum {}", node_text(nn, src)));
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
                            ) && symbols.len() < 8
                            {
                                symbols.push(format!("fn {}()", node_text(nn, src)));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    (symbols, imports)
}

fn extract_go_ast(text: &str) -> (Vec<String>, Vec<String>) {
    let mut parser = TsParser::new();
    let _ = parser.set_language(&tree_sitter_go::LANGUAGE.into());
    let Some(tree) = parser.parse(text, None) else {
        return (Vec::new(), Vec::new());
    };
    let src = text.as_bytes();
    let root = tree.root_node();
    let mut types_order: Vec<String> = Vec::new();
    let mut recv_methods: HashMap<String, Vec<String>> = HashMap::new();
    let mut funcs: Vec<String> = Vec::new();
    let mut imports: Vec<String> = Vec::new();

    let mut cur = root.walk();
    for child in root.children(&mut cur) {
        match child.kind() {
            "import_declaration" => {
                let mut ic = child.walk();
                for sub in child.children(&mut ic) {
                    if sub.kind() == "import_spec" {
                        if let Some(pn) = sub.child_by_field_name("path") {
                            imports.push(node_text(pn, src).trim_matches('"').to_string());
                        }
                    } else if sub.kind() == "import_spec_list" {
                        let mut lc = sub.walk();
                        for sp in sub.children(&mut lc) {
                            if sp.kind() == "import_spec" {
                                if let Some(pn) = sp.child_by_field_name("path") {
                                    imports.push(node_text(pn, src).trim_matches('"').to_string());
                                }
                            }
                        }
                    }
                }
            }
            "type_declaration" => {
                let mut tc = child.walk();
                for sub in child.children(&mut tc) {
                    if sub.kind() == "type_spec" {
                        if let Some(nn) = sub.child_by_field_name("name") {
                            let tname = node_text(nn, src).to_string();
                            if !types_order.contains(&tname) {
                                types_order.push(tname);
                            }
                        }
                    }
                }
            }
            "method_declaration" => {
                let mname = child
                    .child_by_field_name("name")
                    .map(|n| node_text(n, src).to_string())
                    .unwrap_or_default();
                if let Some(recv) = child.child_by_field_name("receiver") {
                    let raw_r = node_text(recv, src);
                    let rtype: String = raw_r
                        .trim_matches(|c| c == '(' || c == ')')
                        .split_whitespace()
                        .last()
                        .unwrap_or("")
                        .trim_start_matches('*')
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !rtype.is_empty() && !mname.is_empty() {
                        if !types_order.contains(&rtype) {
                            types_order.push(rtype.clone());
                        }
                        recv_methods.entry(rtype).or_default().push(mname);
                    }
                }
            }
            "function_declaration" => {
                if let Some(nn) = child.child_by_field_name("name") {
                    funcs.push(format!("func {}()", node_text(nn, src)));
                }
            }
            _ => {}
        }
    }

    let mut symbols = Vec::new();
    for tname in types_order {
        let ms = recv_methods.remove(&tname).unwrap_or_default();
        let m_str = if ms.is_empty() {
            String::new()
        } else {
            let take_n = ms.len().min(4);
            format!("({})", ms[..take_n].join(","))
        };
        symbols.push(format!("type {tname}{m_str}"));
    }
    symbols.extend(funcs);
    symbols.truncate(8);
    (symbols, imports)
}

fn extract_rs_ast(text: &str) -> (Vec<String>, Vec<String>) {
    let mut parser = TsParser::new();
    let _ = parser.set_language(&tree_sitter_rust::LANGUAGE.into());
    let Some(tree) = parser.parse(text, None) else {
        return (Vec::new(), Vec::new());
    };
    let src = text.as_bytes();
    let root = tree.root_node();
    let mut types_order: Vec<(String, String)> = Vec::new();
    let mut impl_methods: HashMap<String, Vec<String>> = HashMap::new();
    let mut funcs: Vec<String> = Vec::new();
    let mut imports: HashSet<String> = HashSet::new();

    let mut cur = root.walk();
    for child in root.children(&mut cur) {
        match child.kind() {
            "mod_item" => {
                if child.child_by_field_name("body").is_none() {
                    if let Some(nn) = child.child_by_field_name("name") {
                        imports.insert(node_text(nn, src).to_string());
                    }
                }
            }
            "use_declaration" => {
                let raw_u = node_text(child, src);
                if let Some(rest) = raw_u.split("crate::").nth(1) {
                    let seg: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !seg.is_empty() {
                        imports.insert(seg);
                    }
                }
            }
            "struct_item" | "enum_item" | "trait_item" => {
                let kind = child.kind().trim_end_matches("_item").to_string();
                if let Some(nn) = child.child_by_field_name("name") {
                    let name = node_text(nn, src).to_string();
                    if !types_order.iter().any(|(_, n)| n == &name) {
                        types_order.push((kind, name));
                    }
                }
            }
            "impl_item" => {
                if let Some(tn) = child.child_by_field_name("type") {
                    let raw_t = node_text(tn, src);
                    let base: String = raw_t
                        .split('<')
                        .next()
                        .unwrap_or(raw_t)
                        .rsplit("::")
                        .next()
                        .unwrap_or(raw_t)
                        .trim()
                        .to_string();
                    if !base.is_empty() {
                        if !types_order.iter().any(|(_, n)| n == &base) {
                            types_order.push(("impl".to_string(), base.clone()));
                        }
                        if let Some(body) = child.child_by_field_name("body") {
                            let mut bc = body.walk();
                            for sub in body.children(&mut bc) {
                                if sub.kind() == "function_item" {
                                    if let Some(mn) = sub.child_by_field_name("name") {
                                        let mname = node_text(mn, src);
                                        if !mname.starts_with('_') {
                                            impl_methods
                                                .entry(base.clone())
                                                .or_default()
                                                .push(mname.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "function_item" => {
                if let Some(nn) = child.child_by_field_name("name") {
                    let fname = node_text(nn, src);
                    if !fname.starts_with('_') || fname == "main" {
                        funcs.push(format!("fn {fname}()"));
                    }
                }
            }
            _ => {}
        }
    }

    let mut symbols = Vec::new();
    for (kind, name) in types_order {
        let ms = impl_methods.remove(&name).unwrap_or_default();
        let m_str = if ms.is_empty() {
            String::new()
        } else {
            let take_n = ms.len().min(4);
            format!("({})", ms[..take_n].join(","))
        };
        symbols.push(format!("{kind} {name}{m_str}"));
    }
    symbols.extend(funcs);
    symbols.truncate(8);
    (symbols, imports.into_iter().collect())
}

fn find_c_declarator_ident<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" => Some(node_text(node, src)),
        _ => {
            if let Some(d) = node.child_by_field_name("declarator") {
                if let Some(id) = find_c_declarator_ident(d, src) {
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

fn extract_c_ast(text: &str) -> (Vec<String>, Vec<String>) {
    let (_, _, _, c_inc_re) = atlas_regexes();
    let mut parser = TsParser::new();
    let _ = parser.set_language(&tree_sitter_c::LANGUAGE.into());
    let Some(tree) = parser.parse(text, None) else {
        return (Vec::new(), Vec::new());
    };
    let src = text.as_bytes();
    let root = tree.root_node();
    let mut symbols = Vec::new();
    let imports: Vec<String> = c_inc_re
        .captures_iter(text)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect();

    let mut cur = root.walk();
    for child in root.children(&mut cur) {
        if symbols.len() >= 8 {
            break;
        }
        match child.kind() {
            "function_definition" => {
                if let Some(decl) = child.child_by_field_name("declarator") {
                    if let Some(fname) = find_c_declarator_ident(decl, src) {
                        symbols.push(format!("fn {fname}()"));
                    }
                }
            }
            "struct_specifier" => {
                if let Some(nn) = child.child_by_field_name("name") {
                    symbols.push(format!("struct {}", node_text(nn, src)));
                }
            }
            "enum_specifier" => {
                if let Some(nn) = child.child_by_field_name("name") {
                    symbols.push(format!("enum {}", node_text(nn, src)));
                }
            }
            "type_definition" => {
                if let Some(decl) = child.child_by_field_name("declarator") {
                    if let Some(tname) = find_c_declarator_ident(decl, src) {
                        symbols.push(format!("typedef {tname}"));
                    }
                }
            }
            _ => {}
        }
    }
    (symbols, imports)
}

fn detect_git_dirty_paths(root: &Path) -> HashSet<String> {
    if !root.join(".git").exists() {
        return HashSet::new();
    }
    let Ok(out) = Command::new("git")
        .args(["status", "--porcelain", "-uno"])
        .current_dir(root)
        .output()
    else {
        return HashSet::new();
    };
    if !out.status.success() {
        return HashSet::new();
    }
    let mut dirty = HashSet::new();
    for ln in String::from_utf8_lossy(&out.stdout).lines() {
        if ln.len() > 3 {
            let rel = ln[3..].trim().trim_matches('"').replace('\\', "/");
            let final_rel = rel.rsplit(" -> ").next().unwrap_or(&rel).trim().to_string();
            dirty.insert(final_rel);
        }
    }
    dirty
}

pub fn scan_workspace(root: &Path, focus: &str, max_files: usize, stale_days: u64) -> AtlasData {
    let t0 = Instant::now();
    let (md_re, todo_re, go_mod_re, _) = atlas_regexes();
    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let focus_l = focus.trim().to_lowercase();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let stale_cutoff = now_secs.saturating_sub(stale_days * 86400);

    let dirty_paths = detect_git_dirty_paths(&root_canon);
    let go_mod_name = fs::read_to_string(root_canon.join("go.mod"))
        .ok()
        .and_then(|s| {
            go_mod_re
                .captures(&s)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
        })
        .unwrap_or_default();

    let mut code_records: Vec<CodeRecord> = Vec::new();
    let mut doc_records: Vec<DocRecord> = Vec::new();
    let mut data_records: Vec<DataRecord> = Vec::new();
    let mut entrypoints: Vec<String> = Vec::new();
    let mut stale_todos: Vec<String> = Vec::new();
    let mut dir_counts: HashMap<String, usize> = HashMap::new();
    let mut raw_imports_by_file: Vec<(PathBuf, String, Vec<String>)> = Vec::new();
    let mut total_raw_bytes = 0u64;
    let mut total_files = 0usize;

    let walker = WalkBuilder::new(&root_canon)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
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
        let fpath = entry.path().to_path_buf();
        let fname = entry.file_name().to_string_lossy().to_string();
        if fname.starts_with('.') && fname != ".env.example" {
            continue;
        }
        let Ok(rel) = fpath.strip_prefix(&root_canon) else {
            continue;
        };
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let top_bucket = rel
            .components()
            .next()
            .map(|c| {
                if rel.components().count() > 1 {
                    c.as_os_str().to_string_lossy().to_string()
                } else {
                    ".".to_string()
                }
            })
            .unwrap_or_else(|| ".".to_string());

        if !focus_l.is_empty() && !rel_str.to_lowercase().contains(&focus_l) {
            *dir_counts.entry(top_bucket).or_insert(0) += 1;
            continue;
        }

        let Ok(meta) = entry.metadata() else { continue };
        let ext = fpath
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_data_ext = matches!(
            ext.as_str(),
            "xlsx"
                | "csv"
                | "tsv"
                | "sqlite"
                | "db"
                | "sqlite3"
                | "docx"
                | "pptx"
                | "pdf"
                | "json"
                | "jsonl"
                | "gz"
                | "tgz"
                | "zip"
        ) && !matches!(
            fname.as_str(),
            "package.json" | "package-lock.json" | "tsconfig.json" | "Cargo.lock"
        );
        if meta.len() > 600_000 && !is_data_ext {
            continue;
        }

        total_files += 1;
        total_raw_bytes += meta.len();
        *dir_counts.entry(top_bucket).or_insert(0) += 1;

        if ENTRYPOINT_NAMES.contains(&fname.as_str()) {
            entrypoints.push(rel_str.clone());
        }

        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let is_code = matches!(
            ext.as_str(),
            "py" | "ts"
                | "tsx"
                | "js"
                | "jsx"
                | "mjs"
                | "cjs"
                | "go"
                | "rs"
                | "c"
                | "cc"
                | "cpp"
                | "h"
                | "hpp"
        ) && !fname.ends_with(".d.ts");

        if is_code {
            let Ok(bytes) = fs::read(&fpath) else {
                continue;
            };
            let txt = String::from_utf8_lossy(&bytes);
            let (syms, imps) = match ext.as_str() {
                "py" => extract_py_ast(&txt),
                "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" => extract_ts_js_ast(&txt, &ext),
                "go" => extract_go_ast(&txt),
                "rs" => extract_rs_ast(&txt),
                "c" | "h" | "cc" | "cpp" | "hpp" => extract_c_ast(&txt),
                _ => (Vec::new(), Vec::new()),
            };
            raw_imports_by_file.push((fpath.clone(), ext.clone(), imps));

            if mtime > 0 && mtime < stale_cutoff && stale_todos.len() < 6 {
                if let Some(cap) = todo_re.captures(&txt) {
                    let age_d = now_secs.saturating_sub(mtime) / 86400;
                    let kind = cap.get(1).map(|m| m.as_str()).unwrap_or("TODO");
                    let body: String = cap
                        .get(2)
                        .map(|m| m.as_str().trim())
                        .unwrap_or("")
                        .chars()
                        .take(60)
                        .collect();
                    stale_todos.push(format!("`{rel_str}` ({age_d}d old {kind}: {body})"));
                }
            }

            let stem = fpath
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            code_records.push(CodeRecord {
                dirty: dirty_paths.contains(&rel_str),
                path: rel_str,
                stem,
                lines: txt.bytes().filter(|&b| b == b'\n').count() + 1,
                mtime,
                symbols: syms,
                hub_refs: 0,
                score: 0.0,
            });
        } else if matches!(ext.as_str(), "md" | "mdx" | "rst" | "txt") {
            let Ok(bytes) = fs::read(&fpath) else {
                continue;
            };
            let txt = String::from_utf8_lossy(&bytes);
            let headings: Vec<String> = md_re
                .captures_iter(&txt)
                .take(4)
                .filter_map(|c| {
                    c.get(2)
                        .map(|m| m.as_str().trim().chars().take(70).collect::<String>())
                })
                .collect();
            doc_records.push(DocRecord {
                path: rel_str,
                lines: txt.bytes().filter(|&b| b == b'\n').count() + 1,
                mtime,
                headings,
            });
        } else if is_data_ext {
            if let Some(summary) = fingerprint_data_artifact(&fpath, &ext, meta.len()) {
                data_records.push(DataRecord {
                    path: rel_str,
                    bytes: meta.len(),
                    mtime,
                    summary,
                });
            }
        }
    }

    let known_rel: HashSet<String> = code_records.iter().map(|r| r.path.clone()).collect();
    let mut inbound_by_path: HashMap<String, usize> = HashMap::new();
    let mut inbound_by_stem: HashMap<String, usize> = HashMap::new();
    let mut directed_edges: Vec<(String, String)> = Vec::new();

    for (src_f, ext, imps) in raw_imports_by_file {
        let src_rel = src_f
            .strip_prefix(&root_canon)
            .unwrap_or(&src_f)
            .to_string_lossy()
            .replace('\\', "/");
        let src_dir = src_f.parent().unwrap_or(&root_canon);
        for imp in imps {
            let mut matched_rel = String::new();
            if matches!(ext.as_str(), "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs")
                && imp.starts_with('.')
            {
                let base = src_dir.join(&imp);
                let mut cands = vec![base.clone()];
                if let Some(bext) = base.extension().and_then(|e| e.to_str()) {
                    if matches!(bext, "js" | "mjs" | "cjs") {
                        let stem_p = base.with_extension("");
                        cands.push(stem_p.with_extension("ts"));
                        cands.push(stem_p.with_extension("tsx"));
                    }
                } else {
                    for ec in ["ts", "tsx", "js", "jsx", "mjs"] {
                        cands.push(PathBuf::from(format!("{}.{ec}", base.display())));
                        cands.push(base.join(format!("index.{ec}")));
                    }
                }
                for c in cands {
                    if let Ok(canon_c) = fs::canonicalize(&c) {
                        if let Ok(rel_c) = canon_c.strip_prefix(&root_canon) {
                            let rs = rel_c.to_string_lossy().replace('\\', "/");
                            if known_rel.contains(&rs) {
                                matched_rel = rs;
                                break;
                            }
                        }
                    }
                }
            } else if ext == "go" && !go_mod_name.is_empty() && imp.starts_with(&go_mod_name) {
                let sub_rel = imp[go_mod_name.len()..].trim_start_matches('/');
                let prefix = if sub_rel.is_empty() {
                    String::new()
                } else {
                    format!("{sub_rel}/")
                };
                for kp in &known_rel {
                    if kp.ends_with(".go") && !kp.ends_with("_test.go") {
                        let same_pkg = if prefix.is_empty() {
                            !kp.contains('/')
                        } else {
                            kp.starts_with(&prefix) && !kp[prefix.len()..].contains('/')
                        };
                        if same_pkg {
                            *inbound_by_path.entry(kp.clone()).or_insert(0) += 1;
                        }
                    }
                }
                continue;
            } else if ext == "rs" {
                for cand_rel in [
                    format!("src/{imp}.rs"),
                    format!("src/{imp}/mod.rs"),
                    format!("{imp}.rs"),
                ] {
                    if known_rel.contains(&cand_rel) {
                        matched_rel = cand_rel;
                        break;
                    }
                }
            } else if matches!(ext.as_str(), "c" | "h" | "cc" | "cpp" | "hpp") {
                if let Ok(canon_h) = fs::canonicalize(src_dir.join(&imp)) {
                    if let Ok(rel_h) = canon_h.strip_prefix(&root_canon) {
                        let rs = rel_h.to_string_lossy().replace('\\', "/");
                        if known_rel.contains(&rs) {
                            matched_rel = rs;
                        }
                    }
                }
            }

            if !matched_rel.is_empty() {
                *inbound_by_path.entry(matched_rel.clone()).or_insert(0) += 1;
                if src_rel != matched_rel {
                    directed_edges.push((src_rel.clone(), matched_rel));
                }
            } else {
                let stem = if imp.contains('/') {
                    Path::new(&imp)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                } else {
                    imp.rsplit('.').next().unwrap_or("")
                };
                if !stem.is_empty() {
                    *inbound_by_stem.entry(stem.to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    // Personalized PageRank (8 power iterations, damping=0.85) biased toward dirty & focus files
    let n_nodes = code_records.len();
    let mut ppr_scores = vec![1.0_f64; n_nodes];
    if n_nodes > 1 {
        let idx_of: HashMap<&str, usize> = code_records
            .iter()
            .enumerate()
            .map(|(i, r)| (r.path.as_str(), i))
            .collect();
        let focus_low = focus.to_ascii_lowercase();
        let mut pers = vec![1.0_f64; n_nodes];
        for (i, r) in code_records.iter().enumerate() {
            if r.dirty {
                pers[i] += 3.0;
            }
            if !focus_low.is_empty() && r.path.to_ascii_lowercase().contains(&focus_low) {
                pers[i] += 5.0;
            }
        }
        let pers_sum: f64 = pers.iter().sum::<f64>().max(1e-9);
        for w in &mut pers {
            *w /= pers_sum;
        }
        let mut out_adj: Vec<Vec<usize>> = vec![Vec::new(); n_nodes];
        for (u_s, v_s) in &directed_edges {
            if let (Some(&u), Some(&v)) = (idx_of.get(u_s.as_str()), idx_of.get(v_s.as_str())) {
                if !out_adj[u].contains(&v) {
                    out_adj[u].push(v);
                }
            }
        }
        ppr_scores = pers.clone();
        let damping = 0.85_f64;
        for _ in 0..8 {
            let mut next = vec![0.0_f64; n_nodes];
            let mut sink_mass = 0.0_f64;
            for u in 0..n_nodes {
                if out_adj[u].is_empty() {
                    sink_mass += ppr_scores[u];
                } else {
                    let share = ppr_scores[u] / (out_adj[u].len() as f64);
                    for &v in &out_adj[u] {
                        next[v] += damping * share;
                    }
                }
            }
            for i in 0..n_nodes {
                next[i] += (1.0 - damping + damping * sink_mass) * pers[i];
            }
            ppr_scores = next;
        }
    }

    let ep_set: HashSet<String> = entrypoints.iter().cloned().collect();
    let scale = (n_nodes.max(1)) as f64;
    for (i, rec) in code_records.iter_mut().enumerate() {
        let hub = inbound_by_path.get(&rec.path).copied().unwrap_or(0)
            + inbound_by_stem.get(&rec.stem).copied().unwrap_or(0);
        rec.hub_refs = hub;
        rec.score = (ppr_scores[i] * scale) * 6.0
            + (hub as f64) * 2.5
            + if rec.dirty { 3.0 } else { 0.0 }
            + (rec.symbols.len().min(6) as f64) * 1.2
            + if ep_set.contains(&rec.path) { 1.0 } else { 0.0 };
    }

    code_records.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.mtime.cmp(&a.mtime))
    });
    doc_records.sort_by_key(|a| std::cmp::Reverse(a.mtime));
    entrypoints.sort();
    entrypoints.truncate(10);

    let mut top_dirs: Vec<(String, usize)> = dir_counts.into_iter().collect();
    top_dirs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top_dirs.truncate(10);

    code_records.truncate(max_files);
    doc_records.truncate(max_files.min(8));
    data_records.sort_by_key(|a| std::cmp::Reverse(a.mtime));
    data_records.truncate(max_files.min(10));

    let root_name = root_canon
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("workspace")
        .to_string();
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;

    AtlasData {
        root: root_name,
        elapsed_ms,
        scanned_files: total_files,
        raw_bytes: total_raw_bytes,
        raw_tokens_if_read_all: total_raw_bytes.div_ceil(4),
        top_dirs,
        entrypoints,
        top_code: code_records,
        top_docs: doc_records,
        top_data: data_records,
        stale_todo_traps: stale_todos,
    }
}

fn human_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{b}B")
    } else if b < 1024 * 1024 {
        format!("{:.1}KB", (b as f64) / 1024.0)
    } else {
        format!("{:.1}MB", (b as f64) / (1024.0 * 1024.0))
    }
}

fn fingerprint_data_artifact(fpath: &Path, ext: &str, bytes: u64) -> Option<String> {
    use std::io::Read;
    let sz = human_bytes(bytes);
    match ext {
        "xlsx" => {
            let mut sheets = Vec::new();
            if let Ok(f) = fs::File::open(fpath) {
                if let Ok(mut za) = zip::ZipArchive::new(f) {
                    if let Ok(mut wf) = za.by_name("xl/workbook.xml") {
                        let mut wxml = String::new();
                        let _ = wf.read_to_string(&mut wxml);
                        static SHEET_RE: OnceLock<Regex> = OnceLock::new();
                        let re = SHEET_RE.get_or_init(|| {
                            Regex::new(r#"<sheet\b[^>]*\bname="([^"]+)""#).unwrap()
                        });
                        for cap in re.captures_iter(&wxml) {
                            sheets.push(cap[1].to_string());
                        }
                    }
                }
            }
            if sheets.is_empty() {
                Some(format!("{sz} xlsx workbook"))
            } else {
                Some(format!("{sz} xlsx, sheets={sheets:?}"))
            }
        }
        "csv" | "tsv" => {
            let mut head_buf = Vec::with_capacity(2048);
            if let Ok(f) = fs::File::open(fpath) {
                let _ = f.take(2048).read_to_end(&mut head_buf);
            }
            let (txt, enc) = if let Ok(s) =
                std::str::from_utf8(head_buf.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&head_buf))
            {
                (s.to_string(), "utf-8")
            } else {
                let (cow, _) = encoding_rs::GB18030.decode_without_bom_handling(&head_buf);
                (cow.into_owned(), "gbk")
            };
            let sep = if ext == "tsv" { '\t' } else { ',' };
            let cols: Vec<String> = txt
                .lines()
                .next()
                .unwrap_or("")
                .split(sep)
                .take(8)
                .map(|c| c.trim().trim_matches('"').to_string())
                .filter(|c| !c.is_empty())
                .collect();
            Some(format!("{sz} {enc} {ext}, cols={cols:?}"))
        }
        "sqlite" | "db" | "sqlite3" => {
            let mut hdr = [0u8; 16];
            let is_sql = fs::File::open(fpath)
                .and_then(|mut f| f.read_exact(&mut hdr))
                .map(|_| &hdr == b"SQLite format 3\0")
                .unwrap_or(false);
            let kind = if is_sql { "sqlite3 db" } else { "db file" };
            Some(format!("{sz} {kind}"))
        }
        _ => Some(format!("{sz} {ext}")),
    }
}

fn fast_shell_and_browser_summary() -> String {
    let mut parts = vec![format!(
        "OS={}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )];
    #[cfg(windows)]
    {
        let has_pwsh = Path::new(r"C:\Program Files\PowerShell\7\pwsh.exe").is_file()
            || std::env::var_os("PATH")
                .map(|v| std::env::split_paths(&v).any(|d| d.join("pwsh.exe").is_file()))
                .unwrap_or(false);
        let has_git_bash = Path::new(r"C:\Program Files\Git\bin\bash.exe").is_file()
            || Path::new(r"C:\Program Files (x86)\Git\bin\bash.exe").is_file();
        let mut sh = Vec::new();
        if has_pwsh {
            sh.push("pwsh7");
        } else {
            sh.push("ps5.1[no-raw-&&]");
        }
        if has_git_bash {
            sh.push("git-bash");
        }
        parts.push(format!(
            "win-shells={} (run commands via `ap exec -c` / `ap_exec` for UTF-8 & && heal)",
            sh.join("+")
        ));
    }
    let has_browser = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ]
    .iter()
    .any(|p| Path::new(p).is_file());
    if has_browser {
        parts.push("headless-CDP=READY (`ap probe smoke` / `ap_smoke`)".to_string());
    }
    parts.join(" | ")
}

fn probe_host_capabilities() -> String {
    let mut caps = vec![fast_shell_and_browser_summary()];
    if let Ok(o) = Command::new("node").arg("--version").output() {
        if o.status.success() {
            let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
            caps.push(format!("node={v} (built-in `node:sqlite`, `node:test`, `--experimental-strip-types` [avoid TS `enum`/param-props])"));
        }
    }
    if let Ok(o) = Command::new("python").arg("--version").output() {
        if o.status.success() {
            caps.push(String::from_utf8_lossy(&o.stdout).trim().replace(' ', "="));
        }
    }
    if let Ok(o) = Command::new("rustc").arg("--version").output() {
        if o.status.success() {
            let v = String::from_utf8_lossy(&o.stdout);
            let short = v.split_whitespace().take(2).collect::<Vec<_>>().join("=");
            caps.push(short);
        }
    }
    caps.join(" | ")
}

pub fn render_atlas_md(data: &AtlasData) -> String {
    let mut lines = vec![format!(
        "# ATLAS MAP: `{}` ({} files scanned in {}ms | raw ~{} tok)",
        data.root, data.scanned_files, data.elapsed_ms, data.raw_tokens_if_read_all
    )];
    if data.scanned_files <= 3 {
        lines.push(format!("**Host Runtime**: {}", probe_host_capabilities()));
    } else {
        lines.push(format!(
            "**Host Env**: {}",
            fast_shell_and_browser_summary()
        ));
    }
    if !data.top_dirs.is_empty() {
        let ds = data
            .top_dirs
            .iter()
            .map(|(k, v)| {
                if k == "." {
                    format!("`root`({v})")
                } else {
                    format!("`{k}/`({v})")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("**Layout**: {ds}"));
    }
    if !data.entrypoints.is_empty() {
        let eps = data
            .entrypoints
            .iter()
            .map(|e| format!("`{e}`"))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("**Entrypoints/Manifests**: {eps}"));
    }
    if !data.top_code.is_empty() {
        lines.push("\n## Key Code Modules (Ranked by Centrality & Symbols)".to_string());
        for c in &data.top_code {
            let dirty_tag = if c.dirty { " [dirty]" } else { "" };
            let hub = if c.hub_refs > 0 {
                format!(" [imported {}x]", c.hub_refs)
            } else {
                String::new()
            };
            let syms = if c.symbols.is_empty() {
                String::new()
            } else {
                let take_n = c.symbols.len().min(5);
                format!(": {}", c.symbols[..take_n].join(", "))
            };
            lines.push(format!(
                "- `{}` ({}L){dirty_tag}{hub}{syms}",
                c.path, c.lines
            ));
        }
    }
    if !data.top_docs.is_empty() {
        lines.push("\n## Active Docs / Knowledge Vault".to_string());
        for d in &data.top_docs {
            let hd = if d.headings.is_empty() {
                String::new()
            } else {
                let take_n = d.headings.len().min(3);
                format!(" -> {}", d.headings[..take_n].join(" / "))
            };
            lines.push(format!("- `{}` ({}L){hd}", d.path, d.lines));
        }
    }
    if !data.top_data.is_empty() {
        lines.push(
            "\n## Data, Office & DB Artifacts (`ap query -f a=<file> --schema` / `ap read <file>`)"
                .to_string(),
        );
        for dt in &data.top_data {
            lines.push(format!("- `{}` [{}]", dt.path, dt.summary));
        }
    }
    if !data.stale_todo_traps.is_empty() {
        lines.push("\n## Stale TODO Traps (Ignore unless explicitly requested)".to_string());
        for t in &data.stale_todo_traps {
            lines.push(format!("- {t}"));
        }
    }
    format!("{}\n", lines.join("\n"))
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    let (root, focus, max_files, stale_days, as_json) = match cli.subcmd {
        Some(SubCmd::Product { root, write, json }) => {
            let root_p = PathBuf::from(&root);
            if !root_p.exists() {
                eprintln!("[atlas] path not found: {root}");
                return 1;
            }
            let pm = product::build_product_map(&root_p, SKIP_DIRS);
            let md = product::render_product_map(&pm);
            if !write.trim().is_empty() {
                let out_p = if Path::new(&write).is_absolute() {
                    PathBuf::from(&write)
                } else {
                    root_p.join(&write)
                };
                if let Err(e) = fs::write(&out_p, &md) {
                    eprintln!("[atlas] failed to write {}: {e}", out_p.display());
                    return 1;
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&pm).unwrap_or_default());
            } else {
                print!("{md}");
            }
            return 0;
        }
        Some(SubCmd::Impact { symbol, root, json }) => {
            let root_p = PathBuf::from(&root);
            if !root_p.exists() {
                eprintln!("[atlas] path not found: {root}");
                return 1;
            }
            let rep = impact::analyze_symbol_impact(&root_p, &[symbol], SKIP_DIRS);
            if json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            } else {
                println!("{}", impact::render_impact_md(&rep));
            }
            return 0;
        }
        Some(SubCmd::Locate {
            query,
            root,
            top_k,
            json,
        }) => {
            let root_p = PathBuf::from(&root);
            if !root_p.exists() {
                eprintln!("[atlas] path not found: {root}");
                return 1;
            }
            let rep = locate::locate_faults(&root_p, &query, top_k);
            if json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            } else {
                print!("{}", locate::render_locate_md(&rep));
            }
            return 0;
        }
        Some(SubCmd::Trace {
            symbol,
            root,
            depth,
            to,
            sinks,
            json,
        }) => {
            let root_p = PathBuf::from(&root);
            if !root_p.exists() {
                eprintln!("[atlas] path not found: {root}");
                return 1;
            }
            let rep = trace::trace_symbol_chain_to(&root_p, &symbol, to.as_deref(), sinks, depth);
            if json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            } else {
                println!("{}", trace::render_trace_md(&rep));
            }
            return 0;
        }
        Some(SubCmd::Changes { root, base, json }) => {
            let root_p = PathBuf::from(&root);
            if !root_p.exists() {
                eprintln!("[atlas] path not found: {root}");
                return 1;
            }
            let rep = changes::analyze_git_changes(&root_p, Some(&base), SKIP_DIRS);
            if json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            } else {
                println!("{}", changes::render_changes_md(&rep));
            }
            return 0;
        }
        Some(SubCmd::History {
            file,
            symbol,
            lines,
            limit,
            json,
        }) => {
            let file_p = PathBuf::from(&file);
            let sym_opt = (!symbol.trim().is_empty()).then_some(symbol.as_str());
            let lines_opt = (!lines.trim().is_empty()).then_some(lines.as_str());
            let rep = history::analyze_file_history(&file_p, sym_opt, lines_opt, limit);
            if json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            } else {
                println!("{}", history::render_history_md(&rep));
            }
            return if file_p.exists() { 0 } else { 1 };
        }
        Some(SubCmd::Deps {
            target,
            root,
            depth,
            dead,
            json,
        }) => {
            let root_p = PathBuf::from(&root);
            if !root_p.exists() {
                eprintln!("[atlas] path not found: {root}");
                return 1;
            }
            let rep = deps::analyze_module_deps_with_opts(&root_p, &target, depth, dead, SKIP_DIRS);
            if json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            } else {
                println!("{}", deps::render_deps_md(&rep));
            }
            return 0;
        }
        Some(SubCmd::Surface {
            root,
            max_files,
            max_per_axis,
            include_vendor,
            include_binaries,
            json,
        }) => {
            let root_p = PathBuf::from(&root);
            if !root_p.exists() {
                eprintln!("[atlas] path not found: {root}");
                return 1;
            }
            let map = surface::build_surface_map(
                &root_p,
                max_files,
                max_per_axis,
                include_vendor,
                include_binaries,
            );
            if json {
                println!("{}", serde_json::to_string_pretty(&map).unwrap_or_default());
            } else {
                print!("{}", surface::render_surface_md(&map));
            }
            return 0;
        }
        Some(SubCmd::Map {
            root,
            focus,
            max_files,
            stale_days,
            json,
        }) => (root, focus, max_files, stale_days, json),
        None => (cli.root, cli.focus, cli.max_files, cli.stale_days, cli.json),
    };
    let root_p = PathBuf::from(&root);
    if !root_p.exists() {
        eprintln!("[atlas] path not found: {root}");
        return 1;
    }
    let data = scan_workspace(&root_p, &focus, max_files, stale_days);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        print!("{}", render_atlas_md(&data));
    }
    0
}
