use crate::read::{decode_any_bytes, extract_office_or_pdf_plain};
use crate::stats::record_event_ex;
use clap::Parser;
use ignore::{WalkBuilder, WalkState};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    ".next",
    ".sieve",
    ".agents",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchMatch {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub pattern: String,
    pub file: String,
    pub line: usize,
    pub scope: String,
    pub snippet: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub ast_kind: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub captures: BTreeMap<String, String>,
}

#[derive(Parser, Debug)]
#[command(
    name = "search",
    about = "Universal .gitignore-aware regex search with enclosing AST symbol spans + batch multi-pattern + .map/.asar/.vsix/Office/minified support"
)]
struct SearchCli {
    /// Regex or literal pattern to search (or pass `--stdin` for 1 pattern per line)
    #[arg(default_value = "")]
    pattern: String,
    /// Root file or directory to search (default: '.')
    #[arg(default_value = ".")]
    path: String,
    /// Optional additional files or directories to search in the same pass (like `rg pat a b`)
    extra_paths: Vec<String>,
    /// Additional patterns to search in the SAME single pass (repeatable: `--pat A --pat B`)
    #[arg(long = "pat")]
    extra_pats: Vec<String>,
    /// Read additional search patterns from stdin (1 regex per line)
    #[arg(long)]
    stdin: bool,
    /// Case-sensitive matching (default is smart case: case-insensitive unless pattern has uppercase)
    #[arg(short = 's', long)]
    case_sensitive: bool,
    /// Force case-insensitive matching even when pattern has uppercase (like `rg -i`)
    #[arg(short = 'i', long)]
    ignore_case: bool,
    /// Treat pattern as literal string instead of regex (like `rg -F`)
    #[arg(short = 'F', long)]
    fixed_strings: bool,
    /// Accepted for `grep`/`rg -n` muscle-memory compatibility (line numbers are always shown)
    #[arg(short = 'n', long = "line-number")]
    _line_number: bool,
    /// Optional glob extension filter, e.g. `ts,js` or `xlsx,docx`
    #[arg(short = 'e', long = "ext", default_value = "")]
    ext_filter: String,
    /// Include only files matching glob/path filters (repeatable: `--include "*.rs" --include "src/*"`)
    #[arg(long = "include")]
    include: Vec<String>,
    /// Maximum matches to return
    #[arg(long, alias = "max", default_value_t = 50)]
    max_hits: usize,
    /// Context characters on each side when slicing matches inside giant/minified single-line bundles
    #[arg(long, default_value_t = 160)]
    around: usize,
    /// Pretty-format minified JS/JSON match slices
    #[arg(long)]
    pretty: bool,
    /// Enable cross-line multiline regex search (`(?s)` / `\n` across lines)
    #[arg(short = 'm', long)]
    multiline: bool,
    /// Emit full enclosing Tree-sitter AST function/class block around each code match
    #[arg(long)]
    block: bool,
    /// Show N surrounding context lines before & after each match (like `rg -C N`)
    #[arg(short = 'C', long, default_value_t = 0)]
    context: usize,
    /// Show N lines BEFORE each match (like `rg -B N`)
    #[arg(short = 'B', long = "before-context", default_value_t = 0)]
    before_context: usize,
    /// Show N lines AFTER each match (like `rg -A N`)
    #[arg(short = 'A', long = "after-context", default_value_t = 0)]
    after_context: usize,
    /// Invert match: emit non-matching lines (like `rg -v`)
    #[arg(short = 'v', long = "invert-match")]
    invert_match: bool,
    /// Only list unique matching file paths (like `rg -l`)
    #[arg(short = 'l', long)]
    files_only: bool,
    /// Emit ONLY the matched substring(s) from each line (like `grep -o` / `rg -o`)
    #[arg(short = 'o', long = "only-matching")]
    only_matching: bool,
    /// Deduplicate matching snippets/tokens and sort by frequency descending
    #[arg(short = 'u', long)]
    unique: bool,
    /// Omit file paths and scopes in text output (like `grep -h` / `rg --no-filename`)
    #[arg(long = "no-filename", alias = "no-path")]
    no_filename: bool,
    /// Accepted for `grep -E` muscle-memory compatibility (regex is enabled by default)
    #[arg(short = 'E', long = "extended-regexp")]
    _extended_regexp: bool,
    /// Emit per-file match counts (like `rg -c`)
    #[arg(short = 'c', long)]
    count: bool,
    /// Code-only mode: skip non-code docs/configs AND matches inside Tree-sitter comments & string literals
    #[arg(long)]
    code_only: bool,
    /// Production-only mode: skip test/fixture/mock files AND Rust #[cfg(test)]/Python test_* blocks
    #[arg(long)]
    no_tests: bool,
    /// Exclude matching relative paths or glob suffixes (repeatable: `-x fixtures -x *.gen.ts`)
    #[arg(short = 'x', long = "exclude")]
    exclude: Vec<String>,
    /// Structural Tree-sitter AST query across Py/TS/JS/Go/Rust/C (`kind:call`, `kind:fn`, `fetch($URL, $$$)`, `$X == $X`, `Command::new($BIN)`)
    #[arg(long, default_value = "")]
    ast: String,
    /// Maximum characters per returned snippet line (0 = keep default snippet)
    #[arg(long, alias = "max-line-len", default_value_t = 0)]
    width: usize,
    /// Maximum matches per pattern in multi-pattern (`--pat`/`--stdin`) mode (0 = auto fair quota)
    #[arg(long = "per-pattern", default_value_t = 0)]
    per_pattern: usize,
    /// Emit structured JSON output
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy)]
struct SearchOpts {
    around: usize,
    pretty: bool,
    multiline: bool,
    block: bool,
    before_ctx: usize,
    after_ctx: usize,
    invert: bool,
    max_hits: usize,
    per_pattern: usize,
    code_only: bool,
    no_tests: bool,
    only_matching: bool,
    need_scope: bool,
}

fn looks_minified_text(text: &str) -> bool {
    if text.len() <= 512 {
        return false;
    }
    let first_non_empty = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    if first_non_empty.len() > 300 {
        let line_cnt = text.bytes().filter(|&b| b == b'\n').count() + 1;
        if text.len() / line_cnt.max(1) > 300 || (line_cnt <= 5 && text.len() > 2048) {
            return true;
        }
    }
    false
}

fn peek_is_binary_nul(path: &Path) -> bool {
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 512];
    let Ok(n) = f.read(&mut buf) else {
        return false;
    };
    let head = &buf[..n];
    head.iter().filter(|&&b| b == 0).count() > 4
        && !head.starts_with(b"\xFF\xFE")
        && !head.starts_with(b"\xFE\xFF")
}

struct FileAstCache {
    ast_spans: Vec<ap_splice::ast::SymbolSpan>,
    non_code_ranges: Vec<(usize, usize)>,
    test_ranges: Vec<(usize, usize)>,
}

impl FileAstCache {
    fn build(text: &str, ext: &str, is_office: bool, opts: SearchOpts) -> Self {
        let can_ast = !is_office
            && text.len() <= 2 * 1024 * 1024
            && ap_splice::ast::language_for_ext(ext).is_some();
        if !can_ast {
            return Self {
                ast_spans: Vec::new(),
                non_code_ranges: Vec::new(),
                test_ranges: Vec::new(),
            };
        }
        let need_ast_spans = (opts.need_scope || opts.block) && !looks_minified_text(text);
        let ast_spans = if need_ast_spans {
            ap_splice::ast::scan_symbols(text, ext)
        } else {
            Vec::new()
        };
        let non_code_ranges = if opts.code_only {
            ap_splice::ast::collect_non_code_ranges(text, ext)
        } else {
            Vec::new()
        };
        let test_ranges = if opts.no_tests {
            ap_splice::ast::collect_test_block_ranges(text, ext)
        } else {
            Vec::new()
        };
        Self {
            ast_spans,
            non_code_ranges,
            test_ranges,
        }
    }
}

fn emit_search_err(as_json: bool, t0: Instant, msg: &str) {
    record_event_ex(
        "search",
        0,
        0,
        0,
        0,
        "search-err",
        false,
        t0.elapsed().as_millis() as u64,
        Some(msg),
    );
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "ok": false, "error": msg })).unwrap_or_default()
        );
    } else {
        eprintln!("{msg}");
    }
}

fn is_non_code_ext(ext: &str) -> bool {
    matches!(
        ext,
        "md" | "txt"
            | "rst"
            | "json"
            | "jsonc"
            | "jsonl"
            | "toml"
            | "yaml"
            | "yml"
            | "xml"
            | "csv"
            | "tsv"
            | "log"
            | "docx"
            | "xlsx"
            | "pptx"
            | "pdf"
            | "map"
            | "html"
            | "htm"
            | "css"
            | "svg"
    )
}

fn is_test_rel_path(rel: &str) -> bool {
    let low = rel.replace('\\', "/").to_ascii_lowercase();
    for seg in low.split('/') {
        if matches!(
            seg,
            "tests" | "test" | "__tests__" | "fixtures" | "fixture" | "mocks" | "mock"
        ) {
            return true;
        }
    }
    let fname = low.rsplit('/').next().unwrap_or(low.as_str());
    fname.contains(".test.")
        || fname.contains(".spec.")
        || fname.ends_with("_test.rs")
        || fname.ends_with("_test.go")
        || fname.ends_with("_test.ts")
        || fname.ends_with("_test.js")
        || (fname.starts_with("test_") && fname.ends_with(".py"))
}

fn glob_match_ci(pat: &str, text: &str) -> bool {
    let p = pat.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_p = Some(pi);
            pi += 1;
            star_t = ti;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

fn matches_include_paths(rel: &str, includes: &[String]) -> bool {
    if includes.is_empty() {
        return true;
    }
    let rel_norm = rel.replace('\\', "/");
    let fname = rel_norm.rsplit('/').next().unwrap_or(rel_norm.as_str());
    for raw in includes {
        let p = raw.trim().trim_start_matches("./");
        if p.is_empty() {
            continue;
        }
        if p.contains('*') || p.contains('?') {
            if glob_match_ci(p, &rel_norm) || (!p.contains('/') && glob_match_ci(p, fname)) {
                return true;
            }
        } else if rel_norm
            .to_ascii_lowercase()
            .contains(&p.to_ascii_lowercase())
        {
            return true;
        }
    }
    false
}

fn matches_exclude(rel: &str, excludes: &[String]) -> bool {
    if excludes.is_empty() {
        return false;
    }
    let rel_low = rel.replace('\\', "/").to_ascii_lowercase();
    for raw in excludes {
        let p = raw.trim().trim_start_matches("./").to_ascii_lowercase();
        if p.is_empty() {
            continue;
        }
        if p.contains('*') || p.contains('?') {
            if glob_match_ci(&p, &rel_low) {
                return true;
            }
        } else if rel_low.contains(&p) {
            return true;
        }
    }
    false
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    idx = idx.min(s.len());
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn ceil_char_boundary(s: &str, mut idx: usize) -> usize {
    idx = idx.min(s.len());
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

#[allow(clippy::too_many_arguments)]
fn push_text_matches(
    pat_label: &str,
    text: &str,
    rel: &str,
    ext: &str,
    is_office: bool,
    re: &Regex,
    opts: SearchOpts,
    ast_cache: &FileAstCache,
    filtered_non_code: &AtomicUsize,
    filtered_tests: &AtomicUsize,
    matches: &mut Vec<SearchMatch>,
) {
    if !opts.invert && !re.is_match(text) {
        return;
    }
    let ast_spans = &ast_cache.ast_spans;
    let non_code_ranges = &ast_cache.non_code_ranges;
    let test_ranges = &ast_cache.test_ranges;
    let allow_span = |abs_s: usize, abs_e: usize| -> bool {
        if !test_ranges.is_empty() && ap_splice::ast::range_is_covered(test_ranges, abs_s, abs_e) {
            filtered_tests.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if !non_code_ranges.is_empty()
            && ap_splice::ast::range_is_covered(non_code_ranges, abs_s, abs_e)
        {
            filtered_non_code.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    };
    let all_lines: Vec<&str> = text.lines().collect();

    if opts.multiline && !opts.invert {
        for m in re.find_iter(text) {
            if !allow_span(m.start(), m.end()) {
                continue;
            }
            let ln_no = text[..m.start()].bytes().filter(|&b| b == b'\n').count() + 1;
            let enc = ast_spans
                .iter()
                .filter(|sp| sp.start_line <= ln_no && ln_no <= sp.end_line)
                .min_by_key(|sp| sp.end_line.saturating_sub(sp.start_line));
            let scope = enc
                .map(|sp| {
                    format!(
                        "{} {} L{}-L{}",
                        sp.kind, sp.qual, sp.start_line, sp.end_line
                    )
                })
                .unwrap_or_default();
            let snip = if opts.only_matching {
                m.as_str().trim().chars().take(300).collect()
            } else if opts.block {
                if let Some(sp) = enc {
                    let s = sp.start_line.saturating_sub(1);
                    let e = sp.end_line.min(all_lines.len()).min(s + 30);
                    all_lines[s..e].join("\n")
                } else {
                    m.as_str().chars().take(300).collect()
                }
            } else {
                m.as_str().trim().chars().take(240).collect()
            };
            matches.push(SearchMatch {
                pattern: pat_label.to_string(),
                file: rel.to_string(),
                line: ln_no,
                scope,
                snippet: snip,
                ast_kind: String::new(),
                captures: BTreeMap::new(),
            });
            if matches.len() >= opts.max_hits {
                return;
            }
        }
        return;
    }

    let mut line_byte_start = 0usize;
    for (idx, ln) in text.split('\n').enumerate() {
        let ln_clean = ln.strip_suffix('\r').unwrap_or(ln);
        let ln_no = idx + 1;
        let line_matched = re.is_match(ln_clean);
        let emit_line = if opts.invert {
            !line_matched
        } else {
            line_matched
        };
        if emit_line {
            if opts.only_matching && !opts.invert {
                let enc = ast_spans
                    .iter()
                    .filter(|sp| sp.start_line <= ln_no && ln_no <= sp.end_line)
                    .min_by_key(|sp| sp.end_line.saturating_sub(sp.start_line));
                let scope = enc
                    .map(|sp| {
                        format!(
                            "{} {} L{}-L{}",
                            sp.kind, sp.qual, sp.start_line, sp.end_line
                        )
                    })
                    .unwrap_or_default();
                for m in re.find_iter(ln_clean) {
                    if !allow_span(line_byte_start + m.start(), line_byte_start + m.end()) {
                        continue;
                    }
                    let tok = m.as_str().trim();
                    if tok.is_empty() {
                        continue;
                    }
                    matches.push(SearchMatch {
                        pattern: pat_label.to_string(),
                        file: rel.to_string(),
                        line: ln_no,
                        scope: scope.clone(),
                        snippet: tok.chars().take(300).collect(),
                        ast_kind: String::new(),
                        captures: BTreeMap::new(),
                    });
                    if matches.len() >= opts.max_hits {
                        return;
                    }
                }
            } else if !opts.invert && ln_clean.len() > 300 {
                // Minified / giant single-line bundle: emit every match as a byte-window slice!
                for m in re.find_iter(ln_clean) {
                    if !allow_span(line_byte_start + m.start(), line_byte_start + m.end()) {
                        continue;
                    }
                    let s = floor_char_boundary(ln_clean, m.start().saturating_sub(opts.around));
                    let e = ceil_char_boundary(ln_clean, m.end().saturating_add(opts.around));
                    let raw_snip = &ln_clean[s..e];
                    let snip = if opts.pretty {
                        crate::binary::pretty_format_js_snippet(raw_snip)
                    } else {
                        raw_snip.to_string()
                    };
                    let abs_off = line_byte_start + m.start();
                    matches.push(SearchMatch {
                        pattern: pat_label.to_string(),
                        file: rel.to_string(),
                        line: ln_no,
                        scope: format!("minified @off={abs_off}"),
                        snippet: snip,
                        ast_kind: String::new(),
                        captures: BTreeMap::new(),
                    });
                    if matches.len() >= opts.max_hits {
                        return;
                    }
                }
            } else {
                if !opts.invert && (!non_code_ranges.is_empty() || !test_ranges.is_empty()) {
                    let mut kept_any = false;
                    for m in re.find_iter(ln_clean) {
                        if allow_span(line_byte_start + m.start(), line_byte_start + m.end()) {
                            kept_any = true;
                        }
                    }
                    if !kept_any {
                        line_byte_start += ln.len() + 1;
                        continue;
                    }
                }
                let enc = ast_spans
                    .iter()
                    .filter(|sp| sp.start_line <= ln_no && ln_no <= sp.end_line)
                    .min_by_key(|sp| sp.end_line.saturating_sub(sp.start_line));
                let scope = enc
                    .map(|sp| {
                        format!(
                            "{} {} L{}-L{}",
                            sp.kind, sp.qual, sp.start_line, sp.end_line
                        )
                    })
                    .unwrap_or_else(|| {
                        if is_office {
                            ext.to_ascii_uppercase()
                        } else {
                            String::new()
                        }
                    });
                let snip: String = if opts.block {
                    if let Some(sp) = enc {
                        let s = sp.start_line.saturating_sub(1);
                        let e = sp.end_line.min(all_lines.len()).min(s + 30);
                        all_lines[s..e].join("\n")
                    } else {
                        ln_clean.trim().chars().take(180).collect()
                    }
                } else if (opts.before_ctx > 0 || opts.after_ctx > 0) && !all_lines.is_empty() {
                    let s = idx.saturating_sub(opts.before_ctx);
                    let e = (idx + opts.after_ctx + 1).min(all_lines.len());
                    (s..e)
                        .map(|k| {
                            let mark = if k == idx { '>' } else { ' ' };
                            let txt: String = all_lines[k].chars().take(160).collect();
                            format!("{mark}L{}: {txt}", k + 1)
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    ln_clean.trim().chars().take(180).collect()
                };
                matches.push(SearchMatch {
                    pattern: pat_label.to_string(),
                    file: rel.to_string(),
                    line: ln_no,
                    scope,
                    snippet: snip,
                    ast_kind: String::new(),
                    captures: BTreeMap::new(),
                });
                if matches.len() >= opts.max_hits {
                    return;
                }
            }
        }
        line_byte_start += ln.len() + 1;
    }
}

fn build_search_regex(
    pat: &str,
    force_case: bool,
    force_ignore_case: bool,
    fixed_strings: bool,
    multiline: bool,
) -> Result<Regex, String> {
    let case_insens = if force_ignore_case {
        true
    } else if force_case {
        false
    } else {
        !pat.chars().any(|c| c.is_uppercase())
    };
    let effective = if fixed_strings {
        regex::escape(pat)
    } else {
        pat.to_string()
    };
    RegexBuilder::new(&effective)
        .case_insensitive(case_insens)
        .multi_line(multiline && !fixed_strings)
        .dot_matches_new_line(multiline && !fixed_strings)
        .build()
        .or_else(|_| {
            RegexBuilder::new(&regex::escape(pat))
                .case_insensitive(case_insens)
                .build()
        })
        .map_err(|e| format!("invalid pattern `{pat}`: {e}"))
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match SearchCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    let t0 = Instant::now();
    let ast_raw = cli.ast.trim();
    let ast_query: Option<ap_splice::ast_search::AstQuery> = if ast_raw.is_empty() {
        None
    } else {
        match ap_splice::ast_search::AstQuery::parse(ast_raw) {
            Ok(q) => Some(q),
            Err(e) => {
                emit_search_err(cli.json, t0, &e);
                return 2;
            }
        }
    };
    let mut cli_pattern = cli.pattern.clone();
    let mut cli_path = cli.path.clone();
    if ast_query.is_some() && !cli_pattern.trim().is_empty() && cli_path == "." {
        let pat_as_path = crate::ls::normalize_cli_path(&cli_pattern);
        if Path::new(&pat_as_path).exists() {
            cli_path = std::mem::take(&mut cli_pattern);
        }
    }

    let mut raw_pats: Vec<String> = Vec::new();
    if !cli_pattern.trim().is_empty() {
        raw_pats.push(cli_pattern);
    }
    for ep in &cli.extra_pats {
        if !ep.trim().is_empty() && !raw_pats.contains(ep) {
            raw_pats.push(ep.clone());
        }
    }
    if cli.stdin {
        let mut buf = String::new();
        let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf);
        for ln in buf.lines() {
            let t = ln.trim();
            if !t.is_empty() && !t.starts_with('#') && !raw_pats.iter().any(|p| p == t) {
                raw_pats.push(t.to_string());
            }
        }
    }
    if raw_pats.is_empty() && ast_query.is_none() {
        emit_search_err(
            cli.json,
            t0,
            "[ap search] provide a search pattern or `--ast <expr>`",
        );
        return 2;
    }
    let multi_mode = raw_pats.len() > 1;
    let mut compiled: Vec<(String, Regex)> = Vec::new();
    for p in raw_pats.into_iter().take(20) {
        match build_search_regex(
            &p,
            cli.case_sensitive,
            cli.ignore_case,
            cli.fixed_strings,
            cli.multiline,
        ) {
            Ok(r) => compiled.push((p, r)),
            Err(e) => {
                emit_search_err(cli.json, t0, &format!("[ap search] {e}"));
                return 2;
            }
        }
    }
    let combined_label = if let Some(aq_raw) = (!ast_raw.is_empty()).then_some(ast_raw) {
        if compiled.is_empty() {
            format!("ast:{aq_raw}")
        } else {
            format!(
                "ast:{aq_raw} + {}",
                compiled
                    .iter()
                    .map(|(p, _)| p.as_str())
                    .collect::<Vec<_>>()
                    .join(" | ")
            )
        }
    } else {
        compiled
            .iter()
            .map(|(p, _)| p.as_str())
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let s_opts = SearchOpts {
        around: cli.around,
        pretty: cli.pretty,
        multiline: cli.multiline,
        block: cli.block,
        before_ctx: cli.before_context.max(cli.context),
        after_ctx: cli.after_context.max(cli.context),
        invert: cli.invert_match,
        max_hits: if cli.count || cli.files_only || cli.unique {
            cli.max_hits.max(500)
        } else {
            cli.max_hits
        },
        per_pattern: cli.per_pattern,
        code_only: cli.code_only,
        no_tests: cli.no_tests,
        only_matching: cli.only_matching,
        need_scope: !cli.files_only && !cli.count && !cli.no_filename,
    };

    let multi_targets = !cli.extra_paths.is_empty();
    let mut targets: Vec<(String, PathBuf, bool)> = Vec::new();
    let mut seen_canon: HashSet<PathBuf> = HashSet::new();
    if !multi_targets {
        let norm_root_str = crate::ls::normalize_cli_path(&cli_path);
        let root = Path::new(&norm_root_str);
        if root.exists() {
            let root_canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
            let is_f = root_canon.is_file();
            targets.push((String::new(), root_canon, is_f));
        } else if norm_root_str.contains('*') || norm_root_str.contains('?') {
            let expanded = expand_glob_target_paths(&norm_root_str);
            if expanded.is_empty() {
                emit_search_err(
                    cli.json,
                    t0,
                    &format!("[ap search] path not found: {norm_root_str}"),
                );
                return 1;
            }
            for (disp, p) in expanded {
                let canon = fs::canonicalize(&p).unwrap_or(p);
                if !seen_canon.insert(canon.clone()) {
                    continue;
                }
                let is_f = canon.is_file();
                let prefix = if disp == "." || disp.is_empty() {
                    String::new()
                } else {
                    disp
                };
                targets.push((prefix, canon, is_f));
            }
        } else {
            emit_search_err(
                cli.json,
                t0,
                &format!("[ap search] path not found: {norm_root_str}"),
            );
            return 1;
        }
    } else {
        for raw_t in std::iter::once(&cli_path).chain(cli.extra_paths.iter()) {
            let norm = crate::ls::normalize_cli_path(raw_t);
            let p = Path::new(&norm);
            if p.exists() {
                let canon = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
                if !seen_canon.insert(canon.clone()) {
                    continue;
                }
                let is_f = canon.is_file();
                let disp = norm.replace('\\', "/").trim_end_matches('/').to_string();
                let prefix = if disp == "." || disp.is_empty() {
                    String::new()
                } else {
                    disp
                };
                targets.push((prefix, canon, is_f));
            } else if norm.contains('*') || norm.contains('?') {
                let expanded = expand_glob_target_paths(&norm);
                if expanded.is_empty() {
                    eprintln!("[ap search] warning: path not found: {norm}");
                    continue;
                }
                for (disp, ep) in expanded {
                    let canon = fs::canonicalize(&ep).unwrap_or(ep);
                    if !seen_canon.insert(canon.clone()) {
                        continue;
                    }
                    let is_f = canon.is_file();
                    let prefix = if disp == "." || disp.is_empty() {
                        String::new()
                    } else {
                        disp
                    };
                    targets.push((prefix, canon, is_f));
                }
            } else {
                eprintln!("[ap search] warning: path not found: {norm}");
            }
        }
        if targets.is_empty() {
            emit_search_err(cli.json, t0, "[ap search] no valid search paths found");
            return 1;
        }
    }
    let mut ext_allow: HashSet<String> = cli
        .ext_filter
        .split(',')
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let mut include_paths: Vec<String> = Vec::new();
    for inc in &cli.include {
        let t = inc.trim().trim_start_matches("./");
        if t.is_empty() {
            continue;
        }
        if let Some(suf) = t.strip_prefix("*.") {
            if !suf.contains('/') && !suf.contains('*') {
                ext_allow.insert(suf.to_ascii_lowercase());
                continue;
            }
        }
        include_paths.push(t.to_string());
    }
    let ast_query_arc = Arc::new(ast_query);
    let compiled_arc = Arc::new(compiled);
    let ext_allow_arc = Arc::new(ext_allow);
    let include_arc = Arc::new(include_paths);
    let exclude_arc = Arc::new(cli.exclude);
    let all_matches: Arc<Mutex<Vec<SearchMatch>>> = Arc::new(Mutex::new(Vec::new()));
    let hit_counter = Arc::new(AtomicUsize::new(0));
    let scanned_files_cnt = Arc::new(AtomicUsize::new(0));
    let total_bytes_cnt = Arc::new(AtomicU64::new(0));
    let filtered_non_code_cnt = Arc::new(AtomicUsize::new(0));
    let filtered_tests_cnt = Arc::new(AtomicUsize::new(0));
    let hit_cap = if multi_mode {
        s_opts
            .max_hits
            .saturating_mul(compiled_arc.len().min(8))
            .max(s_opts.max_hits)
    } else {
        s_opts.max_hits
    };

    #[allow(clippy::too_many_arguments)]
    fn push_compiled_text_hits(
        compiled: &[(String, Regex)],
        multi_mode: bool,
        text: &str,
        rel: &str,
        ext: &str,
        is_office: bool,
        s_opts: SearchOpts,
        filtered_non_code: &AtomicUsize,
        filtered_tests: &AtomicUsize,
        local_matches: &mut Vec<SearchMatch>,
    ) {
        let pat_cap = if s_opts.per_pattern > 0 {
            s_opts.per_pattern
        } else if multi_mode && compiled.len() > 1 {
            (s_opts.max_hits / compiled.len()).max(5)
        } else {
            s_opts.max_hits
        };
        let pat_opts = SearchOpts {
            max_hits: pat_cap,
            ..s_opts
        };
        let mut ast_cache: Option<FileAstCache> = None;
        for (pl, r) in compiled {
            if !s_opts.invert && !r.is_match(text) {
                continue;
            }
            let cache =
                ast_cache.get_or_insert_with(|| FileAstCache::build(text, ext, is_office, s_opts));
            let lbl = if multi_mode { pl.as_str() } else { "" };
            let mut pat_hits = Vec::new();
            push_text_matches(
                lbl,
                text,
                rel,
                ext,
                is_office,
                r,
                pat_opts,
                cache,
                filtered_non_code,
                filtered_tests,
                &mut pat_hits,
            );
            local_matches.extend(pat_hits);
            if !multi_mode && local_matches.len() >= s_opts.max_hits {
                break;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_file(
        p: &Path,
        root_canon: &Path,
        rel_prefix: &str,
        explicit_file: bool,
        ext_allow: &HashSet<String>,
        includes: &[String],
        excludes: &[String],
        ast_query: Option<&ap_splice::ast_search::AstQuery>,
        compiled: &[(String, Regex)],
        multi_mode: bool,
        s_opts: SearchOpts,
        scanned_files_cnt: &AtomicUsize,
        total_bytes_cnt: &AtomicU64,
        filtered_non_code: &AtomicUsize,
        filtered_tests: &AtomicUsize,
    ) -> Vec<SearchMatch> {
        let mut local_matches = Vec::new();
        if !p.is_file() {
            return local_matches;
        }
        let rel = if explicit_file {
            if !rel_prefix.is_empty() {
                rel_prefix.to_string()
            } else {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string()
            }
        } else {
            let sub_rel = p
                .strip_prefix(root_canon)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/");
            if rel_prefix.is_empty() {
                sub_rel
            } else {
                format!("{rel_prefix}/{sub_rel}")
            }
        };
        if !matches_include_paths(&rel, includes) {
            return local_matches;
        }
        if matches_exclude(&rel, excludes) {
            return local_matches;
        }
        let ext = p
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !ext_allow.is_empty() && !ext_allow.contains(&ext) {
            return local_matches;
        }
        if s_opts.code_only && is_non_code_ext(&ext) {
            return local_matches;
        }
        if s_opts.no_tests && is_test_rel_path(&rel) {
            return local_matches;
        }
        if matches!(
            ext.as_str(),
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "ico"
                | "bmp"
                | "tif"
                | "tiff"
                | "cur"
                | "woff"
                | "woff2"
                | "ttf"
                | "otf"
                | "eot"
                | "mp3"
                | "mp4"
                | "wav"
                | "ogg"
                | "avi"
                | "mov"
                | "mkv"
                | "flac"
                | "sqlite"
                | "sqlite-wal"
                | "sqlite-shm"
                | "db"
                | "ldb"
                | "sst"
                | "lock"
        ) {
            return local_matches;
        }
        let is_bin_ext = matches!(
            ext.as_str(),
            "exe"
                | "dll"
                | "sys"
                | "ocx"
                | "cpl"
                | "efi"
                | "so"
                | "ko"
                | "dylib"
                | "node"
                | "wasm"
                | "bin"
        );
        let is_dir_walk_skip_bin = is_bin_ext
            || matches!(
                ext.as_str(),
                "pdb"
                    | "lib"
                    | "obj"
                    | "o"
                    | "a"
                    | "rlib"
                    | "rmeta"
                    | "i64"
                    | "idb"
                    | "dmp"
                    | "evtx"
                    | "etl"
                    | "vmdk"
                    | "qcow2"
                    | "iso"
                    | "msi"
                    | "cab"
                    | "7z"
                    | "rar"
                    | "pak"
                    | "dat"
                    | "pyc"
                    | "pyo"
                    | "class"
                    | "nupkg"
                    | "apk"
                    | "ipa"
                    | "deb"
                    | "rpm"
                    | "dex"
                    | "zip"
                    | "vsix"
                    | "jar"
                    | "war"
                    | "ear"
                    | "whl"
                    | "tar"
                    | "tgz"
                    | "gz"
                    | "bz2"
                    | "xz"
                    | "zst"
            );
        if is_dir_walk_skip_bin && !explicit_file && ext_allow.is_empty() {
            return local_matches;
        }
        let Ok(meta) = p.metadata() else {
            return local_matches;
        };
        let is_archive_ext = matches!(
            ext.as_str(),
            "asar" | "zip" | "vsix" | "jar" | "war" | "ear" | "whl" | "tar" | "tgz" | "gz"
        );
        let is_office_ext = matches!(ext.as_str(), "docx" | "xlsx" | "pptx" | "pdf");
        let size_cap = if explicit_file {
            if is_archive_ext {
                256 * 1024 * 1024
            } else if is_bin_ext {
                128 * 1024 * 1024
            } else {
                64 * 1024 * 1024
            }
        } else {
            16 * 1024 * 1024
        };
        if meta.len() > size_cap {
            return local_matches;
        }
        // For files >64 KiB during directory walks, peek only 512 bytes for NUL binary detection
        // before reading multi-megabyte blobs into RAM.
        if !explicit_file
            && meta.len() > 64 * 1024
            && !is_archive_ext
            && !is_bin_ext
            && !is_office_ext
            && ext != "pyc"
            && peek_is_binary_nul(p)
        {
            return local_matches;
        }
        let Ok(bytes) = fs::read(p) else {
            return local_matches;
        };
        scanned_files_cnt.fetch_add(1, Ordering::Relaxed);
        total_bytes_cnt.fetch_add(bytes.len() as u64, Ordering::Relaxed);

        // SourceMap v3 embedded original sources search (`.js.map` / `.map`)
        if ext == "map" {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if crate::inspect::is_sourcemap_v3(&v) {
                    if let (Some(srcs), Some(contents)) = (
                        v.get("sources").and_then(|x| x.as_array()),
                        v.get("sourcesContent").and_then(|x| x.as_array()),
                    ) {
                        for (idx, s_val) in srcs.iter().enumerate() {
                            let Some(sname) = s_val.as_str() else {
                                continue;
                            };
                            let Some(body) = contents.get(idx).and_then(|x| x.as_str()) else {
                                continue;
                            };
                            let eext = Path::new(sname)
                                .extension()
                                .and_then(|s| s.to_str())
                                .unwrap_or("js")
                                .to_ascii_lowercase();
                            let virt_rel = format!("{rel}::{sname}");
                            let mut ast_cache: Option<FileAstCache> = None;
                            for (pl, r) in compiled {
                                if !s_opts.invert && !r.is_match(body) {
                                    continue;
                                }
                                let cache = ast_cache.get_or_insert_with(|| {
                                    FileAstCache::build(body, &eext, false, s_opts)
                                });
                                let lbl = if multi_mode { pl.as_str() } else { "" };
                                push_text_matches(
                                    lbl,
                                    body,
                                    &virt_rel,
                                    &eext,
                                    false,
                                    r,
                                    s_opts,
                                    cache,
                                    filtered_non_code,
                                    filtered_tests,
                                    &mut local_matches,
                                );
                                if local_matches.len() >= s_opts.max_hits {
                                    return local_matches;
                                }
                            }
                        }
                    }
                    return local_matches;
                }
            }
        }

        // Virtual Electron .asar archive search (zero extraction!)
        if ext == "asar" {
            if let Ok((base, entries)) = crate::binary::parse_asar_index(&bytes) {
                for ent in entries {
                    if ent.unpacked || ent.size == 0 || ent.size > 32 * 1024 * 1024 {
                        continue;
                    }
                    let eext = Path::new(&ent.path)
                        .extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if !matches!(
                        eext.as_str(),
                        "js" | "mjs"
                            | "cjs"
                            | "ts"
                            | "tsx"
                            | "jsx"
                            | "json"
                            | "html"
                            | "htm"
                            | "css"
                            | "xml"
                            | "txt"
                            | "md"
                            | "yml"
                            | "yaml"
                            | "map"
                    ) {
                        continue;
                    }
                    let st = base.saturating_add(ent.offset);
                    let en = st.saturating_add(ent.size);
                    if en <= bytes.len() {
                        let txt = decode_any_bytes(&bytes[st..en]).0;
                        let virt_rel = format!("{rel}::{}", ent.path);
                        let mut ast_cache: Option<FileAstCache> = None;
                        for (pl, r) in compiled {
                            if !s_opts.invert && !r.is_match(&txt) {
                                continue;
                            }
                            let cache = ast_cache.get_or_insert_with(|| {
                                FileAstCache::build(&txt, &eext, false, s_opts)
                            });
                            let lbl = if multi_mode { pl.as_str() } else { "" };
                            push_text_matches(
                                lbl,
                                &txt,
                                &virt_rel,
                                &eext,
                                false,
                                r,
                                s_opts,
                                cache,
                                filtered_non_code,
                                filtered_tests,
                                &mut local_matches,
                            );
                            if local_matches.len() >= s_opts.max_hits {
                                return local_matches;
                            }
                        }
                    }
                }
            }
            return local_matches;
        }

        // Virtual .zip / .vsix / .jar / .war / .ear / .whl archive search (includes Java `.class` Constant Pool scanning!)
        if matches!(ext.as_str(), "zip" | "vsix" | "jar" | "war" | "ear" | "whl")
            && (explicit_file || !ext_allow.is_empty())
        {
            if let Ok(mut za) = zip::ZipArchive::new(std::io::Cursor::new(&bytes)) {
                for i in 0..za.len() {
                    if let Ok(mut zf) = za.by_index(i) {
                        if zf.is_dir() || zf.size() > 8 * 1024 * 1024 {
                            continue;
                        }
                        let nm = zf.name().replace('\\', "/");
                        let eext = Path::new(&nm)
                            .extension()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if !matches!(
                            eext.as_str(),
                            "js" | "mjs"
                                | "cjs"
                                | "ts"
                                | "json"
                                | "html"
                                | "xml"
                                | "py"
                                | "txt"
                                | "md"
                                | "yml"
                                | "yaml"
                                | "properties"
                                | "class"
                                | "pyc"
                        ) {
                            continue;
                        }
                        let mut eb = Vec::new();
                        if std::io::Read::read_to_end(&mut zf, &mut eb).is_ok() {
                            let txt = if eext == "pyc" || crate::binary::is_pyc_magic(&eb) {
                                crate::binary::extract_pyc_searchable_text(&eb)
                            } else if eext == "class" {
                                crate::binary::extract_java_class_searchable_text(&eb)
                            } else {
                                decode_any_bytes(&eb).0
                            };
                            let virt_rel = format!("{rel}::{nm}");
                            push_compiled_text_hits(
                                compiled,
                                multi_mode,
                                &txt,
                                &virt_rel,
                                &eext,
                                false,
                                s_opts,
                                filtered_non_code,
                                filtered_tests,
                                &mut local_matches,
                            );
                            let cap = if multi_mode {
                                s_opts.max_hits.saturating_mul(compiled.len().min(8))
                            } else {
                                s_opts.max_hits
                            };
                            if local_matches.len() >= cap {
                                return local_matches;
                            }
                        }
                    }
                }
            }
            return local_matches;
        }

        // Virtual `.tar` / `.tgz` / `.tar.gz` archive search (supports GNU @LongLink!)
        let rel_low = rel.to_ascii_lowercase();
        if (ext == "tar" || ext == "tgz" || rel_low.ends_with(".tar.gz"))
            && (explicit_file || !ext_allow.is_empty())
        {
            let tar_buf: std::borrow::Cow<[u8]> = if ext == "tgz" || rel_low.ends_with(".tar.gz") {
                let mut ubuf = Vec::new();
                let dec = flate2::read::GzDecoder::new(std::io::Cursor::new(&bytes));
                let _ = std::io::Read::read_to_end(
                    &mut std::io::Read::take(dec, 16 * 1024 * 1024),
                    &mut ubuf,
                );
                std::borrow::Cow::Owned(ubuf)
            } else {
                std::borrow::Cow::Borrowed(&bytes)
            };
            for ent in crate::binary::parse_tar_index(&tar_buf) {
                if ent.size == 0 || ent.size > 4 * 1024 * 1024 {
                    continue;
                }
                let Some(eb) = tar_buf.get(ent.offset..ent.offset + ent.size) else {
                    continue;
                };
                if crate::binary::is_binary_magic(eb)
                    && !crate::binary::is_java_class_magic(eb)
                    && !crate::binary::is_pyc_magic(eb)
                {
                    continue;
                }
                let eext = Path::new(&ent.path)
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let txt = if eext == "pyc" || crate::binary::is_pyc_magic(eb) {
                    crate::binary::extract_pyc_searchable_text(eb)
                } else if crate::binary::is_java_class_magic(eb) {
                    crate::binary::extract_java_class_searchable_text(eb)
                } else {
                    decode_any_bytes(eb).0
                };
                let virt_rel = format!("{rel}::{}", ent.path);
                push_compiled_text_hits(
                    compiled,
                    multi_mode,
                    &txt,
                    &virt_rel,
                    &eext,
                    false,
                    s_opts,
                    filtered_non_code,
                    filtered_tests,
                    &mut local_matches,
                );
                let cap = if multi_mode {
                    s_opts.max_hits.saturating_mul(compiled.len().min(8))
                } else {
                    s_opts.max_hits
                };
                if local_matches.len() >= cap {
                    return local_matches;
                }
            }
            return local_matches;
        }

        // CPython .pyc Marshal v4 + bytecode search when explicitly targeted or --ext pyc
        if ext == "pyc" || (explicit_file && crate::binary::is_pyc_magic(&bytes)) {
            let txt = crate::binary::extract_pyc_searchable_text(&bytes);
            if !txt.is_empty() {
                push_compiled_text_hits(
                    compiled,
                    multi_mode,
                    &txt,
                    &rel,
                    "py",
                    false,
                    s_opts,
                    filtered_non_code,
                    filtered_tests,
                    &mut local_matches,
                );
            }
            return local_matches;
        }

        // Binary ASCII + Windows UTF-16LE strings search when explicitly targeted
        if is_bin_ext || (explicit_file && crate::binary::is_binary_magic(&bytes)) {
            for (pl, _) in compiled {
                let lbl = if multi_mode {
                    pl.clone()
                } else {
                    String::new()
                };
                let md = crate::binary::inspect_binary_md(&bytes, Some(pl), s_opts.max_hits);
                for (idx, ln) in md.lines().enumerate() {
                    if ln.starts_with("[ascii ") || ln.starts_with("[utf16le ") {
                        local_matches.push(SearchMatch {
                            pattern: lbl.clone(),
                            file: rel.clone(),
                            line: idx + 1,
                            scope: "BINARY".to_string(),
                            snippet: ln.chars().take(200).collect(),
                            ast_kind: String::new(),
                            captures: BTreeMap::new(),
                        });
                        if local_matches.len() >= s_opts.max_hits {
                            return local_matches;
                        }
                    }
                }
            }
            return local_matches;
        }

        let is_office = matches!(ext.as_str(), "docx" | "xlsx" | "pptx" | "pdf");
        if ast_query.is_some() && (is_office || ap_splice::ast::language_for_ext(&ext).is_none()) {
            return local_matches;
        }
        let text = if is_office {
            match extract_office_or_pdf_plain(&bytes, &ext) {
                Ok(s) => s,
                Err(_) => return local_matches,
            }
        } else {
            if bytes.iter().take(512).filter(|&&b| b == 0).count() > 4
                && !bytes.starts_with(b"\xFF\xFE")
                && !bytes.starts_with(b"\xFE\xFF")
            {
                return local_matches;
            }
            decode_any_bytes(&bytes).0
        };

        if let Some(aq) = ast_query {
            let test_ranges = if s_opts.no_tests {
                ap_splice::ast::collect_test_block_ranges(&text, &ext)
            } else {
                Vec::new()
            };
            let ast_hits =
                ap_splice::ast_search::search_ast_source(&text, &ext, aq, s_opts.max_hits);
            for ah in ast_hits {
                if !test_ranges.is_empty()
                    && ap_splice::ast::range_is_covered(&test_ranges, ah.start_byte, ah.end_byte)
                {
                    filtered_tests.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let raw_span = &text[ah.start_byte.min(text.len())..ah.end_byte.min(text.len())];
                if !compiled.is_empty() && !compiled.iter().any(|(_, r)| r.is_match(raw_span)) {
                    continue;
                }
                let snip = if s_opts.block {
                    raw_span.lines().take(30).collect::<Vec<_>>().join("\n")
                } else {
                    ah.snippet
                };
                local_matches.push(SearchMatch {
                    pattern: String::new(),
                    file: rel.clone(),
                    line: ah.line,
                    scope: ah.scope,
                    snippet: snip,
                    ast_kind: ah.kind,
                    captures: ah.captures,
                });
                if local_matches.len() >= s_opts.max_hits {
                    break;
                }
            }
            return local_matches;
        }

        push_compiled_text_hits(
            compiled,
            multi_mode,
            &text,
            &rel,
            &ext,
            is_office,
            s_opts,
            filtered_non_code,
            filtered_tests,
            &mut local_matches,
        );
        local_matches
    }

    for (rel_prefix, target_canon, is_explicit_file) in targets {
        if hit_counter.load(Ordering::Relaxed) >= hit_cap {
            break;
        }
        if is_explicit_file {
            let local = process_file(
                &target_canon,
                &target_canon,
                &rel_prefix,
                true,
                &ext_allow_arc,
                &include_arc,
                &exclude_arc,
                ast_query_arc.as_ref().as_ref(),
                &compiled_arc,
                multi_mode,
                s_opts,
                &scanned_files_cnt,
                &total_bytes_cnt,
                &filtered_non_code_cnt,
                &filtered_tests_cnt,
            );
            if !local.is_empty() {
                let added = local.len();
                if let Ok(mut guard) = all_matches.lock() {
                    guard.extend(local);
                }
                hit_counter.fetch_add(added, Ordering::Relaxed);
            }
        } else {
            let root_canon_arc = Arc::new(target_canon.clone());
            let rel_prefix_arc = Arc::new(rel_prefix);
            let walker = WalkBuilder::new(&target_canon)
                .hidden(false)
                .git_ignore(true)
                .filter_entry(|e| {
                    if e.depth() == 0 {
                        return true;
                    }
                    let nm = e.file_name().to_str().unwrap_or("");
                    !SKIP_DIRS.contains(&nm)
                })
                .build_parallel();

            walker.run(|| {
                let ast_q_c = Arc::clone(&ast_query_arc);
                let compiled_c = Arc::clone(&compiled_arc);
                let ext_allow_c = Arc::clone(&ext_allow_arc);
                let include_c = Arc::clone(&include_arc);
                let exclude_c = Arc::clone(&exclude_arc);
                let root_c = Arc::clone(&root_canon_arc);
                let prefix_c = Arc::clone(&rel_prefix_arc);
                let matches_c = Arc::clone(&all_matches);
                let hit_c = Arc::clone(&hit_counter);
                let scanned_c = Arc::clone(&scanned_files_cnt);
                let bytes_c = Arc::clone(&total_bytes_cnt);
                let f_nc_c = Arc::clone(&filtered_non_code_cnt);
                let f_test_c = Arc::clone(&filtered_tests_cnt);

                Box::new(move |res| {
                    if hit_c.load(Ordering::Relaxed) >= hit_cap {
                        return WalkState::Quit;
                    }
                    let Ok(entry) = res else {
                        return WalkState::Continue;
                    };
                    let local = process_file(
                        entry.path(),
                        &root_c,
                        &prefix_c,
                        false,
                        &ext_allow_c,
                        &include_c,
                        &exclude_c,
                        ast_q_c.as_ref().as_ref(),
                        &compiled_c,
                        multi_mode,
                        s_opts,
                        &scanned_c,
                        &bytes_c,
                        &f_nc_c,
                        &f_test_c,
                    );
                    if !local.is_empty() {
                        let added = local.len();
                        if let Ok(mut guard) = matches_c.lock() {
                            guard.extend(local);
                        }
                        let prev = hit_c.fetch_add(added, Ordering::Relaxed);
                        if prev + added >= hit_cap {
                            return WalkState::Quit;
                        }
                    }
                    WalkState::Continue
                })
            });
        }
    }

    let scanned_files = scanned_files_cnt.load(Ordering::Relaxed);
    let total_bytes = total_bytes_cnt.load(Ordering::Relaxed);
    let filtered_non_code = filtered_non_code_cnt.load(Ordering::Relaxed);
    let filtered_tests = filtered_tests_cnt.load(Ordering::Relaxed);
    let mut filter_notes = Vec::new();
    if filtered_non_code > 0 {
        filter_notes.push(format!("{filtered_non_code} comment/string"));
    }
    if filtered_tests > 0 {
        filter_notes.push(format!("{filtered_tests} test"));
    }
    let filter_tag = if filter_notes.is_empty() {
        String::new()
    } else {
        format!(" [filtered {} hit(s)]", filter_notes.join(", "))
    };
    let mut matches = match Arc::try_unwrap(all_matches) {
        Ok(m) => m.into_inner().unwrap_or_default(),
        Err(arc) => arc.lock().map(|g| g.clone()).unwrap_or_default(),
    };
    matches.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.pattern.cmp(&b.pattern))
    });
    if !cli.count
        && !cli.files_only
        && !cli.unique
        && (matches.len() > cli.max_hits || cli.per_pattern > 0)
    {
        if multi_mode && compiled_arc.len() > 1 {
            use std::collections::VecDeque;
            let mut buckets: BTreeMap<String, VecDeque<SearchMatch>> = BTreeMap::new();
            for m in matches.drain(..) {
                buckets.entry(m.pattern.clone()).or_default().push_back(m);
            }
            if cli.per_pattern > 0 {
                for q in buckets.values_mut() {
                    while q.len() > cli.per_pattern {
                        q.pop_back();
                    }
                }
            }
            let order: Vec<String> = compiled_arc.iter().map(|(p, _)| p.clone()).collect();
            let mut selected = Vec::with_capacity(cli.max_hits);
            loop {
                let mut progressed = false;
                for pat_key in &order {
                    if selected.len() >= cli.max_hits {
                        break;
                    }
                    if let Some(q) = buckets.get_mut(pat_key) {
                        if let Some(m) = q.pop_front() {
                            selected.push(m);
                            progressed = true;
                        }
                    }
                }
                if !progressed || selected.len() >= cli.max_hits {
                    break;
                }
            }
            selected.sort_by(|a, b| {
                a.file
                    .cmp(&b.file)
                    .then_with(|| a.line.cmp(&b.line))
                    .then_with(|| a.pattern.cmp(&b.pattern))
            });
            matches = selected;
        } else if matches.len() > cli.max_hits {
            matches.truncate(cli.max_hits);
        }
    }
    if cli.width > 0 {
        for m in &mut matches {
            let char_cnt = m.snippet.chars().count();
            if char_cnt > cli.width {
                let mut truncated: String = m.snippet.chars().take(cli.width).collect();
                truncated.push('…');
                m.snippet = truncated;
            }
        }
    }

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
    let mut per_file_counts: BTreeMap<String, usize> = BTreeMap::new();
    for m in &matches {
        *per_file_counts.entry(m.file.clone()).or_insert(0) += 1;
    }

    let mut unique_entries: Vec<(String, usize)> = Vec::new();
    if cli.unique {
        let mut freq: BTreeMap<String, usize> = BTreeMap::new();
        for m in &matches {
            *freq.entry(m.snippet.clone()).or_insert(0) += 1;
        }
        unique_entries = freq.into_iter().collect();
        unique_entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        if unique_entries.len() > cli.max_hits {
            unique_entries.truncate(cli.max_hits);
        }
    }

    let rendered = if cli.files_only {
        let mut out_lines = vec![format!(
            "# SEARCH FILES `{combined_label}` ({} file(s) across {scanned_files} scanned in {elapsed_ms}ms){filter_tag}",
            per_file_counts.len()
        )];
        for f in per_file_counts.keys() {
            out_lines.push(format!("- `{f}`"));
        }
        out_lines.join("\n")
    } else if cli.count {
        let mut out_lines = vec![format!(
            "# SEARCH COUNT `{combined_label}` ({} hit(s) in {} file(s) across {scanned_files} scanned in {elapsed_ms}ms){filter_tag}",
            matches.len(),
            per_file_counts.len()
        )];
        for (f, c) in &per_file_counts {
            out_lines.push(format!("- `{f}`: {c}"));
        }
        out_lines.join("\n")
    } else if cli.unique {
        let mut out_lines = vec![format!(
            "# SEARCH UNIQUE `{combined_label}` ({} unique from {} hit(s) across {scanned_files} files in {elapsed_ms}ms){filter_tag}",
            unique_entries.len(),
            matches.len()
        )];
        for (txt, cnt) in &unique_entries {
            if cli.no_filename {
                out_lines.push(txt.clone());
            } else {
                out_lines.push(format!("- [{cnt}x] `{txt}`"));
            }
        }
        out_lines.join("\n")
    } else {
        let mut out_lines = vec![format!(
            "# SEARCH `{combined_label}` ({} hit(s) across {scanned_files} files in {elapsed_ms}ms){filter_tag}",
            matches.len()
        )];
        for m in &matches {
            if cli.no_filename {
                out_lines.push(m.snippet.clone());
                continue;
            }
            let ptag = if m.pattern.is_empty() {
                String::new()
            } else {
                format!("[pat:`{}`] ", m.pattern)
            };
            let sc = if m.scope.is_empty() {
                String::new()
            } else {
                format!(" [{}]", m.scope)
            };
            let cap_tag = if m.captures.is_empty() {
                String::new()
            } else {
                let pairs: Vec<String> = m
                    .captures
                    .iter()
                    .map(|(k, v)| format!("${k}={v}"))
                    .collect();
                format!(" {{{}}}", pairs.join(", "))
            };
            if m.snippet.contains('\n') {
                out_lines.push(format!(
                    "- {ptag}`{}:{}`{sc}{cap_tag}\n{}",
                    m.file, m.line, m.snippet
                ));
            } else {
                out_lines.push(format!(
                    "- {ptag}`{}:{}`{sc}{cap_tag} — `{}`",
                    m.file, m.line, m.snippet
                ));
            }
        }
        out_lines.join("\n")
    };

    record_event_ex(
        "search",
        total_bytes,
        rendered.len() as u64,
        0,
        0,
        "parallel-ast-office-search",
        true,
        t0.elapsed().as_millis() as u64,
        None,
    );

    if cli.json {
        if cli.files_only {
            let files: Vec<&String> = per_file_counts.keys().collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "elapsed_ms": elapsed_ms,
                    "scanned_files": scanned_files,
                    "filtered_non_code": filtered_non_code,
                    "filtered_tests": filtered_tests,
                    "files": files,
                }))
                .unwrap_or_default()
            );
        } else if cli.count {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "elapsed_ms": elapsed_ms,
                    "scanned_files": scanned_files,
                    "filtered_non_code": filtered_non_code,
                    "filtered_tests": filtered_tests,
                    "total_matches": matches.len(),
                    "counts": per_file_counts,
                }))
                .unwrap_or_default()
            );
        } else if cli.unique {
            let ujson: Vec<serde_json::Value> = unique_entries
                .iter()
                .map(|(txt, cnt)| json!({"text": txt, "count": cnt}))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "elapsed_ms": elapsed_ms,
                    "scanned_files": scanned_files,
                    "filtered_non_code": filtered_non_code,
                    "filtered_tests": filtered_tests,
                    "total_matches": matches.len(),
                    "unique_matches": ujson,
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "elapsed_ms": elapsed_ms,
                    "scanned_files": scanned_files,
                    "filtered_non_code": filtered_non_code,
                    "filtered_tests": filtered_tests,
                    "matches": matches,
                }))
                .unwrap_or_default()
            );
        }
    } else {
        println!("{rendered}");
    }
    0
}

fn glob_segment_match(pattern: &str, text: &str) -> bool {
    #[cfg(windows)]
    let (p, t): (Vec<char>, Vec<char>) = (
        pattern.chars().flat_map(char::to_lowercase).collect(),
        text.chars().flat_map(char::to_lowercase).collect(),
    );
    #[cfg(not(windows))]
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn expand_glob_target_paths(raw_norm: &str) -> Vec<(String, PathBuf)> {
    const MAX_GLOB_TARGETS: usize = 256;
    if !raw_norm.contains('*') && !raw_norm.contains('?') {
        return Vec::new();
    }
    let clean = raw_norm.replace('\\', "/");
    let trimmed = clean.trim_end_matches('/');
    let Some(first_wild) = trimmed.find(['*', '?']) else {
        return Vec::new();
    };
    let before_wild = &trimmed[..first_wild];
    let (base_str, rest_str) = match before_wild.rfind('/') {
        Some(slash) => {
            let base = if slash == 0 {
                "/"
            } else if trimmed[..slash].ends_with(':') {
                &trimmed[..=slash]
            } else {
                &trimmed[..slash]
            };
            (base, &trimmed[slash + 1..])
        }
        None => (".", trimmed),
    };
    let base_path = PathBuf::from(base_str);
    if !base_path.exists() {
        return Vec::new();
    }
    let segs: Vec<&str> = rest_str.split('/').filter(|s| !s.is_empty()).collect();
    if segs.is_empty() {
        return Vec::new();
    }
    let mut frontier: Vec<PathBuf> = vec![base_path];
    for (idx, seg) in segs.iter().enumerate() {
        let mut next: Vec<PathBuf> = Vec::new();
        if *seg == "." {
            next = frontier;
        } else if *seg == ".." {
            next = frontier.into_iter().map(|p| p.join("..")).collect();
        } else if !seg.contains('*') && !seg.contains('?') {
            for p in frontier {
                let cand = if p == Path::new(".") {
                    PathBuf::from(seg)
                } else {
                    p.join(seg)
                };
                if cand.exists() {
                    next.push(cand);
                    if next.len() >= MAX_GLOB_TARGETS {
                        break;
                    }
                }
            }
        } else {
            for dir in frontier {
                let Ok(rd) = fs::read_dir(&dir) else {
                    continue;
                };
                for entry in rd.flatten() {
                    let name_os = entry.file_name();
                    let name = name_os.to_string_lossy();
                    if SKIP_DIRS.contains(&name.as_ref()) && !seg.starts_with('.') {
                        continue;
                    }
                    if glob_segment_match(seg, &name) {
                        let child = if dir == Path::new(".") {
                            PathBuf::from(name_os)
                        } else {
                            entry.path()
                        };
                        next.push(child);
                        if next.len() >= MAX_GLOB_TARGETS {
                            break;
                        }
                    }
                }
                if next.len() >= MAX_GLOB_TARGETS {
                    break;
                }
            }
        }
        if idx + 1 < segs.len() {
            next.retain(|p| p.is_dir());
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }
    let mut out: Vec<(String, PathBuf)> = frontier
        .into_iter()
        .map(|p| {
            let mut disp = p.to_string_lossy().replace('\\', "/");
            while let Some(stripped) = disp.strip_prefix("./") {
                disp = stripped.to_string();
            }
            (disp.trim_end_matches('/').to_string(), p)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_segment_and_path_expansion_work_deterministically() {
        assert!(glob_segment_match("pkg-*", "pkg-alpha"));
        assert!(glob_segment_match("a?c.rs", "abc.rs"));
        assert!(!glob_segment_match("a?c.rs", "abbc.rs"));
        assert!(glob_segment_match("*.rs", "main.rs"));

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("pkg-one/sub")).unwrap();
        fs::create_dir_all(root.join("pkg-two/sub")).unwrap();
        fs::create_dir_all(root.join("misc/sub")).unwrap();
        fs::write(root.join("pkg-one/sub/b_one.txt"), "1").unwrap();
        fs::write(root.join("pkg-two/sub/b_two.txt"), "2").unwrap();
        fs::write(root.join("misc/sub/b_misc.txt"), "3").unwrap();

        let pat1 = format!("{}/pkg-*", root.to_string_lossy().replace('\\', "/"));
        let r1 = expand_glob_target_paths(&pat1);
        assert_eq!(r1.len(), 2, "{r1:?}");
        assert!(r1[0].0.ends_with("pkg-one"));
        assert!(r1[1].0.ends_with("pkg-two"));

        let pat2 = format!(
            "{}/pkg-*/sub/b*.txt",
            root.to_string_lossy().replace('\\', "/")
        );
        let r2 = expand_glob_target_paths(&pat2);
        assert_eq!(r2.len(), 2, "{r2:?}");
        assert!(r2[0].0.ends_with("pkg-one/sub/b_one.txt"));
        assert!(r2[1].0.ends_with("pkg-two/sub/b_two.txt"));

        let pat3 = format!(
            "{}/does-not-exist-*",
            root.to_string_lossy().replace('\\', "/")
        );
        assert!(expand_glob_target_paths(&pat3).is_empty());
    }

    #[test]
    fn binary_512b_peek_and_minified_ast_gate_work_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let bin_f = dir.path().join("opaque_blob");
        let mut blob = vec![0u8; 128 * 1024];
        blob[10..18].copy_from_slice(b"NEEDLE_X");
        fs::write(&bin_f, &blob).unwrap();
        assert!(peek_is_binary_nul(&bin_f));

        let txt_f = dir.path().join("normal.txt");
        fs::write(&txt_f, "hello NEEDLE_X\nsecond line\n").unwrap();
        assert!(!peek_is_binary_nul(&txt_f));

        let minified = format!("var a=1;{};console.log('x');", "b=2;".repeat(250));
        assert!(looks_minified_text(&minified));
        let normal_code = "fn alpha() {\n    let x = 1;\n}\nfn beta() {\n    let y = 2;\n}\n";
        assert!(!looks_minified_text(normal_code));

        // FileAstCache skips scan_symbols when need_scope is false (e.g. --files-only/--count/--no-filename)
        let opts_no_scope = SearchOpts {
            around: 160,
            pretty: false,
            multiline: false,
            block: false,
            before_ctx: 0,
            after_ctx: 0,
            invert: false,
            max_hits: 50,
            per_pattern: 0,
            code_only: false,
            no_tests: false,
            only_matching: false,
            need_scope: false,
        };
        let c_skip = FileAstCache::build(normal_code, "rs", false, opts_no_scope);
        assert!(c_skip.ast_spans.is_empty());
        let opts_with_scope = SearchOpts {
            need_scope: true,
            ..opts_no_scope
        };
        let c_keep = FileAstCache::build(normal_code, "rs", false, opts_with_scope);
        assert!(!c_keep.ast_spans.is_empty());
        let c_min = FileAstCache::build(&minified, "js", false, opts_with_scope);
        assert!(c_min.ast_spans.is_empty());
    }
}
