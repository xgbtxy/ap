use crate::smoke::kill_process_tree;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tree_sitter::{Node, Parser};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutantOutcome {
    pub line: usize,
    pub original_op: String,
    pub mutated_op: String,
    pub snippet: String,
    pub killed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationReport {
    pub ok: bool,
    pub target: String,
    pub test_cmd: String,
    pub total_mutants: usize,
    pub killed_mutants: usize,
    pub mutation_score_pct: f64,
    pub elapsed_ms: f64,
    pub survivors: Vec<MutantOutcome>,
}

struct FileRestoreGuard {
    path: PathBuf,
    orig_bytes: Vec<u8>,
}

impl Drop for FileRestoreGuard {
    fn drop(&mut self) {
        let _ = fs::write(&self.path, &self.orig_bytes);
    }
}

struct RawSite {
    start_byte: usize,
    end_byte: usize,
    line: usize,
    orig: &'static str,
    rep: &'static str,
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

fn flip_operator(op: &str, has_string_child: bool) -> Option<(&'static str, &'static str)> {
    match op {
        ">=" => Some((">=", ">")),
        ">" => Some((">", ">=")),
        "<=" => Some(("<=", "<")),
        "<" => Some(("<", "<=")),
        "===" => Some(("===", "!==")),
        "!==" => Some(("!==", "===")),
        "==" => Some(("==", "!=")),
        "!=" => Some(("!=", "==")),
        "+" if !has_string_child => Some(("+", "-")),
        "-" => Some(("-", "+")),
        "*" => Some(("*", "/")),
        "&&" => Some(("&&", "||")),
        "||" => Some(("||", "&&")),
        "and" => Some(("and", "or")),
        "or" => Some(("or", "and")),
        _ => None,
    }
}

fn collect_sites(node: Node, src: &[u8], in_fn: bool, out: &mut Vec<RawSite>) {
    let kind = node.kind();
    let now_in_fn =
        in_fn || kind.contains("function") || kind.contains("method") || kind == "arrow_function";

    if now_in_fn
        && (kind.contains("binary") || kind.contains("comparison") || kind.contains("boolean"))
    {
        let mut cursor = node.walk();
        let children: Vec<Node> = node.children(&mut cursor).collect();
        let has_str = children
            .iter()
            .any(|c| c.kind().contains("string") || c.kind().contains("template"));
        for ch in &children {
            if !ch.is_named() || ch.kind() == "and" || ch.kind() == "or" {
                let s = ch.start_byte();
                let e = ch.end_byte();
                if e > s && e <= src.len() {
                    if let Ok(tok) = std::str::from_utf8(&src[s..e]) {
                        if let Some((orig, rep)) = flip_operator(tok.trim(), has_str) {
                            if tok == orig {
                                out.push(RawSite {
                                    start_byte: s,
                                    end_byte: e,
                                    line: ch.start_position().row + 1,
                                    orig,
                                    rep,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    for ch in node.children(&mut cursor) {
        collect_sites(ch, src, now_in_fn, out);
    }
}

fn detect_mutate_test_cmd(cwd: &Path) -> Option<String> {
    let pkg = cwd.join("package.json");
    if pkg.is_file() {
        if let Ok(txt) = fs::read_to_string(&pkg) {
            if txt.contains("\"test\"") && !txt.contains("no test specified") {
                return Some("npm test".to_string());
            }
        }
    }
    if cwd.join("Cargo.toml").is_file() {
        return Some("cargo test --quiet".to_string());
    }
    if cwd.join("go.mod").is_file() {
        return Some("go test ./...".to_string());
    }
    if cwd.join("pyproject.toml").is_file() || cwd.join("tests").is_dir() {
        return Some("python -m unittest discover".to_string());
    }
    None
}

#[cfg(windows)]
fn compact_windows_path_if_long() -> Option<String> {
    let raw = std::env::var("PATH").ok()?;
    if raw.len() < 3072 {
        return None;
    }
    let mut seen = std::collections::HashSet::<String>::new();
    let mut kept = Vec::new();
    for seg in raw.split(';') {
        let s = seg.trim();
        if s.is_empty() {
            continue;
        }
        let key = s.trim_end_matches(['\\', '/']).to_ascii_lowercase();
        if seen.insert(key) && Path::new(s).is_dir() {
            kept.push(s);
        }
    }
    let compacted = kept.join(";");
    if !compacted.is_empty() && compacted.len() < raw.len() {
        Some(compacted)
    } else {
        None
    }
}

fn run_cmd_bounded(cwd: &Path, cmd_str: &str, timeout_ms: u64) -> (bool, u64) {
    let t0 = Instant::now();
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.args(["/C", cmd_str]);
        if let Some(compacted) = compact_windows_path_if_long() {
            c.env("PATH", compacted);
        }
        c
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.args(["-c", cmd_str]);
        c
    };
    let Ok(mut ch) = cmd
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return (false, 0);
    };
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if let Ok(Some(st)) = ch.try_wait() {
            return (st.success(), t0.elapsed().as_millis() as u64);
        }
        if Instant::now() >= deadline {
            kill_process_tree(&mut ch);
            return (false, timeout_ms);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn run_mutate(
    cwd: &Path,
    target_rel: &Path,
    test_cmd_opt: Option<&str>,
    max_mutants: usize,
    as_json: bool,
) -> i32 {
    let t0 = Instant::now();
    let target_p = if target_rel.is_absolute() {
        target_rel.to_path_buf()
    } else {
        cwd.join(target_rel)
    };
    let Ok(orig_bytes) = fs::read(&target_p) else {
        eprintln!("[probe mutate] file not found: {}", target_p.display());
        return 1;
    };
    let Ok(src_txt) = String::from_utf8(orig_bytes.clone()) else {
        eprintln!("[probe mutate] file must be valid UTF-8");
        return 1;
    };
    let ext = target_p
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let Some(mut parser) = parser_for_ext(&ext) else {
        eprintln!("[probe mutate] unsupported language `.{ext}`");
        return 2;
    };
    let Some(test_cmd) = test_cmd_opt
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .or_else(|| detect_mutate_test_cmd(cwd))
    else {
        eprintln!("[probe mutate] pass --test-cmd \"<cmd>\"");
        return 2;
    };

    let Some(tree) = parser.parse(&src_txt, None) else {
        eprintln!("[probe mutate] failed to parse AST");
        return 1;
    };
    let mut all_sites = Vec::new();
    collect_sites(tree.root_node(), src_txt.as_bytes(), false, &mut all_sites);

    let (base_ok, base_ms) = run_cmd_bounded(cwd, &test_cmd, 25_000);
    if !base_ok {
        eprintln!("[probe mutate] baseline test command `{test_cmd}` failed before mutation; fix failing tests first.");
        return 1;
    }

    let cap = max_mutants.clamp(1, 30);
    let step = (all_sites.len() / cap).max(1);
    let picked: Vec<&RawSite> = all_sites.iter().step_by(step).take(cap).collect();
    let per_timeout = (base_ms * 4).clamp(3000, 15_000);
    let src_lines: Vec<&str> = src_txt.lines().collect();

    let guard = FileRestoreGuard {
        path: target_p.clone(),
        orig_bytes: orig_bytes.clone(),
    };
    let mut killed = 0usize;
    let mut survivors = Vec::new();

    for site in &picked {
        let mut mutated = Vec::with_capacity(orig_bytes.len() + 4);
        mutated.extend_from_slice(&orig_bytes[..site.start_byte]);
        mutated.extend_from_slice(site.rep.as_bytes());
        mutated.extend_from_slice(&orig_bytes[site.end_byte..]);
        let _ = fs::write(&target_p, &mutated);

        let (still_passes, _) = run_cmd_bounded(cwd, &test_cmd, per_timeout);
        if !still_passes {
            killed += 1;
        } else {
            let ln_str = src_lines
                .get(site.line.saturating_sub(1))
                .copied()
                .unwrap_or("")
                .trim()
                .to_string();
            survivors.push(MutantOutcome {
                line: site.line,
                original_op: site.orig.to_string(),
                mutated_op: site.rep.to_string(),
                snippet: ln_str,
                killed: false,
            });
        }
    }
    drop(guard);

    let total = picked.len();
    let score = if total == 0 {
        100.0
    } else {
        ((killed as f64) * 1000.0 / (total as f64)).round() / 10.0
    };
    let rep = MutationReport {
        ok: survivors.is_empty(),
        target: target_rel.to_string_lossy().replace('\\', "/"),
        test_cmd,
        total_mutants: total,
        killed_mutants: killed,
        mutation_score_pct: score,
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0).round(),
        survivors,
    };

    if as_json {
        println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
    } else {
        println!(
            "[probe mutate] `{}` — Mutation Score: {}/{} killed ({:.1}%) in {}ms",
            rep.target,
            rep.killed_mutants,
            rep.total_mutants,
            rep.mutation_score_pct,
            rep.elapsed_ms
        );
        if !rep.survivors.is_empty() {
            println!("Surviving Mutants (add edge-case/boundary assertions to kill these):");
            for s in &rep.survivors {
                println!(
                    "  - L{}: changed `{}` -> `{}` on `{}` (test suite still passed!)",
                    s.line, s.original_op, s.mutated_op, s.snippet
                );
            }
        }
    }
    if rep.ok {
        0
    } else {
        1
    }
}
