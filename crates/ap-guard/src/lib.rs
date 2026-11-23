use base64::Engine;
use clap::{Parser, Subcommand};
pub mod deps_sec;
pub mod diff_audit;
pub mod pack;
pub mod rules;
pub mod sec;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const EXIT_BLOCK: i32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub sig: String,
    pub cmd: String,
    pub exit: i32,
    pub at: u64,
}

#[derive(Parser, Debug)]
#[command(
    name = "guard",
    about = "Sub-2ms exit-2 truth gate, loop breaker & blast-radius shield"
)]
struct Cli {
    #[command(subcommand)]
    subcmd: SubCmd,
}

#[derive(Subcommand, Debug)]
enum SubCmd {
    /// Inspect command/payload or Hook stdin JSON for unsafe actions & secrets
    Shield {
        #[arg(long, default_value = "")]
        text: String,
    },
    /// Execute command with shield + repetition-loop breaker
    Run {
        #[arg(long, default_value_t = 3)]
        max_repeats: usize,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Verify completion invariants; exit 2 on stderr if unverified
    StopGate {
        #[arg(long = "check")]
        checks: Vec<String>,
    },
    /// Run full anti-slop code rules + project checks + .agents/smoke.ap (exit 2 on failure)
    Verify {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long)]
        all: bool,
        /// Fuse cross-file contract linker + unit tests + API chaos/concurrency fuzz + AST mutation into 1 pass
        #[arg(long)]
        deep: bool,
        #[arg(long = "check")]
        checks: Vec<String>,
    },
    /// Manage persistent deterministic code rules (.agents/guard.json)
    Rule {
        #[command(subcommand)]
        action: RuleCmd,
    },
    /// Sub-5ms OWASP & native memory/trust-boundary audit (SQLi, Path Traversal, Cmd Inj, DOM XSS, SSRF, Deser, C/C++ memcpy_s/alloc overflow)
    Sec {
        #[arg(default_value = ".")]
        cwd: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Semantic git diff self-audit: catches test-weakening (deleted assertions), added debug leftovers & mass deletions
    Diff {
        #[arg(default_value = ".")]
        cwd: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Deterministic deliverable/evidence bundle gate: verifies full 64-hex SHA-256 manifests, scans secret/absolute-path leaks & required headers
    Pack {
        #[arg(default_value = ".")]
        dir: PathBuf,
        #[arg(long)]
        max_lines: Option<usize>,
        #[arg(long = "require-header")]
        require_headers: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Clear loop ledger
    Reset,
}

#[derive(Subcommand, Debug)]
enum RuleCmd {
    /// Initialize .agents/guard.json with anti-slop rules & auto-detected test suite
    Init {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
    },
    /// Add a permanent deterministic forbidden-pattern rule (turns past agent mistakes into exit-2 gates)
    Add {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "*")]
        glob: String,
        #[arg(long)]
        forbid: String,
        #[arg(long)]
        msg: String,
    },
    /// List active rules & checks in .agents/guard.json
    List {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
    },
}

struct SafetyPatterns {
    destructive: Vec<(&'static str, Regex)>,
    secrets: Vec<(&'static str, Regex)>,
    conflict_re: Regex,
    hex_ts_re: Regex,
}

fn safety_patterns() -> &'static SafetyPatterns {
    static PATS: OnceLock<SafetyPatterns> = OnceLock::new();
    PATS.get_or_init(|| {
        let destructive = vec![
            (
                "recursive root/home delete",
                Regex::new(
                    r#"rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:/|~|\$HOME|\.\.)(?:[\s"';&|]|$)"#,
                )
                .unwrap(),
            ),
            (
                "forced git history overwrite",
                Regex::new(r"\bgit\s+push\b.*(?:\s--force\b|\s-f\b)").unwrap(),
            ),
            (
                "hard working-tree wipe",
                Regex::new(r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-zA-Z]*f)").unwrap(),
            ),
            (
                "destructive SQL DDL",
                Regex::new(r"(?i)\b(?:DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b").unwrap(),
            ),
            (
                "unbounded outbound mail/webhook blast",
                Regex::new(r"(?i)\b(?:sendmail\s+-t|mass[_-]?send|blast[_-]?all)\b").unwrap(),
            ),
        ];
        let secrets = vec![
            (
                "OpenAI/Anthropic/xAI API key",
                Regex::new(r"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|xai-[A-Za-z0-9_-]{20,})\b")
                    .unwrap(),
            ),
            (
                "GitHub Personal/App token",
                Regex::new(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{24,}\b").unwrap(),
            ),
            (
                "AWS Access Key ID",
                Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            ),
            (
                "PEM Private Key block",
                Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----").unwrap(),
            ),
        ];
        let conflict_re = Regex::new(r"(?m)^(?:<{7}\s|={7}$|>{7}\s)").unwrap();
        let hex_ts_re = Regex::new(r"\b0x[0-9a-fA-F]+\b|\b\d{4}-\d{2}-\d{2}[T\s]\S+").unwrap();
        SafetyPatterns {
            destructive,
            secrets,
            conflict_re,
            hex_ts_re,
        }
    })
}

pub fn guard_dir(cwd: &Path) -> PathBuf {
    let base = match std::env::var("GUARD_HOME") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => cwd.join(".guard"),
    };
    let _ = fs::create_dir_all(&base);
    let gi = base.join(".gitignore");
    if !gi.exists() {
        let _ = fs::write(&gi, "*\n");
    }
    base
}

fn should_auto_sieve(cmd: &str) -> bool {
    let t = cmd.trim();
    if t.is_empty()
        || t.contains("sieve")
        || t.chars()
            .any(|c| matches!(c, '|' | '>' | '<' | ';' | '\n' | '`'))
        || t.contains("&&")
        || t.contains("||")
    {
        return false;
    }
    const PREFIXES: &[&str] = &[
        "pytest",
        "python -m pytest",
        "cargo test",
        "cargo clippy",
        "npm test",
        "npm run test",
        "pnpm test",
        "vitest run",
        "go test",
    ];
    PREFIXES
        .iter()
        .any(|p| t == *p || t.starts_with(&format!("{p} ")))
}

fn should_auto_win_exec(cmd: &str) -> bool {
    let force_win = std::env::var("AP_FORCE_WIN_SHIELD").ok().as_deref() == Some("1");
    if !cfg!(windows) && !force_win {
        return false;
    }
    let t = cmd.trim();
    if t.is_empty()
        || t.contains("ap exec")
        || t.contains("ap.exe\" exec")
        || t.contains("ap\" exec")
        || t.contains("sieve run")
    {
        return false;
    }
    static WIN_TRAP_RE: OnceLock<Regex> = OnceLock::new();
    let re = WIN_TRAP_RE.get_or_init(|| {
        Regex::new(
            r#"(?:&&|<<-?\s*['"]?[A-Za-z_]|/dev/null\b|(?:^|[;|&(\s])curl\s+(?:-[A-Za-z-]|https?://)|\bpython3?\s+-c\b|\bnode\s+-e\b|\|\s*(?:head|tail|grep|egrep|awk|sed|wc)\b|https?://[^\s'"`;&|]+&[^\s'"`;&|]+)"#,
        )
        .unwrap()
    });
    re.is_match(t)
}

pub fn inspect_text_safety(text: &str) -> Vec<String> {
    let pats = safety_patterns();
    let mut findings = Vec::new();
    for (label, pat) in &pats.destructive {
        if pat.is_match(text) {
            findings.push(format!("Destructive action blocked: {label}"));
        }
    }
    for (label, pat) in &pats.secrets {
        if pat.is_match(text) {
            findings.push(format!("Credential/secret leak blocked: {label}"));
        }
    }
    findings
}

fn normalize_error_sig(cmd_str: &str, output: &str, exit_code: i32) -> String {
    static JITTER_RES: OnceLock<(Regex, Regex)> = OnceLock::new();
    let (ansi_re, jitter_re) = JITTER_RES.get_or_init(|| {
        (
            Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]").unwrap(),
            Regex::new(
                r"(?i)(?:\bpid[=:\s]+\d+|\b\d+(?:\.\d+)?\s*(?:ms|s)\b|(?:/tmp/|\\Temp\\)[A-Za-z0-9._-]+)",
            )
            .unwrap(),
        )
    });
    let pats = safety_patterns();
    let norm_cmd = cmd_str.split_whitespace().collect::<Vec<_>>().join(" ");
    let err_lines: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            let no_ansi = ansi_re.replace_all(l, "");
            let no_hex = pats.hex_ts_re.replace_all(&no_ansi, "<HEX>");
            jitter_re.replace_all(&no_hex, "<VAR>").to_string()
        })
        .collect();
    let start = err_lines.len().saturating_sub(6);
    let tail_joined = err_lines[start..].join("\n");
    let tail_sig: String = tail_joined.chars().take(400).collect();
    let raw = format!("{exit_code}::{norm_cmd}::{tail_sig}");
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    hex[..12].to_string()
}

fn load_ledger(base: &Path) -> Vec<LedgerEntry> {
    let p = base.join("loop_ledger.json");
    fs::read_to_string(&p)
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<LedgerEntry>>(&s).ok())
        .unwrap_or_default()
}

fn save_ledger(base: &Path, entries: &[LedgerEntry]) {
    let start = entries.len().saturating_sub(40);
    if let Ok(js) = serde_json::to_string_pretty(&entries[start..]) {
        let _ = fs::write(base.join("loop_ledger.json"), js);
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn record_attempt(
    base: &Path,
    cmd_str: &str,
    exit_code: i32,
    output: &str,
    max_repeats: usize,
) -> (bool, usize, String) {
    let mut entries = load_ledger(base);
    let cmd_trunc: String = cmd_str.chars().take(160).collect();
    if exit_code == 0 {
        entries.push(LedgerEntry {
            sig: "ok".to_string(),
            cmd: cmd_trunc,
            exit: 0,
            at: now_epoch(),
        });
        save_ledger(base, &entries);
        return (false, 0, "ok".to_string());
    }
    let sig = normalize_error_sig(cmd_str, output, exit_code);
    entries.push(LedgerEntry {
        sig: sig.clone(),
        cmd: cmd_trunc,
        exit: exit_code,
        at: now_epoch(),
    });
    save_ledger(base, &entries);
    let win_start = entries.len().saturating_sub(8);
    let repeat_count = entries[win_start..].iter().filter(|e| e.sig == sig).count();
    (repeat_count >= max_repeats, repeat_count, sig)
}

fn scan_conflict_and_secret_markers(root: &Path) -> Vec<String> {
    let pats = safety_patterns();
    let secrets = &pats.secrets;
    let conflict_re = &pats.conflict_re;
    let mut bad_files = Vec::new();
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(out) = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(root)
        .output()
    {
        if out.status.success() {
            for ln in String::from_utf8_lossy(&out.stdout).lines() {
                if ln.len() > 3 {
                    let rel = ln[3..].trim().trim_matches('"');
                    let rel = rel.rsplit(" -> ").next().unwrap_or(rel);
                    candidates.push(root.join(rel));
                }
            }
        }
    }
    if candidates.is_empty() {
        fn walk_shallow(dir: &Path, out: &mut Vec<PathBuf>) {
            if out.len() >= 150 {
                return;
            }
            if let Ok(rd) = fs::read_dir(dir) {
                for entry in rd.flatten() {
                    let p = entry.path();
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with('.')
                        || matches!(
                            name.as_str(),
                            "target" | "node_modules" | "dist" | "build" | "__pycache__"
                        )
                    {
                        continue;
                    }
                    if p.is_dir() {
                        walk_shallow(&p, out);
                    } else if p.is_file() {
                        if let Ok(m) = entry.metadata() {
                            if m.len() < 512_000 {
                                out.push(p);
                            }
                        }
                    }
                }
            }
        }
        walk_shallow(root, &mut candidates);
    }

    for fp in candidates {
        if let Ok(meta) = fp.metadata() {
            if meta.is_file() && meta.len() < 1_000_000 {
                if let Ok(bytes) = fs::read(&fp) {
                    let txt = String::from_utf8_lossy(&bytes);
                    let rel_disp = fp
                        .strip_prefix(root)
                        .unwrap_or(&fp)
                        .to_string_lossy()
                        .replace('\\', "/");
                    if conflict_re.is_match(&txt) {
                        bad_files.push(rel_disp.clone());
                    }
                    for (_, spat) in secrets {
                        if spat.is_match(&txt) {
                            bad_files.push(format!("{rel_disp} (contains exposed secret pattern)"));
                            break;
                        }
                    }
                }
            }
        }
    }
    bad_files
}

fn spawn_command_list(cmd: &[String], cwd: &Path) -> Result<std::process::Output, std::io::Error> {
    match Command::new(&cmd[0])
        .args(&cmd[1..])
        .current_dir(cwd)
        .output()
    {
        Ok(o) => Ok(o),
        #[cfg(windows)]
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Command::new("cmd")
            .arg("/C")
            .args(cmd)
            .current_dir(cwd)
            .output(),
        Err(e) => Err(e),
    }
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

fn spawn_shell_string(shell_cmd: &str, cwd: &Path) -> Result<std::process::Output, std::io::Error> {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("cmd");
        cmd.args(["/C", shell_cmd]).current_dir(cwd);
        if let Some(compacted) = compact_windows_path_if_long() {
            cmd.env("PATH", compacted);
        }
        cmd.output()
    }
    #[cfg(not(windows))]
    {
        Command::new("sh")
            .args(["-c", shell_cmd])
            .current_dir(cwd)
            .output()
    }
}

fn extract_failing_frame_snippet(scan_root: &Path, text: &str) -> String {
    static FRAME_RE: OnceLock<Regex> = OnceLock::new();
    let re = FRAME_RE.get_or_init(|| {
        Regex::new(r#"(?:([A-Za-z0-9_./\\-]+\.(?:ts|tsx|js|mjs|py|rs|go|c)):(\d+)|File "([^"]+\.py)", line (\d+))"#).unwrap()
    });
    for cap in re.captures_iter(text) {
        let (rel_raw, line_s) = if let (Some(p), Some(l)) = (cap.get(1), cap.get(2)) {
            (p.as_str(), l.as_str())
        } else if let (Some(p), Some(l)) = (cap.get(3), cap.get(4)) {
            (p.as_str(), l.as_str())
        } else {
            continue;
        };
        if rel_raw.contains("node_modules") {
            continue;
        }
        let Ok(ln_no) = line_s.parse::<usize>() else {
            continue;
        };
        let cand = {
            let p = Path::new(rel_raw);
            if p.is_file() {
                p.to_path_buf()
            } else {
                scan_root.join(rel_raw)
            }
        };
        if let Ok(src) = fs::read_to_string(&cand) {
            let src_lines: Vec<&str> = src.lines().collect();
            if ln_no >= 1 && ln_no <= src_lines.len() {
                let s = ln_no.saturating_sub(2).max(1);
                let e = (ln_no + 2).min(src_lines.len());
                let block = (s..=e)
                    .map(|k| {
                        let mark = if k == ln_no { ">" } else { " " };
                        format!("{mark}{k:4} | {}", src_lines[k - 1])
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                return format!("`{}`:\n{block}", rel_raw.replace('\\', "/"));
            }
        }
    }
    String::new()
}

fn collect_test_imported_stems(scan_root: &Path) -> Vec<String> {
    let mut blobs = String::new();
    for dir_name in ["test", "tests"] {
        let d = scan_root.join(dir_name);
        if let Ok(rd) = fs::read_dir(&d) {
            for ent in rd.flatten() {
                if ent.path().is_file() {
                    if let Ok(t) = fs::read_to_string(ent.path()) {
                        blobs.push_str(&t);
                        blobs.push('\n');
                    }
                }
            }
        }
    }
    blobs
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .filter(|s| s.len() >= 3)
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

fn select_active_logic_files(scan_root: &Path) -> Vec<PathBuf> {
    let mut git_dirty: Vec<String> = Vec::new();
    if let Ok(o) = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(scan_root)
        .output()
    {
        if o.status.success() {
            for ln in String::from_utf8_lossy(&o.stdout).lines() {
                if ln.len() > 3 {
                    let rel = ln[3..].trim().trim_matches('"');
                    let rel = rel.rsplit(" -> ").next().unwrap_or(rel);
                    git_dirty.push(rel.replace('\\', "/"));
                }
            }
        }
    }

    let test_tokens = collect_test_imported_stems(scan_root);
    let mut candidates: Vec<(PathBuf, bool, bool, u128)> = Vec::new();
    let src_dir = if scan_root.join("src").is_dir() {
        scan_root.join("src")
    } else {
        scan_root.to_path_buf()
    };
    if let Ok(rd) = fs::read_dir(&src_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let nm = entry.file_name().to_string_lossy().to_ascii_lowercase();
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
            if !matches!(ext, "ts" | "tsx" | "js" | "mjs" | "py" | "go" | "rs" | "c") {
                continue;
            }
            if nm.contains(".test.")
                || nm.contains(".spec.")
                || nm.starts_with("test_")
                || nm.starts_with("server.")
                || nm.starts_with("main.")
                || nm.starts_with("index.")
            {
                continue;
            }
            let rel = p
                .strip_prefix(scan_root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            let is_dirty = git_dirty.iter().any(|g| g == &rel);
            let stem = p
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let in_tests = !stem.is_empty() && test_tokens.iter().any(|t| t == &stem);
            let mtime_ms = p
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis())
                .unwrap_or(0);
            candidates.push((p, is_dirty, in_tests, mtime_ms));
        }
    }

    let any_dirty = candidates.iter().any(|c| c.1);
    let any_tested = candidates.iter().any(|c| c.2);
    if any_dirty {
        candidates.retain(|c| c.1);
    } else if any_tested {
        candidates.retain(|c| c.2);
    }
    if !any_dirty && candidates.len() > 1 {
        let max_mt = candidates.iter().map(|c| c.3).max().unwrap_or(0);
        let min_mt = candidates.iter().map(|c| c.3).min().unwrap_or(0);
        if max_mt.saturating_sub(min_mt) >= 3_000 {
            candidates.retain(|c| max_mt.saturating_sub(c.3) < 3_000);
        }
    }
    candidates.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| b.3.cmp(&a.3))
            .then_with(|| a.0.cmp(&b.0))
    });
    candidates.into_iter().take(2).map(|c| c.0).collect()
}

fn run_deep_creation_and_test_gates(scan_root: &Path) -> (Vec<String>, Vec<String>) {
    let mut deep_issues = Vec::new();
    let mut receipts = Vec::new();
    let Ok(exe) = std::env::current_exe() else {
        return (deep_issues, receipts);
    };
    let stem = exe.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if !stem.eq_ignore_ascii_case("ap") {
        return (deep_issues, receipts);
    }

    // 0. Sub-5ms AI-code OWASP Security & Trust-Boundary Audit (CWE-89/22/78/79)
    let sec_findings = sec::scan_security_issues(scan_root);
    if sec_findings.is_empty() {
        receipts.push("[sec] 0 SQLi/Path-Traversal/Cmd-Inj/DOM-XSS/TLS flaws".to_string());
    } else {
        for sf in sec_findings {
            deep_issues.push(format!(
                "[SECURITY {}] {}:L{} — `{}` -> {}",
                sf.cwe, sf.file, sf.line, sf.snippet, sf.fix
            ));
        }
    }

    // 0b. Semantic git diff self-audit (catches deleted assertions, debug leftovers & silent truncation)
    let da = diff_audit::audit_git_diff(scan_root);
    if da.is_git_repo {
        if da.findings.is_empty() {
            receipts.push(format!(
                "[diff] 0 test-weakening / debug-leftover / mass-deletion regressions ({} file(s), +{}/-{})",
                da.files_changed, da.lines_added, da.lines_deleted
            ));
        } else {
            for df in da.findings {
                deep_issues.push(format!("[DIFF {}] {}", df.kind, df.detail));
            }
        }
    }

    // 1. Cross-File Export & Arity Contract Linker (`ap splice check`)
    if let Ok(o) = Command::new(&exe)
        .args(["splice", "check"])
        .arg(scan_root)
        .output()
    {
        if !o.status.success() {
            let out_s = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            deep_issues.push(format!(
                "Cross-file contract check failed:\n{}",
                out_s.trim()
            ));
            return (deep_issues, receipts);
        } else {
            receipts.push("[contracts] 0 broken imports / arity mismatches".to_string());
        }
    }

    // 2. Auto API Chaos + Concurrency Fuzzer & Headless UI Audit if HTTP server exists
    let has_server = scan_root.join("package.json").is_file()
        && fs::read_to_string(scan_root.join("package.json"))
            .map(|t| t.contains("\"start\""))
            .unwrap_or(false)
        || scan_root.join("src/server.mjs").is_file()
        || scan_root.join("src/server.ts").is_file()
        || scan_root.join("src/server.js").is_file()
        || scan_root.join("server.py").is_file();
    if has_server {
        if let Ok(o) = Command::new(&exe)
            .args(["probe", "fuzz", "--cwd"])
            .arg(scan_root)
            .output()
        {
            let out_s = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            if !o.status.success() {
                deep_issues.push(format!(
                    "Adversarial API & concurrency fuzz failed:\n{}",
                    out_s.trim()
                ));
            } else if let Some(first_ln) = out_s.lines().find(|l| !l.trim().is_empty()) {
                receipts.push(format!("[fuzz] {}", first_ln.trim()));
            }
        }
        let has_ui = scan_root.join("public/index.html").is_file()
            || scan_root.join("index.html").is_file()
            || scan_root.join("static/index.html").is_file()
            || scan_root.join("src/index.html").is_file();
        if has_ui {
            if let Ok(o) = Command::new(&exe)
                .args(["probe", "ui", "--cwd"])
                .arg(scan_root)
                .output()
            {
                let out_s = format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                );
                if !o.status.success() {
                    deep_issues.push(format!(
                        "Headless UI layout/network audit failed:\n{}",
                        out_s.trim()
                    ));
                } else if let Some(first_ln) = out_s.lines().find(|l| !l.trim().is_empty()) {
                    receipts.push(format!("[ui] {}", first_ln.trim()));
                }
            }
        }
    }

    // 3. Auto Polyglot Tree-sitter AST Mutation Audit on active/tested logic file(s)
    for lf in select_active_logic_files(scan_root) {
        let rel = lf.strip_prefix(scan_root).unwrap_or(&lf);
        if let Ok(o) = Command::new(&exe)
            .args(["probe", "mutate"])
            .arg(rel)
            .arg("--cwd")
            .arg(scan_root)
            .args(["--max-mutants", "8"])
            .output()
        {
            let out_s = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            if !o.status.success() {
                deep_issues.push(format!(
                    "Unit-test mutation audit found surviving bugs:\n{}",
                    out_s.trim()
                ));
            } else if let Some(first_ln) = out_s.lines().find(|l| !l.trim().is_empty()) {
                receipts.push(format!("[mutate] {}", first_ln.trim()));
            }
        }
    }
    (deep_issues, receipts)
}

fn collect_verification_issues(
    scan_root: &Path,
    explicit_checks: &[String],
    scan_all_files: bool,
    force_default_rules: bool,
) -> Vec<String> {
    let mut issues = scan_conflict_and_secret_markers(scan_root);
    let cfg_opt = rules::load_config(scan_root);
    let active_cfg = if let Some(c) = cfg_opt {
        Some(c)
    } else if force_default_rules {
        Some(rules::default_guard_config(scan_root))
    } else {
        None
    };

    let mut all_checks: Vec<String> = explicit_checks.to_vec();
    if let Some(cfg) = &active_cfg {
        issues.extend(rules::evaluate_code_rules(scan_root, cfg, scan_all_files));
        for c in &cfg.checks {
            if !all_checks.contains(c) {
                all_checks.push(c.clone());
            }
        }
    }

    for chk in all_checks {
        match spawn_shell_string(&chk, scan_root) {
            Ok(o) if !o.status.success() => {
                let code = o.status.code().unwrap_or(1);
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                );
                let lines: Vec<&str> = combined.lines().collect();
                let mut key_lines: Vec<&str> = lines
                    .iter()
                    .copied()
                    .filter(|l| {
                        l.contains("AssertionError")
                            || l.contains("Error:")
                            || l.contains("FAIL")
                            || l.contains("panicked at")
                            || l.trim_start().starts_with("at ")
                            || l.trim_start().starts_with("-->")
                    })
                    .take(10)
                    .collect();
                let start = lines.len().saturating_sub(10);
                for tl in &lines[start..] {
                    if !key_lines.contains(tl) {
                        key_lines.push(tl);
                    }
                }
                let snippet = extract_failing_frame_snippet(scan_root, &combined);
                let mut msg = format!(
                    "Check failed (`{chk}`, exit {code}):\n{}",
                    key_lines.join("\n")
                );
                if !snippet.is_empty() {
                    msg.push_str("\n## Pinpoint Source Context\n");
                    msg.push_str(&snippet);
                }
                issues.push(msg);
            }
            Ok(o) => {
                let chk_low = chk.to_ascii_lowercase();
                if chk_low.contains("test")
                    || chk_low.contains("pytest")
                    || chk_low.contains("vitest")
                    || chk_low.contains("jest")
                {
                    let combined = format!(
                        "{}{}",
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    );
                    let low = combined.to_ascii_lowercase();
                    let vacuous = low.contains("collected 0 items")
                        || low.contains("no tests ran")
                        || low.contains("[no test files]")
                        || low.contains("no tests found")
                        || (low.contains("tests 0")
                            && (low.contains("pass 0") || low.contains("# tests 0")));
                    if vacuous {
                        issues.push(format!(
                            "[VACUOUS TEST RUN] Check `{chk}` exited 0 but executed 0 tests! Add real assertions and verify test file paths."
                        ));
                    }
                    // Also catch Node `--test` / runner files that exit 0 (`# pass 1`) with ZERO assertions
                    for dir_name in ["test", "tests"] {
                        let td = scan_root.join(dir_name);
                        if let Ok(rd) = fs::read_dir(&td) {
                            for ent in rd.flatten() {
                                let p = ent.path();
                                if !p.is_file() {
                                    continue;
                                }
                                let nm = ent.file_name().to_string_lossy().to_ascii_lowercase();
                                let is_test_file = nm.contains(".test.")
                                    || nm.contains(".spec.")
                                    || nm.starts_with("test_")
                                    || nm.ends_with("_test.go")
                                    || nm.ends_with("_test.rs");
                                if !is_test_file {
                                    continue;
                                }
                                if let Ok(txt) = fs::read_to_string(&p) {
                                    let low_t = txt.to_ascii_lowercase();
                                    let has_assert = low_t.contains("assert")
                                        || low_t.contains("expect(")
                                        || low_t.contains(".should")
                                        || low_t.contains("t.error")
                                        || low_t.contains("t.fatal")
                                        || low_t.contains("throw new error");
                                    if !has_assert {
                                        let rel = p
                                            .strip_prefix(scan_root)
                                            .unwrap_or(&p)
                                            .to_string_lossy()
                                            .replace('\\', "/");
                                        issues.push(format!(
                                            "[VACUOUS TEST RUN] `{rel}` contains 0 assertions (false-green test file)! Add real assertions."
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                issues.push(format!("Check failed (`{chk}`): {e}"));
            }
        }
    }

    let smoke_spec = scan_root.join(".agents").join("smoke.ap");
    if smoke_spec.is_file() {
        if let Ok(exe) = std::env::current_exe() {
            let exe_stem = exe.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if exe_stem.eq_ignore_ascii_case("ap") {
                if let Ok(o) = Command::new(&exe)
                    .args(["probe", "smoke", "--cwd"])
                    .arg(scan_root)
                    .arg("--spec")
                    .arg(&smoke_spec)
                    .output()
                {
                    if !o.status.success() {
                        let out_s = format!(
                            "{}{}",
                            String::from_utf8_lossy(&o.stdout),
                            String::from_utf8_lossy(&o.stderr)
                        );
                        issues.push(format!(
                            "Live smoke gate failed (`.agents/smoke.ap`):\n{}",
                            out_s.trim()
                        ));
                    }
                }
            }
        }
    }

    issues
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { EXIT_BLOCK } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match cli.subcmd {
        SubCmd::Reset => {
            let base = guard_dir(&cwd);
            save_ledger(&base, &[]);
            println!("[guard] loop ledger reset.");
            0
        }
        SubCmd::Shield { text } => {
            if !text.is_empty() {
                let findings = inspect_text_safety(&text);
                if !findings.is_empty() {
                    for f in findings {
                        eprintln!("[GUARD BLOCKED | exit 2] {f}");
                    }
                    eprintln!("Action halted. Request explicit human confirmation or sanitize secrets first.");
                    return EXIT_BLOCK;
                }
                println!("[guard] shield passed.");
                return 0;
            }

            let mut payload = String::new();
            if !std::io::stdin().is_terminal() {
                let _ = std::io::stdin().read_to_string(&mut payload);
            }
            let trimmed = payload.trim_start();
            if trimmed.starts_with('{') {
                if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(trimmed) {
                    // Antigravity camelCase hook contract (`hookEventName` / `toolCall`)
                    if map.contains_key("hookEventName") || map.contains_key("toolCall") {
                        let target_val = map.get("toolCall").cloned().unwrap_or(Value::Object(map));
                        let target_text = serde_json::to_string(&target_val).unwrap_or_default();
                        let findings = inspect_text_safety(&target_text);
                        if !findings.is_empty() {
                            println!(
                                "{}",
                                json!({
                                    "decision": "deny",
                                    "reason": format!("[GUARD BLOCKED] {}", findings.join("; "))
                                })
                            );
                        } else {
                            println!("{}", json!({ "decision": "allow" }));
                        }
                        return 0;
                    }
                    // Claude Code / Codex snake_case hook contract (`hook_event_name` / `tool_input`)
                    if map.contains_key("hook_event_name") || map.contains_key("tool_input") {
                        let is_pre_shell = map.get("hook_event_name").and_then(Value::as_str)
                            == Some("PreToolUse")
                            && matches!(
                                map.get("tool_name").and_then(Value::as_str),
                                Some("Bash" | "shell" | "exec_command")
                            );
                        let raw_cmd = map
                            .get("tool_input")
                            .and_then(|ti| ti.get("command"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        let target_val =
                            map.get("tool_input").cloned().unwrap_or(Value::Object(map));
                        let target_text = serde_json::to_string(&target_val).unwrap_or_default();
                        let findings = inspect_text_safety(&target_text);
                        if !findings.is_empty() {
                            for f in findings {
                                eprintln!("[GUARD BLOCKED | exit 2] {f}");
                            }
                            eprintln!("Action halted. Request explicit human confirmation or sanitize secrets first.");
                            return EXIT_BLOCK;
                        }
                        if is_pre_shell
                            && (should_auto_sieve(&raw_cmd) || should_auto_win_exec(&raw_cmd))
                        {
                            if let Ok(exe) = std::env::current_exe() {
                                if exe
                                    .file_stem()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or("")
                                    .eq_ignore_ascii_case("ap")
                                {
                                    let ap_p = exe.to_string_lossy().replace('\\', "/");
                                    let rewritten_cmd = if should_auto_sieve(&raw_cmd) {
                                        format!("\"{ap_p}\" sieve run -- {}", raw_cmd.trim())
                                    } else {
                                        let b64 = base64::engine::general_purpose::STANDARD
                                            .encode(raw_cmd.trim().as_bytes());
                                        format!("\"{ap_p}\" exec --base64 {b64}")
                                    };
                                    println!(
                                        "{}",
                                        json!({
                                            "hookSpecificOutput": {
                                                "hookEventName": "PreToolUse",
                                                "permissionDecision": "allow",
                                                "updatedInput": {
                                                    "command": rewritten_cmd
                                                }
                                            }
                                        })
                                    );
                                }
                            }
                        }
                        return 0;
                    }
                }
            }

            let findings = inspect_text_safety(&payload);
            if !findings.is_empty() {
                for f in findings {
                    eprintln!("[GUARD BLOCKED | exit 2] {f}");
                }
                eprintln!(
                    "Action halted. Request explicit human confirmation or sanitize secrets first."
                );
                return EXIT_BLOCK;
            }
            println!("[guard] shield passed.");
            0
        }
        SubCmd::Run { max_repeats, cmd } => {
            let clean_cmd: Vec<String> = if cmd.first().map(|s| s.as_str()) == Some("--") {
                cmd[1..].to_vec()
            } else {
                cmd
            };
            if clean_cmd.is_empty() {
                eprintln!("[guard] usage: ap guard run -- <command...>");
                return EXIT_BLOCK;
            }
            let cmd_str = clean_cmd.join(" ");
            let findings = inspect_text_safety(&cmd_str);
            if !findings.is_empty() {
                for f in findings {
                    eprintln!("[GUARD BLOCKED | exit 2] {f}");
                }
                return EXIT_BLOCK;
            }

            let base = guard_dir(&cwd);
            let prior = load_ledger(&base);
            let win_start = prior.len().saturating_sub(6);
            let cmd_key: String = cmd_str.chars().take(160).collect();
            let prior_fails = prior[win_start..]
                .iter()
                .filter(|e| e.cmd == cmd_key && e.exit != 0)
                .count();
            if prior_fails >= max_repeats {
                eprintln!(
                    "[GUARD LOOP BREAKER | exit 2] Command '{cmd_str}' already failed {prior_fails}x in a row.\n\
                     STOP retrying the identical command. Diagnose root cause or record a dead-end in `baton` first."
                );
                return EXIT_BLOCK;
            }

            let out = match spawn_command_list(&clean_cmd, &cwd) {
                Ok(o) => o,
                Err(err) => {
                    let msg = format!("Failed to spawn `{cmd_str}`: {err}\n");
                    eprint!("{msg}");
                    let (tripped, count, sig) =
                        record_attempt(&base, &cmd_str, 127, &msg, max_repeats);
                    if tripped {
                        eprintln!(
                            "\n[GUARD LOOP BREAKER | exit 2] Failure signature {sig} repeated {count}x.\n\
                             Do NOT re-run the same command unchanged. Formulate a new hypothesis first."
                        );
                        return EXIT_BLOCK;
                    }
                    return 127;
                }
            };

            let mut combined = String::from_utf8_lossy(&out.stdout).to_string();
            let err_s = String::from_utf8_lossy(&out.stderr);
            if !err_s.is_empty() {
                if !combined.is_empty() && !combined.ends_with('\n') {
                    combined.push('\n');
                }
                combined.push_str(&err_s);
            }
            if !combined.is_empty() {
                print!("{combined}");
            }
            let code = out.status.code().unwrap_or(1);
            let (tripped, count, sig) =
                record_attempt(&base, &cmd_str, code, &combined, max_repeats);
            if tripped {
                eprintln!(
                    "\n[GUARD LOOP BREAKER | exit 2] Failure signature {sig} repeated {count}x.\n\
                     Do NOT re-run the same command unchanged. Formulate a new hypothesis first."
                );
                return EXIT_BLOCK;
            }
            code
        }
        SubCmd::StopGate { checks } => {
            let mut raw_in = String::new();
            if !std::io::stdin().is_terminal() {
                let _ = std::io::stdin().read_to_string(&mut raw_in);
            }
            let hook_obj = if raw_in.trim_start().starts_with('{') {
                serde_json::from_str::<Value>(raw_in.trim_start())
                    .ok()
                    .and_then(|v| v.as_object().cloned())
            } else {
                None
            };

            let is_agy = hook_obj
                .as_ref()
                .map(|m| m.contains_key("hookEventName") || m.contains_key("terminationReason"))
                .unwrap_or(false);
            let is_claude = hook_obj
                .as_ref()
                .map(|m| m.contains_key("hook_event_name") || m.contains_key("stop_hook_active"))
                .unwrap_or(false);

            if is_agy {
                if let Some(m) = &hook_obj {
                    let cont = m
                        .get("continuationActive")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let reason = m
                        .get("terminationReason")
                        .and_then(Value::as_str)
                        .unwrap_or("NO_TOOL_CALL");
                    if cont || reason != "NO_TOOL_CALL" {
                        println!("{}", json!({ "decision": "stop" }));
                        return 0;
                    }
                }
            }
            if is_claude {
                if let Some(m) = &hook_obj {
                    if m.get("stop_hook_active")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        return 0;
                    }
                }
            }

            let scan_root = hook_obj
                .as_ref()
                .and_then(|m| m.get("cwd"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .unwrap_or(cwd);

            let issues = collect_verification_issues(&scan_root, &checks, false, false);

            if is_agy {
                if !issues.is_empty() {
                    println!(
                        "{}",
                        json!({
                            "decision": "continue",
                            "reason": format!("[GUARD STOP-GATE] Cannot finish yet: {}", issues.join("; "))
                        })
                    );
                } else {
                    println!("{}", json!({ "decision": "stop" }));
                }
                return 0;
            }

            if !issues.is_empty() {
                eprintln!("[GUARD STOP-GATE BLOCKED | exit 2] Cannot mark task complete:");
                for item in issues {
                    eprintln!("- {item}");
                }
                return EXIT_BLOCK;
            }
            if !is_claude {
                println!("[guard] stop-gate verified clean.");
            }
            0
        }
        SubCmd::Verify {
            cwd,
            all,
            deep,
            checks,
        } => {
            let mut issues = collect_verification_issues(&cwd, &checks, all || deep, true);
            let mut receipts = Vec::new();
            if issues.is_empty() && deep {
                let (di, dr) = run_deep_creation_and_test_gates(&cwd);
                issues.extend(di);
                receipts.extend(dr);
            }
            if !issues.is_empty() {
                eprintln!(
                    "[GUARD VERIFY BLOCKED | exit 2] {} verification failure(s):",
                    issues.len()
                );
                for item in issues {
                    eprintln!("- {item}");
                }
                return EXIT_BLOCK;
            }
            if deep {
                println!(
                    "[guard verify --deep] PASS — 0 issues across all {} verified deep gate(s):",
                    receipts.len() + 1
                );
                println!(
                    "  - [tests/slop] 0 secret/conflict/anti-slop violations; unit tests passed"
                );
                for r in receipts {
                    println!("  - {r}");
                }
            } else {
                println!("[guard verify] PASS — 0 secret/conflict leaks, 0 code-rule/slop violations, all checks green.");
            }
            0
        }
        SubCmd::Sec { cwd, json } => {
            let findings = sec::scan_security_issues(&cwd);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": findings.is_empty(),
                        "count": findings.len(),
                        "findings": findings
                    }))
                    .unwrap_or_default()
                );
            } else if findings.is_empty() {
                println!("[guard sec] PASS — 0 SQLi, Path Traversal, Command Injection, DOM XSS, SSRF, Deser, C/C++ memory-copy/overflow, or Debug/TLS flaws detected.");
            } else {
                eprintln!(
                    "[GUARD SEC BLOCKED | exit 2] {} security issue(s) found:",
                    findings.len()
                );
                for f in &findings {
                    eprintln!(
                        "  - [{}] {}:L{} `{}` -> {}",
                        f.cwe, f.file, f.line, f.snippet, f.fix
                    );
                }
            }
            if findings.is_empty() {
                0
            } else {
                EXIT_BLOCK
            }
        }
        SubCmd::Diff { cwd, json } => {
            let rep = diff_audit::audit_git_diff(&cwd);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": rep.findings.is_empty(),
                        "is_git_repo": rep.is_git_repo,
                        "files_changed": rep.files_changed,
                        "lines_added": rep.lines_added,
                        "lines_deleted": rep.lines_deleted,
                        "findings": rep.findings,
                        "api_changes": rep.api_changes,
                    }))
                    .unwrap_or_default()
                );
            } else if !rep.is_git_repo {
                println!("[guard diff] Not a git repository (skipped).");
            } else if rep.findings.is_empty() {
                println!(
                    "[guard diff] PASS — {} file(s) changed (+{}/-{}), 0 test-weakening, debug-leftover, or mass-deletion issues.",
                    rep.files_changed, rep.lines_added, rep.lines_deleted
                );
                if !rep.api_changes.is_empty() {
                    println!("  API Surface Shifts ({}):", rep.api_changes.len());
                    for ac in &rep.api_changes {
                        println!("  - [{}] {}", ac.kind, ac.detail);
                    }
                }
            } else {
                eprintln!(
                    "[GUARD DIFF BLOCKED | exit 2] {} regression(s) in git diff ({} file(s), +{}/-{}):",
                    rep.findings.len(),
                    rep.files_changed,
                    rep.lines_added,
                    rep.lines_deleted
                );
                for f in &rep.findings {
                    eprintln!("  - [{}] {}", f.kind, f.detail);
                }
                if !rep.api_changes.is_empty() {
                    eprintln!("  API Surface Shifts ({}):", rep.api_changes.len());
                    for ac in &rep.api_changes {
                        eprintln!("  - [{}] {}", ac.kind, ac.detail);
                    }
                }
            }
            if rep.findings.is_empty() {
                0
            } else {
                EXIT_BLOCK
            }
        }
        SubCmd::Rule { action } => match action {
            RuleCmd::Init { cwd } => {
                let cfg = rules::default_guard_config(&cwd);
                match rules::save_config(&cwd, &cfg) {
                    Ok(p) => {
                        println!(
                            "[guard rule init] Wrote {} rule(s) & {} check(s) -> {}",
                            cfg.rules.len(),
                            cfg.checks.len(),
                            p.display()
                        );
                        0
                    }
                    Err(e) => {
                        eprintln!("[guard rule init] {e}");
                        1
                    }
                }
            }
            RuleCmd::Add {
                cwd,
                id,
                glob,
                forbid,
                msg,
            } => {
                if let Err(e) = Regex::new(&forbid) {
                    eprintln!("[guard rule add] invalid regex `{forbid}`: {e}");
                    return EXIT_BLOCK;
                }
                let mut cfg =
                    rules::load_config(&cwd).unwrap_or_else(|| rules::default_guard_config(&cwd));
                cfg.rules.retain(|r| r.id != id);
                cfg.rules.push(rules::CodeRule {
                    id: id.clone(),
                    glob,
                    forbid,
                    message: msg,
                });
                match rules::save_config(&cwd, &cfg) {
                    Ok(p) => {
                        println!("[guard rule add] Saved rule `{id}` -> {}", p.display());
                        0
                    }
                    Err(e) => {
                        eprintln!("[guard rule add] {e}");
                        1
                    }
                }
            }
            RuleCmd::List { cwd } => {
                let cfg =
                    rules::load_config(&cwd).unwrap_or_else(|| rules::default_guard_config(&cwd));
                println!("{}", serde_json::to_string_pretty(&cfg).unwrap_or_default());
                0
            }
        },
        SubCmd::Pack {
            dir,
            max_lines,
            require_headers,
            json,
        } => pack::run_pack_audit(&dir, max_lines, &require_headers, json),
    }
}
