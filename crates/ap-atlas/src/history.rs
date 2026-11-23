use crate::changes::{collect_symbol_spans, lang_for_ext};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;
use tree_sitter::Parser;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryCommit {
    pub hash: String,
    pub short_hash: String,
    pub date: String,
    pub author: String,
    pub subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorShare {
    pub author: String,
    pub lines: usize,
    pub share_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoChangedFile {
    pub path: String,
    pub co_changes: usize,
    pub ratio_pct: f64,
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryReport {
    pub is_git_repo: bool,
    pub repo_root: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_range: Option<(usize, usize)>,
    pub elapsed_ms: f64,
    pub total_commits_sampled: usize,
    pub commits: Vec<HistoryCommit>,
    pub owners: Vec<AuthorShare>,
    pub co_changed_files: Vec<CoChangedFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

fn norm_posix_str(p: &Path) -> String {
    p.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}

fn parse_lines_arg(raw: &str) -> Option<(usize, usize)> {
    static LINE_RE: OnceLock<Regex> = OnceLock::new();
    let re =
        LINE_RE.get_or_init(|| Regex::new(r"(?i)^\s*L?(\d+)(?:\s*[-:,]\s*L?(\d+))?\s*$").unwrap());
    let caps = re.captures(raw)?;
    let s: usize = caps.get(1)?.as_str().parse().ok()?;
    let e: usize = caps
        .get(2)
        .and_then(|m| m.as_str().parse().ok())
        .unwrap_or(s);
    let s = s.max(1);
    let e = e.max(s);
    Some((s, e))
}

fn resolve_symbol_range(abs_file: &Path, symbol: &str) -> Option<(String, usize, usize)> {
    let ext = abs_file.extension().and_then(|e| e.to_str()).unwrap_or("");
    let lang = lang_for_ext(ext)?;
    let bytes = fs::read(abs_file).ok()?;
    let body = String::from_utf8_lossy(&bytes);
    let mut parser = Parser::new();
    parser.set_language(&lang).ok()?;
    let tree = parser.parse(body.as_ref(), None)?;
    let mut spans = Vec::new();
    collect_symbol_spans(tree.root_node(), body.as_bytes(), &mut spans);
    if spans.is_empty() {
        return None;
    }
    let sym_trimmed = symbol.trim();
    if let Some((nm, s, e)) = spans.iter().find(|(nm, _, _)| nm == sym_trimmed) {
        return Some((nm.clone(), *s, *e));
    }
    let short = sym_trimmed
        .rsplit("::")
        .next()
        .unwrap_or(sym_trimmed)
        .rsplit('.')
        .next()
        .unwrap_or(sym_trimmed);
    if let Some((nm, s, e)) = spans.iter().find(|(nm, _, _)| {
        nm == short || nm.ends_with(&format!("::{short}")) || nm.ends_with(&format!(".{short}"))
    }) {
        return Some((nm.clone(), *s, *e));
    }
    let low = sym_trimmed.to_ascii_lowercase();
    if let Some((nm, s, e)) = spans
        .iter()
        .find(|(nm, _, _)| nm.to_ascii_lowercase() == low)
    {
        return Some((nm.clone(), *s, *e));
    }
    None
}

fn parse_git_commits(raw: &str) -> Vec<HistoryCommit> {
    let mut commits = Vec::new();
    let mut seen = HashSet::new();
    for line in raw.lines() {
        let mut parts = line.splitn(5, '\x1f');
        let (Some(hash), Some(short_hash), Some(date), Some(author), Some(subject)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        let h = hash.trim();
        if h.len() < 7 || !seen.insert(h.to_string()) {
            continue;
        }
        commits.push(HistoryCommit {
            hash: h.to_string(),
            short_hash: short_hash.trim().to_string(),
            date: date.trim().to_string(),
            author: author.trim().to_string(),
            subject: subject.trim().chars().take(160).collect(),
        });
    }
    commits
}

fn resolve_rel_path(abs_file: &Path, canon_repo_root: &Path, raw_file_arg: &Path) -> String {
    if let Ok(rel) = abs_file.strip_prefix(canon_repo_root) {
        return rel.to_string_lossy().replace('\\', "/");
    }
    if let Some(work_dir) = abs_file.parent() {
        if let Some(name) = abs_file.file_name() {
            if let Ok(out) = Command::new("git")
                .args(["ls-files", "--full-name", "--"])
                .arg(name)
                .current_dir(work_dir)
                .output()
            {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !s.is_empty() {
                        return s.replace('\\', "/");
                    }
                }
            }
        }
    }
    norm_posix_str(raw_file_arg)
}

pub fn analyze_file_history(
    file_path: &Path,
    symbol_opt: Option<&str>,
    lines_opt: Option<&str>,
    limit: usize,
) -> HistoryReport {
    let t0 = Instant::now();
    let limit = limit.clamp(1, 25);

    if !file_path.exists() {
        return HistoryReport {
            is_git_repo: false,
            repo_root: String::new(),
            file: norm_posix_str(file_path),
            resolved_symbol: None,
            line_range: None,
            elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
            total_commits_sampled: 0,
            commits: Vec::new(),
            owners: Vec::new(),
            co_changed_files: Vec::new(),
            note: Some(format!("File not found: {}", norm_posix_str(file_path))),
        };
    }

    let abs_file = fs::canonicalize(file_path).unwrap_or_else(|_| file_path.to_path_buf());
    let work_dir = abs_file.parent().unwrap_or_else(|| Path::new("."));

    let top_out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(work_dir)
        .output();
    let Ok(top) = top_out else {
        return HistoryReport {
            is_git_repo: false,
            repo_root: String::new(),
            file: norm_posix_str(&abs_file),
            resolved_symbol: None,
            line_range: None,
            elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
            total_commits_sampled: 0,
            commits: Vec::new(),
            owners: Vec::new(),
            co_changed_files: Vec::new(),
            note: Some("Unable to execute `git rev-parse --show-toplevel`.".to_string()),
        };
    };
    if !top.status.success() {
        return HistoryReport {
            is_git_repo: false,
            repo_root: String::new(),
            file: norm_posix_str(&abs_file),
            resolved_symbol: None,
            line_range: None,
            elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
            total_commits_sampled: 0,
            commits: Vec::new(),
            owners: Vec::new(),
            co_changed_files: Vec::new(),
            note: Some("Not inside a git working tree.".to_string()),
        };
    }

    let raw_root = PathBuf::from(String::from_utf8_lossy(&top.stdout).trim());
    let repo_root = fs::canonicalize(&raw_root).unwrap_or(raw_root);
    let rel_path = resolve_rel_path(&abs_file, &repo_root, file_path);

    let file_lines = fs::read(&abs_file)
        .map(|b| String::from_utf8_lossy(&b).lines().count().max(1))
        .unwrap_or(1);

    let mut note: Option<String> = None;
    let mut resolved_symbol: Option<String> = None;
    let mut line_range: Option<(usize, usize)> = None;

    if let Some(sym) = symbol_opt.map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((nm, s, e)) = resolve_symbol_range(&abs_file, sym) {
            resolved_symbol = Some(nm);
            line_range = Some((s.min(file_lines), e.min(file_lines).max(s.min(file_lines))));
        } else {
            note = Some(format!(
                "Symbol `{sym}` not found in `{rel_path}`; showing file-level history."
            ));
        }
    } else if let Some(lr_raw) = lines_opt.map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((s, e)) = parse_lines_arg(lr_raw) {
            let cs = s.min(file_lines).max(1);
            let ce = e.min(file_lines).max(cs);
            line_range = Some((cs, ce));
        } else {
            note = Some(format!(
                "Invalid line range `{lr_raw}`; showing file-level history."
            ));
        }
    }

    let fmt_str = "%H\x1f%h\x1f%ad\x1f%an\x1f%s";
    let mut commits = Vec::new();
    if let Some((s, e)) = line_range {
        let range_spec = format!("{s},{e}:{rel_path}");
        if let Ok(out) = Command::new("git")
            .args([
                "log",
                "-s",
                "--no-patch",
                "-n",
                &limit.to_string(),
                "-L",
                &range_spec,
                &format!("--format={fmt_str}"),
                "--date=short",
            ])
            .current_dir(&repo_root)
            .output()
        {
            if out.status.success() {
                commits = parse_git_commits(&String::from_utf8_lossy(&out.stdout));
            }
        }
    }
    if commits.is_empty() {
        if let Ok(out) = Command::new("git")
            .args([
                "log",
                "-n",
                &limit.to_string(),
                "--follow",
                &format!("--format={fmt_str}"),
                "--date=short",
                "--",
                &rel_path,
            ])
            .current_dir(&repo_root)
            .output()
        {
            if out.status.success() {
                commits = parse_git_commits(&String::from_utf8_lossy(&out.stdout));
            }
        }
    }

    // Blame authorship summary over resolved span or up to 400 lines
    let (bs, be) = line_range.unwrap_or((1, file_lines.min(400)));
    let mut author_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut blamed_total = 0usize;
    if let Ok(out) = Command::new("git")
        .args([
            "blame",
            "--line-porcelain",
            "-L",
            &format!("{bs},{be}"),
            "--",
            &rel_path,
        ])
        .current_dir(&repo_root)
        .output()
    {
        if out.status.success() {
            for ln in String::from_utf8_lossy(&out.stdout).lines() {
                if let Some(author) = ln.strip_prefix("author ") {
                    let a = author.trim();
                    if !a.is_empty() {
                        *author_counts.entry(a.to_string()).or_insert(0) += 1;
                        blamed_total += 1;
                    }
                }
            }
        }
    }
    let mut owner_pairs: Vec<(String, usize)> = author_counts.into_iter().collect();
    owner_pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let owners: Vec<AuthorShare> = owner_pairs
        .into_iter()
        .take(5)
        .map(|(author, lines)| AuthorShare {
            author,
            lines,
            share_pct: if blamed_total > 0 {
                ((lines as f64 / blamed_total as f64) * 1000.0).round() / 10.0
            } else {
                0.0
            },
        })
        .collect();

    // Temporal co-change coupling across up to 40 recent commits touching rel_path
    let mut total_commits_sampled = 0usize;
    let mut co_counts: BTreeMap<String, usize> = BTreeMap::new();
    let hashes: Vec<String> = Command::new("git")
        .args([
            "log",
            "-n",
            "40",
            "--follow",
            "--format=format:%H",
            "--",
            &rel_path,
        ])
        .current_dir(&repo_root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::trim)
                .filter(|s| s.len() >= 7)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();

    if !hashes.is_empty() {
        let mut cmd = Command::new("git");
        cmd.args([
            "log",
            "--no-walk",
            "--name-only",
            "--format=format:---AP-COMMIT---",
        ])
        .args(&hashes)
        .current_dir(&repo_root);
        if let Ok(out) = cmd.output() {
            if out.status.success() {
                let mut in_commit = false;
                let mut bucket: HashSet<String> = HashSet::new();
                let flush = |bucket: &mut HashSet<String>,
                             total: &mut usize,
                             co: &mut BTreeMap<String, usize>,
                             self_rel: &str| {
                    *total += 1;
                    for p in bucket.drain() {
                        if p != self_rel {
                            *co.entry(p).or_insert(0) += 1;
                        }
                    }
                };
                for raw_ln in String::from_utf8_lossy(&out.stdout).lines() {
                    let ln = raw_ln.trim();
                    if ln == "---AP-COMMIT---" {
                        if in_commit {
                            flush(
                                &mut bucket,
                                &mut total_commits_sampled,
                                &mut co_counts,
                                &rel_path,
                            );
                        }
                        in_commit = true;
                        continue;
                    }
                    if in_commit && !ln.is_empty() {
                        bucket.insert(ln.replace('\\', "/"));
                    }
                }
                if in_commit {
                    flush(
                        &mut bucket,
                        &mut total_commits_sampled,
                        &mut co_counts,
                        &rel_path,
                    );
                }
            }
        }
    }

    let mut co_pairs: Vec<(String, usize)> = co_counts.into_iter().collect();
    co_pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let co_changed_files: Vec<CoChangedFile> = co_pairs
        .into_iter()
        .take(8)
        .map(|(path, co_changes)| {
            let ratio_pct = if total_commits_sampled > 0 {
                ((co_changes as f64 / total_commits_sampled as f64) * 1000.0).round() / 10.0
            } else {
                0.0
            };
            let exists = repo_root.join(&path).exists();
            CoChangedFile {
                path,
                co_changes,
                ratio_pct,
                exists,
            }
        })
        .collect();

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
    HistoryReport {
        is_git_repo: true,
        repo_root: norm_posix_str(&repo_root),
        file: rel_path,
        resolved_symbol,
        line_range,
        elapsed_ms,
        total_commits_sampled,
        commits,
        owners,
        co_changed_files,
        note,
    }
}

pub fn render_history_md(rep: &HistoryReport) -> String {
    if !rep.is_git_repo {
        let msg = rep
            .note
            .as_deref()
            .unwrap_or("Not inside a git working tree.");
        return format!("[atlas history] {msg}");
    }
    let scope = match (&rep.resolved_symbol, rep.line_range) {
        (Some(sym), Some((s, e))) => format!("symbol `{sym}` L{s}-L{e}"),
        (None, Some((s, e))) => format!("L{s}-L{e}"),
        _ => "file".to_string(),
    };
    let mut out = vec![format!(
        "# GIT HISTORY & TEMPORAL COUPLING (`{}` | {} | {}ms)",
        rep.file, scope, rep.elapsed_ms
    )];
    if let Some(n) = &rep.note {
        out.push(format!("> Note: {n}"));
    }
    out.push(format!("\n## Recent Commits ({})", rep.commits.len()));
    if rep.commits.is_empty() {
        out.push("- (no committed history recorded yet)".to_string());
    } else {
        for c in &rep.commits {
            out.push(format!(
                "- `{}` {} **{}** — {}",
                c.short_hash, c.date, c.author, c.subject
            ));
        }
    }
    if !rep.owners.is_empty() {
        out.push("\n## Blame Authorship".to_string());
        for o in &rep.owners {
            out.push(format!(
                "- **{}**: {} lines ({:.1}%)",
                o.author, o.lines, o.share_pct
            ));
        }
    }
    if !rep.co_changed_files.is_empty() {
        out.push(format!(
            "\n## Temporal Co-Change Hotspots (across {} commits)",
            rep.total_commits_sampled
        ));
        for co in &rep.co_changed_files {
            let gone = if co.exists { "" } else { " [deleted/moved]" };
            out.push(format!(
                "- `{}` — {}/{} commits ({:.1}%){gone}",
                co.path, co.co_changes, rep.total_commits_sampled, co.ratio_pct
            ));
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("git command");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn history_symbol_blame_and_cochange_work_on_temp_repo() {
        struct TempClean(PathBuf);
        impl Drop for TempClean {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root_buf =
            std::env::temp_dir().join(format!("ap_atlas_hist_{}_{}", std::process::id(), uniq));
        let _ = fs::remove_dir_all(&root_buf);
        fs::create_dir_all(&root_buf).unwrap();
        let _guard = TempClean(root_buf.clone());
        let root = root_buf.as_path();
        run_git(root, &["init"]);
        run_git(root, &["config", "user.name", "Test Author"]);
        run_git(root, &["config", "user.email", "test@example.com"]);

        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::create_dir_all(root.join("docs")).unwrap();

        fs::write(root.join("docs/notes.md"), "# Notes\n").unwrap();
        run_git(root, &["add", "docs/notes.md"]);
        run_git(root, &["commit", "-m", "docs: add initial notes"]);

        fs::write(
            root.join("src/calc.py"),
            "def compute_total(price, qty):\n    return price * qty\n\ndef format_label(v):\n    return str(v)\n",
        )
        .unwrap();
        fs::write(
            root.join("tests/test_calc.py"),
            "def test_basic():\n    assert True\n",
        )
        .unwrap();
        run_git(root, &["add", "src/calc.py", "tests/test_calc.py"]);
        run_git(root, &["commit", "-m", "feat: add compute_total and test"]);

        fs::write(
            root.join("src/calc.py"),
            "def compute_total(price, qty, tax=0):\n    return price * qty + tax\n\ndef format_label(v):\n    return str(v)\n",
        )
        .unwrap();
        fs::write(
            root.join("tests/test_calc.py"),
            "def test_basic():\n    assert True\n\ndef test_tax():\n    assert True\n",
        )
        .unwrap();
        run_git(root, &["add", "src/calc.py", "tests/test_calc.py"]);
        run_git(
            root,
            &["commit", "-m", "fix: support optional tax in compute_total"],
        );

        let rep = analyze_file_history(&root.join("src/calc.py"), Some("compute_total"), None, 8);
        assert!(rep.is_git_repo);
        assert_eq!(rep.resolved_symbol.as_deref(), Some("compute_total"));
        assert_eq!(rep.line_range, Some((1, 2)));
        assert!(!rep.commits.is_empty(), "{rep:?}");
        assert!(
            rep.commits
                .iter()
                .any(|c| c.subject.contains("support optional tax")),
            "{:?}",
            rep.commits
        );
        assert_eq!(
            rep.owners.first().map(|o| o.author.as_str()),
            Some("Test Author")
        );
        assert_eq!(
            rep.co_changed_files.first().map(|c| c.path.as_str()),
            Some("tests/test_calc.py")
        );
        assert!(!rep
            .co_changed_files
            .iter()
            .any(|c| c.path == "docs/notes.md"));

        let md = render_history_md(&rep);
        assert!(md.contains("compute_total"));
        assert!(md.contains("tests/test_calc.py"));
        assert!(md.contains("Test Author"));
    }
}
