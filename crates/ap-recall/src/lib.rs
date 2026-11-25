use clap::{Parser, Subcommand};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub id: String,
    pub kind: String,
    pub triggers: String,
    pub rule: String,
    pub score: f64,
    pub hits: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_file: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stale_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaleRuleEntry {
    pub id: String,
    pub kind: String,
    pub triggers: String,
    pub source_file: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub total_rules: usize,
    pub tracked_rules: usize,
    pub fresh_rules: usize,
    pub stale_rules: usize,
    pub pruned_rules: usize,
    pub stale_entries: Vec<StaleRuleEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStats {
    pub total_rules: usize,
    pub monolithic_tokens_if_always_loaded: usize,
    pub typical_top3_injected_tokens: usize,
    pub total_hits: i64,
}

#[derive(Parser, Debug)]
#[command(
    name = "recall",
    about = "Sub-millisecond triggered micro-memory vault (bundled SQLite FTS5)"
)]
struct Cli {
    #[command(subcommand)]
    subcmd: SubCmd,
}

#[derive(Subcommand, Debug)]
enum SubCmd {
    /// Add or update a triggered micro-rule (optionally bound to a source file hash & git commit)
    Add {
        #[arg(long)]
        triggers: String,
        #[arg(long)]
        rule: String,
        #[arg(long, default_value = "gotcha")]
        kind: String,
        #[arg(long = "file", default_value = "")]
        source_file: String,
    },
    /// Retrieve top-K matching rules in <1ms
    Match {
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long, default_value = "")]
        files: String,
        #[arg(long, default_value_t = 3)]
        top: usize,
        /// Optional rule kind filter (e.g. 'gotcha', 'pattern', 'negative', 'deadend')
        #[arg(long, default_value = "")]
        kind: String,
        /// Optional total character budget across emitted rules (0 = unlimited)
        #[arg(long, default_value_t = 0)]
        max_chars: usize,
        #[arg(long)]
        json: bool,
    },
    /// Verify file-backed rule provenance and detect or prune stale rules
    Verify {
        #[arg(long)]
        prune_stale: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show vault size, token comparison, and hit metrics
    Stats {
        #[arg(long)]
        json: bool,
    },
    /// Delete zero-hit rules older than N days
    Prune {
        #[arg(long, default_value_t = 90)]
        stale_days: i64,
    },
}

fn is_cjk(c: char) -> bool {
    ('\u{4e00}'..='\u{9fff}').contains(&c)
}

pub fn tokenize_cjk_hybrid(text: &str) -> String {
    let mut out_tokens: Vec<String> = Vec::new();
    let mut cur_ascii = String::new();
    let mut cjk_buf: Vec<char> = Vec::new();

    let flush_ascii = |buf: &mut String, out: &mut Vec<String>| {
        if !buf.is_empty() {
            for w in buf.split_whitespace() {
                if !w.is_empty() {
                    out.push(w.to_string());
                }
            }
            buf.clear();
        }
    };

    let flush_cjk = |buf: &mut Vec<char>, out: &mut Vec<String>| {
        if !buf.is_empty() {
            for &ch in buf.iter() {
                out.push(ch.to_string());
            }
            for win in buf.windows(2) {
                let mut bi = String::with_capacity(6);
                bi.push(win[0]);
                bi.push(win[1]);
                out.push(bi);
            }
            buf.clear();
        }
    };

    for ch in text.chars() {
        if is_cjk(ch) {
            flush_ascii(&mut cur_ascii, &mut out_tokens);
            cjk_buf.push(ch);
        } else {
            flush_cjk(&mut cjk_buf, &mut out_tokens);
            cur_ascii.push(ch);
        }
    }
    flush_ascii(&mut cur_ascii, &mut out_tokens);
    flush_cjk(&mut cjk_buf, &mut out_tokens);
    out_tokens.join(" ")
}

pub fn vault_path(cwd: &Path) -> PathBuf {
    let base = match std::env::var("RECALL_HOME") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => cwd.join(".recall"),
    };
    let _ = fs::create_dir_all(&base);
    let gi = base.join(".gitignore");
    if !gi.exists() {
        let _ = fs::write(&gi, "*.db-journal\n*.db-wal\n*.db-shm\n");
    }
    base.join("vault.db")
}

pub fn open_vault(db_path: &Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = db_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let conn = Connection::open(db_path)?;
    let _ = conn.busy_timeout(std::time::Duration::from_millis(2000));
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            triggers TEXT NOT NULL,
            rule TEXT NOT NULL,
            search_tokens TEXT NOT NULL,
            hits INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            last_hit_at INTEGER NOT NULL DEFAULT 0,
            source_file TEXT NOT NULL DEFAULT '',
            source_hash TEXT NOT NULL DEFAULT '',
            git_commit TEXT NOT NULL DEFAULT ''
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS rules_fts USING fts5(
            id UNINDEXED,
            search_tokens,
            tokenize='unicode61'
        );",
    )?;
    let mut existing_cols: HashSet<String> = HashSet::new();
    {
        let mut stmt = conn.prepare("PRAGMA table_info(rules)")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
        for col in rows.flatten() {
            existing_cols.insert(col);
        }
    }
    for (col, ddl) in [
        (
            "source_file",
            "ALTER TABLE rules ADD COLUMN source_file TEXT NOT NULL DEFAULT ''",
        ),
        (
            "source_hash",
            "ALTER TABLE rules ADD COLUMN source_hash TEXT NOT NULL DEFAULT ''",
        ),
        (
            "git_commit",
            "ALTER TABLE rules ADD COLUMN git_commit TEXT NOT NULL DEFAULT ''",
        ),
    ] {
        if !existing_cols.contains(col) {
            conn.execute(ddl, [])?;
        }
    }
    Ok(conn)
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn normalize_source_file(source_file: &str) -> String {
    source_file
        .trim()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string()
}

fn resolve_provenance_path(cwd: &Path, source_file: &str) -> PathBuf {
    let p = Path::new(source_file);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

fn hash_file_short(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(format!("{:x}", hasher.finalize())[..16].to_string())
}

fn git_head_short(cwd: &Path) -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(cwd)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn check_provenance(cwd: &Path, source_file: &str, source_hash: &str) -> (bool, String) {
    if source_file.is_empty() || source_hash.is_empty() {
        return (false, String::new());
    }
    let resolved = resolve_provenance_path(cwd, source_file);
    if !resolved.exists() {
        return (true, "source_file_deleted".to_string());
    }
    if hash_file_short(&resolved).as_deref() != Some(source_hash) {
        return (true, "source_file_modified".to_string());
    }
    (false, String::new())
}

pub fn add_rule(
    conn: &Connection,
    triggers: &str,
    rule: &str,
    kind: &str,
) -> rusqlite::Result<String> {
    add_rule_with_provenance(conn, Path::new("."), triggers, rule, kind, "")
}

pub fn add_rule_with_provenance(
    conn: &Connection,
    cwd: &Path,
    triggers: &str,
    rule: &str,
    kind: &str,
    source_file: &str,
) -> rusqlite::Result<String> {
    let norm_rule = rule.split_whitespace().collect::<Vec<_>>().join(" ");
    let norm_trig = triggers
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    let norm_src = normalize_source_file(source_file);
    let (src_hash, git_commit) = if norm_src.is_empty() {
        (String::new(), String::new())
    } else {
        let resolved = resolve_provenance_path(cwd, &norm_src);
        (
            hash_file_short(&resolved).unwrap_or_default(),
            git_head_short(cwd),
        )
    };
    let mut hasher = Sha256::new();
    hasher.update(format!("{norm_trig}::{norm_rule}").as_bytes());
    let rule_id = format!("{:x}", hasher.finalize())[..10].to_string();
    let now = now_epoch();
    let tokens = tokenize_cjk_hybrid(&format!(
        "{} {norm_rule} {kind}",
        norm_trig.replace(',', " ")
    ));

    conn.execute(
        "INSERT INTO rules (id, kind, triggers, rule, search_tokens, hits, created_at, last_hit_at, source_file, source_hash, git_commit)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, 0, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET
             kind=excluded.kind,
             triggers=excluded.triggers,
             rule=excluded.rule,
             search_tokens=excluded.search_tokens,
             source_file=excluded.source_file,
             source_hash=excluded.source_hash,
             git_commit=excluded.git_commit",
        params![
            rule_id, kind, norm_trig, norm_rule, tokens, now, norm_src, src_hash, git_commit
        ],
    )?;
    conn.execute("DELETE FROM rules_fts WHERE id = ?1", params![rule_id])?;
    conn.execute(
        "INSERT INTO rules_fts (id, search_tokens) VALUES (?1, ?2)",
        params![rule_id, tokens],
    )?;
    Ok(rule_id)
}

fn wildcard_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
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

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn contains_token_bounded(haystack: &str, needle: &str, block_left_slash: bool) -> bool {
    if needle.is_empty() {
        return false;
    }
    for (idx, _) in haystack.match_indices(needle) {
        let left_ok = match haystack[..idx].chars().next_back() {
            None => true,
            Some(c) => !is_ident_char(c) && !(block_left_slash && c == '/'),
        };
        let right_idx = idx + needle.len();
        let right_ok = match haystack[right_idx..].chars().next() {
            None => true,
            Some(c) => !is_ident_char(c),
        };
        if left_ok && right_ok {
            return true;
        }
    }
    false
}

struct StoredRow {
    kind: String,
    triggers: String,
    rule: String,
    hits: i64,
    created_at: i64,
    source_file: String,
    source_hash: String,
}

fn is_negative_kind(kind: &str) -> bool {
    let k = kind.to_ascii_lowercase();
    matches!(
        k.as_str(),
        "negative" | "deadend" | "trap" | "anti" | "blocker" | "forbidden"
    ) || k.contains("negative")
        || k.contains("deadend")
}

pub fn match_rules(
    conn: &Connection,
    query: &str,
    files: &[String],
    top_k: usize,
) -> rusqlite::Result<(Vec<RuleMatch>, f64)> {
    match_rules_in(conn, Path::new("."), query, files, top_k)
}

pub fn match_rules_in(
    conn: &Connection,
    cwd: &Path,
    query: &str,
    files: &[String],
    top_k: usize,
) -> rusqlite::Result<(Vec<RuleMatch>, f64)> {
    match_rules_with_opts(conn, cwd, query, files, top_k, None, 0)
}

pub fn match_rules_with_opts(
    conn: &Connection,
    cwd: &Path,
    query: &str,
    files: &[String],
    top_k: usize,
    kind_filter: Option<&str>,
    max_chars: usize,
) -> rusqlite::Result<(Vec<RuleMatch>, f64)> {
    let t0 = Instant::now();
    let mut scores: HashMap<String, f64> = HashMap::new();
    let mut rows_by_id: HashMap<String, StoredRow> = HashMap::new();

    let kind_req = kind_filter
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());
    let q_lower = query.to_lowercase();
    let norm_files: Vec<String> = files
        .iter()
        .map(|f| {
            f.trim()
                .replace('\\', "/")
                .trim_start_matches("./")
                .to_string()
        })
        .filter(|f| !f.is_empty())
        .collect();
    let norm_files_lower: Vec<String> = norm_files.iter().map(|f| f.to_lowercase()).collect();

    {
        let mut stmt = conn.prepare(
            "SELECT id, kind, triggers, rule, hits, created_at, source_file, source_hash FROM rules",
        )?;
        let iter = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                StoredRow {
                    kind: r.get(1)?,
                    triggers: r.get(2)?,
                    rule: r.get(3)?,
                    hits: r.get(4)?,
                    created_at: r.get(5)?,
                    source_file: r.get(6)?,
                    source_hash: r.get(7)?,
                },
            ))
        })?;
        for item in iter {
            let (rid, row) = item?;
            if let Some(ref kr) = kind_req {
                if !row.kind.to_ascii_lowercase().contains(kr.as_str()) {
                    continue;
                }
            }
            let mut sc = 0.0;
            for trig in row
                .triggers
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let tl = trig.to_lowercase().replace('\\', "/");
                if tl.contains('*') || tl.contains('?') || tl.contains('/') {
                    let prefix = tl.trim_end_matches(['/', '*']);
                    for nfl in &norm_files_lower {
                        if wildcard_match(&tl, nfl)
                            || (!prefix.is_empty()
                                && (nfl == prefix || nfl.starts_with(&format!("{prefix}/"))))
                        {
                            sc += 8.0;
                        }
                    }
                    if !prefix.is_empty() && contains_token_bounded(&q_lower, prefix, true) {
                        sc += 4.0;
                    }
                } else if contains_token_bounded(&q_lower, &tl, false)
                    || norm_files_lower
                        .iter()
                        .any(|nfl| contains_token_bounded(nfl, &tl, false))
                {
                    sc += 5.0;
                }
            }
            if sc > 0.0 {
                scores.insert(rid.clone(), sc);
            }
            rows_by_id.insert(rid, row);
        }
    }

    let combined_q = format!("{query} {}", norm_files.join(" "));
    let mut q_tokens: Vec<String> = Vec::new();
    for raw_tok in tokenize_cjk_hybrid(&combined_q).split_whitespace() {
        let cleaned: String = raw_tok
            .chars()
            .filter(|&c| c.is_alphanumeric() || c == '_' || is_cjk(c))
            .collect();
        if (cleaned.chars().count() >= 2 || cleaned.chars().any(is_cjk))
            && !q_tokens.contains(&cleaned)
        {
            q_tokens.push(cleaned);
            if q_tokens.len() >= 24 {
                break;
            }
        }
    }

    if !q_tokens.is_empty() {
        let fts_expr = q_tokens
            .iter()
            .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" OR ");
        if let Ok(mut fts_stmt) = conn.prepare(
            "SELECT id, bm25(rules_fts) AS rank FROM rules_fts WHERE rules_fts MATCH ?1 ORDER BY rank LIMIT 20",
        ) {
            if let Ok(rows) = fts_stmt.query_map(params![fts_expr], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?))
            }) {
                for pair in rows.flatten() {
                    if !rows_by_id.contains_key(&pair.0) {
                        continue;
                    }
                    let boost = (-pair.1).max(0.5);
                    *scores.entry(pair.0).or_insert(0.0) += boost;
                }
            }
        }
    }

    let now = now_epoch();
    let mut provenance_by_id: HashMap<String, (bool, String)> = HashMap::new();
    for (rid, sc) in scores.iter_mut() {
        if *sc > 0.0 {
            if let Some(r) = rows_by_id.get(rid) {
                // Utility-decay bonus: reinforced hits boost score; unhit old entries gently decay
                let age_days = ((now - r.created_at).max(0) as f64) / 86_400.0;
                *sc += (r.hits as f64).min(10.0) * 0.20 - (age_days * 0.01).min(1.5);
                if is_negative_kind(&r.kind) {
                    *sc += 0.25;
                }
                let (is_stale, reason) = check_provenance(cwd, &r.source_file, &r.source_hash);
                if is_stale {
                    *sc *= if reason == "source_file_deleted" {
                        0.50
                    } else {
                        0.65
                    };
                }
                provenance_by_id.insert(rid.clone(), (is_stale, reason));
            }
        }
    }

    let mut ranked: Vec<(String, f64)> = scores.into_iter().filter(|(_, sc)| *sc > 0.0).collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked.truncate(top_k);

    let mut used_chars = 0usize;
    let mut results = Vec::new();
    for (rid, sc) in ranked {
        if let Some(r) = rows_by_id.get(&rid) {
            let entry_len = r.kind.len() + r.triggers.len() + r.rule.len() + 16;
            if max_chars > 0 && !results.is_empty() && used_chars + entry_len > max_chars {
                break;
            }
            used_chars += entry_len;
            let _ = conn.execute(
                "UPDATE rules SET hits = hits + 1, last_hit_at = ?1 WHERE id = ?2",
                params![now, rid],
            );
            let (stale, stale_reason) = provenance_by_id.remove(&rid).unwrap_or_default();
            results.push(RuleMatch {
                id: rid,
                kind: r.kind.clone(),
                triggers: r.triggers.clone(),
                rule: r.rule.clone(),
                score: (sc * 100.0).round() / 100.0,
                hits: r.hits + 1,
                source_file: r.source_file.clone(),
                stale,
                stale_reason,
            });
        }
    }

    let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
    Ok((results, elapsed_ms))
}

pub fn verify_vault(
    conn: &Connection,
    cwd: &Path,
    prune_stale: bool,
) -> rusqlite::Result<VerifyReport> {
    let mut stmt =
        conn.prepare("SELECT id, kind, triggers, source_file, source_hash FROM rules")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    let mut total_rules = 0usize;
    let mut tracked_rules = 0usize;
    let mut fresh_rules = 0usize;
    let mut stale_entries = Vec::new();
    for item in rows {
        let (id, kind, triggers, source_file, source_hash) = item?;
        total_rules += 1;
        if source_file.is_empty() || source_hash.is_empty() {
            continue;
        }
        tracked_rules += 1;
        let (is_stale, reason) = check_provenance(cwd, &source_file, &source_hash);
        if is_stale {
            stale_entries.push(StaleRuleEntry {
                id,
                kind,
                triggers,
                source_file,
                reason,
            });
        } else {
            fresh_rules += 1;
        }
    }
    let mut pruned_rules = 0usize;
    if prune_stale {
        for entry in &stale_entries {
            let n = conn.execute("DELETE FROM rules WHERE id = ?1", params![entry.id])?;
            let _ = conn.execute("DELETE FROM rules_fts WHERE id = ?1", params![entry.id]);
            pruned_rules += n;
        }
    }
    Ok(VerifyReport {
        total_rules,
        tracked_rules,
        fresh_rules,
        stale_rules: stale_entries.len(),
        pruned_rules,
        stale_entries,
    })
}

pub fn compute_stats(conn: &Connection) -> rusqlite::Result<VaultStats> {
    let mut stmt = conn.prepare("SELECT rule, triggers, hits FROM rules")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    let mut total_rules = 0usize;
    let mut full_bytes = 0usize;
    let mut total_hits = 0i64;
    for item in rows {
        let (rule, triggers, hits) = item?;
        total_rules += 1;
        full_bytes += rule.len() + triggers.len() + 16;
        total_hits += hits;
    }
    let full_tokens_est = full_bytes.div_ceil(4);
    Ok(VaultStats {
        total_rules,
        monolithic_tokens_if_always_loaded: full_tokens_est,
        typical_top3_injected_tokens: full_tokens_est.min(135),
        total_hits,
    })
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
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let conn = match open_vault(&vault_path(&cwd)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[recall] failed to open SQLite vault: {e}");
            return 1;
        }
    };

    match cli.subcmd {
        SubCmd::Add {
            triggers,
            rule,
            kind,
            source_file,
        } => match add_rule_with_provenance(&conn, &cwd, &triggers, &rule, &kind, &source_file) {
            Ok(rid) => {
                if source_file.trim().is_empty() {
                    println!("[recall] stored id={rid} kind={kind} triggers='{triggers}'");
                } else {
                    println!(
                        "[recall] stored id={rid} kind={kind} triggers='{triggers}' file='{source_file}'"
                    );
                }
                0
            }
            Err(e) => {
                eprintln!("[recall] error storing rule: {e}");
                1
            }
        },
        SubCmd::Match {
            query,
            files,
            top,
            kind,
            max_chars,
            json: as_json,
        } => {
            let file_list: Vec<String> = files
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            let kind_opt = (!kind.trim().is_empty()).then_some(kind.as_str());
            match match_rules_with_opts(&conn, &cwd, &query, &file_list, top, kind_opt, max_chars) {
                Ok((hits, elapsed_ms)) => {
                    let negative_constraints: Vec<&RuleMatch> =
                        hits.iter().filter(|h| is_negative_kind(&h.kind)).collect();
                    let positive_rules: Vec<&RuleMatch> =
                        hits.iter().filter(|h| !is_negative_kind(&h.kind)).collect();
                    if as_json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "elapsed_ms": (elapsed_ms * 100.0).round() / 100.0,
                                "negative_constraints": negative_constraints,
                                "rules": positive_rules,
                                "matches": hits
                            }))
                            .unwrap_or_default()
                        );
                        return 0;
                    }
                    if hits.is_empty() {
                        println!("[recall] 0 triggered rules ({elapsed_ms:.2}ms)");
                        return 0;
                    }
                    println!(
                        "# Recall Active Rules ({} matched in {elapsed_ms:.2}ms)",
                        hits.len()
                    );
                    if !negative_constraints.is_empty() {
                        println!("## Negative Constraints (DO NOT REPEAT)");
                        for h in negative_constraints {
                            let stale_note = if h.stale {
                                format!(" [STALE: {} ({})]", h.stale_reason, h.source_file)
                            } else {
                                String::new()
                            };
                            println!(
                                "- **[{}]** (`{}`): {}{stale_note}",
                                h.kind, h.triggers, h.rule
                            );
                        }
                    }
                    for h in positive_rules {
                        let stale_note = if h.stale {
                            format!(" [STALE: {} ({})]", h.stale_reason, h.source_file)
                        } else {
                            String::new()
                        };
                        println!(
                            "- **[{}]** (`{}`): {}{stale_note}",
                            h.kind, h.triggers, h.rule
                        );
                    }
                    0
                }
                Err(e) => {
                    eprintln!("[recall] match failed: {e}");
                    1
                }
            }
        }
        SubCmd::Verify {
            prune_stale,
            json: as_json,
        } => match verify_vault(&conn, &cwd, prune_stale) {
            Ok(rep) => {
                if as_json {
                    println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
                } else {
                    println!(
                        "[recall verify] total={} tracked={} fresh={} stale={} pruned={}",
                        rep.total_rules,
                        rep.tracked_rules,
                        rep.fresh_rules,
                        rep.stale_rules,
                        rep.pruned_rules
                    );
                    for s in rep.stale_entries {
                        println!(
                            "- [STALE: {}] id={} (`{}`) file=`{}`",
                            s.reason, s.id, s.triggers, s.source_file
                        );
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("[recall] verify failed: {e}");
                1
            }
        },
        SubCmd::Stats { json: as_json } => match compute_stats(&conn) {
            Ok(st) => {
                if as_json {
                    println!("{}", serde_json::to_string_pretty(&st).unwrap_or_default());
                } else {
                    println!(
                        "[recall] rules={} | full-dump={} tok vs top-3={} tok | total_hits={}",
                        st.total_rules,
                        st.monolithic_tokens_if_always_loaded,
                        st.typical_top3_injected_tokens,
                        st.total_hits
                    );
                }
                0
            }
            Err(e) => {
                eprintln!("[recall] stats failed: {e}");
                1
            }
        },
        SubCmd::Prune { stale_days } => {
            let cutoff = now_epoch() - stale_days * 86400;
            let stale_ids: Vec<String> = conn
                .prepare("SELECT id FROM rules WHERE hits = 0 AND created_at < ?1")
                .and_then(|mut st| {
                    let rows = st.query_map(params![cutoff], |r| r.get::<_, String>(0))?;
                    Ok(rows.flatten().collect())
                })
                .unwrap_or_default();
            for rid in &stale_ids {
                let _ = conn.execute("DELETE FROM rules WHERE id = ?1", params![rid]);
                let _ = conn.execute("DELETE FROM rules_fts WHERE id = ?1", params![rid]);
            }
            println!("[recall] pruned {} stale zero-hit rules.", stale_ids.len());
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recall_provenance_detects_modified_deleted_and_prunes() {
        let dir = std::env::temp_dir().join(format!("ap_recall_prov_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        let src_p = dir.join("src/mod.rs");
        fs::write(&src_p, "pub fn check() -> bool { true }\n").unwrap();

        let conn = open_vault(&dir.join("vault.db")).unwrap();
        let _id = add_rule_with_provenance(
            &conn,
            &dir,
            "check,auth",
            "check returns bool cleanly",
            "gotcha",
            "src/mod.rs",
        )
        .unwrap();

        let (fresh_hits, _) = match_rules_in(&conn, &dir, "check", &[], 3).unwrap();
        assert_eq!(fresh_hits.len(), 1);
        assert!(!fresh_hits[0].stale);
        let fresh_score = fresh_hits[0].score;

        fs::write(&src_p, "pub fn check() -> Option<bool> { Some(true) }\n").unwrap();
        let (mod_hits, _) = match_rules_in(&conn, &dir, "check", &[], 3).unwrap();
        assert_eq!(mod_hits.len(), 1);
        assert!(mod_hits[0].stale);
        assert_eq!(mod_hits[0].stale_reason, "source_file_modified");
        assert!(mod_hits[0].score < fresh_score);

        fs::remove_file(&src_p).unwrap();
        let (del_hits, _) = match_rules_in(&conn, &dir, "check", &[], 3).unwrap();
        assert!(del_hits[0].stale);
        assert_eq!(del_hits[0].stale_reason, "source_file_deleted");

        let rep = verify_vault(&conn, &dir, true).unwrap();
        assert_eq!(rep.stale_rules, 1);
        assert_eq!(rep.pruned_rules, 1);

        let rep_after = verify_vault(&conn, &dir, false).unwrap();
        assert_eq!(rep_after.total_rules, 0);
        drop(conn);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recall_filters_kind_splits_negative_and_enforces_max_chars() {
        let dir = std::env::temp_dir().join(format!("ap_recall_neg_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conn = open_vault(&dir.join("vault.db")).unwrap();

        add_rule_with_provenance(
            &conn,
            &dir,
            "auth,oauth",
            "Do NOT reuse legacy unsigned fallback token in auth middleware",
            "negative",
            "",
        )
        .unwrap();
        add_rule_with_provenance(
            &conn,
            &dir,
            "auth,oauth",
            "Verify issuer and audience claims strictly with constant-time compare",
            "pattern",
            "",
        )
        .unwrap();

        let (neg_only, _) =
            match_rules_with_opts(&conn, &dir, "auth oauth", &[], 5, Some("negative"), 0).unwrap();
        assert_eq!(neg_only.len(), 1);
        assert!(is_negative_kind(&neg_only[0].kind));

        let (capped, _) =
            match_rules_with_opts(&conn, &dir, "auth oauth", &[], 5, None, 60).unwrap();
        assert_eq!(capped.len(), 1, "max_chars=60 should cap to 1 rule");
        drop(conn);
        let _ = fs::remove_dir_all(&dir);
    }
}
