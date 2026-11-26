use clap::{Parser, Subcommand};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static RECALL_LOCK_SEQ: AtomicU64 = AtomicU64::new(0);
const MAX_SYNC_FILE_BYTES: u64 = 2 * 1024 * 1024;

fn emit_err(as_json: bool, msg: &str) {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "ok": false, "error": msg })).unwrap_or_default()
        );
    } else {
        eprintln!("{msg}");
    }
}

fn default_weight() -> f64 {
    1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(default = "default_weight")]
    pub weight: f64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub section: String,
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
pub struct SyncReport {
    pub ok: bool,
    pub store: String,
    pub root: String,
    pub scanned_files: usize,
    pub indexed_files: usize,
    pub skipped_unchanged: usize,
    #[serde(default)]
    pub skipped_files: usize,
    #[serde(default)]
    pub error_files: usize,
    pub pruned_files: usize,
    pub indexed_entries: usize,
    pub elapsed_ms: f64,
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
    /// Optional custom SQLite vault path (file or directory; overrides RECALL_HOME and .recall/vault.db)
    #[arg(long, global = true)]
    store: Option<PathBuf>,
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
        /// Optional namespace scope tag(s), comma-separated (e.g. 'backend,auth')
        #[arg(long, default_value = "")]
        scope: String,
        /// Optional relevance boost multiplier (default: 1.0, range 0.05..=100.0)
        #[arg(long, default_value_t = 1.0)]
        weight: f64,
        /// Optional heading/section label
        #[arg(long, default_value = "")]
        section: String,
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
        /// Optional namespace scope filter (comma-separated tag(s); strict match)
        #[arg(long, default_value = "")]
        scope: String,
        /// Optional total character budget across emitted rules (0 = unlimited)
        #[arg(long, default_value_t = 0)]
        max_chars: usize,
        #[arg(long)]
        json: bool,
    },
    /// Incrementally sync Markdown/JSON/JSONL knowledge files into the SQLite FTS5 vault
    Sync {
        /// File or directory path to ingest
        path: PathBuf,
        /// Filename glob pattern(s), repeatable or comma-separated (default: *.md,*.markdown,*.json,*.jsonl)
        #[arg(long = "glob")]
        globs: Vec<String>,
        /// Optional namespace scope tag(s) applied to ingested entries (comma-separated)
        #[arg(long, default_value = "")]
        scope: String,
        /// Default rule kind for ingested entries
        #[arg(long, default_value = "note")]
        kind: String,
        /// Default relevance weight multiplier for ingested entries
        #[arg(long, default_value_t = 1.0)]
        weight: f64,
        /// Prune previously synced entries whose source files no longer exist
        #[arg(long)]
        prune: bool,
        /// Emit structured JSON output
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

fn split_ascii_subtokens(word: &str, out: &mut Vec<String>) {
    if word.is_empty() {
        return;
    }
    out.push(word.to_string());
    // Split on separators (_, -, ., /, :, \) and camelCase boundaries for bilingual identifier recall
    for seg in word.split(|c: char| !c.is_ascii_alphanumeric()) {
        if seg.is_empty() {
            continue;
        }
        if seg != word && seg.len() >= 2 {
            out.push(seg.to_string());
        }
        let chars: Vec<char> = seg.chars().collect();
        let mut start = 0usize;
        for i in 1..chars.len() {
            let prev = chars[i - 1];
            let cur = chars[i];
            let next_is_lower = chars.get(i + 1).is_some_and(|c| c.is_ascii_lowercase());
            let boundary = (prev.is_ascii_lowercase() && cur.is_ascii_uppercase())
                || (prev.is_ascii_uppercase() && cur.is_ascii_uppercase() && next_is_lower)
                || (prev.is_ascii_alphabetic() && cur.is_ascii_digit())
                || (prev.is_ascii_digit() && cur.is_ascii_alphabetic());
            if boundary {
                let part: String = chars[start..i].iter().collect();
                if part.len() >= 2 && part != seg && part != word {
                    out.push(part);
                }
                start = i;
            }
        }
        if start > 0 && start < chars.len() {
            let tail: String = chars[start..].iter().collect();
            if tail.len() >= 2 && tail != seg && tail != word {
                out.push(tail);
            }
        }
    }
}

pub fn tokenize_cjk_hybrid(text: &str) -> String {
    let mut out_tokens: Vec<String> = Vec::new();
    let mut cur_ascii = String::new();
    let mut cjk_buf: Vec<char> = Vec::new();

    let flush_ascii = |buf: &mut String, out: &mut Vec<String>| {
        if !buf.is_empty() {
            for w in buf.split_whitespace() {
                if !w.is_empty() {
                    split_ascii_subtokens(w, out);
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

pub fn normalize_scopes(raw: &str) -> String {
    let mut tags: Vec<String> = raw
        .split([',', ';'])
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    tags.sort();
    tags.dedup();
    tags.join(",")
}

fn scope_matches(row_scope: &str, requested_scopes: &[String]) -> bool {
    if requested_scopes.is_empty() {
        return true;
    }
    if requested_scopes.iter().any(|r| r == "*" || r == "all") {
        return true;
    }
    let row_tags: Vec<String> = row_scope
        .split([',', ';'])
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if row_tags.iter().any(|t| t == "*" || t == "all") {
        return true;
    }
    row_tags
        .iter()
        .any(|t| requested_scopes.iter().any(|req| req == t))
}

pub fn vault_path(cwd: &Path) -> PathBuf {
    let base = match std::env::var("RECALL_HOME") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => cwd.join(".recall"),
    };
    let _ = fs::create_dir_all(&base);
    let gi = base.join(".gitignore");
    if !gi.exists() {
        let _ = fs::write(&gi, "*.db-journal\n*.db-wal\n*.db-shm\n*.lock\n");
    }
    base.join("vault.db")
}

pub fn resolve_vault_path(cwd: &Path, store: Option<&Path>) -> PathBuf {
    let Some(raw) = store.filter(|p| !p.as_os_str().is_empty()) else {
        return vault_path(cwd);
    };
    let resolved = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    };
    if resolved.is_dir() {
        return resolved.join("vault.db");
    }
    if let Some(parent) = resolved.parent() {
        let _ = fs::create_dir_all(parent);
    }
    resolved
}

struct VaultLockGuard {
    lock_path: PathBuf,
    token: String,
}

impl Drop for VaultLockGuard {
    fn drop(&mut self) {
        let owns_lock = fs::read_to_string(&self.lock_path)
            .map(|cur| cur.trim() == self.token)
            .unwrap_or(false);
        if !owns_lock {
            return;
        }
        for attempt in 0..12u64 {
            match fs::remove_file(&self.lock_path) {
                Ok(()) => return,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                Err(_) if attempt < 11 => {
                    std::thread::sleep(Duration::from_millis(2 + attempt * 2));
                }
                Err(_) => return,
            }
        }
    }
}

fn parse_lock_pid(content: &str) -> Option<u32> {
    content
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("pid=")?.parse::<u32>().ok())
}

#[cfg(windows)]
fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut core::ffi::c_void;
        fn GetExitCodeProcess(handle: *mut core::ffi::c_void, code: *mut u32) -> i32;
        fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
    }
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return std::io::Error::last_os_error().raw_os_error() == Some(5);
    }
    let mut exit_code: u32 = 0;
    let ok = unsafe { GetExitCodeProcess(h, &mut exit_code) };
    unsafe {
        let _ = CloseHandle(h);
    }
    ok != 0 && exit_code == STILL_ACTIVE
}

#[cfg(unix)]
fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    let rc = unsafe { kill(pid as i32, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(1)
}

#[cfg(not(any(windows, unix)))]
fn is_pid_alive(_pid: u32) -> bool {
    true
}

fn acquire_vault_lock(db_path: &Path) -> Result<VaultLockGuard, String> {
    if let Some(parent) = db_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut os = db_path.as_os_str().to_os_string();
    os.push(".lock");
    let lock_path = PathBuf::from(os);
    let deadline = Instant::now() + Duration::from_secs(10);
    let pid = std::process::id();
    let seq = RECALL_LOCK_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let token = format!("pid={pid} seq={seq} ns={nanos}");
    let mut attempt = 0u64;
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(mut f) => {
                let _ = writeln!(f, "{token}");
                let _ = f.flush();
                return Ok(VaultLockGuard { lock_path, token });
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::AlreadyExists
                    || (cfg!(windows)
                        && (e.kind() == std::io::ErrorKind::PermissionDenied
                            || matches!(e.raw_os_error(), Some(5) | Some(32)))) =>
            {
                if let Ok(meta) = fs::metadata(&lock_path) {
                    if let Ok(mtime) = meta.modified() {
                        if let Ok(age) = SystemTime::now().duration_since(mtime) {
                            let dead_holder = age >= Duration::from_millis(500)
                                && fs::read_to_string(&lock_path)
                                    .ok()
                                    .and_then(|s| parse_lock_pid(&s))
                                    .is_some_and(|holder| holder != pid && !is_pid_alive(holder));
                            if dead_holder || age > Duration::from_secs(8) {
                                let _ = fs::remove_file(&lock_path);
                                continue;
                            }
                        }
                    }
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "Timed out waiting for recall vault lock {}: {e}",
                        lock_path.display()
                    ));
                }
                attempt += 1;
                let jitter = ((pid as u64).wrapping_mul(31) + attempt * 7) % 7;
                std::thread::sleep(Duration::from_millis(2 + jitter));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn read_table_cols(conn: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
    Ok(rows.flatten().collect())
}

fn vault_needs_migration(conn: &Connection) -> rusqlite::Result<bool> {
    let rules_cols: HashSet<String> = read_table_cols(conn, "rules")?.into_iter().collect();
    let required_cols = [
        "search_tokens",
        "source_file",
        "source_hash",
        "git_commit",
        "scope",
        "weight",
        "section",
        "origin",
    ];
    if rules_cols.is_empty() || required_cols.iter().any(|c| !rules_cols.contains(*c)) {
        return Ok(true);
    }
    let fts_cols = read_table_cols(conn, "rules_fts")?;
    if fts_cols.len() != 2 || !fts_cols.iter().any(|c| c == "search_tokens") {
        return Ok(true);
    }
    let sync_cols = read_table_cols(conn, "sync_files")?;
    Ok(sync_cols.is_empty())
}

fn migrate_vault_schema(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            triggers TEXT NOT NULL,
            rule TEXT NOT NULL,
            search_tokens TEXT NOT NULL DEFAULT '',
            hits INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT 0,
            last_hit_at INTEGER NOT NULL DEFAULT 0,
            source_file TEXT NOT NULL DEFAULT '',
            source_hash TEXT NOT NULL DEFAULT '',
            git_commit TEXT NOT NULL DEFAULT '',
            scope TEXT NOT NULL DEFAULT '',
            weight REAL NOT NULL DEFAULT 1.0,
            section TEXT NOT NULL DEFAULT '',
            origin TEXT NOT NULL DEFAULT 'manual'
        );
        CREATE TABLE IF NOT EXISTS sync_files (
            file_path TEXT PRIMARY KEY,
            mtime_ns INTEGER NOT NULL DEFAULT 0,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            sha256 TEXT NOT NULL DEFAULT '',
            scope TEXT NOT NULL DEFAULT '',
            entry_count INTEGER NOT NULL DEFAULT 0,
            synced_at INTEGER NOT NULL DEFAULT 0
        );",
    )?;
    let existing_cols: HashSet<String> = read_table_cols(&tx, "rules")?.into_iter().collect();
    let mut added_search_tokens = false;
    for (col, ddl) in [
        (
            "search_tokens",
            "ALTER TABLE rules ADD COLUMN search_tokens TEXT NOT NULL DEFAULT ''",
        ),
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
        (
            "scope",
            "ALTER TABLE rules ADD COLUMN scope TEXT NOT NULL DEFAULT ''",
        ),
        (
            "weight",
            "ALTER TABLE rules ADD COLUMN weight REAL NOT NULL DEFAULT 1.0",
        ),
        (
            "section",
            "ALTER TABLE rules ADD COLUMN section TEXT NOT NULL DEFAULT ''",
        ),
        (
            "origin",
            "ALTER TABLE rules ADD COLUMN origin TEXT NOT NULL DEFAULT 'manual'",
        ),
    ] {
        if !existing_cols.contains(col) {
            tx.execute(ddl, [])?;
            if col == "search_tokens" {
                added_search_tokens = true;
            }
        }
    }

    let fts_cols = read_table_cols(&tx, "rules_fts")?;
    let need_fts_rebuild = fts_cols.len() != 2 || !fts_cols.iter().any(|c| c == "search_tokens");

    // Backfill empty search_tokens for legacy rows before rebuilding FTS
    if added_search_tokens || need_fts_rebuild {
        let legacy_rows: Vec<(String, String, String, String, String, String)> = {
            let mut st = tx.prepare(
                "SELECT id, kind, triggers, rule, scope, section FROM rules WHERE search_tokens = ''",
            )?;
            let rows = st.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })?;
            rows.flatten().collect()
        };
        for (id, kind, triggers, rule, scope, section) in legacy_rows {
            let toks = tokenize_cjk_hybrid(&format!(
                "{} {section} {rule} {kind} {}",
                triggers.replace(',', " "),
                scope.replace(',', " ")
            ));
            tx.execute(
                "UPDATE rules SET search_tokens = ?1 WHERE id = ?2",
                params![toks, id],
            )?;
        }
    }

    if need_fts_rebuild {
        tx.execute_batch(
            "DROP TABLE IF EXISTS rules_fts;
             CREATE VIRTUAL TABLE rules_fts USING fts5(
                 id UNINDEXED,
                 search_tokens,
                 tokenize='unicode61'
             );",
        )?;
        let all_rows: Vec<(String, String)> = {
            let mut st = tx.prepare("SELECT id, search_tokens FROM rules")?;
            let rows =
                st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            rows.flatten().collect()
        };
        for (id, toks) in all_rows {
            tx.execute(
                "INSERT INTO rules_fts (id, search_tokens) VALUES (?1, ?2)",
                params![id, toks],
            )?;
        }
    }
    tx.commit()
}

fn open_vault_inner(db_path: &Path, already_locked: bool) -> rusqlite::Result<Connection> {
    if let Some(parent) = db_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut conn = Connection::open(db_path)?;
    let _ = conn.busy_timeout(Duration::from_millis(5000));
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.pragma_update(None, "synchronous", "NORMAL");
    if vault_needs_migration(&conn)? {
        let _mig_lock = if already_locked {
            None
        } else {
            Some(acquire_vault_lock(db_path).map_err(|msg| {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                    Some(msg),
                )
            })?)
        };
        if vault_needs_migration(&conn)? {
            migrate_vault_schema(&mut conn)?;
        }
    }
    Ok(conn)
}

pub fn open_vault(db_path: &Path) -> rusqlite::Result<Connection> {
    open_vault_inner(db_path, false)
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
    add_rule_full(conn, cwd, triggers, rule, kind, source_file, "", 1.0, "")
}

#[allow(clippy::too_many_arguments)]
pub fn add_rule_full(
    conn: &Connection,
    cwd: &Path,
    triggers: &str,
    rule: &str,
    kind: &str,
    source_file: &str,
    scope: &str,
    weight: f64,
    section: &str,
) -> rusqlite::Result<String> {
    let norm_rule = rule.split_whitespace().collect::<Vec<_>>().join(" ");
    let norm_trig = triggers
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    let norm_src = normalize_source_file(source_file);
    let norm_scope = normalize_scopes(scope);
    let norm_section = section.trim().to_string();
    let eff_weight = if weight.is_finite() {
        weight.clamp(0.05, 100.0)
    } else {
        1.0
    };
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
    if norm_scope.is_empty() && norm_section.is_empty() {
        hasher.update(format!("{norm_trig}::{norm_rule}").as_bytes());
    } else {
        hasher.update(format!("{norm_scope}::{norm_section}::{norm_trig}::{norm_rule}").as_bytes());
    }
    let rule_id = format!("{:x}", hasher.finalize())[..10].to_string();
    let now = now_epoch();
    let tokens = tokenize_cjk_hybrid(&format!(
        "{} {norm_section} {norm_rule} {kind} {}",
        norm_trig.replace(',', " "),
        norm_scope.replace(',', " ")
    ));

    struct ImmediateTxGuard<'a> {
        conn: &'a Connection,
        committed: bool,
    }
    impl<'a> Drop for ImmediateTxGuard<'a> {
        fn drop(&mut self) {
            if !self.committed {
                let _ = self.conn.execute_batch("ROLLBACK");
            }
        }
    }
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let mut tx_guard = ImmediateTxGuard {
        conn,
        committed: false,
    };

    conn.execute(
        "INSERT INTO rules (id, kind, triggers, rule, search_tokens, hits, created_at, last_hit_at, source_file, source_hash, git_commit, scope, weight, section, origin)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, 0, ?7, ?8, ?9, ?10, ?11, ?12, 'manual')
         ON CONFLICT(id) DO UPDATE SET
             kind=excluded.kind,
             triggers=excluded.triggers,
             rule=excluded.rule,
             search_tokens=excluded.search_tokens,
             source_file=excluded.source_file,
             source_hash=excluded.source_hash,
             git_commit=excluded.git_commit,
             scope=excluded.scope,
             weight=excluded.weight,
             section=excluded.section,
             origin='manual'",
        params![
            rule_id,
            kind,
            norm_trig,
            norm_rule,
            tokens,
            now,
            norm_src,
            src_hash,
            git_commit,
            norm_scope,
            eff_weight,
            norm_section
        ],
    )?;
    conn.execute("DELETE FROM rules_fts WHERE id = ?1", params![rule_id])?;
    conn.execute(
        "INSERT INTO rules_fts (id, search_tokens) VALUES (?1, ?2)",
        params![rule_id, tokens],
    )?;
    conn.execute_batch("COMMIT")?;
    tx_guard.committed = true;
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
    scope: String,
    weight: f64,
    section: String,
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
    match_rules_scoped(conn, cwd, query, files, top_k, kind_filter, None, max_chars)
}

#[allow(clippy::too_many_arguments)]
pub fn match_rules_scoped(
    conn: &Connection,
    cwd: &Path,
    query: &str,
    files: &[String],
    top_k: usize,
    kind_filter: Option<&str>,
    scope_filter: Option<&str>,
    max_chars: usize,
) -> rusqlite::Result<(Vec<RuleMatch>, f64)> {
    let t0 = Instant::now();
    let mut scores: HashMap<String, f64> = HashMap::new();
    let mut rows_by_id: HashMap<String, StoredRow> = HashMap::new();

    let kind_req = kind_filter
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());
    let requested_scopes: Vec<String> = scope_filter
        .unwrap_or("")
        .split([',', ';'])
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
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
            "SELECT id, kind, triggers, rule, hits, created_at, source_file, source_hash, scope, weight, section FROM rules",
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
                    scope: r.get(8).unwrap_or_default(),
                    weight: r.get(9).unwrap_or(1.0),
                    section: r.get(10).unwrap_or_default(),
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
            if !scope_matches(&row.scope, &requested_scopes) {
                continue;
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

    if !q_tokens.is_empty() && !rows_by_id.is_empty() {
        let fts_expr = q_tokens
            .iter()
            .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" OR ");
        // Stream BM25 hits in rank order and collect up to 64 in-scope/in-kind matches
        // so scoped queries on large multi-scope vaults are never starved by global LIMIT 64.
        if let Ok(mut fts_stmt) = conn.prepare(
            "SELECT f.id, bm25(rules_fts) AS rank FROM rules_fts f WHERE rules_fts MATCH ?1 ORDER BY rank",
        ) {
            if let Ok(rows) = fts_stmt.query_map(params![fts_expr], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?))
            }) {
                let mut matched_in_scope = 0usize;
                for pair in rows.flatten() {
                    if !rows_by_id.contains_key(&pair.0) {
                        continue;
                    }
                    let boost = (-pair.1).max(0.5);
                    *scores.entry(pair.0).or_insert(0.0) += boost;
                    matched_in_scope += 1;
                    if matched_in_scope >= 64 {
                        break;
                    }
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
                let eff_w = if r.weight.is_finite() {
                    r.weight.clamp(0.05, 100.0)
                } else {
                    1.0
                };
                *sc = (*sc).max(0.05) * eff_w;
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
                scope: r.scope.clone(),
                weight: r.weight,
                section: r.section.clone(),
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

struct SyncEntryDraft {
    triggers: String,
    rule: String,
    kind: String,
    scope: String,
    weight: f64,
    section: String,
}

fn expand_globs(globs: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in globs {
        for part in raw.split(',') {
            let clean = part.trim().to_ascii_lowercase();
            if !clean.is_empty() && !out.contains(&clean) {
                out.push(clean);
            }
        }
    }
    if out.is_empty() {
        out.extend([
            "*.md".to_string(),
            "*.markdown".to_string(),
            "*.json".to_string(),
            "*.jsonl".to_string(),
        ]);
    }
    out
}

fn matches_any_glob(rel_path: &str, file_name: &str, globs: &[String]) -> bool {
    let rel_low = rel_path.replace('\\', "/").to_ascii_lowercase();
    let name_low = file_name.to_ascii_lowercase();
    globs
        .iter()
        .any(|g| wildcard_match(g, &name_low) || wildcard_match(g, &rel_low))
}

fn is_symlink_or_reparse_point(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

fn collect_sync_files(root: &Path, globs: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.is_file() {
        if !is_symlink_or_reparse_point(root) {
            out.push(root.to_path_buf());
        }
        return out;
    }
    let skip_dirs = [
        ".git",
        "node_modules",
        "target",
        ".recall",
        ".sieve",
        ".baton",
        ".guard",
        "__pycache__",
        ".venv",
        "venv",
    ];
    let mut visited_dirs: HashSet<PathBuf> = HashSet::new();
    if let Ok(c) = fs::canonicalize(root) {
        visited_dirs.insert(c);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            if is_symlink_or_reparse_point(&p) {
                continue;
            }
            let fname = ent.file_name().to_string_lossy().to_string();
            let Ok(ft) = ent.file_type() else {
                continue;
            };
            if ft.is_dir() {
                if !skip_dirs.iter().any(|s| s.eq_ignore_ascii_case(&fname)) {
                    let canon = fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
                    if visited_dirs.insert(canon) {
                        stack.push(p);
                    }
                }
            } else if ft.is_file() {
                let rel = p
                    .strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                if matches_any_glob(&rel, &fname, globs) {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    out
}

fn derive_markdown_triggers(stem: &str, heading: &str) -> String {
    let mut toks: Vec<String> = Vec::new();
    for raw in [stem, heading] {
        for part in raw.split(|c: char| !c.is_alphanumeric() && !is_cjk(c) && c != '_') {
            let clean = part.trim();
            if clean.chars().count() >= 2 && !toks.iter().any(|t| t.eq_ignore_ascii_case(clean)) {
                toks.push(clean.to_string());
                if toks.len() >= 8 {
                    break;
                }
            }
        }
    }
    if toks.is_empty() {
        stem.to_string()
    } else {
        toks.join(",")
    }
}

fn compact_text_clip(raw: &str, max_chars: usize) -> String {
    let joined = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.chars().count() <= max_chars {
        joined
    } else {
        let mut s: String = joined.chars().take(max_chars).collect();
        s.push_str("...");
        s
    }
}

fn decode_text_smart(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    // UTF-16LE / UTF-16BE BOM detection
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let (cow, _, _) = encoding_rs::UTF_16LE.decode(&bytes[2..]);
        return Some(cow.into_owned());
    }
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        let (cow, _, _) = encoding_rs::UTF_16BE.decode(&bytes[2..]);
        return Some(cow.into_owned());
    }
    // Reject binary files (NUL byte in prefix)
    let sample = &bytes[..bytes.len().min(8192)];
    if sample.contains(&0) {
        return None;
    }
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if let Ok(s) = std::str::from_utf8(body) {
        return Some(s.to_string());
    }
    let (cow, _, _) = encoding_rs::GBK.decode(body);
    Some(cow.into_owned())
}

fn parse_markdown_entries(
    file_path: &Path,
    text: &str,
    default_scope: &str,
    default_kind: &str,
    default_weight: f64,
) -> Vec<SyncEntryDraft> {
    let stem = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("doc");
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    let mut cur_heading = stem.to_string();
    let mut cur_lines: Vec<String> = Vec::new();
    let mut in_fence: Option<char> = None;

    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("```") {
            match in_fence {
                Some('`') => in_fence = None,
                None => in_fence = Some('`'),
                _ => {}
            }
            cur_lines.push(t.to_string());
            continue;
        }
        if t.starts_with("~~~") {
            match in_fence {
                Some('~') => in_fence = None,
                None => in_fence = Some('~'),
                _ => {}
            }
            cur_lines.push(t.to_string());
            continue;
        }
        if in_fence.is_none() && t.starts_with('#') {
            let trimmed_h = t.trim_start_matches('#').trim();
            if !trimmed_h.is_empty()
                && t.as_bytes().get(t.len() - trimmed_h.len() - 1) == Some(&b' ')
            {
                if !cur_lines.is_empty() {
                    sections.push((cur_heading.clone(), std::mem::take(&mut cur_lines)));
                }
                cur_heading = trimmed_h.to_string();
                continue;
            }
        }
        if !t.is_empty() {
            cur_lines.push(t.to_string());
        }
    }
    if !cur_lines.is_empty() {
        sections.push((cur_heading, cur_lines));
    }

    let mut entries = Vec::new();
    for (heading, lines) in sections {
        let body = compact_text_clip(&lines.join(" "), 760);
        if body.len() < 4 {
            continue;
        }
        let triggers = derive_markdown_triggers(stem, &heading);
        entries.push(SyncEntryDraft {
            triggers,
            rule: body,
            kind: default_kind.to_string(),
            scope: default_scope.to_string(),
            weight: default_weight,
            section: heading,
        });
    }
    entries
}

fn parse_json_obj_entry(
    obj: &serde_json::Map<String, Value>,
    stem: &str,
    default_scope: &str,
    default_kind: &str,
    default_weight: f64,
) -> Option<SyncEntryDraft> {
    let rule = ["rule", "text", "content", "summary", "snippet", "body"]
        .iter()
        .find_map(|k| obj.get(*k).and_then(Value::as_str))
        .map(|s| compact_text_clip(s, 760))
        .filter(|s| !s.is_empty())?;
    let section = ["section", "title", "heading", "name", "id"]
        .iter()
        .find_map(|k| obj.get(*k).and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_string();
    let triggers = if let Some(v) = obj
        .get("triggers")
        .or_else(|| obj.get("tags"))
        .or_else(|| obj.get("keywords"))
    {
        if let Some(s) = v.as_str() {
            s.trim().to_string()
        } else if let Some(arr) = v.as_array() {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(",")
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    let triggers = if triggers.is_empty() {
        derive_markdown_triggers(stem, if section.is_empty() { &rule } else { &section })
    } else {
        triggers
    };
    let kind = obj
        .get("kind")
        .or_else(|| obj.get("type"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(default_kind)
        .to_string();
    let item_scope = if let Some(v) = obj.get("scope").or_else(|| obj.get("scopes")) {
        if let Some(s) = v.as_str() {
            s.to_string()
        } else if let Some(arr) = v.as_array() {
            arr.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    let merged_scope = normalize_scopes(&format!("{default_scope},{item_scope}"));
    let weight = obj
        .get("weight")
        .and_then(Value::as_f64)
        .unwrap_or(default_weight);
    Some(SyncEntryDraft {
        triggers,
        rule,
        kind,
        scope: merged_scope,
        weight,
        section,
    })
}

fn parse_json_entries(
    file_path: &Path,
    text: &str,
    default_scope: &str,
    default_kind: &str,
    default_weight: f64,
) -> Result<Vec<SyncEntryDraft>, String> {
    let stem = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("data");
    let mut out = Vec::new();
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext == "jsonl" {
        let mut saw_nonempty = false;
        let mut parse_errors = 0usize;
        for line in text.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            saw_nonempty = true;
            match serde_json::from_str::<Value>(t) {
                Ok(Value::Object(obj)) => {
                    if let Some(d) = parse_json_obj_entry(
                        &obj,
                        stem,
                        default_scope,
                        default_kind,
                        default_weight,
                    ) {
                        out.push(d);
                    }
                }
                Ok(_) => parse_errors += 1,
                Err(_) => parse_errors += 1,
            }
        }
        if saw_nonempty && out.is_empty() && parse_errors > 0 {
            return Err("invalid JSONL entries".to_string());
        }
        return Ok(out);
    }
    let val = serde_json::from_str::<Value>(text).map_err(|e| format!("invalid JSON: {e}"))?;
    let items_opt = val.as_array().or_else(|| {
        ["items", "rules", "entries", "cards", "records"]
            .iter()
            .find_map(|k| val.get(*k).and_then(Value::as_array))
    });
    if let Some(arr) = items_opt {
        for item in arr {
            if let Some(obj) = item.as_object() {
                if let Some(d) =
                    parse_json_obj_entry(obj, stem, default_scope, default_kind, default_weight)
                {
                    out.push(d);
                }
            }
        }
    } else if let Some(obj) = val.as_object() {
        if let Some(d) =
            parse_json_obj_entry(obj, stem, default_scope, default_kind, default_weight)
        {
            out.push(d);
        }
    }
    Ok(out)
}

fn file_mtime_ns_and_size(path: &Path) -> (i64, i64) {
    let Ok(meta) = fs::metadata(path) else {
        return (0, 0);
    };
    let sz = meta.len() as i64;
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or(0);
    (mtime_ns, sz)
}

fn normalize_drive_letter_case(p: String) -> String {
    let bytes = p.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let mut out = String::with_capacity(p.len());
        out.push((bytes[0] as char).to_ascii_lowercase());
        out.push_str(&p[1..]);
        out
    } else {
        p
    }
}

fn normalize_sync_key(cwd: &Path, file_path: &Path) -> String {
    let abs = if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        cwd.join(file_path)
    };
    let file_c = fs::canonicalize(&abs).unwrap_or(abs);
    let s = file_c.to_string_lossy().to_string();
    let stripped = s.strip_prefix(r"\\?\").unwrap_or(&s);
    normalize_drive_letter_case(normalize_source_file(stripped))
}

#[allow(clippy::too_many_arguments)]
pub fn sync_path(
    db_path: &Path,
    cwd: &Path,
    target_path: &Path,
    globs: &[String],
    scope: &str,
    kind: &str,
    weight: f64,
    prune: bool,
) -> Result<SyncReport, String> {
    let t0 = Instant::now();
    let resolved_root = if target_path.is_absolute() {
        target_path.to_path_buf()
    } else {
        cwd.join(target_path)
    };
    if !resolved_root.exists() {
        return Err(format!("sync path not found: {}", resolved_root.display()));
    }
    let _lock = acquire_vault_lock(db_path)?;
    let mut conn = open_vault_inner(db_path, true).map_err(|e| e.to_string())?;
    let eff_globs = expand_globs(globs);
    let norm_scope = normalize_scopes(scope);
    let eff_weight = if weight.is_finite() {
        weight.clamp(0.05, 100.0)
    } else {
        1.0
    };
    let files = collect_sync_files(&resolved_root, &eff_globs);
    let scanned_files = files.len();

    let mut existing_sync: HashMap<String, (i64, i64, String, String, usize)> = HashMap::new();
    {
        let mut st = conn
            .prepare("SELECT file_path, mtime_ns, size_bytes, sha256, scope, entry_count FROM sync_files")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    (
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5)? as usize,
                    ),
                ))
            })
            .map_err(|e| e.to_string())?;
        for pair in rows.flatten() {
            existing_sync.insert(pair.0, pair.1);
        }
    }

    let now = now_epoch();
    let git_commit = git_head_short(cwd);
    let mut seen_keys: HashSet<String> = HashSet::new();
    let mut indexed_files = 0usize;
    let mut skipped_unchanged = 0usize;
    let mut skipped_files = 0usize;
    let mut error_files = 0usize;
    let mut indexed_entries = 0usize;

    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;

    for fp in &files {
        let key = normalize_sync_key(cwd, fp);
        seen_keys.insert(key.clone());
        let (mtime_ns, size_bytes) = file_mtime_ns_and_size(fp);
        if size_bytes < 0 || (size_bytes as u64) > MAX_SYNC_FILE_BYTES {
            skipped_files += 1;
            continue;
        }
        if let Some((prev_m, prev_sz, _prev_sha, prev_scope, _cnt)) = existing_sync.get(&key) {
            if *prev_m == mtime_ns && *prev_sz == size_bytes && prev_scope == &norm_scope {
                skipped_unchanged += 1;
                continue;
            }
        }
        let Ok(bytes) = fs::read(fp) else {
            error_files += 1;
            continue;
        };
        let Some(text) = decode_text_smart(&bytes) else {
            skipped_files += 1;
            continue;
        };
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let full_sha = format!("{:x}", hasher.finalize());
        let short_sha = full_sha[..16].to_string();

        if let Some((_prev_m, _prev_sz, prev_sha, prev_scope, _cnt)) = existing_sync.get(&key) {
            if prev_sha == &full_sha && prev_scope == &norm_scope {
                let _ = tx.execute(
                    "UPDATE sync_files SET mtime_ns = ?1, size_bytes = ?2, synced_at = ?3 WHERE file_path = ?4",
                    params![mtime_ns, size_bytes, now, key],
                );
                skipped_unchanged += 1;
                continue;
            }
        }

        let ext = fp
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let drafts = if ext == "json" || ext == "jsonl" {
            match parse_json_entries(fp, &text, &norm_scope, kind, eff_weight) {
                Ok(d) => d,
                Err(_) => {
                    error_files += 1;
                    continue;
                }
            }
        } else {
            parse_markdown_entries(fp, &text, &norm_scope, kind, eff_weight)
        };

        // Atomically replace ONLY sync-origin rules previously indexed from this source_file
        // (preserving any manually added `ap recall add --file` rules).
        let old_ids: Vec<String> = {
            let mut st = tx
                .prepare("SELECT id FROM rules WHERE source_file = ?1 AND origin = 'sync'")
                .map_err(|e| e.to_string())?;
            let rows = st
                .query_map(params![key], |r| r.get::<_, String>(0))
                .map_err(|e| e.to_string())?;
            rows.flatten().collect()
        };
        for oid in &old_ids {
            let _ = tx.execute("DELETE FROM rules WHERE id = ?1", params![oid]);
            let _ = tx.execute("DELETE FROM rules_fts WHERE id = ?1", params![oid]);
        }

        let mut inserted_for_file = 0usize;
        for d in drafts {
            let norm_rule = d.rule.split_whitespace().collect::<Vec<_>>().join(" ");
            if norm_rule.is_empty() {
                continue;
            }
            let norm_trig = d
                .triggers
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            let d_scope = normalize_scopes(&d.scope);
            let d_weight = if d.weight.is_finite() {
                d.weight.clamp(0.05, 100.0)
            } else {
                1.0
            };
            let mut id_h = Sha256::new();
            id_h.update(format!("{key}::{}::{}::{norm_rule}", d.section, d_scope).as_bytes());
            let rid = format!("{:x}", id_h.finalize())[..10].to_string();
            let tokens = tokenize_cjk_hybrid(&format!(
                "{} {} {norm_rule} {} {}",
                norm_trig.replace(',', " "),
                d.section,
                d.kind,
                d_scope.replace(',', " ")
            ));
            tx.execute(
                "INSERT INTO rules (id, kind, triggers, rule, search_tokens, hits, created_at, last_hit_at, source_file, source_hash, git_commit, scope, weight, section, origin)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, 0, ?7, ?8, ?9, ?10, ?11, ?12, 'sync')
                 ON CONFLICT(id) DO UPDATE SET
                     kind=excluded.kind,
                     triggers=excluded.triggers,
                     rule=excluded.rule,
                     search_tokens=excluded.search_tokens,
                     source_file=excluded.source_file,
                     source_hash=excluded.source_hash,
                     git_commit=excluded.git_commit,
                     scope=excluded.scope,
                     weight=excluded.weight,
                     section=excluded.section,
                     origin='sync'",
                params![
                    rid,
                    d.kind,
                    norm_trig,
                    norm_rule,
                    tokens,
                    now,
                    key,
                    short_sha,
                    git_commit,
                    d_scope,
                    d_weight,
                    d.section
                ],
            )
            .map_err(|e| e.to_string())?;
            let _ = tx.execute("DELETE FROM rules_fts WHERE id = ?1", params![rid]);
            tx.execute(
                "INSERT INTO rules_fts (id, search_tokens) VALUES (?1, ?2)",
                params![rid, tokens],
            )
            .map_err(|e| e.to_string())?;
            inserted_for_file += 1;
        }

        tx.execute(
            "INSERT INTO sync_files (file_path, mtime_ns, size_bytes, sha256, scope, entry_count, synced_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(file_path) DO UPDATE SET
                 mtime_ns=excluded.mtime_ns,
                 size_bytes=excluded.size_bytes,
                 sha256=excluded.sha256,
                 scope=excluded.scope,
                 entry_count=excluded.entry_count,
                 synced_at=excluded.synced_at",
            params![
                key,
                mtime_ns,
                size_bytes,
                full_sha,
                norm_scope,
                inserted_for_file as i64,
                now
            ],
        )
        .map_err(|e| e.to_string())?;
        indexed_files += 1;
        indexed_entries += inserted_for_file;
    }

    let mut pruned_files = 0usize;
    if prune {
        let root_key = normalize_sync_key(cwd, &resolved_root);
        let root_prefix = if resolved_root.is_dir() && !root_key.is_empty() && root_key != "." {
            format!("{}/", root_key.trim_end_matches('/'))
        } else {
            String::new()
        };
        for tracked_fp in existing_sync.keys() {
            if seen_keys.contains(tracked_fp) {
                continue;
            }
            // Strictly scope pruning to tracked files inside the synced root matching current --glob,
            // canonicalizing both absolute and legacy relative keys so cross-CWD sync --prune works cleanly
            // without ever wiping entries from other roots, globs, or manual rules.
            let is_abs_tracked = tracked_fp.starts_with('/')
                || (tracked_fp.len() >= 2 && tracked_fp.as_bytes()[1] == b':');
            let canon_tracked = if is_abs_tracked {
                normalize_drive_letter_case(normalize_source_file(tracked_fp))
            } else {
                normalize_sync_key(cwd, &cwd.join(tracked_fp))
            };
            if seen_keys.contains(&canon_tracked) {
                // Legacy relative key superseded by canonical key for the exact same live file: drop duplicate row
                let old_ids: Vec<String> = {
                    let mut st = tx
                        .prepare("SELECT id FROM rules WHERE source_file = ?1 AND origin = 'sync'")
                        .map_err(|e| e.to_string())?;
                    let rows = st
                        .query_map(params![tracked_fp], |r| r.get::<_, String>(0))
                        .map_err(|e| e.to_string())?;
                    rows.flatten().collect()
                };
                for oid in &old_ids {
                    let _ = tx.execute("DELETE FROM rules WHERE id = ?1", params![oid]);
                    let _ = tx.execute("DELETE FROM rules_fts WHERE id = ?1", params![oid]);
                }
                let _ = tx.execute(
                    "DELETE FROM sync_files WHERE file_path = ?1",
                    params![tracked_fp],
                );
                continue;
            }
            let rel_within_root: Option<&str> = if resolved_root.is_file() {
                (canon_tracked == root_key).then_some(canon_tracked.as_str())
            } else if root_prefix.is_empty() {
                (!is_abs_tracked).then_some(tracked_fp.as_str())
            } else if let Some(rest) = canon_tracked.strip_prefix(&root_prefix) {
                Some(rest)
            } else if canon_tracked == root_key {
                Some(canon_tracked.as_str())
            } else {
                None
            };
            let Some(rel_sub) = rel_within_root else {
                continue;
            };
            let fname = rel_sub.rsplit('/').next().unwrap_or(rel_sub);
            if !matches_any_glob(rel_sub, fname, &eff_globs) {
                continue;
            }
            let old_ids: Vec<String> = {
                let mut st = tx
                    .prepare("SELECT id FROM rules WHERE source_file = ?1 AND origin = 'sync'")
                    .map_err(|e| e.to_string())?;
                let rows = st
                    .query_map(params![tracked_fp], |r| r.get::<_, String>(0))
                    .map_err(|e| e.to_string())?;
                rows.flatten().collect()
            };
            for oid in &old_ids {
                let _ = tx.execute("DELETE FROM rules WHERE id = ?1", params![oid]);
                let _ = tx.execute("DELETE FROM rules_fts WHERE id = ?1", params![oid]);
            }
            let _ = tx.execute(
                "DELETE FROM sync_files WHERE file_path = ?1",
                params![tracked_fp],
            );
            pruned_files += 1;
        }
    }

    tx.commit().map_err(|e| e.to_string())?;
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
    Ok(SyncReport {
        ok: true,
        store: db_path.to_string_lossy().replace('\\', "/"),
        root: resolved_root.to_string_lossy().replace('\\', "/"),
        scanned_files,
        indexed_files,
        skipped_unchanged,
        skipped_files,
        error_files,
        pruned_files,
        indexed_entries,
        elapsed_ms,
    })
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
    let db_path = resolve_vault_path(&cwd, cli.store.as_deref());

    if let SubCmd::Sync {
        path,
        globs,
        scope,
        kind,
        weight,
        prune,
        json: as_json,
    } = cli.subcmd
    {
        return match sync_path(&db_path, &cwd, &path, &globs, &scope, &kind, weight, prune) {
            Ok(rep) => {
                if as_json {
                    println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
                } else {
                    println!(
                        "[recall sync] scanned={} indexed={} skipped={} pruned={} entries={} ({:.2}ms)",
                        rep.scanned_files,
                        rep.indexed_files,
                        rep.skipped_unchanged,
                        rep.pruned_files,
                        rep.indexed_entries,
                        rep.elapsed_ms
                    );
                }
                0
            }
            Err(e) => {
                if as_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({"ok": false, "error": e}))
                            .unwrap_or_default()
                    );
                } else {
                    eprintln!("[recall sync] failed: {e}");
                }
                1
            }
        };
    }

    let want_json = matches!(
        cli.subcmd,
        SubCmd::Match { json: true, .. }
            | SubCmd::Verify { json: true, .. }
            | SubCmd::Stats { json: true }
            | SubCmd::Sync { json: true, .. }
    );
    let conn = match open_vault(&db_path) {
        Ok(c) => c,
        Err(e) => {
            emit_err(
                want_json,
                &format!("[recall] failed to open SQLite vault: {e}"),
            );
            return 1;
        }
    };

    match cli.subcmd {
        SubCmd::Add {
            triggers,
            rule,
            kind,
            source_file,
            scope,
            weight,
            section,
        } => match add_rule_full(
            &conn,
            &cwd,
            &triggers,
            &rule,
            &kind,
            &source_file,
            &scope,
            weight,
            &section,
        ) {
            Ok(rid) => {
                let mut extra = String::new();
                if !source_file.trim().is_empty() {
                    extra.push_str(&format!(" file='{source_file}'"));
                }
                if !scope.trim().is_empty() {
                    extra.push_str(&format!(" scope='{}'", normalize_scopes(&scope)));
                }
                if (weight - 1.0).abs() > f64::EPSILON {
                    extra.push_str(&format!(" weight={weight:.2}"));
                }
                println!("[recall] stored id={rid} kind={kind} triggers='{triggers}'{extra}");
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
            scope,
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
            let scope_opt = (!scope.trim().is_empty()).then_some(scope.as_str());
            match match_rules_scoped(
                &conn, &cwd, &query, &file_list, top, kind_opt, scope_opt, max_chars,
            ) {
                Ok((hits, elapsed_ms)) => {
                    let negative_constraints: Vec<&RuleMatch> =
                        hits.iter().filter(|h| is_negative_kind(&h.kind)).collect();
                    let positive_rules: Vec<&RuleMatch> =
                        hits.iter().filter(|h| !is_negative_kind(&h.kind)).collect();
                    if as_json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": true,
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
                            let scope_note = if h.scope.is_empty() {
                                String::new()
                            } else {
                                format!(" [scope:{}]", h.scope)
                            };
                            println!(
                                "- **[{}]**{scope_note} (`{}`): {}{stale_note}",
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
                        let scope_note = if h.scope.is_empty() {
                            String::new()
                        } else {
                            format!(" [scope:{}]", h.scope)
                        };
                        println!(
                            "- **[{}]**{scope_note} (`{}`): {}{stale_note}",
                            h.kind, h.triggers, h.rule
                        );
                    }
                    0
                }
                Err(e) => {
                    emit_err(as_json, &format!("[recall] match failed: {e}"));
                    1
                }
            }
        }
        SubCmd::Sync { .. } => unreachable!(),
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
                emit_err(as_json, &format!("[recall] verify failed: {e}"));
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
                emit_err(as_json, &format!("[recall] stats failed: {e}"));
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

    #[test]
    fn recall_store_scope_weight_and_bilingual_sync_incremental_prune() {
        let dir = std::env::temp_dir().join(format!("ap_recall_sync_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("docs")).unwrap();
        let store_path = dir.join("custom_store/my_vault.sqlite");

        // Test custom --store + --scope + --weight + bilingual camelCase/CJK tokenization
        let resolved = resolve_vault_path(&dir, Some(&store_path));
        let conn = open_vault(&resolved).unwrap();
        add_rule_full(
            &conn,
            &dir,
            "token,cache",
            "Refresh accessToken before TTL expires in webAuthFlow",
            "pattern",
            "",
            "web,auth",
            3.0,
            "Token Refresh",
        )
        .unwrap();
        add_rule_full(
            &conn,
            &dir,
            "token,cache",
            "Use ephemeral token in cli runner",
            "pattern",
            "",
            "cli",
            1.0,
            "CLI Token",
        )
        .unwrap();
        add_rule_full(
            &conn,
            &dir,
            "编码,windows",
            "Windows子进程必须开启UTF8模式防止中文乱码",
            "gotcha",
            "",
            "win,ops",
            2.0,
            "中文编码",
        )
        .unwrap();

        // Scope filter strictly isolates namespaces
        let (web_hits, _) =
            match_rules_scoped(&conn, &dir, "token", &[], 5, None, Some("web"), 0).unwrap();
        assert_eq!(web_hits.len(), 1);
        assert_eq!(web_hits[0].scope, "auth,web");
        assert!((web_hits[0].weight - 3.0).abs() < 1e-6);

        // Weight boost ranks weight=3.0 above weight=1.0 for same triggers
        let (all_tok, _) = match_rules_scoped(&conn, &dir, "token", &[], 5, None, None, 0).unwrap();
        assert!(all_tok.len() >= 2);
        assert!(all_tok[0].score > all_tok[1].score);
        assert_eq!(all_tok[0].section, "Token Refresh");

        // Bilingual CJK + camelCase subtoken recall
        let (camel_hits, _) =
            match_rules_scoped(&conn, &dir, "access flow", &[], 5, None, Some("auth"), 0).unwrap();
        assert_eq!(camel_hits.len(), 1);
        let (cjk_hits, _) =
            match_rules_scoped(&conn, &dir, "中文乱码", &[], 5, None, Some("win"), 0).unwrap();
        assert_eq!(cjk_hits.len(), 1);
        drop(conn);

        // Incremental Markdown + JSON sync with mtime/SHA-256 skip and --prune
        let md_p = dir.join("docs/guide.md");
        fs::write(
            &md_p,
            "# Timeout Budget\nKeep network timeout under 30 seconds.\n\n## 中文缓存策略\n保持系统前缀稳定以复用缓存。\n",
        )
        .unwrap();
        let json_p = dir.join("docs/cards.json");
        fs::write(
            &json_p,
            r#"{"items":[{"title":"Pool Limit","triggers":["pool","socket"],"rule":"Recycle idle keepalive sockets before upstream timeout","kind":"pattern","scope":"net","weight":2.5}]}"#,
        )
        .unwrap();

        let rep1 = sync_path(
            &resolved,
            &dir,
            &dir.join("docs"),
            &[],
            "shared",
            "note",
            1.0,
            false,
        )
        .unwrap();
        assert!(rep1.ok);
        assert_eq!(rep1.scanned_files, 2);
        assert_eq!(rep1.indexed_files, 2);
        assert_eq!(rep1.skipped_unchanged, 0);
        assert_eq!(rep1.indexed_entries, 3);

        // Second sync without modifications skips both files cleanly
        let rep2 = sync_path(
            &resolved,
            &dir,
            &dir.join("docs"),
            &[],
            "shared",
            "note",
            1.0,
            false,
        )
        .unwrap();
        assert_eq!(rep2.indexed_files, 0);
        assert_eq!(rep2.skipped_unchanged, 2);

        // Query synced entries across scopes
        let conn2 = open_vault(&resolved).unwrap();
        let (net_hits, _) = match_rules_scoped(
            &conn2,
            &dir,
            "keepalive socket",
            &[],
            5,
            None,
            Some("net"),
            0,
        )
        .unwrap();
        assert_eq!(net_hits.len(), 1);
        assert_eq!(net_hits[0].section, "Pool Limit");
        let (zh_hits, _) =
            match_rules_scoped(&conn2, &dir, "前缀 缓存", &[], 5, None, Some("shared"), 0).unwrap();
        assert!(!zh_hits.is_empty());
        drop(conn2);

        // Delete cards.json and run sync --prune -> removes pruned file's entries
        fs::remove_file(&json_p).unwrap();
        let rep3 = sync_path(
            &resolved,
            &dir,
            &dir.join("docs"),
            &[],
            "shared",
            "note",
            1.0,
            true,
        )
        .unwrap();
        assert_eq!(rep3.pruned_files, 1);

        let conn3 = open_vault(&resolved).unwrap();
        let (after_prune, _) = match_rules_scoped(
            &conn3,
            &dir,
            "keepalive socket",
            &[],
            5,
            None,
            Some("net"),
            0,
        )
        .unwrap();
        assert!(after_prune.is_empty());
        drop(conn3);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recall_legacy_migration_concurrent_open_scope_starvation_and_sync_hygiene() {
        let dir = std::env::temp_dir().join(format!(
            "ap_recall_c2_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("repo_a")).unwrap();
        fs::create_dir_all(dir.join("repo_b")).unwrap();
        let db = dir.join("legacy.db");

        // 1. Create pre-Wave-1 legacy SQLite schema (NO search_tokens column, 3-col rules_fts)
        {
            let c = Connection::open(&db).unwrap();
            c.execute_batch(
                "CREATE TABLE rules (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    triggers TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    hits INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL DEFAULT 0,
                    last_hit_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE VIRTUAL TABLE rules_fts USING fts5(id UNINDEXED, triggers, rule);
                INSERT INTO rules (id, kind, triggers, rule, hits, created_at, last_hit_at)
                    VALUES ('legacy0001', 'gotcha', 'legacy,sqlite', 'Preserve legacy rules across schema upgrades', 2, 1000, 1000);
                INSERT INTO rules_fts (id, triggers, rule)
                    VALUES ('legacy0001', 'legacy,sqlite', 'Preserve legacy rules across schema upgrades');",
            )
            .unwrap();
        }

        // Concurrent open_vault calls on legacy DB must migrate cleanly with zero duplicate-column errors
        let bar = std::sync::Arc::new(std::sync::Barrier::new(4));
        std::thread::scope(|s| {
            for _ in 0..4 {
                let db_p = &db;
                let bar_c = std::sync::Arc::clone(&bar);
                s.spawn(move || {
                    bar_c.wait();
                    let conn = open_vault(db_p).expect("concurrent legacy migration must succeed");
                    let (hits, _) = match_rules_in(&conn, Path::new("."), "legacy sqlite", &[], 5)
                        .expect("legacy rule must remain searchable");
                    assert!(
                        hits.iter().any(|h| h.id == "legacy0001"),
                        "migrated legacy rule missing: {hits:?}"
                    );
                });
            }
        });

        // 2. Multi-scope >64-row FTS5 starvation test + nasty FTS5 metacharacters
        let conn = open_vault(&db).unwrap();
        for i in 0..80 {
            add_rule_full(
                &conn,
                &dir,
                &format!("auth,token,noisy{i}"),
                &format!("High frequency noisy alpha auth rule number {i} auth auth"),
                "note",
                "",
                "alpha",
                2.0,
                "",
            )
            .unwrap();
        }
        add_rule_full(
            &conn,
            &dir,
            "auth,rare",
            "Rare beta scope authentication policy rule",
            "gotcha",
            "",
            "beta",
            1.0,
            "",
        )
        .unwrap();
        let (beta_hits, _) = match_rules_scoped(
            &conn,
            &dir,
            "auth-policy:rare* (OR) NOT",
            &[],
            5,
            None,
            Some("beta"),
            0,
        )
        .unwrap();
        assert_eq!(
            beta_hits.len(),
            1,
            "beta scope must not be starved by 80 alpha hits"
        );

        // Manual rule bound to a file inside repo_a must NOT be wiped by sync/prune!
        let manual_f = dir.join("repo_a/guide.md");
        fs::write(
            &manual_f,
            "# Real Heading\n```bash\n# comment inside code fence\necho hello\n```\nBody line stays in Real Heading.\n",
        )
        .unwrap();
        add_rule_full(
            &conn,
            &dir,
            "manualkeep",
            "Manual note attached to guide.md must survive sync",
            "gotcha",
            "repo_a/guide.md",
            "manual",
            1.0,
            "",
        )
        .unwrap();
        drop(conn);

        // 3. Binary, oversized, GBK, and invalid JSON hygiene + fenced code check
        fs::write(
            dir.join("repo_a/bin_fake.md"),
            b"\x00\x01\x02BINARY\x00DATA",
        )
        .unwrap();
        let (gbk_bytes, _, _) = encoding_rs::GBK.encode("# 中文配置\n必须使用GBK兼容解码读取。\n");
        fs::write(dir.join("repo_a/gbk.md"), gbk_bytes.as_ref()).unwrap();
        fs::write(dir.join("repo_a/bad.json"), "{ not valid json").unwrap();
        fs::write(
            dir.join("repo_a/good.json"),
            r#"{"items":[{"title":"GoodCard","triggers":["goodcard"],"rule":"Valid json card survives md-only prune"}]}"#,
        )
        .unwrap();
        fs::write(
            dir.join("repo_b/other.md"),
            "# Repo B Doc\nEntries in repo B must survive repo A prune.\n",
        )
        .unwrap();

        let rep_a = sync_path(&db, &dir, &dir.join("repo_a"), &[], "a", "doc", 1.0, false).unwrap();
        assert_eq!(
            rep_a.skipped_files, 1,
            "binary file must be skipped: {rep_a:?}"
        );
        assert_eq!(
            rep_a.error_files, 1,
            "invalid json must count as error: {rep_a:?}"
        );
        assert_eq!(
            rep_a.indexed_files, 3,
            "guide.md + gbk.md + good.json: {rep_a:?}"
        );

        let rep_b = sync_path(
            &db,
            &dir.join("repo_b"),
            &dir.join("repo_b"),
            &["*.md".to_string()],
            "b",
            "doc",
            1.0,
            false,
        )
        .unwrap();
        assert_eq!(rep_b.indexed_files, 1);

        // Syncing repo_a with ONLY `--glob "*.md" --prune` must NOT prune good.json OR repo_b/other.md OR manual rule!
        let rep_prune = sync_path(
            &db,
            &dir,
            &dir.join("repo_a"),
            &["*.md".to_string()],
            "a",
            "doc",
            1.0,
            true,
        )
        .unwrap();
        assert_eq!(rep_prune.pruned_files, 0, "{rep_prune:?}");

        let conn2 = open_vault(&db).unwrap();
        // GBK decoded cleanly without mojibake
        let (gbk_hits, _) =
            match_rules_scoped(&conn2, &dir, "兼容解码", &[], 5, None, Some("a"), 0).unwrap();
        assert!(!gbk_hits.is_empty(), "GBK markdown must match cleanly");
        assert!(
            !gbk_hits[0].rule.contains('\u{FFFD}'),
            "no mojibake allowed"
        );
        // Fenced code `# comment inside code fence` did NOT create a fake section
        let (fence_hits, _) = match_rules_scoped(
            &conn2,
            &dir,
            "comment inside code fence",
            &[],
            5,
            None,
            Some("a"),
            0,
        )
        .unwrap();
        assert!(!fence_hits.is_empty());
        assert_eq!(fence_hits[0].section, "Real Heading");
        // good.json, repo_b, and manual rule all survived
        let (json_hits, _) =
            match_rules_scoped(&conn2, &dir, "goodcard", &[], 5, None, Some("a"), 0).unwrap();
        assert_eq!(json_hits.len(), 1);
        let (b_hits, _) =
            match_rules_scoped(&conn2, &dir, "Repo B Doc", &[], 5, None, Some("b"), 0).unwrap();
        assert_eq!(b_hits.len(), 1);
        let (man_hits, _) =
            match_rules_scoped(&conn2, &dir, "manualkeep", &[], 5, None, Some("manual"), 0)
                .unwrap();
        assert_eq!(man_hits.len(), 1);
        drop(conn2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recall_junction_cycle_skip_cross_cwd_prune_and_dead_pid_lock() {
        let dir = std::env::temp_dir().join(format!(
            "ap_recall_c3_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        let ws = dir.join("ws");
        let sub = ws.join("prune_test");
        let outside = dir.join("outside_secret");
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(
            sub.join("a.md"),
            "# Keep Rule\nAlways verify token signatures cleanly.\n",
        )
        .unwrap();
        fs::write(
            sub.join("b.md"),
            "# Temp Rule\nTemporary rule slated for deletion.\n",
        )
        .unwrap();
        fs::write(
            outside.join("leak.md"),
            "# Outside\nOUTSIDE_JUNCTION_MUST_NEVER_INDEX\n",
        )
        .unwrap();

        // Create both an out-of-tree junction/symlink AND a self-loop junction/symlink
        #[cfg(windows)]
        {
            let _ = Command::new("cmd")
                .args([
                    "/C",
                    "mklink",
                    "/J",
                    &sub.join("ext_junc").to_string_lossy(),
                    &outside.to_string_lossy(),
                ])
                .output();
            let _ = Command::new("cmd")
                .args([
                    "/C",
                    "mklink",
                    "/J",
                    &sub.join("self_loop").to_string_lossy(),
                    &sub.to_string_lossy(),
                ])
                .output();
        }
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(&outside, sub.join("ext_junc"));
            let _ = std::os::unix::fs::symlink(&sub, sub.join("self_loop"));
        }

        let db = ws.join(".recall").join("vault.db");
        // 1. Initial sync from cwd = ws targeting relative "prune_test"
        let r1 = sync_path(
            &db,
            &ws,
            Path::new("prune_test"),
            &[],
            "c3",
            "doc",
            1.0,
            false,
        )
        .unwrap();
        assert_eq!(
            r1.scanned_files, 2,
            "junction/self-loop must be skipped cleanly: {r1:?}"
        );
        assert_eq!(r1.indexed_files, 2);

        // Confirm outside junction content was NEVER indexed
        let conn = open_vault(&db).unwrap();
        let (leak_hits, _) = match_rules_scoped(
            &conn,
            &ws,
            "OUTSIDE_JUNCTION_MUST_NEVER_INDEX",
            &[],
            5,
            None,
            None,
            0,
        )
        .unwrap();
        assert!(leak_hits.is_empty(), "junction escaped root: {leak_hits:?}");
        drop(conn);

        // 2. Cross-CWD sync --prune from DIFFERENT cwd (`dir`, parent of `ws`) after deleting b.md
        fs::remove_file(sub.join("b.md")).unwrap();
        let r2 = sync_path(&db, &dir, &sub, &[], "c3", "doc", 1.0, true).unwrap();
        assert_eq!(r2.scanned_files, 1, "{r2:?}");
        assert_eq!(
            r2.skipped_unchanged, 1,
            "must NOT duplicate a.md across CWDs: {r2:?}"
        );
        assert_eq!(r2.indexed_files, 0, "a.md unchanged across CWDs: {r2:?}");
        assert_eq!(r2.pruned_files, 1, "b.md must prune across CWDs: {r2:?}");

        let conn2 = open_vault(&db).unwrap();
        let (keep_hits, _) = match_rules_scoped(
            &conn2,
            &dir,
            "verify token signatures",
            &[],
            5,
            None,
            Some("c3"),
            0,
        )
        .unwrap();
        assert_eq!(
            keep_hits.len(),
            1,
            "a.md must have exactly 1 row (no dup): {keep_hits:?}"
        );
        let (gone_hits, _) = match_rules_scoped(
            &conn2,
            &dir,
            "Temporary slated",
            &[],
            5,
            None,
            Some("c3"),
            0,
        )
        .unwrap();
        assert!(gone_hits.is_empty(), "b.md must be pruned: {gone_hits:?}");
        let b_rows: i64 = conn2
            .query_row(
                "SELECT COUNT(*) FROM rules WHERE source_file LIKE '%b.md'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(b_rows, 0, "b.md rows must be 0 after cross-CWD prune");
        drop(conn2);

        // 3. Dead-PID stale vault lock fast reclaim
        let dead_child = if cfg!(windows) {
            Command::new("cmd").args(["/C", "exit", "0"]).spawn()
        } else {
            Command::new("sh").args(["-c", "exit 0"]).spawn()
        };
        if let Ok(mut ch) = dead_child {
            let dead_pid = ch.id();
            let _ = ch.wait();
            let lock_p = PathBuf::from(format!("{}.lock", db.display()));
            fs::write(&lock_p, format!("pid={dead_pid} seq=1 ns=1\n")).unwrap();
            let t0 = Instant::now();
            let _g = acquire_vault_lock(&db).expect("must reclaim dead-PID recall lock");
            assert!(
                t0.elapsed() < Duration::from_secs(4),
                "dead-PID recall lock reclaim took {:?}",
                t0.elapsed()
            );
        }

        // Remove junctions before recursive cleanup on Windows
        #[cfg(windows)]
        {
            let _ = fs::remove_dir(sub.join("ext_junc"));
            let _ = fs::remove_dir(sub.join("self_loop"));
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
