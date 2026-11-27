use clap::{Parser, Subcommand};
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SIEVE_LOCK_SEQ: AtomicU64 = AtomicU64::new(0);
static SIEVE_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

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

fn has_explicit_sieve_home() -> bool {
    std::env::var("SIEVE_HOME")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

pub const DEFAULT_MAX_STORE_BYTES: u64 = 18 * 1024 * 1024;
pub const PASSTHROUGH_BYTES: usize = 1200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SieveResult {
    pub id: String,
    pub mode: String,
    pub exit_code: i32,
    pub raw_bytes: usize,
    pub digest_bytes: usize,
    #[serde(default)]
    pub saved_pct: f64,
    pub raw_tokens_est: usize,
    pub digest_tokens_est: usize,
    pub rendered: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub id: String,
    pub label: String,
    pub snippet: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "sieve",
    about = "Lossless output compressor & SQLite FTS5 flight recorder"
)]
struct Cli {
    #[command(subcommand)]
    subcmd: SubCmd,
}

#[derive(Subcommand, Debug)]
enum SubCmd {
    /// Run a command and compress its output losslessly
    Run {
        #[arg(long)]
        json: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Read stdin and compress losslessly
    Pipe {
        #[arg(long, default_value = "stdin")]
        label: String,
        #[arg(long)]
        json: bool,
    },
    /// Retrieve exact raw slices by archive id
    Peek {
        id: String,
        #[arg(long)]
        lines: Option<String>,
        #[arg(long)]
        grep: Option<String>,
        /// Accepted for grep `-i` muscle-memory compatibility (sieve grep is already case-insensitive)
        #[arg(short = 'i', long = "ignore-case")]
        _ignore_case: bool,
        #[arg(short = 'C', long, default_value_t = 3)]
        context: usize,
        #[arg(long, default_value_t = 10)]
        max_hits: usize,
        #[arg(long)]
        json_path: Option<String>,
        /// Maximum output characters to return (UTF-8 safe)
        #[arg(long = "max-chars", alias = "max_chars", alias = "chars")]
        max_chars: Option<usize>,
        /// Starting character offset for paging huge single-line JSON or text outputs
        #[arg(long = "char-offset", alias = "char_offset", default_value_t = 0)]
        char_offset: usize,
        /// Emit raw lines without `L<n>:` prefixes or truncation footers (safe for `| python -c json.load`)
        #[arg(long)]
        raw: bool,
        /// Pretty-print valid JSON before slicing/outputting
        #[arg(long)]
        pretty: bool,
    },
    /// Sub-millisecond SQLite FTS5 full-text search across all archived outputs
    Search {
        query: String,
        #[arg(long, default_value_t = 8)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Bounded maintenance: prune oldest/expired archives & VACUUM SQLite FTS5 store
    Prune {
        /// Maximum retained raw+meta store size per directory in MiB (default: 64)
        #[arg(long = "max-mb", default_value_t = 64)]
        max_mb: u64,
        /// Optional maximum age in hours (archives older than this are removed)
        #[arg(long = "max-age-hours")]
        max_age_hours: Option<u64>,
        /// Run SQLite WAL checkpoint + VACUUM after deleting pruned rows
        #[arg(long)]
        vacuum: bool,
        /// Emit structured JSON summary
        #[arg(long)]
        json: bool,
    },
}

fn log_regexes() -> &'static (Regex, Regex, Regex) {
    static RE: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    RE.get_or_init(|| {
        let err_re = Regex::new(
            r#"(?i)(traceback \(most recent call last\)|^\s*file ".*", line \d+|\b(?:error|exception|failed|failure|fatal|panic|assertionerror|typeerror|valueerror|keyerror|syntaxerror|segfault)\b|^E\s+|^FAIL[:\s]|^ERROR[:\s])"#,
        )
        .unwrap();
        let ts_re = Regex::new(r"\b\d{2,4}[-/:]\d{2}[-/:]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b").unwrap();
        let num_re = Regex::new(r"\d+").unwrap();
        (err_re, ts_re, num_re)
    })
}

fn trunc_chars(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i >= max_chars {
            break;
        }
        out.push(ch);
    }
    out
}

fn est_tokens(text: &str) -> usize {
    if text.is_empty() {
        0
    } else {
        text.len().div_ceil(4).max(1)
    }
}

pub fn global_sieve_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .map(|h| h.join(".ap").join("sieve"))
}

fn store_dir_readonly(cwd: &Path) -> PathBuf {
    match std::env::var("SIEVE_HOME") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => cwd.join(".sieve"),
    }
}

pub fn store_dir(cwd: &Path) -> PathBuf {
    let base = store_dir_readonly(cwd);
    let _ = fs::create_dir_all(&base);
    let gi = base.join(".gitignore");
    if !gi.exists() {
        let _ = fs::write(&gi, "*\n");
    }
    base
}

struct SieveLockGuard {
    lock_path: PathBuf,
    token: String,
}

impl Drop for SieveLockGuard {
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
        // ERROR_INVALID_PARAMETER (87) proves the PID does not exist; treat ERROR_ACCESS_DENIED (5)
        // or any other transient failure conservatively as alive so active locks are never stolen.
        return std::io::Error::last_os_error().raw_os_error() != Some(87);
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

fn acquire_sieve_lock(store: &Path) -> Result<SieveLockGuard, String> {
    let _ = fs::create_dir_all(store);
    let lock_path = store.join("index.sqlite.lock");
    let deadline = Instant::now() + Duration::from_secs(12);
    let pid = std::process::id();
    let seq = SIEVE_LOCK_SEQ.fetch_add(1, Ordering::Relaxed);
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
                return Ok(SieveLockGuard { lock_path, token });
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
                                    .map(|holder| !is_pid_alive(holder))
                                    .unwrap_or(false);
                            if dead_holder || age >= Duration::from_secs(8) {
                                let _ = fs::remove_file(&lock_path);
                                continue;
                            }
                        }
                    }
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "timed out acquiring sieve lock {}",
                        lock_path.display()
                    ));
                }
                attempt = attempt.saturating_add(1);
                let jitter = ((pid as u64).wrapping_mul(31) + attempt * 17) % 19;
                std::thread::sleep(Duration::from_millis(6 + jitter));
            }
            Err(e) => return Err(format!("open sieve lock {}: {e}", lock_path.display())),
        }
    }
}

fn write_file_atomic(dst: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    let seq = SIEVE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(
        ".{}.tmp.{}.{}",
        dst.file_name().and_then(|s| s.to_str()).unwrap_or("sieve"),
        std::process::id(),
        seq
    ));
    let mut f = fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    drop(f);
    #[cfg(windows)]
    {
        for attempt in 0..8u64 {
            if fs::rename(&tmp, dst).is_ok() {
                return Ok(());
            }
            if dst.exists() {
                let _ = fs::remove_file(dst);
                if fs::rename(&tmp, dst).is_ok() {
                    return Ok(());
                }
            }
            if attempt < 7 {
                std::thread::sleep(Duration::from_millis(4 + attempt * 3));
            }
        }
        let res = fs::write(dst, bytes);
        let _ = fs::remove_file(&tmp);
        res
    }
    #[cfg(not(windows))]
    {
        let res = fs::rename(&tmp, dst);
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res
    }
}

fn open_sieve_db(db_path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(db_path)?;
    let _ = conn.busy_timeout(Duration::from_millis(8000));
    Ok(conn)
}

fn ensure_chunks_table(conn: &Connection) -> rusqlite::Result<()> {
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.pragma_update(None, "synchronous", "NORMAL");
    conn.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5(id UNINDEXED, label, content);",
    )
}

fn backfilled_cache() -> &'static Mutex<HashMap<PathBuf, u128>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, u128>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn store_dir_mtime_nanos(store: &Path) -> Option<u128> {
    fs::metadata(store)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
}

fn upsert_chunk_tx(
    conn: &Connection,
    item_id: &str,
    label: &str,
    raw_text: &str,
) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM chunks WHERE id = ?1", params![item_id])?;
    tx.execute(
        "INSERT INTO chunks(id, label, content) VALUES (?1, ?2, ?3)",
        params![item_id, label, raw_text],
    )?;
    tx.commit()
}

fn index_archive(store: &Path, item_id: &str, label: &str, raw_text: &str) -> Result<(), String> {
    let _lock = acquire_sieve_lock(store)?;
    if !store.join(format!("{item_id}.raw")).is_file() {
        return Ok(());
    }
    let db_path = store.join("index.sqlite");
    let conn = open_sieve_db(&db_path).map_err(|e| format!("open index.sqlite: {e}"))?;
    ensure_chunks_table(&conn).map_err(|e| format!("init chunks fts5: {e}"))?;
    upsert_chunk_tx(&conn, item_id, label, raw_text)
        .map_err(|e| format!("upsert chunk {item_id}: {e}"))?;
    if let Some(mt) = store_dir_mtime_nanos(store) {
        if let Ok(mut guard) = backfilled_cache().lock() {
            guard.insert(store.to_path_buf(), mt);
        }
    }
    Ok(())
}

fn delete_chunk_ids(conn: &Connection, ids: &[String]) {
    for chunk in ids.chunks(64) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = (1..=chunk.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("DELETE FROM chunks WHERE id IN ({placeholders})");
        if let Ok(mut stmt) = conn.prepare(&sql) {
            let params_iter = chunk.iter().map(|s| s as &dyn rusqlite::ToSql);
            let _ = stmt.execute(rusqlite::params_from_iter(params_iter));
        }
    }
}

fn rebuild_fts_from_surviving(
    conn: &Connection,
    store: &Path,
    surviving_ids: &std::collections::HashSet<String>,
) {
    let _ = conn.execute_batch(
        "DROP TABLE IF EXISTS chunks;\
         CREATE VIRTUAL TABLE chunks USING fts5(id UNINDEXED, label, content);",
    );
    if let Ok(tx) = conn.unchecked_transaction() {
        for id in surviving_ids {
            let raw_p = store.join(format!("{id}.raw"));
            let meta_p = store.join(format!("{id}.meta.json"));
            let label = fs::read_to_string(&meta_p)
                .ok()
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .and_then(|v| v.get("label").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| "archive".to_string());
            if let Ok(raw_text) = fs::read_to_string(&raw_p) {
                let _ = tx.execute(
                    "INSERT INTO chunks(id, label, content) VALUES (?1, ?2, ?3)",
                    params![id, label, raw_text],
                );
            }
        }
        let _ = tx.commit();
    }
}

fn collect_orphan_chunk_ids(
    conn: &Connection,
    surviving_ids: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut orphans = Vec::new();
    if let Ok(mut st) = conn.prepare("SELECT id FROM chunks") {
        if let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0)) {
            for id in rows.flatten() {
                if !surviving_ids.contains(&id) {
                    orphans.push(id);
                }
            }
        }
    }
    orphans
}

fn maybe_compact_sieve_db(
    conn: &Connection,
    db_bytes: u64,
    total_raw_bytes: u64,
    min_db_bytes: u64,
) -> bool {
    if db_bytes > min_db_bytes && db_bytes > total_raw_bytes.saturating_mul(2) {
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
            .is_ok()
    } else {
        false
    }
}

fn prune_ring_buffer(store: &Path, max_bytes: u64) {
    let Ok(_lock) = acquire_sieve_lock(store) else {
        return;
    };
    let Ok(rd) = fs::read_dir(store) else { return };
    let mut raw_files: Vec<(u64, u64, String, PathBuf)> = Vec::new();
    let mut total = 0u64;
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("raw") {
            let Some(stem) = p.file_stem().and_then(|s| s.to_str()).map(str::to_string) else {
                continue;
            };
            if let Ok(meta) = entry.metadata() {
                let sz = meta.len();
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                total += sz;
                raw_files.push((mtime, sz, stem, p));
            }
        }
    }
    raw_files.sort_by_key(|x| x.0);
    let mut idx = 0usize;
    let mut removed_ids: Vec<String> = Vec::new();
    // Bound synchronous eviction per hot-path call so huge backlogs drain incrementally without stalling.
    while total > max_bytes && raw_files.len().saturating_sub(idx) > 1 && removed_ids.len() < 32 {
        let (_, sz, ref stem, ref victim) = raw_files[idx];
        let _ = fs::remove_file(victim);
        let _ = fs::remove_file(victim.with_extension("meta.json"));
        removed_ids.push(stem.clone());
        total = total.saturating_sub(sz);
        idx += 1;
    }

    let db_path = store.join("index.sqlite");
    if !db_path.is_file() {
        return;
    }
    let db_bytes = fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
    let need_vacuum = db_bytes > 24 * 1024 * 1024 && db_bytes > total.saturating_mul(2);
    if removed_ids.is_empty() && !need_vacuum {
        return;
    }
    // Synchronously delete evicted IDs from FTS5 in <1ms; compact automatically when index.sqlite
    // bloats above 24 MiB and > 2x live .raw bytes under the already-held SieveLockGuard.
    if let Ok(conn) = open_sieve_db(&db_path) {
        if !removed_ids.is_empty() {
            delete_chunk_ids(&conn, &removed_ids);
        }
        if need_vacuum {
            let _ = maybe_compact_sieve_db(&conn, db_bytes, total, 24 * 1024 * 1024);
        }
    }
}

pub fn prune_store(
    store: &Path,
    max_bytes: u64,
    max_age_hours: Option<u64>,
    vacuum: bool,
) -> Value {
    if !store.is_dir() {
        return json!({
            "store": store.display().to_string(),
            "exists": false,
            "removed_entries": 0,
            "freed_bytes": 0,
            "remaining_bytes": 0,
            "vacuumed": false,
        });
    }
    let _lock = match acquire_sieve_lock(store) {
        Ok(g) => g,
        Err(e) => {
            return json!({
                "store": store.display().to_string(),
                "exists": true,
                "error": e,
                "removed_entries": 0,
                "freed_bytes": 0,
                "remaining_bytes": 0,
                "vacuumed": false,
            });
        }
    };
    let Ok(rd) = fs::read_dir(store) else {
        return json!({
            "store": store.display().to_string(),
            "exists": false,
            "removed_entries": 0,
            "freed_bytes": 0,
            "remaining_bytes": 0,
            "vacuumed": false,
        });
    };

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cutoff_secs = max_age_hours.map(|h| now_secs.saturating_sub(h.saturating_mul(3600)));

    let mut items: Vec<(u64, u64, String, PathBuf)> = Vec::new();
    let mut total_bytes = 0u64;
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("raw") {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        let meta_p = store.join(format!("{stem}.meta.json"));
        let Ok(raw_meta) = entry.metadata() else {
            continue;
        };
        let mtime_secs = raw_meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let meta_len = fs::metadata(&meta_p).map(|m| m.len()).unwrap_or(0);
        let entry_bytes = raw_meta.len().saturating_add(meta_len);
        total_bytes = total_bytes.saturating_add(entry_bytes);
        items.push((mtime_secs, entry_bytes, stem, p));
    }

    items.sort_by_key(|x| x.0);
    let mut removed_ids: Vec<String> = Vec::new();
    let mut freed_bytes = 0u64;
    let mut kept_bytes = 0u64;

    let mut remaining: Vec<(u64, u64, String, PathBuf)> = Vec::new();
    for (mt, sz, id, raw_p) in items {
        let expired = cutoff_secs.map(|c| mt < c).unwrap_or(false);
        if expired {
            let _ = fs::remove_file(&raw_p);
            let _ = fs::remove_file(store.join(format!("{id}.meta.json")));
            freed_bytes = freed_bytes.saturating_add(sz);
            removed_ids.push(id);
        } else {
            kept_bytes = kept_bytes.saturating_add(sz);
            remaining.push((mt, sz, id, raw_p));
        }
    }

    let db_path = store.join("index.sqlite");
    let db_bytes_before = fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
    let effective_raw_cap = if max_bytes == 0 {
        0
    } else if db_bytes_before > max_bytes && kept_bytes > 0 {
        let ratio_cap = ((kept_bytes as u128 * max_bytes as u128 / db_bytes_before.max(1) as u128)
            * 75
            / 100) as u64;
        max_bytes.min(ratio_cap.max(max_bytes / 4))
    } else {
        max_bytes
    };

    let mut surviving_ids = std::collections::HashSet::new();
    let mut surviving_list: Vec<(u64, String, PathBuf)> = Vec::new();
    // Evict oldest non-expired items until kept_bytes <= effective_raw_cap (guaranteeing index.sqlite <= max_bytes)
    for (_, sz, id, raw_p) in remaining {
        if kept_bytes <= effective_raw_cap && (max_bytes > 0 || effective_raw_cap > 0) {
            surviving_ids.insert(id.clone());
            surviving_list.push((sz, id, raw_p));
            continue;
        }
        let _ = fs::remove_file(&raw_p);
        let _ = fs::remove_file(store.join(format!("{id}.meta.json")));
        kept_bytes = kept_bytes.saturating_sub(sz);
        freed_bytes = freed_bytes.saturating_add(sz);
        removed_ids.push(id);
    }

    let mut vacuumed = false;
    if db_path.is_file() {
        if let Ok(conn) = open_sieve_db(&db_path) {
            let _ = ensure_chunks_table(&conn);
            let orphans = collect_orphan_chunk_ids(&conn, &surviving_ids);
            let total_del = removed_ids.len() + orphans.len();
            if total_del >= 100 {
                // Dropping & rebuilding FTS5 is >50x faster than un-indexing hundreds of docs via UNINDEXED scans.
                rebuild_fts_from_surviving(&conn, store, &surviving_ids);
                vacuumed = conn
                    .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
                    .is_ok();
            } else {
                if !removed_ids.is_empty() {
                    delete_chunk_ids(&conn, &removed_ids);
                }
                if !orphans.is_empty() {
                    delete_chunk_ids(&conn, &orphans);
                }
                if vacuum
                    || !orphans.is_empty()
                    || !removed_ids.is_empty()
                    || db_bytes_before > max_bytes.max(1)
                {
                    vacuumed = conn
                        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
                        .is_ok();
                }
            }
            if max_bytes > 0 {
                for _ in 0..2 {
                    let cur_db = fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
                    if cur_db <= max_bytes || surviving_list.is_empty() {
                        break;
                    }
                    let trim_n = (surviving_list.len() / 2).max(1);
                    let mut extra_ids = Vec::with_capacity(trim_n);
                    for (sz, id, raw_p) in surviving_list.drain(..trim_n) {
                        let _ = fs::remove_file(&raw_p);
                        let _ = fs::remove_file(store.join(format!("{id}.meta.json")));
                        kept_bytes = kept_bytes.saturating_sub(sz);
                        freed_bytes = freed_bytes.saturating_add(sz);
                        surviving_ids.remove(&id);
                        removed_ids.push(id.clone());
                        extra_ids.push(id);
                    }
                    if extra_ids.len() >= 100 {
                        rebuild_fts_from_surviving(&conn, store, &surviving_ids);
                    } else {
                        delete_chunk_ids(&conn, &extra_ids);
                    }
                    if conn
                        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
                        .is_ok()
                    {
                        vacuumed = true;
                    }
                }
            }
        }
    }
    let db_bytes_after = fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);

    json!({
        "store": store.display().to_string(),
        "exists": true,
        "before_bytes": total_bytes,
        "removed_entries": removed_ids.len(),
        "freed_bytes": freed_bytes,
        "remaining_bytes": kept_bytes,
        "db_bytes_before": db_bytes_before,
        "db_bytes_after": db_bytes_after,
        "vacuumed": vacuumed,
    })
}

fn archive_stream(
    store: &Path,
    raw_text: &str,
    label: &str,
    exit_code: i32,
    elapsed_ms: f64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_text.as_bytes());
    let id = format!("{:x}", hasher.finalize())[..10].to_string();
    let raw_path = store.join(format!("{id}.raw"));
    let meta_path = store.join(format!("{id}.meta.json"));
    let _ = write_file_atomic(&raw_path, raw_text.as_bytes());
    let raw_lines = raw_text.lines().count();
    let meta = json!({
        "id": id,
        "label": label,
        "exit_code": exit_code,
        "elapsed_ms": (elapsed_ms * 10.0).round() / 10.0,
        "raw_bytes": raw_text.len(),
        "raw_lines": raw_lines,
        "created_epoch": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    });
    if let Ok(ms) = serde_json::to_string_pretty(&meta) {
        let _ = write_file_atomic(&meta_path, ms.as_bytes());
    }
    if let Err(e) = index_archive(store, &id, label, raw_text) {
        eprintln!("[sieve] warning: failed to index archive {id}: {e}");
    }
    if raw_text.len() >= 16_384 || id.as_bytes().first().copied().unwrap_or(0) % 8 == 0 {
        prune_ring_buffer(store, DEFAULT_MAX_STORE_BYTES);
    }
    id
}

fn format_pipe_table(rows: &[Vec<String>], max_rows: usize) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let sample_n = rows.len().min(max_rows + 2);
    let ncols = rows[..sample_n]
        .iter()
        .map(|r| r.len())
        .max()
        .unwrap_or(0)
        .min(10);
    if ncols == 0 {
        return String::new();
    }
    let fmt_row = |r: &[String]| -> String {
        let cells: Vec<String> = (0..ncols)
            .map(|i| {
                let raw = r.get(i).map(String::as_str).unwrap_or("");
                trunc_chars(raw.replace('|', "\\|").trim(), 48)
            })
            .collect();
        format!("| {} |", cells.join(" | "))
    };
    let mut out = vec![
        fmt_row(&rows[0]),
        format!("| {} |", vec!["---"; ncols].join(" | ")),
    ];
    let body = &rows[1..];
    if body.len() <= max_rows {
        for r in body {
            out.push(fmt_row(r));
        }
    } else {
        let head_n = max_rows.saturating_sub(2).max(1);
        for r in &body[..head_n] {
            out.push(fmt_row(r));
        }
        let empty_tail = if ncols > 1 {
            format!(" | {}", vec![""; ncols - 1].join(" | "))
        } else {
            String::new()
        };
        out.push(format!(
            "| ... ({} middle rows omitted){empty_tail} |",
            body.len() - max_rows
        ));
        for r in &body[body.len() - 2..] {
            out.push(fmt_row(r));
        }
    }
    out.join("\n")
}

fn summarize_json(val: &Value) -> String {
    let mut lines = Vec::new();
    match val {
        Value::Object(map) => {
            let keys: Vec<&String> = map.keys().collect();
            let top_preview: Vec<&str> = keys.iter().take(15).map(|s| s.as_str()).collect();
            lines.push(format!(
                "JSON Object ({} top-level keys): {}",
                keys.len(),
                top_preview.join(", ")
            ));
            for k in keys.iter().take(10) {
                let v = &map[*k];
                match v {
                    Value::Array(arr) => {
                        let schema = match arr.first() {
                            Some(Value::Object(o)) => {
                                format!("{:?}", o.keys().take(8).collect::<Vec<_>>())
                            }
                            Some(other) => value_type_name(other).to_string(),
                            None => "empty".to_string(),
                        };
                        lines.push(format!(
                            "  - {k}: Array[{}] (item schema: {schema})",
                            arr.len()
                        ));
                    }
                    Value::Object(sub) => {
                        let sk: Vec<&str> = sub.keys().take(8).map(|s| s.as_str()).collect();
                        lines.push(format!(
                            "  - {k}: Object({} keys: {})",
                            sub.len(),
                            sk.join(", ")
                        ));
                    }
                    _ => {
                        let s = serde_json::to_string(v).unwrap_or_default();
                        lines.push(format!("  - {k}: {}", trunc_chars(&s, 100)));
                    }
                }
            }
            for alert_k in ["error", "errors", "message", "status", "detail", "warnings"] {
                if let Some(av) = map.get(alert_k) {
                    if !av.is_null()
                        && av != &Value::Bool(false)
                        && av != &json!("")
                        && av != &json!([])
                    {
                        let s = serde_json::to_string(av).unwrap_or_default();
                        lines.push(format!("  ! {alert_k}: {}", trunc_chars(&s, 240)));
                    }
                }
            }
        }
        Value::Array(arr) => {
            let schema = match arr.first() {
                Some(Value::Object(o)) => format!("{:?}", o.keys().take(10).collect::<Vec<_>>()),
                Some(other) => value_type_name(other).to_string(),
                None => "empty".to_string(),
            };
            lines.push(format!(
                "JSON Array ({} items, item schema: {schema})",
                arr.len()
            ));
            if let Some(first) = arr.first() {
                let s = serde_json::to_string(first).unwrap_or_default();
                lines.push(format!("  - [0] preview: {}", trunc_chars(&s, 260)));
            }
        }
        _ => {
            let s = serde_json::to_string(val).unwrap_or_default();
            lines.push(format!("JSON Scalar: {}", trunc_chars(&s, 200)));
        }
    }
    lines.join("\n")
}

fn value_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn try_summarize_jsonl(raw: &str) -> Option<String> {
    let all_lines: Vec<&str> = raw.lines().collect();
    let non_empty: Vec<(usize, &str)> = all_lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            let t = l.trim();
            if t.is_empty() {
                None
            } else {
                Some((i + 1, t))
            }
        })
        .collect();
    if non_empty.len() < 2 {
        return None;
    }
    let sample_n = non_empty.len().min(40);
    let mut valid = 0usize;
    for &(_, ln) in &non_empty[..sample_n] {
        if ln.starts_with('{') && ln.ends_with('}') {
            if let Ok(Value::Object(_)) = serde_json::from_str::<Value>(ln) {
                valid += 1;
            }
        }
    }
    if valid < ((sample_n * 3) / 4).max(2) {
        return None;
    }

    let mut key_counts: HashMap<String, usize> = HashMap::new();
    let mut type_counts: HashMap<String, usize> = HashMap::new();
    let mut err_records: Vec<String> = Vec::new();
    let mut parsed_count = 0usize;
    let mut first_preview = String::new();
    let mut last_preview = String::new();

    for &(lineno, ln) in &non_empty {
        let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(ln) else {
            continue;
        };
        parsed_count += 1;
        if first_preview.is_empty() {
            first_preview = trunc_chars(ln, 200);
        }
        last_preview = trunc_chars(ln, 200);
        for k in obj.keys() {
            *key_counts.entry(k.clone()).or_insert(0) += 1;
        }
        for tk in ["type", "event", "kind", "level"] {
            if let Some(tv) = obj.get(tk) {
                let tag = match tv {
                    Value::String(s) => Some(format!("{tk}={s}")),
                    Value::Number(n) => Some(format!("{tk}={n}")),
                    _ => None,
                };
                if let Some(t) = tag {
                    *type_counts.entry(t).or_insert(0) += 1;
                    break;
                }
            }
        }
        let is_err = obj
            .get("error")
            .map(|v| !v.is_null() && v != &Value::Bool(false) && v != &json!(""))
            .unwrap_or(false)
            || obj
                .get("errors")
                .map(|v| !v.is_null() && v != &json!([]))
                .unwrap_or(false)
            || obj.get("isError") == Some(&Value::Bool(true))
            || obj.get("ok") == Some(&Value::Bool(false))
            || obj
                .get("level")
                .and_then(Value::as_str)
                .map(|l| {
                    matches!(
                        l.to_ascii_lowercase().as_str(),
                        "error" | "fatal" | "critical"
                    )
                })
                .unwrap_or(false)
            || obj
                .get("status")
                .and_then(Value::as_i64)
                .map(|s| s >= 400)
                .unwrap_or(false);
        if is_err && err_records.len() < 5 {
            err_records.push(format!("  - L{lineno}: {}", trunc_chars(ln, 220)));
        }
    }

    let mut kc_vec: Vec<(String, usize)> = key_counts.into_iter().collect();
    kc_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top_keys = kc_vec
        .into_iter()
        .take(12)
        .map(|(k, c)| format!("{k}({c})"))
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = vec![format!(
        "JSONL Stream ({parsed_count} records across {} lines) | Schema: {top_keys}",
        all_lines.len()
    )];
    if !type_counts.is_empty() {
        let mut tc_vec: Vec<(String, usize)> = type_counts.into_iter().collect();
        tc_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let dist = tc_vec
            .into_iter()
            .take(8)
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(format!("Distribution: {dist}"));
    }
    if !err_records.is_empty() {
        out.push(format!(
            "High-Signal Error/Alert Records (showing {}):",
            err_records.len()
        ));
        out.extend(err_records);
    }
    if !first_preview.is_empty() {
        out.push(format!(
            "First record (L{}): {first_preview}",
            non_empty[0].0
        ));
    }
    if !last_preview.is_empty() && non_empty.len() > 1 {
        out.push(format!(
            "Last record (L{}): {last_preview}",
            non_empty[non_empty.len() - 1].0
        ));
    }
    Some(out.join("\n"))
}

fn try_summarize_tabular(raw: &str) -> Option<(String, String)> {
    let non_empty: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    if non_empty.len() < 4 {
        return None;
    }
    let sample_txt = non_empty[..non_empty.len().min(15)].join("\n");
    for (delim, kind_name) in [(b'\t', "tsv"), (b',', "csv")] {
        if non_empty[0]
            .as_bytes()
            .iter()
            .filter(|&&b| b == delim)
            .count()
            < 2
        {
            continue;
        }
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .delimiter(delim)
            .flexible(true)
            .from_reader(sample_txt.as_bytes());
        let sample_rows: Vec<Vec<String>> = rdr
            .records()
            .flatten()
            .map(|rec| rec.iter().map(String::from).collect())
            .collect();
        if sample_rows.len() < 4 {
            continue;
        }
        let col_n = sample_rows[0].len();
        if col_n < 3
            || sample_rows[0].iter().take(2).any(|c| c.trim().is_empty())
            || sample_rows[0].iter().any(|c| c.chars().count() > 64)
        {
            continue;
        }
        let consistent = sample_rows[1..].iter().filter(|r| r.len() == col_n).count();
        if consistent * 5 < (sample_rows.len() - 1) * 4 {
            continue;
        }
        let mut full_rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .delimiter(delim)
            .flexible(true)
            .from_reader(raw.as_bytes());
        let all_rows: Vec<Vec<String>> = full_rdr
            .records()
            .flatten()
            .map(|rec| rec.iter().map(String::from).collect::<Vec<_>>())
            .filter(|r| r.iter().any(|c| !c.trim().is_empty()))
            .collect();
        let hdr_cols: Vec<&str> = sample_rows[0].iter().take(10).map(String::as_str).collect();
        let summary = format!(
            "{} Table ({} data rows x {col_n} columns): {}\n{}",
            kind_name.to_uppercase(),
            all_rows.len().saturating_sub(1),
            hdr_cols.join(", "),
            format_pipe_table(&all_rows, 6)
        );
        return Some((kind_name.to_string(), summary));
    }
    None
}

fn decode_basic_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

fn summarize_html(raw: &str) -> String {
    let mut skip_depth = 0usize;
    let mut in_title = false;
    let mut heading_tag: Option<String> = None;
    let mut title_buf = String::new();
    let mut cur_heading = String::new();
    let mut headings: Vec<String> = Vec::new();
    let mut text_chunks: Vec<String> = Vec::new();
    let mut link_count = 0usize;
    let mut tables: Vec<Vec<Vec<String>>> = Vec::new();
    let mut cur_table: Option<Vec<Vec<String>>> = None;
    let mut cur_row: Option<Vec<String>> = None;
    let mut cur_cell: Option<String> = None;

    let bytes = raw.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if raw[i..].starts_with("<!--") {
                if let Some(end_c) = raw[i + 4..].find("-->") {
                    i += 4 + end_c + 3;
                    continue;
                }
            }
            if let Some(gt_rel) = raw[i..].find('>') {
                let tag_inner = raw[i + 1..i + gt_rel].trim();
                let is_end = tag_inner.starts_with('/');
                let is_self_close = tag_inner.ends_with('/');
                let clean = tag_inner
                    .trim_start_matches('/')
                    .trim_end_matches('/')
                    .trim();
                let tag_name: String = clean
                    .split(|c: char| c.is_whitespace() || c == '/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();

                if !is_end {
                    if matches!(tag_name.as_str(), "script" | "style" | "svg" | "noscript")
                        && !is_self_close
                    {
                        skip_depth += 1;
                    } else if skip_depth == 0 {
                        match tag_name.as_str() {
                            "title" => in_title = true,
                            "h1" | "h2" | "h3" => {
                                heading_tag = Some(tag_name.to_uppercase());
                                cur_heading.clear();
                            }
                            "a" => link_count += 1,
                            "table" => cur_table = Some(Vec::new()),
                            "tr" if cur_table.is_some() => cur_row = Some(Vec::new()),
                            "th" | "td" if cur_row.is_some() => cur_cell = Some(String::new()),
                            _ => {}
                        }
                    }
                } else {
                    if matches!(tag_name.as_str(), "script" | "style" | "svg" | "noscript") {
                        skip_depth = skip_depth.saturating_sub(1);
                    } else if skip_depth == 0 {
                        match tag_name.as_str() {
                            "title" => in_title = false,
                            "h1" | "h2" | "h3" => {
                                if let Some(ht) = heading_tag.take() {
                                    let h = cur_heading
                                        .split_whitespace()
                                        .collect::<Vec<_>>()
                                        .join(" ");
                                    if !h.is_empty() {
                                        headings.push(format!("{ht}: {}", trunc_chars(&h, 100)));
                                    }
                                }
                            }
                            "th" | "td" => {
                                if let (Some(cell), Some(row)) = (cur_cell.take(), cur_row.as_mut())
                                {
                                    let c = cell.split_whitespace().collect::<Vec<_>>().join(" ");
                                    row.push(trunc_chars(&c, 80));
                                }
                            }
                            "tr" => {
                                if let (Some(row), Some(tbl)) = (cur_row.take(), cur_table.as_mut())
                                {
                                    if row.iter().any(|c| !c.is_empty()) {
                                        tbl.push(row);
                                    }
                                }
                            }
                            "table" => {
                                if let Some(tbl) = cur_table.take() {
                                    if !tbl.is_empty() {
                                        tables.push(tbl);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                i += gt_rel + 1;
                continue;
            }
        }
        let next_lt = raw[i..].find('<').map(|off| i + off).unwrap_or(raw.len());
        if skip_depth == 0 && next_lt > i {
            let text = decode_basic_entities(&raw[i..next_lt]);
            if in_title {
                title_buf.push_str(&text);
            }
            if heading_tag.is_some() {
                cur_heading.push_str(&text);
            }
            if let Some(cell) = cur_cell.as_mut() {
                cell.push_str(&text);
            } else {
                let cleaned = text.split_whitespace().collect::<Vec<_>>().join(" ");
                if !cleaned.is_empty() {
                    text_chunks.push(cleaned);
                }
            }
        }
        i = next_lt.max(i + 1);
    }

    let title_clean = title_buf.split_whitespace().collect::<Vec<_>>().join(" ");
    let title = if title_clean.is_empty() {
        "(untitled)".to_string()
    } else {
        trunc_chars(&title_clean, 140)
    };
    let body = text_chunks.join(" ");
    let mut out = vec![format!(
        "HTML Document | Title: {title} | Links: {link_count} | Tables: {}",
        tables.len()
    )];
    if !headings.is_empty() {
        out.push("Outline:".to_string());
        for h in headings.iter().take(12) {
            out.push(format!("  - {h}"));
        }
    }
    for (idx, tbl) in tables.iter().take(2).enumerate() {
        out.push(format!(
            "Table #{} ({} rows):\n{}",
            idx + 1,
            tbl.len(),
            format_pipe_table(tbl, 5)
        ));
    }
    let body_lead = trunc_chars(&body, 450);
    let ellipsis = if body.chars().count() > 450 {
        "..."
    } else {
        ""
    };
    out.push(format!("Lead text: {body_lead}{ellipsis}"));
    out.join("\n")
}

fn summarize_log(raw: &str) -> String {
    let (err_re, ts_re, num_re) = log_regexes();
    let lines: Vec<&str> = raw.lines().collect();
    let n = lines.len();
    let mut norm_counts: HashMap<String, usize> = HashMap::new();
    let mut error_windows: Vec<(usize, usize)> = Vec::new();

    for (idx, &ln) in lines.iter().enumerate() {
        let norm_head = trunc_chars(ln, 240);
        let norm = ts_re.replace_all(&norm_head, "<TS>").trim().to_string();
        if !norm.is_empty() {
            *norm_counts.entry(norm).or_insert(0) += 1;
        }
        let err_head = trunc_chars(ln, 4096);
        if err_re.is_match(&err_head) {
            let start = idx.saturating_sub(1);
            let end = (idx + 3).min(n.saturating_sub(1));
            if let Some(last) = error_windows.last_mut() {
                if start <= last.1 + 2 {
                    last.1 = last.1.max(end);
                    continue;
                }
            }
            error_windows.push((start, end));
        }
    }

    let mut sections: Vec<String> = Vec::new();
    let head: Vec<String> = lines
        .iter()
        .enumerate()
        .take(5)
        .filter(|(_, l)| !l.trim().is_empty())
        .take(4)
        .map(|(i, l)| format!("L{}: {}", i + 1, trunc_chars(l, 140)))
        .collect();
    if !head.is_empty() {
        sections.push(format!("Head:\n  {}", head.join("\n  ")));
    }

    if !error_windows.is_empty() {
        let mut seen_sigs: HashSet<String> = HashSet::new();
        let mut kept_blocks: Vec<String> = Vec::new();
        for &(s, e) in &error_windows {
            let sig_end = (e + 1).min(s + 3);
            let sig = (s..sig_end)
                .map(|k| {
                    let prefix = trunc_chars(lines[k], 240);
                    trunc_chars(&num_re.replace_all(&prefix, "#"), 80)
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !seen_sigs.insert(sig) {
                continue;
            }
            const MAX_BLOCK_LINES: usize = 14;
            let span_len = e.saturating_sub(s) + 1;
            let snippet = if span_len <= MAX_BLOCK_LINES {
                (s..=e)
                    .map(|k| format!("L{}: {}", k + 1, trunc_chars(lines[k], 160)))
                    .collect::<Vec<_>>()
                    .join("\n    ")
            } else {
                let head_n = 10usize;
                let tail_n = 3usize;
                let omitted_mid = span_len.saturating_sub(head_n + tail_n);
                let mut parts: Vec<String> = (s..s + head_n)
                    .map(|k| format!("L{}: {}", k + 1, trunc_chars(lines[k], 160)))
                    .collect();
                parts.push(format!(
                    "... ({omitted_mid} lines omitted in L{}-L{}; inspect via ap sieve peek)",
                    s + head_n + 1,
                    e + 1 - tail_n
                ));
                for (k, line) in lines.iter().enumerate().take(e + 1).skip(e + 1 - tail_n) {
                    parts.push(format!("L{}: {}", k + 1, trunc_chars(line, 160)));
                }
                parts.join("\n    ")
            };
            kept_blocks.push(format!("  [L{}-L{}]\n    {snippet}", s + 1, e + 1));
            if kept_blocks.len() >= 4 {
                break;
            }
        }
        let omitted = error_windows.len().saturating_sub(kept_blocks.len());
        let hdr = if omitted > 0 {
            format!(
                "High-Signal Failure/Error Blocks ({} total, {omitted} similar omitted):",
                error_windows.len()
            )
        } else {
            format!(
                "High-Signal Failure/Error Blocks ({} total):",
                error_windows.len()
            )
        };
        sections.push(format!("{hdr}\n{}", kept_blocks.join("\n")));
    }

    let mut noisy: Vec<(usize, String)> = norm_counts
        .into_iter()
        .filter(|(_, cnt)| *cnt >= 5)
        .map(|(txt, cnt)| (cnt, txt))
        .collect();
    noisy.sort_by_key(|a| std::cmp::Reverse(a.0));
    if !noisy.is_empty() {
        let rep = noisy
            .into_iter()
            .take(3)
            .map(|(cnt, txt)| format!("[x{cnt}] {}", trunc_chars(&txt, 110)))
            .collect::<Vec<_>>()
            .join("\n  ");
        sections.push(format!("Collapsed Repetitions:\n  {rep}"));
    }

    if n > 6 {
        let tail_start = 5.max(n.saturating_sub(5));
        let tail: Vec<String> = (tail_start..n)
            .filter(|&i| !lines[i].trim().is_empty())
            .map(|i| format!("L{}: {}", i + 1, trunc_chars(lines[i], 140)))
            .collect();
        if !tail.is_empty() {
            sections.push(format!("Tail:\n  {}", tail.join("\n  ")));
        }
    }
    sections.join("\n")
}

pub fn strip_ansi(raw: &str) -> Cow<'_, str> {
    if !raw.contains('\x1b') {
        return Cow::Borrowed(raw);
    }
    static ANSI_RE: OnceLock<Regex> = OnceLock::new();
    let re = ANSI_RE.get_or_init(|| {
        Regex::new(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
            .unwrap()
    });
    re.replace_all(raw, "")
}

fn try_summarize_diff(clean: &str) -> Option<String> {
    let lines: Vec<&str> = clean.lines().collect();
    if lines.len() < 6 {
        return None;
    }
    let has_git_diff = lines.iter().any(|l| l.starts_with("diff --git "));
    let has_unified = lines.iter().any(|l| l.starts_with("--- "))
        && lines.iter().any(|l| l.starts_with("+++ "))
        && lines.iter().any(|l| l.starts_with("@@ "));
    if !has_git_diff && !has_unified {
        return None;
    }

    struct FileDiffStat {
        path: String,
        added: usize,
        deleted: usize,
        hunks: Vec<String>,
        sample_changes: Vec<String>,
    }

    let mut files: Vec<FileDiffStat> = Vec::new();
    let mut cur: Option<FileDiffStat> = None;

    let flush_cur = |cur_opt: &mut Option<FileDiffStat>, out: &mut Vec<FileDiffStat>| {
        if let Some(f) = cur_opt.take() {
            out.push(f);
        }
    };

    for &ln in &lines {
        if let Some(rest) = ln.strip_prefix("diff --git ") {
            flush_cur(&mut cur, &mut files);
            let path = rest
                .split_whitespace()
                .nth(1)
                .map(|s| s.strip_prefix("b/").unwrap_or(s))
                .unwrap_or(rest)
                .to_string();
            cur = Some(FileDiffStat {
                path,
                added: 0,
                deleted: 0,
                hunks: Vec::new(),
                sample_changes: Vec::new(),
            });
            continue;
        }
        if let Some(rest) = ln.strip_prefix("+++ ") {
            let p = rest
                .split('\t')
                .next()
                .unwrap_or(rest)
                .trim()
                .strip_prefix("b/")
                .unwrap_or(rest.trim())
                .to_string();
            if let Some(ref mut f) = cur {
                if p != "/dev/null" && !p.is_empty() {
                    f.path = p;
                }
            } else if p != "/dev/null" && !p.is_empty() {
                cur = Some(FileDiffStat {
                    path: p,
                    added: 0,
                    deleted: 0,
                    hunks: Vec::new(),
                    sample_changes: Vec::new(),
                });
            }
            continue;
        }
        if ln.starts_with("--- ") {
            continue;
        }
        let Some(ref mut f) = cur else {
            continue;
        };
        if ln.starts_with("@@ ") {
            if f.hunks.len() < 3 {
                let ctx = ln
                    .split("@@")
                    .nth(2)
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                if let Some(c) = ctx {
                    f.hunks.push(trunc_chars(c, 60));
                } else {
                    f.hunks.push(trunc_chars(ln, 48));
                }
            }
        } else if ln.starts_with('+') && !ln.starts_with("+++") {
            f.added += 1;
            if f.sample_changes.len() < 2 && ln.len() > 2 {
                f.sample_changes.push(trunc_chars(ln, 96));
            }
        } else if ln.starts_with('-') && !ln.starts_with("---") {
            f.deleted += 1;
            if f.sample_changes.len() < 2 && ln.len() > 2 {
                f.sample_changes.push(trunc_chars(ln, 96));
            }
        }
    }
    flush_cur(&mut cur, &mut files);
    if files.is_empty() {
        return None;
    }

    let total_added: usize = files.iter().map(|f| f.added).sum();
    let total_deleted: usize = files.iter().map(|f| f.deleted).sum();
    let mut out = vec![format!(
        "Unified Diff Digest ({} file(s), +{total_added}/-{total_deleted} across {} lines):",
        files.len(),
        lines.len()
    )];
    for f in files.iter().take(20) {
        let hunk_txt = if f.hunks.is_empty() {
            String::new()
        } else {
            format!(" | hunks: {}", f.hunks.join(", "))
        };
        out.push(format!(
            "  - {} (+{}/-{}){hunk_txt}",
            f.path, f.added, f.deleted
        ));
        if files.len() <= 8 {
            for s in &f.sample_changes {
                out.push(format!("      {s}"));
            }
        }
    }
    if files.len() > 20 {
        out.push(format!(
            "  ... ({} additional files omitted; use `ap sieve peek`)",
            files.len() - 20
        ));
    }
    Some(out.join("\n"))
}

fn try_summarize_compiler(clean: &str) -> Option<String> {
    static COMP_RES: OnceLock<(Regex, Regex, Regex, Regex, Regex, Regex)> = OnceLock::new();
    let (rust_diag, rust_loc, tsc_diag, generic_diag, go_diag, go_msg_kw) =
        COMP_RES.get_or_init(|| {
            (
                Regex::new(r"^(error|warning)(?:\[([A-Za-z0-9_-]+)\])?:\s+(.+)$").unwrap(),
                Regex::new(r"^\s*-->\s+(.+:\d+:\d+)\s*$").unwrap(),
                Regex::new(r"^([^\s(]+)\((\d+),(\d+)\):\s+(error|warning)\s+(TS\d+):\s+(.+)$")
                    .unwrap(),
                Regex::new(
                    r"^([A-Za-z0-9_./\\-]+\.(?:rs|ts|tsx|js|jsx|go|c|cc|cpp|h|hpp|py)):(\d+)(?::(\d+))?:\s*(?:-\s*)?(error|warning)(?:\s+([A-Za-z0-9_-]+))?:\s+(.+)$",
                )
                .unwrap(),
                Regex::new(r"^([A-Za-z0-9_./\\-]+\.go):(\d+):(\d+):\s+(.+)$").unwrap(),
                Regex::new(
                    r"(?i)(?:\bundefined:|cannot use\b|\bsyntax error\b|\bdeclared and not used\b|\bimported and not used\b|\btoo many arguments\b|\bnot enough arguments\b|\bcannot assign\b|\binvalid operation\b|\bmissing return\b|\bredeclared in this block\b|\bhas no field or method\b)",
                )
                .unwrap(),
            )
        });

    let lines: Vec<&str> = clean.lines().collect();
    let mut err_count = 0usize;
    let mut warn_count = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut seen_err: HashSet<String> = HashSet::new();
    let mut seen_warn: HashSet<String> = HashSet::new();

    let mut i = 0usize;
    while i < lines.len() {
        let ln = lines[i].trim_end();
        if let Some(cap) = rust_diag.captures(ln) {
            let sev = &cap[1];
            let code = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let msg = cap[3].trim();
            // Skip cargo roll-up summary lines like "could not compile" or "generated 3 warnings"
            if msg.starts_with("aborting due to")
                || msg.starts_with("could not compile")
                || msg.contains("warnings emitted")
            {
                i += 1;
                continue;
            }
            let mut loc = String::new();
            for next_ln in lines.iter().skip(i + 1).take(3) {
                if let Some(lc) = rust_loc.captures(next_ln) {
                    loc = lc[1].to_string();
                    break;
                }
            }
            let tag = if code.is_empty() {
                sev.to_string()
            } else {
                format!("{sev}[{code}]")
            };
            let entry = if loc.is_empty() {
                format!("{tag}: {}", trunc_chars(msg, 120))
            } else {
                format!("{loc} | {tag}: {}", trunc_chars(msg, 110))
            };
            let dedup_key = format!("{tag}::{}::{}", loc, trunc_chars(msg, 60));
            if sev == "error" {
                err_count += 1;
                if seen_err.insert(dedup_key) && errors.len() < 14 {
                    errors.push(format!("  - {entry}"));
                }
            } else {
                warn_count += 1;
                if seen_warn.insert(dedup_key) && warnings.len() < 6 {
                    warnings.push(format!("  - {entry}"));
                }
            }
        } else if let Some(cap) = tsc_diag.captures(ln) {
            let loc = format!("{}:{}:{}", &cap[1], &cap[2], &cap[3]);
            let sev = &cap[4];
            let code = &cap[5];
            let msg = cap[6].trim();
            let entry = format!("{loc} | {sev}[{code}]: {}", trunc_chars(msg, 110));
            let dedup_key = format!("{code}::{loc}");
            if sev == "error" {
                err_count += 1;
                if seen_err.insert(dedup_key) && errors.len() < 14 {
                    errors.push(format!("  - {entry}"));
                }
            } else {
                warn_count += 1;
                if seen_warn.insert(dedup_key) && warnings.len() < 6 {
                    warnings.push(format!("  - {entry}"));
                }
            }
        } else if let Some(cap) = generic_diag.captures(ln) {
            let loc = match cap.get(3) {
                Some(col) => format!("{}:{}:{}", &cap[1], &cap[2], col.as_str()),
                None => format!("{}:{}", &cap[1], &cap[2]),
            };
            let sev = &cap[4];
            let code = cap.get(5).map(|m| m.as_str()).unwrap_or("");
            let msg = cap[6].trim();
            let tag = if code.is_empty() {
                sev.to_string()
            } else {
                format!("{sev}[{code}]")
            };
            let entry = format!("{loc} | {tag}: {}", trunc_chars(msg, 110));
            let dedup_key = format!("{tag}::{loc}");
            if sev == "error" {
                err_count += 1;
                if seen_err.insert(dedup_key) && errors.len() < 14 {
                    errors.push(format!("  - {entry}"));
                }
            } else {
                warn_count += 1;
                if seen_warn.insert(dedup_key) && warnings.len() < 6 {
                    warnings.push(format!("  - {entry}"));
                }
            }
        } else if let Some(cap) = go_diag.captures(ln) {
            let msg = cap[4].trim();
            if !msg.starts_with("warning:") && go_msg_kw.is_match(msg) {
                let loc = format!("{}:{}:{}", &cap[1], &cap[2], &cap[3]);
                let entry = format!("{loc} | error[go]: {}", trunc_chars(msg, 110));
                let dedup_key = format!("go::{loc}::{}", trunc_chars(msg, 60));
                err_count += 1;
                if seen_err.insert(dedup_key) && errors.len() < 14 {
                    errors.push(format!("  - {entry}"));
                }
            }
        }
        i += 1;
    }

    let total_diags = err_count + warn_count;
    if err_count == 0 && total_diags < 2 {
        return None;
    }
    let mut out = vec![format!(
        "Compiler Diagnostics Digest (errors={err_count}, warnings={warn_count} across {} lines):",
        lines.len()
    )];
    if !errors.is_empty() {
        out.push(format!("Root-Cause Errors (showing {}):", errors.len()));
        out.extend(errors);
    }
    if !warnings.is_empty() {
        out.push(format!("Warnings (showing {}):", warnings.len()));
        out.extend(warnings);
    }
    Some(out.join("\n"))
}

fn try_summarize_test_output(clean: &str) -> Option<String> {
    static TEST_RES: OnceLock<(Regex, Regex, Regex, Regex, Regex)> = OnceLock::new();
    let (pass_re, fail_re, skip_re, summary_re, assert_re) = TEST_RES.get_or_init(|| {
        (
            Regex::new(
                r"(?:^test\s+\S+\s+\.\.\.\s+ok\b|^---\s+PASS:\s+\S+|\bPASSED\b|^PASS\s+\S|^✔\s+|\bok\s+\d+\s+-)",
            )
            .unwrap(),
            Regex::new(
                r"(?:^test\s+(\S+)\s+\.\.\.\s+FAILED\b|^---\s+FAIL:\s+(\S+)|^(?:FAIL|FAILED|ERROR)\s+(\S+)|^✖\s+(.+)|^not ok\s+\d+\s+-\s+(.+))",
            )
            .unwrap(),
            Regex::new(r"(?:^test\s+\S+\s+\.\.\.\s+ignored\b|\bSKIPPED\b|^---\s+SKIP:)").unwrap(),
            Regex::new(
                r"(?:^test result:|^Tests:\s+|\d+\s+passed(?:,\s+\d+\s+failed)?|\d+\s+failed,\s+\d+\s+passed|^FAIL\s+\S+\s+[0-9.]+s)",
            )
            .unwrap(),
            Regex::new(
                r"(?i)(?:panicked at|assertion|expected|received|AssertionError|TypeError|ValueError|RuntimeError|Error:|^\s*E\s+|^\s*left:|^\s*right:)",
            )
            .unwrap(),
        )
    });

    let lines: Vec<&str> = clean.lines().collect();
    let mut passed = 0usize;
    let mut failed_names: Vec<String> = Vec::new();
    let mut failed_seen: HashSet<String> = HashSet::new();
    let mut skipped = 0usize;
    let mut summary_lines: Vec<String> = Vec::new();
    let mut failure_snippets: Vec<String> = Vec::new();

    for (idx, &ln) in lines.iter().enumerate() {
        let tr = ln.trim();
        if tr.is_empty() {
            continue;
        }
        if let Some(cap) = fail_re.captures(tr) {
            let name = (1..=5)
                .find_map(|g| cap.get(g).map(|m| m.as_str().trim()))
                .unwrap_or(tr);
            let nm = trunc_chars(name, 100);
            if failed_seen.insert(nm.clone()) {
                failed_names.push(nm);
            }
            if failure_snippets.len() < 8 {
                let mut block = vec![format!("L{}: {}", idx + 1, trunc_chars(tr, 150))];
                for (k, raw_nxt) in lines
                    .iter()
                    .enumerate()
                    .take((idx + 7).min(lines.len()))
                    .skip(idx + 1)
                {
                    let nxt = raw_nxt.trim();
                    if nxt.is_empty() || pass_re.is_match(nxt) {
                        break;
                    }
                    if assert_re.is_match(nxt)
                        || nxt.starts_with("File ")
                        || nxt.starts_with("Traceback")
                        || nxt.starts_with("at ")
                    {
                        block.push(format!("L{}: {}", k + 1, trunc_chars(nxt, 150)));
                    }
                }
                failure_snippets.push(format!("  - {}", block.join("\n      ")));
            }
        } else if pass_re.is_match(tr) {
            passed += 1;
        } else if skip_re.is_match(tr) {
            skipped += 1;
        }
        if summary_re.is_match(tr) && summary_lines.len() < 4 {
            summary_lines.push(format!("  {}", trunc_chars(tr, 140)));
        }
    }

    // Also pick up Rust/Cargo `failures:` section assertion/panic lines if not already attached
    if !failed_names.is_empty() && failure_snippets.len() < 8 {
        let mut in_failures_detail = false;
        for (idx, &ln) in lines.iter().enumerate() {
            let tr = ln.trim();
            if tr == "failures:" {
                in_failures_detail = true;
                continue;
            }
            if in_failures_detail && assert_re.is_match(tr) {
                let snip = format!("  - L{}: {}", idx + 1, trunc_chars(tr, 150));
                if !failure_snippets.iter().any(|s| s.contains(tr)) {
                    failure_snippets.push(snip);
                    if failure_snippets.len() >= 8 {
                        break;
                    }
                }
            }
        }
    }

    let has_runner_signal =
        !summary_lines.is_empty() || passed >= 3 || (passed >= 1 && !failed_names.is_empty());
    if !has_runner_signal {
        return None;
    }

    let mut out = vec![format!(
        "Test Runner Digest (passed={passed}, failed={}, skipped={skipped} across {} lines):",
        failed_names.len(),
        lines.len()
    )];
    if !failed_names.is_empty() {
        out.push(format!(
            "Failed Tests ({}): {}",
            failed_names.len(),
            failed_names
                .iter()
                .take(12)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !failure_snippets.is_empty() {
        out.push("Failure Details:".to_string());
        out.extend(failure_snippets);
    }
    if !summary_lines.is_empty() {
        out.push("Runner Summary:".to_string());
        out.extend(summary_lines);
    }
    Some(out.join("\n"))
}

fn strip_wrapper_prefix_for_json(clean: &str) -> &str {
    let mut s = clean.trim_start();
    loop {
        if let Some(rest) = s.strip_prefix("<console_output>") {
            s = rest.trim_start();
            continue;
        }
        if s.starts_with("==> text ") {
            if let Some(nl) = s.find('\n') {
                if s[..nl].contains(" <==") {
                    s = s[nl + 1..].trim_start();
                    continue;
                }
            }
        }
        if s.starts_with("Script completed") || s.starts_with("Script failed") {
            if let Some(out_idx) = s.find("\nOutput:\n") {
                s = s[out_idx + "\nOutput:\n".len()..].trim_start();
                continue;
            }
        }
        break;
    }
    s
}

fn summarize_partial_json(stripped: &str) -> Option<String> {
    if !stripped.starts_with('{') && !stripped.starts_with('[') {
        return None;
    }
    static KEY_RE: OnceLock<Regex> = OnceLock::new();
    let key_re = KEY_RE
        .get_or_init(|| Regex::new(r#""([A-Za-z0-9_@.\-\u{4e00}-\u{9fff}]{1,48})"\s*:"#).unwrap());
    let mut keys: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let scan_slice = if stripped.len() > 24_000 {
        let mut cut = 24_000;
        while cut > 0 && !stripped.is_char_boundary(cut) {
            cut -= 1;
        }
        &stripped[..cut]
    } else {
        stripped
    };
    for cap in key_re.captures_iter(scan_slice) {
        let k = cap[1].to_string();
        if seen.insert(k.clone()) {
            keys.push(k);
            if keys.len() >= 24 {
                break;
            }
        }
    }
    if keys.is_empty() && stripped.len() < 80 {
        return None;
    }
    let line_cnt = stripped.lines().count();
    let kind_label = if stripped.starts_with('[') {
        "Truncated JSON Array"
    } else {
        "Truncated JSON Object"
    };
    let mut out = vec![format!(
        "{kind_label} ({}B across {line_cnt} lines; keys={}): {}",
        stripped.len(),
        keys.len(),
        if keys.is_empty() {
            "(none)".to_string()
        } else {
            keys.join(", ")
        }
    )];
    static ALERT_RE: OnceLock<Regex> = OnceLock::new();
    let alert_re = ALERT_RE.get_or_init(|| {
        Regex::new(r#""(ok|status|error|errors|workspace_id|action|dedup_risk|verdict)"\s*:\s*("[^"\r\n]{0,120}"|true|false|-?\d+)"#).unwrap()
    });
    let mut alerts: Vec<String> = Vec::new();
    let mut seen_a: HashSet<String> = HashSet::new();
    for cap in alert_re.captures_iter(scan_slice) {
        let pair = format!("{}: {}", &cap[1], &cap[2]);
        if seen_a.insert(pair.clone()) {
            alerts.push(format!("  - {pair}"));
            if alerts.len() >= 8 {
                break;
            }
        }
    }
    if !alerts.is_empty() {
        out.push("Extracted Fields:".to_string());
        out.extend(alerts);
    }
    out.push(format!(
        "Head: {}",
        trunc_chars(stripped, 280).replace('\n', " ")
    ));
    let tail_char_cnt = stripped.chars().count();
    if tail_char_cnt > 320 {
        let tail: String = stripped
            .chars()
            .skip(tail_char_cnt.saturating_sub(200))
            .collect();
        out.push(format!("Tail: ...{}", tail.replace('\n', " ")));
    }
    Some(out.join("\n"))
}

fn parse_line_range(spec: &str) -> Result<(usize, usize), String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err("empty --lines specification".to_string());
    }
    let sep = if trimmed.contains(':') {
        Some(':')
    } else if trimmed.contains('-') {
        Some('-')
    } else {
        None
    };
    if let Some(delim) = sep {
        let parts: Vec<&str> = trimmed.split(delim).collect();
        if parts.len() != 2 {
            return Err(format!(
                "invalid --lines range '{spec}' (expected N, A-B, or A:B)"
            ));
        }
        let start = parts[0]
            .trim()
            .parse::<usize>()
            .map_err(|_| format!("invalid --lines start in '{spec}'"))?;
        if start == 0 {
            return Err(format!("invalid --lines start 0 in '{spec}' (1-based)"));
        }
        let end = if parts[1].trim().is_empty() {
            usize::MAX
        } else {
            let e = parts[1]
                .trim()
                .parse::<usize>()
                .map_err(|_| format!("invalid --lines end in '{spec}'"))?;
            if e < start {
                return Err(format!(
                    "invalid --lines range '{spec}' (end {e} < start {start})"
                ));
            }
            e
        };
        Ok((start, end))
    } else {
        let line = trimmed
            .parse::<usize>()
            .map_err(|_| format!("invalid --lines value '{spec}' (expected N, A-B, or A:B)"))?;
        if line == 0 {
            return Err(format!("invalid --lines value 0 in '{spec}' (1-based)"));
        }
        Ok((line, line))
    }
}

fn slice_chars_window(
    s: &str,
    char_offset: usize,
    max_chars: Option<usize>,
) -> (String, usize, usize, bool) {
    let total = s.chars().count();
    let start = char_offset.min(total);
    let mut end = total;
    let body: String = match max_chars {
        Some(limit) => {
            let mut buf = String::new();
            let mut taken = 0usize;
            for ch in s.chars().skip(start) {
                if taken >= limit {
                    break;
                }
                buf.push(ch);
                taken += 1;
            }
            end = start + taken;
            buf
        }
        None => s.chars().skip(start).collect(),
    };
    let truncated = start > 0 || end < total;
    (body, start, end, truncated)
}

pub fn compress_stream_in(
    store: &Path,
    raw_text: &str,
    label: &str,
    exit_code: i32,
    elapsed_ms: f64,
) -> SieveResult {
    let raw_bytes = raw_text.len();
    let item_id = archive_stream(store, raw_text, label, exit_code, elapsed_ms);

    if raw_bytes <= PASSTHROUGH_BYTES {
        let rendered = format!(
            "{}\n[sieve id={item_id} | exit={exit_code} | {raw_bytes}B passthrough]",
            raw_text.trim_end()
        );
        let digest_bytes = rendered.len();
        return SieveResult {
            id: item_id,
            mode: "passthrough".to_string(),
            exit_code,
            raw_bytes,
            digest_bytes,
            saved_pct: 0.0,
            raw_tokens_est: est_tokens(raw_text),
            digest_tokens_est: est_tokens(&rendered),
            rendered,
        };
    }

    let clean_cow = strip_ansi(raw_text);
    let clean = clean_cow.as_ref();
    let stripped = strip_wrapper_prefix_for_json(clean);
    let (kind, body_summary) = if stripped.starts_with('{') || stripped.starts_with('[') {
        if let Ok(parsed) = serde_json::from_str::<Value>(stripped) {
            ("json".to_string(), summarize_json(&parsed))
        } else if let Some(jl) = try_summarize_jsonl(stripped) {
            ("jsonl".to_string(), jl)
        } else if let Some(pj) = summarize_partial_json(stripped) {
            ("partial-json".to_string(), pj)
        } else {
            ("log".to_string(), summarize_log(clean))
        }
    } else {
        let head_low = trunc_chars(stripped, 400).to_ascii_lowercase();
        if head_low.starts_with("<!doctype html")
            || head_low.contains("<html")
            || head_low.contains("<table")
        {
            ("html".to_string(), summarize_html(clean))
        } else if let Some(diff_s) = try_summarize_diff(clean) {
            ("diff".to_string(), diff_s)
        } else if let Some(comp_s) = try_summarize_compiler(clean) {
            ("compiler".to_string(), comp_s)
        } else if let Some(test_s) = try_summarize_test_output(clean) {
            ("test".to_string(), test_s)
        } else if let Some((tk, ts)) = try_summarize_tabular(clean) {
            (tk, ts)
        } else {
            ("log".to_string(), summarize_log(clean))
        }
    };

    let raw_tok = est_tokens(raw_text);
    let footer = format!(
        "[sieve id={item_id} | kind={kind} | exit={exit_code} | raw={raw_bytes}B (~{raw_tok} tok) | peek: ap sieve peek {item_id} --lines A:B | --grep REGEX]"
    );
    let rendered = format!("{body_summary}\n{footer}");
    let dig_bytes = rendered.len();
    let dig_tok = est_tokens(&rendered);
    let saved_pct =
        ((1.0 - (dig_bytes as f64) / (raw_bytes.max(1) as f64)) * 1000.0).round() / 10.0;

    SieveResult {
        id: item_id,
        mode: kind,
        exit_code,
        raw_bytes,
        digest_bytes: dig_bytes,
        saved_pct,
        raw_tokens_est: raw_tok,
        digest_tokens_est: dig_tok,
        rendered,
    }
}

fn resolve_json_path<'a>(mut cur: &'a Value, path: &str) -> Option<&'a Value> {
    let mut rest = path.trim();
    if let Some(stripped) = rest.strip_prefix('$') {
        rest = stripped;
    }
    rest = rest.trim_start_matches('.');
    if rest.is_empty() {
        return Some(cur);
    }
    let mut tokens: Vec<&str> = Vec::new();
    for seg in rest.split('.').filter(|p| !p.is_empty()) {
        let mut s = seg;
        while let Some(b_start) = s.find('[') {
            let head = &s[..b_start];
            if !head.is_empty() {
                tokens.push(head);
            }
            let after_open = &s[b_start + 1..];
            let b_end = after_open.find(']')?;
            let inner = after_open[..b_end]
                .trim()
                .trim_matches(|c| c == '\'' || c == '"');
            if !inner.is_empty() {
                tokens.push(inner);
            }
            s = &after_open[b_end + 1..];
        }
        if !s.is_empty() {
            tokens.push(s);
        }
    }
    for part in tokens {
        match cur {
            Value::Array(arr) => {
                let idx: usize = part.parse().ok()?;
                cur = arr.get(idx)?;
            }
            Value::Object(map) => {
                cur = map.get(part)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

fn ensure_backfilled(store: &Path) {
    if !store.is_dir() {
        return;
    }
    let db_path = store.join("index.sqlite");
    let dir_mt = store_dir_mtime_nanos(store);
    if db_path.exists() {
        if let Some(mt) = dir_mt {
            if let Ok(guard) = backfilled_cache().lock() {
                if guard.get(store) == Some(&mt) {
                    return;
                }
            }
        }
    }
    let Ok(_lock) = acquire_sieve_lock(store) else {
        return;
    };
    let Ok(rd) = fs::read_dir(store) else { return };
    let mut raw_entries: Vec<(String, PathBuf)> = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("raw") {
            if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                raw_entries.push((stem.to_string(), p));
            }
        }
    }
    if raw_entries.is_empty() && !db_path.exists() {
        return;
    }
    let Ok(conn) = open_sieve_db(&db_path) else {
        return;
    };
    if ensure_chunks_table(&conn).is_err() {
        return;
    }
    let mut existing: HashSet<String> = HashSet::new();
    if let Ok(mut st) = conn.prepare("SELECT id FROM chunks") {
        if let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0)) {
            existing.extend(rows.flatten());
        }
    }
    let missing: Vec<(String, PathBuf)> = raw_entries
        .into_iter()
        .filter(|(stem, _)| !existing.contains(stem))
        .collect();
    if !missing.is_empty() {
        if let Ok(tx) = conn.unchecked_transaction() {
            for (stem, p) in missing {
                let meta_p = p.with_extension("meta.json");
                let lbl = fs::read_to_string(&meta_p)
                    .ok()
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .and_then(|v| v.get("label").and_then(Value::as_str).map(String::from))
                    .unwrap_or_else(|| "stream".to_string());
                if let Ok(bytes) = fs::read(&p) {
                    let raw_text = String::from_utf8_lossy(&bytes);
                    let _ = tx.execute("DELETE FROM chunks WHERE id = ?1", params![&stem]);
                    let _ = tx.execute(
                        "INSERT INTO chunks(id, label, content) VALUES (?1, ?2, ?3)",
                        params![&stem, &lbl, raw_text.as_ref()],
                    );
                }
            }
            let _ = tx.commit();
        }
    }
    if db_path.exists() {
        if let Some(mt) = store_dir_mtime_nanos(store) {
            if let Ok(mut guard) = backfilled_cache().lock() {
                guard.insert(store.to_path_buf(), mt);
            }
        }
    }
}

fn query_fts_once(db_path: &Path, fts_q: &str, limit: usize) -> rusqlite::Result<Vec<SearchHit>> {
    let conn = open_sieve_db(db_path)?;
    let mut st = conn.prepare(
        "SELECT id, label, snippet(chunks, 2, '[', ']', ' ... ', 20) FROM chunks WHERE chunks MATCH ?1 LIMIT ?2",
    )?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut hits = Vec::new();
    let rows = st.query_map(params![fts_q, limit as i64], |r| {
        Ok(SearchHit {
            id: r.get(0)?,
            label: r.get(1)?,
            snippet: r
                .get::<_, String>(2)?
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        })
    })?;
    for h in rows.flatten() {
        if seen.insert(h.id.clone()) {
            hits.push(h);
        }
    }
    Ok(hits)
}

pub fn search_archives(store: &Path, query: &str, limit: usize) -> (Vec<SearchHit>, f64) {
    let t0 = Instant::now();
    ensure_backfilled(store);
    let db_path = store.join("index.sqlite");
    let mut hits = Vec::new();
    let q = query.trim();
    if db_path.exists() && !q.is_empty() {
        let fts_q = q
            .split_whitespace()
            .filter(|t| !t.is_empty())
            .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" ");
        match query_fts_once(&db_path, &fts_q, limit) {
            Ok(h) => hits = h,
            Err(_) => {
                // Retry once serialized behind lock if a concurrent prune rebuild/VACUUM was in flight
                if let Ok(_lock) = acquire_sieve_lock(store) {
                    if let Ok(h) = query_fts_once(&db_path, &fts_q, limit) {
                        hits = h;
                    }
                }
            }
        }
    }
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
    (hits, elapsed_ms)
}

fn normalize_sieve_cli_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut i = 0usize;
    while i < args.len() {
        if i + 2 < args.len()
            && args[i] == "--grep"
            && matches!(args[i + 1].as_str(), "-i" | "--ignore-case")
            && !args[i + 2].starts_with('-')
        {
            out.push(args[i + 1].clone());
            out.push(args[i].clone());
            out.push(args[i + 2].clone());
            i += 3;
            continue;
        }
        out.push(args[i].clone());
        i += 1;
    }
    out
}

pub fn run_cli(args: &[String]) -> i32 {
    let norm_args = normalize_sieve_cli_args(args);
    let cli = match Cli::try_parse_from(&norm_args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match cli.subcmd {
        SubCmd::Run { json: as_json, cmd } => {
            let store = store_dir(&cwd);
            let clean_cmd: Vec<String> = if cmd.first().map(|s| s.as_str()) == Some("--") {
                cmd[1..].to_vec()
            } else {
                cmd
            };
            if clean_cmd.is_empty() {
                emit_err(as_json, "[sieve] usage: ap sieve run -- <command...>");
                return 2;
            }
            let t0 = Instant::now();
            let out = match Command::new(&clean_cmd[0])
                .args(&clean_cmd[1..])
                .current_dir(&cwd)
                .output()
            {
                Ok(o) => o,
                #[cfg(windows)]
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    match Command::new("cmd")
                        .arg("/C")
                        .args(&clean_cmd)
                        .current_dir(&cwd)
                        .output()
                    {
                        Ok(o) => o,
                        Err(e2) => {
                            emit_err(
                                as_json,
                                &format!(
                                    "[sieve] failed to execute `{}`: {e2}",
                                    clean_cmd.join(" ")
                                ),
                            );
                            return 127;
                        }
                    }
                }
                Err(e) => {
                    emit_err(
                        as_json,
                        &format!("[sieve] failed to execute `{}`: {e}", clean_cmd.join(" ")),
                    );
                    return 127;
                }
            };
            let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let mut combined = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr_s = String::from_utf8_lossy(&out.stderr);
            if !stderr_s.is_empty() {
                if !combined.is_empty() && !combined.ends_with('\n') {
                    combined.push('\n');
                }
                combined.push_str(&stderr_s);
            }
            let code = out.status.code().unwrap_or(1);
            let label = clean_cmd
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            let res = compress_stream_in(&store, &combined, &label, code, elapsed_ms);
            if as_json {
                println!("{}", serde_json::to_string_pretty(&res).unwrap_or_default());
            } else {
                println!("{}", res.rendered);
            }
            code
        }
        SubCmd::Pipe {
            label,
            json: as_json,
        } => {
            let store = store_dir(&cwd);
            let mut raw = String::new();
            let _ = std::io::stdin().read_to_string(&mut raw);
            let res = compress_stream_in(&store, &raw, &label, 0, 0.0);
            if as_json {
                println!("{}", serde_json::to_string_pretty(&res).unwrap_or_default());
            } else {
                println!("{}", res.rendered);
            }
            0
        }
        SubCmd::Peek {
            id,
            lines: line_spec,
            grep,
            _ignore_case: _,
            context,
            max_hits,
            json_path,
            max_chars,
            char_offset,
            raw: raw_mode,
            pretty,
        } => {
            let primary = store_dir_readonly(&cwd);
            let mut candidate_dirs = vec![primary.clone()];
            if !has_explicit_sieve_home() {
                if let Some(g) = global_sieve_dir() {
                    if g != primary {
                        candidate_dirs.push(g);
                    }
                }
            }
            let mut match_file: Option<PathBuf> = None;
            'dirs: for dir in &candidate_dirs {
                if let Ok(rd) = fs::read_dir(dir) {
                    for entry in rd.flatten() {
                        let p = entry.path();
                        if p.extension().and_then(|e| e.to_str()) == Some("raw") {
                            if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                                if stem.starts_with(&id) {
                                    match_file = Some(p);
                                    break 'dirs;
                                }
                            }
                        }
                    }
                }
            }
            let Some(raw_path) = match_file else {
                eprintln!(
                    "[sieve] error: unknown archive id '{id}' in {}",
                    primary.display()
                );
                return 1;
            };
            let raw_body =
                String::from_utf8_lossy(&fs::read(&raw_path).unwrap_or_default()).to_string();

            if let Some(jpath) = json_path {
                let parsed_val: Option<Value> = if let Ok(v) =
                    serde_json::from_str::<Value>(strip_wrapper_prefix_for_json(&raw_body))
                {
                    Some(v)
                } else {
                    let raw_lines: Vec<&str> = raw_body.lines().collect();
                    if let Some(ls) = &line_spec {
                        let (start, _) = match parse_line_range(ls) {
                            Ok(r) => r,
                            Err(e) => {
                                eprintln!("[sieve] error: {e}");
                                return 2;
                            }
                        };
                        let idx = start.saturating_sub(1);
                        raw_lines
                            .get(idx)
                            .and_then(|ln| serde_json::from_str::<Value>(ln).ok())
                    } else {
                        let arr: Vec<Value> = raw_lines
                            .iter()
                            .filter(|l| !l.trim().is_empty())
                            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                            .collect();
                        Some(Value::Array(arr))
                    }
                };
                let Some(root_v) = parsed_val else {
                    eprintln!("[sieve] archive '{id}' is not valid JSON/JSONL");
                    return 1;
                };
                let Some(sub) = resolve_json_path(&root_v, &jpath) else {
                    eprintln!("[sieve] json-path '{jpath}' not found in archive '{id}'");
                    return 1;
                };
                let out_json = serde_json::to_string_pretty(sub).unwrap_or_default();
                let limit = max_chars.unwrap_or(8000);
                let (sliced, _, _, _) = slice_chars_window(&out_json, char_offset, Some(limit));
                println!("{sliced}");
                return 0;
            }

            let parsed_range = if let Some(ref ls) = line_spec {
                match parse_line_range(ls) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        eprintln!("[sieve] error: {e}");
                        return 2;
                    }
                }
            } else {
                None
            };

            let maybe_pretty_owned = if pretty && parsed_range.is_none() {
                let candidate = strip_wrapper_prefix_for_json(&raw_body);
                serde_json::from_str::<Value>(candidate)
                    .ok()
                    .and_then(|v| serde_json::to_string_pretty(&v).ok())
            } else {
                None
            };
            let source_text = maybe_pretty_owned.as_deref().unwrap_or(&raw_body);
            let all_lines: Vec<&str> = source_text.lines().collect();

            let (win_start_idx, win_end_excl) = if let Some((s, e)) = parsed_range {
                let s_idx = s.saturating_sub(1).min(all_lines.len());
                let e_excl = e.min(all_lines.len());
                (s_idx, e_excl)
            } else {
                (0usize, all_lines.len())
            };

            let floor_b = |s: &str, mut idx: usize| -> usize {
                idx = idx.min(s.len());
                while idx > 0 && !s.is_char_boundary(idx) {
                    idx -= 1;
                }
                idx
            };
            let ceil_b = |s: &str, mut idx: usize| -> usize {
                idx = idx.min(s.len());
                while idx < s.len() && !s.is_char_boundary(idx) {
                    idx += 1;
                }
                idx
            };

            let mut rendered_lines: Vec<String> = Vec::new();
            let mut pretty_slice_used = false;
            if let Some(pat_str) = grep {
                let pat = match Regex::new(&format!("(?i){pat_str}")) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[sieve] invalid regex '{pat_str}': {e}");
                        return 2;
                    }
                };
                let mut shown: HashSet<usize> = HashSet::new();
                let mut hits = 0usize;
                for i in win_start_idx..win_end_excl {
                    let ln = all_lines[i];
                    if pat.is_match(ln) {
                        hits += 1;
                        let s = i.saturating_sub(context).max(win_start_idx);
                        let e = (i + context + 1).min(win_end_excl);
                        for (j, j_line) in all_lines.iter().enumerate().take(e).skip(s) {
                            if shown.insert(j) {
                                if raw_mode {
                                    rendered_lines.push((*j_line).to_string());
                                } else if j == i && j_line.len() > 600 {
                                    // Single-line minified/JSON archive: emit match-centered windows
                                    // so matches deep in the line are never lost to head truncation.
                                    for m in pat.find_iter(j_line).take(3) {
                                        let ws = floor_b(j_line, m.start().saturating_sub(240));
                                        let we = ceil_b(j_line, m.end().saturating_add(240));
                                        let lead = if ws > 0 { "..." } else { "" };
                                        let trail = if we < j_line.len() { "..." } else { "" };
                                        rendered_lines.push(format!(
                                            ">L{} [@off={}]: {lead}{}{trail}",
                                            j + 1,
                                            m.start(),
                                            &j_line[ws..we]
                                        ));
                                    }
                                } else if j_line.len() > 600 {
                                    let cut = floor_b(j_line, 240);
                                    rendered_lines.push(format!(
                                        " L{}: {}...",
                                        j + 1,
                                        &j_line[..cut]
                                    ));
                                } else {
                                    let marker = if j == i { '>' } else { ' ' };
                                    rendered_lines.push(format!("{marker}L{}: {j_line}", j + 1));
                                }
                            }
                        }
                        if hits >= max_hits {
                            if !raw_mode {
                                rendered_lines.push(format!("... (capped at {max_hits} matches)"));
                            }
                            break;
                        }
                    }
                }
                if hits == 0 {
                    println!(
                        "[sieve] 0 matches for /{pat_str}/ in {} lines.",
                        win_end_excl.saturating_sub(win_start_idx)
                    );
                    return 0;
                }
            } else if parsed_range.is_some() {
                if pretty {
                    let joined = all_lines[win_start_idx..win_end_excl].join("\n");
                    if let Ok(v) =
                        serde_json::from_str::<Value>(strip_wrapper_prefix_for_json(&joined))
                    {
                        if let Ok(pj) = serde_json::to_string_pretty(&v) {
                            pretty_slice_used = true;
                            if raw_mode {
                                rendered_lines.push(pj);
                            } else {
                                for (k, ln) in pj.lines().enumerate() {
                                    rendered_lines.push(format!("L{}: {ln}", k + 1));
                                }
                            }
                        }
                    }
                }
                if !pretty_slice_used {
                    for (idx, line_txt) in all_lines
                        .iter()
                        .enumerate()
                        .take(win_end_excl)
                        .skip(win_start_idx)
                    {
                        if raw_mode {
                            rendered_lines.push((*line_txt).to_string());
                        } else {
                            rendered_lines.push(format!("L{}: {line_txt}", idx + 1));
                        }
                    }
                }
            } else {
                for (idx, &ln) in all_lines.iter().take(40).enumerate() {
                    if raw_mode {
                        rendered_lines.push(ln.to_string());
                    } else {
                        rendered_lines.push(format!("L{}: {ln}", idx + 1));
                    }
                }
            }

            let combined = rendered_lines.join("\n");
            let total_chars = combined.chars().count();
            if char_offset > 0 || max_chars.is_some() {
                let (sliced, start_c, end_c, truncated) =
                    slice_chars_window(&combined, char_offset, max_chars);
                if raw_mode || !truncated {
                    println!("{sliced}");
                } else {
                    println!(
                        "{sliced}\n... [sieve peek chars {start_c}..{end_c} of {total_chars}; pass --char-offset {end_c}]"
                    );
                }
            } else if !combined.is_empty() {
                println!("{combined}");
            }
            0
        }
        SubCmd::Search {
            query,
            limit,
            json: as_json,
        } => {
            let primary = store_dir_readonly(&cwd);
            let (mut hits, mut elapsed_ms) = search_archives(&primary, &query, limit);
            let mut searched = primary.clone();
            if hits.is_empty() && !has_explicit_sieve_home() {
                if let Some(g) = global_sieve_dir() {
                    if g != primary && g.join("index.sqlite").is_file() {
                        let (ghits, gms) = search_archives(&g, &query, limit);
                        if !ghits.is_empty() {
                            hits = ghits;
                            elapsed_ms = gms;
                            searched = g;
                        }
                    }
                }
            }
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "query": query.trim(),
                        "elapsed_ms": elapsed_ms,
                        "hits": hits,
                    }))
                    .unwrap_or_default()
                );
                return 0;
            }
            if hits.is_empty() {
                println!(
                    "[sieve search] 0 matches for {:?} across {} ({elapsed_ms} ms)",
                    query.trim(),
                    searched.display()
                );
                return 0;
            }
            println!(
                "[sieve search] {} archive hit(s) for {:?} in {elapsed_ms} ms:",
                hits.len(),
                query.trim()
            );
            for h in hits {
                println!("  - id={} ({}): {}", h.id, h.label, h.snippet);
            }
            0
        }
        SubCmd::Prune {
            max_mb,
            max_age_hours,
            vacuum,
            json: as_json,
        } => {
            let max_bytes = max_mb.saturating_mul(1024).saturating_mul(1024);
            let mut targets = Vec::new();
            let primary = store_dir_readonly(&cwd);
            let has_explicit_home = std::env::var("SIEVE_HOME")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
            targets.push(primary.clone());
            if !has_explicit_home {
                if let Some(g) = global_sieve_dir() {
                    if g != primary && g.is_dir() {
                        targets.push(g);
                    }
                }
            }
            let mut reports = Vec::new();
            let mut total_removed = 0u64;
            let mut total_freed = 0u64;
            for dir in &targets {
                if dir.is_dir() {
                    let rep = prune_store(dir, max_bytes, max_age_hours, vacuum);
                    total_removed += rep["removed_entries"].as_u64().unwrap_or(0);
                    total_freed += rep["freed_bytes"].as_u64().unwrap_or(0);
                    reports.push(rep);
                }
            }
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "max_mb": max_mb,
                        "max_age_hours": max_age_hours,
                        "vacuum": vacuum,
                        "removed_entries": total_removed,
                        "freed_bytes": total_freed,
                        "stores": reports,
                    }))
                    .unwrap_or_default()
                );
            } else {
                println!(
                    "[sieve prune] removed={total_removed} entries freed={total_freed} B across {} store(s) (max_mb={max_mb}, vacuum={vacuum})",
                    reports.len()
                );
            }
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiler_digest_handles_single_rust_error_and_go_errors() {
        let rust_log = "   Compiling demo v0.1.0\nerror[E0308]: mismatched types\n --> src/main.rs:42:12\n  |\n42|     let x: i32 = \"oops\";\nerror: could not compile `demo` due to 1 previous error\n";
        let rust_digest = try_summarize_compiler(rust_log).expect("expected rust 1-error digest");
        assert!(rust_digest.contains("errors=1"), "{rust_digest}");
        assert!(
            rust_digest.contains("src/main.rs:42:12 | error[E0308]"),
            "{rust_digest}"
        );

        let go_log = "# example.com/pkg\npkg/handler.go:18:9: undefined: missingHelper\npkg/handler.go:24:2: x declared and not used\n";
        let go_digest = try_summarize_compiler(go_log).expect("expected go compiler digest");
        assert!(go_digest.contains("errors=2"), "{go_digest}");
        assert!(
            go_digest.contains("pkg/handler.go:18:9 | error[go]"),
            "{go_digest}"
        );
    }

    #[test]
    fn compresses_giant_single_line_log_fast_and_compact() {
        let tmp = std::env::temp_dir().join(format!("ap_sieve_giant_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let giant_line = format!(
            "INFO boot\nERROR bundle crash: {}\nDONE\n",
            "x".repeat(45 * 1024)
        );
        let res = compress_stream_in(&tmp, &giant_line, "giant-line", 0, 12.0);
        let _ = fs::remove_dir_all(&tmp);
        assert!(
            res.rendered.len() < 4000,
            "compressed output too large: {}",
            res.rendered.len()
        );
        assert!(
            res.rendered.contains("[sieve id="),
            "missing archive header: {}",
            res.rendered
        );
    }

    #[test]
    fn parse_line_range_supports_hyphen_colon_and_rejects_invalid() {
        assert_eq!(parse_line_range("41-150").unwrap(), (41, 150));
        assert_eq!(parse_line_range("41:150").unwrap(), (41, 150));
        assert_eq!(parse_line_range("7").unwrap(), (7, 7));
        assert_eq!(parse_line_range("12:").unwrap(), (12, usize::MAX));
        assert_eq!(parse_line_range("12-").unwrap(), (12, usize::MAX));
        assert!(parse_line_range("0-10").is_err());
        assert!(parse_line_range("50-10").is_err());
        assert!(parse_line_range("abc").is_err());
        assert!(parse_line_range("1:2:3").is_err());
    }

    #[test]
    fn pipe_strips_wrapper_prefix_and_summarizes_truncated_json() {
        let tmp = std::env::temp_dir().join(format!("ap_sieve_pjson_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let wrapped_ok = format!(
            "<console_output>\n{{\"ok\":true,\"items\":[{}]}}\n",
            (0..80)
                .map(|i| format!("{{\"id\":{i},\"name\":\"item_{i}\"}}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let res_ok = compress_stream_in(&tmp, &wrapped_ok, "wrapped-json", 0, 5.0);
        assert_eq!(res_ok.mode, "json", "rendered={}", res_ok.rendered);
        assert!(res_ok.rendered.contains("items"), "{}", res_ok.rendered);

        let partial = format!(
            "==> text 1/1 <==\n{{\n  \"workspace_id\": \"ws_alpha\",\n  \"ok\": true,\n  \"dedup_risk\": \"low\",\n  \"payload\": \"{}\"",
            "z".repeat(1600)
        );
        let res_part = compress_stream_in(&tmp, &partial, "partial-json", 0, 5.0);
        let _ = fs::remove_dir_all(&tmp);
        assert_eq!(
            res_part.mode, "partial-json",
            "rendered={}",
            res_part.rendered
        );
        assert!(
            res_part.rendered.contains("Truncated JSON Object"),
            "{}",
            res_part.rendered
        );
        assert!(
            res_part.rendered.contains("workspace_id"),
            "{}",
            res_part.rendered
        );
        assert!(
            res_part.rendered.contains("dedup_risk"),
            "{}",
            res_part.rendered
        );
    }

    #[test]
    fn prune_store_removes_oversized_and_vacuums_db() {
        let td = std::env::temp_dir().join(format!("ap_sieve_prune_{}", std::process::id()));
        let _ = fs::remove_dir_all(&td);
        fs::create_dir_all(&td).unwrap();

        for idx in 0..5usize {
            let payload = format!("item-{idx}-{}", "A".repeat(4000));
            let _ = compress_stream_in(&td, &payload, &format!("lbl-{idx}"), 0, 2.0);
            std::thread::sleep(Duration::from_millis(8));
        }

        // Retain at most ~9 KiB of raw+meta files and VACUUM SQLite
        let rep = prune_store(&td, 9000, None, true);
        let _ = fs::remove_dir_all(&td);
        assert!(
            rep["removed_entries"].as_u64().unwrap_or(0) >= 2,
            "expected >=2 pruned entries: {rep}"
        );
        assert!(
            rep["remaining_bytes"].as_u64().unwrap_or(u64::MAX) <= 9000,
            "{rep}"
        );
        assert_eq!(rep["vacuumed"], Value::Bool(true), "{rep}");
    }

    #[test]
    fn concurrent_pipe_search_prune_and_dead_pid_lock_have_zero_dups_or_loss() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let td = std::env::temp_dir().join(format!("ap_sieve_c4_{}_{}", std::process::id(), nanos));
        let _ = fs::remove_dir_all(&td);
        fs::create_dir_all(&td).unwrap();

        // 1. Dead-PID stale lock fast reclaim (<4s)
        let dead_child = if cfg!(windows) {
            Command::new("cmd").args(["/C", "exit", "0"]).spawn()
        } else {
            Command::new("sh").args(["-c", "exit 0"]).spawn()
        };
        if let Ok(mut ch) = dead_child {
            let dead_pid = ch.id();
            let _ = ch.wait();
            let lock_p = td.join("index.sqlite.lock");
            fs::write(&lock_p, format!("pid={dead_pid} seq=1 ns=1\n")).unwrap();
            let t0 = Instant::now();
            let _g = acquire_sieve_lock(&td).expect("must reclaim dead-PID sieve lock");
            assert!(
                t0.elapsed() < Duration::from_secs(4),
                "dead-PID lock reclaim too slow: {:?}",
                t0.elapsed()
            );
        }

        // 2. Concurrent archive + search + prune_store under shared lock
        std::thread::scope(|s| {
            for i in 0..8usize {
                let d = td.clone();
                s.spawn(move || {
                    let body = format!("C4_CONC_TOKEN_{i} {}", "payload line\n".repeat(120));
                    let _ = compress_stream_in(&d, &body, &format!("w{i}"), 0, 1.0);
                });
            }
            for _ in 0..4usize {
                let d = td.clone();
                s.spawn(move || {
                    let _ = search_archives(&d, "C4_CONC_TOKEN", 20);
                });
            }
            for _ in 0..2usize {
                let d = td.clone();
                s.spawn(move || {
                    let _ = prune_store(&d, 4 * 1024 * 1024, None, true);
                });
            }
        });

        // Verify 100% parity between surviving .raw files and FTS5 rows (0 duplicates, 0 lost)
        let mut raw_ids: Vec<String> = fs::read_dir(&td)
            .unwrap()
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                (p.extension().and_then(|s| s.to_str()) == Some("raw"))
                    .then(|| p.file_stem().and_then(|s| s.to_str()).map(String::from))
                    .flatten()
            })
            .collect();
        raw_ids.sort();
        assert_eq!(raw_ids.len(), 8, "expected all 8 raw files: {raw_ids:?}");

        let conn = open_sieve_db(&td.join("index.sqlite")).unwrap();
        let mut st = conn.prepare("SELECT id FROM chunks").unwrap();
        let mut fts_ids: Vec<String> = st
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .flatten()
            .collect();
        fts_ids.sort();
        drop(st);
        drop(conn);
        let _ = fs::remove_dir_all(&td);
        assert_eq!(
            fts_ids, raw_ids,
            "FTS5 chunks must match .raw files 1:1 with zero duplicates and zero loss"
        );
    }

    #[test]
    fn cycle6_json_path_brackets_and_auto_compact_helper() {
        let doc = json!({
            "items": [
                {"service": "svc_alpha", "meta": {"ok": true}},
                {"service": "svc_beta", "meta": {"ok": false}}
            ]
        });
        assert_eq!(
            resolve_json_path(&doc, "$.items[0].service").and_then(Value::as_str),
            Some("svc_alpha")
        );
        assert_eq!(
            resolve_json_path(&doc, "items[1]['service']").and_then(Value::as_str),
            Some("svc_beta")
        );
        assert_eq!(
            resolve_json_path(&doc, "items.0.meta.ok").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(resolve_json_path(&doc, "$"), Some(&doc));
        assert!(resolve_json_path(&doc, "items[unclosed").is_none());

        let td = std::env::temp_dir().join(format!("ap_sieve_c6_vac_{}", std::process::id()));
        let _ = fs::remove_dir_all(&td);
        fs::create_dir_all(&td).unwrap();
        let mut ids = Vec::new();
        for i in 0..8usize {
            let body = format!("row-{i}-{}", "X".repeat(6000));
            let res = compress_stream_in(&td, &body, &format!("v{i}"), 0, 1.0);
            ids.push(res.id);
        }
        let db_p = td.join("index.sqlite");
        let conn = open_sieve_db(&db_p).unwrap();
        delete_chunk_ids(&conn, &ids);
        let before_sz = fs::metadata(&db_p).unwrap().len();
        assert!(
            maybe_compact_sieve_db(&conn, before_sz, 1024, 1024),
            "expected compaction when db exceeds min_db_bytes and 2x raw bytes"
        );
        drop(conn);
        let after_sz = fs::metadata(&db_p).unwrap().len();
        let _ = fs::remove_dir_all(&td);
        assert!(
            after_sz < before_sz,
            "expected VACUUM to shrink db: before={before_sz}, after={after_sz}"
        );
    }
}
