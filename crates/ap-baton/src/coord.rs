use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceClaim {
    pub resource: String,
    pub owner: String,
    pub note: String,
    pub acquired_at: u64,
    pub expires_at: u64,
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn claims_store_dir() -> PathBuf {
    if let Ok(ah) = std::env::var("AP_HOME") {
        if !ah.trim().is_empty() {
            return PathBuf::from(ah);
        }
    }
    if let Ok(bh) = std::env::var("BATON_HOME") {
        if !bh.trim().is_empty() {
            return PathBuf::from(bh);
        }
    }
    std::env::temp_dir().join("ap_baton_claims")
}

struct FileGuard(PathBuf);
impl Drop for FileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn acquire_lock(dir: &Path) -> Result<FileGuard, String> {
    let _ = fs::create_dir_all(dir);
    let lock_p = dir.join("claims.lock");
    let deadline = Instant::now() + Duration::from_millis(4000);
    let pid = std::process::id();
    let mut attempt = 0u64;
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_p)
        {
            Ok(mut f) => {
                use std::io::Write;
                let _ = writeln!(f, "pid={pid}");
                return Ok(FileGuard(lock_p));
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::AlreadyExists
                    || (cfg!(windows)
                        && (e.kind() == std::io::ErrorKind::PermissionDenied
                            || matches!(e.raw_os_error(), Some(5) | Some(32)))) =>
            {
                // Reap stale lock older than 15s
                if let Ok(md) = fs::metadata(&lock_p) {
                    if let Ok(mt) = md.modified() {
                        if SystemTime::now()
                            .duration_since(mt)
                            .map(|d| d.as_secs() > 15)
                            .unwrap_or(false)
                        {
                            let _ = fs::remove_file(&lock_p);
                            continue;
                        }
                    }
                }
                if Instant::now() >= deadline {
                    return Err(format!("timed out acquiring baton claims lock: {e}"));
                }
                attempt += 1;
                let jitter = ((pid as u64).wrapping_mul(37) + attempt * 11) % 19;
                thread::sleep(Duration::from_millis(8 + jitter));
            }
            Err(e) => return Err(format!("failed acquiring baton claims lock: {e}")),
        }
    }
}

fn load_claims(dir: &Path) -> BTreeMap<String, ResourceClaim> {
    let p = dir.join("claims.json");
    for attempt in 0..5u64 {
        if let Ok(raw) = fs::read_to_string(&p) {
            if let Ok(parsed) = serde_json::from_str::<BTreeMap<String, ResourceClaim>>(&raw) {
                return parsed;
            }
        }
        if !p.exists() {
            return BTreeMap::new();
        }
        if attempt < 4 {
            thread::sleep(Duration::from_millis(6 + attempt * 4));
        }
    }
    BTreeMap::new()
}

fn save_claims(dir: &Path, map: &BTreeMap<String, ResourceClaim>) -> Result<(), String> {
    let body = serde_json::to_string_pretty(map).map_err(|e| e.to_string())?;
    crate::frontier::atomic_write_text(&dir.join("claims.json"), &body)
}

/// Atomically claim a shared multi-agent resource with TTL expiry (exit 2 if held by another owner).
pub fn run_claim(resource: &str, owner: &str, ttl_secs: u64, note: &str, as_json: bool) -> i32 {
    let dir = claims_store_dir();
    let Ok(_guard) = acquire_lock(&dir) else {
        eprintln!("[baton claim] Could not acquire atomic claims lock");
        return 1;
    };
    let now = now_unix_secs();
    let ttl = ttl_secs.clamp(5, 86_400);
    let mut map = load_claims(&dir);
    if let Some(existing) = map.get(resource) {
        if existing.expires_at > now && !existing.owner.eq_ignore_ascii_case(owner) {
            let rem = existing.expires_at.saturating_sub(now);
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "status": "held",
                        "resource": resource,
                        "held_by": existing.owner,
                        "remaining_secs": rem,
                        "note": existing.note,
                    }))
                    .unwrap_or_default()
                );
            } else {
                eprintln!(
                    "[CLAIM HELD | exit 2] `{resource}` is actively claimed by `{}` ({rem}s remaining; note: {})",
                    existing.owner, existing.note
                );
            }
            return 2;
        }
    }
    let claim = ResourceClaim {
        resource: resource.to_string(),
        owner: owner.to_string(),
        note: note.to_string(),
        acquired_at: now,
        expires_at: now + ttl,
    };
    map.insert(resource.to_string(), claim.clone());
    if let Err(e) = save_claims(&dir, &map) {
        eprintln!("[baton claim] save failed: {e}");
        return 1;
    }
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "status": "acquired",
                "claim": claim,
            }))
            .unwrap_or_default()
        );
    } else {
        println!("[baton claim] ACQUIRED `{resource}` for `{owner}` (ttl={ttl}s)");
    }
    0
}

pub fn run_release(resource: &str, owner: Option<&str>, force: bool, as_json: bool) -> i32 {
    let dir = claims_store_dir();
    let Ok(_guard) = acquire_lock(&dir) else {
        eprintln!("[baton release] Could not acquire atomic claims lock");
        return 1;
    };
    let now = now_unix_secs();
    let mut map = load_claims(&dir);
    if let Some(existing) = map.get(resource) {
        if !force
            && existing.expires_at > now
            && owner
                .map(|o| !o.eq_ignore_ascii_case(&existing.owner))
                .unwrap_or(false)
        {
            eprintln!(
                "[CLAIM OWNED BY OTHER | exit 2] `{resource}` is held by `{}` (pass `--force` to override)",
                existing.owner
            );
            return 2;
        }
    }
    let existed = map.remove(resource).is_some();
    let _ = save_claims(&dir, &map);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "resource": resource,
                "released": existed,
            }))
            .unwrap_or_default()
        );
    } else if existed {
        println!("[baton release] RELEASED `{resource}`");
    } else {
        println!("[baton release] `{resource}` was not claimed");
    }
    0
}

pub fn run_claims_list(as_json: bool) -> i32 {
    let dir = claims_store_dir();
    let now = now_unix_secs();
    let map = load_claims(&dir);
    let rows: Vec<serde_json::Value> = map
        .values()
        .map(|c| {
            let active = c.expires_at > now;
            let rem = c.expires_at.saturating_sub(now);
            json!({
                "resource": c.resource,
                "owner": c.owner,
                "note": c.note,
                "active": active,
                "remaining_secs": rem,
            })
        })
        .collect();
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "count": rows.len(),
                "claims": rows,
            }))
            .unwrap_or_default()
        );
    } else if rows.is_empty() {
        println!("[baton claims] No resource claims recorded.");
    } else {
        println!("[baton claims] {} claim(s):", rows.len());
        for c in map.values() {
            let rem = c.expires_at.saturating_sub(now);
            let st = if c.expires_at > now {
                format!("ACTIVE ({rem}s left)")
            } else {
                "EXPIRED".to_string()
            };
            println!(
                "  - `{}` owner=`{}` [{}] {}",
                c.resource, c.owner, st, c.note
            );
        }
    }
    0
}

fn is_cjk(c: char) -> bool {
    matches!(c as u32, 0x4E00..=0x9FFF | 0x3400..=0x4DBF | 0xF900..=0xFAFF)
}

/// Tokenize mixed English camelCase/snake_case identifiers + CJK bigrams for high-recall semantic dedup.
fn tokenize_hybrid(text: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let mut ascii_buf = String::new();
    let mut cjk_run: Vec<char> = Vec::new();

    let flush_ascii = |buf: &mut String, out: &mut Vec<String>| {
        if buf.len() >= 2 {
            let full = buf.to_ascii_lowercase();
            out.push(full.clone());
            // Split camelCase
            let mut sub = String::new();
            for ch in buf.chars() {
                if ch.is_uppercase() && !sub.is_empty() {
                    if sub.len() >= 2 {
                        out.push(sub.to_ascii_lowercase());
                    }
                    sub.clear();
                }
                sub.push(ch);
            }
            if sub.len() >= 2 {
                let low = sub.to_ascii_lowercase();
                if low != full {
                    out.push(low);
                }
            }
        }
        buf.clear();
    };

    let flush_cjk = |run: &mut Vec<char>, out: &mut Vec<String>| {
        if run.len() == 1 {
            out.push(run[0].to_string());
        } else if run.len() >= 2 {
            for w in run.windows(2) {
                out.push(format!("{}{}", w[0], w[1]));
            }
        }
        run.clear();
    };

    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            flush_cjk(&mut cjk_run, &mut toks);
            ascii_buf.push(ch);
        } else if is_cjk(ch) {
            flush_ascii(&mut ascii_buf, &mut toks);
            cjk_run.push(ch);
        } else {
            flush_ascii(&mut ascii_buf, &mut toks);
            flush_cjk(&mut cjk_run, &mut toks);
        }
    }
    flush_ascii(&mut ascii_buf, &mut toks);
    flush_cjk(&mut cjk_run, &mut toks);
    toks
}

struct DedupDoc {
    source: String,
    line: usize,
    text: String,
    tokens: HashSet<String>,
}

fn collect_entries_from_file(p: &Path, docs: &mut Vec<DedupDoc>) {
    let Ok(raw) = fs::read_to_string(p) else {
        return;
    };
    let src = p.to_string_lossy().replace('\\', "/");
    let ext = p
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if ext == "json" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            let items: Vec<&serde_json::Value> = if let Some(arr) = v.as_array() {
                arr.iter().collect()
            } else if let Some(arr) = v
                .get("records")
                .or_else(|| v.get("items"))
                .or_else(|| v.get("entries"))
                .and_then(|x| x.as_array())
            {
                arr.iter().collect()
            } else {
                vec![&v]
            };
            for (idx, it) in items.iter().enumerate() {
                let s = it.to_string();
                let toks: HashSet<String> = tokenize_hybrid(&s).into_iter().collect();
                if !toks.is_empty() {
                    docs.push(DedupDoc {
                        source: src.clone(),
                        line: idx + 1,
                        text: s.chars().take(240).collect(),
                        tokens: toks,
                    });
                }
            }
            return;
        }
    }

    for (idx, raw_ln) in raw.lines().enumerate() {
        let t = raw_ln.trim();
        if t.len() < 4 || t.starts_with("---") || t.starts_with("```") {
            continue;
        }
        let toks: HashSet<String> = tokenize_hybrid(t).into_iter().collect();
        if toks.is_empty() {
            continue;
        }
        docs.push(DedupDoc {
            source: src.clone(),
            line: idx + 1,
            text: t.chars().take(240).collect(),
            tokens: toks,
        });
    }
}

/// Sub-15ms hybrid BM25 + CJK bigram semantic near-duplicate finder across ledgers, markdown lists & JSON indexes.
pub fn run_dedup(query: &str, files: &[PathBuf], top_k: usize, as_json: bool) -> i32 {
    let t0 = Instant::now();
    let q_toks: HashSet<String> = tokenize_hybrid(query).into_iter().collect();
    if q_toks.is_empty() {
        eprintln!("[baton dedup] Empty query");
        return 2;
    }
    let mut docs = Vec::new();
    for f in files {
        if f.is_file() {
            collect_entries_from_file(f, &mut docs);
        }
    }
    let n_docs = docs.len().max(1) as f64;
    let mut df: HashMap<String, usize> = HashMap::new();
    for d in &docs {
        for tk in &d.tokens {
            if q_toks.contains(tk) {
                *df.entry(tk.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut scored: Vec<(f64, Vec<String>, &DedupDoc)> = Vec::new();
    for d in &docs {
        let mut score = 0.0f64;
        let mut matched = Vec::new();
        for qt in &q_toks {
            if d.tokens.contains(qt) {
                let f_df = *df.get(qt).unwrap_or(&1) as f64;
                let idf = ((n_docs - f_df + 0.5) / (f_df + 0.5) + 1.0).ln().max(0.2);
                score += idf;
                matched.push(qt.clone());
            }
        }
        if score > 0.0 {
            let norm = (d.tokens.len() as f64).sqrt().max(2.0);
            let final_score = score / norm;
            matched.sort();
            scored.push((final_score, matched, d));
        }
    }
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(top_k.clamp(1, 30));

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
    if as_json {
        let hits: Vec<serde_json::Value> = scored
            .iter()
            .map(|(sc, m, d)| {
                json!({
                    "score": (*sc * 1000.0).round() / 1000.0,
                    "source": d.source,
                    "line": d.line,
                    "overlap": m,
                    "text": d.text,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "query": query,
                "scanned_entries": docs.len(),
                "elapsed_ms": elapsed_ms,
                "matches": hits,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[baton dedup] Top {} near-duplicate(s) across {} entries in {}ms:",
            scored.len(),
            docs.len(),
            elapsed_ms
        );
        for (i, (sc, m, d)) in scored.iter().enumerate() {
            println!(
                "  {}. [{:.2}] {}:L{} (overlap: {}) — {}",
                i + 1,
                sc,
                d.source,
                d.line,
                m.iter().take(6).cloned().collect::<Vec<_>>().join(", "),
                d.text
            );
        }
    }
    0
}
