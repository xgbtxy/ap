use crate::audit::default_home_dir;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
pub(crate) static AP_HOME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) struct ApHomeTestGuard {
    _guard: std::sync::MutexGuard<'static, ()>,
    prev: Option<std::ffi::OsString>,
}

#[cfg(test)]
impl ApHomeTestGuard {
    pub(crate) fn set(path: &std::path::Path) -> Self {
        let guard = AP_HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("AP_HOME");
        std::env::set_var("AP_HOME", path);
        Self {
            _guard: guard,
            prev,
        }
    }
}

#[cfg(test)]
impl Drop for ApHomeTestGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var("AP_HOME", v),
            None => std::env::remove_var("AP_HOME"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatEvent {
    pub ts: u64,
    pub kind: String,
    pub raw_bytes: u64,
    pub out_bytes: u64,
    pub win_heals: u32,
    pub guards: u32,
    #[serde(default)]
    pub note: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "stats",
    about = "Show local token savings, log compression & Windows execution crashes prevented"
)]
struct StatsCli {
    /// Emit machine-readable JSON summary
    #[arg(long)]
    json: bool,
    /// Reset local stats ledger
    #[arg(long)]
    reset: bool,
    /// Only include events from the last N hours (e.g. `--since-hours 24`)
    #[arg(long)]
    since_hours: Option<u64>,
    /// Override home directory
    #[arg(long)]
    home: Option<String>,
}

pub fn stats_file_path(home_override: Option<&str>) -> PathBuf {
    if let Some(h) = home_override.filter(|s| !s.trim().is_empty()) {
        return PathBuf::from(h)
            .join(".agent-primitives")
            .join("stats.jsonl");
    }
    if let Ok(ap_home) = std::env::var("AP_HOME") {
        if !ap_home.trim().is_empty() {
            return PathBuf::from(ap_home).join("stats.jsonl");
        }
    }
    default_home_dir()
        .join(".agent-primitives")
        .join("stats.jsonl")
}

pub fn record_event(
    kind: &str,
    raw_bytes: u64,
    out_bytes: u64,
    win_heals: u32,
    guards: u32,
    note: &str,
) {
    let path = stats_file_path(None);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ev = StatEvent {
        ts,
        kind: kind.to_string(),
        raw_bytes,
        out_bytes,
        win_heals,
        guards,
        note: note.to_string(),
    };
    if let Ok(line) = serde_json::to_string(&ev) {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match StatsCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    let path = stats_file_path(cli.home.as_deref());
    if cli.reset {
        let _ = fs::remove_file(&path);
        if cli.json {
            println!("{}", json!({"ok": true, "reset": true}));
        } else {
            println!("[ap stats] Local token & execution ledger reset.");
        }
        return 0;
    }

    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cutoff = cli
        .since_hours
        .map(|h| now_s.saturating_sub(h.saturating_mul(3600)));

    let mut events: Vec<StatEvent> = Vec::new();
    if let Ok(txt) = fs::read_to_string(&path) {
        for ln in txt.lines() {
            if let Ok(ev) = serde_json::from_str::<StatEvent>(ln) {
                if cutoff.map(|c| ev.ts >= c).unwrap_or(true) {
                    events.push(ev);
                }
            }
        }
    }

    let total_calls = events.len() as u64;
    let total_raw: u64 = events.iter().map(|e| e.raw_bytes).sum();
    let total_out: u64 = events.iter().map(|e| e.out_bytes).sum();
    let total_win_heals: u64 = events.iter().map(|e| e.win_heals as u64).sum();
    let total_guards: u64 = events.iter().map(|e| e.guards as u64).sum();
    let mut by_kind: BTreeMap<String, u64> = BTreeMap::new();
    for ev in &events {
        *by_kind.entry(ev.kind.clone()).or_insert(0) += 1;
    }
    let saved_bytes = total_raw.saturating_sub(total_out);
    let direct_tokens_saved = saved_bytes / 4;
    let retry_tokens_avoided = total_win_heals * 3_500;
    let net_tokens_saved = direct_tokens_saved + retry_tokens_avoided;
    let compression_pct = if total_raw > 0 {
        ((saved_bytes as f64 / total_raw as f64) * 1000.0).round() / 10.0
    } else {
        0.0
    };

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "total_calls": total_calls,
                "raw_bytes": total_raw,
                "emitted_bytes": total_out,
                "compression_pct": compression_pct,
                "windows_heals": total_win_heals,
                "quality_gates": total_guards,
                "direct_tokens_saved": direct_tokens_saved,
                "retry_tokens_avoided": retry_tokens_avoided,
                "estimated_total_tokens_saved": net_tokens_saved,
                "by_kind": by_kind,
            }))
            .unwrap_or_default()
        );
        return 0;
    }

    println!("[ap stats] Coding-Agent Efficiency & Thinking-Flow Ledger (100% offline)");
    println!("------------------------------------------------------------------------");
    if total_calls == 0 {
        println!("  No recorded runs yet. Use your coding agent normally (after `ap init`),");
        println!("  then run `ap stats` anytime to see prevented derailments & speedups!");
        return 0;
    }
    println!("  Accelerated Agent Steps      : {total_calls} actions");
    println!(
        "  Thinking Derailments Healed  : {total_win_heals} Windows/shell crashes prevented before retry loops"
    );
    println!(
        "  1-Shot Edits & Browser Gates : {total_guards} verified (Tree-sitter AST + Headless Edge/Chrome + 0-slop)"
    );
    println!(
        "  Working-Memory Noise Filtered: {:.1} KB -> {:.1} KB (-{compression_pct:.1}% log/context clutter)",
        total_raw as f64 / 1024.0,
        total_out as f64 / 1024.0
    );
    println!(
        "  Byproduct Token Savings      : ~{net_tokens_saved} wasted tokens avoided (~{direct_tokens_saved} diet + ~{retry_tokens_avoided} retry)"
    );
    if !by_kind.is_empty() {
        let mut ranked: Vec<(&String, &u64)> = by_kind.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        let summary = ranked
            .into_iter()
            .take(6)
            .map(|(k, c)| format!("{k}={c}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  Top Primitives Breakdown     : {summary}");
    }
    0
}
