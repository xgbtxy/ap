use crate::surface::guard_re;
use crate::trace::{
    classify_hop_guard, clean_fn_name, collect_project_fns, lookup_call_taint, FnDef, NOTABLE_SINKS,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantFinding {
    pub function: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub sink: String,
    pub sink_line: usize,
    pub guard_placement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub guard_note: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arg_taint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arg_preview: String,
    pub is_outlier: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantsReport {
    pub root: String,
    pub elapsed_ms: f64,
    pub scanned_functions: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_symbol: Option<String>,
    pub target_sinks: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_guard: Option<String>,
    pub total_siblings: usize,
    pub guarded_before_count: usize,
    pub guard_after_count: usize,
    pub unguarded_count: usize,
    pub guard_ratio_pct: u32,
    pub siblings: Vec<VariantFinding>,
}

fn extra_guard_placement(
    f: &FnDef,
    root: &Path,
    sink_line: usize,
    custom_guard: Option<&Regex>,
) -> (String, String) {
    let (base_cls, base_note) = classify_hop_guard(f, sink_line);
    if base_cls == "GUARD_BEFORE" {
        return (base_cls, base_note);
    }
    let Some(re) = custom_guard else {
        return (base_cls, base_note);
    };
    let Ok(src) = fs::read_to_string(root.join(&f.file)) else {
        return (base_cls, base_note);
    };
    let lines: Vec<&str> = src.lines().collect();
    let scan_start = if f.end_line > f.start_line {
        f.start_line + 1
    } else {
        f.start_line
    };
    for ln in (scan_start..sink_line).rev() {
        if let Some(txt) = lines.get(ln.saturating_sub(1)) {
            let trimmed = txt.trim();
            if !trimmed.is_empty() && re.is_match(trimmed) {
                return (
                    "GUARD_BEFORE".to_string(),
                    format!("L{ln}: {}", trimmed.chars().take(90).collect::<String>()),
                );
            }
        }
    }
    if base_cls == "GUARD_AFTER" {
        return (base_cls, base_note);
    }
    for ln in (sink_line + 1)..=f.end_line {
        if let Some(txt) = lines.get(ln.saturating_sub(1)) {
            let trimmed = txt.trim();
            if !trimmed.is_empty() && re.is_match(trimmed) {
                return (
                    "GUARD_AFTER".to_string(),
                    format!("L{ln}: {}", trimmed.chars().take(90).collect::<String>()),
                );
            }
        }
    }
    ("UNGUARDED".to_string(), String::new())
}

fn infer_seed_sinks(all_fns: &[FnDef], seed: &str) -> Vec<String> {
    let clean = clean_fn_name(seed);
    let mut notable = Vec::new();
    let mut other = Vec::new();
    let mut seen = HashSet::new();
    for f in all_fns.iter().filter(|f| f.name == clean) {
        for (ident, _) in &f.called_idents {
            let id = ident.as_str();
            if id == clean || guard_re().is_match(id) || !seen.insert(id.to_string()) {
                continue;
            }
            if NOTABLE_SINKS.contains(&id) {
                notable.push(id.to_string());
            } else if !matches!(
                id,
                "return" | "const" | "let" | "var" | "await" | "async" | "true" | "false" | "null"
            ) {
                other.push(id.to_string());
            }
        }
    }
    if !notable.is_empty() {
        notable
    } else {
        other.into_iter().take(6).collect()
    }
}

/// AST structural sibling & guard-asymmetry sweeper across Py/TS/JS/Go/Rust/C/C++.
/// Finds all sibling functions invoking matching sink(s), classifies `GUARD_BEFORE` / `GUARD_AFTER` /
/// `UNGUARDED`, computes sibling guard-asymmetry ratio, and ranks unguarded outliers first.
pub fn analyze_variants(
    root: &Path,
    sink_query: Option<&str>,
    seed_symbol: Option<&str>,
    guard_pattern: Option<&str>,
) -> VariantsReport {
    analyze_variants_with_opts(root, sink_query, seed_symbol, guard_pattern, false)
}

pub fn analyze_variants_with_opts(
    root: &Path,
    sink_query: Option<&str>,
    seed_symbol: Option<&str>,
    guard_pattern: Option<&str>,
    tainted_only: bool,
) -> VariantsReport {
    let t0 = Instant::now();
    let all_fns = collect_project_fns(root);

    let custom_re = guard_pattern
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|pat| Regex::new(pat).ok());

    let sink_clean = sink_query.map(str::trim).filter(|s| !s.is_empty());
    let seed_clean = seed_symbol.map(str::trim).filter(|s| !s.is_empty());

    let mut target_sinks: Vec<String> = Vec::new();
    let sink_re = if let Some(sq) = sink_clean {
        target_sinks.push(sq.to_string());
        Regex::new(&format!("(?i){}", regex::escape(sq)))
            .ok()
            .filter(|_| !sq.contains('|') && !sq.contains(".*") && !sq.contains('['))
            .or_else(|| Regex::new(sq).ok())
    } else if let Some(seed) = seed_clean {
        target_sinks = infer_seed_sinks(&all_fns, seed);
        if target_sinks.is_empty() {
            None
        } else {
            let pat = format!(
                "^(?:{})$",
                target_sinks
                    .iter()
                    .map(|s| regex::escape(s))
                    .collect::<Vec<_>>()
                    .join("|")
            );
            Regex::new(&pat).ok()
        }
    } else {
        target_sinks = NOTABLE_SINKS.iter().map(|s| (*s).to_string()).collect();
        None
    };

    let mut raw_hits: Vec<VariantFinding> = Vec::new();
    let mut seen_fn_sink: HashSet<(String, String, usize)> = HashSet::new();

    for f in &all_fns {
        for (ident, ln) in &f.called_idents {
            if ident == &f.name {
                continue;
            }
            let matched = if let Some(ref re) = sink_re {
                re.is_match(ident)
            } else if sink_clean.is_some() || seed_clean.is_some() {
                false
            } else {
                NOTABLE_SINKS.contains(&ident.as_str())
            };
            if !matched {
                continue;
            }
            if !seen_fn_sink.insert((f.file.clone(), f.name.clone(), *ln)) {
                continue;
            }
            let (guard_placement, guard_note) =
                extra_guard_placement(f, root, *ln, custom_re.as_ref());
            let (arg_taint, arg_preview) = lookup_call_taint(f, ident, *ln);
            if tainted_only && arg_taint == "CONST_LITERAL" {
                continue;
            }
            raw_hits.push(VariantFinding {
                function: f.name.clone(),
                file: f.file.clone(),
                start_line: f.start_line,
                end_line: f.end_line,
                sink: ident.clone(),
                sink_line: *ln,
                guard_placement,
                guard_note,
                arg_taint,
                arg_preview,
                is_outlier: false,
            });
        }
    }

    let total_siblings = raw_hits.len();
    let guarded_before_count = raw_hits
        .iter()
        .filter(|v| v.guard_placement == "GUARD_BEFORE")
        .count();
    let guard_after_count = raw_hits
        .iter()
        .filter(|v| v.guard_placement == "GUARD_AFTER")
        .count();
    let unguarded_count = raw_hits
        .iter()
        .filter(|v| v.guard_placement == "UNGUARDED")
        .count();
    let guard_ratio_pct = (guarded_before_count * 100)
        .checked_div(total_siblings)
        .unwrap_or(0) as u32;

    // Flag unguarded/post-guarded siblings as outliers when >=1 sibling is guarded AND call arg is NOT constant literal
    let has_guarded_peers = guarded_before_count > 0;
    for v in &mut raw_hits {
        v.is_outlier = has_guarded_peers
            && v.guard_placement != "GUARD_BEFORE"
            && v.arg_taint != "CONST_LITERAL";
    }

    raw_hits.sort_by(|a, b| {
        let rank = |g: &str| match g {
            "UNGUARDED" => 0u8,
            "GUARD_AFTER" => 1u8,
            _ => 2u8,
        };
        let taint_rank = |t: &str| match t {
            "PARAM_TAINTED" => 0u8,
            "VAR_DYNAMIC" => 1u8,
            "CONST_LITERAL" => 3u8,
            _ => 2u8,
        };
        rank(&a.guard_placement)
            .cmp(&rank(&b.guard_placement))
            .then_with(|| taint_rank(&a.arg_taint).cmp(&taint_rank(&b.arg_taint)))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.sink_line.cmp(&b.sink_line))
    });
    raw_hits.truncate(48);

    VariantsReport {
        root: root.display().to_string(),
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
        scanned_functions: all_fns.len(),
        seed_symbol: seed_clean.map(str::to_string),
        target_sinks,
        custom_guard: guard_pattern
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        total_siblings,
        guarded_before_count,
        guard_after_count,
        unguarded_count,
        guard_ratio_pct,
        siblings: raw_hits,
    }
}

pub fn render_variants_md(rep: &VariantsReport) -> String {
    let mut out = vec![format!(
        "# ATLAS VARIANTS ({} sibling(s), guard_ratio={}%, {} unguarded / {} guard_after / {} guard_before in {}ms)",
        rep.total_siblings,
        rep.guard_ratio_pct,
        rep.unguarded_count,
        rep.guard_after_count,
        rep.guarded_before_count,
        rep.elapsed_ms
    )];
    if let Some(ref seed) = rep.seed_symbol {
        out.push(format!(
            "Seed: `{seed}` -> sinks: [{}]",
            rep.target_sinks.join(", ")
        ));
    } else {
        out.push(format!("Sinks: [{}]", rep.target_sinks.join(", ")));
    }
    if rep.siblings.is_empty() {
        out.push("*(no matching sibling calls found)*".to_string());
    } else {
        for v in &rep.siblings {
            let tag = if v.is_outlier {
                "[OUTLIER]"
            } else if v.guard_placement == "GUARD_BEFORE" {
                "[GUARDED]"
            } else {
                "[UNGUARDED]"
            };
            let note = if v.guard_note.is_empty() {
                String::new()
            } else {
                format!(" (`{}`)", v.guard_note)
            };
            let taint_tag = if v.arg_taint.is_empty() {
                String::new()
            } else {
                format!(" [{}]", v.arg_taint)
            };
            out.push(format!(
                "  - {tag}{} {} `{}` (`{}:L{}-L{}`) calls `{}`@L{}{}",
                taint_tag,
                v.guard_placement,
                v.function,
                v.file,
                v.start_line,
                v.end_line,
                v.sink,
                v.sink_line,
                note
            ));
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweeps_siblings_and_flags_unguarded_guard_asymmetry_outliers() {
        let dir = std::env::temp_dir().join(format!("ap_variants_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("handlers.ts"),
            "export function deleteUserSafe(req: any) {\n\
               if (!requireAdmin(req.user)) return 403;\n\
               return db.execute('DELETE FROM users WHERE id = ?', [req.id]);\n\
             }\n\
             export function updateUserSafe(req: any) {\n\
               if (!authorize(req.user)) return 403;\n\
               return db.execute('UPDATE users SET name = ? WHERE id = ?', [req.name, req.id]);\n\
             }\n\
             export function resetUserBuggy(req: any) {\n\
               return db.execute('UPDATE users SET role = ? WHERE id = ?', [req.role, req.id]);\n\
             }\n\
             export function healthCheckConst() {\n\
               const sql = 'SELECT 1';\n\
               return db.execute(sql);\n\
             }\n",
        )
        .unwrap();

        let rep = analyze_variants(&dir, Some("execute"), None, Some(r"requireAdmin"));
        assert_eq!(rep.total_siblings, 4);
        assert_eq!(rep.guarded_before_count, 2);
        assert_eq!(rep.unguarded_count, 2);
        assert_eq!(rep.siblings[0].function, "resetUserBuggy");
        assert_eq!(rep.siblings[0].guard_placement, "UNGUARDED");
        assert_eq!(rep.siblings[0].arg_taint, "PARAM_TAINTED");
        assert!(rep.siblings[0].is_outlier);
        let const_hit = rep
            .siblings
            .iter()
            .find(|s| s.function == "healthCheckConst")
            .unwrap();
        assert_eq!(const_hit.arg_taint, "CONST_LITERAL");
        assert!(!const_hit.is_outlier);

        let tainted =
            analyze_variants_with_opts(&dir, Some("execute"), None, Some(r"requireAdmin"), true);
        assert_eq!(tainted.total_siblings, 3);
        assert!(!tainted
            .siblings
            .iter()
            .any(|s| s.function == "healthCheckConst"));

        let seed_rep = analyze_variants(&dir, None, Some("deleteUserSafe"), Some(r"requireAdmin"));
        assert_eq!(seed_rep.total_siblings, 4);
        assert_eq!(seed_rep.siblings[0].function, "resetUserBuggy");
        let _ = fs::remove_dir_all(&dir);
    }
}
