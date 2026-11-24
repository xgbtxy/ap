use base64::Engine;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// Check whether parsed JSON is a SourceMap v3 document.
pub fn is_sourcemap_v3(v: &Value) -> bool {
    v.get("version").and_then(Value::as_u64) == Some(3)
        && v.get("sources").and_then(Value::as_array).is_some()
}

pub fn list_sourcemap_md(v: &Value, query: Option<&str>) -> String {
    let sources = v
        .get("sources")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let contents = v.get("sourcesContent").and_then(Value::as_array);
    let q_low = query.map(|q| q.to_ascii_lowercase());
    let mut lines = vec![format!(
        "## SourceMap v3 ({} original source files — use `--entry <path>` or `--map-pos <line>:<col>`)",
        sources.len()
    )];
    let mut shown = 0usize;
    for (idx, s) in sources.iter().enumerate() {
        let name = s.as_str().unwrap_or("");
        if let Some(ref q) = q_low {
            if !name.to_ascii_lowercase().contains(q) {
                continue;
            }
        }
        let sz = contents
            .and_then(|arr| arr.get(idx))
            .and_then(Value::as_str)
            .map(|c| format!(" ({} B embedded)", c.len()))
            .unwrap_or_else(|| " (external)".to_string());
        lines.push(format!("- `{name}`{sz}"));
        shown += 1;
        if shown >= 200 {
            lines.push(format!(
                "... ({} more sources; narrow with `--query <substr>`)",
                sources.len().saturating_sub(shown)
            ));
            break;
        }
    }
    lines.join("\n")
}

pub fn read_sourcemap_entry(v: &Value, entry: &str) -> Result<(String, String), String> {
    let sources = v
        .get("sources")
        .and_then(Value::as_array)
        .ok_or("SourceMap missing sources array")?;
    let contents = v
        .get("sourcesContent")
        .and_then(Value::as_array)
        .ok_or("SourceMap has no embedded sourcesContent")?;
    let norm = entry.trim_start_matches("./").trim_start_matches('/');
    let low = norm.to_ascii_lowercase();
    for (idx, s) in sources.iter().enumerate() {
        let nm = s.as_str().unwrap_or("");
        let nm_low = nm.to_ascii_lowercase();
        if nm_low == low || nm_low.ends_with(&format!("/{low}")) || nm_low.ends_with(&low) {
            let body = contents
                .get(idx)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("Source `{nm}` has no embedded sourcesContent"))?;
            return Ok((nm.to_string(), body.to_string()));
        }
    }
    Err(format!("source `{entry}` not found in SourceMap v3"))
}

fn b64_vlq_val(b: u8) -> Option<i64> {
    match b {
        b'A'..=b'Z' => Some((b - b'A') as i64),
        b'a'..=b'z' => Some((b - b'a' + 26) as i64),
        b'0'..=b'9' => Some((b - b'0' + 52) as i64),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn decode_vlq_segment(seg: &str) -> Vec<i64> {
    let mut vals = Vec::new();
    let bytes = seg.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        while let Some(&b) = bytes.get(i) {
            i += 1;
            let Some(digit) = b64_vlq_val(b) else { break };
            let cont = (digit & 32) != 0;
            result += (digit & 31) << shift;
            shift += 5;
            if !cont || shift > 55 {
                break;
            }
        }
        let neg = (result & 1) != 0;
        let signed = result >> 1;
        vals.push(if neg { -signed } else { signed });
    }
    vals
}

/// Pure-Rust SourceMap v3 VLQ resolver: maps 1-based generated `line:col` -> original source & snippet.
pub fn resolve_sourcemap_pos(
    v: &Value,
    target_line: usize,
    target_col: usize,
) -> Result<String, String> {
    let mappings = v
        .get("mappings")
        .and_then(Value::as_str)
        .ok_or("SourceMap missing mappings field")?;
    let sources = v
        .get("sources")
        .and_then(Value::as_array)
        .ok_or("SourceMap missing sources")?;
    let names = v.get("names").and_then(Value::as_array);
    let contents = v.get("sourcesContent").and_then(Value::as_array);

    let mut src_idx: i64 = 0;
    let mut orig_line: i64 = 0;
    let mut orig_col: i64 = 0;
    let mut name_idx: i64 = 0;
    let mut best: Option<(usize, usize, usize, usize, Option<String>)> = None;

    for (gen_ln_0, line_str) in mappings.split(';').enumerate() {
        let gen_ln = gen_ln_0 + 1;
        let mut gen_col: i64 = 0;
        for seg in line_str.split(',') {
            if seg.is_empty() {
                continue;
            }
            let nums = decode_vlq_segment(seg);
            if nums.is_empty() {
                continue;
            }
            gen_col += nums[0];
            if nums.len() >= 4 {
                src_idx += nums[1];
                orig_line += nums[2];
                orig_col += nums[3];
                let sym = if nums.len() >= 5 {
                    name_idx += nums[4];
                    names
                        .and_then(|a| a.get(name_idx as usize))
                        .and_then(Value::as_str)
                        .map(String::from)
                } else {
                    None
                };
                if gen_ln == target_line && (gen_col as usize) <= target_col {
                    best = Some((
                        gen_col as usize,
                        src_idx.max(0) as usize,
                        (orig_line.max(0) as usize) + 1,
                        orig_col.max(0) as usize,
                        sym,
                    ));
                }
            }
        }
        if gen_ln >= target_line {
            break;
        }
    }

    let Some((_, sidx, oline, ocol, sym)) = best else {
        return Err(format!(
            "No SourceMap mapping found for generated L{target_line}:C{target_col}"
        ));
    };
    let sname = sources
        .get(sidx)
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    let sym_tag = sym
        .as_deref()
        .map(|s| format!(" (symbol `{s}`)"))
        .unwrap_or_default();
    let mut out = vec![format!(
        "## SourceMap VLQ Resolved `L{target_line}:C{target_col}` -> `{sname}:L{oline}:C{ocol}`{sym_tag}"
    )];
    if let Some(src_txt) = contents
        .and_then(|arr| arr.get(sidx))
        .and_then(Value::as_str)
    {
        let src_lines: Vec<&str> = src_txt.lines().collect();
        let start = oline.saturating_sub(3).max(1);
        let end = (oline + 3).min(src_lines.len());
        for ln in start..=end {
            let mark = if ln == oline { ">" } else { " " };
            out.push(format!("{mark}{ln:4} | {}", src_lines[ln - 1]));
        }
    }
    Ok(out.join("\n"))
}

/// Evaluate zero-jq JSON path (`a.b[0].c`, `items[*].name`, or `..key` recursive descent).
pub fn eval_json_path<'a>(root: &'a Value, expr: &str) -> Vec<&'a Value> {
    let clean = expr.trim().trim_start_matches('$').trim_start_matches('.');
    if clean.is_empty() {
        return vec![root];
    }
    if let Some(rec_key) = expr.trim().strip_prefix("..") {
        let mut found = Vec::new();
        fn walk_rec<'b>(v: &'b Value, key: &str, out: &mut Vec<&'b Value>) {
            match v {
                Value::Object(map) => {
                    for (k, val) in map {
                        if k == key {
                            out.push(val);
                        }
                        walk_rec(val, key, out);
                    }
                }
                Value::Array(arr) => {
                    for item in arr {
                        walk_rec(item, key, out);
                    }
                }
                _ => {}
            }
        }
        walk_rec(root, rec_key.trim(), &mut found);
        return found;
    }

    let mut cur: Vec<&Value> = vec![root];
    for raw_part in clean.split('.') {
        if raw_part.is_empty() {
            continue;
        }
        let mut next = Vec::new();
        if let Some((key, bracket_rest)) = raw_part.split_once('[') {
            let idx_str = bracket_rest.trim_end_matches(']');
            for v in &cur {
                let target = if key.is_empty() { Some(*v) } else { v.get(key) };
                if let Some(Value::Array(arr)) = target {
                    if idx_str == "*" {
                        next.extend(arr.iter());
                    } else if let Ok(i) = idx_str.parse::<usize>() {
                        if let Some(el) = arr.get(i) {
                            next.push(el);
                        }
                    }
                }
            }
        } else {
            for v in &cur {
                if let Some(sub) = v.get(raw_part) {
                    next.push(sub);
                } else if let Value::Array(arr) = v {
                    for el in arr {
                        if let Some(sub) = el.get(raw_part) {
                            next.push(sub);
                        }
                    }
                }
            }
        }
        cur = next;
    }
    cur
}

fn split_json_path_segments(expr: &str) -> Vec<&str> {
    let s = expr.trim();
    let b = s.as_bytes();
    let mut segs = Vec::new();
    let mut start = 0usize;
    let mut sq_depth = 0i32;
    let mut brace_depth = 0i32;
    let mut in_q: Option<u8> = None;
    let mut i = 0usize;
    while i < b.len() {
        let ch = b[i];
        if let Some(q) = in_q {
            if ch == q && (i == 0 || b[i - 1] != b'\\') {
                in_q = None;
            }
            i += 1;
            continue;
        }
        match ch {
            b'\'' | b'"' => in_q = Some(ch),
            b'[' => sq_depth += 1,
            b']' => sq_depth = (sq_depth - 1).max(0),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = (brace_depth - 1).max(0),
            b'.' if sq_depth == 0 && brace_depth == 0 => {
                if i > start {
                    segs.push(&s[start..i]);
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < s.len() {
        segs.push(&s[start..]);
    }
    segs
}

fn value_as_f64_or_str(v: &Value) -> (Option<f64>, String) {
    match v {
        Value::Number(n) => (n.as_f64(), n.to_string()),
        Value::Bool(b) => (None, b.to_string()),
        Value::Null => (None, "null".to_string()),
        Value::String(s) => (s.trim().parse::<f64>().ok(), s.clone()),
        other => (None, other.to_string()),
    }
}

fn matches_json_predicate(item: &Value, pred: &str) -> bool {
    let p = pred.trim().trim_start_matches('?').trim();
    const OPS: [&str; 8] = ["!=", ">=", "<=", "~=", "==", "=", ">", "<"];
    let Some((op_pos, op)) = OPS
        .iter()
        .filter_map(|op| p.find(op).map(|pos| (pos, *op)))
        .min_by_key(|x| x.0)
    else {
        return false;
    };
    let lhs_path = p[..op_pos].trim();
    let rhs_raw = p[op_pos + op.len()..].trim();
    let rhs = rhs_raw
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .or_else(|| {
            rhs_raw
                .strip_prefix('\'')
                .and_then(|x| x.strip_suffix('\''))
        })
        .unwrap_or(rhs_raw);
    let vals = eval_json_path(item, lhs_path);
    if vals.is_empty() {
        return op == "!=" && rhs != "null";
    }
    let rhs_num = rhs.parse::<f64>().ok();
    vals.into_iter().any(|v| {
        let (v_num, v_str) = value_as_f64_or_str(v);
        match op {
            "=" | "==" => {
                if let (Some(a), Some(b)) = (v_num, rhs_num) {
                    (a - b).abs() < 1e-9
                } else {
                    v_str.eq_ignore_ascii_case(rhs)
                }
            }
            "!=" => {
                if let (Some(a), Some(b)) = (v_num, rhs_num) {
                    (a - b).abs() >= 1e-9
                } else {
                    !v_str.eq_ignore_ascii_case(rhs)
                }
            }
            "~=" => v_str
                .to_ascii_lowercase()
                .contains(&rhs.to_ascii_lowercase()),
            ">" => v_num.zip(rhs_num).map(|(a, b)| a > b).unwrap_or(false),
            "<" => v_num.zip(rhs_num).map(|(a, b)| a < b).unwrap_or(false),
            ">=" => v_num.zip(rhs_num).map(|(a, b)| a >= b).unwrap_or(false),
            "<=" => v_num.zip(rhs_num).map(|(a, b)| a <= b).unwrap_or(false),
            _ => false,
        }
    })
}

fn eval_json_path_owned(root: &Value, expr: &str) -> Vec<Value> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return vec![root.clone()];
    }
    if let Some(rec_key) = trimmed.strip_prefix("..") {
        if !rec_key.contains('[') && !rec_key.contains('{') {
            return eval_json_path(root, trimmed).into_iter().cloned().collect();
        }
    }
    let clean = trimmed.trim_start_matches('$').trim_start_matches('.');
    if clean.is_empty() {
        return vec![root.clone()];
    }
    let mut cur: Vec<Value> = vec![root.clone()];
    for part in split_json_path_segments(clean) {
        if part.is_empty() {
            continue;
        }
        if part == "keys()" {
            cur = cur
                .into_iter()
                .filter_map(|v| match v {
                    Value::Object(map) => Some(Value::Array(
                        map.keys().cloned().map(Value::String).collect(),
                    )),
                    _ => None,
                })
                .collect();
            continue;
        }
        if part == "len()" || part == "length" {
            cur = cur
                .into_iter()
                .filter_map(|v| match v {
                    Value::Array(a) => Some(serde_json::json!(a.len())),
                    Value::Object(m) => Some(serde_json::json!(m.len())),
                    Value::String(s) => Some(serde_json::json!(s.chars().count())),
                    _ => None,
                })
                .collect();
            continue;
        }
        if part.starts_with('{') && part.ends_with('}') && part.len() >= 2 {
            let inner = &part[1..part.len() - 1];
            let fields: Vec<(&str, &str)> = inner
                .split(',')
                .map(str::trim)
                .filter(|f| !f.is_empty())
                .map(|f| match f.split_once(':') {
                    Some((alias, path)) => (alias.trim(), path.trim()),
                    None => (f, f),
                })
                .collect();
            cur = cur
                .into_iter()
                .map(|v| {
                    let mut obj = serde_json::Map::new();
                    for (alias, fpath) in &fields {
                        let hits = eval_json_path(&v, fpath);
                        let val = match hits.len() {
                            0 => Value::Null,
                            1 => hits[0].clone(),
                            _ => Value::Array(hits.into_iter().cloned().collect()),
                        };
                        obj.insert((*alias).to_string(), val);
                    }
                    Value::Object(obj)
                })
                .collect();
            continue;
        }

        let mut next = Vec::new();
        if let Some((key, bracket_rest)) = part.split_once('[') {
            let inner = bracket_rest.trim_end_matches(']').trim();
            for v in &cur {
                let target = if key.is_empty() { Some(v) } else { v.get(key) };
                if let Some(Value::Array(arr)) = target {
                    if inner == "*" {
                        next.extend(arr.iter().cloned());
                    } else if let Ok(idx) = inner.parse::<usize>() {
                        if let Some(el) = arr.get(idx) {
                            next.push(el.clone());
                        }
                    } else {
                        for el in arr {
                            if matches_json_predicate(el, inner) {
                                next.push(el.clone());
                            }
                        }
                    }
                }
            }
        } else {
            for v in &cur {
                if let Some(sub) = v.get(part) {
                    next.push(sub.clone());
                } else if let Value::Array(arr) = v {
                    for el in arr {
                        if let Some(sub) = el.get(part) {
                            next.push(sub.clone());
                        }
                    }
                }
            }
        }
        cur = next;
    }
    cur
}

pub fn query_json_or_jsonl(text: &str, expr: &str) -> Result<String, String> {
    let mut results: Vec<Value> = Vec::new();
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        results.extend(eval_json_path_owned(&v, expr));
    } else {
        for ln in text.lines() {
            let t = ln.trim();
            if t.starts_with('{') || t.starts_with('[') {
                if let Ok(v) = serde_json::from_str::<Value>(t) {
                    results.extend(eval_json_path_owned(&v, expr));
                }
            }
        }
    }
    if results.is_empty() {
        return Ok(format!("## JSON Path `{expr}` (0 matches)"));
    }
    let body = if results.len() == 1 {
        serde_json::to_string_pretty(&results[0]).unwrap_or_default()
    } else {
        serde_json::to_string_pretty(&results).unwrap_or_default()
    };
    Ok(format!(
        "## JSON Path `{expr}` ({} match(es))\n{body}",
        results.len()
    ))
}

fn summarize_json_node(v: &Value, name: &str, depth: usize, out: &mut Vec<String>) {
    if out.len() >= 75 {
        return;
    }
    let pad = "  ".repeat(depth);
    match v {
        Value::Object(map) => {
            if !name.is_empty() {
                out.push(format!("{pad}{name}: object ({} keys)", map.len()));
            }
            if depth >= 4 {
                return;
            }
            for (k, child) in map.iter().take(24) {
                summarize_json_node(child, k, depth + if name.is_empty() { 0 } else { 1 }, out);
                if out.len() >= 75 {
                    break;
                }
            }
            if map.len() > 24 {
                out.push(format!("{pad}  ... (+{} more keys)", map.len() - 24));
            }
        }
        Value::Array(arr) => {
            out.push(format!("{pad}{name}: array[{}]", arr.len()));
            if depth < 4 && !arr.is_empty() {
                let mut merged = serde_json::Map::new();
                for item in arr.iter().take(5) {
                    if let Value::Object(obj) = item {
                        for (k, val) in obj {
                            merged.entry(k.clone()).or_insert_with(|| val.clone());
                        }
                    }
                }
                if !merged.is_empty() {
                    for (k, val) in merged.iter().take(20) {
                        summarize_json_node(val, &format!("[].{k}"), depth + 1, out);
                        if out.len() >= 75 {
                            break;
                        }
                    }
                } else {
                    summarize_json_node(&arr[0], "[0]", depth + 1, out);
                }
            }
        }
        Value::String(s) => {
            let preview: String = s.chars().take(36).collect();
            let ell = if s.chars().count() > 36 { "..." } else { "" };
            out.push(format!(
                "{pad}{name}: string ({}ch \"{preview}{ell}\")",
                s.len()
            ));
        }
        Value::Number(n) => out.push(format!("{pad}{name}: number ({n})")),
        Value::Bool(b) => out.push(format!("{pad}{name}: bool ({b})")),
        Value::Null => out.push(format!("{pad}{name}: null")),
    }
}

/// Compact schema outline for JSON documents, HAR captures (`log.entries`), and JSONL streams.
pub fn outline_json_or_jsonl(text: &str) -> Option<String> {
    let trimmed = text.trim_start_matches('\u{FEFF}').trim();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return None;
    }
    let mut lines_out = Vec::new();
    if let Ok(root) = serde_json::from_str::<Value>(trimmed) {
        if let Some(entries) = root
            .get("log")
            .and_then(|l| l.get("entries"))
            .and_then(Value::as_array)
        {
            let mut methods: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            let mut statuses: std::collections::BTreeMap<u64, usize> =
                std::collections::BTreeMap::new();
            let mut hosts: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            for e in entries {
                if let Some(m) = e.pointer("/request/method").and_then(Value::as_str) {
                    *methods.entry(m.to_string()).or_default() += 1;
                }
                if let Some(st) = e.pointer("/response/status").and_then(Value::as_u64) {
                    *statuses.entry(st).or_default() += 1;
                }
                if let Some(u) = e.pointer("/request/url").and_then(Value::as_str) {
                    if let Some(rest) = u.split("://").nth(1) {
                        let host = rest.split('/').next().unwrap_or("");
                        if !host.is_empty() {
                            *hosts.entry(host.to_string()).or_default() += 1;
                        }
                    }
                }
            }
            lines_out.push(format!(
                "HAR Capture: {} entries | methods={methods:?} | statuses={statuses:?} | hosts={hosts:?}",
                entries.len()
            ));
        }
        summarize_json_node(
            &root,
            if root.is_array() { "root" } else { "" },
            0,
            &mut lines_out,
        );
        if lines_out.is_empty() {
            lines_out.push("(empty JSON container)".to_string());
        }
        return Some(lines_out.join("\n"));
    }

    let mut records = Vec::new();
    for ln in trimmed.lines().take(200) {
        let t = ln.trim();
        if t.starts_with('{') || t.starts_with('[') {
            if let Ok(v) = serde_json::from_str::<Value>(t) {
                records.push(v);
            }
        }
    }
    if records.is_empty() {
        return None;
    }
    lines_out.push(format!(
        "JSONL Stream: {} parsed record(s) sampled",
        records.len()
    ));
    summarize_json_node(&Value::Array(records), "records", 0, &mut lines_out);
    Some(lines_out.join("\n"))
}

fn der_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let l0 = buf[1];
    let (hdr_len, val_len) = if l0 < 0x80 {
        (2usize, l0 as usize)
    } else {
        let nb = (l0 & 0x7F) as usize;
        if nb == 0 || nb > 4 || buf.len() < 2 + nb {
            return None;
        }
        let mut n = 0usize;
        for &b in &buf[2..2 + nb] {
            n = (n << 8) | (b as usize);
        }
        (2 + nb, n)
    };
    let end = hdr_len.checked_add(val_len)?;
    if end > buf.len() {
        return None;
    }
    Some((tag, &buf[hdr_len..end], &buf[end..]))
}

fn der_oid_dotted(raw: &[u8]) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let mut parts = vec![(raw[0] / 40) as u64, (raw[0] % 40) as u64];
    let mut acc = 0u64;
    for &b in &raw[1..] {
        acc = (acc << 7) | ((b & 0x7F) as u64);
        if (b & 0x80) == 0 {
            parts.push(acc);
            acc = 0;
        }
    }
    parts
        .into_iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn der_oid_label(oid: &str) -> &str {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "1.2.840.113549.1.9.1" => "email",
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.113549.1.1.5" => "sha1WithRSA",
        "1.2.840.113549.1.1.11" => "sha256WithRSA",
        "1.2.840.113549.1.1.12" => "sha384WithRSA",
        "1.2.840.113549.1.1.13" => "sha512WithRSA",
        "1.2.840.10045.2.1" => "EC",
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.101.112" => "Ed25519",
        "1.2.840.10045.4.3.2" => "ecdsa-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-SHA384",
        other => other,
    }
}

fn parse_der_name(seq: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut cur = seq;
    while let Some((t, set_body, rest)) = der_tlv(cur) {
        cur = rest;
        if t != 0x31 {
            continue;
        }
        let mut sc = set_body;
        while let Some((st, atv, srest)) = der_tlv(sc) {
            sc = srest;
            if st != 0x30 {
                continue;
            }
            if let Some((0x06, oid_b, rem)) = der_tlv(atv) {
                if let Some((_vt, val_b, _)) = der_tlv(rem) {
                    let oid_s = der_oid_dotted(oid_b);
                    let k = der_oid_label(&oid_s);
                    let v = String::from_utf8_lossy(val_b).trim().to_string();
                    parts.push(format!("{k}={v}"));
                }
            }
        }
    }
    if parts.is_empty() {
        "(empty)".to_string()
    } else {
        parts.join(", ")
    }
}

fn format_der_time(tag: u8, val: &[u8]) -> String {
    let s = String::from_utf8_lossy(val);
    let b = s.as_bytes();
    if tag == 0x17 && b.len() >= 12 {
        let yy = std::str::from_utf8(&b[0..2]).unwrap_or("00");
        let cen = if yy.parse::<u16>().unwrap_or(0) >= 50 {
            "19"
        } else {
            "20"
        };
        format!(
            "{cen}{}-{}-{}T{}:{}:{}Z",
            yy,
            std::str::from_utf8(&b[2..4]).unwrap_or("00"),
            std::str::from_utf8(&b[4..6]).unwrap_or("00"),
            std::str::from_utf8(&b[6..8]).unwrap_or("00"),
            std::str::from_utf8(&b[8..10]).unwrap_or("00"),
            std::str::from_utf8(&b[10..12]).unwrap_or("00")
        )
    } else if tag == 0x18 && b.len() >= 14 {
        format!(
            "{}-{}-{}T{}:{}:{}Z",
            std::str::from_utf8(&b[0..4]).unwrap_or("0000"),
            std::str::from_utf8(&b[4..6]).unwrap_or("00"),
            std::str::from_utf8(&b[6..8]).unwrap_or("00"),
            std::str::from_utf8(&b[8..10]).unwrap_or("00"),
            std::str::from_utf8(&b[10..12]).unwrap_or("00"),
            std::str::from_utf8(&b[12..14]).unwrap_or("00")
        )
    } else {
        s.to_string()
    }
}

fn inspect_single_x509_der(der: &[u8], idx: usize) -> Result<String, String> {
    let (0x30, cert_body, _) = der_tlv(der).ok_or("invalid DER SEQUENCE header")? else {
        return Err("certificate must start with ASN.1 SEQUENCE (0x30)".to_string());
    };
    let (0x30, mut tbs, _) = der_tlv(cert_body).ok_or("missing tbsCertificate")? else {
        return Err("tbsCertificate must be ASN.1 SEQUENCE".to_string());
    };
    let mut version = 1u8;
    if let Some((0xA0, ver_inner, rest)) = der_tlv(tbs) {
        if let Some((0x02, vb, _)) = der_tlv(ver_inner) {
            version = vb.last().copied().unwrap_or(0).saturating_add(1);
        }
        tbs = rest;
    }
    let (0x02, serial_b, rest) = der_tlv(tbs).ok_or("missing serialNumber")? else {
        return Err("missing serialNumber INTEGER".to_string());
    };
    let serial = serial_b
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let (_, sig_body, rest) = der_tlv(rest).ok_or("missing signature AlgorithmIdentifier")?;
    let sig_alg = der_tlv(sig_body)
        .filter(|(t, _, _)| *t == 0x06)
        .map(|(_, ob, _)| der_oid_label(&der_oid_dotted(ob)).to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let (_, issuer_b, rest) = der_tlv(rest).ok_or("missing issuer")?;
    let issuer = parse_der_name(issuer_b);
    let (_, val_b, rest) = der_tlv(rest).ok_or("missing validity")?;
    let (not_before, not_after) = if let Some((t1, b1, r1)) = der_tlv(val_b) {
        if let Some((t2, b2, _)) = der_tlv(r1) {
            (format_der_time(t1, b1), format_der_time(t2, b2))
        } else {
            (format_der_time(t1, b1), "?".to_string())
        }
    } else {
        ("?".to_string(), "?".to_string())
    };
    let (_, subj_b, rest) = der_tlv(rest).ok_or("missing subject")?;
    let subject = parse_der_name(subj_b);
    let (_, spki_b, mut rem) = der_tlv(rest).ok_or("missing SubjectPublicKeyInfo")?;
    let key_info = if let Some((0x30, alg_b, spki_rest)) = der_tlv(spki_b) {
        let alg_oid = der_tlv(alg_b)
            .filter(|(t, _, _)| *t == 0x06)
            .map(|(_, ob, r)| {
                let main = der_oid_label(&der_oid_dotted(ob)).to_string();
                if let Some((0x06, pb, _)) = der_tlv(r) {
                    format!("{main} ({})", der_oid_label(&der_oid_dotted(pb)))
                } else {
                    main
                }
            })
            .unwrap_or_else(|| "unknown".to_string());
        let bits = der_tlv(spki_rest)
            .filter(|(t, _, _)| *t == 0x03)
            .map(|(_, kb, _)| kb.len().saturating_sub(1) * 8)
            .unwrap_or(0);
        format!("{alg_oid} (~{bits}b SPKI)")
    } else {
        "unknown".to_string()
    };

    let mut sans = Vec::new();
    let mut is_ca: Option<bool> = None;
    while let Some((t, inner, rnext)) = der_tlv(rem) {
        rem = rnext;
        if t != 0xA3 {
            continue;
        }
        if let Some((0x30, mut ext_seq, _)) = der_tlv(inner) {
            while let Some((0x30, ext, erest)) = der_tlv(ext_seq) {
                ext_seq = erest;
                let Some((0x06, eoid_b, ext_r)) = der_tlv(ext) else {
                    continue;
                };
                let eoid = der_oid_dotted(eoid_b);
                let mut cur_r = ext_r;
                if let Some((0x01, _, after_crit)) = der_tlv(cur_r) {
                    cur_r = after_crit;
                }
                let Some((0x04, oct, _)) = der_tlv(cur_r) else {
                    continue;
                };
                if eoid == "2.5.29.17" {
                    if let Some((0x30, mut gn_seq, _)) = der_tlv(oct) {
                        while let Some((gt, gb, grest)) = der_tlv(gn_seq) {
                            gn_seq = grest;
                            match gt {
                                0x82 => sans.push(format!("DNS:{}", String::from_utf8_lossy(gb))),
                                0x86 => sans.push(format!("URI:{}", String::from_utf8_lossy(gb))),
                                0x87 if gb.len() == 4 => {
                                    sans.push(format!(
                                        "IP:{}.{}.{}.{}",
                                        gb[0], gb[1], gb[2], gb[3]
                                    ));
                                }
                                0x87 if gb.len() == 16 => {
                                    let hexs = gb
                                        .chunks_exact(2)
                                        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                                        .collect::<Vec<_>>()
                                        .join(":");
                                    sans.push(format!("IP:{hexs}"));
                                }
                                _ => {}
                            }
                        }
                    }
                } else if eoid == "2.5.29.19" {
                    if let Some((0x30, bc_body, _)) = der_tlv(oct) {
                        is_ca = Some(
                            der_tlv(bc_body)
                                .filter(|(bt, _, _)| *bt == 0x01)
                                .and_then(|(_, bb, _)| bb.first().map(|&v| v != 0))
                                .unwrap_or(false),
                        );
                    }
                }
            }
        }
    }

    let fp = crate::binary::sha256_hex(der);
    let mut lines = vec![
        format!("### X.509 Certificate #{idx} (v{version}) | SHA-256: `{fp}`"),
        format!("- **Subject**: `{subject}`"),
        format!("- **Issuer**: `{issuer}`"),
        format!("- **Validity**: `{not_before}` .. `{not_after}`"),
        format!("- **Key & Signature**: `{key_info}` | sig=`{sig_alg}` | serial=`{serial}`"),
    ];
    if let Some(ca) = is_ca {
        lines.push(format!("- **BasicConstraints**: CA={ca}"));
    }
    if !sans.is_empty() {
        lines.push(format!(
            "- **SANs ({})**: `{}`",
            sans.len(),
            sans.join("`, `")
        ));
    }
    Ok(lines.join("\n"))
}

/// Pure-Rust zero-OpenSSL X.509 PEM/DER certificate inspector (`--cert`).
pub fn inspect_x509_pem_or_der(bytes: &[u8]) -> Result<String, String> {
    let text = String::from_utf8_lossy(bytes);
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if text.contains(BEGIN) {
        let mut out = Vec::new();
        let mut search = text.as_ref();
        let mut idx = 1usize;
        while let Some(s_pos) = search.find(BEGIN) {
            let after = &search[s_pos + BEGIN.len()..];
            let Some(e_pos) = after.find(END) else {
                break;
            };
            let b64: String = after[..e_pos]
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();
            let der = base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| format!("PEM base64 decode failed: {e}"))?;
            out.push(inspect_single_x509_der(&der, idx)?);
            idx += 1;
            search = &after[e_pos + END.len()..];
            if idx > 8 {
                break;
            }
        }
        if out.is_empty() {
            return Err("no complete PEM certificate block found".to_string());
        }
        return Ok(out.join("\n\n"));
    }
    if bytes.first() == Some(&0x30) {
        return inspect_single_x509_der(bytes, 1);
    }
    Err("input is neither PEM (-----BEGIN CERTIFICATE-----) nor DER SEQUENCE (0x30)".to_string())
}

fn decode_b64_any(s: &str) -> Option<Vec<u8>> {
    let std_s = s.replace('-', "+").replace('_', "/");
    let pad = (4 - (std_s.len() % 4)) % 4;
    let padded = format!("{std_s}{}", "=".repeat(pad));
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .ok()
}

/// Auto-decode embedded JWT tokens, Base64 payloads, and URL-encoded strings (`--decode`).
pub fn decode_embedded_payloads(text: &str) -> String {
    static RE: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    let (jwt_re, b64_re, url_re) = RE.get_or_init(|| {
        (
            Regex::new(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,})\b")
                .unwrap(),
            Regex::new(r"\b([A-Za-z0-9+/]{24,}={0,2})\b").unwrap(),
            Regex::new(r"(?:[^\s'\x22<>]*%[0-9A-Fa-f]{2}){2,}[^\s'\x22<>]*").unwrap(),
        )
    });
    let mut lines = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for cap in jwt_re.captures_iter(text).take(8) {
        let tok = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if !seen.insert(tok.to_string()) {
            continue;
        }
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() == 3 {
            let hdr = decode_b64_any(parts[0])
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default();
            let pay = decode_b64_any(parts[1])
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default();
            lines.push(format!("- [JWT] header={hdr} | payload={pay}"));
        }
    }

    for cap in b64_re.captures_iter(text).take(12) {
        let s = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if s.starts_with("eyJ") || !seen.insert(s.to_string()) {
            continue;
        }
        if let Some(bytes) = decode_b64_any(s) {
            if let Ok(decoded) = String::from_utf8(bytes) {
                let printable = decoded
                    .chars()
                    .filter(|c| !c.is_control() || c.is_whitespace())
                    .count();
                if decoded.len() >= 8 && printable * 10 >= decoded.len() * 9 {
                    lines.push(format!(
                        "- [Base64] `{}` -> `{}`",
                        s.chars().take(24).collect::<String>(),
                        decoded.trim().chars().take(200).collect::<String>()
                    ));
                }
            }
        }
    }

    for m in url_re.find_iter(text).take(8) {
        let raw = m.as_str();
        let mut bytes = Vec::new();
        let b = raw.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let Ok(hex) = std::str::from_utf8(&b[i + 1..i + 3]) {
                    if let Ok(v) = u8::from_str_radix(hex, 16) {
                        bytes.push(v);
                        i += 3;
                        continue;
                    }
                }
            }
            bytes.push(b[i]);
            i += 1;
        }
        if let Ok(dec) = String::from_utf8(bytes) {
            if seen.insert(dec.clone()) {
                lines.push(format!("- [URL] `{raw}` -> `{dec}`"));
            }
        }
    }

    if lines.is_empty() {
        "## Decoded Payloads\n*(no decodable JWT / Base64 / URL-encoded payloads found)*"
            .to_string()
    } else {
        format!(
            "## Decoded Payloads ({} found)\n{}",
            lines.len(),
            lines.join("\n")
        )
    }
}

fn read_pb_varint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let mut val = 0u64;
    let mut shift = 0u32;
    while *pos < b.len() && shift < 64 {
        let byte = b[*pos];
        *pos += 1;
        val |= ((byte & 0x7F) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Some(val);
        }
        shift += 7;
    }
    None
}

fn decode_pb_fields(b: &[u8], depth: usize, out: &mut Vec<String>) -> bool {
    if depth > 6 || b.is_empty() {
        return false;
    }
    let indent = "  ".repeat(depth);
    let mut pos = 0usize;
    let mut count = 0usize;
    while pos < b.len() && out.len() < 160 {
        let Some(tag) = read_pb_varint(b, &mut pos) else {
            return false;
        };
        let field_no = tag >> 3;
        let wire_type = (tag & 0x7) as u8;
        if field_no == 0 || field_no > 536_870_911 {
            return false;
        }
        match wire_type {
            0 => {
                let Some(v) = read_pb_varint(b, &mut pos) else {
                    return false;
                };
                out.push(format!("{indent}{field_no} (varint): {v} (0x{v:x})"));
            }
            1 => {
                if pos + 8 > b.len() {
                    return false;
                }
                let v = u64::from_le_bytes([
                    b[pos],
                    b[pos + 1],
                    b[pos + 2],
                    b[pos + 3],
                    b[pos + 4],
                    b[pos + 5],
                    b[pos + 6],
                    b[pos + 7],
                ]);
                pos += 8;
                out.push(format!("{indent}{field_no} (fixed64): 0x{v:016x} ({v})"));
            }
            2 => {
                let Some(len_u64) = read_pb_varint(b, &mut pos) else {
                    return false;
                };
                let len = len_u64 as usize;
                if len > b.len().saturating_sub(pos) {
                    return false;
                }
                let slice = &b[pos..pos + len];
                pos += len;
                let mut nested = Vec::new();
                if slice.len() >= 2 && depth < 5 && decode_pb_fields(slice, depth + 1, &mut nested)
                {
                    // Prefer UTF-8 string if entire slice is clean printable text and nested only had 1 trivial field
                    let is_clean_text = std::str::from_utf8(slice)
                        .map(|s| {
                            !s.is_empty()
                                && s.chars()
                                    .all(|c| (!c.is_control()) || matches!(c, '\n' | '\r' | '\t'))
                        })
                        .unwrap_or(false);
                    if is_clean_text && nested.len() <= 1 {
                        let s = std::str::from_utf8(slice).unwrap_or("");
                        out.push(format!(
                            "{indent}{field_no} (str, {}B): {:?}",
                            slice.len(),
                            s.chars().take(180).collect::<String>()
                        ));
                    } else {
                        out.push(format!("{indent}{field_no} (msg, {}B) {{", slice.len()));
                        out.extend(nested);
                        out.push(format!("{indent}}}"));
                    }
                } else if let Ok(s) = std::str::from_utf8(slice) {
                    if !s.is_empty()
                        && s.chars()
                            .all(|c| (!c.is_control()) || matches!(c, '\n' | '\r' | '\t'))
                    {
                        out.push(format!(
                            "{indent}{field_no} (str, {}B): {:?}",
                            slice.len(),
                            s.chars().take(180).collect::<String>()
                        ));
                    } else {
                        let hx: String =
                            slice.iter().take(32).map(|x| format!("{x:02x}")).collect();
                        out.push(format!(
                            "{indent}{field_no} (bytes, {}B): 0x{hx}",
                            slice.len()
                        ));
                    }
                } else {
                    let hx: String = slice.iter().take(32).map(|x| format!("{x:02x}")).collect();
                    out.push(format!(
                        "{indent}{field_no} (bytes, {}B): 0x{hx}",
                        slice.len()
                    ));
                }
            }
            5 => {
                if pos + 4 > b.len() {
                    return false;
                }
                let v = u32::from_le_bytes([b[pos], b[pos + 1], b[pos + 2], b[pos + 3]]);
                pos += 4;
                out.push(format!("{indent}{field_no} (fixed32): 0x{v:08x} ({v})"));
            }
            _ => return false,
        }
        count += 1;
    }
    count > 0 && pos == b.len()
}

/// Pure-Rust schema-less raw Protocol Buffers wire-format decoder (`--proto`).
pub fn decode_raw_protobuf_md(bytes: &[u8]) -> Result<String, String> {
    let mut lines = Vec::new();
    let slice = &bytes[..bytes.len().min(512 * 1024)];
    if !decode_pb_fields(slice, 0, &mut lines) {
        return Err("payload is not a valid Protocol Buffers wire stream".to_string());
    }
    Ok(format!(
        "## Raw Protobuf Wire Decode ({} B, {} line(s))\n{}",
        bytes.len(),
        lines.len(),
        lines.join("\n")
    ))
}

fn unix_secs_to_iso_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    // Howard Hinnant civil-from-days algorithm (Gregorian calendar, zero deps)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Pure-Rust JWT token & security posture inspector (`--jwt`).
/// Accepts a raw JWT string (`eyJ...`, `Bearer eyJ...`) or arbitrary text/JSON containing JWTs.
pub fn inspect_jwt_md(raw_text: &str) -> Result<(String, serde_json::Value), String> {
    static JWT_RE: OnceLock<Regex> = OnceLock::new();
    let jwt_re = JWT_RE.get_or_init(|| {
        Regex::new(r"(eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*)").unwrap()
    });
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut seen = std::collections::HashSet::new();
    let mut items: Vec<serde_json::Value> = Vec::new();
    let mut blocks: Vec<String> = Vec::new();

    for cap in jwt_re.captures_iter(raw_text) {
        if items.len() >= 12 {
            break;
        }
        let tok = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if tok.is_empty() || !seen.insert(tok.to_string()) {
            continue;
        }
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() != 3 {
            continue;
        }
        let Some(hdr_bytes) = decode_b64_any(parts[0]) else {
            continue;
        };
        let Some(pay_bytes) = decode_b64_any(parts[1]) else {
            continue;
        };
        let Ok(hdr_val) = serde_json::from_slice::<Value>(&hdr_bytes) else {
            continue;
        };
        let Ok(pay_val) = serde_json::from_slice::<Value>(&pay_bytes) else {
            continue;
        };

        let alg = hdr_val
            .get("alg")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        let mut risks: Vec<String> = Vec::new();
        if alg.eq_ignore_ascii_case("none") || alg == "<missing>" {
            risks.push(format!("WEAK-ALG:{alg}"));
        } else if alg.to_ascii_uppercase().starts_with("HS") {
            risks.push(format!("SYMMETRIC-HMAC:{alg}"));
        }
        if parts[2].is_empty() {
            risks.push("EMPTY-SIGNATURE".to_string());
        }
        let mut hdr_inj: Vec<&str> = Vec::new();
        for key in ["jwk", "jku", "x5u", "x5c", "kid"] {
            if hdr_val.get(key).is_some() {
                hdr_inj.push(key);
            }
        }
        if !hdr_inj.is_empty() {
            risks.push(format!("HEADER-INJECTION-SURFACE:{}", hdr_inj.join(",")));
        }

        let iat = pay_val.get("iat").and_then(Value::as_i64);
        let nbf = pay_val.get("nbf").and_then(Value::as_i64);
        let exp = pay_val.get("exp").and_then(Value::as_i64);
        let mut time_notes: Vec<String> = Vec::new();
        if let Some(v) = iat {
            time_notes.push(format!("iat={}", unix_secs_to_iso_utc(v)));
        }
        if let Some(v) = nbf {
            let st = if now_secs > 0 && v > now_secs {
                " [NOT-YET-VALID]"
            } else {
                ""
            };
            time_notes.push(format!("nbf={}{st}", unix_secs_to_iso_utc(v)));
        }
        if let Some(v) = exp {
            let expired = now_secs > 0 && v < now_secs;
            if expired {
                risks.push("EXPIRED".to_string());
            }
            time_notes.push(format!(
                "exp={} ({})",
                unix_secs_to_iso_utc(v),
                if expired { "EXPIRED" } else { "ACTIVE" }
            ));
        } else {
            risks.push("NO-EXP-CLAIM".to_string());
        }

        let mut priv_keys: Vec<&str> = Vec::new();
        if let Some(obj) = pay_val.as_object() {
            for k in obj.keys() {
                let kl = k.to_ascii_lowercase();
                if matches!(
                    kl.as_str(),
                    "role"
                        | "roles"
                        | "admin"
                        | "is_admin"
                        | "isadmin"
                        | "scope"
                        | "scopes"
                        | "permissions"
                        | "perms"
                        | "tenant"
                        | "tenant_id"
                ) {
                    priv_keys.push(k.as_str());
                }
            }
        }
        if !priv_keys.is_empty() {
            priv_keys.sort_unstable();
            risks.push(format!("AUTHZ-CLAIMS:{}", priv_keys.join(",")));
        }

        let idx = items.len() + 1;
        let hdr_pretty = serde_json::to_string(&hdr_val).unwrap_or_default();
        let pay_pretty = serde_json::to_string_pretty(&pay_val).unwrap_or_default();
        let risk_line = if risks.is_empty() {
            "none".to_string()
        } else {
            risks.join(" | ")
        };
        let time_line = if time_notes.is_empty() {
            "no iat/nbf/exp timestamps".to_string()
        } else {
            time_notes.join(", ")
        };
        blocks.push(format!(
            "### JWT #{idx} (alg=`{alg}`, sig_len={})\n- Posture: `{risk_line}`\n- Timestamps: {time_line}\n- Header: `{hdr_pretty}`\n- Payload:\n```json\n{pay_pretty}\n```",
            parts[2].len()
        ));
        items.push(serde_json::json!({
            "index": idx,
            "alg": alg,
            "signature_len": parts[2].len(),
            "header": hdr_val,
            "payload": pay_val,
            "iat_utc": iat.map(unix_secs_to_iso_utc),
            "nbf_utc": nbf.map(unix_secs_to_iso_utc),
            "exp_utc": exp.map(unix_secs_to_iso_utc),
            "posture_flags": risks,
        }));
    }

    if items.is_empty() {
        return Err("no valid JWT token (`eyJ...`) found in input".to_string());
    }
    let md = format!(
        "## JWT Posture Inspector ({} token(s))\n\n{}",
        items.len(),
        blocks.join("\n\n")
    );
    let jv = serde_json::json!({
        "count": items.len(),
        "tokens": items,
    });
    Ok((md, jv))
}

struct JsRouteRegexes {
    api_path: Regex,
    http_call: Regex,
    post_msg: Regex,
    dom_sink: Regex,
    ext_origin: Regex,
    local_server_ipc: Regex,
    lazy_chunk: Regex,
    custom_header: Regex,
}

fn js_route_re() -> &'static JsRouteRegexes {
    static R: OnceLock<JsRouteRegexes> = OnceLock::new();
    R.get_or_init(|| JsRouteRegexes {
        api_path: Regex::new(
            r#"['"`](/(?:api|v[1-9][0-9]?|rest|graphql|oauth[0-9]*|auth|admin|internal|rpc|gw|gateway|proxy|upload|download|export|import|webhook|console|manage|portal|service|services|backend|bff)/[A-Za-z0-9_./:${}-]{1,180})['"`]"#,
        )
        .unwrap(),
        http_call: Regex::new(
            r#"(?i)\b(?:axios\.(get|post|put|delete|patch|request)|router\.(get|post|put|delete|patch|use|all)|(fetch)\s*)\(\s*['"`]((?:/|https?://)[^'"`\r\n]{2,180})['"`]"#,
        )
        .unwrap(),
        post_msg: Regex::new(
            r#"(?:addEventListener\s*\(\s*['"]message['"]|\.onmessage\s*=)"#,
        )
        .unwrap(),
        dom_sink: Regex::new(
            r#"(?:\.(?:innerHTML|outerHTML)\s*\+?=|dangerouslySetInnerHTML|document\.write(?:ln)?\s*\(|\beval\s*\(|\bnew\s+Function\s*\(|\blocation\.(?:href\s*=|assign\s*\(|replace\s*\()|\bwindow\.open\s*\()"#,
        )
        .unwrap(),
        ext_origin: Regex::new(r#"(?:https?|wss?)://([A-Za-z0-9][A-Za-z0-9.-]{2,100}(?::\d{2,5})?)"#)
            .unwrap(),
        local_server_ipc: Regex::new(
            r#"(?:\b(?:http|https|net)\.createServer\s*\(|\bnew\s+WebSocketServer\s*\(|['"`]/oauth/callback['"`]|\bipcMain\.(?:handle|on)\s*\(|\bcontextBridge\.exposeInMainWorld\s*\(|\bshell\.openExternal\s*\(|\b(?:execFile|execSync|spawn|spawnSync)\s*\()"#,
        )
        .unwrap(),
        lazy_chunk: Regex::new(
            r#"(?:['"`]([A-Za-z0-9_./-]{1,64}\.(?:chunk|bundle|async)\.[a-f0-9]{6,20}\.js|[0-9]{1,5}\.[a-f0-9]{8,20}\.js|assets/[A-Za-z0-9_.-]{3,64}-[A-Za-z0-9_-]{6,16}\.js)['"`]|\b([0-9]{1,5})\s*:\s*['"]([a-f0-9]{12,20})['"])"#,
        )
        .unwrap(),
        custom_header: Regex::new(
            r#"(?i)['"`](X-(?:Auth-Token|Domain-Id|Project-Id|Tenant-Id|User-Id|Csrf-Token|Xsrf-Token|Api-Key|Security-Token|Target-Services|Forwarded-[A-Za-z0-9-]+|Signature[A-Za-z0-9-]*|Request-[A-Za-z0-9-]+))['"`]"#,
        )
        .unwrap(),
    })
}

fn byte_line_col(text: &str, byte_off: usize) -> usize {
    text[..byte_off.min(text.len())]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1
}

/// Pure-Rust `<20ms` JavaScript/TypeScript/HTML API route, postMessage origin-check & DOM sink extractor (`--routes`).
fn is_sensitive_param_name(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    [
        "id", "uid", "user", "account", "tenant", "org", "role", "admin", "file", "path", "url",
        "uri", "redirect", "next", "callback", "cmd", "exec", "token", "key", "secret", "filter",
        "query", "sql", "domain", "project",
    ]
    .iter()
    .any(|k| low == *k || low.contains(k))
}

fn normalize_har_path(raw_path: &str) -> String {
    static UUID_RE: OnceLock<Regex> = OnceLock::new();
    let uuid_re = UUID_RE.get_or_init(|| {
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap()
    });
    let no_q = raw_path.split(['?', '#']).next().unwrap_or("/");
    let mut segs = Vec::new();
    for seg in no_q.split('/').filter(|s| !s.is_empty()) {
        if uuid_re.is_match(seg)
            || seg.bytes().all(|b| b.is_ascii_digit())
            || (seg.len() >= 16 && seg.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            segs.push(":id");
        } else {
            segs.push(seg);
        }
    }
    if segs.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segs.join("/"))
    }
}

/// Analyze HTTP Archive (`.har`) traffic into a normalized API endpoint & AuthZ/CORS posture surface matrix (never emits raw tokens/cookies).
pub fn extract_har_routes_md(
    text: &str,
    label: &str,
    query: Option<&str>,
) -> Option<(String, serde_json::Value)> {
    let trimmed = text.trim_start_matches('\u{FEFF}').trim();
    if !trimmed.starts_with('{') {
        return None;
    }
    let root = serde_json::from_str::<Value>(trimmed).ok()?;
    let entries = root.pointer("/log/entries").and_then(Value::as_array)?;

    #[derive(Default)]
    struct EpStat {
        hits: usize,
        statuses: std::collections::BTreeSet<u64>,
        auth_headers: std::collections::BTreeSet<String>,
        params: std::collections::BTreeSet<String>,
        min_body: Option<u64>,
        max_body: u64,
        unauth_2xx: bool,
        cors_creds: bool,
    }

    let mut grouped: std::collections::BTreeMap<(String, String), EpStat> =
        std::collections::BTreeMap::new();
    let mut hosts: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let q_low = query
        .map(|q| q.trim().to_ascii_lowercase())
        .filter(|q| !q.is_empty());

    for ent in entries {
        let method = ent
            .pointer("/request/method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let raw_url = ent
            .pointer("/request/url")
            .and_then(Value::as_str)
            .unwrap_or("");
        if raw_url.is_empty() {
            continue;
        }
        let (host, raw_path_and_q) = if let Some(after) = raw_url.split_once("://").map(|x| x.1) {
            match after.find('/') {
                Some(idx) => (after[..idx].to_string(), &after[idx..]),
                None => (after.to_string(), "/"),
            }
        } else {
            (String::new(), raw_url)
        };
        if !host.is_empty() {
            hosts.insert(host.clone());
        }
        let norm_path = normalize_har_path(raw_path_and_q);
        let endpoint = if host.is_empty() {
            norm_path
        } else {
            format!("{host}{norm_path}")
        };

        let status = ent
            .pointer("/response/status")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        let mut req_auth: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        if let Some(hdrs) = ent.pointer("/request/headers").and_then(Value::as_array) {
            for h in hdrs {
                let nm = h.get("name").and_then(Value::as_str).unwrap_or("").trim();
                let low = nm.to_ascii_lowercase();
                if matches!(
                    low.as_str(),
                    "authorization"
                        | "cookie"
                        | "x-auth-token"
                        | "x-csrf-token"
                        | "x-xsrf-token"
                        | "x-api-key"
                        | "proxy-authorization"
                ) || low.contains("token")
                {
                    req_auth.insert(nm.to_string());
                }
            }
        }
        let mut params: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        if let Some((_, qs)) = raw_path_and_q.split_once('?') {
            for kv in qs.split('&') {
                let k = kv.split('=').next().unwrap_or("").trim();
                if !k.is_empty() {
                    params.insert(k.to_string());
                }
            }
        }
        if let Some(qarr) = ent
            .pointer("/request/queryString")
            .and_then(Value::as_array)
        {
            for q in qarr {
                if let Some(nm) = q.get("name").and_then(Value::as_str).map(str::trim) {
                    if !nm.is_empty() {
                        params.insert(nm.to_string());
                    }
                }
            }
        }
        if let Some(post_txt) = ent
            .pointer("/request/postData/text")
            .and_then(Value::as_str)
        {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(post_txt) {
                for k in map.keys().take(24) {
                    params.insert(k.clone());
                }
            }
        }

        let mut acao = String::new();
        let mut acac = false;
        if let Some(rhdrs) = ent.pointer("/response/headers").and_then(Value::as_array) {
            for h in rhdrs {
                let low = h
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let val = h.get("value").and_then(Value::as_str).unwrap_or("").trim();
                if low == "access-control-allow-origin" {
                    acao = val.to_string();
                } else if low == "access-control-allow-credentials"
                    && val.eq_ignore_ascii_case("true")
                {
                    acac = true;
                }
            }
        }

        if let Some(ref q) = q_low {
            let p_joined = params.iter().cloned().collect::<Vec<_>>().join(" ");
            let hay = format!("{method} {endpoint} {p_joined}").to_ascii_lowercase();
            if !hay.contains(q) {
                continue;
            }
        }

        let st = grouped.entry((method, endpoint)).or_default();
        st.hits += 1;
        if status > 0 {
            st.statuses.insert(status);
        }
        st.auth_headers.extend(req_auth.iter().cloned());
        st.params.extend(params);
        if (200..=299).contains(&status) && req_auth.is_empty() {
            st.unauth_2xx = true;
        }
        if !acao.is_empty() && acac {
            st.cors_creds = true;
        }
        if let Some(bsz) = ent
            .pointer("/response/bodySize")
            .and_then(Value::as_i64)
            .filter(|&v| v >= 0)
            .map(|v| v as u64)
            .or_else(|| {
                ent.pointer("/response/content/size")
                    .and_then(Value::as_u64)
            })
        {
            st.min_body = Some(st.min_body.map(|m| m.min(bsz)).unwrap_or(bsz));
            st.max_body = st.max_body.max(bsz);
        }
    }

    let mut rows: Vec<(u8, String, String, EpStat)> = grouped
        .into_iter()
        .map(|((m, ep), st)| {
            let sens = st.params.iter().any(|p| is_sensitive_param_name(p));
            let score = (st.cors_creds as u8) * 8
                + (st.unauth_2xx as u8) * 6
                + (matches!(m.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") as u8) * 4
                + (sens as u8) * 2;
            (score, m, ep, st)
        })
        .collect();
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.2.cmp(&b.2)));

    let total_eps = rows.len();
    let mut unauth_n = 0usize;
    let mut cors_n = 0usize;
    let mut sens_n = 0usize;
    let mut md_lines = vec![format!(
        "## HAR API Attack Surface `{label}` ({} entries -> {total_eps} normalized endpoints | {} host(s))",
        entries.len(),
        hosts.len()
    )];
    let mut ep_json = Vec::new();
    for (_, method, ep, st) in rows.into_iter().take(80) {
        let mut flags = Vec::new();
        if st.unauth_2xx {
            unauth_n += 1;
            flags.push("UNAUTH-2XX");
        }
        if st.cors_creds {
            cors_n += 1;
            flags.push("CORS-CREDS-EXPOSED");
        }
        let sens_params: Vec<String> = st
            .params
            .iter()
            .filter(|p| is_sensitive_param_name(p))
            .cloned()
            .collect();
        if !sens_params.is_empty() {
            sens_n += 1;
            flags.push("SENSITIVE-PARAMS");
        }
        let flag_str = if flags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", flags.join(","))
        };
        let status_s = st
            .statuses
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("/");
        let auth_s = if st.auth_headers.is_empty() {
            "none".to_string()
        } else {
            st.auth_headers
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        };
        let param_s = if st.params.is_empty() {
            "-".to_string()
        } else {
            st.params
                .iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        };
        let size_s = match st.min_body {
            Some(mn) if mn != st.max_body => format!("{mn}..{}B", st.max_body),
            Some(mn) => format!("{mn}B"),
            None => "?B".to_string(),
        };
        md_lines.push(format!(
            "- `{method}` `{ep}` (hits={} status=[{status_s}] size={size_s} auth=[{auth_s}] params=[{param_s}]){flag_str}",
            st.hits
        ));
        ep_json.push(serde_json::json!({
            "method": method,
            "endpoint": ep,
            "hits": st.hits,
            "statuses": st.statuses.into_iter().collect::<Vec<_>>(),
            "auth_headers": st.auth_headers.into_iter().collect::<Vec<_>>(),
            "params": st.params.into_iter().collect::<Vec<_>>(),
            "flags": flags,
        }));
    }
    let jv = serde_json::json!({
        "entries_total": entries.len(),
        "endpoints_total": total_eps,
        "hosts": hosts.into_iter().collect::<Vec<_>>(),
        "counts": {
            "unauth_2xx": unauth_n,
            "cors_creds_exposed": cors_n,
            "sensitive_params": sens_n,
        },
        "endpoints": ep_json,
    });
    Some((md_lines.join("\n"), jv))
}

pub fn extract_js_routes_md(
    text: &str,
    label: &str,
    query: Option<&str>,
) -> (String, serde_json::Value) {
    let re = js_route_re();
    let scan_end = {
        let limit = text.len().min(24 * 1024 * 1024);
        let mut e = limit;
        while e > 0 && !text.is_char_boundary(e) {
            e -= 1;
        }
        e
    };
    let slice = &text[..scan_end];
    let q_low = query
        .map(|q| q.trim().to_ascii_lowercase())
        .filter(|q| !q.is_empty());
    let matches_q = |s: &str| -> bool {
        match &q_low {
            Some(q) => s.to_ascii_lowercase().contains(q),
            None => true,
        }
    };

    let mut route_map: std::collections::BTreeMap<String, (String, usize, Vec<&'static str>)> =
        std::collections::BTreeMap::new();

    let mut add_route = |method: &str, raw_path: &str, off: usize| {
        let p = raw_path.trim();
        if p.len() < 3 || p.contains("//") && !p.starts_with("http") {
            return;
        }
        if !matches_q(p) && !matches_q(method) {
            return;
        }
        let mut tags: Vec<&'static str> = Vec::new();
        if p.contains(':') || p.contains('{') || p.contains("${") {
            tags.push("PARAM");
        }
        let pl = p.to_ascii_lowercase();
        if [
            "admin", "delete", "remove", "grant", "role", "perm", "token", "secret", "upload",
            "export", "import", "proxy", "internal", "transfer", "billing", "passwd", "password",
        ]
        .iter()
        .any(|kw| pl.contains(kw))
        {
            tags.push("SENSITIVE");
        }
        let m_up = method.to_ascii_uppercase();
        route_map
            .entry(p.to_string())
            .and_modify(|e| {
                if e.0 == "ANY" && m_up != "ANY" {
                    e.0 = m_up.clone();
                }
            })
            .or_insert((m_up, off, tags));
    };

    for cap in re.http_call.captures_iter(slice) {
        let method = cap
            .get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str())
            .unwrap_or("FETCH");
        if let Some(pm) = cap.get(4) {
            add_route(method, pm.as_str(), pm.start());
        }
    }
    for cap in re.api_path.captures_iter(slice) {
        if let Some(pm) = cap.get(1) {
            let start = pm.start();
            let ctx_start = start.saturating_sub(48);
            let mut cs = ctx_start;
            while cs < start && !slice.is_char_boundary(cs) {
                cs += 1;
            }
            let prefix = slice[cs..start].to_ascii_lowercase();
            let method = if prefix.contains("delete") {
                "DELETE"
            } else if prefix.contains("put") {
                "PUT"
            } else if prefix.contains("patch") {
                "PATCH"
            } else if prefix.contains("post") {
                "POST"
            } else if prefix.contains("get") {
                "GET"
            } else {
                "ANY"
            };
            add_route(method, pm.as_str(), start);
        }
    }

    let mut post_messages: Vec<serde_json::Value> = Vec::new();
    for m in re.post_msg.find_iter(slice).take(30) {
        let hard_end = {
            let mut e = (m.end() + 480).min(slice.len());
            while e > m.end() && !slice.is_char_boundary(e) {
                e -= 1;
            }
            e
        };
        let raw_win = &slice[m.start()..hard_end];
        // Bound the scan to this listener's own `{ ... }` callback body so adjacent minified
        // listeners never leak their `.origin` check into an unguarded sibling handler.
        let bounded_len = if let Some(first_brace) = raw_win.find('{') {
            let mut depth = 0i32;
            let mut end_rel = raw_win.len();
            for (bi, ch) in raw_win[first_brace..].char_indices() {
                if ch == '{' {
                    depth += 1;
                } else if ch == '}' {
                    depth -= 1;
                    if depth == 0 {
                        end_rel = (first_brace + bi + 1).min(raw_win.len());
                        break;
                    }
                }
            }
            end_rel
        } else {
            raw_win[m.len()..]
                .find("addEventListener")
                .map(|p| m.len() + p)
                .unwrap_or(raw_win.len())
        };
        let window = &raw_win[..bounded_len];
        let win_low = window.to_ascii_lowercase();
        let has_origin_check = win_low.contains(".origin")
            || win_low.contains("allowedorigin")
            || win_low.contains("trustedorigin")
            || win_low.contains("origin===")
            || win_low.contains("origin ==")
            || win_low.contains("origin!==");
        let snip: String = window
            .replace(['\r', '\n'], " ")
            .chars()
            .take(120)
            .collect();
        if !matches_q(&snip) && !matches_q("postmessage") {
            continue;
        }
        post_messages.push(serde_json::json!({
            "line": byte_line_col(slice, m.start()),
            "offset": m.start(),
            "missing_origin_check": !has_origin_check,
            "snippet": snip,
        }));
    }

    let mut dom_sinks: Vec<serde_json::Value> = Vec::new();
    let mut seen_sink_off = std::collections::HashSet::new();
    for m in re.dom_sink.find_iter(slice) {
        if dom_sinks.len() >= 40 {
            break;
        }
        let w_start = {
            let mut s = m.start().saturating_sub(24);
            while s < m.start() && !slice.is_char_boundary(s) {
                s += 1;
            }
            s
        };
        let w_end = {
            let mut e = (m.end() + 96).min(slice.len());
            while e > m.end() && !slice.is_char_boundary(e) {
                e -= 1;
            }
            e
        };
        let snip: String = slice[w_start..w_end]
            .replace(['\r', '\n'], " ")
            .chars()
            .take(110)
            .collect();
        if !matches_q(&snip) {
            continue;
        }
        if seen_sink_off.insert(m.start() / 32) {
            dom_sinks.push(serde_json::json!({
                "sink": m.as_str().trim(),
                "line": byte_line_col(slice, m.start()),
                "offset": m.start(),
                "snippet": snip,
            }));
        }
    }

    let mut origins: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for cap in re.ext_origin.captures_iter(slice) {
        if let Some(hm) = cap.get(1) {
            let host = hm.as_str().to_ascii_lowercase();
            if matches!(
                host.as_str(),
                "www.w3.org"
                    | "schemas.openxmlformats.org"
                    | "purl.org"
                    | "ns.adobe.com"
                    | "example.com"
            ) {
                continue;
            }
            if matches_q(&host) {
                origins.insert(host);
            }
        }
    }

    let mut local_ipc_sinks: Vec<serde_json::Value> = Vec::new();
    let mut seen_ipc_off = std::collections::HashSet::new();
    for m in re.local_server_ipc.find_iter(slice) {
        if local_ipc_sinks.len() >= 30 {
            break;
        }
        let hard_end = {
            let mut e = (m.end() + 420).min(slice.len());
            while e > m.end() && !slice.is_char_boundary(e) {
                e -= 1;
            }
            e
        };
        let raw_win = &slice[m.start()..hard_end];
        let bounded_len = if let Some(fb) = raw_win.find('{') {
            let mut depth = 0i32;
            let mut end_rel = raw_win.len();
            for (bi, ch) in raw_win[fb..].char_indices() {
                if ch == '{' {
                    depth += 1;
                } else if ch == '}' {
                    depth -= 1;
                    if depth == 0 {
                        end_rel = (fb + bi + 1).min(raw_win.len());
                        break;
                    }
                }
            }
            end_rel
        } else {
            raw_win.len().min(180)
        };
        let win = &raw_win[..bounded_len];
        let kind_s = m.as_str().trim();
        let is_server = kind_s.contains("createServer")
            || kind_s.contains("WebSocketServer")
            || kind_s.contains("oauth/callback");
        let win_low = win.to_ascii_lowercase();
        let missing_auth = is_server
            && !win_low.contains("origin")
            && !win_low.contains("authorization")
            && !win_low.contains("csrf")
            && !win_low.contains("state")
            && !win_low.contains("token");
        let snip: String = win.replace(['\r', '\n'], " ").chars().take(120).collect();
        if !matches_q(&snip) && !matches_q(kind_s) {
            continue;
        }
        if seen_ipc_off.insert(m.start() / 24) {
            local_ipc_sinks.push(serde_json::json!({
                "kind": kind_s,
                "line": byte_line_col(slice, m.start()),
                "offset": m.start(),
                "missing_origin_or_auth": missing_auth,
                "snippet": snip,
            }));
        }
    }

    let mut lazy_chunks: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for cap in re.lazy_chunk.captures_iter(slice) {
        if lazy_chunks.len() >= 50 {
            break;
        }
        let item = if let Some(m1) = cap.get(1) {
            m1.as_str().to_string()
        } else if let (Some(id), Some(h)) = (cap.get(2), cap.get(3)) {
            format!("{}.{}.js", id.as_str(), h.as_str())
        } else {
            continue;
        };
        if matches_q(&item) {
            lazy_chunks.insert(item);
        }
    }

    let mut custom_headers: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for cap in re.custom_header.captures_iter(slice) {
        if let Some(hm) = cap.get(1) {
            let h = hm.as_str().to_string();
            if matches_q(&h) {
                custom_headers.insert(h);
            }
        }
    }

    let mut routes_json: Vec<serde_json::Value> = Vec::new();
    let mut route_lines: Vec<String> = Vec::new();
    for (p, (method, off, tags)) in route_map.iter().take(120) {
        let ln = byte_line_col(slice, *off);
        let tag_str = if tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", tags.join(","))
        };
        route_lines.push(format!("- `{method}` `{p}`{tag_str} (L{ln}, @{off})"));
        routes_json.push(serde_json::json!({
            "method": method,
            "path": p,
            "line": ln,
            "offset": off,
            "tags": tags,
        }));
    }

    let mut out = vec![format!(
        "# JS/API Surface `{label}` ({} route(s) | {} postMessage | {} local-server/IPC | {} DOM sink(s) | {} lazy chunk(s) | {} header(s) | {} origin(s))",
        route_map.len(),
        post_messages.len(),
        local_ipc_sinks.len(),
        dom_sinks.len(),
        lazy_chunks.len(),
        custom_headers.len(),
        origins.len()
    )];
    if !route_lines.is_empty() {
        out.push(format!(
            "\n## API / HTTP Routes (showing {}/{})\n{}",
            route_lines.len(),
            route_map.len(),
            route_lines.join("\n")
        ));
    }
    if !post_messages.is_empty() {
        let pm_lines: Vec<String> = post_messages
            .iter()
            .map(|p| {
                let flag = if p["missing_origin_check"].as_bool().unwrap_or(false) {
                    " **[MISSING-ORIGIN-CHECK]**"
                } else {
                    " [origin-checked]"
                };
                format!(
                    "- L{} (@{}){flag}: `{}`",
                    p["line"],
                    p["offset"],
                    p["snippet"].as_str().unwrap_or("")
                )
            })
            .collect();
        out.push(format!(
            "\n## postMessage Listeners\n{}",
            pm_lines.join("\n")
        ));
    }
    if !dom_sinks.is_empty() {
        let sk_lines: Vec<String> = dom_sinks
            .iter()
            .take(25)
            .map(|s| {
                format!(
                    "- `{}` (L{}, @{}): `{}`",
                    s["sink"].as_str().unwrap_or(""),
                    s["line"],
                    s["offset"],
                    s["snippet"].as_str().unwrap_or("")
                )
            })
            .collect();
        out.push(format!(
            "\n## Client-Side DOM / Eval / Navigation Sinks (showing {}/{})\n{}",
            sk_lines.len(),
            dom_sinks.len(),
            sk_lines.join("\n")
        ));
    }
    if !local_ipc_sinks.is_empty() {
        let ipc_lines: Vec<String> = local_ipc_sinks
            .iter()
            .take(20)
            .map(|s| {
                let flag = if s["missing_origin_or_auth"].as_bool().unwrap_or(false) {
                    " **[NO-ORIGIN-OR-AUTH-CHECK]**"
                } else {
                    ""
                };
                format!(
                    "- `{}` (L{}, @{}){flag}: `{}`",
                    s["kind"].as_str().unwrap_or(""),
                    s["line"],
                    s["offset"],
                    s["snippet"].as_str().unwrap_or("")
                )
            })
            .collect();
        out.push(format!(
            "\n## Local Server / IPC / Process Exec Sinks\n{}",
            ipc_lines.join("\n")
        ));
    }
    if !lazy_chunks.is_empty() {
        let ch_list: Vec<String> = lazy_chunks
            .iter()
            .take(30)
            .map(|c| format!("`{c}`"))
            .collect();
        out.push(format!(
            "\n## Lazy Webpack / Vite Chunks ({})\n{}",
            lazy_chunks.len(),
            ch_list.join(", ")
        ));
    }
    if !custom_headers.is_empty() {
        let h_list: Vec<String> = custom_headers
            .iter()
            .take(25)
            .map(|h| format!("`{h}`"))
            .collect();
        out.push(format!(
            "\n## Custom Auth / Tenant Headers\n{}",
            h_list.join(", ")
        ));
    }
    if !origins.is_empty() {
        let org_list: Vec<String> = origins.iter().take(40).map(|o| format!("`{o}`")).collect();
        out.push(format!("\n## External Origins\n{}", org_list.join(", ")));
    }

    let origins_vec: Vec<String> = origins.into_iter().take(80).collect();
    let chunks_vec: Vec<String> = lazy_chunks.into_iter().take(50).collect();
    let headers_vec: Vec<String> = custom_headers.into_iter().take(30).collect();
    let jv = serde_json::json!({
        "target": label,
        "counts": {
            "routes": route_map.len(),
            "post_message": post_messages.len(),
            "local_server_ipc": local_ipc_sinks.len(),
            "dom_sinks": dom_sinks.len(),
            "lazy_chunks": chunks_vec.len(),
            "custom_headers": headers_vec.len(),
            "origins": origins_vec.len(),
        },
        "routes": routes_json,
        "post_message_handlers": post_messages,
        "local_server_and_ipc": local_ipc_sinks,
        "client_sinks": dom_sinks,
        "lazy_chunks": chunks_vec,
        "custom_headers": headers_vec,
        "external_origins": origins_vec,
    });
    (out.join("\n"), jv)
}

fn redact_secret(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= 8 {
        return "***".to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}...{tail} ({} chars)", chars.len())
}

fn is_placeholder_secret(val: &str) -> bool {
    let low = val.trim().to_ascii_lowercase();
    low.len() < 8
        || low.contains("example")
        || low.contains("placeholder")
        || low.contains("changeme")
        || low.contains("your_")
        || low.contains("your-")
        || low.contains("dummy")
        || low.contains("redacted")
        || low.contains("${")
        || low.contains("{{")
        || low.starts_with('<')
        || low
            .chars()
            .all(|c| c == '*' || c == 'x' || c == '0' || c == '-')
}

/// Pure-Rust `<15ms` defensive hardcoded-secret & credential hygiene scanner (`--secrets`).
/// Always redacts matched secret values in output so credentials are never echoed verbatim.
pub fn scan_secrets_md(
    text: &str,
    label: &str,
    query: Option<&str>,
) -> (String, serde_json::Value) {
    static PATS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    let pats = PATS.get_or_init(|| {
        vec![
            (
                "PEM_PRIVATE_KEY",
                Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----").unwrap(),
            ),
            (
                "CLOUD_ACCESS_KEY",
                Regex::new(r"\b((?:AKIA|ASIA|LTAI)[0-9A-Z]{16,24})\b").unwrap(),
            ),
            (
                "SCM_OR_SAAS_TOKEN",
                Regex::new(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{24,}|glpat-[A-Za-z0-9_-]{18,}|xox[baprs]-[A-Za-z0-9-]{16,}|sk-(?:live|proj|test)?-?[A-Za-z0-9]{20,})\b").unwrap(),
            ),
            (
                "EMBEDDED_URI_CRED",
                Regex::new(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|https?)://([^:\s/'\x22@]{2,32}:[^@\s/'\x22]{6,64})@[A-Za-z0-9.-]{3,}").unwrap(),
            ),
            (
                "HARDCODED_AUTH_HEADER",
                Regex::new(r#"(?i)(?:authorization['"]?\s*[:=]\s*['"])((?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{16,})['"]"#).unwrap(),
            ),
            (
                "HARDCODED_SECRET_ASSIGN",
                Regex::new(r#"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?secret|client[_-]?secret|private[_-]?key|db[_-]?pass(?:word)?|jwt[_-]?secret)\b['"]?\s*[:=]\s*['"]([^'"\r\n\s]{12,128})['"]"#).unwrap(),
            ),
        ]
    });

    let scan_end = {
        let mut e = text.len().min(16 * 1024 * 1024);
        while e > 0 && !text.is_char_boundary(e) {
            e -= 1;
        }
        e
    };
    let slice = &text[..scan_end];
    let q_low = query
        .map(|q| q.trim().to_ascii_lowercase())
        .filter(|q| !q.is_empty());

    let mut seen = std::collections::HashSet::new();
    let mut findings: Vec<serde_json::Value> = Vec::new();
    for (kind, re) in pats {
        for cap in re.captures_iter(slice) {
            if findings.len() >= 80 {
                break;
            }
            let Some(m0) = cap.get(0) else { continue };
            let raw_val = cap.get(1).map(|m| m.as_str()).unwrap_or(m0.as_str());
            if *kind != "PEM_PRIVATE_KEY" && is_placeholder_secret(raw_val) {
                continue;
            }
            let redacted = if *kind == "PEM_PRIVATE_KEY" {
                m0.as_str().to_string()
            } else {
                redact_secret(raw_val)
            };
            let ln = byte_line_col(slice, m0.start());
            if let Some(ref q) = q_low {
                if !kind.to_ascii_lowercase().contains(q)
                    && !redacted.to_ascii_lowercase().contains(q)
                {
                    continue;
                }
            }
            let dedup_key = format!("{kind}:{ln}:{}", m0.start() / 16);
            if !seen.insert(dedup_key) {
                continue;
            }
            findings.push(serde_json::json!({
                "kind": kind,
                "line": ln,
                "offset": m0.start(),
                "redacted": redacted,
            }));
        }
    }

    let mut out = vec![format!(
        "# Secret Hygiene Audit `{label}` ({} finding(s), all values redacted)",
        findings.len()
    )];
    if findings.is_empty() {
        out.push("*(0 hardcoded secret/credential patterns detected)*".to_string());
    } else {
        for f in &findings {
            out.push(format!(
                "- `{}` (L{}, @{}): `{}`",
                f["kind"].as_str().unwrap_or(""),
                f["line"],
                f["offset"],
                f["redacted"].as_str().unwrap_or("")
            ));
        }
    }
    let jv = serde_json::json!({
        "target": label,
        "count": findings.len(),
        "findings": findings,
    });
    (out.join("\n"), jv)
}

fn json_key_child_path(parent: &str, key: &str) -> String {
    let simple = !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if simple {
        format!("{parent}.{key}")
    } else {
        let esc = key.replace('"', "\\\"");
        format!("{parent}[\"{esc}\"]")
    }
}

fn json_preview_val(v: &Value) -> String {
    let raw = match v {
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| format!("{s:?}")),
        Value::Null | Value::Bool(_) | Value::Number(_) => v.to_string(),
        Value::Array(a) => format!("[{} item(s)]", a.len()),
        Value::Object(m) => format!("{{{} key(s)}}", m.len()),
    };
    let clean = raw.replace(['\r', '\n'], " ");
    if clean.chars().count() > 120 {
        let cut: String = clean.chars().take(119).collect();
        format!("{cut}…")
    } else {
        clean
    }
}

#[derive(Default)]
struct JsonDiffAcc {
    added: Vec<(String, String)>,
    removed: Vec<(String, String)>,
    changed: Vec<(String, String, String)>,
    unchanged_leaves: usize,
    truncated: bool,
}

fn collect_json_diff(old_v: &Value, new_v: &Value, path: &str, acc: &mut JsonDiffAcc) {
    const CAP: usize = 120;
    match (old_v, new_v) {
        (Value::Object(om), Value::Object(nm)) => {
            let mut keys: Vec<&String> = om.keys().collect();
            for k in nm.keys() {
                if !om.contains_key(k) {
                    keys.push(k);
                }
            }
            keys.sort();
            for k in keys {
                let cp = json_key_child_path(path, k);
                match (om.get(k), nm.get(k)) {
                    (None, Some(nv)) => {
                        if acc.added.len() < CAP {
                            acc.added.push((cp, json_preview_val(nv)));
                        } else {
                            acc.truncated = true;
                        }
                    }
                    (Some(ov), None) => {
                        if acc.removed.len() < CAP {
                            acc.removed.push((cp, json_preview_val(ov)));
                        } else {
                            acc.truncated = true;
                        }
                    }
                    (Some(ov), Some(nv)) => collect_json_diff(ov, nv, &cp, acc),
                    (None, None) => {}
                }
            }
        }
        (Value::Array(oa), Value::Array(na)) => {
            let max_len = oa.len().max(na.len());
            for idx in 0..max_len {
                let cp = format!("{path}[{idx}]");
                match (oa.get(idx), na.get(idx)) {
                    (None, Some(nv)) => {
                        if acc.added.len() < CAP {
                            acc.added.push((cp, json_preview_val(nv)));
                        } else {
                            acc.truncated = true;
                        }
                    }
                    (Some(ov), None) => {
                        if acc.removed.len() < CAP {
                            acc.removed.push((cp, json_preview_val(ov)));
                        } else {
                            acc.truncated = true;
                        }
                    }
                    (Some(ov), Some(nv)) => collect_json_diff(ov, nv, &cp, acc),
                    (None, None) => {}
                }
            }
        }
        _ => {
            if old_v == new_v {
                acc.unchanged_leaves += 1;
            } else if acc.changed.len() < CAP {
                acc.changed.push((
                    path.to_string(),
                    json_preview_val(old_v),
                    json_preview_val(new_v),
                ));
            } else {
                acc.truncated = true;
            }
        }
    }
}

/// Pure-Rust semantic structural JSON diff ignoring whitespace and object key ordering.
pub fn diff_json_structural_md(
    new_val: &Value,
    old_val: &Value,
    new_label: &str,
    old_label: &str,
) -> (String, Value) {
    let mut acc = JsonDiffAcc::default();
    collect_json_diff(old_val, new_val, "$", &mut acc);
    let mut lines = vec![format!(
        "## Structural JSON Diff: `{new_label}` vs `{old_label}` (+{} added, -{} removed, ~{} changed, {} unchanged)",
        acc.added.len(),
        acc.removed.len(),
        acc.changed.len(),
        acc.unchanged_leaves
    )];
    if acc.added.is_empty() && acc.removed.is_empty() && acc.changed.is_empty() {
        lines.push("*(0 semantic differences — formatting or key order only)*".to_string());
    } else {
        if !acc.added.is_empty() {
            lines.push("### Added".to_string());
            for (p, v) in &acc.added {
                lines.push(format!("- `{p}`: `{v}`"));
            }
        }
        if !acc.removed.is_empty() {
            lines.push("### Removed".to_string());
            for (p, v) in &acc.removed {
                lines.push(format!("- `{p}`: `{v}`"));
            }
        }
        if !acc.changed.is_empty() {
            lines.push("### Changed".to_string());
            for (p, ov, nv) in &acc.changed {
                lines.push(format!("- `{p}`: `{ov}` -> `{nv}`"));
            }
        }
        if acc.truncated {
            lines.push("*(diff output capped at 120 entries per category)*".to_string());
        }
    }
    let jv = serde_json::json!({
        "added": acc.added.iter().map(|(p, v)| serde_json::json!({"path": p, "value": v})).collect::<Vec<_>>(),
        "removed": acc.removed.iter().map(|(p, v)| serde_json::json!({"path": p, "value": v})).collect::<Vec<_>>(),
        "changed": acc.changed.iter().map(|(p, o, n)| serde_json::json!({"path": p, "old": o, "new": n})).collect::<Vec<_>>(),
        "truncated": acc.truncated,
        "counts": {
            "added": acc.added.len(),
            "removed": acc.removed.len(),
            "changed": acc.changed.len(),
            "unchanged": acc.unchanged_leaves,
        }
    });
    (lines.join("\n"), jv)
}

#[derive(Debug, Clone)]
struct RawXmlNode {
    name: String,
    attrs: serde_json::Map<String, Value>,
    children: Vec<RawXmlNode>,
    text_buf: String,
}

fn decode_xml_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    let bytes = raw.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(semi_rel) = raw[i..].find(';') {
                if semi_rel <= 12 {
                    let ent = &raw[i + 1..i + semi_rel];
                    let decoded = match ent {
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "amp" => Some('&'),
                        "quot" => Some('"'),
                        "apos" => Some('\''),
                        _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                            u32::from_str_radix(&ent[2..], 16)
                                .ok()
                                .and_then(char::from_u32)
                        }
                        _ if ent.starts_with('#') => {
                            ent[1..].parse::<u32>().ok().and_then(char::from_u32)
                        }
                        _ => None,
                    };
                    if let Some(ch) = decoded {
                        out.push(ch);
                        i += semi_rel + 1;
                        continue;
                    }
                }
            }
        }
        let ch = raw[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn parse_xml_attributes(raw_attrs: &str) -> serde_json::Map<String, Value> {
    let mut attrs = serde_json::Map::new();
    let bytes = raw_attrs.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let k_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' {
            i += 1;
        }
        let key = raw_attrs[k_start..i].trim();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let q = bytes[i];
                i += 1;
                let v_start = i;
                while i < bytes.len() && bytes[i] != q {
                    i += 1;
                }
                let val = decode_xml_entities(&raw_attrs[v_start..i]);
                if i < bytes.len() {
                    i += 1;
                }
                if !key.is_empty() {
                    attrs.insert(format!("@{key}"), Value::String(val));
                }
            } else {
                let v_start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                let val = decode_xml_entities(&raw_attrs[v_start..i]);
                if !key.is_empty() {
                    attrs.insert(format!("@{key}"), Value::String(val));
                }
            }
        } else if !key.is_empty() {
            attrs.insert(format!("@{key}"), Value::Bool(true));
        }
    }
    attrs
}

fn plist_node_to_json(node: &RawXmlNode) -> Value {
    match node.name.as_str() {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "integer" => {
            let t = node.text_buf.trim();
            if let Ok(n) = t.parse::<i64>() {
                Value::Number(n.into())
            } else {
                Value::String(t.to_string())
            }
        }
        "real" => {
            let t = node.text_buf.trim();
            if let Some(num) = t.parse::<f64>().ok().and_then(serde_json::Number::from_f64) {
                Value::Number(num)
            } else {
                Value::String(t.to_string())
            }
        }
        "array" => Value::Array(node.children.iter().map(plist_node_to_json).collect()),
        "dict" => {
            let mut map = serde_json::Map::new();
            let mut idx = 0usize;
            while idx < node.children.len() {
                if node.children[idx].name == "key" {
                    let k = decode_xml_entities(node.children[idx].text_buf.trim());
                    if let Some(v_node) = node.children.get(idx + 1) {
                        map.insert(k, plist_node_to_json(v_node));
                        idx += 2;
                        continue;
                    }
                }
                idx += 1;
            }
            Value::Object(map)
        }
        _ => Value::String(decode_xml_entities(node.text_buf.trim())),
    }
}

fn xml_node_to_json(node: &RawXmlNode) -> Value {
    let trimmed_text = decode_xml_entities(node.text_buf.trim());
    if node.attrs.is_empty() && node.children.is_empty() {
        return Value::String(trimmed_text);
    }
    let mut map = node.attrs.clone();
    for ch in &node.children {
        let child_val = xml_node_to_json(ch);
        match map.get_mut(&ch.name) {
            Some(Value::Array(arr)) => arr.push(child_val),
            Some(existing) => {
                let prev = std::mem::replace(existing, Value::Null);
                *existing = Value::Array(vec![prev, child_val]);
            }
            None => {
                map.insert(ch.name.clone(), child_val);
            }
        }
    }
    if !trimmed_text.is_empty() {
        map.insert("#text".to_string(), Value::String(trimmed_text));
    }
    Value::Object(map)
}

/// Pure-Rust iterative XML parser supporting attributes (`@attr`), CDATA, entities, and Apple `.plist`.
pub fn parse_xml_to_json(text: &str) -> Option<Value> {
    let src = text.trim_start_matches('\u{FEFF}').trim();
    if !src.starts_with('<') {
        return None;
    }
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut stack: Vec<RawXmlNode> = Vec::new();
    let mut root: Option<RawXmlNode> = None;

    while i < len {
        if bytes[i] == b'<' {
            if src[i..].starts_with("<!--") {
                let end = src[i + 4..].find("-->")?;
                i += 4 + end + 3;
                continue;
            }
            if src[i..].starts_with("<![CDATA[") {
                let end = src[i + 9..].find("]]>")?;
                let inner = &src[i + 9..i + 9 + end];
                if let Some(top) = stack.last_mut() {
                    top.text_buf.push_str(inner);
                }
                i += 9 + end + 3;
                continue;
            }
            if src[i..].starts_with("<?") {
                let end = src[i + 2..].find("?>")?;
                i += 2 + end + 2;
                continue;
            }
            if src[i..].starts_with("<!") {
                // Scan <!DOCTYPE ... [ ... ]> cleanly
                let mut j = i + 2;
                let mut quote: Option<u8> = None;
                let mut bracket_depth = 0usize;
                while j < len {
                    let b = bytes[j];
                    if let Some(q) = quote {
                        if b == q {
                            quote = None;
                        }
                    } else if b == b'"' || b == b'\'' {
                        quote = Some(b);
                    } else if b == b'[' {
                        bracket_depth += 1;
                    } else if b == b']' && bracket_depth > 0 {
                        bracket_depth -= 1;
                    } else if b == b'>' && bracket_depth == 0 {
                        break;
                    }
                    j += 1;
                }
                if j >= len {
                    return None;
                }
                i = j + 1;
                continue;
            }
            if src[i..].starts_with("</") {
                let close_end = src[i + 2..].find('>')?;
                let close_name = src[i + 2..i + 2 + close_end].trim();
                let popped = stack.pop()?;
                if popped.name != close_name {
                    return None;
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(popped);
                } else {
                    root = Some(popped);
                }
                i += 2 + close_end + 1;
                continue;
            }

            // Opening or self-closing tag: locate closing `>` outside attribute quotes
            let mut j = i + 1;
            let mut quote: Option<u8> = None;
            while j < len {
                let b = bytes[j];
                if let Some(q) = quote {
                    if b == q {
                        quote = None;
                    }
                } else if b == b'"' || b == b'\'' {
                    quote = Some(b);
                } else if b == b'>' {
                    break;
                }
                j += 1;
            }
            if j >= len {
                return None;
            }
            let raw_tag = src[i + 1..j].trim();
            let self_closing = raw_tag.ends_with('/');
            let tag_inner = if self_closing {
                raw_tag[..raw_tag.len() - 1].trim_end()
            } else {
                raw_tag
            };
            let (name, attr_str) = match tag_inner.find(|c: char| c.is_ascii_whitespace()) {
                Some(pos) => (&tag_inner[..pos], tag_inner[pos..].trim()),
                None => (tag_inner, ""),
            };
            if name.is_empty()
                || !name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_' || c == ':')
            {
                return None;
            }
            let node = RawXmlNode {
                name: name.to_string(),
                attrs: if attr_str.is_empty() {
                    serde_json::Map::new()
                } else {
                    parse_xml_attributes(attr_str)
                },
                children: Vec::new(),
                text_buf: String::new(),
            };
            if self_closing {
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    root = Some(node);
                }
            } else {
                stack.push(node);
            }
            i = j + 1;
        } else {
            let next_lt = src[i..].find('<').map_or(len, |rel| i + rel);
            if let Some(top) = stack.last_mut() {
                top.text_buf.push_str(&src[i..next_lt]);
            } else if !src[i..next_lt].trim().is_empty() {
                return None;
            }
            i = next_lt;
        }
    }

    if !stack.is_empty() {
        return None;
    }
    let r = root?;
    if r.name == "plist" {
        if let Some(first_child) = r.children.first() {
            if matches!(first_child.name.as_str(), "dict" | "array") {
                return Some(plist_node_to_json(first_child));
            }
        }
    }
    let mut wrapper = serde_json::Map::new();
    let val = xml_node_to_json(&r);
    wrapper.insert(r.name, val);
    Some(Value::Object(wrapper))
}

fn split_toml_key_path(raw: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut esc = false;
    for ch in raw.chars() {
        if let Some(q) = quote {
            if esc {
                cur.push(ch);
                esc = false;
            } else if q == '"' && ch == '\\' {
                esc = true;
            } else if ch == q {
                quote = None;
            } else {
                cur.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if ch == '.' {
            let t = cur.trim().to_string();
            if !t.is_empty() {
                parts.push(t);
            }
            cur.clear();
        } else {
            cur.push(ch);
        }
    }
    let tail = cur.trim().to_string();
    if !tail.is_empty() {
        parts.push(tail);
    }
    parts
}

fn ensure_toml_table_mut<'a>(
    root: &'a mut serde_json::Map<String, Value>,
    path: &[String],
) -> &'a mut serde_json::Map<String, Value> {
    let mut cur = root;
    for seg in path {
        let entry = cur
            .entry(seg.clone())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Value::Array(arr) = entry {
            if !arr.last().is_some_and(|v| v.is_object()) {
                arr.push(Value::Object(serde_json::Map::new()));
            }
            cur = arr.last_mut().unwrap().as_object_mut().unwrap();
        } else {
            if !entry.is_object() {
                *entry = Value::Object(serde_json::Map::new());
            }
            cur = entry.as_object_mut().unwrap();
        }
    }
    cur
}

fn push_toml_array_table(root: &mut serde_json::Map<String, Value>, path: &[String]) {
    if path.is_empty() {
        return;
    }
    let parent = ensure_toml_table_mut(root, &path[..path.len() - 1]);
    let leaf = &path[path.len() - 1];
    let entry = parent
        .entry(leaf.clone())
        .or_insert_with(|| Value::Array(Vec::new()));
    if !entry.is_array() {
        *entry = Value::Array(Vec::new());
    }
    if let Value::Array(arr) = entry {
        arr.push(Value::Object(serde_json::Map::new()));
    }
}

fn unescape_toml_basic(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\n') | Some('\r') => {
                    while let Some(peek) = chars.clone().next() {
                        if peek.is_whitespace() {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn split_toml_items(inner: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = inner.as_bytes();
    let mut i = 0usize;
    let mut start = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut quote: Option<u8> = None;
    let mut esc = false;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if esc {
                esc = false;
            } else if q == b'"' && b == b'\\' {
                esc = true;
            } else if b == q {
                quote = None;
            }
        } else if b == b'"' || b == b'\'' {
            quote = Some(b);
        } else if b == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        } else if b == b'[' {
            bracket += 1;
        } else if b == b']' && bracket > 0 {
            bracket -= 1;
        } else if b == b'{' {
            brace += 1;
        } else if b == b'}' && brace > 0 {
            brace -= 1;
        } else if b == b',' && bracket == 0 && brace == 0 {
            let s = inner[start..i].trim();
            if !s.is_empty() {
                out.push(s);
            }
            start = i + 1;
        }
        i += 1;
    }
    let tail = inner[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

fn strip_toml_line_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    let mut esc = false;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if esc {
                esc = false;
            } else if q == b'"' && b == b'\\' {
                esc = true;
            } else if b == q {
                quote = None;
            }
        } else if b == b'"' || b == b'\'' {
            quote = Some(b);
        } else if b == b'#' {
            return &s[..i];
        }
        i += 1;
    }
    s
}

fn parse_toml_value(raw: &str) -> Value {
    let t = raw.trim();
    if let Some(inner) = t
        .strip_prefix("\"\"\"")
        .and_then(|s| s.strip_suffix("\"\"\""))
    {
        let trimmed = inner
            .strip_prefix("\r\n")
            .or_else(|| inner.strip_prefix('\n'))
            .unwrap_or(inner);
        return Value::String(unescape_toml_basic(trimmed));
    }
    if let Some(inner) = t.strip_prefix("'''").and_then(|s| s.strip_suffix("'''")) {
        let trimmed = inner
            .strip_prefix("\r\n")
            .or_else(|| inner.strip_prefix('\n'))
            .unwrap_or(inner);
        return Value::String(trimmed.to_string());
    }
    if let Some(inner) = t.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Value::String(unescape_toml_basic(inner));
    }
    if let Some(inner) = t.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return Value::String(inner.to_string());
    }
    if t == "true" {
        return Value::Bool(true);
    }
    if t == "false" {
        return Value::Bool(false);
    }
    if let Some(inner) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let items = split_toml_items(inner)
            .into_iter()
            .filter_map(|it| {
                let c = strip_toml_line_comment(it).trim();
                if c.is_empty() {
                    None
                } else {
                    Some(parse_toml_value(c))
                }
            })
            .collect();
        return Value::Array(items);
    }
    if let Some(inner) = t.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        let mut map = serde_json::Map::new();
        for item in split_toml_items(inner) {
            if let Some((k_raw, v_raw)) = split_unquoted_kv(item, b'=') {
                let kpath = split_toml_key_path(k_raw);
                if !kpath.is_empty() {
                    let tgt = ensure_toml_table_mut(&mut map, &kpath[..kpath.len() - 1]);
                    tgt.insert(kpath.last().unwrap().clone(), parse_toml_value(v_raw));
                }
            }
        }
        return Value::Object(map);
    }
    let clean_num = t.replace('_', "");
    if let Some(hex) = clean_num.strip_prefix("0x") {
        if let Ok(n) = i64::from_str_radix(hex, 16) {
            return Value::Number(n.into());
        }
    } else if let Some(oct) = clean_num.strip_prefix("0o") {
        if let Ok(n) = i64::from_str_radix(oct, 8) {
            return Value::Number(n.into());
        }
    } else if let Some(bin) = clean_num.strip_prefix("0b") {
        if let Ok(n) = i64::from_str_radix(bin, 2) {
            return Value::Number(n.into());
        }
    } else if let Ok(n) = clean_num.parse::<i64>() {
        return Value::Number(n.into());
    } else if let Ok(f) = clean_num.parse::<f64>() {
        if let Some(num) = serde_json::Number::from_f64(f) {
            return Value::Number(num);
        }
    }
    Value::String(t.to_string())
}

fn split_unquoted_kv(s: &str, delim: u8) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut quote: Option<u8> = None;
    let mut esc = false;
    for (i, &b) in bytes.iter().enumerate() {
        if let Some(q) = quote {
            if esc {
                esc = false;
            } else if q == b'"' && b == b'\\' {
                esc = true;
            } else if b == q {
                quote = None;
            }
        } else if b == b'"' || b == b'\'' {
            quote = Some(b);
        } else if b == delim {
            return Some((&s[..i], &s[i + 1..]));
        }
    }
    None
}

fn toml_balance_open(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut bracket = 0i32;
    let mut brace = 0i32;
    let mut quote: Option<&[u8]> = None;
    while i < bytes.len() {
        if let Some(q) = quote {
            if q == b"\"" && bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i..].starts_with(q) {
                i += q.len();
                quote = None;
                continue;
            }
            i += 1;
            continue;
        }
        if bytes[i] == b'#' {
            break;
        }
        if bytes[i..].starts_with(b"\"\"\"") {
            quote = Some(b"\"\"\"");
            i += 3;
            continue;
        }
        if bytes[i..].starts_with(b"'''") {
            quote = Some(b"'''");
            i += 3;
            continue;
        }
        if bytes[i] == b'"' {
            quote = Some(b"\"");
        } else if bytes[i] == b'\'' {
            quote = Some(b"'");
        } else if bytes[i] == b'[' {
            bracket += 1;
        } else if bytes[i] == b']' {
            bracket -= 1;
        } else if bytes[i] == b'{' {
            brace += 1;
        } else if bytes[i] == b'}' {
            brace -= 1;
        }
        i += 1;
    }
    quote.is_some() || bracket > 0 || brace > 0
}

/// Pure-Rust TOML parser supporting tables, `[[array]]`, dotted keys, multiline strings/arrays, and inline tables.
pub fn parse_toml_to_json(text: &str) -> Option<Value> {
    let clean = text.trim_start_matches('\u{FEFF}');
    let mut root = serde_json::Map::new();
    let mut cur_path: Vec<String> = Vec::new();
    let lines: Vec<&str> = clean.lines().collect();
    let mut idx = 0usize;

    while idx < lines.len() {
        let stripped = strip_toml_line_comment(lines[idx]).trim();
        if stripped.is_empty() {
            idx += 1;
            continue;
        }
        if let Some(arr_tbl) = stripped
            .strip_prefix("[[")
            .and_then(|s| s.strip_suffix("]]"))
        {
            let path = split_toml_key_path(arr_tbl);
            if !path.is_empty() {
                push_toml_array_table(&mut root, &path);
                cur_path = path;
            }
            idx += 1;
            continue;
        }
        if let Some(tbl) = stripped.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let path = split_toml_key_path(tbl);
            if !path.is_empty() {
                ensure_toml_table_mut(&mut root, &path);
                cur_path = path;
            }
            idx += 1;
            continue;
        }

        let mut stmt = stripped.to_string();
        while toml_balance_open(&stmt) && idx + 1 < lines.len() {
            idx += 1;
            stmt.push('\n');
            stmt.push_str(lines[idx]);
        }
        let stmt_clean = strip_toml_line_comment(stmt.trim()).trim();
        if let Some((k_raw, v_raw)) = split_unquoted_kv(stmt_clean, b'=') {
            let kpath = split_toml_key_path(k_raw);
            if !kpath.is_empty() {
                let mut full_prefix = cur_path.clone();
                full_prefix.extend_from_slice(&kpath[..kpath.len() - 1]);
                let tgt = ensure_toml_table_mut(&mut root, &full_prefix);
                tgt.insert(kpath.last().unwrap().clone(), parse_toml_value(v_raw));
            }
        }
        idx += 1;
    }

    if root.is_empty() {
        None
    } else {
        Some(Value::Object(root))
    }
}

/// Pure-Rust INI / `.cfg` / `.conf` / `.properties` parser supporting `[section]` headers and `key=value`.
pub fn parse_ini_to_json(text: &str, ext: &str) -> Option<Value> {
    let clean = text.trim_start_matches('\u{FEFF}');
    let mut root = serde_json::Map::new();
    let mut cur_sec: Option<String> = None;
    let is_props = ext.eq_ignore_ascii_case("properties");

    for line in clean.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
            let sec = trimmed[1..trimmed.len() - 1].trim().to_string();
            if !sec.is_empty() {
                root.entry(sec.clone())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                cur_sec = Some(sec);
            }
            continue;
        }
        let split_pos = if is_props {
            let eq = trimmed.find('=');
            let col = trimmed.find(':');
            match (eq, col) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
        } else {
            trimmed.find('=')
        };
        if let Some(pos) = split_pos {
            let k = trimmed[..pos].trim();
            let v_raw = trimmed[pos + 1..].trim();
            let v = v_raw
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| v_raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(v_raw);
            if !k.is_empty() {
                if let Some(ref sec) = cur_sec {
                    if let Some(Value::Object(map)) = root.get_mut(sec) {
                        map.insert(k.to_string(), Value::String(v.to_string()));
                    }
                } else {
                    root.insert(k.to_string(), Value::String(v.to_string()));
                }
            }
        }
    }

    if root.is_empty() {
        None
    } else {
        Some(Value::Object(root))
    }
}

/// Dispatch structured configuration parsing (XML, Apple PLIST, TOML, INI) into normalized JSON.
pub fn parse_structured_config_to_json(text: &str, ext: &str) -> Option<(&'static str, Value)> {
    let low = ext.trim().trim_start_matches('.').to_ascii_lowercase();
    match low.as_str() {
        "plist" => parse_xml_to_json(text).map(|v| ("PLIST", v)),
        "xml" | "csproj" | "vbproj" | "fsproj" | "props" | "targets" | "config" | "manifest"
        | "svg" | "xaml" | "nuspec" | "wsdl" | "xsd" | "pom" => {
            parse_xml_to_json(text).map(|v| ("XML", v))
        }
        "toml" => parse_toml_to_json(text).map(|v| ("TOML", v)),
        "ini" | "cfg" | "conf" | "inf" | "properties" | "editorconfig" => {
            parse_ini_to_json(text, &low).map(|v| ("INI", v))
        }
        _ => {
            let trimmed = text.trim_start_matches('\u{FEFF}').trim_start();
            if trimmed.starts_with("<?xml") {
                parse_xml_to_json(text).map(|v| ("XML", v))
            } else {
                None
            }
        }
    }
}

/// Compact schema outline for structured configuration formats (XML, PLIST, TOML, INI).
pub fn outline_structured_config(text: &str, ext: &str) -> Option<(&'static str, String)> {
    let (kind, val) = parse_structured_config_to_json(text, ext)?;
    let mut lines_out = Vec::new();
    summarize_json_node(&val, "", 0, &mut lines_out);
    if lines_out.is_empty() {
        None
    } else {
        Some((kind, lines_out.join("\n")))
    }
}

/// Evaluate `--json-path` against JSON/JSONL first, then seamlessly against XML/PLIST/TOML/INI configs.
pub fn query_json_or_structured(text: &str, ext: &str, expr: &str) -> Result<String, String> {
    if serde_json::from_str::<Value>(text).is_ok() {
        return query_json_or_jsonl(text, expr);
    }
    if let Some((_, val)) = parse_structured_config_to_json(text, ext) {
        let results = eval_json_path_owned(&val, expr);
        if results.is_empty() {
            return Ok(format!("## JSON Path `{expr}` (0 matches)"));
        }
        let body = if results.len() == 1 {
            serde_json::to_string_pretty(&results[0]).unwrap_or_default()
        } else {
            serde_json::to_string_pretty(&results).unwrap_or_default()
        };
        return Ok(format!(
            "## JSON Path `{expr}` ({} match(es))\n{body}",
            results.len()
        ));
    }
    query_json_or_jsonl(text, expr)
}

#[cfg(test)]
mod inspect_tests {
    use super::*;

    #[test]
    fn decodes_nested_raw_protobuf_wire_message() {
        // field 1 (varint) = 150 (08 96 01), field 2 (nested msg): field 1 (str) = "admin" (12 07 0a 05 61 64 6d 69 6e)
        let pb: Vec<u8> = vec![
            0x08, 0x96, 0x01, 0x12, 0x07, 0x0A, 0x05, b'a', b'd', b'm', b'i', b'n',
        ];
        let md = decode_raw_protobuf_md(&pb).unwrap();
        assert!(md.contains("1 (varint): 150"), "missing varint in:\n{md}");
        assert!(md.contains("2 (msg, 7B)"), "missing nested msg in:\n{md}");
        assert!(md.contains("\"admin\""), "missing nested str in:\n{md}");
    }

    #[test]
    fn inspects_jwt_posture_flags_and_timestamps() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let hdr = URL_SAFE_NO_PAD
            .encode(r#"{"alg":"none","typ":"JWT","jku":"https://auth.internal/jwks.json"}"#);
        let pay = URL_SAFE_NO_PAD
            .encode(r#"{"sub":"u1","role":"admin","iat":1700000000,"exp":1700003600}"#);
        let tok = format!("Bearer {hdr}.{pay}.");
        let (md, jv) = inspect_jwt_md(&tok).unwrap();
        assert_eq!(jv["count"], 1);
        assert!(md.contains("WEAK-ALG:none"), "missing WEAK-ALG in:\n{md}");
        assert!(
            md.contains("EMPTY-SIGNATURE"),
            "missing EMPTY-SIGNATURE in:\n{md}"
        );
        assert!(
            md.contains("HEADER-INJECTION-SURFACE:jku"),
            "missing jku flag in:\n{md}"
        );
        assert!(md.contains("EXPIRED"), "missing EXPIRED in:\n{md}");
        assert!(
            md.contains("2023-11-14T22:13:20Z"),
            "wrong UTC timestamp in:\n{md}"
        );
    }

    #[test]
    fn extracts_routes_postmessage_and_sinks_from_minified_js() {
        let bundle = r#"!function(){axios.post("/api/v2/admin/users/:id",{headers:{"X-Domain-Id":d,"X-Target-Services":"svc"}});fetch("/rest/v1/export/report");const chunks={41:"fb19bfac5e8bf871"};http.createServer(function(req,res){res.end("ok")});window.addEventListener("message",function(e){el.innerHTML=e.data.html});window.addEventListener("message",function(ev){if(ev.origin!=="https://app.acme.test")return;console.log(ev.data)});const h="https://cdn.acme.test/app.js"}();"#;
        let (md, jv) = extract_js_routes_md(bundle, "app.min.js", None);
        assert!(
            md.contains("/api/v2/admin/users/:id"),
            "missing route in:\n{md}"
        );
        assert!(md.contains("[PARAM,SENSITIVE]"), "missing tags in:\n{md}");
        assert!(
            md.contains("[MISSING-ORIGIN-CHECK]"),
            "missing origin gap in:\n{md}"
        );
        assert!(
            md.contains("[origin-checked]"),
            "missing checked handler in:\n{md}"
        );
        assert!(
            md.contains("41.fb19bfac5e8bf871.js"),
            "missing lazy chunk in:\n{md}"
        );
        assert!(
            md.contains("[NO-ORIGIN-OR-AUTH-CHECK]"),
            "missing local server gap in:\n{md}"
        );
        assert!(
            md.contains("X-Domain-Id"),
            "missing custom header in:\n{md}"
        );
        assert!(md.contains("innerHTML"), "missing DOM sink in:\n{md}");
        assert!(
            md.contains("cdn.acme.test"),
            "missing external origin in:\n{md}"
        );
        assert_eq!(jv["counts"]["post_message"], 2);
        assert_eq!(jv["counts"]["lazy_chunks"], 1);
    }

    #[test]
    fn scans_and_redacts_hardcoded_secrets_while_skipping_placeholders() {
        let pem_hdr = format!("{}{}", "-----BEGIN RSA ", "PRIVATE KEY-----");
        let ak_val = format!("{}{}", "AKIA", "9X4B7M2Q8W5R1T6Y");
        let cfg = format!(
            "const pem = \"{pem_hdr}\";\nconst ak = \"{ak_val}\";\nconst db = \"postgres://svc_user:Sup3rS3cretPass!@db.internal:5432/prod\";\nconst safe = {{ api_key: \"your_example_placeholder_key\" }};\n"
        );
        let (md, jv) = scan_secrets_md(&cfg, "cfg.js", None);
        assert_eq!(jv["count"], 3, "unexpected count in:\n{md}");
        assert!(md.contains("PEM_PRIVATE_KEY"), "missing PEM in:\n{md}");
        assert!(md.contains("CLOUD_ACCESS_KEY"), "missing AK in:\n{md}");
        assert!(
            md.contains("EMBEDDED_URI_CRED"),
            "missing URI cred in:\n{md}"
        );
        assert!(
            !md.contains("Sup3rS3cretPass!"),
            "secret must be redacted in:\n{md}"
        );
        assert!(!md.contains(&ak_val), "AK must be redacted in:\n{md}");
    }

    fn der_tlv_build(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else {
            let len_bytes = (body.len() as u32).to_be_bytes();
            let first = len_bytes.iter().position(|&b| b != 0).unwrap_or(3);
            let n = 4 - first;
            out.push(0x80 | (n as u8));
            out.extend_from_slice(&len_bytes[first..]);
        }
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn json_outline_filtered_json_path_and_x509_cert_inspection() {
        // 1. HAR outline & filtered/projected JSON path
        let har = r#"{
          "log": {
            "entries": [
              {"request": {"method": "GET", "url": "https://api.acme.test/v1/users"}, "response": {"status": 200}},
              {"request": {"method": "POST", "url": "https://api.acme.test/v1/admin/role"}, "response": {"status": 403}}
            ]
          }
        }"#;
        let out = outline_json_or_jsonl(har).unwrap();
        assert!(
            out.contains("HAR Capture: 2 entries") && out.contains("api.acme.test"),
            "{out}"
        );

        let proj = query_json_or_jsonl(
            har,
            "log.entries[?response.status!=200].{method:request.method,url:request.url,status:response.status}",
        )
        .unwrap();
        assert!(
            proj.contains("POST") && proj.contains("/v1/admin/role") && !proj.contains("/v1/users"),
            "{proj}"
        );

        let keys_md = query_json_or_jsonl(har, "log.entries[0].keys()").unwrap();
        assert!(
            keys_md.contains("\"request\"") && keys_md.contains("\"response\""),
            "{keys_md}"
        );

        // 2. Minimal synthetic DER -> PEM X.509 v3 certificate with SAN & BasicConstraints
        let oid_cn = der_tlv_build(0x06, &[0x55, 0x04, 0x03]);
        let rdn = |name: &str| {
            let atv = der_tlv_build(
                0x30,
                &[oid_cn.clone(), der_tlv_build(0x0C, name.as_bytes())].concat(),
            );
            der_tlv_build(0x31, &atv)
        };
        let issuer = der_tlv_build(0x30, &rdn("Acme Root CA"));
        let subject = der_tlv_build(0x30, &rdn("api.acme.test"));
        let validity = der_tlv_build(
            0x30,
            &[
                der_tlv_build(0x17, b"260101000000Z"),
                der_tlv_build(0x17, b"270101000000Z"),
            ]
            .concat(),
        );
        let spki = der_tlv_build(
            0x30,
            &[
                der_tlv_build(
                    0x30,
                    &der_tlv_build(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
                ),
                der_tlv_build(0x03, &[0x00, 0x04, 0xAA, 0xBB]),
            ]
            .concat(),
        );
        let san_ext = der_tlv_build(
            0x30,
            &[
                der_tlv_build(0x06, &[0x55, 0x1D, 0x11]),
                der_tlv_build(
                    0x04,
                    &der_tlv_build(0x30, &der_tlv_build(0x82, b"api.acme.test")),
                ),
            ]
            .concat(),
        );
        let exts = der_tlv_build(0xA3, &der_tlv_build(0x30, &san_ext));
        let sig_alg = der_tlv_build(
            0x30,
            &der_tlv_build(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]),
        );
        let tbs = der_tlv_build(
            0x30,
            &[
                der_tlv_build(0xA0, &der_tlv_build(0x02, &[0x02])),
                der_tlv_build(0x02, &[0x01, 0x2A]),
                sig_alg.clone(),
                issuer,
                validity,
                subject,
                spki,
                exts,
            ]
            .concat(),
        );
        let cert_der = der_tlv_build(
            0x30,
            &[tbs, sig_alg, der_tlv_build(0x03, &[0x00, 0x01])].concat(),
        );
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(&cert_der)
        );
        let xmd = inspect_x509_pem_or_der(pem.as_bytes()).unwrap();
        assert!(
            xmd.contains("(v3)")
                && xmd.contains("CN=Acme Root CA")
                && xmd.contains("DNS:api.acme.test"),
            "{xmd}"
        );
        assert!(
            xmd.contains("2026-01-01T00:00:00Z") && xmd.contains("ecdsa-SHA256"),
            "{xmd}"
        );
    }

    #[test]
    fn extracts_har_api_attack_surface_without_leaking_secrets() {
        let har = r#"{
          "log": {
            "entries": [
              {
                "request": {
                  "method": "POST",
                  "url": "https://api.example.com/v1/users/550e8400-e29b-41d4-a716-446655440000/profile?debug=1",
                  "headers": [{"name": "Content-Type", "value": "application/json"}],
                  "postData": {"text": "{\"role\":\"admin\",\"target_url\":\"http://127.0.0.1\"}"}
                },
                "response": {
                  "status": 200,
                  "bodySize": 312,
                  "headers": [
                    {"name": "Access-Control-Allow-Origin", "value": "https://evil.test"},
                    {"name": "Access-Control-Allow-Credentials", "value": "true"}
                  ]
                }
              },
              {
                "request": {
                  "method": "GET",
                  "url": "https://api.example.com/v1/users/987654/profile",
                  "headers": [{"name": "Authorization", "value": "Bearer TOP_SECRET_JWT_NEVER_EMIT"}]
                },
                "response": {"status": 200, "bodySize": 180, "headers": []}
              }
            ]
          }
        }"#;
        let (md, jv) = extract_har_routes_md(har, "cap.har", None).unwrap();
        assert!(md.contains("api.example.com/v1/users/:id/profile"), "{md}");
        assert!(md.contains("UNAUTH-2XX"), "{md}");
        assert!(md.contains("CORS-CREDS-EXPOSED"), "{md}");
        assert!(md.contains("SENSITIVE-PARAMS"), "{md}");
        assert!(md.contains("Authorization"), "{md}");
        assert!(!md.contains("TOP_SECRET_JWT_NEVER_EMIT"), "{md}");
        assert_eq!(jv["counts"]["unauth_2xx"], 1);
        assert_eq!(jv["counts"]["cors_creds_exposed"], 1);
    }

    #[test]
    fn diffs_json_structurally_ignoring_key_order() {
        let old_v: Value = serde_json::from_str(
            r#"{"b": 2, "a": 1, "nested": {"keep": true, "drop": "x"}, "arr": [10, 20]}"#,
        )
        .unwrap();
        let reordered: Value = serde_json::from_str(
            r#"{"nested": {"drop": "x", "keep": true}, "arr": [10, 20], "a": 1, "b": 2}"#,
        )
        .unwrap();
        let (same_md, same_jv) = diff_json_structural_md(&reordered, &old_v, "re.json", "old.json");
        assert!(same_md.contains("0 semantic differences"), "{same_md}");
        assert_eq!(same_jv["counts"]["added"], 0);
        assert_eq!(same_jv["counts"]["removed"], 0);
        assert_eq!(same_jv["counts"]["changed"], 0);

        let new_v: Value = serde_json::from_str(
            r#"{"a": 1, "b": 3, "nested": {"keep": true, "add": "y"}, "arr": [10, 25, 30]}"#,
        )
        .unwrap();
        let (diff_md, diff_jv) = diff_json_structural_md(&new_v, &old_v, "new.json", "old.json");
        assert!(
            diff_md.contains("$.b")
                && diff_md.contains("$.nested.add")
                && diff_md.contains("$.nested.drop")
                && diff_md.contains("$.arr[2]"),
            "{diff_md}"
        );
        assert_eq!(diff_jv["counts"]["added"], 2);
        assert_eq!(diff_jv["counts"]["removed"], 1);
        assert_eq!(diff_jv["counts"]["changed"], 2);
    }

    #[test]
    fn parses_xml_plist_toml_ini_for_outline_query_and_structural_diff() {
        // 1. XML with attributes, repeated tags, CDATA & entities
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <artifactId>demo-svc</artifactId>
  <notes><![CDATA[raw <tag> & text]]></notes>
  <desc>Fast &amp; safe</desc>
  <dependencies>
    <dependency scope="compile"><artifactId>serde</artifactId></dependency>
    <dependency scope="test"><artifactId>tempfile</artifactId></dependency>
  </dependencies>
</project>"#;
        let (x_kind, x_out) = outline_structured_config(xml, "xml").unwrap();
        assert_eq!(x_kind, "XML");
        assert!(x_out.contains("project: object"), "{x_out}");
        let x_q = query_json_or_structured(
            xml,
            "xml",
            "$.project.dependencies.dependency[*].artifactId",
        )
        .unwrap();
        assert!(
            x_q.contains("\"serde\"") && x_q.contains("\"tempfile\""),
            "{x_q}"
        );
        let x_notes = query_json_or_structured(xml, "xml", "$.project.notes").unwrap();
        assert!(x_notes.contains("raw <tag> & text"), "{x_notes}");

        // 2. Apple XML .plist
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.example.demo</string>
  <key>LSUIElement</key>
  <true/>
  <key>Port</key>
  <integer>8443</integer>
</dict>
</plist>"#;
        let p_id = query_json_or_structured(plist, "plist", "$.CFBundleIdentifier").unwrap();
        assert!(p_id.contains("com.example.demo"), "{p_id}");
        let p_flag = query_json_or_structured(plist, "plist", "$.LSUIElement").unwrap();
        assert!(p_flag.contains("true"), "{p_flag}");

        // 3. TOML (reordered parity + structural diff)
        let toml_a = r#"
[package]
name = "demo"
version = "1.0.0"

[dependencies]
serde = { version = "1.0", features = ["derive"] }

[[bin]]
name = "cli"
"#;
        let toml_b = r#"
[[bin]]
name = "cli"

[dependencies]
serde = { features = ["derive"], version = "1.0" }

[package]
version = "1.0.0"
name = "demo"
"#;
        let (_, va) = parse_structured_config_to_json(toml_a, "toml").unwrap();
        let (_, vb) = parse_structured_config_to_json(toml_b, "toml").unwrap();
        let (same_md, _) = diff_json_structural_md(&vb, &va, "b.toml", "a.toml");
        assert!(same_md.contains("0 semantic differences"), "{same_md}");

        // 4. INI
        let ini = "; sample config\n[database]\nhost = \"127.0.0.1\"\nport = 5432\n";
        let (i_kind, i_out) = outline_structured_config(ini, "ini").unwrap();
        assert_eq!(i_kind, "INI");
        assert!(i_out.contains("database: object"), "{i_out}");
        let i_q = query_json_or_structured(ini, "ini", "$.database.host").unwrap();
        assert!(i_q.contains("127.0.0.1"), "{i_q}");
    }
}
