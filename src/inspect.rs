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

pub fn query_json_or_jsonl(text: &str, expr: &str) -> Result<String, String> {
    let mut results: Vec<Value> = Vec::new();
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        for hit in eval_json_path(&v, expr) {
            results.push(hit.clone());
        }
    } else {
        for ln in text.lines() {
            let t = ln.trim();
            if t.starts_with('{') || t.starts_with('[') {
                if let Ok(v) = serde_json::from_str::<Value>(t) {
                    for hit in eval_json_path(&v, expr) {
                        results.push(hit.clone());
                    }
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
                if slice.len() >= 2 && depth < 5 && decode_pb_fields(slice, depth + 1, &mut nested) {
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
                        let hx: String = slice
                            .iter()
                            .take(32)
                            .map(|x| format!("{x:02x}"))
                            .collect();
                        out.push(format!("{indent}{field_no} (bytes, {}B): 0x{hx}", slice.len()));
                    }
                } else {
                    let hx: String = slice
                        .iter()
                        .take(32)
                        .map(|x| format!("{x:02x}"))
                        .collect();
                    out.push(format!("{indent}{field_no} (bytes, {}B): 0x{hx}", slice.len()));
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
                    "role" | "roles" | "admin" | "is_admin" | "isadmin" | "scope" | "scopes" | "permissions" | "perms" | "tenant" | "tenant_id"
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
    let q_low = query.map(|q| q.trim().to_ascii_lowercase()).filter(|q| !q.is_empty());
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
        if ["admin", "delete", "remove", "grant", "role", "perm", "token", "secret", "upload", "export", "import", "proxy", "internal", "transfer", "billing", "passwd", "password"]
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
                "www.w3.org" | "schemas.openxmlformats.org" | "purl.org" | "ns.adobe.com" | "example.com"
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
        let is_server = kind_s.contains("createServer") || kind_s.contains("WebSocketServer") || kind_s.contains("oauth/callback");
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
        out.push(format!("\n## postMessage Listeners\n{}", pm_lines.join("\n")));
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
        let ch_list: Vec<String> = lazy_chunks.iter().take(30).map(|c| format!("`{c}`")).collect();
        out.push(format!(
            "\n## Lazy Webpack / Vite Chunks ({})\n{}",
            lazy_chunks.len(),
            ch_list.join(", ")
        ));
    }
    if !custom_headers.is_empty() {
        let h_list: Vec<String> = custom_headers.iter().take(25).map(|h| format!("`{h}`")).collect();
        out.push(format!("\n## Custom Auth / Tenant Headers\n{}", h_list.join(", ")));
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
        || low.chars().all(|c| c == '*' || c == 'x' || c == '0' || c == '-')
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
                if !kind.to_ascii_lowercase().contains(q) && !redacted.to_ascii_lowercase().contains(q) {
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
        let hdr = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT","jku":"https://auth.internal/jwks.json"}"#);
        let pay = URL_SAFE_NO_PAD.encode(r#"{"sub":"u1","role":"admin","iat":1700000000,"exp":1700003600}"#);
        let tok = format!("Bearer {hdr}.{pay}.");
        let (md, jv) = inspect_jwt_md(&tok).unwrap();
        assert_eq!(jv["count"], 1);
        assert!(md.contains("WEAK-ALG:none"), "missing WEAK-ALG in:\n{md}");
        assert!(md.contains("EMPTY-SIGNATURE"), "missing EMPTY-SIGNATURE in:\n{md}");
        assert!(md.contains("HEADER-INJECTION-SURFACE:jku"), "missing jku flag in:\n{md}");
        assert!(md.contains("EXPIRED"), "missing EXPIRED in:\n{md}");
        assert!(md.contains("2023-11-14T22:13:20Z"), "wrong UTC timestamp in:\n{md}");
    }

    #[test]
    fn extracts_routes_postmessage_and_sinks_from_minified_js() {
        let bundle = r#"!function(){axios.post("/api/v2/admin/users/:id",{headers:{"X-Domain-Id":d,"X-Target-Services":"svc"}});fetch("/rest/v1/export/report");const chunks={41:"fb19bfac5e8bf871"};http.createServer(function(req,res){res.end("ok")});window.addEventListener("message",function(e){el.innerHTML=e.data.html});window.addEventListener("message",function(ev){if(ev.origin!=="https://app.acme.test")return;console.log(ev.data)});const h="https://cdn.acme.test/app.js"}();"#;
        let (md, jv) = extract_js_routes_md(bundle, "app.min.js", None);
        assert!(md.contains("/api/v2/admin/users/:id"), "missing route in:\n{md}");
        assert!(md.contains("[PARAM,SENSITIVE]"), "missing tags in:\n{md}");
        assert!(md.contains("[MISSING-ORIGIN-CHECK]"), "missing origin gap in:\n{md}");
        assert!(md.contains("[origin-checked]"), "missing checked handler in:\n{md}");
        assert!(md.contains("41.fb19bfac5e8bf871.js"), "missing lazy chunk in:\n{md}");
        assert!(md.contains("[NO-ORIGIN-OR-AUTH-CHECK]"), "missing local server gap in:\n{md}");
        assert!(md.contains("X-Domain-Id"), "missing custom header in:\n{md}");
        assert!(md.contains("innerHTML"), "missing DOM sink in:\n{md}");
        assert!(md.contains("cdn.acme.test"), "missing external origin in:\n{md}");
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
        assert!(md.contains("EMBEDDED_URI_CRED"), "missing URI cred in:\n{md}");
        assert!(!md.contains("Sup3rS3cretPass!"), "secret must be redacted in:\n{md}");
        assert!(!md.contains(&ak_val), "AK must be redacted in:\n{md}");
    }
}
