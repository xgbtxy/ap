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
}
