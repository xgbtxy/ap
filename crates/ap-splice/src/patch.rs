use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditOp {
    pub path: String,
    pub op: String,
    #[serde(default)]
    pub old: String,
    #[serde(default)]
    pub new: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub line_hint: Option<String>,
}

struct PatchRegexes {
    hdr: Regex,
    open: Regex,
    mid: Regex,
    close: Regex,
    line_hint_tail: Regex,
    gutter_prefix: Regex,
}

fn patch_regexes() -> &'static PatchRegexes {
    static RE: OnceLock<PatchRegexes> = OnceLock::new();
    RE.get_or_init(|| PatchRegexes {
        hdr: Regex::new(
            r"(?i)^@@\s*(FILE_ALL|FILE|EDIT|REPLACE|SYMBOL|WRITE|APPEND|PREPEND)\s*:\s*(.+?)\s*$",
        )
        .unwrap(),
        open: Regex::new(r"(?i)^<<<(?:\s*(?:OLD|SEARCH|EOF))?\s*$").unwrap(),
        mid: Regex::new(r"(?i)^===(?:\s*(?:NEW|REPLACE))?\s*$").unwrap(),
        close: Regex::new(r"(?i)^>>>(?:\s*(?:END|REPLACE|EOF))?\s*$").unwrap(),
        line_hint_tail: Regex::new(r"(?i)^(.*?)\s+@L(\d+(?:\s*-\s*L?\d+)?)\s*$").unwrap(),
        gutter_prefix: Regex::new(r"^\s*\d+(?::[0-9a-fA-F]{2}\||:\s|\|)").unwrap(),
    })
}

pub fn parse_text_spec(raw_spec: &str) -> Result<Vec<EditOp>, String> {
    let re_set = patch_regexes();
    let hdr_re = &re_set.hdr;
    let open_re = &re_set.open;
    let mid_re = &re_set.mid;
    let close_re = &re_set.close;
    let norm = raw_spec.replace("\r\n", "\n");
    let lines: Vec<&str> = norm.split('\n').collect();
    let mut ops = Vec::new();
    let mut i = 0usize;
    let n = lines.len();

    while i < n {
        let ln = lines[i];
        if ln.trim().is_empty() {
            i += 1;
            continue;
        }
        let Some(cap) = hdr_re.captures(ln) else {
            return Err(format!(
                "Line {}: expected `@@ FILE: <path>`, `@@ SYMBOL: <path> :: <Sym>`, or `@@ WRITE: <path>`, got: {:?}",
                i + 1,
                ln
            ));
        };
        let kind = cap[1].to_ascii_uppercase();
        let raw_rest = cap[2].trim();
        let (rest, line_hint) = if matches!(kind.as_str(), "FILE" | "FILE_ALL" | "EDIT" | "REPLACE")
        {
            if let Some(hcap) = re_set.line_hint_tail.captures(raw_rest) {
                (
                    hcap[1].trim().to_string(),
                    Some(
                        hcap[2]
                            .chars()
                            .filter(|c| !c.is_whitespace() && *c != 'L' && *c != 'l')
                            .collect(),
                    ),
                )
            } else {
                (raw_rest.to_string(), None)
            }
        } else {
            (raw_rest.to_string(), None)
        };
        i += 1;

        match kind.as_str() {
            "FILE" | "FILE_ALL" | "EDIT" | "REPLACE" => {
                let replace_all = kind == "FILE_ALL";
                let mut hunks = 0usize;
                while i < n {
                    if hdr_re.is_match(lines[i]) {
                        break;
                    }
                    if lines[i].trim().is_empty() {
                        i += 1;
                        continue;
                    }
                    if !open_re.is_match(lines[i]) {
                        return Err(format!(
                            "Line {} ({rest}): expected `<<<` to start search block, got: {:?}",
                            i + 1,
                            lines[i]
                        ));
                    }
                    i += 1;
                    let mut old_buf = Vec::new();
                    while i < n && !mid_re.is_match(lines[i]) {
                        old_buf.push(lines[i]);
                        i += 1;
                    }
                    if i >= n {
                        return Err(format!(
                            "Unclosed `<<<` block in `{rest}`: missing `===` separator."
                        ));
                    }
                    i += 1;
                    let mut new_buf = Vec::new();
                    while i < n && !close_re.is_match(lines[i]) {
                        new_buf.push(lines[i]);
                        i += 1;
                    }
                    if i >= n {
                        return Err(format!(
                            "Unclosed `===` block in `{rest}`: missing `>>>` terminator."
                        ));
                    }
                    i += 1;
                    ops.push(EditOp {
                        path: rest.clone(),
                        op: "replace".to_string(),
                        old: old_buf.join("\n"),
                        new: new_buf.join("\n"),
                        content: None,
                        symbol: String::new(),
                        all: replace_all,
                        line_hint: line_hint.clone(),
                    });
                    hunks += 1;
                }
                if hunks == 0 {
                    return Err(format!(
                        "`@@ {kind}: {rest}` had no `<<< ... === ... >>>` edit blocks."
                    ));
                }
            }
            "SYMBOL" => {
                let Some((p_raw, s_raw)) = rest.split_once("::") else {
                    return Err(format!(
                        "`@@ SYMBOL: {rest}` must use `@@ SYMBOL: <path> :: <SymbolName>`."
                    ));
                };
                let path = p_raw.trim().to_string();
                let sym = s_raw.trim().to_string();
                while i < n && lines[i].trim().is_empty() {
                    i += 1;
                }
                let mut body_buf = Vec::new();
                if i < n && open_re.is_match(lines[i]) {
                    i += 1;
                    while i < n && !close_re.is_match(lines[i]) {
                        body_buf.push(lines[i]);
                        i += 1;
                    }
                    if i >= n {
                        return Err(format!(
                            "Unclosed `@@ SYMBOL: {path} :: {sym}` block: missing `>>>`."
                        ));
                    }
                    i += 1;
                } else {
                    while i < n && !hdr_re.is_match(lines[i]) {
                        body_buf.push(lines[i]);
                        i += 1;
                    }
                }
                ops.push(EditOp {
                    path,
                    op: "replace_symbol".to_string(),
                    old: String::new(),
                    new: body_buf.join("\n"),
                    content: None,
                    symbol: sym,
                    all: false,
                    line_hint: None,
                });
            }
            "WRITE" | "APPEND" | "PREPEND" => {
                let op_name = kind.to_ascii_lowercase();
                let path = rest;
                let mut j = i;
                while j < n && lines[j].trim().is_empty() {
                    j += 1;
                }
                let content_s = if j < n && open_re.is_match(lines[j]) {
                    i = j + 1;
                    let mut w_buf = Vec::new();
                    while i < n && !close_re.is_match(lines[i]) {
                        w_buf.push(lines[i]);
                        i += 1;
                    }
                    if i >= n {
                        return Err(format!(
                            "Unclosed `@@ {kind}: {path}` block: missing `>>>`."
                        ));
                    }
                    i += 1;
                    format!("{}\n", w_buf.join("\n"))
                } else {
                    let mut w_buf = Vec::new();
                    while i < n && !hdr_re.is_match(lines[i]) {
                        w_buf.push(lines[i]);
                        i += 1;
                    }
                    let mut s = w_buf.join("\n");
                    if !s.is_empty() && !s.ends_with('\n') {
                        s.push('\n');
                    }
                    s
                };
                ops.push(EditOp {
                    path,
                    op: op_name,
                    old: String::new(),
                    new: String::new(),
                    content: Some(content_s),
                    symbol: String::new(),
                    all: false,
                    line_hint: None,
                });
            }
            _ => unreachable!(),
        }
    }
    Ok(ops)
}

fn extract_unified_hunk_hint(hdr: &str) -> Option<String> {
    let body = hdr.strip_prefix("@@ ")?;
    let end = body.find("@@")?;
    let range_part = body[..end].trim();
    let old_tok = range_part
        .split_whitespace()
        .find(|t| t.starts_with('-'))?
        .trim_start_matches('-');
    let (s_str, c_str) = old_tok.split_once(',').unwrap_or((old_tok, "1"));
    let start = s_str.parse::<usize>().ok()?;
    let count = c_str.parse::<usize>().unwrap_or(1).max(1);
    if start == 0 {
        return None;
    }
    let lo = start.saturating_sub(8).max(1);
    let hi = start + count + 12;
    Some(format!("{lo}-{hi}"))
}

fn parse_unified_diff(raw_diff: &str) -> Result<Vec<EditOp>, String> {
    let norm = raw_diff.replace("\r\n", "\n");
    let lines: Vec<&str> = norm.split('\n').collect();
    let mut ops = Vec::new();
    let mut cur_path = String::new();
    let mut is_new_file = false;
    let mut i = 0usize;
    while i < lines.len() {
        let ln = lines[i];
        if let Some(rest) = ln.strip_prefix("--- ") {
            let p = rest.split('\t').next().unwrap_or(rest).trim();
            is_new_file = p == "/dev/null";
            i += 1;
            continue;
        }
        if let Some(rest) = ln.strip_prefix("+++ ") {
            let p = rest.split('\t').next().unwrap_or(rest).trim();
            cur_path = p
                .strip_prefix("b/")
                .or_else(|| p.strip_prefix("a/"))
                .unwrap_or(p)
                .to_string();
            i += 1;
            continue;
        }
        if ln.starts_with("@@ ") && ln[3..].contains("@@") && !cur_path.is_empty() {
            let hunk_hint = extract_unified_hunk_hint(ln);
            i += 1;
            let mut old_buf = Vec::new();
            let mut new_buf = Vec::new();
            while i < lines.len() {
                let hl = lines[i];
                if hl.starts_with("diff --git ")
                    || hl.starts_with("--- ")
                    || hl.starts_with("+++ ")
                    || (hl.starts_with("@@ ") && hl[3..].contains("@@"))
                {
                    break;
                }
                if hl.starts_with('\\') {
                    i += 1;
                    continue;
                }
                if let Some(add) = hl.strip_prefix('+') {
                    new_buf.push(add);
                } else if let Some(del) = hl.strip_prefix('-') {
                    old_buf.push(del);
                } else if let Some(ctx) = hl.strip_prefix(' ') {
                    old_buf.push(ctx);
                    new_buf.push(ctx);
                } else if hl.is_empty() && i + 1 < lines.len() {
                    old_buf.push("");
                    new_buf.push("");
                } else {
                    break;
                }
                i += 1;
            }
            if is_new_file && old_buf.is_empty() {
                ops.push(EditOp {
                    path: cur_path.clone(),
                    op: "write".to_string(),
                    old: String::new(),
                    new: String::new(),
                    content: Some(format!("{}\n", new_buf.join("\n"))),
                    symbol: String::new(),
                    all: false,
                    line_hint: None,
                });
            } else if !old_buf.is_empty() {
                ops.push(EditOp {
                    path: cur_path.clone(),
                    op: "replace".to_string(),
                    old: old_buf.join("\n"),
                    new: new_buf.join("\n"),
                    content: None,
                    symbol: String::new(),
                    all: false,
                    line_hint: hunk_hint,
                });
            }
            continue;
        }
        i += 1;
    }
    if ops.is_empty() {
        Err("Unified diff contained no applicable hunks.".to_string())
    } else {
        Ok(ops)
    }
}

fn parse_codex_patch(raw: &str) -> Result<Vec<EditOp>, String> {
    let norm = raw.replace("\r\n", "\n");
    let lines: Vec<&str> = norm.split('\n').collect();
    let mut ops = Vec::new();
    let mut i = 0usize;
    let n = lines.len();

    while i < n {
        let trimmed = lines[i].trim();
        if trimmed == "*** Begin Patch" || trimmed.is_empty() {
            i += 1;
            continue;
        }
        if trimmed == "*** End Patch" {
            break;
        }
        if let Some(path_raw) = trimmed.strip_prefix("*** Add File:") {
            let path = path_raw.trim().to_string();
            i += 1;
            let mut add_lines = Vec::new();
            while i < n {
                let l = lines[i];
                let lt = l.trim();
                if lt.starts_with("*** ") {
                    break;
                }
                if let Some(rest) = l.strip_prefix('+') {
                    add_lines.push(rest);
                } else if !l.is_empty() {
                    add_lines.push(l);
                }
                i += 1;
            }
            let content = if add_lines.is_empty() {
                String::new()
            } else {
                format!("{}\n", add_lines.join("\n"))
            };
            ops.push(EditOp {
                path,
                op: "write".to_string(),
                old: String::new(),
                new: String::new(),
                content: Some(content),
                symbol: String::new(),
                all: false,
                line_hint: None,
            });
            continue;
        }
        if let Some(path_raw) = trimmed.strip_prefix("*** Update File:") {
            let path = path_raw.trim().to_string();
            i += 1;
            while i < n {
                let lt = lines[i].trim();
                if lt == "*** End Patch"
                    || lt.starts_with("*** Update File:")
                    || lt.starts_with("*** Add File:")
                {
                    break;
                }
                if lt.starts_with("*** Move to:") || lt == "*** End of File" || lt.is_empty() {
                    i += 1;
                    continue;
                }
                if lines[i].starts_with("@@") {
                    let hunk_hint = extract_unified_hunk_hint(lines[i]);
                    i += 1;
                    let mut old_buf = Vec::new();
                    let mut new_buf = Vec::new();
                    while i < n {
                        let hl = lines[i];
                        let hlt = hl.trim();
                        if hl.starts_with("@@") || hlt.starts_with("*** ") {
                            break;
                        }
                        if let Some(add) = hl.strip_prefix('+') {
                            new_buf.push(add);
                        } else if let Some(del) = hl.strip_prefix('-') {
                            old_buf.push(del);
                        } else if let Some(ctx) = hl.strip_prefix(' ') {
                            old_buf.push(ctx);
                            new_buf.push(ctx);
                        } else if hl.is_empty() {
                            old_buf.push("");
                            new_buf.push("");
                        } else {
                            break;
                        }
                        i += 1;
                    }
                    if !old_buf.is_empty() {
                        ops.push(EditOp {
                            path: path.clone(),
                            op: "replace".to_string(),
                            old: old_buf.join("\n"),
                            new: new_buf.join("\n"),
                            content: None,
                            symbol: String::new(),
                            all: false,
                            line_hint: hunk_hint,
                        });
                    }
                    continue;
                }
                i += 1;
            }
            continue;
        }
        i += 1;
    }

    if ops.is_empty() {
        Err("`*** Begin Patch` envelope contained no applicable hunks.".to_string())
    } else {
        Ok(ops)
    }
}

pub fn parse_edit_spec(raw_spec: &str) -> Result<Vec<EditOp>, String> {
    let stripped = raw_spec.trim_start_matches(|c: char| c == '\u{feff}' || c.is_whitespace());
    if stripped.starts_with("*** Begin Patch") {
        return parse_codex_patch(stripped);
    }
    if stripped.starts_with("diff --git ")
        || stripped.starts_with("--- ")
        || stripped.starts_with("Index: ")
    {
        return parse_unified_diff(stripped);
    }
    if stripped.starts_with("@@") {
        return parse_text_spec(stripped);
    }
    let val: Value = serde_json::from_str(stripped).map_err(|e| e.to_string())?;
    match val {
        Value::Array(_) => serde_json::from_value::<Vec<EditOp>>(val).map_err(|e| e.to_string()),
        Value::Object(mut map) => {
            if let Some(edits) = map.remove("edits") {
                serde_json::from_value::<Vec<EditOp>>(edits).map_err(|e| e.to_string())
            } else {
                serde_json::from_value::<EditOp>(Value::Object(map))
                    .map(|op| vec![op])
                    .map_err(|e| e.to_string())
            }
        }
        _ => Ok(Vec::new()),
    }
}

pub fn parse_line_hint(hint: Option<&str>) -> Option<(usize, usize)> {
    let raw = hint?.trim();
    if raw.is_empty() {
        return None;
    }
    let clean = raw
        .trim_start_matches('@')
        .trim_start_matches(['L', 'l'])
        .trim();
    if let Some((a, b)) = clean.split_once('-') {
        let s = a
            .trim()
            .trim_start_matches(['L', 'l'])
            .parse::<usize>()
            .ok()?;
        let e = b
            .trim()
            .trim_start_matches(['L', 'l'])
            .parse::<usize>()
            .ok()?;
        let lo = s.max(1);
        let hi = e.max(lo);
        Some((lo, hi))
    } else {
        let center = clean.parse::<usize>().ok()?.max(1);
        Some((center.saturating_sub(10).max(1), center.saturating_add(10)))
    }
}

fn strip_read_gutter_if_consistent(block: &str) -> Option<String> {
    let g_re = &patch_regexes().gutter_prefix;
    let lines: Vec<&str> = block.split('\n').collect();
    let non_empty: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| !l.trim().is_empty())
        .collect();
    if non_empty.is_empty() || !non_empty.iter().all(|l| g_re.is_match(l)) {
        return None;
    }
    let mut stripped_any = false;
    let out: Vec<String> = lines
        .into_iter()
        .map(|ln| {
            if ln.trim().is_empty() {
                String::new()
            } else if let Some(m) = g_re.find(ln) {
                stripped_any = true;
                ln[m.end()..].to_string()
            } else {
                ln.to_string()
            }
        })
        .collect();
    stripped_any.then(|| out.join("\n"))
}

fn normalize_unicode_punct(s: &str) -> String {
    s.replace(['\u{201C}', '\u{201D}'], "\"")
        .replace(['\u{2018}', '\u{2019}'], "'")
        .replace(['\u{2013}', '\u{2014}'], "-")
}

fn format_ambiguous_err(tier: &str, src_lines: &[&str], hits_0based: &[usize]) -> String {
    let candidates: Vec<String> = hits_0based
        .iter()
        .take(5)
        .map(|&idx| {
            let preview: String = src_lines
                .get(idx)
                .copied()
                .unwrap_or("")
                .trim()
                .chars()
                .take(48)
                .collect();
            format!("L{}: `{preview}`", idx + 1)
        })
        .collect();
    format!(
        "`old` matched {} locations via {tier} ({}). Disambiguate with `@L<start>-L<end>` on the header (or `line_hint`), add 1-2 surrounding lines, or use `@@ FILE_ALL:` / `\"all\": true`.",
        hits_0based.len(),
        candidates.join(", ")
    )
}

pub fn replace_crlf_tolerant(
    content_lf: &str,
    old_lf: &str,
    new_lf: &str,
    replace_all: bool,
) -> Result<(String, usize), String> {
    replace_crlf_tolerant_with_hint(content_lf, old_lf, new_lf, replace_all, None)
}

pub fn replace_crlf_tolerant_with_hint(
    content_lf: &str,
    old_lf: &str,
    new_lf: &str,
    replace_all: bool,
    line_hint: Option<&str>,
) -> Result<(String, usize), String> {
    replace_crlf_inner(content_lf, old_lf, new_lf, replace_all, line_hint, true)
}

fn replace_crlf_inner(
    content_lf: &str,
    old_lf: &str,
    new_lf: &str,
    replace_all: bool,
    line_hint: Option<&str>,
    allow_gutter_strip: bool,
) -> Result<(String, usize), String> {
    if old_lf.is_empty() {
        return Err("`old` cannot be empty.".to_string());
    }
    let hint_win = parse_line_hint(line_hint);
    let src_lines: Vec<&str> = content_lf.split('\n').collect();

    // Tier 1: exact match (+ line_hint disambiguation when multiple matches exist)
    let cnt = content_lf.matches(old_lf).count();
    if cnt == 1 || (cnt > 1 && replace_all) {
        let updated = if replace_all {
            content_lf.replace(old_lf, new_lf)
        } else {
            content_lf.replacen(old_lf, new_lf, 1)
        };
        return Ok((updated, cnt));
    }
    if cnt > 1 && !replace_all {
        let mut hits: Vec<(usize, usize)> = Vec::new();
        for (byte_pos, _) in content_lf.match_indices(old_lf) {
            let ln0 = content_lf[..byte_pos]
                .bytes()
                .filter(|&b| b == b'\n')
                .count();
            hits.push((byte_pos, ln0));
        }
        if let Some((hs, he)) = hint_win {
            let scoped: Vec<(usize, usize)> = hits
                .iter()
                .copied()
                .filter(|&(_, ln0)| (hs..=he).contains(&(ln0 + 1)))
                .collect();
            if scoped.len() == 1 {
                let bpos = scoped[0].0;
                let mut updated = String::with_capacity(
                    content_lf.len() + new_lf.len().saturating_sub(old_lf.len()),
                );
                updated.push_str(&content_lf[..bpos]);
                updated.push_str(new_lf);
                updated.push_str(&content_lf[bpos + old_lf.len()..]);
                return Ok((updated, 1));
            }
        }
        let line_idxs: Vec<usize> = hits.into_iter().map(|(_, ln0)| ln0).collect();
        return Err(format_ambiguous_err("exact match", &src_lines, &line_idxs));
    }

    // Tier 0.5: accidental copied read/view/hashline line-number gutters in `old` (and optionally `new`)
    if allow_gutter_strip {
        if let Some(clean_old) = strip_read_gutter_if_consistent(old_lf) {
            if !clean_old.trim().is_empty() && clean_old != old_lf {
                let clean_new =
                    strip_read_gutter_if_consistent(new_lf).unwrap_or_else(|| new_lf.to_string());
                if let Ok(res) = replace_crlf_inner(
                    content_lf,
                    &clean_old,
                    &clean_new,
                    replace_all,
                    line_hint,
                    false,
                ) {
                    return Ok(res);
                }
            }
        }
    }

    let old_lines: Vec<&str> = old_lf.split('\n').collect();
    let src_stripped: Vec<&str> = src_lines.iter().map(|l| l.trim_end()).collect();
    let old_stripped: Vec<&str> = old_lines.iter().map(|l| l.trim_end()).collect();
    let n_old = old_stripped.len();
    if n_old > src_stripped.len() {
        return Err("`old` target block not found in file.".to_string());
    }

    let pick_disambiguated = |cands: &[usize]| -> Option<usize> {
        if cands.len() == 1 {
            return Some(cands[0]);
        }
        if let Some((hs, he)) = hint_win {
            let scoped: Vec<usize> = cands
                .iter()
                .copied()
                .filter(|&ln0| (hs..=he).contains(&(ln0 + 1)))
                .collect();
            if scoped.len() == 1 {
                return Some(scoped[0]);
            }
        }
        None
    };

    // Tier 2: trailing-whitespace normalization
    let hits: Vec<usize> = (0..=(src_stripped.len() - n_old))
        .filter(|&i| src_stripped[i..i + n_old] == old_stripped[..])
        .collect();
    if !hits.is_empty() && !replace_all {
        if let Some(idx) = pick_disambiguated(&hits) {
            let mut updated: Vec<&str> = Vec::new();
            updated.extend_from_slice(&src_lines[..idx]);
            updated.extend(new_lf.split('\n'));
            updated.extend_from_slice(&src_lines[idx + n_old..]);
            return Ok((updated.join("\n"), 1));
        }
        return Err(format_ambiguous_err("rstrip alignment", &src_lines, &hits));
    }

    // Tier 3 (Aider-style uniform indentation-delta fallback when unambiguous)
    let min_space = |ls: &[&str]| -> usize {
        ls.iter()
            .filter(|l| !l.is_empty())
            .map(|l| l.bytes().take_while(|b| *b == b' ').count())
            .min()
            .unwrap_or(0)
    };
    fn strip_n(l: &str, n: usize) -> &str {
        let take = l.bytes().take_while(|b| *b == b' ').count().min(n);
        &l[take..]
    }

    let has_substance = n_old >= 2
        || old_stripped
            .first()
            .map(|l| l.trim().len() >= 12)
            .unwrap_or(false);
    if has_substance && !replace_all {
        let old_ind = min_space(&old_stripped);
        let old_dedent: Vec<&str> = old_stripped.iter().map(|l| strip_n(l, old_ind)).collect();
        let mut indent_hits: Vec<(usize, usize)> = Vec::new();
        for i in 0..=(src_stripped.len() - n_old) {
            let win = &src_stripped[i..i + n_old];
            let win_ind = min_space(win);
            if win
                .iter()
                .zip(&old_dedent)
                .all(|(w, o)| strip_n(w, win_ind) == *o)
            {
                indent_hits.push((i, win_ind));
            }
        }
        if !indent_hits.is_empty() {
            let line_idxs: Vec<usize> = indent_hits.iter().map(|&(idx, _)| idx).collect();
            if let Some(chosen_idx) = pick_disambiguated(&line_idxs) {
                let win_ind = indent_hits
                    .iter()
                    .find(|&&(idx, _)| idx == chosen_idx)
                    .map(|&(_, wi)| wi)
                    .unwrap_or(old_ind);
                let delta = (win_ind as isize) - (old_ind as isize);
                let shifted_new: Vec<String> = new_lf
                    .split('\n')
                    .map(|l| {
                        if l.trim().is_empty() {
                            String::new()
                        } else {
                            let cur = l.bytes().take_while(|b| *b == b' ').count();
                            let next_ind = ((cur as isize) + delta).max(0) as usize;
                            format!("{}{}", " ".repeat(next_ind), &l[cur..])
                        }
                    })
                    .collect();
                let mut updated: Vec<String> =
                    Vec::with_capacity(src_lines.len() + shifted_new.len());
                updated.extend(src_lines[..chosen_idx].iter().map(|s| (*s).to_string()));
                updated.extend(shifted_new);
                updated.extend(
                    src_lines[chosen_idx + n_old..]
                        .iter()
                        .map(|s| (*s).to_string()),
                );
                return Ok((updated.join("\n"), 1));
            }
            return Err(format_ambiguous_err(
                "indentation normalization",
                &src_lines,
                &line_idxs,
            ));
        }

        // Tier 4: Blank-line-insensitive unique match (rescues LLM blank-line elision/insertion)
        let old_nonempty: Vec<&str> = old_stripped
            .iter()
            .copied()
            .filter(|l| !l.is_empty())
            .collect();
        if old_nonempty.len() >= 2 {
            let old_ne_ind = min_space(&old_nonempty);
            let old_ne_ded: Vec<&str> = old_nonempty
                .iter()
                .map(|l| strip_n(l, old_ne_ind))
                .collect();
            let src_ne: Vec<(usize, &str)> = src_stripped
                .iter()
                .copied()
                .enumerate()
                .filter(|(_, l)| !l.is_empty())
                .collect();
            let m = old_ne_ded.len();
            if m <= src_ne.len() {
                let mut ne_hits: Vec<(usize, usize, usize)> = Vec::new();
                for k in 0..=(src_ne.len() - m) {
                    let win_lines: Vec<&str> = src_ne[k..k + m].iter().map(|(_, l)| *l).collect();
                    let w_ind = min_space(&win_lines);
                    if win_lines
                        .iter()
                        .zip(&old_ne_ded)
                        .all(|(w, o)| strip_n(w, w_ind) == *o)
                    {
                        ne_hits.push((src_ne[k].0, src_ne[k + m - 1].0, w_ind));
                    }
                }
                if !ne_hits.is_empty() {
                    let line_idxs: Vec<usize> = ne_hits.iter().map(|&(s, _, _)| s).collect();
                    if let Some(chosen_s) = pick_disambiguated(&line_idxs) {
                        let (s_idx, e_idx, w_ind) = ne_hits
                            .into_iter()
                            .find(|&(s, _, _)| s == chosen_s)
                            .unwrap();
                        let delta = (w_ind as isize) - (old_ne_ind as isize);
                        let shifted_new: Vec<String> = new_lf
                            .split('\n')
                            .map(|l| {
                                if l.trim().is_empty() {
                                    String::new()
                                } else {
                                    let cur = l.bytes().take_while(|b| *b == b' ').count();
                                    let next_ind = ((cur as isize) + delta).max(0) as usize;
                                    format!("{}{}", " ".repeat(next_ind), &l[cur..])
                                }
                            })
                            .collect();
                        let mut updated: Vec<String> = Vec::new();
                        updated.extend(src_lines[..s_idx].iter().map(|s| (*s).to_string()));
                        updated.extend(shifted_new);
                        updated.extend(src_lines[e_idx + 1..].iter().map(|s| (*s).to_string()));
                        return Ok((updated.join("\n"), 1));
                    }
                    return Err(format_ambiguous_err(
                        "blank-line normalization",
                        &src_lines,
                        &line_idxs,
                    ));
                }
            }
        }
    }

    // Tier 4.5: Smart-quote / typographic-dash fallback when LLM emitted “curly” quotes or dashes
    let norm_old_str = normalize_unicode_punct(old_lf);
    if !replace_all && norm_old_str != old_lf {
        let old_u_lines: Vec<String> = norm_old_str
            .split('\n')
            .map(|l| l.trim_end().to_string())
            .collect();
        let src_u_lines: Vec<String> = src_stripped
            .iter()
            .map(|l| normalize_unicode_punct(l))
            .collect();
        if old_u_lines.len() <= src_u_lines.len() {
            let mut u_hits = Vec::new();
            for i in 0..=(src_u_lines.len() - old_u_lines.len()) {
                if src_u_lines[i..i + old_u_lines.len()] == old_u_lines[..] {
                    u_hits.push(i);
                }
            }
            if let Some(idx) = pick_disambiguated(&u_hits) {
                let clean_new = normalize_unicode_punct(new_lf);
                let mut updated: Vec<String> = Vec::new();
                updated.extend(src_lines[..idx].iter().map(|s| (*s).to_string()));
                updated.extend(clean_new.split('\n').map(|s| s.to_string()));
                updated.extend(
                    src_lines[idx + old_u_lines.len()..]
                        .iter()
                        .map(|s| (*s).to_string()),
                );
                return Ok((updated.join("\n"), 1));
            }
        }
    }

    // SWE-agent ACI diagnostic hint: surface closest matching line or sliding window so the LLM self-corrects without re-reading
    if let Some(first_anchor) = old_stripped.iter().map(|l| l.trim()).find(|l| l.len() >= 6) {
        if let Some((ln_idx, actual)) = src_lines
            .iter()
            .enumerate()
            .find(|(_, l)| l.contains(first_anchor))
        {
            let ctx_end = (ln_idx + n_old.clamp(1, 6)).min(src_lines.len());
            let preview = (ln_idx..ctx_end)
                .map(|k| format!("  {:4}: {}", k + 1, src_lines[k]))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(format!(
                "`old` target block not found (closest anchor at L{}: `{}`). Actual file lines:\n{preview}",
                ln_idx + 1,
                actual.trim()
            ));
        }
    }

    // Token-similarity sliding window fallback when even line 1 had a typo
    fn line_tokens(s: &str) -> std::collections::HashSet<String> {
        s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|t| t.len() >= 2)
            .map(|t| t.to_ascii_lowercase())
            .collect()
    }
    let old_toks = line_tokens(old_lf);
    if !old_toks.is_empty() && !src_lines.is_empty() {
        let win_sz = n_old.clamp(1, 8).min(src_lines.len());
        let mut best_score = 0.0f64;
        let mut best_start = 0usize;
        for i in 0..=(src_lines.len() - win_sz) {
            let chunk = src_lines[i..i + win_sz].join("\n");
            let w_toks = line_tokens(&chunk);
            if w_toks.is_empty() {
                continue;
            }
            let inter = old_toks.intersection(&w_toks).count();
            let union = old_toks.union(&w_toks).count();
            let score = (inter as f64) / (union.max(1) as f64);
            if score > best_score {
                best_score = score;
                best_start = i;
            }
        }
        if best_score >= 0.30 {
            let ctx_end = (best_start + win_sz).min(src_lines.len());
            let pct = (best_score * 100.0).round() as usize;
            let preview = (best_start..ctx_end)
                .map(|k| format!("  {:4}: {}", k + 1, src_lines[k]))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(format!(
                "`old` target block not found (closest window L{}-L{}, {pct}% token match):\n{preview}",
                best_start + 1,
                ctx_end
            ));
        }
    }
    Err("`old` target block not found in file.".to_string())
}

pub fn dedent_and_reindent(new_block: &str, col_indent: usize) -> Vec<String> {
    let clean = new_block.replace("\r\n", "\n");
    let trimmed = clean.trim_end_matches('\n');
    let raw_lines: Vec<&str> = trimmed.split('\n').collect();
    let min_indent = raw_lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.chars().take_while(|c| *c == ' ').count())
        .min()
        .unwrap_or(0);
    let pad = " ".repeat(col_indent);
    raw_lines
        .into_iter()
        .map(|l| {
            if l.trim().is_empty() {
                String::new()
            } else {
                let stripped: String = l.chars().skip(min_indent).collect();
                format!("{pad}{stripped}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gutter_strip_rescues_copied_line_numbers_and_hashlines() {
        let src = "fn compute() -> i32 {\n    let a = 10;\n    a + 2\n}";
        let old = "   2:     let a = 10;\n   3:     a + 2";
        let new = "   2:     let a = 20;\n   3:     a + 2";
        let (out, cnt) =
            replace_crlf_tolerant_with_hint(src, old, new, false, None).expect("gutter strip");
        assert_eq!(cnt, 1);
        assert!(out.contains("let a = 20;"));
        assert!(!out.contains("   2:"));

        let hashline_old = "2:ab|    let a = 10;\n3:cd|    a + 2";
        let (out2, cnt2) = replace_crlf_tolerant_with_hint(
            src,
            hashline_old,
            "    let a = 30;\n    a + 2",
            false,
            None,
        )
        .expect("hashline strip");
        assert_eq!(cnt2, 1);
        assert!(out2.contains("let a = 30;"));
    }

    #[test]
    fn line_hint_disambiguates_duplicate_blocks_and_reports_candidate_lines() {
        let src = [
            "fn first() {",
            "    return 1;",
            "}",
            "fn middle() {",
            "    let x = 2;",
            "}",
            "fn second() {",
            "    return 1;",
            "}",
        ]
        .join("\n");

        let spec = "@@ FILE: demo.rs @L7-L9\n<<<\n    return 1;\n===\n    return 99;\n>>>\n";
        let ops = parse_text_spec(spec).unwrap();
        assert_eq!(ops[0].path, "demo.rs");
        assert_eq!(ops[0].line_hint.as_deref(), Some("7-9"));

        let (out, cnt) = replace_crlf_tolerant_with_hint(
            &src,
            &ops[0].old,
            &ops[0].new,
            false,
            ops[0].line_hint.as_deref(),
        )
        .unwrap();
        assert_eq!(cnt, 1);
        assert!(out.starts_with("fn first() {\n    return 1;\n}"));
        assert!(out.ends_with("fn second() {\n    return 99;\n}"));

        let err =
            replace_crlf_tolerant_with_hint(&src, "    return 1;", "    return 99;", false, None)
                .unwrap_err();
        assert!(err.contains("L2:"), "{err}");
        assert!(err.contains("L8:"), "{err}");
    }

    #[test]
    fn unicode_smart_quote_fallback_rescues_curly_quotes() {
        let src = "let msg = \"hello-world\";";
        let old = "let msg = \u{201C}hello\u{2013}world\u{201D};";
        let new = "let msg = \u{201C}fixed-world\u{201D};";
        let (out, cnt) =
            replace_crlf_tolerant_with_hint(src, old, new, false, None).expect("unicode rescue");
        assert_eq!(cnt, 1);
        assert_eq!(out, "let msg = \"fixed-world\";");
    }

    #[test]
    fn codex_begin_patch_parses_update_and_add_file_multi_hunks() {
        let patch = r#"*** Begin Patch
*** Update File: src/app.ts
@@
 const a = 1;
-const b = 2;
+const b = 20;
@@
 function tail() {
-  return false;
+  return true;
 }
*** Add File: src/extra.ts
+export const EXTRA = 42;
*** End Patch
"#;
        let ops = parse_edit_spec(patch).expect("codex begin patch");
        assert_eq!(ops.len(), 3, "{ops:?}");
        assert_eq!(ops[0].op, "replace");
        assert_eq!(ops[0].path, "src/app.ts");
        assert!(ops[0].new.contains("const b = 20;"));
        assert_eq!(ops[1].op, "replace");
        assert!(ops[1].new.contains("return true;"));
        assert_eq!(ops[2].op, "write");
        assert_eq!(ops[2].path, "src/extra.ts");
        assert_eq!(
            ops[2].content.as_deref(),
            Some("export const EXTRA = 42;\n")
        );
    }

    #[test]
    fn unified_diff_sets_hunk_line_hint_to_disambiguate_duplicate_blocks() {
        let src = [
            "fn first() {",
            "    return 1;",
            "}",
            "fn pad1() { let a = 1; }",
            "fn pad2() { let b = 2; }",
            "fn pad3() { let c = 3; }",
            "fn pad4() { let d = 4; }",
            "fn pad5() { let e = 5; }",
            "fn second() {",
            "    return 1;",
            "}",
        ]
        .join("\n");
        let diff = "--- a/demo.rs\n+++ b/demo.rs\n@@ -9,3 +9,3 @@\n fn second() {\n-    return 1;\n+    return 99;\n";
        let ops = parse_edit_spec(diff).expect("unified diff");
        assert!(ops[0].line_hint.is_some(), "{ops:?}");
        let (out, cnt) = replace_crlf_tolerant_with_hint(
            &src,
            &ops[0].old,
            &ops[0].new,
            false,
            ops[0].line_hint.as_deref(),
        )
        .expect("line-hint disambiguation");
        assert_eq!(cnt, 1);
        assert!(out.starts_with("fn first() {\n    return 1;\n}"));
        assert!(out.ends_with("fn second() {\n    return 99;\n}"));
    }
}
