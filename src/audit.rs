use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, UNIX_EPOCH};

const MAX_LINE_PARSE_BYTES: usize = 128 * 1024;
const MAX_FILE_TAIL_BYTES: u64 = 16 * 1024 * 1024;
const MODEL_FAMILIES: [&str; 7] = [
    "deepseek", "claude", "openai", "gemini", "grok", "qwen", "other",
];

#[derive(Parser, Debug)]
#[command(
    name = "audit",
    about = "Local zero-cloud telemetry auditor across Codex, Pi, Antigravity, Claude, Grok & Gemini CLI (strictly anonymized process friction only)"
)]
struct AuditCli {
    #[arg(long, default_value = "")]
    home: String,
    #[arg(long, default_value_t = 50)]
    max_sessions: usize,
    #[arg(long)]
    compare: bool,
    /// Emit a strictly anonymized, zero-PII Maintainer Brief mapping top observed process bottlenecks directly to `ap` source modules
    #[arg(long)]
    maintainer: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Counters {
    pub tool_calls: usize,
    pub file_reads: usize,
    pub redundant_same_file_rereads: usize,
    pub adhoc_inline_python: usize,
    pub shell_line_slice_read: usize,
    pub shell_broad_search: usize,
    pub shell_quoting_collision: usize,
    pub patch_target_mismatch: usize,
    pub encoding_utf8_crash: usize,
    pub import_syspath_error: usize,
    pub outputs_over_8kb: usize,
    pub output_truncation_spill: usize,
    pub identical_retry_loops: usize,
    pub heavy_thinking_turns: usize,
    pub dsml_tool_leaks: usize,
    pub serial_single_tool_turns: usize,
    pub shell_timeouts: usize,
    pub path_translation_errors: usize,
    pub kv_cache_cold_drops: usize,
    pub prompt_input_tokens: u64,
    pub prompt_cache_read_tokens: u64,
}

impl Counters {
    fn add(&mut self, o: &Counters) {
        self.tool_calls += o.tool_calls;
        self.file_reads += o.file_reads;
        self.redundant_same_file_rereads += o.redundant_same_file_rereads;
        self.adhoc_inline_python += o.adhoc_inline_python;
        self.shell_line_slice_read += o.shell_line_slice_read;
        self.shell_broad_search += o.shell_broad_search;
        self.shell_quoting_collision += o.shell_quoting_collision;
        self.patch_target_mismatch += o.patch_target_mismatch;
        self.encoding_utf8_crash += o.encoding_utf8_crash;
        self.import_syspath_error += o.import_syspath_error;
        self.outputs_over_8kb += o.outputs_over_8kb;
        self.output_truncation_spill += o.output_truncation_spill;
        self.identical_retry_loops += o.identical_retry_loops;
        self.heavy_thinking_turns += o.heavy_thinking_turns;
        self.dsml_tool_leaks += o.dsml_tool_leaks;
        self.serial_single_tool_turns += o.serial_single_tool_turns;
        self.shell_timeouts += o.shell_timeouts;
        self.path_translation_errors += o.path_translation_errors;
        self.kv_cache_cold_drops += o.kv_cache_cold_drops;
        self.prompt_input_tokens += o.prompt_input_tokens;
        self.prompt_cache_read_tokens += o.prompt_cache_read_tokens;
    }
}

#[derive(Debug, Default, Clone)]
struct SessionScan {
    counters: Counters,
    model_family: Option<&'static str>,
}

/// Strictly map arbitrary raw model strings to an allowlisted public family name (never leaks custom/private endpoints).
pub fn classify_model_family(raw: &str) -> &'static str {
    let low = raw.trim().to_ascii_lowercase();
    if low.is_empty() {
        return "other";
    }
    if low.contains("deepseek") || low.contains("flash-auto") {
        return "deepseek";
    }
    if low.contains("claude")
        || low.contains("sonnet")
        || low.contains("opus")
        || low.contains("haiku")
    {
        return "claude";
    }
    if low.contains("gpt-")
        || low.starts_with("gpt")
        || low.contains("openai")
        || low.contains("codex")
        || low.starts_with("o1")
        || low.starts_with("o3")
        || low.starts_with("o4")
        || low.contains("/o1")
        || low.contains("/o3")
        || low.contains("/o4")
    {
        return "openai";
    }
    if low.contains("gemini") {
        return "gemini";
    }
    if low.contains("grok") {
        return "grok";
    }
    if low.contains("qwen") {
        return "qwen";
    }
    "other"
}

fn family_index(fam: &'static str) -> usize {
    MODEL_FAMILIES
        .iter()
        .position(|&x| x == fam)
        .unwrap_or(MODEL_FAMILIES.len() - 1)
}

fn record_model_hint(hist: &mut [usize; 7], raw: &str) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }
    let fam = classify_model_family(trimmed);
    hist[family_index(fam)] += 1;
}

fn pick_dominant_family(hist: &[usize; 7]) -> Option<&'static str> {
    let mut best_idx = None;
    let mut best_cnt = 0usize;
    for (idx, &cnt) in hist[..MODEL_FAMILIES.len() - 1].iter().enumerate() {
        if cnt > best_cnt {
            best_cnt = cnt;
            best_idx = Some(idx);
        }
    }
    if let Some(i) = best_idx {
        return Some(MODEL_FAMILIES[i]);
    }
    let other_idx = MODEL_FAMILIES.len() - 1;
    if hist[other_idx] > 0 {
        return Some("other");
    }
    None
}

fn cmd_regexes() -> &'static (Regex, Regex, Regex) {
    static RE: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    RE.get_or_init(|| {
        let inline = Regex::new(r"(?s)\b(?:python(?:\.exe|3)?\s+-c|node(?:\.exe)?\s+-(?:e|-eval))\b|@['\x22]\s*\n.*import\s+").unwrap();
        let slice = Regex::new(r"\b(?:Get-Content|cat|head|tail|Select-Object\s+-(?:First|Last|Skip)|sed\s+-n)\b").unwrap();
        let search = Regex::new(r"\b(?:rg|grep|Select-String|Get-ChildItem|find\s+|findstr)\b").unwrap();
        (inline, slice, search)
    })
}

fn classify_cmd(cmd: &str, st: &mut Counters) {
    let (inline_re, slice_re, search_re) = cmd_regexes();
    if inline_re.is_match(cmd) {
        st.adhoc_inline_python += 1;
    }
    if slice_re.is_match(cmd) {
        st.shell_line_slice_read += 1;
    }
    if search_re.is_match(cmd) {
        st.shell_broad_search += 1;
    }
}

#[inline]
fn contains_ascii_ci(hay: &str, needle: &str) -> bool {
    let hb = hay.as_bytes();
    let nb = needle.as_bytes();
    if nb.is_empty() {
        return true;
    }
    if hb.len() < nb.len() {
        return false;
    }
    hb.windows(nb.len()).any(|w| w.eq_ignore_ascii_case(nb))
}

#[inline]
fn safe_head_slice(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[inline]
fn safe_tail_slice(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut start = s.len() - max_bytes;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

fn classify_err(txt: &str, st: &mut Counters) {
    let (head, tail) = if txt.len() <= 8192 {
        (txt, "")
    } else {
        (safe_head_slice(txt, 4096), safe_tail_slice(txt, 4096))
    };
    let has = |k: &str| head.contains(k) || (!tail.is_empty() && tail.contains(k));
    let has_ci =
        |k: &str| contains_ascii_ci(head, k) || (!tail.is_empty() && contains_ascii_ci(tail, k));

    if [
        "ParserError",
        "Unexpected token",
        "The '&&' operator",
        "The '<' operator",
        "unterminated triple-quoted",
        "Script sandbox failed",
    ]
    .iter()
    .any(|k| has(k))
    {
        st.shell_quoting_collision += 1;
    }
    if (has("Target") && (has("not found") || has("match")))
        || has("Failed to find expected lines")
        || (has_ci("apply_patch") && has_ci("error"))
    {
        st.patch_target_mismatch += 1;
    }
    if [
        "UnicodeDecodeError",
        "UnicodeEncodeError",
        "'gbk' codec",
        "'charmap' codec",
    ]
    .iter()
    .any(|k| has(k))
    {
        st.encoding_utf8_crash += 1;
    }
    if has("ModuleNotFoundError") || has("ImportError") || has("No module named pytest") {
        st.import_syspath_error += 1;
    }
    if [
        "truncated due to being too long",
        "output was truncated",
        "chars truncated",
    ]
    .iter()
    .any(|k| has(k))
    {
        st.output_truncation_spill += 1;
    }
    if has_ci("timed out") || has_ci("etimedout") || has_ci("deadline exceeded") {
        st.shell_timeouts += 1;
    }
    if ((has_ci("no such file") || has_ci("cannot find the path") || has_ci("filenotfounderror"))
        && (has_ci("/mnt/") || has_ci("unicodeescape")))
        || has("Program Files/Git/")
        || has("Program Files\\Git\\")
    {
        st.path_translation_errors += 1;
    }
}

fn for_each_bounded_line(file: File, max_parse_bytes: usize, cb: impl FnMut(&str, usize)) {
    for_each_bounded_line_with_cap(file, max_parse_bytes, MAX_FILE_TAIL_BYTES, cb);
}

fn for_each_bounded_line_with_cap(
    mut file: File,
    max_parse_bytes: usize,
    max_file_tail_bytes: u64,
    mut cb: impl FnMut(&str, usize),
) {
    let mut skipped_partial_head = false;
    if max_file_tail_bytes > 0 {
        if let Ok(meta) = file.metadata() {
            let len = meta.len();
            if len > max_file_tail_bytes {
                let offset = len - max_file_tail_bytes;
                if file.seek(SeekFrom::Start(offset)).is_ok() {
                    skipped_partial_head = true;
                }
            }
        }
    }
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut buf = Vec::with_capacity(16 * 1024);
    if skipped_partial_head {
        let _ = reader.read_until(b'\n', &mut buf);
    }
    loop {
        buf.clear();
        let Ok(n) = reader.read_until(b'\n', &mut buf) else {
            break;
        };
        if n == 0 {
            break;
        }
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        let raw_len = buf.len();
        if raw_len <= max_parse_bytes {
            let s = String::from_utf8_lossy(&buf);
            cb(&s, raw_len);
        } else {
            let head_len = max_parse_bytes.min(raw_len);
            let head = String::from_utf8_lossy(&buf[..head_len]);
            let tail_start = raw_len.saturating_sub(16 * 1024).max(head_len);
            if tail_start < raw_len {
                let tail = String::from_utf8_lossy(&buf[tail_start..]);
                let mut bounded = String::with_capacity(head.len() + tail.len() + 1);
                bounded.push_str(&head);
                bounded.push('\n');
                bounded.push_str(&tail);
                cb(&bounded, raw_len);
            } else {
                cb(&head, raw_len);
            }
        }
    }
}

fn norm_cmd_key(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(160)
        .collect()
}

fn track_sliding_loop(win: &mut VecDeque<String>, nk: String) -> bool {
    if nk.is_empty() {
        return false;
    }
    win.push_back(nk.clone());
    if win.len() > 6 {
        win.pop_front();
    }
    win.iter().filter(|x| x.as_str() == nk.as_str()).count() >= 3
}

fn scan_codex(f: &Path) -> SessionScan {
    let mut st = Counters::default();
    let mut hist = [0usize; 7];
    let Ok(file) = File::open(f) else {
        return SessionScan::default();
    };
    let mut recent: VecDeque<String> = VecDeque::with_capacity(7);
    for_each_bounded_line(file, MAX_LINE_PARSE_BYTES, |line, raw_len| {
        if raw_len > MAX_LINE_PARSE_BYTES {
            if line.contains("_call_output\"") && raw_len >= 8192 {
                st.outputs_over_8kb += 1;
            }
            classify_err(line, &mut st);
            return;
        }
        if !line.contains("call") && !line.contains("\"model") {
            return;
        }
        if line.contains("_call_output\"") {
            if raw_len >= 8192 {
                st.outputs_over_8kb += 1;
            }
            classify_err(line, &mut st);
            return;
        }
        let Ok(o) = serde_json::from_str::<Value>(line) else {
            return;
        };
        for m in [
            o["payload"]["model"].as_str(),
            o["model"].as_str(),
            o["payload"]["model_provider"].as_str(),
        ]
        .into_iter()
        .flatten()
        {
            record_model_hint(&mut hist, m);
        }
        let pt = o["payload"]["type"].as_str().unwrap_or("");
        if pt == "function_call" || pt == "custom_tool_call" {
            st.tool_calls += 1;
            let inp = o["payload"]["arguments"]
                .as_str()
                .or_else(|| o["payload"]["input"].as_str())
                .unwrap_or("");
            if track_sliding_loop(&mut recent, norm_cmd_key(inp)) {
                st.identical_retry_loops += 1;
            }
            classify_cmd(inp, &mut st);
        } else if pt == "function_call_output" || pt == "custom_tool_call_output" {
            let out_s = o["payload"]["output"].as_str().unwrap_or("");
            if out_s.len() >= 8192 {
                st.outputs_over_8kb += 1;
            }
            classify_err(out_s, &mut st);
        }
    });
    SessionScan {
        counters: st,
        model_family: pick_dominant_family(&hist),
    }
}

fn scan_agy(f: &Path) -> SessionScan {
    let mut st = Counters::default();
    let mut hist = [0usize; 7];
    let Ok(file) = File::open(f) else {
        return SessionScan::default();
    };
    let mut seen_reads: HashMap<String, usize> = HashMap::new();
    for_each_bounded_line(file, MAX_LINE_PARSE_BYTES, |line, raw_len| {
        if raw_len > MAX_LINE_PARSE_BYTES {
            st.outputs_over_8kb += 1;
            classify_err(line, &mut st);
            return;
        }
        if !line.contains("\"tool_calls\"")
            && !line.contains("\"model\"")
            && !line.contains("\"content\"")
        {
            return;
        }
        let Ok(o) = serde_json::from_str::<Value>(line) else {
            return;
        };
        if let Some(m) = o["model"].as_str() {
            record_model_hint(&mut hist, m);
        }
        if let Some(c) = o["content"].as_str() {
            if c.len() >= 8192 {
                st.outputs_over_8kb += 1;
            }
            classify_err(c, &mut st);
        }
        if let Some(tcs) = o["tool_calls"].as_array() {
            for tc in tcs {
                st.tool_calls += 1;
                let nm = tc["name"]
                    .as_str()
                    .or_else(|| tc["tool_name"].as_str())
                    .unwrap_or("");
                let args = if let Some(s) = tc["args"].as_str().or_else(|| tc["arguments"].as_str())
                {
                    serde_json::from_str::<Value>(s).unwrap_or(Value::Null)
                } else if tc["args"].is_object() {
                    tc["args"].clone()
                } else {
                    tc["arguments"].clone()
                };
                if nm == "read_file" {
                    st.file_reads += 1;
                    if let Some(pk) = args["Path"].as_str().filter(|s| !s.is_empty()) {
                        let cnt = seen_reads.entry(pk.to_string()).or_insert(0);
                        *cnt += 1;
                        if *cnt >= 2 {
                            st.redundant_same_file_rereads += 1;
                        }
                    }
                } else if nm == "run_command" {
                    if let Some(cl) = args["CommandLine"].as_str() {
                        classify_cmd(cl, &mut st);
                    }
                }
            }
        }
    });
    SessionScan {
        counters: st,
        model_family: pick_dominant_family(&hist),
    }
}

fn scan_claude(f: &Path) -> SessionScan {
    let mut st = Counters::default();
    let mut hist = [0usize; 7];
    let Ok(file) = File::open(f) else {
        return SessionScan::default();
    };
    let mut seen_reads: HashMap<String, usize> = HashMap::new();
    for_each_bounded_line(file, MAX_LINE_PARSE_BYTES, |line, raw_len| {
        if raw_len > MAX_LINE_PARSE_BYTES {
            if line.contains("tool_result") && raw_len >= 8192 {
                st.outputs_over_8kb += 1;
            }
            classify_err(line, &mut st);
            return;
        }
        if !line.contains("tool_") && !line.contains("\"model\"") {
            return;
        }
        let Ok(o) = serde_json::from_str::<Value>(line) else {
            return;
        };
        if let Some(m) = o["message"]["model"]
            .as_str()
            .or_else(|| o["model"].as_str())
        {
            record_model_hint(&mut hist, m);
        }
        if let Some(arr) = o["message"]["content"].as_array() {
            for blk in arr {
                match blk["type"].as_str().unwrap_or("") {
                    "tool_use" => {
                        st.tool_calls += 1;
                        let nm = blk["name"].as_str().unwrap_or("");
                        if nm == "Read" {
                            st.file_reads += 1;
                            if let Some(fp) =
                                blk["input"]["file_path"].as_str().filter(|s| !s.is_empty())
                            {
                                let cnt = seen_reads.entry(fp.to_string()).or_insert(0);
                                *cnt += 1;
                                if *cnt >= 2 {
                                    st.redundant_same_file_rereads += 1;
                                }
                            }
                        } else if nm == "Bash" {
                            if let Some(c) = blk["input"]["command"].as_str() {
                                classify_cmd(c, &mut st);
                            }
                        }
                    }
                    "tool_result" => {
                        let rc = serde_json::to_string(&blk["content"]).unwrap_or_default();
                        if rc.len() >= 8192 {
                            st.outputs_over_8kb += 1;
                        }
                        classify_err(&rc, &mut st);
                    }
                    _ => {}
                }
            }
        }
    });
    SessionScan {
        counters: st,
        model_family: pick_dominant_family(&hist),
    }
}

fn scan_grok(f: &Path) -> SessionScan {
    let mut st = Counters::default();
    let mut hist = [0usize; 7];
    let Ok(file) = File::open(f) else {
        return SessionScan::default();
    };
    let mut seen_reads: HashMap<String, usize> = HashMap::new();
    for_each_bounded_line(file, MAX_LINE_PARSE_BYTES, |line, raw_len| {
        if raw_len > MAX_LINE_PARSE_BYTES {
            if line.contains("\"tool_call_update\"") && raw_len >= 8192 {
                st.outputs_over_8kb += 1;
            }
            classify_err(line, &mut st);
            return;
        }
        if !line.contains("tool_call") && !line.contains("\"model\"") {
            return;
        }
        if line.contains("\"tool_call_update\"") {
            if line.contains("\"completed\"") || line.contains("\"failed\"") {
                if raw_len >= 8192 {
                    st.outputs_over_8kb += 1;
                }
                classify_err(line, &mut st);
            }
            return;
        }
        let Ok(o) = serde_json::from_str::<Value>(line) else {
            return;
        };
        if let Some(m) = o["model"]
            .as_str()
            .or_else(|| o["params"]["model"].as_str())
        {
            record_model_hint(&mut hist, m);
        }
        let upd = &o["params"]["update"];
        match upd["sessionUpdate"].as_str().unwrap_or("") {
            "tool_call" => {
                st.tool_calls += 1;
                let nm = upd["title"].as_str().unwrap_or("");
                if nm == "read_file" {
                    st.file_reads += 1;
                    let fp = upd["rawInput"]["file_path"]
                        .as_str()
                        .or_else(|| upd["rawInput"]["path"].as_str())
                        .unwrap_or("");
                    if !fp.is_empty() {
                        let cnt = seen_reads.entry(fp.to_string()).or_insert(0);
                        *cnt += 1;
                        if *cnt >= 2 {
                            st.redundant_same_file_rereads += 1;
                        }
                    }
                } else if nm == "run_terminal_command" {
                    if let Some(c) = upd["rawInput"]["command"].as_str() {
                        classify_cmd(c, &mut st);
                    }
                }
            }
            "tool_call_update" => {
                let status = upd["status"].as_str().unwrap_or("");
                if status == "completed" || status == "failed" {
                    let raw_out = serde_json::to_string(&upd["rawOutput"]).unwrap_or_default();
                    if raw_out.len() >= 8192 {
                        st.outputs_over_8kb += 1;
                    }
                    classify_err(&raw_out, &mut st);
                }
            }
            _ => {}
        }
    });
    SessionScan {
        counters: st,
        model_family: pick_dominant_family(&hist),
    }
}

fn scan_pi(f: &Path) -> SessionScan {
    let mut st = Counters::default();
    let mut hist = [0usize; 7];
    let Ok(file) = File::open(f) else {
        return SessionScan::default();
    };
    let mut seen_reads: HashMap<String, usize> = HashMap::new();
    let mut recent: VecDeque<String> = VecDeque::with_capacity(7);
    let mut prev_prompt_tokens = 0u64;
    let mut serial_1tool_run = 0usize;
    let flush_serial = |run: &mut usize, out: &mut Counters| {
        if *run >= 3 {
            out.serial_single_tool_turns += *run;
        }
        *run = 0;
    };
    for_each_bounded_line(file, MAX_LINE_PARSE_BYTES, |line, raw_len| {
        if raw_len > MAX_LINE_PARSE_BYTES {
            if line.contains("\"toolResult\"") && raw_len >= 8192 {
                st.outputs_over_8kb += 1;
            }
            classify_err(line, &mut st);
            return;
        }
        if !line.contains("\"message\"") && !line.contains("\"model_change\"") {
            return;
        }
        if line.contains("\"toolResult\"") && raw_len <= MAX_LINE_PARSE_BYTES {
            if raw_len >= 8192 {
                st.outputs_over_8kb += 1;
            }
            classify_err(line, &mut st);
            return;
        }
        let Ok(o) = serde_json::from_str::<Value>(line) else {
            return;
        };
        let top_type = o["type"].as_str().unwrap_or("");
        if top_type == "model_change" {
            for m in [
                o["modelId"].as_str(),
                o["provider"].as_str(),
                o["model"].as_str(),
            ]
            .into_iter()
            .flatten()
            {
                record_model_hint(&mut hist, m);
            }
            return;
        }
        if top_type != "message" {
            return;
        }
        let msg = &o["message"];
        match msg["role"].as_str().unwrap_or("") {
            "user" => {
                flush_serial(&mut serial_1tool_run, &mut st);
            }
            "assistant" => {
                for m in [msg["model"].as_str(), msg["provider"].as_str()]
                    .into_iter()
                    .flatten()
                {
                    record_model_hint(&mut hist, m);
                }
                let stop_reason = msg["stopReason"].as_str().unwrap_or("");
                if let Some(u) = msg["usage"].as_object() {
                    let u_in = u.get("input").and_then(Value::as_u64).unwrap_or(0);
                    let u_cr = u.get("cacheRead").and_then(Value::as_u64).unwrap_or(0);
                    st.prompt_input_tokens += u_in;
                    st.prompt_cache_read_tokens += u_cr;
                    let prompt_tok = u_in + u_cr;
                    if stop_reason != "error" && stop_reason != "aborted" {
                        if prompt_tok >= 10_000
                            && prev_prompt_tokens >= 10_000
                            && (u_cr * 100) / prompt_tok < 45
                        {
                            st.kv_cache_cold_drops += 1;
                        }
                        if prompt_tok > 0 {
                            prev_prompt_tokens = prompt_tok;
                        }
                    }
                }
                if let Some(arr) = msg["content"].as_array() {
                    let mut turn_thinking_chars = 0usize;
                    let mut has_dsml_leak = false;
                    let mut turn_tool_calls = 0usize;
                    for blk in arr {
                        let bt = blk["type"].as_str().unwrap_or("");
                        if bt == "thinking" {
                            turn_thinking_chars +=
                                blk["thinking"].as_str().map(str::len).unwrap_or(0);
                            continue;
                        }
                        if bt == "text" {
                            let tx = blk["text"].as_str().unwrap_or("");
                            if tx.contains("DSML") && tx.contains("invoke") {
                                has_dsml_leak = true;
                            }
                            continue;
                        }
                        if bt != "toolCall" && bt != "tool_use" {
                            continue;
                        }
                        turn_tool_calls += 1;
                        st.tool_calls += 1;
                        let nm = blk["name"].as_str().unwrap_or("");
                        let args = &blk["arguments"];
                        if nm == "read" {
                            st.file_reads += 1;
                            let fp = args["path"]
                                .as_str()
                                .or_else(|| args["file_path"].as_str())
                                .unwrap_or("");
                            if !fp.is_empty() {
                                let cnt = seen_reads.entry(fp.to_string()).or_insert(0);
                                *cnt += 1;
                                if *cnt >= 2 {
                                    st.redundant_same_file_rereads += 1;
                                }
                            }
                        } else if nm == "bash" || nm == "powershell" {
                            let cmd_s = args["command"].as_str().unwrap_or("");
                            if track_sliding_loop(&mut recent, norm_cmd_key(cmd_s)) {
                                st.identical_retry_loops += 1;
                            }
                            classify_cmd(cmd_s, &mut st);
                        }
                    }
                    if turn_tool_calls == 1 {
                        serial_1tool_run += 1;
                    } else {
                        flush_serial(&mut serial_1tool_run, &mut st);
                    }
                    if turn_thinking_chars >= 8000 {
                        st.heavy_thinking_turns += 1;
                    }
                    if has_dsml_leak {
                        st.dsml_tool_leaks += 1;
                    }
                }
            }
            "toolResult" => {
                let joined = serde_json::to_string(&msg["content"]).unwrap_or_default();
                if joined.len() >= 8192 {
                    st.outputs_over_8kb += 1;
                }
                classify_err(&joined, &mut st);
            }
            _ => {}
        }
    });
    flush_serial(&mut serial_1tool_run, &mut st);
    SessionScan {
        counters: st,
        model_family: pick_dominant_family(&hist),
    }
}

fn collect_matching_files(
    root: &Path,
    suffix_or_name: &str,
    prefix_opt: Option<&str>,
) -> Vec<PathBuf> {
    let mut found: Vec<(u64, PathBuf)> = Vec::new();
    fn walk(d: &Path, suf: &str, pref: Option<&str>, out: &mut Vec<(u64, PathBuf)>) {
        let Ok(rd) = fs::read_dir(d) else { return };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let os_nm = entry.file_name();
                let dname = os_nm.to_string_lossy();
                if matches!(
                    dname.as_ref(),
                    "scratch"
                        | "node_modules"
                        | ".git"
                        | "target"
                        | "tasks"
                        | "steps"
                        | ".user_uploaded"
                        | "browser"
                ) {
                    continue;
                }
                walk(&p, suf, pref, out);
            } else if p.is_file() {
                let nm = entry.file_name().to_string_lossy().to_string();
                let ok_name = if suf.starts_with('.') {
                    nm.ends_with(suf)
                } else {
                    nm == suf
                };
                let ok_pref = pref.map(|pr| nm.starts_with(pr)).unwrap_or(true);
                if ok_name && ok_pref {
                    let mtime = entry
                        .metadata()
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|dur| dur.as_millis() as u64)
                        .unwrap_or(0);
                    out.push((mtime, p));
                }
            }
        }
    }
    if root.is_dir() {
        walk(root, suffix_or_name, prefix_opt, &mut found);
    }
    found.sort_by_key(|a| std::cmp::Reverse(a.0));
    found.into_iter().map(|(_, p)| p).collect()
}

fn compute_half_comparison(per_session: &[Counters]) -> Option<Value> {
    if per_session.len() < 2 {
        return None;
    }
    let mid = per_session.len() / 2;
    let recent = &per_session[..mid];
    let older = &per_session[mid..];

    let rates = |bucket: &[Counters]| -> [f64; 5] {
        let cnt = bucket.len().max(1) as f64;
        let mut agg = Counters::default();
        for c in bucket {
            agg.add(c);
        }
        let crashes = agg.shell_quoting_collision
            + agg.patch_target_mismatch
            + agg.encoding_utf8_crash
            + agg.import_syspath_error;
        let r2 = |v: usize| ((v as f64 / cnt) * 100.0).round() / 100.0;
        [
            r2(agg.tool_calls),
            r2(agg.redundant_same_file_rereads),
            r2(agg.adhoc_inline_python),
            r2(crashes),
            r2(agg.outputs_over_8kb + agg.output_truncation_spill),
        ]
    };

    let ov = rates(older);
    let nv = rates(recent);
    let keys = [
        "calls_per_session",
        "rereads_per_session",
        "inline_py_per_session",
        "crashes_per_session",
        "spills_over_8kb_per_session",
    ];
    let mut old_obj = serde_json::Map::new();
    let mut new_obj = serde_json::Map::new();
    let mut delta_obj = serde_json::Map::new();
    old_obj.insert("sessions".into(), json!(older.len()));
    new_obj.insert("sessions".into(), json!(recent.len()));
    for (i, k) in keys.iter().enumerate() {
        old_obj.insert((*k).into(), json!(ov[i]));
        new_obj.insert((*k).into(), json!(nv[i]));
        let d_str = if ov[i] > 0.0 {
            let pct = ((nv[i] - ov[i]) / ov[i]) * 100.0;
            format!("{} -> {} ({:+.1}%)", ov[i], nv[i], pct)
        } else {
            format!("{} -> {}", ov[i], nv[i])
        };
        delta_obj.insert((*k).into(), json!(d_str));
    }
    Some(json!({
        "older_half": old_obj,
        "recent_half": new_obj,
        "delta": delta_obj,
    }))
}

pub fn default_home_dir() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn scan_gemini(f: &Path) -> SessionScan {
    let mut st = Counters::default();
    let mut hist = [0usize; 7];
    let Ok(raw) = fs::read_to_string(f) else {
        return SessionScan::default();
    };
    if raw.len() > 25_000_000 {
        return SessionScan::default();
    }
    let Ok(v) = serde_json::from_str::<Value>(&raw) else {
        return SessionScan::default();
    };
    if let Some(m) = v["model"].as_str() {
        record_model_hint(&mut hist, m);
    }
    let Some(msgs) = v.get("messages").and_then(Value::as_array) else {
        return SessionScan {
            counters: st,
            model_family: pick_dominant_family(&hist),
        };
    };
    let mut seen_reads: HashMap<String, usize> = HashMap::new();
    for m in msgs {
        if let Some(mm) = m.get("model").and_then(Value::as_str) {
            record_model_hint(&mut hist, mm);
        }
        if let Some(tcs) = m.get("toolCalls").and_then(Value::as_array) {
            for tc in tcs {
                st.tool_calls += 1;
                let nm = tc.get("name").and_then(Value::as_str).unwrap_or("");
                let args = &tc["args"];
                if nm == "read_file" || nm == "read_many_files" {
                    st.file_reads += 1;
                    if let Some(fp) = args["absolute_path"]
                        .as_str()
                        .or_else(|| args["path"].as_str())
                        .filter(|s| !s.is_empty())
                    {
                        let cnt = seen_reads.entry(fp.to_string()).or_insert(0);
                        *cnt += 1;
                        if *cnt >= 2 {
                            st.redundant_same_file_rereads += 1;
                        }
                    }
                } else if nm == "run_shell_command" {
                    if let Some(c) = args["command"].as_str() {
                        classify_cmd(c, &mut st);
                    }
                }
                if let Some(res) = tc.get("result") {
                    let rs = serde_json::to_string(res).unwrap_or_default();
                    if rs.len() >= 8192 {
                        st.outputs_over_8kb += 1;
                    }
                    classify_err(&rs, &mut st);
                }
            }
        }
    }
    SessionScan {
        counters: st,
        model_family: pick_dominant_family(&hist),
    }
}

pub fn build_maintainer_targets(totals: &Counters) -> Vec<Value> {
    let mut items: Vec<(usize, Value)> = Vec::new();
    let mut push_if = |count: usize, id: &str, summary: &str, files: &[&str], focus: &str| {
        if count > 0 {
            items.push((
                count,
                json!({
                    "bottleneck_id": id,
                    "count": count,
                    "summary": summary,
                    "target_files": files,
                    "optimization_focus": focus,
                }),
            ));
        }
    };
    push_if(
        totals.shell_quoting_collision + totals.encoding_utf8_crash + totals.path_translation_errors,
        "shell_os_friction",
        "Shell quoting collisions, UTF-8/GBK crashes, or cross-OS path translation failures",
        &["src/exec.rs", "src/install.rs"],
        "Expand pre-execution command auto-healing, quote/backslash normalization, and UTF-8 locking without breaking destructive-command boundaries",
    );
    push_if(
        totals.adhoc_inline_python + totals.import_syspath_error,
        "adhoc_inline_scripts",
        "Ad-hoc inline python -c / node -e scripts or missing-package ImportErrors",
        &["src/read.rs", "src/query.rs", "crates/ap-probe/src/"],
        "Identify recurring one-off script patterns (file formats, HTTP/JSON/binary/log parsing) and promote them into zero-dependency native Rust subcommands",
    );
    push_if(
        totals.redundant_same_file_rereads + totals.shell_line_slice_read,
        "blind_reading_and_rereads",
        "Redundant same-file re-reads or manual head/tail/sed line-slice paging",
        &["src/read.rs", "crates/ap-atlas/src/lib.rs", "crates/ap-splice/src/lib.rs"],
        "Improve AST symbol outlines, batch read ergonomics, and truncated-file structural TOC hints",
    );
    push_if(
        totals.patch_target_mismatch,
        "edit_patch_mismatch",
        "Edit/patch target mismatches causing retry round-trips",
        &["crates/ap-splice/src/lib.rs", "src/install.rs"],
        "Tighten fuzzy anchor recovery (indentation/blank-line/hashline tolerance) and closest-window diagnostics",
    );
    push_if(
        totals.outputs_over_8kb + totals.output_truncation_spill,
        "context_log_bloat",
        "Oversized (>8 KB) tool outputs or truncation spills flooding working memory",
        &["crates/ap-sieve/src/lib.rs", "src/exec.rs"],
        "Improve deterministic semantic digesting for noisy CLI/compiler/test/JSON logs while preserving lossless FTS5 peek",
    );
    push_if(
        totals.shell_broad_search + totals.shell_timeouts,
        "slow_search_and_timeouts",
        "Broad shell searches or command timeouts stalling agent loops",
        &["src/search.rs", "src/exec.rs", "crates/ap-atlas/src/lib.rs"],
        "Accelerate multi-pattern/archive search, prune noisy vendor/cache dirs, and cap unbounded read-only probes",
    );
    push_if(
        totals.identical_retry_loops,
        "retry_doom_loops",
        "Identical failing command retry loops without strategy change",
        &["crates/ap-guard/src/lib.rs", "crates/ap-baton/src/lib.rs"],
        "Strengthen deterministic loop-breakers and cross-turn dead-end recording",
    );
    push_if(
        totals.heavy_thinking_turns
            + totals.dsml_tool_leaks
            + totals.serial_single_tool_turns
            + totals.kv_cache_cold_drops,
        "reasoning_and_cache_friction",
        "Heavy-thinking churn, DSML tool leaks, serial 1-tool loops, or KV-cache cold drops",
        &["src/pi_patch.rs", "src/install.rs", "src/profile.rs"],
        "Refine Pi runtime patches, KV-cache prefix stability, model-tier profiles, parallel tool batching hints, and tool-name self-healing",
    );
    items.sort_by_key(|a| std::cmp::Reverse(a.0));
    items.into_iter().map(|(_, v)| v).collect()
}

pub fn build_adapter_recommendations(
    harnesses: &serde_json::Map<String, Value>,
    model_families: &serde_json::Map<String, Value>,
    totals: &Counters,
) -> Vec<Value> {
    let mut recs = Vec::new();
    let core_friction = totals.adhoc_inline_python
        + totals.shell_quoting_collision
        + totals.redundant_same_file_rereads
        + totals.outputs_over_8kb;
    if core_friction > 0 || !harnesses.is_empty() {
        recs.push(json!({
            "layer": "Layer 1: Universal Core",
            "target": "all_harnesses",
            "command": "ap init",
            "reason": format!(
                "{} ad-hoc scripts, {} shell/quoting crashes, {} redundant re-reads, {} >8KB log spills benefit across all hosts via `ap read/search/query/splice/exec`",
                totals.adhoc_inline_python,
                totals.shell_quoting_collision,
                totals.redundant_same_file_rereads,
                totals.outputs_over_8kb
            ),
        }));
    }
    if harnesses.contains_key("pi_cli")
        && (totals.heavy_thinking_turns
            + totals.dsml_tool_leaks
            + totals.kv_cache_cold_drops
            + totals.outputs_over_8kb
            > 0)
    {
        recs.push(json!({
            "layer": "Layer 3: Pi x DeepSeek/Long-Ctx Adapter",
            "target": "pi_cli",
            "command": "ap init -a pi --with-hooks && ap pi patch && ap profile set --model deepseek",
            "reason": format!(
                "Pi runtime patches (incl. template-literal-safe codemode shim), KV-cache warming, DSML recovery ({} leaks) & 12KB fast auto-sieve",
                totals.dsml_tool_leaks
            ),
        }));
    } else if model_families.contains_key("deepseek") {
        recs.push(json!({
            "layer": "Layer 3: DeepSeek Model Profile",
            "target": "deepseek",
            "command": "ap profile set --model deepseek --apply",
            "reason": "Configures 45s KV-cache-safe sleep clamp, 12KB auto-sieve threshold, 210k masking high-water, and DSML recovery",
        }));
    }
    let has_non_codemode_cli = [
        "codex_cli",
        "claude_code",
        "gemini_cli",
        "grok_cli",
        "antigravity_cli",
    ]
    .iter()
    .any(|k| {
        harnesses
            .get(*k)
            .and_then(|v| v.get("tool_calls"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0
    });
    if has_non_codemode_cli {
        recs.push(json!({
            "layer": "Layer 3: Non-Codemode CLI MCP Profile",
            "target": "cli_harnesses",
            "command": "ap profile set --mcp-profile core --apply",
            "reason": "Wires native TOML/JSON MCP (`--mcp-profile core`: 8 everyday tools + `ap_discover`/`ap_call`, or `deferred` for ~94% fewer schema tokens) + <5ms PostToolUse AST checks across Codex, Claude Code, Grok, Gemini CLI & Antigravity",
        }));
    }
    recs
}

#[derive(Default)]
struct ModelFamilyAgg {
    sessions: usize,
    tool_calls: usize,
    kv_cache_cold_drops: usize,
    dsml_tool_leaks: usize,
    outputs_over_8kb: usize,
    adhoc_inline_python: usize,
    shell_quoting_collision: usize,
}

pub fn audit_home(home: &Path, max_per_harness: usize, compare: bool) -> Value {
    let t0 = Instant::now();
    type AuditSpec<'a> = (
        &'a str,
        PathBuf,
        &'a str,
        Option<&'a str>,
        fn(&Path) -> SessionScan,
    );
    let specs: [AuditSpec; 6] = [
        (
            "codex_cli",
            home.join(".codex").join("sessions"),
            ".jsonl",
            Some("rollout-"),
            scan_codex,
        ),
        (
            "pi_cli",
            home.join(".pi").join("agent").join("sessions"),
            ".jsonl",
            None,
            scan_pi,
        ),
        (
            "antigravity_cli",
            home.join(".gemini").join("antigravity-cli").join("brain"),
            "transcript.jsonl",
            None,
            scan_agy,
        ),
        (
            "claude_code",
            home.join(".claude").join("projects"),
            ".jsonl",
            None,
            scan_claude,
        ),
        (
            "grok_cli",
            home.join(".grok").join("sessions"),
            "updates.jsonl",
            None,
            scan_grok,
        ),
        (
            "gemini_cli",
            home.join(".gemini").join("tmp"),
            ".json",
            Some("session-"),
            scan_gemini,
        ),
    ];

    struct ScanJob {
        harness_idx: usize,
        file_idx: usize,
        path: PathBuf,
        scanner: fn(&Path) -> SessionScan,
    }

    let mut per_harness_counts = [0usize; 6];
    let mut jobs: Vec<ScanJob> = Vec::new();
    for (h_idx, (_, hdir, suf, pref, scanner)) in specs.iter().enumerate() {
        let mut files = collect_matching_files(hdir, suf, *pref);
        files.truncate(max_per_harness);
        per_harness_counts[h_idx] = files.len();
        for (f_idx, path) in files.into_iter().enumerate() {
            jobs.push(ScanJob {
                harness_idx: h_idx,
                file_idx: f_idx,
                path,
                scanner: *scanner,
            });
        }
    }

    let mut per_harness_scans: [Vec<Option<SessionScan>>; 6] =
        std::array::from_fn(|i| vec![None; per_harness_counts[i]]);
    if !jobs.is_empty() {
        let next_idx = AtomicUsize::new(0);
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(1, 8)
            .min(jobs.len());
        let results_lock = Mutex::new(&mut per_harness_scans);
        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| loop {
                    let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                    if idx >= jobs.len() {
                        break;
                    }
                    let job = &jobs[idx];
                    let scan = (job.scanner)(&job.path);
                    let mut guard = results_lock.lock().unwrap();
                    guard[job.harness_idx][job.file_idx] = Some(scan);
                });
            }
        });
    }

    let mut harnesses = serde_json::Map::new();
    let mut comparisons = serde_json::Map::new();
    let mut totals = Counters::default();
    let mut family_aggs: BTreeMap<&'static str, ModelFamilyAgg> = BTreeMap::new();

    for (h_idx, (hname, _, _, _, _)) in specs.iter().enumerate() {
        let scans = &per_harness_scans[h_idx];
        if scans.is_empty() {
            continue;
        }
        let mut h_agg = Counters::default();
        let mut per_session = Vec::with_capacity(scans.len());
        for scan in scans.iter().flatten() {
            h_agg.add(&scan.counters);
            if let Some(fam) = scan.model_family {
                let agg = family_aggs.entry(fam).or_default();
                agg.sessions += 1;
                agg.tool_calls += scan.counters.tool_calls;
                agg.kv_cache_cold_drops += scan.counters.kv_cache_cold_drops;
                agg.dsml_tool_leaks += scan.counters.dsml_tool_leaks;
                agg.outputs_over_8kb += scan.counters.outputs_over_8kb;
                agg.adhoc_inline_python += scan.counters.adhoc_inline_python;
                agg.shell_quoting_collision += scan.counters.shell_quoting_collision;
            }
            per_session.push(scan.counters.clone());
        }
        totals.add(&h_agg);
        let mut hv = serde_json::to_value(&h_agg).unwrap_or_default();
        hv["sessions"] = json!(scans.len());
        harnesses.insert((*hname).to_string(), hv);
        if compare {
            if let Some(cmp) = compute_half_comparison(&per_session) {
                comparisons.insert((*hname).to_string(), cmp);
            }
        }
    }

    let mut model_families_detected = serde_json::Map::new();
    for (fam, agg) in family_aggs {
        model_families_detected.insert(
            fam.to_string(),
            json!({
                "sessions": agg.sessions,
                "tool_calls": agg.tool_calls,
                "kv_cache_cold_drops": agg.kv_cache_cold_drops,
                "dsml_tool_leaks": agg.dsml_tool_leaks,
                "outputs_over_8kb": agg.outputs_over_8kb,
                "adhoc_inline_python": agg.adhoc_inline_python,
                "shell_quoting_collision": agg.shell_quoting_collision,
            }),
        );
    }

    let mut recs = Vec::new();
    if totals.adhoc_inline_python + totals.import_syspath_error + totals.shell_quoting_collision > 0
    {
        recs.push(json!({
            "primitive": "probe",
            "evidence": format!("{} inline `python -c`/`node -e` probes, {} ImportError/sys.path failures, {} shell-quoting crashes", totals.adhoc_inline_python, totals.import_syspath_error, totals.shell_quoting_collision),
            "why": "Replaces brittle inline probes & prose mental execution with Tree-sitter reachability slicing (`ap probe slice --bundle`), heap/mutation tracing (`run`), and differential testing (`diff`)."
        }));
    }
    if totals.redundant_same_file_rereads
        + totals.shell_line_slice_read
        + totals.patch_target_mismatch
        + totals.encoding_utf8_crash
        > 0
    {
        recs.push(json!({
            "primitive": "splice",
            "evidence": format!("{} redundant file re-reads, {} shell line-slice reads, {} patch mismatches, {} UTF-8/encoding crashes", totals.redundant_same_file_rereads, totals.shell_line_slice_read, totals.patch_target_mismatch, totals.encoding_utf8_crash),
            "why": "Extracts exact 6-language Tree-sitter symbols/Markdown sections (`ap splice view`) and applies zero-escaping atomic edits + auto-tests (`ap splice apply --stdin --test`)."
        }));
    }
    if totals.outputs_over_8kb + totals.output_truncation_spill > 0 {
        recs.push(json!({
            "primitive": "sieve",
            "evidence": format!("{} tool outputs >8 KB, {} truncation spills", totals.outputs_over_8kb, totals.output_truncation_spill),
            "why": "Compresses noisy CI/JSON/JSONL/HTML outputs by ~98% into structured failure/schema digests while indexing raw streams in bundled SQLite FTS5."
        }));
    }
    if totals.shell_broad_search > 5 {
        recs.push(json!({
            "primitive": "atlas",
            "evidence": format!("{} broad shell search/listing calls", totals.shell_broad_search),
            "why": "Generates a deterministic <800-token Tree-sitter structural codebase/vault map + stale-TODO trap warning in <50ms."
        }));
    }
    if totals.identical_retry_loops > 0 || totals.tool_calls > 50 {
        recs.push(json!({
            "primitive": "guard + baton",
            "evidence": format!("{} identical retry loops across {} tool calls", totals.identical_retry_loops, totals.tool_calls),
            "why": "Hard-stops identical failing retries (`exit 2` in <2ms) and preserves verified facts/dead-ends across compaction."
        }));
    }
    if totals.heavy_thinking_turns > 0
        || totals.dsml_tool_leaks > 0
        || totals.serial_single_tool_turns >= 20
        || totals.shell_timeouts >= 3
    {
        recs.push(json!({
            "primitive": "pi accelerator (`ap init -a pi --with-hooks`)",
            "evidence": format!("{} heavy-thinking turns (>8k chars), {} DSML text tool leaks, {} serial 1-tool turns, {} shell timeouts, {} cold KV-cache drops", totals.heavy_thinking_turns, totals.dsml_tool_leaks, totals.serial_single_tool_turns, totals.shell_timeouts, totals.kv_cache_cold_drops),
            "why": "Enables zero-token Pi v1.5+ batch observation masking, cold-cache free cleanup, dual-tier auto-sieve, heredoc backslash auto-heal, serial-batch nudges & dynamic deepseek/flash-auto effort routing."
        }));
    }

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
    let maintainer_targets = build_maintainer_targets(&totals);
    let recommended_adapters =
        build_adapter_recommendations(&harnesses, &model_families_detected, &totals);
    let mut out = json!({
        "privacy_guarantee": "100% local & strictly anonymized: zero prompts, zero code snippets, zero file paths, and zero raw model IDs/credentials emitted.",
        "elapsed_ms": elapsed_ms,
        "harnesses_detected": harnesses,
        "model_families_detected": model_families_detected,
        "aggregate_friction_counts": totals,
        "recommended_primitives": recs,
        "recommended_adapters": recommended_adapters,
        "maintainer_targets": maintainer_targets,
    });
    if compare {
        out["period_comparison"] = Value::Object(comparisons);
    }
    out
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match AuditCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    let home = if cli.home.trim().is_empty() {
        default_home_dir()
    } else {
        PathBuf::from(&cli.home)
    };
    let report = audit_home(&home, cli.max_sessions, cli.compare);
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return 0;
    }

    if cli.maintainer {
        println!(
            "# ap Maintainer Friction-to-Source Brief (scanned in {} ms — 100% local, zero-PII)",
            report["elapsed_ms"]
        );
        println!("> Privacy Guarantee: numeric process-friction counters ONLY — zero prompts, zero user paths, zero code, zero raw model endpoints, zero secrets.\n");
        let Some(hmap) = report["harnesses_detected"].as_object() else {
            return 0;
        };
        if hmap.is_empty() {
            println!("No local session logs found under ~/.codex, ~/.pi, ~/.claude, ~/.grok, ~/.gemini/tmp, or ~/.gemini/antigravity-cli.");
            return 0;
        }
        println!("## Harnesses Sampled");
        for (h, st) in hmap {
            println!(
                "- **{h}**: {} sessions, {} tool calls",
                st["sessions"], st["tool_calls"]
            );
        }
        if let Some(fmap) = report["model_families_detected"]
            .as_object()
            .filter(|m| !m.is_empty())
        {
            println!("\n## Allowlisted Model Families Sampled");
            for (fam, st) in fmap {
                println!(
                    "- **{fam}**: {} sessions, {} calls, {} cold KV drops, {} >8KB spills",
                    st["sessions"],
                    st["tool_calls"],
                    st["kv_cache_cold_drops"],
                    st["outputs_over_8kb"]
                );
            }
        }
        println!("\n## Ranked Optimization Targets Mapped to `ap` Source Modules");
        if let Some(targets) = report["maintainer_targets"].as_array() {
            if targets.is_empty() {
                println!("- No significant process friction detected in sampled sessions.");
            } else {
                for (idx, t) in targets.iter().enumerate() {
                    let files = t["target_files"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    println!(
                        "{}. **[{}] count={}** — {}\n   - `ap` source: `{}`\n   - Focus: {}",
                        idx + 1,
                        t["bottleneck_id"].as_str().unwrap_or(""),
                        t["count"],
                        t["summary"].as_str().unwrap_or(""),
                        files,
                        t["optimization_focus"].as_str().unwrap_or(""),
                    );
                }
            }
        }
        if let Some(adapters) = report["recommended_adapters"]
            .as_array()
            .filter(|a| !a.is_empty())
        {
            println!("\n## Recommended On-Demand Adapters (Core + Harness x Model)");
            for (i, a) in adapters.iter().enumerate() {
                println!(
                    "{}. **[{}]** `{}`\n   - {}",
                    i + 1,
                    a["layer"].as_str().unwrap_or(""),
                    a["command"].as_str().unwrap_or(""),
                    a["reason"].as_str().unwrap_or(""),
                );
            }
        }
        println!("\n## Required Verification Before Opening a PR");
        println!("```bash\ncargo fmt --all -- --check\ncargo clippy --workspace --all-targets -- -D warnings\ncargo test --workspace\n```");
        return 0;
    }

    println!(
        "# Local Agent Process Telemetry Audit (scanned in {} ms — 100% local, zero cloud)",
        report["elapsed_ms"]
    );
    let Some(hmap) = report["harnesses_detected"].as_object() else {
        return 0;
    };
    if hmap.is_empty() {
        println!("No local session logs found under ~/.codex, ~/.pi, ~/.claude, ~/.grok, or ~/.gemini/antigravity-cli.");
        return 0;
    }
    println!("\n## Harnesses Scanned");
    for (h, st) in hmap {
        println!(
            "- **{h}**: {} recent sessions, {} tool calls",
            st["sessions"], st["tool_calls"]
        );
    }
    if let Some(fmap) = report["model_families_detected"]
        .as_object()
        .filter(|m| !m.is_empty())
    {
        println!("\n## Model Families Scanned (Allowlisted)");
        for (fam, st) in fmap {
            println!(
                "- **{fam}**: {} sessions, {} calls, {} cold drops",
                st["sessions"], st["tool_calls"], st["kv_cache_cold_drops"]
            );
        }
    }
    let c = &report["aggregate_friction_counts"];
    println!("\n## Measured Process Bottlenecks Across Your Sessions");
    println!(
        "- Inline `python -c` / `node -e` probes: **{}** (`ImportError`: **{}**, shell-quoting crashes: **{}**)",
        c["adhoc_inline_python"], c["import_syspath_error"], c["shell_quoting_collision"]
    );
    println!(
        "- Redundant same-file re-reads: **{}** | Manual shell line-slice reads: **{}**",
        c["redundant_same_file_rereads"], c["shell_line_slice_read"]
    );
    println!(
        "- Patch target mismatches: **{}** | UTF-8/encoding crashes: **{}**",
        c["patch_target_mismatch"], c["encoding_utf8_crash"]
    );
    println!(
        "- Tool outputs >8 KB: **{}** (truncation spills: **{}**)",
        c["outputs_over_8kb"], c["output_truncation_spill"]
    );
    println!(
        "- Broad shell searches: **{}** | Identical retry loops: **{}**",
        c["shell_broad_search"], c["identical_retry_loops"]
    );
    let heavy_t = c["heavy_thinking_turns"].as_u64().unwrap_or(0);
    let dsml_l = c["dsml_tool_leaks"].as_u64().unwrap_or(0);
    let serial_t = c["serial_single_tool_turns"].as_u64().unwrap_or(0);
    let timeouts = c["shell_timeouts"].as_u64().unwrap_or(0);
    let cold_drops = c["kv_cache_cold_drops"].as_u64().unwrap_or(0);
    let in_tok = c["prompt_input_tokens"].as_u64().unwrap_or(0);
    let cache_tok = c["prompt_cache_read_tokens"].as_u64().unwrap_or(0);
    if heavy_t > 0 || dsml_l > 0 || cache_tok > 0 || serial_t > 0 || timeouts > 0 {
        let cache_pct = if in_tok + cache_tok > 0 {
            ((cache_tok as f64 / (in_tok + cache_tok) as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        };
        println!(
            "- Heavy-thinking turns (>8k chars): **{heavy_t}** | DSML leaks: **{dsml_l}** | Serial 1-tool turns (runs>=3): **{serial_t}** | Timeouts: **{timeouts}** | Prompt KV-cache hit rate: **{cache_pct:.1}%** (cold drops: **{cold_drops}**)"
        );
    }

    if let Some(cmp_map) = report["period_comparison"]
        .as_object()
        .filter(|m| !m.is_empty())
    {
        println!("\n## Period Trend (Older Half -> Recent Half of Scanned Sessions)");
        for (h, cmp) in cmp_map {
            let d = &cmp["delta"];
            println!(
                "- **{h}** ({} older vs {} recent): calls/sess `{}`, re-reads/sess `{}`, crashes/sess `{}`, >8KB spills/sess `{}`",
                cmp["older_half"]["sessions"],
                cmp["recent_half"]["sessions"],
                d["calls_per_session"].as_str().unwrap_or(""),
                d["rereads_per_session"].as_str().unwrap_or(""),
                d["crashes_per_session"].as_str().unwrap_or(""),
                d["spills_over_8kb_per_session"].as_str().unwrap_or(""),
            );
        }
    }

    if let Some(recs) = report["recommended_primitives"]
        .as_array()
        .filter(|a| !a.is_empty())
    {
        println!("\n## Recommended Primitives (`ap init` or `ap init --only <list>`)");
        for r in recs {
            println!(
                "- **`{}`** — {}\n  _{}_",
                r["primitive"].as_str().unwrap_or(""),
                r["evidence"].as_str().unwrap_or(""),
                r["why"].as_str().unwrap_or("")
            );
        }
    }
    if let Some(adapters) = report["recommended_adapters"]
        .as_array()
        .filter(|a| !a.is_empty())
    {
        println!("\n## Recommended On-Demand Adapters (Core + Harness x Model)");
        for a in adapters {
            println!(
                "- **[{}]** `{}` — {}",
                a["layer"].as_str().unwrap_or(""),
                a["command"].as_str().unwrap_or(""),
                a["reason"].as_str().unwrap_or("")
            );
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_home_emits_zero_private_paths_or_prompt_text_and_maps_models() {
        assert_eq!(classify_model_family("deepseek-flash"), "deepseek");
        assert_eq!(classify_model_family("claude-sonnet-4"), "claude");
        assert_eq!(classify_model_family("gpt-5-codex"), "openai");
        assert_eq!(classify_model_family("gemini-2.5-pro"), "gemini");
        assert_eq!(classify_model_family("corp-secret-endpoint-999"), "other");

        let tmp = std::env::temp_dir().join(format!("ap_audit_privacy_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let codex_dir = tmp.join(".codex").join("sessions");
        let pi_dir = tmp.join(".pi").join("agent").join("sessions");
        fs::create_dir_all(&codex_dir).unwrap();
        fs::create_dir_all(&pi_dir).unwrap();

        let codex_lines = [
            json!({
                "payload": {
                    "type": "function_call",
                    "model": "corp-secret-endpoint-999",
                    "arguments": "python -c \"open('C:/PrivateCorp/payroll_2026.csv')\" # SECRET_TOKEN_XYZ_999"
                }
            })
            .to_string(),
            json!({
                "payload": {
                    "type": "function_call_output",
                    "output": "ParserError: Unexpected token && UnicodeDecodeError: 'gbk' codec in C:/PrivateCorp/payroll_2026.csv SECRET_TOKEN_XYZ_999"
                }
            })
            .to_string(),
        ]
        .join("\n");
        fs::write(codex_dir.join("rollout-sample.jsonl"), codex_lines).unwrap();

        let pi_lines = [
            json!({ "type": "model_change", "provider": "deepseek", "modelId": "deepseek-flash" })
                .to_string(),
            json!({
                "type": "message",
                "message": {
                    "role": "assistant",
                    "model": "deepseek-flash",
                    "usage": { "input": 5000, "cacheRead": 50000 },
                    "content": [{ "type": "toolCall", "name": "bash", "arguments": { "command": "python -c 'print(1)'" } }]
                }
            })
            .to_string(),
        ]
        .join("\n");
        fs::write(pi_dir.join("pi-sample.jsonl"), pi_lines).unwrap();

        let report = audit_home(&tmp, 10, false);
        let _ = fs::remove_dir_all(&tmp);
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(
            report["aggregate_friction_counts"]["adhoc_inline_python"]
                .as_u64()
                .unwrap_or(0)
                >= 2
        );
        assert!(
            report["aggregate_friction_counts"]["shell_quoting_collision"]
                .as_u64()
                .unwrap_or(0)
                >= 1
        );
        assert!(
            report["aggregate_friction_counts"]["encoding_utf8_crash"]
                .as_u64()
                .unwrap_or(0)
                >= 1
        );
        assert_eq!(report["model_families_detected"]["deepseek"]["sessions"], 1);
        assert_eq!(report["model_families_detected"]["other"]["sessions"], 1);
        assert!(!report["maintainer_targets"].as_array().unwrap().is_empty());
        assert!(!report["recommended_adapters"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(!serialized.contains("PrivateCorp"));
        assert!(!serialized.contains("payroll_2026"));
        assert!(!serialized.contains("SECRET_TOKEN_XYZ_999"));
        assert!(!serialized.contains("corp-secret-endpoint-999"));
    }

    #[test]
    fn contains_ascii_ci_and_tail_seeking_skip_old_prefix_cleanly() {
        assert!(contains_ascii_ci("Error: TIMED OUT waiting", "timed out"));
        assert!(contains_ascii_ci("Apply_Patch failed ERROR", "error"));
        assert!(!contains_ascii_ci("short", "longer needle"));
        assert!(contains_ascii_ci("abc", ""));

        let tmp = std::env::temp_dir().join(format!("ap_audit_tail_{}.jsonl", std::process::id()));
        let old_line = format!("{{\"old\":\"{}\"}}\n", "x".repeat(400));
        let new_line = "{\"tail_marker\":\"hit\"}\n";
        let payload = format!("{old_line}{old_line}{new_line}");
        fs::write(&tmp, &payload).unwrap();

        let f = File::open(&tmp).unwrap();
        let mut seen = Vec::new();
        for_each_bounded_line_with_cap(f, MAX_LINE_PARSE_BYTES, 128, |line, _| {
            seen.push(line.to_string());
        });
        let _ = fs::remove_file(&tmp);
        assert!(
            seen.iter().any(|l| l.contains("tail_marker")),
            "expected tail line preserved: {seen:?}"
        );
        assert!(
            seen.len() <= 2,
            "expected early lines before tail cap skipped: {seen:?}"
        );
    }
}
