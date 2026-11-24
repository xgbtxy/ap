use crate::audit::default_home_dir;
use crate::stats::record_event;
use base64::Engine;
use clap::Parser;
use regex::Regex;
use serde_json::json;
use std::fs::{self, File};
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    GitBash,
    Pwsh7,
    PowerShell5,
}

#[derive(Parser, Debug)]
#[command(
    name = "exec",
    about = "UTF-8 locked, Bash-in-PowerShell auto-healed, deadlock-proof command runner"
)]
struct ExecCli {
    /// Shell command string to execute safely
    #[arg(short = 'c', long = "cmd")]
    cmd: Option<String>,
    /// Base64-encoded UTF-8 shell command (zero-quoting hook transport)
    #[arg(long)]
    base64: Option<String>,
    /// Working directory
    #[arg(long, default_value = ".")]
    cwd: PathBuf,
    /// Wall-clock timeout in seconds (kills full process tree on timeout)
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    /// Cleanly free an orphaned local TCP port before running (or standalone)
    #[arg(long)]
    free_port: Option<u16>,
    /// Disable automatic sieve compression on large outputs
    #[arg(long)]
    raw: bool,
    /// Scrub leaked secrets and defang indirect prompt-injection signals from output
    #[arg(long)]
    scrub: bool,
    /// Emit structured JSON output
    #[arg(long)]
    json: bool,
    /// Direct argv command when `-c` / `--base64` is not used
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<String>,
}

#[cfg_attr(not(windows), allow(dead_code))]
struct HealRegexes {
    posix_only: Regex,
    ps_cmdlet: Regex,
    slow_grep: Regex,
    py_win_backslash: Regex,
    curl_cmd: Regex,
    dev_null: Regex,
    bare_amp_url: Regex,
    port_in_use: Regex,
    bash_long_sleep: Regex,
    ps_long_sleep: Regex,
    loop_sleep_re: Regex,
    body_sleep_re: Regex,
    bg_sleep_guard: Regex,
    sleep_skip_kw: Regex,
    msys_win_cli_flag: Regex,
    msys_openssl_subj: Regex,
    msys_drive_prefix: Regex,
}

fn heal_re() -> &'static HealRegexes {
    static R: OnceLock<HealRegexes> = OnceLock::new();
    R.get_or_init(|| HealRegexes {
        posix_only: Regex::new(
            r"(<<-?\s*['\x22]?[A-Za-z_]\w*|(?:^|[;&|]\s*)export\s+[A-Za-z_]\w*=|(?:^|[;&|]\s*)(?:if\s+\[|for\s+\w+\s+in\b)|\|\s*(?:head|tail|grep|egrep|awk|sed|wc|cut|tr|xargs)\b)",
        )
        .unwrap(),
        ps_cmdlet: Regex::new(
            r"(?i)(?:^|[;&|]\s*)(?:Get-Content|Get-ChildItem|Select-String|Get-Date|ForEach-Object|ConvertFrom-Json|Invoke-WebRequest|Invoke-RestMethod|Test-Path|Set-Content)\b",
        )
        .unwrap(),
        slow_grep: Regex::new(
            r#"^\s*grep\s+(-[rR][A-Za-z]*)\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))(?:\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+)))?\s*$"#,
        )
        .unwrap(),
        py_win_backslash: Regex::new(r#"(?i)\b(?:python3?|py)\s+-c\s+.*['"][A-Za-z]:\\"#).unwrap(),
        curl_cmd: Regex::new(r"(^|[;|&(\s])curl(\s+(?:-[A-Za-z-]|https?://))").unwrap(),
        dev_null: Regex::new(r"([12]?>+\s*)/dev/null\b").unwrap(),
        bare_amp_url: Regex::new(r#"(^|[\s=])(https?://[^\s'"`;&|]+&[^\s'"`;&|]+)"#).unwrap(),
        port_in_use: Regex::new(r"(?i)(?:EADDRINUSE|address already in use|10048).*?(?::(\d{2,5})\b|\bport\s+(\d{2,5})\b)").unwrap(),
        bash_long_sleep: Regex::new(r"(?i)(^|[;&|]\s*)sleep\s+(\d+(?:\.\d+)?)s?(\s*(?:$|[;&|]))").unwrap(),
        ps_long_sleep: Regex::new(r"(?i)(^|[;&|]\s*)Start-Sleep(?:\s+-s(?:ec(?:ond)?s?)?)?\s+(\d+(?:\.\d+)?)(\s*(?:$|[;&|]))").unwrap(),
        loop_sleep_re: Regex::new(r"(?is)\b(for\s+\w+\s+in\s+(?:\$\(\s*seq\s+(?:(\d+)\s+)?(\d+)\s*\)|([^\r\n;]+));\s*do\b)([\s\S]*?)(\bdone\b)").unwrap(),
        body_sleep_re: Regex::new(r"(?i)(^|[;&|\s])sleep\s+(\d+(?:\.\d+)?)s?(\s*(?:$|[;&|]))").unwrap(),
        bg_sleep_guard: Regex::new(r"(?i)(?:&\s*$|\(\s*[^)]*\bsleep\b[^)]*\)\s*&)").unwrap(),
        sleep_skip_kw: Regex::new(r"(?i)(?:\bnohup\b|<<|\b(?:python3?|py|node)\b)").unwrap(),
        msys_win_cli_flag: Regex::new(
            r"(?i)(?:^|[;&|]\s*)(?:cmd(?:\.exe)?|taskkill(?:\.exe)?|tasklist(?:\.exe)?|sc(?:\.exe)?|icacls(?:\.exe)?|reg(?:\.exe)?|netstat(?:\.exe)?|whoami(?:\.exe)?|schtasks(?:\.exe)?|wevtutil(?:\.exe)?|netsh(?:\.exe)?|where(?:\.exe)?|wmic(?:\.exe)?|certutil(?:\.exe)?|bcdedit(?:\.exe)?|secedit(?:\.exe)?)\b[^\r\n;&|]*?\s/[A-Za-z?]",
        )
        .unwrap(),
        msys_openssl_subj: Regex::new(r#"(?i)\bopenssl\b[^\r\n;&|]*?\s-subj\s+['"]?/"#).unwrap(),
        msys_drive_prefix: Regex::new(
            r#"(^|[\s'"=])/([a-zA-Z])/([^\s'"`;&|<>()]*)"#,
        )
        .unwrap(),
    })
}

/// Shield Git Bash MSYS2 path conversion when invoking native Windows CLIs with `/flag` arguments
/// (e.g. `cmd /c`, `taskkill /F /PID`, `icacls ... /grant`, `sc query`, `reg query`) or `openssl -subj '/CN=...'`.
/// Skips commands that already set `MSYS_NO_PATHCONV` / `MSYS2_ARG_CONV_EXCL` or already use explicit `//flag` escapes,
/// and converts explicit MSYS `/c/...` drive paths -> `C:/...` first so Windows native tools keep resolving paths.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn try_shield_msys_pathconv(raw: &str) -> Option<String> {
    let re = heal_re();
    if raw.contains("MSYS_NO_PATHCONV") || raw.contains("MSYS2_ARG_CONV_EXCL") {
        return None;
    }
    let has_double_slash_flag = raw
        .split_whitespace()
        .any(|tok| tok.starts_with("//") && tok.len() >= 3);
    if has_double_slash_flag {
        return None;
    }
    if !re.msys_win_cli_flag.is_match(raw) && !re.msys_openssl_subj.is_match(raw) {
        return None;
    }
    let converted = re
        .msys_drive_prefix
        .replace_all(raw, |caps: &regex::Captures| {
            let pfx = &caps[1];
            let drv = caps[2].to_ascii_uppercase();
            let tail = &caps[3];
            format!("{pfx}{drv}:/{tail}")
        })
        .into_owned();
    let trimmed = converted.trim_start();
    if trimmed.contains('\n') {
        Some(format!("export MSYS_NO_PATHCONV=1\n{converted}"))
    } else if trimmed.contains("&&")
        || trimmed.contains("||")
        || trimmed.contains(';')
        || trimmed.contains('|')
    {
        Some(format!("export MSYS_NO_PATHCONV=1; {converted}"))
    } else {
        Some(format!("MSYS_NO_PATHCONV=1 {converted}"))
    }
}

/// Clamp long foreground synchronous sleeps (>= 60s) and polling sleep loops (`iters * secs >= 90`)
/// so total synchronous wait stays <= `max_sec` without touching short, background, heredoc, or Python/Node sleeps.
pub fn try_cap_long_sleep(raw: &str, max_sec: u64) -> Option<String> {
    let re = heal_re();
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || re.sleep_skip_kw.is_match(trimmed)
        || re.bg_sleep_guard.is_match(trimmed)
    {
        return None;
    }
    let mut changed = false;
    let after_bash = re
        .bash_long_sleep
        .replace_all(raw, |caps: &regex::Captures| {
            let secs = caps
                .get(2)
                .and_then(|m| m.as_str().parse::<f64>().ok())
                .unwrap_or(0.0);
            if secs >= 60.0 {
                changed = true;
                format!("{}sleep {}{}", &caps[1], max_sec, &caps[3])
            } else {
                caps[0].to_string()
            }
        });
    let after_loop = re
        .loop_sleep_re
        .replace_all(&after_bash, |caps: &regex::Captures| {
            let iters: u64 = if let Some(end_m) = caps.get(3) {
                let start_n = caps
                    .get(2)
                    .and_then(|m| m.as_str().parse::<u64>().ok())
                    .unwrap_or(1);
                let end_n = end_m.as_str().parse::<u64>().unwrap_or(0);
                if end_n >= start_n {
                    end_n - start_n + 1
                } else {
                    0
                }
            } else if let Some(wl) = caps.get(4) {
                let wc = wl.as_str().split_whitespace().count() as u64;
                if wc >= 3 {
                    wc
                } else {
                    0
                }
            } else {
                0
            };
            if iters < 3 {
                return caps[0].to_string();
            }
            let body = &caps[5];
            let mut loop_changed = false;
            let new_body = re.body_sleep_re.replace_all(body, |bc: &regex::Captures| {
                let s_num = bc
                    .get(2)
                    .and_then(|m| m.as_str().parse::<f64>().ok())
                    .unwrap_or(0.0);
                if s_num > 0.0 && (iters as f64) * s_num >= 90.0 {
                    let per_iter = (max_sec / iters).max(2);
                    if (per_iter as f64) < s_num {
                        loop_changed = true;
                        return format!("{}sleep {}{}", &bc[1], per_iter, &bc[3]);
                    }
                }
                bc[0].to_string()
            });
            if loop_changed {
                changed = true;
                format!("{}{}{}", &caps[1], new_body, &caps[6])
            } else {
                caps[0].to_string()
            }
        });
    let after_ps = re
        .ps_long_sleep
        .replace_all(&after_loop, |caps: &regex::Captures| {
            let secs = caps
                .get(2)
                .and_then(|m| m.as_str().parse::<f64>().ok())
                .unwrap_or(0.0);
            if secs >= 60.0 {
                changed = true;
                format!("{}Start-Sleep -Seconds {}{}", &caps[1], max_sec, &caps[3])
            } else {
                caps[0].to_string()
            }
        });
    if changed {
        Some(after_ps.into_owned())
    } else {
        None
    }
}

fn split_leading_cd_prefix(raw: &str) -> (Option<&str>, &str) {
    static CD_PFX_RE: OnceLock<Regex> = OnceLock::new();
    let re = CD_PFX_RE.get_or_init(|| {
        Regex::new(r#"^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)([\s\S]+)$"#).unwrap()
    });
    if let Some(caps) = re.captures(raw) {
        if let (Some(p), Some(rest)) = (caps.get(1), caps.get(2)) {
            return (Some(p.as_str()), rest.as_str());
        }
    }
    (None, raw)
}

/// Detect bare or `| head -n N` / `2>/dev/null`-tailed recursive GNU `grep -rn` / `grep -rl` `<pat> [path]`
/// (which hangs 60-180s on large Windows trees) — including after a leading `cd <dir> &&` prefix —
/// and rewrite cleanly to sub-50ms `ap search`.
pub fn try_accelerate_slow_grep(raw: &str) -> Option<String> {
    let (cd_pfx, body) = split_leading_cd_prefix(raw);
    static TAIL_HEAD_RE: OnceLock<(Regex, Regex)> = OnceLock::new();
    let (head_pipe_re, stderr_null_re) = TAIL_HEAD_RE.get_or_init(|| {
        (
            Regex::new(r#"(?is)^([\s\S]+?)\s*\|\s*head\s+(?:-n\s*(\d+)|-(\d+))\s*$"#).unwrap(),
            Regex::new(r#"(?i)\s+2>\s*(?:/dev/null|NUL|&1)\s*$"#).unwrap(),
        )
    });
    let mut max_hits: Option<usize> = None;
    let mut core_body = body;
    if let Some(hcap) = head_pipe_re.captures(body) {
        let n: usize = hcap.get(2).or_else(|| hcap.get(3))?.as_str().parse().ok()?;
        if n == 0 {
            return None;
        }
        max_hits = Some(n);
        core_body = hcap.get(1)?.as_str();
    }
    let clean_owned = stderr_null_re.replace(core_body.trim(), "").into_owned();
    let grep_body = clean_owned.trim();
    if has_unsafe_shell_meta(grep_body) {
        return None;
    }
    let cap = heal_re().slow_grep.captures(grep_body)?;
    let flags = cap.get(1).map(|m| m.as_str()).unwrap_or("");
    let pat = cap
        .get(2)
        .or_else(|| cap.get(3))
        .or_else(|| cap.get(4))
        .map(|m| m.as_str())?;
    let target = cap
        .get(5)
        .or_else(|| cap.get(6))
        .or_else(|| cap.get(7))
        .map(|m| m.as_str())
        .unwrap_or(".");
    let ap_bin = std::env::current_exe()
        .ok()
        .filter(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("ap"))
                .unwrap_or(false)
        })
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| "ap".to_string());
    let pat_esc = pat.replace('"', "\\\"");
    let mut args_out = String::new();
    if flags.contains('l') {
        args_out.push_str(" --files-only");
    } else if flags.contains('c') {
        args_out.push_str(" --count");
    }
    if flags.contains('o') {
        args_out.push_str(" --only-matching");
    }
    if flags.contains('h') {
        args_out.push_str(" --no-filename");
    }
    if flags.contains('i') {
        args_out.push_str(" --ignore-case");
    }
    if flags.contains('F') {
        args_out.push_str(" --fixed-strings");
    }
    if let Some(n) = max_hits {
        args_out.push_str(&format!(" --max {n}"));
    }
    Some(format!(
        "{}\"{ap_bin}\" search{args_out} \"{pat_esc}\" \"{target}\"",
        cd_pfx.unwrap_or("")
    ))
}

/// Rewrite MS-DOS `dir /b [flags] [path]` (even after leading `cd <dir> &&`, and including `/a-d`, `/a:-d`, `/o:n`, etc.)
/// cleanly to bounded `ap ls` with `--depth 3` when `/s` is present. Passes through pipes and globs safely.
pub fn try_heal_windows_dir_cmd(raw: &str) -> Option<String> {
    let (cd_pfx, body) = split_leading_cd_prefix(raw);
    if has_unsafe_shell_meta(body) {
        return None;
    }
    let toks = split_ps_args(body.trim())?;
    let head = toks.first()?;
    if !head.eq_ignore_ascii_case("dir") {
        return None;
    }
    let mut bare = false;
    let mut recursive = false;
    let mut target: Option<String> = None;
    for tok in toks.into_iter().skip(1) {
        if tok.eq_ignore_ascii_case("/b") {
            bare = true;
        } else if tok.eq_ignore_ascii_case("/s") {
            recursive = true;
        } else if tok.starts_with('/') && tok.len() >= 2 {
            continue;
        } else if target.is_none() {
            if tok.contains('*') || tok.contains('?') || tok.contains(',') {
                return None;
            }
            target = Some(tok);
        } else {
            return None;
        }
    }
    if !bare {
        return None;
    }
    let ap_bin = std::env::current_exe()
        .ok()
        .filter(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("ap"))
                .unwrap_or(false)
        })
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| "ap".to_string());
    let depth_flag = if recursive { " --depth 3" } else { "" };
    let tgt_arg = target.unwrap_or_else(|| ".".to_string());
    let tgt_esc = tgt_arg.replace('"', "\\\"");
    Some(format!(
        "{}\"{ap_bin}\" ls \"{tgt_esc}\"{depth_flag}",
        cd_pfx.unwrap_or("")
    ))
}

fn split_ps_args(s: &str) -> Option<Vec<String>> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for ch in s.chars() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                cur.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if ch.is_whitespace() {
            if !cur.is_empty() {
                toks.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(ch);
        }
    }
    if quote.is_some() {
        return None;
    }
    if !cur.is_empty() {
        toks.push(cur);
    }
    Some(toks)
}

/// Rewrite bare PowerShell `Select-String -Pattern <pat> -Path <path>` (or `sls`, optionally after leading `cd <dir> &&`)
/// cleanly to sub-50ms `ap search`, while bailing out safely on pipes, arrays, wildcards, or unsupported flags.
pub fn try_accelerate_select_string(raw: &str) -> Option<String> {
    let (cd_pfx, body) = split_leading_cd_prefix(raw);
    if body.contains('|')
        || body.contains(';')
        || body.contains("&&")
        || body.contains('>')
        || body.contains('<')
        || body.contains('{')
        || body.contains('}')
        || body.contains("$(")
        || body.contains('`')
    {
        return None;
    }
    let toks = split_ps_args(body.trim())?;
    let head = toks.first()?.to_ascii_lowercase();
    if head != "select-string" && head != "sls" {
        return None;
    }

    let mut pattern: Option<String> = None;
    let mut path: Option<String> = None;
    let mut simple_match = false;
    let mut case_sensitive = false;
    let mut files_only = false;

    let mut i = 1usize;
    while i < toks.len() {
        let tok = &toks[i];
        let low = tok.to_ascii_lowercase();
        if low == "-pattern" {
            let val = toks.get(i + 1)?;
            pattern = Some(val.clone());
            i += 2;
        } else if low == "-path" || low == "-literalpath" {
            let val = toks.get(i + 1)?;
            if val.contains(',') || val.contains('*') || val.contains('?') {
                return None;
            }
            path = Some(val.clone());
            i += 2;
        } else if low == "-simplematch" {
            simple_match = true;
            i += 1;
        } else if low == "-casesensitive" {
            case_sensitive = true;
            i += 1;
        } else if low == "-list" {
            files_only = true;
            i += 1;
        } else if tok.starts_with('-') {
            return None;
        } else if pattern.is_none() {
            pattern = Some(tok.clone());
            i += 1;
        } else if path.is_none() {
            if tok.contains(',') || tok.contains('*') || tok.contains('?') {
                return None;
            }
            path = Some(tok.clone());
            i += 1;
        } else {
            return None;
        }
    }

    let pat = pattern?;
    if pat.is_empty() {
        return None;
    }
    let tgt = path.unwrap_or_else(|| ".".to_string());
    let ap_bin = std::env::current_exe()
        .ok()
        .filter(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("ap"))
                .unwrap_or(false)
        })
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| "ap".to_string());

    let mut flags = String::new();
    if files_only {
        flags.push_str(" --files-only");
    }
    if simple_match {
        flags.push_str(" --fixed-strings");
    }
    if !case_sensitive {
        flags.push_str(" --ignore-case");
    }
    let pat_esc = pat.replace('"', "\\\"");
    let tgt_esc = tgt.replace('"', "\\\"");
    Some(format!(
        "{}\"{ap_bin}\" search{flags} \"{pat_esc}\" \"{tgt_esc}\"",
        cd_pfx.unwrap_or("")
    ))
}

fn has_unsafe_shell_meta(body: &str) -> bool {
    body.contains('|')
        || body.contains(';')
        || body.contains("&&")
        || body.contains('>')
        || body.contains('<')
        || body.contains('{')
        || body.contains('}')
        || body.contains("$(")
        || body.contains('`')
}

/// Rewrite bare PowerShell `Get-Content` / `gc` calls cleanly to UTF-8-safe `ap read`
/// (with optional `--limit` for `-Head`/`-TotalCount`/`-First`), while safely passing through pipes,
/// globs, `-Tail`, `-Wait`, or complex switches.
pub fn try_accelerate_get_content(raw: &str) -> Option<String> {
    let (cd_pfx, body) = split_leading_cd_prefix(raw);
    if has_unsafe_shell_meta(body) {
        return None;
    }
    let toks = split_ps_args(body.trim())?;
    let head = toks.first()?.to_ascii_lowercase();
    if head != "get-content" && head != "gc" {
        return None;
    }
    let mut path: Option<String> = None;
    let mut limit: Option<usize> = None;
    let mut i = 1usize;
    while i < toks.len() {
        let tok = &toks[i];
        let low = tok.to_ascii_lowercase();
        if low == "-path" || low == "-literalpath" {
            let val = toks.get(i + 1)?;
            if val.contains(',') || val.contains('*') || val.contains('?') {
                return None;
            }
            path = Some(val.clone());
            i += 2;
        } else if low == "-totalcount" || low == "-head" || low == "-first" {
            let n: usize = toks.get(i + 1)?.parse().ok()?;
            if n == 0 {
                return None;
            }
            limit = Some(n);
            i += 2;
        } else if low == "-raw" {
            i += 1;
        } else if low == "-encoding" {
            let enc = toks.get(i + 1)?.to_ascii_lowercase();
            if enc != "utf8" && enc != "utf8nobom" {
                return None;
            }
            i += 2;
        } else if tok.starts_with('-') {
            return None;
        } else if path.is_none() {
            if tok.contains(',') || tok.contains('*') || tok.contains('?') {
                return None;
            }
            path = Some(tok.clone());
            i += 1;
        } else {
            return None;
        }
    }
    let tgt = path?;
    let ap_bin = std::env::current_exe()
        .ok()
        .filter(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("ap"))
                .unwrap_or(false)
        })
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| "ap".to_string());
    let limit_flag = limit.map(|n| format!(" --lines 1-{n}")).unwrap_or_default();
    let tgt_esc = tgt.replace('"', "\\\"");
    Some(format!(
        "{}\"{ap_bin}\" read \"{tgt_esc}\"{limit_flag}",
        cd_pfx.unwrap_or("")
    ))
}

/// Rewrite bare `sed -n '<start>,<end>p' <file>` (with optional leading `cd <dir> &&`) cleanly
/// to bounded `ap read "<file>" --lines <start>-<end>`. Passes through piped or complex sed expressions.
pub fn try_accelerate_sed_slice(raw: &str) -> Option<String> {
    let (cd_pfx, body) = split_leading_cd_prefix(raw);
    if has_unsafe_shell_meta(body) {
        return None;
    }
    static SED_RE: OnceLock<Regex> = OnceLock::new();
    let re = SED_RE.get_or_init(|| {
        Regex::new(
            r#"^\s*sed\s+-n\s+(?:'(\d+),(\d+)p'|"(\d+),(\d+)p"|(\d+),(\d+)p)\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))\s*$"#,
        )
        .unwrap()
    });
    let cap = re.captures(body.trim())?;
    let s_str = cap
        .get(1)
        .or_else(|| cap.get(3))
        .or_else(|| cap.get(5))?
        .as_str();
    let e_str = cap
        .get(2)
        .or_else(|| cap.get(4))
        .or_else(|| cap.get(6))?
        .as_str();
    let start: usize = s_str.parse().ok()?;
    let end: usize = e_str.parse().ok()?;
    if start == 0 || end < start {
        return None;
    }
    let file = cap
        .get(7)
        .or_else(|| cap.get(8))
        .or_else(|| cap.get(9))?
        .as_str();
    if file.contains('*') || file.contains('?') || file.contains(',') {
        return None;
    }
    let ap_bin = std::env::current_exe()
        .ok()
        .filter(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("ap"))
                .unwrap_or(false)
        })
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| "ap".to_string());
    let file_esc = file.replace('"', "\\\"");
    Some(format!(
        "{}\"{ap_bin}\" read \"{file_esc}\" --lines {start}-{end}",
        cd_pfx.unwrap_or("")
    ))
}

/// Rewrite bare `head -n <N> <file>` or `head -<N> <file>` (with optional leading `cd <dir> &&`) cleanly
/// to bounded `ap read "<file>" --lines 1-<N>`. Passes through piped `head` streams safely.
pub fn try_accelerate_head_slice(raw: &str) -> Option<String> {
    let (cd_pfx, body) = split_leading_cd_prefix(raw);
    if has_unsafe_shell_meta(body) {
        return None;
    }
    static HEAD_RE: OnceLock<Regex> = OnceLock::new();
    let re = HEAD_RE.get_or_init(|| {
        Regex::new(
            r#"^\s*head\s+(?:-n\s*(\d+)|-(\d+))\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))\s*$"#,
        )
        .unwrap()
    });
    let cap = re.captures(body.trim())?;
    let n: usize = cap.get(1).or_else(|| cap.get(2))?.as_str().parse().ok()?;
    if n == 0 {
        return None;
    }
    let file = cap
        .get(3)
        .or_else(|| cap.get(4))
        .or_else(|| cap.get(5))?
        .as_str();
    if file.contains('*') || file.contains('?') || file.contains(',') {
        return None;
    }
    let ap_bin = std::env::current_exe()
        .ok()
        .filter(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("ap"))
                .unwrap_or(false)
        })
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| "ap".to_string());
    let file_esc = file.replace('"', "\\\"");
    Some(format!(
        "{}\"{ap_bin}\" read \"{file_esc}\" --lines 1-{n}",
        cd_pfx.unwrap_or("")
    ))
}

/// Rewrite bare `tail -n <N> <file>` or `tail -<N> <file>` (with optional leading `cd <dir> &&`) cleanly
/// to bounded `ap read "<file>" --tail <N>`. Passes through `-f`, `--follow`, `+N`, pipes, and globs safely.
pub fn try_accelerate_tail_slice(raw: &str) -> Option<String> {
    let (cd_pfx, body) = split_leading_cd_prefix(raw);
    if has_unsafe_shell_meta(body) {
        return None;
    }
    static TAIL_RE: OnceLock<Regex> = OnceLock::new();
    let re = TAIL_RE.get_or_init(|| {
        Regex::new(
            r#"^\s*tail\s+(?:-n\s*(\d+)|-(\d+))\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&-]+))\s*$"#,
        )
        .unwrap()
    });
    let cap = re.captures(body.trim())?;
    let n: usize = cap.get(1).or_else(|| cap.get(2))?.as_str().parse().ok()?;
    if n == 0 {
        return None;
    }
    let file = cap
        .get(3)
        .or_else(|| cap.get(4))
        .or_else(|| cap.get(5))?
        .as_str();
    if file.contains('*') || file.contains('?') || file.contains(',') {
        return None;
    }
    let ap_bin = std::env::current_exe()
        .ok()
        .filter(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("ap"))
                .unwrap_or(false)
        })
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| "ap".to_string());
    let file_esc = file.replace('"', "\\\"");
    Some(format!(
        "{}\"{ap_bin}\" read \"{file_esc}\" --tail {n}",
        cd_pfx.unwrap_or("")
    ))
}

/// Rewrite single-file `cat <file> | head -n <N>`, `cat <file> | tail -n <N>`, or `cat <file> | sed -n '<A>,<B>p'`
/// (with optional leading `cd <dir> &&`) cleanly to bounded `ap read`. Passes through multi-file `cat` and globs.
pub fn try_accelerate_cat_slice(raw: &str) -> Option<String> {
    let (cd_pfx, body) = split_leading_cd_prefix(raw);
    if body.contains(';')
        || body.contains("&&")
        || body.contains('>')
        || body.contains('<')
        || body.contains('{')
        || body.contains('}')
        || body.contains("$(")
        || body.contains('`')
    {
        return None;
    }
    let (lhs, rhs) = body.split_once('|')?;
    if rhs.contains('|') {
        return None;
    }
    static CAT_RE: OnceLock<(Regex, Regex, Regex, Regex)> = OnceLock::new();
    let (cat_re, head_re, tail_re, sed_re) = CAT_RE.get_or_init(|| {
        (
            Regex::new(r#"^\s*cat\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&-]+))\s*$"#).unwrap(),
            Regex::new(r#"^\s*head\s+(?:-n\s*(\d+)|-(\d+))\s*$"#).unwrap(),
            Regex::new(r#"^\s*tail\s+(?:-n\s*(\d+)|-(\d+))\s*$"#).unwrap(),
            Regex::new(r#"^\s*sed\s+-n\s+(?:'(\d+),(\d+)p'|"(\d+),(\d+)p"|(\d+),(\d+)p)\s*$"#)
                .unwrap(),
        )
    });
    let cat_cap = cat_re.captures(lhs.trim())?;
    let file = cat_cap
        .get(1)
        .or_else(|| cat_cap.get(2))
        .or_else(|| cat_cap.get(3))?
        .as_str();
    if file == "-" || file.contains('*') || file.contains('?') || file.contains(',') {
        return None;
    }
    let rhs_t = rhs.trim();
    let slice_flag = if let Some(hc) = head_re.captures(rhs_t) {
        let n: usize = hc.get(1).or_else(|| hc.get(2))?.as_str().parse().ok()?;
        if n == 0 {
            return None;
        }
        format!("--lines 1-{n}")
    } else if let Some(tc) = tail_re.captures(rhs_t) {
        let n: usize = tc.get(1).or_else(|| tc.get(2))?.as_str().parse().ok()?;
        if n == 0 {
            return None;
        }
        format!("--tail {n}")
    } else {
        let sc = sed_re.captures(rhs_t)?;
        let s: usize = sc
            .get(1)
            .or_else(|| sc.get(3))
            .or_else(|| sc.get(5))?
            .as_str()
            .parse()
            .ok()?;
        let e: usize = sc
            .get(2)
            .or_else(|| sc.get(4))
            .or_else(|| sc.get(6))?
            .as_str()
            .parse()
            .ok()?;
        if s == 0 || e < s {
            return None;
        }
        format!("--lines {s}-{e}")
    };
    let ap_bin = std::env::current_exe()
        .ok()
        .filter(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("ap"))
                .unwrap_or(false)
        })
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| "ap".to_string());
    let file_esc = file.replace('"', "\\\"");
    Some(format!(
        "{}\"{ap_bin}\" read \"{file_esc}\" {slice_flag}",
        cd_pfx.unwrap_or("")
    ))
}

/// Rewrite bounded `find [path] [-maxdepth N] [-type f|d] [-name "*.ext"] [2>/dev/null] [| head -n M]`
/// (with optional leading `cd <dir> &&`) to bounded `ap ls`. Passes through complex predicates (`-exec`, `-o`, `!`, `(`, `-size`, etc.).
pub fn try_accelerate_find_files(raw: &str) -> Option<String> {
    let (cd_pfx, body) = split_leading_cd_prefix(raw);
    static HEAD_PIPE_RE: OnceLock<Regex> = OnceLock::new();
    static STDERR_NULL_RE: OnceLock<Regex> = OnceLock::new();
    static EXT_RE: OnceLock<Regex> = OnceLock::new();
    let head_pipe_re = HEAD_PIPE_RE
        .get_or_init(|| Regex::new(r"^(?s)(.+?)\s*\|\s*head\s+(?:-n\s*(\d+)|-(\d+))\s*$").unwrap());
    let stderr_null_re =
        STDERR_NULL_RE.get_or_init(|| Regex::new(r"\s*2>\s*/dev/null\s*$").unwrap());
    let ext_re = EXT_RE.get_or_init(|| Regex::new(r"^\*\.([A-Za-z0-9_]+)$").unwrap());

    let mut limit: Option<usize> = None;
    let mut core = body;
    if let Some(hcap) = head_pipe_re.captures(body) {
        let n: usize = hcap.get(2).or_else(|| hcap.get(3))?.as_str().parse().ok()?;
        if n == 0 {
            return None;
        }
        limit = Some(n);
        core = hcap.get(1)?.as_str();
    }
    let clean_owned = stderr_null_re.replace(core.trim(), "").into_owned();
    let find_body = clean_owned.trim();
    if has_unsafe_shell_meta(find_body) {
        return None;
    }
    let toks = split_ps_args(find_body)?;
    if toks.first()?.as_str() != "find" {
        return None;
    }
    let mut idx = 1usize;
    let target = if let Some(first_arg) = toks.get(idx) {
        if !first_arg.starts_with('-')
            && !matches!(first_arg.as_str(), "(" | ")" | "!" | "\\(" | "\\)")
        {
            if first_arg.contains('*') || first_arg.contains('?') || first_arg.contains(',') {
                return None;
            }
            idx += 1;
            first_arg.as_str()
        } else {
            "."
        }
    } else {
        "."
    };

    let mut depth: usize = 3;
    let mut files_only = false;
    let mut dirs_only = false;
    let mut ext: Option<String> = None;
    while idx < toks.len() {
        match toks[idx].as_str() {
            "-maxdepth" => {
                let d: usize = toks.get(idx + 1)?.parse().ok()?;
                if d == 0 || d > 5 {
                    return None;
                }
                depth = d;
                idx += 2;
            }
            "-type" => {
                match toks.get(idx + 1)?.as_str() {
                    "f" => files_only = true,
                    "d" => dirs_only = true,
                    _ => return None,
                }
                if files_only && dirs_only {
                    return None;
                }
                idx += 2;
            }
            "-name" => {
                if ext.is_some() {
                    return None;
                }
                let pat = toks.get(idx + 1)?;
                let ecap = ext_re.captures(pat)?;
                ext = Some(ecap.get(1)?.as_str().to_string());
                idx += 2;
            }
            _ => return None,
        }
    }

    let ap_bin = std::env::current_exe()
        .ok()
        .filter(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("ap"))
                .unwrap_or(false)
        })
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| "ap".to_string());
    let tgt_esc = target.replace('"', "\\\"");
    let mut flags = format!(" --depth {depth}");
    if files_only {
        flags.push_str(" --files-only");
    } else if dirs_only {
        flags.push_str(" --dirs-only");
    }
    if let Some(e) = ext {
        flags.push_str(&format!(" --ext {e}"));
    }
    if let Some(m) = limit {
        flags.push_str(&format!(" --limit {m}"));
    }
    Some(format!(
        "{}\"{ap_bin}\" ls \"{tgt_esc}\"{flags}",
        cd_pfx.unwrap_or("")
    ))
}

/// Rewrite bare PowerShell `Get-ChildItem` / `gci` calls cleanly to bounded `ap ls`
/// (with `--depth`), while safely passing through pipes, `-Filter`/`-Include`, or globs.
pub fn try_accelerate_get_child_item(raw: &str) -> Option<String> {
    let (cd_pfx, body) = split_leading_cd_prefix(raw);
    if has_unsafe_shell_meta(body) {
        return None;
    }
    let toks = split_ps_args(body.trim())?;
    let head = toks.first()?.to_ascii_lowercase();
    if head != "get-childitem" && head != "gci" {
        return None;
    }
    let mut path: Option<String> = None;
    let mut recurse = false;
    let mut depth: Option<usize> = None;
    let mut i = 1usize;
    while i < toks.len() {
        let tok = &toks[i];
        let low = tok.to_ascii_lowercase();
        if low == "-path" || low == "-literalpath" {
            let val = toks.get(i + 1)?;
            if val.contains(',') || val.contains('*') || val.contains('?') {
                return None;
            }
            path = Some(val.clone());
            i += 2;
        } else if low == "-recurse" {
            recurse = true;
            i += 1;
        } else if low == "-name" {
            i += 1;
        } else if low == "-depth" {
            let d: usize = toks.get(i + 1)?.parse().ok()?;
            depth = Some(d.max(1));
            i += 2;
        } else if tok.starts_with('-') {
            return None;
        } else if path.is_none() {
            if tok.contains(',') || tok.contains('*') || tok.contains('?') {
                return None;
            }
            path = Some(tok.clone());
            i += 1;
        } else {
            return None;
        }
    }
    let tgt = path.unwrap_or_else(|| ".".to_string());
    let ap_bin = std::env::current_exe()
        .ok()
        .filter(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("ap"))
                .unwrap_or(false)
        })
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| "ap".to_string());
    let depth_flag = match depth {
        Some(d) => format!(" --depth {d}"),
        None if recurse => " --depth 3".to_string(),
        None => String::new(),
    };
    let tgt_esc = tgt.replace('"', "\\\"");
    Some(format!(
        "{}\"{ap_bin}\" ls \"{tgt_esc}\"{depth_flag}",
        cd_pfx.unwrap_or("")
    ))
}

/// Retry bare `rg <pattern>` commands (including after leading `cd <dir> &&`) that exited 2 with `rg: regex parse error` as literal `rg -F <pattern>`.
pub fn try_build_rg_fixed_retry(raw: &str) -> Option<String> {
    let (cd_pfx, body) = split_leading_cd_prefix(raw);
    if body.contains('|') || body.contains(';') || body.contains("&&") || body.contains('>') {
        return None;
    }
    let trimmed = body.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    let prefix_len = if lower.starts_with("rg.exe ") || lower.starts_with("rg.exe\t") {
        6
    } else if lower.starts_with("rg ") || lower.starts_with("rg\t") {
        2
    } else {
        return None;
    };
    let tail = &trimmed[prefix_len..];
    if tail
        .split_whitespace()
        .any(|t| t == "-F" || t == "--fixed-strings" || t == "-P" || t == "--pcre2")
    {
        return None;
    }
    Some(format!(
        "{}{} -F{tail}",
        cd_pfx.unwrap_or(""),
        &trimmed[..prefix_len]
    ))
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn split_top_level_and_and(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_sq = false;
    let mut in_dq = false;
    let mut depth = 0i32;
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = s[i..].chars().next().unwrap();
        let clen = ch.len_utf8();
        if ch == '`' && !in_sq && i + clen < bytes.len() {
            let nxt = s[i + clen..].chars().next().unwrap();
            cur.push(ch);
            cur.push(nxt);
            i += clen + nxt.len_utf8();
            continue;
        }
        if ch == '\'' && !in_dq {
            in_sq = !in_sq;
        } else if ch == '"' && !in_sq {
            in_dq = !in_dq;
        } else if !in_sq && !in_dq {
            if ch == '(' || ch == '{' {
                depth += 1;
            } else if ch == ')' || ch == '}' {
                depth = (depth - 1).max(0);
            } else if depth == 0
                && ch == '&'
                && bytes.get(i + 1) == Some(&b'&')
                && bytes.get(i + 2) != Some(&b'&')
            {
                parts.push(cur.trim().to_string());
                cur.clear();
                i += 2;
                continue;
            }
        }
        cur.push(ch);
        i += clen;
    }
    if !cur.trim().is_empty() || !parts.is_empty() {
        parts.push(cur.trim().to_string());
    }
    parts
}

/// Safely normalize unescaped Windows drive backslashes (`'C:\foo\bar'` -> `'C:/foo/bar'`)
/// inside `python -c` non-raw string literals, while leaving Python raw strings (`r'C:\foo'`)
/// and already-escaped strings (`'C:\\foo'`) completely untouched.
#[cfg_attr(not(windows), allow(dead_code))]
fn contains_lethal_py_backslash(seg: &str) -> bool {
    if seg.contains("\\\\") {
        return false;
    }
    let bytes = seg.as_bytes();
    if bytes.len() >= 4 && bytes[1].is_ascii_alphabetic() && bytes[2] == b':' && bytes[3] == b'\\' {
        return true;
    }
    const SEG_KEYS: [&str; 12] = [
        "\\Users",
        "\\Network",
        "\\Windows",
        "\\AppData",
        "\\Local",
        "\\Roaming",
        "\\System32",
        "\\Program Files",
        "\\Temp",
        "\\Desktop",
        "\\Documents",
        "\\Default",
    ];
    SEG_KEYS.iter().any(|k| {
        seg.find(k).is_some_and(|idx| {
            let after = idx + k.len();
            matches!(seg.as_bytes().get(after), Some(b'\\') | None)
        })
    })
}

fn heal_py_win_backslashes(cmd: &str) -> (String, bool) {
    let b = cmd.as_bytes();
    let mut out = String::with_capacity(cmd.len());
    let mut i = 0usize;
    let mut changed = false;
    while i < b.len() {
        let ch = b[i];
        if ch == b'\'' || ch == b'"' {
            let quote = ch;
            let other = if quote == b'"' { b'\'' } else { b'"' };
            let prev_is_raw = i > 0
                && matches!(b[i - 1], b'r' | b'R')
                && (i == 1 || !(b[i - 2].is_ascii_alphanumeric() || b[i - 2] == b'_'));
            let mut end = i + 1;
            while end < b.len() && b[end] != quote && b[end] != b'\n' && b[end] != b'\r' {
                end += 1;
            }
            if end < b.len() && b[end] == quote {
                if prev_is_raw {
                    out.push_str(&cmd[i..=end]);
                    i = end + 1;
                    continue;
                }
                if !b[i + 1..end].contains(&other) {
                    let inner = &cmd[i..=end];
                    if contains_lethal_py_backslash(inner) {
                        out.push_str(&inner.replace('\\', "/"));
                        changed = true;
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        let next_ch = cmd[i..].chars().next().unwrap();
        out.push(next_ch);
        i += next_ch.len_utf8();
    }
    (out, changed)
}

/// Convert simple Windows CMD `for %x in (a b c) do ...` (without `/f`, `/r`, `/l`, `/d`) into Bash `for x in a b c; do ...; done`,
/// optionally preserving a leading `cd [/d] <dir> &/&&` prefix.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn try_heal_cmd_for_loop(raw: &str) -> Option<String> {
    static RE: OnceLock<(Regex, Regex)> = OnceLock::new();
    let (for_re, var_re) = RE.get_or_init(|| {
        (
            Regex::new(
                r#"(?is)^\s*(?:(cd(?:\s+/d)?\s+(?:"[^"]+"|'[^']+'|\S+))\s*(?:&&|&)\s*)?for\s+%%?([A-Za-z_]\w*)\s+in\s+\(([^)\r\n]+)\)\s+do\s+(.+?)\s*$"#,
            )
            .unwrap(),
            Regex::new(r"%%?([A-Za-z_]\w*)").unwrap(),
        )
    });
    let trimmed = raw.trim();
    if Regex::new(r"(?i)\bfor\s+/[frld]\b")
        .unwrap()
        .is_match(trimmed)
    {
        return None;
    }
    let caps = for_re.captures(trimmed)?;
    let var = caps.get(2)?.as_str();
    let items = caps.get(3)?.as_str().trim();
    if items.is_empty() {
        return None;
    }
    let mut body = caps.get(4)?.as_str().trim().to_string();
    if let Some(stripped) = body.strip_prefix('@') {
        body = stripped.trim().to_string();
    }
    if body.starts_with('(') && body.ends_with(')') && body.len() >= 2 {
        body = body[1..body.len() - 1].trim().to_string();
    }
    body = var_re
        .replace_all(&body, |c: &regex::Captures| {
            if &c[1] == var {
                format!("${{{var}}}")
            } else {
                c[0].to_string()
            }
        })
        .into_owned();
    // Convert standalone CMD `&` separator between subcommands (avoiding `&&` or `>&`) to `; `
    let mut bash_body = String::with_capacity(body.len());
    let b = body.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'&'
            && b.get(i.wrapping_sub(1)) != Some(&b'&')
            && b.get(i + 1) != Some(&b'&')
            && b.get(i.wrapping_sub(1)) != Some(&b'>')
            && b.get(i + 1) != Some(&b'>')
        {
            bash_body.push_str("; ");
            i += 1;
            while i < b.len() && b[i] == b' ' {
                i += 1;
            }
        } else {
            let ch = body[i..].chars().next().unwrap();
            bash_body.push(ch);
            i += ch.len_utf8();
        }
    }
    let cd_part = caps
        .get(1)
        .map(|m| {
            let cleaned = Regex::new(r"(?i)^cd\s+/d\s+")
                .unwrap()
                .replace(m.as_str().trim(), "cd ");
            format!("{cleaned} && ")
        })
        .unwrap_or_default()
        .replace('\\', "/");
    Some(format!(
        "{cd_part}for {var} in {items}; do {}; done",
        bash_body.trim()
    ))
}

fn route_accelerated_cmd(
    rewritten: String,
    has_pwsh7: bool,
    has_git_bash: bool,
) -> (ShellKind, String) {
    if let (Some(cd_p), tail) = split_leading_cd_prefix(&rewritten) {
        if has_git_bash {
            return (ShellKind::GitBash, rewritten);
        }
        let ps_body = format!("& {tail}");
        if has_pwsh7 {
            return (ShellKind::Pwsh7, format!("{cd_p}{ps_body}"));
        }
        let cd_clean = cd_p
            .trim_end()
            .trim_end_matches("&&")
            .trim_end_matches(';')
            .trim_end();
        return (
            ShellKind::PowerShell5,
            format!("{cd_clean}; if ($?) {{ {ps_body} }}"),
        );
    }
    (
        if has_pwsh7 {
            ShellKind::Pwsh7
        } else {
            ShellKind::PowerShell5
        },
        format!("& {rewritten}"),
    )
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn heal_windows_command(
    raw: &str,
    has_pwsh7: bool,
    has_git_bash: bool,
) -> (ShellKind, String, Vec<&'static str>) {
    let re = heal_re();
    let mut heals: Vec<&'static str> = Vec::new();
    if let Some(fast_search) = try_accelerate_slow_grep(raw) {
        heals.push("slow-grep->ap-search");
        let (kind, cmd_out) = route_accelerated_cmd(fast_search, has_pwsh7, has_git_bash);
        return (kind, cmd_out, heals);
    }
    if let Some(fast_ls) = try_heal_windows_dir_cmd(raw) {
        heals.push("dir-/b->ap-ls");
        let (kind, cmd_out) = route_accelerated_cmd(fast_ls, has_pwsh7, has_git_bash);
        return (kind, cmd_out, heals);
    }
    if let Some(fast_sls) = try_accelerate_select_string(raw) {
        heals.push("select-string->ap-search");
        let (kind, cmd_out) = route_accelerated_cmd(fast_sls, has_pwsh7, has_git_bash);
        return (kind, cmd_out, heals);
    }
    if let Some(fast_gc) = try_accelerate_get_content(raw) {
        heals.push("get-content->ap-read");
        let (kind, cmd_out) = route_accelerated_cmd(fast_gc, has_pwsh7, has_git_bash);
        return (kind, cmd_out, heals);
    }
    if let Some(fast_gci) = try_accelerate_get_child_item(raw) {
        heals.push("get-childitem->ap-ls");
        let (kind, cmd_out) = route_accelerated_cmd(fast_gci, has_pwsh7, has_git_bash);
        return (kind, cmd_out, heals);
    }
    if let Some(fast_sed) = try_accelerate_sed_slice(raw) {
        heals.push("sed-slice->ap-read");
        let (kind, cmd_out) = route_accelerated_cmd(fast_sed, has_pwsh7, has_git_bash);
        return (kind, cmd_out, heals);
    }
    if let Some(fast_head) = try_accelerate_head_slice(raw) {
        heals.push("head-slice->ap-read");
        let (kind, cmd_out) = route_accelerated_cmd(fast_head, has_pwsh7, has_git_bash);
        return (kind, cmd_out, heals);
    }
    if let Some(fast_tail) = try_accelerate_tail_slice(raw) {
        heals.push("tail-slice->ap-read");
        let (kind, cmd_out) = route_accelerated_cmd(fast_tail, has_pwsh7, has_git_bash);
        return (kind, cmd_out, heals);
    }
    if let Some(fast_cat) = try_accelerate_cat_slice(raw) {
        heals.push("cat-slice->ap-read");
        let (kind, cmd_out) = route_accelerated_cmd(fast_cat, has_pwsh7, has_git_bash);
        return (kind, cmd_out, heals);
    }
    if let Some(fast_find) = try_accelerate_find_files(raw) {
        heals.push("find->ap-ls");
        let (kind, cmd_out) = route_accelerated_cmd(fast_find, has_pwsh7, has_git_bash);
        return (kind, cmd_out, heals);
    }
    if has_git_bash {
        if let Some(healed_for) = try_heal_cmd_for_loop(raw) {
            heals.push("cmd-for->bash-for");
            return (ShellKind::GitBash, healed_for, heals);
        }
    }
    let has_ps_cmdlet = re.ps_cmdlet.is_match(raw);
    if has_git_bash && !has_ps_cmdlet && re.posix_only.is_match(raw) {
        heals.push("posix->git-bash");
        let mut bash_cmd = raw.to_string();
        if let Some(clamped) = try_cap_long_sleep(&bash_cmd, 45) {
            heals.push("sleep-clamp->45s");
            bash_cmd = clamped;
        }
        if let Some(shielded) = try_shield_msys_pathconv(&bash_cmd) {
            heals.push("msys-no-pathconv");
            bash_cmd = shielded;
        }
        return (ShellKind::GitBash, bash_cmd, heals);
    }

    let mut out = raw.to_string();
    if has_ps_cmdlet {
        heals.push("ps-cmdlet->pwsh");
    }
    if let Some(clamped) = try_cap_long_sleep(&out, 45) {
        out = clamped;
        heals.push("sleep-clamp->45s");
    }
    if re.py_win_backslash.is_match(&out) || out.contains("python") || out.contains("py ") {
        let (fixed, did_fix) = heal_py_win_backslashes(&out);
        if did_fix {
            out = fixed;
            heals.push("py-win-backslash->slash");
        }
    }
    if re.curl_cmd.is_match(&out) {
        out = re
            .curl_cmd
            .replace_all(&out, "${1}curl.exe${2}")
            .to_string();
        heals.push("curl->curl.exe");
    }
    if re.dev_null.is_match(&out) {
        out = re.dev_null.replace_all(&out, "${1}$$null").to_string();
        heals.push("/dev/null->$null");
    }
    if re.bare_amp_url.is_match(&out) {
        out = re.bare_amp_url.replace_all(&out, "${1}'${2}'").to_string();
        heals.push("quote-url-&");
    }

    if has_pwsh7 {
        return (ShellKind::Pwsh7, out, heals);
    }

    let segs = split_top_level_and_and(&out);
    if segs.len() >= 2 && segs.iter().all(|s| !s.is_empty()) {
        let mut chain = Vec::with_capacity(segs.len());
        for (idx, seg) in segs.iter().enumerate() {
            if idx + 1 < segs.len() {
                chain.push(format!(
                    "$global:LASTEXITCODE = 0; {seg}; if (-not $? -or ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0)) {{ exit $(if ($LASTEXITCODE) {{ $LASTEXITCODE }} else {{ 1 }}) }}"
                ));
            } else {
                chain.push(format!("$global:LASTEXITCODE = 0; {seg}"));
            }
        }
        out = chain.join("; ");
        heals.push("ps51-&&-chain");
    }
    (ShellKind::PowerShell5, out, heals)
}

#[cfg(windows)]
pub fn probe_git_bash() -> Option<PathBuf> {
    for cand in [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ] {
        let p = Path::new(cand);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    None
}

#[cfg(windows)]
pub fn probe_pwsh7() -> bool {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        if dir.join("pwsh.exe").is_file() {
            return true;
        }
    }
    Path::new(r"C:\Program Files\PowerShell\7\pwsh.exe").is_file()
}

fn build_augmented_path() -> (std::ffi::OsString, bool) {
    let home = default_home_dir();
    let cur_os = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs: Vec<PathBuf> = std::env::split_paths(&cur_os).collect();
    let mut changed = false;

    let mut front_cands = vec![
        home.join(".cargo").join("bin"),
        home.join(".local").join("bin"),
    ];
    #[cfg(windows)]
    {
        if let Ok(app) = std::env::var("APPDATA") {
            front_cands.push(PathBuf::from(app).join("npm"));
        }
        if let Ok(lapp) = std::env::var("LOCALAPPDATA") {
            front_cands.push(PathBuf::from(lapp).join("pnpm"));
        }
    }
    #[cfg(not(windows))]
    {
        front_cands.push(PathBuf::from("/opt/homebrew/bin"));
        front_cands.push(PathBuf::from("/usr/local/bin"));
    }

    for cand in front_cands.into_iter().rev() {
        if cand.is_dir() && !dirs.iter().any(|d| d == &cand) {
            dirs.insert(0, cand);
            changed = true;
        }
    }

    #[cfg(windows)]
    {
        let git_usr = PathBuf::from(r"C:\Program Files\Git\usr\bin");
        if git_usr.is_dir() && !dirs.iter().any(|d| d == &git_usr) {
            dirs.push(git_usr);
            changed = true;
        }
    }

    let joined = std::env::join_paths(dirs).unwrap_or(cur_os);
    (joined, changed)
}

fn kill_tree(child: &mut std::process::Child) {
    let pid = child.id();
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("pkill")
            .args(["-KILL", "-P", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub fn find_port_pids(port: u16) -> Vec<u32> {
    let mut pids = Vec::new();
    let self_pid = std::process::id();
    #[cfg(windows)]
    {
        if let Ok(out) = Command::new("netstat").args(["-ano", "-p", "tcp"]).output() {
            let needle = format!(":{port}");
            for ln in String::from_utf8_lossy(&out.stdout).lines() {
                let cols: Vec<&str> = ln.split_whitespace().collect();
                if cols.len() >= 5 && cols[1].ends_with(&needle) && cols[3] == "LISTENING" {
                    if let Ok(pid) = cols[4].parse::<u32>() {
                        if pid > 4 && pid != self_pid && !pids.contains(&pid) {
                            pids.push(pid);
                        }
                    }
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(out) = Command::new("lsof")
            .args(["-ti", &format!("tcp:{port}")])
            .output()
        {
            for ln in String::from_utf8_lossy(&out.stdout).lines() {
                if let Ok(pid) = ln.trim().parse::<u32>() {
                    if pid > 1 && pid != self_pid && !pids.contains(&pid) {
                        pids.push(pid);
                    }
                }
            }
        }
    }
    pids
}

pub fn free_local_port(port: u16) -> Vec<u32> {
    let pids = find_port_pids(port);
    for &pid in &pids {
        #[cfg(windows)]
        {
            let _ = Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        #[cfg(not(windows))]
        {
            let _ = Command::new("kill")
                .args(["-9", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
    pids
}

fn build_shell_command(raw_cmd: &str) -> (Command, Vec<&'static str>) {
    #[cfg(windows)]
    {
        let git_bash = probe_git_bash();
        let has_pwsh7 = probe_pwsh7();
        let (kind, healed, mut heals) =
            heal_windows_command(raw_cmd, has_pwsh7, git_bash.is_some());
        heals.push("utf8-env");
        match kind {
            ShellKind::GitBash => {
                let mut c = Command::new(git_bash.unwrap());
                c.args(["--noprofile", "--norc", "-c", &healed]);
                (c, heals)
            }
            ShellKind::Pwsh7 => {
                let prologue = "[Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.UTF8Encoding]::new($false); $PSDefaultParameterValues['*:Encoding'] = 'utf8'; ";
                let mut c = Command::new("pwsh.exe");
                c.args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!("{prologue}{healed}"),
                ]);
                (c, heals)
            }
            ShellKind::PowerShell5 => {
                let prologue = "[Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.UTF8Encoding]::new($false); $PSDefaultParameterValues['*:Encoding'] = 'utf8'; ";
                let mut c = Command::new("powershell.exe");
                c.args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!("{prologue}{healed}"),
                ]);
                (c, heals)
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(fast_search) = try_accelerate_slow_grep(raw_cmd) {
            let mut c = Command::new("sh");
            c.args(["-c", &fast_search]);
            return (c, vec!["slow-grep->ap-search"]);
        }
        let mut c = Command::new("sh");
        c.args(["-c", raw_cmd]);
        (c, Vec::new())
    }
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match ExecCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };

    let mut win_heals = 0u32;
    let mut freed_pids = Vec::new();
    if let Some(port) = cli.free_port {
        freed_pids = free_local_port(port);
        if !freed_pids.is_empty() {
            win_heals += 1;
        }
    }

    let shell_str: Option<String> = if let Some(b64) = &cli.base64 {
        match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("[ap exec] invalid UTF-8 in --base64 payload: {e}");
                    return 2;
                }
            },
            Err(e) => {
                eprintln!("[ap exec] invalid --base64 payload: {e}");
                return 2;
            }
        }
    } else {
        cli.cmd.clone()
    };

    let clean_argv: Vec<String> = if cli.argv.first().map(|s| s.as_str()) == Some("--") {
        cli.argv[1..].to_vec()
    } else {
        cli.argv.clone()
    };

    if shell_str.is_none() && clean_argv.is_empty() {
        if let Some(port) = cli.free_port {
            record_event("exec", 0, 0, win_heals, 0, "free-port");
            if cli.json {
                println!(
                    "{}",
                    json!({"ok": true, "port": port, "freed_pids": freed_pids})
                );
            } else if freed_pids.is_empty() {
                println!("[ap exec] Port {port} is already free.");
            } else {
                println!(
                    "[ap exec] Freed port {port} (terminated PIDs: {:?}).",
                    freed_pids
                );
            }
            return 0;
        }
        eprintln!("[ap exec] provide `-c \"<cmd>\"`, `--base64 <b64>`, `--free-port <p>`, or `-- <prog> <args...>`");
        return 2;
    }

    let label = shell_str.clone().unwrap_or_else(|| clean_argv.join(" "));
    let safety_issues = ap_guard::inspect_text_safety(&label);
    if !safety_issues.is_empty() {
        for item in safety_issues {
            eprintln!("[GUARD BLOCKED | exit 2] {item}");
        }
        return 2;
    }

    let (mut child_cmd, heals) = if let Some(ref s) = shell_str {
        build_shell_command(s)
    } else {
        let mut c = Command::new(&clean_argv[0]);
        if clean_argv.len() > 1 {
            c.args(&clean_argv[1..]);
        }
        #[cfg(windows)]
        let hv = vec!["utf8-env"];
        #[cfg(not(windows))]
        let hv: Vec<&'static str> = Vec::new();
        (c, hv)
    };
    win_heals += heals.iter().filter(|&&h| h != "utf8-env").count() as u32;

    let (aug_path, path_healed) = build_augmented_path();
    if path_healed && cfg!(windows) {
        win_heals = win_heals.max(1);
    }

    child_cmd
        .current_dir(&cli.cwd)
        .env("PATH", aug_path)
        .env("PYTHONUTF8", "1")
        .env("PYTHONIOENCODING", "utf-8")
        .env("LC_ALL", "C.UTF-8")
        .env("LANG", "C.UTF-8")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("NPM_CONFIG_YES", "true")
        .env("PIP_NO_INPUT", "1")
        .env("NEXT_TELEMETRY_DISABLED", "1")
        .stdin(Stdio::null());

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid_self = std::process::id();
    let out_file_p = std::env::temp_dir().join(format!("ap_exec_out_{pid_self}_{stamp}.log"));
    let err_file_p = std::env::temp_dir().join(format!("ap_exec_err_{pid_self}_{stamp}.log"));

    let Ok(out_f) = File::create(&out_file_p) else {
        eprintln!("[ap exec] failed to allocate temp output file");
        return 1;
    };
    let Ok(err_f) = File::create(&err_file_p) else {
        let _ = fs::remove_file(&out_file_p);
        eprintln!("[ap exec] failed to allocate temp error file");
        return 1;
    };
    child_cmd
        .stdout(Stdio::from(out_f))
        .stderr(Stdio::from(err_f));

    let t0 = Instant::now();
    let mut child = match child_cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = fs::remove_file(&out_file_p);
            let _ = fs::remove_file(&err_file_p);
            eprintln!("[ap exec] failed to spawn `{label}`: {e}");
            return 127;
        }
    };
    let mut job_guard = crate::win_job::WinJobGuard::attach(&child);

    let deadline = Duration::from_secs(cli.timeout.max(1));
    let mut timed_out = false;
    let exit_code = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.code().unwrap_or(1),
            Ok(None) => {
                if t0.elapsed() >= deadline {
                    timed_out = true;
                    drop(job_guard.take());
                    kill_tree(&mut child);
                    win_heals += 1;
                    break 124;
                }
                thread::sleep(Duration::from_millis(15));
            }
            Err(_) => {
                drop(job_guard.take());
                kill_tree(&mut child);
                break 1;
            }
        }
    };
    drop(job_guard);
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;

    let out_bytes_raw = fs::read(&out_file_p).unwrap_or_default();
    let err_bytes_raw = fs::read(&err_file_p).unwrap_or_default();
    let _ = fs::remove_file(&out_file_p);
    let _ = fs::remove_file(&err_file_p);

    fn strip_bom(b: &[u8]) -> &[u8] {
        b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b)
    }
    let mut combined = String::from_utf8_lossy(strip_bom(&out_bytes_raw)).to_string();
    let err_str = String::from_utf8_lossy(strip_bom(&err_bytes_raw));
    if !err_str.is_empty() {
        if !combined.is_empty() && !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(&err_str);
    }
    let mut exit_code = exit_code;
    let mut heals = heals;
    if exit_code == 2 && !timed_out && shell_str.is_some() && combined.contains("regex parse error")
    {
        if let Some(retry_raw) = try_build_rg_fixed_retry(&label) {
            let (mut rcmd, _) = build_shell_command(&retry_raw);
            let (aug2, _) = build_augmented_path();
            rcmd.current_dir(&cli.cwd)
                .env("PATH", aug2)
                .env("PYTHONUTF8", "1")
                .env("PYTHONIOENCODING", "utf-8")
                .env("LC_ALL", "C.UTF-8")
                .env("LANG", "C.UTF-8")
                .stdin(Stdio::null());
            if let Ok(rout) = rcmd.output() {
                let r_code = rout.status.code().unwrap_or(1);
                let mut r_comb = String::from_utf8_lossy(strip_bom(&rout.stdout)).to_string();
                let r_err = String::from_utf8_lossy(strip_bom(&rout.stderr));
                if !r_err.is_empty() {
                    if !r_comb.is_empty() && !r_comb.ends_with('\n') {
                        r_comb.push('\n');
                    }
                    r_comb.push_str(&r_err);
                }
                exit_code = r_code;
                combined = format!(
                    "[ap exec auto-healed: rg regex parse error -> retried with -F fixed-strings]\n{r_comb}"
                );
                heals.push("rg-regex->-F");
                win_heals += 1;
            }
        }
    }
    if timed_out {
        combined.push_str(&format!(
            "\n[ap exec] TIMEOUT after {}s — killed orphaned process tree cleanly.\n",
            cli.timeout
        ));
    }

    if exit_code != 0 {
        if let Some(cap) = heal_re().port_in_use.captures(&combined) {
            if let Some(p_str) = cap.get(1).or_else(|| cap.get(2)).map(|m| m.as_str()) {
                if let Ok(port_num) = p_str.parse::<u16>() {
                    let owners = find_port_pids(port_num);
                    combined.push_str(&format!(
                        "\n[ap exec port-lock] Port {port_num} is held by PID(s) {owners:?}. Free it cleanly via: ap exec --free-port {port_num}\n"
                    ));
                }
            }
        }
    }

    let (mut combined, mut win_heals_scrub) = (combined, false);
    if cli.scrub {
        let rep = ap_guard::sanitize::scrub_untrusted_text(&combined);
        let total_flagged = rep.secrets_redacted + rep.injections_flagged;
        if total_flagged > 0 {
            win_heals_scrub = true;
            combined = format!(
                "[ap guard scrub] redacted {} secret(s), defanged {} prompt-injection signal(s)\n{}",
                rep.secrets_redacted, rep.injections_flagged, rep.sanitized
            );
        } else {
            combined = rep.sanitized;
        }
    }
    if win_heals_scrub {
        heals.push("scrub");
        win_heals += 1;
    }

    let raw_len = combined.len() as u64;
    let final_text = if !cli.raw && combined.len() > 1800 {
        let sieve_store = std::env::var("SIEVE_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| cli.cwd.join(".sieve"));
        let sr =
            ap_sieve::compress_stream_in(&sieve_store, &combined, &label, exit_code, elapsed_ms);
        sr.rendered
    } else {
        combined
    };

    let out_len = final_text.len() as u64;
    let note = if heals.is_empty() {
        "exec".to_string()
    } else {
        heals.join("+")
    };
    record_event("exec", raw_len, out_len, win_heals, 0, &note);

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": exit_code == 0,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "elapsed_ms": elapsed_ms,
                "heals": heals,
                "raw_bytes": raw_len,
                "emitted_bytes": out_len,
                "output": final_text,
            }))
            .unwrap_or_default()
        );
    } else if !final_text.is_empty() {
        print!("{final_text}");
        if !final_text.ends_with('\n') {
            println!();
        }
    }
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_command_heals_ps51_curl_url_and_posix_routing() {
        let (k1, h1, tags1) = heal_windows_command(
            "curl -s https://api.example.com/items?page=1&per_page=50 > /dev/null && echo ok",
            false,
            true,
        );
        assert_eq!(k1, ShellKind::PowerShell5);
        assert!(
            h1.contains("curl.exe -s 'https://api.example.com/items?page=1&per_page=50' > $null")
        );
        assert!(h1.contains("LASTEXITCODE"));
        assert!(tags1.contains(&"curl->curl.exe"));
        assert!(tags1.contains(&"/dev/null->$null"));
        assert!(tags1.contains(&"quote-url-&"));
        assert!(tags1.contains(&"ps51-&&-chain"));

        // Quoted `&&` must NOT be split
        let parts = split_top_level_and_and(r#"node -e "if (a && b) console.log(1)" && echo done"#);
        assert_eq!(parts.len(), 2);

        // POSIX heredoc / Unix pipe routes to Git Bash when available
        let (k2, _, tags2) = heal_windows_command("cat << 'EOF'\nhello\nEOF", true, true);
        assert_eq!(k2, ShellKind::GitBash);
        assert!(tags2.contains(&"posix->git-bash"));

        // Bare recursive GNU `grep -rn` auto-accelerates to `ap search`
        let (_, h3, tags3) = heal_windows_command("grep -rn 'secretToken' src", true, true);
        assert!(h3.contains("search \"secretToken\" \"src\""));
        assert!(tags3.contains(&"slow-grep->ap-search"));

        // PowerShell cmdlet mixed with Unix pipe stays on PowerShell (never fails as command-not-found in Git Bash)
        let (k4, _, tags4) = heal_windows_command("Get-Content app.log | head -n 5", true, true);
        assert_eq!(k4, ShellKind::Pwsh7);
        assert!(tags4.contains(&"ps-cmdlet->pwsh"));

        // Unescaped Windows drive backslash inside `python -c` auto-normalizes to `/`
        let (_, h5, tags5) = heal_windows_command(
            r#"python -c "print(open('C:\Users\demo\a.txt').read())""#,
            true,
            true,
        );
        assert!(h5.contains("C:/Users/demo/a.txt"));
        assert!(tags5.contains(&"py-win-backslash->slash"));

        // Raw strings (`r'C:\...'`) and already-escaped strings (`'C:\\...'`) stay untouched
        let (_, h6, tags6) = heal_windows_command(
            r#"python -c "print(r'C:\Users\demo\a.txt', 'C:\\Users\\demo\\b.txt')""#,
            true,
            true,
        );
        assert!(h6.contains(r"r'C:\Users\demo\a.txt'"));
        assert!(h6.contains(r"'C:\\Users\\demo\\b.txt'"));
        assert!(!tags6.contains(&"py-win-backslash->slash"));

        // Recursive `grep -rl` accelerates directly to `ap search --files-only`
        let (_, h7, tags7) = heal_windows_command("grep -rl 'authToken' src", true, true);
        assert!(h7.contains("search --files-only \"authToken\" \"src\""));
        assert!(tags7.contains(&"slow-grep->ap-search"));

        // `grep -rhoE` forwards `--only-matching --no-filename`, and `dir /s /b` routes to `ap ls`
        let (_, h8, tags8) = heal_windows_command("grep -rhoE 'api/[a-z]+' src", true, true);
        assert!(h8.contains("--only-matching") && h8.contains("--no-filename"));
        assert!(tags8.contains(&"slow-grep->ap-search"));

        let (_, h9, tags9) = heal_windows_command("dir /s /b src", true, true);
        assert!(h9.contains("ls \"src\" --depth 3"));
        assert!(tags9.contains(&"dir-/b->ap-ls"));

        // `try_build_rg_fixed_retry` inserts `-F` cleanly on bare `rg` commands only
        assert_eq!(
            try_build_rg_fixed_retry("rg \"foo(bar\" src").as_deref(),
            Some("rg -F \"foo(bar\" src")
        );
        assert!(try_build_rg_fixed_retry("rg -F \"foo(bar\" src").is_none());
        assert!(try_build_rg_fixed_retry("rg \"foo\" src | head -n 5").is_none());

        // `try_cap_long_sleep` clamps foreground >=60s waits while keeping short/bg/python sleeps untouched
        assert_eq!(
            try_cap_long_sleep("sleep 120 && echo ok", 45).as_deref(),
            Some("sleep 45 && echo ok")
        );
        assert_eq!(
            try_cap_long_sleep("Start-Sleep -Seconds 90", 45).as_deref(),
            Some("Start-Sleep -Seconds 45")
        );
        assert!(try_cap_long_sleep("sleep 30 && echo ok", 45).is_none());
        assert!(try_cap_long_sleep("nohup sleep 120 &", 45).is_none());
        assert!(try_cap_long_sleep("python -c \"import time; time.sleep(120)\"", 45).is_none());

        let (_, h10, tags10) =
            heal_windows_command("export FOO=1; sleep 90 && echo ok", true, true);
        assert!(h10.contains("sleep 45") && tags10.contains(&"sleep-clamp->45s"));

        assert_eq!(
            try_cap_long_sleep("for i in $(seq 1 18); do sleep 30; done", 45).as_deref(),
            Some("for i in $(seq 1 18); do sleep 2; done")
        );

        // `try_shield_msys_pathconv` shields Windows CLI `/flag` & `openssl -subj '/...'` against Git Bash MSYS2 path mangling
        assert_eq!(
            try_shield_msys_pathconv("taskkill /F /PID 1234").as_deref(),
            Some("MSYS_NO_PATHCONV=1 taskkill /F /PID 1234")
        );
        assert_eq!(
            try_shield_msys_pathconv("openssl req -new -subj '/CN=127.0.0.1'").as_deref(),
            Some("MSYS_NO_PATHCONV=1 openssl req -new -subj '/CN=127.0.0.1'")
        );
        assert_eq!(
            try_shield_msys_pathconv("cd /d/work && icacls /d/work/secret.txt /grant Users:R")
                .as_deref(),
            Some(
                "export MSYS_NO_PATHCONV=1; cd D:/work && icacls D:/work/secret.txt /grant Users:R"
            )
        );
        assert!(try_shield_msys_pathconv("taskkill //F //PID 1234").is_none());
        assert!(try_shield_msys_pathconv("MSYS_NO_PATHCONV=1 taskkill /F /PID 1234").is_none());
        assert!(try_shield_msys_pathconv("rg foo src/").is_none());

        let (_, h11, tags11) =
            heal_windows_command("tasklist /FI \"STATUS eq RUNNING\" | head -n 5", true, true);
        assert!(
            h11.starts_with("export MSYS_NO_PATHCONV=1;") && tags11.contains(&"msys-no-pathconv")
        );

        // `try_heal_cmd_for_loop` translates Windows CMD `for %p in (...) do ...` into POSIX Bash loops
        assert_eq!(
            try_heal_cmd_for_loop(
                r#"cd /d D:\work\demo & for %p in (9451 9223) do @(echo === %p ===& curl -s -m 3 http://127.0.0.1:%p/json)"#
            )
            .as_deref(),
            Some("cd D:/work/demo && for p in 9451 9223; do echo === ${p} ===; curl -s -m 3 http://127.0.0.1:${p}/json; done")
        );
        assert!(
            try_heal_cmd_for_loop(r#"for /f "tokens=*" %a in (list.txt) do echo %a"#).is_none()
        );

        // `heal_py_win_backslashes` heals both drive-letter & relative Windows backslash literals (`\Network\`, `\Users\`)
        let (_, h12, tags12) = heal_windows_command(
            r#"python -c "p = 'Default\Network\Cookies'; q = r'Default\Raw\Stay'""#,
            true,
            false,
        );
        assert!(
            h12.contains("Default/Network/Cookies")
                && h12.contains(r#"r'Default\Raw\Stay'"#)
                && tags12.contains(&"py-win-backslash->slash"),
            "unexpected py heal: {h12}"
        );

        // Leading `cd <dir> &&` prefix still triggers `slow-grep`, `dir /b`, and `rg -F` retry acceleration cleanly without emitting `& cd`
        let (k13, h13, tags13) =
            heal_windows_command("cd /c/work/demo && grep -rn 'secretToken' src", true, true);
        assert_eq!(k13, ShellKind::GitBash);
        assert!(
            h13.starts_with("cd /c/work/demo && ")
                && h13.contains("search \"secretToken\" \"src\""),
            "{h13}"
        );
        assert!(tags13.contains(&"slow-grep->ap-search"));

        let (k14, h14, tags14) =
            heal_windows_command("cd /c/work/demo && dir /s /b src", true, true);
        assert_eq!(k14, ShellKind::GitBash);
        assert!(
            h14.starts_with("cd /c/work/demo && ") && h14.contains("ls \"src\" --depth 3"),
            "{h14}"
        );
        assert!(tags14.contains(&"dir-/b->ap-ls"));

        let (k14b, h14b, _) =
            heal_windows_command("cd D:/work && grep -rn 'tok' src", false, false);
        assert_eq!(k14b, ShellKind::PowerShell5);
        assert!(h14b.contains("cd D:/work; if ($?) { & "), "{h14b}");

        assert_eq!(
            try_build_rg_fixed_retry("cd /c/work && rg \"foo(bar\" src").as_deref(),
            Some("cd /c/work && rg -F \"foo(bar\" src")
        );

        // `try_accelerate_select_string` accelerates bare PowerShell `Select-String` / `sls` safely
        let (k15, h15, tags15) =
            heal_windows_command("Select-String -Pattern authToken -Path src", true, true);
        assert!(
            h15.contains("search --ignore-case \"authToken\" \"src\""),
            "{h15}"
        );
        assert!(tags15.contains(&"select-string->ap-search"));
        let _ = k15;

        let (_, h16, tags16) = heal_windows_command(
            "cd sub && Select-String -SimpleMatch -CaseSensitive -Pattern \"a+b\" -Path app.py",
            false,
            false,
        );
        assert!(
            h16.contains("cd sub; if ($?) { & ")
                && h16.contains("search --fixed-strings \"a+b\" \"app.py\""),
            "{h16}"
        );
        assert!(tags16.contains(&"select-string->ap-search"));
        assert!(try_accelerate_select_string(
            "Select-String -Pattern foo -Path app.py | Select-Object Line"
        )
        .is_none());

        // `Get-Content` / `gc` and `Get-ChildItem` / `gci` PowerShell accelerators (safe passthrough when piped/tail/filtered)
        let (_, h17, tags17) =
            heal_windows_command("Get-Content src/app.py -TotalCount 40", true, true);
        assert!(h17.contains("read \"src/app.py\" --lines 1-40"), "{h17}");
        assert!(tags17.contains(&"get-content->ap-read"));

        let (k18, h18, tags18) = heal_windows_command("cd sub && gc -Raw README.md", true, true);
        assert_eq!(k18, ShellKind::GitBash);
        assert!(
            h18.starts_with("cd sub && ") && h18.contains("read \"README.md\""),
            "{h18}"
        );
        assert!(tags18.contains(&"get-content->ap-read"));

        let (_, h19, tags19) =
            heal_windows_command("Get-ChildItem src -Recurse -Depth 2", true, true);
        assert!(h19.contains("ls \"src\" --depth 2"), "{h19}");
        assert!(tags19.contains(&"get-childitem->ap-ls"));

        assert!(try_accelerate_get_content("Get-Content -Tail 20 app.log").is_none());
        assert!(try_accelerate_get_child_item("Get-ChildItem -Filter *.rs src").is_none());

        // `try_accelerate_sed_slice` accelerates bare `sed -n '<A>,<B>p' <file>` cleanly
        let (_, h20, tags20) = heal_windows_command("sed -n '10,40p' src/app.py", true, true);
        assert!(h20.contains("read \"src/app.py\" --lines 10-40"), "{h20}");
        assert!(tags20.contains(&"sed-slice->ap-read"));

        let (k21, h21, tags21) =
            heal_windows_command("cd sub && sed -n \"1,25p\" README.md", true, true);
        assert_eq!(k21, ShellKind::GitBash);
        assert!(
            h21.starts_with("cd sub && ") && h21.contains("read \"README.md\" --lines 1-25"),
            "{h21}"
        );
        assert!(tags21.contains(&"sed-slice->ap-read"));
        assert!(try_accelerate_sed_slice("sed -n '1,10p' app.py | grep foo").is_none());

        // `try_accelerate_head_slice` accelerates bare `head -n <N>` / `head -<N>` cleanly
        let (_, h22, tags22) = heal_windows_command("head -n 30 src/main.rs", true, true);
        assert!(h22.contains("read \"src/main.rs\" --lines 1-30"), "{h22}");
        assert!(tags22.contains(&"head-slice->ap-read"));

        let (k23, h23, tags23) = heal_windows_command("cd sub && head -20 README.md", true, true);
        assert_eq!(k23, ShellKind::GitBash);
        assert!(
            h23.starts_with("cd sub && ") && h23.contains("read \"README.md\" --lines 1-20"),
            "{h23}"
        );
        assert!(tags23.contains(&"head-slice->ap-read"));
        assert!(try_accelerate_head_slice("rg foo | head -n 5").is_none());

        // `try_accelerate_tail_slice` accelerates bare `tail -n <N>` / `tail -<N>` while passing through `-f` / `+N` / pipes
        let (_, h24, tags24) = heal_windows_command("tail -n 20 app.log", true, true);
        assert!(h24.contains("read \"app.log\" --tail 20"), "{h24}");
        assert!(tags24.contains(&"tail-slice->ap-read"));

        let (k25, h25, tags25) =
            heal_windows_command("cd sub && tail -50 \"src/a b.rs\"", true, true);
        assert_eq!(k25, ShellKind::GitBash);
        assert!(
            h25.starts_with("cd sub && ") && h25.contains("read \"src/a b.rs\" --tail 50"),
            "{h25}"
        );
        assert!(tags25.contains(&"tail-slice->ap-read"));
        assert!(try_accelerate_tail_slice("tail -f app.log").is_none());
        assert!(try_accelerate_tail_slice("tail -n +5 app.log").is_none());
        assert!(try_accelerate_tail_slice("cat app.log | tail -n 10").is_none());

        // `try_heal_windows_dir_cmd` handles `/a-d`, `/o:n`, quoted paths & `/s /b` while rejecting globs & pipes
        let (_, h26, tags26) = heal_windows_command("dir /a-d /b src", true, true);
        assert!(h26.contains("ls \"src\""), "{h26}");
        assert!(tags26.contains(&"dir-/b->ap-ls"));

        let (_, h27, tags27) = heal_windows_command("dir /s /b /a:-d \"my dir\"", true, true);
        assert!(h27.contains("ls \"my dir\" --depth 3"), "{h27}");
        assert!(tags27.contains(&"dir-/b->ap-ls"));

        let (k28, h28, tags28) = heal_windows_command("cd sub && dir /b /o:n .", true, true);
        assert_eq!(k28, ShellKind::GitBash);
        assert!(
            h28.starts_with("cd sub && ") && h28.contains("ls \".\""),
            "{h28}"
        );
        assert!(tags28.contains(&"dir-/b->ap-ls"));

        assert!(try_heal_windows_dir_cmd("dir /b *.rs").is_none());
        assert!(try_heal_windows_dir_cmd("dir /b | head").is_none());

        // Piped recursive `grep -rn ... | head -n N` and `cat <file> | head/tail/sed` accelerators
        let (_, h29, tags29) =
            heal_windows_command("grep -rn 'secretToken' src | head -n 30", true, true);
        assert!(
            h29.contains("search --max 30 \"secretToken\" \"src\""),
            "{h29}"
        );
        assert!(tags29.contains(&"slow-grep->ap-search"));

        let (k30, h30, tags30) = heal_windows_command(
            "cd /c/work && grep -rl \"foo\" . 2>/dev/null | head -15",
            true,
            true,
        );
        assert_eq!(k30, ShellKind::GitBash);
        assert!(
            h30.starts_with("cd /c/work && ")
                && h30.contains("search --files-only --max 15 \"foo\" \".\""),
            "{h30}"
        );
        assert!(tags30.contains(&"slow-grep->ap-search"));

        let (_, h31, tags31) = heal_windows_command("cat src/app.rs | head -n 40", true, true);
        assert!(h31.contains("read \"src/app.rs\" --lines 1-40"), "{h31}");
        assert!(tags31.contains(&"cat-slice->ap-read"));

        let (k32, h32, tags32) =
            heal_windows_command("cd sub && cat app.log | tail -25", true, true);
        assert_eq!(k32, ShellKind::GitBash);
        assert!(
            h32.starts_with("cd sub && ") && h32.contains("read \"app.log\" --tail 25"),
            "{h32}"
        );
        assert!(tags32.contains(&"cat-slice->ap-read"));

        let (_, h33, tags33) = heal_windows_command("cat README.md | sed -n '10,30p'", true, true);
        assert!(h33.contains("read \"README.md\" --lines 10-30"), "{h33}");
        assert!(tags33.contains(&"cat-slice->ap-read"));

        assert!(try_accelerate_cat_slice("cat *.js | head -n 10").is_none());
        assert!(try_accelerate_cat_slice("cat a.txt b.txt | head -n 10").is_none());
        assert!(try_accelerate_slow_grep("grep -rn foo . | sort").is_none());

        // Bounded `find` -> `ap ls` accelerator
        let (_, h34, tags34) = heal_windows_command(
            "find src -maxdepth 2 -type f -name '*.rs' 2>/dev/null | head -n 25",
            true,
            true,
        );
        assert!(
            h34.contains("ls \"src\" --depth 2 --files-only --ext rs --limit 25"),
            "{h34}"
        );
        assert!(tags34.contains(&"find->ap-ls"));

        let (k35, h35, tags35) =
            heal_windows_command("cd sub && find . -type d -maxdepth 1", true, true);
        assert_eq!(k35, ShellKind::GitBash);
        assert!(
            h35.starts_with("cd sub && ") && h35.contains("ls \".\" --depth 1 --dirs-only"),
            "{h35}"
        );
        assert!(tags35.contains(&"find->ap-ls"));

        assert!(try_accelerate_find_files("find . -name '*.rs' -exec rm {} +").is_none());
        assert!(try_accelerate_find_files("find src tests -type f").is_none());
        assert!(try_accelerate_find_files("find . -maxdepth 8 -type f").is_none());
    }
}
