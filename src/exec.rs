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
    bg_sleep_guard: Regex,
    sleep_skip_kw: Regex,
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
        bg_sleep_guard: Regex::new(r"(?i)(?:&\s*$|\(\s*[^)]*\bsleep\b[^)]*\)\s*&)").unwrap(),
        sleep_skip_kw: Regex::new(r"(?i)(?:\bnohup\b|<<|\b(?:python3?|py|node)\b)").unwrap(),
    })
}

/// Clamp long foreground synchronous sleeps (>= 60s) to `max_sec` so they do not evict LLM KV-caches,
/// while preserving short sleeps, background `&` jobs, heredocs, and `python`/`node` invocations.
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
    let after_ps = re
        .ps_long_sleep
        .replace_all(&after_bash, |caps: &regex::Captures| {
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

/// Detect bare recursive GNU `grep -rn` / `grep -rl` `<pat> [path]` (which hangs 60-180s on large Windows trees)
/// and rewrite cleanly to sub-50ms `ap search` (or `ap search --files-only` when `-l` is present).
pub fn try_accelerate_slow_grep(raw: &str) -> Option<String> {
    if raw.contains('|') || raw.contains(';') || raw.contains("&&") || raw.contains('>') {
        return None;
    }
    let cap = heal_re().slow_grep.captures(raw)?;
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
    Some(format!(
        "\"{ap_bin}\" search{args_out} \"{pat_esc}\" \"{target}\""
    ))
}

/// Rewrite MS-DOS `dir /b [path]` or `dir /s /b [path]` (which fails in Git Bash with `dir: cannot access '/b'`)
/// cleanly to bounded `ap ls` with optional depth for `/s`.
pub fn try_heal_windows_dir_cmd(raw: &str) -> Option<String> {
    if raw.contains('|') || raw.contains(';') || raw.contains("&&") || raw.contains('>') {
        return None;
    }
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !(lower == "dir /b"
        || lower.starts_with("dir /b ")
        || lower == "dir /s /b"
        || lower.starts_with("dir /s /b ")
        || lower == "dir /b /s"
        || lower.starts_with("dir /b /s "))
    {
        return None;
    }
    let toks: Vec<&str> = trimmed.split_whitespace().collect();
    let mut recursive = false;
    let mut target: Option<&str> = None;
    for tok in toks.into_iter().skip(1) {
        if tok.eq_ignore_ascii_case("/s") {
            recursive = true;
        } else if tok.starts_with('/') && tok.len() <= 4 {
            continue;
        } else {
            target = Some(tok.trim_matches('"').trim_matches('\''));
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
    let depth_flag = if recursive { " --depth 3" } else { "" };
    let tgt_arg = target.unwrap_or(".");
    Some(format!("\"{ap_bin}\" ls \"{tgt_arg}\"{depth_flag}"))
}

/// Retry bare `rg <pattern>` commands that exited 2 with `rg: regex parse error` as literal `rg -F <pattern>`.
pub fn try_build_rg_fixed_retry(raw: &str) -> Option<String> {
    if raw.contains('|') || raw.contains(';') || raw.contains("&&") || raw.contains('>') {
        return None;
    }
    let trimmed = raw.trim_start();
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
    Some(format!("{} -F{tail}", &trimmed[..prefix_len]))
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
fn heal_py_win_backslashes(cmd: &str) -> (String, bool) {
    let b = cmd.as_bytes();
    let mut out = String::with_capacity(cmd.len());
    let mut i = 0usize;
    let mut changed = false;
    while i < b.len() {
        let ch = b[i];
        if (ch == b'\'' || ch == b'"') && i + 4 <= b.len() {
            let prev_is_raw = i > 0
                && matches!(b[i - 1], b'r' | b'R')
                && (i == 1 || !(b[i - 2].is_ascii_alphanumeric() || b[i - 2] == b'_'));
            if !prev_is_raw
                && b[i + 1].is_ascii_alphabetic()
                && b[i + 2] == b':'
                && b[i + 3] == b'\\'
                && b.get(i + 4) != Some(&b'\\')
            {
                let quote = ch;
                let mut end = i + 4;
                while end < b.len() && b[end] != quote && !b[end].is_ascii_whitespace() {
                    end += 1;
                }
                let seg = &cmd[i..end];
                out.push_str(&seg.replace('\\', "/"));
                changed = true;
                i = end;
                continue;
            }
        }
        let next_ch = cmd[i..].chars().next().unwrap();
        out.push(next_ch);
        i += next_ch.len_utf8();
    }
    (out, changed)
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
        return (
            if has_pwsh7 {
                ShellKind::Pwsh7
            } else {
                ShellKind::PowerShell5
            },
            format!("& {fast_search}"),
            heals,
        );
    }
    if let Some(fast_ls) = try_heal_windows_dir_cmd(raw) {
        heals.push("dir-/b->ap-ls");
        return (
            if has_pwsh7 {
                ShellKind::Pwsh7
            } else {
                ShellKind::PowerShell5
            },
            format!("& {fast_ls}"),
            heals,
        );
    }
    let has_ps_cmdlet = re.ps_cmdlet.is_match(raw);
    if has_git_bash && !has_ps_cmdlet && re.posix_only.is_match(raw) {
        heals.push("posix->git-bash");
        if let Some(clamped) = try_cap_long_sleep(raw, 45) {
            heals.push("sleep-clamp->45s");
            return (ShellKind::GitBash, clamped, heals);
        }
        return (ShellKind::GitBash, raw.to_string(), heals);
    }

    let mut out = raw.to_string();
    if has_ps_cmdlet {
        heals.push("ps-cmdlet->pwsh");
    }
    if let Some(clamped) = try_cap_long_sleep(&out, 45) {
        out = clamped;
        heals.push("sleep-clamp->45s");
    }
    if re.py_win_backslash.is_match(&out) {
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
    }
}
