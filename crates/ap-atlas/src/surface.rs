use ignore::WalkBuilder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Instant;
use zip::ZipArchive;

pub const ALL_AXES: &[&str] = &[
    "exec_spawn",
    "net_listen_rpc",
    "ipc_pipe_proto",
    "fs_path_io",
    "deserialize_parse",
    "loader_plugin_ext",
    "auth_token_cred",
    "webview_browser",
    "service_priv_acl",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceItem {
    pub id: String,
    pub axis: String,
    pub module: String,
    pub target: String,
    pub line: usize,
    pub symbol: String,
    pub snippet: String,
    #[serde(default)]
    pub guard_hint: String,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxisSummary {
    pub axis: String,
    pub total_hits: usize,
    pub distinct_files: usize,
    pub distinct_modules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceMap {
    pub root: String,
    pub elapsed_ms: f64,
    pub scanned_files: usize,
    pub scanned_archives: usize,
    #[serde(default)]
    pub scanned_binaries: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub excluded_files: usize,
    pub axes_present: Vec<String>,
    pub axes_absent: Vec<String>,
    pub axis_summaries: Vec<AxisSummary>,
    pub items: Vec<SurfaceItem>,
}

fn is_zero(v: &usize) -> bool {
    *v == 0
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

pub struct ExcludeMatcher {
    globs: Vec<String>,
    regexes: Vec<Regex>,
}

impl ExcludeMatcher {
    pub fn compile(patterns: &[String]) -> Result<Self, String> {
        let mut globs = Vec::new();
        let mut regexes = Vec::new();
        for raw in patterns {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(re_src) = trimmed.strip_prefix("re:") {
                let re = Regex::new(re_src.trim())
                    .map_err(|e| format!("invalid --exclude regex `{trimmed}`: {e}"))?;
                regexes.push(re);
            } else {
                globs.push(trimmed.replace('\\', "/").to_ascii_lowercase());
            }
        }
        Ok(Self { globs, regexes })
    }

    pub fn is_excluded(&self, rel_path: &str) -> bool {
        self.is_excluded_with_vendor(rel_path, true, false)
    }

    pub fn is_excluded_opts(&self, rel_path: &str, apply_builtin_noise: bool) -> bool {
        self.is_excluded_with_vendor(rel_path, apply_builtin_noise, false)
    }

    pub fn is_excluded_with_vendor(
        &self,
        rel_path: &str,
        apply_builtin_noise: bool,
        include_vendor: bool,
    ) -> bool {
        let norm = rel_path.replace('\\', "/");
        let low = norm.to_ascii_lowercase();
        let fname = low.rsplit('/').next().unwrap_or(&low);
        // Built-in generic OS CRT / uninstaller / declaration / log / vendored runtime noise exclusions
        // (applied only on directory/archive sweeps, never dropping an explicit single-file target)
        if apply_builtin_noise {
            let is_builtin_non_vendor_noise = fname.ends_with(".d.ts")
                || fname.ends_with(".log")
                || fname.starts_with("api-ms-win-")
                || fname.starts_with("vcruntime")
                || fname.starts_with("ucrtbase")
                || fname.starts_with("msvcp")
                || fname.starts_with("concrt140")
                || fname.starts_with("vcomp")
                || ((fname.starts_with("uninstall") || fname.starts_with("unins"))
                    && fname.ends_with(".exe"))
                || low.contains("/node_modules/@types/")
                || low.starts_with("node_modules/@types/")
                || low.contains("!/node_modules/@types/")
                || low.contains("/site-packages/")
                || low.contains("/dist-packages/");
            let is_builtin_vendor_noise = !include_vendor
                && (low.contains("/node_modules/")
                    || low.starts_with("node_modules/")
                    || low.contains("!/node_modules/")
                    || low.contains("/_vendored/")
                    || low.starts_with("_vendored/")
                    || low.contains("!/_vendored/")
                    || low.contains("/lib/python")
                    || low.starts_with("lib/python")
                    || low.contains("!/lib/python")
                    || low.contains("/runtime/lib/")
                    || low.starts_with("runtime/lib/")
                    || low.contains("!/runtime/lib/")
                    || low.contains("/locales/")
                    || low.starts_with("locales/")
                    || low.contains("!/locales/"));
            if is_builtin_non_vendor_noise || is_builtin_vendor_noise {
                return true;
            }
        }
        for pat in &self.globs {
            if pat.contains('*') || pat.contains('?') {
                if glob_match_ci(pat, &low) || glob_match_ci(pat, fname) {
                    return true;
                }
            } else if low.contains(pat.as_str()) {
                return true;
            }
        }
        for re in &self.regexes {
            if re.is_match(&norm) {
                return true;
            }
        }
        false
    }
}

pub(crate) fn guard_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:startsWith|commonpath|path\.relative|realpath|canonical|normalize|verify|authenticate|authorize|checkPermission|hasPermission|isTrusted|isWorkspaceTrusted|allowlist|whitelist|csrf|hmac|signature|validate|sanitize|escapeHtml|isSafe|sameOrigin|checkOrigin|requireAuth|forbidden|403|401)\b",
        )
        .unwrap()
    })
}

fn classify_guard_proximity(text: &str, byte_start: usize, byte_end: usize) -> (&'static str, i32) {
    // Minified single-line bundles (>400 chars on the match line): scan +-320 byte window
    let line_start = text[..byte_start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = text[byte_end..]
        .find('\n')
        .map(|i| byte_end + i)
        .unwrap_or(text.len());
    let gre = guard_re();
    let (before, after) = if line_end.saturating_sub(line_start) > 400 {
        let mut b0 = byte_start.saturating_sub(320).max(line_start);
        while b0 < byte_start && !text.is_char_boundary(b0) {
            b0 += 1;
        }
        let mut a1 = (byte_end + 200).min(line_end);
        while a1 > byte_end && !text.is_char_boundary(a1) {
            a1 -= 1;
        }
        (&text[b0..byte_start], &text[byte_end..a1])
    } else {
        // Walk up to 12 lines before and 6 lines after
        let mut b0 = line_start;
        let mut back = 0usize;
        while b0 > 0 && back < 12 {
            if let Some(prev_nl) = text[..b0.saturating_sub(1)].rfind('\n') {
                b0 = prev_nl + 1;
                back += 1;
            } else {
                b0 = 0;
                break;
            }
        }
        let mut a1 = line_end;
        let mut fwd = 0usize;
        while a1 < text.len() && fwd < 6 {
            let next_start = (a1 + 1).min(text.len());
            if let Some(rel_nl) = text[next_start..].find('\n') {
                a1 = next_start + rel_nl;
                fwd += 1;
            } else {
                a1 = text.len();
                break;
            }
        }
        (&text[b0..byte_start], &text[byte_end..a1])
    };

    let has_before = gre.is_match(before);
    let has_after = gre.is_match(after);
    if has_before {
        ("guard_before", -10)
    } else if has_after {
        ("guard_after", 18)
    } else {
        ("none_nearby", 14)
    }
}

fn is_native_binary_ext(ext: &str) -> bool {
    matches!(
        ext,
        "exe" | "dll" | "sys" | "ocx" | "cpl" | "efi" | "so" | "ko" | "dylib" | "node"
    )
}

fn extract_binary_strings(raw: &[u8]) -> String {
    // Fast bounded ASCII + UTF-16LE printable string extractor for PE/ELF/Mach-O binaries
    let cap = raw.len().min(3 * 1024 * 1024);
    let slice = &raw[..cap];
    let mut out = String::with_capacity(64 * 1024);

    // 1. ASCII runs >= 5 chars
    let mut run = Vec::with_capacity(128);
    for &b in slice {
        if (0x20..=0x7e).contains(&b) {
            if run.len() < 240 {
                run.push(b);
            }
        } else {
            if run.len() >= 5 {
                if let Ok(s) = std::str::from_utf8(&run) {
                    out.push_str(s);
                    out.push('\n');
                }
            }
            run.clear();
            if out.len() >= 384 * 1024 {
                break;
            }
        }
    }
    if run.len() >= 5 && out.len() < 384 * 1024 {
        if let Ok(s) = std::str::from_utf8(&run) {
            out.push_str(s);
            out.push('\n');
        }
    }

    // 2. UTF-16LE printable runs >= 5 chars (critical for Windows PE binaries)
    let mut u16_run = String::with_capacity(128);
    let mut i = 0usize;
    while i + 1 < slice.len() && out.len() < 512 * 1024 {
        let lo = slice[i];
        let hi = slice[i + 1];
        if hi == 0 && (0x20..=0x7e).contains(&lo) {
            if u16_run.len() < 240 {
                u16_run.push(lo as char);
            }
            i += 2;
        } else {
            if u16_run.len() >= 5 {
                out.push_str(&u16_run);
                out.push('\n');
            }
            u16_run.clear();
            i += 2;
        }
    }
    if u16_run.len() >= 5 && out.len() < 512 * 1024 {
        out.push_str(&u16_run);
        out.push('\n');
    }
    out
}

struct AxisRule {
    axis: &'static str,
    base_score: u32,
    re: Regex,
}

fn axis_rules() -> &'static [AxisRule] {
    static RULES: OnceLock<Vec<AxisRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            AxisRule {
                axis: "exec_spawn",
                base_score: 90,
                re: Regex::new(
                    r"\b(?:child_process|execFileSync|execFile|execSync|spawnSync|spawn|CreateProcess[AW]?|ShellExecute(?:Ex)?[AW]?|WinExec|ProcessBuilder|Runtime\.getRuntime\(\)\.exec|subprocess\.(?:Popen|run|call|check_output)|os\.system|os/exec|exec\.Command|Command::new)\b",
                )
                .unwrap(),
            },
            AxisRule {
                axis: "net_listen_rpc",
                base_score: 92,
                re: Regex::new(
                    r"\b(?:createServer|ServerSocket|TcpListener::bind|net\.Listen|WebSocketServer|http\.HandleFunc|ListenAndServe|uvicorn\.run|FastAPI|JsonRpc|LanguageServer|DebugAdapter|startServer|bind\s*\(\s*\(?['\x22]?(?:0\.0\.0\.0|127\.0\.0\.1|localhost)|\.listen\s*\()",
                )
                .unwrap(),
            },
            AxisRule {
                axis: "net_listen_rpc",
                base_score: 83,
                re: Regex::new(
                    r"['\x22`](/[a-zA-Z0-9_-]{2,24}/(?:v[1-9]|api|rest|graphql|rpc|admin|console|internal|auth|oauth|upload|download|export|import|file|files|proxy|webhook)/[a-zA-Z0-9_./{}$:-]{2,80})['\x22`]|['\x22`](/(?:api|rest|v[1-9]|graphql|rpc|admin|console|internal)/[a-zA-Z0-9_./{}$:-]{3,80})['\x22`]",
                )
                .unwrap(),
            },
            AxisRule {
                axis: "ipc_pipe_proto",
                base_score: 88,
                re: Regex::new(
                    r"\b(?:ipcMain\.(?:handle|on)|contextBridge\.exposeInMainWorld|setAsDefaultProtocolClient|register(?:File|Http|Buffer|Stream|String)?Protocol|protocol\.handle|CreateNamedPipe[AW]?|ConnectNamedPipe|CallNamedPipe|DeviceIoControl|IoCreateDevice|IoCreateSymbolicLink|METHOD_NEITHER|OnRemoteRequest|ReadFileDescriptor|\\\\\.\\pipe\\|postMessage|addEventListener\s*\(\s*['\x22]message['\x22]|registerUriHandler|open-url|second-instance)\b",
                )
                .unwrap(),
            },
            AxisRule {
                axis: "fs_path_io",
                base_score: 82,
                re: Regex::new(
                    r"\b(?:Files\.newBufferedReader|Files\.readAllBytes|Files\.write|File\.delete|ZipInputStream|ZipFile|extractAllTo|extractTo|tar\.extract|shutil\.(?:unpack_archive|copy|rmtree)|writeFileSync|readFileSync|createWriteStream|createReadStream|fs\.unlink|fs\.rmSync|fs::write|fs::copy|symlinkSync|MoveFileEx[AW]?|CopyFile[AW]?|PutObject|GetObject|CreatePresigned|presign(?:ed)?Url|downloadUrl|previewUrl|response-content-type)\b",
                )
                .unwrap(),
            },
            AxisRule {
                axis: "deserialize_parse",
                base_score: 86,
                re: Regex::new(
                    r"\b(?:ObjectInputStream|readObject|yaml\.load|pickle\.loads?|marshal\.loads?|vm\.runIn(?:New|This)?Context|new\s+Function\s*\(|\beval\s*\(|DocumentBuilderFactory|SAXParserFactory|XMLDecoder|XStream|BinaryFormatter|innerHTML|outerHTML|dangerouslySetInnerHTML|insertAdjacentHTML|DOMParser|memcpy_s|memmove_s|ReadBuffer|ReadRawData|ProbeForRead|ProbeForWrite|copy_from_user|copy_to_user)\b",
                )
                .unwrap(),
            },
            AxisRule {
                axis: "loader_plugin_ext",
                base_score: 84,
                re: Regex::new(
                    r"\b(?:LoadLibrary(?:Ex)?[AW]?|dlopen|URLClassLoader|importlib\.import_module|__import__|require\.resolve|contributes|extensionPath|pluginDir|loadPlugin|executablePath|commandLineArguments|settings\.json)\b",
                )
                .unwrap(),
            },
            AxisRule {
                axis: "auth_token_cred",
                base_score: 80,
                re: Regex::new(
                    r"\b(?:rejectUnauthorized\s*:\s*false|InsecureSkipVerify|X509TrustManager|checkServerTrusted|NODE_TLS_REJECT_UNAUTHORIZED|CredRead[AW]?|CryptUnprotectData|Authorization|X-Auth-Token|cookie|sessionToken|refreshToken|accessToken|jwt\.decode)\b",
                )
                .unwrap(),
            },
            AxisRule {
                axis: "webview_browser",
                base_score: 85,
                re: Regex::new(
                    r"\b(?:BrowserWindow|webPreferences|nodeIntegration|contextIsolation|sandbox\s*:\s*false|webSecurity\s*:\s*false|allowRunningInsecureContent|setWindowOpenHandler|will-navigate|shell\.openExternal|createWebviewPanel|asWebviewUri|preload)\b",
                )
                .unwrap(),
            },
            AxisRule {
                axis: "service_priv_acl",
                base_score: 87,
                re: Regex::new(
                    r"\b(?:CreateService[AW]?|ChangeServiceConfig|StartService[AW]?|RegSetValue(?:Ex)?[AW]?|RegCreateKey(?:Ex)?[AW]?|SetNamedSecurityInfo|ConvertStringSecurityDescriptorToSecurityDescriptor|icacls|schtasks|sudo\b|setuid|chmod\s+777|runas|ShellExecute.*runas|NETWORK SERVICE|LOCAL SYSTEM)\b",
                )
                .unwrap(),
            },
        ]
    })
}

fn fnv1a_hex(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}", (h ^ (h >> 32)) as u32)
}

fn derive_module(rel: &str) -> String {
    let clean = rel.replace('\\', "/");
    let parts: Vec<&str> = clean.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return "root".to_string();
    }
    if parts.len() == 1 {
        return parts[0].to_string();
    }
    // Group e.g. extensions/foo/bar.js -> extensions/foo; resources/app.asar!/... -> app.asar/...
    if parts[0].eq_ignore_ascii_case("extensions")
        || parts[0].eq_ignore_ascii_case("plugins")
        || parts[0].eq_ignore_ascii_case("packages")
        || parts[0].eq_ignore_ascii_case("crates")
        || parts[0].eq_ignore_ascii_case("resources")
    {
        return format!("{}/{}", parts[0], parts[1]);
    }
    if let Some((arch, inner)) = clean.split_once("!/") {
        let arch_name = Path::new(arch)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(arch);
        let first_inner = inner.split('/').next().unwrap_or("");
        if first_inner.is_empty() {
            return arch_name.to_string();
        }
        return format!("{arch_name}/{first_inner}");
    }
    format!("{}/{}", parts[0], parts[1])
}

fn clip_snippet(text: &str, byte_start: usize, byte_end: usize) -> (usize, String) {
    let line_start = text[..byte_start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = text[byte_end..]
        .find('\n')
        .map(|i| byte_end + i)
        .unwrap_or(text.len());
    let line_no = text[..byte_start].bytes().filter(|&b| b == b'\n').count() + 1;
    let line = &text[line_start..line_end];
    if line.len() <= 160 {
        return (line_no, line.trim().to_string());
    }
    // Minified single-line bundle: take a clean UTF-8 boundary window around the match
    let mut win_start = byte_start.saturating_sub(48).max(line_start);
    while win_start < byte_start && !text.is_char_boundary(win_start) {
        win_start += 1;
    }
    let mut win_end = (byte_end + 80).min(line_end);
    while win_end > byte_end && !text.is_char_boundary(win_end) {
        win_end -= 1;
    }
    let slice = text[win_start..win_end].replace(['\r', '\n', '\t'], " ");
    (line_no, slice.trim().to_string())
}

fn is_scannable_text_ext(ext: &str, file_name: &str) -> bool {
    let low_name = file_name.to_ascii_lowercase();
    if matches!(
        low_name.as_str(),
        "package.json" | "manifest.json" | "plugin.xml" | "androidmanifest.xml" | "config.json"
    ) {
        return true;
    }
    matches!(
        ext,
        "js" | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "jsx"
            | "py"
            | "go"
            | "rs"
            | "c"
            | "cc"
            | "cpp"
            | "h"
            | "hpp"
            | "java"
            | "kt"
            | "cs"
            | "rb"
            | "php"
            | "sh"
            | "ps1"
            | "yaml"
            | "yml"
            | "toml"
    )
}

fn is_archive_ext(ext: &str) -> bool {
    matches!(ext, "asar" | "vsix" | "zip" | "jar")
}

struct ScanAcc {
    axis_hits: HashMap<String, usize>,
    axis_files: HashMap<String, HashSet<String>>,
    axis_modules: HashMap<String, HashSet<String>>,
    candidates: Vec<SurfaceItem>,
}

impl ScanAcc {
    fn new() -> Self {
        Self {
            axis_hits: HashMap::new(),
            axis_files: HashMap::new(),
            axis_modules: HashMap::new(),
            candidates: Vec::new(),
        }
    }
}

fn normalize_surface_target(raw: &str) -> String {
    let mut s = raw.replace('\\', "/");
    for ext in [".asar!", ".zip!", ".vsix!", ".jar!", ".whl!", ".apk!"] {
        let low = s.to_ascii_lowercase();
        if let Some(pos) = low.find(ext) {
            let bang_end = pos + ext.len();
            if s.as_bytes().get(bang_end) != Some(&b'/') {
                s.insert(bang_end, '/');
            }
            break;
        }
    }
    s
}

fn is_bare_es_import_export_line(line: &str) -> bool {
    let s = line.trim_start();
    if let Some(after) = s.strip_prefix("import") {
        let a = after.trim_start();
        // Keep dynamic `import(...)` calls; skip static ES module import statements
        return !a.starts_with('(')
            && (after.starts_with(char::is_whitespace)
                || after.starts_with('{')
                || after.starts_with('*')
                || after.starts_with('"')
                || after.starts_with('\''));
    }
    if let Some(after) = s.strip_prefix("export") {
        let a = after.trim_start();
        return (after.starts_with(char::is_whitespace)
            || after.starts_with('{')
            || after.starts_with('*'))
            && a.contains(" from ");
    }
    false
}

fn is_legal_doc_url_prose(axis: &str, text: &str) -> bool {
    if axis != "auth_token_cred" {
        return false;
    }
    let l = text.to_ascii_lowercase();
    (l.contains("http://") || l.contains("https://"))
        && (l.contains("cookie-policy")
            || l.contains("privacy-policy")
            || l.contains("/legal/")
            || l.contains("/docs/"))
}

fn scan_text_into(
    rel_target: &str,
    text: &str,
    is_binary_strings: bool,
    rules: &[AxisRule],
    acc: &mut ScanAcc,
) {
    let norm_target = normalize_surface_target(rel_target);
    let rel_target = norm_target.as_str();
    let module = derive_module(rel_target);
    let is_manifest = rel_target.ends_with("package.json")
        || rel_target.ends_with("manifest.json")
        || rel_target.ends_with("plugin.xml");
    let low_rel = rel_target.to_ascii_lowercase();
    let is_test = low_rel.contains("/test/")
        || low_rel.contains("/tests/")
        || low_rel.contains(".test.")
        || low_rel.contains(".spec.")
        || low_rel.contains("_test.");
    if is_test {
        return;
    }

    for rule in rules {
        let mut seen_symbols: HashSet<String> = HashSet::new();
        let mut file_axis_hits = 0usize;
        for m in rule.re.find_iter(text) {
            // Skip obvious comment-only, bare ES import/export, and legal/docs URL prose lines
            let (line_no, snippet) = clip_snippet(text, m.start(), m.end());
            if !is_binary_strings {
                if snippet.starts_with("//")
                    || snippet.starts_with('#')
                    || snippet.starts_with('*')
                    || is_legal_doc_url_prose(rule.axis, &snippet)
                {
                    continue;
                }
                let line_start = text[..m.start()].rfind('\n').map(|i| i + 1).unwrap_or(0);
                let line_end = text[m.end()..]
                    .find('\n')
                    .map(|i| m.end() + i)
                    .unwrap_or(text.len());
                if line_end.saturating_sub(line_start) <= 400
                    && is_bare_es_import_export_line(&text[line_start..line_end])
                {
                    continue;
                }
            }
            let sym = m
                .as_str()
                .trim()
                .trim_matches(|c| c == '\'' || c == '"' || c == '`')
                .to_string();
            *acc.axis_hits.entry(rule.axis.to_string()).or_insert(0) += 1;
            acc.axis_files
                .entry(rule.axis.to_string())
                .or_default()
                .insert(rel_target.to_string());
            acc.axis_modules
                .entry(rule.axis.to_string())
                .or_default()
                .insert(module.clone());

            file_axis_hits += 1;
            let per_rule_cap = if rule.base_score == 83 { 6 } else { 3 };
            if file_axis_hits > per_rule_cap || !seen_symbols.insert(sym.to_ascii_lowercase()) {
                continue;
            }

            let (guard_hint, guard_delta) = if is_binary_strings {
                ("binary_import_str", 6i32)
            } else {
                classify_guard_proximity(text, m.start(), m.end())
            };

            // Scale pure static surface hits cleanly into [10..=85] to avoid ceiling saturation at 100
            // while preserving full relative ranking (guard_after > none_nearby > guard_before).
            let raw_static = (rule.base_score as i32 - 20 + guard_delta).max(10) as u32;
            let mut score = raw_static;
            if rel_target.contains("!/") {
                score = score.saturating_add(2);
            }
            if is_manifest {
                score = score.saturating_sub(6);
            }
            if low_rel.contains("node_modules/") {
                score = score.saturating_sub(18);
            }
            score = score.clamp(10, 85);
            let key = format!("{}|{}|{}", rule.axis, rel_target, sym.to_ascii_lowercase());
            let id = format!("{}:{}", rule.axis, fnv1a_hex(&key));
            acc.candidates.push(SurfaceItem {
                id,
                axis: rule.axis.to_string(),
                module: module.clone(),
                target: rel_target.to_string(),
                line: if is_binary_strings { 0 } else { line_no },
                symbol: sym,
                snippet,
                guard_hint: guard_hint.to_string(),
                score,
            });
        }
    }
}

fn collect_asar_files(
    node: &Value,
    prefix: &str,
    include_vendor: bool,
    out: &mut Vec<(String, u64, u64)>,
    limit: usize,
) {
    if out.len() >= limit {
        return;
    }
    let Some(files) = node.get("files").and_then(|v| v.as_object()) else {
        return;
    };
    for (name, val) in files {
        if out.len() >= limit {
            break;
        }
        let next = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if val.get("files").is_some() {
            let name_low = name.to_ascii_lowercase();
            if !include_vendor
                && matches!(name_low.as_str(), "node_modules" | "_vendored" | "locales")
            {
                continue;
            }
            if name_low == "node_modules" && prefix.to_ascii_lowercase().contains("node_modules") {
                continue;
            }
            collect_asar_files(val, &next, include_vendor, out, limit);
        } else if let (Some(off_v), Some(size_v)) = (val.get("offset"), val.get("size")) {
            let off = off_v
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| off_v.as_u64());
            let sz = size_v.as_u64();
            if let (Some(o), Some(s)) = (off, sz) {
                if s > 0 && s <= 512_000 {
                    let ext = Path::new(&next)
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if is_scannable_text_ext(&ext, name) {
                        out.push((next, o, s));
                    }
                }
            }
        }
    }
}

fn scan_asar_archive(
    archive_path: &Path,
    rel_archive: &str,
    include_vendor: bool,
    rules: &[AxisRule],
    matcher: &ExcludeMatcher,
    excluded_files: &mut usize,
    acc: &mut ScanAcc,
) -> usize {
    let Ok(bytes) = fs::read(archive_path) else {
        return 0;
    };
    if bytes.len() < 16 {
        return 0;
    }
    let header_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let json_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    let header_end = 8usize.saturating_add(header_size);
    let json_end = 16usize.saturating_add(json_len);
    if json_end > bytes.len() || header_end > bytes.len() || json_end > header_end + 8 {
        return 0;
    }
    let Ok(header_str) = std::str::from_utf8(&bytes[16..json_end]) else {
        return 0;
    };
    let Ok(header_json) = serde_json::from_str::<Value>(header_str) else {
        return 0;
    };
    let mut entries = Vec::new();
    collect_asar_files(&header_json, "", include_vendor, &mut entries, 160);
    let mut scanned = 0usize;
    for (inner_path, off, sz) in entries {
        let start = header_end.saturating_add(off as usize);
        let end = start.saturating_add(sz as usize);
        if end > bytes.len() {
            continue;
        }
        let vpath = format!("{rel_archive}!/{inner_path}");
        if matcher.is_excluded_with_vendor(&vpath, true, include_vendor)
            || matcher.is_excluded_with_vendor(&inner_path, true, include_vendor)
        {
            *excluded_files += 1;
            continue;
        }
        let text = String::from_utf8_lossy(&bytes[start..end]);
        scan_text_into(&vpath, &text, false, rules, acc);
        scanned += 1;
    }
    scanned
}

fn scan_zip_archive(
    archive_path: &Path,
    rel_archive: &str,
    include_vendor: bool,
    rules: &[AxisRule],
    matcher: &ExcludeMatcher,
    excluded_files: &mut usize,
    acc: &mut ScanAcc,
) -> usize {
    let Ok(meta) = archive_path.metadata() else {
        return 0;
    };
    if meta.len() > 48 * 1024 * 1024 {
        return 0;
    }
    let Ok(bytes) = fs::read(archive_path) else {
        return 0;
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        return 0;
    };
    let mut scanned = 0usize;
    for i in 0..zip.len() {
        if scanned >= 120 {
            break;
        }
        let Ok(entry) = zip.by_index(i) else {
            continue;
        };
        if entry.is_dir() || entry.size() == 0 || entry.size() > 512_000 {
            continue;
        }
        let name = entry.name().to_string();
        let file_name = Path::new(&name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&name);
        let ext = Path::new(&name)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !is_scannable_text_ext(&ext, file_name) {
            continue;
        }
        let vpath = format!("{rel_archive}!/{name}");
        if matcher.is_excluded_with_vendor(&vpath, true, include_vendor)
            || matcher.is_excluded_with_vendor(&name, true, include_vendor)
        {
            *excluded_files += 1;
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size().min(512_000) as usize);
        if entry.take(512_000).read_to_end(&mut buf).is_err() {
            continue;
        }
        let text = String::from_utf8_lossy(&buf);
        scan_text_into(&vpath, &text, false, rules, acc);
        scanned += 1;
    }
    scanned
}

pub fn build_surface_map(
    root: &Path,
    max_files: usize,
    max_per_axis: usize,
    include_vendor: bool,
    include_binaries: bool,
) -> SurfaceMap {
    build_surface_map_with_excludes(
        root,
        max_files,
        max_per_axis,
        include_vendor,
        include_binaries,
        &[],
    )
}

pub fn build_surface_map_with_excludes(
    root: &Path,
    max_files: usize,
    max_per_axis: usize,
    include_vendor: bool,
    include_binaries: bool,
    excludes: &[String],
) -> SurfaceMap {
    try_build_surface_map_with_excludes(
        root,
        max_files,
        max_per_axis,
        include_vendor,
        include_binaries,
        excludes,
    )
    .unwrap_or_else(|_| {
        try_build_surface_map_with_excludes(
            root,
            max_files,
            max_per_axis,
            include_vendor,
            include_binaries,
            &[],
        )
        .expect("empty excludes always compile")
    })
}

pub fn try_build_surface_map_with_excludes(
    root: &Path,
    max_files: usize,
    max_per_axis: usize,
    include_vendor: bool,
    include_binaries: bool,
    excludes: &[String],
) -> Result<SurfaceMap, String> {
    let t0 = Instant::now();
    let rules = axis_rules();
    let matcher = ExcludeMatcher::compile(excludes)?;
    let mut acc = ScanAcc::new();
    let mut scanned_files = 0usize;
    let mut scanned_archives = 0usize;
    let mut scanned_binaries = 0usize;
    let mut excluded_files = 0usize;

    let hard_skip = [
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".venv",
        "venv",
        "target",
        ".sieve",
        ".baton",
        ".recall",
        ".guard",
        ".probe",
        ".splice",
        "coverage",
    ];

    if root.is_file() {
        let rel = root
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("target")
            .to_string();
        if matcher.is_excluded_opts(&rel, false) {
            excluded_files += 1;
        } else {
            let ext = root
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ext == "asar" {
                scanned_files += scan_asar_archive(
                    root,
                    &rel,
                    include_vendor,
                    rules,
                    &matcher,
                    &mut excluded_files,
                    &mut acc,
                );
                scanned_archives += 1;
            } else if is_archive_ext(&ext) {
                scanned_files += scan_zip_archive(
                    root,
                    &rel,
                    include_vendor,
                    rules,
                    &matcher,
                    &mut excluded_files,
                    &mut acc,
                );
                scanned_archives += 1;
            } else if is_native_binary_ext(&ext) {
                if let Ok(raw) = fs::read(root) {
                    let text = extract_binary_strings(&raw);
                    scan_text_into(&rel, &text, true, rules, &mut acc);
                    scanned_binaries += 1;
                    scanned_files += 1;
                }
            } else if let Ok(raw) = fs::read(root) {
                let cap = raw.len().min(1_048_576);
                let text = String::from_utf8_lossy(&raw[..cap]);
                scan_text_into(&rel, &text, false, rules, &mut acc);
                scanned_files += 1;
            }
        }
    } else {
        let walker = WalkBuilder::new(root)
            .hidden(false)
            .git_ignore(!include_vendor)
            .git_global(false)
            .git_exclude(false)
            .filter_entry(move |e| {
                if e.depth() == 0 {
                    return true;
                }
                let nm = e.file_name().to_string_lossy();
                if hard_skip.iter().any(|s| *s == nm) {
                    return false;
                }
                if !include_vendor
                    && matches!(
                        nm.to_ascii_lowercase().as_str(),
                        "node_modules" | "vendor" | "_vendored" | "locales"
                    )
                {
                    return false;
                }
                true
            })
            .build();

        for entry in walker.flatten() {
            if scanned_files >= max_files {
                break;
            }
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let rel = p
                .strip_prefix(root)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/");
            if matcher.is_excluded_with_vendor(&rel, true, include_vendor) {
                excluded_files += 1;
                continue;
            }
            let file_name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            if ext == "asar" && scanned_archives < 16 {
                scanned_files += scan_asar_archive(
                    p,
                    &rel,
                    include_vendor,
                    rules,
                    &matcher,
                    &mut excluded_files,
                    &mut acc,
                );
                scanned_archives += 1;
                continue;
            }
            if is_archive_ext(&ext) && scanned_archives < 24 {
                scanned_files += scan_zip_archive(
                    p,
                    &rel,
                    include_vendor,
                    rules,
                    &matcher,
                    &mut excluded_files,
                    &mut acc,
                );
                scanned_archives += 1;
                continue;
            }
            if include_binaries && is_native_binary_ext(&ext) && scanned_binaries < 40 {
                let Ok(meta) = p.metadata() else { continue };
                if meta.len() > 0 && meta.len() <= 32 * 1024 * 1024 {
                    if let Ok(raw) = fs::read(p) {
                        let text = extract_binary_strings(&raw);
                        scan_text_into(&rel, &text, true, rules, &mut acc);
                        scanned_binaries += 1;
                        scanned_files += 1;
                    }
                }
                continue;
            }
            if !is_scannable_text_ext(&ext, file_name) {
                continue;
            }
            let Ok(meta) = p.metadata() else { continue };
            if meta.len() == 0 || meta.len() > 2 * 1024 * 1024 {
                continue;
            }
            let Ok(raw) = fs::read(p) else { continue };
            let cap = raw.len().min(768_000);
            let text = String::from_utf8_lossy(&raw[..cap]);
            scan_text_into(&rel, &text, false, rules, &mut acc);
            scanned_files += 1;
        }
    }

    let ScanAcc {
        axis_hits,
        axis_files,
        axis_modules,
        candidates,
    } = acc;

    // Rank & diversify per axis (module diversity first, then score)
    let mut by_axis: BTreeMap<String, Vec<SurfaceItem>> = BTreeMap::new();
    for item in candidates {
        by_axis.entry(item.axis.clone()).or_default().push(item);
    }
    let mut final_items: Vec<SurfaceItem> = Vec::new();
    for ax in ALL_AXES {
        let Some(mut list) = by_axis.remove(*ax) else {
            continue;
        };
        list.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.target.cmp(&b.target))
                .then_with(|| a.line.cmp(&b.line))
        });
        // Deduplicate by normalized target (case-insensitive on Windows) + symbol so the highest-scored hit wins.
        let mut seen_dedup: HashSet<(String, String)> = HashSet::new();
        list.retain(|it| {
            let t_key = if cfg!(windows) {
                it.target.to_ascii_lowercase()
            } else {
                it.target.clone()
            };
            seen_dedup.insert((t_key, it.symbol.to_ascii_lowercase()))
        });
        // Pick up to max_per_axis with module round-robin so one huge file doesn't crowd out other modules
        let mut by_mod: BTreeMap<String, Vec<SurfaceItem>> = BTreeMap::new();
        for it in list {
            by_mod.entry(it.module.clone()).or_default().push(it);
        }
        let mut picked = 0usize;
        let mut round = 0usize;
        while picked < max_per_axis {
            let mut added_this_round = false;
            for vec in by_mod.values() {
                if let Some(it) = vec.get(round) {
                    final_items.push(it.clone());
                    picked += 1;
                    added_this_round = true;
                    if picked >= max_per_axis {
                        break;
                    }
                }
            }
            if !added_this_round {
                break;
            }
            round += 1;
        }
    }

    let mut axes_present = Vec::new();
    let mut axes_absent = Vec::new();
    let mut axis_summaries = Vec::new();
    for ax in ALL_AXES {
        let hits = *axis_hits.get(*ax).unwrap_or(&0);
        if hits > 0 {
            axes_present.push((*ax).to_string());
            let mut mods: Vec<String> = axis_modules
                .get(*ax)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            mods.sort();
            mods.truncate(8);
            axis_summaries.push(AxisSummary {
                axis: (*ax).to_string(),
                total_hits: hits,
                distinct_files: axis_files.get(*ax).map(|s| s.len()).unwrap_or(0),
                distinct_modules: mods,
            });
        } else {
            axes_absent.push((*ax).to_string());
        }
    }

    Ok(SurfaceMap {
        root: root.to_string_lossy().to_string(),
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
        scanned_files,
        scanned_archives,
        scanned_binaries,
        excluded_files,
        axes_present,
        axes_absent,
        axis_summaries,
        items: final_items,
    })
}

pub fn render_surface_md(map: &SurfaceMap) -> String {
    let mut out = Vec::new();
    out.push(format!(
        "# ATLAS SURFACE MAP ({} files, {} archives, {} binaries, {:.1}ms)",
        map.scanned_files, map.scanned_archives, map.scanned_binaries, map.elapsed_ms
    ));
    out.push(format!("**Root**: `{}`", map.root));
    out.push(format!(
        "**Axes Present ({}/{})**: {}",
        map.axes_present.len(),
        ALL_AXES.len(),
        if map.axes_present.is_empty() {
            "(none)".to_string()
        } else {
            map.axes_present.join(", ")
        }
    ));
    if !map.axes_absent.is_empty() {
        out.push(format!("**Axes Absent**: {}", map.axes_absent.join(", ")));
    }
    if !map.axis_summaries.is_empty() {
        out.push("\n## Axis Coverage".to_string());
        for s in &map.axis_summaries {
            out.push(format!(
                "- `{}`: {} hits across {} files (modules: {})",
                s.axis,
                s.total_hits,
                s.distinct_files,
                s.distinct_modules.join(", ")
            ));
        }
    }
    if !map.items.is_empty() {
        out.push("\n## Top Entrypoint / Sink Surfaces".to_string());
        for it in map.items.iter().take(36) {
            let guard_tag = if it.guard_hint.is_empty() {
                String::new()
            } else {
                format!(" [{}]", it.guard_hint)
            };
            out.push(format!(
                "- `{}` [{}]{} `{}:{}` (`{}`) — {}",
                it.id,
                it.axis,
                guard_tag,
                it.target,
                it.line,
                it.symbol,
                it.snippet.chars().take(100).collect::<String>()
            ));
        }
    }
    format!("{}\n", out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detects_multiple_orthogonal_axes_and_zip_archives() {
        let dir = std::env::temp_dir().join(format!("ap_surface_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/server.js"),
            "const net = require('http');\nconst s = net.createServer((req,res)=>{});\ns.listen(8080);\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/ipc.ts"),
            "ipcMain.handle('open', async (_e, p) => fs.readFileSync(p));\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/java_sock.java"),
            "ServerSocket ss = new ServerSocket(0);\nFiles.newBufferedReader(Paths.get(p));\n",
        )
        .unwrap();

        // Also write a zip archive containing a webview surface
        let zip_path = dir.join("ext.vsix");
        {
            let file = fs::File::create(&zip_path).unwrap();
            let mut zw = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zw.start_file("extension/main.js", opts).unwrap();
            zw.write_all(b"new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n")
                .unwrap();
            zw.finish().unwrap();
        }

        let map = build_surface_map(&dir, 500, 10, false, false);
        assert!(map.axes_present.contains(&"net_listen_rpc".to_string()));
        assert!(map.axes_present.contains(&"ipc_pipe_proto".to_string()));
        assert!(map.axes_present.contains(&"fs_path_io".to_string()));
        assert!(map.axes_present.contains(&"webview_browser".to_string()));
        assert_eq!(map.scanned_archives, 1);
        assert!(map
            .items
            .iter()
            .any(|it| it.target.contains("ext.vsix!/extension/main.js")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prioritizes_unguarded_sinks_and_scans_native_binaries() {
        let dir = std::env::temp_dir().join(format!("ap_surface_guard_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/safe_io.js"),
            "function readSafe(base, p) {\n  if (!p.startsWith(base)) throw new Error('403');\n  return fs.readFileSync(p);\n}\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/raw_io.js"),
            "function readRaw(p) {\n  return fs.readFileSync(p);\n}\n",
        )
        .unwrap();
        // Mock PE binary containing ASCII + UTF-16LE pipe/exec imports
        let mut bin = b"MZ\x00\x00CreateProcessW\x00\\\\.\\pipe\\demo_svc\x00".to_vec();
        for ch in "ShellExecuteW".encode_utf16() {
            bin.extend_from_slice(&ch.to_le_bytes());
        }
        bin.extend_from_slice(&[0, 0]);
        fs::write(dir.join("helper.dll"), &bin).unwrap();

        let map = build_surface_map(&dir, 100, 10, false, true);
        assert_eq!(map.scanned_binaries, 1);
        let raw_item = map
            .items
            .iter()
            .find(|i| i.target == "src/raw_io.js")
            .unwrap();
        let safe_item = map
            .items
            .iter()
            .find(|i| i.target == "src/safe_io.js")
            .unwrap();
        assert_eq!(raw_item.guard_hint, "none_nearby");
        assert_eq!(safe_item.guard_hint, "guard_before");
        assert!(raw_item.score > safe_item.score);
        assert!(map
            .items
            .iter()
            .any(|i| i.target == "helper.dll" && i.guard_hint == "binary_import_str"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scans_electron_asar_in_memory() {
        let dir = std::env::temp_dir().join(format!("ap_surface_asar_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let body = b"const { shell } = require('electron'); shell.openExternal(url);";
        let header_json = format!(
            r#"{{"files":{{"main.js":{{"size":{},"offset":"0"}}}}}}"#,
            body.len()
        );
        let json_bytes = header_json.as_bytes();
        let pad = (4 - (json_bytes.len() % 4)) % 4;
        let aligned_len = json_bytes.len() + pad;
        let header_size = aligned_len + 8;
        let mut asar = Vec::new();
        asar.extend_from_slice(&4u32.to_le_bytes());
        asar.extend_from_slice(&(header_size as u32).to_le_bytes());
        asar.extend_from_slice(&((aligned_len + 4) as u32).to_le_bytes());
        asar.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
        asar.extend_from_slice(json_bytes);
        asar.resize(asar.len() + pad, 0);
        asar.extend_from_slice(body);
        fs::write(dir.join("app.asar"), &asar).unwrap();

        let map = build_surface_map(&dir, 100, 10, false, false);
        assert_eq!(map.scanned_archives, 1);
        assert!(map.axes_present.contains(&"webview_browser".to_string()));
        assert!(map.items.iter().any(|it| it.target == "app.asar!/main.js"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn surface_excludes_patterns_exclude_file_and_crt_noise() {
        let dir = std::env::temp_dir().join(format!("ap_surface_excl_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join("scratch")).unwrap();
        fs::write(dir.join("src/app.js"), "child_process.spawnSync('ls');\n").unwrap();
        fs::write(
            dir.join("scratch/demo_probe.js"),
            "child_process.spawnSync('x');\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/types.d.ts"),
            "declare function execSync(cmd: string): void;\n",
        )
        .unwrap();
        fs::write(dir.join("vcruntime140.dll"), b"MZCreateProcessW\0").unwrap();
        let ef = dir.join("excludes.txt");
        fs::write(&ef, "# comment\nscratch/*\n*_probe.js\n").unwrap();

        let pats = load_exclude_file(&ef).unwrap();
        let map = try_build_surface_map_with_excludes(&dir, 100, 10, false, true, &pats).unwrap();
        assert!(map.excluded_files >= 3, "expected excluded files: {map:?}");
        assert!(map.items.iter().any(|i| i.target == "src/app.js"));
        assert!(!map.items.iter().any(|i| i.target.contains("scratch/")));
        assert!(!map.items.iter().any(|i| i.target.contains("types.d.ts")));
        assert!(!map.items.iter().any(|i| i.target.contains("vcruntime140")));
        // Pure static hits must stay differentiated and <= 85 (no saturation at 100)
        assert!(
            map.items.iter().all(|i| i.score <= 85),
            "static surface scores must not saturate above 85: {:?}",
            map.items
        );
        // Invalid `re:` regex must fail explicitly (not be silently ignored)
        assert!(
            try_build_surface_map_with_excludes(
                &dir,
                100,
                10,
                false,
                false,
                &["re:[unclosed".to_string()],
            )
            .is_err(),
            "invalid re: regex must return Err"
        );
        // Explicit single-file target named `.log` must NOT be dropped by built-in dir noise filter
        let single_log = dir.join("explicit_target.log");
        fs::write(&single_log, "child_process.execSync(userInput);\n").unwrap();
        let single_map =
            try_build_surface_map_with_excludes(&single_log, 100, 10, false, false, &[]).unwrap();
        assert_eq!(single_map.excluded_files, 0);
        assert_eq!(single_map.scanned_files, 1);
        assert!(!single_map.items.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cycle6_surface_filters_vendored_imports_legal_urls_and_normalizes_paths() {
        let dir = std::env::temp_dir().join(format!("ap_surface_c6_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join("_vendored/pkg")).unwrap();
        fs::create_dir_all(dir.join("runtime/lib/python3.11")).unwrap();
        fs::create_dir_all(dir.join("locales/en")).unwrap();

        // Bare ES imports/exports & legal/docs URL prose must be skipped while real calls survive
        fs::write(
            dir.join("src/entry.ts"),
            "import { execSync } from 'child_process';\n\
export { spawnSync } from 'child_process';\n\
const policyUrl = \"https://example.test/legal/cookie-policy\";\n\
const docsUrl = \"https://example.test/docs/privacy-policy?token=1\";\n\
export function runCmd(arg: string) { return execSync(arg); }\n",
        )
        .unwrap();
        // Vendored/stdlib/locales noise must be skipped by default
        fs::write(
            dir.join("_vendored/pkg/tool.js"),
            "child_process.execSync('vendored');\n",
        )
        .unwrap();
        fs::write(
            dir.join("runtime/lib/python3.11/os_wrap.py"),
            "import subprocess\nsubprocess.Popen(['sh'])\n",
        )
        .unwrap();
        fs::write(
            dir.join("locales/en/strings.json"),
            r#"{"cookie":"https://example.test/cookie-policy","authToken":"label"}"#,
        )
        .unwrap();

        // Synthetic ASAR with both node_modules/dep.js (must skip!) and app/main.js (must scan!)
        let dep_body = b"child_process.execSync('from_dep');\n";
        let main_body = b"child_process.spawnSync('from_app');\n";
        let hdr_json = format!(
            r#"{{"files":{{"node_modules":{{"files":{{"dep.js":{{"size":{},"offset":"0"}}}}}},"app":{{"files":{{"main.js":{{"size":{},"offset":"{}"}}}}}}}}}}"#,
            dep_body.len(),
            main_body.len(),
            dep_body.len()
        );
        let hdr_bytes = hdr_json.as_bytes();
        let pad = (4 - (hdr_bytes.len() % 4)) % 4;
        let pickle_inner_len = 4 + hdr_bytes.len() + pad;
        let mut asar = Vec::new();
        asar.extend_from_slice(&4u32.to_le_bytes());
        asar.extend_from_slice(&(pickle_inner_len as u32 + 4).to_le_bytes());
        asar.extend_from_slice(&(pickle_inner_len as u32).to_le_bytes());
        asar.extend_from_slice(&(hdr_bytes.len() as u32).to_le_bytes());
        asar.extend_from_slice(hdr_bytes);
        asar.resize(asar.len() + pad, 0);
        asar.extend_from_slice(dep_body);
        asar.extend_from_slice(main_body);
        fs::write(dir.join("bundle.asar"), &asar).unwrap();

        let map = try_build_surface_map_with_excludes(&dir, 200, 12, false, false, &[]).unwrap();
        assert!(
            map.items
                .iter()
                .any(|i| i.target == "src/entry.ts" && i.line == 5),
            "real call on L5 must survive: {:?}",
            map.items
        );
        assert!(
            !map.items
                .iter()
                .any(|i| i.target == "src/entry.ts" && (i.line == 1 || i.line == 2)),
            "bare ES import/export lines must be skipped: {:?}",
            map.items
        );
        assert!(
            !map.items
                .iter()
                .any(|i| i.axis == "auth_token_cred" && i.target == "src/entry.ts"),
            "legal/docs cookie-policy URL prose must be skipped: {:?}",
            map.items
        );
        assert!(
            !map.items.iter().any(|i| i.target.contains("_vendored")
                || i.target.contains("runtime/lib")
                || i.target.contains("locales/")
                || i.target.contains("node_modules")),
            "vendored/stdlib/locales/asar node_modules must be filtered: {:?}",
            map.items
        );
        assert!(
            map.items
                .iter()
                .any(|i| i.target == "bundle.asar!/app/main.js"),
            "non-vendored asar entry must be scanned with canonical !/ path: {:?}",
            map.items
        );
        assert_eq!(
            normalize_surface_target(r"res\app.asar!dist\main.js"),
            "res/app.asar!/dist/main.js"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
