use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecFinding {
    pub cwe: String,
    pub file: String,
    pub line: usize,
    pub snippet: String,
    pub fix: String,
}

struct SecPatterns {
    js_sqli: Regex,
    py_sqli: Regex,
    cmd_inj: Regex,
    dom_xss_tpl: Regex,
    tpl_expr: Regex,
    path_trav_sink: Regex,
    path_trav_dyn: Regex,
    debug_tls: Regex,
    memcpy_s_same_var: Regex,
    alloc_mul_overflow: Regex,
    ssrf_taint: Regex,
    two_phase_header: Regex,
    unsafe_deser: Regex,
}

fn sec_re() -> &'static SecPatterns {
    static RE: OnceLock<SecPatterns> = OnceLock::new();
    RE.get_or_init(|| SecPatterns {
        js_sqli: Regex::new(
            r"(?i)\.(?:exec|prepare|query|run|all|get)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{",
        )
        .unwrap(),
        py_sqli: Regex::new(
            r#"(?i)\.execute\s*\(\s*(?:f["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*(?:%|\+\s*[A-Za-z_]|\.format\())"#,
        )
        .unwrap(),
        cmd_inj: Regex::new(
            r"(?:execSync|child_process\.exec)\s*\(\s*`[^`]*\$\{|os\.system\s*\(\s*f['\x22]|subprocess\.(?:run|Popen|call)\s*\([^)]*\bshell\s*=\s*True",
        )
        .unwrap(),
        dom_xss_tpl: Regex::new(r"(?s)\.innerHTML\s*(?:\+?=)\s*`([^`]*)`").unwrap(),
        tpl_expr: Regex::new(r"\$\{([^}]+)\}").unwrap(),
        path_trav_sink: Regex::new(
            r"(?:readFileSync|readFile|createReadStream|sendFile)\s*\([^)]*(?:req\.url|pathname|searchParams|params\.|query\.)",
        )
        .unwrap(),
        path_trav_dyn: Regex::new(
            r"(?:readFileSync|readFile|createReadStream|sendFile)\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*(?:,|\))",
        )
        .unwrap(),
        debug_tls: Regex::new(
            r"(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\x22]0['\x22]|app\.run\s*\([^)]*debug\s*=\s*True)",
        )
        .unwrap(),
        memcpy_s_same_var: Regex::new(
            r"\b(?:memcpy_s|memmove_s|strncpy_s)\s*\([^,]+,\s*([A-Za-z_][A-Za-z0-9_.\->]*)\s*,[^,]+,\s*([A-Za-z_][A-Za-z0-9_.\->]*)\s*\)",
        )
        .unwrap(),
        alloc_mul_overflow: Regex::new(
            r"\b(?:malloc|realloc)\s*\([^;)]*[A-Za-z_][A-Za-z0-9_]*\s*\*\s*(?:sizeof\b|[A-Za-z_][A-Za-z0-9_]*)",
        )
        .unwrap(),
        ssrf_taint: Regex::new(
            r"(?i)\b(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post|request)|http\.Get|urllib\.request\.urlopen)\s*\([^)]*(?:req\.(?:query|body|params)|request\.(?:args|form|json)|r\.URL\.Query|searchParams)",
        )
        .unwrap(),
        two_phase_header: Regex::new(
            r"(?i)(?:response-content-type|Content-Disposition['\x22\s:=]+inline\b)",
        )
        .unwrap(),
        unsafe_deser: Regex::new(
            r"\b(?:pickle\.loads?|marshal\.loads?)\s*\(|\byaml\.load\s*\([^)]*\)|\beval\s*\([^)]*(?:req\.|request\.|searchParams)",
        )
        .unwrap(),
    })
}

fn has_escape_wrapper(expr: &str) -> bool {
    let low = expr.to_ascii_lowercase();
    low.contains("esc(")
        || low.contains("escape")
        || low.contains("sanitize")
        || low.contains("encodeuri")
        || low.contains("encodehtml")
        || low.contains("safehtml")
        || low.contains("number(")
        || low.contains("math.")
        || low.ends_with(".length")
        || low.ends_with("cents")
        || low.ends_with("count")
        || low.ends_with("stock")
        || low.ends_with("price")
}

fn walk_code_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    if out.len() >= 300 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        let nm = entry.file_name().to_string_lossy().to_string();
        if nm.starts_with('.')
            || matches!(
                nm.as_str(),
                "node_modules" | "target" | "dist" | "build" | "__pycache__" | "vendor"
            )
        {
            continue;
        }
        if p.is_dir() {
            walk_code_files(&p, out);
        } else if p.is_file() {
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
            if matches!(
                ext,
                "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "py" | "go" | "rs" | "c" | "cc" | "cpp" | "h" | "hpp"
            ) {
                out.push(p);
            }
        }
    }
}

pub fn scan_security_issues(root: &Path) -> Vec<SecFinding> {
    let re = sec_re();
    let mut files = Vec::new();
    walk_code_files(root, &mut files);
    let mut findings = Vec::new();

    for fp in files {
        let rel = fp
            .strip_prefix(root)
            .unwrap_or(&fp)
            .to_string_lossy()
            .replace('\\', "/");
        let low_rel = rel.to_ascii_lowercase();
        if low_rel.starts_with("tests/")
            || low_rel.starts_with("test/")
            || low_rel.contains(".test.")
            || low_rel.contains(".spec.")
            || low_rel.contains("_test.")
        {
            continue;
        }
        let Ok(txt) = fs::read_to_string(&fp) else {
            continue;
        };
        let has_path_guard = txt.contains(".startsWith(")
            || txt.contains("path.basename(")
            || txt.contains("path.relative(")
            || txt.contains("os.path.commonpath")
            || txt.contains("includes('..')")
            || txt.contains("includes(\"..\")");
        let has_req_path_taint =
            txt.contains("searchParams") || txt.contains("req.query") || txt.contains("req.params");
        let txt_low = txt.to_ascii_lowercase();
        let has_ssrf_allowlist = txt_low.contains("allowlist")
            || txt_low.contains("whitelist")
            || txt.contains("allowedHosts")
            || txt.contains("ALLOWED_HOSTS");
        let has_safe_download_headers =
            txt_low.contains("nosniff") && txt_low.contains("attachment");

        // Multi-line & multi-expression CWE-79 DOM XSS audit across `.innerHTML = \`...\``
        for cap in re.dom_xss_tpl.captures_iter(&txt) {
            let Some(m_full) = cap.get(0) else { continue };
            let tpl_body = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let mut unsafe_expr = None;
            for ec in re.tpl_expr.captures_iter(tpl_body) {
                let expr = ec.get(1).map(|m| m.as_str().trim()).unwrap_or("");
                if !expr.is_empty() && !has_escape_wrapper(expr) {
                    unsafe_expr = Some(expr.to_string());
                    break;
                }
            }
            if let Some(expr) = unsafe_expr {
                let lineno = txt[..m_full.start()]
                    .bytes()
                    .filter(|&b| b == b'\n')
                    .count()
                    + 1;
                findings.push(SecFinding {
                    cwe: "CWE-79 DOM XSS".to_string(),
                    file: rel.clone(),
                    line: lineno,
                    snippet: format!("innerHTML interpolates `${{{expr}}}` without escaping"),
                    fix: "Use `textContent` / DOM nodes or wrap interpolated data in an `escapeHtml(...)` helper before assigning `innerHTML`.".to_string(),
                });
            }
        }

        let lines: Vec<&str> = txt.lines().collect();
        let mut flagged_trav = false;
        for (idx, ln) in lines.iter().copied().enumerate() {
            let trim = ln.trim();
            if trim.starts_with("//") || trim.starts_with('#') || trim.starts_with('*') {
                continue;
            }
            let lineno = idx + 1;

            if re.js_sqli.is_match(ln) || re.py_sqli.is_match(ln) {
                findings.push(SecFinding {
                    cwe: "CWE-89 SQL Injection".to_string(),
                    file: rel.clone(),
                    line: lineno,
                    snippet: trim.chars().take(120).collect(),
                    fix: "Use parameterized placeholders (`?` / `$1`) instead of interpolating variables into SQL strings.".to_string(),
                });
            }
            if re.cmd_inj.is_match(ln) {
                findings.push(SecFinding {
                    cwe: "CWE-78 Command Injection".to_string(),
                    file: rel.clone(),
                    line: lineno,
                    snippet: trim.chars().take(120).collect(),
                    fix: "Pass explicit argv array to `execFileSync`/`spawnSync`/`subprocess.run(..., shell=False)` instead of shell string interpolation.".to_string(),
                });
            }
            if !has_path_guard
                && !flagged_trav
                && (re.path_trav_sink.is_match(ln)
                    || (has_req_path_taint && re.path_trav_dyn.is_match(ln)))
            {
                flagged_trav = true;
                findings.push(SecFinding {
                    cwe: "CWE-22 Path Traversal".to_string(),
                    file: rel.clone(),
                    line: lineno,
                    snippet: trim.chars().take(120).collect(),
                    fix: "Resolve canonical path (`path.resolve(baseDir, rel)`) and verify `resolved.startsWith(baseDir + path.sep)` before reading files.".to_string(),
                });
            }
            if re.debug_tls.is_match(ln) {
                findings.push(SecFinding {
                    cwe: "CWE-295/489 Insecure Debug/TLS".to_string(),
                    file: rel.clone(),
                    line: lineno,
                    snippet: trim.chars().take(120).collect(),
                    fix: "Do not disable TLS verification or leave `debug=True` enabled in server entrypoints.".to_string(),
                });
            }
            if let Some(cap) = re.memcpy_s_same_var.captures(ln) {
                let dmax = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
                let cnt = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
                if !dmax.is_empty() && dmax == cnt {
                    findings.push(SecFinding {
                        cwe: "CWE-120/787 Bounded-Copy Size Reuse".to_string(),
                        file: rel.clone(),
                        line: lineno,
                        snippet: trim.chars().take(120).collect(),
                        fix: "Pass the actual destination buffer capacity (e.g. `sizeof(dst)` or tracked allocation capacity) as `destMax`, never the copy count variable.".to_string(),
                    });
                }
            }
            if re.alloc_mul_overflow.is_match(ln) {
                let prev_ctx = lines[idx.saturating_sub(2)..=idx]
                    .join(" ")
                    .to_ascii_lowercase();
                let guarded = prev_ctx.contains("size_max")
                    || prev_ctx.contains("checked_mul")
                    || prev_ctx.contains("overflow")
                    || prev_ctx.contains("__builtin_mul_overflow");
                if !guarded {
                    findings.push(SecFinding {
                        cwe: "CWE-190 Allocation Integer Overflow".to_string(),
                        file: rel.clone(),
                        line: lineno,
                        snippet: trim.chars().take(120).collect(),
                        fix: "Use `calloc(count, elem_size)` or verify `count <= SIZE_MAX / elem_size` before multiplying inside `malloc`/`realloc`.".to_string(),
                    });
                }
            }
            if !has_ssrf_allowlist && re.ssrf_taint.is_match(ln) {
                findings.push(SecFinding {
                    cwe: "CWE-918 Potential SSRF".to_string(),
                    file: rel.clone(),
                    line: lineno,
                    snippet: trim.chars().take(120).collect(),
                    fix: "Validate outbound URL scheme/host against an explicit allowlist and block loopback/link-local/RFC1918 targets.".to_string(),
                });
            }
            if re.two_phase_header.is_match(ln) {
                let is_query_override = ln.to_ascii_lowercase().contains("response-content-type");
                if is_query_override || !has_safe_download_headers {
                    findings.push(SecFinding {
                        cwe: "CWE-434/79 Two-Phase Storage/Header Defense Gap".to_string(),
                        file: rel.clone(),
                        line: lineno,
                        snippet: trim.chars().take(120).collect(),
                        fix: "Serve user-controlled uploads from an isolated download domain with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, and disallow unsigned `response-content-type` overrides.".to_string(),
                    });
                }
            }
            if re.unsafe_deser.is_match(ln)
                && !ln.contains("SafeLoader")
                && !ln.contains("CSafeLoader")
            {
                findings.push(SecFinding {
                    cwe: "CWE-94/502 Unsafe Deserialization / Eval".to_string(),
                    file: rel.clone(),
                    line: lineno,
                    snippet: trim.chars().take(120).collect(),
                    fix: "Replace `pickle`/`marshal`/`yaml.load`/`eval` on untrusted data with JSON or `yaml.safe_load` / `SafeLoader`.".to_string(),
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_tmp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ap_sec_test_{tag}_{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detects_cpp_and_web_v2_cwes() {
        let dir = make_tmp_dir("vuln");
        fs::write(
            dir.join("native.cpp"),
            r#"
int handle(void* dst, const void* src, size_t len, size_t n) {
    char* buf = (char*)malloc(n * sizeof(int));
    memcpy_s(dst, len, src, len);
    return buf != nullptr;
}
"#,
        )
        .unwrap();
        fs::write(
            dir.join("handler.py"),
            r#"
import pickle, yaml, requests
def route(request):
    r = requests.get(request.args["url"])
    obj = pickle.loads(r.content)
    cfg = yaml.load(r.text)
    hdr = "Content-Disposition: inline"
    return obj, cfg, hdr
"#,
        )
        .unwrap();

        let findings = scan_security_issues(&dir);
        let cwes: Vec<&str> = findings.iter().map(|f| f.cwe.as_str()).collect();
        assert!(cwes.iter().any(|c| c.contains("CWE-120")), "missing CWE-120: {cwes:?}");
        assert!(cwes.iter().any(|c| c.contains("CWE-190")), "missing CWE-190: {cwes:?}");
        assert!(cwes.iter().any(|c| c.contains("CWE-918")), "missing CWE-918: {cwes:?}");
        assert!(cwes.iter().any(|c| c.contains("CWE-434")), "missing CWE-434: {cwes:?}");
        assert!(cwes.iter().any(|c| c.contains("CWE-94/502")), "missing CWE-94/502: {cwes:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ignores_safe_guards_for_v2_cwes() {
        let dir = make_tmp_dir("safe");
        fs::write(
            dir.join("safe.cpp"),
            r#"
int handle(char dst[64], const void* src, size_t len, size_t n) {
    if (n > SIZE_MAX / sizeof(int)) return -1;
    char* buf = (char*)malloc(n * sizeof(int));
    memcpy_s(dst, sizeof(dst), src, len);
    return buf != nullptr;
}
"#,
        )
        .unwrap();
        fs::write(
            dir.join("safe.py"),
            r#"
import yaml, requests
ALLOWED_HOSTS = {"api.example.com"}
def route(request):
    cfg = yaml.load(request.data, Loader=yaml.SafeLoader)
    return requests.get(request.args["url"]) if ALLOWED_HOSTS else cfg
"#,
        )
        .unwrap();

        let findings = scan_security_issues(&dir);
        assert!(findings.is_empty(), "expected 0 findings on guarded code, got: {findings:?}");
        let _ = fs::remove_dir_all(&dir);
    }
}
