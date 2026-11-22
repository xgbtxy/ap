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
    xxe_parser: Regex,
    proto_pollution: Regex,
    weak_jwt_tls: Regex,
    unbounded_container: Regex,
    unsigned_underflow: Regex,
    async_raw_this: Regex,
    native_raw_sql_concat: Regex,
    weak_crypto_mode: Regex,
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
        xxe_parser: Regex::new(
            r"\b(?:DocumentBuilderFactory\.newInstance|XMLInputFactory\.newInstance|SAXParserFactory\.newInstance|lxml\.etree\.XMLParser)\s*\(",
        )
        .unwrap(),
        proto_pollution: Regex::new(
            r"\bObject\.assign\s*\([^,]+,\s*(?:req\.body|req\.query|JSON\.parse\s*\()|\[\s*['\x22]__proto__['\x22]\s*\]",
        )
        .unwrap(),
        weak_jwt_tls: Regex::new(
            r#"(?i)(?:algorithms\s*:\s*\[\s*['"]none['"]\s*\]|requests\.(?:get|post|put|delete|request)\s*\([^)]*\bverify\s*=\s*False)"#,
        )
        .unwrap(),
        unbounded_container: Regex::new(
            r"\b[a-z][A-Za-z0-9_]*_\.(?:emplace|emplace_back|insert|push_back)\s*\(",
        )
        .unwrap(),
        unsigned_underflow: Regex::new(
            r"\b(?:size_t|uint(?:16|32|64)_t|unsigned\s+(?:int|long))\s+[A-Za-z_]\w*\s*=\s*([A-Za-z_][A-Za-z0-9_.\->]*)\s*-\s*([A-Za-z_][A-Za-z0-9_.\->]*)\s*;",
        )
        .unwrap(),
        async_raw_this: Regex::new(
            r"\b(?:std::thread|std::async|PostTask|postTask|dispatch_async|ScheduleTask)\s*\([^;\n]*\[(?:[^\]]*\bthis\b|&)\s*\]",
        )
        .unwrap(),
        native_raw_sql_concat: Regex::new(
            r#""[^"]*(?i:SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+\s*(?:[a-z][A-Za-z0-9_.\->]*)\b"#,
        )
        .unwrap(),
        weak_crypto_mode: Regex::new(
            r#"(?:\b(?:AES_ECB|EVP_aes_(?:128|192|256)_ecb|DES_ecb|RC4_set_key|MD5_Init)\b|Cipher\.getInstance\s*\(\s*["'](?:AES/ECB|DES|RC4|AES["'])|hashlib\.md5\s*\()"#,
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
                "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "py" | "go" | "rs" | "java" | "c" | "cc" | "cpp" | "h" | "hpp"
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
            if re.xxe_parser.is_match(ln)
                && !txt_low.contains("disallow-doctype-decl")
                && !txt_low.contains("resolve_entities=false")
                && !txt_low.contains("is_supporting_external_entities")
            {
                findings.push(SecFinding {
                    cwe: "CWE-611 XML External Entity (XXE)".to_string(),
                    file: rel.clone(),
                    line: lineno,
                    snippet: trim.chars().take(120).collect(),
                    fix: "Disable DOCTYPE and external entities (`disallow-doctype-decl=true` or `resolve_entities=False`).".to_string(),
                });
            }
            if re.proto_pollution.is_match(ln)
                && !txt_low.contains("hasown")
                && !txt.contains("!== '__proto__'")
                && !txt.contains("!== \"__proto__\"")
            {
                findings.push(SecFinding {
                    cwe: "CWE-1321 Prototype Pollution".to_string(),
                    file: rel.clone(),
                    line: lineno,
                    snippet: trim.chars().take(120).collect(),
                    fix: "Pick explicit allowlisted keys or reject `__proto__`/`constructor`/`prototype` before merging untrusted objects.".to_string(),
                });
            }
            if re.weak_jwt_tls.is_match(ln) {
                findings.push(SecFinding {
                    cwe: "CWE-295/347 Weak JWT/TLS Verification".to_string(),
                    file: rel.clone(),
                    line: lineno,
                    snippet: trim.chars().take(120).collect(),
                    fix: "Enforce strong JWT algorithms (never `none`) and keep TLS certificate verification enabled (`verify=True`).".to_string(),
                });
            }
            if re.unbounded_container.is_match(ln) {
                let win_start = idx.saturating_sub(6);
                let win_ctx = lines[win_start..=idx].join(" ").to_ascii_lowercase();
                let has_cap = win_ctx.contains(".size() >=")
                    || win_ctx.contains(".size() >")
                    || win_ctx.contains("max_")
                    || win_ctx.contains("quota")
                    || win_ctx.contains("limit")
                    || win_ctx.contains("capacity");
                if !has_cap {
                    findings.push(SecFinding {
                        cwe: "CWE-400 Unbounded Container Growth".to_string(),
                        file: rel.clone(),
                        line: lineno,
                        snippet: trim.chars().take(120).collect(),
                        fix: "Enforce an explicit upper bound / per-caller quota check (e.g. `if (items_.size() >= MAX_ITEMS) return ERR;`) before inserting into member containers.".to_string(),
                    });
                }
            }
            if re.unsigned_underflow.is_match(ln) {
                let win_start = idx.saturating_sub(4);
                let win_ctx = lines[win_start..=idx].join(" ").to_ascii_lowercase();
                let guarded = win_ctx.contains("if (")
                    || win_ctx.contains("if(")
                    || win_ctx.contains("checked_sub")
                    || win_ctx.contains("saturating_sub")
                    || win_ctx.contains("std::max")
                    || win_ctx.contains("std::min");
                if !guarded {
                    findings.push(SecFinding {
                        cwe: "CWE-191 Unsigned Integer Underflow".to_string(),
                        file: rel.clone(),
                        line: lineno,
                        snippet: trim.chars().take(120).collect(),
                        fix: "Verify `lhs >= rhs` before subtracting unsigned lengths/sizes to prevent wrap-around to huge positive values.".to_string(),
                    });
                }
            }
            if re.async_raw_this.is_match(ln) {
                let win_start = idx.saturating_sub(5);
                let win_ctx = lines[win_start..=idx].join(" ").to_ascii_lowercase();
                let safe_ref = win_ctx.contains("weak_ptr")
                    || win_ctx.contains("shared_from_this")
                    || win_ctx.contains("wptr")
                    || win_ctx.contains("weak_from_this");
                if !safe_ref {
                    findings.push(SecFinding {
                        cwe: "CWE-416 Async Raw-this Lifetime Risk".to_string(),
                        file: rel.clone(),
                        line: lineno,
                        snippet: trim.chars().take(120).collect(),
                        fix: "Capture a `std::weak_ptr` / `weak_from_this()` and `lock()` inside the async callback instead of capturing raw `[this]` or `[&]`.".to_string(),
                    });
                }
            }
            if re.native_raw_sql_concat.is_match(ln)
                && !ln.contains("to_string(")
                && !ln.contains("strconv.Itoa")
                && !ln.contains("String.valueOf")
            {
                findings.push(SecFinding {
                    cwe: "CWE-89 Raw SQL String Concatenation".to_string(),
                    file: rel.clone(),
                    line: lineno,
                    snippet: trim.chars().take(120).collect(),
                    fix: "Use bound parameters / prepared statements instead of concatenating runtime variables into SQL statements.".to_string(),
                });
            }
            if re.weak_crypto_mode.is_match(ln) {
                let low_ln = ln.to_ascii_lowercase();
                let non_sec_hash = low_ln.contains("usedforsecurity=false")
                    || low_ln.contains("checksum")
                    || low_ln.contains("etag")
                    || low_ln.contains("cache_key");
                if !non_sec_hash {
                    findings.push(SecFinding {
                        cwe: "CWE-327 Weak Crypto Algorithm / ECB Mode".to_string(),
                        file: rel.clone(),
                        line: lineno,
                        snippet: trim.chars().take(120).collect(),
                        fix: "Use authenticated encryption (AES-GCM / ChaCha20-Poly1305) and SHA-256/SHA-3 instead of ECB, DES, RC4, or MD5.".to_string(),
                    });
                }
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

        fs::write(
            dir.join("XmlCtrl.java"),
            "class XmlCtrl { void f() { DocumentBuilderFactory.newInstance(); } }\n",
        )
        .unwrap();
        fs::write(
            dir.join("merge.js"),
            "function m(dst, req) { Object.assign(dst, req.body); jwt.verify(t, k, { algorithms: ['none'] }); }\n",
        )
        .unwrap();
        let findings2 = scan_security_issues(&dir);
        let cwes2: Vec<&str> = findings2.iter().map(|f| f.cwe.as_str()).collect();
        assert!(cwes2.iter().any(|c| c.contains("CWE-611")), "missing CWE-611: {cwes2:?}");
        assert!(cwes2.iter().any(|c| c.contains("CWE-1321")), "missing CWE-1321: {cwes2:?}");
        assert!(cwes2.iter().any(|c| c.contains("CWE-295/347")), "missing CWE-295/347: {cwes2:?}");
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

    #[test]
    fn detects_v3_native_and_crypto_cwes_with_guard_precision() {
        let dir = make_tmp_dir("v3_vuln");
        fs::write(
            dir.join("server.cpp"),
            r#"
void Service::OnReq(uint32_t total, uint32_t hdr, std::string user) {
    sessions_.emplace(user, 1);
    size_t bodyLen = total - hdr;
    std::thread([this]() { this->Flush(); }).detach();
    std::string sql = "SELECT * FROM users WHERE name = " + user;
    EVP_aes_128_ecb();
}
"#,
        )
        .unwrap();
        let findings = scan_security_issues(&dir);
        let cwes: Vec<&str> = findings.iter().map(|f| f.cwe.as_str()).collect();
        assert!(cwes.iter().any(|c| c.contains("CWE-400")), "missing CWE-400: {cwes:?}");
        assert!(cwes.iter().any(|c| c.contains("CWE-191")), "missing CWE-191: {cwes:?}");
        assert!(cwes.iter().any(|c| c.contains("CWE-416")), "missing CWE-416: {cwes:?}");
        assert!(cwes.iter().any(|c| c.contains("CWE-89")), "missing CWE-89: {cwes:?}");
        assert!(cwes.iter().any(|c| c.contains("CWE-327")), "missing CWE-327: {cwes:?}");
        let _ = fs::remove_dir_all(&dir);

        let safe_dir = make_tmp_dir("v3_safe");
        fs::write(
            safe_dir.join("safe_server.cpp"),
            r#"
void Service::OnReq(uint32_t total, uint32_t hdr, int uid) {
    if (sessions_.size() >= MAX_SESSIONS) return;
    sessions_.emplace(uid, 1);
    if (total < hdr) return;
    size_t bodyLen = total - hdr;
    auto weak = weak_from_this();
    std::thread([weak]() { if (auto s = weak.lock()) s->Flush(); }).detach();
    std::string sql = "SELECT * FROM " + TABLE_USERS;
}
"#,
        )
        .unwrap();
        let safe_findings = scan_security_issues(&safe_dir);
        assert!(
            safe_findings.is_empty(),
            "expected 0 findings on guarded v3 code, got: {safe_findings:?}"
        );
        let _ = fs::remove_dir_all(&safe_dir);
    }
}
