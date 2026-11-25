use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeResult {
    pub method: String,
    pub url: String,
    pub status: u16,
    pub elapsed_ms: f64,
    pub content_type: String,
    pub headers: Vec<String>,
    pub body_preview: String,
    pub error: String,
}

fn is_loopback_url(url: &str) -> bool {
    let low = url.to_ascii_lowercase();
    low.contains("://127.0.0.1") || low.contains("://localhost") || low.contains("://[::1]")
}

pub fn execute_http_probe(
    method: &str,
    url: &str,
    headers: &[String],
    body: Option<&str>,
    timeout_sec: u64,
    insecure: bool,
    follow: bool,
) -> HttpProbeResult {
    execute_http_probe_with_raw(method, url, headers, body, timeout_sec, insecure, follow).0
}

fn execute_http_probe_with_raw(
    method: &str,
    url: &str,
    headers: &[String],
    body: Option<&str>,
    timeout_sec: u64,
    insecure: bool,
    follow: bool,
) -> (HttpProbeResult, String) {
    let t0 = Instant::now();
    let curl_bin = if cfg!(windows) { "curl.exe" } else { "curl" };
    let mut cmd = Command::new(curl_bin);
    cmd.args([
        "-sS",
        "-i",
        "--max-time",
        &timeout_sec.clamp(1, 120).to_string(),
        "-X",
        method,
    ]);
    if is_loopback_url(url) {
        cmd.args(["--noproxy", "127.0.0.1,localhost,::1"]);
    }
    let after_scheme = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);
    if let Some(slash_idx) = after_scheme.find('/') {
        let req_path = &after_scheme[slash_idx..];
        if req_path.contains("/./")
            || req_path.contains("/../")
            || req_path.contains("..;")
            || req_path.contains("//")
        {
            cmd.arg("--path-as-is");
        }
    }
    if insecure {
        cmd.arg("-k");
    }
    if follow {
        cmd.arg("-L");
    }
    for h in headers {
        cmd.args(["-H", h]);
    }
    if let Some(b) = body.filter(|s| !s.is_empty()) {
        let has_ct = headers
            .iter()
            .any(|h| h.to_ascii_lowercase().starts_with("content-type:"));
        if !has_ct && (b.trim_start().starts_with('{') || b.trim_start().starts_with('[')) {
            cmd.args(["-H", "Content-Type: application/json"]);
        }
        cmd.args(["--data-raw", b]);
    }
    cmd.arg(url);

    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            return (
                HttpProbeResult {
                    method: method.to_string(),
                    url: url.to_string(),
                    status: 0,
                    elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0).round(),
                    content_type: String::new(),
                    headers: Vec::new(),
                    body_preview: String::new(),
                    error: format!("failed to spawn {curl_bin}: {e}"),
                },
                String::new(),
            );
        }
    };
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
    if !out.status.success() && out.stdout.is_empty() {
        return (
            HttpProbeResult {
                method: method.to_string(),
                url: url.to_string(),
                status: 0,
                elapsed_ms,
                content_type: String::new(),
                headers: Vec::new(),
                body_preview: String::new(),
                error: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            },
            String::new(),
        );
    }

    let raw = String::from_utf8_lossy(&out.stdout).to_string();
    // Handle redirect chains / 100 Continue by taking the LAST HTTP header block
    let mut rest = raw.as_str();
    let mut hdr_block = "";
    while rest.starts_with("HTTP/") {
        if let Some(idx) = rest.find("\r\n\r\n") {
            hdr_block = &rest[..idx];
            rest = &rest[idx + 4..];
        } else if let Some(idx) = rest.find("\n\n") {
            hdr_block = &rest[..idx];
            rest = &rest[idx + 2..];
        } else {
            break;
        }
    }
    let body_raw = rest;
    let mut status = 0u16;
    let mut ct = String::new();
    let mut hdrs = Vec::new();
    for (idx, ln) in hdr_block.lines().enumerate() {
        let t = ln.trim();
        if idx == 0 {
            status = t
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
        } else if !t.is_empty() {
            if let Some((k, v)) = t.split_once(':') {
                if k.eq_ignore_ascii_case("content-type") {
                    ct = v.trim().to_string();
                }
            }
            if hdrs.len() < 24 {
                hdrs.push(t.to_string());
            }
        }
    }

    let preview: String = if body_raw.len() > 2400 {
        format!(
            "{}...\n[truncated: {}B total]",
            body_raw.chars().take(2400).collect::<String>(),
            body_raw.len()
        )
    } else {
        body_raw.to_string()
    };

    (
        HttpProbeResult {
            method: method.to_string(),
            url: url.to_string(),
            status,
            elapsed_ms,
            content_type: ct,
            headers: hdrs,
            body_preview: preview,
            error: String::new(),
        },
        body_raw.to_string(),
    )
}

fn has_header_name(headers: &[String], target: &str) -> bool {
    headers.iter().any(|h| {
        h.split_once(':')
            .map(|(k, _)| k.trim().eq_ignore_ascii_case(target))
            .unwrap_or(false)
    })
}

/// Fetch live cookies from a local loopback CDP port strictly in-memory as a `Cookie: ...` header.
/// Never prints, logs, or serializes cookie names or values.
fn resolve_cdp_cookie_header(port: u16, url: &str) -> Result<(Option<String>, usize), String> {
    let pairs = crate::cdp::CdpSession::fetch_cookies_for_url("127.0.0.1", port, url)?;
    if pairs.is_empty() {
        return Ok((None, 0));
    }
    let count = pairs.len();
    let joined = pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    Ok((Some(format!("Cookie: {joined}")), count))
}

/// Parse `--principal-cdp` spec (`label=port` or bare `port`).
pub fn parse_principal_cdp_spec(raw: &str) -> Result<(String, u16), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty --principal-cdp spec".to_string());
    }
    let (label, port_str) = match trimmed.split_once('=') {
        Some((l, p)) => (l.trim().to_string(), p.trim()),
        None => (format!("cdp:{trimmed}"), trimmed),
    };
    let port = port_str
        .parse::<u16>()
        .map_err(|_| format!("invalid port `{port_str}` in --principal-cdp `{raw}`"))?;
    if port == 0 {
        return Err(format!("port must be 1..=65535 in --principal-cdp `{raw}`"));
    }
    let final_label = if label.is_empty() {
        format!("cdp:{port}")
    } else {
        label
    };
    Ok((final_label, port))
}

/// Extract a lightweight dot-path JSON selector (supports `[*]` array projection and numeric indices).
pub fn extract_json_select(body: &str, select_expr: &str) -> Option<Value> {
    let parsed: Value = serde_json::from_str(body.trim()).ok()?;
    let tokens: Vec<&str> = select_expr
        .trim()
        .trim_start_matches("$.")
        .trim_start_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
        .collect();
    if tokens.is_empty() {
        return Some(parsed);
    }
    fn step(cur: &Value, toks: &[&str]) -> Option<Value> {
        let Some((&head, rest)) = toks.split_first() else {
            return Some(cur.clone());
        };
        if let Some(field) = head.strip_suffix("[*]") {
            let arr_val = if field.is_empty() {
                cur
            } else {
                cur.get(field)?
            };
            let arr = arr_val.as_array()?;
            let mapped: Vec<Value> = arr.iter().filter_map(|el| step(el, rest)).collect();
            return Some(Value::Array(mapped));
        }
        if head == "*" {
            let arr = cur.as_array()?;
            let mapped: Vec<Value> = arr.iter().filter_map(|el| step(el, rest)).collect();
            return Some(Value::Array(mapped));
        }
        if let Ok(idx) = head.parse::<usize>() {
            if let Some(arr) = cur.as_array() {
                return arr.get(idx).and_then(|el| step(el, rest));
            }
        }
        cur.get(head).and_then(|next| step(next, rest))
    }
    step(&parsed, &tokens)
}

/// Audit HTTP response headers specifically for cross-origin CORS reflection & Vary: Origin posture.
pub fn audit_cors_reflection(sent_origin: &str, headers: &[String]) -> Vec<String> {
    let sent = sent_origin.trim();
    if sent.is_empty() {
        return Vec::new();
    }
    let mut acao: Option<String> = None;
    let mut acac = false;
    let mut vary_vals: Vec<String> = Vec::new();
    for h in headers {
        if let Some((k, v)) = h.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let vt = v.trim();
            if kl == "access-control-allow-origin" {
                acao = Some(vt.to_string());
            } else if kl == "access-control-allow-credentials" {
                acac = vt.eq_ignore_ascii_case("true");
            } else if kl == "vary" {
                vary_vals.push(vt.to_ascii_lowercase());
            }
        }
    }
    let mut findings = Vec::new();
    if let Some(ref allow) = acao {
        let reflected = allow.eq_ignore_ascii_case(sent);
        let wildcard_or_null = allow == "*" || allow.eq_ignore_ascii_case("null");
        if reflected && acac {
            findings.push(format!(
                "CORS-CRITICAL: reflected Origin `{sent}` with Access-Control-Allow-Credentials: true"
            ));
        } else if reflected {
            findings.push(format!(
                "CORS-WARN: reflected Origin `{sent}` (without Allow-Credentials)"
            ));
        } else if wildcard_or_null && acac {
            findings.push(format!(
                "CORS-CRITICAL: Access-Control-Allow-Origin `{allow}` with Allow-Credentials: true"
            ));
        }
        if reflected {
            let has_vary_origin = vary_vals.iter().any(|v| {
                v.split(',')
                    .any(|p| p.trim() == "origin" || p.trim() == "*")
            });
            if !has_vary_origin {
                findings.push(
                    "CORS-WARN: dynamic Access-Control-Allow-Origin missing `Vary: Origin`"
                        .to_string(),
                );
            }
        }
    }
    findings
}

fn parse_json_http_job(v: &Value) -> Option<(String, String, Vec<String>, Option<String>)> {
    let obj = v.as_object()?;
    let u = obj.get("url").and_then(Value::as_str)?.trim();
    if !(u.starts_with("http://") || u.starts_with("https://")) {
        return None;
    }
    let m = obj
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .trim()
        .to_ascii_uppercase();
    let mut hdrs = Vec::new();
    if let Some(arr) = obj.get("headers").and_then(Value::as_array) {
        for item in arr {
            if let Some(s) = item.as_str() {
                hdrs.push(s.to_string());
            }
        }
    } else if let Some(map) = obj.get("headers").and_then(Value::as_object) {
        for (k, val) in map {
            if let Some(s) = val.as_str() {
                hdrs.push(format!("{k}: {s}"));
            } else {
                hdrs.push(format!("{k}: {val}"));
            }
        }
    }
    let body = obj.get("body").and_then(|b| match b {
        Value::Null => None,
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::String(_) => None,
        other => Some(other.to_string()),
    });
    Some((m, u.to_string(), hdrs, body))
}

#[allow(clippy::too_many_arguments)]
pub fn run_http_cli(
    url_opt: Option<&str>,
    method: &str,
    headers: &[String],
    body: Option<&str>,
    timeout_sec: u64,
    insecure: bool,
    follow: bool,
    batch_stdin: bool,
    cdp_cookies_port: Option<u16>,
    cors_origin: Option<&str>,
    select_expr: Option<&str>,
    audit_headers: bool,
    as_json: bool,
) -> i32 {
    let mut jobs: Vec<(String, String, Vec<String>, Option<String>)> = Vec::new();
    if let Some(u) = url_opt.filter(|s| !s.trim().is_empty()) {
        jobs.push((
            method.to_ascii_uppercase(),
            u.to_string(),
            Vec::new(),
            body.map(str::to_string),
        ));
    }
    if batch_stdin {
        let mut buf = String::new();
        let _ = std::io::stdin().read_to_string(&mut buf);
        let trimmed = buf.trim();
        if trimmed.starts_with('[') {
            if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(trimmed) {
                for it in items {
                    if let Some(job) = parse_json_http_job(&it) {
                        jobs.push(job);
                    }
                }
            }
        } else {
            for raw_ln in buf.lines() {
                let ln = raw_ln.trim();
                if ln.is_empty() || ln.starts_with('#') {
                    continue;
                }
                if ln.starts_with('{') {
                    if let Ok(v) = serde_json::from_str::<Value>(ln) {
                        if let Some(job) = parse_json_http_job(&v) {
                            jobs.push(job);
                            continue;
                        }
                    }
                }
                if ln.starts_with("http://") || ln.starts_with("https://") {
                    jobs.push(("GET".to_string(), ln.to_string(), Vec::new(), None));
                    continue;
                }
                let mut p = ln.splitn(3, char::is_whitespace);
                let m = p.next().unwrap_or("GET").to_ascii_uppercase();
                let u = p.next().unwrap_or("").trim();
                let b = p
                    .next()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                if u.starts_with("http://") || u.starts_with("https://") {
                    jobs.push((m, u.to_string(), Vec::new(), b));
                }
            }
        }
    }
    if jobs.is_empty() {
        eprintln!(
            "[probe http] Provide a URL or pass `--batch-stdin` with `METHOD URL [BODY]` lines or JSON/JSONL request objects."
        );
        return 2;
    }

    let cors_orig_clean = cors_origin.map(str::trim).filter(|s| !s.is_empty());
    let select_clean = select_expr.map(str::trim).filter(|s| !s.is_empty());
    let mut results = Vec::new();
    let mut raw_bodies = Vec::new();
    for (m, u, extra_hdrs, b) in jobs.into_iter().take(25) {
        let mut merged_hdrs = headers.to_vec();
        merged_hdrs.extend(extra_hdrs);
        if let Some(orig) = cors_orig_clean {
            if !has_header_name(&merged_hdrs, "origin") {
                merged_hdrs.push(format!("Origin: {orig}"));
            }
        }
        if let Some(port) = cdp_cookies_port {
            if !has_header_name(&merged_hdrs, "cookie") {
                match resolve_cdp_cookie_header(port, &u) {
                    Ok((Some(ch), _cnt)) => merged_hdrs.push(ch),
                    Ok((None, _)) => {}
                    Err(e) => {
                        results.push(HttpProbeResult {
                            method: m,
                            url: u,
                            status: 0,
                            elapsed_ms: 0.0,
                            content_type: String::new(),
                            headers: Vec::new(),
                            body_preview: String::new(),
                            error: format!("cdp-cookies:{port}: {e}"),
                        });
                        raw_bodies.push(String::new());
                        continue;
                    }
                }
            }
        }
        let (res, raw_b) = execute_http_probe_with_raw(
            &m,
            &u,
            &merged_hdrs,
            b.as_deref(),
            timeout_sec,
            insecure,
            follow,
        );
        results.push(res);
        raw_bodies.push(raw_b);
    }

    let any_err = results.iter().any(|r| !r.error.is_empty() || r.status == 0);
    let do_audit = audit_headers || cors_orig_clean.is_some();
    let header_audits: Vec<Vec<String>> = if do_audit {
        results
            .iter()
            .map(|r| {
                let mut gaps = if audit_headers {
                    audit_response_headers(&r.url, r.status, &r.content_type, &r.headers)
                } else {
                    Vec::new()
                };
                if let Some(orig) = cors_orig_clean {
                    gaps.extend(audit_cors_reflection(orig, &r.headers));
                }
                gaps
            })
            .collect()
    } else {
        Vec::new()
    };
    let selected_vals: Vec<Option<Value>> = if let Some(sel) = select_clean {
        raw_bodies
            .iter()
            .map(|rb| extract_json_select(rb, sel))
            .collect()
    } else {
        Vec::new()
    };
    if as_json {
        let needs_extra = do_audit
            || select_clean.is_some()
            || results
                .iter()
                .any(|r| summarize_non_json_body(&r.content_type, &r.body_preview).is_some());
        let out_val = if needs_extra {
            let enriched: Vec<Value> = results
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    let mut v = serde_json::to_value(r).unwrap_or_else(|_| json!({}));
                    if let Some(m) = v.as_object_mut() {
                        if do_audit {
                            m.insert(
                                "header_findings".to_string(),
                                json!(header_audits.get(i).cloned().unwrap_or_default()),
                            );
                        }
                        if select_clean.is_some() {
                            m.insert(
                                "selected".to_string(),
                                selected_vals
                                    .get(i)
                                    .cloned()
                                    .flatten()
                                    .unwrap_or(Value::Null),
                            );
                        }
                        if let Some(diag) =
                            summarize_non_json_body(&r.content_type, &r.body_preview)
                        {
                            m.insert("body_diagnostic".to_string(), json!(diag));
                        }
                    }
                    v
                })
                .collect();
            json!({
                "ok": !any_err,
                "count": results.len(),
                "cors_origin": cors_orig_clean,
                "results": enriched,
            })
        } else {
            json!({
                "ok": !any_err,
                "count": results.len(),
                "results": results,
            })
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&out_val).unwrap_or_default()
        );
    } else if results.len() == 1 {
        let r = &results[0];
        if !r.error.is_empty() {
            eprintln!("[probe http] FAIL {} {} — {}", r.method, r.url, r.error);
        } else {
            println!(
                "[probe http] {} {} -> HTTP {} ({}ms | {})",
                r.method, r.url, r.status, r.elapsed_ms, r.content_type
            );
            for h in r.headers.iter().take(10) {
                println!("  {h}");
            }
            if do_audit {
                let gaps = header_audits.first().cloned().unwrap_or_default();
                if gaps.is_empty() {
                    println!("  [header-audit] PASS (0 security/CORS gaps)");
                } else {
                    println!(
                        "  [header-audit] {} gap(s): {}",
                        gaps.len(),
                        gaps.join(" | ")
                    );
                }
            }
            if let Some(sel) = select_clean {
                let sval = selected_vals
                    .first()
                    .cloned()
                    .flatten()
                    .unwrap_or(Value::Null);
                println!("  [select:{sel}] {sval}");
            } else if !r.body_preview.is_empty() {
                println!("\n{}", r.body_preview);
            }
        }
    } else {
        println!("[probe http] Batch {} request(s):", results.len());
        for (i, r) in results.iter().enumerate() {
            if !r.error.is_empty() {
                println!("  {}. {} {} -> ERR ({})", i + 1, r.method, r.url, r.error);
            } else {
                let snip: String = if select_clean.is_some() {
                    selected_vals
                        .get(i)
                        .cloned()
                        .flatten()
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "null".to_string())
                        .chars()
                        .take(120)
                        .collect()
                } else {
                    r.body_preview
                        .replace(['\r', '\n'], " ")
                        .chars()
                        .take(120)
                        .collect()
                };
                let gap_tag = if do_audit {
                    let g = header_audits.get(i).map(|v| v.len()).unwrap_or(0);
                    format!(" [gaps={g}]")
                } else {
                    String::new()
                };
                println!(
                    "  {}. {} {} -> HTTP {} ({}ms){} — `{}`",
                    i + 1,
                    r.method,
                    r.url,
                    r.status,
                    r.elapsed_ms,
                    gap_tag,
                    snip
                );
            }
        }
    }
    if any_err {
        1
    } else {
        0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpVariantSpec {
    pub label: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<String>,
    pub body: Option<String>,
}

fn load_saved_request(
    path: &std::path::Path,
) -> Result<(String, String, Vec<String>, Option<String>), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        let v: Value =
            serde_json::from_str(trimmed).map_err(|e| format!("parse JSON request: {e}"))?;
        return parse_json_http_job(&v).ok_or_else(|| {
            "JSON request must contain valid `url` (http:// or https://)".to_string()
        });
    }
    // Raw HTTP request format:
    // METHOD https://... (or /path with Host header) HTTP/1.1
    let mut lines = raw.lines();
    let first = lines.next().unwrap_or("").trim();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_ascii_uppercase();
    let target = parts.next().unwrap_or("").to_string();
    let mut hdrs = Vec::new();
    let mut host = String::new();
    let mut body_lines = Vec::new();
    let mut in_body = false;
    for ln in lines {
        if !in_body {
            if ln.trim().is_empty() {
                in_body = true;
                continue;
            }
            if let Some((k, v)) = ln.split_once(':') {
                if k.eq_ignore_ascii_case("host") {
                    host = v.trim().to_string();
                    continue;
                }
                if k.eq_ignore_ascii_case("content-length") {
                    continue;
                }
            }
            hdrs.push(ln.trim().to_string());
        } else {
            body_lines.push(ln);
        }
    }
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target
    } else if !host.is_empty() {
        let scheme = if host.starts_with("127.0.0.1") || host.starts_with("localhost") {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{host}{target}")
    } else {
        return Err("raw HTTP file needs full URL or Host header".to_string());
    };
    let body_str = body_lines.join("\n");
    let body = if body_str.trim().is_empty() {
        None
    } else {
        Some(body_str)
    };
    Ok((method, url, hdrs, body))
}

fn build_single_field_variants(
    method: &str,
    url: &str,
    headers: &[String],
    body: Option<&str>,
    field: &str,
    alt_value: Option<&str>,
    max_variants: usize,
) -> Vec<HttpVariantSpec> {
    let mut out = Vec::new();
    let alt = alt_value.unwrap_or("alt_probe_val");
    out.push(HttpVariantSpec {
        label: "baseline".to_string(),
        method: method.to_string(),
        url: url.to_string(),
        headers: headers.to_vec(),
        body: body.map(str::to_string),
    });

    // 1. JSON body field variations if body is a JSON object containing `field` (or even adding it)
    if let Some(b_raw) = body {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(b_raw) {
            if map.contains_key(field) {
                let orig_val = map.get(field).cloned().unwrap_or(Value::Null);
                let mut omit = map.clone();
                omit.remove(field);
                out.push(HttpVariantSpec {
                    label: format!("json:omit:{field}"),
                    method: method.to_string(),
                    url: url.to_string(),
                    headers: headers.to_vec(),
                    body: Some(Value::Object(omit).to_string()),
                });

                let mut null_m = map.clone();
                null_m.insert(field.to_string(), Value::Null);
                out.push(HttpVariantSpec {
                    label: format!("json:null:{field}"),
                    method: method.to_string(),
                    url: url.to_string(),
                    headers: headers.to_vec(),
                    body: Some(Value::Object(null_m).to_string()),
                });

                let mut empty_m = map.clone();
                empty_m.insert(field.to_string(), Value::String(String::new()));
                out.push(HttpVariantSpec {
                    label: format!("json:empty:{field}"),
                    method: method.to_string(),
                    url: url.to_string(),
                    headers: headers.to_vec(),
                    body: Some(Value::Object(empty_m).to_string()),
                });

                let mut alt_m = map.clone();
                alt_m.insert(field.to_string(), Value::String(alt.to_string()));
                out.push(HttpVariantSpec {
                    label: format!("json:alt:{field}"),
                    method: method.to_string(),
                    url: url.to_string(),
                    headers: headers.to_vec(),
                    body: Some(Value::Object(alt_m).to_string()),
                });

                let swapped = match &orig_val {
                    Value::String(_) => json!(0),
                    Value::Number(_) => Value::String(orig_val.to_string()),
                    Value::Bool(b) => Value::Bool(!b),
                    Value::Array(_) => json!({}),
                    _ => json!([alt]),
                };
                let mut type_m = map.clone();
                type_m.insert(field.to_string(), swapped);
                out.push(HttpVariantSpec {
                    label: format!("json:type_swap:{field}"),
                    method: method.to_string(),
                    url: url.to_string(),
                    headers: headers.to_vec(),
                    body: Some(Value::Object(type_m).to_string()),
                });

                // Raw duplicate JSON key variant: keeps original pair and appends duplicate key with alt value
                let trimmed_b = b_raw.trim();
                if let Some(prefix) = trimmed_b.strip_suffix('}') {
                    let dup_body = format!(
                        "{},{}:{}}}",
                        prefix,
                        serde_json::to_string(field).unwrap_or_default(),
                        serde_json::to_string(alt).unwrap_or_default()
                    );
                    out.push(HttpVariantSpec {
                        label: format!("json:dup_key:{field}"),
                        method: method.to_string(),
                        url: url.to_string(),
                        headers: headers.to_vec(),
                        body: Some(dup_body),
                    });
                }
            }
        }
    }

    // 2. Query string single-parameter variations
    if let Some((base, qs)) = url.split_once('?') {
        let pairs: Vec<&str> = qs.split('&').filter(|p| !p.is_empty()).collect();
        let has_q = pairs
            .iter()
            .any(|p| p.split_once('=').map(|(k, _)| k).unwrap_or(p) == field);
        if has_q {
            let omit_qs: Vec<&str> = pairs
                .iter()
                .copied()
                .filter(|p| p.split_once('=').map(|(k, _)| k).unwrap_or(p) != field)
                .collect();
            let omit_url = if omit_qs.is_empty() {
                base.to_string()
            } else {
                format!("{base}?{}", omit_qs.join("&"))
            };
            out.push(HttpVariantSpec {
                label: format!("query:omit:{field}"),
                method: method.to_string(),
                url: omit_url,
                headers: headers.to_vec(),
                body: body.map(str::to_string),
            });

            let empty_qs: Vec<String> = pairs
                .iter()
                .map(|p| {
                    if p.split_once('=').map(|(k, _)| k).unwrap_or(p) == field {
                        format!("{field}=")
                    } else {
                        (*p).to_string()
                    }
                })
                .collect();
            out.push(HttpVariantSpec {
                label: format!("query:empty:{field}"),
                method: method.to_string(),
                url: format!("{base}?{}", empty_qs.join("&")),
                headers: headers.to_vec(),
                body: body.map(str::to_string),
            });

            let alt_qs: Vec<String> = pairs
                .iter()
                .map(|p| {
                    if p.split_once('=').map(|(k, _)| k).unwrap_or(p) == field {
                        format!("{field}={alt}")
                    } else {
                        (*p).to_string()
                    }
                })
                .collect();
            out.push(HttpVariantSpec {
                label: format!("query:alt:{field}"),
                method: method.to_string(),
                url: format!("{base}?{}", alt_qs.join("&")),
                headers: headers.to_vec(),
                body: body.map(str::to_string),
            });

            out.push(HttpVariantSpec {
                label: format!("query:dup:{field}"),
                method: method.to_string(),
                url: format!("{url}&{field}={alt}"),
                headers: headers.to_vec(),
                body: body.map(str::to_string),
            });
        }
    }

    // 3. Header variation if field matches an existing header (never duplicate Content-Length / Transfer-Encoding)
    let low_f = field.to_ascii_lowercase();
    if low_f != "content-length" && low_f != "transfer-encoding" {
        if let Some(idx) = headers.iter().position(|h| {
            h.split_once(':')
                .map(|(k, _)| k.trim().eq_ignore_ascii_case(field))
                .unwrap_or(false)
        }) {
            let mut dup_h = headers.to_vec();
            dup_h.push(format!("{field}: {alt}"));
            out.push(HttpVariantSpec {
                label: format!("header:dup:{field}"),
                method: method.to_string(),
                url: url.to_string(),
                headers: dup_h,
                body: body.map(str::to_string),
            });
            let mut omit_h = headers.to_vec();
            omit_h.remove(idx);
            out.push(HttpVariantSpec {
                label: format!("header:omit:{field}"),
                method: method.to_string(),
                url: url.to_string(),
                headers: omit_h,
                body: body.map(str::to_string),
            });
        }
    }

    out.truncate(max_variants.clamp(1, 100));
    out
}

#[allow(clippy::too_many_arguments)]
pub fn run_http_vary(
    req_file: Option<&std::path::Path>,
    url_opt: Option<&str>,
    method: &str,
    headers: &[String],
    body: Option<&str>,
    field: &str,
    alt_value: Option<&str>,
    rate_ms: u64,
    max_variants: usize,
    dry_run: bool,
    cdp_cookies_port: Option<u16>,
    timeout_sec: u64,
    insecure: bool,
    follow: bool,
    as_json: bool,
) -> i32 {
    let (m, u, mut hdrs, b) = if let Some(rf) = req_file {
        match load_saved_request(rf) {
            Ok(spec) => spec,
            Err(e) => {
                eprintln!("[probe http vary] {e}");
                return 2;
            }
        }
    } else if let Some(url) = url_opt.filter(|s| !s.trim().is_empty()) {
        (
            method.to_ascii_uppercase(),
            url.to_string(),
            Vec::new(),
            body.map(str::to_string),
        )
    } else {
        eprintln!("[probe http vary] Provide a URL or `--vary-request <file>`.");
        return 2;
    };
    hdrs.extend(headers.iter().cloned());
    if !dry_run {
        if let Some(port) = cdp_cookies_port {
            if !has_header_name(&hdrs, "cookie") {
                match resolve_cdp_cookie_header(port, &u) {
                    Ok((Some(ch), _)) => hdrs.push(ch),
                    Ok((None, _)) => {}
                    Err(e) => {
                        eprintln!("[probe http vary] cdp-cookies:{port}: {e}");
                        return 1;
                    }
                }
            }
        }
    }

    let variants =
        build_single_field_variants(&m, &u, &hdrs, b.as_deref(), field, alt_value, max_variants);
    if dry_run {
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "dry_run": true,
                    "field": field,
                    "count": variants.len(),
                    "variants": variants,
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "[probe http vary] DRY-RUN generated {} single-field variant(s) for `{field}`:",
                variants.len()
            );
            for (i, v) in variants.iter().enumerate() {
                println!(
                    "  {}. [{}] {} {} {}",
                    i + 1,
                    v.label,
                    v.method,
                    v.url,
                    v.body.as_deref().unwrap_or("")
                );
            }
        }
        return 0;
    }

    let mut rows = Vec::new();
    let mut buckets: std::collections::HashMap<(u16, String, usize), usize> =
        std::collections::HashMap::new();
    for (idx, v) in variants.iter().enumerate() {
        if idx > 0 && rate_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(rate_ms.min(5000)));
        }
        let r = execute_http_probe(
            &v.method,
            &v.url,
            &v.headers,
            v.body.as_deref(),
            timeout_sec,
            insecure,
            follow,
        );
        let words = r.body_preview.split_whitespace().count();
        let ct_base = r
            .content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let sig = (r.status, ct_base, words / 4);
        *buckets.entry(sig.clone()).or_insert(0) += 1;
        rows.push((v.label.clone(), r, words, sig));
    }

    let base_sig = rows.first().map(|r| r.3.clone());
    let mut outliers = Vec::new();
    let mut json_rows = Vec::new();
    for (label, r, words, sig) in &rows {
        let freq = buckets.get(sig).copied().unwrap_or(1);
        let is_outlier =
            base_sig.as_ref().map(|bs| bs != sig).unwrap_or(false) || freq == 1 && rows.len() > 2;
        if is_outlier && label != "baseline" {
            outliers.push(json!({
                "label": label,
                "status": r.status,
                "content_type": r.content_type,
                "words": words,
                "body_preview": r.body_preview.chars().take(300).collect::<String>(),
            }));
        }
        json_rows.push(json!({
            "label": label,
            "status": r.status,
            "elapsed_ms": r.elapsed_ms,
            "content_type": r.content_type,
            "words": words,
            "outlier": is_outlier && label != "baseline",
            "error": r.error,
            "body_preview": r.body_preview.chars().take(400).collect::<String>(),
        }));
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "field": field,
                "count": json_rows.len(),
                "outlier_count": outliers.len(),
                "outliers": outliers,
                "results": json_rows,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[probe http vary] `{field}`: {} variant(s), {} outlier(s):",
            rows.len(),
            outliers.len()
        );
        for (label, r, words, sig) in &rows {
            let mark =
                if base_sig.as_ref().map(|bs| bs != sig).unwrap_or(false) && label != "baseline" {
                    "*"
                } else {
                    " "
                };
            println!(
                " {mark} [{label}] HTTP {} | words={} | {} ({}ms)",
                r.status, words, r.content_type, r.elapsed_ms
            );
        }
    }
    0
}

/// Inspect HTTP response headers for generic web & two-phase download/storage security defense gaps.
pub fn audit_response_headers(
    url: &str,
    status: u16,
    content_type: &str,
    headers: &[String],
) -> Vec<String> {
    let mut findings = Vec::new();
    if status == 0 {
        return findings;
    }
    let mut hdr_map: Vec<(String, String)> = Vec::new();
    for h in headers {
        if let Some((k, v)) = h.split_once(':') {
            hdr_map.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let get_hdr = |name: &str| -> Option<&str> {
        hdr_map
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let ct_low = content_type.to_ascii_lowercase();
    let url_low = url.to_ascii_lowercase();

    let has_nosniff = get_hdr("x-content-type-options")
        .map(|v| v.to_ascii_lowercase().contains("nosniff"))
        .unwrap_or(false);
    if (200..300).contains(&status) && !has_nosniff {
        findings.push("missing X-Content-Type-Options: nosniff".to_string());
    }
    if let Some(cd) = get_hdr("content-disposition") {
        if cd.to_ascii_lowercase().contains("inline") {
            findings.push(format!("Content-Disposition inline ({cd})"));
        }
    } else if (200..300).contains(&status)
        && (url_low.contains("download")
            || url_low.contains("upload")
            || url_low.contains("preview")
            || url_low.contains("getobject")
            || url_low.contains("file"))
    {
        findings
            .push("download/storage endpoint missing Content-Disposition: attachment".to_string());
    }
    if (200..300).contains(&status)
        && (ct_low.contains("text/html") || ct_low.contains("image/svg+xml"))
        && get_hdr("content-security-policy").is_none()
    {
        findings.push(format!(
            "active content ({content_type}) missing Content-Security-Policy"
        ));
    }
    if (200..300).contains(&status) && url_low.contains("response-content-type=") {
        findings.push(format!(
            "2xx response accepted response-content-type override (served as `{content_type}`)"
        ));
    }
    if let Some(acao) = get_hdr("access-control-allow-origin") {
        let acac = get_hdr("access-control-allow-credentials")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if acac && (acao.trim() == "*" || acao.trim().eq_ignore_ascii_case("null")) {
            findings.push(format!(
                "permissive CORS Access-Control-Allow-Origin: {acao} with Allow-Credentials: true"
            ));
        }
    }
    for (k, v) in &hdr_map {
        if k == "set-cookie" {
            let vl = v.to_ascii_lowercase();
            let mut miss = Vec::new();
            if !vl.contains("httponly") {
                miss.push("HttpOnly");
            }
            if url_low.starts_with("https://") && !vl.contains("secure") {
                miss.push("Secure");
            }
            if !miss.is_empty() {
                let cname = v.split('=').next().unwrap_or("cookie").trim();
                findings.push(format!("Set-Cookie `{cname}` missing {}", miss.join("/")));
            }
        }
    }
    findings
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpDiffReport {
    pub verdict: String,
    pub possible_bypass: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_nonempty_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sentinel_hits: Vec<String>,
}

fn json_is_nonempty_leaf(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn flatten_json_paths(
    val: &Value,
    prefix: &str,
    depth: usize,
    out: &mut std::collections::BTreeMap<String, Value>,
) {
    if out.len() >= 256 || depth > 8 {
        return;
    }
    match val {
        Value::Object(map) => {
            if map.is_empty() && !prefix.is_empty() {
                out.insert(prefix.to_string(), Value::Object(serde_json::Map::new()));
                return;
            }
            for (k, v) in map {
                let next = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_json_paths(v, &next, depth + 1, out);
            }
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                if !prefix.is_empty() {
                    out.insert(prefix.to_string(), Value::Array(Vec::new()));
                }
                return;
            }
            for (idx, item) in arr.iter().take(16).enumerate() {
                let next = if prefix.is_empty() {
                    format!("[{idx}]")
                } else {
                    format!("{prefix}[{idx}]")
                };
                flatten_json_paths(item, &next, depth + 1, out);
            }
        }
        _ => {
            let key = if prefix.is_empty() { "$" } else { prefix };
            out.insert(key.to_string(), val.clone());
        }
    }
}

/// Produce a crisp diagnostic summary when an HTTP response body is empty or non-JSON (e.g. HTML error/login shell).
pub fn summarize_non_json_body(content_type: &str, body: &str) -> Option<String> {
    let trimmed = body.trim();
    if !trimmed.is_empty() && serde_json::from_str::<Value>(trimmed).is_ok() {
        return None;
    }
    let ct = if content_type.trim().is_empty() {
        "unknown"
    } else {
        content_type.trim()
    };
    if trimmed.is_empty() {
        return Some(format!("non-JSON empty body ({ct})"));
    }
    let low = trimmed.to_ascii_lowercase();
    let html_title = if let Some(s) = low.find("<title") {
        let rest_orig = &trimmed[s..];
        let rest_low = &low[s..];
        rest_low.find('>').and_then(|gt| {
            let after_gt = gt + 1;
            rest_low[after_gt..].find("</title>").map(|end| {
                rest_orig[after_gt..after_gt + end]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .chars()
                    .take(80)
                    .collect::<String>()
            })
        })
    } else {
        None
    };
    let preview: String = trimmed
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(140)
        .collect();
    if let Some(title) = html_title.filter(|t| !t.is_empty()) {
        Some(format!("non-JSON ({ct}): title=\"{title}\" | {preview}"))
    } else {
        Some(format!("non-JSON ({ct}): {preview}"))
    }
}

/// Deep structural diff oracle comparing an unprivileged/cross-tenant candidate HTTP response against
/// a privileged baseline, with recursive JSON path diffing, sentinel leak checks, and HTML/non-JSON summaries.
pub fn classify_auth_matrix_diff_deep(
    base: &HttpProbeResult,
    cand: &HttpProbeResult,
    sentinels: &[String],
) -> HttpDiffReport {
    classify_auth_matrix_diff_deep_bodies(
        base,
        &base.body_preview,
        cand,
        &cand.body_preview,
        sentinels,
    )
}

pub(crate) fn classify_auth_matrix_diff_deep_bodies(
    base: &HttpProbeResult,
    base_raw: &str,
    cand: &HttpProbeResult,
    cand_raw: &str,
    sentinels: &[String],
) -> HttpDiffReport {
    if cand.status == 0 || !cand.error.is_empty() {
        return HttpDiffReport {
            verdict: "TRANSPORT_ERROR".to_string(),
            possible_bypass: false,
            reason: format!("transport error: {}", cand.error),
            shared_nonempty_paths: Vec::new(),
            added_paths: Vec::new(),
            removed_paths: Vec::new(),
            changed_paths: Vec::new(),
            sentinel_hits: Vec::new(),
        };
    }

    let sentinel_hits: Vec<String> = sentinels
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && cand_raw.contains(*s))
        .map(str::to_string)
        .collect();

    let mut base_paths = std::collections::BTreeMap::new();
    let mut cand_paths = std::collections::BTreeMap::new();
    let base_json = serde_json::from_str::<Value>(base_raw.trim()).ok();
    let cand_json = serde_json::from_str::<Value>(cand_raw.trim()).ok();
    if let Some(ref bv) = base_json {
        flatten_json_paths(bv, "", 0, &mut base_paths);
    }
    if let Some(ref cv) = cand_json {
        flatten_json_paths(cv, "", 0, &mut cand_paths);
    }

    let mut shared_nonempty_paths = Vec::new();
    let mut added_paths = Vec::new();
    let mut removed_paths = Vec::new();
    let mut changed_paths = Vec::new();
    if !base_paths.is_empty() && !cand_paths.is_empty() {
        for (k, bv) in &base_paths {
            match cand_paths.get(k) {
                Some(cv) => {
                    if json_is_nonempty_leaf(bv) && json_is_nonempty_leaf(cv) {
                        shared_nonempty_paths.push(k.clone());
                    }
                    if bv != cv {
                        changed_paths.push(k.clone());
                    }
                }
                None => removed_paths.push(k.clone()),
            }
        }
        for k in cand_paths.keys() {
            if !base_paths.contains_key(k) {
                added_paths.push(k.clone());
            }
        }
        shared_nonempty_paths.truncate(24);
        added_paths.truncate(24);
        removed_paths.truncate(24);
        changed_paths.truncate(24);
    }

    if !sentinel_hits.is_empty() {
        return HttpDiffReport {
            verdict: "SENTINEL_LEAK".to_string(),
            possible_bypass: true,
            reason: format!(
                "HTTP {} leaked sentinel(s): [{}]",
                cand.status,
                sentinel_hits.join(", ")
            ),
            shared_nonempty_paths,
            added_paths,
            removed_paths,
            changed_paths,
            sentinel_hits,
        };
    }

    if !(200..300).contains(&cand.status) {
        let verdict = if matches!(cand.status, 401 | 403) {
            "AUTH_DENIED_401_403"
        } else {
            "REJECTED_4XX_5XX"
        };
        let extra = summarize_non_json_body(&cand.content_type, &cand.body_preview)
            .map(|d| format!(" ({d})"))
            .unwrap_or_default();
        return HttpDiffReport {
            verdict: verdict.to_string(),
            possible_bypass: false,
            reason: format!("rejected with HTTP {}{}", cand.status, extra),
            shared_nonempty_paths,
            added_paths,
            removed_paths,
            changed_paths,
            sentinel_hits,
        };
    }

    let low_body = cand.body_preview.to_ascii_lowercase();
    for deny_kw in [
        "unauthorized",
        "forbidden",
        "access denied",
        "permission denied",
        "not allowed",
        "invalid token",
        "login required",
        "\"code\":401",
        "\"code\":403",
        "\"status\":403",
    ] {
        if low_body.contains(deny_kw) {
            return HttpDiffReport {
                verdict: "PSEUDO_DENIAL_200".to_string(),
                possible_bypass: false,
                reason: format!(
                    "HTTP {} but body contains auth denial marker `{deny_kw}`",
                    cand.status
                ),
                shared_nonempty_paths,
                added_paths,
                removed_paths,
                changed_paths,
                sentinel_hits,
            };
        }
    }

    if !base_paths.is_empty() && !cand_paths.is_empty() {
        let base_nonempty_cnt = base_paths
            .values()
            .filter(|v| json_is_nonempty_leaf(v))
            .count()
            .max(1);
        let shared = shared_nonempty_paths.len();
        let overlap = (shared * 100) / base_nonempty_cnt;
        if overlap >= 50 && cand.body_preview.len() >= 16 {
            return HttpDiffReport {
                verdict: "LIKELY_BYPASS".to_string(),
                possible_bypass: true,
                reason: format!(
                    "HTTP {} with {overlap}% deep JSON path overlap ({shared}/{base_nonempty_cnt}), {} changed, {} removed",
                    cand.status,
                    changed_paths.len(),
                    removed_paths.len(),
                ),
                shared_nonempty_paths,
                added_paths,
                removed_paths,
                changed_paths,
                sentinel_hits,
            };
        }
        return HttpDiffReport {
            verdict: "IDENTICAL_OR_SUBSET".to_string(),
            possible_bypass: false,
            reason: format!(
                "HTTP {} with low deep JSON overlap ({shared}/{base_nonempty_cnt}, {} removed, {} added)",
                cand.status,
                removed_paths.len(),
                added_paths.len(),
            ),
            shared_nonempty_paths,
            added_paths,
            removed_paths,
            changed_paths,
            sentinel_hits,
        };
    }

    let base_len = base.body_preview.len();
    let cand_len = cand.body_preview.len();
    if (200..300).contains(&base.status) && base_len >= 16 && cand_len * 100 >= base_len * 40 {
        let extra = summarize_non_json_body(&cand.content_type, &cand.body_preview)
            .map(|d| format!(" [{d}]"))
            .unwrap_or_default();
        return HttpDiffReport {
            verdict: "LIKELY_BYPASS".to_string(),
            possible_bypass: true,
            reason: format!(
                "HTTP {} with non-denied {}B payload ({}% of baseline {}B){}",
                cand.status,
                cand_len,
                (cand_len * 100) / base_len.max(1),
                base_len,
                extra
            ),
            shared_nonempty_paths,
            added_paths,
            removed_paths,
            changed_paths,
            sentinel_hits,
        };
    }
    let verdict = if base_json.is_none() || cand_json.is_none() {
        "NON_JSON_BODY"
    } else {
        "IDENTICAL_OR_SUBSET"
    };
    let extra = summarize_non_json_body(&cand.content_type, &cand.body_preview)
        .map(|d| format!(" [{d}]"))
        .unwrap_or_default();
    HttpDiffReport {
        verdict: verdict.to_string(),
        possible_bypass: false,
        reason: format!(
            "HTTP {} with divergent/minimal payload ({cand_len}B vs baseline {base_len}B){}",
            cand.status, extra
        ),
        shared_nonempty_paths,
        added_paths,
        removed_paths,
        changed_paths,
        sentinel_hits,
    }
}

/// Compare an unprivileged/cross-tenant candidate HTTP response against a privileged owner baseline.
/// Returns `(possible_bypass, reason)`.
pub fn classify_auth_matrix_diff(base: &HttpProbeResult, cand: &HttpProbeResult) -> (bool, String) {
    let rep = classify_auth_matrix_diff_deep(base, cand, &[]);
    (rep.possible_bypass, rep.reason)
}

fn parse_principal_spec(raw: &str) -> (String, Vec<String>) {
    let (name, rest) = match raw.split_once('=') {
        Some((n, r)) => (n.trim().to_string(), r.trim()),
        None => (raw.trim().to_string(), ""),
    };
    let label = if name.is_empty() {
        "principal".to_string()
    } else {
        name
    };
    let hdrs: Vec<String> = rest
        .split(";;")
        .map(str::trim)
        .filter(|s| s.contains(':'))
        .map(str::to_string)
        .collect();
    (label, hdrs)
}

fn merge_principal_headers(
    base_headers: &[String],
    principal_headers: &[String],
    strip_auth: bool,
) -> Vec<String> {
    let override_keys: Vec<String> = principal_headers
        .iter()
        .filter_map(|h| {
            h.split_once(':')
                .map(|(k, _)| k.trim().to_ascii_lowercase())
        })
        .collect();
    let mut merged: Vec<String> = base_headers
        .iter()
        .filter(|h| {
            let k = h
                .split_once(':')
                .map(|(k, _)| k.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if override_keys.contains(&k) {
                return false;
            }
            if strip_auth
                && matches!(
                    k.as_str(),
                    "authorization" | "cookie" | "x-auth-token" | "x-api-key"
                )
            {
                return false;
            }
            true
        })
        .cloned()
        .collect();
    merged.extend(principal_headers.iter().cloned());
    merged
}

struct ResolvedPrincipal {
    label: String,
    headers: Vec<String>,
    cookie_count: Option<usize>,
    resolve_err: Option<String>,
}

struct AuthMatrixRow {
    label: String,
    result: HttpProbeResult,
    raw_body: String,
    gaps: Vec<String>,
    cookie_count: Option<usize>,
    selected: Option<Value>,
}

#[allow(clippy::too_many_arguments)]
pub fn run_http_auth_matrix(
    req_file: Option<&std::path::Path>,
    url_opt: Option<&str>,
    method: &str,
    headers: &[String],
    body: Option<&str>,
    principals: &[String],
    principal_cdps: &[String],
    cors_origin: Option<&str>,
    select_expr: Option<&str>,
    audit_headers: bool,
    sentinels: &[String],
    timeout_sec: u64,
    insecure: bool,
    follow: bool,
    as_json: bool,
) -> i32 {
    let (m, u, mut base_hdrs, b) = if let Some(rf) = req_file {
        match load_saved_request(rf) {
            Ok(spec) => spec,
            Err(e) => {
                eprintln!("[probe http auth-matrix] {e}");
                return 2;
            }
        }
    } else if let Some(url) = url_opt.filter(|s| !s.trim().is_empty()) {
        (
            method.to_ascii_uppercase(),
            url.to_string(),
            Vec::new(),
            body.map(str::to_string),
        )
    } else {
        eprintln!("[probe http auth-matrix] Provide a URL or `--vary-request <file>`.");
        return 2;
    };
    base_hdrs.extend(headers.iter().cloned());
    let cors_orig_clean = cors_origin.map(str::trim).filter(|s| !s.is_empty());
    let select_clean = select_expr.map(str::trim).filter(|s| !s.is_empty());
    if let Some(orig) = cors_orig_clean {
        if !has_header_name(&base_hdrs, "origin") {
            base_hdrs.push(format!("Origin: {orig}"));
        }
    }

    let mut resolved: Vec<ResolvedPrincipal> = Vec::new();
    for raw_cdp in principal_cdps {
        match parse_principal_cdp_spec(raw_cdp) {
            Ok((label, port)) => match resolve_cdp_cookie_header(port, &u) {
                Ok((Some(ch), cnt)) => resolved.push(ResolvedPrincipal {
                    label,
                    headers: vec![ch],
                    cookie_count: Some(cnt),
                    resolve_err: None,
                }),
                Ok((None, cnt)) => resolved.push(ResolvedPrincipal {
                    label,
                    headers: Vec::new(),
                    cookie_count: Some(cnt),
                    resolve_err: None,
                }),
                Err(e) => resolved.push(ResolvedPrincipal {
                    label,
                    headers: Vec::new(),
                    cookie_count: Some(0),
                    resolve_err: Some(format!("cdp:{port}: {e}")),
                }),
            },
            Err(e) => {
                eprintln!("[probe http auth-matrix] {e}");
                return 2;
            }
        }
    }
    for p in principals {
        let (label, phdrs) = parse_principal_spec(p);
        resolved.push(ResolvedPrincipal {
            label,
            headers: phdrs,
            cookie_count: None,
            resolve_err: None,
        });
    }

    let do_audit = audit_headers || cors_orig_clean.is_some();
    let mut rows: Vec<AuthMatrixRow> = Vec::new();
    for spec in &resolved {
        if let Some(ref err_msg) = spec.resolve_err {
            rows.push(AuthMatrixRow {
                label: spec.label.clone(),
                result: HttpProbeResult {
                    method: m.clone(),
                    url: u.clone(),
                    status: 0,
                    elapsed_ms: 0.0,
                    content_type: String::new(),
                    headers: Vec::new(),
                    body_preview: String::new(),
                    error: err_msg.clone(),
                },
                raw_body: String::new(),
                gaps: Vec::new(),
                cookie_count: spec.cookie_count,
                selected: None,
            });
            continue;
        }
        let strip_auth = spec.headers.is_empty();
        let req_hdrs = merge_principal_headers(&base_hdrs, &spec.headers, strip_auth);
        let (res, raw_b) = execute_http_probe_with_raw(
            &m,
            &u,
            &req_hdrs,
            b.as_deref(),
            timeout_sec,
            insecure,
            follow,
        );
        let mut gaps = if audit_headers {
            audit_response_headers(&res.url, res.status, &res.content_type, &res.headers)
        } else {
            Vec::new()
        };
        if let Some(orig) = cors_orig_clean {
            gaps.extend(audit_cors_reflection(orig, &res.headers));
        }
        let sel_val = select_clean.and_then(|expr| extract_json_select(&raw_b, expr));
        rows.push(AuthMatrixRow {
            label: spec.label.clone(),
            result: res,
            raw_body: raw_b,
            gaps,
            cookie_count: spec.cookie_count,
            selected: sel_val,
        });
    }

    let baseline = rows
        .first()
        .map(|row| (row.result.clone(), row.raw_body.clone()));
    let mut bypasses = Vec::new();
    let mut json_rows = Vec::new();
    for (idx, row) in rows.iter().enumerate() {
        let label = &row.label;
        let r = &row.result;
        let gaps = &row.gaps;
        let cookie_cnt = row.cookie_count;
        let sel_val = &row.selected;
        let diff_rep = if idx == 0 {
            HttpDiffReport {
                verdict: "BASELINE".to_string(),
                possible_bypass: false,
                reason: "baseline principal".to_string(),
                shared_nonempty_paths: Vec::new(),
                added_paths: Vec::new(),
                removed_paths: Vec::new(),
                changed_paths: Vec::new(),
                sentinel_hits: Vec::new(),
            }
        } else if let Some((ref base, ref base_raw)) = baseline {
            classify_auth_matrix_diff_deep_bodies(base, base_raw, r, &row.raw_body, sentinels)
        } else {
            HttpDiffReport {
                verdict: "NO_BASELINE".to_string(),
                possible_bypass: false,
                reason: "no baseline".to_string(),
                shared_nonempty_paths: Vec::new(),
                added_paths: Vec::new(),
                removed_paths: Vec::new(),
                changed_paths: Vec::new(),
                sentinel_hits: Vec::new(),
            }
        };
        if diff_rep.possible_bypass {
            bypasses.push(json!({
                "principal": label,
                "status": r.status,
                "verdict": diff_rep.verdict,
                "reason": diff_rep.reason,
                "sentinel_hits": diff_rep.sentinel_hits,
                "shared_nonempty_paths": diff_rep.shared_nonempty_paths,
                "body_preview": r.body_preview.chars().take(240).collect::<String>(),
            }));
        }
        let mut row_obj = json!({
            "principal": label,
            "status": r.status,
            "elapsed_ms": r.elapsed_ms,
            "content_type": r.content_type,
            "body_len": r.body_preview.len(),
            "verdict": diff_rep.verdict,
            "possible_bypass": diff_rep.possible_bypass,
            "diff_reason": diff_rep.reason,
            "diff": diff_rep,
            "header_findings": gaps,
            "error": r.error,
            "body_preview": r.body_preview.chars().take(360).collect::<String>(),
        });
        if let Some(map) = row_obj.as_object_mut() {
            if let Some(cc) = cookie_cnt {
                map.insert("cdp_cookie_count".to_string(), json!(cc));
            }
            if select_clean.is_some() {
                map.insert(
                    "selected".to_string(),
                    sel_val.clone().unwrap_or(Value::Null),
                );
            }
        }
        json_rows.push(row_obj);
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "method": m,
                "url": u,
                "cors_origin": cors_orig_clean,
                "principal_count": rows.len(),
                "possible_bypass_count": bypasses.len(),
                "possible_bypasses": bypasses,
                "results": json_rows,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[probe http auth-matrix] {} {} — {} principal(s), {} possible bypass(es):",
            m,
            u,
            rows.len(),
            bypasses.len()
        );
        for item in &json_rows {
            let flag = if item["possible_bypass"].as_bool().unwrap_or(false) {
                "[POSSIBLE-AUTHZ-BYPASS]"
            } else {
                "[ok]"
            };
            let gap_str = if do_audit {
                let n = item["header_findings"]
                    .as_array()
                    .map(|a| a.len())
                    .unwrap_or(0);
                if n > 0 {
                    format!(" [gaps={n}]")
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            println!(
                "  - {:<14} HTTP {} ({}B) {}{} — {}",
                item["principal"].as_str().unwrap_or("?"),
                item["status"].as_u64().unwrap_or(0),
                item["body_len"].as_u64().unwrap_or(0),
                flag,
                gap_str,
                item["diff_reason"].as_str().unwrap_or("")
            );
        }
    }
    0
}

fn fnv1a_hash_str(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn parse_plain_http_target(url: &str) -> Option<(SocketAddr, String, String)> {
    let rest = url.strip_prefix("http://")?;
    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let connect_target = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };
    let sa = connect_target
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())?;
    Some((sa, host_port.to_string(), path.to_string()))
}

fn build_raw_http11_request(
    method: &str,
    host_port: &str,
    path: &str,
    headers: &[String],
    body: Option<&str>,
) -> Vec<u8> {
    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    if !has_header_name(headers, "host") {
        req.push_str(&format!("Host: {host_port}\r\n"));
    }
    if !has_header_name(headers, "connection") {
        req.push_str("Connection: close\r\n");
    }
    for h in headers {
        let t = h.trim();
        if !t.is_empty() {
            req.push_str(t);
            req.push_str("\r\n");
        }
    }
    if let Some(b) = body {
        if !has_header_name(headers, "content-length") {
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        if !has_header_name(headers, "content-type") && b.trim_start().starts_with('{') {
            req.push_str("Content-Type: application/json\r\n");
        }
        req.push_str("\r\n");
        req.push_str(b);
    } else {
        req.push_str("\r\n");
    }
    req.into_bytes()
}

fn parse_http_wire_response(
    method: &str,
    url: &str,
    raw_bytes: &[u8],
    elapsed_ms: f64,
) -> (HttpProbeResult, String) {
    let raw = String::from_utf8_lossy(raw_bytes).to_string();
    let mut rest = raw.as_str();
    let mut hdr_block = "";
    while rest.starts_with("HTTP/") {
        if let Some(idx) = rest.find("\r\n\r\n") {
            hdr_block = &rest[..idx];
            rest = &rest[idx + 4..];
        } else if let Some(idx) = rest.find("\n\n") {
            hdr_block = &rest[..idx];
            rest = &rest[idx + 2..];
        } else {
            break;
        }
    }
    let body_raw = rest;
    let mut status = 0u16;
    let mut ct = String::new();
    let mut hdrs = Vec::new();
    for (idx, ln) in hdr_block.lines().enumerate() {
        let t = ln.trim();
        if idx == 0 {
            status = t
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
        } else if !t.is_empty() {
            if let Some((k, v)) = t.split_once(':') {
                if k.eq_ignore_ascii_case("content-type") {
                    ct = v.trim().to_string();
                }
            }
            if hdrs.len() < 24 {
                hdrs.push(t.to_string());
            }
        }
    }
    let preview: String = if body_raw.len() > 2400 {
        format!(
            "{}...\n[truncated: {}B total]",
            body_raw.chars().take(2400).collect::<String>(),
            body_raw.len()
        )
    } else {
        body_raw.to_string()
    };
    (
        HttpProbeResult {
            method: method.to_string(),
            url: url.to_string(),
            status,
            elapsed_ms,
            content_type: ct,
            headers: hdrs,
            body_preview: preview,
            error: String::new(),
        },
        body_raw.to_string(),
    )
}

/// Synchronized Barrier HTTP Race / TOCTOU concurrency burst (`--race N`, 2..=32 threads firing simultaneously).
/// Uses low-jitter raw TCP pre-connect + synchronized `write_all` barrier for plain `http://` targets when `!follow`,
/// falling back to `curl` for `https://` or redirects, plus body clustering, `--select` uniqueness & latency spread.
#[allow(clippy::too_many_arguments)]
pub fn run_http_race(
    req_file: Option<&std::path::Path>,
    url_opt: Option<&str>,
    method: &str,
    headers: &[String],
    body: Option<&str>,
    race_n: usize,
    cdp_cookies_port: Option<u16>,
    select_expr: Option<&str>,
    timeout_sec: u64,
    insecure: bool,
    follow: bool,
    as_json: bool,
) -> i32 {
    let (m, u, mut hdrs, b) = if let Some(rf) = req_file {
        match load_saved_request(rf) {
            Ok(spec) => spec,
            Err(e) => {
                eprintln!("[probe http race] {e}");
                return 2;
            }
        }
    } else if let Some(url) = url_opt.filter(|s| !s.trim().is_empty()) {
        (
            method.to_ascii_uppercase(),
            url.to_string(),
            Vec::new(),
            body.map(str::to_string),
        )
    } else {
        eprintln!("[probe http race] Provide a URL or `--vary-request <file>`.");
        return 2;
    };
    hdrs.extend(headers.iter().cloned());
    if let Some(port) = cdp_cookies_port {
        if !has_header_name(&hdrs, "cookie") {
            match resolve_cdp_cookie_header(port, &u) {
                Ok((Some(ch), _)) => hdrs.push(ch),
                Ok((None, _)) => {}
                Err(e) => {
                    eprintln!("[probe http race] cdp-cookies:{port}: {e}");
                    return 1;
                }
            }
        }
    }

    let n = race_n.clamp(2, 32);
    let raw_target = if !follow {
        parse_plain_http_target(&u)
    } else {
        None
    };
    let transport_mode = if raw_target.is_some() {
        "tcp_barrier"
    } else {
        "curl_barrier"
    };
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    if let Some((sa, host_port, path)) = raw_target {
        let req_bytes = std::sync::Arc::new(build_raw_http11_request(
            &m,
            &host_port,
            &path,
            &hdrs,
            b.as_deref(),
        ));
        for idx in 0..n {
            let bar = std::sync::Arc::clone(&barrier);
            let req_c = std::sync::Arc::clone(&req_bytes);
            let m_c = m.clone();
            let u_c = u.clone();
            handles.push(std::thread::spawn(move || {
                let to = Duration::from_secs(timeout_sec.clamp(1, 30));
                let mut stream_opt = TcpStream::connect_timeout(&sa, to).ok();
                if let Some(ref s) = stream_opt {
                    let _ = s.set_read_timeout(Some(to));
                    let _ = s.set_write_timeout(Some(to));
                    let _ = s.set_nodelay(true);
                }
                bar.wait();
                let t0 = Instant::now();
                let pair = match stream_opt.as_mut() {
                    Some(s) => {
                        if let Err(e) = s.write_all(&req_c) {
                            (
                                HttpProbeResult {
                                    method: m_c,
                                    url: u_c,
                                    status: 0,
                                    elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0).round(),
                                    content_type: String::new(),
                                    headers: Vec::new(),
                                    body_preview: String::new(),
                                    error: format!("write failed: {e}"),
                                },
                                String::new(),
                            )
                        } else {
                            let mut buf = Vec::new();
                            let _ = s.take(262_144).read_to_end(&mut buf);
                            let el = (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
                            parse_http_wire_response(&m_c, &u_c, &buf, el)
                        }
                    }
                    None => (
                        HttpProbeResult {
                            method: m_c,
                            url: u_c,
                            status: 0,
                            elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0).round(),
                            content_type: String::new(),
                            headers: Vec::new(),
                            body_preview: String::new(),
                            error: format!("connect timeout/refused: {sa}"),
                        },
                        String::new(),
                    ),
                };
                (idx, pair.0, pair.1)
            }));
        }
    } else {
        for idx in 0..n {
            let bar = std::sync::Arc::clone(&barrier);
            let m_c = m.clone();
            let u_c = u.clone();
            let h_c = hdrs.clone();
            let b_c = b.clone();
            handles.push(std::thread::spawn(move || {
                bar.wait();
                let (res, raw_b) = execute_http_probe_with_raw(
                    &m_c,
                    &u_c,
                    &h_c,
                    b_c.as_deref(),
                    timeout_sec,
                    insecure,
                    follow,
                );
                (idx, res, raw_b)
            }));
        }
    }

    let mut results = Vec::with_capacity(n);
    for h in handles {
        if let Ok(triple) = h.join() {
            results.push(triple);
        }
    }
    results.sort_by_key(|(i, _, _)| *i);

    let mut status_counts: BTreeMap<u16, usize> = BTreeMap::new();
    let mut body_clusters: BTreeMap<String, usize> = BTreeMap::new();
    let mut selected_set: BTreeSet<String> = BTreeSet::new();
    let mut latencies: Vec<f64> = Vec::with_capacity(results.len());
    let mut ok_2xx = 0usize;
    let mut err_5xx = 0usize;
    let sel_clean = select_expr.map(str::trim).filter(|s| !s.is_empty());

    for (_, r, raw_b) in &results {
        *status_counts.entry(r.status).or_insert(0) += 1;
        if (200..300).contains(&r.status) {
            ok_2xx += 1;
        } else if r.status >= 500 {
            err_5xx += 1;
        }
        let bkey = format!("{:016x}", fnv1a_hash_str(raw_b.trim()));
        *body_clusters.entry(bkey).or_insert(0) += 1;
        latencies.push(r.elapsed_ms);
        if let Some(sel) = sel_clean {
            if let Some(val) = extract_json_select(raw_b, sel) {
                selected_set.insert(val.to_string());
            }
        }
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let lat_min = latencies.first().copied().unwrap_or(0.0);
    let lat_max = latencies.last().copied().unwrap_or(0.0);
    let lat_p50 = latencies.get(latencies.len() / 2).copied().unwrap_or(0.0);
    let lat_spread = ((lat_max - lat_min) * 10.0).round() / 10.0;

    let unique_body_count = body_clusters.len();
    let is_mutating = matches!(m.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
    let mixed_statuses = status_counts.len() > 1;
    let distinct_selected_count = selected_set.len();
    let race_anomaly = (is_mutating && ok_2xx >= 2)
        || (mixed_statuses && ok_2xx >= 1)
        || err_5xx >= 1
        || (sel_clean.is_some() && ok_2xx >= 2 && distinct_selected_count < ok_2xx);

    if as_json {
        let rows: Vec<Value> = results
            .iter()
            .map(|(idx, r, raw_b)| {
                let sel_val = sel_clean.and_then(|s| extract_json_select(raw_b, s));
                json!({
                    "thread": idx,
                    "status": r.status,
                    "elapsed_ms": r.elapsed_ms,
                    "body_len": raw_b.len(),
                    "body_hash": format!("{:016x}", fnv1a_hash_str(raw_b.trim())),
                    "selected": sel_val,
                    "error": r.error,
                    "body_preview": r.body_preview.chars().take(240).collect::<String>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "method": m,
                "url": u,
                "transport": transport_mode,
                "threads": n,
                "ok_2xx": ok_2xx,
                "err_5xx": err_5xx,
                "unique_body_count": unique_body_count,
                "distinct_selected_count": distinct_selected_count,
                "distinct_selected": selected_set.iter().take(16).collect::<Vec<_>>(),
                "latency_ms": {
                    "min": lat_min,
                    "p50": lat_p50,
                    "max": lat_max,
                    "spread": lat_spread,
                },
                "status_histogram": status_counts,
                "race_anomaly": race_anomaly,
                "results": rows,
            }))
            .unwrap_or_default()
        );
    } else {
        let badge = if race_anomaly {
            "[RACE-ANOMALY]"
        } else {
            "[UNIFORM]"
        };
        println!(
            "[probe http race] {} {} x{n} ({transport_mode}) {badge} | 2xx={ok_2xx} 5xx={err_5xx} bodies={unique_body_count} spread={lat_spread}ms hist={:?}",
            m, u, status_counts
        );
        for (idx, r, _) in results.iter().take(12) {
            let prev: String = r
                .body_preview
                .replace(['\r', '\n'], " ")
                .chars()
                .take(100)
                .collect();
            println!(
                "  #{:02} HTTP {} ({}ms | {}B) — `{prev}`",
                idx + 1,
                r.status,
                r.elapsed_ms,
                r.body_preview.len()
            );
        }
    }
    0
}

#[derive(Debug, Clone, Deserialize)]
struct FlowStepSpec {
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_get")]
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    cdp_cookies: Option<u16>,
    #[serde(default)]
    extract: HashMap<String, String>,
    #[serde(default)]
    expect_status: Option<u16>,
    #[serde(default)]
    sentinels: Vec<String>,
    #[serde(default)]
    compare_step: Option<usize>,
}

fn default_get() -> String {
    "GET".to_string()
}

fn substitute_flow_vars(tmpl: &str, vars: &HashMap<String, String>) -> String {
    let mut out = tmpl.to_string();
    for (k, v) in vars {
        let needle = format!("{{{{{k}}}}}");
        if out.contains(&needle) {
            out = out.replace(&needle, v);
        }
    }
    out
}

fn extract_flow_value(res: &HttpProbeResult, raw_body: &str, expr: &str) -> Option<String> {
    let e = expr.trim();
    if e.eq_ignore_ascii_case("status") {
        return Some(res.status.to_string());
    }
    if let Some(hname) = e.strip_prefix("header:") {
        let target = hname.trim();
        for h in &res.headers {
            if let Some((k, v)) = h.split_once(':') {
                if k.trim().eq_ignore_ascii_case(target) {
                    return Some(v.trim().to_string());
                }
            }
        }
        return None;
    }
    extract_json_select(raw_body, e).map(|v| match v {
        Value::String(s) => s,
        other => other.to_string(),
    })
}

/// Ordered stateful multi-step HTTP runner (`--flow <path_or_dash>`) supporting `{{var}}`
/// propagation, per-step `cdp_cookies`, sentinel checks, and cross-step differential comparison.
pub fn run_http_flow(
    flow_spec: &str,
    base_headers: &[String],
    global_sentinels: &[String],
    timeout_sec: u64,
    insecure: bool,
    follow: bool,
    as_json: bool,
) -> i32 {
    let raw_txt = if flow_spec.trim() == "-" {
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_err() {
            eprintln!("[probe http flow] failed reading stdin");
            return 2;
        }
        buf
    } else {
        match std::fs::read_to_string(flow_spec) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[probe http flow] failed reading `{flow_spec}`: {e}");
                return 2;
            }
        }
    };
    let parsed: Value = match serde_json::from_str(raw_txt.trim()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[probe http flow] invalid JSON flow spec: {e}");
            return 2;
        }
    };

    let mut vars: HashMap<String, String> = HashMap::new();
    let mut flow_sentinels: Vec<String> = global_sentinels.to_vec();
    let steps_val = if parsed.is_array() {
        parsed
    } else {
        if let Some(vmap) = parsed.get("vars").and_then(Value::as_object) {
            for (k, v) in vmap {
                let s = match v {
                    Value::String(st) => st.clone(),
                    other => other.to_string(),
                };
                vars.insert(k.clone(), s);
            }
        }
        if let Some(sarr) = parsed.get("sentinels").and_then(Value::as_array) {
            for s in sarr.iter().filter_map(Value::as_str) {
                flow_sentinels.push(s.to_string());
            }
        }
        parsed.get("steps").cloned().unwrap_or(Value::Null)
    };
    let steps: Vec<FlowStepSpec> = match serde_json::from_value(steps_val) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[probe http flow] invalid steps schema: {e}");
            return 2;
        }
    };
    if steps.is_empty() {
        eprintln!("[probe http flow] flow contains 0 steps");
        return 2;
    }

    let mut step_results: Vec<HttpProbeResult> = Vec::with_capacity(steps.len());
    let mut step_raw_bodies: Vec<String> = Vec::with_capacity(steps.len());
    let mut json_steps: Vec<Value> = Vec::with_capacity(steps.len());
    let mut failed_count = 0usize;
    let mut sentinel_leak_count = 0usize;

    for (idx, step) in steps.iter().enumerate() {
        let label = step
            .name
            .clone()
            .unwrap_or_else(|| format!("step_{}", idx + 1));
        let m = step.method.to_ascii_uppercase();
        let u = substitute_flow_vars(&step.url, &vars);
        let mut hdrs: Vec<String> = base_headers
            .iter()
            .map(|h| substitute_flow_vars(h, &vars))
            .collect();
        hdrs.extend(step.headers.iter().map(|h| substitute_flow_vars(h, &vars)));
        let body_sub = step.body.as_deref().map(|b| substitute_flow_vars(b, &vars));

        if let Some(port) = step.cdp_cookies {
            if !has_header_name(&hdrs, "cookie") {
                if let Ok((Some(ch), _)) = resolve_cdp_cookie_header(port, &u) {
                    hdrs.push(ch);
                }
            }
        }

        let (res, raw_b) = execute_http_probe_with_raw(
            &m,
            &u,
            &hdrs,
            body_sub.as_deref(),
            timeout_sec,
            insecure,
            follow,
        );

        let mut extracted_here = serde_json::Map::new();
        for (k, expr) in &step.extract {
            if let Some(val) = extract_flow_value(&res, &raw_b, expr) {
                vars.insert(k.clone(), val.clone());
                extracted_here.insert(k.clone(), Value::String(val));
            }
        }

        let mut step_sents = flow_sentinels.clone();
        step_sents.extend(step.sentinels.iter().cloned());
        let sentinel_hits: Vec<String> = step_sents
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && raw_b.contains(*s))
            .map(str::to_string)
            .collect();
        if !sentinel_hits.is_empty() {
            sentinel_leak_count += 1;
        }

        let expectation_ok = step
            .expect_status
            .map(|exp| res.status == exp)
            .unwrap_or_else(|| res.error.is_empty() && res.status != 0);
        if !expectation_ok {
            failed_count += 1;
        }

        let diff_rep = step
            .compare_step
            .and_then(|base_i| step_results.get(base_i).zip(step_raw_bodies.get(base_i)))
            .map(|(base_res, base_raw)| {
                classify_auth_matrix_diff_deep_bodies(base_res, base_raw, &res, &raw_b, &step_sents)
            });

        let non_json = summarize_non_json_body(&res.content_type, &res.body_preview);
        let mut obj = json!({
            "step": idx,
            "name": label,
            "method": res.method,
            "url": res.url,
            "status": res.status,
            "elapsed_ms": res.elapsed_ms,
            "expectation_ok": expectation_ok,
            "extracted": extracted_here,
            "sentinel_hits": sentinel_hits,
            "error": res.error,
            "body_preview": res.body_preview.chars().take(360).collect::<String>(),
        });
        if let Some(map) = obj.as_object_mut() {
            if let Some(ref d) = diff_rep {
                map.insert("diff".to_string(), json!(d));
            }
            if let Some(ref nj) = non_json {
                map.insert("body_diagnostic".to_string(), json!(nj));
            }
        }
        step_results.push(res);
        step_raw_bodies.push(raw_b);
        json_steps.push(obj);
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": failed_count == 0,
                "step_count": steps.len(),
                "failed_steps": failed_count,
                "sentinel_leak_steps": sentinel_leak_count,
                "vars": vars,
                "steps": json_steps,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[probe http flow] {} step(s), failed={failed_count}, sentinel_leaks={sentinel_leak_count}:",
            steps.len()
        );
        for s in &json_steps {
            println!(
                "  #{}. {} {} {} -> HTTP {} ({}ms) [ok={}]",
                s["step"].as_u64().unwrap_or(0) + 1,
                s["name"].as_str().unwrap_or("?"),
                s["method"].as_str().unwrap_or("GET"),
                s["url"].as_str().unwrap_or(""),
                s["status"].as_u64().unwrap_or(0),
                s["elapsed_ms"].as_f64().unwrap_or(0.0),
                s["expectation_ok"].as_bool().unwrap_or(false),
            );
        }
    }
    if failed_count == 0 {
        0
    } else {
        1
    }
}

fn header_get<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|h| {
        h.split_once(':')
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
    })
}

fn replace_or_add_header(headers: &[String], name: &str, value: &str) -> Vec<String> {
    let mut out: Vec<String> = headers
        .iter()
        .filter(|h| {
            h.split_once(':')
                .map(|(k, _)| !k.trim().eq_ignore_ascii_case(name))
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    out.push(format!("{name}: {value}"));
    out
}

fn remove_header_ci(headers: &[String], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter(|h| {
            h.split_once(':')
                .map(|(k, _)| !k.trim().eq_ignore_ascii_case(name))
                .unwrap_or(true)
        })
        .cloned()
        .collect()
}

fn url_append_query_param(url: &str, key: &str, val: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{key}={val}")
}

fn path_normalization_variants(url: &str) -> Vec<(&'static str, String)> {
    let (base_no_q, qs) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    let scheme_end = base_no_q.find("://").map(|i| i + 3).unwrap_or(0);
    let Some(rel_slash) = base_no_q[scheme_end..].find('/') else {
        return Vec::new();
    };
    let path_start = scheme_end + rel_slash;
    let origin = &base_no_q[..path_start];
    let path = &base_no_q[path_start..];
    if path.len() <= 1 {
        return Vec::new();
    }
    let trimmed = path.trim_end_matches('/');
    let Some(last_slash) = trimmed.rfind('/') else {
        return Vec::new();
    };
    let parent = &trimmed[..last_slash];
    let leaf = &trimmed[last_slash + 1..];
    if leaf.is_empty() {
        return Vec::new();
    }
    let finish = |p: String| match qs {
        Some(q) => format!("{origin}{p}?{q}"),
        None => format!("{origin}{p}"),
    };
    vec![
        ("norm:double_slash", finish(format!("{parent}//{leaf}"))),
        ("norm:dot_segment", finish(format!("{parent}/./{leaf}"))),
        (
            "norm:semicolon_dotdot",
            finish(format!("{parent}/probe/..;/{leaf}")),
        ),
    ]
}

/// Build a bounded 7-class orthogonal HTTP semantic mutation matrix for parser/gateway differential probing.
pub fn build_semantic_mutation_matrix(
    method: &str,
    url: &str,
    headers: &[String],
    body: Option<&str>,
    alt_value: Option<&str>,
    max_variants: usize,
) -> Vec<(String, HttpVariantSpec)> {
    let mut specs: Vec<(String, HttpVariantSpec)> = Vec::new();
    let m_up = method.to_ascii_uppercase();
    let alt = alt_value.unwrap_or("alt_probe");
    let push_spec = |specs: &mut Vec<(String, HttpVariantSpec)>,
                     class_name: &str,
                     label: String,
                     m: &str,
                     u: String,
                     h: Vec<String>,
                     b: Option<String>| {
        specs.push((
            class_name.to_string(),
            HttpVariantSpec {
                label,
                method: m.to_string(),
                url: u,
                headers: h,
                body: b,
            },
        ));
    };

    // 1. Path Normalization Desync (3)
    for (lbl, u_var) in path_normalization_variants(url) {
        push_spec(
            &mut specs,
            "path_normalization",
            lbl.to_string(),
            &m_up,
            u_var,
            headers.to_vec(),
            body.map(str::to_string),
        );
    }

    // 2. Method Override & Verb Swap (3)
    let alt_method = if m_up == "GET" { "POST" } else { "GET" };
    push_spec(
        &mut specs,
        "method_override",
        format!("method:verb_swap:{alt_method}"),
        alt_method,
        url.to_string(),
        headers.to_vec(),
        body.map(str::to_string),
    );
    let carrier_method = if m_up == "GET" { "POST" } else { "GET" };
    push_spec(
        &mut specs,
        "method_override",
        format!("method:x_http_method_override:{m_up}"),
        carrier_method,
        url.to_string(),
        replace_or_add_header(headers, "X-HTTP-Method-Override", &m_up),
        body.map(str::to_string),
    );
    push_spec(
        &mut specs,
        "method_override",
        format!("method:query_override:{m_up}"),
        carrier_method,
        url_append_query_param(url, "_method", &m_up),
        headers.to_vec(),
        body.map(str::to_string),
    );

    // 3. Content-Type Switch + 4. RFC-8259 Duplicate Key & Type Confusion + 5. Mass Assignment
    if let Some(b_raw) = body.filter(|s| !s.trim().is_empty()) {
        push_spec(
            &mut specs,
            "content_type_switch",
            "ctype:text_plain".to_string(),
            &m_up,
            url.to_string(),
            replace_or_add_header(headers, "Content-Type", "text/plain"),
            Some(b_raw.to_string()),
        );

        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(b_raw.trim()) {
            let mut form_pairs: Vec<String> = Vec::new();
            for (k, v) in &map {
                let sv = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                form_pairs.push(format!("{k}={sv}"));
            }
            if !form_pairs.is_empty() {
                push_spec(
                    &mut specs,
                    "content_type_switch",
                    "ctype:form_urlencoded".to_string(),
                    &m_up,
                    url.to_string(),
                    replace_or_add_header(
                        headers,
                        "Content-Type",
                        "application/x-www-form-urlencoded",
                    ),
                    Some(form_pairs.join("&")),
                );
            }

            if let Some((first_k, orig_val)) = map
                .iter()
                .find(|(k, _)| {
                    let kl = k.to_ascii_lowercase();
                    kl.contains("id") || kl.contains("role") || kl.contains("user")
                })
                .or_else(|| map.iter().next())
            {
                if let Some(prefix) = b_raw.trim().strip_suffix('}') {
                    let dup_body = format!(
                        "{prefix},{}:{}}}",
                        serde_json::to_string(first_k).unwrap_or_default(),
                        serde_json::to_string(alt).unwrap_or_default()
                    );
                    push_spec(
                        &mut specs,
                        "json_desync",
                        format!("json:dup_key:{first_k}"),
                        &m_up,
                        url.to_string(),
                        headers.to_vec(),
                        Some(dup_body),
                    );
                }

                let mut arr_m = map.clone();
                arr_m.insert(first_k.clone(), Value::Array(vec![orig_val.clone()]));
                push_spec(
                    &mut specs,
                    "json_desync",
                    format!("json:array_wrap:{first_k}"),
                    &m_up,
                    url.to_string(),
                    headers.to_vec(),
                    Some(Value::Object(arr_m).to_string()),
                );

                let swapped = match orig_val {
                    Value::String(_) => json!(0),
                    Value::Number(_) => Value::Bool(true),
                    Value::Bool(_) => Value::String("true".to_string()),
                    _ => json!(0),
                };
                let mut type_m = map.clone();
                type_m.insert(first_k.clone(), swapped);
                push_spec(
                    &mut specs,
                    "json_desync",
                    format!("json:type_swap:{first_k}"),
                    &m_up,
                    url.to_string(),
                    headers.to_vec(),
                    Some(Value::Object(type_m).to_string()),
                );
            }

            if matches!(m_up.as_str(), "POST" | "PUT" | "PATCH") {
                let mut mass_m = map.clone();
                mass_m
                    .entry("role".to_string())
                    .or_insert_with(|| Value::String("admin".to_string()));
                mass_m
                    .entry("isAdmin".to_string())
                    .or_insert_with(|| Value::Bool(true));
                push_spec(
                    &mut specs,
                    "mass_assignment",
                    "mass_assign:role_admin".to_string(),
                    &m_up,
                    url.to_string(),
                    headers.to_vec(),
                    Some(Value::Object(mass_m).to_string()),
                );
            }
        }
    }

    // 6. Header-vs-Body Identity Desync (2)
    for id_hdr in ["X-Tenant-Id", "X-Project-Id", "X-Account-Id", "X-User-Id"] {
        if header_get(headers, id_hdr).is_some() {
            push_spec(
                &mut specs,
                "identity_desync",
                format!("id_desync:omit:{id_hdr}"),
                &m_up,
                url.to_string(),
                remove_header_ci(headers, id_hdr),
                body.map(str::to_string),
            );
            push_spec(
                &mut specs,
                "identity_desync",
                format!("id_desync:swap:{id_hdr}"),
                &m_up,
                url.to_string(),
                replace_or_add_header(headers, id_hdr, alt),
                body.map(str::to_string),
            );
            break;
        }
    }

    // 7. GraphQL Batch & Alias Probe (2, only when GraphQL)
    let is_gql = url.to_ascii_lowercase().contains("graphql")
        || body.is_some_and(|b| b.contains("\"query\""));
    if is_gql {
        if let Some(b_raw) = body {
            let trimmed = b_raw.trim();
            if trimmed.starts_with('{') {
                push_spec(
                    &mut specs,
                    "graphql_batch_alias",
                    "graphql:array_batch".to_string(),
                    &m_up,
                    url.to_string(),
                    headers.to_vec(),
                    Some(format!("[{trimmed},{trimmed}]")),
                );
                if let Ok(Value::Object(mut gmap)) = serde_json::from_str::<Value>(trimmed) {
                    if let Some(q_str) = gmap
                        .get("query")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                    {
                        if let (Some(ob), Some(cb)) = (q_str.find('{'), q_str.rfind('}')) {
                            let inner = q_str[ob + 1..cb].trim();
                            if !inner.is_empty() && !inner.contains("ap_a1:") {
                                let aliased = format!(
                                    "{} {{ ap_a1: {inner} ap_a2: {inner} }}",
                                    q_str[..ob].trim()
                                );
                                gmap.insert("query".to_string(), Value::String(aliased));
                                push_spec(
                                    &mut specs,
                                    "graphql_batch_alias",
                                    "graphql:dup_alias".to_string(),
                                    &m_up,
                                    url.to_string(),
                                    headers.to_vec(),
                                    Some(Value::Object(gmap).to_string()),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    specs.truncate(max_variants.clamp(1, 32));
    specs
}

type MutationAnomaly = (String, String, Vec<String>, Vec<String>, Vec<String>);

#[cfg(test)]
fn classify_mutation_anomaly(
    base: &HttpProbeResult,
    cand: &HttpProbeResult,
    class_name: &str,
    label: &str,
    alt: &str,
    volatile_paths: &std::collections::HashSet<String>,
    sentinels: &[String],
) -> Option<MutationAnomaly> {
    classify_mutation_anomaly_raw(
        base,
        &base.body_preview,
        cand,
        &cand.body_preview,
        class_name,
        label,
        alt,
        volatile_paths,
        sentinels,
    )
}

#[allow(clippy::too_many_arguments)]
fn classify_mutation_anomaly_raw(
    base: &HttpProbeResult,
    base_raw: &str,
    cand: &HttpProbeResult,
    cand_raw: &str,
    class_name: &str,
    label: &str,
    alt: &str,
    volatile_paths: &std::collections::HashSet<String>,
    sentinels: &[String],
) -> Option<MutationAnomaly> {
    if cand.status == 0 || !cand.error.is_empty() {
        return None;
    }

    let sentinel_hits: Vec<String> = sentinels
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && cand_raw.contains(*s))
        .map(str::to_string)
        .collect();

    let mut base_paths = std::collections::BTreeMap::new();
    let mut cand_paths = std::collections::BTreeMap::new();
    let base_json = serde_json::from_str::<Value>(base_raw.trim()).ok();
    let cand_json = serde_json::from_str::<Value>(cand_raw.trim()).ok();
    if let Some(ref bv) = base_json {
        flatten_json_paths(bv, "", 0, &mut base_paths);
    }
    if let Some(ref cv) = cand_json {
        flatten_json_paths(cv, "", 0, &mut cand_paths);
    }

    let added_paths: Vec<String> = cand_paths
        .keys()
        .filter(|k| !volatile_paths.contains(*k) && !base_paths.contains_key(*k))
        .take(16)
        .cloned()
        .collect();
    let changed_paths: Vec<String> = cand_paths
        .iter()
        .filter(|(k, cv)| {
            !volatile_paths.contains(*k) && base_paths.get(*k).is_some_and(|bv| bv != *cv)
        })
        .map(|(k, _)| k.clone())
        .take(16)
        .collect();

    if !sentinel_hits.is_empty() {
        return Some((
            "SENTINEL_LEAK".to_string(),
            format!("HTTP {} leaked sentinel(s)", cand.status),
            added_paths,
            changed_paths,
            sentinel_hits,
        ));
    }

    let low_body = cand_raw.to_ascii_lowercase();
    let is_pseudo_denial = [
        "unauthorized",
        "forbidden",
        "access denied",
        "permission denied",
        "login required",
    ]
    .iter()
    .any(|kw| low_body.contains(kw));

    if matches!(base.status, 401 | 403 | 404 | 405)
        && (200..300).contains(&cand.status)
        && !is_pseudo_denial
    {
        return Some((
            "AUTH_OR_ROUTE_BYPASS".to_string(),
            format!(
                "Baseline HTTP {} flipped to HTTP {} under `{label}`",
                base.status, cand.status
            ),
            added_paths,
            changed_paths,
            sentinel_hits,
        ));
    }

    if class_name == "graphql_batch_alias" && (200..300).contains(&cand.status) {
        let batch_ok = cand_json
            .as_ref()
            .and_then(Value::as_array)
            .is_some_and(|a| a.len() >= 2);
        let alias_ok = cand_raw.contains("ap_a1") && cand_raw.contains("ap_a2");
        if batch_ok || alias_ok {
            return Some((
                "GRAPHQL_BATCH_OR_ALIAS_ALLOWED".to_string(),
                format!("HTTP {} accepted `{label}`", cand.status),
                added_paths,
                changed_paths,
                sentinel_hits,
            ));
        }
    }

    if label == "mass_assign:role_admin" && (200..300).contains(&cand.status) {
        let echoed_admin = (cand_raw.contains("\"role\"")
            && cand_raw.contains("\"admin\"")
            && !base_raw.contains("\"admin\""))
            || (cand_raw.contains("\"isAdmin\":true") && !base_raw.contains("\"isAdmin\":true"))
            || !(200..300).contains(&base.status);
        if echoed_admin {
            return Some((
                "PARSER_DESYNC_ECHO".to_string(),
                "Response accepted/echoed injected admin mass-assignment keys".to_string(),
                added_paths,
                changed_paths,
                sentinel_hits,
            ));
        }
    }

    if label.starts_with("json:dup_key:")
        && (200..300).contains(&cand.status)
        && cand_raw.contains(alt)
        && !base_raw.contains(alt)
    {
        return Some((
            "PARSER_DESYNC_ECHO".to_string(),
            format!("Duplicate JSON key `{label}` echoed override `{alt}`"),
            added_paths,
            changed_paths,
            sentinel_hits,
        ));
    }

    if class_name == "identity_desync"
        && (200..300).contains(&base.status)
        && (200..300).contains(&cand.status)
        && !is_pseudo_denial
    {
        return Some((
            "PARSER_DESYNC_ECHO".to_string(),
            format!(
                "Identity header mutation `{label}` still returned HTTP {}",
                cand.status
            ),
            added_paths,
            changed_paths,
            sentinel_hits,
        ));
    }

    if !(500..600).contains(&base.status) && (500..600).contains(&cand.status) {
        return Some((
            "SERVER_FAULT_5XX".to_string(),
            format!(
                "Baseline HTTP {} triggered HTTP {} on `{label}`",
                base.status, cand.status
            ),
            added_paths,
            changed_paths,
            sentinel_hits,
        ));
    }

    if base.status != cand.status && !added_paths.is_empty() {
        return Some((
            "STRUCTURAL_DIFF".to_string(),
            format!(
                "HTTP {} -> {} with {} new non-volatile JSON path(s)",
                base.status,
                cand.status,
                added_paths.len()
            ),
            added_paths,
            changed_paths,
            sentinel_hits,
        ));
    }

    None
}

/// Bounded 7-class HTTP semantic mutation & parser/gateway differential oracle.
/// Runs baseline twice to isolate volatile JSON keys, then probes normalized/override/parser variants.
#[allow(clippy::too_many_arguments)]
pub fn run_http_mutate_matrix(
    req_file: Option<&std::path::Path>,
    url_opt: Option<&str>,
    method: &str,
    headers: &[String],
    body: Option<&str>,
    alt_value: Option<&str>,
    rate_ms: u64,
    max_variants: usize,
    dry_run: bool,
    cdp_cookies_port: Option<u16>,
    sentinels: &[String],
    timeout_sec: u64,
    insecure: bool,
    follow: bool,
    as_json: bool,
) -> i32 {
    let (m, u, mut hdrs, b) = if let Some(rf) = req_file {
        match load_saved_request(rf) {
            Ok(spec) => spec,
            Err(e) => {
                eprintln!("[probe http mutate-matrix] {e}");
                return 2;
            }
        }
    } else if let Some(url) = url_opt.filter(|s| !s.trim().is_empty()) {
        (
            method.to_ascii_uppercase(),
            url.to_string(),
            Vec::new(),
            body.map(str::to_string),
        )
    } else {
        eprintln!("[probe http mutate-matrix] Provide a URL or `--vary-request <file>`.");
        return 2;
    };
    hdrs.extend(headers.iter().cloned());
    if !dry_run {
        if let Some(port) = cdp_cookies_port {
            if !has_header_name(&hdrs, "cookie") {
                match resolve_cdp_cookie_header(port, &u) {
                    Ok((Some(ch), _)) => hdrs.push(ch),
                    Ok((None, _)) => {}
                    Err(e) => {
                        eprintln!("[probe http mutate-matrix] cdp-cookies:{port}: {e}");
                        return 1;
                    }
                }
            }
        }
    }

    let alt = alt_value.unwrap_or("alt_probe");
    let matrix =
        build_semantic_mutation_matrix(&m, &u, &hdrs, b.as_deref(), Some(alt), max_variants);
    if dry_run {
        let preview: Vec<Value> = matrix
            .iter()
            .map(|(cls, sp)| {
                json!({
                    "class": cls,
                    "label": sp.label,
                    "method": sp.method,
                    "url": sp.url,
                    "body": sp.body,
                })
            })
            .collect();
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "dry_run": true,
                    "mode": "http_mutate_matrix",
                    "target": u,
                    "count": preview.len(),
                    "variants": preview,
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "[probe http mutate-matrix] DRY-RUN generated {} semantic mutation(s):",
                preview.len()
            );
            for (i, (cls, sp)) in matrix.iter().enumerate() {
                println!("  {}. [{cls}/{}] {} {}", i + 1, sp.label, sp.method, sp.url);
            }
        }
        return 0;
    }

    // Run baseline twice to automatically discover volatile JSON fields (timestamps/request_id/nonces)
    let (base1, base1_raw) =
        execute_http_probe_with_raw(&m, &u, &hdrs, b.as_deref(), timeout_sec, insecure, follow);
    let (_base2, base2_raw) =
        execute_http_probe_with_raw(&m, &u, &hdrs, b.as_deref(), timeout_sec, insecure, follow);
    let mut volatile_paths = std::collections::HashSet::new();
    if let (Ok(v1), Ok(v2)) = (
        serde_json::from_str::<Value>(base1_raw.trim()),
        serde_json::from_str::<Value>(base2_raw.trim()),
    ) {
        let mut p1 = std::collections::BTreeMap::new();
        let mut p2 = std::collections::BTreeMap::new();
        flatten_json_paths(&v1, "", 0, &mut p1);
        flatten_json_paths(&v2, "", 0, &mut p2);
        for (k, val1) in &p1 {
            if p2.get(k) != Some(val1) {
                volatile_paths.insert(k.clone());
            }
        }
        for k in p2.keys() {
            if !p1.contains_key(k) {
                volatile_paths.insert(k.clone());
            }
        }
    }

    let mut anomalies: Vec<Value> = Vec::new();
    let mut suppressed_count = 0usize;
    for (idx, (cls, spec)) in matrix.iter().enumerate() {
        if idx > 0 && rate_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(rate_ms.min(5000)));
        }
        let (cand, cand_raw) = execute_http_probe_with_raw(
            &spec.method,
            &spec.url,
            &spec.headers,
            spec.body.as_deref(),
            timeout_sec,
            insecure,
            follow,
        );
        if let Some((kind, detail, added, changed, s_hits)) = classify_mutation_anomaly_raw(
            &base1,
            &base1_raw,
            &cand,
            &cand_raw,
            cls,
            &spec.label,
            alt,
            &volatile_paths,
            sentinels,
        ) {
            anomalies.push(json!({
                "class": cls,
                "label": spec.label,
                "method": cand.method,
                "url": cand.url,
                "status": cand.status,
                "kind": kind,
                "detail": detail,
                "added_paths": added,
                "changed_paths": changed,
                "sentinel_hits": s_hits,
                "body_preview": cand.body_preview.chars().take(240).collect::<String>(),
            }));
        } else {
            suppressed_count += 1;
        }
    }

    let vol_vec: Vec<String> = volatile_paths.into_iter().take(20).collect();
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "mode": "http_mutate_matrix",
                "target": u,
                "baseline_status": base1.status,
                "volatile_keys": vol_vec,
                "variants_run": matrix.len(),
                "suppressed_count": suppressed_count,
                "anomaly_count": anomalies.len(),
                "anomalies": anomalies,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[probe http mutate-matrix] baseline=HTTP {}, run={}, anomalies={}, suppressed={} (volatile_keys={}):",
            base1.status,
            matrix.len(),
            anomalies.len(),
            suppressed_count,
            vol_vec.len()
        );
        for a in &anomalies {
            println!(
                "  ! [{}] ({}) HTTP {} — {}",
                a["kind"].as_str().unwrap_or(""),
                a["label"].as_str().unwrap_or(""),
                a["status"].as_u64().unwrap_or(0),
                a["detail"].as_str().unwrap_or("")
            );
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audits_two_phase_and_cors_security_headers() {
        let gaps = audit_response_headers(
            "https://storage.example/download/doc?response-content-type=text/html",
            200,
            "text/html; charset=utf-8",
            &[
                "Content-Disposition: inline; filename=evil.html".to_string(),
                "Access-Control-Allow-Origin: *".to_string(),
                "Access-Control-Allow-Credentials: true".to_string(),
                "Set-Cookie: sid=abc123; Path=/".to_string(),
            ],
        );
        let joined = gaps.join(" | ");
        assert!(joined.contains("nosniff"), "missing nosniff: {joined}");
        assert!(joined.contains("inline"), "missing inline: {joined}");
        assert!(
            joined.contains("Content-Security-Policy"),
            "missing CSP: {joined}"
        );
        assert!(
            joined.contains("response-content-type"),
            "missing override: {joined}"
        );
        assert!(
            joined.contains("Allow-Credentials"),
            "missing CORS: {joined}"
        );
        assert!(
            joined.contains("HttpOnly/Secure"),
            "missing cookie flags: {joined}"
        );
    }

    #[test]
    fn classifies_idor_auth_matrix_bypass_vs_denial() {
        let base = HttpProbeResult {
            method: "GET".to_string(),
            url: "https://api.example/v1/items/42".to_string(),
            status: 200,
            elapsed_ms: 12.0,
            content_type: "application/json".to_string(),
            headers: Vec::new(),
            body_preview: r#"{"id":42,"owner":"alice","secret":"val"}"#.to_string(),
            error: String::new(),
        };
        let leaked = HttpProbeResult {
            body_preview: r#"{"id":42,"owner":"alice","secret":"val"}"#.to_string(),
            ..base.clone()
        };
        let denied_403 = HttpProbeResult {
            status: 403,
            body_preview: r#"{"error":"forbidden"}"#.to_string(),
            ..base.clone()
        };
        let soft_denied_200 = HttpProbeResult {
            status: 200,
            body_preview: r#"{"code":403,"msg":"permission denied"}"#.to_string(),
            ..base.clone()
        };
        assert!(classify_auth_matrix_diff(&base, &leaked).0);
        assert!(!classify_auth_matrix_diff(&base, &denied_403).0);
        assert!(!classify_auth_matrix_diff(&base, &soft_denied_200).0);
    }

    #[test]
    fn audits_cors_reflection_and_vary_origin() {
        let crit = audit_cors_reflection(
            "https://untrusted.example",
            &[
                "Access-Control-Allow-Origin: https://untrusted.example".to_string(),
                "Access-Control-Allow-Credentials: true".to_string(),
            ],
        );
        let j = crit.join(" | ");
        assert!(j.contains("CORS-CRITICAL"), "expected CORS-CRITICAL: {j}");
        assert!(j.contains("Vary: Origin"), "expected missing Vary: {j}");

        let safe = audit_cors_reflection(
            "https://untrusted.example",
            &[
                "Access-Control-Allow-Origin: https://trusted.example".to_string(),
                "Access-Control-Allow-Credentials: true".to_string(),
                "Vary: Origin".to_string(),
            ],
        );
        assert!(
            safe.is_empty(),
            "safe origin should yield 0 findings: {safe:?}"
        );
    }

    #[test]
    fn parses_principal_cdp_specs_and_json_select() {
        assert_eq!(
            parse_principal_cdp_spec("owner=9222").unwrap(),
            ("owner".to_string(), 9222)
        );
        assert_eq!(
            parse_principal_cdp_spec("9223").unwrap(),
            ("cdp:9223".to_string(), 9223)
        );
        assert!(parse_principal_cdp_spec("owner=0").is_err());
        assert!(parse_principal_cdp_spec("owner=abc").is_err());

        let body = r#"{"ok":true,"data":{"items":[{"id":1,"role":"a"},{"id":2,"role":"b"}]}}"#;
        assert_eq!(
            extract_json_select(body, "data.items[*].id"),
            Some(json!([1, 2]))
        );
        assert_eq!(
            extract_json_select(body, "data.items.1.role"),
            Some(json!("b"))
        );
        assert_eq!(extract_json_select(body, "ok"), Some(json!(true)));
    }

    #[test]
    fn deep_diff_detects_nested_bypass_sentinel_leak_and_html_summary() {
        let base = HttpProbeResult {
            method: "GET".to_string(),
            url: "https://api.example/v1/account".to_string(),
            status: 200,
            elapsed_ms: 8.0,
            content_type: "application/json".to_string(),
            headers: Vec::new(),
            body_preview: r#"{"ok":true,"data":{"user":{"email":"owner@example.org","role":"admin","tier":"pro"}}}"#.to_string(),
            error: String::new(),
        };
        let leaked_nested = HttpProbeResult {
            body_preview: r#"{"ok":true,"data":{"user":{"email":"owner@example.org","role":"guest","tier":"pro"}}}"#.to_string(),
            ..base.clone()
        };
        let rep = classify_auth_matrix_diff_deep(&base, &leaked_nested, &[]);
        assert!(rep.possible_bypass);
        assert_eq!(rep.verdict, "LIKELY_BYPASS");
        assert!(rep
            .shared_nonempty_paths
            .contains(&"data.user.email".to_string()));
        assert!(rep.changed_paths.contains(&"data.user.role".to_string()));

        let err_sentinel = HttpProbeResult {
            status: 500,
            content_type: "text/html".to_string(),
            body_preview: "<html><title>Debug Error</title><body>leaked_tok_XYZ</body></html>"
                .to_string(),
            ..base.clone()
        };
        let srep =
            classify_auth_matrix_diff_deep(&base, &err_sentinel, &["leaked_tok_XYZ".to_string()]);
        assert!(srep.possible_bypass);
        assert_eq!(srep.verdict, "SENTINEL_LEAK");
        assert_eq!(srep.sentinel_hits, vec!["leaked_tok_XYZ".to_string()]);

        let html_denied = HttpProbeResult {
            status: 403,
            content_type: "text/html".to_string(),
            body_preview:
                "<html><head><title>403 Access Blocked</title></head><body>Sign in</body></html>"
                    .to_string(),
            ..base.clone()
        };
        let hrep = classify_auth_matrix_diff_deep(&base, &html_denied, &[]);
        assert!(!hrep.possible_bypass);
        assert_eq!(hrep.verdict, "AUTH_DENIED_401_403");
        assert!(
            hrep.reason.contains("403 Access Blocked"),
            "{}",
            hrep.reason
        );
    }

    #[test]
    fn semantic_mutation_matrix_builds_7_classes_and_detects_anomalies_without_volatile_noise() {
        let headers = vec![
            "Content-Type: application/json".to_string(),
            "X-User-Id: user_1001".to_string(),
        ];
        let body = r#"{"amount":10,"userId":"user_1001"}"#;
        let specs = build_semantic_mutation_matrix(
            "POST",
            "https://api.example/v1/admin/transfer?id=1",
            &headers,
            Some(body),
            Some("user_1002"),
            32,
        );
        let classes: std::collections::HashSet<&str> =
            specs.iter().map(|(c, _)| c.as_str()).collect();
        assert!(classes.contains("path_normalization"), "{classes:?}");
        assert!(classes.contains("method_override"), "{classes:?}");
        assert!(classes.contains("content_type_switch"), "{classes:?}");
        assert!(classes.contains("json_desync"), "{classes:?}");
        assert!(classes.contains("mass_assignment"), "{classes:?}");
        assert!(classes.contains("identity_desync"), "{classes:?}");

        let gql_specs = build_semantic_mutation_matrix(
            "POST",
            "https://api.example/graphql",
            &["Content-Type: application/json".to_string()],
            Some(r#"{"query":"{ viewer { id } }"}"#),
            None,
            32,
        );
        assert!(gql_specs.iter().any(|(c, _)| c == "graphql_batch_alias"));
        assert!(gql_specs
            .iter()
            .any(|(_, s)| s.label == "graphql:dup_alias"));

        let base1 = HttpProbeResult {
            method: "POST".to_string(),
            url: "https://api.example/v1/admin/transfer".to_string(),
            status: 403,
            elapsed_ms: 5.0,
            content_type: "application/json".to_string(),
            headers: Vec::new(),
            body_preview: r#"{"error":"forbidden","request_id":"r1","ts":100}"#.to_string(),
            error: String::new(),
        };
        let base2 = HttpProbeResult {
            body_preview: r#"{"error":"forbidden","request_id":"r2","ts":101}"#.to_string(),
            ..base1.clone()
        };
        let mut volatile = std::collections::HashSet::new();
        let mut p1 = std::collections::BTreeMap::new();
        let mut p2 = std::collections::BTreeMap::new();
        flatten_json_paths(
            &serde_json::from_str(&base1.body_preview).unwrap(),
            "",
            0,
            &mut p1,
        );
        flatten_json_paths(
            &serde_json::from_str(&base2.body_preview).unwrap(),
            "",
            0,
            &mut p2,
        );
        for (k, v1) in &p1 {
            if p2.get(k) != Some(v1) {
                volatile.insert(k.clone());
            }
        }
        assert!(volatile.contains("request_id"));
        assert!(volatile.contains("ts"));

        // Volatile-only noise on identical 403 -> suppressed (None)
        let noisy_same = HttpProbeResult {
            body_preview: r#"{"error":"forbidden","request_id":"r99","ts":999}"#.to_string(),
            ..base1.clone()
        };
        assert!(classify_mutation_anomaly(
            &base1,
            &noisy_same,
            "path_norm",
            "path:trailing_slash",
            "user_1002",
            &volatile,
            &[],
        )
        .is_none());

        // 403 -> 200 dot-segment route bypass -> AUTH_OR_ROUTE_BYPASS
        let bypass = HttpProbeResult {
            status: 200,
            body_preview: r#"{"ok":true,"granted":"yes","request_id":"r3","ts":102}"#.to_string(),
            ..base1.clone()
        };
        let (kind, _, added, _, _) = classify_mutation_anomaly(
            &base1,
            &bypass,
            "path_norm",
            "path:dot_segment",
            "user_1002",
            &volatile,
            &[],
        )
        .expect("bypass detected");
        assert_eq!(kind, "AUTH_OR_ROUTE_BYPASS");
        assert!(added.contains(&"ok".to_string()));
        assert!(!added.contains(&"request_id".to_string()));

        // Mass assignment echo on 200 baseline -> PARSER_DESYNC_ECHO
        let ok_base = HttpProbeResult {
            status: 200,
            body_preview: r#"{"ok":true,"role":"user"}"#.to_string(),
            ..base1.clone()
        };
        let ma_echo = HttpProbeResult {
            status: 200,
            body_preview: r#"{"ok":true,"role":"admin"}"#.to_string(),
            ..base1.clone()
        };
        let (mak, _, _, _, _) = classify_mutation_anomaly(
            &ok_base,
            &ma_echo,
            "mass_assign",
            "mass_assign:role_admin",
            "user_1002",
            &volatile,
            &[],
        )
        .expect("mass assignment detected");
        assert_eq!(mak, "PARSER_DESYNC_ECHO");

        // GraphQL alias allowed -> GRAPHQL_BATCH_OR_ALIAS_ALLOWED
        let gql_alias = HttpProbeResult {
            status: 200,
            body_preview: r#"{"data":{"ap_a1":{"id":1},"ap_a2":{"id":1}}}"#.to_string(),
            ..base1
        };
        let (gk, _, _, _, _) = classify_mutation_anomaly(
            &ok_base,
            &gql_alias,
            "graphql_batch_alias",
            "graphql:dup_alias",
            "user_1002",
            &volatile,
            &[],
        )
        .expect("graphql alias detected");
        assert_eq!(gk, "GRAPHQL_BATCH_OR_ALIAS_ALLOWED");
    }

    #[test]
    fn mutate_matrix_and_deep_diff_handle_over_4kb_json_bodies() {
        let big_pad = "x".repeat(4200);
        let base_raw =
            format!(r#"{{"pad":"{big_pad}","meta":{{"req_id":"r1"}},"role":"user","ok":true}}"#);
        let cand_raw = format!(
            r#"{{"pad":"{big_pad}","meta":{{"req_id":"r2"}},"role":"admin","extra":"leaked","ok":true}}"#
        );
        let base_meta = HttpProbeResult {
            method: "POST".to_string(),
            url: "https://api.example/v1/profile".to_string(),
            status: 200,
            elapsed_ms: 4.0,
            content_type: "application/json".to_string(),
            headers: Vec::new(),
            body_preview: format!(
                "{}...\n[truncated: {}B total]",
                &base_raw[..2400],
                base_raw.len()
            ),
            error: String::new(),
        };
        let cand_meta = HttpProbeResult {
            body_preview: format!(
                "{}...\n[truncated: {}B total]",
                &cand_raw[..2400],
                cand_raw.len()
            ),
            ..base_meta.clone()
        };

        let mut volatile = std::collections::HashSet::new();
        volatile.insert("meta.req_id".to_string());
        let (kind, _, added, changed, _) = classify_mutation_anomaly_raw(
            &base_meta,
            &base_raw,
            &cand_meta,
            &cand_raw,
            "mass_assignment",
            "mass_assign:role_admin",
            "alt",
            &volatile,
            &[],
        )
        .expect("mass-assignment beyond 2400B preview detected");
        assert_eq!(kind, "PARSER_DESYNC_ECHO");
        assert!(added.contains(&"extra".to_string()), "{added:?}");
        assert!(changed.contains(&"role".to_string()), "{changed:?}");
        assert!(!changed.contains(&"meta.req_id".to_string()), "{changed:?}");

        let flow_diff = classify_auth_matrix_diff_deep_bodies(
            &base_meta,
            &base_raw,
            &cand_meta,
            &cand_raw,
            &[],
        );
        assert!(flow_diff.possible_bypass);
        assert!(flow_diff.added_paths.contains(&"extra".to_string()));
        assert!(flow_diff.changed_paths.contains(&"role".to_string()));
    }
}
