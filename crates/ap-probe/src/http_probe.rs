use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Read;
use std::process::Command;
use std::time::Instant;

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
            return HttpProbeResult {
                method: method.to_string(),
                url: url.to_string(),
                status: 0,
                elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0).round(),
                content_type: String::new(),
                headers: Vec::new(),
                body_preview: String::new(),
                error: format!("failed to spawn {curl_bin}: {e}"),
            };
        }
    };
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
    if !out.status.success() && out.stdout.is_empty() {
        return HttpProbeResult {
            method: method.to_string(),
            url: url.to_string(),
            status: 0,
            elapsed_ms,
            content_type: String::new(),
            headers: Vec::new(),
            body_preview: String::new(),
            error: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        };
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

    HttpProbeResult {
        method: method.to_string(),
        url: url.to_string(),
        status,
        elapsed_ms,
        content_type: ct,
        headers: hdrs,
        body_preview: preview,
        error: String::new(),
    }
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

    let mut results = Vec::new();
    for (m, u, extra_hdrs, b) in jobs.into_iter().take(25) {
        let mut merged_hdrs = headers.to_vec();
        merged_hdrs.extend(extra_hdrs);
        results.push(execute_http_probe(
            &m,
            &u,
            &merged_hdrs,
            b.as_deref(),
            timeout_sec,
            insecure,
            follow,
        ));
    }

    let any_err = results.iter().any(|r| !r.error.is_empty() || r.status == 0);
    let header_audits: Vec<Vec<String>> = if audit_headers {
        results
            .iter()
            .map(|r| audit_response_headers(&r.url, r.status, &r.content_type, &r.headers))
            .collect()
    } else {
        Vec::new()
    };
    if as_json {
        let out_val = if audit_headers {
            let enriched: Vec<Value> = results
                .iter()
                .zip(header_audits.iter())
                .map(|(r, findings)| {
                    let mut v = serde_json::to_value(r).unwrap_or_else(|_| json!({}));
                    if let Some(m) = v.as_object_mut() {
                        m.insert("header_findings".to_string(), json!(findings));
                    }
                    v
                })
                .collect();
            json!({
                "ok": !any_err,
                "count": results.len(),
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
            if audit_headers {
                let gaps = header_audits.first().cloned().unwrap_or_default();
                if gaps.is_empty() {
                    println!("  [header-audit] PASS (0 security/two-phase gaps)");
                } else {
                    println!("  [header-audit] {} gap(s): {}", gaps.len(), gaps.join(" | "));
                }
            }
            if !r.body_preview.is_empty() {
                println!("\n{}", r.body_preview);
            }
        }
    } else {
        println!("[probe http] Batch {} request(s):", results.len());
        for (i, r) in results.iter().enumerate() {
            if !r.error.is_empty() {
                println!("  {}. {} {} -> ERR ({})", i + 1, r.method, r.url, r.error);
            } else {
                let snip: String = r
                    .body_preview
                    .replace(['\r', '\n'], " ")
                    .chars()
                    .take(120)
                    .collect();
                let gap_tag = if audit_headers {
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
        findings.push("download/storage endpoint missing Content-Disposition: attachment".to_string());
    }
    if (200..300).contains(&status)
        && (ct_low.contains("text/html") || ct_low.contains("image/svg+xml"))
        && get_hdr("content-security-policy").is_none()
    {
        findings.push(format!("active content ({content_type}) missing Content-Security-Policy"));
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

fn json_top_keys(body: &str) -> Vec<String> {
    if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(body.trim()) {
        let mut keys: Vec<String> = m.keys().cloned().collect();
        keys.sort();
        keys
    } else {
        Vec::new()
    }
}

/// Compare an unprivileged/cross-tenant candidate HTTP response against a privileged owner baseline.
/// Returns `(possible_bypass, reason)`.
pub fn classify_auth_matrix_diff(base: &HttpProbeResult, cand: &HttpProbeResult) -> (bool, String) {
    if cand.status == 0 || !cand.error.is_empty() {
        return (false, format!("transport error: {}", cand.error));
    }
    if !(200..300).contains(&cand.status) {
        return (false, format!("rejected with HTTP {}", cand.status));
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
            return (
                false,
                format!("HTTP {} but body contains auth denial marker `{deny_kw}`", cand.status),
            );
        }
    }
    let base_keys = json_top_keys(&base.body_preview);
    let cand_keys = json_top_keys(&cand.body_preview);
    if !base_keys.is_empty() && !cand_keys.is_empty() {
        let shared = cand_keys.iter().filter(|k| base_keys.contains(k)).count();
        let denom = base_keys.len().max(1);
        let overlap = (shared * 100) / denom;
        if overlap >= 50 && cand.body_preview.len() >= 16 {
            return (
                true,
                format!(
                    "HTTP {} with {overlap}% JSON key overlap ({shared}/{denom}) and {}B body (baseline {}B)",
                    cand.status,
                    cand.body_preview.len(),
                    base.body_preview.len()
                ),
            );
        }
    }
    let base_len = base.body_preview.len();
    let cand_len = cand.body_preview.len();
    if (200..300).contains(&base.status) && base_len >= 16 && cand_len * 100 >= base_len * 40 {
        return (
            true,
            format!(
                "HTTP {} with non-denied {}B payload ({}% of baseline {}B)",
                cand.status,
                cand_len,
                (cand_len * 100) / base_len.max(1),
                base_len
            ),
        );
    }
    (
        false,
        format!("HTTP {} with divergent/minimal payload ({cand_len}B vs baseline {base_len}B)", cand.status),
    )
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

fn merge_principal_headers(base_headers: &[String], principal_headers: &[String], strip_auth: bool) -> Vec<String> {
    let override_keys: Vec<String> = principal_headers
        .iter()
        .filter_map(|h| h.split_once(':').map(|(k, _)| k.trim().to_ascii_lowercase()))
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
            if strip_auth && matches!(k.as_str(), "authorization" | "cookie" | "x-auth-token" | "x-api-key") {
                return false;
            }
            true
        })
        .cloned()
        .collect();
    merged.extend(principal_headers.iter().cloned());
    merged
}

#[allow(clippy::too_many_arguments)]
pub fn run_http_auth_matrix(
    req_file: Option<&std::path::Path>,
    url_opt: Option<&str>,
    method: &str,
    headers: &[String],
    body: Option<&str>,
    principals: &[String],
    audit_headers: bool,
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

    let parsed: Vec<(String, Vec<String>)> = principals.iter().map(|p| parse_principal_spec(p)).collect();
    let mut rows: Vec<(String, HttpProbeResult, Vec<String>)> = Vec::new();
    for (label, phdrs) in &parsed {
        let strip_auth = phdrs.is_empty();
        let req_hdrs = merge_principal_headers(&base_hdrs, phdrs, strip_auth);
        let res = execute_http_probe(&m, &u, &req_hdrs, b.as_deref(), timeout_sec, insecure, follow);
        let gaps = if audit_headers {
            audit_response_headers(&res.url, res.status, &res.content_type, &res.headers)
        } else {
            Vec::new()
        };
        rows.push((label.clone(), res, gaps));
    }

    let baseline = rows.first().map(|(_, r, _)| r.clone());
    let mut bypasses = Vec::new();
    let mut json_rows = Vec::new();
    for (idx, (label, r, gaps)) in rows.iter().enumerate() {
        let (possible_bypass, reason) = if idx == 0 {
            (false, "baseline principal".to_string())
        } else if let Some(ref base) = baseline {
            classify_auth_matrix_diff(base, r)
        } else {
            (false, "no baseline".to_string())
        };
        if possible_bypass {
            bypasses.push(json!({
                "principal": label,
                "status": r.status,
                "reason": reason,
                "body_preview": r.body_preview.chars().take(240).collect::<String>(),
            }));
        }
        json_rows.push(json!({
            "principal": label,
            "status": r.status,
            "elapsed_ms": r.elapsed_ms,
            "content_type": r.content_type,
            "body_len": r.body_preview.len(),
            "possible_bypass": possible_bypass,
            "diff_reason": reason,
            "header_findings": gaps,
            "error": r.error,
            "body_preview": r.body_preview.chars().take(360).collect::<String>(),
        }));
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "method": m,
                "url": u,
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
            println!(
                "  - {:<14} HTTP {} ({}B) {} — {}",
                item["principal"].as_str().unwrap_or("?"),
                item["status"].as_u64().unwrap_or(0),
                item["body_len"].as_u64().unwrap_or(0),
                flag,
                item["diff_reason"].as_str().unwrap_or("")
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
        assert!(joined.contains("Content-Security-Policy"), "missing CSP: {joined}");
        assert!(joined.contains("response-content-type"), "missing override: {joined}");
        assert!(joined.contains("Allow-Credentials"), "missing CORS: {joined}");
        assert!(joined.contains("HttpOnly/Secure"), "missing cookie flags: {joined}");
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
}
