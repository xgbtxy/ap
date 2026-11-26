use crate::http_probe::{classify_auth_matrix_diff_deep, execute_http_probe, HttpProbeResult};
use crate::net_probe::{run_ws_cli, run_ws_origin_matrix};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarEndpointCluster {
    pub method: String,
    pub host: String,
    pub path_template: String,
    pub sample_url: String,
    pub count: usize,
    pub auth_headers: Vec<String>,
    pub sample_headers: Vec<String>,
    pub query_keys: Vec<String>,
    pub json_schema_keys: Vec<String>,
    pub sample_body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarWsFlow {
    pub url: String,
    pub headers: Vec<String>,
    pub sample_frames: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedHarFlow {
    pub endpoints: Vec<HarEndpointCluster>,
    pub ws_flows: Vec<HarWsFlow>,
}

fn normalize_path_segment(seg: &str) -> String {
    if seg.is_empty() {
        return String::new();
    }
    if !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()) {
        return "{id}".to_string();
    }
    // UUID v4-like
    if seg.len() == 36
        && seg.chars().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
    {
        return "{uuid}".to_string();
    }
    // Long hex/base64url token
    if seg.len() >= 16 && seg.bytes().all(|b| b.is_ascii_hexdigit()) {
        return "{hex}".to_string();
    }
    seg.to_string()
}

fn split_url_parts(raw_url: &str) -> (String, String, String, Vec<(String, String)>) {
    let without_frag = raw_url.split('#').next().unwrap_or(raw_url);
    let (base, query_str) = match without_frag.split_once('?') {
        Some((b, q)) => (b, q),
        None => (without_frag, ""),
    };
    let (scheme_host, raw_path) = if let Some(pos) = base.find("://") {
        let rest = &base[pos + 3..];
        if let Some(slash) = rest.find('/') {
            (&base[..pos + 3 + slash], &rest[slash..])
        } else {
            (base, "/")
        }
    } else {
        ("", base)
    };
    let tmpl_path: String = raw_path
        .split('/')
        .map(normalize_path_segment)
        .collect::<Vec<_>>()
        .join("/");
    let query_pairs = query_str
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (kv.to_string(), String::new()),
        })
        .collect();
    (
        scheme_host.to_string(),
        tmpl_path,
        base.to_string(),
        query_pairs,
    )
}

fn collect_nested_json_keys(val: &Value, prefix: &str, out: &mut BTreeSet<String>) {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                out.insert(p.clone());
                collect_nested_json_keys(v, &p, out);
            }
        }
        Value::Array(arr) => {
            if let Some(first) = arr.first() {
                let p = format!("{prefix}[]");
                collect_nested_json_keys(first, &p, out);
            }
        }
        _ => {}
    }
}

fn is_auth_header_name(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    matches!(
        low.as_str(),
        "authorization" | "cookie" | "x-api-key" | "x-auth-token" | "x-csrf-token" | "x-xsrf-token"
    ) || low.contains("token")
        || low.contains("session")
}

fn should_keep_replay_header(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    !matches!(
        low.as_str(),
        "host"
            | "content-length"
            | "connection"
            | "accept-encoding"
            | ":authority"
            | ":method"
            | ":path"
            | ":scheme"
    )
}

pub fn parse_har_or_jsonl(raw: &str) -> Result<ParsedHarFlow, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("HAR/JSONL input is empty".to_string());
    }

    let mut raw_entries: Vec<Value> = Vec::new();
    if trimmed.starts_with('{') {
        let root: Value =
            serde_json::from_str(trimmed).map_err(|e| format!("invalid HAR JSON: {e}"))?;
        if let Some(arr) = root.pointer("/log/entries").and_then(Value::as_array) {
            raw_entries = arr.clone();
        } else if let Some(arr) = root.get("entries").and_then(Value::as_array) {
            raw_entries = arr.clone();
        } else {
            // Single JSON object entry or JSONL line
            raw_entries.push(root);
        }
    } else if trimmed.starts_with('[') {
        raw_entries =
            serde_json::from_str(trimmed).map_err(|e| format!("invalid JSON array: {e}"))?;
    } else {
        for line in trimmed.lines() {
            let l = line.trim();
            if l.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(l) {
                raw_entries.push(v);
            }
        }
    }

    let mut clusters: BTreeMap<(String, String, String), HarEndpointCluster> = BTreeMap::new();
    let mut ws_map: BTreeMap<String, HarWsFlow> = BTreeMap::new();

    for entry in raw_entries {
        let req = entry.get("request").unwrap_or(&entry);
        let url = req
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if url.is_empty() {
            continue;
        }
        let method = req
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();

        let mut headers = Vec::new();
        let mut auth_headers = BTreeSet::new();
        let mut upgrade_ws = false;
        if let Some(harr) = req.get("headers").and_then(Value::as_array) {
            for h in harr {
                let name = h.get("name").and_then(Value::as_str).unwrap_or("").trim();
                let val = h.get("value").and_then(Value::as_str).unwrap_or("").trim();
                if name.is_empty() {
                    continue;
                }
                if name.eq_ignore_ascii_case("upgrade") && val.eq_ignore_ascii_case("websocket") {
                    upgrade_ws = true;
                }
                if is_auth_header_name(name) {
                    auth_headers.insert(name.to_ascii_lowercase());
                }
                if should_keep_replay_header(name) {
                    headers.push(format!("{name}: {val}"));
                }
            }
        } else if let Some(hobj) = req.get("headers").and_then(Value::as_object) {
            for (name, val_v) in hobj {
                let val = val_v.as_str().unwrap_or("");
                if name.eq_ignore_ascii_case("upgrade") && val.eq_ignore_ascii_case("websocket") {
                    upgrade_ws = true;
                }
                if is_auth_header_name(name) {
                    auth_headers.insert(name.to_ascii_lowercase());
                }
                if should_keep_replay_header(name) {
                    headers.push(format!("{name}: {val}"));
                }
            }
        }

        let resp_status = entry
            .pointer("/response/status")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let kind_ws = entry
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|k| k.eq_ignore_ascii_case("ws"));
        let ws_msgs: Vec<String> = entry
            .get("_webSocketMessages")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter(|m| {
                        m.get("type")
                            .and_then(Value::as_str)
                            .map(|t| t == "send")
                            .unwrap_or(true)
                    })
                    .filter_map(|m| m.get("data").and_then(Value::as_str).map(|s| s.to_string()))
                    .take(4)
                    .collect()
            })
            .unwrap_or_default();

        if url.starts_with("ws://")
            || url.starts_with("wss://")
            || upgrade_ws
            || resp_status == 101
            || kind_ws
            || !ws_msgs.is_empty()
        {
            let ws_url = if url.starts_with("https://") {
                url.replacen("https://", "wss://", 1)
            } else if url.starts_with("http://") {
                url.replacen("http://", "ws://", 1)
            } else {
                url.clone()
            };
            let flow = ws_map.entry(ws_url.clone()).or_insert_with(|| HarWsFlow {
                url: ws_url,
                headers: headers.clone(),
                sample_frames: Vec::new(),
            });
            for m in ws_msgs {
                if !flow.sample_frames.contains(&m) && flow.sample_frames.len() < 8 {
                    flow.sample_frames.push(m);
                }
            }
            if let Some(frame) = entry.get("frame").and_then(Value::as_str) {
                if !frame.is_empty() && flow.sample_frames.len() < 8 {
                    flow.sample_frames.push(frame.to_string());
                }
            }
            if url.starts_with("ws://")
                || url.starts_with("wss://")
                || resp_status == 101
                || kind_ws
            {
                continue;
            }
        }

        let (host, path_template, _base_url, query_pairs) = split_url_parts(&url);
        let body_text = req
            .pointer("/postData/text")
            .and_then(Value::as_str)
            .or_else(|| req.get("body").and_then(Value::as_str))
            .map(|s| s.to_string());

        let mut schema_keys = BTreeSet::new();
        if let Some(bt) = &body_text {
            if let Ok(jv) = serde_json::from_str::<Value>(bt) {
                collect_nested_json_keys(&jv, "", &mut schema_keys);
            }
        }

        let key = (method.clone(), host.clone(), path_template.clone());
        let cl = clusters.entry(key).or_insert_with(|| HarEndpointCluster {
            method,
            host,
            path_template,
            sample_url: url.clone(),
            count: 0,
            auth_headers: Vec::new(),
            sample_headers: headers.clone(),
            query_keys: Vec::new(),
            json_schema_keys: Vec::new(),
            sample_body: body_text.clone(),
        });
        cl.count += 1;
        for ah in auth_headers {
            if !cl.auth_headers.contains(&ah) {
                cl.auth_headers.push(ah);
            }
        }
        for (qk, _) in query_pairs {
            if !cl.query_keys.contains(&qk) {
                cl.query_keys.push(qk);
            }
        }
        for sk in schema_keys {
            if !cl.json_schema_keys.contains(&sk) {
                cl.json_schema_keys.push(sk);
            }
        }
        if cl.sample_body.is_none() && body_text.is_some() {
            cl.sample_body = body_text;
        }
    }

    Ok(ParsedHarFlow {
        endpoints: clusters.into_values().collect(),
        ws_flows: ws_map.into_values().collect(),
    })
}

fn mutate_json_leaf_at_path(root: &mut Value, path: &str, replacement: Value) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    fn inner(cur: &mut Value, parts: &[&str], replacement: Value) -> bool {
        if parts.is_empty() {
            return false;
        }
        let seg = parts[0];
        let (key, is_arr) = if let Some(stripped) = seg.strip_suffix("[]") {
            (stripped, true)
        } else {
            (seg, false)
        };
        let Some(obj) = cur.as_object_mut() else {
            return false;
        };
        let Some(child) = obj.get_mut(key) else {
            return false;
        };
        if parts.len() == 1 {
            if child.is_object() || child.is_array() {
                return false;
            }
            *child = replacement;
            return true;
        }
        if is_arr {
            if let Some(arr) = child.as_array_mut() {
                if let Some(first) = arr.first_mut() {
                    return inner(first, &parts[1..], replacement);
                }
            }
            return false;
        }
        inner(child, &parts[1..], replacement)
    }
    inner(root, &parts, replacement)
}

#[derive(Debug, Clone, Serialize)]
pub struct FuzzVariant {
    pub kind: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<String>,
    pub body: Option<String>,
    pub note: String,
}

pub fn build_schema_fuzz_variants(
    ep: &HarEndpointCluster,
    max_variants: usize,
    extra_principal_headers: &[String],
) -> Vec<FuzzVariant> {
    let mut variants = Vec::new();
    let base_headers = ep.sample_headers.clone();

    // 1. Cross-principal / unauthenticated replay (if auth headers present)
    if !ep.auth_headers.is_empty() {
        let stripped: Vec<String> = base_headers
            .iter()
            .filter(|h| {
                let nm = h.split(':').next().unwrap_or("").trim();
                !is_auth_header_name(nm)
            })
            .cloned()
            .collect();
        variants.push(FuzzVariant {
            kind: "unauth_replay".to_string(),
            method: ep.method.clone(),
            url: ep.sample_url.clone(),
            headers: stripped,
            body: ep.sample_body.clone(),
            note: format!("stripped auth headers [{}]", ep.auth_headers.join(",")),
        });
    }

    if !extra_principal_headers.is_empty() {
        let mut swapped: Vec<String> = base_headers
            .iter()
            .filter(|h| {
                let nm = h.split(':').next().unwrap_or("").trim();
                !is_auth_header_name(nm)
            })
            .cloned()
            .collect();
        swapped.extend(extra_principal_headers.iter().cloned());
        variants.push(FuzzVariant {
            kind: "cross_principal_replay".to_string(),
            method: ep.method.clone(),
            url: ep.sample_url.clone(),
            headers: swapped,
            body: ep.sample_body.clone(),
            note: "replayed with caller-supplied --principal headers".to_string(),
        });
    }

    // 2. HTTP Parameter Pollution (HPP) on first query key if present
    if let Some(first_qk) = ep.query_keys.first() {
        let sep = if ep.sample_url.contains('?') {
            '&'
        } else {
            '?'
        };
        variants.push(FuzzVariant {
            kind: "hpp_duplicate_param".to_string(),
            method: ep.method.clone(),
            url: format!("{}{}{}={}", ep.sample_url, sep, first_qk, "0"),
            headers: base_headers.clone(),
            body: ep.sample_body.clone(),
            note: format!("duplicated query param `{first_qk}` for HPP check"),
        });
    }

    // 3. Nested JSON leaf mutation + mass-assignment / privilege field injection
    if let Some(body) = &ep.sample_body {
        if let Ok(root_val) = serde_json::from_str::<Value>(body) {
            if let Some(mut obj) = root_val.as_object().cloned() {
                for inject_key in ["role", "isAdmin", "admin"] {
                    if !obj.contains_key(inject_key) {
                        let val = if inject_key == "role" {
                            Value::String("admin".to_string())
                        } else {
                            Value::Bool(true)
                        };
                        obj.insert(inject_key.to_string(), val);
                        variants.push(FuzzVariant {
                            kind: "mass_assignment".to_string(),
                            method: ep.method.clone(),
                            url: ep.sample_url.clone(),
                            headers: base_headers.clone(),
                            body: Some(Value::Object(obj.clone()).to_string()),
                            note: format!("injected `{inject_key}` into JSON payload"),
                        });
                        obj.remove(inject_key);
                        break;
                    }
                }
            }

            // Mutate leaf fields at depth (type confusion / sentinel probe)
            for key_path in &ep.json_schema_keys {
                if variants.len() >= max_variants {
                    break;
                }
                let mut cloned = root_val.clone();
                if mutate_json_leaf_at_path(&mut cloned, key_path, Value::String("0".to_string())) {
                    variants.push(FuzzVariant {
                        kind: "nested_key_fuzz".to_string(),
                        method: ep.method.clone(),
                        url: ep.sample_url.clone(),
                        headers: base_headers.clone(),
                        body: Some(cloned.to_string()),
                        note: format!("mutated nested JSON key `{key_path}`"),
                    });
                }
            }
        }
    }

    variants.truncate(max_variants);
    variants
}

pub struct HarProbeConfig<'a> {
    pub har_path: &'a str,
    pub fuzz_schema: bool,
    pub dry_run: bool,
    pub max_variants: usize,
    pub rate_ms: u64,
    pub principal_headers: &'a [String],
    pub sentinels: &'a [String],
    pub timeout_sec: u64,
    pub insecure: bool,
    pub follow: bool,
    pub as_json: bool,
}

pub fn run_http_from_har(cfg: HarProbeConfig<'_>) -> i32 {
    let HarProbeConfig {
        har_path,
        fuzz_schema,
        dry_run,
        max_variants,
        rate_ms,
        principal_headers,
        sentinels,
        timeout_sec,
        insecure,
        follow,
        as_json,
    } = cfg;
    let raw = match fs::read_to_string(Path::new(har_path)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ap probe http --from-har: failed to read `{har_path}`: {e}");
            return 2;
        }
    };
    let parsed = match parse_har_or_jsonl(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ap probe http --from-har: {e}");
            return 2;
        }
    };

    let mut endpoint_reports: Vec<Value> = Vec::new();
    let mut findings_total = 0usize;

    for ep in &parsed.endpoints {
        let variants = if fuzz_schema {
            build_schema_fuzz_variants(ep, max_variants.max(1), principal_headers)
        } else {
            Vec::new()
        };

        if dry_run {
            endpoint_reports.push(json!({
                "method": ep.method,
                "host": ep.host,
                "path_template": ep.path_template,
                "sample_url": ep.sample_url,
                "count": ep.count,
                "auth_headers": ep.auth_headers,
                "query_keys": ep.query_keys,
                "json_schema_keys": ep.json_schema_keys,
                "planned_variants": variants,
            }));
            continue;
        }

        // Execute baseline + schema variants safely (rate limited)
        let base_res: HttpProbeResult = execute_http_probe(
            &ep.method,
            &ep.sample_url,
            &ep.sample_headers,
            ep.sample_body.as_deref(),
            timeout_sec,
            insecure,
            follow,
        );
        let mut variant_results = Vec::new();
        for v in variants {
            if rate_ms > 0 {
                thread::sleep(Duration::from_millis(rate_ms));
            }
            let cand = execute_http_probe(
                &v.method,
                &v.url,
                &v.headers,
                v.body.as_deref(),
                timeout_sec,
                insecure,
                follow,
            );
            let diff = classify_auth_matrix_diff_deep(&base_res, &cand, sentinels);
            if diff.possible_bypass || !diff.sentinel_hits.is_empty() || cand.status >= 500 {
                findings_total += 1;
            }
            variant_results.push(json!({
                "kind": v.kind,
                "note": v.note,
                "status": cand.status,
                "error": cand.error,
                "verdict": diff.verdict,
                "possible_bypass": diff.possible_bypass,
                "reason": diff.reason,
                "sentinel_hits": diff.sentinel_hits,
                "body_preview": cand.body_preview.chars().take(180).collect::<String>(),
            }));
        }

        endpoint_reports.push(json!({
            "method": ep.method,
            "host": ep.host,
            "path_template": ep.path_template,
            "sample_url": ep.sample_url,
            "auth_headers": ep.auth_headers,
            "json_schema_keys": ep.json_schema_keys,
            "baseline_status": base_res.status,
            "baseline_error": base_res.error,
            "variants": variant_results,
        }));
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "har_path": har_path,
                "dry_run": dry_run,
                "fuzz_schema": fuzz_schema,
                "endpoint_clusters": parsed.endpoints.len(),
                "ws_flows_detected": parsed.ws_flows.len(),
                "notable_findings": findings_total,
                "endpoints": endpoint_reports,
            }))
            .unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("# HAR HTTP Schema & Differential Probe (`{har_path}`)");
        println!(
            "- Endpoint clusters: `{}` | WebSocket flows: `{}` | Notable findings: `{}` | Mode: `{}`\n",
            parsed.endpoints.len(),
            parsed.ws_flows.len(),
            findings_total,
            if dry_run { "dry-run" } else { "live-probe" }
        );
        for ep in &endpoint_reports {
            println!(
                "## {} `{}` (`{}`)",
                ep["method"].as_str().unwrap_or("GET"),
                ep["path_template"].as_str().unwrap_or("/"),
                ep["sample_url"].as_str().unwrap_or("")
            );
            if let Some(keys) = ep["json_schema_keys"].as_array().filter(|a| !a.is_empty()) {
                let ks: Vec<&str> = keys.iter().filter_map(Value::as_str).collect();
                println!("- JSON Schema keys: [{}]", ks.join(", "));
            }
            if let Some(pv) = ep["planned_variants"].as_array() {
                for v in pv {
                    println!(
                        "  - [planned] `{}`: {} -> {} {}",
                        v["kind"].as_str().unwrap_or(""),
                        v["note"].as_str().unwrap_or(""),
                        v["method"].as_str().unwrap_or(""),
                        v["url"].as_str().unwrap_or(""),
                    );
                }
            }
            if let Some(vs) = ep["variants"].as_array() {
                println!(
                    "- Baseline status: `{}`",
                    ep["baseline_status"].as_u64().unwrap_or(0)
                );
                for v in vs {
                    println!(
                        "  - `{}` ({}) -> HTTP `{}` verdict=`{}` bypass={}",
                        v["kind"].as_str().unwrap_or(""),
                        v["note"].as_str().unwrap_or(""),
                        v["status"].as_u64().unwrap_or(0),
                        v["verdict"].as_str().unwrap_or(""),
                        v["possible_bypass"].as_bool().unwrap_or(false),
                    );
                }
            }
        }
    }
    0
}

pub fn run_ws_replay_har(
    har_path: &str,
    send_extra: &[String],
    origins: &[String],
    origin_matrix: bool,
    wait_ms: u64,
    as_json: bool,
) -> i32 {
    let raw = match fs::read_to_string(Path::new(har_path)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ap probe ws --replay-har: failed to read `{har_path}`: {e}");
            return 2;
        }
    };
    let parsed = match parse_har_or_jsonl(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ap probe ws --replay-har: {e}");
            return 2;
        }
    };
    if parsed.ws_flows.is_empty() {
        if as_json {
            println!("{}", json!({ "har_path": har_path, "ws_flows": 0 }));
        } else {
            println!("No WebSocket handshakes or frames found in `{har_path}`.");
        }
        return 0;
    }

    let mut worst_exit = 0i32;
    for flow in &parsed.ws_flows {
        let mut frames = flow.sample_frames.clone();
        frames.extend(send_extra.iter().cloned());
        if origin_matrix || !origins.is_empty() {
            let rc =
                run_ws_origin_matrix(&flow.url, &frames, &flow.headers, origins, wait_ms, as_json);
            if rc != 0 {
                worst_exit = rc;
            }
        } else {
            let rc = run_ws_cli(&flow.url, &frames, &flow.headers, wait_ms, as_json);
            if rc != 0 {
                worst_exit = rc;
            }
        }
    }
    worst_exit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_har_clusters_nested_json_and_builds_fuzz_variants() {
        let har = json!({
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.test/v1/orders/12345/update?expand=items",
                            "headers": [
                                {"name": "Authorization", "value": "Bearer tok_a"},
                                {"name": "Content-Type", "value": "application/json"}
                            ],
                            "postData": {
                                "text": "{\"user\":{\"id\":42,\"name\":\"alice\"},\"amount\":100}"
                            }
                        },
                        "response": { "status": 200 }
                    },
                    {
                        "request": {
                            "method": "GET",
                            "url": "wss://ws.example.test/stream",
                            "headers": [
                                {"name": "Cookie", "value": "sid=abc"}
                            ]
                        },
                        "response": { "status": 101 },
                        "_webSocketMessages": [
                            {"type": "send", "data": "{\"op\":\"subscribe\"}"}
                        ]
                    }
                ]
            }
        });

        let parsed = parse_har_or_jsonl(&har.to_string()).unwrap();
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.path_template, "/v1/orders/{id}/update");
        assert!(ep.json_schema_keys.contains(&"user.id".to_string()));
        assert!(ep.json_schema_keys.contains(&"amount".to_string()));
        assert!(ep.auth_headers.contains(&"authorization".to_string()));

        let variants =
            build_schema_fuzz_variants(ep, 8, &["Authorization: Bearer tok_b".to_string()]);
        assert!(variants.iter().any(|v| v.kind == "unauth_replay"));
        assert!(variants.iter().any(|v| v.kind == "cross_principal_replay"));
        assert!(variants.iter().any(|v| v.kind == "hpp_duplicate_param"));
        assert!(variants.iter().any(|v| v.kind == "mass_assignment"));
        assert!(variants.iter().any(|v| v.kind == "nested_key_fuzz"));

        assert_eq!(parsed.ws_flows.len(), 1);
        assert_eq!(parsed.ws_flows[0].url, "wss://ws.example.test/stream");
        assert_eq!(
            parsed.ws_flows[0].sample_frames,
            vec!["{\"op\":\"subscribe\"}"]
        );
    }
}
