use crate::smoke::{
    auto_detect_start_cmd, http_request, kill_process_tree, pick_free_port,
    spawn_detached_logged_server,
};
use ignore::WalkBuilder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzFailure {
    pub category: String,
    pub target: String,
    pub status: i32,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzReport {
    pub ok: bool,
    pub mode: String,
    pub probes_executed: usize,
    pub elapsed_ms: f64,
    pub discovered_routes: Vec<String>,
    pub failures: Vec<FuzzFailure>,
}

fn fuzz_regexes() -> &'static (Regex, Regex, Regex, Regex) {
    static RE: OnceLock<(Regex, Regex, Regex, Regex)> = OnceLock::new();
    RE.get_or_init(|| {
        let fw = Regex::new(
            r#"(?i)\b(?:app|router|server|api|bp)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`](/[^'"`\s)]*)['"`]"#,
        )
        .unwrap();
        let api_lit = Regex::new(r#"['"`](/api/[A-Za-z0-9_/:.{}-]+)['"`]"#).unwrap();
        let field_re = Regex::new(
            r#"(?:body\.([A-Za-z_]\w*)|\{\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*\}\s*=\s*(?:req\.)?(?:body|data|payload)|get\(\s*['"]([A-Za-z_]\w*)['"]\s*\))"#,
        )
        .unwrap();
        let param_re = Regex::new(r":([A-Za-z0-9_]+)|\{([A-Za-z0-9_]+)\}").unwrap();
        (fw, api_lit, field_re, param_re)
    })
}

fn discover_routes_and_fields(cwd: &Path) -> (Vec<(String, String)>, Vec<String>) {
    let (fw_re, api_lit_re, field_re, param_re) = fuzz_regexes();
    let mut routes = BTreeSet::new();
    let mut fields = BTreeSet::new();
    let walker = WalkBuilder::new(cwd)
        .git_ignore(true)
        .max_depth(Some(4))
        .build();
    for entry in walker.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let ext = entry
            .path()
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if !matches!(
            ext,
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "py" | "go" | "rs"
        ) {
            continue;
        }
        let rel_low = entry.path().to_string_lossy().to_ascii_lowercase();
        if rel_low.contains(".test.") || rel_low.contains(".spec.") {
            continue;
        }
        let Ok(txt) = fs::read_to_string(entry.path()) else {
            continue;
        };
        for cap in fw_re.captures_iter(&txt) {
            let m = cap[1].to_ascii_uppercase();
            let p = param_re.replace_all(&cap[2], "1").to_string();
            routes.insert((m, p));
        }
        let lines: Vec<&str> = txt.lines().collect();
        for (li, ln) in lines.iter().enumerate() {
            for cap in api_lit_re.captures_iter(ln) {
                let p = param_re.replace_all(&cap[1], "1").to_string();
                let ctx = lines[li.saturating_sub(2)..(li + 3).min(lines.len())].join(" ");
                let mut matched_m = false;
                for m in ["POST", "PUT", "PATCH", "DELETE", "GET"] {
                    if ctx.contains(&format!("'{m}'")) || ctx.contains(&format!("\"{m}\"")) {
                        routes.insert((m.to_string(), p.clone()));
                        matched_m = true;
                    }
                }
                if !matched_m {
                    routes.insert(("POST".to_string(), p.clone()));
                    routes.insert(("GET".to_string(), p));
                }
            }
        }
        for cap in field_re.captures_iter(&txt) {
            for g in [1, 2, 3] {
                if let Some(m) = cap.get(g) {
                    for part in m.as_str().split(',') {
                        let f = part.trim();
                        if !f.is_empty() && f.len() <= 32 {
                            fields.insert(f.to_string());
                        }
                    }
                }
            }
        }
    }
    if routes.is_empty() {
        routes.insert(("GET".to_string(), "/".to_string()));
    }
    if fields.is_empty() {
        for d in ["id", "name", "amount", "count"] {
            fields.insert(d.to_string());
        }
    }
    (routes.into_iter().collect(), fields.into_iter().collect())
}

fn is_numeric_field(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    [
        "amount", "price", "qty", "quantity", "count", "stock", "total", "cents", "limit", "rate",
        "balance", "score", "age",
    ]
    .iter()
    .any(|k| low.contains(k))
}

fn run_cli_fuzz(cwd: &Path, cli_cmd: &str, as_json: bool) -> i32 {
    let t0 = Instant::now();
    let cases: &[(&str, &str, &str)] = &[
        ("empty-args", "", ""),
        ("help-flag", "--help", ""),
        ("unknown-flag", "--__ap_unknown_flag_99__", ""),
        ("missing-file", "__ap_nonexistent_input_99__.json", ""),
        ("cjk-quote-arg", "\"中文 空格'测试\"", ""),
        ("malformed-stdin", "", "{\"truncated_json\": [1, 2"),
    ];
    let mut failures = Vec::new();
    for &(label, extra_arg, stdin_payload) in cases {
        let full = if extra_arg.is_empty() {
            cli_cmd.to_string()
        } else {
            format!("{cli_cmd} {extra_arg}")
        };
        let mut child_cmd = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/C", &full]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", &full]);
            c
        };
        if let Ok(mut ch) = child_cmd
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            let mut job = crate::smoke::ProbeJobGuard::attach(&ch);
            if let Some(mut sin) = ch.stdin.take() {
                let _ = sin.write_all(stdin_payload.as_bytes());
            }
            let out_p = ch.stdout.take();
            let err_p = ch.stderr.take();
            let out_h = thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(mut r) = out_p {
                    let _ = std::io::Read::read_to_end(&mut r, &mut buf);
                }
                buf
            });
            let err_h = thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(mut r) = err_p {
                    let _ = std::io::Read::read_to_end(&mut r, &mut buf);
                }
                buf
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut timed_out = false;
            let exit_code = loop {
                match ch.try_wait() {
                    Ok(Some(st)) => break st.code().unwrap_or(1),
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            timed_out = true;
                            drop(job.take());
                            kill_process_tree(&mut ch);
                            break 124;
                        }
                        thread::sleep(Duration::from_millis(15));
                    }
                    Err(_) => {
                        drop(job.take());
                        kill_process_tree(&mut ch);
                        break 1;
                    }
                }
            };
            drop(job);
            let stdout_b = out_h.join().unwrap_or_default();
            let stderr_b = err_h.join().unwrap_or_default();
            if timed_out {
                failures.push(FuzzFailure {
                    category: format!("cli-{label}"),
                    target: full,
                    status: 124,
                    detail: "CLI fuzz probe timed out after 10s (killed process tree)".to_string(),
                });
            } else {
                let comb = format!(
                    "{}\n{}",
                    String::from_utf8_lossy(&stdout_b),
                    String::from_utf8_lossy(&stderr_b)
                );
                let crashed = exit_code >= 128
                    || comb.contains("panicked at")
                    || comb.contains("Traceback (most recent call last)")
                    || comb.contains("TypeError:")
                    || comb.contains("ReferenceError:");
                if crashed {
                    let first_err = comb.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
                    failures.push(FuzzFailure {
                        category: format!("cli-{label}"),
                        target: full,
                        status: exit_code,
                        detail: first_err.chars().take(160).collect(),
                    });
                }
            }
        }
    }
    emit_fuzz_report(
        FuzzReport {
            ok: failures.is_empty(),
            mode: "cli".to_string(),
            probes_executed: cases.len(),
            elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0).round(),
            discovered_routes: Vec::new(),
            failures,
        },
        as_json,
    )
}

fn emit_fuzz_err(as_json: bool, msg: &str) {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "ok": false, "error": msg })).unwrap_or_default()
        );
    } else {
        eprintln!("{msg}");
    }
}

pub fn run_fuzz(
    cwd: &Path,
    start_opt: Option<&str>,
    url_opt: Option<&str>,
    cli_opt: Option<&str>,
    concurrency: usize,
    as_json: bool,
) -> i32 {
    if let Some(cli_cmd) = cli_opt.filter(|s| !s.trim().is_empty()) {
        return run_cli_fuzz(cwd, cli_cmd, as_json);
    }
    let t0 = Instant::now();
    let (routes, fields) = discover_routes_and_fields(cwd);
    let mut child_opt: Option<Child> = None;
    let mut _child_job: Option<crate::smoke::ProbeJobGuard> = None;
    let pid = std::process::id();
    let out_f = std::env::temp_dir().join(format!("ap_fuzz_{pid}.out.log"));
    let err_f = std::env::temp_dir().join(format!("ap_fuzz_{pid}.err.log"));

    let base_url = if let Some(u) = url_opt.filter(|s| !s.trim().is_empty()) {
        u.trim_end_matches('/').to_string()
    } else {
        let Some(sc) = start_opt
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .or_else(|| auto_detect_start_cmd(cwd))
        else {
            emit_fuzz_err(
                as_json,
                "[probe fuzz] Provide --start \"<cmd>\", --url http://..., or --cli \"<cmd>\"",
            );
            return 2;
        };
        let Ok(port) = pick_free_port() else {
            emit_fuzz_err(as_json, "[probe fuzz] Failed to allocate a free local port");
            return 2;
        };
        match spawn_detached_logged_server(&sc, cwd, port, &[], &out_f, &err_f) {
            Ok(ch) => {
                _child_job = crate::smoke::ProbeJobGuard::attach(&ch);
                child_opt = Some(ch);
            }
            Err(e) => {
                emit_fuzz_err(as_json, &format!("[probe fuzz] {e}"));
                return 1;
            }
        }
        format!("http://127.0.0.1:{port}")
    };

    let deadline = Instant::now() + Duration::from_millis(8000);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Ok((st, _, _)) = http_request(&base_url, "GET", "/", &[], None, 600) {
            if st > 0 {
                ready = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    let mut failures = Vec::new();
    let mut probes = 0usize;

    if !ready {
        failures.push(FuzzFailure {
            category: "startup".to_string(),
            target: base_url.clone(),
            status: 0,
            detail: "Server failed to become reachable within 8s".to_string(),
        });
    } else {
        let mut write_targets: Vec<(String, String)> = routes
            .iter()
            .filter(|(m, _)| matches!(m.as_str(), "POST" | "PUT" | "PATCH"))
            .take(6)
            .cloned()
            .collect();
        if write_targets.is_empty() {
            write_targets.push(("POST".to_string(), "/api/test".to_string()));
        }

        // Build boundary & injection payloads from discovered field names
        let mut neg_obj = serde_json::Map::new();
        let mut zero_obj = serde_json::Map::new();
        let mut inj_obj = serde_json::Map::new();
        for f in &fields {
            if is_numeric_field(f) {
                neg_obj.insert(f.clone(), json!(-100));
                zero_obj.insert(f.clone(), json!(0));
                inj_obj.insert(f.clone(), json!("NaN"));
            } else {
                neg_obj.insert(f.clone(), json!(""));
                zero_obj.insert(f.clone(), json!("   "));
                inj_obj.insert(f.clone(), json!("中文🚀'\"<script>;--DROP TABLE users;"));
            }
        }
        let neg_s = Value::Object(neg_obj).to_string();
        let zero_s = Value::Object(zero_obj).to_string();
        let inj_s = Value::Object(inj_obj).to_string();

        let mut matrix: Vec<(&str, String, String, Option<String>)> = vec![
            (
                "404-resilience",
                "GET".into(),
                "/api/__ap_nonexistent_99__".into(),
                None,
            ),
            (
                "traversal-guard",
                "GET".into(),
                "/..%2f..%2fpackage.json".into(),
                None,
            ),
        ];
        for (wm, wp) in &write_targets {
            matrix.push((
                "truncated-json",
                wm.clone(),
                wp.clone(),
                Some("{\"broken\": [1,".into()),
            ));
            matrix.push(("empty-body", wm.clone(), wp.clone(), Some(String::new())));
            matrix.push(("null-json", wm.clone(), wp.clone(), Some("null".into())));
            matrix.push((
                "negative-boundary",
                wm.clone(),
                wp.clone(),
                Some(neg_s.clone()),
            ));
            matrix.push((
                "zero-whitespace",
                wm.clone(),
                wp.clone(),
                Some(zero_s.clone()),
            ));
            matrix.push((
                "nan-unicode-sqli",
                wm.clone(),
                wp.clone(),
                Some(inj_s.clone()),
            ));
        }
        for (m, p) in &routes {
            if m == "GET" || m == "DELETE" {
                matrix.push(("route-sweep", m.clone(), p.clone(), None));
            }
        }

        for (cat, m, p, body) in &matrix {
            probes += 1;
            match http_request(&base_url, m, p, &[], body.as_deref(), 2000) {
                Ok((st, _, resp_body)) => {
                    if st >= 500 {
                        failures.push(FuzzFailure {
                            category: (*cat).to_string(),
                            target: format!("{m} {p}"),
                            status: st as i32,
                            detail: format!(
                                "HTTP {st} server error: {}",
                                resp_body.chars().take(120).collect::<String>()
                            ),
                        });
                    } else if resp_body.contains(":NaN")
                        || resp_body.contains("\"NaN\"")
                        || resp_body.contains("[object Object]")
                    {
                        failures.push(FuzzFailure {
                            category: format!("{cat}-nan-leak"),
                            target: format!("{m} {p}"),
                            status: st as i32,
                            detail: format!(
                                "Response leaked NaN/[object Object]: {}",
                                resp_body.chars().take(120).collect::<String>()
                            ),
                        });
                    }
                }
                Err(e) => {
                    failures.push(FuzzFailure {
                        category: format!("{cat}-crash"),
                        target: format!("{m} {p}"),
                        status: -1,
                        detail: format!("Server dropped connection / crashed: {e}"),
                    });
                    break;
                }
            }
        }

        // Simultaneous Barrier Concurrency Burst
        let burst_n = concurrency.clamp(2, 24);
        let barrier = Arc::new(Barrier::new(burst_n));
        let burst_target = routes
            .first()
            .cloned()
            .unwrap_or(("GET".into(), "/".into()));
        let burst_body = if matches!(burst_target.0.as_str(), "POST" | "PUT" | "PATCH") {
            Some(json!({"id": "race-1", "name": "burst", "amount": 10, "count": 1}).to_string())
        } else {
            None
        };
        let mut handles = Vec::with_capacity(burst_n);
        for _ in 0..burst_n {
            let b = Arc::clone(&barrier);
            let u = base_url.clone();
            let (m, p) = burst_target.clone();
            let bd = burst_body.clone();
            handles.push(thread::spawn(move || {
                b.wait();
                http_request(&u, &m, &p, &[], bd.as_deref(), 3000)
            }));
        }
        probes += burst_n;
        for h in handles {
            match h.join().unwrap_or_else(|_| Err("thread panic".into())) {
                Ok((st, _, b)) if st >= 500 => {
                    failures.push(FuzzFailure {
                        category: "concurrency-race-500".to_string(),
                        target: format!(
                            "{}x parallel {} {}",
                            burst_n, burst_target.0, burst_target.1
                        ),
                        status: st as i32,
                        detail: b.chars().take(120).collect(),
                    });
                    break;
                }
                Err(e) => {
                    failures.push(FuzzFailure {
                        category: "concurrency-crash".to_string(),
                        target: format!(
                            "{}x parallel {} {}",
                            burst_n, burst_target.0, burst_target.1
                        ),
                        status: -1,
                        detail: e,
                    });
                    break;
                }
                _ => {}
            }
        }

        if let Ok(err_txt) = fs::read_to_string(&err_f) {
            for kw in [
                "UnhandledPromiseRejection",
                "SQLITE_BUSY",
                "Traceback (most recent call last)",
                "panicked at",
            ] {
                if err_txt.contains(kw) {
                    failures.push(FuzzFailure {
                        category: "stderr-unhandled".to_string(),
                        target: "server stderr".to_string(),
                        status: 500,
                        detail: format!("Detected `{kw}` in server stderr during fuzzing"),
                    });
                }
            }
        }
    }

    if let Some(mut ch) = child_opt {
        kill_process_tree(&mut ch);
    }
    let _ = fs::remove_file(&out_f);
    let _ = fs::remove_file(&err_f);

    emit_fuzz_report(
        FuzzReport {
            ok: failures.is_empty(),
            mode: "http+concurrency".to_string(),
            probes_executed: probes,
            elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0).round(),
            discovered_routes: routes
                .into_iter()
                .map(|(m, p)| format!("{m} {p}"))
                .collect(),
            failures,
        },
        as_json,
    )
}

fn emit_fuzz_report(rep: FuzzReport, as_json: bool) -> i32 {
    let ok = rep.ok;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
    } else if ok {
        println!(
            "[probe fuzz] PASS — {} adversarial/concurrency probes clean in {}ms (routes: {:?})",
            rep.probes_executed, rep.elapsed_ms, rep.discovered_routes
        );
    } else {
        println!(
            "[probe fuzz] FAIL — {} bug(s) exposed across {} probes in {}ms:",
            rep.failures.len(),
            rep.probes_executed,
            rep.elapsed_ms
        );
        for f in &rep.failures {
            println!(
                "  - [{}] `{}` (status {}): {}",
                f.category, f.target, f.status, f.detail
            );
        }
    }
    if ok {
        0
    } else {
        1
    }
}
