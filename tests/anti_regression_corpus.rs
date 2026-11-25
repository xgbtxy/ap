use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

fn ap_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ap"))
}

fn run_ap(
    cwd: &Path,
    args: &[&str],
    stdin_data: Option<&str>,
    extra_env: &[(&str, &Path)],
) -> Output {
    let mut cmd = Command::new(ap_bin());
    cmd.args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().expect("failed to spawn ap binary");
    if let Some(input) = stdin_data {
        if let Some(mut sin) = child.stdin.take() {
            sin.write_all(input.as_bytes())
                .expect("failed to write stdin");
        }
    }
    child
        .wait_with_output()
        .expect("failed to wait on ap binary")
}

#[test]
fn corpus_01_baton_frontier_contrast_and_upsert_invariants() {
    use ap_baton::frontier::{
        load_frontier, save_frontier, seed_from_json_str, sync_stopped_from_text, FrontierState,
        FrontierStatus,
    };

    let td = TempDir::new().unwrap();
    let store_path = td.path().join("frontier.json");
    let mut state = FrontierState::default();

    let seed_payload = json!({
        "items": [
            {
                "id": "web_api:rbac",
                "axis": "web_api_route",
                "module": "src/auth",
                "target": "src/auth/rbac.ts",
                "line": 28,
                "symbol": "verifyAdminRole",
                "guard_hint": "UNGUARDED",
                "score": 91
            },
            {
                "id": "ipc_pipe:ctl",
                "axis": "ipc_pipe_proto",
                "module": "src/rpc",
                "target": "server.js",
                "line": 14,
                "symbol": "handle",
                "guard_hint": "UNGUARDED",
                "score": 84
            },
            {
                "id": "exec_spawn:job",
                "axis": "exec_spawn",
                "module": "src/worker",
                "target": "src/worker/job_runner.ts",
                "line": 55,
                "symbol": "dispatchWorkerJob",
                "guard_hint": "PARAM_TAINTED",
                "score": 89
            }
        ]
    });
    let (added, skipped) = seed_from_json_str(&mut state, &seed_payload.to_string()).unwrap();
    assert_eq!(added, 3);
    assert_eq!(skipped, 0);

    // Multi-section Markdown with blank lines after contrast headings, generic prose tokens,
    // and only ONE real confirmed stop (`src/worker/job_runner.ts` / `dispatchWorkerJob`).
    let markdown_notes = "\
# Session Investigation Ledger

## Contrast / Differentiation

- Distinct from `src/auth/rbac.ts` (`verifyAdminRole`): that endpoint enforces role checks.
- Do not confuse `server.js` (`handle`) with the worker queue path.

## Dedup Exclusion

`src/auth/rbac.ts` verifyAdminRole reviewed in earlier contrast table only.

## Generic Architecture Notes

The proxy listener accepts admin token auth params on http port listen control fastfail route.
server.js handle requests for user status error check info data list create update delete.

## Confirmed Findings

- Stopped `src/worker/job_runner.ts` (`dispatchWorkerJob`): static command array, zero user taint.
";
    let newly_stopped = sync_stopped_from_text(&mut state, "notes.md", markdown_notes);
    assert_eq!(newly_stopped, 1, "only exact confirmed target should stop");
    assert_eq!(state.items[0].status, FrontierStatus::Unvisited);
    assert_eq!(state.items[1].status, FrontierStatus::Unvisited);
    assert_eq!(state.items[2].status, FrontierStatus::Stopped);

    // Re-ingesting updated metadata updates line/score/guard_hint while keeping Stopped status.
    let updated_payload = json!({
        "items": [
            {
                "id": "web_api:rbac",
                "axis": "web_api_route",
                "module": "src/auth",
                "target": "src/auth/rbac.ts",
                "line": 44,
                "symbol": "verifyAdminRole",
                "guard_hint": "PARAM_TAINTED",
                "score": 97
            },
            {
                "id": "exec_spawn:job",
                "axis": "exec_spawn",
                "module": "src/worker",
                "target": "src/worker/job_runner.ts",
                "line": 61,
                "symbol": "dispatchWorkerJob",
                "guard_hint": "CONST_LITERAL",
                "score": 93
            }
        ]
    });
    seed_from_json_str(&mut state, &updated_payload.to_string()).unwrap();
    assert_eq!(state.items[0].line, 44);
    assert_eq!(state.items[0].score, 97);
    assert_eq!(state.items[0].guard_hint, "PARAM_TAINTED");
    assert_eq!(state.items[2].status, FrontierStatus::Stopped);
    assert_eq!(state.items[2].line, 61);
    assert_eq!(state.items[2].score, 93);

    save_frontier(&store_path, &mut state).unwrap();
    save_frontier(&store_path, &mut state).unwrap();
    let reloaded = load_frontier(&store_path);
    assert_eq!(reloaded.items.len(), 3);
    assert_eq!(reloaded.items[0].line, 44);
    assert_eq!(reloaded.items[2].status, FrontierStatus::Stopped);
}

fn read_http_req_wire(stream: &mut std::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let hdr = String::from_utf8_lossy(&buf[..pos]);
                    let clen = hdr
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if buf.len() >= pos + 4 + clen {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
fn corpus_02_probe_http_large_json_diff_race_chunked_ipv6_and_ws() {
    let td = TempDir::new().unwrap();
    let big_pad = "p".repeat(4200);

    // 1. Loopback HTTP server: >4KB JSON with volatile fields, tail semantic diff, and chunked race endpoint.
    let http_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    let stop_http = Arc::new(AtomicBool::new(false));
    let stop_http_c = Arc::clone(&stop_http);
    let seq = Arc::new(AtomicUsize::new(0));
    let seq_c = Arc::clone(&seq);
    let pad_c = big_pad.clone();

    let http_srv = thread::spawn(move || {
        let _ = http_listener.set_nonblocking(true);
        while !stop_http_c.load(Ordering::Relaxed) {
            match http_listener.accept() {
                Ok((mut s, _)) => {
                    let _ = s.set_nonblocking(false);
                    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                    let req = read_http_req_wire(&mut s);
                    let first = req.lines().next().unwrap_or("");
                    let path = first.split_whitespace().nth(1).unwrap_or("/");
                    let n = seq_c.fetch_add(1, Ordering::Relaxed) + 1;
                    let ts = 1_700_000_000 + n;

                    if path.starts_with("/chunked-race") {
                        let json_body = format!(r#"{{"id":"race_{n}","ok":true,"pad":"{pad_c}"}}"#);
                        let chunk_hdr = format!("{:x}\r\n", json_body.len());
                        let mut wire = Vec::new();
                        wire.extend_from_slice(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                        );
                        wire.extend_from_slice(chunk_hdr.as_bytes());
                        wire.extend_from_slice(json_body.as_bytes());
                        wire.extend_from_slice(b"\r\n0\r\n\r\n");
                        let _ = s.write_all(&wire);
                        continue;
                    }

                    let (status_line, body) = if path.contains("..;/")
                        || path.starts_with("/flow/step2")
                    {
                        (
                            "200 OK",
                            format!(
                                r#"{{"pad":"{pad_c}","meta":{{"request_id":"req_{n}","timestamp":{ts},"nonce":"n_{n}"}},"role":"admin","leaked_flag":true}}"#
                            ),
                        )
                    } else if path.starts_with("/flow/step1") {
                        (
                            "200 OK",
                            format!(
                                r#"{{"pad":"{pad_c}","meta":{{"request_id":"req_{n}","timestamp":{ts},"nonce":"n_{n}"}},"role":"viewer"}}"#
                            ),
                        )
                    } else {
                        (
                            "403 Forbidden",
                            format!(
                                r#"{{"pad":"{pad_c}","meta":{{"request_id":"req_{n}","timestamp":{ts},"nonce":"n_{n}"}},"error":"forbidden"}}"#
                            ),
                        )
                    };
                    let resp = format!(
                        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    // 1a. --mutate-matrix across >4KB JSON with volatile noise + tail semantic anomaly
    let mut_out = run_ap(
        td.path(),
        &[
            "probe",
            "http",
            &format!("http://127.0.0.1:{http_port}/api/v1/admin/panel"),
            "--mutate-matrix",
            "--json",
        ],
        None,
        &[],
    );
    assert!(
        mut_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&mut_out.stderr)
    );
    let mut_json: Value = serde_json::from_slice(&mut_out.stdout).unwrap();
    let anomalies = mut_json["anomalies"].as_array().unwrap();
    assert!(
        !anomalies.is_empty(),
        "expected tail >2.4KB mutation anomaly to be captured: {mut_json}"
    );
    assert!(
        anomalies
            .iter()
            .all(|a| a["kind"] != "HEADER_OR_STATUS_VOLATILITY_NOISE"),
        "{anomalies:?}"
    );

    // 1b. --flow compare_step across >4KB JSON
    let flow_spec = json!({
        "steps": [
            { "name": "baseline_viewer", "method": "GET", "url": format!("http://127.0.0.1:{http_port}/flow/step1") },
            { "name": "elevated_check", "method": "GET", "url": format!("http://127.0.0.1:{http_port}/flow/step2"), "compare_step": 0 }
        ]
    });
    let flow_path = td.path().join("flow.json");
    fs::write(&flow_path, flow_spec.to_string()).unwrap();
    let flow_out = run_ap(
        td.path(),
        &[
            "probe",
            "http",
            "--flow",
            flow_path.to_str().unwrap(),
            "--json",
        ],
        None,
        &[],
    );
    assert!(flow_out.status.success());
    let flow_json: Value = serde_json::from_slice(&flow_out.stdout).unwrap();
    let cmp_diff = &flow_json["steps"][1]["diff"];
    assert_eq!(cmp_diff["possible_bypass"], true, "{flow_json}");
    let added = cmp_diff["added_paths"].as_array().unwrap();
    assert!(
        added.iter().any(|x| x == "leaked_flag"),
        "expected deep >4KB tail path `leaked_flag`: {cmp_diff}"
    );

    // 1c. --race on Transfer-Encoding: chunked JSON >4KB with --select id
    let race_out = run_ap(
        td.path(),
        &[
            "probe",
            "http",
            "-X",
            "POST",
            &format!("http://127.0.0.1:{http_port}/chunked-race"),
            "--race",
            "4",
            "--select",
            "id",
            "--json",
        ],
        None,
        &[],
    );
    assert!(
        race_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&race_out.stderr)
    );
    let race_json: Value = serde_json::from_slice(&race_out.stdout).unwrap();
    assert_eq!(race_json["distinct_selected_count"], 4, "{race_json}");

    stop_http.store(true, Ordering::Relaxed);
    let _ = http_srv.join();

    // 2. Loopback WebSocket server: CSWSH (`http://localhost.evil.com` vs `http://localhost`) + Ping/Pong + FIN=0 fragments.
    let ws_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let ws_port = ws_listener.local_addr().unwrap().port();
    let stop_ws = Arc::new(AtomicBool::new(false));
    let stop_ws_c = Arc::clone(&stop_ws);

    let ws_srv = thread::spawn(move || {
        let _ = ws_listener.set_nonblocking(true);
        while !stop_ws_c.load(Ordering::Relaxed) {
            match ws_listener.accept() {
                Ok((mut s, _)) => {
                    let _ = s.set_nonblocking(false);
                    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                    let req = read_http_req_wire(&mut s);
                    let low = req.to_ascii_lowercase();
                    if low.contains("origin: null") {
                        let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
                        continue;
                    }
                    let _ = s.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                    );
                    if low.contains("origin: http://localhost\r\n") {
                        fn read_frame_op(stream: &mut std::net::TcpStream) -> Option<u8> {
                            let mut hdr = [0u8; 2];
                            stream.read_exact(&mut hdr).ok()?;
                            let op = hdr[0] & 0x0F;
                            let plen = (hdr[1] & 0x7F) as usize;
                            let mut skip =
                                vec![0u8; plen + if (hdr[1] & 0x80) != 0 { 4 } else { 0 }];
                            stream.read_exact(&mut skip).ok()?;
                            Some(op)
                        }
                        let _ = read_frame_op(&mut s);
                        let _ = s.write_all(&[0x89, 1, b'k']);
                        if read_frame_op(&mut s) == Some(10) {
                            let _ = s.write_all(&[0x01, 5, b'p', b'a', b'r', b't', b'-']);
                            let _ = s.write_all(&[0x80, 3, b't', b'w', b'o']);
                        }
                        let _ = s.write_all(&[0x88, 2, 0x03, 0xE8]);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let ws_out = run_ap(
        td.path(),
        &[
            "probe",
            "ws",
            &format!("ws://127.0.0.1:{ws_port}/rpc"),
            "--send",
            "hello",
            "--origin-matrix",
            "--origin",
            "http://localhost.evil.com",
            "--origin",
            "http://localhost",
            "--origin",
            "null",
            "--wait-ms",
            "500",
            "--json",
        ],
        None,
        &[],
    );
    stop_ws.store(true, Ordering::Relaxed);
    let _ = ws_srv.join();

    assert!(ws_out.status.success());
    let ws_json: Value = serde_json::from_slice(&ws_out.stdout).unwrap();
    assert_eq!(ws_json["cswsh_vulnerable"], true, "{ws_json}");
    let untrusted: Vec<String> = ws_json["untrusted_accepted"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert!(
        untrusted.iter().any(|u| u == "http://localhost.evil.com"),
        "attacker subdomain localhost.evil.com must be flagged untrusted: {untrusted:?}"
    );
    assert!(
        !untrusted.iter().any(|u| u == "http://localhost"),
        "exact localhost origin must remain trusted: {untrusted:?}"
    );
    let results = ws_json["results"].as_array().unwrap();
    let localhost_row = results
        .iter()
        .find(|r| r["origin"] == "http://localhost")
        .unwrap();
    assert_eq!(localhost_row["messages"][0], "part-two", "{localhost_row}");
}

#[test]
fn corpus_03_splice_windows_path_aliasing_and_atomic_rollback() {
    let td = TempDir::new().unwrap();
    let root = td.path();
    fs::create_dir_all(root.join("src")).unwrap();
    let target = root.join("src/module.rs");
    let orig_src = "pub fn step_one() -> i32 { 1 }\npub fn step_two() -> i32 { 2 }\npub fn step_three() -> i32 { 3 }\n";
    fs::write(&target, orig_src).unwrap();

    // 1. Multi-op aliased paths merge cleanly without overwriting earlier ops
    let third_alias = if cfg!(windows) {
        "src/MODULE.rs"
    } else {
        "./src/../src/module.rs"
    };
    let batch_ok = json!([
        {"op": "replace", "path": "./src/module.rs", "old": "pub fn step_one() -> i32 { 1 }", "new": "pub fn step_one() -> i32 { 11 }"},
        {"op": "replace", "path": "src\\module.rs".replace('\\', if cfg!(windows) { "\\" } else { "/" }), "old": "pub fn step_two() -> i32 { 2 }", "new": "pub fn step_two() -> i32 { 22 }"},
        {"op": "replace", "path": third_alias, "old": "pub fn step_three() -> i32 { 3 }", "new": "pub fn step_three() -> i32 { 33 }"}
    ])
    .to_string();
    let rc_ok = ap_splice::apply_spec_silent(root, &batch_ok);
    assert_eq!(rc_ok, 0);
    let after_ok = fs::read_to_string(&target).unwrap();
    assert!(after_ok.contains("11") && after_ok.contains("22") && after_ok.contains("33"));

    // 2. Failing second op (broken Rust syntax) rolls back ALL ops in batch cleanly
    let batch_fail = json!([
        {"op": "replace", "path": "src/module.rs", "old": "pub fn step_one() -> i32 { 11 }", "new": "pub fn step_one() -> i32 { 999 }"},
        {"op": "replace", "path": "./src/module.rs", "old": "pub fn step_three() -> i32 { 33 }", "new": "pub fn step_three( -> broken {{{"}
    ])
    .to_string();
    let rc_fail = ap_splice::apply_spec_silent(root, &batch_fail);
    assert_ne!(rc_fail, 0);
    assert_eq!(fs::read_to_string(&target).unwrap(), after_ok);
}

#[test]
fn corpus_04_atlas_ast_taint_wrappers_and_cross_file_isolation() {
    let td = TempDir::new().unwrap();
    let root = td.path();
    fs::create_dir_all(root.join("src/auth")).unwrap();
    fs::create_dir_all(root.join("src/admin")).unwrap();
    fs::create_dir_all(root.join("src/shared")).unwrap();

    fs::write(
        root.join("src/shared/wrap.ts"),
        "export function leafPass(val: string, _unused: string) { return val; }\n\
         export function wrapKeep(v: string) { return leafPass(v, 'tag'); }\n\
         export function wrapDrop(v: string) { return leafPass('constant', v); }\n\
         export function execKeep(req: any) { const c = wrapKeep(req.cmd); return execSync(c); }\n\
         export function execDrop(req: any) { const c = wrapDrop(req.cmd); return execSync(c); }\n",
    )
    .unwrap();
    fs::write(
        root.join("src/auth/guard.ts"),
        "function handle(input: string) { return execSync('status'); }\n\
         export function safeEntry(req: any) { return handle(req.cmd); }\n\
         export function dualSinkLine(req: any) { return [execSync(req.a), query(req.b)]; }\n",
    )
    .unwrap();
    fs::write(
        root.join("src/admin/route.ts"),
        "function handle(input: string) { return execSync(input); }\n\
         export function adminEntry(req: any) { return handle(req.cmd); }\n\
         export function commentedSink(req: any) {\n\
           // requireAdmin(req.user)\n\
           /* authorize(req.user) */\n\
           return db.execute(req.sql);\n\
         }\n",
    )
    .unwrap();

    let v_exec =
        ap_atlas::variants::analyze_variants(root, Some("execute"), None, Some(r"requireAdmin"));
    assert_eq!(v_exec.total_siblings, 1);
    assert_eq!(v_exec.siblings[0].guard_placement, "UNGUARDED");

    let v_all = ap_atlas::variants::analyze_variants(root, None, None, None);
    let dual: Vec<&str> = v_all
        .siblings
        .iter()
        .filter(|s| s.function == "dualSinkLine")
        .map(|s| s.sink.as_str())
        .collect();
    assert!(
        dual.contains(&"execSync") && dual.contains(&"query"),
        "{dual:?}"
    );

    let keep_rep = ap_atlas::trace::trace_symbol_chain_to_opts(
        root,
        "execKeep",
        Some("execSync"),
        false,
        true,
        4,
    );
    assert_eq!(keep_rep.reachability_paths.len(), 1);
    assert_eq!(
        keep_rep.reachability_paths[0].hops[0].arg_taint,
        "PARAM_TAINTED"
    );

    let drop_rep = ap_atlas::trace::trace_symbol_chain_to_opts(
        root,
        "execDrop",
        Some("execSync"),
        false,
        true,
        4,
    );
    assert!(
        drop_rep.reachability_paths.is_empty(),
        "{:?}",
        drop_rep.reachability_paths
    );

    let safe_rep = ap_atlas::trace::trace_symbol_chain_to_opts(
        root,
        "safeEntry",
        Some("execSync"),
        false,
        true,
        4,
    );
    assert!(
        safe_rep.reachability_paths.is_empty(),
        "src/auth/guard.ts `handle` must stay isolated from src/admin/route.ts: {:?}",
        safe_rep.reachability_paths
    );
    let vuln_rep = ap_atlas::trace::trace_symbol_chain_to_opts(
        root,
        "adminEntry",
        Some("execSync"),
        false,
        true,
        4,
    );
    assert_eq!(vuln_rep.reachability_paths.len(), 1);
    assert!(vuln_rep.reachability_paths[0]
        .hops
        .iter()
        .all(|h| h.file == "src/admin/route.ts"));
}

#[test]
fn corpus_05_sieve_and_recall_concurrent_busy_timeout_stress() {
    let td = TempDir::new().unwrap();
    let vault_db = td.path().join("vault.db");
    let sieve_store = td.path().join("sieve_store");
    fs::create_dir_all(&sieve_store).unwrap();

    // Seed initial rule & archive so tables exist cleanly
    let init_conn = ap_recall::open_vault(&vault_db).unwrap();
    ap_recall::add_rule(
        &init_conn,
        "auth,jwt",
        "Always verify JWT alg & aud",
        "gotcha",
    )
    .unwrap();
    drop(init_conn);

    let big_log = (0..60)
        .map(|i| format!("INFO line={i} status=ok component=worker payload=alpha_beta_gamma"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\nERROR timeout_marker fatal failure in stage=3\n";
    ap_sieve::compress_stream_in(&sieve_store, &big_log, "seed-log", 1, 5.0);

    let mut handles = Vec::new();
    for tid in 0..6 {
        let vdb = vault_db.clone();
        let wroot = td.path().to_path_buf();
        let ss = sieve_store.clone();
        let log_c = big_log.clone();
        handles.push(thread::spawn(move || {
            for iter in 0..4 {
                let conn =
                    ap_recall::open_vault(&vdb).expect("recall open_vault under concurrency");
                ap_recall::add_rule_with_provenance(
                    &conn,
                    &wroot,
                    &format!("worker_{tid},token_{iter}"),
                    &format!("Rule body for thread {tid} iteration {iter}"),
                    "gotcha",
                    "",
                )
                .expect("recall add_rule under concurrency");
                let (hits, _) = ap_recall::match_rules_in(&conn, &wroot, "jwt auth worker", &[], 5)
                    .expect("recall match_rules under concurrency");
                assert!(!hits.is_empty());

                let res = ap_sieve::compress_stream_in(
                    &ss,
                    &format!("{log_c}\nTHREAD={tid} ITER={iter}\n"),
                    &format!("job-{tid}-{iter}"),
                    0,
                    2.0,
                );
                assert!(res.rendered.contains("[sieve id="));
                let (shits, _) = ap_sieve::search_archives(&ss, "timeout_marker", 5);
                assert!(!shits.is_empty());
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }
}

#[test]
fn corpus_06_guard_diff_audit_and_mcp_ai_surface_invariants() {
    let td = TempDir::new().unwrap();
    let dir = td.path();
    let ok_git = Command::new("git")
        .args(["init"])
        .current_dir(dir)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok_git {
        let _ = Command::new("git")
            .args(["config", "user.email", "ci@example.com"])
            .current_dir(dir)
            .status();
        let _ = Command::new("git")
            .args(["config", "user.name", "CI"])
            .current_dir(dir)
            .status();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join("tests")).unwrap();
        fs::write(
            dir.join("src/calc.rs"),
            "pub fn compute(v: i32) -> i32 { v }\n",
        )
        .unwrap();
        fs::write(
            dir.join("tests/calc_test.rs"),
            "fn t() {\n  assert_eq!(1, 1);\n  assert_eq!(2, 2);\n  assert_eq!(3, 3);\n  assert_eq!(4, 4);\n}\n",
        )
        .unwrap();
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .status();
        let _ = Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(dir)
            .status();

        // Clean refactor: multiline block comment + raw string + parameterized test loop
        fs::write(
            dir.join("src/calc.rs"),
            "pub fn compute(v: i32) -> i32 {\n  /*\n   dbg!(v);\n  */\n  let _note = r#\"prefix\"dbg!(v)\"#;\n  v + 1\n}\n",
        )
        .unwrap();
        fs::write(
            dir.join("tests/calc_test.rs"),
            "fn t() {\n  for x in [1, 2, 3, 4] { assert_eq!(x, x); }\n}\n",
        )
        .unwrap();
        let clean_rep = ap_guard::diff_audit::audit_git_diff(dir);
        assert!(clean_rep.findings.is_empty(), "{:?}", clean_rep.findings);

        // Pointer dereference with dbg! MUST still be caught
        fs::write(
            dir.join("src/calc.rs"),
            "pub unsafe fn write_ptr(ptr: *mut i32, val: i32) {\n  *ptr = dbg!(val);\n}\n",
        )
        .unwrap();
        let deref_rep = ap_guard::diff_audit::audit_git_diff(dir);
        assert!(
            deref_rep
                .findings
                .iter()
                .any(|f| f.kind == "DEBUG-LEFTOVER"),
            "{:?}",
            deref_rep.findings
        );
    }

    // MCP JSON-RPC: tools/list budget + ap_guard_pack without `dir` when `ai_surface: true`
    let mcp_dir = TempDir::new().unwrap();
    fs::write(
        mcp_dir.path().join(".mcp.json"),
        r#"{"mcpServers":{"runner":{"command":"sh","args":["-c","echo hi"]}}}"#,
    )
    .unwrap();
    let rpc_input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ap_guard_pack","arguments":{"ai_surface":true}}}"#,
        "\n"
    );
    let mcp_out = run_ap(
        mcp_dir.path(),
        &["mcp", "--profile", "full"],
        Some(rpc_input),
        &[],
    );
    assert!(mcp_out.status.success());
    let stdout_s = String::from_utf8_lossy(&mcp_out.stdout);
    let resps: Vec<Value> = stdout_s
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .collect();
    assert_eq!(resps.len(), 3, "{stdout_s}");

    let tools = resps[1]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 37);
    let guard_pack = tools.iter().find(|t| t["name"] == "ap_guard_pack").unwrap();
    assert!(
        guard_pack["inputSchema"].get("required").is_none(),
        "ap_guard_pack schema must allow omitting `dir` for ai_surface: {guard_pack}"
    );

    let call_res = &resps[2]["result"];
    assert_ne!(call_res["isError"], true, "{call_res}");
    let body_txt = call_res["content"][0]["text"].as_str().unwrap();
    let ai_rep: Value = serde_json::from_str(body_txt).unwrap();
    assert!(ai_rep["findings"].is_array(), "{ai_rep}");
}

#[test]
fn corpus_07_probe_cdp_eval_stdin_and_invalid_stdin_guard() {
    let td = TempDir::new().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::clone(&stop);

    fn read_client_ws_frame(s: &mut std::net::TcpStream) -> Option<(u8, String)> {
        let mut hdr = [0u8; 2];
        s.read_exact(&mut hdr).ok()?;
        let op = hdr[0] & 0x0F;
        let masked = (hdr[1] & 0x80) != 0;
        let mut len = (hdr[1] & 0x7F) as usize;
        if len == 126 {
            let mut b = [0u8; 2];
            s.read_exact(&mut b).ok()?;
            len = u16::from_be_bytes(b) as usize;
        }
        let mut mask = [0u8; 4];
        if masked {
            s.read_exact(&mut mask).ok()?;
        }
        let mut data = vec![0u8; len];
        if len > 0 {
            s.read_exact(&mut data).ok()?;
        }
        if masked {
            for (i, b) in data.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
        }
        Some((op, String::from_utf8_lossy(&data).into_owned()))
    }

    fn write_server_ws_text(s: &mut std::net::TcpStream, txt: &str) {
        let b = txt.as_bytes();
        let mut fr = vec![0x81u8];
        if b.len() <= 125 {
            fr.push(b.len() as u8);
        } else {
            fr.push(126);
            fr.extend_from_slice(&(b.len() as u16).to_be_bytes());
        }
        fr.extend_from_slice(b);
        let _ = s.write_all(&fr);
    }

    let srv = thread::spawn(move || {
        let _ = listener.set_nonblocking(true);
        while !stop_c.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let _ = s.set_nonblocking(false);
                    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                    let req = read_http_req_wire(&mut s);
                    let first = req.lines().next().unwrap_or("");
                    if first.contains("/json") {
                        let list = json!([{
                            "id": "page-1",
                            "type": "page",
                            "title": "MockPage",
                            "url": "http://127.0.0.1/",
                            "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/1")
                        }])
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{list}",
                            list.len()
                        );
                        let _ = s.write_all(resp.as_bytes());
                        continue;
                    }
                    if first.contains("/devtools/page/1") {
                        let _ = s.write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                        );
                        while let Some((op, txt)) = read_client_ws_frame(&mut s) {
                            if op == 8 {
                                break;
                            }
                            if let Ok(msg) = serde_json::from_str::<Value>(&txt) {
                                let id = msg["id"].as_u64().unwrap_or(1);
                                let method = msg["method"].as_str().unwrap_or("");
                                if method == "Runtime.evaluate" {
                                    let expr = msg["params"]["expression"].as_str().unwrap_or("");
                                    let val = if expr.contains("const x = 40") {
                                        "42"
                                    } else if expr.contains("2+2") {
                                        "4"
                                    } else {
                                        "ok"
                                    };
                                    let reply = json!({"id": id, "result": {"result": {"type": "string", "value": val}}});
                                    write_server_ws_text(&mut s, &reply.to_string());
                                } else {
                                    let reply = json!({"id": id, "result": {}});
                                    write_server_ws_text(&mut s, &reply.to_string());
                                }
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    // 1. --eval-stdin with `2+2` returns real `"4"` instead of `null`
    let out_add = run_ap(
        td.path(),
        &[
            "probe",
            "cdp",
            "--port",
            &port.to_string(),
            "--eval-stdin",
            "--json",
        ],
        Some("2+2"),
        &[],
    );
    assert!(
        out_add.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_add.stderr)
    );
    let j_add: Value = serde_json::from_slice(&out_add.stdout).unwrap();
    assert_eq!(j_add["ok"], true);
    assert_eq!(j_add["eval"], "4");

    // 2. --eval-stdin with multiline JS preserves newlines & returns `"42"`
    let out_multi = run_ap(
        td.path(),
        &[
            "probe",
            "cdp",
            "--port",
            &port.to_string(),
            "--eval-stdin",
            "--json",
        ],
        Some("const x = 40;\nconst y = 2;\nx + y"),
        &[],
    );
    assert!(out_multi.status.success());
    let j_multi: Value = serde_json::from_slice(&out_multi.stdout).unwrap();
    assert_eq!(j_multi["eval"], "42");

    // 3. --stdin with raw JS or JSON missing `steps` must fail cleanly (exit 2, ok=false)
    let out_bad_raw = run_ap(
        td.path(),
        &[
            "probe",
            "cdp",
            "--port",
            &port.to_string(),
            "--stdin",
            "--json",
        ],
        Some("2+2"),
        &[],
    );
    assert!(!out_bad_raw.status.success());
    let j_bad_raw: Value = serde_json::from_slice(&out_bad_raw.stdout).unwrap();
    assert_eq!(j_bad_raw["ok"], false);

    let out_bad_json = run_ap(
        td.path(),
        &[
            "probe",
            "cdp",
            "--port",
            &port.to_string(),
            "--stdin",
            "--json",
        ],
        Some(r#"{"expr":"2+2"}"#),
        &[],
    );
    assert!(!out_bad_json.status.success());
    let j_bad_json: Value = serde_json::from_slice(&out_bad_json.stdout).unwrap();
    assert_eq!(j_bad_json["ok"], false);

    // 4. MCP `ap_cdp({ port, eval: "2+2" })` uses `--eval-stdin` cleanly
    let rpc = format!(
        "{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ap_cdp","arguments":{"port":port,"eval":"2+2"}}})
    );
    let mcp_out = run_ap(td.path(), &["mcp", "--profile", "full"], Some(&rpc), &[]);
    assert!(mcp_out.status.success());
    let mcp_s = String::from_utf8_lossy(&mcp_out.stdout);
    let resp2: Value = serde_json::from_str(mcp_s.lines().nth(1).unwrap()).unwrap();
    let txt = resp2["result"]["content"][0]["text"].as_str().unwrap();
    assert!(txt.contains("eval: 4"), "{txt}");

    stop.store(true, Ordering::Relaxed);
    let _ = srv.join();
}

#[test]
fn corpus_08_sieve_peek_flags_and_partial_json_invariants() {
    let td = tempfile::tempdir().unwrap();
    let sieve_home = td.path().join("sieve_home");
    fs::create_dir_all(&sieve_home).unwrap();
    let envs = [("SIEVE_HOME", sieve_home.as_path())];

    // 1. Archive a 60-line stream so we can test --lines A-B, --lines + --grep, --max-chars, --char-offset, --raw
    let mut lines_raw = String::new();
    for i in 1..=60 {
        lines_raw.push_str(&format!(
            "line-{i:02} marker={} payload={}\n",
            if i == 10 || i == 45 {
                "NEEDLE"
            } else {
                "noise"
            },
            "x".repeat(40)
        ));
    }
    let pipe_out = run_ap(
        td.path(),
        &["sieve", "pipe", "--label", "corpus08", "--json"],
        Some(&lines_raw),
        &envs,
    );
    assert!(pipe_out.status.success());
    let pj: Value = serde_json::from_slice(&pipe_out.stdout).unwrap();
    let sid = pj["id"].as_str().unwrap().to_string();

    // Hyphen range --lines 41-50 must return L41..L50 (never fall back to L1..L41)
    let peek_hyp = run_ap(
        td.path(),
        &["sieve", "peek", &sid, "--lines", "41-50"],
        None,
        &envs,
    );
    assert!(peek_hyp.status.success());
    let hyp_s = String::from_utf8_lossy(&peek_hyp.stdout);
    assert!(hyp_s.contains("L41: line-41"), "{hyp_s}");
    assert!(hyp_s.contains("L50: line-50"), "{hyp_s}");
    assert!(!hyp_s.contains("L1: line-01"), "{hyp_s}");

    // Invalid range must fail cleanly with exit 2
    let peek_bad = run_ap(
        td.path(),
        &["sieve", "peek", &sid, "--lines", "50-10"],
        None,
        &envs,
    );
    assert!(!peek_bad.status.success());

    // Compose --lines 40-60 + --grep NEEDLE -> only matches L45, NOT L10
    let peek_comp = run_ap(
        td.path(),
        &[
            "sieve", "peek", &sid, "--lines", "40-60", "--grep", "NEEDLE",
        ],
        None,
        &envs,
    );
    assert!(peek_comp.status.success());
    let comp_s = String::from_utf8_lossy(&peek_comp.stdout);
    assert!(comp_s.contains("L45: line-45"), "{comp_s}");
    assert!(!comp_s.contains("line-10"), "{comp_s}");

    // 2. Single-line JSON with --raw --pretty --max-chars --char-offset
    let big_json = format!(
        "{{\"ok\":true,\"entries\":[{}]}}",
        (0..60)
            .map(|i| format!("{{\"idx\":{i},\"tag\":\"alpha_{i}\"}}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let pj2: Value = serde_json::from_slice(
        &run_ap(
            td.path(),
            &["sieve", "pipe", "--label", "json-peek", "--json"],
            Some(&big_json),
            &envs,
        )
        .stdout,
    )
    .unwrap();
    let jid = pj2["id"].as_str().unwrap().to_string();

    let raw_peek = run_ap(
        td.path(),
        &["sieve", "peek", &jid, "--lines", "1-1", "--raw", "--pretty"],
        None,
        &envs,
    );
    assert!(raw_peek.status.success());
    let raw_parsed: Value = serde_json::from_slice(&raw_peek.stdout).unwrap();
    assert_eq!(raw_parsed["ok"], true);
    assert_eq!(raw_parsed["entries"].as_array().unwrap().len(), 60);

    let paged = run_ap(
        td.path(),
        &[
            "sieve",
            "peek",
            &jid,
            "--lines",
            "1-1",
            "--raw",
            "--char-offset",
            "0",
            "--max-chars",
            "64",
        ],
        None,
        &envs,
    );
    assert!(paged.status.success());
    let paged_s = String::from_utf8_lossy(&paged.stdout).trim().to_string();
    assert_eq!(paged_s.chars().count(), 64, "{paged_s}");
    assert!(!paged_s.contains("[sieve peek chars"), "{paged_s}");

    // 3. Partial truncated JSON digest preserves extracted keys & fields
    let partial = format!(
        "<console_output>\n{{\"status\":200,\"workspace_id\":\"demo\",\"action\":\"scan\",\"blob\":\"{}\"",
        "q".repeat(1600)
    );
    let pj3: Value = serde_json::from_slice(
        &run_ap(
            td.path(),
            &["sieve", "pipe", "--label", "partial", "--json"],
            Some(&partial),
            &envs,
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(pj3["mode"], "partial-json", "{pj3}");
    let r3 = pj3["rendered"].as_str().unwrap();
    assert!(r3.contains("workspace_id") && r3.contains("action"), "{r3}");
}

#[test]
fn corpus_09_accelerator_bash_ps_hashline_and_win_sig_invariants() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    #[cfg(windows)]
    {
        let sig_out = run_ap(
            root,
            &[
                "probe",
                "win",
                "--sig",
                r"C:\Windows\System32\notepad.exe",
                "--json",
            ],
            None,
            &[],
        );
        assert!(
            sig_out.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&sig_out.stderr)
        );
        let sj: Value = serde_json::from_slice(&sig_out.stdout).unwrap();
        assert_eq!(sj["ok"], true, "{sj}");
        assert_eq!(sj["signed"], true, "{sj}");
        assert_eq!(sj["valid"], true, "{sj}");
        assert!(!sj["subject"].as_str().unwrap_or("").is_empty(), "{sj}");
    }

    let fake_home = root.join("home_c09");
    let ap_home = root.join("ap_home_c09");
    let pi_agent = fake_home.join(".pi").join("agent");
    fs::create_dir_all(&pi_agent).unwrap();
    let init_out = run_ap(
        root,
        &["init", "-a", "pi", "--with-hooks", "--no-rules"],
        None,
        &[
            ("HOME", fake_home.as_path()),
            ("USERPROFILE", fake_home.as_path()),
            ("AP_HOME", ap_home.as_path()),
        ],
    );
    assert!(init_out.status.success());

    let accel_ts = pi_agent.join("extensions").join("zz-ap-accelerator.ts");
    let node_check = r###"
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const mod = await import(pathToFileURL(process.env.ACCEL_TS).href);
const {
  shouldAutoSieveShellOutput,
  healCommand,
  annotateReadWithHashlines,
  healCodemodeSource,
  AP_DEEPSEEK_GUIDELINES,
} = mod;

// 1. Small <=12 line <=12KB minified JS line exempt from SIEVE_GIANT_LINE_CHARS
const twoLineJs = "line1=" + "a".repeat(5200) + "\nline2=" + "b".repeat(1200);
assert.equal(shouldAutoSieveShellOutput(twoLineJs, false, undefined, 30000), false);
assert.equal(shouldAutoSieveShellOutput("x".repeat(5000) + "\n".repeat(15), false, undefined, 30000), true);

// 2. Relative unquoted backslash healing in bash (without breaking regexes)
const rel1 = healCommand("ap read notes\\current_plan.md --lines 1-30", "bash");
assert.equal(rel1, "ap read notes/current_plan.md --lines 1-30");
const rel2 = healCommand("wc -l docs\\guide.md", "bash");
assert.equal(rel2, "wc -l docs/guide.md");

// 3. Expanded grep (-A/-B/-C, BRE \|, single-file, findstr) & && exit-semantics preservation
const gCtx = healCommand('grep -n "heading" -A 15 docs/manual.md', "bash");
assert.ok(gCtx && gCtx.includes("search") && gCtx.includes("-A 15") && gCtx.includes('"docs/manual.md"'), gCtx);
const gBre = healCommand('grep -n "foo\\|bar" src/lib.rs', "bash");
assert.ok(gBre && (gBre.includes("'foo|bar'") || gBre.includes('"foo|bar"')) && gBre.includes('"src/lib.rs"'), gBre);
const fsCmd = healCommand('findstr /i /s "needle" *.ts', "bash");
assert.ok(fsCmd && fsCmd.includes("search") && fsCmd.includes("-i") && fsCmd.includes("-e ts"), fsCmd);
const condGrep = healCommand('grep -rn "pat" src && echo found', "bash");
assert.equal(condGrep, undefined, "must not rewrite grep on LHS of &&");

// 4. Read-only PowerShell discovery -> ap probe ports/win/ps
const psPorts = healCommand('powershell -NoProfile -Command "Get-NetTCPConnection -State Listen"', "bash");
assert.ok(psPorts && psPorts.includes("probe ports"), psPorts);
const psPipes = healCommand(`powershell -NoProfile -Command "[System.IO.Directory]::GetFiles('\\\\\\\\.\\\\pipe\\\\') | Where-Object { \\$_ -match 'ipc' }"`, "bash");
assert.ok(psPipes && psPipes.includes("probe win --pipes") && psPipes.includes('--filter "ipc"'), psPipes);
const psProc = healCommand('powershell -NoProfile -Command "Get-CimInstance Win32_Process | Select-Object -First 15"', "bash");
assert.ok(psProc && psProc.includes("probe ps") && psProc.includes("--limit 15"), psProc);
const psSvc = healCommand('powershell -NoProfile -Command "Get-Service"', "bash");
assert.ok(psSvc && psSvc.includes("probe win --services"), psSvc);

// 5. Selective hashline: only editable code/config files <=400 lines
const code2 = "const a = 1;\nconst b = 2;";
assert.ok(annotateReadWithHashlines(code2, 1, "src/app.ts")?.includes("|const a = 1;"));
assert.equal(annotateReadWithHashlines(code2, 1, "notes/readme.md"), undefined);
assert.equal(annotateReadWithHashlines(code2, 1, "data/out.json"), undefined);
const code405 = Array.from({ length: 405 }, (_, i) => `let x${i} = ${i};`).join("\n");
assert.equal(annotateReadWithHashlines(code405, 1, "src/big.ts"), undefined);

// 6. Codemode String.raw inner backtick & regex alternation slash heals
const psRaw = "const ps = String.raw`\n\"$h`:$p OPEN\"\n`;\ntext(ps);";
const healedPs = healCodemodeSource(psRaw);
assert.ok(healedPs, "expected String.raw inner backtick heal");
new Function(`return async () => {\n${healedPs}\n};`);

const rxRaw = 'const ok = (/alpha|/beta/.test(s));';
const healedRx = healCodemodeSource(rxRaw);
assert.ok(healedRx && healedRx.includes("\\/beta/"), healedRx);
new Function(`return async () => {\n${healedRx}\n};`);

// 7. Guidelines include new high-value primitives
assert.ok(AP_DEEPSEEK_GUIDELINES.join("\n").includes("ap ps|ports"));
assert.ok(AP_DEEPSEEK_GUIDELINES.join("\n").includes("--sig"));
"###;

    let run = Command::new("node")
        .args([
            "--experimental-strip-types",
            "--input-type=module",
            "-e",
            node_check,
        ])
        .env("ACCEL_TS", &accel_ts)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "Node corpus_09 check failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn corpus_10_version_diff_and_sieve_prune_invariants() {
    use zip::write::SimpleFileOptions;
    let td = TempDir::new().unwrap();
    let root = td.path();

    // 1. Two zip archives where dist/main.js has identical byte length but changed content (SHA-256 detects!)
    let old_zip = root.join("app_v1.zip");
    let new_zip = root.join("app_v2.zip");

    let js_v1 =
        r#"app.get('/api/v1/health', ok); ipcMain.on('ping', h); // padding_same_len_123456"#;
    let js_v2 = r#"app.post('/api/v2/run', go); ipcMain.handle('exec', h); // pad_123"#;
    let js_v2_padded = format!(
        "{js_v2}{}",
        " ".repeat(js_v1.len().saturating_sub(js_v2.len()))
    );
    assert_eq!(js_v1.len(), js_v2_padded.len(), "same-size invariant");

    let write_zip = |path: &Path, js_body: &str, py_body: &str| {
        let f = fs::File::create(path).unwrap();
        let mut zw = zip::ZipWriter::new(f);
        let opts = SimpleFileOptions::default();
        zw.start_file("dist/main.js", opts).unwrap();
        zw.write_all(js_body.as_bytes()).unwrap();
        zw.start_file("pkg/handler.py", opts).unwrap();
        zw.write_all(py_body.as_bytes()).unwrap();
        zw.finish().unwrap();
    };
    write_zip(&old_zip, js_v1, "def check(x):\n    return x == 'a'\n");
    write_zip(
        &new_zip,
        &js_v2_padded,
        "def check(x):\n    return x == 'a' and is_admin(x)\n",
    );

    let d_out = run_ap(
        root,
        &[
            "diff",
            old_zip.to_str().unwrap(),
            new_zip.to_str().unwrap(),
            "--json",
        ],
        None,
        &[],
    );
    assert!(
        d_out.status.success(),
        "{}",
        String::from_utf8_lossy(&d_out.stderr)
    );
    assert!(
        d_out.stdout.len() <= 16_384,
        "version-diff JSON must stay compact <=16KB (got {})",
        d_out.stdout.len()
    );
    let dj: Value = serde_json::from_slice(&d_out.stdout).unwrap();
    assert_eq!(dj["ok"], true, "{dj}");
    assert_eq!(dj["archive_summary"]["modified_hash"], 2, "{dj}");
    let members_s = dj["changed_code_members"].to_string();
    assert!(members_s.contains("/api/v2/run"), "{dj}");
    assert!(members_s.contains("ipcMain.handle"), "{dj}");

    // Same engine works via `ap probe archive-diff` and `ap read --diff --json`
    let p_out = run_ap(
        root,
        &[
            "probe",
            "archive-diff",
            old_zip.to_str().unwrap(),
            new_zip.to_str().unwrap(),
            "--json",
        ],
        None,
        &[],
    );
    assert!(p_out.status.success());
    let pj: Value = serde_json::from_slice(&p_out.stdout).unwrap();
    assert_eq!(pj["archive_summary"]["modified_hash"], 2, "{pj}");

    let r_out = run_ap(
        root,
        &[
            "read",
            new_zip.to_str().unwrap(),
            "--diff",
            old_zip.to_str().unwrap(),
            "--json",
        ],
        None,
        &[],
    );
    assert!(r_out.status.success());
    let rj: Value = serde_json::from_slice(&r_out.stdout).unwrap();
    assert_eq!(rj["archive_summary"]["modified_hash"], 2, "{rj}");

    // 2. Bounded `ap sieve prune --max-mb 0 --vacuum --json`
    let sieve_home = root.join("sieve_c10");
    fs::create_dir_all(&sieve_home).unwrap();
    let envs = [("SIEVE_HOME", sieve_home.as_path())];
    for idx in 0..4usize {
        let payload = format!("row-{idx}-{}", "B".repeat(2500));
        let pr = run_ap(
            root,
            &["sieve", "pipe", "--label", "c10", "--json"],
            Some(&payload),
            &envs,
        );
        assert!(pr.status.success());
    }
    let prune_out = run_ap(
        root,
        &["sieve", "prune", "--max-mb", "0", "--vacuum", "--json"],
        None,
        &envs,
    );
    assert!(
        prune_out.status.success(),
        "{}",
        String::from_utf8_lossy(&prune_out.stderr)
    );
    let prj: Value = serde_json::from_slice(&prune_out.stdout).unwrap();
    assert_eq!(prj["ok"], true, "{prj}");
    assert_eq!(prj["removed_entries"], 4, "{prj}");
    assert_eq!(prj["vacuum"], true, "{prj}");
}

#[test]
fn corpus_11_probe_http_roles_matrix_and_win_surface_invariants() {
    let td = TempDir::new().unwrap();
    let root = td.path();

    // 1. Live mock HTTP server testing cross-tenant IDOR + write-AuthZ bypass + volatile scrubbing
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        for _ in 0..16 {
            let Ok((mut sock, _)) = listener.accept() else {
                break;
            };
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let first = req.lines().next().unwrap_or("");
            let mut ps = first.split_whitespace();
            let method = ps.next().unwrap_or("GET");
            let path = ps.next().unwrap_or("/");
            let auth = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .unwrap_or("")
                .to_ascii_lowercase();
            let (code, body) = if !auth.contains("bearer ") {
                ("401 Unauthorized", r#"{"error":"unauthorized"}"#)
            } else if path.ends_with("/101") && method == "DELETE" && auth.contains("other") {
                ("200 OK", r#"{"ok":true,"deleted":101,"requestId":"r-99"}"#)
            } else if path.ends_with("/101") {
                (
                    "200 OK",
                    r#"{"id":101,"owner":"alice","secret":"SECRET_ALPHA","requestId":"r-1"}"#,
                )
            } else if path.ends_with("/102") && auth.contains("other") {
                (
                    "200 OK",
                    r#"{"id":102,"owner":"bob","secret":"SECRET_BOB","requestId":"r-2"}"#,
                )
            } else {
                ("403 Forbidden", r#"{"error":"denied"}"#)
            };
            let resp = format!(
                "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes());
        }
    });

    let spec = json!({
        "url": format!("http://127.0.0.1:{port}/api/doc/{{{{id}}}}"),
        "methods": ["GET", "DELETE"],
        "cross_id": true,
        "roles": [
            { "name": "owner", "headers": ["Authorization: Bearer owner_tok"], "vars": { "id": "101" } },
            { "name": "other", "headers": ["Authorization: Bearer other_tok"], "vars": { "id": "102" } },
            { "name": "anon", "headers": [] }
        ]
    });

    // Dry-run fires 0 HTTP requests
    let dry = run_ap(
        root,
        &[
            "probe",
            "http",
            "--roles-matrix",
            "-",
            "--dry-run",
            "--json",
        ],
        Some(&spec.to_string()),
        &[],
    );
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let dj: Value = serde_json::from_slice(&dry.stdout).unwrap();
    assert_eq!(dj["mode"], "roles_matrix_dry_run", "{dj}");
    assert_eq!(dj["cells_total"], 12, "{dj}");

    let live = run_ap(
        root,
        &[
            "probe",
            "http",
            "--roles-matrix",
            "-",
            "--sentinel",
            "SECRET_ALPHA",
            "--json",
        ],
        Some(&spec.to_string()),
        &[],
    );
    drop(handle);
    assert!(
        live.status.success(),
        "{}",
        String::from_utf8_lossy(&live.stderr)
    );
    let lj: Value = serde_json::from_slice(&live.stdout).unwrap();
    assert_eq!(lj["ok"], true, "{lj}");
    let anom = lj["anomalies"].as_array().unwrap();
    assert!(
        anom.iter().any(|a| a["verdict"] == "WRITE_AUTHZ_BYPASS"
            && a["method"] == "DELETE"
            && a["actor"] == "other"),
        "{lj}"
    );
    assert!(
        anom.iter()
            .any(|a| a["method"] == "GET" && a["actor"] == "other" && a["target_owner"] == "owner"),
        "{lj}"
    );

    // 2. Pure-Rust `ap probe win --weak-acl / --unquoted / --com / --rpc`
    let scan_dir = root.join("win_acl_dir");
    fs::create_dir_all(&scan_dir).unwrap();
    let sample_exe = scan_dir.join("helper.exe");
    fs::write(&sample_exe, b"MZ").unwrap();

    for flag_args in [
        vec![
            "probe",
            "win",
            "--weak-acl",
            scan_dir.to_str().unwrap(),
            "--max",
            "5",
            "--json",
        ],
        vec!["probe", "win", "--unquoted", "--max", "5", "--json"],
        vec!["probe", "win", "--com", "--max", "5", "--json"],
        vec!["probe", "win", "--rpc", "--max", "5", "--json"],
    ] {
        let out = run_ap(root, &flag_args, None, &[]);
        #[cfg(windows)]
        {
            assert!(
                out.status.success(),
                "{flag_args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let v: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(v["ok"], true, "{v}");
        }
        #[cfg(not(windows))]
        {
            assert_eq!(out.status.code(), Some(2));
        }
    }
}

#[test]
fn corpus_12_atomic_frontier_exec_lang_and_accel_v2_invariants() {
    use base64::Engine;
    let td = TempDir::new().unwrap();
    let root = td.path();

    // 1. Multi-process concurrent `ap baton` writes -> frontier.json must never disappear or corrupt
    let mut handles = Vec::new();
    for wid in 0..4usize {
        let cwd = root.to_path_buf();
        handles.push(thread::spawn(move || {
            for r in 0..5usize {
                let res = run_ap(
                    &cwd,
                    &[
                        "baton",
                        "fact",
                        &format!("worker-{wid}-round-{r}"),
                        "--ref",
                        "src/lib.rs:1",
                    ],
                    None,
                    &[],
                );
                assert!(
                    res.status.success(),
                    "{}",
                    String::from_utf8_lossy(&res.stderr)
                );
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let st_out = run_ap(root, &["baton", "resume", "--json"], None, &[]);
    assert!(st_out.status.success());

    // 2. `ap exec --lang py --base64` and `--run-stdin` UTF-8 + zero shell quoting
    let py_code = "import json\nprint(json.dumps({'ok': True, 'msg': 'hello_\"world\"_UTF8_测试'}, ensure_ascii=False))";
    let b64 = base64::engine::general_purpose::STANDARD.encode(py_code.as_bytes());
    let ex_b64 = run_ap(
        root,
        &["exec", "--lang", "py", "--base64", &b64, "--json"],
        None,
        &[],
    );
    assert!(
        ex_b64.status.success(),
        "{}",
        String::from_utf8_lossy(&ex_b64.stderr)
    );
    let exj: Value = serde_json::from_slice(&ex_b64.stdout).unwrap();
    assert_eq!(exj["exit_code"], 0, "{exj}");
    let py_out: Value = serde_json::from_str(exj["output"].as_str().unwrap().trim()).unwrap();
    assert_eq!(py_out["msg"], "hello_\"world\"_UTF8_测试", "{py_out}");

    // 3. `zz-ap-accelerator.ts` v2 checks via Node
    if !Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return;
    }
    let fake_home = root.join("home_c12");
    let ap_home = root.join("ap_home_c12");
    fs::create_dir_all(fake_home.join(".pi").join("agent")).unwrap();
    let init_out = run_ap(
        root,
        &["init", "-a", "pi", "--with-hooks", "--no-rules"],
        None,
        &[
            ("HOME", fake_home.as_path()),
            ("USERPROFILE", fake_home.as_path()),
            ("AP_HOME", ap_home.as_path()),
        ],
    );
    assert!(init_out.status.success());
    let accel_ts = fake_home
        .join(".pi")
        .join("agent")
        .join("extensions")
        .join("zz-ap-accelerator.ts");

    let node_check = r###"
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const mod = await import(pathToFileURL(process.env.ACCEL_TS).href);
const { healCommand, AP_DEEPSEEK_GUIDELINES } = mod;

// A. Benign exit-1 normalization for standalone searches (preserving exit >=2 & && / | sort)
const rgMiss = healCommand('rg "nonexistent_needle" src', "bash");
assert.ok(rgMiss && rgMiss.includes("_ap_ec=$?") && rgMiss.includes("[ap-empty]"), rgMiss);
assert.equal(healCommand('grep -rn "pat" src && echo found', "bash"), undefined);
assert.equal(healCommand("grep -n 'foo' app.js | sort", "bash"), undefined);

// B. PS & icacls security discovery auto-routing
const psSig = healCommand('powershell -NoProfile -Command "Get-AuthenticodeSignature \'C:\\App\\bin.exe\'"', "bash");
assert.ok(psSig && psSig.includes('probe win --sig "C:/App/bin.exe"'), psSig);
const psAcl = healCommand('powershell -NoProfile -Command "(Get-Acl \'C:\\App\\bin.exe\').Sddl"', "bash");
assert.ok(psAcl && psAcl.includes('probe win --acl "C:/App/bin.exe"'), psAcl);
const psReg = healCommand('powershell -NoProfile -Command "Get-ItemProperty \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\'"', "bash");
assert.ok(psReg && psReg.includes('probe win --reg "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip"'), psReg);
const icRo = healCommand('icacls "C:\\App\\dir"', "bash");
assert.ok(icRo && icRo.includes('probe win --acl "C:/App/dir"'), icRo);
const icWr = healCommand('icacls "C:\\App\\dir" /grant Everyone:F', "bash");
assert.ok(!icWr || !icWr.includes("probe win"), icWr);

// C. Hallucinated `ap` subcommand aliases
const apSurf = healCommand("ap bin_surface app.exe", "bash");
assert.equal(apSurf, "ap read app.exe --surface");
const apFiles = healCommand("ap files src", "bash");
assert.equal(apFiles, "ap ls src");
const apRg = healCommand("ap rg foo src", "bash");
assert.equal(apRg, "ap search foo src");

// D. Broken inline `python -c` quoting transport vs clean one-liner preservation
const pyOk = healCommand('python3 -c "print(1)"', "bash");
assert.ok(pyOk && pyOk.includes("PYTHONUTF8=1") && !pyOk.includes("--base64"), pyOk);
const pyBroken = healCommand('python3 -c "print(\'a\\\' + \'b\')"', "bash");
const pyBroken2 = healCommand('python3 -c "print(p.split(\'\\\'))"'.replace("\\\\", "\\"), "bash");
const pyUnclosed = healCommand('python3 -c "print(\'unclosed)', "bash");
assert.ok(pyUnclosed && pyUnclosed.includes("exec --lang py --base64 "), pyUnclosed);
assert.ok(pyBroken2 && pyBroken2.includes("exec --lang py --base64 "), pyBroken2);

// E. Updated guidelines include Wave-15 primitives
const g = AP_DEEPSEEK_GUIDELINES.join("\n");
assert.ok(g.includes("ap diff") && g.includes("--weak-acl") && g.includes("--roles-matrix"), g);
"###;

    let run = Command::new("node")
        .args([
            "--experimental-strip-types",
            "--input-type=module",
            "-e",
            node_check,
        ])
        .env("ACCEL_TS", &accel_ts)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "Node corpus_12 check failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn corpus_13_read_panic_win_unquoted_and_accel_v3() {
    let td = TempDir::new().unwrap();
    let root = td.path();

    // 1. Reproduce & verify fix for `src/read.rs:2253:77` panic on empty file + `--lines`
    let empty_f = root.join("empty.txt");
    fs::write(&empty_f, b"").unwrap();
    for args in [
        vec![
            "read",
            empty_f.to_str().unwrap(),
            "--lines",
            "1-50",
            "--json",
        ],
        vec![
            "read",
            empty_f.to_str().unwrap(),
            "--lines",
            "1-10,20-30",
            "--json",
        ],
        vec!["read", empty_f.to_str().unwrap(), "--tail", "10", "--json"],
    ] {
        let out = run_ap(root, &args, None, &[]);
        assert!(
            out.status.success(),
            "empty read {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let jv: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(jv["ok"], true, "{jv}");
    }

    // CJK multibyte `--lines --width` & `--offset` boundary safety
    let cjk_f = root.join("cjk.txt");
    fs::write(&cjk_f, "第一行中文测试内容很长很长\n第二行Hello世界\n").unwrap();
    for args in [
        vec![
            "read",
            cjk_f.to_str().unwrap(),
            "--lines",
            "1-2",
            "--width",
            "4",
            "--json",
        ],
        vec![
            "read",
            cjk_f.to_str().unwrap(),
            "--offset",
            "1",
            "--chars",
            "5",
            "--json",
        ],
    ] {
        let out = run_ap(root, &args, None, &[]);
        assert!(out.status.success(), "{args:?}");
    }

    // 2. `win.rs` `extract_service_exe_path` unquoted path WITHOUT trailing CLI args + bare system DLL
    let no_arg_unquoted = r"C:\Program Files\Vendor App\svc.exe";
    assert_eq!(
        ap_probe::win::extract_service_exe_path(no_arg_unquoted),
        no_arg_unquoted
    );
    let hops = ap_probe::win::find_unquoted_space_prefixes(no_arg_unquoted);
    assert_eq!(hops.len(), 2, "{hops:?}");
    assert_eq!(hops[0].0, r"C:\Program.exe");
    assert_eq!(hops[1].0, r"C:\Program Files\Vendor.exe");
    #[cfg(windows)]
    {
        let resolved = ap_probe::win::resolve_windows_exe_candidate("combase.dll");
        assert!(
            resolved
                .to_ascii_lowercase()
                .contains(r"\system32\combase.dll")
                || resolved
                    .to_ascii_lowercase()
                    .contains(r"\syswow64\combase.dll"),
            "expected System32/SysWOW64 resolution for combase.dll, got `{resolved}`"
        );
    }

    // 3. `zz-ap-accelerator.ts` v3 trailing-pipe python, multi-line exit-1 & quoted space grep fixes
    if !Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return;
    }
    let fake_home = root.join("home_c13");
    let ap_home = root.join("ap_home_c13");
    fs::create_dir_all(fake_home.join(".pi").join("agent")).unwrap();
    let init_out = run_ap(
        root,
        &["init", "-a", "pi", "--with-hooks", "--no-rules"],
        None,
        &[
            ("HOME", fake_home.as_path()),
            ("USERPROFILE", fake_home.as_path()),
            ("AP_HOME", ap_home.as_path()),
        ],
    );
    assert!(init_out.status.success());
    let accel_ts = fake_home
        .join(".pi")
        .join("agent")
        .join("extensions")
        .join("zz-ap-accelerator.ts");

    let node_check = r###"
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const { healCommand } = await import(pathToFileURL(process.env.ACCEL_TS).href);

// Balanced `python -c "..." | awk ... | head -60` must NEVER fold pipe into `--base64`
const pyPipeClean = healCommand('python -c "import sys; print(sys.version)" | awk \'{print $1}\' | head -60', "bash");
assert.ok(!pyPipeClean || !pyPipeClean.includes("--base64"), `unexpected base64 wrap: ${pyPipeClean}`);

// Broken inner python with trailing pipe keeps trailing pipe OUTSIDE `--base64`
const pyTrapPipe = healCommand('python3 -c "print(p.split(\'\\\'))" | head -20'.replace("\\\\", "\\"), "bash");
assert.ok(pyTrapPipe && pyTrapPipe.includes("exec --lang py --base64 ") && pyTrapPipe.trim().endsWith("| head -20"), pyTrapPipe);
const b64Part = pyTrapPipe.match(/--base64\s+([A-Za-z0-9+/=]+)/)?.[1] || "";
const decodedPy = Buffer.from(b64Part, "base64").toString("utf8");
assert.ok(!decodedPy.includes("| head -20"), `pipe leaked into python source: ${decodedPy}`);

// Multi-line scripts must NEVER be wrapped by wrapBenignSearchExit1
const multiLine = 'SDK="foo"\ngrep bar app.txt\nls . | grep baz';
const multiRes = healCommand(multiLine, "bash");
assert.ok(!multiRes || !multiRes.includes("_ap_ec="), `unexpected multi-line exit-1 wrap: ${multiRes}`);

// Quoted paths with spaces in `grep -n` rewrite cleanly to `ap search`
const spacedGrep = healCommand('grep -n "needle" "Program Files/Vendor Dir/cfg.xml"', "bash");
assert.ok(spacedGrep && spacedGrep.includes(" search ") && spacedGrep.includes("Program Files/Vendor Dir/cfg.xml"), spacedGrep);
"###;

    let run = Command::new("node")
        .args([
            "--experimental-strip-types",
            "--input-type=module",
            "-e",
            node_check,
        ])
        .env("ACCEL_TS", &accel_ts)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "Node corpus_13 check failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

fn build_synthetic_asar(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut files_map = serde_json::Map::new();
    let mut payload = Vec::new();
    for &(name, data, unpacked) in entries {
        let off = payload.len();
        if !unpacked {
            payload.extend_from_slice(data);
        }
        let mut obj = serde_json::Map::new();
        obj.insert("size".into(), json!(data.len()));
        obj.insert("offset".into(), json!(off.to_string()));
        if unpacked {
            obj.insert("unpacked".into(), json!(true));
        }
        files_map.insert(name.to_string(), Value::Object(obj));
    }
    let header_json = json!({ "files": files_map });
    let hdr_bytes = serde_json::to_vec(&header_json).unwrap();
    let aligned_len = (hdr_bytes.len() + 3) & !3;
    let pad = aligned_len - hdr_bytes.len();
    let mut asar = Vec::new();
    asar.extend_from_slice(&4u32.to_le_bytes());
    asar.extend_from_slice(&((aligned_len + 8) as u32).to_le_bytes());
    asar.extend_from_slice(&((aligned_len + 4) as u32).to_le_bytes());
    asar.extend_from_slice(&(hdr_bytes.len() as u32).to_le_bytes());
    asar.extend_from_slice(&hdr_bytes);
    asar.resize(asar.len() + pad, 0);
    asar.extend_from_slice(&payload);
    asar
}

#[test]
fn corpus_14_asar_surface_streaming_diff_and_sieve_sqlite() {
    let td = TempDir::new().unwrap();
    let root = td.path();

    // 1. `--asar-surface --json` handles minified `!0`/`!1`, IPC channels, sinks, protocols & `.unpacked` sibling dir
    let pkg = br#"{"name":"app","version":"2.0.0","main":"main.js","build":{"protocols":[{"name":"Demo","schemes":["demoapp"]}]}}"#;
    let main_v1 = br#"const {BrowserWindow:B,ipcMain:I,shell:S}=require("electron");new B({webPreferences:{nodeIntegration:!0,contextIsolation:!1,webSecurity:!1}});I.handle("app:open",(e,p)=>execFile(p));S.openExternal(u);axios.post("/api/v1/items/create",{name:n});"#;
    let helper_v1 = br#"exports.ping = () => "pong";"#;

    let asar_v1_path = root.join("app.asar");
    fs::write(
        &asar_v1_path,
        build_synthetic_asar(&[
            ("package.json", pkg, false),
            ("main.js", main_v1, false),
            ("helper.js", helper_v1, false),
        ]),
    )
    .unwrap();
    let unpacked_dir = root.join("app.asar.unpacked");
    fs::create_dir_all(&unpacked_dir).unwrap();
    fs::write(unpacked_dir.join("bridge.node"), b"MZ\x90\x00").unwrap();

    let surf_out = run_ap(
        root,
        &[
            "read",
            asar_v1_path.to_str().unwrap(),
            "--asar-surface",
            "--routes",
            "--json",
        ],
        None,
        &[],
    );
    assert!(
        surf_out.status.success(),
        "{}",
        String::from_utf8_lossy(&surf_out.stderr)
    );
    assert!(
        surf_out.stdout.len() < 10_000,
        "expected compact <10KB JSON, got {}B",
        surf_out.stdout.len()
    );
    let sj: Value = serde_json::from_slice(&surf_out.stdout).unwrap();
    assert_eq!(sj["format"], "asar-surface", "{sj}");
    let flags = sj["electron_security_flags"].as_array().unwrap();
    assert!(
        flags.iter().any(|f| f["kind"] == "nodeIntegration_enabled"),
        "{sj}"
    );
    assert!(
        flags
            .iter()
            .any(|f| f["kind"] == "contextIsolation_disabled"),
        "{sj}"
    );
    assert!(
        flags.iter().any(|f| f["kind"] == "webSecurity_disabled"),
        "{sj}"
    );
    assert_eq!(sj["ipc_handlers"][0]["channel"], "app:open", "{sj}");
    assert!(
        !sj["dangerous_sinks"].as_array().unwrap().is_empty(),
        "{sj}"
    );
    assert!(
        sj["native_bins"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["path"] == "bridge.node" && b["on_disk_unpacked"] == true),
        "{sj}"
    );
    assert_eq!(sj["manifests"][0]["protocols"][0], "demoapp", "{sj}");

    // 2. Streaming `.asar` diff detects modified code member without loading unchanged members into RAM
    let main_v2 = br#"const {BrowserWindow:B,ipcMain:I,shell:S}=require("electron");new B({webPreferences:{nodeIntegration:!0,contextIsolation:!1,webSecurity:!1}});I.handle("app:open",(e,p)=>execFile(p));I.handle("app:admin",(e,c)=>eval(c));S.openExternal(u);axios.post("/api/v1/items/create",{name:n});axios.delete("/api/v1/items/:id");"#;
    let asar_v2_path = root.join("app_v2.asar");
    fs::write(
        &asar_v2_path,
        build_synthetic_asar(&[
            ("package.json", pkg, false),
            ("main.js", main_v2, false),
            ("helper.js", helper_v1, false),
        ]),
    )
    .unwrap();

    let diff_out = run_ap(
        root,
        &[
            "diff",
            asar_v1_path.to_str().unwrap(),
            asar_v2_path.to_str().unwrap(),
            "--json",
        ],
        None,
        &[],
    );
    assert!(
        diff_out.status.success(),
        "{}",
        String::from_utf8_lossy(&diff_out.stderr)
    );
    let dj: Value = serde_json::from_slice(&diff_out.stdout).unwrap();
    assert_eq!(dj["streaming"], true, "{dj}");
    assert_eq!(dj["archive_summary"]["unchanged"], 2, "{dj}");
    assert_eq!(dj["archive_summary"]["modified_hash"], 1, "{dj}");

    // 3. `ap-sieve` cleans orphan SQLite rows and vacuums `index.sqlite`
    let sieve_home = root.join("sieve_c14");
    let fake_home_c14 = root.join("home_c14");
    fs::create_dir_all(&sieve_home).unwrap();
    fs::create_dir_all(&fake_home_c14).unwrap();
    let big_log = (0..180)
        .map(|i| format!("line-{i}: INFO verbose diagnostic entry c14orphanxyz padding abcdefghijklmnopqrstuvwxyz"))
        .collect::<Vec<_>>()
        .join("\n");
    let c1 = ap_sieve::compress_stream_in(&sieve_home, &big_log, "c14alpha", 0, 1.0);
    let _c2 = ap_sieve::compress_stream_in(
        &sieve_home,
        &format!("{big_log}\nextra-2"),
        "c14beta",
        0,
        1.0,
    );
    // Simulate orphan SQLite row where `.raw` was previously removed
    let _ = fs::remove_file(sieve_home.join(format!("{}.raw", c1.id)));
    let _ = fs::remove_file(sieve_home.join(format!("{}.meta.json", c1.id)));

    let env_c14 = [
        ("SIEVE_HOME", sieve_home.as_path()),
        ("HOME", fake_home_c14.as_path()),
        ("USERPROFILE", fake_home_c14.as_path()),
    ];
    let pr_out = run_ap(
        root,
        &["sieve", "prune", "--max-mb", "1", "--vacuum", "--json"],
        None,
        &env_c14,
    );
    assert!(
        pr_out.status.success(),
        "{}",
        String::from_utf8_lossy(&pr_out.stderr)
    );
    let pj: Value = serde_json::from_slice(&pr_out.stdout).unwrap();
    assert_eq!(pj["stores"][0]["vacuumed"], true, "{pj}");
    let srch = run_ap(
        root,
        &["sieve", "search", "c14alpha", "--json"],
        None,
        &env_c14,
    );
    assert!(srch.status.success());
    let sj2: Value = serde_json::from_slice(&srch.stdout).unwrap();
    assert_eq!(
        sj2["hits"].as_array().unwrap().len(),
        0,
        "orphan chunk row should be deleted: {sj2}"
    );
}

fn build_synthetic_pe64_driver(code: &[u8], rdata: &[u8]) -> Vec<u8> {
    // Minimal PE64 with Export (`DriverEntry`), `.text` (code), and `.rdata` (strings)
    let text_raw_ptr = 0x200usize;
    let text_raw_sz = code.len().max(16).div_ceil(0x200) * 0x200;
    let rdata_raw_ptr = text_raw_ptr + text_raw_sz;
    let rdata_raw_sz = (rdata.len() + 0x100).div_ceil(0x200) * 0x200;
    let total_len = rdata_raw_ptr + rdata_raw_sz;
    let mut pe = vec![0u8; total_len];

    pe[0..2].copy_from_slice(b"MZ");
    let pe_off = 0x80usize;
    pe[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    pe[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    pe[pe_off + 4..pe_off + 6].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[pe_off + 6..pe_off + 8].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    pe[pe_off + 20..pe_off + 22].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
    let opt = pe_off + 24;
    pe[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
    pe[opt + 24..opt + 32].copy_from_slice(&0x0001_4000_0000u64.to_le_bytes());

    let text_va = 0x1000u32;
    let rdata_va = 0x2000u32;
    let dd = opt + 112;
    // Export Directory in `.rdata` right after `rdata` bytes
    let exp_local_off = (rdata.len() + 15) & !15;
    let exp_rva = rdata_va + exp_local_off as u32;
    pe[dd..dd + 4].copy_from_slice(&exp_rva.to_le_bytes());
    pe[dd + 4..dd + 8].copy_from_slice(&0x60u32.to_le_bytes());

    let sec_base = opt + 0xF0;
    // .text
    pe[sec_base..sec_base + 5].copy_from_slice(b".text");
    pe[sec_base + 8..sec_base + 12].copy_from_slice(&(code.len() as u32).to_le_bytes());
    pe[sec_base + 12..sec_base + 16].copy_from_slice(&text_va.to_le_bytes());
    pe[sec_base + 16..sec_base + 20].copy_from_slice(&(text_raw_sz as u32).to_le_bytes());
    pe[sec_base + 20..sec_base + 24].copy_from_slice(&(text_raw_ptr as u32).to_le_bytes());
    pe[sec_base + 36..sec_base + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // .rdata
    let s2 = sec_base + 40;
    pe[s2..s2 + 6].copy_from_slice(b".rdata");
    pe[s2 + 8..s2 + 12].copy_from_slice(&((rdata.len() + 0x80) as u32).to_le_bytes());
    pe[s2 + 12..s2 + 16].copy_from_slice(&rdata_va.to_le_bytes());
    pe[s2 + 16..s2 + 20].copy_from_slice(&(rdata_raw_sz as u32).to_le_bytes());
    pe[s2 + 20..s2 + 24].copy_from_slice(&(rdata_raw_ptr as u32).to_le_bytes());
    pe[s2 + 36..s2 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

    pe[text_raw_ptr..text_raw_ptr + code.len()].copy_from_slice(code);
    pe[rdata_raw_ptr..rdata_raw_ptr + rdata.len()].copy_from_slice(rdata);

    // Populate minimal export table (`NumberOfNames=1`, `AddressOfNames`)
    let exp_file = rdata_raw_ptr + exp_local_off;
    let names_rva = exp_rva + 0x28;
    let str_rva = exp_rva + 0x30;
    pe[exp_file + 24..exp_file + 28].copy_from_slice(&1u32.to_le_bytes());
    pe[exp_file + 32..exp_file + 36].copy_from_slice(&names_rva.to_le_bytes());
    pe[exp_file + 0x28..exp_file + 0x2C].copy_from_slice(&str_rva.to_le_bytes());
    pe[exp_file + 0x30..exp_file + 0x3C].copy_from_slice(b"DriverEntry\0");
    pe
}

#[test]
fn corpus_15_routes_mutating_ioctl_pipes_and_cdp_export_role() {
    let td = TempDir::new().unwrap();
    let root = td.path();

    // 1. `--routes --mutating-only --json` filters out GET/query noise and keeps body_keys + risk_tags
    let bundle = root.join("bundle.js");
    fs::write(
        &bundle,
        r#"
        axios.get('/api/v1/public/catalog');
        axios.get('/api/v1/public/health');
        axios.get('/api/v1/public/banner');
        fetch('/api/v1/admin/grant', { method: 'POST', body: JSON.stringify({ userId: 42, roleName: 'admin' }) });
        axios.delete('/api/v1/files/:id', { data: { filePath: '/tmp/a' } });
        const q = `query ListDocs { docs { id } }`;
        const m = `mutation DeleteDoc($id: ID!) { deleteDoc(id: $id) }`;
        "#,
    )
    .unwrap();
    let all_r = run_ap(
        root,
        &["read", bundle.to_str().unwrap(), "--routes", "--json"],
        None,
        &[],
    );
    let mut_r = run_ap(
        root,
        &[
            "read",
            bundle.to_str().unwrap(),
            "--routes",
            "--mutating-only",
            "--json",
        ],
        None,
        &[],
    );
    assert!(all_r.status.success() && mut_r.status.success());
    let mj: Value = serde_json::from_slice(&mut_r.stdout).unwrap();
    let surf = &mj["surface"];
    assert_eq!(surf["mutating_only"], true, "{mj}");
    let routes = surf["routes"].as_array().unwrap();
    assert!(
        routes.iter().all(|r| r["method"] != "GET"),
        "expected 0 GET routes: {routes:?}"
    );
    let grant = routes
        .iter()
        .find(|r| r["path"] == "/api/v1/admin/grant")
        .unwrap();
    assert!(
        grant["body_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k == "userId" || k == "roleName"),
        "{grant}"
    );
    assert!(
        grant["risk_tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "AUTH_ADMIN"),
        "{grant}"
    );
    assert!(
        surf["graphql_ops"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["kind"] == "mutation"),
        "{surf}"
    );
    assert!(
        mut_r.stdout.len() < all_r.stdout.len(),
        "mutating-only should shrink JSON"
    );

    // 2. `ap read <driver.sys> --ioctl --pipes --json`
    // Code: `sub rsp, 0x28` (48 83 EC 28), `mov eax, 0x00222003` (B8 03 20 22 00), `cmp ecx, 0x80002004` (81 F9 04 20 00 80)
    let code: Vec<u8> = vec![
        0x48, 0x83, 0xEC, 0x28, 0xB8, 0x03, 0x20, 0x22, 0x00, 0x81, 0xF9, 0x04, 0x20, 0x00, 0x80,
        0xC3,
    ];
    let mut rdata: Vec<u8> = Vec::new();
    rdata.extend_from_slice(br"\Device\DemoCtl");
    rdata.push(0);
    for ch in r"\\.\pipe\demo_ctl_pipe".encode_utf16() {
        rdata.extend_from_slice(&ch.to_le_bytes());
    }
    rdata.extend_from_slice(&[0, 0]);
    let sys_path = root.join("demo_drv.sys");
    fs::write(&sys_path, build_synthetic_pe64_driver(&code, &rdata)).unwrap();
    let io_out = run_ap(
        root,
        &[
            "read",
            sys_path.to_str().unwrap(),
            "--ioctl",
            "--pipes",
            "--json",
        ],
        None,
        &[],
    );
    assert!(
        io_out.status.success(),
        "{}",
        String::from_utf8_lossy(&io_out.stderr)
    );
    let ioj: Value = serde_json::from_slice(&io_out.stdout).unwrap();
    assert_eq!(ioj["format"], "binary-ioctl-pipes", "{ioj}");
    let ioctls = ioj["ioctl_codes"].as_array().unwrap();
    assert!(
        ioctls
            .iter()
            .any(|c| c["code"] == "0x00222003" && c["method"] == "METHOD_NEITHER"),
        "{ioj}"
    );
    assert!(ioctls.iter().any(|c| c["code"] == "0x80002004"), "{ioj}");
    let pipes = ioj["device_pipes"].as_array().unwrap();
    assert!(
        pipes
            .iter()
            .any(|p| p["value"].as_str().unwrap().contains("demo_ctl_pipe")),
        "{ioj}"
    );
    assert!(
        pipes
            .iter()
            .any(|p| p["value"].as_str().unwrap().contains(r"\Device\DemoCtl")),
        "{ioj}"
    );
    assert!(
        ioj["exports"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e == "DriverEntry"),
        "{ioj}"
    );

    // 3. Mock CDP `--export-role` + `ap probe http --roles-matrix --vary-json-field` + `LOGIN_HTML`/`302`/array
    let cdp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let cdp_port = cdp_listener.local_addr().unwrap().port();
    let stop_cdp = Arc::new(AtomicBool::new(false));
    let stop_cdp_c = Arc::clone(&stop_cdp);
    let cdp_srv = thread::spawn(move || {
        let _ = cdp_listener.set_nonblocking(true);
        while !stop_cdp_c.load(Ordering::Relaxed) {
            match cdp_listener.accept() {
                Ok((mut sock, _)) => {
                    let _ = sock.set_nonblocking(false);
                    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                    let req = read_http_req_wire(&mut sock);
                    if req.starts_with("GET /json/list") || req.starts_with("GET /json ") {
                        let targets = json!([{
                            "id": "tab1",
                            "type": "page",
                            "title": "Demo App",
                            "url": format!("http://127.0.0.1:{cdp_port}/app"),
                            "webSocketDebuggerUrl": format!("ws://127.0.0.1:{cdp_port}/devtools/page/tab1"),
                        }])
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{targets}",
                            targets.len()
                        );
                        let _ = sock.write_all(resp.as_bytes());
                    } else if let Some(_key_line) = req
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
                    {
                        let _ = sock.write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: dummy=\r\n\r\n",
                        );
                        // Read CDP command frames (enable calls + Network.getCookies + Runtime.evaluate) and reply
                        for _ in 0..10 {
                            let mut hdr = [0u8; 2];
                            if sock.read_exact(&mut hdr).is_err() {
                                break;
                            }
                            let mut plen = (hdr[1] & 0x7F) as usize;
                            if plen == 126 {
                                let mut b = [0u8; 2];
                                if sock.read_exact(&mut b).is_err() {
                                    break;
                                }
                                plen = u16::from_be_bytes(b) as usize;
                            }
                            let mut mask = [0u8; 4];
                            if (hdr[1] & 0x80) != 0 && sock.read_exact(&mut mask).is_err() {
                                break;
                            }
                            let mut data = vec![0u8; plen];
                            if sock.read_exact(&mut data).is_err() {
                                break;
                            }
                            if (hdr[1] & 0x80) != 0 {
                                for (idx, b) in data.iter_mut().enumerate() {
                                    *b ^= mask[idx & 3];
                                }
                            }
                            let msg: Value = serde_json::from_slice(&data).unwrap_or(Value::Null);
                            let cid = msg["id"].as_u64().unwrap_or(1);
                            let meth = msg["method"].as_str().unwrap_or("");
                            let reply = if meth == "Network.getCookies" {
                                json!({
                                    "id": cid,
                                    "result": {
                                        "cookies": [
                                            { "name": "sid", "value": "sess_owner_1" },
                                            { "name": "XSRF-TOKEN", "value": "xsrf_val_9" }
                                        ]
                                    }
                                })
                            } else if meth == "Runtime.evaluate" {
                                json!({
                                    "id": cid,
                                    "result": {
                                        "result": {
                                            "value": json!({
                                                "storage": [["localStorage.authToken", "eyJhbGciOiJIUzI1NiJ9.payload.sig"]],
                                                "metas": []
                                            }).to_string()
                                        }
                                    }
                                })
                            } else {
                                json!({ "id": cid, "result": {} })
                            }
                            .to_string();
                            let rb = reply.as_bytes();
                            let mut frame = Vec::with_capacity(rb.len() + 4);
                            frame.push(0x81);
                            if rb.len() <= 125 {
                                frame.push(rb.len() as u8);
                            } else {
                                frame.push(126);
                                frame.extend_from_slice(&(rb.len() as u16).to_be_bytes());
                            }
                            frame.extend_from_slice(rb);
                            let _ = sock.write_all(&frame);
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let exp_out = run_ap(
        root,
        &[
            "probe",
            "cdp",
            "--export-role",
            &cdp_port.to_string(),
            "--role-name",
            "owner",
            "--json",
        ],
        None,
        &[],
    );
    stop_cdp.store(true, Ordering::Relaxed);
    let _ = cdp_srv.join();
    assert!(
        exp_out.status.success(),
        "{}",
        String::from_utf8_lossy(&exp_out.stderr)
    );
    let ej: Value = serde_json::from_slice(&exp_out.stdout).unwrap();
    assert_eq!(ej["mode"], "export_role", "{ej}");
    assert_eq!(ej["role"]["name"], "owner", "{ej}");
    let hdrs = ej["role"]["headers"].as_array().unwrap();
    assert!(
        hdrs.iter()
            .any(|h| h.as_str().unwrap().contains("sid=sess_owner_1")),
        "{ej}"
    );
    assert!(
        hdrs.iter()
            .any(|h| h.as_str().unwrap().starts_with("Authorization: Bearer eyJ")),
        "{ej}"
    );
    assert!(
        hdrs.iter()
            .any(|h| h.as_str().unwrap() == "X-XSRF-TOKEN: xsrf_val_9"),
        "{ej}"
    );

    // 4. `http_probe` `--vary-json-field` + `LOGIN_HTML` + `302 /login` + JSON-array root diff
    let http_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    let stop_http = Arc::new(AtomicBool::new(false));
    let stop_http_c = Arc::clone(&stop_http);
    let http_srv = thread::spawn(move || {
        let _ = http_listener.set_nonblocking(true);
        while !stop_http_c.load(Ordering::Relaxed) {
            match http_listener.accept() {
                Ok((mut sock, _)) => {
                    let _ = sock.set_nonblocking(false);
                    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                    let req = read_http_req_wire(&mut sock);
                    let req_line = req.lines().next().unwrap_or("");
                    let low = req.to_ascii_lowercase();
                    let (status, ct, extra_hdr, body) = if req_line.contains("/arr") {
                        if low.contains("bearer owner_tok") {
                            (
                                "200 OK",
                                "application/json",
                                "",
                                r#"[{"id":101,"name":"Alpha"}]"#,
                            )
                        } else {
                            ("200 OK", "application/json", "", "[]")
                        }
                    } else if low.contains("bearer anon_login_html") {
                        (
                            "200 OK",
                            "text/html",
                            "",
                            "<html><body><form action=\"/login\"><input type=\"password\" name=\"password\"></form></body></html>",
                        )
                    } else if !low.contains("authorization:") {
                        ("302 Found", "text/html", "Location: /login\r\n", "")
                    } else if req_line.starts_with("POST ") && req.contains("\"docId\":\"101\"") {
                        ("200 OK", "application/json", "", r#"{"updated":"101"}"#)
                    } else {
                        (
                            "403 Forbidden",
                            "application/json",
                            "",
                            r#"{"err":"denied"}"#,
                        )
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {ct}\r\n{extra_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let rm_out = run_ap(
        root,
        &[
            "probe",
            "http",
            &format!("http://127.0.0.1:{http_port}/api/update"),
            "-X",
            "POST",
            "-d",
            r#"{"docId":"999","title":"hi"}"#,
            "--vary-json-field",
            "docId",
            "--principal",
            "owner=Authorization: Bearer owner_tok",
            "--principal",
            "other=Authorization: Bearer anon_login_html",
            "--principal",
            "anon=",
            "--role-var",
            "owner:docId=101",
            "--role-var",
            "other:docId=102",
            "--cross-id",
            "--json",
        ],
        None,
        &[],
    );
    let arr_out = run_ap(
        root,
        &[
            "probe",
            "http",
            &format!("http://127.0.0.1:{http_port}/arr"),
            "--principal",
            "owner=Authorization: Bearer owner_tok",
            "--principal",
            "other=Authorization: Bearer other_tok",
            "--json",
        ],
        None,
        &[],
    );
    stop_http.store(true, Ordering::Relaxed);
    let _ = http_srv.join();

    assert!(
        rm_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rm_out.stderr)
    );
    let rmj: Value = serde_json::from_slice(&rm_out.stdout).unwrap();
    let matrix = rmj["matrix"].as_array().unwrap();
    assert!(
        matrix
            .iter()
            .any(|r| r["actor"] == "anon" && r["verdict"] == "AUTH_REDIRECT_LOGIN"),
        "{rmj}"
    );
    assert!(
        matrix
            .iter()
            .any(|r| r["actor"] == "other" && r["verdict"] == "LOGIN_HTML"),
        "{rmj}"
    );
    assert!(
        matrix
            .iter()
            .any(|r| r["actor"] == "owner" && r["target_owner"] == "owner" && r["status"] == 200),
        "expected `--vary-json-field docId` rewrite to 101: {rmj}"
    );

    assert!(arr_out.status.success());
    let arrj: Value = serde_json::from_slice(&arr_out.stdout).unwrap();
    assert_eq!(arrj["possible_bypass_count"], 0, "{arrj}");

    #[cfg(windows)]
    {
        for wargs in [
            vec![
                "probe",
                "win",
                "--services",
                "--non-ms",
                "--max",
                "10",
                "--json",
            ],
            vec!["probe", "win", "--rpc", "--non-ms", "--max", "10", "--json"],
        ] {
            let wo = run_ap(root, &wargs, None, &[]);
            assert!(wo.status.success(), "{wargs:?}");
            let wj: Value = serde_json::from_slice(&wo.stdout).unwrap();
            assert_eq!(wj["ok"], true, "{wj}");
        }
    }
}
