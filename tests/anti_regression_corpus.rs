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
