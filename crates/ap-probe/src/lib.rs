pub mod cdp;
pub mod fs_diff;
pub mod fuzz;
pub mod http_probe;
pub mod mutate;
pub mod net_probe;
pub mod ports;
pub mod ps;
pub mod runtime;
pub mod slice;
pub mod smoke;
pub mod ui;

use base64::Engine;
use clap::{Parser, Subcommand};
use fuzz::run_fuzz;
use mutate::run_mutate;
use runtime::{detect_lang, run_diff_dispatch, run_trace_dispatch};
use slice::run_slice;
use smoke::run_smoke;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use ui::run_ui_audit;

#[derive(Parser, Debug)]
#[command(
    name = "probe",
    about = "Tree-sitter reachability slicer, runtime microscope & differential oracle"
)]
struct Cli {
    #[command(subcommand)]
    cmd: SubCmd,
}

#[derive(Subcommand, Debug)]
enum SubCmd {
    /// Static Tree-sitter/import reachability slice (Python, TS/JS, Go, Rust, C) & active bundle
    Slice {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long = "entry")]
        entries: Vec<String>,
        #[arg(long)]
        bundle: bool,
        #[arg(long, default_value_t = 18)]
        max_bundle_kb: usize,
        #[arg(long)]
        json: bool,
    },
    /// Trace execution & auto-detect heap aliasing, in-place mutation, and state no-ops
    Run {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long, default_value = "auto")]
        lang: String,
        #[arg(long, default_value = "")]
        focus: String,
        #[arg(long)]
        code: Option<String>,
        #[arg(long)]
        b64: Option<String>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        script: Option<String>,
        #[arg(long)]
        unittest: Option<String>,
        #[arg(long, default_value_t = 30)]
        max_calls: usize,
        #[arg(long)]
        include_tests: bool,
        #[arg(long)]
        json: bool,
    },
    /// Differential & boundary-matrix oracle across Python, TS/JS, or Rust
    Diff {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long, default_value = "auto")]
        lang: String,
        #[arg(long, default_value = "")]
        setup: String,
        #[arg(long)]
        fn_a: String,
        #[arg(long)]
        fn_b: String,
        #[arg(long, default_value = "")]
        vars: String,
        #[arg(long, default_value = "")]
        inputs: String,
        #[arg(long)]
        json: bool,
    },
    /// Interactive headless CDP browser (OPEN/FILL/SELECT/CLICK/EVAL) + HTTP E2E server runner.
    /// Stdin DSL steps: OPEN / | FILL #id val | SELECT #id val | CLICK #id or text=Btn | EVAL <js>
    /// | GET/POST/PUT/PATCH/DELETE /api/... | BODY {...} | EXPECT STATUS 200 | EXPECT CONTAINS txt | EXPECT JSON a.b == 1
    Smoke {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long)]
        start: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long, default_value = "/")]
        ready_path: String,
        #[arg(long, default_value_t = 12000)]
        timeout_ms: u64,
        #[arg(long = "env")]
        envs: Vec<String>,
        #[arg(long)]
        spec: Option<PathBuf>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        json: bool,
    },
    /// Adversarial HTTP/API & CLI chaos fuzzer (malformed JSON, negative/zero/NaN, CJK/SQLi & Barrier concurrency burst)
    Fuzz {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long)]
        start: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        cli: Option<String>,
        #[arg(long, default_value_t = 8)]
        concurrency: usize,
        #[arg(long)]
        json: bool,
    },
    /// Sub-2s polyglot Tree-sitter AST mutation tester (seeds boundary/operator faults to expose weak unit tests)
    Mutate {
        target: PathBuf,
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long)]
        test_cmd: Option<String>,
        #[arg(long, default_value_t = 8)]
        max_mutants: usize,
        #[arg(long)]
        json: bool,
    },
    /// Dual-observability headless Edge/Chrome UI auditor (Desktop+Mobile overflow, overlapped/blocked buttons, broken <img>, JS errors & 4xx/5xx network leaks)
    Ui {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long)]
        start: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long, default_value = "/")]
        path: String,
        #[arg(long, default_value_t = true)]
        mobile: bool,
        #[arg(long)]
        screenshot: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Attach to an ALREADY-RUNNING Chrome/Edge/Electron/WebView CDP debugging port (--list, --target, --eval, --audit, --screenshot, --watch-ms, --diff-ports, --stdin) without killing the host app
    Cdp {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(short = 'p', long, default_value_t = 9222)]
        port: u16,
        /// Optional pair of ports `portA,portB` to concurrently evaluate `--eval` and compute structured diff
        #[arg(long)]
        diff_ports: Option<String>,
        /// Optional pair of target filters/IDs `targetA,targetB` paired with `--diff-ports`
        #[arg(long)]
        target_ids: Option<String>,
        #[arg(long)]
        list: bool,
        #[arg(short = 't', long)]
        target: Option<String>,
        #[arg(short = 'e', long)]
        eval: Option<String>,
        #[arg(long)]
        audit: bool,
        #[arg(long)]
        screenshot: Option<PathBuf>,
        #[arg(long)]
        stdin: bool,
        /// Non-blocking bounded event watch window in ms (captures async console logs & network responses without hanging)
        #[arg(long, default_value_t = 0)]
        watch_ms: u64,
        #[arg(long)]
        json: bool,
    },
    /// Cross-platform listening TCP port, process PID & live CDP DevTools radar (replaces netstat/lsof/ss + port guessing)
    Ports {
        #[arg(short = 'p', long)]
        port: Option<u16>,
        /// Probe localhost ports for `/json/version` to auto-badge `[CDP READY]` debugging ports (default: true)
        #[arg(long, default_value_t = true)]
        probe_cdp: bool,
        #[arg(long)]
        json: bool,
    },
    /// Zero-dependency HTTP/API diagnostic probe (single URL, `--batch-stdin`, or single-field `--vary-field` outlier analyzer)
    Http {
        /// Optional single target URL (omit when using `--batch-stdin` or `--vary-request`)
        url: Option<String>,
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        #[arg(short = 'd', long)]
        body: Option<String>,
        #[arg(long, default_value_t = 15)]
        timeout: u64,
        #[arg(short = 'k', long)]
        insecure: bool,
        #[arg(short = 'L', long)]
        follow: bool,
        /// Read `METHOD URL [BODY]` lines from stdin to probe up to 25 endpoints in one call
        #[arg(long)]
        batch_stdin: bool,
        /// Optional saved JSON or raw HTTP request file for `--vary-field` single-field testing
        #[arg(long)]
        vary_request: Option<PathBuf>,
        /// Vary one single JSON/query/header field across boundary variants and cluster response outliers
        #[arg(long)]
        vary_field: Option<String>,
        /// Optional alternate value used by `--vary-field`
        #[arg(long)]
        alt_value: Option<String>,
        /// Delay in ms between serial `--vary-field` requests (default: 0, max: 5000)
        #[arg(long, default_value_t = 0)]
        rate_ms: u64,
        /// Maximum number of `--vary-field` variants (default: 20, max: 100)
        #[arg(long, default_value_t = 20)]
        max_variants: usize,
        /// Generate `--vary-field` variants without sending any network request
        #[arg(long)]
        dry_run: bool,
        /// Multi-principal AuthZ/IDOR matrix (`--principal "owner=Authorization: Bearer A" --principal "anon="`)
        #[arg(long = "principal")]
        principals: Vec<String>,
        /// Audit response headers for security & two-phase storage/CORS/CSP/cookie gaps
        #[arg(long)]
        audit_headers: bool,
        #[arg(long)]
        json: bool,
    },
    /// Cross-platform running process tree, full command-line & listening TCP port inspector (replaces wmic/tasklist/ps)
    Ps {
        #[arg(short = 'f', long)]
        filter: Option<String>,
        #[arg(short = 'p', long)]
        pid: Option<u32>,
        /// Join listening TCP ports onto each matched process (default: true)
        #[arg(long, default_value_t = true)]
        ports: bool,
        #[arg(long, default_value_t = 40)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Atomic before/after directory snapshot diff (`--run`, `--snapshot`, `--diff`) & newest-files radar (`--recent`)
    Fs {
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// Show files modified within the last N seconds (0 = show newest N files overall)
        #[arg(long, default_value_t = 0)]
        recent: u64,
        /// Save a named directory snapshot for later `--diff`
        #[arg(long)]
        snapshot: Option<String>,
        /// Diff current directory against a previously saved `--snapshot <NAME>`
        #[arg(long)]
        diff: Option<String>,
        /// Run command and atomically diff added/modified/deleted files in `<dir>` before & after
        #[arg(long)]
        run: Option<String>,
        #[arg(long, default_value_t = 60)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Deadline-bounded raw TCP banner & text/hex send-recv probe (replaces `nc`/`telnet` & hanging Python sockets)
    Tcp {
        /// Target `host:port` (e.g. `127.0.0.1:6379`)
        addr: String,
        /// Optional text payload to send (supports `\r`, `\n`, `\t`, `\0`)
        #[arg(long)]
        send: Option<String>,
        /// Optional hex-encoded binary payload to send (e.g. `050100`)
        #[arg(long)]
        send_hex: Option<String>,
        /// Max read wait window in ms (default: 800, max: 10000)
        #[arg(long, default_value_t = 800)]
        wait_ms: u64,
        /// TCP connect timeout in ms (default: 3000)
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
        #[arg(long)]
        json: bool,
    },
    /// Bounded ephemeral HTTP webhook/callback capture server (auto-exits after `--max-reqs` or `--wait-ms`, zero orphan server leaks)
    Listen {
        /// Port to bind on 127.0.0.1 (0 = ephemeral free port)
        #[arg(short = 'p', long, default_value_t = 0)]
        port: u16,
        /// Max wait window in ms before clean exit (default: 5000, max: 30000)
        #[arg(long, default_value_t = 5000)]
        wait_ms: u64,
        /// Stop cleanly after capturing N HTTP requests (default: 1)
        #[arg(long, default_value_t = 1)]
        max_reqs: usize,
        #[arg(long, default_value_t = 200)]
        reply_status: u16,
        #[arg(long, default_value = "application/json")]
        reply_type: String,
        #[arg(long, default_value = "{\"ok\":true}")]
        reply_body: String,
        /// Optional command to trigger while listening (replaces `{{PORT}}` with the bound port)
        #[arg(long)]
        run: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Deadline-bounded RFC 6455 generic WebSocket (`ws://`) send/recv diagnostic client (zero hangs)
    Ws {
        url: String,
        #[arg(long = "send")]
        send: Vec<String>,
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        #[arg(long, default_value_t = 1000)]
        wait_ms: u64,
        #[arg(long)]
        json: bool,
    },
    /// Cross-platform TLS protocol & X.509 certificate Subject/Issuer/Expiry/SHA-256 inspector
    Tls {
        addr: String,
        #[arg(long)]
        sni: Option<String>,
        #[arg(long, default_value_t = 6)]
        timeout: u64,
        #[arg(long)]
        json: bool,
    },
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    match cli.cmd {
        SubCmd::Slice {
            root,
            entries,
            bundle,
            max_bundle_kb,
            json,
        } => run_slice(&root, &entries, json, bundle, max_bundle_kb).1,
        SubCmd::Run {
            cwd,
            lang,
            focus,
            code,
            b64,
            stdin,
            script,
            unittest,
            max_calls,
            include_tests,
            json,
        } => {
            let snippet = if stdin {
                let mut s = String::new();
                let _ = std::io::stdin().read_to_string(&mut s);
                Some(s)
            } else if let Some(b) = b64 {
                match base64::engine::general_purpose::STANDARD.decode(b.trim()) {
                    Ok(bytes) => Some(String::from_utf8_lossy(&bytes).to_string()),
                    Err(e) => {
                        eprintln!("[probe run] invalid --b64 payload: {e}");
                        return 2;
                    }
                }
            } else {
                code
            };
            if snippet.is_none() && script.is_none() && unittest.is_none() {
                eprintln!(
                    "[probe run] pass one of --code, --stdin, --b64, --script, or --unittest"
                );
                return 2;
            }
            let plang = detect_lang(&cwd, &lang, &focus, snippet.as_deref(), script.as_deref());
            run_trace_dispatch(
                &cwd,
                plang,
                &focus,
                snippet.as_deref(),
                script.as_deref(),
                unittest.as_deref(),
                max_calls,
                include_tests,
                json,
            )
        }
        SubCmd::Diff {
            cwd,
            lang,
            setup,
            fn_a,
            fn_b,
            vars,
            inputs,
            json,
        } => {
            let combined = format!("{setup}\n{fn_a}");
            let plang = detect_lang(&cwd, &lang, "", Some(&combined), None);
            run_diff_dispatch(&cwd, plang, &setup, &fn_a, &fn_b, &vars, &inputs, json)
        }
        SubCmd::Smoke {
            cwd,
            start,
            url,
            ready_path,
            timeout_ms,
            envs,
            spec,
            stdin,
            json,
        } => {
            let spec_text = if stdin {
                let mut s = String::new();
                let _ = std::io::stdin().read_to_string(&mut s);
                s
            } else if let Some(sp) = spec {
                match fs::read_to_string(&sp) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[probe smoke] failed to read {}: {e}", sp.display());
                        return 2;
                    }
                }
            } else {
                let default_p = cwd.join(".agents").join("smoke.ap");
                if default_p.is_file() {
                    fs::read_to_string(default_p).unwrap_or_default()
                } else {
                    String::new()
                }
            };
            let parsed_envs: Vec<(String, String)> = envs
                .into_iter()
                .filter_map(|kv| {
                    kv.split_once('=')
                        .map(|(k, v)| (k.trim().to_string(), v.to_string()))
                })
                .collect();
            run_smoke(
                &cwd,
                start.as_deref(),
                url.as_deref(),
                &ready_path,
                timeout_ms,
                &parsed_envs,
                &spec_text,
                json,
            )
        }
        SubCmd::Fuzz {
            cwd,
            start,
            url,
            cli,
            concurrency,
            json,
        } => run_fuzz(
            &cwd,
            start.as_deref(),
            url.as_deref(),
            cli.as_deref(),
            concurrency,
            json,
        ),
        SubCmd::Mutate {
            target,
            cwd,
            test_cmd,
            max_mutants,
            json,
        } => run_mutate(&cwd, &target, test_cmd.as_deref(), max_mutants, json),
        SubCmd::Ui {
            cwd,
            start,
            url,
            path,
            mobile,
            screenshot,
            json,
        } => run_ui_audit(
            &cwd,
            start.as_deref(),
            url.as_deref(),
            &path,
            mobile,
            screenshot.as_deref(),
            json,
        ),
        SubCmd::Cdp {
            host,
            port,
            diff_ports,
            target_ids,
            list,
            target,
            eval,
            audit,
            screenshot,
            stdin,
            watch_ms,
            json,
        } => {
            if let Some(dp) = diff_ports.as_deref().filter(|s| !s.trim().is_empty()) {
                let parts: Vec<u16> = dp
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .collect();
                if parts.len() != 2 {
                    eprintln!("[probe cdp] --diff-ports requires two comma-separated ports, e.g. `9222,9223`");
                    return 2;
                }
                let Some(expr) = eval.as_deref().filter(|s| !s.trim().is_empty()) else {
                    eprintln!("[probe cdp] --diff-ports requires `--eval <JS>`");
                    return 2;
                };
                let (ta, tb) = if let Some(tids) = target_ids.as_deref() {
                    let mut it = tids.splitn(2, ',');
                    let a = it.next().map(str::trim).filter(|s| !s.is_empty());
                    let b = it.next().map(str::trim).filter(|s| !s.is_empty());
                    (a, b)
                } else {
                    (target.as_deref(), target.as_deref())
                };
                return cdp::run_cdp_diff_ports(&host, parts[0], parts[1], ta, tb, expr, json);
            }
            let mut steps = String::new();
            if stdin {
                let _ = std::io::stdin().read_to_string(&mut steps);
            }
            cdp::run_cdp_attach(
                &host,
                port,
                list,
                target.as_deref(),
                eval.as_deref(),
                audit,
                screenshot.as_deref(),
                &steps,
                watch_ms,
                json,
            )
        }
        SubCmd::Ports {
            port,
            probe_cdp,
            json,
        } => ports::run_ports_radar(port, probe_cdp, json),
        SubCmd::Http {
            url,
            method,
            headers,
            body,
            timeout,
            insecure,
            follow,
            batch_stdin,
            vary_request,
            vary_field,
            alt_value,
            rate_ms,
            max_variants,
            dry_run,
            principals,
            audit_headers,
            json,
        } => {
            if !principals.is_empty() {
                return http_probe::run_http_auth_matrix(
                    vary_request.as_deref(),
                    url.as_deref(),
                    &method,
                    &headers,
                    body.as_deref(),
                    &principals,
                    audit_headers,
                    timeout,
                    insecure,
                    follow,
                    json,
                );
            }
            if let Some(vf) = vary_field.as_deref().filter(|s| !s.trim().is_empty()) {
                return http_probe::run_http_vary(
                    vary_request.as_deref(),
                    url.as_deref(),
                    &method,
                    &headers,
                    body.as_deref(),
                    vf,
                    alt_value.as_deref(),
                    rate_ms,
                    max_variants,
                    dry_run,
                    timeout,
                    insecure,
                    follow,
                    json,
                );
            }
            http_probe::run_http_cli(
                url.as_deref(),
                &method,
                &headers,
                body.as_deref(),
                timeout,
                insecure,
                follow,
                batch_stdin,
                audit_headers,
                json,
            )
        }
        SubCmd::Ps {
            filter,
            pid,
            ports,
            limit,
            json,
        } => ps::run_ps_cli(filter.as_deref(), pid, ports, limit, json),
        SubCmd::Fs {
            dir,
            recent,
            snapshot,
            diff,
            run,
            limit,
            json,
        } => fs_diff::run_fs_cli(
            &dir,
            recent,
            snapshot.as_deref(),
            diff.as_deref(),
            run.as_deref(),
            limit,
            json,
        ),
        SubCmd::Tcp {
            addr,
            send,
            send_hex,
            wait_ms,
            timeout_ms,
            json,
        } => net_probe::run_tcp_cli(
            &addr,
            send.as_deref(),
            send_hex.as_deref(),
            wait_ms,
            timeout_ms,
            json,
        ),
        SubCmd::Listen {
            port,
            wait_ms,
            max_reqs,
            reply_status,
            reply_type,
            reply_body,
            run,
            json,
        } => net_probe::run_listen_cli(
            port,
            wait_ms,
            max_reqs,
            reply_status,
            &reply_type,
            &reply_body,
            run.as_deref(),
            json,
        ),
        SubCmd::Ws {
            url,
            send,
            headers,
            wait_ms,
            json,
        } => net_probe::run_ws_cli(&url, &send, &headers, wait_ms, json),
        SubCmd::Tls {
            addr,
            sni,
            timeout,
            json,
        } => net_probe::run_tls_cli(&addr, sni.as_deref(), timeout, json),
    }
}
