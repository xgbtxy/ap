pub mod cdp;
pub mod fs_diff;
pub mod fuzz;
pub mod har_probe;
pub mod http_probe;
pub mod mutate;
pub mod net_probe;
pub mod ports;
pub mod ps;
pub mod runtime;
pub mod slice;
pub mod smoke;
pub mod ui;
pub mod win;

use base64::Engine;
use clap::{Args, Parser, Subcommand};
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

#[derive(Args, Debug)]
struct RunArgs {
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
}

#[derive(Args, Debug)]
struct SmokeArgs {
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
}

#[derive(Args, Debug)]
struct CdpArgs {
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
    /// Read raw JavaScript expression/statements from stdin and evaluate via CDP
    #[arg(long)]
    eval_stdin: bool,
    #[arg(long)]
    audit: bool,
    #[arg(long)]
    screenshot: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
    /// Non-blocking bounded event watch window in ms (captures async console logs & network responses without hanging)
    #[arg(long, default_value_t = 0)]
    watch_ms: u64,
    /// Export cookies + localStorage/sessionStorage auth/CSRF headers into `ap probe http --roles-matrix` JSON schema (`--export-role [PORT]`)
    #[arg(long = "export-role", num_args = 0..=1, default_missing_value = "")]
    export_role: Option<String>,
    /// Role label to emit with `--export-role` (default: `role1`)
    #[arg(long = "role-name", default_value = "role1")]
    role_name: String,
    /// Origin URL filter to match target/cookies for `--export-role`
    #[arg(long)]
    origin: Option<String>,
    /// Skip localStorage/sessionStorage extraction during `--export-role` (cookies only)
    #[arg(long = "no-storage")]
    no_storage: bool,
    /// Redact exported secret header values when printing `--export-role` output
    #[arg(long)]
    redact: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct HttpArgs {
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
    /// Reuse live cookies in-memory from a local `127.0.0.1` CDP browser port (zero tabs opened, values never printed)
    #[arg(long)]
    cdp_cookies: Option<u16>,
    /// Multi-principal AuthZ matrix reusing live local CDP browser sessions (`--principal-cdp owner=9451 --principal-cdp other=9470`)
    #[arg(long = "principal-cdp")]
    principal_cdps: Vec<String>,
    /// Send a cross-origin `Origin: <url>` header and audit Access-Control-Allow-Origin / Allow-Credentials / Vary reflection
    #[arg(long)]
    cors_origin: Option<String>,
    /// Extract a dot-separated JSON path (supports `[*]` array projection) from JSON responses
    #[arg(long)]
    select: Option<String>,
    /// Audit response headers for security & two-phase storage/CORS/CSP/cookie gaps
    #[arg(long)]
    audit_headers: bool,
    /// Synchronized Barrier concurrency/TOCTOU race burst count (2..=32 parallel threads firing simultaneously)
    #[arg(long, default_value_t = 0)]
    race: usize,
    /// Run bounded 7-class HTTP semantic mutation & parser/gateway differential matrix vs volatile-filtered baseline
    #[arg(long)]
    mutate_matrix: bool,
    /// Ordered stateful multi-step HTTP flow JSON file (or `-` for stdin) with `{{var}}` extraction & cross-step assertions
    #[arg(long)]
    flow: Option<String>,
    /// Sentinels to flag if leaked in auth-matrix candidate responses
    #[arg(long = "sentinel")]
    sentinels: Vec<String>,
    /// Multi-role differential matrix spec (`roles_matrix.json`, `-` stdin, or inline JSON)
    #[arg(long = "roles-matrix")]
    roles_matrix: Option<String>,
    /// Per-role template variables (`role:key=value`, e.g. `owner:id=101`), repeatable
    #[arg(long = "role-var")]
    role_vars: Vec<String>,
    /// Comma-separated HTTP methods for `--roles-matrix` (e.g. `GET,POST,DELETE`)
    #[arg(long)]
    methods: Option<String>,
    /// Expand cross-tenant `(actor, target_owner)` combinations when `--role-var` values differ
    #[arg(long = "cross-id")]
    cross_id: bool,
    /// JSON body key name(s) (comma-separated) whose values should be rewritten using target owner's `--role-var` in `--roles-matrix`
    #[arg(long = "vary-json-field")]
    vary_json_field: Option<String>,
    /// Ingest a `.har` or JSONL HTTP trace, cluster endpoints, infer nested JSON schemas, and replay/fuzz
    #[arg(long = "from-har")]
    from_har: Option<String>,
    /// With `--from-har`, run bounded nested-key, HPP, mass-assignment, and cross-principal differential probes
    #[arg(long = "fuzz-schema")]
    fuzz_schema: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct ListenArgs {
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
    Run(Box<RunArgs>),
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
    Smoke(Box<SmokeArgs>),
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
    Cdp(Box<CdpArgs>),
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
    Http(Box<HttpArgs>),
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
    Listen(Box<ListenArgs>),
    /// Deadline-bounded RFC 6455 generic WebSocket (`ws://`) send/recv & CSWSH cross-origin handshake auditor (zero hangs)
    Ws {
        /// Optional `ws://` or `wss://` URL (omit when using `--replay-har`)
        url: Option<String>,
        #[arg(long = "send")]
        send: Vec<String>,
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        #[arg(long, default_value_t = 1000)]
        wait_ms: u64,
        /// Probe cross-origin CSWSH acceptance across omitted/`https://evil.example`/`null`/`http://localhost` (or custom `--origin`)
        #[arg(long)]
        origin_matrix: bool,
        /// Optional custom Origin header(s) for `--origin-matrix` (repeatable)
        #[arg(long = "origin")]
        origins: Vec<String>,
        /// Replay recorded WebSocket URLs, headers, and frames from a `.har` or JSONL trace
        #[arg(long = "replay-har")]
        replay_har: Option<String>,
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
    /// Pure-Rust Windows OS inspector (named pipes + ACL, registry, SDDL ACL, services, token privileges)
    Win {
        /// Enumerate \\.\pipe\* named pipes (with SDDL when <=30 or filtered)
        #[arg(long)]
        pipes: bool,
        /// Query Windows registry key values and subkeys (e.g. HKLM\SYSTEM\...)
        #[arg(long)]
        reg: Option<String>,
        /// Inspect Windows file/directory or named-pipe DACL + SDDL + non-admin write flags
        #[arg(long)]
        acl: Option<String>,
        /// Enumerate Windows Win32 services (state, start type, binary path, SDDL when filtered)
        #[arg(long)]
        services: bool,
        /// Inspect current process token user, SID, elevation, integrity level, and privileges
        #[arg(long)]
        whoami: bool,
        /// Inspect PE Authenticode signature & Windows catalog trust (`subject`, `issuer`, `valid`, `sha256`)
        #[arg(long)]
        sig: Option<PathBuf>,
        /// Audit non-admin writable pipes/services/dirs (`--weak-acl` for OS sweep or `--weak-acl <PATH>`)
        #[arg(long = "weak-acl", num_args = 0..=1, default_missing_value = "")]
        weak_acl: Option<String>,
        /// Scan services for unquoted ImagePaths containing spaces & check intermediate directory ACLs
        #[arg(long)]
        unquoted: bool,
        /// Audit HKLM\SOFTWARE\Classes\CLSID COM LocalServer/InprocServer hijacks & AutoElevation
        #[arg(long)]
        com: bool,
        /// Enumerate live Windows RPC Endpoint Mapper bindings via rpcrt4.dll
        #[arg(long)]
        rpc: bool,
        /// Enumerate running Windows processes with native Win32 Integrity Level, session ID & elevation
        #[arg(long)]
        procs: bool,
        /// Combined single-shot Windows attack-surface sweep (`--weak-acl` + `--com` + `--rpc` + `--procs`)
        #[arg(long)]
        all: bool,
        /// Filter out standard Microsoft / Windows OS baseline pipes, System32 services, core COM DLLs & OS RPC bindings
        #[arg(long = "non-ms", alias = "exclude-microsoft")]
        non_ms: bool,
        /// Case-insensitive substring filter for pipes, registry values/subkeys, services, COM, or RPC
        #[arg(long)]
        filter: Option<String>,
        /// Maximum entries to return (1..=200)
        #[arg(long, default_value_t = 50)]
        max: usize,
        /// Emit structured JSON output
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
        SubCmd::Run(boxed) => {
            let RunArgs {
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
            } = *boxed;
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
        SubCmd::Smoke(boxed) => {
            let SmokeArgs {
                cwd,
                start,
                url,
                ready_path,
                timeout_ms,
                envs,
                spec,
                stdin,
                json,
            } = *boxed;
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
        SubCmd::Cdp(boxed) => {
            let CdpArgs {
                host,
                port,
                diff_ports,
                target_ids,
                list,
                target,
                eval,
                eval_stdin,
                audit,
                screenshot,
                stdin,
                watch_ms,
                export_role,
                role_name,
                origin,
                no_storage,
                redact,
                json,
            } = *boxed;
            if let Some(er_port_str) = export_role {
                let eff_port = if er_port_str.trim().is_empty() {
                    port
                } else {
                    match er_port_str.trim().parse::<u16>() {
                        Ok(p) if p > 0 => p,
                        _ => {
                            let msg =
                                format!("[probe cdp] invalid --export-role port `{er_port_str}`");
                            if json {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&serde_json::json!({
                                        "ok": false,
                                        "error": msg
                                    }))
                                    .unwrap_or_default()
                                );
                            } else {
                                eprintln!("{msg}");
                            }
                            return 2;
                        }
                    }
                };
                return cdp::run_cdp_export_role(
                    &host,
                    eff_port,
                    target.as_deref(),
                    &role_name,
                    origin.as_deref(),
                    !no_storage,
                    redact,
                    json,
                );
            }
            let mut eval_owned = eval;
            if eval_stdin {
                let mut js_buf = String::new();
                let _ = std::io::stdin().read_to_string(&mut js_buf);
                let trimmed = js_buf.trim();
                if trimmed.is_empty() {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": false,
                                "error": "--eval-stdin received empty stdin"
                            }))
                            .unwrap_or_default()
                        );
                    } else {
                        eprintln!("[probe cdp] --eval-stdin received empty stdin");
                    }
                    return 2;
                }
                eval_owned = Some(trimmed.to_string());
            }
            if let Some(dp) = diff_ports.as_deref().filter(|s| !s.trim().is_empty()) {
                let parts: Vec<u16> = dp
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .collect();
                if parts.len() != 2 {
                    let msg = "[probe cdp] --diff-ports requires two comma-separated ports, e.g. `9222,9223`";
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": false,
                                "error": msg
                            }))
                            .unwrap_or_default()
                        );
                    } else {
                        eprintln!("{msg}");
                    }
                    return 2;
                }
                let Some(expr) = eval_owned.as_deref().filter(|s| !s.trim().is_empty()) else {
                    let msg = "[probe cdp] --diff-ports requires `--eval <JS>` or `--eval-stdin`";
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": false,
                                "error": msg
                            }))
                            .unwrap_or_default()
                        );
                    } else {
                        eprintln!("{msg}");
                    }
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
            if stdin && !eval_stdin {
                let _ = std::io::stdin().read_to_string(&mut steps);
                if steps.trim().is_empty() {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": false,
                                "error": "--stdin received empty input (pass DSL steps, JSON {\"steps\": [...]}, or use --eval-stdin)"
                            }))
                            .unwrap_or_default()
                        );
                    } else {
                        eprintln!("[probe cdp] --stdin received empty input (use --eval-stdin for raw JS)");
                    }
                    return 2;
                }
            }
            cdp::run_cdp_attach(
                &host,
                port,
                list,
                target.as_deref(),
                eval_owned.as_deref(),
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
        SubCmd::Http(boxed) => {
            let HttpArgs {
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
                cdp_cookies,
                principal_cdps,
                cors_origin,
                select,
                audit_headers,
                race,
                mutate_matrix,
                flow,
                sentinels,
                roles_matrix,
                role_vars,
                methods,
                cross_id,
                vary_json_field,
                from_har,
                fuzz_schema,
                json,
            } = *boxed;
            let has_from_har = from_har.as_deref().is_some_and(|s| !s.trim().is_empty());
            let vary_fields_vec: Vec<String> = vary_json_field
                .as_deref()
                .map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|x| !x.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let has_roles_matrix = roles_matrix.is_some()
                || !role_vars.is_empty()
                || methods.is_some()
                || cross_id
                || !vary_fields_vec.is_empty();
            let has_flow = flow.as_deref().is_some_and(|s| !s.trim().is_empty());
            let has_vary_field = vary_field.as_deref().is_some_and(|s| !s.trim().is_empty());
            let mut active_http_modes: Vec<&str> = Vec::new();
            if has_from_har {
                active_http_modes.push("--from-har");
            }
            if has_roles_matrix {
                active_http_modes.push("--roles-matrix");
            }
            if has_flow {
                active_http_modes.push("--flow");
            }
            if mutate_matrix {
                active_http_modes.push("--mutate-matrix");
            }
            if race >= 2 {
                active_http_modes.push("--race");
            }
            if batch_stdin {
                active_http_modes.push("--batch-stdin");
            }
            if has_vary_field {
                active_http_modes.push("--vary-field");
            }
            if active_http_modes.len() > 1 {
                let msg = format!(
                    "[probe http] conflicting mutually-exclusive mode flags: {} (run one mode per invocation)",
                    active_http_modes.join(", ")
                );
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": msg
                        }))
                        .unwrap_or_default()
                    );
                } else {
                    eprintln!("{msg}");
                }
                return 2;
            }
            if let Some(har) = from_har.as_deref().filter(|s| !s.trim().is_empty()) {
                let mut principal_hdrs = Vec::new();
                for p in &principals {
                    if let Some((lhs, rhs)) = p.split_once('=') {
                        if !lhs.contains(':') && rhs.contains(':') {
                            principal_hdrs.push(rhs.trim().to_string());
                        } else {
                            principal_hdrs.push(p.trim().to_string());
                        }
                    } else if !p.trim().is_empty() {
                        principal_hdrs.push(p.trim().to_string());
                    }
                }
                return har_probe::run_http_from_har(har_probe::HarProbeConfig {
                    har_path: har,
                    fuzz_schema,
                    dry_run,
                    max_variants,
                    rate_ms,
                    principal_headers: &principal_hdrs,
                    sentinels: &sentinels,
                    timeout_sec: timeout,
                    insecure,
                    follow,
                    as_json: json,
                });
            }
            if has_roles_matrix {
                return http_probe::run_http_roles_matrix(
                    roles_matrix.as_deref(),
                    vary_request.as_deref(),
                    url.as_deref(),
                    &method,
                    methods.as_deref(),
                    &headers,
                    body.as_deref(),
                    &principals,
                    &principal_cdps,
                    &role_vars,
                    &vary_fields_vec,
                    cross_id,
                    rate_ms,
                    max_variants,
                    dry_run,
                    &sentinels,
                    timeout,
                    insecure,
                    follow,
                    json,
                );
            }
            if let Some(fl) = flow.as_deref().filter(|s| !s.trim().is_empty()) {
                return http_probe::run_http_flow(
                    fl, &headers, &sentinels, timeout, insecure, follow, json,
                );
            }
            if mutate_matrix {
                return http_probe::run_http_mutate_matrix(
                    vary_request.as_deref(),
                    url.as_deref(),
                    &method,
                    &headers,
                    body.as_deref(),
                    alt_value.as_deref(),
                    rate_ms,
                    if max_variants == 20 { 18 } else { max_variants },
                    dry_run,
                    cdp_cookies,
                    &sentinels,
                    timeout,
                    insecure,
                    follow,
                    json,
                );
            }
            if race >= 2 {
                return http_probe::run_http_race(
                    vary_request.as_deref(),
                    url.as_deref(),
                    &method,
                    &headers,
                    body.as_deref(),
                    race,
                    cdp_cookies,
                    select.as_deref(),
                    timeout,
                    insecure,
                    follow,
                    json,
                );
            }
            if !principals.is_empty() || !principal_cdps.is_empty() {
                return http_probe::run_http_auth_matrix(
                    vary_request.as_deref(),
                    url.as_deref(),
                    &method,
                    &headers,
                    body.as_deref(),
                    &principals,
                    &principal_cdps,
                    cors_origin.as_deref(),
                    select.as_deref(),
                    audit_headers,
                    &sentinels,
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
                    cdp_cookies,
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
                cdp_cookies,
                cors_origin.as_deref(),
                select.as_deref(),
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
        SubCmd::Listen(boxed) => {
            let ListenArgs {
                port,
                wait_ms,
                max_reqs,
                reply_status,
                reply_type,
                reply_body,
                run,
                json,
            } = *boxed;
            net_probe::run_listen_cli(
                port,
                wait_ms,
                max_reqs,
                reply_status,
                &reply_type,
                &reply_body,
                run.as_deref(),
                json,
            )
        }
        SubCmd::Ws {
            url,
            send,
            headers,
            wait_ms,
            origin_matrix,
            origins,
            replay_har,
            json,
        } => {
            if let Some(har) = replay_har.as_deref().filter(|s| !s.trim().is_empty()) {
                return har_probe::run_ws_replay_har(
                    har,
                    &send,
                    &origins,
                    origin_matrix,
                    wait_ms,
                    json,
                );
            }
            let Some(ws_url) = url.as_deref().filter(|s| !s.trim().is_empty()) else {
                let msg = "ap probe ws: pass <url> or --replay-har <file>";
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": msg
                        }))
                        .unwrap_or_default()
                    );
                } else {
                    eprintln!("{msg}");
                }
                return 2;
            };
            if origin_matrix || !origins.is_empty() {
                return net_probe::run_ws_origin_matrix(
                    ws_url, &send, &headers, &origins, wait_ms, json,
                );
            }
            net_probe::run_ws_cli(ws_url, &send, &headers, wait_ms, json)
        }
        SubCmd::Tls {
            addr,
            sni,
            timeout,
            json,
        } => net_probe::run_tls_cli(&addr, sni.as_deref(), timeout, json),
        SubCmd::Win {
            pipes,
            reg,
            acl,
            services,
            whoami,
            sig,
            weak_acl,
            unquoted,
            com,
            rpc,
            procs,
            all,
            non_ms,
            filter,
            max,
            json,
        } => win::run_win_cli_ex(
            pipes,
            reg.as_deref(),
            acl.as_deref(),
            services,
            whoami,
            sig.as_deref(),
            weak_acl.as_deref(),
            unquoted,
            com,
            rpc,
            procs,
            all,
            non_ms,
            filter.as_deref(),
            max,
            json,
        ),
    }
}
