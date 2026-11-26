use crate::cdp::CdpSession;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmokeStepResult {
    pub index: usize,
    pub action: String,
    pub status: u16,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmokeReport {
    pub ok: bool,
    pub base_url: String,
    pub elapsed_ms: f64,
    pub steps: Vec<SmokeStepResult>,
    pub server_errors: Vec<String>,
    pub stderr_tail: String,
}

pub(crate) fn pick_free_port() -> Result<u16, String> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind ephemeral port: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    Ok(port)
}

fn encode_uri_non_ascii(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 16);
    for ch in path.chars() {
        if ch.is_ascii() && ch != ' ' {
            out.push(ch);
        } else if ch == ' ' {
            out.push_str("%20");
        } else {
            let mut buf = [0u8; 4];
            for b in ch.encode_utf8(&mut buf).as_bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

fn decode_chunked(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        let Some(rel_end) = raw[i..].windows(2).position(|w| w == b"\r\n") else {
            out.extend_from_slice(&raw[i..]);
            break;
        };
        let size_str = String::from_utf8_lossy(&raw[i..i + rel_end]);
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let Ok(sz) = usize::from_str_radix(size_hex, 16) else {
            out.extend_from_slice(&raw[i..]);
            break;
        };
        i += rel_end + 2;
        if sz == 0 {
            break;
        }
        let end = (i + sz).min(raw.len());
        out.extend_from_slice(&raw[i..end]);
        i = (end + 2).min(raw.len());
    }
    out
}

pub(crate) fn http_request(
    host_port: &str,
    method: &str,
    raw_path: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    timeout_ms: u64,
) -> Result<(u16, String, String), String> {
    let addr = host_port
        .strip_prefix("http://")
        .unwrap_or(host_port)
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:80");
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    let to = Some(Duration::from_millis(timeout_ms.max(500)));
    let _ = stream.set_read_timeout(to);
    let _ = stream.set_write_timeout(to);

    let wire_path = if raw_path.starts_with('/') {
        encode_uri_non_ascii(raw_path)
    } else {
        encode_uri_non_ascii(&format!("/{raw_path}"))
    };
    let body_bytes = body.map(str::as_bytes).unwrap_or(&[]);
    let mut req = format!("{method} {wire_path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    let mut has_ct = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-type") {
            has_ct = true;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if body.is_some() {
        if !has_ct {
            req.push_str("Content-Type: application/json; charset=utf-8\r\n");
        }
        req.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .and_then(|_| stream.write_all(body_bytes))
        .map_err(|e| format!("write request: {e}"))?;

    let mut resp_bytes = Vec::new();
    let _ = stream.read_to_end(&mut resp_bytes);
    let Some(hdr_end) = resp_bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err("malformed HTTP response (missing header separator)".to_string());
    };
    let hdr_text = String::from_utf8_lossy(&resp_bytes[..hdr_end]).to_string();
    let status = hdr_text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let raw_body = &resp_bytes[hdr_end + 4..];
    let is_chunked = hdr_text.lines().any(|l| {
        l.to_ascii_lowercase().starts_with("transfer-encoding:")
            && l.to_ascii_lowercase().contains("chunked")
    });
    let decoded = if is_chunked {
        decode_chunked(raw_body)
    } else {
        raw_body.to_vec()
    };
    let body_text = String::from_utf8_lossy(&decoded).to_string();
    Ok((status, hdr_text, body_text))
}

pub(crate) fn find_headless_browser() -> Option<PathBuf> {
    let candidates = if cfg!(windows) {
        vec![
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ]
    } else {
        vec![
            "/usr/bin/google-chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/microsoft-edge",
        ]
    };
    for c in candidates {
        let p = PathBuf::from(c);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[cfg(windows)]
mod probe_win_job {
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use std::ptr;

    type Handle = *mut core::ffi::c_void;
    type Bool = i32;

    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    impl Default for JobObjectBasicLimitInformation {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(
            lp_job_attributes: *const core::ffi::c_void,
            lp_name: *const u16,
        ) -> Handle;
        fn SetInformationJobObject(
            h_job: Handle,
            job_object_info_class: i32,
            lp_job_object_info: *const core::ffi::c_void,
            cb_job_object_info_length: u32,
        ) -> Bool;
        fn AssignProcessToJobObject(h_job: Handle, h_process: Handle) -> Bool;
        fn CloseHandle(h_object: Handle) -> Bool;
    }

    pub(crate) struct ProbeJobGuard {
        handle: Handle,
    }

    impl ProbeJobGuard {
        pub(crate) fn attach(child: &Child) -> Option<Self> {
            unsafe {
                let job = CreateJobObjectW(ptr::null(), ptr::null());
                if job.is_null() {
                    return None;
                }
                let mut info = JobObjectExtendedLimitInformation::default();
                info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if SetInformationJobObject(
                    job,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    (&info as *const JobObjectExtendedLimitInformation).cast(),
                    core::mem::size_of::<JobObjectExtendedLimitInformation>() as u32,
                ) == 0
                {
                    let _ = CloseHandle(job);
                    return None;
                }
                if AssignProcessToJobObject(job, child.as_raw_handle() as Handle) == 0 {
                    let _ = CloseHandle(job);
                    return None;
                }
                Some(Self { handle: job })
            }
        }
    }

    impl Drop for ProbeJobGuard {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe {
                    let _ = CloseHandle(self.handle);
                }
            }
        }
    }
}

#[cfg(windows)]
pub(crate) use probe_win_job::ProbeJobGuard;

#[cfg(not(windows))]
pub(crate) struct ProbeJobGuard;

#[cfg(not(windows))]
impl ProbeJobGuard {
    pub(crate) fn attach(_child: &Child) -> Option<Self> {
        None
    }
}

pub(crate) fn run_cmd_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
    stdin_bytes: Option<&[u8]>,
) -> Result<std::process::Output, String> {
    if stdin_bytes.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;
    let mut job = ProbeJobGuard::attach(&child);
    if let Some(bytes) = stdin_bytes {
        if let Some(mut sin) = child.stdin.take() {
            let _ = sin.write_all(bytes);
        }
    }
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let out_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = stdout_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });
    let err_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = stderr_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                drop(job);
                let stdout = out_handle.join().unwrap_or_default();
                let stderr = err_handle.join().unwrap_or_default();
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    drop(job.take());
                    kill_process_tree(&mut child);
                    let _ = out_handle.join();
                    let _ = err_handle.join();
                    return Err(format!("command timed out after {}ms", timeout.as_millis()));
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                drop(job.take());
                kill_process_tree(&mut child);
                let _ = out_handle.join();
                let _ = err_handle.join();
                return Err(format!("wait failed: {e}"));
            }
        }
    }
}

fn dump_browser_dom(url: &str, budget_ms: u64) -> Result<(u16, String), String> {
    let Some(bin) = find_headless_browser() else {
        let (st, _, body) = http_request(
            url.split('/')
                .take(3)
                .collect::<Vec<_>>()
                .join("/")
                .as_str(),
            "GET",
            &format!("/{}", url.split('/').skip(3).collect::<Vec<_>>().join("/")),
            &[],
            None,
            5000,
        )?;
        return Ok((st, body));
    };
    let profile_dir = std::env::temp_dir().join(format!("ap_smoke_browser_{}", std::process::id()));
    let _ = fs::create_dir_all(&profile_dir);
    let mut cmd = Command::new(&bin);
    cmd.args([
        "--headless=new",
        "--disable-gpu",
        "--disable-extensions",
        "--log-level=3",
        "--no-first-run",
        &format!("--user-data-dir={}", profile_dir.display()),
        &format!("--virtual-time-budget={}", budget_ms.max(800)),
        "--dump-dom",
        url,
    ]);
    let timeout = Duration::from_millis((budget_ms.max(800) + 5000).clamp(4000, 20_000));
    let out = run_cmd_with_timeout(&mut cmd, timeout, None);
    let _ = fs::remove_dir_all(&profile_dir);
    match out {
        Ok(o) => {
            let dom = String::from_utf8_lossy(&o.stdout).to_string();
            if dom.trim().is_empty() {
                Err(format!(
                    "headless browser returned empty DOM: {}",
                    String::from_utf8_lossy(&o.stderr)
                ))
            } else {
                Ok((200, dom))
            }
        }
        Err(e) => Err(format!("failed to run headless browser: {e}")),
    }
}

pub(crate) fn spawn_detached_logged_server(
    start_cmd: &str,
    cwd: &Path,
    port: u16,
    extra_envs: &[(String, String)],
    stdout_file: &Path,
    stderr_file: &Path,
) -> Result<Child, String> {
    let out_f = File::create(stdout_file).map_err(|e| e.to_string())?;
    let err_f = File::create(stderr_file).map_err(|e| e.to_string())?;
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", start_cmd]);
        c
    } else {
        let mut c = Command::new("sh");
        c.args(["-c", start_cmd]);
        c
    };
    cmd.current_dir(cwd)
        .env("PORT", port.to_string())
        .env("HOST", "127.0.0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_f))
        .stderr(Stdio::from(err_f));
    for (k, v) in extra_envs {
        cmd.env(k, v);
    }
    cmd.spawn().map_err(|e| format!("spawn `{start_cmd}`: {e}"))
}

pub(crate) fn kill_process_tree(child: &mut Child) {
    let pid_s = child.id().to_string();
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid_s, "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("pkill")
            .args(["-KILL", "-P", &pid_s])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Debug, Clone)]
enum ExpectRule {
    Status(String),
    Contains(String),
    NotContains(String),
    JsonCmp {
        path: String,
        op: String,
        rhs: String,
    },
}

#[derive(Debug, Clone)]
struct SmokeStepSpec {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    expects: Vec<ExpectRule>,
}

fn parse_smoke_spec(spec_text: &str) -> Vec<SmokeStepSpec> {
    let mut steps: Vec<SmokeStepSpec> = Vec::new();
    let lines: Vec<&str> = spec_text.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        i += 1;
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let kw = parts.next().unwrap_or("").to_uppercase();
        let rest = parts.next().unwrap_or("").trim();

        if matches!(
            kw.as_str(),
            "GET"
                | "POST"
                | "PUT"
                | "PATCH"
                | "DELETE"
                | "BROWSER"
                | "OPEN"
                | "CLICK"
                | "FILL"
                | "TYPE"
                | "SELECT"
                | "EVAL"
                | "WAIT_MS"
                | "VIEWPORT"
                | "SCREENSHOT"
                | "AUDIT_UI"
        ) && (!rest.is_empty() || kw == "AUDIT_UI")
        {
            steps.push(SmokeStepSpec {
                method: kw,
                path: rest.to_string(),
                headers: Vec::new(),
                body: None,
                expects: Vec::new(),
            });
            continue;
        }
        let Some(cur) = steps.last_mut() else {
            continue;
        };
        if kw == "HEADER" {
            if let Some((k, v)) = rest.split_once(':') {
                cur.headers
                    .push((k.trim().to_string(), v.trim().to_string()));
            }
        } else if kw == "BODY" {
            if rest == "<<<" {
                let mut buf = Vec::new();
                while i < lines.len() && lines[i].trim() != ">>>" {
                    buf.push(lines[i]);
                    i += 1;
                }
                if i < lines.len() {
                    i += 1;
                }
                cur.body = Some(buf.join("\n"));
            } else {
                cur.body = Some(rest.to_string());
            }
        } else if kw == "EXPECT" {
            let mut ep = rest.splitn(2, char::is_whitespace);
            let ek = ep.next().unwrap_or("").to_uppercase();
            let ev = ep.next().unwrap_or("").trim();
            match ek.as_str() {
                "STATUS" => cur.expects.push(ExpectRule::Status(ev.to_string())),
                "CONTAINS" => cur.expects.push(ExpectRule::Contains(ev.to_string())),
                "NOT_CONTAINS" => cur.expects.push(ExpectRule::NotContains(ev.to_string())),
                "JSON" => {
                    for op in ["==", "!=", ">=", "<=", ">", "<"] {
                        if let Some((lhs, rhs)) = ev.split_once(op) {
                            cur.expects.push(ExpectRule::JsonCmp {
                                path: lhs.trim().to_string(),
                                op: op.to_string(),
                                rhs: rhs.trim().trim_matches('"').trim_matches('\'').to_string(),
                            });
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if steps.is_empty() {
        steps.push(SmokeStepSpec {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: None,
            expects: vec![ExpectRule::Status("2xx".to_string())],
        });
    }
    steps
}

fn eval_json_path(root: &Value, dot_path: &str) -> Option<String> {
    let mut cur = root;
    let segs: Vec<&str> = dot_path.split('.').filter(|s| !s.is_empty()).collect();
    for (idx, seg) in segs.iter().enumerate() {
        if *seg == "length" && idx + 1 == segs.len() {
            return match cur {
                Value::Array(a) => Some(a.len().to_string()),
                Value::String(s) => Some(s.chars().count().to_string()),
                Value::Object(m) => Some(m.len().to_string()),
                _ => None,
            };
        }
        if let Ok(arr_i) = seg.parse::<usize>() {
            cur = cur.get(arr_i)?;
        } else {
            cur = cur.get(*seg)?;
        }
    }
    match cur {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some("null".to_string()),
        other => Some(other.to_string()),
    }
}

fn check_cmp(actual: &str, op: &str, expected: &str) -> bool {
    if let (Ok(a), Ok(b)) = (actual.parse::<f64>(), expected.parse::<f64>()) {
        return match op {
            "==" => (a - b).abs() < 1e-9,
            "!=" => (a - b).abs() >= 1e-9,
            ">=" => a >= b,
            "<=" => a <= b,
            ">" => a > b,
            "<" => a < b,
            _ => false,
        };
    }
    match op {
        "==" => actual == expected,
        "!=" => actual != expected,
        _ => false,
    }
}

pub fn auto_detect_start_cmd(cwd: &Path) -> Option<String> {
    let pkg = cwd.join("package.json");
    if pkg.is_file() {
        if let Ok(txt) = fs::read_to_string(&pkg) {
            if let Ok(v) = serde_json::from_str::<Value>(&txt) {
                if let Some(s) = v
                    .get("scripts")
                    .and_then(|x| x.get("start"))
                    .and_then(Value::as_str)
                {
                    return Some(s.to_string());
                }
                if v.get("scripts").and_then(|x| x.get("dev")).is_some() {
                    return Some("npm run dev".to_string());
                }
            }
        }
    }
    if cwd.join("src/server.ts").is_file() {
        return Some("node --experimental-strip-types src/server.ts".to_string());
    }
    if cwd.join("server.py").is_file() {
        return Some("python server.py".to_string());
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub fn run_smoke(
    cwd: &Path,
    start_opt: Option<&str>,
    url_opt: Option<&str>,
    ready_path: &str,
    timeout_ms: u64,
    extra_envs: &[(String, String)],
    spec_text: &str,
    as_json: bool,
) -> i32 {
    let t0 = Instant::now();
    let mut child_opt: Option<Child> = None;
    let mut _child_job: Option<ProbeJobGuard> = None;
    let pid_tag = std::process::id();
    let stdout_f = std::env::temp_dir().join(format!("ap_smoke_{pid_tag}.out.log"));
    let stderr_f = std::env::temp_dir().join(format!("ap_smoke_{pid_tag}.err.log"));

    let base_url = if let Some(u) = url_opt.filter(|s| !s.trim().is_empty()) {
        u.trim_end_matches('/').to_string()
    } else {
        let start_cmd = match start_opt
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .or_else(|| auto_detect_start_cmd(cwd))
        {
            Some(c) => c,
            None => {
                let msg =
                    "[probe smoke] Provide --start \"<cmd>\" or --url http://127.0.0.1:<port>";
                if as_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({ "ok": false, "error": msg })
                        )
                        .unwrap_or_default()
                    );
                } else {
                    eprintln!("{msg}");
                }
                return 2;
            }
        };
        let port = match pick_free_port() {
            Ok(p) => p,
            Err(e) => {
                let msg = format!("[probe smoke] {e}");
                if as_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({ "ok": false, "error": msg })
                        )
                        .unwrap_or_default()
                    );
                } else {
                    eprintln!("{msg}");
                }
                return 2;
            }
        };
        match spawn_detached_logged_server(&start_cmd, cwd, port, extra_envs, &stdout_f, &stderr_f)
        {
            Ok(ch) => {
                _child_job = ProbeJobGuard::attach(&ch);
                child_opt = Some(ch);
            }
            Err(e) => {
                let msg = format!("[probe smoke] {e}");
                if as_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({ "ok": false, "error": msg })
                        )
                        .unwrap_or_default()
                    );
                } else {
                    eprintln!("{msg}");
                }
                return 1;
            }
        }
        format!("http://127.0.0.1:{port}")
    };

    // Poll readiness
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1000));
    let mut ready = false;
    while Instant::now() < deadline {
        if let Some(ch) = child_opt.as_mut() {
            if let Ok(Some(_)) = ch.try_wait() {
                break;
            }
        }
        if let Ok((st, _, _)) = http_request(&base_url, "GET", ready_path, &[], None, 800) {
            if st > 0 && st < 500 {
                ready = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    let mut step_results = Vec::new();
    let mut cdp_js_errors: Vec<String> = Vec::new();
    let specs = parse_smoke_spec(spec_text);
    if !ready {
        step_results.push(SmokeStepResult {
            index: 1,
            action: format!("READY {ready_path}"),
            status: 0,
            ok: false,
            detail: format!("Server at {base_url} did not become ready within {timeout_ms}ms"),
        });
    } else {
        let mut cdp_opt: Option<CdpSession> = None;
        fn ensure_cdp(slot: &mut Option<CdpSession>) -> Result<&mut CdpSession, String> {
            if slot.is_none() {
                let bin = find_headless_browser().ok_or_else(|| {
                    "No headless Edge/Chrome/Chromium binary found for interactive CDP".to_string()
                })?;
                *slot = Some(CdpSession::launch(&bin)?);
            }
            Ok(slot.as_mut().unwrap())
        }

        for (idx, sp) in specs.iter().enumerate() {
            let step_no = idx + 1;
            let req_res: Result<(u16, String, String), String> = match sp.method.as_str() {
                "OPEN" | "BROWSER" => {
                    let full_u =
                        if sp.path.starts_with("http://") || sp.path.starts_with("https://") {
                            sp.path.clone()
                        } else if sp.path.starts_with('/') {
                            format!("{base_url}{}", encode_uri_non_ascii(&sp.path))
                        } else {
                            format!("{base_url}/{}", encode_uri_non_ascii(&sp.path))
                        };
                    match ensure_cdp(&mut cdp_opt) {
                        Ok(cdp) => cdp.navigate(&full_u).map(|dom| (200, String::new(), dom)),
                        Err(_) => dump_browser_dom(&full_u, 2200)
                            .map(|(st, dom)| (st, String::new(), dom)),
                    }
                }
                "CLICK" => ensure_cdp(&mut cdp_opt)
                    .and_then(|cdp| cdp.click(&sp.path).map(|dom| (200, String::new(), dom))),
                "FILL" | "TYPE" => {
                    let mut p = sp.path.splitn(2, char::is_whitespace);
                    let sel = p.next().unwrap_or("");
                    let val = p.next().unwrap_or("");
                    ensure_cdp(&mut cdp_opt)
                        .and_then(|cdp| cdp.fill(sel, val).map(|dom| (200, String::new(), dom)))
                }
                "SELECT" => {
                    let mut p = sp.path.splitn(2, char::is_whitespace);
                    let sel = p.next().unwrap_or("");
                    let val = p.next().unwrap_or("");
                    ensure_cdp(&mut cdp_opt).and_then(|cdp| {
                        cdp.select_option(sel, val)
                            .map(|dom| (200, String::new(), dom))
                    })
                }
                "EVAL" => ensure_cdp(&mut cdp_opt)
                    .and_then(|cdp| cdp.eval_js(&sp.path).map(|out| (200, String::new(), out))),
                "WAIT_MS" => {
                    let ms = sp.path.parse::<u64>().unwrap_or(200).min(5000);
                    thread::sleep(Duration::from_millis(ms));
                    ensure_cdp(&mut cdp_opt)
                        .and_then(|cdp| cdp.dom_snapshot().map(|dom| (200, String::new(), dom)))
                }
                "VIEWPORT" => {
                    let (w, h) = sp
                        .path
                        .split_once('x')
                        .or_else(|| sp.path.split_once('X'))
                        .and_then(|(a, b)| {
                            Some((a.trim().parse::<u32>().ok()?, b.trim().parse::<u32>().ok()?))
                        })
                        .unwrap_or((1280, 800));
                    ensure_cdp(&mut cdp_opt).and_then(|cdp| {
                        cdp.set_viewport(w, h, w <= 500)
                            .map(|_| (200, String::new(), format!("viewport={w}x{h}")))
                    })
                }
                "SCREENSHOT" => {
                    let out_p = cwd.join(sp.path.trim());
                    ensure_cdp(&mut cdp_opt).and_then(|cdp| {
                        cdp.capture_screenshot(&out_p)
                            .map(|n| (200, String::new(), format!("screenshot={n}B")))
                    })
                }
                "AUDIT_UI" => {
                    let (w, h) = sp
                        .path
                        .split_once('x')
                        .or_else(|| sp.path.split_once('X'))
                        .and_then(|(a, b)| {
                            Some((a.trim().parse::<u32>().ok()?, b.trim().parse::<u32>().ok()?))
                        })
                        .unwrap_or((1280, 800));
                    ensure_cdp(&mut cdp_opt).and_then(|cdp| {
                        let rep = cdp.audit_layout(w, h)?;
                        let issues = rep
                            .get("issues")
                            .and_then(Value::as_array)
                            .map(|a| a.len())
                            .unwrap_or(0);
                        if issues > 0 {
                            Err(format!("UI layout issues at {w}x{h}: {}", rep["issues"]))
                        } else {
                            Ok((200, String::new(), rep.to_string()))
                        }
                    })
                }
                _ => http_request(
                    &base_url,
                    &sp.method,
                    &sp.path,
                    &sp.headers,
                    sp.body.as_deref(),
                    5000,
                ),
            };

            match req_res {
                Err(e) => step_results.push(SmokeStepResult {
                    index: step_no,
                    action: format!("{} {}", sp.method, sp.path),
                    status: 0,
                    ok: false,
                    detail: e,
                }),
                Ok((status, _, body)) => {
                    let mut failures = Vec::new();
                    let expects = if sp.expects.is_empty() {
                        vec![ExpectRule::Status("2xx".to_string())]
                    } else {
                        sp.expects.clone()
                    };
                    let parsed_json: Option<Value> = serde_json::from_str(&body).ok();
                    for ex in expects {
                        match ex {
                            ExpectRule::Status(want) => {
                                let ok = if want.eq_ignore_ascii_case("2xx") {
                                    (200..300).contains(&status)
                                } else {
                                    want.parse::<u16>().map(|w| w == status).unwrap_or(false)
                                };
                                if !ok {
                                    failures.push(format!("status={status} (expected {want})"));
                                }
                            }
                            ExpectRule::Contains(sub) => {
                                if !body.contains(&sub) {
                                    failures.push(format!("missing `{sub}` in response"));
                                }
                            }
                            ExpectRule::NotContains(sub) => {
                                if body.contains(&sub) {
                                    failures.push(format!("unexpected `{sub}` found in response"));
                                }
                            }
                            ExpectRule::JsonCmp { path, op, rhs } => match &parsed_json {
                                Some(jv) => match eval_json_path(jv, &path) {
                                    Some(actual) => {
                                        if !check_cmp(&actual, &op, &rhs) {
                                            failures.push(format!(
                                                "json `{path}`={actual} (expected {op} {rhs})"
                                            ));
                                        }
                                    }
                                    None => failures.push(format!("json path `{path}` not found")),
                                },
                                None => failures.push("response is not valid JSON".to_string()),
                            },
                        }
                    }
                    let ok = failures.is_empty();
                    let detail = if ok {
                        "PASS".to_string()
                    } else {
                        let snippet: String = body.chars().take(120).collect();
                        format!(
                            "{} | body: {}",
                            failures.join("; "),
                            snippet.replace('\n', " ")
                        )
                    };
                    step_results.push(SmokeStepResult {
                        index: step_no,
                        action: format!("{} {}", sp.method, sp.path),
                        status,
                        ok,
                        detail,
                    });
                }
            }
        }
        if let Some(cdp) = cdp_opt.take() {
            cdp_js_errors = cdp.js_errors.clone();
            cdp_js_errors.extend(cdp.network_errors.clone());
            drop(cdp);
        }
    }

    if let Some(mut ch) = child_opt {
        kill_process_tree(&mut ch);
    }

    let stderr_raw = fs::read_to_string(&stderr_f).unwrap_or_default();
    let _ = fs::remove_file(&stdout_f);
    let _ = fs::remove_file(&stderr_f);

    let mut server_errors = cdp_js_errors;
    for ln in stderr_raw.lines() {
        let low = ln.to_ascii_lowercase();
        if low.contains("[server error]")
            || low.contains("unhandledpromiserejection")
            || low.contains("typeerror:")
            || low.contains("referenceerror:")
            || low.contains("traceback (most recent")
            || low.contains("panicked at")
        {
            server_errors.push(ln.trim().to_string());
        }
    }
    let err_lines: Vec<&str> = stderr_raw.lines().collect();
    let tail_start = err_lines.len().saturating_sub(10);
    let stderr_tail = err_lines[tail_start..].join("\n");

    let all_ok = ready && step_results.iter().all(|s| s.ok) && server_errors.is_empty();
    let report = SmokeReport {
        ok: all_ok,
        base_url,
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
        steps: step_results,
        server_errors,
        stderr_tail,
    };

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        let badge = if report.ok { "PASS" } else { "FAIL" };
        println!(
            "[probe smoke: {badge}] {} ({} step(s) in {:.1}ms, process tree cleaned)",
            report.base_url,
            report.steps.len(),
            report.elapsed_ms
        );
        for st in &report.steps {
            let tag = if st.ok { "OK" } else { "FAIL" };
            println!(
                "  [{tag}] #{0} {1} (HTTP {2}) -> {3}",
                st.index, st.action, st.status, st.detail
            );
        }
        if !report.server_errors.is_empty() {
            println!("  [SERVER STDERR ERRORS]:");
            for se in &report.server_errors {
                println!("    - {se}");
            }
        } else if !report.ok && !report.stderr_tail.trim().is_empty() {
            println!("  [SERVER STDERR TAIL]:\n{}", report.stderr_tail);
        }
    }
    if report.ok {
        0
    } else {
        1
    }
}
