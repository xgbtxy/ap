use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdpTarget {
    pub id: String,
    pub target_type: String,
    pub title: String,
    pub url: String,
    pub ws_url: String,
}

pub struct CdpSession {
    child: Option<Child>,
    _job: Option<crate::smoke::ProbeJobGuard>,
    profile_dir: Option<PathBuf>,
    stream: TcpStream,
    next_id: u64,
    pub js_errors: Vec<String>,
    pub network_errors: Vec<String>,
    pub console_logs: Vec<String>,
    pub network_events: Vec<String>,
}

fn free_port() -> Result<u16, String> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let p = l.local_addr().map_err(|e| e.to_string())?.port();
    drop(l);
    Ok(p)
}

fn extract_origin_prefix(url: &str) -> String {
    if let Some(idx) = url.find("://") {
        let rest = &url[idx + 3..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        return url[..idx + 3 + end].to_string();
    }
    String::new()
}

fn read_exact_bytes<R: Read>(stream: &mut R, buf: &mut [u8]) -> Result<(), String> {
    stream.read_exact(buf).map_err(|e| format!("ws read: {e}"))
}

fn ws_write_text(stream: &mut TcpStream, text: &str) -> Result<(), String> {
    let payload = text.as_bytes();
    let len = payload.len();
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut frame = Vec::with_capacity(len + 14);
    frame.push(0x81); // FIN + text frame
    if len <= 125 {
        frame.push(0x80 | (len as u8));
    } else if len <= 65535 {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i & 3]);
    }
    stream
        .write_all(&frame)
        .map_err(|e| format!("ws write: {e}"))
}

const MAX_CDP_WS_FRAME_BYTES: usize = 32 * 1024 * 1024;

fn ws_read_message<S: Read + Write>(stream: &mut S) -> Result<String, String> {
    let mut msg_bytes = Vec::new();
    loop {
        let mut hdr = [0u8; 2];
        read_exact_bytes(stream, &mut hdr)?;
        let fin = (hdr[0] & 0x80) != 0;
        let opcode = hdr[0] & 0x0F;
        let masked = (hdr[1] & 0x80) != 0;
        let mut len = (hdr[1] & 0x7F) as usize;
        if len == 126 {
            let mut b = [0u8; 2];
            read_exact_bytes(stream, &mut b)?;
            len = u16::from_be_bytes(b) as usize;
        } else if len == 127 {
            let mut b = [0u8; 8];
            read_exact_bytes(stream, &mut b)?;
            let raw_len = u64::from_be_bytes(b);
            if raw_len > MAX_CDP_WS_FRAME_BYTES as u64 {
                return Err(format!("CDP websocket frame too large ({raw_len} bytes)"));
            }
            len = raw_len as usize;
        }
        if msg_bytes.len().saturating_add(len) > MAX_CDP_WS_FRAME_BYTES {
            return Err("CDP websocket message exceeded 32 MiB cap".to_string());
        }
        let mut mask = [0u8; 4];
        if masked {
            read_exact_bytes(stream, &mut mask)?;
        }
        let mut data = vec![0u8; len];
        if len > 0 {
            read_exact_bytes(stream, &mut data)?;
        }
        if masked {
            for (i, b) in data.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
        }
        match opcode {
            8 => return Err("CDP websocket closed".to_string()),
            9 => {
                let _ = stream.write_all(&[0x8A, 0x80, 0, 0, 0, 0]);
                continue;
            }
            10 => continue,
            _ => {
                msg_bytes.extend_from_slice(&data);
                if fin {
                    return Ok(String::from_utf8_lossy(&msg_bytes).to_string());
                }
            }
        }
    }
}

fn http_get_json_host(host: &str, port: u16, path: &str) -> Result<Value, String> {
    let mut s = TcpStream::connect((host, port)).map_err(|e| e.to_string())?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(1500)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(1500)));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err("no http body".to_string());
    };
    serde_json::from_slice(&buf[pos + 4..]).map_err(|e| e.to_string())
}

fn http_get_json(port: u16, path: &str) -> Result<Value, String> {
    http_get_json_host("127.0.0.1", port, path)
}

fn open_cdp_websocket(ws_url: &str) -> Result<TcpStream, String> {
    let after_scheme = ws_url.strip_prefix("ws://").unwrap_or(ws_url);
    let (addr, ws_path) = after_scheme
        .split_once('/')
        .map(|(a, p)| (a, format!("/{p}")))
        .unwrap_or((after_scheme, "/".to_string()));
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect CDP ws: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(8000)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(8000)));

    let hs = format!(
        "GET {ws_path} HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(hs.as_bytes()).map_err(|e| e.to_string())?;
    let mut resp = Vec::with_capacity(256);
    let mut b1 = [0u8; 1];
    while !resp.ends_with(b"\r\n\r\n") {
        read_exact_bytes(&mut stream, &mut b1)?;
        resp.push(b1[0]);
        if resp.len() > 8192 {
            return Err("CDP websocket handshake header overflow".to_string());
        }
    }
    if !String::from_utf8_lossy(&resp).contains("101") {
        return Err("CDP websocket upgrade rejected".to_string());
    }
    Ok(stream)
}

impl CdpSession {
    pub fn launch(browser_bin: &PathBuf) -> Result<Self, String> {
        let port = free_port()?;
        let pid = std::process::id();
        let profile_dir = std::env::temp_dir().join(format!("ap_cdp_{pid}_{port}"));
        let _ = fs::create_dir_all(&profile_dir);
        let out_log = profile_dir.join("browser.out.log");
        let err_log = profile_dir.join("browser.err.log");
        let out_f = File::create(&out_log).map_err(|e| e.to_string())?;
        let err_f = File::create(&err_log).map_err(|e| e.to_string())?;

        let mut child = Command::new(browser_bin)
            .args([
                "--headless=new",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--disable-setuid-sandbox",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--metrics-recording-only",
                "--mute-audio",
                "--no-sandbox",
                "--proxy-bypass-list=<-loopback>",
                "--log-level=3",
                "--no-first-run",
                "--no-default-browser-check",
                "--remote-debugging-address=127.0.0.1",
                &format!("--remote-debugging-port={port}"),
                &format!("--user-data-dir={}", profile_dir.display()),
                "about:blank",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(out_f))
            .stderr(Stdio::from(err_f))
            .spawn()
            .map_err(|e| format!("spawn headless browser: {e}"))?;
        let job = crate::smoke::ProbeJobGuard::attach(&child);

        let deadline = Instant::now() + Duration::from_millis(15000);
        let mut ws_url = String::new();
        let mut exited_early: Option<String> = None;
        while Instant::now() < deadline {
            if let Ok(Some(st)) = child.try_wait() {
                exited_early = Some(format!("browser exited early ({st})"));
                break;
            }
            if let Ok(Value::Array(items)) = http_get_json(port, "/json/list") {
                for it in items {
                    if it.get("type").and_then(Value::as_str) == Some("page") {
                        if let Some(u) = it.get("webSocketDebuggerUrl").and_then(Value::as_str) {
                            ws_url = u.to_string();
                            break;
                        }
                    }
                }
                if !ws_url.is_empty() {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(60));
        }

        if ws_url.is_empty() {
            let err_tail = fs::read_to_string(&err_log)
                .unwrap_or_default()
                .chars()
                .take(400)
                .collect::<String>();
            kill_browser(&mut child, &profile_dir);
            let reason = exited_early
                .unwrap_or_else(|| "Timed out waiting for headless browser CDP /json/list".into());
            return Err(format!("{reason}; stderr={}", err_tail.trim()));
        }

        let stream = match open_cdp_websocket(&ws_url) {
            Ok(s) => s,
            Err(e) => {
                kill_browser(&mut child, &profile_dir);
                return Err(e);
            }
        };

        let mut sess = Self {
            child: Some(child),
            _job: job,
            profile_dir: Some(profile_dir),
            stream,
            next_id: 1,
            js_errors: Vec::new(),
            network_errors: Vec::new(),
            console_logs: Vec::new(),
            network_events: Vec::new(),
        };
        let _ = sess.call("Page.enable", json!({}));
        let _ = sess.call("Runtime.enable", json!({}));
        let _ = sess.call("Log.enable", json!({}));
        let _ = sess.call("Network.enable", json!({}));
        Ok(sess)
    }

    /// Discover all live debuggable targets on an already-running Chrome/Edge/Electron CDP port.
    pub fn list_targets(host: &str, port: u16) -> Result<Vec<CdpTarget>, String> {
        let arr = http_get_json_host(host, port, "/json/list")
            .or_else(|_| http_get_json_host(host, port, "/json"))?;
        let Some(items) = arr.as_array() else {
            return Err("CDP /json/list did not return a JSON array".to_string());
        };
        let mut out = Vec::new();
        for it in items {
            let ws_url = it
                .get("webSocketDebuggerUrl")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if ws_url.is_empty() {
                continue;
            }
            out.push(CdpTarget {
                id: it
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                target_type: it
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                title: it
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                url: it
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                ws_url,
            });
        }
        Ok(out)
    }

    /// Attach to an already-running Chrome/Edge/Electron target WebSocket WITHOUT taking process ownership.
    pub fn attach(ws_url: &str) -> Result<Self, String> {
        let stream = open_cdp_websocket(ws_url)?;
        let mut sess = Self {
            child: None,
            _job: None,
            profile_dir: None,
            stream,
            next_id: 1,
            js_errors: Vec::new(),
            network_errors: Vec::new(),
            console_logs: Vec::new(),
            network_events: Vec::new(),
        };
        let _ = sess.call("Runtime.enable", json!({}));
        let _ = sess.call("Log.enable", json!({}));
        let _ = sess.call("Network.enable", json!({}));
        Ok(sess)
    }

    /// Fetch live cookies matching `url` in-memory from a local loopback (`127.0.0.1`/`localhost`)
    /// browser DevTools port without opening any new tabs or writing cookies to disk.
    pub fn fetch_cookies_for_url(
        host: &str,
        port: u16,
        url: &str,
    ) -> Result<Vec<(String, String)>, String> {
        let host_low = host.trim().to_ascii_lowercase();
        if !matches!(
            host_low.as_str(),
            "127.0.0.1" | "localhost" | "::1" | "[::1]"
        ) {
            return Err(format!(
                "refusing CDP cookie reuse from non-loopback host `{host}`"
            ));
        }
        let targets = Self::list_targets(host, port)?;
        let pages: Vec<&CdpTarget> = targets
            .iter()
            .filter(|t| t.target_type == "page" && !t.ws_url.is_empty())
            .collect();
        if pages.is_empty() {
            return Err(format!(
                "no attachable page target found on CDP {host}:{port}"
            ));
        }
        let url_origin = extract_origin_prefix(url);
        let chosen = pages
            .iter()
            .copied()
            .find(|t| !url_origin.is_empty() && t.url.starts_with(&url_origin))
            .unwrap_or(pages[0]);
        let mut sess = Self::attach(&chosen.ws_url)?;
        let res = sess.call("Network.getCookies", json!({ "urls": [url] }))?;
        let mut out = Vec::new();
        if let Some(arr) = res.get("cookies").and_then(Value::as_array) {
            for c in arr {
                let name = c.get("name").and_then(Value::as_str).unwrap_or("").trim();
                let val = c.get("value").and_then(Value::as_str).unwrap_or("");
                if !name.is_empty()
                    && !name.contains(['\r', '\n', ';', '='])
                    && !val.contains(['\r', '\n'])
                {
                    out.push((name.to_string(), val.to_string()));
                }
            }
        }
        Ok(out)
    }

    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({ "id": id, "method": method, "params": params }).to_string();
        ws_write_text(&mut self.stream, &msg)?;
        loop {
            let raw = ws_read_message(&mut self.stream)?;
            let Ok(v) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            if let Some(ev) = v.get("method").and_then(Value::as_str) {
                self.record_event(ev, v.get("params").unwrap_or(&Value::Null));
                continue;
            }
            if v.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(err) = v.get("error") {
                    return Err(format!("CDP {method} error: {err}"));
                }
                return Ok(v.get("result").cloned().unwrap_or(Value::Null));
            }
        }
    }

    /// Drain incoming CDP events (console logs, network responses, JS exceptions) for a bounded window without hanging.
    pub fn watch_events(&mut self, duration_ms: u64) {
        let bounded = duration_ms.min(15_000);
        if bounded == 0 {
            return;
        }
        let deadline = Instant::now() + Duration::from_millis(bounded);
        let _ = self
            .stream
            .set_read_timeout(Some(Duration::from_millis(60)));
        while Instant::now() < deadline {
            let mut probe = [0u8; 1];
            match self.stream.peek(&mut probe) {
                Ok(0) => break,
                Ok(_) => {
                    let _ = self
                        .stream
                        .set_read_timeout(Some(Duration::from_millis(2000)));
                    let frame = ws_read_message(&mut self.stream);
                    let _ = self
                        .stream
                        .set_read_timeout(Some(Duration::from_millis(60)));
                    match frame {
                        Ok(raw) => {
                            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                                if let Some(ev) = v.get("method").and_then(Value::as_str) {
                                    self.record_event(ev, v.get("params").unwrap_or(&Value::Null));
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
        let _ = self
            .stream
            .set_read_timeout(Some(Duration::from_millis(8000)));
    }

    fn record_event(&mut self, ev: &str, params: &Value) {
        if ev == "Runtime.exceptionThrown" {
            let desc = params
                .pointer("/exceptionDetails/exception/description")
                .or_else(|| params.pointer("/exceptionDetails/text"))
                .and_then(Value::as_str)
                .unwrap_or("Uncaught JS exception");
            self.js_errors.push(format!(
                "[pageerror] {}",
                desc.lines().next().unwrap_or(desc)
            ));
        } else if ev == "Runtime.consoleAPICalled" {
            let kind = params.get("type").and_then(Value::as_str).unwrap_or("log");
            if let Some(args) = params.get("args").and_then(Value::as_array) {
                let parts: Vec<String> = args
                    .iter()
                    .filter_map(|a| a.get("value").or_else(|| a.get("description")))
                    .map(|x| x.to_string().trim_matches('"').to_string())
                    .collect();
                if !parts.is_empty() {
                    let msg = parts.join(" ");
                    if self.console_logs.len() < 100 {
                        self.console_logs.push(format!("[console.{kind}] {msg}"));
                    }
                    if kind == "error" {
                        self.js_errors.push(format!("[console.error] {msg}"));
                    }
                }
            }
        } else if ev == "Network.responseReceived" {
            let status = params
                .pointer("/response/status")
                .and_then(Value::as_u64)
                .unwrap_or(200);
            let url = params
                .pointer("/response/url")
                .and_then(Value::as_str)
                .unwrap_or("");
            let res_type = params
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("Other");
            if !url.ends_with("/favicon.ico") && !url.starts_with("data:") {
                if self.network_events.len() < 100 {
                    self.network_events
                        .push(format!("[{status} {res_type}] {url}"));
                }
                if status >= 400 {
                    self.network_errors
                        .push(format!("[network {status}] {url}"));
                }
            }
        } else if ev == "Network.loadingFailed" {
            let err_txt = params
                .get("errorText")
                .and_then(Value::as_str)
                .unwrap_or("load failed");
            let canceled = params
                .get("canceled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !canceled && !err_txt.contains("ERR_ABORTED") {
                self.network_errors
                    .push(format!("[network failed] {err_txt}"));
            }
        }
    }
}

fn kill_browser(child: &mut Child, profile_dir: &PathBuf) {
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
    let _ = fs::remove_dir_all(profile_dir);
}

impl Drop for CdpSession {
    fn drop(&mut self) {
        let _ = self.stream.write_all(&[0x88, 0x80, 0, 0, 0, 0]);
        if let (Some(mut ch), Some(pd)) = (self.child.take(), self.profile_dir.take()) {
            kill_browser(&mut ch, &pd);
        }
    }
}

impl CdpSession {
    pub fn eval_js(&mut self, expr: &str) -> Result<String, String> {
        let wrapped = format!(
            "(async () => {{ const __r = await ({expr}); return typeof __r === 'string' ? __r : JSON.stringify(__r ?? ''); }})()"
        );
        let mut res = self.call(
            "Runtime.evaluate",
            json!({
                "expression": wrapped,
                "awaitPromise": true,
                "returnByValue": true
            }),
        )?;
        // Auto-fallback for multi-statement JS snippets (e.g. `const x = 1; x + 2;` or `setTimeout(...); 'ok'`)
        if let Some(exc) = res.get("exceptionDetails") {
            let err_desc = exc
                .pointer("/exception/description")
                .or_else(|| exc.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if err_desc.contains("SyntaxError") {
                let expr_json = serde_json::to_string(expr).unwrap_or_else(|_| "\"\"".to_string());
                let stmt_wrapped = format!(
                    "(async () => {{ const __r = await (0, eval)({expr_json}); return typeof __r === 'string' ? __r : JSON.stringify(__r ?? ''); }})()"
                );
                res = self.call(
                    "Runtime.evaluate",
                    json!({
                        "expression": stmt_wrapped,
                        "awaitPromise": true,
                        "returnByValue": true
                    }),
                )?;
            }
        }
        if let Some(exc) = res.get("exceptionDetails") {
            let txt = exc
                .pointer("/exception/description")
                .or_else(|| exc.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("JS evaluation error");
            return Err(txt.lines().next().unwrap_or(txt).to_string());
        }
        Ok(match res.pointer("/result/value") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        })
    }

    pub fn navigate(&mut self, url: &str) -> Result<String, String> {
        let _ = self.call(
            "Page.addScriptToEvaluateOnNewDocument",
            json!({
                "source": "window.confirm = () => true; window.alert = (m) => { window.__lastAlert = String(m); };"
            }),
        );
        self.call("Page.navigate", json!({ "url": url }))?;
        let deadline = Instant::now() + Duration::from_millis(6000);
        while Instant::now() < deadline {
            if let Ok(st) = self.eval_js("document.readyState") {
                if st == "complete" || st == "interactive" {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(60));
        }
        thread::sleep(Duration::from_millis(320));
        self.dom_snapshot()
    }

    pub fn dom_snapshot(&mut self) -> Result<String, String> {
        self.eval_js("document.documentElement ? (document.documentElement.outerHTML + '\\n---TEXT---\\n' + (document.body ? document.body.innerText : '')) : ''")
    }

    pub fn fill(&mut self, selector: &str, value: &str) -> Result<String, String> {
        let sel_js = serde_json::to_string(selector).unwrap_or_else(|_| "\"\"".to_string());
        let val_js = serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string());
        let script = format!(
            "(() => {{
                const el = document.querySelector({sel_js});
                if (!el) throw new Error('Selector not found: ' + {sel_js});
                el.focus();
                el.value = {val_js};
                el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                return new Promise(r => setTimeout(() => r(document.body.innerText), 160));
            }})()"
        );
        self.eval_js(&script)
    }

    pub fn select_option(&mut self, selector: &str, value: &str) -> Result<String, String> {
        let sel_js = serde_json::to_string(selector).unwrap_or_else(|_| "\"\"".to_string());
        let val_js = serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string());
        let script = format!(
            "(() => {{
                const el = document.querySelector({sel_js});
                if (!el) throw new Error('Select not found: ' + {sel_js});
                let matched = false;
                for (const opt of Array.from(el.options || [])) {{
                    if (opt.value === {val_js} || (opt.textContent || '').includes({val_js})) {{
                        el.value = opt.value;
                        matched = true;
                        break;
                    }}
                }}
                if (!matched) el.value = {val_js};
                el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                return new Promise(r => setTimeout(() => r(document.body.innerText), 180));
            }})()"
        );
        self.eval_js(&script)
    }

    pub fn click(&mut self, target: &str) -> Result<String, String> {
        let script = if let Some(txt) = target.strip_prefix("text=") {
            let t_js = serde_json::to_string(txt.trim()).unwrap_or_else(|_| "\"\"".to_string());
            format!(
                "(() => {{
                    const cands = Array.from(document.querySelectorAll('button, a, [role=\"button\"], input[type=\"submit\"], input[type=\"button\"], label'));
                    const el = cands.find(n => (n.innerText || n.value || n.textContent || '').trim().includes({t_js}));
                    if (!el) throw new Error('Button/link with text not found: ' + {t_js});
                    el.click();
                    return new Promise(r => setTimeout(() => r(document.documentElement.outerHTML + '\\n' + document.body.innerText), 260));
                }})()"
            )
        } else {
            let sel_js = serde_json::to_string(target).unwrap_or_else(|_| "\"\"".to_string());
            format!(
                "(() => {{
                    const el = document.querySelector({sel_js});
                    if (!el) throw new Error('Click target not found: ' + {sel_js});
                    el.click();
                    return new Promise(r => setTimeout(() => r(document.documentElement.outerHTML + '\\n' + document.body.innerText), 260));
                }})()"
            )
        };
        self.eval_js(&script)
    }

    pub fn set_viewport(&mut self, width: u32, height: u32, mobile: bool) -> Result<(), String> {
        let _ = self.call(
            "Emulation.setDeviceMetricsOverride",
            json!({
                "width": width,
                "height": height,
                "deviceScaleFactor": 1,
                "mobile": mobile
            }),
        )?;
        thread::sleep(Duration::from_millis(120));
        Ok(())
    }

    pub fn capture_screenshot(&mut self, out_path: &Path) -> Result<usize, String> {
        let res = self.call(
            "Page.captureScreenshot",
            json!({ "format": "png", "fromSurface": true }),
        )?;
        let b64 = res
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| "CDP Page.captureScreenshot returned no data".to_string())?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("decode screenshot base64: {e}"))?;
        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(out_path, &bytes).map_err(|e| format!("write screenshot: {e}"))?;
        Ok(bytes.len())
    }

    pub fn audit_layout(&mut self, width: u32, height: u32) -> Result<Value, String> {
        self.set_viewport(width, height, width <= 500)?;
        let js = r#"(() => {
            const issues = [];
            const vw = window.innerWidth, vh = window.innerHeight;
            const sw = document.documentElement ? document.documentElement.scrollWidth : 0;
            const textLen = (document.body ? document.body.innerText : '').trim().length;
            if (textLen === 0) issues.push('Blank page: document.body.innerText is empty');
            if (sw > vw + 4) issues.push(`Horizontal overflow at ${vw}x${vh}: scrollWidth=${sw} > innerWidth=${vw}`);
            const brokenImgs = Array.from(document.querySelectorAll('img'))
                .filter(img => img.complete && img.naturalWidth === 0)
                .map(img => img.getAttribute('src') || '(no src)');
            if (brokenImgs.length) issues.push(`Broken <img> (${brokenImgs.length}): ${brokenImgs.slice(0, 4).join(', ')}`);
            const ctrls = Array.from(document.querySelectorAll('button, a[href], input:not([type="hidden"]), select, textarea'));
            let visibleCtrls = 0;
            for (const el of ctrls.slice(0, 80)) {
                const st = window.getComputedStyle(el);
                if (st.display === 'none' || st.visibility === 'hidden' || parseFloat(st.opacity) === 0) continue;
                const r = el.getBoundingClientRect();
                const lbl = (el.id ? '#' + el.id : el.tagName.toLowerCase()) + (el.innerText ? ` "${el.innerText.trim().slice(0, 24)}"` : '');
                if (r.width < 2 || r.height < 2) {
                    issues.push(`Zero-size control ${lbl} (${Math.round(r.width)}x${Math.round(r.height)})`);
                    continue;
                }
                visibleCtrls++;
                if (r.right > vw + 4 || r.left < -4) {
                    issues.push(`Offscreen/clipped control ${lbl} at ${vw}x${vh} (left=${Math.round(r.left)}, right=${Math.round(r.right)})`);
                }
                if (r.top >= 0 && r.bottom <= vh && r.left >= 0 && r.right <= vw) {
                    const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
                    const hit = document.elementFromPoint(cx, cy);
                    if (hit && hit !== el && !el.contains(hit) && !hit.contains(el)) {
                        const blocker = hit.id ? '#' + hit.id : (hit.className ? hit.tagName.toLowerCase() + '.' + String(hit.className).trim().split(/\s+/)[0] : hit.tagName.toLowerCase());
                        issues.push(`Overlapped/blocked control ${lbl} covered by <${blocker}> at (${Math.round(cx)},${Math.round(cy)})`);
                    }
                }
            }
            return JSON.stringify({ viewport: `${vw}x${vh}`, textLen, visibleCtrls, issues });
        })()"#;
        let raw = self.eval_js(js)?;
        serde_json::from_str::<Value>(&raw).map_err(|e| format!("parse layout audit JSON: {e}"))
    }
}

fn parse_cdp_stdin_steps(steps_text: &str) -> Result<Vec<(String, String)>, String> {
    let trimmed = steps_text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let val: Value = serde_json::from_str(trimmed)
            .map_err(|e| format!("--stdin JSON parse failed: {e} (use --eval-stdin for raw JS)"))?;
        let arr = val.get("steps").and_then(Value::as_array).ok_or_else(|| {
            "--stdin JSON object must contain a `steps` array (use --eval-stdin for raw JS)"
                .to_string()
        })?;
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            if let Some(line) = item.as_str() {
                let ln = line.trim();
                if ln.is_empty() || ln.starts_with('#') {
                    continue;
                }
                let mut parts = ln.splitn(2, char::is_whitespace);
                let kw = parts.next().unwrap_or("").to_ascii_uppercase();
                let rest = parts.next().unwrap_or("").trim().to_string();
                if !matches!(
                    kw.as_str(),
                    "EVAL" | "FILL" | "CLICK" | "WAIT_MS" | "EXPECT"
                ) {
                    return Err(format!(
                        "Unrecognized CDP step keyword `{kw}` in `steps` (expected EVAL|FILL|CLICK|WAIT_MS|EXPECT)"
                    ));
                }
                out.push((kw, rest));
            } else {
                return Err(
                    "Each entry in `--stdin` JSON `steps` array must be a command string (e.g. `EVAL 2+2`)"
                        .to_string(),
                );
            }
        }
        return Ok(out);
    }

    let mut out = Vec::new();
    for raw_ln in trimmed.lines() {
        let ln = raw_ln.trim();
        if ln.is_empty() || ln.starts_with('#') {
            continue;
        }
        let mut parts = ln.splitn(2, char::is_whitespace);
        let kw = parts.next().unwrap_or("").to_ascii_uppercase();
        let rest = parts.next().unwrap_or("").trim().to_string();
        if !matches!(
            kw.as_str(),
            "EVAL" | "FILL" | "CLICK" | "WAIT_MS" | "EXPECT"
        ) {
            return Err(format!(
                "Unrecognized CDP step line `{ln}` (expected EVAL|FILL|CLICK|WAIT_MS|EXPECT or JSON {{\"steps\":[...]}}; pass --eval-stdin for raw JS)"
            ));
        }
        out.push((kw, rest));
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn run_cdp_attach(
    host: &str,
    port: u16,
    list_only: bool,
    target_filter: Option<&str>,
    eval_expr: Option<&str>,
    audit: bool,
    screenshot: Option<&Path>,
    steps_text: &str,
    watch_ms: u64,
    as_json: bool,
) -> i32 {
    let t0 = Instant::now();
    let parsed_steps = match parse_cdp_stdin_steps(steps_text) {
        Ok(s) => s,
        Err(e) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "ok": false, "error": e }))
                        .unwrap_or_default()
                );
            } else {
                eprintln!("[probe cdp] {e}");
            }
            return 2;
        }
    };
    let targets = match CdpSession::list_targets(host, port) {
        Ok(ts) => ts,
        Err(e) => {
            let msg = format!("[probe cdp] Failed to query http://{host}:{port}/json/list: {e}");
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "ok": false, "error": msg }))
                        .unwrap_or_default()
                );
            } else {
                eprintln!("{msg}");
            }
            return 1;
        }
    };

    if list_only
        || (eval_expr.is_none()
            && !audit
            && screenshot.is_none()
            && steps_text.trim().is_empty()
            && watch_ms == 0)
    {
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "endpoint": format!("http://{host}:{port}"),
                    "count": targets.len(),
                    "targets": targets,
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "[probe cdp] {} live target(s) on {host}:{port}:",
                targets.len()
            );
            for (idx, t) in targets.iter().enumerate() {
                println!(
                    "  {}. [{}] `{}` — {} (id={})",
                    idx + 1,
                    t.target_type,
                    t.title,
                    t.url,
                    t.id
                );
            }
        }
        return 0;
    }

    let picked = if let Some(filt) = target_filter.filter(|s| !s.trim().is_empty()) {
        let low = filt.to_ascii_lowercase();
        targets.iter().find(|t| {
            t.title.to_ascii_lowercase().contains(&low)
                || t.url.to_ascii_lowercase().contains(&low)
                || t.id.to_ascii_lowercase().contains(&low)
        })
    } else {
        targets
            .iter()
            .find(|t| t.target_type == "page")
            .or_else(|| targets.first())
    };
    let Some(tgt) = picked else {
        let msg = format!("[probe cdp] No matching CDP target found on {host}:{port}");
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "ok": false, "error": msg }))
                    .unwrap_or_default()
            );
        } else {
            eprintln!("{msg}");
        }
        return 1;
    };

    let mut sess = match CdpSession::attach(&tgt.ws_url) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("[probe cdp] Attach failed (`{}`): {e}", tgt.title);
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "ok": false, "error": msg }))
                        .unwrap_or_default()
                );
            } else {
                eprintln!("{msg}");
            }
            return 1;
        }
    };

    let mut eval_out: Option<String> = None;
    let mut audit_out: Option<Value> = None;
    let mut shot_out: Option<String> = None;
    let mut step_logs: Vec<String> = Vec::new();
    let mut ok = true;

    if let Some(expr) = eval_expr {
        match sess.eval_js(expr) {
            Ok(v) => eval_out = Some(v),
            Err(e) => {
                ok = false;
                step_logs.push(format!("EVAL error: {e}"));
            }
        }
    }

    if audit {
        match sess.audit_layout(1280, 800) {
            Ok(v) => {
                let iss_cnt = v
                    .get("issues")
                    .and_then(Value::as_array)
                    .map(|a| a.len())
                    .unwrap_or(0);
                if iss_cnt > 0 {
                    ok = false;
                }
                audit_out = Some(v);
            }
            Err(e) => {
                ok = false;
                step_logs.push(format!("AUDIT error: {e}"));
            }
        }
    }

    if let Some(sp) = screenshot {
        match sess.capture_screenshot(sp) {
            Ok(n) => shot_out = Some(format!("{} ({n} B)", sp.display())),
            Err(e) => {
                ok = false;
                step_logs.push(format!("SCREENSHOT error: {e}"));
            }
        }
    }

    let mut last_body = eval_out.clone().unwrap_or_default();
    for (kw, rest) in &parsed_steps {
        match kw.as_str() {
            "EVAL" => match sess.eval_js(rest) {
                Ok(v) => {
                    step_logs.push(format!("EVAL -> {v}"));
                    last_body = v;
                }
                Err(e) => {
                    ok = false;
                    step_logs.push(format!("EVAL FAIL: {e}"));
                }
            },
            "FILL" => {
                let mut fp = rest.splitn(2, char::is_whitespace);
                let sel = fp.next().unwrap_or("");
                let val = fp.next().unwrap_or("");
                match sess.fill(sel, val) {
                    Ok(v) => {
                        step_logs.push(format!("FILL {sel} OK"));
                        last_body = v;
                    }
                    Err(e) => {
                        ok = false;
                        step_logs.push(format!("FILL {sel} FAIL: {e}"));
                    }
                }
            }
            "CLICK" => match sess.click(rest) {
                Ok(v) => {
                    step_logs.push(format!("CLICK {rest} OK"));
                    last_body = v;
                }
                Err(e) => {
                    ok = false;
                    step_logs.push(format!("CLICK {rest} FAIL: {e}"));
                }
            },
            "WAIT_MS" => {
                let ms = rest.parse::<u64>().unwrap_or(200).min(10000);
                thread::sleep(Duration::from_millis(ms));
                step_logs.push(format!("WAIT_MS {ms}"));
            }
            "EXPECT" => {
                if let Some(needle) = rest.strip_prefix("CONTAINS ") {
                    let n = needle.trim().trim_matches('"');
                    if !last_body.contains(n) {
                        ok = false;
                        step_logs.push(format!("EXPECT CONTAINS `{n}` FAIL"));
                    } else {
                        step_logs.push(format!("EXPECT CONTAINS `{n}` OK"));
                    }
                }
            }
            _ => {}
        }
    }

    if watch_ms > 0 {
        sess.watch_events(watch_ms);
    }

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": ok,
                "elapsed_ms": elapsed_ms,
                "target": tgt,
                "eval": eval_out,
                "audit": audit_out,
                "screenshot": shot_out,
                "steps": step_logs,
                "console_logs": sess.console_logs,
                "network_events": sess.network_events,
                "js_errors": sess.js_errors,
                "network_errors": sess.network_errors,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[probe cdp] {} `{}` ({}) in {}ms",
            if ok { "OK" } else { "FAIL" },
            tgt.title,
            tgt.url,
            elapsed_ms
        );
        if let Some(ev) = &eval_out {
            println!("  eval: {ev}");
        }
        if let Some(au) = &audit_out {
            println!("  audit: {au}");
        }
        if let Some(sh) = &shot_out {
            println!("  screenshot: {sh}");
        }
        for sl in &step_logs {
            println!("  - {sl}");
        }
        for cl in &sess.console_logs {
            println!("  log: {cl}");
        }
        for ne in &sess.network_events {
            println!("  net: {ne}");
        }
        for je in &sess.js_errors {
            println!("  ! {je}");
        }
        for ne in &sess.network_errors {
            println!("  ! {ne}");
        }
    }
    if ok {
        0
    } else {
        1
    }
}

fn eval_single_cdp_endpoint(
    host: &str,
    port: u16,
    target_filter: Option<&str>,
    eval_expr: &str,
) -> (Option<CdpTarget>, Option<String>, Option<String>) {
    let targets = match CdpSession::list_targets(host, port) {
        Ok(t) => t,
        Err(e) => {
            return (
                None,
                None,
                Some(format!("list targets on {host}:{port}: {e}")),
            )
        }
    };
    let picked = if let Some(filt) = target_filter.filter(|s| !s.trim().is_empty()) {
        let low = filt.to_ascii_lowercase();
        targets.iter().find(|t| {
            t.id.eq_ignore_ascii_case(filt.trim())
                || t.title.to_ascii_lowercase().contains(&low)
                || t.url.to_ascii_lowercase().contains(&low)
                || t.id.to_ascii_lowercase().contains(&low)
        })
    } else {
        targets
            .iter()
            .find(|t| t.target_type == "page")
            .or_else(|| targets.first())
    };
    let Some(tgt) = picked.cloned() else {
        return (
            None,
            None,
            Some(format!("no matching CDP target on {host}:{port}")),
        );
    };
    let mut sess = match CdpSession::attach(&tgt.ws_url) {
        Ok(s) => s,
        Err(e) => return (Some(tgt), None, Some(format!("attach failed: {e}"))),
    };
    match sess.eval_js(eval_expr) {
        Ok(val) => (Some(tgt), Some(val), None),
        Err(e) => (Some(tgt), None, Some(format!("eval failed: {e}"))),
    }
}

fn json_object_diff(a: &str, b: &str) -> Option<Value> {
    let va: Value = serde_json::from_str(a).ok()?;
    let vb: Value = serde_json::from_str(b).ok()?;
    let (Some(oa), Some(ob)) = (va.as_object(), vb.as_object()) else {
        return None;
    };
    let mut only_in_a = Vec::new();
    let mut only_in_b = Vec::new();
    let mut changed_keys = Vec::new();
    for (k, val_a) in oa {
        match ob.get(k) {
            None => only_in_a.push(k.clone()),
            Some(val_b) if val_b != val_a => changed_keys.push(k.clone()),
            _ => {}
        }
    }
    for k in ob.keys() {
        if !oa.contains_key(k) {
            only_in_b.push(k.clone());
        }
    }
    only_in_a.sort();
    only_in_b.sort();
    changed_keys.sort();
    Some(json!({
        "only_in_a": only_in_a,
        "only_in_b": only_in_b,
        "changed_keys": changed_keys,
    }))
}

/// Concurrently evaluate the same JS expression across two live CDP ports and report structured diff.
pub fn run_cdp_diff_ports(
    host: &str,
    port_a: u16,
    port_b: u16,
    target_a: Option<&str>,
    target_b: Option<&str>,
    eval_expr: &str,
    as_json: bool,
) -> i32 {
    let t0 = Instant::now();
    let (res_a, res_b) = thread::scope(|s| {
        let ha = s.spawn(|| eval_single_cdp_endpoint(host, port_a, target_a, eval_expr));
        let hb = s.spawn(|| eval_single_cdp_endpoint(host, port_b, target_b, eval_expr));
        let ra = ha
            .join()
            .unwrap_or((None, None, Some("worker A panicked".to_string())));
        let rb = hb
            .join()
            .unwrap_or((None, None, Some("worker B panicked".to_string())));
        (ra, rb)
    });

    let ok = res_a.2.is_none() && res_b.2.is_none();
    let same_result = ok && res_a.1 == res_b.1;
    let json_diff = match (&res_a.1, &res_b.1) {
        (Some(a), Some(b)) => json_object_diff(a, b),
        _ => None,
    };
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": ok,
                "elapsed_ms": elapsed_ms,
                "same_result": same_result,
                "port_a": port_a,
                "port_b": port_b,
                "target_a": res_a.0,
                "target_b": res_b.0,
                "eval_a": res_a.1,
                "eval_b": res_b.1,
                "error_a": res_a.2,
                "error_b": res_b.2,
                "json_diff": json_diff,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[probe cdp diff] {}:{} vs {}:{} -> {} ({}ms)",
            host,
            port_a,
            host,
            port_b,
            if !ok {
                "ERROR"
            } else if same_result {
                "IDENTICAL"
            } else {
                "DIFFERENT"
            },
            elapsed_ms
        );
        if let Some(ea) = &res_a.2 {
            println!("  A({port_a}) ERR: {ea}");
        } else if let Some(va) = &res_a.1 {
            println!(
                "  A({port_a}): {}",
                va.chars().take(400).collect::<String>()
            );
        }
        if let Some(eb) = &res_b.2 {
            println!("  B({port_b}) ERR: {eb}");
        } else if let Some(vb) = &res_b.1 {
            println!(
                "  B({port_b}): {}",
                vb.chars().take(400).collect::<String>()
            );
        }
        if let Some(d) = &json_diff {
            println!("  json_diff: {d}");
        }
    }
    if ok {
        0
    } else {
        1
    }
}

fn is_loopback_cdp_host(host: &str) -> bool {
    let host_low = host.trim().to_ascii_lowercase();
    matches!(
        host_low.as_str(),
        "127.0.0.1" | "localhost" | "::1" | "[::1]"
    )
}

fn redact_header_value(hdr: &str) -> String {
    let Some((k, v)) = hdr.split_once(':') else {
        return "***".to_string();
    };
    let val = v.trim();
    if val.len() <= 8 {
        return format!("{k}: ***");
    }
    let head: String = val.chars().take(4).collect();
    let tail: String = val
        .chars()
        .rev()
        .take(3)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{k}: {head}***{tail} (len={})", val.len())
}

pub fn synthesize_role_headers_from_capture(
    cookies: &[(String, String)],
    storage_items: &[(String, String)],
    meta_csrfs: &[(String, String)],
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut headers: Vec<String> = Vec::new();
    let mut auth_keys: Vec<String> = Vec::new();
    let mut csrf_keys: Vec<String> = Vec::new();

    if !cookies.is_empty() {
        let cookie_str = cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        headers.push(format!("Cookie: {cookie_str}"));
    }

    let mut bearer_val: Option<String> = None;
    let mut csrf_pair: Option<(String, String)> = None;

    for (k, v) in storage_items {
        let vt = v.trim();
        if vt.is_empty() || vt.len() > 4096 || vt.contains(['\r', '\n']) {
            continue;
        }
        let kl = k.to_ascii_lowercase();
        if kl.contains("csrf") || kl.contains("xsrf") {
            csrf_keys.push(k.clone());
            if csrf_pair.is_none() {
                let hdr_name = if kl.contains("xsrf") {
                    "X-XSRF-TOKEN"
                } else {
                    "X-CSRF-Token"
                };
                csrf_pair = Some((hdr_name.to_string(), vt.to_string()));
            }
            continue;
        }
        if kl.contains("token")
            || kl.contains("jwt")
            || kl.contains("auth")
            || kl.contains("bearer")
            || kl.contains("session")
            || kl.contains("ticket")
        {
            auth_keys.push(k.clone());
            if bearer_val.is_none()
                && (vt.starts_with("eyJ")
                    || vt.to_ascii_lowercase().starts_with("bearer ")
                    || vt.len() >= 12)
            {
                let formatted = if vt.to_ascii_lowercase().starts_with("bearer ") {
                    vt.to_string()
                } else {
                    format!("Bearer {vt}")
                };
                bearer_val = Some(formatted);
            }
        }
    }

    for (k, v) in meta_csrfs {
        let vt = v.trim();
        if vt.is_empty() || vt.len() > 1024 || vt.contains(['\r', '\n']) {
            continue;
        }
        let kl = k.to_ascii_lowercase();
        csrf_keys.push(format!("meta:{k}"));
        if csrf_pair.is_none() {
            let hdr_name = if kl.contains("xsrf") {
                "X-XSRF-TOKEN"
            } else {
                "X-CSRF-Token"
            };
            csrf_pair = Some((hdr_name.to_string(), vt.to_string()));
        }
    }

    for (ck, cv) in cookies {
        let kl = ck.to_ascii_lowercase();
        let vt = cv.trim();
        if (kl.contains("csrf") || kl.contains("xsrf"))
            && !vt.is_empty()
            && !vt.contains(['\r', '\n'])
        {
            csrf_keys.push(format!("cookie:{ck}"));
            if csrf_pair.is_none() {
                let hdr_name = if kl.contains("xsrf") {
                    "X-XSRF-TOKEN"
                } else {
                    "X-CSRF-Token"
                };
                csrf_pair = Some((hdr_name.to_string(), vt.to_string()));
            }
        }
    }

    if let Some(bv) = bearer_val {
        headers.push(format!("Authorization: {bv}"));
    }
    if let Some((hk, hv)) = csrf_pair {
        headers.push(format!("{hk}: {hv}"));
    }

    (headers, auth_keys, csrf_keys)
}

/// Export live cookies, localStorage/sessionStorage auth/Bearer tokens, and CSRF tokens from an active
/// local CDP browser session directly into the `ap probe http --roles-matrix` role schema.
#[allow(clippy::too_many_arguments)]
pub fn run_cdp_export_role(
    host: &str,
    port: u16,
    target_filter: Option<&str>,
    role_name: &str,
    origin_filter: Option<&str>,
    include_storage: bool,
    redact: bool,
    as_json: bool,
) -> i32 {
    if !is_loopback_cdp_host(host) {
        let err = format!("refusing CDP --export-role from non-loopback host `{host}`");
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({ "ok": false, "mode": "export_role", "error": err })
                )
                .unwrap_or_default()
            );
        } else {
            eprintln!("[probe cdp] {err}");
        }
        return 1;
    }

    let targets = match CdpSession::list_targets(host, port) {
        Ok(t) => t,
        Err(e) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({ "ok": false, "mode": "export_role", "error": e })
                    )
                    .unwrap_or_default()
                );
            } else {
                eprintln!("[probe cdp] {e}");
            }
            return 1;
        }
    };

    let origin_low = origin_filter
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    let filt_low = target_filter
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    let pages: Vec<&CdpTarget> = targets
        .iter()
        .filter(|t| t.target_type == "page" && !t.ws_url.is_empty())
        .collect();
    let pool: Vec<&CdpTarget> = if pages.is_empty() {
        targets.iter().filter(|t| !t.ws_url.is_empty()).collect()
    } else {
        pages
    };
    let chosen = pool
        .iter()
        .copied()
        .find(|t| {
            let u_low = t.url.to_ascii_lowercase();
            let o_ok = origin_low
                .as_ref()
                .map(|o| u_low.contains(o))
                .unwrap_or(true);
            let f_ok = filt_low
                .as_ref()
                .map(|f| {
                    u_low.contains(f)
                        || t.title.to_ascii_lowercase().contains(f)
                        || t.id.to_ascii_lowercase().contains(f)
                })
                .unwrap_or(true);
            o_ok && f_ok
        })
        .or_else(|| pool.first().copied());

    let Some(tgt) = chosen else {
        let err = format!("no attachable page target found on CDP {host}:{port}");
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({ "ok": false, "mode": "export_role", "error": err })
                )
                .unwrap_or_default()
            );
        } else {
            eprintln!("[probe cdp] {err}");
        }
        return 1;
    };

    let mut sess = match CdpSession::attach(&tgt.ws_url) {
        Ok(s) => s,
        Err(e) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({ "ok": false, "mode": "export_role", "error": e })
                    )
                    .unwrap_or_default()
                );
            } else {
                eprintln!("[probe cdp] {e}");
            }
            return 1;
        }
    };

    let effective_origin = origin_filter
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let pfx = extract_origin_prefix(&tgt.url);
            if pfx.is_empty() {
                tgt.url.clone()
            } else {
                pfx
            }
        });

    let cookie_params =
        if effective_origin.starts_with("http://") || effective_origin.starts_with("https://") {
            json!({ "urls": [effective_origin] })
        } else {
            json!({})
        };
    let mut cookies: Vec<(String, String)> = Vec::new();
    if let Ok(res) = sess.call("Network.getCookies", cookie_params) {
        if let Some(arr) = res.get("cookies").and_then(Value::as_array) {
            for c in arr {
                let name = c.get("name").and_then(Value::as_str).unwrap_or("").trim();
                let val = c.get("value").and_then(Value::as_str).unwrap_or("");
                if !name.is_empty()
                    && !name.contains(['\r', '\n', ';', '='])
                    && !val.contains(['\r', '\n'])
                {
                    cookies.push((name.to_string(), val.to_string()));
                }
            }
        }
    }

    let mut storage_items: Vec<(String, String)> = Vec::new();
    let mut meta_csrfs: Vec<(String, String)> = Vec::new();
    if include_storage {
        let js = r#"(() => {
            const keyRe = /(?:token|jwt|auth|bearer|csrf|xsrf|session|ticket)/i;
            const storage = [];
            for (const [scope, st] of [['localStorage', window.localStorage], ['sessionStorage', window.sessionStorage]]) {
                try {
                    if (!st) continue;
                    for (let i = 0; i < st.length; i++) {
                        const k = st.key(i);
                        if (!k || !keyRe.test(k)) continue;
                        const v = st.getItem(k);
                        if (typeof v === 'string' && v.length > 0 && v.length <= 4096) {
                            storage.push([scope + '.' + k, v]);
                        }
                    }
                } catch {}
            }
            const metas = [];
            try {
                for (const m of document.querySelectorAll('meta[name*="csrf" i], meta[name*="xsrf" i]')) {
                    const nm = m.getAttribute('name') || 'csrf-token';
                    const ct = m.getAttribute('content') || '';
                    if (ct) metas.push([nm, ct]);
                }
            } catch {}
            return JSON.stringify({ storage, metas, origin: location.origin });
        })()"#;
        if let Ok(raw_s) = sess.eval_js(js) {
            if let Ok(v) = serde_json::from_str::<Value>(&raw_s) {
                if let Some(arr) = v.get("storage").and_then(Value::as_array) {
                    for pair in arr {
                        if let (Some(k), Some(val)) = (
                            pair.get(0).and_then(Value::as_str),
                            pair.get(1).and_then(Value::as_str),
                        ) {
                            storage_items.push((k.to_string(), val.to_string()));
                        }
                    }
                }
                if let Some(arr) = v.get("metas").and_then(Value::as_array) {
                    for pair in arr {
                        if let (Some(k), Some(val)) = (
                            pair.get(0).and_then(Value::as_str),
                            pair.get(1).and_then(Value::as_str),
                        ) {
                            meta_csrfs.push((k.to_string(), val.to_string()));
                        }
                    }
                }
            }
        }
    }

    let (raw_headers, storage_auth_keys, csrf_tokens) =
        synthesize_role_headers_from_capture(&cookies, &storage_items, &meta_csrfs);
    let out_headers: Vec<String> = if redact {
        raw_headers.iter().map(|h| redact_header_value(h)).collect()
    } else {
        raw_headers
    };
    let clean_role = if role_name.trim().is_empty() {
        "role1"
    } else {
        role_name.trim()
    };

    let out = json!({
        "ok": true,
        "mode": "export_role",
        "origin": effective_origin,
        "cdp_port": port,
        "target_url": tgt.url,
        "redacted": redact,
        "role": {
            "name": clean_role,
            "headers": out_headers,
            "cdp_port": port,
            "cookie_count": cookies.len(),
            "storage_auth_keys": storage_auth_keys,
            "csrf_tokens": csrf_tokens,
        },
        "matrix_snippet": {
            "roles": [
                {
                    "name": clean_role,
                    "headers": out_headers,
                }
            ]
        }
    });
    if as_json {
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        println!(
            "[probe cdp export-role] role=`{clean_role}` origin=`{effective_origin}` cookies={} headers={} storage_keys={:?}",
            cookies.len(),
            out_headers.len(),
            out["role"]["storage_auth_keys"]
        );
    }
    0
}

#[cfg(test)]
mod cdp_tests {
    use super::*;

    #[test]
    fn cdp_stdin_steps_validator_accepts_dsl_and_json_steps_but_rejects_raw_js() {
        assert!(parse_cdp_stdin_steps("").unwrap().is_empty());
        let dsl = parse_cdp_stdin_steps("# comment\nEVAL 2+2\nWAIT_MS 50\n").unwrap();
        assert_eq!(dsl.len(), 2);
        assert_eq!(dsl[0], ("EVAL".to_string(), "2+2".to_string()));

        let json_steps =
            parse_cdp_stdin_steps(r#"{"steps":["EVAL 1+1","EXPECT CONTAINS 2"]}"#).unwrap();
        assert_eq!(json_steps.len(), 2);

        let err_raw = parse_cdp_stdin_steps("2+2").unwrap_err();
        assert!(err_raw.contains("--eval-stdin"), "{err_raw}");

        let err_json = parse_cdp_stdin_steps(r#"{"expr":"2+2"}"#).unwrap_err();
        assert!(err_json.contains("steps"), "{err_json}");

        let mut oversize = vec![0x81u8, 127u8];
        oversize.extend_from_slice(&(64u64 * 1024 * 1024).to_be_bytes());
        let cap_err = ws_read_message(&mut std::io::Cursor::new(oversize));
        assert!(cap_err.is_err());
    }
}
