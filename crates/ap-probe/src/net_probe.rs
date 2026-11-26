use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use crate::smoke::run_cmd_with_timeout;

fn unescape_payload(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                'r' => {
                    out.push(b'\r');
                    i += 2;
                    continue;
                }
                'n' => {
                    out.push(b'\n');
                    i += 2;
                    continue;
                }
                't' => {
                    out.push(b'\t');
                    i += 2;
                    continue;
                }
                '0' => {
                    out.push(0);
                    i += 2;
                    continue;
                }
                '\\' => {
                    out.push(b'\\');
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        let mut buf = [0u8; 4];
        out.extend_from_slice(chars[i].encode_utf8(&mut buf).as_bytes());
        i += 1;
    }
    out
}

fn decode_hex_str(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if clean.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for idx in (0..clean.len()).step_by(2) {
        let b = u8::from_str_radix(&clean[idx..idx + 2], 16)
            .map_err(|e| format!("invalid hex at {idx}: {e}"))?;
        out.push(b);
    }
    Ok(out)
}

fn mini_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(256)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Deadline-bounded raw TCP banner/send/recv probe (replaces `nc`/`telnet` & hanging Python sockets).
pub fn run_tcp_cli(
    addr_str: &str,
    send_txt: Option<&str>,
    send_hex: Option<&str>,
    wait_ms: u64,
    timeout_ms: u64,
    as_json: bool,
) -> i32 {
    let t0 = Instant::now();
    let Ok(mut addrs) = addr_str.to_socket_addrs() else {
        eprintln!("[probe tcp] Failed to resolve `{addr_str}`");
        return 2;
    };
    let Some(sock_addr) = addrs.next() else {
        eprintln!("[probe tcp] No socket address resolved for `{addr_str}`");
        return 2;
    };
    let conn_dur = Duration::from_millis(timeout_ms.clamp(100, 30_000));
    let mut stream = match TcpStream::connect_timeout(&sock_addr, conn_dur) {
        Ok(s) => s,
        Err(e) => {
            let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "addr": addr_str,
                        "connected": false,
                        "elapsed_ms": elapsed_ms,
                        "error": e.to_string(),
                    }))
                    .unwrap_or_default()
                );
            } else {
                eprintln!("[probe tcp] FAIL `{addr_str}` ({elapsed_ms}ms): {e}");
            }
            return 1;
        }
    };

    let _ = stream.set_write_timeout(Some(Duration::from_millis(3000)));
    if let Some(hx) = send_hex.filter(|s| !s.trim().is_empty()) {
        match decode_hex_str(hx) {
            Ok(bytes) => {
                if let Err(e) = stream.write_all(&bytes) {
                    eprintln!("[probe tcp] write error: {e}");
                    return 1;
                }
            }
            Err(e) => {
                eprintln!("[probe tcp] {e}");
                return 2;
            }
        }
    } else if let Some(txt) = send_txt {
        let bytes = unescape_payload(txt);
        if let Err(e) = stream.write_all(&bytes) {
            eprintln!("[probe tcp] write error: {e}");
            return 1;
        }
    }

    let bounded_wait = wait_ms.clamp(50, 10_000);
    let deadline = Instant::now() + Duration::from_millis(bounded_wait);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(60)));
    let mut received = Vec::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline && received.len() < 16_384 {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                received.extend_from_slice(&buf[..n]);
                if received.len() >= 16_384 {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if !received.is_empty() {
                    break;
                }
                continue;
            }
            Err(_) => break,
        }
    }

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
    let text_preview = String::from_utf8_lossy(&received)
        .chars()
        .take(1600)
        .collect::<String>();
    let hex_preview = mini_hex(&received);

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "addr": addr_str,
                "connected": true,
                "elapsed_ms": elapsed_ms,
                "bytes_read": received.len(),
                "text": text_preview,
                "hex": hex_preview,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[probe tcp] CONNECTED `{addr_str}` ({elapsed_ms}ms | {} B received)",
            received.len()
        );
        if !text_preview.trim().is_empty() {
            println!("  text: {}", text_preview.trim());
        }
        if !hex_preview.is_empty() {
            println!("  hex : {hex_preview}");
        }
    }
    0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedHttpReq {
    pub method: String,
    pub path: String,
    pub headers: Vec<String>,
    pub body: String,
}

fn handle_one_http(
    mut stream: TcpStream,
    reply_status: u16,
    reply_type: &str,
    reply_body: &str,
) -> Option<CapturedHttpReq> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut hdr_end: Option<usize> = None;
    let mut content_len: usize = 0;

    while raw.len() < 65_536 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if hdr_end.is_none() {
                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        hdr_end = Some(pos + 4);
                        let htxt = String::from_utf8_lossy(&raw[..pos]);
                        for ln in htxt.lines().skip(1) {
                            if let Some((k, v)) = ln.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    content_len = v.trim().parse::<usize>().unwrap_or(0);
                                }
                            }
                        }
                    }
                }
                if let Some(he) = hdr_end {
                    if raw.len() >= he + content_len {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    if raw.is_empty() {
        return None;
    }

    let (hdr_part, body_part) = if let Some(he) = hdr_end {
        (
            String::from_utf8_lossy(&raw[..he.saturating_sub(4)]).to_string(),
            String::from_utf8_lossy(&raw[he..]).to_string(),
        )
    } else {
        (String::from_utf8_lossy(&raw).to_string(), String::new())
    };
    let mut lines = hdr_part.lines();
    let first = lines.next().unwrap_or("");
    let mut fp = first.split_whitespace();
    let method = fp.next().unwrap_or("GET").to_string();
    let path = fp.next().unwrap_or("/").to_string();
    let headers: Vec<String> = lines
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .take(32)
        .collect();

    let reason = match reply_status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "OK",
    };
    let resp = format!(
        "HTTP/1.1 {reply_status} {reason}\r\nContent-Type: {reply_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply_body}",
        reply_body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();

    Some(CapturedHttpReq {
        method,
        path,
        headers,
        body: body_part.chars().take(4000).collect(),
    })
}

/// Bounded ephemeral HTTP callback/webhook capture server (auto-exits after `max_reqs` or `wait_ms` — zero hanging server leaks!).
#[allow(clippy::too_many_arguments)]
pub fn run_listen_cli(
    port: u16,
    wait_ms: u64,
    max_reqs: usize,
    reply_status: u16,
    reply_type: &str,
    reply_body: &str,
    run_cmd: Option<&str>,
    as_json: bool,
) -> i32 {
    let t0 = Instant::now();
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[probe listen] Failed to bind 127.0.0.1:{port}: {e}");
            return 1;
        }
    };
    let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    let _ = listener.set_nonblocking(true);

    let bg_handle = run_cmd.filter(|s| !s.trim().is_empty()).map(|raw| {
        let expanded = raw.replace("{{PORT}}", &bound_port.to_string());
        thread::spawn(move || {
            let out = if cfg!(windows) {
                Command::new("pwsh.exe")
                    .args(["-NoLogo", "-NoProfile", "-Command", &expanded])
                    .output()
                    .or_else(|_| {
                        Command::new("powershell.exe")
                            .args(["-NoLogo", "-NoProfile", "-Command", &expanded])
                            .output()
                    })
            } else {
                Command::new("sh").args(["-c", &expanded]).output()
            };
            match out {
                Ok(o) => (
                    o.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&o.stdout)
                        .chars()
                        .take(400)
                        .collect::<String>(),
                ),
                Err(e) => (-1, format!("spawn error: {e}")),
            }
        })
    });

    let deadline = Instant::now() + Duration::from_millis(wait_ms.clamp(200, 30_000));
    let target_reqs = max_reqs.clamp(1, 50);
    let mut captured = Vec::new();
    while Instant::now() < deadline && captured.len() < target_reqs {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                if let Some(req) = handle_one_http(stream, reply_status, reply_type, reply_body) {
                    captured.push(req);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }

    let run_res = bg_handle.and_then(|h| h.join().ok());
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": !captured.is_empty(),
                "port": bound_port,
                "elapsed_ms": elapsed_ms,
                "captured_count": captured.len(),
                "requests": captured,
                "run_exit": run_res.as_ref().map(|(c, _)| *c),
                "run_output": run_res.as_ref().map(|(_, o)| o.as_str()),
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[probe listen] 127.0.0.1:{bound_port} captured {} request(s) in {elapsed_ms}ms:",
            captured.len()
        );
        for (i, r) in captured.iter().enumerate() {
            println!(
                "  {}. {} {} ({} headers, {} B body)",
                i + 1,
                r.method,
                r.path,
                r.headers.len(),
                r.body.len()
            );
            for h in r.headers.iter().take(6) {
                println!("     {h}");
            }
            if !r.body.is_empty() {
                println!(
                    "     body: {}",
                    r.body.chars().take(240).collect::<String>()
                );
            }
        }
    }
    if captured.is_empty() {
        1
    } else {
        0
    }
}

const MAX_WS_FRAME_BYTES: usize = 8 * 1024 * 1024;

fn parse_ws_target(url: &str) -> Result<(bool, String, String, u16, String), String> {
    let (is_tls, default_port, rest) = if let Some(r) = url.strip_prefix("ws://") {
        (false, 80u16, r)
    } else if let Some(r) = url.strip_prefix("wss://") {
        (true, 443u16, r)
    } else {
        return Err("URL must start with `ws://` or `wss://`".to_string());
    };
    let (host_port_raw, req_path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if host_port_raw.is_empty() {
        return Err("missing host in WebSocket URL".to_string());
    }
    let (host_only, port, host_port_hdr) = if host_port_raw.starts_with('[') {
        if let Some(end_br) = host_port_raw.find(']') {
            let h = &host_port_raw[1..end_br];
            let after = &host_port_raw[end_br + 1..];
            if let Some(p_str) = after.strip_prefix(':') {
                let p = p_str
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port `{p_str}`"))?;
                (h.to_string(), p, host_port_raw.to_string())
            } else {
                (h.to_string(), default_port, host_port_raw.to_string())
            }
        } else {
            return Err("unclosed IPv6 bracket in host".to_string());
        }
    } else if let Some((h, p_str)) = host_port_raw.rsplit_once(':') {
        let p = p_str
            .parse::<u16>()
            .map_err(|_| format!("invalid port `{p_str}`"))?;
        (h.to_string(), p, host_port_raw.to_string())
    } else {
        (
            host_port_raw.to_string(),
            default_port,
            host_port_raw.to_string(),
        )
    };
    Ok((is_tls, host_port_hdr, host_only, port, req_path.to_string()))
}

fn ws_connect_addr_str(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn extract_ws_origin_host(origin: &str) -> String {
    let low = origin.trim().to_ascii_lowercase();
    let after_scheme = low
        .strip_prefix("http://")
        .or_else(|| low.strip_prefix("https://"))
        .unwrap_or(low.as_str());
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .unwrap_or("")
            .trim_start_matches('[')
            .to_string()
    } else {
        authority.split(':').next().unwrap_or("").to_string()
    }
}

fn is_untrusted_ws_origin(origin: Option<&str>) -> bool {
    let Some(o) = origin else {
        return false;
    };
    let low = o.trim().to_ascii_lowercase();
    if low == "null" {
        return true;
    }
    if !(low.starts_with("http://") || low.starts_with("https://")) {
        return true;
    }
    let host = extract_ws_origin_host(&low);
    !matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
}

fn ws_encode_text_frame(text: &str) -> Vec<u8> {
    let payload = text.as_bytes();
    let len = payload.len();
    let mask = [0x42u8, 0x9a, 0x11, 0x7e];
    let mut frame = Vec::with_capacity(len + 14);
    frame.push(0x81); // FIN + Text
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
    frame
}

fn ws_write_text_frame<W: Write>(stream: &mut W, text: &str) -> Result<(), String> {
    let frame = ws_encode_text_frame(text);
    stream
        .write_all(&frame)
        .map_err(|e| format!("ws write failed: {e}"))
}

fn ws_write_pong_frame<W: Write>(stream: &mut W, payload: &[u8]) -> Result<(), String> {
    let body = &payload[..payload.len().min(125)];
    let mask = [0x42u8, 0x9a, 0x11, 0x7e];
    let mut frame = Vec::with_capacity(body.len() + 6);
    frame.push(0x8A); // FIN + Pong
    frame.push(0x80 | (body.len() as u8));
    frame.extend_from_slice(&mask);
    for (i, b) in body.iter().enumerate() {
        frame.push(b ^ mask[i & 3]);
    }
    stream
        .write_all(&frame)
        .map_err(|e| format!("ws pong write failed: {e}"))
}

fn ws_read_one_frame<R: Read>(stream: &mut R) -> Result<(bool, u8, Vec<u8>), String> {
    let mut hdr = [0u8; 2];
    stream
        .read_exact(&mut hdr)
        .map_err(|e| format!("ws hdr: {e}"))?;
    let fin = (hdr[0] & 0x80) != 0;
    let opcode = hdr[0] & 0x0F;
    let masked = (hdr[1] & 0x80) != 0;
    let mut len = (hdr[1] & 0x7F) as usize;
    if len == 126 {
        let mut b = [0u8; 2];
        stream
            .read_exact(&mut b)
            .map_err(|e| format!("ws len16: {e}"))?;
        len = u16::from_be_bytes(b) as usize;
    } else if len == 127 {
        let mut b = [0u8; 8];
        stream
            .read_exact(&mut b)
            .map_err(|e| format!("ws len64: {e}"))?;
        let raw_len = u64::from_be_bytes(b);
        if raw_len > MAX_WS_FRAME_BYTES as u64 {
            return Err(format!(
                "ws frame too large ({raw_len} bytes > {MAX_WS_FRAME_BYTES})"
            ));
        }
        len = raw_len as usize;
    }
    let mut mask = [0u8; 4];
    if masked {
        stream
            .read_exact(&mut mask)
            .map_err(|e| format!("ws mask: {e}"))?;
    }
    let mut data = vec![0u8; len];
    if len > 0 {
        stream
            .read_exact(&mut data)
            .map_err(|e| format!("ws body: {e}"))?;
    }
    if masked {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok((fin, opcode, data))
}

fn build_ws_upgrade_req(
    host_port: &str,
    req_path: &str,
    headers: &[String],
    origin: Option<&str>,
) -> String {
    let mut req = format!(
        "GET {req_path} HTTP/1.1\r\nHost: {host_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
    );
    if let Some(orig) = origin {
        req.push_str(&format!("Origin: {orig}\r\n"));
    }
    for h in headers {
        let t = h.trim();
        if t.is_empty() {
            continue;
        }
        if origin.is_some() && t.to_ascii_lowercase().starts_with("origin:") {
            continue;
        }
        req.push_str(t);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req
}

#[allow(unused_variables)]
fn run_wss_exchange(
    host: &str,
    port: u16,
    req_str: &str,
    send_msgs: &[String],
    wait_ms: u64,
) -> Result<serde_json::Value, String> {
    let clamped_wait = wait_ms.clamp(80, 12_000);
    let mut send_frames = Vec::new();
    for m in send_msgs {
        send_frames.extend_from_slice(&ws_encode_text_frame(m));
    }

    #[cfg(windows)]
    {
        let h_esc = host.replace('\'', "''");
        let req_b64 = base64::engine::general_purpose::STANDARD.encode(req_str.as_bytes());
        let send_b64 = base64::engine::general_purpose::STANDARD.encode(&send_frames);
        let ps_code = format!(
            "$ErrorActionPreference='Stop'; \
$reqB=[Convert]::FromBase64String('{req_b64}'); \
$sendB=[Convert]::FromBase64String('{send_b64}'); \
$c=New-Object System.Net.Sockets.TcpClient; \
$ar=$c.BeginConnect('{h_esc}',{port},$null,$null); \
if(-not $ar.AsyncWaitHandle.WaitOne(4000,$false)){{ throw 'TCP connect timeout' }}; \
$c.EndConnect($ar); \
$s=New-Object System.Net.Security.SslStream($c.GetStream(),$false,({{param($a,$b,$ce,$e)$true}})); \
$s.ReadTimeout=3000; $s.WriteTimeout=3000; \
$s.AuthenticateAsClient('{h_esc}'); \
$s.Write($reqB,0,$reqB.Length); $s.Flush(); \
$hb=New-Object System.Collections.Generic.List[byte]; \
while($hb.Count -lt 8192){{ $x=$s.ReadByte(); if($x -lt 0){{break}}; [void]$hb.Add([byte]$x); $n=$hb.Count; if($n -ge 4 -and $hb[$n-4] -eq 13 -and $hb[$n-3] -eq 10 -and $hb[$n-2] -eq 13 -and $hb[$n-1] -eq 10){{break}} }}; \
$ht=[Text.Encoding]::UTF8.GetString($hb.ToArray()); \
$lines=$ht -split \"`r?`n\"; \
$sl=if($lines.Length -gt 0){{$lines[0].Trim()}}else{{''}}; \
$hp=($lines | Where-Object {{$_.Trim() -ne ''}} | Select-Object -First 6) -join ' | '; \
$acc=($sl -like '*101*'); \
$msgs=New-Object System.Collections.Generic.List[string]; \
$cr='handshake_rejected'; $cc=$null; $cm=$null; \
if($acc){{ \
  $cr='idle_timeout'; \
  if($sendB.Length -gt 0){{ $s.Write($sendB,0,$sendB.Length); $s.Flush() }}; \
  $s.ReadTimeout=60; \
  $sw=[Diagnostics.Stopwatch]::StartNew(); \
  $frag=New-Object System.Collections.Generic.List[byte]; $inFrag=$false; \
  while($sw.ElapsedMilliseconds -lt {clamped_wait} -and $msgs.Count -lt 40){{ \
    try {{ \
      $b0=$s.ReadByte(); if($b0 -lt 0){{ $cr='eof'; break }}; \
      $s.ReadTimeout=1500; \
      $b1=$s.ReadByte(); if($b1 -lt 0){{ $cr='eof'; break }}; \
      $fin=($b0 -band 128) -ne 0; $op=$b0 -band 15; $mk=($b1 -band 128) -ne 0; \
      [long]$ln=$b1 -band 127; \
      if($ln -eq 126){{ $lb=New-Object byte[] 2; $r=0; while($r -lt 2){{$n=$s.Read($lb,$r,2-$r);if($n -le 0){{throw 'eof'}};$r+=$n}}; $ln=([int]$lb[0] -shl 8) -bor [int]$lb[1] }} \
      elseif($ln -eq 127){{ $lb=New-Object byte[] 8; $r=0; while($r -lt 8){{$n=$s.Read($lb,$r,8-$r);if($n -le 0){{throw 'eof'}};$r+=$n}}; [uint64]$u=0; for($k=0;$k -lt 8;$k++){{$u=($u -shl 8) -bor [uint64]$lb[$k]}}; if($u -gt 8388608){{ throw 'ws frame too large' }}; $ln=[long]$u }}; \
      $mb=New-Object byte[] 4; if($mk){{ $r=0; while($r -lt 4){{$n=$s.Read($mb,$r,4-$r);if($n -le 0){{throw 'eof'}};$r+=$n}} }}; \
      $pl=New-Object byte[] $ln; $r=0; while($r -lt $ln){{ $n=$s.Read($pl,$r,[int]($ln-$r)); if($n -le 0){{throw 'eof'}}; $r+=$n }}; \
      if($mk){{ for($k=0;$k -lt $ln;$k++){{ $pl[$k]=$pl[$k] -bxor $mb[$k -band 3] }} }}; \
      $s.ReadTimeout=60; \
      if($op -eq 8){{ if($pl.Length -ge 2){{$cc=([int]$pl[0] -shl 8) -bor [int]$pl[1]; if($pl.Length -gt 2){{$cm=[Text.Encoding]::UTF8.GetString($pl,2,$pl.Length-2).Trim()}}}}; $cr=if($cc -ne $null){{\"close_frame_$cc\"}}else{{'close_frame'}}; break }} \
      elseif($op -eq 9){{ $pn=[Math]::Min($pl.Length,125); $pf=New-Object byte[] (6+$pn); $pf[0]=0x8A; $pf[1]=(0x80 -bor $pn); $pf[2]=0x42; $pf[3]=0x9A; $pf[4]=0x11; $pf[5]=0x7E; for($k=0;$k -lt $pn;$k++){{$pf[6+$k]=$pl[$k] -bxor $pf[2+($k -band 3)]}}; $s.Write($pf,0,$pf.Length); $s.Flush(); continue }} \
      elseif($op -eq 1 -or $op -eq 2){{ if($fin){{ $t=[Text.Encoding]::UTF8.GetString($pl); if($t.Length -gt 2000){{$t=$t.Substring(0,2000)}}; [void]$msgs.Add($t); $frag.Clear(); $inFrag=$false }} else {{ $frag.Clear(); $frag.AddRange($pl); $inFrag=$true }} }} \
      elseif($op -eq 0 -and $inFrag){{ if(($frag.Count + $pl.Length) -gt 8388608){{ throw 'ws fragmented message too large' }}; $frag.AddRange($pl); if($fin){{ $t=[Text.Encoding]::UTF8.GetString($frag.ToArray()); if($t.Length -gt 2000){{$t=$t.Substring(0,2000)}}; [void]$msgs.Add($t); $frag.Clear(); $inFrag=$false }} }} \
    }} catch [System.IO.IOException] {{ \
      if($_.Exception.InnerException -is [System.Net.Sockets.SocketException] -and $_.Exception.InnerException.SocketErrorCode -eq 'TimedOut'){{ $s.ReadTimeout=60; continue }} else {{ $cr='eof'; break }} \
    }} \
  }} \
}}; \
try{{$s.Close();$c.Close()}}catch{{}}; \
[ordered]@{{accepted=$acc;status_line=$sl;headers_preview=$hp;close_reason=$cr;close_code=$cc;close_message=$cm;messages=$msgs.ToArray()}} | ConvertTo-Json -Compress"
        );
        let timeout = Duration::from_millis(clamped_wait + 8000);
        let mut last_err = "PowerShell unavailable for wss://".to_string();
        for bin in ["pwsh.exe", "powershell.exe"] {
            let mut cmd = Command::new(bin);
            cmd.args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &ps_code,
            ]);
            match run_cmd_with_timeout(&mut cmd, timeout, None) {
                Ok(o) if o.status.success() => {
                    return serde_json::from_slice(&o.stdout)
                        .map_err(|e| format!("wss JSON parse error: {e}"));
                }
                Ok(o) => {
                    last_err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    break;
                }
                Err(e) if e.starts_with("spawn failed:") => {
                    last_err = e;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err)
    }

    #[cfg(not(windows))]
    {
        let mut child = Command::new("openssl")
            .args([
                "s_client",
                "-quiet",
                "-servername",
                host,
                "-connect",
                &format!("{host}:{port}"),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("openssl s_client spawn failed: {e}"))?;
        let mut sin = child.stdin.take().ok_or("missing stdin")?;
        let mut sout = child.stdout.take().ok_or("missing stdout")?;
        sin.write_all(req_str.as_bytes())
            .map_err(|e| format!("wss write failed: {e}"))?;
        let _ = sin.flush();
        let mut hbuf = Vec::new();
        let mut b1 = [0u8; 1];
        while hbuf.len() < 8192 {
            match sout.read(&mut b1) {
                Ok(1) => {
                    hbuf.push(b1[0]);
                    if hbuf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                _ => break,
            }
        }
        let htxt = String::from_utf8_lossy(&hbuf).to_string();
        let status_line = htxt.lines().next().unwrap_or("").trim().to_string();
        let headers_preview: String = htxt
            .lines()
            .take(6)
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(" | ");
        let accepted = status_line.contains("101");
        let mut messages: Vec<String> = Vec::new();
        let mut close_reason = if accepted {
            "idle_timeout".to_string()
        } else {
            "handshake_rejected".to_string()
        };
        let mut close_code: Option<u16> = None;
        let mut close_message: Option<String> = None;
        if accepted {
            if !send_frames.is_empty() {
                let _ = sin.write_all(&send_frames);
                let _ = sin.flush();
            }
            let (tx, rx) = std::sync::mpsc::channel::<Result<(bool, u8, Vec<u8>), String>>();
            std::thread::spawn(move || loop {
                let fr = ws_read_one_frame(&mut sout);
                let done = fr.is_err();
                if tx.send(fr).is_err() || done {
                    break;
                }
            });
            let deadline = Instant::now() + Duration::from_millis(clamped_wait);
            let mut frag_buf: Vec<u8> = Vec::new();
            let mut in_frag = false;
            while Instant::now() < deadline && messages.len() < 40 {
                let rem = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(rem.min(Duration::from_millis(80))) {
                    Ok(Ok((fin, opcode, data))) => match opcode {
                        8 => {
                            if data.len() >= 2 {
                                close_code = Some(u16::from_be_bytes([data[0], data[1]]));
                                if data.len() > 2 {
                                    let msg = String::from_utf8_lossy(&data[2..])
                                        .trim()
                                        .chars()
                                        .take(240)
                                        .collect::<String>();
                                    if !msg.is_empty() {
                                        close_message = Some(msg);
                                    }
                                }
                            }
                            close_reason = match close_code {
                                Some(c) => format!("close_frame_{c}"),
                                None => "close_frame".to_string(),
                            };
                            break;
                        }
                        9 => {
                            let _ = ws_write_pong_frame(&mut sin, &data);
                            let _ = sin.flush();
                        }
                        1 | 2 => {
                            if fin {
                                messages.push(
                                    String::from_utf8_lossy(&data).chars().take(2000).collect(),
                                );
                                frag_buf.clear();
                                in_frag = false;
                            } else {
                                frag_buf = data;
                                in_frag = true;
                            }
                        }
                        0 if in_frag => {
                            if frag_buf.len().saturating_add(data.len()) > MAX_WS_FRAME_BYTES {
                                close_reason = "read_error: fragmented message too large".into();
                                break;
                            }
                            frag_buf.extend_from_slice(&data);
                            if fin {
                                messages.push(
                                    String::from_utf8_lossy(&frag_buf)
                                        .chars()
                                        .take(2000)
                                        .collect(),
                                );
                                frag_buf.clear();
                                in_frag = false;
                            }
                        }
                        _ => {}
                    },
                    Ok(Err(e)) => {
                        close_reason = if e.contains("eof") {
                            "eof".to_string()
                        } else {
                            format!("read_error: {e}")
                        };
                        break;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        close_reason = "eof".to_string();
                        break;
                    }
                }
            }
        }
        crate::smoke::kill_process_tree(&mut child);
        Ok(json!({
            "accepted": accepted,
            "status_line": status_line,
            "headers_preview": headers_preview,
            "close_reason": close_reason,
            "close_code": close_code,
            "close_message": close_message,
            "messages": messages,
        }))
    }
}

/// Deadline-bounded non-CDP RFC 6455 WebSocket (`ws://` / `wss://`) send/recv diagnostic client (zero hangs).
pub(crate) fn probe_ws_result(
    url: &str,
    send_msgs: &[String],
    headers: &[String],
    wait_ms: u64,
) -> (i32, serde_json::Value) {
    let t0 = Instant::now();
    let (is_tls, host_port, host_only, port, req_path) = match parse_ws_target(url) {
        Ok(v) => v,
        Err(e) => {
            return (
                2,
                json!({
                    "ok": false,
                    "url": url,
                    "error": format!("Invalid URL `{url}`: {e}"),
                }),
            );
        }
    };
    let req = build_ws_upgrade_req(&host_port, &req_path, headers, None);
    let clamped_wait = wait_ms.clamp(100, 12_000);

    if is_tls {
        let res = match run_wss_exchange(&host_only, port, &req, send_msgs, clamped_wait) {
            Ok(v) => v,
            Err(e) => {
                return (
                    1,
                    json!({
                        "ok": false,
                        "url": url,
                        "error": format!("wss:// connect/exchange failed (`{url}`): {e}"),
                    }),
                );
            }
        };
        let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
        let accepted = res["accepted"].as_bool().unwrap_or(false);
        let status_line = res["status_line"].as_str().unwrap_or("");
        if !accepted {
            let rej_preview = res["headers_preview"].as_str().unwrap_or("");
            return (
                1,
                json!({
                    "ok": false,
                    "url": url,
                    "handshake": status_line,
                    "close_reason": "handshake_rejected",
                    "headers_preview": rej_preview,
                    "elapsed_ms": elapsed_ms,
                }),
            );
        }
        let messages: Vec<String> = res["messages"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let close_reason = res["close_reason"].as_str().unwrap_or("idle_timeout");
        return (
            0,
            json!({
                "ok": true,
                "url": url,
                "handshake": status_line,
                "elapsed_ms": elapsed_ms,
                "wait_ms": clamped_wait,
                "close_reason": close_reason,
                "close_code": res["close_code"],
                "close_message": res["close_message"],
                "received_count": messages.len(),
                "messages": messages,
            }),
        );
    }

    let connect_target = ws_connect_addr_str(&host_only, port);
    let Ok(mut addrs) = connect_target.to_socket_addrs() else {
        return (
            2,
            json!({
                "ok": false,
                "url": url,
                "error": format!("Failed to resolve `{connect_target}`"),
            }),
        );
    };
    let Some(sa) = addrs.next() else {
        return (
            2,
            json!({
                "ok": false,
                "url": url,
                "error": format!("No address resolved for `{connect_target}`"),
            }),
        );
    };
    let mut stream = match TcpStream::connect_timeout(&sa, Duration::from_secs(4)) {
        Ok(s) => s,
        Err(e) => {
            return (
                1,
                json!({
                    "ok": false,
                    "url": url,
                    "error": format!("Connect failed (`{url}`): {e}"),
                }),
            );
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));

    if let Err(e) = stream.write_all(req.as_bytes()) {
        return (
            1,
            json!({
                "ok": false,
                "url": url,
                "error": format!("Handshake write error: {e}"),
            }),
        );
    }

    let mut hbuf = Vec::new();
    let mut b1 = [0u8; 1];
    while hbuf.len() < 8192 {
        match stream.read(&mut b1) {
            Ok(1) => {
                hbuf.push(b1[0]);
                if hbuf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            _ => break,
        }
    }
    let htxt = String::from_utf8_lossy(&hbuf).to_string();
    let status_line = htxt.lines().next().unwrap_or("").trim().to_string();
    if !status_line.contains("101") {
        let rej_preview: String = htxt
            .lines()
            .take(6)
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(" | ");
        return (
            1,
            json!({
                "ok": false,
                "url": url,
                "handshake": status_line,
                "close_reason": "handshake_rejected",
                "headers_preview": rej_preview,
                "elapsed_ms": (t0.elapsed().as_secs_f64() * 1000.0).round(),
            }),
        );
    }

    for msg in send_msgs {
        if let Err(e) = ws_write_text_frame(&mut stream, msg) {
            return (
                1,
                json!({
                    "ok": false,
                    "url": url,
                    "error": e,
                }),
            );
        }
    }

    let deadline = Instant::now() + Duration::from_millis(clamped_wait);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(60)));
    let mut messages: Vec<String> = Vec::new();
    let mut frag_buf: Vec<u8> = Vec::new();
    let mut in_frag = false;
    let mut close_reason = "idle_timeout".to_string();
    let mut close_code: Option<u16> = None;
    let mut close_message: Option<String> = None;

    while Instant::now() < deadline {
        if messages.len() >= 40 {
            close_reason = "max_messages".to_string();
            break;
        }
        let mut peek_b = [0u8; 1];
        match stream.peek(&mut peek_b) {
            Ok(0) => {
                close_reason = "eof".to_string();
                break;
            }
            Ok(_) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
                let fr = ws_read_one_frame(&mut stream);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(60)));
                match fr {
                    Ok((_, 8, data)) => {
                        if data.len() >= 2 {
                            close_code = Some(u16::from_be_bytes([data[0], data[1]]));
                            if data.len() > 2 {
                                let msg = String::from_utf8_lossy(&data[2..])
                                    .trim()
                                    .chars()
                                    .take(240)
                                    .collect::<String>();
                                if !msg.is_empty() {
                                    close_message = Some(msg);
                                }
                            }
                        }
                        close_reason = match close_code {
                            Some(c) => format!("close_frame_{c}"),
                            None => "close_frame".to_string(),
                        };
                        break;
                    }
                    Ok((_, 9, data)) => {
                        let _ = ws_write_pong_frame(&mut stream, &data);
                    }
                    Ok((fin, 1 | 2, data)) => {
                        if fin {
                            messages
                                .push(String::from_utf8_lossy(&data).chars().take(2000).collect());
                            frag_buf.clear();
                            in_frag = false;
                        } else {
                            frag_buf = data;
                            in_frag = true;
                        }
                    }
                    Ok((fin, 0, data)) if in_frag => {
                        if frag_buf.len().saturating_add(data.len()) > MAX_WS_FRAME_BYTES {
                            close_reason = "read_error: fragmented message too large".to_string();
                            break;
                        }
                        frag_buf.extend_from_slice(&data);
                        if fin {
                            messages.push(
                                String::from_utf8_lossy(&frag_buf)
                                    .chars()
                                    .take(2000)
                                    .collect(),
                            );
                            frag_buf.clear();
                            in_frag = false;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        close_reason = format!("read_error: {e}");
                        break;
                    }
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
            Err(e) => {
                close_reason = format!("io_error: {e}");
                break;
            }
        }
    }

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
    (
        0,
        json!({
            "ok": true,
            "url": url,
            "handshake": status_line,
            "elapsed_ms": elapsed_ms,
            "wait_ms": clamped_wait,
            "close_reason": close_reason,
            "close_code": close_code,
            "close_message": close_message,
            "received_count": messages.len(),
            "messages": messages,
        }),
    )
}

pub fn run_ws_cli(
    url: &str,
    send_msgs: &[String],
    headers: &[String],
    wait_ms: u64,
    as_json: bool,
) -> i32 {
    let (rc, val) = probe_ws_result(url, send_msgs, headers, wait_ms);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
    } else if rc != 0 {
        if let Some(err) = val.get("error").and_then(serde_json::Value::as_str) {
            eprintln!("[probe ws] {err}");
        } else {
            eprintln!(
                "[probe ws] Handshake rejected: `{}` ({})",
                val["handshake"].as_str().unwrap_or(""),
                val["headers_preview"].as_str().unwrap_or("")
            );
        }
    } else {
        let msgs = val["messages"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        println!(
            "[probe ws] CONNECTED `{url}` ({} | {}ms | close={} | {} msg(s)):",
            val["handshake"].as_str().unwrap_or(""),
            val["elapsed_ms"].as_f64().unwrap_or(0.0),
            val["close_reason"].as_str().unwrap_or("idle_timeout"),
            msgs.len()
        );
        for (i, m) in msgs.iter().enumerate() {
            println!("  {}. {}", i + 1, m.as_str().unwrap_or(""));
        }
    }
    rc
}

fn ws_handshake_one_origin(
    url: &str,
    origin: Option<&str>,
    send_msgs: &[String],
    base_headers: &[String],
    wait_ms: u64,
) -> serde_json::Value {
    let t0 = Instant::now();
    let label = origin.unwrap_or("(none)");
    let (is_tls, host_port, host_only, port, req_path) = match parse_ws_target(url) {
        Ok(v) => v,
        Err(e) => {
            return json!({
                "origin": label,
                "accepted": false,
                "status_line": "",
                "error": e,
                "elapsed_ms": 0.0,
                "messages": [],
            });
        }
    };
    let req = build_ws_upgrade_req(&host_port, &req_path, base_headers, origin);
    if is_tls {
        return match run_wss_exchange(&host_only, port, &req, send_msgs, wait_ms.clamp(80, 3000)) {
            Ok(v) => json!({
                "origin": label,
                "accepted": v["accepted"].as_bool().unwrap_or(false),
                "status_line": v["status_line"].as_str().unwrap_or(""),
                "error": "",
                "elapsed_ms": (t0.elapsed().as_secs_f64() * 1000.0).round(),
                "messages": v["messages"],
            }),
            Err(e) => json!({
                "origin": label,
                "accepted": false,
                "status_line": "",
                "error": e,
                "elapsed_ms": (t0.elapsed().as_secs_f64() * 1000.0).round(),
                "messages": [],
            }),
        };
    }

    let connect_target = ws_connect_addr_str(&host_only, port);
    let Some(sa) = connect_target
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    else {
        return json!({
            "origin": label,
            "accepted": false,
            "status_line": "",
            "error": format!("resolve failed: {connect_target}"),
            "elapsed_ms": 0.0,
            "messages": [],
        });
    };
    let mut stream = match TcpStream::connect_timeout(&sa, Duration::from_secs(3)) {
        Ok(s) => s,
        Err(e) => {
            return json!({
                "origin": label,
                "accepted": false,
                "status_line": "",
                "error": format!("connect failed: {e}"),
                "elapsed_ms": (t0.elapsed().as_secs_f64() * 1000.0).round(),
                "messages": [],
            });
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    if let Err(e) = stream.write_all(req.as_bytes()) {
        return json!({
            "origin": label,
            "accepted": false,
            "status_line": "",
            "error": format!("write failed: {e}"),
            "elapsed_ms": (t0.elapsed().as_secs_f64() * 1000.0).round(),
            "messages": [],
        });
    }

    let mut hbuf = Vec::new();
    let mut b1 = [0u8; 1];
    while hbuf.len() < 4096 {
        match stream.read(&mut b1) {
            Ok(1) => {
                hbuf.push(b1[0]);
                if hbuf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            _ => break,
        }
    }
    let htxt = String::from_utf8_lossy(&hbuf).to_string();
    let status_line = htxt.lines().next().unwrap_or("").trim().to_string();
    let accepted = status_line.contains("101");
    let mut messages = Vec::new();
    if accepted && !send_msgs.is_empty() {
        for msg in send_msgs {
            if ws_write_text_frame(&mut stream, msg).is_err() {
                break;
            }
        }
        let deadline = Instant::now() + Duration::from_millis(wait_ms.clamp(80, 3000));
        let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
        let mut frag_buf: Vec<u8> = Vec::new();
        let mut in_frag = false;
        while Instant::now() < deadline && messages.len() < 10 {
            let mut pb = [0u8; 1];
            match stream.peek(&mut pb) {
                Ok(0) => break,
                Ok(_) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
                    let fr = ws_read_one_frame(&mut stream);
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                    match fr {
                        Ok((_, 9, data)) => {
                            let _ = ws_write_pong_frame(&mut stream, &data);
                        }
                        Ok((fin, 1 | 2, data)) => {
                            if fin {
                                messages.push(
                                    String::from_utf8_lossy(&data)
                                        .chars()
                                        .take(600)
                                        .collect::<String>(),
                                );
                                frag_buf.clear();
                                in_frag = false;
                            } else {
                                frag_buf = data;
                                in_frag = true;
                            }
                        }
                        Ok((fin, 0, data)) if in_frag => {
                            if frag_buf.len().saturating_add(data.len()) > MAX_WS_FRAME_BYTES {
                                break;
                            }
                            frag_buf.extend_from_slice(&data);
                            if fin {
                                messages.push(
                                    String::from_utf8_lossy(&frag_buf)
                                        .chars()
                                        .take(600)
                                        .collect::<String>(),
                                );
                                frag_buf.clear();
                                in_frag = false;
                            }
                        }
                        Ok((_, 8, _)) | Err(_) => break,
                        _ => {}
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
    }
    json!({
        "origin": label,
        "accepted": accepted,
        "status_line": status_line,
        "error": "",
        "elapsed_ms": (t0.elapsed().as_secs_f64() * 1000.0).round(),
        "messages": messages,
    })
}

/// Probe Cross-Site WebSocket Hijacking (CSWSH) across untrusted/null/omitted/localhost Origin headers.
pub(crate) fn probe_ws_origin_matrix_result(
    url: &str,
    send_msgs: &[String],
    headers: &[String],
    custom_origins: &[String],
    wait_ms: u64,
) -> (i32, serde_json::Value) {
    let origin_specs: Vec<Option<String>> = if custom_origins.is_empty() {
        vec![
            None,
            Some("https://evil.example".to_string()),
            Some("null".to_string()),
            Some("http://localhost".to_string()),
        ]
    } else {
        custom_origins
            .iter()
            .map(|o| {
                let t = o.trim();
                if t.is_empty() || t.eq_ignore_ascii_case("none") {
                    None
                } else {
                    Some(t.to_string())
                }
            })
            .collect()
    };

    let mut rows = Vec::new();
    let mut untrusted_accepted = Vec::new();
    for spec in &origin_specs {
        let row = ws_handshake_one_origin(url, spec.as_deref(), send_msgs, headers, wait_ms);
        let acc = row["accepted"].as_bool().unwrap_or(false);
        let is_untrusted = is_untrusted_ws_origin(spec.as_deref());
        if acc && is_untrusted {
            untrusted_accepted.push(row["origin"].as_str().unwrap_or("?").to_string());
        }
        rows.push(row);
    }

    let cswsh_vulnerable = !untrusted_accepted.is_empty();
    (
        0,
        json!({
            "ok": true,
            "url": url,
            "cswsh_vulnerable": cswsh_vulnerable,
            "untrusted_accepted": untrusted_accepted,
            "results": rows,
        }),
    )
}

pub fn run_ws_origin_matrix(
    url: &str,
    send_msgs: &[String],
    headers: &[String],
    custom_origins: &[String],
    wait_ms: u64,
    as_json: bool,
) -> i32 {
    let (rc, val) = probe_ws_origin_matrix_result(url, send_msgs, headers, custom_origins, wait_ms);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
    } else {
        let cswsh_vulnerable = val["cswsh_vulnerable"].as_bool().unwrap_or(false);
        let rows = val["results"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        let badge = if cswsh_vulnerable {
            "[POSSIBLE-CSWSH]"
        } else {
            "[ORIGIN-GUARDED]"
        };
        println!(
            "[probe ws origin-matrix] `{url}` {badge} ({} origins tested):",
            rows.len()
        );
        for r in rows {
            println!(
                "  - Origin={:<24} accepted={:<5} ({}) msgs={}",
                r["origin"].as_str().unwrap_or("?"),
                r["accepted"].as_bool().unwrap_or(false),
                r["status_line"].as_str().unwrap_or(""),
                r["messages"].as_array().map(|a| a.len()).unwrap_or(0)
            );
        }
    }
    rc
}

/// Cross-platform TLS protocol & X.509 certificate inspector (uses native .NET SslStream on Windows / openssl on Unix).
pub fn run_tls_cli(addr_str: &str, sni: Option<&str>, timeout_sec: u64, as_json: bool) -> i32 {
    let t0 = Instant::now();
    let (host, port) = match addr_str.rsplit_once(':') {
        Some((h, p)) => (h.trim(), p.trim().parse::<u16>().unwrap_or(443)),
        None => (addr_str.trim(), 443),
    };
    let server_name = sni.filter(|s| !s.trim().is_empty()).unwrap_or(host);
    let _tmo = timeout_sec.clamp(1, 30);

    #[cfg(windows)]
    let info_res: Result<serde_json::Value, String> = {
        let h_esc = host.replace('\'', "''");
        let sni_esc = server_name.replace('\'', "''");
        let ms = _tmo * 1000;
        let ps_code = format!(
            "$ErrorActionPreference='Stop'; $c=New-Object System.Net.Sockets.TcpClient; $ar=$c.BeginConnect('{h_esc}',{port},$null,$null); if(-not $ar.AsyncWaitHandle.WaitOne({ms},$false)){{ throw 'TCP connect timeout' }}; $c.EndConnect($ar); $s=New-Object System.Net.Security.SslStream($c.GetStream(),$false,({{param($a,$b,$ce,$e)$true}})); $s.ReadTimeout={ms}; $s.AuthenticateAsClient('{sni_esc}'); $cert=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($s.RemoteCertificate); $sha=[BitConverter]::ToString($cert.GetCertHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)).Replace('-','').ToLower(); $out=[ordered]@{{protocol=$s.SslProtocol.ToString();subject=$cert.Subject;issuer=$cert.Issuer;not_before=$cert.NotBefore.ToUniversalTime().ToString('o');not_after=$cert.NotAfter.ToUniversalTime().ToString('o');sha256=$sha;expired=($cert.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow)}}; $s.Close(); $c.Close(); $out | ConvertTo-Json -Compress"
        );
        let out = ["pwsh.exe", "powershell.exe"].into_iter().find_map(|bin| {
            Command::new(bin)
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &ps_code,
                ])
                .output()
                .ok()
        });
        match out {
            Some(o) if o.status.success() => {
                serde_json::from_slice(&o.stdout).map_err(|e| format!("TLS JSON parse: {e}"))
            }
            Some(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
            None => Err("PowerShell unavailable".to_string()),
        }
    };

    #[cfg(not(windows))]
    let info_res: Result<serde_json::Value, String> = {
        let sh_cmd = format!(
            "echo | openssl s_client -servername '{}' -connect '{}:{}' 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256",
            server_name.replace('\'', ""),
            host.replace('\'', ""),
            port
        );
        match Command::new("sh").args(["-c", &sh_cmd]).output() {
            Ok(o) if o.status.success() && !o.stdout.is_empty() => {
                let txt = String::from_utf8_lossy(&o.stdout);
                let mut subject = String::new();
                let mut issuer = String::new();
                let mut not_before = String::new();
                let mut not_after = String::new();
                let mut sha256 = String::new();
                for ln in txt.lines() {
                    if let Some(v) = ln.strip_prefix("subject=") {
                        subject = v.trim().to_string();
                    } else if let Some(v) = ln.strip_prefix("issuer=") {
                        issuer = v.trim().to_string();
                    } else if let Some(v) = ln.strip_prefix("notBefore=") {
                        not_before = v.trim().to_string();
                    } else if let Some(v) = ln.strip_prefix("notAfter=") {
                        not_after = v.trim().to_string();
                    } else if let Some((_, v)) = ln.split_once("Fingerprint=") {
                        sha256 = v.trim().replace(':', "").to_ascii_lowercase();
                    }
                }
                Ok(json!({
                    "protocol": "TLS",
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "sha256": sha256,
                }))
            }
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
            Err(e) => Err(format!("openssl spawn error: {e}")),
        }
    };

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
    match info_res {
        Ok(val) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "target": format!("{host}:{port}"),
                        "sni": server_name,
                        "elapsed_ms": elapsed_ms,
                        "tls": val,
                    }))
                    .unwrap_or_default()
                );
            } else {
                println!("[probe tls] OK `{host}:{port}` (sni={server_name} | {elapsed_ms}ms):");
                if let Some(obj) = val.as_object() {
                    for (k, v) in obj {
                        println!("  - {k}: {}", v.to_string().trim_matches('"'));
                    }
                }
            }
            0
        }
        Err(e) => {
            eprintln!("[probe tls] FAIL `{host}:{port}` ({elapsed_ms}ms): {e}");
            1
        }
    }
}

#[cfg(test)]
mod ws_tests {
    use super::*;

    #[test]
    fn detects_cswsh_cross_origin_ws_acceptance_vs_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            for _ in 0..2 {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut buf = [0u8; 2048];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                    if req.contains("origin: https://evil.example") {
                        let _ = s.write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                        );
                    } else {
                        let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
                    }
                }
            }
        });
        let url = format!("ws://127.0.0.1:{port}/rpc");
        let evil = ws_handshake_one_origin(&url, Some("https://evil.example"), &[], &[], 200);
        let null_o = ws_handshake_one_origin(&url, Some("null"), &[], &[], 200);
        let _ = srv.join();
        assert_eq!(evil["accepted"], true);
        assert_eq!(null_o["accepted"], false);
    }

    #[test]
    fn cswsh_origin_host_parse_and_ws_ping_frag_frame_guards() {
        assert!(is_untrusted_ws_origin(Some("http://localhost.evil.com")));
        assert!(is_untrusted_ws_origin(Some(
            "https://127.0.0.1.attacker.test:8443"
        )));
        assert!(is_untrusted_ws_origin(Some("null")));
        assert!(!is_untrusted_ws_origin(Some("http://localhost:3000")));
        assert!(!is_untrusted_ws_origin(Some("https://127.0.0.1")));
        assert!(!is_untrusted_ws_origin(None));

        let (tls, hp, host, port, path) = parse_ws_target("wss://[::1]:8443/ws/chat").unwrap();
        assert!(tls);
        assert_eq!(hp, "[::1]:8443");
        assert_eq!(host, "::1");
        assert_eq!(port, 8443);
        assert_eq!(path, "/ws/chat");

        let mut oversize = vec![0x82u8, 127u8];
        oversize.extend_from_slice(&(16u64 * 1024 * 1024).to_be_bytes());
        let err = ws_read_one_frame(&mut std::io::Cursor::new(oversize)).unwrap_err();
        assert!(err.contains("too large"), "{err}");

        // Loopback WS server sends Ping then two fragmented text frames before Close
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let lport = listener.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            );
            // Send Ping("hi")
            let _ = s.write_all(&[0x89, 2, b'h', b'i']);
            // Read client text("probe") + Pong(0x8A) + send fragmented "hello " + "world"
            let (_, op1, txt_data) = ws_read_one_frame(&mut s).unwrap();
            assert_eq!(op1, 1);
            assert_eq!(txt_data, b"probe");
            let (_, op2, pong_data) = ws_read_one_frame(&mut s).unwrap();
            assert_eq!(op2, 10);
            assert_eq!(pong_data, b"hi");
            let _ = s.write_all(&[0x01, 6, b'h', b'e', b'l', b'l', b'o', b' ']);
            let _ = s.write_all(&[0x80, 5, b'w', b'o', b'r', b'l', b'd']);
            let _ = s.write_all(&[0x88, 2, 0x03, 0xE8]);
        });
        let row = ws_handshake_one_origin(
            &format!("ws://127.0.0.1:{lport}/stream"),
            Some("http://localhost:3000"),
            &["probe".to_string()],
            &[],
            800,
        );
        let _ = srv.join();
        assert_eq!(row["accepted"], true);
        let msgs = row["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0], "hello world");
    }
}
