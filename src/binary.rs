use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::time::Instant;
use zip::ZipArchive;

/// Mini-beautifier for single-line / minified JS & JSON snippets (zero dependencies).
pub fn pretty_format_js_snippet(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + raw.len() / 4);
    let mut indent: usize = 0;
    let mut in_str: Option<char> = None;
    let mut escape = false;
    let mut paren_depth: usize = 0;
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = in_str {
            out.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == q {
                in_str = None;
            }
            i += 1;
            continue;
        }
        match ch {
            '"' | '\'' | '`' => {
                in_str = Some(ch);
                out.push(ch);
            }
            '(' => {
                paren_depth += 1;
                out.push(ch);
            }
            ')' => {
                paren_depth = paren_depth.saturating_sub(1);
                out.push(ch);
            }
            '{' => {
                out.push('{');
                indent = (indent + 1).min(8);
                out.push('\n');
                out.push_str(&"  ".repeat(indent));
            }
            '}' => {
                indent = indent.saturating_sub(1);
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(&"  ".repeat(indent));
                out.push('}');
                if i + 1 < chars.len() && !matches!(chars[i + 1], ';' | ',' | ')' | '\n') {
                    out.push('\n');
                    out.push_str(&"  ".repeat(indent));
                }
            }
            ';' if paren_depth == 0 => {
                out.push(';');
                out.push('\n');
                out.push_str(&"  ".repeat(indent));
            }
            '\n' | '\r' => {
                if !out.ends_with('\n') {
                    out.push('\n');
                    out.push_str(&"  ".repeat(indent));
                }
            }
            _ => out.push(ch),
        }
        i += 1;
    }
    out.trim().to_string()
}

#[derive(Debug, Clone)]
pub struct AsarEntry {
    pub path: String,
    pub offset: usize,
    pub size: usize,
    pub unpacked: bool,
    pub hash: Option<String>,
}

fn read_u64_le(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u16_le(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_cstr(b: &[u8], off: usize, max_len: usize) -> Option<String> {
    if off >= b.len() {
        return None;
    }
    let slice = &b[off..b.len().min(off + max_len)];
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&slice[..end]).to_string())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let dig = h.finalize();
    let mut out = String::with_capacity(64);
    for b in dig {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut ent = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = (c as f64) / n;
            ent -= p * p.log2();
        }
    }
    ent
}

/// Canonical `xxd`/`hexdump -C` hex + ASCII viewer (zero external tools).
pub fn format_hex_dump(bytes: &[u8], offset: usize, len: usize) -> String {
    if offset >= bytes.len() {
        return format!("(offset 0x{offset:x} exceeds file size {} B)", bytes.len());
    }
    let end = offset.saturating_add(len.clamp(16, 4096)).min(bytes.len());
    let mut lines = Vec::new();
    let mut cur = offset;
    while cur < end {
        let row_end = (cur + 16).min(end);
        let row = &bytes[cur..row_end];
        let mut hex_part = String::with_capacity(50);
        let mut asc_part = String::with_capacity(16);
        for i in 0..16 {
            if i == 8 {
                hex_part.push(' ');
            }
            if let Some(&b) = row.get(i) {
                hex_part.push_str(&format!("{b:02x} "));
                asc_part.push(if (0x20..=0x7E).contains(&b) {
                    b as char
                } else {
                    '.'
                });
            } else {
                hex_part.push_str("   ");
            }
        }
        lines.push(format!("{cur:08x}: {hex_part} |{asc_part}|"));
        cur += 16;
    }
    lines.join("\n")
}

fn walk_asar_tree(node: &Value, prefix: &str, out: &mut Vec<AsarEntry>) {
    let Some(files) = node.get("files").and_then(Value::as_object) else {
        return;
    };
    for (name, val) in files {
        let full = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if val.get("files").is_some() {
            walk_asar_tree(val, &full, out);
        } else if let Some(sz) = val.get("size").and_then(Value::as_u64) {
            let unpacked = val
                .get("unpacked")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let off = val
                .get("offset")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(0) as usize;
            let hash = val
                .pointer("/integrity/hash")
                .and_then(Value::as_str)
                .map(str::to_string);
            out.push(AsarEntry {
                path: full,
                offset: off,
                size: sz as usize,
                unpacked,
                hash,
            });
        }
    }
}

/// Parse Electron `.asar` Chromium Pickle header from any `Read + Seek` stream -> (base_data_offset, sorted entries).
pub fn parse_asar_index_reader<R: Read + Seek>(
    r: &mut R,
) -> Result<(usize, Vec<AsarEntry>), String> {
    r.seek(SeekFrom::Start(0))
        .map_err(|e| format!("asar seek failed: {e}"))?;
    let mut hdr = [0u8; 16];
    r.read_exact(&mut hdr)
        .map_err(|_| "invalid .asar file (too short)".to_string())?;
    let header_pickle_sz = read_u32_le(&hdr, 4).ok_or("asar header truncated")? as usize;
    let json_len = read_u32_le(&hdr, 12).ok_or("asar json_len truncated")? as usize;
    if json_len == 0 || json_len > 64 * 1024 * 1024 {
        return Err("invalid .asar header JSON bounds".to_string());
    }
    let mut json_buf = vec![0u8; json_len];
    r.read_exact(&mut json_buf)
        .map_err(|_| "invalid .asar header JSON bounds".to_string())?;
    let header_json: Value =
        serde_json::from_slice(&json_buf).map_err(|e| format!("invalid .asar JSON header: {e}"))?;
    let base_offset = 8usize.saturating_add(header_pickle_sz);
    let mut entries = Vec::new();
    walk_asar_tree(&header_json, "", &mut entries);
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((base_offset, entries))
}

/// Parse Electron `.asar` Chromium Pickle header -> (base_data_offset, sorted entries).
pub fn parse_asar_index(bytes: &[u8]) -> Result<(usize, Vec<AsarEntry>), String> {
    parse_asar_index_reader(&mut Cursor::new(bytes))
}

struct ElectronFlagPatterns {
    rules: [(&'static str, &'static str, Regex); 11],
}

fn electron_flag_patterns() -> &'static ElectronFlagPatterns {
    static P: std::sync::OnceLock<ElectronFlagPatterns> = std::sync::OnceLock::new();
    P.get_or_init(|| ElectronFlagPatterns {
        rules: [
            (
                "nodeIntegration_enabled",
                "HIGH",
                Regex::new(r#"\bnodeIntegration\s*:\s*(?:true|!0)\b"#).unwrap(),
            ),
            (
                "contextIsolation_disabled",
                "HIGH",
                Regex::new(r#"\bcontextIsolation\s*:\s*(?:false|!1)\b"#).unwrap(),
            ),
            (
                "sandbox_disabled",
                "MEDIUM",
                Regex::new(r#"\bsandbox\s*:\s*(?:false|!1)\b"#).unwrap(),
            ),
            (
                "webSecurity_disabled",
                "HIGH",
                Regex::new(r#"\bwebSecurity\s*:\s*(?:false|!1)\b"#).unwrap(),
            ),
            (
                "allowRunningInsecureContent",
                "HIGH",
                Regex::new(r#"\ballowRunningInsecureContent\s*:\s*(?:true|!0)\b"#).unwrap(),
            ),
            (
                "enableRemoteModule_enabled",
                "HIGH",
                Regex::new(r#"\benableRemoteModule\s*:\s*(?:true|!0)\b"#).unwrap(),
            ),
            (
                "webviewTag_enabled",
                "MEDIUM",
                Regex::new(r#"\bwebviewTag\s*:\s*(?:true|!0)\b"#).unwrap(),
            ),
            (
                "protocol_handler",
                "MEDIUM",
                Regex::new(
                    r#"(?:\bsetAsDefaultProtocolClient\s*\(|\bprotocol\.register[A-Za-z]*\s*\()"#,
                )
                .unwrap(),
            ),
            (
                "ipc_handler",
                "MEDIUM",
                Regex::new(
                    r#"(?:\b(?:ipcMain|ipcRenderer)\.(?:handle|on|once|handleOnce|invoke)\s*\(|\b[A-Za-z_$][A-Za-z0-9_$]{0,16}\.(?:handle|handleOnce)\(\s*["'`][A-Za-z0-9_.:/-]{2,80}["'`]\s*,)"#,
                )
                .unwrap(),
            ),
            (
                "contextBridge_expose",
                "MEDIUM",
                Regex::new(r#"(?:\bcontextBridge|["']electron["']).*?\.exposeInMainWorld\s*\(|\bcontextBridge\.exposeInMainWorld\s*\("#).unwrap(),
            ),
            (
                "shell_openExternal",
                "MEDIUM",
                Regex::new(r#"(?:\bshell\.open(?:External|Path)|\.openExternal)\s*\("#).unwrap(),
            ),
        ],
    })
}

fn archive_entry_priority(path_low: &str) -> Option<(u8, bool)> {
    if path_low.ends_with(".d.ts") {
        return None;
    }
    let is_code = [
        ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".htm",
    ]
    .iter()
    .any(|ext| path_low.ends_with(ext));
    if !is_code {
        return None;
    }
    let in_nm = path_low.starts_with("node_modules/") || path_low.contains("/node_modules/");
    let high_sig = [
        "main",
        "preload",
        "ipc",
        "bridge",
        "protocol",
        "electron",
        "background",
        "extension",
        "server",
        "router",
        "auth",
        "window",
        "app",
    ]
    .iter()
    .any(|kw| path_low.contains(kw));
    let tier = match (in_nm, high_sig) {
        (false, true) => 0,
        (false, false) => 1,
        (true, true) => 2,
        (true, false) => 3,
    };
    Some((tier, in_nm))
}

fn inspect_archive_manifest(
    path: &str,
    text: &str,
    manifests: &mut Vec<Value>,
    manifest_risks: &mut Vec<Value>,
) {
    let low = path.to_ascii_lowercase();
    if low.ends_with("package.json") && !low.contains("node_modules/") {
        if let Ok(v) = serde_json::from_str::<Value>(text) {
            let name = v["name"].as_str().unwrap_or("");
            let version = v["version"].as_str().unwrap_or("");
            let main_entry = v["main"].as_str().unwrap_or("");
            let mut script_keys: Vec<String> = Vec::new();
            if let Some(sc) = v["scripts"].as_object() {
                for k in sc.keys() {
                    script_keys.push(k.clone());
                    if matches!(k.as_str(), "postinstall" | "preinstall" | "install") {
                        manifest_risks.push(json!({
                            "kind": "lifecycle_install_script",
                            "severity": "HIGH",
                            "entry_path": path,
                            "detail": format!("script `{k}`: {}", sc[k].as_str().unwrap_or("").chars().take(120).collect::<String>()),
                        }));
                    }
                }
            }
            if v.pointer("/capabilities/untrustedWorkspaces/supported")
                .is_some()
            {
                let sup = &v["capabilities"]["untrustedWorkspaces"]["supported"];
                if sup.as_bool() == Some(true) {
                    manifest_risks.push(json!({
                        "kind": "untrusted_workspaces_enabled",
                        "severity": "MEDIUM",
                        "entry_path": path,
                        "detail": "capabilities.untrustedWorkspaces.supported = true",
                    }));
                }
            }
            if let Some(cfg) = v.pointer("/contributes/configuration") {
                let has_unrestricted = cfg
                    .pointer("/properties")
                    .and_then(Value::as_object)
                    .is_some_and(|props| {
                        props.values().any(|p| {
                            p["scope"].as_str() != Some("application")
                                && p["scope"].as_str() != Some("machine")
                        })
                    });
                if has_unrestricted {
                    manifest_risks.push(json!({
                        "kind": "workspace_overridable_setting",
                        "severity": "MEDIUM",
                        "entry_path": path,
                        "detail": "contributes.configuration contains non-machine-scoped settings",
                    }));
                }
            }
            let mut protocol_schemes: Vec<String> = Vec::new();
            let push_schemes = |arr: Option<&Vec<Value>>, dst: &mut Vec<String>| {
                if let Some(items) = arr {
                    for it in items {
                        if let Some(schemes) = it.get("schemes").and_then(Value::as_array) {
                            for s in schemes.iter().filter_map(Value::as_str) {
                                let clean = s.trim().to_string();
                                if !clean.is_empty() && !dst.contains(&clean) {
                                    dst.push(clean);
                                }
                            }
                        } else if let Some(s) = it.as_str() {
                            let clean = s.trim().to_string();
                            if !clean.is_empty() && !dst.contains(&clean) {
                                dst.push(clean);
                            }
                        }
                    }
                }
            };
            push_schemes(
                v.get("protocols").and_then(Value::as_array),
                &mut protocol_schemes,
            );
            push_schemes(
                v.pointer("/build/protocols").and_then(Value::as_array),
                &mut protocol_schemes,
            );
            if !protocol_schemes.is_empty() {
                manifest_risks.push(json!({
                    "kind": "custom_protocol_schemes",
                    "severity": "MEDIUM",
                    "entry_path": path,
                    "detail": format!("registered protocol schemes: {}", protocol_schemes.join(", ")),
                }));
            }
            manifests.push(json!({
                "entry_path": path,
                "kind": "package.json",
                "name": name,
                "version": version,
                "main": main_entry,
                "scripts": script_keys,
                "protocols": protocol_schemes,
            }));
        }
    } else if low.ends_with("manifest.mf")
        || low.ends_with("extension.vsixmanifest")
        || low.ends_with("plugin.xml")
        || low.ends_with("manifest.json")
    {
        let preview: String = text
            .lines()
            .take(12)
            .collect::<Vec<_>>()
            .join(" | ")
            .chars()
            .take(240)
            .collect();
        manifests.push(json!({
            "entry_path": path,
            "kind": path.rsplit('/').next().unwrap_or(path),
            "preview": preview,
        }));
    }
}

fn extract_first_quoted_arg(snip: &str) -> Option<String> {
    let open_paren = snip.find('(')?;
    let rest = snip[open_paren + 1..].trim_start();
    let q = rest.chars().next()?;
    if q != '\'' && q != '"' && q != '`' {
        return None;
    }
    let body = &rest[q.len_utf8()..];
    let end = body.find(q)?;
    let tok = body[..end].trim();
    if tok.is_empty() || tok.len() > 120 {
        None
    } else {
        Some(tok.to_string())
    }
}

fn collect_unpacked_sibling_bins(disk_path: Option<&std::path::Path>) -> Vec<Value> {
    let Some(p) = disk_path else {
        return Vec::new();
    };
    let unpacked_dir = std::path::PathBuf::from(format!("{}.unpacked", p.display()));
    if !unpacked_dir.is_dir() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let walker = ignore::WalkBuilder::new(&unpacked_dir)
        .hidden(false)
        .git_ignore(false)
        .build();
    for ent in walker.flatten() {
        if !ent.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let ep = ent.path();
        let low = ep.to_string_lossy().to_ascii_lowercase();
        if [".node", ".exe", ".dll", ".so", ".dylib", ".wasm"]
            .iter()
            .any(|x| low.ends_with(x))
        {
            let rel = ep
                .strip_prefix(&unpacked_dir)
                .unwrap_or(ep)
                .to_string_lossy()
                .replace('\\', "/");
            let sz = ent.metadata().map(|m| m.len()).unwrap_or(0);
            out.push(json!({
                "path": rel,
                "size": sz,
                "unpacked": true,
                "on_disk_unpacked": true,
            }));
            if out.len() >= 60 {
                break;
            }
        }
    }
    out
}

/// Zero-unpack in-memory / seek-streamed archive surface scanner for `.asar`, `.zip`, `.vsix`, `.jar`, `.apk`, `.whl`.
pub fn inspect_archive_surface_reader<R: Read + Seek>(
    r: &mut R,
    ext: &str,
    label: &str,
    include_routes: bool,
    query: Option<&str>,
) -> Result<(String, Value), String> {
    inspect_archive_surface_reader_opts(r, ext, label, None, include_routes, query, false)
}

/// Compact Electron `.asar` security surface extractor (`--asar-surface`), checking `<target>.unpacked`
/// on disk, minified `!0`/`!1` flags, up to 64 IPC channels/entry, and dangerous exec/shell/eval/FS sinks.
pub fn inspect_asar_surface_compact_reader<R: Read + Seek>(
    r: &mut R,
    ext: &str,
    label: &str,
    disk_path: Option<&std::path::Path>,
    include_routes: bool,
    query: Option<&str>,
) -> Result<(String, Value), String> {
    inspect_archive_surface_reader_opts(r, ext, label, disk_path, include_routes, query, true)
}

fn inspect_archive_surface_reader_opts<R: Read + Seek>(
    r: &mut R,
    ext: &str,
    label: &str,
    disk_path: Option<&std::path::Path>,
    include_routes: bool,
    query: Option<&str>,
    compact_asar_surface: bool,
) -> Result<(String, Value), String> {
    let t0 = Instant::now();
    let ext_low = ext.to_ascii_lowercase();
    let q_low = query
        .map(|q| q.trim().to_ascii_lowercase())
        .filter(|q| !q.is_empty());

    struct CandidateEntry {
        path: String,
        tier: u8,
        offset: usize,
        size: usize,
        zip_index: usize,
    }

    let total_entries;
    let mut unpacked_count = 0usize;
    let mut asar_base = 0usize;
    let mut native_bins: Vec<Value> = Vec::new();
    let mut manifest_targets: Vec<(String, usize, usize, usize)> = Vec::new();
    let mut code_targets: Vec<CandidateEntry> = Vec::new();

    if ext_low == "asar" {
        let (base, entries) = parse_asar_index_reader(r)?;
        asar_base = base;
        total_entries = entries.len();
        for e in entries {
            if e.unpacked {
                unpacked_count += 1;
            }
            let pl = e.path.to_ascii_lowercase();
            if [".exe", ".dll", ".so", ".dylib", ".node", ".wasm"]
                .iter()
                .any(|x| pl.ends_with(x))
            {
                if native_bins.len() < 60 {
                    native_bins.push(json!({
                        "path": e.path,
                        "size": e.size,
                        "unpacked": e.unpacked,
                    }));
                }
                continue;
            }
            if e.unpacked {
                continue;
            }
            if (pl.ends_with("package.json")
                || pl.ends_with("manifest.mf")
                || pl.ends_with("extension.vsixmanifest")
                || pl.ends_with("plugin.xml")
                || pl.ends_with("manifest.json"))
                && !pl.contains("node_modules/")
                && e.size <= 256 * 1024
                && manifest_targets.len() < 20
            {
                manifest_targets.push((e.path, e.offset, e.size, 0));
                continue;
            }
            if e.size > 4 * 1024 * 1024 || e.size == 0 {
                continue;
            }
            if let Some((tier, in_nm)) = archive_entry_priority(&pl) {
                if in_nm && !q_low.as_ref().is_some_and(|q| pl.contains(q)) {
                    continue;
                }
                code_targets.push(CandidateEntry {
                    path: e.path,
                    tier,
                    offset: e.offset,
                    size: e.size,
                    zip_index: 0,
                });
            }
        }
    } else {
        let mut za = ZipArchive::new(&mut *r).map_err(|e| format!("zip error: {e}"))?;
        total_entries = za.len();
        for idx in 0..za.len() {
            let Ok(f) = za.by_index(idx) else {
                continue;
            };
            if f.is_dir() {
                continue;
            }
            let path = f.name().replace('\\', "/");
            let sz = f.size() as usize;
            let pl = path.to_ascii_lowercase();
            if [".exe", ".dll", ".so", ".dylib", ".node", ".wasm"]
                .iter()
                .any(|x| pl.ends_with(x))
            {
                if native_bins.len() < 60 {
                    native_bins.push(json!({
                        "path": path,
                        "size": sz,
                        "unpacked": false,
                    }));
                }
                continue;
            }
            if (pl.ends_with("package.json")
                || pl.ends_with("meta-inf/manifest.mf")
                || pl.ends_with("extension.vsixmanifest")
                || pl.ends_with("plugin.xml")
                || pl.ends_with("manifest.json"))
                && !pl.contains("node_modules/")
                && sz <= 256 * 1024
                && manifest_targets.len() < 20
            {
                manifest_targets.push((path, 0, sz, idx));
                continue;
            }
            if sz > 4 * 1024 * 1024 || sz == 0 {
                continue;
            }
            if let Some((tier, in_nm)) = archive_entry_priority(&pl) {
                if in_nm && !q_low.as_ref().is_some_and(|q| pl.contains(q)) {
                    continue;
                }
                code_targets.push(CandidateEntry {
                    path,
                    tier,
                    offset: 0,
                    size: sz,
                    zip_index: idx,
                });
            }
        }
    }

    code_targets.sort_by(|a, b| a.tier.cmp(&b.tier).then_with(|| a.path.cmp(&b.path)));
    let selected_code: Vec<CandidateEntry> = code_targets.into_iter().take(150).collect();

    let mut manifests: Vec<Value> = Vec::new();
    let mut manifest_risks: Vec<Value> = Vec::new();
    let mut electron_flags: Vec<Value> = Vec::new();
    let mut ipc_handlers: Vec<Value> = Vec::new();
    let mut seen_ipc_chans: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    let mut dangerous_sinks: Vec<Value> = Vec::new();
    let mut seen_sinks: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    let mut js_acc = crate::inspect::JsSurfaceData::default();
    let mut scanned_js_entries = 0usize;
    let snip_cap = if compact_asar_surface { 96 } else { 140 };
    let ipc_cap = if compact_asar_surface { 120 } else { 40 };

    static SINK_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let sink_re = SINK_RE.get_or_init(|| {
        Regex::new(r#"(?:\bchild_process\b|(?:\b|\.)(?:execFile|execFileSync|spawn|spawnSync|execSync)\s*\(|\.(?:exec|openExternal|openPath)\s*\(|\bvm\.runIn[A-Za-z]*\s*\(|\beval\s*\(|\bnew\s+Function\s*\(|\bfs\.(?:writeFile|writeFileSync|chmod|chmodSync)\s*\()"#).unwrap()
    });

    let read_entry_text = |stream: &mut R, off: usize, sz: usize| -> Option<String> {
        let pos = (asar_base as u64).checked_add(off as u64)?;
        stream.seek(SeekFrom::Start(pos)).ok()?;
        let mut buf = vec![0u8; sz];
        stream.read_exact(&mut buf).ok()?;
        Some(String::from_utf8_lossy(&buf).into_owned())
    };

    let mut process_code = |path: &str, text: &str| {
        scanned_js_entries += 1;
        let has_electron_ctx = text.contains("electron")
            || text.contains("ipcMain")
            || text.contains("ipcRenderer")
            || path.to_ascii_lowercase().contains("ipc");
        let pats = electron_flag_patterns();
        for (kind, default_sev, re) in &pats.rules {
            let match_take = if matches!(*kind, "ipc_handler" | "contextBridge_expose") {
                64
            } else {
                12
            };
            for m in re.find_iter(text).take(match_take) {
                if *kind == "ipc_handler" && !has_electron_ctx && !m.as_str().contains("ipc") {
                    continue;
                }
                let ln = text[..m.start()].bytes().filter(|&b| b == b'\n').count() + 1;
                let mut w_end = (m.end() + 140).min(text.len());
                while w_end > m.end() && !text.is_char_boundary(w_end) {
                    w_end -= 1;
                }
                let mut w_start = m.start().saturating_sub(24);
                while w_start < m.start() && !text.is_char_boundary(w_start) {
                    w_start += 1;
                }
                let raw_snip: String = text[w_start..w_end].replace(['\r', '\n'], " ");
                let snip: String = raw_snip.chars().take(snip_cap).collect();
                if let Some(ref q) = q_low {
                    if !snip.to_ascii_lowercase().contains(q)
                        && !path.to_ascii_lowercase().contains(q)
                        && !kind.to_ascii_lowercase().contains(q)
                    {
                        continue;
                    }
                }
                let sev = if *kind == "contextBridge_expose"
                    && (raw_snip.contains("ipcRenderer.send")
                        || raw_snip.contains("ipcRenderer.invoke")
                        || raw_snip.contains("ipcRenderer.on"))
                {
                    "HIGH"
                } else {
                    *default_sev
                };
                if *kind == "ipc_handler" {
                    let chan = extract_first_quoted_arg(
                        &raw_snip[(m.start() - w_start).min(raw_snip.len())..],
                    )
                    .unwrap_or_default();
                    let dedup_k = (
                        path.to_string(),
                        if chan.is_empty() {
                            format!("L{ln}")
                        } else {
                            chan.clone()
                        },
                    );
                    if seen_ipc_chans.insert(dedup_k) && ipc_handlers.len() < ipc_cap {
                        let mut item = json!({
                            "entry_path": path,
                            "line": ln,
                            "snippet": snip,
                        });
                        if !chan.is_empty() {
                            item["channel"] = json!(chan);
                        }
                        ipc_handlers.push(item);
                    }
                } else if electron_flags.len() < 60 {
                    let mut item = json!({
                        "kind": kind,
                        "severity": sev,
                        "entry_path": path,
                        "line": ln,
                        "snippet": snip,
                    });
                    if *kind == "contextBridge_expose" {
                        if let Some(api_nm) = extract_first_quoted_arg(
                            &raw_snip[(m.start() - w_start).min(raw_snip.len())..],
                        ) {
                            item["api_name"] = json!(api_nm);
                        }
                    }
                    electron_flags.push(item);
                }
            }
        }
        for sm in sink_re.find_iter(text).take(32) {
            if dangerous_sinks.len() >= 40 {
                break;
            }
            let sink_tok = sm.as_str().trim_end_matches('(').trim().to_string();
            if seen_sinks.insert((path.to_string(), sink_tok.clone())) {
                let ln = text[..sm.start()].bytes().filter(|&b| b == b'\n').count() + 1;
                let mut ws = sm.start().saturating_sub(20);
                while ws < sm.start() && !text.is_char_boundary(ws) {
                    ws += 1;
                }
                let mut we = (sm.end() + 72).min(text.len());
                while we > sm.end() && !text.is_char_boundary(we) {
                    we -= 1;
                }
                let sn: String = text[ws..we]
                    .replace(['\r', '\n'], " ")
                    .chars()
                    .take(snip_cap)
                    .collect();
                if let Some(ref q) = q_low {
                    if !sn.to_ascii_lowercase().contains(q)
                        && !path.to_ascii_lowercase().contains(q)
                    {
                        continue;
                    }
                }
                dangerous_sinks.push(json!({
                    "sink": sink_tok,
                    "entry_path": path,
                    "line": ln,
                    "snippet": sn,
                }));
            }
        }
        crate::inspect::collect_js_surface_into(text, Some(path), query, &mut js_acc);
    };

    if ext_low == "asar" {
        for (mpath, moff, msz, _) in &manifest_targets {
            if let Some(txt) = read_entry_text(r, *moff, *msz) {
                inspect_archive_manifest(mpath, &txt, &mut manifests, &mut manifest_risks);
            }
        }
        for c in &selected_code {
            if let Some(txt) = read_entry_text(r, c.offset, c.size) {
                process_code(&c.path, &txt);
            }
        }
    } else {
        let mut za = ZipArchive::new(&mut *r).map_err(|e| format!("zip error: {e}"))?;
        for (mpath, _, msz, zidx) in &manifest_targets {
            if let Ok(f) = za.by_index(*zidx) {
                let mut buf = Vec::with_capacity((*msz).min(256 * 1024));
                let _ = f.take(256 * 1024).read_to_end(&mut buf);
                let txt = String::from_utf8_lossy(&buf);
                inspect_archive_manifest(mpath, &txt, &mut manifests, &mut manifest_risks);
            }
        }
        for c in &selected_code {
            if let Ok(f) = za.by_index(c.zip_index) {
                let mut buf = Vec::with_capacity(c.size.min(4 * 1024 * 1024));
                let _ = f.take(4 * 1024 * 1024).read_to_end(&mut buf);
                let txt = String::from_utf8_lossy(&buf);
                process_code(&c.path, &txt);
            }
        }
    }

    let (_, js_surface_json) = crate::inspect::render_js_surface(js_acc, label, None);
    let has_js_hits = include_routes
        || js_surface_json["counts"]["routes"].as_u64().unwrap_or(0) > 0
        || js_surface_json["counts"]["graphql"].as_u64().unwrap_or(0) > 0
        || js_surface_json["counts"]["ws_sse"].as_u64().unwrap_or(0) > 0
        || js_surface_json["counts"]["post_message"]
            .as_u64()
            .unwrap_or(0)
            > 0
        || js_surface_json["counts"]["local_server_ipc"]
            .as_u64()
            .unwrap_or(0)
            > 0;

    let disk_unpacked_bins = collect_unpacked_sibling_bins(disk_path);
    if !disk_unpacked_bins.is_empty() {
        for ub in disk_unpacked_bins {
            let p_str = ub["path"].as_str().unwrap_or("");
            if !native_bins
                .iter()
                .any(|x| x["path"].as_str().unwrap_or("") == p_str)
                && native_bins.len() < 80
            {
                native_bins.push(ub);
            }
        }
    }

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
    let mut md = vec![format!(
        "# ARCHIVE SURFACE `{label}` ({ext_low} | entries={total_entries}, scanned_js={scanned_js_entries}, native_bins={}, electron_flags={}, ipc_handlers={}, dangerous_sinks={}, manifest_risks={} in {elapsed_ms}ms)",
        native_bins.len(),
        electron_flags.len(),
        ipc_handlers.len(),
        dangerous_sinks.len(),
        manifest_risks.len(),
    )];
    if !electron_flags.is_empty() {
        md.push("\n## Electron / Bridge Security Posture".to_string());
        for fl in electron_flags.iter().take(25) {
            md.push(format!(
                "- [{}] `{}` (`{}:L{}`): `{}`",
                fl["severity"].as_str().unwrap_or(""),
                fl["kind"].as_str().unwrap_or(""),
                fl["entry_path"].as_str().unwrap_or(""),
                fl["line"].as_u64().unwrap_or(0),
                fl["snippet"].as_str().unwrap_or(""),
            ));
        }
    }
    if !manifest_risks.is_empty() {
        md.push("\n## Manifest & Extension Risks".to_string());
        for mr in manifest_risks.iter().take(15) {
            md.push(format!(
                "- [{}] `{}` (`{}`): {}",
                mr["severity"].as_str().unwrap_or(""),
                mr["kind"].as_str().unwrap_or(""),
                mr["entry_path"].as_str().unwrap_or(""),
                mr["detail"].as_str().unwrap_or(""),
            ));
        }
    }
    if !ipc_handlers.is_empty() {
        md.push(format!("\n## IPC Handlers ({})", ipc_handlers.len()));
        for h in ipc_handlers.iter().take(25) {
            let ch = h.get("channel").and_then(Value::as_str).unwrap_or("");
            let ch_s = if ch.is_empty() {
                String::new()
            } else {
                format!(" `{ch}`")
            };
            md.push(format!(
                "- `{}:L{}`{ch_s}: `{}`",
                h["entry_path"].as_str().unwrap_or(""),
                h["line"].as_u64().unwrap_or(0),
                h["snippet"].as_str().unwrap_or(""),
            ));
        }
    }
    if !dangerous_sinks.is_empty() {
        md.push(format!("\n## Dangerous Sinks ({})", dangerous_sinks.len()));
        for sk in dangerous_sinks.iter().take(20) {
            md.push(format!(
                "- `{}` (`{}:L{}`): `{}`",
                sk["sink"].as_str().unwrap_or(""),
                sk["entry_path"].as_str().unwrap_or(""),
                sk["line"].as_u64().unwrap_or(0),
                sk["snippet"].as_str().unwrap_or(""),
            ));
        }
    }
    if !native_bins.is_empty() {
        let nb: Vec<String> = native_bins
            .iter()
            .take(20)
            .map(|b| {
                format!(
                    "`{}` ({}B{})",
                    b["path"].as_str().unwrap_or(""),
                    b["size"].as_u64().unwrap_or(0),
                    if b["unpacked"].as_bool().unwrap_or(false) {
                        ", unpacked"
                    } else {
                        ""
                    }
                )
            })
            .collect();
        md.push(format!(
            "\n## Native Binaries Inside Archive ({})\n{}",
            native_bins.len(),
            nb.join(", ")
        ));
    }
    if has_js_hits {
        md.push(format!(
            "\n## Contained JS/API Surface (routes={}, graphql={}, ws_sse={}, race={}, flow={})",
            js_surface_json["counts"]["routes"].as_u64().unwrap_or(0),
            js_surface_json["counts"]["graphql"].as_u64().unwrap_or(0),
            js_surface_json["counts"]["ws_sse"].as_u64().unwrap_or(0),
            js_surface_json["counts"]["race_candidates"]
                .as_u64()
                .unwrap_or(0),
            js_surface_json["counts"]["flow_candidates"]
                .as_u64()
                .unwrap_or(0),
        ));
    }

    let mut jv = json!({
        "ok": true,
        "format": if compact_asar_surface { "asar-surface" } else { "archive-surface" },
        "archive_kind": ext_low,
        "target": label,
        "elapsed_ms": elapsed_ms,
        "entry_counts": {
            "total": total_entries,
            "unpacked": unpacked_count,
            "scanned_js": scanned_js_entries,
            "native_bins": native_bins.len(),
        },
        "manifests": manifests,
        "manifest_risks": manifest_risks,
        "native_bins": if compact_asar_surface { native_bins.iter().take(20).cloned().collect() } else { native_bins },
        "electron_security_flags": if compact_asar_surface { electron_flags.iter().take(25).cloned().collect() } else { electron_flags },
        "ipc_handlers": if compact_asar_surface { ipc_handlers.iter().take(40).cloned().collect() } else { ipc_handlers },
        "dangerous_sinks": if compact_asar_surface { dangerous_sinks.iter().take(20).cloned().collect() } else { dangerous_sinks },
    });
    if compact_asar_surface {
        let mut compact_routes: Vec<Value> = Vec::new();
        if let Some(arr) = js_surface_json.get("routes").and_then(Value::as_array) {
            for r in arr.iter().take(12) {
                compact_routes.push(json!({
                    "method": r["method"],
                    "path": r["path"],
                    "risk_score": r["risk_score"],
                }));
            }
        }
        jv["js_surface_summary"] = json!({
            "counts": js_surface_json["counts"],
            "top_routes": compact_routes,
        });
    } else if has_js_hits {
        jv["js_surface"] = js_surface_json;
    }
    Ok((md.join("\n"), jv))
}

pub fn inspect_archive_surface(
    bytes: &[u8],
    ext: &str,
    label: &str,
    include_routes: bool,
    query: Option<&str>,
) -> Result<(String, Value), String> {
    inspect_archive_surface_reader(&mut Cursor::new(bytes), ext, label, include_routes, query)
}

pub fn read_asar_member(bytes: &[u8], entry_path: &str) -> Result<Vec<u8>, String> {
    let (base, entries) = parse_asar_index(bytes)?;
    let norm = entry_path
        .trim()
        .replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string();
    let suffix = format!("/{norm}");
    let hit = entries
        .iter()
        .find(|e| e.path.eq_ignore_ascii_case(&norm))
        .or_else(|| {
            entries.iter().find(|e| {
                let p = e.path.to_ascii_lowercase();
                p.ends_with(&suffix.to_ascii_lowercase())
            })
        })
        .ok_or_else(|| {
            let needle = norm.to_ascii_lowercase();
            let base_name = needle.rsplit('/').next().unwrap_or(&needle);
            let hints: Vec<&str> = entries
                .iter()
                .filter(|e| {
                    let pl = e.path.to_ascii_lowercase();
                    pl.contains(&needle) || (!base_name.is_empty() && pl.contains(base_name))
                })
                .take(8)
                .map(|e| e.path.as_str())
                .collect();
            if hints.is_empty() {
                format!(
                    "entry `{entry_path}` not found in .asar ({} total entries)",
                    entries.len()
                )
            } else {
                format!(
                    "entry `{entry_path}` not found in .asar; closest matches: {}",
                    hints.join(", ")
                )
            }
        })?;
    if hit.unpacked {
        return Err(format!(
            "entry `{}` is marked unpacked (lives in app.asar.unpacked)",
            hit.path
        ));
    }
    let start = base.saturating_add(hit.offset);
    let end = start.saturating_add(hit.size);
    if end > bytes.len() {
        return Err(format!("entry `{}` offset out of bounds", hit.path));
    }
    Ok(bytes[start..end].to_vec())
}

pub fn list_asar_md(bytes: &[u8], query: Option<&str>) -> Result<String, String> {
    let (_, entries) = parse_asar_index(bytes)?;
    let q_low = query.map(|q| q.to_ascii_lowercase());
    let mut lines = vec![format!(
        "## Electron ASAR Archive ({} files — pass `--entry <path>` to read without extracting)",
        entries.len()
    )];
    let mut shown = 0usize;
    for e in &entries {
        if let Some(ref q) = q_low {
            if !e.path.to_ascii_lowercase().contains(q) {
                continue;
            }
        }
        let tag = if e.unpacked { " [unpacked]" } else { "" };
        lines.push(format!("- `{}` ({} B){tag}", e.path, e.size));
        shown += 1;
        if shown >= 200 {
            lines.push(format!(
                "... ({} more entries; narrow with `--query <substr>`)",
                entries.len().saturating_sub(shown)
            ));
            break;
        }
    }
    Ok(lines.join("\n"))
}

pub fn read_zip_member(bytes: &[u8], entry_path: &str) -> Result<Vec<u8>, String> {
    let mut za = ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("zip error: {e}"))?;
    let norm = entry_path
        .trim()
        .replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string();
    let suffix_low = format!("/{}", norm.to_ascii_lowercase());
    let mut exact_name: Option<String> = None;
    let mut suffix_name: Option<String> = None;
    let mut all_names: Vec<String> = Vec::new();
    for i in 0..za.len() {
        if let Ok(f) = za.by_index(i) {
            let orig = f.name().to_string();
            let nm = orig.replace('\\', "/");
            if nm.eq_ignore_ascii_case(&norm) {
                exact_name = Some(orig);
                break;
            }
            if suffix_name.is_none() && nm.to_ascii_lowercase().ends_with(&suffix_low) {
                suffix_name = Some(orig.clone());
            }
            if all_names.len() < 4000 {
                all_names.push(nm);
            }
        }
    }
    let Some(name) = exact_name.or(suffix_name) else {
        let needle = norm.to_ascii_lowercase();
        let base_name = needle.rsplit('/').next().unwrap_or(&needle);
        let hints: Vec<&str> = all_names
            .iter()
            .filter(|n| {
                let nl = n.to_ascii_lowercase();
                nl.contains(&needle) || (!base_name.is_empty() && nl.contains(base_name))
            })
            .take(8)
            .map(String::as_str)
            .collect();
        if hints.is_empty() {
            return Err(format!("entry `{entry_path}` not found in archive"));
        }
        return Err(format!(
            "entry `{entry_path}` not found in archive; closest matches: {}",
            hints.join(", ")
        ));
    };
    let f = za.by_name(&name).map_err(|e| format!("zip entry: {e}"))?;
    let mut buf = Vec::new();
    let _ = f.take(16 * 1024 * 1024).read_to_end(&mut buf);
    Ok(buf)
}

fn read_u16_be(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

pub fn is_java_class_magic(bytes: &[u8]) -> bool {
    if bytes.len() < 12 || &bytes[0..4] != b"\xCA\xFE\xBA\xBE" {
        return false;
    }
    // Distinguish Java .class (major >= 45) from macOS Mach-O universal fat binary (nfat_arch is small, typically 1..16)
    let major = read_u16_be(bytes, 6).unwrap_or(0);
    (45..=100).contains(&major)
}

/// Pure-Rust JVM `.class` Constant Pool, Methods & Dangerous Sink Analyzer (zero `javap`/JDK required).
pub fn parse_java_class_md(bytes: &[u8], query: Option<&str>) -> String {
    if !is_java_class_magic(bytes) {
        return "*(not a valid Java .class file)*".to_string();
    }
    let minor = read_u16_be(bytes, 4).unwrap_or(0);
    let major = read_u16_be(bytes, 6).unwrap_or(0);
    let cp_count = read_u16_be(bytes, 8).unwrap_or(0) as usize;
    let mut pos = 10usize;
    let mut utf8s: Vec<Option<String>> = vec![None; cp_count];
    let mut classes: Vec<Option<u16>> = vec![None; cp_count];
    let mut strings: Vec<u16> = Vec::new();
    let mut member_refs: Vec<(u16, u16)> = Vec::new();
    let mut name_and_types: Vec<Option<(u16, u16)>> = vec![None; cp_count];

    let mut idx = 1usize;
    while idx < cp_count && pos < bytes.len() {
        let tag = bytes[pos];
        pos += 1;
        match tag {
            1 => {
                // CONSTANT_Utf8
                let Some(len) = read_u16_be(bytes, pos).map(|v| v as usize) else {
                    break;
                };
                pos += 2;
                if pos + len > bytes.len() {
                    break;
                }
                utf8s[idx] = Some(String::from_utf8_lossy(&bytes[pos..pos + len]).to_string());
                pos += len;
            }
            3 | 4 => pos += 4, // Integer / Float
            5 | 6 => {
                // Long / Double occupy 2 CP slots
                pos += 8;
                idx += 1;
            }
            7 => {
                // Class
                classes[idx] = read_u16_be(bytes, pos);
                pos += 2;
            }
            8 => {
                // String
                if let Some(si) = read_u16_be(bytes, pos) {
                    strings.push(si);
                }
                pos += 2;
            }
            9..=11 => {
                // Fieldref / Methodref / InterfaceMethodref
                if let (Some(ci), Some(nti)) =
                    (read_u16_be(bytes, pos), read_u16_be(bytes, pos + 2))
                {
                    member_refs.push((ci, nti));
                }
                pos += 4;
            }
            12 => {
                // NameAndType
                if let (Some(ni), Some(di)) = (read_u16_be(bytes, pos), read_u16_be(bytes, pos + 2))
                {
                    name_and_types[idx] = Some((ni, di));
                }
                pos += 4;
            }
            15 => pos += 3,           // MethodHandle
            16 | 19 | 20 => pos += 2, // MethodType / Module / Package
            17 | 18 => pos += 4,      // Dynamic / InvokeDynamic
            _ => break,
        }
        idx += 1;
    }

    let resolve_utf8 = |i: u16| -> String {
        utf8s
            .get(i as usize)
            .and_then(|o| o.as_deref())
            .unwrap_or("")
            .to_string()
    };
    let resolve_class = |i: u16| -> String {
        classes
            .get(i as usize)
            .and_then(|o| *o)
            .map(resolve_utf8)
            .unwrap_or_default()
    };

    let this_cls = read_u16_be(bytes, pos + 2)
        .map(resolve_class)
        .unwrap_or_default();
    let super_cls = read_u16_be(bytes, pos + 4)
        .map(resolve_class)
        .unwrap_or_default();

    let mut calls = Vec::new();
    let mut notable = Vec::new();
    const DANGER_JVM: [&str; 18] = [
        "Runtime.exec",
        "ProcessBuilder",
        "ObjectInputStream",
        "readObject",
        "XMLDecoder",
        "InitialContext",
        "lookup",
        "Class.forName",
        "ScriptEngine",
        "Method.invoke",
        "DriverManager",
        "URLClassLoader",
        "DocumentBuilderFactory",
        "XStream",
        "Files.write",
        "FileOutputStream",
        "ZipInputStream",
        "defineClass",
    ];
    for (ci, nti) in member_refs {
        let cname = resolve_class(ci);
        let (mname, mdesc) = name_and_types
            .get(nti as usize)
            .and_then(|o| *o)
            .map(|(n, d)| (resolve_utf8(n), resolve_utf8(d)))
            .unwrap_or_default();
        if !cname.is_empty() && !mname.is_empty() {
            let full = format!("{cname}.{mname}");
            if DANGER_JVM.iter().any(|k| full.contains(k))
                && !notable.contains(&full)
                && notable.len() < 24
            {
                notable.push(full.clone());
            }
            if calls.len() < 50 && !calls.contains(&full) {
                calls.push(format!("{full}{mdesc}"));
            }
        }
    }

    let q_re = query.and_then(|q| {
        Regex::new(&format!("(?i){q}"))
            .or_else(|_| Regex::new(&format!("(?i){}", regex::escape(q))))
            .ok()
    });
    let mut str_hits = Vec::new();
    for si in strings {
        let s = resolve_utf8(si);
        if s.len() >= 3
            && q_re.as_ref().map(|r| r.is_match(&s)).unwrap_or(true)
            && !str_hits.contains(&s)
        {
            str_hits.push(s);
            if str_hits.len() >= 60 {
                break;
            }
        }
    }

    let mut out = vec![
        format!(
            "## Binary Header: Java Bytecode `.class` (major={major}.{minor}, {} B) | `{this_cls}` extends `{super_cls}`",
            bytes.len()
        ),
        format!("- SHA-256: `{}` | Constant Pool entries: {}", sha256_hex(bytes), cp_count),
    ];
    if !notable.is_empty() {
        out.push(format!(
            "- **Notable JVM Sinks**: `{}`",
            notable.join("`, `")
        ));
    }
    if !calls.is_empty() {
        out.push(format!(
            "### JVM Referenced Methods/Fields ({} shown)",
            calls.len()
        ));
        for c in calls.iter().take(35) {
            out.push(format!("- `{c}`"));
        }
    }
    if !str_hits.is_empty() {
        out.push(format!(
            "### JVM String Constants ({} shown)",
            str_hits.len()
        ));
        for s in str_hits {
            out.push(format!("- {s}"));
        }
    }
    out.join("\n")
}

/// Extract searchable text from a Java `.class` Constant Pool for zero-extraction `.jar`/`.war` search.
pub fn extract_java_class_searchable_text(bytes: &[u8]) -> String {
    if !is_java_class_magic(bytes) {
        return String::new();
    }
    let cp_count = read_u16_be(bytes, 8).unwrap_or(0) as usize;
    let mut pos = 10usize;
    let mut out = String::new();
    let mut idx = 1usize;
    while idx < cp_count && pos < bytes.len() && out.len() < 128 * 1024 {
        let tag = bytes[pos];
        pos += 1;
        match tag {
            1 => {
                let Some(len) = read_u16_be(bytes, pos).map(|v| v as usize) else {
                    break;
                };
                pos += 2;
                if pos + len > bytes.len() {
                    break;
                }
                if len >= 3 {
                    out.push_str(&String::from_utf8_lossy(&bytes[pos..pos + len]));
                    out.push('\n');
                }
                pos += len;
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => pos += 4,
            5 | 6 => {
                pos += 8;
                idx += 1;
            }
            7 | 8 | 16 | 19 | 20 => pos += 2,
            15 => pos += 3,
            _ => break,
        }
        idx += 1;
    }
    out
}

/// Pure-Rust `.NET` CLR `BSJB` metadata inspector: extracts runtime version & notable managed APIs.
fn scan_dotnet_clr_meta(bytes: &[u8]) -> Option<(String, Vec<String>)> {
    // Locate BSJB metadata signature (0x424A5342)
    let scan_lim = bytes.len().min(16 * 1024 * 1024);
    let bsjb = bytes[..scan_lim].windows(4).position(|w| w == b"BSJB")?;
    if bsjb + 20 > bytes.len() {
        return None;
    }
    let ver_len = read_u32_le(bytes, bsjb + 12).unwrap_or(0) as usize;
    if ver_len == 0 || ver_len > 128 || bsjb + 16 + ver_len + 4 > bytes.len() {
        return None;
    }
    let ver = String::from_utf8_lossy(&bytes[bsjb + 16..bsjb + 16 + ver_len])
        .trim_end_matches('\0')
        .to_string();
    let mut cur = bsjb + 16 + ver_len;
    // Align to 4-byte boundary if needed (ver_len in CLR is padded to 4 bytes)
    if cur % 4 != 0 {
        cur += 4 - (cur % 4);
    }
    if cur + 4 > bytes.len() {
        return Some((ver, Vec::new()));
    }
    let num_streams = read_u16_le(bytes, cur + 2).unwrap_or(0) as usize;
    cur += 4;
    let mut strings_stream: Option<(usize, usize)> = None;
    for _ in 0..num_streams.min(16) {
        if cur + 8 >= bytes.len() {
            break;
        }
        let s_off = read_u32_le(bytes, cur).unwrap_or(0) as usize;
        let s_sz = read_u32_le(bytes, cur + 4).unwrap_or(0) as usize;
        cur += 8;
        let nm_start = cur;
        while cur < bytes.len() && bytes[cur] != 0 && cur - nm_start < 32 {
            cur += 1;
        }
        let sname = String::from_utf8_lossy(&bytes[nm_start..cur]).to_string();
        cur += 1; // null terminator
        let pad = (4 - ((cur - nm_start) % 4)) % 4;
        cur += pad;
        if sname == "#Strings" {
            strings_stream = Some((bsjb.saturating_add(s_off), s_sz));
        }
    }
    let mut notable = Vec::new();
    const CLR_SINKS: [&str; 18] = [
        "ProcessStartInfo",
        "BinaryFormatter",
        "SoapFormatter",
        "NetDataContractSerializer",
        "LosFormatter",
        "JavaScriptSerializer",
        "XmlSerializer",
        "AssemblyLoad",
        "DllImportAttribute",
        "NamedPipeServerStream",
        "HttpListener",
        "WebClient",
        "SqlCommand",
        "RegistryKey",
        "DirectoryDelete",
        "CreateProcess",
        "ShellExecute",
        "UnsafeDeserialize",
    ];
    if let Some((off, sz)) = strings_stream {
        if off < bytes.len() {
            let end = off.saturating_add(sz.min(2 * 1024 * 1024)).min(bytes.len());
            for part in bytes[off..end].split(|&b| b == 0) {
                if part.len() < 4 || part.len() > 96 {
                    continue;
                }
                if let Ok(s) = std::str::from_utf8(part) {
                    if CLR_SINKS.iter().any(|k| s.contains(k)) && !notable.contains(&s.to_string())
                    {
                        notable.push(s.to_string());
                        if notable.len() >= 24 {
                            break;
                        }
                    }
                }
            }
        }
    }
    Some((ver, notable))
}

/// Compact bounded line diff hunk between two UTF-8 text snippets (<= `max_lines` lines).
pub fn compact_text_hunk(old_txt: &str, new_txt: &str, max_lines: usize) -> String {
    let old_lines: Vec<&str> = old_txt.lines().collect();
    let new_lines: Vec<&str> = new_txt.lines().collect();
    let old_set: std::collections::HashSet<&str> = old_lines.iter().copied().collect();
    let new_set: std::collections::HashSet<&str> = new_lines.iter().copied().collect();
    let mut out = Vec::new();
    for (idx, line) in old_lines.iter().enumerate() {
        if !new_set.contains(line) && !line.trim().is_empty() {
            let clipped: String = line.chars().take(180).collect();
            out.push(format!("- L{}: {clipped}", idx + 1));
            if out.len() >= max_lines / 2 {
                break;
            }
        }
    }
    for (idx, line) in new_lines.iter().enumerate() {
        if !old_set.contains(line) && !line.trim().is_empty() {
            let clipped: String = line.chars().take(180).collect();
            out.push(format!("+ L{}: {clipped}", idx + 1));
            if out.len() >= max_lines {
                break;
            }
        }
    }
    out.join("\n")
}

fn scan_electron_ipc_flags(text: &str) -> std::collections::BTreeSet<String> {
    let mut flags = std::collections::BTreeSet::new();
    let pats = electron_flag_patterns();
    for (name, sev, re) in &pats.rules {
        if re.is_match(text) {
            flags.insert(format!("[{sev}] {name}"));
        }
    }
    flags
}

fn extract_pe_exports_set(bytes: &[u8]) -> std::collections::BTreeSet<String> {
    let mut exports = std::collections::BTreeSet::new();
    if !bytes.starts_with(b"MZ") || bytes.len() <= 0x44 {
        return exports;
    }
    let pe_off = read_u32_le(bytes, 0x3C).unwrap_or(0) as usize;
    if bytes.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return exports;
    }
    let n_sec = read_u16_le(bytes, pe_off + 6).unwrap_or(0) as usize;
    let opt_sz = read_u16_le(bytes, pe_off + 20).unwrap_or(0) as usize;
    let opt_off = pe_off + 24;
    let is_pe64 = opt_sz >= 2 && read_u16_le(bytes, opt_off).unwrap_or(0) == 0x020B;
    let dd_off = opt_off + if is_pe64 { 112 } else { 96 };
    if opt_sz < if is_pe64 { 120 } else { 104 } {
        return exports;
    }
    let mut secs = Vec::new();
    let sec_base = opt_off + opt_sz;
    for s in 0..n_sec.min(32) {
        let off = sec_base + s * 40;
        if off + 40 > bytes.len() {
            break;
        }
        secs.push(PeSection {
            name: String::new(),
            vsize: read_u32_le(bytes, off + 8).unwrap_or(0),
            vaddr: read_u32_le(bytes, off + 12).unwrap_or(0),
            raw_size: read_u32_le(bytes, off + 16).unwrap_or(0),
            raw_ptr: read_u32_le(bytes, off + 20).unwrap_or(0),
            chars: read_u32_le(bytes, off + 36).unwrap_or(0),
        });
    }
    let exp_rva = read_u32_le(bytes, dd_off).unwrap_or(0);
    if let Some(exp_off) = rva_to_file_offset(exp_rva, &secs) {
        let n_names = read_u32_le(bytes, exp_off + 24).unwrap_or(0) as usize;
        let names_rva = read_u32_le(bytes, exp_off + 32).unwrap_or(0);
        if let Some(names_off) = rva_to_file_offset(names_rva, &secs) {
            for idx in 0..n_names.min(2000) {
                if let Some(nrva) = read_u32_le(bytes, names_off + idx * 4) {
                    if let Some(noff) = rva_to_file_offset(nrva, &secs) {
                        if let Some(nm) = read_cstr(bytes, noff, 128) {
                            exports.insert(nm);
                        }
                    }
                }
            }
        }
    }
    exports
}

fn extract_elf_dynsyms_set(bytes: &[u8]) -> std::collections::BTreeSet<String> {
    let mut syms = std::collections::BTreeSet::new();
    if !bytes.starts_with(b"\x7FELF") || bytes.len() < 64 || bytes[4] != 2 {
        return syms;
    }
    let shoff = read_u64_le(bytes, 40).unwrap_or(0) as usize;
    let shentsize = read_u16_le(bytes, 58).unwrap_or(0) as usize;
    let shnum = read_u16_le(bytes, 60).unwrap_or(0) as usize;
    let shstrndx = read_u16_le(bytes, 62).unwrap_or(0) as usize;
    if shoff == 0 || shentsize < 64 || shnum == 0 {
        return syms;
    }
    let strtab_hdr = shoff.saturating_add(shstrndx.saturating_mul(shentsize));
    let shstr_off = read_u64_le(bytes, strtab_hdr + 24).unwrap_or(0) as usize;
    let mut dynstr_slice: Option<(usize, usize)> = None;
    let mut dynsym_slice: Option<(usize, usize, usize)> = None;
    for i in 0..shnum.min(64) {
        let h = shoff.saturating_add(i.saturating_mul(shentsize));
        if h + 64 > bytes.len() {
            break;
        }
        let nm_off = read_u32_le(bytes, h).unwrap_or(0) as usize;
        let sh_type = read_u32_le(bytes, h + 4).unwrap_or(0);
        let s_off = read_u64_le(bytes, h + 24).unwrap_or(0) as usize;
        let s_sz = read_u64_le(bytes, h + 32).unwrap_or(0) as usize;
        let entsz = read_u64_le(bytes, h + 56).unwrap_or(0) as usize;
        let sname = read_cstr(bytes, shstr_off.saturating_add(nm_off), 64).unwrap_or_default();
        if sname == ".dynstr" {
            dynstr_slice = Some((s_off, s_sz));
        } else if sh_type == 11 || sname == ".dynsym" {
            dynsym_slice = Some((s_off, s_sz, entsz.max(24)));
        }
    }
    if let (Some((dstr_off, _)), Some((sym_off, sym_sz, entsz))) = (dynstr_slice, dynsym_slice) {
        for k in 0..(sym_sz / entsz).min(3000) {
            let p = sym_off + k * entsz;
            if p + 24 > bytes.len() {
                break;
            }
            let st_name = read_u32_le(bytes, p).unwrap_or(0) as usize;
            if st_name > 0 {
                if let Some(nm) = read_cstr(bytes, dstr_off.saturating_add(st_name), 128) {
                    syms.insert(nm);
                }
            }
        }
    }
    syms
}

fn is_code_member_ext(path: &str) -> bool {
    let low = path.to_ascii_lowercase();
    [
        ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".json", ".html", ".htm",
    ]
    .iter()
    .any(|ext| low.ends_with(ext))
}

fn is_js_like_member(path: &str) -> bool {
    let low = path.to_ascii_lowercase();
    [
        ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".htm",
    ]
    .iter()
    .any(|ext| low.ends_with(ext))
}

#[allow(clippy::too_many_arguments)]
fn diff_archive_member_bytes(
    out: &mut Vec<String>,
    new_members: &std::collections::BTreeMap<String, Vec<u8>>,
    old_members: &std::collections::BTreeMap<String, Vec<u8>>,
    kind_label: &str,
    new_label: &str,
    old_label: &str,
    h_new: &str,
    h_old: &str,
    size_delta: i64,
    deep: bool,
    max_items: usize,
) -> (String, Value) {
    let mut added: Vec<(String, usize)> = Vec::new();
    let mut removed: Vec<(String, usize)> = Vec::new();
    let mut changed: Vec<(String, i64, usize, bool)> = Vec::new();
    let mut unchanged = 0usize;

    for (path, nb) in new_members {
        match old_members.get(path) {
            None => added.push((path.clone(), nb.len())),
            Some(ob) => {
                if sha256_hex(nb) != sha256_hex(ob) {
                    changed.push((
                        path.clone(),
                        (nb.len() as i64) - (ob.len() as i64),
                        nb.len(),
                        is_code_member_ext(path),
                    ));
                } else {
                    unchanged += 1;
                }
            }
        }
    }
    for (path, ob) in old_members {
        if !new_members.contains_key(path) {
            removed.push((path.clone(), ob.len()));
        }
    }

    added.sort_by(|a, b| {
        is_code_member_ext(&b.0)
            .cmp(&is_code_member_ext(&a.0))
            .then_with(|| b.1.cmp(&a.1))
    });
    removed.sort_by(|a, b| {
        is_code_member_ext(&b.0)
            .cmp(&is_code_member_ext(&a.0))
            .then_with(|| b.1.cmp(&a.1))
    });
    changed.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| b.1.abs().cmp(&a.1.abs())));

    out.push(format!(
        "### Archive Member Diff ({kind_label}): +{} added, -{} removed, ~{} hash-changed ({unchanged} identical)",
        added.len(),
        removed.len(),
        changed.len()
    ));
    for (p, sz) in added.iter().take(max_items) {
        out.push(format!("- [ADDED] `{p}` ({sz} B)"));
    }
    for (p, sz) in removed.iter().take(max_items) {
        out.push(format!("- [REMOVED] `{p}` ({sz} B)"));
    }
    for (p, d, sz, _) in changed.iter().take(max_items) {
        out.push(format!("- [CHANGED] `{p}` ({d:+} B -> {sz} B)"));
    }

    let mut changed_code_members = Vec::new();
    let mut security_signals = Vec::new();
    if deep {
        let mut inspect_targets: Vec<(String, bool)> = Vec::new();
        for (p, d, _, is_code) in &changed {
            if *is_code && inspect_targets.len() < 12 {
                let _ = d;
                inspect_targets.push((p.clone(), false));
            }
        }
        for (p, _) in &added {
            if is_code_member_ext(p) && inspect_targets.len() < 12 {
                inspect_targets.push((p.clone(), true));
            }
        }
        for (mpath, is_added) in inspect_targets {
            let Some(nb) = new_members.get(&mpath) else {
                continue;
            };
            if nb.len() > 2 * 1024 * 1024 {
                continue;
            }
            let new_txt = String::from_utf8_lossy(nb);
            let old_txt = old_members
                .get(&mpath)
                .map(|ob| String::from_utf8_lossy(ob))
                .unwrap_or_default();
            let mut routes_added = Vec::new();
            let mut removed_routes_count = 0u64;
            let mut ipc_sinks_added = Vec::new();
            if is_js_like_member(&mpath) {
                let (_, jv) = crate::inspect::extract_js_routes_diff_md(
                    &new_txt, &mpath, None, &old_txt, &mpath,
                );
                removed_routes_count = jv
                    .pointer("/diff/removed_routes_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if let Some(ra) = jv.pointer("/diff/new_routes").and_then(Value::as_array) {
                    routes_added = ra
                        .iter()
                        .take(12)
                        .filter_map(|item| {
                            if let Some(s) = item.as_str() {
                                Some(s.to_string())
                            } else {
                                let meth = item.get("method").and_then(Value::as_str).unwrap_or("");
                                let path = item.get("path").and_then(Value::as_str)?;
                                Some(if meth.is_empty() {
                                    path.to_string()
                                } else {
                                    format!("{meth} {path}")
                                })
                            }
                        })
                        .collect();
                }
                if let Some(ni) = jv.pointer("/diff/new_ipc_sinks").and_then(Value::as_array) {
                    for item in ni.iter().take(12) {
                        let kind = item.get("kind").and_then(Value::as_str).unwrap_or("ipc");
                        let snip = item.get("snippet").and_then(Value::as_str).unwrap_or("");
                        let tag = format!("{kind}: {snip}");
                        if !ipc_sinks_added.contains(&tag) {
                            ipc_sinks_added.push(tag.clone());
                            security_signals.push(format!("{mpath}: added {tag}"));
                        }
                    }
                }
                let old_ipc = scan_electron_ipc_flags(&old_txt);
                let new_ipc = scan_electron_ipc_flags(&new_txt);
                for f in new_ipc.difference(&old_ipc) {
                    if !ipc_sinks_added.contains(f) {
                        ipc_sinks_added.push(f.clone());
                        security_signals.push(format!("{mpath}: added {f}"));
                    }
                }
                for r in &routes_added {
                    security_signals.push(format!("{mpath}: added route {r}"));
                }
            }
            let hunk_preview = if is_added {
                new_txt.lines().take(12).collect::<Vec<_>>().join("\n")
            } else {
                compact_text_hunk(&old_txt, &new_txt, 14)
            };
            changed_code_members.push(json!({
                "path": mpath,
                "status": if is_added { "added" } else { "modified" },
                "size_delta": (nb.len() as i64) - (old_members.get(&mpath).map(|v| v.len() as i64).unwrap_or(0)),
                "routes_added": routes_added,
                "removed_routes_count": removed_routes_count,
                "ipc_sinks_added": ipc_sinks_added,
                "hunk_preview": hunk_preview,
            }));
        }
    }
    if !changed_code_members.is_empty() {
        out.push("\n### Deep Code Member Deltas".to_string());
        for cm in &changed_code_members {
            out.push(format!(
                "- `{}` ({}, {:+} B) routes+={:?} ipc+={:?}",
                cm["path"].as_str().unwrap_or(""),
                cm["status"].as_str().unwrap_or(""),
                cm["size_delta"].as_i64().unwrap_or(0),
                cm["routes_added"],
                cm["ipc_sinks_added"],
            ));
        }
    }

    let jv = json!({
        "ok": true,
        "mode": "version-diff",
        "kind": kind_label,
        "old_target": old_label,
        "new_target": new_label,
        "old_sha256": h_old,
        "new_sha256": h_new,
        "size_delta": size_delta,
        "archive_summary": {
            "added": added.len(),
            "removed": removed.len(),
            "modified_hash": changed.len(),
            "unchanged": unchanged,
        },
        "members_added": added.iter().take(max_items).map(|(p, sz)| json!({"path": p, "bytes": sz})).collect::<Vec<_>>(),
        "members_removed": removed.iter().take(max_items).map(|(p, sz)| json!({"path": p, "bytes": sz})).collect::<Vec<_>>(),
        "members_changed": changed.iter().take(max_items).map(|(p, d, sz, _)| json!({"path": p, "delta_bytes": d, "bytes": sz})).collect::<Vec<_>>(),
        "changed_code_members": changed_code_members,
        "security_signals": security_signals,
    });
    (out.join("\n"), jv)
}

/// Streaming zero-full-RAM `.asar` archive diff: parses Pickle headers first and compares entry sizes /
/// `.asar` integrity hashes (or 64 KiB streamed member chunks) without allocating unchanged members into memory.
pub fn diff_asar_files_streaming(
    new_p: &std::path::Path,
    old_p: &std::path::Path,
    new_label: &str,
    old_label: &str,
    deep: bool,
    max_items: usize,
) -> Result<(String, Value), String> {
    let new_len = std::fs::metadata(new_p).map(|m| m.len()).unwrap_or(0);
    let old_len = std::fs::metadata(old_p).map(|m| m.len()).unwrap_or(0);
    let mut fn_new = std::io::BufReader::new(
        std::fs::File::open(new_p).map_err(|e| format!("failed to open `{new_label}`: {e}"))?,
    );
    let mut fn_old = std::io::BufReader::new(
        std::fs::File::open(old_p).map_err(|e| format!("failed to open `{old_label}`: {e}"))?,
    );
    let (base_new, en_new) = parse_asar_index_reader(&mut fn_new)?;
    let (base_old, en_old) = parse_asar_index_reader(&mut fn_old)?;

    let mut old_idx: BTreeMap<String, &AsarEntry> = BTreeMap::new();
    for e in &en_old {
        if !e.unpacked {
            old_idx.insert(e.path.clone(), e);
        }
    }
    let mut new_idx: BTreeMap<String, &AsarEntry> = BTreeMap::new();
    for e in &en_new {
        if !e.unpacked {
            new_idx.insert(e.path.clone(), e);
        }
    }

    let read_member = |r: &mut std::io::BufReader<std::fs::File>,
                       base: usize,
                       off: usize,
                       sz: usize|
     -> Option<Vec<u8>> {
        let pos = (base as u64).checked_add(off as u64)?;
        r.seek(SeekFrom::Start(pos)).ok()?;
        let mut buf = vec![0u8; sz];
        r.read_exact(&mut buf).ok()?;
        Some(buf)
    };
    let stream_member_eq = |r1: &mut std::io::BufReader<std::fs::File>,
                            b1: usize,
                            o1: usize,
                            r2: &mut std::io::BufReader<std::fs::File>,
                            b2: usize,
                            o2: usize,
                            sz: usize|
     -> bool {
        if r1.seek(SeekFrom::Start((b1 + o1) as u64)).is_err()
            || r2.seek(SeekFrom::Start((b2 + o2) as u64)).is_err()
        {
            return false;
        }
        let mut rem = sz;
        let mut buf1 = [0u8; 65_536];
        let mut buf2 = [0u8; 65_536];
        while rem > 0 {
            let chunk = rem.min(buf1.len());
            if r1.read_exact(&mut buf1[..chunk]).is_err()
                || r2.read_exact(&mut buf2[..chunk]).is_err()
            {
                return false;
            }
            if buf1[..chunk] != buf2[..chunk] {
                return false;
            }
            rem -= chunk;
        }
        true
    };

    let mut added: Vec<(String, usize, &AsarEntry)> = Vec::new();
    let mut removed: Vec<(String, usize)> = Vec::new();
    let mut changed: Vec<(String, i64, usize, bool, &AsarEntry, &AsarEntry)> = Vec::new();
    let mut unchanged = 0usize;

    for (path, ne) in &new_idx {
        match old_idx.get(path) {
            None => added.push((path.clone(), ne.size, *ne)),
            Some(oe) => {
                let same = if ne.size != oe.size {
                    false
                } else if let (Some(hn), Some(ho)) = (&ne.hash, &oe.hash) {
                    hn == ho
                } else {
                    stream_member_eq(
                        &mut fn_new,
                        base_new,
                        ne.offset,
                        &mut fn_old,
                        base_old,
                        oe.offset,
                        ne.size,
                    )
                };
                if same {
                    unchanged += 1;
                } else {
                    changed.push((
                        path.clone(),
                        (ne.size as i64) - (oe.size as i64),
                        ne.size,
                        is_code_member_ext(path),
                        *ne,
                        *oe,
                    ));
                }
            }
        }
    }
    for (path, oe) in &old_idx {
        if !new_idx.contains_key(path) {
            removed.push((path.clone(), oe.size));
        }
    }

    let size_delta = (new_len as i64) - (old_len as i64);
    let mut out = vec![format!(
        "## Binary/Archive Patch Diff: `{new_label}` ({new_len} B) vs `{old_label}` ({old_len} B, delta={size_delta:+} B)"
    )];

    if size_delta == 0 && added.is_empty() && removed.is_empty() && changed.is_empty() {
        out.push(format!(
            "- **IDENTICAL** ({unchanged} member(s) match by header+size/hash)"
        ));
        return Ok((
            out.join("\n"),
            json!({
                "ok": true,
                "mode": "version-diff",
                "identical": true,
                "kind": "asar",
                "old_target": old_label,
                "new_target": new_label,
                "size_delta": 0,
                "archive_summary": {
                    "added": 0,
                    "removed": 0,
                    "modified_hash": 0,
                    "unchanged": unchanged,
                },
            }),
        ));
    }

    added.sort_by(|a, b| {
        is_code_member_ext(&b.0)
            .cmp(&is_code_member_ext(&a.0))
            .then_with(|| b.1.cmp(&a.1))
    });
    removed.sort_by(|a, b| {
        is_code_member_ext(&b.0)
            .cmp(&is_code_member_ext(&a.0))
            .then_with(|| b.1.cmp(&a.1))
    });
    changed.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| b.1.abs().cmp(&a.1.abs())));

    out.push(format!(
        "### Archive Member Diff (asar): +{} added, -{} removed, ~{} changed ({unchanged} identical)",
        added.len(),
        removed.len(),
        changed.len()
    ));
    for (p, sz, _) in added.iter().take(max_items) {
        out.push(format!("- [ADDED] `{p}` ({sz} B)"));
    }
    for (p, sz) in removed.iter().take(max_items) {
        out.push(format!("- [REMOVED] `{p}` ({sz} B)"));
    }
    for (p, d, sz, _, _, _) in changed.iter().take(max_items) {
        out.push(format!("- [CHANGED] `{p}` ({d:+} B -> {sz} B)"));
    }

    let mut changed_code_members = Vec::new();
    let mut security_signals = Vec::new();
    if deep {
        let mut inspect_targets: Vec<(&str, bool, &AsarEntry, Option<&AsarEntry>)> = Vec::new();
        for (p, _, _, is_code, ne, oe) in &changed {
            if *is_code && inspect_targets.len() < 12 {
                inspect_targets.push((p.as_str(), false, *ne, Some(*oe)));
            }
        }
        for (p, _, ne) in &added {
            if is_code_member_ext(p) && inspect_targets.len() < 12 {
                inspect_targets.push((p.as_str(), true, *ne, None));
            }
        }
        for (mpath, is_added, ne, oe_opt) in inspect_targets {
            if ne.size > 2 * 1024 * 1024 {
                continue;
            }
            let Some(nb) = read_member(&mut fn_new, base_new, ne.offset, ne.size) else {
                continue;
            };
            let new_txt = String::from_utf8_lossy(&nb);
            let old_bytes = oe_opt
                .filter(|o| o.size <= 2 * 1024 * 1024)
                .and_then(|o| read_member(&mut fn_old, base_old, o.offset, o.size))
                .unwrap_or_default();
            let old_txt = String::from_utf8_lossy(&old_bytes);
            let mut routes_added = Vec::new();
            let mut removed_routes_count = 0u64;
            let mut ipc_sinks_added = Vec::new();
            if is_js_like_member(mpath) {
                let (_, jv) = crate::inspect::extract_js_routes_diff_md(
                    &new_txt, mpath, None, &old_txt, mpath,
                );
                removed_routes_count = jv
                    .pointer("/diff/removed_routes_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if let Some(ra) = jv.pointer("/diff/new_routes").and_then(Value::as_array) {
                    routes_added = ra
                        .iter()
                        .take(12)
                        .filter_map(|item| {
                            if let Some(s) = item.as_str() {
                                Some(s.to_string())
                            } else {
                                let meth = item.get("method").and_then(Value::as_str).unwrap_or("");
                                let path = item.get("path").and_then(Value::as_str)?;
                                Some(if meth.is_empty() {
                                    path.to_string()
                                } else {
                                    format!("{meth} {path}")
                                })
                            }
                        })
                        .collect();
                }
                if let Some(ni) = jv.pointer("/diff/new_ipc_sinks").and_then(Value::as_array) {
                    for item in ni.iter().take(12) {
                        let kind = item.get("kind").and_then(Value::as_str).unwrap_or("ipc");
                        let snip = item.get("snippet").and_then(Value::as_str).unwrap_or("");
                        let tag = format!("{kind}: {snip}");
                        if !ipc_sinks_added.contains(&tag) {
                            ipc_sinks_added.push(tag.clone());
                            security_signals.push(format!("{mpath}: added {tag}"));
                        }
                    }
                }
                let old_ipc = scan_electron_ipc_flags(&old_txt);
                let new_ipc = scan_electron_ipc_flags(&new_txt);
                for f in new_ipc.difference(&old_ipc) {
                    if !ipc_sinks_added.contains(f) {
                        ipc_sinks_added.push(f.clone());
                        security_signals.push(format!("{mpath}: added {f}"));
                    }
                }
                for r in &routes_added {
                    security_signals.push(format!("{mpath}: added route {r}"));
                }
            }
            let hunk_preview = if is_added {
                new_txt.lines().take(12).collect::<Vec<_>>().join("\n")
            } else {
                compact_text_hunk(&old_txt, &new_txt, 14)
            };
            changed_code_members.push(json!({
                "path": mpath,
                "status": if is_added { "added" } else { "modified" },
                "size_delta": (ne.size as i64) - (oe_opt.map(|o| o.size as i64).unwrap_or(0)),
                "routes_added": routes_added,
                "removed_routes_count": removed_routes_count,
                "ipc_sinks_added": ipc_sinks_added,
                "hunk_preview": hunk_preview,
            }));
        }
    }

    let jv = json!({
        "ok": true,
        "mode": "version-diff",
        "kind": "asar",
        "streaming": true,
        "old_target": old_label,
        "new_target": new_label,
        "size_delta": size_delta,
        "archive_summary": {
            "added": added.len(),
            "removed": removed.len(),
            "modified_hash": changed.len(),
            "unchanged": unchanged,
        },
        "members_added": added.iter().take(max_items).map(|(p, sz, _)| json!({"path": p, "bytes": sz})).collect::<Vec<_>>(),
        "members_removed": removed.iter().take(max_items).map(|(p, sz)| json!({"path": p, "bytes": sz})).collect::<Vec<_>>(),
        "members_changed": changed.iter().take(max_items).map(|(p, d, sz, _, _, _)| json!({"path": p, "delta_bytes": d, "bytes": sz})).collect::<Vec<_>>(),
        "changed_code_members": changed_code_members,
        "security_signals": security_signals,
    });
    Ok((out.join("\n"), jv))
}

/// Pure-Rust Binary & Archive Patch-Diff Engine (`ap diff` & `ap read <new> --diff <old>`).
/// Supports PE/DLL/SYS, ELF/SO, Go binaries, Electron `.asar`, and `.zip`/`.jar`/`.vsix`/`.war`/`.whl`.
pub fn diff_binaries_or_archives(
    new_bytes: &[u8],
    old_bytes: &[u8],
    new_label: &str,
    old_label: &str,
    ext: &str,
    deep: bool,
    max_items: usize,
) -> (String, Value) {
    let size_delta = (new_bytes.len() as i64) - (old_bytes.len() as i64);
    let mut out = vec![format!(
        "## Binary/Archive Patch Diff: `{new_label}` ({} B) vs `{old_label}` ({} B, delta={size_delta:+} B)",
        new_bytes.len(),
        old_bytes.len(),
    )];
    let h_new = sha256_hex(new_bytes);
    let h_old = sha256_hex(old_bytes);
    if h_new == h_old {
        out.push(format!("- **IDENTICAL** (SHA-256 `{h_new}`)"));
        return (
            out.join("\n"),
            json!({
                "ok": true,
                "mode": "version-diff",
                "identical": true,
                "kind": if ext.is_empty() { "binary" } else { ext },
                "old_target": old_label,
                "new_target": new_label,
                "old_sha256": h_old,
                "new_sha256": h_new,
                "size_delta": 0,
            }),
        );
    }
    out.push(format!("- New SHA-256: `{h_new}` | Old SHA-256: `{h_old}`"));

    // 1. Archive diff (.asar / .zip / .jar / .vsix / .war / .whl) with SHA-256 + deep code inspection
    if ext == "asar" {
        if let (Ok((base_new, en_new)), Ok((base_old, en_old))) =
            (parse_asar_index(new_bytes), parse_asar_index(old_bytes))
        {
            let mut m_new = std::collections::BTreeMap::new();
            let mut m_old = std::collections::BTreeMap::new();
            for e in en_new {
                if !e.unpacked {
                    let s = base_new.saturating_add(e.offset);
                    let end = s.saturating_add(e.size).min(new_bytes.len());
                    if s <= end {
                        m_new.insert(e.path, new_bytes[s..end].to_vec());
                    }
                }
            }
            for e in en_old {
                if !e.unpacked {
                    let s = base_old.saturating_add(e.offset);
                    let end = s.saturating_add(e.size).min(old_bytes.len());
                    if s <= end {
                        m_old.insert(e.path, old_bytes[s..end].to_vec());
                    }
                }
            }
            return diff_archive_member_bytes(
                &mut out, &m_new, &m_old, "asar", new_label, old_label, &h_new, &h_old, size_delta,
                deep, max_items,
            );
        }
    }
    if matches!(ext, "zip" | "jar" | "vsix" | "war" | "apk" | "whl") {
        if let (Ok(mut zn), Ok(mut zo)) = (
            ZipArchive::new(Cursor::new(new_bytes)),
            ZipArchive::new(Cursor::new(old_bytes)),
        ) {
            let mut m_new = std::collections::BTreeMap::new();
            let mut m_old = std::collections::BTreeMap::new();
            for i in 0..zn.len().min(3000) {
                if let Ok(mut f) = zn.by_index(i) {
                    if !f.is_dir() && f.size() <= 4 * 1024 * 1024 {
                        let nm = f.name().to_string();
                        let mut buf = Vec::with_capacity(f.size() as usize);
                        if f.read_to_end(&mut buf).is_ok() {
                            m_new.insert(nm, buf);
                        }
                    }
                }
            }
            for i in 0..zo.len().min(3000) {
                if let Ok(mut f) = zo.by_index(i) {
                    if !f.is_dir() && f.size() <= 4 * 1024 * 1024 {
                        let nm = f.name().to_string();
                        let mut buf = Vec::with_capacity(f.size() as usize);
                        if f.read_to_end(&mut buf).is_ok() {
                            m_old.insert(nm, buf);
                        }
                    }
                }
            }
            return diff_archive_member_bytes(
                &mut out, &m_new, &m_old, ext, new_label, old_label, &h_new, &h_old, size_delta,
                deep, max_items,
            );
        }
    }

    // 2. Native Binary Diff (PE / ELF / Go): mitigations, exports, risky IAT imports, ELF .dynsym, Go funcs, RPC, strings
    let surf_new = inspect_binary_surface(new_bytes);
    let surf_old = inspect_binary_surface(old_bytes);
    let kind = surf_new["format"].as_str().unwrap_or("binary").to_string();

    let extract_mits = |s: &Value| -> String {
        s["header_summary"]
            .as_array()
            .and_then(|arr| {
                arr.iter().filter_map(Value::as_str).find_map(|ln| {
                    ln.split("Mitigations:")
                        .nth(1)
                        .map(|r| r.trim().to_string())
                })
            })
            .unwrap_or_default()
    };
    let mit_old = extract_mits(&surf_old);
    let mit_new = extract_mits(&surf_new);
    let mut mitigations_changed = Vec::new();
    if mit_old != mit_new && (!mit_old.is_empty() || !mit_new.is_empty()) {
        out.push(format!("- Mitigations changed: `{mit_old}` -> `{mit_new}`"));
        mitigations_changed.push(json!({ "old": mit_old, "new": mit_new }));
    }

    let collect_imports = |s: &Value| -> std::collections::BTreeSet<String> {
        let mut set = std::collections::BTreeSet::new();
        if let Some(obj) = s["import_risk_buckets"].as_object() {
            for (bkt, arr) in obj {
                if let Some(items) = arr.as_array() {
                    for sym in items.iter().filter_map(Value::as_str) {
                        set.insert(format!("[{bkt}] {sym}"));
                    }
                }
            }
        }
        set
    };
    let imp_new = collect_imports(&surf_new);
    let imp_old = collect_imports(&surf_old);
    let imports_added: Vec<String> = imp_new
        .difference(&imp_old)
        .take(max_items)
        .cloned()
        .collect();
    let imports_removed: Vec<String> = imp_old
        .difference(&imp_new)
        .take(max_items)
        .cloned()
        .collect();
    if !imports_added.is_empty() || !imports_removed.is_empty() {
        out.push(format!(
            "### Risky Import Diff: +{} added, -{} removed",
            imports_added.len(),
            imports_removed.len()
        ));
        for s in &imports_added {
            out.push(format!("- [IMP+] {s}"));
        }
        for s in &imports_removed {
            out.push(format!("- [IMP-] {s}"));
        }
    }

    let (sym_new, sym_old) = if kind == "pe" {
        (
            extract_pe_exports_set(new_bytes),
            extract_pe_exports_set(old_bytes),
        )
    } else if kind == "elf" {
        (
            extract_elf_dynsyms_set(new_bytes),
            extract_elf_dynsyms_set(old_bytes),
        )
    } else {
        (Default::default(), Default::default())
    };
    let symbols_added: Vec<String> = sym_new
        .difference(&sym_old)
        .take(max_items)
        .cloned()
        .collect();
    let symbols_removed: Vec<String> = sym_old
        .difference(&sym_new)
        .take(max_items)
        .cloned()
        .collect();
    if !symbols_added.is_empty() || !symbols_removed.is_empty() {
        out.push(format!(
            "### Export/Symbol Diff: +{} added, -{} removed",
            symbols_added.len(),
            symbols_removed.len()
        ));
        for s in &symbols_added {
            out.push(format!("- [SYM+] {s}"));
        }
        for s in &symbols_removed {
            out.push(format!("- [SYM-] {s}"));
        }
    }

    let extract_set = |b: &[u8]| -> std::collections::BTreeSet<String> {
        let mut set = std::collections::BTreeSet::new();
        let lim = b.len().min(12 * 1024 * 1024);
        let data = &b[..lim];
        let mut i = 0usize;
        while i < data.len() && set.len() < 12000 {
            if (0x20..=0x7E).contains(&data[i]) {
                let st = i;
                while i < data.len() && (0x20..=0x7E).contains(&data[i]) && i - st < 180 {
                    i += 1;
                }
                if i - st >= 8 {
                    let s = String::from_utf8_lossy(&data[st..i]).to_string();
                    if s.contains('/')
                        || s.contains('\\')
                        || s.contains("http")
                        || s.contains("err")
                        || s.contains("fail")
                        || s.contains("invalid")
                        || s.contains("deny")
                        || s.contains("check")
                        || s.contains("pipe")
                        || s.contains('%')
                    {
                        set.insert(s);
                    }
                }
            } else {
                i += 1;
            }
        }
        let mut j = 0usize;
        while j + 1 < data.len() && set.len() < 16000 {
            if (0x20..=0x7E).contains(&data[j]) && data[j + 1] == 0 {
                let mut s = String::new();
                while j + 1 < data.len()
                    && (0x20..=0x7E).contains(&data[j])
                    && data[j + 1] == 0
                    && s.len() < 160
                {
                    s.push(data[j] as char);
                    j += 2;
                }
                if s.len() >= 7
                    && (s.contains('/')
                        || s.contains('\\')
                        || s.contains("http")
                        || s.contains("err")
                        || s.contains("fail")
                        || s.contains("invalid")
                        || s.contains("pipe")
                        || s.contains('%'))
                {
                    set.insert(s);
                }
            } else {
                j += 1;
            }
        }
        set
    };

    let s_new = extract_set(new_bytes);
    let s_old = extract_set(old_bytes);
    let added_s: Vec<String> = s_new
        .difference(&s_old)
        .take(max_items.max(35))
        .cloned()
        .collect();
    let removed_s: Vec<String> = s_old.difference(&s_new).take(max_items).cloned().collect();

    let g_new: std::collections::BTreeSet<String> = scan_go_pclntab_funcs(new_bytes, None, 2000)
        .into_iter()
        .map(|s| s.split(" (pc=").next().unwrap_or(&s).to_string())
        .collect();
    let g_old: std::collections::BTreeSet<String> = scan_go_pclntab_funcs(old_bytes, None, 2000)
        .into_iter()
        .map(|s| s.split(" (pc=").next().unwrap_or(&s).to_string())
        .collect();
    let go_added: Vec<String> = g_new.difference(&g_old).take(max_items).cloned().collect();
    let go_removed: Vec<String> = g_old.difference(&g_new).take(max_items).cloned().collect();
    if !go_added.is_empty() || !go_removed.is_empty() {
        out.push(format!(
            "### Go Function Diff: +{} added, -{} removed",
            go_added.len(),
            go_removed.len()
        ));
        for f in &go_added {
            out.push(format!("- [GO+] {f}"));
        }
        for f in &go_removed {
            out.push(format!("- [GO-] {f}"));
        }
    }

    let r_new: std::collections::BTreeSet<String> = scan_pe_rpc_interfaces(new_bytes, true)
        .into_iter()
        .map(|s| s.split(" (").next().unwrap_or(&s).to_string())
        .collect();
    let r_old: std::collections::BTreeSet<String> = scan_pe_rpc_interfaces(old_bytes, true)
        .into_iter()
        .map(|s| s.split(" (").next().unwrap_or(&s).to_string())
        .collect();
    let rpc_added: Vec<String> = r_new.difference(&r_old).take(max_items).cloned().collect();
    let rpc_removed: Vec<String> = r_old.difference(&r_new).take(max_items).cloned().collect();
    if !rpc_added.is_empty() || !rpc_removed.is_empty() {
        out.push("### MS-RPC Interface Diff".to_string());
        for r in &rpc_added {
            out.push(format!("- [RPC+] {r}"));
        }
        for r in &rpc_removed {
            out.push(format!("- [RPC-] {r}"));
        }
    }

    out.push(format!(
        "### Security-Relevant Strings Diff (+{} added, -{} removed)",
        added_s.len(),
        removed_s.len()
    ));
    for s in &added_s {
        out.push(format!("+ {s}"));
    }
    for s in &removed_s {
        out.push(format!("- {s}"));
    }

    let mut security_signals = Vec::new();
    for i in &imports_added {
        security_signals.push(format!("Added risky import {i}"));
    }
    for r in &rpc_added {
        security_signals.push(format!("Added RPC interface {r}"));
    }
    let jv = json!({
        "ok": true,
        "mode": "version-diff",
        "kind": kind,
        "old_target": old_label,
        "new_target": new_label,
        "old_sha256": h_old,
        "new_sha256": h_new,
        "size_delta": size_delta,
        "mitigations_changed": mitigations_changed,
        "exports_added": if kind == "pe" { symbols_added.clone() } else { Vec::new() },
        "exports_removed": if kind == "pe" { symbols_removed.clone() } else { Vec::new() },
        "symbols_added": symbols_added,
        "symbols_removed": symbols_removed,
        "imports_added": imports_added,
        "imports_removed": imports_removed,
        "go_funcs_added": go_added,
        "go_funcs_removed": go_removed,
        "rpc_added": rpc_added,
        "rpc_removed": rpc_removed,
        "strings_added": added_s,
        "strings_removed": removed_s,
        "security_signals": security_signals,
    });
    (out.join("\n"), jv)
}

pub fn diff_binaries_or_archives_md(
    new_bytes: &[u8],
    old_bytes: &[u8],
    new_label: &str,
    old_label: &str,
    ext: &str,
) -> String {
    diff_binaries_or_archives(new_bytes, old_bytes, new_label, old_label, ext, true, 25).0
}

pub fn is_binary_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\x7FELF")
        || bytes.starts_with(b"\x00asm")
        || is_java_class_magic(bytes)
        || is_pyc_magic(bytes)
        || bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
        || bytes.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || bytes.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
}

/// Detect CPython 3.8–3.14 `.pyc` files (PEP-552 16-byte header followed by Marshal v4 `TYPE_CODE`).
pub fn is_pyc_magic(bytes: &[u8]) -> bool {
    if bytes.len() < 18 || bytes[2] != 0x0D || bytes[3] != 0x0A {
        return false;
    }
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    if !(3400..=3650).contains(&magic) {
        return false;
    }
    let Some(bitfield) = read_u32_le(bytes, 4) else {
        return false;
    };
    bitfield <= 3 && (bytes[16] & 0x7F) == b'c'
}

fn pyc_python_version(magic: u16) -> &'static str {
    match magic {
        3400..=3419 => "3.8",
        3420..=3429 => "3.9",
        3430..=3449 => "3.10",
        3450..=3509 => "3.11",
        3510..=3549 => "3.12",
        3550..=3599 => "3.13",
        _ => "3.14+",
    }
}

#[derive(Debug, Clone)]
struct PycCodeObj {
    argcount: i32,
    firstlineno: i32,
    name: String,
    qualname: String,
    filename: String,
    consts: Vec<MarshalVal>,
    names: Vec<String>,
    varnames: Vec<String>,
}

#[derive(Debug, Clone)]
enum MarshalVal {
    Null,
    Scalar,
    Str(String),
    Seq(Vec<MarshalVal>),
    Code(Box<PycCodeObj>),
}

impl MarshalVal {
    fn as_str(&self) -> Option<&str> {
        match self {
            MarshalVal::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_str_list(&self) -> Vec<String> {
        match self {
            MarshalVal::Seq(items) => items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        }
    }
}

struct MarshalReader<'a> {
    data: &'a [u8],
    pos: usize,
    magic: u16,
    refs: Vec<MarshalVal>,
    obj_count: usize,
}

impl<'a> MarshalReader<'a> {
    fn new(data: &'a [u8], pos: usize, magic: u16) -> Self {
        Self {
            data,
            pos,
            magic,
            refs: Vec::new(),
            obj_count: 0,
        }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_i32(&mut self) -> Option<i32> {
        let s = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_u32(&mut self) -> Option<u32> {
        let s = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_i64(&mut self) -> Option<i64> {
        let s = self.data.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        Some(i64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn read_f64(&mut self) -> Option<f64> {
        let s = self.data.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        Some(f64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn read_bytes_slice(&mut self, len: usize) -> Option<&'a [u8]> {
        if len > 16 * 1024 * 1024 || self.pos.saturating_add(len) > self.data.len() {
            return None;
        }
        let s = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some(s)
    }

    fn read_obj(&mut self, depth: usize) -> Option<MarshalVal> {
        if depth > 40 || self.obj_count > 60_000 {
            return None;
        }
        self.obj_count += 1;
        let raw_tag = self.read_u8()?;
        let flag = (raw_tag & 0x80) != 0;
        let tag = raw_tag & 0x7F;
        let ref_idx = if flag {
            let idx = self.refs.len();
            self.refs.push(MarshalVal::Null);
            Some(idx)
        } else {
            None
        };

        let val = match tag {
            b'0' => MarshalVal::Null,
            b'N' | b'S' | b'.' | b'F' | b'T' => MarshalVal::Scalar,
            b'i' => {
                let _ = self.read_i32()?;
                MarshalVal::Scalar
            }
            b'I' => {
                let _ = self.read_i64()?;
                MarshalVal::Scalar
            }
            b'l' => {
                let n = self.read_i32()?;
                let digits = n.unsigned_abs() as usize;
                let _ = self.read_bytes_slice(digits.saturating_mul(2))?;
                MarshalVal::Scalar
            }
            b'g' => {
                let _ = self.read_f64()?;
                MarshalVal::Scalar
            }
            b'f' => {
                let n = self.read_u8()? as usize;
                let _ = self.read_bytes_slice(n)?;
                MarshalVal::Scalar
            }
            b'y' => {
                let _ = self.read_f64()?;
                let _ = self.read_f64()?;
                MarshalVal::Scalar
            }
            b'x' => {
                let n1 = self.read_u8()? as usize;
                let _ = self.read_bytes_slice(n1)?;
                let n2 = self.read_u8()? as usize;
                let _ = self.read_bytes_slice(n2)?;
                MarshalVal::Scalar
            }
            b's' => {
                let n = self.read_u32()? as usize;
                let _ = self.read_bytes_slice(n)?;
                MarshalVal::Scalar
            }
            b't' | b'u' | b'a' | b'A' => {
                let n = self.read_u32()? as usize;
                let b = self.read_bytes_slice(n)?;
                MarshalVal::Str(String::from_utf8_lossy(b).into_owned())
            }
            b'z' | b'Z' => {
                let n = self.read_u8()? as usize;
                let b = self.read_bytes_slice(n)?;
                MarshalVal::Str(String::from_utf8_lossy(b).into_owned())
            }
            b')' => {
                let n = self.read_u8()? as usize;
                let mut items = Vec::with_capacity(n.min(256));
                for _ in 0..n {
                    items.push(self.read_obj(depth + 1)?);
                }
                MarshalVal::Seq(items)
            }
            b'(' | b'[' | b'<' | b'>' => {
                let n = (self.read_u32()? as usize).min(20_000);
                let mut items = Vec::with_capacity(n.min(256));
                for _ in 0..n {
                    items.push(self.read_obj(depth + 1)?);
                }
                MarshalVal::Seq(items)
            }
            b'{' => {
                let mut pairs = Vec::new();
                for _ in 0..20_000 {
                    let k = self.read_obj(depth + 1)?;
                    if matches!(k, MarshalVal::Null) {
                        break;
                    }
                    let v = self.read_obj(depth + 1)?;
                    pairs.push(k);
                    pairs.push(v);
                }
                MarshalVal::Seq(pairs)
            }
            b'r' => {
                let idx = self.read_u32()? as usize;
                self.refs.get(idx).cloned().unwrap_or(MarshalVal::Null)
            }
            b'c' => {
                let argcount = self.read_i32()?;
                let _posonly = if self.magic >= 3413 {
                    self.read_i32()?
                } else {
                    0
                };
                let _kwonly = self.read_i32()?;
                let _nlocals = self.read_i32()?;
                let _stacksize = self.read_i32()?;
                let _flags = self.read_i32()?;
                let _code = self.read_obj(depth + 1)?;
                let consts_val = self.read_obj(depth + 1)?;
                let names_val = self.read_obj(depth + 1)?;

                let varnames = if self.magic >= 3450 {
                    let lp = self.read_obj(depth + 1)?;
                    let _lpk = self.read_obj(depth + 1)?;
                    lp.as_str_list()
                } else {
                    let vn = self.read_obj(depth + 1)?;
                    let _fv = self.read_obj(depth + 1)?;
                    let _cv = self.read_obj(depth + 1)?;
                    vn.as_str_list()
                };
                let filename = self.read_obj(depth + 1)?.as_str().unwrap_or("").to_string();
                let name = self
                    .read_obj(depth + 1)?
                    .as_str()
                    .unwrap_or("<codeobj>")
                    .to_string();
                let qualname = if self.magic >= 3450 {
                    self.read_obj(depth + 1)?
                        .as_str()
                        .unwrap_or(&name)
                        .to_string()
                } else {
                    name.clone()
                };
                let firstlineno = self.read_i32()?;
                let _linetable = self.read_obj(depth + 1)?;
                if self.magic >= 3450 {
                    let _exc = self.read_obj(depth + 1)?;
                }
                let consts = match consts_val {
                    MarshalVal::Seq(v) => v,
                    _ => Vec::new(),
                };
                MarshalVal::Code(Box::new(PycCodeObj {
                    argcount,
                    firstlineno,
                    name,
                    qualname,
                    filename,
                    consts,
                    names: names_val.as_str_list(),
                    varnames,
                }))
            }
            _ => return None,
        };

        if let Some(idx) = ref_idx {
            if let Some(slot) = self.refs.get_mut(idx) {
                *slot = val.clone();
            }
        }
        Some(val)
    }
}

#[derive(Default)]
struct PycWalkAcc {
    code_lines: Vec<String>,
    const_strs: Vec<String>,
    seen_consts: std::collections::HashSet<String>,
    sym_names: Vec<String>,
    seen_syms: std::collections::HashSet<String>,
}

fn collect_pyc_walk(code: &PycCodeObj, depth: usize, q_re: Option<&Regex>, acc: &mut PycWalkAcc) {
    if acc.code_lines.len() < 80 {
        let indent = "  ".repeat(depth.min(4));
        let label = if !code.qualname.is_empty() {
            &code.qualname
        } else {
            &code.name
        };
        let locals_s = if code.varnames.is_empty() {
            String::new()
        } else {
            let preview: Vec<&str> = code.varnames.iter().take(6).map(String::as_str).collect();
            format!(" | locals=[{}]", preview.join(", "))
        };
        let refs_s = if code.names.is_empty() {
            String::new()
        } else {
            let preview: Vec<&str> = code.names.iter().take(6).map(String::as_str).collect();
            format!(" | refs=[{}]", preview.join(", "))
        };
        let row = format!(
            "{indent}- `{label}` (args={}, L{}){locals_s}{refs_s}",
            code.argcount, code.firstlineno
        );
        if q_re.map_or(true, |r| r.is_match(&row)) {
            acc.code_lines.push(row);
        }
    }
    for n in &code.names {
        if acc.sym_names.len() < 80
            && !n.is_empty()
            && q_re.map_or(true, |r| r.is_match(n))
            && acc.seen_syms.insert(n.clone())
        {
            acc.sym_names.push(n.clone());
        }
    }
    fn push_const(acc: &mut PycWalkAcc, s: &str, q_re: Option<&Regex>) {
        let clean = s.replace('\r', "").replace('\n', "\\n");
        let trimmed = clean.trim();
        if acc.const_strs.len() < 120
            && trimmed.len() >= 2
            && trimmed.chars().any(|ch| !ch.is_control())
            && q_re.map_or(true, |r| r.is_match(trimmed))
            && acc.seen_consts.insert(trimmed.to_string())
        {
            acc.const_strs.push(trimmed.chars().take(180).collect());
        }
    }
    for c in &code.consts {
        match c {
            MarshalVal::Str(s) => push_const(acc, s, q_re),
            MarshalVal::Code(sub) => collect_pyc_walk(sub, depth + 1, q_re, acc),
            MarshalVal::Seq(items) => {
                for item in items {
                    if let MarshalVal::Str(s) = item {
                        push_const(acc, s, q_re);
                    } else if let MarshalVal::Code(sub) = item {
                        collect_pyc_walk(sub, depth + 1, q_re, acc);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Pure-Rust CPython 3.8–3.14 `.pyc` Marshal v4 Bytecode, Code-Object & Constant-Pool Analyzer.
pub fn parse_pyc_md(bytes: &[u8], query: Option<&str>) -> String {
    if !is_pyc_magic(bytes) {
        return "*(not a valid CPython .pyc file)*".to_string();
    }
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    let py_ver = pyc_python_version(magic);
    let mut reader = MarshalReader::new(bytes, 16, magic);
    let Some(MarshalVal::Code(root)) = reader.read_obj(0) else {
        return format!(
            "## Binary Header: Python Bytecode `.pyc` (Python {py_ver}, magic={magic}, {} B) | SHA-256: `{}`\n*(marshal stream truncated or unsupported opcodes)*",
            bytes.len(),
            sha256_hex(bytes)
        );
    };
    let q_re = query.and_then(|q| {
        Regex::new(&format!("(?i){q}"))
            .or_else(|_| Regex::new(&format!("(?i){}", regex::escape(q))))
            .ok()
    });
    let mut acc = PycWalkAcc::default();
    collect_pyc_walk(&root, 0, q_re.as_ref(), &mut acc);

    let fname = if root.filename.is_empty() {
        "<module>"
    } else {
        root.filename.as_str()
    };
    let mut out = vec![
        format!(
            "## Binary Header: Python Bytecode `.pyc` (Python {py_ver}, magic={magic}, {} B) | `{fname}` | SHA-256: `{}`",
            bytes.len(),
            sha256_hex(bytes)
        ),
    ];
    if !acc.code_lines.is_empty() {
        out.push(format!("### Code Objects ({})", acc.code_lines.len()));
        out.extend(acc.code_lines);
    }
    if !acc.const_strs.is_empty() {
        out.push(format!("### String Constants ({})", acc.const_strs.len()));
        for s in acc.const_strs {
            out.push(format!("- `{s}`"));
        }
    }
    if !acc.sym_names.is_empty() {
        out.push(format!(
            "### Referenced Symbols (co_names, {})",
            acc.sym_names.len()
        ));
        out.push(format!("- `{}`", acc.sym_names.join("`, `")));
    }
    out.join("\n")
}

/// Extract searchable text from a CPython `.pyc` bytecode file for `ap search` (incl. inside `.zip`/`.whl`/`.tar`).
pub fn extract_pyc_searchable_text(bytes: &[u8]) -> String {
    if !is_pyc_magic(bytes) {
        return String::new();
    }
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    let mut reader = MarshalReader::new(bytes, 16, magic);
    let Some(MarshalVal::Code(root)) = reader.read_obj(0) else {
        return String::new();
    };
    let mut out = String::new();
    fn walk_text(c: &PycCodeObj, out: &mut String) {
        if out.len() >= 192 * 1024 {
            return;
        }
        let qn = if !c.qualname.is_empty() {
            &c.qualname
        } else {
            &c.name
        };
        out.push_str(&format!("{}:{}:L{}\n", c.filename, qn, c.firstlineno));
        if !c.names.is_empty() {
            out.push_str(&c.names.join(" "));
            out.push('\n');
        }
        if !c.varnames.is_empty() {
            out.push_str(&c.varnames.join(" "));
            out.push('\n');
        }
        for item in &c.consts {
            match item {
                MarshalVal::Str(s) if !s.is_empty() => {
                    out.push_str(&s.replace('\r', "").replace('\n', "\\n"));
                    out.push('\n');
                }
                MarshalVal::Code(sub) => walk_text(sub, out),
                MarshalVal::Seq(seq) => {
                    for x in seq {
                        if let MarshalVal::Str(s) = x {
                            if !s.is_empty() {
                                out.push_str(&s.replace('\r', "").replace('\n', "\\n"));
                                out.push('\n');
                            }
                        } else if let MarshalVal::Code(sub) = x {
                            walk_text(sub, out);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    walk_text(&root, &mut out);
    out
}

struct PeSection {
    name: String,
    vsize: u32,
    vaddr: u32,
    raw_size: u32,
    raw_ptr: u32,
    chars: u32,
}

fn rva_to_file_offset(rva: u32, secs: &[PeSection]) -> Option<usize> {
    if rva == 0 {
        return None;
    }
    for s in secs {
        let span = s.vsize.max(s.raw_size);
        if rva >= s.vaddr && rva < s.vaddr.saturating_add(span) {
            let delta = rva - s.vaddr;
            if delta < s.raw_size {
                return Some((s.raw_ptr as usize).saturating_add(delta as usize));
            }
        }
    }
    None
}

fn file_offset_to_rva(off: usize, secs: &[PeSection]) -> Option<(u32, &str)> {
    for s in secs {
        let start = s.raw_ptr as usize;
        let end = start.saturating_add(s.raw_size as usize);
        if off >= start && off < end {
            let delta = (off - start) as u32;
            return Some((s.vaddr.saturating_add(delta), s.name.as_str()));
        }
    }
    None
}

struct PeContext {
    is_pe64: bool,
    image_base: u64,
    secs: Vec<PeSection>,
    iat_map: Vec<(u32, String)>,
}

fn is_notable_import(fn_name: &str) -> bool {
    const NOTABLE: [&str; 36] = [
        "CreateProcess",
        "ShellExecute",
        "WinExec",
        "LoadLibrary",
        "GetProcAddress",
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "CryptUnprotectData",
        "CreateNamedPipe",
        "ConnectNamedPipe",
        "ImpersonateNamedPipeClient",
        "DeviceIoControl",
        "IoCreateDevice",
        "IoCreateSymbolicLink",
        "MmMapIoSpace",
        "ZwOpenSection",
        "RpcServerRegisterIf",
        "RpcServerUseProtseq",
        "SetNamedSecurityInfo",
        "CoCreateInstance",
        "MoveFileEx",
        "CreateSymbolicLink",
        "WSAConnect",
        "InternetOpen",
        "WinHttpOpen",
        "URLDownloadToFile",
        "RegSetValue",
        "RegCreateKey",
        "SetWindowsHook",
        "CreateService",
        "OpenProcess",
        "memcpy_s",
        "strcpy",
        "system",
    ];
    NOTABLE.iter().any(|k| fn_name.contains(k))
}

fn parse_pe_details(bytes: &[u8], pe_off: usize, out: &mut Vec<String>) -> PeContext {
    let machine = read_u16_le(bytes, pe_off + 4).unwrap_or(0);
    let n_sec = read_u16_le(bytes, pe_off + 6).unwrap_or(0) as usize;
    let opt_sz = read_u16_le(bytes, pe_off + 20).unwrap_or(0) as usize;
    let arch = match machine {
        0x8664 => "x86_64",
        0x014c => "x86",
        0xaa64 => "ARM64",
        _ => "other",
    };

    let opt_off = pe_off + 24;
    let opt_magic = if opt_sz >= 2 {
        read_u16_le(bytes, opt_off).unwrap_or(0)
    } else {
        0
    };
    let is_pe64 = opt_magic == 0x020B;
    let image_base = if is_pe64 && opt_sz >= 32 {
        read_u64_le(bytes, opt_off + 24).unwrap_or(0x0001_4000_0000)
    } else if !is_pe64 && opt_sz >= 32 {
        read_u32_le(bytes, opt_off + 28).unwrap_or(0x0040_0000) as u64
    } else {
        0
    };
    let entry_rva = if opt_sz >= 20 {
        read_u32_le(bytes, opt_off + 16).unwrap_or(0)
    } else {
        0
    };
    let mut mitigations = Vec::new();
    if opt_sz >= 72 {
        let dll_chars = read_u16_le(bytes, opt_off + 70).unwrap_or(0);
        if (dll_chars & 0x0040) != 0 {
            mitigations.push("ASLR");
        }
        if (dll_chars & 0x0100) != 0 {
            mitigations.push("NX/DEP");
        }
        if (dll_chars & 0x4000) != 0 {
            mitigations.push("CFG");
        }
        if (dll_chars & 0x0020) != 0 {
            mitigations.push("HighEntropyVA");
        }
    }

    let mut secs = Vec::new();
    let sec_base = opt_off + opt_sz;
    for s in 0..n_sec.min(32) {
        let off = sec_base + s * 40;
        if off + 40 > bytes.len() {
            break;
        }
        let nm = String::from_utf8_lossy(&bytes[off..off + 8])
            .trim_end_matches('\0')
            .to_string();
        secs.push(PeSection {
            name: if nm.is_empty() { format!("sec{s}") } else { nm },
            vsize: read_u32_le(bytes, off + 8).unwrap_or(0),
            vaddr: read_u32_le(bytes, off + 12).unwrap_or(0),
            raw_size: read_u32_le(bytes, off + 16).unwrap_or(0),
            raw_ptr: read_u32_le(bytes, off + 20).unwrap_or(0),
            chars: read_u32_le(bytes, off + 36).unwrap_or(0),
        });
    }

    let sec_names: Vec<&str> = secs.iter().map(|s| s.name.as_str()).collect();
    out.push(format!(
        "## Binary Header: Windows PE ({arch}, {} B, entry=0x{entry_rva:x}, sections: [{}])",
        bytes.len(),
        sec_names.join(", ")
    ));
    let ent = shannon_entropy(&bytes[..bytes.len().min(4 * 1024 * 1024)]);
    let ent_tag = if ent > 7.2 {
        " [HIGH-ENTROPY/PACKED]"
    } else {
        ""
    };
    out.push(format!(
        "- SHA-256: `{}` | Entropy: `{ent:.2}`{ent_tag} | Mitigations: `[{}]`",
        sha256_hex(bytes),
        if mitigations.is_empty() {
            "none".to_string()
        } else {
            mitigations.join(", ")
        }
    ));

    if !secs.is_empty() {
        let mut sec_rows = Vec::new();
        for s in &secs {
            let mut perm = String::new();
            if (s.chars & 0x4000_0000) != 0 {
                perm.push('R');
            }
            if (s.chars & 0x8000_0000) != 0 {
                perm.push('W');
            }
            if (s.chars & 0x2000_0000) != 0 {
                perm.push('X');
            }
            let s_ent = bytes
                .get(
                    s.raw_ptr as usize
                        ..(s.raw_ptr as usize)
                            .saturating_add((s.raw_size as usize).min(1024 * 1024)),
                )
                .map(shannon_entropy)
                .unwrap_or(0.0);
            let rwx_flag = if (s.chars & 0xE000_0000) == 0xE000_0000 {
                " [RWX!]"
            } else {
                ""
            };
            sec_rows.push(format!(
                "`{}` (rva=0x{:x} raw={}B {}{} ent={:.2})",
                s.name, s.vaddr, s.raw_size, perm, rwx_flag, s_ent
            ));
        }
        out.push(format!(
            "### PE Sections ({}): {}",
            secs.len(),
            sec_rows.join(" · ")
        ));
    }

    // Embedded RPC server interface scanner (NDR20 / NDR64 TransferSyntax GUIDs in .rdata/.data)
    let rpc_ifaces = scan_pe_rpc_interfaces(bytes, is_pe64);
    if !rpc_ifaces.is_empty() {
        out.push(format!(
            "### Embedded RPC Interfaces ({}): {}",
            rpc_ifaces.len(),
            rpc_ifaces.join(" · ")
        ));
    }

    // .NET CLR BSJB metadata scanner (auto-detects managed assemblies & notable managed APIs)
    if let Some((clr_ver, clr_sinks)) = scan_dotnet_clr_meta(bytes) {
        let sinks_s = if clr_sinks.is_empty() {
            "none flagged".to_string()
        } else {
            format!("`{}`", clr_sinks.join("`, `"))
        };
        out.push(format!(
            "### .NET CLR Assembly (`{clr_ver}`) | Notable Managed APIs: {sinks_s}"
        ));
    }

    let dd_off = opt_off + if is_pe64 { 112 } else { 96 };
    // 1. Export Directory (index 0)
    if opt_sz >= if is_pe64 { 120 } else { 104 } {
        let exp_rva = read_u32_le(bytes, dd_off).unwrap_or(0);
        if let Some(exp_off) = rva_to_file_offset(exp_rva, &secs) {
            let n_names = read_u32_le(bytes, exp_off + 24).unwrap_or(0) as usize;
            let names_rva = read_u32_le(bytes, exp_off + 32).unwrap_or(0);
            if let Some(names_off) = rva_to_file_offset(names_rva, &secs) {
                let mut exports = Vec::new();
                for idx in 0..n_names.min(60) {
                    if let Some(nrva) = read_u32_le(bytes, names_off + idx * 4) {
                        if let Some(noff) = rva_to_file_offset(nrva, &secs) {
                            if let Some(nm) = read_cstr(bytes, noff, 128) {
                                exports.push(nm);
                            }
                        }
                    }
                }
                if !exports.is_empty() {
                    out.push(format!(
                        "### PE Exports ({} shown / {} total): {}",
                        exports.len(),
                        n_names,
                        exports.join(", ")
                    ));
                }
            }
        }
    }

    // 2. Import Directory (index 1)
    let mut iat_map: Vec<(u32, String)> = Vec::new();
    if opt_sz >= if is_pe64 { 128 } else { 112 } {
        let imp_rva = read_u32_le(bytes, dd_off + 8).unwrap_or(0);
        if let Some(imp_off) = rva_to_file_offset(imp_rva, &secs) {
            let mut dll_lines = Vec::new();
            let mut notable = Vec::new();
            for d_idx in 0..64usize {
                let desc = imp_off + d_idx * 20;
                if desc + 20 > bytes.len() {
                    break;
                }
                let oft = read_u32_le(bytes, desc).unwrap_or(0);
                let name_rva = read_u32_le(bytes, desc + 12).unwrap_or(0);
                let ft = read_u32_le(bytes, desc + 16).unwrap_or(0);
                if oft == 0 && name_rva == 0 && ft == 0 {
                    break;
                }
                let dll_name = rva_to_file_offset(name_rva, &secs)
                    .and_then(|o| read_cstr(bytes, o, 128))
                    .unwrap_or_else(|| format!("dll@{name_rva:#x}"));
                let thunk_rva = if oft != 0 { oft } else { ft };
                let mut funcs = Vec::new();
                if let Some(mut t_off) = rva_to_file_offset(thunk_rva, &secs) {
                    let step = if is_pe64 { 8 } else { 4 };
                    for slot_idx in 0..256u32 {
                        let val: u64 = if is_pe64 {
                            read_u64_le(bytes, t_off).unwrap_or(0)
                        } else {
                            read_u32_le(bytes, t_off).unwrap_or(0) as u64
                        };
                        if val == 0 {
                            break;
                        }
                        t_off += step;
                        let is_ord = if is_pe64 {
                            (val & (1u64 << 63)) != 0
                        } else {
                            (val & (1u64 << 31)) != 0
                        };
                        if is_ord {
                            if funcs.len() < 16 {
                                funcs.push(format!("#{}", val & 0xFFFF));
                            }
                        } else if let Some(hn_off) =
                            rva_to_file_offset((val & 0x7FFF_FFFF) as u32, &secs)
                        {
                            if let Some(fn_name) = read_cstr(bytes, hn_off + 2, 128) {
                                if ft != 0 && iat_map.len() < 4096 {
                                    let slot_rva =
                                        ft.saturating_add(slot_idx.saturating_mul(step as u32));
                                    iat_map.push((slot_rva, format!("{dll_name}!{fn_name}")));
                                }
                                if is_notable_import(&fn_name) && notable.len() < 32 {
                                    notable.push(format!("{dll_name}!{fn_name}"));
                                }
                                if funcs.len() < 16 {
                                    funcs.push(fn_name);
                                }
                            }
                        }
                    }
                }
                dll_lines.push(format!(
                    "- `{dll_name}`: {}",
                    if funcs.is_empty() {
                        "(ordinals/stripped)".to_string()
                    } else {
                        funcs.join(", ")
                    }
                ));
            }
            if !dll_lines.is_empty() {
                out.push(format!("### PE Imports ({} DLLs)", dll_lines.len()));
                if !notable.is_empty() {
                    out.push(format!("- **Notable APIs**: `{}`", notable.join("`, `")));
                }
                out.extend(dll_lines);
            }
        }
    }

    append_pe_delay_imports(bytes, opt_sz, dd_off, is_pe64, image_base, &secs, out);
    append_pe_debug_and_sig_metadata(bytes, opt_sz, dd_off, is_pe64, &secs, out);
    append_pe_manifest_and_version_info(bytes, &secs, out);

    PeContext {
        is_pe64,
        image_base,
        secs,
        iat_map,
    }
}

fn delay_addr_to_rva(val: u32, gr_attrs: u32, image_base: u64) -> u32 {
    if (gr_attrs & 1) != 0 {
        val
    } else {
        let base_lo = (image_base & 0xFFFF_FFFF) as u32;
        if val >= base_lo {
            val - base_lo
        } else {
            val
        }
    }
}

fn append_pe_delay_imports(
    bytes: &[u8],
    opt_sz: usize,
    dd_off: usize,
    is_pe64: bool,
    image_base: u64,
    secs: &[PeSection],
    out: &mut Vec<String>,
) {
    let min_opt = if is_pe64 { 224 } else { 208 };
    if opt_sz < min_opt {
        return;
    }
    let delay_rva = read_u32_le(bytes, dd_off + 13 * 8).unwrap_or(0);
    let Some(delay_off) = rva_to_file_offset(delay_rva, secs) else {
        return;
    };
    let mut dll_lines = Vec::new();
    let mut notable = Vec::new();
    for idx in 0..48usize {
        let desc = delay_off.saturating_add(idx * 32);
        if desc + 32 > bytes.len() {
            break;
        }
        let gr_attrs = read_u32_le(bytes, desc).unwrap_or(0);
        let name_val = read_u32_le(bytes, desc + 4).unwrap_or(0);
        let iat_val = read_u32_le(bytes, desc + 12).unwrap_or(0);
        let int_val = read_u32_le(bytes, desc + 16).unwrap_or(0);
        if name_val == 0 && iat_val == 0 && int_val == 0 {
            break;
        }
        let name_rva = delay_addr_to_rva(name_val, gr_attrs, image_base);
        let dll_name = rva_to_file_offset(name_rva, secs)
            .and_then(|o| read_cstr(bytes, o, 128))
            .unwrap_or_else(|| format!("delay_dll@{name_rva:#x}"));
        let thunk_rva = delay_addr_to_rva(
            if int_val != 0 { int_val } else { iat_val },
            gr_attrs,
            image_base,
        );
        let mut funcs = Vec::new();
        if let Some(mut t_off) = rva_to_file_offset(thunk_rva, secs) {
            let step = if is_pe64 { 8 } else { 4 };
            for _ in 0..128usize {
                let val: u64 = if is_pe64 {
                    read_u64_le(bytes, t_off).unwrap_or(0)
                } else {
                    read_u32_le(bytes, t_off).unwrap_or(0) as u64
                };
                if val == 0 {
                    break;
                }
                t_off += step;
                let is_ord = if is_pe64 {
                    (val & (1u64 << 63)) != 0
                } else {
                    (val & (1u64 << 31)) != 0
                };
                if is_ord {
                    if funcs.len() < 16 {
                        funcs.push(format!("#{}", val & 0xFFFF));
                    }
                } else {
                    let hn_rva =
                        delay_addr_to_rva((val & 0x7FFF_FFFF) as u32, gr_attrs, image_base);
                    if let Some(hn_off) = rva_to_file_offset(hn_rva, secs) {
                        if let Some(fn_name) = read_cstr(bytes, hn_off + 2, 128) {
                            if is_notable_import(&fn_name) && notable.len() < 24 {
                                notable.push(format!("{dll_name}!{fn_name}"));
                            }
                            if funcs.len() < 16 {
                                funcs.push(fn_name);
                            }
                        }
                    }
                }
            }
        }
        dll_lines.push(format!(
            "- `{dll_name}`: {}",
            if funcs.is_empty() {
                "(ordinals/stripped)".to_string()
            } else {
                funcs.join(", ")
            }
        ));
    }
    if !dll_lines.is_empty() {
        out.push(format!(
            "### PE Delay-Load Imports ({} DLLs)",
            dll_lines.len()
        ));
        if !notable.is_empty() {
            out.push(format!(
                "- **Notable Delayed APIs**: `{}`",
                notable.join("`, `")
            ));
        }
        out.extend(dll_lines);
    }
}

fn append_pe_debug_and_sig_metadata(
    bytes: &[u8],
    opt_sz: usize,
    dd_off: usize,
    is_pe64: bool,
    secs: &[PeSection],
    out: &mut Vec<String>,
) {
    // Debug Directory DataDirectory[6] (CodeView RSDS PDB path + GUID + Age)
    let min_dbg = if is_pe64 { 168 } else { 152 };
    if opt_sz >= min_dbg {
        let dbg_rva = read_u32_le(bytes, dd_off + 6 * 8).unwrap_or(0);
        let dbg_sz = read_u32_le(bytes, dd_off + 6 * 8 + 4).unwrap_or(0) as usize;
        if let Some(dbg_off) = rva_to_file_offset(dbg_rva, secs) {
            for idx in 0..(dbg_sz / 28).min(16) {
                let ent = dbg_off.saturating_add(idx * 28);
                if ent + 28 > bytes.len() {
                    break;
                }
                let kind = read_u32_le(bytes, ent + 12).unwrap_or(0);
                let sz = read_u32_le(bytes, ent + 16).unwrap_or(0) as usize;
                let raw_ptr = read_u32_le(bytes, ent + 24).unwrap_or(0) as usize;
                if kind == 2
                    && sz >= 25
                    && raw_ptr.saturating_add(sz) <= bytes.len()
                    && bytes.get(raw_ptr..raw_ptr + 4) == Some(b"RSDS")
                {
                    {
                        let d1 = read_u32_le(bytes, raw_ptr + 4).unwrap_or(0);
                        let d2 = read_u16_le(bytes, raw_ptr + 8).unwrap_or(0);
                        let d3 = read_u16_le(bytes, raw_ptr + 10).unwrap_or(0);
                        let d4 = &bytes[raw_ptr + 12..raw_ptr + 20];
                        let age = read_u32_le(bytes, raw_ptr + 20).unwrap_or(0);
                        let guid = format!(
                            "{d1:08X}{d2:04X}{d3:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                            d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
                        );
                        if let Some(pdb) = read_cstr(bytes, raw_ptr + 24, 260) {
                            if !pdb.is_empty() {
                                out.push(format!("- Debug PDB: `{pdb}` (guid=`{guid}` age={age})"));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Security Directory DataDirectory[4] (FILE OFFSET, NOT RVA) + PE Overlay size
    let min_sec = if is_pe64 { 152 } else { 136 };
    let mut cert_file_off = None;
    if opt_sz >= min_sec {
        let cert_off = read_u32_le(bytes, dd_off + 4 * 8).unwrap_or(0) as usize;
        let cert_sz = read_u32_le(bytes, dd_off + 4 * 8 + 4).unwrap_or(0) as usize;
        if cert_off > 0 && cert_sz >= 8 && cert_off.saturating_add(cert_sz) <= bytes.len() {
            cert_file_off = Some(cert_off);
            let blob = &bytes[cert_off..cert_off + cert_sz];
            let mut cns: Vec<String> = Vec::new();
            let mut i = 0usize;
            while i + 5 < blob.len() && cns.len() < 8 {
                if blob[i] == 0x55
                    && blob[i + 1] == 0x04
                    && (blob[i + 2] == 0x03 || blob[i + 2] == 0x0A)
                {
                    let tag = blob[i + 3];
                    let slen = blob[i + 4] as usize;
                    if matches!(tag, 0x0C | 0x13 | 0x16 | 0x14)
                        && (1..=96).contains(&slen)
                        && i + 5 + slen <= blob.len()
                    {
                        if let Ok(s) = std::str::from_utf8(&blob[i + 5..i + 5 + slen]) {
                            let clean = s.trim();
                            if !clean.is_empty()
                                && clean.is_ascii()
                                && !cns.iter().any(|x| x == clean)
                            {
                                cns.push(clean.to_string());
                            }
                        }
                        i += 5 + slen;
                        continue;
                    }
                }
                i += 1;
            }
            if cns.is_empty() {
                out.push(format!(
                    "- Authenticode: signed ({cert_sz} B @0x{cert_off:x})"
                ));
            } else {
                out.push(format!(
                    "- Authenticode: signed ({cert_sz} B @0x{cert_off:x}) | Certs: `{}`",
                    cns.join("` · `")
                ));
            }
        }
    }
    let max_sec_end = secs
        .iter()
        .map(|s| (s.raw_ptr as usize).saturating_add(s.raw_size as usize))
        .max()
        .unwrap_or(0);
    if max_sec_end > 0 {
        let data_end = cert_file_off
            .filter(|&c| c >= max_sec_end && c <= bytes.len())
            .unwrap_or(bytes.len());
        if data_end >= max_sec_end + 64 {
            out.push(format!(
                "- Overlay: {} B @0x{max_sec_end:x}",
                data_end - max_sec_end
            ));
        }
    }
}

fn append_pe_manifest_and_version_info(bytes: &[u8], secs: &[PeSection], out: &mut Vec<String>) {
    let rsrc_slice: &[u8] = secs
        .iter()
        .find(|s| s.name.starts_with(".rsrc"))
        .and_then(|s| {
            let st = s.raw_ptr as usize;
            let len = (s.raw_size as usize).min(6 * 1024 * 1024);
            bytes.get(st..st.saturating_add(len).min(bytes.len()))
        })
        .unwrap_or_else(|| &bytes[bytes.len().saturating_sub(2 * 1024 * 1024)..]);

    // UAC RT_MANIFEST summary
    if let Some(mpos) = rsrc_slice
        .windows(24)
        .position(|w| w == b"<requestedExecutionLevel")
    {
        let win_end = (mpos + 512).min(rsrc_slice.len());
        let snippet = String::from_utf8_lossy(&rsrc_slice[mpos..win_end]);
        let extract_attr = |k: &str| -> Option<String> {
            let pat = format!("{k}=\"");
            let idx = snippet.find(&pat)?;
            let rest = &snippet[idx + pat.len()..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        };
        let mut parts = Vec::new();
        if let Some(lvl) = extract_attr("level") {
            parts.push(format!("level={lvl}"));
        }
        if let Some(uia) = extract_attr("uiAccess") {
            parts.push(format!("uiAccess={uia}"));
        }
        let full_lo = String::from_utf8_lossy(&rsrc_slice[mpos.saturating_sub(300)..win_end]);
        if full_lo.contains("<autoElevate") && full_lo.contains("true") {
            parts.push("autoElevate=true".to_string());
        }
        if !parts.is_empty() {
            out.push(format!("- UAC Manifest: `{}`", parts.join("` · `")));
        }
    }

    // UTF-16LE VS_VERSION_INFO string properties
    let mut ver_pairs = Vec::new();
    for key in [
        "CompanyName",
        "ProductName",
        "FileDescription",
        "FileVersion",
        "OriginalFilename",
    ] {
        let mut needle: Vec<u8> = Vec::with_capacity((key.len() + 1) * 2);
        for u in key.encode_utf16() {
            needle.extend_from_slice(&u.to_le_bytes());
        }
        needle.extend_from_slice(&[0, 0]);
        let Some(pos) = rsrc_slice
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
        else {
            continue;
        };
        let mut v_off = pos + needle.len();
        // Skip up to 6 padding zero bytes for DWORD alignment before value UTF-16LE string
        let max_skip = (v_off + 6).min(rsrc_slice.len().saturating_sub(1));
        while v_off + 1 < max_skip && rsrc_slice[v_off] == 0 && rsrc_slice[v_off + 1] == 0 {
            v_off += 2;
        }
        let mut code_units = Vec::new();
        let mut cur = v_off;
        while cur + 1 < rsrc_slice.len() && code_units.len() < 96 {
            let u = u16::from_le_bytes([rsrc_slice[cur], rsrc_slice[cur + 1]]);
            if u == 0 {
                break;
            }
            if u < 0x20 || u == 0x7F {
                code_units.clear();
                break;
            }
            code_units.push(u);
            cur += 2;
        }
        if !code_units.is_empty() {
            let val = String::from_utf16_lossy(&code_units);
            let clean = val.trim();
            if !clean.is_empty() {
                ver_pairs.push(format!("{key}=\"{clean}\""));
            }
        }
    }
    if !ver_pairs.is_empty() {
        out.push(format!("- VersionInfo: {}", ver_pairs.join(" · ")));
    }
}

fn find_enclosing_x64_func_rva(sec_bytes: &[u8], sec_vaddr: u32, insn_rel: usize) -> u32 {
    let min_back = insn_rel.saturating_sub(4096);
    let mut cur = insn_rel;
    while cur > min_back {
        cur -= 1;
        let b = sec_bytes[cur];
        // Padding byte (INT3 0xCC or NOP 0x90) immediately preceding function prologue
        if (b == 0xCC || b == 0x90) && cur + 1 < insn_rel {
            let nxt = sec_bytes[cur + 1];
            if nxt != 0xCC && nxt != 0x90 {
                return sec_vaddr.saturating_add((cur + 1) as u32);
            }
        }
        // Standard MSVC/Clang x64 prologues at 16-byte aligned boundary
        if cur % 16 == 0 && cur + 3 < sec_bytes.len() {
            let b0 = sec_bytes[cur];
            let b1 = sec_bytes[cur + 1];
            let b2 = sec_bytes[cur + 2];
            if (b0 == 0x48 && b1 == 0x89 && b2 == 0x5C)
                || (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC)
                || (b0 == 0x48 && b1 == 0x81 && b2 == 0xEC)
                || (b0 == 0x40 && (b1 == 0x53 || b1 == 0x55 || b1 == 0x56 || b1 == 0x57))
                || (b0 == 0x55 && b1 == 0x48)
                || (b0 == 0x4C && b1 == 0x8B && b2 == 0xDC)
            {
                return sec_vaddr.saturating_add(cur as u32);
            }
        }
    }
    sec_vaddr.saturating_add(min_back as u32)
}

/// Pure-Rust `<20ms` x64 PE RIP-relative String (`LEA`) & IAT Import (`CALL`/`JMP`) cross-reference scanner.
fn scan_pe64_xrefs(
    bytes: &[u8],
    pe: &PeContext,
    str_rvas: &[(u32, String)],
    q_re: Option<&Regex>,
    max_xrefs: usize,
) -> Vec<String> {
    if !pe.is_pe64 {
        return Vec::new();
    }
    let mut str_lookup = std::collections::HashMap::<u32, &str>::new();
    for (rva, s) in str_rvas {
        str_lookup.insert(*rva, s.as_str());
    }
    let mut iat_lookup = std::collections::HashMap::<u32, &str>::new();
    for (rva, sym) in &pe.iat_map {
        let keep = match q_re {
            Some(re) => re.is_match(sym),
            None => is_notable_import(sym),
        };
        if keep {
            iat_lookup.insert(*rva, sym.as_str());
        }
    }
    if str_lookup.is_empty() && iat_lookup.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::<(u32, u32)>::new();
    for s in &pe.secs {
        // IMAGE_SCN_MEM_EXECUTE (0x20000000)
        if (s.chars & 0x2000_0000) == 0 || s.raw_size < 7 {
            continue;
        }
        let start = s.raw_ptr as usize;
        let len = (s.raw_size as usize).min(16 * 1024 * 1024);
        let Some(code) = bytes.get(start..start.saturating_add(len).min(bytes.len())) else {
            continue;
        };
        let mut i = 0usize;
        while i + 7 <= code.len() && out.len() < max_xrefs {
            let b0 = code[i];
            let b1 = code[i + 1];
            // 1. x64 RIP-relative `LEA reg, [RIP + disp32]` -> 48/4C 8D (mod=00, rm=101) disp32
            if !str_lookup.is_empty() && (b0 == 0x48 || b0 == 0x4C) && b1 == 0x8D {
                let modrm = code[i + 2];
                if (modrm & 0xC7) == 0x05 {
                    let disp =
                        i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
                    let insn_rva = s.vaddr.saturating_add(i as u32);
                    let target = (insn_rva as i64) + 7 + (disp as i64);
                    if target > 0 && target <= u32::MAX as i64 {
                        let trva = target as u32;
                        if let Some(sv) = str_lookup.get(&trva) {
                            if seen.insert((insn_rva, trva)) {
                                let func_rva = find_enclosing_x64_func_rva(code, s.vaddr, i);
                                let func_va = pe.image_base.saturating_add(func_rva as u64);
                                let preview: String = sv.chars().take(72).collect();
                                out.push(format!(
                                    "- [str-xref] insn=0x{insn_rva:x} in func_rva=0x{func_rva:x} (va=0x{func_va:x}) -> rva=0x{trva:x} `{preview}`"
                                ));
                                i += 7;
                                continue;
                            }
                        }
                    }
                }
            }
            // 2. x64 RIP-relative `CALL/JMP [RIP + disp32]` -> FF 15/25 disp32
            if !iat_lookup.is_empty()
                && b0 == 0xFF
                && (b1 == 0x15 || b1 == 0x25)
                && i + 6 <= code.len()
            {
                let disp = i32::from_le_bytes([code[i + 2], code[i + 3], code[i + 4], code[i + 5]]);
                let insn_rva = s.vaddr.saturating_add(i as u32);
                let target = (insn_rva as i64) + 6 + (disp as i64);
                if target > 0 && target <= u32::MAX as i64 {
                    let trva = target as u32;
                    if let Some(sym) = iat_lookup.get(&trva) {
                        if seen.insert((insn_rva, trva)) {
                            let func_rva = find_enclosing_x64_func_rva(code, s.vaddr, i);
                            let func_va = pe.image_base.saturating_add(func_rva as u64);
                            let op = if b1 == 0x15 { "call" } else { "jmp" };
                            out.push(format!(
                                "- [iat-xref] {op} insn=0x{insn_rva:x} in func_rva=0x{func_rva:x} (va=0x{func_va:x}) -> `{sym}` (iat=0x{trva:x})"
                            ));
                            i += 6;
                            continue;
                        }
                    }
                }
            }
            i += 1;
        }
    }
    out
}

fn format_guid_le(b: &[u8]) -> Option<String> {
    if b.len() < 16 {
        return None;
    }
    let d1 = read_u32_le(b, 0)?;
    let d2 = read_u16_le(b, 4)?;
    let d3 = read_u16_le(b, 6)?;
    Some(format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

/// Pure-Rust scanner for embedded Windows MS-RPC `RPC_SERVER_INTERFACE` descriptors (NDR20 & NDR64).
fn scan_pe_rpc_interfaces(bytes: &[u8], is_pe64: bool) -> Vec<String> {
    // NDR20 TransferSyntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
    const NDR20: [u8; 16] = [
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60,
    ];
    // NDR64 TransferSyntax UUID: 71710533-beba-4937-8319-b5dbef9ccc36
    const NDR64: [u8; 16] = [
        0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc,
        0x36,
    ];
    let expected_len: u32 = if is_pe64 { 0x60 } else { 0x44 };
    let scan_lim = bytes.len().min(16 * 1024 * 1024);
    let data = &bytes[..scan_lim];
    let mut found: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (tag, needle) in [("NDR20", &NDR20), ("NDR64", &NDR64)] {
        let mut pos = 24usize;
        while pos + 16 <= data.len() && found.len() < 16 {
            if let Some(rel) = data[pos..].windows(16).position(|w| w == needle) {
                let hit = pos + rel;
                // RPC_SERVER_INTERFACE layout:
                // +0x00 Length (u32 == 0x60 on x64 / 0x44 on x86)
                // +0x04 InterfaceId.SyntaxGUID (16B) + Major/Minor (u16/u16)
                // +0x18 TransferSyntax.SyntaxGUID (16B == NDR20/NDR64)
                if hit >= 24 {
                    let base = hit - 24;
                    let len_field = read_u32_le(data, base).unwrap_or(0);
                    if len_field == expected_len || len_field == 0x60 || len_field == 0x44 {
                        if let Some(uuid) = format_guid_le(&data[base + 4..base + 20]) {
                            let maj = read_u16_le(data, base + 20).unwrap_or(0);
                            let min = read_u16_le(data, base + 22).unwrap_or(0);
                            if uuid != "00000000-0000-0000-0000-000000000000"
                                && seen.insert(uuid.clone())
                            {
                                found.push(format!("`{uuid}` v{maj}.{min} ({tag} @0x{base:x})"));
                            }
                        }
                    }
                }
                pos = hit + 16;
            } else {
                break;
            }
        }
    }
    found
}

struct ElfSection {
    name: String,
    vaddr: u64,
    raw_ptr: usize,
    raw_size: usize,
    flags: u64,
}

struct ElfContext {
    is_64: bool,
    machine: u16,
    secs: Vec<ElfSection>,
    func_syms: Vec<(u64, String)>,
}

fn elf_file_offset_to_vaddr(off: usize, secs: &[ElfSection]) -> Option<(u64, &str)> {
    for s in secs {
        if s.vaddr == 0 || s.raw_size == 0 {
            continue;
        }
        let end = s.raw_ptr.saturating_add(s.raw_size);
        if off >= s.raw_ptr && off < end {
            return Some((
                s.vaddr.saturating_add((off - s.raw_ptr) as u64),
                s.name.as_str(),
            ));
        }
    }
    None
}

fn is_notable_elf_symbol(nm: &str) -> bool {
    const NOTABLE: [&str; 26] = [
        "system",
        "popen",
        "execve",
        "execl",
        "execlp",
        "dlopen",
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "gets",
        "memcpy_s",
        "ioctl",
        "mprotect",
        "chmod",
        "chown",
        "setuid",
        "setgid",
        "symlink",
        "mktemp",
        "tmpnam",
        "OnRemoteRequest",
        "ReadFileDescriptor",
        "ReadBuffer",
        "ReadRawData",
        "Unmarshalling",
    ];
    NOTABLE.iter().any(|k| nm == *k || nm.contains(k))
}

fn is_go_stdlib_func(nm: &str) -> bool {
    const STD: [&str; 24] = [
        "runtime.",
        "runtime/",
        "internal/",
        "reflect.",
        "syscall.",
        "sync.",
        "sync/",
        "fmt.",
        "strings.",
        "strconv.",
        "bytes.",
        "bufio.",
        "io.",
        "os.",
        "path.",
        "sort.",
        "time.",
        "unicode",
        "encoding/",
        "crypto/",
        "net/http.",
        "vendor/",
        "type:",
        "go:",
    ];
    STD.iter().any(|p| nm.starts_with(p))
}

/// Pure-Rust Go 1.18+ / 1.20+ `.gopclntab` user function extractor (works on both PE and ELF Go binaries).
fn scan_go_pclntab_funcs(bytes: &[u8], q_re: Option<&Regex>, max_funcs: usize) -> Vec<String> {
    // Go 1.20+ magic: 0xFFFFFFF1 (LE: f1 ff ff ff 00 00), Go 1.18-1.19 magic: 0xFFFFFFF0 (LE: f0 ff ff ff 00 00)
    const MAGICS: [[u8; 6]; 2] = [
        [0xF1, 0xFF, 0xFF, 0xFF, 0x00, 0x00],
        [0xF0, 0xFF, 0xFF, 0xFF, 0x00, 0x00],
    ];
    let mut tab_off: Option<usize> = None;
    let scan_end = bytes.len().min(32 * 1024 * 1024);
    for magic in &MAGICS {
        let mut pos = 0usize;
        while pos + 80 <= scan_end {
            let Some(rel) = bytes[pos..scan_end].windows(6).position(|w| w == magic) else {
                break;
            };
            let cand = pos + rel;
            let min_lc = bytes[cand + 6];
            let ptr_sz = bytes[cand + 7];
            if (min_lc == 1 || min_lc == 2 || min_lc == 4) && (ptr_sz == 4 || ptr_sz == 8) {
                let nfunc = if ptr_sz == 8 {
                    read_u64_le(bytes, cand + 8).unwrap_or(0) as usize
                } else {
                    read_u32_le(bytes, cand + 8).unwrap_or(0) as usize
                };
                if (1..=500_000).contains(&nfunc) {
                    tab_off = Some(cand);
                    break;
                }
            }
            pos = cand + 4;
        }
        if tab_off.is_some() {
            break;
        }
    }
    let Some(base) = tab_off else {
        return Vec::new();
    };
    let ptr_sz = bytes[base + 7] as usize;
    let read_ptr = |off: usize| -> Option<u64> {
        if ptr_sz == 8 {
            read_u64_le(bytes, off)
        } else {
            read_u32_le(bytes, off).map(|v| v as u64)
        }
    };
    // Go 1.18+ pcHeader layout (8-byte header + 8 pointer-sized fields):
    // +8: nfunc, +8+1p: nfiles, +8+2p: textStart, +8+3p: funcnameOffset, +8+4p: cuOffset,
    // +8+5p: filetabOffset, +8+6p: pctabOffset, +8+7p: pclnOffset
    let nfunc = read_ptr(base + 8).unwrap_or(0) as usize;
    let text_start = read_ptr(base + 8 + 2 * ptr_sz).unwrap_or(0);
    let funcname_off = read_ptr(base + 8 + 3 * ptr_sz).unwrap_or(0) as usize;
    let pcln_off = read_ptr(base + 8 + 7 * ptr_sz).unwrap_or(0) as usize;
    let fn_tab_base = base.saturating_add(pcln_off);
    let fn_names_base = base.saturating_add(funcname_off);
    if fn_tab_base >= bytes.len() || fn_names_base >= bytes.len() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::<String>::new();
    // In Go 1.18+, each functab entry is two uint32s: (entryoff, funcoff) relative to textStart / pcln_base
    for idx in 0..nfunc.min(80_000) {
        let ent = fn_tab_base.saturating_add(idx.saturating_mul(8));
        if ent + 8 > bytes.len() {
            break;
        }
        let entry_off = read_u32_le(bytes, ent).unwrap_or(0) as u64;
        let func_info_off = read_u32_le(bytes, ent + 4).unwrap_or(0) as usize;
        let fi = fn_tab_base.saturating_add(func_info_off);
        if fi + 8 > bytes.len() {
            continue;
        }
        // _func struct starts with entryOff (u32), nameOff (i32)
        let name_off = read_u32_le(bytes, fi + 4).unwrap_or(0) as usize;
        if let Some(nm) = read_cstr(bytes, fn_names_base.saturating_add(name_off), 180) {
            if nm.len() < 3 || is_go_stdlib_func(&nm) {
                continue;
            }
            if let Some(re) = q_re {
                if !re.is_match(&nm) {
                    continue;
                }
            }
            if seen.insert(nm.clone()) {
                let pc = text_start.saturating_add(entry_off);
                out.push(format!("`{nm}` (pc=0x{pc:x})"));
                if out.len() >= max_funcs {
                    break;
                }
            }
        }
    }
    out
}

fn find_enclosing_elf_func(elf: &ElfContext, vaddr: u64) -> String {
    // Find nearest symbol <= vaddr within 64 KB
    let mut best: Option<(u64, &str)> = None;
    for (sa, nm) in &elf.func_syms {
        if *sa <= vaddr && vaddr - *sa < 0x10000 && best.map(|(ba, _)| *sa > ba).unwrap_or(true) {
            best = Some((*sa, nm.as_str()));
        }
    }
    if let Some((sa, nm)) = best {
        format!("`{nm}`+0x{:x} (0x{sa:x})", vaddr - sa)
    } else {
        format!("vaddr=0x{vaddr:x}")
    }
}

/// Pure-Rust `<20ms` ELF64 x86_64 RIP-relative (`LEA`) & AArch64 (`ADRP+ADD`) string XREF scanner.
fn scan_elf64_xrefs(
    bytes: &[u8],
    elf: &ElfContext,
    str_vaddrs: &[(u64, String)],
    max_xrefs: usize,
) -> Vec<String> {
    if !elf.is_64 || str_vaddrs.is_empty() {
        return Vec::new();
    }
    let mut str_lookup = std::collections::HashMap::<u64, &str>::new();
    for (va, s) in str_vaddrs {
        str_lookup.insert(*va, s.as_str());
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::<(u64, u64)>::new();

    for sec in &elf.secs {
        // SHF_EXECINSTR (0x4)
        if (sec.flags & 0x4) == 0 || sec.raw_size < 8 {
            continue;
        }
        let len = sec.raw_size.min(16 * 1024 * 1024);
        let Some(code) = bytes.get(sec.raw_ptr..sec.raw_ptr.saturating_add(len).min(bytes.len()))
        else {
            continue;
        };

        if elf.machine == 0x3E {
            // x86_64 RIP-relative LEA reg, [RIP+disp32]
            let mut i = 0usize;
            while i + 7 <= code.len() && out.len() < max_xrefs {
                if (code[i] == 0x48 || code[i] == 0x4C)
                    && code[i + 1] == 0x8D
                    && (code[i + 2] & 0xC7) == 0x05
                {
                    let disp =
                        i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
                    let insn_va = sec.vaddr.saturating_add(i as u64);
                    let target = (insn_va as i64) + 7 + (disp as i64);
                    if target > 0 {
                        let tva = target as u64;
                        if let Some(sv) = str_lookup.get(&tva) {
                            if seen.insert((insn_va, tva)) {
                                let func = find_enclosing_elf_func(elf, insn_va);
                                let prev: String = sv.chars().take(72).collect();
                                out.push(format!(
                                    "- [elf-str-xref] x64 insn=0x{insn_va:x} in {func} -> vaddr=0x{tva:x} `{prev}`"
                                ));
                                i += 7;
                                continue;
                            }
                        }
                    }
                }
                i += 1;
            }
        } else if elf.machine == 0xB7 {
            // AArch64 `ADRP Xd, #page` + `ADD Xd2, Xd, #imm12` within next 1..8 instructions
            let mut i = 0usize;
            while i + 8 <= code.len() && out.len() < max_xrefs {
                let insn = u32::from_le_bytes([code[i], code[i + 1], code[i + 2], code[i + 3]]);
                if (insn & 0x9F00_0000) == 0x9000_0000 {
                    let rd = insn & 0x1F;
                    let immlo = (insn >> 29) & 0x3;
                    let immhi = (insn >> 5) & 0x7_FFFF;
                    let raw21 = (immhi << 2) | immlo;
                    let signed21 = if (raw21 & (1 << 20)) != 0 {
                        (raw21 | !0x1F_FFFF) as i32 as i64
                    } else {
                        raw21 as i64
                    };
                    let pc = sec.vaddr.saturating_add(i as u64);
                    let page = ((pc & !0xFFF) as i64).wrapping_add(signed21 << 12);
                    // Look ahead up to 8 instructions for `ADD X?, Xrd, #imm12`
                    for k in 1..=8usize {
                        let off2 = i + k * 4;
                        if off2 + 4 > code.len() {
                            break;
                        }
                        let insn2 = u32::from_le_bytes([
                            code[off2],
                            code[off2 + 1],
                            code[off2 + 2],
                            code[off2 + 3],
                        ]);
                        // ADD (immediate, 64-bit, unshifted): sf=1(bit31), op=0(bit30), S=0(bit29), 100010(bits28..23), sh=0(bit22)
                        if (insn2 & 0xFFC0_0000) == 0x9100_0000 {
                            let rn = (insn2 >> 5) & 0x1F;
                            if rn == rd {
                                let imm12 = ((insn2 >> 10) & 0xFFF) as i64;
                                let target = page.wrapping_add(imm12);
                                if target > 0 {
                                    let tva = target as u64;
                                    if let Some(sv) = str_lookup.get(&tva) {
                                        if seen.insert((pc, tva)) {
                                            let func = find_enclosing_elf_func(elf, pc);
                                            let prev: String = sv.chars().take(72).collect();
                                            out.push(format!(
                                                "- [elf-str-xref] arm64 adrp+add=0x{pc:x} in {func} -> vaddr=0x{tva:x} `{prev}`"
                                            ));
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        // Stop if rd is overwritten by another ADRP
                        if (insn2 & 0x9F00_0000) == 0x9000_0000 && (insn2 & 0x1F) == rd {
                            break;
                        }
                    }
                }
                i += 4;
            }
        }
    }
    out
}

fn parse_elf_details(bytes: &[u8], out: &mut Vec<String>) -> ElfContext {
    let is_64 = bytes[4] == 2;
    let bits = if is_64 { "64-bit" } else { "32-bit" };
    let e_type = read_u16_le(bytes, 16).unwrap_or(0);
    let mach = read_u16_le(bytes, 18).unwrap_or(0);
    let arch = match mach {
        0x3E => "x86_64",
        0xB7 => "AArch64",
        0x03 => "x86",
        0x28 => "ARM",
        0xF3 => "RISC-V",
        _ => "other",
    };
    out.push(format!(
        "## Binary Header: Linux ELF {bits} ({arch}, {} B)",
        bytes.len()
    ));
    let ent = shannon_entropy(&bytes[..bytes.len().min(4 * 1024 * 1024)]);

    // Parse ELF64 Program Headers for NX / RELRO / PIE hardening summary
    let mut elf_mit: Vec<&'static str> = Vec::new();
    let mut has_relro = false;
    let mut has_bind_now = false;
    let mut has_nx = false;
    let mut has_exec_stack = false;
    let mut elf_interp: Option<String> = None;
    let mut elf_build_id: Option<String> = None;
    if is_64 && bytes.len() >= 64 {
        if e_type == 3 {
            elf_mit.push("PIE");
        } else if e_type == 2 {
            elf_mit.push("NO-PIE!");
        }
        let phoff = read_u64_le(bytes, 32).unwrap_or(0) as usize;
        let phentsize = read_u16_le(bytes, 54).unwrap_or(0) as usize;
        let phnum = read_u16_le(bytes, 56).unwrap_or(0) as usize;
        if phoff > 0 && phentsize >= 56 && phnum > 0 {
            for i in 0..phnum.min(64) {
                let p = phoff.saturating_add(i.saturating_mul(phentsize));
                if p + 56 > bytes.len() {
                    break;
                }
                let p_type = read_u32_le(bytes, p).unwrap_or(0);
                let p_flags = read_u32_le(bytes, p + 4).unwrap_or(0);
                let p_off = read_u64_le(bytes, p + 8).unwrap_or(0) as usize;
                let p_fsz = read_u64_le(bytes, p + 32).unwrap_or(0) as usize;
                if p_type == 3 && p_fsz > 0 && p_fsz < 256 {
                    // PT_INTERP
                    if let Some(s) = read_cstr(bytes, p_off, p_fsz) {
                        if !s.is_empty() {
                            elf_interp = Some(s);
                        }
                    }
                } else if p_type == 4 && (16..=4096).contains(&p_fsz) && elf_build_id.is_none() {
                    // PT_NOTE (look for NT_GNU_BUILD_ID type=3, name="GNU\0")
                    if let Some(note_b) =
                        bytes.get(p_off..p_off.saturating_add(p_fsz).min(bytes.len()))
                    {
                        let mut noff = 0usize;
                        while noff + 12 <= note_b.len() {
                            let namesz = read_u32_le(note_b, noff).unwrap_or(0) as usize;
                            let descsz = read_u32_le(note_b, noff + 4).unwrap_or(0) as usize;
                            let ntype = read_u32_le(note_b, noff + 8).unwrap_or(0);
                            let name_start = noff + 12;
                            let name_end = name_start.saturating_add((namesz + 3) & !3);
                            let desc_end = name_end.saturating_add((descsz + 3) & !3);
                            if desc_end > note_b.len() {
                                break;
                            }
                            if ntype == 3
                                && descsz > 0
                                && descsz <= 64
                                && note_b.get(name_start..name_start + 4) == Some(b"GNU\0")
                            {
                                elf_build_id = Some(
                                    note_b[name_end..name_end + descsz]
                                        .iter()
                                        .map(|b| format!("{b:02x}"))
                                        .collect(),
                                );
                                break;
                            }
                            noff = desc_end.max(noff + 12);
                        }
                    }
                } else if p_type == 0x6474_e551 {
                    // PT_GNU_STACK
                    if (p_flags & 1) != 0 {
                        has_exec_stack = true;
                    } else {
                        has_nx = true;
                    }
                } else if p_type == 0x6474_e552 {
                    // PT_GNU_RELRO
                    has_relro = true;
                }
            }
        }
    }
    if has_exec_stack {
        elf_mit.push("EXEC-STACK!");
    } else if has_nx {
        elf_mit.push("NX");
    }
    let has_canary = bytes
        .windows(b"__stack_chk_fail".len())
        .any(|w| w == b"__stack_chk_fail");
    if has_canary {
        elf_mit.push("Canary");
    }

    let mut ctx = ElfContext {
        is_64,
        machine: mach,
        secs: Vec::new(),
        func_syms: Vec::new(),
    };
    if !is_64 || bytes.len() < 64 {
        out.push(format!(
            "- SHA-256: `{}` | Entropy: `{ent:.2}`",
            sha256_hex(bytes)
        ));
        return ctx;
    }
    let shoff = read_u64_le(bytes, 40).unwrap_or(0) as usize;
    let shentsize = read_u16_le(bytes, 58).unwrap_or(0) as usize;
    let shnum = read_u16_le(bytes, 60).unwrap_or(0) as usize;
    let shstrndx = read_u16_le(bytes, 62).unwrap_or(0) as usize;
    if shoff == 0 || shentsize < 64 || shnum == 0 {
        if has_relro {
            elf_mit.push("RELRO");
        }
        out.push(format!(
            "- SHA-256: `{}` | Entropy: `{ent:.2}` | Mitigations: `[{}]`",
            sha256_hex(bytes),
            if elf_mit.is_empty() {
                "none".to_string()
            } else {
                elf_mit.join(", ")
            }
        ));
        if let Some(ref interp) = elf_interp {
            out.push(format!("- Interpreter: `{interp}`"));
        }
        if let Some(ref bid) = elf_build_id {
            out.push(format!("- Build-ID: `{bid}`"));
        }
        return ctx;
    }
    let strtab_hdr = shoff.saturating_add(shstrndx.saturating_mul(shentsize));
    let shstr_off = read_u64_le(bytes, strtab_hdr + 24).unwrap_or(0) as usize;
    let mut sec_names = Vec::new();
    let mut dynstr_slice: Option<(usize, usize)> = None;
    let mut dynsym_slice: Option<(usize, usize, usize)> = None;
    let mut strtab_slice: Option<(usize, usize)> = None;
    let mut symtab_slice: Option<(usize, usize, usize)> = None;
    let mut dynamic_slice: Option<(usize, usize)> = None;

    for i in 0..shnum.min(64) {
        let h = shoff.saturating_add(i.saturating_mul(shentsize));
        if h + 64 > bytes.len() {
            break;
        }
        let nm_off = read_u32_le(bytes, h).unwrap_or(0) as usize;
        let sh_type = read_u32_le(bytes, h + 4).unwrap_or(0);
        let sh_flags = read_u64_le(bytes, h + 8).unwrap_or(0);
        let s_addr = read_u64_le(bytes, h + 16).unwrap_or(0);
        let s_off = read_u64_le(bytes, h + 24).unwrap_or(0) as usize;
        let s_sz = read_u64_le(bytes, h + 32).unwrap_or(0) as usize;
        let entsz = read_u64_le(bytes, h + 56).unwrap_or(0) as usize;
        let sname = read_cstr(bytes, shstr_off.saturating_add(nm_off), 64).unwrap_or_default();
        if !sname.is_empty() {
            sec_names.push(sname.clone());
        }
        ctx.secs.push(ElfSection {
            name: sname.clone(),
            vaddr: s_addr,
            raw_ptr: s_off,
            raw_size: s_sz,
            flags: sh_flags,
        });
        if sname == ".dynstr" {
            dynstr_slice = Some((s_off, s_sz));
        } else if sh_type == 11 || sname == ".dynsym" {
            dynsym_slice = Some((s_off, s_sz, entsz.max(24)));
        } else if sname == ".strtab" {
            strtab_slice = Some((s_off, s_sz));
        } else if sh_type == 2 || sname == ".symtab" {
            symtab_slice = Some((s_off, s_sz, entsz.max(24)));
        } else if sh_type == 6 || sname == ".dynamic" {
            dynamic_slice = Some((s_off, s_sz));
        }
    }
    if let Some((dyn_off, dyn_sz)) = dynamic_slice {
        let count = (dyn_sz / 16).min(128);
        for k in 0..count {
            let p = dyn_off + k * 16;
            let tag = read_u64_le(bytes, p).unwrap_or(0);
            let val = read_u64_le(bytes, p + 8).unwrap_or(0);
            if tag == 0 {
                break;
            }
            if tag == 24
                || (tag == 30 && (val & 0x8) != 0)
                || (tag == 0x6fff_fffb && (val & 0x1) != 0)
            {
                has_bind_now = true;
            }
        }
    }
    if has_relro {
        elf_mit.push(if has_bind_now {
            "Full-RELRO"
        } else {
            "Partial-RELRO"
        });
    } else {
        elf_mit.push("NO-RELRO");
    }
    out.push(format!(
        "- SHA-256: `{}` | Entropy: `{ent:.2}` | Mitigations: `[{}]`",
        sha256_hex(bytes),
        if elf_mit.is_empty() {
            "none".to_string()
        } else {
            elf_mit.join(", ")
        }
    ));
    if let Some(ref interp) = elf_interp {
        out.push(format!("- Interpreter: `{interp}`"));
    }
    if let Some(ref bid) = elf_build_id {
        out.push(format!("- Build-ID: `{bid}`"));
    }
    if !sec_names.is_empty() {
        out.push(format!("### ELF Sections: `[{}]`", sec_names.join(", ")));
    }
    if let Some((dstr_off, _)) = dynstr_slice {
        if let Some((dyn_off, dyn_sz)) = dynamic_slice {
            let mut needed = Vec::new();
            let mut soname: Option<String> = None;
            let mut rpaths = Vec::new();
            let count = (dyn_sz / 16).min(128);
            for k in 0..count {
                let p = dyn_off + k * 16;
                let tag = read_u64_le(bytes, p).unwrap_or(0);
                let val = read_u64_le(bytes, p + 8).unwrap_or(0) as usize;
                if tag == 0 {
                    break;
                }
                if tag == 1 {
                    if let Some(lib) = read_cstr(bytes, dstr_off.saturating_add(val), 128) {
                        needed.push(lib);
                    }
                } else if tag == 14 {
                    soname = read_cstr(bytes, dstr_off.saturating_add(val), 128);
                } else if tag == 15 || tag == 29 {
                    if let Some(rp) = read_cstr(bytes, dstr_off.saturating_add(val), 256) {
                        if !rp.is_empty() {
                            rpaths.push(rp);
                        }
                    }
                }
            }
            if let Some(ref sn) = soname {
                out.push(format!("- SONAME: `{sn}`"));
            }
            if !rpaths.is_empty() {
                let joined = rpaths.join(":");
                let warn = if joined.contains("$ORIGIN")
                    || joined.contains("/tmp")
                    || joined.starts_with('.')
                {
                    " [RPATH-CHECK]"
                } else {
                    ""
                };
                out.push(format!("- RPATH/RUNPATH: `{joined}`{warn}"));
            }
            if !needed.is_empty() {
                out.push(format!(
                    "### ELF DT_NEEDED Libraries: `{}`",
                    needed.join("`, `")
                ));
            }
        }
        if let Some((sym_off, sym_sz, entsz)) = dynsym_slice {
            let mut syms = Vec::new();
            let mut imp_syms = Vec::new();
            let mut notable_syms = Vec::new();
            let count = (sym_sz / entsz).min(2048);
            for k in 0..count {
                let p = sym_off + k * entsz;
                if p + 24 > bytes.len() {
                    break;
                }
                let st_name = read_u32_le(bytes, p).unwrap_or(0) as usize;
                let st_shndx = read_u16_le(bytes, p + 6).unwrap_or(0);
                let st_value = read_u64_le(bytes, p + 8).unwrap_or(0);
                if st_name > 0 {
                    if let Some(nm) = read_cstr(bytes, dstr_off.saturating_add(st_name), 128) {
                        if is_notable_elf_symbol(&nm)
                            && notable_syms.len() < 30
                            && !notable_syms.contains(&nm)
                        {
                            notable_syms.push(nm.clone());
                        }
                        if st_shndx == 0 {
                            if imp_syms.len() < 60 && !imp_syms.contains(&nm) {
                                imp_syms.push(nm);
                            }
                        } else {
                            if st_value > 0 && ctx.func_syms.len() < 4096 {
                                ctx.func_syms.push((st_value, nm.clone()));
                            }
                            if syms.len() < 60 {
                                syms.push(nm);
                            }
                        }
                    }
                }
            }
            if !notable_syms.is_empty() {
                out.push(format!(
                    "- **Notable ELF Symbols**: `{}`",
                    notable_syms.join("`, `")
                ));
            }
            if !imp_syms.is_empty() {
                out.push(format!(
                    "### ELF Imported Symbols ({} shown): {}",
                    imp_syms.len(),
                    imp_syms.join(", ")
                ));
            }
            if !syms.is_empty() {
                out.push(format!(
                    "### ELF Exported Symbols ({} shown): {}",
                    syms.len(),
                    syms.join(", ")
                ));
            }
        }
    }
    if let (Some((st_off, _)), Some((sym_off, sym_sz, entsz))) = (strtab_slice, symtab_slice) {
        let count = (sym_sz / entsz).min(4096);
        for k in 0..count {
            let p = sym_off + k * entsz;
            if p + 24 > bytes.len() {
                break;
            }
            let st_name = read_u32_le(bytes, p).unwrap_or(0) as usize;
            let st_shndx = read_u16_le(bytes, p + 6).unwrap_or(0);
            let st_value = read_u64_le(bytes, p + 8).unwrap_or(0);
            if st_name > 0 && st_shndx != 0 && st_value > 0 && ctx.func_syms.len() < 8192 {
                if let Some(nm) = read_cstr(bytes, st_off.saturating_add(st_name), 128) {
                    ctx.func_syms.push((st_value, nm));
                }
            }
        }
    }
    ctx
}

pub struct TarEntry {
    pub path: String,
    pub offset: usize,
    pub size: usize,
}

/// Pure-Rust USTAR + GNU `@LongLink` TAR archive indexer (skips directories & PAX metadata).
pub fn parse_tar_index(tar_bytes: &[u8]) -> Vec<TarEntry> {
    let mut pos = 0usize;
    let mut entries = Vec::new();
    let mut long_name: Option<String> = None;
    while pos + 512 <= tar_bytes.len() {
        let blk = &tar_bytes[pos..pos + 512];
        if blk.iter().all(|&b| b == 0) {
            break;
        }
        let size_s = String::from_utf8_lossy(&blk[124..136]);
        let oct = size_s.trim_matches(|c: char| c == '\0' || c.is_whitespace());
        let size = usize::from_str_radix(oct, 8).unwrap_or(0);
        let data_start = pos + 512;
        let padded = size.div_ceil(512).saturating_mul(512);
        let next_pos = data_start.saturating_add(padded);
        let typeflag = blk[156];
        if typeflag == b'L' {
            if let Some(lb) =
                tar_bytes.get(data_start..data_start.saturating_add(size).min(tar_bytes.len()))
            {
                let s = String::from_utf8_lossy(lb)
                    .trim_matches(|c: char| c == '\0' || c == '\n' || c == '\r')
                    .to_string();
                if !s.is_empty() {
                    long_name = Some(s);
                }
            }
            pos = next_pos;
            continue;
        }
        let path = if let Some(ln) = long_name.take() {
            ln
        } else {
            let name_end = blk[..100].iter().position(|&b| b == 0).unwrap_or(100);
            let nm = String::from_utf8_lossy(&blk[..name_end]).trim().to_string();
            let pfx_end = blk[345..500].iter().position(|&b| b == 0).unwrap_or(155);
            let pfx = String::from_utf8_lossy(&blk[345..345 + pfx_end])
                .trim()
                .to_string();
            if pfx.is_empty() {
                nm
            } else {
                format!("{pfx}/{nm}")
            }
        };
        if !path.is_empty()
            && !matches!(typeflag, b'5' | b'x' | b'g' | b'K')
            && data_start.saturating_add(size) <= tar_bytes.len()
        {
            entries.push(TarEntry {
                path: path.replace('\\', "/"),
                offset: data_start,
                size,
            });
        }
        if next_pos <= pos {
            break;
        }
        pos = next_pos;
    }
    entries
}

pub fn list_tar_md(tar_bytes: &[u8], query: Option<&str>) -> String {
    let entries = parse_tar_index(tar_bytes);
    let q_low = query
        .map(|q| q.trim().to_ascii_lowercase())
        .filter(|q| !q.is_empty());
    let mut shown = Vec::new();
    let mut matched = 0usize;
    for ent in &entries {
        if let Some(ref q) = q_low {
            if !ent.path.to_ascii_lowercase().contains(q) {
                continue;
            }
        }
        matched += 1;
        if shown.len() < 120 {
            shown.push(format!("  - `{}` ({} B)", ent.path, ent.size));
        }
    }
    format!(
        "## TAR Archive ({matched} matched / {} total entries)\n{}",
        entries.len(),
        shown.join("\n")
    )
}

pub fn read_tar_member(tar_bytes: &[u8], entry_path: &str) -> Result<Vec<u8>, String> {
    let entries = parse_tar_index(tar_bytes);
    let norm_want = entry_path
        .trim()
        .trim_start_matches("./")
        .replace('\\', "/");
    let found = entries
        .iter()
        .find(|e| e.path.trim_start_matches("./") == norm_want)
        .or_else(|| {
            entries
                .iter()
                .find(|e| e.path.ends_with(&format!("/{norm_want}")))
        })
        .or_else(|| {
            entries.iter().find(|e| {
                e.path
                    .to_ascii_lowercase()
                    .contains(&norm_want.to_ascii_lowercase())
            })
        })
        .ok_or_else(|| format!("entry `{entry_path}` not found in TAR archive"))?;
    tar_bytes
        .get(found.offset..found.offset + found.size)
        .map(|s| s.to_vec())
        .ok_or_else(|| format!("TAR entry `{}` out of bounds", found.path))
}

#[allow(dead_code)]
struct MachoSegment {
    name: String,
    vmaddr: u64,
    vmsize: u64,
    fileoff: usize,
    filesize: usize,
    initprot: u32,
}

struct MachoContext {
    slice_off: usize,
    segs: Vec<MachoSegment>,
}

fn macho_file_offset_to_vmaddr(off: usize, m: &MachoContext) -> Option<(u64, &str)> {
    let rel = off.checked_sub(m.slice_off)?;
    for s in &m.segs {
        if s.filesize == 0 {
            continue;
        }
        if rel >= s.fileoff && rel < s.fileoff.saturating_add(s.filesize) {
            return Some((
                s.vmaddr.saturating_add((rel - s.fileoff) as u64),
                s.name.as_str(),
            ));
        }
    }
    None
}

fn resolve_macho_slice(bytes: &[u8]) -> Option<(usize, usize, Vec<String>)> {
    if bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) && bytes.len() >= 32 {
        return Some((0, bytes.len(), Vec::new()));
    }
    if bytes.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) && bytes.len() >= 28 {
        let nfat = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        if (1..=8).contains(&nfat) && bytes.len() >= 8 + nfat * 20 {
            let mut arches = Vec::new();
            let mut chosen: Option<(usize, usize)> = None;
            for idx in 0..nfat {
                let base = 8 + idx * 20;
                let cpu = u32::from_be_bytes([
                    bytes[base],
                    bytes[base + 1],
                    bytes[base + 2],
                    bytes[base + 3],
                ]);
                let off = u32::from_be_bytes([
                    bytes[base + 8],
                    bytes[base + 9],
                    bytes[base + 10],
                    bytes[base + 11],
                ]) as usize;
                let sz = u32::from_be_bytes([
                    bytes[base + 12],
                    bytes[base + 13],
                    bytes[base + 14],
                    bytes[base + 15],
                ]) as usize;
                let label = match cpu {
                    0x0100_000C => "arm64",
                    0x0100_0007 => "x86_64",
                    0x0000_0007 => "x86",
                    _ => "other",
                };
                arches.push(label.to_string());
                if off.saturating_add(sz) <= bytes.len()
                    && sz >= 32
                    && bytes.get(off..off + 4) == Some(&[0xCF, 0xFA, 0xED, 0xFE])
                    && chosen.is_none()
                {
                    chosen = Some((off, sz));
                }
            }
            if let Some((off, sz)) = chosen {
                return Some((off, sz, arches));
            }
        }
    }
    None
}

fn parse_macho_details(bytes: &[u8], out: &mut Vec<String>) -> Option<MachoContext> {
    let (slice_off, slice_len, fat_arches) = resolve_macho_slice(bytes)?;
    let slice = bytes.get(slice_off..slice_off + slice_len)?;
    if slice.len() < 32 {
        return None;
    }
    let cputype = read_u32_le(slice, 4).unwrap_or(0);
    let filetype = read_u32_le(slice, 12).unwrap_or(0);
    let ncmds = read_u32_le(slice, 16).unwrap_or(0) as usize;
    let sizeofcmds = read_u32_le(slice, 20).unwrap_or(0) as usize;
    let flags = read_u32_le(slice, 24).unwrap_or(0);
    let arch = match cputype {
        0x0100_000C => "ARM64",
        0x0100_0007 => "x86_64",
        _ => "64-bit",
    };
    let ftype_s = match filetype {
        2 => "MH_EXECUTE",
        6 => "MH_DYLIB",
        8 => "MH_BUNDLE",
        _ => "Mach-O",
    };
    let fat_tag = if fat_arches.is_empty() {
        String::new()
    } else {
        format!(" | Universal FAT: [{}]", fat_arches.join(", "))
    };
    out.push(format!(
        "## Binary Header: macOS Mach-O {arch} ({ftype_s}, {} B){fat_tag}",
        bytes.len()
    ));
    let mut mits = Vec::new();
    if (flags & 0x0020_0000) != 0 {
        mits.push("PIE");
    }
    if (flags & 0x0100_0000) != 0 {
        mits.push("NO-HEAP-EXEC");
    }
    if (flags & 0x0002_0000) != 0 {
        mits.push("ALLOW-STACK-EXEC!");
    }
    out.push(format!(
        "- SHA-256: `{}` | Entropy: `{:.2}` | Flags: `[{}]`",
        sha256_hex(bytes),
        shannon_entropy(&bytes[..bytes.len().min(4 * 1024 * 1024)]),
        if mits.is_empty() {
            "none".to_string()
        } else {
            mits.join(", ")
        }
    ));

    let mut ctx = MachoContext {
        slice_off,
        segs: Vec::new(),
    };
    let mut dylibs = Vec::new();
    let mut rpaths = Vec::new();
    let mut seg_rows = Vec::new();
    let mut entitlements = Vec::new();
    let mut sym_names = Vec::new();
    let mut sig_len = 0usize;

    let cmds_end = (32 + sizeofcmds).min(slice.len());
    let mut pos = 32usize;
    for _ in 0..ncmds.min(256) {
        if pos + 8 > cmds_end {
            break;
        }
        let cmd = read_u32_le(slice, pos).unwrap_or(0);
        let cmdsize = read_u32_le(slice, pos + 4).unwrap_or(0) as usize;
        if cmdsize < 8 || pos + cmdsize > cmds_end {
            break;
        }
        let lc = &slice[pos..pos + cmdsize];
        if cmd == 0x19 && lc.len() >= 72 {
            // LC_SEGMENT_64
            let nm = String::from_utf8_lossy(&lc[8..24])
                .trim_end_matches('\0')
                .to_string();
            let vmaddr = read_u64_le(lc, 24).unwrap_or(0);
            let vmsize = read_u64_le(lc, 32).unwrap_or(0);
            let fileoff = read_u64_le(lc, 40).unwrap_or(0) as usize;
            let filesize = read_u64_le(lc, 48).unwrap_or(0) as usize;
            let initprot = read_u32_le(lc, 60).unwrap_or(0);
            let mut perm = String::new();
            if (initprot & 1) != 0 {
                perm.push('R');
            }
            if (initprot & 2) != 0 {
                perm.push('W');
            }
            if (initprot & 4) != 0 {
                perm.push('X');
            }
            let rwx = if initprot & 7 == 7 { " [RWX!]" } else { "" };
            seg_rows.push(format!(
                "`{nm}` (va=0x{vmaddr:x} sz={}B {perm}{rwx})",
                vmsize
            ));
            ctx.segs.push(MachoSegment {
                name: nm,
                vmaddr,
                vmsize,
                fileoff,
                filesize,
                initprot,
            });
        } else if matches!(cmd, 0x0C | 0x18 | 0x8000_0018 | 0x8000_001F) && lc.len() >= 24 {
            let str_off = read_u32_le(lc, 8).unwrap_or(0) as usize;
            if let Some(dl) = read_cstr(lc, str_off, 256) {
                dylibs.push(dl);
            }
        } else if cmd == 0x8000_001C && lc.len() >= 12 {
            // LC_RPATH
            let str_off = read_u32_le(lc, 8).unwrap_or(0) as usize;
            if let Some(rp) = read_cstr(lc, str_off, 256) {
                rpaths.push(rp);
            }
        } else if cmd == 0x1D && lc.len() >= 16 {
            // LC_CODE_SIGNATURE
            let dataoff = read_u32_le(lc, 8).unwrap_or(0) as usize;
            let datasize = read_u32_le(lc, 12).unwrap_or(0) as usize;
            if dataoff > 0 && datasize > 0 && dataoff.saturating_add(datasize) <= slice.len() {
                sig_len = datasize;
                let sig_txt = String::from_utf8_lossy(&slice[dataoff..dataoff + datasize]);
                for cand in sig_txt.match_indices("<key>") {
                    let rest = &sig_txt[cand.0 + 5..];
                    if let Some(end_k) = rest.find("</key>") {
                        let k = rest[..end_k].trim();
                        if (k.contains("com.apple.security.") || k == "get-task-allow")
                            && entitlements.len() < 12
                            && !entitlements.iter().any(|x| x == k)
                        {
                            entitlements.push(k.to_string());
                        }
                    }
                }
            }
        } else if cmd == 0x02 && lc.len() >= 24 {
            // LC_SYMTAB
            let symoff = read_u32_le(lc, 8).unwrap_or(0) as usize;
            let nsyms = read_u32_le(lc, 12).unwrap_or(0) as usize;
            let stroff = read_u32_le(lc, 16).unwrap_or(0) as usize;
            let strsize = read_u32_le(lc, 20).unwrap_or(0) as usize;
            if stroff < slice.len() && strsize > 0 {
                for sidx in 0..nsyms.min(256) {
                    let nlist = symoff.saturating_add(sidx * 16);
                    if nlist + 16 > slice.len() {
                        break;
                    }
                    let strx = read_u32_le(slice, nlist).unwrap_or(0) as usize;
                    if strx > 0 && strx < strsize {
                        if let Some(nm) = read_cstr(slice, stroff + strx, 128) {
                            if nm.len() >= 3 && sym_names.len() < 50 && !sym_names.contains(&nm) {
                                sym_names.push(nm);
                            }
                        }
                    }
                }
            }
        }
        pos += cmdsize;
    }

    if !seg_rows.is_empty() {
        out.push(format!(
            "### Mach-O Segments ({}): {}",
            seg_rows.len(),
            seg_rows.join(" · ")
        ));
    }
    if !rpaths.is_empty() {
        out.push(format!("- LC_RPATH: `{}`", rpaths.join("`, `")));
    }
    if sig_len > 0 {
        if entitlements.is_empty() {
            out.push(format!("- CodeSignature: present ({sig_len} B)"));
        } else {
            out.push(format!(
                "- CodeSignature: present ({sig_len} B) | Entitlements: `{}`",
                entitlements.join("`, `")
            ));
        }
    }
    if !dylibs.is_empty() {
        out.push(format!(
            "### Mach-O Dylibs ({}): `{}`",
            dylibs.len(),
            dylibs.join("`, `")
        ));
    }
    if !sym_names.is_empty() {
        out.push(format!(
            "### Mach-O Symbols ({} shown): {}",
            sym_names.len(),
            sym_names.join(", ")
        ));
    }
    Some(ctx)
}

/// Inspect PE / ELF / Mach-O / WASM headers, imports/exports, SHA-256, entropy + ASCII & Windows UTF-16LE wide strings.
pub fn inspect_binary_md(bytes: &[u8], query: Option<&str>, max_strings: usize) -> String {
    inspect_binary_with_xref_md(bytes, query, max_strings, false)
}

/// Inspect native binaries with optional pure-Rust PE64/ELF64 (x64 & AArch64) XREF resolution + Go `.gopclntab` extraction.
pub fn inspect_binary_with_xref_md(
    bytes: &[u8],
    query: Option<&str>,
    max_strings: usize,
    include_xref: bool,
) -> String {
    let mut out = Vec::new();
    let mut pe_ctx: Option<PeContext> = None;
    let mut elf_ctx: Option<ElfContext> = None;
    let mut macho_ctx: Option<MachoContext> = None;
    if bytes.starts_with(b"MZ") && bytes.len() > 0x44 {
        let pe_off = read_u32_le(bytes, 0x3C).unwrap_or(0) as usize;
        if bytes.get(pe_off..pe_off + 4) == Some(b"PE\0\0") {
            pe_ctx = Some(parse_pe_details(bytes, pe_off, &mut out));
        } else {
            out.push(format!(
                "## Binary Header: DOS/MZ ({} B) | SHA-256: `{}`",
                bytes.len(),
                sha256_hex(bytes)
            ));
        }
    } else if bytes.starts_with(b"\x7FELF") && bytes.len() >= 20 {
        elf_ctx = Some(parse_elf_details(bytes, &mut out));
    } else if is_java_class_magic(bytes) {
        return parse_java_class_md(bytes, query);
    } else if is_pyc_magic(bytes) {
        return parse_pyc_md(bytes, query);
    } else if bytes.starts_with(b"\x00asm") {
        out.push(format!(
            "## Binary Header: WebAssembly ({} B) | SHA-256: `{}`",
            bytes.len(),
            sha256_hex(bytes)
        ));
    } else if let Some(mctx) = parse_macho_details(bytes, &mut out) {
        macho_ctx = Some(mctx);
    } else {
        out.push(format!(
            "## Binary File ({} B) | SHA-256: `{}` | Entropy: `{:.2}`",
            bytes.len(),
            sha256_hex(bytes),
            shannon_entropy(&bytes[..bytes.len().min(4 * 1024 * 1024)])
        ));
    }

    let q_re = query.and_then(|q| {
        Regex::new(&format!("(?i){q}"))
            .or_else(|_| Regex::new(&format!("(?i){}", regex::escape(q))))
            .ok()
    });
    let go_funcs = scan_go_pclntab_funcs(bytes, q_re.as_ref(), 45);
    if !go_funcs.is_empty() {
        let go_line = format!(
            "### Go User Functions (.gopclntab, {} shown): {}",
            go_funcs.len(),
            go_funcs.join(", ")
        );
        let insert_at = out
            .iter()
            .position(|l| l.starts_with("### PE Imports") || l.starts_with("### ELF Exported"))
            .unwrap_or(out.len());
        out.insert(insert_at, go_line);
    }

    let mut hits: Vec<String> = Vec::new();
    let mut matched_str_rvas: Vec<(u32, String)> = Vec::new();
    let mut matched_elf_vaddrs: Vec<(u64, String)> = Vec::new();
    let scan_cap = if query.is_some() || include_xref {
        24 * 1024 * 1024
    } else {
        8 * 1024 * 1024
    };
    let scan_lim = bytes.len().min(scan_cap);
    let data = &bytes[..scan_lim];

    // 1. ASCII printable strings (len >= 6)
    let mut i = 0usize;
    while i < data.len() && hits.len() < max_strings {
        if (0x20..=0x7E).contains(&data[i]) {
            let st = i;
            while i < data.len() && (0x20..=0x7E).contains(&data[i]) && i - st < 240 {
                i += 1;
            }
            if i - st >= 6 {
                let s = String::from_utf8_lossy(&data[st..i]);
                if q_re.as_ref().map(|r| r.is_match(&s)).unwrap_or(true) {
                    if let Some((rva, sec)) = pe_ctx
                        .as_ref()
                        .and_then(|p| file_offset_to_rva(st, &p.secs))
                    {
                        hits.push(format!("[ascii @0x{st:x} rva=0x{rva:x} ({sec})] {s}"));
                        matched_str_rvas.push((rva, s.into_owned()));
                    } else if let Some((va, sec)) = elf_ctx
                        .as_ref()
                        .and_then(|e| elf_file_offset_to_vaddr(st, &e.secs))
                    {
                        hits.push(format!("[ascii @0x{st:x} vaddr=0x{va:x} ({sec})] {s}"));
                        matched_elf_vaddrs.push((va, s.into_owned()));
                    } else if let Some((va, sec)) = macho_ctx
                        .as_ref()
                        .and_then(|m| macho_file_offset_to_vmaddr(st, m))
                    {
                        hits.push(format!("[ascii @0x{st:x} vaddr=0x{va:x} ({sec})] {s}"));
                    } else {
                        hits.push(format!("[ascii @0x{st:x}] {s}"));
                    }
                }
            }
        } else {
            i += 1;
        }
    }

    // 2. Windows UTF-16LE wide strings (len >= 5 chars)
    let mut j = 0usize;
    while j + 1 < data.len() && hits.len() < max_strings {
        if (0x20..=0x7E).contains(&data[j]) && data[j + 1] == 0 {
            let st = j;
            let mut s = String::new();
            while j + 1 < data.len()
                && (0x20..=0x7E).contains(&data[j])
                && data[j + 1] == 0
                && s.len() < 200
            {
                s.push(data[j] as char);
                j += 2;
            }
            if s.len() >= 5 && q_re.as_ref().map(|r| r.is_match(&s)).unwrap_or(true) {
                if let Some((rva, sec)) = pe_ctx
                    .as_ref()
                    .and_then(|p| file_offset_to_rva(st, &p.secs))
                {
                    hits.push(format!("[utf16le @0x{st:x} rva=0x{rva:x} ({sec})] {s}"));
                    matched_str_rvas.push((rva, s));
                } else {
                    hits.push(format!("[utf16le @0x{st:x}] {s}"));
                }
            }
        } else {
            j += 1;
        }
    }

    if include_xref {
        if let Some(ref pe) = pe_ctx {
            let xrefs = scan_pe64_xrefs(bytes, pe, &matched_str_rvas, q_re.as_ref(), 60);
            let mut xref_block = vec![format!(
                "### PE64 RIP-Relative Code XREFs ({} found)",
                xrefs.len()
            )];
            if xrefs.is_empty() {
                xref_block.push(
                    "*(no matching x64 RIP-relative LEA/CALL XREFs found in executable sections)*"
                        .to_string(),
                );
            } else {
                xref_block.extend(xrefs);
            }
            let insert_at = out
                .iter()
                .position(|l| l.starts_with("### PE Imports"))
                .unwrap_or(out.len());
            out.splice(insert_at..insert_at, xref_block);
        } else if let Some(ref elf) = elf_ctx {
            let xrefs = scan_elf64_xrefs(bytes, elf, &matched_elf_vaddrs, 60);
            let mut xref_block = vec![format!("### ELF64 Code XREFs ({} found)", xrefs.len())];
            if xrefs.is_empty() {
                xref_block.push("*(no matching x86_64 LEA or AArch64 ADRP+ADD XREFs found in executable sections)*".to_string());
            } else {
                xref_block.extend(xrefs);
            }
            let insert_at = out
                .iter()
                .position(|l| l.starts_with("### ELF Exported"))
                .unwrap_or(out.len());
            out.splice(insert_at..insert_at, xref_block);
        }
    }

    let mut str_block = vec![format!(
        "### Extracted Strings ({} shown; scans ASCII + Windows UTF-16LE — narrow with `--query <regex>` or add `--xref`)",
        hits.len()
    )];
    if hits.is_empty() {
        str_block.push("*(no matching printable ASCII/UTF-16LE strings)*".to_string());
    } else {
        str_block.extend(hits);
    }
    if query.is_some() || include_xref {
        let insert_at = out
            .iter()
            .position(|l| l.starts_with("### PE Imports") || l.starts_with("### ELF Exported"))
            .unwrap_or(out.len());
        out.splice(insert_at..insert_at, str_block);
    } else {
        out.extend(str_block);
    }
    out.join("\n")
}

fn parse_addr_hex_or_dec(spec: &str) -> Result<u64, String> {
    let s = spec.trim();
    if s.is_empty() {
        return Err("empty address".to_string());
    }
    if let Some(hx) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hx, 16).map_err(|_| format!("invalid hex address `{spec}`"));
    }
    if s.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F')) {
        u64::from_str_radix(s, 16).map_err(|_| format!("invalid hex address `{spec}`"))
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("invalid address `{spec}`"))
    }
}

fn parse_elf_pt_load(bytes: &[u8]) -> Vec<(usize, u64, usize)> {
    let mut segs = Vec::new();
    if bytes.starts_with(b"\x7FELF") && bytes.get(4) == Some(&2) && bytes.len() >= 64 {
        let phoff = read_u64_le(bytes, 32).unwrap_or(0) as usize;
        let phentsize = read_u16_le(bytes, 54).unwrap_or(0) as usize;
        let phnum = read_u16_le(bytes, 56).unwrap_or(0) as usize;
        if phoff > 0 && phentsize >= 56 {
            for i in 0..phnum.min(64) {
                let p = phoff.saturating_add(i.saturating_mul(phentsize));
                if p + 56 > bytes.len() {
                    break;
                }
                let p_type = read_u32_le(bytes, p).unwrap_or(0);
                if p_type == 1 {
                    let p_offset = read_u64_le(bytes, p + 8).unwrap_or(0) as usize;
                    let p_vaddr = read_u64_le(bytes, p + 16).unwrap_or(0);
                    let p_filesz = read_u64_le(bytes, p + 32).unwrap_or(0) as usize;
                    if p_filesz > 0 {
                        segs.push((p_offset, p_vaddr, p_filesz));
                    }
                }
            }
        }
    }
    segs
}

/// Map a PE RVA/VA (or ELF VA/offset) to exact file offset, section, enclosing function, nearby calls & hex dump.
pub fn inspect_binary_address_md(
    bytes: &[u8],
    addr_spec: &str,
    is_va: bool,
    window: usize,
) -> Result<String, String> {
    let addr = parse_addr_hex_or_dec(addr_spec)?;
    let win = window.clamp(16, 4096);
    if bytes.starts_with(b"MZ") && bytes.len() > 0x44 {
        let pe_off = read_u32_le(bytes, 0x3C).unwrap_or(0) as usize;
        if bytes.get(pe_off..pe_off + 4) == Some(b"PE\0\0") {
            let mut sink = Vec::new();
            let pe = parse_pe_details(bytes, pe_off, &mut sink);
            let rva64 = if is_va {
                addr.checked_sub(pe.image_base).ok_or_else(|| {
                    format!("VA 0x{addr:x} is below ImageBase 0x{:x}", pe.image_base)
                })?
            } else {
                addr
            };
            let rva = u32::try_from(rva64).map_err(|_| format!("RVA 0x{rva64:x} exceeds u32"))?;
            let va = pe.image_base.saturating_add(rva as u64);
            let matched_sec = pe
                .secs
                .iter()
                .find(|s| rva >= s.vaddr && rva < s.vaddr.saturating_add(s.vsize.max(s.raw_size)));
            let file_off = rva_to_file_offset(rva, &pe.secs)
                .or_else(|| {
                    if (rva as usize) < bytes.len() && matched_sec.is_none() {
                        Some(rva as usize)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| format!("RVA 0x{rva:x} not mapped to raw file bytes"))?;

            let sec_info = matched_sec
                .map(|s| format!("`{}` (sec_rva=0x{:x})", s.name, s.vaddr))
                .unwrap_or_else(|| "`PE_HEADER`".to_string());
            let mut lines = vec![format!(
                "## Address Lookup: PE rva=0x{rva:x} (va=0x{va:x}) -> offset=0x{file_off:x} | section={sec_info}"
            )];

            if let Some(sec) = matched_sec {
                if pe.is_pe64 && (sec.chars & 0x2000_0000) != 0 {
                    let s_start = sec.raw_ptr as usize;
                    let s_len = (sec.raw_size as usize).min(16 * 1024 * 1024);
                    if let Some(code) =
                        bytes.get(s_start..s_start.saturating_add(s_len).min(bytes.len()))
                    {
                        let rel = file_off.saturating_sub(s_start);
                        if rel < code.len() {
                            let fn_rva = find_enclosing_x64_func_rva(code, sec.vaddr, rel);
                            let fn_va = pe.image_base.saturating_add(fn_rva as u64);
                            lines.push(format!("- Enclosing x64 Function: `func_rva=0x{fn_rva:x}` (`va=0x{fn_va:x}`)"));
                        }
                        let mut targets = Vec::new();
                        let scan_end = rel.saturating_add(win).min(code.len());
                        let mut p = rel;
                        while p + 5 <= scan_end && targets.len() < 16 {
                            let b0 = code[p];
                            let cur_rva = sec.vaddr.saturating_add(p as u32);
                            if (b0 == 0xE8 || b0 == 0xE9) && p + 5 <= scan_end {
                                let disp = i32::from_le_bytes([
                                    code[p + 1],
                                    code[p + 2],
                                    code[p + 3],
                                    code[p + 4],
                                ]);
                                let tgt = (cur_rva as i64) + 5 + (disp as i64);
                                if tgt > 0 {
                                    let kind = if b0 == 0xE8 { "CALL" } else { "JMP" };
                                    targets.push(format!(
                                        "`0x{cur_rva:x}: {kind} 0x{:x}`",
                                        tgt as u64
                                    ));
                                    p += 5;
                                    continue;
                                }
                            } else if b0 == 0xFF
                                && p + 6 <= scan_end
                                && (code[p + 1] == 0x15 || code[p + 1] == 0x25)
                            {
                                let disp = i32::from_le_bytes([
                                    code[p + 2],
                                    code[p + 3],
                                    code[p + 4],
                                    code[p + 5],
                                ]);
                                let tgt = (cur_rva as i64) + 6 + (disp as i64);
                                if tgt > 0 {
                                    let trva = tgt as u32;
                                    let sym = pe
                                        .iat_map
                                        .iter()
                                        .find(|(r, _)| *r == trva)
                                        .map(|(_, s)| s.as_str())
                                        .unwrap_or("iat_slot");
                                    targets.push(format!("`0x{cur_rva:x}: [0x{trva:x}] -> {sym}`"));
                                    p += 6;
                                    continue;
                                }
                            } else if (b0 == 0x48 || b0 == 0x4C)
                                && p + 7 <= scan_end
                                && code[p + 1] == 0x8D
                                && (code[p + 2] & 0xC7) == 0x05
                            {
                                let disp = i32::from_le_bytes([
                                    code[p + 3],
                                    code[p + 4],
                                    code[p + 5],
                                    code[p + 6],
                                ]);
                                let tgt = (cur_rva as i64) + 7 + (disp as i64);
                                if tgt > 0 {
                                    let trva = tgt as u32;
                                    let s_preview = rva_to_file_offset(trva, &pe.secs)
                                        .and_then(|fo| read_cstr(bytes, fo, 48))
                                        .unwrap_or_default();
                                    if s_preview.is_empty() {
                                        targets
                                            .push(format!("`0x{cur_rva:x}: LEA rva=0x{trva:x}`"));
                                    } else {
                                        targets.push(format!(
                                            "`0x{cur_rva:x}: LEA 0x{trva:x} \"{}\"`",
                                            s_preview
                                        ));
                                    }
                                    p += 7;
                                    continue;
                                }
                            }
                            p += 1;
                        }
                        if !targets.is_empty() {
                            lines.push(format!("- Disasm Hints: {}", targets.join(" · ")));
                        }
                    }
                }
            }
            lines.push(format_hex_dump(bytes, file_off, win));
            return Ok(lines.join("\n"));
        }
    }

    if bytes.starts_with(b"\x7FELF") {
        let mut sink = Vec::new();
        let elf = parse_elf_details(bytes, &mut sink);
        let loads = parse_elf_pt_load(bytes);
        let mapped_sec = elf.secs.iter().find(|s| {
            s.vaddr > 0 && addr >= s.vaddr && addr < s.vaddr.saturating_add(s.raw_size as u64)
        });
        let file_off = mapped_sec
            .map(|s| s.raw_ptr.saturating_add((addr - s.vaddr) as usize))
            .or_else(|| {
                loads.iter().find_map(|&(poff, pva, psz)| {
                    if addr >= pva && addr < pva.saturating_add(psz as u64) {
                        Some(poff.saturating_add((addr - pva) as usize))
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| format!("ELF VA 0x{addr:x} not mapped to file bytes"))?;
        let sec_nm = mapped_sec.map(|s| s.name.as_str()).unwrap_or("PT_LOAD");
        let nearest = elf
            .func_syms
            .iter()
            .filter(|(sv, _)| *sv <= addr)
            .max_by_key(|(sv, _)| *sv)
            .map(|(sv, nm)| format!(" | nearest_sym=`{nm}+0x{:x}`", addr - sv))
            .unwrap_or_default();
        let out = format!(
            "## Address Lookup: ELF va=0x{addr:x} -> offset=0x{file_off:x} | section=`{sec_nm}`{nearest}\n{}",
            format_hex_dump(bytes, file_off, win)
        );
        return Ok(out);
    }

    if resolve_macho_slice(bytes).is_some() {
        let mut sink = Vec::new();
        if let Some(macho) = parse_macho_details(bytes, &mut sink) {
            let mut matched_file_off = None;
            let mut matched_seg = "MachO";
            for seg in &macho.segs {
                if seg.filesize > 0
                    && addr >= seg.vmaddr
                    && addr < seg.vmaddr.saturating_add(seg.filesize as u64)
                {
                    matched_file_off = Some(
                        macho
                            .slice_off
                            .saturating_add(seg.fileoff)
                            .saturating_add((addr - seg.vmaddr) as usize),
                    );
                    matched_seg = seg.name.as_str();
                    break;
                }
            }
            let file_off = matched_file_off
                .filter(|&fo| fo < bytes.len())
                .ok_or_else(|| format!("Mach-O VA 0x{addr:x} not mapped to raw bytes"))?;
            return Ok(format!(
                "## Address Lookup: Mach-O va=0x{addr:x} -> offset=0x{file_off:x} | segment=`{matched_seg}`\n{}",
                format_hex_dump(bytes, file_off, win)
            ));
        }
    }

    let off = usize::try_from(addr).map_err(|_| "offset overflow".to_string())?;
    if off >= bytes.len() {
        return Err(format!(
            "offset 0x{off:x} exceeds file size ({} B)",
            bytes.len()
        ));
    }
    Ok(format!(
        "## Offset Lookup: 0x{off:x} ({off} B)\n{}",
        format_hex_dump(bytes, off, win)
    ))
}

fn parse_byte_pattern(pattern: &str) -> Result<Vec<Option<u8>>, String> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err("empty --find-bytes pattern".to_string());
    }
    let mut pat = Vec::new();
    if trimmed.contains(' ') || trimmed.contains('\t') {
        for tok in trimmed.split_whitespace() {
            let t = tok.trim_start_matches("0x").trim_start_matches("0X");
            if t == "??" || t == "?" || t == "*" || t == "**" {
                pat.push(None);
            } else if t.len() == 2 {
                let b = u8::from_str_radix(t, 16)
                    .map_err(|_| format!("invalid hex byte token `{tok}`"))?;
                pat.push(Some(b));
            } else {
                return Err(format!(
                    "invalid hex token `{tok}` (expected 2-hex byte or `??`)"
                ));
            }
        }
    } else {
        let s = trimmed.trim_start_matches("0x").trim_start_matches("0X");
        let b = s.as_bytes();
        if b.len() % 2 != 0 {
            return Err(format!("hex pattern `{trimmed}` must have even length"));
        }
        for pair in b.chunks_exact(2) {
            let p_str = std::str::from_utf8(pair).unwrap_or("");
            if p_str == "??" || p_str == "**" {
                pat.push(None);
            } else {
                let byte = u8::from_str_radix(p_str, 16)
                    .map_err(|_| format!("invalid hex byte `{p_str}`"))?;
                pat.push(Some(byte));
            }
        }
    }
    if !pat.iter().any(|x| x.is_some()) {
        return Err("pattern cannot consist solely of wildcards".to_string());
    }
    Ok(pat)
}

/// Wildcard binary byte-signature finder (`--find-bytes`) mapping hits to PE RVA/VA/enclosing function or ELF VA.
pub fn find_binary_bytes_md(
    bytes: &[u8],
    pattern: &str,
    max_hits: usize,
) -> Result<String, String> {
    let pat = parse_byte_pattern(pattern)?;
    let cap = if max_hits == 0 {
        30
    } else {
        max_hits.clamp(1, 200)
    };
    let scan_end = bytes.len().min(64 * 1024 * 1024);
    let data = &bytes[..scan_end];
    if pat.len() > data.len() {
        return Ok(format!("## Byte Search `{pattern}` (0 hits)"));
    }

    let mut pe_ctx: Option<PeContext> = None;
    let mut elf_ctx: Option<ElfContext> = None;
    let mut macho_ctx: Option<MachoContext> = None;
    if bytes.starts_with(b"MZ") && bytes.len() > 0x44 {
        let pe_off = read_u32_le(bytes, 0x3C).unwrap_or(0) as usize;
        if bytes.get(pe_off..pe_off + 4) == Some(b"PE\0\0") {
            let mut sink = Vec::new();
            pe_ctx = Some(parse_pe_details(bytes, pe_off, &mut sink));
        }
    } else if bytes.starts_with(b"\x7FELF") {
        let mut sink = Vec::new();
        elf_ctx = Some(parse_elf_details(bytes, &mut sink));
    } else if resolve_macho_slice(bytes).is_some() {
        let mut sink = Vec::new();
        macho_ctx = parse_macho_details(bytes, &mut sink);
    }

    let first_anchor = pat
        .iter()
        .enumerate()
        .find_map(|(idx, &b)| b.map(|v| (idx, v)))
        .unwrap();
    let mut hits = Vec::new();
    let mut pos = first_anchor.0;
    let limit_i = data.len() - pat.len();
    while pos <= limit_i + first_anchor.0 && hits.len() < cap {
        let Some(rel) = data[pos..=limit_i + first_anchor.0]
            .iter()
            .position(|&x| x == first_anchor.1)
        else {
            break;
        };
        let cand_start = pos + rel - first_anchor.0;
        let window = &data[cand_start..cand_start + pat.len()];
        if pat
            .iter()
            .enumerate()
            .all(|(k, &m)| m.map(|v| v == window[k]).unwrap_or(true))
        {
            let preview_end = (cand_start + 16).min(data.len());
            let hex_prev = data[cand_start..preview_end]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            let mut loc = format!("offset=0x{cand_start:x}");
            if let Some(ref pe) = pe_ctx {
                if let Some((rva, sec_nm)) = file_offset_to_rva(cand_start, &pe.secs) {
                    let va = pe.image_base.saturating_add(rva as u64);
                    loc.push_str(&format!(" rva=0x{rva:x} va=0x{va:x} ({sec_nm})"));
                    if pe.is_pe64 {
                        if let Some(sec) = pe
                            .secs
                            .iter()
                            .find(|s| s.name == sec_nm && (s.chars & 0x2000_0000) != 0)
                        {
                            let s_st = sec.raw_ptr as usize;
                            let s_len = (sec.raw_size as usize).min(16 * 1024 * 1024);
                            if let Some(code) =
                                bytes.get(s_st..s_st.saturating_add(s_len).min(bytes.len()))
                            {
                                let fn_rva = find_enclosing_x64_func_rva(
                                    code,
                                    sec.vaddr,
                                    cand_start.saturating_sub(s_st),
                                );
                                loc.push_str(&format!(" func_rva=0x{fn_rva:x}"));
                            }
                        }
                    }
                }
            } else if let Some(ref elf) = elf_ctx {
                if let Some((va, sec_nm)) = elf_file_offset_to_vaddr(cand_start, &elf.secs) {
                    loc.push_str(&format!(" va=0x{va:x} ({sec_nm})"));
                }
            } else if let Some(ref macho) = macho_ctx {
                if let Some((va, seg_nm)) = macho_file_offset_to_vmaddr(cand_start, macho) {
                    loc.push_str(&format!(" va=0x{va:x} ({seg_nm})"));
                }
            }
            hits.push(format!("- {loc} | `{hex_prev}`"));
        }
        pos = cand_start + first_anchor.0 + 1;
    }

    if hits.is_empty() {
        return Ok(format!(
            "## Byte Search `{pattern}` (0 hits across {scan_end} B)"
        ));
    }
    Ok(format!(
        "## Byte Search `{pattern}` ({} hit(s), cap={cap})\n{}",
        hits.len(),
        hits.join("\n")
    ))
}

/// Extract printable ASCII and Windows UTF-16LE strings with GNU `strings`-compatible filters (`min_len`, `encoding`: `s`/`l`/both).
pub fn extract_strings_md(
    bytes: &[u8],
    query: Option<&str>,
    min_len: usize,
    max_strings: usize,
    encoding: &str,
) -> String {
    let enc_low = encoding.trim().to_ascii_lowercase();
    let scan_ascii = !matches!(enc_low.as_str(), "l" | "utf16" | "utf-16le" | "wide");
    let scan_wide = !matches!(enc_low.as_str(), "s" | "ascii");
    let min_ascii = if min_len >= 2 { min_len } else { 6 };
    let min_wide = if min_len >= 2 { min_len } else { 5 };
    let q_re = query.and_then(|q| {
        Regex::new(&format!("(?i){q}"))
            .or_else(|_| Regex::new(&format!("(?i){}", regex::escape(q))))
            .ok()
    });
    let cap_hits = if max_strings == 0 { 200 } else { max_strings };
    let scan_lim = bytes.len().min(if query.is_some() {
        24 * 1024 * 1024
    } else {
        8 * 1024 * 1024
    });
    let data = &bytes[..scan_lim];
    let mut hits: Vec<String> = Vec::new();

    if scan_ascii {
        let mut i = 0usize;
        while i < data.len() && hits.len() < cap_hits {
            if (0x20..=0x7E).contains(&data[i]) {
                let st = i;
                while i < data.len() && (0x20..=0x7E).contains(&data[i]) && i - st < 240 {
                    i += 1;
                }
                if i - st >= min_ascii {
                    let s = String::from_utf8_lossy(&data[st..i]);
                    if q_re.as_ref().map(|r| r.is_match(&s)).unwrap_or(true) {
                        hits.push(format!("[ascii @0x{st:x}] {s}"));
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    if scan_wide {
        let mut j = 0usize;
        while j + 1 < data.len() && hits.len() < cap_hits {
            if (0x20..=0x7E).contains(&data[j]) && data[j + 1] == 0 {
                let st = j;
                let mut s = String::new();
                while j + 1 < data.len()
                    && (0x20..=0x7E).contains(&data[j])
                    && data[j + 1] == 0
                    && s.len() < 200
                {
                    s.push(data[j] as char);
                    j += 2;
                }
                if s.len() >= min_wide && q_re.as_ref().map(|r| r.is_match(&s)).unwrap_or(true) {
                    hits.push(format!("[utf16le @0x{st:x}] {s}"));
                }
            } else {
                j += 1;
            }
        }
    }

    let enc_label = if scan_ascii && scan_wide {
        "ascii+utf16le"
    } else if scan_wide {
        "utf16le"
    } else {
        "ascii"
    };
    let mut lines = vec![format!(
        "## Strings ({} B | min_len={} | encoding={} | {} hit(s))",
        bytes.len(),
        if scan_ascii { min_ascii } else { min_wide },
        enc_label,
        hits.len()
    )];
    if hits.is_empty() {
        lines.push("*(no matching printable strings found)*".to_string());
    } else {
        lines.extend(hits);
    }
    lines.join("\n")
}

fn classify_import_risk_bucket(name: &str) -> Option<&'static str> {
    let low = name.to_ascii_lowercase();
    if [
        "createprocess",
        "shellexecute",
        "winexec",
        "system",
        "popen",
        "execve",
        "execvp",
        "execl",
        "posix_spawn",
        "loadlibrary",
        "dlopen",
    ]
    .iter()
    .any(|k| low.contains(k))
    {
        return Some("exec");
    }
    if [
        "virtualalloc",
        "virtualprotect",
        "writeprocessmemory",
        "createremotethread",
        "mmap",
        "mprotect",
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "gets",
    ]
    .iter()
    .any(|k| low.contains(k))
    {
        return Some("memory");
    }
    if [
        "namedpipe",
        "rpcserver",
        "ndrserver",
        "cocreateinstance",
        "createservice",
        "openservice",
        "deviceiocontrol",
    ]
    .iter()
    .any(|k| low.contains(k))
    {
        return Some("ipc_rpc");
    }
    if [
        "createfile",
        "writefile",
        "deletefile",
        "movefile",
        "copyfile",
        "setfilesecurity",
        "setnamedsecurityinfo",
        "fopen",
        "unlink",
        "chmod",
        "chown",
    ]
    .iter()
    .any(|k| low.contains(k))
    {
        return Some("file_path");
    }
    if [
        "wsastartup",
        "wsaconnect",
        "httpsendrequest",
        "internetopen",
        "winhttp",
        "socket",
        "connect",
        "bind",
        "listen",
        "sendto",
        "recvfrom",
    ]
    .iter()
    .any(|k| low.contains(k))
    {
        return Some("net");
    }
    if [
        "adjusttoken",
        "impersonate",
        "openprocesstoken",
        "logonuser",
        "setuid",
        "setgid",
    ]
    .iter()
    .any(|k| low.contains(k))
    {
        return Some("priv_auth");
    }
    if [
        "cryptacquire",
        "cryptdecrypt",
        "cryptencrypt",
        "bcrypt",
        "evp_",
        "aes_",
        "rsa_",
    ]
    .iter()
    .any(|k| low.contains(k))
    {
        return Some("crypto");
    }
    None
}

fn classify_surface_string(s: &str) -> Option<&'static str> {
    let low = s.to_ascii_lowercase();
    if low.contains("\\\\.\\pipe\\") || low.contains("/pipe/") {
        return Some("named_pipes");
    }
    if low.contains("ncacn_") || low.contains("ncalrpc:") {
        return Some("rpc_endpoints");
    }
    if low.starts_with("http://")
        || low.starts_with("https://")
        || low.starts_with("ws://")
        || low.starts_with("wss://")
    {
        if !low.contains("schemas.microsoft.com")
            && !low.contains("www.w3.org/")
            && !low.contains("ns.adobe.com")
        {
            return Some("urls");
        }
        return None;
    }
    if let Some(pos) = low.find("://") {
        let scheme = &low[..pos];
        if (2..=18).contains(&scheme.len())
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
            && !matches!(scheme, "http" | "https" | "ws" | "wss" | "urn")
        {
            return Some("uri_schemes");
        }
    }
    if low.starts_with("hklm\\")
        || low.starts_with("hkcu\\")
        || low.starts_with("hkcr\\")
        || low.starts_with("hkey_")
        || low.contains("software\\")
        || low.contains("system\\currentcontrolset\\")
    {
        return Some("registry_keys");
    }
    if low.contains("cmd.exe")
        || low.contains("powershell")
        || low.contains("/bin/sh")
        || low.contains("/bin/bash")
        || (low.contains(" %s") && (low.contains(" --") || low.contains("/c ")))
    {
        return Some("cmd_templates");
    }
    if (low.contains('/') || low.contains('\\'))
        && [
            ".dll", ".exe", ".so", ".dylib", ".sqlite", ".db", "/etc/", "/var/", "/tmp/",
        ]
        .iter()
        .any(|k| low.contains(k))
    {
        return Some("interesting_paths");
    }
    None
}

/// Pure-Rust single-pass native binary surface inspector (PE/ELF/Mach-O/raw).
/// Emits structured JSON with format/mitigations, risk-bucketed imports/exports,
/// and categorized ASCII + UTF-16LE surface artifacts with file offset + RVA/VAddr.
pub fn inspect_binary_surface(bytes: &[u8]) -> Value {
    let t0 = Instant::now();
    let mut header_lines = Vec::new();
    let mut pe_ctx: Option<PeContext> = None;
    let mut elf_ctx: Option<ElfContext> = None;
    let mut macho_ctx: Option<MachoContext> = None;
    let format = if bytes.starts_with(b"MZ") && bytes.len() > 0x44 {
        let pe_off = read_u32_le(bytes, 0x3C).unwrap_or(0) as usize;
        if bytes.get(pe_off..pe_off + 4) == Some(b"PE\0\0") {
            pe_ctx = Some(parse_pe_details(bytes, pe_off, &mut header_lines));
            "pe"
        } else {
            "mz"
        }
    } else if bytes.starts_with(b"\x7FELF") && bytes.len() >= 20 {
        elf_ctx = Some(parse_elf_details(bytes, &mut header_lines));
        "elf"
    } else if let Some(mc) = parse_macho_details(bytes, &mut header_lines) {
        macho_ctx = Some(mc);
        "macho"
    } else {
        "raw"
    };

    let mut import_buckets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut push_import = |sym: &str| {
        if let Some(bucket) = classify_import_risk_bucket(sym) {
            let list = import_buckets.entry(bucket.to_string()).or_default();
            if list.len() < 24 && !list.iter().any(|x| x == sym) {
                list.push(sym.to_string());
            }
        }
    };
    if let Some(ref pe) = pe_ctx {
        for (_, sym) in &pe.iat_map {
            push_import(sym);
        }
    }
    for ln in &header_lines {
        if let Some(rest) = ln
            .strip_prefix("### ELF Imported Symbols")
            .or_else(|| ln.strip_prefix("### Mach-O Symbols"))
        {
            if let Some((_, syms)) = rest.split_once(':') {
                for sym in syms.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    push_import(sym);
                }
            }
        } else if ln.starts_with("- `") && ln.contains("`: ") {
            if let Some((_, syms)) = ln.split_once("`: ") {
                for sym in syms.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    push_import(sym);
                }
            }
        }
    }

    let mut artifacts: BTreeMap<&'static str, Vec<Value>> = BTreeMap::from([
        ("named_pipes", Vec::new()),
        ("rpc_endpoints", Vec::new()),
        ("urls", Vec::new()),
        ("uri_schemes", Vec::new()),
        ("registry_keys", Vec::new()),
        ("cmd_templates", Vec::new()),
        ("interesting_paths", Vec::new()),
    ]);
    let mut seen_vals: std::collections::HashSet<String> = std::collections::HashSet::new();
    let data = &bytes[..bytes.len().min(16 * 1024 * 1024)];

    let mut record_str = |s: &str, enc: &str, off: usize| {
        let trimmed = s.trim();
        let Some(cat) = classify_surface_string(trimmed) else {
            return;
        };
        let bucket = artifacts.get_mut(cat).unwrap();
        if bucket.len() >= 24 || !seen_vals.insert(format!("{cat}:{trimmed}")) {
            return;
        }
        let va_hint = pe_ctx
            .as_ref()
            .and_then(|p| {
                file_offset_to_rva(off, &p.secs).map(|(r, sec)| format!("rva=0x{r:x} ({sec})"))
            })
            .or_else(|| {
                elf_ctx.as_ref().and_then(|e| {
                    elf_file_offset_to_vaddr(off, &e.secs)
                        .map(|(v, sec)| format!("vaddr=0x{v:x} ({sec})"))
                })
            })
            .or_else(|| {
                macho_ctx.as_ref().and_then(|m| {
                    macho_file_offset_to_vmaddr(off, m)
                        .map(|(v, sec)| format!("vaddr=0x{v:x} ({sec})"))
                })
            });
        bucket.push(json!({
            "value": trimmed,
            "encoding": enc,
            "offset": format!("0x{off:x}"),
            "addr": va_hint,
        }));
    };

    // Single-pass ASCII strings (>= 5 chars)
    let mut i = 0usize;
    while i < data.len() {
        if (0x20..=0x7E).contains(&data[i]) {
            let st = i;
            while i < data.len() && (0x20..=0x7E).contains(&data[i]) && i - st < 260 {
                i += 1;
            }
            if i - st >= 5 {
                let s = String::from_utf8_lossy(&data[st..i]);
                record_str(&s, "ascii", st);
            }
        } else {
            i += 1;
        }
    }

    // Single-pass UTF-16LE wide strings (>= 5 chars)
    let mut j = 0usize;
    while j + 1 < data.len() {
        if (0x20..=0x7E).contains(&data[j]) && data[j + 1] == 0 {
            let st = j;
            let mut s = String::new();
            while j + 1 < data.len()
                && (0x20..=0x7E).contains(&data[j])
                && data[j + 1] == 0
                && s.len() < 240
            {
                s.push(data[j] as char);
                j += 2;
            }
            if s.len() >= 5 {
                record_str(&s, "utf16le", st);
            }
        } else {
            j += 1;
        }
    }

    let total_risky_imports: usize = import_buckets.values().map(|v| v.len()).sum();
    let total_surface_artifacts: usize = artifacts.values().map(|v| v.len()).sum();
    let ent = shannon_entropy(&bytes[..bytes.len().min(4 * 1024 * 1024)]);

    json!({
        "ok": true,
        "format": format,
        "size_bytes": bytes.len(),
        "sha256": sha256_hex(bytes),
        "entropy": (ent * 100.0).round() / 100.0,
        "elapsed_ms": (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
        "header_summary": header_lines.into_iter().take(12).collect::<Vec<_>>(),
        "total_risky_imports": total_risky_imports,
        "import_risk_buckets": import_buckets,
        "total_surface_artifacts": total_surface_artifacts,
        "artifacts": artifacts,
    })
}

pub fn format_binary_surface_md(surf: &Value) -> String {
    let mut out = vec![format!(
        "# BINARY SURFACE `{}` ({} B | entropy={} | {}ms)",
        surf["format"].as_str().unwrap_or("bin"),
        surf["size_bytes"].as_u64().unwrap_or(0),
        surf["entropy"].as_f64().unwrap_or(0.0),
        surf["elapsed_ms"].as_f64().unwrap_or(0.0),
    )];
    out.push(format!(
        "- SHA-256: `{}` | Risky Imports: {} | Surface Artifacts: {}",
        surf["sha256"].as_str().unwrap_or(""),
        surf["total_risky_imports"].as_u64().unwrap_or(0),
        surf["total_surface_artifacts"].as_u64().unwrap_or(0),
    ));
    if let Some(hdrs) = surf["header_summary"].as_array() {
        for h in hdrs.iter().take(6).filter_map(Value::as_str) {
            out.push(h.to_string());
        }
    }
    if let Some(buckets) = surf["import_risk_buckets"].as_object() {
        if !buckets.is_empty() {
            out.push("\n## Risk-Bucketed Imports".to_string());
            for (k, v) in buckets {
                let items: Vec<&str> = v
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                out.push(format!(
                    "- **{k}** ({}): `{}`",
                    items.len(),
                    items.join("`, `")
                ));
            }
        }
    }
    if let Some(arts) = surf["artifacts"].as_object() {
        out.push("\n## Surface Artifacts".to_string());
        for (cat, v) in arts {
            let arr = v.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.is_empty() {
                continue;
            }
            out.push(format!("### {cat} ({})", arr.len()));
            for item in arr.iter().take(12) {
                let val = item["value"].as_str().unwrap_or("");
                let off = item["offset"].as_str().unwrap_or("");
                let enc = item["encoding"].as_str().unwrap_or("");
                let addr = item["addr"].as_str().unwrap_or("");
                if addr.is_empty() {
                    out.push(format!("  - `[{enc} @{off}]` {val}"));
                } else {
                    out.push(format!("  - `[{enc} @{off} {addr}]` {val}"));
                }
            }
        }
    }
    out.join("\n")
}

fn decode_ctl_code(code: u32) -> Value {
    let dev_type = (code >> 16) & 0xFFFF;
    let access = (code >> 14) & 0x3;
    let func = (code >> 2) & 0xFFF;
    let method = code & 0x3;
    let method_str = match method {
        0 => "METHOD_BUFFERED",
        1 => "METHOD_IN_DIRECT",
        2 => "METHOD_OUT_DIRECT",
        _ => "METHOD_NEITHER",
    };
    let access_str = match access {
        0 => "FILE_ANY_ACCESS",
        1 => "FILE_READ_DATA",
        2 => "FILE_WRITE_DATA",
        _ => "FILE_READ_DATA|FILE_WRITE_DATA",
    };
    let mut risk_flags = Vec::new();
    if method == 3 {
        risk_flags.push("METHOD_NEITHER");
    }
    if access == 0 {
        risk_flags.push("FILE_ANY_ACCESS");
    }
    json!({
        "code": format!("0x{code:08x}"),
        "device_type": format!("0x{dev_type:04x}"),
        "function": format!("0x{func:03x}"),
        "method": method_str,
        "access": access_str,
        "risk_flags": risk_flags,
    })
}

fn is_plausible_ctl_code(code: u32) -> bool {
    let dev_type = (code >> 16) & 0xFFFF;
    let func = (code >> 2) & 0xFFF;
    let valid_dev = (0x0011..=0x0055).contains(&dev_type) || (0x8000..=0xFFFE).contains(&dev_type);
    if !valid_dev || (dev_type != 0x0022 && func == 0) {
        return false;
    }
    // Filter out printable 4-byte ASCII constants like 'TEST' / 'DATA'
    !code.to_le_bytes().iter().all(|b| (0x20..=0x7E).contains(b))
}

fn is_pipe_or_device_artifact(s: &str) -> bool {
    let low = s.to_ascii_lowercase();
    low.contains(r"\\.\pipe\")
        || low.starts_with(r"\device\")
        || low.starts_with(r"\dosdevices\")
        || low.starts_with(r"\\.\")
        || low.contains("ncacn_np:")
}

/// Pure-Rust Win32 driver / native IPC static slicer (`--ioctl` & `--pipes`):
/// extracts decoded `CTL_CODE` immediates (`METHOD_NEITHER`/`FILE_ANY_ACCESS`), IAT XREFs,
/// ASCII/UTF-16LE `\\.\pipe\*` / `\Device\*` / `\DosDevices\*` strings & XREFs, and PE exports.
pub fn inspect_pe_ioctl_and_pipes(
    bytes: &[u8],
    label: &str,
    include_ioctl: bool,
    include_pipes: bool,
    query: Option<&str>,
) -> (String, Value) {
    let t0 = Instant::now();
    let q_re = query.and_then(|q| {
        Regex::new(&format!("(?i){q}"))
            .or_else(|_| Regex::new(&format!("(?i){}", regex::escape(q))))
            .ok()
    });

    let mut dummy_hdr = Vec::new();
    let mut pe_ctx: Option<PeContext> = None;
    let mut arch = "unknown";
    if bytes.starts_with(b"MZ") && bytes.len() > 0x44 {
        let pe_off = read_u32_le(bytes, 0x3C).unwrap_or(0) as usize;
        if bytes.get(pe_off..pe_off + 4) == Some(b"PE\0\0") {
            let machine = read_u16_le(bytes, pe_off + 4).unwrap_or(0);
            arch = match machine {
                0x8664 => "x86_64",
                0x014c => "x86",
                0xaa64 => "ARM64",
                _ => "pe",
            };
            pe_ctx = Some(parse_pe_details(bytes, pe_off, &mut dummy_hdr));
        }
    }

    let exports: Vec<String> = extract_pe_exports_set(bytes).into_iter().take(80).collect();

    let mut ioctl_iat_imports: Vec<String> = Vec::new();
    let mut ioctl_iat_xrefs: Vec<String> = Vec::new();
    let mut ioctl_codes: Vec<Value> = Vec::new();
    if include_ioctl {
        if let Some(ref pe) = pe_ctx {
            let ioctl_re = Regex::new(
                r"(?i)(?:DeviceIoControl|IoCreateDevice|IoCreateSymbolicLink|MmMapIoSpace|ZwMapViewOfSection|ZwOpenSection|ProbeForRead|ProbeForWrite|ExAllocatePool)",
            )
            .unwrap();
            for (_, sym) in &pe.iat_map {
                if ioctl_re.is_match(sym) && !ioctl_iat_imports.contains(sym) {
                    ioctl_iat_imports.push(sym.clone());
                }
            }
            ioctl_iat_xrefs = scan_pe64_xrefs(bytes, pe, &[], Some(&ioctl_re), 40);

            let mut seen_codes = std::collections::HashSet::<u32>::new();
            for s in &pe.secs {
                if (s.chars & 0x2000_0000) == 0 || s.raw_size < 5 {
                    continue;
                }
                let start = s.raw_ptr as usize;
                let len = (s.raw_size as usize).min(16 * 1024 * 1024);
                let Some(code) = bytes.get(start..start.saturating_add(len).min(bytes.len()))
                else {
                    continue;
                };
                let mut i = 0usize;
                while i + 5 <= code.len() && ioctl_codes.len() < 80 {
                    let b0 = code[i];
                    let imm_pair: Option<(u32, usize)> =
                        if (b0 == 0x3D || b0 == 0x2D || (0xB8..=0xBF).contains(&b0))
                            && i + 5 <= code.len()
                        {
                            Some((
                                u32::from_le_bytes([
                                    code[i + 1],
                                    code[i + 2],
                                    code[i + 3],
                                    code[i + 4],
                                ]),
                                5,
                            ))
                        } else if i + 6 <= code.len()
                            && ((b0 == 0x41 && (0xB8..=0xBF).contains(&code[i + 1]))
                                || (b0 == 0x81 && (0xE8..=0xFF).contains(&code[i + 1])))
                        {
                            Some((
                                u32::from_le_bytes([
                                    code[i + 2],
                                    code[i + 3],
                                    code[i + 4],
                                    code[i + 5],
                                ]),
                                6,
                            ))
                        } else if (b0 == 0x41 || b0 == 0x48 || b0 == 0x49)
                            && i + 7 <= code.len()
                            && code[i + 1] == 0x81
                            && (0xE8..=0xFF).contains(&code[i + 2])
                        {
                            Some((
                                u32::from_le_bytes([
                                    code[i + 3],
                                    code[i + 4],
                                    code[i + 5],
                                    code[i + 6],
                                ]),
                                7,
                            ))
                        } else {
                            None
                        };
                    if let Some((cand, step)) = imm_pair {
                        if is_plausible_ctl_code(cand) {
                            let code_hex = format!("0x{cand:08x}");
                            if q_re.as_ref().map(|r| r.is_match(&code_hex)).unwrap_or(true)
                                && seen_codes.insert(cand)
                            {
                                let insn_rva = s.vaddr.saturating_add(i as u32);
                                let func_rva = if pe.is_pe64 {
                                    find_enclosing_x64_func_rva(code, s.vaddr, i)
                                } else {
                                    insn_rva
                                };
                                let mut obj = decode_ctl_code(cand);
                                if let Some(m) = obj.as_object_mut() {
                                    m.insert("section".to_string(), json!(s.name));
                                    m.insert(
                                        "file_offset".to_string(),
                                        json!(format!("0x{:x}", start + i)),
                                    );
                                    m.insert(
                                        "insn_rva".to_string(),
                                        json!(format!("0x{insn_rva:x}")),
                                    );
                                    m.insert(
                                        "func_rva".to_string(),
                                        json!(format!("0x{func_rva:x}")),
                                    );
                                }
                                ioctl_codes.push(obj);
                                i += step;
                                continue;
                            }
                        }
                    }
                    i += 1;
                }
            }
        }
    }

    let mut device_pipes: Vec<Value> = Vec::new();
    let mut pipe_str_rvas: Vec<(u32, String)> = Vec::new();
    let mut pipe_str_xrefs: Vec<String> = Vec::new();
    let mut pipe_iat_imports: Vec<String> = Vec::new();
    if include_pipes {
        let mut seen_pipe_vals = std::collections::HashSet::<String>::new();
        let data = &bytes[..bytes.len().min(24 * 1024 * 1024)];
        let mut push_pipe = |st: usize, enc: &str, s: String| -> bool {
            if device_pipes.len() >= 120 {
                return false;
            }
            if !is_pipe_or_device_artifact(&s) {
                return true;
            }
            if !q_re.as_ref().map(|r| r.is_match(&s)).unwrap_or(true) {
                return true;
            }
            if !seen_pipe_vals.insert(s.clone()) {
                return true;
            }
            if let Some((rva, sec)) = pe_ctx
                .as_ref()
                .and_then(|p| file_offset_to_rva(st, &p.secs))
            {
                pipe_str_rvas.push((rva, s.clone()));
                device_pipes.push(json!({
                    "value": s,
                    "encoding": enc,
                    "offset": format!("0x{st:x}"),
                    "rva": format!("0x{rva:x}"),
                    "section": sec,
                }));
            } else {
                device_pipes.push(json!({
                    "value": s,
                    "encoding": enc,
                    "offset": format!("0x{st:x}"),
                }));
            }
            device_pipes.len() < 120
        };

        let mut i = 0usize;
        while i < data.len() {
            if (0x20..=0x7E).contains(&data[i]) {
                let st = i;
                while i < data.len() && (0x20..=0x7E).contains(&data[i]) && i - st < 240 {
                    i += 1;
                }
                if i - st >= 6 {
                    let s = String::from_utf8_lossy(&data[st..i]).into_owned();
                    if !push_pipe(st, "ascii", s) {
                        break;
                    }
                }
            } else {
                i += 1;
            }
        }
        let mut j = 0usize;
        while j + 1 < data.len() {
            if (0x20..=0x7E).contains(&data[j]) && data[j + 1] == 0 {
                let st = j;
                let mut s = String::new();
                while j + 1 < data.len()
                    && (0x20..=0x7E).contains(&data[j])
                    && data[j + 1] == 0
                    && s.len() < 200
                {
                    s.push(data[j] as char);
                    j += 2;
                }
                if s.len() >= 6 && !push_pipe(st, "utf16le", s) {
                    break;
                }
            } else {
                j += 1;
            }
        }

        if let Some(ref pe) = pe_ctx {
            let pipe_iat_re = Regex::new(
                r"(?i)(?:CreateNamedPipe|ConnectNamedPipe|ImpersonateNamedPipeClient|ConvertStringSecurityDescriptor|SetSecurityDescriptorDacl|RpcServerUseProtseq)",
            )
            .unwrap();
            for (_, sym) in &pe.iat_map {
                if pipe_iat_re.is_match(sym) && !pipe_iat_imports.contains(sym) {
                    pipe_iat_imports.push(sym.clone());
                }
            }
            if !pipe_str_rvas.is_empty() {
                pipe_str_xrefs = scan_pe64_xrefs(bytes, pe, &pipe_str_rvas, None, 60);
            }
        }
    }

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
    let mut md = vec![format!(
        "# BINARY IOCTL / PIPE SURFACE `{label}` ({arch} | ioctls={}, pipes={}, ioctl_xrefs={}, exports={} in {elapsed_ms}ms)",
        ioctl_codes.len(),
        device_pipes.len(),
        ioctl_iat_xrefs.len(),
        exports.len()
    )];
    if !ioctl_iat_imports.is_empty() {
        md.push(format!(
            "- **IOCTL/Driver Imports**: `{}`",
            ioctl_iat_imports.join("`, `")
        ));
    }
    if !ioctl_codes.is_empty() {
        md.push(format!(
            "\n## Candidate CTL_CODE Constants ({})",
            ioctl_codes.len()
        ));
        for c in ioctl_codes.iter().take(25) {
            md.push(format!(
                "- `{}` dev=`{}` fn=`{}` `{}` `{}` (insn={}, func={})",
                c["code"].as_str().unwrap_or(""),
                c["device_type"].as_str().unwrap_or(""),
                c["function"].as_str().unwrap_or(""),
                c["method"].as_str().unwrap_or(""),
                c["access"].as_str().unwrap_or(""),
                c["insn_rva"].as_str().unwrap_or(""),
                c["func_rva"].as_str().unwrap_or(""),
            ));
        }
    }
    if !device_pipes.is_empty() {
        md.push(format!(
            "\n## Named Pipes & Device Paths ({})",
            device_pipes.len()
        ));
        for p in device_pipes.iter().take(25) {
            md.push(format!(
                "- `[{} @{} {}]` `{}`",
                p["encoding"].as_str().unwrap_or(""),
                p["offset"].as_str().unwrap_or(""),
                p["rva"].as_str().unwrap_or(""),
                p["value"].as_str().unwrap_or(""),
            ));
        }
    }
    if !pipe_iat_imports.is_empty() {
        md.push(format!(
            "- **Pipe/SDDL Imports**: `{}`",
            pipe_iat_imports.join("`, `")
        ));
    }
    if !exports.is_empty() {
        md.push(format!(
            "\n## PE Exports ({} shown)\n{}",
            exports.len(),
            exports
                .iter()
                .take(25)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let jv = json!({
        "ok": true,
        "format": "binary-ioctl-pipes",
        "target": label,
        "arch": arch,
        "elapsed_ms": elapsed_ms,
        "exports": exports,
        "ioctl_iat_imports": ioctl_iat_imports,
        "ioctl_iat_xrefs": ioctl_iat_xrefs,
        "ioctl_codes": ioctl_codes,
        "device_pipes": device_pipes,
        "pipe_str_xrefs": pipe_str_xrefs,
        "pipe_iat_imports": pipe_iat_imports,
    });
    (md.join("\n"), jv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_embedded_pe_rpc_interface_uuid_ndr20() {
        // Construct a synthetic 0x80-byte buffer containing an x64 RPC_SERVER_INTERFACE (Length=0x60)
        // InterfaceId: 12345678-1234-5678-9abc-def012345678 v1.2 + NDR20 TransferSyntax
        let mut buf = vec![0u8; 0x80];
        let base = 0x10usize;
        buf[base..base + 4].copy_from_slice(&0x60u32.to_le_bytes());
        buf[base + 4..base + 20].copy_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
            0x56, 0x78,
        ]);
        buf[base + 20..base + 22].copy_from_slice(&1u16.to_le_bytes());
        buf[base + 22..base + 24].copy_from_slice(&2u16.to_le_bytes());
        buf[base + 24..base + 40].copy_from_slice(&[
            0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
            0x48, 0x60,
        ]);
        let res = scan_pe_rpc_interfaces(&buf, true);
        assert_eq!(res.len(), 1);
        assert!(res[0].contains("12345678-1234-5678-9abc-def012345678"));
        assert!(res[0].contains("v1.2"));
        assert!(res[0].contains("NDR20"));
    }

    #[test]
    fn reports_elf64_security_mitigations_pie_nx_relro_canary() {
        // Minimal synthetic ELF64 header (e_type=ET_DYN=3, x86_64) + 2 program headers (PT_GNU_STACK NX, PT_GNU_RELRO)
        let mut elf = vec![0u8; 256];
        elf[0..4].copy_from_slice(b"\x7FELF");
        elf[4] = 2; // 64-bit
        elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN -> PIE
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes()); // x86_64
        elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff = 64
        elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize = 56
        elf[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum = 2
                                                          // PHDR 0: PT_GNU_STACK (RW only -> NX)
        elf[64..68].copy_from_slice(&0x6474_e551u32.to_le_bytes());
        elf[68..72].copy_from_slice(&6u32.to_le_bytes());
        // PHDR 1: PT_GNU_RELRO
        elf[120..124].copy_from_slice(&0x6474_e552u32.to_le_bytes());
        // Embed __stack_chk_fail marker
        elf[200..216].copy_from_slice(b"__stack_chk_fail");
        let md = inspect_binary_md(&elf, None, 10);
        assert!(md.contains("PIE"), "Expected PIE in {md}");
        assert!(md.contains("NX"), "Expected NX in {md}");
        assert!(md.contains("RELRO"), "Expected RELRO in {md}");
        assert!(md.contains("Canary"), "Expected Canary in {md}");
    }

    #[test]
    fn scans_pe64_rip_relative_string_and_iat_xrefs() {
        // Minimal synthetic PE64 with .text (RVA 0x1000, raw 0x200) + .rdata (RVA 0x2000, raw 0x400)
        // Contains Import Directory pointing to KERNEL32.dll!CreateProcessW at IAT RVA 0x2040
        // and wide string "\\\\.\\pipe\\DemoSvc" at RVA 0x2080, referenced by LEA + CALL in .text.
        let mut pe = vec![0u8; 0x600];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // x86_64
        pe[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
        pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
        let opt = 0x98usize;
        pe[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
        pe[opt + 24..opt + 32].copy_from_slice(&0x0001_4000_0000_u64.to_le_bytes());
        // Import Directory DataDirectory[1] at opt + 112 + 8 = opt + 120 -> RVA 0x2000
        pe[opt + 120..opt + 124].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[opt + 124..opt + 128].copy_from_slice(&0x28u32.to_le_bytes());

        let sh = opt + 0xF0; // 0x188
                             // Section 0: .text (vaddr 0x1000, raw 0x200, size 0x200, RX)
        pe[sh..sh + 5].copy_from_slice(b".text");
        pe[sh + 8..sh + 12].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sh + 36..sh + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        // Section 1: .rdata (vaddr 0x2000, raw 0x400, size 0x200, R)
        let sh1 = sh + 40;
        pe[sh1..sh1 + 6].copy_from_slice(b".rdata");
        pe[sh1 + 8..sh1 + 12].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sh1 + 12..sh1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[sh1 + 16..sh1 + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sh1 + 20..sh1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
        pe[sh1 + 36..sh1 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

        // .rdata @ 0x400 (RVA 0x2000): Import Descriptor
        // OFT=0x2040, Name=0x2050 ("KERNEL32.dll"), FirstThunk=0x2040
        pe[0x400..0x404].copy_from_slice(&0x2040u32.to_le_bytes());
        pe[0x40C..0x410].copy_from_slice(&0x2050u32.to_le_bytes());
        pe[0x410..0x414].copy_from_slice(&0x2040u32.to_le_bytes());
        // Thunk @ 0x440 (RVA 0x2040) -> Hint/Name @ RVA 0x2060
        pe[0x440..0x448].copy_from_slice(&0x2060u64.to_le_bytes());
        pe[0x450..0x45D].copy_from_slice(b"KERNEL32.dll\0");
        pe[0x462..0x471].copy_from_slice(b"CreateProcessW\0");
        // UTF-16LE string @ 0x480 (RVA 0x2080): "\\.\pipe\DemoSvc"
        let wide_str = r"\\.\pipe\DemoSvc";
        for (idx, ch) in wide_str.bytes().enumerate() {
            pe[0x480 + idx * 2] = ch;
            pe[0x480 + idx * 2 + 1] = 0;
        }

        // .text @ 0x200 (RVA 0x1000): INT3 pad -> func @ 0x1010 (sub rsp, 0x28)
        for b in &mut pe[0x200..0x210] {
            *b = 0xCC;
        }
        // func @ 0x210 (RVA 0x1010): 48 83 EC 28
        pe[0x210..0x214].copy_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
        // @ 0x214 (RVA 0x1014): LEA RCX, [RIP + disp32] -> target RVA 0x2080
        // disp32 = 0x2080 - (0x1014 + 7) = 0x1065
        pe[0x214..0x217].copy_from_slice(&[0x48, 0x8D, 0x0D]);
        pe[0x217..0x21B].copy_from_slice(&(0x1065i32).to_le_bytes());
        // @ 0x21B (RVA 0x101B): CALL [RIP + disp32] -> target IAT RVA 0x2040
        // disp32 = 0x2040 - (0x101B + 6) = 0x101F
        pe[0x21B..0x21D].copy_from_slice(&[0xFF, 0x15]);
        pe[0x21D..0x221].copy_from_slice(&(0x101Fi32).to_le_bytes());

        let md = inspect_binary_with_xref_md(&pe, Some("DemoSvc|CreateProcess"), 40, true);
        assert!(
            md.contains("rva=0x2080 (.rdata)"),
            "Expected RVA on string in:\n{md}"
        );
        assert!(
            md.contains("[str-xref] insn=0x1014 in func_rva=0x1010"),
            "Expected str-xref in:\n{md}"
        );
        assert!(
            md.contains("[iat-xref] call insn=0x101b in func_rva=0x1010"),
            "Expected iat-xref in:\n{md}"
        );
        assert!(
            md.contains("KERNEL32.dll!CreateProcessW"),
            "Expected IAT symbol in:\n{md}"
        );
    }

    #[test]
    fn scans_elf64_aarch64_adrp_add_string_xrefs_and_go_pclntab() {
        // 1. Minimal synthetic ELF64 AArch64 binary with .text (vaddr 0x1000, off 0x200), .rodata (vaddr 0x2000, off 0x300),
        //    .shstrtab (off 0x380), .dynstr (off 0x3C0), .dynsym (off 0x400), shdrs at off 0x480
        let mut elf = vec![0u8; 0x700];
        elf[0..4].copy_from_slice(b"\x7FELF");
        elf[4] = 2; // 64-bit
        elf[5] = 1; // LE
        elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        elf[18..20].copy_from_slice(&0xB7u16.to_le_bytes()); // AArch64
        elf[40..48].copy_from_slice(&0x480u64.to_le_bytes()); // e_shoff
        elf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        elf[60..62].copy_from_slice(&6u16.to_le_bytes()); // e_shnum (null + 5)
        elf[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx = 3 (.shstrtab)

        // .text @ 0x200 (vaddr 0x1000): ADRP X0, #0x1000 (page 0x1000 + 0x1000 = 0x2000); ADD X0, X0, #0x20 (-> 0x2020)
        // ADRP X0, +1 page: immlo=1 (bit29), immhi=0, rd=0 -> 0xB000_0000
        elf[0x200..0x204].copy_from_slice(&0xB000_0000u32.to_le_bytes());
        // ADD X0, X0, #0x20: 0x9100_0000 | (0x20 << 10) = 0x9100_8000
        elf[0x204..0x208].copy_from_slice(&0x9100_8000u32.to_le_bytes());
        // .rodata @ 0x320 (vaddr 0x2020): "/dev/ipc_ctl"
        elf[0x320..0x32D].copy_from_slice(b"/dev/ipc_ctl\0");
        // .shstrtab @ 0x380
        let shstrs = b"\0.text\0.rodata\0.shstrtab\0.dynstr\0.dynsym\0";
        elf[0x380..0x380 + shstrs.len()].copy_from_slice(shstrs);
        // .dynstr @ 0x3C0: "\0OnRemoteRequest\0system\0"
        let dstrs = b"\0OnRemoteRequest\0system\0";
        elf[0x3C0..0x3C0 + dstrs.len()].copy_from_slice(dstrs);
        // .dynsym @ 0x400: entry 1 = OnRemoteRequest (exported at vaddr 0x1000), entry 2 = system (imported shndx=0)
        elf[0x418..0x41C].copy_from_slice(&1u32.to_le_bytes()); // st_name = 1
        elf[0x41E..0x420].copy_from_slice(&1u16.to_le_bytes()); // st_shndx = 1 (.text)
        elf[0x420..0x428].copy_from_slice(&0x1000u64.to_le_bytes()); // st_value = 0x1000
        elf[0x430..0x434].copy_from_slice(&17u32.to_le_bytes()); // st_name = 17 ("system")
        elf[0x436..0x438].copy_from_slice(&0u16.to_le_bytes()); // st_shndx = 0 (imported)

        let write_shdr = |buf: &mut [u8],
                          idx: usize,
                          name: u32,
                          ty: u32,
                          flags: u64,
                          addr: u64,
                          off: u64,
                          sz: u64,
                          entsz: u64| {
            let h = 0x480 + idx * 64;
            buf[h..h + 4].copy_from_slice(&name.to_le_bytes());
            buf[h + 4..h + 8].copy_from_slice(&ty.to_le_bytes());
            buf[h + 8..h + 16].copy_from_slice(&flags.to_le_bytes());
            buf[h + 16..h + 24].copy_from_slice(&addr.to_le_bytes());
            buf[h + 24..h + 32].copy_from_slice(&off.to_le_bytes());
            buf[h + 32..h + 40].copy_from_slice(&sz.to_le_bytes());
            buf[h + 56..h + 64].copy_from_slice(&entsz.to_le_bytes());
        };
        write_shdr(&mut elf, 1, 1, 1, 0x6, 0x1000, 0x200, 0x100, 0); // .text
        write_shdr(&mut elf, 2, 7, 1, 0x2, 0x2000, 0x300, 0x80, 0); // .rodata
        write_shdr(&mut elf, 3, 15, 3, 0, 0, 0x380, 0x40, 0); // .shstrtab
        write_shdr(&mut elf, 4, 25, 3, 0, 0, 0x3C0, 0x40, 0); // .dynstr
        write_shdr(&mut elf, 5, 33, 11, 0, 0, 0x400, 0x60, 24); // .dynsym

        let md = inspect_binary_with_xref_md(&elf, Some("ipc_ctl"), 40, true);
        assert!(
            md.contains("vaddr=0x2020 (.rodata)"),
            "Expected ELF vaddr on string:\n{md}"
        );
        assert!(
            md.contains("[elf-str-xref] arm64 adrp+add=0x1000 in `OnRemoteRequest`+0x0"),
            "Expected ARM64 ADRP+ADD XREF:\n{md}"
        );
        assert!(
            md.contains("Notable ELF Symbols") && md.contains("system"),
            "Expected notable ELF symbols:\n{md}"
        );

        // 2. Synthetic Go 1.20 .gopclntab (magic 0xFFFFFFF1, 64-bit)
        let mut go_blob = vec![0u8; 0x200];
        let base = 0x20usize;
        go_blob[base..base + 8].copy_from_slice(&[0xF1, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x08]);
        go_blob[base + 8..base + 16].copy_from_slice(&2u64.to_le_bytes()); // nfunc = 2
        go_blob[base + 24..base + 32].copy_from_slice(&0x401000u64.to_le_bytes()); // textStart
        go_blob[base + 32..base + 40].copy_from_slice(&0x60u64.to_le_bytes()); // funcnameOffset = 0x60
        go_blob[base + 64..base + 72].copy_from_slice(&0xC0u64.to_le_bytes()); // pclnOffset = 0xC0
                                                                               // funcnames at base + 0x60 = 0x80
        go_blob[0x80..0x98].copy_from_slice(b"runtime.gcBgMarkWorker\0\0");
        go_blob[0x98..0xB0].copy_from_slice(b"main.handleRpcRequest\0\0\0");
        // functab at base + 0xC0 = 0xE0: 2 entries * 8B + _func structs at +0x20 and +0x28
        go_blob[0xE0..0xE4].copy_from_slice(&0x10u32.to_le_bytes());
        go_blob[0xE4..0xE8].copy_from_slice(&0x20u32.to_le_bytes());
        go_blob[0xE8..0xEC].copy_from_slice(&0x80u32.to_le_bytes());
        go_blob[0xEC..0xF0].copy_from_slice(&0x28u32.to_le_bytes());
        // _func 0 @ 0x100: nameOff = 0 ("runtime.gcBgMarkWorker")
        go_blob[0x104..0x108].copy_from_slice(&0u32.to_le_bytes());
        // _func 1 @ 0x108: nameOff = 0x18 ("main.handleRpcRequest")
        go_blob[0x10C..0x110].copy_from_slice(&0x18u32.to_le_bytes());

        let funcs = scan_go_pclntab_funcs(&go_blob, None, 10);
        assert_eq!(
            funcs.len(),
            1,
            "Expected 1 non-stdlib Go func, got {funcs:?}"
        );
        assert!(funcs[0].contains("main.handleRpcRequest") && funcs[0].contains("0x401080"));
    }

    #[test]
    fn parses_java_class_dotnet_clr_and_binary_patch_diff() {
        // 1. Minimal synthetic Java .class (major 55 = Java 11):
        // CP[1]=Utf8 "com/demo/Runner", CP[2]=Class(1), CP[3]=Utf8 "java/lang/Object", CP[4]=Class(3),
        // CP[5]=Utf8 "java/lang/Runtime", CP[6]=Class(5), CP[7]=Utf8 "exec", CP[8]=Utf8 "(Ljava/lang/String;)Ljava/lang/Process;",
        // CP[9]=NameAndType(7,8), CP[10]=Methodref(6,9), CP[11]=Utf8 "/bin/sh -c id", CP[12]=String(11)
        let mut cls: Vec<u8> = Vec::new();
        cls.extend_from_slice(b"\xCA\xFE\xBA\xBE");
        cls.extend_from_slice(&0u16.to_be_bytes());
        cls.extend_from_slice(&55u16.to_be_bytes());
        cls.extend_from_slice(&13u16.to_be_bytes()); // cp_count = 13 (1..12)
        let push_utf8 = |v: &mut Vec<u8>, s: &str| {
            v.push(1);
            v.extend_from_slice(&(s.len() as u16).to_be_bytes());
            v.extend_from_slice(s.as_bytes());
        };
        push_utf8(&mut cls, "com/demo/Runner"); // 1
        cls.push(7);
        cls.extend_from_slice(&1u16.to_be_bytes()); // 2
        push_utf8(&mut cls, "java/lang/Object"); // 3
        cls.push(7);
        cls.extend_from_slice(&3u16.to_be_bytes()); // 4
        push_utf8(&mut cls, "java/lang/Runtime"); // 5
        cls.push(7);
        cls.extend_from_slice(&5u16.to_be_bytes()); // 6
        push_utf8(&mut cls, "exec"); // 7
        push_utf8(&mut cls, "(Ljava/lang/String;)Ljava/lang/Process;"); // 8
        cls.push(12);
        cls.extend_from_slice(&7u16.to_be_bytes());
        cls.extend_from_slice(&8u16.to_be_bytes()); // 9
        cls.push(10);
        cls.extend_from_slice(&6u16.to_be_bytes());
        cls.extend_from_slice(&9u16.to_be_bytes()); // 10
        push_utf8(&mut cls, "/bin/sh -c id"); // 11
        cls.push(8);
        cls.extend_from_slice(&11u16.to_be_bytes()); // 12
                                                     // access_flags, this_class=2, super_class=4
        cls.extend_from_slice(&0x0021u16.to_be_bytes());
        cls.extend_from_slice(&2u16.to_be_bytes());
        cls.extend_from_slice(&4u16.to_be_bytes());

        let jmd = parse_java_class_md(&cls, None);
        assert!(
            jmd.contains("com/demo/Runner"),
            "missing class name:\n{jmd}"
        );
        assert!(
            jmd.contains("java/lang/Runtime.exec"),
            "missing Runtime.exec sink:\n{jmd}"
        );
        assert!(
            jmd.contains("/bin/sh -c id"),
            "missing string constant:\n{jmd}"
        );

        // 2. Synthetic .NET CLR BSJB metadata + #Strings stream
        let mut clr = vec![0u8; 0x120];
        let b = 0x10usize;
        clr[b..b + 4].copy_from_slice(b"BSJB");
        clr[b + 12..b + 16].copy_from_slice(&12u32.to_le_bytes()); // ver_len=12
        clr[b + 16..b + 26].copy_from_slice(b"v4.0.30319");
        // flags (2B) + streams=1 (2B) at b + 28
        clr[b + 30..b + 32].copy_from_slice(&1u16.to_le_bytes());
        // stream 0 hdr at b + 32: off=0x60, sz=0x50, name="#Strings\0\0\0\0"
        clr[b + 32..b + 36].copy_from_slice(&0x60u32.to_le_bytes());
        clr[b + 36..b + 40].copy_from_slice(&0x50u32.to_le_bytes());
        clr[b + 40..b + 49].copy_from_slice(b"#Strings\0");
        // #Strings body at b + 0x60 = 0x70
        let s_payload = b"\0BinaryFormatter\0ProcessStartInfo\0SafeFn\0";
        clr[0x70..0x70 + s_payload.len()].copy_from_slice(s_payload);
        let (ver, sinks) = scan_dotnet_clr_meta(&clr).unwrap();
        assert_eq!(ver, "v4.0.30319");
        assert!(
            sinks.iter().any(|s| s == "BinaryFormatter")
                && sinks.iter().any(|s| s == "ProcessStartInfo")
        );

        // 3. Binary patch diff
        let old_b = b"MZ\0\0____/api/v1/old_route\0invalid_old_check\0";
        let new_b = b"MZ\0\0____/api/v1/old_route\0/api/v2/admin_exec\0invalid_path_guard\0";
        let dmd = diff_binaries_or_archives_md(new_b, old_b, "new.dll", "old.dll", "dll");
        assert!(
            dmd.contains("+ /api/v2/admin_exec") && dmd.contains("- invalid_old_check"),
            "unexpected diff:\n{dmd}"
        );
    }

    #[test]
    fn parses_pe_delay_pdb_cert_overlay_manifest_ver_rva_and_find_bytes() {
        let mut pe = vec![0u8; 0x900];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // x86_64
        pe[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
        pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // opt_sz=240
        let opt = 0x98usize;
        pe[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
        pe[opt + 24..opt + 32].copy_from_slice(&0x0001_4000_0000u64.to_le_bytes());
        let dd = opt + 112;
        // DataDirectory[4] Authenticode (FILE OFFSET @0x600, size=0x40)
        pe[dd + 4 * 8..dd + 4 * 8 + 4].copy_from_slice(&0x600u32.to_le_bytes());
        pe[dd + 4 * 8 + 4..dd + 4 * 8 + 8].copy_from_slice(&0x40u32.to_le_bytes());
        // DataDirectory[6] Debug (RVA 0x2000, size=28)
        pe[dd + 6 * 8..dd + 6 * 8 + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[dd + 6 * 8 + 4..dd + 6 * 8 + 8].copy_from_slice(&28u32.to_le_bytes());
        // DataDirectory[13] Delay-Load (RVA 0x2100, size=64)
        pe[dd + 13 * 8..dd + 13 * 8 + 4].copy_from_slice(&0x2100u32.to_le_bytes());
        pe[dd + 13 * 8 + 4..dd + 13 * 8 + 8].copy_from_slice(&64u32.to_le_bytes());

        // Section 0: .text (vaddr 0x1000, raw 0x200..0x400)
        let s0 = opt + 0xF0;
        pe[s0..s0 + 5].copy_from_slice(b".text");
        pe[s0 + 8..s0 + 12].copy_from_slice(&0x200u32.to_le_bytes());
        pe[s0 + 12..s0 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[s0 + 16..s0 + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[s0 + 20..s0 + 24].copy_from_slice(&0x200u32.to_le_bytes());
        pe[s0 + 36..s0 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        // Prologue + x64 instruction pattern @0x220 (RVA 0x1020)
        pe[0x220..0x228].copy_from_slice(&[0x48, 0x83, 0xEC, 0x28, 0x48, 0x8D, 0x05, 0x11]);

        // Section 1: .rdata (vaddr 0x2000, raw 0x400..0x600)
        let s1 = s0 + 40;
        pe[s1..s1 + 6].copy_from_slice(b".rdata");
        pe[s1 + 8..s1 + 12].copy_from_slice(&0x200u32.to_le_bytes());
        pe[s1 + 12..s1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[s1 + 16..s1 + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[s1 + 20..s1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
        pe[s1 + 36..s1 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

        // Debug directory @0x400 (RVA 0x2000) -> RSDS @0x440
        pe[0x400 + 12..0x400 + 16].copy_from_slice(&2u32.to_le_bytes());
        pe[0x400 + 16..0x400 + 20].copy_from_slice(&40u32.to_le_bytes());
        pe[0x400 + 24..0x400 + 28].copy_from_slice(&0x440u32.to_le_bytes());
        pe[0x440..0x444].copy_from_slice(b"RSDS");
        pe[0x454..0x458].copy_from_slice(&7u32.to_le_bytes());
        pe[0x458..0x467].copy_from_slice(b"C:\\b\\demo.pdb\0\0");

        // Delay-Load descriptor @0x500 (RVA 0x2100)
        pe[0x500..0x504].copy_from_slice(&1u32.to_le_bytes()); // grAttrs=1 (RVA)
        pe[0x504..0x508].copy_from_slice(&0x2140u32.to_le_bytes()); // szName
        pe[0x510..0x514].copy_from_slice(&0x2160u32.to_le_bytes()); // pINT
        pe[0x540..0x54D].copy_from_slice(b"WINHTTP.dll\0\0");
        pe[0x560..0x568].copy_from_slice(&0x2180u64.to_le_bytes()); // thunk[0]
        pe[0x580..0x58D].copy_from_slice(b"\0\0WinHttpOpen");

        // Authenticode blob @0x600 with CN OID 55 04 03 "Acme Signer" + Manifest + VersionInfo in tail
        let cert_snippet = b"\x30\x20\x55\x04\x03\x0C\x0BAcme Signer";
        pe[0x600..0x600 + cert_snippet.len()].copy_from_slice(cert_snippet);
        let man = b"<requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>";
        pe[0x680..0x680 + man.len()].copy_from_slice(man);
        let mut vi = Vec::new();
        for u in "CompanyName\0\0AcmeCorp\0".encode_utf16() {
            vi.extend_from_slice(&u.to_le_bytes());
        }
        pe[0x720..0x720 + vi.len()].copy_from_slice(&vi);

        let md = inspect_binary_md(&pe, None, 20);
        assert!(
            md.contains("WINHTTP.dll") && md.contains("WinHttpOpen"),
            "{md}"
        );
        assert!(md.contains("demo.pdb") && md.contains("age=7"), "{md}");
        assert!(md.contains("Acme Signer"), "{md}");
        assert!(md.contains("requireAdministrator"), "{md}");
        assert!(md.contains("CompanyName=\"AcmeCorp\""), "{md}");

        let rva_md = inspect_binary_address_md(&pe, "0x1024", false, 32).unwrap();
        assert!(
            rva_md.contains("offset=0x224")
                && rva_md.contains(".text")
                && rva_md.contains("0x1020"),
            "{rva_md}"
        );
        let va_md = inspect_binary_address_md(&pe, "0x140001024", true, 32).unwrap();
        assert!(
            va_md.contains("rva=0x1024") && va_md.contains("offset=0x224"),
            "{va_md}"
        );

        let hits_md = find_binary_bytes_md(&pe, "48 83 EC ?? 48 8D", 10).unwrap();
        assert!(
            hits_md.contains("0x220") && hits_md.contains("rva=0x1020"),
            "{hits_md}"
        );
    }

    #[test]
    fn parses_elf_deep_macho64_and_tar_ustar_longlink() {
        // 1. Minimal synthetic 64-bit ELF with PT_INTERP, PT_NOTE GNU Build-ID, DT_SONAME, DT_RPATH & imported symbol
        let mut elf = vec![0u8; 0x500];
        elf[0..4].copy_from_slice(b"\x7FELF");
        elf[4] = 2; // 64-bit
        elf[5] = 1; // LE
        elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes()); // x86_64
        elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff=64
        elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        elf[56..58].copy_from_slice(&2u16.to_le_bytes()); // phnum=2
                                                          // PHDR 0: PT_INTERP @0x100 len 28
        elf[64..68].copy_from_slice(&3u32.to_le_bytes());
        elf[72..80].copy_from_slice(&0x100u64.to_le_bytes());
        elf[96..104].copy_from_slice(&28u64.to_le_bytes());
        elf[0x100..0x11C].copy_from_slice(b"/lib64/ld-linux-x86-64.so.2\0");
        // PHDR 1: PT_NOTE @0x140 len 20 (namesz=4, descsz=4, type=3, "GNU\0", 0xDEADBEEF)
        elf[120..124].copy_from_slice(&4u32.to_le_bytes());
        elf[128..136].copy_from_slice(&0x140u64.to_le_bytes());
        elf[152..160].copy_from_slice(&20u64.to_le_bytes());
        elf[0x140..0x144].copy_from_slice(&4u32.to_le_bytes());
        elf[0x144..0x148].copy_from_slice(&4u32.to_le_bytes());
        elf[0x148..0x14C].copy_from_slice(&3u32.to_le_bytes());
        elf[0x14C..0x150].copy_from_slice(b"GNU\0");
        elf[0x150..0x154].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        // Section table @0x300 (4 sections: null, .shstrtab, .dynstr, .dynamic)
        elf[40..48].copy_from_slice(&0x300u64.to_le_bytes());
        elf[58..60].copy_from_slice(&64u16.to_le_bytes());
        elf[60..62].copy_from_slice(&5u16.to_le_bytes());
        elf[62..64].copy_from_slice(&1u16.to_le_bytes());
        let shstr = b"\0.shstrtab\0.dynstr\0.dynamic\0.dynsym\0";
        elf[0x180..0x180 + shstr.len()].copy_from_slice(shstr);
        let dynstr = b"\0libc.so.6\0libdemo.so.1\0$ORIGIN/../lib\0system\0";
        elf[0x1B0..0x1B0 + dynstr.len()].copy_from_slice(dynstr);
        // .dynamic @0x200: DT_NEEDED(libc), DT_SONAME(libdemo), DT_RUNPATH($ORIGIN), DT_NULL
        let dyn_ents: [(u64, u64); 4] = [(1, 1), (14, 11), (29, 24), (0, 0)];
        for (i, (t, v)) in dyn_ents.iter().enumerate() {
            elf[0x200 + i * 16..0x208 + i * 16].copy_from_slice(&t.to_le_bytes());
            elf[0x208 + i * 16..0x210 + i * 16].copy_from_slice(&v.to_le_bytes());
        }
        // .dynsym @0x260: entry 0 null, entry 1: st_name="system"@37, shndx=0 (imported)
        elf[0x260 + 24..0x260 + 28].copy_from_slice(&37u32.to_le_bytes());
        let write_sh =
            |buf: &mut [u8], idx: usize, nm: u32, ty: u32, off: u64, sz: u64, esz: u64| {
                let p = 0x300 + idx * 64;
                buf[p..p + 4].copy_from_slice(&nm.to_le_bytes());
                buf[p + 4..p + 8].copy_from_slice(&ty.to_le_bytes());
                buf[p + 24..p + 32].copy_from_slice(&off.to_le_bytes());
                buf[p + 32..p + 40].copy_from_slice(&sz.to_le_bytes());
                buf[p + 56..p + 64].copy_from_slice(&esz.to_le_bytes());
            };
        write_sh(&mut elf, 1, 1, 3, 0x180, shstr.len() as u64, 0);
        write_sh(&mut elf, 2, 11, 3, 0x1B0, dynstr.len() as u64, 0);
        write_sh(&mut elf, 3, 19, 6, 0x200, 64, 16);
        write_sh(&mut elf, 4, 28, 11, 0x260, 48, 24);
        let emd = inspect_binary_md(&elf, None, 20);
        assert!(
            emd.contains("/lib64/ld-linux-x86-64.so.2") && emd.contains("deadbeef"),
            "{emd}"
        );
        assert!(
            emd.contains("libdemo.so.1") && emd.contains("RPATH-CHECK"),
            "{emd}"
        );
        assert!(
            emd.contains("ELF Imported Symbols") && emd.contains("system"),
            "{emd}"
        );

        // 2. Synthetic Mach-O 64-bit binary (LC_SEGMENT_64 __TEXT + LC_LOAD_DYLIB + LC_CODE_SIGNATURE entitlements)
        let mut mo = vec![0u8; 0x300];
        mo[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // MH_MAGIC_64
        mo[4..8].copy_from_slice(&0x0100_000Cu32.to_le_bytes()); // ARM64
        mo[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        mo[16..20].copy_from_slice(&3u32.to_le_bytes()); // ncmds=3
        mo[20..24].copy_from_slice(&120u32.to_le_bytes()); // sizeofcmds
        mo[24..28].copy_from_slice(&0x0020_0000u32.to_le_bytes()); // PIE
                                                                   // cmd 0 @32: LC_SEGMENT_64 (72B) __TEXT vmaddr=0x100000000 fileoff=0x180 filesize=0x80
        let c0 = 32usize;
        mo[c0..c0 + 4].copy_from_slice(&0x19u32.to_le_bytes());
        mo[c0 + 4..c0 + 8].copy_from_slice(&72u32.to_le_bytes());
        mo[c0 + 8..c0 + 14].copy_from_slice(b"__TEXT");
        mo[c0 + 24..c0 + 32].copy_from_slice(&0x1_0000_0000u64.to_le_bytes());
        mo[c0 + 32..c0 + 40].copy_from_slice(&0x100u64.to_le_bytes());
        mo[c0 + 40..c0 + 48].copy_from_slice(&0x180u64.to_le_bytes());
        mo[c0 + 48..c0 + 56].copy_from_slice(&0x80u64.to_le_bytes());
        mo[c0 + 60..c0 + 64].copy_from_slice(&5u32.to_le_bytes()); // R+X
                                                                   // cmd 1 @104: LC_LOAD_DYLIB (32B) "/usr/lib/libSystem.B.dylib" -> needs >=24+path -> 52B -> pad to 56B
        let dylib = b"/usr/lib/libSystem.B.dylib\0";
        mo[16..20].copy_from_slice(&3u32.to_le_bytes());
        let c1 = 104usize;
        let c1_sz = 52usize;
        mo[c1..c1 + 4].copy_from_slice(&0x0Cu32.to_le_bytes());
        mo[c1 + 4..c1 + 8].copy_from_slice(&(c1_sz as u32).to_le_bytes());
        mo[c1 + 8..c1 + 12].copy_from_slice(&24u32.to_le_bytes());
        mo[c1 + 24..c1 + 24 + dylib.len()].copy_from_slice(dylib);
        // cmd 2 @156: LC_CODE_SIGNATURE (16B) -> dataoff=0x220 datasize=0x80
        let c2 = c1 + c1_sz;
        mo[20..24].copy_from_slice(&((72 + c1_sz + 16) as u32).to_le_bytes());
        mo[c2..c2 + 4].copy_from_slice(&0x1Du32.to_le_bytes());
        mo[c2 + 4..c2 + 8].copy_from_slice(&16u32.to_le_bytes());
        mo[c2 + 8..c2 + 12].copy_from_slice(&0x220u32.to_le_bytes());
        mo[c2 + 12..c2 + 16].copy_from_slice(&0x80u32.to_le_bytes());
        mo[0x190..0x194].copy_from_slice(&[0xD5, 0x03, 0x20, 0x1F]); // NOP
        let ent_xml = b"<key>com.apple.security.get-task-allow</key>";
        mo[0x220..0x220 + ent_xml.len()].copy_from_slice(ent_xml);
        let mmd = inspect_binary_md(&mo, None, 20);
        assert!(
            mmd.contains("ARM64")
                && mmd.contains("libSystem.B.dylib")
                && mmd.contains("com.apple.security.get-task-allow"),
            "{mmd}"
        );
        let mva = inspect_binary_address_md(&mo, "0x100000010", true, 32).unwrap();
        assert!(
            mva.contains("Mach-O va=0x100000010") && mva.contains("offset=0x190"),
            "{mva}"
        );
        let mfb = find_binary_bytes_md(&mo, "D5 03 ?? 1F", 5).unwrap();
        assert!(
            mfb.contains("va=0x100000010") && mfb.contains("__TEXT"),
            "{mfb}"
        );

        // 3. USTAR + GNU @LongLink TAR archive parser
        let mut tar = vec![0u8; 512 * 5];
        let long_path = b"very/long/nested/directory/prefix/service_config_extra.json\0";
        tar[0..13].copy_from_slice(b"././@LongLink");
        tar[124..136].copy_from_slice(format!("{:011o}\0", long_path.len()).as_bytes());
        tar[156] = b'L';
        tar[512..512 + long_path.len()].copy_from_slice(long_path);
        let hdr2 = 1024usize;
        let payload = br#"{"ok":true}"#;
        tar[hdr2..hdr2 + 9].copy_from_slice(b"short.tmp");
        tar[hdr2 + 124..hdr2 + 136].copy_from_slice(format!("{:011o}\0", payload.len()).as_bytes());
        tar[hdr2 + 156] = b'0';
        tar[1536..1536 + payload.len()].copy_from_slice(payload);
        let tmd = list_tar_md(&tar, Some("service_config"));
        assert!(
            tmd.contains("very/long/nested/directory/prefix/service_config_extra.json"),
            "{tmd}"
        );
        let member = read_tar_member(&tar, "service_config_extra.json").unwrap();
        assert_eq!(member, payload);

        // 4. Synthetic Python 3.11 .pyc (PEP-552 16B header + Marshal v4 TYPE_CODE + FLAG_REF/TYPE_REF)
        fn push_short_ascii(buf: &mut Vec<u8>, s: &str, intern_ref: bool) {
            let tag = if intern_ref { b'z' | 0x80 } else { b'z' };
            buf.push(tag);
            buf.push(s.len() as u8);
            buf.extend_from_slice(s.as_bytes());
        }
        fn push_bytes(buf: &mut Vec<u8>, raw: &[u8]) {
            buf.push(b's');
            buf.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            buf.extend_from_slice(raw);
        }
        let mut pyc = Vec::new();
        pyc.extend_from_slice(&3495u16.to_le_bytes()); // Python 3.11 magic
        pyc.extend_from_slice(&[0x0D, 0x0A]);
        pyc.extend_from_slice(&0u32.to_le_bytes()); // PEP-552 bitfield=0
        pyc.extend_from_slice(&0u32.to_le_bytes()); // mtime
        pyc.extend_from_slice(&0u32.to_le_bytes()); // size
                                                    // Root module code object
        pyc.push(b'c');
        for v in [0i32, 0, 0, 1, 2, 0] {
            pyc.extend_from_slice(&v.to_le_bytes());
        }
        push_bytes(&mut pyc, b"\x97\x00"); // co_code
                                           // co_consts: tuple of (String constant, nested Code object)
        pyc.push(b')');
        pyc.push(2);
        push_short_ascii(&mut pyc, "https://api.example.test/v1/health", false);
        // Nested function code object (Python 3.11 layout)
        pyc.push(b'c');
        for v in [2i32, 0, 0, 2, 3, 67] {
            pyc.extend_from_slice(&v.to_le_bytes());
        }
        push_bytes(&mut pyc, b"\x97\x00");
        pyc.push(b')');
        pyc.push(1);
        push_short_ascii(&mut pyc, "secret_const_token", false);
        pyc.push(b')');
        pyc.push(1);
        push_short_ascii(&mut pyc, "urllib_open", false);
        pyc.push(b')');
        pyc.push(2);
        push_short_ascii(&mut pyc, "endpoint", false);
        push_short_ascii(&mut pyc, "timeout", false);
        push_bytes(&mut pyc, b"\x00\x00"); // localspluskinds
        push_short_ascii(&mut pyc, "client.py", true); // ref #0 (after root? wait: root hasn't pushed ref yet -> ref #0)
        push_short_ascii(&mut pyc, "fetch_health", false);
        push_short_ascii(&mut pyc, "Client.fetch_health", false);
        pyc.extend_from_slice(&14i32.to_le_bytes()); // firstlineno
        push_bytes(&mut pyc, b""); // linetable
        push_bytes(&mut pyc, b""); // exceptiontable
                                   // Root co_names, localsplusnames, localspluskinds, filename (TYPE_REF 0!), name, qualname, firstlineno, linetable, exceptiontable
        pyc.push(b')');
        pyc.push(1);
        push_short_ascii(&mut pyc, "Client", false);
        pyc.push(b')');
        pyc.push(0); // localsplusnames
        push_bytes(&mut pyc, b""); // localspluskinds
        pyc.push(b'r');
        pyc.extend_from_slice(&0u32.to_le_bytes()); // filename via TYPE_REF -> "client.py"
        push_short_ascii(&mut pyc, "<module>", false);
        push_short_ascii(&mut pyc, "<module>", false);
        pyc.extend_from_slice(&1i32.to_le_bytes());
        push_bytes(&mut pyc, b"");
        push_bytes(&mut pyc, b"");

        assert!(is_pyc_magic(&pyc));
        let pmd = parse_pyc_md(&pyc, None);
        assert!(
            pmd.contains("Python 3.11")
                && pmd.contains("client.py")
                && pmd.contains("Client.fetch_health")
                && pmd.contains("https://api.example.test/v1/health")
                && pmd.contains("urllib_open"),
            "{pmd}"
        );
        let pmd_q = parse_pyc_md(&pyc, Some("secret_const"));
        assert!(
            pmd_q.contains("secret_const_token") && !pmd_q.contains("health"),
            "{pmd_q}"
        );
        let ptxt = extract_pyc_searchable_text(&pyc);
        assert!(
            ptxt.contains("Client.fetch_health:L14") && ptxt.contains("urllib_open"),
            "{ptxt}"
        );
    }

    #[test]
    fn extracts_strings_with_min_len_and_utf16le_filter() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"\x00\x00short\x00\x00");
        blob.extend_from_slice(b"API_TOKEN_ASCII_V268\x00\x00");
        for b in b"WIDE_SERVICE_V268" {
            blob.push(*b);
            blob.push(0);
        }
        blob.extend_from_slice(b"\x00\x00");

        let both = extract_strings_md(&blob, None, 8, 50, "");
        assert!(
            both.contains("API_TOKEN_ASCII_V268")
                && both.contains("WIDE_SERVICE_V268")
                && !both.contains("short"),
            "{both}"
        );

        let wide_only = extract_strings_md(&blob, None, 6, 50, "l");
        assert!(
            wide_only.contains("WIDE_SERVICE_V268") && !wide_only.contains("API_TOKEN_ASCII_V268"),
            "{wide_only}"
        );

        let queried = extract_strings_md(&blob, Some("TOKEN"), 8, 50, "s");
        assert!(
            queried.contains("API_TOKEN_ASCII_V268") && !queried.contains("WIDE_SERVICE_V268"),
            "{queried}"
        );
    }

    #[test]
    fn extracts_binary_surface_buckets_and_categorized_artifacts() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        blob.extend_from_slice(b"\x03\x00\x3E\x00\x01\x00\x00\x00");
        blob.resize(64, 0);
        blob.extend_from_slice(b"\\\\.\\pipe\\demo_ipc_v1\x00");
        blob.extend_from_slice(b"https://api.example.invalid/v1/status\x00");
        blob.extend_from_slice(b"HKLM\\SOFTWARE\\DemoVendor\\Agent\x00");
        blob.extend_from_slice(b"cmd.exe /c echo %s\x00");
        for b in b"ncalrpc:demo_rpc_ep" {
            blob.push(*b);
            blob.push(0);
        }
        blob.extend_from_slice(b"\x00\x00");

        let surf = inspect_binary_surface(&blob);
        assert_eq!(surf["ok"], true);
        assert!(surf["artifacts"]["named_pipes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["value"].as_str().unwrap().contains("demo_ipc_v1")));
        assert!(surf["artifacts"]["urls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["value"].as_str().unwrap().contains("api.example.invalid")));
        assert!(surf["artifacts"]["registry_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["value"].as_str().unwrap().contains("HKLM\\SOFTWARE")));
        assert!(surf["artifacts"]["cmd_templates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["value"].as_str().unwrap().contains("cmd.exe")));
        assert!(surf["artifacts"]["rpc_endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["value"].as_str().unwrap().contains("ncalrpc:demo_rpc_ep")));
        let md = format_binary_surface_md(&surf);
        assert!(
            md.contains("BINARY SURFACE") && md.contains("demo_ipc_v1"),
            "{md}"
        );
    }

    #[test]
    fn scans_electron_asar_and_zip_archives_without_disk_unpacking() {
        use std::io::Write;
        // 1. Minimal synthetic Electron ASAR archive
        let pkg = br#"{"name":"demo-app","version":"1.0.0","main":"main.js","scripts":{"postinstall":"node setup.js"},"capabilities":{"untrustedWorkspaces":{"supported":true}}}"#;
        let main_js = br#"
const { BrowserWindow, ipcMain, contextBridge, shell } = require('electron');
new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false, webSecurity: false } });
ipcMain.handle('app:exec', (ev, cmd) => execFile(cmd));
contextBridge.exposeInMainWorld('api', { send: (c, a) => ipcRenderer.send(c, a) });
shell.openExternal(url);
axios.post('/api/v1/quota/redeem', { voucherCode: code });
axios.get('/api/v1/quota/:id');
"#;
        let native_stub = b"MZ\x90\x00";
        let header_json = serde_json::json!({
            "files": {
                "package.json": { "size": pkg.len(), "offset": "0" },
                "main.js": { "size": main_js.len(), "offset": pkg.len().to_string() },
                "native": {
                    "files": {
                        "addon.node": { "size": native_stub.len(), "offset": (pkg.len() + main_js.len()).to_string(), "unpacked": true }
                    }
                }
            }
        });
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
        asar.extend_from_slice(pkg);
        asar.extend_from_slice(main_js);
        asar.extend_from_slice(native_stub);

        let (md, jv) =
            inspect_archive_surface(&asar, "asar", "app.asar", true, None).expect("asar surface");
        assert_eq!(jv["format"], "archive-surface");
        assert_eq!(jv["entry_counts"]["unpacked"], 1);
        assert_eq!(jv["native_bins"][0]["path"], "native/addon.node");
        assert!(jv["manifest_risks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kind"] == "lifecycle_install_script"));
        assert!(jv["manifest_risks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kind"] == "untrusted_workspaces_enabled"));
        assert!(jv["electron_security_flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "nodeIntegration_enabled" && f["severity"] == "HIGH"));
        assert!(jv["electron_security_flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "contextBridge_expose" && f["severity"] == "HIGH"));
        assert_eq!(jv["ipc_handlers"].as_array().unwrap().len(), 1);
        assert!(jv["js_surface"]["race_candidates"][0]["path"] == "/api/v1/quota/redeem");
        assert_eq!(
            jv["js_surface"]["flow_candidates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(md.contains("ARCHIVE SURFACE"), "{md}");

        // 2. Minimal synthetic VSIX/ZIP archive
        let mut zip_buf = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut zip_buf);
            let opts = zip::write::SimpleFileOptions::default();
            zw.start_file("extension/package.json", opts).unwrap();
            zw.write_all(br#"{"name":"ext","contributes":{"configuration":{"properties":{"ext.path":{"type":"string"}}}}}"#).unwrap();
            zw.start_file("extension/out/ext.js", opts).unwrap();
            zw.write_all(br#"protocol.registerStringProtocol('demo', h); fetch('/api/v1/orders/create'); axios.delete('/api/v1/orders/:id');"#).unwrap();
            zw.finish().unwrap();
        }
        let zbytes = zip_buf.into_inner();
        let (_, zjv) = inspect_archive_surface(&zbytes, "vsix", "demo.vsix", true, None)
            .expect("vsix surface");
        assert!(zjv["manifest_risks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kind"] == "workspace_overridable_setting"));
        assert!(zjv["electron_security_flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "protocol_handler"));
        assert_eq!(
            zjv["js_surface"]["flow_candidates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}
