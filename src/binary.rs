use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
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
            out.push(AsarEntry {
                path: full,
                offset: off,
                size: sz as usize,
                unpacked,
            });
        }
    }
}

/// Parse Electron `.asar` Chromium Pickle header -> (base_data_offset, sorted entries).
pub fn parse_asar_index(bytes: &[u8]) -> Result<(usize, Vec<AsarEntry>), String> {
    if bytes.len() < 16 {
        return Err("invalid .asar file (too short)".to_string());
    }
    let header_pickle_sz = read_u32_le(bytes, 4).ok_or("asar header truncated")? as usize;
    let json_len = read_u32_le(bytes, 12).ok_or("asar json_len truncated")? as usize;
    let json_end = 16usize.saturating_add(json_len);
    if json_end > bytes.len() {
        return Err("invalid .asar header JSON bounds".to_string());
    }
    let header_json: Value = serde_json::from_slice(&bytes[16..json_end])
        .map_err(|e| format!("invalid .asar JSON header: {e}"))?;
    let base_offset = 8usize.saturating_add(header_pickle_sz);
    let mut entries = Vec::new();
    walk_asar_tree(&header_json, "", &mut entries);
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((base_offset, entries))
}

pub fn read_asar_member(bytes: &[u8], entry_path: &str) -> Result<Vec<u8>, String> {
    let (base, entries) = parse_asar_index(bytes)?;
    let norm = entry_path.trim_start_matches("./").trim_start_matches('/');
    let hit = entries
        .iter()
        .find(|e| e.path.eq_ignore_ascii_case(norm) || e.path.ends_with(&format!("/{norm}")))
        .ok_or_else(|| format!("entry `{entry_path}` not found in .asar"))?;
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
    let norm = entry_path.trim_start_matches("./").trim_start_matches('/');
    let mut matched_name = None;
    for i in 0..za.len() {
        if let Ok(f) = za.by_index(i) {
            let nm = f.name().replace('\\', "/");
            if nm.eq_ignore_ascii_case(norm) || nm.ends_with(&format!("/{norm}")) {
                matched_name = Some(f.name().to_string());
                break;
            }
        }
    }
    let Some(name) = matched_name else {
        return Err(format!("entry `{entry_path}` not found in archive"));
    };
    let f = za.by_name(&name).map_err(|e| format!("zip entry: {e}"))?;
    let mut buf = Vec::new();
    let _ = f.take(16 * 1024 * 1024).read_to_end(&mut buf);
    Ok(buf)
}

pub fn is_binary_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\x7FELF")
        || bytes.starts_with(b"\x00asm")
        || bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
        || bytes.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || bytes.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
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

fn file_offset_to_rva<'a>(off: usize, secs: &'a [PeSection]) -> Option<(u32, &'a str)> {
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
        read_u64_le(bytes, opt_off + 24).unwrap_or(0x14000_0000)
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
                                    let slot_rva = ft.saturating_add(slot_idx.saturating_mul(step as u32));
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
    PeContext {
        is_pe64,
        image_base,
        secs,
        iat_map,
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
                    let disp = i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
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
            if !iat_lookup.is_empty() && b0 == 0xFF && (b1 == 0x15 || b1 == 0x25) && i + 6 <= code.len() {
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

fn parse_elf_details(bytes: &[u8], out: &mut Vec<String>) {
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
                if p_type == 0x6474_e551 {
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

    if !is_64 || bytes.len() < 64 {
        out.push(format!(
            "- SHA-256: `{}` | Entropy: `{ent:.2}`",
            sha256_hex(bytes)
        ));
        return;
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
        return;
    }
    let strtab_hdr = shoff.saturating_add(shstrndx.saturating_mul(shentsize));
    let shstr_off = read_u64_le(bytes, strtab_hdr + 24).unwrap_or(0) as usize;
    let mut sec_names = Vec::new();
    let mut dynstr_slice: Option<(usize, usize)> = None;
    let mut dynsym_slice: Option<(usize, usize, usize)> = None;
    let mut dynamic_slice: Option<(usize, usize)> = None;

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
        if !sname.is_empty() {
            sec_names.push(sname.clone());
        }
        if sname == ".dynstr" {
            dynstr_slice = Some((s_off, s_sz));
        } else if sh_type == 11 || sname == ".dynsym" {
            dynsym_slice = Some((s_off, s_sz, entsz.max(24)));
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
            // DT_BIND_NOW (24) or DT_FLAGS(30) DF_BIND_NOW(0x8) or DT_FLAGS_1(0x6ffffffb) DF_1_NOW(0x1)
            if tag == 24 || (tag == 30 && (val & 0x8) != 0) || (tag == 0x6fff_fffb && (val & 0x1) != 0) {
                has_bind_now = true;
            }
        }
    }
    if has_relro {
        elf_mit.push(if has_bind_now { "Full-RELRO" } else { "Partial-RELRO" });
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
    if !sec_names.is_empty() {
        out.push(format!("### ELF Sections: `[{}]`", sec_names.join(", ")));
    }
    if let Some((dstr_off, _)) = dynstr_slice {
        if let Some((dyn_off, dyn_sz)) = dynamic_slice {
            let mut needed = Vec::new();
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
                }
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
            let count = (sym_sz / entsz).min(512);
            for k in 0..count {
                let p = sym_off + k * entsz;
                if p + 24 > bytes.len() {
                    break;
                }
                let st_name = read_u32_le(bytes, p).unwrap_or(0) as usize;
                let st_shndx = read_u16_le(bytes, p + 6).unwrap_or(0);
                if st_name > 0 && st_shndx != 0 {
                    if let Some(nm) = read_cstr(bytes, dstr_off.saturating_add(st_name), 128) {
                        syms.push(nm);
                        if syms.len() >= 60 {
                            break;
                        }
                    }
                }
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
}

/// Inspect PE / ELF / Mach-O / WASM headers, imports/exports, SHA-256, entropy + ASCII & Windows UTF-16LE wide strings.
pub fn inspect_binary_md(bytes: &[u8], query: Option<&str>, max_strings: usize) -> String {
    inspect_binary_with_xref_md(bytes, query, max_strings, false)
}

/// Inspect native binaries with optional pure-Rust PE64 x64 RIP-relative string & IAT import XREF resolution.
pub fn inspect_binary_with_xref_md(
    bytes: &[u8],
    query: Option<&str>,
    max_strings: usize,
    include_xref: bool,
) -> String {
    let mut out = Vec::new();
    let mut pe_ctx: Option<PeContext> = None;
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
        parse_elf_details(bytes, &mut out);
    } else if bytes.starts_with(b"\x00asm") {
        out.push(format!(
            "## Binary Header: WebAssembly ({} B) | SHA-256: `{}`",
            bytes.len(),
            sha256_hex(bytes)
        ));
    } else if bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
        || bytes.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
    {
        out.push(format!(
            "## Binary Header: macOS Mach-O ({} B) | SHA-256: `{}`",
            bytes.len(),
            sha256_hex(bytes)
        ));
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
    let mut hits: Vec<String> = Vec::new();
    let mut matched_str_rvas: Vec<(u32, String)> = Vec::new();
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
                    if let Some((rva, sec)) = pe_ctx.as_ref().and_then(|p| file_offset_to_rva(st, &p.secs)) {
                        hits.push(format!("[ascii @0x{st:x} rva=0x{rva:x} ({sec})] {s}"));
                        matched_str_rvas.push((rva, s.into_owned()));
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
                if let Some((rva, sec)) = pe_ctx.as_ref().and_then(|p| file_offset_to_rva(st, &p.secs)) {
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
                xref_block.push("*(no matching x64 RIP-relative LEA/CALL XREFs found in executable sections)*".to_string());
            } else {
                xref_block.extend(xrefs);
            }
            // Place XREFs right after PE Sections/RPC/Exports (before bulky full import dump) so hunters see code targets immediately!
            let insert_at = out
                .iter()
                .position(|l| l.starts_with("### PE Imports"))
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
            .position(|l| l.starts_with("### PE Imports"))
            .unwrap_or(out.len());
        out.splice(insert_at..insert_at, str_block);
    } else {
        out.extend(str_block);
    }
    out.join("\n")
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
        pe[opt + 24..opt + 32].copy_from_slice(&0x14000_0000u64.to_le_bytes());
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
        assert!(md.contains("rva=0x2080 (.rdata)"), "Expected RVA on string in:\n{md}");
        assert!(md.contains("[str-xref] insn=0x1014 in func_rva=0x1010"), "Expected str-xref in:\n{md}");
        assert!(md.contains("[iat-xref] call insn=0x101b in func_rva=0x1010"), "Expected iat-xref in:\n{md}");
        assert!(md.contains("KERNEL32.dll!CreateProcessW"), "Expected IAT symbol in:\n{md}");
    }
}
