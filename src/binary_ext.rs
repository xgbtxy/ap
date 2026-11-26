use crate::binary::{
    file_offset_to_rva, format_guid_le, parse_pe_details, read_cstr, read_u16_le, read_u32_le,
    read_u64_le, rva_to_file_offset, scan_pe64_xrefs, scan_pe_rpc_interfaces, shannon_entropy,
    PeContext, PeSection,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn va_to_rva(va: u64, pe: &PeContext) -> Option<u32> {
    if let Some(rel) = va.checked_sub(pe.image_base) {
        if rel > 0 && rel < 0x1000_0000 {
            return Some(rel as u32);
        }
    }
    if va > 0 && va < 0x0400_0000 && rva_to_file_offset(va as u32, &pe.secs).is_some() {
        return Some(va as u32);
    }
    None
}

fn is_exec_rva(rva: u32, secs: &[PeSection]) -> bool {
    secs.iter().any(|s| {
        s.chars & 0x2000_0000 != 0
            && rva >= s.vaddr
            && rva < s.vaddr.saturating_add(s.vsize.max(s.raw_size))
    })
}

fn read_ptr_at_off(bytes: &[u8], off: usize, is_pe64: bool) -> Option<u64> {
    if is_pe64 {
        read_u64_le(bytes, off)
    } else {
        read_u32_le(bytes, off).map(|v| v as u64)
    }
}

fn extract_ascii_runs(slice: &[u8], min_len: usize, max_items: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < slice.len() {
        if slice[i].is_ascii_graphic() || slice[i] == b' ' {
            let s0 = i;
            while i < slice.len()
                && (slice[i].is_ascii_graphic() || slice[i] == b' ')
                && i - s0 < 120
            {
                i += 1;
            }
            if i - s0 >= min_len {
                if let Ok(s) = std::str::from_utf8(&slice[s0..i]) {
                    let t = s.trim();
                    if t.chars().any(|c| c.is_ascii_alphabetic()) {
                        out.push(t.to_string());
                        if out.len() >= max_items {
                            break;
                        }
                    }
                }
            }
        }
        i += 1;
    }
    out
}

fn extract_msft_typelib_summary(blob: &[u8], base_off: usize) -> Value {
    let ver = read_u32_le(blob, 4).unwrap_or(0);
    let nrtypeinfos = read_u32_le(blob, 0x20).unwrap_or(0);
    let mut guids = Vec::new();
    let mut i = 0usize;
    // Scan TypeLib Name/String tables safely for printable TypeLib identifiers
    let names: Vec<String> = extract_ascii_runs(blob, 3, 64)
        .into_iter()
        .filter(|s| s != "MSFT" && !s.starts_with("SLTG"))
        .collect();
    while i + 16 <= blob.len() && guids.len() < 16 {
        // Heuristic non-trivial GUIDs (not all 0x00 or 0xFF)
        if i >= 0x40 {
            let chunk = &blob[i..i + 16];
            let zeros = chunk.iter().filter(|b| **b == 0).count();
            let ffs = chunk.iter().filter(|b| **b == 0xFF).count();
            if zeros <= 8 && ffs <= 4 && chunk[7] & 0xF0 == 0x40 {
                // Likely version-4 or DCE UUID bytes inside GUID table
                guids.push(format_guid_le(chunk));
                i += 16;
                continue;
            }
        }
        i += 4;
    }
    json!({
        "magic": if blob.starts_with(b"MSFT") { "MSFT" } else { "SLTG" },
        "file_offset": format!("0x{base_off:x}"),
        "size": blob.len(),
        "version": format!("0x{ver:08x}"),
        "typeinfo_hint": nrtypeinfos,
        "guids": guids,
        "identifiers": names,
    })
}

fn scan_rpc_dispatch_details(bytes: &[u8], pe: &PeContext) -> Vec<Value> {
    const NDR20: [u8; 16] = [
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60,
    ];
    const NDR64: [u8; 16] = [
        0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc,
        0x36,
    ];
    let expected_struct_len = if pe.is_pe64 { 0x60u32 } else { 0x44u32 };
    let mut out = Vec::new();
    let mut seen_if = BTreeSet::new();

    for pat in [NDR20, NDR64] {
        let mut pos = 0usize;
        while let Some(rel) = bytes[pos..].windows(16).position(|w| w == pat) {
            let ts_off = pos + rel;
            pos = ts_off + 4;
            if ts_off < 0x18 {
                continue;
            }
            let base = ts_off - 0x18;
            let len_field = read_u32_le(bytes, base).unwrap_or(0);
            if len_field != expected_struct_len {
                continue;
            }
            let Some(if_guid_bytes) = bytes.get(base + 4..base + 20) else {
                continue;
            };
            let if_uuid = format_guid_le(if_guid_bytes);
            if !seen_if.insert(if_uuid.clone()) {
                continue;
            }
            let maj = read_u16_le(bytes, base + 20).unwrap_or(0);
            let min = read_u16_le(bytes, base + 22).unwrap_or(0);
            let struct_rva = file_offset_to_rva(base, &pe.secs)
                .map(|(r, _)| r)
                .unwrap_or(0);

            let (disp_ptr_off, interp_ptr_off) = if pe.is_pe64 {
                (base + 0x30, base + 0x50)
            } else {
                (base + 0x2C, base + 0x3C)
            };

            let mut opnum_count = 0usize;
            if let Some(disp_va) = read_ptr_at_off(bytes, disp_ptr_off, pe.is_pe64) {
                if let Some(disp_rva) = va_to_rva(disp_va, pe) {
                    if let Some(disp_off) = rva_to_file_offset(disp_rva, &pe.secs) {
                        let cnt = read_u32_le(bytes, disp_off).unwrap_or(0) as usize;
                        if (1..=512).contains(&cnt) {
                            opnum_count = cnt;
                        }
                    }
                }
            }

            let mut opnums = Vec::new();
            let mut midl_info_rva = None;
            if let Some(interp_va) = read_ptr_at_off(bytes, interp_ptr_off, pe.is_pe64) {
                if let Some(interp_rva) = va_to_rva(interp_va, pe) {
                    midl_info_rva = Some(format!("0x{interp_rva:x}"));
                    if let Some(interp_off) = rva_to_file_offset(interp_rva, &pe.secs) {
                        let srv_disp_ptr_off = interp_off + if pe.is_pe64 { 8 } else { 4 };
                        if let Some(srv_disp_va) =
                            read_ptr_at_off(bytes, srv_disp_ptr_off, pe.is_pe64)
                        {
                            if let Some(srv_disp_rva) = va_to_rva(srv_disp_va, pe) {
                                if let Some(arr_off) = rva_to_file_offset(srv_disp_rva, &pe.secs) {
                                    let max_ops = if opnum_count > 0 { opnum_count } else { 64 };
                                    let stride = if pe.is_pe64 { 8 } else { 4 };
                                    for idx in 0..max_ops {
                                        let Some(fn_va) = read_ptr_at_off(
                                            bytes,
                                            arr_off + idx * stride,
                                            pe.is_pe64,
                                        ) else {
                                            break;
                                        };
                                        let Some(fn_rva) = va_to_rva(fn_va, pe) else {
                                            if opnum_count == 0 {
                                                break;
                                            }
                                            continue;
                                        };
                                        if !is_exec_rva(fn_rva, &pe.secs) {
                                            if opnum_count == 0 {
                                                break;
                                            }
                                            continue;
                                        }
                                        opnums.push(json!({
                                            "opnum": idx,
                                            "rva": format!("0x{fn_rva:x}"),
                                            "va": format!("0x{:x}", pe.image_base + fn_rva as u64),
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            out.push(json!({
                "uuid": if_uuid,
                "version": format!("{maj}.{min}"),
                "transfer_syntax": if pat == NDR64 { "NDR64" } else { "NDR20" },
                "interface_rva": format!("0x{struct_rva:x}"),
                "midl_server_info_rva": midl_info_rva,
                "declared_opnums": opnum_count,
                "opnums": opnums,
            }));
        }
    }
    out
}

fn scan_rdata_dispatch_vectors(bytes: &[u8], pe: &PeContext) -> Vec<Value> {
    let mut tables = Vec::new();
    for sec in &pe.secs {
        // Read-only / data sections, non-executable
        if sec.chars & 0x2000_0000 != 0 || sec.raw_size < 16 {
            continue;
        }
        let sec_start = sec.raw_ptr as usize;
        let sec_end = sec_start
            .saturating_add(sec.raw_size as usize)
            .min(bytes.len());
        if sec_end <= sec_start {
            continue;
        }

        // Scan pointer-sized VA dispatch vectors (vtables / RPC / IOCTL tables)
        let ptr_sz = if pe.is_pe64 { 8 } else { 4 };
        let mut off = sec_start;
        while off + ptr_sz * 4 <= sec_end {
            let mut targets = Vec::new();
            let mut k = off;
            while k + ptr_sz <= sec_end && targets.len() < 128 {
                let Some(va) = read_ptr_at_off(bytes, k, pe.is_pe64) else {
                    break;
                };
                if let Some(rva) = va_to_rva(va, pe) {
                    if is_exec_rva(rva, &pe.secs) {
                        targets.push(format!("0x{rva:x}"));
                        k += ptr_sz;
                        continue;
                    }
                }
                break;
            }
            if targets.len() >= 4 {
                if let Some((tbl_rva, _)) = file_offset_to_rva(off, &pe.secs) {
                    tables.push(json!({
                        "section": sec.name,
                        "kind": if pe.is_pe64 { "va64_table" } else { "va32_table" },
                        "table_rva": format!("0x{tbl_rva:x}"),
                        "count": targets.len(),
                        "sample_targets": targets.into_iter().take(12).collect::<Vec<_>>(),
                    }));
                }
                off = k;
            } else {
                off += ptr_sz;
            }
            if tables.len() >= 40 {
                return tables;
            }
        }

        // Scan dense 32-bit RVA jump tables (x64 MSVC switch tables / Dispatch arrays)
        let mut off32 = sec_start;
        while off32 + 16 <= sec_end {
            let mut targets = Vec::new();
            let mut k = off32;
            while k + 4 <= sec_end && targets.len() < 128 {
                let rva = read_u32_le(bytes, k).unwrap_or(0);
                if rva >= 0x1000 && is_exec_rva(rva, &pe.secs) {
                    targets.push(format!("0x{rva:x}"));
                    k += 4;
                } else {
                    break;
                }
            }
            if targets.len() >= 4 {
                if let Some((tbl_rva, _)) = file_offset_to_rva(off32, &pe.secs) {
                    tables.push(json!({
                        "section": sec.name,
                        "kind": "rva32_table",
                        "table_rva": format!("0x{tbl_rva:x}"),
                        "count": targets.len(),
                        "sample_targets": targets.into_iter().take(12).collect::<Vec<_>>(),
                    }));
                }
                off32 = k;
            } else {
                off32 += 4;
            }
            if tables.len() >= 60 {
                return tables;
            }
        }
    }
    tables
}

/// Inspect Windows PE MIDL RPC interfaces + opnum dispatch tables, embedded COM TypeLibs,
/// ALPC/COM imports/port names, and `.rdata` dispatch vectors.
pub fn inspect_pe_rpc_com_alpc(bytes: &[u8], label: &str, as_json: bool) -> Result<String, String> {
    if !bytes.starts_with(b"MZ") || bytes.len() <= 0x44 {
        return Err(format!("`{label}` is not a PE binary"));
    }
    let pe_off = read_u32_le(bytes, 0x3C).unwrap_or(0) as usize;
    if bytes.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return Err(format!("`{label}` has no valid PE signature"));
    }

    let mut pe_lines = Vec::new();
    let pe = parse_pe_details(bytes, pe_off, &mut pe_lines);

    let rpc_basic = scan_pe_rpc_interfaces(bytes, pe.is_pe64);
    let rpc_detailed = scan_rpc_dispatch_details(bytes, &pe);

    // Embedded COM TypeLibs (`MSFT` or `SLTG`) in resource / data sections
    let mut typelibs = Vec::new();
    for magic in [b"MSFT".as_slice(), b"SLTG".as_slice()] {
        let mut p = 0usize;
        while let Some(rel) = bytes[p..].windows(4).position(|w| w == magic) {
            let off = p + rel;
            p = off + 4;
            let max_end = (off + 64 * 1024).min(bytes.len());
            typelibs.push(extract_msft_typelib_summary(&bytes[off..max_end], off));
            if typelibs.len() >= 12 {
                break;
            }
        }
    }

    // COM & ALPC imports
    let interesting_imports: Vec<String> = pe
        .iat_map
        .iter()
        .filter_map(|(rva, name)| {
            let low = name.to_ascii_lowercase();
            if low.contains("alpc")
                || low.contains("rpc")
                || low.contains("coregister")
                || low.contains("cocreate")
                || low.contains("coinitialize")
                || low.contains("clsid")
                || low.contains("typelib")
            {
                Some(format!("{name} @ IAT_RVA=0x{rva:x}"))
            } else {
                None
            }
        })
        .collect();

    // ALPC ports, RPC endpoints, and CLSID/IID string literals + PE64 XREFs
    let mut anchor_rvas = Vec::new();
    let mut alpc_ports = BTreeSet::new();
    let mut clsid_strings = BTreeSet::new();
    let mut rpc_endpoints = BTreeSet::new();
    for sec in &pe.secs {
        let start = sec.raw_ptr as usize;
        let len = (sec.raw_size as usize).min(bytes.len().saturating_sub(start));
        let slice = &bytes[start..start + len];
        let mut i = 0usize;
        while i < slice.len() {
            if slice[i].is_ascii_graphic() {
                let s0 = i;
                while i < slice.len()
                    && (slice[i].is_ascii_graphic() || slice[i] == b' ')
                    && i - s0 < 128
                {
                    i += 1;
                }
                if i - s0 >= 6 {
                    let s = String::from_utf8_lossy(&slice[s0..i]).to_string();
                    let low = s.to_ascii_lowercase();
                    if low.contains("\\rpc control\\") || low.contains("alpc") {
                        alpc_ports.insert(s.clone());
                        if let Some((rva, _)) = file_offset_to_rva(start + s0, &pe.secs) {
                            anchor_rvas.push((rva, s.clone()));
                        }
                    } else if s.starts_with('{') && s.ends_with('}') && s.len() == 38 {
                        clsid_strings.insert(s.clone());
                        if let Some((rva, _)) = file_offset_to_rva(start + s0, &pe.secs) {
                            anchor_rvas.push((rva, s.clone()));
                        }
                    } else if low.starts_with("ncacn_")
                        || low.starts_with("ncalrpc")
                        || low.starts_with("\\pipe\\")
                    {
                        rpc_endpoints.insert(s.clone());
                        if let Some((rva, _)) = file_offset_to_rva(start + s0, &pe.secs) {
                            anchor_rvas.push((rva, s.clone()));
                        }
                    }
                }
            }
            i += 1;
        }
    }

    let xrefs = if pe.is_pe64 && !anchor_rvas.is_empty() {
        scan_pe64_xrefs(bytes, &pe, &anchor_rvas, None, 40)
    } else {
        Vec::new()
    };

    let dispatch_tables = scan_rdata_dispatch_vectors(bytes, &pe);

    if as_json {
        return Ok(serde_json::to_string_pretty(&json!({
            "file": label,
            "arch": if pe.is_pe64 { "pe64" } else { "pe32" },
            "image_base": format!("0x{:x}", pe.image_base),
            "rpc_interfaces": rpc_detailed,
            "rpc_raw_hits": rpc_basic,
            "rpc_endpoints": rpc_endpoints.into_iter().collect::<Vec<_>>(),
            "typelibs": typelibs,
            "com_alpc_imports": interesting_imports,
            "alpc_ports": alpc_ports.into_iter().collect::<Vec<_>>(),
            "clsids": clsid_strings.into_iter().collect::<Vec<_>>(),
            "dispatch_tables": dispatch_tables,
            "xrefs": xrefs,
        }))
        .unwrap_or_else(|_| "{}".to_string()));
    }

    let mut md = vec![
        format!("# PE RPC / COM / ALPC & Dispatch Surface: `{label}`"),
        String::new(),
        format!(
            "- Format: `{}` | ImageBase: `0x{:x}` | RPC Interfaces (MIDL): `{}` | TypeLibs: `{}` | `.rdata` Dispatch Tables: `{}`",
            if pe.is_pe64 { "PE64" } else { "PE32" },
            pe.image_base,
            rpc_detailed.len().max(rpc_basic.len()),
            typelibs.len(),
            dispatch_tables.len(),
        ),
        String::new(),
    ];

    if !rpc_detailed.is_empty() {
        md.push("## MIDL `RPC_SERVER_INTERFACE` & `DispatchTable` Opnums".to_string());
        for iface in &rpc_detailed {
            md.push(format!(
                "- `{}` v{} ({}, interface @ `{}`, MIDL_SERVER_INFO @ `{}`, declared_opnums=`{}`)",
                iface["uuid"].as_str().unwrap_or(""),
                iface["version"].as_str().unwrap_or(""),
                iface["transfer_syntax"].as_str().unwrap_or(""),
                iface["interface_rva"].as_str().unwrap_or(""),
                iface["midl_server_info_rva"].as_str().unwrap_or("-"),
                iface["declared_opnums"].as_u64().unwrap_or(0),
            ));
            if let Some(ops) = iface["opnums"].as_array() {
                for op in ops.iter().take(32) {
                    md.push(format!(
                        "  - opnum[{}]: RVA `{}` (VA `{}`)",
                        op["opnum"].as_u64().unwrap_or(0),
                        op["rva"].as_str().unwrap_or(""),
                        op["va"].as_str().unwrap_or(""),
                    ));
                }
            }
        }
        md.push(String::new());
    } else if !rpc_basic.is_empty() {
        md.push("## Raw RPC Syntax Hits".to_string());
        for line in &rpc_basic {
            md.push(format!("- {line}"));
        }
        md.push(String::new());
    }

    if !typelibs.is_empty() {
        md.push("## Embedded COM TypeLibs".to_string());
        for tl in &typelibs {
            let ids: Vec<&str> = tl["identifiers"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).take(16).collect())
                .unwrap_or_default();
            md.push(format!(
                "- `{}` @ `{}` (typeinfo_hint={}): identifiers=[{}]",
                tl["magic"].as_str().unwrap_or(""),
                tl["file_offset"].as_str().unwrap_or(""),
                tl["typeinfo_hint"].as_u64().unwrap_or(0),
                ids.join(", ")
            ));
        }
        md.push(String::new());
    }

    if !interesting_imports.is_empty()
        || !alpc_ports.is_empty()
        || !rpc_endpoints.is_empty()
        || !clsid_strings.is_empty()
    {
        md.push("## COM / ALPC Imports & Endpoints".to_string());
        for imp in &interesting_imports {
            md.push(format!("- Import: `{imp}`"));
        }
        for ep in &rpc_endpoints {
            md.push(format!("- Endpoint: `{ep}`"));
        }
        for port in &alpc_ports {
            md.push(format!("- ALPC Port: `{port}`"));
        }
        for clsid in clsid_strings.iter().take(20) {
            md.push(format!("- CLSID/IID: `{clsid}`"));
        }
        md.push(String::new());
    }

    if !dispatch_tables.is_empty() {
        md.push("## `.rdata` / Data Dispatch Tables".to_string());
        for tbl in dispatch_tables.iter().take(24) {
            let samples: Vec<&str> = tbl["sample_targets"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).take(6).collect())
                .unwrap_or_default();
            md.push(format!(
                "- `{}` `{}` @ `{}` (`{}` targets): [{}]",
                tbl["section"].as_str().unwrap_or(""),
                tbl["kind"].as_str().unwrap_or(""),
                tbl["table_rva"].as_str().unwrap_or(""),
                tbl["count"].as_u64().unwrap_or(0),
                samples.join(", "),
            ));
        }
        md.push(String::new());
    }

    if !xrefs.is_empty() {
        md.push("## PE64 Code XREFs to RPC/COM/ALPC Strings".to_string());
        for x in xrefs {
            md.push(format!("- {x}"));
        }
    }

    Ok(md.join("\n"))
}

fn read_u32_be(bytes: &[u8], off: usize) -> Option<u32> {
    let b = bytes.get(off..off + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Pure-Rust zero-C-dependency embedded firmware image scanner (`--fw-surface`):
/// detects filesystems/containers (`SquashFS`, `CPIO`, `uImage`, `DTB`, `TRX`, `TAR`, `ZIP`,
/// `GZIP`, `XZ`, `ZSTD`, `ELF`), computes sliding entropy windows, extracts service/CGI paths,
/// and clusters heuristic binary TLV chains.
pub fn inspect_firmware_surface(
    bytes: &[u8],
    label: &str,
    as_json: bool,
) -> Result<String, String> {
    if bytes.len() < 16 {
        return Err(format!(
            "`{label}` too small for firmware scan ({} bytes)",
            bytes.len()
        ));
    }

    let mut containers: Vec<Value> = Vec::new();

    // 1. Multi-offset container / filesystem magic scan
    let mut off = 0usize;
    while off + 8 <= bytes.len() && containers.len() < 64 {
        let b = &bytes[off..];
        // SquashFS LE ("hsqs") or BE ("sqsh")
        if (b.starts_with(b"hsqs") || b.starts_with(b"sqsh")) && b.len() >= 96 {
            let le = b.starts_with(b"hsqs");
            let get32 = |o: usize| -> u32 {
                if le {
                    read_u32_le(b, o).unwrap_or(0)
                } else {
                    read_u32_be(b, o).unwrap_or(0)
                }
            };
            let get16 = |o: usize| -> u16 {
                let s = &b[o..o + 2];
                if le {
                    u16::from_le_bytes([s[0], s[1]])
                } else {
                    u16::from_be_bytes([s[0], s[1]])
                }
            };
            let inodes = get32(4);
            let block_sz = get32(12);
            let comp_id = get16(20);
            let ver_maj = get16(28);
            if inodes > 0
                && block_sz.is_power_of_two()
                && (4096..=1_048_576).contains(&block_sz)
                && (1..=6).contains(&comp_id)
                && ver_maj == 4
            {
                let comp = match comp_id {
                    1 => "gzip",
                    2 => "lzma",
                    3 => "lzo",
                    4 => "xz",
                    5 => "lz4",
                    6 => "zstd",
                    _ => "unknown",
                };
                containers.push(json!({
                    "offset": format!("0x{off:x}"),
                    "offset_dec": off,
                    "kind": if le { "squashfs-le" } else { "squashfs-be" },
                    "detail": format!("inodes={inodes}, block_size={block_sz}, compression={comp}"),
                }));
                off += 96;
                continue;
            }
        }

        // U-Boot uImage (0x27051956)
        if b.starts_with(&[0x27, 0x05, 0x19, 0x56]) && b.len() >= 64 {
            let img_sz = read_u32_be(b, 12).unwrap_or(0);
            let comp = b[31];
            if img_sz > 0 && (img_sz as usize) <= b.len() && comp <= 5 {
                let name = read_cstr(b, 32, 32).unwrap_or_default();
                let comp_name = match comp {
                    0 => "none",
                    1 => "gzip",
                    2 => "bzip2",
                    3 => "lzma",
                    4 => "lzo",
                    5 => "lz4",
                    _ => "other",
                };
                containers.push(json!({
                    "offset": format!("0x{off:x}"),
                    "offset_dec": off,
                    "kind": "u-boot-uimage",
                    "detail": format!("name=\"{name}\", data_size={img_sz}, compression={comp_name}"),
                }));
                off += 64;
                continue;
            }
        }

        // Device Tree Blob (0xD00DFEED)
        if b.starts_with(&[0xD0, 0x0D, 0xFE, 0xED]) && b.len() >= 40 {
            let total_sz = read_u32_be(b, 4).unwrap_or(0);
            let ver = read_u32_be(b, 20).unwrap_or(0);
            if total_sz >= 40 && (total_sz as usize) <= b.len() && (1..=20).contains(&ver) {
                containers.push(json!({
                    "offset": format!("0x{off:x}"),
                    "offset_dec": off,
                    "kind": "fdt-dtb",
                    "detail": format!("total_size={total_sz}, version={ver}"),
                }));
                off += 40;
                continue;
            }
        }

        // TRX header ("HDR0")
        if b.starts_with(b"HDR0") && b.len() >= 28 {
            let len = read_u32_le(b, 4).unwrap_or(0);
            if len >= 28 && (len as usize) <= b.len() {
                containers.push(json!({
                    "offset": format!("0x{off:x}"),
                    "offset_dec": off,
                    "kind": "trx",
                    "detail": format!("length={len}"),
                }));
                off += 28;
                continue;
            }
        }

        // CPIO newc ("070701" or "070702")
        if (b.starts_with(b"070701") || b.starts_with(b"070702"))
            && b.len() >= 110
            && b[6..110].iter().all(|c| c.is_ascii_hexdigit())
        {
            let name = read_cstr(b, 110, 64).unwrap_or_default();
            if !name.is_empty() {
                containers.push(json!({
                    "offset": format!("0x{off:x}"),
                    "offset_dec": off,
                    "kind": "cpio-newc",
                    "detail": format!("first_entry=\"{name}\""),
                }));
                off += 110;
                continue;
            }
        }

        // GZIP (conservative check: CM=8, FLG <= 0x1F)
        if b.starts_with(&[0x1F, 0x8B, 0x08]) && b.len() >= 10 && b[3] <= 0x1F {
            containers.push(json!({
                "offset": format!("0x{off:x}"),
                "offset_dec": off,
                "kind": "gzip",
                "detail": format!("flags=0x{:02x}", b[3]),
            }));
            off += 10;
            continue;
        }

        // XZ ("\xFD7zXZ\0")
        if b.starts_with(b"\xFD7zXZ\x00") {
            containers.push(json!({
                "offset": format!("0x{off:x}"),
                "offset_dec": off,
                "kind": "xz",
                "detail": "XZ stream",
            }));
            off += 6;
            continue;
        }

        // ZSTD
        if b.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
            containers.push(json!({
                "offset": format!("0x{off:x}"),
                "offset_dec": off,
                "kind": "zstd",
                "detail": "Zstandard frame",
            }));
            off += 4;
            continue;
        }

        // ELF embedded binary
        if b.starts_with(b"\x7FELF")
            && b.len() >= 20
            && (b[4] == 1 || b[4] == 2)
            && (b[5] == 1 || b[5] == 2)
        {
            let e_type = if b[5] == 1 {
                u16::from_le_bytes([b[16], b[17]])
            } else {
                u16::from_be_bytes([b[16], b[17]])
            };
            if (1..=4).contains(&e_type) {
                containers.push(json!({
                    "offset": format!("0x{off:x}"),
                    "offset_dec": off,
                    "kind": if b[4] == 2 { "elf64" } else { "elf32" },
                    "detail": format!("e_type={e_type}, endian={}", if b[5] == 1 { "LE" } else { "BE" }),
                }));
                off += 20;
                continue;
            }
        }

        // USTAR tar ("ustar" at +257)
        if b.len() >= 263 && &b[257..262] == b"ustar" {
            let first = read_cstr(b, 0, 64).unwrap_or_default();
            containers.push(json!({
                "offset": format!("0x{off:x}"),
                "offset_dec": off,
                "kind": "tar-ustar",
                "detail": format!("first_entry=\"{first}\""),
            }));
            off += 512;
            continue;
        }

        // ZIP local file header ("PK\x03\x04")
        if b.starts_with(b"PK\x03\x04") && b.len() >= 30 {
            let nlen = u16::from_le_bytes([b[26], b[27]]) as usize;
            if nlen > 0 && nlen < 256 && 30 + nlen <= b.len() {
                let name = String::from_utf8_lossy(&b[30..30 + nlen]).to_string();
                containers.push(json!({
                    "offset": format!("0x{off:x}"),
                    "offset_dec": off,
                    "kind": "zip",
                    "detail": format!("first_entry=\"{name}\""),
                }));
                off += 30 + nlen;
                continue;
            }
        }

        off += 1;
    }

    // 2. Sliding Shannon entropy bands
    let win_sz = if bytes.len() >= 512 * 1024 {
        64 * 1024
    } else {
        (bytes.len() / 8).clamp(512, 64 * 1024)
    };
    let mut entropy_bands: Vec<Value> = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let end = (pos + win_sz).min(bytes.len());
        let h = shannon_entropy(&bytes[pos..end]);
        let class = if h < 1.5 {
            "padding/empty"
        } else if h >= 7.2 {
            "compressed/encrypted"
        } else {
            "code/data/plaintext"
        };
        if let Some(last) = entropy_bands.last_mut() {
            let lclass: &str = last["class"].as_str().unwrap_or("");
            if lclass == class {
                last["end"] = json!(format!("0x{end:x}"));
                last["size"] = json!(end - last["start_dec"].as_u64().unwrap_or(0) as usize);
                last["entropy"] = json!(format!("{h:.2}"));
                pos = end;
                continue;
            }
        }
        entropy_bands.push(json!({
            "start": format!("0x{pos:x}"),
            "start_dec": pos,
            "end": format!("0x{end:x}"),
            "size": end - pos,
            "entropy": format!("{h:.2}"),
            "class": class,
        }));
        pos = end;
    }

    // 3. Embedded web / CGI / service path & command hints
    let mut service_hints = BTreeSet::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_graphic() || bytes[i] == b' ' {
            let s0 = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_graphic() || bytes[i] == b' ')
                && i - s0 < 140
            {
                i += 1;
            }
            if i - s0 >= 6 {
                let s = String::from_utf8_lossy(&bytes[s0..i]);
                let low = s.to_ascii_lowercase();
                if low.contains("/cgi-bin/")
                    || low.contains("/bin/sh")
                    || low.contains("/bin/ash")
                    || low.contains("/etc/init.d")
                    || low.contains("/etc/passwd")
                    || low.contains("httpd")
                    || low.contains("uhttpd")
                    || low.contains("lighttpd")
                    || low.contains("dropbear")
                    || low.contains("telnetd")
                    || low.contains("busybox")
                    || low.contains("nvram")
                {
                    service_hints.insert(s.trim().to_string());
                    if service_hints.len() >= 48 {
                        break;
                    }
                }
            }
        }
        i += 1;
    }

    // 4. Heuristic binary TLV chain detection (Tag u16 LE/BE or u8 + Len u16 + Value, >= 4 records)
    let mut tlv_clusters = Vec::new();
    let mut t = 0usize;
    while t + 16 < bytes.len() && tlv_clusters.len() < 8 {
        // Check (tag: u16, len: u16) LE chaining >= 4 contiguous records
        let mut cur = t;
        let mut recs = Vec::new();
        while cur + 4 <= bytes.len() && recs.len() < 32 {
            let tag = u16::from_le_bytes([bytes[cur], bytes[cur + 1]]);
            let vlen = u16::from_le_bytes([bytes[cur + 2], bytes[cur + 3]]) as usize;
            if tag == 0 || tag == 0xFFFF || vlen == 0 || vlen > 256 || cur + 4 + vlen > bytes.len()
            {
                break;
            }
            // Value should have either printable chars or bounded non-padding bytes
            let val = &bytes[cur + 4..cur + 4 + vlen];
            let all_zero = val.iter().all(|b| *b == 0);
            if all_zero && vlen > 4 {
                break;
            }
            recs.push(format!("tag=0x{tag:04x}(len={vlen})"));
            cur += 4 + vlen;
        }
        if recs.len() >= 4 && cur - t >= 24 {
            tlv_clusters.push(json!({
                "offset": format!("0x{t:x}"),
                "format": "tlv-u16le-u16le",
                "record_count": recs.len(),
                "span_bytes": cur - t,
                "sample_records": recs.into_iter().take(6).collect::<Vec<_>>(),
            }));
            t = cur;
        } else {
            t += 1;
        }
    }

    if as_json {
        return Ok(serde_json::to_string_pretty(&json!({
            "file": label,
            "size_bytes": bytes.len(),
            "overall_entropy": format!("{:.2}", shannon_entropy(bytes)),
            "containers": containers,
            "entropy_bands": entropy_bands,
            "service_hints": service_hints.into_iter().collect::<Vec<_>>(),
            "tlv_clusters": tlv_clusters,
        }))
        .unwrap_or_else(|_| "{}".to_string()));
    }

    let mut md = vec![
        format!("# Firmware & Embedded Image Surface: `{label}`"),
        String::new(),
        format!(
            "- Size: `{}` bytes | Overall Entropy: `{:.2}` bits/byte | Embedded Containers: `{}` | Service/CGI Hints: `{}` | TLV Clusters: `{}`",
            bytes.len(),
            shannon_entropy(bytes),
            containers.len(),
            service_hints.len(),
            tlv_clusters.len(),
        ),
        String::new(),
    ];

    if !containers.is_empty() {
        md.push("## Embedded Filesystems, Containers & Kernels".to_string());
        for c in &containers {
            md.push(format!(
                "- `{}` (`{}` bytes from start) -> **{}**: {}",
                c["offset"].as_str().unwrap_or(""),
                c["offset_dec"].as_u64().unwrap_or(0),
                c["kind"].as_str().unwrap_or(""),
                c["detail"].as_str().unwrap_or(""),
            ));
        }
        md.push(String::new());
    }

    md.push("## Entropy Map".to_string());
    for e in entropy_bands.iter().take(24) {
        md.push(format!(
            "- `{}..{}` ({} B): entropy `{}` -> `{}`",
            e["start"].as_str().unwrap_or(""),
            e["end"].as_str().unwrap_or(""),
            e["size"].as_u64().unwrap_or(0),
            e["entropy"].as_str().unwrap_or(""),
            e["class"].as_str().unwrap_or(""),
        ));
    }
    md.push(String::new());

    if !service_hints.is_empty() {
        md.push("## Service, Web/CGI & Shell Surface Hints".to_string());
        for h in service_hints {
            md.push(format!("- `{h}`"));
        }
        md.push(String::new());
    }

    if !tlv_clusters.is_empty() {
        md.push("## Heuristic Binary TLV Clusters".to_string());
        for c in &tlv_clusters {
            let samples: Vec<&str> = c["sample_records"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            md.push(format!(
                "- `{}` ({}, {} records, {} B): [{}]",
                c["offset"].as_str().unwrap_or(""),
                c["format"].as_str().unwrap_or(""),
                c["record_count"].as_u64().unwrap_or(0),
                c["span_bytes"].as_u64().unwrap_or(0),
                samples.join(", "),
            ));
        }
    }

    Ok(md.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_surface_detects_uimage_squashfs_service_and_tlv() {
        let mut img = vec![0xAAu8; 4096];
        // Embedded uImage at 0x80
        img[0x80..0x84].copy_from_slice(&[0x27, 0x05, 0x19, 0x56]);
        img[0x80 + 12..0x80 + 16].copy_from_slice(&512u32.to_be_bytes());
        img[0x80 + 31] = 1; // gzip
        img[0x80 + 32..0x80 + 44].copy_from_slice(b"Linux-Kernel");

        // Embedded SquashFS LE at 0x400
        img[0x400..0x404].copy_from_slice(b"hsqs");
        img[0x400 + 4..0x400 + 8].copy_from_slice(&42u32.to_le_bytes()); // inodes
        img[0x400 + 12..0x400 + 16].copy_from_slice(&131072u32.to_le_bytes()); // block size
        img[0x400 + 20..0x400 + 22].copy_from_slice(&4u16.to_le_bytes()); // xz
        img[0x400 + 28..0x400 + 30].copy_from_slice(&4u16.to_le_bytes()); // version 4

        // Embedded CGI path at 0x800
        let cgi = b"/cgi-bin/config.cgi\0";
        img[0x800..0x800 + cgi.len()].copy_from_slice(cgi);

        // Embedded TLV records at 0x900
        let mut p = 0x900usize;
        for (tag, val) in [
            (0x1001u16, b"admin".as_slice()),
            (0x1002, b"8080"),
            (0x1003, b"enable"),
            (0x1004, b"eth0"),
        ] {
            img[p..p + 2].copy_from_slice(&tag.to_le_bytes());
            img[p + 2..p + 4].copy_from_slice(&(val.len() as u16).to_le_bytes());
            img[p + 4..p + 4 + val.len()].copy_from_slice(val);
            p += 4 + val.len();
        }

        let report = inspect_firmware_surface(&img, "fw.bin", false).unwrap();
        assert!(report.contains("u-boot-uimage"));
        assert!(report.contains("Linux-Kernel"));
        assert!(report.contains("squashfs-le"));
        assert!(report.contains("compression=xz"));
        assert!(report.contains("/cgi-bin/config.cgi"));
        assert!(report.contains("tlv-u16le-u16le"));
    }

    #[test]
    fn pe_rpc_com_alpc_extracts_midl_opnums_typelib_and_rdata_table() {
        // Synthetic minimal PE64 with .text (VA 0x1000..0x1200) and .rdata (VA 0x2000..0x2400)
        let image_base: u64 = 0x0001_4000_0000;
        let mut pe = vec![0u8; 0x1000];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
        pe[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
        pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // opt header size
        let opt = 0x98usize;
        pe[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
        pe[opt + 24..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let sec_tbl = opt + 0xF0;
        // .text @ raw 0x400, rva 0x1000, size 0x400
        pe[sec_tbl..sec_tbl + 5].copy_from_slice(b".text");
        pe[sec_tbl + 8..sec_tbl + 12].copy_from_slice(&0x400u32.to_le_bytes());
        pe[sec_tbl + 12..sec_tbl + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[sec_tbl + 16..sec_tbl + 20].copy_from_slice(&0x400u32.to_le_bytes());
        pe[sec_tbl + 20..sec_tbl + 24].copy_from_slice(&0x400u32.to_le_bytes());
        pe[sec_tbl + 36..sec_tbl + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        // .rdata @ raw 0x800, rva 0x2000, size 0x400
        let s2 = sec_tbl + 40;
        pe[s2..s2 + 6].copy_from_slice(b".rdata");
        pe[s2 + 8..s2 + 12].copy_from_slice(&0x400u32.to_le_bytes());
        pe[s2 + 12..s2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[s2 + 16..s2 + 20].copy_from_slice(&0x400u32.to_le_bytes());
        pe[s2 + 20..s2 + 24].copy_from_slice(&0x800u32.to_le_bytes());
        pe[s2 + 36..s2 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

        // Populate .text stubs
        pe[0x410] = 0xC3;
        pe[0x420] = 0xC3;
        pe[0x430] = 0xC3;
        pe[0x440] = 0xC3;

        // RPC_SERVER_INTERFACE @ file 0x800 (RVA 0x2000)
        pe[0x800..0x804].copy_from_slice(&0x60u32.to_le_bytes());
        pe[0x804..0x814].copy_from_slice(&[0x11; 16]); // Interface UUID
        pe[0x814..0x816].copy_from_slice(&1u16.to_le_bytes()); // maj=1
                                                               // NDR20 @ +0x18
        pe[0x818..0x828].copy_from_slice(&[
            0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
            0x48, 0x60,
        ]);
        // DispatchTable -> RVA 0x2080 (file 0x880)
        pe[0x830..0x838].copy_from_slice(&(image_base + 0x2080).to_le_bytes());
        // InterpreterInfo -> RVA 0x20A0 (file 0x8A0)
        pe[0x850..0x858].copy_from_slice(&(image_base + 0x20A0).to_le_bytes());

        // RPC_DISPATCH_TABLE @ 0x880: DispatchTableCount = 2
        pe[0x880..0x884].copy_from_slice(&2u32.to_le_bytes());
        // MIDL_SERVER_INFO @ 0x8A0: +8 points to SERVER_ROUTINE[] @ RVA 0x2100 (file 0x900)
        pe[0x8A8..0x8B0].copy_from_slice(&(image_base + 0x2100).to_le_bytes());

        // SERVER_ROUTINE[] + 4-entry vtable @ file 0x900
        pe[0x900..0x908].copy_from_slice(&(image_base + 0x1010).to_le_bytes());
        pe[0x908..0x910].copy_from_slice(&(image_base + 0x1020).to_le_bytes());
        pe[0x910..0x918].copy_from_slice(&(image_base + 0x1030).to_le_bytes());
        pe[0x918..0x920].copy_from_slice(&(image_base + 0x1040).to_le_bytes());

        // Embedded MSFT TypeLib @ file 0xA00
        pe[0xA00..0xA04].copy_from_slice(b"MSFT");
        pe[0xA04..0xA08].copy_from_slice(&0x00010002u32.to_le_bytes());
        pe[0xA20..0xA24].copy_from_slice(&3u32.to_le_bytes());
        pe[0xA50..0xA62].copy_from_slice(b"IServiceController");

        let out = inspect_pe_rpc_com_alpc(&pe, "rpc_srv.dll", false).unwrap();
        assert!(out.contains("declared_opnums=`2`"));
        assert!(out.contains("opnum[0]: RVA `0x1010`"));
        assert!(out.contains("opnum[1]: RVA `0x1020`"));
        assert!(out.contains("IServiceController"));
        assert!(out.contains("va64_table"));
    }
}
