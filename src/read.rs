use crate::stats::record_event_ex;
use clap::Parser;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use regex::Regex;
use serde_json::json;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use zip::ZipArchive;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "read",
    about = "Read any file (.docx, .xlsx, .pptx, .pdf, .csv, .json, GBK/UTF-16 text) or URL without context overflow or mojibake"
)]
struct ReadCli {
    /// File path or http(s):// URL to read
    target: String,
    /// Optional extra file paths to read in the same batch call (up to 12 files)
    extra_targets: Vec<String>,
    /// Optional Tree-sitter AST symbol name(s) to extract cleanly (comma-separated, e.g. `handle_rpc_request,Engine.commit`)
    #[arg(long)]
    symbol: Option<String>,
    /// Emit ONLY the compact Tree-sitter symbol outline (for code) or heading outline (for Markdown)
    #[arg(long)]
    outline: bool,
    /// Optional line range or comma-separated batch ranges (e.g. `1-120` or `10-40,120-160,300-340`)
    #[arg(long)]
    lines: Option<String>,
    /// Read only the first N lines (convenience alias for `--lines 1-N`)
    #[arg(long)]
    limit: Option<usize>,
    /// Read only the last N lines of a file (e.g. `ap read app.log --tail 50`)
    #[arg(long)]
    tail: Option<usize>,
    /// Optional max characters per output line (UTF-8 safe, like `cut -c1-N` without splitting CJK)
    #[arg(long, alias = "max-line-len", default_value_t = 0)]
    width: usize,
    /// Filter or search rows/paragraphs matching keyword or regex
    #[arg(short = 'q', long)]
    query: Option<String>,
    /// Optional worksheet name filter for .xlsx files
    #[arg(long)]
    sheet: Option<String>,
    /// Virtual archive entry path to read inside .asar/.zip/.vsix/.jar/.apk/.whl without extracting
    #[arg(long)]
    entry: Option<String>,
    /// Byte offset or comma-separated batch offsets for minified bundles (e.g. --offset 18000,95000 --chars 1200 --pretty)
    #[arg(long)]
    offset: Option<String>,
    /// Character/byte window size when slicing with --offset/--hex/--rva/--va (or output budget alias for --max-chars)
    #[arg(long)]
    chars: Option<usize>,
    /// Pretty-format minified JS/JSON snippets when slicing with --offset or --query
    #[arg(long)]
    pretty: bool,
    /// Zero-jq JSON/JSONL path query (e.g. `items[*].name`, `config.auth.url`, or `..token`)
    #[arg(long = "json-path", alias = "jq")]
    json_path: Option<String>,
    /// Resolve generated `line:col` inside a `.js.map` SourceMap v3 back to original file:line:col via VLQ
    #[arg(long = "map-pos")]
    map_pos: Option<String>,
    /// Auto-decode embedded JWT tokens, Base64 blobs, and URL-encoded strings
    #[arg(long)]
    decode: bool,
    /// Render URL in real Headless Edge/Chrome (extracts JS-hydrated text, tables & interactive controls)
    #[arg(long)]
    render: bool,
    /// Canonical hex + ASCII dump (`xxd`/`hexdump -C`) with SHA-256 & entropy (supports decimal or `0x` `--offset`)
    #[arg(long)]
    hex: bool,
    /// Extract printable ASCII & UTF-16LE strings (`ap strings` compatible: supports `-n`, `-a`, `-e s|l`, `-q`)
    #[arg(long)]
    strings: bool,
    /// Minimum printable string length for `--strings` / `ap strings` (default: 6 ASCII / 5 UTF-16LE)
    #[arg(short = 'n', long = "min-len", alias = "bytes", default_value_t = 0)]
    min_len: usize,
    /// Accepted for GNU `strings -a` compatibility (always scans full bounded buffer)
    #[arg(short = 'a', long = "all")]
    _all_sections: bool,
    /// String encoding filter for `--strings` / `ap strings` (`s`=ASCII, `l`=UTF-16LE, default=both)
    #[arg(short = 'e', long = "encoding", default_value = "")]
    str_encoding: String,
    /// Map a PE RVA (or ELF offset) to file offset, section, enclosing x64 function & hex/disasm preview
    #[arg(long)]
    rva: Option<String>,
    /// Map a PE/ELF virtual address (`VA`, e.g. `0x140001080`) to file offset, section & nearby XREFs
    #[arg(long)]
    va: Option<String>,
    /// Search binary for a hex/wildcard byte pattern (e.g. `"48 8D ?? ?? ?? ?? ?? E8"`), mapping hits to RVA/VA/func
    #[arg(long = "find-bytes")]
    find_bytes: Option<String>,
    /// Resolve PE64/ELF64 (x64 & AArch64) string & IAT import cross-references with enclosing function RVAs
    #[arg(long)]
    xref: bool,
    /// Pure-Rust binary surface inspector: format, mitigations, risk-bucketed imports & categorized ASCII/UTF-16LE artifacts
    #[arg(long)]
    surface: bool,
    /// Pure-Rust zero-OpenSSL X.509 PEM/DER certificate inspector (Subject, Issuer, Validity, SANs, SHA-256)
    #[arg(long)]
    cert: bool,
    /// Schema-less raw Protocol Buffers wire-format decoder (no `protoc` required)
    #[arg(long)]
    proto: bool,
    /// Extract JS/TS/HTML API routes, postMessage origin-check posture, DOM/eval sinks & external origins
    #[arg(long)]
    routes: bool,
    /// When used with `--routes`, keep ONLY state-mutating routes (POST/PUT/PATCH/DELETE, mutations, WS emits) with extracted body keys
    #[arg(long = "mutating-only")]
    mutating_only: bool,
    /// Compact Electron `.asar` security surface extractor (handles minified `!0`/`!1` flags, IPC channels, sinks & `.asar.unpacked`)
    #[arg(long = "asar-surface")]
    asar_surface: bool,
    /// Extract PE/driver Windows `CTL_CODE` IOCTL constants, dangerous IOCTL/memory IAT XREFs & exports
    #[arg(long)]
    ioctl: bool,
    /// Extract binary ASCII & UTF-16LE named-pipe (`\\.\pipe\*`) and Windows device/DOS device (`\Device\*`, `\DosDevices\*`) artifacts + XREFs
    #[arg(long)]
    pipes: bool,
    /// Spotlight synthesized `--race` and multi-step `--flow` probe candidates extracted from routes/HAR/archives
    #[arg(long)]
    candidates: bool,
    /// Decode JWT header/claims/UTC timestamps & defensive posture flags (accepts file path or inline `eyJ...` token)
    #[arg(long)]
    jwt: bool,
    /// Defensive hardcoded-secret & credential hygiene audit (PEM keys, cloud AKs, embedded URI creds, tokens; auto-redacted)
    #[arg(long)]
    secrets: bool,
    /// Patch-diff this binary/archive (PE/ELF/Go/.asar/.zip/.jar/.vsix) against an older file path
    #[arg(long)]
    diff: Option<String>,
    /// Build Tree-sitter cross-file Electron/JS/TS IPC bridge stitcher (`bridge -> channel -> handler -> sink + guard`)
    #[arg(long = "ipc-graph")]
    ipc_graph: bool,
    /// When used with `--diff`, perform AST/CFG-normalized semantic patch-diff ignoring chunk hashes & mangled names
    #[arg(long)]
    semantic: bool,
    /// Extract PE MIDL RPC `DispatchTable` opnums, embedded COM `TYPELIB`, ALPC ports, and `.rdata` dispatch vectors
    #[arg(long = "rpc-com-alpc")]
    rpc_com_alpc: bool,
    /// Scan raw firmware/embedded images for SquashFS/uImage/DTB/TRX/CPIO/ELF magic, entropy bands, CGI hints & TLV clusters
    #[arg(long = "fw-surface")]
    fw_surface: bool,
    /// Extract ONLY the matching Markdown `# Heading` section cleanly (substring match, auto-ends at next heading of same/higher level)
    #[arg(long, alias = "heading")]
    section: Option<String>,
    /// Context window for `--query` (bytes on each side for minified files, lines for normal files)
    #[arg(long, default_value_t = 0)]
    around: usize,
    /// Maximum `--query` match windows/blocks to return (default: 12 minified / 25 normal)
    #[arg(long, alias = "max", default_value_t = 0)]
    max_hits: usize,
    /// Maximum characters before smart outline + pagination kicks in
    #[arg(long, default_value_t = 8000)]
    max_chars: usize,
    /// Scrub leaked secrets and defang indirect prompt-injection signals before output
    #[arg(long)]
    scrub: bool,
    /// Emit structured JSON output
    #[arg(long)]
    json: bool,
}

struct XmlRegexes {
    xml_tag: Regex,
    html_invisible: Regex,
    docx_block: Regex,
    docx_style: Regex,
    docx_tr: Regex,
    docx_tc: Regex,
    docx_t: Regex,
    xlsx_si: Regex,
    xlsx_sheet: Regex,
    xlsx_row: Regex,
    xlsx_cell: Regex,
    xlsx_v: Regex,
    pptx_p: Regex,
    pptx_t: Regex,
    pdf_tj: Regex,
}

fn xre() -> &'static XmlRegexes {
    static R: OnceLock<XmlRegexes> = OnceLock::new();
    R.get_or_init(|| XmlRegexes {
        xml_tag: Regex::new(r"<[^>]+>").unwrap(),
        html_invisible: Regex::new(r"(?is)<(?:script|style|head)\b.*?</(?:script|style|head)>")
            .unwrap(),
        docx_block: Regex::new(r"(?s)<w:tbl\b.*?</w:tbl>|<w:p\b.*?</w:p>").unwrap(),
        docx_style: Regex::new(r#"<w:pStyle\s+w:val="([^"]+)""#).unwrap(),
        docx_tr: Regex::new(r"(?s)<w:tr\b.*?</w:tr>").unwrap(),
        docx_tc: Regex::new(r"(?s)<w:tc\b.*?</w:tc>").unwrap(),
        docx_t: Regex::new(r"(?s)<w:t(?:\s[^>]*)?>(.*?)</w:t>").unwrap(),
        xlsx_si: Regex::new(r"(?s)<si\b[^>]*>(.*?)</si>").unwrap(),
        xlsx_sheet: Regex::new(r#"<sheet\b[^>]*\bname="([^"]+)""#).unwrap(),
        xlsx_row: Regex::new(r"(?s)<row\b[^>]*>(.*?)</row>").unwrap(),
        xlsx_cell: Regex::new(r#"(?s)<c\b([^>]*)>(.*?)</c>"#).unwrap(),
        xlsx_v: Regex::new(r"(?s)<v>(.*?)</v>|<t(?:\s[^>]*)?>(.*?)</t>").unwrap(),
        pptx_p: Regex::new(r"(?s)<a:p\b[^>]*>(.*?)</a:p>").unwrap(),
        pptx_t: Regex::new(r"(?s)<a:t(?:\s[^>]*)?>(.*?)</a:t>").unwrap(),
        pdf_tj: Regex::new(r"\(([^()\\]*(?:\\.[^()\\]*)*)\)\s*Tj|\[(.*?)\]\s*TJ").unwrap(),
    })
}

fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#10;", "\n")
        .replace("&#13;", "")
        .replace("&amp;", "&")
}

pub fn decode_any_bytes(raw: &[u8]) -> (String, &'static str, u32) {
    if let Some(rest) = raw.strip_prefix(b"\xEF\xBB\xBF") {
        if let Ok(s) = std::str::from_utf8(rest) {
            return (s.to_string(), "utf-8-bom", 1);
        }
    }
    if let Some(rest) = raw.strip_prefix(b"\xFF\xFE") {
        let (cow, _, _) = encoding_rs::UTF_16LE.decode(rest);
        return (cow.into_owned(), "utf-16le", 1);
    }
    if let Some(rest) = raw.strip_prefix(b"\xFE\xFF") {
        let (cow, _, _) = encoding_rs::UTF_16BE.decode(rest);
        return (cow.into_owned(), "utf-16be", 1);
    }
    if let Ok(s) = std::str::from_utf8(raw) {
        return (s.to_string(), "utf-8", 0);
    }
    let (gbk_cow, gbk_err) = encoding_rs::GB18030.decode_without_bom_handling(raw);
    if !gbk_err {
        return (gbk_cow.into_owned(), "gb18030/gbk", 1);
    }
    let (win_cow, _) = encoding_rs::WINDOWS_1252.decode_without_bom_handling(raw);
    (win_cow.into_owned(), "windows-1252", 1)
}

const MAX_OFFICE_XML_BYTES: u64 = 16 * 1024 * 1024;
const MAX_XLSX_COL_INDEX: usize = 16_383; // Excel max column `XFD` (16,384 columns)

fn read_bounded_utf8<R: Read>(reader: R, max_bytes: u64) -> Result<String, std::io::Error> {
    let mut buf = Vec::new();
    reader.take(max_bytes).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn extract_docx_md(bytes: &[u8]) -> Result<String, String> {
    let mut zip =
        ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("docx zip error: {e}"))?;
    let doc_f = zip
        .by_name("word/document.xml")
        .map_err(|_| "word/document.xml missing in .docx".to_string())?;
    let xml = read_bounded_utf8(doc_f, MAX_OFFICE_XML_BYTES).map_err(|e| e.to_string())?;

    let re = xre();
    let mut out = Vec::new();
    for m in re.docx_block.find_iter(&xml) {
        let blk = m.as_str();
        if blk.starts_with("<w:tbl") {
            let mut rows: Vec<Vec<String>> = Vec::new();
            for tr in re.docx_tr.find_iter(blk) {
                let mut cells = Vec::new();
                for tc in re.docx_tc.find_iter(tr.as_str()) {
                    let txt: String = re
                        .docx_t
                        .captures_iter(tc.as_str())
                        .map(|c| unescape_xml(&c[1]))
                        .collect::<Vec<_>>()
                        .join("");
                    cells.push(
                        txt.replace('|', "\\|")
                            .replace('\n', " ")
                            .trim()
                            .to_string(),
                    );
                }
                if !cells.is_empty() {
                    rows.push(cells);
                }
            }
            if !rows.is_empty() {
                let width = rows.iter().map(|r| r.len()).max().unwrap_or(1);
                for (ri, r) in rows.iter().enumerate() {
                    let mut padded = r.clone();
                    padded.resize(width, String::new());
                    out.push(format!("| {} |", padded.join(" | ")));
                    if ri == 0 {
                        out.push(format!("| {} |", vec!["---"; width].join(" | ")));
                    }
                }
                out.push(String::new());
            }
        } else {
            let txt: String = re
                .docx_t
                .captures_iter(blk)
                .map(|c| unescape_xml(&c[1]))
                .collect::<Vec<_>>()
                .join("");
            let trimmed = txt.trim();
            if trimmed.is_empty() {
                continue;
            }
            let prefix = match re
                .docx_style
                .captures(blk)
                .map(|c| c[1].to_ascii_lowercase())
                .as_deref()
            {
                Some(s) if s.contains("heading1") || s == "1" || s == "title" => "# ",
                Some(s) if s.contains("heading2") || s == "2" => "## ",
                Some(s) if s.contains("heading3") || s == "3" => "### ",
                _ => "",
            };
            out.push(format!("{prefix}{trimmed}"));
        }
    }
    Ok(out.join("\n"))
}

fn col_ref_to_index(attrs: &str) -> Option<usize> {
    let r_pos = attrs.find("r=\"")?;
    let after = &attrs[r_pos + 3..];
    let end_q = after.find('"')?;
    let letters: String = after[..end_q]
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    if letters.is_empty() {
        return None;
    }
    let mut idx = 0usize;
    for ch in letters.bytes() {
        let digit = (ch.to_ascii_uppercase() - b'A') as usize + 1;
        idx = idx.checked_mul(26)?.checked_add(digit)?;
        if idx > MAX_XLSX_COL_INDEX + 1 {
            return None;
        }
    }
    Some(idx.saturating_sub(1))
}

pub type XlsxSheetRows = (String, Vec<Vec<String>>);

pub fn extract_xlsx_sheets_raw(bytes: &[u8]) -> Result<Vec<XlsxSheetRows>, String> {
    let mut zip =
        ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("xlsx zip error: {e}"))?;
    let re = xre();

    let mut shared: Vec<String> = Vec::new();
    if let Ok(sf) = zip.by_name("xl/sharedStrings.xml") {
        let sxml = read_bounded_utf8(sf, MAX_OFFICE_XML_BYTES).unwrap_or_default();
        for cap in re.xlsx_si.captures_iter(&sxml) {
            let plain = unescape_xml(&re.xml_tag.replace_all(&cap[1], ""));
            shared.push(plain.replace('\n', " ").trim().to_string());
        }
    }

    let mut sheet_names: Vec<String> = Vec::new();
    if let Ok(wf) = zip.by_name("xl/workbook.xml") {
        let wxml = read_bounded_utf8(wf, MAX_OFFICE_XML_BYTES).unwrap_or_default();
        for cap in re.xlsx_sheet.captures_iter(&wxml) {
            sheet_names.push(unescape_xml(&cap[1]));
        }
    }

    let mut out_sheets = Vec::new();
    let max_sheets = sheet_names.len().max(1);
    for idx in 0..max_sheets {
        let sname = sheet_names
            .get(idx)
            .cloned()
            .unwrap_or_else(|| format!("Sheet{}", idx + 1));
        let xml_path = format!("xl/worksheets/sheet{}.xml", idx + 1);
        let Ok(shf) = zip.by_name(&xml_path) else {
            continue;
        };
        let shxml = read_bounded_utf8(shf, MAX_OFFICE_XML_BYTES).unwrap_or_default();

        let mut rows: Vec<Vec<String>> = Vec::new();
        for rcap in re.xlsx_row.captures_iter(&shxml) {
            let mut row_cells: Vec<String> = Vec::new();
            let mut cur_col = 0usize;
            for ccap in re.xlsx_cell.captures_iter(&rcap[1]) {
                let attrs = &ccap[1];
                let inner = &ccap[2];
                let col_idx = col_ref_to_index(attrs).unwrap_or(cur_col);
                if col_idx > MAX_XLSX_COL_INDEX {
                    continue;
                }
                if row_cells.len() <= col_idx {
                    row_cells.resize(col_idx + 1, String::new());
                }
                let is_shared = attrs.contains("t=\"s\"");
                let raw_val = re
                    .xlsx_v
                    .captures(inner)
                    .and_then(|vc| vc.get(1).or_else(|| vc.get(2)))
                    .map(|m| unescape_xml(m.as_str()))
                    .unwrap_or_default();
                let resolved = if is_shared {
                    raw_val
                        .trim()
                        .parse::<usize>()
                        .ok()
                        .and_then(|si| shared.get(si).cloned())
                        .unwrap_or(raw_val)
                } else {
                    raw_val
                };
                row_cells[col_idx] = resolved.replace('\n', " ").trim().to_string();
                cur_col = col_idx + 1;
            }
            if row_cells.iter().any(|c| !c.is_empty()) {
                rows.push(row_cells);
            }
        }
        out_sheets.push((sname, rows));
    }
    Ok(out_sheets)
}

fn extract_xlsx_md(
    bytes: &[u8],
    sheet_filter: Option<&str>,
    query: Option<&str>,
) -> Result<String, String> {
    let raw_sheets = extract_xlsx_sheets_raw(bytes)?;
    let q_low = query.map(|q| q.to_ascii_lowercase());
    let sf_low = sheet_filter.map(|s| s.to_ascii_lowercase());
    let mut sections = Vec::new();

    for (sname, rows) in raw_sheets {
        if let Some(ref f) = sf_low {
            if !sname.to_ascii_lowercase().contains(f) {
                continue;
            }
        }
        let width = rows.iter().map(|r| r.len()).max().unwrap_or(0);
        let mut out_lines = vec![format!(
            "## Sheet: `{sname}` ({} non-empty rows x {width} cols)",
            rows.len()
        )];
        if rows.is_empty() || width == 0 {
            out_lines.push("*(empty sheet)*".to_string());
            sections.push(out_lines.join("\n"));
            continue;
        }

        let mut shown = 0usize;
        for (ri, r) in rows.iter().enumerate() {
            if ri > 0 {
                if let Some(ref ql) = q_low {
                    let hit = r.iter().any(|c| c.to_ascii_lowercase().contains(ql));
                    if !hit {
                        continue;
                    }
                }
            }
            let mut padded: Vec<String> = r.iter().map(|c| c.replace('|', "\\|")).collect();
            padded.resize(width, String::new());
            out_lines.push(format!("| {} |", padded.join(" | ")));
            if ri == 0 {
                out_lines.push(format!("| {} |", vec!["---"; width].join(" | ")));
            }
            shown += 1;
            if shown >= 40 {
                out_lines.push(format!(
                    "... ({} total rows in `{sname}` — pass `--query <term>`, `--sheet \"{sname}\"`, or run `ap query -f t=<file.xlsx> \"SELECT ...\"`)",
                    rows.len()
                ));
                break;
            }
        }
        sections.push(out_lines.join("\n"));
    }
    Ok(sections.join("\n\n"))
}

fn extract_pptx_or_zip(bytes: &[u8], ext: &str) -> Result<String, String> {
    let mut zip = ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("zip error: {e}"))?;
    let re = xre();
    if ext == "pptx" {
        let mut slides = Vec::new();
        for i in 1..=200 {
            let name = format!("ppt/slides/slide{i}.xml");
            let Ok(sf) = zip.by_name(&name) else {
                if i == 1 {
                    break;
                }
                continue;
            };
            let xml = read_bounded_utf8(sf, MAX_OFFICE_XML_BYTES).unwrap_or_default();
            let mut paras = Vec::new();
            for pm in re.pptx_p.captures_iter(&xml) {
                let txt: String = re
                    .pptx_t
                    .captures_iter(&pm[1])
                    .map(|c| unescape_xml(&c[1]))
                    .collect::<Vec<_>>()
                    .join("");
                if !txt.trim().is_empty() {
                    paras.push(format!("- {}", txt.trim()));
                }
            }
            slides.push(format!("## Slide {i}\n{}", paras.join("\n")));
        }
        return Ok(slides.join("\n\n"));
    }
    let mut listing = vec![format!("# ZIP Archive ({} entries)", zip.len())];
    for i in 0..zip.len().min(120) {
        if let Ok(f) = zip.by_index(i) {
            listing.push(format!("- `{}` ({} bytes)", f.name(), f.size()));
        }
    }
    Ok(listing.join("\n"))
}

fn extract_pdf_text(bytes: &[u8]) -> Result<String, String> {
    let re = xre();
    let mut chunks = Vec::new();
    let mut pos = 0usize;
    while let Some(rel_s) = bytes[pos..].windows(6).position(|w| w == b"stream") {
        let mut s_start = pos + rel_s + 6;
        if bytes.get(s_start) == Some(&b'\r') {
            s_start += 1;
        }
        if bytes.get(s_start) == Some(&b'\n') {
            s_start += 1;
        } else {
            pos = s_start;
            continue;
        }
        let Some(rel_e) = bytes[s_start..].windows(9).position(|w| w == b"endstream") else {
            break;
        };
        let stream_slice = &bytes[s_start..s_start + rel_e];
        pos = s_start + rel_e + 9;

        let mut decoded = Vec::new();
        if ZlibDecoder::new(stream_slice)
            .take(MAX_OFFICE_XML_BYTES)
            .read_to_end(&mut decoded)
            .is_err()
        {
            decoded.clear();
            if DeflateDecoder::new(stream_slice)
                .take(MAX_OFFICE_XML_BYTES)
                .read_to_end(&mut decoded)
                .is_err()
            {
                let cap = stream_slice.len().min(MAX_OFFICE_XML_BYTES as usize);
                decoded.extend_from_slice(&stream_slice[..cap]);
            }
        }
        let text = String::from_utf8_lossy(&decoded);
        if text.contains("Tj") || text.contains("TJ") {
            let mut line_buf = Vec::new();
            for cap in re.pdf_tj.captures_iter(&text) {
                if let Some(m1) = cap.get(1) {
                    line_buf.push(m1.as_str().replace("\\(", "(").replace("\\)", ")"));
                } else if let Some(m2) = cap.get(2) {
                    let mut in_p = false;
                    let mut cur = String::new();
                    for ch in m2.as_str().chars() {
                        if ch == '(' && !in_p {
                            in_p = true;
                        } else if ch == ')' && in_p {
                            in_p = false;
                        } else if in_p {
                            cur.push(ch);
                        }
                    }
                    if !cur.is_empty() {
                        line_buf.push(cur);
                    }
                }
            }
            if !line_buf.is_empty() {
                chunks.push(line_buf.join(" "));
            }
        }
    }
    if chunks.is_empty() {
        Ok(
            "[ap read] Scanned PDF contains no embedded text streams (likely image-only scan)."
                .to_string(),
        )
    } else {
        Ok(chunks.join("\n"))
    }
}

pub fn extract_office_or_pdf_plain(bytes: &[u8], ext: &str) -> Result<String, String> {
    match ext {
        "docx" => extract_docx_md(bytes),
        "xlsx" => extract_xlsx_md(bytes, None, None),
        "pptx" => extract_pptx_or_zip(bytes, "pptx"),
        "pdf" => extract_pdf_text(bytes),
        _ => Err("unsupported office/pdf ext".to_string()),
    }
}

fn find_browser_bin() -> Option<PathBuf> {
    for cand in [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ] {
        let p = Path::new(cand);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    None
}

fn render_url_via_headless_cdp(url: &str) -> Result<String, String> {
    let browser =
        find_browser_bin().ok_or_else(|| "No local Edge/Chrome found for --render".to_string())?;
    let mut sess = ap_probe::cdp::CdpSession::launch(&browser)?;
    let _ = sess.navigate(url)?;
    let extract_js = r#"(() => {
        const title = document.title || '(untitled)';
        const headings = Array.from(document.querySelectorAll('h1,h2,h3')).slice(0, 20)
            .map(h => `${'#'.repeat(Number(h.tagName[1]))} ${(h.innerText||'').trim()}`).filter(Boolean);
        const ctrls = Array.from(document.querySelectorAll('button, input, select, textarea, a[href]')).slice(0, 30)
            .map(el => {
                const tag = el.tagName.toLowerCase();
                const id = el.id ? `#${el.id}` : '';
                const label = (el.innerText || el.placeholder || el.value || el.getAttribute('aria-label') || '').trim().slice(0, 50);
                return `[${tag}${id}${label ? ' "' + label.replace(/\s+/g,' ') + '"' : ''}]`;
            });
        const tables = Array.from(document.querySelectorAll('table')).slice(0, 3).map((tbl, ti) => {
            const rows = Array.from(tbl.querySelectorAll('tr')).slice(0, 15).map(tr =>
                Array.from(tr.querySelectorAll('th,td')).map(c => (c.innerText||'').replace(/\s+/g,' ').trim())
            ).filter(r => r.length > 0);
            if (!rows.length) return '';
            const w = Math.max(...rows.map(r => r.length));
            return `### Table ${ti+1}\n` + rows.map((r, ri) => {
                while (r.length < w) r.push('');
                const ln = '| ' + r.join(' | ') + ' |';
                return ri === 0 ? ln + '\n| ' + Array(w).fill('---').join(' | ') + ' |' : ln;
            }).join('\n');
        }).filter(Boolean);
        const body = (document.body ? document.body.innerText : '').trim().slice(0, 6000);
        return [
            `Title: ${title}`,
            headings.length ? `## Headings\n${headings.join('\n')}` : '',
            ctrls.length ? `## Interactive Elements (${ctrls.length})\n${ctrls.join(' ')}` : '',
            tables.join('\n\n'),
            `## Visible Content\n${body}`
        ].filter(Boolean).join('\n\n');
    })()"#;
    sess.eval_js(extract_js)
}

fn parse_line_window(spec: &str, total: usize) -> Option<(usize, usize)> {
    let norm = spec.trim().replace(':', "-");
    let (a, b) = norm.split_once('-')?;
    let s = a.trim().parse::<usize>().ok()?.max(1);
    let b_num = b.trim().parse::<usize>().ok()?;
    if total == 0 {
        return Some((1, 0));
    }
    let e = b_num.max(s).min(total);
    Some((s, e))
}

fn extract_sqlite_md(p: &Path) -> Result<String, String> {
    use rusqlite::{Connection, OpenFlags};
    let conn = Connection::open_with_flags(
        p,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("open sqlite read-only: {e}"))?;
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|e| e.to_string())?;
    let tables: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .flatten()
        .collect();
    if tables.is_empty() {
        return Ok("*(empty SQLite database — 0 user tables)*".to_string());
    }
    let mut sections = Vec::new();
    for tbl in tables.iter().take(15) {
        let qt = tbl.replace('"', "\"\"");
        let cnt: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM \"{qt}\""), [], |r| r.get(0))
            .unwrap_or(0);
        let mut s = conn
            .prepare(&format!("SELECT * FROM \"{qt}\" LIMIT 5"))
            .map_err(|e| e.to_string())?;
        let cols: Vec<String> = s.column_names().map(String::from).collect();
        let mut out = vec![format!("## Table `{tbl}` ({cnt} rows)")];
        if !cols.is_empty() {
            out.push(format!("| {} |", cols.join(" | ")));
            out.push(format!("| {} |", vec!["---"; cols.len()].join(" | ")));
            if let Ok(mut rows) = s.query([]) {
                while let Ok(Some(r)) = rows.next() {
                    let cells: Vec<String> = (0..cols.len())
                        .map(|i| match r.get_ref(i) {
                            Ok(rusqlite::types::ValueRef::Null) | Err(_) => "NULL".to_string(),
                            Ok(rusqlite::types::ValueRef::Integer(v)) => v.to_string(),
                            Ok(rusqlite::types::ValueRef::Real(v)) => format!("{v}"),
                            Ok(rusqlite::types::ValueRef::Text(b)) => String::from_utf8_lossy(b)
                                .replace('|', "\\|")
                                .replace('\n', " "),
                            Ok(rusqlite::types::ValueRef::Blob(b)) => format!("<{}B>", b.len()),
                        })
                        .collect();
                    out.push(format!("| {} |", cells.join(" | ")));
                }
            }
        }
        sections.push(out.join("\n"));
    }
    sections.push(format!(
        "[Tip: run exact SQL joins via `ap query -f db=\"{}\" \"SELECT ...\"`]",
        p.display()
    ));
    Ok(sections.join("\n\n"))
}

fn read_tar_or_entry(
    tar_bytes: &[u8],
    entry: Option<&str>,
    query: Option<&str>,
    xref: bool,
    list_tag: &'static str,
    format_tag: &mut &str,
    win_heals: &mut u32,
) -> Result<String, (i32, String)> {
    if let Some(ent) = entry {
        let eb = crate::binary::read_tar_member(tar_bytes, ent)
            .map_err(|e| (1, format!("[ap read] {e}")))?;
        if crate::binary::is_java_class_magic(&eb) {
            *format_tag = "java-class";
            Ok(crate::binary::parse_java_class_md(&eb, query))
        } else if crate::binary::is_pyc_magic(&eb) {
            *format_tag = "pyc";
            Ok(crate::binary::parse_pyc_md(&eb, query))
        } else if crate::binary::is_binary_magic(&eb) {
            *format_tag = "tar-entry-bin";
            Ok(crate::binary::inspect_binary_with_xref_md(
                &eb, query, 80, xref,
            ))
        } else {
            *format_tag = "tar-entry";
            let (dec_s, _, healed) = decode_any_bytes(&eb);
            *win_heals += healed;
            Ok(dec_s)
        }
    } else {
        *format_tag = list_tag;
        Ok(crate::binary::list_tar_md(tar_bytes, query))
    }
}

fn try_extract_image_meta(raw: &[u8], ext: &str) -> Option<String> {
    let kb = (raw.len() as f64) / 1024.0;
    if raw.len() >= 24 && &raw[..8] == b"\x89PNG\r\n\x1a\n" {
        let w = u32::from_be_bytes([raw[16], raw[17], raw[18], raw[19]]);
        let h = u32::from_be_bytes([raw[20], raw[21], raw[22], raw[23]]);
        return Some(format!(
            "[IMAGE METADATA: PNG {w}x{h} px | {kb:.1} KB — binary pixels omitted]"
        ));
    }
    if raw.len() >= 10 && (&raw[..6] == b"GIF87a" || &raw[..6] == b"GIF89a") {
        let w = u16::from_le_bytes([raw[6], raw[7]]);
        let h = u16::from_le_bytes([raw[8], raw[9]]);
        return Some(format!(
            "[IMAGE METADATA: GIF {w}x{h} px | {kb:.1} KB — binary pixels omitted]"
        ));
    }
    if matches!(ext, "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "ico") {
        return Some(format!(
            "[IMAGE METADATA: {} | {kb:.1} KB — binary pixels omitted]",
            ext.to_ascii_uppercase()
        ));
    }
    None
}

fn fetch_url_bytes(url: &str) -> Result<Vec<u8>, String> {
    let curl_bin = if cfg!(windows) { "curl.exe" } else { "curl" };
    let out = Command::new(curl_bin)
        .args([
            "-fsSL",
            "-L",
            "--noproxy",
            "127.0.0.1,localhost,::1",
            "--max-time",
            "20",
            "-A",
            "Mozilla/5.0 ap-reader",
            url,
        ])
        .output()
        .map_err(|e| format!("failed to invoke {curl_bin}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{curl_bin} failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

fn scrub_rendered_and_json(rendered: &mut String, jv: &mut serde_json::Value) {
    let rep = ap_guard::sanitize::scrub_untrusted_text(rendered);
    let total_flagged = rep.secrets_redacted + rep.injections_flagged;
    let scrubbed = if total_flagged > 0 {
        format!(
            "[ap guard scrub] redacted {} secret(s), defanged {} prompt-injection signal(s)\n{}",
            rep.secrets_redacted, rep.injections_flagged, rep.sanitized
        )
    } else {
        rep.sanitized
    };
    *rendered = scrubbed.clone();
    if let Some(obj) = jv.as_object_mut() {
        obj.insert("content".to_string(), json!(scrubbed));
        obj.insert(
            "scrub".to_string(),
            json!({
                "secrets_redacted": rep.secrets_redacted,
                "injections_flagged": rep.injections_flagged,
            }),
        );
    }
}

fn parse_byte_offset(tok: &str) -> Result<usize, ()> {
    let t = tok.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        t.parse::<usize>().map_err(|_| ())
    }
}

fn split_virtual_archive_target(target: &str) -> Option<(String, String)> {
    const ARCHIVE_EXTS: &[&str] = &[".asar", ".zip", ".vsix", ".jar", ".whl", ".apk"];
    let low = target.to_ascii_lowercase();
    for ext in ARCHIVE_EXTS {
        let mut search_from = 0usize;
        while let Some(pos) = low[search_from..].find(ext) {
            let end_ext = search_from + pos + ext.len();
            let rest = &target[end_ext..];
            let member = rest
                .strip_prefix("!/")
                .or_else(|| rest.strip_prefix("!\\"))
                .or_else(|| rest.strip_prefix('!'))
                .or_else(|| rest.strip_prefix("::"));
            if let Some(m) = member {
                let archive_path = &target[..end_ext];
                let clean = m.replace('\\', "/");
                let clean = clean.trim_start_matches('/');
                if !clean.is_empty() && Path::new(archive_path).is_file() {
                    return Some((archive_path.to_string(), clean.to_string()));
                }
            }
            search_from = end_ext;
        }
    }
    None
}

pub fn run_cli(args: &[String]) -> i32 {
    let mut cli = match ReadCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    if cli.lines.is_none() && cli.tail.is_none() {
        if let Some(n) = cli.limit.filter(|&n| n > 0) {
            cli.lines = Some(format!("1-{n}"));
        }
    }
    if cli.offset.is_none() && cli.rva.is_none() && cli.va.is_none() && !cli.hex {
        if let Some(c) = cli.chars {
            cli.max_chars = c.max(200);
        }
    }

    if !cli.extra_targets.is_empty() {
        let mut all_targets = vec![crate::ls::normalize_cli_path(&cli.target)];
        for t in cli.extra_targets.iter().take(11) {
            all_targets.push(crate::ls::normalize_cli_path(t));
        }
        let per_budget = (cli.max_chars / all_targets.len().max(1)).max(1600);
        let mut sub_cli = cli;
        sub_cli.max_chars = per_budget;
        sub_cli.extra_targets.clear();

        let mut rendered_blocks = Vec::new();
        let mut json_files = Vec::new();
        let mut had_err = false;
        for t in &all_targets {
            match read_single_target(&sub_cli, t.trim()) {
                Ok((mut md, mut jv)) => {
                    if sub_cli.scrub {
                        scrub_rendered_and_json(&mut md, &mut jv);
                    }
                    rendered_blocks.push(md);
                    json_files.push(jv);
                }
                Err((_, msg)) => {
                    had_err = true;
                    rendered_blocks.push(format!("# READ `{t}` [ERROR]\n{msg}"));
                    json_files.push(json!({ "ok": false, "target": t, "error": msg }));
                }
            }
        }
        if sub_cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": !had_err,
                    "count": json_files.len(),
                    "files": json_files,
                }))
                .unwrap_or_default()
            );
        } else {
            println!("{}", rendered_blocks.join("\n\n"));
        }
        return if had_err { 1 } else { 0 };
    }

    let t0 = std::time::Instant::now();
    let norm_target = crate::ls::normalize_cli_path(&cli.target);
    match read_single_target(&cli, norm_target.trim()) {
        Ok((mut rendered, mut jv)) => {
            if cli.scrub {
                scrub_rendered_and_json(&mut rendered, &mut jv);
            }
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&jv).unwrap_or_default());
            } else {
                println!("{rendered}");
            }
            0
        }
        Err((code, msg)) => {
            record_event_ex(
                "read",
                0,
                0,
                0,
                0,
                "read-err",
                false,
                t0.elapsed().as_millis() as u64,
                Some(&msg),
            );
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "target": norm_target,
                        "error": msg,
                    }))
                    .unwrap_or_default()
                );
            } else if !msg.is_empty() {
                eprintln!("{msg}");
            }
            code
        }
    }
}

#[derive(Clone)]
struct CppSymSpan {
    kind: String,
    qual: String,
    start_line: usize,
    end_line: usize,
}

fn find_balanced_brace_end(lines: &[&str], decl_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut opened = false;
    let mut in_block_comment = false;
    for (rel_idx, raw_ln) in lines[decl_idx..].iter().enumerate() {
        let abs_idx = decl_idx + rel_idx;
        if !opened && rel_idx > 4 {
            return None;
        }
        let b = raw_ln.as_bytes();
        let mut i = 0usize;
        let mut in_dq = false;
        let mut in_sq = false;
        while i < b.len() {
            if in_block_comment {
                if i + 1 < b.len() && b[i] == b'*' && b[i + 1] == b'/' {
                    in_block_comment = false;
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            if in_dq {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == b'"' {
                    in_dq = false;
                }
                i += 1;
                continue;
            }
            if in_sq {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == b'\'' {
                    in_sq = false;
                }
                i += 1;
                continue;
            }
            if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'/' {
                break;
            }
            if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
                in_block_comment = true;
                i += 2;
                continue;
            }
            match b[i] {
                b'"' => in_dq = true,
                b'\'' => in_sq = true,
                b';' if !opened => return None,
                b'{' => {
                    opened = true;
                    depth += 1;
                }
                b'}' if opened => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(abs_idx + 1);
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    None
}

fn scan_cpp_symbols(source: &str) -> Vec<CppSymSpan> {
    static CPP_RE: OnceLock<(Regex, Regex)> = OnceLock::new();
    let (type_re, fn_re) = CPP_RE.get_or_init(|| {
        let t = Regex::new(
            r"^\s*(?:template\s*<[^>]+>\s*)?(class|struct|enum(?:\s+class)?|namespace)\s+([A-Za-z_]\w*)",
        )
        .unwrap();
        let f = Regex::new(
            r"^(?:[\w:\*&\s<>~]+?)\b([A-Za-z_~]\w*(?:::[A-Za-z_~]\w*)?)\s*\(",
        )
        .unwrap();
        (t, f)
    });
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    for idx in 0..lines.len() {
        let raw_ln = lines[idx];
        let trimmed = raw_ln.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        if let Some(cap) = type_re.captures(raw_ln) {
            if let Some(end_ln) = find_balanced_brace_end(&lines, idx) {
                out.push(CppSymSpan {
                    kind: cap[1].to_string(),
                    qual: cap[2].to_string(),
                    start_line: idx + 1,
                    end_line: end_ln,
                });
            } else if raw_ln.contains('{') {
                out.push(CppSymSpan {
                    kind: cap[1].to_string(),
                    qual: cap[2].to_string(),
                    start_line: idx + 1,
                    end_line: idx + 1,
                });
            }
            continue;
        }
        if let Some(cap) = fn_re.captures(trimmed) {
            let sym = &cap[1];
            if matches!(
                sym,
                "if" | "for" | "while" | "switch" | "catch" | "return" | "sizeof"
            ) {
                continue;
            }
            // Match single-line or up-to-4-line C++ signature ending with `{` (excluding `;` calls/declarations)
            let mut look = String::new();
            let mut has_open_brace = false;
            let mut terminated_semi = false;
            for k in 0..=4 {
                if idx + k >= lines.len() {
                    break;
                }
                let l = lines[idx + k].trim();
                look.push_str(l);
                look.push(' ');
                if l.ends_with(';') && !l.contains('{') {
                    terminated_semi = true;
                    break;
                }
                if l.contains('{') {
                    has_open_brace = true;
                    break;
                }
            }
            if !terminated_semi && has_open_brace && look.contains(')') {
                if let Some(end_ln) = find_balanced_brace_end(&lines, idx) {
                    out.push(CppSymSpan {
                        kind: "fn".to_string(),
                        qual: sym.to_string(),
                        start_line: idx + 1,
                        end_line: end_ln,
                    });
                }
            }
        }
    }
    out
}

fn scan_cpp_outline_lines(source: &str) -> Vec<String> {
    scan_cpp_symbols(source)
        .into_iter()
        .map(|s| format!("L{}-L{}: {} {}", s.start_line, s.end_line, s.kind, s.qual))
        .collect()
}

fn find_cpp_symbol_span(source: &str, symbol: &str) -> Option<CppSymSpan> {
    let want = symbol.trim();
    let syms = scan_cpp_symbols(source);
    syms.iter()
        .find(|s| s.qual == want)
        .or_else(|| {
            syms.iter()
                .find(|s| s.qual.rsplit("::").next() == Some(want))
        })
        .cloned()
        .map(|s| CppSymSpan {
            kind: s.kind,
            qual: s.qual,
            start_line: s.start_line,
            end_line: s.end_line,
        })
}

fn extract_md_section(
    all_lines: &[&str],
    query: &str,
) -> Result<(usize, usize, String), Vec<String>> {
    let q_low = query.trim().to_ascii_lowercase();
    let mut headings: Vec<(usize, usize, String)> = Vec::new();
    let mut in_fence = false;
    for (idx, ln) in all_lines.iter().enumerate() {
        let trimmed = ln.trim_start();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let hashes = trimmed.bytes().take_while(|&b| b == b'#').count();
        if (1..=6).contains(&hashes) && trimmed.as_bytes().get(hashes) == Some(&b' ') {
            let title = trimmed[hashes..].trim().to_string();
            headings.push((idx, hashes, title));
        }
    }
    let hit = headings
        .iter()
        .position(|(_, _, t)| t.to_ascii_lowercase().contains(&q_low));
    let Some(h_pos) = hit else {
        return Err(headings
            .into_iter()
            .take(30)
            .map(|(i, lvl, t)| format!("L{}: {} {t}", i + 1, "#".repeat(lvl)))
            .collect());
    };
    let (start_0, start_lvl, _) = &headings[h_pos];
    let end_0 = headings[h_pos + 1..]
        .iter()
        .find(|(_, lvl, _)| *lvl <= *start_lvl)
        .map(|(i, _, _)| *i)
        .unwrap_or(all_lines.len());
    let slice = (*start_0..end_0)
        .map(|k| format!("{:5}: {}", k + 1, all_lines[k]))
        .collect::<Vec<_>>()
        .join("\n");
    Ok((*start_0 + 1, end_0.max(*start_0 + 1), slice))
}

fn read_single_target(
    cli: &ReadCli,
    target: &str,
) -> Result<(String, serde_json::Value), (i32, String)> {
    let t0 = std::time::Instant::now();
    let record_event = |kind: &str, raw: u64, out: u64, wh: u32, g: u32, tag: &str| {
        record_event_ex(
            kind,
            raw,
            out,
            wh,
            g,
            tag,
            true,
            t0.elapsed().as_millis() as u64,
            None,
        );
    };
    let is_url = target.starts_with("http://") || target.starts_with("https://");

    let (raw_bytes, ext, label) = if is_url {
        if cli.render {
            match render_url_via_headless_cdp(target) {
                Ok(snap) => (
                    snap.into_bytes(),
                    "rendered-dom".to_string(),
                    target.to_string(),
                ),
                Err(e) => return Err((1, format!("[ap read --render] {e}"))),
            }
        } else {
            match fetch_url_bytes(target) {
                Ok(b) => {
                    let preview = String::from_utf8_lossy(&b);
                    let body_only = xre().html_invisible.replace_all(&preview, "");
                    let looks_empty_spa = (preview.contains("id=\"root\"")
                        || preview.contains("id=\"app\"")
                        || preview.contains("id=\"__next\""))
                        && xre().xml_tag.replace_all(&body_only, "").trim().len() < 180;
                    if looks_empty_spa {
                        if let Ok(snap) = render_url_via_headless_cdp(target) {
                            (
                                snap.into_bytes(),
                                "rendered-dom".to_string(),
                                target.to_string(),
                            )
                        } else {
                            (b, "html".to_string(), target.to_string())
                        }
                    } else {
                        (b, "html".to_string(), target.to_string())
                    }
                }
                Err(e) => return Err((1, format!("[ap read] {e}"))),
            }
        }
    } else {
        let p = Path::new(target);
        if !p.exists() {
            if cli.entry.is_none() {
                if let Some((archive_path, member)) = split_virtual_archive_target(target) {
                    let mut sub = cli.clone();
                    sub.entry = Some(member);
                    return read_single_target(&sub, &archive_path);
                }
            }
            if cli.jwt && (target.contains("eyJ") && target.contains('.')) {
                let (rendered, jv_inner) = crate::inspect::inspect_jwt_md(target)
                    .map_err(|e| (1, format!("[ap read --jwt] {e}")))?;
                record_event(
                    "read",
                    target.len() as u64,
                    rendered.len() as u64,
                    0,
                    1,
                    "jwt",
                );
                let jv = json!({
                    "ok": true,
                    "target": "<inline-jwt>",
                    "format": "jwt",
                    "jwt": jv_inner,
                    "content": rendered,
                });
                return Ok((rendered, jv));
            }
            return Err((1, format!("[ap read] path not found: {target}")));
        }
        if p.is_dir() {
            if cli.routes {
                let old_path = cli.diff.as_deref().map(|s| {
                    let norm_old = crate::ls::normalize_cli_path(s);
                    std::path::PathBuf::from(norm_old)
                });
                let (mut rendered, jv_inner) = crate::inspect::extract_js_dir_routes_md_opts(
                    p,
                    cli.query.as_deref(),
                    old_path.as_deref(),
                    cli.mutating_only,
                )?;
                if cli.candidates {
                    rendered = crate::inspect::render_candidates_focus_md(&jv_inner, target);
                }
                record_event(
                    "read",
                    rendered.len() as u64,
                    rendered.len() as u64,
                    0,
                    1,
                    "js-dir-routes",
                );
                let jv = json!({
                    "ok": true,
                    "target": target,
                    "format": "js-dir-routes",
                    "surface": jv_inner,
                    "content": rendered,
                });
                return Ok((rendered, jv));
            }
            if cli.semantic {
                if let Some(ref old_path_str) = cli.diff {
                    let norm_old = crate::ls::normalize_cli_path(old_path_str);
                    let (md, mut jv) =
                        crate::semantic_diff::diff_semantic_paths_both(Path::new(&norm_old), p)
                            .map_err(|e| (1, format!("[ap read --semantic] {e}")))?;
                    if let Some(m) = jv.as_object_mut() {
                        m.insert("ok".into(), json!(true));
                        m.insert("format".into(), json!("dir-js-semantic-diff"));
                        if !cli.json {
                            m.insert("content".into(), json!(md));
                        }
                    }
                    return Ok((md, jv));
                }
            }
            if cli.ipc_graph {
                let (rendered, mut jv) =
                    crate::ipc_graph::inspect_ipc_graph_path(p, target, cli.query.as_deref())
                        .map_err(|e| (1, format!("[ap read --ipc-graph] {e}")))?;
                if let Some(m) = jv.as_object_mut() {
                    m.insert("ok".into(), json!(true));
                    m.insert("format".into(), json!("ipc-graph"));
                    if !cli.json {
                        m.insert("content".into(), json!(rendered));
                    }
                }
                return Ok((rendered, jv));
            }
            let data = ap_atlas::scan_workspace(p, "", 35, 14);
            let md = ap_atlas::render_atlas_md(&data);
            return Ok((
                md.clone(),
                json!({
                    "ok": true,
                    "target": target,
                    "format": "directory-atlas",
                    "content": md,
                }),
            ));
        }
        let ext_s = p
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let lbl = p.to_string_lossy().replace('\\', "/");
        if !cli.hex && !cli.routes && cli.entry.is_none() && ext_s == "asar" {
            if let Some(ref old_path_str) = cli.diff {
                let norm_old = crate::ls::normalize_cli_path(old_path_str);
                let old_p = Path::new(&norm_old);
                if old_p.is_file()
                    && old_p
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case("asar"))
                {
                    if cli.semantic {
                        let (rendered, mut jv) =
                            crate::semantic_diff::diff_semantic_paths_both(old_p, p)
                                .map_err(|e| (1, format!("[ap read --semantic] {e}")))?;
                        if let Some(m) = jv.as_object_mut() {
                            m.insert("ok".into(), json!(true));
                            m.insert("format".into(), json!("asar-semantic-diff"));
                            if !cli.json {
                                m.insert("content".into(), json!(rendered));
                            }
                        }
                        return Ok((rendered, jv));
                    }
                    let (rendered, mut diff_jv) = crate::binary::diff_asar_files_streaming(
                        p, old_p, &lbl, &norm_old, true, 25,
                    )
                    .map_err(|e| (1, format!("[ap read --diff] {e}")))?;
                    record_event(
                        "read",
                        p.metadata().map(|m| m.len()).unwrap_or(0)
                            + old_p.metadata().map(|m| m.len()).unwrap_or(0),
                        rendered.len() as u64,
                        0,
                        1,
                        "asar-diff",
                    );
                    if let Some(obj) = diff_jv.as_object_mut() {
                        obj.insert("format".to_string(), json!("binary-diff"));
                        obj.insert("target".to_string(), json!(lbl));
                        if !cli.json {
                            obj.insert("content".to_string(), json!(rendered));
                        }
                    }
                    return Ok((rendered, diff_jv));
                }
            }
        }
        if !cli.hex
            && cli.diff.is_none()
            && cli.entry.is_none()
            && cli.ipc_graph
            && (ext_s == "asar" || crate::semantic_diff::is_js_or_ts_path(&lbl))
        {
            let (rendered, mut jv) =
                crate::ipc_graph::inspect_ipc_graph_path(p, &lbl, cli.query.as_deref())
                    .map_err(|e| (1, format!("[ap read --ipc-graph] {e}")))?;
            record_event(
                "read",
                rendered.len() as u64,
                rendered.len() as u64,
                0,
                1,
                "ipc-graph",
            );
            if let Some(m) = jv.as_object_mut() {
                m.insert("ok".into(), json!(true));
                m.insert("target".into(), json!(target));
                m.insert("format".into(), json!("ipc-graph"));
                if !cli.json {
                    m.insert("content".into(), json!(rendered));
                }
            }
            return Ok((rendered, jv));
        }
        if !cli.hex
            && cli.diff.is_none()
            && cli.entry.is_none()
            && (cli.asar_surface || cli.surface || cli.routes)
            && matches!(
                ext_s.as_str(),
                "asar" | "zip" | "vsix" | "jar" | "war" | "ear" | "apk" | "whl"
            )
        {
            let mut f = fs::File::open(p)
                .map_err(|e| (1, format!("[ap read] failed to open `{target}`: {e}")))?;
            let (mut rendered, mut jv) = if cli.asar_surface {
                crate::binary::inspect_asar_surface_compact_reader(
                    &mut f,
                    &ext_s,
                    &lbl,
                    Some(p),
                    cli.routes,
                    cli.query.as_deref(),
                )
            } else {
                crate::binary::inspect_archive_surface_reader(
                    &mut f,
                    &ext_s,
                    &lbl,
                    cli.routes,
                    cli.query.as_deref(),
                )
            }
            .map_err(|e| (1, format!("[ap read --surface] {e}")))?;
            if cli.candidates {
                rendered = crate::inspect::render_candidates_focus_md(&jv, &lbl);
            }
            record_event(
                "read",
                rendered.len() as u64,
                rendered.len() as u64,
                0,
                1,
                if cli.asar_surface {
                    "asar-surface"
                } else {
                    "archive-surface"
                },
            );
            if let Some(m) = jv.as_object_mut() {
                if cli.asar_surface && cli.json {
                    let first_ln = rendered.lines().next().unwrap_or("").to_string();
                    m.insert("summary".to_string(), json!(first_ln));
                } else {
                    m.insert("content".to_string(), json!(rendered));
                }
            }
            return Ok((rendered, jv));
        } else if !cli.hex
            && (matches!(ext_s.as_str(), "sqlite" | "db" | "sqlite3")
                || crate::query::is_sqlite_magic(p))
        {
            match extract_sqlite_md(p) {
                Ok(md) => (md.into_bytes(), "sqlite-md".to_string(), lbl),
                Err(e) => return Err((1, format!("[ap read] {e}"))),
            }
        } else {
            let Ok(b) = fs::read(p) else {
                return Err((1, format!("[ap read] failed to read file: {target}")));
            };
            (b, ext_s, lbl)
        }
    };

    if cli.hex {
        let mut offs: Vec<usize> = Vec::new();
        if let Some(ref spec) = cli.offset {
            for part in spec.split(',') {
                let t = part.trim();
                let parsed = if let Some(hx) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"))
                {
                    usize::from_str_radix(hx, 16).ok()
                } else {
                    t.parse::<usize>().ok()
                };
                if let Some(v) = parsed {
                    offs.push(v);
                }
            }
        }
        if offs.is_empty() {
            offs.push(0);
        }
        let win = cli.chars.map(|c| c.clamp(16, 4096)).unwrap_or(512);
        let sha = crate::binary::sha256_hex(&raw_bytes);
        let ent =
            crate::binary::shannon_entropy(&raw_bytes[..raw_bytes.len().min(4 * 1024 * 1024)]);
        let mut blocks = Vec::new();
        for off in offs.iter().take(12) {
            let dump = crate::binary::format_hex_dump(&raw_bytes, *off, win);
            blocks.push(format!("## Offset 0x{off:x} ({off} B, len={win})\n{dump}"));
        }
        let rendered = format!(
            "# HEX `{label}` ({} B | sha256=`{sha}` | entropy=`{ent:.2}`)\n{}",
            raw_bytes.len(),
            blocks.join("\n\n")
        );
        record_event(
            "read",
            raw_bytes.len() as u64,
            rendered.len() as u64,
            0,
            1,
            "hex",
        );
        let jv = json!({
            "ok": true,
            "target": label,
            "format": "hex",
            "size_bytes": raw_bytes.len(),
            "sha256": sha,
            "entropy": (ent * 100.0).round() / 100.0,
            "content": rendered,
        });
        return Ok((rendered, jv));
    }

    if !cli.routes {
        if let Some(ref old_path_str) = cli.diff {
            let norm_old = crate::ls::normalize_cli_path(old_path_str);
            let old_p = Path::new(&norm_old);
            let old_bytes = fs::read(old_p).map_err(|e| {
                (
                    1,
                    format!("[ap read --diff] failed to read `{old_path_str}`: {e}"),
                )
            })?;
            if !crate::binary::is_binary_magic(&raw_bytes)
                && !crate::binary::is_binary_magic(&old_bytes)
            {
                if let (Ok(new_v), Ok(old_v)) = (
                    serde_json::from_slice::<serde_json::Value>(&raw_bytes),
                    serde_json::from_slice::<serde_json::Value>(&old_bytes),
                ) {
                    if matches!(
                        new_v,
                        serde_json::Value::Object(_) | serde_json::Value::Array(_)
                    ) && matches!(
                        old_v,
                        serde_json::Value::Object(_) | serde_json::Value::Array(_)
                    ) {
                        let (rendered, json_diff) = crate::inspect::diff_json_structural_md(
                            &new_v, &old_v, &label, &norm_old,
                        );
                        record_event(
                            "read",
                            (raw_bytes.len() + old_bytes.len()) as u64,
                            rendered.len() as u64,
                            0,
                            1,
                            "json-diff",
                        );
                        let jv = json!({
                            "ok": true,
                            "target": label,
                            "old_target": norm_old,
                            "format": "json-diff",
                            "json_diff": json_diff,
                            "content": rendered,
                        });
                        return Ok((rendered, jv));
                    }
                }
                let old_ext = old_p
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let (new_txt, _, _) = decode_any_bytes(&raw_bytes);
                let (old_txt, _, _) = decode_any_bytes(&old_bytes);
                if let (Some((_, new_v)), Some((_, old_v))) = (
                    crate::inspect::parse_structured_config_to_json(&new_txt, &ext),
                    crate::inspect::parse_structured_config_to_json(&old_txt, &old_ext),
                ) {
                    if matches!(
                        new_v,
                        serde_json::Value::Object(_) | serde_json::Value::Array(_)
                    ) && matches!(
                        old_v,
                        serde_json::Value::Object(_) | serde_json::Value::Array(_)
                    ) {
                        let (rendered, json_diff) = crate::inspect::diff_json_structural_md(
                            &new_v, &old_v, &label, &norm_old,
                        );
                        record_event(
                            "read",
                            (raw_bytes.len() + old_bytes.len()) as u64,
                            rendered.len() as u64,
                            0,
                            1,
                            "config-diff",
                        );
                        let jv = json!({
                            "ok": true,
                            "target": label,
                            "old_target": norm_old,
                            "format": "config-diff",
                            "json_diff": json_diff,
                            "content": rendered,
                        });
                        return Ok((rendered, jv));
                    }
                }
            }
            if cli.semantic {
                let (rendered, mut diff_jv) = crate::semantic_diff::diff_semantic_paths_both(
                    Path::new(&norm_old),
                    Path::new(target),
                )
                .map_err(|e| (1, format!("[ap read --semantic] {e}")))?;
                record_event(
                    "read",
                    (raw_bytes.len() + old_bytes.len()) as u64,
                    rendered.len() as u64,
                    0,
                    1,
                    "semantic-diff",
                );
                if let Some(m) = diff_jv.as_object_mut() {
                    m.insert("ok".into(), json!(true));
                    m.insert("format".into(), json!("semantic-diff"));
                    if !cli.json {
                        m.insert("content".into(), json!(rendered));
                    }
                }
                return Ok((rendered, diff_jv));
            }
            let (rendered, mut diff_jv) = crate::binary::diff_binaries_or_archives(
                &raw_bytes, &old_bytes, &label, &norm_old, &ext, true, 25,
            );
            record_event(
                "read",
                (raw_bytes.len() + old_bytes.len()) as u64,
                rendered.len() as u64,
                0,
                1,
                "binary-diff",
            );
            if let Some(obj) = diff_jv.as_object_mut() {
                obj.insert("format".to_string(), json!("binary-diff"));
                obj.insert("target".to_string(), json!(label));
                obj.insert("content".to_string(), json!(rendered));
            }
            return Ok((rendered, diff_jv));
        }
    }

    if let Some(ref addr_spec) = cli.rva {
        let win = cli.chars.unwrap_or(256);
        let rendered = crate::binary::inspect_binary_address_md(&raw_bytes, addr_spec, false, win)
            .map_err(|e| (1, format!("[ap read --rva] {e}")))?;
        record_event(
            "read",
            raw_bytes.len() as u64,
            rendered.len() as u64,
            0,
            1,
            "bin-rva",
        );
        let jv = json!({
            "ok": true,
            "target": label,
            "format": "bin-rva",
            "address": addr_spec,
            "content": rendered,
        });
        return Ok((rendered, jv));
    }

    if let Some(ref addr_spec) = cli.va {
        let win = cli.chars.unwrap_or(256);
        let rendered = crate::binary::inspect_binary_address_md(&raw_bytes, addr_spec, true, win)
            .map_err(|e| (1, format!("[ap read --va] {e}")))?;
        record_event(
            "read",
            raw_bytes.len() as u64,
            rendered.len() as u64,
            0,
            1,
            "bin-va",
        );
        let jv = json!({
            "ok": true,
            "target": label,
            "format": "bin-va",
            "address": addr_spec,
            "content": rendered,
        });
        return Ok((rendered, jv));
    }

    if let Some(ref byte_pat) = cli.find_bytes {
        let rendered = crate::binary::find_binary_bytes_md(&raw_bytes, byte_pat, cli.max_hits)
            .map_err(|e| (1, format!("[ap read --find-bytes] {e}")))?;
        record_event(
            "read",
            raw_bytes.len() as u64,
            rendered.len() as u64,
            0,
            1,
            "bin-bytes",
        );
        let jv = json!({
            "ok": true,
            "target": label,
            "format": "bin-bytes",
            "pattern": byte_pat,
            "content": rendered,
        });
        return Ok((rendered, jv));
    }

    let auto_cert = matches!(ext.as_str(), "pem" | "crt" | "cer" | "der")
        && cli.lines.is_none()
        && cli.query.is_none()
        && cli.offset.is_none()
        && !cli.hex
        && !cli.secrets
        && !cli.jwt
        && String::from_utf8_lossy(&raw_bytes[..raw_bytes.len().min(512)])
            .contains("-----BEGIN CERTIFICATE-----");
    if cli.cert || auto_cert {
        let rendered = crate::inspect::inspect_x509_pem_or_der(&raw_bytes)
            .map_err(|e| (1, format!("[ap read --cert] {e}")))?;
        record_event(
            "read",
            raw_bytes.len() as u64,
            rendered.len() as u64,
            0,
            1,
            "x509-cert",
        );
        let jv = json!({
            "ok": true,
            "target": label,
            "format": "x509-cert",
            "size_bytes": raw_bytes.len(),
            "content": rendered,
        });
        return Ok((rendered, jv));
    }

    if cli.proto {
        let rendered = crate::inspect::decode_raw_protobuf_md(&raw_bytes)
            .map_err(|e| (1, format!("[ap read --proto] {e}")))?;
        record_event(
            "read",
            raw_bytes.len() as u64,
            rendered.len() as u64,
            0,
            1,
            "protobuf-raw",
        );
        let jv = json!({
            "ok": true,
            "target": label,
            "format": "protobuf-raw",
            "size_bytes": raw_bytes.len(),
            "content": rendered,
        });
        return Ok((rendered, jv));
    }

    if cli.strings {
        let max_hits = if cli.max_hits > 0 { cli.max_hits } else { 200 };
        let raw_rendered = crate::binary::extract_strings_md(
            &raw_bytes,
            cli.query.as_deref(),
            cli.min_len,
            max_hits,
            &cli.str_encoding,
        );
        let rendered = if cli.width > 0 {
            raw_rendered
                .lines()
                .map(|ln| {
                    if ln.chars().count() > cli.width {
                        let cut: String = ln.chars().take(cli.width).collect();
                        format!("{cut}…")
                    } else {
                        ln.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            raw_rendered
        };
        record_event(
            "read",
            raw_bytes.len() as u64,
            rendered.len() as u64,
            0,
            1,
            "strings",
        );
        let jv = json!({
            "ok": true,
            "target": label,
            "format": "strings",
            "size_bytes": raw_bytes.len(),
            "min_len": cli.min_len,
            "encoding": cli.str_encoding,
            "content": rendered,
        });
        return Ok((rendered, jv));
    }

    if cli.jwt && cli.entry.is_none() {
        let (decoded_txt, _, _) = decode_any_bytes(&raw_bytes);
        let (rendered, jv_inner) = crate::inspect::inspect_jwt_md(&decoded_txt)
            .map_err(|e| (1, format!("[ap read --jwt] {e}")))?;
        record_event(
            "read",
            raw_bytes.len() as u64,
            rendered.len() as u64,
            0,
            1,
            "jwt",
        );
        let jv = json!({
            "ok": true,
            "target": label,
            "format": "jwt",
            "size_bytes": raw_bytes.len(),
            "jwt": jv_inner,
            "content": rendered,
        });
        return Ok((rendered, jv));
    }

    if cli.routes
        && cli.entry.is_none()
        && !matches!(
            ext.as_str(),
            "asar" | "zip" | "vsix" | "jar" | "war" | "ear" | "apk" | "whl"
        )
    {
        let (decoded_txt, _, _) = decode_any_bytes(&raw_bytes);
        let (mut rendered, jv_inner, fmt_tag) = if let Some((h_md, h_jv)) =
            crate::inspect::extract_har_routes_md(&decoded_txt, &label, cli.query.as_deref())
        {
            (h_md, h_jv, "har-routes")
        } else if let Some(ref old_path_str) = cli.diff {
            let norm_old = crate::ls::normalize_cli_path(old_path_str);
            let old_p = Path::new(&norm_old);
            if old_p.is_dir() {
                crate::inspect::extract_js_dir_routes_md_opts(
                    Path::new(&target),
                    cli.query.as_deref(),
                    Some(old_p),
                    cli.mutating_only,
                )
                .map(|(m, j)| (m, j, "js-routes"))?
            } else {
                let old_bytes = fs::read(old_p).map_err(|e| {
                    (
                        1,
                        format!("[ap read --routes --diff] failed to read `{old_path_str}`: {e}"),
                    )
                })?;
                let (old_txt, _, _) = decode_any_bytes(&old_bytes);
                let (j_md, j_jv) = crate::inspect::extract_js_routes_diff_md_opts(
                    &decoded_txt,
                    &label,
                    cli.query.as_deref(),
                    &old_txt,
                    old_path_str,
                    cli.mutating_only,
                );
                (j_md, j_jv, "js-routes")
            }
        } else {
            let (j_md, j_jv) = crate::inspect::extract_js_routes_md_opts(
                &decoded_txt,
                &label,
                cli.query.as_deref(),
                cli.mutating_only,
            );
            (j_md, j_jv, "js-routes")
        };
        if cli.candidates {
            rendered = crate::inspect::render_candidates_focus_md(&jv_inner, &label);
        }
        record_event(
            "read",
            raw_bytes.len() as u64,
            rendered.len() as u64,
            0,
            1,
            fmt_tag,
        );
        let jv = json!({
            "ok": true,
            "target": label,
            "format": fmt_tag,
            "size_bytes": raw_bytes.len(),
            "surface": jv_inner,
            "content": rendered,
        });
        return Ok((rendered, jv));
    }

    if cli.secrets && cli.entry.is_none() {
        let (decoded_txt, _, _) = decode_any_bytes(&raw_bytes);
        let (rendered, jv_inner) =
            crate::inspect::scan_secrets_md(&decoded_txt, &label, cli.query.as_deref());
        record_event(
            "read",
            raw_bytes.len() as u64,
            rendered.len() as u64,
            0,
            1,
            "secrets",
        );
        let jv = json!({
            "ok": true,
            "target": label,
            "format": "secrets",
            "size_bytes": raw_bytes.len(),
            "secrets": jv_inner,
            "content": rendered,
        });
        return Ok((rendered, jv));
    }

    let raw_len = raw_bytes.len() as u64;
    let mut win_heals = 0u32;
    let mut format_tag = ext.as_str();

    let converted: String = match ext.as_str() {
        "docx" => match extract_docx_md(&raw_bytes) {
            Ok(s) => s,
            Err(e) => return Err((1, format!("[ap read] {e}"))),
        },
        "xlsx" => match extract_xlsx_md(&raw_bytes, cli.sheet.as_deref(), cli.query.as_deref()) {
            Ok(s) => s,
            Err(e) => return Err((1, format!("[ap read] {e}"))),
        },
        "map" => match serde_json::from_slice::<serde_json::Value>(&raw_bytes) {
            Ok(v) if crate::inspect::is_sourcemap_v3(&v) => {
                if let Some(ref mp) = cli.map_pos {
                    let parts: Vec<&str> = mp.split(':').collect();
                    let ln = parts
                        .first()
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(1);
                    let col = parts
                        .get(1)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    format_tag = "sourcemap-vlq";
                    match crate::inspect::resolve_sourcemap_pos(&v, ln, col) {
                        Ok(s) => s,
                        Err(e) => return Err((1, format!("[ap read] {e}"))),
                    }
                } else if let Some(ref ent) = cli.entry {
                    format_tag = "sourcemap-entry";
                    match crate::inspect::read_sourcemap_entry(&v, ent) {
                        Ok((_, body)) => body,
                        Err(e) => return Err((1, format!("[ap read] {e}"))),
                    }
                } else {
                    format_tag = "sourcemap-v3";
                    crate::inspect::list_sourcemap_md(&v, cli.query.as_deref())
                }
            }
            _ => decode_any_bytes(&raw_bytes).0,
        },
        "asar" => {
            if let Some(ref ent) = cli.entry {
                match crate::binary::read_asar_member(&raw_bytes, ent) {
                    Ok(eb) => {
                        format_tag = "asar-entry";
                        let (dec, _, healed) = decode_any_bytes(&eb);
                        win_heals += healed;
                        dec
                    }
                    Err(e) => return Err((1, format!("[ap read] {e}"))),
                }
            } else {
                format_tag = "asar";
                match crate::binary::list_asar_md(&raw_bytes, cli.query.as_deref()) {
                    Ok(s) => s,
                    Err(e) => return Err((1, format!("[ap read] {e}"))),
                }
            }
        }
        "pptx" | "zip" | "vsix" | "jar" | "war" | "ear" | "apk" | "whl" => {
            if let Some(ref ent) = cli.entry {
                match crate::binary::read_zip_member(&raw_bytes, ent) {
                    Ok(eb) => {
                        if crate::binary::is_java_class_magic(&eb) {
                            format_tag = "java-class";
                            crate::binary::parse_java_class_md(&eb, cli.query.as_deref())
                        } else if crate::binary::is_pyc_magic(&eb) {
                            format_tag = "pyc";
                            crate::binary::parse_pyc_md(&eb, cli.query.as_deref())
                        } else {
                            format_tag = "zip-entry";
                            let (dec, _, healed) = decode_any_bytes(&eb);
                            win_heals += healed;
                            dec
                        }
                    }
                    Err(e) => return Err((1, format!("[ap read] {e}"))),
                }
            } else {
                match extract_pptx_or_zip(&raw_bytes, &ext) {
                    Ok(s) => s,
                    Err(e) => return Err((1, format!("[ap read] {e}"))),
                }
            }
        }
        "pdf" => match extract_pdf_text(&raw_bytes) {
            Ok(s) => s,
            Err(e) => return Err((1, format!("[ap read] {e}"))),
        },
        "rendered-dom" | "sqlite-md" => String::from_utf8_lossy(&raw_bytes).to_string(),
        "tgz" | "gz" => {
            let dec = GzDecoder::new(Cursor::new(&raw_bytes));
            let mut ubuf = Vec::new();
            let _ = dec.take(16 * 1024 * 1024).read_to_end(&mut ubuf);
            if ext == "tgz" || label.to_ascii_lowercase().ends_with(".tar.gz") {
                read_tar_or_entry(
                    &ubuf,
                    cli.entry.as_deref(),
                    cli.query.as_deref(),
                    cli.xref,
                    "tar.gz",
                    &mut format_tag,
                    &mut win_heals,
                )?
            } else {
                format_tag = "gzip";
                let (decoded, _, _) = decode_any_bytes(&ubuf);
                if decoded.len() > 2400 && cli.lines.is_none() && cli.query.is_none() {
                    let sieve_store = std::env::var("SIEVE_HOME")
                        .ok()
                        .filter(|s| !s.is_empty())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| std::env::temp_dir().join("ap_read_sieve"));
                    ap_sieve::compress_stream_in(&sieve_store, &decoded, &label, 0, 1.0).rendered
                } else {
                    decoded
                }
            }
        }
        "tar" => read_tar_or_entry(
            &raw_bytes,
            cli.entry.as_deref(),
            cli.query.as_deref(),
            cli.xref,
            "tar",
            &mut format_tag,
            &mut win_heals,
        )?,
        _ => {
            if cli.fw_surface {
                format_tag = "firmware-surface";
                let rendered =
                    crate::binary_ext::inspect_firmware_surface(&raw_bytes, &label, false)
                        .map_err(|e| (1, format!("[ap read --fw-surface] {e}")))?;
                let jv_str = crate::binary_ext::inspect_firmware_surface(&raw_bytes, &label, true)
                    .unwrap_or_else(|_| "{}".to_string());
                let mut jv = serde_json::from_str::<serde_json::Value>(&jv_str)
                    .unwrap_or_else(|_| json!({ "content": &rendered }));
                record_event(
                    "read",
                    raw_bytes.len() as u64,
                    rendered.len() as u64,
                    0,
                    1,
                    format_tag,
                );
                if let Some(m) = jv.as_object_mut() {
                    m.insert("ok".into(), json!(true));
                    m.insert("format_tag".into(), json!(format_tag));
                    if !cli.json {
                        m.insert("content".into(), json!(rendered));
                    }
                }
                return Ok((rendered, jv));
            }
            if let Some(img_meta) = try_extract_image_meta(&raw_bytes, &ext) {
                format_tag = "image-meta";
                img_meta
            } else if matches!(
                ext.as_str(),
                "exe"
                    | "dll"
                    | "sys"
                    | "ocx"
                    | "cpl"
                    | "efi"
                    | "so"
                    | "ko"
                    | "dylib"
                    | "node"
                    | "wasm"
                    | "bin"
                    | "class"
                    | "pyc"
            ) || (!is_url && crate::binary::is_binary_magic(&raw_bytes))
            {
                let bin_modes = usize::from(cli.ioctl || cli.pipes)
                    + usize::from(cli.rpc_com_alpc)
                    + usize::from(cli.surface);
                if bin_modes >= 2 {
                    format_tag = "binary-combined";
                    let mut md_parts: Vec<String> = Vec::new();
                    let mut merged = serde_json::Map::new();
                    let mut modes_run: Vec<&str> = Vec::new();
                    if cli.ioctl || cli.pipes {
                        modes_run.push("ioctl_pipes");
                        let (r_md, r_jv) = crate::binary::inspect_pe_ioctl_and_pipes(
                            &raw_bytes,
                            &label,
                            cli.ioctl,
                            cli.pipes || cli.ioctl,
                            cli.query.as_deref(),
                        );
                        md_parts.push(r_md);
                        if let Some(m) = r_jv.as_object() {
                            for (k, v) in m {
                                merged.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    if cli.rpc_com_alpc {
                        modes_run.push("rpc_com_alpc");
                        if cli.json {
                            let r_jstr = crate::binary_ext::inspect_pe_rpc_com_alpc(
                                &raw_bytes, &label, true,
                            )
                            .map_err(|e| (1, format!("[ap read --rpc-com-alpc] {e}")))?;
                            if let Ok(serde_json::Value::Object(m)) =
                                serde_json::from_str::<serde_json::Value>(&r_jstr)
                            {
                                for (k, v) in m {
                                    merged.insert(k, v);
                                }
                            }
                        } else {
                            let r_md = crate::binary_ext::inspect_pe_rpc_com_alpc(
                                &raw_bytes, &label, false,
                            )
                            .map_err(|e| (1, format!("[ap read --rpc-com-alpc] {e}")))?;
                            md_parts.push(r_md);
                        }
                    }
                    if cli.surface {
                        modes_run.push("surface");
                        let surf_json = crate::binary::inspect_binary_surface(&raw_bytes);
                        if !cli.json {
                            md_parts.push(crate::binary::format_binary_surface_md(&surf_json));
                        }
                        if let Some(m) = surf_json.as_object() {
                            for (k, v) in m {
                                merged.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    let rendered = md_parts.join("\n\n");
                    merged.insert("ok".to_string(), json!(true));
                    merged.insert("target".to_string(), json!(label));
                    merged.insert("format_tag".to_string(), json!(format_tag));
                    merged.insert("modes_run".to_string(), json!(modes_run));
                    if !cli.json {
                        merged.insert("content".to_string(), json!(rendered));
                    }
                    let out_bytes = if cli.json {
                        serde_json::to_string(&merged)
                            .map(|s| s.len() as u64)
                            .unwrap_or(0)
                    } else {
                        rendered.len() as u64
                    };
                    record_event("read", raw_bytes.len() as u64, out_bytes, 0, 1, format_tag);
                    return Ok((rendered, serde_json::Value::Object(merged)));
                }
                if cli.ioctl || cli.pipes {
                    format_tag = "binary-ioctl-pipes";
                    let (rendered, mut jv) = crate::binary::inspect_pe_ioctl_and_pipes(
                        &raw_bytes,
                        &label,
                        cli.ioctl,
                        cli.pipes || cli.ioctl,
                        cli.query.as_deref(),
                    );
                    record_event(
                        "read",
                        raw_bytes.len() as u64,
                        rendered.len() as u64,
                        0,
                        1,
                        format_tag,
                    );
                    if let Some(m) = jv.as_object_mut() {
                        m.insert("format_tag".to_string(), json!(format_tag));
                        if !cli.json {
                            m.insert("content".to_string(), json!(rendered));
                        }
                    }
                    return Ok((rendered, jv));
                }
                if cli.rpc_com_alpc {
                    format_tag = "pe-rpc-com-alpc";
                    let (rendered, mut jv) = if cli.json {
                        let jv_str =
                            crate::binary_ext::inspect_pe_rpc_com_alpc(&raw_bytes, &label, true)
                                .map_err(|e| (1, format!("[ap read --rpc-com-alpc] {e}")))?;
                        let parsed = serde_json::from_str::<serde_json::Value>(&jv_str)
                            .unwrap_or_else(|_| json!({ "content": &jv_str }));
                        (jv_str, parsed)
                    } else {
                        let md =
                            crate::binary_ext::inspect_pe_rpc_com_alpc(&raw_bytes, &label, false)
                                .map_err(|e| (1, format!("[ap read --rpc-com-alpc] {e}")))?;
                        let parsed = json!({ "content": &md });
                        (md, parsed)
                    };
                    record_event(
                        "read",
                        raw_bytes.len() as u64,
                        rendered.len() as u64,
                        0,
                        1,
                        format_tag,
                    );
                    if let Some(m) = jv.as_object_mut() {
                        m.insert("ok".into(), json!(true));
                        m.insert("format_tag".into(), json!(format_tag));
                        if !cli.json {
                            m.insert("content".into(), json!(rendered));
                        }
                    }
                    return Ok((rendered, jv));
                }
                if cli.surface {
                    format_tag = "binary-surface";
                    let surf_json = crate::binary::inspect_binary_surface(&raw_bytes);
                    let rendered = if cli.json {
                        serde_json::to_string_pretty(&surf_json).unwrap_or_default()
                    } else {
                        crate::binary::format_binary_surface_md(&surf_json)
                    };
                    record_event(
                        "read",
                        raw_bytes.len() as u64,
                        rendered.len() as u64,
                        0,
                        1,
                        format_tag,
                    );
                    let mut jv = surf_json;
                    if let Some(m) = jv.as_object_mut() {
                        m.insert("target".to_string(), json!(label));
                        m.insert("format_tag".to_string(), json!(format_tag));
                    }
                    return Ok((rendered, jv));
                }
                format_tag = "binary";
                crate::binary::inspect_binary_with_xref_md(
                    &raw_bytes,
                    cli.query.as_deref(),
                    80,
                    cli.xref,
                )
            } else {
                let (decoded, enc_name, healed) = decode_any_bytes(&raw_bytes);
                win_heals += healed;
                format_tag = enc_name;
                if (is_url
                    || matches!(
                        ext.as_str(),
                        "csv" | "tsv" | "json" | "jsonl" | "html" | "htm"
                    ))
                    && decoded.len() > 2400
                    && cli.lines.is_none()
                    && cli.query.is_none()
                    && cli.offset.is_none()
                    && cli.json_path.is_none()
                    && !cli.outline
                    && !cli.decode
                {
                    let sieve_store = std::env::var("SIEVE_HOME")
                        .ok()
                        .filter(|s| !s.is_empty())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| std::env::temp_dir().join("ap_read_sieve"));
                    let sr = ap_sieve::compress_stream_in(&sieve_store, &decoded, &label, 0, 1.0);
                    sr.rendered
                } else {
                    decoded
                }
            }
        }
    };

    // Compose `--entry` on virtual archives (.asar/.zip/.vsix/.jar/.map) with `--routes`/`--secrets`/`--jwt`
    if cli.entry.is_some() {
        let entry_label = format!("{label}!{}", cli.entry.as_deref().unwrap_or(""));
        if cli.jwt {
            let (rendered, jv_inner) = crate::inspect::inspect_jwt_md(&converted)
                .map_err(|e| (1, format!("[ap read --entry --jwt] {e}")))?;
            record_event(
                "read",
                raw_len,
                rendered.len() as u64,
                win_heals,
                1,
                "entry-jwt",
            );
            let jv = json!({
                "ok": true,
                "target": entry_label,
                "format": "jwt",
                "jwt": jv_inner,
                "content": rendered,
            });
            return Ok((rendered, jv));
        }
        if cli.routes {
            let (rendered, jv_inner, fmt_tag) = if let Some((h_md, h_jv)) =
                crate::inspect::extract_har_routes_md(
                    &converted,
                    &entry_label,
                    cli.query.as_deref(),
                ) {
                (h_md, h_jv, "har-routes")
            } else {
                let (j_md, j_jv) = crate::inspect::extract_js_routes_md(
                    &converted,
                    &entry_label,
                    cli.query.as_deref(),
                );
                (j_md, j_jv, "js-routes")
            };
            record_event(
                "read",
                raw_len,
                rendered.len() as u64,
                win_heals,
                1,
                fmt_tag,
            );
            let jv = json!({
                "ok": true,
                "target": entry_label,
                "format": fmt_tag,
                "surface": jv_inner,
                "content": rendered,
            });
            return Ok((rendered, jv));
        }
        if cli.secrets {
            let (rendered, jv_inner) =
                crate::inspect::scan_secrets_md(&converted, &entry_label, cli.query.as_deref());
            record_event(
                "read",
                raw_len,
                rendered.len() as u64,
                win_heals,
                1,
                "entry-secrets",
            );
            let jv = json!({
                "ok": true,
                "target": entry_label,
                "format": "secrets",
                "secrets": jv_inner,
                "content": rendered,
            });
            return Ok((rendered, jv));
        }
    }

    let all_lines: Vec<&str> = converted.lines().collect();
    let total_lines = all_lines.len();
    let is_minified = format_tag != "binary" && all_lines.iter().any(|l| l.len() > 1000);

    let floor_boundary = |s: &str, mut idx: usize| -> usize {
        idx = idx.min(s.len());
        while idx > 0 && !s.is_char_boundary(idx) {
            idx -= 1;
        }
        idx
    };
    let ceil_boundary = |s: &str, mut idx: usize| -> usize {
        idx = idx.min(s.len());
        while idx < s.len() && !s.is_char_boundary(idx) {
            idx += 1;
        }
        idx
    };

    fn cap_line_width(s: &str, width: usize) -> std::borrow::Cow<'_, str> {
        if width == 0 || s.chars().count() <= width {
            std::borrow::Cow::Borrowed(s)
        } else {
            let cut: String = s.chars().take(width).collect();
            std::borrow::Cow::Owned(format!("{cut}…"))
        }
    }

    let mut rendered = if cli.outline {
        if format_tag == "binary" {
            converted.clone()
        } else if ap_splice::ast::language_for_ext(&ext).is_some() {
            let syms = ap_splice::ast::scan_symbols(&converted, &ext);
            let lines_out: Vec<String> = syms
                .iter()
                .map(|s| {
                    let pad = if s.qual.contains('.') { "  " } else { "" };
                    format!(
                        "{pad}L{}-L{}: {} {}",
                        s.start_line, s.end_line, s.kind, s.qual
                    )
                })
                .collect();
            format!(
                "# OUTLINE `{label}` [{} AST symbol(s) across {total_lines} lines | {format_tag}]\n{}",
                syms.len(),
                if lines_out.is_empty() {
                    "*(no top-level symbols detected)*".to_string()
                } else {
                    lines_out.join("\n")
                }
            )
        } else if matches!(ext.as_str(), "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx") {
            let cpp_syms = scan_cpp_outline_lines(&converted);
            format!(
                "# OUTLINE `{label}` [{} C/C++ outline symbol(s) across {total_lines} lines | {format_tag}]\n{}",
                cpp_syms.len(),
                if cpp_syms.is_empty() {
                    "*(no C/C++ outline symbols detected)*".to_string()
                } else {
                    cpp_syms.iter().take(100).cloned().collect::<Vec<_>>().join("\n")
                }
            )
        } else if let Some(json_outline) = crate::inspect::outline_json_or_jsonl(&converted) {
            format!(
                "# OUTLINE `{label}` [JSON/HAR/JSONL schema across {total_lines} lines | {format_tag}]\n{json_outline}"
            )
        } else if let Some((cfg_kind, cfg_outline)) =
            crate::inspect::outline_structured_config(&converted, &ext)
        {
            format!(
                "# OUTLINE `{label}` [{cfg_kind} schema across {total_lines} lines | {format_tag}]\n{cfg_outline}"
            )
        } else {
            let headings: Vec<String> = all_lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.starts_with('#') || l.starts_with("## Sheet:"))
                .take(80)
                .map(|(i, l)| format!("L{}: {}", i + 1, l))
                .collect();
            format!(
                "# OUTLINE `{label}` [{} heading(s) across {total_lines} lines | {format_tag}]\n{}",
                headings.len(),
                if headings.is_empty() {
                    "*(no headings detected)*".to_string()
                } else {
                    headings.join("\n")
                }
            )
        }
    } else if let Some(ref sec_q) = cli.section {
        match extract_md_section(&all_lines, sec_q) {
            Ok((s, e, slice)) => format!(
                "# READ `{label}` [section='{sec_q}' | L{s}-L{e} of {total_lines} | {format_tag}]\n{slice}"
            ),
            Err(avail) => {
                let hint = if avail.is_empty() {
                    "no Markdown headings found".to_string()
                } else {
                    avail.join("; ")
                };
                return Err((
                    1,
                    format!("[ap read] section `{sec_q}` not found in `{label}` (available: {hint})"),
                ));
            }
        }
    } else if let Some(ref sym_spec) = cli.symbol {
        let is_cpp = matches!(ext.as_str(), "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx");
        if ap_splice::ast::language_for_ext(&ext).is_none() && !is_cpp {
            return Err((
                2,
                format!("[ap read] --symbol requires a Tree-sitter code file (Py/TS/JS/Go/Rust/C) or C/C++, got `.{ext}`"),
            ));
        }
        let wanted: Vec<&str> = sym_spec
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if wanted.is_empty() {
            return Err((2, "[ap read] empty --symbol value".to_string()));
        }
        let mut blocks = Vec::new();
        for sym in wanted.into_iter().take(12) {
            let (kind, qual, s_ln, e_ln) = if !is_cpp {
                if let Some(sp) = ap_splice::ast::find_symbol_span(&converted, &ext, sym) {
                    (sp.kind, sp.qual, sp.start_line, sp.end_line)
                } else {
                    let avail: Vec<String> = ap_splice::ast::scan_symbols(&converted, &ext)
                        .into_iter()
                        .take(12)
                        .map(|s| s.qual)
                        .collect();
                    return Err((
                        1,
                        format!(
                            "[ap read] symbol `{sym}` not found in `{label}` (available: {})",
                            avail.join(", ")
                        ),
                    ));
                }
            } else if let Some(sp) = find_cpp_symbol_span(&converted, sym) {
                (sp.kind, sp.qual, sp.start_line, sp.end_line)
            } else {
                let avail: Vec<String> = scan_cpp_symbols(&converted)
                    .into_iter()
                    .take(12)
                    .map(|s| s.qual)
                    .collect();
                return Err((
                    1,
                    format!(
                        "[ap read] symbol `{sym}` not found in `{label}` (available: {})",
                        avail.join(", ")
                    ),
                ));
            };
            let s = s_ln.max(1);
            let e = e_ln.min(total_lines);
            let slice = if total_lines == 0 || s > e {
                String::new()
            } else {
                (s..=e)
                    .filter_map(|ln| {
                        ln.checked_sub(1)
                            .and_then(|idx| all_lines.get(idx))
                            .map(|line| format!("{ln:5}: {line}"))
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            blocks.push(format!("## {kind} {qual} [L{s}-L{e}]\n{slice}"));
        }
        format!(
            "# READ `{label}` [{} AST symbol(s) of {total_lines} lines | {format_tag}]\n{}",
            blocks.len(),
            blocks.join("\n\n")
        )
    } else if let Some(ref jp) = cli.json_path {
        match crate::inspect::query_json_or_structured(&converted, &ext, jp) {
            Ok(out) => format!("# READ `{label}` [json-path='{jp}' | {format_tag}]\n{out}"),
            Err(e) => return Err((1, format!("[ap read] {e}"))),
        }
    } else if let Some(ref off_spec) = cli.offset {
        let mut offsets: Vec<usize> = Vec::new();
        for tok in off_spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match parse_byte_offset(tok) {
                Ok(n) => offsets.push(n),
                Err(_) => {
                    return Err((
                        2,
                        format!("[ap read] invalid --offset `{tok}` (expected decimal or 0x hex byte offset(s), e.g. 18000, 0x4650, or 18000,95000)"),
                    ));
                }
            }
        }
        if offsets.is_empty() {
            return Err((2, "[ap read] empty --offset value".to_string()));
        }
        let slice_chars = cli.chars.unwrap_or(2400).max(120);
        if offsets.len() == 1 {
            let s = floor_boundary(&converted, offsets[0]);
            let e = ceil_boundary(&converted, s.saturating_add(slice_chars));
            let raw_slice = &converted[s..e];
            let body = if cli.pretty {
                crate::binary::pretty_format_js_snippet(raw_slice)
            } else {
                raw_slice.to_string()
            };
            format!(
                "# READ `{label}` [offset {s}..{e} of {}B | {format_tag}{}]\n{body}",
                converted.len(),
                if cli.pretty { " | pretty" } else { "" }
            )
        } else {
            let mut blocks = Vec::new();
            for off in offsets.into_iter().take(12) {
                let s = floor_boundary(&converted, off);
                let e = ceil_boundary(&converted, s.saturating_add(slice_chars));
                let raw_slice = &converted[s..e];
                let body = if cli.pretty {
                    crate::binary::pretty_format_js_snippet(raw_slice)
                } else {
                    raw_slice.to_string()
                };
                blocks.push(format!("## offset {s}..{e}\n{body}"));
            }
            format!(
                "# READ `{label}` [batch {} offset window(s) of {}B | {format_tag}{}]\n{}",
                blocks.len(),
                converted.len(),
                if cli.pretty { " | pretty" } else { "" },
                blocks.join("\n\n")
            )
        }
    } else if let Some(ref lspec) = cli.lines {
        let parts: Vec<&str> = lspec
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if parts.len() <= 1 {
            if let Some((s, e)) = parse_line_window(lspec, total_lines) {
                let slice = if total_lines == 0 || s > e {
                    "*(empty)*".to_string()
                } else {
                    (s..=e)
                        .filter_map(|ln| {
                            ln.checked_sub(1)
                                .and_then(|idx| all_lines.get(idx))
                                .map(|line| format!("{ln:5}: {}", cap_line_width(line, cli.width)))
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                format!("# READ `{label}` [L{s}-L{e} of {total_lines} | {format_tag}]\n{slice}")
            } else {
                return Err((
                    2,
                    format!("[ap read] invalid --lines `{lspec}` (expected START-END, e.g. 1-120 or 10-40,120-160)"),
                ));
            }
        } else {
            let mut blocks = Vec::new();
            for p in parts.into_iter().take(12) {
                let Some((s, e)) = parse_line_window(p, total_lines) else {
                    return Err((
                        2,
                        format!("[ap read] invalid --lines range `{p}` in `{lspec}`"),
                    ));
                };
                let slice = if total_lines == 0 || s > e {
                    "*(empty)*".to_string()
                } else {
                    (s..=e)
                        .filter_map(|ln| {
                            ln.checked_sub(1)
                                .and_then(|idx| all_lines.get(idx))
                                .map(|line| format!("{ln:5}: {}", cap_line_width(line, cli.width)))
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                blocks.push(format!("## L{s}-L{e}\n{slice}"));
            }
            format!(
                "# READ `{label}` [batch {} line window(s) of {total_lines} | {format_tag}]\n{}",
                blocks.len(),
                blocks.join("\n\n")
            )
        }
    } else if let Some(tail_n) = cli.tail {
        if tail_n == 0 {
            return Err((2, "[ap read] invalid --tail 0 (expected >= 1)".to_string()));
        }
        if total_lines == 0 {
            format!("# READ `{label}` [tail {tail_n} of 0 lines | {format_tag}]\n")
        } else {
            let s = total_lines.saturating_sub(tail_n) + 1;
            let e = total_lines;
            let slice = (s..=e)
                .filter_map(|ln| {
                    ln.checked_sub(1)
                        .and_then(|idx| all_lines.get(idx))
                        .map(|line| format!("{ln:5}: {}", cap_line_width(line, cli.width)))
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!("# READ `{label}` [L{s}-L{e} of {total_lines} | {format_tag}]\n{slice}")
        }
    } else if let Some(ref q) = cli
        .query
        .clone()
        .filter(|_| !matches!(format_tag, "xlsx" | "asar" | "binary" | "sourcemap-v3"))
    {
        if is_minified {
            let q_re = Regex::new(&format!("(?i){q}"))
                .or_else(|_| Regex::new(&format!("(?i){}", regex::escape(q))))
                .unwrap();
            let around = if cli.around > 0 { cli.around } else { 240 };
            let limit = if cli.max_hits > 0 {
                cli.max_hits.min(100)
            } else {
                12
            };
            let mut hits = Vec::new();
            for m in q_re.find_iter(&converted).take(limit) {
                let s = floor_boundary(&converted, m.start().saturating_sub(around));
                let e = ceil_boundary(&converted, m.end().saturating_add(around));
                let raw_snip = &converted[s..e];
                let body = if cli.pretty {
                    crate::binary::pretty_format_js_snippet(raw_snip)
                } else {
                    raw_snip.to_string()
                };
                hits.push(format!("### @off={}\n{body}", m.start()));
            }
            format!(
                "# READ `{label}` [minified query='{q}' | {} byte-window hit(s) in {}B]\n{}",
                hits.len(),
                converted.len(),
                if hits.is_empty() {
                    "*(no matches)*".to_string()
                } else {
                    hits.join("\n\n")
                }
            )
        } else {
            let q_re = Regex::new(&format!("(?i){q}"))
                .or_else(|_| Regex::new(&format!("(?i){}", regex::escape(q))))
                .unwrap();
            let ctx_n = if cli.around > 0 {
                cli.around.min(20)
            } else {
                1
            };
            let limit = if cli.max_hits > 0 {
                cli.max_hits.min(100)
            } else {
                25
            };
            let mut hits = Vec::new();
            for (idx, ln) in all_lines.iter().enumerate() {
                if q_re.is_match(ln) {
                    let s = idx.saturating_sub(ctx_n);
                    let e = (idx + ctx_n).min(total_lines.saturating_sub(1));
                    let ctx = (s..=e)
                        .filter_map(|k| {
                            all_lines.get(k).map(|line| {
                                format!("  {}: {}", k + 1, cap_line_width(line, cli.width))
                            })
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    hits.push(ctx);
                    if hits.len() >= limit {
                        break;
                    }
                }
            }
            format!(
                "# READ `{label}` [query='{q}' | {} match block(s) in {total_lines} lines]\n{}",
                hits.len(),
                if hits.is_empty() {
                    "*(no matches)*".to_string()
                } else {
                    hits.join("\n  ---\n")
                }
            )
        }
    } else if is_minified && converted.len() > cli.max_chars {
        let e = ceil_boundary(&converted, 1800);
        let raw_head = &converted[..e];
        let body = if cli.pretty {
            crate::binary::pretty_format_js_snippet(raw_head)
        } else {
            raw_head.to_string()
        };
        format!(
            "# READ `{label}` [minified/long-line file: {}B across {total_lines} lines | {format_tag}]\n{body}\n\n[ap read minified pager: pass `--query <regex> --pretty` or `--offset 1800 --chars 2400 --pretty` to slice without context overflow]",
            converted.len()
        )
    } else if converted.len() > cli.max_chars
        && !(format_tag == "binary"
            && (cli.query.is_some() || cli.xref)
            && converted.len() <= 24000)
    {
        let is_ast_code = ap_splice::ast::language_for_ext(&ext).is_some();
        let outline = if is_ast_code {
            let syms = ap_splice::ast::scan_symbols(&converted, &ext);
            if syms.is_empty() {
                String::new()
            } else {
                let sym_lines: Vec<String> = syms
                    .iter()
                    .take(35)
                    .map(|s| format!("  L{}-L{}: {} {}", s.start_line, s.end_line, s.kind, s.qual))
                    .collect();
                let more = if syms.len() > 35 {
                    format!(
                        "\n  ... (+{} more symbols; pass `--outline`)",
                        syms.len() - 35
                    )
                } else {
                    String::new()
                };
                format!(
                    "AST Symbol Outline ({} total):\n{}{more}\n\n",
                    syms.len(),
                    sym_lines.join("\n")
                )
            }
        } else if matches!(ext.as_str(), "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx") {
            let cpp_syms = scan_cpp_outline_lines(&converted);
            if cpp_syms.is_empty() {
                String::new()
            } else {
                format!(
                    "C/C++ Outline ({} total; pass `--outline`):\n{}\n\n",
                    cpp_syms.len(),
                    cpp_syms
                        .iter()
                        .take(25)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            }
        } else {
            let headings: Vec<String> = all_lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.starts_with('#') || l.starts_with("## Sheet:"))
                .take(25)
                .map(|(i, l)| format!("  L{}: {}", i + 1, l))
                .collect();
            if headings.is_empty() {
                String::new()
            } else {
                format!("Outline:\n{}\n\n", headings.join("\n"))
            }
        };
        let head_n = 45.min(total_lines);
        let head_s = (1..=head_n)
            .filter_map(|ln| {
                ln.checked_sub(1)
                    .and_then(|idx| all_lines.get(idx))
                    .map(|line| format!("{ln:5}: {}", cap_line_width(line, cli.width)))
            })
            .collect::<Vec<_>>()
            .join("\n");
        let tip = if is_ast_code {
            format!(
                "[ap read pager: pass `--symbol <Name>` (AST-exact), `--lines {}-{}`, or `--query <keyword>`]",
                head_n + 1,
                (head_n + 120).min(total_lines.max(1))
            )
        } else {
            format!(
                "[ap read pager: pass `--lines {}-{} ` or `--query <keyword>` to inspect specific sections]",
                head_n + 1,
                (head_n + 120).min(total_lines.max(1))
            )
        };
        format!(
            "# READ `{label}` [paged: {}B -> preview of L1-L{head_n} / {total_lines} total lines | {format_tag}]\n{outline}{head_s}\n\n{tip}",
            raw_len
        )
    } else if cli.width > 0 {
        let capped = all_lines
            .iter()
            .map(|l| cap_line_width(l, cli.width))
            .collect::<Vec<_>>()
            .join("\n");
        format!("# READ `{label}` [{total_lines} lines | {format_tag}]\n{capped}")
    } else {
        format!("# READ `{label}` [{total_lines} lines | {format_tag}]\n{converted}")
    };

    if cli.decode {
        let dec_block = crate::inspect::decode_embedded_payloads(&rendered);
        rendered.push_str("\n\n");
        rendered.push_str(&dec_block);
    }

    let out_len = rendered.len() as u64;
    record_event("read", raw_len, out_len, win_heals, 0, format_tag);

    let jv = json!({
        "ok": true,
        "target": label,
        "format": format_tag,
        "raw_bytes": raw_len,
        "emitted_bytes": out_len,
        "total_lines": total_lines,
        "content": rendered,
    });
    Ok((rendered, jv))
}
