use crate::stats::record_event;
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

#[derive(Parser, Debug)]
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
    /// Character/byte window size when slicing with --offset (default: 2400)
    #[arg(long, default_value_t = 2400)]
    chars: usize,
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
    /// Resolve PE64 x64 RIP-relative string & IAT import cross-references with enclosing function RVAs
    #[arg(long)]
    xref: bool,
    /// Maximum characters before smart outline + pagination kicks in
    #[arg(long, default_value_t = 8000)]
    max_chars: usize,
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

fn extract_docx_md(bytes: &[u8]) -> Result<String, String> {
    let mut zip =
        ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("docx zip error: {e}"))?;
    let mut xml = String::new();
    zip.by_name("word/document.xml")
        .map_err(|_| "word/document.xml missing in .docx".to_string())?
        .read_to_string(&mut xml)
        .map_err(|e| e.to_string())?;

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
        idx = idx * 26 + ((ch.to_ascii_uppercase() - b'A') as usize + 1);
    }
    Some(idx.saturating_sub(1))
}

pub type XlsxSheetRows = (String, Vec<Vec<String>>);

pub fn extract_xlsx_sheets_raw(bytes: &[u8]) -> Result<Vec<XlsxSheetRows>, String> {
    let mut zip =
        ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("xlsx zip error: {e}"))?;
    let re = xre();

    let mut shared: Vec<String> = Vec::new();
    if let Ok(mut sf) = zip.by_name("xl/sharedStrings.xml") {
        let mut sxml = String::new();
        let _ = sf.read_to_string(&mut sxml);
        for cap in re.xlsx_si.captures_iter(&sxml) {
            let plain = unescape_xml(&re.xml_tag.replace_all(&cap[1], ""));
            shared.push(plain.replace('\n', " ").trim().to_string());
        }
    }

    let mut sheet_names: Vec<String> = Vec::new();
    if let Ok(mut wf) = zip.by_name("xl/workbook.xml") {
        let mut wxml = String::new();
        let _ = wf.read_to_string(&mut wxml);
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
        let Ok(mut shf) = zip.by_name(&xml_path) else {
            continue;
        };
        let mut shxml = String::new();
        let _ = shf.read_to_string(&mut shxml);

        let mut rows: Vec<Vec<String>> = Vec::new();
        for rcap in re.xlsx_row.captures_iter(&shxml) {
            let mut row_cells: Vec<String> = Vec::new();
            let mut cur_col = 0usize;
            for ccap in re.xlsx_cell.captures_iter(&rcap[1]) {
                let attrs = &ccap[1];
                let inner = &ccap[2];
                let col_idx = col_ref_to_index(attrs).unwrap_or(cur_col);
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
            let Ok(mut sf) = zip.by_name(&name) else {
                if i == 1 {
                    break;
                }
                continue;
            };
            let mut xml = String::new();
            let _ = sf.read_to_string(&mut xml);
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
            .read_to_end(&mut decoded)
            .is_err()
        {
            decoded.clear();
            if DeflateDecoder::new(stream_slice)
                .read_to_end(&mut decoded)
                .is_err()
            {
                decoded.extend_from_slice(stream_slice);
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
    let e = b.trim().parse::<usize>().ok()?.max(s).min(total.max(1));
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

fn extract_tar_entries(tar_bytes: &[u8]) -> String {
    let mut pos = 0usize;
    let mut entries = Vec::new();
    while pos + 512 <= tar_bytes.len() {
        let blk = &tar_bytes[pos..pos + 512];
        if blk.iter().all(|&b| b == 0) {
            break;
        }
        let name_end = blk[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let name = String::from_utf8_lossy(&blk[..name_end]).trim().to_string();
        let size_s = String::from_utf8_lossy(&blk[124..136]);
        let oct = size_s.trim_matches(|c: char| c == '\0' || c.is_whitespace());
        let size = usize::from_str_radix(oct, 8).unwrap_or(0);
        if !name.is_empty() && blk[156] != b'5' {
            entries.push(format!("  - `{name}` ({size} B)"));
        }
        pos += 512 + size.div_ceil(512) * 512;
    }
    format!(
        "## TAR Archive ({} file entries)\n{}",
        entries.len(),
        entries.into_iter().take(120).collect::<Vec<_>>().join("\n")
    )
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

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match ReadCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };

    if !cli.extra_targets.is_empty() {
        let mut all_targets = vec![cli.target.clone()];
        all_targets.extend(cli.extra_targets.iter().take(11).cloned());
        let per_budget = (cli.max_chars / all_targets.len().max(1)).max(1600);
        let mut sub_cli = cli;
        sub_cli.max_chars = per_budget;
        sub_cli.extra_targets.clear();

        let mut rendered_blocks = Vec::new();
        let mut json_files = Vec::new();
        let mut had_err = false;
        for t in &all_targets {
            match read_single_target(&sub_cli, t.trim()) {
                Ok((md, jv)) => {
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

    match read_single_target(&cli, cli.target.trim()) {
        Ok((rendered, jv)) => {
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&jv).unwrap_or_default());
            } else {
                println!("{rendered}");
            }
            0
        }
        Err((code, msg)) => {
            if !msg.is_empty() {
                eprintln!("{msg}");
            }
            code
        }
    }
}

fn read_single_target(
    cli: &ReadCli,
    target: &str,
) -> Result<(String, serde_json::Value), (i32, String)> {
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
            return Err((1, format!("[ap read] path not found: {target}")));
        }
        if p.is_dir() {
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
        if !cli.hex
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
        let win = if cli.chars == 2400 {
            512
        } else {
            cli.chars.clamp(16, 4096)
        };
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
        "pptx" | "zip" | "vsix" | "jar" | "apk" | "whl" => {
            if let Some(ref ent) = cli.entry {
                match crate::binary::read_zip_member(&raw_bytes, ent) {
                    Ok(eb) => {
                        format_tag = "zip-entry";
                        let (dec, _, healed) = decode_any_bytes(&eb);
                        win_heals += healed;
                        dec
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
            let _ = dec.take(4 * 1024 * 1024).read_to_end(&mut ubuf);
            if ext == "tgz" || label.to_ascii_lowercase().ends_with(".tar.gz") {
                format_tag = "tar.gz";
                extract_tar_entries(&ubuf)
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
        "tar" => extract_tar_entries(&raw_bytes),
        _ => {
            if let Some(img_meta) = try_extract_image_meta(&raw_bytes, &ext) {
                format_tag = "image-meta";
                img_meta
            } else if matches!(
                ext.as_str(),
                "exe" | "dll" | "sys" | "ocx" | "cpl" | "efi" | "so" | "ko" | "dylib" | "node" | "wasm" | "bin"
            ) || (!is_url && crate::binary::is_binary_magic(&raw_bytes))
            {
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

    let all_lines: Vec<&str> = converted.lines().collect();
    let total_lines = all_lines.len();
    let is_minified = all_lines.iter().any(|l| l.len() > 1000);

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

    let mut rendered = if cli.outline {
        if ap_splice::ast::language_for_ext(&ext).is_some() {
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
    } else if let Some(ref sym_spec) = cli.symbol {
        if ap_splice::ast::language_for_ext(&ext).is_none() {
            return Err((
                2,
                format!("[ap read] --symbol requires a Tree-sitter code file (Py/TS/JS/Go/Rust/C), got `.{ext}`"),
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
            let Some(sp) = ap_splice::ast::find_symbol_span(&converted, &ext, sym) else {
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
            };
            let s = sp.start_line.max(1);
            let e = sp.end_line.min(total_lines);
            let slice = (s..=e)
                .map(|ln| format!("{ln:5}: {}", all_lines[ln - 1]))
                .collect::<Vec<_>>()
                .join("\n");
            blocks.push(format!("## {} {} [L{s}-L{e}]\n{slice}", sp.kind, sp.qual,));
        }
        format!(
            "# READ `{label}` [{} AST symbol(s) of {total_lines} lines | {format_tag}]\n{}",
            blocks.len(),
            blocks.join("\n\n")
        )
    } else if let Some(ref jp) = cli.json_path {
        match crate::inspect::query_json_or_jsonl(&converted, jp) {
            Ok(out) => format!("# READ `{label}` [json-path='{jp}' | {format_tag}]\n{out}"),
            Err(e) => return Err((1, format!("[ap read] {e}"))),
        }
    } else if let Some(ref off_spec) = cli.offset {
        let mut offsets: Vec<usize> = Vec::new();
        for tok in off_spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match tok.parse::<usize>() {
                Ok(n) => offsets.push(n),
                Err(_) => {
                    return Err((
                        2,
                        format!("[ap read] invalid --offset `{tok}` (expected byte offset(s), e.g. 18000 or 18000,95000)"),
                    ));
                }
            }
        }
        if offsets.is_empty() {
            return Err((2, "[ap read] empty --offset value".to_string()));
        }
        if offsets.len() == 1 {
            let s = floor_boundary(&converted, offsets[0]);
            let e = ceil_boundary(&converted, s.saturating_add(cli.chars.max(120)));
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
                let e = ceil_boundary(&converted, s.saturating_add(cli.chars.max(120)));
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
                let slice = (s..=e)
                    .map(|ln| format!("{ln:5}: {}", all_lines[ln - 1]))
                    .collect::<Vec<_>>()
                    .join("\n");
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
                let slice = (s..=e)
                    .map(|ln| format!("{ln:5}: {}", all_lines[ln - 1]))
                    .collect::<Vec<_>>()
                    .join("\n");
                blocks.push(format!("## L{s}-L{e}\n{slice}"));
            }
            format!(
                "# READ `{label}` [batch {} line window(s) of {total_lines} | {format_tag}]\n{}",
                blocks.len(),
                blocks.join("\n\n")
            )
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
            let mut hits = Vec::new();
            for m in q_re.find_iter(&converted).take(12) {
                let s = floor_boundary(&converted, m.start().saturating_sub(200));
                let e = ceil_boundary(&converted, m.end().saturating_add(240));
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
            let q_low = q.to_ascii_lowercase();
            let mut hits = Vec::new();
            for (idx, ln) in all_lines.iter().enumerate() {
                if ln.to_ascii_lowercase().contains(&q_low) {
                    let s = idx.saturating_sub(1);
                    let e = (idx + 1).min(total_lines.saturating_sub(1));
                    let ctx = (s..=e)
                        .map(|k| format!("  {}: {}", k + 1, all_lines[k]))
                        .collect::<Vec<_>>()
                        .join("\n");
                    hits.push(ctx);
                    if hits.len() >= 25 {
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
    } else if converted.len() > cli.max_chars {
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
            .map(|ln| format!("{ln:5}: {}", all_lines[ln - 1]))
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
