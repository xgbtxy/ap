use crate::read::{decode_any_bytes, extract_xlsx_sheets_raw};
use crate::stats::record_event_ex;
use clap::Parser;
use rusqlite::types::Value as SqlVal;
use rusqlite::{params_from_iter, Connection};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "query",
    about = "Run exact SQL joins & aggregations directly across .xlsx, GBK/UTF-8 .csv/.tsv & .json/.jsonl files (zero Python/DuckDB)"
)]
struct QueryCli {
    /// Input table bindings: `-f orders=sales.xlsx` or `--table bank.csv`
    #[arg(short = 'f', long = "file", visible_alias = "table", required = true)]
    files: Vec<String>,
    /// SQL query to execute (omit when passing `--schema` or `--stdin`)
    sql: Option<String>,
    /// Read SQL query from stdin (avoids PowerShell/shell quote escaping)
    #[arg(long)]
    stdin: bool,
    /// Inspect loaded table names, row counts & column schemas without running SQL
    #[arg(long)]
    schema: bool,
    /// Optional path to export full query result as clean UTF-8 CSV
    #[arg(long)]
    out: Option<String>,
    /// Maximum rows to print in stdout Markdown table
    #[arg(long, default_value_t = 80)]
    limit: usize,
    /// Emit structured JSON output
    #[arg(long)]
    json: bool,
}

fn sanitize_ident(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.trim().chars() {
        if ch.is_alphanumeric() || ch == '_' || ('\u{4E00}'..='\u{9FFF}').contains(&ch) {
            out.push(ch);
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }
    let had_leading_underscore = raw.trim().starts_with('_');
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "col".to_string()
    } else if had_leading_underscore {
        format!("_{trimmed}")
    } else if trimmed.chars().next().unwrap().is_ascii_digit() {
        format!("t_{trimmed}")
    } else {
        trimmed
    }
}

fn parse_cell_sql_val(raw: &str) -> SqlVal {
    let t = raw.trim();
    if t.is_empty()
        || t.eq_ignore_ascii_case("null")
        || t.eq_ignore_ascii_case("na")
        || t.eq_ignore_ascii_case("n/a")
    {
        return SqlVal::Null;
    }
    if let Ok(iv) = t.parse::<i64>() {
        return SqlVal::Integer(iv);
    }
    if let Ok(fv) = t.parse::<f64>() {
        if fv.is_finite() {
            return SqlVal::Real(fv);
        }
    }
    // Handle currency / comma-grouped numbers like "$1,250.50" or "¥3,200"
    let stripped = t.trim_start_matches(['$', '¥', '￥', '€']).replace(',', "");
    if !stripped.is_empty()
        && stripped != t
        && stripped
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
    {
        if let Ok(iv) = stripped.parse::<i64>() {
            return SqlVal::Integer(iv);
        }
        if let Ok(fv) = stripped.parse::<f64>() {
            if fv.is_finite() {
                return SqlVal::Real(fv);
            }
        }
    }
    SqlVal::Text(t.to_string())
}

fn load_rows_into_table(
    conn: &Connection,
    table_name: &str,
    headers: &[String],
    rows: &[Vec<String>],
) -> Result<(usize, Vec<String>), String> {
    let mut cols: Vec<String> = Vec::with_capacity(headers.len().max(1));
    let mut used = std::collections::HashSet::new();
    for (idx, h) in headers.iter().enumerate() {
        let base = if h.trim().is_empty() {
            format!("col_{}", idx + 1)
        } else {
            sanitize_ident(h)
        };
        let mut cand = base.clone();
        let mut suffix = 2usize;
        while !used.insert(cand.to_lowercase()) {
            cand = format!("{base}_{suffix}");
            suffix += 1;
        }
        cols.push(cand);
    }
    if cols.is_empty() {
        cols.push("col_1".to_string());
    }

    let col_defs = cols
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    if let Err(e) = conn.execute_batch(&format!(
        "BEGIN; DROP TABLE IF EXISTS \"{table_name}\"; CREATE TABLE \"{table_name}\" ({col_defs});"
    )) {
        let _ = conn.execute_batch("ROLLBACK;");
        return Err(format!("create table `{table_name}`: {e}"));
    }

    let placeholders = vec!["?"; cols.len()].join(", ");
    let insert_sql = format!("INSERT INTO \"{table_name}\" ({col_defs}) VALUES ({placeholders})");
    let mut stmt = match conn.prepare(&insert_sql) {
        Ok(s) => s,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(format!("prepare insert `{table_name}`: {e}"));
        }
    };

    let mut inserted = 0usize;
    for r in rows {
        if r.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        let mut vals: Vec<SqlVal> = Vec::with_capacity(cols.len());
        for ci in 0..cols.len() {
            let s = r.get(ci).map(String::as_str).unwrap_or("");
            vals.push(parse_cell_sql_val(s));
        }
        if let Err(e) = stmt.execute(params_from_iter(vals)) {
            drop(stmt);
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(format!("insert row in `{table_name}`: {e}"));
        }
        inserted += 1;
    }
    drop(stmt);
    if let Err(e) = conn.execute_batch("COMMIT;") {
        let _ = conn.execute_batch("ROLLBACK;");
        return Err(format!("commit table `{table_name}`: {e}"));
    }
    Ok((inserted, cols))
}

fn load_csv_or_tsv(
    conn: &Connection,
    alias: &str,
    text: &str,
    delim: u8,
) -> Result<(usize, Vec<String>), String> {
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .has_headers(true)
        .from_reader(text.as_bytes());
    let hdr_rec = rdr
        .headers()
        .map_err(|e| format!("csv header error: {e}"))?
        .clone();
    let headers: Vec<String> = hdr_rec.iter().map(|s| s.trim().to_string()).collect();
    let mut rows = Vec::new();
    for rec in rdr.records().flatten() {
        rows.push(rec.iter().map(|s| s.to_string()).collect());
    }
    load_rows_into_table(conn, alias, &headers, &rows)
}

fn load_json_or_jsonl(
    conn: &Connection,
    alias: &str,
    text: &str,
) -> Result<(usize, Vec<String>), String> {
    let mut objs: Vec<serde_json::Map<String, Value>> = Vec::new();
    if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(text.trim()) {
        for it in arr {
            if let Value::Object(m) = it {
                objs.push(m);
            }
        }
    } else {
        for ln in text.lines() {
            if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(ln.trim()) {
                objs.push(m);
            }
        }
    }
    let mut col_order: Vec<String> = Vec::new();
    for m in &objs {
        for k in m.keys() {
            if !col_order.contains(k) {
                col_order.push(k.clone());
            }
        }
    }
    let mut rows = Vec::with_capacity(objs.len());
    for m in &objs {
        let mut r = Vec::with_capacity(col_order.len());
        for k in &col_order {
            let cell = match m.get(k) {
                None | Some(Value::Null) => String::new(),
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
            };
            r.push(cell);
        }
        rows.push(r);
    }
    load_rows_into_table(conn, alias, &col_order, &rows)
}

pub fn is_sqlite_magic(p: &Path) -> bool {
    use std::io::Read;
    let mut hdr = [0u8; 16];
    fs::File::open(p)
        .and_then(|mut f| f.read_exact(&mut hdr))
        .map(|_| &hdr == b"SQLite format 3\0")
        .unwrap_or(false)
}

fn attach_sqlite_db(
    conn: &Connection,
    alias: &str,
    p: &Path,
    path_str: &str,
    schema_info: &mut Vec<Value>,
) -> Result<(), String> {
    let canon = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let clean_p = canon
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('\'', "''");
    conn.execute_batch(&format!("ATTACH DATABASE '{clean_p}' AS \"{alias}\";"))
        .map_err(|e| format!("attach sqlite `{path_str}`: {e}"))?;

    let mut tbl_stmt = conn
        .prepare(&format!(
            "SELECT name FROM \"{alias}\".sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ))
        .map_err(|e| format!("inspect sqlite_master: {e}"))?;
    let tbl_names: Vec<String> = tbl_stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .flatten()
        .collect();

    for tbl in tbl_names {
        let q_tbl = tbl.replace('"', "\"\"");
        let row_cnt: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM \"{alias}\".\"{q_tbl}\""),
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let mut col_stmt = conn
            .prepare(&format!("PRAGMA \"{alias}\".table_info(\"{q_tbl}\")"))
            .map_err(|e| e.to_string())?;
        let cols: Vec<String> = col_stmt
            .query_map([], |r| r.get::<_, String>(1))
            .map_err(|e| e.to_string())?
            .flatten()
            .collect();

        let safe_tbl = sanitize_ident(&tbl);
        let sub_view = format!("{alias}__{safe_tbl}");
        let _ = conn.execute_batch(&format!(
            "CREATE TEMP VIEW IF NOT EXISTS \"{sub_view}\" AS SELECT * FROM \"{alias}\".\"{q_tbl}\";
             CREATE TEMP VIEW IF NOT EXISTS \"{safe_tbl}\" AS SELECT * FROM \"{alias}\".\"{q_tbl}\";"
        ));
        schema_info.push(json!({
            "table": safe_tbl,
            "qualified": format!("{alias}.{tbl}"),
            "source": format!("{path_str} [sqlite:{tbl}]"),
            "rows": row_cnt,
            "columns": cols,
        }));
    }
    Ok(())
}

fn format_clean_real(v: f64) -> String {
    if !v.is_finite() {
        return v.to_string();
    }
    if (v - v.round()).abs() < 1e-9 {
        return format!("{:.1}", v.round());
    }
    if v.abs() < 1e12 {
        let r6 = (v * 1_000_000.0).round() / 1_000_000.0;
        if (v - r6).abs() < 1e-9 * v.abs().max(1.0) {
            let s = format!("{r6:.6}");
            return s.trim_end_matches('0').trim_end_matches('.').to_string();
        }
    }
    v.to_string()
}

fn emit_query_err(as_json: bool, t0: Instant, msg: &str) {
    record_event_ex(
        "query",
        0,
        0,
        0,
        0,
        "query-err",
        false,
        t0.elapsed().as_millis() as u64,
        Some(msg),
    );
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "ok": false, "error": msg })).unwrap_or_default()
        );
    } else {
        eprintln!("{msg}");
    }
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match QueryCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    let t0 = Instant::now();
    let Ok(conn) = Connection::open_in_memory() else {
        emit_query_err(
            cli.json,
            t0,
            "[ap query] failed to initialize in-memory SQLite engine",
        );
        return 1;
    };

    let mut schema_info = Vec::new();
    let mut win_heals = 0u32;
    let mut total_raw_bytes = 0u64;

    for spec in &cli.files {
        let (alias_raw, path_str) = match spec.split_once('=') {
            Some((a, p)) if !a.trim().is_empty() => {
                let norm_p = crate::ls::normalize_cli_path(p);
                if Path::new(&norm_p).exists() {
                    (a.trim().to_string(), norm_p)
                } else {
                    let norm_full = crate::ls::normalize_cli_path(spec);
                    let pf = Path::new(&norm_full);
                    let stem = pf.file_stem().and_then(|s| s.to_str()).unwrap_or("tbl");
                    (sanitize_ident(stem), norm_full)
                }
            }
            _ => {
                let norm_full = crate::ls::normalize_cli_path(spec);
                let p = Path::new(&norm_full);
                let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("tbl");
                (sanitize_ident(stem), norm_full)
            }
        };
        let alias = sanitize_ident(&alias_raw);
        let p = Path::new(&path_str);
        if !p.is_file() {
            emit_query_err(
                cli.json,
                t0,
                &format!("[ap query] file not found: {path_str}"),
            );
            return 1;
        }
        let ext = p
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if matches!(ext.as_str(), "sqlite" | "db" | "sqlite3") || is_sqlite_magic(p) {
            total_raw_bytes += fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            if let Err(e) = attach_sqlite_db(&conn, &alias, p, &path_str, &mut schema_info) {
                emit_query_err(cli.json, t0, &format!("[ap query] {path_str}: {e}"));
                return 1;
            }
            continue;
        }

        let Ok(bytes) = fs::read(p) else {
            emit_query_err(
                cli.json,
                t0,
                &format!("[ap query] failed to read: {path_str}"),
            );
            return 1;
        };
        total_raw_bytes += bytes.len() as u64;

        if ext == "xlsx" {
            let sheets = match extract_xlsx_sheets_raw(&bytes) {
                Ok(s) => s,
                Err(e) => {
                    emit_query_err(cli.json, t0, &format!("[ap query] {path_str}: {e}"));
                    return 1;
                }
            };
            let mut primary_bound = false;
            let mut primary_headers: Vec<String> = Vec::new();
            let mut union_rows: Vec<Vec<String>> = Vec::new();
            let mut union_sheets = 0usize;
            for (sname, srows) in sheets {
                if srows.is_empty() {
                    continue;
                }
                let headers = &srows[0];
                let body = &srows[1..];
                if !primary_bound {
                    match load_rows_into_table(&conn, &alias, headers, body) {
                        Ok((cnt, cols)) => {
                            schema_info.push(json!({"table": alias, "source": format!("{path_str} [{sname}]"), "rows": cnt, "columns": cols}));
                            primary_headers = headers.clone();
                            primary_bound = true;
                        }
                        Err(e) => {
                            emit_query_err(cli.json, t0, &format!("[ap query] {e}"));
                            return 1;
                        }
                    }
                }
                if headers == &primary_headers && !primary_headers.is_empty() {
                    union_sheets += 1;
                    for r in body {
                        let mut ur = Vec::with_capacity(primary_headers.len() + 1);
                        for ci in 0..primary_headers.len() {
                            ur.push(r.get(ci).cloned().unwrap_or_default());
                        }
                        ur.push(sname.clone());
                        union_rows.push(ur);
                    }
                }
                let sub_tbl = format!("{alias}__{}", sanitize_ident(&sname));
                if sub_tbl != alias {
                    if let Ok((cnt, cols)) = load_rows_into_table(&conn, &sub_tbl, headers, body) {
                        schema_info.push(json!({"table": sub_tbl, "source": format!("{path_str} [{sname}]"), "rows": cnt, "columns": cols}));
                    }
                }
            }
            if union_sheets >= 2 {
                let mut u_headers = primary_headers;
                u_headers.push("_sheet".to_string());
                let all_tbl = format!("{alias}__all");
                if let Ok((cnt, cols)) =
                    load_rows_into_table(&conn, &all_tbl, &u_headers, &union_rows)
                {
                    schema_info.push(json!({"table": all_tbl, "source": format!("{path_str} [ALL {union_sheets} SHEETS]"), "rows": cnt, "columns": cols}));
                }
            }
        } else {
            let (decoded, _, healed) = decode_any_bytes(&bytes);
            win_heals += healed;
            let res = match ext.as_str() {
                "tsv" => load_csv_or_tsv(&conn, &alias, &decoded, b'\t'),
                "json" | "jsonl" => load_json_or_jsonl(&conn, &alias, &decoded),
                _ => load_csv_or_tsv(&conn, &alias, &decoded, b','),
            };
            match res {
                Ok((cnt, cols)) => {
                    schema_info.push(
                        json!({"table": alias, "source": path_str, "rows": cnt, "columns": cols}),
                    );
                }
                Err(e) => {
                    emit_query_err(cli.json, t0, &format!("[ap query] {path_str}: {e}"));
                    return 1;
                }
            }
        }
    }

    let resolved_sql = if cli.stdin || cli.sql.as_deref() == Some("-") {
        use std::io::Read;
        let mut buf = String::new();
        let _ = std::io::stdin().read_to_string(&mut buf);
        buf
    } else {
        cli.sql.clone().unwrap_or_default()
    };

    if cli.schema || resolved_sql.trim().is_empty() {
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&schema_info).unwrap_or_default()
            );
        } else {
            println!("# SQL TABLES READY (SQLite 3.46+ w/ JOIN, GROUP BY, CTE & Window Functions)");
            for t in &schema_info {
                println!(
                    "- Table `{}` ({} rows from `{}`): columns = {:?}",
                    t["table"].as_str().unwrap_or(""),
                    t["rows"].as_u64().unwrap_or(0),
                    t["source"].as_str().unwrap_or(""),
                    t["columns"]
                );
            }
        }
        return 0;
    }

    let sql_str = resolved_sql.trim();
    let mut stmt = match conn.prepare(sql_str) {
        Ok(s) => s,
        Err(e) => {
            emit_query_err(
                cli.json,
                t0,
                &format!("[ap query] SQL syntax/schema error: {e}\nLoaded tables: {schema_info:?}"),
            );
            return 1;
        }
    };
    let col_names: Vec<String> = stmt.column_names().map(String::from).collect();
    let ncols = col_names.len();

    let mut result_rows: Vec<Vec<String>> = Vec::new();
    let mut rows_iter = match stmt.query([]) {
        Ok(r) => r,
        Err(e) => {
            emit_query_err(
                cli.json,
                t0,
                &format!("[ap query] SQL execution error: {e}"),
            );
            return 1;
        }
    };
    while let Ok(Some(row)) = rows_iter.next() {
        let mut r = Vec::with_capacity(ncols);
        for i in 0..ncols {
            let cell = match row.get_ref(i) {
                Ok(rusqlite::types::ValueRef::Null) | Err(_) => String::new(),
                Ok(rusqlite::types::ValueRef::Integer(v)) => v.to_string(),
                Ok(rusqlite::types::ValueRef::Real(v)) => format_clean_real(v),
                Ok(rusqlite::types::ValueRef::Text(b)) => String::from_utf8_lossy(b).to_string(),
                Ok(rusqlite::types::ValueRef::Blob(b)) => format!("<{}B blob>", b.len()),
            };
            r.push(cell);
        }
        result_rows.push(r);
    }

    if let Some(ref out_p) = cli.out {
        let norm_out = crate::ls::normalize_cli_path(out_p);
        let write_res: Result<(), String> = (|| {
            let mut wtr = csv::Writer::from_path(&norm_out).map_err(|e| e.to_string())?;
            wtr.write_record(&col_names).map_err(|e| e.to_string())?;
            for r in &result_rows {
                wtr.write_record(r).map_err(|e| e.to_string())?;
            }
            wtr.flush().map_err(|e| e.to_string())
        })();
        if let Err(e) = write_res {
            emit_query_err(
                cli.json,
                t0,
                &format!("[ap query] failed to write --out `{out_p}`: {e}"),
            );
            return 1;
        }
    }

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
    let mut md_lines = vec![format!(
        "# SQL QUERY RESULT ({} row(s) in {elapsed_ms}ms)",
        result_rows.len()
    )];
    if !col_names.is_empty() {
        md_lines.push(format!("| {} |", col_names.join(" | ")));
        md_lines.push(format!("| {} |", vec!["---"; ncols].join(" | ")));
        for r in result_rows.iter().take(cli.limit) {
            let esc: Vec<String> = r
                .iter()
                .map(|c| c.replace('|', "\\|").replace('\n', " "))
                .collect();
            md_lines.push(format!("| {} |", esc.join(" | ")));
        }
        if result_rows.len() > cli.limit {
            md_lines.push(format!(
                "... ({} more rows — pass `--limit N` or `--out result.csv`)",
                result_rows.len() - cli.limit
            ));
        }
    }
    let rendered = md_lines.join("\n");
    record_event_ex(
        "query",
        total_raw_bytes,
        rendered.len() as u64,
        win_heals,
        1,
        "sql-query",
        true,
        t0.elapsed().as_millis() as u64,
        None,
    );

    if cli.json {
        let records: Vec<serde_json::Map<String, Value>> = result_rows
            .iter()
            .take(cli.limit)
            .map(|r| {
                let mut m = serde_json::Map::new();
                for (i, col) in col_names.iter().enumerate() {
                    let s = r.get(i).map(String::as_str).unwrap_or("");
                    let v = if s.is_empty() {
                        Value::Null
                    } else if let Ok(iv) = s.parse::<i64>() {
                        json!(iv)
                    } else if let Ok(fv) = s.parse::<f64>() {
                        if fv.is_finite() {
                            json!(fv)
                        } else {
                            Value::String(s.to_string())
                        }
                    } else {
                        Value::String(s.to_string())
                    };
                    m.insert(col.clone(), v);
                }
                m
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "elapsed_ms": elapsed_ms,
                "row_count": result_rows.len(),
                "columns": col_names,
                "rows": result_rows.iter().take(cli.limit).collect::<Vec<_>>(),
                "records": records,
            }))
            .unwrap_or_default()
        );
    } else {
        println!("{rendered}");
    }
    0
}
