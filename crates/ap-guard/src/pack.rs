use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackIssue {
    pub severity: String,
    pub kind: String,
    pub file: String,
    pub detail: String,
}

struct PackRegexes {
    sha_pair: Regex,
    short_sha: Regex,
    abs_user_path: Regex,
    secret_ak: Regex,
}

fn pre() -> &'static PackRegexes {
    static R: OnceLock<PackRegexes> = OnceLock::new();
    R.get_or_init(|| PackRegexes {
        // Matches lines listing a relative path alongside a 64-hex sha256 (e.g. `evidence/out.log  <64hex>` or `"sha256": "<64hex>"`)
        sha_pair: Regex::new(
            r#"(?i)([A-Za-z0-9_./-]+\.[A-Za-z0-9]{1,8})[\s:`"|,=-]+([0-9a-f]{64})\b|\b([0-9a-f]{64})[\s:`"|,=-]+([A-Za-z0-9_./-]+\.[A-Za-z0-9]{1,8})"#,
        )
        .unwrap(),
        short_sha: Regex::new(r#"(?i)\bsha-?256\s*[:=]\s*`?([0-9a-f]{8,63})\b"#).unwrap(),
        abs_user_path: Regex::new(
            r#"(?i)(?:[A-Z]:\\Users\\[^\\\s"'`]+\\Downloads\\|/Users/[^/\s"'`]+/Downloads/|/home/[^/\s"'`]+/Downloads/)"#,
        )
        .unwrap(),
        secret_ak: Regex::new(
            r#"(?i)(?:AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36})\b)"#,
        )
        .unwrap(),
    })
}

fn sha256_file(p: &Path) -> Option<String> {
    let b = fs::read(p).ok()?;
    let mut h = Sha256::new();
    h.update(&b);
    let dig = h.finalize();
    let mut s = String::with_capacity(64);
    for byte in dig {
        s.push_str(&format!("{byte:02x}"));
    }
    Some(s)
}

fn walk_bundle_files(dir: &Path, depth: usize, out: &mut Vec<std::path::PathBuf>) {
    if depth > 6 || out.len() >= 500 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let p = ent.path();
        let Ok(ft) = ent.file_type() else {
            continue;
        };
        if ft.is_dir() {
            let nm = ent.file_name().to_string_lossy().to_string();
            if matches!(nm.as_str(), ".git" | "node_modules" | "__pycache__") {
                continue;
            }
            walk_bundle_files(&p, depth + 1, out);
        } else if ft.is_file() {
            out.push(p);
        }
    }
}

/// Deterministic deliverable/evidence bundle hygiene & SHA-256 manifest verifier (exit 2 on any defect).
pub fn run_pack_audit(
    dir: &Path,
    max_lines: Option<usize>,
    required_headers: &[String],
    as_json: bool,
) -> i32 {
    if !dir.is_dir() {
        crate::emit_err(
            as_json,
            &format!("[guard pack] directory not found: {}", dir.display()),
        );
        return 2;
    }
    let t0 = Instant::now();
    let rx = pre();
    let mut files = Vec::new();
    walk_bundle_files(dir, 0, &mut files);
    files.sort();

    let mut issues: Vec<PackIssue> = Vec::new();
    let mut verified_hashes = 0usize;
    let mut md_files_checked = 0usize;
    let mut header_seen: Vec<bool> = vec![false; required_headers.len()];

    for f in &files {
        let rel = f
            .strip_prefix(dir)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        let ext = f
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_text = matches!(
            ext.as_str(),
            "md" | "txt"
                | "json"
                | "jsonl"
                | "yaml"
                | "yml"
                | "toml"
                | "py"
                | "js"
                | "mjs"
                | "ts"
                | "sh"
                | "ps1"
                | "bat"
                | "cmd"
                | "log"
        );
        if !is_text {
            continue;
        }
        let Ok(content) = fs::read_to_string(f) else {
            continue;
        };

        // 1. Secret / private-key leak scan
        if let Some(m) = rx.secret_ak.find(&content) {
            let snip: String = m.as_str().chars().take(18).collect();
            issues.push(PackIssue {
                severity: "ERROR".into(),
                kind: "SECRET-LEAK".into(),
                file: rel.clone(),
                detail: format!("Potential secret/private-key material detected (`{snip}...`)"),
            });
        }

        // 2. Hardcoded user Downloads path leak scan (except explicit manifest header lines)
        for (lidx, ln) in content.lines().enumerate() {
            if rx.abs_user_path.is_match(ln) {
                issues.push(PackIssue {
                    severity: "ERROR".into(),
                    kind: "ABS-DOWNLOADS-PATH".into(),
                    file: format!("{rel}:L{}", lidx + 1),
                    detail:
                        "Hardcoded user Downloads absolute path found; use bundle-relative path"
                            .into(),
                });
                break;
            }
        }

        // 3. Markdown/JSON manifest checks
        if matches!(ext.as_str(), "md" | "txt" | "json") {
            if ext == "md" {
                md_files_checked += 1;
                for (hi, req_h) in required_headers.iter().enumerate() {
                    if content.lines().take(20).any(|l| l.contains(req_h.as_str())) {
                        header_seen[hi] = true;
                    }
                }
                if let Some(limit) = max_lines {
                    let non_empty = content.lines().filter(|l| !l.trim().is_empty()).count();
                    if non_empty > limit {
                        issues.push(PackIssue {
                            severity: "WARN".into(),
                            kind: "LINE-BUDGET".into(),
                            file: rel.clone(),
                            detail: format!(
                                "{non_empty} non-empty lines exceeds budget of {limit}"
                            ),
                        });
                    }
                }
            }

            // Detect truncated SHA-256 values (<64 hex chars)
            for cap in rx.short_sha.captures_iter(&content) {
                let h = &cap[1];
                if h.len() < 64 {
                    issues.push(PackIssue {
                        severity: "ERROR".into(),
                        kind: "TRUNCATED-SHA256".into(),
                        file: rel.clone(),
                        detail: format!(
                            "Truncated SHA-256 (`{h}`, {} hex chars; full 64-hex required)",
                            h.len()
                        ),
                    });
                }
            }

            // Verify every listed (relative_path, 64-hex sha256) pair against disk!
            for cap in rx.sha_pair.captures_iter(&content) {
                let (ref_path, expected_hex) = if let (Some(p), Some(h)) = (cap.get(1), cap.get(2))
                {
                    (p.as_str(), h.as_str().to_ascii_lowercase())
                } else if let (Some(h), Some(p)) = (cap.get(3), cap.get(4)) {
                    (p.as_str(), h.as_str().to_ascii_lowercase())
                } else {
                    continue;
                };
                if ref_path.starts_with("http://") || ref_path.starts_with("https://") {
                    continue;
                }
                let candidate = dir.join(ref_path.trim_start_matches("./"));
                if !candidate.is_file() {
                    issues.push(PackIssue {
                        severity: "ERROR".into(),
                        kind: "MISSING-ARTIFACT".into(),
                        file: rel.clone(),
                        detail: format!(
                            "Referenced artifact `{ref_path}` does not exist in bundle"
                        ),
                    });
                } else if let Some(actual) = sha256_file(&candidate) {
                    if actual != expected_hex {
                        issues.push(PackIssue {
                            severity: "ERROR".into(),
                            kind: "SHA256-MISMATCH".into(),
                            file: rel.clone(),
                            detail: format!(
                                "`{ref_path}` hash mismatch: manifest={} actual={}",
                                &expected_hex[..12],
                                &actual[..12]
                            ),
                        });
                    } else {
                        verified_hashes += 1;
                    }
                }
            }
        }
    }

    for (hi, req_h) in required_headers.iter().enumerate() {
        if !header_seen[hi] {
            issues.push(PackIssue {
                severity: "ERROR".into(),
                kind: "MISSING-HEADER".into(),
                file: dir.to_string_lossy().replace('\\', "/"),
                detail: format!("Required header `{req_h}` missing from bundle markdown headers"),
            });
        }
    }

    let err_count = issues.iter().filter(|i| i.severity == "ERROR").count();
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0).round();
    let ok = err_count == 0;

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": ok,
                "dir": dir.to_string_lossy(),
                "files_scanned": files.len(),
                "md_checked": md_files_checked,
                "verified_sha256": verified_hashes,
                "error_count": err_count,
                "elapsed_ms": elapsed_ms,
                "issues": issues,
            }))
            .unwrap_or_default()
        );
    } else if ok {
        println!(
            "[guard pack] PASS ({} files scanned, {} full SHA-256 verified, 0 hygiene errors | {}ms)",
            files.len(),
            verified_hashes,
            elapsed_ms
        );
    } else {
        eprintln!(
            "[guard pack | exit 2] FAILED ({err_count} error(s), {} verified hashes | {}ms):",
            verified_hashes, elapsed_ms
        );
        for iss in &issues {
            eprintln!(
                "  - [{} {}] {} — {}",
                iss.severity, iss.kind, iss.file, iss.detail
            );
        }
    }

    if ok {
        0
    } else {
        2
    }
}
