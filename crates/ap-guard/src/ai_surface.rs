use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSurfaceFinding {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub file: String,
    pub line: usize,
    pub symbol: String,
    pub snippet: String,
    pub guard_hint: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSurfaceReport {
    pub ok: bool,
    pub root: String,
    pub scanned_files: usize,
    pub elapsed_ms: f64,
    pub counts_by_category: BTreeMap<String, usize>,
    pub findings: Vec<AiSurfaceFinding>,
}

struct AiPatterns {
    mcp_shell_cmd: Regex,
    mcp_var_interp: Regex,
    mcp_url: Regex,
    ide_get_cfg: Regex,
    ide_exec_near: Regex,
    ide_cfg_write: Regex,
    auto_approve: Regex,
    tool_exec_sink: Regex,
    untrusted_var: Regex,
    md_html_true: Regex,
    mermaid_loose: Regex,
    webview_no_roots: Regex,
    raw_ipc_bridge: Regex,
    csp_permissive_img: Regex,
    prompt_sys: Regex,
    prompt_untrusted_cat: Regex,
}

fn ai_re() -> &'static AiPatterns {
    static R: OnceLock<AiPatterns> = OnceLock::new();
    R.get_or_init(|| AiPatterns {
        mcp_shell_cmd: Regex::new(
            r#"(?i)^(?:cmd(?:\.exe)?|sh|bash|zsh|powershell(?:\.exe)?|pwsh(?:\.exe)?|npx|uvx)$"#,
        )
        .unwrap(),
        mcp_var_interp: Regex::new(r#"\$\{(?:workspaceFolder|env:|input:|command:|userHome)[^}]*\}"#)
            .unwrap(),
        mcp_url: Regex::new(r#"^https?://"#).unwrap(),
        ide_get_cfg: Regex::new(r#"\bgetConfiguration\s*\("#).unwrap(),
        ide_exec_near: Regex::new(
            r#"\b(?:execSync|execFile|execFileSync|spawn|spawnSync|openExternal|child_process)\b"#,
        )
        .unwrap(),
        ide_cfg_write: Regex::new(
            r#"(?:\.vscode[/\\]settings\.json|\.code-workspace|\.mcp\.json|["']\$schema["']\s*:)"#,
        )
        .unwrap(),
        auto_approve: Regex::new(
            r#"(?i)(?:["']?(?:autoApprove|alwaysAllow|bypassPermissions|dangerouslySkipPermissions|trustAll|autoExecute)["']?\s*:\s*true|--dangerously-skip-permissions\b|--yolo\b|["']alwaysAllow["']\s*:\s*\[\s*["']\*["']\s*\])"#,
        )
        .unwrap(),
        tool_exec_sink: Regex::new(
            r#"\b(?:execSync|child_process\.exec|spawnSync|os\.system|subprocess\.(?:run|Popen|call)|eval|Function|writeFileSync)\s*\("#,
        )
        .unwrap(),
        untrusted_var: Regex::new(
            r#"(?i)\b(?:prompt|userInput|toolArgs|mcpResult|toolOutput|message\.content|response\.text|args\.command|fileContent|externalDoc|urlBody|fetchResult)\b"#,
        )
        .unwrap(),
        md_html_true: Regex::new(
            r#"(?i)(?:MarkdownIt\s*\([^)]*html\s*:\s*(?:true|!0)|markdown[-_]?it[^;\n]{0,80}html\s*:\s*(?:true|!0)|dangerouslySetInnerHTML)"#,
        )
        .unwrap(),
        mermaid_loose: Regex::new(
            r#"(?i)mermaid\.initialize\s*\([^)]*securityLevel\s*:\s*['"]loose['"]"#,
        )
        .unwrap(),
        webview_no_roots: Regex::new(r#"\benableScripts\s*:\s*true\b"#).unwrap(),
        raw_ipc_bridge: Regex::new(
            r#"\bcontextBridge\.exposeInMainWorld\s*\([^;\n]{0,200}ipcRenderer\.(?:send|invoke|on)"#,
        )
        .unwrap(),
        csp_permissive_img: Regex::new(r#"(?i)\bimg-src\s+(?:\*|https?:)"#).unwrap(),
        prompt_sys: Regex::new(
            r#"(?i)(?:role\s*:\s*['"]system['"]|\b(?:systemPrompt|SYSTEM_PROMPT|systemInstruction)\b)"#,
        )
        .unwrap(),
        prompt_untrusted_cat: Regex::new(
            r#"(?i)(?:\$\{[^}]*(?:fileContent|fetchResult|urlBody|toolOutput|externalDoc|mcpResult|userMessage|readme)[^}]*\}|\+\s*(?:fileContent|fetchResult|urlBody|toolOutput|externalDoc|mcpResult|userMessage)|f["'][^"']*\{(?:file_?content|fetch_?result|url_?body|tool_?output|external_?doc|mcp_?result|user_?message)\})"#,
        )
        .unwrap(),
    })
}

fn fnv1a_id(cat: &str, file: &str, line: usize, sym: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in format!("{cat}|{file}|{line}|{sym}").as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{cat}:{:08x}", (h ^ (h >> 32)) as u32)
}

fn clip(s: &str, max: usize) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max)
        .collect()
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "node_modules" | "target" | "__pycache__" | ".venv" | "venv" | ".tox"
    )
}

fn collect_target_files(dir: &Path, max_files: usize, out: &mut Vec<std::path::PathBuf>) {
    if out.len() >= max_files {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut subs = Vec::new();
    for entry in entries.flatten() {
        if out.len() >= max_files {
            break;
        }
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            if !should_skip_dir(&name) {
                subs.push(p);
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let name_low = name.to_ascii_lowercase();
        if name_low.ends_with(".d.ts") {
            continue;
        }
        let ext = p
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(
            ext.as_str(),
            "json"
                | "jsonc"
                | "yaml"
                | "yml"
                | "toml"
                | "js"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "jsx"
                | "py"
                | "go"
                | "rs"
                | "sh"
                | "ps1"
                | "md"
        ) {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if meta.len() > 2 * 1024 * 1024 || meta.len() == 0 {
                continue;
            }
        }
        out.push(p);
    }
    subs.sort();
    for sub in subs {
        if out.len() >= max_files {
            break;
        }
        collect_target_files(&sub, max_files, out);
    }
}

fn scan_mcp_json_config(rel: &str, raw: &str, out: &mut Vec<AiSurfaceFinding>) {
    let re = ai_re();
    let Ok(val) = serde_json::from_str::<Value>(raw) else {
        return;
    };
    let servers = val
        .get("mcpServers")
        .or_else(|| val.get("servers"))
        .and_then(Value::as_object);
    let Some(map) = servers else {
        return;
    };

    for (name, cfg) in map {
        let cmd = cfg
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let args: Vec<&str> = cfg
            .get("args")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let args_joined = args.join(" ");
        let cfg_str = cfg.to_string();

        if !cmd.is_empty()
            && (re.mcp_shell_cmd.is_match(cmd)
                || args
                    .iter()
                    .any(|a| matches!(*a, "-c" | "/c" | "-Command" | "-e")))
        {
            out.push(AiSurfaceFinding {
                id: fnv1a_id("MCP_CONFIG_EXEC", rel, 1, name),
                category: "MCP_CONFIG_EXEC".to_string(),
                severity: "HIGH".to_string(),
                file: rel.to_string(),
                line: 1,
                symbol: format!("mcp:{name}"),
                snippet: clip(&format!("{cmd} {args_joined}"), 140),
                guard_hint: "MCP_SHELL_EXEC".to_string(),
                remediation: "Pin an immutable executable path with explicit argv instead of invoking a shell/package runner.".to_string(),
            });
        }
        if re.mcp_var_interp.is_match(&cfg_str) {
            out.push(AiSurfaceFinding {
                id: fnv1a_id("MCP_CONFIG_EXEC", rel, 1, &format!("{name}:interp")),
                category: "MCP_CONFIG_EXEC".to_string(),
                severity: "HIGH".to_string(),
                file: rel.to_string(),
                line: 1,
                symbol: format!("mcp:{name}:interpolation"),
                snippet: clip(&cfg_str, 140),
                guard_hint: "MCP_WORKSPACE_INTERP".to_string(),
                remediation: "Avoid interpolating untrusted workspace variables (${workspaceFolder}/${env:...}) into MCP launch configs.".to_string(),
            });
        }
        if let Some(url) = cfg.get("url").and_then(Value::as_str).map(str::trim) {
            let low = url.to_ascii_lowercase();
            let is_local =
                low.starts_with("http://127.0.0.1") || low.starts_with("http://localhost");
            let has_auth = cfg.get("headers").is_some() || cfg.get("auth").is_some();
            if re.mcp_url.is_match(&low) && !is_local && (low.starts_with("http://") || !has_auth) {
                out.push(AiSurfaceFinding {
                    id: fnv1a_id("MCP_CONFIG_EXEC", rel, 1, &format!("{name}:url")),
                    category: "MCP_CONFIG_EXEC".to_string(),
                    severity: "MEDIUM".to_string(),
                    file: rel.to_string(),
                    line: 1,
                    symbol: format!("mcp:{name}:remote_url"),
                    snippet: clip(url, 140),
                    guard_hint: "MCP_REMOTE_NO_AUTH_OR_TLS".to_string(),
                    remediation: "Enforce HTTPS and explicit authentication headers on non-localhost remote MCP endpoints.".to_string(),
                });
            }
        }
    }
}

fn scan_ide_package_json(rel: &str, raw: &str, out: &mut Vec<AiSurfaceFinding>) {
    let Ok(val) = serde_json::from_str::<Value>(raw) else {
        return;
    };
    let restricted_list: HashSet<String> = val
        .pointer("/capabilities/untrustedWorkspaces/restrictedConfigurations")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    if val
        .pointer("/capabilities/untrustedWorkspaces/supported")
        .and_then(Value::as_bool)
        == Some(true)
    {
        out.push(AiSurfaceFinding {
            id: fnv1a_id("IDE_WORKSPACE_TRUST_BYPASS", rel, 1, "untrustedWorkspaces"),
            category: "IDE_WORKSPACE_TRUST_BYPASS".to_string(),
            severity: "MEDIUM".to_string(),
            file: rel.to_string(),
            line: 1,
            symbol: "capabilities.untrustedWorkspaces.supported".to_string(),
            snippet: "capabilities.untrustedWorkspaces.supported = true".to_string(),
            guard_hint: "UNTRUSTED_WORKSPACES_ON".to_string(),
            remediation: "Restrict sensitive execution/path configuration keys when untrustedWorkspaces is enabled.".to_string(),
        });
    }

    let dangerous_key_kws = [
        "path", "bin", "exe", "exec", "command", "cmd", "runtime", "python", "node", "java", "sdk",
        "proxy", "hook", "shell", "linter", "lsp", "server", "schema",
    ];
    let mut cfg_nodes = Vec::new();
    if let Some(c) = val.pointer("/contributes/configuration") {
        if let Some(arr) = c.as_array() {
            cfg_nodes.extend(arr.iter());
        } else {
            cfg_nodes.push(c);
        }
    }
    for cfg in cfg_nodes {
        let Some(props) = cfg.get("properties").and_then(Value::as_object) else {
            continue;
        };
        for (key, prop) in props {
            let k_low = key.to_ascii_lowercase();
            if !dangerous_key_kws.iter().any(|kw| k_low.contains(kw)) {
                continue;
            }
            let scope = prop
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or("window");
            let restricted = prop
                .get("restricted")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if matches!(scope, "application" | "machine")
                || restricted
                || restricted_list.contains(key)
            {
                continue;
            }
            out.push(AiSurfaceFinding {
                id: fnv1a_id("IDE_WORKSPACE_TRUST_BYPASS", rel, 1, key),
                category: "IDE_WORKSPACE_TRUST_BYPASS".to_string(),
                severity: "HIGH".to_string(),
                file: rel.to_string(),
                line: 1,
                symbol: key.clone(),
                snippet: format!("{key} (scope={scope}, restricted=false)"),
                guard_hint: "UNRESTRICTED_WORKSPACE_SETTING".to_string(),
                remediation: "Set `scope: \"machine\"` or `restricted: true` and list in `restrictedConfigurations`.".to_string(),
            });
        }
    }
}

fn scan_code_and_config_lines(rel: &str, raw: &str, out: &mut Vec<AiSurfaceFinding>) {
    let re = ai_re();
    let lines: Vec<&str> = raw.lines().collect();
    let raw_low = raw.to_ascii_lowercase();

    for (idx, &ln) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let trimmed = ln.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        if re.ide_get_cfg.is_match(ln) {
            let hi = (idx + 12).min(lines.len());
            let win = lines[idx..hi].join(" ");
            if re.ide_exec_near.is_match(&win) {
                out.push(AiSurfaceFinding {
                    id: fnv1a_id("IDE_WORKSPACE_TRUST_BYPASS", rel, line_no, "getConfigExec"),
                    category: "IDE_WORKSPACE_TRUST_BYPASS".to_string(),
                    severity: "HIGH".to_string(),
                    file: rel.to_string(),
                    line: line_no,
                    symbol: "getConfiguration->exec".to_string(),
                    snippet: clip(trimmed, 140),
                    guard_hint: "IDE_CONFIG_TO_EXEC".to_string(),
                    remediation: "Validate workspace trust (`vscode.workspace.isTrusted`) and canonicalize setting paths before spawning processes.".to_string(),
                });
            }
        }
        if re.ide_cfg_write.is_match(ln)
            && (ln.contains("write")
                || ln.contains("fs.")
                || ln.contains("open(")
                || ln.contains("$schema"))
        {
            out.push(AiSurfaceFinding {
                id: fnv1a_id("IDE_WORKSPACE_TRUST_BYPASS", rel, line_no, "ideCfgWrite"),
                category: "IDE_WORKSPACE_TRUST_BYPASS".to_string(),
                severity: "MEDIUM".to_string(),
                file: rel.to_string(),
                line: line_no,
                symbol: "ide_config_target".to_string(),
                snippet: clip(trimmed, 140),
                guard_hint: "IDE_CONFIG_WRITE_SURFACE".to_string(),
                remediation: "Protect `.vscode/settings.json`, `.code-workspace`, `.mcp.json`, and remote `$schema` paths from untrusted writes.".to_string(),
            });
        }

        if re.auto_approve.is_match(ln) {
            out.push(AiSurfaceFinding {
                id: fnv1a_id("AGENT_AUTO_APPROVE_OR_TOOL_SINK", rel, line_no, "autoApprove"),
                category: "AGENT_AUTO_APPROVE_OR_TOOL_SINK".to_string(),
                severity: "HIGH".to_string(),
                file: rel.to_string(),
                line: line_no,
                symbol: "autoApprove".to_string(),
                snippet: clip(trimmed, 140),
                guard_hint: "AUTO_APPROVE_BYPASS".to_string(),
                remediation: "Require explicit per-tool approval for shell, filesystem write, and network actions.".to_string(),
            });
        }

        if re.tool_exec_sink.is_match(ln) && re.untrusted_var.is_match(ln) {
            out.push(AiSurfaceFinding {
                id: fnv1a_id("AGENT_AUTO_APPROVE_OR_TOOL_SINK", rel, line_no, "toolSink"),
                category: "AGENT_AUTO_APPROVE_OR_TOOL_SINK".to_string(),
                severity: "HIGH".to_string(),
                file: rel.to_string(),
                line: line_no,
                symbol: "untrusted_var->tool_sink".to_string(),
                snippet: clip(trimmed, 140),
                guard_hint: "PARAM_TAINTED".to_string(),
                remediation: "Do not pass untrusted prompt/tool outputs into shell-invoking or file-writing primitives without strict allowlisting.".to_string(),
            });
        }

        if re.md_html_true.is_match(ln)
            || re.mermaid_loose.is_match(ln)
            || re.raw_ipc_bridge.is_match(ln)
            || re.csp_permissive_img.is_match(ln)
        {
            out.push(AiSurfaceFinding {
                id: fnv1a_id("AI_MARKDOWN_WEBVIEW_EXFIL", rel, line_no, "mdWebview"),
                category: "AI_MARKDOWN_WEBVIEW_EXFIL".to_string(),
                severity: "HIGH".to_string(),
                file: rel.to_string(),
                line: line_no,
                symbol: "webview_or_markdown_sink".to_string(),
                snippet: clip(trimmed, 140),
                guard_hint: "UNSANITIZED_RENDER_OR_EXFIL".to_string(),
                remediation: "Disable raw HTML in markdown (`html: false`), set Mermaid `securityLevel: 'strict'`, and enforce strict CSP `img-src`.".to_string(),
            });
        }
        if re.webview_no_roots.is_match(ln) && !raw_low.contains("localresourceroots") {
            out.push(AiSurfaceFinding {
                id: fnv1a_id("AI_MARKDOWN_WEBVIEW_EXFIL", rel, line_no, "enableScripts"),
                category: "AI_MARKDOWN_WEBVIEW_EXFIL".to_string(),
                severity: "MEDIUM".to_string(),
                file: rel.to_string(),
                line: line_no,
                symbol: "enableScripts_without_localResourceRoots".to_string(),
                snippet: clip(trimmed, 140),
                guard_hint: "WEBVIEW_NO_LOCAL_ROOTS".to_string(),
                remediation: "Bind `localResourceRoots` and a nonce-guarded CSP whenever `enableScripts: true` is enabled.".to_string(),
            });
        }

        if re.prompt_sys.is_match(ln) {
            let hi = (idx + 5).min(lines.len());
            let win = lines[idx..hi].join(" ");
            let win_low = win.to_ascii_lowercase();
            let has_delimiter = win_low.contains("scrub")
                || win_low.contains("sanitize")
                || win_low.contains("escape")
                || win_low.contains("delimiter")
                || win_low.contains("untrusted");
            if re.prompt_untrusted_cat.is_match(&win) && !has_delimiter {
                out.push(AiSurfaceFinding {
                    id: fnv1a_id("PROMPT_BOUNDARY_HYGIENE", rel, line_no, "sysPromptCat"),
                    category: "PROMPT_BOUNDARY_HYGIENE".to_string(),
                    severity: "MEDIUM".to_string(),
                    file: rel.to_string(),
                    line: line_no,
                    symbol: "system_prompt_untrusted_concat".to_string(),
                    snippet: clip(trimmed, 140),
                    guard_hint: "UNTRUSTED_SYSTEM_PROMPT_JOIN".to_string(),
                    remediation: "Isolate untrusted external content in user/tool messages with explicit delimiters rather than raw system-prompt interpolation.".to_string(),
                });
            }
        }
    }
}

/// Pure-Rust `<50ms` AI-agent, IDE extension, and MCP trust-boundary security-surface auditor.
pub fn scan_ai_surface(root: &Path, max_files: usize) -> AiSurfaceReport {
    let t0 = Instant::now();
    let mut files = Vec::new();
    let cap = max_files.clamp(1, 4000);
    if root.is_file() {
        files.push(root.to_path_buf());
    } else if root.is_dir() {
        collect_target_files(root, cap, &mut files);
    }

    let mut raw_findings: Vec<AiSurfaceFinding> = Vec::new();
    let mut scanned = 0usize;
    for fp in &files {
        let Ok(raw) = fs::read_to_string(fp) else {
            continue;
        };
        scanned += 1;
        let rel = if root.is_file() {
            fp.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("file")
                .to_string()
        } else {
            fp.strip_prefix(root)
                .unwrap_or(fp)
                .to_string_lossy()
                .replace('\\', "/")
        };
        let rel_low = rel.to_ascii_lowercase();
        let file_name = fp
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if file_name.ends_with(".json")
            && (file_name.contains("mcp") || file_name == "claude_desktop_config.json")
        {
            scan_mcp_json_config(&rel, &raw, &mut raw_findings);
        } else if file_name == "package.json" && !rel_low.contains("node_modules/") {
            scan_ide_package_json(&rel, &raw, &mut raw_findings);
        }
        scan_code_and_config_lines(&rel, &raw, &mut raw_findings);
    }

    let mut seen_ids = HashSet::new();
    raw_findings.retain(|f| seen_ids.insert(f.id.clone()));
    raw_findings.sort_by(|a, b| {
        let sev_rank = |s: &str| match s {
            "HIGH" => 0u8,
            "MEDIUM" => 1u8,
            _ => 2u8,
        };
        sev_rank(&a.severity)
            .cmp(&sev_rank(&b.severity))
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
    raw_findings.truncate(120);

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in &raw_findings {
        *counts.entry(f.category.clone()).or_insert(0) += 1;
    }

    AiSurfaceReport {
        ok: raw_findings.is_empty(),
        root: root.display().to_string(),
        scanned_files: scanned,
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
        counts_by_category: counts,
        findings: raw_findings,
    }
}

pub fn render_ai_surface_md(rep: &AiSurfaceReport) -> String {
    let mut out = vec![format!(
        "# AI / IDE / MCP SECURITY SURFACE `{}` ({} finding(s) across {} file(s) in {}ms)",
        rep.root,
        rep.findings.len(),
        rep.scanned_files,
        rep.elapsed_ms
    )];
    if !rep.counts_by_category.is_empty() {
        let cats: Vec<String> = rep
            .counts_by_category
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        out.push(format!("Categories: {}", cats.join(", ")));
    }
    if rep.findings.is_empty() {
        out.push("*(no AI/IDE/MCP security-boundary findings detected)*".to_string());
    } else {
        for f in rep.findings.iter().take(40) {
            out.push(format!(
                "- [{}] `{}` `{}:L{}` (`{}`): `{}`",
                f.severity, f.category, f.file, f.line, f.symbol, f.snippet
            ));
        }
    }
    format!("{}\n", out.join("\n"))
}

pub fn run_ai_surface_cli(root: &Path, max_files: usize, as_json: bool) -> i32 {
    if !root.exists() {
        crate::emit_err(
            as_json,
            &format!("[guard ai-surface] path not found: {}", root.display()),
        );
        return 1;
    }
    let rep = scan_ai_surface(root, max_files);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "clean": rep.ok,
                "mode": "ai_surface",
                "root": rep.root,
                "scanned_files": rep.scanned_files,
                "elapsed_ms": rep.elapsed_ms,
                "counts_by_category": rep.counts_by_category,
                "findings": rep.findings,
            }))
            .unwrap_or_default()
        );
    } else {
        print!("{}", render_ai_surface_md(&rep));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_mcp_ide_trust_auto_approve_webview_and_prompt_boundaries() {
        let dir = std::env::temp_dir().join(format!("ap_ai_surf_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(
            dir.join(".mcp.json"),
            r#"{"mcpServers":{"runner":{"command":"bash","args":["-c","echo ${workspaceFolder}"]},"remote":{"url":"http://api.example.invalid/sse"}}}"#,
        )
        .unwrap();
        fs::write(
            dir.join("package.json"),
            r#"{"name":"ext","capabilities":{"untrustedWorkspaces":{"supported":true}},"contributes":{"configuration":{"properties":{"demo.cliPath":{"type":"string"},"demo.safeFlag":{"type":"boolean","scope":"machine"}}}}}"#,
        )
        .unwrap();
        fs::write(
            dir.join("agent.ts"),
            r#"
const cfg = { autoApprove: true };
function handleTool(toolArgs: any, fileContent: string) {
  const path = vscode.workspace.getConfiguration("demo").get("cliPath");
  execSync(toolArgs.command);
  const md = new MarkdownIt({ html: true });
  mermaid.initialize({ securityLevel: 'loose' });
  const sys = { role: 'system', content: `Follow instructions: ${fileContent}` };
}
"#,
        )
        .unwrap();

        let rep = scan_ai_surface(&dir, 500);
        assert!(
            rep.counts_by_category.contains_key("MCP_CONFIG_EXEC"),
            "missing MCP_CONFIG_EXEC: {:?}",
            rep.counts_by_category
        );
        assert!(
            rep.counts_by_category
                .contains_key("IDE_WORKSPACE_TRUST_BYPASS"),
            "missing IDE_WORKSPACE_TRUST_BYPASS: {:?}",
            rep.counts_by_category
        );
        assert!(
            rep.counts_by_category
                .contains_key("AGENT_AUTO_APPROVE_OR_TOOL_SINK"),
            "missing AGENT_AUTO_APPROVE_OR_TOOL_SINK: {:?}",
            rep.counts_by_category
        );
        assert!(
            rep.counts_by_category
                .contains_key("AI_MARKDOWN_WEBVIEW_EXFIL"),
            "missing AI_MARKDOWN_WEBVIEW_EXFIL: {:?}",
            rep.counts_by_category
        );
        assert!(
            rep.counts_by_category
                .contains_key("PROMPT_BOUNDARY_HYGIENE"),
            "missing PROMPT_BOUNDARY_HYGIENE: {:?}",
            rep.counts_by_category
        );
        assert!(
            !rep.findings.iter().any(|f| f.symbol == "demo.safeFlag"),
            "machine-scoped config must not be flagged"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
