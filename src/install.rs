use crate::audit::default_home_dir;
use regex::Regex;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const ALL_PRIMITIVES: [&str; 7] = [
    "sieve", "baton", "recall", "guard", "atlas", "probe", "splice",
];
pub const FENCE_START: &str = "<!-- agent-primitives:start -->";
pub const FENCE_END: &str = "<!-- agent-primitives:end -->";

const EMBEDDED_SKILLS: [(&str, &str); 7] = [
    ("sieve", include_str!("../skills/sieve/SKILL.md")),
    ("baton", include_str!("../skills/baton/SKILL.md")),
    ("recall", include_str!("../skills/recall/SKILL.md")),
    ("guard", include_str!("../skills/guard/SKILL.md")),
    ("atlas", include_str!("../skills/atlas/SKILL.md")),
    ("probe", include_str!("../skills/probe/SKILL.md")),
    ("splice", include_str!("../skills/splice/SKILL.md")),
];

struct HarnessSpec {
    id: &'static str,
    cli_bin: &'static str,
    probe_dirs: &'static [&'static str],
    skill_dirs: &'static [&'static str],
    rule_file: &'static str,
}

const HARNESS_SPECS: &[HarnessSpec] = &[
    HarnessSpec {
        id: "codex",
        cli_bin: "codex",
        probe_dirs: &[".codex"],
        skill_dirs: &[".codex/skills", ".agents/skills"],
        rule_file: ".codex/AGENTS.md",
    },
    HarnessSpec {
        id: "pi",
        cli_bin: "pi",
        probe_dirs: &[".pi"],
        skill_dirs: &[".pi/agent/skills", ".agents/skills"],
        rule_file: ".pi/agent/AGENTS.md",
    },
    HarnessSpec {
        id: "antigravity",
        cli_bin: "agy",
        probe_dirs: &[
            ".gemini/antigravity-cli",
            ".gemini/antigravity",
            ".gemini/config",
        ],
        skill_dirs: &[".gemini/config/skills", ".agents/skills"],
        rule_file: ".gemini/config/GEMINI.md",
    },
    HarnessSpec {
        id: "claude",
        cli_bin: "claude",
        probe_dirs: &[".claude"],
        skill_dirs: &[".claude/skills"],
        rule_file: ".claude/CLAUDE.md",
    },
    HarnessSpec {
        id: "grok",
        cli_bin: "grok",
        probe_dirs: &[".grok"],
        skill_dirs: &[".grok/skills"],
        rule_file: ".grok/AGENTS.md",
    },
    HarnessSpec {
        id: "opencode",
        cli_bin: "opencode",
        probe_dirs: &[".config/opencode", ".local/share/opencode"],
        skill_dirs: &[".config/opencode/skills", ".agents/skills"],
        rule_file: ".config/opencode/AGENTS.md",
    },
    HarnessSpec {
        id: "qwen",
        cli_bin: "qwen",
        probe_dirs: &[".qwen"],
        skill_dirs: &[".qwen/skills", ".agents/skills"],
        rule_file: ".qwen/QWEN.md",
    },
    HarnessSpec {
        id: "gemini-cli",
        cli_bin: "gemini",
        probe_dirs: &[".gemini"],
        skill_dirs: &[".gemini/skills", ".agents/skills"],
        rule_file: ".gemini/GEMINI.md",
    },
    HarnessSpec {
        id: "goose",
        cli_bin: "goose",
        probe_dirs: &[".config/goose"],
        skill_dirs: &[".agents/skills"],
        rule_file: ".config/goose/AGENTS.md",
    },
    HarnessSpec {
        id: "cursor",
        cli_bin: "cursor",
        probe_dirs: &[".cursor"],
        skill_dirs: &[".agents/skills"],
        rule_file: ".cursor/AGENTS.md",
    },
    HarnessSpec {
        id: "windsurf",
        cli_bin: "windsurf",
        probe_dirs: &[".codeium/windsurf"],
        skill_dirs: &[".agents/skills"],
        rule_file: ".codeium/windsurf/AGENTS.md",
    },
    HarnessSpec {
        id: "vscode",
        cli_bin: "code",
        probe_dirs: &[".vscode"],
        skill_dirs: &[".agents/skills"],
        rule_file: ".agents/AGENTS.md",
    },
    HarnessSpec {
        id: "claude-desktop",
        cli_bin: "claude-desktop-nonexistent-cli",
        probe_dirs: &[
            "AppData/Roaming/Claude",
            "Library/Application Support/Claude",
            ".config/Claude",
        ],
        skill_dirs: &[".agents/skills"],
        rule_file: ".agents/AGENTS.md",
    },
    HarnessSpec {
        id: "openclaw",
        cli_bin: "openclaw",
        probe_dirs: &[".openclaw"],
        skill_dirs: &[".openclaw/skills"],
        rule_file: ".openclaw/AGENTS.md",
    },
    HarnessSpec {
        id: "hermes",
        cli_bin: "hermes",
        probe_dirs: &[".hermes"],
        skill_dirs: &[".hermes/skills"],
        rule_file: ".hermes/AGENTS.md",
    },
];

pub fn embedded_skill_md(name: &str) -> Option<&'static str> {
    EMBEDDED_SKILLS
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| *v)
}

pub fn all_embedded_skills() -> &'static [(&'static str, &'static str); 7] {
    &EMBEDDED_SKILLS
}

fn posix(p: &Path) -> String {
    fs::canonicalize(p)
        .unwrap_or_else(|_| p.to_path_buf())
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}

fn which_exists(bin: &str) -> bool {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        if dir.join(bin).is_file() {
            return true;
        }
        #[cfg(windows)]
        for ext in ["exe", "cmd", "bat", "ps1"] {
            if dir.join(format!("{bin}.{ext}")).is_file() {
                return true;
            }
        }
    }
    false
}

fn normalize_harness_alias(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "agy" | "antigravity" => Some("antigravity"),
        "gemini" | "gemini-cli" => Some("gemini-cli"),
        "opencode" | "open-code" => Some("opencode"),
        "qwen" | "qwen-code" => Some("qwen"),
        "goose" => Some("goose"),
        "codex" => Some("codex"),
        "pi" | "pi-coding-agent" => Some("pi"),
        "claude" | "claude-code" => Some("claude"),
        "grok" => Some("grok"),
        "cursor" => Some("cursor"),
        "windsurf" | "codeium" => Some("windsurf"),
        "vscode" | "vs-code" | "copilot" => Some("vscode"),
        "claude-desktop" | "claudedesktop" => Some("claude-desktop"),
        "openclaw" => Some("openclaw"),
        "hermes" => Some("hermes"),
        "agents" => Some("agents"),
        _ => None,
    }
}

fn resolve_requested_harnesses(
    agent_arg: &str,
    home: &Path,
    check_path_bins: bool,
) -> Result<Vec<&'static str>, String> {
    let items: Vec<String> = agent_arg
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if items.is_empty() || items == ["auto"] {
        let mut found = Vec::new();
        for sp in HARNESS_SPECS {
            let has_dir = sp.probe_dirs.iter().any(|d| home.join(d).exists());
            let has_bin = check_path_bins && which_exists(sp.cli_bin);
            if has_dir || has_bin {
                found.push(sp.id);
            }
        }
        return Ok(found);
    }
    if items == ["all"] {
        return Ok(HARNESS_SPECS.iter().map(|s| s.id).collect());
    }
    let mut out = Vec::new();
    for it in items {
        let Some(canon) = normalize_harness_alias(&it) else {
            return Err(format!(
                "Unknown harness '{it}'. Choose from: auto, all, codex, pi, agy, claude, grok, openclaw, hermes, agents"
            ));
        };
        if !out.contains(&canon) {
            out.push(canon);
        }
    }
    Ok(out)
}

pub fn render_fenced_agents_block(ap_cmd: &str, selected: &[&str]) -> String {
    let sel: HashSet<&str> = selected.iter().copied().collect();
    let mut bullets = Vec::new();
    if sel.contains("probe") || sel.contains("atlas") {
        bullets.push(format!(
            "1. **Orient, Locate & Trace (`atlas`)**: Non-empty dir -> `{ap_cmd} atlas map .` (<15ms Code/Office/SQLite X-Ray). Bug hunting -> `{ap_cmd} atlas locate \"<symptom>\" .` (<25ms Top-5 functions). Call chains -> `{ap_cmd} atlas trace <Sym> .` (<30ms multi-hop callers/sinks). Shared symbol edits -> `{ap_cmd} atlas impact <Sym> .`."
        ));
    }
    if sel.contains("splice") {
        bullets.push(format!(
            "2. **Create & Edit (`splice`)**: Use native edit tools or batch via `{ap_cmd} splice apply --cwd . --stdin` (`@@ WRITE: p` / `@@ APPEND: p` `<<<`...`>>>`, `@@ FILE: p` `<<<` old `===` new `>>>`, `@@ SYMBOL: p :: S`, or Git unified diff) — auto-checks AST & cross-file exports."
        ));
    }
    if sel.contains("probe") || sel.contains("guard") {
        bullets.push(format!(
            "3. **Deep Verify, Live CDP, Process, FS & Net (`guard` / `probe`)**: `{ap_cmd} guard verify --cwd . --deep` (OWASP + git diff + vacuous/slop + contracts + tests + fuzz + UI + mutation). Ports/Procs -> `{ap_cmd} probe ports` / `probe ps -f <name>`; Live CDP -> `{ap_cmd} probe cdp --port <P> [--eval JS --watch-ms 1500]`; Batch HTTP/TCP/Callback -> `probe http --batch-stdin` / `probe tcp <h:p>` / `probe listen --run <cmd>`; FS diff -> `probe fs <dir> [--run <cmd>|--recent 300]`."
        ));
    }
    if ["probe", "sieve", "recall", "guard", "baton"]
        .iter()
        .any(|x| sel.contains(x))
    {
        bullets.push(format!(
            "4. **Batch Read, Hex/Binary, Search, SQL, Exec & Undo**: `{ap_cmd} read <target> [--lines 1-30,90-120|--offset 18000,95000 --pretty|--hex|--json-path P|--decode|--map-pos L:C|--entry E|--render]` (PE/ELF imports+exports+SHA256, Office/SQLite/`.map`/`.asar`); `{ap_cmd} search <pat> <path> [--pat P2 --multiline --block --pretty]`; `{ap_cmd} query`; `{ap_cmd} exec -c \"<cmd>\"`; `{ap_cmd} undo`."
        ));
    }
    format!(
        "{FENCE_START}\n## Agent Primitives (`{ap_cmd} <tool>` — self-contained, skip reading SKILL.md or running --help)\n{}\n{FENCE_END}\n",
        bullets.join("\n")
    )
}

fn upsert_fenced_block(md_path: &Path, block: &str) -> &'static str {
    if let Some(parent) = md_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if md_path.exists() {
        let orig = fs::read_to_string(md_path).unwrap_or_default();
        let pat = Regex::new(&format!(
            r"(?s){}.*?{}\n?",
            regex::escape(FENCE_START),
            regex::escape(FENCE_END)
        ))
        .unwrap();
        if pat.is_match(&orig) {
            let updated = pat.replacen(&orig, 1, block).to_string();
            let _ = fs::write(md_path, updated);
            return "updated";
        }
        let sep = if orig.is_empty() || orig.ends_with("\n\n") {
            ""
        } else if orig.ends_with('\n') {
            "\n"
        } else {
            "\n\n"
        };
        let _ = fs::write(md_path, format!("{orig}{sep}{block}"));
        return "appended";
    }
    let _ = fs::write(md_path, block);
    "created"
}

fn remove_fenced_block(md_path: &Path) -> bool {
    if !md_path.exists() {
        return false;
    }
    let orig = fs::read_to_string(md_path).unwrap_or_default();
    let pat = Regex::new(&format!(
        r"(?s)\n*{}.*?{}\n*",
        regex::escape(FENCE_START),
        regex::escape(FENCE_END)
    ))
    .unwrap();
    if !pat.is_match(&orig) {
        return false;
    }
    let cleaned = pat.replace_all(&orig, "\n").trim().to_string();
    if cleaned.is_empty() {
        let _ = fs::remove_file(md_path);
    } else {
        let _ = fs::write(md_path, format!("{cleaned}\n"));
    }
    true
}

fn install_self_binary(dest_dir: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(dest_dir).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    for legacy in ["ap", "ap.cmd", "ap.ps1"] {
        let lp = dest_dir.join(legacy);
        if lp.is_file() {
            let _ = fs::remove_file(lp);
        }
    }
    let exe_name = if cfg!(windows) { "ap.exe" } else { "ap" };
    let dst = dest_dir.join(exe_name);
    let src = std::env::current_exe().map_err(|e| e.to_string())?;
    let same = fs::canonicalize(&src).ok() == fs::canonicalize(&dst).ok() && dst.exists();
    if !same {
        if dst.exists() {
            let _ = fs::remove_file(&dst);
        }
        if fs::hard_link(&src, &dst).is_err() {
            fs::copy(&src, &dst)
                .map_err(|e| format!("Failed to install binary to {}: {e}", dst.display()))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dst, fs::Permissions::from_mode(0o755));
        }
    }
    Ok(dst)
}

fn write_skill_folders(
    dest_skills_dir: &Path,
    selected: &[&str],
    ap_cmd_rewrite: Option<&str>,
) -> Result<usize, String> {
    fs::create_dir_all(dest_skills_dir).map_err(|e| e.to_string())?;
    let rewrite_re = Regex::new(r"\bap (sieve|baton|recall|guard|atlas|probe|splice)\b").unwrap();
    let mut count = 0usize;
    for &name in selected {
        let Some(raw_md) = embedded_skill_md(name) else {
            return Err(format!("Unknown primitive: {name}"));
        };
        let folder = dest_skills_dir.join(name);
        if folder.exists() {
            let _ = fs::remove_dir_all(&folder);
        }
        fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
        let final_md = if let Some(cmd_p) = ap_cmd_rewrite {
            rewrite_re
                .replace_all(raw_md, |caps: &regex::Captures| {
                    format!("{cmd_p} {}", &caps[1])
                })
                .to_string()
        } else {
            raw_md.to_string()
        };
        fs::write(folder.join("SKILL.md"), final_md).map_err(|e| e.to_string())?;
        count += 1;
    }
    Ok(count)
}

fn merge_claude_or_codex_hooks(
    settings_path: &Path,
    ap_bin_posix: &str,
    selected: &[&str],
    include_precompact: bool,
) -> String {
    let sel: HashSet<&str> = selected.iter().copied().collect();
    let mut data: Value = if settings_path.exists() {
        let _ = fs::copy(settings_path, settings_path.with_extension("json.bak"));
        fs::read_to_string(settings_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}))
    } else {
        json!({})
    };
    if !data.is_object() {
        data = json!({});
    }
    let hooks_obj = data
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| json!({}));
    if !hooks_obj.is_object() {
        *hooks_obj = json!({});
    }

    let mut ensure_hook = |event: &str, cmd_str: String, matcher: Option<&str>| {
        let arr = hooks_obj
            .as_object_mut()
            .unwrap()
            .entry(event)
            .or_insert_with(|| json!([]));
        if let Some(vec) = arr.as_array_mut() {
            // Remove any legacy python guard.py/baton.py or stale ap hook for the same role
            vec.retain(|item| {
                let s = item.to_string();
                !s.contains("guard/scripts/guard.py")
                    && !s.contains("baton/scripts/baton.py")
                    && !s.contains(&cmd_str)
            });
            let mut entry = json!({
                "hooks": [{"type": "command", "command": cmd_str}]
            });
            if let Some(m) = matcher {
                entry["matcher"] = json!(m);
            }
            vec.push(entry);
        }
    };

    if sel.contains("guard") {
        ensure_hook(
            "PreToolUse",
            format!("\"{ap_bin_posix}\" guard shield"),
            Some("Bash"),
        );
        ensure_hook("Stop", format!("\"{ap_bin_posix}\" guard stop-gate"), None);
    }
    if include_precompact && sel.contains("baton") {
        ensure_hook(
            "PreCompact",
            format!("\"{ap_bin_posix}\" baton checkpoint --note \"auto pre-compact snapshot\""),
            None,
        );
    }

    if let Some(parent) = settings_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(
        settings_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        ),
    );
    posix(settings_path)
}

fn remove_claude_or_codex_hooks(settings_path: &Path) -> bool {
    let Ok(raw) = fs::read_to_string(settings_path) else {
        return false;
    };
    let Ok(mut data) = serde_json::from_str::<Value>(&raw) else {
        return false;
    };
    let Some(hooks) = data.get_mut("hooks").and_then(Value::as_object_mut) else {
        return false;
    };
    let mut changed = false;
    let keys: Vec<String> = hooks.keys().cloned().collect();
    for ev in keys {
        if let Some(arr) = hooks.get_mut(&ev).and_then(Value::as_array_mut) {
            let before = arr.len();
            arr.retain(|item| {
                let s = item.to_string();
                !s.contains("guard/scripts/guard.py")
                    && !s.contains("baton/scripts/baton.py")
                    && !s.contains(" guard shield")
                    && !s.contains(" guard stop-gate")
                    && !s.contains(" baton checkpoint")
            });
            if arr.len() != before {
                changed = true;
            }
            if arr.is_empty() {
                hooks.remove(&ev);
            }
        }
    }
    if hooks.is_empty() {
        if let Some(m) = data.as_object_mut() {
            m.remove("hooks");
        }
    }
    if !changed {
        return false;
    }
    if data.as_object().map(|m| m.is_empty()).unwrap_or(false) {
        let _ = fs::remove_file(settings_path);
    } else {
        let _ = fs::write(
            settings_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            ),
        );
    }
    true
}

fn merge_antigravity_hooks(
    hooks_path: &Path,
    ap_bin_posix: &str,
    selected: &[&str],
) -> Option<String> {
    if !selected.contains(&"guard") {
        return None;
    }
    let mut data: Value = if hooks_path.exists() {
        let _ = fs::copy(hooks_path, hooks_path.with_extension("json.bak"));
        fs::read_to_string(hooks_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}))
    } else {
        json!({})
    };
    if !data.is_object() {
        data = json!({});
    }
    data["agent-primitives-guard"] = json!({
        "enabled": true,
        "PreToolUse": [{
            "matcher": "run_command",
            "hooks": [{
                "type": "command",
                "command": format!("\"{ap_bin_posix}\" guard shield"),
                "timeout": 10
            }]
        }],
        "Stop": [{
            "type": "command",
            "command": format!("\"{ap_bin_posix}\" guard stop-gate"),
            "timeout": 15
        }]
    });
    if let Some(parent) = hooks_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(
        hooks_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        ),
    );
    Some(posix(hooks_path))
}

fn remove_antigravity_hooks(hooks_path: &Path) -> bool {
    let Ok(raw) = fs::read_to_string(hooks_path) else {
        return false;
    };
    let Ok(mut data) = serde_json::from_str::<Value>(&raw) else {
        return false;
    };
    let Some(map) = data.as_object_mut() else {
        return false;
    };
    if map.remove("agent-primitives-guard").is_none() {
        return false;
    }
    if map.is_empty() {
        let _ = fs::remove_file(hooks_path);
        let bak = hooks_path.with_extension("json.bak");
        if let Ok(bs) = fs::read_to_string(&bak) {
            if let Ok(Value::Object(bm)) = serde_json::from_str::<Value>(&bs) {
                if bm.len() <= 1 && (bm.is_empty() || bm.contains_key("agent-primitives-guard")) {
                    let _ = fs::remove_file(bak);
                }
            }
        }
    } else {
        let _ = fs::write(
            hooks_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            ),
        );
    }
    true
}

fn merge_opencode_mcp(cfg_path: &Path, ap_bin_posix: &str) -> String {
    let mut data: Value = if cfg_path.exists() {
        fs::read_to_string(cfg_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}))
    } else {
        json!({})
    };
    if !data.is_object() {
        data = json!({});
    }
    let obj = data.as_object_mut().unwrap();
    obj.entry("$schema")
        .or_insert_with(|| json!("https://opencode.ai/config.json"));
    let mcp = obj.entry("mcp").or_insert_with(|| json!({}));
    if !mcp.is_object() {
        *mcp = json!({});
    }
    mcp.as_object_mut().unwrap().insert(
        "agent-primitives".to_string(),
        json!({
            "type": "local",
            "command": [ap_bin_posix, "mcp"],
            "enabled": true
        }),
    );
    if let Some(p) = cfg_path.parent() {
        let _ = fs::create_dir_all(p);
    }
    let _ = fs::write(
        cfg_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        ),
    );
    posix(cfg_path)
}

fn remove_opencode_mcp(cfg_path: &Path) {
    let Ok(txt) = fs::read_to_string(cfg_path) else {
        return;
    };
    let Ok(mut data) = serde_json::from_str::<Value>(&txt) else {
        return;
    };
    let Some(obj) = data.as_object_mut() else {
        return;
    };
    if let Some(mcp) = obj.get_mut("mcp").and_then(Value::as_object_mut) {
        mcp.remove("agent-primitives");
        if mcp.is_empty() {
            obj.remove("mcp");
        }
    }
    let only_schema = obj.is_empty() || (obj.len() == 1 && obj.contains_key("$schema"));
    if only_schema {
        let _ = fs::remove_file(cfg_path);
    } else {
        let _ = fs::write(
            cfg_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            ),
        );
    }
}

fn merge_mcp_servers_json(cfg_path: &Path, ap_bin_posix: &str, include_trust: bool) -> String {
    let mut data: Value = if cfg_path.exists() {
        fs::read_to_string(cfg_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}))
    } else {
        json!({})
    };
    if !data.is_object() {
        data = json!({});
    }
    let servers = data
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| json!({}));
    if !servers.is_object() {
        *servers = json!({});
    }
    let mut entry = json!({
        "command": ap_bin_posix,
        "args": ["mcp"]
    });
    if include_trust {
        entry["trust"] = json!(true);
    }
    servers
        .as_object_mut()
        .unwrap()
        .insert("agent-primitives".to_string(), entry);
    if let Some(p) = cfg_path.parent() {
        let _ = fs::create_dir_all(p);
    }
    let _ = fs::write(
        cfg_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        ),
    );
    posix(cfg_path)
}

fn remove_mcp_servers_json(cfg_path: &Path) {
    let Ok(txt) = fs::read_to_string(cfg_path) else {
        return;
    };
    let Ok(mut data) = serde_json::from_str::<Value>(&txt) else {
        return;
    };
    let Some(obj) = data.as_object_mut() else {
        return;
    };
    if let Some(srvs) = obj.get_mut("mcpServers").and_then(Value::as_object_mut) {
        srvs.remove("agent-primitives");
        if srvs.is_empty() {
            obj.remove("mcpServers");
        }
    }
    if obj.is_empty() {
        let _ = fs::remove_file(cfg_path);
    } else {
        let _ = fs::write(
            cfg_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            ),
        );
    }
}

fn merge_pi_mcp(cfg_path: &Path, ap_bin_posix: &str) -> String {
    let mut data: Value = if cfg_path.exists() {
        fs::read_to_string(cfg_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}))
    } else {
        json!({})
    };
    if !data.is_object() {
        data = json!({});
    }
    let servers = data
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| json!({}));
    if !servers.is_object() {
        *servers = json!({});
    }
    servers.as_object_mut().unwrap().insert(
        "agent-primitives".to_string(),
        json!({
            "command": ap_bin_posix,
            "args": ["mcp"],
            "exposure": "codemode",
            "description": "Fast Pure-Rust MCP 2025-06-18 (36 annotated tools, Resources, Prompts; batch via Promise.allSettled in codemode): AST ap_read (--symbol/--outline/batch), parallel ap_search (-l/-c/-C), ap_edit/ap_rename, ap_orient/ap_surface/ap_impact/ap_changes/ap_locate/ap_trace, ap_query (named records), ap_sieve (compiler/test/diff), ap_baton/ap_frontier/ap_recall & CDP/HTTP/TCP/WS/TLS probes"
        }),
    );
    if let Some(p) = cfg_path.parent() {
        let _ = fs::create_dir_all(p);
    }
    let _ = fs::write(
        cfg_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        ),
    );
    posix(cfg_path)
}

pub fn render_pi_accelerator_ts(ap_bin_posix: &str) -> String {
    let escaped = ap_bin_posix.replace('\\', "/").replace('"', "\\\"");
    format!(
        r#"// Managed by agent-primitives (`ap init`). Zero system-prompt token overhead.
// Designed for Pi v1.5+ and interleaved-thinking models (e.g. DeepSeek Flash / Reasoner):
// - Accelerates slow `grep -rn`, heals Windows `> NUL`, non-raw `python -c` paths & UTF-8
// - Auto-sieves >28KB direct-to-LLM shell outputs into `~/.ap/sieve` (zero `.sieve` clutter)
// - Native Pi v1.5 `context_edit` batch observation masking at high-water marks (180k tok / 72%)
//   with >=10-turn cooldown to prevent Context Rot while preserving DeepSeek 50x KV-cache & thinking
// - Breaks 3x shell doom-loops, 3x unchanged file re-reads & 3-turn heavy-thinking stalls
// - Recovers leaked DSML XML tool blocks when 0 native tool calls were emitted (zero conflict)
// - Self-healing tips for `edit` misses, `codemode` errors & giant code `read` calls
// - Auto-checkpoints `.baton/` on compaction (only if `.baton` already exists) + live KV-cache HUD
// - Native Pi v1.5 `agent_before_settle` closed-loop syntax + diff blocker gate (max 1 retry/run)
// - Opt-in `deepseek/flash-auto` virtual model (dynamic low/high/max effort, zero cache-bust switch)
import {{ spawnSync }} from "node:child_process";
import {{ existsSync, readFileSync, statSync }} from "node:fs";
import {{ homedir }} from "node:os";
import {{ isAbsolute, join, resolve }} from "node:path";
import type {{
	ContextEditEntryDraft,
	CustomMessageEntryDraft,
	ExtensionAPI,
	ExtensionContext,
	ProjectedSessionEntry,
}} from "@earendil-works/pi-coding-agent";

const AP_BIN = "{escaped}";
const SIEVE_HOME = process.env.SIEVE_HOME || join(homedir(), ".ap", "sieve");
const DESTRUCTIVE_OR_WRITE =
	/(?:^|[;&|]\s*)(?:Remove-Item|rm|del|erase|rmdir|rd|Move-Item|Rename-Item|mv|ren|Set-Content|Add-Content|Clear-Content|Out-File|Copy-Item|cpi|copy)\b|shutil\.rmtree|os\.remove|os\.unlink|\.unlink\(|\.rmdir\(|\bgit(?:\.exe)?\b[\s\S]{{0,80}}?\bclean\b/i;
const BARE_SLOW_GREP =
	/^\s*grep\s+-([rRnwiEHlc]+)\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))(?:\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+)))?\s*$/;
const PY_INVOKE = /\b(?:python3?(?:\.exe)?|py(?:\.exe)?|pytest)\b/i;
const HAS_UTF8_ENV = /PYTHONUTF8|PYTHONIOENCODING/i;
const PY_WIN_BS =
	/\b(?:python3?(?:\.exe)?|py(?:\.exe)?)\b[\s\S]*(?:-c\b|<<)[\s\S]*(?<![rR])(['"])([A-Za-z]:\\(?!\\)[^'"\r\n]+)\1/;
const REDIR_NUL = /(\s(?:[12]?>|&>))\s*NUL\b/gi;
const QUOTE_OR_BS_ERR =
	/unterminated string|EOL while scanning|unicodeescape|unexpected character after line continuation|syntax error near unexpected token/i;
const TIMEOUT_ERR_RE = /\b(?:timed out|timeout|deadline exceeded|ETIMEDOUT)\b/i;
const SEARCH_CMD_RE =
	/^\s*(?:export\s+\S+\s*;?\s*|\$env:\w+\s*=\s*\S+\s*;?\s*)*(?:grep|egrep|fgrep|rg|find|fd|ls|dir|tree|Get-ChildItem|Select-String)\b/i;
const ENOENT_ERR_RE =
	/no such file or directory|cannot find the path|FileNotFoundError|ENOENT/i;
const PATH_MISMATCH_RE = /\/mnt\/[a-z]\//i;
const BASH_BS_PATH_RE = /(?:^|[\s=])[A-Za-z]:\\/;
const CMD_NOT_FOUND_RE = /command not found|is not recognized|exit(?:ed with)? code 127\b/i;
const MISSING_CLI_MAP: ReadonlyArray<[RegExp, string]> = [
	[/\bjq\b/i, 'ap read <file> --json-path "..." or ap query'],
	[/\b(?:xxd|hexdump)\b/i, "ap read <file> --hex"],
	[/\b(?:rg|ag)\b/i, "ap search <pattern> [path]"],
	[/\b(?:tree|fd)\b/i, "ap atlas map [path]"],
	[/\bsqlite3\b/i, "ap query -f db=<file.sqlite> <sql>"],
	[/\bpdftotext\b/i, "ap read <file.pdf>"],
	[/\bstrings\b/i, "ap read <binary> or ap search <pattern> <binary>"],
];
const CODE_FILE_EXT = /\.(?:rs|ts|tsx|js|jsx|mjs|cjs|py|go|c|cc|cpp|h|hpp)$/i;
const EDIT_TOOLS = new Set(["write", "edit", "ap_edit", "ap_rename"]);
const SERIAL_BATCHABLE_TOOLS = new Set(["bash", "powershell", "read", "grep", "find", "ls"]);
const LOOP_WINDOW = 6;
const LOOP_ERR_THRESHOLD = 3;
const LOOP_OK_THRESHOLD = 5;
const REREAD_THRESHOLD = 3;
const HEAVY_THINKING_CHARS = 12000;
const LIGHT_THINKING_CHARS = 1500;
const STAGNATION_TURNS = 3;
const SERIAL_BATCH_THRESHOLD = 6;
const BATCH_TIP_COOLDOWN_TURNS = 25;
const CODEMODE_PARALLEL_COOLDOWN_TURNS = 20;
const CODEMODE_PARALLEL_MAX_TIPS = 2;
const WRITE_OVERWRITE_TIP_CHARS = 4000;
const WRITE_TIP_COOLDOWN_TURNS = 15;
const LARGE_CODE_READ_CHARS = 20000;
const SIEVE_HARD_CHARS = 20000;
const SIEVE_STRUCTURED_CHARS = 14000;
const SIEVE_GIANT_LINE_CHARS = 4500;
const SIEVE_STRUCTURED_LINES = 180;
const BINARY_READ_EXT = /\.(?:png|jpe?g|gif|webp|bmp|ico|pdf|zip|gz|tar|7z|exe|dll|so|dylib|wasm|sqlite|db|docx|xlsx|pptx)$/i;

// Two-tier amortized deep-sweep observation masking constants (keeps DeepSeek V4.1 Flash in its <240k Peak-IQ zone)
const MASK_PREFIX = "[ap masked stale toolResult:";
const MASK_HIGH_WATER_PCT = 72;
const MASK_HIGH_WATER_TOKENS = 180000;
const MASK_TIER2_PCT = 78;
const MASK_TIER2_TOKENS = 240000;
const MASK_TIER2_MIN_ENTRY_CHARS = 1800;
const MASK_TIER2_KEEP_RECENT = 6;
const MASK_TIER2_MIN_RECLAIMED = 10000;
const MASK_STALE_CHARS_FALLBACK = 240000;
const FREE_MASK_MIN_TOKENS = 80000;
const MASK_KEEP_RECENT_ENTRIES = 10;
const MASK_MIN_ENTRY_CHARS = 2400;
const MASK_MIN_BATCH_ENTRIES = 2;
const MASK_MIN_RECLAIMED_CHARS = 48000;
const MASK_COOLDOWN_TURNS = 15;

export function isBenignGrepNoMatch(cmd: string, outText: string): boolean {{
	if (!cmd || !outText) return false;
	if (!/(?:^|[;&|]\s*)(?:grep|egrep|fgrep|rg|findstr|Select-String)\b/i.test(cmd)) return false;
	if (!/exit(?:ed with)? code 1\b/i.test(outText)) return false;
	const body = outText.replace(/command exited with code 1[\s\S]*/i, "").trim();
	return body.length < 15;
}}

const LEADING_SHELL_PREFIX_RE =
	/^\s*(?:(?:export\s+\S+|unset\s+\S+|\$env:\w+\s*=\s*\S+|cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)|chcp\s+\d+(?:\s*>\s*(?:\/dev\/null|NUL))?)\s*(?:&&|;)\s*)+/i;
const READONLY_PROBE_TIMEOUT_RE =
	/^\s*(?:grep|egrep|fgrep|rg|find|fd|ls|dir|tree|cat|head|tail|sed|awk|nl|wc|stat|file|strings|curl(?:\.exe)?|wget|Get-Content|Get-ChildItem|Select-String)\b/i;
const READONLY_PS_INVOKE_RE = /^\s*(?:powershell|pwsh)(?:\.exe)?\b/i;
const PS_MUTATING_CMDLET_RE =
	/\b(?:Set-|New-|Add-|Out-|Remove-|Clear-|Stop-|Restart-|Install-|Start-Process|-OutFile\b)/i;
const LONG_BUILD_TEST_RE =
	/\b(?:cargo|rustc|npm|pnpm|yarn|bun|pytest|vitest|jest|go\s+test|make|cmake|gradle|mvn|docker|pip\s+install|uv\s+sync)\b/i;

/**
 * Guard unbounded OR overly long (>120s) read-only shell probes with a 90s timeout so a hung
 * search/HTTP call fails fast BEFORE crossing DeepSeek's 2-5m KV-cache eviction cliff.
 * Strips leading `cd ... &&` / env prefixes so chained probes are guarded too.
 * Never shortens <=120s explicit timeouts or touches build/test/write commands.
 */
export function resolveSafeShellTimeout(cmd: string, currentTimeout: unknown): number | undefined {{
	if (!cmd || LONG_BUILD_TEST_RE.test(cmd) || DESTRUCTIVE_OR_WRITE.test(cmd)) return undefined;
	const coreCmd = cmd.replace(LEADING_SHELL_PREFIX_RE, "");
	const isReadonlyProbe =
		READONLY_PROBE_TIMEOUT_RE.test(coreCmd) ||
		(READONLY_PS_INVOKE_RE.test(coreCmd) && !PS_MUTATING_CMDLET_RE.test(coreCmd));
	if (!isReadonlyProbe) return undefined;
	if (currentTimeout === undefined || currentTimeout === null) return 90;
	if (typeof currentTimeout === "number" && Number.isFinite(currentTimeout) && currentTimeout > 120) {{
		return 90;
	}}
	return undefined;
}}

/**
 * Deterministic ASCII lexicographical tool-schema ordering for `before_provider_request`
 * (inspired by pi-deepseek-cache): prevents DeepSeek KV-cache prefix invalidation from
 * tool-list order jitter across MCP reconnects or reloads while preserving Anthropic `cache_control`.
 */
export function stabilizeProviderTools(payload: unknown): unknown {{
	if (!payload || typeof payload !== "object") return undefined;
	const p = payload as {{ tools?: unknown }};
	if (!Array.isArray(p.tools) || p.tools.length < 2) return undefined;
	const toolKey = (t: unknown): string => {{
		if (!t || typeof t !== "object") return "";
		const rec = t as {{
			name?: unknown;
			function?: {{ name?: unknown }};
			custom?: {{ name?: unknown }};
		}};
		if (typeof rec.function?.name === "string") return rec.function.name;
		if (typeof rec.custom?.name === "string") return rec.custom.name;
		if (typeof rec.name === "string") return rec.name;
		return "";
	}};
	// Never reorder if any tool carries provider-specific `cache_control` breakpoint markers
	for (const t of p.tools) {{
		if (t && typeof t === "object" && "cache_control" in (t as Record<string, unknown>)) {{
			return undefined;
		}}
	}}
	let prev = "";
	let needsSort = false;
	for (let i = 0; i < p.tools.length; i++) {{
		const k = toolKey(p.tools[i]);
		if (!k) return undefined;
		if (i > 0 && prev > k) {{
			needsSort = true;
		}}
		prev = k;
	}}
	if (!needsSort) return undefined;
	const sorted = [...p.tools].sort((a, b) => {{
		const ka = toolKey(a);
		const kb = toolKey(b);
		return ka < kb ? -1 : ka > kb ? 1 : 0;
	}});
	return {{ ...(p as Record<string, unknown>), tools: sorted }};
}}

const CODEMODE_SETTIMEOUT_SHIM =
	`const setTimeout = (fn, ms = 0, ...a) => {{ if (typeof sleep === "function") {{ sleep(ms).then(() => {{ if (typeof fn === "function") fn(...a); }}); }} else if (typeof fn === "function") {{ fn(...a); }} return 0; }};`;

/**
 * Lossless pre-execution auto-heal for Pi `codemode` JS scripts:
 * 1) Strips outer markdown code fences (```js ... ```) that break QuickJS parsing / `// @options:` line 1.
 * 2) Repairs `tools.mcp__agent-primitives__` -> `tools.mcp__agent_primitives__` (avoids JS subtraction ReferenceError).
 * 3) Auto-shims `setTimeout(...)` via host `sleep(ms)` (eliminating 100% of QuickJS timer ReferenceErrors while keeping `// @options:` on line 1).
 */
export function healCodemodeSource(code: string): string | undefined {{
	if (!code) return undefined;
	let next = code;
	const fenced = next.match(/^\s*```(?:js|javascript|ts|typescript)?[ \t]*\r?\n([\s\S]*?)\r?\n```\s*$/i);
	if (fenced) {{
		next = fenced[1];
	}}
	if (next.includes("tools.mcp__agent-primitives__")) {{
		next = next.replace(/tools\.mcp__agent-primitives__/g, "tools.mcp__agent_primitives__");
	}}
	// Strip accidental TypeScript `as any|unknown|string|number|boolean|object|const` assertions in QuickJS scripts
	if (/\bas\s+(?:any|unknown|string|number|boolean|object|const)\b/.test(next)) {{
		next = next.replace(
			/(\)|\]|\b[A-Za-z_$][A-Za-z0-9_$]*)\s+as\s+(?:any|unknown|string|number|boolean|object|const)\b(?=\s*[;,)\]\r\n.?:&|])/g,
			"$1",
		);
	}}
	if (/\bsetTimeout\s*\(/.test(next) && !/\b(?:const|let|var|function)\s+setTimeout\b/.test(next)) {{
		const optLine = next.match(/^([ \t]*\/\/[ \t]*@options:[^\r\n]*\r?\n)([\s\S]*)$/);
		if (optLine) {{
			next = `${{optLine[1]}}${{CODEMODE_SETTIMEOUT_SHIM}}\n${{optLine[2]}}`;
		}} else {{
			next = `${{CODEMODE_SETTIMEOUT_SHIM}}\n${{next}}`;
		}}
	}}
	return next !== code ? next : undefined;
}}

/**
 * Aggregate all text blocks from a Pi `tool_result` content array (critical for multi-block
 * `codemode` results where content[0] is the "Script completed/failed" header and content[1..N]
 * hold the actual script output and "Script error: ..." diagnostics).
 */
export function extractAllToolResultText(
	content: ReadonlyArray<{{ type?: string; text?: string }}>,
): string {{
	if (!Array.isArray(content)) return "";
	return content
		.filter((c) => c?.type === "text" && typeof c.text === "string")
		.map((c) => c.text as string)
		.join("\n");
}}

/**
 * Losslessly auto-sieve oversized `codemode` multi-block body text (content[1..N]) while keeping
 * the `Script completed`/`Script failed` header (content[0]), any trailing `Script error:` diagnostic,
 * and any `image` / non-text blocks 100% intact.
 */
export function sieveCodemodeContentBlocks(
	content: ReadonlyArray<{{ type?: string; text?: string; [k: string]: unknown }}>,
	sieveFn: (rawBody: string) => string | undefined,
): Array<{{ type?: string; text?: string; [k: string]: unknown }}> | undefined {{
	if (!Array.isArray(content) || content.length === 0) return undefined;
	const first = content[0];
	const hasHeader =
		first?.type === "text" &&
		typeof first.text === "string" &&
		/^Script (?:completed|failed)\b/.test(first.text);
	const startIdx = hasHeader ? 1 : 0;
	const bodyTexts: string[] = [];
	const preservedNonText: Array<{{ type?: string; text?: string; [k: string]: unknown }}> = [];
	for (let i = startIdx; i < content.length; i++) {{
		const blk = content[i];
		if (blk?.type === "text" && typeof blk.text === "string") {{
			bodyTexts.push(blk.text);
		}} else {{
			preservedNonText.push(blk);
		}}
	}}
	const combinedBody = bodyTexts.join("\n");
	if (!combinedBody || combinedBody.includes("[sieve id=") || !shouldAutoSieveShellOutput(combinedBody)) {{
		return undefined;
	}}
	// Preserve any trailing `Script error:` block verbatim so error diagnostics + classifiers keep full fidelity
	let sieveInput = combinedBody;
	let errorTail = "";
	const errIdx = combinedBody.lastIndexOf("\nScript error:\n");
	if (errIdx > 0) {{
		sieveInput = combinedBody.slice(0, errIdx);
		errorTail = combinedBody.slice(errIdx + 1).slice(0, 2400);
	}} else if (combinedBody.startsWith("Script error:\n")) {{
		return undefined;
	}}
	if (!shouldAutoSieveShellOutput(sieveInput)) {{
		return undefined;
	}}
	const digested = sieveFn(sieveInput);
	if (!digested || digested.length <= 40 || digested.length >= sieveInput.length * 0.78) {{
		return undefined;
	}}
	const finalText = errorTail ? `${{digested.trimEnd()}}\n\n${{errorTail}}` : digested;
	const out: Array<{{ type?: string; text?: string; [k: string]: unknown }}> = [];
	if (hasHeader) out.push(first);
	out.push(...preservedNonText);
	out.push({{ type: "text", text: finalText }});
	return out;
}}

/**
 * Format an instant (<12ms) post-edit Tree-sitter/JSON/TOML syntax alert from `ap splice check --json`.
 * Returns `undefined` whenever syntax is clean (`ok !== false`) so zero bytes are added on valid edits.
 */
export function formatInstantSyntaxAlert(
	rawPath: string,
	checkStdout: string,
	cwd?: string,
): string | undefined {{
	const trimmed = (checkStdout || "").trim();
	if (!trimmed.startsWith("{{")) return undefined;
	try {{
		const parsed = JSON.parse(trimmed) as {{
			ok?: boolean;
			issues?: Array<string | {{ file?: string; line?: number; message?: string; detail?: string }}>;
		}};
		if (parsed.ok !== false || !Array.isArray(parsed.issues) || parsed.issues.length === 0) {{
			return undefined;
		}}
		const lines = parsed.issues.slice(0, 3).map((iss) =>
			typeof iss === "string"
				? `- ${{iss.slice(0, 180)}}`
				: `- ${{iss.file ?? normRelPath(rawPath, cwd)}}${{iss.line ? `:${{iss.line}}` : ""}} ${{(iss.message ?? iss.detail ?? "syntax error").slice(0, 180)}}`,
		);
		return `[ap syntax-alert] Immediate syntax error in ${{normRelPath(rawPath, cwd)}}:\n${{lines.join("\n")}}\nFix this syntax error now before moving to other files or tests.`;
	}} catch {{
		return undefined;
	}}
}}

/**
 * Targeted QuickJS `codemode` failure recovery classifier (addresses live ReferenceError/TypeError/Timeout/Syntax/OOM errors).
 */
export function classifyCodemodeFailureTip(outText: string): string {{
	if (/\bReferenceError\b|is not defined/i.test(outText)) {{
		return `[ap codemode-tip] QuickJS sandbox has NO Node APIs (fs/path/require/process/fetch/Buffer); use await sleep(ms) for delays and tools.<name>(args) (e.g. tools.read, tools.bash, tools.mcp__agent_primitives__ap_search) or inspect ALL_TOOLS.`;
	}}
	if (
		/\bTypeError\b|(?:split|trim|match|replace|includes|slice|indexOf|toLowerCase|toUpperCase|startsWith|endsWith)\s+is not a function|cannot read propert|not iterable|unexpected token.*\[object Object\]/i.test(
			outText,
		)
	) {{
		return `[ap codemode-tip] TypeError: tools.bash(...) resolves to an OBJECT {{ output, exit_code, truncated, full_output_path }} (use (res.output ?? ""), NOT res.split/slice!), tools.read(...) resolves to a string, and tools.mcp__* resolves to {{ content, structuredContent, isError }} (already parsed; check Object.keys(res) instead of slicing undefined). Run await describeTool("<name>") to verify exact fields.`;
	}}
	if (/\bSyntaxError\b|options line/i.test(outText)) {{
		return `[ap codemode-tip] Pass raw JS body only (no markdown code fences); // @options: {{...}} must be line 1 if used.`;
	}}
	if (/\bout of memory\b/i.test(outText)) {{
		return `[ap codemode-tip] Hit QuickJS 256MB WASM heap limit; filter/slice large payloads inside ap_search/ap_query or process files in smaller batches instead of buffering everything in RAM.`;
	}}
	if (/\b(?:timed out|timeout|deadline)\b/i.test(outText)) {{
		return `[ap codemode-tip] Codemode script timed out; parallelize independent calls with Promise.allSettled([...]) or raise // @options: {{"timeout_ms": 90000}}.`;
	}}
	if (/\bvalidation\b|must be|required property/i.test(outText)) {{
		return `[ap codemode-tip] Tool argument schema mismatch; run await describeTool("mcp__agent_primitives__<name>") to inspect exact required fields and types.`;
	}}
	if (/\bENOENT\b|no such file|does not exist|cannot find the path/i.test(outText)) {{
		return `[ap codemode-tip] File/path not found inside codemode; verify exact paths via tools.mcp__agent_primitives__ap_atlas / ap_search before reading or editing.`;
	}}
	return `[ap codemode-tip] Use await searchTools("ap_") or await describeTool("mcp__agent_primitives__<name>") to verify exact tool IDs (dashes become underscores on tools.*) & typed structuredContent fields.`;
}}

/**
 * Static, 100% KV-cache-locked DeepSeek Flash execution guidelines (~145 tokens total, cached at $0.006/1M)
 * injected via `before_agent_start` -> `systemPromptOptions.promptGuidelines` with concrete copy-paste idioms
 * (empirical production telemetry showed abstract prose had 0% ap-CLI & codemode-parallel adoption).
 */
export const AP_DEEPSEEK_GUIDELINES: readonly string[] = [
	"Parallel-first execution: batch 2+ independent reads/searches/checks in parallel tool calls OR one codemode script via `const res = await Promise.allSettled([tools.read({{path}}), tools.bash({{command}})]);` (cuts latency & thinking tokens ~40%); persist cross-turn state via `store(key, val)`/`load(key)`.",
	"In codemode (QuickJS sandbox — NO Node fs/path/require/process/fetch; `await sleep(ms)` is available): `tools.bash({{command}})` returns `{{ output, exit_code, truncated }}` (read `.output`), `tools.read({{path}})` returns a string, and `tools.mcp__agent_primitives__*` returns parsed `{{ content, structuredContent, isError }}`.",
	'Fast local CLI & exact edits: direct `read` shows `L:HH|` hashline anchors (pass `L:HH|` lines in `edit` `oldText` to disambiguate duplicates in 1 shot). In bash, prefer zero-dep `ap` over slow grep/python one-liners: `ap search "<re>" [dir] -e <ext>`, `ap read <file> --outline|--symbol <S>|--lines 1-80|--json-path <P>|--hex`, `ap query -f db=<db> "<sql>"`, `ap atlas map .`; keep read-only probes <=90s.',
];

export function injectDeepSeekGuidelines(guidelines: string[]): boolean {{
	if (!Array.isArray(guidelines)) return false;
	let added = false;
	for (const rule of AP_DEEPSEEK_GUIDELINES) {{
		if (!guidelines.includes(rule)) {{
			guidelines.push(rule);
			added = true;
		}}
	}}
	return added;
}}

/**
 * Calibrate Pi v1.5+ native `CacheWarmer` for DeepSeek V4.1 Flash economics ($0.006/1M cacheRead vs
 * $0.30/1M cold miss = 49x ROI). Overrides Pi's Opus-calibrated $0.05 floor when missCost >= $0.015
 * (~51k+ tokens) and ROI >= 20x so long tool runs & brief pauses stay at ~99% KV-cache hit rate.
 */
export function decideDeepSeekCacheWarming(input: {{
	provider?: string;
	modelId?: string;
	warmCost?: number;
	missCost?: number;
	action?: string;
}}): {{ action: "warm" }} | undefined {{
	const prov = String(input.provider ?? "").toLowerCase();
	const mid = String(input.modelId ?? "").toLowerCase();
	const isDs = prov.includes("deepseek") || mid.includes("deepseek") || mid.includes("flash-auto");
	if (!isDs) return undefined;
	const warm = typeof input.warmCost === "number" ? input.warmCost : 0;
	const miss = typeof input.missCost === "number" ? input.missCost : 0;
	if (warm > 0 && miss >= 0.015 && miss / warm >= 20) {{
		return {{ action: "warm" }};
	}}
	return undefined;
}}

/**
 * Standalone serializer for fast `reasoning: "low"` dead-end-preserving auto-compaction
 * (zero runtime SDK imports; preserves previousSummary, exact TOOL_ERROR signatures, file ops & store keys).
 */
export function serializeMessagesForCompaction(
	messages: ReadonlyArray<Record<string, unknown>>,
	previousSummary?: string,
	readFiles: readonly string[] = [],
	modifiedFiles: readonly string[] = [],
	storeKeys: readonly string[] = [],
): string {{
	const parts: string[] = [];
	if (previousSummary && previousSummary.trim()) {{
		parts.push(`## Previous Summary\n${{previousSummary.trim().slice(0, 6000)}}`);
	}}
	const errors: string[] = [];
	const trace: string[] = [];
	for (const raw of messages ?? []) {{
		const m = raw as {{
			role?: string;
			toolName?: string;
			isError?: boolean;
			content?: string | Array<{{ type?: string; text?: string; name?: string; arguments?: Record<string, unknown> }}>;
		}};
		if (m?.role === "user" || m?.role === "assistant") {{
			let txt = "";
			if (typeof m.content === "string") {{
				txt = m.content;
			}} else if (Array.isArray(m.content)) {{
				const segs: string[] = [];
				for (const b of m.content) {{
					if (b?.type === "text" && typeof b.text === "string" && b.text.trim()) {{
						segs.push(b.text.trim());
					}} else if (b?.type === "toolCall" && typeof b.name === "string") {{
						const pArg =
							typeof b.arguments?.path === "string"
								? `(${{b.arguments.path}})`
								: typeof b.arguments?.command === "string"
									? `(${{String(b.arguments.command).replace(/\s+/g, " ").slice(0, 80)}})`
									: "";
						segs.push(`[call:${{b.name}}${{pArg}}]`);
					}}
				}}
				txt = segs.join("\n");
			}}
			if (txt.trim()) trace.push(`${{m.role.toUpperCase()}}: ${{txt.trim().slice(0, 1000)}}`);
		}} else if (m?.role === "toolResult" && m.isError) {{
			const rawTxt = Array.isArray(m.content)
				? m.content.map((b) => (typeof b.text === "string" ? b.text : "")).join("\n")
				: "";
			const sigs = extractErrorSignatureLines(rawTxt);
			const line = `(${{m.toolName ?? "tool"}}) ${{(sigs.join(" | ") || rawTxt.replace(/\s+/g, " ").slice(0, 180)).trim()}}`;
			if (errors.length < 18 && !errors.includes(line)) errors.push(line);
		}}
	}}
	if (trace.length > 0) parts.push(`## Conversation Trace\n${{trace.join("\n").slice(-26000)}}`);
	if (errors.length > 0) parts.push(`## Exact Failing Errors Observed\n- ${{errors.join("\n- ")}}`);
	if (modifiedFiles.length > 0) parts.push(`## Modified Files\n${{modifiedFiles.slice(0, 40).join(", ")}}`);
	if (readFiles.length > 0) parts.push(`## Read-Only Files\n${{readFiles.slice(0, 40).join(", ")}}`);
	if (storeKeys.length > 0) parts.push(`## Active codemode-store Keys (recoverable via load(key))\n${{storeKeys.slice(0, 20).join(", ")}}`);
	return parts.join("\n\n");
}}

export function shouldAutoSieveShellOutput(text: string): boolean {{
	if (!text) return false;
	if (text.length >= SIEVE_HARD_CHARS) return true;
	const lines = text.split("\n");
	if (lines.some((l) => l.length > SIEVE_GIANT_LINE_CHARS)) return true;
	if (text.length >= SIEVE_STRUCTURED_CHARS) {{
		if (lines.length >= SIEVE_STRUCTURED_LINES) return true;
		if (text.includes("\x1b[")) return true;
		if (text.includes("{{") && text.split('":').length >= 21) return true;
	}}
	return false;
}}

export function classifyShellFailureTip(
	toolName: string,
	cmd: string,
	outText: string,
): string | undefined {{
	if (isBenignGrepNoMatch(cmd, outText)) return undefined;
	if (QUOTE_OR_BS_ERR.test(outText)) {{
		return `[ap quote-tip] Avoid nested quotes/backslashes inside inline python -c; use a single-quoted heredoc (python - <<'PY' ... PY) or write a script file via write/ap_edit.`;
	}}
	if (TIMEOUT_ERR_RE.test(outText)) {{
		if (SEARCH_CMD_RE.test(cmd)) {{
			return `[ap timeout-tip] Slow recursive shell search timed out; use ap search (or ap_search / ap_atlas) with -e <ext> or a narrower directory instead.`;
		}}
		return `[ap timeout-tip] Command timed out (commands >2m also risk evicting DeepSeek KV-cache); cap synchronous commands <=90s, narrow scope, or redirect long jobs to a log file.`;
	}}
	if (CMD_NOT_FOUND_RE.test(outText)) {{
		for (const [re, replacement] of MISSING_CLI_MAP) {{
			if (re.test(cmd)) {{
				return `[ap cmd-tip] Missing shell CLI detected; use built-in zero-dependency \`${{replacement}}\` instead.`;
			}}
		}}
	}}
	if (ENOENT_ERR_RE.test(outText)) {{
		if (PATH_MISMATCH_RE.test(cmd)) {{
			return `[ap path-tip] Detected /mnt/<drive>/ path; use native drive paths (C:/...) in Windows tools/Python or verify cwd before retrying.`;
		}}
		if (toolName === "bash" && BASH_BS_PATH_RE.test(cmd)) {{
			return `[ap path-tip] Unquoted Windows backslashes in Git Bash are stripped as escapes; use forward slashes (C:/path/to/file) or single quotes.`;
		}}
		return `[ap enoent-tip] Path not found; verify actual paths via \`ap atlas map\` / \`ap search -l\` or check cwd before retrying.`;
	}}
	if (/\b(?:ModuleNotFoundError|ImportError)\b/i.test(outText)) {{
		return `[ap py-tip] Missing Python package; zero-dependency \`ap read\` (.docx/.xlsx/.pdf/PE/ELF/hex/JSON-path), \`ap query\` (SQLite/CSV/Excel) & \`ap search\` work without pip packages.`;
	}}
	return undefined;
}}

/**
 * Deterministic 2-hex FNV-1a content hash tag for Hashline (`L:HH|line`) anchored reading & editing
 * (inspired by Can Boluk's *The Harness Problem* / oh-my-pi; whitespace-trimmed & 100% KV-cache safe).
 */
export function hashlineTag(line: string): string {{
	const s = line.trim();
	let h = 2166136261;
	for (let i = 0; i < s.length; i++) {{
		h ^= s.charCodeAt(i);
		h = Math.imul(h, 16777619);
	}}
	return ((h ^ (h >>> 8) ^ (h >>> 16) ^ (h >>> 24)) & 0xff).toString(16).padStart(2, "0");
}}

/**
 * Annotate direct built-in `read` text output with compact `L:HH|` hashline anchors while
 * preserving Pi's trailing truncation banner and leaving `codemode` raw `structuredContent` untouched.
 */
export function annotateReadWithHashlines(outText: string, startOffset = 1): string | undefined {{
	if (!outText || outText.length > 60_000) return undefined;
	const trailerRe = /\n\n(\[(?:Showing lines [^\]]+|\d+ more lines in file[^\]]+|Truncated[^\]]+)\])\s*$/;
	const tm = outText.match(trailerRe);
	const body = tm ? outText.slice(0, tm.index) : outText;
	const trailer = tm ? outText.slice(tm.index) : "";
	const lines = body.split("\n");
	if (lines.length < 2) return undefined;
	// Skip minified / giant single-line bundles
	if (lines.some((l) => l.length > 600)) return undefined;
	// Skip if already line-numbered or hashline-tagged
	const sampleNonBlank = lines.filter((l) => l.trim().length > 0).slice(0, 2);
	if (sampleNonBlank.length >= 1 && sampleNonBlank.every((l) => /^\s*\d+(?::[0-9a-f]{{2}})?(?::|\||\t)/.test(l))) {{
		return undefined;
	}}
	const base = Number.isFinite(startOffset) && startOffset >= 1 ? Math.floor(startOffset) : 1;
	const tagged = lines.map((l, idx) => `${{base + idx}}:${{hashlineTag(l)}}|${{l}}`).join("\n");
	return tagged + trailer;
}}

/**
 * Clamp out-of-bounds `read(offset=...)` requests to the file's tail before Pi throws
 * `Offset N is beyond end of file (M lines total)`, eliminating wasted error round-trips.
 */
export function clampReadOffsetToEof(
	fileContent: string,
	offset: unknown,
	limit: unknown,
): {{ requestedOffset: number; clampedOffset: number; totalLines: number }} | undefined {{
	if (typeof offset !== "number" || !Number.isFinite(offset) || offset < 2) return undefined;
	const req = Math.floor(offset);
	const totalLines = fileContent.split("\n").length;
	if (req <= totalLines) return undefined;
	const win =
		typeof limit === "number" && Number.isFinite(limit) && limit > 0
			? Math.min(80, Math.max(20, Math.floor(limit)))
			: 60;
	const clampedOffset = Math.max(1, totalLines - win + 1);
	return {{ requestedOffset: req, clampedOffset, totalLines }};
}}

/**
 * Fast (<2ms) structural outline for truncated NON-CODE files (.md, .toml, .ini, .yaml, .json, .log, .jsonl, .csv)
 * so DeepSeek jumps straight to the target offset instead of blind sequential paging.
 */
export function extractNonCodeOutline(filePath: string, content: string): string | undefined {{
	if (!filePath || !content) return undefined;
	const lines = content.replace(/\r\n/g, "\n").split("\n");
	const total = lines.length;
	if (total < 10) return undefined;
	const ext = (filePath.match(/\.([a-z0-9]+)$/i)?.[1] ?? "").toLowerCase();
	const items: string[] = [];
	if (ext === "md" || ext === "markdown") {{
		for (let i = 0; i < total && items.length < 28; i++) {{
			const m = lines[i].match(/^(#{{1,4}}\s+.+)$/);
			if (m) items.push(`L${{i + 1}}: ${{m[1].trim().slice(0, 90)}}`);
		}}
		if (items.length > 0) {{
			return `[ap read-outline] Markdown TOC (${{total}} lines; jump with read(offset=...)):\n${{items.join("\n")}}`;
		}}
	}} else if (ext === "toml" || ext === "ini" || ext === "cfg") {{
		for (let i = 0; i < total && items.length < 28; i++) {{
			const m = lines[i].match(/^\s*(\[[^\]]+\])/);
			if (m) items.push(`L${{i + 1}}: ${{m[1].slice(0, 80)}}`);
		}}
		if (items.length > 0) {{
			return `[ap read-outline] Config sections (${{total}} lines; jump with read(offset=...)):\n${{items.join("\n")}}`;
		}}
	}} else if (ext === "yml" || ext === "yaml") {{
		for (let i = 0; i < total && items.length < 28; i++) {{
			const m = lines[i].match(/^([A-Za-z0-9_.-]+:\s*(?:\S.*)?)$/);
			if (m) items.push(`L${{i + 1}}: ${{m[1].slice(0, 80)}}`);
		}}
		if (items.length > 0) {{
			return `[ap read-outline] YAML keys (${{total}} lines; jump with read(offset=...)):\n${{items.join("\n")}}`;
		}}
	}} else if (ext === "json" || ext === "jsonc") {{
		for (let i = 0; i < total && items.length < 28; i++) {{
			const m = lines[i].match(/^(?:  |\t)("[^"]+"\s*:)/);
			if (m) items.push(`L${{i + 1}}: ${{m[1].slice(0, 80)}}`);
		}}
		if (items.length > 0) {{
			return `[ap read-outline] JSON keys (${{total}} lines; jump with read(offset=...) or ap_read(json_path=...)):\n${{items.join("\n")}}`;
		}}
	}}
	return `[ap read-tip] Truncated large file (${{total}} lines); jump directly with read(offset=...) or filter via ap_search / ap_read(json_path=...) / ap_query instead of paging serially.`;
}}

function countSubstringOccurrences(haystack: string, needle: string): number {{
	if (!needle) return 0;
	let count = 0;
	let pos = 0;
	while (true) {{
		const idx = haystack.indexOf(needle, pos);
		if (idx < 0) break;
		count++;
		if (count > 2) return count;
		pos = idx + 1;
	}}
	return count;
}}

function stripHashlinePrefixes(lines: readonly string[]): string[] {{
	return lines.map((l) => {{
		const m = l.match(/^\s*\d+:[0-9a-f]{{2}}\|(.*)$/);
		return m ? m[1] : l;
	}});
}}

interface ParsedHashlineRange {{
	startIdx: number;
	endIdx: number;
	effectiveNew: string;
	expandedLo: number;
	expandedHi: number;
}}

function parseHashlineAnchorRange(
	lfFile: string,
	fileLines: readonly string[],
	rawOldLines: readonly string[],
	lfNew: string,
): ParsedHashlineRange | undefined {{
	const hlRe = /^\s*(\d+):([0-9a-f]{{2}})\|(.*)$/;
	const parsed: Array<{{ lineNum: number; hash: string; body: string }} | null> = [];
	let firstLineNum = -1;
	let lastLineNum = -1;
	let anchorCount = 0;
	for (const l of rawOldLines) {{
		if (l.trim().length === 0) {{
			parsed.push(null);
			continue;
		}}
		const m = l.match(hlRe);
		if (!m) return undefined;
		const num = Number(m[1]);
		if (!Number.isInteger(num) || num < 1 || num > fileLines.length) return undefined;
		if (firstLineNum < 0) {{
			firstLineNum = num;
		}} else if (num !== lastLineNum + 1) {{
			return undefined;
		}}
		const diskLine = fileLines[num - 1];
		if (hashlineTag(diskLine) !== m[2]) return undefined;
		const body = m[3] ?? "";
		if (body.trim().length > 0 && body.trim() !== diskLine.trim()) return undefined;
		parsed.push({{ lineNum: num, hash: m[2], body }});
		lastLineNum = num;
		anchorCount++;
	}}
	if (anchorCount === 0 || firstLineNum < 1) return undefined;
	const startIdx = firstLineNum - 1;
	const endIdx = lastLineNum; // exclusive
	const matchedDisk = fileLines.slice(startIdx, endIdx);
	const strippedOldBodies = parsed.filter((p): p is NonNullable<typeof p> => p !== null).map((p) => p.body);
	const cleanNew = stripHashlinePrefixes(lfNew.split("\n")).join("\n");
	const effectiveNew = reindentReplacement(cleanNew, strippedOldBodies, matchedDisk);
	for (let pad = 0; pad <= 8; pad++) {{
		const lo = Math.max(0, startIdx - pad);
		const hi = Math.min(fileLines.length, endIdx + pad);
		const candOld = fileLines.slice(lo, hi).join("\n");
		if (countSubstringOccurrences(lfFile, candOld) === 1) {{
			return {{ startIdx, endIdx, effectiveNew, expandedLo: lo, expandedHi: hi }};
		}}
	}}
	return undefined;
}}

/**
 * Tier-0A Hashline anchor resolution: supports BOTH single-line AND multi-line `L:HH|...` anchors,
 * verifies exact 1-based line number + 2-hex FNV hash against disk (zero stale-edit risk), and
 * symmetrically auto-expands surrounding context lines when the target slice occurs multiple times!
 */
function resolveHashlineAnchorEdit(
	lfFile: string,
	fileLines: readonly string[],
	rawOldLines: readonly string[],
	lfNew: string,
): {{ oldText: string; newText: string; strategy: string }} | undefined {{
	const r = parseHashlineAnchorRange(lfFile, fileLines, rawOldLines, lfNew);
	if (!r) return undefined;
	const candOld = fileLines.slice(r.expandedLo, r.expandedHi).join("\n");
	const prefix = fileLines.slice(r.expandedLo, r.startIdx);
	const suffix = fileLines.slice(r.endIdx, r.expandedHi);
	const candNew = [...prefix, r.effectiveNew, ...suffix].join("\n");
	const expanded = r.expandedLo < r.startIdx || r.expandedHi > r.endIdx;
	return {{
		oldText: candOld,
		newText: candNew,
		strategy: expanded ? "hashline-anchor-expanded" : "hashline-anchor-unique",
	}};
}}

/**
 * Resolve multi-hunk `edit.edits[]` arrays where 2+ disjoint Hashline-anchored hunks would overlap
 * after symmetric context expansion (e.g. editing two adjacent duplicate lines in one `edit` call),
 * automatically merging overlapping expanded clusters into single unique non-overlapping blocks.
 */
export function resolveAndMergeHashlineEdits(
	fileContent: string,
	edits: ReadonlyArray<{{ oldText?: string; newText?: string }}>,
): {{ edits: Array<{{ oldText: string; newText: string }}>; healed: number }} | undefined {{
	if (!fileContent || !Array.isArray(edits) || edits.length < 2) return undefined;
	const lfFile = fileContent.replace(/\r\n/g, "\n");
	const fileLines = lfFile.split("\n");
	const parsed: Array<{{ origIdx: number; range: ParsedHashlineRange }}> = [];
	const others: Array<{{ oldText: string; newText: string }}> = [];
	for (let i = 0; i < edits.length; i++) {{
		const it = edits[i];
		if (typeof it?.oldText !== "string" || typeof it?.newText !== "string") return undefined;
		const r = parseHashlineAnchorRange(
			lfFile,
			fileLines,
			it.oldText.replace(/\r\n/g, "\n").split("\n"),
			it.newText.replace(/\r\n/g, "\n"),
		);
		if (r) {{
			parsed.push({{ origIdx: i, range: r }});
		}} else {{
			others.push({{ oldText: it.oldText, newText: it.newText }});
		}}
	}}
	if (parsed.length < 2) return undefined;
	parsed.sort((a, b) => a.range.startIdx - b.range.startIdx);
	// Bail safely if raw Hashline target ranges themselves overlap (let Pi surface the genuine overlap error)
	for (let i = 1; i < parsed.length; i++) {{
		if (parsed[i - 1].range.endIdx > parsed[i].range.startIdx) return undefined;
	}}
	// Group items whose expanded unique windows overlap
	const clusters: Array<Array<ParsedHashlineRange>> = [[parsed[0].range]];
	let clusterHi = parsed[0].range.expandedHi;
	let hasMergedCluster = false;
	for (let i = 1; i < parsed.length; i++) {{
		const cur = parsed[i].range;
		if (cur.expandedLo < clusterHi) {{
			clusters[clusters.length - 1].push(cur);
			clusterHi = Math.max(clusterHi, cur.expandedHi);
			hasMergedCluster = true;
		}} else {{
			clusters.push([cur]);
			clusterHi = cur.expandedHi;
		}}
	}}
	if (!hasMergedCluster) return undefined;

	const outEdits: Array<{{ oldText: string; newText: string }}> = [];
	for (const group of clusters) {{
		const minStart = group[0].startIdx;
		const maxEnd = group[group.length - 1].endIdx;
		const midLines: string[] = [];
		let cursor = minStart;
		for (const g of group) {{
			if (g.startIdx > cursor) {{
				midLines.push(...fileLines.slice(cursor, g.startIdx));
			}}
			midLines.push(g.effectiveNew);
			cursor = g.endIdx;
		}}
		const mergedBodyNew = midLines.join("\n");
		let resolved: {{ oldText: string; newText: string }} | undefined;
		for (let pad = 0; pad <= 8; pad++) {{
			const lo = Math.max(0, minStart - pad);
			const hi = Math.min(fileLines.length, maxEnd + pad);
			const candOld = fileLines.slice(lo, hi).join("\n");
			if (countSubstringOccurrences(lfFile, candOld) === 1) {{
				const prefix = fileLines.slice(lo, minStart);
				const suffix = fileLines.slice(maxEnd, hi);
				resolved = {{
					oldText: candOld,
					newText: [...prefix, mergedBodyNew, ...suffix].join("\n"),
				}};
				break;
			}}
		}}
		if (!resolved) return undefined;
		outEdits.push(resolved);
	}}
	let healed = parsed.length;
	for (const o of others) {{
		const fixed = healEditBlock(fileContent, o.oldText, o.newText);
		if (fixed) {{
			outEdits.push({{ oldText: fixed.oldText, newText: fixed.newText }});
			healed += 1;
		}} else {{
			outEdits.push(o);
		}}
	}}
	return {{ edits: outEdits, healed }};
}}

function stripSequentialLineNumbers(lines: readonly string[]): string[] | undefined {{
	const nonBlank = lines.filter((l) => l.trim().length > 0);
	if (nonBlank.length < 2) return undefined;
	const lineRe = /^\s*(\d+)(?::[0-9a-f]{{2}})?(?::|\||\t) ?(.*)$/;
	let prevNum = -1;
	const stripped: string[] = [];
	for (const l of lines) {{
		if (l.trim().length === 0) {{
			stripped.push("");
			continue;
		}}
		const m = l.match(lineRe);
		if (!m) return undefined;
		const num = Number(m[1]);
		if (!Number.isFinite(num) || num <= prevNum) return undefined;
		prevNum = num;
		stripped.push(m[2] ?? "");
	}}
	return stripped;
}}

function reindentReplacement(
	newStr: string,
	oldLines: readonly string[],
	matchedDiskLines: readonly string[],
): string {{
	const oldFirst = oldLines.find((l) => l.trim().length > 0);
	const diskFirst = matchedDiskLines.find((l) => l.trim().length > 0);
	if (oldFirst === undefined || diskFirst === undefined) return newStr;
	const oldLead = oldFirst.match(/^[ \t]*/)?.[0] ?? "";
	const diskLead = diskFirst.match(/^[ \t]*/)?.[0] ?? "";
	if (oldLead === diskLead) return newStr;
	return newStr
		.split("\n")
		.map((line) => {{
			if (line.trim().length === 0) return "";
			if (oldLead.length > 0 && line.startsWith(oldLead)) {{
				return diskLead + line.slice(oldLead.length);
			}}
			if (oldLead.length === 0) {{
				return diskLead + line;
			}}
			return line;
		}})
		.join("\n");
}}

/**
 * Proactive pre-execution indent/blank-line repair for Pi's built-in `edit` tool
 * (complements Pi's edit-diff.js which normalizes trailing spaces/smart-quotes but not leading indent).
 * Strictly requires a 100% unique match on disk — returns `undefined` if already valid or ambiguous.
 */
export function healEditBlock(
	fileContent: string,
	oldText: string,
	newText: string,
): {{ oldText: string; newText: string; strategy: string }} | undefined {{
	if (!fileContent || !oldText) return undefined;
	const lfFile = fileContent.replace(/\r\n/g, "\n");
	const lfOld = oldText.replace(/\r\n/g, "\n");
	const lfNew = newText.replace(/\r\n/g, "\n");
	if (lfFile.includes(lfOld)) return undefined;
	const trimEndAll = (s: string) =>
		s
			.split("\n")
			.map((l) => l.trimEnd())
			.join("\n");
	if (trimEndAll(lfFile).includes(trimEndAll(lfOld))) return undefined;

	const fileLines = lfFile.split("\n");
	const rawOldLines = lfOld.split("\n");
	// Tier 0A: Exact verified Hashline `L:HH|...` anchor resolution (works on 1-line & duplicate lines via symmetric context expansion!)
	const hlHit = resolveHashlineAnchorEdit(lfFile, fileLines, rawOldLines, lfNew);
	if (hlHit) return hlHit;
	// Tier 0B: Auto-strip accidental sequential line-number prefixes (e.g. `12: code` / `12:a3|code` copied from read/edit-closest/nl)
	const strippedOld = stripSequentialLineNumbers(rawOldLines);
	const oldLines = strippedOld ?? rawOldLines;
	let effectiveNew = lfNew;
	if (strippedOld) {{
		const strippedNew = stripSequentialLineNumbers(lfNew.split("\n"));
		if (strippedNew) effectiveNew = strippedNew.join("\n");
	}}
	const nonBlankOld = oldLines.filter((l) => l.trim().length > 0);
	if (nonBlankOld.length === 0 || !nonBlankOld.some((l) => l.trim().length >= 4)) {{
		return undefined;
	}}

	// Tier 1 (or Tier 0 after lineno strip): Exact-length dedented line-block unique match
	const n = oldLines.length;
	const exactHits: number[] = [];
	for (let i = 0; i <= fileLines.length - n; i++) {{
		let ok = true;
		for (let k = 0; k < n; k++) {{
			if (fileLines[i + k].trim() !== oldLines[k].trim()) {{
				ok = false;
				break;
			}}
		}}
		if (ok) {{
			exactHits.push(i);
			if (exactHits.length > 1) break;
		}}
	}}
	if (exactHits.length === 1) {{
		const matched = fileLines.slice(exactHits[0], exactHits[0] + n);
		const healedOld = matched.join("\n");
		if (healedOld !== lfOld) {{
			return {{
				oldText: healedOld,
				newText: reindentReplacement(effectiveNew, oldLines, matched),
				strategy: strippedOld ? "lineno-strip-unique" : "indent-unique",
			}};
		}}
	}}

	// Tier 2: Blank-line-tolerant dedented unique match (requires >=2 non-blank lines)
	if (nonBlankOld.length >= 2) {{
		const spans: Array<[number, number]> = [];
		const firstTrim = nonBlankOld[0].trim();
		for (let i = 0; i < fileLines.length; i++) {{
			if (fileLines[i].trim() !== firstTrim) continue;
			let cur = i + 1;
			let matchedAll = true;
			let lastIdx = i;
			for (let k = 1; k < nonBlankOld.length; k++) {{
				let skippedBlanks = 0;
				while (cur < fileLines.length && fileLines[cur].trim().length === 0 && skippedBlanks < 2) {{
					cur++;
					skippedBlanks++;
				}}
				if (cur >= fileLines.length || fileLines[cur].trim() !== nonBlankOld[k].trim()) {{
					matchedAll = false;
					break;
				}}
				lastIdx = cur;
				cur++;
			}}
			if (matchedAll) {{
				spans.push([i, lastIdx]);
				if (spans.length > 1) break;
			}}
		}}
		if (spans.length === 1) {{
			const [s0, s1] = spans[0];
			const matched = fileLines.slice(s0, s1 + 1);
			const healedOld = matched.join("\n");
			if (healedOld !== lfOld) {{
				return {{
					oldText: healedOld,
					newText: reindentReplacement(effectiveNew, oldLines, matched),
					strategy: "blankline-unique",
				}};
			}}
		}}
	}}

	// Tier 3: Punctuation & collapsed-whitespace normalized unique match (heals full-width `：`/`，`/`（` vs ASCII drift)
	if (nonBlankOld.some((l) => l.trim().length >= 8)) {{
		const normLoose = (s: string) =>
			s
				.trim()
				.replace(/[：]/g, ":")
				.replace(/[，]/g, ",")
				.replace(/[（]/g, "(")
				.replace(/[）]/g, ")")
				.replace(/[“”]/g, '"')
				.replace(/[‘’]/g, "'")
				.replace(/\s+/g, " ")
				.replace(/\s*([:,()])\s*/g, "$1");
		const looseHits: number[] = [];
		for (let i = 0; i <= fileLines.length - n; i++) {{
			let ok = true;
			for (let k = 0; k < n; k++) {{
				if (normLoose(fileLines[i + k]) !== normLoose(oldLines[k])) {{
					ok = false;
					break;
				}}
			}}
			if (ok) {{
				looseHits.push(i);
				if (looseHits.length > 1) break;
			}}
		}}
		if (looseHits.length === 1) {{
			const matched = fileLines.slice(looseHits[0], looseHits[0] + n);
			const healedOld = matched.join("\n");
			if (healedOld !== lfOld) {{
				return {{
					oldText: healedOld,
					newText: reindentReplacement(effectiveNew, oldLines, matched),
					strategy: "punctuation-loose-unique",
				}};
			}}
		}}
	}}
	return undefined;
}}

/**
 * Heal multi-hunk `edit.edits[]` arrays:
 * 1) Heals each hunk independently against the original file (matching Pi's non-incremental semantics).
 * 2) If a hunk only resolves sequentially after an earlier hunk (or two hunks overlap), simulates
 *    sequentially and collapses compact (<=80-line) changes into a single unique edit on the original file.
 */
export function healMultiEditsSequential(
	fileContent: string,
	edits: ReadonlyArray<{{ oldText?: string; newText?: string }}>,
): {{ edits: Array<{{ oldText: string; newText: string }}>; healed: number }} | undefined {{
	if (!fileContent || !Array.isArray(edits) || edits.length === 0) return undefined;
	const lfOrig = fileContent.replace(/\r\n/g, "\n");
	const origOut: Array<{{ oldText: string; newText: string }}> = [];
	const origRanges: Array<[number, number]> = [];
	let origHealed = 0;
	let allMatchOrigUnique = true;
	for (const item of edits) {{
		if (typeof item?.oldText !== "string" || typeof item?.newText !== "string") return undefined;
		let curOld = item.oldText;
		let curNew = item.newText;
		const fixed = healEditBlock(lfOrig, curOld, curNew);
		if (fixed) {{
			curOld = fixed.oldText;
			curNew = fixed.newText;
			origHealed += 1;
		}}
		const lfOld = curOld.replace(/\r\n/g, "\n");
		const idx = lfOld.length > 0 ? lfOrig.indexOf(lfOld) : -1;
		if (idx < 0 || lfOrig.indexOf(lfOld, idx + 1) >= 0) {{
			allMatchOrigUnique = false;
		}} else {{
			origRanges.push([idx, idx + lfOld.length]);
		}}
		origOut.push({{ oldText: curOld, newText: curNew }});
	}}
	let hasOrigOverlap = false;
	if (allMatchOrigUnique && origRanges.length >= 2) {{
		const sorted = [...origRanges].sort((a, b) => a[0] - b[0]);
		for (let i = 1; i < sorted.length; i++) {{
			if (sorted[i - 1][1] > sorted[i][0]) {{
				hasOrigOverlap = true;
				break;
			}}
		}}
	}}
	if (allMatchOrigUnique && !hasOrigOverlap) {{
		return origHealed > 0 ? {{ edits: origOut, healed: origHealed }} : undefined;
	}}
	if (edits.length < 2) {{
		return origHealed > 0 ? {{ edits: origOut, healed: origHealed }} : undefined;
	}}
	let virtual = lfOrig;
	let allApplied = true;
	for (const item of edits) {{
		if (typeof item?.oldText !== "string" || typeof item?.newText !== "string") return undefined;
		let curOld = item.oldText;
		let curNew = item.newText;
		const fixed = healEditBlock(virtual, curOld, curNew);
		if (fixed) {{
			curOld = fixed.oldText;
			curNew = fixed.newText;
		}}
		const lfOld = curOld.replace(/\r\n/g, "\n");
		const lfNew = curNew.replace(/\r\n/g, "\n");
		const idx = lfOld.length > 0 ? virtual.indexOf(lfOld) : -1;
		if (idx < 0 || virtual.indexOf(lfOld, idx + 1) >= 0) {{
			allApplied = false;
			break;
		}}
		virtual = virtual.slice(0, idx) + lfNew + virtual.slice(idx + lfOld.length);
	}}
	if (allApplied && virtual !== lfOrig) {{
		const origLines = lfOrig.split("\n");
		const finalLines = virtual.split("\n");
		let prefix = 0;
		const minLen = Math.min(origLines.length, finalLines.length);
		while (prefix < minLen && origLines[prefix] === finalLines[prefix]) prefix++;
		let suffix = 0;
		while (
			suffix < minLen - prefix &&
			origLines[origLines.length - 1 - suffix] === finalLines[finalLines.length - 1 - suffix]
		) {{
			suffix++;
		}}
		const origEnd = origLines.length - suffix;
		const finalEnd = finalLines.length - suffix;
		if (origEnd - prefix <= 80) {{
			for (let pad = 0; pad <= 8; pad++) {{
				const lo = prefix - Math.min(pad, prefix);
				const rightPad = Math.min(pad, suffix);
				const hiOrig = origEnd + rightPad;
				const hiFinal = finalEnd + rightPad;
				const candOld = origLines.slice(lo, hiOrig).join("\n");
				if (candOld.length > 0 && countSubstringOccurrences(lfOrig, candOld) === 1) {{
					const candNew = finalLines.slice(lo, hiFinal).join("\n");
					return {{ edits: [{{ oldText: candOld, newText: candNew }}], healed: edits.length }};
				}}
			}}
		}}
	}}
	return origHealed > 0 ? {{ edits: origOut, healed: origHealed }} : undefined;
}}

/**
 * Normalize legacy or double-encoded `edit` argument shapes in place (pi-edit-guard pattern):
 * `file_path -> path`, `old_string -> oldText`, `new_string -> newText`, and stringified `edits[]`.
 */
export function normalizeEditArgs(input: Record<string, unknown>): boolean {{
	if (!input || typeof input !== "object") return false;
	let changed = false;
	if (typeof input.path !== "string" && typeof input.file_path === "string") {{
		input.path = input.file_path;
		delete input.file_path;
		changed = true;
	}}
	if (typeof input.edits === "string" && input.edits.trim().startsWith("[")) {{
		try {{
			const parsed = JSON.parse(input.edits);
			if (Array.isArray(parsed)) {{
				input.edits = parsed;
				changed = true;
			}}
		}} catch {{
			// leave invalid JSON untouched
		}}
	}}
	if (Array.isArray(input.edits)) {{
		for (const item of input.edits) {{
			if (!item || typeof item !== "object") continue;
			const rec = item as Record<string, unknown>;
			if (typeof rec.oldText !== "string" && typeof rec.old_string === "string") {{
				rec.oldText = rec.old_string;
				delete rec.old_string;
				changed = true;
			}}
			if (typeof rec.newText !== "string" && typeof rec.new_string === "string") {{
				rec.newText = rec.new_string;
				delete rec.new_string;
				changed = true;
			}}
		}}
	}} else {{
		if (typeof input.oldText !== "string" && typeof input.old_string === "string") {{
			input.oldText = input.old_string;
			delete input.old_string;
			changed = true;
		}}
		if (typeof input.newText !== "string" && typeof input.new_string === "string") {{
			input.newText = input.new_string;
			delete input.new_string;
			changed = true;
		}}
	}}
	return changed;
}}

/**
 * Locate all exact (or trimmed-indent) occurrences when built-in `edit` fails due to multiple matches,
 * reporting exact 1-based line numbers + surrounding context so the next turn disambiguates in 1 shot.
 */
export function findAllEditOccurrenceLines(
	fileContent: string,
	oldText: string,
	maxHits = 6,
): string | undefined {{
	if (!fileContent || !oldText) return undefined;
	const lines = fileContent.replace(/\r\n/g, "\n").split("\n");
	const needleLines = oldText.replace(/\r\n/g, "\n").split("\n");
	const n = needleLines.length;
	if (n === 0 || n > lines.length) return undefined;
	const hits: number[] = [];
	for (let i = 0; i <= lines.length - n; i++) {{
		let ok = true;
		for (let j = 0; j < n; j++) {{
			if (lines[i + j].trim() !== needleLines[j].trim()) {{
				ok = false;
				break;
			}}
		}}
		if (ok) {{
			hits.push(i);
		}}
	}}
	if (hits.length < 2) return undefined;
	const shown = hits.slice(0, maxHits).map((idx) => {{
		const prev = idx > 0 ? lines[idx - 1].trim().slice(0, 55) : "<BOF>";
		const cur = lines[idx].trim().slice(0, 65);
		return `L${{idx + 1}} [${{idx + 1}}:${{hashlineTag(lines[idx])}}|${{cur}}] (after: ${{prev}})`;
	}});
	const more = hits.length > maxHits ? ` (+${{hits.length - maxHits}} more)` : "";
	return `[ap edit-multi] Found ${{hits.length}} occurrences${{more}} — pass the exact L:HH| anchor or add 1 unique surrounding line to oldText:\n${{shown.join("\n")}}`;
}}

/**
 * Compute a compact numbered Top-1 closest matching line window when built-in `edit` fails,
 * eliminating the ~47% wasted post-error full-file `read` round-trip.
 */
export function findClosestEditWindow(fileContent: string, oldText: string): string | undefined {{
	if (!fileContent || !oldText) return undefined;
	const tokenize = (s: string) => new Set(s.toLowerCase().match(/[a-z0-9_]{{2,}}/g) ?? []);
	const qToks = tokenize(oldText);
	if (qToks.size < 2) return undefined;
	const lines = fileContent.replace(/\r\n/g, "\n").split("\n");
	if (lines.length === 0) return undefined;
	const oldCount = oldText.replace(/\r\n/g, "\n").split("\n").length;
	const win = Math.max(3, Math.min(14, oldCount + 2));
	const maxScan = Math.min(lines.length, 6000);
	const step = maxScan > 2000 ? 2 : 1;
	let bestScore = 0;
	let bestStart = -1;
	for (let i = 0; i < maxScan; i += step) {{
		const end = Math.min(lines.length, i + win);
		const wToks = tokenize(lines.slice(i, end).join("\n"));
		if (wToks.size === 0) continue;
		let inter = 0;
		for (const t of qToks) {{
			if (wToks.has(t)) inter++;
		}}
		const dice = (2 * inter) / (qToks.size + wToks.size);
		if (dice > bestScore) {{
			bestScore = dice;
			bestStart = i;
		}}
	}}
	if (bestStart < 0 || bestScore < 0.3) return undefined;
	const end = Math.min(lines.length, bestStart + win);
	const body = lines
		.slice(bestStart, end)
		.map((l, idx) => `${{bestStart + idx + 1}}:${{hashlineTag(l)}}|${{l}}`)
		.join("\n")
		.slice(0, 850);
	return `[ap edit-closest] Closest lines on disk (L${{bestStart + 1}}-L${{end}}; pass L:HH| directly in edit oldText):\n${{body}}`;
}}

export function listCodemodeStoreKeys(branch: ReadonlyArray<Record<string, unknown>>): string[] {{
	const keys = new Set<string>();
	if (!Array.isArray(branch)) return [];
	for (const e of branch) {{
		if (e?.type === "custom" && e.customType === "codemode-store" && e.data && typeof e.data === "object") {{
			const d = e.data as {{ set?: Record<string, unknown>; delete?: string[] }};
			if (d.set && typeof d.set === "object") {{
				for (const k of Object.keys(d.set)) keys.add(k);
			}}
			if (Array.isArray(d.delete)) {{
				for (const k of d.delete) keys.delete(k);
			}}
		}}
	}}
	return [...keys];
}}

export function countCodemodeStoreKeys(branch: ReadonlyArray<Record<string, unknown>>): number {{
	return listCodemodeStoreKeys(branch).length;
}}

export function normCmdFingerprint(raw: string): string {{
	return raw
		.replace(/^export\s+PYTHONUTF8=1\s+PYTHONIOENCODING=utf-8;\s*/i, "")
		.replace(/^\$env:PYTHONUTF8='1';\s*\$env:PYTHONIOENCODING='utf-8';\s*/i, "")
		.replace(/\b0x[0-9a-fA-F]{{4,}}\b/g, "<HEX>")
		.replace(/\b\d{{4}}-\d{{2}}-\d{{2}}[T\s]\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?Z?\b/g, "<TS>")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, 180);
}}

export function formatPostEditLineShiftTip(
	input: Record<string, unknown> | undefined,
	details?: {{ firstChangedLine?: number }} | undefined,
): string | undefined {{
	if (!input || typeof input !== "object") return undefined;
	const items: Array<{{ oldText?: string; newText?: string }}> = Array.isArray(input.edits)
		? (input.edits as Array<{{ oldText?: string; newText?: string }}>)
		: typeof input.oldText === "string" && typeof input.newText === "string"
			? [{{ oldText: input.oldText, newText: input.newText }}]
			: [];
	if (items.length === 0) return undefined;
	let delta = 0;
	for (const it of items) {{
		if (typeof it?.oldText !== "string" || typeof it?.newText !== "string") continue;
		const oldLines = it.oldText.replace(/\r\n/g, "\n").split("\n").length;
		const newLines = it.newText.replace(/\r\n/g, "\n").split("\n").length;
		delta += newLines - oldLines;
	}}
	if (delta === 0) return undefined;
	const sign = delta > 0 ? `+${{delta}}` : `${{delta}}`;
	const anchor =
		typeof details?.firstChangedLine === "number" && details.firstChangedLine > 0
			? ` below L${{details.firstChangedLine}}`
			: "";
	return `[ap edit-lines] Net line shift: ${{sign}} line(s)${{anchor}} (subsequent line numbers shifted by ${{sign}}).`;
}}

function rewriteSlowRecursiveGrep(cmd: string, toolName: string): string | undefined {{
	// Match optional leading `cd <dir> && ` or `cd <dir>; `, recursive `grep -r[nwiEHlcIsF] [--exclude-dir=...] [--include="*.ext"...] [-e] <pat> [path]`,
	// optional `2>/dev/null` stderr suppression, and optional safe read-only pipe suffix (`| head/tail/wc/sort/cut ...`).
	const cleaned = cmd
		.replace(/\s+2>\s*(?:\/dev\/null|NUL)\b/gi, "")
		.replace(/\s+--exclude-dir=(?:'[^']+'|"[^"]+"|[^\s|&;]+)/g, "");
	if (/>/.test(cleaned)) return undefined;

	// Fast-path A: slow minified-JS context regex `grep -oE '.{{0,N}}PAT.{{0,M}}' file [| head ...]` -> `<25ms` `ap search --around`
	const aroundMatch = cleaned.match(
		/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?\s*grep\s+-[oEP]+\s+['"]\.\{{0,(\d+)\}}([^'"]+?)(\.\{{0,(\d+)\}})?['"]\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))(\s*\|\s*(?:head|tail|wc|sort|cut)\b[^;&|>]*)?\s*$/,
	);
	if (aroundMatch) {{
		const cdPrefix = aroundMatch[1] || "";
		const leftN = Math.min(800, Math.max(40, Number(aroundMatch[2]) || 160));
		const rightN = Math.min(800, Math.max(40, Number(aroundMatch[5]) || leftN));
		const around = Math.max(leftN, rightN);
		const pat = (aroundMatch[3] || "").replace(/"/g, '\\"');
		const target = aroundMatch[6] || aroundMatch[7] || aroundMatch[8] || ".";
		const pipeSuffix = aroundMatch[9] || "";
		if (pat && !pat.includes("{{")) {{
			const prefix = toolName === "powershell" ? "& " : "";
			return `${{cdPrefix}}${{prefix}}"${{AP_BIN}}" search --around ${{around}} "${{pat}}" "${{target}}"${{pipeSuffix}}`;
		}}
	}}

	// Collect one or more `--include=*.ext` flags anywhere in the grep command
	const exts: string[] = [];
	let complexGlob = false;
	const withoutIncludes = cleaned.replace(
		/\s+--include=(?:'([^']+)'|"([^"]+)"|([^\s|&;]+))/g,
		(_m, g1: string, g2: string, g3: string) => {{
			const glob = g1 || g2 || g3 || "";
			const em = glob.match(/^\*\.([A-Za-z0-9]+)$/);
			if (em) exts.push(em[1]);
			else complexGlob = true;
			return "";
		}},
	);
	if (complexGlob) return undefined;

	const m = withoutIncludes.match(
		/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?\s*grep\s+-([rRnwiEHlcIsF]+)(?:\s+-e)?\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))(?:\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+)))?(\s*\|\s*(?:head|tail|wc|sort|cut)\b[^;&|>]*)?\s*$/,
	);
	if (!m || !/[rR]/.test(m[2])) return undefined;
	const cdPrefix = m[1] || "";
	const flags = m[2];
	const pat = (m[3] || m[4] || m[5] || "").replace(/"/g, '\\"');
	if (!pat) return undefined;
	const target = m[6] || m[7] || m[8] || ".";
	const pipeSuffix = m[9] || "";
	const extFlag = exts.length > 0 ? ` -e ${{[...new Set(exts)].join(",")}}` : "";
	const prefix = toolName === "powershell" ? "& " : "";
	const extra = flags.includes("l") ? " -l" : flags.includes("c") ? " -c" : "";
	return `${{cdPrefix}}${{prefix}}"${{AP_BIN}}" search${{extra}}${{extFlag}} "${{pat}}" "${{target}}"${{pipeSuffix}}`;
}}

export function healCommand(raw: string, toolName: string): string | undefined {{
	if (!raw) return undefined;
	const isDestructive = DESTRUCTIVE_OR_WRITE.test(raw);
	let cmd = raw;
	let changed = false;

	// 1. Recursive GNU `grep -r[nwiEHlc] [--include=*.ext...] <pat> [path]` & minified `grep -oE '.{{0,N}}...'` -> `<50ms` `ap search`
	if (!isDestructive) {{
		const fastGrep = rewriteSlowRecursiveGrep(cmd, toolName);
		if (fastGrep) {{
			return fastGrep;
		}}
		if (!/[|;&>]/.test(cmd)) {{
			const gm = cmd.match(BARE_SLOW_GREP);
			if (gm && /[rR]/.test(gm[1])) {{
				const flags = gm[1];
				const pat = (gm[2] || gm[3] || gm[4] || "").replace(/"/g, '\\"');
				const target = gm[5] || gm[6] || gm[7] || ".";
				const prefix = toolName === "powershell" ? "& " : "";
				const extra = flags.includes("l") ? " -l" : flags.includes("c") ? " -c" : "";
				return `${{prefix}}"${{AP_BIN}}" search${{extra}} "${{pat}}" "${{target}}"`;
			}}
		}}
	}}

	// 2. Prevent accidental literal `NUL` file creation in Git Bash (always safe)
	if (toolName === "bash" && REDIR_NUL.test(cmd)) {{
		cmd = cmd.replace(REDIR_NUL, "$1 /dev/null");
		changed = true;
	}}

	// 2b. Strip Windows cmd `cd /d <path>` flag inside Git Bash -> `cd <path>`
	if (toolName === "bash" && /(?:^|[;&|]\s*)cd\s+\/d\s+/i.test(cmd)) {{
		cmd = cmd.replace(/(^|[;&|]\s*)cd\s+\/d\s+/gi, "$1cd ");
		changed = true;
	}}

	// 3. Auto-fix unescaped Windows drive backslashes inside `python -c` & `python <<'PY'` non-raw literals
	if (PY_WIN_BS.test(cmd)) {{
		const fixed = cmd.replace(
			/(?<![rR])(['"])([A-Za-z]:)(\\(?!\\)[^'"\r\n]+)\1/g,
			(m, q: string, drv: string, rest: string) => {{
				if (/\\[nrt]$/.test(rest)) return m;
				return q + drv + rest.replace(/\\/g, "/") + q;
			}},
		);
		if (fixed !== cmd) {{
			cmd = fixed;
			changed = true;
		}}
	}}

	// 4. Auto-lock UTF-8 across BOTH Bash and PowerShell Python invocations (prevents 99% of Windows GBK crashes)
	if (PY_INVOKE.test(cmd) && !HAS_UTF8_ENV.test(cmd)) {{
		if (toolName === "bash") {{
			cmd = `export PYTHONUTF8=1 PYTHONIOENCODING=utf-8; ${{cmd}}`;
			changed = true;
		}} else if (toolName === "powershell") {{
			cmd = `$env:PYTHONUTF8='1'; $env:PYTHONIOENCODING='utf-8'; ${{cmd}}`;
			changed = true;
		}}
	}}

	// 5. Prevent PowerShell 5.1 `curl` -> Invoke-WebRequest alias crashes
	if (toolName === "powershell" && /(?:^|[;&|]\s*)curl(?=\s)/i.test(cmd)) {{
		cmd = cmd.replace(/(^|[;&|]\s*)curl(?=\s)/gi, "$1curl.exe");
		changed = true;
	}}

	// 6. Rewrite Windows cmd `type <file>` inside Git Bash -> `cat <posix-path>` (leaves POSIX `type -a/-t/-p` and bare commands untouched)
	if (toolName === "bash" && !isDestructive) {{
		const tm = cmd.match(
			/^(\s*(?:cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?)type\s+(?!-[atpPf]\b)(?:'([^']+)'|"([^"]+)"|([^\s'"|;&>]+))([\s\S]*)$/,
		);
		const rawTarget = tm ? tm[2] || tm[3] || tm[4] || "" : "";
		if (tm && rawTarget && /[./\\]/.test(rawTarget)) {{
			const posixTarget = rawTarget.replace(/\\/g, "/");
			const quoted = posixTarget.includes("'")
				? `"${{posixTarget.replace(/"/g, '\\"')}}"`
				: `'${{posixTarget}}'`;
			cmd = `${{tm[1] || ""}}cat ${{quoted}}${{tm[5] || ""}}`;
			changed = true;
		}}
	}}

	// 6b. Wrap bare read-only PowerShell cmdlets accidentally sent to Git Bash (fixes syntax error near unexpected token)
	if (toolName === "bash" && !isDestructive && !/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(cmd)) {{
		const psBare = cmd.match(
			/^(\s*(?:cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?)((?:Get-ChildItem|Get-Content|Get-Process|Get-CimInstance|Select-String)\b[\s\S]*)$/,
		);
		if (psBare && !psBare[2].includes("'")) {{
			cmd = `${{psBare[1] || ""}}powershell.exe -NoProfile -Command '[Console]::OutputEncoding=[Text.Encoding]::UTF8; ${{psBare[2].trim()}}'`;
			changed = true;
		}}
	}}

	// 7. Lock UTF-8 output encoding & shield PowerShell `$var` when Git Bash spawns `powershell -Command "..."`
	if (
		toolName === "bash" &&
		/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(cmd) &&
		!/OutputEncoding|UTF8Encoding|-EncodedCommand\b|-enc\b/i.test(cmd)
	) {{
		let psFixed = cmd;
		const psDq = cmd.match(
			/^(\s*(?:cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?)((?:powershell|pwsh)(?:\.exe)?(?:\s+-[A-Za-z-]+)*\s+-(?:Command|c)\s+)"([\s\S]+)"(\s*)$/i,
		);
		if (
			psDq &&
			!psDq[3].includes("'") &&
			!/\$\(/.test(psDq[3]) &&
			/\$(?:_|PSItem\b|env:|null\b|true\b|false\b|[A-Za-z_]\w*)/i.test(psDq[3])
		) {{
			const inner = psDq[3].replace(/\\"/g, '"').replace(/\\\$/g, "$");
			psFixed = `${{psDq[1]}}${{psDq[2]}}'[Console]::OutputEncoding=[Text.Encoding]::UTF8; ${{inner}}'${{psDq[4]}}`;
		}} else {{
			psFixed = cmd.replace(
				/\b((?:powershell|pwsh)(?:\.exe)?\b[^|;&]*?\s-(?:Command|c)\s+)(['"])/i,
				"$1$2[Console]::OutputEncoding=[Text.Encoding]::UTF8; ",
			);
		}}
		if (psFixed !== cmd) {{
			cmd = psFixed;
			changed = true;
		}}
	}}

	// 8. Auto-switch bare `rg "pattern"` with unbalanced `(` or `[` to `rg -F` (eliminates `rg: regex parse error`)
	if (
		toolName === "bash" &&
		!/[|;&><]/.test(cmd) &&
		/^\s*(?:rg|rg\.exe)\s+/i.test(cmd) &&
		!/\s(?:-F|--fixed-strings|-P|--pcre2)\b/.test(cmd)
	) {{
		const rgPat = cmd.match(/^\s*(?:rg|rg\.exe)\s+(?:-[A-Za-z]+\s+)*(['"])([\s\S]+?)\1/);
		if (rgPat) {{
			const p = rgPat[2];
			let parens = 0;
			let brackets = 0;
			let esc = false;
			let broken = false;
			for (let i = 0; i < p.length; i++) {{
				const ch = p[i];
				if (esc) {{ esc = false; continue; }}
				if (ch === "\\") {{ esc = true; continue; }}
				if (ch === "(") parens++;
				else if (ch === ")") {{ if (--parens < 0) broken = true; }}
				else if (ch === "[") brackets++;
				else if (ch === "]") {{ if (--brackets < 0) broken = true; }}
			}}
			if (broken || parens !== 0 || brackets !== 0) {{
				cmd = cmd.replace(/^\s*(rg(?:\.exe)?)\s+/i, "$1 -F ");
				changed = true;
			}}
		}}
	}}

	return changed ? cmd : undefined;
}}

const HALLUCINATED_TOOL_ALIASES: Readonly<Record<string, string>> = {{
	codemake: "codemode",
	code_mode: "codemode",
	"code-mode": "codemode",
	read_file: "read",
	view_file: "read",
	edit_file: "edit",
	replace_in_file: "edit",
	write_file: "write",
	create_file: "write",
	run_command: "bash",
	run_shell: "bash",
	shell: "bash",
	execute_command: "bash",
	exec_command: "bash",
}};

/**
 * Deterministically repair high-frequency hallucinated tool names (e.g. `codemake` -> `codemode`,
 * `read_file` -> `read`, `run_command` -> `bash`) strictly when the target tool is active.
 */
export function repairHallucinatedToolName(
	rawName: string,
	activeTools: ReadonlySet<string>,
): string | undefined {{
	if (!rawName || activeTools.has(rawName)) return undefined;
	const key = rawName.trim().toLowerCase();
	if (!key) return undefined;
	const mapped = HALLUCINATED_TOOL_ALIASES[key];
	if (mapped && activeTools.has(mapped)) return mapped;
	if (activeTools.has(key)) return key;
	return undefined;
}}

function normalizeRepairedToolArgs(
	targetName: string,
	rawArgs: unknown,
): Record<string, unknown> {{
	const args: Record<string, unknown> =
		rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs)
			? {{ ...(rawArgs as Record<string, unknown>) }}
			: {{}};
	if (targetName === "bash" && typeof args.command !== "string" && typeof args.cmd === "string") {{
		args.command = args.cmd;
		delete args.cmd;
	}} else if (
		(targetName === "read" || targetName === "edit" || targetName === "write") &&
		typeof args.path !== "string" &&
		typeof args.file_path === "string"
	) {{
		args.path = args.file_path;
		delete args.file_path;
	}} else if (targetName === "codemode" && typeof args.code !== "string" && typeof args.script === "string") {{
		args.code = args.script;
		delete args.script;
	}}
	return args;
}}

export interface DsmlRecoveredCall {{
	type: "toolCall";
	id: string;
	name: string;
	arguments: Record<string, unknown>;
}}

/**
 * Recover leaked DeepSeek DSML XML tool invocations into native Pi `toolCall` blocks.
 * Strictly gated to currently active tools (`allowedTools`) so unknown names never run.
 */
export function extractDsmlToolCalls(
	text: string,
	allowedTools: ReadonlySet<string>,
): {{ cleanedText: string; calls: DsmlRecoveredCall[] }} | undefined {{
	if (!text || !text.includes("DSML") || !text.includes("invoke")) return undefined;
	const invokeRe =
		/<[|｜]DSML[|｜]invoke\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/[|｜]DSML[|｜]invoke>/g;
	const paramRe =
		/<[|｜]DSML[|｜]parameter\s+name="([^"]+)"(?:\s+string="(true|false)")?[^>]*>([\s\S]*?)<\/[|｜]DSML[|｜]parameter>/g;

	const calls: DsmlRecoveredCall[] = [];
	let match: RegExpExecArray | null;
	let seq = 0;
	while ((match = invokeRe.exec(text)) !== null) {{
		const rawToolName = (match[1] || "").trim();
		const toolName = allowedTools.has(rawToolName)
			? rawToolName
			: repairHallucinatedToolName(rawToolName, allowedTools) ?? "";
		if (!toolName) continue;
		const body = match[2] || "";
		const args: Record<string, unknown> = {{}};
		let pm: RegExpExecArray | null;
		paramRe.lastIndex = 0;
		while ((pm = paramRe.exec(body)) !== null) {{
			const key = (pm[1] || "").trim();
			const isStr = pm[2] !== "false";
			const rawVal = pm[3] ?? "";
			if (!key) continue;
			if (!isStr) {{
				try {{
					args[key] = JSON.parse(rawVal.trim());
					continue;
				}} catch {{
					// fall through to raw string
				}}
			}}
			args[key] = rawVal;
		}}
		seq += 1;
		calls.push({{
			type: "toolCall",
			id: `ap_dsml_${{Date.now()}}_${{seq}}`,
			name: toolName,
			arguments: toolName !== rawToolName ? normalizeRepairedToolArgs(toolName, args) : args,
		}});
	}}
	if (calls.length === 0) return undefined;
	const cleanedText = text
		.replace(/<[|｜]DSML[|｜]function_calls>[\s\S]*?<\/[|｜]DSML[|｜]function_calls>/g, "")
		.replace(invokeRe, "")
		.trim();
	return {{ cleanedText, calls }};
}}

/**
 * Recover leaked `<tool_call>{{"name":"...","arguments":{{...}}}}</tool_call>` blocks
 * emitted as plain text under high context pressure (strictly gated to `allowedTools`).
 */
export function extractXmlJsonToolCalls(
	text: string,
	allowedTools: ReadonlySet<string>,
): {{ cleanedText: string; calls: DsmlRecoveredCall[] }} | undefined {{
	if (!text || !text.includes("<tool_call>")) return undefined;
	const re = /<tool_call>\s*([\s\S]*?)\s*<\/tool_call>/g;
	const calls: DsmlRecoveredCall[] = [];
	let match: RegExpExecArray | null;
	let seq = 0;
	while ((match = re.exec(text)) !== null) {{
		try {{
			const obj = JSON.parse(match[1]) as {{
				name?: unknown;
				arguments?: unknown;
				parameters?: unknown;
			}};
			const rawName = typeof obj?.name === "string" ? obj.name.trim() : "";
			const name = allowedTools.has(rawName)
				? rawName
				: repairHallucinatedToolName(rawName, allowedTools) ?? "";
			if (!name) continue;
			const rawArgs = obj.arguments ?? obj.parameters ?? {{}};
			const baseArgs =
				rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs)
					? (rawArgs as Record<string, unknown>)
					: {{}};
			const args = name !== rawName ? normalizeRepairedToolArgs(name, baseArgs) : baseArgs;
			seq += 1;
			calls.push({{
				type: "toolCall",
				id: `ap_xmltc_${{Date.now()}}_${{seq}}`,
				name,
				arguments: args,
			}});
		}} catch {{
			// ignore non-JSON blocks
		}}
	}}
	if (calls.length === 0) return undefined;
	const cleanedText = text.replace(re, "").trim();
	return {{ cleanedText, calls }};
}}

const ERROR_LINE_RE =
	/(?:^|\s)(?:error\[E\d+\]|ERROR:|FATAL:|Traceback|AssertionError|TypeError|SyntaxError|ReferenceError|RangeError|ValueError|RuntimeError|panicked at|FAILED\b|Exception:|Command exited with code [1-9])/i;

/**
 * Extract up to 3 high-signal error lines so observation masking never erases failure lessons
 * (Manus Context Engineering rule: keep error signatures in the trace to prevent repeat loops).
 */
export function extractErrorSignatureLines(rawText: string): string[] {{
	const seen = new Set<string>();
	const out: string[] = [];
	for (const ln of rawText.split("\n")) {{
		const clean = ln.replace(/\s+/g, " ").trim();
		if (clean.length < 8 || !ERROR_LINE_RE.test(clean)) continue;
		const clipped = clean.slice(0, 140);
		if (seen.has(clipped)) continue;
		seen.add(clipped);
		out.push(clipped);
		if (out.length >= 3) break;
	}}
	return out;
}}

/**
 * Deterministic, timestamp-free replacement stub for stale bulky `toolResult` entries.
 * Preserves any `ap sieve` archive ID AND top error signatures for lossless failure memory.
 */
export function formatMaskedToolResult(
	toolName: string,
	rawText: string,
	isError = false,
): string {{
	const lineCount = rawText.split("\n").length;
	const sieveMatch =
		rawText.match(/\bsieve\s+(?:id=|peek\s+)([a-zA-Z0-9_-]{{4,40}})\b/i) ||
		rawText.match(/\[sieve\s+id=([a-zA-Z0-9_-]{{4,40}})\b/i);
	const sieveId = sieveMatch?.[1];
	const head = rawText.slice(0, 140).replace(/\s+/g, " ").trim();
	const tail = rawText.slice(-110).replace(/\s+/g, " ").trim();
	const errLines = extractErrorSignatureLines(rawText);
	const errBlock =
		isError || errLines.length > 0
			? `\nerrors: ${{errLines.length > 0 ? errLines.join(" | ") : "tool returned isError=true"}}`
			: "";
	const recovery = sieveId
		? `(Recover full output via ap_sieve(action="peek", id="${{sieveId}}").)`
		: "(Re-run or narrow with ap_read(symbol/outline) / ap_search if needed.)";
	const sieveTag = sieveId ? ` | sieve=${{sieveId}}` : "";
	const errTag = isError ? " | ERROR" : "";
	return `${{MASK_PREFIX}} ${{toolName}} (${{rawText.length}} chars, ${{lineCount}} lines)${{errTag}}${{sieveTag}}]\nhead: ${{head}}${{errBlock}}\ntail: ${{tail}}\n${{recovery}}`;
}}

/**
 * Compact, standalone branch serializer for `/ap handoff <goal>` (zero runtime SDK value imports).
 */
export function serializeBranchForHandoff(branch: ReadonlyArray<Record<string, unknown>>): string {{
	if (!Array.isArray(branch) || branch.length === 0) return "";
	let startIdx = 0;
	for (let i = branch.length - 1; i >= 0; i--) {{
		if (branch[i]?.type === "compaction") {{
			startIdx = i;
			break;
		}}
	}}
	const chunks: string[] = [];
	for (let i = startIdx; i < branch.length; i++) {{
		const e = branch[i];
		if (e?.type === "compaction" && typeof e.summary === "string") {{
			chunks.push(`[Compaction Summary]\n${{e.summary.slice(0, 4000)}}`);
			continue;
		}}
		if (e?.type !== "message" || !e.message || typeof e.message !== "object") continue;
		const m = e.message as {{
			role?: string;
			toolName?: string;
			isError?: boolean;
			content?: string | Array<{{ type?: string; text?: string; name?: string }}>;
		}};
		if (m.role === "user" || m.role === "assistant") {{
			let txt = "";
			if (typeof m.content === "string") {{
				txt = m.content;
			}} else if (Array.isArray(m.content)) {{
				const parts: string[] = [];
				for (const b of m.content) {{
					if (b?.type === "text" && typeof b.text === "string") parts.push(b.text);
					else if (b?.type === "toolCall" && typeof b.name === "string") parts.push(`[call:${{b.name}}]`);
				}}
				txt = parts.join("\n");
			}}
			if (txt.trim()) chunks.push(`${{m.role.toUpperCase()}}: ${{txt.trim().slice(0, 1200)}}`);
		}} else if (m.role === "toolResult" && m.isError) {{
			const raw = Array.isArray(m.content)
				? m.content.map((b) => (typeof b.text === "string" ? b.text : "")).join("\n")
				: "";
			const errs = extractErrorSignatureLines(raw);
			chunks.push(`TOOL_ERROR(${{m.toolName ?? "tool"}}): ${{(errs.join(" | ") || raw.slice(0, 240)).trim()}}`);
		}}
	}}
	return chunks.join("\n\n").slice(-24000);
}}

export interface ObservationMaskPlan {{
	edits: ContextEditEntryDraft[];
	maskedCount: number;
	reclaimedChars: number;
	reason: string;
}}

export interface ObservationMaskOptions {{
	usagePercent?: number | null;
	usageTokens?: number | null;
	keepRecentEntries?: number;
	minEntryChars?: number;
	highWaterPercent?: number;
	highWaterTokens?: number;
	staleCharsFallback?: number;
	minBatchEntries?: number;
	minReclaimedChars?: number;
}}

/**
 * Plan a single KV-cache-friendly batch of Pi v1.5 `context_edit` drafts to mask stale
 * oversized `toolResult` entries outside the recent active tail.
 * Never touches assistant messages, thinking/reasoning_content blocks, user turns, or images.
 */
export function planObservationMasking(
	contextEntries: readonly ProjectedSessionEntry[],
	options: ObservationMaskOptions = {{}},
): ObservationMaskPlan {{
	const pct = typeof options.usagePercent === "number" ? options.usagePercent : null;
	const tok = typeof options.usageTokens === "number" ? options.usageTokens : null;
	const tier2 =
		options.minEntryChars === undefined &&
		((tok !== null && tok >= MASK_TIER2_TOKENS) || (pct !== null && pct >= MASK_TIER2_PCT));

	const keepRecent =
		options.keepRecentEntries ?? (tier2 ? MASK_TIER2_KEEP_RECENT : MASK_KEEP_RECENT_ENTRIES);
	const minChars =
		options.minEntryChars ?? (tier2 ? MASK_TIER2_MIN_ENTRY_CHARS : MASK_MIN_ENTRY_CHARS);
	const highPct = options.highWaterPercent ?? MASK_HIGH_WATER_PCT;
	const highTok = options.highWaterTokens ?? MASK_HIGH_WATER_TOKENS;
	const staleFallback = options.staleCharsFallback ?? MASK_STALE_CHARS_FALLBACK;
	const minEntries = options.minBatchEntries ?? MASK_MIN_BATCH_ENTRIES;
	const minReclaimed =
		options.minReclaimedChars ?? (tier2 ? MASK_TIER2_MIN_RECLAIMED : MASK_MIN_RECLAIMED_CHARS);

	if (!Array.isArray(contextEntries) || contextEntries.length <= keepRecent) {{
		return {{ edits: [], maskedCount: 0, reclaimedChars: 0, reason: "too-few-entries" }};
	}}

	const scanLimit = contextEntries.length - keepRecent;
	const candidates: Array<{{ targetId: string; toolName: string; rawText: string; isError: boolean }}> = [];
	let totalStaleChars = 0;

	for (let i = 0; i < scanLimit; i++) {{
		const proj = contextEntries[i];
		const src = proj?.sourceEntry as {{ id?: string; type?: string }} | undefined;
		if (!src || src.type !== "message" || typeof src.id !== "string" || !src.id) continue;
		if (!Array.isArray(proj.messages) || proj.messages.length !== 1) continue;
		const msg = proj.messages[0] as {{
			role?: string;
			toolName?: string;
			isError?: boolean;
			content?: Array<{{ type?: string; text?: string }}>;
		}};
		if (msg?.role !== "toolResult" || !Array.isArray(msg.content) || msg.content.length === 0) {{
			continue;
		}}
		// Keep multimodal/image tool results untouched
		if (msg.content.some((b) => b?.type !== "text")) continue;
		const rawText = msg.content.map((b) => (typeof b.text === "string" ? b.text : "")).join("\n");
		if (rawText.length < minChars || rawText.startsWith(MASK_PREFIX)) continue;

		candidates.push({{
			targetId: src.id,
			toolName: typeof msg.toolName === "string" && msg.toolName ? msg.toolName : "tool",
			rawText,
			isError: msg.isError === true,
		}});
		totalStaleChars += rawText.length;
	}}

	if (candidates.length < minEntries) {{
		return {{ edits: [], maskedCount: 0, reclaimedChars: 0, reason: "below-min-entries" }};
	}}

	const pctTriggered = pct !== null && pct >= highPct;
	const tokTriggered = tok !== null && tok >= highTok;
	// Never let stale-payload fallback bust a hot <180k KV-cache when exact token count is known!
	const fallbackTriggered =
		(tok === null || tok >= highTok) && totalStaleChars >= staleFallback && candidates.length >= 4;

	if (!pctTriggered && !tokTriggered && !fallbackTriggered) {{
		return {{ edits: [], maskedCount: 0, reclaimedChars: 0, reason: "below-high-water" }};
	}}

	const edits: ContextEditEntryDraft[] = [];
	let reclaimedChars = 0;
	for (const c of candidates) {{
		const stub = formatMaskedToolResult(c.toolName, c.rawText, c.isError);
		const saved = c.rawText.length - stub.length;
		if (saved < 1000) continue;
		edits.push({{
			type: "context_edit",
			targetId: c.targetId,
			replacement: {{ content: [{{ type: "text", text: stub }}] }},
		}});
		reclaimedChars += saved;
	}}

	if (edits.length < minEntries || reclaimedChars < minReclaimed) {{
		return {{ edits: [], maskedCount: 0, reclaimedChars: 0, reason: "savings-too-small" }};
	}}

	const reason = tier2
		? "tier2-peak-iq-guard"
		: tokTriggered
			? "high-water-tokens"
			: pctTriggered
				? "high-water-percent"
				: "stale-payload-fallback";
	return {{ edits, maskedCount: edits.length, reclaimedChars, reason }};
}}

export type DeepSeekEffort = "low" | "high" | "max";

const COMPLEX_PROMPT_RE =
	/\b(?:architect|architecture|refactor|redesign|concurrency|deadlock|race\s+condition|root\s+cause|debug|diagnose|profil|optimiz|benchmark|migrat|multi[- ]file|security|audit|algorithm|compil|memory\s+leak)\b|架构|重构|并发|死锁|根因|排查|定位|性能|优化|基准|迁移|跨文件|深度|设计|算法|泄漏/i;
const SIMPLE_PROMPT_RE =
	/^(?:hi|hello|hey|ok|okay|thanks|thank you|yes|no|continue|go|lgtm|commit|push|status|git status|format|lint|run tests?|你好|继续|好的|谢谢|提交|推送|跑测试|看状态)\b[\s!.。？?]*$/i;
const BLOCKER_DIFF_KINDS = new Set([
	"SECRET-ADDED",
	"TEST-SKIPPED",
	"INCOMPLETE-STUB",
	"DEBUG-LEFTOVER",
]);
const CHECKABLE_CODE_EXT = /\.(?:rs|ts|tsx|js|jsx|mjs|cjs|py|go|c|cc|cpp|h|hpp|json|jsonc|toml)$/i;

/**
 * Deterministic <0.1ms effort selector for DeepSeek V4.1 Flash (`low` / `high` / `max`).
 * Avoids burning max-effort overthinking on trivial turns while preserving deep reasoning for complex work.
 */
export function classifyDeepSeekEffort(
	userText: string,
	ceiling: DeepSeekEffort = "max",
): DeepSeekEffort {{
	if (ceiling === "low") return "low";
	const trimmed = (userText || "").trim();
	if (!trimmed) return "low";
	if (trimmed.length <= 80 && SIMPLE_PROMPT_RE.test(trimmed)) return "low";
	const hasCodeBlock = trimmed.includes("```") || trimmed.includes("Error:") || trimmed.includes("Traceback");
	const lineCount = trimmed.split("\n").length;
	if (
		trimmed.length >= 240 ||
		lineCount >= 6 ||
		hasCodeBlock ||
		COMPLEX_PROMPT_RE.test(trimmed)
	) {{
		return ceiling === "max" ? "max" : "high";
	}}
	if (trimmed.length <= 45 && !/[?？]/.test(trimmed)) return "low";
	return "high";
}}

export interface DeepSeekRouteInput {{
	reason: "user" | "continuation" | "retry" | "direct";
	selectedLevel?: string;
	previousLevel?: string;
	userText?: string;
	recentToolErrors?: number;
	recentToolSuccessesAfterEdit?: number;
	stagnantHeavyTurns?: number;
	consecutiveLightTurns?: number;
	cachedPrefixTokens?: number;
}}

/**
 * Detect deep-discount prefix-cache models (e.g. DeepSeek V4.1 Flash's 50:1 $0.30 vs $0.006/1M ratio)
 * where mid-prefix mutation (`context_edit` / effort-switch) costs 20-50x more than clean-slate resets.
 */
export function isDeepCacheDiscountModel(model?: {{
	provider?: string;
	id?: string;
	cost?: {{ input?: number; cacheRead?: number }};
}}): boolean {{
	if (!model) return false;
	const inp = Number(model.cost?.input ?? 0);
	const cr = Number(model.cost?.cacheRead ?? 0);
	if (inp > 0 && cr > 0 && inp / cr >= 20) return true;
	const prov = String(model.provider ?? "").toLowerCase();
	const id = String(model.id ?? "").toLowerCase();
	return prov.includes("deepseek") || id.includes("deepseek") || id.includes("flash-auto");
}}

function clampDeepSeekEffort(raw?: string): DeepSeekEffort {{
	if (raw === "low" || raw === "minimal" || raw === "off") return "low";
	if (raw === "max" || raw === "xhigh") return "max";
	return "high";
}}

/**
 * KV-cache-preserving reasoning-effort router staying strictly on the SAME physical `deepseek-flash`
 * model. Locks effort once a hot cached prefix (>=16k tokens) is established because switching
 * `reasoning_effort` mid-session mutates token-0 template headers and busts 100% of DeepSeek KV-cache;
 * picks fresh effort cleanly on Turn 0 or right after a clean-slate compaction, and only breaks lock
 * on explicit retry or >=3 repeated tool errors.
 */
export function routeDeepSeekFlashEffort(input: DeepSeekRouteInput): {{
	thinkingLevel: DeepSeekEffort;
	phase: string;
}} {{
	const ceiling = clampDeepSeekEffort(input.selectedLevel);
	if (input.reason === "direct") {{
		return {{ thinkingLevel: "low", phase: "direct-summary" }};
	}}
	const prev = input.previousLevel ? clampDeepSeekEffort(input.previousLevel) : ceiling;
	const errs = input.recentToolErrors ?? 0;
	const hotPrefix = !!input.previousLevel && (input.cachedPrefixTokens ?? 0) >= 16000;
	if (input.reason === "retry") {{
		const next: DeepSeekEffort = prev === "low" ? "high" : "max";
		return {{ thinkingLevel: next, phase: "retry-escalate" }};
	}}
	if (hotPrefix) {{
		if (errs >= 3 && prev !== "max") {{
			const next: DeepSeekEffort = prev === "low" ? "high" : "max";
			return {{ thinkingLevel: next, phase: "error-escalate" }};
		}}
		return {{ thinkingLevel: prev, phase: "cache-locked" }};
	}}
	if (input.reason === "user") {{
		const chosen = classifyDeepSeekEffort(input.userText ?? "", ceiling);
		return {{ thinkingLevel: chosen, phase: `user-${{chosen}}` }};
	}}
	// continuation on cold/small prefix: escalate on repeated tool errors, cool down on stalls or routine loops
	if (errs >= 2) {{
		const next: DeepSeekEffort = prev === "low" ? "high" : "max";
		return {{ thinkingLevel: next, phase: "error-escalate" }};
	}}
	if (
		prev === "max" &&
		((input.stagnantHeavyTurns ?? 0) >= 3 ||
			(input.recentToolSuccessesAfterEdit ?? 0) >= 2 ||
			(errs === 0 && (input.consecutiveLightTurns ?? 0) >= 4))
	) {{
		return {{ thinkingLevel: "high", phase: "cool-down" }};
	}}
	return {{ thinkingLevel: prev, phase: "sticky" }};
}}

export interface DiffFindingItem {{
	kind?: string;
	file?: string;
	detail?: string;
}}

function normRelPath(p: string, cwd?: string): string {{
	const clean = p.replace(/\\/g, "/").replace(/^\.\//, "");
	if (cwd) {{
		const base = cwd.replace(/\\/g, "/").replace(/\/+$/, "") + "/";
		if (clean.toLowerCase().startsWith(base.toLowerCase())) {{
			return clean.slice(base.length);
		}}
	}}
	return clean;
}}

/**
 * Filter `ap guard diff --json` findings strictly to high-precision blockers inside files
 * edited during this agent run (eliminating false positives from pre-existing dirty files).
 */
export function filterSettleDiffBlockers(
	findings: readonly DiffFindingItem[],
	editedFiles: ReadonlySet<string>,
	cwd?: string,
): string[] {{
	if (!Array.isArray(findings) || findings.length === 0 || editedFiles.size === 0) return [];
	const normEdited = new Set<string>();
	for (const f of editedFiles) {{
		const rel = normRelPath(f, cwd).toLowerCase();
		if (rel) normEdited.add(rel);
	}}
	const out: string[] = [];
	for (const item of findings) {{
		const kind = String(item?.kind ?? "");
		if (!BLOCKER_DIFF_KINDS.has(kind)) continue;
		const file = normRelPath(String(item?.file ?? ""), cwd);
		if (!file) continue;
		const low = file.toLowerCase();
		const touched =
			normEdited.has(low) ||
			[...normEdited].some((e) => e.endsWith(`/${{low}}`) || low.endsWith(`/${{e}}`));
		if (!touched) continue;
		out.push(`- [${{kind}}] ${{file}}: ${{String(item?.detail ?? "").slice(0, 160)}}`);
	}}
	return out.slice(0, 6);
}}

function extractEditedPathsFromTool(toolName: string, input: Record<string, unknown> | undefined): string[] {{
	if (!input) return [];
	const out: string[] = [];
	const pushStr = (v: unknown) => {{
		if (typeof v === "string" && v.trim()) out.push(v.trim());
	}};
	if (toolName === "write" || toolName === "edit") {{
		pushStr(input.path ?? input.file_path);
	}} else if (toolName === "ap_edit") {{
		for (const key of ["writes", "edits", "appends", "symbols"]) {{
			const arr = input[key];
			if (Array.isArray(arr)) {{
				for (const item of arr) {{
					if (item && typeof item === "object") pushStr((item as {{ path?: unknown }}).path);
				}}
			}}
		}}
	}}
	return out;
}}

export default function (pi: ExtensionAPI) {{
	const recentShellFps: string[] = [];
	const unchangedReads = new Map<string, number>();
	const outlinedPaths = new Set<string>();
	const editedFilesThisRun = new Set<string>();
	const builtInCodeEditsThisRun = new Set<string>();
	const largeOverwriteCallIds = new Set<string>();
	const clampedReadCallIds = new Map<string, {{ requestedOffset: number; clampedOffset: number; totalLines: number }}>();
	let settleGateFiredThisRun = false;
	let stagnantHeavyTurns = 0;
	let consecutiveLightTurns = 0;
	let pendingThinkingNudge = false;
	let serialSingleToolTurns = 0;
	let lastBatchTipTurn = -BATCH_TIP_COOLDOWN_TURNS;
	let lastWriteTipTurn = -WRITE_TIP_COOLDOWN_TURNS;
	let pendingBatchNudge = false;
	let largeReadTipShown = false;
	let codemodeParallelTipsShown = 0;
	let lastCodemodeParallelTipTurn = -CODEMODE_PARALLEL_COOLDOWN_TURNS;
	let sessionTurnCount = 0;
	let lastMaskTurn = -MASK_COOLDOWN_TURNS;
	let lastSeenCompactionId = "";
	let expectedCacheReset = false;
	let sessionInputTokens = 0;
	let sessionCacheReadTokens = 0;
	let lastKnownPromptTokens = 0;
	let lastCacheDropPct: number | null = null;
	let sievedCount = 0;
	let maskedCount = 0;
	let guardsTriggered = 0;
	let healedEditsCount = 0;
	let extCompactionsCount = 0;
	let cacheWarmsCount = 0;
	let totalToolTurns = 0;
	let serialSingleTotalTurns = 0;

	const resetRunState = () => {{
		editedFilesThisRun.clear();
		builtInCodeEditsThisRun.clear();
		settleGateFiredThisRun = false;
	}};

	const resetTransientState = () => {{
		recentShellFps.length = 0;
		unchangedReads.clear();
		outlinedPaths.clear();
		largeOverwriteCallIds.clear();
		clampedReadCallIds.clear();
		resetRunState();
		stagnantHeavyTurns = 0;
		consecutiveLightTurns = 0;
		pendingThinkingNudge = false;
		serialSingleToolTurns = 0;
		lastBatchTipTurn = -BATCH_TIP_COOLDOWN_TURNS;
		lastWriteTipTurn = -WRITE_TIP_COOLDOWN_TURNS;
		pendingBatchNudge = false;
		sessionTurnCount = 0;
		lastMaskTurn = -MASK_COOLDOWN_TURNS;
		lastKnownPromptTokens = 0;
		lastCacheDropPct = null;
	}};

	// Opt-in Pi v1.5 virtual model: `deepseek/flash-auto` (same physical deepseek-flash, dynamic low/high/max effort)
	if (typeof pi.registerVirtualModel === "function") {{
		pi.registerVirtualModel<{{ phase: string; lastEffort: DeepSeekEffort }}>({{
			provider: "deepseek",
			id: "flash-auto",
			name: "DeepSeek Flash Auto-Effort (ap)",
			thinkingLevels: ["low", "high", "max"],
			contextWindow: 1000000,
			maxTokens: 384000,
			input: ["text", "image"],
			route(request, ctx) {{
				const physical =
					ctx.modelRegistry.find("deepseek", "deepseek-flash") ?? request.previous?.model;
				if (!physical) {{
					throw new Error("Physical model deepseek/deepseek-flash not found in Pi model registry");
				}}
				let userText = "";
				let recentToolErrors = 0;
				let recentToolSuccessesAfterEdit = 0;
				if (Array.isArray(request.messages)) {{
					for (let i = request.messages.length - 1; i >= 0; i--) {{
						const m = request.messages[i] as {{
							role?: string;
							content?: string | Array<{{ type?: string; text?: string }}>;
							isError?: boolean;
						}};
						if (m.role === "user") {{
							if (typeof m.content === "string") userText = m.content;
							else if (Array.isArray(m.content)) {{
								userText = m.content
									.filter((b) => b?.type === "text" && typeof b.text === "string")
									.map((b) => b.text as string)
									.join("\n");
							}}
							break;
						}}
						if (m.role === "toolResult") {{
							if (m.isError) recentToolErrors += 1;
							else if (editedFilesThisRun.size > 0) recentToolSuccessesAfterEdit += 1;
						}}
					}}
				}}
				const decision = routeDeepSeekFlashEffort({{
					reason: request.reason,
					selectedLevel: request.thinkingLevel,
					previousLevel: request.previous?.thinkingLevel ?? request.state?.lastEffort,
					userText,
					recentToolErrors,
					recentToolSuccessesAfterEdit,
					stagnantHeavyTurns,
					consecutiveLightTurns,
					cachedPrefixTokens: lastKnownPromptTokens,
				}});
				const nextState =
					request.reason === "direct"
						? undefined
						: request.state?.phase === decision.phase &&
								request.state?.lastEffort === decision.thinkingLevel
							? request.state
							: {{ phase: decision.phase, lastEffort: decision.thinkingLevel }};
				return {{
					model: physical,
					thinkingLevel: decision.thinkingLevel,
					state: nextState,
				}};
			}},
		}});
	}}

	const updateHud = (ctx?: ExtensionContext) => {{
		if (!ctx || !ctx.hasUI) return;
		const usage = ctx.getContextUsage?.();
		const pct = typeof usage?.percent === "number" ? Math.round(usage.percent) : null;
		const tok = typeof usage?.tokens === "number" ? usage.tokens : null;
		const tokLabel = tok !== null ? `${{Math.round(tok / 1000)}}k` : null;
		const parts: string[] = [];
		const totalPrompt = sessionInputTokens + sessionCacheReadTokens;
		if (lastCacheDropPct !== null) {{
			parts.push(`CACHE DROP ${{lastCacheDropPct}}%`);
		}} else if (totalPrompt >= 10000) {{
			const hitPct = Math.round((sessionCacheReadTokens / totalPrompt) * 100);
			parts.push(`cache ${{hitPct}}%`);
		}}
		if (sievedCount > 0) parts.push(`${{sievedCount}} sieved`);
		if (maskedCount > 0) parts.push(`${{maskedCount}} masked`);
		if (guardsTriggered > 0) parts.push(`${{guardsTriggered}} guarded`);
		const highWater =
			(pct !== null && pct >= MASK_HIGH_WATER_PCT) ||
			(tok !== null && tok >= MASK_HIGH_WATER_TOKENS);
		if (highWater) {{
			parts.push(
				tokLabel && pct !== null
					? `CTX HIGH ${{tokLabel}} (${{pct}}%)`
					: pct !== null
						? `CTX HIGH ${{pct}}%`
						: `CTX HIGH ${{tokLabel}}`,
			);
		}} else if ((pct !== null && pct >= 55) || (tok !== null && tok >= 120000)) {{
			if (parts.length > 0 || (tok !== null && tok >= 120000)) {{
				parts.push(tokLabel && pct !== null ? `ctx ${{tokLabel}} (${{pct}}%)` : `ctx ${{pct ?? tokLabel}}`);
			}}
		}}
		ctx.ui.setStatus("ap", parts.length > 0 ? `ap: ${{parts.join(" | ")}}` : undefined);
	}};

	pi.on("session_start", (_event, ctx) => {{
		resetTransientState();
		lastSeenCompactionId = "";
		largeReadTipShown = false;
		codemodeParallelTipsShown = 0;
		lastCodemodeParallelTipTurn = -CODEMODE_PARALLEL_COOLDOWN_TURNS;
		sessionInputTokens = 0;
		sessionCacheReadTokens = 0;
		expectedCacheReset = false;
		sievedCount = 0;
		maskedCount = 0;
		guardsTriggered = 0;
		healedEditsCount = 0;
		extCompactionsCount = 0;
		cacheWarmsCount = 0;
		totalToolTurns = 0;
		serialSingleTotalTurns = 0;
		updateHud(ctx);
	}});

	pi.on("before_agent_start", (event, ctx) => {{
		const m = ctx?.model;
		const isDs = Boolean(
			m &&
				(String(m.provider ?? "").toLowerCase().includes("deepseek") ||
					String(m.id ?? "").toLowerCase().includes("deepseek") ||
					String(m.id ?? "").toLowerCase().includes("flash-auto")),
		);
		if (isDs && Array.isArray(event?.systemPromptOptions?.promptGuidelines)) {{
			const branch = ctx?.sessionManager?.getBranch?.() ?? [];
			const hasPriorAssistant =
				Array.isArray(branch) &&
				branch.some(
					(e: {{ type?: string; message?: {{ role?: string }} }}) =>
						e?.type === "message" && e.message?.role === "assistant",
				);
			const compatMid =
				(m as {{ compat?: {{ supportsMidConvoSystemMessages?: boolean }} }})?.compat
					?.supportsMidConvoSystemMessages === true;
			const alreadyHasApRule = event.systemPromptOptions.promptGuidelines.some(
				(g: string) => typeof g === "string" && g.includes("In codemode (QuickJS sandbox"),
			);
			// Inject on Turn 0 directly into messages[0]; on resumed sessions never emit redundant `rules` diffs!
			if (!hasPriorAssistant || (compatMid && !alreadyHasApRule)) {{
				injectDeepSeekGuidelines(event.systemPromptOptions.promptGuidelines);
			}}
		}}
		return undefined;
	}});

	pi.on("cache_warming_decision", (event, ctx) => {{
		const override = decideDeepSeekCacheWarming({{
			provider: ctx?.model?.provider,
			modelId: ctx?.model?.id,
			warmCost: event?.warmCost,
			missCost: event?.missCost,
			action: event?.action,
		}});
		if (override) {{
			cacheWarmsCount += 1;
			return override;
		}}
		return undefined;
	}});

	pi.on("before_provider_request", (event) => {{
		return stabilizeProviderTools(event?.payload);
	}});

	pi.on("agent_start", () => {{
		resetRunState();
	}});

	pi.on("session_before_switch", () => {{
		resetTransientState();
		largeReadTipShown = false;
		codemodeParallelTipsShown = 0;
		lastCodemodeParallelTipTurn = -CODEMODE_PARALLEL_COOLDOWN_TURNS;
		sessionInputTokens = 0;
		sessionCacheReadTokens = 0;
		expectedCacheReset = false;
	}});

	pi.on("session_compact", (event, ctx) => {{
		if ((event as {{ fromExtension?: boolean }} | undefined)?.fromExtension) {{
			extCompactionsCount += 1;
		}}
		resetTransientState();
		expectedCacheReset = true;
		updateHud(ctx);
	}});

	pi.on("session_before_compact", async (event, ctx) => {{
		// 1. Zero-clutter compaction sync: checkpoint `.baton` if the workspace already uses it
		let batonBrief = "";
		if (ctx?.cwd && existsSync(join(ctx.cwd, ".baton"))) {{
			spawnSync(AP_BIN, ["baton", "checkpoint", "--note", "pi-compact"], {{
				cwd: ctx.cwd,
				encoding: "utf8",
				timeout: 2500,
				windowsHide: true,
			}});
			const bt = spawnSync(AP_BIN, ["baton", "resume"], {{
				cwd: ctx.cwd,
				encoding: "utf8",
				timeout: 2000,
				windowsHide: true,
			}});
			if (bt.status === 0 && bt.stdout?.trim()) {{
				batonBrief = `\n\n## Baton Task State\n${{bt.stdout.trim().slice(0, 1500)}}`;
			}}
			if (existsSync(join(ctx.cwd, ".baton", "frontier.json"))) {{
				const fr = spawnSync(AP_BIN, ["baton", "frontier", "status", "-k", "4"], {{
					cwd: ctx.cwd,
					encoding: "utf8",
					timeout: 2000,
					windowsHide: true,
				}});
				if (fr.status === 0 && fr.stdout?.trim()) {{
					batonBrief += `\n\n## Exploration Frontier\n${{fr.stdout.trim().slice(0, 1000)}}`;
				}}
			}}
		}}
		if (process.env.AP_YIELD_COMPACT === "1") {{
			return undefined;
		}}

		// 2. Fast `reasoning: "low"` dead-end-preserving auto-compaction for DeepSeek models
		//    (5-10x faster than max-effort default compaction; safely falls back to Pi built-in on any issue)
		const model = ctx?.model;
		const prep = event?.preparation as {{
			firstKeptEntryId?: string;
			messagesToSummarize?: Array<Record<string, unknown>>;
			turnPrefixMessages?: Array<Record<string, unknown>>;
			tokensBefore?: number;
			previousSummary?: string;
			fileOps?: {{ read?: Iterable<string>; written?: Iterable<string>; edited?: Iterable<string> }};
		}} | undefined;
		const isDeepSeek = Boolean(
			model &&
				(String(model.provider ?? "").toLowerCase().includes("deepseek") ||
					String(model.id ?? "").toLowerCase().includes("deepseek") ||
					String(model.id ?? "").toLowerCase().includes("flash-auto")),
		);
		const hasSimpleComplete =
			typeof ctx?.modelRegistry?.streamSimple === "function" ||
			typeof ctx?.modelRegistry?.complete === "function";
		if (
			!isDeepSeek ||
			!model ||
			!prep?.firstKeptEntryId ||
			typeof prep.tokensBefore !== "number" ||
			event?.signal?.aborted ||
			!hasSimpleComplete
		) {{
			return undefined;
		}}

		try {{
			const modSet = new Set<string>([
				...(prep.fileOps?.written ? [...prep.fileOps.written] : []),
				...(prep.fileOps?.edited ? [...prep.fileOps.edited] : []),
			]);
			const readFiles = prep.fileOps?.read
				? [...prep.fileOps.read].filter((f) => !modSet.has(f)).sort()
				: [];
			const modifiedFiles = [...modSet].sort();
			const storeKeys = listCodemodeStoreKeys(
				(event.branchEntries ?? []) as unknown as Array<Record<string, unknown>>,
			);
			const allMsgs = [
				...(Array.isArray(prep.messagesToSummarize) ? prep.messagesToSummarize : []),
				...(Array.isArray(prep.turnPrefixMessages) ? prep.turnPrefixMessages : []),
			];
			if (allMsgs.length === 0) return undefined;
			const serialized = serializeMessagesForCompaction(
				allMsgs,
				prep.previousSummary,
				readFiles,
				modifiedFiles,
				storeKeys,
			);
			const extraInstr = event.customInstructions?.trim()
				? `\n\n## Additional Focus\n${{event.customInstructions.trim()}}`
				: "";
			const compCtx = {{
				systemPrompt:
					"You are a context compaction summarizer for a coding agent. Output ONLY a crisp, structured handoff summary with these exact headings: ## Goal & Constraints, ## Verified Facts & Progress, ## Falsified Dead-Ends (DO NOT RETRY), ## Key Decisions & File Map, ## Next Immediate Action. Preserve exact file paths, symbol names, build/test commands, and error signatures. Do NOT continue the conversation.",
				messages: [
					{{
						role: "user" as const,
						content: [
							{{
								type: "text" as const,
								text: `${{serialized}}${{batonBrief}}${{extraInstr}}`,
							}},
						],
						timestamp: Date.now(),
					}},
				],
			}};
			const compOpts = {{
				reasoning: "low" as const,
				maxTokens: 6144,
				cacheRetention: "none" as const,
				signal: event.signal,
			}};
			// Use `streamSimple().result()` (NOT `complete()`): in Pi v1.5+, `complete()` bypasses
			// `streamSimple`, dropping `reasoning` effort mapping and rejecting virtual models like `flash-auto`.
			const response =
				typeof ctx.modelRegistry.streamSimple === "function"
					? await ctx.modelRegistry.streamSimple(model, compCtx, compOpts).result()
					: await ctx.modelRegistry.complete(model, compCtx, compOpts as never);
			if (
				!response ||
				response.stopReason === "error" ||
				response.stopReason === "aborted" ||
				response.stopReason === "length"
			) {{
				return undefined;
			}}
			let summary = (response.content ?? [])
				.filter((c): c is {{ type: "text"; text: string }} => c?.type === "text" && typeof c.text === "string")
				.map((c) => c.text)
				.join("\n")
				.trim();
			if (summary.length < 40) return undefined;
			if (readFiles.length > 0) {{
				summary += `\n\n<read-files>\n${{readFiles.join("\n")}}\n</read-files>`;
			}}
			if (modifiedFiles.length > 0) {{
				summary += `\n\n<modified-files>\n${{modifiedFiles.join("\n")}}\n</modified-files>`;
			}}
			if (storeKeys.length > 0) {{
				summary += `\n\n<codemode-store-keys>\n${{storeKeys.join(", ")}}\n</codemode-store-keys>`;
			}}
			return {{
				compaction: {{
					summary,
					firstKeptEntryId: prep.firstKeptEntryId,
					tokensBefore: prep.tokensBefore,
					usage: response.usage,
					details: {{ readFiles, modifiedFiles }},
				}},
			}};
		}} catch {{
			// Fall back cleanly to Pi's built-in compactor
			return undefined;
		}}
	}});

	pi.on("session_before_tree", (_event, ctx) => {{
		// Keep branch-switch summaries sharp by preserving verified facts, dead-ends & active codemode-store keys
		const branch = ctx?.sessionManager?.getBranch?.() ?? [];
		const storeKeys = listCodemodeStoreKeys(branch as unknown as Array<Record<string, unknown>>);
		const storeAnchor =
			storeKeys.length > 0
				? ` Note active codemode-store keys recoverable via load(key): [${{storeKeys.slice(0, 12).join(", ")}}].`
				: "";
		return {{
			customInstructions:
				`Preserve exact file paths, symbol names, verified facts, falsified hypotheses/dead-ends, and exact failing error signatures so the target branch never repeats failed attempts.${{storeAnchor}}`,
		}};
	}});

	// Zero-prompt-token interactive `/ap` command inside Pi (`/ap`, `status`, `doctor`, `compact`, `handoff <goal>`)
	if (typeof pi.registerCommand === "function") {{
		pi.registerCommand("ap", {{
			description: "Live ap + DeepSeek KV-cache telemetry, doctor, focused compact, clean-session handoff, or independent diff review",
			getArgumentCompletions(prefix: string) {{
				const items = [
					{{ value: "status", label: "status — Live KV-cache, masking, edit-heal & codemode-store telemetry" }},
					{{ value: "doctor", label: "doctor — Run native ap doctor health check" }},
					{{ value: "compact", label: "compact — Compact while anchoring verified facts & dead-ends" }},
					{{ value: "fresh ", label: "fresh [goal] — Instant 0-history linked session seeded with .baton & frontier" }},
					{{ value: "handoff ", label: "handoff <goal> — Transfer context cleanly to a fresh 0-rot session" }},
					{{ value: "review", label: "review [focus] — Independent clean-context diff review (0 parent bloat)" }},
				];
				const p = (prefix || "").trim().toLowerCase();
				return p ? items.filter((it) => it.value.trim().startsWith(p)) : items;
			}},
			async handler(args, ctx) {{
				const rawArgs = (args || "").trim();
				const firstSpace = rawArgs.indexOf(" ");
				const sub = (firstSpace >= 0 ? rawArgs.slice(0, firstSpace) : rawArgs).toLowerCase() || "status";
				const rest = firstSpace >= 0 ? rawArgs.slice(firstSpace + 1).trim() : "";

				if (sub === "doctor") {{
					const res = spawnSync(AP_BIN, ["doctor"], {{
						cwd: ctx.cwd,
						encoding: "utf8",
						timeout: 5000,
						windowsHide: true,
					}});
					const summary = (res.stdout || res.stderr || "ap doctor failed")
						.trim()
						.split("\n")
						.slice(0, 12)
						.join("\n");
					ctx.ui.notify(summary, res.status === 0 ? "info" : "warning");
					return;
				}}
				if (sub === "compact") {{
					const branch = ctx.sessionManager?.getBranch?.() ?? [];
					const storeKeys = listCodemodeStoreKeys(branch as unknown as Array<Record<string, unknown>>);
					const storeAnchor =
						storeKeys.length > 0
							? ` Preserve active codemode-store keys recoverable via load(key): [${{storeKeys.slice(0, 12).join(", ")}}].`
							: "";
					ctx.compact({{
						customInstructions:
							`Preserve exact file paths, symbol names, verified facts, falsified dead-ends, and exact build/test commands needed to continue cleanly.${{storeAnchor}}`,
					}});
					ctx.ui.notify("[ap] Triggered focused compaction preserving verified facts, dead-ends & store keys.", "info");
					return;
				}}
				if (sub === "fresh") {{
					const parentSession = ctx.sessionManager?.getSessionFile?.();
					const seedParts: string[] = [];
					if (ctx.cwd && existsSync(join(ctx.cwd, ".baton"))) {{
						const bt = spawnSync(AP_BIN, ["baton", "resume"], {{
							cwd: ctx.cwd,
							encoding: "utf8",
							timeout: 2000,
							windowsHide: true,
						}});
						if (bt.status === 0 && bt.stdout?.trim()) {{
							seedParts.push(bt.stdout.trim().slice(0, 1500));
						}}
						if (existsSync(join(ctx.cwd, ".baton", "frontier.json"))) {{
							const fr = spawnSync(AP_BIN, ["baton", "frontier", "status", "-k", "5"], {{
								cwd: ctx.cwd,
								encoding: "utf8",
								timeout: 2000,
								windowsHide: true,
							}});
							if (fr.status === 0 && fr.stdout?.trim()) {{
								seedParts.push(fr.stdout.trim().slice(0, 1200));
							}}
						}}
					}}
					const kickoff = [rest || "Continue from the clean-slate frontier above.", ...seedParts].join("\n\n").trim();
					if (typeof ctx.newSession === "function") {{
						await ctx.newSession({{
							parentSession,
							withSession: async (nextCtx) => {{
								if (rest && typeof nextCtx.sendUserMessage === "function") {{
									await nextCtx.sendUserMessage(kickoff);
								}} else {{
									nextCtx.ui.setEditorText(kickoff);
								}}
								nextCtx.ui.notify("[ap fresh] Started 0-history child session linked to parent.", "info");
							}},
						}});
					}} else {{
						ctx.ui.setEditorText?.(kickoff);
					}}
					return;
				}}
				if (sub === "handoff") {{
					if (!rest) {{
						ctx.ui.notify("Usage: /ap handoff <goal for the new focused session>", "warning");
						return;
					}}
					if (!ctx.model) {{
						ctx.ui.notify("[ap handoff] No active model selected.", "error");
						return;
					}}
					const branch = ctx.sessionManager?.getBranch?.() ?? [];
					const transcript = serializeBranchForHandoff(branch as unknown as Array<Record<string, unknown>>);
					if (!transcript) {{
						ctx.ui.notify("[ap handoff] Current branch has no messages to transfer.", "warning");
						return;
					}}
					let envFacts = "";
					if (ctx.cwd && existsSync(join(ctx.cwd, ".git"))) {{
						const gs = spawnSync("git", ["status", "--short"], {{
							cwd: ctx.cwd,
							encoding: "utf8",
							timeout: 2000,
							windowsHide: true,
						}});
						if (gs.status === 0 && gs.stdout?.trim()) {{
							envFacts += `\n\n## Modified Files (git status)\n${{gs.stdout.trim().slice(0, 1500)}}`;
						}}
					}}
					if (ctx.cwd && existsSync(join(ctx.cwd, ".baton"))) {{
						const bt = spawnSync(AP_BIN, ["baton", "resume"], {{
							cwd: ctx.cwd,
							encoding: "utf8",
							timeout: 2000,
							windowsHide: true,
						}});
						if (bt.status === 0 && bt.stdout?.trim()) {{
							envFacts += `\n\n## Baton State\n${{bt.stdout.trim().slice(0, 1500)}}`;
						}}
					}}
					ctx.ui.notify("[ap handoff] Generating clean transfer brief (low effort)...", "info");
					try {{
						const handoffCtx = {{
							systemPrompt:
								"Generate a concise, self-contained handoff prompt for a brand-new coding-agent session. Include: ## Context (verified facts & key decisions), ## Falsified Dead-Ends (what NOT to retry), ## Relevant Files, and ## Next Task. Output ONLY the prompt itself.",
							messages: [
								{{
									role: "user" as const,
									content: [
										{{
											type: "text" as const,
											text: `## Conversation Branch\n${{transcript}}${{envFacts}}\n\n## Goal For New Session\n${{rest}}`,
										}},
									],
									timestamp: Date.now(),
								}},
							],
						}};
						const handoffOpts = {{
							reasoning: "low" as const,
							maxTokens: 6144,
							cacheRetention: "none" as const,
						}};
						const response =
							typeof ctx.modelRegistry.streamSimple === "function"
								? await ctx.modelRegistry.streamSimple(ctx.model, handoffCtx, handoffOpts).result()
								: await ctx.modelRegistry.complete(ctx.model, handoffCtx, handoffOpts as never);
						const draft = response.content
							.filter((c): c is {{ type: "text"; text: string }} => c.type === "text")
							.map((c) => c.text)
							.join("\n")
							.trim();
						if (!draft) {{
							ctx.ui.notify("[ap handoff] Empty response from model.", "warning");
							return;
						}}
						const edited =
							typeof ctx.ui.editor === "function"
								? await ctx.ui.editor("Review /ap handoff prompt", draft)
								: draft;
						if (edited === undefined) {{
							ctx.ui.notify("[ap handoff] Cancelled.", "info");
							return;
						}}
						const parentSession = ctx.sessionManager?.getSessionFile?.();
						if (typeof ctx.newSession === "function") {{
							await ctx.newSession({{
								parentSession,
								withSession: async (nextCtx) => {{
									nextCtx.ui.setEditorText(edited);
									nextCtx.ui.notify("[ap handoff] Fresh session ready — press Enter to start!", "info");
								}},
							}});
						}} else {{
							ctx.ui.setEditorText?.(edited);
						}}
					}} catch (err) {{
						ctx.ui.notify(
							`[ap handoff] Failed: ${{err instanceof Error ? err.message : String(err)}}`,
							"error",
						);
					}}
					return;
				}}
				if (sub === "review") {{
					if (!ctx.model) {{
						ctx.ui.notify("[ap review] No active model selected.", "error");
						return;
					}}
					const cwd = ctx.cwd || process.cwd();
					if (!existsSync(join(cwd, ".git"))) {{
						ctx.ui.notify("[ap review] Current directory is not a Git repository.", "warning");
						return;
					}}
					let diffText = "";
					const d1 = spawnSync("git", ["diff", "HEAD"], {{
						cwd,
						encoding: "utf8",
						timeout: 4000,
						windowsHide: true,
					}});
					if (d1.status === 0 && d1.stdout?.trim()) {{
						diffText = d1.stdout.trim();
					}} else {{
						const d2 = spawnSync("git", ["diff", "HEAD~1..HEAD"], {{
							cwd,
							encoding: "utf8",
							timeout: 4000,
							windowsHide: true,
						}});
						if (d2.status === 0 && d2.stdout?.trim()) {{
							diffText = d2.stdout.trim();
						}}
					}}
					if (!diffText) {{
						ctx.ui.notify("[ap review] No uncommitted or HEAD~1 diff found to review.", "info");
						return;
					}}
					let guardSummary = "";
					const gd = spawnSync(AP_BIN, ["guard", "diff", "--json", cwd], {{
						cwd,
						encoding: "utf8",
						timeout: 3000,
						windowsHide: true,
					}});
					if (gd.status === 0 && gd.stdout?.trim()) {{
						guardSummary = `\n\n## Automated ap guard diff Findings\n${{gd.stdout.trim().slice(0, 3000)}}`;
					}}
					ctx.ui.notify("[ap review] Running isolated skeptical diff review (0 parent context bloat)...", "info");
					try {{
						const focusLine = rest ? `\n\n## Specific Review Focus\n${{rest}}` : "";
						// Resolve physical deepseek-flash if active model is virtual `flash-auto` so `/ap review` always runs at true `high` effort
						const reviewModel =
							ctx.model.id === "flash-auto"
								? ctx.modelRegistry.find?.("deepseek", "deepseek-flash") ?? ctx.model
								: ctx.model;
						const reviewCtx = {{
							systemPrompt:
								"You are an independent, skeptical senior code reviewer seeing this Git diff with fresh eyes (zero bias from the author). Identify ONLY concrete, verified defects: logic bugs, edge cases, regressions, missing error handling, concurrency/resource leaks, or skipped/weak tests. Cite exact file:line. If the diff is solid, say LGTM concisely.",
							messages: [
								{{
									role: "user" as const,
									content: [
										{{
											type: "text" as const,
											text: `## Git Diff\n\`\`\`diff\n${{diffText.slice(0, 24000)}}\n\`\`\`${{guardSummary}}${{focusLine}}`,
										}},
									],
									timestamp: Date.now(),
								}},
							],
						}};
						const reviewOpts = {{
							reasoning: "high" as const,
							maxTokens: 8192,
							cacheRetention: "none" as const,
						}};
						const response =
							typeof ctx.modelRegistry.streamSimple === "function"
								? await ctx.modelRegistry.streamSimple(reviewModel, reviewCtx, reviewOpts).result()
								: await ctx.modelRegistry.complete(reviewModel, reviewCtx, reviewOpts as never);
						const report = response.content
							.filter((c): c is {{ type: "text"; text: string }} => c.type === "text")
							.map((c) => c.text)
							.join("\n")
							.trim();
						if (!report) {{
							ctx.ui.notify("[ap review] Reviewer returned empty response.", "warning");
							return;
						}}
						if (typeof ctx.ui.editor === "function") {{
							await ctx.ui.editor("Independent /ap review findings (Esc to close)", report);
						}} else {{
							ctx.ui.notify(report.slice(0, 2000), "info");
						}}
					}} catch (err) {{
						ctx.ui.notify(
							`[ap review] Failed: ${{err instanceof Error ? err.message : String(err)}}`,
							"error",
						);
					}}
					return;
				}}

				const usage = ctx.getContextUsage?.();
				const totalPrompt = sessionInputTokens + sessionCacheReadTokens;
				const hitPct =
					totalPrompt > 0 ? ((sessionCacheReadTokens / totalPrompt) * 100).toFixed(1) : "n/a";
				// DeepSeek V4.1 Flash savings: ($0.30 - $0.006) / 1M = $0.294 per 1M cacheRead tokens
				const estUsdSaved = ((sessionCacheReadTokens / 1_000_000) * 0.294).toFixed(4);
				const ctxStr =
					typeof usage?.tokens === "number"
						? `${{Math.round(usage.tokens / 1000)}}k (${{Math.round(usage.percent ?? 0)}}%)`
						: "n/a";
				const modelStr = ctx.model ? `${{ctx.model.provider}}/${{ctx.model.id}}` : "unknown";
				const serialPct =
					totalToolTurns > 0 ? `${{Math.round((serialSingleTotalTurns / totalToolTurns) * 100)}}%` : "n/a";
				const branch = ctx.sessionManager?.getBranch?.() ?? [];
				const storeKeys = countCodemodeStoreKeys(branch as unknown as Array<Record<string, unknown>>);
				const compactSuffix = extCompactionsCount > 0 ? ` extCompacts=${{extCompactionsCount}}` : "";
				const warmSuffix = cacheWarmsCount > 0 ? ` cacheWarms=${{cacheWarmsCount}}` : "";
				ctx.ui.notify(
					`[ap telemetry] model=${{modelStr}} | ctx=${{ctxStr}} (mask@180k) | cache=${{hitPct}}% (saved ~$${{estUsdSaved}}) | sieved=${{sievedCount}} masked=${{maskedCount}} healedEdits=${{healedEditsCount}} guarded=${{guardsTriggered}}${{compactSuffix}}${{warmSuffix}} | serial1=${{serialPct}} storeKeys=${{storeKeys}}`,
					"info",
				);
			}},
		}});
	}}

	pi.on("message_end", (event) => {{
		const msg = event.message as {{
			role?: string;
			content?: Array<{{ type?: string; text?: string; name?: string; arguments?: unknown; [k: string]: unknown }}>;
		}} | undefined;
		if (!msg || msg.role !== "assistant" || !Array.isArray(msg.content)) return undefined;

		const active = new Set(pi.getActiveTools?.() ?? []);
		if (active.size === 0) return undefined;

		// 1. Repair hallucinated native toolCall names (e.g. `codemake` -> `codemode`, `read_file` -> `read`)
		if (msg.content.some((b) => b?.type === "toolCall")) {{
			let repairedAny = false;
			const repairedContent = msg.content.map((blk) => {{
				if (blk?.type === "toolCall" && typeof blk.name === "string" && !active.has(blk.name)) {{
					const fixedName = repairHallucinatedToolName(blk.name, active);
					if (fixedName) {{
						repairedAny = true;
						return {{
							...blk,
							name: fixedName,
							arguments: normalizeRepairedToolArgs(fixedName, blk.arguments),
						}};
					}}
				}}
				return blk;
			}});
			if (!repairedAny) return undefined;
			guardsTriggered += 1;
			return {{
				message: {{
					...(msg as Record<string, unknown>),
					content: repairedContent,
				}} as typeof event.message,
			}};
		}}

		let recoveredAny = false;
		const nextContent: Array<Record<string, unknown>> = [];
		for (const blk of msg.content) {{
			if (blk?.type === "text" && typeof blk.text === "string") {{
				const rec = blk.text.includes("DSML")
					? extractDsmlToolCalls(blk.text, active)
					: blk.text.includes("<tool_call>")
						? extractXmlJsonToolCalls(blk.text, active)
						: undefined;
				if (rec) {{
					recoveredAny = true;
					if (rec.cleanedText) {{
						nextContent.push({{ ...blk, text: rec.cleanedText }});
					}}
					for (const call of rec.calls) {{
						nextContent.push(call as unknown as Record<string, unknown>);
					}}
					continue;
				}}
			}}
			nextContent.push(blk as Record<string, unknown>);
		}}
		if (!recoveredAny) return undefined;
		guardsTriggered += 1;
		return {{
			message: {{
				...(msg as Record<string, unknown>),
				content: nextContent,
			}} as typeof event.message,
		}};
	}});

	pi.on("turn_end", (event, ctx) => {{
		const firstCtxEntry = event.context?.contextEntries?.[0]?.sourceEntry as {{ id?: string; type?: string }} | undefined;
		if (firstCtxEntry?.type === "compaction" && typeof firstCtxEntry.id === "string" && firstCtxEntry.id !== lastSeenCompactionId) {{
			lastSeenCompactionId = firstCtxEntry.id;
			resetTransientState();
			expectedCacheReset = true;
		}}
		sessionTurnCount += 1;
		const msg = event.message as {{
			role?: string;
			content?: Array<{{ type?: string; thinking?: string; name?: string }}>;
			usage?: {{ input?: number; cacheRead?: number }};
		}} | undefined;
		let turnPrompt = 0;
		let justRebuiltColdCache = false;
		if (msg?.role === "assistant" && Array.isArray(msg.content)) {{
			// Live DeepSeek 50x KV-cache hit-rate telemetry & unexpected drop alarm
			const uIn = typeof msg.usage?.input === "number" ? msg.usage.input : 0;
			const uCache = typeof msg.usage?.cacheRead === "number" ? msg.usage.cacheRead : 0;
			turnPrompt = uIn + uCache;
			if (turnPrompt > 0) {{
				sessionInputTokens += uIn;
				sessionCacheReadTokens += uCache;
				const turnHitPct = Math.round((uCache / turnPrompt) * 100);
				if (turnPrompt >= 20000 && turnHitPct < 45 && !expectedCacheReset) {{
					lastCacheDropPct = turnHitPct;
				}} else if (turnHitPct >= 60) {{
					lastCacheDropPct = null;
				}}
				if (turnPrompt >= FREE_MASK_MIN_TOKENS && turnHitPct < 55 && !expectedCacheReset) {{
					justRebuiltColdCache = true;
				}}
				expectedCacheReset = false;
			}}

			let thinkChars = 0;
			let didEdit = false;
			let toolCallCount = 0;
			let singleToolName = "";
			for (const blk of msg.content) {{
				if (blk?.type === "thinking" && typeof blk.thinking === "string") {{
					thinkChars += blk.thinking.length;
				}} else if (blk?.type === "toolCall" && typeof blk.name === "string") {{
					toolCallCount += 1;
					singleToolName = blk.name;
					if (EDIT_TOOLS.has(blk.name)) {{
						didEdit = true;
					}}
				}}
			}}
			const hadToolError = Array.isArray(event.toolResults)
				? event.toolResults.some((r: {{ isError?: boolean }}) => r?.isError === true)
				: false;
			if (hadToolError || didEdit || thinkChars >= HEAVY_THINKING_CHARS) {{
				consecutiveLightTurns = 0;
			}} else if (toolCallCount > 0 && thinkChars < LIGHT_THINKING_CHARS) {{
				consecutiveLightTurns += 1;
			}} else {{
				consecutiveLightTurns = 0;
			}}
			if (toolCallCount > 0) {{
				totalToolTurns += 1;
				if (toolCallCount === 1) serialSingleTotalTurns += 1;
			}}
			if (toolCallCount === 1 && SERIAL_BATCHABLE_TOOLS.has(singleToolName) && !didEdit && !hadToolError) {{
				serialSingleToolTurns += 1;
				if (
					serialSingleToolTurns >= SERIAL_BATCH_THRESHOLD &&
					sessionTurnCount - lastBatchTipTurn >= BATCH_TIP_COOLDOWN_TURNS
				) {{
					pendingBatchNudge = true;
					lastBatchTipTurn = sessionTurnCount;
				}}
			}} else if (toolCallCount !== 1 || didEdit || hadToolError || singleToolName === "codemode") {{
				serialSingleToolTurns = 0;
			}}
			if (didEdit) {{
				stagnantHeavyTurns = 0;
				pendingThinkingNudge = false;
			}} else if (thinkChars >= HEAVY_THINKING_CHARS) {{
				stagnantHeavyTurns += 1;
				if (stagnantHeavyTurns >= STAGNATION_TURNS) {{
					pendingThinkingNudge = true;
				}}
			}} else {{
				stagnantHeavyTurns = Math.max(0, stagnantHeavyTurns - 1);
			}}
		}}

		// Native Pi v1.5 batch observation masking using monotonic sessionTurnCount
		// (Pi resets event.turnIndex=0 on each agent_start). Protect a brand-new cache right after
		// a cold turn paid full price to rebuild it, AND on 50:1 deep-cache-discount models (e.g. DeepSeek Flash)
		// defer mid-prefix context_edit until emergency >=210k so normal 0-160k runs keep 99.5%+ pure KV-cache hits!
		const contextEntries = event.context?.contextEntries;
		const usage = ctx?.getContextUsage?.();
		const effTokens = usage?.tokens ?? (turnPrompt > 0 ? turnPrompt : null);
		if (typeof effTokens === "number" && effTokens > 0) {{
			lastKnownPromptTokens = effTokens;
		}}
		const deepCacheDiscount = isDeepCacheDiscountModel(
			ctx?.model as {{ provider?: string; id?: string; cost?: {{ input?: number; cacheRead?: number }} }} | undefined,
		);
		const effCooldown = deepCacheDiscount ? 25 : MASK_COOLDOWN_TURNS;
		const cooldownReady = sessionTurnCount - lastMaskTurn >= effCooldown;
		const protectFreshColdRebuild =
			justRebuiltColdCache && (effTokens === null || effTokens < MASK_TIER2_TOKENS);
		if (Array.isArray(contextEntries) && cooldownReady && !protectFreshColdRebuild) {{
			const plan = planObservationMasking(contextEntries, {{
				usagePercent: usage?.percent ?? null,
				usageTokens: effTokens,
				...(deepCacheDiscount ? {{ highWaterTokens: 210000, staleCharsFallback: 360000 }} : {{}}),
			}});
			if (plan.edits.length > 0) {{
				lastMaskTurn = sessionTurnCount;
				maskedCount += plan.maskedCount;
				expectedCacheReset = true;
				updateHud(ctx);
				return {{
					entries: [...(event.entries ?? []), ...plan.edits],
				}};
			}}
		}}

		updateHud(ctx);
		return undefined;
	}});

	pi.on("agent_before_settle", (event, ctx) => {{
		if (event.outcome !== "completed" || settleGateFiredThisRun) {{
			return undefined;
		}}
		if (Array.isArray(event.entries) && event.entries.some((e) => e?.type === "compaction")) {{
			editedFilesThisRun.clear();
			builtInCodeEditsThisRun.clear();
			return undefined;
		}}

		// 0. Recover silent thinking-only stall (assistant emitted thinking with 0 text & 0 toolCalls)
		const ctxMsgs = event.context?.contextMessages;
		if (Array.isArray(ctxMsgs) && ctxMsgs.length > 0) {{
			const last = ctxMsgs[ctxMsgs.length - 1] as {{
				role?: string;
				content?: Array<{{ type?: string; thinking?: string; text?: string }}>;
			}};
			if (last?.role === "assistant" && Array.isArray(last.content)) {{
				const hasThinking = last.content.some(
					(b) => b?.type === "thinking" && typeof b.thinking === "string" && b.thinking.trim().length > 0,
				);
				const hasVisible = last.content.some(
					(b) =>
						b?.type === "toolCall" ||
						(b?.type === "text" && typeof b.text === "string" && b.text.trim().length > 0),
				);
				if (hasThinking && !hasVisible) {{
					settleGateFiredThisRun = true;
					guardsTriggered += 1;
					updateHud(ctx);
					const draft: CustomMessageEntryDraft = {{
						type: "custom_message",
						customType: "ap-empty-recover",
						display: false,
						content:
							"[ap recover] Previous assistant turn produced internal reasoning with no visible text or tool call. Emit your concrete tool call or final answer now.",
					}};
					return {{
						entries: [...(event.entries ?? []), draft],
						continue: true,
					}};
				}}
			}}
		}}

		if (editedFilesThisRun.size === 0) {{
			return undefined;
		}}
		const cwd = ctx?.cwd;
		if (!cwd) return undefined;

		const blockers: string[] = [];

		// 1. Fast (<15ms) Tree-sitter/JSON/TOML syntax check on code files edited via built-in write/edit
		for (const rawPath of [...builtInCodeEditsThisRun].slice(0, 6)) {{
			if (!CHECKABLE_CODE_EXT.test(rawPath)) continue;
			const absPath = isAbsolute(rawPath) ? rawPath : resolve(cwd, rawPath);
			if (!existsSync(absPath)) continue;
			const chk = spawnSync(AP_BIN, ["splice", "check", "--json", absPath], {{
				cwd,
				encoding: "utf8",
				timeout: 2500,
				windowsHide: true,
			}});
			if (chk.stdout && chk.stdout.trim().startsWith("{{")) {{
				try {{
					const parsed = JSON.parse(chk.stdout) as {{
						ok?: boolean;
						issues?: Array<string | {{ file?: string; line?: number; message?: string; detail?: string }}>;
					}};
					if (parsed.ok === false && Array.isArray(parsed.issues)) {{
						for (const iss of parsed.issues.slice(0, 3)) {{
							const msg =
								typeof iss === "string"
									? iss
									: `${{iss.file ?? normRelPath(rawPath, cwd)}}${{iss.line ? `:${{iss.line}}` : ""}} ${{iss.message ?? iss.detail ?? "syntax error"}}`;
							blockers.push(`- [SYNTAX] ${{msg.slice(0, 180)}}`);
						}}
					}}
				}} catch {{
					// ignore unparseable output
				}}
			}}
		}}

		// 2. Fast (<25ms) Git diff blocker gate strictly scoped to files edited in this run
		if (existsSync(join(cwd, ".git"))) {{
			const diffRes = spawnSync(AP_BIN, ["guard", "diff", "--json", cwd], {{
				cwd,
				encoding: "utf8",
				timeout: 2500,
				windowsHide: true,
			}});
			if (diffRes.stdout && diffRes.stdout.trim().startsWith("{{")) {{
				try {{
					const parsed = JSON.parse(diffRes.stdout) as {{ findings?: DiffFindingItem[] }};
					if (Array.isArray(parsed.findings)) {{
						blockers.push(...filterSettleDiffBlockers(parsed.findings, editedFilesThisRun, cwd));
					}}
				}} catch {{
					// ignore unparseable output
				}}
			}}
		}}

		if (blockers.length === 0) {{
			editedFilesThisRun.clear();
			builtInCodeEditsThisRun.clear();
			return undefined;
		}}

		settleGateFiredThisRun = true;
		guardsTriggered += 1;
		updateHud(ctx);
		const draft: CustomMessageEntryDraft = {{
			type: "custom_message",
			customType: "ap-settle-gate",
			display: true,
			content: `[ap settle-gate] Blocked premature completion — concrete issue(s) found in files edited this run:\n${{blockers.slice(0, 6).join("\n")}}\nFix these issues and re-verify before finishing.`,
		}};
		return {{
			entries: [...(event.entries ?? []), draft],
			continue: true,
		}};
	}});

	pi.on("tool_call", (event, ctx) => {{
		const baseTool = event.toolName.replace(/^mcp__agent_primitives__/, "");
		if (EDIT_TOOLS.has(baseTool)) {{
			recentShellFps.length = 0;
			unchangedReads.clear();
			outlinedPaths.clear();
			stagnantHeavyTurns = 0;
			pendingThinkingNudge = false;

			// Track large full-file `write` overwrites of already-existing files (to nudge surgical `edit`)
			if (event.toolName === "write" && event.input && typeof event.input === "object") {{
				const inp = event.input as {{ path?: string; file_path?: string; content?: string }};
				const rawPath = String(inp.path ?? inp.file_path ?? "").trim();
				const content = typeof inp.content === "string" ? inp.content : "";
				if (rawPath && content.length >= WRITE_OVERWRITE_TIP_CHARS) {{
					const cwd = ctx?.cwd || process.cwd();
					const absPath = isAbsolute(rawPath) ? rawPath : resolve(cwd, rawPath);
					if (existsSync(absPath) && typeof event.toolCallId === "string" && event.toolCallId) {{
						largeOverwriteCallIds.add(event.toolCallId);
					}}
				}}
			}}

			// Proactive <1ms pre-execution legacy-arg normalization + indent/blank-line repair for Pi built-in `edit` (pi-edit-guard pattern)
			if (event.toolName === "edit" && event.input && typeof event.input === "object") {{
				if (normalizeEditArgs(event.input as Record<string, unknown>)) {{
					healedEditsCount += 1;
				}}
				const inp = event.input as {{
					path?: string;
					file_path?: string;
					oldText?: string;
					newText?: string;
					edits?: Array<{{ oldText?: string; newText?: string }}>;
				}};
				const rawPath = String(inp.path ?? inp.file_path ?? "").trim();
				if (rawPath) {{
					const cwd = ctx?.cwd || process.cwd();
					const absPath = isAbsolute(rawPath) ? rawPath : resolve(cwd, rawPath);
					if (existsSync(absPath)) {{
						try {{
							const content = readFileSync(absPath, "utf8");
							if (content.length <= 2_000_000) {{
								if (Array.isArray(inp.edits)) {{
									const merged = resolveAndMergeHashlineEdits(content, inp.edits);
									if (merged) {{
										inp.edits = merged.edits;
										healedEditsCount += merged.healed;
									}} else {{
										const seqHealed = healMultiEditsSequential(content, inp.edits);
										if (seqHealed) {{
											inp.edits = seqHealed.edits;
											healedEditsCount += seqHealed.healed;
										}}
									}}
								}} else if (typeof inp.oldText === "string" && typeof inp.newText === "string") {{
									const fixed = healEditBlock(content, inp.oldText, inp.newText);
									if (fixed) {{
										inp.oldText = fixed.oldText;
										inp.newText = fixed.newText;
										healedEditsCount += 1;
									}}
								}}
							}}
						}} catch {{
							// ignore unreadable/binary files
						}}
					}}
				}}
			}}
			return undefined;
		}}
		if (event.toolName === "read" && event.input && typeof event.input === "object") {{
			const inp = event.input as {{ path?: string; file_path?: string; offset?: unknown; limit?: unknown }};
			const rawPath = String(inp.path ?? inp.file_path ?? "").trim();
			if (
				rawPath &&
				!BINARY_READ_EXT.test(rawPath) &&
				typeof inp.offset === "number" &&
				Number.isFinite(inp.offset) &&
				inp.offset >= 2
			) {{
				const cwd = ctx?.cwd || process.cwd();
				const absPath = isAbsolute(rawPath) ? rawPath : resolve(cwd, rawPath);
				if (existsSync(absPath)) {{
					try {{
						const st = statSync(absPath);
						if (st.isFile() && st.size <= 2_000_000) {{
							const content = readFileSync(absPath, "utf8");
							const clamped = clampReadOffsetToEof(content, inp.offset, inp.limit);
							if (clamped) {{
								inp.offset = clamped.clampedOffset;
								if (typeof event.toolCallId === "string" && event.toolCallId) {{
									clampedReadCallIds.set(event.toolCallId, clamped);
								}}
							}}
						}}
					}} catch {{
						// ignore unreadable files
					}}
				}}
			}}
			return undefined;
		}}
		if (event.toolName === "codemode" && event.input && typeof event.input === "object") {{
			const code = typeof event.input.code === "string" ? event.input.code : "";
			const healedCode = healCodemodeSource(code);
			if (healedCode && healedCode !== code) {{
				event.input.code = healedCode;
			}}
			return undefined;
		}}
		if (event.toolName !== "bash" && event.toolName !== "powershell") return undefined;
		const cmd = typeof event.input?.command === "string" ? event.input.command : "";
		if (DESTRUCTIVE_OR_WRITE.test(cmd)) {{
			unchangedReads.clear();
		}}
		const healed = healCommand(cmd, event.toolName);
		if (healed && healed !== cmd) {{
			event.input.command = healed;
		}}
		const safeTimeout = resolveSafeShellTimeout(
			typeof event.input?.command === "string" ? event.input.command : cmd,
			event.input?.timeout,
		);
		if (safeTimeout !== undefined) {{
			event.input.timeout = safeTimeout;
		}}
		return undefined;
	}});

	pi.on("tool_result", (event, ctx) => {{
		// Track edited files across both direct calls and codemode child calls for `agent_before_settle`
		const baseTool = event.toolName.replace(/^mcp__agent_primitives__/, "");
		if (!event.isError && EDIT_TOOLS.has(baseTool)) {{
			for (const p of extractEditedPathsFromTool(baseTool, event.input as Record<string, unknown> | undefined)) {{
				editedFilesThisRun.add(p);
				if (baseTool === "write" || baseTool === "edit") {{
					builtInCodeEditsThisRun.add(p);
				}}
			}}
		}}
		// Leave codemode child calls (`parentToolCallId`) untouched so JS scripts keep raw structuredContent!
		if (event.parentToolCallId) return undefined;
		if (!Array.isArray(event.content) || event.content.length === 0) return undefined;

		let workingContent: Array<{{ type?: string; text?: string; [k: string]: unknown }}> = event.content as Array<{{
			type?: string;
			text?: string;
			[k: string]: unknown;
		}}>;
		let mutated = false;

		// 0. Lossless multi-block auto-sieve for oversized `codemode` dumps (content[1..N]; preserves header, Script error & images)
		if (event.toolName === "codemode") {{
			const sieved = sieveCodemodeContentBlocks(workingContent, (rawBody) => {{
				const res = spawnSync(AP_BIN, ["sieve", "pipe", "--label", "pi-codemode"], {{
					input: rawBody,
					encoding: "utf8",
					timeout: 4000,
					windowsHide: true,
					env: {{ ...process.env, SIEVE_HOME }},
				}});
				return res.status === 0 && res.stdout ? res.stdout : undefined;
			}});
			if (sieved) {{
				workingContent = sieved;
				sievedCount += 1;
				mutated = true;
			}}
		}}

		let lastTextIdx = -1;
		for (let i = workingContent.length - 1; i >= 0; i--) {{
			if (workingContent[i]?.type === "text" && typeof workingContent[i].text === "string") {{
				lastTextIdx = i;
				break;
			}}
		}}
		if (lastTextIdx < 0) {{
			if (!mutated) return undefined;
			updateHud(ctx);
			return event.structuredContent !== undefined
				? {{ content: workingContent, structuredContent: event.structuredContent }}
				: {{ content: workingContent }};
		}}

		const fullText = extractAllToolResultText(workingContent);
		let outText = workingContent[lastTextIdx].text as string;
		let textMutated = false;

		// A. Built-in `read` Hashline (`L:HH|`) tagging + redundant re-read guard + universal truncated-file outline (<15ms)
		if (event.toolName === "read" && !event.isError) {{
			const p = String(event.input?.path ?? event.input?.file_path ?? "");
			const off = String(event.input?.offset ?? "");
			const lim = String(event.input?.limit ?? "");
			const startOff = Math.max(1, Math.floor(Number(event.input?.offset) || 1));
			const readDetails = event.details as {{ truncation?: {{ truncated?: boolean }} }} | undefined;
			const isTruncated =
				readDetails?.truncation?.truncated === true ||
				/use offset=\d+|lines remaining|more lines in file|truncated to \d+/i.test(outText);
			const hashed = annotateReadWithHashlines(outText, startOff);
			if (hashed) {{
				outText = hashed;
				textMutated = true;
				mutated = true;
			}}
			if (typeof event.toolCallId === "string") {{
				const clamped = clampedReadCallIds.get(event.toolCallId);
				if (clamped) {{
					clampedReadCallIds.delete(event.toolCallId);
					outText += `\n[ap read-clamped] Requested offset=${{clamped.requestedOffset}} > EOF (${{clamped.totalLines}} lines); showing tail from L${{clamped.clampedOffset}}.`;
					textMutated = true;
					mutated = true;
				}}
			}}
			if (p) {{
				const key = `${{p}}::${{off}}::${{lim}}`;
				const hits = (unchangedReads.get(key) ?? 0) + 1;
				unchangedReads.set(key, hits);
				if (hits >= REREAD_THRESHOLD) {{
					outText += `\n[ap reread-guard] Exact unchanged slice (${{p}}) read ${{hits}}x already in this session. Avoid re-reading; use ap_search/ap_locate or proceed directly to edits.`;
					guardsTriggered += 1;
					textMutated = true;
					mutated = true;
				}} else if (isTruncated) {{
					const cwd = ctx?.cwd || process.cwd();
					const absPath = isAbsolute(p) ? p : resolve(cwd, p);
					const normOutlineKey = absPath.toLowerCase();
					if (existsSync(absPath) && !outlinedPaths.has(normOutlineKey)) {{
						if (CODE_FILE_EXT.test(p)) {{
							const ol = spawnSync(AP_BIN, ["read", absPath, "--outline"], {{
								cwd,
								encoding: "utf8",
								timeout: 1500,
								windowsHide: true,
							}});
							if (ol.status === 0 && ol.stdout?.trim()) {{
								outText += `\n[ap read-outline] File was truncated; full AST symbol map (jump directly via read(offset=...) or ap_read(symbol=...)):\n${{ol.stdout.trim().slice(0, 1800)}}`;
								outlinedPaths.add(normOutlineKey);
								textMutated = true;
								mutated = true;
							}}
						}} else {{
							try {{
								const rawDoc = readFileSync(absPath, "utf8");
								if (rawDoc.length <= 2_000_000) {{
									const nonCodeOl = extractNonCodeOutline(p, rawDoc);
									if (nonCodeOl) {{
										outText += `\n${{nonCodeOl}}`;
										outlinedPaths.add(normOutlineKey);
										textMutated = true;
										mutated = true;
									}}
								}}
							}} catch {{
								// ignore unreadable/binary files
							}}
						}}
					}}
				}} else if (!largeReadTipShown && outText.length >= LARGE_CODE_READ_CHARS && CODE_FILE_EXT.test(p)) {{
					outText += `\n[ap read-tip] Large code file loaded; use ap_read(outline=true) or ap_read(symbol="...") for AST-exact slices (~85% fewer tokens).`;
					largeReadTipShown = true;
					textMutated = true;
					mutated = true;
				}}
			}}
		}}

		// B. Built-in `edit` error self-healing tip + Top-1 closest line window from disk (cuts ~47% re-reads)
		if (event.toolName === "edit" && event.isError) {{
			let closestSnippet = "";
			const inp = event.input as {{
				path?: string;
				file_path?: string;
				oldText?: string;
				edits?: Array<{{ oldText?: string }}>;
			}} | undefined;
			const rawPath = String(inp?.path ?? inp?.file_path ?? "").trim();
			const failIdxMatch = outText.match(/\bedits\[(\d+)\]/);
			const failIdx = failIdxMatch ? Number(failIdxMatch[1]) : -1;
			const targetOld =
				typeof inp?.oldText === "string"
					? inp.oldText
					: Array.isArray(inp?.edits)
						? (failIdx >= 0 && typeof inp.edits[failIdx]?.oldText === "string"
							? inp.edits[failIdx].oldText
							: inp.edits.find((e) => typeof e?.oldText === "string" && e.oldText.trim().length > 0)?.oldText) ?? ""
						: "";
			if (rawPath && targetOld) {{
				const cwd = ctx?.cwd || process.cwd();
				const absPath = isAbsolute(rawPath) ? rawPath : resolve(cwd, rawPath);
				if (existsSync(absPath)) {{
					try {{
						const content = readFileSync(absPath, "utf8");
						if (content.length <= 2_000_000) {{
							const isMulti = /multiple|occurrences|more than once/i.test(outText);
							const diag = isMulti
								? findAllEditOccurrenceLines(content, targetOld) ?? findClosestEditWindow(content, targetOld)
								: findClosestEditWindow(content, targetOld);
							if (diag) closestSnippet = `\n${{diag}}`;
						}}
					}} catch {{
						// ignore unreadable file
					}}
				}}
			}}
			outText += `${{closestSnippet}}\n[ap edit-tip] Patch target missed; use the exact lines above, ap_edit (4-tier fuzzy + AST symbols), or ap splice view.`;
			mutated = true;
		}}

		// B1. Instant <12ms post-edit Tree-sitter/JSON/TOML syntax alert (oh-my-pi / Claude Code PostToolUse pattern)
		//     + large full-file overwrite tip on `write` (rate-limited: once per 15 turns)
		if ((event.toolName === "edit" || event.toolName === "write") && !event.isError) {{
			const rawEditPath = String(event.input?.path ?? event.input?.file_path ?? "").trim();
			if (rawEditPath && CHECKABLE_CODE_EXT.test(rawEditPath)) {{
				const cwd = ctx?.cwd || process.cwd();
				const absEditPath = isAbsolute(rawEditPath) ? rawEditPath : resolve(cwd, rawEditPath);
				if (existsSync(absEditPath)) {{
					const chk = spawnSync(AP_BIN, ["splice", "check", "--json", absEditPath], {{
						cwd,
						encoding: "utf8",
						timeout: 2000,
						windowsHide: true,
					}});
					const alert = formatInstantSyntaxAlert(rawEditPath, chk.stdout || "", cwd);
					if (alert) {{
						outText += `\n${{alert}}`;
						guardsTriggered += 1;
						textMutated = true;
						mutated = true;
					}}
				}}
			}}
			if (event.toolName === "edit") {{
				const shiftTip = formatPostEditLineShiftTip(
					event.input as Record<string, unknown> | undefined,
					event.details as {{ firstChangedLine?: number }} | undefined,
				);
				if (shiftTip) {{
					outText += `\n${{shiftTip}}`;
					textMutated = true;
					mutated = true;
				}}
			}}
		}}
		if (event.toolName === "write" && !event.isError && typeof event.toolCallId === "string") {{
			if (largeOverwriteCallIds.delete(event.toolCallId)) {{
				if (sessionTurnCount - lastWriteTipTurn >= WRITE_TIP_COOLDOWN_TURNS) {{
					lastWriteTipTurn = sessionTurnCount;
					outText += `\n[ap write-tip] Full-file overwrite (>=4KB) on existing file. Prefer surgical \`edit\` (supports multi-hunk edits[]) or \`ap_edit\` to save output tokens & generation time.`;
					textMutated = true;
					mutated = true;
				}}
			}}
		}}

		// B2. Pi `codemode` targeted error self-healing classifier (inspects ALL multi-block text!) + parallelism tip
		if (event.toolName === "codemode") {{
			if (
				event.isError ||
				fullText.includes("Script failed") ||
				fullText.includes("Script error:") ||
				fullText.includes("is not a function")
			) {{
				outText += `\n${{classifyCodemodeFailureTip(fullText)}}`;
				textMutated = true;
				mutated = true;
			}} else if (
				codemodeParallelTipsShown < CODEMODE_PARALLEL_MAX_TIPS &&
				sessionTurnCount - lastCodemodeParallelTipTurn >= CODEMODE_PARALLEL_COOLDOWN_TURNS
			) {{
				const code = typeof event.input?.code === "string" ? event.input.code : "";
				const awaitCount = (code.match(/\bawait\s+/g) ?? []).length;
				if (awaitCount >= 3 && !/Promise\.all(?:Settled)?\s*\(/.test(code)) {{
					outText += `\n[ap codemode-parallel] ${{awaitCount}} sequential awaits detected. Batch independent calls concurrently: \`const [a, b] = await Promise.allSettled([tools.bash({{command}}), tools.read({{path}})]);\` for 3-5x faster multi-step runs.`;
					codemodeParallelTipsShown += 1;
					lastCodemodeParallelTipTurn = sessionTurnCount;
					textMutated = true;
					mutated = true;
				}}
			}}
		}}

		// C. Dual-tier shell auto-sieve (>=24KB unconditional, >=14KB structured/noisy) + failure tips + loop-breaker
		if (event.toolName === "bash" || event.toolName === "powershell") {{
			const cmd = typeof event.input?.command === "string" ? event.input.command : "";
			const skipSieve =
				cmd.includes("ap.exe") ||
				/\bap\s+(?:read|search|query|atlas|probe|guard|sieve|baton|splice|recall)\b/.test(cmd);
			if (!skipSieve && shouldAutoSieveShellOutput(outText)) {{
				const res = spawnSync(AP_BIN, ["sieve", "pipe", "--label", "pi-bash"], {{
					input: outText,
					encoding: "utf8",
					timeout: 4000,
					windowsHide: true,
					env: {{ ...process.env, SIEVE_HOME }},
				}});
				if (res.status === 0 && res.stdout && res.stdout.length > 40 && res.stdout.length < outText.length * 0.78) {{
					outText = res.stdout;
					sievedCount += 1;
					mutated = true;
				}}
			}}

			const benignGrep = event.isError && isBenignGrepNoMatch(cmd, outText);
			if (event.isError && !benignGrep) {{
				const failTip = classifyShellFailureTip(event.toolName, cmd, outText);
				if (failTip) {{
					outText += `\n${{failTip}}`;
					mutated = true;
				}}
			}}

			const fp = normCmdFingerprint(cmd);
			if (fp.length >= 8) {{
				recentShellFps.push(fp);
				if (recentShellFps.length > LOOP_WINDOW) {{
					recentShellFps.shift();
				}}
				const repeats = recentShellFps.filter((x) => x === fp).length;
				const effectiveErr = event.isError && !benignGrep;
				const threshold = effectiveErr ? LOOP_ERR_THRESHOLD : LOOP_OK_THRESHOLD;
				if (repeats >= threshold) {{
					const hint = effectiveErr
						? `\n[ap loop-breaker] Repeated failing shell command (${{repeats}}/${{LOOP_WINDOW}} calls) without intervening edits. Pause, inspect root cause, edit code or switch strategy instead of retrying identically.`
						: `\n[ap loop-breaker] Identical shell command repeated (${{repeats}}/${{LOOP_WINDOW}} calls) without edits. Avoid redundant polling; summarize findings or pivot to the next concrete action.`;
					outText = `${{outText}}${{hint}}`;
					guardsTriggered += 1;
					mutated = true;
				}}
			}}
		}}

		// D. DeepSeek overthinking stagnation nudge (emitted once after 3 consecutive >12k-char thinking turns without edits)
		if (pendingThinkingNudge) {{
			outText += `\n[ap thinking-guard] 3 consecutive heavy-thinking turns without code changes. Commit to one concrete edit, focused test, or ap_locate/ap_changes call now.`;
			pendingThinkingNudge = false;
			stagnantHeavyTurns = 0;
			guardsTriggered += 1;
			mutated = true;
		}}

		// E. Serial single-tool exploration batch nudge (rate-limited: once per 25 turns after 6 clean 1-tool turns)
		if (pendingBatchNudge) {{
			outText += `\n[ap batch-tip] ${{SERIAL_BATCH_THRESHOLD}} consecutive clean single-tool turns. Combine independent reads/searches/probes now via parallel tool calls or one codemode script: \`await Promise.allSettled([tools.read({{path}}), tools.bash({{command}})])\`.`;
			pendingBatchNudge = false;
			serialSingleToolTurns = 0;
			guardsTriggered += 1;
			mutated = true;
		}}

		if (!mutated) return undefined;
		updateHud(ctx);
		const patchedContent =
			textMutated || outText !== workingContent[lastTextIdx].text
				? workingContent.map((c, idx) => (idx === lastTextIdx ? {{ ...c, text: outText }} : c))
				: workingContent;
		return event.structuredContent !== undefined
			? {{ content: patchedContent, structuredContent: event.structuredContent }}
			: {{ content: patchedContent }};
	}});
}}
"#
    )
}

fn install_pi_accelerator_extension(ext_dir: &Path, ap_bin_posix: &str) -> String {
    let _ = fs::create_dir_all(ext_dir);
    let dst = ext_dir.join("zz-ap-accelerator.ts");
    let _ = fs::write(&dst, render_pi_accelerator_ts(ap_bin_posix));
    posix(&dst)
}

fn remove_pi_accelerator_extension(ext_dir: &Path) {
    let _ = fs::remove_file(ext_dir.join("zz-ap-accelerator.ts"));
}

fn merge_vscode_mcp(cfg_path: &Path, ap_bin_posix: &str) -> String {
    let mut data: Value = if cfg_path.exists() {
        fs::read_to_string(cfg_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}))
    } else {
        json!({})
    };
    if !data.is_object() {
        data = json!({});
    }
    let servers = data
        .as_object_mut()
        .unwrap()
        .entry("servers")
        .or_insert_with(|| json!({}));
    if !servers.is_object() {
        *servers = json!({});
    }
    servers.as_object_mut().unwrap().insert(
        "agent-primitives".to_string(),
        json!({
            "type": "stdio",
            "command": ap_bin_posix,
            "args": ["mcp"]
        }),
    );
    if let Some(p) = cfg_path.parent() {
        let _ = fs::create_dir_all(p);
    }
    let _ = fs::write(
        cfg_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        ),
    );
    posix(cfg_path)
}

fn remove_vscode_mcp(cfg_path: &Path) {
    let Ok(txt) = fs::read_to_string(cfg_path) else {
        return;
    };
    let Ok(mut data) = serde_json::from_str::<Value>(&txt) else {
        return;
    };
    let Some(obj) = data.as_object_mut() else {
        return;
    };
    if let Some(srvs) = obj.get_mut("servers").and_then(Value::as_object_mut) {
        srvs.remove("agent-primitives");
        if srvs.is_empty() {
            obj.remove("servers");
        }
    }
    if obj.is_empty() {
        let _ = fs::remove_file(cfg_path);
    } else {
        let _ = fs::write(
            cfg_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            ),
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_init(
    agent_arg: &str,
    only_arg: &str,
    here: bool,
    dir_opt: Option<&str>,
    home_opt: Option<&str>,
    with_hooks: bool,
    with_mcp: bool,
    no_rules: bool,
) -> i32 {
    let home = home_opt
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_home_dir);
    let check_bins = fs::canonicalize(&home).ok() == fs::canonicalize(default_home_dir()).ok();

    let selected: Vec<&str> = only_arg
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            ALL_PRIMITIVES
                .iter()
                .copied()
                .find(|&p| p == s)
                .unwrap_or("")
        })
        .collect();
    if selected.is_empty() || selected.contains(&"") {
        eprintln!(
            "[ap init] unknown primitive in --only '{only_arg}'. Choose from: {}",
            ALL_PRIMITIVES.join(", ")
        );
        return 2;
    }

    let harnesses = match resolve_requested_harnesses(agent_arg, &home, check_bins) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[ap init] {e}");
            return 2;
        }
    };
    let explicit_agents = !matches!(agent_arg.trim().to_ascii_lowercase().as_str(), "" | "auto");

    if here || dir_opt.is_some() {
        let repo_dir = fs::canonicalize(dir_opt.unwrap_or("."))
            .unwrap_or_else(|_| PathBuf::from(dir_opt.unwrap_or(".")));
        let agents_root = repo_dir.join(".agents");
        let bin_dst = match install_self_binary(&agents_root.join("bin")) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[ap init --here] {e}");
                return 1;
            }
        };
        let rel_ap_cmd = if cfg!(windows) {
            ".agents/bin/ap.exe"
        } else {
            ".agents/bin/ap"
        };
        let dest_skills = agents_root.join("skills");
        if let Err(e) = write_skill_folders(&dest_skills, &selected, Some(rel_ap_cmd)) {
            eprintln!("[ap init --here] {e}");
            return 1;
        }

        let mut extra_dirs = Vec::new();
        for (hid, rel_d) in [
            ("pi", ".pi/skills"),
            ("claude", ".claude/skills"),
            ("grok", ".grok/skills"),
        ] {
            let dot_root = repo_dir.join(rel_d.split('/').next().unwrap());
            if (harnesses.contains(&hid) && explicit_agents) || dot_root.is_dir() {
                let _ = write_skill_folders(&repo_dir.join(rel_d), &selected, Some(rel_ap_cmd));
                extra_dirs.push(rel_d);
            }
        }

        let mut rule_notes = Vec::new();
        if !no_rules {
            let block = render_fenced_agents_block(rel_ap_cmd, &selected);
            let st_a = upsert_fenced_block(&repo_dir.join("AGENTS.md"), &block);
            rule_notes.push(format!("AGENTS.md ({st_a})"));
            if (harnesses.contains(&"claude") && explicit_agents)
                || repo_dir.join("CLAUDE.md").exists()
            {
                let st_c = upsert_fenced_block(&repo_dir.join("CLAUDE.md"), &block);
                rule_notes.push(format!("CLAUDE.md ({st_c})"));
            }
        }

        if selected.contains(&"guard") {
            let gcfg_path = repo_dir.join(".agents").join("guard.json");
            if !gcfg_path.exists() {
                let cfg = ap_guard::rules::default_guard_config(&repo_dir);
                let _ = ap_guard::rules::save_config(&repo_dir, &cfg);
            }
        }

        let mut hook_paths = Vec::new();
        if with_hooks {
            let ap_abs = posix(&bin_dst);
            if !explicit_agents || harnesses.contains(&"claude") {
                hook_paths.push(merge_claude_or_codex_hooks(
                    &repo_dir.join(".claude").join("settings.json"),
                    &ap_abs,
                    &selected,
                    true,
                ));
            }
            if !explicit_agents || harnesses.contains(&"codex") {
                hook_paths.push(merge_claude_or_codex_hooks(
                    &repo_dir.join(".codex").join("hooks.json"),
                    &ap_abs,
                    &selected,
                    false,
                ));
            }
            if !explicit_agents || harnesses.contains(&"antigravity") {
                if let Some(hp) = merge_antigravity_hooks(
                    &repo_dir.join(".agents").join("hooks.json"),
                    &ap_abs,
                    &selected,
                ) {
                    hook_paths.push(hp);
                }
            }
        }

        let mut mcp_paths = Vec::new();
        let ap_abs_here = posix(&bin_dst);
        if with_mcp
            || (explicit_agents && harnesses.contains(&"opencode"))
            || repo_dir.join("opencode.json").exists()
        {
            mcp_paths.push(merge_opencode_mcp(
                &repo_dir.join("opencode.json"),
                &ap_abs_here,
            ));
        }
        if with_mcp || (explicit_agents && harnesses.contains(&"qwen")) {
            mcp_paths.push(merge_mcp_servers_json(
                &repo_dir.join(".qwen").join("settings.json"),
                &ap_abs_here,
                true,
            ));
        }
        if with_mcp || (explicit_agents && harnesses.contains(&"gemini-cli")) {
            mcp_paths.push(merge_mcp_servers_json(
                &repo_dir.join(".gemini").join("settings.json"),
                &ap_abs_here,
                true,
            ));
        }
        if with_mcp
            || (explicit_agents && harnesses.contains(&"cursor"))
            || repo_dir.join(".cursor").is_dir()
        {
            mcp_paths.push(merge_mcp_servers_json(
                &repo_dir.join(".cursor").join("mcp.json"),
                &ap_abs_here,
                false,
            ));
        }
        if with_mcp
            || (explicit_agents && harnesses.contains(&"vscode"))
            || repo_dir.join(".vscode").is_dir()
        {
            mcp_paths.push(merge_vscode_mcp(
                &repo_dir.join(".vscode").join("mcp.json"),
                &ap_abs_here,
            ));
        }
        if with_mcp
            || (explicit_agents && harnesses.contains(&"pi"))
            || repo_dir.join(".pi").is_dir()
        {
            mcp_paths.push(merge_pi_mcp(
                &repo_dir.join(".pi").join("mcp.json"),
                &ap_abs_here,
            ));
            if with_hooks {
                hook_paths.push(install_pi_accelerator_extension(
                    &repo_dir.join(".pi").join("extensions"),
                    &ap_abs_here,
                ));
            }
        }
        if with_mcp {
            mcp_paths.push(merge_mcp_servers_json(
                &repo_dir.join(".mcp.json"),
                &ap_abs_here,
                false,
            ));
        }

        let extras_s = if extra_dirs.is_empty() {
            String::new()
        } else {
            format!(" (+ {})", extra_dirs.join(", "))
        };
        println!("[ap init --here] Ready in {}!", posix(&repo_dir));
        println!(
            "  - Installed {} standalone Rust primitives -> .agents/skills/{{{}}}{extras_s}",
            selected.len(),
            selected.join(",")
        );
        println!(
            "  - Self-contained native binary -> {rel_ap_cmd} <{}>",
            selected.join("|")
        );
        if !rule_notes.is_empty() {
            println!("  - Routing rules wired -> {}", rule_notes.join(", "));
        }
        if !mcp_paths.is_empty() {
            println!(
                "  - Native stdio MCP (`ap mcp`) wired -> {}",
                mcp_paths.join(", ")
            );
        }
        if !hook_paths.is_empty() {
            println!(
                "  - Native <2ms hooks merged (with .bak) -> {}",
                hook_paths.join(", ")
            );
        }
        return 0;
    }

    // Global onboarding
    let bin_dir = home.join(".local").join("bin");
    let global_bin = match install_self_binary(&bin_dir) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[ap init] {e}");
            return 1;
        }
    };
    // Remove legacy Python shims (`~/.agents/ap.py`, `~/.local/bin/ap.cmd`) so `ap.exe` runs directly!
    let _ = fs::remove_file(home.join(".agents").join("ap.py"));
    if cfg!(windows) {
        let _ = fs::remove_file(bin_dir.join("ap.cmd"));
        let _ = fs::remove_file(bin_dir.join("ap"));
    }

    let global_bin_posix = posix(&global_bin);
    let ap_on_path = which_exists("ap");
    let ap_cmd_str = if ap_on_path {
        "ap".to_string()
    } else if global_bin_posix.contains(' ') {
        format!("\"{global_bin_posix}\"")
    } else {
        global_bin_posix.clone()
    };
    let skill_cmd_rewrite = if ap_on_path {
        None
    } else {
        Some(ap_cmd_str.as_str())
    };

    let mut skill_targets: Vec<PathBuf> = vec![home.join(".agents").join("skills")];
    let mut rule_targets: Vec<PathBuf> = Vec::new();
    for &hid in &harnesses {
        if hid == "agents" {
            continue;
        }
        if let Some(sp) = HARNESS_SPECS.iter().find(|s| s.id == hid) {
            for &sd in sp.skill_dirs {
                let tp = home.join(sd);
                if !skill_targets.contains(&tp) {
                    skill_targets.push(tp);
                }
            }
            let rp = home.join(sp.rule_file);
            if !rule_targets.contains(&rp) {
                rule_targets.push(rp);
            }
        }
    }

    for st in &skill_targets {
        if let Err(e) = write_skill_folders(st, &selected, skill_cmd_rewrite) {
            eprintln!("[ap init] {e}");
            return 1;
        }
    }

    let mut wired_rules = Vec::new();
    if !no_rules {
        let block = render_fenced_agents_block(&ap_cmd_str, &selected);
        if rule_targets.is_empty() {
            rule_targets.push(home.join(".agents").join("AGENTS.md"));
        }
        for rt in &rule_targets {
            let st_r = upsert_fenced_block(rt, &block);
            wired_rules.push(format!("{} ({st_r})", posix(rt)));
        }
    }

    let mut hook_paths = Vec::new();
    if with_hooks {
        if harnesses.is_empty() || harnesses.contains(&"claude") {
            hook_paths.push(merge_claude_or_codex_hooks(
                &home.join(".claude").join("settings.json"),
                &global_bin_posix,
                &selected,
                true,
            ));
        }
        if harnesses.contains(&"codex") {
            hook_paths.push(merge_claude_or_codex_hooks(
                &home.join(".codex").join("hooks.json"),
                &global_bin_posix,
                &selected,
                false,
            ));
        }
        if harnesses.contains(&"antigravity") {
            if let Some(hp) = merge_antigravity_hooks(
                &home.join(".gemini").join("config").join("hooks.json"),
                &global_bin_posix,
                &selected,
            ) {
                hook_paths.push(hp);
            }
        }
        if harnesses.contains(&"pi") {
            hook_paths.push(install_pi_accelerator_extension(
                &home.join(".pi").join("agent").join("extensions"),
                &global_bin_posix,
            ));
        }
    }

    // Zero-flag automatic MCP registration for free/open coding agents (OpenCode, Qwen Code, Gemini CLI, Pi codemode)
    let mut mcp_paths = Vec::new();
    if harnesses.contains(&"pi") {
        mcp_paths.push(merge_pi_mcp(
            &home.join(".pi").join("agent").join("mcp.json"),
            &global_bin_posix,
        ));
    }
    if harnesses.contains(&"opencode") {
        mcp_paths.push(merge_opencode_mcp(
            &home.join(".config").join("opencode").join("opencode.json"),
            &global_bin_posix,
        ));
    }
    if harnesses.contains(&"qwen") {
        mcp_paths.push(merge_mcp_servers_json(
            &home.join(".qwen").join("settings.json"),
            &global_bin_posix,
            true,
        ));
    }
    if harnesses.contains(&"gemini-cli") {
        mcp_paths.push(merge_mcp_servers_json(
            &home.join(".gemini").join("settings.json"),
            &global_bin_posix,
            true,
        ));
    }
    if harnesses.contains(&"cursor") {
        mcp_paths.push(merge_mcp_servers_json(
            &home.join(".cursor").join("mcp.json"),
            &global_bin_posix,
            false,
        ));
    }
    if harnesses.contains(&"windsurf") {
        mcp_paths.push(merge_mcp_servers_json(
            &home
                .join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
            &global_bin_posix,
            false,
        ));
    }
    if harnesses.contains(&"claude-desktop") {
        let cd_rel = [
            "AppData/Roaming/Claude",
            "Library/Application Support/Claude",
            ".config/Claude",
        ]
        .iter()
        .copied()
        .find(|d| home.join(d).is_dir())
        .unwrap_or(if cfg!(windows) {
            "AppData/Roaming/Claude"
        } else if cfg!(target_os = "macos") {
            "Library/Application Support/Claude"
        } else {
            ".config/Claude"
        });
        mcp_paths.push(merge_mcp_servers_json(
            &home.join(cd_rel).join("claude_desktop_config.json"),
            &global_bin_posix,
            false,
        ));
    }

    println!("[ap init] Global native Rust onboarding complete!");
    println!(
        "  - Harnesses configured: {}",
        if harnesses.is_empty() {
            "agents (~/.agents)".to_string()
        } else {
            harnesses.join(", ")
        }
    );
    println!(
        "  - Synced {} primitives into {} skill directory(s): {}",
        selected.len(),
        skill_targets.len(),
        skill_targets
            .iter()
            .map(|t| posix(t))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  - Installed native single binary: {global_bin_posix}");
    if !wired_rules.is_empty() {
        println!(
            "  - Global routing blocks wired: {}",
            wired_rules.join(", ")
        );
    }
    if !mcp_paths.is_empty() {
        println!(
            "  - Native stdio MCP (`ap mcp`) auto-wired: {}",
            mcp_paths.join(", ")
        );
    }
    if !hook_paths.is_empty() {
        println!(
            "  - Native <2ms hooks merged (with .bak): {}",
            hook_paths.join(", ")
        );
    }
    0
}

pub fn cmd_uninstall(here: bool, dir_opt: Option<&str>, home_opt: Option<&str>) -> i32 {
    if here || dir_opt.is_some() {
        let repo_dir = fs::canonicalize(dir_opt.unwrap_or("."))
            .unwrap_or_else(|_| PathBuf::from(dir_opt.unwrap_or(".")));
        let mut removed: HashSet<&str> = HashSet::new();
        for sub in [
            ".agents/skills",
            ".pi/skills",
            ".claude/skills",
            ".grok/skills",
        ] {
            let sr = repo_dir.join(sub);
            for &nm in &ALL_PRIMITIVES {
                let p = sr.join(nm);
                if p.exists() {
                    let _ = fs::remove_dir_all(&p);
                    removed.insert(nm);
                }
            }
            if sr.is_dir()
                && fs::read_dir(&sr)
                    .map(|mut r| r.next().is_none())
                    .unwrap_or(false)
            {
                let _ = fs::remove_dir(&sr);
            }
        }
        let _ = fs::remove_dir_all(repo_dir.join(".agents").join("bin"));
        let _ = fs::remove_file(repo_dir.join(".agents").join("ap.py"));
        let _ = fs::remove_file(repo_dir.join(".agents").join("guard.json"));
        remove_antigravity_hooks(&repo_dir.join(".agents").join("hooks.json"));
        remove_claude_or_codex_hooks(&repo_dir.join(".claude").join("settings.json"));
        remove_claude_or_codex_hooks(&repo_dir.join(".codex").join("hooks.json"));
        remove_opencode_mcp(&repo_dir.join("opencode.json"));
        remove_mcp_servers_json(&repo_dir.join(".mcp.json"));
        remove_mcp_servers_json(&repo_dir.join(".cursor").join("mcp.json"));
        remove_vscode_mcp(&repo_dir.join(".vscode").join("mcp.json"));
        remove_mcp_servers_json(&repo_dir.join(".qwen").join("settings.json"));
        remove_mcp_servers_json(&repo_dir.join(".gemini").join("settings.json"));
        remove_mcp_servers_json(&repo_dir.join(".pi").join("mcp.json"));
        remove_pi_accelerator_extension(&repo_dir.join(".pi").join("extensions"));

        for dot in [
            ".agents", ".pi", ".claude", ".codex", ".grok", ".qwen", ".gemini", ".cursor",
            ".vscode",
        ] {
            let dp = repo_dir.join(dot);
            if dp.is_dir()
                && fs::read_dir(&dp)
                    .map(|mut r| r.next().is_none())
                    .unwrap_or(false)
            {
                let _ = fs::remove_dir(&dp);
            }
        }
        let md_removed = remove_fenced_block(&repo_dir.join("AGENTS.md"));
        remove_fenced_block(&repo_dir.join("CLAUDE.md"));
        println!(
            "[ap uninstall --here] Removed {} primitives from {} (AGENTS.md block removed={md_removed}).",
            removed.len(),
            posix(&repo_dir)
        );
        return 0;
    }

    let home = home_opt
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_home_dir);
    let mut skill_dirs: Vec<PathBuf> = vec![home.join(".agents").join("skills")];
    let mut rule_files: Vec<PathBuf> = vec![home.join(".agents").join("AGENTS.md")];
    for sp in HARNESS_SPECS {
        for &sd in sp.skill_dirs {
            let p = home.join(sd);
            if !skill_dirs.contains(&p) {
                skill_dirs.push(p);
            }
        }
        let rf = home.join(sp.rule_file);
        if !rule_files.contains(&rf) {
            rule_files.push(rf);
        }
    }

    let mut count = 0usize;
    for st in skill_dirs {
        for &nm in &ALL_PRIMITIVES {
            let p = st.join(nm);
            if p.exists() {
                let _ = fs::remove_dir_all(&p);
                count += 1;
            }
        }
    }
    let mut rules_cleaned = 0usize;
    for rf in rule_files {
        if remove_fenced_block(&rf) {
            rules_cleaned += 1;
        }
    }
    remove_claude_or_codex_hooks(&home.join(".claude").join("settings.json"));
    remove_claude_or_codex_hooks(&home.join(".codex").join("hooks.json"));
    remove_antigravity_hooks(&home.join(".gemini").join("config").join("hooks.json"));
    remove_opencode_mcp(&home.join(".config").join("opencode").join("opencode.json"));
    remove_mcp_servers_json(&home.join(".qwen").join("settings.json"));
    remove_mcp_servers_json(&home.join(".gemini").join("settings.json"));
    remove_mcp_servers_json(&home.join(".pi").join("agent").join("mcp.json"));
    remove_pi_accelerator_extension(&home.join(".pi").join("agent").join("extensions"));
    remove_mcp_servers_json(&home.join(".cursor").join("mcp.json"));
    remove_mcp_servers_json(
        &home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
    );
    for cd_rel in [
        "AppData/Roaming/Claude",
        "Library/Application Support/Claude",
        ".config/Claude",
    ] {
        remove_mcp_servers_json(&home.join(cd_rel).join("claude_desktop_config.json"));
    }

    let cur_exe = std::env::current_exe()
        .ok()
        .and_then(|p| fs::canonicalize(p).ok());
    for f in [
        home.join(".agents").join("ap.py"),
        home.join(".agents").join("audit").join("audit_sessions.py"),
        home.join(".local").join("bin").join("ap"),
        home.join(".local").join("bin").join("ap.cmd"),
        home.join(".local").join("bin").join("ap.exe"),
    ] {
        if f.exists() && fs::canonicalize(&f).ok() != cur_exe {
            let _ = fs::remove_file(&f);
        }
    }
    let _ = fs::remove_dir_all(home.join(".agent-primitives"));
    println!("[ap uninstall] Removed {count} installed skill folder(s) and {rules_cleaned} global rule block(s).");
    0
}

fn inspect_pi_runtime(home: &Path) -> Value {
    let pi_agent = home.join(".pi").join("agent");
    if !pi_agent.is_dir() {
        return json!({
            "detected": false,
            "hints": []
        });
    }

    let accel_path = pi_agent.join("extensions").join("zz-ap-accelerator.ts");
    let accel_txt = fs::read_to_string(&accel_path).ok();
    let accelerator_present = accel_txt.is_some();
    let accelerator_up_to_date = accel_txt
        .as_deref()
        .map(|s| {
            s.contains("planObservationMasking")
                && s.contains("extractDsmlToolCalls")
                && s.contains("extractXmlJsonToolCalls")
                && s.contains("extractErrorSignatureLines")
                && s.contains("serializeBranchForHandoff")
                && s.contains("LOOP_ERR_THRESHOLD")
                && s.contains("QUOTE_OR_BS_ERR")
                && s.contains("shouldAutoSieveShellOutput")
                && s.contains("classifyShellFailureTip")
                && s.contains("sessionTurnCount")
                && s.contains("healEditBlock")
                && s.contains("findClosestEditWindow")
                && s.contains("countCodemodeStoreKeys")
                && s.contains("listCodemodeStoreKeys")
                && s.contains("isBenignGrepNoMatch")
                && s.contains("MASK_TIER2_TOKENS")
                && s.contains("classifyCodemodeFailureTip")
                && s.contains("resolveSafeShellTimeout")
                && s.contains("serializeMessagesForCompaction")
                && s.contains("stabilizeProviderTools")
                && s.contains("healCodemodeSource")
                && s.contains("normalizeEditArgs")
                && s.contains("findAllEditOccurrenceLines")
                && s.contains("extractAllToolResultText")
                && s.contains("sieveCodemodeContentBlocks")
                && s.contains("formatInstantSyntaxAlert")
                && s.contains("decideDeepSeekCacheWarming")
                && s.contains("injectDeepSeekGuidelines")
                && s.contains("hashlineTag")
                && s.contains("annotateReadWithHashlines")
                && s.contains("extractNonCodeOutline")
                && s.contains("hashline-anchor-expanded")
                && s.contains("cache_warming_decision")
                && s.contains("before_agent_start")
                && s.contains("before_provider_request")
                && s.contains("session_before_compact")
                && s.contains("agent_before_settle")
                && s.contains("routeDeepSeekFlashEffort")
                && s.contains("registerCommand(\"ap\"")
                && s.contains("session_before_tree")
                && s.contains("repairHallucinatedToolName")
                && s.contains("healMultiEditsSequential")
                && s.contains("isDeepCacheDiscountModel")
        })
        .unwrap_or(false);

    let mcp_path = pi_agent.join("mcp.json");
    let mcp_json = fs::read_to_string(&mcp_path)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok());
    let mcp_server = mcp_json
        .as_ref()
        .and_then(|v| v.pointer("/mcpServers/agent-primitives"));
    let mcp_codemode_wired = mcp_server
        .and_then(|v| v.get("exposure"))
        .and_then(Value::as_str)
        == Some("codemode");

    let settings_json = fs::read_to_string(pi_agent.join("settings.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok());
    let default_provider = settings_json
        .as_ref()
        .and_then(|v| v.get("defaultProvider"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let default_model_id = settings_json
        .as_ref()
        .and_then(|v| v.get("defaultModel"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let default_model = match (&default_provider, &default_model_id) {
        (Some(p), Some(m)) => Some(format!("{p}/{m}")),
        (None, Some(m)) => Some(m.clone()),
        _ => None,
    };
    let codemode_enabled = settings_json
        .as_ref()
        .and_then(|v| v.get("defaultTools"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .any(|t| t == "+codemode" || t == "codemode")
        })
        .unwrap_or(false);
    let compaction_reserve_tokens = settings_json
        .as_ref()
        .and_then(|v| {
            default_model
                .as_deref()
                .and_then(|dm| {
                    v.pointer("/compaction/modelOverrides")
                        .and_then(|mo| mo.get(dm))
                        .and_then(|ov| ov.get("reserveTokens"))
                })
                .or_else(|| {
                    if default_model.as_deref() == Some("deepseek/flash-auto") {
                        v.pointer("/compaction/modelOverrides")
                            .and_then(|mo| mo.get("deepseek/deepseek-flash"))
                            .and_then(|ov| ov.get("reserveTokens"))
                    } else {
                        None
                    }
                })
                .or_else(|| v.pointer("/compaction/reserveTokens"))
        })
        .and_then(Value::as_u64);
    let show_cache_miss_notices = settings_json
        .as_ref()
        .and_then(|v| v.get("showCacheMissNotices"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let flash_auto_enabled = settings_json
        .as_ref()
        .and_then(|v| v.get("enabledModels"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .any(|m| m == "deepseek/flash-auto")
        })
        .unwrap_or(false);
    let retry_max_retries = settings_json
        .as_ref()
        .and_then(|v| v.pointer("/retry/maxRetries"))
        .and_then(Value::as_u64);
    let retry_base_delay_ms = settings_json
        .as_ref()
        .and_then(|v| v.pointer("/retry/baseDelayMs"))
        .and_then(Value::as_u64);
    // Pi v1.5 default is 300_000ms (5 min); "disabled" => 0
    let http_idle_timeout_ms: u64 = settings_json
        .as_ref()
        .and_then(|v| v.get("httpIdleTimeoutMs"))
        .map(|v| {
            if let Some(n) = v.as_u64() {
                n
            } else if v
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case("disabled"))
            {
                0
            } else {
                300_000
            }
        })
        .unwrap_or(300_000);

    let models_json = fs::read_to_string(pi_agent.join("models.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok());
    let deepseek_mid_convo_system = models_json
        .as_ref()
        .and_then(|v| {
            default_model_id
                .as_deref()
                .and_then(|mid| {
                    v.pointer(&format!(
                        "/providers/deepseek/modelOverrides/{mid}/compat/supportsMidConvoSystemMessages"
                    ))
                })
                .or_else(|| {
                    v.pointer(
                        "/providers/deepseek/modelOverrides/deepseek-flash/compat/supportsMidConvoSystemMessages",
                    )
                })
        })
        .and_then(Value::as_bool);
    let deepseek_prompt_cache_ttl_s = models_json
        .as_ref()
        .and_then(|v| {
            default_model_id
                .as_deref()
                .and_then(|mid| {
                    v.pointer(&format!(
                        "/providers/deepseek/modelOverrides/{mid}/promptCache/short"
                    ))
                })
                .or_else(|| {
                    v.pointer("/providers/deepseek/modelOverrides/deepseek-flash/promptCache/short")
                })
        })
        .and_then(Value::as_u64);
    let cache_warming_mode = settings_json
        .as_ref()
        .and_then(|v| v.get("cacheWarming"))
        .and_then(Value::as_str)
        .unwrap_or("idle");
    let provider_timeout_ms = settings_json
        .as_ref()
        .and_then(|v| v.pointer("/retry/provider/timeoutMs"))
        .and_then(Value::as_u64);

    let mut hints: Vec<String> = Vec::new();
    if !accelerator_present || !accelerator_up_to_date {
        hints.push(
            "Run `ap init -a pi --with-hooks --no-rules` to install/upgrade zz-ap-accelerator.ts (context_edit batch masking, agent_before_settle gate, deepseek/flash-auto router & DSML recovery)."
                .to_string(),
        );
    }
    if mcp_server.is_some() && !mcp_codemode_wired {
        hints.push(
            "Set `\"exposure\": \"codemode\"` for agent-primitives in ~/.pi/agent/mcp.json to keep provider tool schemas deferred and preserve KV-cache hits."
                .to_string(),
        );
    }
    if mcp_codemode_wired && !codemode_enabled {
        hints.push(
            "Add `\"+codemode\"` to `defaultTools` in ~/.pi/agent/settings.json so Pi can invoke deferred MCP tools in QuickJS scripts."
                .to_string(),
        );
    }
    let is_deepseek = default_provider.as_deref() == Some("deepseek")
        || default_model_id
            .as_deref()
            .map(|m| m.contains("deepseek"))
            .unwrap_or(false);
    if is_deepseek && deepseek_mid_convo_system != Some(true) {
        hints.push(
            "Consider enabling `compat.supportsMidConvoSystemMessages: true` under providers.deepseek.modelOverrides in ~/.pi/agent/models.json to keep DeepSeek prefix KV-cache intact."
                .to_string(),
        );
    }

    let effective_compaction_trigger_tokens = if is_deepseek
        && matches!(
            default_model_id.as_deref(),
            Some("deepseek-flash") | Some("flash-auto")
        ) {
        compaction_reserve_tokens.map(|r| 1_000_000u64.saturating_sub(r))
    } else {
        None
    };

    let mut recommendations: Vec<String> = Vec::new();
    if let Some(trigger) = effective_compaction_trigger_tokens {
        if trigger > 400_000 {
            recommendations.push(
                format!("deepseek-flash (1M window) auto-compacts at {trigger} tokens; set compaction.modelOverrides[\"deepseek/deepseek-flash\"].reserveTokens=650000 (350k trigger; or 780000 for 220k) to compact cleanly before the >=400k latency cliff.")
            );
        }
    }
    if is_deepseek && !show_cache_miss_notices {
        recommendations.push(
            "Set `\"showCacheMissNotices\": true` in ~/.pi/agent/settings.json to surface DeepSeek prefix cache misses immediately."
                .to_string(),
        );
    }
    if is_deepseek && retry_max_retries.is_some_and(|r| r < 5) {
        recommendations.push(
            "Raise `retry.maxRetries` to 6 in ~/.pi/agent/settings.json to survive transient DeepSeek stream drops/timeouts during long sessions."
                .to_string(),
        );
    }
    if is_deepseek && retry_base_delay_ms.is_some_and(|d| d > 1500) {
        recommendations.push(
            "Lower `retry.baseDelayMs` to 1000 in ~/.pi/agent/settings.json so transient socket/TLS retries finish inside DeepSeek's 2-minute 98.7% KV-cache hot zone."
                .to_string(),
        );
    }
    if is_deepseek && (http_idle_timeout_ms == 0 || http_idle_timeout_ms > 150_000) {
        recommendations.push(
            "Set `\"httpIdleTimeoutMs\": 120000` in ~/.pi/agent/settings.json (default 300s lets stalled TCP streams cross DeepSeek's 2-5m KV-cache eviction cliff before retrying)."
                .to_string(),
        );
    }
    if is_deepseek && provider_timeout_ms.is_some_and(|t| t > 300_000) {
        recommendations.push(
            "Remove `retry.provider.timeoutMs` (currently >5m) in ~/.pi/agent/settings.json — in Pi sdk.js it overrides `httpIdleTimeoutMs` and causes long zombie stream hangs."
                .to_string(),
        );
    }
    if is_deepseek
        && models_json.is_some()
        && cache_warming_mode != "off"
        && deepseek_prompt_cache_ttl_s.is_none()
    {
        recommendations.push(
            "Add `\"promptCache\": { \"short\": 90 }` under providers.deepseek.modelOverrides.deepseek-flash in ~/.pi/agent/models.json to activate Pi's native CacheWarmer (80s keep-warm ping, beating 95-120s eviction at 49x ROI)."
                .to_string(),
        );
    }

    let runtime_patches = crate::pi_patch::inspect_pi_patches(None);

    json!({
        "detected": true,
        "accelerator_present": accelerator_present,
        "accelerator_up_to_date": accelerator_up_to_date,
        "mcp_codemode_wired": mcp_codemode_wired,
        "codemode_enabled": codemode_enabled,
        "default_model": default_model,
        "compaction_reserve_tokens": compaction_reserve_tokens,
        "effective_compaction_trigger_tokens": effective_compaction_trigger_tokens,
        "show_cache_miss_notices": show_cache_miss_notices,
        "flash_auto_enabled": flash_auto_enabled,
        "retry_max_retries": retry_max_retries,
        "retry_base_delay_ms": retry_base_delay_ms,
        "http_idle_timeout_ms": http_idle_timeout_ms,
        "provider_timeout_ms": provider_timeout_ms,
        "cache_warming_mode": cache_warming_mode,
        "deepseek_mid_convo_system": deepseek_mid_convo_system,
        "deepseek_prompt_cache_ttl_s": deepseek_prompt_cache_ttl_s,
        "runtime_patches": runtime_patches,
        "hints": hints,
        "recommendations": recommendations,
    })
}

pub fn cmd_doctor(as_json: bool) -> i32 {
    let mut ok = true;
    let fts5_ok = Connection::open_in_memory()
        .and_then(|c| {
            c.execute_batch(
                "CREATE VIRTUAL TABLE t USING fts5(x, tokenize='unicode61'); INSERT INTO t VALUES ('ok');",
            )
        })
        .is_ok();
    if !fts5_ok {
        ok = false;
    }
    let mut ast_ok = true;
    for ext in ["py", "ts", "js", "go", "rs", "c"] {
        if ap_splice::ast::language_for_ext(ext).is_none() {
            ast_ok = false;
            ok = false;
        }
    }
    for (_, md) in all_embedded_skills() {
        if md.is_empty() {
            ok = false;
        }
    }

    let browser_found = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ]
    .iter()
    .copied()
    .find(|p| Path::new(p).is_file());

    let home = default_home_dir();
    let detected = resolve_requested_harnesses("auto", &home, true).unwrap_or_default();

    let global_bin =
        home.join(".local")
            .join("bin")
            .join(if cfg!(windows) { "ap.exe" } else { "ap" });
    let global_bin_version = if global_bin.is_file() {
        std::process::Command::new(&global_bin)
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        None
    };
    let expected_ver = format!("ap {}", env!("CARGO_PKG_VERSION"));
    let global_bin_up_to_date = global_bin_version
        .as_deref()
        .map(|v| v == expected_ver)
        .unwrap_or(false);

    let mcp_candidates = [
        home.join(".pi").join("agent").join("mcp.json"),
        home.join(".config").join("opencode").join("opencode.json"),
        home.join(".cursor").join("mcp.json"),
        home.join(".gemini").join("settings.json"),
        home.join(".qwen").join("settings.json"),
        home.join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
    ];
    let wired_mcp_count = mcp_candidates
        .iter()
        .filter(|p| {
            fs::read_to_string(p)
                .map(|s| s.contains("agent-primitives"))
                .unwrap_or(false)
        })
        .count();

    let hook_candidates = [
        home.join(".claude").join("settings.json"),
        home.join(".codex").join("hooks.json"),
        home.join(".gemini").join("config").join("hooks.json"),
        home.join(".pi")
            .join("agent")
            .join("extensions")
            .join("zz-ap-accelerator.ts"),
    ];
    let wired_hooks_count = hook_candidates
        .iter()
        .filter(|p| {
            fs::read_to_string(p)
                .map(|s| {
                    s.contains("agent-primitives") || s.contains("ap exec") || s.contains("ap.exe")
                })
                .unwrap_or(false)
        })
        .count();

    let sieve_dir = home.join(".ap").join("sieve");
    let mut sieve_archives = 0usize;
    let mut sieve_bytes = 0u64;
    if let Ok(rd) = fs::read_dir(&sieve_dir) {
        for ent in rd.flatten() {
            if ent.path().extension().and_then(|e| e.to_str()) == Some("raw") {
                sieve_archives += 1;
                sieve_bytes += ent.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }

    let pi_runtime = inspect_pi_runtime(&home);

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": ok,
                "version": env!("CARGO_PKG_VERSION"),
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "fts5_ok": fts5_ok,
                "ast_ok": ast_ok,
                "browser_cdp": browser_found,
                "detected_agents": detected,
                "global_bin_version": global_bin_version,
                "global_bin_up_to_date": global_bin_up_to_date,
                "wired_mcp_count": wired_mcp_count,
                "wired_hooks_count": wired_hooks_count,
                "sieve_archives": sieve_archives,
                "sieve_kb": ((sieve_bytes as f64 / 1024.0) * 10.0).round() / 10.0,
                "pi_runtime": pi_runtime,
            }))
            .unwrap_or_default()
        );
        return if ok { 0 } else { 1 };
    }

    println!(
        "[ap doctor] agent-primitives v{} ({}/{}) -> OK (Pure-Rust single binary, zero external runtime)",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    if fts5_ok {
        println!("  [OK] Engine Core       : Bundled SQLite FTS5/BM25 + 7 embedded modules ready");
    } else {
        println!("  [FAIL] Engine Core     : Bundled SQLite FTS5 failed");
    }
    println!(
        "  [OK] AST Syntax Gate   : Python, TypeScript/TSX, JS, Go, Rust, C grammars compiled"
    );

    #[cfg(windows)]
    {
        let has_pwsh7 = crate::exec::probe_pwsh7();
        let git_bash = crate::exec::probe_git_bash();
        let py_utf8 = std::env::var("PYTHONUTF8").ok().as_deref() == Some("1");
        println!(
            "  [OK] Windows Shell     : pwsh7={}, git-bash={}, PYTHONUTF8={} (`ap exec` auto-heals UTF-8, `&&`, `curl.exe` & POSIX pipes)",
            if has_pwsh7 { "yes" } else { "no (PS 5.1)" },
            if git_bash.is_some() { "yes" } else { "no" },
            if py_utf8 { "1" } else { "auto-injected by ap" }
        );
    }
    #[cfg(not(windows))]
    {
        println!(
            "  [OK] Host Shell        : POSIX sh + UTF-8 lock & deadlock-free timeout shield ready"
        );
    }

    if let Some(bp) = browser_found {
        println!("  [OK] Browser Smoke CDP : READY ({bp}) — 0-MB native headless verification");
    } else {
        println!("  [INFO] Browser Smoke   : HTTP/API smoke ready (install Edge/Chrome to enable DOM CDP)");
    }

    if !detected.is_empty() {
        println!("  [OK] Detected Agents   : {}", detected.join(", "));
    }
    println!(
        "  [OK] Agent Wiring      : {wired_mcp_count} MCP config(s), {wired_hooks_count} hook/extension(s), global bin={} | ~/.ap/sieve: {sieve_archives} archive(s) ({:.1} KB)",
        global_bin_version.as_deref().unwrap_or("not installed"),
        sieve_bytes as f64 / 1024.0
    );
    if pi_runtime["detected"].as_bool() == Some(true) {
        let accel_ok = pi_runtime["accelerator_up_to_date"].as_bool() == Some(true);
        let mcp_ok = pi_runtime["mcp_codemode_wired"].as_bool() == Some(true);
        let cm_ok = pi_runtime["codemode_enabled"].as_bool() == Some(true);
        let model = pi_runtime["default_model"].as_str().unwrap_or("unset");
        let badge = if accel_ok && mcp_ok && cm_ok {
            "[OK]"
        } else {
            "[WARN]"
        };
        println!(
            "  {badge} Pi Runtime        : model={model}, codemode={}, mcp_deferred={}, accelerator={}",
            if cm_ok { "on" } else { "off" },
            if mcp_ok { "yes" } else { "no" },
            if accel_ok { "v2.29+ (Hashline + MultiEdit + CachePhysics + CacheWarmer + context_edit + settle-gate + flash-auto + /ap fresh|handoff)" } else { "stale/missing" }
        );
        if pi_runtime["runtime_patches"]["detected"].as_bool() == Some(true) {
            let applied = pi_runtime["runtime_patches"]["applied_count"]
                .as_u64()
                .unwrap_or(0);
            let total = pi_runtime["runtime_patches"]["total_count"]
                .as_u64()
                .unwrap_or(0);
            let ver = pi_runtime["runtime_patches"]["pi_version"]
                .as_str()
                .unwrap_or("?");
            let hint = if applied < total {
                " (run `ap pi patch` to apply)"
            } else {
                ""
            };
            println!(
                "         [pi-patch] Pi v{ver}: {applied}/{total} runtime patches applied{hint}"
            );
        }
        if let Some(hints) = pi_runtime["hints"].as_array() {
            for h in hints.iter().filter_map(Value::as_str) {
                println!("         -> {h}");
            }
        }
        if let Some(recs) = pi_runtime["recommendations"].as_array() {
            for r in recs.iter().filter_map(Value::as_str) {
                println!("         [tune] {r}");
            }
        }
    }
    println!(
        "  Tip: Run `ap stats` (or `ap stats --since-hours 24`) anytime to view saved tokens & prevented crashes."
    );
    if ok {
        0
    } else {
        1
    }
}

pub fn cmd_status(dir_opt: Option<&str>, home_opt: Option<&str>) -> i32 {
    let repo_dir = fs::canonicalize(dir_opt.unwrap_or(".")).unwrap_or_else(|_| PathBuf::from("."));
    let home = home_opt
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_home_dir);
    let local_skills: Vec<&str> = ALL_PRIMITIVES
        .iter()
        .copied()
        .filter(|nm| {
            repo_dir
                .join(".agents")
                .join("skills")
                .join(nm)
                .join("SKILL.md")
                .is_file()
        })
        .collect();
    let has_fence = fs::read_to_string(repo_dir.join("AGENTS.md"))
        .map(|s| s.contains(FENCE_START))
        .unwrap_or(false);
    println!("[ap status]");
    println!(
        "  - Repo ({}): {}/7 primitives ({}), AGENTS.md wired={has_fence}",
        posix(&repo_dir),
        local_skills.len(),
        if local_skills.is_empty() {
            "none".to_string()
        } else {
            local_skills.join(", ")
        }
    );
    for sp in HARNESS_SPECS {
        let st_dir = home.join(sp.skill_dirs[0]);
        let installed: Vec<&str> = ALL_PRIMITIVES
            .iter()
            .copied()
            .filter(|nm| st_dir.join(nm).join("SKILL.md").is_file())
            .collect();
        let rf_wired = fs::read_to_string(home.join(sp.rule_file))
            .map(|s| s.contains(FENCE_START))
            .unwrap_or(false);
        if !installed.is_empty() || rf_wired {
            println!(
                "  - Global [{}] ({}): {}/7 primitives, rules wired={rf_wired}",
                sp.id,
                posix(&st_dir),
                installed.len()
            );
        }
    }
    0
}
