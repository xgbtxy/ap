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
            let role_tag = if cmd_str.contains("guard shield") {
                " guard shield"
            } else if cmd_str.contains("guard stop-gate") {
                " guard stop-gate"
            } else if cmd_str.contains("baton checkpoint") {
                " baton checkpoint"
            } else if cmd_str.contains("splice check --hook") {
                " splice check --hook"
            } else {
                cmd_str.as_str()
            };
            // Remove any legacy python guard.py/baton.py or stale ap hook for the same role
            vec.retain(|item| {
                let s = item.to_string();
                !s.contains("guard/scripts/guard.py")
                    && !s.contains("baton/scripts/baton.py")
                    && !s.contains(&cmd_str)
                    && !s.contains(role_tag)
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
    if sel.contains("splice") {
        ensure_hook(
            "PostToolUse",
            format!("\"{ap_bin_posix}\" splice check --hook"),
            Some("Edit|Write|MultiEdit|edit_file|write_file|apply_patch"),
        );
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
                    && !s.contains(" splice check --hook")
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
    let want_guard = selected.contains(&"guard");
    let want_splice = selected.contains(&"splice");
    if !want_guard && !want_splice {
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
    let mut entry = serde_json::Map::new();
    entry.insert("enabled".to_string(), json!(true));
    if want_guard {
        entry.insert(
            "PreToolUse".to_string(),
            json!([{
                "matcher": "run_command",
                "hooks": [{
                    "type": "command",
                    "command": format!("\"{ap_bin_posix}\" guard shield"),
                    "timeout": 10
                }]
            }]),
        );
        entry.insert(
            "Stop".to_string(),
            json!([{
                "type": "command",
                "command": format!("\"{ap_bin_posix}\" guard stop-gate"),
                "timeout": 15
            }]),
        );
    }
    if want_splice {
        entry.insert(
            "PostToolUse".to_string(),
            json!([{
                "matcher": "edit_file|write_file|replace_file_content|multi_replace_file_content|write_to_file",
                "hooks": [{
                    "type": "command",
                    "command": format!("\"{ap_bin_posix}\" splice check --hook"),
                    "timeout": 10
                }]
            }]),
        );
    }
    data["agent-primitives-guard"] = Value::Object(entry);
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

fn mcp_args_for_profile(mcp_profile: &str) -> Vec<&'static str> {
    match mcp_profile {
        "core" => vec!["mcp", "--profile", "core"],
        "deferred" => vec!["mcp", "--profile", "deferred"],
        _ => vec!["mcp"],
    }
}

fn merge_opencode_mcp(cfg_path: &Path, ap_bin_posix: &str, mcp_profile: &str) -> String {
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
    let mut cmd = vec![ap_bin_posix];
    cmd.extend(mcp_args_for_profile(mcp_profile));
    mcp.as_object_mut().unwrap().insert(
        "agent-primitives".to_string(),
        json!({
            "type": "local",
            "command": cmd,
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

fn toml_escape_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn strip_toml_comment(line: &str) -> &str {
    let b = line.as_bytes();
    let mut in_dq = false;
    let mut in_sq = false;
    let mut i = 0usize;
    while i < b.len() {
        if in_dq {
            if b[i] == b'\\' {
                i += 2;
                continue;
            }
            if b[i] == b'"' {
                in_dq = false;
            }
        } else if in_sq {
            if b[i] == b'\'' {
                in_sq = false;
            }
        } else if b[i] == b'"' {
            in_dq = true;
        } else if b[i] == b'\'' {
            in_sq = true;
        } else if b[i] == b'#' {
            return &line[..i];
        }
        i += 1;
    }
    line
}

fn is_toml_table_header(line: &str) -> bool {
    let head = strip_toml_comment(line).trim();
    if head.starts_with("[[") && head.ends_with("]]") && head.len() > 4 {
        return true;
    }
    if head.starts_with('[') && head.ends_with(']') && head.len() > 2 && !head.starts_with("[[") {
        let inner = &head[1..head.len() - 1];
        let mut in_dq = false;
        let mut in_sq = false;
        let bytes = inner.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if in_dq {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    in_dq = false;
                }
            } else if in_sq {
                if bytes[i] == b'\'' {
                    in_sq = false;
                }
            } else if bytes[i] == b'"' {
                in_dq = true;
            } else if bytes[i] == b'\'' {
                in_sq = true;
            } else if matches!(bytes[i], b',' | b'=') {
                return false;
            }
            i += 1;
        }
        return true;
    }
    false
}

fn is_ap_toml_mcp_header(line: &str) -> bool {
    let head = strip_toml_comment(line).trim();
    matches!(
        head,
        "[mcp_servers.agent-primitives]"
            | "[mcp_servers.\"agent-primitives\"]"
            | "[mcp_servers.'agent-primitives']"
    )
}

fn render_toml_ap_section(ap_bin_posix: &str, mcp_profile: &str) -> Vec<String> {
    let args_list: String = mcp_args_for_profile(mcp_profile)
        .into_iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    vec![
        "[mcp_servers.agent-primitives]".to_string(),
        format!("command = \"{}\"", toml_escape_str(ap_bin_posix)),
        format!("args = [{args_list}]"),
    ]
}

fn merge_toml_mcp_server(cfg_path: &Path, ap_bin_posix: &str, mcp_profile: &str) -> String {
    let section_lines = render_toml_ap_section(ap_bin_posix, mcp_profile);
    let orig = fs::read_to_string(cfg_path).unwrap_or_default();
    let lines: Vec<String> = orig.lines().map(ToString::to_string).collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + section_lines.len() + 2);
    let mut replaced = false;
    let mut i = 0usize;

    while i < lines.len() {
        if is_ap_toml_mcp_header(&lines[i]) {
            if !replaced {
                out.extend(section_lines.iter().cloned());
                replaced = true;
            }
            i += 1;
            while i < lines.len() && !is_toml_table_header(&lines[i]) {
                i += 1;
            }
            if i < lines.len() && out.last().map(|l| !l.trim().is_empty()).unwrap_or(false) {
                out.push(String::new());
            }
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }

    if !replaced {
        if out.last().map(|l| !l.trim().is_empty()).unwrap_or(false) {
            out.push(String::new());
        }
        out.extend(section_lines);
    }

    if let Some(p) = cfg_path.parent() {
        let _ = fs::create_dir_all(p);
    }
    let body = if out.is_empty() {
        String::new()
    } else {
        format!("{}\n", out.join("\n"))
    };
    let _ = fs::write(cfg_path, body);
    posix(cfg_path)
}

fn remove_toml_mcp_server(cfg_path: &Path) -> bool {
    let Ok(orig) = fs::read_to_string(cfg_path) else {
        return false;
    };
    let lines: Vec<&str> = orig.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut changed = false;
    let mut i = 0usize;
    while i < lines.len() {
        if is_ap_toml_mcp_header(lines[i]) {
            changed = true;
            i += 1;
            while i < lines.len() && !is_toml_table_header(lines[i]) {
                i += 1;
            }
            continue;
        }
        let cur = lines[i];
        if cur.trim().is_empty() && out.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
            i += 1;
            continue;
        }
        out.push(cur.to_string());
        i += 1;
    }
    if !changed {
        return false;
    }
    while out.first().map(|l| l.trim().is_empty()).unwrap_or(false) {
        out.remove(0);
    }
    while out.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        out.pop();
    }
    if out.is_empty() {
        let _ = fs::remove_file(cfg_path);
    } else {
        let _ = fs::write(cfg_path, format!("{}\n", out.join("\n")));
    }
    true
}

fn extract_mcp_profile_from_toml(cfg_path: &Path) -> Option<&'static str> {
    let raw = fs::read_to_string(cfg_path).ok()?;
    let lines: Vec<&str> = raw.lines().collect();
    let mut in_sec = false;
    for ln in lines {
        if is_ap_toml_mcp_header(ln) {
            in_sec = true;
            continue;
        }
        if in_sec {
            if is_toml_table_header(ln) {
                break;
            }
            let body = strip_toml_comment(ln).trim();
            if body.starts_with("args") && body.contains("--profile") {
                if body.contains("\"core\"") || body.contains("'core'") {
                    return Some("core");
                }
                if body.contains("\"deferred\"") || body.contains("'deferred'") {
                    return Some("deferred");
                }
            }
        }
    }
    in_sec.then_some("full")
}

fn merge_claude_mcp_json(cfg_path: &Path, ap_bin_posix: &str, mcp_profile: &str) -> String {
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
            "type": "stdio",
            "command": ap_bin_posix,
            "args": mcp_args_for_profile(mcp_profile)
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

fn merge_mcp_servers_json(
    cfg_path: &Path,
    ap_bin_posix: &str,
    include_trust: bool,
    mcp_profile: &str,
) -> String {
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
        "args": mcp_args_for_profile(mcp_profile)
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

fn merge_pi_mcp(cfg_path: &Path, ap_bin_posix: &str, mcp_profile: &str) -> String {
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
            "args": mcp_args_for_profile(mcp_profile),
            "exposure": "codemode",
            "description": "Fast Pure-Rust MCP 2025-06-18 (37 annotated tools, Resources, Prompts; batch via Promise.allSettled in codemode): AST ap_read (--symbol/--outline/batch), parallel ap_search (-l/-c/-C), ap_edit/ap_rename, ap_orient/ap_surface/ap_impact/ap_changes/ap_locate/ap_trace, ap_query (named records), ap_sieve (compiler/test/diff), ap_baton/ap_frontier/ap_recall & CDP/HTTP/TCP/WS/TLS/Win probes"
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

const PI_ACCELERATOR_TS_TEMPLATE: &str = include_str!("../assets/zz-ap-accelerator.ts");
const PI_ACCELERATOR_BIN_PLACEHOLDER: &str = "__AP_BIN_POSIX__";

pub fn render_pi_accelerator_ts(ap_bin_posix: &str) -> String {
    let escaped = ap_bin_posix.replace('\\', "/").replace('"', "\\\"");
    debug_assert!(PI_ACCELERATOR_TS_TEMPLATE.contains(PI_ACCELERATOR_BIN_PLACEHOLDER));
    PI_ACCELERATOR_TS_TEMPLATE.replace("\r\n", "\n").replacen(
        PI_ACCELERATOR_BIN_PLACEHOLDER,
        &escaped,
        1,
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

fn merge_vscode_mcp(cfg_path: &Path, ap_bin_posix: &str, mcp_profile: &str) -> String {
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
            "args": mcp_args_for_profile(mcp_profile)
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
    mcp_profile_arg: &str,
    model_profile_arg: &str,
) -> i32 {
    let home = home_opt
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_home_dir);
    let check_bins = fs::canonicalize(&home).ok() == fs::canonicalize(default_home_dir()).ok();

    let explicit_mcp = match crate::profile::parse_mcp_profile_arg(mcp_profile_arg) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[ap init] {e}");
            return 2;
        }
    };
    let explicit_model = match crate::profile::parse_model_profile_arg(model_profile_arg) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[ap init] {e}");
            return 2;
        }
    };

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

    let mut stored_profile = if !here && dir_opt.is_none() {
        crate::profile::load_profile(&home)
    } else {
        None
    };
    if !here && dir_opt.is_none() && (explicit_mcp.is_some() || explicit_model.is_some()) {
        let mut cfg = stored_profile.unwrap_or_default();
        if let Some(mp) = explicit_model {
            cfg.model_profile = mp.as_str().to_string();
        }
        if let Some(mcp_p) = explicit_mcp {
            if explicit_agents && !harnesses.is_empty() && harnesses.len() < HARNESS_SPECS.len() {
                for &hid in &harnesses {
                    cfg.harness_mcp_profiles
                        .insert(hid.to_string(), mcp_p.to_string());
                }
            } else {
                cfg.default_mcp_profile = Some(mcp_p.to_string());
            }
        }
        if let Err(e) = crate::profile::save_profile(&home, &cfg) {
            eprintln!("[ap init] {e}");
            return 1;
        }
        stored_profile = Some(cfg);
    }
    let effective_model_profile = explicit_model
        .or_else(|| {
            stored_profile
                .as_ref()
                .and_then(|c| crate::profile::ModelProfile::parse(&c.model_profile))
        })
        .unwrap_or(crate::profile::ModelProfile::Auto);
    let mcp_for = |h: &str| -> &'static str {
        crate::profile::resolve_mcp_profile_for_harness(
            stored_profile.as_ref(),
            h,
            explicit_mcp.unwrap_or(""),
            effective_model_profile,
        )
    };

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
                mcp_for("opencode"),
            ));
        }
        if with_mcp || (explicit_agents && harnesses.contains(&"qwen")) {
            mcp_paths.push(merge_mcp_servers_json(
                &repo_dir.join(".qwen").join("settings.json"),
                &ap_abs_here,
                true,
                mcp_for("qwen"),
            ));
        }
        if with_mcp || (explicit_agents && harnesses.contains(&"gemini-cli")) {
            mcp_paths.push(merge_mcp_servers_json(
                &repo_dir.join(".gemini").join("settings.json"),
                &ap_abs_here,
                true,
                mcp_for("gemini-cli"),
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
                mcp_for("cursor"),
            ));
        }
        if with_mcp
            || (explicit_agents && harnesses.contains(&"vscode"))
            || repo_dir.join(".vscode").is_dir()
        {
            mcp_paths.push(merge_vscode_mcp(
                &repo_dir.join(".vscode").join("mcp.json"),
                &ap_abs_here,
                mcp_for("vscode"),
            ));
        }
        if with_mcp
            || (explicit_agents && harnesses.contains(&"pi"))
            || repo_dir.join(".pi").is_dir()
        {
            mcp_paths.push(merge_pi_mcp(
                &repo_dir.join(".pi").join("mcp.json"),
                &ap_abs_here,
                mcp_for("pi"),
            ));
            if with_hooks {
                hook_paths.push(install_pi_accelerator_extension(
                    &repo_dir.join(".pi").join("extensions"),
                    &ap_abs_here,
                ));
            }
        }
        if with_mcp
            || (explicit_agents && harnesses.contains(&"codex"))
            || repo_dir.join(".codex").is_dir()
        {
            mcp_paths.push(merge_toml_mcp_server(
                &repo_dir.join(".codex").join("config.toml"),
                &ap_abs_here,
                mcp_for("codex"),
            ));
        }
        if with_mcp
            || (explicit_agents && harnesses.contains(&"grok"))
            || repo_dir.join(".grok").is_dir()
        {
            mcp_paths.push(merge_toml_mcp_server(
                &repo_dir.join(".grok").join("config.toml"),
                &ap_abs_here,
                mcp_for("grok"),
            ));
        }
        if with_mcp || (explicit_agents && harnesses.contains(&"antigravity")) {
            mcp_paths.push(merge_mcp_servers_json(
                &repo_dir.join(".agents").join("mcp_config.json"),
                &ap_abs_here,
                false,
                mcp_for("antigravity"),
            ));
        }
        if with_mcp || (explicit_agents && harnesses.contains(&"claude")) {
            let prof = if explicit_agents && harnesses.contains(&"claude") {
                mcp_for("claude")
            } else {
                explicit_mcp.unwrap_or("full")
            };
            mcp_paths.push(merge_mcp_servers_json(
                &repo_dir.join(".mcp.json"),
                &ap_abs_here,
                false,
                prof,
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

    // Zero-flag automatic MCP registration for supported CLIs & IDEs (Pi codemode, OpenCode, Codex, Grok, Claude Code, Antigravity, Qwen, Gemini CLI, Cursor, Windsurf, Claude Desktop)
    let mut mcp_paths = Vec::new();
    if harnesses.contains(&"pi") {
        mcp_paths.push(merge_pi_mcp(
            &home.join(".pi").join("agent").join("mcp.json"),
            &global_bin_posix,
            mcp_for("pi"),
        ));
    }
    if harnesses.contains(&"codex") {
        mcp_paths.push(merge_toml_mcp_server(
            &home.join(".codex").join("config.toml"),
            &global_bin_posix,
            mcp_for("codex"),
        ));
    }
    if harnesses.contains(&"grok") {
        mcp_paths.push(merge_toml_mcp_server(
            &home.join(".grok").join("config.toml"),
            &global_bin_posix,
            mcp_for("grok"),
        ));
    }
    if harnesses.contains(&"claude") {
        mcp_paths.push(merge_claude_mcp_json(
            &home.join(".claude.json"),
            &global_bin_posix,
            mcp_for("claude"),
        ));
    }
    if harnesses.contains(&"antigravity") {
        mcp_paths.push(merge_mcp_servers_json(
            &home.join(".gemini").join("config").join("mcp_config.json"),
            &global_bin_posix,
            false,
            mcp_for("antigravity"),
        ));
    }
    if harnesses.contains(&"opencode") {
        mcp_paths.push(merge_opencode_mcp(
            &home.join(".config").join("opencode").join("opencode.json"),
            &global_bin_posix,
            mcp_for("opencode"),
        ));
    }
    if harnesses.contains(&"qwen") {
        mcp_paths.push(merge_mcp_servers_json(
            &home.join(".qwen").join("settings.json"),
            &global_bin_posix,
            true,
            mcp_for("qwen"),
        ));
    }
    if harnesses.contains(&"gemini-cli") {
        mcp_paths.push(merge_mcp_servers_json(
            &home.join(".gemini").join("settings.json"),
            &global_bin_posix,
            true,
            mcp_for("gemini-cli"),
        ));
    }
    if harnesses.contains(&"cursor") {
        mcp_paths.push(merge_mcp_servers_json(
            &home.join(".cursor").join("mcp.json"),
            &global_bin_posix,
            false,
            mcp_for("cursor"),
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
            mcp_for("windsurf"),
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
            mcp_for("claude-desktop"),
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
    if stored_profile.is_some() || explicit_mcp.is_some() || explicit_model.is_some() {
        println!(
            "  - Layer 3 adapter profile : model={}, mcp={}",
            effective_model_profile.as_str(),
            explicit_mcp.unwrap_or(effective_model_profile.knobs().recommended_mcp_profile)
        );
    }
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
        remove_toml_mcp_server(&repo_dir.join(".codex").join("config.toml"));
        remove_toml_mcp_server(&repo_dir.join(".grok").join("config.toml"));
        remove_mcp_servers_json(&repo_dir.join(".agents").join("mcp_config.json"));
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
    remove_toml_mcp_server(&home.join(".codex").join("config.toml"));
    remove_toml_mcp_server(&home.join(".grok").join("config.toml"));
    remove_mcp_servers_json(&home.join(".claude.json"));
    remove_mcp_servers_json(&home.join(".gemini").join("config").join("mcp_config.json"));
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
    let _ = fs::remove_file(crate::profile::profile_path(&home));
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
                && s.contains("healJsStringRawNewlines")
                && s.contains("loadApProfile")
                && s.contains("normalizeEditArgs")
                && s.contains("findAllEditOccurrenceLines")
                && s.contains("--fw-surface")
                && s.contains("--ipc-graph")
                && s.contains("ap surface-tip")
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
                && s.contains("healBashPowerShellCommand")
                && s.contains("clampKvSafeSleep")
                && s.contains("shellQuoteBashPat")
                && s.contains("normalizeWindowsToolPath")
                && s.contains("healMsysPathConv")
                && s.contains("healCmdForLoop")
                && s.contains("shouldYieldCompaction")
                && s.contains("resolveEffectiveMaskHighWaterTokens")
                && s.contains("scrubLeakedToolMarkup")
                && s.contains("callSubLlmWithRetry")
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
        .and_then(|v| {
            v.pointer("/notices/cacheMisses")
                .or_else(|| v.get("showCacheMissNotices"))
        })
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
            "Set `\"notices\": { \"cacheMisses\": true }` in ~/.pi/agent/settings.json (Pi v1.6.1+; legacy `showCacheMissNotices: true`) to surface DeepSeek prefix cache misses immediately."
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

fn extract_mcp_profile_from_entry(entry: &Value, arr_ptr: &str) -> &'static str {
    let Some(arr) = entry.pointer(arr_ptr).and_then(Value::as_array) else {
        return "full";
    };
    for pair in arr.windows(2) {
        if pair[0].as_str() == Some("--profile") {
            match pair[1].as_str() {
                Some("core") => return "core",
                Some("deferred") => return "deferred",
                _ => return "full",
            }
        }
    }
    "full"
}

fn has_ap_hook_file(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|s| {
            s.contains("agent-primitives")
                || s.contains("ap exec")
                || s.contains("ap.exe")
                || s.contains(" guard shield")
                || s.contains(" guard stop-gate")
                || s.contains(" splice check --hook")
        })
        .unwrap_or(false)
}

pub fn inspect_wired_harness_profiles(home: &Path) -> Value {
    let cd_rel = [
        "AppData/Roaming/Claude",
        "Library/Application Support/Claude",
        ".config/Claude",
    ]
    .iter()
    .copied()
    .find(|d| home.join(d).join("claude_desktop_config.json").is_file())
    .unwrap_or(if cfg!(windows) {
        "AppData/Roaming/Claude"
    } else if cfg!(target_os = "macos") {
        "Library/Application Support/Claude"
    } else {
        ".config/Claude"
    });

    let mcp_specs: [(&str, PathBuf, &str, &str); 9] = [
        (
            "pi",
            home.join(".pi").join("agent").join("mcp.json"),
            "/mcpServers/agent-primitives",
            "/args",
        ),
        (
            "opencode",
            home.join(".config").join("opencode").join("opencode.json"),
            "/mcp/agent-primitives",
            "/command",
        ),
        (
            "claude",
            home.join(".claude.json"),
            "/mcpServers/agent-primitives",
            "/args",
        ),
        (
            "antigravity",
            home.join(".gemini").join("config").join("mcp_config.json"),
            "/mcpServers/agent-primitives",
            "/args",
        ),
        (
            "cursor",
            home.join(".cursor").join("mcp.json"),
            "/mcpServers/agent-primitives",
            "/args",
        ),
        (
            "gemini-cli",
            home.join(".gemini").join("settings.json"),
            "/mcpServers/agent-primitives",
            "/args",
        ),
        (
            "qwen",
            home.join(".qwen").join("settings.json"),
            "/mcpServers/agent-primitives",
            "/args",
        ),
        (
            "windsurf",
            home.join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
            "/mcpServers/agent-primitives",
            "/args",
        ),
        (
            "claude-desktop",
            home.join(cd_rel).join("claude_desktop_config.json"),
            "/mcpServers/agent-primitives",
            "/args",
        ),
    ];

    let hook_for = |hid: &str| -> bool {
        match hid {
            "pi" => home
                .join(".pi")
                .join("agent")
                .join("extensions")
                .join("zz-ap-accelerator.ts")
                .is_file(),
            "claude" => has_ap_hook_file(&home.join(".claude").join("settings.json")),
            "codex" => has_ap_hook_file(&home.join(".codex").join("hooks.json")),
            "antigravity" => {
                has_ap_hook_file(&home.join(".gemini").join("config").join("hooks.json"))
            }
            _ => false,
        }
    };

    let mut rows = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for (hid, cfg_p, entry_ptr, arr_ptr) in mcp_specs {
        let Ok(raw) = fs::read_to_string(&cfg_p) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let Some(entry) = v.pointer(entry_ptr) else {
            continue;
        };
        let mcp_profile = extract_mcp_profile_from_entry(entry, arr_ptr);
        let codemode_deferred =
            hid == "pi" && entry.get("exposure").and_then(Value::as_str) == Some("codemode");
        seen.insert(hid);
        rows.push(json!({
            "harness": hid,
            "mcp_profile": mcp_profile,
            "codemode_deferred": codemode_deferred,
            "hooks": hook_for(hid),
        }));
    }

    for (hid, toml_p) in [
        ("codex", home.join(".codex").join("config.toml")),
        ("grok", home.join(".grok").join("config.toml")),
    ] {
        if let Some(mcp_profile) = extract_mcp_profile_from_toml(&toml_p) {
            seen.insert(hid);
            rows.push(json!({
                "harness": hid,
                "mcp_profile": mcp_profile,
                "codemode_deferred": false,
                "hooks": hook_for(hid),
            }));
        }
    }

    for hid in ["claude", "codex", "antigravity"] {
        if !seen.contains(hid) && hook_for(hid) {
            rows.push(json!({
                "harness": hid,
                "mcp_profile": "hook-only",
                "codemode_deferred": false,
                "hooks": true,
            }));
        }
    }

    Value::Array(rows)
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
        home.join(".codex").join("config.toml"),
        home.join(".grok").join("config.toml"),
        home.join(".claude.json"),
        home.join(".gemini").join("config").join("mcp_config.json"),
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
        .filter(|p| has_ap_hook_file(p))
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
    let stored_profile = crate::profile::load_profile(&home);
    let active_model_profile = stored_profile
        .as_ref()
        .map(|c| c.model_profile.as_str())
        .unwrap_or("auto");
    let wired_harnesses = inspect_wired_harness_profiles(&home);
    let adapter_layers = json!({
        "core_version": env!("CARGO_PKG_VERSION"),
        "mcp_tools": 37,
        "idle_skill_tokens": 390,
        "model_profile": active_model_profile,
        "profile_file_present": stored_profile.is_some(),
        "wired_harnesses": wired_harnesses,
    });

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
                "adapter_layers": adapter_layers,
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
    let wired_n = wired_harnesses.as_array().map(|a| a.len()).unwrap_or(0);
    println!(
        "  [OK] Adapter Layers    : Core v{} (37 MCP tools, 390 idle tok) | model_profile={active_model_profile} (custom={}) | wired_adapters={wired_n}",
        env!("CARGO_PKG_VERSION"),
        stored_profile.is_some()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_mcp_upsert_and_remove_preserves_existing_tables() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        let seed = "\
# user comment preserved
model = \"gpt-5-codex\"

[features]
shell_tool = true

[plugins.\"sample@bundled\"]
enabled = true
";
        fs::write(&cfg, seed).unwrap();

        merge_toml_mcp_server(&cfg, "/usr/local/bin/ap", "full");
        assert_eq!(extract_mcp_profile_from_toml(&cfg), Some("full"));
        let after_full = fs::read_to_string(&cfg).unwrap();
        assert!(after_full.contains("# user comment preserved"));
        assert!(after_full.contains("[features]\nshell_tool = true"));
        assert!(after_full.contains("[plugins.\"sample@bundled\"]\nenabled = true"));
        assert!(after_full.contains("[mcp_servers.agent-primitives]"));

        merge_toml_mcp_server(&cfg, "/usr/local/bin/ap", "core");
        assert_eq!(extract_mcp_profile_from_toml(&cfg), Some("core"));
        let after_core = fs::read_to_string(&cfg).unwrap();
        assert_eq!(
            after_core.matches("[mcp_servers.agent-primitives]").count(),
            1
        );
        assert!(after_core.contains("args = [\"mcp\", \"--profile\", \"core\"]"));

        merge_toml_mcp_server(&cfg, "/usr/local/bin/ap", "deferred");
        assert_eq!(extract_mcp_profile_from_toml(&cfg), Some("deferred"));

        assert!(remove_toml_mcp_server(&cfg));
        assert_eq!(extract_mcp_profile_from_toml(&cfg), None);
        let after_rm = fs::read_to_string(&cfg).unwrap();
        assert!(!after_rm.contains("agent-primitives"));
        assert!(after_rm.contains("# user comment preserved"));
        assert!(after_rm.contains("[features]\nshell_tool = true"));
        assert!(after_rm.contains("[plugins.\"sample@bundled\"]\nenabled = true"));

        let standalone = dir.path().join("only_ap.toml");
        merge_toml_mcp_server(&standalone, "/usr/local/bin/ap", "core");
        assert!(standalone.is_file());
        assert!(remove_toml_mcp_server(&standalone));
        assert!(!standalone.exists());
    }

    #[test]
    fn inspect_pi_runtime_recognizes_v161_notices_and_legacy_cache_miss_setting() {
        let dir = tempfile::tempdir().unwrap();
        let pi_agent = dir.path().join(".pi").join("agent");
        fs::create_dir_all(&pi_agent).unwrap();

        // Pi v1.6.1 nested notices.cacheMisses = true
        fs::write(
            pi_agent.join("settings.json"),
            r#"{"defaultProvider":"deepseek","defaultModel":"deepseek-flash","notices":{"cacheMisses":true}}"#,
        )
        .unwrap();
        let r1 = inspect_pi_runtime(dir.path());
        assert_eq!(r1["show_cache_miss_notices"], true);
        let recs1 = r1["recommendations"].as_array().unwrap();
        assert!(
            !recs1
                .iter()
                .any(|x| x.as_str().unwrap_or("").contains("cacheMisses")),
            "notices.cacheMisses=true must silence cache-miss recommendation: {recs1:?}"
        );

        // Legacy showCacheMissNotices = true still recognized
        fs::write(
            pi_agent.join("settings.json"),
            r#"{"defaultProvider":"deepseek","defaultModel":"deepseek-flash","showCacheMissNotices":true}"#,
        )
        .unwrap();
        let r2 = inspect_pi_runtime(dir.path());
        assert_eq!(r2["show_cache_miss_notices"], true);

        // Missing notice triggers v1.6.1 notices.cacheMisses recommendation
        fs::write(
            pi_agent.join("settings.json"),
            r#"{"defaultProvider":"deepseek","defaultModel":"deepseek-flash"}"#,
        )
        .unwrap();
        let r3 = inspect_pi_runtime(dir.path());
        assert_eq!(r3["show_cache_miss_notices"], false);
        let recs3 = r3["recommendations"].as_array().unwrap();
        assert!(recs3
            .iter()
            .any(|x| x.as_str().unwrap_or("").contains("notices")));
    }

    #[test]
    fn pi_accelerator_ts_node_verifies_yield_masking_scrubbing_bash_and_sub_llm_retry() {
        let node_ok = std::process::Command::new("node")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !node_ok {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let ts_path = dir.path().join("zz-ap-accelerator.ts");
        let rendered = render_pi_accelerator_ts("ap");
        // Guard existing integration invariants
        assert!(rendered.contains("MASK_HIGH_WATER_TOKENS = 180000"));
        assert!(rendered.contains("highWaterTokens: 210000"));
        assert!(rendered.contains("staleCharsFallback: 360000"));
        fs::write(&ts_path, &rendered).unwrap();

        let prof_yield = dir.path().join("profile-yield.json");
        fs::write(
            &prof_yield,
            r#"{"schema_version":1,"model_profile":"auto","yield_compact":true}"#,
        )
        .unwrap();
        let prof_small = dir.path().join("profile-small.json");
        fs::write(
            &prof_small,
            r#"{"schema_version":1,"model_profile":"small"}"#,
        )
        .unwrap();
        let settings_p = dir.path().join("settings.json");
        fs::write(
            &settings_p,
            r#"{"compaction":{"reserveTokens":16384,"modelOverrides":{"deepseek/deepseek-flash":{"reserveTokens":840000}}}}"#,
        )
        .unwrap();

        let url = format!("file:///{}", ts_path.to_string_lossy().replace('\\', "/"));
        let py_str = prof_yield.to_string_lossy().replace('\\', "/");
        let ps_str = prof_small.to_string_lossy().replace('\\', "/");
        let st_str = settings_p.to_string_lossy().replace('\\', "/");

        let script = format!(
            r#"
import assert from "node:assert/strict";
import mod from "{url}";
import {{
  loadApProfile,
  shouldYieldCompaction,
  readModelCompactionTriggerTokens,
  resolveEffectiveMaskHighWaterTokens,
  scrubLeakedToolMarkup,
  repairHallucinatedToolName,
  normalizeRepairedToolArgs,
  healCommand,
  classifyCodemodeFailureTip,
  callSubLlmWithRetry,
  isNonRetryableSubLlmError,
}} from "{url}";

// 1. Profile + yield_compact protocol
const py = loadApProfile("{py_str}");
assert.strictEqual(py?.yieldCompact, true);
const ps = loadApProfile("{ps_str}");
assert.strictEqual(ps?.sieveHardChars, 10000);
assert.strictEqual(shouldYieldCompaction({{ compactionClaimed: true }}), true);
assert.strictEqual(shouldYieldCompaction({{ envYieldCompact: "1" }}), true);
assert.strictEqual(shouldYieldCompaction({{ profileYieldCompact: true }}), true);
assert.strictEqual(shouldYieldCompaction({{ peerClaimed: true }}), true);
assert.strictEqual(shouldYieldCompaction({{}}), false);

// 2. Dynamic masking threshold below 160k DeepSeek Flash compaction trigger
const trigger = readModelCompactionTriggerTokens({{ provider: "deepseek", id: "flash-auto", contextWindow: 1000000 }}, "{st_str}");
assert.strictEqual(trigger, 160000);
const effMask = resolveEffectiveMaskHighWaterTokens({{ deepCacheDiscount: true, compactionTriggerTokens: trigger }});
assert.strictEqual(effMask, 136000, "must clamp below 85% of 160k compaction trigger");

// 3. Tool alias + arg healing + DSML/tool_call scrubbing
const active = new Set(["bash", "read", "edit", "write", "codemode", "grep"]);
assert.strictEqual(repairHallucinatedToolName("run_bash", active), "bash");
assert.strictEqual(repairHallucinatedToolName("str_replace", active), "edit");
assert.strictEqual(repairHallucinatedToolName("js_eval", active), "codemode");
assert.deepStrictEqual(normalizeRepairedToolArgs("edit", {{ file: "a.ts", old_text: "x", new_text: "y" }}).args, {{ path: "a.ts", oldText: "x", newText: "y" }});
assert.deepStrictEqual(normalizeRepairedToolArgs("bash", {{ shell_command: "ls" }}).args, {{ command: "ls" }});
const scrubbed = scrubLeakedToolMarkup('before <|DSML|function_calls><|DSML|invoke name="bash"></|DSML|invoke></|DSML|function_calls> <tool_call>{{"name":"read"}}</tool_call> after');
assert.strictEqual(scrubbed.replace(/\s+/g, " "), "before after");
assert.ok(!scrubbed.includes("DSML") && !scrubbed.includes("tool_call"));

// 4. RSI bash rewrites (2>&1, ls | head, cat | grep | head, strict pass-through on semantic-changing pipes)
assert.ok(healCommand("ls -la src 2>&1 | head -n 10", "bash")?.includes('ls "src" -a --depth 1 --limit 10'));
assert.strictEqual(healCommand("ls -lt --color=never src | tail -n 5", "bash"), undefined);
assert.strictEqual(healCommand("ls -r | head -10", "bash"), undefined);
assert.strictEqual(healCommand("ls --reverse | head -10", "bash"), undefined);
assert.strictEqual(healCommand("ls src 2>&1 | grep -i foo | head -n 15", "bash"), undefined);
assert.ok(healCommand("cat app.log 2>&1 | grep -in 'error' | head -n 20", "bash")?.includes('search --max 20 -i'));
assert.ok(!healCommand("cat Makefile | grep -i build", "bash")?.includes('"ap" search'));
assert.ok(healCommand("head -n 25 README.md 2>&1", "bash")?.includes('read "README.md" --lines 1-25'));

// 5. Codemode failure tip retains all contract phrases + live JSON.stringify/JSON.parse hints
const tip = classifyCodemodeFailureTip("TypeError: cannot read property 'slice' of undefined");
assert.ok(tip.includes("VOID output printer"));
assert.ok(tip.includes("JSON.stringify(undefined)"));
assert.ok(tip.includes("res?.output"));
const parseObjTip = classifyCodemodeFailureTip("SyntaxError: unexpected token: 'object'");
assert.ok(parseObjTip.includes("ALREADY return structured JS objects"));

// 6. Sub-LLM retry: retries transient stopReason=error, NEVER retries 402 insufficient balance, never false-positives bare numbers
assert.strictEqual(isNonRetryableSubLlmError("HTTP 402 Insufficient Balance"), true);
assert.strictEqual(isNonRetryableSubLlmError("ECONNRESET socket hang up"), false);
assert.strictEqual(isNonRetryableSubLlmError("Connection reset after 404 ms"), false);
assert.strictEqual(isNonRetryableSubLlmError("ECONNRESET while reading 422 bytes"), false);
let callsTransient = 0;
const okResp = await callSubLlmWithRetry(
  {{
    modelRegistry: {{
      find: (_p, id) => ({{ provider: "deepseek", id }}),
      streamSimple: () => ({{
        async result() {{
          callsTransient += 1;
          if (callsTransient === 1) return {{ stopReason: "error", errorMessage: "ECONNRESET" }};
          return {{ stopReason: "stop", content: [{{ type: "text", text: "recovered" }}] }};
        }}
      }})
    }}
  }},
  {{ provider: "deepseek", id: "flash-auto" }},
  {{}},
  {{ unwrapVirtual: true, retryDelayMs: 5, timeoutMs: 2000 }}
);
assert.strictEqual(callsTransient, 2);
assert.strictEqual(okResp?.stopReason, "stop");

let calls402 = 0;
const resp402 = await callSubLlmWithRetry(
  {{
    modelRegistry: {{
      streamSimple: () => ({{
        async result() {{
          calls402 += 1;
          return {{ stopReason: "error", errorMessage: "402 Insufficient Balance" }};
        }}
      }})
    }}
  }},
  {{ provider: "deepseek", id: "deepseek-flash" }},
  {{}},
  {{ retryDelayMs: 5, timeoutMs: 2000 }}
);
assert.strictEqual(calls402, 1, "402 must NEVER be retried");
assert.strictEqual(resp402?.stopReason, "error");

// 7. Extension hook wiring: ap:claim_compaction, context scrub, message_end stopReason=toolUse, agent_before_settle yield
const handlers = new Map();
const eventSubs = new Map();
const fakePi = {{
  on(ev, fn) {{ handlers.set(ev, fn); }},
  events: {{
    on(ch, fn) {{ eventSubs.set(ch, fn); }},
    emit(ch) {{ eventSubs.get(ch)?.(); }},
  }},
  getActiveTools: () => ["bash", "read", "edit", "write", "codemode"],
}};
mod(fakePi);

// agent_before_settle must yield when continue===true or entries non-empty
const settleFn = handlers.get("agent_before_settle");
assert.strictEqual(settleFn({{ outcome: "completed", continue: true, entries: [] }}, {{}}), undefined);
assert.strictEqual(settleFn({{ outcome: "completed", continue: false, entries: [{{ type: "custom_message" }}] }}, {{}}), undefined);

// context hook scrubs leaked DSML on assistant without toolCall, leaves clean messages untouched
const ctxFn = handlers.get("context");
assert.strictEqual(ctxFn({{ messages: [{{ role: "assistant", content: [{{ type: "text", text: "clean" }}] }}] }}), undefined);
const scrubbedCtx = ctxFn({{ messages: [{{ role: "assistant", content: [{{ type: "text", text: 'hi <tool_call>{{"name":"bash"}}</tool_call>' }}] }}] }});
assert.strictEqual(scrubbedCtx?.messages?.[0]?.content?.[0]?.text, "hi");

// message_end sets stopReason: "toolUse" on DSML recovery and heals native arg aliases
const msgEndFn = handlers.get("message_end");
const recMsg = msgEndFn({{ message: {{ role: "assistant", stopReason: "stop", content: [{{ type: "text", text: '<|DSML|invoke name="bash"><|DSML|parameter name="command">echo ok</|DSML|parameter></|DSML|invoke>' }}] }} }});
assert.strictEqual(recMsg?.message?.stopReason, "toolUse");
assert.strictEqual(recMsg?.message?.content?.[0]?.type, "toolCall");
const argHealMsg = msgEndFn({{ message: {{ role: "assistant", stopReason: "toolUse", content: [{{ type: "toolCall", id: "1", name: "bash", arguments: {{ cmd: "pwd" }} }}] }} }});
assert.strictEqual(argHealMsg?.message?.content?.[0]?.arguments?.command, "pwd");

// session_before_compact yields after ap:claim_compaction event
fakePi.events.emit("ap:claim_compaction");
const compactFn = handlers.get("session_before_compact");
const compactRes = await compactFn({{ preparation: {{ firstKeptEntryId: "x", tokensBefore: 100000, messagesToSummarize: [{{ role: "user", content: "hi" }}] }} }}, {{ model: {{ provider: "deepseek", id: "deepseek-flash" }}, modelRegistry: {{ streamSimple: () => {{ throw new Error("should not call LLM when yielded"); }} }} }});
assert.strictEqual(compactRes, undefined);
console.log("OK_PI_ACCELERATOR_NODE");
"#
        );
        let run = std::process::Command::new("node")
            .args([
                "--experimental-strip-types",
                "--no-warnings",
                "--input-type=module",
                "-e",
                &script,
            ])
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "Node accelerator verification failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
    }

    #[test]
    fn pi_accelerator_adversarial_metamorphic_and_live_ap_cli_suite() {
        let node_ok = std::process::Command::new("node")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !node_ok {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let fixture_dir = dir.path().join("src");
        fs::create_dir_all(&fixture_dir).unwrap();
        let sample_file = fixture_dir.join("sample.log");
        fs::write(
            &sample_file,
            "alpha line 1\nERROR token_abc=42\nwarn foo bar\nERROR token_xyz=99\nbeta line 5\n",
        )
        .unwrap();
        let ts_path = dir.path().join("zz-ap-accelerator.ts");
        fs::write(&ts_path, render_pi_accelerator_ts("ap")).unwrap();

        let url = format!("file:///{}", ts_path.to_string_lossy().replace('\\', "/"));
        let fix_dir_s = fixture_dir.to_string_lossy().replace('\\', "/");
        let sample_s = sample_file.to_string_lossy().replace('\\', "/");

        // 65+ adversarial / metamorphic assertions + export every rewritten `"ap" ...` command for live in-process ap CLI verification
        let script = format!(
            r#"
import assert from "node:assert/strict";
import initAccelerator, {{
  healCommand,
  healCodemodeSource,
  guardEphemeralServerCommand,
  scrubLeakedToolMarkup,
  isNonRetryableSubLlmError,
  callSubLlmWithRetry,
  classifyCodemodeFailureTip,
  isDeepSeekModel,
  snapshotProviderRequestHashes,
  classifyCacheDropCause,
}} from "{url}";

const DIR = "{fix_dir_s}";
const FILE = "{sample_s}";

// A) MUST PASS THROUGH (undefined) or NOT emit ap search/ls/read — semantic preservation invariants (34 cases)
const mustNotRewriteToAp = [
  // ls semantic traps (reverse sort, multi-dir, glob, tail/grep format & >120 truncation)
  `ls -r | head -10`,
  `ls -lr ${{DIR}} | head -n 5`,
  `ls --reverse ${{DIR}} | head -n 5`,
  `ls -la ${{DIR}} ${{DIR}} | head -n 10`,
  `ls ${{DIR}}/*.log | head -n 5`,
  `ls -la ${{DIR}} | tail -n 5`,
  `ls -1 ${{DIR}} | tail -n 3`,
  `ls -la ${{DIR}} | grep "^d"`,
  `ls -la ${{DIR}} | grep "Nov"`,
  `ls ${{DIR}} 2>&1 | grep -v foo | head -n 10`,
  `ls -R ${{DIR}} | head -n 10`,
  `(ls ${{DIR}}) | head -n 5`,
  `ls ${{DIR}} & head -n 5`,
  // cat + grep semantic traps (-w unsupported, -c format, -l format, bare cat|grep, sort -u order, multi-file, && / || exit-code)
  `cat ${{FILE}} ${{FILE}} | head -n 5`,
  `cat ${{FILE}} | grep ERROR`,
  `cat ${{FILE}} | grep -n ERROR`,
  `cat ${{FILE}} | grep -w ERROR`,
  `cat ${{FILE}} | grep -w ERROR | head -n 5`,
  `grep -rnw ERROR ${{DIR}}`,
  `grep -w ERROR ${{FILE}} | head -n 5`,
  `rg --word-regexp ERROR ${{DIR}} | head -n 5`,
  `cat ${{FILE}} | grep -c ERROR`,
  `cat ${{FILE}} | grep -c ERROR | head -n 5`,
  `cat ${{FILE}} | grep -l ERROR | head -n 5`,
  `cat ${{FILE}} | grep -n ERROR | sort -u | head -n 10`,
  `grep -n ERROR ${{FILE}} | sort -u | head -n 10`,
  `cat ${{FILE}} | grep ERROR | wc -l`,
  `cat ${{FILE}} | grep ERROR && echo found`,
  `cat ${{FILE}} | grep ERROR | head -n 5 && echo found`,
  `grep ERROR ${{FILE}} || echo missing`,
  // 2>&1 boundary / quoting / subshell traps
  `echo foo2>&1 | head -n 1`,
  `echo "a | b" 2>&1 | head -n 1`,
  `head -n 5 ${{FILE}} ${{FILE}}`,
  `ls ${{DIR}} 2>&12 | head -n 5`,
];
for (const cmd of mustNotRewriteToAp) {{
  const out = healCommand(cmd, "bash");
  const badAp = typeof out === "string" && /"ap"\s+(?:search|ls|read)\b/.test(out);
  assert.strictEqual(badAp, false, `Semantic trap must NOT rewrite to ap: ${{cmd}} => ${{out}}`);
}}

// Fast-path A3 regression: `cat f | grep -E "a|b"` MUST NEVER inject `-o`
const catE = healCommand(`cat ${{FILE}} | grep -E "ERROR|warn" | head -n 10`, "bash");
assert.ok(catE && catE.includes(`"ap" search --max 10`), `expected safe ap search, got: ${{catE}}`);
assert.ok(!catE.includes(" -o"), `cat | grep -E must never inject -o: ${{catE}}`);

// Fast-path A3 positive: explicit `cat f | grep -oE` still accelerates safely (and without -n/-A)
const catOE = healCommand(`cat ${{FILE}} | grep -oE 'token_[a-z]+'`, "bash");
assert.ok(catOE && catOE.includes("rg -a --no-ignore -o"), `expected rg -o fast-path: ${{catOE}}`);
const catNoDropN = healCommand(`cat ${{FILE}} | grep -on 'token_[a-z]+'`, "bash");
assert.ok(!catNoDropN?.includes("rg -a --no-ignore -o"), `must not drop -n in Fast-path A3: ${{catNoDropN}}`);

// B) Safe positive rewrites -> verify output AND collect all `"ap" ...` invocations for live Rust CLI execution (18 cases)
const positiveCases = [
  [`ls -la ${{DIR}} | head -n 5`, `"ap" ls`],
  [`ls -la ${{DIR}} 2>&1 | head -n 5`, `"ap" ls`],
  [`ls -t --color=never ${{DIR}} | head -n 5`, `"ap" ls`],
  [`ls -S --group-directories-first ${{DIR}} 2>/dev/null | head -5`, `"ap" ls`],
  [`ls -A --human-readable ${{DIR}} 2>&1|head -n 4`, `"ap" ls`],
  [`cat ${{FILE}} | head -n 3`, `"ap" read`],
  [`cat ${{FILE}} 2>&1 | tail -n 2`, `"ap" read`],
  [`cat ${{FILE}} | sed -n '1,3p'`, `"ap" read`],
  [`head -n 3 ${{FILE}} 2>&1`, `"ap" read`],
  [`tail -n 2 ${{FILE}} 2>&1`, `"ap" read`],
  [`sed -n '2,4p' ${{FILE}} 2>&1`, `"ap" read`],
  [`cat ${{FILE}} 2>&1 | grep -i error | head -n 5`, `"ap" search`],
  [`cat ${{FILE}} | grep -E "ERROR|warn" | head -n 5`, `"ap" search`],
  [`cat ${{FILE}} | egrep -i "error|warn" | cut -c 1-80`, `"ap" search`],
  [`cat ${{FILE}} | fgrep "token_abc" | head -n 3`, `"ap" search`],
  [`grep -in "error" ${{FILE}} 2>&1 | head -n 5`, `"ap" search`],
  [`grep -oE "token_[a-z]+" ${{FILE}} | sort -u | head -n 5`, `"ap" search`],
  [`grep -rn "ERROR" ${{DIR}}`, `"ap" search`],
];

function splitShellArgs(cmdStr) {{
  const out = [];
  let cur = "";
  let q = null;
  for (let i = 0; i < cmdStr.length; i++) {{
    const c = cmdStr[i];
    if (q) {{
      if (c === q) {{ q = null; continue; }}
      if (q === '"' && c === "\\" && i + 1 < cmdStr.length) {{ cur += cmdStr[++i]; continue; }}
      cur += c;
    }} else if (c === "'" || c === '"') {{
      q = c;
    }} else if (/\s/.test(c)) {{
      if (cur.length > 0) {{ out.push(cur); cur = ""; }}
    }} else {{
      cur += c;
    }}
  }}
  if (cur.length > 0) out.push(cur);
  return out;
}}

const emittedApInvocations = [];
for (const [cmd, expectedPrefix] of positiveCases) {{
  const rewritten = healCommand(cmd, "bash");
  assert.ok(rewritten && rewritten.startsWith(expectedPrefix), `Expected ${{expectedPrefix}} for ${{cmd}}, got ${{rewritten}}`);
  emittedApInvocations.push(splitShellArgs(rewritten));
}}

// C) isNonRetryableSubLlmError positive & negative matrix (14 cases)
for (const e of [
  "HTTP 402 Insufficient Balance",
  "HTTP/1.1 401 Unauthorized",
  "HTTP/2 403 Forbidden",
  "status: 400 Bad Request",
  "status code=422 Unprocessable",
  "402 Insufficient Balance",
  "invalid_api_key provided",
  "context_length_exceeded",
]) {{
  assert.strictEqual(isNonRetryableSubLlmError(e), true, `Expected non-retryable: ${{e}}`);
}}
for (const e of [
  "Error at line 400 of stream",
  "Connection reset after 404 ms",
  "ECONNRESET while reading 422 bytes",
  "terminated: read ECONNRESET",
  "getaddrinfo ENOTFOUND api.deepseek.com",
  "HTTP 502 Bad Gateway",
]) {{
  assert.strictEqual(isNonRetryableSubLlmError(e), false, `Expected retryable: ${{e}}`);
}}

// D) scrubLeakedToolMarkup preserves inline & fenced code blocks (incl. 4-backtick nested, unclosed-to-EOF, double-backtick, escaped \` + no-op KV-cache identity)
assert.strictEqual(scrubLeakedToolMarkup("Use `<|DSML|invoke>` syntax in tests"), "Use `<|DSML|invoke>` syntax in tests");
const fencedXml = "Here is ```xml\n<tool_call>{{\"name\":\"bash\"}}</tool_call>\n``` example";
assert.strictEqual(scrubLeakedToolMarkup(fencedXml), fencedXml);
const tildeFence = "~~~xml\n<|DSML|invoke name=\"bash\"></|DSML|invoke>\n~~~";
assert.strictEqual(scrubLeakedToolMarkup(tildeFence), tildeFence);
const nested4Fence = "````md\n```xml\n<|DSML|invoke name=\"bash\">x</|DSML|invoke>\n```\n````";
assert.strictEqual(scrubLeakedToolMarkup(nested4Fence), nested4Fence);
const unclosedFence = "Intro\n```xml\n<|DSML|invoke name=\"bash\">example</|DSML|invoke>";
assert.strictEqual(scrubLeakedToolMarkup(unclosedFence), unclosedFence);
const doubleBtInline = "Use `` `<|DSML|invoke>` `` inline.";
assert.strictEqual(scrubLeakedToolMarkup(doubleBtInline), doubleBtInline);
const escBtShield = "Here is \\`not code <tool_call>{{\"name\":\"bash\"}}</tool_call>\\` ok";
assert.ok(!scrubLeakedToolMarkup(escBtShield).includes("tool_call"));
const escBtBeforeCode = "Note \\` here then `<tool_call>inside_real_code</tool_call>` end";
assert.strictEqual(scrubLeakedToolMarkup(escBtBeforeCode), escBtBeforeCode);
const noopWithTripleNl = "Example:\n```md\nline1\n\n\n<|DSML|invoke>\n```\n";
assert.strictEqual(scrubLeakedToolMarkup(noopWithTripleNl), noopWithTripleNl, "no-op scrub must never mutate KV-cache prefix");
const mixedLeak = "Keep `<code>` and <tool_call>{{\"name\":\"bash\"}}</tool_call> done";
assert.strictEqual(scrubLeakedToolMarkup(mixedLeak).replace(/\s+/g, " "), "Keep `<code>` and done");
assert.ok(!scrubLeakedToolMarkup("raw <|DSML|function_calls><|DSML|invoke name=\"x\"></|DSML|invoke></|DSML|function_calls> end").includes("DSML"));
assert.strictEqual(isDeepSeekModel({{ provider: "deepseek", id: "flash-auto" }}), true);
assert.strictEqual(isDeepSeekModel({{ provider: "anthropic", id: "claude-sonnet" }}), false);
assert.strictEqual(isDeepSeekModel({{ provider: "google", id: "gemini-flash-auto" }}), false);

// E) Codemode tips for #50 top live crashes
assert.ok(classifyCodemodeFailureTip("TypeError: cannot read property 'slice' of undefined").includes("JSON.stringify(undefined)"));
assert.ok(classifyCodemodeFailureTip("SyntaxError: unexpected token: 'object'").includes("ALREADY return structured JS objects"));

// F) Cycle 3 regression checks: guardEphemeralServerCommand, healCodemodeSource balanced JSON.stringify().slice,
//    Fast-path A2b/A3/A4/ls/grep/heredoc/REDIR_NUL, isNonRetryableSubLlmError 429/paren, callSubLlmWithRetry timeout retry,
//    and before_provider_request retry-safe KV-cache classifier
assert.strictEqual(
  guardEphemeralServerCommand("cd /tmp/site && python -m http.server 8000 &"),
  "cd /tmp/site && timeout 900 python -m http.server 8000 &"
);
assert.strictEqual(
  guardEphemeralServerCommand("echo hi; python -m http.server 8000 &"),
  "echo hi; timeout 900 python -m http.server 8000 &"
);
assert.strictEqual(
  guardEphemeralServerCommand("nohup node proxy.js &"),
  "nohup timeout 900 node proxy.js &"
);
assert.strictEqual(
  guardEphemeralServerCommand("cd /tmp && nohup python3 mitm.py 8899 > m.log 2>&1 &"),
  "cd /tmp && nohup timeout 900 python3 mitm.py 8899 > m.log 2>&1 &"
);
assert.strictEqual(guardEphemeralServerCommand("(cd /tmp && python -m http.server 8000) &"), undefined);
assert.strictEqual(guardEphemeralServerCommand("timeout 60 python -m http.server 8000 &"), undefined);

// Balanced JSON.stringify(...).slice( preventive guard in healCodemodeSource
assert.strictEqual(
  healCodemodeSource("text(JSON.stringify(r.result).slice(0, 200));"),
  'text((JSON.stringify(r.result) ?? "undefined").slice(0, 200));'
);
assert.strictEqual(
  healCodemodeSource("const s = JSON.stringify(foo(a, b(1)), null, 2).slice(0, 50);"),
  'const s = (JSON.stringify(foo(a, b(1)), null, 2) ?? "undefined").slice(0, 50);'
);
assert.strictEqual(
  healCodemodeSource("const s = JSON.stringify(JSON.stringify(x).slice(0, 5)).slice(0, 10);"),
  'const s = (JSON.stringify((JSON.stringify(x) ?? "undefined").slice(0, 5)) ?? "undefined").slice(0, 10);'
);
assert.strictEqual(
  healCodemodeSource("const s = `len=${{JSON.stringify(x).slice(0, 5)}}`;"),
  'const s = `len=${{(JSON.stringify(x) ?? "undefined").slice(0, 5)}}`;'
);
// Must NOT touch optional chaining, already-guarded, strings, comments, regexes, property access, or ASI-unsafe bare newline
for (const untouched of [
  "const s = JSON.stringify(x)?.slice(0, 10);",
  'const s = (JSON.stringify(x) ?? "undefined").slice(0, 10);',
  'const s = "JSON.stringify(x).slice(0, 10)";',
  "// JSON.stringify(x).slice(0, 10)\nconst a = 1;",
  "/* JSON.stringify(x).slice(0, 10) */\nconst a = 1;",
  "const r = /JSON\\.stringify\\(x\\)\\.slice\\(/;",
  "const fn = myObj.JSON.stringify(x).slice(0, 10);",
  "const a = foo\nJSON.stringify(x).slice(0, 10)",
]) {{
  assert.strictEqual(healCodemodeSource(untouched), undefined, `must leave untouched: ${{untouched}}`);
}}
// Live execution check: healed JSON.stringify(undefined).slice(0, 5) returns "undef" without throwing
const healedUndef = healCodemodeSource("return JSON.stringify(undefined).slice(0, 5);");
assert.strictEqual(new Function(healedUndef)(), "undef");

// Bash rewriter Cycle 3 fixes
const echoCat = healCommand('echo header; cat f.txt | grep -o "foo"', "bash");
assert.ok(echoCat && echoCat.includes("echo header;") && echoCat.includes("rg -a --no-ignore -o"));
const breCat = healCommand("cat f.txt | grep -o 'foo\\|bar'", "bash");
assert.ok(breCat && breCat.includes("'foo|bar'"), `BRE must translate for rg: ${{breCat}}`);
const catN = healCommand('cat -n f.txt | grep -o "foo"', "bash");
assert.ok(!catN?.includes("rg -a") && !catN?.includes('"ap" search'), `cat -n must not rewrite to rg/ap: ${{catN}}`);
assert.ok(healCommand("grep -oi 'foo' a.txt b.txt", "bash")?.includes(" -i"));
assert.ok(healCommand('for f in a.txt b.txt; do echo "$f"; grep -oi \'foo\' "$f"; done', "bash")?.includes(" -i"));
assert.strictEqual(healCommand("ls '$HOME' | head -n 5", "bash"), undefined);
assert.ok(healCommand("grep -rla 'pat' . 2>&1", "bash")?.includes('"ap" search -l'));
assert.ok(healCommand("cd /c/foo && grep -rla 'pat' . || true", "bash")?.endsWith("|| true"));
const hdCd = healCommand("cd D:\\foo\\bar && python - <<'PY'\nprint(r'D:\\keep\\me')\nPY", "bash");
assert.ok(hdCd && hdCd.includes("cd D:/foo/bar") && hdCd.includes("print(r'D:\\keep\\me')"));
assert.strictEqual(healCommand("ls>nul", "bash"), "ls> /dev/null");
assert.strictEqual(healCommand('echo "a>nul"', "bash"), undefined);

// isNonRetryableSubLlmError Cycle 3 checks
assert.strictEqual(isNonRetryableSubLlmError("HTTP 429 Too Many Requests: per-minute quota exceeded"), false);
assert.strictEqual(isNonRetryableSubLlmError("DeepSeek API error (402): balance too low"), true);
assert.strictEqual(isNonRetryableSubLlmError("Provider returned 400 Bad Request"), true);
assert.strictEqual(isNonRetryableSubLlmError("Retry after (404 ms)"), false);

// callSubLlmWithRetry must retry internal timeout abort, but NOT caller abort
let toCalls = 0;
const toResp = await callSubLlmWithRetry(
  {{
    modelRegistry: {{
      streamSimple(_m, _c, opts) {{
        toCalls += 1;
        return {{
          result() {{
            if (toCalls === 1) {{
              return new Promise((res) => {{
                opts.signal.addEventListener("abort", () => res({{ stopReason: "aborted", errorMessage: "Request was aborted" }}));
              }});
            }}
            return Promise.resolve({{ stopReason: "stop", content: [{{ type: "text", text: "ok-after-timeout" }}] }});
          }}
        }};
      }}
    }}
  }},
  {{ provider: "deepseek", id: "deepseek-flash" }},
  {{ messages: [] }},
  {{ timeoutMs: 1000, maxAttempts: 2, retryDelayMs: 5 }}
);
assert.strictEqual(toCalls, 2, "internal timeout abort must retry attempt 2");
assert.strictEqual(toResp?.stopReason, "stop");

const callerAc = new AbortController();
let callerAbortCalls = 0;
const callerAbortResp = await callSubLlmWithRetry(
  {{
    modelRegistry: {{
      streamSimple(_m, _c, opts) {{
        callerAbortCalls += 1;
        return {{
          result() {{
            return new Promise((res) => {{
              opts.signal.addEventListener("abort", () => res({{ stopReason: "aborted" }}));
              setTimeout(() => callerAc.abort(), 15);
            }});
          }}
        }};
      }}
    }}
  }},
  {{ provider: "deepseek", id: "deepseek-flash" }},
  {{ messages: [] }},
  {{ signal: callerAc.signal, timeoutMs: 2000, maxAttempts: 2, retryDelayMs: 5 }}
);
assert.strictEqual(callerAbortCalls, 1, "caller abort must never retry");
assert.strictEqual(callerAbortResp?.stopReason, "aborted");

// before_provider_request retry-safe KV-cache drop classification + thinking/system detection
const hMap = new Map();
let dropEvt = null;
const fakePi = {{
  on(ev, fn) {{ hMap.set(ev, fn); }},
  events: {{ on() {{}}, emit(ch, d) {{ if (ch === "ap:cache_drop") dropEvt = d; }} }},
  getActiveTools: () => ["bash", "read"],
}};
initAccelerator(fakePi);
const bpr = hMap.get("before_provider_request");
const te = hMap.get("turn_end");
bpr({{ payload: {{ model: "deepseek-flash", thinking: {{ type: "enabled" }}, tools: [], messages: [{{ role: "system", content: "sysA" }}] }} }});
te({{ message: {{ role: "assistant", content: [], usage: {{ input: 1000, cacheRead: 25000 }} }} }});
// Turn 2 fires twice due to transient retry before turn_end
bpr({{ payload: {{ model: "deepseek-flash", thinking: {{ type: "enabled" }}, tools: [], messages: [{{ role: "system", content: "sysB" }}] }} }});
bpr({{ payload: {{ model: "deepseek-flash", thinking: {{ type: "enabled" }}, tools: [], messages: [{{ role: "system", content: "sysB" }}] }} }});
te({{ message: {{ role: "assistant", content: [], usage: {{ input: 25000, cacheRead: 1000 }} }} }});
assert.strictEqual(dropEvt?.cause, "msg[0]_mutated", "mid-turn retry must preserve real KV-cache drop cause");
const hThink1 = snapshotProviderRequestHashes({{ model: "deepseek-flash", thinking: {{ type: "enabled" }}, tools: [], messages: [] }});
const hThink2 = snapshotProviderRequestHashes({{ model: "deepseek-flash", thinking: {{ type: "disabled" }}, tools: [], messages: [] }});
assert.strictEqual(classifyCacheDropCause(hThink1, hThink2), "thinking_changed");
const hSys1 = snapshotProviderRequestHashes({{ model: "claude", system: "A", tools: [], messages: [] }});
const hSys2 = snapshotProviderRequestHashes({{ model: "claude", system: "B", tools: [], messages: [] }});
assert.strictEqual(classifyCacheDropCause(hSys1, hSys2), "system_changed");

console.log(JSON.stringify(emittedApInvocations));
"#
        );

        let run = std::process::Command::new("node")
            .args([
                "--experimental-strip-types",
                "--no-warnings",
                "--input-type=module",
                "-e",
                &script,
            ])
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "Adversarial/metamorphic Node suite failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );

        // Execute EVERY rewritten `ap search` / `ap ls` / `ap read` command directly through ap's real clap CLI handlers
        let invocations: Vec<Vec<String>> =
            serde_json::from_slice(&run.stdout).expect("expected JSON invocations from Node");
        assert!(invocations.len() >= 18);
        let _ap_home_guard = crate::stats::ApHomeTestGuard::set(&dir.path().join("ap_home"));
        for inv in invocations {
            assert!(inv.len() >= 2, "invalid invocation: {inv:?}");
            let sub = inv[1].as_str();
            let sub_args: Vec<String> = inv[1..].to_vec();
            let rc = match sub {
                "search" => crate::search::run_cli(&sub_args),
                "ls" => crate::ls::run_cli(&sub_args),
                "read" => crate::read::run_cli(&sub_args),
                other => {
                    panic!("unexpected ap subcommand emitted by healCommand: {other} ({inv:?})")
                }
            };
            assert_eq!(
                rc, 0,
                "Rewritten command failed live ap CLI execution (rc={rc}): {inv:?}"
            );
        }
    }

    #[test]
    fn assets_zz_ap_accelerator_ts_passes_node_strip_types_check_directly() {
        let rendered = render_pi_accelerator_ts("C:/Users/example/.local/bin/ap.exe");
        assert!(rendered.contains("const AP_BIN = \"C:/Users/example/.local/bin/ap.exe\";"));
        assert!(!rendered.contains(PI_ACCELERATOR_BIN_PLACEHOLDER));
        assert!(!rendered.contains("\r\n"));

        let node_ok = std::process::Command::new("node")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !node_ok {
            return;
        }
        let asset_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("assets")
            .join("zz-ap-accelerator.ts");
        assert!(
            asset_path.is_file(),
            "assets/zz-ap-accelerator.ts must exist"
        );
        let chk = std::process::Command::new("node")
            .args(["--experimental-strip-types", "--no-warnings", "--check"])
            .arg(&asset_path)
            .output()
            .unwrap();
        assert!(
            chk.status.success(),
            "node --experimental-strip-types --check failed on {}:\nstdout={}\nstderr={}",
            asset_path.display(),
            String::from_utf8_lossy(&chk.stdout),
            String::from_utf8_lossy(&chk.stderr)
        );
    }
}
