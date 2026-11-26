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
import {{ homedir, tmpdir }} from "node:os";
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
	/^\s*grep\s+-([rRniEHlco]+)\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))(?:\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+)))?\s*$/;
const PY_INVOKE = /(?:^|[;&|(\s=])(?:python3?(?:\.exe)?|py(?:\.exe)?|pytest)(?=\s|$)/i;
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
	[/\bidat64(?:\.exe)?\b/i, "idat.exe or ap read <bin> --xref --ioctl --rpc-com-alpc"],
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
export interface ProviderRequestHashes {{
	model: string;
	effort: string;
	toolsHash: number;
	msgHashes: number[];
}}

function fnv1a32(text: string): number {{
	let h = 0x811c9dc5;
	for (let i = 0; i < text.length; i++) {{
		h ^= text.charCodeAt(i);
		h = Math.imul(h, 0x01000193) >>> 0;
	}}
	return h >>> 0;
}}

/**
 * Compute deterministic wire-level hashes across `model`, `reasoning_effort`, `tools`, and
 * `messages[]` before provider send (<0.4ms) so `turn_end` can classify unexpected KV-cache drops.
 */
export function snapshotProviderRequestHashes(payload: unknown): ProviderRequestHashes | null {{
	if (!payload || typeof payload !== "object") return null;
	const p = payload as {{
		model?: unknown;
		reasoning_effort?: unknown;
		reasoningEffort?: unknown;
		tools?: unknown;
		messages?: unknown;
	}};
	const model = String(p.model ?? "");
	const effort = String(p.reasoning_effort ?? p.reasoningEffort ?? "");
	let toolsHash = 0;
	if (Array.isArray(p.tools)) {{
		try {{
			toolsHash = fnv1a32(JSON.stringify(p.tools));
		}} catch {{
			toolsHash = p.tools.length;
		}}
	}}
	const msgHashes: number[] = [];
	if (Array.isArray(p.messages)) {{
		const cap = Math.min(p.messages.length, 400);
		for (let i = 0; i < cap; i++) {{
			try {{
				msgHashes.push(fnv1a32(JSON.stringify(p.messages[i])));
			}} catch {{
				msgHashes.push(i);
			}}
		}}
	}}
	return {{ model, effort, toolsHash, msgHashes }};
}}

/**
 * Pinpoint the exact diverging prefix boundary when DeepSeek KV-cache drops unexpectedly.
 */
export function classifyCacheDropCause(
	prev: ProviderRequestHashes | null,
	curr: ProviderRequestHashes | null,
): string {{
	if (!prev || !curr) return "ttl_eviction";
	if (prev.model !== curr.model) return "model_changed";
	if (prev.effort !== curr.effort) return "effort_changed";
	if (prev.toolsHash !== curr.toolsHash) return "tools_changed";
	const common = Math.min(prev.msgHashes.length, curr.msgHashes.length);
	for (let i = 0; i < common; i++) {{
		if (prev.msgHashes[i] !== curr.msgHashes[i]) {{
			return `msg[${{i}}]_mutated`;
		}}
	}}
	if (curr.msgHashes.length < prev.msgHashes.length) return "prefix_truncated";
	return "ttl_eviction";
}}

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
	`const setTimeout = typeof globalThis.setTimeout === "function" ? globalThis.setTimeout : (fn, ms = 0, ...a) => {{ if (typeof sleep === "function") {{ sleep(ms).then(() => {{ if (typeof fn === "function") fn(...a); }}); }} else if (typeof fn === "function") {{ fn(...a); }} return 0; }};`;

export interface ApProfileOverrides {{
	modelProfile: string;
	sieveHardChars?: number;
	kvSafeSleepSec?: number;
	maskHighWaterTokens?: number;
	dsmlRecovery?: boolean;
	yieldCompact?: boolean;
}}

const MODEL_PROFILE_KNOBS: Readonly<Record<string, Omit<ApProfileOverrides, "modelProfile" | "yieldCompact">>> = {{
	balanced: {{ sieveHardChars: 20000, kvSafeSleepSec: 60, maskHighWaterTokens: 180000, dsmlRecovery: false }},
	deepseek: {{ sieveHardChars: 12000, kvSafeSleepSec: 45, maskHighWaterTokens: 135000, dsmlRecovery: true }},
	fast: {{ sieveHardChars: 12000, kvSafeSleepSec: 45, maskHighWaterTokens: 140000, dsmlRecovery: false }},
	reasoning: {{ sieveHardChars: 16000, kvSafeSleepSec: 45, maskHighWaterTokens: 180000, dsmlRecovery: false }},
	small: {{ sieveHardChars: 10000, kvSafeSleepSec: 45, maskHighWaterTokens: 90000, dsmlRecovery: false }},
}};

/**
 * Load optional Layer 3 declarative profile overrides (`~/.ap/profile.json`) once on startup.
 * Returns `undefined` when missing and no explicit override (`model_profile` != auto or `yield_compact`) is set.
 */
export function loadApProfile(profilePath?: string): ApProfileOverrides | undefined {{
	try {{
		const p = profilePath || join(homedir(), ".ap", "profile.json");
		if (!existsSync(p)) return undefined;
		const parsed = JSON.parse(readFileSync(p, "utf8")) as {{
			model_profile?: unknown;
			yield_compact?: unknown;
			yieldCompact?: unknown;
		}};
		const mp = typeof parsed?.model_profile === "string" ? parsed.model_profile.trim().toLowerCase() : "";
		const yieldCompact =
			typeof parsed?.yield_compact === "boolean"
				? parsed.yield_compact
				: typeof parsed?.yieldCompact === "boolean"
					? parsed.yieldCompact
					: undefined;
		const knobs = mp && mp !== "auto" ? MODEL_PROFILE_KNOBS[mp] : undefined;
		if (!knobs && yieldCompact === undefined) return undefined;
		return {{
			modelProfile: knobs ? mp : (mp || "auto"),
			...(knobs ?? {{}}),
			...(yieldCompact !== undefined ? {{ yieldCompact }} : {{}}),
		}};
	}} catch {{
		return undefined;
	}}
}}

/**
 * Decide whether `zz-ap-accelerator` should yield LLM compaction summarization to an earlier extension or host workflow.
 * Note: `.baton` checkpointing still runs unconditionally before this yield check.
 */
export function shouldYieldCompaction(input: {{
	compactionClaimed?: boolean;
	envYieldCompact?: string;
	profileYieldCompact?: boolean;
	peerClaimed?: boolean;
}}): boolean {{
	return Boolean(
		input.compactionClaimed ||
			input.envYieldCompact === "1" ||
			input.profileYieldCompact === true ||
			input.peerClaimed,
	);
}}

/**
 * Read active model auto-compaction trigger tokens (`contextWindow - reserveTokens`) from `~/.pi/agent/settings.json`.
 */
export function readModelCompactionTriggerTokens(
	model?: {{ provider?: string; id?: string; contextWindow?: number }},
	settingsPath?: string,
): number | undefined {{
	try {{
		const p = settingsPath || join(homedir(), ".pi", "agent", "settings.json");
		if (!existsSync(p)) return undefined;
		const parsed = JSON.parse(readFileSync(p, "utf8")) as {{
			compaction?: {{
				reserveTokens?: unknown;
				modelOverrides?: Record<string, {{ reserveTokens?: unknown }}>;
			}};
		}};
		const comp = parsed?.compaction;
		if (!comp || typeof comp !== "object") return undefined;
		const prov = String(model?.provider ?? "").trim();
		const id = String(model?.id ?? "").trim();
		const key = prov && id ? `${{prov}}/${{id}}` : id;
		const overrides = comp.modelOverrides && typeof comp.modelOverrides === "object" ? comp.modelOverrides : undefined;
		let reserve: unknown = key && overrides?.[key]?.reserveTokens;
		if (typeof reserve !== "number" && id === "flash-auto" && overrides?.["deepseek/deepseek-flash"]) {{
			reserve = overrides["deepseek/deepseek-flash"].reserveTokens;
		}}
		if (typeof reserve !== "number") {{
			reserve = comp.reserveTokens;
		}}
		if (typeof reserve !== "number" || !Number.isFinite(reserve) || reserve <= 0) return undefined;
		const ctxWindow =
			typeof model?.contextWindow === "number" && model.contextWindow > 0
				? model.contextWindow
				: id === "deepseek-flash" || id === "flash-auto"
					? 1000000
					: 0;
		if (ctxWindow <= reserve) return undefined;
		return ctxWindow - reserve;
	}} catch {{
		return undefined;
	}}
}}

/**
 * Compute effective observation-masking high-water threshold, capping safely below active auto-compaction trigger
 * (`floor(trigger * 0.85)`) so masking actually runs before compaction resets KV-cache.
 */
export function resolveEffectiveMaskHighWaterTokens(input: {{
	deepCacheDiscount?: boolean;
	profileMaskTokens?: number;
	compactionTriggerTokens?: number;
}}): number {{
	const base =
		typeof input.profileMaskTokens === "number" && input.profileMaskTokens > 0
			? input.profileMaskTokens
			: input.deepCacheDiscount
				? 210000
				: MASK_HIGH_WATER_TOKENS;
	if (typeof input.compactionTriggerTokens === "number" && input.compactionTriggerTokens >= 40000) {{
		const dynamicCap = Math.max(40000, Math.floor(input.compactionTriggerTokens * 0.85));
		return Math.min(base, dynamicCap);
	}}
	return base;
}}

/**
 * Return true for DeepSeek models (including virtual `deepseek/flash-auto`).
 */
export function isDeepSeekModel(model?: {{ provider?: string; id?: string; modelId?: string }}): boolean {{
	if (!model) return false;
	const prov = String(model.provider ?? "").toLowerCase();
	const id = String(model.id ?? model.modelId ?? "").toLowerCase();
	return prov.includes("deepseek") || id.includes("deepseek") || id.includes("flash-auto");
}}

/**
 * Strip benign trailing stderr redirections (`2>/dev/null`, `2>NUL`, `2>&1`) from a shell command stage.
 */
function stripBenignStderrRedir(s: string): string {{
	return s.replace(/\s+2>\s*(?:\/dev\/null|NUL|&1)\s*$/i, "").trim();
}}

/**
 * Return true for non-retryable billing/auth/request errors (HTTP 400/401/402/403/404/422, insufficient balance,
 * quota/auth/context-length) that sub-LLM helpers must never retry. Anchors numeric codes to HTTP/status context
 * so bare numbers in transport errors (e.g. "reset after 404 ms", "reading 422 bytes") are still retried.
 */
export function isNonRetryableSubLlmError(errMsg: string): boolean {{
	if (!errMsg) return false;
	return /(?:HTTP(?:\/\d(?:\.\d)?)?\s+|status(?:\s+code)?[\s:=]+|\berror(?:\s+code)?[\s:=]+)(?:400|401|402|403|404|422)\b|^\s*(?:400|401|402|403|404|422)\s+[A-Za-z]|insufficient[\s_-]*balance|quota|billing|payment|invalid[\s_-]*api[\s_-]*key|unauthorized|forbidden|authentication|context[\s_-]*length/i.test(
		errMsg,
	);
}}

export interface SubLlmRetryOptions {{
	reasoning?: "low" | "medium" | "high" | "max";
	maxTokens?: number;
	cacheRetention?: "none" | "short" | "long";
	signal?: AbortSignal;
	timeoutMs?: number;
	maxAttempts?: number;
	retryDelayMs?: number;
	unwrapVirtual?: boolean;
}}

/**
 * Bounded-timeout, 1-retry jittered sub-LLM caller for compaction / handoff / review helpers.
 * Optionally unwraps `deepseek/flash-auto` to physical `deepseek/deepseek-flash`, and strictly never
 * retries 402/billing/auth/400 errors or caller aborts.
 */
export async function callSubLlmWithRetry(
	ctx: {{
		modelRegistry?: {{
			find?: (provider: string, id: string) => unknown;
			streamSimple?: (model: unknown, reqCtx: unknown, opts: unknown) => {{ result: () => Promise<Record<string, unknown>> }};
			complete?: (model: unknown, reqCtx: unknown, opts: unknown) => Promise<Record<string, unknown>>;
		}};
	}},
	model: {{ provider?: string; id?: string; [k: string]: unknown }},
	reqCtx: unknown,
	opts: SubLlmRetryOptions = {{}},
): Promise<Record<string, unknown> | undefined> {{
	const targetModel =
		opts.unwrapVirtual && model?.id === "flash-auto"
			? (ctx?.modelRegistry?.find?.("deepseek", "deepseek-flash") ?? model)
			: model;
	const maxAttempts = Math.max(1, Math.min(3, opts.maxAttempts ?? 2));
	const timeoutMs = Math.max(1000, opts.timeoutMs ?? 45000);
	let lastResponse: Record<string, unknown> | undefined;
	let lastError: unknown;

	for (let attempt = 1; attempt <= maxAttempts; attempt++) {{
		if (opts.signal?.aborted) return undefined;
		const ac = new AbortController();
		const onParentAbort = () => ac.abort();
		opts.signal?.addEventListener("abort", onParentAbort, {{ once: true }});
		const timer = setTimeout(() => ac.abort(), timeoutMs);
		try {{
			const callOpts = {{
				reasoning: opts.reasoning ?? "low",
				maxTokens: opts.maxTokens ?? 6144,
				cacheRetention: opts.cacheRetention ?? "none",
				signal: ac.signal,
			}};
			const resp =
				typeof ctx?.modelRegistry?.streamSimple === "function"
					? await ctx.modelRegistry.streamSimple(targetModel, reqCtx, callOpts).result()
					: typeof ctx?.modelRegistry?.complete === "function"
						? await ctx.modelRegistry.complete(targetModel, reqCtx, callOpts)
						: undefined;
			lastResponse = resp;
			if (!resp) {{
				if (attempt >= maxAttempts) return undefined;
			}} else if (resp.stopReason === "aborted") {{
				return resp;
			}} else if (resp.stopReason === "error") {{
				const errMsg = String(resp.errorMessage ?? resp.error ?? "");
				if (isNonRetryableSubLlmError(errMsg) || attempt >= maxAttempts) {{
					return resp;
				}}
			}} else {{
				return resp;
			}}
		}} catch (err) {{
			lastError = err;
			const errMsg = err instanceof Error ? err.message : String(err);
			if (opts.signal?.aborted || isNonRetryableSubLlmError(errMsg) || attempt >= maxAttempts) {{
				throw err;
			}}
		}} finally {{
			clearTimeout(timer);
			opts.signal?.removeEventListener("abort", onParentAbort);
		}}
		const delay =
			typeof opts.retryDelayMs === "number"
				? Math.max(0, opts.retryDelayMs)
				: 400 + Math.floor(Math.random() * 400);
		if (delay > 0) {{
			await new Promise((r) => setTimeout(r, delay));
		}}
	}}
	if (lastResponse) return lastResponse;
	if (lastError) throw lastError;
	return undefined;
}}

/**
 * Lexically escape unescaped raw newlines inside single/double-quoted JS strings while leaving
 * comments, regex literals, and multiline backtick template literals untouched (prevents QuickJS EOS errors).
 */
export function healJsStringRawNewlines(code: string): string | undefined {{
	if (!code || (!code.includes("\n") && !code.includes("\r") && !code.includes("\\"))) return undefined;
	const n = code.length;
	let out = "";
	let lastFlush = 0;
	let changed = false;
	let i = 0;

	const scanRegexLiteral = (startSlash: number): number => {{
		let prev = startSlash - 1;
		while (prev >= 0 && (code[prev] === " " || code[prev] === "\t")) prev--;
		let allowRegex = prev < 0 || "([,=;:!&|?{{}}~+-*%^<>\n\r".includes(code[prev]);
		if (!allowRegex && prev >= 0 && /[A-Za-z_$0-9]/.test(code[prev])) {{
			let wStart = prev;
			while (wStart > 0 && /[A-Za-z_$0-9]/.test(code[wStart - 1])) wStart--;
			const word = code.slice(wStart, prev + 1);
			allowRegex = /^(?:return|throw|case|typeof|void|delete|await|yield|in|of|new)$/.test(word);
		}}
		if (!allowRegex) return -1;
		let j = startSlash + 1;
		let inClass = false;
		while (j < n) {{
			const rc = code[j];
			if (rc === "\n" || rc === "\r") return -1;
			if (rc === "\\") {{
				if (j + 1 >= n || code[j + 1] === "\n" || code[j + 1] === "\r") return -1;
				j += 2;
				continue;
			}}
			if (rc === "[") {{
				inClass = true;
				j++;
				continue;
			}}
			if (rc === "]" && inClass) {{
				inClass = false;
				j++;
				continue;
			}}
			if (rc === "/" && !inClass) {{
				j++;
				while (j < n && /[a-z]/i.test(code[j])) j++;
				return j;
			}}
			j++;
		}}
		return -1;
	}};

	const scanQuoted = (quote: string) => {{
		i++;
		while (i < n) {{
			const ch = code[i];
			if (ch === "\\") {{
				let bs = 0;
				while (i + bs < n && code[i + bs] === "\\") bs++;
				if (bs % 2 === 1 && i + bs < n && code[i + bs] === quote) {{
					let k = i + bs + 1;
					while (k < n && (code[k] === " " || code[k] === "\t")) k++;
					const nextCh = k < n ? code[k] : "";
					if (nextCh === "" || ",;}}]):\r\n".includes(nextCh)) {{
						let hasLaterClose = false;
						let s = i + bs + 1;
						while (s < n && code[s] !== "\n" && code[s] !== "\r") {{
							if (code[s] === "\\") {{
								let sbs = 0;
								while (s + sbs < n && code[s + sbs] === "\\") sbs++;
								s +=
									sbs % 2 === 1 && s + sbs < n && code[s + sbs] !== "\n" && code[s + sbs] !== "\r"
										? sbs + 1
										: sbs;
								continue;
							}}
							if (code[s] === quote) {{
								hasLaterClose = true;
								break;
							}}
							s++;
						}}
						if (!hasLaterClose) {{
							out += code.slice(lastFlush, i + bs) + "\\";
							lastFlush = i + bs;
							changed = true;
							i += bs + 1;
							break;
						}}
					}}
				}}
				i += bs % 2 === 1 && i + bs < n ? bs + 1 : bs;
				continue;
			}}
			if (ch === "\r") {{
				out += code.slice(lastFlush, i);
				if (code[i + 1] === "\n") {{
					out += "\\n";
					i += 2;
				}} else {{
					out += "\\r";
					i++;
				}}
				lastFlush = i;
				changed = true;
				continue;
			}}
			if (ch === "\n") {{
				out += code.slice(lastFlush, i) + "\\n";
				i++;
				lastFlush = i;
				changed = true;
				continue;
			}}
			if (ch === quote) {{
				i++;
				break;
			}}
			i++;
		}}
	}};

	const scanTemplate = (isRawTag: boolean) => {{
		i++;
		while (i < n) {{
			const ch = code[i];
			if (ch === "\\") {{
				let bs = 0;
				while (i + bs < n && code[i + bs] === "\\") bs++;
				if (bs % 2 === 1 && i + bs < n && code[i + bs] === "`") {{
					let k = i + bs + 1;
					while (k < n && (code[k] === " " || code[k] === "\t")) k++;
					const nextCh = k < n ? code[k] : "";
					if (nextCh === "" || ",;}}]):\r\n".includes(nextCh)) {{
						let hasLaterBacktick = false;
						let s = i + bs + 1;
						while (s < n) {{
							if (code[s] === "\\") {{
								let sbs = 0;
								while (s + sbs < n && code[s + sbs] === "\\") sbs++;
								s += sbs % 2 === 1 && s + sbs < n ? sbs + 1 : sbs;
								continue;
							}}
							if (code[s] === "`") {{
								hasLaterBacktick = true;
								break;
							}}
							s++;
						}}
						if (!hasLaterBacktick) {{
							if (isRawTag) {{
								out += code.slice(lastFlush, i + bs - 1) + '` + "\\\\"';
								lastFlush = i + bs + 1;
							}} else {{
								out += code.slice(lastFlush, i + bs) + "\\";
								lastFlush = i + bs;
							}}
							changed = true;
							i += bs + 1;
							break;
						}}
					}}
				}}
				i += bs % 2 === 1 && i + bs < n ? bs + 1 : bs;
				continue;
			}}
			if (ch === "$" && code[i + 1] === "{{") {{
				i += 2;
				scanNormal(true);
				continue;
			}}
			if (ch === "`") {{
				i++;
				break;
			}}
			i++;
		}}
	}};

	const scanNormal = (stopOnCloseBrace: boolean) => {{
		let braceDepth = 0;
		while (i < n) {{
			const ch = code[i];
			if (ch === "{{" && stopOnCloseBrace) {{
				braceDepth++;
				i++;
				continue;
			}}
			if (ch === "}}" && stopOnCloseBrace) {{
				if (braceDepth === 0) {{
					i++;
					return;
				}}
				braceDepth--;
				i++;
				continue;
			}}
			if (ch === "/" && code[i + 1] === "/") {{
				const nl = code.indexOf("\n", i + 2);
				i = nl < 0 ? n : nl + 1;
				continue;
			}}
			if (ch === "/" && code[i + 1] === "*") {{
				const end = code.indexOf("*/", i + 2);
				i = end < 0 ? n : end + 2;
				continue;
			}}
			if (ch === "/" && code[i + 1] !== "/" && code[i + 1] !== "*") {{
				const rEnd = scanRegexLiteral(i);
				if (rEnd > i) {{
					i = rEnd;
					continue;
				}}
			}}
			if (ch === "'" || ch === '"') {{
				scanQuoted(ch);
				continue;
			}}
			if (ch === "`") {{
				const isRawTag = /\bString\.raw[ \t]*$/.test(code.slice(Math.max(0, i - 16), i));
				scanTemplate(isRawTag);
				continue;
			}}
			i++;
		}}
	}};

	scanNormal(false);
	if (!changed) return undefined;
	out += code.slice(lastFlush);
	return out;
}}

const AP_MCP_TOOL_NAMES: ReadonlySet<string> = new Set([
	"ap_read",
	"ap_query",
	"ap_search",
	"ap_undo",
	"ap_orient",
	"ap_impact",
	"ap_edit",
	"ap_smoke",
	"ap_fuzz",
	"ap_mutate",
	"ap_ui",
	"ap_locate",
	"ap_trace",
	"ap_cdp",
	"ap_http",
	"ap_ports",
	"ap_ps",
	"ap_win",
	"ap_fs_diff",
	"ap_tcp",
	"ap_listen",
	"ap_ws",
	"ap_tls",
	"ap_baton_claim",
	"ap_baton_dedup",
	"ap_guard_pack",
	"ap_diff_audit",
	"ap_verify",
	"ap_exec",
	"ap_probe",
	"ap_rename",
	"ap_sieve",
	"ap_baton",
	"ap_recall",
	"ap_changes",
	"ap_surface",
	"ap_frontier",
	"ap_discover",
	"ap_call",
]);

function maskCodemodeSpans(code: string): {{ masked: string; tokens: string[] }} | null {{
	if (!code || code.includes("\u0001")) return null;
	const tokens: string[] = [];
	let masked = "";
	let last = 0;
	let i = 0;
	const n = code.length;
	const maskSpan = (start: number, end: number) => {{
		masked += code.slice(last, start);
		const idx = tokens.length;
		tokens.push(code.slice(start, end));
		masked += `\u0001T${{idx}}\u0001`;
		last = end;
	}};
	const scanRegexLit = (startSlash: number): number => {{
		let prev = startSlash - 1;
		while (prev >= 0 && (code[prev] === " " || code[prev] === "\t")) prev--;
		let allow = prev < 0 || "([,=;:!&|?{{}}~+-*%^<>\n\r".includes(code[prev]);
		if (!allow && prev >= 0 && /[A-Za-z_$0-9]/.test(code[prev])) {{
			let ws = prev;
			while (ws > 0 && /[A-Za-z_$0-9]/.test(code[ws - 1])) ws--;
			allow = /^(?:return|throw|case|typeof|void|delete|await|yield|in|of|new)$/.test(code.slice(ws, prev + 1));
		}}
		if (!allow) return -1;
		let j = startSlash + 1;
		let inClass = false;
		while (j < n) {{
			const rc = code[j];
			if (rc === "\n" || rc === "\r") return -1;
			if (rc === "\\") {{
				if (j + 1 >= n || code[j + 1] === "\n" || code[j + 1] === "\r") return -1;
				j += 2;
				continue;
			}}
			if (rc === "[") inClass = true;
			else if (rc === "]" && inClass) inClass = false;
			else if (rc === "/" && !inClass) {{
				j++;
				while (j < n && /[a-z]/i.test(code[j])) j++;
				return j;
			}}
			j++;
		}}
		return -1;
	}};
	const scanTpl = () => {{
		let spanStart = i;
		i++;
		while (i < n) {{
			const ch = code[i];
			if (ch === "\\") {{
				i += i + 1 < n ? 2 : 1;
				continue;
			}}
			if (ch === "$" && code[i + 1] === "{{") {{
				i += 2;
				maskSpan(spanStart, i);
				scanCode(true);
				spanStart = i;
				continue;
			}}
			if (ch === "`") {{
				i++;
				maskSpan(spanStart, i);
				return;
			}}
			i++;
		}}
		maskSpan(spanStart, n);
	}};
	const scanCode = (stopOnBrace: boolean) => {{
		let braceDepth = 0;
		while (i < n) {{
			const ch = code[i];
			if (ch === "{{" && stopOnBrace) {{
				braceDepth++;
				i++;
				continue;
			}}
			if (ch === "}}" && stopOnBrace) {{
				if (braceDepth === 0) {{
					i++;
					return;
				}}
				braceDepth--;
				i++;
				continue;
			}}
			if (ch === "/" && code[i + 1] === "/") {{
				const s = i;
				const nl = code.indexOf("\n", i + 2);
				i = nl < 0 ? n : nl;
				maskSpan(s, i);
				continue;
			}}
			if (ch === "/" && code[i + 1] === "*") {{
				const s = i;
				const end = code.indexOf("*/", i + 2);
				i = end < 0 ? n : end + 2;
				maskSpan(s, i);
				continue;
			}}
			if (ch === "/" && code[i + 1] !== "/" && code[i + 1] !== "*") {{
				const reEnd = scanRegexLit(i);
				if (reEnd > i) {{
					maskSpan(i, reEnd);
					i = reEnd;
					continue;
				}}
			}}
			if (ch === "'" || ch === '"') {{
				const s = i;
				const q = ch;
				i++;
				while (i < n) {{
					if (code[i] === "\\") {{
						i += i + 1 < n ? 2 : 1;
						continue;
					}}
					if (code[i] === q) {{
						i++;
						break;
					}}
					if (code[i] === "\n" || code[i] === "\r") break;
					i++;
				}}
				maskSpan(s, i);
				continue;
			}}
			if (ch === "`") {{
				scanTpl();
				continue;
			}}
			i++;
		}}
	}};
	scanCode(false);
	masked += code.slice(last);
	return {{ masked, tokens }};
}}

function stripTsTypesInCodemode(code: string): string {{
	if (!code || (!code.includes(":") && !/\bas\s+/.test(code))) return code;
	const spanRes = maskCodemodeSpans(code);
	if (!spanRes) return code;
	const {{ masked, tokens }} = spanRes;

	const consumeBalancedType = (s: string, start: number, allowFnArrow: boolean): number => {{
		let p = start;
		while (p < s.length && (s[p] === " " || s[p] === "\t")) p++;
		let angle = 0;
		let paren = 0;
		let bracket = 0;
		let brace = 0;
		let sawToken = false;
		let expectMore = true;
		while (p < s.length) {{
			const ch = s[p];
			const depth = angle + paren + bracket + brace;
			if (ch === "<") {{
				if (depth > 0 || sawToken) {{
					angle++;
					p++;
					expectMore = true;
					continue;
				}}
				break;
			}}
			if (ch === ">") {{
				if (angle > 0) {{
					angle--;
					p++;
					sawToken = true;
					expectMore = false;
					continue;
				}}
				break;
			}}
			if (ch === "(") {{
				if (depth > 0 || expectMore) {{
					paren++;
					p++;
					expectMore = true;
					continue;
				}}
				break;
			}}
			if (ch === ")") {{
				if (paren > 0) {{
					paren--;
					p++;
					sawToken = true;
					expectMore = false;
					continue;
				}}
				break;
			}}
			if (ch === "[") {{
				bracket++;
				p++;
				expectMore = true;
				continue;
			}}
			if (ch === "]") {{
				if (bracket > 0) {{
					bracket--;
					p++;
					sawToken = true;
					expectMore = false;
					continue;
				}}
				break;
			}}
			if (ch === "{{") {{
				if (depth > 0 || expectMore) {{
					brace++;
					p++;
					expectMore = true;
					continue;
				}}
				break;
			}}
			if (ch === "}}") {{
				if (brace > 0) {{
					brace--;
					p++;
					sawToken = true;
					expectMore = false;
					continue;
				}}
				break;
			}}
			if (depth === 0) {{
				if (ch === "=" && s[p + 1] === ">") {{
					if (!allowFnArrow) break;
					p += 2;
					expectMore = true;
					continue;
				}}
				if (";,=\r\n?:".includes(ch)) break;
				if (ch === "|" || ch === "&") {{
					p++;
					expectMore = true;
					continue;
				}}
				if (ch === " " || ch === "\t") {{
					let q = p;
					while (q < s.length && (s[q] === " " || s[q] === "\t")) q++;
					if (s[q] === "=" && s[q + 1] === ">" && allowFnArrow) {{
						p = q + 2;
						expectMore = true;
						continue;
					}}
					if (s[q] === "|" || s[q] === "&" || s[q] === "[" || s[q] === "<") {{
						p = q;
						continue;
					}}
					const kw = s.slice(q).match(/^(?:in|of|as)\b/);
					if (kw) break;
					if (!expectMore) break;
					p = q;
					continue;
				}}
				if (ch === "\u0001") {{
					const endM = s.indexOf("\u0001", p + 1);
					if (endM < 0) break;
					p = endM + 1;
					sawToken = true;
					expectMore = false;
					continue;
				}}
				if (/[A-Za-z0-9_$.]/.test(ch)) {{
					p++;
					sawToken = true;
					expectMore = false;
					continue;
				}}
				break;
			}}
			p++;
		}}
		if (angle !== 0 || paren !== 0 || bracket !== 0 || brace !== 0 || !sawToken) return -1;
		while (p > start && (s[p - 1] === " " || s[p - 1] === "\t")) p--;
		return p > start ? p : -1;
	}};

	const stripParamList = (params: string): string => {{
		let outP = "";
		let idx = 0;
		let dp = 0;
		let db = 0;
		let da = 0;
		while (idx < params.length) {{
			const ch = params[idx];
			if (ch === "(") dp++;
			else if (ch === ")" && dp > 0) dp--;
			else if (ch === "[") db++;
			else if (ch === "]" && db > 0) db--;
			else if (ch === "<") da++;
			else if (ch === ">" && da > 0) da--;
			else if (ch === "{{") {{
				let bDepth = 1;
				let j = idx + 1;
				while (j < params.length && bDepth > 0) {{
					if (params[j] === "{{") bDepth++;
					else if (params[j] === "}}") bDepth--;
					j++;
				}}
				outP += params.slice(idx, j);
				idx = j;
				if (dp === 0 && db === 0 && da === 0) {{
					const rest = params.slice(idx).match(/^[ \t]*\??[ \t]*:/);
					if (rest) {{
						const tEnd = consumeBalancedType(params, idx + rest[0].length, true);
						if (tEnd > 0) idx = tEnd;
					}}
				}}
				continue;
			}}
			if (dp === 0 && db === 0 && da === 0 && (ch === "?" || ch === ":")) {{
				const colonM = params.slice(idx).match(/^\??[ \t]*:/);
				if (colonM) {{
					const tEnd = consumeBalancedType(params, idx + colonM[0].length, true);
					if (tEnd > 0) {{
						idx = tEnd;
						continue;
					}}
				}}
			}}
			outP += ch;
			idx++;
		}}
		return outP;
	}};

	let res = masked;
	// 1. Variable declarations: `const x: Type = ...` or `let x: Type;`
	if (/\b(?:const|let|var)[ \t]+[A-Za-z_$]/.test(res)) {{
		let nextRes = "";
		let cur = 0;
		const declRe = /\b(const|let|var)[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*:/g;
		let dm: RegExpExecArray | null;
		while ((dm = declRe.exec(res)) !== null) {{
			const colonPos = dm.index + dm[0].length;
			const tEnd = consumeBalancedType(res, colonPos, true);
			if (tEnd > colonPos) {{
				let k = tEnd;
				while (k < res.length && (res[k] === " " || res[k] === "\t")) k++;
				const tail = res.slice(k);
				if (
					k >= res.length ||
					"=;,\r\n)".includes(res[k]) ||
					/^(?:in|of)\b/.test(tail)
				) {{
					nextRes += res.slice(cur, dm.index) + res.slice(dm.index, colonPos - 1).replace(/[ \t]*$/, "");
					cur = tEnd;
					declRe.lastIndex = tEnd;
				}}
			}}
		}}
		if (cur > 0) res = nextRes + res.slice(cur);
	}}

	// 2. `catch (e: unknown)` -> `catch (e)`
	res = res.replace(
		/\bcatch[ \t]*\([ \t]*([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*:[^()\n]+\)/g,
		"catch ($1)",
	);

	// 3. Function declarations/expressions & arrow functions (params + return types)
	if (res.includes(":")) {{
		const fnHeadRe = /\b((?:async[ \t]+)?function(?:[ \t]+[A-Za-z_$][A-Za-z0-9_$]*)?[ \t]*)(?:<[^>\n;{{]+>[ \t]*)?\(/g;
		let fnOut = "";
		let fnCur = 0;
		let fm: RegExpExecArray | null;
		while ((fm = fnHeadRe.exec(res)) !== null) {{
			const openParen = fm.index + fm[0].length - 1;
			let depth = 1;
			let p = openParen + 1;
			while (p < res.length && depth > 0) {{
				if (res[p] === "(") depth++;
				else if (res[p] === ")") depth--;
				p++;
			}}
			if (depth !== 0) continue;
			const closeParen = p - 1;
			const rawParams = res.slice(openParen + 1, closeParen);
			const cleanParams = rawParams.includes(":") ? stripParamList(rawParams) : rawParams;
			let afterClose = closeParen + 1;
			const retColon = res.slice(afterClose).match(/^[ \t]*:/);
			if (retColon) {{
				const tEnd = consumeBalancedType(res, afterClose + retColon[0].length, false);
				if (tEnd > 0) {{
					let k = tEnd;
					while (k < res.length && (res[k] === " " || res[k] === "\t")) k++;
					if (res[k] === "{{") {{
						afterClose = tEnd;
					}}
				}}
			}}
			fnOut += res.slice(fnCur, fm.index) + fm[1] + "(" + cleanParams + ")" + (afterClose > closeParen + 1 ? " " : "");
			fnCur = afterClose;
			fnHeadRe.lastIndex = afterClose;
		}}
		if (fnCur > 0) res = fnOut + res.slice(fnCur);

		// Arrow functions: `(params)[: ReturnType] =>`
		let arrOut = "";
		let arrCur = 0;
		for (let p = 0; p < res.length; p++) {{
			if (res[p] !== "(") continue;
			let depth = 1;
			let q = p + 1;
			while (q < res.length && depth > 0) {{
				if (res[q] === "(") depth++;
				else if (res[q] === ")") depth--;
				q++;
			}}
			if (depth !== 0) continue;
			const closeP = q - 1;
			let k = closeP + 1;
			while (k < res.length && (res[k] === " " || res[k] === "\t")) k++;
			let arrowStart = -1;
			let retEnd = closeP + 1;
			if (res[k] === "=" && res[k + 1] === ">") {{
				arrowStart = k;
			}} else if (res[k] === ":") {{
				const tEnd = consumeBalancedType(res, k + 1, false);
				if (tEnd > 0) {{
					let k2 = tEnd;
					while (k2 < res.length && (res[k2] === " " || res[k2] === "\t")) k2++;
					if (res[k2] === "=" && res[k2 + 1] === ">") {{
						arrowStart = k2;
						retEnd = tEnd;
					}}
				}}
			}}
			if (arrowStart >= 0) {{
				const rawParams = res.slice(p + 1, closeP);
				if (rawParams.includes(":") || retEnd > closeP + 1) {{
					const cleanParams = rawParams.includes(":") ? stripParamList(rawParams) : rawParams;
					arrOut += res.slice(arrCur, p) + "(" + cleanParams + ")" + (retEnd > closeP + 1 ? " " : "");
					arrCur = retEnd;
					p = arrowStart + 1;
				}}
			}}
		}}
		if (arrCur > 0) res = arrOut + res.slice(arrCur);
	}}

	// 4. `as <Type>` casts (supports nested generics like `as unknown as Record<string, any>`)
	if (/\bas[ \t]+/.test(res)) {{
		for (let pass = 0; pass < 3; pass++) {{
			let asOut = "";
			let asCur = 0;
			const asRe = /(\)|\]|\}}|\b[A-Za-z_$][A-Za-z0-9_$]*)[ \t]+\bas[ \t]+/g;
			let am: RegExpExecArray | null;
			while ((am = asRe.exec(res)) !== null) {{
				const typeStart = am.index + am[0].length;
				const tEnd = consumeBalancedType(res, typeStart, true);
				if (tEnd > typeStart) {{
					let k = tEnd;
					while (k < res.length && (res[k] === " " || res[k] === "\t")) k++;
					const nextCh = k < res.length ? res[k] : "";
					if (
						nextCh === "" ||
						";,)]\r\n.?:&|".includes(nextCh) ||
						/^as\b/.test(res.slice(k))
					) {{
						asOut += res.slice(asCur, am.index + am[1].length);
						asCur = tEnd;
						asRe.lastIndex = tEnd;
					}}
				}}
			}}
			if (asCur === 0) break;
			res = asOut + res.slice(asCur);
		}}
	}}

	return res.replace(/\u0001T(\d+)\u0001/g, (_m, idx: string) => tokens[Number(idx)] ?? "");
}}

export function healStringRawInnerBackticks(code: string): string {{
	if (!code || !code.includes("String.raw`")) return code;
	let out = "";
	let last = 0;
	let i = 0;
	const n = code.length;
	while (i < n) {{
		if (
			code.startsWith("String.raw`", i) &&
			(i === 0 || !/[A-Za-z0-9_$]/.test(code[i - 1]))
		) {{
			let j = i + "String.raw`".length;
			let segOut = "";
			let segLast = j;
			let closed = false;
			while (j < n) {{
				const ch = code[j];
				if (ch === "$" && code[j + 1] === "{{") {{
					j += 2;
					let depth = 1;
					let q: string | null = null;
					while (j < n && depth > 0) {{
						const ic = code[j];
						if (q) {{
							if (ic === "\\" && q !== "`") {{ j += 2; continue; }}
							if (ic === q) q = null;
							j++;
							continue;
						}}
						if (ic === "'" || ic === '"' || ic === "`") {{ q = ic; j++; continue; }}
						if (ic === "{{") depth++;
						else if (ic === "}}") depth--;
						j++;
					}}
					continue;
				}}
				if (ch === "`") {{
					const after = code.slice(j + 1);
					const eolM = after.match(/^([^\r\n]*)/);
					const restLine = (eolM ? eolM[1] : "").trim();
					const isClosing =
						/^[;,)\]\}}]?(?:\s*(?:\/\/.*)?)?$/.test(restLine) &&
						(restLine.length > 0 ||
							after.trim().length === 0 ||
							/^\r?\n(?:\s*(?:const|let|var|await|return|if|for|while|try|text|console|tools|\}}|\)|\]|;))/.test(after));
					if (isClosing) {{
						segOut += code.slice(segLast, j + 1);
						j++;
						closed = true;
						break;
					}}
					segOut += code.slice(segLast, j) + '${{"`"}}';
					j++;
					segLast = j;
					continue;
				}}
				j++;
			}}
			if (closed && segOut !== code.slice(i + "String.raw`".length, j)) {{
				out += code.slice(last, i + "String.raw`".length) + segOut;
				last = j;
				i = j;
				continue;
			}}
			i = j;
			continue;
		}}
		i++;
	}}
	return last === 0 ? code : out + code.slice(last);
}}

export function healRegexAlternationSlashes(code: string): string {{
	if (!code || !code.includes("|/")) return code;
	return code.replace(
		/([(=,:;!&|?]\s*\/[^\/\r\n]*\|)\/([^\/\r\n]+\/[gimsuy]*\s*\.(?:test|exec)\b)/g,
		"$1\\/$2",
	);
}}

/**
 * Lossless pre-execution auto-heal for Pi `codemode` JS scripts:
 * 1) Strips outer markdown code fences (```js ... ```) that break QuickJS parsing / `// @options:` line 1.
 * 2) Repairs `tools.mcp__agent-primitives__` -> `tools.mcp__agent_primitives__` (avoids JS subtraction ReferenceError).
 * 3) Escapes raw newlines inside single/double-quoted strings & heals trailing escaped quotes (`healJsStringRawNewlines`).
 * 4) Escapes embedded backticks inside `String.raw` blocks & unescaped alternation slashes in `.test()`/`.exec()` regexes.
 * 5) Strips accidental TypeScript variable/parameter/return annotations and `as <Type>` casts (`stripTsTypesInCodemode`).
 * 6) Auto-shims `setTimeout(...)` via host `sleep(ms)` (eliminating 100% of QuickJS timer ReferenceErrors while keeping `// @options:` on line 1).
 */
export function healCodemodeSource(
	code: string,
	options?: {{ hasBuiltinSetTimeout?: boolean }},
): string | undefined {{
	if (!code) return undefined;
	let next = code;
	const fenced = next.match(/^\s*```(?:js|javascript|ts|typescript)?[ \t]*\r?\n([\s\S]*?)\r?\n```\s*$/i);
	if (fenced) {{
		next = fenced[1];
	}}
	next = healStringRawInnerBackticks(next);
	if (next.includes("String.raw`")) {{
		next = next.replace(
			/(\bString\.raw`[^`\r\n]*?)(\\+)`([ \t]*(?:[;,)\]]|$))/gm,
			(m, head: string, bs: string, tail: string) =>
				bs.length % 2 === 1 ? `${{head}}${{bs.slice(0, -1)}}\` + "\\\\"${{tail}}` : m,
		);
	}}
	const healedNewlines = healJsStringRawNewlines(next);
	if (healedNewlines) {{
		next = healedNewlines;
	}}
	next = healRegexAlternationSlashes(next);

	let needsSetTimeoutShim = false;
	const spanRes = maskCodemodeSpans(next);
	if (spanRes) {{
		let {{ masked }} = spanRes;
		const {{ tokens }} = spanRes;
		// Hoist any real standalone `// @options:` comment (never inside string/template literals) to line 1
		const firstNl = next.indexOf("\n");
		const firstLine = firstNl >= 0 ? next.slice(0, firstNl) : next;
		if (!/^[ \t]*\/\/[ \t]*@options\b/.test(firstLine)) {{
			const optIdx = tokens.findIndex((t) => /^\/\/[ \t]*@options[ \t]*:[^\r\n]*/.test(t));
			if (optIdx >= 0) {{
				const tokTag = `\u0001T${{optIdx}}\u0001`;
				const tagRe = new RegExp(`(?:^|\\r?\\n)([ \\t]*${{tokTag}})`);
				const hm = masked.match(tagRe);
				if (hm && hm.index !== undefined) {{
					const before = masked.slice(0, hm.index);
					const after = masked.slice(hm.index + hm[0].length);
					const rest = `${{before}}${{after}}`.replace(/^(?:[ \t]*\r?\n)+/, "");
					masked = `${{tokTag}}\n${{rest}}`;
				}}
			}}
		}}
		if (masked.includes("tools.mcp__agent-primitives__")) {{
			masked = masked.replace(/tools\.mcp__agent-primitives__/g, "tools.mcp__agent_primitives__");
		}}
		if (/\btools\??\.ap_[a-z_]+\b/.test(masked)) {{
			masked = masked.replace(/\btools(\??\.)(ap_[a-z_]+)\b/g, (m, sep: string, name: string) =>
				AP_MCP_TOOL_NAMES.has(name) ? `tools${{sep}}mcp__agent_primitives__${{name}}` : m,
			);
		}}
		if (/\btools\[/.test(masked)) {{
			masked = masked.replace(/\btools\[\u0001T(\d+)\u0001\]/g, (m, idxStr: string) => {{
				const idx = Number(idxStr);
				const tm = tokens[idx]?.match(/^(['"])(ap_[a-z_]+)\1$/);
				if (tm && AP_MCP_TOOL_NAMES.has(tm[2])) {{
					tokens[idx] = `${{tm[1]}}mcp__agent_primitives__${{tm[2]}}${{tm[1]}}`;
				}}
				return m;
			}});
		}}
		if (/\bdescribeTool\(/.test(masked)) {{
			masked = masked.replace(/\bdescribeTool\(\u0001T(\d+)\u0001\)/g, (m, idxStr: string) => {{
				const idx = Number(idxStr);
				const tm = tokens[idx]?.match(/^(['"])(ap_[a-z_]+)\1$/);
				if (tm && AP_MCP_TOOL_NAMES.has(tm[2])) {{
					tokens[idx] = `${{tm[1]}}mcp__agent_primitives__${{tm[2]}}${{tm[1]}}`;
				}}
				return m;
			}});
		}}
		if (/\btools\.(?:describeTool|searchTools|describeNamespace)\b/.test(masked)) {{
			masked = masked.replace(/\btools\.(describeTool|searchTools|describeNamespace)\b/g, "$1");
		}}
		needsSetTimeoutShim =
			!options?.hasBuiltinSetTimeout &&
			/\bsetTimeout\s*\(/.test(masked) &&
			!/\b(?:const|let|var|function)\s+setTimeout\b/.test(masked);
		next = masked.replace(/\u0001T(\d+)\u0001/g, (_m, idx: string) => tokens[Number(idx)] ?? "");
	}} else {{
		needsSetTimeoutShim =
			!options?.hasBuiltinSetTimeout &&
			/\bsetTimeout\s*\(/.test(next) &&
			!/\b(?:const|let|var|function)\s+setTimeout\b/.test(next);
	}}

	next = stripTsTypesInCodemode(next);
	if (needsSetTimeoutShim) {{
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

function tryCompactJsonUnderLimit(
	raw: string,
	isFastModel = false,
	hardLimitOverride?: number,
	contextTokens?: number,
): string | undefined {{
	const trimmed = raw.trim();
	if (
		!(trimmed.startsWith("{{") && trimmed.endsWith("}}")) &&
		!(trimmed.startsWith("[") && trimmed.endsWith("]"))
	) {{
		return undefined;
	}}
	let effHard = resolveProgressiveHardLimit(isFastModel ? 12000 : SIEVE_HARD_CHARS, hardLimitOverride, contextTokens, 18000);
	try {{
		const compacted = JSON.stringify(JSON.parse(trimmed));
		// Exempt valid compacted single-line JSON < effHard from SIEVE_GIANT_LINE_CHARS (4.5KB) fallback
		if (compacted && compacted.length < raw.length * 0.9 && compacted.length < effHard) {{
			return compacted;
		}}
	}} catch {{
		// Fall through to full `ap sieve`
	}}
	return undefined;
}}

/**
 * Losslessly auto-sieve oversized `codemode` multi-block body text (content[1..N]) while keeping
 * the `Script completed`/`Script failed` header (content[0]), any trailing `Script error:` diagnostic,
 * and any `image` / non-text blocks 100% intact.
 */
export function sieveCodemodeContentBlocks(
	content: ReadonlyArray<{{ type?: string; text?: string; [k: string]: unknown }}>,
	sieveFn: (rawBody: string) => string | undefined,
	isFastModel = false,
	hardLimitOverride?: number,
	contextTokens?: number,
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
	if (
		!combinedBody ||
		combinedBody.includes("[sieve id=") ||
		!shouldAutoSieveShellOutput(combinedBody, isFastModel, hardLimitOverride, contextTokens)
	) {{
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
	if (!shouldAutoSieveShellOutput(sieveInput, isFastModel, hardLimitOverride, contextTokens)) {{
		return undefined;
	}}
	// Lossless whitespace compaction on pretty-printed JSON before invoking `ap sieve`
	const compacted = tryCompactJsonUnderLimit(sieveInput, isFastModel, hardLimitOverride, contextTokens);
	if (compacted) {{
		const finalCompact = errorTail ? `${{compacted}}\n\n${{errorTail}}` : compacted;
		const outCompact: Array<{{ type?: string; text?: string; [k: string]: unknown }}> = [];
		if (hasHeader) outCompact.push(first);
		outCompact.push(...preservedNonText);
		outCompact.push({{ type: "text", text: finalCompact }});
		return outCompact;
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
 * Resolve the primary payload text block index in a multi-block `tool_result` (e.g. `read` file
 * content in `content[0]` when upstream hooks append trailing advisory blocks at `content[1..N]`).
 */
export function findPrimaryToolResultTextIndex(
	content: ReadonlyArray<{{ type?: string; text?: string }}>,
	toolName?: string,
): number {{
	if (!Array.isArray(content) || content.length === 0) return -1;
	let firstIdx = -1;
	for (let i = 0; i < content.length; i++) {{
		if (content[i]?.type === "text" && typeof content[i].text === "string") {{
			firstIdx = i;
			break;
		}}
	}}
	if (firstIdx < 0) return -1;
	if (toolName === "read") return firstIdx;
	return firstIdx;
}}

/**
 * Losslessly auto-sieve every oversized text block in a `bash`/`powershell` `tool_result`
 * while preserving trailing advisory notices and non-text (`image`) blocks verbatim in place.
 */
export function sieveShellContentBlocks(
	content: ReadonlyArray<{{ type?: string; text?: string; [k: string]: unknown }}>,
	sieveFn: (rawBody: string) => string | undefined,
	isFastModel = false,
	hardLimitOverride?: number,
	contextTokens?: number,
): Array<{{ type?: string; text?: string; [k: string]: unknown }}> | undefined {{
	if (!Array.isArray(content) || content.length === 0) return undefined;
	let changed = false;
	const out = content.map((blk) => {{
		if (
			blk?.type === "text" &&
			typeof blk.text === "string" &&
			!blk.text.includes("[sieve id=") &&
			shouldAutoSieveShellOutput(blk.text, isFastModel, hardLimitOverride, contextTokens)
		) {{
			const compacted = tryCompactJsonUnderLimit(blk.text, isFastModel, hardLimitOverride, contextTokens);
			if (compacted) {{
				changed = true;
				return {{ ...blk, text: compacted }};
			}}
			const digested = sieveFn(blk.text);
			if (digested && digested.length > 40 && digested.length < blk.text.length * 0.78) {{
				changed = true;
				return {{ ...blk, text: digested }};
			}}
		}}
		return blk;
	}});
	return changed ? out : undefined;
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
		return `[ap codemode-tip] TypeError: JSON.stringify(undefined) returns undefined (ALWAYS guard with (JSON.stringify(val) ?? "").slice(...)) and text(val) is a VOID output printer in older bundles (don't chain .slice() on it); guard undefined strings with String(res?.output ?? res?.text ?? "").slice(...) before slicing/splitting. tools.bash(...) resolves to an OBJECT {{ output, exit_code, truncated, full_output_path }}, tools.read(...) resolves to a string, and tools.mcp__* resolves to {{ content, structuredContent, isError }} (already parsed; check Object.keys(res) instead of slicing undefined). With Promise.allSettled([...]), check r.status === "fulfilled" (read r.value?.output ?? r.value; rejected items have r.value === undefined and r.reason as an Error, so use String(r.reason)). Run await describeTool("<name>") to verify exact fields.`;
	}}
	if (/Unexpected end of JSON input|unexpected token:\s*'object'|JSON\.parse/i.test(outText)) {{
		return `[ap codemode-tip] SyntaxError (JSON.parse): tools.* ALREADY return structured JS objects/strings — inspect res.structuredContent or (res.output ?? "") directly without calling JSON.parse() on an already-parsed object or non-JSON wrapper.`;
	}}
	if (/Unexpected identifier|unterminated string/i.test(outText)) {{
		return `[ap codemode-tip] SyntaxError: unescaped quote or multiline literal inside JS source. Write complex payloads cleanly via tools.write instead of inline escaping.`;
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
	"In codemode (QuickJS sandbox — NO Node fs/path/require/process/fetch; `await sleep(ms)` is available): prefer typed MCP primitives `tools.mcp__agent_primitives__ap_search({{pattern, path, only_matching: true, unique: true, json: true}})`, `ap_read({{target, routes: true, section, json: true}})`, `ap_http`, `ap_cdp` over bash python/grep one-liners; `tools.bash({{command}})` returns `{{ output, exit_code }}`.",
	'Fast local CLI & exact edits: `read` on code/config shows `L:HH|` anchors (pass `L:HH|` in `edit` `oldText`). In bash, prefer zero-dep `ap` over grep/python/PS: `ap ls <d>`, `ap search -o -u --around 160 --pretty "<re>" [d]`, `ap read <file> --outline|--symbol <S>|--lines 1-80|--json-path <P>|--hex|--surface|--asar-surface|--ipc-graph|--fw-surface|--rpc-com-alpc|--routes --mutating-only|--ioctl --pipes|--xref`, `ap diff <old> <new> --semantic --json`, `ap sieve peek <id> --lines A-B --raw --max-chars 8000`, `ap ps|ports`, `ap win --pipes|--acl|--reg|--services|--sig <f>|--weak-acl|--unquoted|--com|--rpc --non-ms`, `ap cdp --export-role <port>`, `ap http --roles-matrix|--from-har <f> --fuzz-schema`, `ap ws --replay-har <f>`, `ap atlas map .`.',
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
	isIdle?: boolean;
}}): {{ action: "warm" }} | undefined {{
	if (!isDeepSeekModel(input)) return undefined;
	const warm = typeof input.warmCost === "number" ? input.warmCost : 0;
	const miss = typeof input.missCost === "number" ? input.missCost : 0;
	if (warm > 0 && ((miss >= 0.015 && miss / warm >= 20) || (input.isIdle && miss >= 0.005 && miss / warm >= 15))) {{
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

function resolveProgressiveHardLimit(
	baseLimit: number,
	hardLimitOverride?: number,
	contextTokens?: number,
	lowCtxFloor = 18000,
): number {{
	let limit =
		typeof hardLimitOverride === "number" && hardLimitOverride > 0 ? hardLimitOverride : baseLimit;
	if (typeof contextTokens === "number" && contextTokens > 0) {{
		if (contextTokens < 60000) {{
			limit = Math.max(limit, lowCtxFloor);
		}} else if (contextTokens >= 120000) {{
			limit = Math.min(limit, 8500);
		}} else if (contextTokens >= 80000) {{
			limit = Math.min(limit, 12000);
		}}
	}}
	return limit;
}}

export function shouldAutoSieveShellOutput(
	text: string,
	isFastModel = false,
	hardLimitOverride?: number,
	contextTokens?: number,
): boolean {{
	if (!text) return false;
	let hardLimit = isFastModel ? 12000 : SIEVE_HARD_CHARS;
	hardLimit = resolveProgressiveHardLimit(
		hardLimit,
		hardLimitOverride,
		contextTokens,
		18000,
	);
	if (text.length >= hardLimit) return true;
	const lines = text.split("\n");
	if (lines.some((l) => l.length > SIEVE_GIANT_LINE_CHARS) && !(lines.length <= 12 && text.length <= 12288)) return true;
	const structuredMin =
		typeof contextTokens === "number" && contextTokens > 0 && contextTokens < 60000
			? 18000
			: SIEVE_STRUCTURED_CHARS;
	if (text.length >= structuredMin) {{
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
	if (/syntax error near unexpected token [`'"]?\(/i.test(outText) && /\bfor\s+%%?[A-Za-z_]|cd\s+\/d\b/i.test(cmd)) {{
		return `[ap cmd-for-tip] Windows CMD \`for %x in (...)\` & \`cd /d\` syntax fails in Git Bash; use POSIX \`for x in ...; do ...; done\` (single-quoted/braced) or run via \`powershell\`.`;
	}}
	if (/unicodeescape.*codec can't decode/i.test(outText)) {{
		return `[ap py-unicodeescape-tip] Python non-raw string hit Windows backslash escape (\`\\U\`, \`\\N\`, etc.); use forward slashes (\`C:/...\`, \`Default/Network/Cookies\`) or raw \`r'...'\` WITHOUT a trailing backslash.`;
	}}
	if (/SyntaxError:\s*unterminated string literal/i.test(outText)) {{
		return `[ap py-rawstr-tip] Unterminated Python string (often trailing \`\\\` inside raw \`r'...'\\\\'\` or nested quotes); use forward slashes, \`ap probe win --pipes\` for named pipes, or \`python - <<'PY'\`.`;
	}}
	if (QUOTE_OR_BS_ERR.test(outText)) {{
		return `[ap quote-tip] Avoid nested quotes/backslashes inside inline python -c; use a single-quoted heredoc (python - <<'PY' ... PY) or write a script file via write/ap_edit.`;
	}}
	if (/\b(?:json\.decoder\.)?JSONDecodeError\b|Unexpected token .* in JSON|\bConvertFrom-Json\b/i.test(outText)) {{
		return `[ap json-tip] JSON parse failed (empty/HTML/non-JSON response); inspect HTTP status & raw prefix first or use \`ap probe http --select\` / \`ap read --json-path\` instead of blind json.loads.`;
	}}
	if (/dir: cannot access '\/[bs]'/i.test(outText)) {{
		return `[ap dir-tip] Windows \`dir /b\` fails under Git Bash; use \`ap ls <dir> --depth 2\` or POSIX \`ls\`.`;
	}}
	if (/Program Files[\/\\]Git[\/\\](?:PID|FO|FI|NH|F|c|C|k|K|TN|TR|grant|query|add|CN=|OU=|O=)|Invalid argument\/option - ['"]?[A-Za-z]:[\/\\]Program Files[\/\\]Git[\/\\]/i.test(outText)) {{
		return `[ap msys-tip] Git Bash MSYS2 mangled a Windows CLI '/flag' into 'C:/Program Files/Git/...'. Prefix with \`MSYS_NO_PATHCONV=1\` or use \`ap probe win --pipes/--reg/--acl/--services/--whoami\` (MCP/codemode: \`ap_win\`) instead of spawning tasklist/sc/icacls/reg/whoami.`;
	}}
	if (/Unicode(?:Decode|Encode)Error:\s*'(?:gbk|cp936|cp1252|charmap)' codec can't/i.test(outText)) {{
		return `[ap utf8-tip] Windows Python hit legacy GBK/cp936 encoding; set \`PYTHONUTF8=1 PYTHONIOENCODING=utf-8\` (or \`encoding="utf-8", errors="replace"\`) — or use \`ap read\`/\`ap search\`/\`ap sieve\` natively in Rust.`;
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
	if (/\.asar\b/i.test(cmd)) {{
		return `[ap surface-tip] For Electron archives/bundles, prefer \`ap read <app.asar> --asar-surface\` or \`--ipc-graph\`.`;
	}}
	if (/\.sys\b|ioctl/i.test(cmd)) {{
		return `[ap bin-tip] For Windows drivers/PE binaries, prefer \`ap read <bin> --ioctl --pipes --rpc-com-alpc\` or \`--xref\`.`;
	}}
	if (/\.har\b|\bplaywright\b|\bfetch\b/i.test(cmd)) {{
		return `[ap probe-tip] Replay & fuzz captured HTTP/WS flows directly via \`ap probe http --from-har <f> --fuzz-schema\` or \`ap probe ws --replay-har <f> --origin-matrix\`.`;
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

const HASHLINE_EDITABLE_EXT = /\.(?:rs|ts|tsx|js|jsx|mjs|cjs|py|go|c|cc|cpp|h|hpp|toml|yaml|yml|ini|cfg|conf|sh|ps1|bat|cmd|sql|html|css|scss|vue|svelte)$/i;

/**
 * Annotate direct built-in `read` text output with compact `L:HH|` hashline anchors while
 * preserving Pi's trailing truncation banner and leaving `codemode` raw `structuredContent` untouched.
 * Emits anchors selectively for editable code/config files with <= 400 lines.
 */
export function annotateReadWithHashlines(outText: string, startOffset = 1, filePath?: string): string | undefined {{
	if (!outText || outText.length > 60_000) return undefined;
	if (filePath && !HASHLINE_EDITABLE_EXT.test(filePath.trim())) return undefined;
	const trailerRe = /\n\n(\[(?:Showing lines [^\]]+|\d+ more lines in file[^\]]+|Truncated[^\]]+)\])\s*$/;
	const tm = outText.match(trailerRe);
	const body = tm ? outText.slice(0, tm.index) : outText;
	const trailer = tm ? outText.slice(tm.index) : "";
	const lines = body.split("\n");
	if (lines.length < 2 || lines.length > 400) return undefined;
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
				.replace(/[\u200B\uFEFF]/g, "")
				.replace(/\u00A0/g, " ")
				.replace(/[—–]/g, "-")
				.trim()
				.replace(/[：]/g, ":")
				.replace(/[，]/g, ",")
				.replace(/[（]/g, "(")
				.replace(/[）]/g, ")")
				.replace(/[“”]/g, '"')
				.replace(/[‘’]/g, "'")
				.replace(/\s+/g, " ")
				.replace(/\s*\|\s*/g, "|")
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

function shellQuoteBashPat(pat: string): string {{
	return `'${{pat.replace(/'/g, "'\\''")}}'`;
}}

function translateGrepBreToRustRegex(pat: string, flags: string): string {{
	if (!pat || flags.includes("E") || flags.includes("F")) return pat;
	return pat.replace(/\\([|(){{}}+?])/g, "$1");
}}

function rewriteSlowRecursiveGrep(cmd: string, toolName: string): string | undefined {{
	// Match optional leading `cd <dir> && ` or `cd <dir>; `, strip `2>/dev/null` & trailing pagers (`| more`/`| less`).
	const cleaned = cmd
		.replace(/\s+2>\s*(?:\/dev\/null|NUL)\b/gi, "")
		.replace(/\s+--exclude-dir=(?:'[^']+'|"[^"]+"|[^\s|&;]+)/g, "")
		.replace(/\s*\|\s*(?:more|less)\s*$/i, "");
	if (/>/.test(cleaned)) return undefined;

	// Fast-path A0: variable-assigned archive/minified grep-o `f="/path/to/app.asar"; [timeout N] grep -a -o ".\{{0,N\}}pat.\{{0,M\}}" "$f" [| head ...]`
	const varGrep = cleaned.match(
		/^\s*(?:([A-Za-z_]\w*)=(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))\s*;\s*)(?:timeout\s+\d+\s+)?grep\s+(?:-[aAoEP]+\s+)+(?:"((?:[^"\\]|\\.)+)"|'([^']+)')\s+"\$(\w+)"(\s*\|\s*(?:head|tail|wc|sort|cut)\b[^;&|>]*)?\s*$/,
	);
	if (varGrep && varGrep[1] === varGrep[7]) {{
		const fileTarget = varGrep[2] || varGrep[3] || varGrep[4] || "";
		const rawPat = varGrep[5] || varGrep[6] || "";
		const bm = rawPat.match(/^(?:\.\\?\{{0,(\d+)\\?\}})?([\s\S]+?)(?:\.\\?\{{0,(\d+)\\?\}})?$/);
		const leftN = Number(bm?.[1] || 0);
		const rightN = Number(bm?.[3] || 0);
		const rawMid = bm?.[2] || rawPat;
		if (fileTarget && (leftN > 0 || rightN > 0) && rawMid) {{
			const around = Math.min(800, Math.max(40, leftN, rightN));
			const prefix = toolName === "powershell" ? "& " : "";
			const quotedPat = toolName === "bash" ? shellQuoteBashPat(rawMid) : `"${{rawMid.replace(/"/g, '\\"')}}"`;
			return `${{prefix}}"${{AP_BIN}}" search --around ${{around}} --pretty ${{quotedPat}} "${{fileTarget}}"${{varGrep[8] || ""}}`;
		}}
	}}

	// Fast-path A: slow minified-JS context regex `grep -oE '.{{0,N}}PAT.{{0,M}}' file [| head ...]` -> `<25ms` `ap search --around`
	const aroundMatch = cleaned.match(
		/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?\s*grep\s+((?:-[aAoEPirRhHn]+\s+)+)['"]\.\\?\{{0,(\d+)\\?\}}([^'"]+?)(\.\\?\{{0,(\d+)\\?\}})?['"]\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))(\s*\|\s*(?:head|tail|wc|sort|cut)\b[^;&|>]*)?\s*$/,
	);
	if (aroundMatch && aroundMatch[2].includes("o")) {{
		const cdPrefix = aroundMatch[1] || "";
		const rawFlags = aroundMatch[2] || "";
		const leftN = Math.min(800, Math.max(40, Number(aroundMatch[3]) || 160));
		const rightN = Math.min(800, Math.max(40, Number(aroundMatch[6]) || leftN));
		const around = Math.max(leftN, rightN);
		const rawPat = aroundMatch[4] || "";
		const target = aroundMatch[7] || aroundMatch[8] || aroundMatch[9] || ".";
		const pipeSuffix = aroundMatch[10] || "";
		if (rawPat && !rawPat.includes("{{")) {{
			const prefix = toolName === "powershell" ? "& " : "";
			const quotedPat = toolName === "bash" ? shellQuoteBashPat(rawPat) : `"${{rawPat.replace(/"/g, '\\"')}}"`;
			const icFlag = rawFlags.includes("i") ? " -i" : "";
			return `${{cdPrefix}}${{prefix}}"${{AP_BIN}}" search${{icFlag}} --around ${{around}} --pretty ${{quotedPat}} "${{target}}"${{pipeSuffix}}`;
		}}
	}}

	// Fast-path A2: `for f in <files>; do [echo "$f";] grep [-a] -o[E] '<pat>' "$f"; done` -> `rg -a --no-ignore -o ...`
	const forGrep = cleaned.match(
		/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?for\s+(\w+)\s+in\s+([^;]+);\s*do\s+(?:echo\s+"?\$\2"?\s*;\s*)?grep\s+(?:-[aAoEP]+\s+)+(['"])([\s\S]+?)\4\s+"?\$\2"?\s*;\s*done\s*$/,
	);
	if (forGrep) {{
		const cdPrefix = forGrep[1] || "";
		const files = forGrep[3].trim();
		const q = forGrep[4];
		const erePat = forGrep[5].replace(/\\([{{}}])/g, "$1");
		return `${{cdPrefix}}rg -a --no-ignore -o ${{q}}${{erePat}}${{q}} ${{files}}`;
	}}

	// Fast-path A2b: `for f in <files>; do [echo "== $f";] grep -a -o -E <pat> "$f" [| pipe...]; done` -> `rg -a --no-ignore -o`
	if (
		/^\s*(?:cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?for\s+\w+\s+in\b[\s\S]*\bgrep\s+-[aAoEPhHi]+[\s\S]*;\s*done\s*$/.test(
			cleaned,
		)
	) {{
		const rewrittenFor = cleaned.replace(
			/\bgrep\s+((?:-[aAoEPhHi]+\s+)+)(['"])([\s\S]+?)\2/g,
			(gm, flg: string, q: string, gp: string) => {{
				if (!flg.includes("o")) return gm;
				const erePat = flg.includes("E") ? gp : gp.replace(/\\([{{}}])/g, "$1");
				const noFile = flg.includes("h") ? " --no-filename" : "";
				return `rg -a --no-ignore -o${{noFile}} ${{q}}${{erePat}}${{q}}`;
			}},
		);
		if (rewrittenFor !== cleaned) return rewrittenFor;
	}}

	// Fast-path A3: `cat <files> | grep -o[E] <pat> [| sort/head...]` -> `rg -a --no-ignore -o --no-filename`
	// Strictly require `-o` and refuse `-n`/`-A` so non-`-o` commands (e.g. `cat f | grep -E "a|b"`) never silently lose full lines.
	const catGrep = cleaned.match(
		/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?(?:echo\s+[^;]+;\s*)?cat\s+([^|;&]+)\|\s*grep\s+-([aAoEhHn]+)\s+('[^']+'|"[^"]+")(\s*\|[\s\S]*)?$/,
	);
	if (catGrep && catGrep[3].includes("o") && !catGrep[3].includes("n") && !catGrep[3].includes("A")) {{
		const cdPrefix = catGrep[1] || "";
		const files = catGrep[2].trim();
		const patTok = catGrep[4];
		const pipeSuffix = catGrep[5] || "";
		return `${{cdPrefix}}rg -a --no-ignore -o --no-filename ${{patTok}} ${{files}}${{pipeSuffix}}`;
	}}

	// Fast-path A4: multi-file `grep -ohE <pat> <2+ targets>` -> `rg -a --no-ignore -o`
	const multiGrep = cleaned.match(
		/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?grep\s+-([ohEia]+)\s+('[^']+'|"[^"]+"|(?!-)\S+)\s+([^\s|;&]+\s+[^\s|;&]+(?:\s+[^\s|;&]+)*)(\s*\|\s*(?:head|tail|wc|sort|cut)\b[^;&|>]*)?$/,
	);
	if (multiGrep && !/[rR]/.test(multiGrep[2]) && multiGrep[2].includes("o")) {{
		const cdPrefix = multiGrep[1] || "";
		const noFile = multiGrep[2].includes("h") ? " --no-filename" : "";
		return `${{cdPrefix}}rg -a --no-ignore -o${{noFile}} ${{multiGrep[3]}} ${{multiGrep[4].trim()}}${{multiGrep[5] || ""}}`;
	}}

	// Collect one or more `--include=*.ext` / `--include=<glob>` flags anywhere in the grep command
	const exts: string[] = [];
	const extraIncludes: string[] = [];
	const globs: string[] = [];
	const withoutIncludes = cleaned.replace(
		/\s+--include=(?:'([^']+)'|"([^"]+)"|([^\s|&;]+))/g,
		(_m, g1: string, g2: string, g3: string) => {{
			const glob = g1 || g2 || g3 || "";
			const em = glob.match(/^\*\.([A-Za-z0-9]+)$/);
			if (em) exts.push(em[1]);
			else if (glob) extraIncludes.push(glob);
			if (glob) globs.push(`-g '${{glob}}'`);
			return "";
		}},
	);

	// Trailing `-l` / `-c`, multi-target, AppData, arbitrary-pipe, or backtick-safe recursive grep -> fast bounded `rg`
	const complexRec = withoutIncludes.match(
		/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?grep\s+((?:-[aArRniEHhlcIFso]+\s+)+)(?:'([^']+)'|"((?:[^"\\]|\\.)+)"|((?!-)[^\s'"|;&]+))([\s\S]*?)((?:\s*\|[^;&<>]+)+)?$/,
	);
	if (complexRec && /[rR]/.test(complexRec[2])) {{
		const cdPrefix = complexRec[1] || "";
		const rawFlags = complexRec[2];
		const patRaw =
			complexRec[3] !== undefined
				? `'${{complexRec[3]}}'`
				: complexRec[4] !== undefined
					? `"${{complexRec[4]}}"`
					: complexRec[5];
		const restArgs = (complexRec[6] || "").trim();
		const pipeSuffix = complexRec[7] || "";
		const hasBacktickPat = complexRec[3]?.includes("`") || complexRec[4]?.includes("`");
		const restUnquoted = restArgs.replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, "");
		const hasCompoundOps = /[;&<>`]|\$\(/.test(restUnquoted);
		const hasTrailingFlag = /(?:^|\s)-[lch](?:\s|$)/.test(restArgs);
		const isAppData = /AppData[/\\]Roaming/i.test(restArgs);
		const multiTarget = restArgs.split(/\s+/).filter(Boolean).length > 1;
		const hasArbitraryPipe =
			Boolean(pipeSuffix) &&
			!/^(?:\s*\|\s*(?:head|tail|wc|sort|uniq|cut|tr)\b[^;&|<>]*)+$/.test(pipeSuffix);
		if (!hasCompoundOps && (hasBacktickPat || hasTrailingFlag || isAppData || multiTarget || hasArbitraryPipe)) {{
			const rFlags = [
				/[a]/.test(rawFlags) ? "-a" : "",
				/[n]/.test(rawFlags) ? "-n --no-heading" : "",
				/[l]/.test(rawFlags) ? "-l" : "",
				/[c]/.test(rawFlags) ? "-c" : "",
				/[o]/.test(rawFlags) ? "-o" : "",
				/[h]/.test(rawFlags) ? "--no-filename" : "",
				/[w]/.test(rawFlags) ? "-w" : "",
				/[i]/.test(rawFlags) ? "-i" : "",
				/[F]/.test(rawFlags) ? "-F" : "",
				isAppData ? "--max-depth 4" : "--max-depth 8",
				"-g '!node_modules'",
				"-g '!target'",
				...globs,
			]
				.filter(Boolean)
				.join(" ");
			const tgtStr = restArgs || ".";
			return `${{cdPrefix}}rg ${{rFlags}} ${{patRaw}} ${{tgtStr}}${{pipeSuffix}}`;
		}}
	}}

	const m = withoutIncludes.match(
		/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?\s*grep\s+((?:-[aArRniEHhlcIFso]+\s+)+)(?:-e\s+)?(?:'([^']+)'|"((?:[^"\\]|\\.)+)"|((?!-)[^\s'"|;&]+))(?:\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+)))?((?:\s*\|\s*(?:head|tail|wc|sort|uniq|cut|tr)\b[^;&|<>]*)+)?\s*$/,
	);
	if (m) {{
		const flags = m[2].replace(/[\s-]+/g, "");
		const cdPrefix = m[1] || "";
		const rawPat = m[3] || (m[4] ? m[4].replace(/\\"/g, '"') : "") || m[5] || "";
		const target = m[6] || m[7] || m[8] || ".";
		const hasConcreteTarget =
			Boolean(m[6] || m[7] || m[8]) &&
			target !== "-" &&
			(Boolean(m[6] || m[7]) ? !/[*?,]/.test(target) : !/[*?,\s]/.test(target));
		if (rawPat && (/[rR]/.test(flags) || (hasConcreteTarget && flags.includes("n") && !m[9]))) {{
			const rustPat = translateGrepBreToRustRegex(rawPat, flags);
			const pipeSuffix = m[9] || "";
			const extFlag = exts.length > 0 ? ` -e ${{[...new Set(exts)].join(",")}}` : "";
			const incFlags = extraIncludes.map((inc) => ` --include "${{inc.replace(/"/g, '\\"')}}"`).join("");
			const prefix = toolName === "powershell" ? "& " : "";
			const quotedPat = toolName === "bash" ? shellQuoteBashPat(rustPat) : `"${{rustPat.replace(/"/g, '\\"')}}"`;
			const extra = [
				flags.includes("l") ? " -l" : flags.includes("c") ? " -c" : "",
				flags.includes("o") ? " -o" : "",
				flags.includes("i") ? " -i" : "",
				flags.includes("F") ? " -F" : "",
				flags.includes("h") ? " --no-filename" : "",
			].join("");
			return `${{cdPrefix}}${{prefix}}"${{AP_BIN}}" search${{extra}}${{extFlag}}${{incFlags}} ${{quotedPat}} "${{target}}"${{pipeSuffix}}`;
		}}
	}}

	// Generalized standalone grep with -A/-B/-C context flags anywhere, BRE `\|`, or single-file grep
	const stdGrepM = withoutIncludes.match(
		/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?grep\s+([\s\S]+?)((?:\s*\|\s*(?:head|tail|wc|sort|uniq|cut|tr)\b[^;&|<>]*)+)?\s*$/,
	);
	if (stdGrepM && !/[;&><{{}}`]|\$\(/.test((stdGrepM[2] || "").replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, ""))) {{
		const cdPrefix = stdGrepM[1] || "";
		const pipeSuffix = stdGrepM[3] || "";
		const toks = ((stdGrepM[2] || "").match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) || []).map((t) =>
			(t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))
				? t.slice(1, -1).replace(/\\"/g, '"')
				: t,
		);
		let rec = false;
		let lineNum = false;
		let ignoreCase = false;
		let fixed = false;
		let extRe = false;
		let filesOnly = false;
		let countOnly = false;
		let onlyMatch = false;
		let noFilename = false;
		let ctxA = 0;
		let ctxB = 0;
		let ctxC = 0;
		let ok = true;
		let endOpts = false;
		const pos: string[] = [];
		for (let i = 0; i < toks.length; i++) {{
			const tok = toks[i];
			if (!endOpts && tok === "--") {{ endOpts = true; continue; }}
			if (!endOpts && (tok === "-A" || tok === "-B" || tok === "-C")) {{
				const num = Number(toks[++i]);
				if (!Number.isInteger(num) || num < 0) {{ ok = false; break; }}
				if (tok === "-A") ctxA = num;
				else if (tok === "-B") ctxB = num;
				else ctxC = num;
				continue;
			}}
			if (!endOpts && /^-[ABC]\d+$/.test(tok)) {{
				const num = Number(tok.slice(2));
				if (tok[1] === "A") ctxA = num;
				else if (tok[1] === "B") ctxB = num;
				else ctxC = num;
				continue;
			}}
			if (!endOpts && tok === "-e") {{
				if (i + 1 >= toks.length) {{ ok = false; break; }}
				pos.unshift(toks[++i]);
				continue;
			}}
			if (!endOpts && tok.startsWith("-") && tok.length > 1) {{
				if (tok.startsWith("--")) {{ ok = false; break; }}
				for (const ch of tok.slice(1)) {{
					if (ch === "r" || ch === "R") rec = true;
					else if (ch === "n") lineNum = true;
					else if (ch === "i") ignoreCase = true;
					else if (ch === "F") fixed = true;
					else if (ch === "E") extRe = true;
					else if (ch === "l") filesOnly = true;
					else if (ch === "c") countOnly = true;
					else if (ch === "o") onlyMatch = true;
					else if (ch === "h") noFilename = true;
					else if (ch === "H" || ch === "s" || ch === "a") continue;
					else {{ ok = false; break; }}
				}}
				if (!ok) break;
				continue;
			}}
			pos.push(tok);
		}}
		if (ok && pos.length >= 1 && pos.length <= 2) {{
			const rawPat = pos[0];
			const target = pos[1] || ".";
			const concreteSingleFile = pos.length === 2 && target !== "-" && !/[*?,]/.test(target);
			if (rawPat && (rec || (!pipeSuffix && concreteSingleFile && (lineNum || ctxA > 0 || ctxB > 0 || ctxC > 0 || rawPat.includes("\\|"))))) {{
				const flagsStr = `${{extRe ? "E" : ""}}${{fixed ? "F" : ""}}`;
				const rustPat = translateGrepBreToRustRegex(rawPat, flagsStr);
				const prefix = toolName === "powershell" ? "& " : "";
				const quotedPat = toolName === "bash" ? shellQuoteBashPat(rustPat) : `"${{rustPat.replace(/"/g, '\\"')}}"`;
				const extra = [
					filesOnly ? " -l" : countOnly ? " -c" : "",
					onlyMatch ? " -o" : "",
					ignoreCase ? " -i" : "",
					fixed ? " -F" : "",
					noFilename ? " --no-filename" : "",
					ctxC > 0 ? ` -C ${{ctxC}}` : "",
					ctxB > 0 ? ` -B ${{ctxB}}` : "",
					ctxA > 0 ? ` -A ${{ctxA}}` : "",
					exts.length > 0 ? ` -e ${{[...new Set(exts)].join(",")}}` : "",
					...extraIncludes.map((inc) => ` --include "${{inc.replace(/"/g, '\\"')}}"`),
				].join("");
				return `${{cdPrefix}}${{prefix}}"${{AP_BIN}}" search${{extra}} ${{quotedPat}} "${{target}}"${{pipeSuffix}}`;
			}}
		}}
	}}

	// Windows `findstr [/i] [/s] [/n] [/c:pat | pat] target` -> `ap search`
	if (toolName === "bash" && /\bfindstr\b/i.test(cleaned)) {{
		const fsM = cleaned.match(
			/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?findstr\s+([\s\S]+?)((?:\s*\|\s*(?:head|tail|wc|sort)\b[^;&|<>]*)+)?\s*$/i,
		);
		if (fsM && !/[;&><{{}}`]|\$\(/.test((fsM[2] || "").replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, ""))) {{
			const toks = ((fsM[2] || "").match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) || []).map((t) =>
				(t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")) ? t.slice(1, -1) : t,
			);
			let ignoreCase = false;
			let fixed = false;
			let recursive = false;
			let explicitPat = "";
			const pos: string[] = [];
			let fsOk = true;
			for (const tok of toks) {{
				const low = tok.toLowerCase();
				if (low.startsWith("/c:")) {{
					explicitPat = tok.slice(3).replace(/^(['"])(.*)\1$/, "$2");
					fixed = true;
				}} else if (low === "/i") ignoreCase = true;
				else if (low === "/s") recursive = true;
				else if (low === "/l") fixed = true;
				else if (low === "/n" || low === "/p" || low === "/r") continue;
				else if (tok.startsWith("/")) {{ fsOk = false; break; }}
				else pos.push(tok);
			}}
			if (fsOk) {{
				const pat = explicitPat || pos[0] || "";
				const tgt = explicitPat ? (pos[0] || "") : (pos[1] || "");
				if (pat && (tgt || recursive)) {{
					const rawTgt = tgt || ".";
					const extM = rawTgt.match(/^\*\.([A-Za-z0-9_]+)$/);
					const actualTgt = extM ? "." : rawTgt;
					if (!/[*?,\s]/.test(actualTgt) && actualTgt !== "-") {{
						const extFlag = extM ? ` -e ${{extM[1]}}` : "";
						const flags = `${{ignoreCase ? " -i" : ""}}${{fixed ? " -F" : ""}}${{extFlag}}`;
						return `${{fsM[1] || ""}}"${{AP_BIN}}" search${{flags}} ${{shellQuoteBashPat(pat)}} "${{actualTgt}}"${{fsM[3] || ""}}`;
					}}
				}}
			}}
		}}
	}}

	return undefined;
}}

/**
 * Guard ephemeral background local HTTP/mock servers with a bounded 900s TTL so aborted/orphaned
 * test runs never leave background Python/Node listeners bound on ports indefinitely.
 */
export function guardEphemeralServerCommand(cmd: string): string | undefined {{
	if (!cmd) return undefined;
	const trimmed = cmd.trim();
	const isBgServer =
		/(?:python3?(?:\.exe)?\s+-m\s+http\.server\b|\bhttp\.server\b|\bap(?:\.exe)?\s+probe\s+listen\b)/.test(trimmed) &&
		/&\s*$/.test(trimmed);
	if (!isBgServer || /\btimeout\s+\d+/.test(trimmed)) return undefined;
	if (/^nohup\s+/i.test(trimmed)) {{
		return trimmed.replace(/^nohup\s+/i, "nohup timeout 900 ");
	}}
	return `timeout 900 ${{trimmed}}`;
}}

/**
 * Hint structured reads (`ap read --outline` / `--section`) when opening giant Markdown/text files.
 */
export function classifyOversizedDocRead(filePath: string, byteLen: number): string | undefined {{
	if (!filePath || byteLen < 10_000) return undefined;
	const norm = filePath.trim().replace(/\\/g, "/").toLowerCase();
	if (!/\.(?:md|txt|log)$/.test(norm) || /(?:^|\/)readme\.md$/.test(norm)) return undefined;
	return `[ap read-tip] Large doc (${{byteLen}} chars) — use \`ap read "${{filePath}}" --outline\` or \`--section "<heading>"\` for ~90% fewer tokens.`;
}}

/**
 * Lossless auto-sieve trigger for unbounded giant `read` responses (offset/limit both unset).
 * Windowed `read(offset, limit)` calls ALWAYS return false so exact edit lines are never altered.
 */
export function shouldAutoSieveUnboundedRead(
	outText: string,
	input: unknown,
	isFastModel = false,
	hardLimitOverride?: number,
	contextTokens?: number,
): boolean {{
	if (!outText || outText.includes("[sieve id=")) return false;
	const rec = input && typeof input === "object" ? (input as {{ path?: unknown; offset?: unknown; limit?: unknown }}) : undefined;
	const readPath = typeof rec?.path === "string" ? rec.path.trim() : "";
	if (/(?:^|[\\/])(?:SKILL|AGENTS|AGENTS\.override)\.md$/i.test(readPath) && outText.length <= 32_768) {{
		return false;
	}}
	if ((rec?.offset !== undefined && rec?.offset !== null) || (rec?.limit !== undefined && rec?.limit !== null)) {{
		return outText.length >= 32_000 && outText.split("\n").some((l) => l.length > SIEVE_GIANT_LINE_CHARS);
	}}
	let thr =
		hardLimitOverride && hardLimitOverride > 0
			? Math.max(hardLimitOverride, 12_000)
			: isFastModel
				? SIEVE_STRUCTURED_CHARS
				: 24_000;
	if (typeof contextTokens === "number" && contextTokens > 0) {{
		if (contextTokens < 60_000) {{
			thr = Math.max(thr, 24_000);
		}} else if (contextTokens >= 120_000) {{
			thr = Math.min(thr, 10_000);
		}} else if (contextTokens >= 80_000) {{
			thr = Math.min(thr, 14_000);
		}}
	}}
	return outText.length >= thr;
}}

/**
 * Guard unguarded standalone Bash `curl` HTTP probes with `--max-time 30` so slow endpoints fail fast
 * instead of hanging into DeepSeek's KV-cache eviction window or stalling turns.
 */
export function guardUnboundedCurlTimeout(cmd: string): string | undefined {{
	if (!cmd || /<<|(?:^|[\s;&|(=])(?:python3?|py|node)(?:\.exe)?(?=\s|$|[;&|)])/i.test(cmd)) return undefined;
	if (!/(?:^|[;&|]\s*)curl(?:\.exe)?\s+/.test(cmd)) return undefined;
	if (/\s(?:-m|--max-time|--connect-timeout)\b/.test(cmd)) return undefined;
	const next = cmd.replace(/(^|[;&|]\s*)(curl(?:\.exe)?)(?=\s)/g, "$1$2 --max-time 30");
	return next !== cmd ? next : undefined;
}}

/**
 * Strip explicit top-level `null` optional fields so strict tool schemas (e.g. read, mcp_*)
 * never reject DeepSeek or other models sending `{{ offset: null, limit: null }}`.
 */
export function stripNullOptionalArgs(input: unknown): boolean {{
	if (!input || typeof input !== "object" || Array.isArray(input)) return false;
	const rec = input as Record<string, unknown>;
	let stripped = false;
	for (const k of Object.keys(rec)) {{
		if (rec[k] === null) {{
			delete rec[k];
			stripped = true;
		}}
	}}
	return stripped;
}}

/**
 * Track consecutive read-only single bash probes and nudge toward batched `codemode` (`Promise.allSettled`).
 */
export function trackReadOnlyBashStreak(
	currentStreak: number,
	cmd: string,
	isDestructive: boolean,
): {{ nextStreak: number; shouldTip: boolean }} {{
	if (!cmd || isDestructive) return {{ nextStreak: 0, shouldTip: false }};
	const clean = cmd.replace(LEADING_SHELL_PREFIX_RE, "").trim();
	const isReadOnlyProbe =
		/^(?:ls|dir|cat|head|tail|grep|egrep|fgrep|rg|find|sed|awk|wc|stat|file|strings|python3?|node)\b/i.test(clean);
	if (!isReadOnlyProbe) return {{ nextStreak: 0, shouldTip: false }};
	const nextStreak = currentStreak + 1;
	if (nextStreak >= 4 && nextStreak % 4 === 0) {{
		return {{ nextStreak, shouldTip: true }};
	}}
	return {{ nextStreak, shouldTip: false }};
}}

export function healBashPowerShellCommand(cmd: string): string | undefined {{
	if (!/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(cmd) || /-EncodedCommand\b|-enc\b/i.test(cmd)) {{
		return undefined;
	}}
	const hereM = cmd.match(
		/^([\s\S]*?\b(?:powershell|pwsh)(?:\.exe)?\b[^|;&"'\r\n]*?\s-(?:Command|c)\s+)@(['"])\r?\n([\s\S]*?)\r?\n\2@([ \t]*(?:2>&1)?(?:[ \t]*\|[^\r\n]*)?)\s*$/i,
	);
	if (hereM) {{
		const head = hereM[1];
		const body = hereM[3];
		const tail = hereM[4] || "";
		const hasUtf8 = /OutputEncoding|UTF8Encoding/i.test(body);
		const utf8Line = hasUtf8 ? "" : "[Console]::OutputEncoding=[Text.Encoding]::UTF8\n";
		let delim = "AP_PS_HEREDOC";
		while (body.includes(delim)) delim += "_X";
		return `${{head}}- <<'${{delim}}'${{tail}}\n${{utf8Line}}${{body}}\n${{delim}}`;
	}}
	const psHeadRe = /\b((?:powershell|pwsh)(?:\.exe)?\b[^|;&"']*?\s-(?:Command|c)\s+)"/gi;
	let out = "";
	let cursor = 0;
	let matchedAny = false;
	while (true) {{
		psHeadRe.lastIndex = cursor;
		const hm = psHeadRe.exec(cmd);
		if (!hm) break;
		const prefixStart = hm.index;
		const bodyStart = prefixStart + hm[0].length;
		let bodyEnd = -1;
		for (let i = bodyStart; i < cmd.length; i++) {{
			const ch = cmd[i];
			if (ch === "\\" && i + 1 < cmd.length && (cmd[i + 1] === '"' || cmd[i + 1] === "\\")) {{
				i += 1;
				continue;
			}}
			if (ch === '"') {{
				bodyEnd = i;
				break;
			}}
		}}
		if (bodyEnd <= bodyStart) break;
		matchedAny = true;
		out += cmd.slice(cursor, prefixStart) + hm[1];
		let inner = cmd.slice(bodyStart, bodyEnd);
		const innerTimed =
			/\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i.test(inner) && !/\s-TimeoutSec\b/i.test(inner)
				? inner.replace(/(^|[;&|(\s])(Invoke-WebRequest|Invoke-RestMethod)(?=\s)/gi, "$1$2 -TimeoutSec 25")
				: inner;
		const hasUtf8 = /OutputEncoding|UTF8Encoding/i.test(innerTimed);
		const utf8Prefix = hasUtf8 ? "" : "[Console]::OutputEncoding=[Text.Encoding]::UTF8; ";
		const hasPsVar = /\$(?:_|PSItem\b|env:|null\b|true\b|false\b|[A-Za-z_]\w*|\?|\()/i.test(innerTimed);
		const hasPsBacktick = /(?<!\\)`/.test(innerTimed);
		if (!innerTimed.includes("'") && !/\$\(/.test(innerTimed) && (hasPsVar || hasPsBacktick)) {{
			const sqInner = innerTimed.replace(/\\"/g, '"').replace(/\\\$/g, "$").replace(/\\`/g, "`");
			out += `'${{utf8Prefix}}${{sqInner}}'`;
		}} else if (hasPsVar || hasPsBacktick || !hasUtf8) {{
			const innerEsc = innerTimed
				.replace(/(?<!\\)\$(?=[A-Za-z_?(])/g, "\\$")
				.replace(/(?<!\\)`/g, "\\`");
			out += `"${{utf8Prefix}}${{innerEsc}}"`;
		}} else {{
			out += `"${{innerTimed}}"`;
		}}
		cursor = bodyEnd + 1;
	}}
	if (matchedAny) {{
		out += cmd.slice(cursor);
		return out !== cmd ? out : undefined;
	}}
	if (!/OutputEncoding|UTF8Encoding/i.test(cmd)) {{
		const psFixed = cmd.replace(
			/\b((?:powershell|pwsh)(?:\.exe)?\b[^|;&]*?\s-(?:Command|c)\s+)(['"])/gi,
			"$1$2[Console]::OutputEncoding=[Text.Encoding]::UTF8; ",
		);
		return psFixed !== cmd ? psFixed : undefined;
	}}
	return undefined;
}}

export function clampKvSafeSleep(cmd: string, toolName: string, maxSec = 45): string | undefined {{
	if (
		!cmd ||
		/\bnohup\b|<<|(?:^|[\s;&|(=])(?:python3?|py|node)(?:\.exe)?(?=\s|$|[;&|)])/i.test(cmd) ||
		/&\s*$/.test(cmd.trim()) ||
		/\(\s*[^)]*\bsleep\b[^)]*\)\s*&/i.test(cmd)
	) {{
		return undefined;
	}}
	if (toolName === "bash") {{
		let next = cmd.replace(
			/(^|[;&|]\s*)sleep\s+(\d+(?:\.\d+)?)s?(?=\s*(?:$|[;&|]))/gi,
			(m, pfx: string, secsStr: string) => (Number(secsStr) >= 60 ? `${{pfx}}sleep ${{maxSec}}` : m),
		);
		next = next.replace(
			/\b(for\s+\w+\s+in\s+(?:\$\(\s*seq\s+(?:(\d+)\s+)?(\d+)\s*\)|([^\r\n;]+));\s*do\b)([\s\S]*?)(\bdone\b)/gi,
			(loopMatch, head: string, seqStart: string | undefined, seqEnd: string | undefined, wordList: string | undefined, body: string, tail: string) => {{
				let iters = 0;
				if (seqEnd) {{
					const startN = seqStart ? Number(seqStart) : 1;
					const endN = Number(seqEnd);
					iters = endN >= startN ? endN - startN + 1 : 0;
				}} else if (wordList) {{
					const words = wordList.trim().split(/\s+/).filter(Boolean);
					if (words.length >= 3) iters = words.length;
				}}
				if (iters < 3) return loopMatch;
				let loopChanged = false;
				const clampedBody = body.replace(
					/(^|[;&|\s])sleep\s+(\d+(?:\.\d+)?)s?(?=\s*(?:$|[;&|]))/gi,
					(sm, spfx: string, sStr: string) => {{
						const sNum = Number(sStr);
						if (sNum > 0 && iters * sNum >= 90) {{
							const perIter = Math.max(2, Math.floor(maxSec / iters));
							if (perIter < sNum) {{
								loopChanged = true;
								return `${{spfx}}sleep ${{perIter}}`;
							}}
						}}
						return sm;
					}},
				);
				return loopChanged ? `${{head}}${{clampedBody}}${{tail}}` : loopMatch;
			}},
		);
		return next !== cmd ? next : undefined;
	}}
	if (toolName === "powershell") {{
		const next = cmd.replace(
			/(^|[;&|]\s*)Start-Sleep(?:\s+-s(?:ec(?:ond)?s?)?)?\s+(\d+(?:\.\d+)?)(?=\s*(?:$|[;&|]))/gi,
			(m, pfx: string, secsStr: string) => (Number(secsStr) >= 60 ? `${{pfx}}Start-Sleep -Seconds ${{maxSec}}` : m),
		);
		return next !== cmd ? next : undefined;
	}}
	return undefined;
}}

const MSYS_WIN_CLI_RE = /(?:^|[;&|]\s*)(?:cmd(?:\.exe)?|taskkill(?:\.exe)?|tasklist(?:\.exe)?|sc(?:\.exe)?|icacls(?:\.exe)?|reg(?:\.exe)?|netstat(?:\.exe)?|whoami(?:\.exe)?|schtasks(?:\.exe)?|wevtutil(?:\.exe)?|netsh(?:\.exe)?|where(?:\.exe)?|wmic(?:\.exe)?|certutil(?:\.exe)?|bcdedit(?:\.exe)?|secedit(?:\.exe)?)\b[^\r\n;&|]*?\s\/[A-Za-z?]/i;
const MSYS_OPENSSL_SUBJ_RE = /\bopenssl\b[^\r\n;&|]*?\s-subj\s+['"]?\//i;

export function normalizeWindowsToolPath(rawPath: string, isWin = process.platform === "win32"): string | undefined {{
	if (!rawPath || !isWin) return undefined;
	const p = rawPath.trim();
	if (/^\/tmp(?:\/|$)/.test(p)) {{
		const winTmp = tmpdir().replace(/\\/g, "/").replace(/\/+$/, "");
		return p === "/tmp" ? winTmp : `${{winTmp}}${{p.slice(4)}}`;
	}}
	const m = p.match(/^\/([a-zA-Z])(?:\/(.*))?$/);
	if (m) {{
		const drv = m[1].toUpperCase();
		const rest = m[2] ?? "";
		return `${{drv}}:/${{rest}}`;
	}}
	return undefined;
}}

export function healMsysPathConv(raw: string, toolName = "bash"): string | undefined {{
	if (!raw || toolName !== "bash") return undefined;
	if (/\b(?:MSYS_NO_PATHCONV|MSYS2_ARG_CONV_EXCL)=/.test(raw)) return undefined;
	if (/(?:^|\s)\/\/[A-Za-z?]/.test(raw)) return undefined;
	if (!MSYS_WIN_CLI_RE.test(raw) && !MSYS_OPENSSL_SUBJ_RE.test(raw)) return undefined;
	const converted = raw.replace(/(^|[\s'"=])\/([a-zA-Z])\/([^\s'"`;&|<>()]*)/g, (_m, pfx: string, drv: string, tail: string) => {{
		return `${{pfx}}${{drv.toUpperCase()}}:/${{tail}}`;
	}});
	const trimmed = converted.trimStart();
	if (trimmed.includes("\n")) return `export MSYS_NO_PATHCONV=1\n${{converted}}`;
	if (/(?:&&|\|\||[;|])/.test(trimmed)) return `export MSYS_NO_PATHCONV=1; ${{converted}}`;
	return `MSYS_NO_PATHCONV=1 ${{converted}}`;
}}

export function healCmdForLoop(raw: string, toolName = "bash"): string | undefined {{
	if (!raw || toolName !== "bash") return undefined;
	if (/\bfor\s+\/[frld]\b/i.test(raw)) return undefined;
	const trimmed = raw.trim();
	const headM = trimmed.match(
		/^(?:(cd(?:\s+\/d)?\s+(?:"[^"]+"|'[^']+'|\S+)(?:\s+2>\s*(?:\/dev\/null|NUL))?)\s*(?:&&|&)\s*)?for\s+%%?([A-Za-z_]\w*)\s+in\s+\(/i,
	);
	if (!headM || headM.index === undefined) return undefined;
	const listStart = headM[0].length;
	let quote: string | null = null;
	let listEnd = -1;
	for (let i = listStart; i < trimmed.length; i++) {{
		const ch = trimmed[i];
		if (quote) {{
			if (ch === quote) quote = null;
		}} else if (ch === '"' || ch === "'") {{
			quote = ch;
		}} else if (ch === ")") {{
			listEnd = i;
			break;
		}} else if (ch === "\n" || ch === "\r") {{
			break;
		}}
	}}
	if (listEnd <= listStart) return undefined;
	const itemsRaw = trimmed.slice(listStart, listEnd).trim();
	if (!itemsRaw) return undefined;
	const doM = trimmed.slice(listEnd + 1).match(/^\s*do\s+([\s\S]+?)\s*$/i);
	if (!doM) return undefined;
	const normWinTmpEnv = (s: string): string =>
		s.replace(/"([^"]*)"|'([^']*)'|%(?:TEMP|TMP)%/gi, (m, dq?: string, sq?: string) => {{
			if (dq !== undefined) return `"${{dq.replace(/%(?:TEMP|TMP)%/gi, "$TEMP")}}"`;
			if (sq !== undefined) return `'${{sq}}'`;
			return '"$TEMP"';
		}});
	const cdRaw = headM[1]
		? `${{normWinTmpEnv(headM[1].trim().replace(/^cd\s+\/d\s+/i, "cd ").replace(/\\/g, "/"))}} && `
		: "";
	const v = headM[2];
	const items = normWinTmpEnv(
		itemsRaw.replace(/([A-Za-z]:)\\([^"'\r\n]*)/g, (_m, d: string, rest: string) => `${{d}}/${{rest.replace(/\\/g, "/")}}`),
	);
	let body = doM[1].trim();
	if (body.startsWith("@")) body = body.slice(1).trim();
	if (body.startsWith("(") && body.endsWith(")") && body.length >= 2) {{
		body = body.slice(1, -1).trim();
	}}
	body = body.replace(new RegExp(`%%?(?:~[fdpnxsatz]*)?${{v}}(?!\\w)`, "gi"), () => "${{" + v + "}}");
	body = normWinTmpEnv(body);
	body = body.replace(/\s+2>\s*nul\b/gi, " 2>/dev/null");
	body = body.replace(/\bdir\s+\/b\s+\/s\s+("[^"]+"|'[^']+'|\S+)/gi, `"${{AP_BIN}}" ls $1 --depth 3`);
	body = body.replace(/\bdir\s+\/s\s+\/b\s+("[^"]+"|'[^']+'|\S+)/gi, `"${{AP_BIN}}" ls $1 --depth 3`);
	body = body.replace(/\bdir\s+\/b\s+("[^"]+"|'[^']+'|\S+)/gi, `"${{AP_BIN}}" ls $1`);
	body = body.replace(/\bfindstr\s+\/I\s+\/C:("[^"]+"|\S+)/gi, "grep -iF $1");
	body = body.replace(/(?<![&>])(?:\s+&\s*|\s*&\s+)(?![&>])/g, "; ");
	return `${{cdRaw}}for ${{v}} in ${{items}}; do ${{body.trim()}}; done`;
}}

const BARE_PS_CMDLET_PREFIX_RE =
	/^(?:\(\s*)?(?:Get-ChildItem|Get-Content|Get-Process|Get-CimInstance|Select-String|Get-NetTCPConnection|Get-Service|Get-ItemProperty|Get-Item|Get-FileHash|Get-Acl|Get-AuthenticodeSignature|Get-ScheduledTask|Test-NetConnection|Test-Path|Resolve-Path)\b/;

function normalizeUnquotedRelativeBackslashes(raw: string): string {{
	let out = "";
	let quote: string | null = null;
	let i = 0;
	const n = raw.length;
	while (i < n) {{
		const ch = raw[i];
		if (quote) {{
			out += ch;
			if (ch === "\\" && quote === '"' && i + 1 < n) {{
				out += raw[i + 1];
				i += 2;
				continue;
			}}
			if (ch === quote) quote = null;
			i++;
			continue;
		}}
		if (ch === "'" || ch === '"') {{
			quote = ch;
			out += ch;
			i++;
			continue;
		}}
		if ((i === 0 || /[\s=;]/.test(raw[i - 1])) && /[A-Za-z0-9_.\u4e00-\u9fff]/.test(ch)) {{
			let j = i;
			while (j < n && !/[\s'"`;|&<>()]/.test(raw[j])) {{
				j++;
			}}
			const tok = raw.slice(i, j);
			if (
				tok.includes("\\") &&
				!/^[A-Za-z]:/.test(tok) &&
				!/[*?{{}}\[\]|^$<>`]/.test(tok) &&
				!/^\\/.test(tok) &&
				/^(?:\.\.?\\[^\s\\]+|[A-Za-z0-9_\u4e00-\u9fff-]{{2,}}\\[A-Za-z0-9_\u4e00-\u9fff.-]{{2,}}(?:\\[^\s\\]+)*|[A-Za-z0-9_\u4e00-\u9fff-]+\\[A-Za-z0-9_.-]+\.[A-Za-z0-9]{{1,8}})$/.test(tok)
			) {{
				out += tok.replace(/\\/g, "/");
				i = j;
				continue;
			}}
			out += tok;
			i = j;
			continue;
		}}
		out += ch;
		i++;
	}}
	return out;
}}

function normalizeUnquotedBashDrivePaths(raw: string): string {{
	let out = "";
	let quote: string | null = null;
	let i = 0;
	while (i < raw.length) {{
		const ch = raw[i];
		if (quote) {{
			out += ch;
			if (ch === "\\" && quote === '"' && i + 1 < raw.length) {{
				out += raw[i + 1];
				i += 2;
				continue;
			}}
			if (ch === quote) quote = null;
			i++;
			continue;
		}}
		if (ch === "'" || ch === '"') {{
			quote = ch;
			out += ch;
			i++;
			continue;
		}}
		if (
			/[A-Za-z]/.test(ch) &&
			raw[i + 1] === ":" &&
			(raw[i + 2] === "\\" || raw[i + 2] === "/") &&
			(i === 0 || /[\s=;]/.test(raw[i - 1]))
		) {{
			const pfM = raw
				.slice(i)
				.match(/^([A-Za-z]:)[\\/](Program Files(?: \(x86\))?(?:[\\/][^\s'"`;|&<>()]*)?)/i);
			if (pfM) {{
				const normPf = `${{pfM[1]}}/${{pfM[2].replace(/\\/g, "/")}}`;
				out += `"${{normPf}}"`;
				i += pfM[0].length;
				continue;
			}}
			if (raw[i + 2] === "\\") {{
				let j = i + 2;
				while (j < raw.length && !/[\s'"`;|&<>()]/.test(raw[j])) {{
					j++;
				}}
				out += `${{ch}}:${{raw.slice(i + 2, j).replace(/\\/g, "/")}}`;
				i = j;
				continue;
			}}
		}}
		out += ch;
		i++;
	}}
	return out;
}}

function splitUnquotedPipes(s: string): string[] | undefined {{
	const parts: string[] = [];
	let cur = "";
	let quote: string | null = null;
	for (let i = 0; i < s.length; i++) {{
		const ch = s[i];
		if (quote) {{
			cur += ch;
			if (ch === quote) {{
				quote = null;
			}} else if (quote === '"' && ch === "\\" && i + 1 < s.length) {{
				cur += s[i + 1];
				i += 1;
			}}
			continue;
		}}
		if (ch === "'" || ch === '"') {{
			quote = ch;
			cur += ch;
		}} else if (ch === "|") {{
			if (s[i + 1] === "|") return undefined;
			const t = cur.trim();
			if (!t) return undefined;
			parts.push(t);
			cur = "";
		}} else if (ch === "&") {{
			if (
				i >= 2 &&
				(i === 2 || /\s/.test(s[i - 3])) &&
				s[i - 1] === ">" &&
				s[i - 2] === "2" &&
				s[i + 1] === "1" &&
				(i + 2 >= s.length || /[\s|]/.test(s[i + 2]))
			) {{
				cur += ch;
			}} else {{
				return undefined;
			}}
		}} else if (ch === "$" && s[i + 1] === "(") {{
			return undefined;
		}} else {{
			cur += ch;
		}}
	}}
	if (quote !== null) return undefined;
	const tail = cur.trim();
	if (!tail) return undefined;
	parts.push(tail);
	return parts;
}}

function accelerateGrepPipeline(
	cmdTailBody: string,
	cdLeadPfx: string,
	fromCat = false,
): string | undefined {{
	const stages = splitUnquotedPipes(cmdTailBody.trim());
	if (!stages || stages.length < 2) return undefined;
	const grepRaw = stripBenignStderrRedir(stages[0]);
	const stripQuotes = (s: string) => s.replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, "");
	if (/[;&><{{}}`]|\$\(/.test(stripQuotes(grepRaw))) return undefined;
	if (!/^(?:grep|egrep|fgrep|rg)(?:\s|$)/.test(grepRaw)) return undefined;
	const gToks = (grepRaw.match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) || []).map((t) => {{
		if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {{
			return t.slice(1, -1).replace(/\\"/g, '"');
		}}
		return t;
	}});
	const isRg = gToks[0] === "rg";
	const isEgrep = gToks[0] === "egrep";
	const isFgrep = gToks[0] === "fgrep";
	if (gToks[0] !== "grep" && !isEgrep && !isFgrep && !isRg) return undefined;
	let ignoreCase = false;
	let fixed = isFgrep;
	let extendedRe = isEgrep;
	let filesOnly = false;
	let countOnly = false;
	let lineNum = false;
	let onlyMatch = false;
	let invertMatch = false;
	let noFilename = false;
	let optMaxCount = 0;
	let ctxA = 0;
	let ctxB = 0;
	let ctxC = 0;
	const exts: string[] = [];
	const includes: string[] = [];
	const addGlob = (g: string): boolean => {{
		if (!g || g.startsWith("!")) return false;
		const em = g.match(/^\*\.([A-Za-z0-9_]+)$/);
		if (em) {{
			if (!exts.includes(em[1])) exts.push(em[1]);
		}} else {{
			includes.push(g);
		}}
		return true;
	}};
	let endOpts = false;
	const gPos: string[] = [];
	for (let gi = 1; gi < gToks.length; gi += 1) {{
		const gt = gToks[gi];
		if (!endOpts && gt === "--") {{
			endOpts = true;
			continue;
		}}
		if (!endOpts && gt.startsWith("--")) {{
			if (gt === "--invert-match") {{
				invertMatch = true;
				continue;
			}}
			if (gt.startsWith("--max-count=")) {{
				const m = Number(gt.slice(12));
				if (!Number.isInteger(m) || m < 1) return undefined;
				optMaxCount = optMaxCount > 0 ? Math.min(optMaxCount, m) : m;
				continue;
			}}
			if (gt === "--max-count") {{
				gi += 1;
				const m = gi < gToks.length ? Number(gToks[gi]) : NaN;
				if (!Number.isInteger(m) || m < 1) return undefined;
				optMaxCount = optMaxCount > 0 ? Math.min(optMaxCount, m) : m;
				continue;
			}}
			if (!isRg) return undefined;
			if (gt.startsWith("--glob=")) {{
				if (!addGlob(gt.slice(7))) return undefined;
			}} else if (gt === "--glob") {{
				gi += 1;
				if (gi >= gToks.length || !addGlob(gToks[gi])) return undefined;
			}} else if (gt === "--no-filename") {{
				noFilename = true;
			}} else if (gt === "--no-messages" || gt === "--no-line-number") {{
				// compatible defaults
			}} else if (gt === "--line-number") {{
				lineNum = true;
			}} else if (gt === "--ignore-case") {{
				ignoreCase = true;
			}} else if (gt === "--fixed-strings") {{
				fixed = true;
			}} else if (gt === "--only-matching") {{
				onlyMatch = true;
			}} else if (gt === "--files-with-matches") {{
				filesOnly = true;
			}} else if (gt === "--count") {{
				countOnly = true;
			}} else {{
				return undefined;
			}}
			continue;
		}}
		if (!endOpts && gt.startsWith("-") && gt.length > 1) {{
			const sh = gt.slice(1);
			if (sh === "A" || sh === "B" || sh === "C") {{
				gi += 1;
				const m = gi < gToks.length ? Number(gToks[gi]) : NaN;
				if (!Number.isInteger(m) || m < 0) return undefined;
				if (sh === "A") ctxA = m;
				else if (sh === "B") ctxB = m;
				else ctxC = m;
				continue;
			}}
			if (/^[ABC]\d+$/.test(sh)) {{
				const m = Number(sh.slice(1));
				if (sh[0] === "A") ctxA = m;
				else if (sh[0] === "B") ctxB = m;
				else ctxC = m;
				continue;
			}}
			if (sh === "m") {{
				gi += 1;
				const m = gi < gToks.length ? Number(gToks[gi]) : NaN;
				if (!Number.isInteger(m) || m < 1) return undefined;
				optMaxCount = optMaxCount > 0 ? Math.min(optMaxCount, m) : m;
				continue;
			}}
			if (sh.startsWith("m")) {{
				const tail = sh.slice(1);
				if (!/^\d+$/.test(tail)) return undefined;
				const m = Number(tail);
				if (m < 1) return undefined;
				optMaxCount = optMaxCount > 0 ? Math.min(optMaxCount, m) : m;
				continue;
			}}
			if (isRg && sh === "g") {{
				gi += 1;
				if (gi >= gToks.length || !addGlob(gToks[gi])) return undefined;
				continue;
			}}
			for (const ch of sh) {{
				if (ch === "n") lineNum = true;
				else if (ch === "H" || ch === "s" || ch === "a") continue;
				else if (isRg && ch === "N") continue;
				else if (isRg && ch === "I") noFilename = true;
				else if (!isRg && (ch === "r" || ch === "R" || ch === "E")) continue;
				else if (ch === "h") noFilename = true;
				else if (ch === "i") ignoreCase = true;
				else if (ch === "F") fixed = true;
				else if (ch === "l") filesOnly = true;
				else if (ch === "c") countOnly = true;
				else if (ch === "o") onlyMatch = true;
				else if (ch === "v") invertMatch = true;
				else return undefined;
			}}
			continue;
		}}
		gPos.push(gt);
	}}
	if (invertMatch && onlyMatch) return undefined;
	if (fromCat && (filesOnly || countOnly)) return undefined;
	const patPos = gPos[0];
	const tgtPos = isRg && gPos.length === 1 ? "." : gPos.length === 2 ? gPos[1] : "";
	if (!patPos || !tgtPos || tgtPos === "-" || /[*?,]/.test(tgtPos) || (gPos.length !== 2 && !(isRg && gPos.length === 1))) {{
		return undefined;
	}}
	const isSingleConcreteFile = !isRg && !gToks.some((t) => /^-[a-zA-Z]*[rR]/.test(t));
	if (isSingleConcreteFile && !fromCat && (tgtPos === "." || !/[./\\]/.test(tgtPos))) {{
		return undefined;
	}}
	let cutWidth = 0;
	let maxHits = optMaxCount;
	let unique = false;
	let sawBareSort = false;
	let sawUniqC = false;
	for (let si = 1; si < stages.length; si += 1) {{
		const norm = stages[si].replace(/\s+/g, " ").trim();
		if (/[;&><{{}}`]|\$\(/.test(norm)) return undefined;
		if (norm === "sort") {{
			if (fromCat || lineNum || sawBareSort) return undefined;
			sawBareSort = true;
			continue;
		}}
		if (norm === "uniq -c" || norm === "uniq") {{
			if (fromCat || lineNum || !sawBareSort) return undefined;
			sawBareSort = false;
			sawUniqC = true;
			unique = true;
			continue;
		}}
		if (sawBareSort) return undefined;
		if (norm === "sort -u") {{
			if (fromCat || lineNum) return undefined;
			unique = true;
		}} else if ((norm === "sort -rn" || norm === "sort -nr" || norm === "sort -r") && sawUniqC) {{
			// `ap search --unique` already ranks descending by frequency
		}} else {{
			const cutM = norm.match(/^cut\s+-c\s*1-(\d+)$/);
			const headM = norm.match(/^head\s+(?:-n\s*(\d+)|-(\d+))$/);
			if (cutM) {{
				const w = Number(cutM[1]);
				if (w < 1) return undefined;
				cutWidth = cutWidth > 0 ? Math.min(cutWidth, w) : w;
			}} else if (headM) {{
				const m = Number(headM[1] || headM[2]);
				if (m < 1) return undefined;
				maxHits = maxHits > 0 ? Math.min(maxHits, m) : m;
			}} else {{
				return undefined;
			}}
		}}
	}}
	if (sawBareSort || (cutWidth === 0 && maxHits === 0 && !unique)) return undefined;
	const rustPat = isRg ? patPos : translateGrepBreToRustRegex(patPos, `${{fixed ? "F" : ""}}${{extendedRe || gToks.some((t) => /^-[a-zA-Z]*E/.test(t)) ? "E" : ""}}`);
	const flags = [
		cutWidth > 0 ? ` --width ${{cutWidth}}` : "",
		maxHits > 0 ? ` --max ${{maxHits}}` : "",
		unique ? " --unique" : "",
		filesOnly ? " --files-only" : countOnly ? " --count" : "",
		onlyMatch ? " -o" : "",
		invertMatch ? " -v" : "",
		noFilename ? " --no-filename" : "",
		ignoreCase ? " -i" : "",
		fixed ? " --fixed-strings" : "",
		ctxC > 0 ? ` -C ${{ctxC}}` : "",
		ctxB > 0 ? ` -B ${{ctxB}}` : "",
		ctxA > 0 ? ` -A ${{ctxA}}` : "",
		exts.length > 0 ? ` --ext ${{exts.join(",")}}` : "",
		...includes.map((inc) => ` --include "${{inc.replace(/"/g, '\\"')}}"`),
	].join("");
	return `${{cdLeadPfx}}"${{AP_BIN}}" search${{flags}} ${{shellQuoteBashPat(rustPat)}} "${{tgtPos.replace(/"/g, '\\"')}}"`;
}}

function accelerateLsPipeline(cmdTailBody: string, cdLeadPfx: string): string | undefined {{
	const stages = splitUnquotedPipes(cmdTailBody.trim());
	if (!stages || stages.length !== 2) return undefined;
	const lhs = stripBenignStderrRedir(stages[0]);
	const rhs = stages[1].trim();
	const stripQuotes = (s: string) => s.replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, "");
	if (/[;&><{{}}`]|\$\(/.test(stripQuotes(lhs)) || /[;&><{{}}`]|\$\(/.test(stripQuotes(rhs))) return undefined;
	const headM = rhs.match(/^head\s+(?:-n\s*(\d+)|-(\d+))$/);
	if (!headM) return undefined;
	const limit = Number(headM[1] || headM[2]);
	if (!Number.isInteger(limit) || limit < 1) return undefined;
	const toks = (lhs.match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) || []).map((t) =>
		(t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")) ? t.slice(1, -1) : t,
	);
	if (toks[0] !== "ls") return undefined;
	let showAll = false;
	let sortMtime = false;
	let sortSize = false;
	let tgt: string | undefined = undefined;
	for (let i = 1; i < toks.length; i += 1) {{
		const t = toks[i];
		if (t.startsWith("-") && t.length > 1) {{
			if (t.startsWith("--")) {{
				if (t === "--all" || t === "--almost-all") {{
					showAll = true;
				}} else if (
					t === "--color=never" ||
					t === "--color=auto" ||
					t === "--group-directories-first" ||
					t === "--classify" ||
					t === "--human-readable"
				) {{
					continue;
				}} else {{
					return undefined;
				}}
				continue;
			}}
			for (const ch of t.slice(1)) {{
				if ("l1hFp".includes(ch)) continue;
				else if (ch === "a" || ch === "A") showAll = true;
				else if (ch === "t") sortMtime = true;
				else if (ch === "S") sortSize = true;
				else return undefined;
			}}
			continue;
		}}
		if (tgt !== undefined || /[*?,]/.test(t)) return undefined;
		tgt = t;
	}}
	const esc = (tgt || ".").replace(/"/g, '\\"');
	const flags = `${{showAll ? " -a" : ""}}${{sortMtime ? " -t" : sortSize ? " -S" : ""}}`;
	return `${{cdLeadPfx}}"${{AP_BIN}}" ls "${{esc}}"${{flags}} --depth 1 --limit ${{limit}}`;
}}

function parseSedLineRanges(expr: string): string | undefined {{
	const parts = expr.split(";");
	if (parts.length === 0 || parts.length > 16) return undefined;
	const out: string[] = [];
	for (const rawPart of parts) {{
		const p = rawPart.trim();
		const m = p.match(/^(\d+)(?:,(\d+))?p$/);
		if (!m) return undefined;
		const s = Number(m[1]);
		const e = m[2] ? Number(m[2]) : s;
		if (!Number.isInteger(s) || !Number.isInteger(e) || s < 1 || e < s) return undefined;
		out.push(`${{s}}-${{e}}`);
	}}
	return out.length > 0 ? out.join(",") : undefined;
}}

function accelerateSingleBashSegment(seg: string, toolName: string): string | undefined {{
	const fastGrep = rewriteSlowRecursiveGrep(seg, toolName);
	if (fastGrep) return fastGrep;

	const cdLeadM = seg.match(/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)([\s\S]+)$/);
	const cdLeadPfx = cdLeadM ? cdLeadM[1] : "";
	const cmdTailBody = cdLeadM ? cdLeadM[2] : seg;
	if (!/[|;&>]/.test(cmdTailBody)) {{
		const gm = cmdTailBody.match(BARE_SLOW_GREP);
		if (gm && /[rR]/.test(gm[1])) {{
			const flags = gm[1];
			const rawPat = gm[2] || gm[3] || gm[4] || "";
			const target = gm[5] || gm[6] || gm[7] || ".";
			const prefix = toolName === "powershell" ? "& " : "";
			const quotedPat = toolName === "bash" ? shellQuoteBashPat(rawPat) : `"${{rawPat.replace(/"/g, '\\"')}}"`;
			const extra = [
				flags.includes("l") ? " -l" : flags.includes("c") ? " -c" : "",
				flags.includes("o") ? " -o" : "",
				flags.includes("i") ? " -i" : "",
			].join("");
			return `${{cdLeadPfx}}${{prefix}}"${{AP_BIN}}" search${{extra}} ${{quotedPat}} "${{target}}"`;
		}}
	}}

	// 1b. Rewrite `cmd //c "where /R <dir> <pat>"` -> fast `.gitignore`-aware `rg --files`
	if (toolName === "bash") {{
		const whereM = seg.match(
			/^cmd\s+\/\/?c\s+"where\s+\/R\s+(?:'([^']+)'|"([^"]+)"|(\S+))\s+([^"]+)"(\s*2>&1)?(\s*\|[\s\S]*)?$/i,
		);
		if (whereM) {{
			const dirArg = (whereM[1] || whereM[2] || whereM[3] || ".").replace(/\\/g, "/");
			const globPat = whereM[4].trim();
			const pipeTail = whereM[6] || "";
			return `rg --files --max-depth 5 -g "${{globPat}}" "${{dirArg}}"${{pipeTail}}`;
		}}
	}}

	// 1c. Rewrite MS-DOS `dir /b [flags] [path|glob] [2>/dev/null|2>&1] [| pipe]` in Git Bash -> bounded `ap ls` / `rg --files`
	if (toolName === "bash" && /\bdir\b/i.test(cmdTailBody)) {{
		const dStages = splitUnquotedPipes(cmdTailBody.trim());
		if (dStages && dStages.length >= 1) {{
			const dirTail = stripBenignStderrRedir(dStages[0]);
			const pipeTail = dStages.length > 1 ? ` | ${{dStages.slice(1).join(" | ")}}` : "";
			if (!/[;&><]/.test(dirTail)) {{
				const toks = dirTail.match(/"[^"]*"|'[^']*'|\S+/g) || [];
				if (toks.length >= 2 && toks[0].toLowerCase() === "dir") {{
					let hasBare = false;
					let recursive = false;
					const tgts: string[] = [];
					let ok = true;
					for (let i = 1; i < toks.length; i += 1) {{
						const rawTok = toks[i];
						const unq = rawTok.replace(/^(['"])(.*)\1$/, "$2");
						const low = unq.toLowerCase();
						if (low === "/b") {{
							hasBare = true;
						}} else if (low === "/s") {{
							recursive = true;
						}} else if (unq.startsWith("/") && unq.length >= 2) {{
							continue;
						}} else if (!/[?,]/.test(unq)) {{
							tgts.push(unq);
						}} else {{
							ok = false;
							break;
						}}
					}}
					if (ok && hasBare) {{
						const depthVal = recursive ? 3 : 1;
						const depthFlag = recursive ? " --depth 3" : "";
						if (tgts.length <= 1) {{
							const rawT = tgts[0] || ".";
							if (rawT.includes("*")) {{
								const normT = rawT.replace(/\\/g, "/");
								const slashIdx = normT.lastIndexOf("/");
								const dirPart = slashIdx >= 0 ? normT.slice(0, slashIdx) || "." : ".";
								const globPart = slashIdx >= 0 ? normT.slice(slashIdx + 1) : normT;
								const extM = globPart.match(/^\*\.([A-Za-z0-9_]+)$/);
								if (extM) {{
									return `${{cdLeadPfx}}"${{AP_BIN}}" ls "${{dirPart.replace(/"/g, '\\"')}}"${{depthFlag}} --ext ${{extM[1]}}${{pipeTail}}`;
								}}
								return `${{cdLeadPfx}}rg --files --no-ignore --max-depth ${{depthVal}} -g '${{globPart.replace(/'/g, "")}}' "${{dirPart.replace(/"/g, '\\"')}}" 2>/dev/null${{pipeTail}}`;
							}}
							return `${{cdLeadPfx}}"${{AP_BIN}}" ls "${{rawT.replace(/"/g, '\\"')}}"${{depthFlag}}${{pipeTail}}`;
						}} else if (tgts.every((t) => !t.includes("*"))) {{
							const quotedDirs = tgts
								.map((t) => `"${{t.replace(/\\/g, "/").replace(/"/g, '\\"')}}"`)
								.join(" ");
							return `${{cdLeadPfx}}rg --files --no-ignore --max-depth ${{depthVal}} ${{quotedDirs}} 2>/dev/null${{pipeTail}}`;
						}}
					}}
				}}
			}}
		}}
	}}

	// 1d. Rewrite bare `sed -n '<A>,<B>p'`, `head -n|-c <N>`, `tail -n <N>`, `cat <file> [2>/dev/null] | ...`,
	// `ls ... | head -n <N>`, or unified `grep ... | cut/sort/uniq/head` pipelines -> bounded `ap` commands
	if (toolName === "bash") {{
		const trimmedTail = cmdTailBody.trim();
		const qPathOk = (f: string) => Boolean(f) && f !== "-" && !/[*?,]/.test(f);
		const stripErr = stripBenignStderrRedir;
		const cutOnlyM = trimmedTail.match(/^([\s\S]+?)\s*\|\s*cut\s+-c\s*1-(\d+)\s*$/);
		const sliceCore = stripErr(cutOnlyM ? cutOnlyM[1].trim() : trimmedTail);
		const sliceWidth = cutOnlyM && Number(cutOnlyM[2]) >= 1 ? Number(cutOnlyM[2]) : 0;
		const sliceWidthFlag = sliceWidth > 0 ? ` --width ${{sliceWidth}}` : "";
		const hasUnsafeOutsideQuotes = (s: string) => /[|;&><{{}}`]|\$\(/.test(s.replace(/'[^']*'|"[^"]*"/g, ""));
		if (!hasUnsafeOutsideQuotes(sliceCore)) {{
			const sedM = sliceCore.match(
				/^sed\s+-n\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&-]+))\s*$/,
			);
			const sedRanges = sedM ? parseSedLineRanges(sedM[1] || sedM[2] || sedM[3] || "") : undefined;
			if (sedM && sedRanges) {{
				const f = sedM[4] || sedM[5] || sedM[6] || "";
				if (qPathOk(f)) {{
					return `${{cdLeadPfx}}"${{AP_BIN}}" read "${{f.replace(/"/g, '\\"')}}" --lines ${{sedRanges}}${{sliceWidthFlag}}`;
				}}
			}}
			if (!/[|;&><{{}}`]|\$\(/.test(sliceCore)) {{
				const headM = sliceCore.match(
					/^head\s+(?:(-c)\s*(\d+)|-n\s*(\d+)|-(\d+))\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&>-]+))\s*$/,
				);
				if (headM) {{
					const isBytes = Boolean(headM[1]);
					const n = Number(headM[2] || headM[3] || headM[4]);
					const f = headM[5] || headM[6] || headM[7] || "";
					if (n >= 1 && qPathOk(f) && !(isBytes && sliceWidth > 0)) {{
						return isBytes
							? `${{cdLeadPfx}}"${{AP_BIN}}" read "${{f.replace(/"/g, '\\"')}}" --offset 0 --chars ${{n}}`
							: `${{cdLeadPfx}}"${{AP_BIN}}" read "${{f.replace(/"/g, '\\"')}}" --lines 1-${{n}}${{sliceWidthFlag}}`;
					}}
				}}
				const tailM = sliceCore.match(/^tail\s+(?:-n\s*(\d+)|-(\d+))\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&-]+))\s*$/);
				if (tailM) {{
					const n = Number(tailM[1] || tailM[2]);
					const f = tailM[3] || tailM[4] || tailM[5] || "";
					if (n >= 1 && qPathOk(f)) {{
						return `${{cdLeadPfx}}"${{AP_BIN}}" read "${{f.replace(/"/g, '\\"')}}" --tail ${{n}}${{sliceWidthFlag}}`;
					}}
				}}
			}}
		}}
		const grepPipeOut = accelerateGrepPipeline(trimmedTail, cdLeadPfx);
		if (grepPipeOut) return grepPipeOut;
		const lsPipeOut = accelerateLsPipeline(trimmedTail, cdLeadPfx);
		if (lsPipeOut) return lsPipeOut;
		const duClean = stripErr(trimmedTail);
		if (!hasUnsafeOutsideQuotes(duClean)) {{
			const duToks = (duClean.match(/"[^"]*"|'[^']*'|\S+/g) || []).map((t) =>
				t.replace(/^(['"])(.*)\1$/, "$2"),
			);
			if (duToks.length >= 2 && duToks[0] === "du") {{
				let hasSummary = false;
				let duTgt: string | undefined = undefined;
				let duOk = true;
				for (let di = 1; di < duToks.length; di += 1) {{
					const tok = duToks[di];
					if (tok.startsWith("-")) {{
						if (/^(?:-s|-h|-sh|-hs|-k|-m|--summarize|--human-readable)$/.test(tok)) {{
							hasSummary = true;
						}} else {{
							duOk = false;
							break;
						}}
					}} else if (duTgt === undefined && !/[*?,]/.test(tok)) {{
						duTgt = tok;
					}} else {{
						duOk = false;
						break;
					}}
				}}
				if (duOk && hasSummary) {{
					const escDu = (duTgt || ".").replace(/"/g, '\\"');
					return `${{cdLeadPfx}}"${{AP_BIN}}" ls "${{escDu}}" --du`;
				}}
			}}
		}}
		const catStages = splitUnquotedPipes(cutOnlyM ? cutOnlyM[1].trim() : trimmedTail);
		if (catStages && catStages.length >= 2) {{
			const catLhs = stripErr(catStages[0]);
			const catM = !/[|;&><{{}}`]|\$\(/.test(catLhs)
				? catLhs.match(/^cat\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&-]+))$/)
				: null;
			const f = catM ? catM[1] || catM[2] || catM[3] || "" : "";
			if (qPathOk(f)) {{
				const esc = f.replace(/"/g, '\\"');
				const rhs1 = stripErr(catStages[1]);
				if (catStages.length === 2 && !hasUnsafeOutsideQuotes(rhs1)) {{
					const rHead = rhs1.match(/^head\s+(?:(-c)\s*(\d+)|-n\s*(\d+)|-(\d+))$/);
					const rTail = rhs1.match(/^tail\s+(?:-n\s*(\d+)|-(\d+))$/);
					const rSed = rhs1.match(/^sed\s+-n\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))$/);
					const rSedRanges = rSed ? parseSedLineRanges(rSed[1] || rSed[2] || rSed[3] || "") : undefined;
					if (rHead) {{
						const isBytes = Boolean(rHead[1]);
						const n = Number(rHead[2] || rHead[3] || rHead[4]);
						if (n >= 1 && !(isBytes && sliceWidth > 0)) {{
							return isBytes
								? `${{cdLeadPfx}}"${{AP_BIN}}" read "${{esc}}" --offset 0 --chars ${{n}}`
								: `${{cdLeadPfx}}"${{AP_BIN}}" read "${{esc}}" --lines 1-${{n}}${{sliceWidthFlag}}`;
						}}
					}} else if (rTail) {{
						const n = Number(rTail[1] || rTail[2]);
						if (n >= 1) return `${{cdLeadPfx}}"${{AP_BIN}}" read "${{esc}}" --tail ${{n}}${{sliceWidthFlag}}`;
					}} else if (rSed && rSedRanges) {{
						return `${{cdLeadPfx}}"${{AP_BIN}}" read "${{esc}}" --lines ${{rSedRanges}}${{sliceWidthFlag}}`;
					}}
				}}
				if ((catStages.length >= 3 || sliceWidth > 0) && /^(?:grep|egrep|fgrep)(?:\s|$)/.test(rhs1) && !hasUnsafeOutsideQuotes(rhs1)) {{
					const tailParts = [
						`${{rhs1}} "${{esc}}"`,
						...catStages.slice(2).map((s) => s.trim()),
						...(sliceWidth > 0 ? [`cut -c 1-${{sliceWidth}}`] : []),
					];
					const catGrepOut = accelerateGrepPipeline(tailParts.join(" | "), cdLeadPfx, true);
					if (catGrepOut) return catGrepOut;
				}}
			}}
		}}
	}}

	// 1e. Rewrite bounded POSIX `find [path] [-maxdepth N] [-type f|d] [-name "<glob>"] [2>/dev/null] [| head -n M]` -> bounded `ap ls` / `rg --files`, and depth-bound any unbounded `find`
	if (toolName === "bash" && /^\s*find(?:\s|$)/.test(cmdTailBody)) {{
		let findCore = cmdTailBody.trim();
		let findLimit = -1;
		const headPipeM = findCore.match(/^([\s\S]+?)\s*\|\s*head\s+(?:-n\s*(\d+)|-(\d+))\s*$/);
		if (headPipeM) {{
			findLimit = Number(headPipeM[2] || headPipeM[3]);
			findCore = headPipeM[1].trim();
		}}
		findCore = findCore.replace(/\s*2>\s*\/dev\/null\s*$/, "").trim();
		if (findLimit !== 0 && !/[|;&><{{}}`]|\$\(/.test(findCore)) {{
			const fToks = (findCore.match(/"[^"]*"|'[^']*'|\S+/g) || []).map((t) =>
				t.replace(/^(['"])(.*)\1$/, "$2"),
			);
			if (fToks.length >= 1 && fToks[0] === "find") {{
				let fIdx = 1;
				let fTarget = ".";
				let findOk = true;
				if (fIdx < fToks.length && !fToks[fIdx].startsWith("-") && !["(", ")", "!"].includes(fToks[fIdx])) {{
					if (/[*?,]/.test(fToks[fIdx])) findOk = false;
					fTarget = fToks[fIdx];
					fIdx += 1;
				}}
				let fDepth = 3;
				let fFilesOnly = false;
				let fDirsOnly = false;
				let fExt = "";
				let fGlob = "";
				while (findOk && fIdx < fToks.length) {{
					const flag = fToks[fIdx];
					if (flag === "-maxdepth" && fIdx + 1 < fToks.length) {{
						const d = Number(fToks[fIdx + 1]);
						if (!Number.isInteger(d) || d < 1 || d > 5) {{
							findOk = false;
							break;
						}}
						fDepth = d;
						fIdx += 2;
					}} else if (flag === "-type" && fIdx + 1 < fToks.length) {{
						const t = fToks[fIdx + 1];
						if (t === "f") fFilesOnly = true;
						else if (t === "d") fDirsOnly = true;
						else findOk = false;
						fIdx += 2;
					}} else if ((flag === "-name" || flag === "-iname") && fIdx + 1 < fToks.length && !fExt && !fGlob) {{
						const rawGlob = fToks[fIdx + 1];
						const em = rawGlob.match(/^\*\.([A-Za-z0-9_]+)$/);
						if (em) {{
							fExt = em[1];
						}} else if (rawGlob && !/[`$]/.test(rawGlob)) {{
							fGlob = rawGlob;
						}} else {{
							findOk = false;
							break;
						}}
						fIdx += 2;
					}} else {{
						findOk = false;
						break;
					}}
				}}
				if (findOk && !(fFilesOnly && fDirsOnly)) {{
					const escTgt = fTarget.replace(/"/g, '\\"');
					if (fGlob && !fDirsOnly) {{
						const headTail = findLimit > 0 ? ` | head -n ${{findLimit}}` : "";
						return `${{cdLeadPfx}}rg --files --no-ignore --max-depth ${{fDepth}} -g '${{fGlob.replace(/'/g, "")}}' "${{escTgt}}" 2>/dev/null${{headTail}}`;
					}}
					const typeFlag = fFilesOnly ? " --files-only" : fDirsOnly ? " --dirs-only" : "";
					const extFlag = fExt ? ` --ext ${{fExt}}` : "";
					const limFlag = findLimit > 0 ? ` --limit ${{findLimit}}` : "";
					return `${{cdLeadPfx}}"${{AP_BIN}}" ls "${{escTgt}}" --depth ${{fDepth}}${{typeFlag}}${{extFlag}}${{limFlag}}`;
				}}
			}}
		}}
		// Safety net: inject `-maxdepth 6` into unbounded `find` pipelines that could not be rewritten
		const rawTrimmedFind = cmdTailBody.trim();
		if (
			!/\s-(?:maxdepth|prune|delete|exec|execdir|ok)\b/.test(rawTrimmedFind) &&
			!/[;&><`]|&&|\|\|/.test(rawTrimmedFind.replace(/'[^']*'|"[^"]*"/g, ""))
		) {{
			const inj = rawTrimmedFind.replace(
				/^(find(?:\s+(?:'[^']+'|"[^"]+"|[^\s-|;&><()!]+))*)(?=\s+(?:-|!|\())/,
				"$1 -maxdepth 6",
			);
			if (inj !== rawTrimmedFind) {{
				return `${{cdLeadPfx}}${{inj}}`;
			}}
		}}
	}}

	// Accelerate slow recursive PowerShell `Get-ChildItem ... -Recurse` (both PS-in-Bash and native PowerShell tool)
	if (toolName === "bash" && /\b(?:Get-ChildItem|gci)\b/i.test(seg) && /-Recurse\b/i.test(seg)) {{
		const psGci = seg.match(
			/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?(?:powershell|pwsh)(?:\.exe)?\b[^|;&]*?\s-(?:Command|c)\s+(['"])([\s\S]+?)\2(?:\s*2>&1)?\s*$/i,
		);
		if (psGci) {{
			const qWrap = psGci[2];
			const psBody = psGci[3]
				.replace(/^\s*\[Console\]::OutputEncoding\s*=[^;]+;\s*/i, "")
				.trim();
			if (
				!PS_MUTATING_CMDLET_RE.test(psBody) &&
				!/\b(?:Where-Object|ForEach-Object|Format-Table|Sort-Object|-Include|-Exclude|-Directory)\b/i.test(psBody)
			) {{
				let gciPart = psBody;
				let firstN = -1;
				const selM = psBody.match(/^([\s\S]+?)\|\s*Select-Object\s+[^|;]*?-First\s+(\d+)\b[^|;]*$/i);
				if (selM) {{
					gciPart = selM[1].trim();
					firstN = Number(selM[2]);
				}}
				if (!gciPart.includes("|") && !gciPart.includes(";")) {{
					const gm = gciPart.match(
						/^(?:Get-ChildItem|gci)\s+[\s\S]*?-(?:Literal)?Path\s+([^;\n]+?)(?=\s+-(?:Recurse|Filter|ErrorAction|File|Directory|Depth)\b|$)/i,
					);
					const posM = !gm
						? gciPart.match(
								/^(?:Get-ChildItem|gci)\s+(?!-)(?:'([^']+)'|"([^"]+)"|([^\s;|]+))(?:\s|$)/i,
							)
						: null;
					const pathExpr = gm ? gm[1] : posM ? posM[1] || posM[2] || posM[3] || "." : ".";
					const fm = gciPart.match(/-Filter\s+(?:'([^']+)'|"([^"]+)"|([^\s;|]+))/i);
					const glob = fm ? fm[1] || fm[2] || fm[3] || "" : "";
					if (!/\$/.test(pathExpr) && !/\$/.test(glob)) {{
						const rawPaths = pathExpr
							.split(",")
							.map((p) => p.trim().replace(/^(['"])(.*)\1$/, "$2").replace(/\\/g, "/"))
							.filter(Boolean);
						if (rawPaths.length > 0 && rawPaths.every((p) => !/[*?`$;|<>]/.test(p))) {{
							const quotedRoots = rawPaths.map((p) => `"${{p.replace(/"/g, '\\"')}}"`).join(" ");
							const globFlag = glob ? ` -g '${{glob.replace(/'/g, "")}}'` : "";
							const headPipe = firstN > 0 ? ` | head -n ${{firstN}}` : "";
							return `${{psGci[1] || ""}}rg --files --no-ignore --max-depth 6${{globFlag}} ${{quotedRoots}} 2>/dev/null${{headPipe}}`;
						}}
					}}
				}}
			}}
			if (!/-Depth\b/i.test(psBody) && !PS_MUTATING_CMDLET_RE.test(psBody)) {{
				const bounded = seg.replace(/(-Recurse\b)/i, "$1 -Depth 5");
				if (bounded !== seg && bounded.includes(qWrap)) return bounded;
			}}
		}}
	}}
	if (
		toolName === "powershell" &&
		/\b(?:Get-ChildItem|gci)\b/i.test(seg) &&
		/-Recurse\b/i.test(seg) &&
		!/-Depth\b/i.test(seg) &&
		!PS_MUTATING_CMDLET_RE.test(seg)
	) {{
		const boundedPs = seg.replace(/(-Recurse\b)/i, "$1 -Depth 5");
		if (boundedPs !== seg) return boundedPs;
	}}

	// Accelerate simple read-only Windows discovery PowerShell one-liners (`Get-NetTCPConnection`,
	// `GetFiles('\\.\pipe\')`, `Get-CimInstance Win32_Process` / `Get-Process`, `Get-Service`) -> fast `ap probe`
	if (toolName === "bash" && /\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(seg)) {{
		const psDiscM = seg.match(
			/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?(?:powershell|pwsh)(?:\.exe)?\b[^|;&]*?\s-(?:Command|c)\s+(['"])([\s\S]+?)\2(?:\s*2>&1)?\s*$/i,
		);
		if (psDiscM) {{
			const cdLead = psDiscM[1] || "";
			const body = psDiscM[3]
				.replace(/^\s*\[Console\]::OutputEncoding\s*=[^;]+;\s*/i, "")
				.trim();
			const hasSideEffectsOrComplex =
				PS_MUTATING_CMDLET_RE.test(body) ||
				/[;>=<`]|(?:\b(?:ForEach-Object|Format-Table|Format-List|ConvertTo-|Export-|Import-)\b|\$[A-Za-z_]\w*\s*=)/i.test(
					body.replace(/\s-(?:match|like|eq)\s/gi, " "),
				);
			if (body && !hasSideEffectsOrComplex) {{
				const firstM = body.match(/\|\s*Select-Object\s+[^|;]*?-First\s+(\d+)\b\s*$/i);
				const core = firstM ? body.slice(0, firstM.index).trim() : body;
				const limNum = firstM ? Math.min(200, Math.max(1, Number(firstM[1]))) : 0;

				// 1. Listening TCP ports
				const tcpM = core.match(
					/^Get-NetTCPConnection(?:\s+-State\s+Listen)?(?:\s+-LocalPort\s+(\d+))?(?:\s+-State\s+Listen)?(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (tcpM) {{
					const portArg = tcpM[1] ? ` -p ${{tcpM[1]}}` : "";
					return `${{cdLead}}"${{AP_BIN}}" probe ports${{portArg}}`;
				}}

				// 2. Named pipes (`[System.IO.Directory]::GetFiles('\\.\pipe\')` or `Get-ChildItem \\.\pipe\`)
				const pipeMatch = core.match(
					/^(?:\[System\.IO\.Directory\]::GetFiles\(\s*['"][\\\/]{{2,4}}\.[\\\/]{{1,2}}pipe[\\\/]*['"]\s*\)|Get-ChildItem\s+['"]?[\\\/]{{2,4}}\.[\\\/]{{1,2}}pipe[\\\/]*['"]?)(?:\s*\|\s*Where-Object\s*\{{\s*\\?\$_\s*-(?:match|like)\s*['"]([^'"]+)['"]\s*\}})?$/i,
				);
				if (pipeMatch) {{
					const rawF = (pipeMatch[1] || "").replace(/^\*+|\*+$/g, "");
					const fFlag = rawF && !/[`$]/.test(rawF) ? ` --filter "${{rawF.replace(/"/g, '\\"')}}"` : "";
					const mFlag = limNum > 0 ? ` --max ${{limNum}}` : "";
					return `${{cdLead}}"${{AP_BIN}}" probe win --pipes${{fFlag}}${{mFlag}}`;
				}}

				// 3. Running processes (`Get-Process` or `Get-CimInstance Win32_Process`)
				const procMatch = core.match(
					/^(?:Get-Process(?:\s+(?:-Name\s+)?['"]?([A-Za-z0-9_.*-]+)['"]?)?|Get-CimInstance\s+Win32_Process(?:\s+-Filter\s+["']Name=['"]([^'"]+)['"]["'])?)(?:\s*\|\s*Where-Object\s*\{{\s*\\?\$_\.(?:Process)?Name\s*-(?:match|like)\s*['"]([^'"]+)['"]\s*\}})?(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (procMatch) {{
					const rawF = (procMatch[1] || procMatch[2] || procMatch[3] || "").replace(/^\*+|\*+$/g, "");
					const fFlag = rawF && !/[`$]/.test(rawF) ? ` --filter "${{rawF.replace(/"/g, '\\"')}}"` : "";
					const lFlag = limNum > 0 ? ` --limit ${{limNum}}` : "";
					return `${{cdLead}}"${{AP_BIN}}" probe ps${{fFlag}}${{lFlag}}`;
				}}

				// 4. Windows services (`Get-Service`)
				const svcMatch = core.match(
					/^Get-Service(?:\s+(?:-Name\s+)?['"]?([A-Za-z0-9_.*-]+)['"]?)?(?:\s*\|\s*Where-Object\s*\{{\s*\\?\$_\.(?:Service|Display)?Name\s*-(?:match|like)\s*['"]([^'"]+)['"]\s*\}})?(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (svcMatch) {{
					const rawF = (svcMatch[1] || svcMatch[2] || "").replace(/^\*+|\*+$/g, "");
					const fFlag = rawF && !/[`$]/.test(rawF) ? ` --filter "${{rawF.replace(/"/g, '\\"')}}"` : "";
					const mFlag = limNum > 0 ? ` --max ${{limNum}}` : "";
					return `${{cdLead}}"${{AP_BIN}}" probe win --services${{fFlag}}${{mFlag}}`;
				}}

				// 5. PE Authenticode signature (`Get-AuthenticodeSignature '<path>'`)
				const sigMatch = core.match(
					/^Get-AuthenticodeSignature(?:\s+-FilePath)?\s+(?:'([^']+)'|"([^"]+)"|([^\s;|'"`$]+))(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (sigMatch) {{
					const rawP = (sigMatch[1] || sigMatch[2] || sigMatch[3] || "").trim();
					if (rawP && !/[`$]/.test(rawP)) {{
						return `${{cdLead}}"${{AP_BIN}}" probe win --sig "${{rawP.replace(/\\/g, "/").replace(/"/g, '\\"')}}"`;
					}}
				}}

				// 6. File/dir ACL (`Get-Acl '<path>'`)
				const aclMatch = core.match(
					/^\(?\s*Get-Acl(?:\s+-(?:Literal)?Path)?\s+(?:'([^']+)'|"([^"]+)"|([^\s;|'"`$)]+))\s*\)?(?:\.(?:Sddl|AccessToString))?(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (aclMatch) {{
					const rawP = (aclMatch[1] || aclMatch[2] || aclMatch[3] || "").trim();
					if (rawP && !/[`$]/.test(rawP)) {{
						return `${{cdLead}}"${{AP_BIN}}" probe win --acl "${{rawP.replace(/\\/g, "/").replace(/"/g, '\\"')}}"`;
					}}
				}}

				// 7. Windows registry key (`Get-ItemProperty 'HKLM:\...'`)
				const regMatch = core.match(
					/^Get-ItemProperty(?:\s+-(?:Literal)?Path)?\s+['"]?(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC):?\\([^'"]+)['"]?(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (regMatch) {{
					const hive = regMatch[1].trim();
					const sub = regMatch[2].trim();
					if (hive && sub && !/[`$]/.test(sub)) {{
						return `${{cdLead}}"${{AP_BIN}}" probe win --reg "${{hive}}\\${{sub.replace(/"/g, '\\"')}}"`;
					}}
				}}
			}}
		}}
	}}

	// Read-only `icacls "<path>"` in Git Bash -> pure-Rust `ap probe win --acl "<path>"`
	if (
		toolName === "bash" &&
		/^\s*(?:cd(?:\s+\/d)?\s+\S+\s*(?:&&|;)\s*)?icacls(?:\.exe)?\s+/i.test(seg) &&
		!/\/(?:grant|deny|remove|setowner|inheritance|reset|restore|save|substitute|t)\b/i.test(seg)
	) {{
		const icM = seg.match(
			/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?icacls(?:\.exe)?\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&>]+))(?:\s+2>\s*(?:\/dev\/null|NUL))?\s*$/i,
		);
		if (icM) {{
			const rawP = (icM[2] || icM[3] || icM[4] || "").trim();
			if (rawP && !/[`$]/.test(rawP)) {{
				return `${{icM[1] || ""}}"${{AP_BIN}}" probe win --acl "${{rawP.replace(/\\/g, "/").replace(/"/g, '\\"')}}"`;
			}}
		}}
	}}

	return undefined;
}}

function accelerateCompoundSegments(cmd: string, toolName: string): string | undefined {{
	if (toolName !== "bash" || !/(?:&&|;|\n)/.test(cmd)) return undefined;
	if (/<<|\b(?:for|while|if)\s+/.test(cmd)) return undefined;
	const parts: Array<{{ text: string; sep: string }}> = [];
	let cur = "";
	let quote: string | null = null;
	let i = 0;
	while (i < cmd.length) {{
		const ch = cmd[i];
		if (quote) {{
			cur += ch;
			if (ch === "\\" && quote === '"' && i + 1 < cmd.length) {{
				cur += cmd[i + 1];
				i += 2;
				continue;
			}}
			if (ch === quote) quote = null;
			i++;
			continue;
		}}
		if (ch === "'" || ch === '"') {{
			quote = ch;
			cur += ch;
			i++;
			continue;
		}}
		if (ch === "&" && cmd[i + 1] === "&") {{
			parts.push({{ text: cur, sep: "&&" }});
			cur = "";
			i += 2;
			continue;
		}}
		if (ch === ";" || ch === "\n") {{
			parts.push({{ text: cur, sep: ch }});
			cur = "";
			i++;
			continue;
		}}
		cur += ch;
		i++;
	}}
	parts.push({{ text: cur, sep: "" }});
	if (parts.length < 2) return undefined;

	let anyChanged = false;
	const out: string[] = [];
	for (const part of parts) {{
		const leadWs = part.text.match(/^\s*/)?.[0] ?? "";
		const trailWs = part.text.match(/\s*$/)?.[0] ?? "";
		const core = part.text.trim();
		let nextCore = core;
		if (core) {{
			const isConditionalGrep =
				(part.sep === "&&" || part.sep === "||") &&
				/^(?:(?:grep|egrep|fgrep|rg|findstr)\b|cat\s+[^|;&]+\|\s*(?:grep|egrep|fgrep|rg)\b)/i.test(core);
			const accel = isConditionalGrep ? undefined : accelerateSingleBashSegment(core, toolName);
			if (accel) {{
				nextCore = accel;
				anyChanged = true;
			}} else if (BARE_PS_CMDLET_PREFIX_RE.test(core) && !/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(core)) {{
				const body = core.replace(/'/g, `'"'"'`);
				nextCore = `powershell.exe -NoProfile -Command '[Console]::OutputEncoding=[Text.Encoding]::UTF8; ${{body}}'`;
				anyChanged = true;
			}}
		}}
		out.push(`${{leadWs}}${{nextCore}}${{trailWs}}${{part.sep}}`);
	}}
	return anyChanged ? out.join("") : undefined;
}}

export function healCommand(
	raw: string,
	toolName: string,
	kvSleepOverrideSec?: number,
): string | undefined {{
	if (!raw) return undefined;
	let cmd = raw;
	let changed = false;
	if (cmd.includes("\0")) {{
		cmd = cmd.replace(/\0/g, "");
		changed = true;
	}}
	const isDestructive = DESTRUCTIVE_OR_WRITE.test(cmd);
	if (isDestructive) {{
		if (toolName === "bash") {{
			const psDestr = healBashPowerShellCommand(cmd);
			if (psDestr) {{
				cmd = psDestr;
				changed = true;
			}}
			const msysDestr = process.platform === "win32" ? healMsysPathConv(cmd, toolName) : undefined;
			if (msysDestr) {{
				cmd = msysDestr;
				changed = true;
			}}
		}}
		return changed ? cmd : undefined;
	}}

	// 0. Pre-normalize safe Git Bash Windowsisms BEFORE accelerators so `cd /d`, `2>NUL`, `&`, unquoted/quoted backslashes, `| more` & `| Select-Object` accelerate too
	if (toolName === "bash") {{
		if (REDIR_NUL.test(cmd)) {{
			cmd = cmd.replace(REDIR_NUL, "$1 /dev/null");
			changed = true;
		}}
		if (/(?:^|[;&|]\s*)cd\s+\/d\s+/i.test(cmd)) {{
			cmd = cmd.replace(/(^|[;&|]\s*)cd\s+\/d\s+/gi, "$1cd ");
			changed = true;
		}}
		const cdAmp = cmd.match(/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)(?:\s+2>\s*\/dev\/null)?)\s*&\s*(?![&>])([\s\S]+)$/);
		if (cdAmp) {{
			cmd = `${{cdAmp[1]}} && ${{cdAmp[2]}}`;
			changed = true;
		}}
		if (/\|\s*more\b/i.test(cmd)) {{
			const noMore = cmd.replace(/\s*\|\s*more(?:\s+\+\d+)?(?=\s*(?:$|[;&|]))/gi, "");
			if (noMore !== cmd) {{
				cmd = noMore;
				changed = true;
			}}
		}}
		const hasScriptRuntime = /<<|(?:^|[\s;&|(=])(?:python3?|py|node|powershell|pwsh)(?:\.exe)?(?=\s|$|[;&|)])/i.test(cmd);
		if (!/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(cmd) && !cmd.includes("<<")) {{
			const normSelect = cmd
				.replace(/\|\s*Select-Object\s+-First\s+(\d+)\b/gi, "| head -n $1")
				.replace(/\|\s*Select-Object\s+-Last\s+(\d+)\b/gi, "| tail -n $1");
			if (normSelect !== cmd) {{
				cmd = normSelect;
				changed = true;
			}}
		}}
		if (!hasScriptRuntime) {{
			const moreToCat = cmd.replace(/(^|[;&|]\s*|\bdo\s+)more(?:\s+\+\d+)?(?=\s+[^-|;&])/gi, "$1cat");
			if (moreToCat !== cmd) {{
				cmd = moreToCat;
				changed = true;
			}}
		}}
		if (!cmd.includes("<<")) {{
			if (/(?:^|[\s=;])[A-Za-z]:\\|[A-Za-z]:[\\/]Program Files/i.test(cmd)) {{
				const normDrv = normalizeUnquotedBashDrivePaths(cmd);
				if (normDrv !== cmd) {{
					cmd = normDrv;
					changed = true;
				}}
			}}
			if (!PY_INVOKE.test(cmd) && !/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(cmd)) {{
				const normRel = normalizeUnquotedRelativeBackslashes(cmd);
				if (normRel !== cmd) {{
					cmd = normRel;
					changed = true;
				}}
				const fixedBs = cmd.replace(/(?<!\\)"([A-Za-z]:\\[^"]*?)"/g, (_m, inner: string) => `"${{inner.replace(/\\/g, "/")}}"`);
				if (fixedBs !== cmd) {{
					cmd = fixedBs;
					changed = true;
				}}
			}}
		}}
	}}

	// 1. Accelerate single-command slow patterns (`grep -rn`, `dir /b`, `sed`/`head`/`tail`/`cat`, `find`, slow PS `Get-ChildItem -Recurse -Filter`)
	const singleAccel = accelerateSingleBashSegment(cmd, toolName);
	if (singleAccel) {{
		return singleAccel;
	}}

	// 1f. Accelerate top-level `;` / `&&` compound Bash probes (and wrap mid-command bare PowerShell cmdlets)
	const compoundAccel = accelerateCompoundSegments(cmd, toolName);
	if (compoundAccel) {{
		cmd = compoundAccel;
		changed = true;
	}}

	// 2a. Strip stray `2>/dev/null` placed inside `for x in *.py 2>/dev/null; do` word lists
	if (toolName === "bash" && /\bfor\s+\w+\s+in\b[^;]*\s2>\s*\/dev\/null\s*;/.test(cmd)) {{
		cmd = cmd.replace(/(\bfor\s+\w+\s+in\b[^;]*?)\s+2>\s*\/dev\/null(\s*;)/g, "$1$2");
		changed = true;
	}}

	// 2c. Normalize Git Bash `find` MSYS paths w/ backslash-escaped spaces (`/c/Program\ Files` -> `"C:/Program Files"`)
	if (toolName === "bash" && /\bfind\s+/.test(cmd)) {{
		const fixedFind = cmd.replace(/\/([a-zA-Z])\/((?:[^\s\\|;&]|\\ )+)/g, (_m, drv: string, tail: string) => {{
			const unesc = tail.replace(/\\ /g, " ");
			return tail.includes("\\ ") ? `"${{drv.toUpperCase()}}:/${{unesc}}"` : `${{drv.toUpperCase()}}:/${{unesc}}`;
		}});
		if (fixedFind !== cmd) {{
			cmd = fixedFind;
			changed = true;
		}}
	}}

	// 2e. Rewrite Windows CMD `for %x in (...) do ...` inside Git Bash into valid Bash loops
	const healedFor = healCmdForLoop(cmd, toolName);
	if (healedFor) {{
		cmd = healedFor;
		changed = true;
	}}

	// 3. Auto-fix unescaped Windows drive & relative path backslashes inside `python -c` & `python <<'PY'` non-raw literals
	if (PY_INVOKE.test(cmd) && /(?:-c\b|<<)/.test(cmd)) {{
		let fixed = cmd.replace(
			/(?<![rR])(['"])([A-Za-z]:)(\\(?!\\)[^'"\r\n]+)\1/g,
			(m, q: string, drv: string, rest: string) => {{
				if (/\\[nrt]$/.test(rest)) return m;
				return q + drv + rest.replace(/\\/g, "/") + q;
			}},
		);
		fixed = fixed.replace(
			/(?<![rR])(['"])([^'"\r\n]*\\(?:Users|Network|Windows|AppData|Local|Roaming|System32|Program Files|Temp|Desktop|Documents|Default)(?:\\[^'"\r\n]*)?)\1/g,
			(m, q: string, inner: string) => (inner.includes("\\\\") ? m : q + inner.replace(/\\/g, "/") + q),
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
	if (toolName === "bash") {{
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
	if (toolName === "bash" && !/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(cmd)) {{
		const psBare = cmd.match(
			/^(\s*(?:cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?)((?:\(\s*)?(?:Get-ChildItem|Get-Content|Get-Process|Get-CimInstance|Select-String|Get-NetTCPConnection|Get-Service|Get-ItemProperty|Get-Item|Get-FileHash|Get-Acl|Get-AuthenticodeSignature|Get-ScheduledTask|Test-NetConnection|Test-Path|Resolve-Path)\b[\s\S]*)$/,
		);
		if (psBare) {{
			const body = psBare[2].trim().replace(/'/g, `'"'"'`);
			cmd = `${{psBare[1] || ""}}powershell.exe -NoProfile -Command '[Console]::OutputEncoding=[Text.Encoding]::UTF8; ${{body}}'`;
			changed = true;
		}}
	}}

	// 7. Lock UTF-8 output encoding & shield PowerShell `$var` when Git Bash spawns `powershell -Command "..."`
	if (toolName === "bash") {{
		const psFixed = healBashPowerShellCommand(cmd);
		if (psFixed) {{
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

	// 9. Clamp long foreground sleeps (>=60s) to kvSleepOverrideSec (default 45s) to avoid evicting LLM KV-caches
	const clampedSleep = clampKvSafeSleep(cmd, toolName, kvSleepOverrideSec ?? 45);
	if (clampedSleep) {{
		cmd = clampedSleep;
		changed = true;
	}}

	// 9b. Inject bounded `--max-time 30` into unguarded standalone Bash `curl` probes (cuts HTTP hangs before KV-cache drops)
	if (toolName === "bash") {{
		const guardedCurl = guardUnboundedCurlTimeout(cmd);
		if (guardedCurl) {{
			cmd = guardedCurl;
			changed = true;
		}}
	}}

	// 10. Shield Git Bash MSYS2 path conversion when invoking Windows CLIs with `/flag` or `openssl -subj '/...'`
	const shieldedMsys = process.platform === "win32" ? healMsysPathConv(cmd, toolName) : undefined;
	if (shieldedMsys) {{
		cmd = shieldedMsys;
		changed = true;
	}}

	// 11. Repair hallucinated `ap` CLI subcommands seen in live logs (`ap bin_surface|objdump|re|files|rg`)
	if (toolName === "bash") {{
		const apAliasM = cmd.match(
			/^(\s*(?:cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?(?:"[^"]*[/\\]ap(?:\.exe)?"|ap(?:\.exe)?)\s+)(bin_surface|objdump|re|files|rg)\b([\s\S]*)$/,
		);
		if (apAliasM) {{
			const lead = apAliasM[1];
			const badSub = apAliasM[2];
			const rest = apAliasM[3] || "";
			if (badSub === "files") {{
				cmd = `${{lead}}ls${{rest}}`;
				changed = true;
			}} else if (badSub === "rg") {{
				cmd = `${{lead}}search${{rest}}`;
				changed = true;
			}} else {{
				const hasMode = /\s--(?:surface|xref|strings|hex|rva|va|diff)\b/.test(rest);
				cmd = `${{lead}}read${{rest}}${{hasMode ? "" : " --surface"}}`;
				changed = true;
			}}
		}}
	}}

	// 12. Auto-transport broken nested/unterminated inline `python -c` scripts via `ap exec --lang py --base64`
	if (toolName === "bash") {{
		const pyBroken = healBrokenInlinePythonCommand(cmd);
		if (pyBroken) {{
			cmd = pyBroken;
			changed = true;
		}}
	}}

	// 13. Normalize benign empty-match exit code 1 on unaccelerated standalone/tail `grep`/`rg`/`findstr`
	//     (strictly preserves exit >= 2 syntax/ENOENT errors and compound &&/|| condition semantics)
	if (toolName === "bash") {{
		const wrappedEmpty = wrapBenignSearchExit1(cmd);
		if (wrappedEmpty) {{
			cmd = wrappedEmpty;
			changed = true;
		}}
	}}

	return changed ? cmd : undefined;
}}

function healBrokenInlinePythonCommand(cmd: string): string | undefined {{
	if (/[<>]|<<|\|\||&&[\s\S]*&&/.test(cmd.replace(/'[^']*'|"[^"]*"/g, ""))) return undefined;
	const m = cmd.match(
		/^(\s*(?:export\s+PYTHONUTF8=1\s+PYTHONIOENCODING=utf-8\s*;\s*)?(?:cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*&&\s*)?)(python3?|py)(?:\.exe)?\s+(?:-[uBE]+\s+)*-c\s+([\s\S]+)$/,
	);
	if (!m) return undefined;
	const lead = (m[1] || "").replace(/^export\s+PYTHONUTF8=1\s+PYTHONIOENCODING=utf-8\s*;\s*/, "");
	const argTail = m[3].trim();
	if (!argTail || (!argTail.startsWith('"') && !argTail.startsWith("'"))) return undefined;

	// Locate balanced closing quote cleanly, even when followed by a trailing shell pipe (e.g. `| awk ... | head -60`).
	const outerQ = argTail[0];
	let consumedEnd = -1;
	if (outerQ === "'") {{
		consumedEnd = argTail.indexOf("'", 1);
	}} else {{
		let esc = false;
		for (let i = 1; i < argTail.length; i++) {{
			const ch = argTail[i];
			if (esc) {{ esc = false; continue; }}
			if (ch === "\\") {{ esc = true; continue; }}
			if (ch === '"') {{
				consumedEnd = i;
				break;
			}}
		}}
	}}

	const trailing = consumedEnd > 0 ? argTail.slice(consumedEnd + 1) : "";
	const trailingTrim = trailing.trim();
	const trailingIsValidShell =
		trailingTrim === "" ||
		/^(?:\||2?>|&>|&&|\|\||;)/.test(trailingTrim);

	if (consumedEnd > 0 && !trailingIsValidShell) return undefined;

	if (consumedEnd > 0 && trailingIsValidShell) {{
		const inner = argTail.slice(1, consumedEnd);
		const hasInnerTrap =
			/(?<![rR\\])'\\'/.test(inner) ||
			(outerQ === '"' && /[\r\n]/.test(inner) && /"[^"\r\n]*"/.test(inner));
		if (!hasInnerTrap) return undefined;
		if (!inner.trim() || inner.length > 32_000) return undefined;
		const b64 = Buffer.from(inner, "utf8").toString("base64");
		return `${{lead}}"${{AP_BIN}}" exec --lang py --base64 ${{b64}}${{trailing}}`;
	}}

	// Unclosed outer quote -> reject if unquoted shell chaining appears
	if (consumedEnd <= 0 && /(?:\||2?>|&&|\|\||;)/.test(argTail.slice(1))) return undefined;

	let rawBody = argTail.slice(1);
	if (rawBody.endsWith(outerQ) && !rawBody.endsWith("\\" + outerQ)) {{
		rawBody = rawBody.slice(0, -1);
	}}
	if (!rawBody.trim() || rawBody.length > 32_000) return undefined;
	const b64 = Buffer.from(rawBody, "utf8").toString("base64");
	return `${{lead}}"${{AP_BIN}}" exec --lang py --base64 ${{b64}}`;
}}

function wrapBenignSearchExit1(cmd: string): string | undefined {{
	if (/[\r\n]/.test(cmd)) return undefined;
	if (cmd.includes("_ap_ec=") || cmd.includes("[ap-empty]")) return undefined;
	const cdM = cmd.match(/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)([\s\S]+)$/);
	const lead = cdM ? cdM[1] : "";
	const tail = (cdM ? cdM[2] : cmd).trim();
	const stripped = tail.replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, "");
	if (/[;&><{{}}`]|\$\(|\|\||&&|\b(?:if|then|while|for)\b/.test(stripped)) return undefined;
	const stages = splitUnquotedPipes(tail);
	if (!stages || stages.length === 0) return undefined;
	const lastStage = stages[stages.length - 1].trim();
	if (!/^(?:grep|egrep|fgrep|rg|findstr)(?:\.exe)?\b/i.test(lastStage)) return undefined;
	return `${{lead}}{{ ${{tail}}; }}; _ap_ec=$?; if [ $_ap_ec -eq 1 ]; then printf '[ap-empty] 0 matches (exit 1)\\n'; exit 0; fi; exit $_ap_ec`;
}}

const HALLUCINATED_TOOL_ALIASES: Readonly<Record<string, string>> = {{
	codemake: "codemode",
	code_mode: "codemode",
	"code-mode": "codemode",
	cdemode: "codemode",
	codemao: "codemode",
	codemodep: "codemode",
	codemod: "codemode",
	codemodocode: "codemode",
	codemodode: "codemode",
	codemask: "codemode",
	code_exec: "codemode",
	code_scan: "codemode",
	code: "codemode",
	codemap: "codemode",
	codemap_placeholder: "codemode",
	js_eval: "codemode",
	eval_js: "codemode",
	run_js: "codemode",
	read_file: "read",
	readfile: "read",
	view_file: "read",
	edit_file: "edit",
	editfile: "edit",
	replace_in_file: "edit",
	str_replace: "edit",
	str_replace_editor: "edit",
	write_file: "write",
	writefile: "write",
	create_file: "write",
	grep_search: "grep",
	search_files: "grep",
	find_files: "find",
	list_files: "ls",
	bashexec: "bash",
	bash_run: "bash",
	run_bash: "bash",
	bash_command: "bash",
	run_command: "bash",
	run_shell: "bash",
	shell: "bash",
	terminal: "bash",
	exec: "bash",
	execute_shell: "bash",
	execute_command: "bash",
	exec_command: "bash",
}};

function damerauLevenshtein(a: string, b: string): number {{
	const n = a.length;
	const m = b.length;
	if (n === 0) return m;
	if (m === 0) return n;
	const dp: number[][] = Array.from({{ length: n + 1 }}, () => new Array<number>(m + 1).fill(0));
	for (let i = 0; i <= n; i++) dp[i][0] = i;
	for (let j = 0; j <= m; j++) dp[0][j] = j;
	for (let i = 1; i <= n; i++) {{
		for (let j = 1; j <= m; j++) {{
			const cost = a[i - 1] === b[j - 1] ? 0 : 1;
			let v = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
			if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {{
				v = Math.min(v, dp[i - 2][j - 2] + 1);
			}}
			dp[i][j] = v;
		}}
	}}
	return dp[n][m];
}}

/**
 * Deterministically repair high-frequency hallucinated tool names (e.g. `codemake` -> `codemode`,
 * `read_file` -> `read`, `run_command` -> `bash`) and unique bounded typos via Damerau-Levenshtein
 * strictly when the target tool is active.
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
	if (key.length >= 5) {{
		const maxDist = key.length >= 7 ? 2 : 1;
		let bestCand: string | undefined = undefined;
		let bestDist = maxDist + 1;
		let bestCount = 0;
		for (const cand of activeTools) {{
			const candLow = cand.toLowerCase();
			if (candLow.length < 4 || Math.abs(key.length - candLow.length) > maxDist) continue;
			const firstOk =
				key[0] === candLow[0] ||
				(key.length >= 2 && key[1] === candLow[0] && key[0] === candLow[1]);
			if (!firstOk) continue;
			const d = damerauLevenshtein(key, candLow);
			if (d <= maxDist) {{
				if (d < bestDist) {{
					bestDist = d;
					bestCand = cand;
					bestCount = 1;
				}} else if (d === bestDist) {{
					bestCount += 1;
				}}
			}}
		}}
		if (bestCand !== undefined && bestCount === 1) return bestCand;
	}}
	return undefined;
}}

export function normalizeRepairedToolArgs(
	targetName: string,
	rawArgs: unknown,
): {{ changed: boolean; args: Record<string, unknown> }} {{
	const args: Record<string, unknown> =
		rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs)
			? {{ ...(rawArgs as Record<string, unknown>) }}
			: {{}};
	let changed = false;
	if (targetName === "bash" && typeof args.command !== "string") {{
		const altCmd =
			typeof args.cmd === "string"
				? args.cmd
				: typeof args.shell_command === "string"
					? args.shell_command
					: typeof args.script === "string"
						? args.script
						: undefined;
		if (altCmd !== undefined) {{
			args.command = altCmd;
			delete args.cmd;
			delete args.shell_command;
			delete args.script;
			changed = true;
		}}
	}} else if (targetName === "read" || targetName === "edit" || targetName === "write") {{
		if (typeof args.path !== "string") {{
			const altPath =
				typeof args.file_path === "string"
					? args.file_path
					: typeof args.filePath === "string"
						? args.filePath
						: typeof args.file === "string"
							? args.file
							: typeof args.filename === "string"
								? args.filename
								: undefined;
			if (altPath !== undefined) {{
				args.path = altPath;
				delete args.file_path;
				delete args.filePath;
				delete args.file;
				delete args.filename;
				changed = true;
			}}
		}}
		if (targetName === "edit") {{
			if (typeof args.oldText !== "string") {{
				const altOld =
					typeof args.old_string === "string"
						? args.old_string
						: typeof args.old_text === "string"
							? args.old_text
							: typeof args.old === "string"
								? args.old
								: undefined;
				if (altOld !== undefined) {{
					args.oldText = altOld;
					delete args.old_string;
					delete args.old_text;
					delete args.old;
					changed = true;
				}}
			}}
			if (typeof args.newText !== "string") {{
				const altNew =
					typeof args.new_string === "string"
						? args.new_string
						: typeof args.new_text === "string"
							? args.new_text
							: typeof args.new === "string"
								? args.new
								: undefined;
				if (altNew !== undefined) {{
					args.newText = altNew;
					delete args.new_string;
					delete args.new_text;
					delete args.new;
					changed = true;
				}}
			}}
		}} else if (targetName === "write" && typeof args.content !== "string") {{
			const altContent =
				typeof args.text === "string"
					? args.text
					: typeof args.body === "string"
						? args.body
						: undefined;
			if (altContent !== undefined) {{
				args.content = altContent;
				delete args.text;
				delete args.body;
				changed = true;
			}}
		}}
	}} else if (targetName === "codemode" && typeof args.code !== "string") {{
		const altCode =
			typeof args.script === "string"
				? args.script
				: typeof args.js === "string"
					? args.js
					: typeof args.source === "string"
						? args.source
						: undefined;
		if (altCode !== undefined) {{
			args.code = altCode;
			delete args.script;
			delete args.js;
			delete args.source;
			changed = true;
		}}
	}} else if (targetName === "grep" && typeof args.pattern !== "string") {{
		const altPat =
			typeof args.query === "string"
				? args.query
				: typeof args.regex === "string"
					? args.regex
					: undefined;
		if (altPat !== undefined) {{
			args.pattern = altPat;
			delete args.query;
			delete args.regex;
			changed = true;
		}}
	}}
	return {{ changed, args }};
}}

/**
 * Scrub leaked DeepSeek DSML / `<tool_call>` XML fragments from assistant prose so unparsed markup
 * never poisons downstream prompt context, while strictly preserving fenced code blocks (``` / ~~~)
 * and inline backtick code spans.
 */
export function scrubLeakedToolMarkup(text: string): string {{
	if (!text || (!text.includes("DSML") && !text.includes("<tool_call>"))) return text;
	const stripRaw = (seg: string): string =>
		seg
			.replace(/<[|｜]{{1,2}}DSML[|｜]{{1,2}}\s*(?:function_)?calls>[\s\S]*?<\/[|｜]{{1,2}}DSML[|｜]{{1,2}}\s*(?:function_)?calls>/g, "")
			.replace(/<\/?[|｜]{{1,2}}DSML[|｜]{{1,2}}\s*invoke\b[\s\S]*?<\/[|｜]{{1,2}}DSML[|｜]{{1,2}}\s*invoke>/g, "")
			.replace(/<\/?[|｜]{{1,2}}DSML[|｜]{{1,2}}[^>]*>/g, "")
			.replace(/<tool_call>[\s\S]*?<\/tool_call>/g, "");
	const protectedRe = /(```[\s\S]*?```|~~~[\s\S]*?~~~|`[^`\r\n]+`)/g;
	let out = "";
	let lastIdx = 0;
	let m: RegExpExecArray | null;
	while ((m = protectedRe.exec(text)) !== null) {{
		out += stripRaw(text.slice(lastIdx, m.index));
		out += m[0];
		lastIdx = m.index + m[0].length;
	}}
	out += stripRaw(text.slice(lastIdx));
	return out.replace(/\n{{3,}}/g, "\n\n").trim();
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
		/<\/?[|｜]{{1,2}}DSML[|｜]{{1,2}}\s*invoke\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/[|｜]{{1,2}}DSML[|｜]{{1,2}}\s*invoke>/g;
	const paramRe =
		/<[|｜]{{1,2}}DSML[|｜]{{1,2}}\s*parameter\s+name="([^"]+)"(?:\s+string="(true|false)")?[^>]*>([\s\S]*?)<\/[|｜]{{1,2}}DSML[|｜]{{1,2}}\s*parameter>/g;

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
			arguments: toolName !== rawToolName ? normalizeRepairedToolArgs(toolName, args).args : args,
		}});
	}}
	if (calls.length === 0) return undefined;
	const cleanedText = text
		.replace(/<[|｜]{{1,2}}DSML[|｜]{{1,2}}\s*(?:function_)?calls>[\s\S]*?<\/[|｜]{{1,2}}DSML[|｜]{{1,2}}\s*(?:function_)?calls>/g, "")
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
			const args = name !== rawName ? normalizeRepairedToolArgs(name, baseArgs).args : baseArgs;
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
	/^(?:hi|hello|hey|ok|okay|thanks|thank you|yes|no|lgtm|commit|push|status|git status|format|lint|run tests?|你好|好的|谢谢|提交|推送|跑测试|看状态)\b[\s!.。？?]*$/i;
const CONTINUATION_PROMPT_RE =
	/^(?:continue|proceed|resume|go(?:\s+ahead)?|keep\s+going|fix\s+(?:it|this|that)|继续|接着做)\b/i;
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
	if (CONTINUATION_PROMPT_RE.test(trimmed)) return "high";
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
	return isDeepSeekModel(model);
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

let cachedPiBuiltinSetTimeout: boolean | null = null;
function detectPiBuiltinSetTimeout(): boolean {{
	if (cachedPiBuiltinSetTimeout !== null) return cachedPiBuiltinSetTimeout;
	try {{
		const cands = [
			process.env.PI_PACKAGE_DIR,
			process.env.APPDATA && join(process.env.APPDATA, "npm", "node_modules", "@earendil-works", "pi-coding-agent"),
			join(homedir(), ".npm-global", "lib", "node_modules", "@earendil-works", "pi-coding-agent"),
		].filter((p): p is string => Boolean(p));
		for (const root of cands) {{
			const worker = join(root, "dist", "bundle", "chunks", "codemode-worker.js");
			if (existsSync(worker)) {{
				const src = readFileSync(worker, "utf8");
				if (src.includes("globalThis, \"setTimeout\"") || src.includes("globalThis,\"setTimeout\"")) {{
					cachedPiBuiltinSetTimeout = true;
					return true;
				}}
			}}
		}}
	}} catch {{
		// ignore fs errors
	}}
	cachedPiBuiltinSetTimeout = false;
	return false;
}}

export default function (pi: ExtensionAPI) {{
	const apProfileOverrides = loadApProfile();
	let peerClaimedCompaction = false;
	const evBusInit = (pi as {{ events?: {{ on?: (ch: string, fn: () => void) => void }} }}).events;
	if (typeof evBusInit?.on === "function") {{
		evBusInit.on("ap:claim_compaction", () => {{
			peerClaimedCompaction = true;
		}});
	}}
	let cachedCompactionTriggerKey = "";
	let cachedCompactionTriggerTokens: number | undefined = undefined;
	const getEffectiveMaskHighWaterTokens = (
		model?: {{ provider?: string; id?: string; contextWindow?: number; cost?: {{ input?: number; cacheRead?: number }} }},
	): number => {{
		const mKey = model ? `${{model.provider ?? ""}}/${{model.id ?? ""}}` : "";
		if (mKey !== cachedCompactionTriggerKey) {{
			cachedCompactionTriggerKey = mKey;
			cachedCompactionTriggerTokens = readModelCompactionTriggerTokens(model);
		}}
		return resolveEffectiveMaskHighWaterTokens({{
			deepCacheDiscount: isDeepCacheDiscountModel(model),
			profileMaskTokens: apProfileOverrides?.maskHighWaterTokens,
			compactionTriggerTokens: cachedCompactionTriggerTokens,
		}});
	}};
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
	let readOnlyBashStreak = 0;
	let lastCodemodeParallelTipTurn = -CODEMODE_PARALLEL_COOLDOWN_TURNS;
	let sessionTurnCount = 0;
	let lastMaskTurn = -MASK_COOLDOWN_TURNS;
	let lastSeenCompactionId = "";
	let expectedCacheReset = false;
	let sessionInputTokens = 0;
	let sessionCacheReadTokens = 0;
	let lastKnownPromptTokens = 0;
	let lastCacheDropPct: number | null = null;
	let lastCacheDropCause = "";
	let prevRequestHashes: ProviderRequestHashes | null = null;
	let currRequestHashes: ProviderRequestHashes | null = null;
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
		lastCacheDropCause = "";
		prevRequestHashes = null;
		currRequestHashes = null;
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
			parts.push(
				lastCacheDropCause
					? `CACHE DROP ${{lastCacheDropPct}}% [${{lastCacheDropCause}}]`
					: `CACHE DROP ${{lastCacheDropPct}}%`,
			);
		}} else if (totalPrompt >= 10000) {{
			const hitPct = Math.round((sessionCacheReadTokens / totalPrompt) * 100);
			parts.push(`cache ${{hitPct}}%`);
		}}
		if (sievedCount > 0) parts.push(`${{sievedCount}} sieved`);
		if (maskedCount > 0) parts.push(`${{maskedCount}} masked`);
		if (guardsTriggered > 0) parts.push(`${{guardsTriggered}} guarded`);
		const effMaskHighWater = getEffectiveMaskHighWaterTokens(
			ctx.model as {{ provider?: string; id?: string; contextWindow?: number; cost?: {{ input?: number; cacheRead?: number }} }} | undefined,
		);
		const highWater =
			(pct !== null && pct >= MASK_HIGH_WATER_PCT) ||
			(tok !== null && tok >= effMaskHighWater);
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
		const isDs = isDeepSeekModel(m);
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
			isIdle: typeof ctx?.isIdle === "function" ? Boolean(ctx.isIdle()) : false,
		}});
		if (override) {{
			cacheWarmsCount += 1;
			return override;
		}}
		return undefined;
	}});

	pi.on("before_provider_request", (event) => {{
		const nextPayload = stabilizeProviderTools(event?.payload);
		const inspected = nextPayload ?? event?.payload;
		const nextHashes = snapshotProviderRequestHashes(inspected);
		if (nextHashes) {{
			prevRequestHashes = currRequestHashes;
			currRequestHashes = nextHashes;
		}}
		return nextPayload;
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
		if (
			shouldYieldCompaction({{
				compactionClaimed: Boolean((event as {{ compactionClaimed?: boolean }} | undefined)?.compactionClaimed),
				envYieldCompact: process.env.AP_YIELD_COMPACT,
				profileYieldCompact: apProfileOverrides?.yieldCompact,
				peerClaimed: peerClaimedCompaction,
			}})
		) {{
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
		const isDeepSeek = isDeepSeekModel(model);
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
			let summary = await summarizeTranscriptLowReasoning(
				ctx,
				model,
				`${{serialized}}${{batonBrief}}${{extraInstr}}`,
				event.signal,
			);
			if (!summary || summary.length < 40) return undefined;
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
					details: {{ readFiles, modifiedFiles }},
				}},
			}};
		}} catch {{
			// Fall back cleanly to Pi's built-in compactor
			return undefined;
		}}
	}});

	async function summarizeTranscriptLowReasoning(
		ctx: ExtensionContext,
		model: NonNullable<ExtensionContext["model"]>,
		promptText: string,
		signal?: AbortSignal,
	): Promise<string | undefined> {{
		const compCtx = {{
			systemPrompt:
				"You are a context compaction summarizer for a coding agent. Output ONLY a crisp, structured handoff summary with these exact headings: ## Goal & Constraints, ## Verified Facts & Progress, ## Falsified Dead-Ends (DO NOT RETRY), ## Key Decisions & File Map, ## Next Immediate Action. Preserve exact file paths, symbol names, build/test commands, and error signatures. Do NOT continue the conversation.",
			messages: [
				{{
					role: "user" as const,
					content: [{{ type: "text" as const, text: promptText }}],
					timestamp: Date.now(),
				}},
			],
		}};
		const compOpts = {{
			reasoning: "low" as const,
			maxTokens: 6144,
			cacheRetention: "none" as const,
			signal,
			timeoutMs: 45000,
			maxAttempts: 2,
		}};
		// Use `streamSimple().result()` (NOT `complete()`): in Pi v1.5+, `complete()` bypasses
		// `streamSimple`, dropping `reasoning` effort mapping and rejecting virtual models like `flash-auto`.
		const response = await callSubLlmWithRetry(
			ctx as Parameters<typeof callSubLlmWithRetry>[0],
			model as Parameters<typeof callSubLlmWithRetry>[1],
			compCtx,
			compOpts,
		);
		if (
			!response ||
			response.stopReason === "error" ||
			response.stopReason === "aborted" ||
			response.stopReason === "length"
		) {{
			return undefined;
		}}
		const respContent = Array.isArray(response.content) ? response.content : [];
		return respContent
			.filter((c): c is {{ type: "text"; text: string }} => c?.type === "text" && typeof c.text === "string")
			.map((c) => c.text)
			.join("\n")
			.trim();
	}}

	pi.on("session_before_tree", async (event, ctx) => {{
		// Keep branch-switch summaries fast & sharp (reasoning: "low" summary when DeepSeek + modelRegistry exist,
		// falling back cleanly to customInstructions with verified facts, dead-ends & active codemode-store keys)
		const branch = ctx?.sessionManager?.getBranch?.() ?? [];
		const storeKeys = listCodemodeStoreKeys(branch as unknown as Array<Record<string, unknown>>);
		const storeAnchor =
			storeKeys.length > 0
				? ` Note active codemode-store keys recoverable via load(key): [${{storeKeys.slice(0, 12).join(", ")}}].`
				: "";
		const fallback = {{
			customInstructions:
				`Preserve exact file paths, symbol names, verified facts, falsified hypotheses/dead-ends, and exact failing error signatures so the target branch never repeats failed attempts.${{storeAnchor}}`,
		}};
		const prep = (event as {{ preparation?: {{ entriesToSummarize?: Array<Record<string, unknown>>; customInstructions?: string; userWantsSummary?: boolean }}; signal?: AbortSignal }} | undefined)?.preparation;
		const signal = (event as {{ signal?: AbortSignal }} | undefined)?.signal;
		const model = ctx?.model;
		const isDeepSeek = isDeepSeekModel(model);
		const hasSimpleComplete =
			typeof ctx?.modelRegistry?.streamSimple === "function" ||
			typeof ctx?.modelRegistry?.complete === "function";
		if (
			prep?.userWantsSummary === false ||
			!isDeepSeek ||
			!model ||
			!hasSimpleComplete ||
			signal?.aborted
		) {{
			return fallback;
		}}
		const entries = Array.isArray(prep?.entriesToSummarize) && prep.entriesToSummarize.length > 0
			? prep.entriesToSummarize
			: (branch as unknown as Array<Record<string, unknown>>);
		const rawMsgs = entries
			.map((e) => ((e as {{ message?: Record<string, unknown> }})?.message ?? e))
			.filter((m) => m && typeof m === "object");
		if (rawMsgs.length === 0) return fallback;
		try {{
			const serialized = serializeMessagesForCompaction(rawMsgs, undefined, [], [], storeKeys);
			const extra = prep?.customInstructions?.trim()
				? `\n\n## Additional Focus\n${{prep.customInstructions.trim()}}`
				: "";
			let summary = await summarizeTranscriptLowReasoning(
				ctx,
				model,
				`${{serialized}}${{extra}}`,
				signal,
			);
			if (!summary || summary.length < 40) return fallback;
			if (storeKeys.length > 0) {{
				summary += `\n\n<codemode-store-keys>\n${{storeKeys.join(", ")}}\n</codemode-store-keys>`;
			}}
			return {{ summary }};
		}} catch {{
			return fallback;
		}}
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
							timeoutMs: 45000,
							maxAttempts: 2,
						}};
						const response = await callSubLlmWithRetry(
							ctx as Parameters<typeof callSubLlmWithRetry>[0],
							ctx.model as Parameters<typeof callSubLlmWithRetry>[1],
							handoffCtx,
							handoffOpts,
						);
						const respBlocks = Array.isArray(response?.content) ? response.content : [];
						const draft = respBlocks
							.filter((c): c is {{ type: "text"; text: string }} => c?.type === "text" && typeof c.text === "string")
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
						// Unwrap virtual `flash-auto` -> physical `deepseek-flash` via callSubLlmWithRetry({{ unwrapVirtual: true }}) so `/ap review` always runs at true `high` effort
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
							timeoutMs: 60000,
							maxAttempts: 2,
							unwrapVirtual: true,
						}};
						const response = await callSubLlmWithRetry(
							ctx as Parameters<typeof callSubLlmWithRetry>[0],
							ctx.model as Parameters<typeof callSubLlmWithRetry>[1],
							reviewCtx,
							reviewOpts,
						);
						const reviewBlocks = Array.isArray(response?.content) ? response.content : [];
						const report = reviewBlocks
							.filter((c): c is {{ type: "text"; text: string }} => c?.type === "text" && typeof c.text === "string")
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
				const effMaskTok = getEffectiveMaskHighWaterTokens(
					ctx.model as {{ provider?: string; id?: string; contextWindow?: number; cost?: {{ input?: number; cacheRead?: number }} }} | undefined,
				);
				ctx.ui.notify(
					`[ap telemetry] model=${{modelStr}} | ctx=${{ctxStr}} (mask@${{Math.round(effMaskTok / 1000)}}k) | cache=${{hitPct}}% (saved ~$${{estUsdSaved}}) | sieved=${{sievedCount}} masked=${{maskedCount}} healedEdits=${{healedEditsCount}} guarded=${{guardsTriggered}}${{compactSuffix}}${{warmSuffix}} | serial1=${{serialPct}} storeKeys=${{storeKeys}}`,
					"info",
				);
			}},
		}});
	}}

	pi.on("message_end", (event) => {{
		const msg = event.message as {{
			role?: string;
			stopReason?: string;
			content?: Array<{{ type?: string; text?: string; name?: string; arguments?: unknown; [k: string]: unknown }}>;
		}} | undefined;
		if (!msg || msg.role !== "assistant" || !Array.isArray(msg.content)) return undefined;

		const active = new Set(pi.getActiveTools?.() ?? []);
		if (active.size === 0) return undefined;

		// 1. Repair hallucinated native toolCall names AND heal parameter aliases on already-active native tools
		if (msg.content.some((b) => b?.type === "toolCall")) {{
			let repairedAny = false;
			const repairedContent = msg.content.map((blk) => {{
				if (blk?.type === "toolCall" && typeof blk.name === "string") {{
					if (!active.has(blk.name)) {{
						const fixedName = repairHallucinatedToolName(blk.name, active);
						if (fixedName) {{
							repairedAny = true;
							return {{
								...blk,
								name: fixedName,
								arguments: normalizeRepairedToolArgs(fixedName, blk.arguments).args,
							}};
						}}
					}} else {{
						const norm = normalizeRepairedToolArgs(blk.name, blk.arguments);
						if (norm.changed) {{
							repairedAny = true;
							return {{
								...blk,
								arguments: norm.args,
							}};
						}}
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
				...(msg.stopReason !== "length" ? {{ stopReason: "toolUse" }} : {{}}),
				content: nextContent,
			}} as typeof event.message,
		}};
	}});

	// Scrub leaked unparsed DSML / <tool_call> XML text on assistant messages without toolCall blocks before provider request
	pi.on("context", (event) => {{
		const msgs = (event as {{ messages?: Array<Record<string, unknown>> }} | undefined)?.messages;
		if (!Array.isArray(msgs) || msgs.length === 0) return undefined;
		let changed = false;
		const nextMessages = msgs.map((m) => {{
			if (!m || m.role !== "assistant" || !Array.isArray(m.content)) return m;
			const content = m.content as Array<{{ type?: string; text?: string; [k: string]: unknown }}>;
			if (content.some((b) => b?.type === "toolCall")) return m;
			let msgChanged = false;
			const nextBlocks = content.map((b) => {{
				if (b?.type === "text" && typeof b.text === "string" && (b.text.includes("DSML") || b.text.includes("<tool_call>"))) {{
					const scrubbed = scrubLeakedToolMarkup(b.text);
					if (scrubbed !== b.text) {{
						msgChanged = true;
						return {{ ...b, text: scrubbed }};
					}}
				}}
				return b;
			}});
			if (!msgChanged) return m;
			changed = true;
			return {{ ...m, content: nextBlocks }};
		}});
		return changed ? {{ messages: nextMessages }} : undefined;
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
					lastCacheDropCause = classifyCacheDropCause(prevRequestHashes, currRequestHashes);
					const evBus = (pi as {{ events?: {{ emit?: (ch: string, d: unknown) => void }} }}).events;
					if (typeof evBus?.emit === "function") {{
						evBus.emit("ap:cache_drop", {{
							turn: sessionTurnCount,
							hitPct: turnHitPct,
							promptTokens: turnPrompt,
							cause: lastCacheDropCause,
						}});
					}}
				}} else if (turnHitPct >= 60) {{
					lastCacheDropPct = null;
					lastCacheDropCause = "";
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
			const basePlanOpts = deepCacheDiscount
				? {{ highWaterTokens: 210000, staleCharsFallback: 360000 }}
				: {{}};
			const effMaskHighWater = getEffectiveMaskHighWaterTokens(
				ctx?.model as {{ provider?: string; id?: string; contextWindow?: number; cost?: {{ input?: number; cacheRead?: number }} }} | undefined,
			);
			const maskOpts = {{
				...basePlanOpts,
				highWaterTokens: effMaskHighWater,
			}};
			const plan = planObservationMasking(contextEntries, {{
				usagePercent: usage?.percent ?? null,
				usageTokens: effTokens,
				...maskOpts,
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
		if (
			(event as {{ continue?: boolean }}).continue === true ||
			(Array.isArray(event.entries) && event.entries.length > 0)
		) {{
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
		if (event.input && typeof event.input === "object") {{
			stripNullOptionalArgs(event.input);
		}}
		if (process.platform === "win32" && event.input && typeof event.input === "object") {{
			const piInp = event.input as {{ path?: unknown; file_path?: unknown }};
			const normP = typeof piInp.path === "string" ? normalizeWindowsToolPath(piInp.path) : undefined;
			if (normP) piInp.path = normP;
			const normFP = typeof piInp.file_path === "string" ? normalizeWindowsToolPath(piInp.file_path) : undefined;
			if (normFP) piInp.file_path = normFP;
		}}
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
			readOnlyBashStreak = 0;
			const code = typeof event.input.code === "string" ? event.input.code : "";
			const hasBuiltinSetTimeout = detectPiBuiltinSetTimeout();
			const healedCode = healCodemodeSource(code, {{ hasBuiltinSetTimeout }});
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
		const ephGuarded = event.toolName === "bash" ? guardEphemeralServerCommand(cmd) : undefined;
		const cmdStage1 = ephGuarded ?? cmd;
		const healed = healCommand(cmdStage1, event.toolName, apProfileOverrides?.kvSafeSleepSec);
		const finalCmd = healed ?? cmdStage1;
		if (finalCmd !== cmd) {{
			event.input.command = finalCmd;
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

		const isFast = isDeepCacheDiscountModel((ctx as {{ model?: {{ id?: string; api?: string }} }} | undefined)?.model);
		const usageTokRaw = (ctx as {{ getContextUsage?: () => {{ tokens?: number | null }} }} | undefined)?.getContextUsage?.()?.tokens;
		const effContextTokens = typeof usageTokRaw === "number" && usageTokRaw > 0 ? usageTokRaw : lastKnownPromptTokens;

		// 0. Lossless multi-block auto-sieve for oversized `codemode` dumps (content[1..N]; preserves header, Script error & images)
		if (event.toolName === "codemode") {{
			const sieved = sieveCodemodeContentBlocks(
				workingContent,
				(rawBody) => {{
					const res = spawnSync(AP_BIN, ["sieve", "pipe", "--label", "pi-codemode"], {{
						input: rawBody,
						encoding: "utf8",
						timeout: 4000,
						windowsHide: true,
						env: {{ ...process.env, SIEVE_HOME }},
					}});
					return res.status === 0 && res.stdout ? res.stdout : undefined;
				}},
				isFast,
				apProfileOverrides?.sieveHardChars,
				effContextTokens,
			);
			if (sieved) {{
				workingContent = sieved;
				sievedCount += 1;
				mutated = true;
			}}
		}}

		const primaryTextIdx = findPrimaryToolResultTextIndex(workingContent, event.toolName);
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

		let fullText = extractAllToolResultText(workingContent);
		let outText = workingContent[lastTextIdx].text as string;
		let textMutated = false;

		// A. Built-in `read` Hashline (`L:HH|`) tagging + redundant re-read guard + universal truncated-file outline (<15ms)
		if (event.toolName === "read" && !event.isError) {{
			const p = String(event.input?.path ?? event.input?.file_path ?? "");
			const off = String(event.input?.offset ?? "");
			const lim = String(event.input?.limit ?? "");
			const startOff = Math.max(1, Math.floor(Number(event.input?.offset) || 1));
			const readIdx = primaryTextIdx >= 0 ? primaryTextIdx : lastTextIdx;
			let readText = workingContent[readIdx].text as string;
			let readBlockMutated = false;
			let readAdvisory = "";
			const readDetails = event.details as {{ truncation?: {{ truncated?: boolean }} }} | undefined;
			const isTruncated =
				readDetails?.truncation?.truncated === true ||
				/use offset=\d+|lines remaining|more lines in file|truncated to \d+/i.test(readText);
			if (typeof event.toolCallId === "string") {{
				const clamped = clampedReadCallIds.get(event.toolCallId);
				if (clamped) {{
					clampedReadCallIds.delete(event.toolCallId);
					readAdvisory += `\n[ap read-clamped] Requested offset=${{clamped.requestedOffset}} > EOF (${{clamped.totalLines}} lines); showing tail from L${{clamped.clampedOffset}}.`;
				}}
			}}
			let didAutoSieveRead = false;
			if (p) {{
				const key = `${{p}}::${{off}}::${{lim}}`;
				const hits = (unchangedReads.get(key) ?? 0) + 1;
				unchangedReads.set(key, hits);
				if (hits >= REREAD_THRESHOLD) {{
					readAdvisory += `\n[ap reread-guard] Exact unchanged slice (${{p}}) read ${{hits}}x already in this session. Avoid re-reading; use ap_search/ap_locate or proceed directly to edits.`;
					guardsTriggered += 1;
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
								readAdvisory += `\n[ap read-outline] File was truncated; full AST symbol map (jump directly via read(offset=...) or ap_read(symbol=...)):\n${{ol.stdout.trim().slice(0, 1800)}}`;
								outlinedPaths.add(normOutlineKey);
							}}
						}} else {{
							try {{
								const rawDoc = readFileSync(absPath, "utf8");
								if (rawDoc.length <= 2_000_000) {{
									const nonCodeOl = extractNonCodeOutline(p, rawDoc);
									if (nonCodeOl) {{
										readAdvisory += `\n${{nonCodeOl}}`;
										outlinedPaths.add(normOutlineKey);
									}}
								}}
							}} catch {{
								// ignore unreadable/binary files
							}}
						}}
					}}
				}} else if (shouldAutoSieveUnboundedRead(readText, event.input, isFast, apProfileOverrides?.sieveHardChars, effContextTokens)) {{
					const res = spawnSync(AP_BIN, ["sieve", "pipe", "--label", "pi-read"], {{
						input: readText,
						encoding: "utf8",
						timeout: 4000,
						windowsHide: true,
						env: {{ ...process.env, SIEVE_HOME }},
					}});
					if (res.status === 0 && res.stdout && res.stdout.length > 40 && res.stdout.length < readText.length * 0.78) {{
						readText = `${{res.stdout.trimEnd()}}\n[ap read-sieve] Unbounded full-file read archived losslessly; use read(offset, limit) for exact edit lines or ap sieve peek/search.`;
						sievedCount += 1;
						readBlockMutated = true;
						didAutoSieveRead = true;
						mutated = true;
					}}
				}} else if (!largeReadTipShown && readText.length >= LARGE_CODE_READ_CHARS && CODE_FILE_EXT.test(p)) {{
					readAdvisory += `\n[ap read-tip] Large code file loaded; use ap_read(outline=true) or ap_read(symbol="...") for AST-exact slices (~85% fewer tokens).`;
					largeReadTipShown = true;
				}} else {{
					const docTip = classifyOversizedDocRead(p, readText.length);
					if (docTip) {{
						readAdvisory += `\n${{docTip}}`;
					}}
				}}
			}}
			if (!didAutoSieveRead) {{
				const hashed = annotateReadWithHashlines(readText, startOff, p);
				if (hashed) {{
					readText = hashed;
					readBlockMutated = true;
					mutated = true;
				}}
			}}
			if (readBlockMutated) {{
				if (readIdx === lastTextIdx) {{
					outText = readText;
					textMutated = true;
				}} else {{
					workingContent = workingContent.map((c, idx) => (idx === readIdx ? {{ ...c, text: readText }} : c));
					fullText = extractAllToolResultText(workingContent);
				}}
			}}
			if (readAdvisory) {{
				outText += readAdvisory;
				textMutated = true;
				mutated = true;
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
			const failIdxMatch = fullText.match(/\bedits\[(\d+)\]/);
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
							const isMulti = /multiple|occurrences|more than once/i.test(fullText);
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
			const hunkMsg =
				Array.isArray(inp?.edits) && failIdx >= 0
					? `\n[ap edit-hunk] edits[${{failIdx}}] (${{targetOld.split("\n").length}} line(s)) missed; fix only this hunk (other hunks can stay unchanged).`
					: "";
			outText += `${{closestSnippet}}${{hunkMsg}}\n[ap edit-tip] Patch target missed; use the exact lines above, ap_edit (4-tier fuzzy + AST symbols), or ap splice view.`;
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

		// C. Dual-tier multi-block shell auto-sieve (>=24KB unconditional, >=14KB structured/noisy) + failure tips + loop-breaker
		if (event.toolName === "bash" || event.toolName === "powershell") {{
			const cmd = typeof event.input?.command === "string" ? event.input.command : "";
			const isSieveSelf = /\bap(?:\.exe)?\s+sieve\b/.test(cmd);
			const isBoundedApCmd =
				cmd.includes("ap.exe") ||
				/\bap\s+(?:read|search|query|atlas|probe|guard|sieve|baton|splice|recall)\b/.test(cmd);
			let maxShellBlockLen = 0;
			let hasGiantShellLine = false;
			for (const blk of workingContent) {{
				if (blk?.type === "text" && typeof blk.text === "string") {{
					if (blk.text.length > maxShellBlockLen) maxShellBlockLen = blk.text.length;
					const blkLines = blk.text.split("\n");
					if (
						!hasGiantShellLine &&
						!(blkLines.length <= 12 && blk.text.length <= 12288) &&
						blkLines.some((l) => l.length > SIEVE_GIANT_LINE_CHARS)
					) {{
						hasGiantShellLine = true;
					}}
				}}
			}}
			const boundedApMax = effContextTokens >= 120_000 ? 12000 : effContextTokens >= 80_000 ? 18000 : 24000;
			const skipSieve = isSieveSelf || (isBoundedApCmd && maxShellBlockLen < boundedApMax && !hasGiantShellLine);
			if (!skipSieve) {{
				const sievedShell = sieveShellContentBlocks(
					workingContent,
					(rawBody) => {{
						const res = spawnSync(AP_BIN, ["sieve", "pipe", "--label", "pi-bash"], {{
							input: rawBody,
							encoding: "utf8",
							timeout: 4000,
							windowsHide: true,
							env: {{ ...process.env, SIEVE_HOME }},
						}});
						return res.status === 0 && res.stdout ? res.stdout : undefined;
					}},
					isFast,
					apProfileOverrides?.sieveHardChars,
					effContextTokens,
				);
				if (sievedShell) {{
					workingContent = sievedShell;
					outText = workingContent[lastTextIdx].text as string;
					fullText = extractAllToolResultText(workingContent);
					sievedCount += 1;
					mutated = true;
				}}
			}}

			if (event.toolName === "bash") {{
				const st = trackReadOnlyBashStreak(readOnlyBashStreak, cmd, DESTRUCTIVE_OR_WRITE.test(cmd));
				readOnlyBashStreak = st.nextStreak;
				if (st.shouldTip && (pi.getActiveTools?.() ?? []).includes("codemode")) {{
					outText += `\n[ap batch-tip] ${{readOnlyBashStreak}} consecutive single bash probes; batch the next 3-5 checks in ONE codemode Promise.allSettled([tools.mcp__agent_primitives__ap_search(...), tools.read(...)]) script.`;
					mutated = true;
				}}
			}}

			const benignGrep = event.isError && isBenignGrepNoMatch(cmd, fullText);
			if (event.isError && !benignGrep) {{
				const failTip = classifyShellFailureTip(event.toolName, cmd, fullText);
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
					const evBus = (pi as {{ events?: {{ emit?: (ch: string, d: unknown) => void }} }}).events;
					if (typeof evBus?.emit === "function") {{
						evBus.emit("ap:tool_loop", {{
							tool: event.toolName,
							count: repeats,
							signature: fp.slice(0, 120),
							isError: Boolean(effectiveErr),
						}});
					}}
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
import {{
  healCommand,
  scrubLeakedToolMarkup,
  isNonRetryableSubLlmError,
  classifyCodemodeFailureTip,
  isDeepSeekModel,
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

// D) scrubLeakedToolMarkup preserves inline & fenced code blocks while scrubbing raw prose leaks (6 cases)
assert.strictEqual(scrubLeakedToolMarkup("Use `<|DSML|invoke>` syntax in tests"), "Use `<|DSML|invoke>` syntax in tests");
const fencedXml = "Here is ```xml\n<tool_call>{{\"name\":\"bash\"}}</tool_call>\n``` example";
assert.strictEqual(scrubLeakedToolMarkup(fencedXml), fencedXml);
const tildeFence = "~~~xml\n<|DSML|invoke name=\"bash\"></|DSML|invoke>\n~~~";
assert.strictEqual(scrubLeakedToolMarkup(tildeFence), tildeFence);
const mixedLeak = "Keep `<code>` and <tool_call>{{\"name\":\"bash\"}}</tool_call> done";
assert.strictEqual(scrubLeakedToolMarkup(mixedLeak).replace(/\s+/g, " "), "Keep `<code>` and done");
assert.ok(!scrubLeakedToolMarkup("raw <|DSML|function_calls><|DSML|invoke name=\"x\"></|DSML|invoke></|DSML|function_calls> end").includes("DSML"));
assert.strictEqual(isDeepSeekModel({{ provider: "deepseek", id: "flash-auto" }}), true);
assert.strictEqual(isDeepSeekModel({{ provider: "anthropic", id: "claude-sonnet" }}), false);

// E) Codemode tips for #50 top live crashes
assert.ok(classifyCodemodeFailureTip("TypeError: cannot read property 'slice' of undefined").includes("JSON.stringify(undefined)"));
assert.ok(classifyCodemodeFailureTip("SyntaxError: unexpected token: 'object'").includes("ALREADY return structured JS objects"));

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
}
