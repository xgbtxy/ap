use crate::audit::default_home_dir;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelProfile {
    Auto,
    Balanced,
    DeepSeek,
    Fast,
    Reasoning,
    Small,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileKnobs {
    pub recommended_mcp_profile: &'static str,
    pub sieve_threshold_chars: usize,
    pub kv_safe_sleep_s: u64,
    pub mask_high_water_tokens: u64,
    pub dsml_recovery: bool,
}

impl ModelProfile {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "balanced" => Some(Self::Balanced),
            "deepseek" => Some(Self::DeepSeek),
            "fast" => Some(Self::Fast),
            "reasoning" => Some(Self::Reasoning),
            "small" => Some(Self::Small),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Balanced => "balanced",
            Self::DeepSeek => "deepseek",
            Self::Fast => "fast",
            Self::Reasoning => "reasoning",
            Self::Small => "small",
        }
    }

    pub fn knobs(self) -> ProfileKnobs {
        match self {
            Self::Auto => ProfileKnobs {
                recommended_mcp_profile: "full",
                sieve_threshold_chars: 20_000,
                kv_safe_sleep_s: 45,
                mask_high_water_tokens: 180_000,
                dsml_recovery: true,
            },
            Self::Balanced => ProfileKnobs {
                recommended_mcp_profile: "core",
                sieve_threshold_chars: 20_000,
                kv_safe_sleep_s: 60,
                mask_high_water_tokens: 180_000,
                dsml_recovery: false,
            },
            Self::DeepSeek => ProfileKnobs {
                recommended_mcp_profile: "core",
                sieve_threshold_chars: 12_000,
                kv_safe_sleep_s: 45,
                mask_high_water_tokens: 210_000,
                dsml_recovery: true,
            },
            Self::Fast => ProfileKnobs {
                recommended_mcp_profile: "core",
                sieve_threshold_chars: 12_000,
                kv_safe_sleep_s: 45,
                mask_high_water_tokens: 140_000,
                dsml_recovery: false,
            },
            Self::Reasoning => ProfileKnobs {
                recommended_mcp_profile: "core",
                sieve_threshold_chars: 16_000,
                kv_safe_sleep_s: 45,
                mask_high_water_tokens: 180_000,
                dsml_recovery: false,
            },
            Self::Small => ProfileKnobs {
                recommended_mcp_profile: "deferred",
                sieve_threshold_chars: 10_000,
                kv_safe_sleep_s: 45,
                mask_high_water_tokens: 90_000,
                dsml_recovery: false,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApProfileConfig {
    pub schema_version: u32,
    pub model_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_mcp_profile: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub harness_mcp_profiles: BTreeMap<String, String>,
}

impl Default for ApProfileConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            model_profile: "auto".to_string(),
            default_mcp_profile: None,
            harness_mcp_profiles: BTreeMap::new(),
        }
    }
}

pub fn profile_path(home: &Path) -> PathBuf {
    home.join(".ap").join("profile.json")
}

pub fn load_profile(home: &Path) -> Option<ApProfileConfig> {
    let p = profile_path(home);
    let raw = fs::read_to_string(p).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_profile(home: &Path, cfg: &ApProfileConfig) -> Result<PathBuf, String> {
    let p = profile_path(home);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let body = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(&p, format!("{body}\n")).map_err(|e| e.to_string())?;
    Ok(p)
}

pub fn reset_profile(home: &Path) -> bool {
    let p = profile_path(home);
    if p.exists() {
        fs::remove_file(&p).is_ok()
    } else {
        false
    }
}

pub fn parse_mcp_profile_arg(raw: &str) -> Result<Option<&'static str>, String> {
    let t = raw.trim().to_ascii_lowercase();
    if t.is_empty() {
        return Ok(None);
    }
    match t.as_str() {
        "full" => Ok(Some("full")),
        "core" => Ok(Some("core")),
        "deferred" => Ok(Some("deferred")),
        _ => Err(format!(
            "Unknown MCP profile '{raw}'. Choose from: full, core, deferred"
        )),
    }
}

pub fn parse_model_profile_arg(raw: &str) -> Result<Option<ModelProfile>, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Ok(None);
    }
    ModelProfile::parse(t).map(Some).ok_or_else(|| {
        format!(
            "Unknown model profile '{raw}'. Choose from: auto, balanced, deepseek, fast, reasoning, small"
        )
    })
}

fn norm_stored_mcp(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "core" => "core",
        "deferred" => "deferred",
        _ => "full",
    }
}

pub fn resolve_mcp_profile_for_harness(
    cfg: Option<&ApProfileConfig>,
    harness: &str,
    explicit_mcp_profile: &str,
    model_profile: ModelProfile,
) -> &'static str {
    if let Ok(Some(explicit)) = parse_mcp_profile_arg(explicit_mcp_profile) {
        return explicit;
    }
    if harness == "pi" {
        if let Some(h_ovr) = cfg.and_then(|c| c.harness_mcp_profiles.get("pi")) {
            return norm_stored_mcp(h_ovr);
        }
        return "full";
    }
    if let Some(h_ovr) = cfg.and_then(|c| c.harness_mcp_profiles.get(harness)) {
        return norm_stored_mcp(h_ovr);
    }
    if let Some(def_mcp) = cfg.and_then(|c| c.default_mcp_profile.as_deref()) {
        return norm_stored_mcp(def_mcp);
    }
    model_profile.knobs().recommended_mcp_profile
}

#[derive(Parser, Debug)]
#[command(
    name = "profile",
    about = "Layer 3 on-demand Harness x Model adapters over Universal ap Core"
)]
struct ProfileCli {
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    home: Option<String>,
    #[command(subcommand)]
    cmd: Option<ProfileSubCmd>,
}

#[derive(Subcommand, Debug)]
enum ProfileSubCmd {
    /// Inspect Universal Core status, active model profile knobs & wired harness adapters
    Show,
    /// Configure declarative on-demand model/harness profile (~/.ap/profile.json)
    Set {
        #[arg(long, default_value = "")]
        model: String,
        #[arg(long = "mcp-profile", default_value = "")]
        mcp_profile: String,
        #[arg(long, default_value = "")]
        harness: String,
        #[arg(long)]
        apply: bool,
    },
    /// Inspect local multi-harness/model telemetry and print on-demand adapter commands
    Recommend {
        #[arg(long, default_value_t = 25)]
        max_sessions: usize,
    },
    /// Remove declarative profile overrides (~/.ap/profile.json) cleanly
    Reset,
}

fn resolve_home(home_opt: Option<&str>) -> PathBuf {
    home_opt
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_home_dir)
}

fn show_profile_value(home: &Path) -> Value {
    let p_path = profile_path(home);
    let loaded = load_profile(home);
    let model_prof = loaded
        .as_ref()
        .and_then(|c| ModelProfile::parse(&c.model_profile))
        .unwrap_or(ModelProfile::Auto);
    let knobs = model_prof.knobs();
    let wired = crate::install::inspect_wired_harness_profiles(home);
    json!({
        "core_version": env!("CARGO_PKG_VERSION"),
        "mcp_tools": 37,
        "idle_skill_tokens": 390,
        "profile_path": p_path.to_string_lossy().replace('\\', "/"),
        "profile_configured": loaded.is_some(),
        "model_profile": model_prof.as_str(),
        "default_mcp_profile": loaded.as_ref().and_then(|c| c.default_mcp_profile.clone()),
        "harness_mcp_profiles": loaded.as_ref().map(|c| &c.harness_mcp_profiles).cloned().unwrap_or_default(),
        "knobs": knobs,
        "wired_harnesses": wired,
    })
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match ProfileCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    let home = resolve_home(cli.home.as_deref());
    match cli.cmd.unwrap_or(ProfileSubCmd::Show) {
        ProfileSubCmd::Show => {
            let val = show_profile_value(&home);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
                return 0;
            }
            println!(
                "[ap profile] Universal Core v{} ({} MCP tools, {} idle skill tokens)",
                val["core_version"].as_str().unwrap_or(""),
                val["mcp_tools"],
                val["idle_skill_tokens"]
            );
            println!(
                "  Layer 3 Profile    : model={} (configured={}) -> sieve={} chars, sleep={}s, mask={} tok, dsml={}",
                val["model_profile"].as_str().unwrap_or("auto"),
                val["profile_configured"],
                val["knobs"]["sieve_threshold_chars"],
                val["knobs"]["kv_safe_sleep_s"],
                val["knobs"]["mask_high_water_tokens"],
                val["knobs"]["dsml_recovery"]
            );
            if let Some(dm) = val["default_mcp_profile"].as_str() {
                println!("  Default MCP Profile: {dm}");
            }
            if let Some(arr) = val["wired_harnesses"].as_array() {
                if arr.is_empty() {
                    println!("  Wired Harnesses    : none (run `ap init` to wire on demand)");
                } else {
                    for h in arr {
                        println!(
                            "  Harness [{:<14}]: mcp_profile={:<8} codemode_deferred={} hooks={}",
                            h["harness"].as_str().unwrap_or(""),
                            h["mcp_profile"].as_str().unwrap_or("full"),
                            h["codemode_deferred"],
                            h["hooks"]
                        );
                    }
                }
            }
            0
        }
        ProfileSubCmd::Set {
            model,
            mcp_profile,
            harness,
            apply,
        } => {
            let parsed_model = match parse_model_profile_arg(&model) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("[ap profile] {e}");
                    return 2;
                }
            };
            let parsed_mcp = match parse_mcp_profile_arg(&mcp_profile) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("[ap profile] {e}");
                    return 2;
                }
            };
            if parsed_model.is_none() && parsed_mcp.is_none() {
                eprintln!("[ap profile] Provide --model <auto|balanced|deepseek|fast|reasoning|small> and/or --mcp-profile <full|core|deferred>");
                return 2;
            }
            let mut cfg = load_profile(&home).unwrap_or_default();
            if let Some(mp) = parsed_model {
                cfg.model_profile = mp.as_str().to_string();
            }
            let target_harness = harness.trim().to_ascii_lowercase();
            if let Some(mcp_p) = parsed_mcp {
                if !target_harness.is_empty() && target_harness != "auto" && target_harness != "all"
                {
                    cfg.harness_mcp_profiles
                        .insert(target_harness.clone(), mcp_p.to_string());
                } else {
                    cfg.default_mcp_profile = Some(mcp_p.to_string());
                }
            }
            let saved_path = match save_profile(&home, &cfg) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[ap profile] Failed to save profile: {e}");
                    return 1;
                }
            };
            if apply {
                let agent_arg = if target_harness.is_empty() {
                    "auto"
                } else {
                    target_harness.as_str()
                };
                let home_s = home.to_string_lossy().to_string();
                let rc = crate::install::cmd_init(
                    agent_arg,
                    "sieve,baton,recall,guard,atlas,probe,splice",
                    false,
                    None,
                    Some(&home_s),
                    false,
                    false,
                    true,
                    parsed_mcp.unwrap_or(""),
                    parsed_model.map(|m| m.as_str()).unwrap_or(""),
                );
                if rc != 0 {
                    return rc;
                }
            }
            if cli.json {
                let mut out = show_profile_value(&home);
                out["saved_path"] = json!(saved_path.to_string_lossy().replace('\\', "/"));
                out["applied"] = json!(apply);
                println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            } else {
                println!(
                    "[ap profile] Saved Layer 3 profile (model={}, saved={})",
                    cfg.model_profile,
                    saved_path.to_string_lossy().replace('\\', "/")
                );
            }
            0
        }
        ProfileSubCmd::Recommend { max_sessions } => {
            let report = crate::audit::audit_home(&home, max_sessions, false);
            if cli.json {
                let out = json!({
                    "core_version": env!("CARGO_PKG_VERSION"),
                    "harnesses_detected": report["harnesses_detected"],
                    "model_families_detected": report["model_families_detected"],
                    "recommended_adapters": report["recommended_adapters"],
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
                return 0;
            }
            println!(
                "[ap profile recommend] Layer 2 Telemetry -> Layer 3 On-Demand Adapters (scanned in {} ms, zero-PII)",
                report["elapsed_ms"]
            );
            if let Some(recs) = report["recommended_adapters"].as_array() {
                if recs.is_empty() {
                    println!("  No local multi-harness telemetry found; run `ap init` for Universal Core defaults.");
                } else {
                    for (i, r) in recs.iter().enumerate() {
                        println!(
                            "  {}. [{}] -> {}\n     Run: `{}`",
                            i + 1,
                            r["layer"].as_str().unwrap_or(""),
                            r["reason"].as_str().unwrap_or(""),
                            r["command"].as_str().unwrap_or(""),
                        );
                    }
                }
            }
            0
        }
        ProfileSubCmd::Reset => {
            let removed = reset_profile(&home);
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "reset": true,
                        "removed": removed,
                        "profile_path": profile_path(&home).to_string_lossy().replace('\\', "/"),
                    }))
                    .unwrap_or_default()
                );
            } else if removed {
                println!(
                    "[ap profile] Removed {} cleanly (reverted to Layer 1 Universal Core defaults).",
                    profile_path(&home).to_string_lossy().replace('\\', "/")
                );
            } else {
                println!("[ap profile] No custom profile override present.");
            }
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_knobs_and_roundtrip_save_load_reset() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_profile(dir.path()).is_none());

        let small_k = ModelProfile::Small.knobs();
        assert_eq!(small_k.recommended_mcp_profile, "deferred");
        assert_eq!(small_k.sieve_threshold_chars, 10_000);
        let ds_k = ModelProfile::DeepSeek.knobs();
        assert_eq!(ds_k.mask_high_water_tokens, 210_000);
        assert!(ds_k.dsml_recovery);

        let mut cfg = ApProfileConfig {
            schema_version: 1,
            model_profile: "deepseek".to_string(),
            default_mcp_profile: Some("core".to_string()),
            harness_mcp_profiles: BTreeMap::new(),
        };
        cfg.harness_mcp_profiles
            .insert("opencode".to_string(), "deferred".to_string());
        let saved = save_profile(dir.path(), &cfg).unwrap();
        assert!(saved.is_file());

        let loaded = load_profile(dir.path()).unwrap();
        assert_eq!(loaded, cfg);

        assert!(reset_profile(dir.path()));
        assert!(!reset_profile(dir.path()));
        assert!(load_profile(dir.path()).is_none());
    }

    #[test]
    fn resolve_mcp_profile_respects_small_deferred_and_pi_codemode() {
        let mut cfg = ApProfileConfig {
            schema_version: 1,
            model_profile: "small".to_string(),
            default_mcp_profile: None,
            harness_mcp_profiles: BTreeMap::new(),
        };
        assert_eq!(
            resolve_mcp_profile_for_harness(Some(&cfg), "opencode", "", ModelProfile::Small),
            "deferred"
        );
        // Pi already uses exposure:"codemode", so it keeps full unless explicitly overridden
        assert_eq!(
            resolve_mcp_profile_for_harness(Some(&cfg), "pi", "", ModelProfile::Small),
            "full"
        );
        assert_eq!(
            resolve_mcp_profile_for_harness(Some(&cfg), "pi", "core", ModelProfile::Small),
            "core"
        );

        cfg.harness_mcp_profiles
            .insert("cursor".to_string(), "core".to_string());
        assert_eq!(
            resolve_mcp_profile_for_harness(Some(&cfg), "cursor", "", ModelProfile::Small),
            "core"
        );
    }
}
