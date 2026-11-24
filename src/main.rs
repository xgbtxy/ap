#![recursion_limit = "256"]

pub mod audit;
pub mod bench;
pub mod binary;
pub mod exec;
pub mod inspect;
pub mod install;
pub mod ls;
pub mod mcp;
pub mod pi_patch;
pub mod profile;
pub mod query;
pub mod read;
pub mod search;
pub mod stats;
pub mod undo;
pub mod win_job;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "ap",
    version,
    about = "Elevate AI coding efficiency on Windows & macOS by solving where LLM <thinking> gets derailed — instant repo clarity, BOM/AST-safe edits, crash-free shell exec & headless browser verification"
)]
struct TopCli {
    #[command(subcommand)]
    cmd: TopCmd,
}

#[derive(Subcommand, Debug)]
enum TopCmd {
    /// 1-command auto-setup for all detected coding agents (install & forget)
    Init {
        #[arg(short = 'a', long, default_value = "auto")]
        agent: String,
        #[arg(long, default_value = "sieve,baton,recall,guard,atlas,probe,splice")]
        only: String,
        #[arg(long)]
        here: bool,
        #[arg(long)]
        dir: Option<String>,
        #[arg(long)]
        home: Option<String>,
        #[arg(long)]
        with_hooks: bool,
        #[arg(long)]
        with_mcp: bool,
        #[arg(long)]
        no_rules: bool,
        /// MCP tool schema profile (`full`, `core`, or `deferred`)
        #[arg(long, default_value = "")]
        mcp_profile: String,
        /// On-demand Layer 3 model profile (`auto`, `balanced`, `deepseek`, `fast`, `reasoning`, `small`)
        #[arg(long, default_value = "")]
        model_profile: String,
    },
    /// View prevented thinking derailments, browser verifications & efficiency gains
    #[command(visible_alias = "gain")]
    Stats {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        reset: bool,
        #[arg(long)]
        since_hours: Option<u64>,
        #[arg(long)]
        home: Option<String>,
    },
    /// Check Windows/macOS shell, UTF-8, headless browser CDP & agent wiring health
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Read any file (.docx, .xlsx, .pptx, .pdf, .csv, GBK/UTF-16) or URL without context overflow
    Read { target: Option<String> },
    /// Fast, token-efficient directory listing with depth, sorting, filters & Windows/Git-Bash path support
    Ls { path: Option<String> },
    /// Run exact SQL joins & aggregations across .xlsx, GBK/UTF-8 .csv/.tsv & .json files
    Query {
        #[arg(short = 'f', long = "file")]
        files: Vec<String>,
        sql: Option<String>,
    },
    /// Universal .gitignore-aware regex search with enclosing AST symbol spans + .docx/.xlsx/GBK
    Search { pattern: Option<String> },
    /// Run commands with UTF-8 lock, Bash-in-PowerShell auto-heal, port unlock & log compression
    Exec {
        #[arg(short = 'c', long = "cmd")]
        cmd: Option<String>,
    },
    /// Restore files from the most recent agent edit snapshot (works even outside Git!)
    Undo {
        #[arg(long)]
        list: bool,
    },
    /// Show current repository and global multi-agent installation status
    Status {
        #[arg(long)]
        dir: Option<String>,
        #[arg(long)]
        home: Option<String>,
    },
    /// Cleanly remove installed skills, hooks, MCP configs, and rule blocks
    Uninstall {
        #[arg(long)]
        here: bool,
        #[arg(long)]
        dir: Option<String>,
        #[arg(long)]
        home: Option<String>,
    },
    /// Start native Model Context Protocol (MCP) stdio JSON-RPC server
    Mcp {
        /// Exposed tool profile: full (37 tools, default), core (8 everyday tools + ap_discover/ap_call), or deferred (only ap_discover + ap_call, ~94% fewer schema tokens)
        #[arg(long, default_value = "")]
        profile: String,
    },
    /// Run deterministic micro-benchmark suite (with honest negative controls)
    Bench {
        #[arg(long, default_value = "bench/results.json")]
        out: String,
    },
}

fn dispatch_primitive(name: &str, tail_args: &[String]) -> Option<i32> {
    let mut sub_argv = Vec::with_capacity(tail_args.len() + 1);
    sub_argv.push(name.to_string());
    sub_argv.extend_from_slice(tail_args);
    let is_help = tail_args.iter().any(|a| a == "--help" || a == "-h");
    let from_mcp = std::env::var("AP_MCP_CHILD").ok().as_deref() == Some("1");
    let code = match name {
        "read" => return Some(read::run_cli(&sub_argv)),
        "ls" => return Some(ls::run_cli(&sub_argv)),
        "bin" | "pe_info" | "pe" | "strings" => {
            sub_argv[0] = "read".to_string();
            return Some(read::run_cli(&sub_argv));
        }
        "cdp" | "http" | "ws" | "tls" | "tcp" | "listen" | "ports" | "ps" | "win" | "ui"
        | "smoke" | "fuzz" | "mutate" => {
            let mut probe_argv = Vec::with_capacity(tail_args.len() + 2);
            probe_argv.push("probe".to_string());
            probe_argv.push(name.to_string());
            probe_argv.extend_from_slice(tail_args);
            return Some(ap_probe::run_cli(&probe_argv));
        }
        "query" => return Some(query::run_cli(&sub_argv)),
        "search" => return Some(search::run_cli(&sub_argv)),
        "exec" => return Some(exec::run_cli(&sub_argv)),
        "undo" => return Some(undo::run_cli(&sub_argv)),
        "stats" | "gain" => return Some(stats::run_cli(&sub_argv)),
        "pi" => return Some(pi_patch::run_cli(&sub_argv)),
        "profile" => return Some(profile::run_cli(&sub_argv)),
        "sieve" => Some(ap_sieve::run_cli(&sub_argv)),
        "baton" => Some(ap_baton::run_cli(&sub_argv)),
        "recall" => Some(ap_recall::run_cli(&sub_argv)),
        "guard" => Some(ap_guard::run_cli(&sub_argv)),
        "atlas" => Some(ap_atlas::run_cli(&sub_argv)),
        "probe" => Some(ap_probe::run_cli(&sub_argv)),
        "splice" => Some(ap_splice::run_cli(&sub_argv)),
        "audit" => return Some(audit::run_cli(&sub_argv)),
        _ => None,
    };
    if code.is_some() && !is_help && !from_mcp {
        let sub_action = tail_args.first().map(String::as_str).unwrap_or("");
        let guards = if matches!(
            (name, sub_action),
            ("splice", "apply" | "check")
                | ("probe", "smoke")
                | ("guard", "verify" | "stop-gate")
                | ("atlas", "impact" | "product")
        ) {
            1
        } else {
            0
        };
        let win_heals = if name == "probe" && sub_action == "smoke" && cfg!(windows) {
            1
        } else {
            0
        };
        stats::record_event(name, 0, 0, win_heals, guards, sub_action);
    }
    code
}

fn main() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info.to_string();
        if msg.contains("failed printing to stdout")
            || msg.contains("Broken pipe")
            || msg.contains("os error 232")
        {
            std::process::exit(0);
        }
        default_hook(info);
    }));

    let args: Vec<String> = std::env::args().collect();

    // 1. Busybox `argv[0]` dispatch if symlinked/hardlinked
    if let Some(arg0) = args.first() {
        let stem = std::path::Path::new(arg0)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if stem != "ap" && stem != "agent-primitives" {
            if let Some(code) = dispatch_primitive(&stem, &args[1..]) {
                std::process::exit(code);
            }
        }
    }

    // 2. Subcommand passthrough to `exec`, `stats`/`gain`, `audit`, and internal engine modules
    if let Some(sub) = args.get(1).map(|s| s.as_str()) {
        if let Some(code) = dispatch_primitive(sub, &args[2..]) {
            std::process::exit(code);
        }
    }

    let cli = match TopCli::try_parse_from(&args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let is_help = e.kind() == clap::error::ErrorKind::DisplayHelp;
            let _ = e.print();
            if is_help {
                println!(
                    "\nInternal Engine Modules (automatically invoked by agents via MCP & hooks):\n  atlas / splice / probe / sieve / guard / recall / baton / audit"
                );
            }
            std::process::exit(code);
        }
    };

    let code = match cli.cmd {
        TopCmd::Init {
            agent,
            only,
            here,
            dir,
            home,
            with_hooks,
            with_mcp,
            no_rules,
            mcp_profile,
            model_profile,
        } => install::cmd_init(
            &agent,
            &only,
            here,
            dir.as_deref(),
            home.as_deref(),
            with_hooks,
            with_mcp,
            no_rules,
            &mcp_profile,
            &model_profile,
        ),
        TopCmd::Stats { .. } => stats::run_cli(&args[1..]),
        TopCmd::Doctor { json } => install::cmd_doctor(json),
        TopCmd::Read { .. } => read::run_cli(&args[1..]),
        TopCmd::Ls { .. } => ls::run_cli(&args[1..]),
        TopCmd::Query { .. } => query::run_cli(&args[1..]),
        TopCmd::Search { .. } => search::run_cli(&args[1..]),
        TopCmd::Exec { .. } => exec::run_cli(&args[1..]),
        TopCmd::Undo { .. } => undo::run_cli(&args[1..]),
        TopCmd::Status { dir, home } => install::cmd_status(dir.as_deref(), home.as_deref()),
        TopCmd::Uninstall { here, dir, home } => {
            install::cmd_uninstall(here, dir.as_deref(), home.as_deref())
        }
        TopCmd::Mcp { profile } => mcp::run_mcp_stdio_with_profile(&profile),
        TopCmd::Bench { out } => bench::run_bench(std::path::Path::new(&out)),
    };
    std::process::exit(code);
}
