# `agent-primitives` Repository Operating Rules (`v2.38+` Pure-Rust Edition)

Before proposing, adding, or modifying anything in this repository, read **[docs/HANDBOOK.md](./docs/HANDBOOK.md)** / **[docs/HANDBOOK.zh-CN.md](./docs/HANDBOOK.zh-CN.md)** and **[CONTRIBUTING.md](./CONTRIBUTING.md)** / **[CONTRIBUTING.zh-CN.md](./CONTRIBUTING.zh-CN.md)**.

## Core Philosophy
1. **Observe Real Coding-Agent Runs First**: Ground every upgrade in actual agent execution logs and `<thinking>` traces across free and commercial harnesses (`OpenCode`, `Codex`, `Pi`, `Claude Code`, `Antigravity`, `Qwen Code`, `Gemini CLI`, `Grok`).
2. **Synthesize Mature Open-Source Engineering (Never Reinvent Slop)**: Study and distill proven open-source mechanisms (`Aider`, `RTK`, `SWE-agent`, `MCP`, Tree-sitter, SQLite FTS5, Chromium CDP, ecosystem typecheckers/linters) into lean, zero-dependency Rust rather than inventing bloated 0-to-1 wrappers or prompt walls.
3. **Elevate Core Coding Capability for Everyone**: Judge every change by measurable gains in speed, token efficiency, first-try pass rate, and zero-slop code quality—even for complete beginners using `$0` free coding agents via 1-line setup.

## Six Non-Negotiable Engineering Invariants
1. **Zero AI Slop**: Zero pure-prompt checklists, zero `Regex::new` inside hot loops (`OnceLock` DFAs), zero swallowed errors, `0` `clippy -D warnings`.
2. **Crate-Level Physical Isolation + Single Binary (`ap`)**: All 7 crates (`crates/ap-*`) maintain **zero sibling `ap-*` dependencies** (`test_crate_physical_isolation_and_frontmatter_budget`), linking into one native binary `ap` (`ap.exe`) exposing both Unix CLI and `ap mcp` stdio JSON-RPC.
3. **Zero External Runtime Prerequisite**: Prebuilt binaries across Linux (`musl` + `arm64`), macOS (`arm64` + `x64`), and Windows (`x64` MSVC) via 1-line `install.sh` / `install.ps1` / `cargo install`.
4. **Hard Context & Latency Budgets**: `SKILL.md` frontmatter **`< 65 tokens`** per folder (`390 tokens` total); core AST/SQLite/Hook latency **`< 20 ms`**.
5. **Tools Enforce Rules, Not Prose**: Recurring mistakes become deterministic `.agents/guard.json` rules, `atlas product` contract checks, or `probe smoke` steps.
6. **Empirical Truth & 1:1 Bilingual Parity**: Validate with live controlled A/B runs (beginner, legacy, and empty-dir random projects) and keep English (`*.md`) & Simplified Chinese (`*.zh-CN.md`) synchronized.

## Required Verification Before Every Commit
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run --release --bin ap -- doctor
cargo run --release --bin ap -- bench --out bench/results.json
```
