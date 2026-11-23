# `agent-primitives` Repository Operating Rules (`v2.39+` Pure-Rust Edition)

Before proposing, adding, or modifying anything in this repository, read **[docs/HANDBOOK.md](./docs/HANDBOOK.md)** / **[docs/HANDBOOK.zh-CN.md](./docs/HANDBOOK.zh-CN.md)**, **[CONTRIBUTING.md](./CONTRIBUTING.md)** / **[CONTRIBUTING.zh-CN.md](./CONTRIBUTING.zh-CN.md)**, and **[.github/PULL_REQUEST_TEMPLATE.md](./.github/PULL_REQUEST_TEMPLATE.md)**.

## Core Philosophy (4-Source Recursive Self-Improvement)
1. **Observe Real Coding-Agent Runs & Survey Mature OSS First**: Ground every upgrade in (a) external community pain points & proven open-source mechanisms (`Aider`, `RTK`, `SWE-agent`, `ripgrep`, `ast-grep`, `oh-my-pi`, Tree-sitter, SQLite FTS5, Chromium CDP) and (b) actual process friction across agent execution logs (`ap audit --maintainer` zero-PII numeric brief across `OpenCode`, `Codex`, `Pi`, `Claude Code`, `Antigravity`, `Qwen Code`, `Gemini CLI`, `Grok`) — strictly anonymized mechanics only, zero private data or misuse.
2. **Synthesize Lean Pure-Rust Primitives (Never Reinvent Slop)**: Distill battle-tested mechanisms into zero-dependency Pure Rust rather than bloated wrappers or verbose prompt walls.
3. **Empirical Verification & Reviewer-First PR Delivery**: Validate every improvement with synthetic tests AND realistic Before-vs-After practical measurements, keeping English (`*.md`) & Simplified Chinese (`*.zh-CN.md`) aligned, and documenting exact `file :: symbol (lines)` change maps in PRs matching **[.github/PULL_REQUEST_TEMPLATE.md](./.github/PULL_REQUEST_TEMPLATE.md)**.

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
