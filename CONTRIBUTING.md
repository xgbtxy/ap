# Co-Maintaining `ap` (Friction-Driven Open-Source Evolution Guide)

**English** · [简体中文](./CONTRIBUTING.zh-CN.md) · [README](./README.md) · [R&D Handbook](./docs/HANDBOOK.md)

`ap` evolves through one simple rule: **never invent bloated prompt walls — observe real process friction in coding-agent runs, and distill recurring tool crashes, quoting bugs, redundant reads, log floods, and retry loops into zero-dependency Pure-Rust primitives.**

Co-maintainers using any AI coding agent (`Claude Code`, `Codex`, `Cursor`, `Pi`, `Antigravity`, `Grok`, `OpenCode`, `Gemini CLI`) are warmly welcome!

---

## Privacy & Responsible-Use Charter (Read First)

1. **Observe Process Friction Only — Zero Private Content**: When auditing local AI session logs, look strictly at **execution mechanics** (shell quoting/UTF-8 crashes, timeouts, redundant file re-reads, patch mismatches, >8 KB output spills, ad-hoc `python -c`/`node -e` glue scripts, retry doom-loops, KV-cache drops). **Never** copy, quote, or commit private project names, business code, user prompts, local usernames/paths, internal domains, accounts, cookies, tokens, or secrets into code, tests, docs, or PRs.
2. **If You Are Uncomfortable Scanning Local History Logs**: No problem at all! Choose either safer alternative:
   - **Option A (Zero-PII Numeric Brief)**: Run `ap audit --maintainer` locally first (100% offline Rust binary, auditable in [`src/audit.rs`](./src/audit.rs) — emits anonymized numeric counters and mapped `ap` source modules ONLY, zero prompts/paths/secrets), verify the output yourself, and feed only that brief to your AI.
   - **Option B (Skip Logs Entirely)**: Paste a single sanitized error snippet or browse the source directly to open an Issue or PR.
3. **Responsible Engineering Scope (No Misuse)**: `ap` is strictly for general software engineering, debugging, automated QA, and authorized defensive security/configuration hygiene. Do **not** submit exploit payloads, unauthorized access tooling, or credential-harvesting features.

---

## Quick Start: Copy-Paste Prompt for Your AI Co-Maintainer

> **How to use**: Clone `https://github.com/xgbtxy/ap.git`, open your AI coding agent inside the repo, and paste the prompt below.

```text
Act as an open-source co-maintainer of `ap` (this Rust repository). Audit process friction from my local AI agent runs and design/implement 1–3 high-impact, 100% generic Pure-Rust improvements against `ap`'s source code.

[PRIVACY & ANTI-MISUSE REDLINES — STRICT]
1. Process friction ONLY — zero private data:
   - Start by running `ap audit --maintainer` locally to get a 100% offline, zero-PII numeric friction-to-source brief.
   - If deeper inspection of recurring tool failures is needed (shell syntax errors, UTF-8 crashes, timeouts, edit mismatches, oversized outputs, repeated inline scripts), abstract ONLY minimal synthetic error patterns. NEVER include real project names, private code, prompt text, local usernames/absolute paths, internal hosts, credentials, or tokens in any summary, code, test, doc, or commit message.
   - (If I am uncomfortable with scanning raw local AI history logs, stop immediately and work solely from `ap audit --maintainer` counters or manually sanitized snippets I provide.)
2. Anti-misuse boundary: Every improvement must remain strictly within generic software engineering, debugging, QA testing, or authorized defensive configuration auditing. No offensive payloads, unauthorized exploitation, or credential harvesting.

[WORKFLOW]
1. Measure friction: Run `ap audit --maintainer` (and only with explicit consent, read-only sample local failure patterns in `~/.codex/sessions`, `~/.claude/projects`, `~/.pi/agent/sessions`, `~/.grok/sessions`, or `~/.gemini/` to rank the Top 5 generic execution bottlenecks).
2. Map bottlenecks to `ap` source modules:
   - Shell quoting/UTF-8/path crashes -> `src/exec.rs`, `src/install.rs`
   - Repeated inline `python -c` / `node -e` glue scripts -> `src/read.rs`, `src/query.rs`, `crates/ap-probe/src/`
   - Redundant file re-reads / manual `head`/`tail`/`sed` slicing -> `src/read.rs`, `crates/ap-atlas/src/`, `crates/ap-splice/src/`
   - Edit/patch target mismatches -> `crates/ap-splice/src/lib.rs`
   - >8 KB noisy output spills -> `crates/ap-sieve/src/lib.rs`
   - Slow recursive `grep`/`find` or timeouts -> `src/search.rs`, `src/exec.rs`
   - Retry doom-loops / compaction amnesia -> `crates/ap-guard/src/`, `crates/ap-baton/src/`
   - Pi / reasoning-model cache drops or churn -> `src/pi_patch.rs`, `src/install.rs`
3. Respect all repository invariants (`AGENTS.md`):
   - Zero external runtime prerequisites; avoid adding Cargo dependencies unless strictly justified.
   - Preserve 0 sibling dependencies across all 7 crates under `crates/ap-*`.
   - Use `OnceLock` for regexes (never `Regex::new` inside hot loops); enforce rules in code, not prose.
   - Add synthetic unit tests (using dummy `example.com` / temp files), update `src/mcp.rs` if CLI flags change, and keep EN/zh-CN docs aligned.
4. Pass all required gates before committing:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace`
   - Review `git diff` line-by-line to confirm 0 private leaks or hardcoded host paths.
```

---

## Architecture Map for Human Maintainers

| Source Path | Responsibility |
| :--- | :--- |
| [`src/read.rs`](./src/read.rs) · [`src/binary.rs`](./src/binary.rs) · [`src/inspect.rs`](./src/inspect.rs) | Universal reader (Office/PDF/SQLite/AST symbols/archives/PE/ELF/Java/.NET/Protobuf/JS routes/JWT/redacted secrets) |
| [`src/search.rs`](./src/search.rs) · [`src/query.rs`](./src/query.rs) | Multi-core regex/archive search & zero-dependency SQL over SQLite/Excel/CSV/JSON |
| [`src/exec.rs`](./src/exec.rs) · [`src/win_job.rs`](./src/win_job.rs) | Cross-platform shell auto-healer, UTF-8 lock, fast `grep` rewrite & Win32 Job Object orphan cleanup |
| [`src/audit.rs`](./src/audit.rs) · [`src/stats.rs`](./src/stats.rs) | 100% offline zero-PII friction auditor (`ap audit --maintainer`) & local efficiency ledger |
| [`src/mcp.rs`](./src/mcp.rs) · [`src/install.rs`](./src/install.rs) · [`src/pi_patch.rs`](./src/pi_patch.rs) | MCP 2025-06-18 36-tool stdio server, 15+ agent auto-wiring & 11-patch Pi v1.5+ runtime patcher |
| [`crates/ap-atlas`](./crates/ap-atlas) · [`ap-splice`](./crates/ap-splice) · [`ap-probe`](./crates/ap-probe) · [`ap-sieve`](./crates/ap-sieve) · [`ap-guard`](./crates/ap-guard) · [`ap-recall`](./crates/ap-recall) · [`ap-baton`](./crates/ap-baton) | 7 zero-coupling isolated Rust crates (structural map / AST editing / HTTP·CDP·runtime probes / FTS5 log sieve / anti-slop guard / micro-recall / compaction baton) |
