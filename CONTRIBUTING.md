# Co-Maintaining `ap` (4-Source Recursive Self-Improvement & PR Guide)

**English** · [简体中文](./CONTRIBUTING.zh-CN.md) · [README](./README.md) · [R&D Handbook](./docs/HANDBOOK.md) · [PR Template](./.github/PULL_REQUEST_TEMPLATE.md)

`ap` evolves through a **4-Source Recursive Self-Improvement Loop** — never speculative prompt walls:

1. **External Community & Mature-Tool Survey**: Study recurring pain points in developer communities (GitHub Issues/Discussions/HN/coding-agent ecosystems) and battle-tested mechanisms from mature OSS tools (`ripgrep`, `fd`, `ast-grep`, `Aider`, `RTK`, `SWE-agent`, `tree-sitter`, `SQLite FTS5`, `Chrome DevTools / Playwright`, `oh-my-pi`), distilling core algorithms cleanly in Pure Rust.
2. **Local Agent Execution Log Analysis**: Run offline `ap audit --maintainer` (or with explicit host consent, read-only sample local execution failures such as quoting/UTF-8 crashes, timeouts, redundant re-reads, patch mismatches, >8 KB spills, ad-hoc inline scripts, retry doom-loops, or KV-cache drops).
3. **Minimal Pure-Rust Implementation**: Map bottlenecks directly to [`src/`](./src) and [`crates/ap-*`](./crates), obeying all [`AGENTS.md`](./AGENTS.md) invariants with zero AI slop.
4. **Empirical Before/After Testing & Reviewer-First PR Delivery**: Beyond synthetic unit tests, run a realistic sanitized Before-vs-After test (time, steps, error rate, output bytes, cache/token impact) and submit via [`.github/PULL_REQUEST_TEMPLATE.md`](./.github/PULL_REQUEST_TEMPLATE.md) with an **Exact Change Map (`file:symbol/line`)** so maintainers can review and merge in minutes without reading the entire codebase.

Co-maintainers using any AI coding agent (`Claude Code`, `Codex`, `Cursor`, `Pi`, `Antigravity`, `Grok`, `OpenCode`, `Gemini CLI`) are warmly welcome!

---

## Privacy & Responsible-Use Charter (Read First)

1. **Observe Process Friction Only — Zero Private Content**:
   - Extract strictly **execution mechanics** and **minimal synthetic failure patterns**.
   - **Never** include real project names, private business code, user prompts, local usernames/absolute paths, internal domains, vendor/client names, accounts, cookies, tokens, or secrets in any analysis, code, comment, test, doc, commit, or PR.
2. **If You Are Uncomfortable Scanning Local History Logs**: Totally optional — choose either alternative:
   - **Option A (Zero-PII Numeric Brief)**: Run `ap audit --maintainer` locally yourself first (100% offline Pure-Rust binary, auditable in [`src/audit.rs`](./src/audit.rs) — emits anonymized numeric counters and mapped `ap` source modules ONLY, zero prompts/paths/code), inspect it yourself, and hand only that brief to your AI.
   - **Option B (Skip Local Logs)**: Work purely from external OSS/community research, a single manually sanitized error snippet, or direct source inspection.
3. **Responsible Engineering Scope (No Misuse)**: `ap` is strictly for general software engineering, debugging, automated QA, and authorized defensive security/configuration hygiene. Do **not** submit exploit payloads, unauthorized access tooling, or credential-harvesting features.

---

## Quick Start: Copy-Paste Prompt for Recursive Self-Improvement

> **How to use**: Clone `https://github.com/xgbtxy/ap.git`, open your AI coding agent inside the repo, and paste the prompt below.

```text
Act as an open-source co-maintainer of `ap` and execute one complete **4-Source Recursive Self-Improvement Loop**: (1) survey external community issues & mature OSS tool patterns, (2) audit local AI agent execution friction, (3) craft 1–3 high-leverage, 100% generic Pure-Rust improvements in `ap`, and (4) validate with empirical Before-vs-After practical tests and a reviewer-first PR report matching `.github/PULL_REQUEST_TEMPLATE.md`.

[PRIVACY & ANTI-MISUSE REDLINES — STRICT]
1. Process friction ONLY — zero private data:
   - Run `ap audit --maintainer` first to obtain an offline, zero-PII numeric friction-to-source brief.
   - If I am uncomfortable scanning raw local AI history logs, stop inspecting raw logs immediately and work strictly from `ap audit --maintainer`, external OSS research, or manually sanitized snippets I provide.
   - When sampling raw logs with explicit consent, abstract ONLY minimal synthetic error patterns. NEVER include real project names, business code, prompt text, local usernames/absolute paths, internal hosts, credentials, or tokens in any summary, code, test, doc, commit, or PR.
2. Anti-misuse boundary: Every change must stay strictly within generic software engineering, debugging, QA testing, or authorized defensive configuration auditing. No offensive payloads, unauthorized exploitation, or credential harvesting.

[4-STEP RECURSIVE LOOP]
Step 1 · External Community & Mature-Tool Survey:
- If network search is available, survey recent OSS/community discussions on coding-agent bottlenecks (shell quoting/encoding crashes, MCP/stdio hangs, noisy log spills, edit mismatches, doom-loops, KV-cache drops) and battle-tested designs in mature tools (`ripgrep`, `ast-grep`, `Aider`, `RTK`, `SWE-agent`, `oh-my-pi`, etc.). If offline, note the constraint and anchor strictly on proven engineering mechanisms.
- Distill core deterministic algorithms/primitives in Rust; never build prompt walls or thin wrappers.

Step 2 · Local Friction Analysis & Source Mapping:
- Run `ap audit --maintainer` (and only with explicit consent, read-only sample failure mechanics in `~/.codex/sessions`, `~/.claude/projects`, `~/.pi/agent/sessions`, `~/.grok/sessions`, or `~/.gemini/`), cross-check with Step 1, and pick Top 1–3 generalizable bottlenecks.
- Map to `ap` source modules:
  * Shell quoting/UTF-8/path/long-PATH crashes -> `src/exec.rs`, `src/install.rs`
  * Repeated inline `python -c` / `node -e` glue scripts -> `src/read.rs`, `src/query.rs`, `crates/ap-probe/src/`
  * Redundant file re-reads / manual `head`/`tail`/`sed` -> `src/read.rs`, `crates/ap-atlas/src/`, `crates/ap-splice/src/`
  * Edit/patch target mismatches -> `crates/ap-splice/src/lib.rs`
  * >8 KB noisy output spills -> `crates/ap-sieve/src/lib.rs`
  * Slow recursive `grep`/`find` or timeouts -> `src/search.rs`, `src/exec.rs`
  * Retry doom-loops / compaction amnesia -> `crates/ap-guard/src/`, `crates/ap-baton/src/`
  * Pi / reasoning-model KV-cache drops or tool churn -> `src/pi_patch.rs`, `src/install.rs`

Step 3 · Pure-Rust Craft & Invariants (`AGENTS.md`):
- Zero external runtime prerequisites; avoid new Cargo dependencies unless strictly justified.
- Preserve 0 sibling dependencies across all 7 crates under `crates/ap-*`.
- Use `OnceLock` for regexes (never `Regex::new` inside hot loops); enforce rules in deterministic code.
- Update `src/mcp.rs` (incl. `outputSchema`) if CLI flags/commands change, keep EN & zh-CN docs aligned, and preserve the `skills/*/SKILL.md` frontmatter token budget.

Step 4 · Practical Before-vs-After Verification & CI Gates:
- Add sanitized synthetic unit/integration tests (`example.com` / temp dirs).
- Run a realistic sanitized practical test comparing **Before vs After** (latency, step count, error rate, output bytes, or cache/token savings).
- Pass ALL local gates before proposing a commit/PR:
  1) `cargo fmt --all -- --check`
  2) `cargo clippy --workspace --all-targets -- -D warnings`
  3) `cargo test --workspace`
  4) Line-by-line `git diff` review confirming 0 private leaks and 0 hardcoded host paths.

[REVIEWER-FIRST PR SPECIFICATION — MANDATORY]
Format your final output strictly following `.github/PULL_REQUEST_TEMPLATE.md` so maintainers can verify and merge rapidly without reading the whole repo:
1. 1-sentence Summary (`What & Why`);
2. Research & Evidence Sources (external survey + anonymized log stats + minimal repro);
3. Exact Change Map (`file :: symbol (lines)` | Before | After | Why) + Architecture Parity checklist;
4. Practical Before-vs-After benchmark table + CI gate results;
5. Cross-OS risks, rejected alternatives, and clean rollback path;
6. Line-by-line privacy & anti-misuse self-audit (+ 1 suggested next focus for the next recursive cycle).
```

---

## Maintainer Rapid-Review Workflow

Because [`.github/PULL_REQUEST_TEMPLATE.md`](./.github/PULL_REQUEST_TEMPLATE.md) enforces an **Exact Change Map (`file:symbol/line`)** and a **Before-vs-After empirical table**, reviewers can evaluate PRs in 4 quick checks:
1. Check Sections 1 & 3 to confirm tight blast radius and zero coupling across `crates/ap-*`.
2. Check Section 4 to verify real practical improvement (not just mock tests) and green Ubuntu/macOS/Windows CI.
3. Spot-check the listed `file:line` spans and Section 5 rollback/guard boundaries.
4. Confirm Section 6 privacy & anti-misuse self-audit before merging.

---

## Source Map for Human Maintainers

| Source Path | Responsibility |
| :--- | :--- |
| [`src/read.rs`](./src/read.rs) · [`src/binary.rs`](./src/binary.rs) · [`src/inspect.rs`](./src/inspect.rs) | Universal reader (Office/PDF/SQLite/AST symbols/archives/PE/ELF/Java/.NET/Protobuf/JS routes/JWT/redacted secrets) |
| [`src/search.rs`](./src/search.rs) · [`src/query.rs`](./src/query.rs) | Multi-core regex/archive search & zero-dependency SQL over SQLite/Excel/CSV/JSON |
| [`src/exec.rs`](./src/exec.rs) · [`src/win_job.rs`](./src/win_job.rs) | Cross-platform shell auto-healer, UTF-8 lock, fast `grep` rewrite & Win32 Job Object orphan cleanup |
| [`src/audit.rs`](./src/audit.rs) · [`src/stats.rs`](./src/stats.rs) | 100% offline zero-PII friction auditor (`ap audit --maintainer`) & local efficiency ledger |
| [`src/mcp.rs`](./src/mcp.rs) · [`src/install.rs`](./src/install.rs) · [`src/pi_patch.rs`](./src/pi_patch.rs) | MCP 2025-06-18 36-tool stdio server, 15+ agent auto-wiring & 11-patch Pi v1.5+ runtime patcher |
| [`crates/ap-atlas`](./crates/ap-atlas) · [`ap-splice`](./crates/ap-splice) · [`ap-probe`](./crates/ap-probe) · [`ap-sieve`](./crates/ap-sieve) · [`ap-guard`](./crates/ap-guard) · [`ap-recall`](./crates/ap-recall) · [`ap-baton`](./crates/ap-baton) | 7 zero-coupling isolated Rust crates (structural map / AST editing / HTTP·WS·UI·runtime probes / FTS5 log sieve / anti-slop guard / micro-recall / compaction baton) |
