# Anti-Obsolescence Design Architecture: Cognitive & Physical Boundaries (`ap` v2.39)

[English](./DESIGN.md) | [简体中文](./DESIGN.zh-CN.md) · [Handbook](./HANDBOOK.md) · [Playbook](./PLAYBOOK.md) · [Contributing](../CONTRIBUTING.md) · [PR Template](../.github/PULL_REQUEST_TEMPLATE.md)

## 1. Why 95% of Agent Repositories Become Obsolete Within 6 Months

- **Prompt Roleplay & Checklists Die First**: Absorbed into frontier RL post-training weights and official slash commands, turning verbose `AGENTS.md` walls into latency and attention taxes.
- **Heavy Orchestration Wrappers Die Second**: Official CLIs (`codex`, `opencode`, `pi`, `claude`, `agy`, `qwen`, `gemini`, `grok`, `hermes`, `openclaw`) natively own conversation loops and subagents.
- **Lossy Vector RAG Wrappers Die Third**: Replaced by exact structural maps and fast deterministic search without Docker/API-key overhead.

**Core Thesis**: Build **zero-slop, sub-20ms Pure-Rust physical instruments (`ap` / `ap.exe`)**—exposed via both **Unix CLI** and **Model Context Protocol (`ap mcp`)**—strictly at the **boundaries where autoregressive token generation collides with OS/AST/Binary/Network/Browser reality**.

---

## 2. The Four Irreducible Cognitive & Physical Boundaries (`v2.39`)

| Boundary in `<thinking>` & OS Reality | Observed Waste Across `101k+` Local Calls & Live `<thinking>` Streams | Our Pure-Rust Organ & Open-Source Best-of-Breed Synthesis (`v2.39`) |
| :--- | :--- | :--- |
| **1. Cold-Start Entropy, Binary Blindness & Dead-Slop Contamination** | `30k+` outputs `>8 KB`; `10k–35k` thinking chars guessing host runtimes; writing brittle `python -c` scripts for Office/PDF/SQLite/`.asar`/PE/ELF/Java/.NET/Protobuf/SourceMaps/JWT/minified JS. | **`ap-atlas`** (Aider **Personalized PageRank**, `<60ms` guard-aware 9-axis `surface --include-binaries`, `<25ms` `locate`, `<30ms` `trace`/`changes`, `product` `#id`/API contract & slop radar) + **`ap read`** / **`ap search --pat`** / **`ap query`** + **`ap-sieve`** (`-98.8%` logs, FTS5 `search`/`peek`, 300-line error storm cap) + **`ap-probe slice`** |
| **2. Cross-File Working-Memory Drift, Edit Mismatches & Shell Quoting** | Dropping HTML `#id` ↔ JS selectors across files; `735+` patch mismatches on indent/blank-line drift; `528+` Windows PowerShell/UTF-8/long-`PATH` crashes. | **`ap-splice`** (`view`, `rename` ignoring comments/strings, Aider 3-tier + Tier-4 blank-line-resilient & Hashline `L:HH\|` `apply`, `<5ms` cross-file linker `check`, `ap undo`) + **`ap exec`** (UTF-8 lock, slow `grep -rn` → `ap search` auto-heal, Win32 Job Objects) + **`ap mcp`** (`36` typed `outputSchema` JSON-RPC tools = `0` shell quoting) |
| **3. Verification Tax, Live Network/Browser QA & Heap Guessing** | **`71%–75%` of vanilla turns** burned on hung Windows servers, orphaned ports, 150-line browser/WS/HTTP AuthZ/CORS scripts, vacuous tests, and missed test mutations. | **`ap-probe`** (`smoke` w/ ephemeral `PORT`, `ui` desktop/mobile layout & network audit, non-destructive `cdp --watch-ms`, `http --principal/--principal-cdp/--cors-origin/--select/--race/--batch-stdin`, RFC 6455 `ws --origin-matrix`, `tls`, `tcp`, `listen`, `ps`, `fs`, AST `mutate`, `fuzz`, `run`/`diff`) + **`ap guard verify --deep`** |
| **4. Prose Rule Amnesia, Doom-Loops, Compaction Wipeout & Runtime KV-Cache Churn** | Models ignore verbose rules under load, burn turns in identical retry loops, lose frontier state after `/compact`, overspend CJK compaction budgets, or bust DeepSeek/provider KV-caches mid-run. | **`ap-guard`** (`<2ms` `exit 2` rules, `sec` C/C++/Java/TS/Py/Go/Rust CWE checks, semantic `diff`, bundle `pack`, `3x` doom-loop breaker) + **`ap-baton`** (`frontier` orthogonal scheduler, `claim` leases, CJK+BM25 `dedup`) + **`ap-recall`** (`3.4ms` BM25) + **`ap pi`** (11-patch Pi v1.5+ runtime patcher + `zz-ap-accelerator.ts`) + **`ap audit --maintainer`** (100% offline zero-PII 6-harness friction brief) |

---

## 3. Why Pure Rust (`v2.39`) + Native `ap mcp`?

1. **Compile-Time Safety & Sub-2ms Startup (`Rust > C & Python`)**: Strict ownership, zero `Regex::new` inside inner loops (`OnceLock` DFAs), zero GC pauses, zero external runtime dependencies, and Windows long-`PATH` / UTF-8 / Job-Object hardening built in.
2. **Universal Zero-Brain Access for `$0` Free & Commercial Agents (`ap mcp`)**: Full **MCP 2025-06-18** stdio JSON-RPC server exposing **36 strongly-typed `outputSchema` tools**, live Resources, and 5 Prompts (`ap init` auto-wires 15+ agents), eliminating shell syntax fragility even for `$0` free models.
3. **7 Physically Isolated Crates (`0` Sibling Dependencies)**: Every primitive under `crates/ap-*` compiles standalone while linking with root modules into a single `~15 MB` stripped native binary (`390 tokens` total idle skill frontmatter).
