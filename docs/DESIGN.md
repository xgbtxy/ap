# Anti-Obsolescence Design Architecture: Cognitive & Physical Boundaries (`ap` v2.50)

[English](./DESIGN.md) | [简体中文](./DESIGN.zh-CN.md) · [Handbook](./HANDBOOK.md) · [Playbook](./PLAYBOOK.md) · [Contributing](../CONTRIBUTING.md) · [PR Template](../.github/PULL_REQUEST_TEMPLATE.md)

## 1. Why 95% of Agent Repositories Become Obsolete Within 6 Months

- **Prompt Roleplay & Checklists Die First**: Absorbed into frontier RL post-training weights and official slash commands, turning verbose `AGENTS.md` walls into latency and attention taxes.
- **Heavy Orchestration Wrappers Die Second**: Official CLIs (`codex`, `opencode`, `pi`, `claude`, `agy`, `qwen`, `gemini`, `grok`, `hermes`, `openclaw`) natively own conversation loops and subagents.
- **Lossy Vector RAG Wrappers Die Third**: Replaced by exact structural maps and fast deterministic search without Docker/API-key overhead.

**Core Thesis**: Build **zero-slop, sub-20ms Pure-Rust physical instruments (`ap` / `ap.exe`)**—exposed via both **Unix CLI** and **Model Context Protocol (`ap mcp`)**—strictly at the **boundaries where autoregressive token generation collides with OS/AST/Binary/Network/Browser reality**.

---

## 2. The Four Irreducible Cognitive & Physical Boundaries (`v2.47`)

| Boundary in `<thinking>` & OS Reality | Observed Waste Across `113k+` Local Calls & Live `<thinking>` Streams | Our Pure-Rust Organ & Open-Source Best-of-Breed Synthesis (`v2.47`) |
| :--- | :--- | :--- |
| **1. Cold-Start Entropy, Binary Blindness & Dead-Slop Contamination** | `30k+` outputs `>8 KB`; `10k–35k` thinking chars guessing host runtimes; `650+` raw `ls` dumps; writing brittle `node -e`/`python -c` scripts for Office/PDF/SQLite/`.asar`/PE/ELF/Java/.NET/Protobuf/SourceMaps/JWT/Markdown sections or missing structural AST search & temporal co-change history. | **`ap ls`** (bounded depth/MSYS2 path fix) + **`ap-atlas`** (Aider **Personalized PageRank**, `<60ms` guard-aware 9-axis `surface --include-binaries`, `<25ms` `locate`, `<30ms` `trace`/`changes`/`history` w/ symbol blame & co-change coupling, `product` `#id`/API contract & slop radar) + **`ap read`** (`--section`/`--around`/C++ `--outline`) / **`ap search`** (`--ast` structural metavar/kind patterns, `-F`/`-i`/`--max`/`--include`/`--code-only --no-tests`) / **`ap query`** + **`ap-sieve`** (`-98.8%` logs, FTS5 `search`/`peek`, 300-line error storm cap) + **`ap-probe slice`** |
| **2. Cross-File Working-Memory Drift, Edit Mismatches & Shell Quoting** | Dropping HTML `#id` ↔ JS selectors across files; `735+` patch mismatches on indent/blank-line drift; `528+` Windows PowerShell `$_` stripping/`rg` regex/UTF-8/long-`PATH` crashes. | **`ap-splice`** (`view`, `rename` ignoring comments/strings, Aider 3-tier + Tier-4 blank-line-resilient & Hashline `L:HH\|` `apply`, `<5ms` cross-file linker & `PostToolUse` `check --hook`, `ap undo`) + **`ap exec`** (UTF-8 lock, `cd &&` prefix accel, PS single-quote auto-heal, slow `grep -rl`/`rg -F` auto-heal, Win32 Job Objects) + **`ap mcp`** (**MCP `2025-11-25`/`2025-06-18`**, `37` typed `outputSchema` tools + 11-harness TOML/JSON wiring) |
| **3. Verification Tax, Live Network/Browser QA & Heap Guessing** | **`71%–75%` of vanilla turns** burned on hung Windows servers, orphaned ports, 150-line browser/WS/HTTP AuthZ/CORS scripts, vacuous tests, and missed test mutations. | **`ap-probe`** (`smoke` w/ ephemeral `PORT`, `ui` desktop/mobile layout & network audit, non-destructive `cdp --watch-ms`, `http --principal/--principal-cdp/--cors-origin/--select/--race/--batch-stdin`, RFC 6455 `ws --origin-matrix`, `tls`, `tcp`, `listen`, `ps`, `fs`, AST `mutate`, `fuzz`, `run`/`diff`) + **`ap guard verify --deep`** |
| **4. Prose Rule Amnesia, Doom-Loops, Compaction Wipeout & Runtime KV-Cache Churn** | Models ignore verbose rules under load, burn turns in identical retry loops, hit QuickJS `codemode` `.output.slice()` `TypeError`, lose frontier state after `/compact`, overspend CJK compaction budgets, or bust DeepSeek/provider KV-caches mid-run. | **`ap-guard`** (`<2ms` `exit 2` rules, `sec` C/C++/Java/TS/Py/Go/Rust CWE checks, semantic `diff`, bundle `pack`, `3x` doom-loop breaker) + **`ap-baton`** (`frontier` orthogonal scheduler, `claim` leases, CJK+BM25 `dedup`) + **`ap-recall`** (`3.4ms` BM25) + **`ap pi`** (14-patch Pi v1.5+/v1.6 runtime patcher + `zz-ap-accelerator.ts`) + **`ap audit --maintainer`** (100% offline zero-PII 6-harness friction brief) |

---

## 3. Why Pure Rust (`v2.47`) + Native `ap mcp`?

1. **Compile-Time Safety & Sub-2ms Startup (`Rust > C & Python`)**: Strict ownership, zero `Regex::new` inside inner loops (`OnceLock` DFAs), zero GC pauses, zero external runtime dependencies, and Windows long-`PATH` / UTF-8 / Job-Object hardening built in.
2. **Progressive MCP Discovery & Zero-Brain Access (`ap mcp --profile full|core|deferred`)**: Full **MCP 2025-06-18** stdio JSON-RPC server exposing **37 strongly-typed `outputSchema` tools** by default, OR **`--profile core`** (`8` everyday tools + `ap_discover`/`ap_call`) / **`--profile deferred`** (`2` meta-tools only, eliminating **~94%** of upfront schema token bloat!).
3. **7 Physically Isolated Crates (`0` Sibling Dependencies)**: Every primitive under `crates/ap-*` compiles standalone while linking with root modules into a single `~15 MB` stripped native binary (`390 tokens` total idle skill frontmatter).

---

## 4. Layered Evolution Model: Durable Universal Core + On-Demand Harness & Model Adapters

`ap` intentionally separates **durable universal primitives**, **cross-harness empirical logs**, and **on-demand adapters** so capability grows without turning into a fragile framework monolith:

```text
Layer 3 · On-Demand Adapters   --> 11-harness TOML/JSON MCP & hooks (`ap init -a <harness>`, `ap pi patch`)
                                    + Model-tier profiles (`--profile core|deferred`, KV-cache & sieve tuning)
Layer 2 · Empirical Telemetry  --> Real execution friction logs across diverse harnesses & models
                                    (distilled offline via zero-PII `ap audit --maintainer`)
Layer 1 · Universal `ap` Core  --> Pure-Rust physical instruments: Read, Search, SQLite, Binary/Archive,
                                    AST Edit, HTTP/WS/CDP/Win Probe, OS Shield, Verification, `ap mcp`
```

### Three Engineering Boundary Rules

1. **Upstream the General, Isolate the Specific**: Whenever real multi-harness or multi-model logs expose friction that applies broadly—Windows/MSYS2 quoting, UTF-8 encoding, archive/binary/HAR parsing, AST search filtering, verification gates—it graduates into **Layer 1 (`ap` Core)**. Only runtime-internal hooks/patches (like `ap pi patch`) or model-tier economics remain in **Layer 3 Adapters**.
2. **Zero Tax When Unused**: Harnesses you do not install and models you do not run add **zero idle prompt tokens**, **zero startup delay**, and **zero schema bloat** (core idle skill frontmatter stays locked at `390` tokens).
3. **Durable Core, Disposable Adapters**: Physical primitives in **Layer 1** stay valuable regardless of which CLI or model wins next year; **Layer 3** adapters are declarative, idempotent, version-checked (`ap doctor`), and cleanly removable the moment an upstream harness or newer model absorbs the gap.
