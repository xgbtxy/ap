<div align="center">
  <img src="./assets/logo.svg" width="60" height="60" alt="ap logo" />
  <h1>ap</h1>
  <p><strong>Make AI coding &amp; desktop agents 2x faster &amp; rock-solid on Windows &amp; macOS — by fixing where LLM <code>&lt;thinking&gt;</code> trips over reading files, running commands, editing, and verifying.</strong></p>
  <p>
    <a href="https://github.com/xgbtxy/ap/actions/workflows/ci.yml"><img src="https://github.com/xgbtxy/ap/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
    <a href="https://github.com/xgbtxy/ap/releases/latest"><img src="https://img.shields.io/github/v/release/xgbtxy/ap?color=22c55e&label=download" alt="Latest Release" /></a>
    <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-0ea5e9" alt="Platform" />
    <img src="https://img.shields.io/badge/dependencies-0%20(single%20Rust%20binary)-f59e0b" alt="Zero Dependencies" />
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-64748b" alt="MIT License" /></a>
  </p>
  <p>
    <strong>English</strong> · <a href="./README.zh-CN.md"><strong>简体中文</strong></a> · <a href="./CONTRIBUTING.md"><strong>Co-Maintain / Contribute</strong></a> · <a href="./docs/HANDBOOK.md">Core R&amp;D Philosophy</a> · <a href="https://github.com/xgbtxy/ap/releases/latest">Prebuilt Downloads</a>
  </p>
  <img src="./assets/hero-comparison.svg" width="100%" alt="Without ap vs With ap comparison" />
</div>

---

## Install in 10 Seconds, Then Forget About It

No `Python`, no `Node`, no `Playwright`, no `Docker`, and **zero new commands to memorize**. One line installs the native `ap` binary and automatically wires your AI Desktop Assistants, IDEs &amp; CLIs (`Claude Desktop`, `OpenClaw`, `Hermes`, `Cursor`, `Windsurf`, `VS Code`, `Claude Code`, `Codex`, `OpenCode`, `Gemini CLI`, `Qwen Code`, `Pi`, `Goose`, `Antigravity`, `Grok`):

**Windows (PowerShell):**
```powershell
curl.exe -fsSL https://raw.githubusercontent.com/xgbtxy/ap/main/install.ps1 | iex
```

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/xgbtxy/ap/main/install.sh | sh
```

> **Prefer direct download?** Grab the standalone binary (**[Windows x64 `.zip`](https://github.com/xgbtxy/ap/releases/latest/download/ap-x86_64-pc-windows-msvc.zip)** · **[macOS Apple Silicon](https://github.com/xgbtxy/ap/releases/latest/download/ap-aarch64-apple-darwin.tar.gz)** · **[macOS Intel](https://github.com/xgbtxy/ap/releases/latest/download/ap-x86_64-apple-darwin.tar.gz)** · **[Linux x64](https://github.com/xgbtxy/ap/releases/latest/download/ap-x86_64-unknown-linux-musl.tar.gz)**) and run `ap init`. Remove cleanly anytime via `ap uninstall`.

---

## Why We Built `ap`: Fixing Where AI `<thinking>` Derails

Saving tokens is **not** the primary goal—it is a natural byproduct.

When we audited **101,108 real tool calls** and raw `<thinking>` traces across coding agents on Windows and macOS, we found that models rarely fail because they "lack intelligence." They get slow, confused, and write sloppy code because **4 real-world bottlenecks hijack their working memory**:

| Where AI `<thinking>` Gets Stuck | What Happens Without `ap` | How `ap` Solves It Automatically (Under the Hood) |
| :--- | :--- | :--- |
| **1. AST Symbol/Batch Reading, Binary/Archive/Web Inspection, Multi-Pattern Search &amp; SQL**<br>*(General, Frontend, Native, Desktop &amp; Coding Agents)* | Chokes on `.docx`/`.xlsx`/`.map`/`.asar`/`.vsix`/`.jar`/PE/ELF imports &amp; XREFs (no `pefile`/`javap`/`protoc`/`xxd` on Windows), wastes serial turns reading 5 files or guessing line numbers in 2,000-line code files, or hangs on GNU `grep -rn`. | **`ap read`** supports **Tree-sitter `--symbol` / `--outline` + multi-file batch reads (up to 12 files)**, **PE32+/ELF64 (`x64` &amp; `AArch64`) `--xref`/mitigations/MS-RPC UUIDs + Go `.gopclntab` + Java `.class`/`.jar` &amp; `.NET CLR` + `--proto` raw Protobuf + `--diff` patch-diff + `--hex`**, **JS/HTML `--routes` (API routes, lazy webpack chunks, local HTTP/IPC server checks &amp; custom headers), `--jwt` posture, redacted `--secrets`**, Office/PDF/SQLite/`.map` VLQ/`.asar` (up to `256 MB`)/`--json-path`/`--decode`/SPA; **`ap search --pat`** runs parallel multi-core search (up to 20 patterns); **`ap query --json`** emits named `records` across `.sqlite`/`.xlsx`/`GBK` CSVs (`0` Python). |
| **2. Starting Blind, Bug Hunting, Surface Mapping, HTTP/WS QA &amp; Call-Chain Tracing**<br>*(Orientation, Guard-Aware 9-Axis Surface Frontier, Git-Diff Blast Radius &amp; Localization)* | Wastes turns running `ls`/`rg` across 18+ files, hand-rolls brittle `curl`/Python RBAC/CORS/race scripts, loses track of untested axes in long sessions, or updates 2 of 7 callers during a refactor. | **<15 ms** Omni-Workspace X-Ray (`atlas map`), **<60 ms Guard-Aware 9-Axis Surface Map (`atlas surface --include-binaries`)** + **Cross-Session Orthogonal Frontier (`baton frontier`)**, **`ap probe http`** (**`--principal` / `--principal-cdp` 0-tab loopback session QA, `--cors-origin` reflection audit, `--select` JSON path, `--audit-headers`, `--vary-field`, `--race`**) &amp; **`ap probe ws --origin-matrix`**, **<25 ms** Fault Localizer (`atlas locate`), **<30 ms Git-Diff Change Impact Brief (`atlas changes`)** &amp; Multi-Hop Tracer (`atlas trace`). |
| **3. Safe Creation, AST Rename, Diffs, Appends &amp; Undo**<br>*(Cross-File Contracts &amp; Refactoring)* | Hallucinates phantom named imports / wrong argument counts across files, corrupts comments/strings on naive search-replace renames, or re-reads whole files after a 1-char patch typo. | **Tree-sitter AST `ap splice rename`** (ignores comments/strings/substrings + `--dry-run`/`--rollback-on-test-fail`) + **Token-Similarity Closest-Window Patch Diagnostics** + **JSON/JSONC/TOML + 6-lang AST gate** + **<5 ms Cross-File Linker** + **`ap undo`**. |
| **4. Environment Derailment, Slow Grep &amp; Doom Loops**<br>*(Windows/Mac Shell &amp; Compiler/Test Noise)* | Trained on Linux Bash, the model hits **`528+` Windows OS/shell crashes**, 60s+ GNU `grep -rn` stalls, ANSI-bloated 40KB compiler/test logs, and repetitive retry doom-loops. | Transparent **Base64 Hook + `ap exec`** accelerates `grep -rn` → `<50ms` parallel `ap search`, fixes raw-string-safe `python -c` paths, locks UTF-8, reaps orphans via **Win32 Job Objects**, strips ANSI to digest **`compiler`/`test`/`diff`** logs 95%+, and adds **stateful 3x doom-loop circuit-breaking**. |
| **5. Deep Verification, Full MCP 2025-06-18, `ap audit --maintainer` &amp; Pi v1.5+ Accelerator**<br>*(36 Typed `outputSchema` MCP Tools + `ap pi` 11-Patch Runtime Patcher + Zero-PII Self-Evolution + 50:1 KV-Cache Physics)* | Ships broken syntax/`.skip`/`todo!()` stubs, fails `edit` on duplicate lines or indent drift, races parallel `bash`+`read` calls, overshoots CJK compaction budgets 2–3x, busts 50:1 prefix caches via mid-run `context_edit` / effort-flip / MCP tool-order jitter, or crashes on `text(x).slice()` in `codemode`. | **Full MCP 2025-06-18** (`36` annotated tools with typed **`outputSchema`** + `structuredContent` + live Resources + `5` Prompts), **`ap pi status\|patch\|restore`** (idempotent **11-patch** Pi v1.5+ runtime patcher incl. `codemode` `text()` return value, 15s/28s keepAlive + 250ms Happy-Eyeballs, `before_agent_start` clean-slate `entries`, Windows UTF-8, `sleep(ms)` + Web builtins, sequential shell barrier, CJK-calibrated compaction, and deterministic tool order), **`ap guard verify --deep`** + **`ap guard sec`** (C/C++/Java/TS/Py/Go/Rust) + **`ap guard diff`**, **`ap doctor`**, **`ap audit --maintainer`** (100% local, zero-PII friction-to-source brief across 6 agent harnesses), and **Pi `zz-ap-accelerator.ts`**. |

---

## How Do I Use It? (Zero Workflow Change)

1. **Just talk to your coding agent in plain language**—even a 1-sentence beginner request on a `$0` free agent works out of the box.
2. **Whenever you want to inspect the efficiency gains**, run **`ap stats`** (or `ap doctor` for an environment check):

```text
$ ap stats
[ap stats] Coding-Agent Efficiency & Thinking-Flow Ledger (100% offline)
------------------------------------------------------------------------
  Accelerated Agent Steps      : 28 actions
  Thinking Derailments Healed  : 11 Windows/shell crashes prevented before retry loops
  1-Shot Edits & Browser Gates : 14 verified (Tree-sitter AST + Headless Edge/Chrome + 0-slop)
  Working-Memory Noise Filtered: 612.4 KB -> 19.2 KB (-96.9% log/context clutter)
  Byproduct Token Savings      : ~186,800 wasted tokens avoided
```

---

## Real Windows 11 End-to-End Results (Zero Fabrication)

Measured head-to-head on Windows 11 across `$0` free coding agents and commercial CLIs on beginner 1-sentence prompts, full-stack upgrades (`WorkPulse`), and empty-directory random projects (`SplitMate`):

| Coding Agent & Real Task | Without `ap` → **With `ap`** (Speed & Steps) | Code Quality & Self-Correction | Wasted Tokens Avoided |
| :--- | :--- | :---: | :--- |
| **`OpenCode` Free (`$0` `big-pickle`)** · *1-Sentence Prompt* | `430.2s` (`60` calls) → **`182.4s` (`23` calls, 2.36x faster)** | `7/8` *(left `empty-catch`)* → **`8/8` (`0` slop)** | **`-75.1%`** (`1.61M → 402k`) |
| **`Codex` (General Office · No Python)** · *`.docx` + `.xlsx` + `GBK .csv`* | `70.5s` *(binary dump + failed py)* → **`46.5s` (1.52x faster)** | **`5/5` → `5/5`** *(0 binary/GBK crashes via `ap read`)* | **`-54.3%`** (`127k → 58k`) |
| **`Codex` (Data &amp; SPA Audit)** · *2,500-Row 2-Sheet `.xlsx` + `GBK .csv` + JS SPA* | `118.4s` *(5x custom XML/py scripts)* → **`94.3s` (1.26x faster)** | **`5/5` → `5/5`** *(cent-exact SQL join + Edge SPA render)* | **`-35.1%`** (`212k → 138k`) |
| **`Codex` (Full-Stack + SQLite Ops · No Python)** · *`.sqlite` + 3,000-Row `.xlsx` + `.log.gz` + JS Bug* | `112.0s` *(.NET ZIP + 4x custom scripts)* → **`94.3s` (1.19x faster)** | **`6/6` → `6/6`** *(1-shot `.gz` `[FATAL]` + SQLite↔XLSX join + `APPEND`)* | **`-28.7%`** (`235k → 167k`) |
| **`Codex` (Native PE DLL + Live TCP Worker + FS Diff + Webhook)** · *PE32+ Exports/Imports/Hex + Cmdline/TCP + Atomic FS Diff + Callback Capture* | `77.70s` *(120-line custom `struct`/socket/HTTP Python script)* → **`73.23s` (1.06x faster, 1-shot PE analysis)** | **`4/4` → `4/4`** *(1-call `ap read *.dll` SHA-256 + exports/imports; worker process untouched)* | *Zero custom PE/ELF parser needed* |
| **`Codex` (Batch Diagnostics + Async CDP Watch)** · *180KB Minified 3-Offset Slice + 5x HTTP Batch + Live CDP Async Console/Network + Quorum Fix* | `89.12s` (`10` calls, custom `capture-audit.mjs`) → **`83.92s` (`8` calls, -20% steps, 0 custom scripts)** | **`5/5` + `--deep` PASS** *(host browser kept alive; 1-shot `--offset`, `probe http --batch-stdin`, `probe cdp --watch-ms`)* | **`-6.0%`** (`135k → 127k`) |
| **`Codex` (Prod SourceMap + JWT Incident Fix)** · *SourceMap v3 VLQ + 500-Line JSONL JWT + Git Diff Gate* | `106.05s` *(custom VLQ + JWT + mutation scripts)* → **`94.36s` (1.12x faster)** | **`5/5` + `100%` Mutation** *(1-shot `--map-pos` + 5-gate `--deep` w/ `guard diff`)* | *Zero custom VLQ / diff audit scripts* |
| **`Codex` (Desktop App &amp; Live CDP Audit)** · *`.asar` + 180KB Minified JS + PE UTF-16LE + Live CDP + 3-Hop Trace* | `98.88s` *(custom Node/WS/ASAR scripts)* → **`83.43s` (1.19x faster, 0 custom scripts)** | **`5/5` → `5/5`** *(`15` vs `4` unit tests + `--deep` PASS, host browser kept alive)* | **`-17.8%`** (`146k → 120k`) |
| **`Codex` (From-Scratch Full-Stack Security &amp; UI)** · *`EventDesk` (SQLite + Desktop/Mobile UI + XSS + Fuzz)* | `0` custom browser scripts *(replaced hand-rolled `test/browser.mjs` via `probe ui` + `smoke`)* | **Mutation Kill Rate: `62.5%` (`5/8`) → `100.0%` (`8/8`)**, **`5/5` (`0` OWASP / `0` 404 / `0` overflow)** | *6-gate proof receipt cut calls `-30.8%` (`13→9`)* |
| **`Codex` (Zero-Hint 18-Module Fault Hunt)** · *`CommerceCore` Voucher Regression (0 File Hints)* | `123.37s` → **`107.59s` (1.15x faster, 1-shot `atlas locate` + `--deep`)** | **`5/5` + `100%` Mutation** *(verified callers via `atlas impact` + active-file `--deep`)* | **`-7.2%`** (`111k → 103k`) |
| **`Codex` (From-Scratch Creation &amp; Deep Test)** · *`FlashVault` Concurrency &amp; Wallet API* | `7` fused calls via `guard verify --deep` | **Test Mutation Kill Rate: `62.5%` (`5/8`) → `100.0%` (`8/8` killed, `10/10` black-box)** | *Killed all 3 surviving boundary/logic bugs* |
| **`Codex` (False-Green Repo Hardening)** · *`OrderGate` Hidden `.only` + `500` Crash + Off-by-1* | `200.6s` → **`183.2s` (faster w/ 5-gate audit)** | **`6/6` + `100%` Mutation + `100%` Chaos Fuzz** *(caught live `500` crash &amp; `.only`)* | *Fused 5 verification gates into 1 pass* |
| **`Codex CLI` (`gpt-6-astra`)** · *14-File Multi-Module Refactor* | `151.6s` → **`96.6s` (1.57x faster)** | **`7/7` → `7/7`** *(all 5 AST callers + Edge UI synced)* | **`-57.4%`** (`296k → 126k`) |
| **`Codex CLI` (`gpt-6-astra`)** · *From-Scratch Random App* | `345.3s` (`23` calls) → **`244.6s` (`9` calls, -61% steps)** | **`6/6` → `6/6`** *(1-shot Edge CDP check)* | **`-83.3%`** (`1.12M → 186k`) |
| **`Codex CLI` (`gpt-6-astra`)** · *Full-Stack Upgrade* | `333.6s` (`24` calls) → **`294.3s` (`11` calls, -54% steps)** | **`8/8` → `8/8`** | **`-65.4%`** (`1.05M → 365k`) |
| **`Pi CLI` (`deepseek-flash`)** · *Full-Stack Upgrade* | `483.0s` (`81` calls) → **`271.5s` (`70` calls, 1.78x faster)** | **`8/8` → `8/8`** *(`-42.7%` `<thinking>` churn)* | **`-36.7%`** (`3.63M → 2.30M`) |
| **`Pi CLI` (`deepseek-flash`)** · *From-Scratch Random App* | `1,821.1s` → **`1,499.3s` (322s faster)** | `5/6` *(2x silent `catch {}`)* → **`6/6` (`0` slop)** | *Model ran extra subset-sum fuzzer* |

<details>
<summary><strong>For Systems Engineers: Pure-Rust Architecture, Micro-Benchmarks &amp; R&amp;D Docs</strong></summary>

<br/>

- **Zero-Coupling Single Binary**: 1 native Rust binary backed by 7 isolated crates (`crates/ap-{atlas,splice,probe,sieve,guard,recall,baton}`) with `0` sibling crate dependencies, bundled SQLite FTS5, 6 compiled Tree-sitter C grammars (Py/TS/JS/Go/Rust/C), and `390` total idle frontmatter tokens.
- **Reproduce Micro-Benchmarks**: Run `ap bench` (see [`bench/results.json`](./bench/results.json)).
- **Engineering Docs**:
  - [Co-Maintaining `ap` from Local Friction Logs (`CONTRIBUTING.md`)](./CONTRIBUTING.md) | [共同维护指南 (`CONTRIBUTING.zh-CN.md`)](./CONTRIBUTING.zh-CN.md)
  - [Core R&D Philosophy & Evolution (`docs/HANDBOOK.md`)](./docs/HANDBOOK.md) | [中文研发手册 (`docs/HANDBOOK.zh-CN.md`)](./docs/HANDBOOK.zh-CN.md)
  - [System Architecture (`docs/DESIGN.md`)](./docs/DESIGN.md) | [架构设计 (`docs/DESIGN.zh-CN.md`)](./docs/DESIGN.zh-CN.md)
  - [Workflow Playbook (`docs/PLAYBOOK.md`)](./docs/PLAYBOOK.md) | [实战手册 (`docs/PLAYBOOK.zh-CN.md`)](./docs/PLAYBOOK.zh-CN.md)
  - [Pi Runtime Maintenance (`docs/PI_RUNTIME.md`)](./docs/PI_RUNTIME.md) | [Pi 运行时维护 (`docs/PI_RUNTIME.zh-CN.md`)](./docs/PI_RUNTIME.zh-CN.md)

</details>

## Privacy, Scope & Responsible Use

- **100% Local & Offline Telemetry**: `ap stats` and `ap audit --maintainer` run strictly locally with zero cloud uploads; `ap audit --maintainer` emits anonymized numeric friction counters only (never prompts, code, file paths, or credentials).
- **Responsible Engineering Scope**: `ap` is built exclusively for software engineering, debugging, QA verification, and authorized defensive security/configuration hygiene on systems you own or have permission to test. Do not misuse it for unauthorized access or harmful activity. See [CONTRIBUTING.md](./CONTRIBUTING.md) to co-maintain `ap` safely with your own AI agent.

## License

[MIT](./LICENSE)
