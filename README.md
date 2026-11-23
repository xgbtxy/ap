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

> **Prefer direct download?** Grab the standalone binary (**[Windows x64 `.zip`](https://github.com/xgbtxy/ap/releases/latest/download/ap-x86_64-pc-windows-msvc.zip)** · **[macOS Apple Silicon](https://github.com/xgbtxy/ap/releases/latest/download/ap-aarch64-apple-darwin.tar.gz)** · **[macOS Intel](https://github.com/xgbtxy/ap/releases/latest/download/ap-x86_64-apple-darwin.tar.gz)** · **[Linux x64](https://github.com/xgbtxy/ap/releases/latest/download/ap-x86_64-unknown-linux-musl.tar.gz)** · **[Linux ARM64](https://github.com/xgbtxy/ap/releases/latest/download/ap-aarch64-unknown-linux-gnu.tar.gz)**) and run `ap init`. Remove cleanly anytime via `ap uninstall`.

---

## Why We Built `ap`: Fixing Where AI `<thinking>` Derails

Saving tokens is **not** the primary goal—it is a natural byproduct.

When we audited **101,108 real tool calls** and raw `<thinking>` traces across coding agents on Windows and macOS, we found that models rarely fail because they "lack intelligence." They get slow, confused, and write sloppy code because **5 real-world bottlenecks hijack their working memory**:

| Where AI `<thinking>` Gets Stuck | What Happens Without `ap` | How `ap` Solves It Automatically (Full CLI Ref: [Playbook](./docs/PLAYBOOK.md)) |
| :--- | :--- | :--- |
| **1. Reading &amp; Searching Code, Data &amp; Binaries**<br>*(AST, Office, Archives, PE/ELF, JS)* | Chokes on Word/Excel/PDF/SQLite/`.asar`/binaries without `python`/`pefile`, drowns in comment/test hits on search, or hangs on GNU `grep -rn`. | **`ap ls` / `ap read` / `ap search` / `ap query`**: Bounded `ap ls --depth`; `--section`/`--around`/`--symbol`/C++ `--outline` &amp; 12-file batch reads; `--ast` structural metavar/kind patterns (`fetch($URL, $$$)`, `$X == $X`), `-o`/`-u`/`--no-filename`/`-F`/`--include`/`--code-only --no-tests` AST search; PE/ELF/Java/.NET/Proto &amp; JS `--routes`/`--jwt`/`--secrets`; zero-Python SQLite SQL. |
| **2. Orientation, Surface, History &amp; Browser/API QA**<br>*(Mapping, Deps, Dead-Code, HTTP/WS)* | Blind `ls`/`rg` across modules, missing cross-file import/cycle graphs, accumulating orphan files &amp; ghost exports, or hand-rolled QA scripts. | **`ap atlas` + `ap probe`**: `<15 ms` PageRank map, `<40 ms` `atlas deps --dead` (outbound imports, inbound blast radius, cycles, orphan files &amp; unused exports), `<60 ms` 9-axis surface frontier, `<25 ms` fault localization, `atlas changes` selective tests, &amp; CDP/HTTP/WS checks. |
| **3. Safe Creation &amp; Multi-File Refactors**<br>*(Codex Diffs, AST Codemod &amp; Checkpoints)* | Naive find-replace corrupts comments/strings, multi-hunk diffs fail on duplicate blocks, or edits lack named checkpoints &amp; diff previews. | **`ap splice` + `ap undo`**: `*** Begin Patch` + hunk-window unified diffs + `@L` line hints + smart-quote rescue, Tree-sitter `rename` &amp; `rewrite` (`, $$$ARGS` elision), 6-lang+JSON/TOML AST gate, `<5 ms` `PostToolUse` hook, plus named `ap undo --save/--diff/--keep`. |
| **4. OS Quoting Crashes, Slow Grep &amp; Doom Loops**<br>*(Windows/Mac Shell &amp; Log Noise)* | Hits **`528+` Windows OS/shell crashes** (GBK/BOM, PS `&&`, `rg` errors, `dir /b`, `sed -n`, `Select-String`, `Get-Content`, `Get-ChildItem`, slow `grep`) &amp; log floods. | **`ap exec` + `ap sieve` + `ap guard`**: Transparent hook fixes UTF-8, `curl.exe`, PS `$var` quoting, `dir /b` &amp; `Get-ChildItem -> ap ls`, `Get-Content`/`sed -n -> ap read --lines`, `Select-String`/`grep -rhoE -> ap search`, `rg -F`, log compression **-98.8%**, &amp; `3x` loop-breaker. |
| **5. Deep Verification, Progressive MCP &amp; Pi Cache**<br>*(6-Gate QA, Progressive MCP, 14 Pi Patches)* | Burns **11k+ schema tokens/turn** dumping all 37 MCP schemas, ships vacuous tests/OWASP bugs, or busts KV-caches mid-run. | **MCP 2025-06-18 (`--profile full\|core\|deferred` w/ `ap_discover`+`ap_call`)** + **`ap guard verify --deep`** + **`ap pi`** (14 idempotent Pi v1.5+/v1.6 runtime patches) + **`ap audit --maintainer`**. |

---

## Architecture &amp; Direction: Universal Core + On-Demand Harness &amp; Model Adapters

```text
+-------------------------------------------------------------------+
|  3. On-Demand Adapters (Selected per Harness x Model Family)      |
|     - Harness hooks/MCP wiring: `ap init -a <harness>` / profiles |
|     - Declarative profile CLI: `ap profile show|set|recommend|reset` |
|     - Optional runtime patches: `ap pi patch` (Pi v1.5+/v1.6)    |
|     - Model-tier economics: KV-cache TTL keep, sieve limits,      |
|       `--profile core|deferred` schema slimming                   |
+-------------------------------------------------------------------+
|  2. Empirical Driver: Real Harness &amp; Model Execution Telemetry    |
|     - Offline zero-PII process logs (`ap audit --maintainer`)     |
|     - Pinpoints where real agents stall across harnesses &amp; models |
+-------------------------------------------------------------------+
|  1. Universal Core (`ap` / `ap.exe` Single Pure-Rust Binary)      |
|     - Model- &amp; harness-agnostic physical primitives: files, AST,  |
|       binaries/archives, SQLite, HTTP/WS/CDP, OS shield, `ap mcp` |
+-------------------------------------------------------------------+
```

- **Universal Core First**: Keep durable physical primitives—reading/searching code, docs, binaries &amp; archives, Tree-sitter AST navigation &amp; safe patching, OS/shell quoting recovery, SQLite SQL, and browser/API verification—inside one dependency-free Rust core usable everywhere via CLI and `37` typed `ap mcp` tools.
- **Driven by Multi-Harness &amp; Multi-Model Reality**: Prioritize work from empirical execution friction logs across real harnesses (`Claude Code`, `Codex`, `Pi`, `OpenCode`, `Cursor`, `Gemini CLI`, `Antigravity`, `Grok`, etc.) and model tiers via offline, zero-PII `ap audit --maintainer` rather than speculative prompting.
- **Composed On Demand**: End users run **Universal `ap` + only the adapters for their chosen harness and model** (e.g., `ap init -a <harness>`, `ap pi patch`, or `--profile deferred`), incurring zero token or runtime tax for unused frameworks and allowing adapters to retire cleanly as upstream hosts or models evolve.

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

Measured head-to-head on Windows 11 across `$0` free coding agents and commercial CLIs on beginner 1-sentence prompts, legacy refactors, non-coding office tasks, and empty-directory random apps:

| Coding Agent & Real Task | Without `ap` → **With `ap`** (Speed & Steps) | Code Quality & Self-Correction | Wasted Tokens Avoided |
| :--- | :--- | :---: | :--- |
| **`OpenCode` Free (`$0` `big-pickle`)** · *1-Sentence Prompt* | `430.2s` (`60` calls) → **`182.4s` (`23` calls, 2.36x faster)** | `7/8` *(left `empty-catch`)* → **`8/8` (`0` slop)** | **`-75.1%`** (`1.61M → 402k`) |
| **`Codex` (General Office · No Python)** · *`.docx` + `.xlsx` + `GBK .csv`* | `70.5s` *(binary dump + failed py)* → **`46.5s` (1.52x faster)** | **`5/5` → `5/5`** *(0 binary/GBK crashes via `ap read`)* | **`-54.3%`** (`127k → 58k`) |
| **`Codex CLI` (`gpt-6-astra`)** · *14-File Multi-Module Refactor* | `151.6s` → **`96.6s` (1.57x faster)** | **`7/7` → `7/7`** *(all 5 AST callers + Edge UI synced)* | **`-57.4%`** (`296k → 126k`) |
| **`Codex CLI` (`gpt-6-astra`)** · *From-Scratch Random App* | `345.3s` (`23` calls) → **`244.6s` (`9` calls, -61% steps)** | **`6/6` → `6/6`** *(1-shot Edge CDP check)* | **`-83.3%`** (`1.12M → 186k`) |
| **`Pi CLI` (`deepseek-flash`)** · *Full-Stack Upgrade* | `483.0s` (`81` calls) → **`271.5s` (`70` calls, 1.78x faster)** | **`8/8` → `8/8`** *(`-42.7%` `<thinking>` churn)* | **`-36.7%`** (`3.63M → 2.30M`) |

<details>
<summary><strong>Show all 12 specialized Windows 11 benchmarks (SQL/SPA, PE/ELF, CDP/HTTP, SourceMap, Mutation &amp; Creation)</strong></summary>

<br/>

| Coding Agent & Real Task | Without `ap` → **With `ap`** (Speed & Steps) | Code Quality & Self-Correction | Wasted Tokens Avoided |
| :--- | :--- | :---: | :--- |
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
| **`Codex CLI` (`gpt-6-astra`)** · *Full-Stack Upgrade* | `333.6s` (`24` calls) → **`294.3s` (`11` calls, -54% steps)** | **`8/8` → `8/8`** | **`-65.4%`** (`1.05M → 365k`) |
| **`Pi CLI` (`deepseek-flash`)** · *From-Scratch Random App* | `1,821.1s` → **`1,499.3s` (322s faster)** | `5/6` *(2x silent `catch {}`)* → **`6/6` (`0` slop)** | *Model ran extra subset-sum fuzzer* |

</details>

---

## Co-Maintain `ap` With Your Own AI

`ap` improves through a **4-Source Recursive Self-Improvement Loop**: (1) survey external community issues &amp; mature OSS tools, (2) measure local execution friction (**100% offline, zero private data**), (3) craft minimal Pure-Rust primitives, and (4) prove real Before-vs-After gains via a reviewer-first PR map:

```bash
# Preview your local zero-PII numeric bottlenecks mapped to ap source files (6 harnesses; safe to inspect first):
ap audit --maintainer
```

- **Want your AI to co-maintain with you?** Grab the ready-to-paste prompt in **[CONTRIBUTING.md](./CONTRIBUTING.md)** (includes privacy-first opt-outs if you prefer not to scan raw local logs + strict anti-misuse guardrails).
- **Submitting a PR?** Use **[.github/PULL_REQUEST_TEMPLATE.md](./.github/PULL_REQUEST_TEMPLATE.md)** — it requires an exact `file:symbol/line` Change Map and Before/After table so maintainers can review and merge in minutes.

---

<details>
<summary><strong>For Systems Engineers: Pure-Rust Architecture, Micro-Benchmarks &amp; R&amp;D Docs</strong></summary>

<br/>

- **Zero-Coupling Single Binary**: 1 native Rust binary backed by 7 isolated crates (`crates/ap-{atlas,splice,probe,sieve,guard,recall,baton}`) with `0` sibling crate dependencies, bundled SQLite FTS5, 6 compiled Tree-sitter C grammars (Py/TS/JS/Go/Rust/C), and `390` total idle frontmatter tokens.
- **Reproduce Micro-Benchmarks**: Run `ap bench` (see [`bench/results.json`](./bench/results.json)).
- **Engineering Docs**:
  - [Co-Maintaining `ap` &amp; 4-Source Recursive Prompt (`CONTRIBUTING.md`)](./CONTRIBUTING.md) | [共同维护指南 (`CONTRIBUTING.zh-CN.md`)](./CONTRIBUTING.zh-CN.md) | [PR Spec (`.github/PULL_REQUEST_TEMPLATE.md`)](./.github/PULL_REQUEST_TEMPLATE.md)
  - [Core R&amp;D Philosophy &amp; Evolution (`docs/HANDBOOK.md`)](./docs/HANDBOOK.md) | [中文研发手册 (`docs/HANDBOOK.zh-CN.md`)](./docs/HANDBOOK.zh-CN.md)
  - [System Architecture (`docs/DESIGN.md`)](./docs/DESIGN.md) | [架构设计 (`docs/DESIGN.zh-CN.md`)](./docs/DESIGN.zh-CN.md)
  - [Workflow Playbook (`docs/PLAYBOOK.md`)](./docs/PLAYBOOK.md) | [实战手册 (`docs/PLAYBOOK.zh-CN.md`)](./docs/PLAYBOOK.zh-CN.md)
  - [Pi Runtime Maintenance (`docs/PI_RUNTIME.md`)](./docs/PI_RUNTIME.md) | [Pi 运行时维护 (`docs/PI_RUNTIME.zh-CN.md`)](./docs/PI_RUNTIME.zh-CN.md)

</details>

## Privacy, Scope & Responsible Use

- **100% Local & Offline Telemetry**: `ap stats` and `ap audit --maintainer` run strictly locally with zero cloud uploads; `ap audit --maintainer` emits anonymized numeric friction counters only (never prompts, code, file paths, or credentials).
- **Responsible Engineering Scope & Anti-Misuse**: `ap` is built exclusively for software engineering, debugging, QA verification, and authorized defensive security/configuration hygiene on systems you own or have permission to test. Do not misuse it for unauthorized access or harmful activity.

## License

[MIT](./LICENSE)
