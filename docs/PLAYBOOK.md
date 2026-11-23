# Real-World Efficiency Playbook: 1-Command Pure-Rust Setup (`ap` v2.49)

[English](./PLAYBOOK.md) | [简体中文](./PLAYBOOK.zh-CN.md) · [Handbook](./HANDBOOK.md) · [Architecture](./DESIGN.md) · [Contributing](../CONTRIBUTING.md) · [PR Template](../.github/PULL_REQUEST_TEMPLATE.md)

`agent-primitives` (`v2.49`) ships as **one native Rust binary (`ap` / `ap.exe`)** embedding **6 Tree-sitter C grammars** (`Py`/`TS`/`JS`/`Go`/`Rust`/`C`), **bundled SQLite FTS5/BM25**, a **Pure-Rust Interactive Headless Edge/Chrome CDP runner**, a **universal file/binary/archive/network inspector**, and a **full MCP 2025-06-18 (`37`-tool) stdio server (`ap mcp`)**—requiring **zero Python, Node, Playwright, or Rust toolchain on user machines**.

---

## 1. Zero-Config 1-Line Onboarding (15+ Agents)

```bash
# macOS / Linux (auto-detects OpenCode, Qwen, Gemini CLI, Goose, Pi, Codex, Antigravity, Claude, Grok, Cursor, Windsurf, VS Code, OpenClaw, Hermes):
curl -fsSL https://raw.githubusercontent.com/xgbtxy/ap/main/install.sh | sh
```

```powershell
# Windows PowerShell:
curl.exe -fsSL https://raw.githubusercontent.com/xgbtxy/ap/main/install.ps1 | iex
```

```bash
# Onboard ONLY the current directory, pick on-demand Layer 3 adapters, or enable Pi patches:
ap init --here -a opencode --mcp-profile core
ap init -a cursor --mcp-profile deferred --model-profile small
ap profile show                            # View Universal Core + Layer 3 harness/model knobs
ap profile set --model deepseek --apply    # Compose Core + DeepSeek KV/sieve profile on demand
ap profile recommend                       # Suggest adapters from zero-PII local telemetry
ap profile reset                           # Remove declarative profile overrides cleanly
ap pi patch                                # Applies 14 idempotent Pi v1.5+/v1.6 runtime patches

# Clean 1-command uninstall (restores original configs untouched):
ap uninstall          # or: ap uninstall --here
```

### Supported Agents Out-of-the-Box (`$0` Free & Commercial)
- **OpenCode (`opencode`)**: Auto-wires `"agent-primitives"` MCP into `~/.config/opencode/opencode.json` (or repo `opencode.json`). Free models (`opencode/big-pickle`, `glm-5.3-flash-free`, `deepseek-flash`) call native MCP tools with zero shell quoting.
- **Qwen Code (`qwen`) & Google Gemini CLI (`gemini`)**: Auto-wires `"trust": true` MCP config into `~/.qwen/settings.json` & `~/.gemini/settings.json`.
- **Pi (`pi` / `pi-coding-agent`) & Goose (`goose`)**: Syncs `~/.pi/agent/skills/`, `"exposure": "codemode"` in `mcp.json`, zero-prompt-bloat `zz-ap-accelerator.ts`, plus **14 idempotent runtime patches** via `ap pi status|patch|restore`.
- **Claude Code (`claude`), OpenAI Codex (`codex`), Antigravity (`agy`), Grok (`grok`), Cursor, Windsurf, VS Code, Claude Desktop, OpenClaw, Hermes**: Auto-wires MCP (`--mcp-profile full|core|deferred`), minimal routing rules, and `<2ms` `exit 2` / JSON hooks with `rtk`-style test output auto-sieving.

---

## 2. How the 37 MCP 2025-06-18 Tools (`--profile full|core|deferred`) & CLI Primitives Work Together

| Capability Group (`ap mcp` + CLI) | Cognitive / OS Bottleneck Eliminated | Typical Latency |
| :--- | :--- | ---: |
| **Universal Read / Search / SQL** (`ap read`, `ap search --pat`, `ap query`) | Tree-sitter `--symbol`/`--outline` + 12-file batch read; `--code-only --no-tests --exclude` AST search filtering comments/strings/tests; Office/PDF/SQLite/`.asar`/`.map` VLQ; PE32+/ELF64 (`--xref`, mitigations, MS-RPC UUID, Go `.gopclntab`); Java `.class`/`.jar`, `.NET CLR`, `--proto`, `--diff`, `--hex`; JS `--routes`/chunks/`--jwt`/redacted `--secrets`; zero-Python SQLite SQL over `.sqlite`/`.xlsx`/`GBK .csv`. | `1–20 ms` |
| **Orient / Surface / Locate / History** (`ap_orient`, `atlas map/surface/locate/trace/changes/history`) | Personalized PageRank repo map, `<60ms` guard-aware 9-axis surface frontier (source + binaries + web routes), `<25ms` zero-hint fault localization, `<30ms` multi-hop call-chain & Git-diff blast radius, plus `atlas history --symbol` (blame + temporal co-change files). | `6–60 ms` |
| **AST Edit & Post-Edit Hook** (`ap_edit`, `ap splice view/apply/rename/check --hook`, `ap undo`) | Chain-of-resiliency patching (strips accidental read gutters, `@L<start>-L<end>` disambiguation, smart-quote rescue + candidate diagnostics, 4-tier indent/blank-line + Hashline `L:HH\|`), Tree-sitter `rename` ignoring comments/strings, 6-lang + JSON/JSONC/TOML AST gate, `<5ms` `PostToolUse` hook & non-Git snapshots. | `0.7–5 ms` |
| **Runtime, Network & UI QA** (`ap_smoke`, `ap probe smoke/ui/cdp/http/ws/tls/tcp/listen/ps/fs/mutate/fuzz`) | Ephemeral `PORT` + process-tree cleanup; headless Edge/Chrome dual-viewport UI/network audit; non-destructive live `cdp --watch-ms`; single/batch/race/CORS/CDP-session `http` QA; RFC 6455 `ws --origin-matrix`; AST mutation testing & chaos fuzzing. | `0.2–4.5 s` |
| **Deep Verify, Guard, Shell & Sieve** (`ap_verify`, `ap guard verify --deep/sec/diff/pack`, `ap exec`, `ap sieve`) | 1-call fused 6-gate verification (tests + vacuous/`.only` block + OWASP C/C++/Java/TS/Py/Go/Rust `sec` + semantic `diff` + cross-file contracts + active-file `mutate`), `3x` doom-loop breaker, Windows UTF-8/long-`PATH` healing & FTS5 log compression (`-98.8%`). | `<2 ms` (+ tests) |
| **Pi Runtime, Baton & Recall** (`ap pi`, `ap baton frontier/claim/dedup`, `ap recall`) | 12 idempotent Pi v1.5+/v1.6 runtime patches (`codemode` `text()`/`.output` shim, keep-alive, serial shell barrier, CJK compaction, tool-order cache lock), orthogonal exploration frontier, atomic TTL leases, and `3.3ms` CJK+BM25 recall. | `<15 ms` |

---

## 3. Diagnostics & Friction-Driven Maintenance (`ap doctor`, `ap stats`, `ap audit`)

```bash
# 1. Verify environment, compiled grammars, headless Edge/Chrome, agent wiring & Pi patch parity:
ap doctor

# 2. View 100% offline prevented crashes, filtered noise & token savings:
ap stats

# 3. Compare agent waste across harnesses (0 bytes uploaded):
ap audit --compare

# 4. Generate a 100% local, zero-PII numeric Friction-to-Source Brief for co-maintainers (6 harnesses):
ap audit --maintainer
```

Want to co-maintain `ap` with your own AI using our 4-source recursive loop & reviewer-first PR spec? Read **[CONTRIBUTING.md](../CONTRIBUTING.md)** and **[.github/PULL_REQUEST_TEMPLATE.md](../.github/PULL_REQUEST_TEMPLATE.md)**.
