# Pi Coding Agent Runtime Maintenance (`ap pi` + `zz-ap-accelerator.ts`)

`ap` maintains both the zero-prompt-overhead Pi extension (`zz-ap-accelerator.ts`, installed via `ap init -a pi --with-hooks --no-rules`) and a pure-Rust, idempotent runtime patcher (`ap pi`) for `@earendil-works/pi-coding-agent` v1.5+.

## Commands

```bash
# Inspect detected @earendil-works/pi-coding-agent package, backup state, and patch status
ap pi status

# Apply all 22 generic runtime patches idempotently (originals backed up to ~/.ap/pi-backups/<version>/)
ap pi patch

# Preview without modifying files
ap pi patch --dry-run

# Restore pristine originals from ~/.ap/pi-backups/<version>/
ap pi restore
```

Pass `--pi-dir <path>` (or set `PI_PACKAGE_DIR`) if Pi is installed in a non-standard location.

## Maintained Generic Pi v1.5+ Runtime Patches (22/22)

1. **`before_agent_start_entries`**: Extends `emitBeforeAgentStart` & `AgentSession._prepareRun` so `before_agent_start` handlers can return `entries?: SessionBoundaryDraft[]` for zero-latency programmatic clean-slate compaction without breaking KV-cache prefix reuse (esbuild identifier-rename resilient).
2. **`windows_python_utf8`**: Auto-injects `PYTHONUTF8=1`, `PYTHONIOENCODING=utf-8`, `LANG=C.UTF-8`, and `LC_ALL=C.UTF-8` into Pi's Windows subprocess environment to eliminate GBK codec crashes.
3. **`codemode_sleep_and_workers`**: Exposes abort-safe `await sleep(ms)` (capped at 30s) inside QuickJS `codemode` scripts and raises `DEFAULT_MAX_CODEMODE_WORKERS` from `2` to `4`.
4. **`http_keepalive_and_transient_retry`**: Adds resilient HTTP keepAlive (`15s` / `28s` / `10s` initial delay), `250ms` Happy-Eyeballs failover, and transient TLS/DNS/socket/gateway retry (`ENOTFOUND`, `EAI_AGAIN`, `ENETUNREACH`, `EHOSTUNREACH`, `fetch failed`, `socket hang up`, `UND_ERR_*`) with jittered exponential backoff.
5. **`virtual_model_cache_warmer`**: Allows virtual models (`api === "pi-virtual"`, such as `deepseek/flash-auto`) to match `CacheWarmer` physical sessions cleanly.
6. **`codemode_web_builtins`**: Injects standard Web/JS builtins (`setTimeout`/`clearTimeout`, `atob`/`btoa`, `TextEncoder`/`TextDecoder`, `Buffer`) into QuickJS `codemode` (bundle worker, execute chunk, and prelude) and stops the wrapper from shadowing prelude globals.
7. **`sequential_shell_tool_barrier`**: Runs `bash`/`powershell` calls sequentially as barriers while keeping adjacent read/search calls parallel (eliminating `bash`+`read` race `ENOENT`s and healing early-break termination drift).
8. **`boundary_compaction_event`**: Emits `session_compact` on extension boundary-draft compactions (in both bundle and unbundled `agent-session.js`) so cache trackers and extensions reset cleanly on auto-rotations.
9. **`cjk_calibrated_compaction_budget`**: Weights CJK/fullwidth characters and calibrates `keepRecentTokens` against provider-reported `prompt_tokens` to prevent 2–3x compaction overshoot.
10. **`deterministic_tool_order`**: Sorts resolved transcript tools deterministically by name so MCP reconnects or reloads never bust prompt KV-cache.
11. **`codemode_text_returns_rendered`**: Returns the rendered string from `codemode`'s `text(value)` helper (both bundle and prelude) to eliminate `TypeError: cannot read property 'slice' of undefined`.
12. **`codemode_result_output_shim`**: Attaches a writable, non-enumerable `.output` string shim on resolved `codemode` tool-result objects (cloning non-extensible/frozen containers via `_cloneExtensible` + pre-lockdown `String.prototype.output`) so `.output.slice(...)` never throws `TypeError` under SES/QuickJS lockdown.
13. **`tool_result_preserve_codemode_structured_content`**: Preserves `structuredContent` on codemode child `tool_result` hooks when extensions rewrite `content` without replacing `structuredContent`.
14. **`windows_utf8_shell_env`**: Locks `PYTHONUTF8=1`, `PYTHONIOENCODING=utf-8`, `LANG=C.UTF-8`, and `LC_ALL=C.UTF-8` on Windows plus cross-platform non-interactive subprocess defaults (`GIT_TERMINAL_PROMPT=0`, `GCM_INTERACTIVE=never`, `GIT_PAGER=cat`, `PAGER=cat`, `GIT_EDITOR=true`, `GIT_MERGE_AUTOEDIT=no`, `PIP_NO_INPUT=1`, `npm_config_yes=true`, all via `??` so explicit user env overrides always win) inside `getShellEnv()` (bundle + `dist/utils/shell.js`).
15. **`codemode_strip_null_tool_args`**: Strips top-level `null` optional fields on QuickJS `tools.*` calls so strict tool schemas never reject explicit `null` arguments.
16. **`codemode_global_log_helper`**: Exposes writable/configurable `globalThis.log(...args)` aliasing `console.log` inside QuickJS `codemode` scripts.
17. **`codemode_mcp_short_aliases`**: Exposes collision-free MCP short aliases (`tools.foo` -> `tools.mcp__server__foo`) and `describeTool()` suffix fallback across worker, prelude, and execute chunks.
18. **`session_before_compact_first_wins`**: Enforces first-non-null compaction ownership in `ExtensionRunner.emit()` (setting `event.compactionClaimed = true` while preserving `cancel: true` preemption and ensuring later truthy non-compaction returns like `{}` or `{ cancel: false }` never wipe out an earlier handler's compaction summary).
19. **`http_dns_stale_cache`**: Injects an LRU 45s fresh-TTL + 10-minute stale-IP coalescing DNS lookup cache onto `EnvHttpProxyAgent`'s plain `connect` options in `configureHttpDispatcher()` (`all: true`/`all: false` + `hints`/`order` safe, case-insensitive host keys, concurrent lookup deduplication, per-lookup single-settlement/re-entrancy guard, snapshotted `opts`, leaving `createUndiciClient()` untouched so HTTP-CONNECT proxy tunnels and keepAlive/timeout options stay intact) to survive transient `ENOTFOUND` / `EAI_AGAIN` / `ETIMEOUT` / `ETIMEDOUT` / `ESERVFAIL` / `EAI_FAIL` / `EAI_NODATA` / `EAI_NONAME` bursts.
20. **`read_eof_clamp`**: Returns a structured `[Offset ... is beyond end of file ...]` notice with `details = { eofClamped: true, totalFileLines }` instead of throwing an uncaught tool error when `read` offset exceeds file length.
21. **`temp_log_cap_and_gc`**: Caps Pi `OutputAccumulator` temp logs at `PI_TEMP_LOG_MAX_BYTES` (default 32 MB) with an explicit cap marker and runs lazy 12-hour GC on stale `pi-bash-*.log` and `pi-codemode-*.txt` files in `os.tmpdir()`.
22. **`windows_bash_cmd_spill`**: Strips embedded NUL bytes and transparently spills >20 KB Windows `bash`/`powershell` command lines to `%TEMP%/pi-cmd-spill/pi-cmd-*.{sh,ps1}` with guaranteed `finally` unlink to prevent `ENAMETOOLONG` / `CreateProcess` command-line truncation (esbuild identifier-rename resilient).

## Multi-Extension Compaction Yield & Dynamic Observation Masking

- **Compaction yield protocol**: `zz-ap-accelerator.ts` still checkpoints `.baton` on `session_before_compact`, then yields its low-reasoning LLM summarization cleanly whenever ANY of the following is true:
  1. `event.compactionClaimed === true` (set automatically by patch #18 `session_before_compact_first_wins`),
  2. `AP_YIELD_COMPACT=1` in the environment,
  3. `"yield_compact": true` (or `"yieldCompact": true`) in `~/.ap/profile.json` (`ap profile set --yield-compact true`), or
  4. A peer extension emitted `"ap:claim_compaction"` on `pi.events`.
- **Dynamic masking calibration**: `zz-ap-accelerator.ts` reads active model `compaction.modelOverrides[<model>].reserveTokens` from `~/.pi/agent/settings.json`. For standard models it caps observation masking below `floor(triggerTokens * 0.85)`; for deep cache-discount models (e.g. 50:1 KV-cache discount such as DeepSeek V4.1 Flash) it keeps masking emergency-only at `210k` (never clamping below `compactionTriggerTokens`), preventing costly mid-prefix KV-cache busts right before compaction while keeping `/ap status` (`mask@210k`) truthful.

## Pairing with Guard-Aware `ap atlas surface` & `ap baton frontier`

Long-horizon reasoning sessions degrade when an agent relies solely on in-context memory to judge coverage. Combine clean-slate rotation (`/ap fresh [goal]` or `before_agent_start` boundary drafts) with external deterministic coverage tracking:

```bash
# 1. Extract 9 orthogonal entrypoint/sink axes with guard-order hints (+ optional native PE/ELF/Mach-O string scan)
ap atlas surface . --include-binaries --json | ap baton frontier seed --stdin

# 2. Pull Top-K unvisited items prioritizing strictly unexplored axes first
ap baton frontier next -k 5

# 3. Record verified / stopped items so fresh sessions never repeat dead ends
ap baton frontier mark <id-or-target> --status stopped --reason "verified safe"
```
