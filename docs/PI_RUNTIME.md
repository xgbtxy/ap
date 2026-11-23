# Pi Coding Agent Runtime Maintenance (`ap pi` + `zz-ap-accelerator.ts`)

`ap` maintains both the zero-prompt-overhead Pi extension (`zz-ap-accelerator.ts`, installed via `ap init -a pi --with-hooks --no-rules`) and a pure-Rust, idempotent runtime patcher (`ap pi`) for `@earendil-works/pi-coding-agent` v1.5+.

## Commands

```bash
# Inspect detected @earendil-works/pi-coding-agent package and patch status
ap pi status

# Apply all 12 generic runtime patches idempotently (originals backed up to ~/.ap/pi-backups/<version>/)
ap pi patch

# Preview without modifying files
ap pi patch --dry-run

# Restore pristine originals from ~/.ap/pi-backups/<version>/
ap pi restore
```

Pass `--pi-dir <path>` (or set `PI_PACKAGE_DIR`) if Pi is installed in a non-standard location.

## Maintained Generic Pi v1.5+ Runtime Patches (12/12)

1. **`before_agent_start_entries`**: Extends `emitBeforeAgentStart` & `AgentSession._prepareRun` so `before_agent_start` handlers can return `entries?: SessionBoundaryDraft[]` for zero-latency programmatic clean-slate compaction without breaking KV-cache prefix reuse.
2. **`windows_python_utf8`**: Auto-injects `PYTHONUTF8=1`, `PYTHONIOENCODING=utf-8`, `LANG=C.UTF-8`, and `LC_ALL=C.UTF-8` into Pi's Windows subprocess environment to eliminate GBK codec crashes.
3. **`codemode_sleep_and_workers`**: Exposes abort-safe `await sleep(ms)` (capped at 30s) inside QuickJS `codemode` scripts and raises `DEFAULT_MAX_CODEMODE_WORKERS` from `2` to `4`.
4. **`http_keepalive_and_transient_retry`**: Adds resilient HTTP keepAlive (`15s` / `28s` / `10s` initial delay), `250ms` Happy-Eyeballs failover, and transient TLS/socket/gateway retry with jittered exponential backoff.
5. **`virtual_model_cache_warmer`**: Allows virtual models (`api === "pi-virtual"`, such as `deepseek/flash-auto`) to match `CacheWarmer` physical sessions cleanly.
6. **`codemode_web_builtins`**: Injects standard Web/JS builtins (`setTimeout`/`clearTimeout`, `atob`/`btoa`, `TextEncoder`/`TextDecoder`, `Buffer`) into QuickJS `codemode` and stops the wrapper from shadowing prelude globals.
7. **`sequential_shell_tool_barrier`**: Runs `bash`/`powershell` calls sequentially as barriers while keeping adjacent read/search calls parallel (eliminating `bash`+`read` race `ENOENT`s).
8. **`boundary_compaction_event`**: Emits `session_compact` on extension boundary-draft compactions so cache trackers and extensions reset cleanly on auto-rotations.
9. **`cjk_calibrated_compaction_budget`**: Weights CJK/fullwidth characters and calibrates `keepRecentTokens` against provider-reported `prompt_tokens` to prevent 2–3x compaction overshoot.
10. **`deterministic_tool_order`**: Sorts resolved transcript tools deterministically by name so MCP reconnects or reloads never bust prompt KV-cache.
11. **`codemode_text_returns_rendered`**: Returns the rendered string from `codemode`'s `text(value)` helper (both bundle and prelude) to eliminate `TypeError: cannot read property 'slice' of undefined`.
12. **`codemode_result_output_shim`**: Attaches a non-enumerable `.output` string shim on resolved `codemode` tool-result objects (in both bundle worker and prelude) so `r.output.slice(...)` never throws `TypeError` when downstream callers expect `.output` alongside rendered text.

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
