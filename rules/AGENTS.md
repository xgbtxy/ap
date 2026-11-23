# Agent Primitives Runtime Routing (`ap` v2.40+)

1. **Orient & Read (`atlas` / `read` / `search` / `query` / `ap_orient`)**: Repo overview -> `ap atlas map .` + `ap atlas surface . --include-binaries` (9-axis frontier); fault localization -> `ap atlas locate`; clean code search -> `ap search <pat> --code-only --no-tests`; AST/Office/PE·ELF·Java·.NET·Proto/JS `--routes`·`--jwt`·`--secrets` -> `ap read`.
2. **Edit & Refactor (`splice` / `ap_edit`)**: Inspect symbols via `ap splice view <file> --symbol <Sym>`; AST rename via `ap splice rename`; atomic AST-gated edits via `ap splice apply --cwd . --stdin --test` (supports `@L<start>-L<end>` disambiguation & read-gutter auto-strip).
3. **Verify (`probe` + `guard verify --deep`)**: Web/API/UI/AuthZ QA via `ap probe smoke|ui|http|ws|cdp`; finish with `ap guard verify --deep`; MCP supports `ap mcp --profile core|deferred` (`ap_discover` + `ap_call`).
4. **Diagnose, Persist & Evolve (`sieve` / `baton` / `recall` / `audit`)**: Compress logs via `ap sieve run -- <cmd>`; track cross-session work via `ap baton frontier` & `ap recall`; inspect zero-PII process bottlenecks via `ap audit --maintainer`.
