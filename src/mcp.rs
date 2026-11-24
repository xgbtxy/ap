use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};
use std::process::Command;

fn mcp_tools_schema() -> Value {
    let mut tools = json!([
        {
            "name": "ap_read",
            "description": "AST/universal reader: Py/TS/JS/Go/Rust/C/C++ --symbol/--outline & batch `targets`, .docx/.xlsx/.pptx/.pdf/.sqlite/.gz, .asar/.zip/.vsix/.jar/.whl archives, PE/ELF/Mach-O headers/RVA/VA/XREF/find_bytes, minified JS (--offset/--chars/--pretty), SourceMaps, GBK, routes, JWT, secrets, structural --diff, and JS-rendered URLs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "File/dir path or URL" },
                    "targets": { "type": "array", "description": "Up to 12 paths to read in 1 call", "items": { "type": "string" } },
                    "symbol": { "type": "string", "description": "Comma-separated AST symbol names" },
                    "outline": { "type": "boolean", "description": "Emit AST/config/heading outline only" },
                    "section": { "type": "string", "description": "Markdown heading substring" },
                    "lines": { "type": "string", "description": "Line range(s), e.g. '1-30,120-160'" },
                    "width": { "type": "integer", "description": "Max chars per line (UTF-8 safe)" },
                    "query": { "type": "string", "description": "Keyword/regex filter" },
                    "around": { "type": "integer", "description": "Context bytes/lines around query hits" },
                    "max_hits": { "type": "integer", "description": "Max query match windows" },
                    "sheet": { "type": "string", "description": ".xlsx sheet filter" },
                    "entry": { "type": "string", "description": "Archive entry path" },
                    "offset": { "type": "string", "description": "Byte offset(s) for minified bundles" },
                    "chars": { "type": "integer", "description": "Slice window length (default: 2400)" },
                    "pretty": { "type": "boolean", "description": "Pretty-format JS/JSON" },
                    "json_path": { "type": "string", "description": "JSON/XML/PLIST/YAML/TOML path query" },
                    "map_pos": { "type": "string", "description": "SourceMap v3 'line:col'" },
                    "decode": { "type": "boolean", "description": "Auto-decode JWT/Base64/URL strings" },
                    "render": { "type": "boolean", "description": "Render JS URL via headless browser" },
                    "hex": { "type": "boolean", "description": "Hex+ASCII dump with SHA-256 & entropy" },
                    "rva": { "type": "string", "description": "PE RVA / ELF offset to function/preview" },
                    "va": { "type": "string", "description": "PE/ELF virtual address to offset/XREFs" },
                    "find_bytes": { "type": "string", "description": "Wildcard hex pattern e.g. '48 8D ?? E8'" },
                    "xref": { "type": "boolean", "description": "PE64/ELF64 string & IAT XREFs" },
                    "cert": { "type": "boolean", "description": "X.509 PEM/DER inspector" },
                    "proto": { "type": "boolean", "description": "Raw protobuf wire decoder" },
                    "routes": { "type": "boolean", "description": "Extract JS/TS/HTML routes, sinks & origins" },
                    "jwt": { "type": "boolean", "description": "Decode JWT header/claims & posture" },
                    "secrets": { "type": "boolean", "description": "Scan redacted hardcoded keys/tokens" },
                    "diff": { "type": "string", "description": "Older binary/archive/config path to diff" },
                    "scrub": { "type": "boolean", "description": "Redact secrets & defang prompt injection" }
                }
            }
        },
        {
            "name": "ap_query",
            "description": "Execute SQLite SQL (`JOIN`, `GROUP BY`, `SUM`, `CTE`, window fns) across `.xlsx`, `.csv`/`.tsv` (GBK/UTF-8), and `.json`/`.jsonl` in <20ms.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "files": { "type": "array", "description": "Bindings like ['orders=sales.xlsx']", "items": { "type": "string" } },
                    "sql": { "type": "string", "description": "SQL query (omit or schema=true to inspect columns)" },
                    "schema": { "type": "boolean", "description": "List table names, counts & columns" },
                    "format": { "type": "string", "description": "'md' (default) or 'json' (structuredContent.records)" },
                    "out": { "type": "string", "description": "Optional output CSV path" }
                },
                "required": ["files"]
            }
        },
        {
            "name": "ap_search",
            "description": "Fast .gitignore-aware regex & Tree-sitter AST search (`ast`: `kind:call`, `fetch($URL, $$$)`) across code, minified bundles, SourceMaps, .asar/.zip, docs & binary strings.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Regex or literal pattern" },
                    "ast": { "type": "string", "description": "AST query (`kind:call` or metavars like `fetch($URL, $$$)`)" },
                    "patterns": { "type": "array", "description": "Extra regex patterns in same walk", "items": { "type": "string" } },
                    "path": { "type": "string", "description": "Target path (default: '.')" },
                    "paths": { "type": "array", "description": "Additional paths in same walk", "items": { "type": "string" } },
                    "ext": { "type": "string", "description": "Comma-separated extensions" },
                    "pretty": { "type": "boolean", "description": "Format minified bundle hits" },
                    "multiline": { "type": "boolean", "description": "Cross-line regex" },
                    "block": { "type": "boolean", "description": "Return enclosing AST fn/class block" },
                    "context": { "type": "integer", "description": "Lines before & after hit (-C)" },
                    "before_context": { "type": "integer", "description": "Lines before hit (-B)" },
                    "after_context": { "type": "integer", "description": "Lines after hit (-A)" },
                    "invert_match": { "type": "boolean", "description": "Non-matching lines (-v)" },
                    "files_only": { "type": "boolean", "description": "Unique file paths only (-l)" },
                    "count": { "type": "boolean", "description": "Per-file hit counts (-c)" },
                    "only_matching": { "type": "boolean", "description": "Matched substrings only (-o)" },
                    "unique": { "type": "boolean", "description": "Deduplicate & frequency-rank hits" },
                    "fixed_strings": { "type": "boolean", "description": "Literal string mode (-F)" },
                    "ignore_case": { "type": "boolean", "description": "Case-insensitive (-i)" },
                    "include": { "type": "array", "description": "Include globs", "items": { "type": "string" } },
                    "code_only": { "type": "boolean", "description": "Code files only, skip comments/strings" },
                    "no_tests": { "type": "boolean", "description": "Skip test paths & test blocks" },
                    "exclude": { "type": "array", "description": "Exclude path filters", "items": { "type": "string" } },
                    "around": { "type": "integer", "description": "Minified slice context chars (default: 160)" },
                    "max_hits": { "type": "integer", "description": "Max total hits (default: 50)" },
                    "per_pattern": { "type": "integer", "description": "Max hits per pattern (0=auto)" },
                    "width": { "type": "integer", "description": "Max snippet chars (UTF-8 safe)" },
                    "json": { "type": "boolean", "description": "Emit structured JSON in structuredContent" }
                }
            }
        },
        {
            "name": "ap_undo",
            "description": "Named checkpoints, diff-before-restore, and atomic file restore (works inside or outside Git). Supports `action`: `'restore'` (default), `'list'`, `'save'` (`label` + optional `files`/`cwd`), or `'diff'` (`id` or `label`), plus `keep` to preserve checkpoints.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "description": "Action: 'restore' (default), 'list', 'save', or 'diff'" },
                    "list": { "type": "boolean", "description": "Legacy alias for action='list'" },
                    "label": { "type": "string", "description": "Checkpoint label when saving (`action='save'`)" },
                    "id": { "type": "string", "description": "Checkpoint ID prefix or exact label for `diff` / `restore`" },
                    "cwd": { "type": "string", "description": "Workspace directory for `save` (default: '.')" },
                    "files": { "type": "array", "items": { "type": "string" }, "description": "Files to include when `action='save'` (defaults to git dirty files in `cwd`)" },
                    "keep": { "type": "boolean", "description": "Keep checkpoint instead of deleting it after `restore`" }
                }
            }
        },
        {
            "name": "ap_orient",
            "description": "Call FIRST on any empty or existing project. Returns verified host runtimes (Node/SQLite/Python/Rust/Browser), Tree-sitter code map, reachable files (pruning dead slop), UI controls, API routes, and broken DOM #id or route mismatches in <30ms.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace root directory (default: '.')" }
                }
            }
        },
        {
            "name": "ap_impact",
            "description": "Call BEFORE changing any shared function, class, struct, interface, route, or file across modules. Maps exact Tree-sitter AST callers (`symbol`) OR cross-file outbound imports, multi-hop inbound importers, exported symbols & dependency cycles (`file`) in <25ms.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace root directory (default: '.')" },
                    "symbol": { "type": "string", "description": "Symbol name or comma-separated symbols (e.g. 'computeTotal,OrderItem')" },
                    "file": { "type": "string", "description": "File path (or '.') to inspect cross-file module dependency graph, reverse blast radius & circular imports" },
                    "depth": { "type": "integer", "description": "Traversal hops 1..5 when `file` is given (default: 2)" },
                    "dead": { "type": "boolean", "description": "When `file` is set (e.g. '.' or a file path), also audit orphan source modules and unused/ghost exports" }
                },
                "required": []
            }
        },
        {
            "name": "ap_edit",
            "description": "Atomically create or edit multiple files in 1 call with zero shell-quoting issues. Cleans UTF-8 BOM/UTF-16LE, validates Tree-sitter AST syntax BEFORE writing to disk, and proactively warns if a modified function/type signature has untouched downstream callers (`[BLAST RADIUS]`).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                    "writes": {
                        "type": "array",
                        "description": "Full file writes [{path, content}]",
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string" },
                                "content": { "type": "string" }
                            },
                            "required": ["path", "content"]
                        }
                    },
                    "edits": {
                        "type": "array",
                        "description": "Substring/indent-resilient replacements [{path, old, new, line_hint?, all?}]",
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string" },
                                "old": { "type": "string" },
                                "new": { "type": "string" },
                                "line_hint": { "type": "string", "description": "Optional line window (e.g. '40-70' or '52') to disambiguate duplicate blocks" },
                                "all": { "type": "boolean", "description": "Replace all matching occurrences in the file" }
                            },
                            "required": ["path", "old", "new"]
                        }
                    },
                    "appends": {
                        "type": "array",
                        "description": "Zero-truncation appends to end of files [{path, content}]",
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string" },
                                "content": { "type": "string" }
                            },
                            "required": ["path", "content"]
                        }
                    },
                    "symbols": {
                        "type": "array",
                        "description": "Tree-sitter AST-exact function/class/struct symbol operations [{path, symbol, mode?, content}]",
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string" },
                                "symbol": { "type": "string" },
                                "mode": { "type": "string", "description": "Operation: 'replace' (default), 'insert_after', 'insert_before', or 'delete' (content optional when mode='delete')" },
                                "content": { "type": "string" }
                            },
                            "required": ["path", "symbol"]
                        }
                    },
                    "diff": { "type": "string", "description": "Optional standard Git unified diff (`--- a/...`, `+++ b/...`, `@@ ... @@`) or Codex `*** Begin Patch` envelope (`*** Update File:` / `*** Add File:`)" },
                    "run_tests": { "type": "boolean", "description": "Run auto-detected test suite after applying" }
                }
            }
        },
        {
            "name": "ap_smoke",
            "description": "Verify web/API apps on Windows/macOS/Linux without hanging terminals or leaking zombie processes. Auto-starts server on a free PORT, drives real headless Edge/Chrome CDP (OPEN /, FILL #id text, SELECT #id val, CLICK #id or text=Btn, EVAL <js>) + UTF-8 HTTP requests, checks 0 JS pageerror/console.error/server-stderr crashes, and kills all process trees.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                    "start": { "type": "string", "description": "Optional start command (auto-detected from package.json if omitted)" },
                    "steps": {
                        "type": "array",
                        "description": "Smoke DSL lines, e.g. ['OPEN /', 'FILL #name Alice', 'CLICK #add-btn', 'EXPECT CONTAINS Alice', 'GET /api/items', 'EXPECT STATUS 200']",
                        "items": { "type": "string" }
                    }
                },
                "required": ["steps"]
            }
        },
        {
            "name": "ap_fuzz",
            "description": "Torture-test any created web/API server or CLI against malformed JSON, negative/zero/NaN boundary inputs, CJK/XSS/SQLi payloads, 404 paths, and simultaneous multi-threaded concurrency bursts in <1s.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                    "start": { "type": "string", "description": "Optional server start command (auto-detected if omitted)" },
                    "cli": { "type": "string", "description": "Optional CLI command to fuzz instead of an HTTP server" },
                    "concurrency": { "type": "integer", "description": "Parallel race-condition threads (default: 8)" }
                }
            }
        },
        {
            "name": "ap_mutate",
            "description": "Test the quality of your unit tests in <2s via Tree-sitter AST fault-seeding (`>=`->`>`, `===`->`!==`, `+`->`-`, `&&`->`||`). Reports exact surviving mutants where your tests missed boundary or logic cases.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                    "target": { "type": "string", "description": "Source file to mutate (e.g. 'src/wallet.ts')" },
                    "test_cmd": { "type": "string", "description": "Optional test command (auto-detected if omitted)" },
                    "max_mutants": { "type": "integer", "description": "Max mutants to evaluate (default: 8)" }
                },
            "required": ["target"]
        }
    },
    {
        "name": "ap_ui",
        "description": "Audit any web UI in real Headless Edge/Chrome across Desktop (1280x800) + Mobile (390x844): catches horizontal overflow, overlapped/blocked buttons via elementFromPoint, broken <img>, JS pageerror/console.error, and silent 4xx/5xx network leaks (0 MB Playwright).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                "start": { "type": "string", "description": "Optional server start command (auto-detected if omitted)" },
                "path": { "type": "string", "description": "Page path (default: '/')" },
                "screenshot": { "type": "string", "description": "Optional PNG screenshot output path" }
            }
        }
    },
    {
        "name": "ap_locate",
        "description": "Hierarchical Agentless/AutoCodeRover fault localizer (<25ms): ranks Top-K suspect functions across the codebase via Tree-sitter + BM25 + camelCase/CJK splitting and returns exact numbered source lines so you find bugs in 1 call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Bug description, error message, or symptom keywords" },
                "path": { "type": "string", "description": "Workspace root directory (default: '.')" },
                "top_k": { "type": "integer", "description": "Number of suspect functions to return (default: 5)" }
            },
            "required": ["query"]
        }
    },
    {
        "name": "ap_trace",
        "description": "Multi-hop Tree-sitter call-chain, source-to-sink reachability & guard-placement tracer (<30ms) across Py/TS/JS/Go/Rust/C/C++.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "symbol": { "type": "string", "description": "Source/target function or method name" },
                "path": { "type": "string", "description": "Workspace root (default: '.')" },
                "depth": { "type": "integer", "description": "Max traversal hops (default: 3)" },
                "to": { "type": "string", "description": "Optional sink/callee name for shortest-path reachability + GUARD_BEFORE/GUARD_AFTER/UNGUARDED check" },
                "sinks": { "type": "boolean", "description": "Find shortest paths to all notable I/O/exec/DOM/SQL sinks" }
            },
            "required": ["symbol"]
        }
    },
    {
        "name": "ap_cdp",
        "description": "Attach directly to ALREADY-RUNNING Chrome/Edge/Electron/WebView CDP debugging port(s) (--list targets, --target filter, --eval async JS, --diff-ports concurrent dual-port diff, --watch-ms non-blocking console/network capture, --audit layout, --screenshot PNG) without killing host apps.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": { "type": "string", "description": "CDP host (default: '127.0.0.1')" },
                "port": { "type": "integer", "description": "CDP debugging port (default: 9222)" },
                "diff_ports": { "type": "string", "description": "Optional 'portA,portB' pair to run `--eval` concurrently on two CDP ports and compute structured JSON diff" },
                "target_ids": { "type": "string", "description": "Optional 'targetA,targetB' filters paired with `diff_ports`" },
                "list": { "type": "boolean", "description": "List all live debuggable targets" },
                "target": { "type": "string", "description": "Substring matching target title, url, or id" },
                "eval": { "type": "string", "description": "JavaScript expression to evaluate (awaits Promises)" },
                "watch_ms": { "type": "integer", "description": "Optional non-blocking bounded event watch window in ms (captures async console logs & network responses)" },
                "audit": { "type": "boolean", "description": "Run live DOM layout/overflow/overlap check" },
                "screenshot": { "type": "string", "description": "Optional PNG screenshot output path" }
            }
        }
    },
    {
        "name": "ap_http",
        "description": "HTTP/API diagnostic probe: single, batch, single-field boundary (`vary_field`), AuthZ/IDOR matrix with deep JSON diff & sentinel checks (`principals`/`principal_cdps`/`sentinels`), CORS audit, header security audit, and barrier TOCTOU race.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "Target HTTP(S) URL" },
                "method": { "type": "string", "description": "HTTP method (default: 'GET')" },
                "headers": { "type": "array", "description": "Request headers", "items": { "type": "string" } },
                "body": { "type": "string", "description": "Raw request body" },
                "batch_requests": { "type": "array", "description": "'METHOD URL [BODY]' lines", "items": { "type": "string" } },
                "vary_request": { "type": "string", "description": "Saved request file for vary_field" },
                "vary_field": { "type": "string", "description": "JSON/query/header field to vary" },
                "alt_value": { "type": "string", "description": "Alternate vary_field value" },
                "rate_ms": { "type": "integer", "description": "Serial vary_field delay ms" },
                "max_variants": { "type": "integer", "description": "Max vary_field variants (default: 20)" },
                "dry_run": { "type": "boolean", "description": "Preview vary_field without sending" },
                "principals": { "type": "array", "description": "AuthZ matrix specs e.g. ['owner=Authorization: Bearer A','anon=']", "items": { "type": "string" } },
                "cdp_cookies": { "type": "integer", "description": "In-memory cookies from 127.0.0.1 CDP port" },
                "principal_cdps": { "type": "array", "description": "AuthZ matrix via CDP ports e.g. ['owner=9451','other=9470']", "items": { "type": "string" } },
                "cors_origin": { "type": "string", "description": "Origin header for CORS reflection audit" },
                "select": { "type": "string", "description": "Dot-path JSON extractor e.g. 'data.items[*].id'" },
                "audit_headers": { "type": "boolean", "description": "Audit security/CORS/CSP/cookie headers" },
                "race": { "type": "integer", "description": "Barrier TOCTOU burst threads (2..=32)" },
                "sentinels": { "type": "array", "description": "Sentinel strings flagged if leaked", "items": { "type": "string" } },
                "timeout": { "type": "integer", "description": "Timeout sec (default: 15)" },
                "insecure": { "type": "boolean", "description": "Skip TLS verify (-k)" },
                "follow": { "type": "boolean", "description": "Follow redirects (-L)" }
            }
        }
    },
    {
        "name": "ap_ports",
        "description": "Cross-platform listening TCP port, process PID & live CDP DevTools radar: lists local listening ports and auto-badges `[CDP READY]` Chrome/Electron debugging ports.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": { "type": "integer", "description": "Optional specific TCP port to inspect" }
            }
        }
    },
    {
        "name": "ap_ps",
        "description": "Cross-platform running process tree, exact command-line arguments & listening TCP ports inspector (replaces wmic/tasklist/ps).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": { "type": "string", "description": "Optional case-insensitive substring matching process name, exe path, or command line" },
                "pid": { "type": "integer", "description": "Optional PID (matches process & its direct children)" },
                "limit": { "type": "integer", "description": "Max processes to return (default: 40)" }
            }
        }
    },
    {
        "name": "ap_win",
        "description": "Zero-subprocess Windows diagnostics inspector (Named Pipes + SDDL DACLs, Registry keys/values, file/dir ACLs, Win32 services, and process token user/IL/privileges) — immune to Git Bash quoting and MSYS2 pathconv.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pipes": { "type": "boolean", "description": "Enumerate \\\\.\\pipe\\* and inspect SDDL/non-admin write ACEs" },
                "reg": { "type": "string", "description": "Registry key to inspect, e.g. HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion" },
                "acl": { "type": "string", "description": "File or directory path whose owner, SDDL DACL & non-admin writability to inspect" },
                "services": { "type": "boolean", "description": "Enumerate Windows services (state, PID, start_type, bin_path, account)" },
                "whoami": { "type": "boolean", "description": "Inspect current process token user, SID, elevation, integrity level & privileges" },
                "filter": { "type": "string", "description": "Optional case-insensitive substring filter for pipes/reg/services" },
                "max": { "type": "integer", "description": "Max entries to return (default: 60)" }
            }
        }
    },
    {
        "name": "ap_fs_diff",
        "description": "Atomic before/after directory snapshot diff (`run`, `snapshot`, `diff`) and recent-files radar (`recent` seconds).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dir": { "type": "string", "description": "Directory to inspect (default: '.')" },
                "recent": { "type": "integer", "description": "Filter files modified in the last N seconds" },
                "snapshot": { "type": "string", "description": "Save named snapshot for later diff" },
                "diff": { "type": "string", "description": "Diff current directory against saved snapshot name" },
                "run": { "type": "string", "description": "Execute shell command and atomically report added/modified/deleted files" }
            }
        }
    },
    {
        "name": "ap_tcp",
        "description": "Deadline-bounded raw TCP banner & text/hex send-recv probe (zero hanging Python sockets).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": { "type": "string", "description": "Target host:port (e.g. '127.0.0.1:6379')" },
                "send": { "type": "string", "description": "Optional text payload (supports \\r\\n)" },
                "send_hex": { "type": "string", "description": "Optional hex bytes payload (e.g. '050100')" },
                "wait_ms": { "type": "integer", "description": "Max read wait window in ms (default: 800)" }
            },
            "required": ["addr"]
        }
    },
    {
        "name": "ap_listen",
        "description": "Bounded ephemeral HTTP webhook/callback capture server (auto-exits after max_reqs or wait_ms; substitutes {{PORT}} in `run`).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": { "type": "integer", "description": "Local TCP port to bind (0 = free ephemeral port)" },
                "wait_ms": { "type": "integer", "description": "Max listen duration in ms (default: 5000)" },
                "max_reqs": { "type": "integer", "description": "Stop cleanly after N requests (default: 1)" },
                "run": { "type": "string", "description": "Optional command to execute while listening (replaces {{PORT}})" }
            }
        }
    },
    {
        "name": "ap_ws",
        "description": "Deadline-bounded RFC 6455 non-CDP WebSocket (`ws://`) send/recv probe (never hangs on recv).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "Target ws://host:port/path URL" },
                "send": { "type": "array", "items": { "type": "string" }, "description": "Text frames to send after handshake" },
                "headers": { "type": "array", "items": { "type": "string" }, "description": "Optional extra HTTP upgrade headers" },
                "origin_matrix": { "type": "boolean", "description": "Run CSWSH cross-origin WebSocket handshake matrix (omitted / https://evil.example / null / localhost)" },
                "origins": { "type": "array", "items": { "type": "string" }, "description": "Custom Origin values for origin_matrix" },
                "wait_ms": { "type": "integer", "description": "Max receive window in ms (default: 1000)" }
            },
            "required": ["url"]
        }
    },
    {
        "name": "ap_tls",
        "description": "Cross-platform TLS protocol & X.509 certificate Subject/Issuer/Expiry/SHA-256 inspector.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": { "type": "string", "description": "Target host:port (e.g. 'example.com:443')" },
                "sni": { "type": "string", "description": "Optional SNI hostname override" },
                "timeout": { "type": "integer", "description": "Timeout in seconds (default: 6)" }
            },
            "required": ["addr"]
        }
    },
    {
        "name": "ap_baton_claim",
        "description": "Atomic multi-agent resource lease manager (claim/release/list shared VMs, servers, ports with TTL expiry; exit 2 if actively held by another agent).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": { "type": "string", "description": "'claim', 'release', or 'list'" },
                "resource": { "type": "string", "description": "Resource key (e.g. 'win10-vm', 'cdp-9222')" },
                "owner": { "type": "string", "description": "Agent/workspace owner identifier" },
                "ttl": { "type": "integer", "description": "Lease TTL in seconds (default: 900)" },
                "note": { "type": "string", "description": "Optional short lease note" }
            },
            "required": ["action"]
        }
    },
    {
        "name": "ap_baton_dedup",
        "description": "Sub-15ms hybrid BM25 + CJK bigram + camelCase semantic near-duplicate finder across Markdown ledgers, notes & JSON/JSONL indexes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Candidate title, component, or effect summary to check" },
                "files": { "type": "array", "items": { "type": "string" }, "description": "Paths to ledger/index/markdown files" },
                "top_k": { "type": "integer", "description": "Max near-duplicate hits (default: 8)" }
            },
            "required": ["query", "files"]
        }
    },
    {
        "name": "ap_guard_pack",
        "description": "Deterministic deliverable/evidence bundle verifier: validates full 64-hex SHA-256 artifact manifests, scans secret/absolute-path leaks, and checks required headers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dir": { "type": "string", "description": "Bundle directory to verify" },
                "max_lines": { "type": "integer", "description": "Optional max non-empty narrative lines budget" },
                "require_headers": { "type": "array", "items": { "type": "string" }, "description": "Optional required header prefixes" }
            },
            "required": ["dir"]
        }
    },
    {
        "name": "ap_diff_audit",
        "description": "Semantic git diff self-audit: catches test-weakening cheating (deleted assertions), newly added debug leftovers (debugger/breakpoint/dbg!), and silent mass deletions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cwd": { "type": "string", "description": "Workspace directory (default: '.')" }
            }
        }
    },
    {
        "name": "ap_verify",
            "description": "Run final quality gate before finishing: checks 0 broken HTML #id <-> JS selector or fetch() <-> route contracts, 0 anti-slop violations (:any, @ts-ignore, empty catch {}), and runs project tests.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                    "deep": { "type": "boolean", "description": "Also run cross-file export/arity linker, API chaos/concurrency fuzzer, and AST mutation audit in 1 pass" }
                }
            }
        },
        {
            "name": "ap_exec",
            "description": "Run shell, build, git, package-manager, Python or Node commands on Windows/macOS/Linux WITHOUT PowerShell `&&`/`curl`/heredoc syntax crashes, GBK/BOM encoding mojibake, pipe deadlocks, or noisy log floods. Automatically heals Windows commands, frees locked ports (`free_port`), kills hung process trees on timeout, and compresses >1.8KB logs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                    "command": { "type": "string", "description": "Shell command string to execute safely" },
                    "timeout": { "type": "integer", "description": "Timeout in seconds (default: 120)" },
                    "free_port": { "type": "integer", "description": "Optional local TCP port to free before running" },
                    "scrub": { "type": "boolean", "description": "Scrub leaked secrets (API keys/tokens/PEM/URI creds) and defang indirect prompt-injection payloads from command output" }
                },
                "required": ["command"]
            }
        },
        {
            "name": "ap_probe",
            "description": "Execute a concrete Python/TS/JS/Rust snippet in the workspace (detecting heap aliasing, mutation & rounding bugs) OR run a noisy command through lossless log compression.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                    "code": { "type": "string", "description": "Code snippet to trace via `ap probe run`" },
                    "sieve_cmd": { "type": "string", "description": "Shell command to run through `ap sieve` compressor" }
                }
            }
        }
    ]);
    let mut extra = vec![
        json!({
            "name": "ap_rename",
            "description": "Tree-sitter AST-exact workspace symbol rename (`old_name`+`new_name`) OR structural AST pattern codemod/rewrite (`pattern`+`replacement`, supporting `$VAR` and `$$$ARGS`, across Py/TS/TSX/JS/Go/Rust/C). Never touches comments or strings, validates 100% syntax before writing, records an `ap_undo` checkpoint, and supports `dry_run` + `run_tests` rollback.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "old_name": { "type": "string", "description": "Existing identifier name to rename (symbol-rename mode)" },
                    "new_name": { "type": "string", "description": "New identifier name (symbol-rename mode)" },
                    "pattern": { "type": "string", "description": "Structural AST pattern with `$VAR` / `$$$ARGS` (rewrite mode, e.g. `oldFetch($URL, $OPTS)`)" },
                    "replacement": { "type": "string", "description": "Replacement template using `$VAR` / `$$$ARGS` (rewrite mode, e.g. `apiClient.request($URL, $OPTS)`)" },
                    "ext": { "type": "string", "description": "Optional comma-separated extension filter in rewrite mode (e.g. `ts,tsx`)" },
                    "no_tests": { "type": "boolean", "description": "Skip test files in rewrite mode" },
                    "path": { "type": "string", "description": "Workspace root directory (default: '.')" },
                    "dry_run": { "type": "boolean", "description": "Preview affected files and lines without modifying disk" },
                    "run_tests": { "type": "boolean", "description": "Run project checks/tests after applying rename/rewrite" },
                    "rollback_on_test_fail": { "type": "boolean", "description": "Atomically restore all files if tests fail" }
                },
                "required": []
            }
        }),
        json!({
            "name": "ap_sieve",
            "description": "Inspect or search archived lossless outputs from `ap sieve` (searches local `.sieve` with read-only fallback to `~/.ap/sieve`). Supports `peek` (by `id`, `lines`, `grep`, `json_path`) and sub-ms SQLite FTS5 `search`.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "description": "'peek' or 'search'" },
                    "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                    "id": { "type": "string", "description": "Archive ID prefix for `peek`" },
                    "lines": { "type": "string", "description": "Line range 'START:END' for `peek`" },
                    "grep": { "type": "string", "description": "Regex filter for `peek`" },
                    "json_path": { "type": "string", "description": "Dot-separated JSON path for `peek`" },
                    "query": { "type": "string", "description": "FTS5 search query for `search`" },
                    "limit": { "type": "integer", "description": "Max FTS5 hits (default: 8)" }
                },
                "required": ["action"]
            }
        }),
        json!({
            "name": "ap_baton",
            "description": "Compaction-proof task state & cross-agent handoff capsule (<500 tokens) with automatic fact/HEAD drift detection on `resume`: `resume`, `set` (goal/constraints/next), `fact` (verified ground truth), `deadend` (falsified approach), `checkpoint`, or `clear`.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "description": "'resume', 'set', 'fact', 'deadend', 'checkpoint', or 'clear'" },
                    "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                    "goal": { "type": "string", "description": "Task goal for `set`" },
                    "constraints": { "type": "array", "items": { "type": "string" }, "description": "Constraint list for `set`" },
                    "next": { "type": "string", "description": "Immediate next action for `set`" },
                    "text": { "type": "string", "description": "Fact or deadend statement" },
                    "ref": { "type": "string", "description": "Optional file:line reference for `fact`" },
                    "reason": { "type": "string", "description": "Optional failure reason for `deadend`" },
                    "note": { "type": "string", "description": "Optional checkpoint note" }
                },
                "required": ["action"]
            }
        }),
        json!({
            "name": "ap_recall",
            "description": "Sub-millisecond SQLite FTS5/BM25 triggered micro-memory vault with file-hash/git provenance & staleness invalidation: `match` (retrieve top-K rules for query/files), `add` (save triggers + rule, optionally bound to `--file`), `stats`, or `verify` (detect/prune stale rules).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "description": "'match', 'add', 'stats', or 'verify'" },
                    "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                    "query": { "type": "string", "description": "Task/command query for `match`" },
                    "files": { "type": "string", "description": "Comma-separated active file paths for `match`" },
                    "top": { "type": "integer", "description": "Max rules to retrieve (default: 3)" },
                    "triggers": { "type": "string", "description": "Trigger keywords/globs for `add`" },
                    "rule": { "type": "string", "description": "Concise actionable rule text for `add`" },
                    "kind": { "type": "string", "description": "Rule category (default: 'gotcha')" },
                    "file": { "type": "string", "description": "Optional bound source file path for provenance hash tracking on `add`" },
                    "prune_stale": { "type": "boolean", "description": "When true on `verify`, delete rules whose bound source_file was modified or deleted" }
                },
                "required": ["action"]
            }
        }),
        json!({
            "name": "ap_changes",
            "description": "Git-diff & symbol history impact brief (<35ms in-process): maps modified AST symbols, untouched callers & related tests for working-tree changes, OR when `history_file` is provided, extracts symbol/line commit history, blame authorship & temporal co-change files.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Git repository root directory (default: '.')" },
                    "base": { "type": "string", "description": "Git base ref to diff against (default: 'HEAD')" },
                    "history_file": { "type": "string", "description": "Optional file path for git symbol/line history, blame authorship & temporal co-change coupling" },
                    "symbol": { "type": "string", "description": "Optional AST symbol inside history_file (e.g. 'computeTotal')" },
                    "lines": { "type": "string", "description": "Optional line range inside history_file (e.g. '10-45')" },
                    "limit": { "type": "integer", "description": "Max commits returned for history_file (default: 8, max: 25)" }
                }
            }
        }),
        json!({
            "name": "ap_surface",
            "description": "Multi-axis guard-aware entrypoint & sink surface mapper (<150ms in-process): scans source code, manifests, minified bundles, virtual archives (.asar/.vsix/.zip/.jar) & optional native PE/ELF/SO binaries across 9 orthogonal axes and prioritizes unprotected/post-guard sinks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Directory, file, archive (.asar/.vsix/.zip/.jar), or native binary to scan (default: '.')" },
                    "max_files": { "type": "integer", "description": "Max files to scan (default: 1500)" },
                    "max_per_axis": { "type": "integer", "description": "Max ranked diverse items per axis (default: 12)" },
                    "include_vendor": { "type": "boolean", "description": "Also scan gitignored/vendor directories (default: false)" },
                    "include_binaries": { "type": "boolean", "description": "Also scan native .exe/.dll/.so/.dylib binary strings/imports (default: false)" }
                }
            }
        }),
        json!({
            "name": "ap_frontier",
            "description": "Multi-session orthogonal exploration frontier tracker: `seed` (from surface scan or manual target), `next` (diversity-maximizing unvisited targets prioritizing unexplored axes), `mark` (probed/stopped/confirmed/deferred), `status`, or `sync_stopped`.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "description": "'seed', 'next', 'mark', 'status', or 'sync_stopped'" },
                    "cwd": { "type": "string", "description": "Workspace directory (default: '.')" },
                    "store": { "type": "string", "description": "Optional custom frontier JSON store path (defaults to .baton/frontier.json)" },
                    "scan_path": { "type": "string", "description": "For action='seed': directory/archive to scan via ap_surface and ingest into frontier" },
                    "axis": { "type": "string", "description": "For manual action='seed': axis category name" },
                    "target": { "type": "string", "description": "For manual action='seed': target path/endpoint" },
                    "module": { "type": "string", "description": "For manual action='seed': module/component label" },
                    "note": { "type": "string", "description": "For manual action='seed': short note/snippet" },
                    "query": { "type": "string", "description": "For action='mark': item id prefix or target substring" },
                    "status": { "type": "string", "description": "For action='mark': 'unvisited', 'probed', 'stopped', 'confirmed', or 'deferred'" },
                    "reason": { "type": "string", "description": "For action='mark': concise reason" },
                    "ref": { "type": "string", "description": "For action='mark': evidence file/ref" },
                    "top_k": { "type": "integer", "description": "For action='next'/'status': max items (default: 5)" },
                    "exclude_axes": { "type": "array", "items": { "type": "string" }, "description": "For action='next': axes to deprioritize" },
                    "text_files": { "type": "array", "items": { "type": "string" }, "description": "For action='sync_stopped': prior notes/ledger paths to cross-reference" }
                },
                "required": ["action"]
            }
        }),
    ];
    if let Value::Array(ref mut arr) = tools {
        arr.append(&mut extra);
    }
    annotate_mcp_tools(tools)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpProfile {
    Full,
    Core,
    Deferred,
}

impl McpProfile {
    pub fn resolve(cli_profile: &str) -> Self {
        let raw = if !cli_profile.trim().is_empty() {
            cli_profile.trim().to_ascii_lowercase()
        } else {
            std::env::var("AP_MCP_PROFILE")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        };
        match raw.as_str() {
            "core" => Self::Core,
            "deferred" | "minimal" | "lazy" => Self::Deferred,
            _ => Self::Full,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Core => "core",
            Self::Deferred => "deferred",
        }
    }
}

fn meta_tools_schema() -> Vec<Value> {
    vec![
        json!({
            "name": "ap_discover",
            "description": "Search and load any of ap's 37 specialist tools by keyword/category (binaries, Win32 pipes/reg/acl/services, HTTP AuthZ/CORS, CDP, WebSocket, AST rename, OWASP sec, baton, etc.) without paying 11k schema tokens up front.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Task keyword(s), e.g. 'http authz', 'binary xref', 'rename', 'websocket'" },
                    "category": { "type": "string", "description": "Optional filter: 'read', 'orient', 'edit', 'probe', 'guard', 'baton', or 'all'" },
                    "include_schema": { "type": "boolean", "description": "Include full JSON inputSchema for matching tools (auto-enabled on exact tool name)" },
                    "limit": { "type": "integer", "description": "Max tools to return (default: 8)" }
                }
            }
        }),
        json!({
            "name": "ap_call",
            "description": "Invoke any specialist `ap_*` tool discovered via `ap_discover` (e.g. tool='ap_http', arguments={...}). Preserves full structuredContent output.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool": { "type": "string", "description": "Target tool name (e.g. 'ap_http', 'ap_rename', 'ap_locate', 'ap_ws')" },
                    "arguments": { "type": "object", "description": "Arguments forwarded directly to that tool" }
                },
                "required": ["tool"]
            }
        }),
    ]
}

fn mcp_tools_for_profile(profile: McpProfile) -> Value {
    let all = mcp_tools_schema();
    match profile {
        McpProfile::Full => all,
        McpProfile::Deferred => annotate_mcp_tools(Value::Array(meta_tools_schema())),
        McpProfile::Core => {
            const CORE_NAMES: &[&str] = &[
                "ap_orient",
                "ap_read",
                "ap_search",
                "ap_edit",
                "ap_verify",
                "ap_smoke",
                "ap_exec",
                "ap_sieve",
            ];
            let mut picked: Vec<Value> = all
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter(|t| {
                            t.get("name")
                                .and_then(Value::as_str)
                                .map(|n| CORE_NAMES.contains(&n))
                                .unwrap_or(false)
                        })
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            let meta = annotate_mcp_tools(Value::Array(meta_tools_schema()));
            if let Value::Array(m_arr) = meta {
                picked.extend(m_arr);
            }
            Value::Array(picked)
        }
    }
}

fn tool_annotations_for(name: &str) -> (&'static str, bool, bool, bool, bool) {
    // (title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint)
    match name {
        "ap_discover" => ("Discover ap Specialist Tools", true, false, true, false),
        "ap_call" => ("Invoke Any ap Tool", false, false, false, true),
        "ap_read" => ("Universal File & URL Reader", true, false, true, true),
        "ap_query" => (
            "Exact SQLite/Office/CSV SQL Query",
            true,
            false,
            true,
            false,
        ),
        "ap_search" => (
            "Multi-Pattern AST & Archive Search",
            true,
            false,
            true,
            false,
        ),
        "ap_undo" => ("Restore Pre-Edit Checkpoint", false, false, false, false),
        "ap_orient" => ("Workspace X-Ray & Product Map", true, false, true, false),
        "ap_impact" => ("Tree-Sitter Symbol Impact Graph", true, false, true, false),
        "ap_edit" => (
            "Atomic AST-Verified Multi-File Edit",
            false,
            false,
            false,
            false,
        ),
        "ap_rename" => (
            "AST-Exact Workspace Symbol Rename",
            false,
            false,
            false,
            false,
        ),
        "ap_smoke" => (
            "Headless Browser & API Smoke Test",
            false,
            false,
            false,
            true,
        ),
        "ap_fuzz" => ("API & CLI Boundary Fuzzer", false, false, false, true),
        "ap_mutate" => ("AST Mutation Test Auditor", false, false, false, false),
        "ap_ui" => (
            "Headless Desktop/Mobile UI Auditor",
            true,
            false,
            true,
            true,
        ),
        "ap_locate" => ("Hierarchical Fault Localizer", true, false, true, false),
        "ap_trace" => ("Multi-Hop AST Call-Chain Tracer", true, false, true, false),
        "ap_cdp" => ("Live Browser CDP Probe", false, false, false, true),
        "ap_http" => ("HTTP/API Diagnostic Probe", false, false, false, true),
        "ap_ports" => ("Listening TCP Port & CDP Radar", true, false, true, false),
        "ap_ps" => ("Process Tree & Command Inspector", true, false, true, false),
        "ap_win" => ("Windows Native OS Inspector", true, false, true, false),
        "ap_fs_diff" => ("Filesystem Snapshot & Diff", false, false, false, false),
        "ap_tcp" => ("Bounded Raw TCP Probe", false, false, false, true),
        "ap_listen" => (
            "Ephemeral Webhook Capture Server",
            false,
            false,
            false,
            true,
        ),
        "ap_ws" => ("Bounded WebSocket Probe", false, false, false, true),
        "ap_tls" => ("TLS & X.509 Certificate Inspector", true, false, true, true),
        "ap_baton_claim" => (
            "Multi-Agent Resource Lease Manager",
            false,
            false,
            false,
            false,
        ),
        "ap_baton_dedup" => (
            "BM25+CJK Semantic Near-Duplicate Finder",
            true,
            false,
            true,
            false,
        ),
        "ap_guard_pack" => (
            "Deliverable Bundle & SHA-256 Gate",
            true,
            false,
            true,
            false,
        ),
        "ap_diff_audit" => ("Semantic Git Diff Self-Audit", true, false, true, false),
        "ap_verify" => ("Quality Gate & Test Verifier", true, false, true, false),
        "ap_exec" => (
            "UTF-8 Healed Shell Command Runner",
            false,
            true,
            false,
            true,
        ),
        "ap_probe" => ("Runtime Microscope & Log Sieve", false, false, false, false),
        "ap_sieve" => (
            "Lossless Archive Peek & FTS5 Search",
            true,
            false,
            true,
            false,
        ),
        "ap_baton" => (
            "Compaction-Proof Task State Capsule",
            false,
            false,
            false,
            false,
        ),
        "ap_recall" => (
            "Sub-ms Triggered Micro-Memory Vault",
            false,
            false,
            false,
            false,
        ),
        "ap_changes" => ("Git-Diff AST Change Impact Brief", true, false, true, false),
        "ap_surface" => (
            "Multi-Axis Entrypoint & Sink Surface Map",
            true,
            false,
            true,
            false,
        ),
        "ap_frontier" => (
            "Orthogonal Exploration Frontier Tracker",
            false,
            false,
            false,
            false,
        ),
        _ => ("Agent Primitive Tool", false, false, false, false),
    }
}

fn tool_output_schema_for(name: &str) -> Value {
    match name {
        "ap_discover" => json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "profile": { "type": "string" },
                "total_tools": { "type": "integer" },
                "matched": { "type": "integer" },
                "tools": { "type": "array" },
                "text": { "type": "string" }
            },
            "additionalProperties": true
        }),
        "ap_call" => json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "tool": { "type": "string" },
                "text": { "type": "string" }
            },
            "additionalProperties": true
        }),
        "ap_search" => json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "elapsed_ms": { "type": "number" },
                "scanned_files": { "type": "integer" },
                "filtered_non_code": { "type": "integer" },
                "filtered_tests": { "type": "integer" },
                "total_matches": { "type": "integer" },
                "matches": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "file": { "type": "string" },
                            "line": { "type": "integer" },
                            "symbol": { "type": "string" },
                            "snippet": { "type": "string" }
                        },
                        "additionalProperties": true
                    }
                },
                "files": { "type": "array", "items": { "type": "string" } },
                "counts": { "type": "object", "additionalProperties": { "type": "integer" } },
                "text": { "type": "string" }
            },
            "additionalProperties": true
        }),
        "ap_query" => json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "elapsed_ms": { "type": "number" },
                "row_count": { "type": "integer" },
                "columns": { "type": "array", "items": { "type": "string" } },
                "rows": { "type": "array", "items": { "type": "array" } },
                "records": { "type": "array", "items": { "type": "object", "additionalProperties": true } },
                "tables": { "type": "array", "items": { "type": "object", "additionalProperties": true } },
                "text": { "type": "string" }
            },
            "additionalProperties": true
        }),
        "ap_diff_audit" => json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "is_git_repo": { "type": "boolean" },
                "files_scanned": { "type": "integer" },
                "added_lines": { "type": "integer" },
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": { "type": "string" },
                            "file": { "type": "string" },
                            "line": { "type": "integer" },
                            "detail": { "type": "string" }
                        },
                        "additionalProperties": true
                    }
                },
                "text": { "type": "string" }
            },
            "additionalProperties": true
        }),
        "ap_edit" | "ap_rename" => json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "modified_files": { "type": "array", "items": { "type": "string" } },
                "replacements": { "type": "integer" },
                "rolled_back": { "type": "boolean" },
                "issues": { "type": "array" },
                "text": { "type": "string" }
            },
            "additionalProperties": true
        }),
        "ap_verify" => json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "passed": { "type": "boolean" },
                "findings": { "type": "array" },
                "issues": { "type": "array" },
                "text": { "type": "string" }
            },
            "additionalProperties": true
        }),
        "ap_locate" | "ap_trace" | "ap_changes" | "ap_impact" => json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "files": { "type": "array", "items": { "type": "string" } },
                "symbols": { "type": "array" },
                "callers": { "type": "array" },
                "text": { "type": "string" }
            },
            "additionalProperties": true
        }),
        "ap_sieve" | "ap_baton" | "ap_recall" | "ap_read" | "ap_orient" | "ap_exec" => json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "id": { "type": "string" },
                "items": { "type": "array" },
                "text": { "type": "string" }
            },
            "additionalProperties": true
        }),
        _ => json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "items": { "type": "array" },
                "text": { "type": "string" }
            },
            "additionalProperties": true
        }),
    }
}

fn annotate_mcp_tools(mut tools: Value) -> Value {
    if let Value::Array(ref mut arr) = tools {
        for item in arr.iter_mut() {
            if let Some(obj) = item.as_object_mut() {
                let name = obj
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let (title, ro, destr, idemp, open) = tool_annotations_for(&name);
                obj.entry("title".to_string())
                    .or_insert_with(|| Value::String(title.to_string()));
                obj.insert(
                    "annotations".to_string(),
                    json!({
                        "title": title,
                        "readOnlyHint": ro,
                        "destructiveHint": destr,
                        "idempotentHint": idemp,
                        "openWorldHint": open
                    }),
                );
                obj.insert("outputSchema".to_string(), tool_output_schema_for(&name));
            }
        }
    }
    tools
}

fn run_self_captured(args: &[String], stdin_data: Option<&str>) -> (bool, String) {
    run_self_captured_in(None, args, stdin_data)
}

fn run_self_captured_in(
    cwd: Option<&str>,
    args: &[String],
    stdin_data: Option<&str>,
) -> (bool, String) {
    let Ok(exe) = std::env::current_exe() else {
        return (false, "Failed to locate ap binary".to_string());
    };
    let mut cmd = Command::new(exe);
    cmd.args(args).env("AP_MCP_CHILD", "1");
    if let Some(dir) = cwd.filter(|s| !s.trim().is_empty()) {
        cmd.current_dir(dir);
    }
    cmd.stdin(if stdin_data.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    });
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (false, format!("spawn error: {e}")),
    };
    if let Some(inp) = stdin_data {
        if let Some(mut sin) = child.stdin.take() {
            let _ = sin.write_all(inp.as_bytes());
        }
    }
    match child.wait_with_output() {
        Ok(o) => {
            let mut txt = String::from_utf8_lossy(&o.stdout).to_string();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.trim().is_empty() {
                if !txt.is_empty() && !txt.ends_with('\n') {
                    txt.push('\n');
                }
                txt.push_str(&err);
            }
            (o.status.success(), txt)
        }
        Err(e) => (false, format!("wait error: {e}")),
    }
}

fn dispatch_tool_call(name: &str, args: &Value) -> (bool, String) {
    match name {
        "ap_read" => {
            let mut all_targets: Vec<String> = Vec::new();
            if let Some(t) = args
                .get("target")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                all_targets.push(t.to_string());
            }
            if let Some(arr) = args.get("targets").and_then(Value::as_array) {
                for v in arr {
                    if let Some(s) = v.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                        if !all_targets.iter().any(|x| x == s) {
                            all_targets.push(s.to_string());
                        }
                    }
                }
            }
            if all_targets.is_empty() {
                return (
                    false,
                    "Pass non-empty `target` or `targets` to `ap_read`.".to_string(),
                );
            }
            let mut cli = vec!["read".to_string()];
            cli.extend(all_targets);
            if let Some(sym) = args
                .get("symbol")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--symbol".to_string());
                cli.push(sym.trim().to_string());
            }
            if args
                .get("outline")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--outline".to_string());
            }
            if let Some(l) = args
                .get("lines")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--lines".to_string());
                cli.push(l.to_string());
            }
            if let Some(w) = args
                .get("width")
                .or_else(|| args.get("max_line_len"))
                .and_then(Value::as_u64)
            {
                if w > 0 {
                    cli.push("--width".to_string());
                    cli.push(w.to_string());
                }
            }
            if let Some(q) = args
                .get("query")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--query".to_string());
                cli.push(q.to_string());
            }
            if let Some(sec) = args
                .get("section")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--section".to_string());
                cli.push(sec.trim().to_string());
            }
            if let Some(ar) = args.get("around").and_then(Value::as_u64) {
                if ar > 0 {
                    cli.push("--around".to_string());
                    cli.push(ar.to_string());
                }
            }
            if let Some(mh) = args.get("max_hits").and_then(Value::as_u64) {
                if mh > 0 {
                    cli.push("--max-hits".to_string());
                    cli.push(mh.to_string());
                }
            }
            if let Some(sh) = args
                .get("sheet")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--sheet".to_string());
                cli.push(sh.to_string());
            }
            if let Some(ent) = args
                .get("entry")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--entry".to_string());
                cli.push(ent.to_string());
            }
            if let Some(off_val) = args.get("offset") {
                if let Some(s) = off_val.as_str().filter(|x| !x.trim().is_empty()) {
                    cli.push("--offset".to_string());
                    cli.push(s.to_string());
                } else if let Some(n) = off_val.as_u64() {
                    cli.push("--offset".to_string());
                    cli.push(n.to_string());
                }
            }
            if let Some(ch) = args.get("chars").and_then(Value::as_u64) {
                cli.push("--chars".to_string());
                cli.push(ch.to_string());
            }
            if args.get("pretty").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--pretty".to_string());
            }
            if let Some(jp) = args
                .get("json_path")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--json-path".to_string());
                cli.push(jp.to_string());
            }
            if let Some(mp) = args
                .get("map_pos")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--map-pos".to_string());
                cli.push(mp.to_string());
            }
            if args.get("decode").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--decode".to_string());
            }
            if args.get("render").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--render".to_string());
            }
            if args.get("hex").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--hex".to_string());
            }
            if let Some(rv) = args
                .get("rva")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--rva".to_string());
                cli.push(rv.trim().to_string());
            }
            if let Some(va) = args
                .get("va")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--va".to_string());
                cli.push(va.trim().to_string());
            }
            if let Some(fb) = args
                .get("find_bytes")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--find-bytes".to_string());
                cli.push(fb.trim().to_string());
            }
            if args.get("xref").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--xref".to_string());
            }
            if args.get("cert").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--cert".to_string());
            }
            if args.get("proto").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--proto".to_string());
            }
            if args.get("routes").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--routes".to_string());
            }
            if args.get("jwt").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--jwt".to_string());
            }
            if args
                .get("secrets")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--secrets".to_string());
            }
            if let Some(df) = args
                .get("diff")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--diff".to_string());
                cli.push(df.trim().to_string());
            }
            if args.get("scrub").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--scrub".to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_query" => {
            let files: Vec<&str> = args
                .get("files")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if files.is_empty() {
                return (
                    false,
                    "Pass non-empty `files` array (e.g. ['t=data.xlsx']) to `ap_query`."
                        .to_string(),
                );
            }
            let mut cli = vec!["query".to_string()];
            for f in files {
                cli.push("-f".to_string());
                cli.push(f.to_string());
            }
            if args.get("schema").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--schema".to_string());
            }
            if args
                .get("format")
                .and_then(Value::as_str)
                .map(|s| s.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
            {
                cli.push("--json".to_string());
            }
            if let Some(out_p) = args
                .get("out")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--out".to_string());
                cli.push(out_p.to_string());
            }
            if let Some(sql) = args
                .get("sql")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push(sql.to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_search" => {
            let ast_expr = args
                .get("ast")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let mut all_pats: Vec<String> = Vec::new();
            if let Some(p) = args
                .get("pattern")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                all_pats.push(p.to_string());
            }
            if let Some(arr) = args.get("patterns").and_then(Value::as_array) {
                for item in arr {
                    if let Some(s) = item.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                        all_pats.push(s.to_string());
                    }
                }
            }
            if all_pats.is_empty() && ast_expr.is_none() {
                return (
                    false,
                    "Pass non-empty `pattern`, `patterns`, or `ast` to `ap_search`.".to_string(),
                );
            }
            let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let first_pat = all_pats.first().cloned().unwrap_or_default();
            let mut cli = vec!["search".to_string()];
            if let Some(ae) = ast_expr {
                cli.push("--ast".to_string());
                cli.push(ae.to_string());
            }
            cli.push(first_pat);
            cli.push(path.to_string());
            if let Some(extra_paths) = args.get("paths").and_then(Value::as_array) {
                for item in extra_paths {
                    if let Some(p) = item.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                        cli.push(p.to_string());
                    }
                }
            }
            for extra in all_pats.iter().skip(1) {
                cli.push("--pat".to_string());
                cli.push(extra.clone());
            }
            if let Some(ext) = args
                .get("ext")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--ext".to_string());
                cli.push(ext.to_string());
            }
            if args.get("pretty").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--pretty".to_string());
            }
            if args
                .get("multiline")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--multiline".to_string());
            }
            if args.get("block").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--block".to_string());
            }
            if let Some(ctx) = args.get("context").and_then(Value::as_u64) {
                if ctx > 0 {
                    cli.push("--context".to_string());
                    cli.push(ctx.to_string());
                }
            }
            if let Some(bc) = args.get("before_context").and_then(Value::as_u64) {
                if bc > 0 {
                    cli.push("--before-context".to_string());
                    cli.push(bc.to_string());
                }
            }
            if let Some(ac) = args.get("after_context").and_then(Value::as_u64) {
                if ac > 0 {
                    cli.push("--after-context".to_string());
                    cli.push(ac.to_string());
                }
            }
            if args
                .get("invert_match")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--invert-match".to_string());
            }
            if args
                .get("files_only")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--files-only".to_string());
            }
            if args.get("count").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--count".to_string());
            }
            if args
                .get("only_matching")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--only-matching".to_string());
            }
            if args.get("unique").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--unique".to_string());
            }
            if args
                .get("fixed_strings")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--fixed-strings".to_string());
            }
            if args
                .get("ignore_case")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--ignore-case".to_string());
            }
            if let Some(inc_arr) = args.get("include").and_then(Value::as_array) {
                for item in inc_arr {
                    if let Some(inc) = item.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                        cli.push("--include".to_string());
                        cli.push(inc.to_string());
                    }
                }
            }
            if args
                .get("code_only")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--code-only".to_string());
            }
            if args
                .get("no_tests")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--no-tests".to_string());
            }
            if let Some(ex_arr) = args.get("exclude").and_then(Value::as_array) {
                for item in ex_arr {
                    if let Some(ex) = item.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                        cli.push("--exclude".to_string());
                        cli.push(ex.to_string());
                    }
                }
            }
            if let Some(w) = args
                .get("width")
                .or_else(|| args.get("max_line_len"))
                .and_then(Value::as_u64)
            {
                if w > 0 {
                    cli.push("--width".to_string());
                    cli.push(w.to_string());
                }
            }
            if let Some(ar) = args.get("around").and_then(Value::as_u64) {
                if ar > 0 {
                    cli.push("--around".to_string());
                    cli.push(ar.to_string());
                }
            }
            if let Some(mh) = args
                .get("max_hits")
                .or_else(|| args.get("max"))
                .and_then(Value::as_u64)
            {
                if mh > 0 {
                    cli.push("--max-hits".to_string());
                    cli.push(mh.to_string());
                }
            }
            if let Some(pp) = args.get("per_pattern").and_then(Value::as_u64) {
                if pp > 0 {
                    cli.push("--per-pattern".to_string());
                    cli.push(pp.to_string());
                }
            }
            if args.get("json").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--json".to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_undo" => {
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let mut cli = vec!["undo".to_string()];
            if action == "list" || args.get("list").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--list".to_string());
                cli.push("--json".to_string());
            } else if action == "save" {
                let lbl = args
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                if lbl.is_empty() {
                    return (
                        false,
                        "Pass non-empty `label` for `ap_undo(action='save')`.".to_string(),
                    );
                }
                cli.push("--save".to_string());
                cli.push(lbl.to_string());
                if let Some(cwd) = args.get("cwd").and_then(Value::as_str) {
                    if !cwd.trim().is_empty() {
                        cli.push("--cwd".to_string());
                        cli.push(cwd.to_string());
                    }
                }
                cli.push("--json".to_string());
                if let Some(arr) = args.get("files").and_then(Value::as_array) {
                    for f in arr {
                        if let Some(s) = f.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                            cli.push(s.to_string());
                        }
                    }
                }
            } else if action == "diff" {
                cli.push("--diff".to_string());
                if let Some(id_s) = args
                    .get("id")
                    .and_then(Value::as_str)
                    .or_else(|| args.get("label").and_then(Value::as_str))
                {
                    if !id_s.trim().is_empty() {
                        cli.push("--id".to_string());
                        cli.push(id_s.trim().to_string());
                    }
                }
                cli.push("--json".to_string());
            } else {
                if let Some(id_s) = args
                    .get("id")
                    .and_then(Value::as_str)
                    .or_else(|| args.get("label").and_then(Value::as_str))
                {
                    if !id_s.trim().is_empty() {
                        cli.push("--id".to_string());
                        cli.push(id_s.trim().to_string());
                    }
                }
                if args.get("keep").and_then(Value::as_bool).unwrap_or(false) {
                    cli.push("--keep".to_string());
                }
                cli.push("--json".to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_orient" => {
            let root = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let root_p = std::path::Path::new(root);
            if !root_p.exists() {
                return (false, format!("[atlas] path not found: {root}"));
            }
            let data = ap_atlas::scan_workspace(root_p, "", 35, 14);
            let raw_b = data.raw_bytes as u64;
            let map_txt = ap_atlas::render_atlas_md(&data);
            let pm = ap_atlas::product::build_product_map(root_p, ap_atlas::SKIP_DIRS);
            let prod_txt = ap_atlas::product::render_product_map(&pm);
            let out = format!("{map_txt}\n{prod_txt}");
            crate::stats::record_event(
                "orient",
                raw_b.max(out.len() as u64),
                out.len() as u64,
                0,
                1,
                "mcp-orient",
            );
            (true, out)
        }
        "ap_edit" => {
            let cwd = args.get("cwd").and_then(Value::as_str).unwrap_or(".");
            let run_tests = args
                .get("run_tests")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let mut ops = Vec::new();
            if let Some(writes) = args.get("writes").and_then(Value::as_array) {
                for w in writes {
                    if let (Some(p), Some(c)) = (
                        w.get("path").and_then(Value::as_str),
                        w.get("content").and_then(Value::as_str),
                    ) {
                        ops.push(json!({ "op": "write", "path": p, "content": c }));
                    }
                }
            }
            if let Some(edits) = args.get("edits").and_then(Value::as_array) {
                for e in edits {
                    if let (Some(p), Some(o), Some(n)) = (
                        e.get("path").and_then(Value::as_str),
                        e.get("old").and_then(Value::as_str),
                        e.get("new").and_then(Value::as_str),
                    ) {
                        let mut op = json!({ "op": "replace", "path": p, "old": o, "new": n });
                        if let Some(lh) = e.get("line_hint").and_then(Value::as_str) {
                            if !lh.trim().is_empty() {
                                op["line_hint"] = Value::String(lh.trim().to_string());
                            }
                        }
                        if e.get("all").and_then(Value::as_bool).unwrap_or(false) {
                            op["all"] = Value::Bool(true);
                        }
                        ops.push(op);
                    }
                }
            }
            if let Some(appends) = args.get("appends").and_then(Value::as_array) {
                for a in appends {
                    if let (Some(p), Some(c)) = (
                        a.get("path").and_then(Value::as_str),
                        a.get("content").and_then(Value::as_str),
                    ) {
                        ops.push(json!({ "op": "append", "path": p, "content": c }));
                    }
                }
            }
            if let Some(symbols) = args.get("symbols").and_then(Value::as_array) {
                for s in symbols {
                    if let (Some(p), Some(sym)) = (
                        s.get("path").and_then(Value::as_str),
                        s.get("symbol").and_then(Value::as_str),
                    ) {
                        let mode = s
                            .get("mode")
                            .and_then(Value::as_str)
                            .unwrap_or("replace")
                            .trim()
                            .to_ascii_lowercase();
                        let op_name = match mode.as_str() {
                            "insert_after" | "insert-after" | "after" => "insert_after_symbol",
                            "insert_before" | "insert-before" | "before" => "insert_before_symbol",
                            "delete" | "remove" => "delete_symbol",
                            _ => "replace_symbol",
                        };
                        let c = s.get("content").and_then(Value::as_str).unwrap_or("");
                        if op_name != "delete_symbol"
                            && s.get("content").and_then(Value::as_str).is_none()
                        {
                            continue;
                        }
                        ops.push(json!({
                            "op": op_name,
                            "path": p,
                            "symbol": sym,
                            "new": c
                        }));
                    }
                }
            }
            if let Some(diff_raw) = args
                .get("diff")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                match ap_splice::patch::parse_edit_spec(diff_raw) {
                    Ok(parsed) => {
                        for p_op in parsed {
                            if let Ok(v) = serde_json::to_value(p_op) {
                                ops.push(v);
                            }
                        }
                    }
                    Err(e) => {
                        return (false, format!("[ap_edit] invalid `diff` patch: {e}"));
                    }
                }
            }
            if ops.is_empty() {
                return (
                    false,
                    "Provide at least one entry in `writes`, `edits`, `appends`, `symbols`, or `diff`."
                        .to_string(),
                );
            }
            let mut touched_for_undo = Vec::new();
            for item in &ops {
                if let Some(p) = item.get("path").and_then(Value::as_str) {
                    touched_for_undo.push(p.to_string());
                }
            }
            let undo_snap =
                crate::undo::record_pre_edit_snapshot(std::path::Path::new(cwd), &touched_for_undo);
            let n_ops = ops.len() as u32;
            let spec = json!({ "edits": ops }).to_string();
            let mut cli = vec![
                "splice".to_string(),
                "apply".to_string(),
                "--cwd".to_string(),
                cwd.to_string(),
                "--stdin".to_string(),
            ];
            if run_tests {
                cli.push("--test".to_string());
            }
            let (ok, mut out) = run_self_captured(&cli, Some(&spec));
            if ok {
                crate::stats::record_event("edit", 0, 0, 0, n_ops, "mcp-edit");
                if let Some(ref snap) = undo_snap {
                    let warns = crate::undo::check_truncation_warnings(snap);
                    if !warns.is_empty() {
                        out.push('\n');
                        out.push_str(&warns.join("\n"));
                    }
                }
            }
            (ok, out)
        }
        "ap_impact" => {
            let root = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let root_p = std::path::Path::new(root);
            if !root_p.exists() {
                return (false, format!("[atlas] path not found: {root}"));
            }
            let file_arg = args
                .get("file")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if !file_arg.is_empty() {
                let depth = args
                    .get("depth")
                    .and_then(Value::as_u64)
                    .map(|n| n as usize)
                    .unwrap_or(2);
                let dead = args.get("dead").and_then(Value::as_bool).unwrap_or(false);
                let rep = ap_atlas::deps::analyze_module_deps_with_opts(
                    root_p,
                    file_arg,
                    depth,
                    dead,
                    ap_atlas::SKIP_DIRS,
                );
                let out = ap_atlas::deps::render_deps_md(&rep);
                crate::stats::record_event("impact", 0, out.len() as u64, 0, 1, "mcp-deps");
                return (true, out);
            }
            let sym = args
                .get("symbol")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if sym.is_empty() {
                return (
                    false,
                    "Pass non-empty `symbol` or `file` to `ap_impact`.".to_string(),
                );
            }
            let rep = ap_atlas::impact::analyze_symbol_impact(
                root_p,
                &[sym.to_string()],
                ap_atlas::SKIP_DIRS,
            );
            let out = ap_atlas::impact::render_impact_md(&rep);
            crate::stats::record_event("impact", 0, out.len() as u64, 0, 1, "mcp-impact");
            (true, out)
        }
        "ap_fuzz" => {
            let cwd = args.get("cwd").and_then(Value::as_str).unwrap_or(".");
            let mut cli = vec![
                "probe".to_string(),
                "fuzz".to_string(),
                "--cwd".to_string(),
                cwd.to_string(),
            ];
            if let Some(st) = args
                .get("start")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--start".to_string());
                cli.push(st.to_string());
            }
            if let Some(cc) = args
                .get("cli")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--cli".to_string());
                cli.push(cc.to_string());
            }
            if let Some(conc) = args.get("concurrency").and_then(Value::as_u64) {
                cli.push("--concurrency".to_string());
                cli.push(conc.to_string());
            }
            let (ok, out) = run_self_captured(&cli, None);
            crate::stats::record_event("fuzz", 0, out.len() as u64, 0, 1, "mcp-fuzz");
            (ok, out)
        }
        "ap_mutate" => {
            let cwd = args.get("cwd").and_then(Value::as_str).unwrap_or(".");
            let target = args
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if target.is_empty() {
                return (false, "Pass `target` file path to `ap_mutate`.".to_string());
            }
            let mut cli = vec![
                "probe".to_string(),
                "mutate".to_string(),
                target.to_string(),
                "--cwd".to_string(),
                cwd.to_string(),
            ];
            if let Some(tc) = args
                .get("test_cmd")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--test-cmd".to_string());
                cli.push(tc.to_string());
            }
            if let Some(mm) = args.get("max_mutants").and_then(Value::as_u64) {
                cli.push("--max-mutants".to_string());
                cli.push(mm.to_string());
            }
            let (ok, out) = run_self_captured(&cli, None);
            crate::stats::record_event("mutate", 0, out.len() as u64, 0, 1, "mcp-mutate");
            (ok, out)
        }
        "ap_ui" => {
            let cwd = args.get("cwd").and_then(Value::as_str).unwrap_or(".");
            let mut cli = vec![
                "probe".to_string(),
                "ui".to_string(),
                "--cwd".to_string(),
                cwd.to_string(),
            ];
            if let Some(st) = args
                .get("start")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--start".to_string());
                cli.push(st.to_string());
            }
            if let Some(p) = args
                .get("path")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--path".to_string());
                cli.push(p.to_string());
            }
            if let Some(sc) = args
                .get("screenshot")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--screenshot".to_string());
                cli.push(sc.to_string());
            }
            let (ok, out) = run_self_captured(&cli, None);
            crate::stats::record_event("ui", 0, out.len() as u64, 0, 1, "mcp-ui");
            (ok, out)
        }
        "ap_locate" => {
            let q = args
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if q.is_empty() {
                return (false, "Pass non-empty `query` to `ap_locate`.".to_string());
            }
            let root = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let root_p = std::path::Path::new(root);
            if !root_p.exists() {
                return (false, format!("[atlas] path not found: {root}"));
            }
            let top_k = args.get("top_k").and_then(Value::as_u64).unwrap_or(5) as usize;
            let rep = ap_atlas::locate::locate_faults(root_p, q, top_k);
            let out = ap_atlas::locate::render_locate_md(&rep);
            crate::stats::record_event("locate", 0, out.len() as u64, 0, 1, "mcp-locate");
            (true, out)
        }
        "ap_exec" => {
            let cwd = args.get("cwd").and_then(Value::as_str).unwrap_or(".");
            let cmd = args
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if cmd.is_empty() {
                return (false, "Pass non-empty `command` to `ap_exec`.".to_string());
            }
            let mut cli = vec![
                "exec".to_string(),
                "--cwd".to_string(),
                cwd.to_string(),
                "-c".to_string(),
                cmd.to_string(),
            ];
            if let Some(t) = args.get("timeout").and_then(Value::as_u64) {
                cli.push("--timeout".to_string());
                cli.push(t.to_string());
            }
            if let Some(fp) = args.get("free_port").and_then(Value::as_u64) {
                cli.push("--free-port".to_string());
                cli.push(fp.to_string());
            }
            if args.get("scrub").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--scrub".to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_smoke" => {
            let cwd = args.get("cwd").and_then(Value::as_str).unwrap_or(".");
            let steps: Vec<&str> = args
                .get("steps")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let spec_txt = steps.join("\n");
            let mut cli = vec![
                "probe".to_string(),
                "smoke".to_string(),
                "--cwd".to_string(),
                cwd.to_string(),
                "--stdin".to_string(),
            ];
            if let Some(st) = args
                .get("start")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--start".to_string());
                cli.push(st.to_string());
            }
            let (ok, out) = run_self_captured(&cli, Some(&spec_txt));
            crate::stats::record_event("smoke", 0, 0, 1, 1, "mcp-smoke");
            (ok, out)
        }
        "ap_trace" => {
            let sym = args
                .get("symbol")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if sym.is_empty() {
                return (false, "Pass non-empty `symbol` to `ap_trace`.".to_string());
            }
            let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let root_p = std::path::Path::new(path);
            if !root_p.exists() {
                return (false, format!("[atlas] path not found: {path}"));
            }
            let depth = args.get("depth").and_then(Value::as_u64).unwrap_or(3) as usize;
            let to_sink = args
                .get("to")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let include_sinks = args.get("sinks").and_then(Value::as_bool).unwrap_or(false);
            let rep =
                ap_atlas::trace::trace_symbol_chain_to(root_p, sym, to_sink, include_sinks, depth);
            let out = ap_atlas::trace::render_trace_md(&rep);
            crate::stats::record_event("trace", 0, out.len() as u64, 0, 1, "mcp-trace");
            (true, out)
        }
        "ap_cdp" => {
            let host = args
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("127.0.0.1");
            let port = args.get("port").and_then(Value::as_u64).unwrap_or(9222);
            let mut cli = vec![
                "probe".into(),
                "cdp".into(),
                "--host".into(),
                host.into(),
                "--port".into(),
                port.to_string(),
            ];
            if let Some(dp) = args
                .get("diff_ports")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--diff-ports".into());
                cli.push(dp.trim().to_string());
            }
            if let Some(tids) = args
                .get("target_ids")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--target-ids".into());
                cli.push(tids.trim().to_string());
            }
            if args.get("list").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--list".into());
            }
            if let Some(t) = args
                .get("target")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--target".into());
                cli.push(t.into());
            }
            if let Some(ev) = args
                .get("eval")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--eval".into());
                cli.push(ev.into());
            }
            if args.get("audit").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--audit".into());
            }
            if let Some(sp) = args
                .get("screenshot")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--screenshot".into());
                cli.push(sp.into());
            }
            if let Some(wm) = args.get("watch_ms").and_then(Value::as_u64) {
                if wm > 0 {
                    cli.push("--watch-ms".into());
                    cli.push(wm.to_string());
                }
            }
            run_self_captured(&cli, None)
        }
        "ap_http" => {
            let mut cli = vec!["probe".into(), "http".into()];
            if let Some(u) = args
                .get("url")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push(u.trim().to_string());
            }
            if let Some(m) = args
                .get("method")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("-X".into());
                cli.push(m.trim().to_string());
            }
            if let Some(hdrs) = args.get("headers").and_then(Value::as_array) {
                for h in hdrs.iter().filter_map(Value::as_str) {
                    cli.push("-H".into());
                    cli.push(h.to_string());
                }
            }
            if let Some(b) = args
                .get("body")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("-d".into());
                cli.push(b.to_string());
            }
            if let Some(t) = args.get("timeout").and_then(Value::as_u64) {
                cli.push("--timeout".into());
                cli.push(t.to_string());
            }
            if args
                .get("insecure")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--insecure".into());
            }
            if args.get("follow").and_then(Value::as_bool).unwrap_or(false) {
                cli.push("--follow".into());
            }
            if let Some(vr) = args
                .get("vary_request")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--vary-request".into());
                cli.push(vr.trim().to_string());
            }
            if let Some(vf) = args
                .get("vary_field")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--vary-field".into());
                cli.push(vf.trim().to_string());
            }
            if let Some(av) = args
                .get("alt_value")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                cli.push("--alt-value".into());
                cli.push(av.to_string());
            }
            if let Some(rm) = args.get("rate_ms").and_then(Value::as_u64) {
                cli.push("--rate-ms".into());
                cli.push(rm.to_string());
            }
            if let Some(mv) = args.get("max_variants").and_then(Value::as_u64) {
                cli.push("--max-variants".into());
                cli.push(mv.to_string());
            }
            if args
                .get("dry_run")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--dry-run".into());
            }
            if let Some(ps) = args.get("principals").and_then(Value::as_array) {
                for p in ps.iter().filter_map(Value::as_str) {
                    cli.push("--principal".into());
                    cli.push(p.to_string());
                }
            }
            if let Some(cp) = args.get("cdp_cookies").and_then(Value::as_u64) {
                if cp > 0 && cp <= 65535 {
                    cli.push("--cdp-cookies".into());
                    cli.push(cp.to_string());
                }
            }
            if let Some(pcp) = args.get("principal_cdps").and_then(Value::as_array) {
                for p in pcp.iter().filter_map(Value::as_str) {
                    cli.push("--principal-cdp".into());
                    cli.push(p.to_string());
                }
            }
            if let Some(co) = args
                .get("cors_origin")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--cors-origin".into());
                cli.push(co.trim().to_string());
            }
            if let Some(sel) = args
                .get("select")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--select".into());
                cli.push(sel.trim().to_string());
            }
            if args
                .get("audit_headers")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--audit-headers".into());
            }
            if let Some(rc) = args.get("race").and_then(Value::as_u64) {
                if rc >= 2 {
                    cli.push("--race".into());
                    cli.push(rc.to_string());
                }
            }
            if let Some(ss) = args.get("sentinels").and_then(Value::as_array) {
                for s in ss.iter().filter_map(Value::as_str) {
                    if !s.trim().is_empty() {
                        cli.push("--sentinel".into());
                        cli.push(s.trim().to_string());
                    }
                }
            }
            let batch_lines: Vec<&str> = args
                .get("batch_requests")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if !batch_lines.is_empty() {
                cli.push("--batch-stdin".into());
                let payload = batch_lines.join("\n");
                run_self_captured(&cli, Some(&payload))
            } else {
                run_self_captured(&cli, None)
            }
        }
        "ap_ports" => {
            let mut cli = vec!["probe".into(), "ports".into()];
            if let Some(p) = args.get("port").and_then(Value::as_u64) {
                cli.push("--port".into());
                cli.push(p.to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_ps" => {
            let mut cli = vec!["probe".into(), "ps".into()];
            if let Some(f) = args
                .get("filter")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--filter".into());
                cli.push(f.to_string());
            }
            if let Some(pid) = args.get("pid").and_then(Value::as_u64) {
                cli.push("--pid".into());
                cli.push(pid.to_string());
            }
            if let Some(lim) = args.get("limit").and_then(Value::as_u64) {
                cli.push("--limit".into());
                cli.push(lim.to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_win" => {
            let mut cli = vec!["probe".into(), "win".into(), "--json".into()];
            if args.get("pipes").and_then(Value::as_bool) == Some(true) {
                cli.push("--pipes".into());
            }
            if let Some(rg) = args
                .get("reg")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--reg".into());
                cli.push(rg.to_string());
            }
            if let Some(ac) = args
                .get("acl")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--acl".into());
                cli.push(ac.to_string());
            }
            if args.get("services").and_then(Value::as_bool) == Some(true) {
                cli.push("--services".into());
            }
            if args.get("whoami").and_then(Value::as_bool) == Some(true) {
                cli.push("--whoami".into());
            }
            if let Some(fl) = args
                .get("filter")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--filter".into());
                cli.push(fl.to_string());
            }
            if let Some(mx) = args.get("max").and_then(Value::as_u64) {
                cli.push("--max".into());
                cli.push(mx.to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_fs_diff" => {
            let dir = args.get("dir").and_then(Value::as_str).unwrap_or(".");
            let mut cli = vec!["probe".into(), "fs".into(), dir.into()];
            if let Some(r) = args.get("recent").and_then(Value::as_u64) {
                if r > 0 {
                    cli.push("--recent".into());
                    cli.push(r.to_string());
                }
            }
            if let Some(sn) = args
                .get("snapshot")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--snapshot".into());
                cli.push(sn.to_string());
            }
            if let Some(df) = args
                .get("diff")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--diff".into());
                cli.push(df.to_string());
            }
            if let Some(rc) = args
                .get("run")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--run".into());
                cli.push(rc.to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_tcp" => {
            let addr = args
                .get("addr")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if addr.is_empty() {
                return (
                    false,
                    "Pass non-empty `addr` (host:port) to `ap_tcp`.".to_string(),
                );
            }
            let mut cli = vec!["probe".into(), "tcp".into(), addr.to_string()];
            if let Some(s) = args.get("send").and_then(Value::as_str) {
                cli.push("--send".into());
                cli.push(s.to_string());
            }
            if let Some(hx) = args
                .get("send_hex")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--send-hex".into());
                cli.push(hx.to_string());
            }
            if let Some(wm) = args.get("wait_ms").and_then(Value::as_u64) {
                cli.push("--wait-ms".into());
                cli.push(wm.to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_listen" => {
            let mut cli = vec!["probe".into(), "listen".into()];
            if let Some(p) = args.get("port").and_then(Value::as_u64) {
                cli.push("--port".into());
                cli.push(p.to_string());
            }
            if let Some(wm) = args.get("wait_ms").and_then(Value::as_u64) {
                cli.push("--wait-ms".into());
                cli.push(wm.to_string());
            }
            if let Some(mr) = args.get("max_reqs").and_then(Value::as_u64) {
                cli.push("--max-reqs".into());
                cli.push(mr.to_string());
            }
            if let Some(rc) = args
                .get("run")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                cli.push("--run".into());
                cli.push(rc.to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_ws" => {
            let url = args.get("url").and_then(Value::as_str).unwrap_or("").trim();
            if url.is_empty() {
                return (
                    false,
                    "Pass non-empty `url` (ws://...) to `ap_ws`.".to_string(),
                );
            }
            let mut cli = vec!["probe".into(), "ws".into(), url.to_string()];
            if let Some(arr) = args.get("send").and_then(Value::as_array) {
                for m in arr.iter().filter_map(Value::as_str) {
                    cli.push("--send".into());
                    cli.push(m.to_string());
                }
            }
            if let Some(hdrs) = args.get("headers").and_then(Value::as_array) {
                for h in hdrs.iter().filter_map(Value::as_str) {
                    cli.push("-H".into());
                    cli.push(h.to_string());
                }
            }
            if let Some(wm) = args.get("wait_ms").and_then(Value::as_u64) {
                cli.push("--wait-ms".into());
                cli.push(wm.to_string());
            }
            if args
                .get("origin_matrix")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                cli.push("--origin-matrix".into());
            }
            if let Some(origs) = args.get("origins").and_then(Value::as_array) {
                for o in origs.iter().filter_map(Value::as_str) {
                    cli.push("--origin".into());
                    cli.push(o.to_string());
                }
            }
            run_self_captured(&cli, None)
        }
        "ap_tls" => {
            let addr = args
                .get("addr")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if addr.is_empty() {
                return (
                    false,
                    "Pass non-empty `addr` (host:port) to `ap_tls`.".to_string(),
                );
            }
            let mut cli = vec!["probe".into(), "tls".into(), addr.to_string()];
            if let Some(s) = args
                .get("sni")
                .and_then(Value::as_str)
                .filter(|x| !x.is_empty())
            {
                cli.push("--sni".into());
                cli.push(s.to_string());
            }
            if let Some(t) = args.get("timeout").and_then(Value::as_u64) {
                cli.push("--timeout".into());
                cli.push(t.to_string());
            }
            run_self_captured(&cli, None)
        }
        "ap_baton_claim" => {
            let act = args
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("list")
                .to_ascii_lowercase();
            let mut cli = vec!["baton".into()];
            match act.as_str() {
                "claim" => {
                    let res = args.get("resource").and_then(Value::as_str).unwrap_or("");
                    let own = args.get("owner").and_then(Value::as_str).unwrap_or("");
                    if res.is_empty() || own.is_empty() {
                        return (
                            false,
                            "Pass `resource` and `owner` for action='claim'.".into(),
                        );
                    }
                    cli.extend(["claim".into(), res.into(), "--owner".into(), own.into()]);
                    if let Some(ttl) = args.get("ttl").and_then(Value::as_u64) {
                        cli.extend(["--ttl".into(), ttl.to_string()]);
                    }
                    if let Some(note) = args.get("note").and_then(Value::as_str) {
                        cli.extend(["--note".into(), note.into()]);
                    }
                }
                "release" => {
                    let res = args.get("resource").and_then(Value::as_str).unwrap_or("");
                    if res.is_empty() {
                        return (false, "Pass `resource` for action='release'.".into());
                    }
                    cli.extend(["release".into(), res.into()]);
                    if let Some(own) = args.get("owner").and_then(Value::as_str) {
                        cli.extend(["--owner".into(), own.into()]);
                    }
                }
                _ => cli.push("claims".into()),
            }
            run_self_captured(&cli, None)
        }
        "ap_baton_dedup" => {
            let q = args
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            let files: Vec<&str> = args
                .get("files")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if q.is_empty() || files.is_empty() {
                return (false, "Pass non-empty `query` and `files` array.".into());
            }
            let mut cli = vec!["baton".into(), "dedup".into(), q.to_string()];
            for f in files {
                cli.push(f.to_string());
            }
            if let Some(k) = args.get("top_k").and_then(Value::as_u64) {
                cli.extend(["-k".into(), k.to_string()]);
            }
            run_self_captured(&cli, None)
        }
        "ap_guard_pack" => {
            let dir = args.get("dir").and_then(Value::as_str).unwrap_or(".");
            let mut cli = vec!["guard".into(), "pack".into(), dir.to_string()];
            if let Some(ml) = args.get("max_lines").and_then(Value::as_u64) {
                cli.extend(["--max-lines".into(), ml.to_string()]);
            }
            if let Some(hdrs) = args.get("require_headers").and_then(Value::as_array) {
                for h in hdrs.iter().filter_map(Value::as_str) {
                    cli.extend(["--require-header".into(), h.to_string()]);
                }
            }
            run_self_captured(&cli, None)
        }
        "ap_diff_audit" => {
            let cwd = args.get("cwd").and_then(Value::as_str).unwrap_or(".");
            let rep = ap_guard::diff_audit::audit_git_diff(std::path::Path::new(cwd));
            let ok = rep.findings.is_empty();
            let js = serde_json::to_string_pretty(&json!({
                "ok": ok,
                "is_git_repo": rep.is_git_repo,
                "files_changed": rep.files_changed,
                "lines_added": rep.lines_added,
                "lines_deleted": rep.lines_deleted,
                "findings": rep.findings,
            }))
            .unwrap_or_default();
            crate::stats::record_event("diff-audit", 0, js.len() as u64, 0, 1, "mcp-diff-audit");
            (ok, js)
        }
        "ap_verify" => {
            let cwd = args.get("cwd").and_then(Value::as_str).unwrap_or(".");
            let (_, prod_json) = run_self_captured(
                &[
                    "atlas".into(),
                    "product".into(),
                    cwd.into(),
                    "--json".into(),
                ],
                None,
            );
            let mut mismatch_lines = Vec::new();
            if let Ok(pj) = serde_json::from_str::<Value>(&prod_json) {
                if let Some(arr) = pj.get("contract_mismatches").and_then(Value::as_array) {
                    for m in arr {
                        if let Some(s) = m.as_str() {
                            mismatch_lines.push(format!("- [CONTRACT MISMATCH] {s}"));
                        }
                    }
                }
            }
            let mut v_args = vec!["guard".into(), "verify".into(), "--cwd".into(), cwd.into()];
            if args.get("deep").and_then(Value::as_bool).unwrap_or(false) {
                v_args.push("--deep".into());
            }
            let (g_ok, g_txt) = run_self_captured(&v_args, None);
            let ok = g_ok && mismatch_lines.is_empty();
            crate::stats::record_event("verify", 0, 0, 0, 1, "mcp-verify");
            let combined = if mismatch_lines.is_empty() {
                g_txt
            } else {
                format!(
                    "Contract mismatches detected:\n{}\n{g_txt}",
                    mismatch_lines.join("\n")
                )
            };
            (ok, combined)
        }
        "ap_probe" => {
            let cwd = args.get("cwd").and_then(Value::as_str).unwrap_or(".");
            if let Some(code) = args
                .get("code")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                return run_self_captured(
                    &[
                        "probe".into(),
                        "run".into(),
                        "--cwd".into(),
                        cwd.into(),
                        "--stdin".into(),
                    ],
                    Some(code),
                );
            }
            if let Some(scmd) = args
                .get("sieve_cmd")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                return run_self_captured(
                    &[
                        "exec".into(),
                        "--cwd".into(),
                        cwd.into(),
                        "-c".into(),
                        scmd.into(),
                    ],
                    None,
                );
            }
            (
                false,
                "Pass `code` or `sieve_cmd` to `ap_probe`.".to_string(),
            )
        }
        "ap_rename" => {
            let root = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let root_p = std::path::Path::new(root);
            let dry_run = args
                .get("dry_run")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let run_tests = args
                .get("run_tests")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let rollback = args
                .get("rollback_on_test_fail")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let pattern = args
                .get("pattern")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if !pattern.is_empty() {
                let Some(replacement) = args.get("replacement").and_then(Value::as_str) else {
                    return (
                        false,
                        "Pass `replacement` when using `pattern` in `ap_rename`.".to_string(),
                    );
                };
                let ext = args.get("ext").and_then(Value::as_str).unwrap_or("");
                let no_tests = args
                    .get("no_tests")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !dry_run {
                    let preview = ap_splice::rewrite::rewrite_pattern_workspace(
                        root_p,
                        pattern,
                        replacement,
                        ext,
                        no_tests,
                        true,
                        false,
                        "",
                        false,
                    );
                    if preview.ok && !preview.changes.is_empty() {
                        let touched: Vec<String> =
                            preview.changes.iter().map(|c| c.path.clone()).collect();
                        let _ = crate::undo::record_pre_edit_snapshot(root_p, &touched);
                    }
                }
                let rep = ap_splice::rewrite::rewrite_pattern_workspace(
                    root_p,
                    pattern,
                    replacement,
                    ext,
                    no_tests,
                    dry_run,
                    run_tests,
                    "",
                    rollback,
                );
                if rep.ok && !dry_run && rep.total_replacements > 0 {
                    crate::stats::record_event(
                        "rewrite",
                        0,
                        0,
                        0,
                        rep.files_changed as u32,
                        "mcp-rewrite",
                    );
                }
                let js = serde_json::to_string_pretty(&rep).unwrap_or_default();
                return (rep.ok, js);
            }

            let old_name = args
                .get("old_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            let new_name = args
                .get("new_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if old_name.is_empty() || new_name.is_empty() {
                return (
                    false,
                    "Pass non-empty `old_name` and `new_name` (or `pattern` and `replacement`) to `ap_rename`."
                        .to_string(),
                );
            }
            if !dry_run {
                let preview = ap_splice::rename::rename_symbol_workspace(
                    root_p, old_name, new_name, true, false, "", false,
                );
                if preview.ok && !preview.changes.is_empty() {
                    let touched: Vec<String> =
                        preview.changes.iter().map(|c| c.path.clone()).collect();
                    let _ = crate::undo::record_pre_edit_snapshot(root_p, &touched);
                }
            }
            let rep = ap_splice::rename::rename_symbol_workspace(
                root_p, old_name, new_name, dry_run, run_tests, "", rollback,
            );
            if rep.ok && !dry_run && rep.total_replacements > 0 {
                crate::stats::record_event(
                    "rename",
                    0,
                    0,
                    0,
                    rep.files_changed as u32,
                    "mcp-rename",
                );
            }
            let js = serde_json::to_string_pretty(&rep).unwrap_or_default();
            (rep.ok, js)
        }
        "ap_sieve" => {
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let cwd = args.get("cwd").and_then(Value::as_str);
            match action.as_str() {
                "peek" => {
                    let id = args.get("id").and_then(Value::as_str).unwrap_or("").trim();
                    if id.is_empty() {
                        return (
                            false,
                            "Pass non-empty `id` for `ap_sieve` action='peek'.".to_string(),
                        );
                    }
                    let mut cli = vec!["sieve".into(), "peek".into(), id.into()];
                    if let Some(l) = args
                        .get("lines")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        cli.push("--lines".into());
                        cli.push(l.into());
                    }
                    if let Some(g) = args
                        .get("grep")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        cli.push("--grep".into());
                        cli.push(g.into());
                    }
                    if let Some(jp) = args
                        .get("json_path")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        cli.push("--json-path".into());
                        cli.push(jp.into());
                    }
                    run_self_captured_in(cwd, &cli, None)
                }
                "search" => {
                    let q = args
                        .get("query")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim();
                    if q.is_empty() {
                        return (
                            false,
                            "Pass non-empty `query` for `ap_sieve` action='search'.".to_string(),
                        );
                    }
                    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(8) as usize;
                    let base_dir = std::env::var("SIEVE_HOME")
                        .ok()
                        .filter(|s| !s.trim().is_empty())
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| {
                            std::path::PathBuf::from(cwd.unwrap_or(".")).join(".sieve")
                        });
                    let (mut hits, mut elapsed_ms) = ap_sieve::search_archives(&base_dir, q, limit);
                    if hits.is_empty() {
                        if let Some(g) = ap_sieve::global_sieve_dir() {
                            if g != base_dir && g.join("index.sqlite").is_file() {
                                let (ghits, gms) = ap_sieve::search_archives(&g, q, limit);
                                if !ghits.is_empty() {
                                    hits = ghits;
                                    elapsed_ms = gms;
                                }
                            }
                        }
                    }
                    let js = serde_json::to_string_pretty(&json!({
                        "query": q,
                        "elapsed_ms": elapsed_ms,
                        "hits": hits,
                    }))
                    .unwrap_or_default();
                    (true, js)
                }
                _ => (
                    false,
                    "Pass `action`: 'peek' or 'search' to `ap_sieve`.".to_string(),
                ),
            }
        }
        "ap_baton" => {
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("resume")
                .trim()
                .to_ascii_lowercase();
            let cwd = args.get("cwd").and_then(Value::as_str);
            match action.as_str() {
                "resume" => run_self_captured_in(
                    cwd,
                    &["baton".into(), "resume".into(), "--json".into()],
                    None,
                ),
                "set" => {
                    let mut cli = vec!["baton".into(), "set".into()];
                    if let Some(g) = args
                        .get("goal")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        cli.push("--goal".into());
                        cli.push(g.into());
                    }
                    if let Some(cs) = args.get("constraints").and_then(Value::as_array) {
                        for c in cs {
                            if let Some(s) = c.as_str().filter(|s| !s.is_empty()) {
                                cli.push("--constraint".into());
                                cli.push(s.into());
                            }
                        }
                    }
                    if let Some(n) = args
                        .get("next")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        cli.push("--next".into());
                        cli.push(n.into());
                    }
                    run_self_captured_in(cwd, &cli, None)
                }
                "fact" => {
                    let text = args
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim();
                    if text.is_empty() {
                        return (
                            false,
                            "Pass non-empty `text` for `ap_baton` action='fact'.".to_string(),
                        );
                    }
                    let mut cli = vec!["baton".into(), "fact".into(), text.into()];
                    if let Some(r) = args
                        .get("ref")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        cli.push("--ref".into());
                        cli.push(r.into());
                    }
                    run_self_captured_in(cwd, &cli, None)
                }
                "deadend" => {
                    let text = args
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim();
                    if text.is_empty() {
                        return (
                            false,
                            "Pass non-empty `text` for `ap_baton` action='deadend'.".to_string(),
                        );
                    }
                    let mut cli = vec!["baton".into(), "deadend".into(), text.into()];
                    if let Some(r) = args
                        .get("reason")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        cli.push("--reason".into());
                        cli.push(r.into());
                    }
                    run_self_captured_in(cwd, &cli, None)
                }
                "checkpoint" => {
                    let mut cli = vec!["baton".into(), "checkpoint".into()];
                    if let Some(n) = args
                        .get("note")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        cli.push("--note".into());
                        cli.push(n.into());
                    }
                    run_self_captured_in(cwd, &cli, None)
                }
                "clear" => run_self_captured_in(cwd, &["baton".into(), "clear".into()], None),
                _ => (
                    false,
                    "Pass `action`: 'resume', 'set', 'fact', 'deadend', 'checkpoint', or 'clear'."
                        .to_string(),
                ),
            }
        }
        "ap_recall" => {
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("match")
                .trim()
                .to_ascii_lowercase();
            let cwd_p =
                std::path::Path::new(args.get("cwd").and_then(Value::as_str).unwrap_or("."));
            let vp = ap_recall::vault_path(cwd_p);
            let Ok(conn) = ap_recall::open_vault(&vp) else {
                return (
                    false,
                    format!("Failed to open recall vault at {}", vp.display()),
                );
            };
            match action.as_str() {
                "match" => {
                    let q = args.get("query").and_then(Value::as_str).unwrap_or("");
                    let files_raw = args.get("files").and_then(Value::as_str).unwrap_or("");
                    let file_list: Vec<String> = files_raw
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                    let top = args.get("top").and_then(Value::as_u64).unwrap_or(3) as usize;
                    match ap_recall::match_rules_in(&conn, cwd_p, q, &file_list, top) {
                        Ok((hits, elapsed_ms)) => (
                            true,
                            serde_json::to_string_pretty(&json!({
                                "elapsed_ms": (elapsed_ms * 100.0).round() / 100.0,
                                "matches": hits
                            }))
                            .unwrap_or_default(),
                        ),
                        Err(e) => (false, format!("recall match failed: {e}")),
                    }
                }
                "add" => {
                    let triggers = args
                        .get("triggers")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim();
                    let rule = args
                        .get("rule")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim();
                    if triggers.is_empty() || rule.is_empty() {
                        return (
                            false,
                            "Pass non-empty `triggers` and `rule` for `ap_recall` action='add'."
                                .to_string(),
                        );
                    }
                    let kind = args
                        .get("kind")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("gotcha");
                    let source_file = args.get("file").and_then(Value::as_str).unwrap_or("");
                    match ap_recall::add_rule_with_provenance(
                        &conn,
                        cwd_p,
                        triggers,
                        rule,
                        kind,
                        source_file,
                    ) {
                        Ok(id) => (
                            true,
                            serde_json::to_string_pretty(&json!({
                                "ok": true,
                                "id": id,
                                "kind": kind,
                                "triggers": triggers,
                                "file": source_file,
                            }))
                            .unwrap_or_default(),
                        ),
                        Err(e) => (false, format!("recall add failed: {e}")),
                    }
                }
                "verify" => {
                    let prune_stale = args
                        .get("prune_stale")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    match ap_recall::verify_vault(&conn, cwd_p, prune_stale) {
                        Ok(rep) => (true, serde_json::to_string_pretty(&rep).unwrap_or_default()),
                        Err(e) => (false, format!("recall verify failed: {e}")),
                    }
                }
                "stats" => match ap_recall::compute_stats(&conn) {
                    Ok(st) => (true, serde_json::to_string_pretty(&st).unwrap_or_default()),
                    Err(e) => (false, format!("recall stats failed: {e}")),
                },
                _ => (
                    false,
                    "Pass `action`: 'match', 'add', 'stats', or 'verify' to `ap_recall`."
                        .to_string(),
                ),
            }
        }
        "ap_changes" => {
            let root = args.get("path").and_then(Value::as_str).unwrap_or(".");
            if let Some(hf) = args
                .get("history_file")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let hf_raw = std::path::Path::new(hf);
                let hf_p = if hf_raw.is_absolute() || hf_raw.exists() {
                    hf_raw.to_path_buf()
                } else {
                    std::path::Path::new(root).join(hf_raw)
                };
                if !hf_p.exists() {
                    return (false, format!("[atlas] history_file not found: {hf}"));
                }
                let symbol = args.get("symbol").and_then(Value::as_str);
                let lines = args.get("lines").and_then(Value::as_str);
                let limit = args
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(8)
                    .clamp(1, 25) as usize;
                let rep = ap_atlas::history::analyze_file_history(&hf_p, symbol, lines, limit);
                let js = serde_json::to_string_pretty(&rep).unwrap_or_default();
                crate::stats::record_event("history", 0, js.len() as u64, 0, 1, "mcp-history");
                return (true, js);
            }
            let root_p = std::path::Path::new(root);
            if !root_p.exists() {
                return (false, format!("[atlas] path not found: {root}"));
            }
            let base = args.get("base").and_then(Value::as_str);
            let rep = ap_atlas::changes::analyze_git_changes(root_p, base, ap_atlas::SKIP_DIRS);
            let js = serde_json::to_string_pretty(&rep).unwrap_or_default();
            crate::stats::record_event("changes", 0, js.len() as u64, 0, 1, "mcp-changes");
            (true, js)
        }
        "ap_surface" => {
            let root = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let root_p = std::path::Path::new(root);
            if !root_p.exists() {
                return (false, format!("[atlas] path not found: {root}"));
            }
            let max_files = args
                .get("max_files")
                .and_then(Value::as_u64)
                .unwrap_or(1500)
                .clamp(20, 10000) as usize;
            let max_per_axis = args
                .get("max_per_axis")
                .and_then(Value::as_u64)
                .unwrap_or(12)
                .clamp(1, 50) as usize;
            let include_vendor = args
                .get("include_vendor")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let include_binaries = args
                .get("include_binaries")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let map = ap_atlas::surface::build_surface_map(
                root_p,
                max_files,
                max_per_axis,
                include_vendor,
                include_binaries,
            );
            let js = serde_json::to_string_pretty(&map).unwrap_or_default();
            crate::stats::record_event("surface", 0, js.len() as u64, 0, 1, "mcp-surface");
            (true, js)
        }
        "ap_frontier" => {
            let cwd_str = args.get("cwd").and_then(Value::as_str).unwrap_or(".");
            let cwd = std::path::PathBuf::from(cwd_str);
            let store = args.get("store").and_then(Value::as_str);
            let store_path = ap_baton::frontier::resolve_store_path(&cwd, store);
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("status");
            match action {
                "seed" => {
                    let mut state = ap_baton::frontier::load_frontier(&store_path);
                    let res = if let Some(sp) = args
                        .get("scan_path")
                        .and_then(Value::as_str)
                        .filter(|s| !s.trim().is_empty())
                    {
                        let p = std::path::Path::new(sp);
                        if !p.exists() {
                            return (false, format!("[frontier] scan_path not found: {sp}"));
                        }
                        let map = ap_atlas::surface::build_surface_map(p, 1500, 12, false, false);
                        let raw = serde_json::to_string(&map).unwrap_or_default();
                        ap_baton::frontier::seed_from_json_str(&mut state, &raw)
                    } else if let Some(tgt) = args
                        .get("target")
                        .and_then(Value::as_str)
                        .filter(|s| !s.trim().is_empty())
                    {
                        let ax = args
                            .get("axis")
                            .and_then(Value::as_str)
                            .unwrap_or("general");
                        let m = args.get("module").and_then(Value::as_str).unwrap_or("");
                        let n = args.get("note").and_then(Value::as_str).unwrap_or("");
                        let row = json!([{"axis": ax, "target": tgt, "module": m, "note": n}]);
                        ap_baton::frontier::seed_from_json_str(&mut state, &row.to_string())
                    } else {
                        return (
                            false,
                            "Pass `scan_path` or `target` for `ap_frontier` action='seed'."
                                .to_string(),
                        );
                    };
                    match res {
                        Ok((added, skipped)) => {
                            if let Err(e) = ap_baton::frontier::save_frontier(&store_path, &mut state)
                            {
                                return (false, format!("[frontier] save failed: {e}"));
                            }
                            let out = json!({
                                "ok": true,
                                "added": added,
                                "skipped_existing": skipped,
                                "total": state.items.len(),
                                "summary": ap_baton::frontier::status_summary_json(&state, 5),
                            });
                            (true, serde_json::to_string_pretty(&out).unwrap_or_default())
                        }
                        Err(e) => (false, e),
                    }
                }
                "mark" => {
                    let q = args.get("query").and_then(Value::as_str).unwrap_or("");
                    let st_s = args.get("status").and_then(Value::as_str).unwrap_or("probed");
                    let rsn = args.get("reason").and_then(Value::as_str).unwrap_or("");
                    let rf = args.get("ref").and_then(Value::as_str).unwrap_or("");
                    let Some(status) = ap_baton::frontier::FrontierStatus::parse(st_s) else {
                        return (
                            false,
                            format!("Invalid status '{st_s}' (unvisited|probed|stopped|confirmed|deferred)"),
                        );
                    };
                    let mut state = ap_baton::frontier::load_frontier(&store_path);
                    let q_low = q.trim().to_ascii_lowercase();
                    let now = ap_baton::now_iso_utc();
                    let mut ids = Vec::new();
                    for it in &mut state.items {
                        let id_low = it.id.to_ascii_lowercase();
                        let tgt_low = it.target.to_ascii_lowercase();
                        if id_low == q_low
                            || id_low.starts_with(&q_low)
                            || (q_low.len() >= 4 && tgt_low.contains(&q_low))
                        {
                            it.status = status.clone();
                            if !rsn.trim().is_empty() {
                                it.reason = rsn.trim().chars().take(180).collect();
                            }
                            if !rf.trim().is_empty() {
                                it.evidence_ref = rf.trim().chars().take(120).collect();
                            }
                            it.updated_at = now.clone();
                            ids.push(it.id.clone());
                        }
                    }
                    if ids.is_empty() {
                        return (false, format!("[frontier] no item matched '{q}'"));
                    }
                    if let Err(e) = ap_baton::frontier::save_frontier(&store_path, &mut state) {
                        return (false, format!("[frontier] save failed: {e}"));
                    }
                    (
                        true,
                        serde_json::to_string_pretty(&json!({
                            "ok": true,
                            "status": status.as_str(),
                            "matched": ids.len(),
                            "ids": ids,
                        }))
                        .unwrap_or_default(),
                    )
                }
                "next" => {
                    let state = ap_baton::frontier::load_frontier(&store_path);
                    let top_k = args
                        .get("top_k")
                        .and_then(Value::as_u64)
                        .unwrap_or(5)
                        .clamp(1, 20) as usize;
                    let exclude: Vec<String> = args
                        .get("exclude_axes")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let items = ap_baton::frontier::pick_next_diverse(&state, top_k, &exclude);
                    let summary = ap_baton::frontier::status_summary_json(&state, top_k);
                    (
                        true,
                        serde_json::to_string_pretty(&json!({
                            "ok": true,
                            "total": state.items.len(),
                            "unvisited": summary["unvisited"],
                            "unexplored_axes": summary["unexplored_axes"],
                            "explored_axes": summary["explored_axes"],
                            "items": items,
                        }))
                        .unwrap_or_default(),
                    )
                }
                "sync_stopped" => {
                    let mut state = ap_baton::frontier::load_frontier(&store_path);
                    let files: Vec<String> = args
                        .get("text_files")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let mut marked = 0usize;
                    for f in files {
                        if let Ok(txt) = std::fs::read_to_string(&f) {
                            let label = std::path::Path::new(&f)
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("notes");
                            marked += ap_baton::frontier::sync_stopped_from_text(
                                &mut state, label, &txt,
                            );
                        }
                    }
                    if marked > 0 {
                        let _ = ap_baton::frontier::save_frontier(&store_path, &mut state);
                    }
                    (
                        true,
                        serde_json::to_string_pretty(&json!({
                            "ok": true,
                            "newly_stopped": marked,
                            "total": state.items.len(),
                        }))
                        .unwrap_or_default(),
                    )
                }
                "status" => {
                    let state = ap_baton::frontier::load_frontier(&store_path);
                    let top_k = args
                        .get("top_k")
                        .and_then(Value::as_u64)
                        .unwrap_or(5)
                        .clamp(1, 20) as usize;
                    let summary = ap_baton::frontier::status_summary_json(&state, top_k);
                    (true, serde_json::to_string_pretty(&summary).unwrap_or_default())
                }
                other => (
                    false,
                    format!("Unknown ap_frontier action '{other}' (use seed|mark|next|status|sync_stopped)"),
                ),
            }
        }
        "ap_discover" => {
            let query = args
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let category = args
                .get("category")
                .and_then(Value::as_str)
                .unwrap_or("all")
                .trim()
                .to_ascii_lowercase();
            let include_schema = args
                .get("include_schema")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(8)
                .clamp(1, 37) as usize;

            let q_tokens: Vec<&str> = query
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                .filter(|t| !t.is_empty())
                .collect();

            let matches_category = |tname: &str, desc: &str| -> bool {
                match category.as_str() {
                    "" | "all" => true,
                    "read" => matches!(tname, "ap_read" | "ap_search" | "ap_query" | "ap_sieve"),
                    "orient" => matches!(
                        tname,
                        "ap_orient"
                            | "ap_surface"
                            | "ap_locate"
                            | "ap_trace"
                            | "ap_changes"
                            | "ap_impact"
                    ),
                    "edit" => matches!(tname, "ap_edit" | "ap_rename" | "ap_undo"),
                    "probe" => matches!(
                        tname,
                        "ap_smoke"
                            | "ap_ui"
                            | "ap_cdp"
                            | "ap_http"
                            | "ap_ws"
                            | "ap_tls"
                            | "ap_tcp"
                            | "ap_listen"
                            | "ap_ports"
                            | "ap_ps"
                            | "ap_win"
                            | "ap_fs_diff"
                            | "ap_mutate"
                            | "ap_fuzz"
                            | "ap_probe"
                    ),
                    "guard" => matches!(
                        tname,
                        "ap_verify" | "ap_diff_audit" | "ap_guard_pack" | "ap_exec"
                    ),
                    "baton" => matches!(
                        tname,
                        "ap_baton"
                            | "ap_baton_claim"
                            | "ap_baton_dedup"
                            | "ap_frontier"
                            | "ap_recall"
                    ),
                    other => tname.contains(other) || desc.to_ascii_lowercase().contains(other),
                }
            };

            let catalog = mcp_tools_schema();
            let all_tools = catalog.as_array().map(Vec::as_slice).unwrap_or(&[]);
            let mut scored: Vec<(usize, Value)> = Vec::new();
            for tool in all_tools {
                let tname = tool.get("name").and_then(Value::as_str).unwrap_or("");
                let desc = tool
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !matches_category(tname, desc) {
                    continue;
                }
                let tname_low = tname.to_ascii_lowercase();
                let desc_low = desc.to_ascii_lowercase();
                let param_keys: Vec<String> = tool
                    .pointer("/inputSchema/properties")
                    .and_then(Value::as_object)
                    .map(|m| m.keys().cloned().collect())
                    .unwrap_or_default();
                let params_low = param_keys.join(" ").to_ascii_lowercase();

                let score = if q_tokens.is_empty() {
                    1usize
                } else {
                    let mut sc = 0usize;
                    if tname_low == query {
                        sc += 50;
                    }
                    for tok in &q_tokens {
                        if tname_low.contains(tok) {
                            sc += 6;
                        }
                        if params_low.contains(tok) {
                            sc += 3;
                        }
                        if desc_low.contains(tok) {
                            sc += 2;
                        }
                    }
                    sc
                };
                if score == 0 {
                    continue;
                }
                let exact_name_hit = !query.is_empty() && tname_low == query;
                let mut entry = json!({
                    "name": tname,
                    "title": tool.get("title").and_then(Value::as_str).unwrap_or(""),
                    "description": desc,
                    "params": param_keys,
                });
                if include_schema || exact_name_hit {
                    if let Some(schema) = tool.get("inputSchema") {
                        entry["inputSchema"] = schema.clone();
                    }
                }
                scored.push((score, entry));
            }
            scored.sort_by(|a, b| {
                b.0.cmp(&a.0).then_with(|| {
                    a.1["name"]
                        .as_str()
                        .unwrap_or("")
                        .cmp(b.1["name"].as_str().unwrap_or(""))
                })
            });
            let selected: Vec<Value> = scored.into_iter().take(limit).map(|(_, v)| v).collect();
            (
                true,
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "total_tools": all_tools.len(),
                    "matched": selected.len(),
                    "tools": selected,
                }))
                .unwrap_or_default(),
            )
        }
        "ap_call" => {
            let target = args
                .get("tool")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if target.is_empty() {
                return (false, "Pass non-empty `tool` to `ap_call`.".to_string());
            }
            if target == "ap_call" {
                return (false, "Recursive `ap_call` is disallowed.".to_string());
            }
            let fwd_args = args.get("arguments").cloned().unwrap_or_else(|| json!({}));
            dispatch_tool_call(target, &fwd_args)
        }
        other => (false, format!("Unknown tool: {other}")),
    }
}

fn mcp_resources_list() -> Value {
    json!([
        {
            "uri": "ap://workspace/map",
            "name": "Workspace Structural Map",
            "description": "Live <25ms Tree-sitter workspace X-ray & product contract map for current directory",
            "mimeType": "text/markdown"
        },
        {
            "uri": "ap://baton/state",
            "name": "Compaction-Proof Task Baton",
            "description": "Current goal, constraints, verified facts, falsified dead-ends, and next step capsule",
            "mimeType": "application/json"
        },
        {
            "uri": "ap://stats/summary",
            "name": "Local Agent Efficiency Ledger",
            "description": "Offline coding-agent efficiency metrics, prevented shell crashes, and per-primitive breakdown",
            "mimeType": "application/json"
        }
    ])
}

fn read_mcp_resource(uri: &str) -> Result<Value, String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match uri {
        "ap://workspace/map" => {
            let data = ap_atlas::scan_workspace(&cwd, "", 35, 14);
            let map_txt = ap_atlas::render_atlas_md(&data);
            let pm = ap_atlas::product::build_product_map(&cwd, ap_atlas::SKIP_DIRS);
            let prod_txt = ap_atlas::product::render_product_map(&pm);
            Ok(json!({
                "contents": [{
                    "uri": uri,
                    "mimeType": "text/markdown",
                    "text": format!("{map_txt}\n{prod_txt}")
                }]
            }))
        }
        "ap://baton/state" => {
            let base = ap_baton::baton_dir(&cwd);
            let mut st = ap_baton::load_state(&base);
            st.workspace = ap_baton::probe_workspace(&cwd);
            let txt = serde_json::to_string_pretty(&st).unwrap_or_else(|_| "{}".to_string());
            Ok(json!({
                "contents": [{
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": txt
                }]
            }))
        }
        "ap://stats/summary" => {
            let (_, txt) = run_self_captured(&["stats".into(), "--json".into()], None);
            Ok(json!({
                "contents": [{
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": txt
                }]
            }))
        }
        _ => Err(format!("Unknown resource URI: {uri}")),
    }
}

fn mcp_prompts_list() -> Value {
    json!([
        {
            "name": "orient-and-plan",
            "description": "Orient in an unfamiliar repository with 0 blind file reads, inspect blast radius, apply atomic edits, and verify with deep gates",
            "arguments": [
                { "name": "task", "description": "Engineering goal or change request", "required": false }
            ]
        },
        {
            "name": "safe-refactor",
            "description": "AST-exact multi-file symbol rename with blast-radius impact map, dry-run preview, atomic test rollback, and diff self-audit",
            "arguments": [
                { "name": "symbol", "description": "Existing symbol name to refactor", "required": true },
                { "name": "new_name", "description": "New symbol name (optional)", "required": false }
            ]
        },
        {
            "name": "debug-root-cause",
            "description": "Locate suspect functions via BM25+Tree-sitter, trace multi-hop call chains, verify with runtime probe, and lock in regression tests",
            "arguments": [
                { "name": "symptom", "description": "Error message, failing test, or bug symptom", "required": true }
            ]
        },
        {
            "name": "deepseek-lean-coding",
            "description": "High-efficiency coding loop tuned for interleaved-thinking models (e.g. DeepSeek Flash/Reasoner): single-pass orientation, zero re-read loops, atomic AST edits, and strict post-edit verification",
            "arguments": [
                { "name": "task", "description": "Software engineering objective", "required": true }
            ]
        },
        {
            "name": "pi-codemode-pipeline",
            "description": "Parallel QuickJS codemode pattern for Pi v1.5+ & DeepSeek Flash: collapse 5-8 serial discovery turns into 1 Promise.allSettled batch, filter large payloads in-sandbox, and persist branch state with store()/load()",
            "arguments": [
                { "name": "task", "description": "Engineering task or investigation goal", "required": true }
            ]
        }
    ])
}

fn get_mcp_prompt(name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "orient-and-plan" => {
            let task = args
                .get("task")
                .and_then(Value::as_str)
                .unwrap_or("the requested engineering change");
            Ok(json!({
                "description": "Zero-blind-read orientation, atomic editing, and deep verification workflow",
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Execute `{task}` using ap primitives cleanly:\n1. Call `ap_orient` first to map workspace structure, runtimes, and UI/API contracts.\n2. Before changing shared symbols, call `ap_impact` or `ap_changes` to inspect downstream callers.\n3. Apply multi-file edits atomically with `ap_edit` (using `edits`, `symbols`, or `writes`).\n4. Run `ap_diff_audit` and `ap_verify` before concluding.")
                    }
                }]
            }))
        }
        "safe-refactor" => {
            let sym = args
                .get("symbol")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "Missing required argument `symbol`".to_string())?;
            let target_clause = match args
                .get("new_name")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                Some(nn) => format!("to `{nn}`"),
                None => "safely across the workspace".to_string(),
            };
            Ok(json!({
                "description": "AST-exact multi-file refactoring workflow",
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Refactor `{sym}` {target_clause}:\n1. Run `ap_impact(symbol=\"{sym}\")` to inspect definitions, callers, and related tests.\n2. Preview the AST-exact rename via `ap_rename(..., dry_run=true)`.\n3. Apply with `ap_rename(..., run_tests=true, rollback_on_test_fail=true)`.\n4. Confirm zero regressions via `ap_changes` and `ap_diff_audit`.")
                    }
                }]
            }))
        }
        "debug-root-cause" => {
            let symptom = args
                .get("symptom")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "Missing required argument `symptom`".to_string())?;
            Ok(json!({
                "description": "Structured root-cause localization and fix workflow",
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Diagnose and fix `{symptom}`:\n1. Run `ap_locate(query=\"{symptom}\")` to rank Top-K suspect functions.\n2. Trace callers/sinks with `ap_trace`.\n3. Reproduce with `ap_probe` or a focused test, apply fix via `ap_edit(run_tests=true)`, and verify via `ap_verify`.")
                    }
                }]
            }))
        }
        "deepseek-lean-coding" => {
            let task = args
                .get("task")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "Missing required argument `task`".to_string())?;
            Ok(json!({
                "description": "Lean interleaved-thinking coding loop that prevents overthinking stalls and re-read loops",
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Complete `{task}` with concise, high-signal tool steps:\n1. Call `ap_orient` once (do not repeatedly re-read unchanged files).\n2. Batch parallel discovery with `ap_search(patterns=[...])` or `ap_locate`.\n3. Commit to one atomic `ap_edit` (or `ap_rename` for refactors) with `run_tests=true` rather than spending >2 turns deliberating.\n4. Finish with `ap_diff_audit` + `ap_verify` and summarize verified results.")
                    }
                }]
            }))
        }
        "pi-codemode-pipeline" => {
            let task = args
                .get("task")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "Missing required argument `task`".to_string())?;
            Ok(json!({
                "description": "Parallel QuickJS codemode execution blueprint for Pi v1.5+ and DeepSeek Flash",
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Execute `{task}` inside Pi `codemode` in minimal turns while protecting DeepSeek KV-cache:\n1. Batch discovery in ONE `codemode` call via `Promise.allSettled([tools.mcp__agent_primitives__ap_orient({{}}), tools.mcp__agent_primitives__ap_search({{patterns:[...], json:true}}), tools.mcp__agent_primitives__ap_read({{targets:[...], outline:true}})])` — all `ap_*` MCP tools declare typed `outputSchema`, so read `res.structuredContent.matches` / `.records` / `.findings` directly with zero `JSON.parse`.\n2. Run noisy shell commands via `tools.bash({{command}})` INSIDE `codemode` (up to 1 MiB output, never throws on non-zero exit_code), filter/slice in QuickJS, and `return` only compact findings (<2KB). Persist branch-safe, compaction-proof plans/cursors with `store('plan', ...)` / `load('plan')`.\n3. Apply changes atomically via `tools.mcp__agent_primitives__ap_edit` (or `ap_rename`) with `run_tests: true`.\n4. Finish with `ap_changes` + `ap_diff_audit` + `ap_verify` in one final verification script.")
                    }
                }]
            }))
        }
        _ => Err(format!("Unknown prompt: {name}")),
    }
}

fn handle_rpc_request(req: &Value, profile: McpProfile) -> Option<Value> {
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let id_opt = req.get("id").cloned();

    // Notifications have no `id` and expect no response
    id_opt.as_ref()?;
    let id = id_opt.unwrap();

    match method {
        "initialize" => {
            let client_proto = req
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2025-11-25");
            let negotiated_proto = match client_proto {
                "2025-11-25" | "2025-06-18" | "2025-03-26" | "2024-11-05" => client_proto,
                _ => "2025-11-25",
            };
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": negotiated_proto,
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "prompts": {}
                    },
                    "serverInfo": {
                        "name": "agent-primitives",
                        "title": "Agent Primitives",
                        "version": env!("CARGO_PKG_VERSION"),
                        "description": "Pure-Rust single-binary universal execution core & 37-tool MCP server",
                        "websiteUrl": "https://github.com/xgbtxy/ap",
                        "profile": profile.as_str()
                    }
                }
            }))
        }
        "ping" => Some(json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": mcp_tools_for_profile(profile)
            }
        })),
        "resources/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "resources": mcp_resources_list() }
        })),
        "resources/read" => {
            let uri = req
                .pointer("/params/uri")
                .and_then(Value::as_str)
                .unwrap_or("");
            match read_mcp_resource(uri) {
                Ok(res) => Some(json!({ "jsonrpc": "2.0", "id": id, "result": res })),
                Err(msg) => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32602, "message": msg }
                })),
            }
        }
        "prompts/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "prompts": mcp_prompts_list() }
        })),
        "prompts/get" => {
            let pname = req
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let pargs = req
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match get_mcp_prompt(pname, &pargs) {
                Ok(res) => Some(json!({ "jsonrpc": "2.0", "id": id, "result": res })),
                Err(msg) => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32602, "message": msg }
                })),
            }
        }
        "tools/call" => {
            let tname = req
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let mut targs = req
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if let Value::Object(ref mut map) = targs {
                map.retain(|_, v| !v.is_null());
            }
            let (ok, text) = dispatch_tool_call(tname, &targs);
            let mut result = json!({
                "content": [{ "type": "text", "text": text }],
                "isError": !ok
            });
            if ok {
                let trimmed = text.trim();
                let mut populated = false;
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
                        match parsed {
                            Value::Object(_) => {
                                result["structuredContent"] = parsed;
                                populated = true;
                            }
                            Value::Array(_) => {
                                result["structuredContent"] =
                                    json!({ "ok": true, "items": parsed });
                                populated = true;
                            }
                            _ => {}
                        }
                    }
                }
                if !populated {
                    result["structuredContent"] = json!({ "ok": true, "text": text });
                }
            }
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            }))
        }
        _ => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": format!("Method not found: {method}")
            }
        })),
    }
}

pub fn run_mcp_stdio() -> i32 {
    run_mcp_stdio_with_profile("")
}

pub fn run_mcp_stdio_with_profile(cli_profile: &str) -> i32 {
    let profile = McpProfile::resolve(cli_profile);
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Mode A: LSP-style `Content-Length: N` framing
        if trimmed.to_ascii_lowercase().starts_with("content-length:") {
            let len: usize = trimmed
                .split_once(':')
                .and_then(|(_, v)| v.trim().parse().ok())
                .unwrap_or(0);
            loop {
                let mut hdr = String::new();
                if reader.read_line(&mut hdr).unwrap_or(0) == 0 || hdr.trim().is_empty() {
                    break;
                }
            }
            if len == 0 {
                continue;
            }
            let mut body = vec![0u8; len];
            if reader.read_exact(&mut body).is_err() {
                break;
            }
            if let Ok(req) = serde_json::from_slice::<Value>(&body) {
                if let Some(resp) = handle_rpc_request(&req, profile) {
                    let s = resp.to_string();
                    let _ = write!(writer, "Content-Length: {}\r\n\r\n{}", s.len(), s);
                    let _ = writer.flush();
                }
            }
            continue;
        }

        // Mode B: Standard MCP 2024-11-05 / 2025-03-26 newline-delimited JSON-RPC
        if let Ok(req) = serde_json::from_str::<Value>(trimmed) {
            if let Some(resp) = handle_rpc_request(&req, profile) {
                let _ = writeln!(writer, "{resp}");
                let _ = writer.flush();
            }
        }
    }
    0
}
