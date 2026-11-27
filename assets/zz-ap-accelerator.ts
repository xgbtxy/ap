// Managed by agent-primitives (`ap init`). Zero system-prompt token overhead.
// Designed for Pi v1.5+ and interleaved-thinking models (e.g. DeepSeek Flash / Reasoner):
// - Accelerates slow `grep -rn`, heals Windows `> NUL`, non-raw `python -c` paths & UTF-8
// - Auto-sieves >28KB direct-to-LLM shell outputs into `~/.ap/sieve` (zero `.sieve` clutter)
// - Native Pi v1.5 `context_edit` batch observation masking at high-water marks (180k tok / 72%)
//   with >=10-turn cooldown to prevent Context Rot while preserving DeepSeek 50x KV-cache & thinking
// - Breaks 3x shell doom-loops, 3x unchanged file re-reads & 3-turn heavy-thinking stalls
// - Recovers leaked DSML XML tool blocks when 0 native tool calls were emitted (zero conflict)
// - Self-healing tips for `edit` misses, `codemode` errors & giant code `read` calls
// - Auto-checkpoints `.baton/` on compaction (only if `.baton` already exists) + live KV-cache HUD
// - Native Pi v1.5 `agent_before_settle` closed-loop syntax + diff blocker gate (max 1 retry/run)
// - Opt-in `deepseek/flash-auto` virtual model (dynamic low/high/max effort, zero cache-bust switch)
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import type {
	ContextEditEntryDraft,
	CustomMessageEntryDraft,
	ExtensionAPI,
	ExtensionContext,
	ProjectedSessionEntry,
} from "@earendil-works/pi-coding-agent";

const AP_BIN = "__AP_BIN_POSIX__";
const SIEVE_HOME = process.env.SIEVE_HOME || join(homedir(), ".ap", "sieve");
const DESTRUCTIVE_OR_WRITE =
	/(?:^|[;&|]\s*)(?:Remove-Item|rm|del|erase|rmdir|rd|Move-Item|Rename-Item|mv|ren|Set-Content|Add-Content|Clear-Content|Out-File|Copy-Item|cpi|copy)\b|shutil\.rmtree|os\.remove|os\.unlink|\.unlink\(|\.rmdir\(|\bgit(?:\.exe)?\b[\s\S]{0,80}?\bclean\b/i;
const BARE_SLOW_GREP =
	/^\s*grep\s+-([rRniEHlco]+)\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))(?:\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+)))?\s*$/;
const PY_INVOKE = /(?:^|[;&|(\s=])(?:python3?(?:\.exe)?|py(?:\.exe)?|pytest)(?=\s|$)/i;
const HAS_UTF8_ENV = /PYTHONUTF8|PYTHONIOENCODING/i;
const PY_WIN_BS =
	/\b(?:python3?(?:\.exe)?|py(?:\.exe)?)\b[\s\S]*(?:-c\b|<<)[\s\S]*(?<![rR])(['"])([A-Za-z]:\\(?!\\)[^'"\r\n]+)\1/;
const REDIR_NUL = /(\s(?:[12]?>>?|&>))\s*NUL(?=$|[\s;&|)])/gi;
function healRedirNul(cmd: string): string {
	if (!/\bNUL(?=$|[\s;&|)])/i.test(cmd)) return cmd;
	const hdIdx = cmd.indexOf("<<");
	const head = hdIdx >= 0 ? cmd.slice(0, hdIdx) : cmd;
	const tail = hdIdx >= 0 ? cmd.slice(hdIdx) : "";
	let out = "";
	let quote: string | null = null;
	let segStart = 0;
	const rewriteUnquoted = (seg: string, followedByQuote: boolean): string =>
		seg.replace(
			followedByQuote
				? /((?:^|[\s"'`)}]|[A-Za-z0-9_./\\-])(?:(?<![A-Za-z0-9_])[12]?>>?|>>?|&>))\s*NUL(?=[\s;&|)])/gi
				: /((?:^|[\s"'`)}]|[A-Za-z0-9_./\\-])(?:(?<![A-Za-z0-9_])[12]?>>?|>>?|&>))\s*NUL(?=$|[\s;&|)])/gi,
			"$1 /dev/null",
		);
	for (let i = 0; i < head.length; i++) {
		const ch = head[i];
		if (quote) {
			if (ch === "\\" && quote === '"' && i + 1 < head.length) {
				i++;
				continue;
			}
			if (ch === quote) {
				out += head.slice(segStart, i + 1);
				segStart = i + 1;
				quote = null;
			}
			continue;
		}
		if (ch === "'" || ch === '"') {
			if (i > segStart) out += rewriteUnquoted(head.slice(segStart, i), true);
			segStart = i;
			quote = ch;
		}
	}
	if (segStart < head.length) {
		out += quote ? head.slice(segStart) : rewriteUnquoted(head.slice(segStart), false);
	}
	return out + tail;
}
function healCmdCdSlashD(cmd: string): string {
	if (!/\bcd\s+\/d\b/i.test(cmd)) return cmd;
	const hdIdx = cmd.indexOf("<<");
	const head = hdIdx >= 0 ? cmd.slice(0, hdIdx) : cmd;
	const tail = hdIdx >= 0 ? cmd.slice(hdIdx) : "";
	let out = "";
	let quote: string | null = null;
	let segStart = 0;
	const rewriteUnquoted = (seg: string, followedByQuote: boolean): string =>
		seg.replace(
			followedByQuote
				? /((?:^|[;&|(\n])|(?:^|[;\n\s])(?:then|do|else)[ \t]+)([ \t]*)cd\s+\/[dD]\s+(?=[^\s;&|)\n]|$)/gi
				: /((?:^|[;&|(\n])|(?:^|[;\n\s])(?:then|do|else)[ \t]+)([ \t]*)cd\s+\/[dD]\s+(?=[^\s;&|)\n])/gi,
			"$1$2cd ",
		);
	for (let i = 0; i < head.length; i++) {
		const ch = head[i];
		if (quote) {
			if (ch === "\\" && quote === '"' && i + 1 < head.length) {
				i++;
				continue;
			}
			if (ch === quote) {
				out += head.slice(segStart, i + 1);
				segStart = i + 1;
				quote = null;
			}
			continue;
		}
		if (ch === "'" || ch === '"') {
			if (i > segStart) out += rewriteUnquoted(head.slice(segStart, i), true);
			segStart = i;
			quote = ch;
		}
	}
	if (segStart < head.length) {
		out += quote ? head.slice(segStart) : rewriteUnquoted(head.slice(segStart), false);
	}
	return out + tail;
}
const QUOTE_OR_BS_ERR =
	/unterminated string|EOL while scanning|unicodeescape|unexpected character after line continuation|syntax error near unexpected token/i;
const TIMEOUT_ERR_RE = /\b(?:timed out|timeout|deadline exceeded|ETIMEDOUT)\b/i;
const SEARCH_CMD_RE =
	/^\s*(?:export\s+\S+\s*;?\s*|\$env:\w+\s*=\s*\S+\s*;?\s*)*(?:grep|egrep|fgrep|rg|find|fd|ls|dir|tree|Get-ChildItem|Select-String)\b/i;
const ENOENT_ERR_RE =
	/no such file or directory|cannot find the path|FileNotFoundError|ENOENT/i;
const PATH_MISMATCH_RE = /\/mnt\/[a-z]\//i;
const BASH_BS_PATH_RE = /(?:^|[\s=])[A-Za-z]:\\/;
const CMD_NOT_FOUND_RE = /command not found|is not recognized|exit(?:ed with)? code 127\b/i;
const MISSING_CLI_MAP: ReadonlyArray<[RegExp, string]> = [
	[/\bjq\b/i, 'ap read <file> --json-path "..." or ap query'],
	[/\b(?:xxd|hexdump)\b/i, "ap read <file> --hex"],
	[/\b(?:rg|ag)\b/i, "ap search <pattern> [path]"],
	[/\b(?:tree|fd)\b/i, "ap atlas map [path]"],
	[/\bsqlite3\b/i, "ap query -f db=<file.sqlite> <sql>"],
	[/\bpdftotext\b/i, "ap read <file.pdf>"],
	[/\bstrings\b/i, "ap read <binary> or ap search <pattern> <binary>"],
	[/\bidat64(?:\.exe)?\b/i, "idat.exe or ap read <bin> --xref --ioctl --rpc-com-alpc"],
];
const CODE_FILE_EXT = /\.(?:rs|ts|tsx|js|jsx|mjs|cjs|py|go|c|cc|cpp|h|hpp)$/i;
const EDIT_TOOLS = new Set(["write", "edit", "ap_edit", "ap_rename"]);
const SERIAL_BATCHABLE_TOOLS = new Set(["bash", "powershell", "read", "grep", "find", "ls"]);
const LOOP_WINDOW = 6;
const LOOP_ERR_THRESHOLD = 3;
const LOOP_OK_THRESHOLD = 5;
const REREAD_THRESHOLD = 3;
const HEAVY_THINKING_CHARS = 12000;
const LIGHT_THINKING_CHARS = 1500;
const STAGNATION_TURNS = 3;
const SERIAL_BATCH_THRESHOLD = 6;
const BATCH_TIP_COOLDOWN_TURNS = 25;
const CODEMODE_PARALLEL_COOLDOWN_TURNS = 20;
const CODEMODE_PARALLEL_MAX_TIPS = 2;
const WRITE_OVERWRITE_TIP_CHARS = 4000;
const WRITE_TIP_COOLDOWN_TURNS = 15;
const LARGE_CODE_READ_CHARS = 20000;
const SIEVE_HARD_CHARS = 20000;
const SIEVE_STRUCTURED_CHARS = 14000;
const SIEVE_GIANT_LINE_CHARS = 4500;
const SIEVE_STRUCTURED_LINES = 180;
const BINARY_READ_EXT = /\.(?:png|jpe?g|gif|webp|bmp|ico|pdf|zip|gz|tar|7z|exe|dll|so|dylib|wasm|sqlite|db|docx|xlsx|pptx)$/i;

// Two-tier amortized deep-sweep observation masking constants (keeps DeepSeek V4.1 Flash in its <240k Peak-IQ zone)
const MASK_PREFIX = "[ap masked stale toolResult:";
const MASK_HIGH_WATER_PCT = 72;
const MASK_HIGH_WATER_TOKENS = 180000;
const MASK_TIER2_PCT = 78;
const MASK_TIER2_TOKENS = 240000;
const MASK_TIER2_MIN_ENTRY_CHARS = 1800;
const MASK_TIER2_KEEP_RECENT = 6;
const MASK_TIER2_MIN_RECLAIMED = 10000;
const MASK_STALE_CHARS_FALLBACK = 240000;
const FREE_MASK_MIN_TOKENS = 80000;
const MASK_KEEP_RECENT_ENTRIES = 10;
const MASK_MIN_ENTRY_CHARS = 2400;
const MASK_MIN_BATCH_ENTRIES = 2;
const MASK_MIN_RECLAIMED_CHARS = 48000;
const MASK_COOLDOWN_TURNS = 15;

export function isBenignGrepNoMatch(cmd: string, outText: string): boolean {
	if (!cmd || !outText) return false;
	if (!/(?:^|[;&|]\s*)(?:grep|egrep|fgrep|rg|findstr|Select-String)\b/i.test(cmd)) return false;
	if (!/exit(?:ed with)? code 1\b/i.test(outText)) return false;
	const body = outText.replace(/command exited with code 1[\s\S]*/i, "").trim();
	return body.length < 15;
}

const LEADING_SHELL_PREFIX_RE =
	/^\s*(?:(?:export\s+\S+|unset\s+\S+|\$env:\w+\s*=\s*\S+|cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)|chcp\s+\d+(?:\s*>\s*(?:\/dev\/null|NUL))?)\s*(?:&&|;)\s*)+/i;
const READONLY_PROBE_TIMEOUT_RE =
	/^\s*(?:grep|egrep|fgrep|rg|find|fd|ls|dir|tree|cat|head|tail|sed|awk|nl|wc|stat|file|strings|curl(?:\.exe)?|wget|Get-Content|Get-ChildItem|Select-String)\b/i;
const READONLY_PS_INVOKE_RE = /^\s*(?:powershell|pwsh)(?:\.exe)?\b/i;
const PS_MUTATING_CMDLET_RE =
	/\b(?:Set-|New-|Add-|Out-|Remove-|Clear-|Stop-|Restart-|Install-|Start-Process|-OutFile\b)/i;
const LONG_BUILD_TEST_RE =
	/\b(?:cargo|rustc|npm|pnpm|yarn|bun|pytest|vitest|jest|go\s+test|make|cmake|gradle|mvn|docker|pip\s+install|uv\s+sync)\b/i;

/**
 * Guard unbounded OR overly long (>120s) read-only shell probes with a 90s timeout so a hung
 * search/HTTP call fails fast BEFORE crossing DeepSeek's 2-5m KV-cache eviction cliff.
 * Strips leading `cd ... &&` / env prefixes so chained probes are guarded too.
 * Never shortens <=120s explicit timeouts or touches build/test/write commands.
 */
export function resolveSafeShellTimeout(cmd: string, currentTimeout: unknown): number | undefined {
	if (!cmd || LONG_BUILD_TEST_RE.test(cmd) || DESTRUCTIVE_OR_WRITE.test(cmd)) return undefined;
	const coreCmd = cmd.replace(LEADING_SHELL_PREFIX_RE, "");
	const isReadonlyProbe =
		READONLY_PROBE_TIMEOUT_RE.test(coreCmd) ||
		(READONLY_PS_INVOKE_RE.test(coreCmd) && !PS_MUTATING_CMDLET_RE.test(coreCmd));
	if (!isReadonlyProbe) return undefined;
	if (currentTimeout === undefined || currentTimeout === null) return 90;
	if (typeof currentTimeout === "number" && Number.isFinite(currentTimeout) && currentTimeout > 120) {
		return 90;
	}
	return undefined;
}

/**
 * Deterministic ASCII lexicographical tool-schema ordering for `before_provider_request`
 * (inspired by pi-deepseek-cache): prevents DeepSeek KV-cache prefix invalidation from
 * tool-list order jitter across MCP reconnects or reloads while preserving Anthropic `cache_control`.
 */
export interface ProviderRequestHashes {
	model: string;
	effort: string;
	thinkingHash?: number;
	systemHash?: number;
	toolsHash: number;
	msgHashes: number[];
}

function fnv1a32(text: string): number {
	let h = 0x811c9dc5;
	for (let i = 0; i < text.length; i++) {
		h ^= text.charCodeAt(i);
		h = Math.imul(h, 0x01000193) >>> 0;
	}
	return h >>> 0;
}

/**
 * Compute deterministic wire-level hashes across `model`, `reasoning_effort`, `thinking`, `system`/`instructions`,
 * `tools`, and `messages[]` before provider send (<0.4ms) so `turn_end` can classify unexpected KV-cache drops.
 */
export function snapshotProviderRequestHashes(payload: unknown): ProviderRequestHashes | null {
	if (!payload || typeof payload !== "object") return null;
	const p = payload as {
		model?: unknown;
		reasoning_effort?: unknown;
		reasoningEffort?: unknown;
		thinking?: unknown;
		system?: unknown;
		instructions?: unknown;
		tools?: unknown;
		messages?: unknown;
	};
	const model = String(p.model ?? "");
	const effort = String(p.reasoning_effort ?? p.reasoningEffort ?? "");
	let thinkingHash = 0;
	if (p.thinking !== undefined) {
		try {
			thinkingHash = fnv1a32(JSON.stringify(p.thinking));
		} catch {
			thinkingHash = 1;
		}
	}
	let systemHash = 0;
	const sysField = p.system !== undefined ? p.system : p.instructions;
	if (sysField !== undefined) {
		try {
			systemHash = fnv1a32(JSON.stringify(sysField));
		} catch {
			systemHash = 1;
		}
	}
	let toolsHash = 0;
	if (Array.isArray(p.tools)) {
		try {
			toolsHash = fnv1a32(JSON.stringify(p.tools));
		} catch {
			toolsHash = p.tools.length;
		}
	}
	const msgHashes: number[] = [];
	if (Array.isArray(p.messages)) {
		const cap = Math.min(p.messages.length, 400);
		for (let i = 0; i < cap; i++) {
			try {
				msgHashes.push(fnv1a32(JSON.stringify(p.messages[i])));
			} catch {
				msgHashes.push(i);
			}
		}
	}
	return { model, effort, thinkingHash, systemHash, toolsHash, msgHashes };
}

/**
 * Pinpoint the exact diverging prefix boundary when DeepSeek KV-cache drops unexpectedly.
 */
export function classifyCacheDropCause(
	prev: ProviderRequestHashes | null,
	curr: ProviderRequestHashes | null,
): string {
	if (!prev || !curr) return "ttl_eviction";
	if (prev.model !== curr.model) return "model_changed";
	if (prev.effort !== curr.effort) return "effort_changed";
	if ((prev.thinkingHash ?? 0) !== (curr.thinkingHash ?? 0)) return "thinking_changed";
	if (prev.toolsHash !== curr.toolsHash) return "tools_changed";
	if ((prev.systemHash ?? 0) !== (curr.systemHash ?? 0)) return "system_changed";
	const common = Math.min(prev.msgHashes.length, curr.msgHashes.length);
	for (let i = 0; i < common; i++) {
		if (prev.msgHashes[i] !== curr.msgHashes[i]) {
			return `msg[${i}]_mutated`;
		}
	}
	if (curr.msgHashes.length < prev.msgHashes.length) return "prefix_truncated";
	return "ttl_eviction";
}

export function stabilizeProviderTools(payload: unknown): unknown {
	if (!payload || typeof payload !== "object") return undefined;
	const p = payload as { tools?: unknown };
	if (!Array.isArray(p.tools) || p.tools.length < 2) return undefined;
	const toolKey = (t: unknown): string => {
		if (!t || typeof t !== "object") return "";
		const rec = t as {
			name?: unknown;
			function?: { name?: unknown };
			custom?: { name?: unknown };
		};
		if (typeof rec.function?.name === "string") return rec.function.name;
		if (typeof rec.custom?.name === "string") return rec.custom.name;
		if (typeof rec.name === "string") return rec.name;
		return "";
	};
	// Never reorder if any tool carries provider-specific `cache_control` breakpoint markers
	for (const t of p.tools) {
		if (t && typeof t === "object" && "cache_control" in (t as Record<string, unknown>)) {
			return undefined;
		}
	}
	let prev = "";
	let needsSort = false;
	for (let i = 0; i < p.tools.length; i++) {
		const k = toolKey(p.tools[i]);
		if (!k) return undefined;
		if (i > 0 && prev > k) {
			needsSort = true;
		}
		prev = k;
	}
	if (!needsSort) return undefined;
	const sorted = [...p.tools].sort((a, b) => {
		const ka = toolKey(a);
		const kb = toolKey(b);
		return ka < kb ? -1 : ka > kb ? 1 : 0;
	});
	return { ...(p as Record<string, unknown>), tools: sorted };
}

const CODEMODE_SETTIMEOUT_SHIM =
	`const setTimeout = typeof globalThis.setTimeout === "function" ? globalThis.setTimeout : (fn, ms = 0, ...a) => { if (typeof sleep === "function") { sleep(ms).then(() => { if (typeof fn === "function") fn(...a); }); } else if (typeof fn === "function") { fn(...a); } return 0; };`;

export interface ApProfileOverrides {
	modelProfile: string;
	sieveHardChars?: number;
	kvSafeSleepSec?: number;
	maskHighWaterTokens?: number;
	dsmlRecovery?: boolean;
	yieldCompact?: boolean;
}

const MODEL_PROFILE_KNOBS: Readonly<Record<string, Omit<ApProfileOverrides, "modelProfile" | "yieldCompact">>> = {
	balanced: { sieveHardChars: 20000, kvSafeSleepSec: 60, maskHighWaterTokens: 180000, dsmlRecovery: false },
	deepseek: { sieveHardChars: 12000, kvSafeSleepSec: 45, maskHighWaterTokens: 210000, dsmlRecovery: true },
	fast: { sieveHardChars: 12000, kvSafeSleepSec: 45, maskHighWaterTokens: 140000, dsmlRecovery: false },
	reasoning: { sieveHardChars: 16000, kvSafeSleepSec: 45, maskHighWaterTokens: 180000, dsmlRecovery: false },
	small: { sieveHardChars: 10000, kvSafeSleepSec: 45, maskHighWaterTokens: 90000, dsmlRecovery: false },
};

/**
 * Load optional Layer 3 declarative profile overrides (`~/.ap/profile.json`) once on startup.
 * Returns `undefined` when missing and no explicit override (`model_profile` != auto or `yield_compact`) is set.
 */
export function loadApProfile(profilePath?: string): ApProfileOverrides | undefined {
	try {
		const p = profilePath || join(homedir(), ".ap", "profile.json");
		if (!existsSync(p)) return undefined;
		const parsed = JSON.parse(readFileSync(p, "utf8")) as {
			model_profile?: unknown;
			yield_compact?: unknown;
			yieldCompact?: unknown;
		};
		const mp = typeof parsed?.model_profile === "string" ? parsed.model_profile.trim().toLowerCase() : "";
		const yieldCompact =
			typeof parsed?.yield_compact === "boolean"
				? parsed.yield_compact
				: typeof parsed?.yieldCompact === "boolean"
					? parsed.yieldCompact
					: undefined;
		const knobs = mp && mp !== "auto" ? MODEL_PROFILE_KNOBS[mp] : undefined;
		if (!knobs && yieldCompact === undefined) return undefined;
		return {
			modelProfile: knobs ? mp : (mp || "auto"),
			...(knobs ?? {}),
			...(yieldCompact !== undefined ? { yieldCompact } : {}),
		};
	} catch {
		return undefined;
	}
}

/**
 * Decide whether `zz-ap-accelerator` should yield LLM compaction summarization to an earlier extension or host workflow.
 * Note: `.baton` checkpointing still runs unconditionally before this yield check.
 */
export function shouldYieldCompaction(input: {
	compactionClaimed?: boolean;
	envYieldCompact?: string;
	profileYieldCompact?: boolean;
	peerClaimed?: boolean;
}): boolean {
	return Boolean(
		input.compactionClaimed ||
			input.envYieldCompact === "1" ||
			input.profileYieldCompact === true ||
			input.peerClaimed,
	);
}

/**
 * Read active model auto-compaction trigger tokens (`contextWindow - reserveTokens`) from `~/.pi/agent/settings.json`.
 */
export function readModelCompactionTriggerTokens(
	model?: { provider?: string; id?: string; contextWindow?: number },
	settingsPath?: string,
): number | undefined {
	try {
		const p = settingsPath || join(homedir(), ".pi", "agent", "settings.json");
		if (!existsSync(p)) return undefined;
		const parsed = JSON.parse(readFileSync(p, "utf8")) as {
			compaction?: {
				reserveTokens?: unknown;
				modelOverrides?: Record<string, { reserveTokens?: unknown }>;
			};
		};
		const comp = parsed?.compaction;
		if (!comp || typeof comp !== "object") return undefined;
		const prov = String(model?.provider ?? "").trim();
		const id = String(model?.id ?? "").trim();
		const key = prov && id ? `${prov}/${id}` : id;
		const overrides = comp.modelOverrides && typeof comp.modelOverrides === "object" ? comp.modelOverrides : undefined;
		let reserve: unknown = key && overrides?.[key]?.reserveTokens;
		if (typeof reserve !== "number" && id === "flash-auto" && overrides?.["deepseek/deepseek-flash"]) {
			reserve = overrides["deepseek/deepseek-flash"].reserveTokens;
		}
		if (typeof reserve !== "number") {
			reserve = comp.reserveTokens;
		}
		if (typeof reserve !== "number" || !Number.isFinite(reserve) || reserve <= 0) return undefined;
		const ctxWindow =
			typeof model?.contextWindow === "number" && model.contextWindow > 0
				? model.contextWindow
				: id === "deepseek-flash" || id === "flash-auto"
					? 1000000
					: 0;
		if (ctxWindow <= reserve) return undefined;
		return ctxWindow - reserve;
	} catch {
		return undefined;
	}
}

/**
 * Compute effective observation-masking high-water threshold:
 * - For deep cache-discount models (e.g. 50:1 cache discount like DeepSeek V4.1 Flash), mid-prefix
 *   `context_edit` invalidates ~80k cached tokens at 50x cost, which is strictly net-negative when
 *   auto-compaction already triggers <= 210k. Preserve emergency-only `210k` (never clamp below
 *   `compactionTriggerTokens`) so hot-cached runs ride cleanly to compaction.
 * - For standard models, cap safely below active auto-compaction trigger (`floor(trigger * 0.85)`).
 */
export function resolveEffectiveMaskHighWaterTokens(input: {
	deepCacheDiscount?: boolean;
	profileMaskTokens?: number;
	compactionTriggerTokens?: number;
}): number {
	const base =
		typeof input.profileMaskTokens === "number" && input.profileMaskTokens > 0
			? input.profileMaskTokens
			: input.deepCacheDiscount
				? 210000
				: MASK_HIGH_WATER_TOKENS;
	if (input.deepCacheDiscount) {
		return base;
	}
	if (typeof input.compactionTriggerTokens === "number" && input.compactionTriggerTokens >= 40000) {
		const dynamicCap = Math.max(40000, Math.floor(input.compactionTriggerTokens * 0.85));
		return Math.min(base, dynamicCap);
	}
	return base;
}

/**
 * Return true for DeepSeek models (including virtual `deepseek/flash-auto`).
 */
export function isDeepSeekModel(model?: { provider?: string; id?: string; modelId?: string }): boolean {
	if (!model) return false;
	const prov = String(model.provider ?? "").toLowerCase();
	const id = String(model.id ?? model.modelId ?? "").toLowerCase();
	return prov.includes("deepseek") || id.includes("deepseek") || id === "flash-auto" || id.endsWith("/flash-auto");
}

/**
 * Strip benign trailing stderr redirections (`2>/dev/null`, `2>NUL`, `2>&1`) from a shell command stage.
 */
function stripBenignStderrRedir(s: string): string {
	return s.replace(/\s+2>\s*(?:\/dev\/null|NUL|&1)\s*$/i, "").trim();
}

/**
 * Return true for non-retryable billing/auth/request errors (HTTP 400/401/402/403/404/422, insufficient balance,
 * hard quota/auth/context-length) that sub-LLM helpers must never retry. Preserves transient HTTP 429 / rate-limit
 * errors as retryable and anchors numeric codes so transport numbers (e.g. "reset after 404 ms") are still retried.
 */
export function isNonRetryableSubLlmError(errMsg: string): boolean {
	if (!errMsg) return false;
	if (/(?:\b429\b|too[\s_-]+many[\s_-]+requests|rate[\s_-]*limit)/i.test(errMsg)) {
		return false;
	}
	return /(?:HTTP(?:\/\d(?:\.\d)?)?\s+|status(?:\s+code)?[\s:=]+|\berror(?:\s+code)?[\s:=]+|\breturned\s+)(?:400|401|402|403|404|422)\b|\(\s*(?:400|401|402|403|404|422)\s*\)|^\s*(?:400|401|402|403|404|422)\s+[A-Za-z]|insufficient[\s_-]*balance|insufficient[\s_-]*quota|quota[\s_-]*exceeded|billing|payment|invalid[\s_-]*api[\s_-]*key|unauthorized|forbidden|authentication|context[\s_-]*length/i.test(
		errMsg,
	);
}

export interface SubLlmRetryOptions {
	reasoning?: "low" | "medium" | "high" | "max";
	maxTokens?: number;
	cacheRetention?: "none" | "short" | "long";
	signal?: AbortSignal;
	timeoutMs?: number;
	maxAttempts?: number;
	retryDelayMs?: number;
	unwrapVirtual?: boolean;
}

/**
 * Bounded-timeout, 1-retry jittered sub-LLM caller for compaction / handoff / review helpers.
 * Optionally unwraps `deepseek/flash-auto` to physical `deepseek/deepseek-flash`, and strictly never
 * retries 402/billing/auth/400 errors or caller aborts.
 */
export async function callSubLlmWithRetry(
	ctx: {
		modelRegistry?: {
			find?: (provider: string, id: string) => unknown;
			streamSimple?: (model: unknown, reqCtx: unknown, opts: unknown) => { result: () => Promise<Record<string, unknown>> };
			complete?: (model: unknown, reqCtx: unknown, opts: unknown) => Promise<Record<string, unknown>>;
		};
	},
	model: { provider?: string; id?: string; [k: string]: unknown },
	reqCtx: unknown,
	opts: SubLlmRetryOptions = {},
): Promise<Record<string, unknown> | undefined> {
	const targetModel =
		opts.unwrapVirtual && model?.id === "flash-auto"
			? (ctx?.modelRegistry?.find?.("deepseek", "deepseek-flash") ?? model)
			: model;
	const maxAttempts = Math.max(1, Math.min(3, opts.maxAttempts ?? 2));
	const timeoutMs = Math.max(1000, opts.timeoutMs ?? 45000);
	let lastResponse: Record<string, unknown> | undefined;
	let lastError: unknown;

	for (let attempt = 1; attempt <= maxAttempts; attempt++) {
		if (opts.signal?.aborted) return undefined;
		const ac = new AbortController();
		const onParentAbort = () => ac.abort();
		opts.signal?.addEventListener("abort", onParentAbort, { once: true });
		const timer = setTimeout(() => ac.abort(), timeoutMs);
		try {
			const callOpts = {
				reasoning: opts.reasoning ?? "low",
				maxTokens: opts.maxTokens ?? 6144,
				cacheRetention: opts.cacheRetention ?? "none",
				signal: ac.signal,
			};
			const resp =
				typeof ctx?.modelRegistry?.streamSimple === "function"
					? await ctx.modelRegistry.streamSimple(targetModel, reqCtx, callOpts).result()
					: typeof ctx?.modelRegistry?.complete === "function"
						? await ctx.modelRegistry.complete(targetModel, reqCtx, callOpts)
						: undefined;
			lastResponse = resp;
			if (!resp) {
				if (attempt >= maxAttempts) return undefined;
			} else if (resp.stopReason === "aborted") {
				if (opts.signal?.aborted || attempt >= maxAttempts) {
					return resp;
				}
			} else if (resp.stopReason === "error") {
				const errMsg = String(resp.errorMessage ?? resp.error ?? "");
				if (isNonRetryableSubLlmError(errMsg) || attempt >= maxAttempts) {
					return resp;
				}
			} else {
				return resp;
			}
		} catch (err) {
			lastError = err;
			const errMsg = err instanceof Error ? err.message : String(err);
			if (opts.signal?.aborted || isNonRetryableSubLlmError(errMsg) || attempt >= maxAttempts) {
				throw err;
			}
		} finally {
			clearTimeout(timer);
			opts.signal?.removeEventListener("abort", onParentAbort);
		}
		const delay =
			typeof opts.retryDelayMs === "number"
				? Math.max(0, opts.retryDelayMs)
				: 400 + Math.floor(Math.random() * 400);
		if (delay > 0) {
			await new Promise((r) => setTimeout(r, delay));
		}
	}
	if (lastResponse) return lastResponse;
	if (lastError) throw lastError;
	return undefined;
}

/**
 * Lexically escape unescaped raw newlines inside single/double-quoted JS strings while leaving
 * comments, regex literals, and multiline backtick template literals untouched (prevents QuickJS EOS errors).
 */
export function healJsStringRawNewlines(code: string): string | undefined {
	if (!code || (!code.includes("\n") && !code.includes("\r") && !code.includes("\\"))) return undefined;
	const n = code.length;
	let out = "";
	let lastFlush = 0;
	let changed = false;
	let i = 0;

	const scanRegexLiteral = (startSlash: number): number => {
		let prev = startSlash - 1;
		while (prev >= 0 && (code[prev] === " " || code[prev] === "\t")) prev--;
		let allowRegex = prev < 0 || "([,=;:!&|?{}~+-*%^<>\n\r".includes(code[prev]);
		if (!allowRegex && prev >= 0 && /[A-Za-z_$0-9]/.test(code[prev])) {
			let wStart = prev;
			while (wStart > 0 && /[A-Za-z_$0-9]/.test(code[wStart - 1])) wStart--;
			const word = code.slice(wStart, prev + 1);
			allowRegex = /^(?:return|throw|case|typeof|void|delete|await|yield|in|of|new)$/.test(word);
		}
		if (!allowRegex) return -1;
		let j = startSlash + 1;
		let inClass = false;
		while (j < n) {
			const rc = code[j];
			if (rc === "\n" || rc === "\r") return -1;
			if (rc === "\\") {
				if (j + 1 >= n || code[j + 1] === "\n" || code[j + 1] === "\r") return -1;
				j += 2;
				continue;
			}
			if (rc === "[") {
				inClass = true;
				j++;
				continue;
			}
			if (rc === "]" && inClass) {
				inClass = false;
				j++;
				continue;
			}
			if (rc === "/" && !inClass) {
				j++;
				while (j < n && /[a-z]/i.test(code[j])) j++;
				return j;
			}
			j++;
		}
		return -1;
	};

	const scanQuoted = (quote: string) => {
		i++;
		while (i < n) {
			const ch = code[i];
			if (ch === "\\") {
				let bs = 0;
				while (i + bs < n && code[i + bs] === "\\") bs++;
				if (bs % 2 === 1 && i + bs < n && code[i + bs] === quote) {
					let k = i + bs + 1;
					while (k < n && (code[k] === " " || code[k] === "\t")) k++;
					const nextCh = k < n ? code[k] : "";
					if (nextCh === "" || ",;}]):\r\n".includes(nextCh)) {
						let hasLaterClose = false;
						let s = i + bs + 1;
						while (s < n && code[s] !== "\n" && code[s] !== "\r") {
							if (code[s] === "\\") {
								let sbs = 0;
								while (s + sbs < n && code[s + sbs] === "\\") sbs++;
								s +=
									sbs % 2 === 1 && s + sbs < n && code[s + sbs] !== "\n" && code[s + sbs] !== "\r"
										? sbs + 1
										: sbs;
								continue;
							}
							if (code[s] === quote) {
								hasLaterClose = true;
								break;
							}
							s++;
						}
						if (!hasLaterClose) {
							out += code.slice(lastFlush, i + bs) + "\\";
							lastFlush = i + bs;
							changed = true;
							i += bs + 1;
							break;
						}
					}
				}
				i += bs % 2 === 1 && i + bs < n ? bs + 1 : bs;
				continue;
			}
			if (ch === "\r") {
				out += code.slice(lastFlush, i);
				if (code[i + 1] === "\n") {
					out += "\\n";
					i += 2;
				} else {
					out += "\\r";
					i++;
				}
				lastFlush = i;
				changed = true;
				continue;
			}
			if (ch === "\n") {
				out += code.slice(lastFlush, i) + "\\n";
				i++;
				lastFlush = i;
				changed = true;
				continue;
			}
			if (ch === quote) {
				i++;
				break;
			}
			i++;
		}
	};

	const scanTemplate = (isRawTag: boolean) => {
		i++;
		while (i < n) {
			const ch = code[i];
			if (ch === "\\") {
				let bs = 0;
				while (i + bs < n && code[i + bs] === "\\") bs++;
				if (bs % 2 === 1 && i + bs < n && code[i + bs] === "`") {
					let k = i + bs + 1;
					while (k < n && (code[k] === " " || code[k] === "\t")) k++;
					const nextCh = k < n ? code[k] : "";
					if (nextCh === "" || ",;}]):\r\n".includes(nextCh)) {
						let hasLaterBacktick = false;
						let s = i + bs + 1;
						while (s < n) {
							if (code[s] === "\\") {
								let sbs = 0;
								while (s + sbs < n && code[s + sbs] === "\\") sbs++;
								s += sbs % 2 === 1 && s + sbs < n ? sbs + 1 : sbs;
								continue;
							}
							if (code[s] === "`") {
								hasLaterBacktick = true;
								break;
							}
							s++;
						}
						if (!hasLaterBacktick) {
							if (isRawTag) {
								out += code.slice(lastFlush, i + bs - 1) + '` + "\\\\"';
								lastFlush = i + bs + 1;
							} else {
								out += code.slice(lastFlush, i + bs) + "\\";
								lastFlush = i + bs;
							}
							changed = true;
							i += bs + 1;
							break;
						}
					}
				}
				i += bs % 2 === 1 && i + bs < n ? bs + 1 : bs;
				continue;
			}
			if (ch === "$" && code[i + 1] === "{") {
				i += 2;
				scanNormal(true);
				continue;
			}
			if (ch === "`") {
				i++;
				break;
			}
			i++;
		}
	};

	const scanNormal = (stopOnCloseBrace: boolean) => {
		let braceDepth = 0;
		while (i < n) {
			const ch = code[i];
			if (ch === "{" && stopOnCloseBrace) {
				braceDepth++;
				i++;
				continue;
			}
			if (ch === "}" && stopOnCloseBrace) {
				if (braceDepth === 0) {
					i++;
					return;
				}
				braceDepth--;
				i++;
				continue;
			}
			if (ch === "/" && code[i + 1] === "/") {
				const nl = code.indexOf("\n", i + 2);
				i = nl < 0 ? n : nl + 1;
				continue;
			}
			if (ch === "/" && code[i + 1] === "*") {
				const end = code.indexOf("*/", i + 2);
				i = end < 0 ? n : end + 2;
				continue;
			}
			if (ch === "/" && code[i + 1] !== "/" && code[i + 1] !== "*") {
				const rEnd = scanRegexLiteral(i);
				if (rEnd > i) {
					i = rEnd;
					continue;
				}
			}
			if (ch === "'" || ch === '"') {
				scanQuoted(ch);
				continue;
			}
			if (ch === "`") {
				const isRawTag = /\bString\.raw[ \t]*$/.test(code.slice(Math.max(0, i - 16), i));
				scanTemplate(isRawTag);
				continue;
			}
			i++;
		}
	};

	scanNormal(false);
	if (!changed) return undefined;
	out += code.slice(lastFlush);
	return out;
}

const AP_MCP_TOOL_NAMES: ReadonlySet<string> = new Set([
	"ap_read",
	"ap_query",
	"ap_search",
	"ap_undo",
	"ap_orient",
	"ap_impact",
	"ap_edit",
	"ap_smoke",
	"ap_fuzz",
	"ap_mutate",
	"ap_ui",
	"ap_locate",
	"ap_trace",
	"ap_cdp",
	"ap_http",
	"ap_ports",
	"ap_ps",
	"ap_win",
	"ap_fs_diff",
	"ap_tcp",
	"ap_listen",
	"ap_ws",
	"ap_tls",
	"ap_baton_claim",
	"ap_baton_dedup",
	"ap_guard_pack",
	"ap_diff_audit",
	"ap_verify",
	"ap_exec",
	"ap_probe",
	"ap_rename",
	"ap_sieve",
	"ap_baton",
	"ap_recall",
	"ap_changes",
	"ap_surface",
	"ap_frontier",
	"ap_discover",
	"ap_call",
]);

function maskCodemodeSpans(code: string): { masked: string; tokens: string[] } | null {
	if (!code || code.includes("\u0001")) return null;
	const tokens: string[] = [];
	let masked = "";
	let last = 0;
	let i = 0;
	const n = code.length;
	const maskSpan = (start: number, end: number) => {
		masked += code.slice(last, start);
		const idx = tokens.length;
		tokens.push(code.slice(start, end));
		masked += `\u0001T${idx}\u0001`;
		last = end;
	};
	const scanRegexLit = (startSlash: number): number => {
		let prev = startSlash - 1;
		while (prev >= 0 && (code[prev] === " " || code[prev] === "\t")) prev--;
		let allow = prev < 0 || "([,=;:!&|?{}~+-*%^<>\n\r".includes(code[prev]);
		if (!allow && prev >= 0 && /[A-Za-z_$0-9]/.test(code[prev])) {
			let ws = prev;
			while (ws > 0 && /[A-Za-z_$0-9]/.test(code[ws - 1])) ws--;
			allow = /^(?:return|throw|case|typeof|void|delete|await|yield|in|of|new)$/.test(code.slice(ws, prev + 1));
		}
		if (!allow) return -1;
		let j = startSlash + 1;
		let inClass = false;
		while (j < n) {
			const rc = code[j];
			if (rc === "\n" || rc === "\r") return -1;
			if (rc === "\\") {
				if (j + 1 >= n || code[j + 1] === "\n" || code[j + 1] === "\r") return -1;
				j += 2;
				continue;
			}
			if (rc === "[") inClass = true;
			else if (rc === "]" && inClass) inClass = false;
			else if (rc === "/" && !inClass) {
				j++;
				while (j < n && /[a-z]/i.test(code[j])) j++;
				return j;
			}
			j++;
		}
		return -1;
	};
	const scanTpl = () => {
		let spanStart = i;
		i++;
		while (i < n) {
			const ch = code[i];
			if (ch === "\\") {
				i += i + 1 < n ? 2 : 1;
				continue;
			}
			if (ch === "$" && code[i + 1] === "{") {
				i += 2;
				maskSpan(spanStart, i);
				scanCode(true);
				spanStart = i;
				continue;
			}
			if (ch === "`") {
				i++;
				maskSpan(spanStart, i);
				return;
			}
			i++;
		}
		maskSpan(spanStart, n);
	};
	const scanCode = (stopOnBrace: boolean) => {
		let braceDepth = 0;
		while (i < n) {
			const ch = code[i];
			if (ch === "{" && stopOnBrace) {
				braceDepth++;
				i++;
				continue;
			}
			if (ch === "}" && stopOnBrace) {
				if (braceDepth === 0) {
					i++;
					return;
				}
				braceDepth--;
				i++;
				continue;
			}
			if (ch === "/" && code[i + 1] === "/") {
				const s = i;
				const nl = code.indexOf("\n", i + 2);
				i = nl < 0 ? n : nl;
				maskSpan(s, i);
				continue;
			}
			if (ch === "/" && code[i + 1] === "*") {
				const s = i;
				const end = code.indexOf("*/", i + 2);
				i = end < 0 ? n : end + 2;
				maskSpan(s, i);
				continue;
			}
			if (ch === "/" && code[i + 1] !== "/" && code[i + 1] !== "*") {
				const reEnd = scanRegexLit(i);
				if (reEnd > i) {
					maskSpan(i, reEnd);
					i = reEnd;
					continue;
				}
			}
			if (ch === "'" || ch === '"') {
				const s = i;
				const q = ch;
				i++;
				while (i < n) {
					if (code[i] === "\\") {
						i += i + 1 < n ? 2 : 1;
						continue;
					}
					if (code[i] === q) {
						i++;
						break;
					}
					if (code[i] === "\n" || code[i] === "\r") break;
					i++;
				}
				maskSpan(s, i);
				continue;
			}
			if (ch === "`") {
				scanTpl();
				continue;
			}
			i++;
		}
	};
	scanCode(false);
	masked += code.slice(last);
	return { masked, tokens };
}

function stripTsTypesInCodemode(code: string): string {
	if (!code || (!code.includes(":") && !/\bas\s+/.test(code) && !/\?[ \t]*[,)=]/.test(code))) return code;
	const spanRes = maskCodemodeSpans(code);
	if (!spanRes) return code;
	const { masked, tokens } = spanRes;

	const consumeBalancedType = (s: string, start: number, allowFnArrow: boolean): number => {
		let p = start;
		while (p < s.length && (s[p] === " " || s[p] === "\t")) p++;
		let angle = 0;
		let paren = 0;
		let bracket = 0;
		let brace = 0;
		let sawToken = false;
		let expectMore = true;
		while (p < s.length) {
			const ch = s[p];
			const depth = angle + paren + bracket + brace;
			if (ch === "<") {
				if (depth > 0 || sawToken) {
					angle++;
					p++;
					expectMore = true;
					continue;
				}
				break;
			}
			if (ch === ">") {
				if (angle > 0) {
					angle--;
					p++;
					sawToken = true;
					expectMore = false;
					continue;
				}
				break;
			}
			if (ch === "(") {
				if (depth > 0 || expectMore) {
					paren++;
					p++;
					expectMore = true;
					continue;
				}
				break;
			}
			if (ch === ")") {
				if (paren > 0) {
					paren--;
					p++;
					sawToken = true;
					expectMore = false;
					continue;
				}
				break;
			}
			if (ch === "[") {
				bracket++;
				p++;
				expectMore = true;
				continue;
			}
			if (ch === "]") {
				if (bracket > 0) {
					bracket--;
					p++;
					sawToken = true;
					expectMore = false;
					continue;
				}
				break;
			}
			if (ch === "{") {
				if (depth > 0 || expectMore) {
					brace++;
					p++;
					expectMore = true;
					continue;
				}
				break;
			}
			if (ch === "}") {
				if (brace > 0) {
					brace--;
					p++;
					sawToken = true;
					expectMore = false;
					continue;
				}
				break;
			}
			if (depth === 0) {
				if (ch === "=" && s[p + 1] === ">") {
					if (!allowFnArrow) break;
					p += 2;
					expectMore = true;
					continue;
				}
				if (";,=\r\n?:".includes(ch)) break;
				if (ch === "|" || ch === "&") {
					p++;
					expectMore = true;
					continue;
				}
				if (ch === " " || ch === "\t") {
					let q = p;
					while (q < s.length && (s[q] === " " || s[q] === "\t")) q++;
					if (s[q] === "=" && s[q + 1] === ">" && allowFnArrow) {
						p = q + 2;
						expectMore = true;
						continue;
					}
					if (s[q] === "|" || s[q] === "&" || s[q] === "[" || s[q] === "<") {
						p = q;
						continue;
					}
					const kw = s.slice(q).match(/^(?:in|of|as)\b/);
					if (kw) break;
					if (!expectMore) break;
					p = q;
					continue;
				}
				if (ch === "\u0001") {
					const endM = s.indexOf("\u0001", p + 1);
					if (endM < 0) break;
					p = endM + 1;
					sawToken = true;
					expectMore = false;
					continue;
				}
				if (/[A-Za-z0-9_$.]/.test(ch)) {
					p++;
					sawToken = true;
					expectMore = false;
					continue;
				}
				break;
			}
			p++;
		}
		if (angle !== 0 || paren !== 0 || bracket !== 0 || brace !== 0 || !sawToken) return -1;
		while (p > start && (s[p - 1] === " " || s[p - 1] === "\t")) p--;
		return p > start ? p : -1;
	};

	const stripParamList = (params: string, recDepth = 0): string => {
		let outP = "";
		let idx = 0;
		let dp = 0;
		let db = 0;
		let da = 0;
		let inDefault = false;
		let defaultBuf = "";
		const flushDefault = () => {
			if (!inDefault) return;
			if (
				recDepth < 4 &&
				(defaultBuf.includes(":") || /\?[ \t]*(?:,|=|\))/.test(defaultBuf)) &&
				(defaultBuf.includes("=>") || /\bfunction\b/.test(defaultBuf))
			) {
				outP += stripFnAndArrowTypes(defaultBuf, recDepth + 1);
			} else {
				outP += defaultBuf;
			}
			defaultBuf = "";
			inDefault = false;
		};
		const pushOut = (chunk: string) => {
			if (inDefault) defaultBuf += chunk;
			else outP += chunk;
		};
		while (idx < params.length) {
			const ch = params[idx];
			if (ch === "(") dp++;
			else if (ch === ")" && dp > 0) dp--;
			else if (ch === "[") db++;
			else if (ch === "]" && db > 0) db--;
			else if (ch === "<" && !inDefault) da++;
			else if (ch === ">" && da > 0) da--;
			else if (ch === "{") {
				let bDepth = 1;
				let j = idx + 1;
				while (j < params.length && bDepth > 0) {
					if (params[j] === "{") bDepth++;
					else if (params[j] === "}") bDepth--;
					j++;
				}
				pushOut(params.slice(idx, j));
				idx = j;
				if (dp === 0 && db === 0 && da === 0 && !inDefault) {
					const rest = params.slice(idx).match(/^[ \t]*\??[ \t]*:/);
					if (rest) {
						const tEnd = consumeBalancedType(params, idx + rest[0].length, true);
						if (tEnd > 0) idx = tEnd;
					} else {
						const bareOpt = params.slice(idx).match(/^[ \t]*\?(?=[ \t]*(?:,|=|$))/);
						if (bareOpt) idx += bareOpt[0].length;
					}
				}
				continue;
			}
			if (dp === 0 && db === 0 && da === 0) {
				if (ch === ",") {
					flushDefault();
					outP += ch;
					idx++;
					continue;
				} else if (
					!inDefault &&
					ch === "=" &&
					params[idx + 1] !== ">" &&
					params[idx + 1] !== "=" &&
					(idx === 0 || !"!=<>".includes(params[idx - 1]))
				) {
					outP += ch;
					inDefault = true;
					idx++;
					continue;
				} else if (!inDefault && (ch === "?" || ch === ":")) {
					const colonM = params.slice(idx).match(/^\??[ \t]*:/);
					if (colonM) {
						const tEnd = consumeBalancedType(params, idx + colonM[0].length, true);
						if (tEnd > 0) {
							idx = tEnd;
							continue;
						}
					} else if (ch === "?" && /[A-Za-z0-9_$}\]]$/.test(outP.trimEnd())) {
						let k = idx + 1;
						while (k < params.length && (params[k] === " " || params[k] === "\t")) k++;
						if (k >= params.length || params[k] === "," || params[k] === "=") {
							idx++;
							continue;
						}
					}
				}
			}
			pushOut(ch);
			idx++;
		}
		flushDefault();
		return outP;
	};

	const hasStrippableParamToken = (rawParams: string): boolean =>
		rawParams.includes(":") || /\?[ \t]*(?:,|=|$)/.test(rawParams);

	const stripFnAndArrowTypes = (src: string, recDepth = 0): string => {
		if (recDepth > 4 || (!src.includes(":") && !src.includes("?"))) return src;
		let curSrc = src;
		const fnHeadRe = /\b((?:async[ \t]+)?function(?:[ \t]+[A-Za-z_$][A-Za-z0-9_$]*)?[ \t]*)(?:<[^>\n;{]+>[ \t]*)?\(/g;
		let fnOut = "";
		let fnCur = 0;
		let fm: RegExpExecArray | null;
		while ((fm = fnHeadRe.exec(curSrc)) !== null) {
			const openParen = fm.index + fm[0].length - 1;
			let depth = 1;
			let p = openParen + 1;
			while (p < curSrc.length && depth > 0) {
				if (curSrc[p] === "(") depth++;
				else if (curSrc[p] === ")") depth--;
				p++;
			}
			if (depth !== 0) continue;
			const closeParen = p - 1;
			const rawParams = curSrc.slice(openParen + 1, closeParen);
			const cleanParams = hasStrippableParamToken(rawParams) ? stripParamList(rawParams, recDepth) : rawParams;
			let afterClose = closeParen + 1;
			const retColon = curSrc.slice(afterClose).match(/^[ \t]*:/);
			if (retColon) {
				const tEnd = consumeBalancedType(curSrc, afterClose + retColon[0].length, false);
				if (tEnd > 0) {
					let k = tEnd;
					while (k < curSrc.length && (curSrc[k] === " " || curSrc[k] === "\t")) k++;
					if (curSrc[k] === "{") {
						afterClose = tEnd;
					}
				}
			}
			fnOut += curSrc.slice(fnCur, fm.index) + fm[1] + "(" + cleanParams + ")" + (afterClose > closeParen + 1 ? " " : "");
			fnCur = afterClose;
			fnHeadRe.lastIndex = afterClose;
		}
		if (fnCur > 0) curSrc = fnOut + curSrc.slice(fnCur);

		// Arrow functions: `(params)[: ReturnType] =>`
		let arrOut = "";
		let arrCur = 0;
		for (let p = 0; p < curSrc.length; p++) {
			if (curSrc[p] !== "(") continue;
			let depth = 1;
			let q = p + 1;
			while (q < curSrc.length && depth > 0) {
				if (curSrc[q] === "(") depth++;
				else if (curSrc[q] === ")") depth--;
				q++;
			}
			if (depth !== 0) continue;
			const closeP = q - 1;
			let k = closeP + 1;
			while (k < curSrc.length && (curSrc[k] === " " || curSrc[k] === "\t")) k++;
			let arrowStart = -1;
			let retEnd = closeP + 1;
			if (curSrc[k] === "=" && curSrc[k + 1] === ">") {
				arrowStart = k;
			} else if (curSrc[k] === ":") {
				const tEnd = consumeBalancedType(curSrc, k + 1, false);
				if (tEnd > 0) {
					let k2 = tEnd;
					while (k2 < curSrc.length && (curSrc[k2] === " " || curSrc[k2] === "\t")) k2++;
					if (curSrc[k2] === "=" && curSrc[k2 + 1] === ">") {
						arrowStart = k2;
						retEnd = tEnd;
					}
				}
			}
			if (arrowStart >= 0) {
				const rawParams = curSrc.slice(p + 1, closeP);
				if (hasStrippableParamToken(rawParams) || retEnd > closeP + 1) {
					const cleanParams = hasStrippableParamToken(rawParams) ? stripParamList(rawParams, recDepth) : rawParams;
					arrOut += curSrc.slice(arrCur, p) + "(" + cleanParams + ")" + (retEnd > closeP + 1 ? " " : "");
					arrCur = retEnd;
					p = arrowStart + 1;
				}
			}
		}
		if (arrCur > 0) curSrc = arrOut + curSrc.slice(arrCur);
		return curSrc;
	};

	let res = masked;
	// 1. Variable declarations: `const x: Type = ...` or `let x: Type;`
	if (/\b(?:const|let|var)[ \t]+[A-Za-z_$]/.test(res)) {
		let nextRes = "";
		let cur = 0;
		const declRe = /\b(const|let|var)[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*:/g;
		let dm: RegExpExecArray | null;
		while ((dm = declRe.exec(res)) !== null) {
			const colonPos = dm.index + dm[0].length;
			const tEnd = consumeBalancedType(res, colonPos, true);
			if (tEnd > colonPos) {
				let k = tEnd;
				while (k < res.length && (res[k] === " " || res[k] === "\t")) k++;
				const tail = res.slice(k);
				if (
					k >= res.length ||
					"=;,\r\n)".includes(res[k]) ||
					/^(?:in|of)\b/.test(tail)
				) {
					nextRes += res.slice(cur, dm.index) + res.slice(dm.index, colonPos - 1).replace(/[ \t]*$/, "");
					cur = tEnd;
					declRe.lastIndex = tEnd;
				}
			}
		}
		if (cur > 0) res = nextRes + res.slice(cur);
	}

	// 2. `catch (e: unknown)` -> `catch (e)`
	res = res.replace(
		/\bcatch[ \t]*\([ \t]*([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*:[^()\n]+\)/g,
		"catch ($1)",
	);

	// 3. Function declarations/expressions & arrow functions (params + return types, recursively into default exprs)
	if (res.includes(":") || res.includes("?")) {
		res = stripFnAndArrowTypes(res, 0);
	}

	// 4. `as <Type>` casts (supports nested generics like `as unknown as Record<string, any>`)
	if (/\bas[ \t]+/.test(res)) {
		for (let pass = 0; pass < 3; pass++) {
			let asOut = "";
			let asCur = 0;
			const asRe = /(\)|\]|\}|\b[A-Za-z_$][A-Za-z0-9_$]*)[ \t]+\bas[ \t]+/g;
			let am: RegExpExecArray | null;
			while ((am = asRe.exec(res)) !== null) {
				const typeStart = am.index + am[0].length;
				const tEnd = consumeBalancedType(res, typeStart, true);
				if (tEnd > typeStart) {
					let k = tEnd;
					while (k < res.length && (res[k] === " " || res[k] === "\t")) k++;
					const nextCh = k < res.length ? res[k] : "";
					if (
						nextCh === "" ||
						";,)]\r\n.?:&|".includes(nextCh) ||
						/^as\b/.test(res.slice(k))
					) {
						asOut += res.slice(asCur, am.index + am[1].length);
						asCur = tEnd;
						asRe.lastIndex = tEnd;
					}
				}
			}
			if (asCur === 0) break;
			res = asOut + res.slice(asCur);
		}
	}

	return res.replace(/\u0001T(\d+)\u0001/g, (_m, idx: string) => tokens[Number(idx)] ?? "");
}

export function healStringRawInnerBackticks(code: string): string {
	if (!code || !code.includes("String.raw`")) return code;
	let out = "";
	let last = 0;
	let i = 0;
	const n = code.length;
	while (i < n) {
		if (
			code.startsWith("String.raw`", i) &&
			(i === 0 || !/[A-Za-z0-9_$]/.test(code[i - 1]))
		) {
			let j = i + "String.raw`".length;
			let segOut = "";
			let segLast = j;
			let closed = false;
			while (j < n) {
				const ch = code[j];
				if (ch === "$" && code[j + 1] === "{") {
					j += 2;
					let depth = 1;
					let q: string | null = null;
					while (j < n && depth > 0) {
						const ic = code[j];
						if (q) {
							if (ic === "\\" && q !== "`") { j += 2; continue; }
							if (ic === q) q = null;
							j++;
							continue;
						}
						if (ic === "'" || ic === '"' || ic === "`") { q = ic; j++; continue; }
						if (ic === "{") depth++;
						else if (ic === "}") depth--;
						j++;
					}
					continue;
				}
				if (ch === "`") {
					const after = code.slice(j + 1);
					const eolM = after.match(/^([^\r\n]*)/);
					const restLine = (eolM ? eolM[1] : "").trim();
					const isClosing =
						/^[;,)\]\}]?(?:\s*(?:\/\/.*)?)?$/.test(restLine) &&
						(restLine.length > 0 ||
							after.trim().length === 0 ||
							/^\r?\n(?:\s*(?:const|let|var|await|return|if|for|while|try|text|console|tools|\}|\)|\]|;))/.test(after));
					if (isClosing) {
						segOut += code.slice(segLast, j + 1);
						j++;
						closed = true;
						break;
					}
					segOut += code.slice(segLast, j) + '${"`"}';
					j++;
					segLast = j;
					continue;
				}
				j++;
			}
			if (closed && segOut !== code.slice(i + "String.raw`".length, j)) {
				out += code.slice(last, i + "String.raw`".length) + segOut;
				last = j;
				i = j;
				continue;
			}
			i = j;
			continue;
		}
		i++;
	}
	return last === 0 ? code : out + code.slice(last);
}

export function healRegexAlternationSlashes(code: string): string {
	if (!code || !code.includes("|/")) return code;
	return code.replace(
		/([(=,:;!&|?]\s*\/[^\/\r\n]*\|)\/([^\/\r\n]+\/[gimsuy]*\s*\.(?:test|exec)\b)/g,
		"$1\\/$2",
	);
}

function isAsiSafeBeforeOpenParen(s: string, pos: number): boolean {
	let j = pos - 1;
	let sawNewline = false;
	while (j >= 0 && (s[j] === " " || s[j] === "\t" || s[j] === "\r" || s[j] === "\n")) {
		if (s[j] === "\n" || s[j] === "\r") sawNewline = true;
		j--;
	}
	if (!sawNewline || j < 0) return true;
	const ch = s[j];
	if (";{},([=?:+-*/%&|^!~".includes(ch)) return true;
	if (ch === ">" && j >= 1 && s[j - 1] === "=") return true;
	if (/[A-Za-z_$]/.test(ch)) {
		let k = j;
		while (k > 0 && /[A-Za-z0-9_$]/.test(s[k - 1])) k--;
		const word = s.slice(k, j + 1);
		return /^(?:return|throw|case|else|do|yield|await|typeof|void|in|of)$/.test(word);
	}
	return false;
}

/**
 * Rewrite bare `JSON.stringify(<balanced>).slice(` calls inside `maskCodemodeSpans`-masked code
 * into `(JSON.stringify(<balanced>) ?? "undefined").slice(` so `JSON.stringify(undefined)` never
 * throws `TypeError: cannot read property 'slice' of undefined` in QuickJS codemode scripts.
 * Leaves `?.slice(`, strings, comments, regex literals, and property accesses untouched.
 */
function guardBareJsonStringifySlice(s: string): string {
	if (!s.includes("JSON.stringify")) return s;
	let out = "";
	let cur = 0;
	let i = 0;
	const n = s.length;
	while (i < n) {
		const idx = s.indexOf("JSON.stringify", i);
		if (idx < 0) break;
		const beforeCh = idx > 0 ? s[idx - 1] : "";
		if (beforeCh && /[A-Za-z0-9_$.]/.test(beforeCh)) {
			i = idx + 14;
			continue;
		}
		let prevSig = idx - 1;
		while (prevSig >= 0 && (s[prevSig] === " " || s[prevSig] === "\t" || s[prevSig] === "\r" || s[prevSig] === "\n")) {
			prevSig--;
		}
		if (prevSig >= 0 && s[prevSig] === ".") {
			i = idx + 14;
			continue;
		}
		let p = idx + 14;
		while (p < n && (s[p] === " " || s[p] === "\t" || s[p] === "\r" || s[p] === "\n")) p++;
		if (p >= n || s[p] !== "(") {
			i = idx + 14;
			continue;
		}
		let depth = 1;
		let q = p + 1;
		while (q < n && depth > 0) {
			if (s[q] === "(") depth++;
			else if (s[q] === ")") depth--;
			q++;
		}
		if (depth !== 0) {
			i = p + 1;
			continue;
		}
		const closeParen = q - 1;
		let after = closeParen + 1;
		while (after < n && (s[after] === " " || s[after] === "\t" || s[after] === "\r" || s[after] === "\n")) after++;
		const sliceM = s.slice(after).match(/^\.[ \t\r\n]*slice[ \t]*\(/);
		if (sliceM && isAsiSafeBeforeOpenParen(s, idx)) {
			const innerArgs = guardBareJsonStringifySlice(s.slice(p + 1, closeParen));
			out +=
				s.slice(cur, idx) +
				`(JSON.stringify(${innerArgs}) ?? "undefined")` +
				s.slice(closeParen + 1, after + sliceM[0].length);
			cur = after + sliceM[0].length;
			i = cur;
			continue;
		}
		const rawInner = s.slice(p + 1, closeParen);
		const fixedInner = guardBareJsonStringifySlice(rawInner);
		if (fixedInner !== rawInner) {
			out += s.slice(cur, p + 1) + fixedInner + ")";
			cur = closeParen + 1;
			i = cur;
			continue;
		}
		i = closeParen + 1;
	}
	return cur === 0 ? s : out + s.slice(cur);
}

/**
 * Lossless pre-execution auto-heal for Pi `codemode` JS scripts:
 * 1) Strips outer markdown code fences (```js ... ```) that break QuickJS parsing / `// @options:` line 1.
 * 2) Repairs `tools.mcp__agent-primitives__` -> `tools.mcp__agent_primitives__` (avoids JS subtraction ReferenceError).
 * 3) Escapes raw newlines inside single/double-quoted strings & heals trailing escaped quotes (`healJsStringRawNewlines`).
 * 4) Escapes embedded backticks inside `String.raw` blocks & unescaped alternation slashes in `.test()`/`.exec()` regexes.
 * 5) Guards bare `JSON.stringify(<balanced>).slice(` against `JSON.stringify(undefined)` TypeError without touching strings/comments/`?.slice`.
 * 6) Strips accidental TypeScript variable/parameter/return annotations and `as <Type>` casts (`stripTsTypesInCodemode`).
 * 7) Auto-shims `setTimeout(...)` via host `sleep(ms)` (eliminating 100% of QuickJS timer ReferenceErrors while keeping `// @options:` on line 1).
 */
export function healCodemodeSource(
	code: string,
	options?: { hasBuiltinSetTimeout?: boolean },
): string | undefined {
	if (!code) return undefined;
	let next = code;
	const fenced = next.match(/^\s*```(?:js|javascript|ts|typescript)?[ \t]*\r?\n([\s\S]*?)\r?\n```\s*$/i);
	if (fenced) {
		next = fenced[1];
	}
	next = healStringRawInnerBackticks(next);
	if (next.includes("String.raw`")) {
		next = next.replace(
			/(\bString\.raw`[^`\r\n]*?)(\\+)`([ \t]*(?:[;,)\]]|$))/gm,
			(m, head: string, bs: string, tail: string) =>
				bs.length % 2 === 1 ? `${head}${bs.slice(0, -1)}\` + "\\\\"${tail}` : m,
		);
	}
	const healedNewlines = healJsStringRawNewlines(next);
	if (healedNewlines) {
		next = healedNewlines;
	}
	next = healRegexAlternationSlashes(next);

	let needsSetTimeoutShim = false;
	const spanRes = maskCodemodeSpans(next);
	if (spanRes) {
		let { masked } = spanRes;
		const { tokens } = spanRes;
		// Hoist any real standalone `// @options:` comment (never inside string/template literals) to line 1
		const firstNl = next.indexOf("\n");
		const firstLine = firstNl >= 0 ? next.slice(0, firstNl) : next;
		if (!/^[ \t]*\/\/[ \t]*@options\b/.test(firstLine)) {
			const optIdx = tokens.findIndex((t) => /^\/\/[ \t]*@options[ \t]*:[^\r\n]*/.test(t));
			if (optIdx >= 0) {
				const tokTag = `\u0001T${optIdx}\u0001`;
				const tagRe = new RegExp(`(?:^|\\r?\\n)([ \\t]*${tokTag})`);
				const hm = masked.match(tagRe);
				if (hm && hm.index !== undefined) {
					const before = masked.slice(0, hm.index);
					const after = masked.slice(hm.index + hm[0].length);
					const rest = `${before}${after}`.replace(/^(?:[ \t]*\r?\n)+/, "");
					masked = `${tokTag}\n${rest}`;
				}
			}
		}
		if (masked.includes("tools.mcp__agent-primitives__")) {
			masked = masked.replace(/tools\.mcp__agent-primitives__/g, "tools.mcp__agent_primitives__");
		}
		if (/\btools\??\.ap_[a-z_]+\b/.test(masked)) {
			masked = masked.replace(/\btools(\??\.)(ap_[a-z_]+)\b/g, (m, sep: string, name: string) =>
				AP_MCP_TOOL_NAMES.has(name) ? `tools${sep}mcp__agent_primitives__${name}` : m,
			);
		}
		if (/\btools\[/.test(masked)) {
			masked = masked.replace(/\btools\[\u0001T(\d+)\u0001\]/g, (m, idxStr: string) => {
				const idx = Number(idxStr);
				const tm = tokens[idx]?.match(/^(['"])(ap_[a-z_]+)\1$/);
				if (tm && AP_MCP_TOOL_NAMES.has(tm[2])) {
					tokens[idx] = `${tm[1]}mcp__agent_primitives__${tm[2]}${tm[1]}`;
				}
				return m;
			});
		}
		if (/\bdescribeTool\(/.test(masked)) {
			masked = masked.replace(/\bdescribeTool\(\u0001T(\d+)\u0001\)/g, (m, idxStr: string) => {
				const idx = Number(idxStr);
				const tm = tokens[idx]?.match(/^(['"])(ap_[a-z_]+)\1$/);
				if (tm && AP_MCP_TOOL_NAMES.has(tm[2])) {
					tokens[idx] = `${tm[1]}mcp__agent_primitives__${tm[2]}${tm[1]}`;
				}
				return m;
			});
		}
		if (/\btools\.(?:describeTool|searchTools|describeNamespace)\b/.test(masked)) {
			masked = masked.replace(/\btools\.(describeTool|searchTools|describeNamespace)\b/g, "$1");
		}
		if (masked.includes("JSON.stringify")) {
			masked = guardBareJsonStringifySlice(masked);
		}
		needsSetTimeoutShim =
			!options?.hasBuiltinSetTimeout &&
			/\bsetTimeout\s*\(/.test(masked) &&
			!/\b(?:const|let|var|function)\s+setTimeout\b/.test(masked);
		next = masked.replace(/\u0001T(\d+)\u0001/g, (_m, idx: string) => tokens[Number(idx)] ?? "");
	} else {
		needsSetTimeoutShim =
			!options?.hasBuiltinSetTimeout &&
			/\bsetTimeout\s*\(/.test(next) &&
			!/\b(?:const|let|var|function)\s+setTimeout\b/.test(next);
	}

	next = stripTsTypesInCodemode(next);
	if (needsSetTimeoutShim) {
		const optLine = next.match(/^([ \t]*\/\/[ \t]*@options:[^\r\n]*\r?\n)([\s\S]*)$/);
		if (optLine) {
			next = `${optLine[1]}${CODEMODE_SETTIMEOUT_SHIM}\n${optLine[2]}`;
		} else {
			next = `${CODEMODE_SETTIMEOUT_SHIM}\n${next}`;
		}
	}
	return next !== code ? next : undefined;
}

/**
 * Aggregate all text blocks from a Pi `tool_result` content array (critical for multi-block
 * `codemode` results where content[0] is the "Script completed/failed" header and content[1..N]
 * hold the actual script output and "Script error: ..." diagnostics).
 */
export function extractAllToolResultText(
	content: ReadonlyArray<{ type?: string; text?: string }>,
): string {
	if (!Array.isArray(content)) return "";
	return content
		.filter((c) => c?.type === "text" && typeof c.text === "string")
		.map((c) => c.text as string)
		.join("\n");
}

function tryCompactJsonUnderLimit(
	raw: string,
	isFastModel = false,
	hardLimitOverride?: number,
	contextTokens?: number,
): string | undefined {
	const trimmed = raw.trim();
	if (
		!(trimmed.startsWith("{") && trimmed.endsWith("}")) &&
		!(trimmed.startsWith("[") && trimmed.endsWith("]"))
	) {
		return undefined;
	}
	let effHard = resolveProgressiveHardLimit(isFastModel ? 12000 : SIEVE_HARD_CHARS, hardLimitOverride, contextTokens, 18000);
	try {
		const compacted = JSON.stringify(JSON.parse(trimmed));
		// Exempt valid compacted single-line JSON < effHard from SIEVE_GIANT_LINE_CHARS (4.5KB) fallback
		if (compacted && compacted.length < raw.length * 0.9 && compacted.length < effHard) {
			return compacted;
		}
	} catch {
		// Fall through to full `ap sieve`
	}
	return undefined;
}

/**
 * Losslessly auto-sieve oversized `codemode` multi-block body text (content[1..N]) while keeping
 * the `Script completed`/`Script failed` header (content[0]), any trailing `Script error:` diagnostic,
 * and any `image` / non-text blocks 100% intact.
 */
export function sieveCodemodeContentBlocks(
	content: ReadonlyArray<{ type?: string; text?: string; [k: string]: unknown }>,
	sieveFn: (rawBody: string) => string | undefined,
	isFastModel = false,
	hardLimitOverride?: number,
	contextTokens?: number,
): Array<{ type?: string; text?: string; [k: string]: unknown }> | undefined {
	if (!Array.isArray(content) || content.length === 0) return undefined;
	const first = content[0];
	const hasHeader =
		first?.type === "text" &&
		typeof first.text === "string" &&
		/^Script (?:completed|failed)\b/.test(first.text);
	const startIdx = hasHeader ? 1 : 0;
	const bodyTexts: string[] = [];
	const preservedNonText: Array<{ type?: string; text?: string; [k: string]: unknown }> = [];
	for (let i = startIdx; i < content.length; i++) {
		const blk = content[i];
		if (blk?.type === "text" && typeof blk.text === "string") {
			bodyTexts.push(blk.text);
		} else {
			preservedNonText.push(blk);
		}
	}
	const combinedBody = bodyTexts.join("\n");
	if (
		!combinedBody ||
		combinedBody.includes("[sieve id=") ||
		!shouldAutoSieveShellOutput(combinedBody, isFastModel, hardLimitOverride, contextTokens)
	) {
		return undefined;
	}
	// Preserve any trailing `Script error:` block verbatim so error diagnostics + classifiers keep full fidelity
	let sieveInput = combinedBody;
	let errorTail = "";
	const errIdx = combinedBody.lastIndexOf("\nScript error:\n");
	if (errIdx > 0) {
		sieveInput = combinedBody.slice(0, errIdx);
		errorTail = combinedBody.slice(errIdx + 1).slice(0, 2400);
	} else if (combinedBody.startsWith("Script error:\n")) {
		return undefined;
	}
	if (!shouldAutoSieveShellOutput(sieveInput, isFastModel, hardLimitOverride, contextTokens)) {
		return undefined;
	}
	// Lossless whitespace compaction on pretty-printed JSON before invoking `ap sieve`
	const compacted = tryCompactJsonUnderLimit(sieveInput, isFastModel, hardLimitOverride, contextTokens);
	if (compacted) {
		const finalCompact = errorTail ? `${compacted}\n\n${errorTail}` : compacted;
		const outCompact: Array<{ type?: string; text?: string; [k: string]: unknown }> = [];
		if (hasHeader) outCompact.push(first);
		outCompact.push(...preservedNonText);
		outCompact.push({ type: "text", text: finalCompact });
		return outCompact;
	}
	const digested = sieveFn(sieveInput);
	if (!digested || digested.length <= 40 || digested.length >= sieveInput.length * 0.78) {
		return undefined;
	}
	const finalText = errorTail ? `${digested.trimEnd()}\n\n${errorTail}` : digested;
	const out: Array<{ type?: string; text?: string; [k: string]: unknown }> = [];
	if (hasHeader) out.push(first);
	out.push(...preservedNonText);
	out.push({ type: "text", text: finalText });
	return out;
}

/**
 * Resolve the primary payload text block index in a multi-block `tool_result` (e.g. `read` file
 * content in `content[0]` when upstream hooks append trailing advisory blocks at `content[1..N]`).
 */
export function findPrimaryToolResultTextIndex(
	content: ReadonlyArray<{ type?: string; text?: string }>,
	toolName?: string,
): number {
	if (!Array.isArray(content) || content.length === 0) return -1;
	let firstIdx = -1;
	for (let i = 0; i < content.length; i++) {
		if (content[i]?.type === "text" && typeof content[i].text === "string") {
			firstIdx = i;
			break;
		}
	}
	if (firstIdx < 0) return -1;
	if (toolName === "read") return firstIdx;
	return firstIdx;
}

/**
 * Losslessly auto-sieve every oversized text block in a `bash`/`powershell` `tool_result`
 * while preserving trailing advisory notices and non-text (`image`) blocks verbatim in place.
 */
export function sieveShellContentBlocks(
	content: ReadonlyArray<{ type?: string; text?: string; [k: string]: unknown }>,
	sieveFn: (rawBody: string) => string | undefined,
	isFastModel = false,
	hardLimitOverride?: number,
	contextTokens?: number,
): Array<{ type?: string; text?: string; [k: string]: unknown }> | undefined {
	if (!Array.isArray(content) || content.length === 0) return undefined;
	let changed = false;
	const out = content.map((blk) => {
		if (
			blk?.type === "text" &&
			typeof blk.text === "string" &&
			!blk.text.includes("[sieve id=") &&
			shouldAutoSieveShellOutput(blk.text, isFastModel, hardLimitOverride, contextTokens)
		) {
			const compacted = tryCompactJsonUnderLimit(blk.text, isFastModel, hardLimitOverride, contextTokens);
			if (compacted) {
				changed = true;
				return { ...blk, text: compacted };
			}
			const digested = sieveFn(blk.text);
			if (digested && digested.length > 40 && digested.length < blk.text.length * 0.78) {
				changed = true;
				return { ...blk, text: digested };
			}
		}
		return blk;
	});
	return changed ? out : undefined;
}

/**
 * Format an instant (<12ms) post-edit Tree-sitter/JSON/TOML syntax alert from `ap splice check --json`.
 * Returns `undefined` whenever syntax is clean (`ok !== false`) so zero bytes are added on valid edits.
 */
export function formatInstantSyntaxAlert(
	rawPath: string,
	checkStdout: string,
	cwd?: string,
): string | undefined {
	const trimmed = (checkStdout || "").trim();
	if (!trimmed.startsWith("{")) return undefined;
	try {
		const parsed = JSON.parse(trimmed) as {
			ok?: boolean;
			issues?: Array<string | { file?: string; line?: number; message?: string; detail?: string }>;
		};
		if (parsed.ok !== false || !Array.isArray(parsed.issues) || parsed.issues.length === 0) {
			return undefined;
		}
		const lines = parsed.issues.slice(0, 3).map((iss) =>
			typeof iss === "string"
				? `- ${iss.slice(0, 180)}`
				: `- ${iss.file ?? normRelPath(rawPath, cwd)}${iss.line ? `:${iss.line}` : ""} ${(iss.message ?? iss.detail ?? "syntax error").slice(0, 180)}`,
		);
		return `[ap syntax-alert] Immediate syntax error in ${normRelPath(rawPath, cwd)}:\n${lines.join("\n")}\nFix this syntax error now before moving to other files or tests.`;
	} catch {
		return undefined;
	}
}

/**
 * Targeted QuickJS `codemode` failure recovery classifier (addresses live ReferenceError/TypeError/Timeout/Syntax/OOM errors).
 */
export function classifyCodemodeFailureTip(outText: string): string {
	if (/\bReferenceError\b|is not defined/i.test(outText)) {
		return `[ap codemode-tip] QuickJS sandbox has NO Node APIs (fs/path/require/process/fetch/Buffer); use await sleep(ms) for delays and tools.<name>(args) (e.g. tools.read, tools.bash, tools.mcp__agent_primitives__ap_search) or inspect ALL_TOOLS.`;
	}
	if (
		/\bTypeError\b|(?:split|trim|match|replace|includes|slice|indexOf|toLowerCase|toUpperCase|startsWith|endsWith)\s+is not a function|\bnot a function\b|cannot read propert|not iterable|unexpected token.*\[object Object\]/i.test(
			outText,
		)
	) {
		return `[ap codemode-tip] TypeError: JSON.stringify(undefined) returns undefined (ALWAYS guard with (JSON.stringify(val) ?? "").slice(...)) and text(val) is a VOID output printer in older bundles (don't chain .slice() on it); if a tool result field (e.g. r.result?.value) is an auto-parsed JSON object/number rather than a string, convert via (typeof v === "string" ? v : JSON.stringify(v) ?? "").slice(...) instead of calling .slice() directly on a non-string; guard undefined strings with String(res?.output ?? res?.text ?? "").slice(...) before slicing/splitting. tools.bash(...) resolves to an OBJECT { output, exit_code, truncated, full_output_path }, tools.read(...) resolves to a string, and tools.mcp__* resolves to { content, structuredContent, isError } (already parsed; check Object.keys(res) instead of slicing undefined). With Promise.allSettled([...]), check r.status === "fulfilled" (read r.value?.output ?? r.value; rejected items have r.value === undefined and r.reason as an Error, so use String(r.reason)). Run await describeTool("<name>") to verify exact fields.`;
	}
	if (/Unexpected end of JSON input|unexpected token:\s*'object'|JSON\.parse/i.test(outText)) {
		return `[ap codemode-tip] SyntaxError (JSON.parse): tools.* ALREADY return structured JS objects/strings — inspect res.structuredContent or (res.output ?? "") directly without calling JSON.parse() on an already-parsed object or non-JSON wrapper.`;
	}
	if (/Unexpected identifier|unterminated string/i.test(outText)) {
		return `[ap codemode-tip] SyntaxError: unescaped quote or multiline literal inside JS source. Write complex payloads cleanly via tools.write instead of inline escaping.`;
	}
	if (/\bSyntaxError\b|options line/i.test(outText)) {
		return `[ap codemode-tip] Pass raw JS body only (no markdown code fences); // @options: {...} must be line 1 if used.`;
	}
	if (/\bout of memory\b/i.test(outText)) {
		return `[ap codemode-tip] Hit QuickJS 256MB WASM heap limit; filter/slice large payloads inside ap_search/ap_query or process files in smaller batches instead of buffering everything in RAM.`;
	}
	if (/\b(?:timed out|timeout|deadline)\b/i.test(outText)) {
		return `[ap codemode-tip] Codemode script timed out; parallelize independent calls with Promise.allSettled([...]) or raise // @options: {"timeout_ms": 90000}.`;
	}
	if (/\bvalidation\b|must be|required property/i.test(outText)) {
		return `[ap codemode-tip] Tool argument schema mismatch; run await describeTool("mcp__agent_primitives__<name>") to inspect exact required fields and types.`;
	}
	if (/\bENOENT\b|no such file|does not exist|cannot find the path/i.test(outText)) {
		return `[ap codemode-tip] File/path not found inside codemode; verify exact paths via tools.mcp__agent_primitives__ap_atlas / ap_search before reading or editing.`;
	}
	return `[ap codemode-tip] Use await searchTools("ap_") or await describeTool("mcp__agent_primitives__<name>") to verify exact tool IDs (dashes become underscores on tools.*) & typed structuredContent fields.`;
}

/**
 * Static, 100% KV-cache-locked DeepSeek Flash execution guidelines (~145 tokens total, cached at $0.006/1M)
 * injected via `before_agent_start` -> `systemPromptOptions.promptGuidelines` with concrete copy-paste idioms
 * (empirical production telemetry showed abstract prose had 0% ap-CLI & codemode-parallel adoption).
 */
export const AP_DEEPSEEK_GUIDELINES: readonly string[] = [
	"Parallel-first execution: batch 2+ independent reads/searches/checks in parallel tool calls OR one codemode script via `const res = await Promise.allSettled([tools.read({path}), tools.bash({command})]);` (cuts latency & thinking tokens ~40%); persist cross-turn state via `store(key, val)`/`load(key)`.",
	"In codemode (QuickJS sandbox — NO Node fs/path/require/process/fetch; `await sleep(ms)` is available): prefer typed MCP primitives `tools.mcp__agent_primitives__ap_search({pattern, path, only_matching: true, unique: true, json: true})`, `ap_read({target, routes: true, section, json: true})`, `ap_http`, `ap_cdp` over bash python/grep one-liners; `tools.bash({command})` returns `{ output, exit_code }`.",
	'Fast local CLI & exact edits: `read` on code/config shows `L:HH|` anchors (pass `L:HH|` in `edit` `oldText`). In bash, prefer zero-dep `ap` over grep/python/PS: `ap ls <d>`, `ap search -o -u --around 160 --pretty "<re>" [d]`, `ap read <file> --outline|--symbol <S>|--lines 1-80|--json-path <P>|--hex|--surface|--asar-surface|--ipc-graph|--fw-surface|--rpc-com-alpc|--routes --mutating-only|--ioctl --pipes|--xref`, `ap diff <old> <new> --semantic --json`, `ap sieve peek <id> --lines A-B --raw --max-chars 8000`, `ap ps|ports`, `ap win --pipes|--acl|--reg|--services|--sig <f>|--weak-acl|--unquoted|--com|--rpc --non-ms`, `ap cdp --export-role <port>`, `ap http --roles-matrix|--from-har <f> --fuzz-schema`, `ap ws --replay-har <f>`, `ap atlas map .`.',
];

export function injectDeepSeekGuidelines(guidelines: string[]): boolean {
	if (!Array.isArray(guidelines)) return false;
	let added = false;
	for (const rule of AP_DEEPSEEK_GUIDELINES) {
		if (!guidelines.includes(rule)) {
			guidelines.push(rule);
			added = true;
		}
	}
	return added;
}

/**
 * Calibrate Pi v1.5+ native `CacheWarmer` for DeepSeek V4.1 Flash economics ($0.006/1M cacheRead vs
 * $0.30/1M cold miss = 49x ROI). Overrides Pi's Opus-calibrated $0.05 floor when missCost >= $0.015
 * (~51k+ tokens) and ROI >= 20x so long tool runs & brief pauses stay at ~99% KV-cache hit rate.
 */
export function decideDeepSeekCacheWarming(input: {
	provider?: string;
	modelId?: string;
	warmCost?: number;
	missCost?: number;
	action?: string;
	isIdle?: boolean;
}): { action: "warm" } | undefined {
	if (!isDeepSeekModel(input)) return undefined;
	const warm = typeof input.warmCost === "number" ? input.warmCost : 0;
	const miss = typeof input.missCost === "number" ? input.missCost : 0;
	if (warm > 0 && ((miss >= 0.015 && miss / warm >= 20) || (input.isIdle && miss >= 0.005 && miss / warm >= 15))) {
		return { action: "warm" };
	}
	return undefined;
}

/**
 * Standalone serializer for fast `reasoning: "low"` dead-end-preserving auto-compaction
 * (zero runtime SDK imports; preserves previousSummary, exact TOOL_ERROR signatures, file ops & store keys).
 */
export function serializeMessagesForCompaction(
	messages: ReadonlyArray<Record<string, unknown>>,
	previousSummary?: string,
	readFiles: readonly string[] = [],
	modifiedFiles: readonly string[] = [],
	storeKeys: readonly string[] = [],
): string {
	const parts: string[] = [];
	if (previousSummary && previousSummary.trim()) {
		parts.push(`## Previous Summary\n${previousSummary.trim().slice(0, 6000)}`);
	}
	const errors: string[] = [];
	const trace: string[] = [];
	for (const raw of messages ?? []) {
		const m = raw as {
			role?: string;
			toolName?: string;
			isError?: boolean;
			content?: string | Array<{ type?: string; text?: string; name?: string; arguments?: Record<string, unknown> }>;
		};
		if (m?.role === "user" || m?.role === "assistant") {
			let txt = "";
			if (typeof m.content === "string") {
				txt = m.content;
			} else if (Array.isArray(m.content)) {
				const segs: string[] = [];
				for (const b of m.content) {
					if (b?.type === "text" && typeof b.text === "string" && b.text.trim()) {
						segs.push(b.text.trim());
					} else if (b?.type === "toolCall" && typeof b.name === "string") {
						const pArg =
							typeof b.arguments?.path === "string"
								? `(${b.arguments.path})`
								: typeof b.arguments?.command === "string"
									? `(${String(b.arguments.command).replace(/\s+/g, " ").slice(0, 80)})`
									: "";
						segs.push(`[call:${b.name}${pArg}]`);
					}
				}
				txt = segs.join("\n");
			}
			if (txt.trim()) trace.push(`${m.role.toUpperCase()}: ${txt.trim().slice(0, 1000)}`);
		} else if (m?.role === "toolResult" && m.isError) {
			const rawTxt = Array.isArray(m.content)
				? m.content.map((b) => (typeof b.text === "string" ? b.text : "")).join("\n")
				: "";
			const sigs = extractErrorSignatureLines(rawTxt);
			const line = `(${m.toolName ?? "tool"}) ${(sigs.join(" | ") || rawTxt.replace(/\s+/g, " ").slice(0, 180)).trim()}`;
			if (errors.length < 18 && !errors.includes(line)) errors.push(line);
		}
	}
	if (trace.length > 0) parts.push(`## Conversation Trace\n${trace.join("\n").slice(-26000)}`);
	if (errors.length > 0) parts.push(`## Exact Failing Errors Observed\n- ${errors.join("\n- ")}`);
	if (modifiedFiles.length > 0) parts.push(`## Modified Files\n${modifiedFiles.slice(0, 40).join(", ")}`);
	if (readFiles.length > 0) parts.push(`## Read-Only Files\n${readFiles.slice(0, 40).join(", ")}`);
	if (storeKeys.length > 0) parts.push(`## Active codemode-store Keys (recoverable via load(key))\n${storeKeys.slice(0, 20).join(", ")}`);
	return parts.join("\n\n");
}

function resolveProgressiveHardLimit(
	baseLimit: number,
	hardLimitOverride?: number,
	contextTokens?: number,
	lowCtxFloor = 18000,
): number {
	let limit =
		typeof hardLimitOverride === "number" && hardLimitOverride > 0 ? hardLimitOverride : baseLimit;
	if (typeof contextTokens === "number" && contextTokens > 0) {
		if (contextTokens < 60000) {
			limit = Math.max(limit, lowCtxFloor);
		} else if (contextTokens >= 120000) {
			limit = Math.min(limit, 8500);
		} else if (contextTokens >= 80000) {
			limit = Math.min(limit, 12000);
		}
	}
	return limit;
}

export function shouldAutoSieveShellOutput(
	text: string,
	isFastModel = false,
	hardLimitOverride?: number,
	contextTokens?: number,
): boolean {
	if (!text) return false;
	let hardLimit = isFastModel ? 12000 : SIEVE_HARD_CHARS;
	hardLimit = resolveProgressiveHardLimit(
		hardLimit,
		hardLimitOverride,
		contextTokens,
		18000,
	);
	if (text.length >= hardLimit) return true;
	const lines = text.split("\n");
	if (lines.some((l) => l.length > SIEVE_GIANT_LINE_CHARS) && !(lines.length <= 12 && text.length <= 12288)) return true;
	const structuredMin =
		typeof contextTokens === "number" && contextTokens > 0 && contextTokens < 60000
			? 18000
			: SIEVE_STRUCTURED_CHARS;
	if (text.length >= structuredMin) {
		if (lines.length >= SIEVE_STRUCTURED_LINES) return true;
		if (text.includes("\x1b[")) return true;
		if (text.includes("{") && text.split('":').length >= 21) return true;
	}
	return false;
}

export function classifyShellFailureTip(
	toolName: string,
	cmd: string,
	outText: string,
): string | undefined {
	if (isBenignGrepNoMatch(cmd, outText)) return undefined;
	if (/syntax error near unexpected token [`'"]?\(/i.test(outText) && /\bfor\s+%%?[A-Za-z_]|cd\s+\/d\b/i.test(cmd)) {
		return `[ap cmd-for-tip] Windows CMD \`for %x in (...)\` & \`cd /d\` syntax fails in Git Bash; use POSIX \`for x in ...; do ...; done\` (single-quoted/braced) or run via \`powershell\`.`;
	}
	if (/unicodeescape.*codec can't decode/i.test(outText)) {
		return `[ap py-unicodeescape-tip] Python non-raw string hit Windows backslash escape (\`\\U\`, \`\\N\`, etc.); use forward slashes (\`C:/...\`, \`Default/Network/Cookies\`) or raw \`r'...'\` WITHOUT a trailing backslash.`;
	}
	if (/SyntaxError:\s*unterminated string literal/i.test(outText)) {
		return `[ap py-rawstr-tip] Unterminated Python string (often trailing \`\\\` inside raw \`r'...'\\\\'\` or nested quotes); use forward slashes, \`ap probe win --pipes\` for named pipes, or \`python - <<'PY'\`.`;
	}
	if (QUOTE_OR_BS_ERR.test(outText)) {
		return `[ap quote-tip] Avoid nested quotes/backslashes inside inline python -c; use a single-quoted heredoc (python - <<'PY' ... PY) or write a script file via write/ap_edit.`;
	}
	if (/\b(?:json\.decoder\.)?JSONDecodeError\b|Unexpected token .* in JSON|\bConvertFrom-Json\b/i.test(outText)) {
		return `[ap json-tip] JSON parse failed (empty/HTML/non-JSON response); inspect HTTP status & raw prefix first or use \`ap probe http --select\` / \`ap read --json-path\` instead of blind json.loads.`;
	}
	if (/dir: cannot access '\/[bs]'/i.test(outText)) {
		return `[ap dir-tip] Windows \`dir /b\` fails under Git Bash; use \`ap ls <dir> --depth 2\` or POSIX \`ls\`.`;
	}
	if (/Program Files[\/\\]Git[\/\\](?:PID|FO|FI|NH|F|c|C|k|K|TN|TR|grant|query|add|CN=|OU=|O=)|Invalid argument\/option - ['"]?[A-Za-z]:[\/\\]Program Files[\/\\]Git[\/\\]/i.test(outText)) {
		return `[ap msys-tip] Git Bash MSYS2 mangled a Windows CLI '/flag' into 'C:/Program Files/Git/...'. Prefix with \`MSYS_NO_PATHCONV=1\` or use \`ap probe win --pipes/--reg/--acl/--services/--whoami\` (MCP/codemode: \`ap_win\`) instead of spawning tasklist/sc/icacls/reg/whoami.`;
	}
	if (/Unicode(?:Decode|Encode)Error:\s*'(?:gbk|cp936|cp1252|charmap)' codec can't/i.test(outText)) {
		return `[ap utf8-tip] Windows Python hit legacy GBK/cp936 encoding; set \`PYTHONUTF8=1 PYTHONIOENCODING=utf-8\` (or \`encoding="utf-8", errors="replace"\`) — or use \`ap read\`/\`ap search\`/\`ap sieve\` natively in Rust.`;
	}
	if (TIMEOUT_ERR_RE.test(outText)) {
		if (SEARCH_CMD_RE.test(cmd)) {
			return `[ap timeout-tip] Slow recursive shell search timed out; use ap search (or ap_search / ap_atlas) with -e <ext> or a narrower directory instead.`;
		}
		return `[ap timeout-tip] Command timed out (commands >2m also risk evicting DeepSeek KV-cache); cap synchronous commands <=90s, narrow scope, or redirect long jobs to a log file.`;
	}
	if (CMD_NOT_FOUND_RE.test(outText)) {
		for (const [re, replacement] of MISSING_CLI_MAP) {
			if (re.test(cmd)) {
				return `[ap cmd-tip] Missing shell CLI detected; use built-in zero-dependency \`${replacement}\` instead.`;
			}
		}
	}
	if (ENOENT_ERR_RE.test(outText)) {
		if (PATH_MISMATCH_RE.test(cmd)) {
			return `[ap path-tip] Detected /mnt/<drive>/ path; use native drive paths (C:/...) in Windows tools/Python or verify cwd before retrying.`;
		}
		if (toolName === "bash" && BASH_BS_PATH_RE.test(cmd)) {
			return `[ap path-tip] Unquoted Windows backslashes in Git Bash are stripped as escapes; use forward slashes (C:/path/to/file) or single quotes.`;
		}
		return `[ap enoent-tip] Path not found; verify actual paths via \`ap atlas map\` / \`ap search -l\` or check cwd before retrying.`;
	}
	if (/\b(?:ModuleNotFoundError|ImportError)\b/i.test(outText)) {
		return `[ap py-tip] Missing Python package; zero-dependency \`ap read\` (.docx/.xlsx/.pdf/PE/ELF/hex/JSON-path), \`ap query\` (SQLite/CSV/Excel) & \`ap search\` work without pip packages.`;
	}
	if (/\.asar\b/i.test(cmd)) {
		return `[ap surface-tip] For Electron archives/bundles, prefer \`ap read <app.asar> --asar-surface\` or \`--ipc-graph\`.`;
	}
	if (/\.sys\b|ioctl/i.test(cmd)) {
		return `[ap bin-tip] For Windows drivers/PE binaries, prefer \`ap read <bin> --ioctl --pipes --rpc-com-alpc\` or \`--xref\`.`;
	}
	if (/\.har\b|\bplaywright\b|\bfetch\b/i.test(cmd)) {
		return `[ap probe-tip] Replay & fuzz captured HTTP/WS flows directly via \`ap probe http --from-har <f> --fuzz-schema\` or \`ap probe ws --replay-har <f> --origin-matrix\`.`;
	}
	return undefined;
}

/**
 * Deterministic 2-hex FNV-1a content hash tag for Hashline (`L:HH|line`) anchored reading & editing
 * (inspired by Can Boluk's *The Harness Problem* / oh-my-pi; whitespace-trimmed & 100% KV-cache safe).
 */
export function hashlineTag(line: string): string {
	const s = line.trim();
	let h = 2166136261;
	for (let i = 0; i < s.length; i++) {
		h ^= s.charCodeAt(i);
		h = Math.imul(h, 16777619);
	}
	return ((h ^ (h >>> 8) ^ (h >>> 16) ^ (h >>> 24)) & 0xff).toString(16).padStart(2, "0");
}

const HASHLINE_EDITABLE_EXT = /\.(?:rs|ts|tsx|js|jsx|mjs|cjs|py|go|c|cc|cpp|h|hpp|toml|yaml|yml|ini|cfg|conf|sh|ps1|bat|cmd|sql|html|css|scss|vue|svelte)$/i;

/**
 * Annotate direct built-in `read` text output with compact `L:HH|` hashline anchors while
 * preserving Pi's trailing truncation banner and leaving `codemode` raw `structuredContent` untouched.
 * Emits anchors selectively for editable code/config files with <= 400 lines.
 */
export function annotateReadWithHashlines(outText: string, startOffset = 1, filePath?: string): string | undefined {
	if (!outText || outText.length > 60_000) return undefined;
	if (filePath && !HASHLINE_EDITABLE_EXT.test(filePath.trim())) return undefined;
	const trailerRe = /\n\n(\[(?:Showing lines [^\]]+|\d+ more lines in file[^\]]+|Truncated[^\]]+)\])\s*$/;
	const tm = outText.match(trailerRe);
	const body = tm ? outText.slice(0, tm.index) : outText;
	const trailer = tm ? outText.slice(tm.index) : "";
	const lines = body.split("\n");
	if (lines.length < 2 || lines.length > 400) return undefined;
	// Skip minified / giant single-line bundles
	if (lines.some((l) => l.length > 600)) return undefined;
	// Skip if already line-numbered or hashline-tagged
	const sampleNonBlank = lines.filter((l) => l.trim().length > 0).slice(0, 2);
	if (sampleNonBlank.length >= 1 && sampleNonBlank.every((l) => /^\s*\d+(?::[0-9a-f]{2})?(?::|\||\t)/.test(l))) {
		return undefined;
	}
	const base = Number.isFinite(startOffset) && startOffset >= 1 ? Math.floor(startOffset) : 1;
	const tagged = lines.map((l, idx) => `${base + idx}:${hashlineTag(l)}|${l}`).join("\n");
	return tagged + trailer;
}

/**
 * Clamp out-of-bounds `read(offset=...)` requests to the file's tail before Pi throws
 * `Offset N is beyond end of file (M lines total)`, eliminating wasted error round-trips.
 */
export function clampReadOffsetToEof(
	fileContent: string,
	offset: unknown,
	limit: unknown,
): { requestedOffset: number; clampedOffset: number; totalLines: number } | undefined {
	if (typeof offset !== "number" || !Number.isFinite(offset) || offset < 2) return undefined;
	const req = Math.floor(offset);
	const totalLines = fileContent.split("\n").length;
	if (req <= totalLines) return undefined;
	const win =
		typeof limit === "number" && Number.isFinite(limit) && limit > 0
			? Math.min(80, Math.max(20, Math.floor(limit)))
			: 60;
	const clampedOffset = Math.max(1, totalLines - win + 1);
	return { requestedOffset: req, clampedOffset, totalLines };
}

/**
 * Fast (<2ms) structural outline for truncated NON-CODE files (.md, .toml, .ini, .yaml, .json, .log, .jsonl, .csv)
 * so DeepSeek jumps straight to the target offset instead of blind sequential paging.
 */
export function extractNonCodeOutline(filePath: string, content: string): string | undefined {
	if (!filePath || !content) return undefined;
	const lines = content.replace(/\r\n/g, "\n").split("\n");
	const total = lines.length;
	if (total < 10) return undefined;
	const ext = (filePath.match(/\.([a-z0-9]+)$/i)?.[1] ?? "").toLowerCase();
	const items: string[] = [];
	if (ext === "md" || ext === "markdown") {
		for (let i = 0; i < total && items.length < 28; i++) {
			const m = lines[i].match(/^(#{1,4}\s+.+)$/);
			if (m) items.push(`L${i + 1}: ${m[1].trim().slice(0, 90)}`);
		}
		if (items.length > 0) {
			return `[ap read-outline] Markdown TOC (${total} lines; jump with read(offset=...)):\n${items.join("\n")}`;
		}
	} else if (ext === "toml" || ext === "ini" || ext === "cfg") {
		for (let i = 0; i < total && items.length < 28; i++) {
			const m = lines[i].match(/^\s*(\[[^\]]+\])/);
			if (m) items.push(`L${i + 1}: ${m[1].slice(0, 80)}`);
		}
		if (items.length > 0) {
			return `[ap read-outline] Config sections (${total} lines; jump with read(offset=...)):\n${items.join("\n")}`;
		}
	} else if (ext === "yml" || ext === "yaml") {
		for (let i = 0; i < total && items.length < 28; i++) {
			const m = lines[i].match(/^([A-Za-z0-9_.-]+:\s*(?:\S.*)?)$/);
			if (m) items.push(`L${i + 1}: ${m[1].slice(0, 80)}`);
		}
		if (items.length > 0) {
			return `[ap read-outline] YAML keys (${total} lines; jump with read(offset=...)):\n${items.join("\n")}`;
		}
	} else if (ext === "json" || ext === "jsonc") {
		for (let i = 0; i < total && items.length < 28; i++) {
			const m = lines[i].match(/^(?:  |\t)("[^"]+"\s*:)/);
			if (m) items.push(`L${i + 1}: ${m[1].slice(0, 80)}`);
		}
		if (items.length > 0) {
			return `[ap read-outline] JSON keys (${total} lines; jump with read(offset=...) or ap_read(json_path=...)):\n${items.join("\n")}`;
		}
	}
	return `[ap read-tip] Truncated large file (${total} lines); jump directly with read(offset=...) or filter via ap_search / ap_read(json_path=...) / ap_query instead of paging serially.`;
}

function countSubstringOccurrences(haystack: string, needle: string): number {
	if (!needle) return 0;
	let count = 0;
	let pos = 0;
	while (true) {
		const idx = haystack.indexOf(needle, pos);
		if (idx < 0) break;
		count++;
		if (count > 2) return count;
		pos = idx + 1;
	}
	return count;
}

function stripHashlinePrefixes(lines: readonly string[]): string[] {
	return lines.map((l) => {
		const m = l.match(/^\s*\d+:[0-9a-f]{2}\|(.*)$/);
		return m ? m[1] : l;
	});
}

interface ParsedHashlineRange {
	startIdx: number;
	endIdx: number;
	effectiveNew: string;
	expandedLo: number;
	expandedHi: number;
}

function parseHashlineAnchorRange(
	lfFile: string,
	fileLines: readonly string[],
	rawOldLines: readonly string[],
	lfNew: string,
): ParsedHashlineRange | undefined {
	const hlRe = /^\s*(\d+):([0-9a-f]{2})\|(.*)$/;
	const parsed: Array<{ lineNum: number; hash: string; body: string } | null> = [];
	let firstLineNum = -1;
	let lastLineNum = -1;
	let anchorCount = 0;
	for (const l of rawOldLines) {
		if (l.trim().length === 0) {
			parsed.push(null);
			continue;
		}
		const m = l.match(hlRe);
		if (!m) return undefined;
		const num = Number(m[1]);
		if (!Number.isInteger(num) || num < 1 || num > fileLines.length) return undefined;
		if (firstLineNum < 0) {
			firstLineNum = num;
		} else if (num !== lastLineNum + 1) {
			return undefined;
		}
		const diskLine = fileLines[num - 1];
		if (hashlineTag(diskLine) !== m[2]) return undefined;
		const body = m[3] ?? "";
		if (body.trim().length > 0 && body.trim() !== diskLine.trim()) return undefined;
		parsed.push({ lineNum: num, hash: m[2], body });
		lastLineNum = num;
		anchorCount++;
	}
	if (anchorCount === 0 || firstLineNum < 1) return undefined;
	const startIdx = firstLineNum - 1;
	const endIdx = lastLineNum; // exclusive
	const matchedDisk = fileLines.slice(startIdx, endIdx);
	const strippedOldBodies = parsed.filter((p): p is NonNullable<typeof p> => p !== null).map((p) => p.body);
	const cleanNew = stripHashlinePrefixes(lfNew.split("\n")).join("\n");
	const effectiveNew = reindentReplacement(cleanNew, strippedOldBodies, matchedDisk);
	for (let pad = 0; pad <= 8; pad++) {
		const lo = Math.max(0, startIdx - pad);
		const hi = Math.min(fileLines.length, endIdx + pad);
		const candOld = fileLines.slice(lo, hi).join("\n");
		if (countSubstringOccurrences(lfFile, candOld) === 1) {
			return { startIdx, endIdx, effectiveNew, expandedLo: lo, expandedHi: hi };
		}
	}
	return undefined;
}

/**
 * Tier-0A Hashline anchor resolution: supports BOTH single-line AND multi-line `L:HH|...` anchors,
 * verifies exact 1-based line number + 2-hex FNV hash against disk (zero stale-edit risk), and
 * symmetrically auto-expands surrounding context lines when the target slice occurs multiple times!
 */
function resolveHashlineAnchorEdit(
	lfFile: string,
	fileLines: readonly string[],
	rawOldLines: readonly string[],
	lfNew: string,
): { oldText: string; newText: string; strategy: string } | undefined {
	const r = parseHashlineAnchorRange(lfFile, fileLines, rawOldLines, lfNew);
	if (!r) return undefined;
	const candOld = fileLines.slice(r.expandedLo, r.expandedHi).join("\n");
	const prefix = fileLines.slice(r.expandedLo, r.startIdx);
	const suffix = fileLines.slice(r.endIdx, r.expandedHi);
	const candNew = [...prefix, r.effectiveNew, ...suffix].join("\n");
	const expanded = r.expandedLo < r.startIdx || r.expandedHi > r.endIdx;
	return {
		oldText: candOld,
		newText: candNew,
		strategy: expanded ? "hashline-anchor-expanded" : "hashline-anchor-unique",
	};
}

/**
 * Resolve multi-hunk `edit.edits[]` arrays where 2+ disjoint Hashline-anchored hunks would overlap
 * after symmetric context expansion (e.g. editing two adjacent duplicate lines in one `edit` call),
 * automatically merging overlapping expanded clusters into single unique non-overlapping blocks.
 */
export function resolveAndMergeHashlineEdits(
	fileContent: string,
	edits: ReadonlyArray<{ oldText?: string; newText?: string }>,
): { edits: Array<{ oldText: string; newText: string }>; healed: number } | undefined {
	if (!fileContent || !Array.isArray(edits) || edits.length < 2) return undefined;
	const lfFile = fileContent.replace(/\r\n/g, "\n");
	const fileLines = lfFile.split("\n");
	const parsed: Array<{ origIdx: number; range: ParsedHashlineRange }> = [];
	const others: Array<{ oldText: string; newText: string }> = [];
	for (let i = 0; i < edits.length; i++) {
		const it = edits[i];
		if (typeof it?.oldText !== "string" || typeof it?.newText !== "string") return undefined;
		const r = parseHashlineAnchorRange(
			lfFile,
			fileLines,
			it.oldText.replace(/\r\n/g, "\n").split("\n"),
			it.newText.replace(/\r\n/g, "\n"),
		);
		if (r) {
			parsed.push({ origIdx: i, range: r });
		} else {
			others.push({ oldText: it.oldText, newText: it.newText });
		}
	}
	if (parsed.length < 2) return undefined;
	parsed.sort((a, b) => a.range.startIdx - b.range.startIdx);
	// Bail safely if raw Hashline target ranges themselves overlap (let Pi surface the genuine overlap error)
	for (let i = 1; i < parsed.length; i++) {
		if (parsed[i - 1].range.endIdx > parsed[i].range.startIdx) return undefined;
	}
	// Group items whose expanded unique windows overlap
	const clusters: Array<Array<ParsedHashlineRange>> = [[parsed[0].range]];
	let clusterHi = parsed[0].range.expandedHi;
	let hasMergedCluster = false;
	for (let i = 1; i < parsed.length; i++) {
		const cur = parsed[i].range;
		if (cur.expandedLo < clusterHi) {
			clusters[clusters.length - 1].push(cur);
			clusterHi = Math.max(clusterHi, cur.expandedHi);
			hasMergedCluster = true;
		} else {
			clusters.push([cur]);
			clusterHi = cur.expandedHi;
		}
	}
	if (!hasMergedCluster) return undefined;

	const outEdits: Array<{ oldText: string; newText: string }> = [];
	for (const group of clusters) {
		const minStart = group[0].startIdx;
		const maxEnd = group[group.length - 1].endIdx;
		const midLines: string[] = [];
		let cursor = minStart;
		for (const g of group) {
			if (g.startIdx > cursor) {
				midLines.push(...fileLines.slice(cursor, g.startIdx));
			}
			midLines.push(g.effectiveNew);
			cursor = g.endIdx;
		}
		const mergedBodyNew = midLines.join("\n");
		let resolved: { oldText: string; newText: string } | undefined;
		for (let pad = 0; pad <= 8; pad++) {
			const lo = Math.max(0, minStart - pad);
			const hi = Math.min(fileLines.length, maxEnd + pad);
			const candOld = fileLines.slice(lo, hi).join("\n");
			if (countSubstringOccurrences(lfFile, candOld) === 1) {
				const prefix = fileLines.slice(lo, minStart);
				const suffix = fileLines.slice(maxEnd, hi);
				resolved = {
					oldText: candOld,
					newText: [...prefix, mergedBodyNew, ...suffix].join("\n"),
				};
				break;
			}
		}
		if (!resolved) return undefined;
		outEdits.push(resolved);
	}
	let healed = parsed.length;
	for (const o of others) {
		const fixed = healEditBlock(fileContent, o.oldText, o.newText);
		if (fixed) {
			outEdits.push({ oldText: fixed.oldText, newText: fixed.newText });
			healed += 1;
		} else {
			outEdits.push(o);
		}
	}
	return { edits: outEdits, healed };
}

function stripSequentialLineNumbers(lines: readonly string[]): string[] | undefined {
	const nonBlank = lines.filter((l) => l.trim().length > 0);
	if (nonBlank.length < 2) return undefined;
	const lineRe = /^\s*(\d+)(?::[0-9a-f]{2})?(?::|\||\t) ?(.*)$/;
	let prevNum = -1;
	const stripped: string[] = [];
	for (const l of lines) {
		if (l.trim().length === 0) {
			stripped.push("");
			continue;
		}
		const m = l.match(lineRe);
		if (!m) return undefined;
		const num = Number(m[1]);
		if (!Number.isFinite(num) || num <= prevNum) return undefined;
		prevNum = num;
		stripped.push(m[2] ?? "");
	}
	return stripped;
}

function reindentReplacement(
	newStr: string,
	oldLines: readonly string[],
	matchedDiskLines: readonly string[],
): string {
	const oldFirst = oldLines.find((l) => l.trim().length > 0);
	const diskFirst = matchedDiskLines.find((l) => l.trim().length > 0);
	if (oldFirst === undefined || diskFirst === undefined) return newStr;
	const oldLead = oldFirst.match(/^[ \t]*/)?.[0] ?? "";
	const diskLead = diskFirst.match(/^[ \t]*/)?.[0] ?? "";
	if (oldLead === diskLead) return newStr;
	return newStr
		.split("\n")
		.map((line) => {
			if (line.trim().length === 0) return "";
			if (oldLead.length > 0 && line.startsWith(oldLead)) {
				return diskLead + line.slice(oldLead.length);
			}
			if (oldLead.length === 0) {
				return diskLead + line;
			}
			return line;
		})
		.join("\n");
}

/**
 * Proactive pre-execution indent/blank-line repair for Pi's built-in `edit` tool
 * (complements Pi's edit-diff.js which normalizes trailing spaces/smart-quotes but not leading indent).
 * Strictly requires a 100% unique match on disk — returns `undefined` if already valid or ambiguous.
 */
export function healEditBlock(
	fileContent: string,
	oldText: string,
	newText: string,
): { oldText: string; newText: string; strategy: string } | undefined {
	if (!fileContent || !oldText) return undefined;
	const lfFile = fileContent.replace(/\r\n/g, "\n");
	const lfOld = oldText.replace(/\r\n/g, "\n");
	const lfNew = newText.replace(/\r\n/g, "\n");
	if (lfFile.includes(lfOld)) return undefined;
	const trimEndAll = (s: string) =>
		s
			.split("\n")
			.map((l) => l.trimEnd())
			.join("\n");
	if (trimEndAll(lfFile).includes(trimEndAll(lfOld))) return undefined;

	const fileLines = lfFile.split("\n");
	const rawOldLines = lfOld.split("\n");
	// Tier 0A: Exact verified Hashline `L:HH|...` anchor resolution (works on 1-line & duplicate lines via symmetric context expansion!)
	const hlHit = resolveHashlineAnchorEdit(lfFile, fileLines, rawOldLines, lfNew);
	if (hlHit) return hlHit;
	// Tier 0B: Auto-strip accidental sequential line-number prefixes (e.g. `12: code` / `12:a3|code` copied from read/edit-closest/nl)
	const strippedOld = stripSequentialLineNumbers(rawOldLines);
	const oldLines = strippedOld ?? rawOldLines;
	let effectiveNew = lfNew;
	if (strippedOld) {
		const strippedNew = stripSequentialLineNumbers(lfNew.split("\n"));
		if (strippedNew) effectiveNew = strippedNew.join("\n");
	}
	const nonBlankOld = oldLines.filter((l) => l.trim().length > 0);
	if (nonBlankOld.length === 0 || !nonBlankOld.some((l) => l.trim().length >= 4)) {
		return undefined;
	}

	// Tier 1 (or Tier 0 after lineno strip): Exact-length dedented line-block unique match
	const n = oldLines.length;
	const exactHits: number[] = [];
	for (let i = 0; i <= fileLines.length - n; i++) {
		let ok = true;
		for (let k = 0; k < n; k++) {
			if (fileLines[i + k].trim() !== oldLines[k].trim()) {
				ok = false;
				break;
			}
		}
		if (ok) {
			exactHits.push(i);
			if (exactHits.length > 1) break;
		}
	}
	if (exactHits.length === 1) {
		const matched = fileLines.slice(exactHits[0], exactHits[0] + n);
		const healedOld = matched.join("\n");
		if (healedOld !== lfOld) {
			return {
				oldText: healedOld,
				newText: reindentReplacement(effectiveNew, oldLines, matched),
				strategy: strippedOld ? "lineno-strip-unique" : "indent-unique",
			};
		}
	}

	// Tier 2: Blank-line-tolerant dedented unique match (requires >=2 non-blank lines)
	if (nonBlankOld.length >= 2) {
		const spans: Array<[number, number]> = [];
		const firstTrim = nonBlankOld[0].trim();
		for (let i = 0; i < fileLines.length; i++) {
			if (fileLines[i].trim() !== firstTrim) continue;
			let cur = i + 1;
			let matchedAll = true;
			let lastIdx = i;
			for (let k = 1; k < nonBlankOld.length; k++) {
				let skippedBlanks = 0;
				while (cur < fileLines.length && fileLines[cur].trim().length === 0 && skippedBlanks < 2) {
					cur++;
					skippedBlanks++;
				}
				if (cur >= fileLines.length || fileLines[cur].trim() !== nonBlankOld[k].trim()) {
					matchedAll = false;
					break;
				}
				lastIdx = cur;
				cur++;
			}
			if (matchedAll) {
				spans.push([i, lastIdx]);
				if (spans.length > 1) break;
			}
		}
		if (spans.length === 1) {
			const [s0, s1] = spans[0];
			const matched = fileLines.slice(s0, s1 + 1);
			const healedOld = matched.join("\n");
			if (healedOld !== lfOld) {
				return {
					oldText: healedOld,
					newText: reindentReplacement(effectiveNew, oldLines, matched),
					strategy: "blankline-unique",
				};
			}
		}
	}

	// Tier 3: Punctuation & collapsed-whitespace normalized unique match (heals full-width `：`/`，`/`（` vs ASCII drift)
	if (nonBlankOld.some((l) => l.trim().length >= 8)) {
		const normLoose = (s: string) =>
			s
				.replace(/[\u200B\uFEFF]/g, "")
				.replace(/\u00A0/g, " ")
				.replace(/[—–]/g, "-")
				.trim()
				.replace(/[：]/g, ":")
				.replace(/[，]/g, ",")
				.replace(/[（]/g, "(")
				.replace(/[）]/g, ")")
				.replace(/[“”]/g, '"')
				.replace(/[‘’]/g, "'")
				.replace(/\s+/g, " ")
				.replace(/\s*\|\s*/g, "|")
				.replace(/\s*([:,()])\s*/g, "$1");
		const looseHits: number[] = [];
		for (let i = 0; i <= fileLines.length - n; i++) {
			let ok = true;
			for (let k = 0; k < n; k++) {
				if (normLoose(fileLines[i + k]) !== normLoose(oldLines[k])) {
					ok = false;
					break;
				}
			}
			if (ok) {
				looseHits.push(i);
				if (looseHits.length > 1) break;
			}
		}
		if (looseHits.length === 1) {
			const matched = fileLines.slice(looseHits[0], looseHits[0] + n);
			const healedOld = matched.join("\n");
			if (healedOld !== lfOld) {
				return {
					oldText: healedOld,
					newText: reindentReplacement(effectiveNew, oldLines, matched),
					strategy: "punctuation-loose-unique",
				};
			}
		}
	}
	return undefined;
}

/**
 * Heal multi-hunk `edit.edits[]` arrays:
 * 1) Heals each hunk independently against the original file (matching Pi's non-incremental semantics).
 * 2) If a hunk only resolves sequentially after an earlier hunk (or two hunks overlap), simulates
 *    sequentially and collapses compact (<=80-line) changes into a single unique edit on the original file.
 */
export function healMultiEditsSequential(
	fileContent: string,
	edits: ReadonlyArray<{ oldText?: string; newText?: string }>,
): { edits: Array<{ oldText: string; newText: string }>; healed: number } | undefined {
	if (!fileContent || !Array.isArray(edits) || edits.length === 0) return undefined;
	const lfOrig = fileContent.replace(/\r\n/g, "\n");
	const origOut: Array<{ oldText: string; newText: string }> = [];
	const origRanges: Array<[number, number]> = [];
	let origHealed = 0;
	let allMatchOrigUnique = true;
	for (const item of edits) {
		if (typeof item?.oldText !== "string" || typeof item?.newText !== "string") return undefined;
		let curOld = item.oldText;
		let curNew = item.newText;
		const fixed = healEditBlock(lfOrig, curOld, curNew);
		if (fixed) {
			curOld = fixed.oldText;
			curNew = fixed.newText;
			origHealed += 1;
		}
		const lfOld = curOld.replace(/\r\n/g, "\n");
		const idx = lfOld.length > 0 ? lfOrig.indexOf(lfOld) : -1;
		if (idx < 0 || lfOrig.indexOf(lfOld, idx + 1) >= 0) {
			allMatchOrigUnique = false;
		} else {
			origRanges.push([idx, idx + lfOld.length]);
		}
		origOut.push({ oldText: curOld, newText: curNew });
	}
	let hasOrigOverlap = false;
	if (allMatchOrigUnique && origRanges.length >= 2) {
		const sorted = [...origRanges].sort((a, b) => a[0] - b[0]);
		for (let i = 1; i < sorted.length; i++) {
			if (sorted[i - 1][1] > sorted[i][0]) {
				hasOrigOverlap = true;
				break;
			}
		}
	}
	if (allMatchOrigUnique && !hasOrigOverlap) {
		return origHealed > 0 ? { edits: origOut, healed: origHealed } : undefined;
	}
	if (edits.length < 2) {
		return origHealed > 0 ? { edits: origOut, healed: origHealed } : undefined;
	}
	let virtual = lfOrig;
	let allApplied = true;
	for (const item of edits) {
		if (typeof item?.oldText !== "string" || typeof item?.newText !== "string") return undefined;
		let curOld = item.oldText;
		let curNew = item.newText;
		const fixed = healEditBlock(virtual, curOld, curNew);
		if (fixed) {
			curOld = fixed.oldText;
			curNew = fixed.newText;
		}
		const lfOld = curOld.replace(/\r\n/g, "\n");
		const lfNew = curNew.replace(/\r\n/g, "\n");
		const idx = lfOld.length > 0 ? virtual.indexOf(lfOld) : -1;
		if (idx < 0 || virtual.indexOf(lfOld, idx + 1) >= 0) {
			allApplied = false;
			break;
		}
		virtual = virtual.slice(0, idx) + lfNew + virtual.slice(idx + lfOld.length);
	}
	if (allApplied && virtual !== lfOrig) {
		const origLines = lfOrig.split("\n");
		const finalLines = virtual.split("\n");
		let prefix = 0;
		const minLen = Math.min(origLines.length, finalLines.length);
		while (prefix < minLen && origLines[prefix] === finalLines[prefix]) prefix++;
		let suffix = 0;
		while (
			suffix < minLen - prefix &&
			origLines[origLines.length - 1 - suffix] === finalLines[finalLines.length - 1 - suffix]
		) {
			suffix++;
		}
		const origEnd = origLines.length - suffix;
		const finalEnd = finalLines.length - suffix;
		if (origEnd - prefix <= 80) {
			for (let pad = 0; pad <= 8; pad++) {
				const lo = prefix - Math.min(pad, prefix);
				const rightPad = Math.min(pad, suffix);
				const hiOrig = origEnd + rightPad;
				const hiFinal = finalEnd + rightPad;
				const candOld = origLines.slice(lo, hiOrig).join("\n");
				if (candOld.length > 0 && countSubstringOccurrences(lfOrig, candOld) === 1) {
					const candNew = finalLines.slice(lo, hiFinal).join("\n");
					return { edits: [{ oldText: candOld, newText: candNew }], healed: edits.length };
				}
			}
		}
	}
	return origHealed > 0 ? { edits: origOut, healed: origHealed } : undefined;
}

/**
 * Normalize legacy or double-encoded `edit` argument shapes in place (pi-edit-guard pattern):
 * `file_path -> path`, `old_string -> oldText`, `new_string -> newText`, and stringified `edits[]`.
 */
export function normalizeEditArgs(input: Record<string, unknown>): boolean {
	if (!input || typeof input !== "object") return false;
	let changed = false;
	if (typeof input.path !== "string" && typeof input.file_path === "string") {
		input.path = input.file_path;
		delete input.file_path;
		changed = true;
	}
	if (typeof input.edits === "string" && input.edits.trim().startsWith("[")) {
		try {
			const parsed = JSON.parse(input.edits);
			if (Array.isArray(parsed)) {
				input.edits = parsed;
				changed = true;
			}
		} catch {
			// leave invalid JSON untouched
		}
	}
	if (Array.isArray(input.edits)) {
		for (const item of input.edits) {
			if (!item || typeof item !== "object") continue;
			const rec = item as Record<string, unknown>;
			if (typeof rec.oldText !== "string" && typeof rec.old_string === "string") {
				rec.oldText = rec.old_string;
				delete rec.old_string;
				changed = true;
			}
			if (typeof rec.newText !== "string" && typeof rec.new_string === "string") {
				rec.newText = rec.new_string;
				delete rec.new_string;
				changed = true;
			}
		}
	} else {
		if (typeof input.oldText !== "string" && typeof input.old_string === "string") {
			input.oldText = input.old_string;
			delete input.old_string;
			changed = true;
		}
		if (typeof input.newText !== "string" && typeof input.new_string === "string") {
			input.newText = input.new_string;
			delete input.new_string;
			changed = true;
		}
	}
	return changed;
}

/**
 * Locate all exact (or trimmed-indent) occurrences when built-in `edit` fails due to multiple matches,
 * reporting exact 1-based line numbers + surrounding context so the next turn disambiguates in 1 shot.
 */
export function findAllEditOccurrenceLines(
	fileContent: string,
	oldText: string,
	maxHits = 6,
): string | undefined {
	if (!fileContent || !oldText) return undefined;
	const lines = fileContent.replace(/\r\n/g, "\n").split("\n");
	const needleLines = oldText.replace(/\r\n/g, "\n").split("\n");
	const n = needleLines.length;
	if (n === 0 || n > lines.length) return undefined;
	const hits: number[] = [];
	for (let i = 0; i <= lines.length - n; i++) {
		let ok = true;
		for (let j = 0; j < n; j++) {
			if (lines[i + j].trim() !== needleLines[j].trim()) {
				ok = false;
				break;
			}
		}
		if (ok) {
			hits.push(i);
		}
	}
	if (hits.length < 2) return undefined;
	const shown = hits.slice(0, maxHits).map((idx) => {
		const prev = idx > 0 ? lines[idx - 1].trim().slice(0, 55) : "<BOF>";
		const cur = lines[idx].trim().slice(0, 65);
		return `L${idx + 1} [${idx + 1}:${hashlineTag(lines[idx])}|${cur}] (after: ${prev})`;
	});
	const more = hits.length > maxHits ? ` (+${hits.length - maxHits} more)` : "";
	return `[ap edit-multi] Found ${hits.length} occurrences${more} — pass the exact L:HH| anchor or add 1 unique surrounding line to oldText:\n${shown.join("\n")}`;
}

/**
 * Compute a compact numbered Top-1 closest matching line window when built-in `edit` fails,
 * eliminating the ~47% wasted post-error full-file `read` round-trip.
 */
export function findClosestEditWindow(fileContent: string, oldText: string): string | undefined {
	if (!fileContent || !oldText) return undefined;
	const tokenize = (s: string) => new Set(s.toLowerCase().match(/[a-z0-9_]{2,}/g) ?? []);
	const qToks = tokenize(oldText);
	if (qToks.size < 2) return undefined;
	const lines = fileContent.replace(/\r\n/g, "\n").split("\n");
	if (lines.length === 0) return undefined;
	const oldCount = oldText.replace(/\r\n/g, "\n").split("\n").length;
	const win = Math.max(3, Math.min(14, oldCount + 2));
	const maxScan = Math.min(lines.length, 6000);
	const step = maxScan > 2000 ? 2 : 1;
	let bestScore = 0;
	let bestStart = -1;
	for (let i = 0; i < maxScan; i += step) {
		const end = Math.min(lines.length, i + win);
		const wToks = tokenize(lines.slice(i, end).join("\n"));
		if (wToks.size === 0) continue;
		let inter = 0;
		for (const t of qToks) {
			if (wToks.has(t)) inter++;
		}
		const dice = (2 * inter) / (qToks.size + wToks.size);
		if (dice > bestScore) {
			bestScore = dice;
			bestStart = i;
		}
	}
	if (bestStart < 0 || bestScore < 0.3) return undefined;
	const end = Math.min(lines.length, bestStart + win);
	const body = lines
		.slice(bestStart, end)
		.map((l, idx) => `${bestStart + idx + 1}:${hashlineTag(l)}|${l}`)
		.join("\n")
		.slice(0, 850);
	return `[ap edit-closest] Closest lines on disk (L${bestStart + 1}-L${end}; pass L:HH| directly in edit oldText):\n${body}`;
}

export function listCodemodeStoreKeys(branch: ReadonlyArray<Record<string, unknown>>): string[] {
	const keys = new Set<string>();
	if (!Array.isArray(branch)) return [];
	for (const e of branch) {
		if (e?.type === "custom" && e.customType === "codemode-store" && e.data && typeof e.data === "object") {
			const d = e.data as { set?: Record<string, unknown>; delete?: string[] };
			if (d.set && typeof d.set === "object") {
				for (const k of Object.keys(d.set)) keys.add(k);
			}
			if (Array.isArray(d.delete)) {
				for (const k of d.delete) keys.delete(k);
			}
		}
	}
	return [...keys];
}

export function countCodemodeStoreKeys(branch: ReadonlyArray<Record<string, unknown>>): number {
	return listCodemodeStoreKeys(branch).length;
}

export const SIEVE_SELF_MAX_BYPASS_CHARS = 64_000;

export function shouldSkipAutoSieveForSelf(isSelf: boolean, maxBlockLen: number): boolean {
	return isSelf && maxBlockLen <= SIEVE_SELF_MAX_BYPASS_CHARS;
}

function hasUnquotedShellChainOrPipe(s: string): boolean {
	let q: "'" | '"' | null = null;
	for (let i = 0; i < s.length; i++) {
		const ch = s[i];
		if (q) {
			if (ch === "\\" && q === '"' && i + 1 < s.length) {
				i++;
				continue;
			}
			if (ch === q) q = null;
			continue;
		}
		if (ch === "\\" && i + 1 < s.length) {
			i++;
			continue;
		}
		if (ch === "'" || ch === '"') {
			q = ch;
			continue;
		}
		if (ch === ";" || ch === "|" || ch === "\n" || ch === "\r") return true;
		if (ch === "&") {
			// Allow benign fd redirections like `2>&1` or `>&2`, reject `&&` and background `&`
			if (s[i + 1] === "&") return true;
			if (i === 0 || s[i - 1] !== ">") return true;
		}
	}
	return false;
}

function stripJsCommentsPreserveStrings(code: string): string {
	let out = "";
	let q: "'" | '"' | "`" | null = null;
	for (let i = 0; i < code.length; i++) {
		const ch = code[i];
		const next = code[i + 1];
		if (q) {
			out += ch;
			if (ch === "\\" && i + 1 < code.length) {
				out += code[++i];
				continue;
			}
			if (ch === q) q = null;
			continue;
		}
		if (ch === "/" && next === "/") {
			i += 2;
			while (i < code.length && code[i] !== "\n") i++;
			if (i < code.length) out += "\n";
			continue;
		}
		if (ch === "/" && next === "*") {
			i += 2;
			while (i + 1 < code.length && !(code[i] === "*" && code[i + 1] === "/")) i++;
			i++;
			out += " ";
			continue;
		}
		if (ch === "'" || ch === '"' || ch === "`") {
			q = ch;
		}
		out += ch;
	}
	return out;
}

export function isSieveSelfCommand(cmd: string): boolean {
	if (!cmd) return false;
	let rest = cmd.trim();
	// Strip harmless leading env prefixes (`export ...;`, `VAR=VAL `) or `cd <dir> &&`
	let progressed = true;
	while (progressed) {
		progressed = false;
		const envM = rest.match(/^(?:export\s+(?:[A-Za-z_]\w*=(?:"[^"]*"|'[^']*'|\S+)\s*)+;\s*|(?:[A-Za-z_]\w*=(?:"[^"]*"|'[^']*'|\S+)\s+)+)/);
		if (envM) {
			rest = rest.slice(envM[0].length).trimStart();
			progressed = true;
			continue;
		}
		const cdM = rest.match(/^cd(?:\s+\/d)?\s+(?:"[^"]+"|'[^']+'|\S+)\s*(?:&&|;)\s*/i);
		if (cdM) {
			rest = rest.slice(cdM[0].length).trimStart();
			progressed = true;
		}
	}
	if (!rest || hasUnquotedShellChainOrPipe(rest)) return false;
	return /^(?:(?:"[^"\r\n]*[/\\]ap(?:\.exe)?"|'[^'\r\n]*[/\\]ap(?:\.exe)?'|(?:[^\s"'`;&|]*[/\\])?ap(?:\.exe)?))\s+sieve\s+(?:peek|search|list|prune|stats)\b/i.test(
		rest,
	);
}

export function isSieveSelfCodemode(code: string): boolean {
	if (!code) return false;
	const stripped = stripJsCommentsPreserveStrings(code);
	const calls: Array<{ name: string; openIdx: number }> = [];
	const callRe = /\btools\.([A-Za-z0-9_$]+)\s*\(/g;
	let m: RegExpExecArray | null;
	while ((m = callRe.exec(stripped)) !== null) {
		calls.push({ name: m[1], openIdx: m.index + m[0].length });
	}
	if (calls.length === 0) return false;
	for (const c of calls) {
		if (/^(?:mcp__agent_primitives__ap_sieve|ap_sieve|[a-z0-9_]*sieve_(?:query|peek))$/i.test(c.name)) {
			continue;
		}
		if (c.name === "bash" || c.name === "powershell") {
			// Extract the balanced call argument slice and verify a static sieve-self command literal
			let depth = 1;
			let q: "'" | '"' | "`" | null = null;
			let i = c.openIdx;
			while (i < stripped.length && depth > 0) {
				const ch = stripped[i];
				if (q) {
					if (ch === "\\" && i + 1 < stripped.length) {
						i += 2;
						continue;
					}
					if (ch === q) q = null;
					i++;
					continue;
				}
				if (ch === "'" || ch === '"' || ch === "`") q = ch;
				else if (ch === "(") depth++;
				else if (ch === ")") depth--;
				i++;
			}
			const argBody = stripped.slice(c.openIdx, Math.max(c.openIdx, i - 1));
			const cmdM = argBody.match(/\bcommand\s*:\s*(['"`])((?:\\[\s\S]|(?!\1)[\s\S])*)\1/);
			if (!cmdM) return false;
			if (cmdM[1] === "`" && cmdM[2].includes("${")) return false;
			const litCmd = cmdM[2].replace(/\\(["'`\\])/g, "$1");
			if (!isSieveSelfCommand(litCmd)) return false;
			continue;
		}
		return false;
	}
	return true;
}

/**
 * Clarify `ap sieve pipe` footer so models never pass regexes to FTS5 `search` or vice versa.
 */
export function formatAutoSieveDigest(stdout: string): string {
	if (!stdout) return stdout;
	return stdout.replace(
		/\|\s*peek:\s*ap sieve peek ([a-z0-9_-]+) --lines A:B\s*\|\s*--grep REGEX\]/i,
		"| regex: ap sieve peek $1 --grep REGEX [--lines A:B] | keywords(FTS5): ap sieve search <words>]",
	);
}

export function normCmdFingerprint(raw: string): string {
	const norm = raw
		.replace(/^export\s+PYTHONUTF8=1\s+PYTHONIOENCODING=utf-8;\s*/i, "")
		.replace(/^\$env:PYTHONUTF8='1';\s*\$env:PYTHONIOENCODING='utf-8';\s*/i, "")
		.replace(/\b0x[0-9a-fA-F]{4,}\b/g, "<HEX>")
		.replace(/\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b/g, "<TS>")
		.replace(/\s+/g, " ")
		.trim();
	if (norm.length < 8) return norm;
	const digest = createHash("sha256").update(norm).digest("hex").slice(0, 16);
	return `${digest}:${norm.slice(0, 96)}`;
}

export function formatPostEditLineShiftTip(
	input: Record<string, unknown> | undefined,
	details?: { firstChangedLine?: number } | undefined,
): string | undefined {
	if (!input || typeof input !== "object") return undefined;
	const items: Array<{ oldText?: string; newText?: string }> = Array.isArray(input.edits)
		? (input.edits as Array<{ oldText?: string; newText?: string }>)
		: typeof input.oldText === "string" && typeof input.newText === "string"
			? [{ oldText: input.oldText, newText: input.newText }]
			: [];
	if (items.length === 0) return undefined;
	let delta = 0;
	for (const it of items) {
		if (typeof it?.oldText !== "string" || typeof it?.newText !== "string") continue;
		const oldLines = it.oldText.replace(/\r\n/g, "\n").split("\n").length;
		const newLines = it.newText.replace(/\r\n/g, "\n").split("\n").length;
		delta += newLines - oldLines;
	}
	if (delta === 0) return undefined;
	const sign = delta > 0 ? `+${delta}` : `${delta}`;
	const anchor =
		typeof details?.firstChangedLine === "number" && details.firstChangedLine > 0
			? ` below L${details.firstChangedLine}`
			: "";
	return `[ap edit-lines] Net line shift: ${sign} line(s)${anchor} (subsequent line numbers shifted by ${sign}).`;
}

function shellQuoteBashPat(pat: string): string {
	return `'${pat.replace(/'/g, "'\\''")}'`;
}

function translateGrepBreToRustRegex(pat: string, flags: string): string {
	if (!pat || flags.includes("E") || flags.includes("F")) return pat;
	return pat.replace(/\\([|(){}+?])/g, "$1");
}

function rewriteSlowRecursiveGrep(cmd: string, toolName: string): string | undefined {
	// Match optional leading `cd <dir> && ` or `cd <dir>; `, strip `2>/dev/null`/`2>NUL`/`2>&1` & trailing pagers (`| more`/`| less`).
	const cleaned = cmd
		.replace(/\s+2>\s*(?:\/dev\/null|NUL|&1)(?=\s*(?:$|\|))/gi, "")
		.replace(/\s+--exclude-dir=(?:'[^']+'|"[^"]+"|[^\s|&;]+)/g, "")
		.replace(/\s*\|\s*(?:more|less)\s*$/i, "");
	if (/>/.test(cleaned)) return undefined;

	// Fast-path A0: variable-assigned archive/minified grep-o `f="/path/to/app.asar"; [timeout N] grep -a -o ".\{0,N\}pat.\{0,M\}" "$f" [| head ...]`
	const varGrep = cleaned.match(
		/^\s*(?:([A-Za-z_]\w*)=(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))\s*;\s*)(?:timeout\s+\d+\s+)?grep\s+(?:-[aAoEP]+\s+)+(?:"((?:[^"\\]|\\.)+)"|'([^']+)')\s+"\$(\w+)"(\s*\|\s*(?:head|tail|wc|sort|cut)\b[^;&|>]*)?\s*$/,
	);
	if (varGrep && varGrep[1] === varGrep[7]) {
		const fileTarget = varGrep[2] || varGrep[3] || varGrep[4] || "";
		const rawPat = varGrep[5] || varGrep[6] || "";
		const bm = rawPat.match(/^(?:\.\\?\{0,(\d+)\\?\})?([\s\S]+?)(?:\.\\?\{0,(\d+)\\?\})?$/);
		const leftN = Number(bm?.[1] || 0);
		const rightN = Number(bm?.[3] || 0);
		const rawMid = bm?.[2] || rawPat;
		if (fileTarget && (leftN > 0 || rightN > 0) && rawMid) {
			const around = Math.min(800, Math.max(40, leftN, rightN));
			const prefix = toolName === "powershell" ? "& " : "";
			const quotedPat = toolName === "bash" ? shellQuoteBashPat(rawMid) : `"${rawMid.replace(/"/g, '\\"')}"`;
			return `${prefix}"${AP_BIN}" search --around ${around} --pretty ${quotedPat} "${fileTarget}"${varGrep[8] || ""}`;
		}
	}

	// Fast-path A: slow minified-JS context regex `grep -oE '.{0,N}PAT.{0,M}' file [| head ...]` -> `<25ms` `ap search --around`
	const aroundMatch = cleaned.match(
		/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?\s*grep\s+((?:-[aAoEPirRhHn]+\s+)+)['"]\.\\?\{0,(\d+)\\?\}([^'"]+?)(\.\\?\{0,(\d+)\\?\})?['"]\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))(\s*\|\s*(?:head|tail|wc|sort|cut)\b[^;&|>]*)?\s*$/,
	);
	if (aroundMatch && aroundMatch[2].includes("o")) {
		const cdPrefix = aroundMatch[1] || "";
		const rawFlags = aroundMatch[2] || "";
		const leftN = Math.min(800, Math.max(40, Number(aroundMatch[3]) || 160));
		const rightN = Math.min(800, Math.max(40, Number(aroundMatch[6]) || leftN));
		const around = Math.max(leftN, rightN);
		const rawPat = aroundMatch[4] || "";
		const target = aroundMatch[7] || aroundMatch[8] || aroundMatch[9] || ".";
		const pipeSuffix = aroundMatch[10] || "";
		if (rawPat && !rawPat.includes("{")) {
			const prefix = toolName === "powershell" ? "& " : "";
			const quotedPat = toolName === "bash" ? shellQuoteBashPat(rawPat) : `"${rawPat.replace(/"/g, '\\"')}"`;
			const icFlag = rawFlags.includes("i") ? " -i" : "";
			return `${cdPrefix}${prefix}"${AP_BIN}" search${icFlag} --around ${around} --pretty ${quotedPat} "${target}"${pipeSuffix}`;
		}
	}

	// Fast-path A2: `for f in <files>; do [echo "$f";] grep [-a] -o[E] '<pat>' "$f"; done` -> `rg -a --no-ignore -o ...`
	const forGrep = cleaned.match(
		/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?for\s+(\w+)\s+in\s+([^;]+);\s*do\s+(?:echo\s+"?\$\2"?\s*;\s*)?grep\s+(?:-[aAoEP]+\s+)+(['"])([\s\S]+?)\4\s+"?\$\2"?\s*;\s*done\s*$/,
	);
	if (forGrep) {
		const cdPrefix = forGrep[1] || "";
		const files = forGrep[3].trim();
		const q = forGrep[4];
		const erePat = forGrep[5].replace(/\\([{}])/g, "$1");
		return `${cdPrefix}rg -a --no-ignore -o ${q}${erePat}${q} ${files}`;
	}

	// Fast-path A2b: `for f in <files>; do [echo "== $f";] grep -a -o -E <pat> "$f" [| pipe...]; done` -> `rg -a --no-ignore -o`
	if (
		/^\s*(?:cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?for\s+\w+\s+in\b[\s\S]*\bgrep\s+-[aAoEPhHi]+[\s\S]*;\s*done\s*$/.test(
			cleaned,
		)
	) {
		const rewrittenFor = cleaned.replace(
			/\bgrep\s+((?:-[aAoEPhHi]+\s+)+)(['"])([\s\S]+?)\2/g,
			(gm, flg: string, q: string, gp: string) => {
				if (!flg.includes("o")) return gm;
				const erePat = flg.includes("E") ? gp : translateGrepBreToRustRegex(gp, "");
				const noFile = flg.includes("h") ? " --no-filename" : "";
				const ic = flg.includes("i") ? " -i" : "";
				return `rg -a --no-ignore -o${noFile}${ic} ${q}${erePat}${q}`;
			},
		);
		if (rewrittenFor !== cleaned) return rewrittenFor;
	}

	// Fast-path A3: `cat <files> | grep -o[E] <pat> [| sort/head...]` -> `rg -a --no-ignore -o --no-filename`
	// Strictly require `-o`, refuse `-n`/`-A`/`cat -<flag>`, preserve leading `echo ...;`, preserve `-i`, and translate BRE when `-E` is absent.
	const catGrep = cleaned.match(
		/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?(echo\s+[^;]+;\s*)?cat\s+([^|;&]+)\|\s*grep\s+-([aAoEhHni]+)\s+('[^']+'|"[^"]+")(\s*\|[\s\S]*)?$/,
	);
	if (catGrep && catGrep[4].includes("o") && !catGrep[4].includes("n") && !catGrep[4].includes("A")) {
		const cdPrefix = catGrep[1] || "";
		const echoPrefix = catGrep[2] || "";
		const files = catGrep[3].trim();
		const flg = catGrep[4];
		const rawPatTok = catGrep[5];
		const pipeSuffix = catGrep[6] || "";
		if (files && !files.startsWith("-")) {
			const q = rawPatTok[0];
			const inner = rawPatTok.slice(1, -1);
			const canTranslate = flg.includes("E") || q === "'" || !/\\[|(){}+?]/.test(inner);
			if (canTranslate) {
				const outPatTok = flg.includes("E") ? rawPatTok : `${q}${translateGrepBreToRustRegex(inner, "")}${q}`;
				const ic = flg.includes("i") ? " -i" : "";
				return `${cdPrefix}${echoPrefix}rg -a --no-ignore -o --no-filename${ic} ${outPatTok} ${files}${pipeSuffix}`;
			}
		}
	}

	// Fast-path A4: multi-file `grep -ohE <pat> <2+ targets>` -> `rg -a --no-ignore -o`
	const multiGrep = cleaned.match(
		/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?grep\s+-([ohEia]+)\s+('[^']+'|"[^"]+"|(?!-)\S+)\s+([^\s|;&]+\s+[^\s|;&]+(?:\s+[^\s|;&]+)*)(\s*\|\s*(?:head|tail|wc|sort|cut)\b[^;&|>]*)?$/,
	);
	if (multiGrep && !/[rR]/.test(multiGrep[2]) && multiGrep[2].includes("o")) {
		const cdPrefix = multiGrep[1] || "";
		const flg = multiGrep[2];
		const rawPatTok = multiGrep[3];
		const isSingleQ = rawPatTok.startsWith("'") && rawPatTok.endsWith("'");
		const isDoubleQ = rawPatTok.startsWith('"') && rawPatTok.endsWith('"');
		const inner = isSingleQ || isDoubleQ ? rawPatTok.slice(1, -1) : rawPatTok;
		const canTranslate = flg.includes("E") || !isDoubleQ || !/\\[|(){}+?]/.test(inner);
		if (canTranslate) {
			const outPatTok = flg.includes("E")
				? rawPatTok
				: isSingleQ
					? `'${translateGrepBreToRustRegex(inner, "")}'`
					: isDoubleQ
						? `"${translateGrepBreToRustRegex(inner, "")}"`
						: translateGrepBreToRustRegex(inner, "");
			const noFile = flg.includes("h") ? " --no-filename" : "";
			const ic = flg.includes("i") ? " -i" : "";
			return `${cdPrefix}rg -a --no-ignore -o${noFile}${ic} ${outPatTok} ${multiGrep[4].trim()}${multiGrep[5] || ""}`;
		}
	}

	// Collect one or more `--include=*.ext` / `--include=<glob>` flags anywhere in the grep command
	const exts: string[] = [];
	const extraIncludes: string[] = [];
	const globs: string[] = [];
	const withoutIncludes = cleaned.replace(
		/\s+--include=(?:'([^']+)'|"([^"]+)"|([^\s|&;]+))/g,
		(_m, g1: string, g2: string, g3: string) => {
			const glob = g1 || g2 || g3 || "";
			const em = glob.match(/^\*\.([A-Za-z0-9]+)$/);
			if (em) exts.push(em[1]);
			else if (glob) extraIncludes.push(glob);
			if (glob) globs.push(`-g '${glob}'`);
			return "";
		},
	);

	// Trailing `-l` / `-c`, multi-target, AppData, arbitrary-pipe, or backtick-safe recursive grep -> fast bounded `rg`
	const complexRec = withoutIncludes.match(
		/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?grep\s+((?:-[aArRniEHhlcIFso]+\s+)+)(?:'([^']+)'|"((?:[^"\\]|\\.)+)"|((?!-)[^\s'"|;&]+))([\s\S]*?)((?:\s*\|[^;&<>]+)+)?$/,
	);
	if (complexRec && /[rR]/.test(complexRec[2])) {
		const cdPrefix = complexRec[1] || "";
		const rawFlags = complexRec[2];
		const patRaw =
			complexRec[3] !== undefined
				? `'${complexRec[3]}'`
				: complexRec[4] !== undefined
					? `"${complexRec[4]}"`
					: complexRec[5];
		const restArgs = (complexRec[6] || "").trim();
		const pipeSuffix = complexRec[7] || "";
		const hasBacktickPat = complexRec[3]?.includes("`") || complexRec[4]?.includes("`");
		const restUnquoted = restArgs.replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, "");
		const hasCompoundOps = /[;&<>`]|\$\(/.test(restUnquoted);
		const hasTrailingFlag = /(?:^|\s)-[lch](?:\s|$)/.test(restArgs);
		const isAppData = /AppData[/\\]Roaming/i.test(restArgs);
		const multiTarget = restArgs.split(/\s+/).filter(Boolean).length > 1;
		const hasArbitraryPipe =
			Boolean(pipeSuffix) &&
			!/^(?:\s*\|\s*(?:head|tail|wc|sort|uniq|cut|tr)\b[^;&|<>]*)+$/.test(pipeSuffix);
		if (!hasCompoundOps && (hasBacktickPat || hasTrailingFlag || isAppData || multiTarget || hasArbitraryPipe)) {
			const rFlags = [
				/[a]/.test(rawFlags) ? "-a" : "",
				/[n]/.test(rawFlags) ? "-n --no-heading" : "",
				/[l]/.test(rawFlags) ? "-l" : "",
				/[c]/.test(rawFlags) ? "-c" : "",
				/[o]/.test(rawFlags) ? "-o" : "",
				/[h]/.test(rawFlags) ? "--no-filename" : "",
				/[w]/.test(rawFlags) ? "-w" : "",
				/[i]/.test(rawFlags) ? "-i" : "",
				/[F]/.test(rawFlags) ? "-F" : "",
				isAppData ? "--max-depth 4" : "--max-depth 8",
				"-g '!node_modules'",
				"-g '!target'",
				...globs,
			]
				.filter(Boolean)
				.join(" ");
			const tgtStr = restArgs || ".";
			return `${cdPrefix}rg ${rFlags} ${patRaw} ${tgtStr}${pipeSuffix}`;
		}
	}

	const m = withoutIncludes.match(
		/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?\s*grep\s+((?:-[aArRniEHhlcIFso]+\s+)+)(?:-e\s+)?(?:'([^']+)'|"((?:[^"\\]|\\.)+)"|((?!-)[^\s'"|;&]+))(?:\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+)))?((?:\s*\|\s*(?:head|tail|wc|sort|uniq|cut|tr)\b[^;&|<>]*)+)?\s*$/,
	);
	if (m) {
		const flags = m[2].replace(/[\s-]+/g, "");
		const cdPrefix = m[1] || "";
		const rawPat = m[3] || (m[4] ? m[4].replace(/\\"/g, '"') : "") || m[5] || "";
		const target = m[6] || m[7] || m[8] || ".";
		const hasConcreteTarget =
			Boolean(m[6] || m[7] || m[8]) &&
			target !== "-" &&
			(Boolean(m[6] || m[7]) ? !/[*?,]/.test(target) : !/[*?,\s]/.test(target));
		if (rawPat && (/[rR]/.test(flags) || (hasConcreteTarget && flags.includes("n") && !m[9]))) {
			const rustPat = translateGrepBreToRustRegex(rawPat, flags);
			const pipeSuffix = m[9] || "";
			const extFlag = exts.length > 0 ? ` -e ${[...new Set(exts)].join(",")}` : "";
			const incFlags = extraIncludes.map((inc) => ` --include "${inc.replace(/"/g, '\\"')}"`).join("");
			const prefix = toolName === "powershell" ? "& " : "";
			const quotedPat = toolName === "bash" ? shellQuoteBashPat(rustPat) : `"${rustPat.replace(/"/g, '\\"')}"`;
			const extra = [
				flags.includes("l") ? " -l" : flags.includes("c") ? " -c" : "",
				flags.includes("o") ? " -o" : "",
				flags.includes("i") ? " -i" : "",
				flags.includes("F") ? " -F" : "",
				flags.includes("h") ? " --no-filename" : "",
			].join("");
			return `${cdPrefix}${prefix}"${AP_BIN}" search${extra}${extFlag}${incFlags} ${quotedPat} "${target}"${pipeSuffix}`;
		}
	}

	// Generalized standalone grep with -A/-B/-C context flags anywhere, BRE `\|`, or single-file grep
	const stdGrepM = withoutIncludes.match(
		/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?grep\s+([\s\S]+?)((?:\s*\|\s*(?:head|tail|wc|sort|uniq|cut|tr)\b[^;&|<>]*)+)?\s*$/,
	);
	if (stdGrepM && !/[;&><{}`]|\$\(/.test((stdGrepM[2] || "").replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, ""))) {
		const cdPrefix = stdGrepM[1] || "";
		const pipeSuffix = stdGrepM[3] || "";
		const toks = ((stdGrepM[2] || "").match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) || []).map((t) =>
			(t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))
				? t.slice(1, -1).replace(/\\"/g, '"')
				: t,
		);
		let rec = false;
		let lineNum = false;
		let ignoreCase = false;
		let fixed = false;
		let extRe = false;
		let filesOnly = false;
		let countOnly = false;
		let onlyMatch = false;
		let noFilename = false;
		let ctxA = 0;
		let ctxB = 0;
		let ctxC = 0;
		let ok = true;
		let endOpts = false;
		const pos: string[] = [];
		for (let i = 0; i < toks.length; i++) {
			const tok = toks[i];
			if (!endOpts && tok === "--") { endOpts = true; continue; }
			if (!endOpts && (tok === "-A" || tok === "-B" || tok === "-C")) {
				const num = Number(toks[++i]);
				if (!Number.isInteger(num) || num < 0) { ok = false; break; }
				if (tok === "-A") ctxA = num;
				else if (tok === "-B") ctxB = num;
				else ctxC = num;
				continue;
			}
			if (!endOpts && /^-[ABC]\d+$/.test(tok)) {
				const num = Number(tok.slice(2));
				if (tok[1] === "A") ctxA = num;
				else if (tok[1] === "B") ctxB = num;
				else ctxC = num;
				continue;
			}
			if (!endOpts && tok === "-e") {
				if (i + 1 >= toks.length) { ok = false; break; }
				pos.unshift(toks[++i]);
				continue;
			}
			if (!endOpts && tok.startsWith("-") && tok.length > 1) {
				if (tok.startsWith("--")) { ok = false; break; }
				for (const ch of tok.slice(1)) {
					if (ch === "r" || ch === "R") rec = true;
					else if (ch === "n") lineNum = true;
					else if (ch === "i") ignoreCase = true;
					else if (ch === "F") fixed = true;
					else if (ch === "E") extRe = true;
					else if (ch === "l") filesOnly = true;
					else if (ch === "c") countOnly = true;
					else if (ch === "o") onlyMatch = true;
					else if (ch === "h") noFilename = true;
					else if (ch === "H" || ch === "s" || ch === "a" || ch === "I") continue;
					else { ok = false; break; }
				}
				if (!ok) break;
				continue;
			}
			pos.push(tok);
		}
		if (ok && pos.length >= 1 && pos.length <= 2) {
			const rawPat = pos[0];
			const target = pos[1] || ".";
			const concreteSingleFile = pos.length === 2 && target !== "-" && !/[*?,]/.test(target);
			if (rawPat && (rec || (!pipeSuffix && concreteSingleFile && (lineNum || ctxA > 0 || ctxB > 0 || ctxC > 0 || rawPat.includes("\\|"))))) {
				const flagsStr = `${extRe ? "E" : ""}${fixed ? "F" : ""}`;
				const rustPat = translateGrepBreToRustRegex(rawPat, flagsStr);
				const prefix = toolName === "powershell" ? "& " : "";
				const quotedPat = toolName === "bash" ? shellQuoteBashPat(rustPat) : `"${rustPat.replace(/"/g, '\\"')}"`;
				const extra = [
					filesOnly ? " -l" : countOnly ? " -c" : "",
					onlyMatch ? " -o" : "",
					ignoreCase ? " -i" : "",
					fixed ? " -F" : "",
					noFilename ? " --no-filename" : "",
					ctxC > 0 ? ` -C ${ctxC}` : "",
					ctxB > 0 ? ` -B ${ctxB}` : "",
					ctxA > 0 ? ` -A ${ctxA}` : "",
					exts.length > 0 ? ` -e ${[...new Set(exts)].join(",")}` : "",
					...extraIncludes.map((inc) => ` --include "${inc.replace(/"/g, '\\"')}"`),
				].join("");
				return `${cdPrefix}${prefix}"${AP_BIN}" search${extra} ${quotedPat} "${target}"${pipeSuffix}`;
			}
		}
	}

	// Windows `findstr [/i] [/s] [/n] [/c:pat | pat] target` -> `ap search`
	if (toolName === "bash" && /\bfindstr\b/i.test(cleaned)) {
		const fsM = cleaned.match(
			/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?findstr\s+([\s\S]+?)((?:\s*\|\s*(?:head|tail|wc|sort)\b[^;&|<>]*)+)?\s*$/i,
		);
		if (fsM && !/[;&><{}`]|\$\(/.test((fsM[2] || "").replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, ""))) {
			const toks = ((fsM[2] || "").match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) || []).map((t) =>
				(t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")) ? t.slice(1, -1) : t,
			);
			let ignoreCase = false;
			let fixed = false;
			let recursive = false;
			let explicitPat = "";
			const pos: string[] = [];
			let fsOk = true;
			for (const tok of toks) {
				const low = tok.toLowerCase();
				if (low.startsWith("/c:")) {
					explicitPat = tok.slice(3).replace(/^(['"])(.*)\1$/, "$2");
					fixed = true;
				} else if (low === "/i") ignoreCase = true;
				else if (low === "/s") recursive = true;
				else if (low === "/l") fixed = true;
				else if (low === "/n" || low === "/p" || low === "/r") continue;
				else if (tok.startsWith("/")) { fsOk = false; break; }
				else pos.push(tok);
			}
			if (fsOk) {
				const pat = explicitPat || pos[0] || "";
				const tgt = explicitPat ? (pos[0] || "") : (pos[1] || "");
				if (pat && (tgt || recursive)) {
					const rawTgt = tgt || ".";
					const extM = rawTgt.match(/^\*\.([A-Za-z0-9_]+)$/);
					const actualTgt = extM ? "." : rawTgt;
					if (!/[*?,\s]/.test(actualTgt) && actualTgt !== "-") {
						const extFlag = extM ? ` -e ${extM[1]}` : "";
						const flags = `${ignoreCase ? " -i" : ""}${fixed ? " -F" : ""}${extFlag}`;
						return `${fsM[1] || ""}"${AP_BIN}" search${flags} ${shellQuoteBashPat(pat)} "${actualTgt}"${fsM[3] || ""}`;
					}
				}
			}
		}
	}

	return undefined;
}

/**
 * Guard ephemeral background local HTTP/mock/proxy servers with a bounded 900s TTL so aborted/orphaned
 * test runs never leave background Python/Node listeners bound on ports indefinitely.
 * Strictly targets ONLY the trailing backgrounded server segment (never wraps shell builtins like `cd`/`echo`).
 */
export function guardEphemeralServerCommand(cmd: string): string | undefined {
	if (!cmd) return undefined;
	const trimmed = cmd.trim();
	if (!/(?<![&>])&\s*$/.test(trimmed)) return undefined;
	// Find the end of the last unquoted top-level compound separator (`&&`, `||`, `;`, `\n`)
	let lastSepEnd = 0;
	let quote: string | null = null;
	let parenDepth = 0;
	let braceDepth = 0;
	for (let i = 0; i < trimmed.length; i++) {
		const ch = trimmed[i];
		if (quote) {
			if (ch === "\\" && quote === '"' && i + 1 < trimmed.length) {
				i++;
				continue;
			}
			if (ch === quote) quote = null;
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
		} else if (ch === "(") {
			parenDepth++;
		} else if (ch === ")" && parenDepth > 0) {
			parenDepth--;
		} else if (ch === "{") {
			braceDepth++;
		} else if (ch === "}" && braceDepth > 0) {
			braceDepth--;
		} else if (parenDepth === 0 && braceDepth === 0) {
			if ((ch === "&" && trimmed[i + 1] === "&") || (ch === "|" && trimmed[i + 1] === "|")) {
				lastSepEnd = i + 2;
				i++;
			} else if (ch === ";" || ch === "\n") {
				lastSepEnd = i + 1;
			}
		}
	}
	const prefix = trimmed.slice(0, lastSepEnd);
	const rawTail = trimmed.slice(lastSepEnd);
	const leadWs = rawTail.match(/^\s*/)?.[0] ?? "";
	const tail = rawTail.slice(leadWs.length);
	if (!tail || /\btimeout\s+\d+/.test(tail)) return undefined;
	// Preserve leading inline env assignments (e.g. `FOO=1 python -m http.server 8000 &`)
	// so external `timeout` never tries to exec `FOO=1` as a command name.
	const envLeadM = tail.match(/^(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"\\]*(?:\\.[^"\\]*)*"|[^\s;&|]*)\s+)+/);
	const envLead = envLeadM ? envLeadM[0] : "";
	const execTail = tail.slice(envLead.length);
	if (!execTail) return undefined;
	// Never place external `timeout` before shell builtins, subshells, or compound blocks
	if (/^(?:cd|export|unset|echo|printf|set|eval|exec|if|for|while|until|case|\(|\{)\b|^[\(\{]/i.test(execTail)) {
		return undefined;
	}
	const isHttpOrProbeServer =
		/(?:python3?(?:\.exe)?\s+-m\s+http\.server\b|\bhttp\.server\b|\bap(?:\.exe)?\s+probe\s+listen\b)/.test(execTail);
	const isNohupScriptServer =
		/^nohup\s+(?:env\s+(?:\w+=\S+\s+)*)?(?:python3?|py|node)(?:\.exe)?\b/i.test(execTail);
	if (!isHttpOrProbeServer && !isNohupScriptServer) return undefined;
	if (/^nohup\s+/i.test(execTail)) {
		return `${prefix}${leadWs}${envLead}${execTail.replace(/^nohup\s+/i, "nohup timeout 900 ")}`;
	}
	return `${prefix}${leadWs}${envLead}timeout 900 ${execTail}`;
}

/**
 * Hint structured reads (`ap read --outline` / `--section`) when opening giant Markdown/text files.
 */
export function classifyOversizedDocRead(filePath: string, byteLen: number): string | undefined {
	if (!filePath || byteLen < 10_000) return undefined;
	const norm = filePath.trim().replace(/\\/g, "/").toLowerCase();
	if (!/\.(?:md|txt|log)$/.test(norm) || /(?:^|\/)readme\.md$/.test(norm)) return undefined;
	return `[ap read-tip] Large doc (${byteLen} chars) — use \`ap read "${filePath}" --outline\` or \`--section "<heading>"\` for ~90% fewer tokens.`;
}

/**
 * Lossless auto-sieve trigger for unbounded giant `read` responses (offset/limit both unset).
 * Windowed `read(offset, limit)` calls ALWAYS return false so exact edit lines are never altered.
 */
export function shouldAutoSieveUnboundedRead(
	outText: string,
	input: unknown,
	isFastModel = false,
	hardLimitOverride?: number,
	contextTokens?: number,
): boolean {
	if (!outText || outText.includes("[sieve id=")) return false;
	const rec = input && typeof input === "object" ? (input as { path?: unknown; offset?: unknown; limit?: unknown }) : undefined;
	const readPath = typeof rec?.path === "string" ? rec.path.trim() : "";
	if (/(?:^|[\\/])(?:SKILL|AGENTS|AGENTS\.override)\.md$/i.test(readPath) && outText.length <= 32_768) {
		return false;
	}
	if ((rec?.offset !== undefined && rec?.offset !== null) || (rec?.limit !== undefined && rec?.limit !== null)) {
		return outText.length >= 32_000 && outText.split("\n").some((l) => l.length > SIEVE_GIANT_LINE_CHARS);
	}
	let thr =
		hardLimitOverride && hardLimitOverride > 0
			? Math.max(hardLimitOverride, 12_000)
			: isFastModel
				? SIEVE_STRUCTURED_CHARS
				: 24_000;
	if (typeof contextTokens === "number" && contextTokens > 0) {
		if (contextTokens < 60_000) {
			thr = Math.max(thr, 24_000);
		} else if (contextTokens >= 120_000) {
			thr = Math.min(thr, 10_000);
		} else if (contextTokens >= 80_000) {
			thr = Math.min(thr, 14_000);
		}
	}
	return outText.length >= thr;
}

/**
 * Guard unguarded standalone Bash `curl` HTTP probes with `--max-time 30` so slow endpoints fail fast
 * instead of hanging into DeepSeek's KV-cache eviction window or stalling turns.
 */
export function guardUnboundedCurlTimeout(cmd: string): string | undefined {
	if (!cmd || /<<|(?:^|[\s;&|(=])(?:python3?|py|node)(?:\.exe)?(?=\s|$|[;&|)])/i.test(cmd)) return undefined;
	if (!/(?:^|[;&|]\s*)curl(?:\.exe)?\s+/.test(cmd)) return undefined;
	if (/\s(?:-m|--max-time|--connect-timeout)\b/.test(cmd)) return undefined;
	const next = cmd.replace(/(^|[;&|]\s*)(curl(?:\.exe)?)(?=\s)/g, "$1$2 --max-time 30");
	return next !== cmd ? next : undefined;
}

/**
 * Strip explicit top-level `null` optional fields so strict tool schemas (e.g. read, mcp_*)
 * never reject DeepSeek or other models sending `{ offset: null, limit: null }`.
 */
export function stripNullOptionalArgs(input: unknown): boolean {
	if (!input || typeof input !== "object" || Array.isArray(input)) return false;
	const rec = input as Record<string, unknown>;
	let stripped = false;
	for (const k of Object.keys(rec)) {
		if (rec[k] === null) {
			delete rec[k];
			stripped = true;
		}
	}
	return stripped;
}

/**
 * Track consecutive read-only single bash probes and nudge toward batched `codemode` (`Promise.allSettled`).
 */
export function trackReadOnlyBashStreak(
	currentStreak: number,
	cmd: string,
	isDestructive: boolean,
): { nextStreak: number; shouldTip: boolean } {
	if (!cmd || isDestructive) return { nextStreak: 0, shouldTip: false };
	const clean = cmd.replace(LEADING_SHELL_PREFIX_RE, "").trim();
	const isReadOnlyProbe =
		/^(?:ls|dir|cat|head|tail|grep|egrep|fgrep|rg|find|sed|awk|wc|stat|file|strings|python3?|node)\b/i.test(clean);
	if (!isReadOnlyProbe) return { nextStreak: 0, shouldTip: false };
	const nextStreak = currentStreak + 1;
	if (nextStreak >= 4 && nextStreak % 4 === 0) {
		return { nextStreak, shouldTip: true };
	}
	return { nextStreak, shouldTip: false };
}

export function healBashPowerShellCommand(cmd: string): string | undefined {
	if (!/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(cmd) || /-EncodedCommand\b|-enc\b/i.test(cmd)) {
		return undefined;
	}
	const hereM = cmd.match(
		/^([\s\S]*?\b(?:powershell|pwsh)(?:\.exe)?\b[^|;&"'\r\n]*?\s-(?:Command|c)\s+)@(['"])\r?\n([\s\S]*?)\r?\n\2@([ \t]*(?:2>&1)?(?:[ \t]*\|[^\r\n]*)?)\s*$/i,
	);
	if (hereM) {
		const head = hereM[1];
		const body = hereM[3];
		const tail = hereM[4] || "";
		const hasUtf8 = /OutputEncoding|UTF8Encoding/i.test(body);
		const utf8Line = hasUtf8 ? "" : "[Console]::OutputEncoding=[Text.Encoding]::UTF8\n";
		let delim = "AP_PS_HEREDOC";
		while (body.includes(delim)) delim += "_X";
		return `${head}- <<'${delim}'${tail}\n${utf8Line}${body}\n${delim}`;
	}
	const psHeadRe = /\b((?:powershell|pwsh)(?:\.exe)?\b[^|;&"']*?\s-(?:Command|c)\s+)"/gi;
	let out = "";
	let cursor = 0;
	let matchedAny = false;
	while (true) {
		psHeadRe.lastIndex = cursor;
		const hm = psHeadRe.exec(cmd);
		if (!hm) break;
		const prefixStart = hm.index;
		const bodyStart = prefixStart + hm[0].length;
		let bodyEnd = -1;
		for (let i = bodyStart; i < cmd.length; i++) {
			const ch = cmd[i];
			if (ch === "\\" && i + 1 < cmd.length && (cmd[i + 1] === '"' || cmd[i + 1] === "\\")) {
				i += 1;
				continue;
			}
			if (ch === '"') {
				bodyEnd = i;
				break;
			}
		}
		if (bodyEnd <= bodyStart) break;
		matchedAny = true;
		out += cmd.slice(cursor, prefixStart) + hm[1];
		let inner = cmd.slice(bodyStart, bodyEnd);
		const innerTimed =
			/\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i.test(inner) && !/\s-TimeoutSec\b/i.test(inner)
				? inner.replace(/(^|[;&|(\s])(Invoke-WebRequest|Invoke-RestMethod)(?=\s)/gi, "$1$2 -TimeoutSec 25")
				: inner;
		const hasUtf8 = /OutputEncoding|UTF8Encoding/i.test(innerTimed);
		const utf8Prefix = hasUtf8 ? "" : "[Console]::OutputEncoding=[Text.Encoding]::UTF8; ";
		const hasPsVar = /\$(?:_|PSItem\b|env:|null\b|true\b|false\b|[A-Za-z_]\w*|\?|\()/i.test(innerTimed);
		const hasPsBacktick = /(?<!\\)`/.test(innerTimed);
		if (!innerTimed.includes("'") && !/\$\(/.test(innerTimed) && (hasPsVar || hasPsBacktick)) {
			const sqInner = innerTimed.replace(/\\"/g, '"').replace(/\\\$/g, "$").replace(/\\`/g, "`");
			out += `'${utf8Prefix}${sqInner}'`;
		} else if (hasPsVar || hasPsBacktick || !hasUtf8) {
			const innerEsc = innerTimed
				.replace(/(?<!\\)\$(?=[A-Za-z_?(])/g, "\\$")
				.replace(/(?<!\\)`/g, "\\`");
			out += `"${utf8Prefix}${innerEsc}"`;
		} else {
			out += `"${innerTimed}"`;
		}
		cursor = bodyEnd + 1;
	}
	if (matchedAny) {
		out += cmd.slice(cursor);
		return out !== cmd ? out : undefined;
	}
	if (!/OutputEncoding|UTF8Encoding/i.test(cmd)) {
		const psFixed = cmd.replace(
			/\b((?:powershell|pwsh)(?:\.exe)?\b[^|;&]*?\s-(?:Command|c)\s+)(['"])/gi,
			"$1$2[Console]::OutputEncoding=[Text.Encoding]::UTF8; ",
		);
		if (psFixed !== cmd) return psFixed;
		// Lock UTF-8 output encoding on `powershell ... -File <script.ps1> [args...]` while preserving
		// script arguments, `$LASTEXITCODE`, non-terminating/terminating failure status, and trailing pipes/redirects.
		const psFileRe = /\b((?:powershell|pwsh)(?:\.exe)?\b[^|;&"'\r\n]*?)\s+-File\s+/gi;
		let fileOut = "";
		let fileCur = 0;
		let fileChanged = false;
		while (true) {
			psFileRe.lastIndex = fileCur;
			const fm = psFileRe.exec(cmd);
			if (!fm) break;
			const segStart = fm.index + fm[0].length;
			let segEnd = segStart;
			let q: string | null = null;
			while (segEnd < cmd.length) {
				const ch = cmd[segEnd];
				if (q) {
					if (ch === "\\" && q === '"' && segEnd + 1 < cmd.length) {
						segEnd += 2;
						continue;
					}
					if (ch === q) q = null;
					segEnd++;
					continue;
				}
				if (ch === "'" || ch === '"') {
					q = ch;
					segEnd++;
					continue;
				}
				if (
					ch === "|" ||
					ch === ";" ||
					ch === "&" ||
					ch === ">" ||
					ch === "<" ||
					ch === "\n" ||
					ch === "\r"
				) {
					break;
				}
				// Stop before `2>&1` / `1>&2` / `2>file`
				if (
					(ch === "1" || ch === "2") &&
					cmd[segEnd + 1] === ">" &&
					(segEnd === segStart || /\s/.test(cmd[segEnd - 1]))
				) {
					break;
				}
				segEnd++;
			}
			const rawTail = cmd.slice(segStart, segEnd);
			const trailWs = rawTail.match(/\s*$/)?.[0] ?? "";
			const argSpan = rawTail.slice(0, rawTail.length - trailWs.length).trim();
			if (!argSpan || argSpan === "-") {
				fileCur = segEnd;
				continue;
			}
			// Extract script token + optional args
			const tokM = argSpan.match(/^('[^']+'|"[^"\\]*(?:\\.[^"\\]*)*"|\S+)([\s\S]*)$/);
			if (!tokM) {
				fileCur = segEnd;
				continue;
			}
			const rawScriptTok = tokM[1];
			const restArgs = tokM[2] || "";
			// Bail out cleanly when bash-escaped metachars (`\$`, `` \` ``, `\"`) or single-quoted `$`/backticks cannot round-trip losslessly
			if (/'[^']*[$`][^']*'/.test(argSpan) || /\\[$`"]/.test(argSpan)) {
				fileCur = segEnd;
				continue;
			}
			const quoteChar =
				rawScriptTok.startsWith('"') && rawScriptTok.endsWith('"')
					? '"'
					: rawScriptTok.startsWith("'") && rawScriptTok.endsWith("'")
						? "'"
						: "";
			let innerPath = quoteChar ? rawScriptTok.slice(1, -1) : rawScriptTok;
			// Normalize MSYS2 `/c/...` or `/tmp/...` paths because MSYS2 does not translate paths embedded inside `-Command`
			const normMsysScript = normalizeWindowsToolPath(innerPath, true);
			if (normMsysScript) {
				innerPath = normMsysScript;
			}
			// PowerShell `& "probe.ps1"` refuses bare filenames in CWD without `./` or `.\` (unlike `-File`)
			if (innerPath && !/[\\/:$]/.test(innerPath)) {
				innerPath = `./${innerPath}`;
			}
			const scriptTok = quoteChar ? `${quoteChar}${innerPath}${quoteChar}` : `"${innerPath}"`;
			const psCall = `${scriptTok}${restArgs}`;
			const needsBashExpand = /[$`]/.test(psCall) || psCall.includes("'");
			const wrappedCmd = needsBashExpand
				? `"[Console]::OutputEncoding=[Text.Encoding]::UTF8; \\$OutputEncoding=[Text.Encoding]::UTF8; & ${psCall.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}; if (\\$LASTEXITCODE) { exit \\$LASTEXITCODE } elseif (-not \\$?) { exit 1 }"`
				: `'[Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Text.Encoding]::UTF8; & ${psCall}; if ($LASTEXITCODE) { exit $LASTEXITCODE } elseif (-not $?) { exit 1 }'`;
			fileOut += `${cmd.slice(fileCur, fm.index)}${fm[1]} -Command ${wrappedCmd}${trailWs}`;
			fileCur = segEnd;
			fileChanged = true;
		}
		if (fileChanged) {
			fileOut += cmd.slice(fileCur);
			return fileOut !== cmd ? fileOut : undefined;
		}
	}
	return undefined;
}

export function clampKvSafeSleep(cmd: string, toolName: string, maxSec = 45): string | undefined {
	if (
		!cmd ||
		/\bnohup\b|<<|(?:^|[\s;&|(=])(?:python3?|py|node)(?:\.exe)?(?=\s|$|[;&|)])/i.test(cmd) ||
		/&\s*$/.test(cmd.trim()) ||
		/\(\s*[^)]*\bsleep\b[^)]*\)\s*&/i.test(cmd)
	) {
		return undefined;
	}
	if (toolName === "bash") {
		let next = cmd.replace(
			/(^|[;&|]\s*)sleep\s+(\d+(?:\.\d+)?)s?(?=\s*(?:$|[;&|]))/gi,
			(m, pfx: string, secsStr: string) => (Number(secsStr) >= 60 ? `${pfx}sleep ${maxSec}` : m),
		);
		next = next.replace(
			/\b(for\s+\w+\s+in\s+(?:\$\(\s*seq\s+(?:(\d+)\s+)?(\d+)\s*\)|([^\r\n;]+));\s*do\b)([\s\S]*?)(\bdone\b)/gi,
			(loopMatch, head: string, seqStart: string | undefined, seqEnd: string | undefined, wordList: string | undefined, body: string, tail: string) => {
				let iters = 0;
				if (seqEnd) {
					const startN = seqStart ? Number(seqStart) : 1;
					const endN = Number(seqEnd);
					iters = endN >= startN ? endN - startN + 1 : 0;
				} else if (wordList) {
					const words = wordList.trim().split(/\s+/).filter(Boolean);
					if (words.length >= 3) iters = words.length;
				}
				if (iters < 3) return loopMatch;
				let loopChanged = false;
				const clampedBody = body.replace(
					/(^|[;&|\s])sleep\s+(\d+(?:\.\d+)?)s?(?=\s*(?:$|[;&|]))/gi,
					(sm, spfx: string, sStr: string) => {
						const sNum = Number(sStr);
						if (sNum > 0 && iters * sNum >= 90) {
							const perIter = Math.max(2, Math.floor(maxSec / iters));
							if (perIter < sNum) {
								loopChanged = true;
								return `${spfx}sleep ${perIter}`;
							}
						}
						return sm;
					},
				);
				return loopChanged ? `${head}${clampedBody}${tail}` : loopMatch;
			},
		);
		return next !== cmd ? next : undefined;
	}
	if (toolName === "powershell") {
		const next = cmd.replace(
			/(^|[;&|]\s*)Start-Sleep(?:\s+-s(?:ec(?:ond)?s?)?)?\s+(\d+(?:\.\d+)?)(?=\s*(?:$|[;&|]))/gi,
			(m, pfx: string, secsStr: string) => (Number(secsStr) >= 60 ? `${pfx}Start-Sleep -Seconds ${maxSec}` : m),
		);
		return next !== cmd ? next : undefined;
	}
	return undefined;
}

const WIN_SYSTEM32_WHOAMI = "C:/Windows/System32/whoami.exe";
const MSYS_WIN_CLI_RE = /(?:^|[;&|]\s*)(?:(?:[A-Za-z]:[/\\]|\/[a-zA-Z]\/)?(?:Windows[/\\]System32[/\\])?whoami(?:\.exe)?|cmd(?:\.exe)?|findstr(?:\.exe)?|taskkill(?:\.exe)?|tasklist(?:\.exe)?|sc(?:\.exe)?|icacls(?:\.exe)?|reg(?:\.exe)?|netstat(?:\.exe)?|schtasks(?:\.exe)?|wevtutil(?:\.exe)?|netsh(?:\.exe)?|where(?:\.exe)?|wmic(?:\.exe)?|certutil(?:\.exe)?|bcdedit(?:\.exe)?|secedit(?:\.exe)?)\b[^\r\n;&|]*?\s\/[A-Za-z?]/i;
const MSYS_OPENSSL_SUBJ_RE = /\bopenssl\b[^\r\n;&|]*?\s-subj\s+['"]?\//i;

function stripQuotedShellContents(raw: string): string {
	let out = "";
	let q: "'" | '"' | null = null;
	for (let i = 0; i < raw.length; i++) {
		const ch = raw[i];
		if (q) {
			if (ch === "\\" && q === '"' && i + 1 < raw.length) {
				i++;
				continue;
			}
			if (ch === q) {
				out += q;
				q = null;
			}
			continue;
		}
		if (ch === "'" || ch === '"') {
			q = ch;
			out += ch;
			continue;
		}
		out += ch;
	}
	return out;
}

/**
 * Rewrite non-path-qualified `whoami` / `whoami.exe` followed by a Windows `/flag` strictly outside
 * quoted strings to `C:/Windows/System32/whoami.exe`, avoiding Git Bash's `/usr/bin/whoami.exe` PATH collision.
 */
function rewriteUnqualifiedWhoamiFlag(raw: string): { text: string; changed: boolean } {
	let out = "";
	let changed = false;
	let q: "'" | '"' | null = null;
	let atCmdPos = true;
	let i = 0;
	while (i < raw.length) {
		const ch = raw[i];
		if (q) {
			out += ch;
			if (ch === "\\" && q === '"' && i + 1 < raw.length) {
				out += raw[++i];
			} else if (ch === q) {
				q = null;
			}
			i++;
			continue;
		}
		if (ch === "'" || ch === '"') {
			q = ch;
			out += ch;
			atCmdPos = false;
			i++;
			continue;
		}
		if (ch === ";" || ch === "&" || ch === "|" || ch === "(" || ch === "\n" || ch === "\r") {
			out += ch;
			atCmdPos = true;
			i++;
			continue;
		}
		if (atCmdPos) {
			if (ch === " " || ch === "\t") {
				out += ch;
				i++;
				continue;
			}
			const tail = raw.slice(i);
			// Skip leading inline env assignment (`FOO=bar `) or shell keyword (`then `, `do `, `else `, `elif `, `! `)
			const envM = tail.match(/^[A-Za-z_]\w*=(?:"(?:\\.|[^"\\])*"|'[^']*'|\S+)[ \t]+/);
			if (envM) {
				out += envM[0];
				i += envM[0].length;
				continue;
			}
			const kwM = tail.match(/^(?:then|do|else|elif|!)(?=[ \t]+)[ \t]+/);
			if (kwM) {
				out += kwM[0];
				i += kwM[0].length;
				continue;
			}
			const whM = tail.match(/^whoami(?:\.exe)?(?=[ \t]+\/[A-Za-z?])/i);
			if (whM) {
				out += WIN_SYSTEM32_WHOAMI;
				i += whM[0].length;
				changed = true;
				atCmdPos = false;
				continue;
			}
			atCmdPos = false;
		}
		if (ch === "\\" && i + 1 < raw.length) {
			out += ch + raw[++i];
			i++;
			continue;
		}
		out += ch;
		i++;
	}
	return { text: out, changed };
}

export function normalizeWindowsToolPath(rawPath: string, isWin = process.platform === "win32"): string | undefined {
	if (!rawPath || !isWin) return undefined;
	const p = rawPath.trim();
	if (/^\/tmp(?:\/|$)/.test(p)) {
		const winTmp = tmpdir().replace(/\\/g, "/").replace(/\/+$/, "");
		return p === "/tmp" ? winTmp : `${winTmp}${p.slice(4)}`;
	}
	const m = p.match(/^\/([a-zA-Z])(?:\/(.*))?$/);
	if (m) {
		const drv = m[1].toUpperCase();
		const rest = m[2] ?? "";
		return `${drv}:/${rest}`;
	}
	return undefined;
}

export function healMsysPathConv(raw: string, toolName = "bash"): string | undefined {
	if (!raw || toolName !== "bash") return undefined;
	const hasMsysEnv = /\b(?:MSYS_NO_PATHCONV|MSYS2_ARG_CONV_EXCL)=/.test(raw);
	const whoamiRewrite = rewriteUnqualifiedWhoamiFlag(raw);
	const hasUnqualifiedWhoamiFlag = whoamiRewrite.changed;
	if (hasMsysEnv && !hasUnqualifiedWhoamiFlag) return undefined;
	const unquoted = stripQuotedShellContents(raw);
	if (!hasUnqualifiedWhoamiFlag && /(?:^|\s)\/\/[A-Za-z?]/.test(unquoted)) return undefined;
	if (!hasUnqualifiedWhoamiFlag && !MSYS_WIN_CLI_RE.test(unquoted) && !MSYS_OPENSSL_SUBJ_RE.test(raw)) return undefined;
	let converted = whoamiRewrite.text.replace(
		/(^|[\s'"=])\/([a-zA-Z])\/([^\s'"`;&|<>()]*)/g,
		(_m, pfx: string, drv: string, tail: string) => {
			return `${pfx}${drv.toUpperCase()}:/${tail}`;
		},
	);
	if (hasMsysEnv) return converted !== raw ? converted : undefined;
	const trimmed = converted.trimStart();
	if (trimmed.includes("\n")) return `export MSYS_NO_PATHCONV=1\n${converted}`;
	if (/(?:&&|\|\||[;|])/.test(trimmed)) return `export MSYS_NO_PATHCONV=1; ${converted}`;
	return `MSYS_NO_PATHCONV=1 ${converted}`;
}

export function healCmdForLoop(raw: string, toolName = "bash"): string | undefined {
	if (!raw || toolName !== "bash") return undefined;
	if (/\bfor\s+\/[frld]\b/i.test(raw)) return undefined;
	const trimmed = raw.trim();
	const headM = trimmed.match(
		/^(?:(cd(?:\s+\/d)?\s+(?:"[^"]+"|'[^']+'|\S+)(?:\s+2>\s*(?:\/dev\/null|NUL))?)\s*(?:&&|&)\s*)?for\s+%%?([A-Za-z_]\w*)\s+in\s+\(/i,
	);
	if (!headM || headM.index === undefined) return undefined;
	const listStart = headM[0].length;
	let quote: string | null = null;
	let listEnd = -1;
	for (let i = listStart; i < trimmed.length; i++) {
		const ch = trimmed[i];
		if (quote) {
			if (ch === quote) quote = null;
		} else if (ch === '"' || ch === "'") {
			quote = ch;
		} else if (ch === ")") {
			listEnd = i;
			break;
		} else if (ch === "\n" || ch === "\r") {
			break;
		}
	}
	if (listEnd <= listStart) return undefined;
	const itemsRaw = trimmed.slice(listStart, listEnd).trim();
	if (!itemsRaw) return undefined;
	const doM = trimmed.slice(listEnd + 1).match(/^\s*do\s+([\s\S]+?)\s*$/i);
	if (!doM) return undefined;
	const normWinTmpEnv = (s: string): string =>
		s.replace(/"([^"]*)"|'([^']*)'|%(?:TEMP|TMP)%/gi, (m, dq?: string, sq?: string) => {
			if (dq !== undefined) return `"${dq.replace(/%(?:TEMP|TMP)%/gi, "$TEMP")}"`;
			if (sq !== undefined) return `'${sq}'`;
			return '"$TEMP"';
		});
	const cdRaw = headM[1]
		? `${normWinTmpEnv(headM[1].trim().replace(/^cd\s+\/d\s+/i, "cd ").replace(/\\/g, "/"))} && `
		: "";
	const v = headM[2];
	const items = normWinTmpEnv(
		itemsRaw.replace(/([A-Za-z]:)\\([^"'\r\n]*)/g, (_m, d: string, rest: string) => `${d}/${rest.replace(/\\/g, "/")}`),
	);
	let body = doM[1].trim();
	if (body.startsWith("@")) body = body.slice(1).trim();
	if (body.startsWith("(") && body.endsWith(")") && body.length >= 2) {
		body = body.slice(1, -1).trim();
	}
	body = body.replace(new RegExp(`%%?(?:~[fdpnxsatz]*)?${v}(?!\\w)`, "gi"), () => "${" + v + "}");
	body = normWinTmpEnv(body);
	body = body.replace(/\s+2>\s*nul(?=$|[\s;&|)])/gi, " 2>/dev/null");
	body = body.replace(/\bdir\s+\/b\s+\/s\s+("[^"]+"|'[^']+'|\S+)/gi, `"${AP_BIN}" ls $1 --depth 3`);
	body = body.replace(/\bdir\s+\/s\s+\/b\s+("[^"]+"|'[^']+'|\S+)/gi, `"${AP_BIN}" ls $1 --depth 3`);
	body = body.replace(/\bdir\s+\/b\s+("[^"]+"|'[^']+'|\S+)/gi, `"${AP_BIN}" ls $1`);
	body = body.replace(/\bfindstr\s+\/I\s+\/C:("[^"]+"|\S+)/gi, "grep -iF $1");
	body = body.replace(/(?<![&>])(?:\s+&\s*|\s*&\s+)(?![&>])/g, "; ");
	return `${cdRaw}for ${v} in ${items}; do ${body.trim()}; done`;
}

const BARE_PS_CMDLET_PREFIX_RE =
	/^(?:\(\s*)?(?:Get-ChildItem|Get-Content|Get-Process|Get-CimInstance|Select-String|Get-NetTCPConnection|Get-Service|Get-ItemProperty|Get-Item|Get-FileHash|Get-Acl|Get-AuthenticodeSignature|Get-ScheduledTask|Test-NetConnection|Test-Path|Resolve-Path)\b/;

function normalizeUnquotedRelativeBackslashes(raw: string): string {
	let out = "";
	let quote: string | null = null;
	let i = 0;
	const n = raw.length;
	while (i < n) {
		const ch = raw[i];
		if (quote) {
			out += ch;
			if (ch === "\\" && quote === '"' && i + 1 < n) {
				out += raw[i + 1];
				i += 2;
				continue;
			}
			if (ch === quote) quote = null;
			i++;
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			out += ch;
			i++;
			continue;
		}
		if ((i === 0 || /[\s=;]/.test(raw[i - 1])) && /[A-Za-z0-9_.\u4e00-\u9fff]/.test(ch)) {
			let j = i;
			while (j < n && !/[\s'"`;|&<>()]/.test(raw[j])) {
				j++;
			}
			const tok = raw.slice(i, j);
			if (
				tok.includes("\\") &&
				!/^[A-Za-z]:/.test(tok) &&
				!/[*?{}\[\]|^$<>`]/.test(tok) &&
				!/^\\/.test(tok) &&
				/^(?:\.\.?\\[^\s\\]+|[A-Za-z0-9_\u4e00-\u9fff-]{2,}\\[A-Za-z0-9_\u4e00-\u9fff.-]{2,}(?:\\[^\s\\]+)*|[A-Za-z0-9_\u4e00-\u9fff-]+\\[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,8})$/.test(tok)
			) {
				out += tok.replace(/\\/g, "/");
				i = j;
				continue;
			}
			out += tok;
			i = j;
			continue;
		}
		out += ch;
		i++;
	}
	return out;
}

function normalizeUnquotedBashDrivePaths(raw: string): string {
	let out = "";
	let quote: string | null = null;
	let i = 0;
	while (i < raw.length) {
		const ch = raw[i];
		if (quote) {
			out += ch;
			if (ch === "\\" && quote === '"' && i + 1 < raw.length) {
				out += raw[i + 1];
				i += 2;
				continue;
			}
			if (ch === quote) quote = null;
			i++;
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			out += ch;
			i++;
			continue;
		}
		if (
			/[A-Za-z]/.test(ch) &&
			raw[i + 1] === ":" &&
			(raw[i + 2] === "\\" || raw[i + 2] === "/") &&
			(i === 0 || /[\s=;(]/.test(raw[i - 1]))
		) {
			const pfM = raw
				.slice(i)
				.match(/^([A-Za-z]:)[\\/](Program Files(?: \(x86\))?(?:[\\/][^\s'"`;|&<>()]*)?)/i);
			if (pfM) {
				const normPf = `${pfM[1]}/${pfM[2].replace(/\\/g, "/")}`;
				out += `"${normPf}"`;
				i += pfM[0].length;
				continue;
			}
			if (raw[i + 2] === "\\") {
				let j = i + 2;
				while (j < raw.length && !/[\s'"`;|&<>()]/.test(raw[j])) {
					j++;
				}
				out += `${ch}:${raw.slice(i + 2, j).replace(/\\/g, "/")}`;
				i = j;
				continue;
			}
		}
		out += ch;
		i++;
	}
	return out;
}

function splitUnquotedPipes(s: string): string[] | undefined {
	const parts: string[] = [];
	let cur = "";
	let quote: string | null = null;
	for (let i = 0; i < s.length; i++) {
		const ch = s[i];
		if (quote) {
			cur += ch;
			if (ch === quote) {
				quote = null;
			} else if (quote === '"' && ch === "\\" && i + 1 < s.length) {
				cur += s[i + 1];
				i += 1;
			}
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			cur += ch;
		} else if (ch === "|") {
			if (s[i + 1] === "|") return undefined;
			const t = cur.trim();
			if (!t) return undefined;
			parts.push(t);
			cur = "";
		} else if (ch === "&") {
			if (
				i >= 2 &&
				(i === 2 || /\s/.test(s[i - 3])) &&
				s[i - 1] === ">" &&
				s[i - 2] === "2" &&
				s[i + 1] === "1" &&
				(i + 2 >= s.length || /[\s|]/.test(s[i + 2]))
			) {
				cur += ch;
			} else {
				return undefined;
			}
		} else if (ch === "$" && s[i + 1] === "(") {
			return undefined;
		} else {
			cur += ch;
		}
	}
	if (quote !== null) return undefined;
	const tail = cur.trim();
	if (!tail) return undefined;
	parts.push(tail);
	return parts;
}

function accelerateGrepPipeline(
	cmdTailBody: string,
	cdLeadPfx: string,
	fromCat = false,
): string | undefined {
	const stages = splitUnquotedPipes(cmdTailBody.trim());
	if (!stages || stages.length < 2) return undefined;
	const grepRaw = stripBenignStderrRedir(stages[0]);
	const stripQuotes = (s: string) => s.replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, "");
	if (/[;&><{}`]|\$\(/.test(stripQuotes(grepRaw))) return undefined;
	if (!/^(?:grep|egrep|fgrep|rg)(?:\s|$)/.test(grepRaw)) return undefined;
	const gToks = (grepRaw.match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) || []).map((t) => {
		if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
			return t.slice(1, -1).replace(/\\"/g, '"');
		}
		return t;
	});
	const isRg = gToks[0] === "rg";
	const isEgrep = gToks[0] === "egrep";
	const isFgrep = gToks[0] === "fgrep";
	if (gToks[0] !== "grep" && !isEgrep && !isFgrep && !isRg) return undefined;
	let ignoreCase = false;
	let fixed = isFgrep;
	let extendedRe = isEgrep;
	let recursive = false;
	let filesOnly = false;
	let countOnly = false;
	let lineNum = false;
	let onlyMatch = false;
	let invertMatch = false;
	let noFilename = false;
	let optMaxCount = 0;
	let ctxA = 0;
	let ctxB = 0;
	let ctxC = 0;
	const exts: string[] = [];
	const includes: string[] = [];
	const addGlob = (g: string): boolean => {
		if (!g || g.startsWith("!")) return false;
		const em = g.match(/^\*\.([A-Za-z0-9_]+)$/);
		if (em) {
			if (!exts.includes(em[1])) exts.push(em[1]);
		} else {
			includes.push(g);
		}
		return true;
	};
	let endOpts = false;
	const gPos: string[] = [];
	for (let gi = 1; gi < gToks.length; gi += 1) {
		const gt = gToks[gi];
		if (!endOpts && gt === "--") {
			endOpts = true;
			continue;
		}
		if (!endOpts && gt.startsWith("--")) {
			if (gt === "--invert-match") {
				invertMatch = true;
				continue;
			}
			if (gt.startsWith("--max-count=")) {
				const m = Number(gt.slice(12));
				if (!Number.isInteger(m) || m < 1) return undefined;
				optMaxCount = optMaxCount > 0 ? Math.min(optMaxCount, m) : m;
				continue;
			}
			if (gt === "--max-count") {
				gi += 1;
				const m = gi < gToks.length ? Number(gToks[gi]) : NaN;
				if (!Number.isInteger(m) || m < 1) return undefined;
				optMaxCount = optMaxCount > 0 ? Math.min(optMaxCount, m) : m;
				continue;
			}
			if (!isRg) return undefined;
			if (gt.startsWith("--glob=")) {
				if (!addGlob(gt.slice(7))) return undefined;
			} else if (gt === "--glob") {
				gi += 1;
				if (gi >= gToks.length || !addGlob(gToks[gi])) return undefined;
			} else if (gt === "--no-filename") {
				noFilename = true;
			} else if (gt === "--no-messages" || gt === "--no-line-number") {
				// compatible defaults
			} else if (gt === "--line-number") {
				lineNum = true;
			} else if (gt === "--ignore-case") {
				ignoreCase = true;
			} else if (gt === "--fixed-strings") {
				fixed = true;
			} else if (gt === "--only-matching") {
				onlyMatch = true;
			} else if (gt === "--files-with-matches") {
				filesOnly = true;
			} else if (gt === "--count") {
				countOnly = true;
			} else {
				return undefined;
			}
			continue;
		}
		if (!endOpts && gt.startsWith("-") && gt.length > 1) {
			const sh = gt.slice(1);
			if (sh === "A" || sh === "B" || sh === "C") {
				gi += 1;
				const m = gi < gToks.length ? Number(gToks[gi]) : NaN;
				if (!Number.isInteger(m) || m < 0) return undefined;
				if (sh === "A") ctxA = m;
				else if (sh === "B") ctxB = m;
				else ctxC = m;
				continue;
			}
			if (/^[ABC]\d+$/.test(sh)) {
				const m = Number(sh.slice(1));
				if (sh[0] === "A") ctxA = m;
				else if (sh[0] === "B") ctxB = m;
				else ctxC = m;
				continue;
			}
			if (sh === "m") {
				gi += 1;
				const m = gi < gToks.length ? Number(gToks[gi]) : NaN;
				if (!Number.isInteger(m) || m < 1) return undefined;
				optMaxCount = optMaxCount > 0 ? Math.min(optMaxCount, m) : m;
				continue;
			}
			if (sh.startsWith("m")) {
				const tail = sh.slice(1);
				if (!/^\d+$/.test(tail)) return undefined;
				const m = Number(tail);
				if (m < 1) return undefined;
				optMaxCount = optMaxCount > 0 ? Math.min(optMaxCount, m) : m;
				continue;
			}
			if (isRg && sh === "g") {
				gi += 1;
				if (gi >= gToks.length || !addGlob(gToks[gi])) return undefined;
				continue;
			}
			for (const ch of sh) {
				if (ch === "n") lineNum = true;
				else if (ch === "H" || ch === "s" || ch === "a") continue;
				else if (isRg && ch === "N") continue;
				else if (isRg && ch === "I") noFilename = true;
				else if (!isRg && ch === "I") continue;
				else if (!isRg && (ch === "r" || ch === "R")) recursive = true;
				else if (!isRg && ch === "E") extendedRe = true;
				else if (ch === "h") noFilename = true;
				else if (ch === "i") ignoreCase = true;
				else if (ch === "F") fixed = true;
				else if (ch === "l") filesOnly = true;
				else if (ch === "c") countOnly = true;
				else if (ch === "o") onlyMatch = true;
				else if (ch === "v") invertMatch = true;
				else return undefined;
			}
			continue;
		}
		gPos.push(gt);
	}
	if (invertMatch && onlyMatch) return undefined;
	if (fromCat && (filesOnly || countOnly)) return undefined;
	const patPos = gPos[0];
	const tgtPos = isRg && gPos.length === 1 ? "." : gPos.length === 2 ? gPos[1] : "";
	if (!patPos || !tgtPos || tgtPos === "-" || /[*?,]/.test(tgtPos) || (gPos.length !== 2 && !(isRg && gPos.length === 1))) {
		return undefined;
	}
	const isSingleConcreteFile = !isRg && !recursive;
	if (isSingleConcreteFile && !fromCat && (tgtPos === "." || !/[./\\]/.test(tgtPos))) {
		return undefined;
	}
	let cutWidth = 0;
	let maxHits = optMaxCount;
	let unique = false;
	let sawBareSort = false;
	let sawUniqC = false;
	for (let si = 1; si < stages.length; si += 1) {
		const norm = stages[si].replace(/\s+/g, " ").trim();
		if (/[;&><{}`]|\$\(/.test(norm)) return undefined;
		if (norm === "sort") {
			if (fromCat || lineNum || sawBareSort) return undefined;
			sawBareSort = true;
			continue;
		}
		if (norm === "uniq -c" || norm === "uniq") {
			if (fromCat || lineNum || !sawBareSort) return undefined;
			sawBareSort = false;
			sawUniqC = true;
			unique = true;
			continue;
		}
		if (sawBareSort) return undefined;
		if (norm === "sort -u") {
			if (fromCat || lineNum) return undefined;
			unique = true;
		} else if ((norm === "sort -rn" || norm === "sort -nr" || norm === "sort -r") && sawUniqC) {
			// `ap search --unique` already ranks descending by frequency
		} else {
			const cutM = norm.match(/^cut\s+-c\s*1-(\d+)$/);
			const headM = norm.match(/^head\s+(?:-n\s*(\d+)|-(\d+))$/);
			if (cutM) {
				const w = Number(cutM[1]);
				if (w < 1) return undefined;
				cutWidth = cutWidth > 0 ? Math.min(cutWidth, w) : w;
			} else if (headM) {
				const m = Number(headM[1] || headM[2]);
				if (m < 1) return undefined;
				maxHits = maxHits > 0 ? Math.min(maxHits, m) : m;
			} else {
				return undefined;
			}
		}
	}
	if (sawBareSort || (cutWidth === 0 && maxHits === 0 && !unique)) return undefined;
	const rustPat = isRg ? patPos : translateGrepBreToRustRegex(patPos, `${fixed ? "F" : ""}${extendedRe ? "E" : ""}`);
	const flags = [
		cutWidth > 0 ? ` --width ${cutWidth}` : "",
		maxHits > 0 ? ` --max ${maxHits}` : "",
		unique ? " --unique" : "",
		filesOnly ? " --files-only" : countOnly ? " --count" : "",
		onlyMatch ? " -o" : "",
		invertMatch ? " -v" : "",
		noFilename ? " --no-filename" : "",
		ignoreCase ? " -i" : "",
		fixed ? " --fixed-strings" : "",
		ctxC > 0 ? ` -C ${ctxC}` : "",
		ctxB > 0 ? ` -B ${ctxB}` : "",
		ctxA > 0 ? ` -A ${ctxA}` : "",
		exts.length > 0 ? ` --ext ${exts.join(",")}` : "",
		...includes.map((inc) => ` --include "${inc.replace(/"/g, '\\"')}"`),
	].join("");
	return `${cdLeadPfx}"${AP_BIN}" search${flags} ${shellQuoteBashPat(rustPat)} "${tgtPos.replace(/"/g, '\\"')}"`;
}

function accelerateLsPipeline(cmdTailBody: string, cdLeadPfx: string): string | undefined {
	const stages = splitUnquotedPipes(cmdTailBody.trim());
	if (!stages || stages.length !== 2) return undefined;
	const lhs = stripBenignStderrRedir(stages[0]);
	const rhs = stages[1].trim();
	const stripQuotes = (s: string) => s.replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, "");
	if (/[;&><{}`]|\$\(/.test(stripQuotes(lhs)) || /[;&><{}`]|\$\(/.test(stripQuotes(rhs))) return undefined;
	const headM = rhs.match(/^head\s+(?:-n\s*(\d+)|-(\d+))$/);
	if (!headM) return undefined;
	const limit = Number(headM[1] || headM[2]);
	if (!Number.isInteger(limit) || limit < 1) return undefined;
	const rawToks = lhs.match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) || [];
	if (rawToks.length === 0 || rawToks[0] !== "ls") return undefined;
	let showAll = false;
	let sortMode: "" | "t" | "S" = "";
	let tgt: string | undefined = undefined;
	for (let i = 1; i < rawToks.length; i += 1) {
		const rawT = rawToks[i];
		const isSingleQ = rawT.startsWith("'") && rawT.endsWith("'") && rawT.length >= 2;
		const isDoubleQ = rawT.startsWith('"') && rawT.endsWith('"') && rawT.length >= 2;
		const t = isSingleQ
			? rawT.slice(1, -1)
			: isDoubleQ
				? rawT.slice(1, -1).replace(/\\"/g, '"')
				: rawT;
		if (!isSingleQ && !isDoubleQ && t.startsWith("-") && t.length > 1) {
			if (t.startsWith("--")) {
				if (t === "--all" || t === "--almost-all") {
					showAll = true;
				} else if (
					t === "--color=never" ||
					t === "--color=auto" ||
					t === "--group-directories-first" ||
					t === "--classify" ||
					t === "--human-readable"
				) {
					continue;
				} else {
					return undefined;
				}
				continue;
			}
			for (const ch of t.slice(1)) {
				if ("l1hFp".includes(ch)) continue;
				else if (ch === "a" || ch === "A") showAll = true;
				else if (ch === "t") sortMode = "t";
				else if (ch === "S") sortMode = "S";
				else return undefined;
			}
			continue;
		}
		if (tgt !== undefined || /[*?,]/.test(t)) return undefined;
		// Never re-wrap single-quoted shell metacharacters (`$`, `` ` ``, `\`) in double quotes (prevents expansion injection)
		if (isSingleQ && /[$`\\]/.test(t)) return undefined;
		tgt = t;
	}
	const esc = (tgt || ".").replace(/"/g, '\\"');
	const flags = `${showAll ? " -a" : ""}${sortMode === "t" ? " -t" : sortMode === "S" ? " -S" : ""}`;
	return `${cdLeadPfx}"${AP_BIN}" ls "${esc}"${flags} --depth 1 --limit ${limit}`;
}

function parseSedLineRanges(expr: string): string | undefined {
	const parts = expr.split(";");
	if (parts.length === 0 || parts.length > 16) return undefined;
	const out: string[] = [];
	for (const rawPart of parts) {
		const p = rawPart.trim();
		const m = p.match(/^(\d+)(?:,(\d+))?p$/);
		if (!m) return undefined;
		const s = Number(m[1]);
		const e = m[2] ? Number(m[2]) : s;
		if (!Number.isInteger(s) || !Number.isInteger(e) || s < 1 || e < s) return undefined;
		out.push(`${s}-${e}`);
	}
	return out.length > 0 ? out.join(",") : undefined;
}

function accelerateSingleBashSegment(seg: string, toolName: string): string | undefined {
	// Safely preserve trailing `|| true` on grep probes (exit code is always discarded -> 0)
	if (toolName === "bash") {
		const orTrueM = seg.match(/^([\s\S]+?)(\s*\|\|\s*true\s*)$/);
		if (orTrueM && !/\|\|/.test(orTrueM[1])) {
			const innerGrep = rewriteSlowRecursiveGrep(orTrueM[1], toolName);
			if (innerGrep) return `${innerGrep}${orTrueM[2]}`;
		}
	}
	const fastGrep = rewriteSlowRecursiveGrep(seg, toolName);
	if (fastGrep) return fastGrep;

	const cdLeadM = seg.match(/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)([\s\S]+)$/);
	const cdLeadPfx = cdLeadM ? cdLeadM[1] : "";
	const cmdTailBody = cdLeadM ? cdLeadM[2] : seg;
	const bareTail = stripBenignStderrRedir(cmdTailBody);
	if (!/[|;&>]/.test(bareTail)) {
		const gm = bareTail.match(BARE_SLOW_GREP);
		if (gm && /[rR]/.test(gm[1])) {
			const flags = gm[1];
			const rawPat = gm[2] || gm[3] || gm[4] || "";
			const target = gm[5] || gm[6] || gm[7] || ".";
			const prefix = toolName === "powershell" ? "& " : "";
			const quotedPat = toolName === "bash" ? shellQuoteBashPat(rawPat) : `"${rawPat.replace(/"/g, '\\"')}"`;
			const extra = [
				flags.includes("l") ? " -l" : flags.includes("c") ? " -c" : "",
				flags.includes("o") ? " -o" : "",
				flags.includes("i") ? " -i" : "",
			].join("");
			return `${cdLeadPfx}${prefix}"${AP_BIN}" search${extra} ${quotedPat} "${target}"`;
		}
	}

	// 1b. Rewrite `cmd //c "where /R <dir> <pat>"` -> fast `.gitignore`-aware `rg --files`
	if (toolName === "bash") {
		const whereM = seg.match(
			/^cmd\s+\/\/?c\s+"where\s+\/R\s+(?:'([^']+)'|"([^"]+)"|(\S+))\s+([^"]+)"(\s*2>&1)?(\s*\|[\s\S]*)?$/i,
		);
		if (whereM) {
			const dirArg = (whereM[1] || whereM[2] || whereM[3] || ".").replace(/\\/g, "/");
			const globPat = whereM[4].trim();
			const pipeTail = whereM[6] || "";
			return `rg --files --max-depth 5 -g "${globPat}" "${dirArg}"${pipeTail}`;
		}
	}

	// 1c. Rewrite MS-DOS `dir /b [flags] [path|glob] [2>/dev/null|2>&1] [| pipe]` in Git Bash -> bounded `ap ls` / `rg --files`
	if (toolName === "bash" && /\bdir\b/i.test(cmdTailBody)) {
		const dStages = splitUnquotedPipes(cmdTailBody.trim());
		if (dStages && dStages.length >= 1) {
			const dirTail = stripBenignStderrRedir(dStages[0]);
			const pipeTail = dStages.length > 1 ? ` | ${dStages.slice(1).join(" | ")}` : "";
			if (!/[;&><]/.test(dirTail)) {
				const toks = dirTail.match(/"[^"]*"|'[^']*'|\S+/g) || [];
				if (toks.length >= 2 && toks[0].toLowerCase() === "dir") {
					let hasBare = false;
					let recursive = false;
					const tgts: string[] = [];
					let ok = true;
					for (let i = 1; i < toks.length; i += 1) {
						const rawTok = toks[i];
						const unq = rawTok.replace(/^(['"])(.*)\1$/, "$2");
						const low = unq.toLowerCase();
						if (low === "/b") {
							hasBare = true;
						} else if (low === "/s") {
							recursive = true;
						} else if (unq.startsWith("/") && unq.length >= 2) {
							continue;
						} else if (!/[?,]/.test(unq)) {
							tgts.push(unq);
						} else {
							ok = false;
							break;
						}
					}
					if (ok && hasBare) {
						const depthVal = recursive ? 3 : 1;
						const depthFlag = recursive ? " --depth 3" : "";
						if (tgts.length <= 1) {
							const rawT = tgts[0] || ".";
							if (rawT.includes("*")) {
								const normT = rawT.replace(/\\/g, "/");
								const slashIdx = normT.lastIndexOf("/");
								const dirPart = slashIdx >= 0 ? normT.slice(0, slashIdx) || "." : ".";
								const globPart = slashIdx >= 0 ? normT.slice(slashIdx + 1) : normT;
								const extM = globPart.match(/^\*\.([A-Za-z0-9_]+)$/);
								if (extM) {
									return `${cdLeadPfx}"${AP_BIN}" ls "${dirPart.replace(/"/g, '\\"')}"${depthFlag} --ext ${extM[1]}${pipeTail}`;
								}
								return `${cdLeadPfx}rg --files --no-ignore --max-depth ${depthVal} -g '${globPart.replace(/'/g, "")}' "${dirPart.replace(/"/g, '\\"')}" 2>/dev/null${pipeTail}`;
							}
							return `${cdLeadPfx}"${AP_BIN}" ls "${rawT.replace(/"/g, '\\"')}"${depthFlag}${pipeTail}`;
						} else if (tgts.every((t) => !t.includes("*"))) {
							const quotedDirs = tgts
								.map((t) => `"${t.replace(/\\/g, "/").replace(/"/g, '\\"')}"`)
								.join(" ");
							return `${cdLeadPfx}rg --files --no-ignore --max-depth ${depthVal} ${quotedDirs} 2>/dev/null${pipeTail}`;
						}
					}
				}
			}
		}
	}

	// 1d. Rewrite bare `sed -n '<A>,<B>p'`, `head -n|-c <N>`, `tail -n <N>`, `cat <file> [2>/dev/null] | ...`,
	// `ls ... | head -n <N>`, or unified `grep ... | cut/sort/uniq/head` pipelines -> bounded `ap` commands
	if (toolName === "bash") {
		const trimmedTail = cmdTailBody.trim();
		const qPathOk = (f: string) => Boolean(f) && f !== "-" && !/[*?,]/.test(f);
		const stripErr = stripBenignStderrRedir;
		const cutOnlyM = trimmedTail.match(/^([\s\S]+?)\s*\|\s*cut\s+-c\s*1-(\d+)\s*$/);
		const sliceCore = stripErr(cutOnlyM ? cutOnlyM[1].trim() : trimmedTail);
		const sliceWidth = cutOnlyM && Number(cutOnlyM[2]) >= 1 ? Number(cutOnlyM[2]) : 0;
		const sliceWidthFlag = sliceWidth > 0 ? ` --width ${sliceWidth}` : "";
		const hasUnsafeOutsideQuotes = (s: string) => /[|;&><{}`]|\$\(/.test(s.replace(/'[^']*'|"[^"]*"/g, ""));
		if (!hasUnsafeOutsideQuotes(sliceCore)) {
			const sedM = sliceCore.match(
				/^sed\s+-n\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&-]+))\s*$/,
			);
			const sedRanges = sedM ? parseSedLineRanges(sedM[1] || sedM[2] || sedM[3] || "") : undefined;
			if (sedM && sedRanges) {
				const f = sedM[4] || sedM[5] || sedM[6] || "";
				if (qPathOk(f)) {
					return `${cdLeadPfx}"${AP_BIN}" read "${f.replace(/"/g, '\\"')}" --lines ${sedRanges}${sliceWidthFlag}`;
				}
			}
			if (!/[|;&><{}`]|\$\(/.test(sliceCore)) {
				const headM = sliceCore.match(
					/^head\s+(?:(-c)\s*(\d+)|-n\s*(\d+)|-(\d+))\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&>-]+))\s*$/,
				);
				if (headM) {
					const isBytes = Boolean(headM[1]);
					const n = Number(headM[2] || headM[3] || headM[4]);
					const f = headM[5] || headM[6] || headM[7] || "";
					if (n >= 1 && qPathOk(f) && !(isBytes && sliceWidth > 0)) {
						return isBytes
							? `${cdLeadPfx}"${AP_BIN}" read "${f.replace(/"/g, '\\"')}" --offset 0 --chars ${n}`
							: `${cdLeadPfx}"${AP_BIN}" read "${f.replace(/"/g, '\\"')}" --lines 1-${n}${sliceWidthFlag}`;
					}
				}
				const tailM = sliceCore.match(/^tail\s+(?:-n\s*(\d+)|-(\d+))\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&-]+))\s*$/);
				if (tailM) {
					const n = Number(tailM[1] || tailM[2]);
					const f = tailM[3] || tailM[4] || tailM[5] || "";
					if (n >= 1 && qPathOk(f)) {
						return `${cdLeadPfx}"${AP_BIN}" read "${f.replace(/"/g, '\\"')}" --tail ${n}${sliceWidthFlag}`;
					}
				}
			}
		}
		const grepPipeOut = accelerateGrepPipeline(trimmedTail, cdLeadPfx);
		if (grepPipeOut) return grepPipeOut;
		const lsPipeOut = accelerateLsPipeline(trimmedTail, cdLeadPfx);
		if (lsPipeOut) return lsPipeOut;
		const duClean = stripErr(trimmedTail);
		if (!hasUnsafeOutsideQuotes(duClean)) {
			const duToks = (duClean.match(/"[^"]*"|'[^']*'|\S+/g) || []).map((t) =>
				t.replace(/^(['"])(.*)\1$/, "$2"),
			);
			if (duToks.length >= 2 && duToks[0] === "du") {
				let hasSummary = false;
				let duTgt: string | undefined = undefined;
				let duOk = true;
				for (let di = 1; di < duToks.length; di += 1) {
					const tok = duToks[di];
					if (tok.startsWith("-")) {
						if (/^(?:-s|-h|-sh|-hs|-k|-m|--summarize|--human-readable)$/.test(tok)) {
							hasSummary = true;
						} else {
							duOk = false;
							break;
						}
					} else if (duTgt === undefined && !/[*?,]/.test(tok)) {
						duTgt = tok;
					} else {
						duOk = false;
						break;
					}
				}
				if (duOk && hasSummary) {
					const escDu = (duTgt || ".").replace(/"/g, '\\"');
					return `${cdLeadPfx}"${AP_BIN}" ls "${escDu}" --du`;
				}
			}
		}
		const catStages = splitUnquotedPipes(cutOnlyM ? cutOnlyM[1].trim() : trimmedTail);
		if (catStages && catStages.length >= 2) {
			const catLhs = stripErr(catStages[0]);
			const catM = !/[|;&><{}`]|\$\(/.test(catLhs)
				? catLhs.match(/^cat\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&-]+))$/)
				: null;
			const f = catM ? catM[1] || catM[2] || catM[3] || "" : "";
			if (qPathOk(f)) {
				const esc = f.replace(/"/g, '\\"');
				const rhs1 = stripErr(catStages[1]);
				if (catStages.length === 2 && !hasUnsafeOutsideQuotes(rhs1)) {
					const rHead = rhs1.match(/^head\s+(?:(-c)\s*(\d+)|-n\s*(\d+)|-(\d+))$/);
					const rTail = rhs1.match(/^tail\s+(?:-n\s*(\d+)|-(\d+))$/);
					const rSed = rhs1.match(/^sed\s+-n\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&]+))$/);
					const rSedRanges = rSed ? parseSedLineRanges(rSed[1] || rSed[2] || rSed[3] || "") : undefined;
					if (rHead) {
						const isBytes = Boolean(rHead[1]);
						const n = Number(rHead[2] || rHead[3] || rHead[4]);
						if (n >= 1 && !(isBytes && sliceWidth > 0)) {
							return isBytes
								? `${cdLeadPfx}"${AP_BIN}" read "${esc}" --offset 0 --chars ${n}`
								: `${cdLeadPfx}"${AP_BIN}" read "${esc}" --lines 1-${n}${sliceWidthFlag}`;
						}
					} else if (rTail) {
						const n = Number(rTail[1] || rTail[2]);
						if (n >= 1) return `${cdLeadPfx}"${AP_BIN}" read "${esc}" --tail ${n}${sliceWidthFlag}`;
					} else if (rSed && rSedRanges) {
						return `${cdLeadPfx}"${AP_BIN}" read "${esc}" --lines ${rSedRanges}${sliceWidthFlag}`;
					}
				}
				if ((catStages.length >= 3 || sliceWidth > 0) && /^(?:grep|egrep|fgrep)(?:\s|$)/.test(rhs1) && !hasUnsafeOutsideQuotes(rhs1)) {
					const tailParts = [
						`${rhs1} "${esc}"`,
						...catStages.slice(2).map((s) => s.trim()),
						...(sliceWidth > 0 ? [`cut -c 1-${sliceWidth}`] : []),
					];
					const catGrepOut = accelerateGrepPipeline(tailParts.join(" | "), cdLeadPfx, true);
					if (catGrepOut) return catGrepOut;
				}
			}
		}
	}

	// 1e. Rewrite bounded POSIX `find [path] [-maxdepth N] [-type f|d] [-name "<glob>"] [2>/dev/null] [| head -n M]` -> bounded `ap ls` / `rg --files`, and depth-bound any unbounded `find`
	if (toolName === "bash" && /^\s*find(?:\s|$)/.test(cmdTailBody)) {
		let findCore = cmdTailBody.trim();
		let findLimit = -1;
		const headPipeM = findCore.match(/^([\s\S]+?)\s*\|\s*head\s+(?:-n\s*(\d+)|-(\d+))\s*$/);
		if (headPipeM) {
			findLimit = Number(headPipeM[2] || headPipeM[3]);
			findCore = headPipeM[1].trim();
		}
		findCore = findCore.replace(/\s*2>\s*\/dev\/null\s*$/, "").trim();
		if (findLimit !== 0 && !/[|;&><{}`]|\$\(/.test(findCore)) {
			const fToks = (findCore.match(/"[^"]*"|'[^']*'|\S+/g) || []).map((t) =>
				t.replace(/^(['"])(.*)\1$/, "$2"),
			);
			if (fToks.length >= 1 && fToks[0] === "find") {
				let fIdx = 1;
				let fTarget = ".";
				let findOk = true;
				if (fIdx < fToks.length && !fToks[fIdx].startsWith("-") && !["(", ")", "!"].includes(fToks[fIdx])) {
					if (/[*?,]/.test(fToks[fIdx])) findOk = false;
					fTarget = fToks[fIdx];
					fIdx += 1;
				}
				let fDepth = 3;
				let fFilesOnly = false;
				let fDirsOnly = false;
				let fExt = "";
				let fGlob = "";
				while (findOk && fIdx < fToks.length) {
					const flag = fToks[fIdx];
					if (flag === "-maxdepth" && fIdx + 1 < fToks.length) {
						const d = Number(fToks[fIdx + 1]);
						if (!Number.isInteger(d) || d < 1 || d > 5) {
							findOk = false;
							break;
						}
						fDepth = d;
						fIdx += 2;
					} else if (flag === "-type" && fIdx + 1 < fToks.length) {
						const t = fToks[fIdx + 1];
						if (t === "f") fFilesOnly = true;
						else if (t === "d") fDirsOnly = true;
						else findOk = false;
						fIdx += 2;
					} else if ((flag === "-name" || flag === "-iname") && fIdx + 1 < fToks.length && !fExt && !fGlob) {
						const rawGlob = fToks[fIdx + 1];
						const em = rawGlob.match(/^\*\.([A-Za-z0-9_]+)$/);
						if (em) {
							fExt = em[1];
						} else if (rawGlob && !/[`$]/.test(rawGlob)) {
							fGlob = rawGlob;
						} else {
							findOk = false;
							break;
						}
						fIdx += 2;
					} else {
						findOk = false;
						break;
					}
				}
				if (findOk && !(fFilesOnly && fDirsOnly)) {
					const escTgt = fTarget.replace(/"/g, '\\"');
					if (fGlob && !fDirsOnly) {
						const headTail = findLimit > 0 ? ` | head -n ${findLimit}` : "";
						return `${cdLeadPfx}rg --files --no-ignore --max-depth ${fDepth} -g '${fGlob.replace(/'/g, "")}' "${escTgt}" 2>/dev/null${headTail}`;
					}
					const typeFlag = fFilesOnly ? " --files-only" : fDirsOnly ? " --dirs-only" : "";
					const extFlag = fExt ? ` --ext ${fExt}` : "";
					const limFlag = findLimit > 0 ? ` --limit ${findLimit}` : "";
					return `${cdLeadPfx}"${AP_BIN}" ls "${escTgt}" --depth ${fDepth}${typeFlag}${extFlag}${limFlag}`;
				}
			}
		}
		// Safety net: inject `-maxdepth 6` into unbounded `find` pipelines that could not be rewritten
		const rawTrimmedFind = cmdTailBody.trim();
		if (
			!/\s-(?:maxdepth|prune|delete|exec|execdir|ok)\b/.test(rawTrimmedFind) &&
			!/[;&><`]|&&|\|\|/.test(rawTrimmedFind.replace(/'[^']*'|"[^"]*"/g, ""))
		) {
			const inj = rawTrimmedFind.replace(
				/^(find(?:\s+(?:'[^']+'|"[^"]+"|[^\s-|;&><()!]+))*)(?=\s+(?:-|!|\())/,
				"$1 -maxdepth 6",
			);
			if (inj !== rawTrimmedFind) {
				return `${cdLeadPfx}${inj}`;
			}
		}
	}

	// Accelerate slow recursive PowerShell `Get-ChildItem ... -Recurse` (both PS-in-Bash and native PowerShell tool)
	if (toolName === "bash" && /\b(?:Get-ChildItem|gci)\b/i.test(seg) && /-Recurse\b/i.test(seg)) {
		const psGci = seg.match(
			/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?(?:powershell|pwsh)(?:\.exe)?\b[^|;&]*?\s-(?:Command|c)\s+(['"])([\s\S]+?)\2(?:\s*2>&1)?\s*$/i,
		);
		if (psGci) {
			const qWrap = psGci[2];
			const psBody = psGci[3]
				.replace(/^\s*\[Console\]::OutputEncoding\s*=[^;]+;\s*/i, "")
				.trim();
			if (
				!PS_MUTATING_CMDLET_RE.test(psBody) &&
				!/\b(?:Where-Object|ForEach-Object|Format-Table|Sort-Object|-Include|-Exclude|-Directory)\b/i.test(psBody)
			) {
				let gciPart = psBody;
				let firstN = -1;
				const selM = psBody.match(/^([\s\S]+?)\|\s*Select-Object\s+[^|;]*?-First\s+(\d+)\b[^|;]*$/i);
				if (selM) {
					gciPart = selM[1].trim();
					firstN = Number(selM[2]);
				}
				if (!gciPart.includes("|") && !gciPart.includes(";")) {
					const gm = gciPart.match(
						/^(?:Get-ChildItem|gci)\s+[\s\S]*?-(?:Literal)?Path\s+([^;\n]+?)(?=\s+-(?:Recurse|Filter|ErrorAction|File|Directory|Depth)\b|$)/i,
					);
					const posM = !gm
						? gciPart.match(
								/^(?:Get-ChildItem|gci)\s+(?!-)(?:'([^']+)'|"([^"]+)"|([^\s;|]+))(?:\s|$)/i,
							)
						: null;
					const pathExpr = gm ? gm[1] : posM ? posM[1] || posM[2] || posM[3] || "." : ".";
					const fm = gciPart.match(/-Filter\s+(?:'([^']+)'|"([^"]+)"|([^\s;|]+))/i);
					const glob = fm ? fm[1] || fm[2] || fm[3] || "" : "";
					if (!/\$/.test(pathExpr) && !/\$/.test(glob)) {
						const rawPaths = pathExpr
							.split(",")
							.map((p) => p.trim().replace(/^(['"])(.*)\1$/, "$2").replace(/\\/g, "/"))
							.filter(Boolean);
						if (rawPaths.length > 0 && rawPaths.every((p) => !/[*?`$;|<>]/.test(p))) {
							const quotedRoots = rawPaths.map((p) => `"${p.replace(/"/g, '\\"')}"`).join(" ");
							const globFlag = glob ? ` -g '${glob.replace(/'/g, "")}'` : "";
							const headPipe = firstN > 0 ? ` | head -n ${firstN}` : "";
							return `${psGci[1] || ""}rg --files --no-ignore --max-depth 6${globFlag} ${quotedRoots} 2>/dev/null${headPipe}`;
						}
					}
				}
			}
			if (!/-Depth\b/i.test(psBody) && !PS_MUTATING_CMDLET_RE.test(psBody)) {
				const bounded = seg.replace(/(-Recurse\b)/i, "$1 -Depth 5");
				if (bounded !== seg && bounded.includes(qWrap)) return bounded;
			}
		}
	}
	if (
		toolName === "powershell" &&
		/\b(?:Get-ChildItem|gci)\b/i.test(seg) &&
		/-Recurse\b/i.test(seg) &&
		!/-Depth\b/i.test(seg) &&
		!PS_MUTATING_CMDLET_RE.test(seg)
	) {
		const boundedPs = seg.replace(/(-Recurse\b)/i, "$1 -Depth 5");
		if (boundedPs !== seg) return boundedPs;
	}

	// Accelerate simple read-only Windows discovery PowerShell one-liners (`Get-NetTCPConnection`,
	// `GetFiles('\\.\pipe\')`, `Get-CimInstance Win32_Process` / `Get-Process`, `Get-Service`) -> fast `ap probe`
	if (toolName === "bash" && /\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(seg)) {
		const psDiscM = seg.match(
			/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?(?:powershell|pwsh)(?:\.exe)?\b[^|;&]*?\s-(?:Command|c)\s+(['"])([\s\S]+?)\2(?:\s*2>&1)?\s*$/i,
		);
		if (psDiscM) {
			const cdLead = psDiscM[1] || "";
			const body = psDiscM[3]
				.replace(/^\s*\[Console\]::OutputEncoding\s*=[^;]+;\s*/i, "")
				.trim();
			const hasSideEffectsOrComplex =
				PS_MUTATING_CMDLET_RE.test(body) ||
				/[;>=<`]|(?:\b(?:ForEach-Object|Format-Table|Format-List|ConvertTo-|Export-|Import-)\b|\$[A-Za-z_]\w*\s*=)/i.test(
					body.replace(/\s-(?:match|like|eq)\s/gi, " "),
				);
			if (body && !hasSideEffectsOrComplex) {
				const firstM = body.match(/\|\s*Select-Object\s+[^|;]*?-First\s+(\d+)\b\s*$/i);
				const core = firstM ? body.slice(0, firstM.index).trim() : body;
				const limNum = firstM ? Math.min(200, Math.max(1, Number(firstM[1]))) : 0;

				// 1. Listening TCP ports
				const tcpM = core.match(
					/^Get-NetTCPConnection(?:\s+-State\s+Listen)?(?:\s+-LocalPort\s+(\d+))?(?:\s+-State\s+Listen)?(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (tcpM) {
					const portArg = tcpM[1] ? ` -p ${tcpM[1]}` : "";
					return `${cdLead}"${AP_BIN}" probe ports${portArg}`;
				}

				// 2. Named pipes (`[System.IO.Directory]::GetFiles('\\.\pipe\')` or `Get-ChildItem \\.\pipe\`)
				const pipeMatch = core.match(
					/^(?:\[System\.IO\.Directory\]::GetFiles\(\s*['"][\\\/]{2,4}\.[\\\/]{1,2}pipe[\\\/]*['"]\s*\)|Get-ChildItem\s+['"]?[\\\/]{2,4}\.[\\\/]{1,2}pipe[\\\/]*['"]?)(?:\s*\|\s*Where-Object\s*\{\s*\\?\$_\s*-(?:match|like)\s*['"]([^'"]+)['"]\s*\})?$/i,
				);
				if (pipeMatch) {
					const rawF = (pipeMatch[1] || "").replace(/^\*+|\*+$/g, "");
					const fFlag = rawF && !/[`$]/.test(rawF) ? ` --filter "${rawF.replace(/"/g, '\\"')}"` : "";
					const mFlag = limNum > 0 ? ` --max ${limNum}` : "";
					return `${cdLead}"${AP_BIN}" probe win --pipes${fFlag}${mFlag}`;
				}

				// 3. Running processes (`Get-Process` or `Get-CimInstance Win32_Process`)
				const procMatch = core.match(
					/^(?:Get-Process(?:\s+(?:-Name\s+)?['"]?([A-Za-z0-9_.*-]+)['"]?)?|Get-CimInstance\s+Win32_Process(?:\s+-Filter\s+["']Name=['"]([^'"]+)['"]["'])?)(?:\s*\|\s*Where-Object\s*\{\s*\\?\$_\.(?:Process)?Name\s*-(?:match|like)\s*['"]([^'"]+)['"]\s*\})?(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (procMatch) {
					const rawF = (procMatch[1] || procMatch[2] || procMatch[3] || "").replace(/^\*+|\*+$/g, "");
					const fFlag = rawF && !/[`$]/.test(rawF) ? ` --filter "${rawF.replace(/"/g, '\\"')}"` : "";
					const lFlag = limNum > 0 ? ` --limit ${limNum}` : "";
					return `${cdLead}"${AP_BIN}" probe ps${fFlag}${lFlag}`;
				}

				// 4. Windows services (`Get-Service`)
				const svcMatch = core.match(
					/^Get-Service(?:\s+(?:-Name\s+)?['"]?([A-Za-z0-9_.*-]+)['"]?)?(?:\s*\|\s*Where-Object\s*\{\s*\\?\$_\.(?:Service|Display)?Name\s*-(?:match|like)\s*['"]([^'"]+)['"]\s*\})?(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (svcMatch) {
					const rawF = (svcMatch[1] || svcMatch[2] || "").replace(/^\*+|\*+$/g, "");
					const fFlag = rawF && !/[`$]/.test(rawF) ? ` --filter "${rawF.replace(/"/g, '\\"')}"` : "";
					const mFlag = limNum > 0 ? ` --max ${limNum}` : "";
					return `${cdLead}"${AP_BIN}" probe win --services${fFlag}${mFlag}`;
				}

				// 5. PE Authenticode signature (`Get-AuthenticodeSignature '<path>'`)
				const sigMatch = core.match(
					/^Get-AuthenticodeSignature(?:\s+-FilePath)?\s+(?:'([^']+)'|"([^"]+)"|([^\s;|'"`$]+))(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (sigMatch) {
					const rawP = (sigMatch[1] || sigMatch[2] || sigMatch[3] || "").trim();
					if (rawP && !/[`$]/.test(rawP)) {
						return `${cdLead}"${AP_BIN}" probe win --sig "${rawP.replace(/\\/g, "/").replace(/"/g, '\\"')}"`;
					}
				}

				// 6. File/dir ACL (`Get-Acl '<path>'`)
				const aclMatch = core.match(
					/^\(?\s*Get-Acl(?:\s+-(?:Literal)?Path)?\s+(?:'([^']+)'|"([^"]+)"|([^\s;|'"`$)]+))\s*\)?(?:\.(?:Sddl|AccessToString))?(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (aclMatch) {
					const rawP = (aclMatch[1] || aclMatch[2] || aclMatch[3] || "").trim();
					if (rawP && !/[`$]/.test(rawP)) {
						return `${cdLead}"${AP_BIN}" probe win --acl "${rawP.replace(/\\/g, "/").replace(/"/g, '\\"')}"`;
					}
				}

				// 7. Windows registry key (`Get-ItemProperty 'HKLM:\...'`)
				const regMatch = core.match(
					/^Get-ItemProperty(?:\s+-(?:Literal)?Path)?\s+['"]?(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC):?\\([^'"]+)['"]?(?:\s*\|\s*Select-Object\b[^|]*)?$/i,
				);
				if (regMatch) {
					const hive = regMatch[1].trim();
					const sub = regMatch[2].trim();
					if (hive && sub && !/[`$]/.test(sub)) {
						return `${cdLead}"${AP_BIN}" probe win --reg "${hive}\\${sub.replace(/"/g, '\\"')}"`;
					}
				}
			}
		}
	}

	// Read-only `icacls "<path>"` in Git Bash -> pure-Rust `ap probe win --acl "<path>"`
	if (
		toolName === "bash" &&
		/^\s*(?:cd(?:\s+\/d)?\s+\S+\s*(?:&&|;)\s*)?icacls(?:\.exe)?\s+/i.test(seg) &&
		!/\/(?:grant|deny|remove|setowner|inheritance|reset|restore|save|substitute|t)\b/i.test(seg)
	) {
		const icM = seg.match(
			/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?icacls(?:\.exe)?\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&>]+))(?:\s+2>\s*(?:\/dev\/null|NUL))?\s*$/i,
		);
		if (icM) {
			const rawP = (icM[2] || icM[3] || icM[4] || "").trim();
			if (rawP && !/[`$]/.test(rawP)) {
				return `${icM[1] || ""}"${AP_BIN}" probe win --acl "${rawP.replace(/\\/g, "/").replace(/"/g, '\\"')}"`;
			}
		}
	}

	return undefined;
}

function accelerateCompoundSegments(cmd: string, toolName: string): string | undefined {
	if (toolName !== "bash" || !/(?:&&|;|\n)/.test(cmd)) return undefined;
	if (/<<|\b(?:for|while|if)\s+/.test(cmd)) return undefined;
	const parts: Array<{ text: string; sep: string }> = [];
	let cur = "";
	let quote: string | null = null;
	let i = 0;
	while (i < cmd.length) {
		const ch = cmd[i];
		if (quote) {
			cur += ch;
			if (ch === "\\" && quote === '"' && i + 1 < cmd.length) {
				cur += cmd[i + 1];
				i += 2;
				continue;
			}
			if (ch === quote) quote = null;
			i++;
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			cur += ch;
			i++;
			continue;
		}
		if (ch === "&" && cmd[i + 1] === "&") {
			parts.push({ text: cur, sep: "&&" });
			cur = "";
			i += 2;
			continue;
		}
		if (ch === ";" || ch === "\n") {
			parts.push({ text: cur, sep: ch });
			cur = "";
			i++;
			continue;
		}
		cur += ch;
		i++;
	}
	parts.push({ text: cur, sep: "" });
	if (parts.length < 2) return undefined;

	let anyChanged = false;
	const out: string[] = [];
	for (const part of parts) {
		const leadWs = part.text.match(/^\s*/)?.[0] ?? "";
		const trailWs = part.text.match(/\s*$/)?.[0] ?? "";
		const core = part.text.trim();
		let nextCore = core;
		if (core) {
			const isConditionalGrep =
				(part.sep === "&&" || part.sep === "||") &&
				/^(?:(?:grep|egrep|fgrep|rg|findstr)\b|cat\s+[^|;&]+\|\s*(?:grep|egrep|fgrep|rg)\b)/i.test(core);
			const accel = isConditionalGrep ? undefined : accelerateSingleBashSegment(core, toolName);
			if (accel) {
				nextCore = accel;
				anyChanged = true;
			} else if (BARE_PS_CMDLET_PREFIX_RE.test(core) && !/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(core)) {
				const body = core.replace(/'/g, `'"'"'`);
				nextCore = `powershell.exe -NoProfile -Command '[Console]::OutputEncoding=[Text.Encoding]::UTF8; ${body}'`;
				anyChanged = true;
			}
		}
		out.push(`${leadWs}${nextCore}${trailWs}${part.sep}`);
	}
	return anyChanged ? out.join("") : undefined;
}

export function healCommand(
	raw: string,
	toolName: string,
	kvSleepOverrideSec?: number,
): string | undefined {
	if (!raw) return undefined;
	let cmd = raw;
	let changed = false;
	if (cmd.includes("\0")) {
		cmd = cmd.replace(/\0/g, "");
		changed = true;
	}
	const isDestructive = DESTRUCTIVE_OR_WRITE.test(cmd);
	if (isDestructive) {
		if (toolName === "bash") {
			const fixedDestrCd = healCmdCdSlashD(cmd);
			if (fixedDestrCd !== cmd) {
				cmd = fixedDestrCd;
				changed = true;
			}
			const psDestr = healBashPowerShellCommand(cmd);
			if (psDestr) {
				cmd = psDestr;
				changed = true;
			}
			const msysDestr = process.platform === "win32" ? healMsysPathConv(cmd, toolName) : undefined;
			if (msysDestr) {
				cmd = msysDestr;
				changed = true;
			}
		}
		return changed ? cmd : undefined;
	}

	// 0. Pre-normalize safe Git Bash Windowsisms BEFORE accelerators so `cd /d`, `2>NUL`, `&`, unquoted/quoted backslashes, `| more` & `| Select-Object` accelerate too
	if (toolName === "bash") {
		if (/\bNUL(?=$|[\s;&|)])/i.test(cmd)) {
			const fixedNul = healRedirNul(cmd);
			if (fixedNul !== cmd) {
				cmd = fixedNul;
				changed = true;
			}
		}
		const fixedCdD = healCmdCdSlashD(cmd);
		if (fixedCdD !== cmd) {
			cmd = fixedCdD;
			changed = true;
		}
		const cdAmp = cmd.match(/^(\s*cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)(?:\s+2>\s*\/dev\/null)?)\s*&\s*(?![&>])([\s\S]+)$/);
		if (cdAmp) {
			cmd = `${cdAmp[1]} && ${cdAmp[2]}`;
			changed = true;
		}
		if (/\|\s*more\b/i.test(cmd)) {
			const noMore = cmd.replace(/\s*\|\s*more(?:\s+\+\d+)?(?=\s*(?:$|[;&|]))/gi, "");
			if (noMore !== cmd) {
				cmd = noMore;
				changed = true;
			}
		}
		const hasScriptRuntime = /<<|(?:^|[\s;&|(=])(?:python3?|py|node|powershell|pwsh)(?:\.exe)?(?=\s|$|[;&|)])/i.test(cmd);
		if (!/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(cmd) && !cmd.includes("<<")) {
			const normSelect = cmd
				.replace(/\|\s*Select-Object\s+-First\s+(\d+)\b/gi, "| head -n $1")
				.replace(/\|\s*Select-Object\s+-Last\s+(\d+)\b/gi, "| tail -n $1");
			if (normSelect !== cmd) {
				cmd = normSelect;
				changed = true;
			}
		}
		if (!hasScriptRuntime) {
			const moreToCat = cmd.replace(/(^|[;&|]\s*|\bdo\s+)more(?:\s+\+\d+)?(?=\s+[^-|;&])/gi, "$1cat");
			if (moreToCat !== cmd) {
				cmd = moreToCat;
				changed = true;
			}
		}
		// Normalize unquoted Windows drive paths (e.g. `cd D:\foo`) even before a `<<` heredoc, never touching heredoc body
		const hdSplitIdx = cmd.indexOf("<<");
		const drvHead = hdSplitIdx >= 0 ? cmd.slice(0, hdSplitIdx) : cmd;
		if (/(?:^|[\s=;(])[A-Za-z]:\\|[A-Za-z]:[\\/]Program Files/i.test(drvHead)) {
			const normDrvHead = normalizeUnquotedBashDrivePaths(drvHead);
			if (normDrvHead !== drvHead) {
				cmd = hdSplitIdx >= 0 ? normDrvHead + cmd.slice(hdSplitIdx) : normDrvHead;
				changed = true;
			}
		}
		if (!cmd.includes("<<")) {
			if (!PY_INVOKE.test(cmd) && !/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(cmd)) {
				const normRel = normalizeUnquotedRelativeBackslashes(cmd);
				if (normRel !== cmd) {
					cmd = normRel;
					changed = true;
				}
				const fixedBs = cmd.replace(/(?<!\\)"([A-Za-z]:\\[^"]*?)"/g, (_m, inner: string) => `"${inner.replace(/\\/g, "/")}"`);
				if (fixedBs !== cmd) {
					cmd = fixedBs;
					changed = true;
				}
			}
		}
	}

	// 1. Accelerate single-command slow patterns (`grep -rn`, `dir /b`, `sed`/`head`/`tail`/`cat`, `find`, slow PS `Get-ChildItem -Recurse -Filter`)
	const singleAccel = accelerateSingleBashSegment(cmd, toolName);
	if (singleAccel) {
		const shieldedSingle = process.platform === "win32" ? healMsysPathConv(singleAccel, toolName) : undefined;
		return shieldedSingle ?? singleAccel;
	}

	// 1f. Accelerate top-level `;` / `&&` compound Bash probes (and wrap mid-command bare PowerShell cmdlets)
	const compoundAccel = accelerateCompoundSegments(cmd, toolName);
	if (compoundAccel) {
		cmd = compoundAccel;
		changed = true;
	}

	// 2a. Strip stray `2>/dev/null` placed inside `for x in *.py 2>/dev/null; do` word lists
	if (toolName === "bash" && /\bfor\s+\w+\s+in\b[^;]*\s2>\s*\/dev\/null\s*;/.test(cmd)) {
		cmd = cmd.replace(/(\bfor\s+\w+\s+in\b[^;]*?)\s+2>\s*\/dev\/null(\s*;)/g, "$1$2");
		changed = true;
	}

	// 2c. Normalize Git Bash `find` MSYS paths w/ backslash-escaped spaces (`/c/Program\ Files` -> `"C:/Program Files"`)
	if (toolName === "bash" && /\bfind\s+/.test(cmd)) {
		const fixedFind = cmd.replace(/\/([a-zA-Z])\/((?:[^\s\\|;&]|\\ )+)/g, (_m, drv: string, tail: string) => {
			const unesc = tail.replace(/\\ /g, " ");
			return tail.includes("\\ ") ? `"${drv.toUpperCase()}:/${unesc}"` : `${drv.toUpperCase()}:/${unesc}`;
		});
		if (fixedFind !== cmd) {
			cmd = fixedFind;
			changed = true;
		}
	}

	// 2e. Rewrite Windows CMD `for %x in (...) do ...` inside Git Bash into valid Bash loops
	const healedFor = healCmdForLoop(cmd, toolName);
	if (healedFor) {
		cmd = healedFor;
		changed = true;
	}

	// 3. Auto-fix unescaped Windows drive & relative path backslashes inside `python -c` & `python <<'PY'` non-raw literals
	if (PY_INVOKE.test(cmd) && /(?:-c\b|<<)/.test(cmd)) {
		let fixed = cmd.replace(
			/(?<![rR])(['"])([A-Za-z]:)(\\(?!\\)[^'"\r\n]+)\1/g,
			(m, q: string, drv: string, rest: string) => {
				if (/\\[nrt]$/.test(rest)) return m;
				return q + drv + rest.replace(/\\/g, "/") + q;
			},
		);
		fixed = fixed.replace(
			/(?<![rR])(['"])([^'"\r\n]*\\(?:Users|Network|Windows|AppData|Local|Roaming|System32|Program Files|Temp|Desktop|Documents|Default)(?:\\[^'"\r\n]*)?)\1/g,
			(m, q: string, inner: string) => (inner.includes("\\\\") ? m : q + inner.replace(/\\/g, "/") + q),
		);
		if (fixed !== cmd) {
			cmd = fixed;
			changed = true;
		}
	}

	// 4. Auto-lock UTF-8 across BOTH Bash and PowerShell Python invocations (prevents 99% of Windows GBK crashes)
	if (PY_INVOKE.test(cmd) && !HAS_UTF8_ENV.test(cmd)) {
		if (toolName === "bash") {
			cmd = `export PYTHONUTF8=1 PYTHONIOENCODING=utf-8; ${cmd}`;
			changed = true;
		} else if (toolName === "powershell") {
			cmd = `$env:PYTHONUTF8='1'; $env:PYTHONIOENCODING='utf-8'; ${cmd}`;
			changed = true;
		}
	}

	// 5. Prevent PowerShell 5.1 `curl` -> Invoke-WebRequest alias crashes
	if (toolName === "powershell" && /(?:^|[;&|]\s*)curl(?=\s)/i.test(cmd)) {
		cmd = cmd.replace(/(^|[;&|]\s*)curl(?=\s)/gi, "$1curl.exe");
		changed = true;
	}

	// 6. Rewrite Windows cmd `type <file>` inside Git Bash -> `cat <posix-path>` (leaves POSIX `type -a/-t/-p` and bare commands untouched)
	if (toolName === "bash") {
		const tm = cmd.match(
			/^(\s*(?:cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?)type\s+(?!-[atpPf]\b)(?:'([^']+)'|"([^"]+)"|([^\s'"|;&>]+))([\s\S]*)$/,
		);
		const rawTarget = tm ? tm[2] || tm[3] || tm[4] || "" : "";
		if (tm && rawTarget && /[./\\]/.test(rawTarget)) {
			const posixTarget = rawTarget.replace(/\\/g, "/");
			const quoted = posixTarget.includes("'")
				? `"${posixTarget.replace(/"/g, '\\"')}"`
				: `'${posixTarget}'`;
			cmd = `${tm[1] || ""}cat ${quoted}${tm[5] || ""}`;
			changed = true;
		}
	}

	// 6b. Wrap bare read-only PowerShell cmdlets accidentally sent to Git Bash (fixes syntax error near unexpected token)
	if (toolName === "bash" && !/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(cmd)) {
		const psBare = cmd.match(
			/^(\s*(?:cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?)((?:\(\s*)?(?:Get-ChildItem|Get-Content|Get-Process|Get-CimInstance|Select-String|Get-NetTCPConnection|Get-Service|Get-ItemProperty|Get-Item|Get-FileHash|Get-Acl|Get-AuthenticodeSignature|Get-ScheduledTask|Test-NetConnection|Test-Path|Resolve-Path)\b[\s\S]*)$/,
		);
		if (psBare) {
			const body = psBare[2].trim().replace(/'/g, `'"'"'`);
			cmd = `${psBare[1] || ""}powershell.exe -NoProfile -Command '[Console]::OutputEncoding=[Text.Encoding]::UTF8; ${body}'`;
			changed = true;
		}
	}

	// 7. Lock UTF-8 output encoding & shield PowerShell `$var` when Git Bash spawns `powershell -Command "..."`
	if (toolName === "bash") {
		const psFixed = healBashPowerShellCommand(cmd);
		if (psFixed) {
			cmd = psFixed;
			changed = true;
		}
	}

	// 8. Auto-switch bare `rg "pattern"` with unbalanced `(` or `[` to `rg -F` (eliminates `rg: regex parse error`)
	if (
		toolName === "bash" &&
		!/[|;&><]/.test(cmd) &&
		/^\s*(?:rg|rg\.exe)\s+/i.test(cmd) &&
		!/\s(?:-F|--fixed-strings|-P|--pcre2)\b/.test(cmd)
	) {
		const rgPat = cmd.match(/^\s*(?:rg|rg\.exe)\s+(?:-[A-Za-z]+\s+)*(['"])([\s\S]+?)\1/);
		if (rgPat) {
			const p = rgPat[2];
			let parens = 0;
			let brackets = 0;
			let esc = false;
			let broken = false;
			for (let i = 0; i < p.length; i++) {
				const ch = p[i];
				if (esc) { esc = false; continue; }
				if (ch === "\\") { esc = true; continue; }
				if (ch === "(") parens++;
				else if (ch === ")") { if (--parens < 0) broken = true; }
				else if (ch === "[") brackets++;
				else if (ch === "]") { if (--brackets < 0) broken = true; }
			}
			if (broken || parens !== 0 || brackets !== 0) {
				cmd = cmd.replace(/^\s*(rg(?:\.exe)?)\s+/i, "$1 -F ");
				changed = true;
			}
		}
	}

	// 9. Clamp long foreground sleeps (>=60s) to kvSleepOverrideSec (default 45s) to avoid evicting LLM KV-caches
	const clampedSleep = clampKvSafeSleep(cmd, toolName, kvSleepOverrideSec ?? 45);
	if (clampedSleep) {
		cmd = clampedSleep;
		changed = true;
	}

	// 9b. Inject bounded `--max-time 30` into unguarded standalone Bash `curl` probes (cuts HTTP hangs before KV-cache drops)
	if (toolName === "bash") {
		const guardedCurl = guardUnboundedCurlTimeout(cmd);
		if (guardedCurl) {
			cmd = guardedCurl;
			changed = true;
		}
	}

	// 10. Shield Git Bash MSYS2 path conversion when invoking Windows CLIs with `/flag` or `openssl -subj '/...'`
	const shieldedMsys = process.platform === "win32" ? healMsysPathConv(cmd, toolName) : undefined;
	if (shieldedMsys) {
		cmd = shieldedMsys;
		changed = true;
	}

	// 11. Repair hallucinated `ap` CLI subcommands seen in live logs (`ap bin_surface|objdump|re|files|rg`)
	if (toolName === "bash") {
		const apAliasM = cmd.match(
			/^(\s*(?:cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)?(?:"[^"]*[/\\]ap(?:\.exe)?"|ap(?:\.exe)?)\s+)(bin_surface|objdump|re|files|rg)\b([\s\S]*)$/,
		);
		if (apAliasM) {
			const lead = apAliasM[1];
			const badSub = apAliasM[2];
			const rest = apAliasM[3] || "";
			if (badSub === "files") {
				cmd = `${lead}ls${rest}`;
				changed = true;
			} else if (badSub === "rg") {
				cmd = `${lead}search${rest}`;
				changed = true;
			} else {
				const hasMode = /\s--(?:surface|xref|strings|hex|rva|va|diff)\b/.test(rest);
				cmd = `${lead}read${rest}${hasMode ? "" : " --surface"}`;
				changed = true;
			}
		}
	}

	// 12. Auto-transport broken nested/unterminated inline `python -c` scripts via `ap exec --lang py --base64`
	if (toolName === "bash") {
		const pyBroken = healBrokenInlinePythonCommand(cmd);
		if (pyBroken) {
			cmd = pyBroken;
			changed = true;
		}
	}

	// 13. Normalize benign empty-match exit code 1 on unaccelerated standalone/tail `grep`/`rg`/`findstr`
	//     (strictly preserves exit >= 2 syntax/ENOENT errors and compound &&/|| condition semantics)
	if (toolName === "bash") {
		const wrappedEmpty = wrapBenignSearchExit1(cmd);
		if (wrappedEmpty) {
			cmd = wrappedEmpty;
			changed = true;
		}
	}

	return changed ? cmd : undefined;
}

function healBrokenInlinePythonCommand(cmd: string): string | undefined {
	if (/[<>]|<<|\|\||&&[\s\S]*&&/.test(cmd.replace(/'[^']*'|"[^"]*"/g, ""))) return undefined;
	const m = cmd.match(
		/^(\s*(?:export\s+PYTHONUTF8=1\s+PYTHONIOENCODING=utf-8\s*;\s*)?(?:cd\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*&&\s*)?)(python3?|py)(?:\.exe)?\s+(?:-[uBE]+\s+)*-c\s+([\s\S]+)$/,
	);
	if (!m) return undefined;
	const lead = (m[1] || "").replace(/^export\s+PYTHONUTF8=1\s+PYTHONIOENCODING=utf-8\s*;\s*/, "");
	const argTail = m[3].trim();
	if (!argTail || (!argTail.startsWith('"') && !argTail.startsWith("'"))) return undefined;

	// Locate balanced closing quote cleanly, even when followed by a trailing shell pipe (e.g. `| awk ... | head -60`).
	const outerQ = argTail[0];
	let consumedEnd = -1;
	if (outerQ === "'") {
		consumedEnd = argTail.indexOf("'", 1);
	} else {
		let esc = false;
		for (let i = 1; i < argTail.length; i++) {
			const ch = argTail[i];
			if (esc) { esc = false; continue; }
			if (ch === "\\") { esc = true; continue; }
			if (ch === '"') {
				consumedEnd = i;
				break;
			}
		}
	}

	const trailing = consumedEnd > 0 ? argTail.slice(consumedEnd + 1) : "";
	const trailingTrim = trailing.trim();
	const trailingIsValidShell =
		trailingTrim === "" ||
		/^(?:\||2?>|&>|&&|\|\||;)/.test(trailingTrim);

	if (consumedEnd > 0 && !trailingIsValidShell) return undefined;

	if (consumedEnd > 0 && trailingIsValidShell) {
		const inner = argTail.slice(1, consumedEnd);
		const hasInnerTrap =
			/(?<![rR\\])'\\'/.test(inner) ||
			(outerQ === '"' && /[\r\n]/.test(inner) && /"[^"\r\n]*"/.test(inner));
		if (!hasInnerTrap) return undefined;
		if (!inner.trim() || inner.length > 32_000) return undefined;
		const b64 = Buffer.from(inner, "utf8").toString("base64");
		return `${lead}"${AP_BIN}" exec --lang py --base64 ${b64}${trailing}`;
	}

	// Unclosed outer quote -> reject if unquoted shell chaining appears
	if (consumedEnd <= 0 && /(?:\||2?>|&&|\|\||;)/.test(argTail.slice(1))) return undefined;

	let rawBody = argTail.slice(1);
	if (rawBody.endsWith(outerQ) && !rawBody.endsWith("\\" + outerQ)) {
		rawBody = rawBody.slice(0, -1);
	}
	if (!rawBody.trim() || rawBody.length > 32_000) return undefined;
	const b64 = Buffer.from(rawBody, "utf8").toString("base64");
	return `${lead}"${AP_BIN}" exec --lang py --base64 ${b64}`;
}

function wrapBenignSearchExit1(cmd: string): string | undefined {
	if (/[\r\n]/.test(cmd)) return undefined;
	if (cmd.includes("_ap_ec=") || cmd.includes("[ap-empty]")) return undefined;
	const cdM = cmd.match(/^(\s*cd(?:\s+\/d)?\s+(?:'[^']+'|"[^"]+"|[^\s&|;]+)\s*(?:&&|;)\s*)([\s\S]+)$/);
	const lead = cdM ? cdM[1] : "";
	const tail = (cdM ? cdM[2] : cmd).trim();
	const stripped = tail.replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, "");
	if (/[;&><{}`]|\$\(|\|\||&&|\b(?:if|then|while|for)\b/.test(stripped)) return undefined;
	const stages = splitUnquotedPipes(tail);
	if (!stages || stages.length === 0) return undefined;
	const lastStage = stages[stages.length - 1].trim();
	if (!/^(?:grep|egrep|fgrep|rg|findstr)(?:\.exe)?\b/i.test(lastStage)) return undefined;
	return `${lead}{ ${tail}; }; _ap_ec=$?; if [ $_ap_ec -eq 1 ]; then printf '[ap-empty] 0 matches (exit 1)\\n'; exit 0; fi; exit $_ap_ec`;
}

const HALLUCINATED_TOOL_ALIASES: Readonly<Record<string, string>> = {
	codemake: "codemode",
	code_mode: "codemode",
	"code-mode": "codemode",
	cdemode: "codemode",
	codemao: "codemode",
	codemodep: "codemode",
	codemod: "codemode",
	codemodocode: "codemode",
	codemodode: "codemode",
	codemask: "codemode",
	code_exec: "codemode",
	code_scan: "codemode",
	code: "codemode",
	codemap: "codemode",
	codemap_placeholder: "codemode",
	js_eval: "codemode",
	eval_js: "codemode",
	run_js: "codemode",
	read_file: "read",
	readfile: "read",
	view_file: "read",
	edit_file: "edit",
	editfile: "edit",
	replace_in_file: "edit",
	str_replace: "edit",
	str_replace_editor: "edit",
	write_file: "write",
	writefile: "write",
	create_file: "write",
	grep_search: "grep",
	search_files: "grep",
	find_files: "find",
	list_files: "ls",
	bashexec: "bash",
	bash_run: "bash",
	run_bash: "bash",
	bash_command: "bash",
	run_command: "bash",
	run_shell: "bash",
	shell: "bash",
	terminal: "bash",
	exec: "bash",
	execute_shell: "bash",
	execute_command: "bash",
	exec_command: "bash",
};

function damerauLevenshtein(a: string, b: string): number {
	const n = a.length;
	const m = b.length;
	if (n === 0) return m;
	if (m === 0) return n;
	const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
	for (let i = 0; i <= n; i++) dp[i][0] = i;
	for (let j = 0; j <= m; j++) dp[0][j] = j;
	for (let i = 1; i <= n; i++) {
		for (let j = 1; j <= m; j++) {
			const cost = a[i - 1] === b[j - 1] ? 0 : 1;
			let v = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
			if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
				v = Math.min(v, dp[i - 2][j - 2] + 1);
			}
			dp[i][j] = v;
		}
	}
	return dp[n][m];
}

/**
 * Deterministically repair high-frequency hallucinated tool names (e.g. `codemake` -> `codemode`,
 * `read_file` -> `read`, `run_command` -> `bash`) and unique bounded typos via Damerau-Levenshtein
 * strictly when the target tool is active.
 */
export function repairHallucinatedToolName(
	rawName: string,
	activeTools: ReadonlySet<string>,
): string | undefined {
	if (!rawName || activeTools.has(rawName)) return undefined;
	const key = rawName.trim().toLowerCase();
	if (!key) return undefined;
	const mapped = HALLUCINATED_TOOL_ALIASES[key];
	if (mapped && activeTools.has(mapped)) return mapped;
	if (activeTools.has(key)) return key;
	if (key.length >= 5) {
		const maxDist = key.length >= 7 ? 2 : 1;
		let bestCand: string | undefined = undefined;
		let bestDist = maxDist + 1;
		let bestCount = 0;
		for (const cand of activeTools) {
			const candLow = cand.toLowerCase();
			if (candLow.length < 4 || Math.abs(key.length - candLow.length) > maxDist) continue;
			const firstOk =
				key[0] === candLow[0] ||
				(key.length >= 2 && key[1] === candLow[0] && key[0] === candLow[1]);
			if (!firstOk) continue;
			const d = damerauLevenshtein(key, candLow);
			if (d <= maxDist) {
				if (d < bestDist) {
					bestDist = d;
					bestCand = cand;
					bestCount = 1;
				} else if (d === bestDist) {
					bestCount += 1;
				}
			}
		}
		if (bestCand !== undefined && bestCount === 1) return bestCand;
	}
	return undefined;
}

export function normalizeRepairedToolArgs(
	targetName: string,
	rawArgs: unknown,
): { changed: boolean; args: Record<string, unknown> } {
	const args: Record<string, unknown> =
		rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs)
			? { ...(rawArgs as Record<string, unknown>) }
			: {};
	let changed = false;
	if (targetName === "bash" && typeof args.command !== "string") {
		const altCmd =
			typeof args.cmd === "string"
				? args.cmd
				: typeof args.shell_command === "string"
					? args.shell_command
					: typeof args.script === "string"
						? args.script
						: undefined;
		if (altCmd !== undefined) {
			args.command = altCmd;
			delete args.cmd;
			delete args.shell_command;
			delete args.script;
			changed = true;
		}
	} else if (targetName === "read" || targetName === "edit" || targetName === "write") {
		if (typeof args.path !== "string") {
			const altPath =
				typeof args.file_path === "string"
					? args.file_path
					: typeof args.filePath === "string"
						? args.filePath
						: typeof args.file === "string"
							? args.file
							: typeof args.filename === "string"
								? args.filename
								: undefined;
			if (altPath !== undefined) {
				args.path = altPath;
				delete args.file_path;
				delete args.filePath;
				delete args.file;
				delete args.filename;
				changed = true;
			}
		}
		if (targetName === "edit") {
			if (typeof args.oldText !== "string") {
				const altOld =
					typeof args.old_string === "string"
						? args.old_string
						: typeof args.old_text === "string"
							? args.old_text
							: typeof args.old === "string"
								? args.old
								: undefined;
				if (altOld !== undefined) {
					args.oldText = altOld;
					delete args.old_string;
					delete args.old_text;
					delete args.old;
					changed = true;
				}
			}
			if (typeof args.newText !== "string") {
				const altNew =
					typeof args.new_string === "string"
						? args.new_string
						: typeof args.new_text === "string"
							? args.new_text
							: typeof args.new === "string"
								? args.new
								: undefined;
				if (altNew !== undefined) {
					args.newText = altNew;
					delete args.new_string;
					delete args.new_text;
					delete args.new;
					changed = true;
				}
			}
		} else if (targetName === "write" && typeof args.content !== "string") {
			const altContent =
				typeof args.text === "string"
					? args.text
					: typeof args.body === "string"
						? args.body
						: undefined;
			if (altContent !== undefined) {
				args.content = altContent;
				delete args.text;
				delete args.body;
				changed = true;
			}
		}
	} else if (targetName === "codemode" && typeof args.code !== "string") {
		const altCode =
			typeof args.script === "string"
				? args.script
				: typeof args.js === "string"
					? args.js
					: typeof args.source === "string"
						? args.source
						: undefined;
		if (altCode !== undefined) {
			args.code = altCode;
			delete args.script;
			delete args.js;
			delete args.source;
			changed = true;
		}
	} else if (targetName === "grep" && typeof args.pattern !== "string") {
		const altPat =
			typeof args.query === "string"
				? args.query
				: typeof args.regex === "string"
					? args.regex
					: undefined;
		if (altPat !== undefined) {
			args.pattern = altPat;
			delete args.query;
			delete args.regex;
			changed = true;
		}
	}
	return { changed, args };
}

interface MarkdownSegment {
	text: string;
	isCode: boolean;
}

function consumeBlockquotePrefix(text: string, lineStart: number): { pos: number; bqDepth: number } {
	const n = text.length;
	let pos = lineStart;
	let bqDepth = 0;
	while (pos < n) {
		let sp = pos;
		while (sp < n && sp - pos < 3 && text[sp] === " ") sp++;
		if (sp < n && text[sp] === ">") {
			bqDepth++;
			pos = sp + 1;
			if (pos < n && text[pos] === " ") pos++;
			continue;
		}
		break;
	}
	return { pos, bqDepth };
}

function matchCommonMarkFenceOpener(
	text: string,
	lineStart: number,
): { fenceChar: string; fenceLen: number; infoEnd: number; bqDepth: number } | undefined {
	const n = text.length;
	const { pos: afterBq, bqDepth } = consumeBlockquotePrefix(text, lineStart);
	let p = afterBq;
	while (p < n && p - afterBq < 3 && text[p] === " ") p++;
	const fc = p < n ? text[p] : "";
	if (fc !== "`" && fc !== "~") return undefined;
	let fl = 0;
	while (p + fl < n && text[p + fl] === fc) fl++;
	if (fl < 3) return undefined;
	const eol = text.indexOf("\n", p + fl);
	const infoEnd = eol < 0 ? n : eol;
	const info = text.slice(p + fl, infoEnd);
	// CommonMark §4.5: backtick code fence info strings cannot contain backticks (tilde fences may)
	if (fc === "`" && info.includes("`")) return undefined;
	return { fenceChar: fc, fenceLen: fl, infoEnd, bqDepth };
}

/**
 * Segment Markdown text into non-overlapping prose (`isCode: false`) and code (`isCode: true`)
 * spans per CommonMark §3/§4.5/§5.1/§6.1:
 * - Fenced code blocks (optional blockquote prefix `(?:[ ]{0,3}>[ ]?)+`, `0-3` leading spaces,
 *   `3+` backticks or tildes, nested longer fences, unclosed-to-EOF/blockquote-end, rejecting
 *   backticks in backtick-fence info strings while allowing them in tilde-fence info strings).
 * - N-backtick inline code spans (respecting escaped `\` `, stopping at blank lines).
 */
function segmentMarkdownCodeSpans(text: string): MarkdownSegment[] {
	const n = text.length;
	const parts: MarkdownSegment[] = [];
	let proseStart = 0;
	let i = 0;
	let atLineStart = true;

	const flushProse = (end: number) => {
		if (end <= proseStart) return;
		parts.push({ text: text.slice(proseStart, end), isCode: false });
	};

	while (i < n) {
		let rejectedBacktickFence = false;
		if (atLineStart) {
			const opener = matchCommonMarkFenceOpener(text, i);
			if (opener) {
				let q = opener.infoEnd < n ? opener.infoEnd + 1 : n;
				let closeEnd = n;
				while (q < n) {
					const lineEnd = text.indexOf("\n", q);
					const nextLine = lineEnd < 0 ? n : lineEnd + 1;
					const lineStop = lineEnd < 0 ? n : lineEnd;
					const lineNoCr = lineStop > q && text[lineStop - 1] === "\r" ? lineStop - 1 : lineStop;
					const { pos: afterBq, bqDepth } = consumeBlockquotePrefix(text, q);
					if (opener.bqDepth > 0 && bqDepth < opener.bqDepth) {
						closeEnd =
							q > 0 && text[q - 1] === "\n"
								? q - 1 > i && text[q - 2] === "\r"
									? q - 2
									: q - 1
								: q;
						break;
					}
					let cp = afterBq;
					while (cp < lineNoCr && cp - afterBq < 3 && text[cp] === " ") cp++;
					let cl = 0;
					while (cp + cl < lineNoCr && text[cp + cl] === opener.fenceChar) cl++;
					if (cl >= opener.fenceLen) {
						let rest = cp + cl;
						while (rest < lineNoCr && (text[rest] === " " || text[rest] === "\t")) rest++;
						if (rest === lineNoCr) {
							closeEnd = lineNoCr;
							break;
						}
					}
					q = nextLine;
				}
				flushProse(i);
				parts.push({ text: text.slice(i, closeEnd), isCode: true });
				i = closeEnd;
				proseStart = i;
				atLineStart = false;
				continue;
			}
			// Detect a CommonMark §4.5 rejected backtick fence opener (info string contains `` ` ``)
			// so its opening backticks can still close on the same line (e.g. ```` ``` a ``` ````)
			// without swallowing subsequent lines as a pseudo-fenced block.
			const { pos: afterBq } = consumeBlockquotePrefix(text, i);
			let p = afterBq;
			while (p < n && p - afterBq < 3 && text[p] === " ") p++;
			if (p < n && text[p] === "`") {
				let fl = 0;
				while (p + fl < n && text[p + fl] === "`") fl++;
				if (fl >= 3) {
					const eol = text.indexOf("\n", p + fl);
					const info = text.slice(p + fl, eol < 0 ? n : eol);
					if (info.includes("`")) {
						rejectedBacktickFence = true;
						if (p > i) {
							i = p;
						}
					}
				}
			}
		}

		const ch = text[i];
		if (ch === "\\" && i + 1 < n && (text[i + 1] === "`" || text[i + 1] === "\\")) {
			i += 2;
			atLineStart = false;
			continue;
		}
		if (ch === "`") {
			let bt = 0;
			while (i + bt < n && text[i + bt] === "`") bt++;
			let j = i + bt;
			let matchEnd = -1;
			while (j < n) {
				if (text[j] === "\n") {
					if (rejectedBacktickFence) break;
					let k = j + 1;
					while (k < n && (text[k] === " " || text[k] === "\t" || text[k] === "\r")) k++;
					if (k < n && text[k] === "\n") break;
					j++;
					continue;
				}
				if (text[j] === "`") {
					let run = 0;
					while (j + run < n && text[j + run] === "`") run++;
					if (run === bt) {
						matchEnd = j + run;
						break;
					}
					j += run;
					continue;
				}
				j++;
			}
			if (matchEnd > 0) {
				flushProse(i);
				parts.push({ text: text.slice(i, matchEnd), isCode: true });
				i = matchEnd;
				proseStart = i;
				atLineStart = false;
				continue;
			}
			i += bt;
			atLineStart = false;
			continue;
		}
		atLineStart = ch === "\n";
		i++;
	}
	flushProse(n);
	return parts;
}

function finalizeStrippedMarkdownSegments(
	segments: Array<{ raw: string; text: string; isCode: boolean; changed: boolean }>,
): string {
	const out = segments.map((seg) => ({
		...seg,
		text: seg.isCode || !seg.changed ? seg.text : seg.text.replace(/\n{3,}/g, "\n\n"),
	}));
	while (out.length > 0 && !out[0].isCode && out[0].changed) {
		const leadTrimmed =
			out[0].text.trim().length === 0 || out[0].raw.trimStart() !== out[0].text.trimStart()
				? out[0].text.replace(/^[ \t\r\n]+/, "")
				: out[0].text;
		out[0].text = leadTrimmed;
		if (out[0].text.length === 0) {
			out.shift();
		} else {
			break;
		}
	}
	while (out.length > 0) {
		const last = out[out.length - 1];
		if (last.isCode || !last.changed) break;
		const trailTrimmed =
			last.text.trim().length === 0 || last.raw.trimEnd() !== last.text.trimEnd()
				? last.text.replace(/[ \t\r\n]+$/, "")
				: last.text;
		last.text = trailTrimmed;
		if (last.text.length === 0) {
			out.pop();
		} else {
			break;
		}
	}
	return out.map((seg) => seg.text).join("");
}

/**
 * Scrub leaked DeepSeek DSML / `<tool_call>` XML fragments from assistant prose so unparsed markup
 * never poisons downstream prompt context, while strictly preserving CommonMark fenced code blocks
 * (N-backtick / N-tilde, incl. nested 4-backtick and unclosed-to-EOF fences) and N-backtick inline
 * code spans (respecting escaped `\` `). Returns the exact original string on no-op so clean history
 * never mutates or busts prompt KV-cache.
 */
export function scrubLeakedToolMarkup(text: string): string {
	if (!text || (!text.includes("DSML") && !text.includes("<tool_call>"))) return text;
	const stripRaw = (seg: string): string =>
		seg
			.replace(/<[|｜]{1,2}DSML[|｜]{1,2}\s*(?:function_)?calls>[\s\S]*?<\/[|｜]{1,2}DSML[|｜]{1,2}\s*(?:function_)?calls>/g, "")
			.replace(/<\/?[|｜]{1,2}DSML[|｜]{1,2}\s*invoke\b[\s\S]*?<\/[|｜]{1,2}DSML[|｜]{1,2}\s*invoke>/g, "")
			.replace(/<\/?[|｜]{1,2}DSML[|｜]{1,2}[^>]*>/g, "")
			.replace(/<tool_call>[\s\S]*?<\/tool_call>/g, "");

	const segments = segmentMarkdownCodeSpans(text);
	let changed = false;
	const processed = segments.map((seg) => {
		if (seg.isCode) {
			return { raw: seg.text, text: seg.text, isCode: true, changed: false };
		}
		const stripped = stripRaw(seg.text);
		const segChanged = stripped !== seg.text;
		if (segChanged) changed = true;
		return { raw: seg.text, text: stripped, isCode: false, changed: segChanged };
	});
	if (!changed) return text;
	return finalizeStrippedMarkdownSegments(processed);
}

export interface DsmlRecoveredCall {
	type: "toolCall";
	id: string;
	name: string;
	arguments: Record<string, unknown>;
}

/**
 * Recover leaked DeepSeek DSML XML tool invocations from assistant prose into native Pi `toolCall` blocks.
 * Strictly ignores Markdown fenced code blocks and inline code spans, and gates names to `allowedTools`.
 */
export function extractDsmlToolCalls(
	text: string,
	allowedTools: ReadonlySet<string>,
): { cleanedText: string; calls: DsmlRecoveredCall[] } | undefined {
	if (!text || !text.includes("DSML") || !text.includes("invoke")) return undefined;
	const invokeRe =
		/<\/?[|｜]{1,2}DSML[|｜]{1,2}\s*invoke\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/[|｜]{1,2}DSML[|｜]{1,2}\s*invoke>/g;
	const paramRe =
		/<[|｜]{1,2}DSML[|｜]{1,2}\s*parameter\s+name="([^"]+)"(?:\s+string="(true|false)")?[^>]*>([\s\S]*?)<\/[|｜]{1,2}DSML[|｜]{1,2}\s*parameter>/g;

	const segments = segmentMarkdownCodeSpans(text);
	const calls: DsmlRecoveredCall[] = [];
	let seq = 0;
	for (const seg of segments) {
		if (seg.isCode || !seg.text.includes("DSML") || !seg.text.includes("invoke")) continue;
		invokeRe.lastIndex = 0;
		let match: RegExpExecArray | null;
		while ((match = invokeRe.exec(seg.text)) !== null) {
			const rawToolName = (match[1] || "").trim();
			const toolName = allowedTools.has(rawToolName)
				? rawToolName
				: repairHallucinatedToolName(rawToolName, allowedTools) ?? "";
			if (!toolName) continue;
			const body = match[2] || "";
			const args: Record<string, unknown> = {};
			let pm: RegExpExecArray | null;
			paramRe.lastIndex = 0;
			while ((pm = paramRe.exec(body)) !== null) {
				const key = (pm[1] || "").trim();
				const isStr = pm[2] !== "false";
				const rawVal = pm[3] ?? "";
				if (!key) continue;
				if (!isStr) {
					try {
						args[key] = JSON.parse(rawVal.trim());
						continue;
					} catch {
						// fall through to raw string
					}
				}
				args[key] = rawVal;
			}
			seq += 1;
			calls.push({
				type: "toolCall",
				id: `ap_dsml_${Date.now()}_${seq}`,
				name: toolName,
				arguments: toolName !== rawToolName ? normalizeRepairedToolArgs(toolName, args).args : args,
			});
		}
	}
	if (calls.length === 0) return undefined;
	const processed = segments.map((seg) => {
		if (seg.isCode) return { raw: seg.text, text: seg.text, isCode: true, changed: false };
		const stripped = seg.text
			.replace(/<[|｜]{1,2}DSML[|｜]{1,2}\s*(?:function_)?calls>[\s\S]*?<\/[|｜]{1,2}DSML[|｜]{1,2}\s*(?:function_)?calls>/g, "")
			.replace(invokeRe, "");
		return { raw: seg.text, text: stripped, isCode: false, changed: stripped !== seg.text };
	});
	const cleanedText = finalizeStrippedMarkdownSegments(processed);
	return { cleanedText, calls };
}

/**
 * Recover leaked `<tool_call>{"name":"...","arguments":{...}}</tool_call>` blocks
 * emitted in plain assistant prose under high context pressure (strictly ignores Markdown
 * fenced code blocks and inline code spans, and gates names to `allowedTools`).
 */
export function extractXmlJsonToolCalls(
	text: string,
	allowedTools: ReadonlySet<string>,
): { cleanedText: string; calls: DsmlRecoveredCall[] } | undefined {
	if (!text || !text.includes("<tool_call>")) return undefined;
	const re = /<tool_call>\s*([\s\S]*?)\s*<\/tool_call>/g;
	const segments = segmentMarkdownCodeSpans(text);
	const calls: DsmlRecoveredCall[] = [];
	let seq = 0;
	for (const seg of segments) {
		if (seg.isCode || !seg.text.includes("<tool_call>")) continue;
		re.lastIndex = 0;
		let match: RegExpExecArray | null;
		while ((match = re.exec(seg.text)) !== null) {
			try {
				const obj = JSON.parse(match[1]) as {
					name?: unknown;
					arguments?: unknown;
					parameters?: unknown;
				};
				const rawName = typeof obj?.name === "string" ? obj.name.trim() : "";
				const name = allowedTools.has(rawName)
					? rawName
					: repairHallucinatedToolName(rawName, allowedTools) ?? "";
				if (!name) continue;
				const rawArgs = obj.arguments ?? obj.parameters ?? {};
				const baseArgs =
					rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs)
						? (rawArgs as Record<string, unknown>)
						: {};
				const args = name !== rawName ? normalizeRepairedToolArgs(name, baseArgs).args : baseArgs;
				seq += 1;
				calls.push({
					type: "toolCall",
					id: `ap_xmltc_${Date.now()}_${seq}`,
					name,
					arguments: args,
				});
			} catch {
				// ignore non-JSON blocks
			}
		}
	}
	if (calls.length === 0) return undefined;
	const processed = segments.map((seg) => {
		if (seg.isCode) return { raw: seg.text, text: seg.text, isCode: true, changed: false };
		const stripped = seg.text.replace(re, "");
		return { raw: seg.text, text: stripped, isCode: false, changed: stripped !== seg.text };
	});
	const cleanedText = finalizeStrippedMarkdownSegments(processed);
	return { cleanedText, calls };
}

const ERROR_LINE_RE =
	/(?:^|\s)(?:error\[E\d+\]|ERROR:|FATAL:|Traceback|AssertionError|TypeError|SyntaxError|ReferenceError|RangeError|ValueError|RuntimeError|panicked at|FAILED\b|Exception:|Command exited with code [1-9])/i;

/**
 * Extract up to 3 high-signal error lines so observation masking never erases failure lessons
 * (Manus Context Engineering rule: keep error signatures in the trace to prevent repeat loops).
 */
export function extractErrorSignatureLines(rawText: string): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const ln of rawText.split("\n")) {
		const clean = ln.replace(/\s+/g, " ").trim();
		if (clean.length < 8 || !ERROR_LINE_RE.test(clean)) continue;
		const clipped = clean.slice(0, 140);
		if (seen.has(clipped)) continue;
		seen.add(clipped);
		out.push(clipped);
		if (out.length >= 3) break;
	}
	return out;
}

/**
 * Deterministic, timestamp-free replacement stub for stale bulky `toolResult` entries.
 * Preserves any `ap sieve` archive ID AND top error signatures for lossless failure memory.
 */
export function formatMaskedToolResult(
	toolName: string,
	rawText: string,
	isError = false,
): string {
	const lineCount = rawText.split("\n").length;
	const sieveMatch =
		rawText.match(/\bsieve\s+(?:id=|peek\s+)([a-zA-Z0-9_-]{4,40})\b/i) ||
		rawText.match(/\[sieve\s+id=([a-zA-Z0-9_-]{4,40})\b/i);
	const sieveId = sieveMatch?.[1];
	const head = rawText.slice(0, 140).replace(/\s+/g, " ").trim();
	const tail = rawText.slice(-110).replace(/\s+/g, " ").trim();
	const errLines = extractErrorSignatureLines(rawText);
	const errBlock =
		isError || errLines.length > 0
			? `\nerrors: ${errLines.length > 0 ? errLines.join(" | ") : "tool returned isError=true"}`
			: "";
	const recovery = sieveId
		? `(Recover full output via ap_sieve(action="peek", id="${sieveId}").)`
		: "(Re-run or narrow with ap_read(symbol/outline) / ap_search if needed.)";
	const sieveTag = sieveId ? ` | sieve=${sieveId}` : "";
	const errTag = isError ? " | ERROR" : "";
	return `${MASK_PREFIX} ${toolName} (${rawText.length} chars, ${lineCount} lines)${errTag}${sieveTag}]\nhead: ${head}${errBlock}\ntail: ${tail}\n${recovery}`;
}

/**
 * Compact, standalone branch serializer for `/ap handoff <goal>` (zero runtime SDK value imports).
 */
export function serializeBranchForHandoff(branch: ReadonlyArray<Record<string, unknown>>): string {
	if (!Array.isArray(branch) || branch.length === 0) return "";
	let startIdx = 0;
	for (let i = branch.length - 1; i >= 0; i--) {
		if (branch[i]?.type === "compaction") {
			startIdx = i;
			break;
		}
	}
	const chunks: string[] = [];
	for (let i = startIdx; i < branch.length; i++) {
		const e = branch[i];
		if (e?.type === "compaction" && typeof e.summary === "string") {
			chunks.push(`[Compaction Summary]\n${e.summary.slice(0, 4000)}`);
			continue;
		}
		if (e?.type !== "message" || !e.message || typeof e.message !== "object") continue;
		const m = e.message as {
			role?: string;
			toolName?: string;
			isError?: boolean;
			content?: string | Array<{ type?: string; text?: string; name?: string }>;
		};
		if (m.role === "user" || m.role === "assistant") {
			let txt = "";
			if (typeof m.content === "string") {
				txt = m.content;
			} else if (Array.isArray(m.content)) {
				const parts: string[] = [];
				for (const b of m.content) {
					if (b?.type === "text" && typeof b.text === "string") parts.push(b.text);
					else if (b?.type === "toolCall" && typeof b.name === "string") parts.push(`[call:${b.name}]`);
				}
				txt = parts.join("\n");
			}
			if (txt.trim()) chunks.push(`${m.role.toUpperCase()}: ${txt.trim().slice(0, 1200)}`);
		} else if (m.role === "toolResult" && m.isError) {
			const raw = Array.isArray(m.content)
				? m.content.map((b) => (typeof b.text === "string" ? b.text : "")).join("\n")
				: "";
			const errs = extractErrorSignatureLines(raw);
			chunks.push(`TOOL_ERROR(${m.toolName ?? "tool"}): ${(errs.join(" | ") || raw.slice(0, 240)).trim()}`);
		}
	}
	return chunks.join("\n\n").slice(-24000);
}

export interface ObservationMaskPlan {
	edits: ContextEditEntryDraft[];
	maskedCount: number;
	reclaimedChars: number;
	reason: string;
}

export interface ObservationMaskOptions {
	usagePercent?: number | null;
	usageTokens?: number | null;
	keepRecentEntries?: number;
	minEntryChars?: number;
	highWaterPercent?: number;
	highWaterTokens?: number;
	staleCharsFallback?: number;
	minBatchEntries?: number;
	minReclaimedChars?: number;
}

/**
 * Plan a single KV-cache-friendly batch of Pi v1.5 `context_edit` drafts to mask stale
 * oversized `toolResult` entries outside the recent active tail.
 * Never touches assistant messages, thinking/reasoning_content blocks, user turns, or images.
 */
export function planObservationMasking(
	contextEntries: readonly ProjectedSessionEntry[],
	options: ObservationMaskOptions = {},
): ObservationMaskPlan {
	const pct = typeof options.usagePercent === "number" ? options.usagePercent : null;
	const tok = typeof options.usageTokens === "number" ? options.usageTokens : null;
	const tier2 =
		options.minEntryChars === undefined &&
		((tok !== null && tok >= MASK_TIER2_TOKENS) || (pct !== null && pct >= MASK_TIER2_PCT));

	const keepRecent =
		options.keepRecentEntries ?? (tier2 ? MASK_TIER2_KEEP_RECENT : MASK_KEEP_RECENT_ENTRIES);
	const minChars =
		options.minEntryChars ?? (tier2 ? MASK_TIER2_MIN_ENTRY_CHARS : MASK_MIN_ENTRY_CHARS);
	const highPct = options.highWaterPercent ?? MASK_HIGH_WATER_PCT;
	const highTok = options.highWaterTokens ?? MASK_HIGH_WATER_TOKENS;
	const staleFallback = options.staleCharsFallback ?? MASK_STALE_CHARS_FALLBACK;
	const minEntries = options.minBatchEntries ?? MASK_MIN_BATCH_ENTRIES;
	const minReclaimed =
		options.minReclaimedChars ?? (tier2 ? MASK_TIER2_MIN_RECLAIMED : MASK_MIN_RECLAIMED_CHARS);

	if (!Array.isArray(contextEntries) || contextEntries.length <= keepRecent) {
		return { edits: [], maskedCount: 0, reclaimedChars: 0, reason: "too-few-entries" };
	}

	const scanLimit = contextEntries.length - keepRecent;
	const candidates: Array<{ targetId: string; toolName: string; rawText: string; isError: boolean }> = [];
	let totalStaleChars = 0;

	for (let i = 0; i < scanLimit; i++) {
		const proj = contextEntries[i];
		const src = proj?.sourceEntry as { id?: string; type?: string } | undefined;
		if (!src || src.type !== "message" || typeof src.id !== "string" || !src.id) continue;
		if (!Array.isArray(proj.messages) || proj.messages.length !== 1) continue;
		const msg = proj.messages[0] as {
			role?: string;
			toolName?: string;
			isError?: boolean;
			content?: Array<{ type?: string; text?: string }>;
		};
		if (msg?.role !== "toolResult" || !Array.isArray(msg.content) || msg.content.length === 0) {
			continue;
		}
		// Keep multimodal/image tool results untouched
		if (msg.content.some((b) => b?.type !== "text")) continue;
		const rawText = msg.content.map((b) => (typeof b.text === "string" ? b.text : "")).join("\n");
		if (rawText.length < minChars || rawText.startsWith(MASK_PREFIX)) continue;

		candidates.push({
			targetId: src.id,
			toolName: typeof msg.toolName === "string" && msg.toolName ? msg.toolName : "tool",
			rawText,
			isError: msg.isError === true,
		});
		totalStaleChars += rawText.length;
	}

	if (candidates.length < minEntries) {
		return { edits: [], maskedCount: 0, reclaimedChars: 0, reason: "below-min-entries" };
	}

	const pctTriggered = pct !== null && pct >= highPct;
	const tokTriggered = tok !== null && tok >= highTok;
	// Never let stale-payload fallback bust a hot <180k KV-cache when exact token count is known!
	const fallbackTriggered =
		(tok === null || tok >= highTok) && totalStaleChars >= staleFallback && candidates.length >= 4;

	if (!pctTriggered && !tokTriggered && !fallbackTriggered) {
		return { edits: [], maskedCount: 0, reclaimedChars: 0, reason: "below-high-water" };
	}

	const edits: ContextEditEntryDraft[] = [];
	let reclaimedChars = 0;
	for (const c of candidates) {
		const stub = formatMaskedToolResult(c.toolName, c.rawText, c.isError);
		const saved = c.rawText.length - stub.length;
		if (saved < 1000) continue;
		edits.push({
			type: "context_edit",
			targetId: c.targetId,
			replacement: { content: [{ type: "text", text: stub }] },
		});
		reclaimedChars += saved;
	}

	if (edits.length < minEntries || reclaimedChars < minReclaimed) {
		return { edits: [], maskedCount: 0, reclaimedChars: 0, reason: "savings-too-small" };
	}

	const reason = tier2
		? "tier2-peak-iq-guard"
		: tokTriggered
			? "high-water-tokens"
			: pctTriggered
				? "high-water-percent"
				: "stale-payload-fallback";
	return { edits, maskedCount: edits.length, reclaimedChars, reason };
}

export type DeepSeekEffort = "low" | "high" | "max";

const COMPLEX_PROMPT_RE =
	/\b(?:architect|architecture|refactor|redesign|concurrency|deadlock|race\s+condition|root\s+cause|debug|diagnose|profil|optimiz|benchmark|migrat|multi[- ]file|security|audit|algorithm|compil|memory\s+leak)\b|架构|重构|并发|死锁|根因|排查|定位|性能|优化|基准|迁移|跨文件|深度|设计|算法|泄漏/i;
const SIMPLE_PROMPT_RE =
	/^(?:hi|hello|hey|ok|okay|thanks|thank you|yes|no|lgtm|commit|push|status|git status|format|lint|run tests?|你好|好的|谢谢|提交|推送|跑测试|看状态)\b[\s!.。？?]*$/i;
const CONTINUATION_PROMPT_RE =
	/^(?:continue|proceed|resume|go(?:\s+ahead)?|keep\s+going|fix\s+(?:it|this|that)|继续|接着做)\b/i;
const BLOCKER_DIFF_KINDS = new Set([
	"SECRET-ADDED",
	"TEST-SKIPPED",
	"INCOMPLETE-STUB",
	"DEBUG-LEFTOVER",
]);
const CHECKABLE_CODE_EXT = /\.(?:rs|ts|tsx|js|jsx|mjs|cjs|py|go|c|cc|cpp|h|hpp|json|jsonc|toml)$/i;

/**
 * Deterministic <0.1ms effort selector for DeepSeek V4.1 Flash (`low` / `high` / `max`).
 * Avoids burning max-effort overthinking on trivial turns while preserving deep reasoning for complex work.
 */
export function classifyDeepSeekEffort(
	userText: string,
	ceiling: DeepSeekEffort = "max",
): DeepSeekEffort {
	if (ceiling === "low") return "low";
	const trimmed = (userText || "").trim();
	if (!trimmed) return "low";
	if (trimmed.length <= 80 && SIMPLE_PROMPT_RE.test(trimmed)) return "low";
	if (CONTINUATION_PROMPT_RE.test(trimmed)) return "high";
	const hasCodeBlock = trimmed.includes("```") || trimmed.includes("Error:") || trimmed.includes("Traceback");
	const lineCount = trimmed.split("\n").length;
	if (
		trimmed.length >= 240 ||
		lineCount >= 6 ||
		hasCodeBlock ||
		COMPLEX_PROMPT_RE.test(trimmed)
	) {
		return ceiling === "max" ? "max" : "high";
	}
	return "high";
}

export interface DeepSeekRouteInput {
	reason: "user" | "continuation" | "retry" | "direct";
	selectedLevel?: string;
	previousLevel?: string;
	userText?: string;
	recentToolErrors?: number;
	recentToolSuccessesAfterEdit?: number;
	stagnantHeavyTurns?: number;
	consecutiveLightTurns?: number;
	cachedPrefixTokens?: number;
}

/**
 * Detect deep-discount prefix-cache models (e.g. DeepSeek V4.1 Flash's 50:1 $0.30 vs $0.006/1M ratio)
 * where mid-prefix mutation (`context_edit` / effort-switch) costs 20-50x more than clean-slate resets.
 */
export function isDeepCacheDiscountModel(model?: {
	provider?: string;
	id?: string;
	cost?: { input?: number; cacheRead?: number };
}): boolean {
	if (!model) return false;
	const inp = Number(model.cost?.input ?? 0);
	const cr = Number(model.cost?.cacheRead ?? 0);
	if (inp > 0 && cr > 0 && inp / cr >= 20) return true;
	return isDeepSeekModel(model);
}

function clampDeepSeekEffort(raw?: string): DeepSeekEffort {
	if (raw === "low" || raw === "minimal" || raw === "off") return "low";
	if (raw === "max" || raw === "xhigh") return "max";
	return "high";
}

/**
 * KV-cache-preserving reasoning-effort router staying strictly on the SAME physical `deepseek-flash`
 * model. Locks effort once a hot cached prefix (>=16k tokens) is established because switching
 * `reasoning_effort` mid-session mutates token-0 template headers and busts 100% of DeepSeek KV-cache;
 * picks fresh effort cleanly on Turn 0 or right after a clean-slate compaction, and only breaks lock
 * on explicit retry or >=3 repeated tool errors.
 */
export function routeDeepSeekFlashEffort(input: DeepSeekRouteInput): {
	thinkingLevel: DeepSeekEffort;
	phase: string;
} {
	const ceiling = clampDeepSeekEffort(input.selectedLevel);
	if (input.reason === "direct") {
		return { thinkingLevel: "low", phase: "direct-summary" };
	}
	const prev = input.previousLevel ? clampDeepSeekEffort(input.previousLevel) : ceiling;
	const errs = input.recentToolErrors ?? 0;
	const hotPrefix = !!input.previousLevel && (input.cachedPrefixTokens ?? 0) >= 16000;
	if (input.reason === "retry") {
		const next: DeepSeekEffort = prev === "low" ? "high" : "max";
		return { thinkingLevel: next, phase: "retry-escalate" };
	}
	if (hotPrefix) {
		if (errs >= 3 && prev !== "max") {
			const next: DeepSeekEffort = prev === "low" ? "high" : "max";
			return { thinkingLevel: next, phase: "error-escalate" };
		}
		return { thinkingLevel: prev, phase: "cache-locked" };
	}
	if (input.reason === "user") {
		const chosen = classifyDeepSeekEffort(input.userText ?? "", ceiling);
		return { thinkingLevel: chosen, phase: `user-${chosen}` };
	}
	// continuation on cold/small prefix: escalate on repeated tool errors, cool down on stalls or routine loops
	if (errs >= 2) {
		const next: DeepSeekEffort = prev === "low" ? "high" : "max";
		return { thinkingLevel: next, phase: "error-escalate" };
	}
	if (
		prev === "max" &&
		((input.stagnantHeavyTurns ?? 0) >= 3 ||
			(input.recentToolSuccessesAfterEdit ?? 0) >= 2 ||
			(errs === 0 && (input.consecutiveLightTurns ?? 0) >= 4))
	) {
		return { thinkingLevel: "high", phase: "cool-down" };
	}
	return { thinkingLevel: prev, phase: "sticky" };
}

export interface DiffFindingItem {
	kind?: string;
	file?: string;
	detail?: string;
}

function normRelPath(p: string, cwd?: string): string {
	const clean = p.replace(/\\/g, "/").replace(/^\.\//, "");
	if (cwd) {
		const base = cwd.replace(/\\/g, "/").replace(/\/+$/, "") + "/";
		if (clean.toLowerCase().startsWith(base.toLowerCase())) {
			return clean.slice(base.length);
		}
	}
	return clean;
}

/**
 * Filter `ap guard diff --json` findings strictly to high-precision blockers inside files
 * edited during this agent run (eliminating false positives from pre-existing dirty files).
 */
export function filterSettleDiffBlockers(
	findings: readonly DiffFindingItem[],
	editedFiles: ReadonlySet<string>,
	cwd?: string,
): string[] {
	if (!Array.isArray(findings) || findings.length === 0 || editedFiles.size === 0) return [];
	const normEdited = new Set<string>();
	for (const f of editedFiles) {
		const rel = normRelPath(f, cwd).toLowerCase();
		if (rel) normEdited.add(rel);
	}
	const out: string[] = [];
	for (const item of findings) {
		const kind = String(item?.kind ?? "");
		if (!BLOCKER_DIFF_KINDS.has(kind)) continue;
		const file = normRelPath(String(item?.file ?? ""), cwd);
		if (!file) continue;
		const low = file.toLowerCase();
		const touched =
			normEdited.has(low) ||
			[...normEdited].some((e) => e.endsWith(`/${low}`) || low.endsWith(`/${e}`));
		if (!touched) continue;
		out.push(`- [${kind}] ${file}: ${String(item?.detail ?? "").slice(0, 160)}`);
	}
	return out.slice(0, 6);
}

function extractEditedPathsFromTool(toolName: string, input: Record<string, unknown> | undefined): string[] {
	if (!input) return [];
	const out: string[] = [];
	const pushStr = (v: unknown) => {
		if (typeof v === "string" && v.trim()) out.push(v.trim());
	};
	if (toolName === "write" || toolName === "edit") {
		pushStr(input.path ?? input.file_path);
	} else if (toolName === "ap_edit") {
		for (const key of ["writes", "edits", "appends", "symbols"]) {
			const arr = input[key];
			if (Array.isArray(arr)) {
				for (const item of arr) {
					if (item && typeof item === "object") pushStr((item as { path?: unknown }).path);
				}
			}
		}
	}
	return out;
}

let cachedPiBuiltinSetTimeout: boolean | null = null;
function detectPiBuiltinSetTimeout(): boolean {
	if (cachedPiBuiltinSetTimeout !== null) return cachedPiBuiltinSetTimeout;
	try {
		const cands = [
			process.env.PI_PACKAGE_DIR,
			process.env.APPDATA && join(process.env.APPDATA, "npm", "node_modules", "@earendil-works", "pi-coding-agent"),
			join(homedir(), ".npm-global", "lib", "node_modules", "@earendil-works", "pi-coding-agent"),
		].filter((p): p is string => Boolean(p));
		for (const root of cands) {
			const worker = join(root, "dist", "bundle", "chunks", "codemode-worker.js");
			if (existsSync(worker)) {
				const src = readFileSync(worker, "utf8");
				if (src.includes("globalThis, \"setTimeout\"") || src.includes("globalThis,\"setTimeout\"")) {
					cachedPiBuiltinSetTimeout = true;
					return true;
				}
			}
		}
	} catch {
		// ignore fs errors
	}
	cachedPiBuiltinSetTimeout = false;
	return false;
}

export default function (pi: ExtensionAPI) {
	const apProfileOverrides = loadApProfile();
	let peerClaimedCompaction = false;
	const evBusInit = (pi as { events?: { on?: (ch: string, fn: () => void) => void } }).events;
	if (typeof evBusInit?.on === "function") {
		evBusInit.on("ap:claim_compaction", () => {
			peerClaimedCompaction = true;
		});
	}
	let cachedCompactionTriggerKey = "";
	let cachedCompactionTriggerTokens: number | undefined = undefined;
	const getEffectiveMaskHighWaterTokens = (
		model?: { provider?: string; id?: string; contextWindow?: number; cost?: { input?: number; cacheRead?: number } },
	): number => {
		const mKey = model ? `${model.provider ?? ""}/${model.id ?? ""}` : "";
		if (mKey !== cachedCompactionTriggerKey) {
			cachedCompactionTriggerKey = mKey;
			cachedCompactionTriggerTokens = readModelCompactionTriggerTokens(model);
		}
		return resolveEffectiveMaskHighWaterTokens({
			deepCacheDiscount: isDeepCacheDiscountModel(model),
			profileMaskTokens: apProfileOverrides?.maskHighWaterTokens,
			compactionTriggerTokens: cachedCompactionTriggerTokens,
		});
	};
	const recentShellFps: string[] = [];
	const unchangedReads = new Map<string, number>();
	const outlinedPaths = new Set<string>();
	const editedFilesThisRun = new Set<string>();
	const builtInCodeEditsThisRun = new Set<string>();
	const largeOverwriteCallIds = new Set<string>();
	const clampedReadCallIds = new Map<string, { requestedOffset: number; clampedOffset: number; totalLines: number }>();
	let settleGateFiredThisRun = false;
	let stagnantHeavyTurns = 0;
	let consecutiveLightTurns = 0;
	let pendingThinkingNudge = false;
	let serialSingleToolTurns = 0;
	let lastBatchTipTurn = -BATCH_TIP_COOLDOWN_TURNS;
	let lastWriteTipTurn = -WRITE_TIP_COOLDOWN_TURNS;
	let pendingBatchNudge = false;
	let largeReadTipShown = false;
	let codemodeParallelTipsShown = 0;
	let readOnlyBashStreak = 0;
	let lastCodemodeParallelTipTurn = -CODEMODE_PARALLEL_COOLDOWN_TURNS;
	let sessionTurnCount = 0;
	let lastMaskTurn = -MASK_COOLDOWN_TURNS;
	let lastSeenCompactionId = "";
	let expectedCacheReset = false;
	let sessionInputTokens = 0;
	let sessionCacheReadTokens = 0;
	let lastKnownPromptTokens = 0;
	let lastCacheDropPct: number | null = null;
	let lastCacheDropCause = "";
	let prevRequestHashes: ProviderRequestHashes | null = null;
	let currRequestHashes: ProviderRequestHashes | null = null;
	let sievedCount = 0;
	let maskedCount = 0;
	let guardsTriggered = 0;
	let healedEditsCount = 0;
	let extCompactionsCount = 0;
	let cacheWarmsCount = 0;
	let totalToolTurns = 0;
	let serialSingleTotalTurns = 0;

	const resetRunState = () => {
		editedFilesThisRun.clear();
		builtInCodeEditsThisRun.clear();
		settleGateFiredThisRun = false;
	};

	const resetTransientState = () => {
		recentShellFps.length = 0;
		unchangedReads.clear();
		outlinedPaths.clear();
		largeOverwriteCallIds.clear();
		clampedReadCallIds.clear();
		resetRunState();
		stagnantHeavyTurns = 0;
		consecutiveLightTurns = 0;
		pendingThinkingNudge = false;
		serialSingleToolTurns = 0;
		lastBatchTipTurn = -BATCH_TIP_COOLDOWN_TURNS;
		lastWriteTipTurn = -WRITE_TIP_COOLDOWN_TURNS;
		pendingBatchNudge = false;
		sessionTurnCount = 0;
		lastMaskTurn = -MASK_COOLDOWN_TURNS;
		lastKnownPromptTokens = 0;
		lastCacheDropPct = null;
		lastCacheDropCause = "";
		prevRequestHashes = null;
		currRequestHashes = null;
	};

	// Opt-in Pi v1.5 virtual model: `deepseek/flash-auto` (same physical deepseek-flash, dynamic low/high/max effort)
	if (typeof pi.registerVirtualModel === "function") {
		pi.registerVirtualModel<{ phase: string; lastEffort: DeepSeekEffort }>({
			provider: "deepseek",
			id: "flash-auto",
			name: "DeepSeek Flash Auto-Effort (ap)",
			thinkingLevels: ["low", "high", "max"],
			contextWindow: 1000000,
			maxTokens: 384000,
			input: ["text", "image"],
			route(request, ctx) {
				const physical =
					ctx.modelRegistry.find("deepseek", "deepseek-flash") ?? request.previous?.model;
				if (!physical) {
					throw new Error("Physical model deepseek/deepseek-flash not found in Pi model registry");
				}
				let userText = "";
				let recentToolErrors = 0;
				let recentToolSuccessesAfterEdit = 0;
				if (Array.isArray(request.messages)) {
					for (let i = request.messages.length - 1; i >= 0; i--) {
						const m = request.messages[i] as {
							role?: string;
							content?: string | Array<{ type?: string; text?: string }>;
							isError?: boolean;
						};
						if (m.role === "user") {
							if (typeof m.content === "string") userText = m.content;
							else if (Array.isArray(m.content)) {
								userText = m.content
									.filter((b) => b?.type === "text" && typeof b.text === "string")
									.map((b) => b.text as string)
									.join("\n");
							}
							break;
						}
						if (m.role === "toolResult") {
							if (m.isError) recentToolErrors += 1;
							else if (editedFilesThisRun.size > 0) recentToolSuccessesAfterEdit += 1;
						}
					}
				}
				const decision = routeDeepSeekFlashEffort({
					reason: request.reason,
					selectedLevel: request.thinkingLevel,
					previousLevel: request.previous?.thinkingLevel ?? request.state?.lastEffort,
					userText,
					recentToolErrors,
					recentToolSuccessesAfterEdit,
					stagnantHeavyTurns,
					consecutiveLightTurns,
					cachedPrefixTokens: lastKnownPromptTokens,
				});
				const nextState =
					request.reason === "direct"
						? undefined
						: request.state?.phase === decision.phase &&
								request.state?.lastEffort === decision.thinkingLevel
							? request.state
							: { phase: decision.phase, lastEffort: decision.thinkingLevel };
				return {
					model: physical,
					thinkingLevel: decision.thinkingLevel,
					state: nextState,
				};
			},
		});
	}

	const updateHud = (ctx?: ExtensionContext) => {
		if (!ctx || !ctx.hasUI) return;
		const usage = ctx.getContextUsage?.();
		const pct = typeof usage?.percent === "number" ? Math.round(usage.percent) : null;
		const tok = typeof usage?.tokens === "number" ? usage.tokens : null;
		const tokLabel = tok !== null ? `${Math.round(tok / 1000)}k` : null;
		const parts: string[] = [];
		const totalPrompt = sessionInputTokens + sessionCacheReadTokens;
		if (lastCacheDropPct !== null) {
			parts.push(
				lastCacheDropCause
					? `CACHE DROP ${lastCacheDropPct}% [${lastCacheDropCause}]`
					: `CACHE DROP ${lastCacheDropPct}%`,
			);
		} else if (totalPrompt >= 10000) {
			const hitPct = Math.round((sessionCacheReadTokens / totalPrompt) * 100);
			parts.push(`cache ${hitPct}%`);
		}
		if (sievedCount > 0) parts.push(`${sievedCount} sieved`);
		if (maskedCount > 0) parts.push(`${maskedCount} masked`);
		if (guardsTriggered > 0) parts.push(`${guardsTriggered} guarded`);
		const effMaskHighWater = getEffectiveMaskHighWaterTokens(
			ctx.model as { provider?: string; id?: string; contextWindow?: number; cost?: { input?: number; cacheRead?: number } } | undefined,
		);
		const highWater =
			(pct !== null && pct >= MASK_HIGH_WATER_PCT) ||
			(tok !== null && tok >= effMaskHighWater);
		if (highWater) {
			parts.push(
				tokLabel && pct !== null
					? `CTX HIGH ${tokLabel} (${pct}%)`
					: pct !== null
						? `CTX HIGH ${pct}%`
						: `CTX HIGH ${tokLabel}`,
			);
		} else if ((pct !== null && pct >= 55) || (tok !== null && tok >= 120000)) {
			if (parts.length > 0 || (tok !== null && tok >= 120000)) {
				parts.push(tokLabel && pct !== null ? `ctx ${tokLabel} (${pct}%)` : `ctx ${pct ?? tokLabel}`);
			}
		}
		ctx.ui.setStatus("ap", parts.length > 0 ? `ap: ${parts.join(" | ")}` : undefined);
	};

	pi.on("session_start", (_event, ctx) => {
		resetTransientState();
		lastSeenCompactionId = "";
		largeReadTipShown = false;
		codemodeParallelTipsShown = 0;
		lastCodemodeParallelTipTurn = -CODEMODE_PARALLEL_COOLDOWN_TURNS;
		sessionInputTokens = 0;
		sessionCacheReadTokens = 0;
		expectedCacheReset = false;
		sievedCount = 0;
		maskedCount = 0;
		guardsTriggered = 0;
		healedEditsCount = 0;
		extCompactionsCount = 0;
		cacheWarmsCount = 0;
		totalToolTurns = 0;
		serialSingleTotalTurns = 0;
		updateHud(ctx);
	});

	pi.on("before_agent_start", (event, ctx) => {
		const m = ctx?.model;
		const isDs = isDeepSeekModel(m);
		if (isDs && Array.isArray(event?.systemPromptOptions?.promptGuidelines)) {
			const branch = ctx?.sessionManager?.getBranch?.() ?? [];
			const hasPriorAssistant =
				Array.isArray(branch) &&
				branch.some(
					(e: { type?: string; message?: { role?: string } }) =>
						e?.type === "message" && e.message?.role === "assistant",
				);
			const compatMid =
				(m as { compat?: { supportsMidConvoSystemMessages?: boolean } })?.compat
					?.supportsMidConvoSystemMessages === true;
			const alreadyHasApRule = event.systemPromptOptions.promptGuidelines.some(
				(g: string) => typeof g === "string" && g.includes("In codemode (QuickJS sandbox"),
			);
			// Inject on Turn 0 directly into messages[0]; on resumed sessions never emit redundant `rules` diffs!
			if (!hasPriorAssistant || (compatMid && !alreadyHasApRule)) {
				injectDeepSeekGuidelines(event.systemPromptOptions.promptGuidelines);
			}
		}
		return undefined;
	});

	pi.on("cache_warming_decision", (event, ctx) => {
		const override = decideDeepSeekCacheWarming({
			provider: ctx?.model?.provider,
			modelId: ctx?.model?.id,
			warmCost: event?.warmCost,
			missCost: event?.missCost,
			action: event?.action,
			isIdle: typeof ctx?.isIdle === "function" ? Boolean(ctx.isIdle()) : false,
		});
		if (override) {
			cacheWarmsCount += 1;
			return override;
		}
		return undefined;
	});

	pi.on("before_provider_request", (event) => {
		const nextPayload = stabilizeProviderTools(event?.payload);
		const inspected = nextPayload ?? event?.payload;
		const nextHashes = snapshotProviderRequestHashes(inspected);
		if (nextHashes) {
			// Update only currRequestHashes here; prevRequestHashes advances on `turn_end`
			// so mid-turn retries never overwrite the previous completed turn's baseline.
			currRequestHashes = nextHashes;
		}
		return nextPayload;
	});

	pi.on("agent_start", () => {
		resetRunState();
	});

	pi.on("session_before_switch", () => {
		resetTransientState();
		largeReadTipShown = false;
		codemodeParallelTipsShown = 0;
		lastCodemodeParallelTipTurn = -CODEMODE_PARALLEL_COOLDOWN_TURNS;
		sessionInputTokens = 0;
		sessionCacheReadTokens = 0;
		expectedCacheReset = false;
	});

	pi.on("session_compact", (event, ctx) => {
		if ((event as { fromExtension?: boolean } | undefined)?.fromExtension) {
			extCompactionsCount += 1;
		}
		resetTransientState();
		expectedCacheReset = true;
		updateHud(ctx);
	});

	pi.on("session_before_compact", async (event, ctx) => {
		// 1. Zero-clutter compaction sync: checkpoint `.baton` if the workspace already uses it
		let batonBrief = "";
		if (ctx?.cwd && existsSync(join(ctx.cwd, ".baton"))) {
			spawnSync(AP_BIN, ["baton", "checkpoint", "--note", "pi-compact"], {
				cwd: ctx.cwd,
				encoding: "utf8",
				timeout: 2500,
				windowsHide: true,
			});
			const bt = spawnSync(AP_BIN, ["baton", "resume"], {
				cwd: ctx.cwd,
				encoding: "utf8",
				timeout: 2000,
				windowsHide: true,
			});
			if (bt.status === 0 && bt.stdout?.trim()) {
				batonBrief = `\n\n## Baton Task State\n${bt.stdout.trim().slice(0, 1500)}`;
			}
			if (existsSync(join(ctx.cwd, ".baton", "frontier.json"))) {
				const fr = spawnSync(AP_BIN, ["baton", "frontier", "status", "-k", "4"], {
					cwd: ctx.cwd,
					encoding: "utf8",
					timeout: 2000,
					windowsHide: true,
				});
				if (fr.status === 0 && fr.stdout?.trim()) {
					batonBrief += `\n\n## Exploration Frontier\n${fr.stdout.trim().slice(0, 1000)}`;
				}
			}
		}
		if (
			shouldYieldCompaction({
				compactionClaimed: Boolean((event as { compactionClaimed?: boolean } | undefined)?.compactionClaimed),
				envYieldCompact: process.env.AP_YIELD_COMPACT,
				profileYieldCompact: apProfileOverrides?.yieldCompact,
				peerClaimed: peerClaimedCompaction,
			})
		) {
			return undefined;
		}

		// 2. Fast `reasoning: "low"` dead-end-preserving auto-compaction for DeepSeek models
		//    (5-10x faster than max-effort default compaction; safely falls back to Pi built-in on any issue)
		const model = ctx?.model;
		const prep = event?.preparation as {
			firstKeptEntryId?: string;
			messagesToSummarize?: Array<Record<string, unknown>>;
			turnPrefixMessages?: Array<Record<string, unknown>>;
			tokensBefore?: number;
			previousSummary?: string;
			fileOps?: { read?: Iterable<string>; written?: Iterable<string>; edited?: Iterable<string> };
		} | undefined;
		const isDeepSeek = isDeepSeekModel(model);
		const hasSimpleComplete =
			typeof ctx?.modelRegistry?.streamSimple === "function" ||
			typeof ctx?.modelRegistry?.complete === "function";
		if (
			!isDeepSeek ||
			!model ||
			!prep?.firstKeptEntryId ||
			typeof prep.tokensBefore !== "number" ||
			event?.signal?.aborted ||
			!hasSimpleComplete
		) {
			return undefined;
		}

		try {
			const modSet = new Set<string>([
				...(prep.fileOps?.written ? [...prep.fileOps.written] : []),
				...(prep.fileOps?.edited ? [...prep.fileOps.edited] : []),
			]);
			const readFiles = prep.fileOps?.read
				? [...prep.fileOps.read].filter((f) => !modSet.has(f)).sort()
				: [];
			const modifiedFiles = [...modSet].sort();
			const storeKeys = listCodemodeStoreKeys(
				(event.branchEntries ?? []) as unknown as Array<Record<string, unknown>>,
			);
			const allMsgs = [
				...(Array.isArray(prep.messagesToSummarize) ? prep.messagesToSummarize : []),
				...(Array.isArray(prep.turnPrefixMessages) ? prep.turnPrefixMessages : []),
			];
			if (allMsgs.length === 0) return undefined;
			const serialized = serializeMessagesForCompaction(
				allMsgs,
				prep.previousSummary,
				readFiles,
				modifiedFiles,
				storeKeys,
			);
			const extraInstr = event.customInstructions?.trim()
				? `\n\n## Additional Focus\n${event.customInstructions.trim()}`
				: "";
			let summary = await summarizeTranscriptLowReasoning(
				ctx,
				model,
				`${serialized}${batonBrief}${extraInstr}`,
				event.signal,
			);
			if (!summary || summary.length < 40) return undefined;
			if (readFiles.length > 0) {
				summary += `\n\n<read-files>\n${readFiles.join("\n")}\n</read-files>`;
			}
			if (modifiedFiles.length > 0) {
				summary += `\n\n<modified-files>\n${modifiedFiles.join("\n")}\n</modified-files>`;
			}
			if (storeKeys.length > 0) {
				summary += `\n\n<codemode-store-keys>\n${storeKeys.join(", ")}\n</codemode-store-keys>`;
			}
			return {
				compaction: {
					summary,
					firstKeptEntryId: prep.firstKeptEntryId,
					tokensBefore: prep.tokensBefore,
					details: { readFiles, modifiedFiles },
				},
			};
		} catch {
			// Fall back cleanly to Pi's built-in compactor
			return undefined;
		}
	});

	async function summarizeTranscriptLowReasoning(
		ctx: ExtensionContext,
		model: NonNullable<ExtensionContext["model"]>,
		promptText: string,
		signal?: AbortSignal,
	): Promise<string | undefined> {
		const compCtx = {
			systemPrompt:
				"You are a context compaction summarizer for a coding agent. Output ONLY a crisp, structured handoff summary with these exact headings: ## Goal & Constraints, ## Verified Facts & Progress, ## Falsified Dead-Ends (DO NOT RETRY), ## Key Decisions & File Map, ## Next Immediate Action. Preserve exact file paths, symbol names, build/test commands, and error signatures. Do NOT continue the conversation.",
			messages: [
				{
					role: "user" as const,
					content: [{ type: "text" as const, text: promptText }],
					timestamp: Date.now(),
				},
			],
		};
		const compOpts = {
			reasoning: "low" as const,
			maxTokens: 6144,
			cacheRetention: "none" as const,
			signal,
			timeoutMs: 45000,
			maxAttempts: 2,
		};
		// Use `streamSimple().result()` (NOT `complete()`): in Pi v1.5+, `complete()` bypasses
		// `streamSimple`, dropping `reasoning` effort mapping and rejecting virtual models like `flash-auto`.
		const response = await callSubLlmWithRetry(
			ctx as Parameters<typeof callSubLlmWithRetry>[0],
			model as Parameters<typeof callSubLlmWithRetry>[1],
			compCtx,
			compOpts,
		);
		if (
			!response ||
			response.stopReason === "error" ||
			response.stopReason === "aborted" ||
			response.stopReason === "length"
		) {
			return undefined;
		}
		const respContent = Array.isArray(response.content) ? response.content : [];
		return respContent
			.filter((c): c is { type: "text"; text: string } => c?.type === "text" && typeof c.text === "string")
			.map((c) => c.text)
			.join("\n")
			.trim();
	}

	pi.on("session_before_tree", async (event, ctx) => {
		// Keep branch-switch summaries fast & sharp (reasoning: "low" summary when DeepSeek + modelRegistry exist,
		// falling back cleanly to customInstructions with verified facts, dead-ends & active codemode-store keys)
		const branch = ctx?.sessionManager?.getBranch?.() ?? [];
		const storeKeys = listCodemodeStoreKeys(branch as unknown as Array<Record<string, unknown>>);
		const storeAnchor =
			storeKeys.length > 0
				? ` Note active codemode-store keys recoverable via load(key): [${storeKeys.slice(0, 12).join(", ")}].`
				: "";
		const fallback = {
			customInstructions:
				`Preserve exact file paths, symbol names, verified facts, falsified hypotheses/dead-ends, and exact failing error signatures so the target branch never repeats failed attempts.${storeAnchor}`,
		};
		const prep = (event as { preparation?: { entriesToSummarize?: Array<Record<string, unknown>>; customInstructions?: string; userWantsSummary?: boolean }; signal?: AbortSignal } | undefined)?.preparation;
		const signal = (event as { signal?: AbortSignal } | undefined)?.signal;
		const model = ctx?.model;
		const isDeepSeek = isDeepSeekModel(model);
		const hasSimpleComplete =
			typeof ctx?.modelRegistry?.streamSimple === "function" ||
			typeof ctx?.modelRegistry?.complete === "function";
		if (
			prep?.userWantsSummary === false ||
			!isDeepSeek ||
			!model ||
			!hasSimpleComplete ||
			signal?.aborted
		) {
			return fallback;
		}
		const entries = Array.isArray(prep?.entriesToSummarize) && prep.entriesToSummarize.length > 0
			? prep.entriesToSummarize
			: (branch as unknown as Array<Record<string, unknown>>);
		const rawMsgs = entries
			.map((e) => ((e as { message?: Record<string, unknown> })?.message ?? e))
			.filter((m) => m && typeof m === "object");
		if (rawMsgs.length === 0) return fallback;
		try {
			const serialized = serializeMessagesForCompaction(rawMsgs, undefined, [], [], storeKeys);
			const extra = prep?.customInstructions?.trim()
				? `\n\n## Additional Focus\n${prep.customInstructions.trim()}`
				: "";
			let summary = await summarizeTranscriptLowReasoning(
				ctx,
				model,
				`${serialized}${extra}`,
				signal,
			);
			if (!summary || summary.length < 40) return fallback;
			if (storeKeys.length > 0) {
				summary += `\n\n<codemode-store-keys>\n${storeKeys.join(", ")}\n</codemode-store-keys>`;
			}
			return { summary };
		} catch {
			return fallback;
		}
	});

	// Zero-prompt-token interactive `/ap` command inside Pi (`/ap`, `status`, `doctor`, `compact`, `handoff <goal>`)
	if (typeof pi.registerCommand === "function") {
		pi.registerCommand("ap", {
			description: "Live ap + DeepSeek KV-cache telemetry, doctor, focused compact, clean-session handoff, or independent diff review",
			getArgumentCompletions(prefix: string) {
				const items = [
					{ value: "status", label: "status — Live KV-cache, masking, edit-heal & codemode-store telemetry" },
					{ value: "doctor", label: "doctor — Run native ap doctor health check" },
					{ value: "compact", label: "compact — Compact while anchoring verified facts & dead-ends" },
					{ value: "fresh ", label: "fresh [goal] — Instant 0-history linked session seeded with .baton & frontier" },
					{ value: "handoff ", label: "handoff <goal> — Transfer context cleanly to a fresh 0-rot session" },
					{ value: "review", label: "review [focus] — Independent clean-context diff review (0 parent bloat)" },
				];
				const p = (prefix || "").trim().toLowerCase();
				return p ? items.filter((it) => it.value.trim().startsWith(p)) : items;
			},
			async handler(args, ctx) {
				const rawArgs = (args || "").trim();
				const firstSpace = rawArgs.indexOf(" ");
				const sub = (firstSpace >= 0 ? rawArgs.slice(0, firstSpace) : rawArgs).toLowerCase() || "status";
				const rest = firstSpace >= 0 ? rawArgs.slice(firstSpace + 1).trim() : "";

				if (sub === "doctor") {
					const res = spawnSync(AP_BIN, ["doctor"], {
						cwd: ctx.cwd,
						encoding: "utf8",
						timeout: 5000,
						windowsHide: true,
					});
					const summary = (res.stdout || res.stderr || "ap doctor failed")
						.trim()
						.split("\n")
						.slice(0, 12)
						.join("\n");
					ctx.ui.notify(summary, res.status === 0 ? "info" : "warning");
					return;
				}
				if (sub === "compact") {
					const branch = ctx.sessionManager?.getBranch?.() ?? [];
					const storeKeys = listCodemodeStoreKeys(branch as unknown as Array<Record<string, unknown>>);
					const storeAnchor =
						storeKeys.length > 0
							? ` Preserve active codemode-store keys recoverable via load(key): [${storeKeys.slice(0, 12).join(", ")}].`
							: "";
					ctx.compact({
						customInstructions:
							`Preserve exact file paths, symbol names, verified facts, falsified dead-ends, and exact build/test commands needed to continue cleanly.${storeAnchor}`,
					});
					ctx.ui.notify("[ap] Triggered focused compaction preserving verified facts, dead-ends & store keys.", "info");
					return;
				}
				if (sub === "fresh") {
					const parentSession = ctx.sessionManager?.getSessionFile?.();
					const seedParts: string[] = [];
					if (ctx.cwd && existsSync(join(ctx.cwd, ".baton"))) {
						const bt = spawnSync(AP_BIN, ["baton", "resume"], {
							cwd: ctx.cwd,
							encoding: "utf8",
							timeout: 2000,
							windowsHide: true,
						});
						if (bt.status === 0 && bt.stdout?.trim()) {
							seedParts.push(bt.stdout.trim().slice(0, 1500));
						}
						if (existsSync(join(ctx.cwd, ".baton", "frontier.json"))) {
							const fr = spawnSync(AP_BIN, ["baton", "frontier", "status", "-k", "5"], {
								cwd: ctx.cwd,
								encoding: "utf8",
								timeout: 2000,
								windowsHide: true,
							});
							if (fr.status === 0 && fr.stdout?.trim()) {
								seedParts.push(fr.stdout.trim().slice(0, 1200));
							}
						}
					}
					const kickoff = [rest || "Continue from the clean-slate frontier above.", ...seedParts].join("\n\n").trim();
					if (typeof ctx.newSession === "function") {
						await ctx.newSession({
							parentSession,
							withSession: async (nextCtx) => {
								if (rest && typeof nextCtx.sendUserMessage === "function") {
									await nextCtx.sendUserMessage(kickoff);
								} else {
									nextCtx.ui.setEditorText(kickoff);
								}
								nextCtx.ui.notify("[ap fresh] Started 0-history child session linked to parent.", "info");
							},
						});
					} else {
						ctx.ui.setEditorText?.(kickoff);
					}
					return;
				}
				if (sub === "handoff") {
					if (!rest) {
						ctx.ui.notify("Usage: /ap handoff <goal for the new focused session>", "warning");
						return;
					}
					if (!ctx.model) {
						ctx.ui.notify("[ap handoff] No active model selected.", "error");
						return;
					}
					const branch = ctx.sessionManager?.getBranch?.() ?? [];
					const transcript = serializeBranchForHandoff(branch as unknown as Array<Record<string, unknown>>);
					if (!transcript) {
						ctx.ui.notify("[ap handoff] Current branch has no messages to transfer.", "warning");
						return;
					}
					let envFacts = "";
					if (ctx.cwd && existsSync(join(ctx.cwd, ".git"))) {
						const gs = spawnSync("git", ["status", "--short"], {
							cwd: ctx.cwd,
							encoding: "utf8",
							timeout: 2000,
							windowsHide: true,
						});
						if (gs.status === 0 && gs.stdout?.trim()) {
							envFacts += `\n\n## Modified Files (git status)\n${gs.stdout.trim().slice(0, 1500)}`;
						}
					}
					if (ctx.cwd && existsSync(join(ctx.cwd, ".baton"))) {
						const bt = spawnSync(AP_BIN, ["baton", "resume"], {
							cwd: ctx.cwd,
							encoding: "utf8",
							timeout: 2000,
							windowsHide: true,
						});
						if (bt.status === 0 && bt.stdout?.trim()) {
							envFacts += `\n\n## Baton State\n${bt.stdout.trim().slice(0, 1500)}`;
						}
					}
					ctx.ui.notify("[ap handoff] Generating clean transfer brief (low effort)...", "info");
					try {
						const handoffCtx = {
							systemPrompt:
								"Generate a concise, self-contained handoff prompt for a brand-new coding-agent session. Include: ## Context (verified facts & key decisions), ## Falsified Dead-Ends (what NOT to retry), ## Relevant Files, and ## Next Task. Output ONLY the prompt itself.",
							messages: [
								{
									role: "user" as const,
									content: [
										{
											type: "text" as const,
											text: `## Conversation Branch\n${transcript}${envFacts}\n\n## Goal For New Session\n${rest}`,
										},
									],
									timestamp: Date.now(),
								},
							],
						};
						const handoffOpts = {
							reasoning: "low" as const,
							maxTokens: 6144,
							cacheRetention: "none" as const,
							timeoutMs: 45000,
							maxAttempts: 2,
						};
						const response = await callSubLlmWithRetry(
							ctx as Parameters<typeof callSubLlmWithRetry>[0],
							ctx.model as Parameters<typeof callSubLlmWithRetry>[1],
							handoffCtx,
							handoffOpts,
						);
						const respBlocks = Array.isArray(response?.content) ? response.content : [];
						const draft = respBlocks
							.filter((c): c is { type: "text"; text: string } => c?.type === "text" && typeof c.text === "string")
							.map((c) => c.text)
							.join("\n")
							.trim();
						if (!draft) {
							ctx.ui.notify("[ap handoff] Empty response from model.", "warning");
							return;
						}
						const edited =
							typeof ctx.ui.editor === "function"
								? await ctx.ui.editor("Review /ap handoff prompt", draft)
								: draft;
						if (edited === undefined) {
							ctx.ui.notify("[ap handoff] Cancelled.", "info");
							return;
						}
						const parentSession = ctx.sessionManager?.getSessionFile?.();
						if (typeof ctx.newSession === "function") {
							await ctx.newSession({
								parentSession,
								withSession: async (nextCtx) => {
									nextCtx.ui.setEditorText(edited);
									nextCtx.ui.notify("[ap handoff] Fresh session ready — press Enter to start!", "info");
								},
							});
						} else {
							ctx.ui.setEditorText?.(edited);
						}
					} catch (err) {
						ctx.ui.notify(
							`[ap handoff] Failed: ${err instanceof Error ? err.message : String(err)}`,
							"error",
						);
					}
					return;
				}
				if (sub === "review") {
					if (!ctx.model) {
						ctx.ui.notify("[ap review] No active model selected.", "error");
						return;
					}
					const cwd = ctx.cwd || process.cwd();
					if (!existsSync(join(cwd, ".git"))) {
						ctx.ui.notify("[ap review] Current directory is not a Git repository.", "warning");
						return;
					}
					let diffText = "";
					const d1 = spawnSync("git", ["diff", "HEAD"], {
						cwd,
						encoding: "utf8",
						timeout: 4000,
						windowsHide: true,
					});
					if (d1.status === 0 && d1.stdout?.trim()) {
						diffText = d1.stdout.trim();
					} else {
						const d2 = spawnSync("git", ["diff", "HEAD~1..HEAD"], {
							cwd,
							encoding: "utf8",
							timeout: 4000,
							windowsHide: true,
						});
						if (d2.status === 0 && d2.stdout?.trim()) {
							diffText = d2.stdout.trim();
						}
					}
					if (!diffText) {
						ctx.ui.notify("[ap review] No uncommitted or HEAD~1 diff found to review.", "info");
						return;
					}
					let guardSummary = "";
					const gd = spawnSync(AP_BIN, ["guard", "diff", "--json", cwd], {
						cwd,
						encoding: "utf8",
						timeout: 3000,
						windowsHide: true,
					});
					if (gd.status === 0 && gd.stdout?.trim()) {
						guardSummary = `\n\n## Automated ap guard diff Findings\n${gd.stdout.trim().slice(0, 3000)}`;
					}
					ctx.ui.notify("[ap review] Running isolated skeptical diff review (0 parent context bloat)...", "info");
					try {
						const focusLine = rest ? `\n\n## Specific Review Focus\n${rest}` : "";
						// Unwrap virtual `flash-auto` -> physical `deepseek-flash` via callSubLlmWithRetry({ unwrapVirtual: true }) so `/ap review` always runs at true `high` effort
						const reviewCtx = {
							systemPrompt:
								"You are an independent, skeptical senior code reviewer seeing this Git diff with fresh eyes (zero bias from the author). Identify ONLY concrete, verified defects: logic bugs, edge cases, regressions, missing error handling, concurrency/resource leaks, or skipped/weak tests. Cite exact file:line. If the diff is solid, say LGTM concisely.",
							messages: [
								{
									role: "user" as const,
									content: [
										{
											type: "text" as const,
											text: `## Git Diff\n\`\`\`diff\n${diffText.slice(0, 24000)}\n\`\`\`${guardSummary}${focusLine}`,
										},
									],
									timestamp: Date.now(),
								},
							],
						};
						const reviewOpts = {
							reasoning: "high" as const,
							maxTokens: 8192,
							cacheRetention: "none" as const,
							timeoutMs: 60000,
							maxAttempts: 2,
							unwrapVirtual: true,
						};
						const response = await callSubLlmWithRetry(
							ctx as Parameters<typeof callSubLlmWithRetry>[0],
							ctx.model as Parameters<typeof callSubLlmWithRetry>[1],
							reviewCtx,
							reviewOpts,
						);
						const reviewBlocks = Array.isArray(response?.content) ? response.content : [];
						const report = reviewBlocks
							.filter((c): c is { type: "text"; text: string } => c?.type === "text" && typeof c.text === "string")
							.map((c) => c.text)
							.join("\n")
							.trim();
						if (!report) {
							ctx.ui.notify("[ap review] Reviewer returned empty response.", "warning");
							return;
						}
						if (typeof ctx.ui.editor === "function") {
							await ctx.ui.editor("Independent /ap review findings (Esc to close)", report);
						} else {
							ctx.ui.notify(report.slice(0, 2000), "info");
						}
					} catch (err) {
						ctx.ui.notify(
							`[ap review] Failed: ${err instanceof Error ? err.message : String(err)}`,
							"error",
						);
					}
					return;
				}

				const usage = ctx.getContextUsage?.();
				const totalPrompt = sessionInputTokens + sessionCacheReadTokens;
				const hitPct =
					totalPrompt > 0 ? ((sessionCacheReadTokens / totalPrompt) * 100).toFixed(1) : "n/a";
				// DeepSeek V4.1 Flash savings: ($0.30 - $0.006) / 1M = $0.294 per 1M cacheRead tokens
				const estUsdSaved = ((sessionCacheReadTokens / 1_000_000) * 0.294).toFixed(4);
				const ctxStr =
					typeof usage?.tokens === "number"
						? `${Math.round(usage.tokens / 1000)}k (${Math.round(usage.percent ?? 0)}%)`
						: "n/a";
				const modelStr = ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : "unknown";
				const serialPct =
					totalToolTurns > 0 ? `${Math.round((serialSingleTotalTurns / totalToolTurns) * 100)}%` : "n/a";
				const branch = ctx.sessionManager?.getBranch?.() ?? [];
				const storeKeys = countCodemodeStoreKeys(branch as unknown as Array<Record<string, unknown>>);
				const compactSuffix = extCompactionsCount > 0 ? ` extCompacts=${extCompactionsCount}` : "";
				const warmSuffix = cacheWarmsCount > 0 ? ` cacheWarms=${cacheWarmsCount}` : "";
				const effMaskTok = getEffectiveMaskHighWaterTokens(
					ctx.model as { provider?: string; id?: string; contextWindow?: number; cost?: { input?: number; cacheRead?: number } } | undefined,
				);
				ctx.ui.notify(
					`[ap telemetry] model=${modelStr} | ctx=${ctxStr} (mask@${Math.round(effMaskTok / 1000)}k) | cache=${hitPct}% (saved ~$${estUsdSaved}) | sieved=${sievedCount} masked=${maskedCount} healedEdits=${healedEditsCount} guarded=${guardsTriggered}${compactSuffix}${warmSuffix} | serial1=${serialPct} storeKeys=${storeKeys}`,
					"info",
				);
			},
		});
	}

	pi.on("message_end", (event) => {
		const msg = event.message as {
			role?: string;
			stopReason?: string;
			content?: Array<{ type?: string; text?: string; name?: string; arguments?: unknown; [k: string]: unknown }>;
		} | undefined;
		if (!msg || msg.role !== "assistant" || !Array.isArray(msg.content)) return undefined;

		const active = new Set(pi.getActiveTools?.() ?? []);
		if (active.size === 0) return undefined;

		// 1. Repair hallucinated native toolCall names AND heal parameter aliases on already-active native tools
		if (msg.content.some((b) => b?.type === "toolCall")) {
			let repairedAny = false;
			const repairedContent = msg.content.map((blk) => {
				if (blk?.type === "toolCall" && typeof blk.name === "string") {
					if (!active.has(blk.name)) {
						const fixedName = repairHallucinatedToolName(blk.name, active);
						if (fixedName) {
							repairedAny = true;
							return {
								...blk,
								name: fixedName,
								arguments: normalizeRepairedToolArgs(fixedName, blk.arguments).args,
							};
						}
					} else {
						const norm = normalizeRepairedToolArgs(blk.name, blk.arguments);
						if (norm.changed) {
							repairedAny = true;
							return {
								...blk,
								arguments: norm.args,
							};
						}
					}
				}
				return blk;
			});
			if (!repairedAny) return undefined;
			guardsTriggered += 1;
			return {
				message: {
					...(msg as Record<string, unknown>),
					content: repairedContent,
				} as typeof event.message,
			};
		}

		let recoveredAny = false;
		const nextContent: Array<Record<string, unknown>> = [];
		for (const blk of msg.content) {
			if (blk?.type === "text" && typeof blk.text === "string") {
				const rec =
					(blk.text.includes("DSML") ? extractDsmlToolCalls(blk.text, active) : undefined) ??
					(blk.text.includes("<tool_call>") ? extractXmlJsonToolCalls(blk.text, active) : undefined);
				if (rec) {
					recoveredAny = true;
					if (rec.cleanedText) {
						nextContent.push({ ...blk, text: rec.cleanedText });
					}
					for (const call of rec.calls) {
						nextContent.push(call as unknown as Record<string, unknown>);
					}
					continue;
				}
			}
			nextContent.push(blk as Record<string, unknown>);
		}
		if (!recoveredAny) return undefined;
		guardsTriggered += 1;
		return {
			message: {
				...(msg as Record<string, unknown>),
				...(msg.stopReason !== "length" ? { stopReason: "toolUse" } : {}),
				content: nextContent,
			} as typeof event.message,
		};
	});

	// Scrub leaked unparsed DSML / <tool_call> XML text on assistant messages without toolCall blocks before provider request
	pi.on("context", (event) => {
		const msgs = (event as { messages?: Array<Record<string, unknown>> } | undefined)?.messages;
		if (!Array.isArray(msgs) || msgs.length === 0) return undefined;
		let changed = false;
		const nextMessages = msgs.map((m) => {
			if (!m || m.role !== "assistant" || !Array.isArray(m.content)) return m;
			const content = m.content as Array<{ type?: string; text?: string; [k: string]: unknown }>;
			if (content.some((b) => b?.type === "toolCall")) return m;
			let msgChanged = false;
			const nextBlocks = content.map((b) => {
				if (b?.type === "text" && typeof b.text === "string" && (b.text.includes("DSML") || b.text.includes("<tool_call>"))) {
					const scrubbed = scrubLeakedToolMarkup(b.text);
					if (scrubbed !== b.text) {
						msgChanged = true;
						return { ...b, text: scrubbed };
					}
				}
				return b;
			});
			if (!msgChanged) return m;
			changed = true;
			return { ...m, content: nextBlocks };
		});
		return changed ? { messages: nextMessages } : undefined;
	});

	pi.on("turn_end", (event, ctx) => {
		const firstCtxEntry = event.context?.contextEntries?.[0]?.sourceEntry as { id?: string; type?: string } | undefined;
		if (firstCtxEntry?.type === "compaction" && typeof firstCtxEntry.id === "string" && firstCtxEntry.id !== lastSeenCompactionId) {
			lastSeenCompactionId = firstCtxEntry.id;
			resetTransientState();
			expectedCacheReset = true;
		}
		sessionTurnCount += 1;
		const msg = event.message as {
			role?: string;
			content?: Array<{ type?: string; thinking?: string; name?: string }>;
			usage?: { input?: number; cacheRead?: number };
		} | undefined;
		let turnPrompt = 0;
		let justRebuiltColdCache = false;
		if (msg?.role === "assistant" && Array.isArray(msg.content)) {
			// Live DeepSeek 50x KV-cache hit-rate telemetry & unexpected drop alarm
			const uIn = typeof msg.usage?.input === "number" ? msg.usage.input : 0;
			const uCache = typeof msg.usage?.cacheRead === "number" ? msg.usage.cacheRead : 0;
			turnPrompt = uIn + uCache;
			if (turnPrompt > 0) {
				sessionInputTokens += uIn;
				sessionCacheReadTokens += uCache;
				const turnHitPct = Math.round((uCache / turnPrompt) * 100);
				if (turnPrompt >= 20000 && turnHitPct < 45 && !expectedCacheReset) {
					lastCacheDropPct = turnHitPct;
					lastCacheDropCause = classifyCacheDropCause(prevRequestHashes, currRequestHashes);
					const evBus = (pi as { events?: { emit?: (ch: string, d: unknown) => void } }).events;
					if (typeof evBus?.emit === "function") {
						evBus.emit("ap:cache_drop", {
							turn: sessionTurnCount,
							hitPct: turnHitPct,
							promptTokens: turnPrompt,
							cause: lastCacheDropCause,
						});
					}
				} else if (turnHitPct >= 60) {
					lastCacheDropPct = null;
					lastCacheDropCause = "";
				}
				if (turnPrompt >= FREE_MASK_MIN_TOKENS && turnHitPct < 55 && !expectedCacheReset) {
					justRebuiltColdCache = true;
				}
				expectedCacheReset = false;
				if (currRequestHashes) {
					prevRequestHashes = currRequestHashes;
				}
			}

			let thinkChars = 0;
			let didEdit = false;
			let toolCallCount = 0;
			let singleToolName = "";
			for (const blk of msg.content) {
				if (blk?.type === "thinking" && typeof blk.thinking === "string") {
					thinkChars += blk.thinking.length;
				} else if (blk?.type === "toolCall" && typeof blk.name === "string") {
					toolCallCount += 1;
					singleToolName = blk.name;
					if (EDIT_TOOLS.has(blk.name)) {
						didEdit = true;
					}
				}
			}
			const hadToolError = Array.isArray(event.toolResults)
				? event.toolResults.some((r: { isError?: boolean }) => r?.isError === true)
				: false;
			if (hadToolError || didEdit || thinkChars >= HEAVY_THINKING_CHARS) {
				consecutiveLightTurns = 0;
			} else if (toolCallCount > 0 && thinkChars < LIGHT_THINKING_CHARS) {
				consecutiveLightTurns += 1;
			} else {
				consecutiveLightTurns = 0;
			}
			if (toolCallCount > 0) {
				totalToolTurns += 1;
				if (toolCallCount === 1) serialSingleTotalTurns += 1;
			}
			if (toolCallCount === 1 && SERIAL_BATCHABLE_TOOLS.has(singleToolName) && !didEdit && !hadToolError) {
				serialSingleToolTurns += 1;
				if (
					serialSingleToolTurns >= SERIAL_BATCH_THRESHOLD &&
					sessionTurnCount - lastBatchTipTurn >= BATCH_TIP_COOLDOWN_TURNS
				) {
					pendingBatchNudge = true;
					lastBatchTipTurn = sessionTurnCount;
				}
			} else if (toolCallCount !== 1 || didEdit || hadToolError || singleToolName === "codemode") {
				serialSingleToolTurns = 0;
			}
			if (didEdit) {
				stagnantHeavyTurns = 0;
				pendingThinkingNudge = false;
			} else if (thinkChars >= HEAVY_THINKING_CHARS) {
				stagnantHeavyTurns += 1;
				if (stagnantHeavyTurns >= STAGNATION_TURNS) {
					pendingThinkingNudge = true;
				}
			} else {
				stagnantHeavyTurns = Math.max(0, stagnantHeavyTurns - 1);
			}
		}

		// Native Pi v1.5 batch observation masking using monotonic sessionTurnCount
		// (Pi resets event.turnIndex=0 on each agent_start). Protect a brand-new cache right after
		// a cold turn paid full price to rebuild it, AND on 50:1 deep-cache-discount models (e.g. DeepSeek Flash)
		// defer mid-prefix context_edit until emergency >=210k so normal 0-160k runs keep 99.5%+ pure KV-cache hits!
		const contextEntries = event.context?.contextEntries;
		const usage = ctx?.getContextUsage?.();
		const effTokens = usage?.tokens ?? (turnPrompt > 0 ? turnPrompt : null);
		if (typeof effTokens === "number" && effTokens > 0) {
			lastKnownPromptTokens = effTokens;
		}
		const deepCacheDiscount = isDeepCacheDiscountModel(
			ctx?.model as { provider?: string; id?: string; cost?: { input?: number; cacheRead?: number } } | undefined,
		);
		const effCooldown = deepCacheDiscount ? 25 : MASK_COOLDOWN_TURNS;
		const cooldownReady = sessionTurnCount - lastMaskTurn >= effCooldown;
		const protectFreshColdRebuild =
			justRebuiltColdCache && (effTokens === null || effTokens < MASK_TIER2_TOKENS);
		if (Array.isArray(contextEntries) && cooldownReady && !protectFreshColdRebuild) {
			const basePlanOpts = deepCacheDiscount
				? { highWaterTokens: 210000, highWaterPercent: 85, staleCharsFallback: 360000 }
				: {};
			const effMaskHighWater = getEffectiveMaskHighWaterTokens(
				ctx?.model as { provider?: string; id?: string; contextWindow?: number; cost?: { input?: number; cacheRead?: number } } | undefined,
			);
			const maskOpts = {
				...basePlanOpts,
				highWaterTokens: effMaskHighWater,
			};
			const plan = planObservationMasking(contextEntries, {
				usagePercent: usage?.percent ?? null,
				usageTokens: effTokens,
				...maskOpts,
			});
			if (plan.edits.length > 0) {
				lastMaskTurn = sessionTurnCount;
				maskedCount += plan.maskedCount;
				expectedCacheReset = true;
				updateHud(ctx);
				return {
					entries: [...(event.entries ?? []), ...plan.edits],
				};
			}
		}

		updateHud(ctx);
		return undefined;
	});

	pi.on("agent_before_settle", (event, ctx) => {
		if (event.outcome !== "completed" || settleGateFiredThisRun) {
			return undefined;
		}
		if (Array.isArray(event.entries) && event.entries.some((e) => e?.type === "compaction")) {
			editedFilesThisRun.clear();
			builtInCodeEditsThisRun.clear();
			return undefined;
		}
		if (
			(event as { continue?: boolean }).continue === true ||
			(Array.isArray(event.entries) && event.entries.length > 0)
		) {
			return undefined;
		}

		// 0. Recover silent thinking-only stall (assistant emitted thinking with 0 text & 0 toolCalls)
		const ctxMsgs = event.context?.contextMessages;
		if (Array.isArray(ctxMsgs) && ctxMsgs.length > 0) {
			const last = ctxMsgs[ctxMsgs.length - 1] as {
				role?: string;
				content?: Array<{ type?: string; thinking?: string; text?: string }>;
			};
			if (last?.role === "assistant" && Array.isArray(last.content)) {
				const hasThinking = last.content.some(
					(b) => b?.type === "thinking" && typeof b.thinking === "string" && b.thinking.trim().length > 0,
				);
				const hasVisible = last.content.some(
					(b) =>
						b?.type === "toolCall" ||
						(b?.type === "text" && typeof b.text === "string" && b.text.trim().length > 0),
				);
				if (hasThinking && !hasVisible) {
					settleGateFiredThisRun = true;
					guardsTriggered += 1;
					updateHud(ctx);
					const draft: CustomMessageEntryDraft = {
						type: "custom_message",
						customType: "ap-empty-recover",
						display: false,
						content:
							"[ap recover] Previous assistant turn produced internal reasoning with no visible text or tool call. Emit your concrete tool call or final answer now.",
					};
					return {
						entries: [...(event.entries ?? []), draft],
						continue: true,
					};
				}
			}
		}

		if (editedFilesThisRun.size === 0) {
			return undefined;
		}
		const cwd = ctx?.cwd;
		if (!cwd) return undefined;

		const blockers: string[] = [];

		// 1. Fast (<15ms) Tree-sitter/JSON/TOML syntax check on code files edited via built-in write/edit
		for (const rawPath of [...builtInCodeEditsThisRun].slice(0, 6)) {
			if (!CHECKABLE_CODE_EXT.test(rawPath)) continue;
			const absPath = isAbsolute(rawPath) ? rawPath : resolve(cwd, rawPath);
			if (!existsSync(absPath)) continue;
			const chk = spawnSync(AP_BIN, ["splice", "check", "--json", absPath], {
				cwd,
				encoding: "utf8",
				timeout: 2500,
				windowsHide: true,
			});
			if (chk.stdout && chk.stdout.trim().startsWith("{")) {
				try {
					const parsed = JSON.parse(chk.stdout) as {
						ok?: boolean;
						issues?: Array<string | { file?: string; line?: number; message?: string; detail?: string }>;
					};
					if (parsed.ok === false && Array.isArray(parsed.issues)) {
						for (const iss of parsed.issues.slice(0, 3)) {
							const msg =
								typeof iss === "string"
									? iss
									: `${iss.file ?? normRelPath(rawPath, cwd)}${iss.line ? `:${iss.line}` : ""} ${iss.message ?? iss.detail ?? "syntax error"}`;
							blockers.push(`- [SYNTAX] ${msg.slice(0, 180)}`);
						}
					}
				} catch {
					// ignore unparseable output
				}
			}
		}

		// 2. Fast (<25ms) Git diff blocker gate strictly scoped to files edited in this run
		if (existsSync(join(cwd, ".git"))) {
			const diffRes = spawnSync(AP_BIN, ["guard", "diff", "--json", cwd], {
				cwd,
				encoding: "utf8",
				timeout: 2500,
				windowsHide: true,
			});
			if (diffRes.stdout && diffRes.stdout.trim().startsWith("{")) {
				try {
					const parsed = JSON.parse(diffRes.stdout) as { findings?: DiffFindingItem[] };
					if (Array.isArray(parsed.findings)) {
						blockers.push(...filterSettleDiffBlockers(parsed.findings, editedFilesThisRun, cwd));
					}
				} catch {
					// ignore unparseable output
				}
			}
		}

		if (blockers.length === 0) {
			editedFilesThisRun.clear();
			builtInCodeEditsThisRun.clear();
			return undefined;
		}

		settleGateFiredThisRun = true;
		guardsTriggered += 1;
		updateHud(ctx);
		const draft: CustomMessageEntryDraft = {
			type: "custom_message",
			customType: "ap-settle-gate",
			display: true,
			content: `[ap settle-gate] Blocked premature completion — concrete issue(s) found in files edited this run:\n${blockers.slice(0, 6).join("\n")}\nFix these issues and re-verify before finishing.`,
		};
		return {
			entries: [...(event.entries ?? []), draft],
			continue: true,
		};
	});

	pi.on("tool_call", (event, ctx) => {
		if (event.input && typeof event.input === "object") {
			stripNullOptionalArgs(event.input);
		}
		if (process.platform === "win32" && event.input && typeof event.input === "object") {
			const piInp = event.input as { path?: unknown; file_path?: unknown };
			const normP = typeof piInp.path === "string" ? normalizeWindowsToolPath(piInp.path) : undefined;
			if (normP) piInp.path = normP;
			const normFP = typeof piInp.file_path === "string" ? normalizeWindowsToolPath(piInp.file_path) : undefined;
			if (normFP) piInp.file_path = normFP;
		}
		const baseTool = event.toolName.replace(/^mcp__agent_primitives__/, "");
		if (EDIT_TOOLS.has(baseTool)) {
			recentShellFps.length = 0;
			unchangedReads.clear();
			outlinedPaths.clear();
			stagnantHeavyTurns = 0;
			pendingThinkingNudge = false;

			// Track large full-file `write` overwrites of already-existing files (to nudge surgical `edit`)
			if (event.toolName === "write" && event.input && typeof event.input === "object") {
				const inp = event.input as { path?: string; file_path?: string; content?: string };
				const rawPath = String(inp.path ?? inp.file_path ?? "").trim();
				const content = typeof inp.content === "string" ? inp.content : "";
				if (rawPath && content.length >= WRITE_OVERWRITE_TIP_CHARS) {
					const cwd = ctx?.cwd || process.cwd();
					const absPath = isAbsolute(rawPath) ? rawPath : resolve(cwd, rawPath);
					if (existsSync(absPath) && typeof event.toolCallId === "string" && event.toolCallId) {
						largeOverwriteCallIds.add(event.toolCallId);
					}
				}
			}

			// Proactive <1ms pre-execution legacy-arg normalization + indent/blank-line repair for Pi built-in `edit` (pi-edit-guard pattern)
			if (event.toolName === "edit" && event.input && typeof event.input === "object") {
				if (normalizeEditArgs(event.input as Record<string, unknown>)) {
					healedEditsCount += 1;
				}
				const inp = event.input as {
					path?: string;
					file_path?: string;
					oldText?: string;
					newText?: string;
					edits?: Array<{ oldText?: string; newText?: string }>;
				};
				const rawPath = String(inp.path ?? inp.file_path ?? "").trim();
				if (rawPath) {
					const cwd = ctx?.cwd || process.cwd();
					const absPath = isAbsolute(rawPath) ? rawPath : resolve(cwd, rawPath);
					if (existsSync(absPath)) {
						try {
							const content = readFileSync(absPath, "utf8");
							if (content.length <= 2_000_000) {
								if (Array.isArray(inp.edits)) {
									const merged = resolveAndMergeHashlineEdits(content, inp.edits);
									if (merged) {
										inp.edits = merged.edits;
										healedEditsCount += merged.healed;
									} else {
										const seqHealed = healMultiEditsSequential(content, inp.edits);
										if (seqHealed) {
											inp.edits = seqHealed.edits;
											healedEditsCount += seqHealed.healed;
										}
									}
								} else if (typeof inp.oldText === "string" && typeof inp.newText === "string") {
									const fixed = healEditBlock(content, inp.oldText, inp.newText);
									if (fixed) {
										inp.oldText = fixed.oldText;
										inp.newText = fixed.newText;
										healedEditsCount += 1;
									}
								}
							}
						} catch {
							// ignore unreadable/binary files
						}
					}
				}
			}
			return undefined;
		}
		if (event.toolName === "read" && event.input && typeof event.input === "object") {
			const inp = event.input as { path?: string; file_path?: string; offset?: unknown; limit?: unknown };
			const rawPath = String(inp.path ?? inp.file_path ?? "").trim();
			if (
				rawPath &&
				!BINARY_READ_EXT.test(rawPath) &&
				typeof inp.offset === "number" &&
				Number.isFinite(inp.offset) &&
				inp.offset >= 2
			) {
				const cwd = ctx?.cwd || process.cwd();
				const absPath = isAbsolute(rawPath) ? rawPath : resolve(cwd, rawPath);
				if (existsSync(absPath)) {
					try {
						const st = statSync(absPath);
						if (st.isFile() && st.size <= 2_000_000) {
							const content = readFileSync(absPath, "utf8");
							const clamped = clampReadOffsetToEof(content, inp.offset, inp.limit);
							if (clamped) {
								inp.offset = clamped.clampedOffset;
								if (typeof event.toolCallId === "string" && event.toolCallId) {
									clampedReadCallIds.set(event.toolCallId, clamped);
								}
							}
						}
					} catch {
						// ignore unreadable files
					}
				}
			}
			return undefined;
		}
		if (event.toolName === "codemode" && event.input && typeof event.input === "object") {
			readOnlyBashStreak = 0;
			const code = typeof event.input.code === "string" ? event.input.code : "";
			const hasBuiltinSetTimeout = detectPiBuiltinSetTimeout();
			const healedCode = healCodemodeSource(code, { hasBuiltinSetTimeout });
			if (healedCode && healedCode !== code) {
				event.input.code = healedCode;
			}
			return undefined;
		}
		if (event.toolName !== "bash" && event.toolName !== "powershell") return undefined;
		const cmd = typeof event.input?.command === "string" ? event.input.command : "";
		if (DESTRUCTIVE_OR_WRITE.test(cmd)) {
			unchangedReads.clear();
		}
		const ephGuarded = event.toolName === "bash" ? guardEphemeralServerCommand(cmd) : undefined;
		const cmdStage1 = ephGuarded ?? cmd;
		const healed = healCommand(cmdStage1, event.toolName, apProfileOverrides?.kvSafeSleepSec);
		const finalCmd = healed ?? cmdStage1;
		if (finalCmd !== cmd) {
			event.input.command = finalCmd;
		}
		const safeTimeout = resolveSafeShellTimeout(
			typeof event.input?.command === "string" ? event.input.command : cmd,
			event.input?.timeout,
		);
		if (safeTimeout !== undefined) {
			event.input.timeout = safeTimeout;
		}
		return undefined;
	});

	pi.on("tool_result", (event, ctx) => {
		// Track edited files across both direct calls and codemode child calls for `agent_before_settle`
		const baseTool = event.toolName.replace(/^mcp__agent_primitives__/, "");
		if (!event.isError && EDIT_TOOLS.has(baseTool)) {
			for (const p of extractEditedPathsFromTool(baseTool, event.input as Record<string, unknown> | undefined)) {
				editedFilesThisRun.add(p);
				if (baseTool === "write" || baseTool === "edit") {
					builtInCodeEditsThisRun.add(p);
				}
			}
		}
		// Leave codemode child calls (`parentToolCallId`) untouched so JS scripts keep raw structuredContent!
		if (event.parentToolCallId) return undefined;
		if (!Array.isArray(event.content) || event.content.length === 0) return undefined;

		let workingContent: Array<{ type?: string; text?: string; [k: string]: unknown }> = event.content as Array<{
			type?: string;
			text?: string;
			[k: string]: unknown;
		}>;
		let mutated = false;

		const isFast = isDeepCacheDiscountModel((ctx as { model?: { id?: string; api?: string } } | undefined)?.model);
		const usageTokRaw = (ctx as { getContextUsage?: () => { tokens?: number | null } } | undefined)?.getContextUsage?.()?.tokens;
		const effContextTokens = typeof usageTokRaw === "number" && usageTokRaw > 0 ? usageTokRaw : lastKnownPromptTokens;

		// 0. Lossless multi-block auto-sieve for oversized `codemode` dumps (content[1..N]; preserves header, Script error & images)
		if (event.toolName === "codemode") {
			const cmCode = typeof event.input?.code === "string" ? event.input.code : "";
			let maxCodemodeBlockLen = 0;
			for (const blk of workingContent) {
				if (blk?.type === "text" && typeof blk.text === "string" && blk.text.length > maxCodemodeBlockLen) {
					maxCodemodeBlockLen = blk.text.length;
				}
			}
			if (!shouldSkipAutoSieveForSelf(isSieveSelfCodemode(cmCode), maxCodemodeBlockLen)) {
				const sieved = sieveCodemodeContentBlocks(
					workingContent,
					(rawBody) => {
						const res = spawnSync(AP_BIN, ["sieve", "pipe", "--label", "pi-codemode"], {
							input: rawBody,
							encoding: "utf8",
							timeout: 4000,
							windowsHide: true,
							env: { ...process.env, SIEVE_HOME },
						});
						return res.status === 0 && res.stdout ? formatAutoSieveDigest(res.stdout) : undefined;
					},
					isFast,
					apProfileOverrides?.sieveHardChars,
					effContextTokens,
				);
				if (sieved) {
					workingContent = sieved;
					sievedCount += 1;
					mutated = true;
				}
			}
		}

		const primaryTextIdx = findPrimaryToolResultTextIndex(workingContent, event.toolName);
		let lastTextIdx = -1;
		for (let i = workingContent.length - 1; i >= 0; i--) {
			if (workingContent[i]?.type === "text" && typeof workingContent[i].text === "string") {
				lastTextIdx = i;
				break;
			}
		}
		if (lastTextIdx < 0) {
			if (!mutated) return undefined;
			updateHud(ctx);
			return event.structuredContent !== undefined
				? { content: workingContent, structuredContent: event.structuredContent }
				: { content: workingContent };
		}

		let fullText = extractAllToolResultText(workingContent);
		let outText = workingContent[lastTextIdx].text as string;
		let textMutated = false;

		// A. Built-in `read` Hashline (`L:HH|`) tagging + redundant re-read guard + universal truncated-file outline (<15ms)
		if (event.toolName === "read" && !event.isError) {
			const p = String(event.input?.path ?? event.input?.file_path ?? "");
			const off = String(event.input?.offset ?? "");
			const lim = String(event.input?.limit ?? "");
			const startOff = Math.max(1, Math.floor(Number(event.input?.offset) || 1));
			const readIdx = primaryTextIdx >= 0 ? primaryTextIdx : lastTextIdx;
			let readText = workingContent[readIdx].text as string;
			let readBlockMutated = false;
			let readAdvisory = "";
			const readDetails = event.details as { truncation?: { truncated?: boolean } } | undefined;
			const isTruncated =
				readDetails?.truncation?.truncated === true ||
				/use offset=\d+|lines remaining|more lines in file|truncated to \d+/i.test(readText);
			if (typeof event.toolCallId === "string") {
				const clamped = clampedReadCallIds.get(event.toolCallId);
				if (clamped) {
					clampedReadCallIds.delete(event.toolCallId);
					readAdvisory += `\n[ap read-clamped] Requested offset=${clamped.requestedOffset} > EOF (${clamped.totalLines} lines); showing tail from L${clamped.clampedOffset}.`;
				}
			}
			let didAutoSieveRead = false;
			if (p) {
				const key = `${p}::${off}::${lim}`;
				const hits = (unchangedReads.get(key) ?? 0) + 1;
				unchangedReads.set(key, hits);
				if (hits >= REREAD_THRESHOLD) {
					readAdvisory += `\n[ap reread-guard] Exact unchanged slice (${p}) read ${hits}x already in this session. Avoid re-reading; use ap_search/ap_locate or proceed directly to edits.`;
					guardsTriggered += 1;
				} else if (isTruncated) {
					const cwd = ctx?.cwd || process.cwd();
					const absPath = isAbsolute(p) ? p : resolve(cwd, p);
					const normOutlineKey = absPath.toLowerCase();
					if (existsSync(absPath) && !outlinedPaths.has(normOutlineKey)) {
						if (CODE_FILE_EXT.test(p)) {
							const ol = spawnSync(AP_BIN, ["read", absPath, "--outline"], {
								cwd,
								encoding: "utf8",
								timeout: 1500,
								windowsHide: true,
							});
							if (ol.status === 0 && ol.stdout?.trim()) {
								readAdvisory += `\n[ap read-outline] File was truncated; full AST symbol map (jump directly via read(offset=...) or ap_read(symbol=...)):\n${ol.stdout.trim().slice(0, 1800)}`;
								outlinedPaths.add(normOutlineKey);
							}
						} else {
							try {
								const rawDoc = readFileSync(absPath, "utf8");
								if (rawDoc.length <= 2_000_000) {
									const nonCodeOl = extractNonCodeOutline(p, rawDoc);
									if (nonCodeOl) {
										readAdvisory += `\n${nonCodeOl}`;
										outlinedPaths.add(normOutlineKey);
									}
								}
							} catch {
								// ignore unreadable/binary files
							}
						}
					}
				} else if (shouldAutoSieveUnboundedRead(readText, event.input, isFast, apProfileOverrides?.sieveHardChars, effContextTokens)) {
					const res = spawnSync(AP_BIN, ["sieve", "pipe", "--label", "pi-read"], {
						input: readText,
						encoding: "utf8",
						timeout: 4000,
						windowsHide: true,
						env: { ...process.env, SIEVE_HOME },
					});
					if (res.status === 0 && res.stdout && res.stdout.length > 40 && res.stdout.length < readText.length * 0.78) {
						readText = `${formatAutoSieveDigest(res.stdout).trimEnd()}\n[ap read-sieve] Unbounded full-file read archived losslessly; use read(offset, limit) for exact edit lines, \`ap sieve peek <id> --grep <regex>\` for regex, or \`ap sieve search <keywords>\` for FTS5 keywords.`;
						sievedCount += 1;
						readBlockMutated = true;
						didAutoSieveRead = true;
						mutated = true;
					}
				} else if (!largeReadTipShown && readText.length >= LARGE_CODE_READ_CHARS && CODE_FILE_EXT.test(p)) {
					readAdvisory += `\n[ap read-tip] Large code file loaded; use ap_read(outline=true) or ap_read(symbol="...") for AST-exact slices (~85% fewer tokens).`;
					largeReadTipShown = true;
				} else {
					const docTip = classifyOversizedDocRead(p, readText.length);
					if (docTip) {
						readAdvisory += `\n${docTip}`;
					}
				}
			}
			if (!didAutoSieveRead) {
				const hashed = annotateReadWithHashlines(readText, startOff, p);
				if (hashed) {
					readText = hashed;
					readBlockMutated = true;
					mutated = true;
				}
			}
			if (readBlockMutated) {
				if (readIdx === lastTextIdx) {
					outText = readText;
					textMutated = true;
				} else {
					workingContent = workingContent.map((c, idx) => (idx === readIdx ? { ...c, text: readText } : c));
					fullText = extractAllToolResultText(workingContent);
				}
			}
			if (readAdvisory) {
				outText += readAdvisory;
				textMutated = true;
				mutated = true;
			}
		}

		// B. Built-in `edit` error self-healing tip + Top-1 closest line window from disk (cuts ~47% re-reads)
		if (event.toolName === "edit" && event.isError) {
			let closestSnippet = "";
			const inp = event.input as {
				path?: string;
				file_path?: string;
				oldText?: string;
				edits?: Array<{ oldText?: string }>;
			} | undefined;
			const rawPath = String(inp?.path ?? inp?.file_path ?? "").trim();
			const failIdxMatch = fullText.match(/\bedits\[(\d+)\]/);
			const failIdx = failIdxMatch ? Number(failIdxMatch[1]) : -1;
			const targetOld =
				typeof inp?.oldText === "string"
					? inp.oldText
					: Array.isArray(inp?.edits)
						? (failIdx >= 0 && typeof inp.edits[failIdx]?.oldText === "string"
							? inp.edits[failIdx].oldText
							: inp.edits.find((e) => typeof e?.oldText === "string" && e.oldText.trim().length > 0)?.oldText) ?? ""
						: "";
			if (rawPath && targetOld) {
				const cwd = ctx?.cwd || process.cwd();
				const absPath = isAbsolute(rawPath) ? rawPath : resolve(cwd, rawPath);
				if (existsSync(absPath)) {
					try {
						const content = readFileSync(absPath, "utf8");
						if (content.length <= 2_000_000) {
							const isMulti = /multiple|occurrences|more than once/i.test(fullText);
							const diag = isMulti
								? findAllEditOccurrenceLines(content, targetOld) ?? findClosestEditWindow(content, targetOld)
								: findClosestEditWindow(content, targetOld);
							if (diag) closestSnippet = `\n${diag}`;
						}
					} catch {
						// ignore unreadable file
					}
				}
			}
			const hunkMsg =
				Array.isArray(inp?.edits) && failIdx >= 0
					? `\n[ap edit-hunk] edits[${failIdx}] (${targetOld.split("\n").length} line(s)) missed; fix only this hunk (other hunks can stay unchanged).`
					: "";
			outText += `${closestSnippet}${hunkMsg}\n[ap edit-tip] Patch target missed; use the exact lines above, ap_edit (4-tier fuzzy + AST symbols), or ap splice view.`;
			mutated = true;
		}

		// B1. Instant <12ms post-edit Tree-sitter/JSON/TOML syntax alert (oh-my-pi / Claude Code PostToolUse pattern)
		//     + large full-file overwrite tip on `write` (rate-limited: once per 15 turns)
		if ((event.toolName === "edit" || event.toolName === "write") && !event.isError) {
			const rawEditPath = String(event.input?.path ?? event.input?.file_path ?? "").trim();
			if (rawEditPath && CHECKABLE_CODE_EXT.test(rawEditPath)) {
				const cwd = ctx?.cwd || process.cwd();
				const absEditPath = isAbsolute(rawEditPath) ? rawEditPath : resolve(cwd, rawEditPath);
				if (existsSync(absEditPath)) {
					const chk = spawnSync(AP_BIN, ["splice", "check", "--json", absEditPath], {
						cwd,
						encoding: "utf8",
						timeout: 2000,
						windowsHide: true,
					});
					const alert = formatInstantSyntaxAlert(rawEditPath, chk.stdout || "", cwd);
					if (alert) {
						outText += `\n${alert}`;
						guardsTriggered += 1;
						textMutated = true;
						mutated = true;
					}
				}
			}
			if (event.toolName === "edit") {
				const shiftTip = formatPostEditLineShiftTip(
					event.input as Record<string, unknown> | undefined,
					event.details as { firstChangedLine?: number } | undefined,
				);
				if (shiftTip) {
					outText += `\n${shiftTip}`;
					textMutated = true;
					mutated = true;
				}
			}
		}
		if (event.toolName === "write" && !event.isError && typeof event.toolCallId === "string") {
			if (largeOverwriteCallIds.delete(event.toolCallId)) {
				if (sessionTurnCount - lastWriteTipTurn >= WRITE_TIP_COOLDOWN_TURNS) {
					lastWriteTipTurn = sessionTurnCount;
					outText += `\n[ap write-tip] Full-file overwrite (>=4KB) on existing file. Prefer surgical \`edit\` (supports multi-hunk edits[]) or \`ap_edit\` to save output tokens & generation time.`;
					textMutated = true;
					mutated = true;
				}
			}
		}

		// B2. Pi `codemode` targeted error self-healing classifier (inspects ALL multi-block text!) + parallelism tip
		if (event.toolName === "codemode") {
			if (
				event.isError ||
				fullText.includes("Script failed") ||
				fullText.includes("Script error:") ||
				fullText.includes("is not a function")
			) {
				outText += `\n${classifyCodemodeFailureTip(fullText)}`;
				textMutated = true;
				mutated = true;
			} else if (
				codemodeParallelTipsShown < CODEMODE_PARALLEL_MAX_TIPS &&
				sessionTurnCount - lastCodemodeParallelTipTurn >= CODEMODE_PARALLEL_COOLDOWN_TURNS
			) {
				const code = typeof event.input?.code === "string" ? event.input.code : "";
				const awaitCount = (code.match(/\bawait\s+/g) ?? []).length;
				if (awaitCount >= 3 && !/Promise\.all(?:Settled)?\s*\(/.test(code)) {
					outText += `\n[ap codemode-parallel] ${awaitCount} sequential awaits detected. Batch independent calls concurrently: \`const [a, b] = await Promise.allSettled([tools.bash({command}), tools.read({path})]);\` for 3-5x faster multi-step runs.`;
					codemodeParallelTipsShown += 1;
					lastCodemodeParallelTipTurn = sessionTurnCount;
					textMutated = true;
					mutated = true;
				}
			}
		}

		// C. Dual-tier multi-block shell auto-sieve (>=24KB unconditional, >=14KB structured/noisy) + failure tips + loop-breaker
		if (event.toolName === "bash" || event.toolName === "powershell") {
			const cmd = typeof event.input?.command === "string" ? event.input.command : "";
			const isSieveSelf = isSieveSelfCommand(cmd);
			const isBoundedApCmd =
				cmd.includes("ap.exe") ||
				/\bap\s+(?:read|search|query|atlas|probe|guard|sieve|baton|splice|recall)\b/.test(cmd);
			let maxShellBlockLen = 0;
			let hasGiantShellLine = false;
			for (const blk of workingContent) {
				if (blk?.type === "text" && typeof blk.text === "string") {
					if (blk.text.length > maxShellBlockLen) maxShellBlockLen = blk.text.length;
					const blkLines = blk.text.split("\n");
					if (
						!hasGiantShellLine &&
						!(blkLines.length <= 12 && blk.text.length <= 12288) &&
						blkLines.some((l) => l.length > SIEVE_GIANT_LINE_CHARS)
					) {
						hasGiantShellLine = true;
					}
				}
			}
			const boundedApMax = effContextTokens >= 120_000 ? 12000 : effContextTokens >= 80_000 ? 18000 : 24000;
			const skipSieve =
				shouldSkipAutoSieveForSelf(isSieveSelf, maxShellBlockLen) ||
				(isBoundedApCmd && maxShellBlockLen < boundedApMax && !hasGiantShellLine);
			if (!skipSieve) {
				const sievedShell = sieveShellContentBlocks(
					workingContent,
					(rawBody) => {
						const res = spawnSync(AP_BIN, ["sieve", "pipe", "--label", "pi-bash"], {
							input: rawBody,
							encoding: "utf8",
							timeout: 4000,
							windowsHide: true,
							env: { ...process.env, SIEVE_HOME },
						});
						return res.status === 0 && res.stdout ? formatAutoSieveDigest(res.stdout) : undefined;
					},
					isFast,
					apProfileOverrides?.sieveHardChars,
					effContextTokens,
				);
				if (sievedShell) {
					workingContent = sievedShell;
					outText = workingContent[lastTextIdx].text as string;
					fullText = extractAllToolResultText(workingContent);
					sievedCount += 1;
					mutated = true;
				}
			}

			if (event.toolName === "bash") {
				const st = trackReadOnlyBashStreak(readOnlyBashStreak, cmd, DESTRUCTIVE_OR_WRITE.test(cmd));
				readOnlyBashStreak = st.nextStreak;
				if (st.shouldTip && (pi.getActiveTools?.() ?? []).includes("codemode")) {
					outText += `\n[ap batch-tip] ${readOnlyBashStreak} consecutive single bash probes; batch the next 3-5 checks in ONE codemode Promise.allSettled([tools.mcp__agent_primitives__ap_search(...), tools.read(...)]) script.`;
					mutated = true;
				}
			}

			const benignGrep = event.isError && isBenignGrepNoMatch(cmd, fullText);
			if (event.isError && !benignGrep) {
				const failTip = classifyShellFailureTip(event.toolName, cmd, fullText);
				if (failTip) {
					outText += `\n${failTip}`;
					mutated = true;
				}
			}

			const fp = normCmdFingerprint(cmd);
			if (fp.length >= 8) {
				recentShellFps.push(fp);
				if (recentShellFps.length > LOOP_WINDOW) {
					recentShellFps.shift();
				}
				const repeats = recentShellFps.filter((x) => x === fp).length;
				const effectiveErr = event.isError && !benignGrep;
				const threshold = effectiveErr ? LOOP_ERR_THRESHOLD : LOOP_OK_THRESHOLD;
				if (repeats >= threshold) {
					const hint = effectiveErr
						? `\n[ap loop-breaker] Repeated failing shell command (${repeats}/${LOOP_WINDOW} calls) without intervening edits. Pause, inspect root cause, edit code or switch strategy instead of retrying identically.`
						: `\n[ap loop-breaker] Identical shell command repeated (${repeats}/${LOOP_WINDOW} calls) without edits. Avoid redundant polling; summarize findings or pivot to the next concrete action.`;
					outText = `${outText}${hint}`;
					guardsTriggered += 1;
					mutated = true;
					const evBus = (pi as { events?: { emit?: (ch: string, d: unknown) => void } }).events;
					if (typeof evBus?.emit === "function") {
						evBus.emit("ap:tool_loop", {
							tool: event.toolName,
							count: repeats,
							signature: fp.slice(0, 120),
							isError: Boolean(effectiveErr),
						});
					}
				}
			}
		}

		// D. DeepSeek overthinking stagnation nudge (emitted once after 3 consecutive >12k-char thinking turns without edits)
		if (pendingThinkingNudge) {
			outText += `\n[ap thinking-guard] 3 consecutive heavy-thinking turns without code changes. Commit to one concrete edit, focused test, or ap_locate/ap_changes call now.`;
			pendingThinkingNudge = false;
			stagnantHeavyTurns = 0;
			guardsTriggered += 1;
			mutated = true;
		}

		// E. Serial single-tool exploration batch nudge (rate-limited: once per 25 turns after 6 clean 1-tool turns)
		if (pendingBatchNudge) {
			outText += `\n[ap batch-tip] ${SERIAL_BATCH_THRESHOLD} consecutive clean single-tool turns. Combine independent reads/searches/probes now via parallel tool calls or one codemode script: \`await Promise.allSettled([tools.read({path}), tools.bash({command})])\`.`;
			pendingBatchNudge = false;
			serialSingleToolTurns = 0;
			guardsTriggered += 1;
			mutated = true;
		}

		if (!mutated) return undefined;
		updateHud(ctx);
		const patchedContent =
			textMutated || outText !== workingContent[lastTextIdx].text
				? workingContent.map((c, idx) => (idx === lastTextIdx ? { ...c, text: outText } : c))
				: workingContent;
		return event.structuredContent !== undefined
			? { content: patchedContent, structuredContent: event.structuredContent }
			: { content: patchedContent };
	});
}
