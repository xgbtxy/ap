use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "pi",
    about = "Inspect, apply, or restore generic idempotent runtime patches for @earendil-works/pi-coding-agent (v1.5+)"
)]
struct PiCli {
    #[command(subcommand)]
    subcmd: PiSubCmd,
}

#[derive(Subcommand, Debug)]
enum PiSubCmd {
    /// Inspect detected @earendil-works/pi-coding-agent installation and patch status
    Status {
        #[arg(long)]
        pi_dir: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Idempotently apply all 22 generic Pi v1.5+ runtime patches (saves pristine originals to ~/.ap/pi-backups/)
    Patch {
        #[arg(long)]
        pi_dir: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Restore original unpatched Pi runtime files from ~/.ap/pi-backups/
    Restore {
        #[arg(long)]
        pi_dir: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

struct PatchHunk {
    id: &'static str,
    rel_hint: Option<&'static str>,
    old: &'static str,
    alt_olds: &'static [&'static str],
    new: &'static str,
    already_present_markers: &'static [&'static str],
}

struct PatchSpec {
    id: &'static str,
    summary: &'static str,
    hunks: &'static [PatchHunk],
}

const CODEMODE_BUILTINS_OLD: &str = "\tfor (const [namespace, members] of namespaces) {\n\t\tObject.freeze(members);\n\t\tconst value = guard(members, namespace, Object.keys(members));\n\t\tObject.defineProperty(globalThis, namespace, { value, enumerable: true });\n\t}";

const CODEMODE_BUILTINS_ALT: &str = "\tfor (const [namespace, members] of namespaces) {\n\t\tObject.freeze(members);\n\t\tconst value = guard(members, namespace, Object.keys(members));\n\t\tObject.defineProperty(globalThis, namespace, { value, enumerable: true });\n\t}\n\t(function(){\n\t\tconst _t = new Set(); let _id = 1;\n\t\tif (typeof globalThis.setTimeout !== \"function\") {\n\t\t\tObject.defineProperty(globalThis, \"setTimeout\", { value: function(fn, ms) { const id = _id++; _t.add(id); const a = Array.prototype.slice.call(arguments, 2); const w = Math.max(0, Number(ms) || 0); Promise.resolve(typeof globalThis.sleep === \"function\" ? globalThis.sleep(w) : 0).then(function() { if (!_t.delete(id)) return; if (typeof fn === \"function\") fn.apply(undefined, a); }, function() { _t.delete(id); }); return id; }, enumerable: true });\n\t\t\tObject.defineProperty(globalThis, \"clearTimeout\", { value: function(id) { _t.delete(id); }, enumerable: true });\n\t\t}\n\t\tconst _B = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";\n\t\tconst _u8e = function(str) { const s = String(str), o = []; for (let i = 0; i < s.length; i++) { let c = s.charCodeAt(i); if (c < 128) o.push(c); else if (c < 2048) o.push(192 | (c >> 6), 128 | (c & 63)); else if ((c & 64512) === 55296 && i + 1 < s.length && (s.charCodeAt(i + 1) & 64512) === 56320) { c = 65536 + ((c & 1023) << 10) + (s.charCodeAt(++i) & 1023); o.push(240 | (c >> 18), 128 | ((c >> 12) & 63), 128 | ((c >> 6) & 63), 128 | (c & 63)); } else o.push(224 | (c >> 12), 128 | ((c >> 6) & 63), 128 | (c & 63)); } return new Uint8Array(o); };\n\t\tconst _u8d = function(b) { const u = b instanceof Uint8Array ? b : new Uint8Array(b); let o = \"\", i = 0; while (i < u.length) { const c = u[i++]; if (c < 128) o += String.fromCharCode(c); else if ((c & 224) === 192) o += String.fromCharCode(((c & 31) << 6) | (u[i++] & 63)); else if ((c & 240) === 224) o += String.fromCharCode(((c & 15) << 12) | ((u[i++] & 63) << 6) | (u[i++] & 63)); else { const cp = (((c & 7) << 18) | ((u[i++] & 63) << 12) | ((u[i++] & 63) << 6) | (u[i++] & 63)) - 65536; o += String.fromCharCode(55296 + (cp >> 10), 56320 + (cp & 1023)); } } return o; };\n\t\tconst _b64e = function(u) { let o = \"\"; for (let i = 0; i < u.length; i += 3) { const a = u[i], b = i + 1 < u.length ? u[i + 1] : 0, c = i + 2 < u.length ? u[i + 2] : 0; o += _B[a >> 2] + _B[((a & 3) << 4) | (b >> 4)] + (i + 1 < u.length ? _B[((b & 15) << 2) | (c >> 6)] : \"=\") + (i + 2 < u.length ? _B[c & 63] : \"=\"); } return o; };\n\t\tconst _b64d = function(s) { let cl = \"\"; const st = String(s); for (let i = 0; i < st.length; i++) { const ch = st[i], cc = st.charCodeAt(i); if (cc <= 32 || ch === \"=\") continue; cl += ch === \"-\" ? \"+\" : ch === \"_\" ? \"/\" : ch; } const o = []; for (let i = 0; i < cl.length; i += 4) { const a = _B.indexOf(cl[i]), b = _B.indexOf(cl[i + 1]), c = i + 2 < cl.length ? _B.indexOf(cl[i + 2]) : -1, d = i + 3 < cl.length ? _B.indexOf(cl[i + 3]) : -1; o.push((a << 2) | (b >> 4)); if (c >= 0) o.push(((b & 15) << 4) | (c >> 2)); if (d >= 0) o.push(((c & 3) << 6) | d); } return new Uint8Array(o); };\n\t\tif (typeof globalThis.btoa !== \"function\") Object.defineProperty(globalThis, \"btoa\", { value: function(s) { const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i) & 255; return _b64e(u); }, enumerable: true });\n\t\tif (typeof globalThis.atob !== \"function\") Object.defineProperty(globalThis, \"atob\", { value: function(s) { const u = _b64d(s); let r = \"\"; for (let i = 0; i < u.length; i++) r += String.fromCharCode(u[i]); return r; }, enumerable: true });\n\t\tif (typeof globalThis.TextEncoder !== \"function\") Object.defineProperty(globalThis, \"TextEncoder\", { value: function TextEncoder() { this.encode = _u8e; }, enumerable: true });\n\t\tif (typeof globalThis.TextDecoder !== \"function\") Object.defineProperty(globalThis, \"TextDecoder\", { value: function TextDecoder() { this.decode = _u8d; }, enumerable: true });\n\t\tif (typeof globalThis.Buffer !== \"function\") { const _wb = function(u) { u.toString = function(enc) { const e = String(enc || \"utf8\").toLowerCase(); if (e === \"base64\" || e === \"base64url\") return e === \"base64url\" ? _b64e(u).replace(/[+]/g, \"-\").replace(/[/]/g, \"_\").replace(/[=]+$/g, \"\") : _b64e(u); if (e === \"hex\") { let h = \"\"; for (let i = 0; i < u.length; i++) h += (u[i] < 16 ? \"0\" : \"\") + u[i].toString(16); return h; } if (e === \"latin1\" || e === \"binary\") { let r = \"\"; for (let i = 0; i < u.length; i++) r += String.fromCharCode(u[i]); return r; } return _u8d(u); }; return u; }; Object.defineProperty(globalThis, \"Buffer\", { value: { isBuffer: function(v) { return v instanceof Uint8Array; }, from: function(v, enc) { if (v instanceof Uint8Array || Array.isArray(v)) return _wb(new Uint8Array(v)); const e = String(enc || \"utf8\").toLowerCase(); if (e === \"base64\" || e === \"base64url\") return _wb(_b64d(v)); if (e === \"hex\") { let h = \"\"; const sv = String(v); for (let i = 0; i < sv.length; i++) if (sv.charCodeAt(i) > 32) h += sv[i]; const o = new Uint8Array(Math.floor(h.length / 2)); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16) || 0; return _wb(o); } return _wb(_u8e(v)); }, concat: function(l) { let t = 0; for (let i = 0; i < l.length; i++) t += l[i].length; const o = new Uint8Array(t); let off = 0; for (let i = 0; i < l.length; i++) { o.set(l[i], off); off += l[i].length; } return _wb(o); } }, enumerable: true }); }\n\t})();";

const CODEMODE_BUILTINS_NEW: &str = "\tfor (const [namespace, members] of namespaces) {\n\t\tObject.freeze(members);\n\t\tconst value = guard(members, namespace, Object.keys(members));\n\t\tObject.defineProperty(globalThis, namespace, { value, enumerable: true });\n\t}\n\t(function(){\n\t\tconst _t = new Set(); let _id = 1;\n\t\tif (typeof globalThis.sleep === \"function\" && typeof globalThis.setTimeout !== \"function\") {\n\t\t\tconst _sleepHost = globalThis.sleep;\n\t\t\tObject.defineProperty(globalThis, \"setTimeout\", { value: function(fn, ms) { const id = _id++; _t.add(id); const a = Array.prototype.slice.call(arguments, 2); const w = Math.min(30000, Math.max(0, Number(ms) || 0)); promiseThen.call(_sleepHost(w), function() { if (!_t.delete(id) || finished) return; if (typeof fn === \"function\") { try { fn.apply(undefined, a); } catch (err) { done(false, describeError(err)); } } }, function() { _t.delete(id); }); return id; }, enumerable: true });\n\t\t\tObject.defineProperty(globalThis, \"clearTimeout\", { value: function(id) { _t.delete(id); }, enumerable: true });\n\t\t}\n\t\tconst _B = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";\n\t\tconst _u8e = function(str) { const s = String(str), o = []; for (let i = 0; i < s.length; i++) { let c = s.charCodeAt(i); if (c < 128) o.push(c); else if (c < 2048) o.push(192 | (c >> 6), 128 | (c & 63)); else if ((c & 64512) === 55296 && i + 1 < s.length && (s.charCodeAt(i + 1) & 64512) === 56320) { c = 65536 + ((c & 1023) << 10) + (s.charCodeAt(++i) & 1023); o.push(240 | (c >> 18), 128 | ((c >> 12) & 63), 128 | ((c >> 6) & 63), 128 | (c & 63)); } else o.push(224 | (c >> 12), 128 | ((c >> 6) & 63), 128 | (c & 63)); } return new Uint8Array(o); };\n\t\tconst _u8d = function(b) { const u = b instanceof Uint8Array ? b : new Uint8Array(b); let o = \"\", i = 0; while (i < u.length) { const c = u[i++]; if (c < 128) o += String.fromCharCode(c); else if ((c & 224) === 192) o += String.fromCharCode(((c & 31) << 6) | (u[i++] & 63)); else if ((c & 240) === 224) o += String.fromCharCode(((c & 15) << 12) | ((u[i++] & 63) << 6) | (u[i++] & 63)); else { const cp = (((c & 7) << 18) | ((u[i++] & 63) << 12) | ((u[i++] & 63) << 6) | (u[i++] & 63)) - 65536; o += String.fromCharCode(55296 + (cp >> 10), 56320 + (cp & 1023)); } } return o; };\n\t\tconst _b64e = function(u) { let o = \"\"; for (let i = 0; i < u.length; i += 3) { const a = u[i], b = i + 1 < u.length ? u[i + 1] : 0, c = i + 2 < u.length ? u[i + 2] : 0; o += _B[a >> 2] + _B[((a & 3) << 4) | (b >> 4)] + (i + 1 < u.length ? _B[((b & 15) << 2) | (c >> 6)] : \"=\") + (i + 2 < u.length ? _B[c & 63] : \"=\"); } return o; };\n\t\tconst _b64d = function(s) { let cl = \"\"; const st = String(s); for (let i = 0; i < st.length; i++) { const ch = st[i], cc = st.charCodeAt(i); if (cc <= 32 || ch === \"=\") continue; cl += ch === \"-\" ? \"+\" : ch === \"_\" ? \"/\" : ch; } const o = []; for (let i = 0; i < cl.length; i += 4) { const a = _B.indexOf(cl[i]), b = _B.indexOf(cl[i + 1]), c = i + 2 < cl.length ? _B.indexOf(cl[i + 2]) : -1, d = i + 3 < cl.length ? _B.indexOf(cl[i + 3]) : -1; o.push((a << 2) | (b >> 4)); if (c >= 0) o.push(((b & 15) << 4) | (c >> 2)); if (d >= 0) o.push(((c & 3) << 6) | d); } return new Uint8Array(o); };\n\t\tif (typeof globalThis.btoa !== \"function\") Object.defineProperty(globalThis, \"btoa\", { value: function(s) { const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i) & 255; return _b64e(u); }, enumerable: true });\n\t\tif (typeof globalThis.atob !== \"function\") Object.defineProperty(globalThis, \"atob\", { value: function(s) { const u = _b64d(s); let r = \"\"; for (let i = 0; i < u.length; i++) r += String.fromCharCode(u[i]); return r; }, enumerable: true });\n\t\tif (typeof globalThis.TextEncoder !== \"function\") Object.defineProperty(globalThis, \"TextEncoder\", { value: function TextEncoder() { this.encode = _u8e; }, enumerable: true });\n\t\tif (typeof globalThis.TextDecoder !== \"function\") Object.defineProperty(globalThis, \"TextDecoder\", { value: function TextDecoder() { this.decode = _u8d; }, enumerable: true });\n\t\tif (typeof globalThis.Buffer !== \"function\") { const _wb = function(u) { u.toString = function(enc) { const e = String(enc || \"utf8\").toLowerCase(); if (e === \"base64\" || e === \"base64url\") return e === \"base64url\" ? _b64e(u).replace(/[+]/g, \"-\").replace(/[/]/g, \"_\").replace(/[=]+$/g, \"\") : _b64e(u); if (e === \"hex\") { let h = \"\"; for (let i = 0; i < u.length; i++) h += (u[i] < 16 ? \"0\" : \"\") + u[i].toString(16); return h; } if (e === \"latin1\" || e === \"binary\") { let r = \"\"; for (let i = 0; i < u.length; i++) r += String.fromCharCode(u[i]); return r; } return _u8d(u); }; return u; }; Object.defineProperty(globalThis, \"Buffer\", { value: { isBuffer: function(v) { return v instanceof Uint8Array; }, from: function(v, enc) { if (v instanceof Uint8Array || Array.isArray(v)) return _wb(new Uint8Array(v)); const e = String(enc || \"utf8\").toLowerCase(); if (e === \"base64\" || e === \"base64url\") return _wb(_b64d(v)); if (e === \"hex\") { let h = \"\"; const sv = String(v); for (let i = 0; i < sv.length; i++) if (sv.charCodeAt(i) > 32) h += sv[i]; const o = new Uint8Array(Math.floor(h.length / 2)); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16) || 0; return _wb(o); } return _wb(_u8e(v)); }, concat: function(l) { let t = 0; for (let i = 0; i < l.length; i++) t += l[i].length; const o = new Uint8Array(t); let off = 0; for (let i = 0; i < l.length; i++) { o.set(l[i], off); off += l[i].length; } return _wb(o); } }, enumerable: true }); }\n\t})();";

const CODEMODE_WRAPPER_OLD: &str =
    "vm.evalCode(`(async (tools, console) => {${data.code}\n})`,\"codemode.js\")";
const CODEMODE_WRAPPER_NEW: &str = "vm.evalCode(`(async () => {${data.code}\n})`,\"codemode.js\")";

const PATCH_SPECS: &[PatchSpec] = &[
    PatchSpec {
        id: "before_agent_start_entries",
        summary: "Allow before_agent_start handlers to return boundary entries (e.g. firstKeptEntryId: null clean-slate compaction)",
        hunks: &[
            PatchHunk {
                id: "bundle_emit_before_agent_start",
                rel_hint: None,
                old: r#"let messages=[];for(let{ext:ext2,handlers}of snapshotEventHandlers(this.extensions,"before_agent_start"))for(let handler of handlers)try{let event={...trigger,type:"before_agent_start",get systemPrompt(){return renderCurrentSystemPrompt()},systemPromptOptions:currentOptions},handlerResult=await handler(event,ctx);if(handlerResult){let result=handlerResult;result.message&&messages.push(result.message),result.systemPrompt!==void 0&&(currentOptions.forceSystemPrompt=result.systemPrompt)}}catch(err){let message=err instanceof Error?err.message:String(err),stack=err instanceof Error?err.stack:void 0;this.emitError({extensionPath:ext2.path,event:"before_agent_start",error:message,stack})}return{messages,systemPromptOptions:currentOptions}"#,
                alt_olds: &[],
                new: r#"let messages=[],entries=[];for(let{ext:ext2,handlers}of snapshotEventHandlers(this.extensions,"before_agent_start"))for(let handler of handlers)try{let event={...trigger,type:"before_agent_start",get systemPrompt(){return renderCurrentSystemPrompt()},systemPromptOptions:currentOptions},handlerResult=await handler(event,ctx);if(handlerResult){let result=handlerResult;result.message&&messages.push(result.message),Array.isArray(result.entries)&&entries.push(...result.entries),result.systemPrompt!==void 0&&(currentOptions.forceSystemPrompt=result.systemPrompt)}}catch(err){let message=err instanceof Error?err.message:String(err),stack=err instanceof Error?err.stack:void 0;this.emitError({extensionPath:ext2.path,event:"before_agent_start",error:message,stack})}return{messages,entries,systemPromptOptions:currentOptions}"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_prepare_run_commit",
                rel_hint: None,
                old: r#"let selectedToolsBefore=this._baseSystemPromptOptions.selectedTools,result=await this._extensionRunner.emitBeforeAgentStart(trigger,this._baseSystemPromptOptions);result.systemPromptOptions.selectedTools.length!==selectedToolsBefore.length"#,
                alt_olds: &[r#"let selectedToolsBefore=this._baseSystemPromptOptions.selectedTools,result=await this._extensionRunner.emitBeforeAgentStart(trigger,this._baseSystemPromptOptions);Array.isArray(result.entries)&&result.entries.length>0&&this._commitBoundaryDrafts(result.entries);result.systemPromptOptions.selectedTools.length!==selectedToolsBefore.length"#],
                new: r#"let selectedToolsBefore=this._baseSystemPromptOptions.selectedTools,result=await this._extensionRunner.emitBeforeAgentStart(trigger,this._baseSystemPromptOptions);Array.isArray(result.entries)&&result.entries.length>0&&await this._commitBoundaryDrafts(result.entries);result.systemPromptOptions.selectedTools.length!==selectedToolsBefore.length"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "core_runner_emit_entries",
                rel_hint: Some("dist/core/extensions/runner.js"),
                old: "        const messages = [];\n        for (const { ext, handlers } of snapshotEventHandlers(this.extensions, \"before_agent_start\")) {\n            for (const handler of handlers) {\n                try {\n                    const event = {\n                        ...trigger,\n                        type: \"before_agent_start\",\n                        get systemPrompt() {\n                            return renderCurrentSystemPrompt();\n                        },\n                        systemPromptOptions: currentOptions,\n                    };\n                    const handlerResult = await handler(event, ctx);\n                    if (handlerResult) {\n                        const result = handlerResult;\n                        if (result.message)\n                            messages.push(result.message);\n                        if (result.systemPrompt !== undefined) {\n                            currentOptions.forceSystemPrompt = result.systemPrompt;\n                        }\n                    }\n                }\n                catch (err) {\n                    const message = err instanceof Error ? err.message : String(err);\n                    const stack = err instanceof Error ? err.stack : undefined;\n                    this.emitError({\n                        extensionPath: ext.path,\n                        event: \"before_agent_start\",\n                        error: message,\n                        stack,\n                    });\n                }\n            }\n        }\n        return { messages, systemPromptOptions: currentOptions };",
                alt_olds: &[],
                new: "        const messages = [];\n        const entries = [];\n        for (const { ext, handlers } of snapshotEventHandlers(this.extensions, \"before_agent_start\")) {\n            for (const handler of handlers) {\n                try {\n                    const event = {\n                        ...trigger,\n                        type: \"before_agent_start\",\n                        get systemPrompt() {\n                            return renderCurrentSystemPrompt();\n                        },\n                        systemPromptOptions: currentOptions,\n                    };\n                    const handlerResult = await handler(event, ctx);\n                    if (handlerResult) {\n                        const result = handlerResult;\n                        if (result.message)\n                            messages.push(result.message);\n                        if (Array.isArray(result.entries))\n                            entries.push(...result.entries);\n                        if (result.systemPrompt !== undefined) {\n                            currentOptions.forceSystemPrompt = result.systemPrompt;\n                        }\n                    }\n                }\n                catch (err) {\n                    const message = err instanceof Error ? err.message : String(err);\n                    const stack = err instanceof Error ? err.stack : undefined;\n                    this.emitError({\n                        extensionPath: ext.path,\n                        event: \"before_agent_start\",\n                        error: message,\n                        stack,\n                    });\n                }\n            }\n        }\n        return { messages, entries, systemPromptOptions: currentOptions };",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "core_agent_session_prepare_run",
                rel_hint: Some("dist/core/agent-session.js"),
                old: "        const selectedToolsBefore = this._baseSystemPromptOptions.selectedTools;\n        const result = await this._extensionRunner.emitBeforeAgentStart(trigger, this._baseSystemPromptOptions);",
                alt_olds: &["        const selectedToolsBefore = this._baseSystemPromptOptions.selectedTools;\n        const result = await this._extensionRunner.emitBeforeAgentStart(trigger, this._baseSystemPromptOptions);\n        if (Array.isArray(result.entries) && result.entries.length > 0) {\n            this._commitBoundaryDrafts(result.entries);\n        }"],
                new: "        const selectedToolsBefore = this._baseSystemPromptOptions.selectedTools;\n        const result = await this._extensionRunner.emitBeforeAgentStart(trigger, this._baseSystemPromptOptions);\n        if (Array.isArray(result.entries) && result.entries.length > 0) {\n            await this._commitBoundaryDrafts(result.entries);\n        }",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "core_types_before_agent_start",
                rel_hint: Some("dist/core/extensions/types.d.ts"),
                old: "export interface BeforeAgentStartEventResult {\n    message?: Pick<CustomMessage, \"customType\" | \"content\" | \"display\" | \"details\">;\n    /** Replace the complete system prompt for this turn. Later handlers observe this exact override. */\n    systemPrompt?: string;\n}",
                alt_olds: &[],
                new: "export interface BeforeAgentStartEventResult {\n    message?: Pick<CustomMessage, \"customType\" | \"content\" | \"display\" | \"details\">;\n    /** Optional boundary drafts (e.g. self-retaining clean-slate compaction) committed before this run's prompt. */\n    entries?: SessionBoundaryDraft[];\n    /** Replace the complete system prompt for this turn. Later handlers observe this exact override. */\n    systemPrompt?: string;\n}",
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "windows_python_utf8",
        summary: "Inject PYTHONUTF8=1, PYTHONIOENCODING=utf-8, LANG and LC_ALL into Windows shell subprocess env",
        hunks: &[PatchHunk {
            id: "bundle_win_python_utf8",
            rel_hint: None,
            old: r#").join(delimiter);return{...process.env,[pathKey]:updatedPath}}function sanitize"#,
            alt_olds: &[
                r#").join(delimiter);return{...process.env,...process.platform==="win32"?{PYTHONUTF8:process.env.PYTHONUTF8??"1",PYTHONIOENCODING:process.env.PYTHONIOENCODING??"utf-8"}:{},[pathKey]:updatedPath}}function sanitize"#,
            ],
            new: r#").join(delimiter);return{...process.env,...process.platform==="win32"?{PYTHONUTF8:process.env.PYTHONUTF8??"1",PYTHONIOENCODING:process.env.PYTHONIOENCODING??"utf-8",LANG:process.env.LANG??"C.UTF-8",LC_ALL:process.env.LC_ALL??"C.UTF-8"}:{},[pathKey]:updatedPath}}function sanitize"#,
            already_present_markers: &[],
        }],
    },
    PatchSpec {
        id: "codemode_sleep_and_workers",
        summary: "Expose abort-safe await sleep(ms) (max 30s) in codemode QuickJS and raise max workers 2 -> 4",
        hunks: &[
            PatchHunk {
                id: "bundle_codemode_workers",
                rel_hint: None,
                old: r#"*1024*1024,DEFAULT_MAX_CODEMODE_WORKERS=2;function maxCodemodeWorkers()"#,
                alt_olds: &[],
                new: r#"*1024*1024,DEFAULT_MAX_CODEMODE_WORKERS=4;function maxCodemodeWorkers()"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_codemode_sleep_binding",
                rel_hint: None,
                old: r#":samples.get(name)??""});return[{name:"searchTools",spread:!0,execute:args=>{"#,
                alt_olds: &[],
                new: r#":samples.get(name)??""});return[{name:"sleep",spread:!0,execute:([ms],{signal})=>{let c=Math.min(3e4,Math.max(0,Number(ms)||0));return new Promise((res,rej)=>{if(signal?.aborted){rej(new Error("aborted"));return}let onA=()=>{clearTimeout(t);rej(new Error("aborted"))},t=setTimeout(()=>{signal?.removeEventListener("abort",onA);res(c)},c);signal?.addEventListener("abort",onA,{once:!0})})}},{name:"searchTools",spread:!0,execute:args=>{"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_codemode_prompt_hint",
                rel_hint: None,
                old: r#"No Node, file system, network, or timers."#,
                alt_olds: &[],
                new: r#"No Node, file system, or network; await sleep(ms) is available (max 30s)."#,
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "http_keepalive_and_transient_retry",
        summary: "Add resilient HTTP keepAlive (15s/28s/10s), 250ms Happy-Eyeballs connect failover & transient TLS/socket/gateway retry with jittered backoff",
        hunks: &[
            PatchHunk {
                id: "bundle_http_keepalive",
                rel_hint: None,
                old: r#",bodyTimeout:normalizedTimeoutMs,connect:{autoSelectFamilyAttemptTimeout:DEFAULT_AUTO_SELECT_FAMILY_ATTEMPT_TIMEOUT_MS},headersTimeout:normalizedTimeoutMs,cli"#,
                alt_olds: &[
                    r#",bodyTimeout:normalizedTimeoutMs,connectTimeout:20000,keepAliveTimeout:25000,keepAliveMaxTimeout:55000,connect:{autoSelectFamilyAttemptTimeout:DEFAULT_AUTO_SELECT_FAMILY_ATTEMPT_TIMEOUT_MS,timeout:20000,keepAlive:!0,keepAliveInitialDelay:15000},headersTimeout:normalizedTimeoutMs,cli"#,
                ],
                new: r#",bodyTimeout:normalizedTimeoutMs,connectTimeout:35000,keepAliveTimeout:15000,keepAliveMaxTimeout:28000,connect:{autoSelectFamilyAttemptTimeout:DEFAULT_AUTO_SELECT_FAMILY_ATTEMPT_TIMEOUT_MS,timeout:35000,keepAlive:!0,keepAliveInitialDelay:10000},headersTimeout:normalizedTimeoutMs,cli"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_happy_eyeballs_250ms",
                rel_hint: None,
                old: r#"DEFAULT_AUTO_SELECT_FAMILY_ATTEMPT_TIMEOUT_MS=2e3"#,
                alt_olds: &[],
                new: r#"DEFAULT_AUTO_SELECT_FAMILY_ATTEMPT_TIMEOUT_MS=250"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_transient_retry_jitter",
                rel_hint: None,
                old: r#","subscription_sharing_user_unavailable"]),DEFAULT_MAX_AGENT_RETRY_DELAY_MS=6e4;function retryDelayMs(policy,attempt){let delay=policy.baseDelayMs*2**Math.max(0,attempt-1),safeDelay=Number.isSafeInteger(delay)?delay:Number.MAX_SAFE_INTEGER;return Math.min(safeDelay,policy.maxAgentDelayMs??DEFAULT_MAX_AGENT_RETRY_DELAY_MS)}"#,
                alt_olds: &[
                    r#","subscription_sharing_user_unavailable","ECONNRESET","ETIMEDOUT","EPIPE","ECONNABORTED","UND_ERR_SOCKET","UND_ERR_BODY_TIMEOUT","UND_ERR_HEADERS_TIMEOUT","premature close","bad gateway","gateway timeout"]),DEFAULT_MAX_AGENT_RETRY_DELAY_MS=6e4;function retryDelayMs(policy,attempt){let delay=policy.baseDelayMs*2**Math.max(0,attempt-1),safeDelay=Number.isSafeInteger(delay)?delay:Number.MAX_SAFE_INTEGER;let capped=Math.min(safeDelay,policy.maxAgentDelayMs??DEFAULT_MAX_AGENT_RETRY_DELAY_MS);return capped<=0?0:Math.max(100,Math.round(capped*(.85+Math.random()*.3)))}"#,
                    r#","subscription_sharing_user_unavailable","ECONNRESET","ETIMEDOUT","EPIPE","ECONNABORTED","ECONNREFUSED","UND_ERR_SOCKET","UND_ERR_BODY_TIMEOUT","UND_ERR_HEADERS_TIMEOUT","premature close","bad gateway","gateway timeout","socket disconnected","before secure tls","connect timeout","this operation was aborted"]),DEFAULT_MAX_AGENT_RETRY_DELAY_MS=6e4;function retryDelayMs(policy,attempt){let delay=policy.baseDelayMs*2**Math.max(0,attempt-1),safeDelay=Number.isSafeInteger(delay)?delay:Number.MAX_SAFE_INTEGER;let capped=Math.min(safeDelay,policy.maxAgentDelayMs??DEFAULT_MAX_AGENT_RETRY_DELAY_MS);return capped<=0?0:Math.max(100,Math.round(capped*(.85+Math.random()*.3)))}"#,
                    r#","subscription_sharing_user_unavailable","ECONNRESET","ETIMEDOUT","EPIPE","ECONNABORTED","ECONNREFUSED","UND_ERR_SOCKET","UND_ERR_BODY_TIMEOUT","UND_ERR_HEADERS_TIMEOUT","premature close","bad gateway","gateway timeout","socket disconnected","before secure tls","connect timeout","this operation was aborted","temporarily unavailable","retry shortly","connection reset by peer"]),DEFAULT_MAX_AGENT_RETRY_DELAY_MS=6e4;function retryDelayMs(policy,attempt){let delay=policy.baseDelayMs*2**Math.max(0,attempt-1),safeDelay=Number.isSafeInteger(delay)?delay:Number.MAX_SAFE_INTEGER;let capped=Math.min(safeDelay,policy.maxAgentDelayMs??DEFAULT_MAX_AGENT_RETRY_DELAY_MS);return capped<=0?0:Math.max(100,Math.round(capped*(.85+Math.random()*.3)))}"#,
                    r#","subscription_sharing_user_unavailable","ECONNRESET","ETIMEDOUT","EPIPE","ECONNABORTED","ECONNREFUSED","UND_ERR_SOCKET","UND_ERR_BODY_TIMEOUT","UND_ERR_HEADERS_TIMEOUT","premature close","bad gateway","gateway timeout","socket disconnected","before secure tls","connect timeout","this operation was aborted","temporarily unavailable","retry shortly","connection reset by peer","other side closed","terminated","request timed out","und_err_connect_timeout"]),DEFAULT_MAX_AGENT_RETRY_DELAY_MS=6e4;function retryDelayMs(policy,attempt){let delay=policy.baseDelayMs*2**Math.max(0,attempt-1),safeDelay=Number.isSafeInteger(delay)?delay:Number.MAX_SAFE_INTEGER;let capped=Math.min(safeDelay,policy.maxAgentDelayMs??DEFAULT_MAX_AGENT_RETRY_DELAY_MS);return capped<=0?0:Math.max(100,Math.round(capped*(.85+Math.random()*.3)))}"#,
                ],
                new: r#","subscription_sharing_user_unavailable","ECONNRESET","ETIMEDOUT","EPIPE","ECONNABORTED","ECONNREFUSED","UND_ERR_SOCKET","UND_ERR_BODY_TIMEOUT","UND_ERR_HEADERS_TIMEOUT","premature close","bad gateway","gateway timeout","socket disconnected","before secure tls","connect timeout","this operation was aborted","temporarily unavailable","retry shortly","connection reset by peer","other side closed","terminated","request timed out","und_err_connect_timeout","ENOTFOUND","EAI_AGAIN","ENETUNREACH","EHOSTUNREACH","fetch failed","socket hang up"]),DEFAULT_MAX_AGENT_RETRY_DELAY_MS=6e4;function retryDelayMs(policy,attempt){let delay=policy.baseDelayMs*2**Math.max(0,attempt-1),safeDelay=Number.isSafeInteger(delay)?delay:Number.MAX_SAFE_INTEGER;let capped=Math.min(safeDelay,policy.maxAgentDelayMs??DEFAULT_MAX_AGENT_RETRY_DELAY_MS);return capped<=0?0:Math.max(100,Math.round(capped*(.85+Math.random()*.3)))}"#,
                already_present_markers: &[
                    "subscription_sharing_user_unavailable",
                    "UND_ERR_SOCKET",
                    "UND_ERR_BODY_TIMEOUT",
                    "und_err_connect_timeout",
                    "ENETUNREACH",
                    "EHOSTUNREACH",
                    "(.85+Math.random()*.3)",
                ],
            },
        ],
    },
    PatchSpec {
        id: "virtual_model_cache_warmer",
        summary: "Allow virtual models (e.g. deepseek/flash-auto) to match CacheWarmer physical sessions",
        hunks: &[PatchHunk {
            id: "bundle_virtual_cache_warmer",
            rel_hint: None,
            old: r#"Model.provider===requestModel.provider&&currentModel.id===requestModel.id&&messages.length<=currentMessages.lengt"#,
            alt_olds: &[],
            new: r#"Model.provider===requestModel.provider&&(currentModel.id===requestModel.id||currentModel.api==="pi-virtual")&&messages.length<=currentMessages.lengt"#,
            already_present_markers: &[],
        }],
    },
    PatchSpec {
        id: "codemode_web_builtins",
        summary: "Provide QuickJS setTimeout/clearTimeout/atob/btoa/TextEncoder/TextDecoder/Buffer and stop wrapper from shadowing prelude globals",
        hunks: &[
            PatchHunk {
                id: "bundle_codemode_worker_builtins",
                rel_hint: None,
                old: CODEMODE_BUILTINS_OLD,
                alt_olds: &[CODEMODE_BUILTINS_ALT],
                new: CODEMODE_BUILTINS_NEW,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_codemode_no_shadow_globals",
                rel_hint: Some("dist/bundle/chunks/codemode-worker.js"),
                old: CODEMODE_WRAPPER_OLD,
                alt_olds: &[],
                new: CODEMODE_WRAPPER_NEW,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "prelude_codemode_builtins",
                rel_hint: Some("node_modules/@earendil-works/pi-codemode/dist/runtime/prelude-source.js"),
                old: CODEMODE_BUILTINS_OLD,
                alt_olds: &[CODEMODE_BUILTINS_ALT],
                new: CODEMODE_BUILTINS_NEW,
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "sequential_shell_tool_barrier",
        summary: "Run bash/powershell calls sequentially as barriers while keeping adjacent read/search calls parallel (eliminates shell+read race ENOENT)",
        hunks: &[
            PatchHunk {
                id: "bundle_execute_tool_calls_barrier",
                rel_hint: None,
                old: r#"async function executeToolCalls(currentContext,assistantMessage,config,signal,emit){let toolCalls=assistantMessage.content.filter(c=>c.type==="toolCall"),hasSequentialToolCall=toolCalls.some(tc=>currentContext.tools?.find(t=>t.name===tc.name)?.executionMode==="sequential");return config.toolExecution==="sequential"||hasSequentialToolCall?executeToolCallsSequential(currentContext,assistantMessage,toolCalls,config,signal,emit):executeToolCallsParallel(currentContext,assistantMessage,toolCalls,config,signal,emit)}"#,
                alt_olds: &[
                    r#"async function executeToolCalls(currentContext,assistantMessage,config,signal,emit){let toolCalls=assistantMessage.content.filter(c=>c.type==="toolCall");if(config.toolExecution==="sequential")return executeToolCallsSequential(currentContext,assistantMessage,toolCalls,config,signal,emit);let segments=[];for(let tc of toolCalls){let isSeq=currentContext.tools?.find(t=>t.name===tc.name)?.executionMode==="sequential",last=segments[segments.length-1];!isSeq&&last?.mode==="parallel"?last.toolCalls.push(tc):segments.push({mode:isSeq?"sequential":"parallel",toolCalls:[tc]})}let messages=[],terminate=toolCalls.length>0;for(let seg of segments){let batch=await(seg.mode==="sequential"?executeToolCallsSequential:executeToolCallsParallel)(currentContext,assistantMessage,seg.toolCalls,config,signal,emit);if(messages.push(...batch.messages),terminate&&=!batch.terminate===!1,!batch.terminate)break}return{messages,terminate}}"#,
                ],
                new: r#"async function executeToolCalls(currentContext,assistantMessage,config,signal,emit){let toolCalls=assistantMessage.content.filter(c=>c.type==="toolCall");if(config.toolExecution==="sequential")return executeToolCallsSequential(currentContext,assistantMessage,toolCalls,config,signal,emit);let segments=[];for(let tc of toolCalls){let isSeq=currentContext.tools?.find(t=>t.name===tc.name)?.executionMode==="sequential",last=segments[segments.length-1];!isSeq&&last?.mode==="parallel"?last.toolCalls.push(tc):segments.push({mode:isSeq?"sequential":"parallel",toolCalls:[tc]})}let messages=[],terminate=toolCalls.length>0;for(let seg of segments){let batch=await(seg.mode==="sequential"?executeToolCallsSequential:executeToolCallsParallel)(currentContext,assistantMessage,seg.toolCalls,config,signal,emit);if(messages.push(...batch.messages),terminate=terminate&&batch.terminate,signal?.aborted)break}return{messages,terminate}}"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_shell_tool_execution_mode",
                rel_hint: None,
                old: r#"function createShellToolDefinition(cwd,config,options){let ops=options?.operations??createLocalBashOperations({shellPath:options?.shellPath}),commandPrefix=options?.commandPrefix,exposeSessionEnvironment=options?.exposeSessionEnvironment??!0,spawnHook=options?.spawnHook;return{name:config.name,label:config.label,"#,
                alt_olds: &[],
                new: r#"function createShellToolDefinition(cwd,config,options){let ops=options?.operations??createLocalBashOperations({shellPath:options?.shellPath}),commandPrefix=options?.commandPrefix,exposeSessionEnvironment=options?.exposeSessionEnvironment??!0,spawnHook=options?.spawnHook;return{name:config.name,label:config.label,executionMode:"sequential","#,
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "boundary_compaction_event",
        summary: "Emit session_compact for boundary-draft compactions so extensions & cache trackers reset cleanly on auto-rotations",
        hunks: &[
            PatchHunk {
                id: "bundle_commit_boundary_drafts_emit",
                rel_hint: None,
                old: r#"_commitBoundaryDrafts(drafts){let appended=this._applyBoundaryDrafts(this.sessionManager,drafts);this._refreshFinalizedContext();for(let entry of appended)this._emit({type:"entry_appended",entry})}"#,
                alt_olds: &[],
                new: r#"async _commitBoundaryDrafts(drafts){let appended=this._applyBoundaryDrafts(this.sessionManager,drafts);this._refreshFinalizedContext();for(let entry of appended){this._emit({type:"entry_appended",entry});if(entry.type==="compaction"&&this._extensionRunner.hasHandlers("session_compact"))await this._extensionRunner.emit({type:"session_compact",compactionEntry:entry,fromExtension:!0,reason:"threshold",willRetry:!1})}}"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_await_commit_turn_end",
                rel_hint: None,
                old: r#"return this._commitBoundaryDrafts(boundary.entries),boundary.continue&&!this._buildBoundaryContext([],"turn_end").canContinue?"#,
                alt_olds: &[],
                new: r#"return await this._commitBoundaryDrafts(boundary.entries),boundary.continue&&!this._buildBoundaryContext([],"turn_end").canContinue?"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_await_commit_before_settle",
                rel_hint: None,
                old: r#"this._commitBoundaryDrafts(result.entries),this._flushPendingCustomMessages();"#,
                alt_olds: &[],
                new: r#"await this._commitBoundaryDrafts(result.entries),this._flushPendingCustomMessages();"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "core_commit_boundary_drafts_emit",
                rel_hint: Some("dist/core/agent-session.js"),
                old: "    _commitBoundaryDrafts(drafts) {\n        const appended = this._applyBoundaryDrafts(this.sessionManager, drafts);\n        this._refreshFinalizedContext();\n        for (const entry of appended)\n            this._emit({ type: \"entry_appended\", entry });\n    }",
                alt_olds: &[],
                new: "    async _commitBoundaryDrafts(drafts) {\n        const appended = this._applyBoundaryDrafts(this.sessionManager, drafts);\n        this._refreshFinalizedContext();\n        for (const entry of appended) {\n            this._emit({ type: \"entry_appended\", entry });\n            if (entry.type === \"compaction\" && this._extensionRunner.hasHandlers(\"session_compact\")) {\n                await this._extensionRunner.emit({\n                    type: \"session_compact\",\n                    compactionEntry: entry,\n                    fromExtension: true,\n                    reason: \"threshold\",\n                    willRetry: false,\n                });\n            }\n        }\n    }",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "core_await_commit_turn_end",
                rel_hint: Some("dist/core/agent-session.js"),
                old: "        this._commitBoundaryDrafts(boundary.entries);\n        if (boundary.continue && !this._buildBoundaryContext([], \"turn_end\").canContinue) {",
                alt_olds: &[],
                new: "        await this._commitBoundaryDrafts(boundary.entries);\n        if (boundary.continue && !this._buildBoundaryContext([], \"turn_end\").canContinue) {",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "core_await_commit_before_settle",
                rel_hint: Some("dist/core/agent-session.js"),
                old: "            this._commitBoundaryDrafts(result.entries);\n            this._flushPendingCustomMessages();",
                alt_olds: &[],
                new: "            await this._commitBoundaryDrafts(result.entries);\n            this._flushPendingCustomMessages();",
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "cjk_calibrated_compaction_budget",
        summary: "Weight CJK/fullwidth characters and calibrate keepRecentTokens against provider-reported prompt_tokens to prevent 2-3x compaction overshoot",
        hunks: &[
            PatchHunk {
                id: "bundle_cjk_weighted_token_estimate",
                rel_hint: None,
                old: r#"function estimateTextAndImageContentChars(content){if(typeof content=="string")return content.length;let chars=0;for(let block of content)block.type==="text"&&block.text?chars+=block.text.length:block.type==="image"&&(chars+=ESTIMATED_IMAGE_CHARS);return chars}function estimateTokens(message){let chars=0;switch(message.role){case"system":{let system=message;if(chars=estimateTextAndImageContentChars(system.content),system.sections)for(let section of Object.values(system.sections))section&&(chars+=section.length);return system.toolsAdded&&(chars+=JSON.stringify(system.toolsAdded).length),Math.ceil(chars/4)}case"user":return chars=estimateTextAndImageContentChars(message.content),Math.ceil(chars/4);case"assistant":{let assistant=message;for(let block of assistant.content)block.type==="text"?chars+=block.text.length:block.type==="thinking"?chars+=block.thinking.length:block.type==="toolCall"&&(chars+=block.name.length+JSON.stringify(block.arguments).length);return Math.ceil(chars/4)}case"custom":case"toolResult":return chars=estimateTextAndImageContentChars(message.content),Math.ceil(chars/4);case"bashExecution":return chars=message.command.length+message.output.length,Math.ceil(chars/4);case"branchSummary":case"compactionSummary":return chars=message.summary.length,Math.ceil(chars/4)}return 0}"#,
                alt_olds: &[],
                new: r#"function _cjkWeightedChars(s){if(!s)return 0;let n=s.length,w=n;for(let i=0;i<n;i++)s.charCodeAt(i)>=11904&&(w+=3.4);return w}function estimateTextAndImageContentChars(content){if(typeof content=="string")return _cjkWeightedChars(content);let chars=0;for(let block of content)block.type==="text"&&block.text?chars+=_cjkWeightedChars(block.text):block.type==="image"&&(chars+=ESTIMATED_IMAGE_CHARS);return chars}function estimateTokens(message){let chars=0;switch(message.role){case"system":{let system=message;if(chars=estimateTextAndImageContentChars(system.content),system.sections)for(let section of Object.values(system.sections))section&&(chars+=_cjkWeightedChars(section));return system.toolsAdded&&(chars+=_cjkWeightedChars(JSON.stringify(system.toolsAdded))),Math.ceil(chars/4)}case"user":return chars=estimateTextAndImageContentChars(message.content),Math.ceil(chars/4);case"assistant":{let assistant=message;for(let block of assistant.content)block.type==="text"?chars+=_cjkWeightedChars(block.text):block.type==="thinking"?chars+=_cjkWeightedChars(block.thinking):block.type==="toolCall"&&(chars+=block.name.length+_cjkWeightedChars(JSON.stringify(block.arguments)));return Math.ceil(chars/4)}case"custom":case"toolResult":return chars=estimateTextAndImageContentChars(message.content),Math.ceil(chars/4);case"bashExecution":return chars=_cjkWeightedChars(message.command)+_cjkWeightedChars(message.output),Math.ceil(chars/4);case"branchSummary":case"compactionSummary":return chars=_cjkWeightedChars(message.summary),Math.ceil(chars/4)}return 0}"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_usage_calibrated_compaction_cut",
                rel_hint: None,
                old: r#"let boundaryEnd=projectedEntries.length,tokensBefore=estimateProjectedContextTokens(projection,pathEntries).tokens,cutPoint=findProjectedCutPoint(projectedEntries,boundaryStart,boundaryEnd,settings.keepRecentTokens)"#,
                alt_olds: &[
                    r#"let boundaryEnd=projectedEntries.length,tokensBefore=estimateProjectedContextTokens(projection,pathEntries).tokens,_est=0;for(let _i=boundaryStart;_i<boundaryEnd;_i++)for(let _m of projectedEntries[_i].messages)_est+=estimateTokens(_m);let _cal=_est>0&&tokensBefore>0?Math.min(4,Math.max(1,tokensBefore/_est)):1,cutPoint=findProjectedCutPoint(projectedEntries,boundaryStart,boundaryEnd,Math.max(1024,Math.floor(settings.keepRecentTokens/_cal)))"#,
                ],
                new: r#"let boundaryEnd=projectedEntries.length,tokensBefore=estimateProjectedContextTokens(projection,pathEntries).tokens,_est=0;for(let _i=boundaryStart;_i<boundaryEnd;_i++)for(let _m of projectedEntries[_i].messages)_est+=estimateTokens(_m);let _cal=_est>=25e3&&tokensBefore>0?Math.min(4,Math.max(1,tokensBefore/_est)):1,cutPoint=findProjectedCutPoint(projectedEntries,boundaryStart,boundaryEnd,Math.max(1024,Math.floor(settings.keepRecentTokens/_cal)))"#,
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "deterministic_tool_order",
        summary: "Sort resolved transcript tools deterministically by name so MCP reconnects/reloads never bust prompt KV-cache",
        hunks: &[PatchHunk {
            id: "bundle_sort_current_tools",
            rel_hint: None,
            old: r#"function getCurrentTools(messages){let tools=new Map;for(let message of messages)if(isSystemMessage(message)){for(let tool of message.toolsRemoved??[])tools.delete(tool.name);for(let tool of message.toolsAdded??[])tools.set(tool.name,tool)}return[...tools.values()]}"#,
            alt_olds: &[],
            new: r#"function getCurrentTools(messages){let tools=new Map;for(let message of messages)if(isSystemMessage(message)){for(let tool of message.toolsRemoved??[])tools.delete(tool.name);for(let tool of message.toolsAdded??[])tools.set(tool.name,tool)}return[...tools.values()].sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)}"#,
            already_present_markers: &[],
        }],
    },
    PatchSpec {
        id: "codemode_text_returns_rendered",
        summary: "Return rendered string from QuickJS codemode text(value) helper to prevent TypeError on text(x).slice()/trim()",
        hunks: &[
            PatchHunk {
                id: "bundle_codemode_text_return",
                rel_hint: None,
                old: "\t\toutput(\"text\", rendered);\n\t}\n\n\tfunction imageUrl(value) {",
                alt_olds: &[],
                new: "\t\toutput(\"text\", rendered);\n\t\treturn rendered;\n\t}\n\n\tfunction imageUrl(value) {",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "prelude_codemode_text_return",
                rel_hint: Some("node_modules/@earendil-works/pi-codemode/dist/runtime/prelude-source.js"),
                old: "\t\toutput(\"text\", rendered);\n\t}\n\n\tfunction imageUrl(value) {",
                alt_olds: &[],
                new: "\t\toutput(\"text\", rendered);\n\t\treturn rendered;\n\t}\n\n\tfunction imageUrl(value) {",
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "codemode_result_output_shim",
        summary: "Attach writable non-enumerable .output string shim & extensible container clone on QuickJS codemode tool-result objects and pre-lockdown String.prototype.output",
        hunks: &[
            PatchHunk {
                id: "bundle_codemode_result_output_shim",
                rel_hint: None,
                old: "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tentry.resolve(value);",
                alt_olds: &[
                    "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && !(\"output\" in value)) {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(\"\\n\") : stringify(value);\n\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, enumerable: false, configurable: true });\n\t\t\t}\n\t\t\tentry.resolve(value);",
                    "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && typeof value.output !== \"string\") {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(\"\\n\") : stringify(value);\n\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, enumerable: false, configurable: true });\n\t\t\t}\n\t\t\tentry.resolve(value);",
                    "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && typeof value.output !== \"string\") {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(String.fromCharCode(10)) : stringify(value);\n\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, enumerable: false, configurable: true });\n\t\t\t}\n\t\t\tentry.resolve(value);",
                    "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (typeof \"\".output !== \"string\") {\n\t\t\t\tObject.defineProperty(String.prototype, \"output\", { get() { return String(this); }, enumerable: false, configurable: true });\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && typeof value.output !== \"string\") {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(String.fromCharCode(10)) : stringify(value);\n\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, enumerable: false, configurable: true });\n\t\t\t}\n\t\t\tentry.resolve(value);",
                    "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (typeof \"\".output !== \"string\" && Object.isExtensible(String.prototype)) {\n\t\t\t\ttry { Object.defineProperty(String.prototype, \"output\", { get() { return String(this); }, enumerable: false, configurable: true }); } catch (_e) {}\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && typeof value.output !== \"string\") {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(String.fromCharCode(10)) : stringify(value);\n\t\t\t\ttry {\n\t\t\t\t\tif (!Object.isExtensible(value)) value = Object.assign({}, value);\n\t\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, enumerable: false, configurable: true });\n\t\t\t\t} catch (_e) {}\n\t\t\t}\n\t\t\tentry.resolve(value);",
                ],
                new: "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (typeof \"\".output !== \"string\" && Object.isExtensible(String.prototype)) {\n\t\t\t\ttry { Object.defineProperty(String.prototype, \"output\", { get() { return String(this); }, enumerable: false, configurable: true }); } catch (_e) {}\n\t\t\t}\n\t\t\tfunction _cloneExtensible(v, d) {\n\t\t\t\tif (!v || typeof v !== \"object\" || (d || 0) > 4) return v;\n\t\t\t\tif (Array.isArray(v)) { const arr = Object.isExtensible(v) ? v : v.slice(); for (let i = 0; i < arr.length; i++) { if (arr[i] && typeof arr[i] === \"object\" && !Object.isExtensible(arr[i])) arr[i] = _cloneExtensible(arr[i], (d || 0) + 1); } return arr; }\n\t\t\t\tconst outObj = Object.isExtensible(v) ? v : Object.assign({}, v);\n\t\t\t\tfor (const k of Object.keys(outObj)) { if (outObj[k] && typeof outObj[k] === \"object\" && !Object.isExtensible(outObj[k])) outObj[k] = _cloneExtensible(outObj[k], (d || 0) + 1); }\n\t\t\t\treturn outObj;\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\") value = _cloneExtensible(value, 0);\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && typeof value.output !== \"string\") {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(String.fromCharCode(10)) : stringify(value);\n\t\t\t\ttry {\n\t\t\t\t\tif (!Object.isExtensible(value)) value = Object.assign({}, value);\n\t\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, writable: true, enumerable: false, configurable: true });\n\t\t\t\t} catch (_e) {}\n\t\t\t}\n\t\t\tentry.resolve(value);",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "prelude_codemode_result_output_shim",
                rel_hint: Some("node_modules/@earendil-works/pi-codemode/dist/runtime/prelude-source.js"),
                old: "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tentry.resolve(value);",
                alt_olds: &[
                    "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && !(\"output\" in value)) {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(\"\\n\") : stringify(value);\n\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, enumerable: false, configurable: true });\n\t\t\t}\n\t\t\tentry.resolve(value);",
                    "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && typeof value.output !== \"string\") {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(\"\\n\") : stringify(value);\n\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, enumerable: false, configurable: true });\n\t\t\t}\n\t\t\tentry.resolve(value);",
                    "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && typeof value.output !== \"string\") {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(String.fromCharCode(10)) : stringify(value);\n\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, enumerable: false, configurable: true });\n\t\t\t}\n\t\t\tentry.resolve(value);",
                    "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (typeof \"\".output !== \"string\") {\n\t\t\t\tObject.defineProperty(String.prototype, \"output\", { get() { return String(this); }, enumerable: false, configurable: true });\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && typeof value.output !== \"string\") {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(String.fromCharCode(10)) : stringify(value);\n\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, enumerable: false, configurable: true });\n\t\t\t}\n\t\t\tentry.resolve(value);",
                    "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (typeof \"\".output !== \"string\" && Object.isExtensible(String.prototype)) {\n\t\t\t\ttry { Object.defineProperty(String.prototype, \"output\", { get() { return String(this); }, enumerable: false, configurable: true }); } catch (_e) {}\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && typeof value.output !== \"string\") {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(String.fromCharCode(10)) : stringify(value);\n\t\t\t\ttry {\n\t\t\t\t\tif (!Object.isExtensible(value)) value = Object.assign({}, value);\n\t\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, enumerable: false, configurable: true });\n\t\t\t\t} catch (_e) {}\n\t\t\t}\n\t\t\tentry.resolve(value);",
                ],
                new: "\t\t\tlet value;\n\t\t\ttry {\n\t\t\t\tvalue = payload === undefined ? undefined : parse(payload);\n\t\t\t} catch (error) {\n\t\t\t\tentry.reject(error);\n\t\t\t\treturn;\n\t\t\t}\n\t\t\tif (typeof \"\".output !== \"string\" && Object.isExtensible(String.prototype)) {\n\t\t\t\ttry { Object.defineProperty(String.prototype, \"output\", { get() { return String(this); }, enumerable: false, configurable: true }); } catch (_e) {}\n\t\t\t}\n\t\t\tfunction _cloneExtensible(v, d) {\n\t\t\t\tif (!v || typeof v !== \"object\" || (d || 0) > 4) return v;\n\t\t\t\tif (Array.isArray(v)) { const arr = Object.isExtensible(v) ? v : v.slice(); for (let i = 0; i < arr.length; i++) { if (arr[i] && typeof arr[i] === \"object\" && !Object.isExtensible(arr[i])) arr[i] = _cloneExtensible(arr[i], (d || 0) + 1); } return arr; }\n\t\t\t\tconst outObj = Object.isExtensible(v) ? v : Object.assign({}, v);\n\t\t\t\tfor (const k of Object.keys(outObj)) { if (outObj[k] && typeof outObj[k] === \"object\" && !Object.isExtensible(outObj[k])) outObj[k] = _cloneExtensible(outObj[k], (d || 0) + 1); }\n\t\t\t\treturn outObj;\n\t\t\t}\n\t\t\tif (value && typeof value === \"object\") value = _cloneExtensible(value, 0);\n\t\t\tif (value && typeof value === \"object\" && !Array.isArray(value) && typeof value.output !== \"string\") {\n\t\t\t\tconst _out = typeof value.text === \"string\" ? value.text : typeof value.stdout === \"string\" ? value.stdout : Array.isArray(value.content) ? value.content.map((c) => c && typeof c.text === \"string\" ? c.text : \"\").filter(Boolean).join(String.fromCharCode(10)) : stringify(value);\n\t\t\t\ttry {\n\t\t\t\t\tif (!Object.isExtensible(value)) value = Object.assign({}, value);\n\t\t\t\t\tObject.defineProperty(value, \"output\", { value: _out, writable: true, enumerable: false, configurable: true });\n\t\t\t\t} catch (_e) {}\n\t\t\t}\n\t\t\tentry.resolve(value);",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_codemode_string_output_prelockdown",
                rel_hint: None,
                old: "\t\"use strict\";\n\n\t// Freeze every object reachable from the built-in globals,",
                alt_olds: &[],
                new: "\t\"use strict\";\n\tif (typeof \"\".output !== \"string\" && Object.isExtensible(String.prototype)) {\n\t\ttry { Object.defineProperty(String.prototype, \"output\", { get() { return String(this); }, enumerable: false, configurable: true }); } catch (_e) {}\n\t}\n\n\t// Freeze every object reachable from the built-in globals,",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "prelude_codemode_string_output_prelockdown",
                rel_hint: Some("node_modules/@earendil-works/pi-codemode/dist/runtime/prelude-source.js"),
                old: "\t\"use strict\";\n\n\t// Freeze every object reachable from the built-in globals,",
                alt_olds: &[],
                new: "\t\"use strict\";\n\tif (typeof \"\".output !== \"string\" && Object.isExtensible(String.prototype)) {\n\t\ttry { Object.defineProperty(String.prototype, \"output\", { get() { return String(this); }, enumerable: false, configurable: true }); } catch (_e) {}\n\t}\n\n\t// Freeze every object reachable from the built-in globals,",
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "tool_result_preserve_codemode_structured_content",
        summary: "Preserve structuredContent on codemode child tool_result hooks when extensions modify content without structuredContent (prevents tools.bash(...).output TypeError)",
        hunks: &[
            PatchHunk {
                id: "bundle_tool_result_preserve_codemode_structured_content",
                rel_hint: None,
                old: "handlerResult.content!==void 0&&(currentEvent.content=handlerResult.content,handlerResult.structuredContent===void 0&&delete currentEvent.structuredContent,modified=!0)",
                alt_olds: &[],
                new: "handlerResult.content!==void 0&&(currentEvent.content=handlerResult.content,handlerResult.structuredContent===void 0&&!currentEvent.parentToolCallId&&delete currentEvent.structuredContent,modified=!0)",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "runner_tool_result_preserve_codemode_structured_content",
                rel_hint: Some("dist/core/extensions/runner.js"),
                old: "                        // Structured content that is not replaced along with the content may no longer match it.\n                        if (handlerResult.structuredContent === undefined)\n                            delete currentEvent.structuredContent;",
                alt_olds: &[],
                new: "                        // Structured content that is not replaced along with the content may no longer match it.\n                        if (handlerResult.structuredContent === undefined && !currentEvent.parentToolCallId)\n                            delete currentEvent.structuredContent;",
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "windows_utf8_shell_env",
        summary: "Lock PYTHONUTF8=1, PYTHONIOENCODING=utf-8, LANG=C.UTF-8 & LC_ALL=C.UTF-8 in Pi Windows getShellEnv() (prevents GBK crashes even on write/destructive shell commands)",
        hunks: &[
            PatchHunk {
                id: "bundle_windows_utf8_shell_env",
                rel_hint: None,
                old: "function getShellEnv(){let binDir=getBinDir(),pathKey=Object.keys(process.env).find(key=>key.toLowerCase()===\"path\")??\"PATH\",currentPath=process.env[pathKey]??\"\",updatedPath=currentPath.split(delimiter).filter(Boolean).includes(binDir)?currentPath:[binDir,currentPath].filter(Boolean).join(delimiter);return{...process.env,[pathKey]:updatedPath}}",
                alt_olds: &[],
                new: "function getShellEnv(){let binDir=getBinDir(),pathKey=Object.keys(process.env).find(key=>key.toLowerCase()===\"path\")??\"PATH\",currentPath=process.env[pathKey]??\"\",updatedPath=currentPath.split(delimiter).filter(Boolean).includes(binDir)?currentPath:[binDir,currentPath].filter(Boolean).join(delimiter);return{...process.env,...process.platform===\"win32\"?{PYTHONUTF8:process.env.PYTHONUTF8??\"1\",PYTHONIOENCODING:process.env.PYTHONIOENCODING??\"utf-8\",LANG:process.env.LANG??\"C.UTF-8\",LC_ALL:process.env.LC_ALL??\"C.UTF-8\"}:{},[pathKey]:updatedPath}}",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "shell_windows_utf8_shell_env",
                rel_hint: Some("dist/utils/shell.js"),
                old: "    return {\n        ...process.env,\n        [pathKey]: updatedPath,\n    };",
                alt_olds: &[],
                new: "    return {\n        ...process.env,\n        ...(process.platform === \"win32\" ? { PYTHONUTF8: process.env.PYTHONUTF8 ?? \"1\", PYTHONIOENCODING: process.env.PYTHONIOENCODING ?? \"utf-8\", LANG: process.env.LANG ?? \"C.UTF-8\", LC_ALL: process.env.LC_ALL ?? \"C.UTF-8\" } : {}),\n        [pathKey]: updatedPath,\n    };",
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "codemode_strip_null_tool_args",
        summary: "Strip top-level null optional properties on QuickJS codemode tools.* calls so strict schemas never reject explicit null fields (template-literal-safe)",
        hunks: &[
            PatchHunk {
                id: "bundle_codemode_strip_null_args",
                rel_hint: None,
                old: "\tfunction caller(kind, name, spread) {\n\t\treturn (...args) =>\n\t\t\tnew Promise((resolve, reject) => {\n\t\t\t\tlet json;\n\t\t\t\ttry {\n\t\t\t\t\tjson = serialize(spread ? args : args[0]);",
                alt_olds: &[],
                new: "\tfunction caller(kind, name, spread) {\n\t\treturn (...args) =>\n\t\t\tnew Promise((resolve, reject) => {\n\t\t\t\tlet json;\n\t\t\t\ttry {\n\t\t\t\t\tlet _arg = spread ? args : args[0];\n\t\t\t\t\tif (kind === \"call\" && !spread && _arg && typeof _arg === \"object\" && !Array.isArray(_arg)) { const _clean = {}; for (const _k of Object.keys(_arg)) { if (_arg[_k] !== null) _clean[_k] = _arg[_k]; } _arg = _clean; }\n\t\t\t\t\tjson = serialize(_arg);",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "prelude_codemode_strip_null_args",
                rel_hint: Some("node_modules/@earendil-works/pi-codemode/dist/runtime/prelude-source.js"),
                old: "\tfunction caller(kind, name, spread) {\n\t\treturn (...args) =>\n\t\t\tnew Promise((resolve, reject) => {\n\t\t\t\tlet json;\n\t\t\t\ttry {\n\t\t\t\t\tjson = serialize(spread ? args : args[0]);",
                alt_olds: &[],
                new: "\tfunction caller(kind, name, spread) {\n\t\treturn (...args) =>\n\t\t\tnew Promise((resolve, reject) => {\n\t\t\t\tlet json;\n\t\t\t\ttry {\n\t\t\t\t\tlet _arg = spread ? args : args[0];\n\t\t\t\t\tif (kind === \"call\" && !spread && _arg && typeof _arg === \"object\" && !Array.isArray(_arg)) { const _clean = {}; for (const _k of Object.keys(_arg)) { if (_arg[_k] !== null) _clean[_k] = _arg[_k]; } _arg = _clean; }\n\t\t\t\t\tjson = serialize(_arg);",
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "codemode_global_log_helper",
        summary: "Expose writable/configurable globalThis.log(...args) alias to console.log inside QuickJS codemode scripts to eliminate ReferenceError: log is not defined (template-literal-safe)",
        hunks: &[
            PatchHunk {
                id: "bundle_codemode_global_log",
                rel_hint: None,
                old: "\tObject.defineProperty(globalThis, \"console\", { value: console, enumerable: true });\n\tObject.defineProperty(globalThis, \"text\", { value: text, enumerable: true });",
                alt_olds: &[],
                new: "\tObject.defineProperty(globalThis, \"console\", { value: console, enumerable: true });\n\tObject.defineProperty(globalThis, \"log\", { value: (...args) => { console.log(...args); }, writable: true, enumerable: true, configurable: true });\n\tObject.defineProperty(globalThis, \"text\", { value: text, enumerable: true });",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "prelude_codemode_global_log",
                rel_hint: Some("node_modules/@earendil-works/pi-codemode/dist/runtime/prelude-source.js"),
                old: "\tObject.defineProperty(globalThis, \"console\", { value: console, enumerable: true });\n\tObject.defineProperty(globalThis, \"text\", { value: text, enumerable: true });",
                alt_olds: &[],
                new: "\tObject.defineProperty(globalThis, \"console\", { value: console, enumerable: true });\n\tObject.defineProperty(globalThis, \"log\", { value: (...args) => { console.log(...args); }, writable: true, enumerable: true, configurable: true });\n\tObject.defineProperty(globalThis, \"text\", { value: text, enumerable: true });",
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "codemode_mcp_short_aliases",
        summary: "Expose unique MCP short aliases (tools.foo -> tools.mcp__server__foo) and describeTool suffix fallback inside QuickJS codemode (template-literal-safe)",
        hunks: &[
            PatchHunk {
                id: "bundle_codemode_mcp_short_aliases",
                rel_hint: None,
                old: "\t\tif (!(name in tools)) tools[name] = fn;\n\t}\n\tObject.freeze(tools);",
                alt_olds: &[],
                new: "\t\tif (!(name in tools)) tools[name] = fn;\n\t}\n\tconst _mcpCounts = new Map();\n\tconst _mcpShort = [];\n\tfor (const { jsName } of allTools) {\n\t\tconst _m = /^mcp__[A-Za-z0-9_]+__(.+)$/.exec(jsName);\n\t\tif (_m && _m[1]) {\n\t\t\t_mcpCounts.set(_m[1], (_mcpCounts.get(_m[1]) || 0) + 1);\n\t\t\t_mcpShort.push([_m[1], jsName]);\n\t\t}\n\t}\n\tfor (const [_sh, _jn] of _mcpShort) {\n\t\tif (_mcpCounts.get(_sh) === 1 && !(_sh in tools)) {\n\t\t\tObject.defineProperty(tools, _sh, { value: tools[_jn], enumerable: false, configurable: false });\n\t\t}\n\t}\n\tObject.freeze(tools);",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "prelude_codemode_mcp_short_aliases",
                rel_hint: Some("node_modules/@earendil-works/pi-codemode/dist/runtime/prelude-source.js"),
                old: "\t\tif (!(name in tools)) tools[name] = fn;\n\t}\n\tObject.freeze(tools);",
                alt_olds: &[],
                new: "\t\tif (!(name in tools)) tools[name] = fn;\n\t}\n\tconst _mcpCounts = new Map();\n\tconst _mcpShort = [];\n\tfor (const { jsName } of allTools) {\n\t\tconst _m = /^mcp__[A-Za-z0-9_]+__(.+)$/.exec(jsName);\n\t\tif (_m && _m[1]) {\n\t\t\t_mcpCounts.set(_m[1], (_mcpCounts.get(_m[1]) || 0) + 1);\n\t\t\t_mcpShort.push([_m[1], jsName]);\n\t\t}\n\t}\n\tfor (const [_sh, _jn] of _mcpShort) {\n\t\tif (_mcpCounts.get(_sh) === 1 && !(_sh in tools)) {\n\t\t\tObject.defineProperty(tools, _sh, { value: tools[_jn], enumerable: false, configurable: false });\n\t\t}\n\t}\n\tObject.freeze(tools);",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "execute_describe_tool_mcp_alias",
                rel_hint: Some("dist/extensions/codemode/execute.js"),
                old: "                const tool = tools.find((candidate) => candidate.name === name || toCodemodeIdentifier(candidate.name) === name);",
                alt_olds: &[],
                new: "                let tool = tools.find((candidate) => candidate.name === name || toCodemodeIdentifier(candidate.name) === name);\n                if (!tool) { const _suf = \"__\" + name; const _m = tools.filter((c) => c.name.endsWith(_suf) || toCodemodeIdentifier(c.name).endsWith(_suf)); if (_m.length === 1) tool = _m[0]; }",
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_execute_describe_tool_mcp_alias",
                rel_hint: None,
                old: r#"{name:"describeTool",spread:!0,execute:args=>{let[name]=args;if(typeof name!="string")throw new Error("describeTool() expects a tool name");let tool=tools.find(candidate=>candidate.name===name||toCodemodeIdentifier(candidate.name)===name);return tool?samples.get(tool.name):void 0}}"#,
                alt_olds: &[],
                new: r#"{name:"describeTool",spread:!0,execute:args=>{let[name]=args;if(typeof name!="string")throw new Error("describeTool() expects a tool name");let tool=tools.find(candidate=>candidate.name===name||toCodemodeIdentifier(candidate.name)===name);if(!tool){let _suf="__"+name,_m=tools.filter(c=>c.name.endsWith(_suf)||toCodemodeIdentifier(c.name).endsWith(_suf));_m.length===1&&(tool=_m[0])}return tool?samples.get(tool.name):void 0}}"#,
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "session_before_compact_first_wins",
        summary: "Preserve first non-null session_before_compact compaction result, set event.compactionClaimed=true, and prevent later extensions from silently overwriting it",
        hunks: &[
            PatchHunk {
                id: "bundle_session_before_compact_first_wins",
                rel_hint: None,
                old: r#"if(this.isSessionBeforeEvent(event)&&handlerResult&&(result=handlerResult,result.cancel))return result"#,
                alt_olds: &[],
                new: r#"if(this.isSessionBeforeEvent(event)&&handlerResult){if(handlerResult.cancel)return handlerResult;if(event.type==="session_before_compact"&&handlerResult.compaction){if(!result?.compaction){result=handlerResult;try{event.compactionClaimed=!0}catch{}}}else result=handlerResult}"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "core_runner_session_before_compact_first_wins",
                rel_hint: Some("dist/core/extensions/runner.js"),
                old: "                    if (this.isSessionBeforeEvent(event) && handlerResult) {\n                        result = handlerResult;\n                        if (result.cancel) {\n                            return result;\n                        }\n                    }",
                alt_olds: &[],
                new: "                    if (this.isSessionBeforeEvent(event) && handlerResult) {\n                        if (handlerResult.cancel) {\n                            return handlerResult;\n                        }\n                        if (event.type === \"session_before_compact\" && handlerResult.compaction) {\n                            if (!result?.compaction) {\n                                result = handlerResult;\n                                try { event.compactionClaimed = true; } catch { }\n                            }\n                        }\n                        else {\n                            result = handlerResult;\n                        }\n                    }",
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "http_dns_stale_cache",
        summary: "Inject a 45s fresh-TTL + 10m stale-IP DNS lookup cache onto EnvHttpProxyAgent's plain connect options (preserves keepAlive/timeouts and HTTP-CONNECT proxy tunnels; leaves createUndiciClient untouched)",
        hunks: &[
            PatchHunk {
                id: "bundle_http_dns_stale_cache",
                rel_hint: None,
                old: r#"withUndiciErrorListener(new undici.EnvHttpProxyAgent("#,
                alt_olds: &[],
                new: r#"withUndiciErrorListener(((_o)=>{if(_o&&typeof _o.connect==="object"&&_o.connect&&!_o.connect.lookup){let _c=globalThis.__piDnsStaleCache??(globalThis.__piDnsStaleCache=new Map),_dp=globalThis.__piDnsModP??(globalThis.__piDnsModP=import("node:dns"));_o={..._o,connect:{..._o.connect,lookup(host,opts,cb){typeof opts=="function"&&(cb=opts,opts={});let fam=typeof opts=="number"?opts:opts?.family??0,all=Boolean(typeof opts=="object"&&opts?.all),key=`${host}|${fam}|${all?1:0}`,now=Date.now(),hit=_c.get(key);if(hit&&now-hit.t<45e3){queueMicrotask(()=>all?cb(null,hit.v.map(x=>({...x}))):cb(null,hit.v[0],hit.v[1]));return}_dp.then(m=>{m.lookup(host,opts,(err,a,b)=>{if(!err){let v=all?Array.isArray(a)?a.map(x=>({address:x.address,family:x.family})):[]:[a,b];if(v.length>0){if(_c.size>=256)_c.delete(_c.keys().next().value);_c.set(key,{v,t:Date.now()})}all?cb(null,a):cb(null,a,b);return}if(hit&&Date.now()-hit.t<6e5&&(err?.code==="ENOTFOUND"||err?.code==="EAI_AGAIN"||err?.code==="ETIMEOUT"||err?.code==="ESERVFAIL")){all?cb(null,hit.v.map(x=>({...x}))):cb(null,hit.v[0],hit.v[1]);return}cb(err)})},e=>cb(e))}}}}return new undici.EnvHttpProxyAgent(_o)})("#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "core_http_dns_stale_cache",
                rel_hint: Some("dist/core/http-dispatcher.js"),
                old: "withUndiciErrorListener(new undici.EnvHttpProxyAgent(",
                alt_olds: &[],
                new: "withUndiciErrorListener(((_o) => {\n        if (_o && typeof _o.connect === \"object\" && _o.connect && !_o.connect.lookup) {\n            const _c = globalThis.__piDnsStaleCache ?? (globalThis.__piDnsStaleCache = new Map());\n            const _dp = globalThis.__piDnsModP ?? (globalThis.__piDnsModP = import(\"node:dns\"));\n            _o = {\n                ..._o,\n                connect: {\n                    ..._o.connect,\n                    lookup(host, opts, cb) {\n                        if (typeof opts === \"function\") { cb = opts; opts = {}; }\n                        const fam = typeof opts === \"number\" ? opts : (opts?.family ?? 0);\n                        const all = Boolean(typeof opts === \"object\" && opts?.all);\n                        const key = `${host}|${fam}|${all ? 1 : 0}`;\n                        const now = Date.now();\n                        const hit = _c.get(key);\n                        if (hit && now - hit.t < 45000) {\n                            queueMicrotask(() => (all ? cb(null, hit.v.map((x) => ({ ...x }))) : cb(null, hit.v[0], hit.v[1])));\n                            return;\n                        }\n                        _dp.then((m) => {\n                            m.lookup(host, opts, (err, a, b) => {\n                                if (!err) {\n                                    const v = all ? (Array.isArray(a) ? a.map((x) => ({ address: x.address, family: x.family })) : []) : [a, b];\n                                    if (v.length > 0) {\n                                        if (_c.size >= 256) _c.delete(_c.keys().next().value);\n                                        _c.set(key, { v, t: Date.now() });\n                                    }\n                                    if (all) cb(null, a); else cb(null, a, b);\n                                    return;\n                                }\n                                if (hit && Date.now() - hit.t < 600000 && (err?.code === \"ENOTFOUND\" || err?.code === \"EAI_AGAIN\" || err?.code === \"ETIMEOUT\" || err?.code === \"ESERVFAIL\")) {\n                                    if (all) cb(null, hit.v.map((x) => ({ ...x }))); else cb(null, hit.v[0], hit.v[1]);\n                                    return;\n                                }\n                                cb(err);\n                            });\n                        }, (e) => cb(e));\n                    },\n                },\n            };\n        }\n        return new undici.EnvHttpProxyAgent(_o);\n    })(",
                already_present_markers: &[],
            },
        ],
    },
    PatchSpec {
        id: "read_eof_clamp",
        summary: "Return a structured EOF notice ({ eofClamped: true, totalFileLines }) instead of throwing when read offset exceeds file length",
        hunks: &[
            PatchHunk {
                id: "bundle_read_eof_clamp",
                rel_hint: None,
                old: r#"if(startLine>=totalFileLines)throw new Error(`Offset ${offset} is beyond end of file (${totalFileLines} lines total)`);let userLimitedLines=limit===void 0?void 0:Math.min(startLine+limit,totalFileLines)-startLine,outputText;if(truncation.firstLineExceedsLimit)"#,
                alt_olds: &[],
                new: r#"let userLimitedLines=limit===void 0?void 0:Math.min(startLine+limit,totalFileLines)-startLine,outputText;if(startLine>=totalFileLines){outputText=`[Offset ${offset} is beyond end of file (${totalFileLines} lines total). Last line is ${totalFileLines}.]`,details={eofClamped:!0,totalFileLines}}else if(truncation.firstLineExceedsLimit)"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "core_read_eof_clamp",
                rel_hint: Some("dist/core/tools/read.js"),
                old: "                            // Check if offset is out of bounds.\n                            if (startLine >= totalFileLines) {\n                                throw new Error(`Offset ${offset} is beyond end of file (${totalFileLines} lines total)`);\n                            }\n                            // A user-specified limit is honored before truncation.\n                            const userLimitedLines = limit === undefined ? undefined : Math.min(startLine + limit, totalFileLines) - startLine;\n                            let outputText;\n                            if (truncation.firstLineExceedsLimit) {",
                alt_olds: &[],
                new: "                            // A user-specified limit is honored before truncation.\n                            const userLimitedLines = limit === undefined ? undefined : Math.min(startLine + limit, totalFileLines) - startLine;\n                            let outputText;\n                            // Gracefully return EOF notice instead of throwing on out-of-bounds offset.\n                            if (startLine >= totalFileLines) {\n                                outputText = `[Offset ${offset} is beyond end of file (${totalFileLines} lines total). Last line is ${totalFileLines}.]`;\n                                details = { eofClamped: true, totalFileLines };\n                            }\n                            else if (truncation.firstLineExceedsLimit) {",
                already_present_markers: &["eofClamped: true", "Last line is ${totalFileLines}"],
            },
        ],
    },
    PatchSpec {
        id: "temp_log_cap_and_gc",
        summary: "Cap OutputAccumulator temp logs at PI_TEMP_LOG_MAX_BYTES (default 32 MB) and lazily GC stale (>12h) pi-bash-*.log temp files",
        hunks: &[
            PatchHunk {
                id: "bundle_temp_log_cap_fields",
                rel_hint: None,
                old: r#"finished=!1;tempFile;constructor(options={}){this.maxLines=options.maxLines??2e3,this.maxBytes=options.maxBytes??51200,this.maxRollingBytes=Math.max(this.maxBytes*2,1),this.tempFilePrefix=options.tempFilePrefix??"pi-output"}append(data){if(this.finished)throw new Error("Cannot append to a finished output accumulator");this.totalRawBytes+=data.length,this.appendDecodedText(this.decoder.decode(data,{stream:!0})),this.tempFile||this.shouldUseTempFile()?(this.ensureTempFile(),this.tempFile.write(data)):data.length>0&&this.rawChunks.push(data)}"#,
                alt_olds: &[],
                new: r#"finished=!1;tempFile;tempFileBytesWritten=0;tempFileCapped=!1;maxTempFileBytes=Math.max(65536,Number(process.env.PI_TEMP_LOG_MAX_BYTES)||33554432);constructor(options={}){this.maxLines=options.maxLines??2e3,this.maxBytes=options.maxBytes??51200,this.maxRollingBytes=Math.max(this.maxBytes*2,1),this.tempFilePrefix=options.tempFilePrefix??"pi-output"}append(data){if(this.finished)throw new Error("Cannot append to a finished output accumulator");this.totalRawBytes+=data.length,this.appendDecodedText(this.decoder.decode(data,{stream:!0})),this.tempFile||this.shouldUseTempFile()?(this.ensureTempFile(),this.writeTempChunk(data)):data.length>0&&this.rawChunks.push(data)}"#,
                already_present_markers: &[],
            },
            PatchHunk {
                id: "bundle_temp_log_cap_write_gc",
                rel_hint: None,
                old: r#"ensureTempFile(){if(this.tempFile)return this.tempFile;let tempFile=createOutputFileStream(this.tempFilePrefix,".log");this.tempFile=tempFile;for(let chunk of this.rawChunks)this.tempFile.write(chunk);return this.rawChunks=[],tempFile}"#,
                alt_olds: &[],
                new: r#"writeTempChunk(chunk){if(!this.tempFile||this.tempFileCapped||!chunk||chunk.length===0)return;let rem=this.maxTempFileBytes-this.tempFileBytesWritten;if(rem<=0){this.tempFileCapped=!0;return}chunk.length<=rem?(this.tempFile.write(chunk),this.tempFileBytesWritten+=chunk.length):(this.tempFile.write(chunk.subarray(0,rem)),this.tempFile.write(Buffer.from("\n[pi-patch19: temp log capped at "+this.maxTempFileBytes+" bytes to protect system drive]\n")),this.tempFileBytesWritten=this.maxTempFileBytes,this.tempFileCapped=!0)}ensureTempFile(){if(this.tempFile)return this.tempFile;if(!globalThis.__piPatch19GcRan){globalThis.__piPatch19GcRan=!0;Promise.all([import("node:fs/promises"),import("node:os"),import("node:path")]).then(async([fsp,osMod,pathMod])=>{try{let tmp=osMod.tmpdir(),cutoff=Date.now()-432e5,names=await fsp.readdir(tmp);for(let nm of names){if(!nm.startsWith("pi-bash-")||!nm.endsWith(".log"))continue;let fp=pathMod.join(tmp,nm);try{let st=await fsp.stat(fp);st.isFile()&&st.mtimeMs<cutoff&&await fsp.unlink(fp)}catch{}}}catch{}}).catch(()=>{})}let tempFile=createOutputFileStream(this.tempFilePrefix,".log");this.tempFile=tempFile;for(let chunk of this.rawChunks)this.writeTempChunk(chunk);return this.rawChunks=[],tempFile}"#,
                already_present_markers: &[
                    "writeTempChunk(",
                    "__piPatch19GcRan",
                    "pi-patch19: temp log capped",
                ],
            },
            PatchHunk {
                id: "core_temp_log_cap_fields",
                rel_hint: Some("dist/core/tools/output-accumulator.js"),
                old: "    finished = false;\n    tempFile;\n    constructor(options = {}) {\n        this.maxLines = options.maxLines ?? DEFAULT_MAX_LINES;\n        this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;\n        this.maxRollingBytes = Math.max(this.maxBytes * 2, 1);\n        this.tempFilePrefix = options.tempFilePrefix ?? \"pi-output\";\n    }\n    append(data) {\n        if (this.finished) {\n            throw new Error(\"Cannot append to a finished output accumulator\");\n        }\n        this.totalRawBytes += data.length;\n        this.appendDecodedText(this.decoder.decode(data, { stream: true }));\n        if (this.tempFile || this.shouldUseTempFile()) {\n            this.ensureTempFile();\n            this.tempFile.write(data);\n        }",
                alt_olds: &[],
                new: "    finished = false;\n    tempFile;\n    tempFileBytesWritten = 0;\n    tempFileCapped = false;\n    maxTempFileBytes = Math.max(65536, Number(process.env.PI_TEMP_LOG_MAX_BYTES) || 32 * 1024 * 1024);\n    constructor(options = {}) {\n        this.maxLines = options.maxLines ?? DEFAULT_MAX_LINES;\n        this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;\n        this.maxRollingBytes = Math.max(this.maxBytes * 2, 1);\n        this.tempFilePrefix = options.tempFilePrefix ?? \"pi-output\";\n    }\n    append(data) {\n        if (this.finished) {\n            throw new Error(\"Cannot append to a finished output accumulator\");\n        }\n        this.totalRawBytes += data.length;\n        this.appendDecodedText(this.decoder.decode(data, { stream: true }));\n        if (this.tempFile || this.shouldUseTempFile()) {\n            this.ensureTempFile();\n            this.writeTempChunk(data);\n        }",
                already_present_markers: &["PI_TEMP_LOG_MAX_BYTES", "this.writeTempChunk(data)"],
            },
            PatchHunk {
                id: "core_temp_log_cap_write_gc",
                rel_hint: Some("dist/core/tools/output-accumulator.js"),
                old: "    ensureTempFile() {\n        if (this.tempFile) {\n            return this.tempFile;\n        }\n        const tempFile = createOutputFileStream(this.tempFilePrefix, \".log\");\n        this.tempFile = tempFile;\n        for (const chunk of this.rawChunks) {\n            this.tempFile.write(chunk);\n        }\n        this.rawChunks = [];\n        return tempFile;\n    }",
                alt_olds: &[],
                new: "    writeTempChunk(chunk) {\n        if (!this.tempFile || this.tempFileCapped || !chunk || chunk.length === 0) return;\n        const rem = this.maxTempFileBytes - this.tempFileBytesWritten;\n        if (rem <= 0) { this.tempFileCapped = true; return; }\n        if (chunk.length <= rem) {\n            this.tempFile.write(chunk);\n            this.tempFileBytesWritten += chunk.length;\n        } else {\n            this.tempFile.write(chunk.subarray(0, rem));\n            this.tempFile.write(Buffer.from(\"\\n[pi-patch19: temp log capped at \" + this.maxTempFileBytes + \" bytes to protect system drive]\\n\"));\n            this.tempFileBytesWritten = this.maxTempFileBytes;\n            this.tempFileCapped = true;\n        }\n    }\n    ensureTempFile() {\n        if (this.tempFile) {\n            return this.tempFile;\n        }\n        if (!globalThis.__piPatch19GcRan) {\n            globalThis.__piPatch19GcRan = true;\n            Promise.all([import(\"node:fs/promises\"), import(\"node:os\"), import(\"node:path\")]).then(async ([fsp, osMod, pathMod]) => {\n                try {\n                    const tmp = osMod.tmpdir();\n                    const cutoff = Date.now() - 12 * 3600 * 1000;\n                    const names = await fsp.readdir(tmp);\n                    for (const nm of names) {\n                        if (!nm.startsWith(\"pi-bash-\") || !nm.endsWith(\".log\")) continue;\n                        const fp = pathMod.join(tmp, nm);\n                        try { const st = await fsp.stat(fp); if (st.isFile() && st.mtimeMs < cutoff) await fsp.unlink(fp); } catch {}\n                    }\n                } catch {}\n            }).catch(() => {});\n        }\n\n        const tempFile = createOutputFileStream(this.tempFilePrefix, \".log\");\n        this.tempFile = tempFile;\n        for (const chunk of this.rawChunks) {\n            this.writeTempChunk(chunk);\n        }\n        this.rawChunks = [];\n        return tempFile;\n    }",
                already_present_markers: &[
                    "writeTempChunk(chunk)",
                    "__piPatch19GcRan",
                    "pi-patch19: temp log capped",
                ],
            },
        ],
    },
    PatchSpec {
        id: "windows_bash_cmd_spill",
        summary: "Strip NUL bytes and spill >20KB Windows bash/powershell commands to %TEMP%/pi-cmd-spill/pi-cmd-*.{sh,ps1} with guaranteed finally cleanup",
        hunks: &[
            PatchHunk {
                id: "bundle_windows_bash_cmd_spill",
                rel_hint: None,
                old: r#"let commandFromStdin=shellConfig.commandTransport==="stdin",child=spawn2(shellConfig.shell,commandFromStdin?shellConfig.args:[...shellConfig.args,command],"#,
                alt_olds: &[],
                new: r#"let commandFromStdin=shellConfig.commandTransport==="stdin",__piCleanCmd=typeof command==="string"&&command.indexOf("\0")!==-1?command.replace(/\0/g,""):command,__piSpillFile,__piExecCmd=__piCleanCmd;if(process.platform==="win32"&&!commandFromStdin&&Buffer.byteLength(__piCleanCmd,"utf8")>20000){try{let __fs=require("node:fs"),__os=require("node:os"),__pt=require("node:path"),__dir=__pt.join(__os.tmpdir(),"pi-cmd-spill"),__st=`${Date.now()}-${Math.random().toString(36).slice(2,8)}`;__fs.mkdirSync(__dir,{recursive:!0});if(shellName==="powershell"){__piSpillFile=__pt.join(__dir,`pi-cmd-${__st}.ps1`);__fs.writeFileSync(__piSpillFile,"\uFEFF"+__piCleanCmd,"utf8");__piExecCmd=`& '${__piSpillFile.replace(/'/g,"''")}'`;}else{__piSpillFile=__pt.join(__dir,`pi-cmd-${__st}.sh`);__fs.writeFileSync(__piSpillFile,__piCleanCmd.replace(/\r\n/g,"\n"),"utf8");__piExecCmd=`. "${__piSpillFile.replace(/\\/g,"/")}"`;}}catch{__piSpillFile=void 0;__piExecCmd=__piCleanCmd}}let child=spawn2(shellConfig.shell,commandFromStdin?shellConfig.args:[...shellConfig.args,__piExecCmd],"#,
                already_present_markers: &["cmd-spill", "pi-cmd-", "Buffer.byteLength("],
            },
            PatchHunk {
                id: "bundle_windows_bash_cmd_spill_cleanup",
                rel_hint: None,
                old: r#"}finally{child.pid&&untrackDetachedChildPid(child.pid),timeoutHandle&&clearTimeout(timeoutHandle),signal&&signal.removeEventListener("abort",onAbort)}}"#,
                alt_olds: &[],
                new: r#"}finally{if(__piSpillFile){try{require("node:fs").unlinkSync(__piSpillFile)}catch{}}child.pid&&untrackDetachedChildPid(child.pid),timeoutHandle&&clearTimeout(timeoutHandle),signal&&signal.removeEventListener("abort",onAbort)}}"#,
                already_present_markers: &["unlinkSync(", "untrackDetachedChildPid(child.pid)"],
            },
            PatchHunk {
                id: "core_bash_cmd_spill_imports",
                rel_hint: Some("dist/core/tools/bash.js"),
                old: "import { constants } from \"node:fs\";\nimport { access as fsAccess } from \"node:fs/promises\";\nimport { constants as osConstants } from \"node:os\";",
                alt_olds: &[],
                new: "import { constants, mkdirSync as __piMkdirSync, unlinkSync as __piUnlinkSync, writeFileSync as __piWriteFileSync } from \"node:fs\";\nimport { access as fsAccess } from \"node:fs/promises\";\nimport { constants as osConstants, tmpdir as __piTmpdir } from \"node:os\";\nimport { join as __piJoin } from \"node:path\";",
                already_present_markers: &["mkdirSync", "unlinkSync", "writeFileSync", "tmpdir", "cmd-spill"],
            },
            PatchHunk {
                id: "core_bash_cmd_spill",
                rel_hint: Some("dist/core/tools/bash.js"),
                old: "            const commandFromStdin = shellConfig.commandTransport === \"stdin\";\n            const child = spawn(shellConfig.shell, commandFromStdin ? shellConfig.args : [...shellConfig.args, command], {",
                alt_olds: &[],
                new: "            const commandFromStdin = shellConfig.commandTransport === \"stdin\";\n            const __piCleanCmd = typeof command === \"string\" && command.indexOf(\"\\0\") !== -1 ? command.replace(/\\0/g, \"\") : command;\n            let __piSpillFile;\n            let __piExecCmd = __piCleanCmd;\n            if (process.platform === \"win32\" && !commandFromStdin && Buffer.byteLength(__piCleanCmd, \"utf8\") > 20000) {\n                try {\n                    const __dir = __piJoin(__piTmpdir(), \"pi-cmd-spill\");\n                    __piMkdirSync(__dir, { recursive: true });\n                    const __stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;\n                    if (shellName === \"powershell\") {\n                        __piSpillFile = __piJoin(__dir, `pi-cmd-${__stamp}.ps1`);\n                        __piWriteFileSync(__piSpillFile, \"\\uFEFF\" + __piCleanCmd, \"utf8\");\n                        __piExecCmd = `& '${__piSpillFile.replace(/'/g, \"''\")}'`;\n                    } else {\n                        __piSpillFile = __piJoin(__dir, `pi-cmd-${__stamp}.sh`);\n                        __piWriteFileSync(__piSpillFile, __piCleanCmd.replace(/\\r\\n/g, \"\\n\"), \"utf8\");\n                        __piExecCmd = `. \"${__piSpillFile.replace(/\\\\/g, \"/\")}\"`;\n                    }\n                } catch {\n                    __piSpillFile = undefined;\n                    __piExecCmd = __piCleanCmd;\n                }\n            }\n            const child = spawn(shellConfig.shell, commandFromStdin ? shellConfig.args : [...shellConfig.args, __piExecCmd], {",
                already_present_markers: &["cmd-spill", "pi-cmd-", "Buffer.byteLength("],
            },
            PatchHunk {
                id: "core_bash_cmd_spill_cleanup",
                rel_hint: Some("dist/core/tools/bash.js"),
                old: "            finally {\n                if (child.pid)\n                    untrackDetachedChildPid(child.pid);",
                alt_olds: &[],
                new: "            finally {\n                if (__piSpillFile) {\n                    try { __piUnlinkSync(__piSpillFile); } catch { }\n                }\n                if (child.pid)\n                    untrackDetachedChildPid(child.pid);",
                already_present_markers: &["SpillFile", "UnlinkSync", "untrackDetachedChildPid(child.pid)"],
            },
        ],
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchReportItem {
    pub id: String,
    pub summary: String,
    pub status: String,
    pub applied_hunks: usize,
    pub total_hunks: usize,
    pub files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_hunks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiPatchReport {
    pub detected: bool,
    pub pi_dir: String,
    pub pi_version: String,
    pub backup_dir: String,
    pub backup_present: bool,
    pub all_applied: bool,
    pub applied_count: usize,
    pub total_count: usize,
    pub patches: Vec<PatchReportItem>,
}

fn read_pi_version(pi_dir: &Path) -> String {
    let pkg = pi_dir.join("package.json");
    fs::read_to_string(&pkg)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.get("version").and_then(Value::as_str).map(String::from))
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn find_pi_package_dir(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        let cand = PathBuf::from(p);
        if cand.join("package.json").is_file() {
            return Some(cand);
        }
        return None;
    }
    if let Ok(env_p) = std::env::var("PI_PACKAGE_DIR") {
        let cand = PathBuf::from(env_p.trim());
        if cand.join("package.json").is_file() {
            return Some(cand);
        }
    }
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        cands.push(
            PathBuf::from(appdata)
                .join("npm")
                .join("node_modules")
                .join("@earendil-works")
                .join("pi-coding-agent"),
        );
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let h = PathBuf::from(home);
        cands.push(
            h.join(".npm-global")
                .join("lib")
                .join("node_modules")
                .join("@earendil-works")
                .join("pi-coding-agent"),
        );
        cands.push(
            h.join("AppData")
                .join("Roaming")
                .join("npm")
                .join("node_modules")
                .join("@earendil-works")
                .join("pi-coding-agent"),
        );
    }
    cands.push(PathBuf::from(
        "/usr/local/lib/node_modules/@earendil-works/pi-coding-agent",
    ));
    cands.push(PathBuf::from(
        "/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent",
    ));

    // Also probe relative to `pi` / `pi.cmd` on PATH
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            if dir.join("pi").is_file()
                || dir.join("pi.cmd").is_file()
                || dir.join("pi.ps1").is_file()
            {
                cands.push(
                    dir.join("node_modules")
                        .join("@earendil-works")
                        .join("pi-coding-agent"),
                );
                if let Some(parent) = dir.parent() {
                    cands.push(
                        parent
                            .join("lib")
                            .join("node_modules")
                            .join("@earendil-works")
                            .join("pi-coding-agent"),
                    );
                }
            }
        }
    }

    cands.into_iter().find(|c| c.join("package.json").is_file())
}

fn collect_bundle_chunks(pi_dir: &Path) -> Vec<PathBuf> {
    let chunks_dir = pi_dir.join("dist").join("bundle").join("chunks");
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(&chunks_dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("js") {
            out.push(p);
        }
    }
    out.sort();
    out
}

fn normalize_lf(s: &str) -> String {
    s.replace("\r\n", "\n")
}

fn backup_root(pi_version: &str) -> PathBuf {
    let ap_home = std::env::var("AP_HOME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let h = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            h.join(".ap")
        });
    ap_home.join("pi-backups").join(pi_version)
}

fn ensure_backup(pi_dir: &Path, pi_version: &str, file_path: &Path) -> Result<(), String> {
    let rel = file_path.strip_prefix(pi_dir).unwrap_or(file_path);
    let dst = backup_root(pi_version).join(rel);
    if dst.exists() {
        return Ok(());
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::copy(file_path, &dst).map_err(|e| e.to_string())?;
    Ok(())
}

fn resolve_hunk_files(
    pi_dir: &Path,
    chunks: &[PathBuf],
    hunk: &PatchHunk,
) -> Vec<(PathBuf, bool, Option<&'static str>)> {
    // Returns all matching (file_path, has_new, matched_old_pattern) targets so duplicated bundler chunks are all patched.
    let match_old = |text: &str| -> Option<&'static str> {
        if text.contains(hunk.old) {
            return Some(hunk.old);
        }
        for alt in hunk.alt_olds {
            if text.contains(alt) {
                return Some(*alt);
            }
        }
        None
    };
    let is_applied = |text: &str| -> bool {
        if text.contains(hunk.new) {
            return true;
        }
        !hunk.already_present_markers.is_empty()
            && hunk
                .already_present_markers
                .iter()
                .all(|m| text.contains(m))
    };
    if let Some(rel) = hunk.rel_hint {
        let p = pi_dir.join(rel);
        if !p.is_file() {
            return Vec::new();
        }
        let Ok(raw) = fs::read_to_string(&p) else {
            return Vec::new();
        };
        let norm = normalize_lf(&raw);
        let has_new = is_applied(&norm);
        let matched_old = if has_new { None } else { match_old(&norm) };
        return vec![(p, has_new, matched_old)];
    }
    let mut matches = Vec::new();
    for ch in chunks {
        let Ok(raw) = fs::read_to_string(ch) else {
            continue;
        };
        let norm = normalize_lf(&raw);
        if is_applied(&norm) {
            matches.push((ch.clone(), true, None));
        } else if let Some(old_pat) = match_old(&norm) {
            matches.push((ch.clone(), false, Some(old_pat)));
        }
    }
    matches
}

pub fn inspect_pi_patches(pi_dir_opt: Option<&str>) -> PiPatchReport {
    let Some(pi_dir) = find_pi_package_dir(pi_dir_opt) else {
        return PiPatchReport {
            detected: false,
            pi_dir: String::new(),
            pi_version: String::new(),
            backup_dir: String::new(),
            backup_present: false,
            all_applied: false,
            applied_count: 0,
            total_count: PATCH_SPECS.len(),
            patches: Vec::new(),
        };
    };
    let pi_version = read_pi_version(&pi_dir);
    let b_root = backup_root(&pi_version);
    let backup_present = b_root.is_dir();
    let chunks = collect_bundle_chunks(&pi_dir);
    let mut patches = Vec::new();
    let mut applied_count = 0usize;

    for spec in PATCH_SPECS {
        let mut applied_hunks = 0usize;
        let mut patchable_hunks = 0usize;
        let mut optional_absent_hunks = 0usize;
        let mut drifted_hunks = 0usize;
        let mut files = Vec::new();
        let mut skipped_hunks = Vec::new();
        for h in spec.hunks {
            let targets = resolve_hunk_files(&pi_dir, &chunks, h);
            if targets.is_empty() {
                if let Some(rel) = h.rel_hint {
                    if !pi_dir.join(rel).is_file() {
                        optional_absent_hunks += 1;
                        continue;
                    }
                }
                drifted_hunks += 1;
                skipped_hunks.push(format!("{} (target not found)", h.id));
                continue;
            }
            let mut any_patchable = false;
            let mut any_mismatched = false;
            let mut all_new = true;
            for (fp, has_new, matched_old) in &targets {
                let rel = fp
                    .strip_prefix(&pi_dir)
                    .unwrap_or(fp)
                    .to_string_lossy()
                    .replace('\\', "/");
                if !files.contains(&rel) {
                    files.push(rel);
                }
                if !*has_new {
                    all_new = false;
                    if matched_old.is_some() {
                        any_patchable = true;
                    } else {
                        any_mismatched = true;
                    }
                }
            }
            if all_new {
                applied_hunks += 1;
            } else if any_mismatched {
                drifted_hunks += 1;
                skipped_hunks.push(format!("{} (pattern mismatch)", h.id));
            } else if any_patchable {
                patchable_hunks += 1;
            } else {
                drifted_hunks += 1;
                skipped_hunks.push(format!("{} (pattern mismatch)", h.id));
            }
        }
        let total = spec.hunks.len();
        let effective_total = total.saturating_sub(optional_absent_hunks);
        let status =
            if effective_total > 0 && applied_hunks == effective_total && drifted_hunks == 0 {
                applied_count += 1;
                "applied"
            } else if (drifted_hunks > 0 && (applied_hunks > 0 || patchable_hunks > 0))
                || (applied_hunks > 0 && patchable_hunks > 0)
            {
                "partial"
            } else if patchable_hunks > 0 {
                "unpatched"
            } else {
                "incompatible"
            };
        patches.push(PatchReportItem {
            id: spec.id.to_string(),
            summary: spec.summary.to_string(),
            status: status.to_string(),
            applied_hunks,
            total_hunks: total,
            files,
            skipped_hunks,
        });
    }

    PiPatchReport {
        detected: true,
        pi_dir: pi_dir.to_string_lossy().to_string(),
        pi_version,
        backup_dir: b_root.to_string_lossy().to_string(),
        backup_present,
        all_applied: applied_count == PATCH_SPECS.len(),
        applied_count,
        total_count: PATCH_SPECS.len(),
        patches,
    }
}

pub fn apply_pi_patches(pi_dir_opt: Option<&str>, dry_run: bool) -> Result<Value, String> {
    let Some(pi_dir) = find_pi_package_dir(pi_dir_opt) else {
        return Err(
            "Could not locate @earendil-works/pi-coding-agent installation (pass --pi-dir <path>)."
                .to_string(),
        );
    };
    let pi_version = read_pi_version(&pi_dir);
    let chunks = collect_bundle_chunks(&pi_dir);
    let mut newly_applied = Vec::new();
    let mut already_applied = Vec::new();
    let mut skipped = Vec::new();

    for spec in PATCH_SPECS {
        for h in spec.hunks {
            let targets = resolve_hunk_files(&pi_dir, &chunks, h);
            if targets.is_empty() {
                if let Some(rel) = h.rel_hint {
                    if !pi_dir.join(rel).is_file() {
                        continue;
                    }
                }
                skipped.push(format!("{}:{} (target not found)", spec.id, h.id));
                continue;
            }
            for (fp, has_new, matched_old) in targets {
                if has_new {
                    already_applied.push(format!("{}:{}", spec.id, h.id));
                    continue;
                }
                let Some(old_pat) = matched_old else {
                    skipped.push(format!("{}:{} (pattern mismatch)", spec.id, h.id));
                    continue;
                };
                if !dry_run {
                    ensure_backup(&pi_dir, &pi_version, &fp)?;
                    let raw = fs::read_to_string(&fp).map_err(|e| e.to_string())?;
                    let uses_crlf = raw.contains("\r\n");
                    let norm = normalize_lf(&raw);
                    let count = norm.matches(old_pat).count();
                    if count != 1 {
                        return Err(format!(
                            "Refusing ambiguous patch {}:{} in {} (expected 1 match, found {})",
                            spec.id,
                            h.id,
                            fp.display(),
                            count
                        ));
                    }
                    let updated_lf = norm.replacen(old_pat, h.new, 1);
                    let final_txt = if uses_crlf {
                        updated_lf.replace('\n', "\r\n")
                    } else {
                        updated_lf
                    };
                    fs::write(&fp, final_txt).map_err(|e| e.to_string())?;
                }
                newly_applied.push(format!("{}:{}", spec.id, h.id));
            }
        }
    }

    let report = inspect_pi_patches(Some(&pi_dir.to_string_lossy()));
    Ok(json!({
        "ok": true,
        "dry_run": dry_run,
        "pi_dir": report.pi_dir,
        "pi_version": report.pi_version,
        "backup_dir": backup_root(&pi_version).to_string_lossy(),
        "newly_applied": newly_applied,
        "already_applied": already_applied,
        "skipped": skipped,
        "report": report,
    }))
}

pub fn restore_pi_patches(pi_dir_opt: Option<&str>) -> Result<Value, String> {
    let Some(pi_dir) = find_pi_package_dir(pi_dir_opt) else {
        return Err(
            "Could not locate @earendil-works/pi-coding-agent installation (pass --pi-dir <path>)."
                .to_string(),
        );
    };
    let pi_version = read_pi_version(&pi_dir);
    let b_root = backup_root(&pi_version);
    if !b_root.is_dir() {
        return Err(format!(
            "No Pi backup directory found at {} (nothing to restore).",
            b_root.display()
        ));
    }
    let mut restored = Vec::new();
    let mut stack = vec![b_root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                let rel = p.strip_prefix(&b_root).unwrap_or(&p);
                let dst = pi_dir.join(rel);
                if let Some(parent) = dst.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                fs::copy(&p, &dst).map_err(|e| e.to_string())?;
                restored.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(json!({
        "ok": true,
        "pi_dir": pi_dir.to_string_lossy(),
        "pi_version": pi_version,
        "restored_count": restored.len(),
        "restored_files": restored,
    }))
}

pub fn run_cli(args: &[String]) -> i32 {
    let cli = match PiCli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    match cli.subcmd {
        PiSubCmd::Status { pi_dir, json } => {
            let rep = inspect_pi_patches(pi_dir.as_deref());
            if json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            } else if !rep.detected {
                println!(
                    "[ap pi] @earendil-works/pi-coding-agent not detected (pass --pi-dir <path>)."
                );
            } else {
                println!(
                    "[ap pi] Pi {} ({}) — {}/{} runtime patches applied (backups: {} [{}])",
                    rep.pi_version,
                    rep.pi_dir,
                    rep.applied_count,
                    rep.total_count,
                    rep.backup_dir,
                    if rep.backup_present {
                        "present"
                    } else {
                        "none"
                    }
                );
                for p in &rep.patches {
                    let skip_note = if p.skipped_hunks.is_empty() {
                        String::new()
                    } else {
                        format!(" [skipped: {}]", p.skipped_hunks.join(", "))
                    };
                    println!(
                        "  - {:<36} [{}] ({}/{} hunks) — {}{}",
                        p.id, p.status, p.applied_hunks, p.total_hunks, p.summary, skip_note
                    );
                }
            }
            if rep.detected {
                0
            } else {
                1
            }
        }
        PiSubCmd::Patch {
            pi_dir,
            dry_run,
            json,
        } => match apply_pi_patches(pi_dir.as_deref(), dry_run) {
            Ok(v) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                } else {
                    let newly = v["newly_applied"].as_array().map(|a| a.len()).unwrap_or(0);
                    let already = v["already_applied"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let mode = if dry_run { " (dry-run)" } else { "" };
                    println!(
                        "[ap pi]{mode} Pi {} — newly applied {newly} hunk(s), already applied {already} hunk(s) (backups: {})",
                        v["pi_version"].as_str().unwrap_or("?"),
                        v["backup_dir"].as_str().unwrap_or("?")
                    );
                }
                0
            }
            Err(e) => {
                if json {
                    println!("{}", json!({"ok": false, "error": e}));
                } else {
                    eprintln!("[ap pi] error: {e}");
                }
                1
            }
        },
        PiSubCmd::Restore { pi_dir, json } => match restore_pi_patches(pi_dir.as_deref()) {
            Ok(v) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                } else {
                    println!(
                        "[ap pi] restored {} file(s) for Pi {}.",
                        v["restored_count"].as_u64().unwrap_or(0),
                        v["pi_version"].as_str().unwrap_or("?")
                    );
                }
                0
            }
            Err(e) => {
                if json {
                    println!("{}", json!({"ok": false, "error": e}));
                } else {
                    eprintln!("[ap pi] error: {e}");
                }
                1
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_and_restores_mock_pi_installation_idempotently() {
        let base = std::env::temp_dir().join(format!("ap_pi_patch_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let pi_dir = base.join("pi-coding-agent");
        let chunks = pi_dir.join("dist").join("bundle").join("chunks");
        let core_ext = pi_dir.join("dist").join("core").join("extensions");
        let ap_home = base.join("ap_home");
        fs::create_dir_all(&chunks).unwrap();
        fs::create_dir_all(&core_ext).unwrap();
        fs::write(
            pi_dir.join("package.json"),
            r#"{"name":"@earendil-works/pi-coding-agent","version":"1.5.2-test"}"#,
        )
        .unwrap();

        // Populate minimal mock bundle + unbundled core files matching all 22 patch specs
        let prelude_dir = pi_dir
            .join("node_modules")
            .join("@earendil-works")
            .join("pi-codemode")
            .join("dist")
            .join("runtime");
        fs::create_dir_all(&prelude_dir).unwrap();
        let core_tools = pi_dir.join("dist").join("core").join("tools");
        fs::create_dir_all(&core_tools).unwrap();
        fs::write(
            chunks.join("chunk-main.js"),
            format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                PATCH_SPECS[0].hunks[0].old,
                PATCH_SPECS[0].hunks[1].old,
                PATCH_SPECS[3].hunks[0].old,
                PATCH_SPECS[3].hunks[1].old,
                PATCH_SPECS[4].hunks[0].old,
                PATCH_SPECS[6].hunks[0].old,
                PATCH_SPECS[6].hunks[1].old,
                PATCH_SPECS[7].hunks[0].old,
                PATCH_SPECS[7].hunks[1].old,
                PATCH_SPECS[7].hunks[2].old,
                PATCH_SPECS[8].hunks[0].old,
                PATCH_SPECS[8].hunks[1].old,
                PATCH_SPECS[12].hunks[0].old,
                PATCH_SPECS[13].hunks[0].old,
                PATCH_SPECS[17].hunks[0].old,
                PATCH_SPECS[18].hunks[0].old,
                PATCH_SPECS[19].hunks[0].old,
                PATCH_SPECS[20].hunks[0].old,
                PATCH_SPECS[20].hunks[1].old,
                PATCH_SPECS[21].hunks[0].old,
                PATCH_SPECS[21].hunks[1].old,
            ),
        )
        .unwrap();
        fs::write(chunks.join("chunk-env.js"), PATCH_SPECS[1].hunks[0].old).unwrap();
        fs::write(
            chunks.join("chunk-cm.js"),
            format!(
                "{}\n{}\n{}\n{}\n",
                PATCH_SPECS[2].hunks[0].old,
                PATCH_SPECS[2].hunks[1].old,
                PATCH_SPECS[2].hunks[2].old,
                PATCH_SPECS[16].hunks[3].old,
            ),
        )
        .unwrap();
        fs::write(chunks.join("chunk-retry.js"), PATCH_SPECS[3].hunks[2].old).unwrap();
        fs::write(chunks.join("chunk-tools.js"), PATCH_SPECS[9].hunks[0].old).unwrap();
        fs::write(
            chunks.join("chunk-tools-dup.js"),
            PATCH_SPECS[9].hunks[0].old,
        )
        .unwrap();
        fs::write(
            chunks.join("codemode-worker.js"),
            format!(
                "{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n",
                CODEMODE_BUILTINS_OLD.replace('\n', "\r\n"),
                CODEMODE_WRAPPER_OLD,
                PATCH_SPECS[10].hunks[0].old.replace('\n', "\r\n"),
                PATCH_SPECS[11].hunks[0].old.replace('\n', "\r\n"),
                PATCH_SPECS[11].hunks[2].old.replace('\n', "\r\n"),
                PATCH_SPECS[14].hunks[0].old.replace('\n', "\r\n"),
                PATCH_SPECS[15].hunks[0].old.replace('\n', "\r\n"),
                PATCH_SPECS[16].hunks[0].old.replace('\n', "\r\n"),
            ),
        )
        .unwrap();
        fs::write(
            prelude_dir.join("prelude-source.js"),
            format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                CODEMODE_BUILTINS_OLD,
                PATCH_SPECS[10].hunks[1].old,
                PATCH_SPECS[11].hunks[1].old,
                PATCH_SPECS[11].hunks[3].old,
                PATCH_SPECS[14].hunks[1].old,
                PATCH_SPECS[15].hunks[1].old,
                PATCH_SPECS[16].hunks[1].old,
            ),
        )
        .unwrap();
        let cm_ext_dir = pi_dir.join("dist").join("extensions").join("codemode");
        fs::create_dir_all(&cm_ext_dir).unwrap();
        fs::write(
            cm_ext_dir.join("execute.js"),
            format!("{}\n", PATCH_SPECS[16].hunks[2].old),
        )
        .unwrap();
        fs::write(
            core_ext.join("runner.js"),
            format!(
                "{}\n{}\n{}\n",
                PATCH_SPECS[0].hunks[2].old,
                PATCH_SPECS[12].hunks[1].old,
                PATCH_SPECS[17].hunks[1].old,
            ),
        )
        .unwrap();
        fs::write(
            pi_dir.join("dist").join("core").join("agent-session.js"),
            format!(
                "{}\n{}\n{}\n{}\n",
                PATCH_SPECS[0].hunks[3].old,
                PATCH_SPECS[7].hunks[3].old,
                PATCH_SPECS[7].hunks[4].old,
                PATCH_SPECS[7].hunks[5].old,
            ),
        )
        .unwrap();
        fs::write(
            pi_dir.join("dist").join("core").join("http-dispatcher.js"),
            PATCH_SPECS[18].hunks[1].old,
        )
        .unwrap();
        fs::write(core_tools.join("read.js"), PATCH_SPECS[19].hunks[1].old).unwrap();
        fs::write(
            core_tools.join("output-accumulator.js"),
            format!(
                "{}\n{}\n",
                PATCH_SPECS[20].hunks[2].old, PATCH_SPECS[20].hunks[3].old
            ),
        )
        .unwrap();
        fs::write(
            core_tools.join("bash.js"),
            format!(
                "{}\n{}\n{}\n",
                PATCH_SPECS[21].hunks[2].old,
                PATCH_SPECS[21].hunks[3].old,
                PATCH_SPECS[21].hunks[4].old,
            ),
        )
        .unwrap();
        fs::write(core_ext.join("types.d.ts"), PATCH_SPECS[0].hunks[4].old).unwrap();
        let dist_utils = pi_dir.join("dist").join("utils");
        fs::create_dir_all(&dist_utils).unwrap();
        fs::write(dist_utils.join("shell.js"), PATCH_SPECS[13].hunks[1].old).unwrap();

        let _ap_home_guard = crate::stats::ApHomeTestGuard::set(&ap_home);
        let pi_str = pi_dir.to_string_lossy().to_string();

        let before = inspect_pi_patches(Some(&pi_str));
        assert!(before.detected);
        assert_eq!(before.applied_count, 0);
        assert!(!before.backup_present);

        let applied = apply_pi_patches(Some(&pi_str), false).unwrap();
        assert_eq!(applied["report"]["all_applied"], true);
        assert_eq!(applied["report"]["applied_count"], 22);
        assert_eq!(applied["report"]["backup_present"], true);
        assert_eq!(applied["skipped"].as_array().unwrap().len(), 0);
        assert!(fs::read_to_string(chunks.join("chunk-tools.js"))
            .unwrap()
            .contains(PATCH_SPECS[9].hunks[0].new));
        assert!(fs::read_to_string(chunks.join("chunk-tools-dup.js"))
            .unwrap()
            .contains(PATCH_SPECS[9].hunks[0].new));

        // Second run must be 100% idempotent (0 newly applied)
        let second = apply_pi_patches(Some(&pi_str), false).unwrap();
        assert_eq!(second["newly_applied"].as_array().unwrap().len(), 0);

        // Restore must bring everything back to 0 applied
        let restored = restore_pi_patches(Some(&pi_str)).unwrap();
        assert!(restored["restored_count"].as_u64().unwrap() >= 7);
        let after_restore = inspect_pi_patches(Some(&pi_str));
        assert_eq!(after_restore.applied_count, 0);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn prelude_patch_hunks_are_template_literal_safe() {
        assert!(!CODEMODE_BUILTINS_NEW.contains(r#""\n""#));
        assert!(!CODEMODE_BUILTINS_NEW.contains(r#""\r""#));
        let spec = PATCH_SPECS
            .iter()
            .find(|s| s.id == "codemode_result_output_shim")
            .unwrap();
        assert_eq!(spec.hunks.len(), 4);
        for h in spec.hunks {
            assert!(!h.new.contains(r#""\n""#), "unsafe \\n in {}", h.id);
            assert!(!h.new.contains(r#""\r""#), "unsafe \\r in {}", h.id);
            assert!(
                !h.new.contains("${"),
                "unsafe template interpolation in {}",
                h.id
            );
            assert!(h.new.contains("String.prototype"));
            assert!(h.new.contains("Object.isExtensible(String.prototype)"));
            if h.id.ends_with("_result_output_shim") {
                assert!(h.new.contains("String.fromCharCode(10)"));
                assert!(h.new.contains("Object.isExtensible(value)"));
                assert!(h.new.contains("_cloneExtensible"));
                assert!(h.new.contains("writable: true"));
                assert_eq!(h.alt_olds.len(), 5);
                assert!(h
                    .alt_olds
                    .iter()
                    .any(|a| a.contains("String.fromCharCode(10)")
                        && a.contains("typeof value.output !== \"string\"")));
                assert!(h
                    .alt_olds
                    .iter()
                    .any(|a| a.contains("typeof value.output !== \"string\"")
                        && a.contains(r#""\n""#)));
                assert!(h
                    .alt_olds
                    .iter()
                    .any(|a| a.contains("!(\"output\" in value)") && a.contains(r#""\n""#)));
                assert!(h.alt_olds.iter().any(|a| a
                    .contains("Object.defineProperty(String.prototype, \"output\"")
                    && !a.contains("Object.isExtensible(String.prototype)")));
            }
        }
        let strip_spec = PATCH_SPECS
            .iter()
            .find(|s| s.id == "codemode_strip_null_tool_args")
            .unwrap();
        assert_eq!(strip_spec.hunks.len(), 2);
        for h in strip_spec.hunks {
            assert!(!h.new.contains(r#""\n""#), "unsafe \\n in {}", h.id);
            assert!(
                !h.new.contains("${"),
                "unsafe template interpolation in {}",
                h.id
            );
        }
        let log_spec = PATCH_SPECS
            .iter()
            .find(|s| s.id == "codemode_global_log_helper")
            .unwrap();
        assert!(log_spec.hunks.len() == 2);
        for h in log_spec.hunks {
            assert!(!h.new.contains(r#""\n""#), "unsafe \\n in {}", h.id);
            assert!(
                !h.new.contains("${"),
                "unsafe template interpolation in {}",
                h.id
            );
        }
        let alias_spec = PATCH_SPECS
            .iter()
            .find(|s| s.id == "codemode_mcp_short_aliases")
            .unwrap();
        assert_eq!(alias_spec.hunks.len(), 4);
        for h in alias_spec.hunks {
            assert!(!h.new.contains(r#""\n""#), "unsafe \\n in {}", h.id);
            assert!(
                !h.new.contains("${"),
                "unsafe template interpolation in {}",
                h.id
            );
        }

        // Verify runtime behavior of Patch #17 aliases & collision guard if Node is on PATH
        if let Ok(node_check) = std::process::Command::new("node").arg("--version").output() {
            if node_check.status.success() {
                let alias_snippet = alias_spec.hunks[1].new;
                let exec_snippet = alias_spec.hunks[2].new;
                let js = format!(
                    r#"
const assert = require('assert');
function setupTools(allTools) {{
  const tools = {{}};
  for (const {{ jsName: name }} of allTools) {{
    const fn = () => name;
{alias_snippet}
  return tools;
}}
const uniq = setupTools([
  {{ jsName: 'mcp__alpha__search_docs' }},
  {{ jsName: 'mcp__alpha__dup_tool' }},
  {{ jsName: 'mcp__beta__dup_tool' }},
  {{ jsName: 'bash' }},
]);
assert.strictEqual(typeof uniq.search_docs, 'function');
assert.strictEqual(uniq.search_docs(), 'mcp__alpha__search_docs');
assert.strictEqual(uniq.dup_tool, undefined, 'colliding MCP suffix must not be aliased');
assert.strictEqual(uniq.bash(), 'bash');

function toCodemodeIdentifier(n) {{ return n.replace(/[^A-Za-z0-9_]/g, '_'); }}
function lookup(tools, name) {{
{exec_snippet}
  return tool ? tool.name : null;
}}
const catalog = [{{ name: 'mcp__alpha__search_docs' }}, {{ name: 'mcp__alpha__dup' }}, {{ name: 'mcp__beta__dup' }}];
assert.strictEqual(lookup(catalog, 'search_docs'), 'mcp__alpha__search_docs');
assert.strictEqual(lookup(catalog, 'dup'), null, 'ambiguous describeTool suffix must not match');
console.log('OK_PATCH17');
"#,
                );
                let out = std::process::Command::new("node")
                    .arg("-e")
                    .arg(&js)
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "Patch #17 Node runtime test failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }

    #[test]
    fn patch15_upgrades_from_v269_alt_old_and_handles_raw_strings() {
        let base = std::env::temp_dir().join(format!("ap_pi_p15_upg_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let pi_dir = base.join("pi-coding-agent");
        let chunks = pi_dir.join("dist").join("bundle").join("chunks");
        let prelude_dir = pi_dir
            .join("node_modules")
            .join("@earendil-works")
            .join("pi-codemode")
            .join("dist")
            .join("runtime");
        fs::create_dir_all(&chunks).unwrap();
        fs::create_dir_all(&prelude_dir).unwrap();
        fs::write(
            pi_dir.join("package.json"),
            r#"{"name":"@earendil-works/pi-coding-agent","version":"1.6.0-test"}"#,
        )
        .unwrap();

        let p15 = PATCH_SPECS
            .iter()
            .find(|s| s.id == "codemode_result_output_shim")
            .unwrap();
        let v269_worker_shim = p15.hunks[0].alt_olds[2];
        let v269_prelude_shim = p15.hunks[1].alt_olds[2];
        fs::write(chunks.join("codemode-worker.js"), v269_worker_shim).unwrap();
        fs::write(prelude_dir.join("prelude-source.js"), v269_prelude_shim).unwrap();

        let _ap_home_guard = crate::stats::ApHomeTestGuard::set(&base.join("ap_home"));
        let pi_str = pi_dir.to_string_lossy().to_string();
        let applied = apply_pi_patches(Some(&pi_str), false).unwrap();
        let newly: Vec<String> = applied["newly_applied"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        assert!(newly.contains(
            &"codemode_result_output_shim:bundle_codemode_result_output_shim".to_string()
        ));
        assert!(newly.contains(
            &"codemode_result_output_shim:prelude_codemode_result_output_shim".to_string()
        ));
        assert!(fs::read_to_string(chunks.join("codemode-worker.js"))
            .unwrap()
            .contains("Object.isExtensible(String.prototype)"));
        assert!(fs::read_to_string(prelude_dir.join("prelude-source.js"))
            .unwrap()
            .contains("Object.isExtensible(String.prototype)"));

        let second = apply_pi_patches(Some(&pi_str), false).unwrap();
        assert_eq!(second["newly_applied"].as_array().unwrap().len(), 0);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn patch15_upgrades_v270_and_survives_frozen_lockdown() {
        let base = std::env::temp_dir().join(format!("ap_pi_p15_v270_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let pi_dir = base.join("pi-coding-agent");
        let chunks = pi_dir.join("dist").join("bundle").join("chunks");
        let prelude_dir = pi_dir
            .join("node_modules")
            .join("@earendil-works")
            .join("pi-codemode")
            .join("dist")
            .join("runtime");
        fs::create_dir_all(&chunks).unwrap();
        fs::create_dir_all(&prelude_dir).unwrap();
        fs::write(
            pi_dir.join("package.json"),
            r#"{"name":"@earendil-works/pi-coding-agent","version":"1.6.0-test"}"#,
        )
        .unwrap();

        let p15 = PATCH_SPECS
            .iter()
            .find(|s| s.id == "codemode_result_output_shim")
            .unwrap();
        fs::write(
            chunks.join("codemode-worker.js"),
            format!("{}\n{}\n", p15.hunks[2].old, p15.hunks[0].alt_olds[3]),
        )
        .unwrap();
        fs::write(
            prelude_dir.join("prelude-source.js"),
            format!("{}\n{}\n", p15.hunks[3].old, p15.hunks[1].alt_olds[3]),
        )
        .unwrap();

        let _ap_home_guard = crate::stats::ApHomeTestGuard::set(&base.join("ap_home"));
        let pi_str = pi_dir.to_string_lossy().to_string();
        let applied = apply_pi_patches(Some(&pi_str), false).unwrap();
        let newly: Vec<String> = applied["newly_applied"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        assert_eq!(
            newly.len(),
            4,
            "expected all 4 patch15 hunks to upgrade: {newly:?}"
        );
        let second = apply_pi_patches(Some(&pi_str), false).unwrap();
        assert_eq!(second["newly_applied"].as_array().unwrap().len(), 0);

        if std::process::Command::new("node")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            let prelock = p15.hunks[2]
                .new
                .split("// Freeze every object")
                .next()
                .unwrap();
            let settle_body = p15.hunks[0].new;
            let script = format!(
                r#"
import assert from "node:assert/strict";
import vm from "node:vm";

// 1) Pre-lockdown + frozen String.prototype/Object.prototype (matches Pi codemode prelude)
const ctx1 = vm.createContext({{}});
vm.runInContext(`
{prelock}
Object.freeze(String.prototype);
Object.freeze(Object.prototype);
const parse = JSON.parse;
const stringify = JSON.stringify;
function settle(payload) {{
  let resolved;
  const entry = {{ resolve(v) {{ resolved = v; }}, reject(e) {{ throw e; }} }};
{settle_body}
  return resolved;
}}
const s = settle(JSON.stringify("hello"));
if (s !== "hello" || s.output !== "hello") throw new Error("string output failed");
const obj = settle(JSON.stringify({{ text: "ok" }}));
if (obj.output !== "ok") throw new Error("object output failed");
let frozen = Object.freeze({{ stdout: "frz" }});
const frz = (() => {{
  let value = frozen;
  let resolved;
  const entry = {{ resolve(v) {{ resolved = v; }} }};
  if (value && typeof value === "object" && !Array.isArray(value) && typeof value.output !== "string") {{
    const _out = typeof value.text === "string" ? value.text : typeof value.stdout === "string" ? value.stdout : stringify(value);
    try {{
      if (!Object.isExtensible(value)) value = Object.assign({{}}, value);
      Object.defineProperty(value, "output", {{ value: _out, enumerable: false, configurable: true }});
    }} catch (_e) {{}}
  }}
  entry.resolve(value);
  return resolved;
}})();
if (frz.output !== "frz") throw new Error("frozen object output failed");
`, ctx1);

// 2) Even if String.prototype was ALREADY frozen before pre-lockdown, settle() must NOT throw
const ctx2 = vm.createContext({{}});
vm.runInContext(`
"use strict";
Object.freeze(String.prototype);
const parse = JSON.parse;
const stringify = JSON.stringify;
function settle(payload) {{
  let resolved;
  const entry = {{ resolve(v) {{ resolved = v; }}, reject(e) {{ throw e; }} }};
{settle_body}
  return resolved;
}}
const s2 = settle(JSON.stringify("plain"));
if (s2 !== "plain") throw new Error("already-frozen String.prototype failed");
const o2 = settle(JSON.stringify({{ content: [{{ type: "text", text: "hi" }}] }}));
if (o2.output !== "hi") throw new Error("content output failed");
`, ctx2);
assert.ok(true);
"#
            );
            let run = std::process::Command::new("node")
                .args(["--input-type=module", "-e", &script])
                .output()
                .unwrap();
            assert!(
                run.status.success(),
                "Frozen lockdown JS check failed:\nstdout={}\nstderr={}",
                String::from_utf8_lossy(&run.stdout),
                String::from_utf8_lossy(&run.stderr)
            );
        }

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn inspect_never_masks_drifted_bundle_hunk_as_applied() {
        let base = std::env::temp_dir().join(format!("ap_pi_drift_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let pi_dir = base.join("pi-coding-agent");
        let chunks = pi_dir.join("dist").join("bundle").join("chunks");
        fs::create_dir_all(&chunks).unwrap();
        fs::write(
            pi_dir.join("package.json"),
            r#"{"name":"@earendil-works/pi-coding-agent","version":"1.6.1-drift"}"#,
        )
        .unwrap();
        // Put ONLY 1 of 2 hunks of sequential_shell_tool_barrier as applied, and drift the other
        let seq_spec = PATCH_SPECS
            .iter()
            .find(|s| s.id == "sequential_shell_tool_barrier")
            .unwrap();
        fs::write(
            chunks.join("chunk-main.js"),
            format!("{}\n// drifted executeToolCalls\n", seq_spec.hunks[1].new),
        )
        .unwrap();

        let report = inspect_pi_patches(Some(&pi_dir.to_string_lossy()));
        let item = report
            .patches
            .iter()
            .find(|p| p.id == "sequential_shell_tool_barrier")
            .unwrap();
        assert_eq!(
            item.status, "partial",
            "drifted required bundle hunk must report partial, never applied"
        );
        assert_eq!(item.applied_hunks, 1);
        assert_eq!(item.total_hunks, 2);
        assert!(item
            .skipped_hunks
            .iter()
            .any(|s| s.contains("bundle_execute_tool_calls_barrier")));
        assert!(!report.all_applied);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn node_verifies_session_before_compact_first_wins_and_dns_stale_cache() {
        if !std::process::Command::new("node")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return;
        }
        let compact_spec = PATCH_SPECS
            .iter()
            .find(|s| s.id == "session_before_compact_first_wins")
            .unwrap();
        let dns_spec = PATCH_SPECS
            .iter()
            .find(|s| s.id == "http_dns_stale_cache")
            .unwrap();
        // Ensure http_dns_stale_cache targets EnvHttpProxyAgent (NOT createUndiciClient) so pre-built function connectors/proxy tunnels stay intact
        for h in dns_spec.hunks {
            assert!(
                !h.old.contains("createUndiciClient") && !h.new.contains("createUndiciClient"),
                "http_dns_stale_cache must not patch createUndiciClient"
            );
            assert!(h.new.contains("EnvHttpProxyAgent"));
        }
        let compact_branch = compact_spec.hunks[0].new;
        let dns_prefix = dns_spec.hunks[0].new;
        let script = format!(
            r#"
import assert from "node:assert/strict";

// 1) Verify session_before_compact_first_wins semantics
const runner = {{
  isSessionBeforeEvent(e) {{ return e.type === "session_before_compact" || e.type === "session_before_tree"; }},
  async emit(event, handlers) {{
    let result;
    for (const handler of handlers) {{
      const handlerResult = await handler(event);
      {compact_branch}
    }}
    return result;
  }}
}};

let seenClaimed = false;
const ev1 = {{ type: "session_before_compact" }};
const res1 = await runner.emit(ev1, [
  async () => ({{ compaction: {{ summary: "first-wins" }} }}),
  async (e) => {{ seenClaimed = Boolean(e.compactionClaimed); return {{ compaction: {{ summary: "second-ignored" }} }}; }},
]);
assert.strictEqual(seenClaimed, true, "second handler must see event.compactionClaimed === true");
assert.strictEqual(res1.compaction.summary, "first-wins", "first compaction must not be overwritten");

const ev2 = {{ type: "session_before_compact" }};
const res2 = await runner.emit(ev2, [
  async () => ({{ compaction: {{ summary: "first" }} }}),
  async () => ({{ cancel: true }}),
]);
assert.strictEqual(res2.cancel, true, "cancel must still preempt");

// 2) Verify http_dns_stale_cache in configureHttpDispatcher:
//    - preserves connect keepAlive/timeout/autoSelectFamilyAttemptTimeout options
//    - never overwrites a function-valued connect (proxy tunnel / pre-built connector)
//    - fresh 45s TTL hit + all:true/all:false + 10m stale fallback on ENOTFOUND + >10m error propagation
let liveCalls = 0;
let failMode = false;
globalThis.__piDnsStaleCache = new Map();
globalThis.__piDnsModP = Promise.resolve({{
  lookup(host, opts, cb) {{
    liveCalls += 1;
    if (failMode) {{
      const err = new Error("getaddrinfo ENOTFOUND " + host);
      err.code = "ENOTFOUND";
      return cb(err);
    }}
    if (opts && opts.all) return cb(null, [{{ address: "1.2.3.4", family: 4 }}]);
    return cb(null, "1.2.3.4", 4);
  }}
}});
let capturedOpts = null;
const withUndiciErrorListener = (x) => x;
const undici = {{
  EnvHttpProxyAgent: class {{
    constructor(opts) {{ capturedOpts = opts; }}
  }}
}};

// Case A: plain connect object retains all tuning knobs + gains lookup
{dns_prefix}{{
  proxyTunnel: true,
  connect: {{
    autoSelectFamilyAttemptTimeout: 250,
    timeout: 35000,
    keepAlive: true,
    keepAliveInitialDelay: 10000,
  }},
}}));
assert.strictEqual(capturedOpts.connect.autoSelectFamilyAttemptTimeout, 250);
assert.strictEqual(capturedOpts.connect.timeout, 35000);
assert.strictEqual(capturedOpts.connect.keepAlive, true);
assert.strictEqual(capturedOpts.connect.keepAliveInitialDelay, 10000);
assert.strictEqual(typeof capturedOpts.connect.lookup, "function");

const lookupFn = capturedOpts.connect.lookup;

// Case B: function-valued connect MUST NOT be overwritten
const prebuiltFn = () => "proxy-connector";
{dns_prefix}{{ connect: prebuiltFn }}));
assert.strictEqual(capturedOpts.connect, prebuiltFn, "function connect must remain untouched");

const lookupP = (host, opts) => new Promise((res, rej) => {{
  lookupFn(host, opts, (err, a, b) => err ? rej(err) : res([a, b]));
}});

// Fresh lookup populates cache
const [addr1, fam1] = await lookupP("api.example.test", {{ family: 4 }});
assert.strictEqual(addr1, "1.2.3.4");
assert.strictEqual(fam1, 4);
assert.strictEqual(liveCalls, 1);

// Second lookup within 45s TTL hits cache (no live DNS call)
const [addr2, fam2] = await lookupP("api.example.test", {{ family: 4 }});
assert.strictEqual(addr2, "1.2.3.4");
assert.strictEqual(fam2, 4);
assert.strictEqual(liveCalls, 1);

// all:true lookup caches array separately
const [arr1] = await lookupP("api.example.test", {{ all: true }});
assert.deepStrictEqual(arr1, [{{ address: "1.2.3.4", family: 4 }}]);
assert.strictEqual(liveCalls, 2);

// Age cache entry to 60s (past 45s fresh TTL, within 10m stale window) and trigger ENOTFOUND
for (const [k, v] of globalThis.__piDnsStaleCache.entries()) {{
  globalThis.__piDnsStaleCache.set(k, {{ ...v, t: Date.now() - 60000 }});
}}
failMode = true;
const [staleAddr, staleFam] = await lookupP("api.example.test", {{ family: 4 }});
assert.strictEqual(staleAddr, "1.2.3.4");
assert.strictEqual(staleFam, 4);
const [staleArr] = await lookupP("api.example.test", {{ all: true }});
assert.deepStrictEqual(staleArr, [{{ address: "1.2.3.4", family: 4 }}]);

// Age cache entry past 10m (>600s) -> ENOTFOUND must propagate
for (const [k, v] of globalThis.__piDnsStaleCache.entries()) {{
  globalThis.__piDnsStaleCache.set(k, {{ ...v, t: Date.now() - 700000 }});
}}
await assert.rejects(() => lookupP("api.example.test", {{ family: 4 }}), /ENOTFOUND/);
console.log("OK_COMPACT_AND_DNS");
"#
        );
        let run = std::process::Command::new("node")
            .args(["--input-type=module", "-e", &script])
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "Node check failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
    }
}
