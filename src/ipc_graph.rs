use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;
use tree_sitter::{Node, Parser};

const SKIP_DIRS: [&str; 6] = [
    "node_modules",
    ".git",
    "dist_backup",
    "__pycache__",
    "target",
    ".venv",
];

const DANGEROUS_SINKS: [&str; 22] = [
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
    "fork",
    "openExternal",
    "openPath",
    "showItemInFolder",
    "eval",
    "Function",
    "executeJavaScript",
    "loadURL",
    "writeFile",
    "writeFileSync",
    "unlink",
    "unlinkSync",
    "rmSync",
    "readFile",
    "readFileSync",
    "dlopen",
];

const GUARD_KEYWORDS: [&str; 18] = [
    "origin",
    "senderFrame",
    "allowlist",
    "whitelist",
    "startsWith",
    "realpath",
    "realpathSync",
    "normalize",
    "resolve",
    "validate",
    "sanitize",
    "isSafe",
    "checkAuth",
    "hasPermission",
    "isAllowed",
    "escape",
    "URL",
    "..",
];

fn js_lang_for_name(name: &str) -> Option<tree_sitter::Language> {
    let low = name.to_ascii_lowercase();
    if low.ends_with(".tsx") {
        Some(tree_sitter_typescript::LANGUAGE_TSX.into())
    } else if low.ends_with(".ts") || low.ends_with(".mts") || low.ends_with(".cts") {
        Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
    } else if low.ends_with(".js")
        || low.ends_with(".mjs")
        || low.ends_with(".cjs")
        || low.ends_with(".jsx")
    {
        Some(tree_sitter_javascript::LANGUAGE.into())
    } else {
        None
    }
}

fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn unquote_js_str(raw: &str) -> String {
    let t = raw.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"'))
            || (t.starts_with('\'') && t.ends_with('\''))
            || (t.starts_with('`') && t.ends_with('`')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

fn resolve_channel_expr(
    node: Node,
    src: &[u8],
    const_map: &HashMap<String, String>,
) -> (String, bool) {
    let txt = node_text(node, src).trim();
    match node.kind() {
        "string" => (unquote_js_str(txt), false),
        "template_string" => (unquote_js_str(txt), txt.contains("${")),
        "identifier" => {
            if let Some(val) = const_map.get(txt) {
                (val.clone(), false)
            } else {
                (txt.to_string(), true)
            }
        }
        "member_expression" => {
            if let Some(val) = const_map.get(txt) {
                (val.clone(), false)
            } else if let Some(prop) = node.child_by_field_name("property") {
                let pt = node_text(prop, src).trim();
                if let Some(val) = const_map.get(pt) {
                    (val.clone(), false)
                } else {
                    (txt.to_string(), true)
                }
            } else {
                (txt.to_string(), true)
            }
        }
        _ => (txt.chars().take(80).collect(), true),
    }
}

#[derive(Clone, Debug)]
struct BridgeExposure {
    file: String,
    namespace: String,
    api_name: String,
    channel: String,
    dynamic: bool,
    via_wrapper: Option<String>,
    line: usize,
}

#[derive(Clone, Debug)]
struct RendererSend {
    file: String,
    channel: String,
    #[allow(dead_code)]
    dynamic: bool,
    via_wrapper: Option<String>,
    line: usize,
}

#[derive(Clone, Debug)]
struct MainHandler {
    file: String,
    channel: String,
    dynamic: bool,
    fn_name: String,
    sinks: Vec<String>,
    guards: Vec<String>,
    called_helpers: Vec<String>,
    line: usize,
}

#[derive(Clone, Debug)]
struct WrapperFn {
    file: String,
    name: String,
    ipc_kind: String, // "renderer" | "sink"
    sinks: Vec<String>,
    guards: Vec<String>,
}

fn collect_sinks_and_guards(node: Node, src: &[u8]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut sinks = BTreeSet::new();
    let mut guards = BTreeSet::new();
    let mut calls = BTreeSet::new();

    fn walk(
        n: Node,
        src: &[u8],
        sinks: &mut BTreeSet<String>,
        guards: &mut BTreeSet<String>,
        calls: &mut BTreeSet<String>,
    ) {
        let k = n.kind();
        let txt = node_text(n, src);
        if k == "call_expression" {
            if let Some(fn_node) = n.child_by_field_name("function") {
                let fn_txt = node_text(fn_node, src).trim();
                let short = fn_txt.rsplit('.').next().unwrap_or(fn_txt);
                if DANGEROUS_SINKS.contains(&short) {
                    sinks.insert(fn_txt.chars().take(64).collect());
                } else if !short.is_empty() && short.len() <= 48 {
                    calls.insert(short.to_string());
                }
                if GUARD_KEYWORDS
                    .iter()
                    .any(|g| short == *g || fn_txt.contains(g))
                {
                    guards.insert(fn_txt.chars().take(48).collect());
                }
            }
        } else if k == "new_expression" {
            if let Some(ctor) = n.child_by_field_name("constructor") {
                let ct = node_text(ctor, src).trim();
                if ct == "Function" {
                    sinks.insert("new Function".to_string());
                } else if ct == "URL" {
                    guards.insert("new URL".to_string());
                }
            }
        } else if k == "member_expression" {
            if let Some(prop) = n.child_by_field_name("property") {
                let p = node_text(prop, src).trim();
                if matches!(p, "origin" | "senderFrame" | "hostname" | "protocol") {
                    guards.insert(txt.chars().take(48).collect());
                }
            }
        } else if k == "string" && txt.contains("..") {
            guards.insert("dotdot_check".to_string());
        }
        let mut cur = n.walk();
        for ch in n.children(&mut cur) {
            walk(ch, src, sinks, guards, calls);
        }
    }

    walk(node, src, &mut sinks, &mut guards, &mut calls);
    (
        sinks.into_iter().collect(),
        guards.into_iter().collect(),
        calls.into_iter().collect(),
    )
}

fn find_ipc_renderer_calls(
    node: Node,
    src: &[u8],
    const_map: &HashMap<String, String>,
    wrapper_names: &HashSetWrapper,
) -> Vec<(String, bool, Option<String>)> {
    let mut out = Vec::new();
    fn walk(
        n: Node,
        src: &[u8],
        const_map: &HashMap<String, String>,
        wrapper_names: &HashSetWrapper,
        out: &mut Vec<(String, bool, Option<String>)>,
    ) {
        if n.kind() == "call_expression" {
            if let Some(fn_node) = n.child_by_field_name("function") {
                let fn_txt = node_text(fn_node, src).trim();
                let short = fn_txt.rsplit('.').next().unwrap_or(fn_txt);
                let is_direct_ipc = fn_txt.contains("ipcRenderer.")
                    && matches!(short, "invoke" | "send" | "sendSync" | "postMessage");
                let is_wrap = wrapper_names.contains(short);
                if is_direct_ipc || is_wrap {
                    if let Some(args) = n.child_by_field_name("arguments") {
                        let first_opt = {
                            let mut acur = args.walk();
                            let x = args.named_children(&mut acur).next();
                            x
                        };
                        if let Some(first_arg) = first_opt {
                            let (ch, dyn_flag) = resolve_channel_expr(first_arg, src, const_map);
                            out.push((
                                ch,
                                dyn_flag,
                                if is_wrap {
                                    Some(short.to_string())
                                } else {
                                    None
                                },
                            ));
                        }
                    }
                }
            }
        }
        let mut cur = n.walk();
        for ch in n.children(&mut cur) {
            walk(ch, src, const_map, wrapper_names, out);
        }
    }
    walk(node, src, const_map, wrapper_names, &mut out);
    out
}

type HashSetWrapper = std::collections::HashSet<String>;

fn collect_js_constants(root: Node, src: &[u8], out: &mut HashMap<String, String>) {
    fn walk(n: Node, src: &[u8], out: &mut HashMap<String, String>) {
        if n.kind() == "variable_declarator" {
            if let (Some(nm), Some(val)) = (
                n.child_by_field_name("name"),
                n.child_by_field_name("value"),
            ) {
                if nm.kind() == "identifier" && val.kind() == "string" {
                    let k = node_text(nm, src).trim();
                    let v = unquote_js_str(node_text(val, src));
                    if !k.is_empty() && !v.is_empty() && v.len() <= 120 {
                        out.insert(k.to_string(), v);
                    }
                }
            }
        } else if n.kind() == "assignment_expression" {
            if let (Some(lhs), Some(rhs)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            ) {
                if rhs.kind() == "string" {
                    let k = node_text(lhs, src).trim();
                    let v = unquote_js_str(node_text(rhs, src));
                    if !k.is_empty() && !v.is_empty() && v.len() <= 120 {
                        out.insert(k.to_string(), v.clone());
                        if let Some(prop) = k.rsplit('.').next() {
                            out.entry(prop.to_string()).or_insert(v);
                        }
                    }
                }
            }
        }
        let mut cur = n.walk();
        for ch in n.children(&mut cur) {
            walk(ch, src, out);
        }
    }
    walk(root, src, out);
}

fn collect_named_functions<'a>(root: Node<'a>, src: &'a [u8]) -> Vec<(String, Node<'a>)> {
    let mut out = Vec::new();
    fn walk<'a>(n: Node<'a>, src: &'a [u8], out: &mut Vec<(String, Node<'a>)>) {
        match n.kind() {
            "function_declaration" => {
                if let Some(nm) = n.child_by_field_name("name") {
                    out.push((node_text(nm, src).trim().to_string(), n));
                }
            }
            "variable_declarator" => {
                if let (Some(nm), Some(val)) = (
                    n.child_by_field_name("name"),
                    n.child_by_field_name("value"),
                ) {
                    if nm.kind() == "identifier"
                        && matches!(
                            val.kind(),
                            "arrow_function" | "function_expression" | "function"
                        )
                    {
                        out.push((node_text(nm, src).trim().to_string(), val));
                    }
                }
            }
            "assignment_expression" => {
                if let (Some(lhs), Some(rhs)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                ) {
                    if matches!(
                        rhs.kind(),
                        "arrow_function" | "function_expression" | "function"
                    ) {
                        let full = node_text(lhs, src).trim();
                        let short = full.rsplit('.').next().unwrap_or(full).to_string();
                        if !short.is_empty() {
                            out.push((short, rhs));
                        }
                    }
                }
            }
            _ => {}
        }
        let mut cur = n.walk();
        for ch in n.children(&mut cur) {
            walk(ch, src, out);
        }
    }
    walk(root, src, &mut out);
    out
}

/// Core Tree-sitter cross-file Electron/JS IPC stitcher (`bridge_api -> channel -> main_handler -> sink + guards`).
pub fn analyze_ipc_graph_files(
    files: &[(String, String)],
    label: &str,
    query: Option<&str>,
) -> (String, Value) {
    let t0 = Instant::now();
    let mut const_map: HashMap<String, String> = HashMap::new();
    let mut parsed_trees: Vec<(&str, &str, tree_sitter::Tree)> = Vec::new();

    for (path, content) in files {
        let Some(lang) = js_lang_for_name(path) else {
            continue;
        };
        if content.len() > 2 * 1024 * 1024 {
            continue;
        }
        let mut parser = Parser::new();
        if parser.set_language(&lang).is_err() {
            continue;
        }
        let Some(tree) = parser.parse(content, None) else {
            continue;
        };
        collect_js_constants(tree.root_node(), content.as_bytes(), &mut const_map);
        parsed_trees.push((path.as_str(), content.as_str(), tree));
    }

    // Pass 1: discover ipcRenderer wrappers & helper functions
    let mut wrappers: Vec<WrapperFn> = Vec::new();
    let mut renderer_wrapper_names: HashSetWrapper = HashSetWrapper::new();
    let mut helper_lookup: HashMap<String, WrapperFn> = HashMap::new();

    for (path, content, tree) in &parsed_trees {
        let src = content.as_bytes();
        for (fn_name, fn_node) in collect_named_functions(tree.root_node(), src) {
            let fn_txt = node_text(fn_node, src);
            if fn_txt.contains("ipcRenderer.")
                && (fn_txt.contains(".invoke(")
                    || fn_txt.contains(".send(")
                    || fn_txt.contains(".sendSync("))
            {
                renderer_wrapper_names.insert(fn_name.clone());
                wrappers.push(WrapperFn {
                    file: (*path).to_string(),
                    name: fn_name.clone(),
                    ipc_kind: "renderer".to_string(),
                    sinks: Vec::new(),
                    guards: Vec::new(),
                });
            }
            let (sinks, guards, _) = collect_sinks_and_guards(fn_node, src);
            if !sinks.is_empty() || !guards.is_empty() {
                helper_lookup.insert(
                    fn_name.clone(),
                    WrapperFn {
                        file: (*path).to_string(),
                        name: fn_name,
                        ipc_kind: "sink".to_string(),
                        sinks,
                        guards,
                    },
                );
            }
        }
    }

    // Pass 2: collect bridge exposures, renderer sends & main handlers
    let mut bridges: Vec<BridgeExposure> = Vec::new();
    let mut renderer_sends: Vec<RendererSend> = Vec::new();
    let mut main_handlers: Vec<MainHandler> = Vec::new();

    for (path, content, tree) in &parsed_trees {
        let src = content.as_bytes();
        let named_fns_here: HashMap<String, Node> = collect_named_functions(tree.root_node(), src)
            .into_iter()
            .collect();

        #[allow(clippy::too_many_arguments)]
        fn visit_node(
            n: Node,
            file: &str,
            src: &[u8],
            const_map: &HashMap<String, String>,
            renderer_wrapper_names: &HashSetWrapper,
            named_fns_here: &HashMap<String, Node>,
            bridges: &mut Vec<BridgeExposure>,
            renderer_sends: &mut Vec<RendererSend>,
            main_handlers: &mut Vec<MainHandler>,
        ) {
            if n.kind() == "call_expression" {
                if let Some(fn_node) = n.child_by_field_name("function") {
                    let fn_txt = node_text(fn_node, src).trim();
                    let short = fn_txt.rsplit('.').next().unwrap_or(fn_txt);
                    let line = n.start_position().row + 1;

                    // A. contextBridge.exposeInMainWorld(ns, { ... })
                    if short == "exposeInMainWorld" || fn_txt.ends_with("exposeInMainWorld") {
                        if let Some(args) = n.child_by_field_name("arguments") {
                            let mut acur = args.walk();
                            let named: Vec<Node> = args.named_children(&mut acur).collect();
                            if named.len() >= 2 {
                                let (ns, _) = resolve_channel_expr(named[0], src, const_map);
                                let obj_node = named[1];
                                if obj_node.kind() == "object" {
                                    let mut ocur = obj_node.walk();
                                    for prop in obj_node.named_children(&mut ocur) {
                                        if prop.kind() == "pair" {
                                            if let (Some(k), Some(v)) = (
                                                prop.child_by_field_name("key"),
                                                prop.child_by_field_name("value"),
                                            ) {
                                                let api_name = unquote_js_str(node_text(k, src));
                                                let calls = find_ipc_renderer_calls(
                                                    v,
                                                    src,
                                                    const_map,
                                                    renderer_wrapper_names,
                                                );
                                                if calls.is_empty() {
                                                    bridges.push(BridgeExposure {
                                                        file: file.to_string(),
                                                        namespace: ns.clone(),
                                                        api_name,
                                                        channel: String::new(),
                                                        dynamic: false,
                                                        via_wrapper: None,
                                                        line,
                                                    });
                                                } else {
                                                    for (ch, dyn_f, wrap) in calls {
                                                        bridges.push(BridgeExposure {
                                                            file: file.to_string(),
                                                            namespace: ns.clone(),
                                                            api_name: api_name.clone(),
                                                            channel: ch,
                                                            dynamic: dyn_f,
                                                            via_wrapper: wrap,
                                                            line,
                                                        });
                                                    }
                                                }
                                            }
                                        } else if prop.kind() == "method_definition" {
                                            if let Some(k) = prop.child_by_field_name("name") {
                                                let api_name = unquote_js_str(node_text(k, src));
                                                let calls = find_ipc_renderer_calls(
                                                    prop,
                                                    src,
                                                    const_map,
                                                    renderer_wrapper_names,
                                                );
                                                for (ch, dyn_f, wrap) in calls {
                                                    bridges.push(BridgeExposure {
                                                        file: file.to_string(),
                                                        namespace: ns.clone(),
                                                        api_name: api_name.clone(),
                                                        channel: ch,
                                                        dynamic: dyn_f,
                                                        via_wrapper: wrap,
                                                        line,
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else if (fn_txt.contains("ipcRenderer.")
                        && matches!(short, "invoke" | "send" | "sendSync" | "postMessage"))
                        || renderer_wrapper_names.contains(short)
                    {
                        if let Some(args) = n.child_by_field_name("arguments") {
                            let first_opt = {
                                let mut acur = args.walk();
                                let x = args.named_children(&mut acur).next();
                                x
                            };
                            if let Some(first_arg) = first_opt {
                                let (ch, dyn_f) = resolve_channel_expr(first_arg, src, const_map);
                                if !ch.is_empty() {
                                    renderer_sends.push(RendererSend {
                                        file: file.to_string(),
                                        channel: ch,
                                        dynamic: dyn_f,
                                        via_wrapper: if renderer_wrapper_names.contains(short) {
                                            Some(short.to_string())
                                        } else {
                                            None
                                        },
                                        line,
                                    });
                                }
                            }
                        }
                    } else if (fn_txt.contains("ipcMain.") || fn_txt == "handle")
                        && matches!(short, "handle" | "handleOnce" | "on")
                    {
                        if let Some(args) = n.child_by_field_name("arguments") {
                            let mut acur = args.walk();
                            let named: Vec<Node> = args.named_children(&mut acur).collect();
                            if named.len() >= 2 {
                                let (ch, dyn_f) = resolve_channel_expr(named[0], src, const_map);
                                let h_node = named[1];
                                let (fn_name, body_node) = if h_node.kind() == "identifier" {
                                    let id = node_text(h_node, src).trim().to_string();
                                    let resolved =
                                        named_fns_here.get(&id).copied().unwrap_or(h_node);
                                    (id, resolved)
                                } else {
                                    (format!("anonymous@L{line}"), h_node)
                                };
                                let (sinks, guards, called_helpers) =
                                    collect_sinks_and_guards(body_node, src);
                                main_handlers.push(MainHandler {
                                    file: file.to_string(),
                                    channel: ch,
                                    dynamic: dyn_f,
                                    fn_name,
                                    sinks,
                                    guards,
                                    called_helpers,
                                    line,
                                });
                            }
                        }
                    }
                }
            }
            let mut cur = n.walk();
            for ch in n.children(&mut cur) {
                visit_node(
                    ch,
                    file,
                    src,
                    const_map,
                    renderer_wrapper_names,
                    named_fns_here,
                    bridges,
                    renderer_sends,
                    main_handlers,
                );
            }
        }

        visit_node(
            tree.root_node(),
            path,
            src,
            &const_map,
            &renderer_wrapper_names,
            &named_fns_here,
            &mut bridges,
            &mut renderer_sends,
            &mut main_handlers,
        );
    }

    // Pass 3: enrich main handlers with 1-hop helper sinks & guards across files
    for mh in &mut main_handlers {
        let mut sset: BTreeSet<String> = mh.sinks.iter().cloned().collect();
        let mut gset: BTreeSet<String> = mh.guards.iter().cloned().collect();
        for helper_nm in &mh.called_helpers {
            if let Some(wf) = helper_lookup.get(helper_nm) {
                for s in &wf.sinks {
                    sset.insert(format!("{helper_nm}->{s}"));
                }
                for g in &wf.guards {
                    gset.insert(format!("{helper_nm}:{g}"));
                }
            }
        }
        mh.sinks = sset.into_iter().collect();
        mh.guards = gset.into_iter().collect();
    }

    // Pass 4: stitch edges `bridge_api -> channel -> main_handler -> sink + guard_summary`
    let q_low = query
        .map(|q| q.trim().to_ascii_lowercase())
        .filter(|q| !q.is_empty());
    let mut handler_by_channel: BTreeMap<String, Vec<&MainHandler>> = BTreeMap::new();
    for mh in &main_handlers {
        handler_by_channel
            .entry(mh.channel.clone())
            .or_default()
            .push(mh);
    }
    let mut bridge_by_channel: BTreeMap<String, Vec<&BridgeExposure>> = BTreeMap::new();
    for b in &bridges {
        if !b.channel.is_empty() {
            bridge_by_channel
                .entry(b.channel.clone())
                .or_default()
                .push(b);
        }
    }
    let mut send_by_channel: BTreeMap<String, Vec<&RendererSend>> = BTreeMap::new();
    for s in &renderer_sends {
        send_by_channel
            .entry(s.channel.clone())
            .or_default()
            .push(s);
    }

    let mut edges: Vec<Value> = Vec::new();
    for mh in &main_handlers {
        let severity = if !mh.sinks.is_empty() && mh.guards.is_empty() {
            "CRITICAL"
        } else if !mh.sinks.is_empty() {
            "HIGH"
        } else if mh.guards.is_empty() {
            "MEDIUM"
        } else {
            "LOW"
        };
        let guard_summary = if mh.guards.is_empty() {
            "unguarded".to_string()
        } else {
            format!("guarded({})", mh.guards.join(", "))
        };
        let matched_bridges = bridge_by_channel.get(&mh.channel);
        let matched_sends = send_by_channel.get(&mh.channel);

        let bridge_apis: Vec<String> = matched_bridges
            .map(|bs| {
                bs.iter()
                    .map(|b| {
                        let w = b
                            .via_wrapper
                            .as_deref()
                            .map(|wn| format!(" via {wn}()"))
                            .unwrap_or_default();
                        format!("{}.{}{w} ({}:L{})", b.namespace, b.api_name, b.file, b.line)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let renderer_callsites: Vec<String> = matched_sends
            .map(|ss| {
                ss.iter()
                    .take(6)
                    .map(|s| {
                        let w = s
                            .via_wrapper
                            .as_deref()
                            .map(|wn| format!(" via {wn}()"))
                            .unwrap_or_default();
                        format!("{}:L{}{w}", s.file, s.line)
                    })
                    .collect()
            })
            .unwrap_or_default();

        let edge_text = format!(
            "{} {} {} {} {}",
            mh.channel,
            mh.file,
            bridge_apis.join(" "),
            mh.sinks.join(" "),
            guard_summary
        )
        .to_ascii_lowercase();
        if let Some(ref q) = q_low {
            if !edge_text.contains(q) {
                continue;
            }
        }
        edges.push(json!({
            "severity": severity,
            "channel": mh.channel,
            "dynamic_channel": mh.dynamic,
            "bridge_apis": bridge_apis,
            "renderer_callsites": renderer_callsites,
            "handler_file": mh.file,
            "handler_fn": mh.fn_name,
            "handler_line": mh.line,
            "sinks": mh.sinks,
            "guards": mh.guards,
            "guard_summary": guard_summary,
        }));
    }

    // Sort edges: CRITICAL first, then HIGH, MEDIUM, LOW
    let sev_rank = |v: &Value| -> u8 {
        match v["severity"].as_str().unwrap_or("") {
            "CRITICAL" => 0,
            "HIGH" => 1,
            "MEDIUM" => 2,
            _ => 3,
        }
    };
    edges.sort_by_key(sev_rank);

    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
    let critical_cnt = edges.iter().filter(|e| e["severity"] == "CRITICAL").count();
    let mut md = vec![format!(
        "# IPC BRIDGE GRAPH `{label}` ({} files parsed | {} edges, {} CRITICAL unguarded, {} bridges, {} wrappers in {elapsed_ms}ms)",
        parsed_trees.len(),
        edges.len(),
        critical_cnt,
        bridges.len(),
        wrappers.len()
    )];
    for e in edges.iter().take(40) {
        let sev = e["severity"].as_str().unwrap_or("");
        let ch = e["channel"].as_str().unwrap_or("");
        let br = e["bridge_apis"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .unwrap_or("(renderer/direct)");
        let sinks: Vec<&str> = e["sinks"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let gsum = e["guard_summary"].as_str().unwrap_or("");
        md.push(format!(
            "- **[{sev}]** `{br}` -> `{ch}` -> `{}:L{}` sinks=`[{}]` | {gsum}",
            e["handler_file"].as_str().unwrap_or(""),
            e["handler_line"].as_u64().unwrap_or(0),
            sinks.join(", ")
        ));
    }

    let jv = json!({
        "ok": true,
        "format": "ipc-graph",
        "target": label,
        "elapsed_ms": elapsed_ms,
        "files_parsed": parsed_trees.len(),
        "counts": {
            "bridges": bridges.len(),
            "wrappers": wrappers.len(),
            "renderer_sends": renderer_sends.len(),
            "main_handlers": main_handlers.len(),
            "edges": edges.len(),
            "critical_unguarded": critical_cnt,
        },
        "bridge_exposures": bridges.iter().take(60).map(|b| json!({
            "file": b.file,
            "namespace": b.namespace,
            "api": b.api_name,
            "channel": b.channel,
            "dynamic": b.dynamic,
            "via_wrapper": b.via_wrapper,
            "line": b.line,
        })).collect::<Vec<_>>(),
        "wrappers": wrappers.iter().take(40).map(|w| json!({
            "file": w.file,
            "name": w.name,
            "kind": w.ipc_kind,
        })).collect::<Vec<_>>(),
        "edges": edges,
    });
    (md.join("\n"), jv)
}

pub fn inspect_ipc_graph_path(
    path: &Path,
    label: &str,
    query: Option<&str>,
) -> Result<(String, Value), String> {
    let mut files: Vec<(String, String)> = Vec::new();
    let is_asar = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("asar"));
    if path.is_file() && is_asar {
        let mut r = BufReader::new(
            fs::File::open(path).map_err(|e| format!("failed to open `{label}`: {e}"))?,
        );
        let (base, entries) = crate::binary::parse_asar_index_reader(&mut r)?;
        for ent in entries {
            if ent.unpacked || ent.size == 0 || ent.size > 2 * 1024 * 1024 {
                continue;
            }
            if js_lang_for_name(&ent.path).is_none() {
                continue;
            }
            let pos = (base as u64)
                .checked_add(ent.offset as u64)
                .ok_or_else(|| "offset overflow".to_string())?;
            if r.seek(SeekFrom::Start(pos)).is_err() {
                continue;
            }
            let mut buf = vec![0u8; ent.size];
            if r.read_exact(&mut buf).is_ok() {
                files.push((ent.path, String::from_utf8_lossy(&buf).into_owned()));
            }
            if files.len() >= 200 {
                break;
            }
        }
    } else if path.is_dir() {
        fn walk_dir(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
            if out.len() >= 200 {
                return;
            }
            let Ok(rd) = fs::read_dir(dir) else {
                return;
            };
            for ent in rd.flatten() {
                let p = ent.path();
                let nm = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if p.is_dir() {
                    if !SKIP_DIRS.contains(&nm) {
                        walk_dir(&p, root, out);
                    }
                } else if p.is_file() && js_lang_for_name(nm).is_some() {
                    if let Ok(md) = p.metadata() {
                        if md.len() > 0 && md.len() <= 2 * 1024 * 1024 {
                            if let Ok(txt) = fs::read_to_string(&p) {
                                let rel = p
                                    .strip_prefix(root)
                                    .unwrap_or(&p)
                                    .to_string_lossy()
                                    .replace('\\', "/");
                                out.push((rel, txt));
                            }
                        }
                    }
                }
                if out.len() >= 200 {
                    break;
                }
            }
        }
        walk_dir(path, path, &mut files);
    } else if path.is_file() {
        let txt = fs::read_to_string(path).map_err(|e| format!("failed to read `{label}`: {e}"))?;
        let rel = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(label)
            .to_string();
        files.push((rel, txt));
    } else {
        return Err(format!("path not found: {label}"));
    }

    Ok(analyze_ipc_graph_files(&files, label, query))
}
