use regex::Regex;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::smoke::run_cmd_with_timeout;

const NODE_PREAMBLE: &str = include_str!("harnesses/node_runtime.txt");
const PY_HARNESS: &str = include_str!("harnesses/py_runtime.txt");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeLang {
    Python,
    TypeScript,
    JavaScript,
    Rust,
    C,
}

fn js_import_regexes() -> &'static (Regex, Regex, Regex, Regex) {
    static RE: OnceLock<(Regex, Regex, Regex, Regex)> = OnceLock::new();
    RE.get_or_init(|| {
        let named = Regex::new(r#"(?m)^\s*import\s+\{([^}]+)\}\s+from\s+(['"])(\.[^'"]+)['"]\s*;?"#).unwrap();
        let ns = Regex::new(
            r#"(?m)^\s*import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+(['"])(\.[^'"]+)['"]\s*;?"#,
        )
        .unwrap();
        let def = Regex::new(
            r#"(?m)^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+(['"])(\.[^'"]+)['"]\s*;?"#,
        )
        .unwrap();
        let ty = Regex::new(r"(?m)^\s*import\s+type\s+[^;]+;?").unwrap();
        (named, ns, def, ty)
    })
}

fn which_ok(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn find_python(cwd: &Path) -> Option<String> {
    #[cfg(windows)]
    let cands = [
        cwd.join(".venv").join("Scripts").join("python.exe"),
        cwd.join("venv").join("Scripts").join("python.exe"),
    ];
    #[cfg(not(windows))]
    let cands = [
        cwd.join(".venv").join("bin").join("python"),
        cwd.join("venv").join("bin").join("python"),
    ];
    for c in cands {
        if c.is_file() {
            return Some(c.to_string_lossy().to_string());
        }
    }
    for b in ["python3", "python"] {
        if which_ok(b) {
            return Some(b.to_string());
        }
    }
    None
}

fn node_supports_strip_types() -> bool {
    let Ok(out) = Command::new("node").arg("-v").output() else {
        return false;
    };
    let s = String::from_utf8_lossy(&out.stdout);
    let major = s
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|m| m.parse::<u32>().ok())
        .unwrap_or(0);
    major >= 22
}

pub fn detect_lang(
    cwd: &Path,
    lang_flag: &str,
    focus: &str,
    code: Option<&str>,
    script: Option<&str>,
) -> ProbeLang {
    match lang_flag.trim().to_ascii_lowercase().as_str() {
        "py" | "python" => return ProbeLang::Python,
        "ts" | "typescript" => return ProbeLang::TypeScript,
        "js" | "javascript" | "mjs" => return ProbeLang::JavaScript,
        "rs" | "rust" => return ProbeLang::Rust,
        "c" => return ProbeLang::C,
        _ => {}
    }
    if let Some(sp) = script {
        match Path::new(sp)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "ts" | "tsx" | "mts" => return ProbeLang::TypeScript,
            "js" | "mjs" | "cjs" => return ProbeLang::JavaScript,
            "rs" => return ProbeLang::Rust,
            "c" => return ProbeLang::C,
            "py" => return ProbeLang::Python,
            _ => {}
        }
    }
    let src = code.unwrap_or("").trim();
    if src.contains("println!(") || src.contains("|x:") || src.contains("fn main()") {
        return ProbeLang::Rust;
    }
    if src.contains("#include <") {
        return ProbeLang::C;
    }
    if (src.contains("import ") && src.contains(" from "))
        || src.contains("=>")
        || src.contains("const ")
        || src.contains("let ")
    {
        let has_ts = src.contains(".ts")
            || cwd.join("tsconfig.json").is_file()
            || fs::read_dir(cwd.join("src"))
                .ok()
                .map(|mut rd| {
                    rd.any(|e| {
                        e.ok()
                            .and_then(|x| x.path().extension().map(|ext| ext == "ts"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
        return if has_ts {
            ProbeLang::TypeScript
        } else {
            ProbeLang::JavaScript
        };
    }
    if !focus.is_empty() && cwd.join("tsconfig.json").is_file() {
        return ProbeLang::TypeScript;
    }
    ProbeLang::Python
}

fn resolve_node_rel_spec(cwd: &Path, rel_mod: &str) -> String {
    if cwd.join(rel_mod).exists() {
        return rel_mod.to_string();
    }
    if let Some(stem) = rel_mod.strip_suffix(".js") {
        let ts_cand = format!("{stem}.ts");
        if cwd.join(&ts_cand).exists() {
            return ts_cand;
        }
    } else if Path::new(rel_mod).extension().is_none() {
        for ext in [".ts", ".mts", ".js", ".mjs"] {
            let cand = format!("{rel_mod}{ext}");
            if cwd.join(&cand).exists() {
                return cand;
            }
        }
    }
    rel_mod.to_string()
}

fn rewrite_js_imports(code: &str, cwd: &Path, wrap_calls: bool) -> String {
    let (named_re, ns_re, def_re, ty_re) = js_import_regexes();
    let stripped_ty = ty_re.replace_all(code, "").to_string();
    let mut counter = 0usize;

    let step1 = named_re
        .replace_all(&stripped_ty, |caps: &regex::Captures| {
            counter += 1;
            let ns = format!("__probe_ns_{counter}");
            let rel_mod = resolve_node_rel_spec(cwd, &caps[3]);
            let clean_mod = rel_mod.trim_start_matches("./");
            let mut stmts = vec![format!("const {ns} = await import(\"{rel_mod}\");")];
            for raw_sp in caps[1].split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if raw_sp.starts_with("type ") {
                    continue;
                }
                let (orig_n, local_n) = if let Some((a, b)) = raw_sp.split_once(" as ") {
                    (a.trim(), b.trim())
                } else {
                    (raw_sp, raw_sp)
                };
                if wrap_calls {
                    stmts.push(format!(
                        "const {local_n} = globalThis.__probeWrap({ns}.{orig_n}, \"{clean_mod}\", \"{orig_n}\");"
                    ));
                } else {
                    stmts.push(format!("const {local_n} = {ns}.{orig_n};"));
                }
            }
            stmts.join(" ")
        })
        .to_string();

    let step2 = ns_re
        .replace_all(&step1, |caps: &regex::Captures| {
            counter += 1;
            let raw_ns = format!("__probe_rawns_{counter}");
            let local_ns = &caps[1];
            let rel_mod = resolve_node_rel_spec(cwd, &caps[3]);
            let clean_mod = rel_mod.trim_start_matches("./");
            if wrap_calls {
                format!(
                    "const {raw_ns} = await import(\"{rel_mod}\"); const {local_ns} = Object.fromEntries(Object.entries({raw_ns}).map(([k, v]) => [k, globalThis.__probeWrap(v, \"{clean_mod}\", k)]));"
                )
            } else {
                format!("const {local_ns} = await import(\"{rel_mod}\");")
            }
        })
        .to_string();

    def_re
        .replace_all(&step2, |caps: &regex::Captures| {
            if &caps[1] == "type" {
                return String::new();
            }
            counter += 1;
            let ns = format!("__probe_def_{counter}");
            let local_n = &caps[1];
            let rel_mod = resolve_node_rel_spec(cwd, &caps[3]);
            let clean_mod = rel_mod.trim_start_matches("./");
            if wrap_calls {
                format!(
                    "const {ns} = await import(\"{rel_mod}\"); const {local_n} = globalThis.__probeWrap({ns}.default, \"{clean_mod}\", \"{local_n}\");"
                )
            } else {
                format!("const {ns} = await import(\"{rel_mod}\"); const {local_n} = {ns}.default;")
            }
        })
        .to_string()
}

fn run_py_bridge(cwd: &Path, req: &Value) -> Result<Value, String> {
    let Some(py) = find_python(cwd) else {
        return Err("Python interpreter not found on PATH for Python target tracing".to_string());
    };
    let payload = serde_json::to_string(req).unwrap_or_default();
    let mut cmd = Command::new(&py);
    cmd.args(["-c", PY_HARNESS]).current_dir(cwd);
    let out = run_cmd_with_timeout(&mut cmd, Duration::from_secs(15), Some(payload.as_bytes()))?;
    let stdout_s = String::from_utf8_lossy(&out.stdout);
    let last_json = stdout_s
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .unwrap_or("");
    if last_json.is_empty() {
        return Err(format!(
            "Python bridge failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    serde_json::from_str::<Value>(last_json).map_err(|e| e.to_string())
}

fn build_js_callable(expr: &str, vars_list: &[String]) -> String {
    let s = expr.trim();
    if s.contains("=>") || s.starts_with("function") || s.starts_with("async function") {
        return format!("({s})");
    }
    if s.contains('(') {
        if vars_list.len() > 1 {
            return format!("(({{ {} }}) => ({s}))", vars_list.join(", "));
        }
        let param = vars_list.first().map(String::as_str).unwrap_or("x");
        return format!("(({param}) => ({s}))");
    }
    format!("({s})")
}

fn clean_path(p: &Path) -> PathBuf {
    let canon = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = canon.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        if stripped.len() >= 2 && stripped.as_bytes()[1] == b':' {
            return PathBuf::from(stripped);
        }
    }
    canon
}

#[allow(clippy::too_many_arguments)]
pub fn run_trace_dispatch(
    cwd: &Path,
    lang: ProbeLang,
    focus: &str,
    code: Option<&str>,
    script: Option<&str>,
    unittest_target: Option<&str>,
    max_calls: usize,
    include_tests: bool,
    as_json: bool,
) -> i32 {
    let cwd_canon = clean_path(cwd);
    if unittest_target.is_some() || lang == ProbeLang::Python {
        let req = json!({
            "mode": "run",
            "cwd": cwd_canon.to_string_lossy(),
            "focus": focus,
            "code": code,
            "script": script,
            "unittest": unittest_target,
            "max_calls": max_calls,
            "include_tests": include_tests,
        });
        match run_py_bridge(&cwd_canon, &req) {
            Ok(data) => {
                let has_err = !data["exec_error"].is_null();
                if as_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&data).unwrap_or_default()
                    );
                    return if has_err { 1 } else { 0 };
                }
                let arr_str = |k: &str| -> Vec<String> {
                    data[k]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let alias = arr_str("alias_hazards");
                let muts = arr_str("mutation_alerts");
                let noops = arr_str("state_noop_alerts");
                let excs = arr_str("exceptions_observed");
                let tree = arr_str("call_tree");
                println!(
                    "[probe run] Traced {} call(s) in {} ms | alias_hazards={} | in_place_mutations={} | state_noops={}",
                    data["total_calls_traced"].as_u64().unwrap_or(0),
                    data["elapsed_ms"],
                    alias.len(),
                    muts.len(),
                    noops.len()
                );
                if let Some(err) = data["exec_error"].as_str() {
                    println!("[EXECUTION ERROR]: {err}");
                }
                if !alias.is_empty() {
                    println!("\n## !! [ALIAS HAZARD] Shared Mutable Nested Heap Objects");
                    for a in alias {
                        println!("- {a}");
                    }
                }
                if !muts.is_empty() {
                    println!(
                        "\n## !! [IN-PLACE MUTATION] Caller Argument / Shared State Mutations"
                    );
                    for m in muts {
                        println!("- {m}");
                    }
                }
                if !noops.is_empty() {
                    println!(
                        "\n## !! [STATE NO-OP] Void Mutator Methods That Left `self` Unchanged"
                    );
                    for n in noops {
                        println!("- {n}");
                    }
                }
                if !excs.is_empty() {
                    println!("\n## [EXCEPTIONS RAISED / CAUGHT]");
                    for e in excs.into_iter().take(10) {
                        println!("- {e}");
                    }
                }
                if !tree.is_empty() {
                    println!("\n## Causal Call Tree");
                    for ln in tree.into_iter().take(max_calls) {
                        println!("{ln}");
                    }
                }
                if let Some(so) = data["stdout"].as_str().filter(|s| !s.trim().is_empty()) {
                    println!("\n## Program Output\n{}", so.trim());
                }
                if has_err {
                    1
                } else {
                    0
                }
            }
            Err(e) => {
                eprintln!("[probe run] {e}");
                1
            }
        }
    } else if matches!(lang, ProbeLang::TypeScript | ProbeLang::JavaScript) {
        if !which_ok("node") {
            eprintln!("[probe run] Node.js (`node`) not found on PATH.");
            return 2;
        }
        let t0 = Instant::now();
        let raw_src = if let Some(sp) = script {
            fs::read_to_string(cwd_canon.join(sp)).unwrap_or_default()
        } else {
            code.unwrap_or("").to_string()
        };
        let instrumented = rewrite_js_imports(&raw_src, &cwd_canon, true);
        let ext = if lang == ProbeLang::TypeScript && node_supports_strip_types() {
            "mts"
        } else {
            "mjs"
        };
        let tmp_runner = cwd_canon.join(format!(".probe_runner_{}.{ext}", std::process::id()));
        let full_js = format!(
            "{NODE_PREAMBLE}\nlet __uncaught = null;\ntry {{\n{instrumented}\n}} catch (__e) {{\n  __uncaught = (__e && __e.stack) ? __e.stack : String(__e);\n}}\nconsole.log('__PROBE_JSON_START__');\nconsole.log(JSON.stringify({{events: __probeEvents, alias: __aliasHazards, mutation: __mutationAlerts, noop: __stateNoops, numeric: __numericHazards, uncaught: __uncaught}}));\n"
        );
        let _ = fs::write(&tmp_runner, &full_js);
        let mut node_args = vec!["--no-warnings".to_string()];
        if ext == "mts" {
            node_args.push("--experimental-strip-types".to_string());
        }
        node_args.push(tmp_runner.to_string_lossy().to_string());
        let out = Command::new("node")
            .args(&node_args)
            .current_dir(&cwd_canon)
            .output();
        let _ = fs::remove_file(&tmp_runner);

        let Ok(proc_out) = out else {
            eprintln!("[probe run] Failed to invoke node.");
            return 1;
        };
        let stdout_s = String::from_utf8_lossy(&proc_out.stdout);
        let Some((user_stdout, json_part)) = stdout_s.split_once("__PROBE_JSON_START__") else {
            eprintln!(
                "[probe run] Execution failed:\n{}{}",
                String::from_utf8_lossy(&proc_out.stderr),
                stdout_s
            );
            return 1;
        };
        let Ok(data) = serde_json::from_str::<Value>(json_part.trim()) else {
            eprintln!("[probe run] Failed to parse Node trace output.");
            return 1;
        };
        let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
        let mode_str = if lang == ProbeLang::TypeScript {
            "ts"
        } else {
            "js"
        };
        let has_uncaught = !data["uncaught"].is_null();
        let payload = json!({
            "language": mode_str,
            "elapsed_ms": elapsed_ms,
            "alias_hazards": data["alias"],
            "mutation_alerts": data["mutation"],
            "state_noop_alerts": data["noop"],
            "numeric_hazards": data["numeric"],
            "uncaught_exception": data["uncaught"],
            "events": data["events"],
            "stdout": user_stdout.trim(),
        });
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
            return if has_uncaught { 1 } else { 0 };
        }
        let ev_n = data["events"].as_array().map(|a| a.len()).unwrap_or(0);
        println!(
            "[probe run ({})] {ev_n} distinct call site(s) traced in {elapsed_ms} ms",
            mode_str.to_uppercase()
        );
        for (title, key) in [
            ("!! [ALIAS HAZARD]", "alias"),
            ("!! [IN-PLACE MUTATION]", "mutation"),
            ("!! [STATE NO-OP]", "noop"),
            ("!! [JS NUMERIC HAZARD]", "numeric"),
        ] {
            if let Some(arr) = data[key].as_array().filter(|a| !a.is_empty()) {
                println!("\n## {title}");
                for it in arr {
                    if let Some(s) = it.as_str() {
                        println!("- {s}");
                    }
                }
            }
        }
        if let Some(u) = data["uncaught"].as_str() {
            println!(
                "\n## !! Uncaught Exception\n{}",
                u.lines().next().unwrap_or(u)
            );
        }
        if !user_stdout.trim().is_empty() {
            println!("\n## Captured Stdout\n{}", user_stdout.trim());
        }
        if has_uncaught {
            1
        } else {
            0
        }
    } else {
        // Native Rust snippet runner (`rustc`)
        if !which_ok("rustc") {
            eprintln!("[probe run (RUST)] `rustc` not found on PATH.");
            return 2;
        }
        let t0 = Instant::now();
        let snippet = code.unwrap_or("");
        let wrapped = if snippet.contains("fn main") {
            snippet.to_string()
        } else {
            format!("fn main() {{\n{snippet}\n}}\n")
        };
        let tmp_dir = std::env::temp_dir().join(format!("ap_probe_rs_{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp_dir);
        let src_p = tmp_dir.join("probe_snip.rs");
        let bin_p = tmp_dir.join(if cfg!(windows) {
            "probe_snip.exe"
        } else {
            "probe_snip"
        });
        let _ = fs::write(&src_p, wrapped);
        let comp = Command::new("rustc")
            .arg(&src_p)
            .arg("-o")
            .arg(&bin_p)
            .output();
        let Ok(c_out) = comp else {
            let _ = fs::remove_dir_all(&tmp_dir);
            return 1;
        };
        if !c_out.status.success() {
            eprintln!(
                "[probe run (RUST)] compile error:\n{}",
                String::from_utf8_lossy(&c_out.stderr)
            );
            let _ = fs::remove_dir_all(&tmp_dir);
            return 1;
        }
        let run_out = Command::new(&bin_p).current_dir(&cwd_canon).output();
        let _ = fs::remove_dir_all(&tmp_dir);
        let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
        let Ok(ro) = run_out else { return 1 };
        let so = String::from_utf8_lossy(&ro.stdout).trim().to_string();
        let se = String::from_utf8_lossy(&ro.stderr).trim().to_string();
        let ok = ro.status.success();
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "language": "rust",
                    "ok": ok,
                    "elapsed_ms": elapsed_ms,
                    "stdout": so,
                    "stderr": se,
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "[probe run (RUST)] exit={} in {elapsed_ms} ms",
                ro.status.code().unwrap_or(1)
            );
            if !so.is_empty() {
                println!("{so}");
            }
            if !se.is_empty() {
                eprintln!("{se}");
            }
        }
        if ok {
            0
        } else {
            1
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_diff_dispatch(
    cwd: &Path,
    lang: ProbeLang,
    setup: &str,
    fn_a: &str,
    fn_b: &str,
    vars_csv: &str,
    inputs_expr: &str,
    as_json: bool,
) -> i32 {
    let cwd_canon = clean_path(cwd);
    if lang == ProbeLang::Rust {
        if !which_ok("rustc") {
            eprintln!("[probe diff (RUST)] `rustc` not found on PATH.");
            return 2;
        }
        let t0 = Instant::now();
        let corpus_expr = if inputs_expr.trim().is_empty() {
            "vec![0_i64, -1, 1, 2, -2, 100, -100, 9999, -9999, 10005, -10005, i32::MAX as i64, i32::MIN as i64]"
        } else {
            inputs_expr.trim()
        };
        let rs_src = format!(
            "{setup}\nfn main() {{\n  let fa = {fn_a};\n  let fb = {fn_b};\n  let corpus = {corpus_expr};\n  let mut divs = Vec::new();\n  for x in &corpus {{\n    let ra = fa(x.clone());\n    let rb = fb(x.clone());\n    if format!(\"{{:?}}\", ra) != format!(\"{{:?}}\", rb) {{\n      divs.push(format!(\"input={{:?}} => fn_a={{:?}} != fn_b={{:?}}\", x, ra, rb));\n    }}\n  }}\n  println!(\"CASES={{}}\", corpus.len());\n  for d in divs {{ println!(\"DIV={{}}\", d); }}\n}}\n"
        );
        let tmp_dir = std::env::temp_dir().join(format!("ap_diff_rs_{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp_dir);
        let src_p = tmp_dir.join("diff_probe.rs");
        let bin_p = tmp_dir.join(if cfg!(windows) {
            "diff_probe.exe"
        } else {
            "diff_probe"
        });
        let _ = fs::write(&src_p, rs_src);
        let comp = Command::new("rustc")
            .arg(&src_p)
            .arg("-o")
            .arg(&bin_p)
            .output();
        let Ok(c_out) = comp else {
            let _ = fs::remove_dir_all(&tmp_dir);
            return 2;
        };
        if !c_out.status.success() {
            eprintln!(
                "[probe diff (RUST)] compile error:\n{}",
                String::from_utf8_lossy(&c_out.stderr)
            );
            let _ = fs::remove_dir_all(&tmp_dir);
            return 2;
        }
        let mut bin_cmd = Command::new(&bin_p);
        bin_cmd.current_dir(&cwd_canon);
        let ro = run_cmd_with_timeout(&mut bin_cmd, Duration::from_secs(10), None);
        let _ = fs::remove_dir_all(&tmp_dir);
        let run_o = match ro {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[probe diff (RUST)] {e}");
                return 2;
            }
        };
        let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
        let out_s = String::from_utf8_lossy(&run_o.stdout);
        let mut cases = 0usize;
        let mut divs = Vec::new();
        for ln in out_s.lines() {
            if let Some(c) = ln.strip_prefix("CASES=") {
                cases = c.parse().unwrap_or(0);
            } else if let Some(d) = ln.strip_prefix("DIV=") {
                divs.push(d.to_string());
            }
        }
        let clean = divs.is_empty();
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "language": "rust",
                    "elapsed_ms": elapsed_ms,
                    "cases_tested": cases,
                    "equivalent": clean,
                    "divergences": divs,
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "[probe diff (RUST)] {} across {cases} inputs in {elapsed_ms} ms (divergences={})",
                if clean {
                    "EQUIVALENT (0 counterexamples)"
                } else {
                    "DIVERGENCE DETECTED"
                },
                divs.len()
            );
            for d in &divs {
                println!("- {d}");
            }
        }
        return if clean { 0 } else { 1 };
    }

    if matches!(lang, ProbeLang::TypeScript | ProbeLang::JavaScript) {
        if !which_ok("node") {
            eprintln!("[probe diff] Node.js (`node`) not found on PATH.");
            return 2;
        }
        let t0 = Instant::now();
        let vars_list: Vec<String> = vars_csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        let fn_a_js = build_js_callable(fn_a, &vars_list);
        let fn_b_js = build_js_callable(fn_b, &vars_list);
        let rewritten_setup = if setup.contains("import ") {
            rewrite_js_imports(setup, &cwd_canon, false)
        } else {
            setup.to_string()
        };
        let ext = if lang == ProbeLang::TypeScript && node_supports_strip_types() {
            "mts"
        } else {
            "mjs"
        };
        let tmp_runner = cwd_canon.join(format!(".probe_diff_{}.{ext}", std::process::id()));
        let has_inputs = !inputs_expr.trim().is_empty();
        let inputs_js = if has_inputs { inputs_expr } else { "[]" };
        let vars_json = serde_json::to_string(&vars_list).unwrap_or_else(|_| "[]".to_string());
        let js_src = format!(
            r#"{rewritten_setup}
const __fnA = {fn_a_js};
const __fnB = {fn_b_js};
function __snap(v, d = 0) {{
  if (v === null || v === undefined) return {{ t: String(v) }};
  if (typeof v === "number") return Number.isNaN(v) ? {{ t: "NaN" }} : Object.is(v, -0) ? {{ t: "-0" }} : {{ t: "num", v }};
  if (typeof v !== "object" || d > 5) return {{ t: typeof v, v: String(v) }};
  if (Array.isArray(v)) return {{ t: "arr", v: v.map(x => __snap(x, d + 1)) }};
  const o = {{}};
  for (const k of Object.keys(v).sort()) o[k] = __snap(v[k], d + 1);
  return {{ t: "obj", o }};
}}
function __clone(v) {{
  if (v === undefined || v === null || typeof v !== "object") return v;
  try {{ return structuredClone(v); }} catch {{
    try {{ return JSON.parse(JSON.stringify(v)); }} catch {{
      return Array.isArray(v) ? [...v] : {{ ...v }};
    }}
  }}
}}
function __call(fn, x) {{
  try {{ return {{ ok: true, s: __snap(fn(x)) }}; }}
  catch (e) {{ return {{ ok: false, err: (e && e.name ? e.name : "Error") }}; }}
}}
const __atoms = [null, undefined, false, true, 0, -0, 1, -1, -100.5, 100.5, "", "0"];
const __vars = {vars_json};
let __corpus = [];
if ({has_inputs}) {{
  __corpus = ({inputs_js});
}} else if (__vars.length > 0) {{
  for (const a of __atoms) {{
    const base = {{}};
    for (const k of __vars) base[k] = 0;
    base[__vars[0]] = a;
    __corpus.push(base);
  }}
}} else {{
  __corpus = [...__atoms, [], {{}}];
}}
const __divs = [], __muts = [], __drifts = [];
for (const item of __corpus) {{
  const inA = __clone(item), inB = __clone(item), beforeSnap = JSON.stringify(__snap(item));
  const rA = __call(__fnA, inA), rB = __call(__fnB, inB);
  if (JSON.stringify(rA) !== JSON.stringify(rB)) __divs.push({{ input: JSON.stringify(__snap(item)), a: JSON.stringify(rA), b: JSON.stringify(rB) }});
  if (JSON.stringify(__snap(inA)) !== beforeSnap) __muts.push({{ input: JSON.stringify(__snap(item)), mutated_by: "fn_a" }});
  if (JSON.stringify(__snap(inB)) !== beforeSnap) __muts.push({{ input: JSON.stringify(__snap(item)), mutated_by: "fn_b" }});
  const rA2 = __call(__fnA, __clone(item));
  if (JSON.stringify(rA) !== JSON.stringify(rA2)) __drifts.push({{ target: "fn_a", input: JSON.stringify(__snap(item)), fresh: JSON.stringify(rA), sequential: JSON.stringify(rA2) }});
}}
console.log("__PROBE_DIFF_JSON__");
console.log(JSON.stringify({{ cases: __corpus.length, divs: __divs, muts: __muts, drifts: __drifts }}));
"#
        );
        let _ = fs::write(&tmp_runner, js_src);
        let mut node_args = vec!["--no-warnings".to_string()];
        if ext == "mts" {
            node_args.push("--experimental-strip-types".to_string());
        }
        node_args.push(tmp_runner.to_string_lossy().to_string());
        let mut node_cmd = Command::new("node");
        node_cmd.args(&node_args).current_dir(&cwd_canon);
        let out = run_cmd_with_timeout(&mut node_cmd, Duration::from_secs(15), None);
        let _ = fs::remove_file(&tmp_runner);
        let proc_out = match out {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[probe diff] {e}");
                return 2;
            }
        };
        let stdout_s = String::from_utf8_lossy(&proc_out.stdout);
        let Some((_, jpart)) = stdout_s.split_once("__PROBE_DIFF_JSON__") else {
            eprintln!(
                "[probe diff] Execution failed:\n{}",
                String::from_utf8_lossy(&proc_out.stderr)
            );
            return 2;
        };
        let Ok(res) = serde_json::from_str::<Value>(jpart.trim()) else {
            return 2;
        };
        let divs = res["divs"].as_array().cloned().unwrap_or_default();
        let drifts = res["drifts"].as_array().cloned().unwrap_or_default();
        let muts = res["muts"].as_array().cloned().unwrap_or_default();
        let clean = divs.is_empty() && drifts.is_empty() && muts.is_empty();
        let elapsed_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
        let mode_str = if lang == ProbeLang::TypeScript {
            "ts"
        } else {
            "js"
        };
        let payload = json!({
            "language": mode_str,
            "elapsed_ms": elapsed_ms,
            "cases_tested": res["cases"],
            "equivalent": clean,
            "divergences": divs,
            "stateful_cache_drifts": drifts,
            "caller_input_mutations": muts,
        });
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
        } else {
            println!(
                "[probe diff ({})] {} across {} boundary inputs in {elapsed_ms} ms (divergences={}, stateful_drifts={}, input_mutations={})",
                mode_str.to_uppercase(),
                if clean { "EQUIVALENT (0 counterexamples)" } else { "DIVERGENCE DETECTED" },
                res["cases"],
                divs.len(),
                drifts.len(),
                muts.len()
            );
            for d in divs.iter().take(8) {
                println!(
                    "- DIVERGENCE input={} => fn_a={} != fn_b={}",
                    d["input"], d["a"], d["b"]
                );
            }
        }
        return if clean { 0 } else { 1 };
    }

    // Python differential oracle
    let req = json!({
        "mode": "diff",
        "cwd": cwd_canon.to_string_lossy(),
        "setup": setup,
        "fn_a": fn_a,
        "fn_b": fn_b,
        "vars": vars_csv,
        "inputs": inputs_expr,
    });
    match run_py_bridge(&cwd_canon, &req) {
        Ok(data) => {
            let clean = data["equivalent"].as_bool().unwrap_or(false);
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_default()
                );
                return if clean { 0 } else { 1 };
            }
            let divs = data["divergences"].as_array().cloned().unwrap_or_default();
            let drifts = data["stateful_cache_drifts"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let muts = data["caller_input_mutations"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            println!(
                "[probe diff] {} across {} boundary/sequence inputs in {} ms (divergences={}, stateful_drifts={}, input_mutations={})",
                if clean { "EQUIVALENT (0 counterexamples)" } else { "DIVERGENCE DETECTED" },
                data["cases_tested"],
                data["elapsed_ms"],
                divs.len(),
                drifts.len(),
                muts.len()
            );
            for d in divs.iter().take(8) {
                println!(
                    "- input={} => fn_a: {} != fn_b: {}",
                    d["input"].as_str().unwrap_or(""),
                    d["a"].as_str().unwrap_or(""),
                    d["b"].as_str().unwrap_or("")
                );
            }
            for s in drifts.iter().take(8) {
                println!(
                    "- [{}] input={} => fresh: {} != sequential: {}",
                    s["target"].as_str().unwrap_or(""),
                    s["input"].as_str().unwrap_or(""),
                    s["fresh"].as_str().unwrap_or(""),
                    s["sequential"].as_str().unwrap_or("")
                );
            }
            if clean {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("[probe diff] {e}");
            1
        }
    }
}
