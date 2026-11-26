use crate::cdp::CdpSession;
use crate::smoke::{
    auto_detect_start_cmd, find_headless_browser, http_request, kill_process_tree, pick_free_port,
    spawn_detached_logged_server,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiViewportReport {
    pub viewport: String,
    pub visible_controls: u64,
    pub text_len: u64,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiAuditReport {
    pub ok: bool,
    pub url: String,
    pub elapsed_ms: f64,
    pub viewports: Vec<UiViewportReport>,
    pub js_errors: Vec<String>,
    pub network_errors: Vec<String>,
    pub screenshot: Option<String>,
}

pub fn run_ui_audit(
    cwd: &Path,
    start_opt: Option<&str>,
    url_opt: Option<&str>,
    page_path: &str,
    mobile: bool,
    screenshot_opt: Option<&Path>,
    as_json: bool,
) -> i32 {
    let t0 = Instant::now();
    let Some(browser) = find_headless_browser() else {
        eprintln!("[probe ui] No local Edge/Chrome/Chromium binary found.");
        return 2;
    };

    let mut child_opt: Option<Child> = None;
    let mut _child_job: Option<crate::smoke::ProbeJobGuard> = None;
    let pid = std::process::id();
    let out_f = std::env::temp_dir().join(format!("ap_ui_{pid}.out.log"));
    let err_f = std::env::temp_dir().join(format!("ap_ui_{pid}.err.log"));

    let base_url = if let Some(u) = url_opt.filter(|s| !s.trim().is_empty()) {
        u.trim_end_matches('/').to_string()
    } else {
        let Some(sc) = start_opt
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .or_else(|| auto_detect_start_cmd(cwd))
        else {
            let msg = "[probe ui] Provide --start \"<cmd>\" or --url http://127.0.0.1:<port>";
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({ "ok": false, "error": msg }))
                        .unwrap_or_default()
                );
            } else {
                eprintln!("{msg}");
            }
            return 2;
        };
        let Ok(port) = pick_free_port() else {
            return 2;
        };
        match spawn_detached_logged_server(&sc, cwd, port, &[], &out_f, &err_f) {
            Ok(ch) => {
                _child_job = crate::smoke::ProbeJobGuard::attach(&ch);
                child_opt = Some(ch);
            }
            Err(e) => {
                let msg = format!("[probe ui] {e}");
                if as_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({ "ok": false, "error": msg })
                        )
                        .unwrap_or_default()
                    );
                } else {
                    eprintln!("{msg}");
                }
                return 1;
            }
        }
        format!("http://127.0.0.1:{port}")
    };

    let target_path = if page_path.starts_with('/') {
        page_path.to_string()
    } else {
        format!("/{page_path}")
    };
    let deadline = Instant::now() + Duration::from_millis(9000);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Ok((st, _, _)) = http_request(&base_url, "GET", &target_path, &[], None, 600) {
            if st > 0 && st < 500 {
                ready = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(60));
    }

    let full_url = format!("{base_url}{target_path}");
    let mut vp_reports = Vec::new();
    let mut js_errors = Vec::new();
    let mut net_errors = Vec::new();
    let mut shot_saved = None;

    if !ready {
        net_errors.push(format!("Server did not become reachable at {full_url}"));
    } else {
        match CdpSession::launch(&browser) {
            Ok(mut cdp) => {
                if let Err(e) = cdp.navigate(&full_url) {
                    js_errors.push(format!("navigate failed: {e}"));
                } else {
                    let mut sizes = vec![(1280u32, 800u32)];
                    if mobile {
                        sizes.push((390u32, 844u32));
                    }
                    for (idx, (w, h)) in sizes.into_iter().enumerate() {
                        match cdp.audit_layout(w, h) {
                            Ok(v) => {
                                let issues: Vec<String> = v
                                    .get("issues")
                                    .and_then(Value::as_array)
                                    .map(|a| {
                                        a.iter()
                                            .filter_map(Value::as_str)
                                            .map(String::from)
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                vp_reports.push(UiViewportReport {
                                    viewport: format!("{w}x{h}"),
                                    visible_controls: v
                                        .get("visibleCtrls")
                                        .and_then(Value::as_u64)
                                        .unwrap_or(0),
                                    text_len: v.get("textLen").and_then(Value::as_u64).unwrap_or(0),
                                    issues,
                                });
                            }
                            Err(e) => {
                                js_errors.push(format!("audit_layout({w}x{h}) error: {e}"));
                            }
                        }
                        if idx == 0 {
                            if let Some(sp) = screenshot_opt {
                                let full_sp = if sp.is_absolute() {
                                    sp.to_path_buf()
                                } else {
                                    cwd.join(sp)
                                };
                                if cdp.capture_screenshot(&full_sp).is_ok() {
                                    shot_saved = Some(full_sp.to_string_lossy().replace('\\', "/"));
                                }
                            }
                        }
                    }
                }
                js_errors.extend(cdp.js_errors.clone());
                net_errors.extend(cdp.network_errors.clone());
            }
            Err(e) => js_errors.push(format!("CDP launch failed: {e}")),
        }
    }

    if let Some(mut ch) = child_opt {
        kill_process_tree(&mut ch);
    }
    let _ = fs::remove_file(&out_f);
    let _ = fs::remove_file(&err_f);

    let layout_issue_cnt: usize = vp_reports.iter().map(|v| v.issues.len()).sum();
    let ok = ready && layout_issue_cnt == 0 && js_errors.is_empty() && net_errors.is_empty();
    let rep = UiAuditReport {
        ok,
        url: full_url,
        elapsed_ms: (t0.elapsed().as_secs_f64() * 1000.0).round(),
        viewports: vp_reports,
        js_errors,
        network_errors: net_errors,
        screenshot: shot_saved,
    };

    if as_json {
        println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
    } else if rep.ok {
        let vps: Vec<String> = rep
            .viewports
            .iter()
            .map(|v| format!("{} ({} ctrls)", v.viewport, v.visible_controls))
            .collect();
        println!(
            "[probe ui] PASS — 0 JS/network errors, 0 layout/overlap/image defects across [{}] in {}ms",
            vps.join(", "),
            rep.elapsed_ms
        );
    } else {
        println!(
            "[probe ui] FAIL — visual/runtime UI defects detected at `{}` in {}ms:",
            rep.url, rep.elapsed_ms
        );
        for v in &rep.viewports {
            for iss in &v.issues {
                println!("  - [layout {}] {iss}", v.viewport);
            }
        }
        for je in &rep.js_errors {
            println!("  - [js] {je}");
        }
        for ne in &rep.network_errors {
            println!("  - [network] {ne}");
        }
    }
    if rep.ok {
        0
    } else {
        1
    }
}
