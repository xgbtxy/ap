use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn looks_like_guid_prefix(s: &str) -> bool {
    let trimmed = s.strip_prefix('{').unwrap_or(s);
    let b = trimmed.as_bytes();
    // Standard 8-4-4-4-12 UUID prefix (36 chars)
    if b.len() >= 36
        && b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && b[..36]
            .iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit())
    {
        return true;
    }
    // Pure hex handle/UUID >= 24 chars (e.g. random IPC channel IDs)
    b.len() >= 24 && b[..24].iter().all(|c| c.is_ascii_hexdigit())
}

/// Identifies noisy browser/runtime GUID, Mojo, Crashpad, or libuv ephemeral pipe names so
/// custom application named pipes are prioritized before noise when capped by `--max`.
pub fn is_noisy_guid_or_mojo_pipe(nm_low: &str) -> bool {
    let tail = nm_low.strip_prefix("local\\").unwrap_or(nm_low);
    tail.starts_with("mojo.")
        || tail.starts_with("crashpad_")
        || tail.starts_with("chrome.")
        || tail.starts_with("msedge.")
        || tail.starts_with("uv\\")
        || tail.starts_with("uv.")
        || tail.contains(".mojo.")
        || looks_like_guid_prefix(tail)
}

pub fn sort_pipe_names_by_signal(names: &mut [String]) {
    names.sort_by(|a, b| {
        let al = a.to_ascii_lowercase();
        let bl = b.to_ascii_lowercase();
        is_noisy_guid_or_mojo_pipe(&al)
            .cmp(&is_noisy_guid_or_mojo_pipe(&bl))
            .then_with(|| al.cmp(&bl))
    });
}

/// Renders compact, readable multi-line text for `ap probe win` when `--json` is omitted.
pub fn format_win_human(val: &Value) -> String {
    let mode = val.get("mode").and_then(Value::as_str).unwrap_or("");
    let ok = val.get("ok").and_then(Value::as_bool).unwrap_or(false);
    if !ok {
        let err = val
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("win probe failed");
        return format!("[ap probe win] error: {err}");
    }
    match mode {
        "pipes" => {
            let returned = val.get("returned").and_then(Value::as_u64).unwrap_or(0);
            let total = val
                .get("total_matched")
                .and_then(Value::as_u64)
                .unwrap_or(returned);
            let arr = val
                .get("pipes")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let weak_cnt = arr
                .iter()
                .filter(|p| p["non_admin_write"].as_bool().unwrap_or(false))
                .count();
            let mut out = format!(
                "# WIN PIPES [returned={returned} of {total} matched | weak_dacl={weak_cnt}]\n"
            );
            for p in arr {
                let path = p["pipe"]
                    .as_str()
                    .unwrap_or(p["name"].as_str().unwrap_or(""));
                let weak = p["non_admin_write"].as_bool().unwrap_or(false);
                let sig = p["signal"].as_str().unwrap_or("");
                let srv = p["server_process"].as_str().unwrap_or("");
                let il = p["server_il"].as_str().unwrap_or("");
                let pid = p["server_pid"].as_u64();
                let mut tags = Vec::new();
                if weak {
                    let aces: Vec<&str> = p["weak_dacl"]
                        .as_array()
                        .map(|a| a.iter().filter_map(Value::as_str).collect())
                        .unwrap_or_default();
                    tags.push(format!("WEAK_DACL({})", aces.join(",")));
                }
                if !sig.is_empty() {
                    tags.push(sig.to_string());
                }
                if let Some(pid_v) = pid {
                    if !srv.is_empty() {
                        tags.push(format!("pid={pid_v} {srv} {il}").trim().to_string());
                    } else {
                        tags.push(format!("pid={pid_v} {il}").trim().to_string());
                    }
                }
                if tags.is_empty() {
                    out.push_str(&format!("- {path}\n"));
                } else {
                    out.push_str(&format!("- {path} [{}]\n", tags.join(" | ")));
                }
            }
            out.trim_end().to_string()
        }
        "services" => {
            let arr = val
                .get("services")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut out = format!("# WIN SERVICES [returned={}]\n", arr.len());
            for s in arr {
                let nm = s["name"].as_str().unwrap_or("");
                let state = s["state"].as_str().unwrap_or("");
                let acct = s["account"].as_str().unwrap_or("");
                let bin = s["bin_path"].as_str().unwrap_or("");
                out.push_str(&format!("- {nm} [{state}] ({acct}) {bin}\n"));
            }
            out.trim_end().to_string()
        }
        "unquoted" => {
            let arr = val
                .get("findings")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut out = format!("# WIN UNQUOTED SERVICES [findings={}]\n", arr.len());
            for f in arr {
                let nm = f["service"].as_str().unwrap_or("");
                let exp = f["exploitable"].as_bool().unwrap_or(false);
                let bin = f["bin_path"].as_str().unwrap_or("");
                out.push_str(&format!("- {nm} [exploitable={exp}] {bin}\n"));
            }
            out.trim_end().to_string()
        }
        "procs" => {
            let arr = val
                .get("processes")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut out = format!("# WIN PROCS [returned={}]\n", arr.len());
            for p in arr {
                let pid = p["pid"].as_u64().unwrap_or(0);
                let il = p["integrity_level"].as_str().unwrap_or("?");
                let sess = p["session_id"].as_u64().unwrap_or(0);
                let name = p["name"].as_str().unwrap_or("");
                out.push_str(&format!("- pid={pid} il={il} sess={sess} {name}\n"));
            }
            out.trim_end().to_string()
        }
        _ => serde_json::to_string_pretty(val).unwrap_or_default(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AceEntry {
    pub ace_type: String,
    pub flags: String,
    pub rights: String,
    pub trustee: String,
    pub non_admin_write: bool,
}

const WEAK_TRUSTEES: &[&str] = &[
    "WD",
    "AU",
    "BU",
    "IU",
    "AN",
    "DU",
    "S-1-1-0",
    "S-1-5-11",
    "S-1-5-32-545",
];

const WRITE_RIGHTS: &[&str] = &["GA", "GW", "FA", "FW", "WD", "WO", "WP", "DC"];

/// Parses an SDDL DACL string into `(dacl_protected, Vec<AceEntry>)`, flagging non-admin write ACEs.
pub fn parse_sddl_aces(sddl: &str) -> (bool, Vec<AceEntry>) {
    let mut aces = Vec::new();
    let Some(d_pos) = sddl.find("D:") else {
        return (false, aces);
    };
    let after_d = &sddl[d_pos + 2..];
    let dacl_slice = match after_d.find("S:") {
        Some(s_pos) => &after_d[..s_pos],
        None => after_d,
    };
    let header = dacl_slice.split('(').next().unwrap_or("");
    let protected = header.contains('P');

    let mut rest = dacl_slice;
    while let Some(open) = rest.find('(') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find(')') else {
            break;
        };
        let body = &after_open[..close];
        rest = &after_open[close + 1..];
        let parts: Vec<&str> = body.split(';').collect();
        if parts.len() < 6 {
            continue;
        }
        let ace_type = parts[0].trim().to_string();
        let flags = parts[1].trim().to_string();
        let rights = parts[2].trim().to_string();
        let trustee = parts[5].trim().to_string();
        let t_up = trustee.to_ascii_uppercase();
        let is_allow = ace_type.eq_ignore_ascii_case("A");
        let is_weak_trustee = WEAK_TRUSTEES.iter().any(|w| t_up == *w);
        let has_write = WRITE_RIGHTS.iter().any(|r| rights.contains(r));
        aces.push(AceEntry {
            ace_type,
            flags,
            rights,
            trustee,
            non_admin_write: is_allow && is_weak_trustee && has_write,
        });
    }
    (protected, aces)
}

/// Extracts the normalized executable path from a Windows service `ImagePath` / `lpBinaryPathName`.
pub fn extract_service_exe_path(bin_path: &str) -> String {
    let s = bin_path.trim();
    if s.is_empty() {
        return String::new();
    }
    let clean = if let Some(rest) = s.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").trim().to_string()
    } else if let Some(rest) = s.strip_prefix('\'') {
        rest.split('\'').next().unwrap_or("").trim().to_string()
    } else {
        let low = s.to_ascii_lowercase();
        let mut matched_end: Option<usize> = None;
        for ext in [".exe", ".sys", ".dll", ".bat", ".cmd"] {
            if let Some(pos) = low.find(ext) {
                let candidate_end = pos + ext.len();
                let next_ch = s.as_bytes().get(candidate_end).copied();
                if next_ch.is_none() || next_ch == Some(b' ') || next_ch == Some(b'\t') {
                    matched_end = Some(candidate_end);
                    break;
                }
            }
        }
        match matched_end {
            Some(end) => s[..end].trim().to_string(),
            None => s.split_whitespace().next().unwrap_or("").to_string(),
        }
    };
    let unprefixed = clean
        .strip_prefix(r"\??\")
        .or_else(|| clean.strip_prefix(r"\\?\"))
        .unwrap_or(&clean);
    let low = unprefixed.to_ascii_lowercase();
    if let Some(rest) = low.strip_prefix(r"\systemroot\") {
        let orig_rest = &unprefixed[r"\systemroot\".len()..];
        let _ = rest;
        return format!(r"C:\Windows\{orig_rest}");
    }
    if low.starts_with(r"system32\") {
        return format!(r"C:\Windows\{unprefixed}");
    }
    if low.starts_with("%systemroot%") {
        let orig_rest = &unprefixed["%systemroot%".len()..];
        return format!(r"C:\Windows{orig_rest}");
    }
    unprefixed.to_string()
}

/// Returns candidate Windows binary hijack paths (`C:\Program.exe`, etc.) for an unquoted `ImagePath`
/// containing spaces before `.exe`. Empty if the path is properly quoted or contains no spaces.
pub fn find_unquoted_space_prefixes(bin_path: &str) -> Vec<(String, String)> {
    let trimmed = bin_path.trim();
    if trimmed.is_empty() || trimmed.starts_with('"') || trimmed.starts_with('\'') {
        return Vec::new();
    }
    let exe = extract_service_exe_path(trimmed);
    if exe.is_empty() || !exe.contains(' ') {
        return Vec::new();
    }
    let norm_exe = exe.replace('/', "\\");
    let low = norm_exe.to_ascii_lowercase();
    if low.starts_with(r"c:\windows\system32\") || low.starts_with(r"c:\windows\syswow64\") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (idx, ch) in norm_exe.char_indices() {
        if ch == ' ' && idx > 2 {
            let prefix = &norm_exe[..idx];
            if prefix.contains('\\') {
                let cand = format!("{prefix}.exe");
                let parent = std::path::Path::new(&cand)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                if !parent.is_empty() {
                    out.push((cand, parent));
                }
            }
        }
    }
    out
}

/// Resolve bare system DLL names (`combase.dll`, `ole32.dll`) and common Windows env-var prefixes
/// into concrete filesystem paths so `--com` does not emit false `missing_target` warnings.
pub fn resolve_windows_exe_candidate(raw_exe: &str) -> String {
    let trimmed = raw_exe.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let low = trimmed.to_ascii_lowercase();
    let expanded = if low.starts_with("%systemroot%") {
        format!(r"C:\Windows{}", &trimmed["%systemroot%".len()..])
    } else if low.starts_with("%windir%") {
        format!(r"C:\Windows{}", &trimmed["%windir%".len()..])
    } else if low.starts_with("%programfiles(x86)%") {
        format!(
            r"C:\Program Files (x86){}",
            &trimmed["%programfiles(x86)%".len()..]
        )
    } else if low.starts_with("%programfiles%") {
        format!(r"C:\Program Files{}", &trimmed["%programfiles%".len()..])
    } else if low.starts_with("%programdata%") {
        format!(r"C:\ProgramData{}", &trimmed["%programdata%".len()..])
    } else {
        trimmed.to_string()
    };
    if !expanded.contains('\\') && !expanded.contains('/') && !expanded.contains('%') {
        let sys32 = format!(r"C:\Windows\System32\{expanded}");
        if std::path::Path::new(&sys32).exists() {
            return sys32;
        }
        let syswow = format!(r"C:\Windows\SysWOW64\{expanded}");
        if std::path::Path::new(&syswow).exists() {
            return syswow;
        }
    }
    expanded
}

pub(crate) fn is_ms_os_pipe(name_low: &str) -> bool {
    let short = name_low
        .trim_start_matches(r"\\.\pipe\")
        .trim_start_matches(r"\pipe\");
    if matches!(
        short,
        "lsass"
            | "initshutdown"
            | "srvsvc"
            | "wkssvc"
            | "ntsvcs"
            | "scerpc"
            | "spoolss"
            | "winreg"
            | "efsrpc"
            | "atsvc"
            | "trkwks"
            | "epmapper"
            | "eventlog"
            | "samr"
            | "netlogon"
            | "svcctl"
            | "browser"
            | "plugplay"
            | "umpnpmgr"
            | "wininit"
            | "w32time"
            | "w32time_alt"
            | "dnsserver"
            | "dhcpserver"
            | "protected_storage"
            | "router"
            | "netdfs"
            | "lsarpc"
            | "llsrpc"
            | "keysvc"
            | "cryptsvc"
            | "iphlpsvc"
            | "tapsrv"
            | "seclogon"
            | "audiosrv"
            | "aelookupsvc"
            | "cert"
            | "nla"
            | "p2pimsvc"
    ) {
        return true;
    }
    short.starts_with("winsock2\\")
        || short.starts_with("w32time")
        || short.starts_with("hydra")
        || short.starts_with("ts_")
        || short.starts_with("termsrv")
        || short.starts_with("protectedprefix\\")
        || short.starts_with("sessenv")
        || short.starts_with("pipe_eventroot\\")
        || short.starts_with("pshost.")
        || short.starts_with("msdtc")
        || short.starts_with("msft_")
        || short.starts_with("windows_")
}

pub(crate) fn is_ms_os_path(path_low: &str) -> bool {
    path_low.starts_with(r"c:\windows\system32\")
        || path_low.starts_with(r"c:\windows\syswow64\")
        || path_low.starts_with(r"c:\windows\winsxs\")
        || path_low.starts_with(r"c:\windows\systemapps\")
        || path_low.starts_with(r"c:\windows\servicing\")
        || path_low.starts_with(r"c:\windows\immersivecontrolpanel\")
        || path_low.starts_with(r"c:\windows\explorer.exe")
        || path_low.starts_with(r"c:\windows\regedit.exe")
        || path_low.starts_with(r"c:\program files\windows defender")
        || path_low.starts_with(r"c:\program files\windowsapps\microsoft.")
        || path_low.starts_with(r"c:\program files (x86)\windows ")
        || path_low.contains(r"\system32\svchost.exe")
        || path_low.contains(r"\syswow64\svchost.exe")
}

pub(crate) fn is_ms_os_rpc(binding_low: &str, ann_low: &str, weak_pipe: bool) -> bool {
    if weak_pipe {
        return false;
    }
    if ann_low.starts_with("ms ")
        || ann_low.starts_with("windows ")
        || ann_low.starts_with("microsoft ")
        || ann_low.starts_with("active directory")
        || ann_low.starts_with("com+")
        || ann_low.starts_with("dcom")
        || ann_low.starts_with("task scheduler")
        || ann_low.starts_with("print spooler")
        || ann_low.starts_with("background intelligent transfer")
        || ann_low.starts_with("remote procedure call")
        || ann_low.starts_with("lsa ")
        || ann_low.starts_with("sam ")
        || ann_low.starts_with("efs ")
    {
        return true;
    }
    if ann_low.is_empty()
        && (binding_low.contains("[lrpc-")
            || binding_low.contains("[epmapper]")
            || binding_low.contains("[lsass]")
            || binding_low.contains("[security")
            || binding_low.contains("[audit")
            || binding_low.contains("[ole")
            || binding_low.contains("[eventlog")
            || binding_low.contains("[sam")
            || binding_low.contains("[srvsvc")
            || binding_low.contains("[wkssvc")
            || binding_low.contains("[spoolss"))
    {
        return true;
    }
    if let Some(np_idx) = binding_low.find(r"\pipe\") {
        let rest = &binding_low[np_idx..];
        let ep = rest.split(']').next().unwrap_or(rest);
        if is_ms_os_pipe(ep) {
            return true;
        }
    }
    false
}

/// Normalizes MSYS2 `/c/...` and POSIX `/tmp/...` paths on Windows when the literal path is absent.
pub fn normalize_win_input_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    #[cfg(windows)]
    {
        if std::path::Path::new(trimmed).exists() {
            return trimmed.to_string();
        }
        if trimmed == "/tmp" || trimmed == "/tmp/" {
            return std::env::temp_dir().to_string_lossy().replace('\\', "/");
        }
        if let Some(rest) = trimmed.strip_prefix("/tmp/") {
            return std::env::temp_dir()
                .join(rest)
                .to_string_lossy()
                .replace('\\', "/");
        }
        let b = trimmed.as_bytes();
        if b.len() >= 2 && b[0] == b'/' && b[1].is_ascii_alphabetic() {
            let drv = (b[1] as char).to_ascii_uppercase();
            if b.len() == 2 {
                return format!("{drv}:/");
            }
            if b[2] == b'/' || b[2] == b'\\' {
                let tail = trimmed[3..].replace('\\', "/");
                return format!("{drv}:/{tail}");
            }
        }
    }
    trimmed.to_string()
}

#[cfg(windows)]
mod imp {
    use super::*;
    use core::ffi::c_void;
    use std::ptr;

    type Handle = *mut c_void;
    type Bool = i32;

    const INVALID_HANDLE_VALUE: isize = -1;
    const MAX_PATH_W: usize = 260;

    const SE_FILE_OBJECT: u32 = 1;
    const SE_KERNEL_OBJECT: u32 = 6;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const SDDL_REVISION_1: u32 = 1;

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    const TOKEN_PRIVILEGES_CLASS: u32 = 3;
    const TOKEN_ELEVATION_CLASS: u32 = 20;
    const TOKEN_INTEGRITY_LEVEL_CLASS: u32 = 25;
    const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;

    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const FILE_SHARE_ALL: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const ERROR_ACCESS_DENIED: u32 = 5;

    const WTD_UI_NONE: u32 = 2;
    const WTD_REVOKE_NONE: u32 = 0;
    const WTD_CHOICE_FILE: u32 = 1;
    const WTD_CHOICE_CATALOG: u32 = 2;
    const WTD_STATEACTION_VERIFY: u32 = 1;
    const WTD_STATEACTION_CLOSE: u32 = 2;
    const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_1000;

    const TRUST_E_NOSIGNATURE_CODE: i32 = 0x800B_0100u32 as i32;
    const TRUST_E_EXPLICIT_DISTRUST_CODE: i32 = 0x800B_0111u32 as i32;
    const TRUST_E_SUBJECT_NOT_TRUSTED_CODE: i32 = 0x800B_0004u32 as i32;
    const CRYPT_E_SECURITY_SETTINGS_CODE: i32 = 0x8009_2026u32 as i32;
    const CERT_E_EXPIRED_CODE: i32 = 0x800B_0101u32 as i32;
    const CERT_E_UNTRUSTEDROOT_CODE: i32 = 0x800B_0109u32 as i32;
    const CERT_E_CHAINING_CODE: i32 = 0x800B_010Au32 as i32;

    const CERT_NAME_RDN_TYPE: u32 = 2;
    const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
    const CERT_NAME_ISSUER_FLAG: u32 = 1;
    const CERT_HASH_PROP_ID: u32 = 3;
    const CERT_SHA256_HASH_PROP_ID: u32 = 107;

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const WINTRUST_ACTION_GENERIC_VERIFY_V2: Guid = Guid {
        data1: 0x00AA_C56B,
        data2: 0xCD44,
        data3: 0x11d0,
        data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };

    #[repr(C)]
    struct SystemTime {
        w_year: u16,
        w_month: u16,
        w_day_of_week: u16,
        w_day: u16,
        w_hour: u16,
        w_minute: u16,
        w_second: u16,
        w_milliseconds: u16,
    }

    #[repr(C)]
    struct WinTrustFileInfo {
        cb_struct: u32,
        pcwsz_file_path: *const u16,
        h_file: Handle,
        pg_known_subject: *const Guid,
    }

    #[repr(C)]
    struct WinTrustCatalogInfo {
        cb_struct: u32,
        dw_catalog_version: u32,
        pcwsz_catalog_file_path: *const u16,
        pcwsz_member_tag: *const u16,
        pcwsz_member_file_path: *const u16,
        h_member_file: Handle,
        pb_calculated_file_hash: *const u8,
        cb_calculated_file_hash: u32,
        pc_catalog_context: *const c_void,
        h_cat_admin: Handle,
    }

    #[repr(C)]
    struct WinTrustData {
        cb_struct: u32,
        p_policy_callback_data: *mut c_void,
        p_sip_client_data: *mut c_void,
        dw_ui_choice: u32,
        fdw_revocation_checks: u32,
        dw_union_choice: u32,
        p_union: *mut c_void,
        dw_state_action: u32,
        h_wvt_state_data: Handle,
        pwsz_url_reference: *const u16,
        dw_prov_flags: u32,
        dw_ui_context: u32,
        p_signature_settings: *mut c_void,
    }

    #[repr(C)]
    struct CatalogInfo {
        cb_struct: u32,
        wsz_catalog_file: [u16; MAX_PATH_W],
    }

    #[repr(C)]
    struct CryptoApiBlob {
        cb_data: u32,
        pb_data: *const u8,
    }

    #[repr(C)]
    struct CryptAlgorithmIdentifier {
        psz_obj_id: *const u8,
        parameters: CryptoApiBlob,
    }

    #[repr(C)]
    struct CertInfo {
        dw_version: u32,
        serial_number: CryptoApiBlob,
        signature_algorithm: CryptAlgorithmIdentifier,
        issuer: CryptoApiBlob,
        not_before: FileTime,
        not_after: FileTime,
    }

    #[repr(C)]
    struct CertContext {
        dw_cert_encoding_type: u32,
        pb_cert_encoded: *const u8,
        cb_cert_encoded: u32,
        p_cert_info: *const CertInfo,
        h_cert_store: Handle,
    }

    #[repr(C)]
    struct CryptProviderSgnr {
        cb_struct: u32,
        sft_verify_as_of: FileTime,
        cs_cert_chain: u32,
        pas_cert_chain: *mut c_void,
        dw_signer_type: u32,
        ps_signer: *mut c_void,
        dw_error: u32,
        cs_counter_signers: u32,
        pas_counter_signers: *mut c_void,
        p_cert_chain_context: *const c_void,
    }

    #[repr(C)]
    struct CryptProviderCert {
        cb_struct: u32,
        p_cert: *const CertContext,
    }

    const HKEY_CLASSES_ROOT: isize = 0x8000_0000u32 as i32 as isize;
    const HKEY_CURRENT_USER: isize = 0x8000_0001u32 as i32 as isize;
    const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
    const HKEY_USERS: isize = 0x8000_0003u32 as i32 as isize;
    const HKEY_CURRENT_CONFIG: isize = 0x8000_0005u32 as i32 as isize;
    const KEY_READ: u32 = 0x0002_0019;
    const READ_CONTROL: u32 = 0x0002_0000;
    const ERROR_MORE_DATA: i32 = 234;
    const ERROR_NO_MORE_ITEMS: i32 = 259;
    const RPC_C_EP_ALL_ELTS: u32 = 0;
    const RPC_C_VERS_ALL: u32 = 1;
    const RPC_S_OK: i32 = 0;
    const RPC_X_NO_MORE_ENTRIES: i32 = 1772;

    const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
    const SERVICE_QUERY_CONFIG: u32 = 0x0001;
    const SC_ENUM_PROCESS_INFO: u32 = 0;
    const SERVICE_WIN32: u32 = 0x0000_0030;
    const SERVICE_STATE_ALL: u32 = 0x0000_0003;

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    struct Win32FindDataW {
        dw_file_attributes: u32,
        ft_creation_time: FileTime,
        ft_last_access_time: FileTime,
        ft_last_write_time: FileTime,
        n_file_size_high: u32,
        n_file_size_low: u32,
        dw_reserved0: u32,
        dw_reserved1: u32,
        c_file_name: [u16; MAX_PATH_W],
        c_alternate_file_name: [u16; 14],
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct Luid {
        low_part: u32,
        high_part: i32,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct LuidAndAttributes {
        luid: Luid,
        attributes: u32,
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenPrivilegesHeader {
        privilege_count: u32,
        privileges: [LuidAndAttributes; 1],
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct ServiceStatusProcess {
        dw_service_type: u32,
        dw_current_state: u32,
        dw_controls_accepted: u32,
        dw_win32_exit_code: u32,
        dw_service_specific_exit_code: u32,
        dw_check_point: u32,
        dw_wait_hint: u32,
        dw_process_id: u32,
        dw_service_flags: u32,
    }

    #[repr(C)]
    struct EnumServiceStatusProcessW {
        lp_service_name: *mut u16,
        lp_display_name: *mut u16,
        service_status_process: ServiceStatusProcess,
    }

    #[repr(C)]
    struct QueryServiceConfigWHeader {
        dw_service_type: u32,
        dw_start_type: u32,
        dw_error_control: u32,
        lp_binary_path_name: *mut u16,
        lp_load_order_group: *mut u16,
        dw_tag_id: u32,
        lp_dependencies: *mut u16,
        lp_service_start_name: *mut u16,
        lp_display_name: *mut u16,
    }

    #[repr(C)]
    struct ProcessEntry32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; MAX_PATH_W],
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn FindFirstFileW(lp_file_name: *const u16, lp_find_data: *mut Win32FindDataW) -> Handle;
        fn FindNextFileW(h_find_file: Handle, lp_find_data: *mut Win32FindDataW) -> Bool;
        fn FindClose(h_find_file: Handle) -> Bool;
        fn CloseHandle(h_object: Handle) -> Bool;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
        fn GetCurrentProcess() -> Handle;
        fn GetLastError() -> u32;
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *mut c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: Handle,
        ) -> Handle;
        fn FileTimeToSystemTime(
            lp_file_time: *const FileTime,
            lp_system_time: *mut SystemTime,
        ) -> Bool;
        fn GetNamedPipeServerProcessId(pipe: Handle, server_process_id: *mut u32) -> Bool;
        fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> Handle;
        fn Process32FirstW(h_snapshot: Handle, lppe: *mut ProcessEntry32W) -> Bool;
        fn Process32NextW(h_snapshot: Handle, lppe: *mut ProcessEntry32W) -> Bool;
        fn OpenProcess(
            dw_desired_access: u32,
            b_inherit_handle: Bool,
            dw_process_id: u32,
        ) -> Handle;
        fn QueryFullProcessImageNameW(
            h_process: Handle,
            dw_flags: u32,
            lp_exe_name: *mut u16,
            lpdw_size: *mut u32,
        ) -> Bool;
        fn ProcessIdToSessionId(dw_process_id: u32, p_session_id: *mut u32) -> Bool;
    }

    #[link(name = "wintrust")]
    extern "system" {
        fn WinVerifyTrust(
            hwnd: Handle,
            pg_action_id: *const Guid,
            p_wvt_data: *mut WinTrustData,
        ) -> i32;
        fn WTHelperProvDataFromStateData(h_state_data: Handle) -> *mut c_void;
        fn WTHelperGetProvSignerFromChain(
            p_prov_data: *mut c_void,
            idx_signer: u32,
            f_counter_signer: Bool,
            idx_counter_signer: u32,
        ) -> *mut CryptProviderSgnr;
        fn WTHelperGetProvCertFromChain(
            p_sgnr: *mut CryptProviderSgnr,
            idx_cert: u32,
        ) -> *mut CryptProviderCert;
        fn CryptCATAdminAcquireContext2(
            ph_cat_admin: *mut Handle,
            pg_subsystem: *const Guid,
            pwsz_hash_algorithm: *const u16,
            p_strong_hash_policy: *const c_void,
            dw_flags: u32,
        ) -> Bool;
        fn CryptCATAdminCalcHashFromFileHandle2(
            h_cat_admin: Handle,
            h_file: Handle,
            pcb_hash: *mut u32,
            pb_hash: *mut u8,
            dw_flags: u32,
        ) -> Bool;
        fn CryptCATAdminEnumCatalogFromHash(
            h_cat_admin: Handle,
            pb_hash: *const u8,
            cb_hash: u32,
            dw_flags: u32,
            ph_prev_cat_info: *mut Handle,
        ) -> Handle;
        fn CryptCATCatalogInfoFromContext(
            h_cat_info: Handle,
            ps_cat_info: *mut CatalogInfo,
            dw_flags: u32,
        ) -> Bool;
        fn CryptCATAdminReleaseCatalogContext(
            h_cat_admin: Handle,
            h_cat_info: Handle,
            dw_flags: u32,
        ) -> Bool;
        fn CryptCATAdminReleaseContext(h_cat_admin: Handle, dw_flags: u32) -> Bool;
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CertGetNameStringW(
            p_cert_context: *const CertContext,
            dw_type: u32,
            dw_flags: u32,
            pv_type_para: *const c_void,
            psz_name_string: *mut u16,
            cch_name_string: u32,
        ) -> u32;
        fn CertGetCertificateContextProperty(
            p_cert_context: *const CertContext,
            dw_prop_id: u32,
            pv_data: *mut c_void,
            pcb_data: *mut u32,
        ) -> Bool;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn GetNamedSecurityInfoW(
            p_object_name: *const u16,
            object_type: u32,
            security_info: u32,
            ppsid_owner: *mut *mut c_void,
            ppsid_group: *mut *mut c_void,
            pp_dacl: *mut *mut c_void,
            pp_sacl: *mut *mut c_void,
            pp_security_descriptor: *mut *mut c_void,
        ) -> u32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security_descriptor: *const c_void,
            requested_string_sd_revision: u32,
            security_information: u32,
            string_security_descriptor: *mut *mut u16,
            string_security_descriptor_len: *mut u32,
        ) -> Bool;
        fn ConvertSidToStringSidW(sid: *const c_void, string_sid: *mut *mut u16) -> Bool;
        fn LookupAccountSidW(
            lp_system_name: *const u16,
            sid: *const c_void,
            name: *mut u16,
            cch_name: *mut u32,
            referenced_domain_name: *mut u16,
            cch_referenced_domain_name: *mut u32,
            pe_use: *mut u32,
        ) -> Bool;
        fn OpenProcessToken(
            process_handle: Handle,
            desired_access: u32,
            token_handle: *mut Handle,
        ) -> Bool;
        fn GetTokenInformation(
            token_handle: Handle,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> Bool;
        fn GetSidSubAuthorityCount(p_sid: *const c_void) -> *mut u8;
        fn GetSidSubAuthority(p_sid: *const c_void, n_sub_authority: u32) -> *mut u32;
        fn LookupPrivilegeNameW(
            lp_system_name: *const u16,
            lp_luid: *const Luid,
            lp_name: *mut u16,
            cch_name: *mut u32,
        ) -> Bool;
        fn RegOpenKeyExW(
            h_key: isize,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut isize,
        ) -> i32;
        fn RegEnumKeyExW(
            h_key: isize,
            dw_index: u32,
            lp_name: *mut u16,
            lpcch_name: *mut u32,
            lp_reserved: *mut u32,
            lp_class: *mut u16,
            lpcch_class: *mut u32,
            lpft_last_write_time: *mut c_void,
        ) -> i32;
        fn RegEnumValueW(
            h_key: isize,
            dw_index: u32,
            lp_value_name: *mut u16,
            lpcch_value_name: *mut u32,
            lp_reserved: *mut u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;
        fn RegQueryValueExW(
            h_key: isize,
            lp_value_name: *const u16,
            lp_reserved: *mut u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;
        fn RegGetKeySecurity(
            h_key: isize,
            security_information: u32,
            p_security_descriptor: *mut c_void,
            lpcb_security_descriptor: *mut u32,
        ) -> i32;
        fn RegCloseKey(h_key: isize) -> i32;
        fn OpenSCManagerW(
            lp_machine_name: *const u16,
            lp_database_name: *const u16,
            dw_desired_access: u32,
        ) -> Handle;
        fn EnumServicesStatusExW(
            h_sc_manager: Handle,
            info_level: u32,
            dw_service_type: u32,
            dw_service_state: u32,
            lp_services: *mut u8,
            cb_buf_size: u32,
            pcb_bytes_needed: *mut u32,
            lp_services_returned: *mut u32,
            lp_resume_handle: *mut u32,
            psz_group_name: *const u16,
        ) -> Bool;
        fn OpenServiceW(
            h_sc_manager: Handle,
            lp_service_name: *const u16,
            dw_desired_access: u32,
        ) -> Handle;
        fn QueryServiceConfigW(
            h_service: Handle,
            lp_service_config: *mut u8,
            cb_buf_size: u32,
            pcb_bytes_needed: *mut u32,
        ) -> Bool;
        fn CloseServiceHandle(h_sc_object: Handle) -> Bool;
    }

    #[link(name = "rpcrt4")]
    extern "system" {
        fn RpcMgmtEpEltInqBegin(
            ep_binding: Handle,
            inquiry_type: u32,
            if_id: *const c_void,
            vers_option: u32,
            object_uuid: *const c_void,
            inquiry_context: *mut Handle,
        ) -> i32;
        fn RpcMgmtEpEltInqNextW(
            inquiry_context: Handle,
            if_id: *mut RpcIfId,
            binding: *mut Handle,
            object_uuid: *mut Guid,
            annotation: *mut *mut u16,
        ) -> i32;
        fn RpcMgmtEpEltInqDone(inquiry_context: *mut Handle) -> i32;
        fn RpcBindingToStringBindingW(binding: Handle, string_binding: *mut *mut u16) -> i32;
        fn RpcBindingFree(binding: *mut Handle) -> i32;
        fn UuidToStringW(uuid: *const Guid, string_uuid: *mut *mut u16) -> i32;
        fn RpcStringFreeW(string: *mut *mut u16) -> i32;
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct RpcIfId {
        uuid: Guid,
        vers_major: u16,
        vers_minor: u16,
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    unsafe fn read_wide_cstr(ptr_w: *const u16) -> String {
        if ptr_w.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while len < 32768 && *ptr_w.add(len) != 0 {
            len += 1;
        }
        let slice = core::slice::from_raw_parts(ptr_w, len);
        String::from_utf16_lossy(slice)
    }

    unsafe fn read_wide_buf(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    unsafe fn sid_to_string(sid: *const c_void) -> String {
        if sid.is_null() {
            return String::new();
        }
        let mut s_ptr: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut s_ptr) != 0 && !s_ptr.is_null() {
            let out = read_wide_cstr(s_ptr);
            LocalFree(s_ptr as *mut c_void);
            out
        } else {
            String::new()
        }
    }

    unsafe fn sid_to_account_and_id(sid: *const c_void) -> (String, String) {
        if sid.is_null() {
            return (String::new(), String::new());
        }
        let sid_str = sid_to_string(sid);
        let mut name_buf = [0u16; 256];
        let mut dom_buf = [0u16; 256];
        let mut cch_name = name_buf.len() as u32;
        let mut cch_dom = dom_buf.len() as u32;
        let mut use_kind = 0u32;
        let account = if LookupAccountSidW(
            ptr::null(),
            sid,
            name_buf.as_mut_ptr(),
            &mut cch_name,
            dom_buf.as_mut_ptr(),
            &mut cch_dom,
            &mut use_kind,
        ) != 0
        {
            let dom = String::from_utf16_lossy(&dom_buf[..cch_dom as usize]);
            let nm = String::from_utf16_lossy(&name_buf[..cch_name as usize]);
            if dom.is_empty() {
                nm
            } else {
                format!("{dom}\\{nm}")
            }
        } else {
            sid_str.clone()
        };
        (account, sid_str)
    }

    unsafe fn sd_to_sddl(sd: *const c_void, sec_info: u32) -> Option<String> {
        let mut sddl_ptr: *mut u16 = ptr::null_mut();
        let mut sddl_len = 0u32;
        if ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            sec_info,
            &mut sddl_ptr,
            &mut sddl_len,
        ) != 0
            && !sddl_ptr.is_null()
        {
            let sddl = read_wide_cstr(sddl_ptr);
            LocalFree(sddl_ptr as *mut c_void);
            Some(sddl)
        } else {
            None
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProcessIlInfo {
        pub pid: u32,
        pub ppid: u32,
        pub name: String,
        pub exe: String,
        pub integrity_level: String,
        pub session_id: u32,
        pub elevated: Option<bool>,
        pub user: String,
    }

    fn read_token_info_buf(h_tok: Handle, class_id: u32) -> Option<Vec<u8>> {
        let mut need = 0u32;
        unsafe { GetTokenInformation(h_tok, class_id, ptr::null_mut(), 0, &mut need) };
        if need == 0 || need > 262_144 {
            return None;
        }
        let mut buf = vec![0u8; need as usize + 16];
        let ok = unsafe {
            GetTokenInformation(
                h_tok,
                class_id,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut need,
            )
        };
        if ok != 0 {
            Some(buf)
        } else {
            None
        }
    }

    fn integrity_level_from_token(h_tok: Handle) -> String {
        read_token_info_buf(h_tok, TOKEN_INTEGRITY_LEVEL_CLASS)
            .map(|b| unsafe {
                let sa = &*(b.as_ptr() as *const SidAndAttributes);
                let cnt_ptr = GetSidSubAuthorityCount(sa.sid);
                if cnt_ptr.is_null() || *cnt_ptr == 0 {
                    return "Unknown".to_string();
                }
                let rid_ptr = GetSidSubAuthority(sa.sid, (*cnt_ptr - 1) as u32);
                if rid_ptr.is_null() {
                    return "Unknown".to_string();
                }
                let rid = *rid_ptr;
                if rid >= 0x4000 {
                    "SYSTEM".to_string()
                } else if rid >= 0x3000 {
                    "High".to_string()
                } else if rid >= 0x2000 {
                    "Medium".to_string()
                } else if rid >= 0x1000 {
                    "Low".to_string()
                } else {
                    "Untrusted".to_string()
                }
            })
            .unwrap_or_else(|| "Unknown".to_string())
    }

    fn inspect_process_il_by_pid(pid: u32) -> (String, String, Option<bool>, String) {
        if pid == 0 {
            return (
                String::new(),
                "SYSTEM".to_string(),
                Some(true),
                String::new(),
            );
        }
        let h_proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h_proc.is_null() {
            let err = unsafe { GetLastError() };
            let il = if err == ERROR_ACCESS_DENIED {
                "SYSTEM_OR_PPL(access_denied)".to_string()
            } else {
                "Unknown".to_string()
            };
            return (String::new(), il, None, String::new());
        }
        let mut exe_buf = [0u16; 1024];
        let mut exe_len = exe_buf.len() as u32;
        let exe =
            if unsafe { QueryFullProcessImageNameW(h_proc, 0, exe_buf.as_mut_ptr(), &mut exe_len) }
                != 0
                && exe_len > 0
            {
                String::from_utf16_lossy(&exe_buf[..exe_len as usize])
            } else {
                String::new()
            };

        let mut h_tok: Handle = ptr::null_mut();
        let (il, elevated, user) = if unsafe { OpenProcessToken(h_proc, TOKEN_QUERY, &mut h_tok) }
            != 0
            && !h_tok.is_null()
        {
            let il_s = integrity_level_from_token(h_tok);
            let elev = read_token_info_buf(h_tok, TOKEN_ELEVATION_CLASS)
                .and_then(|b| {
                    (b.len() >= 4).then(|| u32::from_le_bytes(b[..4].try_into().unwrap()))
                })
                .map(|v| v != 0);
            let (usr, _sid) = read_token_info_buf(h_tok, TOKEN_USER_CLASS)
                .map(|b| unsafe {
                    let sa = &*(b.as_ptr() as *const SidAndAttributes);
                    sid_to_account_and_id(sa.sid)
                })
                .unwrap_or_default();
            unsafe {
                CloseHandle(h_tok);
            }
            (il_s, elev, usr)
        } else {
            let err = unsafe { GetLastError() };
            let il_s = if err == ERROR_ACCESS_DENIED {
                "SYSTEM_OR_PPL(access_denied)".to_string()
            } else {
                "Unknown".to_string()
            };
            (il_s, None, String::new())
        };
        unsafe {
            CloseHandle(h_proc);
        }
        (exe, il, elevated, user)
    }

    pub fn collect_processes_il() -> Result<Vec<ProcessIlInfo>, String> {
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap as isize == INVALID_HANDLE_VALUE || snap.is_null() {
            return Err(format!(
                "CreateToolhelp32Snapshot failed (err={})",
                unsafe { GetLastError() }
            ));
        }
        let mut pe: ProcessEntry32W = unsafe { core::mem::zeroed() };
        pe.dw_size = core::mem::size_of::<ProcessEntry32W>() as u32;
        let mut out = Vec::new();
        if unsafe { Process32FirstW(snap, &mut pe) } != 0 {
            loop {
                let pid = pe.th32_process_id;
                let ppid = pe.th32_parent_process_id;
                let name = unsafe { read_wide_buf(&pe.sz_exe_file) };
                let mut session_id = 0u32;
                let _ = unsafe { ProcessIdToSessionId(pid, &mut session_id) };
                let (exe, integrity_level, elevated, user) = inspect_process_il_by_pid(pid);
                out.push(ProcessIlInfo {
                    pid,
                    ppid,
                    name,
                    exe,
                    integrity_level,
                    session_id,
                    elevated,
                    user,
                });
                if unsafe { Process32NextW(snap, &mut pe) } == 0 {
                    break;
                }
            }
        }
        unsafe {
            CloseHandle(snap);
        }
        Ok(out)
    }

    pub fn query_procs_opts(
        filter: Option<&str>,
        max: usize,
        non_ms: bool,
        cached_procs: Option<&[ProcessIlInfo]>,
    ) -> Value {
        let owned;
        let all_procs: &[ProcessIlInfo] = match cached_procs {
            Some(slice) => slice,
            None => match collect_processes_il() {
                Ok(v) => {
                    owned = v;
                    &owned
                }
                Err(e) => return json!({ "ok": false, "mode": "procs", "error": e }),
            },
        };
        let f_low = filter.map(|s| s.to_ascii_lowercase());
        let cap = max.clamp(1, 200);
        let mut total_matched = 0usize;
        let mut items = Vec::new();
        for p in all_procs {
            if let Some(ref fl) = f_low {
                let hit = p.name.to_ascii_lowercase().contains(fl)
                    || p.exe.to_ascii_lowercase().contains(fl)
                    || p.integrity_level.to_ascii_lowercase().contains(fl)
                    || p.user.to_ascii_lowercase().contains(fl);
                if !hit {
                    continue;
                }
            }
            if non_ms {
                let exe_low = p.exe.to_ascii_lowercase();
                let nm_low = p.name.to_ascii_lowercase();
                if (!exe_low.is_empty() && super::is_ms_os_path(&exe_low))
                    || matches!(
                        nm_low.as_str(),
                        "system"
                            | "[system process]"
                            | "registry"
                            | "memory compression"
                            | "secure system"
                            | "smss.exe"
                            | "csrss.exe"
                            | "wininit.exe"
                            | "services.exe"
                            | "lsass.exe"
                            | "svchost.exe"
                            | "fontdrvhost.exe"
                            | "dwm.exe"
                            | "winlogon.exe"
                    )
                {
                    continue;
                }
            }
            total_matched += 1;
            if items.len() < cap {
                items.push(json!({
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "name": p.name,
                    "exe": p.exe,
                    "integrity_level": p.integrity_level,
                    "session_id": p.session_id,
                    "elevated": p.elevated,
                    "user": p.user,
                }));
            }
        }
        json!({
            "ok": true,
            "mode": "procs",
            "total_matched": total_matched,
            "returned": items.len(),
            "processes": items,
        })
    }

    fn is_privileged_il(il: &str) -> bool {
        il == "SYSTEM" || il == "High" || il.starts_with("SYSTEM_OR_PPL")
    }

    fn attribute_pipe_server(
        full_pipe_path: &str,
        proc_map: Option<&std::collections::HashMap<u32, &ProcessIlInfo>>,
    ) -> (Option<u32>, Option<String>, Option<String>) {
        let w_path = to_wide(full_pipe_path);
        let h = unsafe {
            CreateFileW(
                w_path.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_ALL,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if h as isize == INVALID_HANDLE_VALUE || h.is_null() {
            return (None, None, None);
        }
        let mut srv_pid = 0u32;
        let ok = unsafe { GetNamedPipeServerProcessId(h, &mut srv_pid) };
        unsafe {
            CloseHandle(h);
        }
        if ok == 0 || srv_pid == 0 {
            return (None, None, None);
        }
        if let Some(map) = proc_map {
            if let Some(info) = map.get(&srv_pid) {
                let proc_label = if !info.exe.is_empty() {
                    info.exe.clone()
                } else {
                    info.name.clone()
                };
                return (
                    Some(srv_pid),
                    Some(proc_label),
                    Some(info.integrity_level.clone()),
                );
            }
        }
        let (exe, il, _elev, _usr) = inspect_process_il_by_pid(srv_pid);
        let proc_label = if exe.is_empty() {
            format!("pid:{srv_pid}")
        } else {
            exe
        };
        (Some(srv_pid), Some(proc_label), Some(il))
    }

    #[cfg(test)]
    pub fn query_pipes(filter: Option<&str>, max: usize) -> Value {
        query_pipes_with_cache(filter, max, false, true, None, true)
    }

    pub fn query_pipes_with_cache(
        filter: Option<&str>,
        max: usize,
        non_ms: bool,
        enforce_200_cap: bool,
        proc_map: Option<&std::collections::HashMap<u32, &ProcessIlInfo>>,
        attribute_non_weak: bool,
    ) -> Value {
        let pat_w = to_wide(r"\\.\pipe\*");
        let mut fd: Win32FindDataW = unsafe { core::mem::zeroed() };
        let h = unsafe { FindFirstFileW(pat_w.as_ptr(), &mut fd) };
        if h as isize == INVALID_HANDLE_VALUE || h.is_null() {
            return json!({
                "ok": false,
                "error": format!("FindFirstFileW(\\\\.\\pipe\\*) failed (err={})", unsafe { GetLastError() }),
            });
        }
        let f_low = filter.map(|s| s.to_ascii_lowercase());
        let mut all_names: Vec<String> = Vec::new();
        loop {
            let nm = unsafe { read_wide_buf(&fd.c_file_name) };
            let nm_low = nm.to_ascii_lowercase();
            let keep_filter =
                !nm.is_empty() && f_low.as_ref().map(|fl| nm_low.contains(fl)).unwrap_or(true);
            let keep_ms = !non_ms || !super::is_ms_os_pipe(&nm_low);
            if keep_filter && keep_ms {
                all_names.push(nm);
            }
            if unsafe { FindNextFileW(h, &mut fd) } == 0 {
                break;
            }
        }
        unsafe {
            FindClose(h);
        }
        all_names.sort();
        all_names.dedup();
        super::sort_pipe_names_by_signal(&mut all_names);
        let total_matched = all_names.len();
        let cap = if enforce_200_cap {
            max.clamp(1, 200)
        } else {
            max.max(1)
        };
        let mut entries = Vec::new();
        for nm in all_names.into_iter().take(cap) {
            let full = format!(r"\\.\pipe\{nm}");
            let mut sddl: Option<String> = None;
            let mut non_admin_write = false;
            let mut weak_dacl: Vec<String> = Vec::new();
            let w_path = to_wide(&full);
            let mut p_dacl: *mut c_void = ptr::null_mut();
            let mut p_sd: *mut c_void = ptr::null_mut();
            let rc = unsafe {
                GetNamedSecurityInfoW(
                    w_path.as_ptr(),
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut p_dacl,
                    ptr::null_mut(),
                    &mut p_sd,
                )
            };
            if rc == 0 && !p_sd.is_null() {
                if let Some(s) = unsafe { sd_to_sddl(p_sd, DACL_SECURITY_INFORMATION) } {
                    let (_prot, aces) = parse_sddl_aces(&s);
                    for a in &aces {
                        if a.non_admin_write {
                            non_admin_write = true;
                            weak_dacl.push(format!("{}:{}", a.trustee, a.rights));
                        }
                    }
                    sddl = Some(s);
                }
                unsafe {
                    LocalFree(p_sd);
                }
            }
            let (server_pid, server_process, server_il) = if non_admin_write || attribute_non_weak {
                attribute_pipe_server(&full, proc_map)
            } else {
                (None, None, None)
            };
            let signal = if non_admin_write {
                if server_il.as_deref().is_some_and(is_privileged_il) {
                    Some("CROSS_IL_PIPE_EOP_CANDIDATE")
                } else {
                    Some("NAMED_PIPE_WEAK_DACL")
                }
            } else {
                None
            };
            entries.push(json!({
                "name": nm,
                "path": full,
                "pipe": full,
                "sddl": sddl,
                "non_admin_write": non_admin_write,
                "weak_dacl": weak_dacl,
                "server_pid": server_pid,
                "server_process": server_process,
                "server_il": server_il,
                "signal": signal,
            }));
        }
        entries.sort_by_key(|e| !e["non_admin_write"].as_bool().unwrap_or(false));
        json!({
            "ok": true,
            "mode": "pipes",
            "total_matched": total_matched,
            "returned": entries.len(),
            "pipes": entries,
        })
    }

    fn parse_reg_hive_and_subkey(raw: &str) -> Result<(isize, String, &'static str), String> {
        let clean = raw.trim().replace('/', "\\");
        let (root_tok, rest) = match clean.find('\\') {
            Some(pos) => (&clean[..pos], clean[pos + 1..].trim_start_matches('\\')),
            None => (clean.as_str(), ""),
        };
        let norm_root = root_tok.trim_end_matches(':').to_ascii_uppercase();
        let (hkey, label) = match norm_root.as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => (HKEY_LOCAL_MACHINE, "HKLM"),
            "HKCU" | "HKEY_CURRENT_USER" => (HKEY_CURRENT_USER, "HKCU"),
            "HKCR" | "HKEY_CLASSES_ROOT" => (HKEY_CLASSES_ROOT, "HKCR"),
            "HKU" | "HKEY_USERS" => (HKEY_USERS, "HKU"),
            "HKCC" | "HKEY_CURRENT_CONFIG" => (HKEY_CURRENT_CONFIG, "HKCC"),
            _ => {
                return Err(format!(
                    "Unsupported registry hive '{root_tok}' (expected HKLM/HKCU/HKCR/HKU/HKCC)"
                ))
            }
        };
        Ok((hkey, rest.to_string(), label))
    }

    fn decode_reg_value(ty: u32, data: &[u8]) -> (String, Value) {
        match ty {
            1 | 2 => {
                let kind = if ty == 1 { "REG_SZ" } else { "REG_EXPAND_SZ" };
                let u16s: Vec<u16> = data
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let s = u16s
                    .iter()
                    .position(|&c| c == 0)
                    .map(|p| String::from_utf16_lossy(&u16s[..p]))
                    .unwrap_or_else(|| String::from_utf16_lossy(&u16s));
                (kind.to_string(), json!(s))
            }
            4 => {
                let v = if data.len() >= 4 {
                    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                } else {
                    0
                };
                ("REG_DWORD".to_string(), json!(v))
            }
            11 => {
                let v = if data.len() >= 8 {
                    u64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]))
                } else {
                    0
                };
                ("REG_QWORD".to_string(), json!(v))
            }
            7 => {
                let u16s: Vec<u16> = data
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let items: Vec<String> = u16s
                    .split(|&c| c == 0)
                    .filter(|s| !s.is_empty())
                    .map(String::from_utf16_lossy)
                    .collect();
                ("REG_MULTI_SZ".to_string(), json!(items))
            }
            other => {
                let kind = if other == 3 {
                    "REG_BINARY".to_string()
                } else {
                    format!("REG_TYPE_{other}")
                };
                let hex: String = data.iter().take(64).map(|b| format!("{b:02x}")).collect();
                (
                    kind,
                    json!(format!("{hex}{}", if data.len() > 64 { "..." } else { "" })),
                )
            }
        }
    }

    pub fn query_registry(raw_key: &str, filter: Option<&str>, max: usize) -> Value {
        let (root_hkey, subkey, hive_lbl) = match parse_reg_hive_and_subkey(raw_key) {
            Ok(v) => v,
            Err(msg) => return json!({ "ok": false, "mode": "reg", "error": msg }),
        };
        let sub_w = to_wide(&subkey);
        let mut hk: isize = 0;
        let rc = unsafe { RegOpenKeyExW(root_hkey, sub_w.as_ptr(), 0, KEY_READ, &mut hk) };
        if rc != 0 {
            return json!({
                "ok": false,
                "mode": "reg",
                "key": format!("{hive_lbl}\\{subkey}"),
                "error": format!("RegOpenKeyExW failed (win32_err={rc})"),
            });
        }
        let cap = max.clamp(1, 200);
        let f_low = filter.map(|s| s.to_ascii_lowercase());
        let mut subkeys: Vec<String> = Vec::new();
        let mut idx = 0u32;
        loop {
            let mut kbuf = [0u16; 260];
            let mut klen = kbuf.len() as u32;
            let erc = unsafe {
                RegEnumKeyExW(
                    hk,
                    idx,
                    kbuf.as_mut_ptr(),
                    &mut klen,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if erc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if erc == 0 {
                let nm = String::from_utf16_lossy(&kbuf[..klen as usize]);
                if f_low
                    .as_ref()
                    .map(|fl| nm.to_ascii_lowercase().contains(fl))
                    .unwrap_or(true)
                {
                    subkeys.push(nm);
                    if subkeys.len() >= cap {
                        break;
                    }
                }
            } else if erc != ERROR_MORE_DATA {
                break;
            }
            idx += 1;
        }

        let mut values: Vec<Value> = Vec::new();
        let mut v_idx = 0u32;
        loop {
            let mut nbuf = [0u16; 512];
            let mut nlen = nbuf.len() as u32;
            let mut ty = 0u32;
            let mut dlen = 4096u32;
            let mut dbuf = vec![0u8; dlen as usize];
            let mut vrc = unsafe {
                RegEnumValueW(
                    hk,
                    v_idx,
                    nbuf.as_mut_ptr(),
                    &mut nlen,
                    ptr::null_mut(),
                    &mut ty,
                    dbuf.as_mut_ptr(),
                    &mut dlen,
                )
            };
            if vrc == ERROR_MORE_DATA && dlen > 0 && dlen <= 1_048_576 {
                nlen = nbuf.len() as u32;
                dbuf.resize(dlen as usize, 0);
                vrc = unsafe {
                    RegEnumValueW(
                        hk,
                        v_idx,
                        nbuf.as_mut_ptr(),
                        &mut nlen,
                        ptr::null_mut(),
                        &mut ty,
                        dbuf.as_mut_ptr(),
                        &mut dlen,
                    )
                };
            }
            if vrc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if vrc == 0 {
                let vname = String::from_utf16_lossy(&nbuf[..nlen as usize]);
                let disp = if vname.is_empty() {
                    "(Default)".to_string()
                } else {
                    vname
                };
                let (vtype, vval) = decode_reg_value(ty, &dbuf[..dlen as usize]);
                let val_str = vval.to_string().to_ascii_lowercase();
                let matches_f = f_low
                    .as_ref()
                    .map(|fl| disp.to_ascii_lowercase().contains(fl) || val_str.contains(fl))
                    .unwrap_or(true);
                if matches_f {
                    values.push(json!({ "name": disp, "type": vtype, "value": vval }));
                    if values.len() >= cap {
                        break;
                    }
                }
            }
            v_idx += 1;
        }
        unsafe {
            RegCloseKey(hk);
        }
        json!({
            "ok": true,
            "mode": "reg",
            "key": format!("{hive_lbl}\\{subkey}"),
            "subkeys": subkeys,
            "values": values,
        })
    }

    pub fn query_acl(raw_path: &str) -> Value {
        let norm_p = normalize_win_input_path(raw_path);
        let win_p = norm_p.replace('/', "\\");
        let w_path = to_wide(&win_p);
        let mut p_owner: *mut c_void = ptr::null_mut();
        let mut p_dacl: *mut c_void = ptr::null_mut();
        let mut p_sd: *mut c_void = ptr::null_mut();
        let rc = unsafe {
            GetNamedSecurityInfoW(
                w_path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut p_owner,
                ptr::null_mut(),
                &mut p_dacl,
                ptr::null_mut(),
                &mut p_sd,
            )
        };
        if rc != 0 || p_sd.is_null() {
            return json!({
                "ok": false,
                "mode": "acl",
                "path": win_p,
                "error": format!("GetNamedSecurityInfoW failed (win32_err={rc})"),
            });
        }
        let (owner, owner_sid) = unsafe { sid_to_account_and_id(p_owner) };
        let sddl = unsafe {
            sd_to_sddl(p_sd, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
                .unwrap_or_default()
        };
        unsafe {
            LocalFree(p_sd);
        }
        let (dacl_protected, aces) = parse_sddl_aces(&sddl);
        let non_admin_writable = aces.iter().any(|a| a.non_admin_write);
        json!({
            "ok": true,
            "mode": "acl",
            "path": win_p,
            "owner": owner,
            "owner_sid": owner_sid,
            "sddl": sddl,
            "dacl_protected": dacl_protected,
            "non_admin_writable": non_admin_writable,
            "aces": aces,
        })
    }

    fn state_str(s: u32) -> &'static str {
        match s {
            1 => "Stopped",
            2 => "StartPending",
            3 => "StopPending",
            4 => "Running",
            5 => "ContinuePending",
            6 => "PausePending",
            7 => "Paused",
            _ => "Unknown",
        }
    }

    fn start_type_str(s: u32) -> &'static str {
        match s {
            0 => "Boot",
            1 => "System",
            2 => "Auto",
            3 => "Manual",
            4 => "Disabled",
            _ => "Unknown",
        }
    }

    #[cfg(test)]
    pub fn query_services(filter: Option<&str>, max: usize) -> Value {
        query_services_opts(filter, max, false)
    }

    pub fn query_services_opts(filter: Option<&str>, max: usize, non_ms: bool) -> Value {
        let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ENUMERATE_SERVICE) };
        if scm.is_null() {
            return json!({
                "ok": false,
                "mode": "services",
                "error": format!("OpenSCManagerW failed (err={})", unsafe { GetLastError() }),
            });
        }
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                ptr::null_mut(),
                0,
                &mut needed,
                &mut count,
                &mut resume,
                ptr::null(),
            );
        }
        let mut buf = vec![0u8; needed as usize + 8192];
        let mut count2 = 0u32;
        let mut resume2 = 0u32;
        let ok = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut needed,
                &mut count2,
                &mut resume2,
                ptr::null(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            unsafe {
                CloseServiceHandle(scm);
            }
            return json!({
                "ok": false,
                "mode": "services",
                "error": format!("EnumServicesStatusExW failed (err={err})"),
            });
        }
        let f_low = filter.map(|s| s.to_ascii_lowercase());
        let cap = max.clamp(1, 200);
        let mut matched: Vec<Value> = Vec::new();
        let mut total_matched = 0usize;
        let ptr_base = buf.as_ptr() as *const EnumServiceStatusProcessW;
        for i in 0..(count2 as usize) {
            let item = unsafe { &*ptr_base.add(i) };
            let name = unsafe { read_wide_cstr(item.lp_service_name) };
            let display_name = unsafe { read_wide_cstr(item.lp_display_name) };
            let match_hit = f_low
                .as_ref()
                .map(|fl| {
                    name.to_ascii_lowercase().contains(fl)
                        || display_name.to_ascii_lowercase().contains(fl)
                })
                .unwrap_or(true);
            if !match_hit {
                continue;
            }
            let mut bin_path = String::new();
            let mut account = String::new();
            let mut start_type = "Unknown".to_string();
            let hs = unsafe { OpenServiceW(scm, item.lp_service_name, SERVICE_QUERY_CONFIG) };
            if !hs.is_null() {
                let mut cfg_need = 0u32;
                unsafe { QueryServiceConfigW(hs, ptr::null_mut(), 0, &mut cfg_need) };
                if cfg_need > 0 && cfg_need <= 65536 {
                    let mut cbuf = vec![0u8; cfg_need as usize + 64];
                    if unsafe {
                        QueryServiceConfigW(hs, cbuf.as_mut_ptr(), cbuf.len() as u32, &mut cfg_need)
                    } != 0
                    {
                        let cfg = unsafe { &*(cbuf.as_ptr() as *const QueryServiceConfigWHeader) };
                        start_type = start_type_str(cfg.dw_start_type).to_string();
                        bin_path = unsafe { read_wide_cstr(cfg.lp_binary_path_name) };
                        account = unsafe { read_wide_cstr(cfg.lp_service_start_name) };
                    }
                }
                unsafe {
                    CloseServiceHandle(hs);
                }
            }
            if non_ms {
                let exe_low = super::resolve_windows_exe_candidate(
                    &super::extract_service_exe_path(&bin_path),
                )
                .to_ascii_lowercase();
                let nm_low = name.to_ascii_lowercase();
                if super::is_ms_os_path(&exe_low)
                    || nm_low.starts_with("microsoft.")
                    || nm_low.starts_with("windows.")
                {
                    continue;
                }
            }
            total_matched += 1;
            if matched.len() >= cap {
                continue;
            }
            matched.push(json!({
                "name": name,
                "display_name": display_name,
                "state": state_str(item.service_status_process.dw_current_state),
                "pid": item.service_status_process.dw_process_id,
                "start_type": start_type,
                "bin_path": bin_path,
                "account": account,
            }));
        }
        unsafe {
            CloseServiceHandle(scm);
        }
        json!({
            "ok": true,
            "mode": "services",
            "total_matched": total_matched,
            "returned": matched.len(),
            "services": matched,
        })
    }

    pub fn query_whoami() -> Value {
        let mut h_tok: Handle = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h_tok) } == 0
            || h_tok.is_null()
        {
            return json!({
                "ok": false,
                "mode": "whoami",
                "error": format!("OpenProcessToken failed (err={})", unsafe { GetLastError() }),
            });
        }
        let get_tok_buf = |class_id: u32| -> Option<Vec<u8>> {
            let mut need = 0u32;
            unsafe { GetTokenInformation(h_tok, class_id, ptr::null_mut(), 0, &mut need) };
            if need == 0 || need > 262_144 {
                return None;
            }
            let mut buf = vec![0u8; need as usize + 16];
            let ok = unsafe {
                GetTokenInformation(
                    h_tok,
                    class_id,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len() as u32,
                    &mut need,
                )
            };
            if ok != 0 {
                Some(buf)
            } else {
                None
            }
        };

        let (user, user_sid) = get_tok_buf(TOKEN_USER_CLASS)
            .map(|b| unsafe {
                let sa = &*(b.as_ptr() as *const SidAndAttributes);
                sid_to_account_and_id(sa.sid)
            })
            .unwrap_or_default();

        let elevated = get_tok_buf(TOKEN_ELEVATION_CLASS)
            .and_then(|b| (b.len() >= 4).then(|| u32::from_le_bytes(b[..4].try_into().unwrap())))
            .unwrap_or(0)
            != 0;

        let integrity_level = get_tok_buf(TOKEN_INTEGRITY_LEVEL_CLASS)
            .map(|b| unsafe {
                let sa = &*(b.as_ptr() as *const SidAndAttributes);
                let cnt_ptr = GetSidSubAuthorityCount(sa.sid);
                if cnt_ptr.is_null() || *cnt_ptr == 0 {
                    return "Unknown".to_string();
                }
                let rid_ptr = GetSidSubAuthority(sa.sid, (*cnt_ptr - 1) as u32);
                if rid_ptr.is_null() {
                    return "Unknown".to_string();
                }
                let rid = *rid_ptr;
                if rid >= 0x4000 {
                    "SYSTEM".to_string()
                } else if rid >= 0x3000 {
                    "High".to_string()
                } else if rid >= 0x2000 {
                    "Medium".to_string()
                } else if rid >= 0x1000 {
                    "Low".to_string()
                } else {
                    "Untrusted".to_string()
                }
            })
            .unwrap_or_else(|| "Unknown".to_string());

        let mut privileges: Vec<Value> = Vec::new();
        if let Some(pbuf) = get_tok_buf(TOKEN_PRIVILEGES_CLASS) {
            if pbuf.len() >= core::mem::size_of::<u32>() {
                let hdr = unsafe { &*(pbuf.as_ptr() as *const TokenPrivilegesHeader) };
                let cnt = hdr.privilege_count as usize;
                let base_privs = core::ptr::addr_of!(hdr.privileges) as *const LuidAndAttributes;
                let avail =
                    pbuf.len().saturating_sub(4) / core::mem::size_of::<LuidAndAttributes>();
                for i in 0..cnt.min(avail) {
                    let la = unsafe { *base_privs.add(i) };
                    let mut nbuf = [0u16; 128];
                    let mut nlen = nbuf.len() as u32;
                    if unsafe {
                        LookupPrivilegeNameW(ptr::null(), &la.luid, nbuf.as_mut_ptr(), &mut nlen)
                    } != 0
                    {
                        let nm = String::from_utf16_lossy(&nbuf[..nlen as usize]);
                        privileges.push(json!({
                            "name": nm,
                            "enabled": (la.attributes & SE_PRIVILEGE_ENABLED) != 0,
                        }));
                    }
                }
            }
        }

        unsafe {
            CloseHandle(h_tok);
        }
        json!({
            "ok": true,
            "mode": "whoami",
            "user": user,
            "sid": user_sid,
            "elevated": elevated,
            "integrity_level": integrity_level,
            "privileges": privileges,
        })
    }

    fn format_trust_status(hr: i32) -> String {
        let code = hr as u32;
        let label = match hr {
            0 => "TRUST_E_OK",
            TRUST_E_NOSIGNATURE_CODE => "TRUST_E_NOSIGNATURE",
            TRUST_E_EXPLICIT_DISTRUST_CODE => "TRUST_E_EXPLICIT_DISTRUST",
            TRUST_E_SUBJECT_NOT_TRUSTED_CODE => "TRUST_E_SUBJECT_NOT_TRUSTED",
            CRYPT_E_SECURITY_SETTINGS_CODE => "CRYPT_E_SECURITY_SETTINGS",
            CERT_E_EXPIRED_CODE => "CERT_E_EXPIRED",
            CERT_E_UNTRUSTEDROOT_CODE => "CERT_E_UNTRUSTEDROOT",
            CERT_E_CHAINING_CODE => "CERT_E_CHAINING",
            _ => "WINVERIFYTRUST_STATUS",
        };
        format!("{label} (0x{code:08x})")
    }

    fn filetime_to_iso_utc(ft: FileTime) -> Option<String> {
        let mut st = SystemTime {
            w_year: 0,
            w_month: 0,
            w_day_of_week: 0,
            w_day: 0,
            w_hour: 0,
            w_minute: 0,
            w_second: 0,
            w_milliseconds: 0,
        };
        if unsafe { FileTimeToSystemTime(&ft, &mut st) } == 0 {
            return None;
        }
        Some(format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            st.w_year, st.w_month, st.w_day, st.w_hour, st.w_minute, st.w_second
        ))
    }

    unsafe fn cert_name_string(p_cert: *const CertContext, name_type: u32, flags: u32) -> String {
        if p_cert.is_null() {
            return String::new();
        }
        let mut buf = [0u16; 512];
        let n = CertGetNameStringW(
            p_cert,
            name_type,
            flags,
            ptr::null(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        if n <= 1 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..(n as usize - 1)])
    }

    unsafe fn cert_prop_hex(p_cert: *const CertContext, prop_id: u32) -> Option<String> {
        let mut sz = 0u32;
        if CertGetCertificateContextProperty(p_cert, prop_id, ptr::null_mut(), &mut sz) == 0
            || sz == 0
            || sz > 256
        {
            return None;
        }
        let mut buf = vec![0u8; sz as usize];
        if CertGetCertificateContextProperty(
            p_cert,
            prop_id,
            buf.as_mut_ptr() as *mut c_void,
            &mut sz,
        ) == 0
        {
            return None;
        }
        Some(
            buf[..sz as usize]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
    }

    unsafe fn extract_signer_from_state(h_state_data: Handle) -> Option<Value> {
        if h_state_data.is_null() {
            return None;
        }
        let prov_data = WTHelperProvDataFromStateData(h_state_data);
        if prov_data.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(prov_data, 0, 0, 0);
        if signer.is_null() {
            return None;
        }
        let timestamped = (*signer).cs_counter_signers > 0;
        let prov_cert = WTHelperGetProvCertFromChain(signer, 0);
        if prov_cert.is_null() || (*prov_cert).p_cert.is_null() {
            return None;
        }
        let p_cert = (*prov_cert).p_cert;
        let subject = cert_name_string(p_cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0);
        let issuer = cert_name_string(p_cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG);
        let subject_dn = cert_name_string(p_cert, CERT_NAME_RDN_TYPE, 0);
        let issuer_dn = cert_name_string(p_cert, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG);
        let sha256 = cert_prop_hex(p_cert, CERT_SHA256_HASH_PROP_ID);
        let sha1 = cert_prop_hex(p_cert, CERT_HASH_PROP_ID);

        let mut serial = String::new();
        let mut not_before = None;
        let mut not_after = None;
        if !(*p_cert).p_cert_info.is_null() {
            let info = &*(*p_cert).p_cert_info;
            if !info.serial_number.pb_data.is_null() && info.serial_number.cb_data > 0 {
                let raw_sn = core::slice::from_raw_parts(
                    info.serial_number.pb_data,
                    (info.serial_number.cb_data as usize).min(64),
                );
                serial = raw_sn
                    .iter()
                    .rev()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
            }
            not_before = filetime_to_iso_utc(info.not_before);
            not_after = filetime_to_iso_utc(info.not_after);
        }

        Some(json!({
            "subject": subject,
            "issuer": issuer,
            "subject_dn": subject_dn,
            "issuer_dn": issuer_dn,
            "serial": serial,
            "sha256": sha256,
            "sha1": sha1,
            "not_before": not_before,
            "not_after": not_after,
            "timestamped": timestamped,
        }))
    }

    pub fn query_signature(raw_path: &str) -> Value {
        let norm = normalize_win_input_path(raw_path);
        let path_obj = std::path::Path::new(&norm);
        if !path_obj.exists() {
            return json!({
                "ok": false,
                "mode": "sig",
                "path": norm,
                "error": format!("File not found: {norm}"),
            });
        }
        let abs = std::fs::canonicalize(path_obj)
            .map(|p| {
                let s = p.to_string_lossy().to_string();
                s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
            })
            .unwrap_or_else(|_| norm.clone());
        let wpath = to_wide(&abs);

        let mut file_info = WinTrustFileInfo {
            cb_struct: core::mem::size_of::<WinTrustFileInfo>() as u32,
            pcwsz_file_path: wpath.as_ptr(),
            h_file: ptr::null_mut(),
            pg_known_subject: ptr::null(),
        };
        let mut wvt = WinTrustData {
            cb_struct: core::mem::size_of::<WinTrustData>() as u32,
            p_policy_callback_data: ptr::null_mut(),
            p_sip_client_data: ptr::null_mut(),
            dw_ui_choice: WTD_UI_NONE,
            fdw_revocation_checks: WTD_REVOKE_NONE,
            dw_union_choice: WTD_CHOICE_FILE,
            p_union: (&mut file_info as *mut WinTrustFileInfo) as *mut c_void,
            dw_state_action: WTD_STATEACTION_VERIFY,
            h_wvt_state_data: ptr::null_mut(),
            pwsz_url_reference: ptr::null(),
            dw_prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            dw_ui_context: 0,
            p_signature_settings: ptr::null_mut(),
        };

        let action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let hr = unsafe { WinVerifyTrust(INVALID_HANDLE_VALUE as Handle, &action, &mut wvt) };
        let mut signer_meta = unsafe { extract_signer_from_state(wvt.h_wvt_state_data) };
        if !wvt.h_wvt_state_data.is_null() {
            wvt.dw_state_action = WTD_STATEACTION_CLOSE;
            unsafe {
                WinVerifyTrust(INVALID_HANDLE_VALUE as Handle, &action, &mut wvt);
            }
        }

        if hr != TRUST_E_NOSIGNATURE_CODE {
            let signed = hr == 0 || signer_meta.is_some();
            let mut out = json!({
                "ok": true,
                "mode": "sig",
                "path": abs,
                "signed": signed,
                "valid": hr == 0,
                "source": if signed { "embedded" } else { "unsigned" },
                "trust_status": format_trust_status(hr),
            });
            if let (Some(obj), Some(Value::Object(sm))) = (out.as_object_mut(), signer_meta) {
                for (k, v) in sm {
                    obj.insert(k, v);
                }
            }
            return out;
        }

        // Fallback: check Windows catalog-signed binaries (e.g. inbox system executables)
        let mut h_cat_admin: Handle = ptr::null_mut();
        let sha256_alg = to_wide("SHA256");
        let h_file = unsafe {
            CreateFileW(
                wpath.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_ALL,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if h_file == INVALID_HANDLE_VALUE as Handle || h_file.is_null() {
            return json!({
                "ok": true,
                "mode": "sig",
                "path": abs,
                "signed": false,
                "valid": false,
                "source": "unsigned",
                "trust_status": format_trust_status(hr),
            });
        }

        let mut cat_hr = hr;
        let mut cat_file_path: Option<String> = None;
        if unsafe {
            CryptCATAdminAcquireContext2(
                &mut h_cat_admin,
                ptr::null(),
                sha256_alg.as_ptr(),
                ptr::null(),
                0,
            )
        } != 0
            && !h_cat_admin.is_null()
        {
            let mut hash_len = 64u32;
            let mut hash_buf = vec![0u8; 64];
            if unsafe {
                CryptCATAdminCalcHashFromFileHandle2(
                    h_cat_admin,
                    h_file,
                    &mut hash_len,
                    hash_buf.as_mut_ptr(),
                    0,
                )
            } != 0
                && hash_len > 0
            {
                let h_slice = &hash_buf[..hash_len as usize];
                let h_cat_info = unsafe {
                    CryptCATAdminEnumCatalogFromHash(
                        h_cat_admin,
                        h_slice.as_ptr(),
                        hash_len,
                        0,
                        ptr::null_mut(),
                    )
                };
                if !h_cat_info.is_null() {
                    let mut ci = CatalogInfo {
                        cb_struct: core::mem::size_of::<CatalogInfo>() as u32,
                        wsz_catalog_file: [0u16; MAX_PATH_W],
                    };
                    if unsafe { CryptCATCatalogInfoFromContext(h_cat_info, &mut ci, 0) } != 0 {
                        let cat_path = unsafe { read_wide_cstr(ci.wsz_catalog_file.as_ptr()) };
                        let w_cat = to_wide(&cat_path);
                        let hex_tag: String = h_slice.iter().map(|b| format!("{b:02X}")).collect();
                        let w_tag = to_wide(&hex_tag);
                        let mut cat_info = WinTrustCatalogInfo {
                            cb_struct: core::mem::size_of::<WinTrustCatalogInfo>() as u32,
                            dw_catalog_version: 0,
                            pcwsz_catalog_file_path: w_cat.as_ptr(),
                            pcwsz_member_tag: w_tag.as_ptr(),
                            pcwsz_member_file_path: wpath.as_ptr(),
                            h_member_file: h_file,
                            pb_calculated_file_hash: h_slice.as_ptr(),
                            cb_calculated_file_hash: hash_len,
                            pc_catalog_context: ptr::null(),
                            h_cat_admin,
                        };
                        let mut cat_wvt = WinTrustData {
                            cb_struct: core::mem::size_of::<WinTrustData>() as u32,
                            p_policy_callback_data: ptr::null_mut(),
                            p_sip_client_data: ptr::null_mut(),
                            dw_ui_choice: WTD_UI_NONE,
                            fdw_revocation_checks: WTD_REVOKE_NONE,
                            dw_union_choice: WTD_CHOICE_CATALOG,
                            p_union: (&mut cat_info as *mut WinTrustCatalogInfo) as *mut c_void,
                            dw_state_action: WTD_STATEACTION_VERIFY,
                            h_wvt_state_data: ptr::null_mut(),
                            pwsz_url_reference: ptr::null(),
                            dw_prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
                            dw_ui_context: 0,
                            p_signature_settings: ptr::null_mut(),
                        };
                        cat_hr = unsafe {
                            WinVerifyTrust(INVALID_HANDLE_VALUE as Handle, &action, &mut cat_wvt)
                        };
                        signer_meta =
                            unsafe { extract_signer_from_state(cat_wvt.h_wvt_state_data) };
                        if !cat_wvt.h_wvt_state_data.is_null() {
                            cat_wvt.dw_state_action = WTD_STATEACTION_CLOSE;
                            unsafe {
                                WinVerifyTrust(
                                    INVALID_HANDLE_VALUE as Handle,
                                    &action,
                                    &mut cat_wvt,
                                );
                            }
                        }
                        cat_file_path = Some(cat_path);
                    }
                    unsafe {
                        CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
                    }
                }
            }
            unsafe {
                CryptCATAdminReleaseContext(h_cat_admin, 0);
            }
        }
        unsafe {
            CloseHandle(h_file);
        }

        let is_catalog_signed = cat_file_path.is_some();
        let mut out = json!({
            "ok": true,
            "mode": "sig",
            "path": abs,
            "signed": is_catalog_signed,
            "valid": is_catalog_signed && cat_hr == 0,
            "source": if is_catalog_signed { "catalog" } else { "unsigned" },
            "trust_status": format_trust_status(cat_hr),
        });
        if let Some(cf) = cat_file_path {
            if let Some(obj) = out.as_object_mut() {
                obj.insert("catalog_file".to_string(), Value::String(cf));
            }
        }
        if let (Some(obj), Some(Value::Object(sm))) = (out.as_object_mut(), signer_meta) {
            for (k, v) in sm {
                obj.insert(k, v);
            }
        }
        out
    }

    fn path_non_admin_write_summary(raw_path: &str) -> (bool, Option<String>, Vec<String>) {
        let info = query_acl(raw_path);
        if info.get("ok").and_then(Value::as_bool) != Some(true) {
            return (false, None, Vec::new());
        }
        let non_adm = info
            .get("non_admin_writable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let sddl = info.get("sddl").and_then(Value::as_str).map(str::to_string);
        let trustees: Vec<String> = info
            .get("aces")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter(|a| a.get("non_admin_write").and_then(Value::as_bool) == Some(true))
                    .filter_map(|a| {
                        let t = a.get("trustee").and_then(Value::as_str)?;
                        let r = a.get("rights").and_then(Value::as_str).unwrap_or("");
                        Some(format!("{t}:{r}"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        (non_adm, sddl, trustees)
    }

    fn query_reg_key_non_admin_write(raw_subkey: &str) -> (bool, Option<String>) {
        let sub_w = to_wide(raw_subkey);
        let mut hk: isize = 0;
        if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub_w.as_ptr(), 0, READ_CONTROL, &mut hk) }
            != 0
        {
            return (false, None);
        }
        let mut needed = 0u32;
        let rc = unsafe {
            RegGetKeySecurity(hk, DACL_SECURITY_INFORMATION, ptr::null_mut(), &mut needed)
        };
        let mut res = (false, None);
        if (rc == 0 || rc == 122) && needed > 0 && needed <= 65_536 {
            let mut buf = vec![0u8; needed as usize + 16];
            if unsafe {
                RegGetKeySecurity(
                    hk,
                    DACL_SECURITY_INFORMATION,
                    buf.as_mut_ptr() as *mut c_void,
                    &mut needed,
                )
            } == 0
            {
                if let Some(sddl) =
                    unsafe { sd_to_sddl(buf.as_ptr() as *const c_void, DACL_SECURITY_INFORMATION) }
                {
                    let (_prot, aces) = parse_sddl_aces(&sddl);
                    res = (aces.iter().any(|a| a.non_admin_write), Some(sddl));
                }
            }
        }
        unsafe {
            RegCloseKey(hk);
        }
        res
    }

    fn read_reg_default_str(root: isize, subkey: &str, value_name: Option<&str>) -> Option<String> {
        let sub_w = to_wide(subkey);
        let mut hk: isize = 0;
        if unsafe { RegOpenKeyExW(root, sub_w.as_ptr(), 0, KEY_READ, &mut hk) } != 0 {
            return None;
        }
        let val_w = value_name.map(to_wide);
        let val_ptr = val_w.as_ref().map(|v| v.as_ptr()).unwrap_or(ptr::null());
        let mut ty = 0u32;
        let mut dlen = 1024u32;
        let mut dbuf = vec![0u8; dlen as usize];
        let mut rc = unsafe {
            RegQueryValueExW(
                hk,
                val_ptr,
                ptr::null_mut(),
                &mut ty,
                dbuf.as_mut_ptr(),
                &mut dlen,
            )
        };
        if rc == ERROR_MORE_DATA && dlen <= 32_768 {
            dbuf.resize(dlen as usize, 0);
            rc = unsafe {
                RegQueryValueExW(
                    hk,
                    val_ptr,
                    ptr::null_mut(),
                    &mut ty,
                    dbuf.as_mut_ptr(),
                    &mut dlen,
                )
            };
        }
        unsafe {
            RegCloseKey(hk);
        }
        if rc != 0 || dlen == 0 {
            return None;
        }
        let (_k, v) = decode_reg_value(ty, &dbuf[..dlen as usize]);
        v.as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    fn read_reg_dword(root: isize, subkey: &str, value_name: &str) -> Option<u32> {
        let sub_w = to_wide(subkey);
        let mut hk: isize = 0;
        if unsafe { RegOpenKeyExW(root, sub_w.as_ptr(), 0, KEY_READ, &mut hk) } != 0 {
            return None;
        }
        let val_w = to_wide(value_name);
        let mut ty = 0u32;
        let mut buf = [0u8; 8];
        let mut dlen = buf.len() as u32;
        let rc = unsafe {
            RegQueryValueExW(
                hk,
                val_w.as_ptr(),
                ptr::null_mut(),
                &mut ty,
                buf.as_mut_ptr(),
                &mut dlen,
            )
        };
        unsafe {
            RegCloseKey(hk);
        }
        if rc == 0 && ty == 4 && dlen >= 4 {
            Some(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
        } else {
            None
        }
    }

    type ServiceRawTuple = (String, String, &'static str, u32, String, String, String);

    fn collect_all_services_raw() -> Result<Vec<ServiceRawTuple>, String> {
        let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ENUMERATE_SERVICE) };
        if scm.is_null() {
            return Err(format!("OpenSCManagerW failed (err={})", unsafe {
                GetLastError()
            }));
        }
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                ptr::null_mut(),
                0,
                &mut needed,
                &mut count,
                &mut resume,
                ptr::null(),
            );
        }
        let mut buf = vec![0u8; needed as usize + 8192];
        let mut count2 = 0u32;
        let mut resume2 = 0u32;
        let ok = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut needed,
                &mut count2,
                &mut resume2,
                ptr::null(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            unsafe {
                CloseServiceHandle(scm);
            }
            return Err(format!("EnumServicesStatusExW failed (err={err})"));
        }
        let mut out = Vec::with_capacity(count2 as usize);
        let ptr_base = buf.as_ptr() as *const EnumServiceStatusProcessW;
        for i in 0..(count2 as usize) {
            let item = unsafe { &*ptr_base.add(i) };
            let name = unsafe { read_wide_cstr(item.lp_service_name) };
            let display_name = unsafe { read_wide_cstr(item.lp_display_name) };
            let mut bin_path = String::new();
            let mut account = String::new();
            let mut start_type = "Unknown".to_string();
            let hs = unsafe { OpenServiceW(scm, item.lp_service_name, SERVICE_QUERY_CONFIG) };
            if !hs.is_null() {
                let mut cfg_need = 0u32;
                unsafe { QueryServiceConfigW(hs, ptr::null_mut(), 0, &mut cfg_need) };
                if cfg_need > 0 && cfg_need <= 65536 {
                    let mut cbuf = vec![0u8; cfg_need as usize + 64];
                    if unsafe {
                        QueryServiceConfigW(hs, cbuf.as_mut_ptr(), cbuf.len() as u32, &mut cfg_need)
                    } != 0
                    {
                        let cfg = unsafe { &*(cbuf.as_ptr() as *const QueryServiceConfigWHeader) };
                        start_type = start_type_str(cfg.dw_start_type).to_string();
                        bin_path = unsafe { read_wide_cstr(cfg.lp_binary_path_name) };
                        account = unsafe { read_wide_cstr(cfg.lp_service_start_name) };
                    }
                }
                unsafe {
                    CloseServiceHandle(hs);
                }
            }
            out.push((
                name,
                display_name,
                state_str(item.service_status_process.dw_current_state),
                item.service_status_process.dw_process_id,
                start_type,
                bin_path,
                account,
            ));
        }
        unsafe {
            CloseServiceHandle(scm);
        }
        Ok(out)
    }

    #[cfg(test)]
    pub fn query_unquoted_services(filter: Option<&str>, max: usize) -> Value {
        query_unquoted_services_opts(filter, max, false)
    }

    pub fn query_unquoted_services_opts(filter: Option<&str>, max: usize, non_ms: bool) -> Value {
        let services = match collect_all_services_raw() {
            Ok(s) => s,
            Err(e) => return json!({ "ok": false, "mode": "unquoted", "error": e }),
        };
        let f_low = filter.map(|s| s.to_ascii_lowercase());
        let cap = max.clamp(1, 200);
        let mut findings = Vec::new();
        let mut exploitable_count = 0usize;
        for (name, display_name, state, pid, start_type, bin_path, account) in services {
            if let Some(ref fl) = f_low {
                if !name.to_ascii_lowercase().contains(fl)
                    && !display_name.to_ascii_lowercase().contains(fl)
                    && !bin_path.to_ascii_lowercase().contains(fl)
                {
                    continue;
                }
            }
            if non_ms {
                let exe_low = super::resolve_windows_exe_candidate(
                    &super::extract_service_exe_path(&bin_path),
                )
                .to_ascii_lowercase();
                if super::is_ms_os_path(&exe_low) {
                    continue;
                }
            }
            let hops = super::find_unquoted_space_prefixes(&bin_path);
            if hops.is_empty() {
                continue;
            }
            let mut writable_hops = Vec::new();
            let mut candidate_bins = Vec::new();
            for (cand_exe, parent_dir) in hops {
                candidate_bins.push(cand_exe.clone());
                let (w, _sddl, trustees) = path_non_admin_write_summary(&parent_dir);
                if w {
                    writable_hops.push(json!({
                        "hijack_exe": cand_exe,
                        "writable_dir": parent_dir,
                        "trustees": trustees,
                    }));
                }
            }
            let exploitable = !writable_hops.is_empty();
            if exploitable {
                exploitable_count += 1;
            }
            if findings.len() < cap {
                findings.push(json!({
                    "service": name,
                    "display_name": display_name,
                    "state": state,
                    "pid": pid,
                    "start_type": start_type,
                    "account": account,
                    "bin_path": bin_path,
                    "candidate_hijack_paths": candidate_bins,
                    "writable_hops": writable_hops,
                    "exploitable": exploitable,
                }));
            }
        }
        findings.sort_by_key(|v| !v["exploitable"].as_bool().unwrap_or(false));
        json!({
            "ok": true,
            "mode": "unquoted",
            "returned": findings.len(),
            "exploitable_count": exploitable_count,
            "findings": findings,
        })
    }

    #[cfg(test)]
    pub fn query_weak_acl(
        target_or_empty: Option<&str>,
        filter: Option<&str>,
        max: usize,
    ) -> Value {
        query_weak_acl_with_cache(target_or_empty, filter, max, false, None, None)
    }

    pub fn query_weak_acl_opts(
        target_or_empty: Option<&str>,
        filter: Option<&str>,
        max: usize,
        non_ms: bool,
    ) -> Value {
        query_weak_acl_with_cache(target_or_empty, filter, max, non_ms, None, None)
    }

    pub fn query_weak_acl_with_cache(
        target_or_empty: Option<&str>,
        filter: Option<&str>,
        max: usize,
        non_ms: bool,
        cached_proc_map: Option<&std::collections::HashMap<u32, &ProcessIlInfo>>,
        cached_all_pipes: Option<&[Value]>,
    ) -> Value {
        let cap = max.clamp(1, 200);
        let raw_tgt = target_or_empty.map(str::trim).filter(|s| !s.is_empty());
        if let Some(tgt) = raw_tgt {
            let norm = normalize_win_input_path(tgt);
            let p = std::path::Path::new(&norm);
            if p.exists() {
                let mut weak_paths = Vec::new();
                let mut scanned = 0usize;
                let walker = ignore::WalkBuilder::new(p)
                    .max_depth(Some(3))
                    .hidden(false)
                    .git_ignore(false)
                    .build();
                let f_low = filter.map(|s| s.to_ascii_lowercase());
                for entry in walker.flatten() {
                    if scanned >= 1500 {
                        break;
                    }
                    let ep = entry.path();
                    let ps = ep.to_string_lossy().to_string();
                    if let Some(ref fl) = f_low {
                        if !ps.to_ascii_lowercase().contains(fl) {
                            continue;
                        }
                    }
                    scanned += 1;
                    let (w, sddl, trustees) = path_non_admin_write_summary(&ps);
                    if w {
                        weak_paths.push(json!({
                            "path": ps,
                            "is_dir": ep.is_dir(),
                            "trustees": trustees,
                            "sddl": sddl,
                        }));
                        if weak_paths.len() >= cap {
                            break;
                        }
                    }
                }
                return json!({
                    "ok": true,
                    "mode": "weak_acl_path",
                    "root": norm,
                    "scanned": scanned,
                    "weak_count": weak_paths.len(),
                    "findings": weak_paths,
                });
            }
        }

        // OS-wide non-admin write attack-surface sweep (pipes + services/bins/regkeys + unquoted)
        let eff_filter = filter.or(raw_tgt);
        let f_low = eff_filter.map(|s| s.to_ascii_lowercase());
        let mut weak_pipes = Vec::new();
        if let Some(all_pipes) = cached_all_pipes {
            for p in all_pipes {
                if p.get("non_admin_write").and_then(Value::as_bool) != Some(true) {
                    continue;
                }
                let nm_low = p
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if let Some(ref fl) = f_low {
                    if !nm_low.contains(fl) {
                        continue;
                    }
                }
                if non_ms && super::is_ms_os_pipe(&nm_low) {
                    continue;
                }
                weak_pipes.push(p.clone());
                if weak_pipes.len() >= cap {
                    break;
                }
            }
        } else {
            let owned_procs;
            let owned_map;
            let pm_ref: &std::collections::HashMap<u32, &ProcessIlInfo> = match cached_proc_map {
                Some(m) => m,
                None => {
                    owned_procs = collect_processes_il().unwrap_or_default();
                    owned_map = owned_procs.iter().map(|p| (p.pid, p)).collect();
                    &owned_map
                }
            };
            let pipe_res =
                query_pipes_with_cache(eff_filter, usize::MAX, non_ms, false, Some(pm_ref), false);
            if let Some(arr) = pipe_res.get("pipes").and_then(Value::as_array) {
                for p in arr {
                    if p.get("non_admin_write").and_then(Value::as_bool) == Some(true) {
                        weak_pipes.push(p.clone());
                        if weak_pipes.len() >= cap {
                            break;
                        }
                    }
                }
            }
        }

        let mut weak_services = Vec::new();
        let mut unquoted_services = Vec::new();
        let mut checked_dirs: std::collections::HashMap<String, (bool, Vec<String>)> =
            std::collections::HashMap::new();
        if let Ok(svcs) = collect_all_services_raw() {
            for (name, _disp, state, _pid, start_type, bin_path, account) in svcs {
                if let Some(ref fl) = f_low {
                    if !name.to_ascii_lowercase().contains(fl)
                        && !bin_path.to_ascii_lowercase().contains(fl)
                    {
                        continue;
                    }
                }
                let exe = super::resolve_windows_exe_candidate(&super::extract_service_exe_path(
                    &bin_path,
                ));
                if exe.is_empty() {
                    continue;
                }
                let exe_low = exe.to_ascii_lowercase();
                let is_sys_exe = super::is_ms_os_path(&exe_low);
                if non_ms && is_sys_exe {
                    continue;
                }
                let mut issues = Vec::new();
                if !is_sys_exe && std::path::Path::new(&exe).exists() {
                    let (ew, _esddl, et) = path_non_admin_write_summary(&exe);
                    if ew {
                        issues
                            .push(json!({ "kind": "service_binary", "path": exe, "trustees": et }));
                    }
                    if let Some(pdir) = std::path::Path::new(&exe).parent() {
                        let pds = pdir.to_string_lossy().to_string();
                        let (dw, dt) = checked_dirs.entry(pds.clone()).or_insert_with(|| {
                            let (w, _s, t) = path_non_admin_write_summary(&pds);
                            (w, t)
                        });
                        if *dw {
                            issues.push(
                                json!({ "kind": "service_dir", "path": pds, "trustees": dt }),
                            );
                        }
                    }
                }
                let svc_reg = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
                let (rw, rsddl) = query_reg_key_non_admin_write(&svc_reg);
                if rw {
                    issues.push(json!({ "kind": "service_regkey", "key": format!("HKLM\\{svc_reg}"), "sddl": rsddl }));
                }
                if !issues.is_empty() && weak_services.len() < cap {
                    weak_services.push(json!({
                        "service": name,
                        "state": state,
                        "start_type": start_type,
                        "account": account,
                        "bin_path": bin_path,
                        "issues": issues,
                    }));
                }
                let hops = super::find_unquoted_space_prefixes(&bin_path);
                if !hops.is_empty() && unquoted_services.len() < cap {
                    let writable_hops: Vec<Value> = hops
                        .into_iter()
                        .filter_map(|(ce, pd)| {
                            let (w, dt) = checked_dirs.entry(pd.clone()).or_insert_with(|| {
                                let (w, _s, t) = path_non_admin_write_summary(&pd);
                                (w, t)
                            });
                            if *w {
                                Some(
                                    json!({ "hijack_exe": ce, "writable_dir": pd, "trustees": dt }),
                                )
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !writable_hops.is_empty() {
                        unquoted_services.push(json!({
                            "service": name,
                            "account": account,
                            "bin_path": bin_path,
                            "writable_hops": writable_hops,
                        }));
                    }
                }
            }
        }

        json!({
            "ok": true,
            "mode": "weak_acl",
            "weak_pipes_count": weak_pipes.len(),
            "weak_services_count": weak_services.len(),
            "exploitable_unquoted_count": unquoted_services.len(),
            "weak_pipes": weak_pipes,
            "weak_services": weak_services,
            "exploitable_unquoted": unquoted_services,
        })
    }

    #[cfg(test)]
    pub fn query_com_audit(filter: Option<&str>, max: usize) -> Value {
        query_com_audit_opts(filter, max, false)
    }

    pub fn query_com_audit_opts(filter: Option<&str>, max: usize, non_ms: bool) -> Value {
        let root_sub = r"SOFTWARE\Classes\CLSID";
        let root_w = to_wide(root_sub);
        let mut h_clsid: isize = 0;
        if unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                root_w.as_ptr(),
                0,
                KEY_READ,
                &mut h_clsid,
            )
        } != 0
        {
            return json!({ "ok": false, "mode": "com", "error": "Failed to open HKLM\\SOFTWARE\\Classes\\CLSID" });
        }
        let f_low = filter.map(|s| s.to_ascii_lowercase());
        let cap = max.clamp(1, 200);
        let mut scanned = 0usize;
        let mut findings = Vec::new();
        let mut idx = 0u32;
        while scanned < 2500 && findings.len() < cap {
            let mut kbuf = [0u16; 128];
            let mut klen = kbuf.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(
                    h_clsid,
                    idx,
                    kbuf.as_mut_ptr(),
                    &mut klen,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            idx += 1;
            if rc != 0 {
                continue;
            }
            scanned += 1;
            let clsid = String::from_utf16_lossy(&kbuf[..klen as usize]);
            let base = format!(r"{root_sub}\{clsid}");
            let label = read_reg_default_str(HKEY_LOCAL_MACHINE, &base, None).unwrap_or_default();
            let local_srv =
                read_reg_default_str(HKEY_LOCAL_MACHINE, &format!(r"{base}\LocalServer32"), None);
            let inproc_srv =
                read_reg_default_str(HKEY_LOCAL_MACHINE, &format!(r"{base}\InprocServer32"), None);
            if local_srv.is_none() && inproc_srv.is_none() {
                continue;
            }
            let auto_elev =
                read_reg_dword(HKEY_LOCAL_MACHINE, &format!(r"{base}\Elevation"), "Enabled")
                    == Some(1);
            let target_raw = local_srv.as_deref().or(inproc_srv.as_deref()).unwrap_or("");
            if let Some(ref fl) = f_low {
                if !clsid.to_ascii_lowercase().contains(fl)
                    && !label.to_ascii_lowercase().contains(fl)
                    && !target_raw.to_ascii_lowercase().contains(fl)
                {
                    continue;
                }
            }
            let raw_extracted = super::extract_service_exe_path(target_raw);
            let target_exe = super::resolve_windows_exe_candidate(&raw_extracted);
            let low_exe = target_exe.to_ascii_lowercase();
            let is_sys = super::is_ms_os_path(&low_exe);
            let bare_name_only =
                !target_exe.is_empty() && !target_exe.contains('\\') && !target_exe.contains('/');
            let missing = !target_exe.is_empty()
                && !target_exe.contains('%')
                && !bare_name_only
                && !std::path::Path::new(&target_exe).exists();
            let (writable, _sddl, trustees) = if !is_sys && !target_exe.is_empty() && !missing {
                path_non_admin_write_summary(&target_exe)
            } else {
                (false, None, Vec::new())
            };
            if non_ms && (is_sys || bare_name_only) && !writable && !auto_elev {
                continue;
            }
            if f_low.is_some() || missing || writable || auto_elev {
                findings.push(json!({
                    "clsid": clsid,
                    "name": label,
                    "server_kind": if local_srv.is_some() { "LocalServer32" } else { "InprocServer32" },
                    "target_raw": target_raw,
                    "target_path": target_exe,
                    "missing_target": missing,
                    "non_admin_writable": writable,
                    "writable_trustees": trustees,
                    "auto_elevate": auto_elev,
                }));
            }
        }
        unsafe {
            RegCloseKey(h_clsid);
        }
        json!({
            "ok": true,
            "mode": "com",
            "scanned_clsids": scanned,
            "returned": findings.len(),
            "findings": findings,
        })
    }

    #[cfg(test)]
    pub fn query_rpc_endpoints(filter: Option<&str>, max: usize) -> Value {
        query_rpc_endpoints_with_cache(filter, max, false, None)
    }

    pub fn query_rpc_endpoints_opts(filter: Option<&str>, max: usize, non_ms: bool) -> Value {
        query_rpc_endpoints_with_cache(filter, max, non_ms, None)
    }

    pub fn query_rpc_endpoints_with_cache(
        filter: Option<&str>,
        max: usize,
        non_ms: bool,
        cached_all_pipes: Option<&[Value]>,
    ) -> Value {
        let mut inq: Handle = ptr::null_mut();
        let rc = unsafe {
            RpcMgmtEpEltInqBegin(
                ptr::null_mut(),
                RPC_C_EP_ALL_ELTS,
                ptr::null(),
                RPC_C_VERS_ALL,
                ptr::null(),
                &mut inq,
            )
        };
        if rc != RPC_S_OK {
            return json!({
                "ok": false,
                "mode": "rpc",
                "error": format!("RpcMgmtEpEltInqBegin failed (rpc_status={rc})"),
            });
        }

        // Cross-link all named pipes for `ncacn_np` weak-ACL visibility (reusing cached pipe sweep when available)
        let mut weak_pipe_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let owned_pipe_res;
        let pipe_slice: Option<&[Value]> = match cached_all_pipes {
            Some(s) => Some(s),
            None => {
                owned_pipe_res =
                    query_pipes_with_cache(None, usize::MAX, false, false, None, false);
                owned_pipe_res
                    .get("pipes")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
            }
        };
        if let Some(arr) = pipe_slice {
            for p in arr {
                if p.get("non_admin_write").and_then(Value::as_bool) == Some(true) {
                    if let Some(nm) = p.get("name").and_then(Value::as_str) {
                        weak_pipe_set.insert(nm.to_ascii_lowercase());
                    }
                }
            }
        }

        let f_low = filter.map(|s| s.to_ascii_lowercase());
        let cap = max.clamp(1, 200);
        let mut endpoints = Vec::new();
        let mut total_matched = 0usize;
        let mut seen = std::collections::HashSet::new();

        for _ in 0..4000 {
            let mut if_id = RpcIfId {
                uuid: Guid {
                    data1: 0,
                    data2: 0,
                    data3: 0,
                    data4: [0; 8],
                },
                vers_major: 0,
                vers_minor: 0,
            };
            let mut binding: Handle = ptr::null_mut();
            let mut obj_uuid = Guid {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            };
            let mut ann_ptr: *mut u16 = ptr::null_mut();
            let nrc = unsafe {
                RpcMgmtEpEltInqNextW(inq, &mut if_id, &mut binding, &mut obj_uuid, &mut ann_ptr)
            };
            if nrc == RPC_X_NO_MORE_ENTRIES || nrc != RPC_S_OK {
                if !ann_ptr.is_null() {
                    unsafe { RpcStringFreeW(&mut ann_ptr) };
                }
                if !binding.is_null() {
                    unsafe { RpcBindingFree(&mut binding) };
                }
                break;
            }
            let annotation = if !ann_ptr.is_null() {
                let s = unsafe { read_wide_cstr(ann_ptr) };
                unsafe { RpcStringFreeW(&mut ann_ptr) };
                s
            } else {
                String::new()
            };

            let mut uuid_ptr: *mut u16 = ptr::null_mut();
            let uuid_str = if unsafe { UuidToStringW(&if_id.uuid, &mut uuid_ptr) } == RPC_S_OK
                && !uuid_ptr.is_null()
            {
                let s = unsafe { read_wide_cstr(uuid_ptr) };
                unsafe { RpcStringFreeW(&mut uuid_ptr) };
                s
            } else {
                String::new()
            };

            let mut sb_ptr: *mut u16 = ptr::null_mut();
            let str_binding = if !binding.is_null()
                && unsafe { RpcBindingToStringBindingW(binding, &mut sb_ptr) } == RPC_S_OK
                && !sb_ptr.is_null()
            {
                let s = unsafe { read_wide_cstr(sb_ptr) };
                unsafe { RpcStringFreeW(&mut sb_ptr) };
                s
            } else {
                String::new()
            };
            if !binding.is_null() {
                unsafe { RpcBindingFree(&mut binding) };
            }

            let protseq = str_binding.split(':').next().unwrap_or("").to_string();
            let endpoint = str_binding
                .split('[')
                .nth(1)
                .and_then(|r| r.split(']').next())
                .unwrap_or("")
                .to_string();
            let key = format!("{uuid_str}|{}|{str_binding}", if_id.vers_major);
            if !seen.insert(key) {
                continue;
            }
            if let Some(ref fl) = f_low {
                if !uuid_str.to_ascii_lowercase().contains(fl)
                    && !str_binding.to_ascii_lowercase().contains(fl)
                    && !annotation.to_ascii_lowercase().contains(fl)
                {
                    continue;
                }
            }
            let pipe_short = endpoint
                .trim_start_matches(r"\pipe\")
                .trim_start_matches(r"\\.\pipe\")
                .to_ascii_lowercase();
            let weak_pipe =
                protseq.eq_ignore_ascii_case("ncacn_np") && weak_pipe_set.contains(&pipe_short);
            if non_ms
                && super::is_ms_os_rpc(
                    &str_binding.to_ascii_lowercase(),
                    &annotation.to_ascii_lowercase(),
                    weak_pipe,
                )
            {
                continue;
            }
            total_matched += 1;
            if endpoints.len() < cap {
                endpoints.push(json!({
                    "uuid": uuid_str,
                    "version": format!("{}.{}", if_id.vers_major, if_id.vers_minor),
                    "protseq": protseq,
                    "endpoint": endpoint,
                    "binding": str_binding,
                    "annotation": annotation,
                    "weak_pipe_acl": weak_pipe,
                }));
            }
        }
        unsafe {
            RpcMgmtEpEltInqDone(&mut inq);
        }
        json!({
            "ok": true,
            "mode": "rpc",
            "total_matched": total_matched,
            "returned": endpoints.len(),
            "endpoints": endpoints,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_win_cli(
    pipes: bool,
    reg: Option<&str>,
    acl: Option<&str>,
    services: bool,
    whoami: bool,
    sig: Option<&std::path::Path>,
    weak_acl: Option<&str>,
    unquoted: bool,
    com: bool,
    rpc: bool,
    non_ms: bool,
    filter: Option<&str>,
    max: usize,
    as_json: bool,
) -> i32 {
    run_win_cli_ex(
        pipes, reg, acl, services, whoami, sig, weak_acl, unquoted, com, rpc, false, false, non_ms,
        filter, max, as_json,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_win_cli_ex(
    pipes: bool,
    reg: Option<&str>,
    acl: Option<&str>,
    services: bool,
    whoami: bool,
    sig: Option<&std::path::Path>,
    weak_acl: Option<&str>,
    unquoted: bool,
    com: bool,
    rpc: bool,
    procs: bool,
    all: bool,
    non_ms: bool,
    filter: Option<&str>,
    max: usize,
    as_json: bool,
) -> i32 {
    #[cfg(not(windows))]
    {
        let _ = (
            pipes, reg, acl, services, whoami, sig, weak_acl, unquoted, com, rpc, procs, all,
            non_ms, filter, max,
        );
        let out = json!({
            "ok": false,
            "os": std::env::consts::OS,
            "error": "ap probe win requires Windows",
        });
        if as_json {
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        } else {
            eprintln!(
                "[ap probe win] requires Windows (current OS: {})",
                std::env::consts::OS
            );
        }
        2
    }
    #[cfg(windows)]
    {
        let mode_count = usize::from(pipes)
            + usize::from(reg.is_some())
            + usize::from(acl.is_some())
            + usize::from(services)
            + usize::from(whoami)
            + usize::from(sig.is_some())
            + usize::from(weak_acl.is_some())
            + usize::from(unquoted)
            + usize::from(com)
            + usize::from(rpc)
            + usize::from(procs);
        if mode_count == 0 && !all {
            let msg = "[ap probe win] Pass one or more of --all, --pipes, --reg <KEY>, --acl <PATH>, --services, --whoami, --sig <PATH>, --weak-acl [PATH], --unquoted, --com, --rpc, or --procs";
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "ok": false, "error": msg }))
                        .unwrap_or_default()
                );
            } else {
                eprintln!("{msg}");
            }
            return 2;
        }
        let val = if !all && mode_count == 1 {
            if let Some(wa) = weak_acl {
                imp::query_weak_acl_opts(Some(wa), filter, max, non_ms)
            } else if unquoted {
                imp::query_unquoted_services_opts(filter, max, non_ms)
            } else if com {
                imp::query_com_audit_opts(filter, max, non_ms)
            } else if rpc {
                imp::query_rpc_endpoints_opts(filter, max, non_ms)
            } else if procs {
                imp::query_procs_opts(filter, max, non_ms, None)
            } else if let Some(sp) = sig {
                imp::query_signature(&sp.to_string_lossy())
            } else if let Some(rk) = reg {
                imp::query_registry(rk, filter, max)
            } else if let Some(ap) = acl {
                imp::query_acl(ap)
            } else if pipes {
                let pv = imp::collect_processes_il().unwrap_or_default();
                let pm: std::collections::HashMap<u32, &imp::ProcessIlInfo> =
                    pv.iter().map(|p| (p.pid, p)).collect();
                imp::query_pipes_with_cache(filter, max, non_ms, true, Some(&pm), true)
            } else if services {
                imp::query_services_opts(filter, max, non_ms)
            } else {
                imp::query_whoami()
            }
        } else {
            // Combined single-shot mode (`--all` or >=2 flags): preserve all single-mode top-level keys + `sections`
            let run_weak_acl = all || weak_acl.is_some();
            let run_com = all || com;
            let run_rpc = all || rpc;
            let run_procs = all || procs;

            // Collect process IL table ONCE and share across procs/weak_acl/pipes
            let cached_procs = if run_procs || run_weak_acl || pipes {
                imp::collect_processes_il().ok()
            } else {
                None
            };
            let proc_map: Option<std::collections::HashMap<u32, &imp::ProcessIlInfo>> =
                cached_procs
                    .as_ref()
                    .map(|v| v.iter().map(|p| (p.pid, p)).collect());

            // Deduplicate named-pipe enumeration when >=2 pipe-consuming sections run together
            let weak_acl_needs_pipes = run_weak_acl
                && weak_acl
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| !std::path::Path::new(&normalize_win_input_path(s)).exists())
                    .unwrap_or(true);
            let pipe_consumers =
                usize::from(weak_acl_needs_pipes) + usize::from(run_rpc) + usize::from(pipes);
            let cached_all_pipes: Option<Vec<Value>> = if pipe_consumers >= 2 {
                imp::query_pipes_with_cache(
                    None,
                    usize::MAX,
                    false,
                    false,
                    proc_map.as_ref(),
                    pipes,
                )
                .get("pipes")
                .and_then(Value::as_array)
                .cloned()
            } else {
                None
            };

            let mut modes_run: Vec<&str> = Vec::new();
            let mut failed_sections: Vec<&str> = Vec::new();
            let mut sections = serde_json::Map::new();
            let mut combined = serde_json::Map::new();
            let mut all_ok = true;

            let mut record_section = |name: &'static str, v: &Value| {
                if v.get("ok").and_then(Value::as_bool) != Some(true) {
                    all_ok = false;
                    failed_sections.push(name);
                }
            };

            if run_weak_acl {
                modes_run.push("weak_acl");
                let wa_arg = weak_acl.unwrap_or("");
                let wa = imp::query_weak_acl_with_cache(
                    Some(wa_arg),
                    filter,
                    max,
                    non_ms,
                    proc_map.as_ref(),
                    cached_all_pipes.as_deref(),
                );
                record_section("weak_acl", &wa);
                for key in [
                    "weak_pipes_count",
                    "weak_services_count",
                    "exploitable_unquoted_count",
                    "weak_pipes",
                    "weak_services",
                    "exploitable_unquoted",
                ] {
                    if let Some(v) = wa.get(key) {
                        combined.insert(key.to_string(), v.clone());
                    }
                }
                if let Some(f) = wa.get("findings") {
                    combined.insert("weak_acl_findings".to_string(), f.clone());
                    if !run_com {
                        combined.insert("findings".to_string(), f.clone());
                    }
                }
                sections.insert("weak_acl".to_string(), wa);
            }
            if run_com {
                modes_run.push("com");
                let c = imp::query_com_audit_opts(filter, max, non_ms);
                record_section("com", &c);
                if let Some(f) = c.get("findings") {
                    combined.insert("findings".to_string(), f.clone());
                }
                if let Some(sc) = c.get("scanned_clsids") {
                    combined.insert("scanned_clsids".to_string(), sc.clone());
                }
                sections.insert("com".to_string(), c);
            }
            if run_rpc {
                modes_run.push("rpc");
                let r = imp::query_rpc_endpoints_with_cache(
                    filter,
                    max,
                    non_ms,
                    cached_all_pipes.as_deref(),
                );
                record_section("rpc", &r);
                if let Some(ep) = r.get("endpoints") {
                    combined.insert("endpoints".to_string(), ep.clone());
                }
                sections.insert("rpc".to_string(), r);
            }
            if run_procs {
                modes_run.push("procs");
                let pr = imp::query_procs_opts(filter, max, non_ms, cached_procs.as_deref());
                record_section("procs", &pr);
                if let Some(arr) = pr.get("processes") {
                    combined.insert("processes".to_string(), arr.clone());
                }
                sections.insert("procs".to_string(), pr);
            }
            if pipes {
                modes_run.push("pipes");
                let pp = if let Some(ref all_p) = cached_all_pipes {
                    let f_low = filter.map(|s| s.to_ascii_lowercase());
                    let cap = max.clamp(1, 200);
                    let mut total_matched = 0usize;
                    let mut filtered_p = Vec::new();
                    for p in all_p {
                        let nm_low = p
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if let Some(ref fl) = f_low {
                            if !nm_low.contains(fl) {
                                continue;
                            }
                        }
                        if non_ms && is_ms_os_pipe(&nm_low) {
                            continue;
                        }
                        total_matched += 1;
                        if filtered_p.len() < cap {
                            filtered_p.push(p.clone());
                        }
                    }
                    json!({
                        "ok": true,
                        "mode": "pipes",
                        "total_matched": total_matched,
                        "returned": filtered_p.len(),
                        "pipes": filtered_p,
                    })
                } else {
                    imp::query_pipes_with_cache(filter, max, non_ms, true, proc_map.as_ref(), true)
                };
                record_section("pipes", &pp);
                if let Some(arr) = pp.get("pipes") {
                    combined.insert("pipes".to_string(), arr.clone());
                }
                sections.insert("pipes".to_string(), pp);
            }
            if services {
                modes_run.push("services");
                let sv = imp::query_services_opts(filter, max, non_ms);
                record_section("services", &sv);
                if let Some(arr) = sv.get("services") {
                    combined.insert("services".to_string(), arr.clone());
                }
                sections.insert("services".to_string(), sv);
            }
            if unquoted {
                modes_run.push("unquoted");
                let uq = imp::query_unquoted_services_opts(filter, max, non_ms);
                record_section("unquoted", &uq);
                if let Some(arr) = uq.get("findings") {
                    combined.insert("unquoted_findings".to_string(), arr.clone());
                    if !combined.contains_key("findings") {
                        combined.insert("findings".to_string(), arr.clone());
                    }
                }
                sections.insert("unquoted".to_string(), uq);
            }
            if whoami {
                modes_run.push("whoami");
                let wh = imp::query_whoami();
                record_section("whoami", &wh);
                combined.insert("whoami".to_string(), wh.clone());
                sections.insert("whoami".to_string(), wh);
            }
            if let Some(rk) = reg {
                modes_run.push("reg");
                let rg = imp::query_registry(rk, filter, max);
                record_section("reg", &rg);
                combined.insert("reg".to_string(), rg.clone());
                sections.insert("reg".to_string(), rg);
            }
            if let Some(ap) = acl {
                modes_run.push("acl");
                let ac = imp::query_acl(ap);
                record_section("acl", &ac);
                combined.insert("acl".to_string(), ac.clone());
                sections.insert("acl".to_string(), ac);
            }
            if let Some(sp) = sig {
                modes_run.push("sig");
                let sg = imp::query_signature(&sp.to_string_lossy());
                record_section("sig", &sg);
                combined.insert("sig".to_string(), sg.clone());
                sections.insert("sig".to_string(), sg);
            }

            combined.insert(
                "ok".to_string(),
                Value::Bool(all_ok && !modes_run.is_empty()),
            );
            combined.insert("mode".to_string(), json!("combined"));
            combined.insert("modes_run".to_string(), json!(modes_run));
            if !failed_sections.is_empty() {
                combined.insert("failed_sections".to_string(), json!(failed_sections));
            }
            combined.insert("non_ms".to_string(), Value::Bool(non_ms));
            if let Some(fl) = filter {
                combined.insert("filter".to_string(), json!(fl));
            }
            combined.insert("sections".to_string(), Value::Object(sections));
            Value::Object(combined)
        };
        let ok = val.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let serialized = if as_json {
            serde_json::to_string_pretty(&val).unwrap_or_default()
        } else {
            format_win_human(&val)
        };
        println!("{serialized}");
        if ok {
            0
        } else {
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sddl_aces_detects_non_admin_write_and_protected_dacl() {
        let sddl = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;;GW;;;AU)";
        let (protected, aces) = parse_sddl_aces(sddl);
        assert!(protected);
        assert_eq!(aces.len(), 3);
        assert!(!aces[0].non_admin_write);
        assert!(!aces[1].non_admin_write);
        assert!(aces[2].non_admin_write);
        assert_eq!(aces[2].trustee, "AU");
    }

    #[test]
    fn unquoted_path_and_service_exe_extraction_work_cleanly() {
        assert_eq!(
            extract_service_exe_path(r#""C:\Program Files\Acme\svc.exe" --daemon"#),
            r"C:\Program Files\Acme\svc.exe"
        );
        assert_eq!(
            extract_service_exe_path(r"C:\Program Files\Vendor App\agent.exe -k run"),
            r"C:\Program Files\Vendor App\agent.exe"
        );
        let hops = find_unquoted_space_prefixes(r"C:\Program Files\Vendor App\agent.exe -k run");
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].0, r"C:\Program.exe");
        assert_eq!(hops[1].0, r"C:\Program Files\Vendor.exe");
        assert!(
            find_unquoted_space_prefixes(r#""C:\Program Files\Vendor App\agent.exe" -k"#)
                .is_empty()
        );
        assert!(
            find_unquoted_space_prefixes(r"C:\Windows\System32\svchost.exe -k netsvcs").is_empty()
        );
    }

    #[cfg(windows)]
    #[test]
    fn win32_native_queries_whoami_pipes_reg_acl_and_services() {
        let who = imp::query_whoami();
        assert_eq!(who["ok"], Value::Bool(true));
        assert!(!who["user"].as_str().unwrap_or("").is_empty());
        assert!(!who["privileges"].as_array().unwrap().is_empty());

        let pipes = imp::query_pipes(None, 5);
        assert_eq!(pipes["ok"], Value::Bool(true));
        assert!(!pipes["pipes"].as_array().unwrap().is_empty());

        let reg = imp::query_registry(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            Some("ProductName"),
            20,
        );
        assert_eq!(reg["ok"], Value::Bool(true));

        let acl = imp::query_acl(r"C:\Windows\System32\cmd.exe");
        assert_eq!(acl["ok"], Value::Bool(true));
        assert!(!acl["sddl"].as_str().unwrap_or("").is_empty());

        let svcs = imp::query_services(Some("EventLog"), 5);
        assert_eq!(svcs["ok"], Value::Bool(true));
        assert!(!svcs["services"].as_array().unwrap().is_empty());

        let sig_ok = imp::query_signature(r"C:\Windows\System32\notepad.exe");
        assert_eq!(sig_ok["ok"], Value::Bool(true));
        assert_eq!(sig_ok["signed"], Value::Bool(true));
        assert_eq!(sig_ok["valid"], Value::Bool(true));

        let wa_os = imp::query_weak_acl(None, Some("EventLog"), 10);
        assert_eq!(wa_os["ok"], Value::Bool(true), "{wa_os}");
        assert_eq!(wa_os["mode"], "weak_acl");

        let unq = imp::query_unquoted_services(None, 10);
        assert_eq!(unq["ok"], Value::Bool(true), "{unq}");
        assert_eq!(unq["mode"], "unquoted");

        let com = imp::query_com_audit(None, 5);
        assert_eq!(com["ok"], Value::Bool(true), "{com}");
        assert_eq!(com["mode"], "com");

        let rpc = imp::query_rpc_endpoints(None, 10);
        assert_eq!(rpc["ok"], Value::Bool(true), "{rpc}");
        assert_eq!(rpc["mode"], "rpc");
        assert!(rpc["returned"].as_u64().unwrap_or(0) >= 1, "{rpc}");
        assert!(
            !sig_ok["subject"].as_str().unwrap_or("").is_empty(),
            "expected non-empty subject: {sig_ok}"
        );

        let tmp_unsigned =
            std::env::temp_dir().join(format!("ap_win_sig_{}.bin", std::process::id()));
        std::fs::write(&tmp_unsigned, b"unsigned dummy bytes").unwrap();
        let sig_uns = imp::query_signature(&tmp_unsigned.to_string_lossy());
        let _ = std::fs::remove_file(&tmp_unsigned);
        assert_eq!(sig_uns["ok"], Value::Bool(true));
        assert_eq!(sig_uns["signed"], Value::Bool(false));
        assert_eq!(sig_uns["valid"], Value::Bool(false));

        let sig_miss = imp::query_signature(r"C:\__ap_nonexistent_sig_target__.exe");
        assert_eq!(sig_miss["ok"], Value::Bool(false));

        let procs = imp::query_procs_opts(None, 10, false, None);
        assert_eq!(procs["ok"], Value::Bool(true), "{procs}");
        assert_eq!(procs["mode"], "procs");
        let parr = procs["processes"].as_array().unwrap();
        assert!(!parr.is_empty(), "{procs}");
        assert!(parr[0].get("integrity_level").is_some(), "{procs}");
        assert!(parr[0].get("session_id").is_some(), "{procs}");

        let pipes_arr = pipes["pipes"].as_array().unwrap();
        assert!(pipes_arr[0].get("pipe").is_some(), "{pipes}");
        assert!(pipes_arr[0].get("weak_dacl").is_some(), "{pipes}");
        assert!(pipes_arr[0].get("server_pid").is_some(), "{pipes}");
    }

    #[test]
    fn cycle6_pipe_priority_sort_and_human_formatter() {
        let mut names = vec![
            "000012ab-34cd-56ef-9012-abcdef123456".to_string(),
            "LOCAL\\mojo.1234.5678.9012".to_string(),
            "crashpad_4012_ABCDEFGHIJ".to_string(),
            "acme_agent_ipc".to_string(),
            "uv\\pipe-1234".to_string(),
            "custom_daemon_ctrl".to_string(),
        ];
        sort_pipe_names_by_signal(&mut names);
        assert_eq!(names[0], "acme_agent_ipc");
        assert_eq!(names[1], "custom_daemon_ctrl");
        assert!(is_noisy_guid_or_mojo_pipe("local\\mojo.1234.5678.9012"));
        assert!(is_noisy_guid_or_mojo_pipe(
            "000012ab-34cd-56ef-9012-abcdef123456"
        ));
        assert!(!is_noisy_guid_or_mojo_pipe("acme_agent_ipc"));

        let sample = json!({
            "ok": true,
            "mode": "pipes",
            "total_matched": 2,
            "returned": 2,
            "pipes": [
                {
                    "name": "acme_agent_ipc",
                    "pipe": r"\\.\pipe\acme_agent_ipc",
                    "non_admin_write": true,
                    "weak_dacl": ["WD:GW"],
                    "server_pid": 4242,
                    "server_process": "acme.exe",
                    "server_il": "System",
                    "signal": "CROSS_IL_PIPE_EOP_CANDIDATE"
                },
                {
                    "name": "safe_pipe",
                    "pipe": r"\\.\pipe\safe_pipe",
                    "non_admin_write": false,
                    "weak_dacl": []
                }
            ]
        });
        let human = format_win_human(&sample);
        assert!(
            human.lines().count() >= 3,
            "expected multi-line human text: {human}"
        );
        assert!(
            human.contains("WEAK_DACL(WD:GW)") && human.contains("acme_agent_ipc"),
            "{human}"
        );
        assert!(
            !human.trim_start().starts_with('{'),
            "non-json mode must not emit raw minified JSON"
        );
    }
}
