use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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

    const HKEY_CLASSES_ROOT: isize = 0x8000_0000u32 as i32 as isize;
    const HKEY_CURRENT_USER: isize = 0x8000_0001u32 as i32 as isize;
    const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
    const HKEY_USERS: isize = 0x8000_0003u32 as i32 as isize;
    const HKEY_CURRENT_CONFIG: isize = 0x8000_0005u32 as i32 as isize;
    const KEY_READ: u32 = 0x0002_0019;
    const ERROR_MORE_DATA: i32 = 234;
    const ERROR_NO_MORE_ITEMS: i32 = 259;

    const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
    const SERVICE_QUERY_CONFIG: u32 = 0x0001;
    const SC_ENUM_PROCESS_INFO: u32 = 0;
    const SERVICE_WIN32: u32 = 0x0000_0030;
    const SERVICE_STATE_ALL: u32 = 0x0000_0003;

    #[repr(C)]
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

    #[link(name = "kernel32")]
    extern "system" {
        fn FindFirstFileW(lp_file_name: *const u16, lp_find_data: *mut Win32FindDataW) -> Handle;
        fn FindNextFileW(h_find_file: Handle, lp_find_data: *mut Win32FindDataW) -> Bool;
        fn FindClose(h_find_file: Handle) -> Bool;
        fn CloseHandle(h_object: Handle) -> Bool;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
        fn GetCurrentProcess() -> Handle;
        fn GetLastError() -> u32;
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

    pub fn query_pipes(filter: Option<&str>, max: usize) -> Value {
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
            if !nm.is_empty()
                && f_low
                    .as_ref()
                    .map(|fl| nm.to_ascii_lowercase().contains(fl))
                    .unwrap_or(true)
            {
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
        let total_matched = all_names.len();
        let cap = max.clamp(1, 200);
        let inspect_sddl = total_matched <= 30 || filter.is_some();
        let mut entries = Vec::new();
        for nm in all_names.into_iter().take(cap) {
            let full = format!(r"\\.\pipe\{nm}");
            let mut sddl: Option<String> = None;
            let mut non_admin_write = false;
            if inspect_sddl {
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
                        non_admin_write = aces.iter().any(|a| a.non_admin_write);
                        sddl = Some(s);
                    }
                    unsafe {
                        LocalFree(p_sd);
                    }
                }
            }
            entries.push(json!({
                "name": nm,
                "path": full,
                "sddl": sddl,
                "non_admin_write": non_admin_write,
            }));
        }
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

    pub fn query_services(filter: Option<&str>, max: usize) -> Value {
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
            total_matched += 1;
            if matched.len() >= cap {
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
}

#[allow(clippy::too_many_arguments)]
pub fn run_win_cli(
    pipes: bool,
    reg: Option<&str>,
    acl: Option<&str>,
    services: bool,
    whoami: bool,
    filter: Option<&str>,
    max: usize,
    as_json: bool,
) -> i32 {
    #[cfg(not(windows))]
    {
        let _ = (pipes, reg, acl, services, whoami, filter, max);
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
            + usize::from(whoami);
        if mode_count == 0 {
            let msg = "[ap probe win] Pass one of --pipes, --reg <KEY>, --acl <PATH>, --services, or --whoami";
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
        let val = if let Some(rk) = reg {
            imp::query_registry(rk, filter, max)
        } else if let Some(ap) = acl {
            imp::query_acl(ap)
        } else if pipes {
            imp::query_pipes(filter, max)
        } else if services {
            imp::query_services(filter, max)
        } else {
            imp::query_whoami()
        };
        let ok = val.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let serialized = if as_json {
            serde_json::to_string_pretty(&val)
        } else {
            serde_json::to_string(&val)
        };
        println!("{}", serialized.unwrap_or_default());
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
    }
}
