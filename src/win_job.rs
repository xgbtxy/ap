//! Win32 Kernel Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) guard.
//! Ensures zero orphaned child/grandchild processes survive on Windows even if
//! `ap.exe` is abruptly killed (`TerminateProcess` / `Ctrl+C`) or panics.

#[cfg(windows)]
mod imp {
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use std::ptr;

    type Handle = *mut core::ffi::c_void;
    type Bool = i32;

    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    impl Default for JobObjectBasicLimitInformation {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(
            lp_job_attributes: *const core::ffi::c_void,
            lp_name: *const u16,
        ) -> Handle;
        fn SetInformationJobObject(
            h_job: Handle,
            job_object_info_class: i32,
            lp_job_object_info: *const core::ffi::c_void,
            cb_job_object_info_length: u32,
        ) -> Bool;
        fn AssignProcessToJobObject(h_job: Handle, h_process: Handle) -> Bool;
        fn CloseHandle(h_object: Handle) -> Bool;
    }

    pub struct WinJobGuard {
        handle: Handle,
    }

    impl WinJobGuard {
        /// Creates a non-inheritable Win32 Job Object configured with
        /// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and attaches `child` to it.
        pub fn attach(child: &Child) -> Option<Self> {
            unsafe {
                // Null security attributes => bInheritHandle = FALSE (prevents handle leak to children!)
                let job = CreateJobObjectW(ptr::null(), ptr::null());
                if job.is_null() {
                    return None;
                }
                let mut info = JobObjectExtendedLimitInformation::default();
                info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let ok_set = SetInformationJobObject(
                    job,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    (&info as *const JobObjectExtendedLimitInformation).cast(),
                    core::mem::size_of::<JobObjectExtendedLimitInformation>() as u32,
                );
                if ok_set == 0 {
                    let _ = CloseHandle(job);
                    return None;
                }
                let raw_proc = child.as_raw_handle() as Handle;
                if AssignProcessToJobObject(job, raw_proc) == 0 {
                    let _ = CloseHandle(job);
                    return None;
                }
                Some(Self { handle: job })
            }
        }
    }

    impl Drop for WinJobGuard {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe {
                    let _ = CloseHandle(self.handle);
                }
            }
        }
    }
}

#[cfg(windows)]
pub use imp::WinJobGuard;

#[cfg(not(windows))]
pub struct WinJobGuard;

#[cfg(not(windows))]
impl WinJobGuard {
    pub fn attach(_child: &std::process::Child) -> Option<Self> {
        None
    }
}

#[cfg(not(windows))]
impl Drop for WinJobGuard {
    fn drop(&mut self) {}
}
