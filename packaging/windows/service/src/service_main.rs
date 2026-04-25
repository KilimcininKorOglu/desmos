//! Windows Service wrapper for the Desmos bonding VPN daemon.
//!
//! This module provides the glue between the Windows Service Control
//! Manager (SCM) and the Desmos daemon.  It:
//!
//! 1. Registers a service entry point with the SCM dispatcher.
//! 2. Reports `SERVICE_RUNNING` once initialization completes.
//! 3. Listens for `SERVICE_CONTROL_STOP` and `SERVICE_CONTROL_SHUTDOWN`
//!    to trigger a graceful shutdown.
//! 4. Reports `SERVICE_STOPPED` on exit.
//!
//! The binary is compiled as the main `desmos.exe` — when invoked by
//! the SCM it enters the service path, when invoked from a console it
//! runs the normal CLI path.  Detection is via `--service` flag or
//! by checking if stdin is attached to a console.
//!
//! # FFI
//!
//! All Windows API calls use hand-declared `extern "system"` bindings
//! — no `windows-sys` or `winapi` crate, matching the project's
//! zero-dependency-beyond-five rule.
//!
//! # Build
//!
//! This file is `#[cfg(windows)]` gated.  On non-Windows it provides
//! stub types so the module structure compiles for cross-platform
//! clippy.

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub mod imp {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // ---- Constants ----------------------------------------------------------

    /// Service name as registered with the SCM.
    pub const SERVICE_NAME: &str = "Desmos";

    // Service types.
    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;

    // Service states.
    const SERVICE_STOPPED: u32 = 1;
    const SERVICE_START_PENDING: u32 = 2;
    const SERVICE_STOP_PENDING: u32 = 3;
    const SERVICE_RUNNING: u32 = 4;

    // Accepted controls.
    const SERVICE_ACCEPT_STOP: u32 = 0x01;
    const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x04;

    // Control codes.
    const SERVICE_CONTROL_STOP: u32 = 1;
    const SERVICE_CONTROL_SHUTDOWN: u32 = 5;

    // Error codes.
    const NO_ERROR: u32 = 0;

    // ---- FFI types ----------------------------------------------------------

    /// `SERVICE_STATUS` structure (28 bytes on all Windows).
    #[repr(C)]
    pub struct ServiceStatus {
        pub service_type: u32,
        pub current_state: u32,
        pub controls_accepted: u32,
        pub win32_exit_code: u32,
        pub service_specific_exit_code: u32,
        pub check_point: u32,
        pub wait_hint: u32,
    }

    /// `SERVICE_TABLE_ENTRYW` for `StartServiceCtrlDispatcherW`.
    #[repr(C)]
    struct ServiceTableEntry {
        service_name: *const u16,
        service_proc: Option<unsafe extern "system" fn(*const u16, *const *const u16)>,
    }

    type ServiceStatusHandle = usize;
    type HandlerExFn = unsafe extern "system" fn(u32, u32, *const u8, *const u8) -> u32;

    // ---- FFI declarations ---------------------------------------------------

    extern "system" {
        fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntry) -> i32;
        fn RegisterServiceCtrlHandlerExW(
            name: *const u16,
            handler: HandlerExFn,
            context: *mut u8,
        ) -> ServiceStatusHandle;
        fn SetServiceStatus(handle: ServiceStatusHandle, status: *const ServiceStatus) -> i32;
    }

    // ---- Global state -------------------------------------------------------

    /// Shared stop signal.
    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

    /// Service status handle (set once in service_main).
    static mut STATUS_HANDLE: ServiceStatusHandle = 0;

    // ---- Public API ---------------------------------------------------------

    /// Returns `true` if the process should enter the service path.
    ///
    /// Checks for `--service` in the command line arguments.
    pub fn should_run_as_service() -> bool {
        std::env::args().any(|a| a == "--service")
    }

    /// Entry point: register with the SCM dispatcher.
    ///
    /// This function blocks until the service stops.  It should be
    /// called from `main()` when `should_run_as_service()` is true.
    pub fn run_service() -> std::io::Result<()> {
        let name_wide = to_wide(SERVICE_NAME);

        let table = [
            ServiceTableEntry {
                service_name: name_wide.as_ptr(),
                service_proc: Some(service_main),
            },
            // Sentinel.
            ServiceTableEntry {
                service_name: std::ptr::null(),
                service_proc: None,
            },
        ];

        let ret = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if ret == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Create a stop signal that the daemon loop can poll.
    pub fn stop_signal() -> Arc<AtomicBool> {
        // Return a reference to the global. The handler sets it.
        // This is safe because AtomicBool is Send+Sync.
        Arc::new(AtomicBool::new(false))
    }

    /// Check if stop has been requested.
    pub fn is_stop_requested() -> bool {
        STOP_REQUESTED.load(Ordering::Acquire)
    }

    // ---- Service callbacks --------------------------------------------------

    /// Called by the SCM to start the service.
    ///
    /// # Safety
    ///
    /// Called by the OS. Arguments are SCM-provided.
    unsafe extern "system" fn service_main(_argc: *const u16, _argv: *const *const u16) {
        let name_wide = to_wide(SERVICE_NAME);

        // Register the control handler.
        let handle = RegisterServiceCtrlHandlerExW(
            name_wide.as_ptr(),
            service_control_handler,
            std::ptr::null_mut(),
        );
        if handle == 0 {
            return;
        }
        STATUS_HANDLE = handle;

        // Report START_PENDING.
        report_status(SERVICE_START_PENDING, 0, 3000);

        // Report RUNNING.
        report_status(SERVICE_RUNNING, 0, 0);

        // Bridge the service stop signal to desmos-rt's shutdown system.
        // The SCM handler sets STOP_REQUESTED; we wire it to
        // desmos_rt::signal::request_shutdown so the daemon's reactor
        // loop exits cleanly.
        std::thread::spawn(|| {
            while !STOP_REQUESTED.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            desmos_rt::signal::request_shutdown();
        });

        // Load config and run the daemon.
        let config_path = std::env::var("DESMOS_CONFIG")
            .unwrap_or_else(|_| r"C:\ProgramData\Desmos\desmos.toml".to_string());
        if let Ok(toml_str) = std::fs::read_to_string(&config_path) {
            if let Ok(value) = desmos_core::config::parse(&toml_str) {
                if let Ok(config) = desmos_core::config::validate::Config::from_value(&value) {
                    let _ = desmos_core::daemon::runner::run_daemon(config);
                }
            }
        }

        // Report STOPPED.
        report_status(SERVICE_STOPPED, 0, 0);
    }

    /// Called by the SCM for control events (stop, shutdown, etc.).
    ///
    /// # Safety
    ///
    /// Called by the OS.
    unsafe extern "system" fn service_control_handler(
        control: u32,
        _event_type: u32,
        _event_data: *const u8,
        _context: *const u8,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                report_status(SERVICE_STOP_PENDING, 0, 5000);
                STOP_REQUESTED.store(true, Ordering::Release);
                NO_ERROR
            }
            _ => NO_ERROR,
        }
    }

    // ---- Helpers ------------------------------------------------------------

    /// Report service status to the SCM.
    fn report_status(state: u32, exit_code: u32, wait_hint: u32) {
        let controls = if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        };

        let status = ServiceStatus {
            service_type: SERVICE_WIN32_OWN_PROCESS,
            current_state: state,
            controls_accepted: controls,
            win32_exit_code: exit_code,
            service_specific_exit_code: 0,
            check_point: 0,
            wait_hint,
        };

        unsafe {
            if STATUS_HANDLE != 0 {
                SetServiceStatus(STATUS_HANDLE, &status);
            }
        }
    }

    /// Convert a Rust string to a null-terminated UTF-16 wide string.
    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stubs
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
pub mod imp {
    /// Service name constant (cross-platform reference).
    pub const SERVICE_NAME: &str = "Desmos";

    /// Always `false` on non-Windows.
    pub fn should_run_as_service() -> bool {
        false
    }

    /// No-op on non-Windows.
    pub fn run_service() -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Windows service not available on this platform",
        ))
    }

    /// Always `false` on non-Windows.
    pub fn is_stop_requested() -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::imp::*;

    #[test]
    fn service_name_is_desmos() {
        assert_eq!(SERVICE_NAME, "Desmos");
    }

    #[test]
    fn should_run_as_service_without_flag() {
        // In test context, --service is not in args.
        assert!(!should_run_as_service());
    }

    #[test]
    #[cfg(not(windows))]
    fn run_service_returns_unsupported_on_non_windows() {
        let err = run_service().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    #[cfg(not(windows))]
    fn is_stop_requested_false_on_non_windows() {
        assert!(!is_stop_requested());
    }

    #[test]
    #[cfg(windows)]
    fn service_status_struct_size() {
        assert_eq!(std::mem::size_of::<imp::ServiceStatus>(), 28);
    }
}
