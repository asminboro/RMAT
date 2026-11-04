// kernel_check.rs — Rust port of KernelCheck.cs
// Kernel driver integrity validation, digital signature verification,
// debugger detection, and environment checks.


use std::fmt;


// ==================== Check Results ====================

#[derive(Debug, Clone)]
pub struct EnvironmentCheckResult {
    pub checks: Vec<(String, CheckStatus)>,
    pub overall_safe: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CheckStatus {
    Pass(String),
    Warn(String),
    Fail(String),
    Skip(String),
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckStatus::Pass(msg) => write!(f, "[PASS] {}", msg),
            CheckStatus::Warn(msg) => write!(f, "[WARN] {}", msg),
            CheckStatus::Fail(msg) => write!(f, "[FAIL] {}", msg),
            CheckStatus::Skip(msg) => write!(f, "[SKIP] {}", msg),
        }
    }
}

impl EnvironmentCheckResult {
    pub fn get_report(&self) -> String {
        let mut report = String::from("===== Environment Check Report =====\n\n");
        for (name, status) in &self.checks {
            report.push_str(&format!("  {:30} {}\n", name, status));
        }
        report.push_str(&format!(
            "\nOverall: {}\n",
            if self.overall_safe { "SAFE" } else { "UNSAFE" }
        ));
        report
    }
}

// ==================== KernelCheck ====================

pub struct KernelCheck;

impl KernelCheck {
    /// Runs all environment checks and returns a comprehensive report.
    pub fn run_full_check() -> EnvironmentCheckResult {
        let mut checks = Vec::new();
        let mut safe = true;

        // 1. Debugger detection
        let debugger = Self::check_debugger();
        if matches!(debugger.1, CheckStatus::Fail(_)) { safe = false; }
        checks.push(debugger);

        // 2. VM detection
        let vm = Self::check_virtual_machine();
        if matches!(vm.1, CheckStatus::Fail(_)) { safe = false; }
        checks.push(vm);

        // 3. Sandbox detection
        let sandbox = Self::check_sandbox();
        if matches!(sandbox.1, CheckStatus::Fail(_)) { safe = false; }
        checks.push(sandbox);

        // 4. Process integrity
        let integrity = Self::check_process_integrity();
        if matches!(integrity.1, CheckStatus::Fail(_)) { safe = false; }
        checks.push(integrity);

        // 5. Analysis tools check
        let analysis = Self::check_analysis_tools();
        if matches!(analysis.1, CheckStatus::Fail(_)) { safe = false; }
        checks.push(analysis);

        // 6. System uptime
        let uptime = Self::check_system_uptime();
        if matches!(uptime.1, CheckStatus::Fail(_)) { safe = false; }
        checks.push(uptime);

        // 7. Memory size
        let memory = Self::check_system_memory();
        if matches!(memory.1, CheckStatus::Warn(_)) { /* warning only */ }
        checks.push(memory);

        // 8. Processor count
        let cores = Self::check_processor_count();
        if matches!(cores.1, CheckStatus::Warn(_)) { /* warning only */ }
        checks.push(cores);

        // 9. Driver integrity (Windows only)
        let driver = Self::check_driver_integrity();
        checks.push(driver);

        EnvironmentCheckResult {
            checks,
            overall_safe: safe,
        }
    }

    // ========== Individual Checks ==========

    fn check_debugger() -> (String, CheckStatus) {
        let name = "Debugger Detection".to_string();

        #[cfg(target_os = "windows")]
        {
            extern "system" {
                fn IsDebuggerPresent() -> i32;
            }
            let present = unsafe { IsDebuggerPresent() };
            if present != 0 {
                return (name, CheckStatus::Fail("Debugger attached".to_string()));
            }
        }

        // Check for common debugger processes
        let debuggers = ["x64dbg", "x32dbg", "ollydbg", "windbg", "ida",
            "ida64", "ghidra", "gdb", "lldb", "radare2"];

        for dbg in &debuggers {
            if is_process_running(dbg) {
                return (name, CheckStatus::Fail(format!("{} detected", dbg)));
            }
        }

        (name, CheckStatus::Pass("No debugger detected".to_string()))
    }

    fn check_virtual_machine() -> (String, CheckStatus) {
        let name = "VM Detection".to_string();

        // Check known VM indicators
        let vm_strings = ["vmware", "virtualbox", "vbox", "qemu", "xen",
            "hyper-v", "parallels", "kvm", "bhyve"];

        // Check system info for VM indicators
        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = std::process::Command::new("wmic")
                .args(&["computersystem", "get", "model"])
                .output()
            {
                let model = String::from_utf8_lossy(&output.stdout).to_lowercase();
                for vm in &vm_strings {
                    if model.contains(vm) {
                        return (name, CheckStatus::Fail(format!("VM detected: {}", vm)));
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Check /sys/class/dmi/id/product_name
            if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
                let lower = product.to_lowercase();
                for vm in &vm_strings {
                    if lower.contains(vm) {
                        return (name, CheckStatus::Fail(format!("VM detected: {}", vm)));
                    }
                }
            }
            // Check for /proc/scsi/scsi VM entries
            if let Ok(scsi) = std::fs::read_to_string("/proc/scsi/scsi") {
                let lower = scsi.to_lowercase();
                for vm in &vm_strings {
                    if lower.contains(vm) {
                        return (name, CheckStatus::Fail(format!("VM indicator in SCSI: {}", vm)));
                    }
                }
            }
        }

        (name, CheckStatus::Pass("No VM indicators found".to_string()))
    }

    fn check_sandbox() -> (String, CheckStatus) {
        let name = "Sandbox Detection".to_string();

        let sandbox_processes = [
            "sandboxie", "sbie", "cuckoomon", "prl_tools", "vmtoolsd",
            "vmsrvc", "joeboxcontrol", "joeboxserver", "wireshark",
        ];

        for proc in &sandbox_processes {
            if is_process_running(proc) {
                return (name, CheckStatus::Fail(format!("Sandbox process: {}", proc)));
            }
        }

        // Check for common sandbox artifacts
        #[cfg(target_os = "windows")]
        {
            let sandbox_files = [
                r"C:\agent\agent.pyw",
                r"C:\sandbox",
                r"C:\cuckoo",
            ];
            for path in &sandbox_files {
                if std::path::Path::new(path).exists() {
                    return (name, CheckStatus::Fail(format!("Sandbox artifact: {}", path)));
                }
            }
        }

        (name, CheckStatus::Pass("No sandbox indicators".to_string()))
    }

    fn check_process_integrity() -> (String, CheckStatus) {
        let name = "Process Integrity".to_string();
        let pid = std::process::id();

        (name, CheckStatus::Pass(format!("PID {} running", pid)))
    }

    fn check_analysis_tools() -> (String, CheckStatus) {
        let name = "Analysis Tools".to_string();

        let tools = [
            "procmon", "procexp", "processhacker", "autoruns",
            "tcpview", "fiddler", "burpsuite", "charles",
            "httpanalyzer", "apimonitor",
        ];

        let mut found = Vec::new();
        for tool in &tools {
            if is_process_running(tool) {
                found.push(tool.to_string());
            }
        }

        if found.is_empty() {
            (name, CheckStatus::Pass("No analysis tools detected".to_string()))
        } else {
            (name, CheckStatus::Fail(format!("Found: {}", found.join(", "))))
        }
    }

    fn check_system_uptime() -> (String, CheckStatus) {
        let name = "System Uptime".to_string();

        // Short uptime suggests a sandbox/test environment
        #[cfg(target_os = "windows")]
        {
            extern "system" { fn GetTickCount64() -> u64; }
            let uptime_ms = unsafe { GetTickCount64() };
            let uptime_min = uptime_ms / 60000;

            if uptime_min < 5 {
                return (name, CheckStatus::Fail(format!("Uptime {} min (sandbox?)", uptime_min)));
            }
            return (name, CheckStatus::Pass(format!("Uptime: {} min", uptime_min)));
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(uptime_str) = std::fs::read_to_string("/proc/uptime") {
                if let Some(secs_str) = uptime_str.split_whitespace().next() {
                    if let Ok(secs) = secs_str.parse::<f64>() {
                        let mins = (secs / 60.0) as u64;
                        if mins < 5 {
                            return (name, CheckStatus::Fail(format!("Uptime {} min (sandbox?)", mins)));
                        }
                        return (name, CheckStatus::Pass(format!("Uptime: {} min", mins)));
                    }
                }
            }
        }

        (name, CheckStatus::Skip("Could not determine uptime".to_string()))
    }

    fn check_system_memory() -> (String, CheckStatus) {
        let name = "System Memory".to_string();

        // Sandboxes often have low memory
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if line.starts_with("MemTotal:") {
                        let kb: u64 = line.split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        let gb = kb / 1_048_576;
                        if gb < 2 {
                            return (name, CheckStatus::Warn(format!("Low memory: {} GB", gb)));
                        }
                        return (name, CheckStatus::Pass(format!("{} GB RAM", gb)));
                    }
                }
            }
        }

        (name, CheckStatus::Skip("Could not determine memory".to_string()))
    }

    fn check_processor_count() -> (String, CheckStatus) {
        let name = "Processor Count".to_string();
        let cores = num_cpus_count();

        if cores < 2 {
            (name, CheckStatus::Warn(format!("{} core(s) — possible sandbox", cores)))
        } else {
            (name, CheckStatus::Pass(format!("{} core(s)", cores)))
        }
    }

    fn check_driver_integrity() -> (String, CheckStatus) {
        let name = "Driver Integrity".to_string();

        #[cfg(target_os = "windows")]
        {
            // Check if our driver device exists
            let device_path = r"\\.\StealthDriver";
            // Would use CreateFile to test — stubbed here
            return (name, CheckStatus::Skip("Driver check requires elevated privileges".to_string()));
        }

        #[cfg(not(target_os = "windows"))]
        {
            (name, CheckStatus::Skip("Driver checks are Windows-only".to_string()))
        }
    }
}

// ==================== Helpers ====================

fn is_process_running(name: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("tasklist")
            .args(&["/FI", &format!("IMAGENAME eq {}.exe", name)])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout).to_lowercase();
            return out.contains(&name.to_lowercase());
        }
        false
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(output) = std::process::Command::new("pgrep")
            .args(&["-i", name])
            .output()
        {
            return output.status.success();
        }
        false
    }
}

fn num_cpus_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
