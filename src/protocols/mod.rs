use async_trait::async_trait;
use std::collections::HashMap;

use crate::error::{AftError, AftResult};

pub mod aftp;
pub mod azure_blob;
pub mod dod;
pub mod ftp;
pub mod gcs;
pub mod http;
pub mod local;
pub mod s3;
pub mod sftp;
pub mod smb;
pub mod webdav;

/// Metadata about a remote resource
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResourceMetadata {
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
    pub accepts_ranges: bool,
    pub headers: HashMap<String, String>,
}

/// Entry in a directory listing
#[derive(Debug, Clone, serde::Serialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub size: Option<u64>,
    pub is_directory: bool,
    pub last_modified: Option<String>,
    /// Relative path from the listing root (populated by recursive listing)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative_path: Option<String>,
    /// Whether this entry is a symbolic link
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_symlink: Option<bool>,
    /// Unix permissions (e.g. 0o755), if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<u32>,
}

/// Options for configuring a protocol handler
#[derive(Debug, Clone, Default)]
pub struct ProtocolOptions {
    pub headers: HashMap<String, String>,
    pub bearer_token: Option<String>,
    pub basic_auth: Option<(String, String)>,
    pub user_agent: Option<String>,
    pub connect_timeout_secs: u64,
    pub timeout_secs: u64,
    pub insecure: bool,
    pub max_redirects: usize,
    /// SHA-256 fingerprint (hex) of a pinned TLS certificate
    pub pin_cert: Option<String>,
    /// Path to a custom CA certificate bundle (PEM file)
    pub ca_bundle: Option<String>,
    /// Request the fountain-coded UDP data plane for AFTP transfers.
    ///
    /// Safe to leave on: it is negotiated, and a peer that does not support it
    /// simply omits the capability and the transfer uses the reliable path.
    pub fec: bool,
    /// Prefer QUIC unreliable datagrams for the FEC data plane (implies `fec`).
    /// Negotiated via `CAP_FEC_QUIC`; falls back to a UDP socket otherwise.
    pub fec_quic: bool,
    /// Consent to run the FEC data plane unauthenticated (CRC32-only symbols).
    /// The client counterpart to the server's `--fec-insecure`; without it an
    /// unauthenticated FEC offer is refused and the reliable path is used.
    pub fec_allow_unauthenticated: bool,
}

/// Trait defining the interface for all protocol handlers.
///
/// Every supported transfer protocol (HTTP, FTP, SFTP, S3, local file system)
/// implements this trait, providing a uniform API for the transfer engine.
#[async_trait]
#[allow(dead_code)]
pub trait ProtocolHandler: Send + Sync {
    /// Protocol scheme identifier (e.g., "https", "ftp", "s3")
    fn scheme(&self) -> &str;

    /// Human-readable protocol name
    fn name(&self) -> &str;

    /// Whether this protocol supports byte-range requests for chunked parallel downloads
    fn supports_ranges(&self) -> bool;

    /// Whether splitting a download across parallel range requests actually
    /// makes it faster.
    ///
    /// Supporting ranges and *benefiting* from parallel ranges are different
    /// questions. Parallel chunking wins for request/response protocols like
    /// HTTP and S3, where each range rides a pooled connection and multiple
    /// TCP flows claim more of the bottleneck.
    ///
    /// It loses badly for protocols that stream over one persistent
    /// connection. AFTP opens a fresh connection and repeats the HELLO
    /// handshake for every range, so N chunks cost N TCP handshakes, N
    /// handshake round trips, and — most expensively — N cold starts of TCP
    /// congestion control. On a 25 ms path that measured 4.2x *slower* than a
    /// single streamed connection, with wild variance as short-lived flows in
    /// slow-start collided.
    ///
    /// Defaults to true, matching the HTTP-family protocols this was built for.
    fn benefits_from_parallel_ranges(&self) -> bool {
        true
    }

    /// Whether writing to `a/b/c.txt` implicitly creates `a/b`.
    ///
    /// Object stores and AFTP create the whole path on write, so a directory
    /// sync need not — and for AFTP *cannot* — issue explicit `mkdir` calls
    /// first. Without this, syncing a tree to such a protocol fails on the
    /// very first subdirectory even though every file would have transferred
    /// fine.
    ///
    /// Note the limitation this implies: a protocol that only creates
    /// directories as a side effect of writing files cannot represent an
    /// *empty* directory, so empty directories are not replicated.
    fn creates_parent_dirs_on_write(&self) -> bool {
        false
    }

    /// Whether this protocol supports resuming interrupted transfers
    fn supports_resume(&self) -> bool;

    /// Get metadata about a remote resource without downloading it
    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata>;

    /// Download a resource to a local file.
    /// `resume_from` specifies byte offset to resume from, if supported.
    /// `progress` callback receives (bytes_so_far, total_bytes_option).
    async fn download(
        &self,
        url: &str,
        dest: &std::path::Path,
        opts: &ProtocolOptions,
        resume_from: Option<u64>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64>;

    /// Download a specific byte range (for parallel chunked downloads)
    async fn download_range(
        &self,
        url: &str,
        start: u64,
        end: u64,
        opts: &ProtocolOptions,
    ) -> AftResult<Vec<u8>>;

    /// Upload a local file to a remote destination
    async fn upload(
        &self,
        source: &std::path::Path,
        url: &str,
        opts: &ProtocolOptions,
        content_type: Option<&str>,
        method: Option<&str>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64>;

    /// List directory contents at a URL
    async fn list(&self, url: &str, opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>>;


    // ------------------------------------------------------------------
    // Extended operations
    // ------------------------------------------------------------------

    /// Whether this handler implements extended operations
    fn supports_extended_ops(&self) -> bool {
        false
    }

    /// Delete a file or directory at the given URL.
    async fn delete(&self, _url: &str, _recursive: bool, _opts: &ProtocolOptions) -> AftResult<()> {
        Err(AftError::UnsupportedProtocol(
            "delete is not supported by this protocol".to_string(),
        ))
    }

    /// Rename / move a resource.
    async fn rename(&self, _from: &str, _to: &str, _opts: &ProtocolOptions) -> AftResult<()> {
        Err(AftError::UnsupportedProtocol(
            "rename is not supported by this protocol".to_string(),
        ))
    }

    /// Create a directory (including parents).
    async fn mkdir(&self, _url: &str, _opts: &ProtocolOptions) -> AftResult<()> {
        Err(AftError::UnsupportedProtocol(
            "mkdir is not supported by this protocol".to_string(),
        ))
    }

    /// Set the modification time on a remote resource.
    async fn set_timestamps(
        &self,
        _url: &str,
        _mtime: chrono::DateTime<chrono::Utc>,
        _opts: &ProtocolOptions,
    ) -> AftResult<()> {
        Err(AftError::UnsupportedProtocol(
            "set_timestamps is not supported by this protocol".to_string(),
        ))
    }

    /// Check whether a resource exists.
    async fn exists(&self, url: &str, opts: &ProtocolOptions) -> AftResult<bool> {
        match self.head(url, opts).await {
            Ok(_) => Ok(true),
            Err(AftError::FileNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Recursively list all entries under a URL.
    async fn list_recursive(
        &self,
        url: &str,
        opts: &ProtocolOptions,
        max_depth: usize,
    ) -> AftResult<Vec<DirectoryEntry>> {
        let effective_max = if max_depth == 0 { 200 } else { max_depth };
        let mut result = Vec::new();
        let mut stack: Vec<(String, String, usize)> = vec![(url.to_string(), String::new(), 0)];

        while let Some((current_url, prefix, depth)) = stack.pop() {
            if depth > effective_max {
                continue;
            }
            let entries = self.list(&current_url, opts).await?;
            for mut entry in entries {
                let rel = if prefix.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{}/{}", prefix, entry.name)
                };
                entry.relative_path = Some(rel.clone());

                if entry.is_directory {
                    let child_url = format!("{}/{}", current_url.trim_end_matches('/'), entry.name);
                    stack.push((child_url, rel, depth + 1));
                }
                result.push(entry);
            }
        }
        Ok(result)
    }
}

/// Resolve a URL string to the appropriate protocol handler.
///
/// Detects the protocol from the URL scheme, or infers local file paths
/// from filesystem-like patterns (relative paths, drive letters, etc.).
/// Checks loaded plugins first before falling back to built-in handlers.
pub fn resolve_protocol(url: &str) -> AftResult<Box<dyn ProtocolHandler>> {
    let scheme = if url.contains("://") {
        let s = url.split("://").next().unwrap_or("").to_lowercase();
        // RFC 3986: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        // Must be non-empty and start with an ASCII letter.
        if s.is_empty() || !s.starts_with(|c: char| c.is_ascii_alphabetic()) {
            return Err(AftError::InvalidUrl(format!(
                "Missing or invalid URL scheme in '{}'",
                url
            )));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            return Err(AftError::InvalidUrl(format!(
                "Invalid characters in URL scheme: '{}'",
                s
            )));
        }
        s
    } else if is_local_path(url) {
        "file".to_string()
    } else {
        return Err(AftError::InvalidUrl(format!(
            "Cannot determine protocol for: {}. Use a URL with a scheme (e.g., https://) or a local path.",
            url
        )));
    };

    // Check plugins first (gracefully handle poisoned mutex)
    match crate::plugins::global_registry().lock() {
        Ok(guard) => {
            if let Some(handler) = guard.create_handler(&scheme) {
                return Ok(handler);
            }
        }
        Err(_) => {
            // Mutex poisoned — skip plugins but continue with built-in handlers
            eprintln!("Warning: plugin registry unavailable (mutex poisoned)");
        }
    }

    match scheme.as_str() {
        "http" | "https" => Ok(Box::new(http::HttpHandler::new(scheme.clone()))),
        "file" => Ok(Box::new(local::LocalHandler)),
        "aftp" | "aftps" => Ok(Box::new(aftp::AftpHandler::new(scheme))),
        "ftp" | "ftps" => Ok(Box::new(ftp::FtpHandler::new(scheme))),
        "sftp" | "scp" | "ssh" => Ok(Box::new(sftp::SftpHandler::new(scheme))),
        "s3" => Ok(Box::new(s3::S3Handler)),
        "webdav" | "webdavs" | "dav" => Ok(Box::new(webdav::WebDavHandler::new(scheme))),
        "az" | "azblob" => Ok(Box::new(azure_blob::AzureBlobHandler)),
        "gs" => Ok(Box::new(gcs::GcsHandler)),
        "smb" => Ok(Box::new(smb::SmbHandler)),
        "dod" => Ok(Box::new(dod::DodHandler)),
        _ => Err(AftError::UnsupportedProtocol(format!(
            "'{}'. Supported: http, https, ftp, ftps, sftp, scp, s3, aftp, webdav, az, gs, smb, dod, file",
            scheme
        ))),
    }
}

fn is_local_path(url: &str) -> bool {
    let path = std::path::Path::new(url);

    // Absolute or relative paths
    url.starts_with('.')
        || url.starts_with('/')
        || url.starts_with('\\')
        || url.starts_with('~')
        // Windows drive letters
        || (url.len() >= 2 && url.as_bytes()[0].is_ascii_alphabetic() && url.as_bytes()[1] == b':')
        // Existing filesystem entries
        || path.exists()
}
