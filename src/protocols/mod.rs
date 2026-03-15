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
}

/// Resolve a URL string to the appropriate protocol handler.
///
/// Detects the protocol from the URL scheme, or infers local file paths
/// from filesystem-like patterns (relative paths, drive letters, etc.).
/// Checks loaded plugins first before falling back to built-in handlers.
pub fn resolve_protocol(url: &str) -> AftResult<Box<dyn ProtocolHandler>> {
    let scheme = if url.contains("://") {
        let s = url.split("://").next().unwrap_or("").to_lowercase();
        // Validate scheme characters (RFC 3986: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ))
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

    // Check plugins first
    if let Ok(guard) = crate::plugins::global_registry().lock() {
        if let Some(handler) = guard.create_handler(&scheme) {
            return Ok(handler);
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
