use std::collections::HashMap;
use std::path::Path;

use async_trait::async_trait;

use super::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};
use crate::error::{AftError, AftResult};

pub struct SmbHandler;

/// Parse smb://[user@]server/share[/path] → (server, share, path, user).
fn parse_smb_url(url: &str) -> AftResult<(String, String, String, Option<String>)> {
    let rest = url
        .strip_prefix("smb://")
        .ok_or_else(|| AftError::InvalidUrl("Not an smb:// URL".into()))?;

    // Check for user@ prefix
    let (user, host_rest) = if let Some(at_pos) = rest.find('@') {
        let before_at = &rest[..at_pos];
        // Only treat as user@ if the @ comes before the first /
        if rest.find('/').map_or(true, |slash| at_pos < slash) {
            (Some(before_at.to_string()), &rest[at_pos + 1..])
        } else {
            (None, rest)
        }
    } else {
        (None, rest)
    };

    // Split server/share/path
    let parts: Vec<&str> = host_rest.splitn(3, '/').collect();
    if parts.is_empty() || parts[0].is_empty() {
        return Err(AftError::InvalidUrl("SMB URL missing server name".into()));
    }

    let server = parts[0].to_string();
    let share = parts.get(1).unwrap_or(&"").to_string();
    let path = parts.get(2).unwrap_or(&"").to_string();

    if share.is_empty() {
        return Err(AftError::InvalidUrl("SMB URL missing share name".into()));
    }

    // Sanitize all components to prevent command injection via smbclient
    validate_smb_component(&server, "server")?;
    validate_smb_component(&share, "share")?;
    if !path.is_empty() {
        for segment in path.split('/') {
            if !segment.is_empty() {
                validate_smb_component(segment, "path")?;
            }
        }
    }

    Ok((server, share, path, user))
}

/// Validate an SMB path component contains only safe characters.
/// Rejects characters that could enable command injection in smbclient,
/// including control characters, shell metacharacters, and newlines.
fn validate_smb_component(component: &str, kind: &str) -> AftResult<()> {
    if component.is_empty() {
        return Err(AftError::InvalidUrl(format!("SMB {} is empty", kind)));
    }
    // Reject any control characters (ASCII 0-31, 127, and C1 range 128-159)
    for ch in component.chars() {
        if ch.is_control() || ('\u{0080}'..='\u{009F}').contains(&ch) {
            return Err(AftError::InvalidUrl(format!(
                "SMB {} contains control character U+{:04X}. Control characters are not allowed.",
                kind, ch as u32
            )));
        }
    }
    // Allow alphanumerics, dots, hyphens, underscores, and spaces
    // Reject quotes, backticks, semicolons, pipes, and other shell metacharacters
    for ch in component.chars() {
        if !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' | ' ') {
            return Err(AftError::InvalidUrl(format!(
                "SMB {} contains unsafe character '{}'. Only alphanumerics, dots, hyphens, underscores, and spaces are allowed.",
                kind, ch
            )));
        }
    }
    // Prevent path traversal
    if component == ".." || component == "." {
        return Err(AftError::InvalidUrl(format!(
            "SMB {} cannot be '.' or '..'",
            kind
        )));
    }
    Ok(())
}

/// Convert smb://server/share/path to a UNC path for local filesystem operations.
/// On Windows: \\server\share\path
/// On Unix: Requires mount at a known location or uses smbclient CLI.
fn to_unc_path(server: &str, share: &str, path: &str) -> String {
    if cfg!(windows) {
        let mut unc = format!("\\\\{}\\{}", server, share);
        if !path.is_empty() {
            unc.push('\\');
            unc.push_str(&path.replace('/', "\\"));
        }
        unc
    } else {
        // On Unix, construct a path for potential CIFS mount points
        let mut p = format!("//{}/{}", server, share);
        if !path.is_empty() {
            p.push('/');
            p.push_str(path);
        }
        p
    }
}

/// Try to access SMB via UNC path (works on Windows natively, or pre-mounted shares on Unix).
async fn access_via_unc(unc_path: &str) -> bool {
    tokio::fs::metadata(unc_path).await.is_ok()
}

#[async_trait]
impl ProtocolHandler for SmbHandler {
    fn scheme(&self) -> &str {
        "smb"
    }

    fn name(&self) -> &str {
        "SMB/CIFS"
    }

    fn supports_ranges(&self) -> bool {
        false
    }

    fn supports_resume(&self) -> bool {
        false
    }

    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
        let (server, share, path, _user) = parse_smb_url(url)?;
        let unc = to_unc_path(&server, &share, &path);

        if !access_via_unc(&unc).await {
            return Err(attempt_smbclient_head(&server, &share, &path, opts).await);
        }

        let metadata = tokio::fs::metadata(&unc).await.map_err(|e| {
            AftError::ConnectionFailed(format!("SMB access failed for {}: {}", unc, e))
        })?;

        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                chrono::DateTime::from_timestamp(d.as_secs() as i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default()
            });

        let content_type = if metadata.is_dir() {
            Some("inode/directory".to_string())
        } else {
            Some("application/octet-stream".to_string())
        };

        Ok(ResourceMetadata {
            content_length: if metadata.is_file() {
                Some(metadata.len())
            } else {
                None
            },
            content_type,
            last_modified: modified,
            etag: None,
            accepts_ranges: false,
            headers: HashMap::new(),
        })
    }

    async fn download(
        &self,
        url: &str,
        dest: &Path,
        opts: &ProtocolOptions,
        _resume_from: Option<u64>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let (server, share, path, _user) = parse_smb_url(url)?;
        let unc = to_unc_path(&server, &share, &path);

        if !access_via_unc(&unc).await {
            return smbclient_download(&server, &share, &path, dest, opts).await;
        }

        // Direct file copy via UNC path
        let metadata = tokio::fs::metadata(&unc)
            .await
            .map_err(|e| AftError::FileNotFound(format!("SMB file not found: {}: {}", unc, e)))?;

        if !metadata.is_file() {
            return Err(AftError::Other(format!("{} is not a file", unc)));
        }

        let file_size = metadata.len();

        tokio::fs::copy(&unc, dest)
            .await
            .map_err(|e| AftError::TransferFailed(format!("SMB copy failed: {}", e)))?;

        if let Some(ref cb) = progress {
            cb(file_size, Some(file_size));
        }

        Ok(file_size)
    }

    async fn download_range(
        &self,
        _url: &str,
        _start: u64,
        _end: u64,
        _opts: &ProtocolOptions,
    ) -> AftResult<Vec<u8>> {
        Err(AftError::Other(
            "SMB does not support range downloads".into(),
        ))
    }

    async fn upload(
        &self,
        source: &Path,
        url: &str,
        opts: &ProtocolOptions,
        _content_type: Option<&str>,
        _method: Option<&str>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let (server, share, path, _user) = parse_smb_url(url)?;
        let unc = to_unc_path(&server, &share, &path);

        if !source.exists() {
            return Err(AftError::FileNotFound(format!(
                "Source file not found: {:?}",
                source
            )));
        }

        let file_size = tokio::fs::metadata(source).await?.len();

        // Try UNC path first
        let unc_parent = Path::new(&unc).parent();
        let unc_accessible = if let Some(parent) = unc_parent {
            access_via_unc(&parent.to_string_lossy()).await
        } else {
            false
        };

        if unc_accessible {
            tokio::fs::copy(source, &unc)
                .await
                .map_err(|e| AftError::TransferFailed(format!("SMB upload failed: {}", e)))?;
        } else {
            return smbclient_upload(source, &server, &share, &path, opts).await;
        }

        if let Some(ref cb) = progress {
            cb(file_size, Some(file_size));
        }

        Ok(file_size)
    }

    async fn list(&self, url: &str, opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        let (server, share, path, _user) = parse_smb_url(url)?;
        let unc = to_unc_path(&server, &share, &path);

        if !access_via_unc(&unc).await {
            return smbclient_list(&server, &share, &path, opts).await;
        }

        let mut entries = Vec::new();
        let mut dir = tokio::fs::read_dir(&unc)
            .await
            .map_err(|e| AftError::Other(format!("SMB list failed for {}: {}", unc, e)))?;

        while let Some(entry) = dir.next_entry().await? {
            let meta = entry.metadata().await?;
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| {
                    chrono::DateTime::from_timestamp(d.as_secs() as i64, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default()
                });

            entries.push(DirectoryEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                size: if meta.is_file() {
                    Some(meta.len())
                } else {
                    None
                },
                is_directory: meta.is_dir(),
                last_modified: modified,
            });
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }
}

// ── Fallback: smbclient CLI (for non-mounted shares) ────────────────────────

async fn attempt_smbclient_head(
    server: &str,
    share: &str,
    path: &str,
    _opts: &ProtocolOptions,
) -> AftError {
    // Check if smbclient is available
    let check = tokio::process::Command::new("smbclient")
        .arg("--version")
        .output()
        .await;

    if check.is_err() {
        return AftError::ConnectionFailed(format!(
            "Cannot access SMB share //{}/{}/{}: share is not mounted and 'smbclient' is not available. \
             On Windows, ensure the share is accessible. On Linux/macOS, install samba-client or mount the share.",
            server, share, path
        ));
    }

    AftError::ConnectionFailed(format!(
        "SMB share //{}/{}/ is not mounted. Mount it first or ensure network access.",
        server, share
    ))
}

async fn smbclient_download(
    server: &str,
    share: &str,
    path: &str,
    dest: &Path,
    _opts: &ProtocolOptions,
) -> AftResult<u64> {
    let smb_path = format!("//{}/{}", server, share);
    let remote_file = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };

    let dest_str = dest.to_string_lossy().to_string();
    let cmd = format!("get \"{}\" \"{}\"", remote_file, dest_str);

    let output = tokio::process::Command::new("smbclient")
        .arg(&smb_path)
        .arg("-N") // no password prompt
        .arg("-c")
        .arg(&cmd)
        .output()
        .await
        .map_err(|e| {
            AftError::ConnectionFailed(format!(
                "smbclient not available or failed: {}. Install samba-client or mount the share.",
                e
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AftError::TransferFailed(format!(
            "smbclient download failed: {}",
            stderr.trim()
        )));
    }

    let file_size = tokio::fs::metadata(dest).await?.len();
    Ok(file_size)
}

async fn smbclient_upload(
    source: &Path,
    server: &str,
    share: &str,
    path: &str,
    _opts: &ProtocolOptions,
) -> AftResult<u64> {
    let smb_path = format!("//{}/{}", server, share);
    let remote_file = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    let source_str = source.to_string_lossy().to_string();
    let cmd = format!("put \"{}\" \"{}\"", source_str, remote_file);

    let output = tokio::process::Command::new("smbclient")
        .arg(&smb_path)
        .arg("-N")
        .arg("-c")
        .arg(&cmd)
        .output()
        .await
        .map_err(|e| AftError::ConnectionFailed(format!("smbclient not available: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AftError::TransferFailed(format!(
            "smbclient upload failed: {}",
            stderr.trim()
        )));
    }

    let file_size = tokio::fs::metadata(source).await?.len();
    Ok(file_size)
}

async fn smbclient_list(
    server: &str,
    share: &str,
    path: &str,
    _opts: &ProtocolOptions,
) -> AftResult<Vec<DirectoryEntry>> {
    let smb_path = format!("//{}/{}", server, share);
    let dir_path = if path.is_empty() || path == "/" {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    let cmd = format!("ls \"{}*\"", dir_path);

    let output = tokio::process::Command::new("smbclient")
        .arg(&smb_path)
        .arg("-N")
        .arg("-c")
        .arg(&cmd)
        .output()
        .await
        .map_err(|e| AftError::ConnectionFailed(format!("smbclient not available: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AftError::Other(format!(
            "smbclient list failed: {}",
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        // smbclient ls output format: "  filename    D     0  Mon Jan  1 00:00:00 2024"
        if trimmed.is_empty() || trimmed.starts_with("blocks") || trimmed.starts_with("Total") {
            continue;
        }

        // Skip . and .. entries
        if trimmed.starts_with(". ") || trimmed.starts_with(".. ") {
            continue;
        }

        let is_dir = trimmed.contains("  D  ") || trimmed.contains("\tD\t");
        // Extract name (first field before multiple spaces)
        if let Some(name_end) = trimmed.find("  ") {
            let name = trimmed[..name_end].trim().to_string();
            if !name.is_empty() && name != "." && name != ".." {
                entries.push(DirectoryEntry {
                    name,
                    size: None,
                    is_directory: is_dir,
                    last_modified: None,
                });
            }
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}
