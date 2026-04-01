use std::collections::HashMap;
use std::path::Path;

use async_trait::async_trait;
use futures::io::AsyncReadExt as FuturesReadExt;
use suppaftp::AsyncFtpStream;
use tokio::io::AsyncWriteExt;

use super::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};
use crate::error::{AftError, AftResult};

pub struct FtpHandler {
    scheme: String,
}

impl FtpHandler {
    pub fn new(scheme: String) -> Self {
        Self { scheme }
    }
}

/// Parse an FTP URL into (host, port, user, password, path).
#[allow(clippy::type_complexity)]
fn parse_ftp_url(url: &str) -> AftResult<(String, u16, Option<String>, Option<String>, String)> {
    let parsed = url::Url::parse(url)
        .map_err(|e| AftError::InvalidUrl(format!("Invalid FTP URL: {}", e)))?;

    let host = parsed
        .host_str()
        .ok_or_else(|| AftError::InvalidUrl("FTP URL missing host".into()))?
        .to_string();
    let port = parsed.port().unwrap_or(21);
    let user = if parsed.username().is_empty() {
        None
    } else {
        Some(parsed.username().to_string())
    };
    let pass = parsed.password().map(|s| s.to_string());
    let path = parsed.path().to_string();

    Ok((host, port, user, pass, path))
}

async fn connect_ftp(
    url: &str,
    opts: &ProtocolOptions,
    _scheme: &str,
) -> AftResult<(AsyncFtpStream, String)> {
    let (host, port, user, pass, path) = parse_ftp_url(url)?;

    let addr = format!("{}:{}", host, port);
    let mut ftp = AsyncFtpStream::connect(addr)
        .await
        .map_err(|e| AftError::ConnectionFailed(format!("FTP connect: {}", e)))?;

    // Login
    let login_user = user
        .or_else(|| opts.basic_auth.as_ref().map(|(u, _)| u.clone()))
        .unwrap_or_else(|| "anonymous".to_string());
    let login_pass = pass
        .or_else(|| opts.basic_auth.as_ref().map(|(_, p)| p.clone()))
        .unwrap_or_else(|| "aft@".to_string());

    ftp.login(&login_user, &login_pass)
        .await
        .map_err(|e| AftError::ConnectionFailed(format!("FTP login: {}", e)))?;

    // Use binary mode
    ftp.transfer_type(suppaftp::types::FileType::Binary)
        .await
        .map_err(|e| AftError::Other(format!("FTP binary mode: {}", e)))?;

    Ok((ftp, path))
}

#[async_trait]
impl ProtocolHandler for FtpHandler {
    fn scheme(&self) -> &str {
        &self.scheme
    }

    fn name(&self) -> &str {
        "FTP/FTPS"
    }

    fn supports_ranges(&self) -> bool {
        true
    }

    fn supports_resume(&self) -> bool {
        true
    }

    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
        let (mut ftp, path) = connect_ftp(url, opts, &self.scheme).await?;

        let size = ftp
            .size(&path)
            .await
            .map_err(|e| AftError::Other(format!("FTP SIZE: {}", e)))?;

        let mdtm = ftp.mdtm(&path).await.ok().map(|dt| dt.to_string());

        let _ = ftp.quit().await;

        Ok(ResourceMetadata {
            content_length: Some(size as u64),
            content_type: None,
            last_modified: mdtm,
            etag: None,
            accepts_ranges: true,
            headers: HashMap::new(),
        })
    }

    async fn download(
        &self,
        url: &str,
        dest: &Path,
        opts: &ProtocolOptions,
        resume_from: Option<u64>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let (mut ftp, path) = connect_ftp(url, opts, &self.scheme).await?;

        let total_size = ftp.size(&path).await.ok().map(|s| s as u64);

        if let Some(offset) = resume_from {
            ftp.resume_transfer(offset as usize)
                .await
                .map_err(|e| AftError::Other(format!("FTP REST: {}", e)))?;
        }

        let mut stream = ftp
            .retr_as_stream(&path)
            .await
            .map_err(|e| AftError::TransferFailed(format!("FTP RETR: {}", e)))?;

        let mut data = Vec::new();
        FuturesReadExt::read_to_end(&mut stream, &mut data)
            .await
            .map_err(|e| AftError::TransferFailed(format!("FTP read: {}", e)))?;

        ftp.finalize_retr_stream(stream)
            .await
            .map_err(|e| AftError::Other(format!("FTP finalize: {}", e)))?;

        let bytes_len = data.len() as u64;

        let mut file = if resume_from.is_some() {
            tokio::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(dest)
                .await?
        } else {
            tokio::fs::File::create(dest).await?
        };

        file.write_all(&data).await?;
        file.flush().await?;

        if let Some(ref cb) = progress {
            cb(bytes_len, total_size);
        }

        let _ = ftp.quit().await;
        Ok(bytes_len)
    }

    async fn download_range(
        &self,
        url: &str,
        start: u64,
        end: u64,
        opts: &ProtocolOptions,
    ) -> AftResult<Vec<u8>> {
        let (mut ftp, path) = connect_ftp(url, opts, &self.scheme).await?;

        ftp.resume_transfer(start as usize)
            .await
            .map_err(|e| AftError::Other(format!("FTP REST: {}", e)))?;

        let mut stream = ftp
            .retr_as_stream(&path)
            .await
            .map_err(|e| AftError::TransferFailed(format!("FTP RETR range: {}", e)))?;

        let mut data = Vec::new();
        FuturesReadExt::read_to_end(&mut stream, &mut data)
            .await
            .map_err(|e| AftError::TransferFailed(format!("FTP read: {}", e)))?;

        ftp.finalize_retr_stream(stream)
            .await
            .map_err(|e| AftError::Other(format!("FTP finalize: {}", e)))?;

        // Truncate to requested range
        let expected_len = (end - start + 1) as usize;
        data.truncate(expected_len);

        let _ = ftp.quit().await;
        Ok(data)
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
        let (mut ftp, path) = connect_ftp(url, opts, &self.scheme).await?;

        let data = tokio::fs::read(source).await?;
        let file_size = data.len() as u64;
        let mut cursor = futures::io::Cursor::new(data);

        ftp.put_file(&path, &mut cursor)
            .await
            .map_err(|e| AftError::TransferFailed(format!("FTP STOR: {}", e)))?;

        if let Some(ref cb) = progress {
            cb(file_size, Some(file_size));
        }

        let _ = ftp.quit().await;
        Ok(file_size)
    }

    async fn list(&self, url: &str, opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        let (mut ftp, path) = connect_ftp(url, opts, &self.scheme).await?;

        let list_path = if path.is_empty() || path == "/" {
            None
        } else {
            Some(path.as_str())
        };

        let raw_entries = ftp
            .list(list_path)
            .await
            .map_err(|e| AftError::Other(format!("FTP LIST: {}", e)))?;

        let _ = ftp.quit().await;

        let entries = raw_entries
            .iter()
            .filter_map(|line| parse_ftp_list_line(line))
            .collect();

        Ok(entries)
    }
}

/// Best-effort parser for Unix-style FTP LIST output lines.
fn parse_ftp_list_line(line: &str) -> Option<DirectoryEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 9 {
        return None;
    }

    let is_directory = parts[0].starts_with('d');
    let size = parts[4].parse::<u64>().unwrap_or(0);
    let name = parts[8..].join(" ");

    if name == "." || name == ".." {
        return None;
    }

    Some(DirectoryEntry {
        name,
        size: Some(size),
        is_directory,
        last_modified: Some(format!("{} {} {}", parts[5], parts[6], parts[7])),
        relative_path: None,
        is_symlink: None,
        permissions: None,
    })
}
