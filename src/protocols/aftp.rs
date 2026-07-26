//! ProtocolHandler implementation for the AFTP (Agentic File Transfer Protocol).
//!
//! Thin adapter: maps the generic `ProtocolHandler` trait surface onto the
//! concrete `AftpClient` in `crate::aftp::client`.
//!
//! Supports both `aftp://` (plain) and `aftps://` (TLS-encrypted) URLs.

use std::collections::HashMap;
use std::path::Path;

use async_trait::async_trait;

use crate::aftp::client::{parse_aftp_url, AftpClient};
use crate::error::AftResult;

use super::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};

pub struct AftpHandler {
    scheme: String,
}

impl AftpHandler {
    pub fn new(scheme: String) -> Self {
        Self { scheme }
    }

    /// Push a whole local directory tree to `url` as one fountain-coded packed
    /// object (see [`AftpClient::upload_tree`]). This is *not* part of the
    /// generic `ProtocolHandler` trait — it is AFTP-specific and reachable only
    /// when the caller has opted into the FEC data plane (`--fec`), because
    /// tree packing has no reliable fallback. Returns the packed byte count.
    #[allow(clippy::type_complexity)]
    pub async fn upload_tree(
        &self,
        source: &Path,
        url: &str,
        opts: &ProtocolOptions,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let (client, path) = make_client(url, opts)?;
        let cb = progress.as_deref();
        client.upload_tree(source, &path, cb).await
    }
}

fn make_client(url: &str, opts: &ProtocolOptions) -> AftResult<(AftpClient, String)> {
    let (host, port, path, use_tls) = parse_aftp_url(url)?;
    let client = AftpClient::new(
        host,
        port,
        opts.bearer_token.clone(),
        use_tls,
        opts.insecure,
    )
    .with_fec(opts.fec)
    .with_fec_quic(opts.fec_quic)
    .with_unauthenticated_fec(opts.fec_allow_unauthenticated);
    Ok((client, path))
}

#[async_trait]
impl ProtocolHandler for AftpHandler {
    fn scheme(&self) -> &str {
        &self.scheme
    }

    fn name(&self) -> &str {
        "AFTP (Agentic File Transfer Protocol)"
    }

    fn supports_ranges(&self) -> bool {
        true
    }

    /// AFTP streams a whole file over one connection, and every range request
    /// costs a new connection plus a fresh HELLO handshake. Splitting a
    /// download into parallel ranges therefore pays repeated TCP slow-start
    /// for no gain — measurably slower than simply streaming.
    fn benefits_from_parallel_ranges(&self) -> bool {
        false
    }

    /// The AFTP server creates the full parent path when handling a PUT, so a
    /// tree sync does not need explicit `mkdir` calls — which is just as well,
    /// because the wire protocol has no MKDIR frame.
    fn creates_parent_dirs_on_write(&self) -> bool {
        true
    }

    fn supports_resume(&self) -> bool {
        true
    }

    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
        let (client, path) = make_client(url, opts)?;
        let info = client.head(&path).await?;
        Ok(ResourceMetadata {
            content_length: Some(info.size),
            content_type: Some(info.content_type),
            last_modified: Some(format!("{}", info.modified_secs)),
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
        let (client, path) = make_client(url, opts)?;
        // Resume is handled by starting a range GET from resume_from offset
        if let Some(offset) = resume_from {
            // For resume, do a range download and append
            let data = client.download_range(&path, offset, 0).await?;
            use tokio::io::AsyncWriteExt;
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dest)
                .await?;
            file.write_all(&data).await?;
            Ok(data.len() as u64)
        } else {
            let cb = progress.as_deref();
            client.download(&path, dest, cb).await
        }
    }

    async fn download_range(
        &self,
        url: &str,
        start: u64,
        end: u64,
        opts: &ProtocolOptions,
    ) -> AftResult<Vec<u8>> {
        let (client, path) = make_client(url, opts)?;
        client.download_range(&path, start, end).await
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
        let (client, path) = make_client(url, opts)?;
        let cb = progress.as_deref();
        client.upload(source, &path, cb).await
    }

    async fn list(&self, url: &str, opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        let (client, path) = make_client(url, opts)?;
        let entries = client.list(&path).await?;
        Ok(entries
            .into_iter()
            .map(|e| DirectoryEntry {
                name: e.name,
                size: Some(e.size),
                is_directory: e.is_dir,
                last_modified: Some(format!("{}", e.modified_secs)),
                relative_path: None,
                is_symlink: None,
                permissions: None,
            })
            .collect())
    }
}
