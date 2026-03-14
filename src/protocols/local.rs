use std::collections::HashMap;
use std::path::Path;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{DirectoryEntry, ProtocolHandler, ProtocolOptions, ResourceMetadata};
use crate::error::{AftError, AftResult};

pub struct LocalHandler;

#[async_trait]
impl ProtocolHandler for LocalHandler {
    fn scheme(&self) -> &str {
        "file"
    }

    fn name(&self) -> &str {
        "Local File System"
    }

    fn supports_ranges(&self) -> bool {
        true
    }

    fn supports_resume(&self) -> bool {
        true
    }

    async fn head(&self, url: &str, _opts: &ProtocolOptions) -> AftResult<ResourceMetadata> {
        let path = url_to_path(url);
        let metadata = tokio::fs::metadata(&path).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => AftError::FileNotFound(path.clone()),
            std::io::ErrorKind::PermissionDenied => AftError::PermissionDenied(path.clone()),
            _ => AftError::Io(e),
        })?;

        let last_modified = metadata
            .modified()
            .ok()
            .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());

        Ok(ResourceMetadata {
            content_length: Some(metadata.len()),
            content_type: guess_content_type(&path),
            last_modified,
            etag: None,
            accepts_ranges: true,
            headers: HashMap::new(),
        })
    }

    async fn download(
        &self,
        url: &str,
        dest: &Path,
        _opts: &ProtocolOptions,
        resume_from: Option<u64>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let source_path = url_to_path(url);
        let mut source =
            tokio::fs::File::open(&source_path)
                .await
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => AftError::FileNotFound(source_path.clone()),
                    std::io::ErrorKind::PermissionDenied => {
                        AftError::PermissionDenied(source_path.clone())
                    }
                    _ => AftError::Io(e),
                })?;

        let total_size = source.metadata().await?.len();
        let mut bytes_written = 0u64;

        if let Some(offset) = resume_from {
            use tokio::io::AsyncSeekExt;
            source.seek(std::io::SeekFrom::Start(offset)).await?;
            bytes_written = offset;
        }

        let mut dest_file = if resume_from.is_some() {
            tokio::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(dest)
                .await?
        } else {
            tokio::fs::File::create(dest).await?
        };

        let mut buf = vec![0u8; 256 * 1024]; // 256KB buffer for throughput
        loop {
            let n = source.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            dest_file.write_all(&buf[..n]).await?;
            bytes_written += n as u64;
            if let Some(ref cb) = progress {
                cb(bytes_written, Some(total_size));
            }
        }

        dest_file.flush().await?;
        Ok(bytes_written)
    }

    async fn download_range(
        &self,
        url: &str,
        start: u64,
        end: u64,
        _opts: &ProtocolOptions,
    ) -> AftResult<Vec<u8>> {
        use tokio::io::AsyncSeekExt;
        let path = url_to_path(url);
        let mut file = tokio::fs::File::open(&path).await?;
        file.seek(std::io::SeekFrom::Start(start)).await?;
        let len = (end - start + 1) as usize;
        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn upload(
        &self,
        source: &Path,
        url: &str,
        _opts: &ProtocolOptions,
        _content_type: Option<&str>,
        _method: Option<&str>,
        progress: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    ) -> AftResult<u64> {
        let dest_path = url_to_path(url);

        if let Some(parent) = Path::new(&dest_path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut src = tokio::fs::File::open(source).await?;
        let total = src.metadata().await?.len();
        let mut dst = tokio::fs::File::create(&dest_path).await?;

        let mut buf = vec![0u8; 256 * 1024];
        let mut written = 0u64;

        loop {
            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            dst.write_all(&buf[..n]).await?;
            written += n as u64;
            if let Some(ref cb) = progress {
                cb(written, Some(total));
            }
        }

        dst.flush().await?;
        Ok(written)
    }

    async fn list(&self, url: &str, _opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        let path = url_to_path(url);
        let mut entries = Vec::new();
        let mut dir =
            tokio::fs::read_dir(&path)
                .await
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => AftError::FileNotFound(path.clone()),
                    std::io::ErrorKind::PermissionDenied => {
                        AftError::PermissionDenied(path.clone())
                    }
                    _ => AftError::Io(e),
                })?;

        while let Some(entry) = dir.next_entry().await? {
            let meta = entry.metadata().await?;
            let last_modified = meta
                .modified()
                .ok()
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());

            entries.push(DirectoryEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                size: Some(meta.len()),
                is_directory: meta.is_dir(),
                last_modified,
            });
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }
}

fn url_to_path(url: &str) -> String {
    if let Some(path) = url.strip_prefix("file://") {
        #[cfg(target_os = "windows")]
        {
            let path = path.strip_prefix('/').unwrap_or(path);
            path.replace('/', "\\")
        }
        #[cfg(not(target_os = "windows"))]
        {
            path.to_string()
        }
    } else {
        url.to_string()
    }
}

fn guess_content_type(path: &str) -> Option<String> {
    let ext = path.rsplit('.').next()?.to_lowercase();
    let ct = match ext.as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "bz2" => "application/x-bzip2",
        "xz" => "application/x-xz",
        "zst" => "application/zstd",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/vnd.rar",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "wasm" => "application/wasm",
        "csv" => "text/csv",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        "rb" => "text/x-ruby",
        "go" => "text/x-go",
        "c" | "h" => "text/x-c",
        "cpp" | "cc" | "cxx" | "hpp" => "text/x-c++",
        "java" => "text/x-java",
        "ts" => "text/typescript",
        "tsx" | "jsx" => "text/x-tsx",
        "sh" | "bash" => "text/x-shellscript",
        "sql" => "text/x-sql",
        "dockerfile" => "text/x-dockerfile",
        _ => return None,
    };
    Some(ct.to_string())
}
