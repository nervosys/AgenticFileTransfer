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
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|e| match e.kind() {
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

        // Fast path: kernel-level copy when no resume is needed.
        if resume_from.is_none() {
            let sp = source_path.clone();
            let dp = dest.to_path_buf();
            let cb = progress;
            let copied = tokio::task::spawn_blocking(move || -> AftResult<u64> {
                let n = std::fs::copy(&sp, &dp).map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => AftError::FileNotFound(sp.clone()),
                    std::io::ErrorKind::PermissionDenied => AftError::PermissionDenied(sp.clone()),
                    _ => AftError::Io(e),
                })?;
                if let Some(ref cb) = cb {
                    cb(n, Some(n));
                }
                Ok(n)
            })
            .await
            .map_err(|e| AftError::Other(format!("spawn_blocking: {}", e)))??;
            return Ok(copied);
        }

        // Resume path: buffered async I/O
        let mut source = tokio::fs::File::open(&source_path)
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
        let mut dest_file = tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(dest)
            .await?;
        let mut buf = vec![0u8; 4 * 1024 * 1024];
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

        // Fast path: kernel-level copy
        let sp = source.to_path_buf();
        let dp = dest_path.clone();
        let cb = progress;
        let copied = tokio::task::spawn_blocking(move || -> AftResult<u64> {
            let n = std::fs::copy(&sp, &dp).map_err(AftError::Io)?;
            if let Some(ref cb) = cb {
                cb(n, Some(n));
            }
            Ok(n)
        })
        .await
        .map_err(|e| AftError::Other(format!("spawn_blocking: {}", e)))??;
        Ok(copied)
    }

    async fn list(&self, url: &str, _opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>> {
        let path = url_to_path(url);
        let mut entries = Vec::new();
        let mut dir = tokio::fs::read_dir(&path)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => AftError::FileNotFound(path.clone()),
                std::io::ErrorKind::PermissionDenied => AftError::PermissionDenied(path.clone()),
                _ => AftError::Io(e),
            })?;

        while let Some(entry) = dir.next_entry().await? {
            let meta = entry.metadata().await?;
            let last_modified = meta
                .modified()
                .ok()
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());

            let is_symlink = entry.file_type().await.map(|ft| ft.is_symlink()).ok();

            #[cfg(unix)]
            let permissions = {
                use std::os::unix::fs::PermissionsExt;
                Some(meta.permissions().mode())
            };
            #[cfg(not(unix))]
            let permissions = None;

            entries.push(DirectoryEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                size: Some(meta.len()),
                is_directory: meta.is_dir(),
                last_modified,
                relative_path: None,
                is_symlink,
                permissions,
            });
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    fn supports_extended_ops(&self) -> bool {
        true
    }

    async fn delete(&self, url: &str, _recursive: bool, _opts: &ProtocolOptions) -> AftResult<()> {
        let path = url_to_path(url);
        let meta = tokio::fs::metadata(&path)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => AftError::FileNotFound(path.clone()),
                std::io::ErrorKind::PermissionDenied => AftError::PermissionDenied(path.clone()),
                _ => AftError::Io(e),
            })?;

        if meta.is_dir() {
            tokio::fs::remove_dir_all(&path).await?;
        } else {
            tokio::fs::remove_file(&path).await?;
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str, _opts: &ProtocolOptions) -> AftResult<()> {
        let src = url_to_path(from);
        let dst = url_to_path(to);
        if let Some(parent) = std::path::Path::new(&dst).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::rename(&src, &dst).await?;
        Ok(())
    }

    async fn mkdir(&self, url: &str, _opts: &ProtocolOptions) -> AftResult<()> {
        let path = url_to_path(url);
        tokio::fs::create_dir_all(&path).await?;
        Ok(())
    }

    async fn set_timestamps(
        &self,
        url: &str,
        mtime: chrono::DateTime<chrono::Utc>,
        _opts: &ProtocolOptions,
    ) -> AftResult<()> {
        let path = url_to_path(url);
        let system_time = std::time::SystemTime::from(mtime);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => AftError::FileNotFound(path.clone()),
                _ => AftError::Io(e),
            })?;
        file.set_modified(system_time)?;
        Ok(())
    }

    async fn exists(&self, url: &str, _opts: &ProtocolOptions) -> AftResult<bool> {
        let path = url_to_path(url);
        Ok(std::path::Path::new(&path).exists())
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
