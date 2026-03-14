use std::path::Path;
use std::sync::Arc;

use sha2::Digest;
use tokio::sync::Mutex;

use crate::error::{AftError, AftResult};
use crate::protocols::{ProtocolHandler, ProtocolOptions};

/// Configuration for the transfer engine
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Number of parallel connections for chunked downloads
    pub parallel_chunks: usize,
    /// Size of each chunk in bytes for parallel downloads
    pub chunk_size: u64,
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial retry delay in milliseconds (doubles each retry)
    pub retry_delay_ms: u64,
    /// Optional checksum verification after transfer
    pub verify_checksum: Option<ChecksumConfig>,
    /// Whether to attempt resuming interrupted transfers
    pub resume: bool,
    /// Maximum bandwidth in bytes per second (0 = unlimited)
    pub rate_limit_bytes_per_sec: u64,
}

#[derive(Debug, Clone)]
pub struct ChecksumConfig {
    pub algorithm: String,
    pub expected_value: Option<String>,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            parallel_chunks: 4,
            chunk_size: 8 * 1024 * 1024, // 8 MB chunks
            max_retries: 3,
            retry_delay_ms: 1000,
            verify_checksum: None,
            resume: false,
            rate_limit_bytes_per_sec: 0,
        }
    }
}

/// Result of a completed transfer operation
#[derive(Debug, Clone, serde::Serialize)]
pub struct TransferResult {
    pub bytes_transferred: u64,
    pub duration_ms: u64,
    pub throughput_bytes_per_sec: f64,
    pub checksum: Option<ChecksumResult>,
    pub retries_used: u32,
    pub chunks_used: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChecksumResult {
    pub algorithm: String,
    pub value: String,
    pub verified: bool,
}

/// Execute a download with automatic retry, parallel chunking, and checksum verification.
///
/// The engine will:
/// 1. Probe the server for range support and content length
/// 2. Use parallel chunked downloads if the server supports ranges and the file is large enough
/// 3. Fall back to single-stream download otherwise
/// 4. Retry failed transfers with exponential backoff
/// 5. Verify checksum if configured
pub async fn download(
    handler: &dyn ProtocolHandler,
    url: &str,
    dest: &Path,
    opts: &ProtocolOptions,
    config: &TransferConfig,
    progress_cb: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>>,
) -> AftResult<TransferResult> {
    let start = std::time::Instant::now();
    let mut retries = 0u32;

    // Determine resume offset
    let resume_offset = if config.resume {
        match tokio::fs::metadata(dest).await {
            Ok(meta) => Some(meta.len()),
            Err(_) => None,
        }
    } else {
        None
    };

    // Probe server for metadata
    let metadata = handler.head(url, opts).await.ok();
    let total_size = metadata.as_ref().and_then(|m| m.content_length);
    let supports_ranges = metadata.as_ref().map(|m| m.accepts_ranges).unwrap_or(false);

    // Decide between parallel chunked download and single-stream
    let use_chunks = supports_ranges
        && total_size.is_some()
        && config.parallel_chunks > 1
        && total_size.unwrap() > config.chunk_size * 2;

    let bytes = if use_chunks {
        let total = total_size.unwrap();
        match chunked_download(handler, url, dest, opts, config, total, progress_cb.clone()).await {
            Ok(bytes) => bytes,
            Err(_) => {
                // Fall back to single-stream
                retry_download(
                    handler,
                    url,
                    dest,
                    opts,
                    config,
                    resume_offset,
                    &mut retries,
                    progress_cb.clone(),
                )
                .await?
            }
        }
    } else {
        retry_download(
            handler,
            url,
            dest,
            opts,
            config,
            resume_offset,
            &mut retries,
            progress_cb.clone(),
        )
        .await?
    };

    let duration = start.elapsed();
    let duration_ms = duration.as_millis() as u64;
    let throughput = if duration_ms > 0 {
        bytes as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    // Compute and verify checksum if requested
    let checksum = if let Some(ref cs_config) = config.verify_checksum {
        Some(compute_and_verify_checksum(dest, cs_config).await?)
    } else {
        None
    };

    Ok(TransferResult {
        bytes_transferred: bytes,
        duration_ms,
        throughput_bytes_per_sec: throughput,
        checksum,
        retries_used: retries,
        chunks_used: if use_chunks {
            config.parallel_chunks
        } else {
            1
        },
    })
}

/// Execute an upload with automatic retry and exponential backoff
pub async fn upload(
    handler: &dyn ProtocolHandler,
    source: &Path,
    url: &str,
    opts: &ProtocolOptions,
    config: &TransferConfig,
    content_type: Option<&str>,
    method: Option<&str>,
    progress_cb: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>>,
) -> AftResult<TransferResult> {
    let start = std::time::Instant::now();
    let mut retries = 0u32;
    let mut last_err = None;

    while retries <= config.max_retries {
        if retries > 0 {
            let delay = config.retry_delay_ms * 2u64.pow(retries - 1);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }

        let cb: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>> =
            progress_cb.clone().map(|cb| {
                Box::new(move |bytes: u64, total: Option<u64>| cb(bytes, total))
                    as Box<dyn Fn(u64, Option<u64>) + Send + Sync>
            });

        match handler
            .upload(source, url, opts, content_type, method, cb)
            .await
        {
            Ok(bytes) => {
                let duration = start.elapsed();
                let duration_ms = duration.as_millis() as u64;
                let throughput = if duration_ms > 0 {
                    bytes as f64 / duration.as_secs_f64()
                } else {
                    0.0
                };

                return Ok(TransferResult {
                    bytes_transferred: bytes,
                    duration_ms,
                    throughput_bytes_per_sec: throughput,
                    checksum: None,
                    retries_used: retries,
                    chunks_used: 1,
                });
            }
            Err(e) => {
                last_err = Some(e);
                retries += 1;
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| AftError::TransferFailed("Upload failed after all retries".to_string())))
}

/// Single-stream download with retry and exponential backoff
async fn retry_download(
    handler: &dyn ProtocolHandler,
    url: &str,
    dest: &Path,
    opts: &ProtocolOptions,
    config: &TransferConfig,
    resume_from: Option<u64>,
    retries: &mut u32,
    progress_cb: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>>,
) -> AftResult<u64> {
    let mut last_err = None;

    while *retries <= config.max_retries {
        if *retries > 0 {
            let delay = config.retry_delay_ms * 2u64.pow(*retries - 1);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }

        let cb: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>> =
            progress_cb.clone().map(|cb| {
                Box::new(move |bytes: u64, total: Option<u64>| cb(bytes, total))
                    as Box<dyn Fn(u64, Option<u64>) + Send + Sync>
            });

        match handler.download(url, dest, opts, resume_from, cb).await {
            Ok(bytes) => return Ok(bytes),
            Err(e) => {
                last_err = Some(e);
                *retries += 1;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        AftError::TransferFailed("Download failed after all retries".to_string())
    }))
}

/// Parallel chunked download for large files with range support.
///
/// Splits the file into chunks and downloads them concurrently, writing
/// each chunk to the correct offset in the output file. Falls back to
/// single-stream on failure.
async fn chunked_download(
    _handler: &dyn ProtocolHandler,
    url: &str,
    dest: &Path,
    opts: &ProtocolOptions,
    config: &TransferConfig,
    total_size: u64,
    progress_cb: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>>,
) -> AftResult<u64> {
    let num_chunks = ((total_size + config.chunk_size - 1) / config.chunk_size) as usize;
    let chunks: Vec<(u64, u64)> = (0..num_chunks)
        .map(|i| {
            let start = i as u64 * config.chunk_size;
            let end = std::cmp::min(start + config.chunk_size - 1, total_size - 1);
            (start, end)
        })
        .collect();

    // Pre-allocate output file to final size
    let file = tokio::fs::File::create(dest).await?;
    file.set_len(total_size).await?;
    drop(file);

    let dest = dest.to_path_buf();
    let progress = Arc::new(Mutex::new(0u64));
    let num_parallel = std::cmp::min(config.parallel_chunks, num_chunks);
    let rate_limit = config.rate_limit_bytes_per_sec;
    let transfer_start = std::time::Instant::now();

    // Semaphore controls concurrent chunk downloads
    let semaphore = Arc::new(tokio::sync::Semaphore::new(num_parallel));
    let mut handles = Vec::with_capacity(num_chunks);

    for (start, end) in chunks {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| AftError::Other(e.to_string()))?;

        let opts = opts.clone();
        let dest = dest.clone();
        let progress = progress.clone();
        let progress_cb = progress_cb.clone();
        let url = url.to_string();
        let t_start = transfer_start;

        let handle = tokio::spawn(async move {
            // Create a fresh handler for this task
            let handler = crate::protocols::resolve_protocol(&url)?;
            let data = handler.download_range(&url, start, end, &opts).await?;

            // Write chunk to correct file offset
            use tokio::io::{AsyncSeekExt, AsyncWriteExt};
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .open(&dest)
                .await?;
            file.seek(std::io::SeekFrom::Start(start)).await?;
            file.write_all(&data).await?;

            let chunk_bytes = data.len() as u64;
            let mut total_progress = progress.lock().await;
            *total_progress += chunk_bytes;
            if let Some(ref cb) = progress_cb {
                cb(*total_progress, Some(end + 1));
            }

            // Rate limiting: if we're exceeding the limit, sleep
            if rate_limit > 0 {
                let elapsed = t_start.elapsed().as_secs_f64();
                let expected_duration = *total_progress as f64 / rate_limit as f64;
                if expected_duration > elapsed {
                    let sleep_ms = ((expected_duration - elapsed) * 1000.0) as u64;
                    drop(total_progress);
                    tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;
                }
            }

            drop(permit);
            Ok::<u64, AftError>(chunk_bytes)
        });

        handles.push(handle);
    }

    let mut total_bytes = 0u64;
    for handle in handles {
        let bytes = handle.await.map_err(|e| AftError::Other(e.to_string()))??;
        total_bytes += bytes;
    }

    Ok(total_bytes)
}

/// Compute a file's checksum and optionally verify against an expected value
async fn compute_and_verify_checksum(
    path: &Path,
    config: &ChecksumConfig,
) -> AftResult<ChecksumResult> {
    let data = tokio::fs::read(path).await?;

    let hash_value = match config.algorithm.as_str() {
        "sha256" => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&data);
            hex::encode(hasher.finalize())
        }
        "sha512" => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(&data);
            hex::encode(hasher.finalize())
        }
        "md5" => {
            let mut hasher = md5::Md5::new();
            hasher.update(&data);
            hex::encode(hasher.finalize())
        }
        _ => {
            return Err(AftError::Other(format!(
                "Unsupported checksum algorithm: {}",
                config.algorithm
            )));
        }
    };

    let verified = if let Some(ref expected) = config.expected_value {
        if expected.eq_ignore_ascii_case(&hash_value) {
            true
        } else {
            return Err(AftError::ChecksumMismatch {
                expected: expected.clone(),
                actual: hash_value,
            });
        }
    } else {
        false
    };

    Ok(ChecksumResult {
        algorithm: config.algorithm.clone(),
        value: hash_value,
        verified,
    })
}
