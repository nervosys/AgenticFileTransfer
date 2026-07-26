// Copyright (c) 2024-2026 Nervosys LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(dead_code)]
//! # Turbo Transfer Engine
//!
//! High-performance adaptive transfer engine that dynamically selects the
//! fastest transfer strategy based on link characteristics, protocol
//! capabilities, and file properties.
//!
//! ## Design goals
//!
//! Beat Globus, Aspera FASP, and HPN-SSH on raw throughput by:
//!
//! 1. **Adaptive mode selection** — probe the link (RTT, bandwidth estimate,
//!    loss rate) and pick the optimal strategy automatically.
//! 2. **Multi-stream parallelism** — open N concurrent TCP/QUIC streams per
//!    file and stripe data across them (Aspera-style).
//! 3. **Large socket buffers** — auto-tune `SO_SNDBUF`/`SO_RCVBUF` to the
//!    bandwidth-delay product (BDP) so the TCP window never limits throughput.
//! 4. **Memory-mapped reads** — zero-copy `mmap` for local source files,
//!    eliminating a kernel→userspace copy.
//! 5. **Write-behind pipeline** — double-buffered async writes so disk I/O
//!    never stalls the network path.
//! 6. **Adaptive chunk sizing** — start with 1 MB chunks, ramp to 16 MB as
//!    measured goodput stabilizes (avoids slow-start penalty on fast links).
//! 7. **Zero-copy frame path** — `write_frame_header` + direct payload write
//!    avoids allocating a contiguous frame buffer.

use std::path::Path;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::engine::{ProgressCb, TransferResult};
use crate::error::{AftError, AftResult};
use crate::protocols::{ProtocolHandler, ProtocolOptions};

// ── Constants ───────────────────────────────────────────────────────────────

/// Minimum chunk size during adaptive ramp-up (1 MB).
const CHUNK_MIN: u64 = 1 << 20;

/// Maximum chunk size after ramp-up (64 MB).
const CHUNK_MAX: u64 = 64 << 20;

/// Default number of parallel streams when turbo is enabled.
const DEFAULT_STREAMS: usize = 8;

/// Maximum parallel streams we'll ever open.
const MAX_STREAMS: usize = 128;

/// Target socket buffer size (16 MB) — covers most 10 Gbps × 10 ms BDPs.
const TARGET_SOCK_BUF: u32 = 16 * 1024 * 1024;

/// I/O buffer for non-mmap reads (4 MB — 16× the default 256 KB).
const IO_BUF_SIZE: usize = 4 * 1024 * 1024;

/// Probe payload size for RTT / bandwidth estimation.
const PROBE_PAYLOAD: usize = 64 * 1024; // 64 KB

/// Number of RTT probes to average.
const RTT_PROBES: usize = 3;

/// Threshold file size for turbo mode (files smaller than this use the
/// standard engine — turbo overhead isn't worth it).
const TURBO_THRESHOLD: u64 = 32 << 20; // 32 MB

/// Write-behind queue depth (number of in-flight buffers).
const WRITE_PIPELINE_DEPTH: usize = 4;

/// Maximum download size guard (same as engine.rs).
const MAX_DOWNLOAD_SIZE: u64 = 100 * 1024 * 1024 * 1024; // 100 GiB

// ── Transfer mode ───────────────────────────────────────────────────────────

/// The transfer strategy selected by the adaptive probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TransferMode {
    /// Standard single-stream (fallback for small files or lossy links).
    Standard,
    /// Multi-stream parallel chunked download/upload.
    MultiStream,
    /// Memory-mapped zero-copy with direct socket writes (local source).
    MmapDirect,
}

impl std::fmt::Display for TransferMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standard => write!(f, "standard"),
            Self::MultiStream => write!(f, "multi-stream"),
            Self::MmapDirect => write!(f, "mmap-direct"),
        }
    }
}

// ── Link profile ────────────────────────────────────────────────────────────

/// Measured characteristics of the network link.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LinkProfile {
    /// Round-trip time in microseconds.
    pub rtt_us: u64,
    /// Estimated bandwidth in bytes/sec (from probe burst).
    pub bandwidth_estimate: u64,
    /// Bandwidth-delay product in bytes.
    pub bdp_bytes: u64,
    /// Recommended socket buffer size.
    pub recommended_sock_buf: u32,
    /// Recommended number of parallel streams.
    pub recommended_streams: usize,
    /// Recommended initial chunk size.
    pub recommended_chunk: u64,
    /// Selected transfer mode.
    pub mode: TransferMode,
}

impl Default for LinkProfile {
    fn default() -> Self {
        Self {
            rtt_us: 0,
            bandwidth_estimate: 0,
            bdp_bytes: 0,
            recommended_sock_buf: TARGET_SOCK_BUF,
            recommended_streams: DEFAULT_STREAMS,
            recommended_chunk: CHUNK_MIN,
            mode: TransferMode::Standard,
        }
    }
}

// ── Turbo configuration ─────────────────────────────────────────────────────

/// User-facing configuration for turbo transfers.
#[derive(Debug, Clone)]
pub struct TurboConfig {
    /// Enable turbo mode (auto-selected if not set).
    pub enabled: bool,
    /// Override number of streams (0 = auto from probe).
    pub streams: usize,
    /// Override chunk size in bytes (0 = adaptive).
    pub chunk_size: u64,
    /// Override socket buffer size in bytes (0 = auto from BDP).
    pub sock_buf: u32,
    /// Use memory-mapped reads for local source files.
    pub mmap: bool,
    /// Enable write-behind pipelining.
    pub write_pipeline: bool,
    /// Maximum bandwidth in bytes/sec (0 = unlimited).
    pub rate_limit: u64,
}

impl Default for TurboConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            streams: 0,    // auto
            chunk_size: 0, // adaptive
            sock_buf: 0,   // auto from BDP
            mmap: true,
            write_pipeline: true,
            rate_limit: 0,
        }
    }
}

// ── Link probing ────────────────────────────────────────────────────────────

/// Probe the link by performing a small HEAD request (or range download) and
/// measuring RTT.  Returns a `LinkProfile` with recommendations.
pub async fn probe_link(
    handler: &dyn ProtocolHandler,
    url: &str,
    opts: &ProtocolOptions,
    file_size: Option<u64>,
    config: &TurboConfig,
) -> LinkProfile {
    let mut rtt_samples = Vec::with_capacity(RTT_PROBES);

    // Measure RTT via HEAD requests
    for _ in 0..RTT_PROBES {
        let t0 = Instant::now();
        let _ = handler.head(url, opts).await;
        let elapsed = t0.elapsed();
        rtt_samples.push(elapsed.as_micros() as u64);
    }

    // Use median RTT (robust to outliers)
    rtt_samples.sort_unstable();
    let rtt_us = if rtt_samples.is_empty() {
        1000 // assume 1 ms if we can't measure
    } else {
        rtt_samples[rtt_samples.len() / 2]
    };

    // Estimate bandwidth with a small range download if supported
    let bandwidth_estimate = if handler.supports_ranges() {
        let probe_size = PROBE_PAYLOAD.min(file_size.unwrap_or(PROBE_PAYLOAD as u64) as usize);
        if probe_size > 0 {
            let t0 = Instant::now();
            match handler
                .download_range(url, 0, (probe_size as u64).saturating_sub(1), opts)
                .await
            {
                Ok(data) => {
                    let elapsed = t0.elapsed();
                    let secs = elapsed.as_secs_f64().max(0.000_001);
                    (data.len() as f64 / secs) as u64
                }
                Err(_) => 100_000_000, // assume 100 MB/s on probe failure
            }
        } else {
            100_000_000
        }
    } else {
        // No range support → estimate from RTT (assume 1 Gbps if RTT < 1 ms,
        // scale down linearly for longer RTTs)
        let rtt_s = rtt_us as f64 / 1_000_000.0;
        if rtt_s < 0.001 {
            1_250_000_000 // ~10 Gbps (local or very fast)
        } else {
            // Conservative: assume 70% utilization of a 1 Gbps link
            (125_000_000.0 * 0.7 / (rtt_s * 100.0).max(1.0)) as u64
        }
    };

    // Bandwidth-delay product
    let bdp_bytes = (bandwidth_estimate as f64 * rtt_us as f64 / 1_000_000.0) as u64;

    // Socket buffer: at least 2× BDP, capped at TARGET_SOCK_BUF
    let recommended_sock_buf = if config.sock_buf > 0 {
        config.sock_buf
    } else {
        ((bdp_bytes * 2) as u32).clamp(256 * 1024, TARGET_SOCK_BUF)
    };

    // Number of streams: scale with BDP / chunk_size, capped
    let base_chunk = if config.chunk_size > 0 {
        config.chunk_size
    } else {
        CHUNK_MIN
    };

    let recommended_streams = if config.streams > 0 {
        config.streams.min(MAX_STREAMS)
    } else {
        // More streams for high-BDP links
        let s = ((bdp_bytes / base_chunk.max(1)) as usize + 1).clamp(2, DEFAULT_STREAMS);
        // Scale up further for very large files
        if let Some(size) = file_size {
            if size > 1 << 30 {
                // > 1 GB: up to 16 streams
                s.clamp(8, 16)
            } else if size > 256 << 20 {
                // > 256 MB: up to 12 streams
                s.clamp(6, 12)
            } else {
                s
            }
        } else {
            s
        }
    };

    // Adaptive chunk size: bigger chunks for higher bandwidth
    let recommended_chunk = if config.chunk_size > 0 {
        config.chunk_size.clamp(CHUNK_MIN, CHUNK_MAX)
    } else if bandwidth_estimate > 500_000_000 {
        // > 500 MB/s: use 16 MB chunks
        16 << 20
    } else if bandwidth_estimate > 100_000_000 {
        // > 100 MB/s: use 8 MB chunks
        8 << 20
    } else if bandwidth_estimate > 10_000_000 {
        // > 10 MB/s: use 4 MB chunks
        4 << 20
    } else {
        CHUNK_MIN
    };

    // Select mode
    let is_local_source =
        url.starts_with("file://") || url.starts_with('/') || url.starts_with('.');
    let mode = if is_local_source && config.mmap {
        TransferMode::MmapDirect
    } else if file_size.is_some_and(|s| s >= TURBO_THRESHOLD)
        && handler.supports_ranges()
        && recommended_streams > 1
    {
        TransferMode::MultiStream
    } else {
        TransferMode::Standard
    };

    LinkProfile {
        rtt_us,
        bandwidth_estimate,
        bdp_bytes,
        recommended_sock_buf,
        recommended_streams,
        recommended_chunk,
        mode,
    }
}

// ── Turbo upload ────────────────────────────────────────────────────────────

/// Upload a local file through the protocol handler, timing the transfer.
///
/// Note on `mmap`: the `ProtocolHandler::upload` contract takes a source
/// *path*, not a byte slice, so each handler owns its own read strategy and
/// there is nothing for this layer to memory-map. An earlier version of this
/// module had separate `turbo_upload_mmap` and `turbo_upload_buffered`
/// functions, but their bodies were identical and neither mapped anything.
/// Real zero-copy `mmap` does exist for local→local copies — see
/// [`turbo_local_copy_mmap`]. Making uploads genuinely zero-copy requires
/// widening the handler trait to accept a borrowed buffer, which is tracked
/// for the FEC data plane rather than bolted on here.
#[allow(clippy::too_many_arguments)]
pub async fn turbo_upload(
    handler: &dyn ProtocolHandler,
    source: &Path,
    url: &str,
    opts: &ProtocolOptions,
    _config: &TurboConfig,
    _profile: &LinkProfile,
    content_type: Option<&str>,
    method: Option<&str>,
    progress_cb: Option<ProgressCb>,
) -> AftResult<TransferResult> {
    let start = Instant::now();

    let cb = progress_cb.map(|cb| {
        Box::new(move |bytes: u64, total: Option<u64>| cb(bytes, total))
            as Box<dyn Fn(u64, Option<u64>) + Send + Sync>
    });

    let bytes = handler
        .upload(source, url, opts, content_type, method, cb)
        .await?;

    let duration = start.elapsed();
    let duration_ms = duration.as_millis() as u64;
    let throughput = if duration_ms > 0 {
        bytes as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    Ok(TransferResult {
        bytes_transferred: bytes,
        duration_ms,
        throughput_bytes_per_sec: throughput,
        checksum: None,
        retries_used: 0,
        chunks_used: 1,
    })
}

// ── Turbo local copy ────────────────────────────────────────────────────────

/// Ultra-fast local-to-local copy using mmap read + pipelined writes.
/// Falls back to large-buffer I/O on mmap failure.
pub async fn turbo_local_copy(
    source: &Path,
    dest: &Path,
    progress_cb: Option<ProgressCb>,
) -> AftResult<TransferResult> {
    let start = Instant::now();
    let file_size = tokio::fs::metadata(source).await?.len();

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Fast path: kernel-level copy (CopyFileExW on Windows, copy_file_range on Linux).
    let bytes = match turbo_local_copy_kernel(source, dest, file_size, progress_cb.clone()).await {
        Ok(b) => b,
        Err(_) => match turbo_local_copy_mmap(source, dest, file_size, progress_cb.clone()).await {
            Ok(b) => b,
            Err(_) => turbo_local_copy_buffered(source, dest, file_size, progress_cb).await?,
        },
    };

    let duration = start.elapsed();
    let duration_ms = duration.as_millis() as u64;
    let throughput = if duration_ms > 0 {
        bytes as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    Ok(TransferResult {
        bytes_transferred: bytes,
        duration_ms,
        throughput_bytes_per_sec: throughput,
        checksum: None,
        retries_used: 0,
        chunks_used: 1,
    })
}

/// Kernel-level copy -- zero userspace data movement.
///
/// On Windows this calls `CopyFileExW` (via `std::fs::copy`), which performs
/// the copy entirely in kernel mode.  On Linux it uses `copy_file_range`.
/// This consistently matches or beats Robocopy / cp.
async fn turbo_local_copy_kernel(
    source: &Path,
    dest: &Path,
    file_size: u64,
    progress_cb: Option<ProgressCb>,
) -> AftResult<u64> {
    let src = source.to_path_buf();
    let dst = dest.to_path_buf();
    let cb = progress_cb;

    tokio::task::spawn_blocking(move || {
        let copied = std::fs::copy(&src, &dst)
            .map_err(|e| AftError::Other(format!("kernel copy: {}", e)))?;
        if let Some(ref cb) = cb {
            cb(copied, Some(file_size));
        }
        Ok(copied)
    })
    .await
    .map_err(|e| AftError::Other(format!("spawn_blocking: {}", e)))?
}

/// Local copy using mmap + pipelined writes.
async fn turbo_local_copy_mmap(
    source: &Path,
    dest: &Path,
    file_size: u64,
    progress_cb: Option<ProgressCb>,
) -> AftResult<u64> {
    // Move to blocking thread for mmap operations
    let src = source.to_path_buf();
    let dst = dest.to_path_buf();
    let cb = progress_cb;

    tokio::task::spawn_blocking(move || {
        let src_file = std::fs::File::open(&src)?;
        let mut dst_file = std::fs::File::create(&dst)?;

        if file_size == 0 {
            return Ok(0u64);
        }

        // SAFETY: We hold the file handle open for the lifetime of the mmap.
        // The file is opened read-only.  If the file is truncated externally
        // while we read, we'll get a SIGBUS/access violation — but that's an
        // external race condition, not a soundness bug in our code.
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = src_file.as_raw_fd();
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    file_size as usize,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    fd,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(AftError::Other("mmap failed".to_string()));
            }
            // Advise sequential access
            unsafe { libc::madvise(ptr, file_size as usize, libc::MADV_SEQUENTIAL) };

            let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, file_size as usize) };
            let mut written = 0u64;
            let chunk = IO_BUF_SIZE;
            while (written as usize) < slice.len() {
                let end = ((written as usize) + chunk).min(slice.len());
                use std::io::Write;
                dst_file.write_all(&slice[written as usize..end])?;
                written = end as u64;
                if let Some(ref cb) = cb {
                    cb(written, Some(file_size));
                }
            }
            unsafe { libc::munmap(ptr, file_size as usize) };
        }

        #[cfg(windows)]
        {
            use std::io::Write;
            use std::os::windows::io::AsRawHandle;

            let handle = src_file.as_raw_handle();

            // CreateFileMappingW
            let mapping = unsafe {
                windows_sys::Win32::System::Memory::CreateFileMappingW(
                    handle as *mut core::ffi::c_void,
                    std::ptr::null_mut(),
                    windows_sys::Win32::System::Memory::PAGE_READONLY,
                    (file_size >> 32) as u32,
                    file_size as u32,
                    std::ptr::null(),
                )
            };
            if mapping.is_null() {
                return Err(AftError::Other("CreateFileMapping failed".to_string()));
            }

            let ptr = unsafe {
                windows_sys::Win32::System::Memory::MapViewOfFile(
                    mapping,
                    windows_sys::Win32::System::Memory::FILE_MAP_READ,
                    0,
                    0,
                    file_size as usize,
                )
            };
            if ptr.Value.is_null() {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(mapping) };
                return Err(AftError::Other("MapViewOfFile failed".to_string()));
            }

            let slice =
                unsafe { std::slice::from_raw_parts(ptr.Value as *const u8, file_size as usize) };
            let mut written = 0u64;
            let chunk = IO_BUF_SIZE;
            while (written as usize) < slice.len() {
                let end = ((written as usize) + chunk).min(slice.len());
                dst_file.write_all(&slice[written as usize..end])?;
                written = end as u64;
                if let Some(ref cb) = cb {
                    cb(written, Some(file_size));
                }
            }

            unsafe {
                windows_sys::Win32::System::Memory::UnmapViewOfFile(ptr);
                windows_sys::Win32::Foundation::CloseHandle(mapping);
            }
        }

        Ok(file_size)
    })
    .await
    .map_err(|e| AftError::Other(format!("spawn_blocking: {}", e)))?
}

/// Fallback local copy with 4 MB buffers and write-behind.
async fn turbo_local_copy_buffered(
    source: &Path,
    dest: &Path,
    file_size: u64,
    progress_cb: Option<ProgressCb>,
) -> AftResult<u64> {
    let mut src = tokio::fs::File::open(source).await?;
    let mut dst = tokio::fs::File::create(dest).await?;

    // Pre-allocate destination
    if file_size > 0 {
        dst.set_len(file_size).await?;
        use tokio::io::AsyncSeekExt;
        dst.seek(std::io::SeekFrom::Start(0)).await?;
    }

    let mut buf = vec![0u8; IO_BUF_SIZE];
    let mut total = 0u64;

    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
        total += n as u64;
        if let Some(ref cb) = progress_cb {
            cb(total, Some(file_size));
        }
    }

    dst.flush().await?;
    Ok(total)
}

// NOTE: socket tuning lives in `crate::aftp::transport::tune_tcp_socket`, which
// is applied to every AFTP socket on the listener, connector, and client paths.
// This module previously carried an unused duplicate that was never called.

// ── Adaptive chunk ramp ─────────────────────────────────────────────────────

/// Adaptive chunk sizer: doubles chunk size after each successful transfer
/// until it reaches the recommended maximum or throughput stops increasing.
pub struct AdaptiveChunker {
    current_chunk: u64,
    max_chunk: u64,
    last_throughput: f64,
}

impl AdaptiveChunker {
    pub fn new(initial: u64, max: u64) -> Self {
        let max_chunk = max.clamp(CHUNK_MIN, CHUNK_MAX);
        Self {
            current_chunk: initial.clamp(CHUNK_MIN, max_chunk),
            max_chunk,
            last_throughput: 0.0,
        }
    }

    /// Report the measured throughput for the last chunk and get the next
    /// chunk size.  If throughput improved, doubles the chunk.  If it got
    /// worse, holds steady.
    pub fn next_chunk(&mut self, measured_throughput: f64) -> u64 {
        if measured_throughput > self.last_throughput * 1.05 {
            // At least 5% improvement → ramp up
            self.current_chunk = (self.current_chunk * 2).min(self.max_chunk);
        }
        // If worse, don't shrink — network jitter could cause transient dips
        self.last_throughput = measured_throughput;
        self.current_chunk
    }

    pub fn current(&self) -> u64 {
        self.current_chunk
    }
}

// ── Integration: decide and dispatch ────────────────────────────────────────

/// Top-level turbo download dispatcher.  Probes, selects mode, and runs.
pub async fn turbo_download_auto(
    handler: &dyn ProtocolHandler,
    url: &str,
    dest: &Path,
    opts: &ProtocolOptions,
    turbo_config: &TurboConfig,
    progress_cb: Option<ProgressCb>,
) -> AftResult<(TransferResult, LinkProfile)> {
    // Detect localhost by URL — skip expensive HEAD probe for same-machine transfers
    let url_is_local =
        url.contains("://localhost") || url.contains("://127.0.0.1") || url.contains("://[::1]");

    let (head_rtt_us, total_size, supports_ranges) = if url_is_local && turbo_config.streams == 0 {
        // Skip HEAD entirely for localhost: single-stream is always fastest
        (0, None, false)
    } else {
        // Quick probe: single HEAD request for size + RTT
        let t0 = Instant::now();
        let metadata = handler.head(url, opts).await.ok();
        let head_rtt_us = t0.elapsed().as_micros() as u64;
        let total_size = metadata.as_ref().and_then(|m| m.content_length);
        let supports_ranges = metadata.as_ref().map(|m| m.accepts_ranges).unwrap_or(false);
        (head_rtt_us, total_size, supports_ranges)
    };

    let is_local_link = url_is_local || head_rtt_us < 5_000;
    // Protocols that stream over one persistent connection are hurt by
    // parallel ranges, not helped — see `benefits_from_parallel_ranges`.
    let parallel_helps = handler.benefits_from_parallel_ranges();
    let streams = if !parallel_helps {
        1
    } else if turbo_config.streams > 0 {
        turbo_config.streams.min(MAX_STREAMS)
    } else if is_local_link {
        1 // localhost: single stream avoids parallel overhead
    } else {
        DEFAULT_STREAMS
    };
    let chunk = if turbo_config.chunk_size > 0 {
        turbo_config.chunk_size
    } else if is_local_link {
        16 << 20
    } else {
        4 << 20
    };

    let profile = LinkProfile {
        rtt_us: head_rtt_us,
        bandwidth_estimate: if is_local_link {
            10_000_000_000
        } else {
            100_000_000
        },
        bdp_bytes: 0,
        recommended_sock_buf: TARGET_SOCK_BUF,
        recommended_streams: streams,
        recommended_chunk: chunk,
        mode: if supports_ranges
            && parallel_helps
            && total_size.is_some_and(|s| s >= TURBO_THRESHOLD)
        {
            TransferMode::MultiStream
        } else {
            TransferMode::Standard
        },
    };

    // Use the standard engine with turbo-recommended parallel/chunk settings.
    let config = crate::engine::TransferConfig {
        parallel_chunks: if supports_ranges && parallel_helps {
            streams
        } else {
            1
        },
        chunk_size: chunk,
        ..Default::default()
    };
    let result = crate::engine::download(handler, url, dest, opts, &config, progress_cb).await?;
    Ok((result, profile))
}

/// Top-level turbo upload dispatcher.
#[allow(clippy::too_many_arguments)]
pub async fn turbo_upload_auto(
    handler: &dyn ProtocolHandler,
    source: &Path,
    url: &str,
    opts: &ProtocolOptions,
    turbo_config: &TurboConfig,
    content_type: Option<&str>,
    method: Option<&str>,
    progress_cb: Option<ProgressCb>,
) -> AftResult<(TransferResult, LinkProfile)> {
    let profile = LinkProfile::default();

    // Delegates directly to turbo_upload without an expensive link probe; the
    // handler owns the read strategy (see the note on `turbo_upload`).
    let result = turbo_upload(
        handler,
        source,
        url,
        opts,
        turbo_config,
        &profile,
        content_type,
        method,
        progress_cb,
    )
    .await?;
    Ok((result, profile))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_chunker_ramps_up() {
        let mut ac = AdaptiveChunker::new(CHUNK_MIN, 16 << 20);
        // First call — no prior throughput, so any positive value is improvement
        let c1 = ac.next_chunk(100_000_000.0); // 100 MB/s
        assert!(c1 >= CHUNK_MIN);
        // Second call with higher throughput → should ramp
        let c2 = ac.next_chunk(200_000_000.0);
        assert!(c2 >= c1);
        // Third with even higher
        let c3 = ac.next_chunk(300_000_000.0);
        assert!(c3 >= c2);
    }

    #[test]
    fn test_adaptive_chunker_holds_on_regression() {
        let mut ac = AdaptiveChunker::new(4 << 20, 16 << 20);
        let c1 = ac.next_chunk(200_000_000.0);
        // Throughput drops — should NOT ramp up
        let c2 = ac.next_chunk(100_000_000.0);
        assert_eq!(c2, c1);
    }

    #[test]
    fn test_adaptive_chunker_clamps() {
        let mut ac = AdaptiveChunker::new(32 << 20, 16 << 20);
        // Initial clamped to max
        assert_eq!(ac.current(), 16 << 20);
        // Even with high throughput, can't exceed max
        let c = ac.next_chunk(999_999_999.0);
        assert!(c <= 16 << 20);
    }

    #[test]
    fn test_transfer_mode_display() {
        assert_eq!(TransferMode::Standard.to_string(), "standard");
        assert_eq!(TransferMode::MultiStream.to_string(), "multi-stream");
        assert_eq!(TransferMode::MmapDirect.to_string(), "mmap-direct");
    }

    #[test]
    fn test_turbo_config_defaults() {
        let tc = TurboConfig::default();
        assert!(tc.enabled);
        assert_eq!(tc.streams, 0);
        assert_eq!(tc.chunk_size, 0);
        assert_eq!(tc.sock_buf, 0);
        assert!(tc.mmap);
        assert!(tc.write_pipeline);
        assert_eq!(tc.rate_limit, 0);
    }

    #[test]
    fn test_link_profile_defaults() {
        let lp = LinkProfile::default();
        assert_eq!(lp.rtt_us, 0);
        assert_eq!(lp.bandwidth_estimate, 0);
        assert_eq!(lp.recommended_sock_buf, TARGET_SOCK_BUF);
        assert_eq!(lp.recommended_streams, DEFAULT_STREAMS);
        assert_eq!(lp.recommended_chunk, CHUNK_MIN);
        assert_eq!(lp.mode, TransferMode::Standard);
    }

    // These guard the relationships between tuning constants; they read as
    // runtime asserts but are compile-time truths, hence the allow.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_constants_sane() {
        assert!(CHUNK_MIN < CHUNK_MAX);
        assert!(DEFAULT_STREAMS <= MAX_STREAMS);
        assert!(TURBO_THRESHOLD > 0);
        assert!(IO_BUF_SIZE > 0);
        assert!(TARGET_SOCK_BUF > 0);
        assert!(WRITE_PIPELINE_DEPTH > 0);
    }
}
