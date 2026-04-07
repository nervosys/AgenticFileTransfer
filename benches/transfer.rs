//! End-to-end transfer benchmarks.
//!
//! Measures:
//! - Local file copy via std::fs (baseline — equivalent to cp/robocopy)
//! - Buffered I/O copy with configurable buffer sizes
//! - Tokio async file copy (simulates engine I/O path)
//!
//! These establish the baseline disk I/O throughput that AFT's turbo engine
//! operates on top of.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::io::{Read, Write};
use tempfile::TempDir;
use tokio::runtime::Runtime;

const SIZES: &[(u64, &str)] = &[
    (1_024 * 1_024, "1MB"),
    (10 * 1_024 * 1_024, "10MB"),
    (100 * 1_024 * 1_024, "100MB"),
];

fn create_test_file(dir: &TempDir, name: &str, size: u64) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    let chunk: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let mut remaining = size as usize;
    while remaining > 0 {
        let n = remaining.min(chunk.len());
        f.write_all(&chunk[..n]).unwrap();
        remaining -= n;
    }
    f.sync_all().unwrap();
    path
}

/// Baseline: std::fs::copy (OS-level copy, equivalent to cp/robocopy)
fn bench_std_copy(c: &mut Criterion) {
    let mut group = c.benchmark_group("std_fs_copy");
    for &(size, label) in SIZES {
        let dir = TempDir::new().unwrap();
        let src = create_test_file(&dir, "src.bin", size);
        let dst = dir.path().join("dst.bin");

        group.throughput(Throughput::Bytes(size));
        group.sample_size(10);
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, _| {
            b.iter(|| {
                let _ = std::fs::remove_file(&dst);
                std::fs::copy(&src, &dst).unwrap();
            });
        });
    }
    group.finish();
}

/// Buffered I/O copy with AFT's 4 MB buffer size
fn bench_buffered_copy(c: &mut Criterion) {
    const BUF_SIZE: usize = 4 * 1024 * 1024; // IO_BUF_SIZE from turbo.rs

    let mut group = c.benchmark_group("buffered_copy_4MB");
    for &(size, label) in SIZES {
        let dir = TempDir::new().unwrap();
        let src = create_test_file(&dir, "src.bin", size);
        let dst = dir.path().join("dst.bin");

        group.throughput(Throughput::Bytes(size));
        group.sample_size(10);
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, _| {
            b.iter(|| {
                let _ = std::fs::remove_file(&dst);
                let mut reader =
                    std::io::BufReader::with_capacity(BUF_SIZE, std::fs::File::open(&src).unwrap());
                let mut writer = std::io::BufWriter::with_capacity(
                    BUF_SIZE,
                    std::fs::File::create(&dst).unwrap(),
                );
                let mut buf = vec![0u8; BUF_SIZE];
                loop {
                    let n = reader.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    writer.write_all(&buf[..n]).unwrap();
                }
                writer.flush().unwrap();
            });
        });
    }
    group.finish();
}

/// Tokio async file copy — simulates AFT's async engine path
fn bench_tokio_copy(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("tokio_async_copy");
    for &(size, label) in SIZES {
        let dir = TempDir::new().unwrap();
        let src = create_test_file(&dir, "src.bin", size);
        let dst = dir.path().join("dst.bin");

        group.throughput(Throughput::Bytes(size));
        group.sample_size(10);
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, _| {
            b.iter(|| {
                let _ = std::fs::remove_file(&dst);
                rt.block_on(async {
                    let mut src_file = tokio::fs::File::open(&src).await.unwrap();
                    let mut dst_file = tokio::fs::File::create(&dst).await.unwrap();
                    tokio::io::copy(&mut src_file, &mut dst_file).await.unwrap();
                });
            });
        });
    }
    group.finish();
}

/// CRC32 + SHA-256 combined: simulates AFT's per-frame CRC32 + transfer SHA-256 integrity
fn bench_integrity_pipeline(c: &mut Criterion) {
    use sha2::{Digest, Sha256};

    let mut group = c.benchmark_group("integrity_pipeline");
    for &(size, label) in SIZES {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let chunk_size = 1_048_576usize; // 1 MB frames

        group.throughput(Throughput::Bytes(size));
        group.sample_size(10);
        group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
            b.iter(|| {
                let mut sha = Sha256::new();
                for chunk in data.chunks(chunk_size) {
                    // Per-frame CRC32 (hardware-accelerated)
                    let _crc = crc32fast::hash(chunk);
                    // Transfer-level SHA-256 (hardware-accelerated)
                    sha.update(chunk);
                }
                sha.finalize()
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_std_copy,
    bench_buffered_copy,
    bench_tokio_copy,
    bench_integrity_pipeline,
);
criterion_main!(benches);
