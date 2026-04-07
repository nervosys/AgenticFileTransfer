//! Benchmarks for AFTP wire protocol operations.
//!
//! Measures:
//! - Frame building (HELLO, GET, PUT, DATA_END, etc.)
//! - Frame parsing
//! - Frame I/O (write_frame / read_frame over in-memory cursor)
//! - Per-frame CRC32 verification

use aft::aftp::frame::*;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::runtime::Runtime;

fn bench_frame_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_build");

    group.bench_function("hello", |b| {
        b.iter(|| {
            build_hello(
                CAP_COMPRESSION | CAP_CHECKSUM | CAP_CRC32_FRAMES,
                Some("token"),
            )
        });
    });

    group.bench_function("get", |b| {
        b.iter(|| build_get("/data/large_file.bin", 0, 0));
    });

    group.bench_function("put", |b| {
        b.iter(|| build_put("/data/output.bin", 1_073_741_824));
    });

    group.bench_function("data_end_sha256", |b| {
        let checksum = [0xABu8; 32];
        b.iter(|| build_data_end(1_073_741_824, CHECKSUM_SHA256, &checksum));
    });

    group.bench_function("error", |b| {
        b.iter(|| build_error(ERR_NOT_FOUND, "File not found: /data/missing.bin"));
    });

    group.finish();
}

fn bench_frame_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_parse");

    let hello_payload = build_hello(
        CAP_COMPRESSION | CAP_CHECKSUM | CAP_CRC32_FRAMES,
        Some("token123"),
    );
    group.bench_function("parse_hello", |b| {
        b.iter(|| parse_hello(&hello_payload).unwrap());
    });

    let hello_ack_payload = build_hello_ack_with_session(
        CAP_COMPRESSION | CAP_CRC32_FRAMES,
        DEFAULT_MAX_FRAME,
        "session-abc-123",
    );
    group.bench_function("parse_hello_ack", |b| {
        b.iter(|| parse_hello_ack(&hello_ack_payload).unwrap());
    });

    let get_payload = build_get("/data/large_file.bin", 0, 0);
    group.bench_function("parse_get", |b| {
        b.iter(|| parse_get(&get_payload).unwrap());
    });

    let data_end_payload = build_data_end(1_073_741_824, CHECKSUM_SHA256, &[0xABu8; 32]);
    group.bench_function("parse_data_end", |b| {
        b.iter(|| parse_data_end(&data_end_payload).unwrap());
    });

    group.finish();
}

fn bench_frame_io(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("frame_io");

    let sizes: &[(usize, &str)] = &[(1_024, "1KB"), (64 * 1_024, "64KB"), (1_024 * 1_024, "1MB")];

    for &(size, label) in sizes {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let frame = Frame::new(FRAME_DATA, payload);

        group.throughput(Throughput::Bytes((HEADER_SIZE + size) as u64));
        group.bench_with_input(
            BenchmarkId::new("write_frame", label),
            &frame,
            |b, frame| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut buf = Vec::with_capacity(HEADER_SIZE + size);
                        write_frame(&mut buf, frame).await.unwrap();
                        buf
                    })
                });
            },
        );
    }

    for &(size, label) in sizes {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let frame = Frame::new(FRAME_DATA, payload);
        // Pre-serialize the frame into a buffer
        let wire = rt.block_on(async {
            let mut buf = Vec::new();
            write_frame(&mut buf, &frame).await.unwrap();
            buf
        });

        group.throughput(Throughput::Bytes(wire.len() as u64));
        group.bench_with_input(BenchmarkId::new("read_frame", label), &wire, |b, wire| {
            b.iter(|| {
                rt.block_on(async {
                    let mut cursor = &wire[..];
                    read_frame(&mut cursor, DEFAULT_MAX_FRAME).await.unwrap()
                })
            });
        });
    }

    group.finish();
}

fn bench_crc32_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_crc32_verify");

    let sizes: &[(usize, &str)] = &[(1_024, "1KB"), (64 * 1_024, "64KB"), (1_024 * 1_024, "1MB")];

    for &(size, label) in sizes {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let crc = crc32fast::hash(&data);
        let mut payload = data;
        payload.extend_from_slice(&crc.to_le_bytes());

        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &payload,
            |b, payload| {
                b.iter(|| verify_frame_crc32(payload).unwrap());
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_frame_build,
    bench_frame_parse,
    bench_frame_io,
    bench_crc32_verify,
);
criterion_main!(benches);
