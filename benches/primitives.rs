//! Benchmarks for hardware-accelerated cryptographic and integrity primitives.
//!
//! Measures throughput of:
//! - CRC32 (SSE4.2 / ARM CRC32 via crc32fast)
//! - SHA-256 (SHA-NI via sha2)
//! - AES-256-GCM encrypt + decrypt (AES-NI via aes-gcm)
//! - Zstd compression + decompression (SIMD via libzstd)

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sha2::{Digest, Sha256};

const SIZES: &[(u64, &str)] = &[
    (1_024, "1KB"),
    (64 * 1_024, "64KB"),
    (1_024 * 1_024, "1MB"),
    (16 * 1_024 * 1_024, "16MB"),
];

fn make_data(size: u64) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn bench_crc32(c: &mut Criterion) {
    let mut group = c.benchmark_group("crc32");
    for &(size, label) in SIZES {
        let data = make_data(size);
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
            b.iter(|| crc32fast::hash(data));
        });
    }
    group.finish();
}

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    for &(size, label) in SIZES {
        let data = make_data(size);
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
            b.iter(|| {
                let mut h = Sha256::new();
                h.update(data);
                h.finalize()
            });
        });
    }
    group.finish();
}

fn bench_aes256gcm(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce_bytes = [0u8; 12];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut group = c.benchmark_group("aes256gcm_encrypt");
    for &(size, label) in SIZES {
        let data = make_data(size);
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
            b.iter(|| cipher.encrypt(nonce, data.as_ref()).unwrap());
        });
    }
    group.finish();

    let mut group = c.benchmark_group("aes256gcm_decrypt");
    for &(size, label) in SIZES {
        let data = make_data(size);
        let ciphertext = cipher.encrypt(nonce, data.as_ref()).unwrap();
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(label), &ciphertext, |b, ct| {
            b.iter(|| cipher.decrypt(nonce, ct.as_ref()).unwrap());
        });
    }
    group.finish();
}

fn bench_zstd(c: &mut Criterion) {
    let mut group = c.benchmark_group("zstd_compress");
    for &(size, label) in SIZES {
        let data = make_data(size);
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
            b.iter(|| zstd::encode_all(data.as_slice(), 3).unwrap());
        });
    }
    group.finish();

    let mut group = c.benchmark_group("zstd_decompress");
    for &(size, label) in SIZES {
        let data = make_data(size);
        let compressed = zstd::encode_all(data.as_slice(), 3).unwrap();
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &compressed,
            |b, comp| {
                b.iter(|| zstd::decode_all(comp.as_slice()).unwrap());
            },
        );
    }
    group.finish();
}

/// XOR throughput benchmark — reproduces the u64-widened XOR from crypto module.
fn bench_xor(c: &mut Criterion) {
    let mut group = c.benchmark_group("xor_u64_widened");
    for &(size, label) in SIZES {
        let data = make_data(size);
        let key: Vec<u8> = (0..32).collect();
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
            b.iter(|| {
                let key_len = key.len();
                let mut out = vec![0u8; data.len()];
                let expanded_len = key_len.max(8).next_multiple_of(key_len);
                let mut expanded_key = Vec::with_capacity(expanded_len);
                while expanded_key.len() < expanded_len {
                    expanded_key.extend_from_slice(&key);
                }
                expanded_key.truncate(expanded_len);

                let chunks8 = data.len() / 8;
                for i in 0..chunks8 {
                    let di = i * 8;
                    let ki = di % expanded_len;
                    let d = u64::from_le_bytes(data[di..di + 8].try_into().unwrap());
                    let k = u64::from_le_bytes(expanded_key[ki..ki + 8].try_into().unwrap());
                    out[di..di + 8].copy_from_slice(&(d ^ k).to_le_bytes());
                }
                let base = chunks8 * 8;
                for j in 0..(data.len() % 8) {
                    out[base + j] = data[base + j] ^ key[(base + j) % key_len];
                }
                out
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_crc32,
    bench_sha256,
    bench_aes256gcm,
    bench_zstd,
    bench_xor,
);
criterion_main!(benches);
