// Copyright (c) 2024-2026 Nervosys LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cryptographic primitives, all supplied by IronCrypto (the IronSecurity stack).
//!
//! This is the one place AFT names a cryptographic implementation. Everything
//! else calls these helpers, so the backend is changed in this file and nowhere
//! else.
//!
//! The wire formats are unchanged from the RustCrypto and aws-lc-rs versions
//! this replaces: AES-256-GCM output is `ciphertext || tag`, HMAC-SHA256 is
//! RFC 2104, and ML-KEM-1024 is FIPS 203. Key files and encrypted payloads
//! written by earlier builds still open.

use ic_cipher::Aes256Gcm;
use ic_core::traits::{Aead, Digest, Mac};
use ic_core::entropy::OsEntropy;
use ic_hash::Sha256;
use ic_mac::HmacSha256;

use crate::error::{AftError, AftResult};

/// AES-256-GCM nonce length (96-bit).
pub const GCM_NONCE_LEN: usize = 12;
/// AES-256-GCM authentication tag length (128-bit).
pub const GCM_TAG_LEN: usize = 16;

fn crypto_err(context: &str, e: ic_core::Error) -> AftError {
    AftError::CryptoError(format!("{}: {}", context, e))
}

/// Fill `out` from the operating system's entropy source.
pub fn random_bytes(out: &mut [u8]) -> AftResult<()> {
    ic_core::entropy::fill(out).map_err(|e| crypto_err("OS entropy unavailable", e))
}

/// The OS entropy source as an IronCrypto `RandomSource`, for keygen and encapsulation.
pub fn os_rng() -> OsEntropy {
    OsEntropy
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(<Sha256 as Digest>::digest(data).as_ref());
    out
}

/// HMAC-SHA256 over the concatenation of `parts`, keyed by `key`.
///
/// HMAC accepts a key of any length, so this only fails if the backend does.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> AftResult<[u8; 32]> {
    let mut mac = HmacSha256::new(key).map_err(|e| crypto_err("HMAC key", e))?;
    for p in parts {
        mac.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(mac.finalize().as_ref());
    Ok(out)
}

/// Constant-time check that `tag` is HMAC-SHA256(`key`, `data`).
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    HmacSha256::verify(key, data, tag).is_ok()
}

/// AES-256-GCM seal. Returns `ciphertext || tag`.
///
/// The caller must never reuse a `(key, nonce)` pair. Callers here draw a
/// fresh 96-bit random nonce per message under a per-message or per-session key.
pub fn gcm_seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> AftResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(key).map_err(|e| crypto_err("AES-256-GCM key", e))?;
    let mut out = plaintext.to_vec();
    let mut tag = [0u8; GCM_TAG_LEN];
    cipher
        .seal_detached(nonce, aad, &mut out, &mut tag)
        .map_err(|e| crypto_err("AES-256-GCM seal", e))?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// AES-256-GCM open. `sealed` is `ciphertext || tag`. Fails if authentication
/// fails, which covers a forged, corrupted, or mis-keyed message.
pub fn gcm_open(key: &[u8], nonce: &[u8], aad: &[u8], sealed: &[u8]) -> AftResult<Vec<u8>> {
    if sealed.len() < GCM_TAG_LEN {
        return Err(AftError::CryptoError(
            "AES-256-GCM input shorter than its tag".into(),
        ));
    }
    let (ct, tag) = sealed.split_at(sealed.len() - GCM_TAG_LEN);
    let cipher = Aes256Gcm::new(key).map_err(|e| crypto_err("AES-256-GCM key", e))?;
    let mut out = ct.to_vec();
    cipher
        .open_detached(nonce, aad, &mut out, tag)
        .map_err(|_| AftError::CryptoError("AES-256-GCM authentication failed".into()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256("abc") from FIPS 180-4 example B.1.
    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// HMAC-SHA256 from RFC 4231 test case 2.
    #[test]
    fn hmac_known_answer() {
        let tag = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]).unwrap();
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert!(hmac_sha256_verify(b"Jefe", b"what do ya want for nothing?", &tag));
        assert!(!hmac_sha256_verify(b"Jefe", b"what do ya want for nothing!", &tag));
    }

    /// AES-256-GCM test case 14 from the McGrew–Viega GCM specification.
    #[test]
    fn gcm_known_answer() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let sealed = gcm_seal(&key, &nonce, b"", &[0u8; 16]).unwrap();
        assert_eq!(
            hex::encode(&sealed),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );
        assert_eq!(gcm_open(&key, &nonce, b"", &sealed).unwrap(), vec![0u8; 16]);
    }

    #[test]
    fn gcm_rejects_tampering() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let mut sealed = gcm_seal(&key, &nonce, b"aad", b"payload").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(gcm_open(&key, &nonce, b"aad", &sealed).is_err());
        assert!(gcm_open(&key, &nonce, b"aad", &[0u8; 3]).is_err());
    }
}
