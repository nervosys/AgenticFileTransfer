// Copyright (c) 2024-2026 Nervosys LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Symbol-plane AEAD and KDF, backed by IronCrypto.
//!
//! The FEC data plane needs exactly two primitives: **AES-256-GCM** (seal/open a
//! symbol — see [`super::envelope`]) and **HMAC-SHA256** (derive the per-session
//! symbol key — see [`super::derive_symbol_key`]). Both come from IronCrypto via
//! [`crate::crypto::primitives`], the single boundary for AFT's cryptography.
//!
//! The wire format is AES-256-GCM with a 96-bit nonce, a 128-bit tag, and the
//! caller's AAD. This module is the *only* place the FEC data plane touches an
//! AEAD or a MAC; both callers go through it.

use crate::crypto::primitives::{self, GCM_NONCE_LEN, GCM_TAG_LEN};
use crate::error::{AftError, AftResult};

/// AES-256 key length.
pub const KEY_LEN: usize = 32;
/// AES-256-GCM nonce length (96-bit).
pub const NONCE_LEN: usize = GCM_NONCE_LEN;
/// AES-256-GCM authentication tag length (128-bit).
pub const TAG_LEN: usize = GCM_TAG_LEN;

/// HMAC-SHA256 over the concatenation of `parts`, keyed by `key`.
///
/// The KDF for the per-session symbol key. Accepts a key of any length. It
/// returns an error only if the IronCrypto backend itself refuses to run, and
/// callers must propagate that rather than continue without a key.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> AftResult<[u8; 32]> {
    primitives::hmac_sha256(key, parts)
}

/// AES-256-GCM seal. Returns `ciphertext || tag` (16-byte tag trailing), which
/// is exactly the layout [`super::envelope`] writes after the nonce.
///
/// `key` must be [`KEY_LEN`] bytes and `nonce` [`NONCE_LEN`] bytes; a wrong
/// length is an error rather than a panic.
pub fn seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> AftResult<Vec<u8>> {
    check_lengths(key, nonce)?;
    primitives::gcm_seal(key, nonce, aad, plaintext)
}

/// AES-256-GCM open. `sealed` is `ciphertext || tag`. Returns the recovered
/// plaintext, or an error if authentication fails (forged/corrupt/wrong key).
pub fn open(key: &[u8], nonce: &[u8], aad: &[u8], sealed: &[u8]) -> AftResult<Vec<u8>> {
    check_lengths(key, nonce)?;
    if sealed.len() < TAG_LEN {
        return Err(AftError::Other(
            "FEC sealed symbol shorter than its tag".to_string(),
        ));
    }
    primitives::gcm_open(key, nonce, aad, sealed).map_err(|_| {
        AftError::Other("FEC symbol authentication failed".to_string())
    })
}

fn check_lengths(key: &[u8], nonce: &[u8]) -> AftResult<()> {
    if key.len() != KEY_LEN {
        return Err(AftError::Other(format!(
            "FEC symbol key must be {} bytes, got {}",
            KEY_LEN,
            key.len()
        )));
    }
    if nonce.len() != NONCE_LEN {
        return Err(AftError::Other(format!(
            "FEC nonce must be {} bytes, got {}",
            NONCE_LEN,
            nonce.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const NONCE: &[u8] = b"unique-nonce"; // 12 bytes

    #[test]
    fn seal_open_round_trip() {
        let aad = b"header-aad";
        let pt = b"one raptorq symbol";
        let sealed = seal(KEY, NONCE, aad, pt).unwrap();
        // ciphertext || 16-byte tag
        assert_eq!(sealed.len(), pt.len() + TAG_LEN);
        let back = open(KEY, NONCE, aad, &sealed).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn wrong_aad_fails() {
        let sealed = seal(KEY, NONCE, b"aad-a", b"payload").unwrap();
        assert!(open(KEY, NONCE, b"aad-b", &sealed).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(KEY, NONCE, b"aad", b"payload").unwrap();
        let bad = b"ffffffffffffffffffffffffffffffff";
        assert!(open(bad, NONCE, b"aad", &sealed).is_err());
    }

    #[test]
    fn tampered_tag_fails() {
        let mut sealed = seal(KEY, NONCE, b"aad", b"payload").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(KEY, NONCE, b"aad", &sealed).is_err());
    }

    #[test]
    fn bad_lengths_are_errors_not_panics() {
        assert!(seal(b"short-key", NONCE, b"", b"x").is_err());
        assert!(seal(KEY, b"short", b"", b"x").is_err());
        assert!(open(KEY, NONCE, b"", b"too-short").is_err()); // < TAG_LEN
    }

    #[test]
    fn hmac_is_deterministic_and_32_bytes() {
        let a = hmac_sha256(b"token", &[b"aft-fec-symbol-key-v2", &7u64.to_be_bytes()]).unwrap();
        let b = hmac_sha256(b"token", &[b"aft-fec-symbol-key-v2", &7u64.to_be_bytes()]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        let c = hmac_sha256(b"token", &[b"aft-fec-symbol-key-v2", &8u64.to_be_bytes()]).unwrap();
        assert_ne!(a, c);
    }

    /// A known-answer test pins the KDF output so the default and FIPS backends
    /// are proven to agree byte-for-byte (run the suite under both feature sets).
    #[test]
    fn hmac_known_answer() {
        // HMAC-SHA256(key="key", msg="The quick brown fox jumps over the lazy dog")
        // = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
        let got = hmac_sha256(b"key", &[b"The quick brown fox jumps over the lazy dog"]).unwrap();
        let expect =
            hex::decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
                .unwrap();
        assert_eq!(&got[..], &expect[..]);
    }
}

/// Known-answer values captured from the RustCrypto/aws-lc-rs build this backend
/// replaced. A mismatch means the wire format changed, which would break
/// interop with peers still on the old build.
#[cfg(test)]
mod wire_compat {
    use super::*;

    #[test]
    fn seal_matches_pre_ironcrypto_bytes() {
        let sealed = seal(&[7u8; 32], &[9u8; 12], b"aad-kat", b"raptorq symbol bytes").unwrap();
        assert_eq!(
            hex::encode(sealed),
            "55e4f4e0d182b041d31ba65a898683bdadc40680f83ebe9b98ecc40f909ada01328eb4b6"
        );
    }

    #[test]
    fn symbol_kdf_matches_pre_ironcrypto_bytes() {
        let key = hmac_sha256(b"token", &[b"aft-fec-symbol-key-v2", &7u64.to_be_bytes()]).unwrap();
        assert_eq!(
            hex::encode(key),
            "3692b866b9cf1fe1edb727ed02d01bc514a39e252b4859e46b734370f65006ad"
        );
    }
}
