//! Symbol-plane AEAD and KDF, with an optional FIPS-validated backend.
//!
//! The FEC data plane needs exactly two primitives: **AES-256-GCM** (seal/open a
//! symbol — see [`super::envelope`]) and **HMAC-SHA256** (derive the per-session
//! symbol key — see [`super::derive_symbol_key`]). By default both come from the
//! RustCrypto crates (`aes-gcm`, `hmac`/`sha2`) that the rest of AFT's non-TLS
//! pipeline uses.
//!
//! With `--features fips` they are instead routed through `aws-lc-rs`, the same
//! FIPS 140-3 validated module rustls uses for TLS (see `server.rs`). A FIPS
//! build therefore keeps *all* of AFT's bulk-data crypto inside the validated
//! boundary, not only the control plane.
//!
//! The wire format is identical either way — AES-256-GCM, 96-bit nonce, 128-bit
//! tag, same AAD — so a `--features fips` build and a default build interoperate
//! symbol-for-symbol on the wire. This module is the *only* place the FEC data
//! plane touches an AEAD or a MAC; both callers go through it.

use crate::error::{AftError, AftResult};

/// AES-256 key length.
pub const KEY_LEN: usize = 32;
/// AES-256-GCM nonce length (96-bit).
pub const NONCE_LEN: usize = 12;
/// AES-256-GCM authentication tag length (128-bit).
pub const TAG_LEN: usize = 16;

/// HMAC-SHA256 over the concatenation of `parts`, keyed by `key`.
///
/// The KDF for the per-session symbol key. Accepts a key of any length (HMAC
/// zero-pads or hashes internally), so it never fails.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    backend::hmac_sha256(key, parts)
}

/// AES-256-GCM seal. Returns `ciphertext || tag` (16-byte tag trailing), which
/// is exactly the layout [`super::envelope`] writes after the nonce.
///
/// `key` must be [`KEY_LEN`] bytes and `nonce` [`NONCE_LEN`] bytes; a wrong
/// length is an error rather than a panic.
pub fn seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> AftResult<Vec<u8>> {
    check_lengths(key, nonce)?;
    backend::seal(key, nonce, aad, plaintext)
}

/// AES-256-GCM open. `sealed` is `ciphertext || tag`. Returns the recovered
/// plaintext, or an error if authentication fails (forged/corrupt/wrong key).
pub fn open(key: &[u8], nonce: &[u8], aad: &[u8], sealed: &[u8]) -> AftResult<Vec<u8>> {
    check_lengths(key, nonce)?;
    if sealed.len() < TAG_LEN {
        return Err(AftError::Other("FEC sealed symbol shorter than its tag".to_string()));
    }
    backend::open(key, nonce, aad, sealed)
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

// ---------------------------------------------------------------- default ----
// RustCrypto backend: the same `aes-gcm` and `hmac`/`sha2` primitives the PQC
// pipeline uses. Selected whenever the `fips` feature is off.
#[cfg(not(feature = "fips"))]
mod backend {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hmac::{Hmac, Mac};

    pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        // `new_from_slice` only errors on an invalid key length, and HMAC
        // accepts any length, so this cannot fail.
        // Disambiguate: `KeyInit` (from aes-gcm, in scope for `seal`/`open`)
        // also offers `new_from_slice`.
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key)
            .expect("HMAC accepts any key length");
        for p in parts {
            mac.update(p);
        }
        mac.finalize().into_bytes().into()
    }

    pub fn seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> AftResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| AftError::Other(format!("FEC cipher key: {}", e)))?;
        cipher
            .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
            .map_err(|_| AftError::Other("FEC symbol encryption failed".to_string()))
    }

    pub fn open(key: &[u8], nonce: &[u8], aad: &[u8], sealed: &[u8]) -> AftResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| AftError::Other(format!("FEC cipher key: {}", e)))?;
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
            .map_err(|_| AftError::Other("FEC symbol authentication failed".to_string()))
    }
}

// ------------------------------------------------------------------- fips ----
// aws-lc-rs backend: FIPS 140-3 validated AES-256-GCM and HMAC-SHA256. Selected
// by `--features fips`. Produces the identical wire bytes as the default path.
#[cfg(feature = "fips")]
mod backend {
    use super::*;
    use aws_lc_rs::{aead, hmac};

    pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let k = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut ctx = hmac::Context::with_key(&k);
        for p in parts {
            ctx.update(p);
        }
        let tag = ctx.sign();
        let mut out = [0u8; 32];
        // HMAC-SHA256 is always 32 bytes.
        out.copy_from_slice(tag.as_ref());
        out
    }

    pub fn seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> AftResult<Vec<u8>> {
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, key)
                .map_err(|_| AftError::Other("FEC cipher key".to_string()))?,
        );
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| AftError::Other("FEC nonce".to_string()))?;
        // seal_in_place_append_tag encrypts in place and appends the 16-byte
        // tag, leaving `in_out` == ciphertext || tag.
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut in_out)
            .map_err(|_| AftError::Other("FEC symbol encryption failed".to_string()))?;
        Ok(in_out)
    }

    pub fn open(key: &[u8], nonce: &[u8], aad: &[u8], sealed: &[u8]) -> AftResult<Vec<u8>> {
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, key)
                .map_err(|_| AftError::Other("FEC cipher key".to_string()))?,
        );
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| AftError::Other("FEC nonce".to_string()))?;
        // open_in_place verifies the trailing tag and returns the plaintext
        // prefix of the (now-decrypted) buffer.
        let mut in_out = sealed.to_vec();
        let plain = key
            .open_in_place(nonce, aead::Aad::from(aad), &mut in_out)
            .map_err(|_| AftError::Other("FEC symbol authentication failed".to_string()))?;
        Ok(plain.to_vec())
    }
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
        let a = hmac_sha256(b"token", &[b"aft-fec-symbol-key-v2", &7u64.to_be_bytes()]);
        let b = hmac_sha256(b"token", &[b"aft-fec-symbol-key-v2", &7u64.to_be_bytes()]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        let c = hmac_sha256(b"token", &[b"aft-fec-symbol-key-v2", &8u64.to_be_bytes()]);
        assert_ne!(a, c);
    }

    /// A known-answer test pins the KDF output so the default and FIPS backends
    /// are proven to agree byte-for-byte (run the suite under both feature sets).
    #[test]
    fn hmac_known_answer() {
        // HMAC-SHA256(key="key", msg="The quick brown fox jumps over the lazy dog")
        // = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
        let got = hmac_sha256(b"key", &[b"The quick brown fox jumps over the lazy dog"]);
        let expect =
            hex::decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
                .unwrap();
        assert_eq!(&got[..], &expect[..]);
    }
}
