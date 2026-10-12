// Copyright (c) 2024-2026 Nervosys LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Post-Quantum Cryptography: ML-KEM-1024 (NIST FIPS 203) + AES-256-GCM.
//!
//! Provides NIST FIPS 203-compliant key encapsulation with ML-KEM-1024
//! (security category 5) combined with AES-256-GCM for authenticated symmetric
//! encryption.
//!
//! Key file formats:
//!   Public key:  AFPK || version || algorithm || reserved || key_len || key_bytes
//!   Secret key:  AFSK || version || algorithm || reserved || key_len || key_bytes
//!
//! ## Migration note (Kyber1024 → ML-KEM-1024)
//!
//! Earlier versions used the unmaintained `pqc_kyber` crate (round-3 Kyber1024,
//! affected by the KyberSlash timing side-channel with no upstream fix). This
//! module now uses IronCrypto's `ic-mlkem`. ML-KEM-1024 (FIPS 203
//! final) is **not** interoperable with the old round-3 Kyber1024, so the key
//! file version was bumped to 2 and legacy (version-1) files are rejected with
//! a clear error — regenerate them with `aft keygen`.

use std::path::Path;

use ic_mlkem::kem1024::{
    CIPHERTEXT_LEN, DECAPS_KEY_LEN, ENCAPS_KEY_LEN, SHARED_SECRET_LEN,
};
use ic_mlkem::MlKem1024;

use super::primitives::{self, GCM_NONCE_LEN};
use crate::error::{AftError, AftResult};

/// Length of the secret-key payload: the FIPS 203 seed `d || z`.
const SEED_LEN: usize = 64;

const PUB_KEY_MAGIC: &[u8; 4] = b"AFPK";
const SEC_KEY_MAGIC: &[u8; 4] = b"AFSK";
/// Key-file version. v1 held round-3 Kyber1024 keys (`pqc_kyber`); v2 holds
/// FIPS-203 ML-KEM-1024 keys (`ic-mlkem`). The two are not interoperable.
const KEY_VERSION: u8 = 2;
/// Algorithm id in the key-file header. 0 was Kyber1024; 1 is ML-KEM-1024.
const ALGORITHM_MLKEM1024: u8 = 1;

/// An ML-KEM-1024 keypair for post-quantum key encapsulation.
pub struct PqcKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Generate a new ML-KEM-1024 keypair (using the system RNG).
///
/// The secret key is stored as the 64-byte FIPS 203 seed rather than the 3168-byte
/// expanded decapsulation key. The public key is the 1568-byte encapsulation key.
/// The expanded form is rebuilt from the seed when needed (see [`expand`]).
pub fn generate_keypair() -> AftResult<PqcKeyPair> {
    let mut seed = [0u8; SEED_LEN];
    primitives::random_bytes(&mut seed)?;
    let (ek, _dk) = expand(&seed)?;
    Ok(PqcKeyPair {
        public_key: ek.to_vec(),
        secret_key: seed.to_vec(),
    })
}

/// Derive the encapsulation and decapsulation keys from a FIPS 203 seed `d || z`.
fn expand(seed: &[u8]) -> AftResult<(Box<[u8; ENCAPS_KEY_LEN]>, Box<[u8; DECAPS_KEY_LEN]>)> {
    if seed.len() != SEED_LEN {
        return Err(AftError::CryptoError(format!(
            "ML-KEM seed must be {} bytes, got {}",
            SEED_LEN,
            seed.len()
        )));
    }
    let d: &[u8; 32] = seed[..32].try_into().expect("length checked above");
    let z: &[u8; 32] = seed[32..].try_into().expect("length checked above");
    let mut ek = Box::new([0u8; ENCAPS_KEY_LEN]);
    let mut dk = Box::new([0u8; DECAPS_KEY_LEN]);
    MlKem1024::keygen_deterministic(d, z, &mut ek, &mut dk);
    Ok((ek, dk))
}

/// Parse a public key (encapsulation key) from its raw bytes.
fn encapsulation_key(bytes: &[u8]) -> AftResult<Box<[u8; ENCAPS_KEY_LEN]>> {
    let ek: Box<[u8; ENCAPS_KEY_LEN]> = bytes.to_vec().into_boxed_slice().try_into().map_err(
        |_| {
            AftError::CryptoError(format!(
                "ML-KEM public key must be {} bytes, got {}",
                ENCAPS_KEY_LEN,
                bytes.len()
            ))
        },
    )?;
    MlKem1024::validate_encapsulation_key(&ek)
        .map_err(|e| AftError::CryptoError(format!("ML-KEM public key: {}", e)))?;
    Ok(ek)
}

/// Decapsulate `kem_ct` with the seed-form secret key, returning the shared secret.
fn decapsulate(kem_ct: &[u8], seed: &[u8]) -> AftResult<[u8; SHARED_SECRET_LEN]> {
    let ct: &[u8; CIPHERTEXT_LEN] = kem_ct.try_into().map_err(|_| {
        AftError::CryptoError("ML-KEM ciphertext has the wrong length".into())
    })?;
    let (_ek, dk) = expand(seed)?;
    let mut shared = [0u8; SHARED_SECRET_LEN];
    MlKem1024::decapsulate(&dk, ct, &mut shared)
        .map_err(|e| AftError::CryptoError(format!("ML-KEM decapsulation: {}", e)))?;
    Ok(shared)
}

/// Encapsulate to `ek`, returning `(kem_ciphertext, shared_secret)`.
fn encapsulate(ek: &[u8; ENCAPS_KEY_LEN]) -> AftResult<(Vec<u8>, [u8; SHARED_SECRET_LEN])> {
    let mut ct = [0u8; CIPHERTEXT_LEN];
    let mut shared = [0u8; SHARED_SECRET_LEN];
    MlKem1024::encapsulate(&mut primitives::os_rng(), ek, &mut ct, &mut shared)
        .map_err(|e| AftError::CryptoError(format!("ML-KEM encapsulation: {}", e)))?;
    Ok((ct.to_vec(), shared))
}

/// Save a public key to a file (atomic write).
pub fn save_public_key(key: &[u8], path: &Path) -> AftResult<()> {
    let mut data = Vec::with_capacity(12 + key.len());
    data.extend_from_slice(PUB_KEY_MAGIC);
    data.push(KEY_VERSION);
    data.push(ALGORITHM_MLKEM1024);
    data.extend_from_slice(&[0u8; 2]); // reserved
    data.extend_from_slice(&(key.len() as u32).to_le_bytes());
    data.extend_from_slice(key);
    std::fs::write(path, &data)?;
    Ok(())
}

/// Save a secret key to a file (atomic write with restricted permissions).
pub fn save_secret_key(key: &[u8], path: &Path) -> AftResult<()> {
    let mut data = Vec::with_capacity(12 + key.len());
    data.extend_from_slice(SEC_KEY_MAGIC);
    data.push(KEY_VERSION);
    data.push(ALGORITHM_MLKEM1024);
    data.extend_from_slice(&[0u8; 2]); // reserved
    data.extend_from_slice(&(key.len() as u32).to_le_bytes());
    data.extend_from_slice(key);
    std::fs::write(path, &data)?;
    // Restrict permissions on Unix (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Reject a key file that is not a current ML-KEM-1024 (version 2) file.
///
/// A legacy version-1 file holds a round-3 Kyber1024 key that ML-KEM cannot
/// use, so we fail with an actionable message rather than feeding incompatible
/// bytes into the KEM.
fn check_header(data: &[u8], magic: &[u8; 4], kind: &str) -> AftResult<()> {
    if data.len() < 12 || &data[..4] != magic {
        return Err(AftError::Other(format!("Not an AFT {} key file", kind)));
    }
    let version = data[4];
    let algorithm = data[5];
    if version != KEY_VERSION || algorithm != ALGORITHM_MLKEM1024 {
        return Err(AftError::CryptoError(format!(
            "{} key is an unsupported format (version {}, algorithm {}); this build uses \
             ML-KEM-1024 (version {}). Regenerate your keys with `aft keygen` — old Kyber1024 \
             keys are not compatible.",
            kind, version, algorithm, KEY_VERSION
        )));
    }
    Ok(())
}

/// Load a public key from a file.
pub fn load_public_key(path: &Path) -> AftResult<Vec<u8>> {
    let data = std::fs::read(path)?;
    check_header(&data, PUB_KEY_MAGIC, "public")?;
    let key_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if data.len() < 12 + key_len {
        return Err(AftError::Other("Public key file truncated".into()));
    }
    Ok(data[12..12 + key_len].to_vec())
}

/// Load a secret key from a file.
pub fn load_secret_key(path: &Path) -> AftResult<Vec<u8>> {
    let data = std::fs::read(path)?;
    check_header(&data, SEC_KEY_MAGIC, "secret")?;
    let key_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if data.len() < 12 + key_len {
        return Err(AftError::Other("Secret key file truncated".into()));
    }
    Ok(data[12..12 + key_len].to_vec())
}

/// Encrypt data using ML-KEM-1024 KEM + AES-256-GCM.
///
/// Returns `(kem_ciphertext, aes_nonce || aes_ciphertext_with_tag)`.
pub fn encrypt(plaintext: &[u8], pub_key_path: &Path) -> AftResult<(Vec<u8>, Vec<u8>)> {
    let pub_key = load_public_key(pub_key_path)?;
    let ek = encapsulation_key(&pub_key)?;

    // KEM encapsulate → 32-byte shared secret
    let (kem_ct, shared_secret) = encapsulate(&ek)?;

    let mut nonce = [0u8; GCM_NONCE_LEN];
    primitives::random_bytes(&mut nonce)?;
    let ciphertext = primitives::gcm_seal(&shared_secret, &nonce, &[], plaintext)?;

    // Combine: nonce || ciphertext (tag is appended by gcm_seal)
    let mut result = Vec::with_capacity(GCM_NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok((kem_ct, result))
}

/// Decrypt data using ML-KEM-1024 KEM + AES-256-GCM.
pub fn decrypt(kem_ct: &[u8], encrypted: &[u8], sec_key_path: &Path) -> AftResult<Vec<u8>> {
    let sec_key = load_secret_key(sec_key_path)?;
    let shared_secret = decapsulate(kem_ct, &sec_key)?;

    if encrypted.len() < GCM_NONCE_LEN {
        return Err(AftError::CryptoError(
            "Encrypted data too short for nonce".into(),
        ));
    }
    let (nonce, ciphertext) = encrypted.split_at(GCM_NONCE_LEN);
    primitives::gcm_open(&shared_secret, nonce, &[], ciphertext)
}

/// Perform KEM encapsulation only (for hybrid mode).
/// Returns `(kem_ciphertext, shared_secret)`.
pub fn encapsulate_key(pub_key_path: &Path) -> AftResult<(Vec<u8>, Vec<u8>)> {
    let pub_key = load_public_key(pub_key_path)?;
    let ek = encapsulation_key(&pub_key)?;
    let (ct, ss) = encapsulate(&ek)?;
    Ok((ct, ss.to_vec()))
}

/// Perform KEM decapsulation only (for hybrid mode).
/// Returns the shared secret.
pub fn decapsulate_key(kem_ct: &[u8], sec_key_path: &Path) -> AftResult<Vec<u8>> {
    let sec_key = load_secret_key(sec_key_path)?;
    Ok(decapsulate(kem_ct, &sec_key)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let pk = dir.path().join("id.afpk");
        let sk = dir.path().join("id.afsk");
        let kp = generate_keypair().unwrap();
        save_public_key(&kp.public_key, &pk).unwrap();
        save_secret_key(&kp.secret_key, &sk).unwrap();
        (dir, pk, sk)
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let (_d, pk, sk) = keys();
        let msg = b"post-quantum secret payload";
        let (kem_ct, enc) = encrypt(msg, &pk).unwrap();
        let back = decrypt(&kem_ct, &enc, &sk).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn hybrid_shared_secret_agrees() {
        let (_d, pk, sk) = keys();
        let (kem_ct, ss_send) = encapsulate_key(&pk).unwrap();
        let ss_recv = decapsulate_key(&kem_ct, &sk).unwrap();
        assert_eq!(ss_send, ss_recv);
        assert_eq!(ss_send.len(), 32); // ML-KEM shared secret is 32 bytes
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let (_d, pk, _sk) = keys();
        let (_d2, _pk2, sk2) = keys();
        let (kem_ct, enc) = encrypt(b"secret", &pk).unwrap();
        // Decapsulating with an unrelated secret key yields a different shared
        // secret (ML-KEM implicit rejection), so the AES-GCM tag fails.
        assert!(decrypt(&kem_ct, &enc, &sk2).is_err());
    }

    /// A legacy version-1 (Kyber1024) key file must be rejected with an
    /// actionable error rather than fed into ML-KEM.
    #[test]
    fn legacy_kyber_key_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let pk = dir.path().join("old.afpk");
        // AFPK || version=1 || algorithm=0 || reserved || key_len=4 || bytes
        let mut data = Vec::new();
        data.extend_from_slice(PUB_KEY_MAGIC);
        data.push(1); // old KEY_VERSION
        data.push(0); // old ALGORITHM_KYBER1024
        data.extend_from_slice(&[0u8; 2]);
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&[1, 2, 3, 4]);
        std::fs::write(&pk, &data).unwrap();

        let err = load_public_key(&pk).unwrap_err();
        assert!(
            format!("{}", err).contains("Regenerate"),
            "expected a regenerate hint, got: {}",
            err
        );
    }
}
