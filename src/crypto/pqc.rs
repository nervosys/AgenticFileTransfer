//! Post-Quantum Cryptography: ML-KEM (Kyber1024) + AES-256-GCM.
//!
//! Provides NIST FIPS 203-compliant key encapsulation with Kyber1024
//! (256-bit post-quantum security) combined with AES-256-GCM for
//! authenticated symmetric encryption.
//!
//! Key file formats:
//!   Public key:  AFPK || version || algorithm || reserved || key_len || key_bytes
//!   Secret key:  AFSK || version || algorithm || reserved || key_len || key_bytes

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use pqc_kyber::*;
use rand::RngCore;

use crate::error::{AftError, AftResult};

const PUB_KEY_MAGIC: &[u8; 4] = b"AFPK";
const SEC_KEY_MAGIC: &[u8; 4] = b"AFSK";
const KEY_VERSION: u8 = 1;
#[allow(dead_code)]
const ALGORITHM_KYBER1024: u8 = 0;

/// A Kyber1024 keypair for post-quantum key encapsulation.
pub struct PqcKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Generate a new Kyber1024 keypair.
pub fn generate_keypair() -> AftResult<PqcKeyPair> {
    let mut rng = rand::rngs::OsRng;
    let keys = keypair(&mut rng)
        .map_err(|e| AftError::Other(format!("Kyber key generation failed: {:?}", e)))?;
    Ok(PqcKeyPair {
        public_key: keys.public.to_vec(),
        secret_key: keys.secret.to_vec(),
    })
}

/// Save a public key to a file.
pub fn save_public_key(key: &[u8], path: &Path) -> AftResult<()> {
    let mut data = Vec::with_capacity(12 + key.len());
    data.extend_from_slice(PUB_KEY_MAGIC);
    data.push(KEY_VERSION);
    data.push(ALGORITHM_KYBER1024);
    data.extend_from_slice(&[0u8; 2]); // reserved
    data.extend_from_slice(&(key.len() as u32).to_le_bytes());
    std::fs::write(path, &data)?;
    // Append key bytes separately to avoid double-allocation
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(path)?;
    f.write_all(key)?;
    Ok(())
}

/// Save a secret key to a file.
pub fn save_secret_key(key: &[u8], path: &Path) -> AftResult<()> {
    let mut data = Vec::with_capacity(12 + key.len());
    data.extend_from_slice(SEC_KEY_MAGIC);
    data.push(KEY_VERSION);
    data.push(ALGORITHM_KYBER1024);
    data.extend_from_slice(&[0u8; 2]); // reserved
    data.extend_from_slice(&(key.len() as u32).to_le_bytes());
    std::fs::write(path, &data)?;
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(path)?;
    f.write_all(key)?;
    Ok(())
}

/// Load a public key from a file.
pub fn load_public_key(path: &Path) -> AftResult<Vec<u8>> {
    let data = std::fs::read(path)?;
    if data.len() < 12 || &data[..4] != PUB_KEY_MAGIC {
        return Err(AftError::Other(
            "Not an AFT public key file".into(),
        ));
    }
    let key_len =
        u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if data.len() < 12 + key_len {
        return Err(AftError::Other("Public key file truncated".into()));
    }
    Ok(data[12..12 + key_len].to_vec())
}

/// Load a secret key from a file.
pub fn load_secret_key(path: &Path) -> AftResult<Vec<u8>> {
    let data = std::fs::read(path)?;
    if data.len() < 12 || &data[..4] != SEC_KEY_MAGIC {
        return Err(AftError::Other(
            "Not an AFT secret key file".into(),
        ));
    }
    let key_len =
        u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if data.len() < 12 + key_len {
        return Err(AftError::Other("Secret key file truncated".into()));
    }
    Ok(data[12..12 + key_len].to_vec())
}

/// Encrypt data using Kyber1024 KEM + AES-256-GCM.
///
/// Returns `(kem_ciphertext, aes_nonce || aes_ciphertext_with_tag)`.
pub fn encrypt(plaintext: &[u8], pub_key_path: &Path) -> AftResult<(Vec<u8>, Vec<u8>)> {
    let pub_key = load_public_key(pub_key_path)?;
    let mut rng = rand::rngs::OsRng;

    // KEM encapsulate → 32-byte shared secret
    let (kem_ct, shared_secret) = encapsulate(&pub_key, &mut rng)
        .map_err(|e| AftError::Other(format!("Kyber encapsulation failed: {:?}", e)))?;

    // AES-256-GCM with the shared secret as key
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|e| AftError::Other(format!("AES key error: {}", e)))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AftError::Other(format!("AES-GCM encryption failed: {}", e)))?;

    // Combine: nonce || ciphertext (tag is appended by aes-gcm)
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok((kem_ct.to_vec(), result))
}

/// Decrypt data using Kyber1024 KEM + AES-256-GCM.
pub fn decrypt(
    kem_ct: &[u8],
    encrypted: &[u8],
    sec_key_path: &Path,
) -> AftResult<Vec<u8>> {
    let sec_key = load_secret_key(sec_key_path)?;

    // KEM decapsulate → recover shared secret
    let shared_secret = decapsulate(kem_ct, &sec_key)
        .map_err(|e| AftError::Other(format!("Kyber decapsulation failed: {:?}", e)))?;

    // AES-256-GCM decrypt
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|e| AftError::Other(format!("AES key error: {}", e)))?;

    if encrypted.len() < 12 {
        return Err(AftError::Other("Encrypted data too short for nonce".into()));
    }
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AftError::Other(format!("AES-GCM decryption failed: {}", e)))?;

    Ok(plaintext)
}

/// Perform KEM encapsulation only (for hybrid mode).
/// Returns `(kem_ciphertext, shared_secret)`.
pub fn encapsulate_key(pub_key_path: &Path) -> AftResult<(Vec<u8>, Vec<u8>)> {
    let pub_key = load_public_key(pub_key_path)?;
    let mut rng = rand::rngs::OsRng;
    let (ct, ss) = encapsulate(&pub_key, &mut rng)
        .map_err(|e| AftError::Other(format!("Kyber encapsulation failed: {:?}", e)))?;
    Ok((ct.to_vec(), ss.to_vec()))
}

/// Perform KEM decapsulation only (for hybrid mode).
/// Returns the shared secret.
pub fn decapsulate_key(kem_ct: &[u8], sec_key_path: &Path) -> AftResult<Vec<u8>> {
    let sec_key = load_secret_key(sec_key_path)?;
    let ss = decapsulate(kem_ct, &sec_key)
        .map_err(|e| AftError::Other(format!("Kyber decapsulation failed: {:?}", e)))?;
    Ok(ss.to_vec())
}
