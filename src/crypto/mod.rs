//! Cryptographic subsystem for AFT.
//!
//! Provides three encryption methods:
//!
//! - **PQC**: Post-quantum Kyber1024 key encapsulation + AES-256-GCM
//!   (NIST FIPS 203). Recommended for DoD environments.
//! - **Neural**: Trained encoder-decoder neural network cipher.
//!   Experimental — the model weights serve as the symmetric key.
//! - **Hybrid**: PQC key exchange for session key, combined with
//!   neural network bulk encryption.
//!
//! Also provides DoD classification level enforcement.
//!
//! ## Hardware acceleration
//!
//! - **AES-256-GCM**: via `aes-gcm` — auto-detects AES-NI (x86_64) and
//!   ARM AES extensions.
//! - **SHA-256**: via `sha2` — auto-detects SHA-NI (x86_64) and SHA2 (aarch64).
//! - **XOR bulk masking**: widened to `u64` operations for hardware-friendly
//!   throughput in the Hybrid encryption path.

pub mod classification;
pub mod neural;
pub mod pqc;

use std::path::Path;

use crate::error::{AftError, AftResult};

/// XOR `data` with `key` (repeated), processing in u64 chunks for throughput.
/// Falls back to byte-at-a-time for the remainder and short keys.
fn xor_with_key(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let key_len = key.len();
    if key_len == 0 {
        out.copy_from_slice(data);
        return out;
    }

    // Build a key buffer that is a multiple of 8 bytes for u64 processing.
    // Repeat the key enough times to fill at least 8 bytes.
    let expanded_len = key_len.max(8).next_multiple_of(key_len);
    let mut expanded_key = Vec::with_capacity(expanded_len);
    while expanded_key.len() < expanded_len {
        expanded_key.extend_from_slice(key);
    }
    expanded_key.truncate(expanded_len);

    let chunks8 = data.len() / 8;
    let remainder = data.len() % 8;

    for i in 0..chunks8 {
        let di = i * 8;
        let ki = di % expanded_len;
        let d = u64::from_le_bytes(data[di..di + 8].try_into().unwrap());
        let k = u64::from_le_bytes(expanded_key[ki..ki + 8].try_into().unwrap());
        out[di..di + 8].copy_from_slice(&(d ^ k).to_le_bytes());
    }

    let base = chunks8 * 8;
    for j in 0..remainder {
        out[base + j] = data[base + j] ^ key[(base + j) % key_len];
    }

    out
}

/// Encryption method selector.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum EncryptionMethod {
    /// Post-quantum: Kyber1024 KEM + AES-256-GCM (NIST FIPS 203)
    Pqc,
    /// Neural network: trained encoder-decoder cipher
    Neural,
    /// Hybrid: PQC key exchange + neural network bulk encryption
    Hybrid,
}

impl EncryptionMethod {
    /// Parse from a CLI string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pqc" | "kyber" | "post-quantum" => Some(Self::Pqc),
            "neural" | "nn" => Some(Self::Neural),
            "hybrid" => Some(Self::Hybrid),
            _ => None,
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            EncryptionMethod::Pqc => 0,
            EncryptionMethod::Neural => 1,
            EncryptionMethod::Hybrid => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(EncryptionMethod::Pqc),
            1 => Some(EncryptionMethod::Neural),
            2 => Some(EncryptionMethod::Hybrid),
            _ => None,
        }
    }
}

/// Magic bytes for AFT encrypted files.
const ENCRYPTED_MAGIC: &[u8; 4] = b"AFTE";
/// Current encrypted file format version.
const ENCRYPTED_VERSION: u8 = 1;
/// Header size in bytes.
const HEADER_SIZE: usize = 20;

/// Encrypt a file on disk.
///
/// The output file uses the AFT encrypted format:
/// `AFTE || version || method || reserved || original_len || kem_ct_len || kem_ct || encrypted_data`
pub async fn encrypt_file(
    input: &Path,
    output: &Path,
    method: EncryptionMethod,
    key_file: &Path,
) -> AftResult<u64> {
    let plaintext = tokio::fs::read(input).await?;
    let original_len = plaintext.len() as u64;

    let (kem_ct, ciphertext) = match method {
        EncryptionMethod::Pqc => pqc::encrypt(&plaintext, key_file)?,
        EncryptionMethod::Neural => {
            let ct = neural::encrypt_file_data(&plaintext, key_file)?;
            (Vec::new(), ct)
        }
        EncryptionMethod::Hybrid => {
            // PQC key exchange → shared secret → deterministic neural cipher
            let (kem_ct, shared_secret) = pqc::encapsulate_key(key_file)?;
            // Derive a full-entropy seed via HMAC-SHA256(shared_secret, "aft-neural-seed")
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac = HmacSha256::new_from_slice(&shared_secret)
                .map_err(|_| AftError::CryptoError("HMAC key init failed".into()))?;
            mac.update(b"aft-neural-seed");
            let derived = mac.finalize().into_bytes();
            let seed = u64::from_le_bytes(
                derived[..8]
                    .try_into()
                    .map_err(|_| AftError::CryptoError("Seed derivation failed".into()))?,
            );
            let cipher = neural::NeuralCipher::train(&neural::TrainConfig {
                epochs: 100,
                seed,
                ..Default::default()
            });
            // XOR plaintext with repeated shared secret, then neural-encrypt
            // Process in u64 chunks for hardware-friendly throughput
            let masked = xor_with_key(&plaintext, &shared_secret);
            let ct = cipher.encrypt(&masked);
            (kem_ct, ct)
        }
    };

    // Build output: header + kem_ciphertext + encrypted_data
    let mut out_data = Vec::with_capacity(HEADER_SIZE + kem_ct.len() + ciphertext.len());
    out_data.extend_from_slice(ENCRYPTED_MAGIC);
    out_data.push(ENCRYPTED_VERSION);
    out_data.push(method.to_byte());
    out_data.extend_from_slice(&[0u8; 2]); // reserved
    out_data.extend_from_slice(&original_len.to_le_bytes());
    out_data.extend_from_slice(&(kem_ct.len() as u32).to_le_bytes());
    out_data.extend_from_slice(&kem_ct);
    out_data.extend_from_slice(&ciphertext);

    tokio::fs::write(output, &out_data).await?;
    Ok(out_data.len() as u64)
}

/// Decrypt an AFT encrypted file.
///
/// The encryption method is detected automatically from the file header.
pub async fn decrypt_file(input: &Path, output: &Path, key_file: &Path) -> AftResult<u64> {
    let data = tokio::fs::read(input).await?;

    if data.len() < HEADER_SIZE {
        return Err(AftError::Other(
            "File too short for encrypted header".into(),
        ));
    }
    if &data[..4] != ENCRYPTED_MAGIC {
        return Err(AftError::Other(
            "Not an AFT encrypted file (missing AFTE magic)".into(),
        ));
    }
    if data[4] != ENCRYPTED_VERSION {
        return Err(AftError::Other(format!(
            "Unsupported encrypted file version: {}",
            data[4]
        )));
    }

    let method = EncryptionMethod::from_byte(data[5])
        .ok_or_else(|| AftError::CryptoError(format!("Unknown encryption method: {}", data[5])))?;
    let original_len = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);
    // Sanity-check: reject files claiming implausible original sizes (> 1 TiB)
    const MAX_ORIGINAL_SIZE: u64 = 1 << 40;
    if original_len > MAX_ORIGINAL_SIZE {
        return Err(AftError::Other(format!(
            "Encrypted file claims original size {} bytes, exceeding limit",
            original_len
        )));
    }
    let kem_ct_len = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

    let kem_ct_end = HEADER_SIZE + kem_ct_len;
    if data.len() < kem_ct_end {
        return Err(AftError::CryptoError(
            "File truncated (KEM ciphertext)".into(),
        ));
    }
    let kem_ct = &data[HEADER_SIZE..kem_ct_end];
    let ciphertext = &data[kem_ct_end..];

    let plaintext = match method {
        EncryptionMethod::Pqc => pqc::decrypt(kem_ct, ciphertext, key_file)?,
        EncryptionMethod::Neural => neural::decrypt_file_data(ciphertext, key_file)?,
        EncryptionMethod::Hybrid => {
            let shared_secret = pqc::decapsulate_key(kem_ct, key_file)?;
            // Re-derive the same neural cipher seed via HMAC-SHA256
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac = HmacSha256::new_from_slice(&shared_secret)
                .map_err(|_| AftError::CryptoError("HMAC key init failed".into()))?;
            mac.update(b"aft-neural-seed");
            let derived = mac.finalize().into_bytes();
            let seed = u64::from_le_bytes(
                derived[..8]
                    .try_into()
                    .map_err(|_| AftError::CryptoError("Seed derivation failed".into()))?,
            );
            let cipher = neural::NeuralCipher::train(&neural::TrainConfig {
                epochs: 100,
                seed,
                ..Default::default()
            });
            let masked = cipher.decrypt(ciphertext);
            // XOR with shared secret to recover plaintext
            // (u64-widened for hardware-friendly throughput)
            xor_with_key(&masked, &shared_secret)
        }
    };

    tokio::fs::write(output, &plaintext).await?;
    Ok(plaintext.len() as u64)
}
