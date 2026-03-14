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

pub mod classification;
pub mod neural;
pub mod pqc;

use std::path::Path;

use crate::error::{AftError, AftResult};

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
            // PQC key exchange → shared secret used as XOR mask → neural encryption
            let (kem_ct, shared_secret) = pqc::encapsulate_key(key_file)?;
            // XOR plaintext with repeated shared secret before neural encryption
            let masked: Vec<u8> = plaintext
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ shared_secret[i % shared_secret.len()])
                .collect();
            let ct = neural::encrypt_file_data(&masked, key_file)?;
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
pub async fn decrypt_file(
    input: &Path,
    output: &Path,
    key_file: &Path,
) -> AftResult<u64> {
    let data = tokio::fs::read(input).await?;

    if data.len() < HEADER_SIZE {
        return Err(AftError::Other("File too short for encrypted header".into()));
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
        .ok_or_else(|| AftError::Other(format!("Unknown encryption method: {}", data[5])))?;
    // original_len at bytes 8..16 (informational)
    let kem_ct_len =
        u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

    let kem_ct_end = HEADER_SIZE + kem_ct_len;
    if data.len() < kem_ct_end {
        return Err(AftError::Other("File truncated (KEM ciphertext)".into()));
    }
    let kem_ct = &data[HEADER_SIZE..kem_ct_end];
    let ciphertext = &data[kem_ct_end..];

    let plaintext = match method {
        EncryptionMethod::Pqc => pqc::decrypt(kem_ct, ciphertext, key_file)?,
        EncryptionMethod::Neural => neural::decrypt_file_data(ciphertext, key_file)?,
        EncryptionMethod::Hybrid => {
            let shared_secret = pqc::decapsulate_key(kem_ct, key_file)?;
            let masked = neural::decrypt_file_data(ciphertext, key_file)?;
            masked
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ shared_secret[i % shared_secret.len()])
                .collect()
        }
    };

    tokio::fs::write(output, &plaintext).await?;
    Ok(plaintext.len() as u64)
}
