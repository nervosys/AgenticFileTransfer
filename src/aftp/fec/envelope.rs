//! Authenticated, encrypted symbol envelope for the AFTP FEC data plane.
//!
//! Every datagram on the data plane is one envelope: a fixed header, the
//! cryptographic material, and one serialized RaptorQ encoding packet. Datagrams
//! are independent by construction — any envelope can be dropped, duplicated, or
//! reordered without affecting the others. That is the whole point of the
//! fountain-coded data plane: the receiver needs *some* K(+ε) envelopes of a
//! block, not any *particular* ones.
//!
//! ## Confidentiality and integrity
//!
//! When the connection is authenticated (a symbol key is derived from the
//! control-plane auth token — see [`super::derive_symbol_key`]), the payload is
//! sealed with **AES-256-GCM**. The fixed header is bound in as additional
//! authenticated data (AAD), so the session id, block id, and length are
//! authenticated even though they travel in the clear, and the RaptorQ symbol
//! itself is *encrypted*. This matches the confidentiality the control plane
//! gets from TLS: once FEC is negotiated, file bytes leave the TLS stream, so
//! the data plane must carry its own encryption rather than shipping plaintext.
//!
//! Without a key the envelope carries a CRC32 instead. That detects corruption
//! but provides neither authenticity nor confidentiality, so it is appropriate
//! only on a physically trusted link (a lab, a private cross-connect) and must
//! never carry sensitive/CUI data. It is reachable only when the control plane
//! itself is unauthenticated.
//!
//! ## Wire format
//!
//! ```text
//! offset  size  field
//! 0       2     magic (0xAF 0xFE)
//! 2       1     version
//! 3       1     flags
//! 4       8     session_id  (u64 big-endian)
//! 12      4     block_id    (u32 big-endian)
//! 16      2     payload_len (u16 big-endian) — plaintext length
//!
//! authenticated + encrypted (FLAG_AUTH | FLAG_ENCRYPTED):
//! 18      12    AES-256-GCM nonce
//! 30      N     ciphertext (payload_len bytes)
//! 30+N    16    AES-256-GCM tag
//!
//! unauthenticated (no flags):
//! 18      4     CRC32 of header[0..18] || payload
//! 22      N     payload — a serialized `raptorq::EncodingPacket`
//! ```
//!
//! GCM authenticates the nonce, the ciphertext, and the AAD (the 18-byte
//! header prefix). Tampering with any of them — including swapping the nonce or
//! editing the block id — fails the tag check, so forged or corrupt symbols are
//! discarded before they ever reach the decoder.
//!
//! ## Why the header is small
//!
//! Header overhead is paid on *every* datagram, so it directly reduces goodput.
//! At 46 bytes encrypted (22 unauthenticated) an envelope leaves 1350 bytes of
//! symbol in a 1400-byte datagram — 96.4% efficiency.

use rand::RngCore;

use super::symcrypto;
use crate::error::{AftError, AftResult};

/// Envelope magic — distinct from the control plane's `0xAF 0x54` so a
/// datagram that lands on the wrong socket is rejected immediately.
pub const ENVELOPE_MAGIC: [u8; 2] = [0xAF, 0xFE];

/// Data-plane wire version. v2 replaced the v1 HMAC-over-plaintext scheme with
/// AES-256-GCM, so the payload is encrypted rather than merely authenticated.
pub const ENVELOPE_VERSION: u8 = 2;

/// Fixed portion of the header, before any crypto material.
pub const HEADER_PREFIX_LEN: usize = 18;

/// AES-256-GCM nonce length.
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length (trails the ciphertext).
pub const GCM_TAG_LEN: usize = 16;

/// Length of the CRC32 tag used when authentication is disabled.
pub const CRC_TAG_LEN: usize = 4;

/// Non-payload bytes in an authenticated (encrypted) envelope: prefix + nonce +
/// trailing GCM tag.
pub const AUTH_OVERHEAD: usize = HEADER_PREFIX_LEN + NONCE_LEN + GCM_TAG_LEN;

/// Non-payload bytes in an unauthenticated envelope: prefix + CRC32.
pub const HEADER_LEN_PLAIN: usize = HEADER_PREFIX_LEN + CRC_TAG_LEN;

/// Offset at which the ciphertext begins in an authenticated envelope.
const ENC_HEADER_LEN: usize = HEADER_PREFIX_LEN + NONCE_LEN;

/// Symbols carry cryptographic authentication (a key is configured).
pub const FLAG_AUTH: u8 = 0x01;

/// Payload is AES-256-GCM sealed. Always set together with `FLAG_AUTH`.
pub const FLAG_ENCRYPTED: u8 = 0x02;

/// Default path MTU for the raw UDP data plane.
pub const DEFAULT_MTU: u16 = 1400;

/// Bytes of RaptorQ payload that fit in `mtu` given the envelope overhead.
///
/// Accounts for both the envelope overhead and RaptorQ's own 4-byte `PayloadId`
/// that prefixes each serialized packet.
pub fn max_symbol_size(mtu: u16, authenticated: bool) -> u16 {
    let overhead = if authenticated {
        AUTH_OVERHEAD
    } else {
        HEADER_LEN_PLAIN
    };
    // 4 bytes of raptorq PayloadId ride inside the payload.
    mtu.saturating_sub(overhead as u16).saturating_sub(4)
}

/// A parsed data-plane datagram. `payload` is always plaintext: on an encrypted
/// envelope it is the result of a successful decrypt-and-verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub session_id: u64,
    pub block_id: u32,
    pub flags: u8,
    /// Serialized `raptorq::EncodingPacket` (plaintext).
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn new(session_id: u64, block_id: u32, payload: Vec<u8>) -> Self {
        Self {
            session_id,
            block_id,
            flags: 0,
            payload,
        }
    }

    fn write_prefix(&self, flags: u8, out: &mut Vec<u8>) {
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        out.push(flags);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.block_id.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        debug_assert_eq!(out.len(), HEADER_PREFIX_LEN);
    }

    /// Serialize, sealing the payload with AES-256-GCM when `key` is supplied.
    ///
    /// With no key the envelope carries a CRC32 instead, which detects
    /// corruption but neither forgery nor disclosure — appropriate only for a
    /// trusted link that never carries sensitive data.
    pub fn encode(&self, key: Option<&[u8]>) -> AftResult<Vec<u8>> {
        if self.payload.len() > u16::MAX as usize {
            return Err(AftError::Other(format!(
                "FEC payload {} exceeds {} bytes",
                self.payload.len(),
                u16::MAX
            )));
        }

        match key {
            Some(k) => {
                let flags = self.flags | FLAG_AUTH | FLAG_ENCRYPTED;
                let mut out = Vec::with_capacity(AUTH_OVERHEAD + self.payload.len());
                self.write_prefix(flags, &mut out);

                let mut nonce_bytes = [0u8; NONCE_LEN];
                rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
                out.extend_from_slice(&nonce_bytes);

                // AAD = the 18-byte prefix, so the header is authenticated even
                // though it is not encrypted. `out` currently holds
                // prefix || nonce; the prefix is its first HEADER_PREFIX_LEN
                // bytes.
                let aad = out[..HEADER_PREFIX_LEN].to_vec();
                let sealed = symcrypto::seal(k, &nonce_bytes, &aad, &self.payload)?;
                out.extend_from_slice(&sealed);
                Ok(out)
            }
            None => {
                let mut out = Vec::with_capacity(HEADER_LEN_PLAIN + self.payload.len());
                self.write_prefix(self.flags & !(FLAG_AUTH | FLAG_ENCRYPTED), &mut out);
                let mut h = crc32fast::Hasher::new();
                h.update(&out);
                h.update(&self.payload);
                out.extend_from_slice(&h.finalize().to_be_bytes());
                out.extend_from_slice(&self.payload);
                Ok(out)
            }
        }
    }

    /// Parse and verify a datagram.
    ///
    /// Fails closed: a datagram whose tag does not verify, whose magic or
    /// version is wrong, or whose declared length disagrees with the received
    /// bytes is rejected rather than partially accepted. `key` must be supplied
    /// iff the sender authenticated; a mismatch is an error, so an attacker
    /// cannot strip authentication (and encryption) by clearing the flags.
    pub fn decode(buf: &[u8], key: Option<&[u8]>) -> AftResult<Self> {
        if buf.len() < HEADER_PREFIX_LEN {
            return Err(AftError::Other(format!(
                "FEC datagram too short: {} bytes",
                buf.len()
            )));
        }
        if buf[0..2] != ENVELOPE_MAGIC {
            return Err(AftError::Other("FEC bad magic".to_string()));
        }
        if buf[2] != ENVELOPE_VERSION {
            return Err(AftError::Other(format!(
                "FEC version mismatch: got {}, expected {}",
                buf[2], ENVELOPE_VERSION
            )));
        }

        let flags = buf[3];
        let encrypted = flags & FLAG_ENCRYPTED != 0;
        let authed = flags & FLAG_AUTH != 0;

        // Refuse a downgrade: holding a key requires an authenticated+encrypted
        // datagram; holding none requires a plain one. Either mismatch is fatal,
        // so an attacker can neither strip encryption nor smuggle in a datagram
        // we cannot decrypt.
        match (key.is_some(), authed && encrypted) {
            (true, true) => {}
            (false, false) if !authed && !encrypted => {}
            (true, _) => {
                return Err(AftError::Other(
                    "FEC datagram is not authenticated/encrypted but a key is configured"
                        .to_string(),
                ))
            }
            (false, _) => {
                return Err(AftError::Other(
                    "FEC datagram is authenticated but no key is configured".to_string(),
                ))
            }
        }

        let session_id = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        let block_id = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        let payload_len = u16::from_be_bytes(buf[16..18].try_into().unwrap()) as usize;

        match key {
            Some(k) => {
                let expected = ENC_HEADER_LEN + payload_len + GCM_TAG_LEN;
                if buf.len() != expected {
                    return Err(AftError::Other(format!(
                        "FEC length mismatch: declared {}, envelope {} bytes",
                        payload_len,
                        buf.len()
                    )));
                }
                let prefix = &buf[0..HEADER_PREFIX_LEN];
                let nonce = &buf[HEADER_PREFIX_LEN..ENC_HEADER_LEN];
                let sealed = &buf[ENC_HEADER_LEN..]; // ciphertext || tag

                let payload = symcrypto::open(k, nonce, prefix, sealed)?;

                Ok(Self {
                    session_id,
                    block_id,
                    flags,
                    payload,
                })
            }
            None => {
                let header_len = HEADER_LEN_PLAIN;
                if buf.len() != header_len + payload_len {
                    return Err(AftError::Other(format!(
                        "FEC length mismatch: declared {}, received {}",
                        payload_len,
                        buf.len().saturating_sub(header_len)
                    )));
                }
                let prefix = &buf[0..HEADER_PREFIX_LEN];
                let tag = &buf[HEADER_PREFIX_LEN..header_len];
                let payload = &buf[header_len..];

                let mut h = crc32fast::Hasher::new();
                h.update(prefix);
                h.update(payload);
                if h.finalize().to_be_bytes() != tag {
                    return Err(AftError::Other("FEC symbol CRC32 mismatch".to_string()));
                }
                Ok(Self {
                    session_id,
                    block_id,
                    flags,
                    payload: payload.to_vec(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn env() -> Envelope {
        Envelope::new(0xDEAD_BEEF_CAFE_1234, 7, b"symbol-payload-bytes".to_vec())
    }

    #[test]
    fn authenticated_round_trip() {
        let e = env();
        let wire = e.encode(Some(KEY)).unwrap();
        let back = Envelope::decode(&wire, Some(KEY)).unwrap();
        assert_eq!(back.session_id, e.session_id);
        assert_eq!(back.block_id, e.block_id);
        assert_eq!(back.payload, e.payload);
        assert!(back.flags & FLAG_AUTH != 0);
        assert!(back.flags & FLAG_ENCRYPTED != 0);
    }

    #[test]
    fn unauthenticated_round_trip() {
        let e = env();
        let wire = e.encode(None).unwrap();
        assert_eq!(wire.len(), HEADER_LEN_PLAIN + e.payload.len());
        let back = Envelope::decode(&wire, None).unwrap();
        assert_eq!(back.payload, e.payload);
    }

    /// The plaintext symbol must not appear anywhere on the wire when a key is
    /// used — this is the property the whole C1 fix exists to provide.
    #[test]
    fn payload_is_encrypted_on_the_wire() {
        let e = env();
        let wire = e.encode(Some(KEY)).unwrap();
        assert!(
            !wire
                .windows(e.payload.len())
                .any(|w| w == e.payload.as_slice()),
            "plaintext payload leaked into the ciphertext envelope"
        );
    }

    /// A fresh nonce per encode means two encodings of the same symbol differ.
    #[test]
    fn each_encode_uses_a_fresh_nonce() {
        let e = env();
        let a = e.encode(Some(KEY)).unwrap();
        let b = e.encode(Some(KEY)).unwrap();
        assert_ne!(a, b, "nonce (and thus ciphertext) must vary per datagram");
        // But both still decrypt to the same plaintext.
        assert_eq!(
            Envelope::decode(&a, Some(KEY)).unwrap().payload,
            Envelope::decode(&b, Some(KEY)).unwrap().payload
        );
    }

    #[test]
    fn authenticated_overhead_is_46_bytes() {
        let e = env();
        let wire = e.encode(Some(KEY)).unwrap();
        assert_eq!(AUTH_OVERHEAD, 46);
        assert_eq!(wire.len(), 46 + e.payload.len());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let wire = env().encode(Some(KEY)).unwrap();
        let bad = b"ffffffffffffffffffffffffffffffff";
        assert!(Envelope::decode(&wire, Some(bad)).is_err());
    }

    /// Flipping any single bit anywhere in the datagram must be caught.
    #[test]
    fn tampering_is_rejected_everywhere() {
        let wire = env().encode(Some(KEY)).unwrap();
        for i in 0..wire.len() {
            let mut t = wire.clone();
            t[i] ^= 0x01;
            assert!(
                Envelope::decode(&t, Some(KEY)).is_err(),
                "tamper at byte {} was accepted",
                i
            );
        }
    }

    #[test]
    fn corruption_is_caught_without_a_key() {
        let wire = env().encode(None).unwrap();
        for i in 0..wire.len() {
            let mut t = wire.clone();
            t[i] ^= 0x01;
            assert!(
                Envelope::decode(&t, None).is_err(),
                "corruption at byte {} was accepted",
                i
            );
        }
    }

    /// An attacker must not be able to strip authentication/encryption by
    /// clearing the flags and swapping in a CRC32.
    #[test]
    fn auth_downgrade_is_refused() {
        let plain = env().encode(None).unwrap();
        assert!(Envelope::decode(&plain, Some(KEY)).is_err());

        let authed = env().encode(Some(KEY)).unwrap();
        assert!(Envelope::decode(&authed, None).is_err());
    }

    #[test]
    fn truncated_datagram_is_rejected() {
        let wire = env().encode(Some(KEY)).unwrap();
        for n in 0..wire.len() {
            assert!(
                Envelope::decode(&wire[..n], Some(KEY)).is_err(),
                "prefix of {} bytes was accepted",
                n
            );
        }
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        let mut wire = env().encode(Some(KEY)).unwrap();
        wire.push(0);
        assert!(Envelope::decode(&wire, Some(KEY)).is_err());
    }

    #[test]
    fn bad_magic_and_version_rejected() {
        let mut wire = env().encode(Some(KEY)).unwrap();
        wire[0] = 0x00;
        assert!(Envelope::decode(&wire, Some(KEY)).is_err());

        let mut wire = env().encode(Some(KEY)).unwrap();
        wire[2] = ENVELOPE_VERSION.wrapping_add(1);
        assert!(Envelope::decode(&wire, Some(KEY)).is_err());
    }

    /// Swapping the nonce for another valid-length one must fail the tag check,
    /// not silently decrypt to garbage.
    #[test]
    fn nonce_tampering_is_rejected() {
        let mut wire = env().encode(Some(KEY)).unwrap();
        wire[HEADER_PREFIX_LEN] ^= 0xFF;
        assert!(Envelope::decode(&wire, Some(KEY)).is_err());
    }

    #[test]
    fn symbol_sizing_fits_the_mtu() {
        let s = max_symbol_size(1400, true);
        assert_eq!(s, 1400 - 46 - 4);
        // A full-size symbol plus its PayloadId must not exceed the MTU.
        let payload = vec![0u8; s as usize + 4];
        let wire = Envelope::new(1, 0, payload).encode(Some(KEY)).unwrap();
        assert_eq!(wire.len(), 1400);

        assert_eq!(max_symbol_size(1200, false), 1200 - 22 - 4);
    }

    #[test]
    fn empty_payload_round_trips() {
        let e = Envelope::new(1, 0, Vec::new());
        let wire = e.encode(Some(KEY)).unwrap();
        assert_eq!(
            Envelope::decode(&wire, Some(KEY)).unwrap().payload,
            Vec::<u8>::new()
        );
    }
}
