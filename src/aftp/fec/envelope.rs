//! Authenticated symbol envelope for the AFTP FEC data plane.
//!
//! Every datagram on the data plane is one envelope: a fixed header, an
//! integrity tag, and one serialized RaptorQ encoding packet. Datagrams are
//! independent by construction — any envelope can be dropped, duplicated, or
//! reordered without affecting the others. That is the whole point of the
//! fountain-coded data plane: the receiver needs *some* K(+ε) envelopes of a
//! block, not any *particular* ones.
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
//! 16      2     payload_len (u16 big-endian)
//! 18      T     integrity tag: 16-byte truncated HMAC-SHA256 if FLAG_AUTH,
//!               else 4-byte CRC32
//! 18+T    N     payload — a serialized `raptorq::EncodingPacket`
//! ```
//!
//! The tag covers `header[0..18] || payload`, so the block id and length are
//! authenticated along with the symbol. A receiver that cannot verify the tag
//! discards the datagram before it reaches the decoder, which keeps forged or
//! corrupt symbols out of the Gaussian elimination entirely.
//!
//! ## Why the header is small
//!
//! Header overhead is paid on *every* datagram, so it directly reduces goodput.
//! At 34 bytes authenticated (22 unauthenticated) an envelope leaves 1362 bytes
//! of symbol in a 1400-byte datagram — 97.3% efficiency.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{AftError, AftResult};

type HmacSha256 = Hmac<Sha256>;

/// Envelope magic — distinct from the control plane's `0xAF 0x54` so a
/// datagram that lands on the wrong socket is rejected immediately.
pub const ENVELOPE_MAGIC: [u8; 2] = [0xAF, 0xFE];

/// Data-plane wire version.
pub const ENVELOPE_VERSION: u8 = 1;

/// Fixed portion of the header, before the integrity tag.
pub const HEADER_PREFIX_LEN: usize = 18;

/// Length of the truncated HMAC-SHA256 tag.
pub const AUTH_TAG_LEN: usize = 16;

/// Length of the CRC32 tag used when authentication is disabled.
pub const CRC_TAG_LEN: usize = 4;

/// Total header length for an authenticated envelope.
pub const HEADER_LEN_AUTH: usize = HEADER_PREFIX_LEN + AUTH_TAG_LEN;

/// Total header length for an unauthenticated envelope.
pub const HEADER_LEN_PLAIN: usize = HEADER_PREFIX_LEN + CRC_TAG_LEN;

/// Symbols carry a truncated HMAC-SHA256 tag rather than a CRC32.
pub const FLAG_AUTH: u8 = 0x01;

/// Reserved: payload is AES-256-GCM sealed. Not yet implemented; parsing an
/// envelope with this bit set is refused so a future sender cannot be
/// misinterpreted as plaintext by an older receiver.
pub const FLAG_ENCRYPTED: u8 = 0x02;

/// Default path MTU for the raw UDP data plane.
pub const DEFAULT_MTU: u16 = 1400;

/// Bytes of RaptorQ payload that fit in `mtu` given the envelope overhead.
///
/// Accounts for both the envelope header and RaptorQ's own 4-byte `PayloadId`
/// that prefixes each serialized packet.
pub fn max_symbol_size(mtu: u16, authenticated: bool) -> u16 {
    let header = if authenticated {
        HEADER_LEN_AUTH
    } else {
        HEADER_LEN_PLAIN
    };
    // 4 bytes of raptorq PayloadId ride inside the payload.
    mtu.saturating_sub(header as u16).saturating_sub(4)
}

/// A parsed data-plane datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub session_id: u64,
    pub block_id: u32,
    pub flags: u8,
    /// Serialized `raptorq::EncodingPacket`.
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

    /// Serialize, authenticating with `key` when one is supplied.
    ///
    /// With no key the envelope carries a CRC32 instead, which detects
    /// corruption but not forgery — appropriate only for trusted links.
    pub fn encode(&self, key: Option<&[u8]>) -> AftResult<Vec<u8>> {
        if self.payload.len() > u16::MAX as usize {
            return Err(AftError::Other(format!(
                "FEC payload {} exceeds {} bytes",
                self.payload.len(),
                u16::MAX
            )));
        }

        let authenticated = key.is_some();
        let tag_len = if authenticated {
            AUTH_TAG_LEN
        } else {
            CRC_TAG_LEN
        };
        let mut out = Vec::with_capacity(HEADER_PREFIX_LEN + tag_len + self.payload.len());

        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        out.push(if authenticated {
            self.flags | FLAG_AUTH
        } else {
            self.flags & !FLAG_AUTH
        });
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.block_id.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        debug_assert_eq!(out.len(), HEADER_PREFIX_LEN);

        match key {
            Some(k) => {
                let tag = compute_tag(k, &out, &self.payload)?;
                out.extend_from_slice(&tag);
            }
            None => {
                let mut h = crc32fast::Hasher::new();
                h.update(&out);
                h.update(&self.payload);
                out.extend_from_slice(&h.finalize().to_be_bytes());
            }
        }

        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Parse and verify a datagram.
    ///
    /// Fails closed: a datagram whose tag does not verify, whose magic or
    /// version is wrong, or whose declared length disagrees with the received
    /// bytes is rejected rather than partially accepted. `key` must be supplied
    /// iff the sender authenticated; a mismatch is an error, so an attacker
    /// cannot strip authentication by clearing the flag.
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
        if flags & FLAG_ENCRYPTED != 0 {
            return Err(AftError::Other(
                "FEC envelope is encrypted; this build cannot decrypt it".to_string(),
            ));
        }

        let authenticated = flags & FLAG_AUTH != 0;
        // Refuse a downgrade: if we hold a key we require authentication, and
        // if we hold none we cannot verify one.
        if authenticated != key.is_some() {
            return Err(AftError::Other(if authenticated {
                "FEC datagram is authenticated but no key is configured".to_string()
            } else {
                "FEC datagram is unauthenticated but a key is configured".to_string()
            }));
        }

        let tag_len = if authenticated {
            AUTH_TAG_LEN
        } else {
            CRC_TAG_LEN
        };
        let header_len = HEADER_PREFIX_LEN + tag_len;
        if buf.len() < header_len {
            return Err(AftError::Other(format!(
                "FEC datagram truncated: {} bytes, need {}",
                buf.len(),
                header_len
            )));
        }

        let session_id = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        let block_id = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        let payload_len = u16::from_be_bytes(buf[16..18].try_into().unwrap()) as usize;

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

        match key {
            Some(k) => {
                let expected = compute_tag(k, prefix, payload)?;
                // `Hmac::verify` is constant-time; compare via it rather than
                // slice equality so tag verification cannot leak timing.
                let mut mac = HmacSha256::new_from_slice(k)
                    .map_err(|e| AftError::Other(format!("FEC hmac key: {}", e)))?;
                mac.update(prefix);
                mac.update(payload);
                mac.verify_truncated_left(tag)
                    .map_err(|_| AftError::Other("FEC symbol authentication failed".to_string()))?;
                debug_assert_eq!(&expected[..], tag);
            }
            None => {
                let mut h = crc32fast::Hasher::new();
                h.update(prefix);
                h.update(payload);
                if h.finalize().to_be_bytes() != tag {
                    return Err(AftError::Other("FEC symbol CRC32 mismatch".to_string()));
                }
            }
        }

        Ok(Self {
            session_id,
            block_id,
            flags,
            payload: payload.to_vec(),
        })
    }
}

fn compute_tag(key: &[u8], prefix: &[u8], payload: &[u8]) -> AftResult<[u8; AUTH_TAG_LEN]> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| AftError::Other(format!("FEC hmac key: {}", e)))?;
    mac.update(prefix);
    mac.update(payload);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; AUTH_TAG_LEN];
    tag.copy_from_slice(&full[..AUTH_TAG_LEN]);
    Ok(tag)
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
    }

    #[test]
    fn unauthenticated_round_trip() {
        let e = env();
        let wire = e.encode(None).unwrap();
        assert_eq!(wire.len(), HEADER_LEN_PLAIN + e.payload.len());
        let back = Envelope::decode(&wire, None).unwrap();
        assert_eq!(back.payload, e.payload);
    }

    #[test]
    fn authenticated_header_is_34_bytes() {
        let e = env();
        let wire = e.encode(Some(KEY)).unwrap();
        assert_eq!(HEADER_LEN_AUTH, 34);
        assert_eq!(wire.len(), 34 + e.payload.len());
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

    /// An attacker must not be able to strip authentication by clearing the
    /// flag and swapping in a CRC32.
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

    #[test]
    fn encrypted_flag_is_refused_not_ignored() {
        let mut e = env();
        e.flags = FLAG_ENCRYPTED;
        let wire = e.encode(Some(KEY)).unwrap();
        let err = Envelope::decode(&wire, Some(KEY)).unwrap_err();
        assert!(err.to_string().contains("encrypted"));
    }

    #[test]
    fn symbol_sizing_fits_the_mtu() {
        let s = max_symbol_size(1400, true);
        assert_eq!(s, 1400 - 34 - 4);
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
        assert_eq!(Envelope::decode(&wire, Some(KEY)).unwrap().payload, Vec::<u8>::new());
    }
}
