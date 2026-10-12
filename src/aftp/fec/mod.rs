// Copyright (c) 2024-2026 Nervosys LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
// The codec, envelope, and pacer are complete and tested, but the client and
// server splices that consume them are still landing, so the binary target
// does not yet reference every item.
#![allow(dead_code)]

//! Fountain-coded data plane for AFTP.
//!
//! AFTP v2 splits a transfer across two planes:
//!
//! - the **control plane** — the existing reliable, ordered AFTP frame stream
//!   over TCP/TLS or a QUIC stream, carrying the handshake, the offer, and
//!   per-block feedback;
//! - the **data plane** — this module: unreliable datagrams each carrying one
//!   RaptorQ symbol, where loss, reordering, and duplication are expected and
//!   handled by the code rather than by retransmission.
//!
//! The split is what makes lossy links cheap. TCP treats a dropped segment as
//! a signal to halve its window and spend a round trip recovering; a fountain
//! code treats it as a reason to send one more symbol. On a 200 ms path that
//! difference is the whole ballgame.
//!
//! Negotiation is fail-safe: a peer that does not advertise `CAP_FEC` gets
//! today's reliable TCP path unchanged, so v1 and v2 interoperate.

pub mod codec;
pub mod envelope;
pub mod manifest;
pub mod pacing;
pub mod quic_dgram;
pub mod symcrypto;
pub mod transfer;
pub mod udp;

// Convenience re-exports for consumers of the library target. The binary does
// not use all of them yet, hence the allow.
#[allow(unused_imports)]
pub use codec::{block_count, block_range, BlockDecoder, BlockEncoder, Oti, DEFAULT_BLOCK_SIZE};
#[allow(unused_imports)]
pub use envelope::{max_symbol_size, Envelope, DEFAULT_MTU};
#[allow(unused_imports)]
pub use pacing::{repair_symbol_count, Pacer, Phase};

/// Smallest transfer worth moving over the data plane.
///
/// Below this the fixed cost — binding a socket, one offer/accept round trip,
/// encoding a block — outweighs anything fountain coding can win back, so
/// small files stay on the reliable frame path where they are already fast.
pub const FEC_MIN_TRANSFER: u64 = 1 << 20; // 1 MiB

/// Derive the per-session AES-256-GCM symbol key from the connection's auth
/// token.
///
/// The 32-byte output is the key the data plane uses to *encrypt and*
/// authenticate every symbol (see [`envelope`]). Binding it to `session_id`
/// means symbols from one session can never decrypt or verify against another,
/// so a captured datagram cannot be replayed into a later transfer — provided
/// `session_id` is unpredictable and unique per session, which is why both ends
/// now exchange a random nonce on the control plane rather than deriving it
/// from public transfer parameters.
///
/// Returns `None` when the connection is unauthenticated, in which case symbols
/// carry a CRC32 only — that detects corruption but provides neither
/// authenticity nor confidentiality, and is appropriate only on a trusted link
/// that never carries sensitive data.
///
/// Crypto note: the KDF and the symbol AEAD both go through [`symcrypto`], which
/// is backed by IronCrypto. Under `--features fips` the IronCrypto FIPS self-tests
/// run at startup. See `docs/SECURITY.md`.
///
/// An error means the crypto backend refused to run. It is not the same as an
/// unauthenticated connection, and callers must not treat it as one.
pub fn derive_symbol_key(
    auth_token: Option<&str>,
    session_id: u64,
) -> crate::error::AftResult<Option<Vec<u8>>> {
    let Some(token) = auth_token else {
        return Ok(None);
    };
    let key = symcrypto::hmac_sha256(
        token.as_bytes(),
        &[b"aft-fec-symbol-key-v2", &session_id.to_be_bytes()],
    )?;
    Ok(Some(key.to_vec()))
}

/// A cryptographically random 64-bit session id for the FEC data plane.
///
/// This is exchanged on the (TLS-protected, when `aftps://`) control plane in
/// the FEC offer, so both ends agree on it without deriving it from public
/// values. Using a random id — rather than `hash(host, port, file_size)` —
/// makes the per-session symbol key unpredictable and unique, which is what
/// actually gives the replay resistance the data plane relies on.
pub fn random_session_id() -> u64 {
    let mut buf = [0u8; 8];
    // Failure here means the OS has no entropy source, and there is no safe
    // session id to fall back to, so this stops rather than guesses.
    crate::crypto::primitives::random_bytes(&mut buf).expect("OS entropy unavailable");
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn key_is_deterministic_across_peers() {
        let a = derive_symbol_key(Some("s3cret"), 42).unwrap().unwrap();
        let b = derive_symbol_key(Some("s3cret"), 42).unwrap().unwrap();
        assert_eq!(a, b, "both ends must derive the same key");
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn key_is_bound_to_the_session() {
        // Replaying a captured symbol into another session must not verify.
        let s1 = derive_symbol_key(Some("s3cret"), 1).unwrap().unwrap();
        let s2 = derive_symbol_key(Some("s3cret"), 2).unwrap().unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn key_is_bound_to_the_token() {
        let a = derive_symbol_key(Some("one"), 7).unwrap().unwrap();
        let b = derive_symbol_key(Some("two"), 7).unwrap().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn unauthenticated_connections_have_no_key() {
        assert!(derive_symbol_key(None, 7).unwrap().is_none());
    }
}
