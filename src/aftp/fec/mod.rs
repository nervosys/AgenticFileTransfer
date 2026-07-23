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
pub mod pacing;
pub mod transfer;
pub mod udp;

// Convenience re-exports for consumers of the library target. The binary does
// not use all of them yet, hence the allow.
#[allow(unused_imports)]
pub use codec::{
    block_count, block_range, BlockDecoder, BlockEncoder, Oti, DEFAULT_BLOCK_SIZE,
};
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

/// Derive the per-session symbol authentication key from the connection's
/// auth token.
///
/// Binding the key to `session_id` means symbols from one session can never
/// verify against another, so a captured datagram cannot be replayed into a
/// later transfer. Returns `None` when the connection is unauthenticated, in
/// which case symbols carry a CRC32 only — that detects corruption but not
/// forgery, and is appropriate only on a trusted link.
pub fn derive_symbol_key(auth_token: Option<&str>, session_id: u64) -> Option<Vec<u8>> {
    use hmac::{Hmac, Mac};
    let token = auth_token?;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(token.as_bytes()).ok()?;
    mac.update(b"aft-fec-symbol-key-v1");
    mac.update(&session_id.to_be_bytes());
    Some(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn key_is_deterministic_across_peers() {
        let a = derive_symbol_key(Some("s3cret"), 42).unwrap();
        let b = derive_symbol_key(Some("s3cret"), 42).unwrap();
        assert_eq!(a, b, "both ends must derive the same key");
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn key_is_bound_to_the_session() {
        // Replaying a captured symbol into another session must not verify.
        let s1 = derive_symbol_key(Some("s3cret"), 1).unwrap();
        let s2 = derive_symbol_key(Some("s3cret"), 2).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn key_is_bound_to_the_token() {
        let a = derive_symbol_key(Some("one"), 7).unwrap();
        let b = derive_symbol_key(Some("two"), 7).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn unauthenticated_connections_have_no_key() {
        assert!(derive_symbol_key(None, 7).is_none());
    }
}
