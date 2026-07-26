//! RaptorQ block codec — the fountain layer of the AFTP data plane.
//!
//! A transfer is cut into fixed-size **blocks** (8 MiB by default). Each block
//! is encoded independently into symbols sized to fit one datagram. The
//! receiver reconstructs a block as soon as it holds enough symbols — *any*
//! enough, not any particular ones.
//!
//! ## Why this beats retransmission on a lossy link
//!
//! Under TCP, a dropped segment costs a round trip to detect and refill, and
//! the congestion window collapses. With a fountain code the sender simply
//! emits more symbols: 10% loss costs ~10% more bytes and no round trips at
//! all. Loss stops being a latency problem and becomes a bandwidth problem,
//! which is the entire reason this data plane exists.
//!
//! ## Bounded memory
//!
//! RaptorQ is *rateless* — a block can produce effectively unlimited distinct
//! repair symbols. [`BlockEncoder::repair_symbols`] generates them on demand
//! from a fixed-size encoder rather than precomputing a pool, so sender memory
//! is a function of block size (8 MiB) and not of file size or loss rate. A 5 GB
//! transfer on a 10%-loss link holds the same working set as a 50 MB one.
//!
//! ## One source block per FEC block
//!
//! The RaptorQ object is configured with exactly one source block, so our
//! `block_id` is the only block identifier on the wire and repair symbol IDs
//! are contiguous per block. RFC 6330 caps a source block at 56 403 symbols;
//! at 8 MiB with ~1.3 KB symbols we use roughly 6 200, well inside the limit.

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};

use crate::error::{AftError, AftResult};

/// Default block size. Large enough to amortize per-block feedback, small
/// enough that the decoder's working set stays modest and a block commits (and
/// frees its buffers) early in a long transfer.
pub const DEFAULT_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// RFC 6330 §4.4.1.2 ceiling on source symbols in one source block.
const MAX_SOURCE_SYMBOLS_PER_BLOCK: u64 = 56_403;

/// Serialized `ObjectTransmissionInformation`, carried in the control-plane
/// offer so the receiver can build a matching decoder.
pub type Oti = [u8; 12];

/// How many blocks a transfer of `total_len` splits into.
pub fn block_count(total_len: u64, block_size: usize) -> u32 {
    if total_len == 0 {
        return 0;
    }
    total_len.div_ceil(block_size as u64) as u32
}

/// Byte range covered by `block_id`.
pub fn block_range(block_id: u32, block_size: usize, total_len: u64) -> (u64, u64) {
    let start = (block_id as u64) * (block_size as u64);
    let end = (start + block_size as u64).min(total_len);
    (start, end)
}

/// Build the transmission parameters for a block of `len` bytes.
///
/// Fails rather than silently splitting into multiple source blocks if the
/// caller asks for a block/symbol combination that exceeds the RFC limit.
pub fn oti_for_block(len: usize, symbol_size: u16) -> AftResult<ObjectTransmissionInformation> {
    if symbol_size == 0 {
        return Err(AftError::Other("FEC symbol size must be non-zero".into()));
    }
    if len == 0 {
        return Err(AftError::Other("FEC block must be non-empty".into()));
    }
    let symbols = (len as u64).div_ceil(symbol_size as u64);
    if symbols > MAX_SOURCE_SYMBOLS_PER_BLOCK {
        return Err(AftError::Other(format!(
            "FEC block of {} bytes needs {} symbols of {} bytes, over the RFC 6330 limit of {}",
            len, symbols, symbol_size, MAX_SOURCE_SYMBOLS_PER_BLOCK
        )));
    }
    // One source block, one sub-block, byte alignment: our block_id is the
    // only block identifier on the wire.
    Ok(ObjectTransmissionInformation::new(
        len as u64,
        symbol_size,
        1,
        1,
        1,
    ))
}

/// Encoder for a single block.
pub struct BlockEncoder {
    inner: Encoder,
    config: ObjectTransmissionInformation,
    source_symbol_count: u32,
}

impl BlockEncoder {
    /// Encode `data` as one block. `symbol_size` must match what the receiver
    /// was told in the offer.
    pub fn new(data: &[u8], symbol_size: u16) -> AftResult<Self> {
        let config = oti_for_block(data.len(), symbol_size)?;
        let inner = Encoder::new(data, config);
        let source_symbol_count = (data.len() as u64).div_ceil(symbol_size as u64) as u32;
        Ok(Self {
            inner,
            config,
            source_symbol_count,
        })
    }

    /// Serialized transmission parameters for the receiver's decoder.
    pub fn oti(&self) -> Oti {
        self.config.serialize()
    }

    /// Number of source symbols — the minimum a receiver needs (RaptorQ
    /// typically decodes at K, and at K+2 with probability ~0.999999).
    pub fn source_symbol_count(&self) -> u32 {
        self.source_symbol_count
    }

    /// The systematic symbols: these *are* the original bytes, in order.
    ///
    /// On a clean link the receiver reassembles from these alone with no
    /// algebraic decoding — the fast path that keeps a perfect link as cheap
    /// as a plain stream copy.
    pub fn source_symbols(&self) -> Vec<Vec<u8>> {
        self.inner
            .get_block_encoders()
            .iter()
            .flat_map(|b| b.source_packets())
            .map(|p| p.serialize())
            .collect()
    }

    /// Generate `count` repair symbols starting at `start_id`, on demand.
    ///
    /// Distinct `start_id` ranges yield distinct symbols, so successive repair
    /// rounds never resend the same symbol. Nothing is cached between calls,
    /// which is what keeps sender memory bounded.
    pub fn repair_symbols(&self, start_id: u32, count: u32) -> Vec<Vec<u8>> {
        if count == 0 {
            return Vec::new();
        }
        self.inner
            .get_block_encoders()
            .iter()
            .flat_map(|b| b.repair_packets(start_id, count))
            .map(|p| p.serialize())
            .collect()
    }
}

/// Decoder for a single block. Feed it symbols until it yields the block.
pub struct BlockDecoder {
    inner: Decoder,
    result: Option<Vec<u8>>,
    accepted: u32,
    expected_len: usize,
}

impl BlockDecoder {
    /// Build a decoder from the serialized parameters in the offer.
    ///
    /// `expected_len` is the block length the control plane promised; a decoded
    /// block of any other length is rejected.
    pub fn new(oti: &Oti, expected_len: usize) -> AftResult<Self> {
        let config = ObjectTransmissionInformation::deserialize(oti);
        if config.transfer_length() != expected_len as u64 {
            return Err(AftError::Other(format!(
                "FEC OTI transfer length {} disagrees with expected block length {}",
                config.transfer_length(),
                expected_len
            )));
        }
        if config.symbol_size() == 0 {
            return Err(AftError::Other("FEC OTI has zero symbol size".into()));
        }
        Ok(Self {
            inner: Decoder::new(config),
            result: None,
            accepted: 0,
            expected_len,
        })
    }

    /// Offer one serialized symbol.
    ///
    /// Returns `Ok(true)` once the block is complete. Extra symbols after
    /// completion are ignored, so a receiver need not race to stop the sender.
    pub fn push(&mut self, payload: &[u8]) -> AftResult<bool> {
        if self.result.is_some() {
            return Ok(true);
        }
        // A serialized packet is a 4-byte PayloadId plus at least one byte of
        // symbol; `EncodingPacket::deserialize` would panic on anything shorter.
        if payload.len() <= 4 {
            return Err(AftError::Other(format!(
                "FEC symbol too short: {} bytes",
                payload.len()
            )));
        }
        self.accepted += 1;
        if let Some(data) = self.inner.decode(EncodingPacket::deserialize(payload)) {
            if data.len() != self.expected_len {
                return Err(AftError::Other(format!(
                    "FEC decoded block is {} bytes, expected {}",
                    data.len(),
                    self.expected_len
                )));
            }
            self.result = Some(data);
            return Ok(true);
        }
        Ok(false)
    }

    pub fn is_complete(&self) -> bool {
        self.result.is_some()
    }

    /// Symbols fed in so far, including any that were redundant.
    pub fn symbols_accepted(&self) -> u32 {
        self.accepted
    }

    /// Take the decoded block, if it is complete.
    pub fn take(&mut self) -> Option<Vec<u8>> {
        self.result.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYM: u16 = 1362;

    fn payload(len: usize) -> Vec<u8> {
        // Deterministic, non-repeating so a mis-ordered reassembly is visible.
        (0..len)
            .map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8)
            .collect()
    }

    #[test]
    fn block_layout_math() {
        assert_eq!(block_count(0, 8), 0);
        assert_eq!(block_count(1, 8), 1);
        assert_eq!(block_count(8, 8), 1);
        assert_eq!(block_count(9, 8), 2);
        assert_eq!(block_range(0, 8, 20), (0, 8));
        assert_eq!(block_range(2, 8, 20), (16, 20));
    }

    #[test]
    fn source_symbols_alone_reconstruct() {
        // The clean-link fast path: no repair symbols needed at all.
        let data = payload(200_000);
        let enc = BlockEncoder::new(&data, SYM).unwrap();
        let mut dec = BlockDecoder::new(&enc.oti(), data.len()).unwrap();

        for s in enc.source_symbols() {
            if dec.push(&s).unwrap() {
                break;
            }
        }
        assert!(dec.is_complete());
        assert_eq!(dec.take().unwrap(), data);
    }

    #[test]
    fn decodes_after_heavy_loss_using_repair() {
        // Drop 30% of source symbols, backfill with repair symbols.
        let data = payload(300_000);
        let enc = BlockEncoder::new(&data, SYM).unwrap();
        let mut dec = BlockDecoder::new(&enc.oti(), data.len()).unwrap();

        let source = enc.source_symbols();
        let mut delivered = 0;
        for (i, s) in source.iter().enumerate() {
            if i % 10 < 3 {
                continue; // "lost" in the network
            }
            delivered += 1;
            let _ = dec.push(s).unwrap();
        }
        assert!(
            !dec.is_complete(),
            "should still need repair after 30% loss"
        );

        // Repair symbols are generated on demand, none precomputed.
        for s in enc.repair_symbols(0, source.len() as u32) {
            delivered += 1;
            if dec.push(&s).unwrap() {
                break;
            }
        }
        assert!(dec.is_complete());
        assert_eq!(dec.take().unwrap(), data);
        // Overhead should be near the information-theoretic floor.
        assert!(
            delivered < source.len() * 2,
            "used {} symbols for {} source symbols",
            delivered,
            source.len()
        );
    }

    #[test]
    fn decodes_from_repair_symbols_only() {
        // The extreme: every source symbol lost. A fountain code still wins.
        let data = payload(120_000);
        let enc = BlockEncoder::new(&data, SYM).unwrap();
        let mut dec = BlockDecoder::new(&enc.oti(), data.len()).unwrap();

        let need = enc.source_symbol_count();
        for s in enc.repair_symbols(0, need * 2) {
            if dec.push(&s).unwrap() {
                break;
            }
        }
        assert!(dec.is_complete());
        assert_eq!(dec.take().unwrap(), data);
    }

    #[test]
    fn out_of_order_delivery_decodes() {
        let data = payload(150_000);
        let enc = BlockEncoder::new(&data, SYM).unwrap();
        let mut dec = BlockDecoder::new(&enc.oti(), data.len()).unwrap();

        let mut symbols = enc.source_symbols();
        symbols.reverse();
        for s in &symbols {
            let _ = dec.push(s).unwrap();
        }
        assert!(dec.is_complete());
        assert_eq!(dec.take().unwrap(), data);
    }

    #[test]
    fn duplicate_symbols_are_harmless() {
        let data = payload(80_000);
        let enc = BlockEncoder::new(&data, SYM).unwrap();
        let mut dec = BlockDecoder::new(&enc.oti(), data.len()).unwrap();

        for s in enc.source_symbols() {
            let _ = dec.push(&s).unwrap();
            let _ = dec.push(&s).unwrap(); // network duplication
        }
        assert!(dec.is_complete());
        assert_eq!(dec.take().unwrap(), data);
    }

    #[test]
    fn insufficient_symbols_do_not_decode() {
        // Fail closed: too few symbols must yield nothing, not partial data.
        let data = payload(200_000);
        let enc = BlockEncoder::new(&data, SYM).unwrap();
        let mut dec = BlockDecoder::new(&enc.oti(), data.len()).unwrap();

        let source = enc.source_symbols();
        for s in source.iter().take(source.len() / 2) {
            let _ = dec.push(s).unwrap();
        }
        assert!(!dec.is_complete());
        assert!(dec.take().is_none());
    }

    #[test]
    fn successive_repair_rounds_yield_new_symbols() {
        // Round N must not resend round N-1's symbols, or a lossy link would
        // never converge.
        let data = payload(50_000);
        let enc = BlockEncoder::new(&data, SYM).unwrap();
        let first = enc.repair_symbols(0, 20);
        let second = enc.repair_symbols(20, 20);
        assert_eq!(first.len(), 20);
        assert_eq!(second.len(), 20);
        for s in &second {
            assert!(!first.contains(s), "repair round 2 resent a round-1 symbol");
        }
    }

    #[test]
    fn repair_generation_is_deterministic() {
        // Same range, same symbols — required for a retransmit to be idempotent.
        let data = payload(40_000);
        let enc = BlockEncoder::new(&data, SYM).unwrap();
        assert_eq!(enc.repair_symbols(5, 10), enc.repair_symbols(5, 10));
        assert!(enc.repair_symbols(0, 0).is_empty());
    }

    #[test]
    fn single_byte_and_sub_symbol_blocks() {
        for len in [1usize, 2, SYM as usize - 1, SYM as usize, SYM as usize + 1] {
            let data = payload(len);
            let enc = BlockEncoder::new(&data, SYM).unwrap();
            let mut dec = BlockDecoder::new(&enc.oti(), len).unwrap();
            for s in enc.source_symbols() {
                if dec.push(&s).unwrap() {
                    break;
                }
            }
            for s in enc.repair_symbols(0, 8) {
                if dec.is_complete() {
                    break;
                }
                let _ = dec.push(&s).unwrap();
            }
            assert!(dec.is_complete(), "len {} did not decode", len);
            assert_eq!(dec.take().unwrap(), data, "len {} mismatched", len);
        }
    }

    #[test]
    fn oti_round_trips_through_the_wire_form() {
        let data = payload(90_000);
        let enc = BlockEncoder::new(&data, SYM).unwrap();
        let wire: Oti = enc.oti();
        let dec = BlockDecoder::new(&wire, data.len()).unwrap();
        assert!(!dec.is_complete());
    }

    #[test]
    fn decoder_rejects_mismatched_length() {
        let data = payload(10_000);
        let enc = BlockEncoder::new(&data, SYM).unwrap();
        // A peer claiming a different block length must be refused up front.
        assert!(BlockDecoder::new(&enc.oti(), data.len() + 1).is_err());
    }

    #[test]
    fn decoder_rejects_runt_symbols() {
        let data = payload(10_000);
        let enc = BlockEncoder::new(&data, SYM).unwrap();
        let mut dec = BlockDecoder::new(&enc.oti(), data.len()).unwrap();
        // Must not panic on a short/garbage payload.
        assert!(dec.push(&[]).is_err());
        assert!(dec.push(&[1, 2, 3, 4]).is_err());
    }

    #[test]
    fn empty_or_oversized_blocks_are_refused() {
        assert!(BlockEncoder::new(&[], SYM).is_err());
        assert!(oti_for_block(1024, 0).is_err());
        // 8 MiB at a 16-byte symbol size needs > 56403 symbols.
        assert!(oti_for_block(8 * 1024 * 1024, 16).is_err());
        // The real configuration must fit comfortably.
        assert!(oti_for_block(DEFAULT_BLOCK_SIZE, SYM).is_ok());
    }
}
