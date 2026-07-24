//! Block scheduler — the loop that actually moves a file over the data plane.
//!
//! The sender sprays symbols for a window of blocks without waiting for
//! anything, and reacts to feedback as it arrives. The receiver decodes blocks
//! as symbols land and reports each one complete. Neither side blocks on the
//! other except to bound memory.
//!
//! ## Why a window rather than a round trip per block
//!
//! The obvious design — send a block, wait for an ack, send the next — costs
//! one RTT per block. On the 200 ms path this data plane exists to serve, a
//! 500 MB file in 8 MiB blocks would spend 63 round trips, roughly 13 seconds,
//! doing nothing but waiting. Keeping `window` blocks in flight hides that
//! latency behind useful transmission, which is the whole reason to pipeline.
//!
//! ## Bounded memory
//!
//! Only `window` block encoders exist at once, and each is dropped as soon as
//! its block is acknowledged. Repair symbols are generated on demand and never
//! pooled. Sender working set is therefore `window × block_size` — about
//! 32 MiB at the defaults — regardless of file size or how lossy the path is.
//!
//! ## Feedback is advisory, completion is not
//!
//! `NeedMore` only influences how many repair symbols to generate. The
//! transfer completes when every block has decoded *and verified*, so lost or
//! delayed feedback costs throughput, never correctness.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::error::{AftError, AftResult};

use super::codec::{block_count, block_range, BlockDecoder, BlockEncoder};
use super::pacing::{repair_symbol_count, Pacer};

/// Blocks in flight at once. Four 8 MiB blocks keeps a 1 Gbit × 200 ms path
/// (a 25 MB BDP) fed while capping the working set at 32 MiB.
pub const DEFAULT_WINDOW: usize = 4;

/// Give up on a block after this many repair rounds. A path that cannot land
/// a block in this many attempts is broken, not merely lossy, and we should
/// surface that rather than spray forever.
pub const MAX_REPAIR_ROUNDS: u32 = 32;

/// How long the receiver waits without progress on a block before asking for
/// more symbols, as a multiple of the estimated RTT.
const NEEDMORE_RTT_MULTIPLE: u32 = 2;

/// Floor on the receiver's patience, so a low RTT estimate cannot cause a
/// feedback storm.
const MIN_NEEDMORE_DELAY: Duration = Duration::from_millis(50);

/// Ceiling on the receiver's patience. Adaptation can only slow the ask rate
/// down to here, so a dead link is still detected in bounded time. Kept tight:
/// feedback is also what drives the sender's pacer, so an over-patient
/// receiver starves the sender of rate samples on exactly the slow links
/// where overshooting hurts most. 1 s covers a 500 ms RTT path — beyond
/// satellite — while still asking a few times per repair round.
const MAX_NEEDMORE_DELAY: Duration = Duration::from_secs(1);

/// Negotiated parameters, shared by both ends.
#[derive(Debug, Clone)]
pub struct FecParams {
    pub session_id: u64,
    pub total_len: u64,
    pub block_size: usize,
    pub symbol_size: u16,
    pub window: usize,
    /// Loss rate hint used to size the first repair round, before any
    /// measurement exists. Zero means "assume clean and let feedback correct
    /// us", which is right for a LAN and merely costs one round trip on a
    /// lossy path.
    pub initial_loss_hint: f64,
}

impl FecParams {
    pub fn block_count(&self) -> u32 {
        block_count(self.total_len, self.block_size)
    }

    pub fn block_len(&self, block_id: u32) -> usize {
        let (s, e) = block_range(block_id, self.block_size, self.total_len);
        (e - s) as usize
    }
}

/// Receiver → sender messages, carried on the reliable control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feedback {
    /// A block is short by roughly this many symbols.
    NeedMore {
        block_id: u32,
        symbols_needed: u32,
        symbols_received: u32,
    },
    /// A block decoded and verified; its buffers can be released.
    BlockOk { block_id: u32, symbols_used: u32 },
}

/// Where symbols go. Implemented by the UDP data plane, and by test doubles
/// that drop symbols deterministically.
#[async_trait::async_trait]
pub trait SymbolSink: Send + Sync {
    async fn send_symbol(&self, block_id: u32, symbol: &[u8]) -> AftResult<()>;
}

/// Where symbols come from. Yields `None` for a datagram that failed
/// verification, which the caller should ignore rather than treat as an error.
#[async_trait::async_trait]
pub trait SymbolSource: Send + Sync {
    async fn recv_symbol(&self) -> AftResult<Option<(u32, Vec<u8>)>>;
}

#[async_trait::async_trait]
impl SymbolSink for super::udp::DataPlane {
    async fn send_symbol(&self, block_id: u32, symbol: &[u8]) -> AftResult<()> {
        self.send(block_id, self.session_id(), symbol).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SymbolSource for super::udp::DataPlane {
    async fn recv_symbol(&self) -> AftResult<Option<(u32, Vec<u8>)>> {
        Ok(self
            .recv(self.session_id())
            .await?
            .map(|(block_id, payload, _)| (block_id, payload)))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SendStats {
    pub symbols_sent: u64,
    pub bytes_sent: u64,
    pub repair_rounds: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RecvStats {
    pub symbols_accepted: u64,
    pub symbols_rejected: u64,
}

/// Supplies block bytes to the sender on demand.
///
/// The scheduler only ever holds the `window` blocks currently in flight, so a
/// file-backed reader keeps sender memory at `window × block_size` no matter
/// how large the file is. That is the difference between a 5 GB transfer
/// costing 32 MiB and costing 5 GB.
#[async_trait::async_trait]
pub trait BlockReader: Send + Sync {
    async fn read_block(&self, start: u64, len: usize) -> AftResult<Vec<u8>>;
}

/// Serves blocks from a buffer already in memory.
pub struct SliceBlocks<'a>(pub &'a [u8]);

#[async_trait::async_trait]
impl BlockReader for SliceBlocks<'_> {
    async fn read_block(&self, start: u64, len: usize) -> AftResult<Vec<u8>> {
        let start = start as usize;
        let end = start
            .checked_add(len)
            .filter(|e| *e <= self.0.len())
            .ok_or_else(|| AftError::Other("FEC block range out of bounds".into()))?;
        Ok(self.0[start..end].to_vec())
    }
}

/// Serves blocks by seeking into a file, one block at a time.
pub struct FileBlocks {
    path: std::path::PathBuf,
    /// Offset of the object within the file, for ranged transfers.
    base: u64,
}

impl FileBlocks {
    pub fn new(path: impl Into<std::path::PathBuf>, base: u64) -> Self {
        Self {
            path: path.into(),
            base,
        }
    }
}

#[async_trait::async_trait]
impl BlockReader for FileBlocks {
    async fn read_block(&self, start: u64, len: usize) -> AftResult<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut f = tokio::fs::File::open(&self.path).await?;
        f.seek(std::io::SeekFrom::Start(self.base + start)).await?;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

/// Receives decoded blocks.
///
/// Blocks decode independently and out of order, so the receiver is handed
/// each one with its absolute offset. Writing straight through to a
/// pre-allocated file keeps receiver memory bounded by the decoder working
/// set rather than by the size of the transfer — the mirror of what
/// [`BlockReader`] does for the sender.
#[async_trait::async_trait]
pub trait BlockWriter: Send + Sync {
    async fn write_block(&mut self, offset: u64, data: &[u8]) -> AftResult<()>;
}

/// Collects blocks into memory. Convenient for small objects and tests.
#[derive(Default)]
pub struct VecBlocks {
    pub buf: Vec<u8>,
}

impl VecBlocks {
    pub fn with_len(len: usize) -> Self {
        Self { buf: vec![0u8; len] }
    }
}

#[async_trait::async_trait]
impl BlockWriter for VecBlocks {
    async fn write_block(&mut self, offset: u64, data: &[u8]) -> AftResult<()> {
        let start = offset as usize;
        let end = start
            .checked_add(data.len())
            .filter(|e| *e <= self.buf.len())
            .ok_or_else(|| AftError::Other("FEC block write out of bounds".into()))?;
        self.buf[start..end].copy_from_slice(data);
        Ok(())
    }
}

/// Writes blocks to a file at their absolute offsets.
pub struct FileBlockWriter {
    file: tokio::fs::File,
}

impl FileBlockWriter {
    /// Create (or truncate) `path` and pre-allocate it to `len`, so
    /// out-of-order block writes always land inside the file.
    pub async fn create(path: &std::path::Path, len: u64) -> AftResult<Self> {
        let file = tokio::fs::File::create(path).await?;
        file.set_len(len).await?;
        Ok(Self { file })
    }

    pub async fn finish(mut self) -> AftResult<()> {
        use tokio::io::AsyncWriteExt;
        self.file.flush().await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl BlockWriter for FileBlockWriter {
    async fn write_block(&mut self, offset: u64, data: &[u8]) -> AftResult<()> {
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};
        self.file.seek(std::io::SeekFrom::Start(offset)).await?;
        self.file.write_all(data).await?;
        Ok(())
    }
}

/// State the sender keeps for one in-flight block.
struct InFlight {
    encoder: BlockEncoder,
    /// Next unused repair symbol id — never rewound, so successive rounds
    /// always produce symbols the receiver has not seen.
    repair_cursor: u32,
    rounds: u32,
    /// When this block's first symbol went out. Feedback for the block turns
    /// this into a delivery-rate sample for the pacer: symbols delivered over
    /// the time since the spray began is the path's goodput, queueing and
    /// loss included.
    spray_started: Instant,
    /// When this block's most recent symbol went out. The gap from here to a
    /// `BlockOk` arriving approximates one round trip.
    last_sent: Instant,
    /// When feedback for this block last arrived, and the receiver's symbol
    /// count at that moment. Delivery-rate samples are the *delta* between
    /// consecutive feedback events — a lifetime average would keep shrinking
    /// for a block that lingers, poisoning the bandwidth filter with
    /// ever-lower samples and collapsing the send rate in a spiral the
    /// transfer never escapes.
    feedback_at: Instant,
    feedback_symbols: u32,
    /// True while the block's initial spray (source + proactive repair) is
    /// still going out. A `NeedMore` that arrives mid-spray is a progress
    /// report, not a repair request: the receiver cannot know what is still
    /// in flight, and our own sent-count is not yet meaningful for loss
    /// measurement.
    spraying: bool,
}

/// Send an in-memory buffer over the data plane.
pub async fn send_object(
    data: &[u8],
    sink: &dyn SymbolSink,
    feedback: &mut mpsc::Receiver<Feedback>,
    params: &FecParams,
) -> AftResult<SendStats> {
    if data.len() as u64 != params.total_len {
        return Err(AftError::Other(format!(
            "FEC send: {} bytes of data but params declare {}",
            data.len(),
            params.total_len
        )));
    }
    send_blocks(&SliceBlocks(data), sink, feedback, params).await
}

/// Send an object over the data plane, reacting to feedback until every block
/// is acknowledged. Blocks are pulled from `reader` as the window opens.
pub async fn send_blocks(
    reader: &dyn BlockReader,
    sink: &dyn SymbolSink,
    feedback: &mut mpsc::Receiver<Feedback>,
    params: &FecParams,
) -> AftResult<SendStats> {
    let total_blocks = params.block_count();
    let window = params.window.max(1);
    let mut pacer = Pacer::new();
    let mut stats = SendStats::default();

    let mut inflight: HashMap<u32, InFlight> = HashMap::new();
    let mut next_block: u32 = 0;
    let mut acked: u32 = 0;
    let mut loss_hint = params.initial_loss_hint;

    while acked < total_blocks {
        // Absorb any feedback that has arrived without blocking. Doing this
        // first keeps the window as open as possible before we consider
        // sending more.
        while let Ok(msg) = feedback.try_recv() {
            apply_feedback(
                msg,
                &mut inflight,
                &mut acked,
                &mut loss_hint,
                params.symbol_size,
                sink,
                &mut pacer,
                &mut stats,
            )
            .await?;
        }

        // The drain above can complete the transfer. Re-check before doing
        // anything that blocks: the receiver drops its feedback sender the
        // instant the last block lands, so a blocking read here would observe
        // a closed channel and report failure on a transfer that succeeded.
        if acked >= total_blocks {
            break;
        }

        // Retire anything that has exhausted its repair budget.
        if let Some(&stuck) = inflight
            .iter()
            .find(|(_, f)| f.rounds > MAX_REPAIR_ROUNDS)
            .map(|(id, _)| id)
        {
            return Err(AftError::TransferFailed(format!(
                "FEC block {} did not converge after {} repair rounds",
                stuck, MAX_REPAIR_ROUNDS
            )));
        }

        // Open the window if we can.
        if inflight.len() < window && next_block < total_blocks {
            let block_id = next_block;
            next_block += 1;

            let (start, end) = block_range(block_id, params.block_size, params.total_len);
            let block = reader.read_block(start, (end - start) as usize).await?;
            let encoder = BlockEncoder::new(&block, params.symbol_size)?;
            let spray_started = Instant::now();

            // Systematic symbols first: on a clean path these *are* the data
            // and the receiver reassembles with no algebraic decoding at all.
            let source = encoder.source_symbols();
            let src_count = encoder.source_symbol_count();

            // Registered before spraying so feedback arriving mid-spray finds
            // the block and can feed the pacer.
            inflight.insert(
                block_id,
                InFlight {
                    encoder,
                    repair_cursor: 0,
                    rounds: 0,
                    spray_started,
                    last_sent: Instant::now(),
                    feedback_at: spray_started,
                    feedback_symbols: 0,
                    spraying: true,
                },
            );

            for symbol in &source {
                // Startup guard: until the pacer has a real delivery sample
                // its rate is a guess, and a guess 10× over a slow link's
                // capacity floods the bottleneck queue for seconds and
                // poisons the first loss measurements with self-induced
                // drops. Cap what we send on faith; the receiver's patience
                // timer guarantees a NeedMore (which carries a received
                // count, i.e. a delivery sample) even at total loss, so this
                // cannot deadlock.
                while !pacer.sampled() && stats.bytes_sent >= Pacer::unsampled_allowance() {
                    match feedback.recv().await {
                        Some(msg) => {
                            apply_feedback(
                                msg,
                                &mut inflight,
                                &mut acked,
                                &mut loss_hint,
                                params.symbol_size,
                                sink,
                                &mut pacer,
                                &mut stats,
                            )
                            .await?
                        }
                        None => {
                            return Err(AftError::TransferFailed(
                                "FEC control plane closed during startup".into(),
                            ))
                        }
                    }
                }
                pace_and_send(sink, block_id, symbol, &mut pacer, &mut stats).await?;
            }

            // Proactive repair, sized to the loss we currently believe in.
            let repair_n = repair_symbol_count(src_count, loss_hint);
            if repair_n > 0 {
                let symbols = match inflight.get_mut(&block_id) {
                    Some(f) => {
                        f.repair_cursor = repair_n;
                        f.encoder.repair_symbols(0, repair_n)
                    }
                    // Decoded from the source spray alone before we got here.
                    None => Vec::new(),
                };
                for symbol in &symbols {
                    pace_and_send(sink, block_id, symbol, &mut pacer, &mut stats).await?;
                }
            }

            if let Some(f) = inflight.get_mut(&block_id) {
                f.spraying = false;
                f.last_sent = Instant::now();
            }
            continue;
        }

        // Window is full or everything is sent: block until feedback moves us.
        match feedback.recv().await {
            Some(msg) => {
                apply_feedback(
                    msg,
                    &mut inflight,
                    &mut acked,
                    &mut loss_hint,
                    params.symbol_size,
                    sink,
                    &mut pacer,
                    &mut stats,
                )
                .await?
            }
            None => {
                return Err(AftError::TransferFailed(format!(
                    "FEC control plane closed with {}/{} blocks acknowledged",
                    acked, total_blocks
                )))
            }
        }
    }

    Ok(stats)
}

// Eight parameters, because this drives the whole in-flight state machine from
// one feedback message: the block table, the ack counter, the loss estimate,
// the pacer, and the stats all move together. Bundling them into a struct would
// obscure rather than clarify the borrows.
#[allow(clippy::too_many_arguments)]
async fn apply_feedback(
    msg: Feedback,
    inflight: &mut HashMap<u32, InFlight>,
    acked: &mut u32,
    loss_hint: &mut f64,
    symbol_size: u16,
    sink: &dyn SymbolSink,
    pacer: &mut Pacer,
    stats: &mut SendStats,
) -> AftResult<()> {
    match msg {
        Feedback::BlockOk {
            block_id,
            symbols_used,
        } => {
            // Dropping the encoder here is what bounds sender memory.
            if let Some(f) = inflight.remove(&block_id) {
                *acked += 1;

                // Feed the pacer: symbols delivered since this block's last
                // feedback event, over the time since that event, is a
                // delivery-rate sample — and the gap since our last send of
                // this block approximates one RTT. Without these samples the
                // BBR filters never move and the pacer free-runs at its
                // initial guess, flooding slow links.
                let delta = symbols_used.saturating_sub(f.feedback_symbols);
                pacer.on_sample(
                    delta as u64 * symbol_size as u64,
                    f.feedback_at.elapsed(),
                    f.last_sent.elapsed(),
                );

                // A block that decoded without ever asking for repair means
                // the proactive overhead was sufficient — likely excessive.
                // Decay the loss estimate so it can find its way back down;
                // NeedMore is the only signal that pushes it up, and once we
                // overshoot hard enough NeedMore stops happening, which would
                // otherwise lock the estimate at its peak forever.
                if f.rounds == 0 {
                    *loss_hint *= 0.7;
                }
            }
        }
        Feedback::NeedMore {
            block_id,
            symbols_needed,
            symbols_received,
        } => {
            let Some(f) = inflight.get_mut(&block_id) else {
                // Feedback for a block already acknowledged — a duplicate or a
                // reordered frame. Harmless.
                return Ok(());
            };

            // A delivery-rate sample for the pacer: what arrived since this
            // block's previous feedback event. No RTT estimate here: a
            // NeedMore only fires after the receiver's patience elapsed, so
            // its timing measures our silence, not the path.
            let delta = symbols_received.saturating_sub(f.feedback_symbols);
            pacer.on_sample(
                delta as u64 * symbol_size as u64,
                f.feedback_at.elapsed(),
                Duration::ZERO,
            );
            f.feedback_at = Instant::now();
            f.feedback_symbols = symbols_received.max(f.feedback_symbols);

            // Mid-spray, that sample is all this message is good for. The
            // receiver is reporting on a spray we have not finished — what it
            // "still needs" is largely in flight, our sent-count would wildly
            // overstate the loss rate, and repair now would duplicate what
            // the tail of the spray already covers.
            if f.spraying {
                return Ok(());
            }

            // The receiver tells us how many it got; we know how many we sent.
            // The shortfall is a direct measurement of the path's loss rate,
            // which sizes this and every subsequent block's repair.
            let sent = f.encoder.source_symbol_count() + f.repair_cursor;
            if sent > 0 && symbols_received <= sent {
                let observed = 1.0 - (symbols_received as f64 / sent as f64);
                // Smooth it: one sample should nudge the estimate, not replace it.
                *loss_hint = (*loss_hint * 0.7 + observed.clamp(0.0, 0.9) * 0.3).clamp(0.0, 0.9);
            }

            // Overshoot the request: another round trip costs far more than a
            // few redundant symbols.
            let extra = ((symbols_needed as f64) * 1.5).ceil() as u32;
            let extra = extra.max(1);

            let symbols = f.encoder.repair_symbols(f.repair_cursor, extra);
            f.repair_cursor += extra;
            f.rounds += 1;
            stats.repair_rounds += 1;

            for symbol in &symbols {
                pace_and_send(sink, block_id, symbol, pacer, stats).await?;
            }
            f.last_sent = Instant::now();
        }
    }
    Ok(())
}

async fn pace_and_send(
    sink: &dyn SymbolSink,
    block_id: u32,
    symbol: &[u8],
    pacer: &mut Pacer,
    stats: &mut SendStats,
) -> AftResult<()> {
    let delay = pacer.acquire(symbol.len() as u64);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    sink.send_symbol(block_id, symbol).await?;
    stats.symbols_sent += 1;
    stats.bytes_sent += symbol.len() as u64;
    Ok(())
}

/// Receive an object into memory, emitting feedback as blocks complete.
///
/// Convenience wrapper over [`recv_object_into`] for small objects. Prefer
/// the streaming form for anything large.
pub async fn recv_object(
    source: &dyn SymbolSource,
    feedback: &mpsc::Sender<Feedback>,
    params: &FecParams,
    rtt_estimate: Duration,
) -> AftResult<(Vec<u8>, RecvStats)> {
    let mut sink = VecBlocks::with_len(params.total_len as usize);
    let stats = recv_object_into(source, &mut sink, feedback, params, rtt_estimate).await?;
    Ok((sink.buf, stats))
}

/// Receive an object, writing each block to `out` as it decodes.
///
/// Blocks are handed off the moment they verify, so nothing accumulates: peak
/// memory is the decoder working set for the blocks currently in flight, not
/// the size of the transfer.
pub async fn recv_object_into(
    source: &dyn SymbolSource,
    out: &mut dyn BlockWriter,
    feedback: &mpsc::Sender<Feedback>,
    params: &FecParams,
    rtt_estimate: Duration,
) -> AftResult<RecvStats> {
    let total_blocks = params.block_count();
    let mut decoders: HashMap<u32, BlockDecoder> = HashMap::new();
    let mut done: HashMap<u32, bool> = HashMap::new();
    let mut stats = RecvStats::default();
    let mut completed: u32 = 0;

    // `rtt_estimate` is only a starting point — neither end measures the path
    // before the transfer starts. Patience adapts from two live signals below:
    // a fruitless NeedMore round (timeout → ask → timeout with nothing in
    // between) doubles it, and the gap between sending a NeedMore and the
    // first symbol that follows is a genuine RTT sample that ratchets it up.
    // Without this, a low initial guess on a high-RTT link asks for repair
    // before the answer to the previous ask can possibly arrive, and the
    // redundant repair traffic floods exactly the links that need FEC most.
    let mut patience = (rtt_estimate * NEEDMORE_RTT_MULTIPLE).max(MIN_NEEDMORE_DELAY);
    let mut last_progress = Instant::now();
    // Set when a NeedMore round is sent; cleared by the next accepted symbol.
    let mut needmore_sent_at: Option<Instant> = None;

    while completed < total_blocks {
        let symbol = tokio::time::timeout(patience, source.recv_symbol()).await;

        match symbol {
            Ok(Ok(Some((block_id, payload)))) => {
                if block_id >= total_blocks {
                    stats.symbols_rejected += 1;
                    continue;
                }
                if *done.get(&block_id).unwrap_or(&false) {
                    // Already complete; the sender has not yet seen our ack.
                    continue;
                }

                // Bound the working set: a well-behaved sender keeps only
                // `window` blocks in flight, so never needs more than that many
                // decoders (~8 MiB each). A malicious sender could otherwise
                // spray one symbol across thousands of distinct block ids and
                // force us to allocate a decoder for each. Refuse to open a new
                // decoder past the window; the dropped symbol is simply resent
                // by the fountain, so a legitimate sender loses nothing.
                let max_decoders = params.window.max(1);
                if !decoders.contains_key(&block_id) && decoders.len() >= max_decoders {
                    stats.symbols_rejected += 1;
                    continue;
                }

                let expected_len = params.block_len(block_id);
                let decoder = match decoders.entry(block_id) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        // Both ends derive the OTI from the same negotiated
                        // parameters, so it never has to cross the wire per
                        // block — one fewer thing an attacker can influence.
                        let oti = super::codec::oti_for_block(expected_len, params.symbol_size)?
                            .serialize();
                        e.insert(BlockDecoder::new(&oti, expected_len)?)
                    }
                };

                match decoder.push(&payload) {
                    Ok(complete) => {
                        stats.symbols_accepted += 1;
                        last_progress = Instant::now();
                        if let Some(asked_at) = needmore_sent_at.take() {
                            // First symbol after a quiet-period ask: the gap is
                            // an RTT sample (ask travels there, symbol travels
                            // back). It can only under-measure — a symbol
                            // already in flight arrives sooner — so it is safe
                            // to ratchet patience up from it, never down.
                            let sample = asked_at.elapsed();
                            patience = patience
                                .max(sample * NEEDMORE_RTT_MULTIPLE)
                                .min(MAX_NEEDMORE_DELAY);
                        }
                        if complete {
                            let symbols_used = decoder.symbols_accepted();
                            let block = decoder
                                .take()
                                .ok_or_else(|| AftError::Other("FEC block vanished".into()))?;
                            let (start, _) =
                                block_range(block_id, params.block_size, params.total_len);
                            out.write_block(start, &block).await?;

                            // Dropping the decoder here is what bounds
                            // receiver memory.
                            decoders.remove(&block_id);
                            done.insert(block_id, true);
                            completed += 1;

                            let _ = feedback
                                .send(Feedback::BlockOk {
                                    block_id,
                                    symbols_used,
                                })
                                .await;
                        }
                    }
                    Err(_) => {
                        // A malformed symbol is not fatal: drop it and wait for
                        // one of the many others the sender is spraying.
                        stats.symbols_rejected += 1;
                    }
                }
            }
            // Verification failure — already counted as a drop by the source.
            Ok(Ok(None)) => stats.symbols_rejected += 1,
            Ok(Err(e)) => return Err(e),
            Err(_elapsed) => {
                // Nothing arrived for a while. Ask for more on every block we
                // are still waiting on.
                if last_progress.elapsed() >= patience {
                    if needmore_sent_at.is_some() {
                        // The previous ask produced nothing before we timed out
                        // again: our patience is shorter than the real path RTT
                        // (or the link is dying). Back off exponentially so we
                        // stop asking faster than answers can arrive.
                        patience = (patience * 2).min(MAX_NEEDMORE_DELAY);
                    }
                    request_more(&decoders, &done, params, total_blocks, feedback).await;
                    needmore_sent_at = Some(Instant::now());
                    last_progress = Instant::now();
                }
            }
        }
    }

    Ok(stats)
}

/// Ask the sender for more symbols on every incomplete block.
async fn request_more(
    decoders: &HashMap<u32, BlockDecoder>,
    done: &HashMap<u32, bool>,
    params: &FecParams,
    total_blocks: u32,
    feedback: &mpsc::Sender<Feedback>,
) {
    for block_id in 0..total_blocks {
        if *done.get(&block_id).unwrap_or(&false) {
            continue;
        }
        let expected_len = params.block_len(block_id);
        let needed_total = (expected_len as u64).div_ceil(params.symbol_size as u64) as u32;

        let (received, still_needed) = match decoders.get(&block_id) {
            Some(d) => {
                let got = d.symbols_accepted();
                (got, needed_total.saturating_sub(got).max(1))
            }
            // Nothing at all has arrived for this block yet.
            None => (0, needed_total),
        };

        let _ = feedback
            .send(Feedback::NeedMore {
                block_id,
                symbols_needed: still_needed,
                symbols_received: received,
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// An in-memory data plane that drops every Nth symbol, so loss behavior
    /// is deterministic and reproducible rather than dependent on a real
    /// lossy network.
    struct LossyLink {
        tx: mpsc::UnboundedSender<(u32, Vec<u8>)>,
        rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(u32, Vec<u8>)>>,
        counter: AtomicU64,
        /// Drop one symbol in every `drop_one_in`; 0 disables loss.
        drop_one_in: u64,
        sent: AtomicU64,
        dropped: AtomicU64,
    }

    impl LossyLink {
        fn new(drop_one_in: u64) -> Arc<Self> {
            let (tx, rx) = mpsc::unbounded_channel();
            Arc::new(Self {
                tx,
                rx: tokio::sync::Mutex::new(rx),
                counter: AtomicU64::new(0),
                drop_one_in,
                sent: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl SymbolSink for LossyLink {
        async fn send_symbol(&self, block_id: u32, symbol: &[u8]) -> AftResult<()> {
            let n = self.counter.fetch_add(1, Ordering::Relaxed);
            if self.drop_one_in > 0 && n % self.drop_one_in == 0 {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return Ok(()); // silently lost, exactly like a real drop
            }
            self.sent.fetch_add(1, Ordering::Relaxed);
            let _ = self.tx.send((block_id, symbol.to_vec()));
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl SymbolSource for LossyLink {
        async fn recv_symbol(&self) -> AftResult<Option<(u32, Vec<u8>)>> {
            let mut rx = self.rx.lock().await;
            Ok(rx.recv().await)
        }
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect()
    }

    fn params(total_len: u64, block_size: usize) -> FecParams {
        FecParams {
            session_id: 0xABCD,
            total_len,
            block_size,
            symbol_size: 1362,
            window: DEFAULT_WINDOW,
            initial_loss_hint: 0.0,
        }
    }

    /// Drive a full transfer over a link with the given loss, returning the
    /// reassembled bytes and both sides' stats.
    async fn run_transfer(
        data: &[u8],
        block_size: usize,
        drop_one_in: u64,
        initial_loss_hint: f64,
    ) -> (Vec<u8>, SendStats, RecvStats) {
        let link = LossyLink::new(drop_one_in);
        let mut p = params(data.len() as u64, block_size);
        p.initial_loss_hint = initial_loss_hint;

        let (fb_tx, mut fb_rx) = mpsc::channel::<Feedback>(1024);

        let send_link = link.clone();
        let send_params = p.clone();
        let data_owned = data.to_vec();
        let sender = tokio::spawn(async move {
            send_object(&data_owned, send_link.as_ref(), &mut fb_rx, &send_params).await
        });

        let recv_link = link.clone();
        let recv_params = p.clone();
        let receiver = tokio::spawn(async move {
            recv_object(
                recv_link.as_ref(),
                &fb_tx,
                &recv_params,
                Duration::from_millis(5),
            )
            .await
        });

        let (out, rstats) = receiver.await.unwrap().expect("receive failed");
        let sstats = sender.await.unwrap().expect("send failed");
        (out, sstats, rstats)
    }

    #[tokio::test]
    async fn clean_link_transfers_exactly() {
        let data = payload(300_000);
        let (out, _, _) = run_transfer(&data, 100_000, 0, 0.0).await;
        assert_eq!(out, data);
    }

    /// On a clean link the systematic symbols alone should suffice — no repair
    /// symbols and no feedback rounds. This is the fast path that keeps a
    /// perfect link as cheap as a plain copy.
    #[tokio::test]
    async fn clean_link_sends_no_repair_symbols() {
        let data = payload(200_000);
        let (out, sstats, _) = run_transfer(&data, 100_000, 0, 0.0).await;
        assert_eq!(out, data);
        assert_eq!(sstats.repair_rounds, 0, "clean link should need no repair");

        let source_symbols = (data.len() as u64).div_ceil(1362);
        // Allow a small margin for per-block symbol rounding.
        assert!(
            sstats.symbols_sent <= source_symbols + 4,
            "sent {} symbols for {} source symbols",
            sstats.symbols_sent,
            source_symbols
        );
    }

    #[tokio::test]
    async fn recovers_from_ten_percent_loss() {
        let data = payload(400_000);
        let (out, _, _) = run_transfer(&data, 100_000, 10, 0.0).await;
        assert_eq!(out, data, "10% loss must still reconstruct exactly");
    }

    #[tokio::test]
    async fn recovers_from_thirty_percent_loss() {
        let data = payload(300_000);
        let (out, _, _) = run_transfer(&data, 100_000, 3, 0.0).await;
        assert_eq!(out, data, "30% loss must still reconstruct exactly");
    }

    /// A loss hint should let the first round carry enough repair to avoid
    /// feedback entirely — trading a few redundant symbols for a saved RTT.
    #[tokio::test]
    async fn loss_hint_avoids_feedback_rounds() {
        let data = payload(200_000);
        let (out, hinted, _) = run_transfer(&data, 100_000, 10, 0.15).await;
        assert_eq!(out, data);

        let (out2, unhinted, _) = run_transfer(&data, 100_000, 10, 0.0).await;
        assert_eq!(out2, data);

        assert!(
            hinted.repair_rounds <= unhinted.repair_rounds,
            "hinted transfer used {} rounds vs unhinted {}",
            hinted.repair_rounds,
            unhinted.repair_rounds
        );
    }

    #[tokio::test]
    async fn multi_block_transfer_reassembles_in_order() {
        // 10 blocks — ordering bugs would show up as a scrambled result.
        let data = payload(1_000_000);
        let (out, _, _) = run_transfer(&data, 100_000, 0, 0.0).await;
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn window_bounds_blocks_in_flight() {
        // More blocks than the window: the scheduler must still complete.
        let data = payload(1_200_000);
        let mut p = params(data.len() as u64, 100_000);
        p.window = 2;
        assert!(p.block_count() > p.window as u32);

        let link = LossyLink::new(0);
        let (fb_tx, mut fb_rx) = mpsc::channel::<Feedback>(1024);
        let sl = link.clone();
        let sp = p.clone();
        let d = data.clone();
        let sender =
            tokio::spawn(async move { send_object(&d, sl.as_ref(), &mut fb_rx, &sp).await });
        let rl = link.clone();
        let rp = p.clone();
        let receiver = tokio::spawn(async move {
            recv_object(rl.as_ref(), &fb_tx, &rp, Duration::from_millis(5)).await
        });

        let (out, _) = receiver.await.unwrap().unwrap();
        sender.await.unwrap().unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn odd_sizes_round_trip() {
        // Partial final block, and a file smaller than one symbol.
        for len in [1usize, 1361, 1362, 1363, 100_001] {
            let data = payload(len);
            let (out, _, _) = run_transfer(&data, 50_000, 0, 0.0).await;
            assert_eq!(out, data, "length {} failed", len);
        }
    }

    #[tokio::test]
    async fn mismatched_length_is_refused() {
        let link = LossyLink::new(0);
        let (_fb_tx, mut fb_rx) = mpsc::channel::<Feedback>(8);
        let p = params(999, 100_000);
        // Data disagrees with the negotiated length — must not proceed.
        let err = send_object(&payload(500), link.as_ref(), &mut fb_rx, &p)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("declare"));
    }

    #[tokio::test]
    async fn sender_errors_when_control_plane_dies() {
        let link = LossyLink::new(1); // drop everything
        let (fb_tx, mut fb_rx) = mpsc::channel::<Feedback>(8);
        drop(fb_tx); // receiver hung up

        let data = payload(300_000);
        let p = params(data.len() as u64, 100_000);
        let err = send_object(&data, link.as_ref(), &mut fb_rx, &p)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("control plane closed"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn feedback_for_unknown_block_is_ignored() {
        // A duplicate or reordered ack must not corrupt sender bookkeeping.
        let data = payload(100_000);
        let link = LossyLink::new(0);
        let p = params(data.len() as u64, 100_000);
        let (fb_tx, mut fb_rx) = mpsc::channel::<Feedback>(16);

        // Stale feedback for a block that will never exist.
        fb_tx
            .send(Feedback::NeedMore {
                block_id: 9_999,
                symbols_needed: 5,
                symbols_received: 0,
            })
            .await
            .unwrap();
        fb_tx
            .send(Feedback::BlockOk {
                block_id: 9_999,
                symbols_used: 1,
            })
            .await
            .unwrap();

        let sl = link.clone();
        let sp = p.clone();
        let d = data.clone();
        let sender =
            tokio::spawn(async move { send_object(&d, sl.as_ref(), &mut fb_rx, &sp).await });
        let rl = link.clone();
        let receiver = tokio::spawn(async move {
            recv_object(rl.as_ref(), &fb_tx, &p, Duration::from_millis(5)).await
        });

        let (out, _) = receiver.await.unwrap().unwrap();
        sender.await.unwrap().unwrap();
        assert_eq!(out, data);
    }
}
