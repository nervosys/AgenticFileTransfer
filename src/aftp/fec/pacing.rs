//! BBR-style pacing for the FEC data plane.
//!
//! The data plane sends UDP datagrams, so there is no kernel congestion
//! controller underneath it — we must supply our own or we would either
//! collapse the link or leave it idle.
//!
//! Loss-based control (Reno, CUBIC) is exactly the wrong choice here. Those
//! algorithms read packet loss as congestion, but on the links this data plane
//! exists to serve, loss is a property of the *medium*, not a queue signal. A
//! CUBIC sender on a 10%-loss path spends its life in backoff. So we model the
//! path the way BBR does — by its two invariants:
//!
//! - **BtlBw**, the bottleneck bandwidth: a windowed *maximum* of measured
//!   delivery rate. Maximum, because the largest rate we ever actually achieved
//!   is a lower bound on what the path can carry.
//! - **RTprop**, the round-trip propagation delay: a windowed *minimum* of
//!   observed RTT. Minimum, because the smallest RTT we ever saw is the one
//!   with the least queueing in it.
//!
//! The optimal operating point is exactly `BtlBw` — enough to fill the pipe,
//! not enough to build a standing queue. We probe for more with a periodic gain
//! cycle, and critically we never reduce rate merely because symbols were lost.
//!
//! Reference: Cardwell et al., *BBR: Congestion-Based Congestion Control*
//! (ACM Queue, 2016).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How long a bandwidth sample stays eligible to be the running maximum.
///
/// Expressed in round trips: BBR uses ~10, long enough to survive a probe
/// cycle, short enough to notice the path genuinely getting slower.
const BTLBW_WINDOW_RTTS: u32 = 10;

/// How long an RTT sample stays eligible to be the running minimum.
const RTPROP_WINDOW: Duration = Duration::from_secs(10);

/// PROBE_BW gain cycle. One phase probes 25% above the estimate to discover
/// new headroom, the next drains 25% below to clear whatever queue that
/// created, and the rest cruise at the estimate.
const GAIN_CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

/// Extra gain applied while starting up, to find the bottleneck quickly
/// instead of creeping toward it. 2/ln(2), as in BBR's STARTUP.
const STARTUP_GAIN: f64 = 2.885;

/// Rate assumed before the first measurement lands (12.5 MB/s ≈ 100 Mbit/s).
/// Deliberately modest: too high floods a slow path before the first sample.
const INITIAL_RATE: f64 = 12_500_000.0;

/// Rate floor, so a bad sample can never stall the transfer outright.
const MIN_RATE: f64 = 64_000.0;

/// Assumed RTT before the first measurement.
const INITIAL_RTT: Duration = Duration::from_millis(50);

/// Shortest pacing delay worth handing to an async timer. Below this the
/// timer's own granularity dominates and costs far more than the gap it was
/// meant to insert.
const MIN_SLEEP: Duration = Duration::from_millis(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Ramping up geometrically to find the bottleneck.
    Startup,
    /// Draining the queue that startup built.
    Drain,
    /// Steady state: cruise at the estimate, probe periodically.
    ProbeBw,
}

/// One `(value, expiry)` sample in a windowed extremum filter.
#[derive(Debug, Clone, Copy)]
struct Sample<T> {
    value: T,
    at: Instant,
}

/// Tracks the bottleneck bandwidth and round-trip propagation delay, and
/// converts them into a send rate.
pub struct Pacer {
    bw_samples: VecDeque<Sample<f64>>,
    rtt_samples: VecDeque<Sample<Duration>>,
    phase: Phase,
    cycle_index: usize,
    cycle_started: Instant,
    /// Consecutive rounds without meaningful bandwidth growth. Three in a row
    /// means startup has found the bottleneck.
    plateau_rounds: u32,
    last_bw: f64,
    /// Token bucket for shaping the actual send loop.
    tokens: f64,
    last_refill: Instant,
    /// Pacing delay owed but not yet slept, accumulated until it is worth a
    /// timer. See [`Pacer::acquire`].
    debt: Duration,
}

impl Pacer {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            bw_samples: VecDeque::new(),
            rtt_samples: VecDeque::new(),
            phase: Phase::Startup,
            cycle_index: 0,
            cycle_started: now,
            plateau_rounds: 0,
            last_bw: 0.0,
            tokens: 0.0,
            last_refill: now,
            debt: Duration::ZERO,
        }
    }

    /// Record a delivery-rate sample: `bytes` acknowledged over `elapsed`,
    /// measured at round-trip time `rtt`.
    ///
    /// Note what is *absent*: there is no loss parameter. Symbol loss is
    /// repaired by the fountain code and must not move the rate estimate, or
    /// we would reproduce exactly the CUBIC collapse this design avoids.
    pub fn on_sample(&mut self, bytes: u64, elapsed: Duration, rtt: Duration) {
        let now = Instant::now();

        if !rtt.is_zero() {
            self.rtt_samples.push_back(Sample {
                value: rtt,
                at: now,
            });
        }
        let secs = elapsed.as_secs_f64();
        if secs > 0.0 && bytes > 0 {
            let rate = bytes as f64 / secs;
            self.bw_samples.push_back(Sample {
                value: rate,
                at: now,
            });
        }

        self.expire(now);
        self.advance(now);
    }

    /// Drop samples that have aged out of their filter windows.
    fn expire(&mut self, now: Instant) {
        // Floor the bandwidth window well above the feedback cadence. Samples
        // here arrive per feedback event — as rarely as once a second on a
        // lossy link — and a window that holds only one or two of them lets a
        // single underestimate (an interval that included sender idle time)
        // become the whole estimate, cratering the rate until probe cycles
        // claw it back. Ten seconds keeps enough honest samples alive to
        // outvote the duds, at the cost of taking that long to believe a link
        // that genuinely slowed.
        let bw_window = self
            .rtprop()
            .saturating_mul(BTLBW_WINDOW_RTTS)
            .max(Duration::from_secs(10));
        while let Some(front) = self.bw_samples.front() {
            if now.duration_since(front.at) > bw_window {
                self.bw_samples.pop_front();
            } else {
                break;
            }
        }
        while let Some(front) = self.rtt_samples.front() {
            if now.duration_since(front.at) > RTPROP_WINDOW {
                self.rtt_samples.pop_front();
            } else {
                break;
            }
        }
        // Never let the filters empty entirely; the most recent sample is
        // always a better estimate than a hardcoded default.
        if self.bw_samples.is_empty() && self.last_bw > 0.0 {
            self.bw_samples.push_back(Sample {
                value: self.last_bw,
                at: now,
            });
        }
    }

    /// Drive the state machine.
    fn advance(&mut self, now: Instant) {
        let bw = self.btlbw();
        match self.phase {
            Phase::Startup => {
                // Growth under 25% per round means we have found the pipe.
                if bw <= self.last_bw * 1.25 {
                    self.plateau_rounds += 1;
                } else {
                    self.plateau_rounds = 0;
                }
                if self.plateau_rounds >= 3 {
                    self.phase = Phase::Drain;
                }
            }
            Phase::Drain => {
                // One RTprop of draining is enough to shed the startup queue.
                if now.duration_since(self.cycle_started) >= self.rtprop() {
                    self.phase = Phase::ProbeBw;
                    self.cycle_started = now;
                    self.cycle_index = 0;
                }
            }
            Phase::ProbeBw => {
                if now.duration_since(self.cycle_started) >= self.rtprop() {
                    self.cycle_index = (self.cycle_index + 1) % GAIN_CYCLE.len();
                    self.cycle_started = now;
                }
            }
        }
        self.last_bw = bw;
    }

    /// Bottleneck bandwidth estimate in bytes/sec — the windowed maximum.
    pub fn btlbw(&self) -> f64 {
        if self.bw_samples.is_empty() {
            return INITIAL_RATE;
        }
        self.bw_samples
            .iter()
            .map(|s| s.value)
            .fold(f64::NEG_INFINITY, f64::max)
            .max(MIN_RATE)
    }

    /// Round-trip propagation delay estimate — the windowed minimum.
    pub fn rtprop(&self) -> Duration {
        self.rtt_samples
            .iter()
            .map(|s| s.value)
            .min()
            .unwrap_or(INITIAL_RTT)
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Whether at least one real delivery sample has arrived. Until then the
    /// rate is pure guesswork and callers should limit how much they send on
    /// faith — see [`Pacer::unsampled_allowance`].
    pub fn sampled(&self) -> bool {
        // `expire` refills from `last_bw` once a sample has ever existed, so
        // an empty deque genuinely means "never sampled".
        !self.bw_samples.is_empty()
    }

    /// How many bytes may reasonably be sent before the first delivery
    /// sample: two initial-RTT windows at the initial rate. The equivalent of
    /// BBR's initial cwnd — enough to elicit feedback from the receiver,
    /// small enough that a wildly wrong initial guess cannot flood a slow
    /// path's queue for seconds.
    pub fn unsampled_allowance() -> u64 {
        (INITIAL_RATE * INITIAL_RTT.as_secs_f64() * 2.0) as u64
    }

    /// Current send rate in bytes/sec: the bandwidth estimate scaled by the
    /// gain appropriate to the current phase.
    pub fn pacing_rate(&self) -> f64 {
        let gain = match self.phase {
            Phase::Startup => STARTUP_GAIN,
            Phase::Drain => 1.0 / STARTUP_GAIN,
            Phase::ProbeBw => GAIN_CYCLE[self.cycle_index],
        };
        (self.btlbw() * gain).max(MIN_RATE)
    }

    /// Bytes that should be in flight to fill the pipe without queueing:
    /// the bandwidth-delay product, with BBR's 2× allowance for delayed and
    /// aggregated acknowledgements.
    pub fn target_inflight(&self) -> u64 {
        let bdp = self.btlbw() * self.rtprop().as_secs_f64();
        ((bdp * 2.0) as u64).max(64 * 1024)
    }

    /// How long to wait before sending `bytes`, shaping output to the pacing
    /// rate. Returns zero when the bucket already holds enough credit.
    ///
    /// Pacing matters more here than in a stream protocol: a fountain sender
    /// with nothing to wait for will happily emit symbols as fast as the CPU
    /// allows and drive the bottleneck queue straight into tail drop.
    ///
    /// Sub-millisecond waits are accumulated rather than slept. A 1362-byte
    /// symbol at 100 MB/s is due a 13 µs gap, but an async timer cannot
    /// resolve that — asking for it yields a full scheduler tick of roughly a
    /// millisecond, which would cap throughput near 1.3 MB/s no matter how
    /// fast the link is. Banking the debt and paying it in one larger sleep
    /// preserves the average rate while keeping the timer count sane.
    pub fn acquire(&mut self, bytes: u64) -> Duration {
        let now = Instant::now();
        let rate = self.pacing_rate();

        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        // Cap accumulated credit at one RTT's worth so an idle sender cannot
        // bank a burst large enough to overrun the bottleneck on resume.
        let burst_cap = (rate * self.rtprop().as_secs_f64()).max(bytes as f64);
        self.tokens = (self.tokens + elapsed * rate).min(burst_cap);

        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
        } else {
            let deficit = bytes as f64 - self.tokens;
            self.tokens = 0.0;
            self.debt += Duration::from_secs_f64(deficit / rate);
        }

        if self.debt >= MIN_SLEEP {
            let owed = self.debt;
            self.debt = Duration::ZERO;
            owed
        } else {
            Duration::ZERO
        }
    }
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new()
    }
}

/// Repair overhead to apply for an observed loss rate.
///
/// To land K symbols across a channel that drops a fraction `p`, send
/// `K / (1 - p)`. The margin covers the variance of a small sample — the cost
/// of guessing low is a whole extra feedback round trip, while the cost of
/// guessing high is a few redundant symbols, so the asymmetry justifies
/// erring upward.
pub fn repair_overhead(loss_rate: f64) -> f64 {
    let p = loss_rate.clamp(0.0, 0.9);
    (1.0 / (1.0 - p)) * 1.05
}

/// Repair symbols to send alongside `source_symbols` at a given loss rate.
pub fn repair_symbol_count(source_symbols: u32, loss_rate: f64) -> u32 {
    if loss_rate <= 0.0 {
        // A clean link needs no proactive repair — the systematic symbols are
        // the data. This is the fast path worth protecting.
        return 0;
    }
    let total = source_symbols as f64 * repair_overhead(loss_rate);
    (total.ceil() as u32).saturating_sub(source_symbols).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_in_startup_with_a_usable_default_rate() {
        let p = Pacer::new();
        assert_eq!(p.phase(), Phase::Startup);
        assert!(p.pacing_rate() > 0.0);
        assert_eq!(p.rtprop(), INITIAL_RTT);
    }

    #[test]
    fn btlbw_takes_the_windowed_maximum() {
        let mut p = Pacer::new();
        let rtt = Duration::from_millis(20);
        p.on_sample(1_000_000, Duration::from_millis(100), rtt); // 10 MB/s
        p.on_sample(5_000_000, Duration::from_millis(100), rtt); // 50 MB/s
        p.on_sample(2_000_000, Duration::from_millis(100), rtt); // 20 MB/s
                                                                 // The peak is the estimate — a dip must not drag it down.
        assert!((p.btlbw() - 50_000_000.0).abs() < 1.0);
    }

    #[test]
    fn rtprop_takes_the_windowed_minimum() {
        let mut p = Pacer::new();
        p.on_sample(1000, Duration::from_millis(10), Duration::from_millis(80));
        p.on_sample(1000, Duration::from_millis(10), Duration::from_millis(20));
        p.on_sample(1000, Duration::from_millis(10), Duration::from_millis(50));
        assert_eq!(p.rtprop(), Duration::from_millis(20));
    }

    /// The property that matters most: loss must not reduce the send rate.
    /// This is what separates this pacer from CUBIC on a 10%-loss path.
    #[test]
    fn sustained_loss_does_not_reduce_the_rate() {
        let mut p = Pacer::new();
        let rtt = Duration::from_millis(200);
        for _ in 0..20 {
            p.on_sample(1_000_000, Duration::from_millis(100), rtt);
        }
        let rate_before = p.btlbw();

        // Simulate a 10%-loss regime: goodput samples arrive, but there is no
        // loss signal anywhere in the API to depress the estimate.
        for _ in 0..20 {
            p.on_sample(900_000, Duration::from_millis(100), rtt);
        }
        assert!(
            p.btlbw() >= rate_before * 0.99,
            "loss dragged the estimate down: {} → {}",
            rate_before,
            p.btlbw()
        );
    }

    #[test]
    fn startup_plateaus_into_drain() {
        let mut p = Pacer::new();
        let rtt = Duration::from_millis(10);
        // Flat bandwidth: no growth, so startup should conclude.
        for _ in 0..6 {
            p.on_sample(1_000_000, Duration::from_millis(100), rtt);
        }
        assert_ne!(p.phase(), Phase::Startup, "startup never terminated");
    }

    #[test]
    fn startup_gain_exceeds_steady_state_gain() {
        let mut startup = Pacer::new();
        startup.on_sample(
            1_000_000,
            Duration::from_millis(100),
            Duration::from_millis(10),
        );
        let startup_rate = startup.pacing_rate();
        let bw = startup.btlbw();
        // Startup deliberately overshoots to find the pipe quickly.
        assert!(startup_rate > bw);
    }

    #[test]
    fn target_inflight_tracks_the_bandwidth_delay_product() {
        let mut p = Pacer::new();
        // 100 MB/s over an 80 ms path → BDP of 8 MB.
        p.on_sample(
            10_000_000,
            Duration::from_millis(100),
            Duration::from_millis(80),
        );
        let inflight = p.target_inflight();
        assert!(
            (8_000_000..=32_000_000).contains(&inflight),
            "inflight {} not in the expected BDP range",
            inflight
        );
    }

    #[test]
    fn token_bucket_shapes_output_to_the_rate() {
        let mut p = Pacer::new();
        p.on_sample(1_000_000, Duration::from_secs(1), Duration::from_millis(10));

        // A request far beyond one RTT of credit must be made to wait.
        let huge = (p.pacing_rate() * 10.0) as u64;
        assert!(p.acquire(huge) > Duration::ZERO);
    }

    /// Sub-millisecond gaps must not each become a timer wait, or the timer's
    /// granularity — not the link — sets the throughput ceiling.
    #[test]
    fn tiny_pacing_gaps_are_accumulated_not_slept() {
        let mut p = Pacer::new();
        // A fast link: each 1362-byte symbol is due only a few microseconds.
        p.on_sample(
            100_000_000,
            Duration::from_secs(1),
            Duration::from_millis(1),
        );

        let mut sleeps = 0;
        let mut total = Duration::ZERO;
        for _ in 0..200 {
            let d = p.acquire(1362);
            if !d.is_zero() {
                sleeps += 1;
                total += d;
                // Anything we do sleep must be worth a timer.
                assert!(d >= MIN_SLEEP, "slept for a sub-millisecond gap: {:?}", d);
            }
        }
        assert!(
            sleeps < 200,
            "every symbol slept; pacing would cap throughput at the timer rate"
        );
        // Whatever was slept still reflects real owed time, not zero pacing.
        assert!(total < Duration::from_secs(1));
    }

    #[test]
    fn token_bucket_does_not_bank_unbounded_burst() {
        let mut p = Pacer::new();
        p.on_sample(
            1_000_000,
            Duration::from_millis(100),
            Duration::from_millis(10),
        );
        // Idle, then demand a large burst: the cap must still force a wait.
        std::thread::sleep(Duration::from_millis(30));
        let burst = (p.pacing_rate() * 5.0) as u64;
        assert!(
            p.acquire(burst) > Duration::ZERO,
            "an idle sender banked an unbounded burst"
        );
    }

    #[test]
    fn repair_overhead_matches_the_erasure_channel() {
        // To land K across a channel dropping p, send K/(1-p) (plus margin).
        assert!(repair_overhead(0.0) >= 1.0);
        assert!((repair_overhead(0.10) - 1.1667).abs() < 0.01);
        assert!((repair_overhead(0.50) - 2.1).abs() < 0.01);
        // Monotonic in loss.
        assert!(repair_overhead(0.2) > repair_overhead(0.1));
        // Clamped, so a pathological input cannot explode the symbol count.
        assert!(repair_overhead(1.5).is_finite());
        assert!(repair_overhead(-1.0).is_finite());
    }

    #[test]
    fn clean_links_pay_no_proactive_repair() {
        // The systematic fast path: zero loss means zero repair symbols.
        assert_eq!(repair_symbol_count(1000, 0.0), 0);
    }

    #[test]
    fn repair_count_scales_with_loss() {
        let low = repair_symbol_count(1000, 0.02);
        let high = repair_symbol_count(1000, 0.10);
        assert!(high > low, "{} should exceed {}", high, low);
        // 10% loss should cost roughly 17% extra symbols, not 2× or 1.001×.
        assert!(
            (150..=250).contains(&high),
            "unexpected repair count {}",
            high
        );
        // Any loss at all yields at least one repair symbol.
        assert!(repair_symbol_count(10, 0.001) >= 1);
    }
}
