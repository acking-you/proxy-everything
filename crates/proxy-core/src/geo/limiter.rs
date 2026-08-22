//! Request admission control for the ip-api geo endpoint.
//!
//! The free tier allows 45 requests per minute, and auto-proxy queries it once
//! per previously unseen host. A cold start on a resource-heavy page produces
//! dozens of distinct hosts at once — the per-host dedupe upstream collapses
//! repeats of the *same* host, not a burst of different ones — so the burst has
//! to be shaped here or the quota is gone.
//!
//! Exceeding it is worse than being slow. Measured against the live endpoint, the
//! API starts answering `fail` a few requests *before* the counter reaches zero,
//! and a 429 then carries `X-Ttl: 60`: a full minute during which everything is
//! rejected. So the budget is deliberately set below the advertised ceiling, and
//! an observed 429 parks new requests for the window the server asks for rather
//! than retrying into it.
//!
//! Waiting here is cheap because nothing user-facing blocks on it: the caller
//! gives up after a short deadline and takes the safe default, while this
//! finishes in the background and records the answer for next time.
//!
//! # The token bucket
//!
//! ```text
//!             one token every 1.5s
//!             (= 40/min, the long-run rate)
//!                       |
//!                       v
//!                 ,-----------,
//!                 |           |  <- a full bucket overflows: idle time
//!       15 -------|-----------|     does not bank without limit
//!                 |###########|
//!                 |###########|  capacity 15
//!                 |###########|  (the burst allowance)
//!                 |###########|
//!        0 -------'-----+-----'
//!                       |
//!                       v  each request takes one token
//!                  empty -> wait for the next drip
//! ```
//!
//! Capacity and drip rate are independent knobs, and both are needed:
//!
//! - **Capacity** decides how many requests may leave at once after an idle period. A plain rate
//!   limit cannot express that — "one per 1.5s" would make the first 15 hosts of a cold start queue
//!   for 22s even though the quota sat unused the whole time. The bucket is what banks the unused
//!   quota.
//! - **Drip rate** decides the sustained pace once the bank is empty.
//!
//! # Nothing drips in the background
//!
//! There is no timer task. The bucket is two numbers, and the tokens earned since
//! the last look are derived on demand in [`Bucket::refill`]: read the clock,
//! divide the elapsed time by the interval, add, clamp to capacity. A periodic
//! tick would cost a resident task and quantise the rate to its own period; this
//! is free and continuous.

use std::time::Duration;

use tokio::sync::{Mutex, Semaphore};
use tokio::time::Instant;

/// Requests per minute this process will spend.
///
/// Below the documented 45 because the endpoint begins failing before the quota
/// is fully consumed, and because a single 429 costs a whole minute.
const REQUESTS_PER_MINUTE: u32 = 40;

/// Tokens available to an idle process.
///
/// Sized for one page's worth of new hosts so an ordinary cold start drains
/// immediately instead of trickling. A starting point, not a derived optimum:
/// how many new hosts a page really produces has not been measured.
///
/// It must stay above [`MAX_CONCURRENCY`], or the bucket always runs dry first and
/// the concurrency cap can never bind. A test asserts this.
///
/// The standard bound on a token bucket is `capacity + rate * window`, so the
/// worst case here is `15 + 40 = 55` requests in a minute against a quota of 45.
/// That overshoot is knowingly left to the penalty window to absorb: reaching it
/// requires ~22.5s idle to fill the bucket followed by 60s of uninterrupted new
/// hosts, and a 429 then costs a minute rather than a wrong answer, because an
/// unresolved lookup is not cached. Structural safety instead of after-the-fact
/// recovery would mean `capacity + rate * 60 <= 45` — e.g. capacity 10 at 30/min,
/// at the cost of a smaller first wave and a slower steady state.
const BURST_CAPACITY: u32 = 15;

/// Simultaneous in-flight requests.
///
/// The rate limit is the real constraint; this only stops a burst from opening a
/// connection per host at the same instant. Paired with a burst of 15 it means the
/// initial wave leaves in two rounds — 8 in flight, 7 waiting on a permit — which
/// at the measured 200-680ms round-trip clears in well under two seconds.
const MAX_CONCURRENCY: usize = 8;

/// How long a request will wait for a token before giving up.
///
/// A lookup that queues for minutes is worth less than the cache entry it would
/// eventually write, and abandoning it keeps the number of parked tasks bounded.
/// Abandoning is safe: the caller has long since proceeded, and a failed lookup
/// is not cached, so the host is simply retried on its next connection.
const MAX_QUEUE_WAIT: Duration = Duration::from_secs(30);

/// Fallback penalty when a 429 arrives without a usable `X-Ttl`.
const DEFAULT_PENALTY: Duration = Duration::from_secs(60);

fn refill_interval() -> Duration {
    Duration::from_secs_f64(60.0 / f64::from(REQUESTS_PER_MINUTE))
}

/// Token bucket plus a server-driven penalty window.
///
/// Twenty new hosts arriving at once on an idle process, where `t` is seconds:
///
/// ```text
///   t=0.000  #1     ,-----,  15   elapsed=0, so refill returns early
///                   |#####|       15 -> 14                    admitted
///                   '-----'
///
///   t=0.000  #2     ,-----,  14
///      ...          |###..|       drained one at a time
///   t=0.000  #15    '-----'   0                       15 admitted at once
///
///   t=0.000  #16    ,-----,   0   under one token
///                   |.....|       missing = 1.0 - 0.0 = 1.0
///                   '-----'       -> Err(1.5s * 1.0), so sleep 1.5s
///
///   t=1.500  #16    ,-----,       earned = 1.5/1.5 = 1.0
///                   |#....|   1   0 -> 1.0 -> take -> 0.0      admitted
///                   '-----'   0
///
///   t=1.501  #17    ,-----,   0   #16 just took it; lost the race
///                   |.....|       -> Err(~1.5s), sleep again
///                   '-----'
/// ```
///
/// The shape to remember: the burst leaves immediately (spending the bank), then
/// the pace drops to one per 1.5s (spending the drip). Whoever is still queued
/// after [`MAX_QUEUE_WAIT`] is abandoned.
#[derive(Debug)]
struct Bucket {
    /// Fractional tokens, so a continuous refill does not round away.
    tokens: f64,
    last_refill: Instant,
    /// While set, no request may proceed: the server told us to back off.
    ///
    /// This is a valve upstream of the bucket rather than part of it — while it is
    /// shut, [`Bucket::try_take`] refuses without even refilling:
    ///
    /// ```text
    ///         ,-----------,
    ///         |  penalty? |   shut by a 429 for its X-Ttl window
    ///         '-----+-----'
    ///               |
    ///        shut --+-- every caller gets Err(time remaining)
    ///               |
    ///               v
    ///         ,-----------,
    ///         |  bucket   |   tokens also zeroed on the way in
    ///         '-----------'
    /// ```
    penalty_until: Option<Instant>,
}

impl Bucket {
    fn new() -> Self {
        Self {
            tokens: f64::from(BURST_CAPACITY),
            last_refill: Instant::now(),
            penalty_until: None,
        }
    }

    /// Add the tokens earned since the last check, capped at the burst size.
    ///
    /// `tokens` is fractional because `last_refill` advances unconditionally, so
    /// truncating the earned amount would discard the elapsed time along with it:
    ///
    /// ```text
    ///   with f64 (correct)
    ///     t=1.501  earned = 0.001/1.5 = 0.00067   tokens = 0.00067  kept
    ///              last_refill = 1.501
    ///     t=3.000  earned = 1.499/1.5 = 0.99933   tokens = 1.0      ready
    ///
    ///   with integers (broken)
    ///     t=1.501  earned = floor(0.00067) = 0    tokens = 0        lost
    ///              last_refill = 1.501   <- the clock moved anyway
    ///     t=3.000  earned = floor(0.99933) = 0    tokens = 0        lost
    ///              last_refill = 3.000
    ///     t=4.500  earned = floor(1.0) = 1        tokens = 1
    ///                                                 ^ a whole interval wasted
    /// ```
    ///
    /// This matters because [`GeoRateLimiter::acquire`] is a retry loop: every
    /// wakeup refills, so with truncation a contended bucket would fill far slower
    /// than the configured rate — arbitrarily slower, the more often it is polled.
    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        if elapsed.is_zero() {
            return;
        }
        self.last_refill = now;
        let earned = elapsed.as_secs_f64() / refill_interval().as_secs_f64();
        self.tokens = (self.tokens + earned).min(f64::from(BURST_CAPACITY));
    }

    /// Take a token, or report how long until one is available.
    ///
    /// Three outcomes: penalised, so the remaining window; a token, so take it; or
    /// short of a token, so the time needed to make up the shortfall. The `Err`
    /// carries a duration rather than a bare "no" so the caller can sleep exactly
    /// that long — no busy-waiting and no fixed polling period.
    ///
    /// The penalty check precedes the refill deliberately, which leaves
    /// `last_refill` untouched for the whole window. The first `try_take` after it
    /// therefore sees the entire window as elapsed (`60/1.5 = 40` tokens earned,
    /// clamped to 15) and the bucket comes back full.
    fn try_take(&mut self, now: Instant) -> Result<(), Duration> {
        if let Some(until) = self.penalty_until {
            if now < until {
                return Err(until - now);
            }
            self.penalty_until = None;
        }
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Ok(());
        }
        // Time for the fraction of a token still missing.
        let missing = 1.0 - self.tokens;
        Err(refill_interval().mul_f64(missing))
    }
}

/// Admission control shared by every geo API request in this process.
#[derive(Debug)]
pub(crate) struct GeoRateLimiter {
    bucket: Mutex<Bucket>,
    concurrency: Semaphore,
}

impl GeoRateLimiter {
    pub(crate) fn new() -> Self {
        Self {
            bucket: Mutex::new(Bucket::new()),
            concurrency: Semaphore::new(MAX_CONCURRENCY),
        }
    }

    /// Wait for permission to issue one request.
    ///
    /// The returned permit caps concurrency for as long as it is held. `None`
    /// means the caller waited [`MAX_QUEUE_WAIT`] without getting a token and
    /// should abandon the lookup.
    ///
    /// Four things about the body are load-bearing:
    ///
    /// - **The block around the `try_take` releases the mutex before sleeping.** Holding it across
    ///   an `await` would serialise every other caller behind this one's wait.
    /// - **`wait.min(remaining)` never sleeps past the deadline.** The bucket may ask for a minute;
    ///   the queue bound still has to hold.
    /// - **It loops rather than sleeping once.** Another task may take the token first, so the
    ///   wakeup has to re-check. The cost is no FIFO guarantee: under pressure a task can keep
    ///   losing the race until it hits the deadline. The unfairness is bounded, which is the
    ///   property that matters.
    /// - **Token first, permit second.** Reversed, a task queued for a token would hold a permit
    ///   while waiting and the concurrency cap would degenerate into a second queue instead of
    ///   describing requests actually in flight.
    pub(crate) async fn acquire(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
        let deadline = Instant::now() + MAX_QUEUE_WAIT;
        loop {
            let wait = {
                let mut bucket = self.bucket.lock().await;
                match bucket.try_take(Instant::now()) {
                    Ok(()) => break,
                    Err(wait) => wait,
                }
            };
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            // Never sleep past the deadline, so the bound is honoured even when
            // the bucket asks for a much longer wait.
            let remaining = deadline - now;
            tokio::time::sleep(wait.min(remaining)).await;
        }

        // A closed semaphore would mean the process is shutting down; treat it
        // the same as giving up rather than panicking.
        self.concurrency.acquire().await.ok()
    }

    /// Record that the server rejected a request, and stop sending for `retry_after`.
    ///
    /// Called for an explicit 429 and for the `fail` body the endpoint starts
    /// returning just before the quota reaches zero — that failure describes the
    /// budget, not the host.
    pub(crate) async fn note_rate_limited(&self, retry_after: Option<Duration>) {
        let penalty = retry_after.unwrap_or(DEFAULT_PENALTY);
        let mut bucket = self.bucket.lock().await;
        bucket.penalty_until = Some(Instant::now() + penalty);
        // Drop any credit as well: the server's view of the budget is what counts,
        // and ours is evidently wrong.
        bucket.tokens = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_burst_is_admitted_then_throttled_to_the_configured_rate() {
        let limiter = GeoRateLimiter::new();

        // The burst allowance is immediate.
        for i in 0..BURST_CAPACITY {
            assert!(
                limiter.acquire().await.is_some(),
                "burst request {i} was refused"
            );
        }
        assert_eq!(
            Instant::now().elapsed(),
            Duration::ZERO,
            "the burst must not sleep"
        );

        // The next one has to wait for a refill.
        let before = Instant::now();
        assert!(limiter.acquire().await.is_some());
        let waited = Instant::now() - before;
        assert!(
            waited >= refill_interval().mul_f64(0.9),
            "expected to wait about one refill interval, waited {waited:?}"
        );
    }

    /// Holding the maximum number of permits must block the next acquirer until
    /// one is released, even though tokens remain.
    #[tokio::test(start_paused = true)]
    async fn concurrency_is_capped_while_permits_are_held() {
        // Enough permits to exhaust concurrency without exhausting the bucket.
        assert!(MAX_CONCURRENCY < BURST_CAPACITY as usize);

        let limiter = std::sync::Arc::new(GeoRateLimiter::new());
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENCY {
            held.push(limiter.acquire().await.expect("within the burst allowance"));
        }

        // A further acquire cannot complete while every permit is outstanding.
        let waiter = {
            let limiter = std::sync::Arc::clone(&limiter);
            tokio::spawn(async move { limiter.acquire().await.is_some() })
        };
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            !waiter.is_finished(),
            "acquired a permit beyond the concurrency cap"
        );

        // Releasing one lets it through.
        held.pop();
        assert!(
            waiter.await.unwrap(),
            "the freed permit was not handed over"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_rate_limit_response_parks_requests_for_the_requested_window() {
        let limiter = GeoRateLimiter::new();
        assert!(limiter.acquire().await.is_some());

        limiter
            .note_rate_limited(Some(Duration::from_secs(5)))
            .await;

        let before = Instant::now();
        assert!(limiter.acquire().await.is_some());
        assert!(
            Instant::now() - before >= Duration::from_secs(5),
            "must not send again before the penalty window elapses"
        );
    }

    /// A request must not queue forever: the answer stops being useful, and the
    /// parked tasks would accumulate.
    #[tokio::test(start_paused = true)]
    async fn a_request_gives_up_rather_than_queueing_indefinitely() {
        let limiter = GeoRateLimiter::new();
        // A penalty far beyond the queue bound.
        limiter
            .note_rate_limited(Some(Duration::from_secs(600)))
            .await;

        let before = Instant::now();
        assert!(
            limiter.acquire().await.is_none(),
            "expected the request to be abandoned"
        );
        let waited = Instant::now() - before;
        assert!(
            waited <= MAX_QUEUE_WAIT + Duration::from_secs(1),
            "gave up after {waited:?}, which exceeds the queue bound"
        );
    }
}
