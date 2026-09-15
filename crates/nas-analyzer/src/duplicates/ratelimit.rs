//! Token-bucket read rate limiter for hashing (spec 19: default 30 MiB/s,
//! 0 = unlimited handled by the caller passing None).

use std::sync::Arc;

use parking_lot::Mutex;

/// Simple blocking token bucket for single-threaded callers.
pub struct TokenBucket {
    rate_per_sec: u64,
    /// Available bytes.
    tokens: u64,
    last_refill: std::time::Instant,
    /// Cap to avoid huge bursts after idle.
    burst: u64,
}

impl TokenBucket {
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        let burst = rate_bytes_per_sec.max(1);
        Self {
            rate_per_sec: rate_bytes_per_sec,
            tokens: burst,
            last_refill: std::time::Instant::now(),
            burst,
        }
    }

    /// Block (sleep) until `bytes` may be consumed. Callers poll their cancel
    /// flag between acquires; acquire granularity is the read chunk size.
    pub fn acquire(&mut self, bytes: u64) {
        loop {
            let Some(wait) = self.try_acquire(bytes) else {
                return;
            };
            // Sleep in bounded slices so cancellation stays responsive.
            std::thread::sleep(wait.min(std::time::Duration::from_millis(200)));
        }
    }

    /// Consume tokens if available, otherwise return the duration after which
    /// another attempt should be made. The caller can release a shared Mutex
    /// before sleeping so unrelated hash workers retain their concurrency.
    pub fn try_acquire(&mut self, bytes: u64) -> Option<std::time::Duration> {
        if bytes == 0 {
            return None;
        }
        self.refill();
        if self.tokens >= bytes {
            self.tokens -= bytes;
            return None;
        }
        let deficit = bytes - self.tokens;
        Some(std::time::Duration::from_secs_f64(
            deficit as f64 / self.rate_per_sec.max(1) as f64,
        ))
    }

    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        if elapsed.is_zero() {
            return;
        }
        let add = (self.rate_per_sec as u128 * elapsed.as_micros()) / 1_000_000;
        let add = u64::try_from(add).unwrap_or(u64::MAX);
        self.tokens = self.tokens.saturating_add(add).min(self.burst);
        self.last_refill = now;
    }
}

/// Thread-safe global limiter. Waiting never holds the inner Mutex, and the
/// cancellation callback is polled before every wait slice.
pub struct SharedTokenBucket {
    inner: Mutex<TokenBucket>,
}

impl SharedTokenBucket {
    pub fn new(rate_bytes_per_sec: u64) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(TokenBucket::new(rate_bytes_per_sec)),
        })
    }

    pub fn acquire(&self, bytes: u64, cancelled: impl Fn() -> bool) -> bool {
        loop {
            if cancelled() {
                return false;
            }
            let wait = self.inner.lock().try_acquire(bytes);
            let Some(wait) = wait else {
                return true;
            };
            let slice = wait.min(std::time::Duration::from_millis(200));
            std::thread::sleep(slice);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_rate() {
        let mut b = TokenBucket::new(10_000_000); // 10 MB/s, 1 s burst
        let start = std::time::Instant::now();
        for _ in 0..25 {
            b.acquire(1_000_000); // 25 MB: 10 burst + 15 throttled ≈ 1.5 s
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed > std::time::Duration::from_millis(1000),
            "expected throttling, took {elapsed:?}"
        );
    }

    #[test]
    fn burst_capped() {
        let mut b = TokenBucket::new(1_000_000);
        std::thread::sleep(std::time::Duration::from_millis(100));
        b.refill();
        assert!(b.tokens <= 1_000_000);
    }

    #[test]
    fn shared_limiter_can_cancel_while_waiting() {
        let limiter = SharedTokenBucket::new(1);
        assert!(limiter.acquire(1, || false));
        let started = std::time::Instant::now();
        assert!(!limiter.acquire(1, || started.elapsed()
            >= std::time::Duration::from_millis(20)));
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
    }
}
