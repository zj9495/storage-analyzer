//! In-process login rate limiting keyed by (IP, username) — spec 14.1:
//! 5 failures within 10 minutes trigger a short backoff; accounts are never
//! permanently locked. State is per-process by design.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::error::{AppError, AppResult, ErrorCode};

const DEFAULT_MAX_FAILURES: u32 = 5;
const DEFAULT_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Sliding-window failure counter. `check` rejects while at least
/// `max_failures` failures sit inside the trailing `window`;
/// `record_success` clears the counter for the key.
pub struct RateLimiter {
    max_failures: u32,
    window: Duration,
    failures: Mutex<HashMap<(String, String), Vec<Instant>>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FAILURES, DEFAULT_WINDOW)
    }
}

impl RateLimiter {
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            max_failures,
            window,
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// `Ok(())` when the attempt may proceed; `RateLimited` (with a
    /// `retry_after_seconds` detail) while the key is in backoff.
    pub fn check(&self, ip: &str, username: &str) -> AppResult<()> {
        let mut map = self.failures.lock();
        let key = (ip.to_string(), username.to_string());
        let Some(failures) = map.get_mut(&key) else {
            return Ok(());
        };
        let now = Instant::now();
        failures.retain(|t| now.duration_since(*t) < self.window);
        if failures.len() >= self.max_failures as usize {
            let oldest = failures.first().copied().unwrap_or(now);
            let retry_after = self.window.saturating_sub(now.duration_since(oldest));
            return Err(
                AppError::new(ErrorCode::RateLimited, "登录失败次数过多，请稍后重试").with_details(
                    serde_json::json!({
                        "retry_after_seconds": retry_after.as_secs(),
                    }),
                ),
            );
        }
        if failures.is_empty() {
            map.remove(&key);
        }
        Ok(())
    }

    /// Record one failed login attempt for the key.
    pub fn record_failure(&self, ip: &str, username: &str) {
        let mut map = self.failures.lock();
        let failures = map
            .entry((ip.to_string(), username.to_string()))
            .or_default();
        let now = Instant::now();
        failures.retain(|t| now.duration_since(*t) < self.window);
        failures.push(now);
    }

    /// Clear the counter after a successful login.
    pub fn record_success(&self, ip: &str, username: &str) {
        self.failures
            .lock()
            .remove(&(ip.to_string(), username.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triggers_after_max_failures_and_recovers_after_window() {
        let limiter = RateLimiter::new(3, Duration::from_millis(80));
        for _ in 0..2 {
            limiter.record_failure("10.0.0.1", "admin");
            limiter.check("10.0.0.1", "admin").unwrap();
        }
        limiter.record_failure("10.0.0.1", "admin");
        let e = limiter.check("10.0.0.1", "admin").unwrap_err();
        assert_eq!(e.code, ErrorCode::RateLimited);
        assert!(e.details.is_some());
        // A different key is unaffected.
        limiter.check("10.0.0.2", "admin").unwrap();
        limiter.check("10.0.0.1", "other").unwrap();
        // Backoff ends with the window; no permanent lockout.
        std::thread::sleep(Duration::from_millis(100));
        limiter.check("10.0.0.1", "admin").unwrap();
    }

    #[test]
    fn success_clears_counter() {
        let limiter = RateLimiter::new(2, Duration::from_secs(600));
        limiter.record_failure("10.0.0.1", "admin");
        limiter.record_failure("10.0.0.1", "admin");
        assert!(limiter.check("10.0.0.1", "admin").unwrap_err().code == ErrorCode::RateLimited);
        limiter.record_success("10.0.0.1", "admin");
        limiter.check("10.0.0.1", "admin").unwrap();
        // Counter restarted: one failure is not enough to trip again.
        limiter.record_failure("10.0.0.1", "admin");
        limiter.check("10.0.0.1", "admin").unwrap();
    }

    #[test]
    fn default_limits_match_spec() {
        let limiter = RateLimiter::default();
        for _ in 0..5 {
            limiter.record_failure("10.0.0.1", "admin");
        }
        assert!(limiter.check("10.0.0.1", "admin").unwrap_err().code == ErrorCode::RateLimited);
    }
}
