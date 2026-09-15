//! Shared resource admission primitives for synchronous scan workers.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

use crate::error::{AppError, AppResult, ErrorCode};

fn validation(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, message)
}

/// A bounded pool for filesystem handles. The permit is held by the caller
/// for the complete lifetime of the operation that owns the handle.
#[derive(Debug)]
pub(crate) struct FileOpenBudget {
    limit: usize,
    available: Mutex<usize>,
    wake: Condvar,
}

#[must_use = "a file-open permit must live for the complete filesystem operation"]
pub(crate) struct FileOpenPermit {
    budget: Arc<FileOpenBudget>,
}

impl FileOpenBudget {
    pub(crate) fn new(limit: u32) -> AppResult<Arc<Self>> {
        let limit =
            usize::try_from(limit).map_err(|_| validation("max_open_files 无法转换为 usize"))?;
        if limit == 0 {
            return Err(validation("max_open_files 必须大于 0"));
        }
        Ok(Arc::new(Self {
            limit,
            available: Mutex::new(limit),
            wake: Condvar::new(),
        }))
    }

    pub(crate) fn capacity(&self) -> usize {
        self.limit
    }

    pub(crate) fn acquire(
        self: &Arc<Self>,
        cancelled: impl Fn() -> bool,
    ) -> Option<FileOpenPermit> {
        let mut available = self.available.lock();
        loop {
            if cancelled() {
                return None;
            }
            if *available > 0 {
                *available -= 1;
                if cancelled() {
                    *available += 1;
                    self.wake.notify_one();
                    return None;
                }
                return Some(FileOpenPermit {
                    budget: Arc::clone(self),
                });
            }
            self.wake
                .wait_for(&mut available, Duration::from_millis(50));
        }
    }
}

impl Drop for FileOpenPermit {
    fn drop(&mut self) {
        let mut available = self.budget.available.lock();
        *available += 1;
        self.budget.wake.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;

    #[test]
    fn permits_never_exceed_configured_limit() {
        let budget = FileOpenBudget::new(2).unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::new();
        for _ in 0..8 {
            let budget = Arc::clone(&budget);
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            joins.push(thread::spawn(move || {
                let _permit = budget.acquire(|| false).unwrap();
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(now, Ordering::SeqCst);
                thread::yield_now();
                active.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for join in joins {
            join.join().unwrap();
        }
        assert!(maximum.load(Ordering::SeqCst) <= 2);
    }

    #[test]
    fn waiting_acquire_observes_cancellation() {
        let budget = FileOpenBudget::new(1).unwrap();
        let held = budget.acquire(|| false).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancelled);
        let budget_for_thread = Arc::clone(&budget);
        let join =
            thread::spawn(move || budget_for_thread.acquire(|| signal.load(Ordering::SeqCst)));
        thread::sleep(Duration::from_millis(60));
        cancelled.store(true, Ordering::SeqCst);
        assert!(join.join().unwrap().is_none());
        drop(held);
    }
}
