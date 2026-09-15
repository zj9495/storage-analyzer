//! SQLite access layer (spec 15.5/15.7).
//!
//! - each Connection is owned exclusively by the thread that created it;
//! - writes go through a single dedicated writer thread behind a bounded
//!   channel (256 pending items); HTTP handlers only await oneshot results;
//! - reads go through a fixed pool of reader threads (default 4), each with
//!   its own connection; the pool size is the global query-slot limit shared
//!   with exports;
//! - control DB: WAL + synchronous=FULL; run indexes: NORMAL.

pub mod migrate;

use std::path::Path;
use std::thread::JoinHandle;

use crossbeam_channel::{Receiver, Sender, bounded};
use rusqlite::Connection;

use crate::error::{AppError, AppResult, ErrorCode};

const WRITE_QUEUE_BOUND: usize = 256;

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

type WriteJob = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

/// Handle to the single-writer thread. Clone freely; all clones feed the
/// same bounded queue (backpressure: send fails with ResourceBusy when full).
#[derive(Clone)]
pub struct DbWriter {
    tx: Sender<WriteMsg>,
}

struct WriteMsg {
    job: WriteJob,
}

pub struct DbWriterGuard {
    pub writer: DbWriter,
    join: Option<JoinHandle<()>>,
}

impl DbWriter {
    /// Spawn the writer thread owning a read-write connection at `path`.
    pub fn spawn(path: &Path, synchronous_full: bool) -> AppResult<DbWriterGuard> {
        let mut conn = open_connection(path, false, synchronous_full)?;
        let (tx, rx) = bounded::<WriteMsg>(WRITE_QUEUE_BOUND);
        let join = std::thread::Builder::new()
            .name("db-writer".into())
            .spawn(move || {
                while let Ok(msg) = rx.recv() {
                    (msg.job)(&mut conn);
                }
            })
            .map_err(|e| internal(format!("spawn db writer: {e}")))?;
        Ok(DbWriterGuard {
            writer: DbWriter { tx },
            join: Some(join),
        })
    }

    /// Run `f` on the writer thread and await its result. `f` must be short
    /// and bounded; long scans/aggregations belong in the run-index writer.
    pub async fn call<F, T>(&self, f: F) -> AppResult<T>
    where
        F: FnOnce(&mut Connection) -> AppResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let (rtx, rrx) = tokio::sync::oneshot::channel();
        let job: WriteJob = Box::new(move |conn| {
            let _ = rtx.send(f(conn));
        });
        self.tx.try_send(WriteMsg { job }).map_err(|_| {
            AppError::new(
                ErrorCode::ResourceBusy,
                "control database write queue is full",
            )
        })?;
        rrx.await
            .map_err(|_| internal("db writer thread dropped request"))?
    }

    /// Blocking variant for use from non-async (worker) threads.
    pub fn call_blocking<F, T>(&self, f: F) -> AppResult<T>
    where
        F: FnOnce(&mut Connection) -> AppResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let (rtx, rrx) = crossbeam_channel::bounded(0);
        let job: WriteJob = Box::new(move |conn| {
            let _ = rtx.send(f(conn));
        });
        self.tx.try_send(WriteMsg { job }).map_err(|_| {
            AppError::new(
                ErrorCode::ResourceBusy,
                "control database write queue is full",
            )
        })?;
        rrx.recv()
            .map_err(|_| internal("db writer thread dropped request"))?
    }
}

impl DbWriterGuard {
    /// Drain and stop the writer thread.
    pub fn shutdown(mut self) {
        drop(self.writer.tx.clone());
        // Close our sender clones by replacing with a disconnected channel.
        let (tx, _rx) = bounded::<WriteMsg>(1);
        self.writer.tx = tx;
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Fixed pool of read threads; each owns its own read connection. The pool
/// size IS the global read query slot limit (spec 15.6).
pub struct DbReadPool {
    tx: Sender<WriteMsg>,
    joins: Vec<JoinHandle<()>>,
}

impl DbReadPool {
    pub fn spawn(path: &Path, slots: usize) -> AppResult<Self> {
        let (tx, rx) = bounded::<WriteMsg>(slots * 8);
        let mut joins = Vec::new();
        for i in 0..slots {
            let rxc: Receiver<WriteMsg> = rx.clone();
            let mut conn = open_connection(path, true, false)?;
            let join = std::thread::Builder::new()
                .name(format!("db-reader-{i}"))
                .spawn(move || {
                    while let Ok(msg) = rxc.recv() {
                        (msg.job)(&mut conn);
                    }
                })
                .map_err(|e| internal(format!("spawn db reader: {e}")))?;
            joins.push(join);
        }
        Ok(Self { tx, joins })
    }

    pub async fn call<F, T>(&self, f: F) -> AppResult<T>
    where
        F: FnOnce(&mut Connection) -> AppResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let (rtx, rrx) = tokio::sync::oneshot::channel();
        let job: WriteJob = Box::new(move |conn| {
            let _ = rtx.send(f(conn));
        });
        self.tx
            .try_send(WriteMsg { job })
            .map_err(|_| AppError::new(ErrorCode::ResourceBusy, "read query slots exhausted"))?;
        rrx.await
            .map_err(|_| internal("db reader thread dropped request"))?
    }

    pub fn shutdown(self) {
        drop(self.tx);
        for j in self.joins {
            let _ = j.join();
        }
    }
}

pub fn open_connection(
    path: &Path,
    read_only: bool,
    synchronous_full: bool,
) -> AppResult<Connection> {
    let conn = if read_only {
        Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_URI
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| internal(format!("open read connection {}: {e}", path.display())))?
    } else {
        Connection::open(path)
            .map_err(|e| internal(format!("open connection {}: {e}", path.display())))?
    };
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| internal(format!("busy_timeout: {e}")))?;
    conn.execute_batch(&format!(
        "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous={};",
        if synchronous_full { "FULL" } else { "NORMAL" }
    ))
    .map_err(|e| internal(format!("pragmas: {e}")))?;
    Ok(conn)
}
