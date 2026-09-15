//! Run index writer (spec 15.5/15.6/16.2). Owns the single `Connection` for
//! `<run>/index.sqlite`; entries are committed in bounded batches, the
//! directory frontier spills to the `frontier` table, and identity dedupe
//! uses a TEMP table so memory stays bounded by disk instead of RAM.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{AppError, AppResult, ErrorCode};
use crate::store::migrate::{self, INDEX_MIGRATIONS};

use super::ScanControl;
use super::index_aggregates;

const MAX_ERROR_ROWS: u64 = 10_000;
const FRONTIER_RELOAD_BATCH: i64 = 512;

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

/// A fully populated entries row (dfs columns are assigned in finalize).
pub(crate) struct NewEntry {
    pub source_id: String,
    pub parent_entry_id: Option<i64>,
    pub raw_relative_path: Vec<u8>,
    pub display_name: String,
    pub path_encoding_warning: bool,
    pub entry_kind: &'static str,
    pub file_identity_key: Option<String>,
    pub device_id: Option<String>,
    pub inode_id: Option<String>,
    pub nlink: Option<i64>,
    pub uid: Option<i64>,
    pub gid: Option<i64>,
    pub mode: Option<i64>,
    pub size_bytes: Option<i64>,
    pub allocated_bytes_estimate: Option<i64>,
    pub mtime: Option<(i64, i64)>,
    pub atime: Option<(i64, i64)>,
    pub ctime: Option<(i64, i64)>,
    pub category_id: Option<&'static str>,
    pub extension: Option<String>,
    pub scan_error: Option<String>,
}

const INSERT_ENTRY_SQL: &str = "INSERT OR IGNORE INTO entries (
    source_id, parent_entry_id, raw_relative_path, display_name, path_encoding_warning,
    entry_kind, file_identity_key, identity_quality, device_id, inode_id, nlink, uid, gid,
    mode, size_bytes, allocated_bytes_estimate, mtime_sec, mtime_nsec, atime_sec,
    atime_nsec, ctime_sec, ctime_nsec, birthtime_sec, birthtime_nsec, category_id,
    extension, scan_error, observation_time
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
    ?19, ?20, ?21, ?22, NULL, NULL, ?23, ?24, ?25,
    strftime('%Y-%m-%dT%H:%M:%fZ','now')
)";

pub(crate) struct IndexWriter {
    conn: Connection,
    pending: Vec<NewEntry>,
    last_flush: Instant,
    errors_written: u64,
    excluded_buf: HashMap<i64, u64>,
    /// source_id → (unique_logical_bytes, unique_allocated_bytes), first-seen
    /// attribution across the whole run.
    unique_by_source: HashMap<String, (Option<u64>, Option<u64>)>,
}

impl IndexWriter {
    pub fn open(path: &Path) -> AppResult<Self> {
        let mut conn = Connection::open(path)
            .map_err(|e| internal(format!("open run index {}: {e}", path.display())))?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| internal(format!("busy_timeout: {e}")))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;",
        )
        .map_err(|e| internal(format!("run index pragmas: {e}")))?;
        migrate::apply(&mut conn, INDEX_MIGRATIONS)?;
        conn.execute_batch(
            "CREATE TEMP TABLE seen_identity(identity_key TEXT PRIMARY KEY);
             CREATE TEMP TABLE dir_excluded(entry_id INTEGER PRIMARY KEY, n INTEGER NOT NULL);",
        )
        .map_err(|e| internal(format!("temp tables: {e}")))?;
        let w = Self {
            conn,
            pending: Vec::new(),
            last_flush: Instant::now(),
            errors_written: 0,
            excluded_buf: HashMap::new(),
            unique_by_source: HashMap::new(),
        };
        w.run_meta_now("scan_started_at")?;
        Ok(w)
    }

    pub fn run_meta(&self, key: &str, value: &str) -> AppResult<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO run_meta(key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(|e| internal(format!("run_meta {key}: {e}")))?;
        Ok(())
    }

    pub fn run_meta_now(&self, key: &str) -> AppResult<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO run_meta(key, value) VALUES (?1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                params![key],
            )
            .map_err(|e| internal(format!("run_meta {key}: {e}")))?;
        Ok(())
    }

    /// Checkpoint the run database before publication.  The scan index uses
    /// WAL while it is mutable, but report publication copies the database
    /// file into an immutable bundle; truncating the WAL here ensures the
    /// copied file contains every committed row without relying on a sidecar
    /// `-wal` file being copied along with it.
    pub fn checkpoint_for_publication(&mut self) -> AppResult<()> {
        self.flush()?;
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| internal(format!("checkpoint run index: {e}")))?;
        Ok(())
    }

    pub fn queue_entry(&mut self, entry: NewEntry) {
        self.pending.push(entry);
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn since_flush(&self) -> Duration {
        self.last_flush.elapsed()
    }

    /// Commit pending entries and excluded-count upserts in one transaction.
    /// Identity dedupe is applied here (insertion order = scan order).
    pub fn flush(&mut self) -> AppResult<()> {
        if self.pending.is_empty() && self.excluded_buf.is_empty() {
            self.last_flush = Instant::now();
            return Ok(());
        }
        let tx = self
            .conn
            .transaction()
            .map_err(|e| internal(format!("begin batch: {e}")))?;
        {
            let mut stmt = tx
                .prepare_cached(INSERT_ENTRY_SQL)
                .map_err(|e| internal(format!("prepare entry insert: {e}")))?;
            let mut seen = tx
                .prepare_cached("INSERT OR IGNORE INTO seen_identity(identity_key) VALUES (?1)")
                .map_err(|e| internal(format!("prepare seen_identity: {e}")))?;
            for e in self.pending.drain(..) {
                stmt.execute(params![
                    e.source_id,
                    e.parent_entry_id,
                    e.raw_relative_path,
                    e.display_name,
                    i64::from(e.path_encoding_warning),
                    e.entry_kind,
                    e.file_identity_key,
                    if e.file_identity_key.is_some() {
                        "reliable"
                    } else {
                        "unknown"
                    },
                    e.device_id,
                    e.inode_id,
                    e.nlink,
                    e.uid,
                    e.gid,
                    e.mode,
                    e.size_bytes,
                    e.allocated_bytes_estimate,
                    e.mtime.map(|t| t.0),
                    e.mtime.map(|t| t.1),
                    e.atime.map(|t| t.0),
                    e.atime.map(|t| t.1),
                    e.ctime.map(|t| t.0),
                    e.ctime.map(|t| t.1),
                    e.category_id,
                    e.extension,
                    e.scan_error,
                ])
                .map_err(|e| internal(format!("insert entry: {e}")))?;
                if e.entry_kind == "regular_file" {
                    let acc = self
                        .unique_by_source
                        .entry(e.source_id.clone())
                        .or_insert((Some(0), Some(0)));
                    let (Some(key), Some(size)) = (&e.file_identity_key, e.size_bytes) else {
                        acc.0 = None;
                        acc.1 = None;
                        continue;
                    };
                    let n = seen
                        .execute(params![key])
                        .map_err(|e| internal(format!("seen_identity: {e}")))?;
                    if n > 0 {
                        if let Some(total) = acc.0 {
                            acc.0 = Some(
                                total
                                    .checked_add(u64::try_from(size).map_err(|_| {
                                        internal("唯一逻辑字节数包含负数或超出 u64")
                                    })?)
                                    .ok_or_else(|| internal("唯一逻辑字节数溢出"))?,
                            );
                        }
                        if let (Some(total), Some(allocated)) = (acc.1, e.allocated_bytes_estimate)
                        {
                            acc.1 = Some(
                                total
                                    .checked_add(u64::try_from(allocated).map_err(|_| {
                                        internal("唯一分配字节数包含负数或超出 u64")
                                    })?)
                                    .ok_or_else(|| internal("唯一分配字节数溢出"))?,
                            );
                        } else {
                            acc.1 = None;
                        }
                    }
                }
            }
            let mut ups = tx
                .prepare_cached(
                    "INSERT INTO dir_excluded(entry_id, n) VALUES (?1, ?2) \
                     ON CONFLICT(entry_id) DO UPDATE SET n = n + excluded.n",
                )
                .map_err(|e| internal(format!("prepare dir_excluded: {e}")))?;
            for (id, n) in self.excluded_buf.drain() {
                ups.execute(params![id, n as i64])
                    .map_err(|e| internal(format!("dir_excluded upsert: {e}")))?;
            }
        }
        tx.commit()
            .map_err(|e| internal(format!("commit batch: {e}")))?;
        self.last_flush = Instant::now();
        Ok(())
    }

    /// Look up a directory's entry_id, flushing pending rows first. Used when
    /// a directory is popped from the frontier (its row was queued when the
    /// directory was discovered in its parent's listing).
    pub fn dir_entry_id(&mut self, source_id: &str, rel: &[u8]) -> AppResult<Option<i64>> {
        self.flush()?;
        self.conn
            .query_row(
                "SELECT entry_id FROM entries WHERE source_id = ?1 AND raw_relative_path = ?2",
                params![source_id, rel],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| internal(format!("lookup dir entry: {e}")))
    }

    /// Spill frontier directories to the `frontier` table. Resolves each
    /// entry_id first (schema stores parent_entry_id for rebuild after an
    /// interrupted run).
    pub fn spill_frontier(&mut self, source_id: &str, rels: &mut Vec<Vec<u8>>) -> AppResult<()> {
        if rels.is_empty() {
            return Ok(());
        }
        self.flush()?;
        let tx = self
            .conn
            .transaction()
            .map_err(|e| internal(format!("begin frontier spill: {e}")))?;
        {
            let mut sel = tx
                .prepare_cached(
                    "SELECT entry_id FROM entries WHERE source_id = ?1 AND raw_relative_path = ?2",
                )
                .map_err(|e| internal(format!("prepare frontier lookup: {e}")))?;
            let mut ins = tx
                .prepare_cached(
                    "INSERT OR IGNORE INTO frontier(source_id, parent_entry_id, raw_relative_path) \
                     VALUES (?1, ?2, ?3)",
                )
                .map_err(|e| internal(format!("prepare frontier insert: {e}")))?;
            for rel in rels.drain(..) {
                let id: Option<i64> = sel
                    .query_row(params![source_id, rel], |r| r.get(0))
                    .optional()
                    .map_err(|e| internal(format!("frontier lookup: {e}")))?;
                let Some(id) = id else {
                    return Err(internal("frontier directory missing its entries row"));
                };
                ins.execute(params![source_id, id, rel])
                    .map_err(|e| internal(format!("frontier insert: {e}")))?;
            }
        }
        tx.commit()
            .map_err(|e| internal(format!("commit frontier spill: {e}")))?;
        Ok(())
    }

    /// Reload up to `FRONTIER_RELOAD_BATCH` spilled directories (FIFO),
    /// deleting them from the table atomically.
    pub fn reload_frontier(
        &mut self,
        source_id: &str,
        out: &mut VecDeque<(Option<i64>, Vec<u8>)>,
    ) -> AppResult<()> {
        let mut stmt = self
            .conn
            .prepare(
                "DELETE FROM frontier WHERE id IN \
                 (SELECT id FROM frontier WHERE source_id = ?1 ORDER BY id LIMIT ?2) \
                 RETURNING parent_entry_id, raw_relative_path",
            )
            .map_err(|e| internal(format!("prepare frontier reload: {e}")))?;
        let rows = stmt
            .query_map(params![source_id, FRONTIER_RELOAD_BATCH], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| internal(format!("frontier reload: {e}")))?;
        for row in rows {
            let (id, rel) = row.map_err(|e| internal(format!("frontier reload row: {e}")))?;
            out.push_back((Some(id), rel));
        }
        Ok(())
    }

    pub fn add_excluded(&mut self, parent_entry_id: i64) {
        *self.excluded_buf.entry(parent_entry_id).or_insert(0) += 1;
    }

    pub fn excluded_buf_len(&self) -> usize {
        self.excluded_buf.len()
    }

    /// Record one scan error row; past the 10,000-row cap only the counters
    /// (kept by the walk and source_observations) keep accumulating (spec
    /// 10.4).
    pub fn record_error(
        &mut self,
        source_id: &str,
        path: Option<&[u8]>,
        errno: Option<i64>,
        category: &str,
        message: &str,
    ) -> AppResult<()> {
        if self.errors_written >= MAX_ERROR_ROWS {
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT INTO scan_errors(source_id, raw_relative_path, errno, category, message, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                params![source_id, path, errno, category, message],
            )
            .map_err(|e| internal(format!("insert scan_error: {e}")))?;
        self.errors_written += 1;
        Ok(())
    }

    pub fn set_entry_scan_error(&mut self, entry_id: i64, message: &str) -> AppResult<()> {
        self.conn
            .execute(
                "UPDATE entries SET scan_error = ?2 WHERE entry_id = ?1",
                params![entry_id, message],
            )
            .map_err(|e| internal(format!("set entry scan_error: {e}")))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_observation(
        &mut self,
        source_id: &str,
        status: &str,
        error_count: u64,
        vanished_count: u64,
        unstable_count: u64,
        excluded_count: u64,
        detail: Option<&str>,
    ) -> AppResult<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO source_observations \
                 (source_id, status, error_count, vanished_count, unstable_count, excluded_count, detail) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    source_id,
                    status,
                    error_count as i64,
                    vanished_count as i64,
                    unstable_count as i64,
                    excluded_count as i64,
                    detail
                ],
            )
            .map_err(|e| internal(format!("record observation: {e}")))?;
        Ok(())
    }

    /// (unique_logical_bytes, unique_allocated_bytes) accumulated for a
    /// source during this run.
    pub fn source_unique(&self, source_id: &str) -> (Option<u64>, Option<u64>) {
        self.unique_by_source
            .get(source_id)
            .copied()
            .unwrap_or((None, None))
    }

    /// Post-traversal finalization: DFS interval assignment, then SQL-side
    /// aggregates. Returns Ok(true) if cancelled mid-way (partial
    /// finalization is rolled back per phase; the index stays consistent).
    pub fn finalize(&mut self, source_ids: &[String], control: &ScanControl) -> AppResult<bool> {
        self.flush()?;
        for sid in source_ids {
            if control.is_cancelled() {
                return Ok(true);
            }
            if index_aggregates::assign_dfs_intervals(&self.conn, sid, control)? {
                return Ok(true);
            }
        }
        if control.is_cancelled() {
            return Ok(true);
        }
        index_aggregates::compute_aggregates(&self.conn, control)
    }
}
