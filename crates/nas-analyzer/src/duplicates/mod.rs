//! Duplicate detection engine (spec 9, F09). Only the hashing core for now;
//! bucketing/grouping over the run index lands with M4.
//!
//! Invariants enforced here:
//! - sampling is ONLY a pre-filter; a duplicate is confirmed solely by full
//!   SHA-256 over the whole file (spec 9.2 stages B/C/D);
//! - files are read through caller-provided FDs obtained from fssecure;
//! - streaming 1 MiB buffer, never whole-file reads into memory;
//! - identity/size/mtime/ctime are re-checked on the open FD before and after
//!   the full read; changes → Unstable, never a confirmed group member.

pub mod hashing;
pub mod ratelimit;

pub use hashing::{
    HASH_ALGORITHM_VERSION, HashOutcome, HashVerdict, SAMPLE_REGION, SAMPLE_THRESHOLD,
    cache_key_string, full_sha256, full_sha256_limited, full_sha256_limited_with_acquire,
    sample_fingerprint, sample_fingerprint_limited, sample_fingerprint_limited_with_acquire,
};
pub use ratelimit::TokenBucket;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError, bounded};
use fssecure::{OpenOptions, SecureRoot};
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{AppError, AppResult, ErrorCode};
use crate::profile::{DuplicateReadPolicy, ProfileDuplicates};
use crate::resource::FileOpenBudget;
use crate::scanner::{ScanControl, ScanSource};
use crate::source::{ReadPolicy, StorageKind};

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

fn validation(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, msg)
}

fn checkpoint_for_publication(conn: &Connection) -> AppResult<()> {
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|error| internal(format!("checkpoint duplicate index: {error}")))?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashStageResult {
    pub partial: bool,
    pub hashed_bytes: u64,
    pub group_count: u64,
}

#[derive(Debug)]
struct Candidate {
    entry_id: i64,
    source_id: String,
    raw_path: Vec<u8>,
    size: i64,
    device: u64,
    inode: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    identity: String,
}

fn join_raw(root: &[u8], path: &[u8]) -> Vec<u8> {
    if root.is_empty() {
        return path.to_vec();
    }
    if path.is_empty() {
        return root.to_vec();
    }
    let mut output = Vec::with_capacity(root.len() + path.len() + 1);
    output.extend_from_slice(root);
    output.push(b'/');
    output.extend_from_slice(path);
    output
}

fn decimal(raw: &str, field: &str) -> AppResult<u64> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(validation(format!("{field} 必须是十进制字节字符串")));
    }
    raw.parse::<u64>()
        .map_err(|_| validation(format!("{field} 超出 u64 范围")))
}

fn roots(sources: &[ScanSource]) -> BTreeMap<String, ScanSource> {
    // Keep only source descriptions here. A SecureRoot owns a root FD, so it
    // must be opened inside the scope of the shared file-open permit.
    sources
        .iter()
        .map(|scan| (scan.source.id.clone(), scan.clone()))
        .collect()
}

fn candidate_key(candidate: &Candidate, config: &ProfileDuplicates) -> String {
    let mut key = format!("size:{}", candidate.size);
    if config.match_name {
        key.push_str("|name:");
        let basename = candidate
            .raw_path
            .rsplit(|byte| *byte == b'/')
            .next()
            .unwrap_or(&candidate.raw_path);
        key.push_str(&hex::encode(basename));
    }
    if config.match_mtime {
        key.push_str("|mtime:");
        key.push_str(&format!("{}.{}", candidate.mtime.0, candidate.mtime.1));
    }
    key
}

fn map_candidate(row: &rusqlite::Row<'_>) -> rusqlite::Result<Candidate> {
    Ok(Candidate {
        entry_id: row.get(0)?,
        source_id: row.get(1)?,
        raw_path: row.get(2)?,
        size: row.get(3)?,
        device: row
            .get::<_, String>(4)?
            .parse()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        inode: row
            .get::<_, String>(5)?
            .parse()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        mtime: (row.get(6)?, row.get(7)?),
        ctime: (row.get(8)?, row.get(9)?),
        identity: row.get(10)?,
    })
}

fn sqlite_size(value: u64, field: &str) -> AppResult<i64> {
    i64::try_from(value).map_err(|_| validation(format!("{field} 超出 SQLite INTEGER 范围")))
}

fn budget_allows(budget: Option<u64>, already_read: u64, next_bytes: u64) -> AppResult<bool> {
    let Some(maximum) = budget else {
        return Ok(true);
    };
    let total = already_read
        .checked_add(next_bytes)
        .ok_or_else(|| validation("重复检测读取预算累计溢出"))?;
    Ok(total <= maximum)
}

fn next_size(
    conn: &Connection,
    minimum: i64,
    maximum: Option<i64>,
    previous: Option<i64>,
) -> AppResult<Option<i64>> {
    conn.query_row(
        "SELECT size_bytes
         FROM entries
         WHERE entry_kind = 'regular_file'
           AND size_bytes >= ?1
           AND (?2 IS NULL OR size_bytes <= ?2)
           AND (?3 IS NULL OR size_bytes > ?3)
         GROUP BY size_bytes
         HAVING COUNT(DISTINCT file_identity_key) > 1
         ORDER BY size_bytes
         LIMIT 1",
        params![minimum, maximum, previous],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| internal(format!("读取重复大小桶失败: {error}")))
}

fn next_candidate(
    conn: &Connection,
    size: i64,
    previous_entry_id: Option<i64>,
) -> AppResult<Option<Candidate>> {
    conn.query_row(
        "SELECT entry_id, source_id, raw_relative_path, size_bytes,
                device_id, inode_id, mtime_sec, mtime_nsec, ctime_sec, ctime_nsec,
                file_identity_key
         FROM entries
         WHERE entry_kind = 'regular_file'
           AND size_bytes = ?1
           AND (?2 IS NULL OR entry_id > ?2)
         ORDER BY entry_id
         LIMIT 1",
        params![size, previous_entry_id],
        map_candidate,
    )
    .optional()
    .map_err(|error| internal(format!("读取重复候选失败: {error}")))
}

fn next_hash_candidate(
    conn: &Connection,
    size: i64,
    sample_threshold: i64,
    previous_entry_id: Option<i64>,
) -> AppResult<Option<Candidate>> {
    conn.query_row(
        "SELECT e.entry_id, e.source_id, e.raw_relative_path, e.size_bytes,
                e.device_id, e.inode_id, e.mtime_sec, e.mtime_nsec,
                e.ctime_sec, e.ctime_nsec, e.file_identity_key
         FROM entries e
         JOIN duplicate_candidates c ON c.entry_id = e.entry_id
         WHERE e.entry_kind = 'regular_file'
           AND e.size_bytes = ?1
           AND c.full_sha256 IS NULL
           AND c.skip_reason IS NULL
           AND (?2 IS NULL OR e.entry_id > ?2)
           AND (
               e.size_bytes <= ?3
               OR c.sample_hash IS NULL
               OR EXISTS (
                   SELECT 1
                   FROM duplicate_candidates other
                   WHERE other.size_bytes = c.size_bytes
                     AND other.candidate_key = c.candidate_key
                     AND other.sample_hash = c.sample_hash
                     AND other.skip_reason IS NULL
                     AND other.entry_id <> c.entry_id
               )
           )
         ORDER BY e.entry_id
         LIMIT 1",
        params![size, previous_entry_id, sample_threshold],
        map_candidate,
    )
    .optional()
    .map_err(|error| internal(format!("读取待全量哈希候选失败: {error}")))
}

struct HashTask {
    candidate: Candidate,
    mount_path: PathBuf,
    source_identity_epoch: i64,
    relative_path: Vec<u8>,
    max_bytes: Option<u64>,
}

struct HashTaskResult {
    candidate: Candidate,
    source_identity_epoch: i64,
    opened: bool,
    cancelled_before_open: bool,
    outcome: AppResult<HashOutcome>,
}

fn run_hash_worker(
    tasks: Receiver<HashTask>,
    results: Sender<HashTaskResult>,
    control: &ScanControl,
    limiter: Option<Arc<ratelimit::SharedTokenBucket>>,
    file_open_budget: Arc<FileOpenBudget>,
) {
    while let Ok(task) = tasks.recv() {
        let candidate = task.candidate;
        let source_identity_epoch = task.source_identity_epoch;
        let Some(_root_permit) = file_open_budget.acquire(|| control.is_cancelled()) else {
            if results
                .send(HashTaskResult {
                    candidate,
                    source_identity_epoch,
                    opened: false,
                    cancelled_before_open: true,
                    outcome: Ok(HashOutcome {
                        verdict: HashVerdict::Cancelled,
                        used_noatime: false,
                        bytes_read: 0,
                    }),
                })
                .is_err()
            {
                break;
            }
            continue;
        };
        let (opened, cancelled_before_open, outcome) =
            match SecureRoot::open(task.mount_path.as_os_str()) {
                Ok(root) => match file_open_budget.acquire(|| control.is_cancelled()) {
                    Some(_file_permit) => match root.open_file(
                        OsStr::from_bytes(&task.relative_path),
                        OpenOptions {
                            noatime: true,
                            ..OpenOptions::default()
                        },
                    ) {
                        Ok(file) => {
                            let expected = (
                                candidate.device,
                                candidate.inode,
                                candidate.size,
                                candidate.mtime.0,
                                candidate.mtime.1,
                                candidate.ctime.0,
                                candidate.ctime.1,
                            );
                            let limiter = limiter.clone();
                            let mut acquire = |bytes| {
                                limiter.as_ref().is_none_or(|limiter| {
                                    limiter.acquire(bytes, || control.is_cancelled())
                                })
                            };
                            (
                                true,
                                false,
                                full_sha256_limited_with_acquire(
                                    &file.fd,
                                    expected,
                                    &mut || control.is_cancelled(),
                                    &mut acquire,
                                    task.max_bytes,
                                ),
                            )
                        }
                        Err(error) => (
                            false,
                            false,
                            Err(internal(format!("打开重复候选文件失败: {error}"))),
                        ),
                    },
                    None => (
                        false,
                        true,
                        Ok(HashOutcome {
                            verdict: HashVerdict::Cancelled,
                            used_noatime: false,
                            bytes_read: 0,
                        }),
                    ),
                },
                Err(error) => (
                    false,
                    false,
                    Err(AppError::new(
                        ErrorCode::SourceUnavailable,
                        format!("打开哈希来源失败: {error}"),
                    )),
                ),
            };
        if results
            .send(HashTaskResult {
                candidate,
                source_identity_epoch,
                opened,
                cancelled_before_open,
                outcome,
            })
            .is_err()
        {
            break;
        }
    }
}

fn start_hash_workers<'scope>(
    scope: &'scope thread::Scope<'scope, '_>,
    worker_count: u32,
    control: &'scope ScanControl,
    limiter: Option<Arc<ratelimit::SharedTokenBucket>>,
    file_open_budget: Arc<FileOpenBudget>,
) -> (
    Sender<HashTask>,
    Receiver<HashTaskResult>,
    Vec<thread::ScopedJoinHandle<'scope, ()>>,
) {
    let queue_capacity = usize::try_from(worker_count).expect("validated hash_workers");
    let (tasks_tx, tasks_rx) = bounded(queue_capacity);
    let (results_tx, results_rx) = bounded(queue_capacity);
    let mut joins = Vec::with_capacity(queue_capacity);
    for index in 0..worker_count {
        let tasks_rx = tasks_rx.clone();
        let results_tx = results_tx.clone();
        let limiter = limiter.clone();
        let file_open_budget = Arc::clone(&file_open_budget);
        joins.push(scope.spawn(move || {
            let _ = index;
            run_hash_worker(tasks_rx, results_tx, control, limiter, file_open_budget);
        }));
    }
    drop(results_tx);
    (tasks_tx, results_rx, joins)
}

fn persist_hash_result(conn: &Connection, result: HashTaskResult) -> AppResult<(u64, bool, bool)> {
    let entry_id = result.candidate.entry_id;
    if result.cancelled_before_open {
        conn.execute(
            "UPDATE duplicate_candidates SET skip_reason='cancelled'
             WHERE entry_id = ?1",
            [entry_id],
        )?;
        return Ok((0, true, true));
    }
    if !result.opened {
        conn.execute(
            "UPDATE duplicate_candidates SET skip_reason='file_unavailable'
             WHERE entry_id = ?1",
            [entry_id],
        )?;
        return Ok((0, true, false));
    }
    let outcome = result.outcome?;
    let bytes_read = outcome.bytes_read;
    match outcome.verdict {
        HashVerdict::FullHash(hash) => {
            conn.execute(
                "UPDATE duplicate_candidates SET full_sha256 = ?2,
                 verification = 'full' WHERE entry_id = ?1",
                params![entry_id, hash],
            )?;
            conn.execute(
                "INSERT OR REPLACE INTO file_hashes
                 (entry_id, algorithm, algorithm_version, sha256, identity_key,
                  size_bytes, mtime_sec, mtime_nsec, ctime_sec, ctime_nsec,
                  hashed_at, source_identity_epoch)
                 VALUES (?1, 'sha256', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                         strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?10)",
                params![
                    entry_id,
                    i64::from(HASH_ALGORITHM_VERSION),
                    hash,
                    result.candidate.identity,
                    result.candidate.size,
                    result.candidate.mtime.0,
                    result.candidate.mtime.1,
                    result.candidate.ctime.0,
                    result.candidate.ctime.1,
                    result.source_identity_epoch,
                ],
            )?;
            Ok((bytes_read, false, false))
        }
        HashVerdict::Unstable => {
            conn.execute(
                "UPDATE duplicate_candidates SET skip_reason='file_changed',
                 verification='unstable' WHERE entry_id = ?1",
                [entry_id],
            )?;
            Ok((bytes_read, true, false))
        }
        HashVerdict::BudgetExceeded => {
            conn.execute(
                "UPDATE duplicate_candidates SET skip_reason='hash_budget_exceeded'
                 WHERE entry_id = ?1",
                [entry_id],
            )?;
            Ok((bytes_read, true, false))
        }
        HashVerdict::Cancelled => {
            conn.execute(
                "UPDATE duplicate_candidates SET skip_reason='cancelled'
                 WHERE entry_id = ?1",
                [entry_id],
            )?;
            Ok((bytes_read, true, true))
        }
    }
}

fn apply_hash_result(
    conn: &Connection,
    result: HashTaskResult,
    hashed_bytes: &mut u64,
    reserved_bytes: &mut u64,
    partial: &mut bool,
    stop: &mut bool,
) -> AppResult<()> {
    let size = u64::try_from(result.candidate.size)
        .map_err(|_| validation("重复候选大小不能转换为 u64"))?;
    *reserved_bytes = reserved_bytes
        .checked_sub(size)
        .ok_or_else(|| internal("重复检测预留字节数计算错误"))?;
    let (bytes_read, result_partial, result_stop) = persist_hash_result(conn, result)?;
    *hashed_bytes = hashed_bytes
        .checked_add(bytes_read)
        .ok_or_else(|| validation("重复检测已读取字节数溢出"))?;
    *partial |= result_partial;
    *stop |= result_stop;
    Ok(())
}

fn cancel_pending_hash_task(
    conn: &Connection,
    pending: &mut Option<HashTask>,
    reserved_bytes: &mut u64,
) -> AppResult<()> {
    let Some(task) = pending.take() else {
        return Ok(());
    };
    let size =
        u64::try_from(task.candidate.size).map_err(|_| validation("重复候选大小不能转换为 u64"))?;
    *reserved_bytes = reserved_bytes
        .checked_sub(size)
        .ok_or_else(|| internal("重复检测预留字节数计算错误"))?;
    conn.execute(
        "UPDATE duplicate_candidates SET skip_reason='cancelled'
         WHERE entry_id = ?1",
        [task.candidate.entry_id],
    )?;
    Ok(())
}

/// Hash duplicate candidates from a completed run index. Size buckets are
/// streamed one at a time; content is opened only with fssecure and a group
/// is confirmed only by a complete SHA-256.
pub fn process_index(
    index_path: &Path,
    config: &ProfileDuplicates,
    sources: &[ScanSource],
    control: &ScanControl,
    hash_workers: u32,
    hash_read_limit_mib_s: u32,
) -> AppResult<HashStageResult> {
    let file_open_budget = FileOpenBudget::new(16)?;
    process_index_with_budget(
        index_path,
        config,
        sources,
        control,
        hash_workers,
        hash_read_limit_mib_s,
        file_open_budget,
    )
}

pub(crate) fn process_index_with_budget(
    index_path: &Path,
    config: &ProfileDuplicates,
    sources: &[ScanSource],
    control: &ScanControl,
    hash_workers: u32,
    hash_read_limit_mib_s: u32,
    file_open_budget: Arc<FileOpenBudget>,
) -> AppResult<HashStageResult> {
    if !config.enabled {
        return Ok(HashStageResult {
            partial: false,
            hashed_bytes: 0,
            group_count: 0,
        });
    }
    if !(1..=4).contains(&hash_workers) {
        return Err(validation("hash_workers 必须为 1–4"));
    }
    if file_open_budget.capacity() < 2 {
        return Err(AppError::new(
            ErrorCode::ResourceBusy,
            "重复检测至少需要同时打开来源根和候选文件",
        ));
    }
    let min_size = decimal(&config.min_size_bytes, "duplicates.min_size_bytes")?;
    let min_size_sql = sqlite_size(min_size, "duplicates.min_size_bytes")?;
    let max_size = config
        .max_size_bytes
        .as_deref()
        .map(|v| decimal(v, "duplicates.max_size_bytes"))
        .transpose()?;
    let max_size_sql = max_size
        .map(|value| sqlite_size(value, "duplicates.max_size_bytes"))
        .transpose()?;
    if max_size.is_some_and(|maximum| maximum < min_size) {
        return Err(validation(
            "duplicates.max_size_bytes 不能小于 min_size_bytes",
        ));
    }
    let budget = config
        .hash_budget_bytes
        .as_deref()
        .map(|v| decimal(v, "duplicates.hash_budget_bytes"))
        .transpose()?;
    let mut conn =
        Connection::open(index_path).map_err(|e| internal(format!("打开重复检测索引失败: {e}")))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| internal(format!("设置重复检测超时失败: {e}")))?;
    conn.execute_batch("DELETE FROM duplicate_members; DELETE FROM duplicate_groups; DELETE FROM duplicate_candidates; DELETE FROM file_hashes;")
        .map_err(|e| internal(format!("清理重复检测表失败: {e}")))?;
    let roots = roots(sources);
    let limiter = (hash_read_limit_mib_s > 0)
        .then(|| ratelimit::SharedTokenBucket::new(u64::from(hash_read_limit_mib_s) * 1024 * 1024));
    let mut hashed_bytes = 0u64;
    let mut partial = false;
    let sample_threshold_sql = sqlite_size(SAMPLE_THRESHOLD, "sample threshold")?;
    let sample_bytes = SAMPLE_REGION
        .checked_mul(3)
        .ok_or_else(|| internal("重复抽样字节数溢出"))?;
    let mut size_cursor = None;
    let mut stop = false;
    while let Some(size) = next_size(&conn, min_size_sql, max_size_sql, size_cursor)? {
        size_cursor = Some(size);
        let mut entry_cursor = None;
        while let Some(candidate) = next_candidate(&conn, size, entry_cursor)? {
            entry_cursor = Some(candidate.entry_id);
            if control.is_cancelled() {
                partial = true;
                stop = true;
                break;
            }
            let key = candidate_key(&candidate, config);
            conn.execute(
                "INSERT INTO duplicate_candidates(size_bytes, candidate_key, entry_id)
                 VALUES (?1, ?2, ?3)",
                params![candidate.size, key, candidate.entry_id],
            )
            .map_err(|error| internal(format!("保存重复候选失败: {error}")))?;
            let Some(scan_source) = roots.get(&candidate.source_id) else {
                partial = true;
                conn.execute(
                    "UPDATE duplicate_candidates SET skip_reason='source_unavailable'
                     WHERE entry_id = ?1",
                    [candidate.entry_id],
                )?;
                continue;
            };
            let source = &scan_source.source;
            if source.read_policy != ReadPolicy::ContentAllowed {
                partial = true;
                conn.execute(
                    "UPDATE duplicate_candidates SET skip_reason='metadata_only'
                     WHERE entry_id = ?1",
                    [candidate.entry_id],
                )?;
                continue;
            }
            if source.storage_kind != StorageKind::Local
                && config.content_read_policy == DuplicateReadPolicy::RespectSourcePolicy
            {
                partial = true;
                conn.execute(
                    "UPDATE duplicate_candidates SET skip_reason='remote_content_disallowed'
                     WHERE entry_id = ?1",
                    [candidate.entry_id],
                )?;
                continue;
            }
            let size_u64 = u64::try_from(candidate.size)
                .map_err(|_| validation("重复候选大小不能转换为 u64"))?;
            if size_u64 > SAMPLE_THRESHOLD && !budget_allows(budget, hashed_bytes, sample_bytes)? {
                partial = true;
                conn.execute(
                    "UPDATE duplicate_candidates SET skip_reason='hash_budget_exceeded'
                     WHERE entry_id = ?1",
                    [candidate.entry_id],
                )?;
                continue;
            }
            let relative = join_raw(&source.raw_relative_root, &candidate.raw_path);
            let Some(_root_permit) = file_open_budget.acquire(|| control.is_cancelled()) else {
                partial = true;
                conn.execute(
                    "UPDATE duplicate_candidates SET skip_reason='cancelled'
                     WHERE entry_id = ?1",
                    [candidate.entry_id],
                )?;
                stop = true;
                break;
            };
            let root = match SecureRoot::open(scan_source.mount_path.as_os_str()) {
                Ok(root) => root,
                Err(_) => {
                    partial = true;
                    conn.execute(
                        "UPDATE duplicate_candidates SET skip_reason='source_unavailable'
                         WHERE entry_id = ?1",
                        [candidate.entry_id],
                    )?;
                    continue;
                }
            };
            let Some(_file_permit) = file_open_budget.acquire(|| control.is_cancelled()) else {
                partial = true;
                conn.execute(
                    "UPDATE duplicate_candidates SET skip_reason='cancelled'
                     WHERE entry_id = ?1",
                    [candidate.entry_id],
                )?;
                stop = true;
                break;
            };
            let opened = match root.open_file(
                OsStr::from_bytes(&relative),
                OpenOptions {
                    noatime: true,
                    ..OpenOptions::default()
                },
            ) {
                Ok(file) => file,
                Err(_) => {
                    partial = true;
                    conn.execute(
                        "UPDATE duplicate_candidates SET skip_reason='file_unavailable'
                         WHERE entry_id = ?1",
                        [candidate.entry_id],
                    )?;
                    continue;
                }
            };
            if opened.stat.identity.device_id != candidate.device
                || opened.stat.identity.inode_id != candidate.inode
                || opened.stat.size_bytes != candidate.size
                || opened.stat.mtime != candidate.mtime
                || opened.stat.ctime != candidate.ctime
            {
                partial = true;
                conn.execute(
                    "UPDATE duplicate_candidates SET skip_reason='file_changed',
                     verification='unstable' WHERE entry_id = ?1",
                    [candidate.entry_id],
                )?;
                continue;
            }
            if size_u64 > SAMPLE_THRESHOLD {
                let limiter_for_sample = limiter.clone();
                let mut acquire = |bytes| {
                    limiter_for_sample
                        .as_ref()
                        .is_none_or(|limiter| limiter.acquire(bytes, || control.is_cancelled()))
                };
                let sample = match sample_fingerprint_limited_with_acquire(
                    &opened.fd,
                    size_u64,
                    &mut || control.is_cancelled(),
                    &mut acquire,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        partial = true;
                        conn.execute(
                            "UPDATE duplicate_candidates SET skip_reason='file_unavailable'
                             WHERE entry_id = ?1",
                            [candidate.entry_id],
                        )?;
                        continue;
                    }
                };
                hashed_bytes = hashed_bytes
                    .checked_add(sample.bytes_read)
                    .ok_or_else(|| validation("重复检测已读取字节数溢出"))?;
                if sample.cancelled {
                    partial = true;
                    conn.execute(
                        "UPDATE duplicate_candidates SET skip_reason='cancelled'
                         WHERE entry_id = ?1",
                        [candidate.entry_id],
                    )?;
                    stop = true;
                    break;
                }
                if let Some(fingerprint) = sample.fingerprint {
                    conn.execute(
                        "UPDATE duplicate_candidates SET sample_hash = ?2,
                         verification = 'sampled' WHERE entry_id = ?1",
                        params![candidate.entry_id, fingerprint],
                    )?;
                }
            }
        }
        if stop {
            break;
        }

        let limiter_for_workers = limiter.clone();
        thread::scope(|scope| -> AppResult<()> {
            let (tasks_tx, results_rx, joins) = start_hash_workers(
                scope,
                hash_workers,
                control,
                limiter_for_workers,
                Arc::clone(&file_open_budget),
            );
            let mut hash_cursor = None;
            let mut pending = None;
            let mut input_done = false;
            let mut reserved_bytes = 0u64;
            while !stop {
                if pending.is_none() && !input_done {
                    let Some(candidate) =
                        next_hash_candidate(&conn, size, sample_threshold_sql, hash_cursor)?
                    else {
                        input_done = true;
                        continue;
                    };
                    hash_cursor = Some(candidate.entry_id);
                    if control.is_cancelled() {
                        partial = true;
                        stop = true;
                        continue;
                    }
                    let size_u64 = u64::try_from(candidate.size)
                        .map_err(|_| validation("重复候选大小不能转换为 u64"))?;
                    let budget_in_use = hashed_bytes
                        .checked_add(reserved_bytes)
                        .ok_or_else(|| validation("重复检测预算累计溢出"))?;
                    if !budget_allows(budget, budget_in_use, size_u64)? {
                        partial = true;
                        conn.execute(
                            "UPDATE duplicate_candidates SET skip_reason='hash_budget_exceeded'
                             WHERE entry_id = ?1",
                            [candidate.entry_id],
                        )?;
                        continue;
                    }
                    let Some(scan_source) = roots.get(&candidate.source_id) else {
                        partial = true;
                        conn.execute(
                            "UPDATE duplicate_candidates SET skip_reason='source_unavailable'
                             WHERE entry_id = ?1",
                            [candidate.entry_id],
                        )?;
                        continue;
                    };
                    let source = &scan_source.source;
                    reserved_bytes = reserved_bytes
                        .checked_add(size_u64)
                        .ok_or_else(|| validation("重复检测预留字节数溢出"))?;
                    pending = Some(HashTask {
                        relative_path: join_raw(&source.raw_relative_root, &candidate.raw_path),
                        source_identity_epoch: source.identity_epoch,
                        max_bytes: budget.map(|maximum| maximum - budget_in_use),
                        mount_path: scan_source.mount_path.clone(),
                        candidate,
                    });
                }

                if let Some(task) = pending.take() {
                    match tasks_tx.try_send(task) {
                        Ok(()) => {}
                        Err(TrySendError::Full(task)) => {
                            pending = Some(task);
                            loop {
                                match results_rx.recv_timeout(std::time::Duration::from_millis(50))
                                {
                                    Ok(result) => {
                                        apply_hash_result(
                                            &conn,
                                            result,
                                            &mut hashed_bytes,
                                            &mut reserved_bytes,
                                            &mut partial,
                                            &mut stop,
                                        )?;
                                        break;
                                    }
                                    Err(RecvTimeoutError::Timeout) => {
                                        if control.is_cancelled() {
                                            partial = true;
                                            stop = true;
                                            cancel_pending_hash_task(
                                                &conn,
                                                &mut pending,
                                                &mut reserved_bytes,
                                            )?;
                                            break;
                                        }
                                    }
                                    Err(RecvTimeoutError::Disconnected) => {
                                        return Err(internal("重复检测哈希 worker 提前退出"));
                                    }
                                }
                            }
                        }
                        Err(TrySendError::Disconnected(_)) => {
                            return Err(internal("重复检测哈希 worker 通道已断开"));
                        }
                    }
                } else if input_done {
                    break;
                }
            }
            cancel_pending_hash_task(&conn, &mut pending, &mut reserved_bytes)?;
            drop(tasks_tx);
            loop {
                match results_rx.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok(result) => apply_hash_result(
                        &conn,
                        result,
                        &mut hashed_bytes,
                        &mut reserved_bytes,
                        &mut partial,
                        &mut stop,
                    )?,
                    Err(RecvTimeoutError::Timeout) => {
                        if control.is_cancelled() {
                            partial = true;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            for join in joins {
                join.join()
                    .map_err(|_| internal("重复检测哈希 worker 线程异常退出"))?;
            }
            Ok(())
        })?;
        if stop {
            break;
        }
    }
    let group_count = build_groups(&mut conn, config.max_listed_files, &mut partial)?;
    checkpoint_for_publication(&conn)?;
    Ok(HashStageResult {
        partial,
        hashed_bytes,
        group_count,
    })
}

fn build_groups(
    conn: &mut Connection,
    max_listed_files: u32,
    partial: &mut bool,
) -> AppResult<u64> {
    let limit = i64::from(max_listed_files.clamp(1, 100_000));
    conn.execute_batch(
        "DROP TABLE IF EXISTS temp.duplicate_group_work;
         CREATE TEMP TABLE duplicate_group_work AS
         SELECT c.size_bytes, c.candidate_key, c.full_sha256,
                COUNT(*) AS member_count,
                COUNT(DISTINCT e.file_identity_key) AS distinct_count
         FROM duplicate_candidates c
         JOIN entries e ON e.entry_id = c.entry_id
         WHERE c.full_sha256 IS NOT NULL
         GROUP BY c.size_bytes, c.candidate_key, c.full_sha256
         HAVING COUNT(DISTINCT e.file_identity_key) > 1
         ORDER BY c.size_bytes DESC, c.full_sha256",
    )
    .map_err(|error| internal(format!("准备重复组查询失败: {error}")))?;
    let mut group_cursor = 0_i64;
    let mut group_count = 0_u64;
    loop {
        let next = conn
            .query_row(
                "SELECT rowid, size_bytes, candidate_key, full_sha256,
                        member_count, distinct_count
                 FROM temp.duplicate_group_work
                 WHERE rowid > ?1
                 ORDER BY rowid
                 LIMIT 1",
                [group_cursor],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| internal(format!("读取重复组失败: {error}")))?;
        let Some((rowid, size, key, hash, member_count, distinct_count)) = next else {
            break;
        };
        group_cursor = rowid;
        let redundancy = size
            .checked_mul(
                distinct_count
                    .checked_sub(1)
                    .ok_or_else(|| validation("重复独立副本数无效"))?,
            )
            .ok_or_else(|| validation("重复逻辑冗余字节数溢出"))?;
        let truncated = member_count > limit;
        *partial |= truncated;
        conn.execute(
            "INSERT INTO duplicate_groups(size_bytes, sha256, member_count, listed_member_count, logical_redundancy_bytes, truncated, verification)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'full')",
            params![
                size,
                hash,
                member_count,
                member_count.min(limit),
                redundancy,
                i64::from(truncated)
            ],
        )?;
        let group_id = conn.last_insert_rowid();
        let mut seen = BTreeSet::new();
        let mut member_cursor = 0_i64;
        let mut listed = 0_i64;
        while listed < limit {
            let member = conn
                .query_row(
                    "SELECT c.entry_id, e.file_identity_key
                     FROM duplicate_candidates c
                     JOIN entries e ON e.entry_id = c.entry_id
                     WHERE c.size_bytes = ?1
                       AND c.candidate_key = ?2
                       AND c.full_sha256 = ?3
                       AND c.entry_id > ?4
                     ORDER BY c.entry_id
                     LIMIT 1",
                    params![size, key, hash, member_cursor],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|error| internal(format!("读取重复成员失败: {error}")))?;
            let Some((entry_id, identity)) = member else {
                break;
            };
            member_cursor = entry_id;
            let alias = !seen.insert(identity);
            conn.execute(
                "INSERT INTO duplicate_members(group_id, entry_id, is_hardlink_alias)
                 VALUES (?1, ?2, ?3)",
                params![group_id, entry_id, i64::from(alias)],
            )?;
            listed = listed
                .checked_add(1)
                .ok_or_else(|| validation("重复成员列举计数溢出"))?;
        }
        group_count = group_count
            .checked_add(1)
            .ok_or_else(|| validation("重复组数量溢出"))?;
    }
    conn.execute_batch("DROP TABLE temp.duplicate_group_work;")
        .map_err(|error| internal(format!("清理重复组临时表失败: {error}")))?;
    Ok(group_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::migrate::{self, INDEX_MIGRATIONS};
    use tempfile::tempdir;

    #[test]
    fn process_index_checkpoints_wal_before_return() {
        let root = tempdir().unwrap();
        let index_path = root.path().join("index.sqlite");
        let wal_path = root.path().join("index.sqlite-wal");
        let mut setup = Connection::open(&index_path).unwrap();
        migrate::apply(&mut setup, INDEX_MIGRATIONS).unwrap();
        setup
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA wal_autocheckpoint=0;
                 INSERT INTO run_meta(key, value) VALUES ('pending', 'wal');",
            )
            .unwrap();
        assert!(std::fs::metadata(&wal_path).unwrap().len() > 0);

        let config = ProfileDuplicates {
            enabled: true,
            ..ProfileDuplicates::default()
        };
        let result = process_index(&index_path, &config, &[], &ScanControl::new(), 1, 0).unwrap();

        assert_eq!(result.group_count, 0);
        assert_eq!(std::fs::metadata(&wal_path).unwrap().len(), 0);
        drop(setup);
    }

    #[test]
    fn duplicate_hashing_requires_room_for_root_and_file_handles() {
        let fixture = crate::fixture::FixtureRoot::new().unwrap();
        let index_path = fixture.root.join("index.sqlite");
        let mut setup = Connection::open(&index_path).unwrap();
        migrate::apply(&mut setup, INDEX_MIGRATIONS).unwrap();
        let config = ProfileDuplicates {
            enabled: true,
            ..ProfileDuplicates::default()
        };
        let budget = FileOpenBudget::new(1).unwrap();
        let error =
            process_index_with_budget(&index_path, &config, &[], &ScanControl::new(), 1, 0, budget)
                .unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceBusy);
        drop(setup);
    }

    #[test]
    fn hash_worker_holds_root_permit_before_waiting_for_file_permit() {
        let fixture = crate::fixture::FixtureRoot::new().unwrap();
        std::fs::write(fixture.root.join("candidate"), []).unwrap();
        let file_open_budget = FileOpenBudget::new(2).unwrap();
        let held_permit = file_open_budget.acquire(|| false).unwrap();
        let control = ScanControl::new();
        let (tasks_tx, tasks_rx) = bounded(1);
        let (results_tx, results_rx) = bounded(1);

        thread::scope(|scope| {
            let worker = scope.spawn(|| {
                run_hash_worker(
                    tasks_rx,
                    results_tx,
                    &control,
                    None,
                    Arc::clone(&file_open_budget),
                )
            });
            tasks_tx
                .send(HashTask {
                    candidate: Candidate {
                        entry_id: 1,
                        source_id: "source".to_owned(),
                        raw_path: b"candidate".to_vec(),
                        size: 0,
                        device: 0,
                        inode: 0,
                        mtime: (0, 0),
                        ctime: (0, 0),
                        identity: String::new(),
                    },
                    mount_path: fixture.root.clone(),
                    source_identity_epoch: 0,
                    relative_path: b"candidate".to_vec(),
                    max_bytes: None,
                })
                .unwrap();

            assert!(matches!(
                results_rx.recv_timeout(std::time::Duration::from_millis(100)),
                Err(RecvTimeoutError::Timeout)
            ));

            control.cancel();
            let result = results_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            assert!(!result.opened);
            assert!(result.cancelled_before_open);

            drop(tasks_tx);
            worker.join().unwrap();
        });

        drop(held_permit);
        let _root_permit = file_open_budget.acquire(|| false).unwrap();
        let _file_permit = file_open_budget.acquire(|| false).unwrap();
    }
}
