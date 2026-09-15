//! Durable job / queue core (spec 7.2, 7.3, 15.6, 16.1).
//!
//! All functions are synchronous and operate directly on a
//! [`rusqlite::Connection`]; callers run them inside the store writer thread
//! (`store::DbWriter`). Jobs, schedule occurrences and job events are always
//! persisted in the control database — never kept only in memory.
//!
//! State machine (spec 7.3):
//! `QUEUED → RUNNING → SUCCEEDED | PARTIAL | FAILED`, control branches
//! `RUNNING → PAUSING → PAUSED → RUNNING` and
//! `QUEUED/RUNNING/PAUSING/PAUSED → CANCELLING → CANCELLED`. Unfinished jobs
//! after a process restart become `INTERRUPTED` (`mark_interrupted`).
//! Cancellation always wins over a racing finish: finishing a job that is
//! `CANCELLING` transitions it to `CANCELLED`, never to a success state.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{AppError, AppResult, ErrorCode};

/// Stored timestamps use SQLite's fixed-width UTC format so lexicographic
/// ordering equals chronological ordering (required for cursor pagination).
const SQL_NOW: &str = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

/// Per-job event retention bound (spec 15.6: event streams must be bounded).
pub const MAX_EVENTS_PER_JOB: i64 = 1000;

/// Maximum page size for the jobs center listing (spec 8.4: cap 200).
pub const MAX_JOB_PAGE_SIZE: usize = 200;

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

fn json_column(value: &str, column: &str) -> rusqlite::Result<serde_json::Value> {
    serde_json::from_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{column} JSON 无效: {error}"),
            )),
        )
    })
}

fn not_found(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::NotFound, msg)
}

fn state_conflict(job_id: &str, state: JobState, action: &str) -> AppError {
    AppError::new(
        ErrorCode::JobStateConflict,
        format!(
            "任务当前状态为 {}，不允许执行 {action} 操作",
            state.as_str()
        ),
    )
    .with_details(serde_json::json!({
        "job_id": job_id,
        "state": state.as_str(),
        "action": action,
    }))
}

fn scan_control_only(job: &Job, action: &str) -> AppResult<()> {
    if job.job_type != JobType::Scan {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            format!("只有 scan 任务支持 {action} 操作"),
        )
        .with_details(serde_json::json!({
            "job_id": job.id,
            "type": job.job_type.as_str(),
            "state": job.state.as_str(),
            "action": action,
        })));
    }
    Ok(())
}

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant),+
        }
        impl $name {
            pub fn as_str(&self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }
            pub fn parse(s: &str) -> AppResult<Self> {
                match s {
                    $($text => Ok(Self::$variant),)+
                    other => Err(internal(format!(
                        "未知的{}取值: {other:?}", stringify!($name)
                    ))),
                }
            }
            pub const ALL: &[Self] = &[$(Self::$variant),+];
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::parse(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

string_enum!(JobState {
    Queued => "QUEUED",
    Running => "RUNNING",
    Pausing => "PAUSING",
    Paused => "PAUSED",
    Cancelling => "CANCELLING",
    Cancelled => "CANCELLED",
    Succeeded => "SUCCEEDED",
    Partial => "PARTIAL",
    Failed => "FAILED",
    Interrupted => "INTERRUPTED",
});

string_enum!(JobPhase {
    Precheck => "PRECHECK",
    Enumerate => "ENUMERATE",
    Hash => "HASH",
    Aggregate => "AGGREGATE",
    Publish => "PUBLISH",
    Notify => "NOTIFY",
});

string_enum!(JobType {
    Scan => "scan",
    Export => "export",
    CleanupAction => "cleanup",
    Compare => "compare",
    Backup => "backup",
});

string_enum!(JobControlAction {
    Pause => "pause",
    Resume => "resume",
    Cancel => "cancel",
    Retry => "retry",
});

impl JobState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Succeeded | Self::Partial | Self::Failed | Self::Interrupted
        )
    }
}

/// State transition contract of spec 7.3. Terminal states have no outgoing
/// transitions; `INTERRUPTED` is only ever set by `mark_interrupted`.
pub fn legal_transition(from: JobState, to: JobState) -> bool {
    use JobState::*;
    let targets: &[JobState] = match from {
        Queued => &[Running, Cancelling],
        Running => &[Pausing, Succeeded, Partial, Failed, Cancelling],
        Pausing => &[Paused, Cancelling],
        Paused => &[Running, Cancelling],
        Cancelling => &[Cancelled],
        Cancelled | Succeeded | Partial | Failed | Interrupted => &[],
    };
    targets.contains(&to)
}

#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub id: String,
    pub run_id: Option<String>,
    #[serde(rename = "type")]
    pub job_type: JobType,
    pub state: JobState,
    pub phase: Option<JobPhase>,
    pub profile_id: Option<String>,
    pub profile_version: Option<i64>,
    #[serde(rename = "params")]
    pub params_json: serde_json::Value,
    #[serde(skip)]
    pub idempotency_key: Option<String>,
    pub retry_of: Option<String>,
    pub requested_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub heartbeat_at: Option<String>,
    #[serde(rename = "progress")]
    pub progress_json: serde_json::Value,
    #[serde(rename = "error")]
    pub error_json: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobEvent {
    pub job_id: String,
    pub sequence: i64,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(rename = "payload")]
    pub payload_json: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScheduleOccurrence {
    pub profile_id: String,
    pub profile_version: i64,
    pub occurrence_key: String,
    pub job_id: Option<String>,
    pub planned_at: Option<String>,
    pub skipped_nonexistent: bool,
}

#[derive(Debug, Clone, Default)]
pub struct JobListFilter {
    pub state: Option<JobState>,
    pub job_type: Option<JobType>,
    pub profile_id: Option<String>,
    /// Opaque cursor from a previous page (base64 of "requested_at|id").
    pub cursor: Option<String>,
    /// Clamped to 1..=MAX_JOB_PAGE_SIZE; default 50.
    pub page_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobPage {
    pub items: Vec<Job>,
    pub next_cursor: Option<String>,
    /// Always null: totals are not tracked for the jobs center listing.
    pub total_known: Option<u64>,
}

fn job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Job> {
    let state_s: String = row.get("state")?;
    let type_s: String = row.get("type")?;
    let phase_s: Option<String> = row.get("phase")?;
    let params_s: String = row.get("params_json")?;
    let progress_s: String = row.get("progress_json")?;
    let error_s: Option<String> = row.get("error_json")?;
    Ok(Job {
        id: row.get("id")?,
        run_id: row.get("run_id")?,
        job_type: JobType::parse(&type_s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.message,
                )),
            )
        })?,
        state: JobState::parse(&state_s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.message,
                )),
            )
        })?,
        phase: match phase_s {
            Some(s) => Some(JobPhase::parse(&s).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.message,
                    )),
                )
            })?),
            None => None,
        },
        profile_id: row.get("profile_id")?,
        profile_version: row.get("profile_version")?,
        params_json: serde_json::from_str(&params_s)
            .map_err(|e| rusqlite::Error::InvalidParameterName(format!("params_json: {e}")))?,
        idempotency_key: row.get("idempotency_key")?,
        retry_of: row.get("retry_of")?,
        requested_at: row.get("requested_at")?,
        started_at: row.get("started_at")?,
        finished_at: row.get("finished_at")?,
        heartbeat_at: row.get("heartbeat_at")?,
        progress_json: serde_json::from_str(&progress_s)
            .map_err(|e| rusqlite::Error::InvalidParameterName(format!("progress_json: {e}")))?,
        error_json: match error_s {
            Some(s) => {
                Some(serde_json::from_str(&s).map_err(|e| {
                    rusqlite::Error::InvalidParameterName(format!("error_json: {e}"))
                })?)
            }
            None => None,
        },
    })
}

const JOB_COLUMNS: &str = "id, run_id, type, state, phase, profile_id, \
     profile_version, params_json, idempotency_key, retry_of, requested_at, \
     started_at, finished_at, heartbeat_at, progress_json, error_json";

fn query_job(conn: &Connection, id: &str) -> AppResult<Option<Job>> {
    conn.query_row(
        &format!("SELECT {JOB_COLUMNS} FROM jobs WHERE id = ?1"),
        params![id],
        job_from_row,
    )
    .optional()
    .map_err(|e| internal(format!("读取任务失败: {e}")))
}

/// Fetch a job by id; `NOT_FOUND` when it does not exist.
pub fn get_job(conn: &Connection, id: &str) -> AppResult<Job> {
    query_job(conn, id)?.ok_or_else(|| not_found(format!("任务不存在: {id}")))
}

/// Create a job row in QUEUED state.
///
/// - when `idempotency_key` is present and already exists, the EXISTING job
///   is returned and no new row is inserted (spec 7.2: duplicate manual
///   clicks return the same job);
/// - scan jobs are bounded by `max_queued`: when the number of QUEUED+RUNNING
///   scan jobs reaches the limit, creation fails with RESOURCE_BUSY;
/// - scan jobs get a fresh `run_id` (used to bind the immutable report).
pub fn create_job(
    conn: &Connection,
    job_type: JobType,
    profile_id: Option<&str>,
    profile_version: Option<i64>,
    params_json: &serde_json::Value,
    idempotency_key: Option<&str>,
    max_queued: usize,
) -> AppResult<Job> {
    if let Some(key) = idempotency_key {
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM jobs WHERE idempotency_key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| internal(format!("查询幂等键失败: {e}")))?;
        if let Some(id) = existing {
            return get_job(conn, &id);
        }
    }

    if job_type == JobType::Scan {
        let max_queued_i64 = i64::try_from(max_queued).map_err(|_| {
            AppError::new(
                ErrorCode::ValidationFailed,
                "扫描队列上限超出 SQLite INTEGER 范围",
            )
        })?;
        let queued: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM jobs WHERE type = 'scan' AND state IN ('QUEUED','RUNNING')",
                [],
                |r| r.get(0),
            )
            .map_err(|e| internal(format!("统计扫描队列失败: {e}")))?;
        if queued >= max_queued_i64 {
            return Err(AppError::new(
                ErrorCode::ResourceBusy,
                format!("扫描任务队列已满（上限 {max_queued}），请稍后重试"),
            )
            .with_details(serde_json::json!({ "queued": queued, "max_queued": max_queued })));
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    let run_id = (job_type == JobType::Scan).then(|| uuid::Uuid::new_v4().to_string());
    let params_s = params_json.to_string();
    conn.execute(
        &format!(
            "INSERT INTO jobs (id, run_id, type, state, phase, profile_id, \
             profile_version, params_json, idempotency_key, retry_of, requested_at, \
             progress_json) \
             VALUES (?1, ?2, ?3, 'QUEUED', NULL, ?4, ?5, ?6, ?7, NULL, {SQL_NOW}, '{{}}')"
        ),
        params![
            id,
            run_id,
            job_type.as_str(),
            profile_id,
            profile_version,
            params_s,
            idempotency_key
        ],
    )
    .map_err(|e| internal(format!("创建任务失败: {e}")))?;
    get_job(conn, &id)
}

/// Create a scan job while applying the persisted per-profile overlap policy.
/// Idempotency is resolved before overlap handling so a retried request always
/// receives the original job, including a previously skipped request.
pub fn create_scan_job(
    conn: &Connection,
    profile_id: &str,
    profile_version: i64,
    params_json: &serde_json::Value,
    idempotency_key: Option<&str>,
    max_queued: usize,
    overlap_policy: crate::scheduler::OverlapPolicy,
) -> AppResult<Job> {
    if let Some(key) = idempotency_key {
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM jobs WHERE idempotency_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| internal(format!("查询扫描幂等键失败: {e}")))?;
        if let Some(id) = existing {
            return get_job(conn, &id);
        }
    }

    let queued: Option<String> = conn
        .query_row(
            "SELECT id FROM jobs
             WHERE type = 'scan' AND profile_id = ?1 AND state = 'QUEUED'
             ORDER BY requested_at ASC, id ASC LIMIT 1",
            [profile_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| internal(format!("检查排队扫描失败: {e}")))?;
    if let (Some(queued_id), crate::scheduler::OverlapPolicy::CoalesceOnce) =
        (queued, overlap_policy)
    {
        return get_job(conn, &queued_id);
    }

    let active: Option<String> = conn
        .query_row(
            "SELECT id FROM jobs
             WHERE type = 'scan' AND profile_id = ?1
               AND state IN ('RUNNING','PAUSING','PAUSED','CANCELLING')
             ORDER BY requested_at ASC, id ASC LIMIT 1",
            [profile_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| internal(format!("检查任务重叠失败: {e}")))?;
    if let Some(active_id) = active {
        match overlap_policy {
            crate::scheduler::OverlapPolicy::CoalesceOnce => {}
            crate::scheduler::OverlapPolicy::Skip => {
                let id = uuid::Uuid::new_v4().to_string();
                let run_id = uuid::Uuid::new_v4().to_string();
                let params_s = params_json.to_string();
                let error_json = serde_json::json!({
                    "code": "OVERLAP_SKIPPED",
                    "message": "同一任务已有运行中或排队中的扫描，本次触发已跳过",
                    "overlapping_job_id": active_id,
                });
                conn.execute(
                    &format!(
                        "INSERT INTO jobs
                         (id, run_id, type, state, phase, profile_id, profile_version,
                          params_json, idempotency_key, retry_of, requested_at,
                          finished_at, progress_json, error_json)
                         VALUES (?1, ?2, 'scan', 'CANCELLED', NULL, ?3, ?4, ?5,
                                 ?6, NULL, {SQL_NOW}, {SQL_NOW}, '{{}}', ?7)"
                    ),
                    params![
                        id,
                        run_id,
                        profile_id,
                        profile_version,
                        params_s,
                        idempotency_key,
                        error_json.to_string(),
                    ],
                )
                .map_err(|e| internal(format!("保存跳过的扫描任务失败: {e}")))?;
                return get_job(conn, &id);
            }
        }
    }

    create_job(
        conn,
        JobType::Scan,
        Some(profile_id),
        Some(profile_version),
        params_json,
        idempotency_key,
        max_queued,
    )
}

/// Claim the oldest queued scan job, atomically, in a single transaction.
///
/// Global single-scan rule (spec 7.2): if any scan job is already started and
/// not finished (RUNNING/PAUSING/PAUSED/CANCELLING), returns `None`. The
/// state flip uses an expected-state UPDATE (`WHERE state='QUEUED'`) so a
/// racing cancel cannot be overwritten.
pub fn claim_next_scan(conn: &mut Connection) -> AppResult<Option<Job>> {
    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("开启领取事务失败: {e}")))?;

    let active: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE type = 'scan' \
             AND state IN ('RUNNING','PAUSING','PAUSED','CANCELLING')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| internal(format!("检查运行中的扫描失败: {e}")))?;
    if active > 0 {
        return Ok(None);
    }

    let candidate: Option<String> = tx
        .query_row(
            "SELECT id FROM jobs WHERE type = 'scan' AND state = 'QUEUED' \
             ORDER BY requested_at ASC, id ASC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| internal(format!("查询待领取扫描失败: {e}")))?;
    let Some(id) = candidate else {
        return Ok(None);
    };

    let changed = tx
        .execute(
            &format!(
                "UPDATE jobs SET state = 'RUNNING', started_at = {SQL_NOW}, \
                 heartbeat_at = {SQL_NOW} WHERE id = ?1 AND state = 'QUEUED'"
            ),
            params![id],
        )
        .map_err(|e| internal(format!("领取扫描任务失败: {e}")))?;
    if changed == 0 {
        // Lost the race to a concurrent state change; nothing claimed.
        return Ok(None);
    }
    let job = tx
        .query_row(
            &format!("SELECT {JOB_COLUMNS} FROM jobs WHERE id = ?1"),
            params![id],
            job_from_row,
        )
        .map_err(|e| internal(format!("读取已领取任务失败: {e}")))?;
    tx.commit()
        .map_err(|e| internal(format!("提交领取事务失败: {e}")))?;
    Ok(Some(job))
}

/// Claim one queued non-scan operation. Export, comparison and backup work is
/// persisted in the same queue as scans but runs in a separate supervisor so
/// an HTTP request never owns the long-running operation.
pub fn claim_next_operation(conn: &mut Connection) -> AppResult<Option<Job>> {
    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("开启操作领取事务失败: {e}")))?;
    let active: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM jobs
             WHERE type IN ('export', 'compare', 'backup', 'cleanup')
               AND state IN ('RUNNING','PAUSING','PAUSED','CANCELLING')",
            [],
            |row| row.get(0),
        )
        .map_err(|e| internal(format!("检查运行中的操作失败: {e}")))?;
    if active > 0 {
        tx.commit()
            .map_err(|e| internal(format!("提交运行中操作检查失败: {e}")))?;
        return Ok(None);
    }
    let candidate: Option<String> = tx
        .query_row(
            "SELECT id FROM jobs
             WHERE type IN ('export', 'compare', 'backup', 'cleanup') AND state = 'QUEUED'
             ORDER BY requested_at ASC, id ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| internal(format!("查询待领取操作失败: {e}")))?;
    let Some(id) = candidate else {
        tx.commit()
            .map_err(|e| internal(format!("提交空操作领取事务失败: {e}")))?;
        return Ok(None);
    };
    let changed = tx
        .execute(
            &format!(
                "UPDATE jobs SET state = 'RUNNING', started_at = {SQL_NOW},
                 heartbeat_at = {SQL_NOW} WHERE id = ?1 AND state = 'QUEUED'"
            ),
            params![id],
        )
        .map_err(|e| internal(format!("领取操作失败: {e}")))?;
    if changed == 0 {
        tx.commit()
            .map_err(|e| internal(format!("提交竞争操作事务失败: {e}")))?;
        return Ok(None);
    }
    let job = tx
        .query_row(
            &format!("SELECT {JOB_COLUMNS} FROM jobs WHERE id = ?1"),
            params![id],
            job_from_row,
        )
        .map_err(|e| internal(format!("读取已领取操作失败: {e}")))?;
    tx.commit()
        .map_err(|e| internal(format!("提交操作领取事务失败: {e}")))?;
    Ok(Some(job))
}

fn transition_expected(
    conn: &Connection,
    job: &Job,
    to: JobState,
    action: &str,
    extra_set: &str,
) -> AppResult<Job> {
    let changed = conn
        .execute(
            &format!("UPDATE jobs SET state = ?2 {extra_set} WHERE id = ?1 AND state = ?3"),
            params![job.id, to.as_str(), job.state.as_str()],
        )
        .map_err(|e| internal(format!("更新任务状态失败: {e}")))?;
    if changed == 0 {
        // State changed between read and write; report the real current state.
        let current = get_job(conn, &job.id)?;
        return Err(state_conflict(&job.id, current.state, action));
    }
    get_job(conn, &job.id)
}

/// Apply a user control action (pause / resume / cancel / retry).
///
/// - pause: only `RUNNING → PAUSING`;
/// - resume: only `PAUSED → RUNNING`;
/// - cancel: `QUEUED → CANCELLED` directly (nothing to unwind);
///   `RUNNING/PAUSING/PAUSED → CANCELLING` (worker finishes its consistency
///   wrap-up, spec 15.6);
/// - retry: only from terminal FAILED/INTERRUPTED/CANCELLED; creates a NEW
///   job with `retry_of` pointing at the old one (new id/run_id, inherited
///   params and profile). The old job and its report stay immutable.
///
/// Anything else fails with JOB_STATE_CONFLICT (409) carrying the current
/// state in `details`.
pub fn control_job(
    conn: &mut Connection,
    job_id: &str,
    action: JobControlAction,
) -> AppResult<Job> {
    use JobState::*;
    let job = get_job(conn, job_id)?;
    let action_s = action.as_str();

    match action {
        JobControlAction::Pause => {
            scan_control_only(&job, action_s)?;
            if job.state != Running {
                return Err(state_conflict(job_id, job.state, action_s));
            }
            transition_expected(conn, &job, Pausing, action_s, "")
        }
        JobControlAction::Resume => {
            scan_control_only(&job, action_s)?;
            if job.state != Paused {
                return Err(state_conflict(job_id, job.state, action_s));
            }
            transition_expected(conn, &job, Running, action_s, "")
        }
        JobControlAction::Cancel => match job.state {
            Queued => transition_expected(
                conn,
                &job,
                Cancelled,
                action_s,
                &format!(", finished_at = {SQL_NOW}"),
            ),
            Running | Pausing | Paused => transition_expected(conn, &job, Cancelling, action_s, ""),
            other => Err(state_conflict(job_id, other, action_s)),
        },
        JobControlAction::Retry => match job.state {
            Failed | Interrupted | Cancelled => {
                let new_id = uuid::Uuid::new_v4().to_string();
                let run_id =
                    (job.job_type == JobType::Scan).then(|| uuid::Uuid::new_v4().to_string());
                let params_s = job.params_json.to_string();
                conn.execute(
                    &format!(
                        "INSERT INTO jobs (id, run_id, type, state, phase, profile_id, \
                         profile_version, params_json, idempotency_key, retry_of, \
                         requested_at, progress_json) \
                         VALUES (?1, ?2, ?3, 'QUEUED', NULL, ?4, ?5, ?6, NULL, ?7, \
                         {SQL_NOW}, '{{}}')"
                    ),
                    params![
                        new_id,
                        run_id,
                        job.job_type.as_str(),
                        job.profile_id,
                        job.profile_version,
                        params_s,
                        job.id
                    ],
                )
                .map_err(|e| internal(format!("创建重试任务失败: {e}")))?;
                get_job(conn, &new_id)
            }
            other => Err(state_conflict(job_id, other, action_s)),
        },
    }
}

/// Worker heartbeat: refreshes `heartbeat_at` and stores the progress
/// snapshot (spec 7.3 progress counters live in `progress_json`).
pub fn job_heartbeat(
    conn: &mut Connection,
    job_id: &str,
    progress_json: &serde_json::Value,
) -> AppResult<Job> {
    let changed = conn
        .execute(
            &format!(
                "UPDATE jobs SET heartbeat_at = {SQL_NOW}, progress_json = ?2
                 WHERE id = ?1 AND state IN ('QUEUED','RUNNING','PAUSING','PAUSED','CANCELLING')"
            ),
            params![job_id, progress_json.to_string()],
        )
        .map_err(|e| internal(format!("更新任务心跳失败: {e}")))?;
    if changed == 0 {
        let job = get_job(conn, job_id)?;
        if matches!(
            job.state,
            JobState::Succeeded
                | JobState::Partial
                | JobState::Failed
                | JobState::Cancelled
                | JobState::Interrupted
        ) {
            return Ok(job);
        }
        return Err(state_conflict(job_id, job.state, "heartbeat"));
    }
    get_job(conn, job_id)
}

/// Record the current RUNNING-internal phase (spec 7.3:
/// PRECHECK → ENUMERATE → HASH → AGGREGATE → PUBLISH → NOTIFY).
pub fn job_set_phase(conn: &mut Connection, job_id: &str, phase: JobPhase) -> AppResult<Job> {
    let changed = conn
        .execute(
            "UPDATE jobs SET phase = ?2 WHERE id = ?1",
            params![job_id, phase.as_str()],
        )
        .map_err(|e| internal(format!("更新任务阶段失败: {e}")))?;
    if changed == 0 {
        return Err(not_found(format!("任务不存在: {job_id}")));
    }
    get_job(conn, job_id)
}

/// A worker calls this after the scanner has reached its cooperative pause
/// checkpoint. The control request first records PAUSING; only the worker may
/// publish PAUSED once the scan is actually stopped at a checkpoint.
pub fn job_mark_paused(conn: &mut Connection, job_id: &str) -> AppResult<Job> {
    let job = get_job(conn, job_id)?;
    scan_control_only(&job, "pause")?;
    match job.state {
        JobState::Pausing => transition_expected(conn, &job, JobState::Paused, "pause", ""),
        JobState::Paused => Ok(job),
        other => Err(state_conflict(job_id, other, "pause")),
    }
}

/// Worker-side finish with a final state of SUCCEEDED / PARTIAL / FAILED.
///
/// Cancellation wins over finish (spec 15.6/16.1): when the current state is
/// CANCELLING the job transitions to CANCELLED instead of the requested
/// final state; when it is already CANCELLED the job is returned unchanged.
/// Finishing from any other non-RUNNING state is a JOB_STATE_CONFLICT.
pub fn job_finish(
    conn: &mut Connection,
    job_id: &str,
    final_state: JobState,
    error_json: Option<&serde_json::Value>,
) -> AppResult<Job> {
    use JobState::*;
    if !matches!(final_state, Succeeded | Partial | Failed) {
        return Err(AppError::new(
            ErrorCode::ValidationFailed,
            format!(
                "任务结束状态必须是 SUCCEEDED/PARTIAL/FAILED，收到 {}",
                final_state.as_str()
            ),
        ));
    }
    let job = get_job(conn, job_id)?;
    match job.state {
        Cancelling => transition_expected(
            conn,
            &job,
            Cancelled,
            "finish",
            &format!(", finished_at = {SQL_NOW}"),
        ),
        Cancelled => Ok(job),
        Running => {
            let error_s = error_json.map(|e| e.to_string());
            let changed = conn
                .execute(
                    &format!(
                        "UPDATE jobs SET state = ?2, finished_at = {SQL_NOW}, \
                         error_json = ?3 WHERE id = ?1 AND state = 'RUNNING'"
                    ),
                    params![job_id, final_state.as_str(), error_s],
                )
                .map_err(|e| internal(format!("结束任务失败: {e}")))?;
            if changed == 0 {
                // Lost the race with a control action (e.g. cancel).
                let current = get_job(conn, job_id)?;
                return match current.state {
                    Cancelling => transition_expected(
                        conn,
                        &current,
                        Cancelled,
                        "finish",
                        &format!(", finished_at = {SQL_NOW}"),
                    ),
                    Cancelled => Ok(current),
                    other => Err(state_conflict(job_id, other, "finish")),
                };
            }
            get_job(conn, job_id)
        }
        other => Err(state_conflict(job_id, other, "finish")),
    }
}

/// Startup recovery (spec 7.3): every job still in an active state when the
/// process (re)starts is marked INTERRUPTED with an error note; QUEUED jobs
/// stay queued. Returns the number of interrupted jobs.
pub fn mark_interrupted(conn: &mut Connection) -> AppResult<u64> {
    let note = serde_json::json!({
        "code": "INTERRUPTED",
        "message": "进程重启，未结束的任务已标记为中断",
    });
    let changed = conn
        .execute(
            &format!(
                "UPDATE jobs SET state = 'INTERRUPTED', finished_at = {SQL_NOW}, \
                 error_json = ?1 \
                 WHERE state IN ('RUNNING','PAUSING','PAUSED','CANCELLING')"
            ),
            params![note.to_string()],
        )
        .map_err(|e| internal(format!("标记中断任务失败: {e}")))?;
    u64::try_from(changed).map_err(|_| internal("中断任务数量超出 u64 范围"))
}

/// Mark one scan worker as interrupted after the child process disappeared or
/// returned a non-zero status.  This is deliberately scoped to the requested
/// job: startup recovery uses [`mark_interrupted`] for all active jobs, while
/// a worker supervisor must not change an unrelated control-plane job.
pub fn interrupt_job(conn: &mut Connection, job_id: &str, message: &str) -> AppResult<Job> {
    let job = get_job(conn, job_id)?;
    if job.state.is_terminal() {
        return Ok(job);
    }
    let error_json = serde_json::json!({
        "code": "INTERRUPTED",
        "message": message,
    });
    let changed = conn
        .execute(
            &format!(
                "UPDATE jobs SET state = 'INTERRUPTED', finished_at = {SQL_NOW}, \
                 error_json = ?2 WHERE id = ?1 \
                 AND state IN ('RUNNING','PAUSING','PAUSED','CANCELLING')"
            ),
            params![job_id, error_json.to_string()],
        )
        .map_err(|e| internal(format!("标记任务中断失败: {e}")))?;
    if changed == 0 {
        let current = get_job(conn, job_id)?;
        if current.state.is_terminal() {
            return Ok(current);
        }
        return Err(state_conflict(job_id, current.state, "interrupt"));
    }
    get_job(conn, job_id)
}

/// Record a fired schedule occurrence. Returns `false` when the occurrence
/// key (profile_id, profile_version, occurrence_key) was already recorded —
/// i.e. this logical trigger point already fired (spec 7.2 dedupe, incl. DST
/// fall-back protection).
pub fn record_occurrence(
    conn: &Connection,
    profile_id: &str,
    profile_version: i64,
    occurrence_key: &str,
    job_id: &str,
    planned_at: &str,
) -> AppResult<bool> {
    let changed = conn
        .execute(
            "INSERT OR IGNORE INTO schedule_occurrences \
             (profile_id, profile_version, occurrence_key, job_id, planned_at, \
              planned_local_at, skipped_nonexistent) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?3, 0)",
            params![
                profile_id,
                profile_version,
                occurrence_key,
                job_id,
                planned_at
            ],
        )
        .map_err(|e| internal(format!("记录调度触发失败: {e}")))?;
    Ok(changed > 0)
}

/// Record a local wall-clock occurrence that did not exist during a
/// spring-forward transition. There is deliberately no job or UTC instant
/// for this row; `occurrence_key` is the authoritative local planned time.
pub fn record_skipped_occurrence(
    conn: &Connection,
    profile_id: &str,
    profile_version: i64,
    occurrence_key: &str,
) -> AppResult<bool> {
    let changed = conn
        .execute(
            "INSERT OR IGNORE INTO schedule_occurrences \
             (profile_id, profile_version, occurrence_key, job_id, planned_at, \
              planned_local_at, skipped_nonexistent) \
             VALUES (?1, ?2, ?3, NULL, NULL, ?3, 1)",
            params![profile_id, profile_version, occurrence_key],
        )
        .map_err(|e| internal(format!("记录调度跳过失败: {e}")))?;
    Ok(changed > 0)
}

/// Recent recorded occurrences of a profile, newest planned first.
pub fn list_occurrences(
    conn: &Connection,
    profile_id: &str,
    limit: usize,
) -> AppResult<Vec<ScheduleOccurrence>> {
    let limit = limit.clamp(1, 1000) as i64;
    let mut stmt = conn
        .prepare(
            "SELECT profile_id, profile_version, occurrence_key, job_id, planned_at, \
                    skipped_nonexistent \
             FROM schedule_occurrences WHERE profile_id = ?1 \
             ORDER BY COALESCE(planned_at, planned_local_at) DESC, occurrence_key DESC LIMIT ?2",
        )
        .map_err(|e| internal(format!("查询调度记录失败: {e}")))?;
    let rows = stmt
        .query_map(params![profile_id, limit], |r| {
            Ok(ScheduleOccurrence {
                profile_id: r.get(0)?,
                profile_version: r.get(1)?,
                occurrence_key: r.get(2)?,
                job_id: r.get(3)?,
                planned_at: r.get(4)?,
                skipped_nonexistent: r.get::<_, i64>(5)? != 0,
            })
        })
        .map_err(|e| internal(format!("查询调度记录失败: {e}")))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| internal(format!("读取调度记录失败: {e}")))?);
    }
    Ok(out)
}

/// Append a job event with a monotonically increasing per-job sequence
/// (assigned inside the same write transaction). Events per job are bounded:
/// once more than [`MAX_EVENTS_PER_JOB`] exist, the oldest are deleted.
pub fn append_event(
    conn: &mut Connection,
    job_id: &str,
    event_type: &str,
    payload_json: &serde_json::Value,
) -> AppResult<JobEvent> {
    let exists: Option<i64> = conn
        .query_row("SELECT 1 FROM jobs WHERE id = ?1", params![job_id], |r| {
            r.get(0)
        })
        .optional()
        .map_err(|e| internal(format!("查询任务失败: {e}")))?;
    if exists.is_none() {
        return Err(not_found(format!("任务不存在: {job_id}")));
    }

    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("开启事件事务失败: {e}")))?;
    let max_seq: Option<i64> = tx
        .query_row(
            "SELECT MAX(sequence) FROM job_events WHERE job_id = ?1",
            params![job_id],
            |r| r.get(0),
        )
        .map_err(|e| internal(format!("查询事件序号失败: {e}")))?;
    let sequence = match max_seq {
        None => 1,
        Some(value) if value >= 0 => value
            .checked_add(1)
            .ok_or_else(|| internal("任务事件序号超出 SQLite INTEGER 范围"))?,
        Some(_) => return Err(internal("数据库中的任务事件序号不能为负数")),
    };
    tx.execute(
        &format!(
            "INSERT INTO job_events (job_id, sequence, type, payload_json, created_at) \
             VALUES (?1, ?2, ?3, ?4, {SQL_NOW})"
        ),
        params![job_id, sequence, event_type, payload_json.to_string()],
    )
    .map_err(|e| internal(format!("写入任务事件失败: {e}")))?;
    // Bound the per-job event count: keep the latest MAX_EVENTS_PER_JOB.
    tx.execute(
        "DELETE FROM job_events WHERE job_id = ?1 AND sequence <= ?2",
        params![job_id, sequence - MAX_EVENTS_PER_JOB],
    )
    .map_err(|e| internal(format!("裁剪任务事件失败: {e}")))?;
    let event = tx
        .query_row(
            "SELECT job_id, sequence, type, payload_json, created_at \
             FROM job_events WHERE job_id = ?1 AND sequence = ?2",
            params![job_id, sequence],
            |r| {
                let payload_s: String = r.get(3)?;
                Ok(JobEvent {
                    job_id: r.get(0)?,
                    sequence: r.get(1)?,
                    event_type: r.get(2)?,
                    payload_json: json_column(&payload_s, "payload_json")?,
                    created_at: r.get(4)?,
                })
            },
        )
        .map_err(|e| internal(format!("读取任务事件失败: {e}")))?;
    tx.commit()
        .map_err(|e| internal(format!("提交事件事务失败: {e}")))?;
    Ok(event)
}

/// Events of a job with `sequence > after_sequence`, ascending — used for SSE
/// resume via Last-Event-ID.
pub fn list_events(
    conn: &Connection,
    job_id: &str,
    after_sequence: i64,
    limit: usize,
) -> AppResult<Vec<JobEvent>> {
    let limit = limit.clamp(1, MAX_EVENTS_PER_JOB as usize) as i64;
    let mut stmt = conn
        .prepare(
            "SELECT job_id, sequence, type, payload_json, created_at FROM job_events \
             WHERE job_id = ?1 AND sequence > ?2 ORDER BY sequence ASC LIMIT ?3",
        )
        .map_err(|e| internal(format!("查询任务事件失败: {e}")))?;
    let rows = stmt
        .query_map(params![job_id, after_sequence, limit], |r| {
            let payload_s: String = r.get(3)?;
            Ok(JobEvent {
                job_id: r.get(0)?,
                sequence: r.get(1)?,
                event_type: r.get(2)?,
                payload_json: json_column(&payload_s, "payload_json")?,
                created_at: r.get(4)?,
            })
        })
        .map_err(|e| internal(format!("查询任务事件失败: {e}")))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| internal(format!("读取任务事件失败: {e}")))?);
    }
    Ok(out)
}

fn encode_cursor(job: &Job) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("{}|{}", job.requested_at, job.id))
}

fn decode_cursor(cursor: &str) -> AppResult<(String, String)> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(cursor)
        .map_err(|_| AppError::new(ErrorCode::ValidationFailed, "分页游标无效"))?;
    let text = String::from_utf8(raw)
        .map_err(|_| AppError::new(ErrorCode::ValidationFailed, "分页游标无效"))?;
    let (requested_at, id) = text
        .split_once('|')
        .ok_or_else(|| AppError::new(ErrorCode::ValidationFailed, "分页游标无效"))?;
    Ok((requested_at.to_string(), id.to_string()))
}

/// Jobs center listing (spec 8.4): newest first, stable keyset pagination on
/// (requested_at, id) — descending, so rows inserted while paging never cause
/// duplicates or skips in subsequent pages. `total_known` is always null.
pub fn list_jobs(conn: &Connection, filter: &JobListFilter) -> AppResult<JobPage> {
    let page_size = filter.page_size.unwrap_or(50).clamp(1, MAX_JOB_PAGE_SIZE);
    let (cursor_ts, cursor_id) = match &filter.cursor {
        Some(c) => {
            let (ts, id) = decode_cursor(c)?;
            (Some(ts), Some(id))
        }
        None => (None, None),
    };
    let state_s = filter.state.map(|s| s.as_str());
    let type_s = filter.job_type.map(|t| t.as_str());
    let profile_id = filter.profile_id.as_deref();

    let mut stmt = conn
        .prepare(&format!(
            "SELECT {JOB_COLUMNS} FROM jobs \
             WHERE (?1 IS NULL OR state = ?1) \
               AND (?2 IS NULL OR type = ?2) \
               AND (?3 IS NULL OR profile_id = ?3) \
               AND (?4 IS NULL OR requested_at < ?4 \
                    OR (requested_at = ?4 AND id < ?5)) \
             ORDER BY requested_at DESC, id DESC LIMIT ?6"
        ))
        .map_err(|e| internal(format!("查询任务列表失败: {e}")))?;
    let rows = stmt
        .query_map(
            params![
                state_s,
                type_s,
                profile_id,
                cursor_ts,
                cursor_id,
                page_size as i64 + 1
            ],
            job_from_row,
        )
        .map_err(|e| internal(format!("查询任务列表失败: {e}")))?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(|e| internal(format!("读取任务列表失败: {e}")))?);
    }

    let next_cursor = if items.len() > page_size {
        items.truncate(page_size);
        items.last().map(encode_cursor)
    } else {
        None
    };
    Ok(JobPage {
        items,
        next_cursor,
        total_known: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::migrate::{self, CONTROL_MIGRATIONS};

    fn setup() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        migrate::apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        conn
    }

    fn scan(conn: &mut Connection, key: Option<&str>) -> Job {
        create_job(
            conn,
            JobType::Scan,
            Some("profile-1"),
            Some(1),
            &serde_json::json!({"sources": ["a"]}),
            key,
            20,
        )
        .unwrap()
    }

    fn scan_with_overlap(
        conn: &Connection,
        policy: crate::scheduler::OverlapPolicy,
        key: Option<&str>,
    ) -> Job {
        create_scan_job(
            conn,
            "profile-1",
            1,
            &serde_json::json!({"sources": ["a"]}),
            key,
            20,
            policy,
        )
        .unwrap()
    }

    // Runs a job through claim → finish(Failed) so retry becomes legal.
    fn failed_job(conn: &mut Connection) -> Job {
        let job = scan(conn, None);
        let claimed = claim_next_scan(conn).unwrap().unwrap();
        assert_eq!(claimed.id, job.id);
        job_finish(
            conn,
            &job.id,
            JobState::Failed,
            Some(&serde_json::json!({"message": "x"})),
        )
        .unwrap()
    }

    #[test]
    fn create_is_idempotent_with_same_key() {
        let mut conn = setup();
        let a = scan(&mut conn, Some("key-1"));
        let b = scan(&mut conn, Some("key-1"));
        assert_eq!(a.id, b.id);
        assert_eq!(a.run_id, b.run_id);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        // Distinct keys create distinct jobs.
        let c = scan(&mut conn, Some("key-2"));
        assert_ne!(a.id, c.id);
    }

    #[test]
    fn skip_policy_records_a_cancelled_overlap_trigger() {
        let mut conn = setup();
        let first = scan_with_overlap(&conn, crate::scheduler::OverlapPolicy::Skip, None);
        claim_next_scan(&mut conn).unwrap();
        let skipped = scan_with_overlap(&conn, crate::scheduler::OverlapPolicy::Skip, None);
        assert_eq!(skipped.state, JobState::Cancelled);
        assert_eq!(
            skipped.error_json.as_ref().and_then(|v| v["code"].as_str()),
            Some("OVERLAP_SKIPPED")
        );
        assert_ne!(first.id, skipped.id);
    }

    #[test]
    fn coalesce_policy_keeps_one_follow_up_job() {
        let mut conn = setup();
        let first = scan_with_overlap(&conn, crate::scheduler::OverlapPolicy::CoalesceOnce, None);
        claim_next_scan(&mut conn).unwrap();
        let queued = scan_with_overlap(&conn, crate::scheduler::OverlapPolicy::CoalesceOnce, None);
        let same = scan_with_overlap(&conn, crate::scheduler::OverlapPolicy::CoalesceOnce, None);
        assert_eq!(queued.state, JobState::Queued);
        assert_eq!(queued.id, same.id);
        assert_ne!(first.id, queued.id);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn queue_full_returns_resource_busy() {
        let mut conn = setup();
        scan(&mut conn, None);
        scan(&mut conn, None);
        let err = create_job(
            &conn,
            JobType::Scan,
            Some("p"),
            Some(1),
            &serde_json::json!({}),
            None,
            2,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::ResourceBusy);
        // Non-scan jobs are not bound by the scan queue limit.
        create_job(
            &conn,
            JobType::Export,
            None,
            None,
            &serde_json::json!({}),
            None,
            2,
        )
        .unwrap();
    }

    #[test]
    fn claim_picks_oldest_and_enforces_single_running() {
        let mut conn = setup();
        let a = scan(&mut conn, None);
        // Sleep past the millisecond timestamp resolution so "oldest" is
        // decided by requested_at rather than the id tie-breaker.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = scan(&mut conn, None);

        let claimed = claim_next_scan(&mut conn).unwrap().unwrap();
        assert_eq!(claimed.id, a.id);
        assert_eq!(claimed.state, JobState::Running);
        assert!(claimed.started_at.is_some());
        assert!(claimed.heartbeat_at.is_some());

        // A running scan blocks any further claim.
        assert!(claim_next_scan(&mut conn).unwrap().is_none());

        // PAUSING / PAUSED / CANCELLING also hold the single scan slot.
        control_job(&mut conn, &a.id, JobControlAction::Pause).unwrap();
        assert!(claim_next_scan(&mut conn).unwrap().is_none());
        // Worker acknowledges the pause.
        let paused = transition_expected(
            &conn,
            &get_job(&conn, &a.id).unwrap(),
            JobState::Paused,
            "worker-pause",
            "",
        )
        .unwrap();
        assert_eq!(paused.state, JobState::Paused);
        assert!(claim_next_scan(&mut conn).unwrap().is_none());

        control_job(&mut conn, &a.id, JobControlAction::Cancel).unwrap();
        assert!(claim_next_scan(&mut conn).unwrap().is_none());

        // Finish while cancelling resolves to CANCELLED and frees the slot.
        let cancelled = job_finish(&mut conn, &a.id, JobState::Succeeded, None).unwrap();
        assert_eq!(cancelled.state, JobState::Cancelled);
        let next = claim_next_scan(&mut conn).unwrap().unwrap();
        assert_eq!(next.id, b.id);
    }

    #[test]
    fn operation_claim_handles_cleanup_with_uppercase_state_and_single_slot() {
        let mut conn = setup();
        let cleanup = create_job(
            &conn,
            JobType::CleanupAction,
            None,
            None,
            &serde_json::json!({
                "action": "quarantine",
                "action_id": "action-1",
                "plan_id": "plan-1",
                "actor_id": "actor-1"
            }),
            None,
            1,
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let export = create_job(
            &conn,
            JobType::Export,
            None,
            None,
            &serde_json::json!({}),
            None,
            1,
        )
        .unwrap();

        let claimed = claim_next_operation(&mut conn).unwrap().unwrap();
        assert_eq!(claimed.id, cleanup.id);
        assert_eq!(claimed.job_type, JobType::CleanupAction);
        assert_eq!(claimed.state, JobState::Running);
        let stored_state: String = conn
            .query_row(
                "SELECT state FROM jobs WHERE id = ?1",
                [&cleanup.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_state, "RUNNING");

        assert!(claim_next_operation(&mut conn).unwrap().is_none());
        job_finish(&mut conn, &cleanup.id, JobState::Succeeded, None).unwrap();
        assert_eq!(
            claim_next_operation(&mut conn).unwrap().unwrap().id,
            export.id
        );
    }

    #[test]
    fn legal_transition_matrix_matches_spec() {
        use JobState::*;
        let expected: &[(JobState, JobState)] = &[
            (Queued, Running),
            (Queued, Cancelling),
            (Running, Pausing),
            (Running, Succeeded),
            (Running, Partial),
            (Running, Failed),
            (Running, Cancelling),
            (Pausing, Paused),
            (Pausing, Cancelling),
            (Paused, Running),
            (Paused, Cancelling),
            (Cancelling, Cancelled),
        ];
        for &from in JobState::ALL {
            for &to in JobState::ALL {
                assert_eq!(
                    legal_transition(from, to),
                    expected.contains(&(from, to)),
                    "transition {:?} -> {:?}",
                    from,
                    to
                );
            }
        }
        // Terminal states have no outgoing transitions at all.
        for t in [Cancelled, Succeeded, Partial, Failed, Interrupted] {
            assert!(t.is_terminal());
            assert!(JobState::ALL.iter().all(|&s| !legal_transition(t, s)));
        }
    }

    #[test]
    fn pause_resume_cancel_from_each_state() {
        use JobState::*;
        // (initial setup to reach the state, pause ok?, resume ok?, cancel ok?, cancel result)
        for &state in JobState::ALL {
            let mut conn = setup();
            let job = reach_state(&mut conn, state);

            for action in [
                JobControlAction::Pause,
                JobControlAction::Resume,
                JobControlAction::Cancel,
                JobControlAction::Retry,
            ] {
                let mut conn2 = setup();
                let j = reach_state(&mut conn2, state);
                let result = control_job(&mut conn2, &j.id, action);
                let ok = matches!(
                    (state, action),
                    (Running, JobControlAction::Pause)
                        | (Paused, JobControlAction::Resume)
                        | (Queued, JobControlAction::Cancel)
                        | (Running, JobControlAction::Cancel)
                        | (Pausing, JobControlAction::Cancel)
                        | (Paused, JobControlAction::Cancel)
                        | (Failed, JobControlAction::Retry)
                        | (Interrupted, JobControlAction::Retry)
                        | (Cancelled, JobControlAction::Retry)
                );
                match (result, ok) {
                    (Ok(updated), true) => {
                        let want = match action {
                            JobControlAction::Pause => Pausing,
                            JobControlAction::Resume => Running,
                            JobControlAction::Cancel if state == Queued => Cancelled,
                            JobControlAction::Cancel => Cancelling,
                            JobControlAction::Retry => Queued,
                        };
                        assert_eq!(updated.state, want, "{state:?} {:?}", action.as_str());
                        if action == JobControlAction::Retry {
                            assert_eq!(updated.retry_of.as_deref(), Some(j.id.as_str()));
                            assert_ne!(updated.id, j.id);
                            // The old job is untouched.
                            assert_eq!(get_job(&conn2, &j.id).unwrap().state, state);
                        }
                    }
                    (Err(e), false) => {
                        assert_eq!(
                            e.code,
                            ErrorCode::JobStateConflict,
                            "{state:?} {:?}",
                            action.as_str()
                        );
                        assert_eq!(
                            e.details.unwrap()["state"],
                            serde_json::json!(state.as_str())
                        );
                    }
                    (Ok(j), false) => {
                        panic!("{state:?} {:?} should fail but gave {j:?}", action.as_str())
                    }
                    (Err(e), true) => panic!(
                        "{state:?} {:?} should succeed but gave {e}",
                        action.as_str()
                    ),
                }
            }
            drop(job);
        }
    }

    #[test]
    fn pause_and_resume_are_rejected_for_non_scan_jobs() {
        let mut conn = setup();
        let export = create_job(
            &conn,
            JobType::Export,
            None,
            None,
            &serde_json::json!({}),
            None,
            1,
        )
        .unwrap();
        conn.execute(
            "UPDATE jobs SET state = 'RUNNING' WHERE id = ?1",
            params![export.id],
        )
        .unwrap();

        let error = control_job(&mut conn, &export.id, JobControlAction::Pause).unwrap_err();
        assert_eq!(error.code, ErrorCode::JobStateConflict);
        assert_eq!(error.details.unwrap()["type"], serde_json::json!("export"));
        assert_eq!(get_job(&conn, &export.id).unwrap().state, JobState::Running);

        conn.execute(
            "UPDATE jobs SET state = 'PAUSED' WHERE id = ?1",
            params![export.id],
        )
        .unwrap();
        let error = control_job(&mut conn, &export.id, JobControlAction::Resume).unwrap_err();
        assert_eq!(error.code, ErrorCode::JobStateConflict);
        assert_eq!(get_job(&conn, &export.id).unwrap().state, JobState::Paused);
    }

    /// Drives a fresh scan job into `state` (through legal transitions).
    fn reach_state(conn: &mut Connection, state: JobState) -> Job {
        use JobState::*;
        let job = scan(conn, None);
        match state {
            Queued => job,
            Running | Pausing | Paused | Cancelling => {
                claim_next_scan(conn).unwrap();
                match state {
                    Running => get_job(conn, &job.id).unwrap(),
                    Pausing | Paused => {
                        control_job(conn, &job.id, JobControlAction::Pause).unwrap();
                        if state == Pausing {
                            get_job(conn, &job.id).unwrap()
                        } else {
                            transition_expected(
                                conn,
                                &get_job(conn, &job.id).unwrap(),
                                Paused,
                                "worker-pause",
                                "",
                            )
                            .unwrap()
                        }
                    }
                    Cancelling => control_job(conn, &job.id, JobControlAction::Cancel).unwrap(),
                    _ => unreachable!(),
                }
            }
            Cancelled => {
                // Cancel from QUEUED goes straight to CANCELLED.
                control_job(conn, &job.id, JobControlAction::Cancel).unwrap()
            }
            Succeeded | Partial | Failed => {
                claim_next_scan(conn).unwrap();
                job_finish(conn, &job.id, state, None).unwrap()
            }
            Interrupted => {
                claim_next_scan(conn).unwrap();
                assert_eq!(mark_interrupted(conn).unwrap(), 1);
                get_job(conn, &job.id).unwrap()
            }
        }
    }

    #[test]
    fn cancellation_beats_finish() {
        let mut conn = setup();
        let job = scan(&mut conn, None);
        claim_next_scan(&mut conn).unwrap();
        control_job(&mut conn, &job.id, JobControlAction::Cancel).unwrap();
        // Worker finishes after the cancel request: SUCCEEDED must lose.
        let done = job_finish(&mut conn, &job.id, JobState::Succeeded, None).unwrap();
        assert_eq!(done.state, JobState::Cancelled);
        assert!(done.finished_at.is_some());

        // Already CANCELLED: finish returns the job unchanged, no overwrite.
        let again = job_finish(&mut conn, &job.id, JobState::Failed, None).unwrap();
        assert_eq!(again.state, JobState::Cancelled);
        assert_eq!(again.finished_at, done.finished_at);

        // QUEUED job cancelled directly: a late finish still cannot overwrite
        // the terminal CANCELLED state; the job is returned unchanged.
        let job2 = scan(&mut conn, None);
        control_job(&mut conn, &job2.id, JobControlAction::Cancel).unwrap();
        let unchanged = job_finish(&mut conn, &job2.id, JobState::Succeeded, None).unwrap();
        assert_eq!(unchanged.state, JobState::Cancelled);
    }

    #[test]
    fn finish_from_non_running_is_conflict() {
        let mut conn = setup();
        let job = scan(&mut conn, None);
        // QUEUED cannot finish.
        let err = job_finish(&mut conn, &job.id, JobState::Succeeded, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::JobStateConflict);
        // Invalid final state rejected.
        claim_next_scan(&mut conn).unwrap();
        let err = job_finish(&mut conn, &job.id, JobState::Queued, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::ValidationFailed);
        // Terminal job cannot be finished twice.
        job_finish(&mut conn, &job.id, JobState::Succeeded, None).unwrap();
        let err = job_finish(&mut conn, &job.id, JobState::Failed, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::JobStateConflict);
    }

    #[test]
    fn retry_creates_linked_new_job() {
        let mut conn = setup();
        let old = failed_job(&mut conn);
        let new = control_job(&mut conn, &old.id, JobControlAction::Retry).unwrap();
        assert_eq!(new.state, JobState::Queued);
        assert_eq!(new.retry_of.as_deref(), Some(old.id.as_str()));
        assert_ne!(new.id, old.id);
        assert!(new.run_id.is_some());
        assert_ne!(new.run_id, old.run_id);
        assert_eq!(new.params_json, old.params_json);
        assert_eq!(new.profile_id, old.profile_id);
        assert_eq!(new.profile_version, old.profile_version);
        assert!(new.idempotency_key.is_none());
        // Old job stays FAILED and immutable.
        let old_after = get_job(&conn, &old.id).unwrap();
        assert_eq!(old_after.state, JobState::Failed);
        assert!(old_after.retry_of.is_none());
        // The retried job can be claimed and run.
        let claimed = claim_next_scan(&mut conn).unwrap().unwrap();
        assert_eq!(claimed.id, new.id);
    }

    #[test]
    fn mark_interrupted_converts_active_states_only() {
        let mut conn = setup();
        let running = scan(&mut conn, None);
        // Sleep past the millisecond timestamp resolution so "oldest" is
        // decided by requested_at rather than the id tie-breaker.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let queued = scan(&mut conn, None);
        // The oldest queued scan is claimed first.
        let claimed = claim_next_scan(&mut conn).unwrap().unwrap();
        assert_eq!(claimed.id, running.id);
        let export = create_job(
            &conn,
            JobType::Export,
            None,
            None,
            &serde_json::json!({}),
            None,
            20,
        )
        .unwrap();
        // Export jobs are not affected by scan claims; put it RUNNING by hand
        // to simulate an active worker job.
        conn.execute(
            "UPDATE jobs SET state = 'RUNNING' WHERE id = ?1",
            params![export.id],
        )
        .unwrap();

        let count = mark_interrupted(&mut conn).unwrap();
        assert_eq!(count, 2);

        let queued_after = get_job(&conn, &queued.id).unwrap();
        assert_eq!(queued_after.state, JobState::Queued);
        for id in [running.id, export.id] {
            let j = get_job(&conn, &id).unwrap();
            assert_eq!(j.state, JobState::Interrupted);
            assert!(j.finished_at.is_some());
            assert_eq!(
                j.error_json.unwrap()["code"],
                serde_json::json!("INTERRUPTED")
            );
        }
        // Interrupted jobs no longer block the scan slot.
        let claimed = claim_next_scan(&mut conn).unwrap().unwrap();
        assert_eq!(claimed.id, queued.id);
    }

    #[test]
    fn mark_interrupted_preserves_queued_cleanup_and_interrupts_active_cleanup() {
        let mut conn = setup();
        let queued = create_job(
            &conn,
            JobType::CleanupAction,
            None,
            None,
            &serde_json::json!({
                "action": "quarantine",
                "action_id": "queued-action",
                "plan_id": "plan-1",
                "actor_id": "actor-1"
            }),
            None,
            1,
        )
        .unwrap();
        let active = create_job(
            &conn,
            JobType::CleanupAction,
            None,
            None,
            &serde_json::json!({
                "action": "quarantine",
                "action_id": "active-action",
                "plan_id": "plan-2",
                "actor_id": "actor-1"
            }),
            None,
            1,
        )
        .unwrap();
        conn.execute(
            "UPDATE jobs SET state = 'RUNNING' WHERE id = ?1",
            [&active.id],
        )
        .unwrap();

        assert_eq!(mark_interrupted(&mut conn).unwrap(), 1);
        assert_eq!(get_job(&conn, &queued.id).unwrap().state, JobState::Queued);
        let interrupted = get_job(&conn, &active.id).unwrap();
        assert_eq!(interrupted.state, JobState::Interrupted);
        assert_eq!(interrupted.error_json.unwrap()["code"], "INTERRUPTED");

        let stored_state: String = conn
            .query_row(
                "SELECT state FROM jobs WHERE id = ?1",
                [&active.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_state, "INTERRUPTED");
    }

    #[test]
    fn interrupt_job_is_scoped_to_the_failed_worker_job() {
        let mut conn = setup();
        let scan_job = scan(&mut conn, None);
        claim_next_scan(&mut conn).unwrap();
        let export_job = create_job(
            &conn,
            JobType::Export,
            None,
            None,
            &serde_json::json!({}),
            None,
            20,
        )
        .unwrap();
        conn.execute(
            "UPDATE jobs SET state = 'RUNNING' WHERE id = ?1",
            params![export_job.id],
        )
        .unwrap();

        let interrupted = interrupt_job(&mut conn, &scan_job.id, "worker exit").unwrap();
        assert_eq!(interrupted.state, JobState::Interrupted);
        assert_eq!(
            get_job(&conn, &export_job.id).unwrap().state,
            JobState::Running
        );
        assert_eq!(
            interrupt_job(&mut conn, &scan_job.id, "late exit")
                .unwrap()
                .state,
            JobState::Interrupted
        );
    }

    #[test]
    fn occurrence_dedupe_and_listing() {
        let mut conn = setup();
        let job = scan(&mut conn, None);
        assert!(
            record_occurrence(
                &conn,
                "p1",
                1,
                "2026-09-10T02:00",
                &job.id,
                "2026-09-10T02:00:00.000Z"
            )
            .unwrap()
        );
        // Same logical trigger point (incl. profile version): already fired.
        assert!(
            !record_occurrence(
                &conn,
                "p1",
                1,
                "2026-09-10T02:00",
                &job.id,
                "2026-09-10T02:00:00.000Z"
            )
            .unwrap()
        );
        // A new profile version is a new dedupe scope.
        assert!(
            record_occurrence(
                &conn,
                "p1",
                2,
                "2026-09-10T02:00",
                &job.id,
                "2026-09-10T02:00:00.000Z"
            )
            .unwrap()
        );
        // A different occurrence key fires independently.
        assert!(
            record_occurrence(
                &conn,
                "p1",
                1,
                "2026-09-11T02:00",
                &job.id,
                "2026-09-11T02:00:00.000Z"
            )
            .unwrap()
        );

        let occs = list_occurrences(&conn, "p1", 10).unwrap();
        assert_eq!(occs.len(), 3);
        assert_eq!(occs[0].occurrence_key, "2026-09-11T02:00");
        assert!(occs.iter().all(|o| o.job_id == Some(job.id.clone())));
        let one = list_occurrences(&conn, "p1", 1).unwrap();
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn skipped_occurrence_is_durable_without_fake_job_or_utc_time() {
        let conn = setup();
        assert!(record_skipped_occurrence(&conn, "p1", 1, "2024-03-10T02:30").unwrap());
        assert!(!record_skipped_occurrence(&conn, "p1", 1, "2024-03-10T02:30").unwrap());

        let occurrences = list_occurrences(&conn, "p1", 10).unwrap();
        assert_eq!(occurrences.len(), 1);
        assert_eq!(occurrences[0].job_id, None);
        assert_eq!(occurrences[0].planned_at, None);
        assert!(occurrences[0].skipped_nonexistent);
    }

    #[test]
    fn event_sequence_monotonic_and_bounded() {
        let mut conn = setup();
        let job = scan(&mut conn, None);
        let e1 = append_event(&mut conn, &job.id, "job.state", &serde_json::json!({})).unwrap();
        let e2 = append_event(&mut conn, &job.id, "job.progress", &serde_json::json!({})).unwrap();
        let e3 = append_event(&mut conn, &job.id, "heartbeat", &serde_json::json!({})).unwrap();
        assert_eq!((e1.sequence, e2.sequence, e3.sequence), (1, 2, 3));

        // SSE resume: only events after the given sequence.
        let page = list_events(&conn, &job.id, 1, 10).unwrap();
        assert_eq!(
            page.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(page[0].event_type, "job.progress");

        // Bound: more than MAX_EVENTS_PER_JOB events trims the oldest.
        for i in 0..MAX_EVENTS_PER_JOB + 2 {
            append_event(
                &mut conn,
                &job.id,
                "heartbeat",
                &serde_json::json!({"i": i}),
            )
            .unwrap();
        }
        let total: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM job_events WHERE job_id = ?1",
                params![job.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, MAX_EVENTS_PER_JOB);
        let all = list_events(&conn, &job.id, 0, 10_000).unwrap();
        assert_eq!(all.len() as i64, MAX_EVENTS_PER_JOB);
        let first = all.first().unwrap().sequence;
        let last = all.last().unwrap().sequence;
        assert_eq!(last - first + 1, MAX_EVENTS_PER_JOB);
        assert_eq!(last, MAX_EVENTS_PER_JOB + 5);

        // Events for a missing job are rejected.
        let err = append_event(&mut conn, "nope", "x", &serde_json::json!({})).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[test]
    fn cursor_pagination_stable_with_interleaved_inserts() {
        let mut conn = setup();
        let mut ids = Vec::new();
        for _ in 0..5 {
            ids.push(scan(&mut conn, None).id);
        }

        // Page 1.
        let p1 = list_jobs(
            &conn,
            &JobListFilter {
                page_size: Some(2),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p1.items.len(), 2);
        assert_eq!(p1.total_known, None);
        let c1 = p1.next_cursor.clone().unwrap();

        // Interleaved insert (newer than every existing row; sleep past the
        // millisecond timestamp resolution to make the age difference real).
        std::thread::sleep(std::time::Duration::from_millis(5));
        let extra1 = scan(&mut conn, None).id;

        // Page 2.
        let p2 = list_jobs(
            &conn,
            &JobListFilter {
                page_size: Some(2),
                cursor: Some(c1),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p2.items.len(), 2);
        let c2 = p2.next_cursor.clone().unwrap();

        let extra2 = scan(&mut conn, None).id;

        // Page 3 (last).
        let p3 = list_jobs(
            &conn,
            &JobListFilter {
                page_size: Some(2),
                cursor: Some(c2),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p3.items.len(), 1);
        assert!(p3.next_cursor.is_none());

        // No duplicates, no skips over the original five; the concatenated
        // pages must equal the authoritative total order (one big page) with
        // the interleaved inserts filtered out.
        let seen: Vec<String> = p1
            .items
            .iter()
            .chain(p2.items.iter())
            .chain(p3.items.iter())
            .map(|j| j.id.clone())
            .collect();
        let full = list_jobs(
            &conn,
            &JobListFilter {
                page_size: Some(200),
                ..Default::default()
            },
        )
        .unwrap();
        let expected: Vec<String> = full
            .items
            .iter()
            .map(|j| j.id.clone())
            .filter(|id| ids.contains(id))
            .collect();
        assert_eq!(seen, expected);
        assert!(!seen.contains(&extra1));
        assert!(!seen.contains(&extra2));

        // A fresh unfiltered first page sees the newest inserts on top
        // (their requested_at is >= every original row's).
        let top = list_jobs(&conn, &JobListFilter::default()).unwrap();
        let top_two: Vec<&str> = top.items[..2].iter().map(|j| j.id.as_str()).collect();
        assert!(top_two.contains(&extra1.as_str()) && top_two.contains(&extra2.as_str()));

        // Filters compose with the cursor.
        let only_scans = list_jobs(
            &conn,
            &JobListFilter {
                job_type: Some(JobType::Scan),
                page_size: Some(200),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(only_scans.items.len(), 7);
        let only_queued = list_jobs(
            &conn,
            &JobListFilter {
                state: Some(JobState::Queued),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            only_queued
                .items
                .iter()
                .all(|j| j.state == JobState::Queued)
        );

        // Invalid cursor rejected.
        let err = list_jobs(
            &conn,
            &JobListFilter {
                cursor: Some("!!!not-base64!!!".into()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn heartbeat_and_phase_updates() {
        let mut conn = setup();
        let job = scan(&mut conn, None);
        let err = job_heartbeat(&mut conn, "missing", &serde_json::json!({})).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);

        let updated = job_heartbeat(
            &mut conn,
            &job.id,
            &serde_json::json!({"files_visited": 42}),
        )
        .unwrap();
        assert!(updated.heartbeat_at.is_some());
        assert_eq!(updated.progress_json["files_visited"], 42);

        claim_next_scan(&mut conn).unwrap();
        let phased = job_set_phase(&mut conn, &job.id, JobPhase::Enumerate).unwrap();
        assert_eq!(phased.phase, Some(JobPhase::Enumerate));
        let err = job_set_phase(&mut conn, "missing", JobPhase::Hash).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }
}
