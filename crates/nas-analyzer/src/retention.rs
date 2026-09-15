//! Immutable report summary/detail retention.
//!
//! Retention is represented by the existing `reports` table. A report pin
//! preserves its summary; a detail pin independently preserves its full
//! detail. Expiring detail only changes `detail_available`, so the summary
//! remains readable and callers can return the stable `DETAIL_EXPIRED`
//! contract instead of presenting an empty result. Report artifact deletion
//! is a durable post-commit operation: the control transaction records the
//! persisted path before removing the report row, and a later filesystem
//! pass marks that intent complete. A restart can therefore retry an
//! incomplete deletion without deriving a path from a report id.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use fssecure::{EntryKind, FsSecureError, SecureRoot};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::auth;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::profile::ProfileRetention;

fn internal(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, message)
}

fn validation(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, message)
}

fn not_found(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::NotFound, message)
}

pub const MIN_QUARANTINE_AUTO_PURGE_DAYS: u32 = 7;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QuarantineAutoPurgePolicy {
    pub enabled: bool,
    pub min_keep_days: u32,
}

impl Default for QuarantineAutoPurgePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            min_keep_days: 30,
        }
    }
}

pub fn validate_quarantine_auto_purge(policy: &QuarantineAutoPurgePolicy) -> AppResult<()> {
    if policy.enabled && policy.min_keep_days < MIN_QUARANTINE_AUTO_PURGE_DAYS {
        return Err(validation("隔离区自动清理最短保留期为 7 天"));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRetentionSetting {
    #[serde(rename = "default_report_keep_count")]
    _default_report_keep_count: u32,
    #[serde(rename = "default_detail_keep_count")]
    _default_detail_keep_count: u32,
    quarantine_auto_purge: QuarantineAutoPurgePolicy,
}

pub fn load_quarantine_auto_purge(conn: &Connection) -> AppResult<QuarantineAutoPurgePolicy> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value_json FROM app_settings WHERE key = 'retention'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| internal(format!("读取自动清理策略失败: {error}")))?;
    let policy = match raw {
        None => QuarantineAutoPurgePolicy::default(),
        Some(raw) => {
            serde_json::from_str::<StoredRetentionSetting>(&raw)
                .map_err(|error| internal(format!("保留策略设置数据损坏: {error}")))?
                .quarantine_auto_purge
        }
    };
    validate_quarantine_auto_purge(&policy)?;
    Ok(policy)
}

fn artifact_fs_error(operation: &str, error: FsSecureError) -> AppError {
    let code = match error {
        FsSecureError::PathOutsideRoot
        | FsSecureError::SymlinkNotAllowed
        | FsSecureError::MountCrossingNotAllowed
        | FsSecureError::CrossDevice
        | FsSecureError::NotRegularFile
        | FsSecureError::NotDirectory
        | FsSecureError::IdentityChanged => ErrorCode::ValidationFailed,
        FsSecureError::MissingCapability => ErrorCode::UnsupportedCapability,
        FsSecureError::NotFound => ErrorCode::NotFound,
        FsSecureError::PermissionDenied => ErrorCode::Forbidden,
        _ => ErrorCode::Internal,
    };
    AppError::new(code, format!("{operation}: {error}"))
}

/// A generated report artifact that can be removed after its control row has
/// been deleted. `manifest_path` is the persisted source of truth; callers
/// must not derive a path from the report id.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExpiredReportArtifact {
    pub report_id: String,
    pub manifest_path: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct RetentionResult {
    pub detail_expired_report_ids: Vec<String>,
    pub reports_deleted: Vec<ExpiredReportArtifact>,
    pub detail_artifacts: Vec<ExpiredReportArtifact>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportRetentionState {
    pub report_id: String,
    pub detail_available: bool,
    pub report_pinned: bool,
    pub detail_pinned: bool,
}

fn profile_predicate() -> &'static str {
    "profile_id IS ?1"
}

fn report_ids_for_deletion(
    conn: &Connection,
    profile_id: Option<&str>,
    keep_count: u32,
) -> AppResult<Vec<ExpiredReportArtifact>> {
    let sql = format!(
        "SELECT id, manifest_path FROM reports WHERE {} \
         AND pinned = 0 AND detail_pinned = 0 \
         ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?2",
        profile_predicate()
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|error| internal(format!("准备报告保留查询失败: {error}")))?;
    stmt.query_map(params![profile_id, i64::from(keep_count)], |row| {
        Ok(ExpiredReportArtifact {
            report_id: row.get(0)?,
            manifest_path: row.get(1)?,
        })
    })
    .map_err(|error| internal(format!("读取过期报告失败: {error}")))?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| internal(format!("解析过期报告失败: {error}")))
}

fn report_ids_for_detail_expiry(
    conn: &Connection,
    profile_id: Option<&str>,
    keep_count: u32,
) -> AppResult<Vec<ExpiredReportArtifact>> {
    let sql = format!(
        "SELECT id, manifest_path FROM reports WHERE {} AND detail_pinned = 0 \
         ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?2",
        profile_predicate()
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|error| internal(format!("准备报告明细保留查询失败: {error}")))?;
    stmt.query_map(params![profile_id, i64::from(keep_count)], |row| {
        Ok(ExpiredReportArtifact {
            report_id: row.get(0)?,
            manifest_path: row.get(1)?,
        })
    })
    .map_err(|error| internal(format!("读取过期报告明细失败: {error}")))?
    .collect::<Result<Vec<ExpiredReportArtifact>, _>>()
    .map_err(|error| internal(format!("解析过期报告明细失败: {error}")))
}

/// Apply one profile's persisted retention policy. The report count and the
/// detail count are independent: a report can remain as a summary while its
/// full detail expires, and either pin prevents the corresponding cleanup.
pub fn apply_report_retention(
    conn: &mut Connection,
    profile_id: Option<&str>,
    policy: &ProfileRetention,
) -> AppResult<RetentionResult> {
    let tx = conn
        .transaction()
        .map_err(|error| internal(format!("开启报告保留事务失败: {error}")))?;
    let result = apply_report_retention_in_transaction(&tx, profile_id, policy)?;
    tx.commit()
        .map_err(|error| internal(format!("提交报告保留事务失败: {error}")))?;
    Ok(result)
}

fn apply_report_retention_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    profile_id: Option<&str>,
    policy: &ProfileRetention,
) -> AppResult<RetentionResult> {
    if policy.report_keep_count == 0 {
        return Err(validation("report_keep_count 必须大于 0"));
    }
    let reports_to_delete = report_ids_for_deletion(tx, profile_id, policy.report_keep_count)?;
    for artifact in &reports_to_delete {
        tx.execute(
            "DELETE FROM reports WHERE id = ?1 AND pinned = 0 AND detail_pinned = 0",
            params![artifact.report_id],
        )
        .map_err(|error| internal(format!("删除过期报告记录失败: {error}")))?;
    }
    let detail_artifacts = report_ids_for_detail_expiry(tx, profile_id, policy.detail_keep_count)?;
    let mut detail_expired_report_ids = Vec::new();
    let mut expired_detail_artifacts = Vec::new();
    for artifact in detail_artifacts {
        let changed = tx
            .execute(
                "UPDATE reports SET detail_available = 0 \
                 WHERE id = ?1 AND detail_pinned = 0 AND detail_available = 1",
                params![artifact.report_id],
            )
            .map_err(|error| internal(format!("标记报告明细过期失败: {error}")))?;
        if changed == 1 {
            detail_expired_report_ids.push(artifact.report_id.clone());
            expired_detail_artifacts.push(artifact);
        }
    }
    Ok(RetentionResult {
        detail_expired_report_ids,
        reports_deleted: reports_to_delete,
        detail_artifacts: expired_detail_artifacts,
    })
}

fn artifact_directory(reports_root: &Path, artifact: &ExpiredReportArtifact) -> AppResult<PathBuf> {
    let expected = reports_root.join(&artifact.report_id).join("manifest.json");
    let persisted = PathBuf::from(&artifact.manifest_path);
    if persisted != expected {
        return Err(validation(format!(
            "报告 {} 的持久化 manifest 不在批准报告目录内",
            artifact.report_id
        )));
    }
    persisted
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| validation("报告 manifest 缺少父目录"))
}

fn validate_artifacts(
    reports_root: &Path,
    result: &RetentionResult,
) -> AppResult<Vec<(PathBuf, bool)>> {
    let mut paths =
        Vec::with_capacity(result.reports_deleted.len() + result.detail_artifacts.len());
    for artifact in &result.reports_deleted {
        paths.push((artifact_directory(reports_root, artifact)?, true));
    }
    for artifact in &result.detail_artifacts {
        paths.push((artifact_directory(reports_root, artifact)?, false));
    }
    Ok(paths)
}

fn schedule_artifact_deletions(
    tx: &rusqlite::Transaction<'_>,
    result: &RetentionResult,
) -> AppResult<()> {
    for artifact in &result.reports_deleted {
        tx.execute(
            "INSERT INTO report_artifact_deletions
             (id, report_id, manifest_path, artifact_kind, state, created_at)
             VALUES (?1, ?2, ?3, 'report', 'pending', ?4)
             ON CONFLICT(report_id, manifest_path, artifact_kind) DO NOTHING",
            params![
                uuid::Uuid::new_v4().to_string(),
                artifact.report_id,
                artifact.manifest_path,
                auth::now_rfc3339(),
            ],
        )
        .map_err(|error| internal(format!("记录报告 artifact 删除意图失败: {error}")))?;
    }
    for artifact in &result.detail_artifacts {
        tx.execute(
            "INSERT INTO report_artifact_deletions
             (id, report_id, manifest_path, artifact_kind, state, created_at)
             VALUES (?1, ?2, ?3, 'detail', 'pending', ?4)
             ON CONFLICT(report_id, manifest_path, artifact_kind) DO NOTHING",
            params![
                uuid::Uuid::new_v4().to_string(),
                artifact.report_id,
                artifact.manifest_path,
                auth::now_rfc3339(),
            ],
        )
        .map_err(|error| internal(format!("记录报告明细 artifact 删除意图失败: {error}")))?;
    }
    Ok(())
}

fn relative_to_reports_root(reports_root: &Path, directory: &Path) -> AppResult<PathBuf> {
    directory
        .strip_prefix(reports_root)
        .map(Path::to_path_buf)
        .map_err(|_| validation("报告 artifact 不在批准报告根内"))
}

fn remove_artifact(
    root: &SecureRoot,
    reports_root: &Path,
    artifact: &ExpiredReportArtifact,
    whole_report: bool,
) -> AppResult<()> {
    let directory = artifact_directory(reports_root, artifact)?;
    let relative = relative_to_reports_root(reports_root, &directory)?;
    if whole_report {
        match root.remove_dir_all(relative.as_os_str()) {
            Ok(()) | Err(FsSecureError::NotFound) => {}
            Err(error) => return Err(artifact_fs_error("删除过期报告 artifact 失败", error)),
        }
    } else {
        let detail = relative.join("index.sqlite");
        match root.unlink_file(detail.as_os_str()) {
            Ok(()) | Err(FsSecureError::NotFound) => {}
            Err(error) => return Err(artifact_fs_error("删除过期报告明细失败", error)),
        }
    }
    Ok(())
}

/// Remove generated report artifacts using the persisted manifest path as the
/// source of truth. This helper is also used by focused filesystem tests;
/// production retention uses the durable intent queue below.
pub fn remove_expired_artifacts(reports_root: &Path, result: &RetentionResult) -> AppResult<()> {
    let paths = validate_artifacts(reports_root, result)?;
    if paths.is_empty() {
        return Ok(());
    }
    let root = match SecureRoot::open(reports_root.as_os_str()) {
        Ok(root) => root,
        Err(FsSecureError::NotFound) => return Ok(()),
        Err(error) => return Err(artifact_fs_error("打开报告 artifact 根失败", error)),
    };
    for artifact in &result.reports_deleted {
        remove_artifact(&root, reports_root, artifact, true)?;
    }
    for artifact in &result.detail_artifacts {
        remove_artifact(&root, reports_root, artifact, false)?;
    }
    Ok(())
}

fn mark_artifact_deletion_failed(conn: &Connection, id: &str, error: &AppError) -> AppResult<()> {
    conn.execute(
        "UPDATE report_artifact_deletions
         SET attempts = attempts + 1, last_error = ?2
         WHERE id = ?1 AND state = 'pending'",
        params![id, error.message],
    )
    .map_err(|db_error| internal(format!("记录报告 artifact 删除失败状态失败: {db_error}")))?;
    Ok(())
}

fn mark_artifact_deleted(conn: &Connection, id: &str) -> AppResult<()> {
    conn.execute(
        "UPDATE report_artifact_deletions
         SET state = 'deleted', attempts = attempts + 1,
             last_error = NULL, deleted_at = ?2
         WHERE id = ?1 AND state = 'pending'",
        params![id, auth::now_rfc3339()],
    )
    .map_err(|error| internal(format!("记录报告 artifact 已删除状态失败: {error}")))?;
    Ok(())
}

/// Complete durable artifact deletion intents after their control-db
/// transaction has committed. Each filesystem operation is followed by a
/// short state update, so a crash leaves only a retryable `pending` intent.
pub fn process_pending_artifact_deletions(
    conn: &mut Connection,
    reports_root: &Path,
) -> AppResult<u64> {
    let pending = {
        let mut stmt = conn
            .prepare(
                "SELECT id, report_id, manifest_path, artifact_kind
                 FROM report_artifact_deletions
                 WHERE state = 'pending'
                 ORDER BY created_at ASC, id ASC
                 LIMIT 100",
            )
            .map_err(|error| internal(format!("读取报告 artifact 删除队列失败: {error}")))?;
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                ExpiredReportArtifact {
                    report_id: row.get(1)?,
                    manifest_path: row.get(2)?,
                },
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| internal(format!("读取报告 artifact 删除意图失败: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal(format!("解析报告 artifact 删除意图失败: {error}")))?
    };
    if pending.is_empty() {
        return Ok(0);
    }

    let mut validated = Vec::with_capacity(pending.len());
    for (id, artifact, kind) in pending {
        let whole_report = match kind.as_str() {
            "report" => true,
            "detail" => false,
            _ => {
                let error = validation("报告 artifact 删除意图类型无效");
                mark_artifact_deletion_failed(conn, &id, &error)?;
                return Err(error);
            }
        };
        if let Err(error) = artifact_directory(reports_root, &artifact) {
            mark_artifact_deletion_failed(conn, &id, &error)?;
            return Err(error);
        }
        validated.push((id, artifact, whole_report));
    }

    let root = match SecureRoot::open(reports_root.as_os_str()) {
        Ok(root) => root,
        Err(FsSecureError::NotFound) => {
            for (id, _, _) in &validated {
                mark_artifact_deleted(conn, id)?;
            }
            return u64::try_from(validated.len())
                .map_err(|_| internal("报告 artifact 删除计数溢出"));
        }
        Err(error) => {
            let mapped = artifact_fs_error("打开报告 artifact 根失败", error);
            for (id, _, _) in &validated {
                mark_artifact_deletion_failed(conn, id, &mapped)?;
            }
            return Err(mapped);
        }
    };

    let mut deleted = 0_u64;
    for (id, artifact, whole_report) in validated {
        if let Err(error) = remove_artifact(&root, reports_root, &artifact, whole_report) {
            mark_artifact_deletion_failed(conn, &id, &error)?;
            return Err(error);
        }
        mark_artifact_deleted(conn, &id)?;
        deleted = deleted
            .checked_add(1)
            .ok_or_else(|| internal("报告 artifact 删除计数溢出"))?;
    }
    Ok(deleted)
}

/// Remove only staging directories created by the publisher after an
/// unclean shutdown. No report id is inferred and no finalized directory is
/// touched.
pub fn cleanup_staging(reports_root: &Path) -> AppResult<u64> {
    let root = match SecureRoot::open(reports_root.as_os_str()) {
        Ok(root) => root,
        Err(FsSecureError::NotFound) => return Ok(0),
        Err(error) => return Err(artifact_fs_error("打开报告 staging 根失败", error)),
    };
    let mut removed = 0_u64;
    let entries = root
        .read_dir(OsStr::new(""))
        .map_err(|error| artifact_fs_error("读取报告 staging 目录失败", error))?;
    for entry in entries {
        let entry = entry.map_err(|error| artifact_fs_error("读取报告 staging 项失败", error))?;
        if !entry.name.as_bytes().starts_with(b".tmp-") {
            continue;
        }
        let is_directory = match entry.kind {
            EntryKind::Directory => true,
            EntryKind::Unknown => {
                root.stat(&entry.name)
                    .map_err(|error| artifact_fs_error("检查报告 staging 项失败", error))?
                    .kind
                    == EntryKind::Directory
            }
            _ => false,
        };
        if is_directory {
            root.remove_dir_all(&entry.name)
                .map_err(|error| artifact_fs_error("清理报告 staging 目录失败", error))?;
            removed = removed
                .checked_add(1)
                .ok_or_else(|| internal("报告 staging 清理计数溢出"))?;
        }
    }
    Ok(removed)
}

/// Apply the same retention policy to reports that have no profile id. This
/// is useful for system-generated reports while retaining the exact nullable
/// `reports.profile_id` contract.
pub fn apply_unprofiled_report_retention(
    conn: &mut Connection,
    policy: &ProfileRetention,
) -> AppResult<RetentionResult> {
    apply_report_retention(conn, None, policy)
}

/// Apply a policy and enqueue the generated files selected by the same
/// transaction. The transaction commits before any filesystem deletion;
/// pending intents are then processed and remain retryable on failure.
pub fn apply_report_retention_with_artifacts(
    conn: &mut Connection,
    profile_id: Option<&str>,
    policy: &ProfileRetention,
    reports_root: &Path,
) -> AppResult<RetentionResult> {
    let tx = conn
        .transaction()
        .map_err(|error| internal(format!("开启带 artifact 的报告保留事务失败: {error}")))?;
    let result = apply_report_retention_in_transaction(&tx, profile_id, policy)?;
    validate_artifacts(reports_root, &result)?;
    schedule_artifact_deletions(&tx, &result)?;
    tx.commit()
        .map_err(|error| internal(format!("提交带 artifact 的报告保留事务失败: {error}")))?;
    process_pending_artifact_deletions(conn, reports_root)?;
    Ok(result)
}

/// Read a report's independent pin/detail state.
pub fn get_report_retention_state(
    conn: &Connection,
    report_id: &str,
) -> AppResult<ReportRetentionState> {
    conn.query_row(
        "SELECT id, detail_available, pinned, detail_pinned FROM reports WHERE id = ?1",
        params![report_id],
        |row| {
            Ok(ReportRetentionState {
                report_id: row.get(0)?,
                detail_available: row.get::<_, i64>(1)? != 0,
                report_pinned: row.get::<_, i64>(2)? != 0,
                detail_pinned: row.get::<_, i64>(3)? != 0,
            })
        },
    )
    .optional()
    .map_err(|error| internal(format!("读取报告保留状态失败: {error}")))?
    .ok_or_else(|| not_found("报告不存在"))
}

/// Update the two persisted pins independently. Passing `None` leaves a pin
/// unchanged; passing `Some(false)` explicitly releases it.
pub fn set_report_pins(
    conn: &Connection,
    report_id: &str,
    report_pinned: Option<bool>,
    detail_pinned: Option<bool>,
) -> AppResult<ReportRetentionState> {
    if report_pinned.is_none() && detail_pinned.is_none() {
        return Err(validation("至少需要更新一个报告保留标记"));
    }
    let current = get_report_retention_state(conn, report_id)?;
    let report_pinned = report_pinned.unwrap_or(current.report_pinned);
    let detail_pinned = detail_pinned.unwrap_or(current.detail_pinned);
    conn.execute(
        "UPDATE reports SET pinned = ?2, detail_pinned = ?3 WHERE id = ?1",
        params![report_id, report_pinned, detail_pinned],
    )
    .map_err(|error| internal(format!("更新报告保留标记失败: {error}")))?;
    get_report_retention_state(conn, report_id)
}

/// Require full detail for a report. A summary row is intentionally not
/// treated as an empty detail result once its detail has expired.
pub fn require_report_detail(conn: &Connection, report_id: &str) -> AppResult<()> {
    let state = get_report_retention_state(conn, report_id)?;
    if !state.detail_available {
        return Err(
            AppError::new(ErrorCode::DetailExpired, "报告文件明细已过期")
                .with_details(serde_json::json!({ "report_id": report_id })),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::migrate::{self, CONTROL_MIGRATIONS};
    use fssecure::SecureRoot;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    fn control() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate::apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        conn
    }

    fn insert_report(
        conn: &Connection,
        id: &str,
        created_at: &str,
        pinned: bool,
        detail_pinned: bool,
    ) {
        conn.execute(
            "INSERT INTO reports \
             (id, run_id, profile_id, manifest_path, status, scope_fingerprint, \
              classification_version, detail_available, pinned, detail_pinned, created_at) \
             VALUES (?1, ?2, 'profile-1', ?3, 'SUCCEEDED', 'scope', 1, 1, ?4, ?5, ?6)",
            params![
                id,
                format!("run-{id}"),
                format!("/data/reports/{id}/manifest.json"),
                pinned,
                detail_pinned,
                created_at
            ],
        )
        .unwrap();
    }

    fn policy(reports: u32, details: u32) -> ProfileRetention {
        ProfileRetention {
            report_keep_count: reports,
            detail_keep_count: details,
        }
    }

    #[test]
    fn summary_and_detail_retention_are_independent_and_pins_are_exceptions() {
        let mut conn = control();
        insert_report(&conn, "new", "2026-01-04T00:00:00.000Z", false, false);
        insert_report(&conn, "middle", "2026-01-03T00:00:00.000Z", false, false);
        insert_report(&conn, "old", "2026-01-02T00:00:00.000Z", false, false);
        insert_report(&conn, "pinned", "2026-01-01T00:00:00.000Z", true, false);
        insert_report(
            &conn,
            "detail-pinned",
            "2025-12-31T00:00:00.000Z",
            false,
            true,
        );

        let result = apply_report_retention(&mut conn, Some("profile-1"), &policy(2, 1)).unwrap();
        assert_eq!(
            result
                .reports_deleted
                .iter()
                .map(|report| report.report_id.as_str())
                .collect::<Vec<_>>(),
            vec!["old"]
        );
        assert_eq!(result.detail_expired_report_ids, vec!["middle", "pinned"]);
        assert!(
            get_report_retention_state(&conn, "detail-pinned")
                .unwrap()
                .detail_available
        );
        assert!(
            get_report_retention_state(&conn, "new")
                .unwrap()
                .detail_available
        );
    }

    #[test]
    fn expired_detail_returns_stable_error_code() {
        let conn = control();
        insert_report(&conn, "report-1", "2026-01-01T00:00:00.000Z", false, false);
        conn.execute(
            "UPDATE reports SET detail_available = 0 WHERE id = 'report-1'",
            [],
        )
        .unwrap();
        let error = require_report_detail(&conn, "report-1").unwrap_err();
        assert_eq!(error.code, ErrorCode::DetailExpired);
    }

    #[test]
    fn pin_update_uses_persisted_columns() {
        let conn = control();
        insert_report(&conn, "report-1", "2026-01-01T00:00:00.000Z", false, false);
        let state = set_report_pins(&conn, "report-1", Some(true), Some(true)).unwrap();
        assert!(state.report_pinned);
        assert!(state.detail_pinned);
    }

    #[test]
    fn artifact_cleanup_uses_persisted_manifest_and_keeps_summary() {
        let root = tempdir().unwrap();
        let reports_root = root.path().join("reports");
        std::fs::create_dir_all(reports_root.join("old")).unwrap();
        std::fs::write(reports_root.join("old/manifest.json"), b"{}").unwrap();
        std::fs::write(reports_root.join("old/index.sqlite"), b"detail").unwrap();
        std::fs::write(reports_root.join("old/report.sqlite"), b"summary").unwrap();
        std::fs::create_dir_all(reports_root.join("new")).unwrap();
        std::fs::write(reports_root.join("new/manifest.json"), b"{}").unwrap();
        std::fs::write(reports_root.join("new/index.sqlite"), b"detail").unwrap();
        if !SecureRoot::open(reports_root.as_os_str())
            .unwrap()
            .caps()
            .supports_safe_writes()
        {
            eprintln!("note: openat2 unavailable; skipping secure artifact cleanup test");
            return;
        }

        let mut conn = control();
        conn.execute(
            "INSERT INTO reports
             (id, run_id, profile_id, manifest_path, status, scope_fingerprint,
              classification_version, detail_available, pinned, detail_pinned, created_at)
             VALUES ('old', 'run-old', 'profile-1', ?1, 'SUCCEEDED', 'scope', 1, 1, 0, 0,
                     '2026-01-01T00:00:00.000Z')",
            [reports_root
                .join("old/manifest.json")
                .to_string_lossy()
                .as_ref()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO reports
             (id, run_id, profile_id, manifest_path, status, scope_fingerprint,
              classification_version, detail_available, pinned, detail_pinned, created_at)
             VALUES ('new', 'run-new', 'profile-1', ?1, 'SUCCEEDED', 'scope', 1, 1, 0, 0,
                     '2026-01-02T00:00:00.000Z')",
            [reports_root
                .join("new/manifest.json")
                .to_string_lossy()
                .as_ref()],
        )
        .unwrap();

        let result = apply_report_retention_with_artifacts(
            &mut conn,
            Some("profile-1"),
            &policy(2, 1),
            &reports_root,
        )
        .unwrap();
        assert_eq!(result.reports_deleted.len(), 0);
        assert!(reports_root.join("old/manifest.json").is_file());
        assert!(!reports_root.join("old/index.sqlite").exists());
        assert!(reports_root.join("old/report.sqlite").is_file());
    }

    #[test]
    fn whole_report_cleanup_removes_only_the_persisted_report_tree() {
        let root = tempdir().unwrap();
        let reports_root = root.path().join("reports");
        std::fs::create_dir_all(reports_root.join("old/nested")).unwrap();
        std::fs::write(reports_root.join("old/manifest.json"), b"{}").unwrap();
        std::fs::write(reports_root.join("old/nested/data"), b"detail").unwrap();
        std::fs::create_dir_all(reports_root.join("new")).unwrap();
        std::fs::write(reports_root.join("new/manifest.json"), b"{}").unwrap();
        if !SecureRoot::open(reports_root.as_os_str())
            .unwrap()
            .caps()
            .supports_safe_writes()
        {
            eprintln!("note: openat2 unavailable; skipping secure report tree cleanup test");
            return;
        }

        let mut conn = control();
        conn.execute(
            "INSERT INTO reports
             (id, run_id, profile_id, manifest_path, status, scope_fingerprint,
              classification_version, detail_available, pinned, detail_pinned, created_at)
             VALUES ('old', 'run-old', 'profile-1', ?1, 'SUCCEEDED', 'scope', 1, 1, 0, 0,
                     '2026-01-01T00:00:00.000Z')",
            [reports_root
                .join("old/manifest.json")
                .to_string_lossy()
                .as_ref()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO reports
             (id, run_id, profile_id, manifest_path, status, scope_fingerprint,
              classification_version, detail_available, pinned, detail_pinned, created_at)
             VALUES ('new', 'run-new', 'profile-1', ?1, 'SUCCEEDED', 'scope', 1, 1, 0, 0,
                     '2026-01-02T00:00:00.000Z')",
            [reports_root
                .join("new/manifest.json")
                .to_string_lossy()
                .as_ref()],
        )
        .unwrap();

        let result = apply_report_retention_with_artifacts(
            &mut conn,
            Some("profile-1"),
            &policy(1, 1),
            &reports_root,
        )
        .unwrap();

        assert_eq!(
            result
                .reports_deleted
                .iter()
                .map(|report| report.report_id.as_str())
                .collect::<Vec<_>>(),
            vec!["old"]
        );
        assert!(!reports_root.join("old").exists());
        assert!(reports_root.join("new/manifest.json").is_file());
    }

    #[test]
    fn artifact_cleanup_refuses_symlink_instead_of_following_or_unlinking_it() {
        let root = tempdir().unwrap();
        let reports_root = root.path().join("reports");
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("sentinel"), b"outside").unwrap();
        std::fs::create_dir_all(reports_root.join("old")).unwrap();
        std::fs::write(reports_root.join("old/manifest.json"), b"{}").unwrap();
        symlink(
            outside.path().join("sentinel"),
            reports_root.join("old/index.sqlite"),
        )
        .unwrap();
        std::fs::create_dir_all(reports_root.join("new")).unwrap();
        std::fs::write(reports_root.join("new/manifest.json"), b"{}").unwrap();
        if !SecureRoot::open(reports_root.as_os_str())
            .unwrap()
            .caps()
            .supports_safe_writes()
        {
            eprintln!("note: openat2 unavailable; skipping adversarial artifact cleanup test");
            return;
        }

        let mut conn = control();
        conn.execute(
            "INSERT INTO reports
             (id, run_id, profile_id, manifest_path, status, scope_fingerprint,
              classification_version, detail_available, pinned, detail_pinned, created_at)
             VALUES ('old', 'run-old', 'profile-1', ?1, 'SUCCEEDED', 'scope', 1, 1, 0, 0,
                     '2026-01-01T00:00:00.000Z')",
            [reports_root
                .join("old/manifest.json")
                .to_string_lossy()
                .as_ref()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO reports
             (id, run_id, profile_id, manifest_path, status, scope_fingerprint,
              classification_version, detail_available, pinned, detail_pinned, created_at)
             VALUES ('new', 'run-new', 'profile-1', ?1, 'SUCCEEDED', 'scope', 1, 1, 0, 0,
                     '2026-01-02T00:00:00.000Z')",
            [reports_root
                .join("new/manifest.json")
                .to_string_lossy()
                .as_ref()],
        )
        .unwrap();

        let error = apply_report_retention_with_artifacts(
            &mut conn,
            Some("profile-1"),
            &policy(2, 1),
            &reports_root,
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::ValidationFailed);
        assert!(
            !get_report_retention_state(&conn, "old")
                .unwrap()
                .detail_available
        );
        assert!(
            reports_root
                .join("old/index.sqlite")
                .symlink_metadata()
                .is_ok()
        );
        assert_eq!(
            std::fs::read(outside.path().join("sentinel")).unwrap(),
            b"outside"
        );
        let pending: (String, i64, Option<String>) = conn
            .query_row(
                "SELECT state, attempts, last_error
                 FROM report_artifact_deletions
                 WHERE report_id = 'old' AND artifact_kind = 'detail'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(pending.0, "pending");
        assert_eq!(pending.1, 1);
        assert!(pending.2.is_some());

        std::fs::remove_file(reports_root.join("old/index.sqlite")).unwrap();
        std::fs::write(reports_root.join("old/index.sqlite"), b"detail").unwrap();
        assert_eq!(
            process_pending_artifact_deletions(&mut conn, &reports_root).unwrap(),
            1
        );
        let state: (String, i64, Option<String>) = conn
            .query_row(
                "SELECT state, attempts, last_error
                 FROM report_artifact_deletions
                 WHERE report_id = 'old' AND artifact_kind = 'detail'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state.0, "deleted");
        assert_eq!(state.1, 2);
        assert!(state.2.is_none());
        assert!(!reports_root.join("old/index.sqlite").exists());
        assert_eq!(
            std::fs::read(outside.path().join("sentinel")).unwrap(),
            b"outside"
        );
    }

    #[test]
    fn staging_cleanup_removes_only_publisher_prefix() {
        let root = tempdir().unwrap();
        let reports_root = root.path().join("reports");
        std::fs::create_dir_all(reports_root.join(".tmp-report")).unwrap();
        std::fs::create_dir_all(reports_root.join("final")).unwrap();
        if !SecureRoot::open(reports_root.as_os_str())
            .unwrap()
            .caps()
            .supports_safe_writes()
        {
            eprintln!("note: openat2 unavailable; skipping secure staging cleanup test");
            return;
        }
        assert_eq!(cleanup_staging(&reports_root).unwrap(), 1);
        assert!(!reports_root.join(".tmp-report").exists());
        assert!(reports_root.join("final").exists());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn artifact_cleanup_fails_closed_without_openat2_write_capability() {
        let root = tempdir().unwrap();
        let reports_root = root.path().join("reports");
        std::fs::create_dir_all(reports_root.join("old")).unwrap();
        std::fs::write(reports_root.join("old/manifest.json"), b"{}").unwrap();
        let result = RetentionResult {
            reports_deleted: vec![ExpiredReportArtifact {
                report_id: "old".to_string(),
                manifest_path: reports_root
                    .join("old/manifest.json")
                    .to_string_lossy()
                    .into_owned(),
            }],
            ..RetentionResult::default()
        };

        let error = remove_expired_artifacts(&reports_root, &result).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedCapability);
        assert!(reports_root.join("old/manifest.json").is_file());
    }
}
