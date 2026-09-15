//! Immutable report publication and report-index query primitives.
//!
//! A scan writes its mutable detail index under `runs/<run_id>`. Publication
//! builds the summary database in a private directory, writes a manifest, and
//! exposes the finished directory with one rename. The control database is
//! updated only after this function returns successfully.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write, copy};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::io::{Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use fssecure::{EntryKind, FsSecureError, OpenOptions, SecureRoot};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult, ErrorCode};
use crate::store::migrate::{self, REPORT_MIGRATIONS};
use crate::volume::VolumeSample;

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

fn validation(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, msg)
}

#[derive(Debug, Clone, Serialize)]
pub struct PublishedReport {
    pub id: String,
    pub run_id: String,
    pub directory: PathBuf,
    pub manifest_path: PathBuf,
    pub status: String,
    pub detail_available: bool,
    pub scan_started_at: Option<String>,
    pub scan_finished_at: Option<String>,
}

/// Immutable control-plane values captured at the moment a scan is published.
/// The worker obtains these values from the control-db writer before handing
/// them to this module; report readers never consult current control tables.
#[derive(Debug, Clone, Default)]
pub struct ReportSnapshot {
    pub volume_samples: Vec<VolumeSample>,
    pub quotas: Vec<QuotaSnapshot>,
    pub source_identities: Vec<SourceIdentitySnapshot>,
    pub section_status: Vec<SectionStatusSnapshot>,
    pub scope_snapshot: Option<serde_json::Value>,
    pub profile_fingerprint: Option<String>,
    pub ruleset_fingerprint: Option<String>,
    pub owner_ids_to_list: Vec<i64>,
}

#[derive(Debug, Clone)]
pub struct QuotaSnapshot {
    pub principal_namespace: String,
    pub principal_uid: i64,
    pub scope_kind: String,
    pub scope_id: String,
    pub metric: String,
    pub origin: String,
    pub limit_state: String,
    pub limit_bytes: Option<String>,
    pub used_bytes: Option<String>,
    pub observed_at: String,
    pub expires_at: Option<String>,
    pub provider_label: String,
    pub stale: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceIdentitySnapshot {
    pub source_id: String,
    pub identity_epoch: i64,
    pub availability: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SectionStatusSnapshot {
    pub section: String,
    pub quality: String,
    pub error_count: i64,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Manifest {
    schema_version: u32,
    app_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ruleset_fingerprint: Option<String>,
    report_id: String,
    run_id: String,
    status: String,
    consistency: String,
    scope_fingerprint: String,
    classification_version: u32,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Serialize)]
struct ManifestFile {
    path: String,
    size_bytes: String,
    sha256: String,
}

#[cfg(target_os = "linux")]
struct TemporaryDatabasePath {
    path: PathBuf,
    _directory: tempfile::TempDir,
}

#[cfg(target_os = "linux")]
impl TemporaryDatabasePath {
    fn cleanup(self) -> AppResult<()> {
        std::fs::remove_file(&self.path)
            .map_err(|error| AppError::from_io("清理报告数据库临时副本失败", error))?;
        drop(self);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for TemporaryDatabasePath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(target_os = "linux")]
fn immutable_sqlite_uri(path: &Path) -> PathBuf {
    let mut uri = Vec::with_capacity(5 + path.as_os_str().len() + 13);
    uri.extend_from_slice(b"file:");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            uri.push(*byte);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            uri.extend_from_slice(&[b'%', HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]]);
        }
    }
    uri.extend_from_slice(b"?immutable=1");
    PathBuf::from(OsString::from_vec(uri))
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
        FsSecureError::AlreadyExists => ErrorCode::Conflict,
        FsSecureError::NotFound => ErrorCode::NotFound,
        FsSecureError::PermissionDenied => ErrorCode::Forbidden,
        _ => ErrorCode::Internal,
    };
    AppError::new(code, format!("{operation}: {error}"))
}

fn open_artifact_root(path: &Path) -> AppResult<SecureRoot> {
    if !path.is_absolute() {
        return Err(validation("报告 artifact 根必须是绝对路径"));
    }
    SecureRoot::open(path.as_os_str())
        .map_err(|error| artifact_fs_error("打开报告 artifact 根失败", error))
}

fn require_safe_writes(root: &SecureRoot) -> AppResult<()> {
    if !root.caps().supports_safe_writes() {
        return Err(AppError::new(
            ErrorCode::UnsupportedCapability,
            "报告 artifact 写入需要 openat2 安全解析能力",
        ));
    }
    Ok(())
}

fn open_source_index(index_path: &Path) -> AppResult<File> {
    if !index_path.is_absolute() {
        return Err(validation("扫描索引路径必须是绝对路径"));
    }
    let parent = index_path
        .parent()
        .ok_or_else(|| validation("扫描索引路径缺少父目录"))?;
    let name = index_path
        .file_name()
        .ok_or_else(|| validation("扫描索引路径缺少文件名"))?;
    let root = SecureRoot::open(parent.as_os_str())
        .map_err(|error| artifact_fs_error("打开扫描索引根失败", error))?;
    let opened = root
        .open_file(name, OpenOptions::default())
        .map_err(|error| artifact_fs_error("打开扫描索引失败", error))?;
    if opened.stat.kind != EntryKind::RegularFile {
        return Err(validation("扫描索引不是普通文件"));
    }
    Ok(File::from(opened.fd))
}

fn manifest_file(root: &SecureRoot, relative: &Path, display: &str) -> AppResult<ManifestFile> {
    let opened = root
        .open_file(relative.as_os_str(), OpenOptions::default())
        .map_err(|error| artifact_fs_error(&format!("打开报告文件 {display} 失败"), error))?;
    if opened.stat.kind != EntryKind::RegularFile {
        return Err(validation(format!("报告文件 {display} 不是普通文件")));
    }
    let size_bytes = opened.stat.size_bytes.to_string();
    let mut file = File::from(opened.fd);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| AppError::from_io(format!("读取报告文件 {display} 失败"), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(ManifestFile {
        path: display.to_string(),
        size_bytes,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn open_read_only_database(path: &Path, operation: &str) -> AppResult<Connection> {
    if !path.is_absolute() {
        return Err(validation(format!(
            "{operation}: artifact 路径必须是绝对路径"
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| validation(format!("{operation}: artifact 路径缺少父目录")))?;
    let name = path
        .file_name()
        .ok_or_else(|| validation(format!("{operation}: artifact 路径缺少文件名")))?;
    let root = open_artifact_root(parent)?;
    let opened = root
        .open_file(name, OpenOptions::default())
        .map_err(|error| artifact_fs_error(operation, error))?;
    if opened.stat.kind != EntryKind::RegularFile {
        return Err(validation(format!("{operation}: artifact 不是普通文件")));
    }
    open_read_only_database_from_opened(opened, operation)
}

fn open_read_only_database_from_opened(
    opened: fssecure::OpenedFile,
    operation: &str,
) -> AppResult<Connection> {
    open_read_only_database_from_file(File::from(opened.fd), operation)
}

fn open_read_only_database_from_file(file: File, operation: &str) -> AppResult<Connection> {
    // The original artifact path must never be reopened after fssecure has
    // validated it. Linux's bundled SQLite VFS adds O_NOFOLLOW to every
    // pathname open, so its final `/dev/fd/<fd>` symlink cannot be used as a
    // SQLite pathname. Stage the already-open inode under a private temporary
    // pathname instead; the normal case is an O(1) hard link, while an
    // unlinked descriptor is streamed into that private file.
    #[cfg(target_os = "linux")]
    let (database_path, temporary_directory) = {
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let staging_directory = std::fs::read_link(&descriptor_path)
            .map_err(|error| AppError::from_io("读取报告数据库描述符路径失败", error))?
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| validation("报告数据库描述符没有临时目录"))?;
        let temporary_directory = tempfile::tempdir_in(staging_directory)
            .map_err(|error| AppError::from_io("创建报告数据库临时目录失败", error))?;
        let database_path = temporary_directory.path().join("database.sqlite");
        let temporary = TemporaryDatabasePath {
            path: database_path.clone(),
            _directory: temporary_directory,
        };
        let linked = rustix::fs::linkat(
            rustix::fs::CWD,
            descriptor_path.as_os_str(),
            rustix::fs::CWD,
            database_path.as_os_str(),
            rustix::fs::AtFlags::SYMLINK_FOLLOW,
        )
        .is_ok();
        if !linked {
            let mut source = file;
            source
                .seek(SeekFrom::Start(0))
                .map_err(|error| AppError::from_io("定位报告数据库临时副本失败", error))?;
            let mut staged = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&database_path)
                .map_err(|error| AppError::from_io("创建报告数据库临时副本失败", error))?;
            copy(&mut source, &mut staged)
                .map_err(|error| AppError::from_io("复制报告数据库临时副本失败", error))?;
            staged
                .sync_all()
                .map_err(|error| AppError::from_io("同步报告数据库临时副本失败", error))?;
        }
        (temporary.path.clone(), temporary)
    };

    #[cfg(not(target_os = "linux"))]
    let database_path = {
        // On the development host the VFS accepts the descriptor path; it
        // still points only at the descriptor validated by fssecure.
        PathBuf::from(format!("/dev/fd/{}", file.as_raw_fd()))
    };

    #[cfg(target_os = "linux")]
    let database_uri = immutable_sqlite_uri(&database_path);
    #[cfg(not(target_os = "linux"))]
    let database_uri = database_path;

    let connection = Connection::open_with_flags(
        database_uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| AppError::from_sqlite(operation, error))?;

    #[cfg(target_os = "linux")]
    temporary_directory.cleanup()?;

    Ok(connection)
}

fn display_path(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

fn depth(raw: &[u8]) -> i64 {
    raw.split(|b| *b == b'/')
        .filter(|part| !part.is_empty())
        .count() as i64
}

fn source_name<'a>(names: &'a BTreeMap<String, String>, source_id: &str) -> AppResult<&'a str> {
    names
        .get(source_id)
        .map(String::as_str)
        .ok_or_else(|| internal(format!("报告来源缺少 source_id={source_id} 的名称快照")))
}

fn populate_summary(
    index: &Connection,
    report: &mut Connection,
    source_names: &BTreeMap<String, String>,
    max_rank: u32,
    owner_ids_to_list: &[i64],
) -> AppResult<()> {
    let tx = report
        .transaction()
        .map_err(|e| AppError::from_sqlite("开启报告发布事务失败", e))?;

    tx.execute_batch(
        "CREATE TABLE report_folders (
             entry_id INTEGER PRIMARY KEY,
             source_id TEXT NOT NULL,
             parent_entry_id INTEGER,
             name TEXT NOT NULL,
             raw_relative_path BLOB NOT NULL,
             display_path TEXT NOT NULL,
             file_count INTEGER NOT NULL,
             subdirectory_count INTEGER NOT NULL,
             logical_bytes INTEGER,
             unique_logical_bytes INTEGER,
             allocated_estimate_bytes INTEGER,
             quality TEXT NOT NULL
         );
         CREATE INDEX idx_report_folders_parent
             ON report_folders(parent_entry_id, entry_id);",
    )
    .map_err(|e| AppError::from_sqlite("创建报告目录查询表失败", e))?;
    tx.execute_batch(
        "CREATE TABLE owner_list_snapshot (
             source_id TEXT NOT NULL,
             uid INTEGER NOT NULL,
             file_count INTEGER NOT NULL,
             logical_bytes INTEGER
         );",
    )
    .map_err(|e| AppError::from_sqlite("创建所有者附加快照表失败", e))?;

    let mut folders = index
        .prepare(
            "SELECT e.entry_id, e.source_id, e.raw_relative_path, e.display_name,
                    e.parent_entry_id,
                    a.file_count, a.dir_count, a.logical_bytes,
                    a.unique_logical_bytes, a.allocated_bytes,
                    o.status
             FROM entries e
             JOIN directory_aggregates a ON a.entry_id = e.entry_id
             JOIN source_observations o ON o.source_id = e.source_id
             WHERE e.entry_kind = 'directory'
             ORDER BY e.source_id, e.entry_id",
        )
        .map_err(|e| AppError::from_sqlite("准备目录聚合查询失败", e))?;
    let folder_rows = folders
        .query_map([], |row| {
            let entry_id: i64 = row.get(0)?;
            let source_id: String = row.get(1)?;
            let raw: Vec<u8> = row.get(2)?;
            let folder_name: String = row.get(3)?;
            let parent_id: Option<i64> = row.get(4)?;
            let parent_path: Option<Vec<u8>> = parent_id.and_then(|id| {
                index
                    .query_row(
                        "SELECT raw_relative_path FROM entries WHERE entry_id = ?1",
                        [id],
                        |r| r.get(0),
                    )
                    .optional()
                    .ok()
                    .flatten()
            });
            Ok((
                entry_id,
                source_id,
                raw,
                folder_name,
                parent_path,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, String>(10)?,
            ))
        })
        .map_err(|e| AppError::from_sqlite("读取目录聚合失败", e))?;
    for row in folder_rows {
        let (
            entry_id,
            source_id,
            raw,
            folder_name,
            parent_path,
            file_count,
            dir_count,
            logical,
            unique,
            allocated,
            completeness,
        ) = row.map_err(|e| AppError::from_sqlite("读取目录聚合行失败", e))?;
        let completeness = if completeness == "complete"
            && logical.is_some()
            && unique.is_some()
            && allocated.is_some()
        {
            "complete"
        } else if logical.is_none() || unique.is_none() || allocated.is_none() {
            "unknown"
        } else {
            completeness.as_str()
        };
        let source_display_name = source_name(source_names, &source_id)?;
        tx.execute(
            "INSERT INTO folder_aggregates
             (source_id, source_name, parent_path, raw_relative_path, display_path,
              depth, file_count, dir_count, logical_bytes, unique_logical_bytes,
              allocated_bytes, completeness)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                source_id,
                source_display_name,
                parent_path,
                raw,
                display_path(&raw),
                depth(&raw),
                file_count,
                dir_count,
                logical,
                unique,
                allocated,
                completeness,
            ],
        )
        .map_err(|e| AppError::from_sqlite("写入目录聚合失败", e))?;
        let parent_entry_id = index
            .query_row(
                "SELECT parent_entry_id FROM entries WHERE entry_id = ?1",
                [entry_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map_err(|e| AppError::from_sqlite("读取目录父 entry_id 失败", e))?;
        tx.execute(
            "INSERT INTO report_folders
             (entry_id, source_id, parent_entry_id, name, raw_relative_path, display_path,
              file_count, subdirectory_count, logical_bytes, unique_logical_bytes,
              allocated_estimate_bytes, quality)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                entry_id,
                source_id,
                parent_entry_id,
                folder_name,
                raw,
                display_path(&raw),
                file_count,
                dir_count,
                logical,
                unique,
                allocated,
                completeness,
            ],
        )
        .map_err(|e| AppError::from_sqlite("写入报告目录查询表失败", e))?;
    }

    let mut owners = index
        .prepare(
            "SELECT source_id, uid, file_count, logical_bytes
             FROM owner_aggregates ORDER BY source_id, uid",
        )
        .map_err(|e| AppError::from_sqlite("准备所有者聚合查询失败", e))?;
    let owner_rows = owners
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })
        .map_err(|e| AppError::from_sqlite("读取所有者聚合失败", e))?;
    for row in owner_rows {
        let (source_id, uid, count, logical) =
            row.map_err(|e| AppError::from_sqlite("读取所有者聚合行失败", e))?;
        tx.execute(
            "INSERT INTO owner_aggregates(source_id, uid, file_count, logical_bytes)
             VALUES (?1, ?2, ?3, ?4)",
            params![source_id, uid, count, logical],
        )
        .map_err(|e| AppError::from_sqlite("写入所有者聚合失败", e))?;
    }
    for uid in owner_ids_to_list {
        let mut statement = index
            .prepare(
                "SELECT source_id, uid, file_count, logical_bytes
                 FROM owner_aggregates WHERE uid = ?1 ORDER BY source_id",
            )
            .map_err(|e| AppError::from_sqlite("准备所有者附加快照查询失败", e))?;
        let rows = statement
            .query_map([uid], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(|e| AppError::from_sqlite("读取所有者附加快照失败", e))?;
        for row in rows {
            let (source_id, uid, file_count, logical_bytes) =
                row.map_err(|e| AppError::from_sqlite("读取所有者附加快照行失败", e))?;
            tx.execute(
                "INSERT INTO owner_list_snapshot(source_id, uid, file_count, logical_bytes)
                 VALUES (?1, ?2, ?3, ?4)",
                params![source_id, uid, file_count, logical_bytes],
            )
            .map_err(|e| AppError::from_sqlite("写入所有者附加快照失败", e))?;
        }
    }

    let mut owner_categories = index
        .prepare(
            "SELECT source_id, uid, category_id, COUNT(*),
                    CASE WHEN COUNT(size_bytes) < COUNT(*) THEN NULL ELSE SUM(size_bytes) END
             FROM entries
             WHERE entry_kind = 'regular_file' AND category_id IS NOT NULL
             GROUP BY source_id, uid, category_id
             ORDER BY source_id, uid, category_id",
        )
        .map_err(|e| AppError::from_sqlite("准备所有者分类聚合查询失败", e))?;
    let owner_category_rows = owner_categories
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .map_err(|e| AppError::from_sqlite("读取所有者分类聚合失败", e))?;
    for row in owner_category_rows {
        let (source_id, uid, category_id, count, logical) =
            row.map_err(|e| AppError::from_sqlite("读取所有者分类聚合行失败", e))?;
        tx.execute(
            "INSERT INTO owner_category_aggregates
             (source_id, uid, category_id, file_count, logical_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![source_id, uid, category_id, count, logical],
        )
        .map_err(|e| AppError::from_sqlite("写入所有者分类聚合失败", e))?;
    }

    let mut category_extensions = index
        .prepare(
            "SELECT source_id, category_id, extension, COUNT(*),
                    CASE WHEN COUNT(size_bytes) < COUNT(*) THEN NULL ELSE SUM(size_bytes) END
             FROM entries
             WHERE entry_kind = 'regular_file' AND category_id IS NOT NULL
             GROUP BY source_id, category_id, extension
             ORDER BY source_id, category_id, extension",
        )
        .map_err(|e| AppError::from_sqlite("准备扩展名聚合查询失败", e))?;
    let extension_rows = category_extensions
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .map_err(|e| AppError::from_sqlite("读取扩展名聚合失败", e))?;
    for row in extension_rows {
        let (source_id, category_id, extension, count, logical) =
            row.map_err(|e| AppError::from_sqlite("读取扩展名聚合行失败", e))?;
        tx.execute(
            "INSERT INTO category_extension_aggregates
             (source_id, category_id, extension, file_count, logical_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![source_id, category_id, extension, count, logical],
        )
        .map_err(|e| AppError::from_sqlite("写入扩展名聚合失败", e))?;
    }

    let mut categories = index
        .prepare(
            "SELECT source_id, category_id, file_count, logical_bytes, allocated_bytes
             FROM category_aggregates ORDER BY source_id, category_id",
        )
        .map_err(|e| AppError::from_sqlite("准备分类聚合查询失败", e))?;
    let category_rows = categories
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .map_err(|e| AppError::from_sqlite("读取分类聚合失败", e))?;
    for row in category_rows {
        let (source_id, category_id, count, logical, allocated) =
            row.map_err(|e| AppError::from_sqlite("读取分类聚合行失败", e))?;
        tx.execute(
            "INSERT INTO category_aggregates
             (source_id, category_id, file_count, logical_bytes, allocated_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![source_id, category_id, count, logical, allocated],
        )
        .map_err(|e| AppError::from_sqlite("写入分类聚合失败", e))?;
    }

    let rank_limit = i64::from(max_rank.clamp(1, 10_000));
    for (kind, order_by) in [
        ("largest", "size_bytes DESC, entry_id ASC"),
        (
            "recently_modified",
            "mtime_sec DESC, mtime_nsec DESC, entry_id ASC",
        ),
        (
            "least_accessed",
            "atime_sec ASC, atime_nsec ASC, entry_id ASC",
        ),
    ] {
        let sql = format!(
            "SELECT entry_id, source_id, raw_relative_path, display_name, uid,
                    category_id, size_bytes, allocated_bytes_estimate,
                    mtime_sec, mtime_nsec, atime_sec, atime_nsec
             FROM entries WHERE entry_kind = 'regular_file'
               AND size_bytes IS NOT NULL ORDER BY {order_by} LIMIT ?1"
        );
        let mut stmt = index
            .prepare(&sql)
            .map_err(|e| AppError::from_sqlite("准备排行查询失败", e))?;
        let rows = stmt
            .query_map([rank_limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                ))
            })
            .map_err(|e| AppError::from_sqlite("读取排行失败", e))?;
        for (rank, row) in rows.enumerate() {
            let (
                entry_id,
                source_id,
                raw,
                display_name,
                uid,
                category_id,
                size,
                allocated,
                mtime_sec,
                mtime_nsec,
                atime_sec,
                atime_nsec,
            ) = row.map_err(|e| AppError::from_sqlite("读取排行行失败", e))?;
            let _ = source_name(source_names, &source_id)?;
            tx.execute(
                "INSERT INTO rankings
                 (kind, rank, entry_id, source_id, raw_relative_path, display_path, display_name,
                  uid, category_id, size_bytes, allocated_bytes_estimate,
                  mtime_sec, mtime_nsec, atime_sec, atime_nsec)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                         ?12, ?13, ?14, ?15)",
                params![
                    kind,
                    i64::try_from(rank + 1).map_err(|_| validation("排行序号溢出"))?,
                    entry_id,
                    source_id,
                    raw,
                    display_path(&raw),
                    display_name,
                    uid,
                    category_id,
                    size,
                    allocated,
                    mtime_sec,
                    mtime_nsec,
                    atime_sec,
                    atime_nsec,
                ],
            )
            .map_err(|e| AppError::from_sqlite("写入排行失败", e))?;
        }
    }
    tx.commit()
        .map_err(|e| AppError::from_sqlite("提交报告汇总失败", e))?;
    Ok(())
}

/// Copy duplicate verification results into the immutable report database.
/// The run index is mutable while the scan is running, so report readers must
/// never query it after publication. Only members selected by the hash stage
/// are copied; a truncated group remains explicitly marked as such.
fn populate_duplicates(index: &Connection, report: &mut Connection) -> AppResult<()> {
    let tx = report
        .transaction()
        .map_err(|e| AppError::from_sqlite("开启重复组发布事务失败", e))?;
    let mut groups = index
        .prepare(
            "SELECT group_id, size_bytes, sha256, member_count,
                    listed_member_count, logical_redundancy_bytes, truncated,
                    verification
             FROM duplicate_groups ORDER BY group_id",
        )
        .map_err(|e| AppError::from_sqlite("准备重复组快照查询失败", e))?;
    let group_rows = groups
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(|e| AppError::from_sqlite("读取重复组快照失败", e))?;
    for row in group_rows {
        let (group_id, size, hash, member_count, listed, redundant, truncated, verification) =
            row.map_err(|e| AppError::from_sqlite("读取重复组快照行失败", e))?;
        tx.execute(
            "INSERT INTO duplicate_groups
             (group_id, size_bytes, sha256, member_count, listed_member_count,
              logical_redundancy_bytes, truncated, verification)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                group_id,
                size,
                hash,
                member_count,
                listed,
                redundant,
                truncated,
                if verification == "full" {
                    "hash_complete"
                } else {
                    "hash_incomplete"
                },
            ],
        )
        .map_err(|e| AppError::from_sqlite("写入重复组快照失败", e))?;

        let mut members = index
            .prepare(
                "SELECT m.entry_id, e.source_id, e.raw_relative_path,
                        e.uid, e.mtime_sec, e.mtime_nsec, e.nlink,
                        e.file_identity_key
                 FROM duplicate_members m
                 JOIN entries e ON e.entry_id = m.entry_id
                 WHERE m.group_id = ?1 ORDER BY m.entry_id",
            )
            .map_err(|e| AppError::from_sqlite("准备重复成员快照查询失败", e))?;
        let member_rows = members
            .query_map([group_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            })
            .map_err(|e| AppError::from_sqlite("读取重复成员快照失败", e))?;
        for member in member_rows {
            let (entry_id, source_id, raw_path, uid, mtime_sec, mtime_nsec, _nlink, _identity) =
                member.map_err(|e| AppError::from_sqlite("读取重复成员快照行失败", e))?;
            let hardlink_alias = index
                .query_row(
                    "SELECT is_hardlink_alias FROM duplicate_members
                     WHERE group_id = ?1 AND entry_id = ?2",
                    params![group_id, entry_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|e| AppError::from_sqlite("读取重复成员别名标记失败", e))?;
            tx.execute(
                "INSERT INTO duplicate_members
                 (group_id, entry_id, source_id, raw_relative_path, display_path,
                  uid, mtime_sec, mtime_nsec, protected, hardlink_alias)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
                params![
                    group_id,
                    entry_id,
                    source_id,
                    raw_path,
                    display_path(&raw_path),
                    uid,
                    mtime_sec,
                    mtime_nsec,
                    hardlink_alias,
                ],
            )
            .map_err(|e| AppError::from_sqlite("写入重复成员快照失败", e))?;
        }
    }
    drop(groups);
    tx.commit()
        .map_err(|e| AppError::from_sqlite("提交重复组快照失败", e))?;
    Ok(())
}

fn populate_snapshot(report: &mut Connection, snapshot: &ReportSnapshot) -> AppResult<()> {
    let tx = report
        .transaction()
        .map_err(|e| AppError::from_sqlite("开启报告快照事务失败", e))?;
    for sample in &snapshot.volume_samples {
        let quality = match sample.quality {
            crate::volume::SampleQuality::Ok => "ok",
            crate::volume::SampleQuality::Error => "error",
        };
        tx.execute(
            "INSERT INTO volume_samples_snapshot
             (volume_id, sample_time, total_bytes, free_bytes, available_bytes, used_bytes, quality)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                sample.volume_id,
                sample.sample_time,
                sample.total_bytes.map(|value| value.to_string()),
                sample.free_bytes.map(|value| value.to_string()),
                sample.available_bytes.map(|value| value.to_string()),
                sample.used_bytes.map(|value| value.to_string()),
                quality,
            ],
        )
        .map_err(|e| AppError::from_sqlite("写入报告容量快照失败", e))?;
    }
    for quota in &snapshot.quotas {
        tx.execute(
            "INSERT INTO quota_snapshot
             (principal_namespace, principal_uid, scope_kind, scope_id, metric, origin,
              limit_state, limit_bytes, used_bytes, observed_at, expires_at, provider_label, stale)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                quota.principal_namespace,
                quota.principal_uid,
                quota.scope_kind,
                quota.scope_id,
                quota.metric,
                quota.origin,
                quota.limit_state,
                quota.limit_bytes,
                quota.used_bytes,
                quota.observed_at,
                quota.expires_at,
                quota.provider_label,
                quota.stale,
            ],
        )
        .map_err(|e| AppError::from_sqlite("写入报告配额快照失败", e))?;
    }
    for section in &snapshot.section_status {
        tx.execute(
            "INSERT INTO section_status(section, quality, error_count, message)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                section.section,
                section.quality,
                section.error_count,
                section.message,
            ],
        )
        .map_err(|e| AppError::from_sqlite("写入报告栏目状态失败", e))?;
    }
    tx.commit()
        .map_err(|e| AppError::from_sqlite("提交报告快照失败", e))?;
    Ok(())
}

/// Publish one scan result atomically. The paths passed here are application
/// data paths selected by the worker, never browser supplied paths.
#[allow(clippy::too_many_arguments)]
pub fn publish_with_snapshot(
    index_path: &Path,
    reports_root: &Path,
    report_id: &str,
    run_id: &str,
    status: &str,
    consistency: &str,
    scope_fingerprint: &str,
    classification_version: u32,
    source_names: &BTreeMap<String, String>,
    max_rank: u32,
    snapshot: &ReportSnapshot,
) -> AppResult<PublishedReport> {
    if report_id.is_empty() || run_id.is_empty() {
        return Err(validation("report_id 和 run_id 不能为空"));
    }
    if !matches!(status, "succeeded" | "partial" | "failed") {
        return Err(validation(format!("未知报告状态: {status}")));
    }
    let root = open_artifact_root(reports_root)?;
    require_safe_writes(&root)?;
    let final_dir = reports_root.join(report_id);
    match root.stat(OsStr::new(report_id)) {
        Ok(_) => {
            return Err(AppError::new(
                ErrorCode::Conflict,
                format!("报告目录已存在: {report_id}"),
            ));
        }
        Err(FsSecureError::NotFound) => {}
        Err(error) => return Err(artifact_fs_error("检查报告目录失败", error)),
    }
    let temp_name = format!(".tmp-{report_id}-{}", uuid::Uuid::new_v4());
    let temp_rel = PathBuf::from(&temp_name);
    root.mkdir(temp_rel.as_os_str(), 0o700)
        .map_err(|error| artifact_fs_error("创建报告临时目录失败", error))?;
    let result = (|| {
        let detail_rel = temp_rel.join("index.sqlite");
        let mut source = open_source_index(index_path)?;
        let destination = root
            .open_file(
                detail_rel.as_os_str(),
                OpenOptions {
                    write: true,
                    create: true,
                    exclusive: true,
                    ..OpenOptions::default()
                },
            )
            .map_err(|error| artifact_fs_error("创建报告明细文件失败", error))?;
        let mut destination = File::from(destination.fd);
        copy(&mut source, &mut destination).map_err(|error| {
            AppError::from_io(format!("复制扫描索引 {} 失败", index_path.display()), error)
        })?;
        destination
            .sync_all()
            .map_err(|error| AppError::from_io("同步报告明细文件失败", error))?;
        let detail_reader = destination
            .try_clone()
            .map_err(|error| AppError::from_io("复制报告明细文件句柄失败", error))?;
        drop(destination);
        let index = open_read_only_database_from_file(detail_reader, "打开扫描索引失败")?;
        let scan_started_at: Option<String> = index
            .query_row(
                "SELECT value FROM run_meta WHERE key = 'scan_started_at'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AppError::from_sqlite("读取扫描开始时间失败", e))?;
        let scan_finished_at: Option<String> = index
            .query_row(
                "SELECT value FROM run_meta WHERE key = 'scan_finished_at'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AppError::from_sqlite("读取扫描完成时间失败", e))?;
        let report_rel = temp_rel.join("report.sqlite");
        let mut report = Connection::open_in_memory()
            .map_err(|e| AppError::from_sqlite("创建报告数据库失败", e))?;
        migrate::apply(&mut report, REPORT_MIGRATIONS)?;
        report
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
            .map_err(|e| AppError::from_sqlite("设置报告数据库参数失败", e))?;
        populate_summary(
            &index,
            &mut report,
            source_names,
            max_rank,
            &snapshot.owner_ids_to_list,
        )?;
        populate_duplicates(&index, &mut report)?;
        populate_snapshot(&mut report, snapshot)?;
        let source_snapshot = serde_json::to_string(source_names)
            .map_err(|e| internal(format!("编码来源快照失败: {e}")))?;
        let source_identities = serde_json::to_string(&snapshot.source_identities)
            .map_err(|e| internal(format!("编码源身份快照失败: {e}")))?;
        let section_status = serde_json::to_string(&snapshot.section_status)
            .map_err(|e| internal(format!("编码栏目状态快照失败: {e}")))?;
        for (key, value) in [
            ("report_id", report_id.to_string()),
            ("run_id", run_id.to_string()),
            ("status", status.to_string()),
            ("consistency", consistency.to_string()),
            ("scope_fingerprint", scope_fingerprint.to_string()),
            ("classification_version", classification_version.to_string()),
            ("source_names", source_snapshot),
            ("source_identities", source_identities),
            ("section_status", section_status),
            ("detail_file", "index.sqlite".to_string()),
        ] {
            report
                .execute(
                    "INSERT OR REPLACE INTO report_meta(key, value) VALUES (?1, ?2)",
                    params![key, value],
                )
                .map_err(|e| AppError::from_sqlite("写入报告元数据失败", e))?;
        }
        if let Some(scope_snapshot) = &snapshot.scope_snapshot {
            let value = serde_json::to_string(scope_snapshot)
                .map_err(|e| internal(format!("编码报告范围快照失败: {e}")))?;
            report
                .execute(
                    "INSERT OR REPLACE INTO report_meta(key, value) VALUES ('scope_snapshot', ?1)",
                    [value],
                )
                .map_err(|e| AppError::from_sqlite("写入报告范围快照失败", e))?;
        }
        if let Some(value) = &scan_started_at {
            report
                .execute(
                    "INSERT OR REPLACE INTO report_meta(key, value) VALUES ('scan_started_at', ?1)",
                    [value],
                )
                .map_err(|e| AppError::from_sqlite("写入扫描开始时间失败", e))?;
        }
        if let Some(value) = &scan_finished_at {
            report
                .execute(
                    "INSERT OR REPLACE INTO report_meta(key, value) VALUES ('scan_finished_at', ?1)",
                    [value],
                )
                .map_err(|e| AppError::from_sqlite("写入扫描完成时间失败", e))?;
        }
        let report_data = report
            .serialize(rusqlite::DatabaseName::Main)
            .map_err(|e| AppError::from_sqlite("序列化报告数据库失败", e))?;
        let report_file = root
            .open_file(
                report_rel.as_os_str(),
                OpenOptions {
                    write: true,
                    create: true,
                    exclusive: true,
                    ..OpenOptions::default()
                },
            )
            .map_err(|error| artifact_fs_error("创建报告数据库失败", error))?;
        let mut report_file = File::from(report_file.fd);
        report_file
            .write_all(&report_data)
            .map_err(|error| AppError::from_io("写入报告数据库失败", error))?;
        report_file
            .sync_all()
            .map_err(|error| AppError::from_io("同步报告数据库失败", error))?;
        drop(report_file);
        drop(report_data);
        drop(report);
        drop(index);
        let files = vec![
            manifest_file(&root, &detail_rel, "index.sqlite")?,
            manifest_file(&root, &report_rel, "report.sqlite")?,
        ];
        let manifest = Manifest {
            schema_version: 1,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            profile_fingerprint: snapshot.profile_fingerprint.clone(),
            ruleset_fingerprint: snapshot.ruleset_fingerprint.clone(),
            report_id: report_id.to_string(),
            run_id: run_id.to_string(),
            status: status.to_string(),
            consistency: consistency.to_string(),
            scope_fingerprint: scope_fingerprint.to_string(),
            classification_version,
            files,
        };
        let manifest_rel = temp_rel.join("manifest.json");
        let bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| internal(format!("编码报告 manifest 失败: {e}")))?;
        let manifest_file = root
            .open_file(
                manifest_rel.as_os_str(),
                OpenOptions {
                    write: true,
                    create: true,
                    exclusive: true,
                    ..OpenOptions::default()
                },
            )
            .map_err(|error| artifact_fs_error("创建报告 manifest 失败", error))?;
        let mut manifest_file = File::from(manifest_file.fd);
        manifest_file
            .write_all(&bytes)
            .map_err(|error| AppError::from_io("写入报告 manifest 失败", error))?;
        manifest_file
            .sync_all()
            .map_err(|error| AppError::from_io("同步报告 manifest 失败", error))?;
        drop(manifest_file);
        root.rename_noreplace(temp_rel.as_os_str(), OsStr::new(report_id))
            .map_err(|error| artifact_fs_error("发布报告目录失败", error))?;
        Ok(PublishedReport {
            id: report_id.to_string(),
            run_id: run_id.to_string(),
            directory: final_dir.clone(),
            manifest_path: final_dir.join("manifest.json"),
            status: status.to_string(),
            detail_available: true,
            scan_started_at,
            scan_finished_at,
        })
    })();
    if result.is_err() {
        match root.remove_dir_all(temp_rel.as_os_str()) {
            Ok(()) | Err(FsSecureError::NotFound) => {}
            Err(error) => return Err(artifact_fs_error("清理报告临时目录失败", error)),
        }
    }
    result
}

/// Publish a report without additional control-plane snapshots. This keeps
/// the low-level publication helper useful for isolated index tests; running
/// workers use [`publish_with_snapshot`] so production reports capture the
/// control-plane values explicitly.
#[allow(clippy::too_many_arguments)]
pub fn publish(
    index_path: &Path,
    reports_root: &Path,
    report_id: &str,
    run_id: &str,
    status: &str,
    consistency: &str,
    scope_fingerprint: &str,
    classification_version: u32,
    source_names: &BTreeMap<String, String>,
    max_rank: u32,
) -> AppResult<PublishedReport> {
    publish_with_snapshot(
        index_path,
        reports_root,
        report_id,
        run_id,
        status,
        consistency,
        scope_fingerprint,
        classification_version,
        source_names,
        max_rank,
        &ReportSnapshot::default(),
    )
}

/// Return a read-only connection to a published report summary database.
pub fn open_published(path: &Path) -> AppResult<Connection> {
    if !path.is_absolute() {
        return Err(validation("已发布报告路径必须是绝对路径"));
    }
    open_read_only_database(path, "打开已发布报告失败")
}

/// Open a published report from an artifact descriptor that has already been
/// validated by [`fssecure::SecureRoot`].  Callers that already hold the
/// descriptor must use this entry point so a control-database path cannot be
/// reopened after its security check.
pub fn open_published_from_opened(
    opened: fssecure::OpenedFile,
    operation: &str,
) -> AppResult<Connection> {
    if opened.stat.kind != EntryKind::RegularFile {
        return Err(validation(format!("{operation}: artifact 不是普通文件")));
    }
    open_read_only_database_from_opened(opened, operation)
}

/// Open one of the fixed files belonging to a report below the approved
/// reports root.  The report id and artifact name are treated as single path
/// components; callers never supply an arbitrary filesystem path here.
pub fn open_published_in_root(
    reports_root: &Path,
    report_id: &str,
    artifact_name: &str,
    operation: &str,
) -> AppResult<Connection> {
    if !matches!(artifact_name, "report.sqlite" | "index.sqlite") {
        return Err(validation("已发布报告 artifact 名称无效"));
    }
    let report_component = Path::new(report_id);
    let mut components = report_component.components();
    if !matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(_)), None)
    ) {
        return Err(validation("已发布报告 id 不是单一路径组件"));
    }
    let root = open_artifact_root(reports_root)?;
    let opened = root
        .open_file(
            report_component.join(artifact_name).as_os_str(),
            OpenOptions::default(),
        )
        .map_err(|error| artifact_fs_error(operation, error))?;
    open_published_from_opened(opened, operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::migrate::{self, INDEX_MIGRATIONS};
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    #[test]
    fn publication_requires_precreated_approved_report_root() {
        let root = tempdir().unwrap();
        let reports_root = root.path().join("reports");
        let error = publish(
            &root.path().join("index.sqlite"),
            &reports_root,
            "report-1",
            "run-1",
            "succeeded",
            "complete",
            "scope-1",
            1,
            &BTreeMap::new(),
            1,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::NotFound);
        assert!(!reports_root.exists());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn publication_fails_closed_without_openat2_write_capability() {
        let root = tempdir().unwrap();
        let reports_root = root.path().join("reports");
        std::fs::create_dir(&reports_root).unwrap();
        let error = publish(
            &root.path().join("index.sqlite"),
            &reports_root,
            "report-1",
            "run-1",
            "succeeded",
            "complete",
            "scope-1",
            1,
            &BTreeMap::new(),
            1,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedCapability);
        assert_eq!(std::fs::read_dir(&reports_root).unwrap().count(), 0);
    }

    #[test]
    fn published_database_reader_rejects_symlink_artifact() {
        let root = tempdir().unwrap();
        let reports_root = root.path().join("reports");
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("report.sqlite"), b"not a database").unwrap();
        std::fs::create_dir(&reports_root).unwrap();
        symlink(
            outside.path().join("report.sqlite"),
            reports_root.join("report.sqlite"),
        )
        .unwrap();

        let error = open_published(&reports_root.join("report.sqlite")).unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn published_database_reader_stays_below_the_approved_reports_root() {
        let root = tempdir().unwrap();
        let reports_root = root.path().join("reports");
        let outside = tempdir().unwrap();
        std::fs::create_dir(&reports_root).unwrap();
        std::fs::create_dir(outside.path().join("report-1")).unwrap();
        std::fs::write(
            outside.path().join("report-1/report.sqlite"),
            b"outside database",
        )
        .unwrap();
        symlink(
            outside.path().join("report-1"),
            reports_root.join("report-1"),
        )
        .unwrap();

        let error = open_published_in_root(
            &reports_root,
            "report-1",
            "report.sqlite",
            "打开测试报告失败",
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);

        let error = open_published_in_root(
            &reports_root,
            "../outside/report-1",
            "report.sqlite",
            "打开测试报告失败",
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn read_only_database_uses_validated_fd_after_path_replacement() {
        let root = tempdir().unwrap();
        let database_path = root.path().join("report.sqlite");
        let replacement_path = root.path().join("replacement.sqlite");

        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch("CREATE TABLE marker (value TEXT NOT NULL); INSERT INTO marker VALUES ('validated-fd');")
            .unwrap();
        drop(connection);
        let connection = Connection::open(&replacement_path).unwrap();
        connection
            .execute_batch("CREATE TABLE marker (value TEXT NOT NULL); INSERT INTO marker VALUES ('replaced-path');")
            .unwrap();
        drop(connection);

        let secure_root = SecureRoot::open(root.path().as_os_str()).unwrap();
        let opened = secure_root
            .open_file(OsStr::new("report.sqlite"), OpenOptions::default())
            .unwrap();
        std::fs::remove_file(&database_path).unwrap();
        std::fs::rename(&replacement_path, &database_path).unwrap();

        let connection = open_read_only_database_from_opened(opened, "打开测试报告失败").unwrap();
        assert!(
            connection
                .is_readonly(rusqlite::DatabaseName::Main)
                .unwrap()
        );
        let value: String = connection
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "validated-fd");
        let replacement =
            Connection::open_with_flags(&database_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let replacement_value: String = replacement
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(replacement_value, "replaced-path");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_only_database_reads_checkpointed_wal_without_sidecars() {
        let root = tempdir().unwrap();
        let database_path = root.path().join("index.sqlite");
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE marker (value TEXT NOT NULL);
                 INSERT INTO marker VALUES ('checkpointed-wal');
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .unwrap();
        drop(connection);

        let secure_root = SecureRoot::open(root.path().as_os_str()).unwrap();
        let opened = secure_root
            .open_file(OsStr::new("index.sqlite"), OpenOptions::default())
            .unwrap();
        let connection =
            open_read_only_database_from_opened(opened, "打开 WAL 测试数据库失败").unwrap();
        let value: String = connection
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "checkpointed-wal");
    }

    #[test]
    fn publication_contains_folder_and_owner_category_snapshots() {
        let root = tempdir().unwrap();
        let index_path = root.path().join("index.sqlite");
        let reports_root = root.path().join("reports");
        std::fs::create_dir(&reports_root).unwrap();
        if !SecureRoot::open(reports_root.as_os_str())
            .unwrap()
            .caps()
            .supports_safe_writes()
        {
            eprintln!("note: openat2 unavailable; skipping secure report publication test");
            return;
        }
        let mut index = Connection::open(&index_path).unwrap();
        migrate::apply(&mut index, INDEX_MIGRATIONS).unwrap();
        index
            .execute(
                "INSERT INTO entries
                 (entry_id, source_id, raw_relative_path, display_name, entry_kind,
                  dfs_left, dfs_right, observation_time)
                 VALUES (1, 'source-1', X'', 'root', 'directory', 1, 4, '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        index
            .execute(
                "INSERT INTO entries
                 (entry_id, source_id, parent_entry_id, raw_relative_path, display_name,
                  entry_kind, uid, category_id, extension, size_bytes,
                  allocated_bytes_estimate, mtime_sec, mtime_nsec, atime_sec, atime_nsec,
                  dfs_left, dfs_right, observation_time)
                 VALUES (2, 'source-1', 1, X'66696C652E747874', 'file.txt',
                         'regular_file', 1000, 'documents', 'txt', 12, 12,
                         1, 0, 2, 0, 2, 3, '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        index
            .execute(
                "INSERT INTO entries
                 (entry_id, source_id, parent_entry_id, raw_relative_path, display_name,
                  entry_kind, device_id, inode_id, nlink, uid, gid, mode,
                  mtime_sec, mtime_nsec, atime_sec, atime_nsec, ctime_sec, ctime_nsec,
                  dfs_left, dfs_right, observation_time)
                 VALUES (3, 'source-1', 1, X'6C696E6B', 'link', 'symlink',
                         '1', '3', 1, 1000, 1000, 511,
                         1, 0, 2, 0, 3, 0, 3, 4, '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        index
            .execute(
                "INSERT INTO directory_aggregates
                 (entry_id, source_id, file_count, dir_count, logical_bytes,
                  unique_logical_bytes, allocated_bytes)
                 VALUES (1, 'source-1', 1, 0, 12, 12, 12)",
                [],
            )
            .unwrap();
        index
            .execute(
                "INSERT INTO owner_aggregates(source_id, uid, file_count, logical_bytes)
                 VALUES ('source-1', 1000, 1, 12)",
                [],
            )
            .unwrap();
        index
            .execute(
                "INSERT INTO owner_aggregates(source_id, uid, file_count, logical_bytes)
                 VALUES ('source-1', 2000, 1, 4)",
                [],
            )
            .unwrap();
        index
            .execute(
                "INSERT INTO category_aggregates
                 (source_id, category_id, file_count, logical_bytes, allocated_bytes)
                 VALUES ('source-1', 'documents', 1, 12, 12)",
                [],
            )
            .unwrap();
        index
            .execute(
                "INSERT INTO source_observations(source_id, status)
                 VALUES ('source-1', 'complete')",
                [],
            )
            .unwrap();
        drop(index);

        let mut names = BTreeMap::new();
        names.insert("source-1".to_string(), "Source 1".to_string());
        let report_id = "00000000-0000-0000-0000-000000000001";
        let published = publish_with_snapshot(
            &index_path,
            &reports_root,
            report_id,
            "00000000-0000-0000-0000-000000000002",
            "succeeded",
            "complete",
            "scope-1",
            10,
            &names,
            10,
            &ReportSnapshot {
                owner_ids_to_list: vec![1000],
                ..ReportSnapshot::default()
            },
        )
        .unwrap();
        let manifest: serde_json::Value = {
            let manifest_root =
                SecureRoot::open(published.directory.parent().unwrap().as_os_str()).unwrap();
            let opened = manifest_root
                .open_file(
                    OsStr::new(&format!("{report_id}/manifest.json")),
                    OpenOptions::default(),
                )
                .unwrap();
            serde_json::from_reader(File::from(opened.fd)).unwrap()
        };
        assert_eq!(manifest["schema_version"], 1);
        assert_eq!(manifest["app_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(manifest["files"][0]["path"], "index.sqlite");
        assert!(manifest["files"][0]["size_bytes"].is_string());
        assert!(manifest["files"][0]["sha256"].is_string());
        let report = open_published(&published.directory.join("report.sqlite")).unwrap();
        let folder: (i64, String, String) = report
            .query_row(
                "SELECT entry_id, name, display_path FROM report_folders",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(folder, (1, "root".to_string(), "".to_string()));
        let owner_category: (String, i64, String) = report
            .query_row(
                "SELECT source_id, uid, category_id FROM owner_category_aggregates",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            owner_category,
            ("source-1".to_string(), 1000, "documents".to_string())
        );
        let ranking_name: String = report
            .query_row(
                "SELECT display_name FROM rankings WHERE kind = 'largest'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ranking_name, "file.txt");

        let (all_owners, listed_owners): (i64, i64) = report
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM owner_aggregates),
                    (SELECT COUNT(*) FROM owner_list_snapshot)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((all_owners, listed_owners), (2, 1));
        let listed_uid: i64 = report
            .query_row("SELECT uid FROM owner_list_snapshot", [], |row| row.get(0))
            .unwrap();
        assert_eq!(listed_uid, 1000);

        let detail = open_published(&published.directory.join("index.sqlite")).unwrap();
        let special: (String, Option<i64>, i64, i64, String) = detail
            .query_row(
                "SELECT entry_kind, size_bytes, uid, mode, display_name
                 FROM entries WHERE entry_id = 3",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            special,
            ("symlink".to_string(), None, 1000, 511, "link".to_string())
        );
    }
}
