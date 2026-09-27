//! Safe cleanup lifecycle (spec 13 and F15).
//!
//! The dangerous part is intentionally synchronous. Callers provide
//! server-owned duplicate-group metadata and already-opened `fssecure` roots;
//! this module never accepts a browser path and never uses filesystem APIs
//! outside `SecureRoot` for source, quarantine, or journal paths.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;

use base64::Engine;
use fssecure::{EntryKind, FsSecureError, OpenOptions, SecureRoot, StatData};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth;
use crate::config::DeploymentConfig;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::jobs::{self, Job, JobState, JobType};
use crate::retention;
use crate::source::{self, IdentityStatus};

/// The persisted cleanup job contract.  Every action has an exact field set;
/// secrets and HTTP-only confirmation values are deliberately not part of the
/// durable job payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupJob {
    Quarantine {
        action_id: String,
        plan_id: String,
        actor_id: String,
    },
    Restore {
        action_id: String,
        item_id: String,
        actor_id: String,
        new_name: Option<Vec<u8>>,
    },
    Purge {
        action_id: String,
        plan_id: String,
        item_id: String,
        actor_id: String,
    },
    AutoPurge {
        action_id: String,
        plan_id: String,
        item_id: String,
        actor_id: String,
    },
}

impl CleanupJob {
    pub fn parse(params: &serde_json::Value) -> AppResult<Self> {
        let object = params
            .as_object()
            .ok_or_else(|| validation("清理任务参数必须是对象"))?;
        let action = required_job_string(object, "action")?;
        match action.as_str() {
            "quarantine" => {
                require_exact_job_fields(object, &["action", "action_id", "plan_id", "actor_id"])?;
                Ok(Self::Quarantine {
                    action_id: required_job_string(object, "action_id")?,
                    plan_id: required_job_string(object, "plan_id")?,
                    actor_id: required_job_string(object, "actor_id")?,
                })
            }
            "restore" => {
                require_exact_job_fields(
                    object,
                    &["action", "action_id", "item_id", "actor_id", "new_name"],
                )?;
                let new_name = match object
                    .get("new_name")
                    .ok_or_else(|| validation("恢复任务缺少 new_name"))?
                {
                    serde_json::Value::Null => None,
                    serde_json::Value::String(value) if !value.is_empty() => {
                        Some(value.as_bytes().to_vec())
                    }
                    serde_json::Value::String(_) => {
                        return Err(validation("恢复任务 new_name 不能为空"));
                    }
                    _ => return Err(validation("恢复任务 new_name 必须是字符串或 null")),
                };
                Ok(Self::Restore {
                    action_id: required_job_string(object, "action_id")?,
                    item_id: required_job_string(object, "item_id")?,
                    actor_id: required_job_string(object, "actor_id")?,
                    new_name,
                })
            }
            "purge" => {
                require_exact_job_fields(
                    object,
                    &["action", "action_id", "plan_id", "item_id", "actor_id"],
                )?;
                Ok(Self::Purge {
                    action_id: required_job_string(object, "action_id")?,
                    plan_id: required_job_string(object, "plan_id")?,
                    item_id: required_job_string(object, "item_id")?,
                    actor_id: required_job_string(object, "actor_id")?,
                })
            }
            "auto_purge" => {
                require_exact_job_fields(
                    object,
                    &["action", "action_id", "plan_id", "item_id", "actor_id"],
                )?;
                Ok(Self::AutoPurge {
                    action_id: required_job_string(object, "action_id")?,
                    plan_id: required_job_string(object, "plan_id")?,
                    item_id: required_job_string(object, "item_id")?,
                    actor_id: required_job_string(object, "actor_id")?,
                })
            }
            other => Err(validation(format!("清理任务 action 不支持: {other}"))),
        }
    }

    pub fn action_id(&self) -> &str {
        match self {
            Self::Quarantine { action_id, .. }
            | Self::Restore { action_id, .. }
            | Self::Purge { action_id, .. }
            | Self::AutoPurge { action_id, .. } => action_id,
        }
    }

    pub fn actor_id(&self) -> &str {
        match self {
            Self::Quarantine { actor_id, .. }
            | Self::Restore { actor_id, .. }
            | Self::Purge { actor_id, .. }
            | Self::AutoPurge { actor_id, .. } => actor_id,
        }
    }
}

fn required_job_string(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> AppResult<String> {
    match object.get(field) {
        Some(serde_json::Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        Some(serde_json::Value::String(_)) => Err(validation(format!("清理任务 {field} 不能为空"))),
        Some(_) => Err(validation(format!("清理任务 {field} 必须是字符串"))),
        None => Err(validation(format!("清理任务缺少 {field}"))),
    }
}

fn require_exact_job_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    expected: &[&str],
) -> AppResult<()> {
    if object.len() != expected.len() || expected.iter().any(|field| !object.contains_key(*field)) {
        return Err(validation("清理任务包含缺失或未知字段"));
    }
    Ok(())
}

type HmacSha256 = Hmac<Sha256>;

const PLAN_TTL_MINUTES: i64 = 5;
const VALIDATION_VERSION: i64 = 1;
const IO_BUFFER_SIZE: usize = 64 * 1024;
const QUARANTINE_MODE: u32 = 0o700;

pub const QUARANTINE_CONFIRMATION: &str = "QUARANTINE_SELECTED_FILES";
pub const PURGE_CONFIRMATION: &str = "PURGE_QUARANTINED_FILE_PERMANENTLY";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceCleanupGate {
    pub mount_writable: bool,
    pub source_write_enabled: bool,
    pub source_protected: bool,
    pub safe_write_capable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupGate {
    pub allow_write_operations: bool,
    pub source: SourceCleanupGate,
}

impl CleanupGate {
    fn check(self) -> AppResult<()> {
        if !self.allow_write_operations {
            return Err(AppError::new(
                ErrorCode::ReadOnlyMode,
                "部署未开启清理写操作",
            ));
        }
        if !self.source.mount_writable || !self.source.source_write_enabled {
            return Err(AppError::new(
                ErrorCode::Forbidden,
                "数据源或批准挂载未开启清理写入",
            ));
        }
        if self.source.source_protected {
            return Err(AppError::new(
                ErrorCode::ProtectedFile,
                "受保护数据源禁止清理",
            ));
        }
        if !self.source.safe_write_capable {
            return Err(AppError::new(
                ErrorCode::UnsupportedCapability,
                "当前运行环境缺少安全写入能力",
            ));
        }
        Ok(())
    }
}

/// Server-owned entry metadata from an immutable duplicate report. `raw_path`
/// is the only path representation accepted by this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupEntry {
    pub entry_id: i64,
    pub source_id: String,
    pub group_id: String,
    pub raw_path: Vec<u8>,
    pub size_bytes: i64,
    pub identity: fssecure::FileIdentity,
    pub nlink: u64,
    pub kind: EntryKind,
    pub protected: bool,
    pub content_sha256: String,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}

#[derive(Debug, Clone)]
pub struct CleanupGroupSelection {
    pub group_id: String,
    pub members: Vec<CleanupEntry>,
    pub keep_entry_ids: Vec<i64>,
    pub target_entry_ids: Vec<i64>,
}

#[derive(Clone)]
pub struct CleanupRoots<'a> {
    pub source_roots: BTreeMap<String, &'a SecureRoot>,
    pub journal_root: &'a SecureRoot,
}

impl<'a> CleanupRoots<'a> {
    fn source(&self, source_id: &str) -> AppResult<&'a SecureRoot> {
        self.source_roots
            .get(source_id)
            .copied()
            .ok_or_else(|| AppError::new(ErrorCode::SourceUnavailable, "清理源未提供安全根"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedReason {
    ProtectedFile,
    HardlinkNotAllowed,
    Symlink,
    OutsideScope,
    TieredPlaceholder,
    ActiveFile,
    NotFound,
    HashIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedEntry {
    pub entry_id: i64,
    pub reason: BlockedReason,
}

#[derive(Debug, Clone)]
pub struct CleanupPlan {
    pub id: String,
    pub report_id: String,
    pub state: String,
    pub selected_count: i64,
    pub logical_total_bytes: i64,
    pub blocked_entries: Vec<BlockedEntry>,
    pub kept_entries: Vec<i64>,
    pub risks: Vec<String>,
    pub validation_version: i64,
    pub confirmation_text: &'static str,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupItemState {
    Planned,
    Validating,
    Moving,
    Quarantined,
    Restored,
    Purged,
    Skipped,
    Failed,
    Conflict,
}

impl CleanupItemState {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Planned => "PLANNED",
            Self::Validating => "VALIDATING",
            Self::Moving => "MOVING",
            Self::Quarantined => "QUARANTINED",
            Self::Restored => "RESTORED",
            Self::Purged => "PURGED",
            Self::Skipped => "SKIPPED",
            Self::Failed => "FAILED",
            Self::Conflict => "CONFLICT",
        }
    }

    fn parse(value: &str) -> AppResult<Self> {
        match value {
            "PLANNED" => Ok(Self::Planned),
            "VALIDATING" => Ok(Self::Validating),
            "MOVING" => Ok(Self::Moving),
            "QUARANTINED" => Ok(Self::Quarantined),
            "RESTORED" => Ok(Self::Restored),
            "PURGED" => Ok(Self::Purged),
            "SKIPPED" => Ok(Self::Skipped),
            "FAILED" => Ok(Self::Failed),
            "CONFLICT" => Ok(Self::Conflict),
            other => Err(internal(format!("清理条目状态损坏: {other}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CleanupItemResult {
    pub id: String,
    pub entry_id: i64,
    pub state: CleanupItemState,
    pub original_path: Vec<u8>,
    pub quarantine_path: Option<Vec<u8>>,
    pub journal_seq: i64,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CleanupAction {
    pub id: String,
    pub plan_id: String,
    pub job_id: String,
    pub state: String,
    pub items: Vec<CleanupItemResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    entry_id: i64,
    source_id: String,
    group_id: String,
    raw_path: Vec<u8>,
    size_bytes: i64,
    device_id: u64,
    inode_id: u64,
    nlink: u64,
    entry_kind: String,
    protected: bool,
    content_sha256: String,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredGroup {
    group_id: String,
    members: Vec<StoredEntry>,
    keep_entry_ids: Vec<i64>,
    target_entry_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlanPayload {
    report_id: String,
    validation_version: i64,
    groups: Vec<StoredGroup>,
}

#[derive(Debug, Clone)]
struct PlanRow {
    report_id: String,
    payload_json: String,
    payload_sig: String,
    expires_at: String,
    actor_id: String,
    state: String,
}

#[derive(Debug, Clone)]
struct ItemRow {
    id: String,
    entry_id: i64,
    source_id: String,
    original_path: Vec<u8>,
    quarantine_path: Option<Vec<u8>>,
    identity: FileStamp,
    content_sha256: String,
    state: CleanupItemState,
    journal_seq: i64,
    error: Option<String>,
    action_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct FileStamp {
    device_id: u64,
    inode_id: u64,
    size_bytes: i64,
    nlink: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

#[derive(Debug, Clone, Copy)]
struct RawFileStamp {
    device_id: i128,
    inode_id: i128,
    size_bytes: i128,
    nlink: i128,
    mtime_sec: i128,
    mtime_nsec: i128,
    ctime_sec: i128,
    ctime_nsec: i128,
}

#[derive(Debug, Clone)]
struct JournalEvent {
    sequence: i64,
    event: String,
    item_id: String,
    original_path: Vec<u8>,
    quarantine_path: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredJournalEvent {
    seq: i64,
    event: String,
    item_id: String,
    original_path_b64: String,
    quarantine_path_b64: Option<String>,
}

impl FileStamp {
    fn from_stat(stat: &StatData) -> Self {
        Self {
            device_id: stat.identity.device_id,
            inode_id: stat.identity.inode_id,
            size_bytes: stat.size_bytes,
            nlink: stat.nlink,
            mtime_sec: stat.mtime.0,
            mtime_nsec: stat.mtime.1,
            ctime_sec: stat.ctime.0,
            ctime_nsec: stat.ctime.1,
        }
    }

    fn from_fd(fd: &OwnedFd) -> AppResult<Self> {
        let stat =
            rustix::fs::fstat(fd).map_err(|e| internal(format!("fstat 清理文件失败: {e}")))?;
        Self::from_raw_values(RawFileStamp {
            device_id: stat.st_dev as i128,
            inode_id: stat.st_ino as i128,
            size_bytes: stat.st_size as i128,
            nlink: stat.st_nlink as i128,
            mtime_sec: stat.st_mtime as i128,
            mtime_nsec: stat.st_mtime_nsec as i128,
            ctime_sec: stat.st_ctime as i128,
            ctime_nsec: stat.st_ctime_nsec as i128,
        })
    }

    /// Renaming a file legitimately changes ctime because its directory
    /// entry changed. The object identity, size, link count and mtime must
    /// still match the pre-rename observation.
    fn matches_after_rename(&self, expected: &Self) -> bool {
        self.device_id == expected.device_id
            && self.inode_id == expected.inode_id
            && self.size_bytes == expected.size_bytes
            && self.nlink == expected.nlink
            && self.mtime_sec == expected.mtime_sec
            && self.mtime_nsec == expected.mtime_nsec
    }

    fn from_raw_values(raw: RawFileStamp) -> AppResult<Self> {
        let device_id =
            u64::try_from(raw.device_id).map_err(|_| internal("文件设备标识超出 u64 范围"))?;
        let inode_id =
            u64::try_from(raw.inode_id).map_err(|_| internal("文件 inode 标识超出 u64 范围"))?;
        let size_bytes = i64::try_from(raw.size_bytes)
            .map_err(|_| internal("文件大小超出 SQLite INTEGER 范围"))?;
        if size_bytes < 0 {
            return Err(internal("文件大小不能为负数"));
        }
        let nlink = u64::try_from(raw.nlink).map_err(|_| internal("文件硬链接数超出 u64 范围"))?;
        let mtime_sec =
            i64::try_from(raw.mtime_sec).map_err(|_| internal("文件 mtime 秒数超出 i64 范围"))?;
        let mtime_nsec = i64::try_from(raw.mtime_nsec)
            .map_err(|_| internal("文件 mtime 纳秒数超出 i64 范围"))?;
        let ctime_sec =
            i64::try_from(raw.ctime_sec).map_err(|_| internal("文件 ctime 秒数超出 i64 范围"))?;
        let ctime_nsec = i64::try_from(raw.ctime_nsec)
            .map_err(|_| internal("文件 ctime 纳秒数超出 i64 范围"))?;
        Ok(Self {
            device_id,
            inode_id,
            size_bytes,
            nlink,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
        })
    }
}

impl CleanupEntry {
    fn to_stored(&self) -> StoredEntry {
        StoredEntry {
            entry_id: self.entry_id,
            source_id: self.source_id.clone(),
            group_id: self.group_id.clone(),
            raw_path: self.raw_path.clone(),
            size_bytes: self.size_bytes,
            device_id: self.identity.device_id,
            inode_id: self.identity.inode_id,
            nlink: self.nlink,
            entry_kind: entry_kind_name(self.kind),
            protected: self.protected,
            content_sha256: self.content_sha256.clone(),
            mtime_sec: self.mtime.0,
            mtime_nsec: self.mtime.1,
            ctime_sec: self.ctime.0,
            ctime_nsec: self.ctime.1,
        }
    }
}

impl StoredEntry {
    fn stamp(&self) -> FileStamp {
        FileStamp {
            device_id: self.device_id,
            inode_id: self.inode_id,
            size_bytes: self.size_bytes,
            nlink: self.nlink,
            mtime_sec: self.mtime_sec,
            mtime_nsec: self.mtime_nsec,
            ctime_sec: self.ctime_sec,
            ctime_nsec: self.ctime_nsec,
        }
    }
}

fn entry_kind_name(kind: EntryKind) -> String {
    match kind {
        EntryKind::RegularFile => "regular_file",
        EntryKind::Directory => "directory",
        EntryKind::Symlink => "symlink",
        EntryKind::Fifo => "fifo",
        EntryKind::Socket => "socket",
        EntryKind::BlockDevice => "block_device",
        EntryKind::CharDevice => "char_device",
        EntryKind::Unknown => "unknown",
    }
    .to_string()
}

fn internal(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, message)
}

fn validation(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, message)
}

fn fs_error(error: FsSecureError) -> AppError {
    let code = match &error {
        FsSecureError::PathOutsideRoot
        | FsSecureError::SymlinkNotAllowed
        | FsSecureError::MountCrossingNotAllowed => ErrorCode::PathOutsideRoot,
        FsSecureError::MissingCapability => ErrorCode::UnsupportedCapability,
        FsSecureError::NotFound => ErrorCode::NotFound,
        FsSecureError::AlreadyExists | FsSecureError::CrossDevice => ErrorCode::QuarantineConflict,
        FsSecureError::NotRegularFile => ErrorCode::ValidationFailed,
        FsSecureError::PermissionDenied => ErrorCode::Forbidden,
        _ => ErrorCode::Internal,
    };
    AppError::new(code, error.to_string())
}

fn db_error(error: rusqlite::Error) -> AppError {
    internal(format!("清理数据库操作失败: {error}"))
}

fn parse_journal_seq(value: Option<i64>, state: &str) -> rusqlite::Result<i64> {
    match value {
        Some(sequence) => Ok(sequence),
        None if state == "PLANNED" => Ok(0),
        None => Err(rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("清理条目 {state} 状态缺少 journal_seq"),
            )),
        )),
    }
}

fn sign_payload(key: &[u8], payload: &str) -> AppResult<String> {
    if key.is_empty() {
        return Err(validation("清理计划签名密钥不能为空"));
    }
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| internal("创建清理计划签名失败"))?;
    mac.update(payload.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_payload(key: &[u8], payload: &str, expected: &str) -> AppResult<()> {
    let actual = sign_payload(key, payload)?;
    if actual == expected {
        Ok(())
    } else {
        Err(AppError::new(ErrorCode::Conflict, "清理计划签名校验失败"))
    }
}

fn raw_path(path: &[u8]) -> &OsStr {
    OsStr::from_bytes(path)
}

fn plan_expired(expires_at: &str) -> AppResult<bool> {
    let expires = expires_at
        .parse::<jiff::Timestamp>()
        .map_err(|_| internal("清理计划到期时间损坏"))?;
    Ok(expires <= jiff::Timestamp::now())
}

fn quarantine_path(action_id: &str, item_id: &str) -> Vec<u8> {
    format!(".nas-analyzer-quarantine/{action_id}/{item_id}").into_bytes()
}

fn journal_dir(action_id: &str) -> OsString {
    OsString::from(format!("actions/{action_id}/journal"))
}

fn ensure_journal_directory(journal_root: &SecureRoot, action_id: &str) -> AppResult<OsString> {
    let actions = OsStr::new("actions");
    match journal_root.mkdir(actions, 0o700) {
        Ok(()) | Err(FsSecureError::AlreadyExists) => {}
        Err(error) => return Err(fs_error(error)),
    }
    journal_root.open_dir(actions).map_err(fs_error)?;
    let action = OsString::from(format!("actions/{action_id}"));
    match journal_root.mkdir(&action, 0o700) {
        Ok(()) | Err(FsSecureError::AlreadyExists) => {}
        Err(error) => return Err(fs_error(error)),
    }
    journal_root.open_dir(&action).map_err(fs_error)?;
    let dir = journal_dir(action_id);
    match journal_root.mkdir(&dir, 0o700) {
        Ok(()) | Err(FsSecureError::AlreadyExists) => {}
        Err(error) => return Err(fs_error(error)),
    }
    journal_root.open_dir(&dir).map_err(fs_error)?;
    journal_root.fsync_dir(&action).map_err(fs_error)?;
    Ok(dir)
}

fn write_journal(
    journal_root: &SecureRoot,
    action_id: &str,
    seq: i64,
    event: &str,
    item_id: &str,
    original: &[u8],
    quarantine: Option<&[u8]>,
) -> AppResult<()> {
    let dir = ensure_journal_directory(journal_root, action_id)?;
    let mut path = dir.clone();
    path.push("/");
    path.push("journal.jsonl");
    let data = serde_json::json!({
        "seq": seq,
        "event": event,
        "item_id": item_id,
        "original_path_b64": base64::engine::general_purpose::STANDARD.encode(original),
        "quarantine_path_b64": quarantine.map(|value| base64::engine::general_purpose::STANDARD.encode(value)),
    });
    let opened = journal_root
        .open_file(
            &path,
            OpenOptions {
                write: true,
                create: true,
                ..OpenOptions::default()
            },
        )
        .map_err(fs_error)?;
    let mut file = std::fs::File::from(opened.fd);
    file.seek(SeekFrom::End(0))
        .map_err(|e| internal(format!("定位清理动作日志末尾失败: {e}")))?;
    file.write_all(data.to_string().as_bytes())
        .map_err(|e| internal(format!("写入清理动作日志失败: {e}")))?;
    file.write_all(b"\n")
        .map_err(|e| internal(format!("写入清理动作日志换行失败: {e}")))?;
    file.sync_all()
        .map_err(|e| internal(format!("同步清理动作日志失败: {e}")))?;
    journal_root.fsync_dir(&dir).map_err(fs_error)
}

fn read_journal(journal_root: &SecureRoot, action_id: &str) -> AppResult<Vec<JournalEvent>> {
    let mut path = journal_dir(action_id);
    path.push("/");
    path.push("journal.jsonl");
    let opened = match journal_root.open_file(&path, OpenOptions::default()) {
        Ok(opened) => opened,
        Err(FsSecureError::NotFound) => return Ok(Vec::new()),
        Err(error) => return Err(fs_error(error)),
    };
    let mut text = String::new();
    std::fs::File::from(opened.fd)
        .read_to_string(&mut text)
        .map_err(|e| internal(format!("读取清理动作日志失败: {e}")))?;
    if text.is_empty() {
        return Err(internal("清理动作日志为空"));
    }
    let mut previous_sequence = 0_i64;
    let mut events = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            return Err(internal("清理动作日志包含空行"));
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|e| internal(format!("清理动作日志损坏: {e}")))?;
        if !value
            .as_object()
            .is_some_and(|object| object.contains_key("quarantine_path_b64"))
        {
            return Err(internal("清理动作日志缺少隔离路径字段"));
        }
        let stored: StoredJournalEvent = serde_json::from_value(value)
            .map_err(|e| internal(format!("清理动作日志损坏: {e}")))?;
        if stored.seq <= previous_sequence {
            return Err(internal("清理动作日志序号不是严格递增"));
        }
        if stored.event.is_empty() || stored.item_id.is_empty() {
            return Err(internal("清理动作日志缺少事件或条目标识"));
        }
        let original_path = base64::engine::general_purpose::STANDARD
            .decode(&stored.original_path_b64)
            .map_err(|e| internal(format!("清理动作日志原路径 base64 损坏: {e}")))?;
        if original_path.is_empty() || original_path.contains(&0) {
            return Err(internal("清理动作日志原路径无效"));
        }
        let quarantine_path = stored
            .quarantine_path_b64
            .as_deref()
            .map(|value| {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(|e| internal(format!("清理动作日志隔离路径 base64 损坏: {e}")))
            })
            .transpose()?;
        if quarantine_path
            .as_deref()
            .is_some_and(|path| path.is_empty() || path.contains(&0))
        {
            return Err(internal("清理动作日志隔离路径无效"));
        }
        let quarantine_required = matches!(
            stored.event.as_str(),
            "before_move" | "after_move" | "before_restore" | "before_purge"
        );
        let quarantine_forbidden = matches!(stored.event.as_str(), "after_restore" | "after_purge");
        if (quarantine_required && quarantine_path.is_none())
            || (quarantine_forbidden && quarantine_path.is_some())
            || !matches!(
                stored.event.as_str(),
                "before_move"
                    | "after_move"
                    | "before_restore"
                    | "after_restore"
                    | "before_purge"
                    | "after_purge"
            )
        {
            return Err(internal("清理动作日志事件字段不符合契约"));
        }
        previous_sequence = stored.seq;
        events.push(JournalEvent {
            sequence: stored.seq,
            event: stored.event,
            item_id: stored.item_id,
            original_path,
            quarantine_path,
        });
    }
    Ok(events)
}

fn journal_event<'a>(
    events: &'a [JournalEvent],
    event: &str,
    item_id: &str,
    original: &[u8],
    quarantine: Option<&[u8]>,
) -> Option<&'a JournalEvent> {
    events.iter().rev().find(|entry| {
        entry.event == event
            && entry.item_id == item_id
            && entry.original_path == original
            && entry.quarantine_path.as_deref() == quarantine
    })
}

fn completed_journal_event<'a>(
    events: &'a [JournalEvent],
    before_event: &str,
    after_event: &str,
    item_id: &str,
    original: &[u8],
    quarantine: &[u8],
) -> Option<&'a JournalEvent> {
    let before = journal_event(events, before_event, item_id, original, Some(quarantine))?;
    let after_quarantine = match after_event {
        "after_move" => Some(quarantine),
        "after_restore" | "after_purge" => None,
        _ => return None,
    };
    journal_event(events, after_event, item_id, original, after_quarantine)
        .filter(|after| after.sequence > before.sequence)
}

fn restore_before_event<'a>(
    events: &'a [JournalEvent],
    item_id: &str,
    quarantine: &[u8],
    destination: Option<&[u8]>,
) -> Option<&'a JournalEvent> {
    events.iter().rev().find(|entry| {
        entry.event == "before_restore"
            && entry.item_id == item_id
            && match destination {
                Some(destination) => entry.original_path == destination,
                None => true,
            }
            && entry.quarantine_path.as_deref() == Some(quarantine)
    })
}

fn restore_after_event<'a>(
    events: &'a [JournalEvent],
    item_id: &str,
    before: &JournalEvent,
) -> Option<&'a JournalEvent> {
    journal_event(
        events,
        "after_restore",
        item_id,
        &before.original_path,
        None,
    )
    .filter(|after| after.sequence > before.sequence)
}

fn last_journal_sequence(events: &[JournalEvent]) -> i64 {
    events.last().map_or(0, |event| event.sequence)
}

fn next_journal_sequence(events: &[JournalEvent], item_journal_seq: i64) -> AppResult<i64> {
    let last_sequence = last_journal_sequence(events);
    if item_journal_seq < 0 || item_journal_seq > last_sequence {
        return Err(internal("清理条目 journal_seq 超出动作日志范围"));
    }
    last_sequence
        .checked_add(1)
        .ok_or_else(|| validation("清理日志序号溢出"))
}

fn journal_seq_matches_item(events: &[JournalEvent], item: &ItemRow) -> bool {
    item.journal_seq == 0
        || events
            .iter()
            .any(|event| event.item_id == item.id && event.sequence == item.journal_seq)
}

fn validate_quarantined_item(
    action_id: &str,
    root: &SecureRoot,
    item: &ItemRow,
    events: &[JournalEvent],
) -> AppResult<()> {
    let quarantine = item
        .quarantine_path
        .as_deref()
        .ok_or_else(|| internal("QUARANTINED 条目缺少隔离路径"))?;
    let expected_quarantine = quarantine_path(action_id, &item.id);
    if quarantine != expected_quarantine.as_slice() {
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "QUARANTINED 条目的隔离路径不是该动作生成的受控路径",
        ));
    }
    completed_journal_event(
        events,
        "before_move",
        "after_move",
        &item.id,
        &item.original_path,
        quarantine,
    )
    .ok_or_else(|| {
        AppError::new(
            ErrorCode::QuarantineConflict,
            "QUARANTINED 条目缺少完整的隔离动作日志",
        )
    })?;
    if item.journal_seq <= 0 || !journal_seq_matches_item(events, item) {
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "QUARANTINED 条目的 journal_seq 未指向该动作日志",
        ));
    }
    let isolated = match root.open_file(raw_path(quarantine), OpenOptions::default()) {
        Ok(file) => file,
        Err(FsSecureError::NotFound) => {
            return Err(AppError::new(
                ErrorCode::QuarantineConflict,
                "QUARANTINED 条目的隔离文件不存在",
            ));
        }
        Err(error) => return Err(fs_error(error)),
    };
    if !FileStamp::from_fd(&isolated.fd)?.matches_after_rename(&item.identity) {
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "QUARANTINED 条目的隔离文件身份已变化",
        ));
    }
    Ok(())
}

#[derive(Debug)]
enum RecoveryDecision {
    Unchanged,
    Update {
        state: CleanupItemState,
        quarantine_path: Option<Vec<u8>>,
        journal_seq: i64,
        error: Option<String>,
    },
}

fn recovery_update(
    state: CleanupItemState,
    quarantine_path: Option<Vec<u8>>,
    journal_seq: i64,
    error: impl Into<String>,
) -> RecoveryDecision {
    RecoveryDecision::Update {
        state,
        quarantine_path,
        journal_seq,
        error: Some(error.into()),
    }
}

fn stat_matches_after_rename(stat: &StatData, expected: &FileStamp) -> bool {
    stat.kind == EntryKind::RegularFile && FileStamp::from_stat(stat).matches_after_rename(expected)
}

fn stat_matches_exact(stat: &StatData, expected: &FileStamp) -> bool {
    stat.kind == EntryKind::RegularFile && FileStamp::from_stat(stat) == *expected
}

fn reconcile_recovery_item(
    action_id: &str,
    root: &SecureRoot,
    item: &ItemRow,
    events: &[JournalEvent],
    restore_destination: Option<&[u8]>,
) -> AppResult<RecoveryDecision> {
    if item.journal_seq < 0
        || item.journal_seq > last_journal_sequence(events)
        || (item.journal_seq > 0 && !journal_seq_matches_item(events, item))
    {
        return Ok(recovery_update(
            CleanupItemState::Conflict,
            item.quarantine_path.clone(),
            item.journal_seq,
            "清理条目的 journal_seq 与动作日志不一致",
        ));
    }
    if matches!(
        item.state,
        CleanupItemState::Planned | CleanupItemState::Validating
    ) {
        return Ok(recovery_update(
            CleanupItemState::Failed,
            item.quarantine_path.clone(),
            item.journal_seq,
            "清理动作在移动前中断",
        ));
    }

    let Some(quarantine) = item.quarantine_path.as_deref() else {
        return Ok(if item.state == CleanupItemState::Moving {
            recovery_update(
                CleanupItemState::Failed,
                None,
                item.journal_seq,
                "MOVING 条目缺少隔离路径",
            )
        } else {
            RecoveryDecision::Unchanged
        });
    };
    let expected_quarantine = quarantine_path(action_id, &item.id);
    if quarantine != expected_quarantine.as_slice() {
        return Ok(recovery_update(
            CleanupItemState::Conflict,
            Some(quarantine.to_vec()),
            item.journal_seq,
            "清理条目的隔离路径不是该动作生成的受控路径",
        ));
    }

    let isolated = stat_for_recovery(root, quarantine)?;
    let isolated_matches = isolated
        .as_ref()
        .is_some_and(|stat| stat_matches_after_rename(stat, &item.identity));
    let move_completed = completed_journal_event(
        events,
        "before_move",
        "after_move",
        &item.id,
        &item.original_path,
        quarantine,
    );

    if item.state == CleanupItemState::Quarantined {
        if item.journal_seq <= 0 || move_completed.is_none() {
            return Ok(recovery_update(
                CleanupItemState::Conflict,
                Some(quarantine.to_vec()),
                item.journal_seq,
                "QUARANTINED 条目缺少完整的隔离动作日志",
            ));
        }
        let purge_completed = completed_journal_event(
            events,
            "before_purge",
            "after_purge",
            &item.id,
            &item.original_path,
            quarantine,
        );
        let restore_before =
            restore_before_event(events, &item.id, quarantine, restore_destination);
        let restore_after =
            restore_before.and_then(|before| restore_after_event(events, &item.id, before));

        if purge_completed.is_some() && restore_after.is_some() {
            return Ok(recovery_update(
                CleanupItemState::Conflict,
                Some(quarantine.to_vec()),
                item.journal_seq,
                "清理日志同时确认永久清理和恢复完成",
            ));
        }

        if let Some(after_purge) = purge_completed {
            return Ok(if isolated.is_none() {
                RecoveryDecision::Update {
                    state: CleanupItemState::Purged,
                    quarantine_path: None,
                    journal_seq: item.journal_seq.max(after_purge.sequence),
                    error: None,
                }
            } else {
                recovery_update(
                    CleanupItemState::Conflict,
                    Some(quarantine.to_vec()),
                    item.journal_seq.max(after_purge.sequence),
                    "永久清理完成日志与隔离文件现状不一致",
                )
            });
        }

        if let Some(after_restore) = restore_after
            && isolated.is_some()
        {
            return Ok(recovery_update(
                CleanupItemState::Conflict,
                Some(quarantine.to_vec()),
                item.journal_seq.max(after_restore.sequence),
                "恢复完成日志与隔离文件同时存在",
            ));
        }

        let restore_event = restore_after.or(restore_before);
        if let Some(restore_event) = restore_event {
            let destination = stat_for_recovery(root, &restore_event.original_path)?;
            let destination_matches = destination
                .as_ref()
                .is_some_and(|stat| stat_matches_after_rename(stat, &item.identity));
            if isolated.is_some() {
                return if !isolated_matches || destination_matches {
                    Ok(recovery_update(
                        CleanupItemState::Conflict,
                        Some(quarantine.to_vec()),
                        item.journal_seq.max(restore_event.sequence),
                        "恢复完成日志与隔离文件同时存在",
                    ))
                } else {
                    Ok(RecoveryDecision::Unchanged)
                };
            }
            return Ok(if isolated.is_none() && destination_matches {
                RecoveryDecision::Update {
                    state: CleanupItemState::Restored,
                    quarantine_path: None,
                    journal_seq: item.journal_seq.max(restore_event.sequence),
                    error: None,
                }
            } else {
                recovery_update(
                    CleanupItemState::Conflict,
                    Some(quarantine.to_vec()),
                    item.journal_seq.max(restore_event.sequence),
                    "恢复目标身份未确认且隔离文件不存在或身份不符",
                )
            });
        }

        return Ok(if isolated_matches {
            RecoveryDecision::Unchanged
        } else if isolated.is_some() {
            recovery_update(
                CleanupItemState::Conflict,
                Some(quarantine.to_vec()),
                item.journal_seq,
                "隔离文件身份已变化",
            )
        } else {
            recovery_update(
                CleanupItemState::Conflict,
                Some(quarantine.to_vec()),
                item.journal_seq,
                "隔离文件不存在且没有完成日志",
            )
        });
    }

    if item.state != CleanupItemState::Moving {
        return Ok(RecoveryDecision::Unchanged);
    }

    if isolated.is_some() && move_completed.is_none() {
        return Ok(recovery_update(
            CleanupItemState::Conflict,
            Some(quarantine.to_vec()),
            item.journal_seq,
            "MOVING 条目存在隔离文件但缺少隔离完成日志",
        ));
    }

    let original = stat_for_recovery(root, &item.original_path)?;
    let original_matches = original
        .as_ref()
        .is_some_and(|stat| stat_matches_exact(stat, &item.identity));
    Ok(match (original_matches, isolated_matches) {
        (false, true) => RecoveryDecision::Update {
            state: CleanupItemState::Quarantined,
            quarantine_path: Some(quarantine.to_vec()),
            journal_seq: move_completed.map_or(item.journal_seq, |event| event.sequence),
            error: None,
        },
        (true, true) => recovery_update(
            CleanupItemState::Conflict,
            Some(quarantine.to_vec()),
            move_completed.map_or(item.journal_seq, |event| event.sequence),
            "原路径和隔离路径同时存在",
        ),
        (true, false) => RecoveryDecision::Update {
            state: CleanupItemState::Failed,
            quarantine_path: Some(quarantine.to_vec()),
            journal_seq: item.journal_seq,
            error: Some("隔离路径不存在，原路径仍在".to_string()),
        },
        (false, false) if original.is_none() && isolated.is_none() => recovery_update(
            CleanupItemState::Failed,
            Some(quarantine.to_vec()),
            item.journal_seq,
            "原路径和隔离路径均不存在",
        ),
        (false, false) => recovery_update(
            CleanupItemState::Conflict,
            Some(quarantine.to_vec()),
            item.journal_seq,
            "原路径或隔离路径身份不符",
        ),
    })
}

fn sync_move_directories(root: &SecureRoot, original: &[u8], quarantine: &[u8]) -> AppResult<()> {
    let original_parent = parent_path(original);
    root.fsync_dir(OsStr::from_bytes(&original_parent))
        .map_err(fs_error)?;
    let quarantine_parent = parent_path(quarantine);
    root.fsync_dir(OsStr::from_bytes(&quarantine_parent))
        .map_err(fs_error)
}

fn ensure_quarantine_directory(root: &SecureRoot, action_id: &str) -> AppResult<OsString> {
    let parent = OsStr::new(".nas-analyzer-quarantine");
    match root.mkdir(parent, QUARANTINE_MODE) {
        Ok(()) | Err(FsSecureError::AlreadyExists) => {}
        Err(error) => return Err(fs_error(error)),
    }
    root.open_dir(parent).map_err(fs_error)?;
    let action = OsString::from(format!(".nas-analyzer-quarantine/{action_id}"));
    match root.mkdir(&action, QUARANTINE_MODE) {
        Ok(()) | Err(FsSecureError::AlreadyExists) => {}
        Err(error) => return Err(fs_error(error)),
    }
    root.open_dir(&action).map_err(fs_error)?;
    root.fsync_dir(parent).map_err(fs_error)?;
    Ok(action)
}

fn ensure_restore_parent(root: &SecureRoot, parent: &[u8]) -> AppResult<()> {
    match root.open_dir(OsStr::from_bytes(parent)) {
        Ok(_) => Ok(()),
        Err(FsSecureError::NotFound) => {
            root.mkdir_all(OsStr::from_bytes(parent), 0o700)
                .map_err(fs_error)?;
            root.open_dir(OsStr::from_bytes(parent))
                .map(|_| ())
                .map_err(fs_error)
        }
        Err(error) => Err(fs_error(error)),
    }
}

fn validate_name_component(name: &[u8]) -> AppResult<()> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        return Err(AppError::new(
            ErrorCode::PathOutsideRoot,
            "恢复名称必须是根内的单一路径组件",
        ));
    }
    if name.len() > 255 || name.contains(&0) {
        return Err(validation("恢复名称长度或字节不合法"));
    }
    Ok(())
}

fn parent_path(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(index) => path[..index].to_vec(),
        None => Vec::new(),
    }
}

fn combine_parent_name(path: &[u8], name: &[u8]) -> Vec<u8> {
    let parent = parent_path(path);
    if !parent.is_empty() {
        let mut result = parent;
        result.push(b'/');
        result.extend_from_slice(name);
        result
    } else {
        name.to_vec()
    }
}

fn stat_for_plan(root: &SecureRoot, entry: &StoredEntry) -> AppResult<StatData> {
    let stat = root.stat(raw_path(&entry.raw_path)).map_err(fs_error)?;
    if stat.kind != EntryKind::RegularFile || FileStamp::from_stat(&stat) != entry.stamp() {
        return Err(AppError::new(
            ErrorCode::FileChanged,
            "计划条目的身份或元数据已变化",
        ));
    }
    Ok(stat)
}

fn open_planned_file(root: &SecureRoot, entry: &StoredEntry) -> AppResult<fssecure::OpenedFile> {
    let opened = root
        .open_file(
            raw_path(&entry.raw_path),
            OpenOptions {
                noatime: true,
                ..OpenOptions::default()
            },
        )
        .map_err(fs_error)?;
    if opened.stat.kind != EntryKind::RegularFile
        || FileStamp::from_stat(&opened.stat) != entry.stamp()
    {
        return Err(AppError::new(
            ErrorCode::FileChanged,
            "计划条目的身份或元数据已变化",
        ));
    }
    Ok(opened)
}

fn digest_opened(opened: &fssecure::OpenedFile) -> AppResult<String> {
    let before = FileStamp::from_fd(&opened.fd)?;
    let mut reader = std::fs::File::from(
        opened
            .fd
            .try_clone()
            .map_err(|e| internal(format!("复制清理文件句柄失败: {e}")))?,
    );
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| internal(format!("定位清理文件开头失败: {e}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; IO_BUFFER_SIZE];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|e| internal(format!("读取清理文件失败: {e}")))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let after = FileStamp::from_fd(&opened.fd)?;
    if before != after {
        return Err(AppError::new(
            ErrorCode::FileChanged,
            "完整读取期间文件发生变化",
        ));
    }
    Ok(hex::encode(hasher.finalize()))
}

fn compare_opened(left: &fssecure::OpenedFile, right: &fssecure::OpenedFile) -> AppResult<bool> {
    let left_before = FileStamp::from_fd(&left.fd)?;
    let right_before = FileStamp::from_fd(&right.fd)?;
    let mut left_reader = std::fs::File::from(
        left.fd
            .try_clone()
            .map_err(|e| internal(format!("复制候选文件句柄失败: {e}")))?,
    );
    let mut right_reader = std::fs::File::from(
        right
            .fd
            .try_clone()
            .map_err(|e| internal(format!("复制保留文件句柄失败: {e}")))?,
    );
    left_reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| internal(format!("定位候选文件开头失败: {e}")))?;
    right_reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| internal(format!("定位保留文件开头失败: {e}")))?;
    let mut left_buffer = [0u8; IO_BUFFER_SIZE];
    let mut right_buffer = [0u8; IO_BUFFER_SIZE];
    let equal = loop {
        let left_count = left_reader
            .read(&mut left_buffer)
            .map_err(|e| internal(format!("读取候选文件失败: {e}")))?;
        let right_count = right_reader
            .read(&mut right_buffer)
            .map_err(|e| internal(format!("读取保留文件失败: {e}")))?;
        if left_count != right_count {
            break false;
        }
        if left_count == 0 {
            break true;
        }
        if left_buffer[..left_count] != right_buffer[..right_count] {
            break false;
        }
    };
    let left_after = FileStamp::from_fd(&left.fd)?;
    let right_after = FileStamp::from_fd(&right.fd)?;
    if left_before != left_after || right_before != right_after {
        return Err(AppError::new(
            ErrorCode::FileChanged,
            "完整比较期间文件发生变化",
        ));
    }
    Ok(equal)
}

fn stored_group_map(payload: &PlanPayload) -> BTreeMap<i64, StoredEntry> {
    payload
        .groups
        .iter()
        .flat_map(|group| {
            group
                .members
                .iter()
                .map(|entry| (entry.entry_id, entry.clone()))
        })
        .collect()
}

fn selected_target_ids(payload: &PlanPayload) -> BTreeSet<i64> {
    payload
        .groups
        .iter()
        .flat_map(|group| group.target_entry_ids.iter().copied())
        .collect()
}

fn gate_for_source(
    gates: &BTreeMap<String, CleanupGate>,
    source_id: &str,
) -> AppResult<CleanupGate> {
    gates
        .get(source_id)
        .copied()
        .ok_or_else(|| AppError::new(ErrorCode::SourceUnavailable, "清理源开关未提供"))
}

/// Create and persist a read-only preview. It does not require write gates,
/// create directories, or mutate any source file.
pub fn preview(
    conn: &Connection,
    report_id: &str,
    actor_id: &str,
    groups: &[CleanupGroupSelection],
    roots: &CleanupRoots<'_>,
    signing_key: &[u8],
) -> AppResult<CleanupPlan> {
    if report_id.is_empty() || actor_id.is_empty() || groups.is_empty() {
        return Err(validation("清理预览必须包含报告、操作者和至少一个重复组"));
    }
    let mut payload_groups = Vec::with_capacity(groups.len());
    let mut blocked_entries = Vec::new();
    let mut kept_entries = Vec::new();
    let mut selected_count = 0i64;
    let mut logical_total_bytes = 0i64;
    let mut seen_targets = BTreeSet::new();

    for group in groups {
        if group.group_id.is_empty()
            || group.keep_entry_ids.is_empty()
            || group.target_entry_ids.is_empty()
        {
            return Err(validation("每个清理组必须有保留项和处理项"));
        }
        let members: BTreeMap<i64, &CleanupEntry> = group
            .members
            .iter()
            .map(|entry| (entry.entry_id, entry))
            .collect();
        if members.len() != group.members.len() {
            return Err(validation("重复组包含重复 entry_id"));
        }
        let keep_set: BTreeSet<i64> = group.keep_entry_ids.iter().copied().collect();
        let target_set: BTreeSet<i64> = group.target_entry_ids.iter().copied().collect();
        if keep_set.len() != group.keep_entry_ids.len()
            || target_set.len() != group.target_entry_ids.len()
            || !keep_set.is_disjoint(&target_set)
        {
            return Err(validation("保留项和处理项不能重复"));
        }
        for entry_id in keep_set.iter().chain(target_set.iter()) {
            let entry = members
                .get(entry_id)
                .copied()
                .ok_or_else(|| validation("选择的 entry_id 不属于报告中的重复组"))?;
            if entry.group_id != group.group_id || entry.source_id.is_empty() {
                return Err(validation("重复组或数据源归属不一致"));
            }
            roots.source(&entry.source_id)?;
            if entry.content_sha256.is_empty() {
                return Err(AppError::new(
                    ErrorCode::HashIncomplete,
                    "清理计划必须来自完整内容校验的重复组",
                ));
            }
        }

        let first_keep = members
            .get(&group.keep_entry_ids[0])
            .copied()
            .ok_or_else(|| validation("保留项不存在"))?;
        for keep_id in &group.keep_entry_ids {
            let keep = members
                .get(keep_id)
                .copied()
                .ok_or_else(|| validation("保留项不存在"))?;
            if keep.content_sha256 != first_keep.content_sha256 {
                return Err(AppError::new(
                    ErrorCode::HashIncomplete,
                    "重复组保留项的完整哈希不一致",
                ));
            }
            kept_entries.push(*keep_id);
        }

        let mut stored_targets = Vec::new();
        for target_id in &group.target_entry_ids {
            if !seen_targets.insert(*target_id) {
                return Err(validation("同一 entry_id 不能在多个清理组中处理"));
            }
            let target = members
                .get(target_id)
                .copied()
                .ok_or_else(|| validation("处理项不存在"))?;
            let blocked = if target.protected {
                Some(BlockedReason::ProtectedFile)
            } else if target.nlink > 1 {
                Some(BlockedReason::HardlinkNotAllowed)
            } else if target.kind == EntryKind::Symlink {
                Some(BlockedReason::Symlink)
            } else if target.kind != EntryKind::RegularFile {
                Some(BlockedReason::TieredPlaceholder)
            } else if target.content_sha256 != first_keep.content_sha256 {
                Some(BlockedReason::HashIncomplete)
            } else {
                None
            };
            if let Some(reason) = blocked {
                blocked_entries.push(BlockedEntry {
                    entry_id: *target_id,
                    reason,
                });
                continue;
            }
            let root = roots.source(&target.source_id)?;
            let stat = match root.stat(raw_path(&target.raw_path)) {
                Ok(stat) => stat,
                Err(FsSecureError::NotFound) => {
                    blocked_entries.push(BlockedEntry {
                        entry_id: *target_id,
                        reason: BlockedReason::NotFound,
                    });
                    continue;
                }
                Err(FsSecureError::SymlinkNotAllowed) => {
                    blocked_entries.push(BlockedEntry {
                        entry_id: *target_id,
                        reason: BlockedReason::Symlink,
                    });
                    continue;
                }
                Err(error) => return Err(fs_error(error)),
            };
            let expected = FileStamp {
                device_id: target.identity.device_id,
                inode_id: target.identity.inode_id,
                size_bytes: target.size_bytes,
                nlink: target.nlink,
                mtime_sec: target.mtime.0,
                mtime_nsec: target.mtime.1,
                ctime_sec: target.ctime.0,
                ctime_nsec: target.ctime.1,
            };
            if FileStamp::from_stat(&stat) != expected {
                blocked_entries.push(BlockedEntry {
                    entry_id: *target_id,
                    reason: BlockedReason::ActiveFile,
                });
                continue;
            }
            selected_count = selected_count
                .checked_add(1)
                .ok_or_else(|| validation("清理条目数量溢出"))?;
            logical_total_bytes = logical_total_bytes
                .checked_add(target.size_bytes)
                .ok_or_else(|| validation("清理逻辑字节数溢出"))?;
            stored_targets.push(target.to_stored());
        }
        if stored_targets.is_empty() {
            continue;
        }
        payload_groups.push(StoredGroup {
            group_id: group.group_id.clone(),
            members: group.members.iter().map(CleanupEntry::to_stored).collect(),
            keep_entry_ids: group.keep_entry_ids.clone(),
            target_entry_ids: stored_targets.iter().map(|entry| entry.entry_id).collect(),
        });
    }

    if selected_count == 0 {
        return Err(AppError::new(
            ErrorCode::ValidationFailed,
            "没有可进入隔离的普通文件",
        ));
    }
    let plan_id = uuid::Uuid::new_v4().to_string();
    let created_at = auth::now_rfc3339();
    let expires_at = auth::rfc3339_plus_minutes(PLAN_TTL_MINUTES);
    let payload = PlanPayload {
        report_id: report_id.to_string(),
        validation_version: VALIDATION_VERSION,
        groups: payload_groups,
    };
    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| internal(format!("序列化清理计划失败: {e}")))?;
    let payload_sig = sign_payload(signing_key, &payload_json)?;
    conn.execute(
        "INSERT INTO cleanup_plans (id, report_id, payload_json, payload_sig, expires_at, actor_id, state, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'preview', ?7)",
        params![plan_id, report_id, payload_json, payload_sig, expires_at, actor_id, created_at],
    ).map_err(db_error)?;

    let selected_ids = selected_target_ids(&payload);
    for entry in stored_group_map(&payload).values() {
        if !selected_ids.contains(&entry.entry_id) {
            continue;
        }
        let item_id = uuid::Uuid::new_v4().to_string();
        let identity_json = serde_json::to_string(&entry.stamp())
            .map_err(|e| internal(format!("序列化清理身份失败: {e}")))?;
        conn.execute(
            "INSERT INTO cleanup_items (id, plan_id, entry_ref, source_id, raw_original_path, identity_json, content_sha256, state, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'PLANNED', ?8, ?8)",
            params![item_id, plan_id, entry.entry_id.to_string(), entry.source_id, entry.raw_path, identity_json, entry.content_sha256, created_at],
        ).map_err(db_error)?;
    }

    Ok(CleanupPlan {
        id: plan_id,
        report_id: report_id.to_string(),
        state: "preview".to_string(),
        selected_count,
        logical_total_bytes,
        blocked_entries,
        kept_entries,
        risks: vec![
            "已隔离，尚未释放磁盘空间".to_string(),
            "执行前会重新认证并完整比较候选与保留副本".to_string(),
            "隔离后的永久清理必须单独确认且不可撤销".to_string(),
        ],
        validation_version: VALIDATION_VERSION,
        confirmation_text: QUARANTINE_CONFIRMATION,
        expires_at,
        created_at,
    })
}

fn load_plan(conn: &Connection, id: &str) -> AppResult<PlanRow> {
    conn.query_row(
        "SELECT report_id, payload_json, payload_sig, expires_at, actor_id, state FROM cleanup_plans WHERE id = ?1",
        params![id],
        |row| Ok(PlanRow {
            report_id: row.get(0)?,
            payload_json: row.get(1)?,
            payload_sig: row.get(2)?,
            expires_at: row.get(3)?,
            actor_id: row.get(4)?,
            state: row.get(5)?,
        }),
    ).optional().map_err(db_error)?.ok_or_else(|| AppError::new(ErrorCode::NotFound, "清理计划不存在"))
}

fn load_payload(plan: &PlanRow, signing_key: &[u8]) -> AppResult<PlanPayload> {
    verify_payload(signing_key, &plan.payload_json, &plan.payload_sig)?;
    let payload: PlanPayload = serde_json::from_str(&plan.payload_json)
        .map_err(|e| internal(format!("清理计划内容损坏: {e}")))?;
    if payload.report_id != plan.report_id || payload.validation_version != VALIDATION_VERSION {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "清理计划校验版本或报告不一致",
        ));
    }
    Ok(payload)
}

fn load_items(
    conn: &Connection,
    action_id: Option<&str>,
    plan_id: &str,
) -> AppResult<Vec<ItemRow>> {
    let sql = "SELECT id, entry_ref, source_id, raw_original_path, raw_quarantine_path,
                      identity_json, content_sha256, state, journal_seq, error, action_id
               FROM cleanup_items
               WHERE (?1 IS NULL OR action_id = ?1) AND plan_id = ?2
               ORDER BY id";
    let mut statement = conn.prepare(sql).map_err(db_error)?;
    let rows = statement
        .query_map(params![action_id, plan_id], |row| {
            let identity_json: String = row.get(5)?;
            let identity: FileStamp = serde_json::from_str(&identity_json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            let state: String = row.get(7)?;
            let entry_id = row.get::<_, String>(1)?.parse::<i64>().map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok(ItemRow {
                id: row.get(0)?,
                entry_id,
                source_id: row.get(2)?,
                original_path: row.get(3)?,
                quarantine_path: row.get(4)?,
                identity,
                content_sha256: row.get(6)?,
                state: CleanupItemState::parse(&state).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                journal_seq: parse_journal_seq(row.get(8)?, &state)?,
                error: row.get(9)?,
                action_id: row.get(10)?,
            })
        })
        .map_err(db_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(db_error)
}

fn load_item(conn: &Connection, item_id: &str) -> AppResult<ItemRow> {
    load_items_by_id(conn, item_id)?
        .into_iter()
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "清理条目不存在"))
}

fn load_items_by_id(conn: &Connection, item_id: &str) -> AppResult<Vec<ItemRow>> {
    let mut statement = conn.prepare("SELECT id, entry_ref, source_id, raw_original_path, raw_quarantine_path, identity_json, content_sha256, state, journal_seq, error, action_id FROM cleanup_items WHERE id = ?1").map_err(db_error)?;
    let rows = statement
        .query_map(params![item_id], |row| {
            let identity_json: String = row.get(5)?;
            let identity: FileStamp = serde_json::from_str(&identity_json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            let state: String = row.get(7)?;
            let entry_id = row.get::<_, String>(1)?.parse::<i64>().map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok(ItemRow {
                id: row.get(0)?,
                entry_id,
                source_id: row.get(2)?,
                original_path: row.get(3)?,
                quarantine_path: row.get(4)?,
                identity,
                content_sha256: row.get(6)?,
                state: CleanupItemState::parse(&state).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                journal_seq: parse_journal_seq(row.get(8)?, &state)?,
                error: row.get(9)?,
                action_id: row.get(10)?,
            })
        })
        .map_err(db_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(db_error)
}

fn update_item(
    conn: &Connection,
    item_id: &str,
    action_id: Option<&str>,
    state: CleanupItemState,
    quarantine: Option<&[u8]>,
    journal_seq: i64,
    error: Option<&str>,
) -> AppResult<()> {
    conn.execute(
        "UPDATE cleanup_items SET action_id = COALESCE(?2, action_id), raw_quarantine_path = ?3, state = ?4, journal_seq = ?5, error = ?6, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
        params![item_id, action_id, quarantine, state.as_str(), journal_seq, error],
    ).map_err(db_error)?;
    Ok(())
}

fn action_from_rows(
    conn: &Connection,
    action_id: &str,
    plan_id: &str,
    job_id: &str,
    state: &str,
) -> AppResult<CleanupAction> {
    let items = load_items(conn, Some(action_id), plan_id)?
        .into_iter()
        .map(|item| CleanupItemResult {
            id: item.id,
            entry_id: item.entry_id,
            state: item.state,
            original_path: item.original_path,
            quarantine_path: item.quarantine_path,
            journal_seq: item.journal_seq,
            error: item.error,
        })
        .collect();
    Ok(CleanupAction {
        id: action_id.to_string(),
        plan_id: plan_id.to_string(),
        job_id: job_id.to_string(),
        state: state.to_string(),
        items,
    })
}

fn job_state(conn: &Connection, job_id: &str) -> AppResult<String> {
    conn.query_row(
        "SELECT state FROM jobs WHERE id = ?1",
        params![job_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(db_error)?
    .ok_or_else(|| AppError::new(ErrorCode::NotFound, "清理任务不存在"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupReservation {
    pub action_id: String,
    pub job_id: String,
}

/// Reserve a quarantine action without touching any source file. This function
/// validates the signed plan and atomically consumes the one-shot re-auth token
/// while creating the durable job/action reservation.
pub fn reserve_quarantine(
    conn: &mut Connection,
    plan_id: &str,
    expected_actor_id: &str,
    reauth_token: &str,
    confirmation: &str,
    idempotency_key: &str,
    signing_key: &[u8],
) -> AppResult<CleanupReservation> {
    if idempotency_key.is_empty() {
        return Err(validation("清理执行必须提供 Idempotency-Key"));
    }
    if let Some((job_id, params_json)) = conn
        .query_row(
            "SELECT id, params_json FROM jobs WHERE idempotency_key = ?1",
            params![idempotency_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(db_error)?
    {
        let job = jobs::get_job(conn, &job_id)?;
        if job.job_type != JobType::CleanupAction {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "Idempotency-Key 已用于其他任务类型",
            ));
        }
        let params: serde_json::Value = serde_json::from_str(&params_json)
            .map_err(|e| internal(format!("幂等清理任务参数损坏: {e}")))?;
        let stored_plan_id = params
            .get("plan_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| internal("幂等清理任务缺少 plan_id"))?;
        let action = params
            .get("action")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| internal("幂等清理任务缺少 action"))?;
        let stored_actor_id = params
            .get("actor_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| internal("幂等清理任务缺少 actor_id"))?;
        let action_id = params
            .get("action_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| internal("幂等清理任务缺少 action_id"))?;
        if stored_plan_id != plan_id
            || action != "quarantine"
            || stored_actor_id != expected_actor_id
        {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "Idempotency-Key 已用于不同的清理请求",
            ));
        }
        return Ok(CleanupReservation {
            action_id: action_id.to_owned(),
            job_id,
        });
    }

    let plan = load_plan(conn, plan_id)?;
    let _payload = load_payload(&plan, signing_key)?;
    if plan_expired(&plan.expires_at)? {
        return Err(AppError::new(ErrorCode::PlanExpired, "清理计划已过期"));
    }
    if plan.state != "preview" {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "清理计划已经执行或失效",
        ));
    }
    if plan.actor_id != expected_actor_id {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "重新认证用户与计划操作者不一致",
        ));
    }
    if confirmation != QUARANTINE_CONFIRMATION {
        return Err(validation("清理确认文本不匹配"));
    }

    let action_id = uuid::Uuid::new_v4().to_string();
    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("开启清理动作预留事务失败: {e}")))?;
    let actor_id = auth::consume_reauth_token(&tx, reauth_token)?;
    if actor_id != expected_actor_id {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "重新认证用户与当前会话不一致",
        ));
    }
    let params_json = serde_json::json!({
        "action": "quarantine",
        "action_id": action_id,
        "plan_id": plan_id,
        "actor_id": actor_id,
    });
    let job = jobs::create_job(
        &tx,
        JobType::CleanupAction,
        None,
        None,
        &params_json,
        Some(idempotency_key),
        1,
    )?;
    let changed = tx
        .execute(
            "UPDATE cleanup_plans SET state = 'executing' WHERE id = ?1 AND state = 'preview'",
            params![plan_id],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "清理计划已经被其他动作占用",
        ));
    }
    tx.execute(
        "UPDATE cleanup_items SET action_id = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE plan_id = ?1 AND action_id IS NULL",
        params![plan_id, action_id],
    )
    .map_err(db_error)?;
    tx.commit()
        .map_err(|e| internal(format!("提交清理动作预留事务失败: {e}")))?;
    Ok(CleanupReservation {
        action_id,
        job_id: job.id,
    })
}

/// Reserve a restore action without touching the source file. Restores are
/// filesystem mutations too, so they consume a recent single-use re-auth
/// token and use the durable jobs idempotency record before the worker runs.
pub fn reserve_restore(
    conn: &mut Connection,
    item_id: &str,
    expected_actor_id: &str,
    reauth_token: &str,
    new_name: Option<&[u8]>,
    idempotency_key: &str,
) -> AppResult<CleanupReservation> {
    if idempotency_key.is_empty() {
        return Err(validation("恢复操作必须提供 Idempotency-Key"));
    }
    if let Some(name) = new_name {
        validate_name_component(name)?;
        std::str::from_utf8(name).map_err(|_| validation("恢复新名称必须是有效 UTF-8"))?;
    }
    let requested_name = new_name.map(ToOwned::to_owned);
    if let Some((job_id, params_json)) = conn
        .query_row(
            "SELECT id, params_json FROM jobs WHERE idempotency_key = ?1",
            params![idempotency_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(db_error)?
    {
        let job = jobs::get_job(conn, &job_id)?;
        if job.job_type != JobType::CleanupAction {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "Idempotency-Key 已用于其他任务类型",
            ));
        }
        let params: serde_json::Value = serde_json::from_str(&params_json)
            .map_err(|error| internal(format!("幂等恢复任务参数损坏: {error}")))?;
        let stored = match CleanupJob::parse(&params)? {
            CleanupJob::Restore {
                action_id,
                item_id: stored_item_id,
                actor_id,
                new_name,
            } => (action_id, stored_item_id, actor_id, new_name),
            _ => {
                return Err(AppError::new(
                    ErrorCode::Conflict,
                    "Idempotency-Key 已用于其他清理动作",
                ));
            }
        };
        if stored.1 != item_id || stored.2 != expected_actor_id || stored.3 != requested_name {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "Idempotency-Key 已用于不同的恢复请求",
            ));
        }
        return Ok(CleanupReservation {
            action_id: stored.0,
            job_id,
        });
    }

    let item = load_item(conn, item_id)?;
    if item.state != CleanupItemState::Quarantined {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "只有 QUARANTINED 条目可以恢复",
        ));
    }
    let action_id = item
        .action_id
        .clone()
        .ok_or_else(|| internal("隔离条目缺少 action_id"))?;
    let plan_id: String = conn
        .query_row(
            "SELECT plan_id FROM cleanup_items WHERE id = ?1",
            params![item_id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let plan = load_plan(conn, &plan_id)?;
    if plan.actor_id != expected_actor_id {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "恢复操作者与清理计划操作者不一致",
        ));
    }
    let new_name_json = requested_name
        .as_deref()
        .map(std::str::from_utf8)
        .transpose()
        .map_err(|_| validation("恢复新名称必须是有效 UTF-8"))?
        .map(str::to_owned);
    let tx = conn
        .transaction()
        .map_err(|error| internal(format!("开启恢复动作预留事务失败: {error}")))?;
    let actor_id = auth::consume_reauth_token(&tx, reauth_token)?;
    if actor_id != expected_actor_id {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "重新认证用户与当前会话不一致",
        ));
    }
    let params_json = serde_json::json!({
        "action": "restore",
        "action_id": action_id,
        "item_id": item_id,
        "actor_id": actor_id,
        "new_name": new_name_json,
    });
    let job = jobs::create_job(
        &tx,
        JobType::CleanupAction,
        None,
        None,
        &params_json,
        Some(idempotency_key),
        1,
    )?;
    tx.commit()
        .map_err(|error| internal(format!("提交恢复动作预留事务失败: {error}")))?;
    Ok(CleanupReservation {
        action_id,
        job_id: job.id,
    })
}

/// Queue due automatic purge actions. The setting is the explicit opt-in;
/// the operation worker still performs the complete gate, identity and
/// surviving-copy checks before removing anything.
pub fn enqueue_due_auto_purges(
    conn: &mut Connection,
    policy: &retention::QuarantineAutoPurgePolicy,
) -> AppResult<u64> {
    retention::validate_quarantine_auto_purge(policy)?;
    if !policy.enabled {
        return Ok(0);
    }
    let tx = conn
        .transaction()
        .map_err(|error| internal(format!("开启自动清理入队事务失败: {error}")))?;
    let due = {
        let mut stmt = tx
            .prepare(
                "SELECT i.id, i.action_id, i.plan_id, p.actor_id
                 FROM cleanup_items i
                 JOIN cleanup_plans p ON p.id = i.plan_id
                 JOIN sources s ON s.id = i.source_id
                 WHERE i.state = 'QUARANTINED'
                   AND i.action_id IS NOT NULL
                   AND s.protected = 0
                   AND s.write_enabled = 1
                   AND julianday(i.updated_at) <=
                       julianday('now', printf('-%d days', ?1))
                   AND NOT EXISTS (
                       SELECT 1
                       FROM jobs j
                       WHERE j.type = 'cleanup'
                         AND json_extract(j.params_json, '$.item_id') = i.id
                         AND json_extract(j.params_json, '$.action') IN ('purge', 'auto_purge')
                   )
                 ORDER BY i.updated_at ASC, i.id ASC
                 LIMIT 100",
            )
            .map_err(db_error)?;
        stmt.query_map(params![i64::from(policy.min_keep_days)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?
    };
    let mut queued = 0_u64;
    for (item_id, action_id, plan_id, actor_id) in due {
        let params_json = serde_json::json!({
            "action": "auto_purge",
            "action_id": action_id,
            "plan_id": plan_id,
            "item_id": item_id,
            "actor_id": actor_id,
        });
        let idempotency_key = format!("auto-purge:{action_id}:{item_id}");
        jobs::create_job(
            &tx,
            JobType::CleanupAction,
            None,
            None,
            &params_json,
            Some(&idempotency_key),
            1,
        )?;
        queued = queued
            .checked_add(1)
            .ok_or_else(|| internal("自动清理入队计数溢出"))?;
    }
    tx.commit()
        .map_err(|error| internal(format!("提交自动清理入队事务失败: {error}")))?;
    Ok(queued)
}

/// Reserve a purge action after the handler has consumed re-authentication.
/// This validates only durable state; the source/quarantine identity and
/// surviving-copy checks remain in `purge_reserved` on the operation worker.
pub fn reserve_purge(
    conn: &mut Connection,
    item_id: &str,
    actor_id: &str,
    reauth_token: &str,
    confirmation: &str,
    idempotency_key: &str,
) -> AppResult<CleanupReservation> {
    if idempotency_key.is_empty() {
        return Err(validation("永久清理必须提供 Idempotency-Key"));
    }
    if confirmation != PURGE_CONFIRMATION {
        return Err(validation("永久清理确认文本不匹配"));
    }
    if let Some((job_id, params_json)) = conn
        .query_row(
            "SELECT id, params_json FROM jobs WHERE idempotency_key = ?1",
            params![idempotency_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(db_error)?
    {
        let job = jobs::get_job(conn, &job_id)?;
        if job.job_type != JobType::CleanupAction {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "Idempotency-Key 已用于其他任务类型",
            ));
        }
        let params: serde_json::Value = serde_json::from_str(&params_json)
            .map_err(|e| internal(format!("幂等永久清理任务参数损坏: {e}")))?;
        let stored_action = params
            .get("action")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| internal("幂等永久清理任务缺少 action"))?;
        let stored_item_id = params
            .get("item_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| internal("幂等永久清理任务缺少 item_id"))?;
        let stored_actor_id = params
            .get("actor_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| internal("幂等永久清理任务缺少 actor_id"))?;
        let stored_action_id = params
            .get("action_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| internal("幂等永久清理任务缺少 action_id"))?;
        if stored_action != "purge" || stored_item_id != item_id || stored_actor_id != actor_id {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "Idempotency-Key 已用于不同的永久清理请求",
            ));
        }
        return Ok(CleanupReservation {
            action_id: stored_action_id.to_owned(),
            job_id,
        });
    }
    let plan_id: String = conn
        .query_row(
            "SELECT plan_id FROM cleanup_items WHERE id = ?1 AND state = 'QUARANTINED'",
            params![item_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::JobStateConflict,
                "只有 QUARANTINED 条目可以永久清理",
            )
        })?;
    let plan = load_plan(conn, &plan_id)?;
    if plan.actor_id != actor_id {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "重新认证用户与清理计划操作者不一致",
        ));
    }
    let action_id: String = conn
        .query_row(
            "SELECT action_id FROM cleanup_items WHERE id = ?1",
            params![item_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?
        .flatten()
        .ok_or_else(|| internal("隔离条目缺少 action_id"))?;
    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("开启永久清理预留事务失败: {e}")))?;
    let consumed_actor_id = auth::consume_reauth_token(&tx, reauth_token)?;
    if consumed_actor_id != actor_id {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "重新认证用户与当前会话不一致",
        ));
    }
    let params_json = serde_json::json!({
        "action": "purge",
        "action_id": action_id,
        "item_id": item_id,
        "plan_id": plan_id,
        "actor_id": actor_id,
    });
    let job = jobs::create_job(
        &tx,
        JobType::CleanupAction,
        None,
        None,
        &params_json,
        Some(idempotency_key),
        1,
    )?;
    tx.commit()
        .map_err(|e| internal(format!("提交永久清理预留事务失败: {e}")))?;
    Ok(CleanupReservation {
        action_id,
        job_id: job.id,
    })
}

/// Consume the single-use re-auth token, re-check gates, fully compare every
/// candidate with a surviving copy, then move candidates with no-replace
/// rename. Validation is completed before the first move.
#[allow(clippy::too_many_arguments)]
pub fn execute_quarantine(
    conn: &Connection,
    plan_id: &str,
    reauth_token: &str,
    confirmation: &str,
    idempotency_key: &str,
    gates: &BTreeMap<String, CleanupGate>,
    roots: &CleanupRoots<'_>,
    signing_key: &[u8],
) -> AppResult<CleanupAction> {
    if idempotency_key.is_empty() {
        return Err(validation("清理执行必须提供 Idempotency-Key"));
    }
    let actor_id = auth::consume_reauth_token(conn, reauth_token)?;
    execute_quarantine_inner(
        conn,
        plan_id,
        &actor_id,
        confirmation,
        Some(idempotency_key),
        None,
        gates,
        roots,
        signing_key,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_quarantine_reserved(
    conn: &Connection,
    plan_id: &str,
    action_id: &str,
    job_id: &str,
    actor_id: &str,
    gates: &BTreeMap<String, CleanupGate>,
    roots: &CleanupRoots<'_>,
    signing_key: &[u8],
) -> AppResult<CleanupAction> {
    execute_quarantine_inner(
        conn,
        plan_id,
        actor_id,
        QUARANTINE_CONFIRMATION,
        None,
        Some((action_id, job_id)),
        gates,
        roots,
        signing_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_quarantine_inner(
    conn: &Connection,
    plan_id: &str,
    actor_id: &str,
    confirmation: &str,
    idempotency_key: Option<&str>,
    reserved: Option<(&str, &str)>,
    gates: &BTreeMap<String, CleanupGate>,
    roots: &CleanupRoots<'_>,
    signing_key: &[u8],
) -> AppResult<CleanupAction> {
    let plan = load_plan(conn, plan_id)?;
    if let Some(idempotency_key) = idempotency_key
        && let Some((job_id, params_json)) = conn
            .query_row(
                "SELECT id, params_json FROM jobs WHERE idempotency_key = ?1",
                params![idempotency_key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(db_error)?
    {
        let value: serde_json::Value = serde_json::from_str(&params_json)
            .map_err(|e| internal(format!("幂等清理任务损坏: {e}")))?;
        let stored_plan_id = value
            .get("plan_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| internal("幂等清理任务缺少 plan_id"))?;
        if stored_plan_id != plan_id {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "Idempotency-Key 已绑定其他清理计划",
            ));
        }
        let action_id = value
            .get("action_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| internal("幂等清理任务缺少 action_id"))?;
        if reserved.is_none() {
            return action_from_rows(
                conn,
                action_id,
                plan_id,
                &job_id,
                &job_state(conn, &job_id)?,
            );
        }
    }
    let payload = load_payload(&plan, signing_key)?;
    if plan_expired(&plan.expires_at)? {
        return Err(AppError::new(ErrorCode::PlanExpired, "清理计划已过期"));
    }
    let expected_plan_state = if reserved.is_some() {
        "executing"
    } else {
        "preview"
    };
    if plan.state != expected_plan_state {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "清理计划已经执行或失效",
        ));
    }
    if actor_id != plan.actor_id {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "重新认证用户与计划操作者不一致",
        ));
    }
    if confirmation != QUARANTINE_CONFIRMATION {
        return Err(validation("清理确认文本不匹配"));
    }
    let entries = stored_group_map(&payload);
    for group in &payload.groups {
        for entry in &group.members {
            gate_for_source(gates, &entry.source_id)?.check()?;
        }
        for target_id in &group.target_entry_ids {
            let target = entries
                .get(target_id)
                .ok_or_else(|| internal("清理计划缺少处理条目"))?;
            let root = roots.source(&target.source_id)?;
            stat_for_plan(root, target)?;
        }
    }

    let (action_id, job_id) = match reserved {
        Some((action_id, job_id)) => (action_id.to_owned(), job_id.to_owned()),
        None => {
            let action_id = uuid::Uuid::new_v4().to_string();
            let job_id = uuid::Uuid::new_v4().to_string();
            let idempotency_key =
                idempotency_key.ok_or_else(|| internal("同步清理执行缺少 Idempotency-Key"))?;
            conn.execute_batch("BEGIN IMMEDIATE").map_err(db_error)?;
            let reservation = (|| -> AppResult<()> {
                let current_state: String = conn
                    .query_row(
                        "SELECT state FROM cleanup_plans WHERE id = ?1",
                        params![plan_id],
                        |row| row.get(0),
                    )
                    .map_err(db_error)?;
                if current_state != "preview" {
                    return Err(AppError::new(
                        ErrorCode::JobStateConflict,
                        "清理计划已经执行或失效",
                    ));
                }
                conn.execute(
                    "INSERT INTO jobs (id, type, state, params_json, idempotency_key, requested_at) VALUES (?1, 'cleanup', 'RUNNING', ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    params![job_id, serde_json::json!({"action": "quarantine", "action_id": action_id, "plan_id": plan_id, "actor_id": actor_id}).to_string(), idempotency_key],
                ).map_err(db_error)?;
                let changed = conn
                    .execute(
                        "UPDATE cleanup_plans SET state = 'executing' WHERE id = ?1 AND state = 'preview'",
                        params![plan_id],
                    )
                    .map_err(db_error)?;
                if changed != 1 {
                    return Err(AppError::new(
                        ErrorCode::JobStateConflict,
                        "清理计划已经被其他动作占用",
                    ));
                }
                conn.execute("UPDATE cleanup_items SET action_id = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE plan_id = ?1", params![plan_id, action_id]).map_err(db_error)?;
                Ok(())
            })();
            if let Err(error) = reservation {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(error);
            }
            conn.execute_batch("COMMIT").map_err(db_error)?;
            (action_id, job_id)
        }
    };

    let mut items = load_items(conn, Some(&action_id), plan_id)?;
    if items.is_empty() {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "清理动作未关联有效的清理条目",
        ));
    }
    let plan_items = load_items(conn, None, plan_id)?;
    if plan_items.len() != items.len()
        || plan_items
            .iter()
            .any(|item| item.action_id.as_deref() != Some(action_id.as_str()))
    {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "清理计划包含未绑定当前动作的条目",
        ));
    }
    let existing_events = read_journal(roots.journal_root, &action_id)?;
    let mut sequence = last_journal_sequence(&existing_events);
    for item in &mut items {
        update_item(
            conn,
            &item.id,
            Some(&action_id),
            CleanupItemState::Validating,
            None,
            item.journal_seq,
            None,
        )?;
        let target = entries
            .get(&item.entry_id)
            .ok_or_else(|| internal("清理动作缺少计划条目"))?;
        let root = roots.source(&item.source_id)?;
        let candidate = match open_planned_file(root, target) {
            Ok(file) => file,
            Err(error) => {
                update_item(
                    conn,
                    &item.id,
                    Some(&action_id),
                    CleanupItemState::Failed,
                    None,
                    sequence,
                    Some(&error.message),
                )?;
                conn.execute(
                    "UPDATE jobs SET state = 'FAILED', finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), error_json = ?2 WHERE id = ?1",
                    params![
                        job_id,
                        serde_json::json!({"code": error.code.as_str(), "message": error.message})
                            .to_string()
                    ],
                )
                .map_err(db_error)?;
                return Err(error);
            }
        };
        let digest = match digest_opened(&candidate) {
            Ok(digest) => digest,
            Err(error) => {
                update_item(
                    conn,
                    &item.id,
                    Some(&action_id),
                    CleanupItemState::Failed,
                    None,
                    sequence,
                    Some(&error.message),
                )?;
                conn.execute(
                    "UPDATE jobs SET state = 'FAILED', finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), error_json = ?2 WHERE id = ?1",
                    params![
                        job_id,
                        serde_json::json!({"code": error.code.as_str(), "message": error.message})
                            .to_string()
                    ],
                )
                .map_err(db_error)?;
                return Err(error);
            }
        };
        if digest != item.content_sha256 || digest != target.content_sha256 {
            let error = AppError::new(ErrorCode::FileChanged, "候选文件完整内容已变化");
            update_item(
                conn,
                &item.id,
                Some(&action_id),
                CleanupItemState::Failed,
                None,
                sequence,
                Some(&error.message),
            )?;
            conn.execute(
                "UPDATE jobs SET state = 'FAILED', finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), error_json = ?2 WHERE id = ?1",
                params![
                    job_id,
                    serde_json::json!({"code": error.code.as_str(), "message": error.message})
                        .to_string()
                ],
            )
            .map_err(db_error)?;
            return Err(error);
        }
        let group = payload
            .groups
            .iter()
            .find(|group| group.target_entry_ids.contains(&item.entry_id))
            .ok_or_else(|| internal("清理条目不属于计划组"))?;
        let mut surviving_copy = false;
        for keep_id in &group.keep_entry_ids {
            let keep = entries
                .get(keep_id)
                .ok_or_else(|| internal("清理计划缺少保留条目"))?;
            let keep_root = roots.source(&keep.source_id)?;
            let keep_file = match open_planned_file(keep_root, keep) {
                Ok(file) => file,
                Err(AppError {
                    code: ErrorCode::NotFound,
                    ..
                }) => continue,
                Err(error) => return Err(error),
            };
            if compare_opened(&candidate, &keep_file)? {
                surviving_copy = true;
                break;
            }
        }
        if !surviving_copy {
            let error = AppError::new(ErrorCode::NoSurvivingCopy, "没有通过完整比较的保留副本");
            update_item(
                conn,
                &item.id,
                Some(&action_id),
                CleanupItemState::Failed,
                None,
                sequence,
                Some(&error.message),
            )?;
            conn.execute(
                "UPDATE jobs SET state = 'FAILED', finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), error_json = ?2 WHERE id = ?1",
                params![
                    job_id,
                    serde_json::json!({"code": error.code.as_str(), "message": error.message})
                        .to_string()
                ],
            )
            .map_err(db_error)?;
            return Err(error);
        }
    }

    for item in &mut items {
        let target = entries
            .get(&item.entry_id)
            .ok_or_else(|| internal("清理动作缺少计划条目"))?;
        let root = roots.source(&item.source_id)?;
        let quarantine = quarantine_path(&action_id, &item.id);
        let quarantine_dir = ensure_quarantine_directory(root, &action_id)?;
        root.fsync_dir(&quarantine_dir).map_err(fs_error)?;
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| validation("清理日志序号溢出"))?;
        update_item(
            conn,
            &item.id,
            Some(&action_id),
            CleanupItemState::Moving,
            Some(&quarantine),
            sequence,
            None,
        )?;
        write_journal(
            roots.journal_root,
            &action_id,
            sequence,
            "before_move",
            &item.id,
            &item.original_path,
            Some(&quarantine),
        )?;
        if let Err(error) = root.rename_noreplace(raw_path(&target.raw_path), raw_path(&quarantine))
        {
            let mapped = fs_error(error);
            update_item(
                conn,
                &item.id,
                Some(&action_id),
                CleanupItemState::Conflict,
                Some(&quarantine),
                sequence,
                Some(&mapped.message),
            )?;
            conn.execute(
                "UPDATE jobs SET state = 'PARTIAL', finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), error_json = ?2 WHERE id = ?1",
                params![
                    job_id,
                    serde_json::json!({"code": mapped.code.as_str(), "message": mapped.message})
                        .to_string()
                ],
            )
            .map_err(db_error)?;
            return action_from_rows(conn, &action_id, plan_id, &job_id, "partial");
        }
        sync_move_directories(root, &target.raw_path, &quarantine)?;
        let moved = root
            .open_file(raw_path(&quarantine), OpenOptions::default())
            .map_err(fs_error)?;
        if !FileStamp::from_fd(&moved.fd)?.matches_after_rename(&target.stamp()) {
            let error = AppError::new(ErrorCode::QuarantineConflict, "隔离目标身份校验失败");
            let rollback = root.rename_noreplace(raw_path(&quarantine), raw_path(&target.raw_path));
            let state = if rollback.is_ok() {
                CleanupItemState::Failed
            } else {
                CleanupItemState::Conflict
            };
            update_item(
                conn,
                &item.id,
                Some(&action_id),
                state,
                Some(&quarantine),
                sequence,
                Some(&error.message),
            )?;
            conn.execute(
                "UPDATE jobs SET state = 'PARTIAL', finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), error_json = ?2 WHERE id = ?1",
                params![
                    job_id,
                    serde_json::json!({"code": error.code.as_str(), "message": error.message})
                        .to_string()
                ],
            )
            .map_err(db_error)?;
            return action_from_rows(conn, &action_id, plan_id, &job_id, "partial");
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| validation("清理日志序号溢出"))?;
        write_journal(
            roots.journal_root,
            &action_id,
            sequence,
            "after_move",
            &item.id,
            &item.original_path,
            Some(&quarantine),
        )?;
        update_item(
            conn,
            &item.id,
            Some(&action_id),
            CleanupItemState::Quarantined,
            Some(&quarantine),
            sequence,
            None,
        )?;
    }
    conn.execute(
        "UPDATE cleanup_plans SET state = 'completed' WHERE id = ?1",
        params![plan_id],
    )
    .map_err(db_error)?;
    conn.execute("UPDATE jobs SET state = 'SUCCEEDED', finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1", params![job_id]).map_err(db_error)?;
    action_from_rows(conn, &action_id, plan_id, &job_id, "completed")
}

/// Reconcile an interrupted MOVING item from both root-relative locations.
pub fn recover_action(
    conn: &Connection,
    action_id: &str,
    roots: &CleanupRoots<'_>,
) -> AppResult<CleanupAction> {
    let plan_id: String = conn
        .query_row(
            "SELECT plan_id FROM cleanup_items WHERE action_id = ?1 LIMIT 1",
            params![action_id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let job_id: String = conn
        .query_row(
            "SELECT id FROM jobs
             WHERE type = 'cleanup'
               AND json_extract(params_json, '$.action_id') = ?1
             ORDER BY CASE state
                        WHEN 'INTERRUPTED' THEN 0
                        WHEN 'RUNNING' THEN 1
                        WHEN 'PAUSING' THEN 1
                        WHEN 'PAUSED' THEN 1
                        WHEN 'CANCELLING' THEN 1
                        ELSE 2
                      END,
                      requested_at DESC, id DESC
             LIMIT 1",
            params![action_id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let job = jobs::get_job(conn, &job_id)?;
    if job.state != JobState::Interrupted {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "只有 INTERRUPTED 清理任务可以恢复",
        ));
    }
    let events = read_journal(roots.journal_root, action_id)?;
    let items = load_items(conn, Some(action_id), &plan_id)?;
    for item in &items {
        let root = roots.source(&item.source_id)?;
        if let RecoveryDecision::Update {
            state,
            quarantine_path,
            journal_seq,
            error,
        } = reconcile_recovery_item(action_id, root, item, &events, None)?
        {
            update_item(
                conn,
                &item.id,
                Some(action_id),
                state,
                quarantine_path.as_deref(),
                journal_seq,
                error.as_deref(),
            )?;
        }
    }
    let action_state = job.state.as_str().to_ascii_lowercase();
    action_from_rows(conn, action_id, &plan_id, &job_id, &action_state)
}

/// Restore a quarantined file to its original path or to a new name in the
/// same original parent. Existing destinations are never replaced.
pub fn restore(
    conn: &Connection,
    item_id: &str,
    roots: &CleanupRoots<'_>,
    new_name: Option<&[u8]>,
) -> AppResult<CleanupItemResult> {
    let item = load_item(conn, item_id)?;
    if item.state != CleanupItemState::Quarantined {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "只有 QUARANTINED 条目可以恢复",
        ));
    }
    let quarantine = item
        .quarantine_path
        .as_deref()
        .ok_or_else(|| internal("隔离条目缺少隔离路径"))?;
    let action_id = item
        .action_id
        .as_deref()
        .ok_or_else(|| internal("隔离条目缺少 action_id"))?;
    let events = read_journal(roots.journal_root, action_id)?;
    if completed_journal_event(
        &events,
        "before_move",
        "after_move",
        &item.id,
        &item.original_path,
        quarantine,
    )
    .is_none()
    {
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "隔离动作日志尚未确认移动完成",
        ));
    }
    if let Some(name) = new_name {
        validate_name_component(name)?;
    }
    let root = roots.source(&item.source_id)?;
    let file = root
        .open_file(raw_path(quarantine), OpenOptions::default())
        .map_err(fs_error)?;
    if !FileStamp::from_fd(&file.fd)?.matches_after_rename(&item.identity) {
        return Err(AppError::new(ErrorCode::FileChanged, "隔离文件身份已变化"));
    }
    let destination = match new_name {
        Some(name) => combine_parent_name(&item.original_path, name),
        None => item.original_path.clone(),
    };
    match root.stat(raw_path(&destination)) {
        Ok(_) => {
            return Err(AppError::new(
                ErrorCode::QuarantineConflict,
                "恢复目标已存在，拒绝覆盖",
            ));
        }
        Err(FsSecureError::NotFound) => {}
        Err(error) => return Err(fs_error(error)),
    }
    let parent = parent_path(&destination);
    if !parent.is_empty() {
        ensure_restore_parent(root, &parent)?;
    }
    let sequence = next_journal_sequence(&events, item.journal_seq)?;
    let after_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| validation("清理日志序号溢出"))?;
    write_journal(
        roots.journal_root,
        action_id,
        sequence,
        "before_restore",
        &item.id,
        &destination,
        Some(quarantine),
    )?;
    root.rename_noreplace(raw_path(quarantine), raw_path(&destination))
        .map_err(fs_error)?;
    if let Err(error) = sync_move_directories(root, quarantine, &destination) {
        let rollback = root.rename_noreplace(raw_path(&destination), raw_path(quarantine));
        if rollback.is_err() {
            return Err(AppError::new(
                ErrorCode::QuarantineConflict,
                format!("恢复后的目录同步失败且无法回滚: {}", error.message),
            ));
        }
        return Err(error);
    }
    let restored = root
        .open_file(raw_path(&destination), OpenOptions::default())
        .map_err(fs_error)?;
    if !FileStamp::from_fd(&restored.fd)?.matches_after_rename(&item.identity) {
        let rollback = root.rename_noreplace(raw_path(&destination), raw_path(quarantine));
        if rollback.is_err() {
            return Err(AppError::new(
                ErrorCode::QuarantineConflict,
                "恢复后文件身份校验失败且无法回滚",
            ));
        }
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "恢复后文件身份校验失败",
        ));
    }
    if let Err(error) = write_journal(
        roots.journal_root,
        action_id,
        after_sequence,
        "after_restore",
        &item.id,
        &destination,
        None,
    ) {
        let rollback = root.rename_noreplace(raw_path(&destination), raw_path(quarantine));
        if rollback.is_err() {
            return Err(AppError::new(
                ErrorCode::QuarantineConflict,
                format!("恢复日志失败且无法回滚: {}", error.message),
            ));
        }
        return Err(error);
    }
    update_item(
        conn,
        item_id,
        Some(action_id),
        CleanupItemState::Restored,
        None,
        after_sequence,
        None,
    )?;
    Ok(CleanupItemResult {
        id: item.id,
        entry_id: item.entry_id,
        state: CleanupItemState::Restored,
        original_path: destination,
        quarantine_path: None,
        journal_seq: after_sequence,
        error: None,
    })
}

/// Permanently remove only an application-owned quarantine file after a new
/// re-authentication and a fresh complete comparison with a surviving copy.
pub fn purge(
    conn: &Connection,
    item_id: &str,
    reauth_token: &str,
    confirmation: &str,
    signing_key: &[u8],
    gates: &BTreeMap<String, CleanupGate>,
    roots: &CleanupRoots<'_>,
) -> AppResult<CleanupItemResult> {
    let actor_id = auth::consume_reauth_token(conn, reauth_token)?;
    purge_reserved(
        conn,
        item_id,
        &actor_id,
        confirmation,
        signing_key,
        gates,
        roots,
    )
}

/// Execute a previously reserved purge action. Re-authentication is consumed
/// by the HTTP reservation step and its token is never persisted in the job.
pub fn purge_reserved(
    conn: &Connection,
    item_id: &str,
    actor_id: &str,
    confirmation: &str,
    signing_key: &[u8],
    gates: &BTreeMap<String, CleanupGate>,
    roots: &CleanupRoots<'_>,
) -> AppResult<CleanupItemResult> {
    if confirmation != PURGE_CONFIRMATION {
        return Err(validation("永久清理确认文本不匹配"));
    }
    let item = load_item(conn, item_id)?;
    if item.state != CleanupItemState::Quarantined {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "只有 QUARANTINED 条目可以永久清理",
        ));
    }
    let action_id = item
        .action_id
        .as_deref()
        .ok_or_else(|| internal("隔离条目缺少 action_id"))?;
    let plan_id: String = conn
        .query_row(
            "SELECT plan_id FROM cleanup_items WHERE id = ?1",
            params![item_id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let plan = load_plan(conn, &plan_id)?;
    if plan.actor_id != actor_id {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "重新认证用户与清理计划操作者不一致",
        ));
    }
    let payload = load_payload(&plan, signing_key)?;
    gate_for_source(gates, &item.source_id)?.check()?;
    let root = roots.source(&item.source_id)?;
    let quarantine = item
        .quarantine_path
        .as_deref()
        .ok_or_else(|| internal("隔离条目缺少路径"))?;
    let expected_quarantine = quarantine_path(action_id, item_id);
    if quarantine != expected_quarantine.as_slice() {
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "隔离路径不是该动作生成的受控路径",
        ));
    }
    let events = read_journal(roots.journal_root, action_id)?;
    if completed_journal_event(
        &events,
        "before_move",
        "after_move",
        item_id,
        &item.original_path,
        quarantine,
    )
    .is_none()
    {
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "隔离动作日志尚未确认移动完成",
        ));
    }
    let quarantined = root
        .open_file(raw_path(quarantine), OpenOptions::default())
        .map_err(fs_error)?;
    if !FileStamp::from_fd(&quarantined.fd)?.matches_after_rename(&item.identity)
        || quarantined.stat.nlink != 1
    {
        return Err(AppError::new(ErrorCode::FileChanged, "隔离文件身份已变化"));
    }
    let entries = stored_group_map(&payload);
    let group = payload
        .groups
        .iter()
        .find(|group| group.target_entry_ids.contains(&item.entry_id))
        .ok_or_else(|| internal("隔离条目不属于计划组"))?;
    let mut surviving = false;
    for keep_id in &group.keep_entry_ids {
        let keep = entries
            .get(keep_id)
            .ok_or_else(|| internal("清理计划缺少保留项"))?;
        let keep_root = roots.source(&keep.source_id)?;
        let keep_file = match open_planned_file(keep_root, keep) {
            Ok(file) => file,
            Err(AppError {
                code: ErrorCode::NotFound,
                ..
            }) => continue,
            Err(error) => return Err(error),
        };
        if compare_opened(&quarantined, &keep_file)? {
            surviving = true;
            break;
        }
    }
    if !surviving {
        return Err(AppError::new(
            ErrorCode::NoSurvivingCopy,
            "保留副本已不存在或内容不一致",
        ));
    }
    let sequence = next_journal_sequence(&events, item.journal_seq)?;
    let after_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| validation("清理日志序号溢出"))?;
    write_journal(
        roots.journal_root,
        action_id,
        sequence,
        "before_purge",
        item_id,
        &item.original_path,
        Some(quarantine),
    )?;
    root.unlink_file(raw_path(quarantine)).map_err(fs_error)?;
    let quarantine_parent = parent_path(quarantine);
    root.fsync_dir(OsStr::from_bytes(&quarantine_parent))
        .map_err(fs_error)?;
    if !matches!(
        root.stat(raw_path(quarantine)),
        Err(FsSecureError::NotFound)
    ) {
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "永久清理后隔离文件仍存在",
        ));
    }
    write_journal(
        roots.journal_root,
        action_id,
        after_sequence,
        "after_purge",
        item_id,
        &item.original_path,
        None,
    )?;
    update_item(
        conn,
        item_id,
        Some(action_id),
        CleanupItemState::Purged,
        None,
        after_sequence,
        None,
    )?;
    Ok(CleanupItemResult {
        id: item.id,
        entry_id: item.entry_id,
        state: CleanupItemState::Purged,
        original_path: item.original_path,
        quarantine_path: None,
        journal_seq: after_sequence,
        error: None,
    })
}

// ---- operation-supervisor execution --------------------------------------

/// The supervisor owns the long-running file operation.  It only uses the
/// control writer for short, bounded SQL calls between filesystem steps.
#[derive(Debug, Clone)]
struct RuntimeSourceSpec {
    source_id: String,
    mount_key: String,
    raw_relative_root: Vec<u8>,
    source_write_enabled: bool,
    source_protected: bool,
    identity_status: IdentityStatus,
    identity_json: serde_json::Value,
}

struct RuntimeCleanupContext {
    source_roots: BTreeMap<String, SecureRoot>,
    gates: BTreeMap<String, CleanupGate>,
    journal_root: SecureRoot,
    signing_key: Option<Vec<u8>>,
}

struct CleanupWriter {
    writer: crate::store::DbWriter,
}

impl CleanupWriter {
    fn new(writer: crate::store::DbWriter) -> Self {
        Self { writer }
    }

    fn load_plan(&self, plan_id: &str) -> AppResult<PlanRow> {
        let plan_id = plan_id.to_owned();
        self.writer
            .call_blocking(move |conn| load_plan(conn, &plan_id))
    }

    fn load_items(&self, action_id: &str, plan_id: &str) -> AppResult<Vec<ItemRow>> {
        let action_id = action_id.to_owned();
        let plan_id = plan_id.to_owned();
        self.writer
            .call_blocking(move |conn| load_items(conn, Some(&action_id), &plan_id))
    }

    fn load_plan_items(&self, plan_id: &str) -> AppResult<Vec<ItemRow>> {
        let plan_id = plan_id.to_owned();
        self.writer
            .call_blocking(move |conn| load_items(conn, None, &plan_id))
    }

    fn load_item(&self, item_id: &str) -> AppResult<ItemRow> {
        let item_id = item_id.to_owned();
        self.writer
            .call_blocking(move |conn| load_item(conn, &item_id))
    }

    fn load_item_plan_id(&self, item_id: &str) -> AppResult<String> {
        let item_id = item_id.to_owned();
        self.writer.call_blocking(move |conn| {
            conn.query_row(
                "SELECT plan_id FROM cleanup_items WHERE id = ?1",
                params![item_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, "清理条目不存在"))
        })
    }

    fn load_item_updated_at(&self, item_id: &str) -> AppResult<String> {
        let item_id = item_id.to_owned();
        self.writer.call_blocking(move |conn| {
            conn.query_row(
                "SELECT updated_at FROM cleanup_items WHERE id = ?1",
                params![item_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, "清理条目不存在"))
        })
    }

    fn load_auto_purge_policy(&self) -> AppResult<retention::QuarantineAutoPurgePolicy> {
        self.writer
            .call_blocking(|conn| retention::load_quarantine_auto_purge(conn))
    }

    fn is_cancelling(&self, job_id: &str) -> AppResult<bool> {
        let job_id = job_id.to_owned();
        self.writer.call_blocking(move |conn| {
            let state: String = conn
                .query_row(
                    "SELECT state FROM jobs WHERE id = ?1",
                    params![job_id],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            Ok(JobState::parse(&state)? == JobState::Cancelling)
        })
    }

    fn load_source_specs(&self, request: &CleanupJob) -> AppResult<Vec<RuntimeSourceSpec>> {
        let request = request.clone();
        self.writer.call_blocking(move |conn| {
            let source_ids = runtime_source_ids(conn, &request)?;
            load_source_specs(conn, &source_ids)
        })
    }

    fn load_source_specs_for_ids(
        &self,
        source_ids: BTreeSet<String>,
    ) -> AppResult<Vec<RuntimeSourceSpec>> {
        self.writer.call_blocking(move |conn| {
            let source_ids = source_ids.into_iter().collect::<Vec<_>>();
            load_source_specs(conn, &source_ids)
        })
    }

    fn load_recovery_jobs(&self) -> AppResult<Vec<(Job, BTreeSet<String>)>> {
        self.writer.call_blocking(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT id
                     FROM jobs
                     WHERE type = 'cleanup' AND state = 'INTERRUPTED'
                     ORDER BY requested_at, id",
                )
                .map_err(db_error)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(db_error)?;
            let mut recovery_jobs = Vec::new();
            for row in rows {
                let job_id = row.map_err(db_error)?;
                let job = jobs::get_job(conn, &job_id)?;
                let request = CleanupJob::parse(&job.params_json)?;
                let source_ids = runtime_source_ids(conn, &request)?
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                recovery_jobs.push((job, source_ids));
            }
            Ok(recovery_jobs)
        })
    }

    fn load_signing_key(&self) -> AppResult<Vec<u8>> {
        self.writer.call_blocking(|conn| {
            let raw: Option<String> = conn
                .query_row(
                    "SELECT value_json FROM app_settings WHERE key = 'cleanup_signing_key'",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            let encoded = raw
                .ok_or_else(|| internal("清理计划签名密钥设置不存在"))
                .and_then(|value| {
                    serde_json::from_str::<String>(&value)
                        .map_err(|error| internal(format!("清理签名密钥设置损坏: {error}")))
                })?;
            let key = hex::decode(encoded).map_err(|_| internal("清理签名密钥不是有效十六进制"))?;
            if key.is_empty() {
                return Err(internal("清理签名密钥为空"));
            }
            Ok(key)
        })
    }

    fn update_item(
        &self,
        item_id: &str,
        action_id: &str,
        state: CleanupItemState,
        quarantine: Option<Vec<u8>>,
        journal_seq: i64,
        error: Option<String>,
    ) -> AppResult<()> {
        let item_id = item_id.to_owned();
        let action_id = action_id.to_owned();
        self.writer.call_blocking(move |conn| {
            update_item(
                conn,
                &item_id,
                Some(&action_id),
                state,
                quarantine.as_deref(),
                journal_seq,
                error.as_deref(),
            )
        })
    }

    fn mark_recovery_conflict(&self, request: &CleanupJob, message: &str) -> AppResult<()> {
        let action_id = request.action_id().to_owned();
        let item_id = match request {
            CleanupJob::Restore { item_id, .. }
            | CleanupJob::Purge { item_id, .. }
            | CleanupJob::AutoPurge { item_id, .. } => Some(item_id.clone()),
            CleanupJob::Quarantine { .. } => None,
        };
        let message = message.to_owned();
        self.writer.call_blocking(move |conn| {
            conn.execute(
                "UPDATE cleanup_items
                 SET state = CASE
                                  WHEN state IN ('PLANNED','VALIDATING') THEN 'FAILED'
                                  ELSE 'CONFLICT'
                              END,
                     error = ?2,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE action_id = ?1
                   AND state IN ('PLANNED','VALIDATING','MOVING','QUARANTINED')
                   AND (?3 IS NULL OR id = ?3)",
                params![action_id, message, item_id],
            )
            .map_err(db_error)?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        &self,
        job_id: &str,
        plan_id: Option<&str>,
        action_id: &str,
        actor_id: &str,
        final_state: JobState,
        plan_state: Option<&str>,
        action_name: &str,
        progress: serde_json::Value,
        error_json: Option<serde_json::Value>,
    ) -> AppResult<JobState> {
        let job_id = job_id.to_owned();
        let plan_id = plan_id.map(str::to_owned);
        let action_id = action_id.to_owned();
        let actor_id = actor_id.to_owned();
        let action_name = action_name.to_owned();
        let plan_state = plan_state.map(str::to_owned);
        self.writer.call_blocking(move |conn| {
            let finished = jobs::job_finish(conn, &job_id, final_state, error_json.as_ref())?;
            if finished.state != JobState::Cancelled
                && let (Some(plan_id), Some(plan_state)) =
                    (plan_id.as_deref(), plan_state.as_deref())
            {
                conn.execute(
                    "UPDATE cleanup_plans SET state = ?2 WHERE id = ?1",
                    params![plan_id, plan_state],
                )
                .map_err(db_error)?;
            }
            let event_payload = json!({
                "action_id": action_id,
                "state": finished.state.as_str(),
                "progress": progress,
            });
            jobs::append_event(conn, &job_id, "job.completed", &event_payload)?;
            let audit_result = match finished.state {
                JobState::Succeeded => "success",
                JobState::Partial => "partial",
                JobState::Cancelled => "cancelled",
                JobState::Failed => "failed",
                JobState::Interrupted => "interrupted",
                JobState::Queued
                | JobState::Running
                | JobState::Pausing
                | JobState::Paused
                | JobState::Cancelling => "completed",
            };
            crate::audit::record(
                conn,
                &actor_id,
                &action_name,
                Some(&action_id),
                audit_result,
                None,
                Some(json!({"job_state": finished.state.as_str()})),
            )?;
            Ok(finished.state)
        })
    }
}

fn runtime_source_ids(conn: &Connection, request: &CleanupJob) -> AppResult<Vec<String>> {
    let mut source_ids = BTreeSet::new();
    match request {
        CleanupJob::Quarantine { plan_id, .. } => {
            let mut statement = conn
                .prepare("SELECT DISTINCT source_id FROM cleanup_items WHERE plan_id = ?1")
                .map_err(db_error)?;
            let rows = statement
                .query_map(params![plan_id], |row| row.get::<_, String>(0))
                .map_err(db_error)?;
            for row in rows {
                source_ids.insert(row.map_err(db_error)?);
            }
        }
        CleanupJob::Restore { item_id, .. }
        | CleanupJob::Purge { item_id, .. }
        | CleanupJob::AutoPurge { item_id, .. } => {
            let source_id: String = conn
                .query_row(
                    "SELECT source_id FROM cleanup_items WHERE id = ?1",
                    params![item_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?
                .ok_or_else(|| AppError::new(ErrorCode::NotFound, "清理条目不存在"))?;
            source_ids.insert(source_id);
        }
    }
    Ok(source_ids.into_iter().collect())
}

fn load_source_specs(
    conn: &Connection,
    source_ids: &[String],
) -> AppResult<Vec<RuntimeSourceSpec>> {
    let mut specs = Vec::with_capacity(source_ids.len());
    for source_id in source_ids {
        let (
            mount_key,
            raw_relative_root,
            write_enabled,
            protected,
            identity_status,
            identity_json,
        ): (String, Vec<u8>, i64, i64, String, String) = conn
            .query_row(
                "SELECT mount_key, CAST(raw_relative_root AS BLOB), write_enabled, protected,
                        identity_status, identity_json
                 FROM sources
                 WHERE id = ?1 AND disabled_at IS NULL",
                params![source_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(db_error)?
            .ok_or_else(|| {
                AppError::new(ErrorCode::SourceUnavailable, "清理数据源不存在或已禁用")
            })?;
        let identity_status = IdentityStatus::parse(&identity_status)?;
        let identity_json = serde_json::from_str(&identity_json)
            .map_err(|error| internal(format!("清理数据源身份记录损坏: {error}")))?;
        specs.push(RuntimeSourceSpec {
            source_id: source_id.clone(),
            mount_key,
            raw_relative_root,
            source_write_enabled: write_enabled != 0,
            source_protected: protected != 0,
            identity_status,
            identity_json,
        });
    }
    Ok(specs)
}

fn validate_runtime_source_identity(
    spec: &RuntimeSourceSpec,
    mount: &crate::config::ApprovedMount,
    root: &SecureRoot,
) -> AppResult<()> {
    if spec.identity_status != IdentityStatus::Verified {
        return Err(AppError::new(
            ErrorCode::SourceIdentityChanged,
            format!(
                "数据源 {} 尚未确认当前文件系统身份，请重新确认身份",
                spec.source_id
            ),
        ));
    }
    if spec
        .identity_json
        .get("device_id")
        .and_then(serde_json::Value::as_str)
        .is_none()
    {
        return Err(AppError::new(
            ErrorCode::SourceIdentityChanged,
            format!("数据源 {} 缺少已确认的文件系统身份", spec.source_id),
        ));
    }

    let probe = source::run_probe(mount, &spec.raw_relative_root);
    let probed = probe.fs_identity.ok_or_else(|| {
        AppError::new(
            ErrorCode::SourceUnavailable,
            format!("数据源 {} 当前无法读取文件系统身份", spec.source_id),
        )
    })?;
    if source::identity_differs(&spec.identity_json, &probed) {
        return Err(AppError::new(
            ErrorCode::SourceIdentityChanged,
            format!("数据源 {} 的文件系统身份与已确认身份不一致", spec.source_id),
        ));
    }

    let opened_root = root
        .stat(OsStr::from_bytes(&spec.raw_relative_root))
        .map_err(fs_error)?;
    if opened_root.identity.device_id.to_string() != probed.device_id {
        return Err(AppError::new(
            ErrorCode::SourceIdentityChanged,
            format!("数据源 {} 在打开后发生文件系统身份变化", spec.source_id),
        ));
    }
    Ok(())
}

fn open_runtime_context(
    config: &DeploymentConfig,
    specs: Vec<RuntimeSourceSpec>,
    signing_key: Option<Vec<u8>>,
) -> AppResult<RuntimeCleanupContext> {
    let mut source_roots = BTreeMap::new();
    let mut gates = BTreeMap::new();
    for spec in specs {
        let mount = config.mount(&spec.mount_key).ok_or_else(|| {
            AppError::new(
                ErrorCode::SourceUnavailable,
                format!("批准挂载不存在: {}", spec.mount_key),
            )
        })?;
        let root = SecureRoot::open(mount.container_path.as_os_str()).map_err(fs_error)?;
        validate_runtime_source_identity(&spec, mount, &root)?;
        gates.insert(
            spec.source_id.clone(),
            CleanupGate {
                allow_write_operations: config.security.allow_write_operations,
                source: SourceCleanupGate {
                    mount_writable: mount.writable,
                    source_write_enabled: spec.source_write_enabled,
                    source_protected: spec.source_protected,
                    safe_write_capable: root.caps().supports_safe_writes(),
                },
            },
        );
        source_roots.insert(spec.source_id, root);
    }
    let journal_root = SecureRoot::open(config.storage.data_dir.as_os_str()).map_err(fs_error)?;
    Ok(RuntimeCleanupContext {
        source_roots,
        gates,
        journal_root,
        signing_key,
    })
}

fn runtime_roots(context: &RuntimeCleanupContext) -> CleanupRoots<'_> {
    let source_roots = context
        .source_roots
        .iter()
        .map(|(source_id, root)| (source_id.clone(), root))
        .collect();
    CleanupRoots {
        source_roots,
        journal_root: &context.journal_root,
    }
}

/// Execute one claimed cleanup job from the operation supervisor.
pub fn run_job(
    writer: crate::store::DbWriter,
    config: &DeploymentConfig,
    job: &Job,
) -> AppResult<()> {
    if job.job_type != JobType::CleanupAction || job.state != JobState::Running {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "清理 supervisor 只能执行已领取的 RUNNING cleanup 任务",
        ));
    }
    let request = CleanupJob::parse(&job.params_json)?;
    let db = CleanupWriter::new(writer);
    let specs = db.load_source_specs(&request)?;
    let signing_key = match request {
        CleanupJob::Quarantine { .. } | CleanupJob::Purge { .. } | CleanupJob::AutoPurge { .. } => {
            Some(db.load_signing_key()?)
        }
        CleanupJob::Restore { .. } => None,
    };
    let context = open_runtime_context(config, specs, signing_key)?;
    let result = match &request {
        CleanupJob::Quarantine {
            action_id,
            plan_id,
            actor_id,
        } => run_quarantine_job(&db, job, action_id, plan_id, actor_id, &context),
        CleanupJob::Restore {
            action_id,
            item_id,
            actor_id,
            new_name,
        } => run_restore_job(
            &db,
            job,
            action_id,
            item_id,
            actor_id,
            new_name.as_deref(),
            &context,
        ),
        CleanupJob::Purge {
            action_id,
            plan_id,
            item_id,
            actor_id,
        } => run_purge_job(
            &db, job, action_id, plan_id, item_id, actor_id, false, &context,
        ),
        CleanupJob::AutoPurge {
            action_id,
            plan_id,
            item_id,
            actor_id,
        } => run_purge_job(
            &db, job, action_id, plan_id, item_id, actor_id, true, &context,
        ),
    };
    if let Err(error) = result {
        if let Err(recovery_error) = recover_action_job(&db, &request, &context) {
            let recovery_message = format!(
                "{}；清理状态恢复失败: {}",
                error.message, recovery_error.message
            );
            db.mark_recovery_conflict(&request, &recovery_message)?;
            return Err(AppError::new(error.code, recovery_message));
        }
        return Err(error);
    }
    Ok(())
}

fn runtime_signing_key(context: &RuntimeCleanupContext) -> AppResult<&[u8]> {
    context
        .signing_key
        .as_deref()
        .ok_or_else(|| internal("清理任务缺少计划签名密钥"))
}

fn cleanup_error_json(error: &AppError) -> serde_json::Value {
    json!({
        "code": error.code.as_str(),
        "message": error.message,
    })
}

fn cleanup_progress(action_id: &str, state: &str) -> serde_json::Value {
    json!({
        "action_id": action_id,
        "state": state,
    })
}

fn fail_cleanup_item(
    db: &CleanupWriter,
    item: &ItemRow,
    action_id: &str,
    error: &AppError,
) -> AppResult<()> {
    db.update_item(
        &item.id,
        action_id,
        CleanupItemState::Failed,
        item.quarantine_path.clone(),
        item.journal_seq,
        Some(error.message.clone()),
    )
}

fn finish_cleanup_partial(
    db: &CleanupWriter,
    job: &Job,
    plan_id: &str,
    action_id: &str,
    actor_id: &str,
    error: &AppError,
) -> AppResult<()> {
    db.finish(
        &job.id,
        Some(plan_id),
        action_id,
        actor_id,
        JobState::Partial,
        Some("completed"),
        "cleanup.execute",
        cleanup_progress(action_id, "partial"),
        Some(cleanup_error_json(error)),
    )?;
    Ok(())
}

fn stop_cleanup_if_cancelling(
    db: &CleanupWriter,
    job: &Job,
    plan_id: Option<&str>,
    action_id: &str,
    actor_id: &str,
    action_name: &str,
) -> AppResult<bool> {
    if !db.is_cancelling(&job.id)? {
        return Ok(false);
    }
    db.finish(
        &job.id,
        plan_id,
        action_id,
        actor_id,
        JobState::Succeeded,
        None,
        action_name,
        cleanup_progress(action_id, "cancelled"),
        None,
    )?;
    Ok(true)
}

fn run_quarantine_job(
    db: &CleanupWriter,
    job: &Job,
    action_id: &str,
    plan_id: &str,
    actor_id: &str,
    context: &RuntimeCleanupContext,
) -> AppResult<()> {
    let signing_key = runtime_signing_key(context)?;
    let plan = db.load_plan(plan_id)?;
    let payload = load_payload(&plan, signing_key)?;
    if plan_expired(&plan.expires_at)? {
        return Err(AppError::new(ErrorCode::PlanExpired, "清理计划已过期"));
    }
    if plan.state != "executing" {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "清理计划已经执行或失效",
        ));
    }
    if plan.actor_id != actor_id {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "清理任务操作者与计划操作者不一致",
        ));
    }

    let roots = runtime_roots(context);
    let mut items = db.load_items(action_id, plan_id)?;
    if items.is_empty() {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "清理动作未关联有效的清理条目",
        ));
    }
    let plan_items = db.load_plan_items(plan_id)?;
    if plan_items.len() != items.len()
        || plan_items
            .iter()
            .any(|item| item.action_id.as_deref() != Some(action_id))
    {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "清理计划包含未绑定当前动作的条目",
        ));
    }
    let existing_events = read_journal(roots.journal_root, action_id)?;
    let entries = stored_group_map(&payload);
    let mut completed_entry_ids = BTreeSet::new();
    for item in &items {
        if stop_cleanup_if_cancelling(
            db,
            job,
            Some(plan_id),
            action_id,
            actor_id,
            "cleanup.execute",
        )? {
            return Ok(());
        }
        if item.action_id.as_deref() != Some(action_id) {
            return Err(internal("清理条目与动作 ID 不一致"));
        }
        let target = entries
            .get(&item.entry_id)
            .ok_or_else(|| internal("清理动作缺少计划条目"))?;
        if item.source_id != target.source_id {
            return Err(AppError::new(
                ErrorCode::JobStateConflict,
                "清理条目数据源与计划条目不一致",
            ));
        }
        match &item.state {
            CleanupItemState::Quarantined => {
                let root = roots.source(&item.source_id)?;
                validate_quarantined_item(action_id, root, item, &existing_events)?;
                completed_entry_ids.insert(item.entry_id);
            }
            CleanupItemState::Planned | CleanupItemState::Validating | CleanupItemState::Failed => {
                if item.quarantine_path.is_some() {
                    return Err(AppError::new(
                        ErrorCode::QuarantineConflict,
                        "待重试条目带有未核验的残留隔离路径",
                    ));
                }
            }
            CleanupItemState::Moving => {
                return Err(AppError::new(
                    ErrorCode::JobStateConflict,
                    "清理条目仍处于 MOVING，必须先完成动作恢复",
                ));
            }
            CleanupItemState::Conflict
            | CleanupItemState::Restored
            | CleanupItemState::Purged
            | CleanupItemState::Skipped => {
                return Err(AppError::new(
                    ErrorCode::JobStateConflict,
                    "清理条目当前状态不能由隔离重试处理",
                ));
            }
        }
    }
    for group in &payload.groups {
        if stop_cleanup_if_cancelling(
            db,
            job,
            Some(plan_id),
            action_id,
            actor_id,
            "cleanup.execute",
        )? {
            return Ok(());
        }
        for entry in &group.members {
            gate_for_source(&context.gates, &entry.source_id)?.check()?;
        }
        for target_id in &group.target_entry_ids {
            if stop_cleanup_if_cancelling(
                db,
                job,
                Some(plan_id),
                action_id,
                actor_id,
                "cleanup.execute",
            )? {
                return Ok(());
            }
            if completed_entry_ids.contains(target_id) {
                continue;
            }
            let target = entries
                .get(target_id)
                .ok_or_else(|| internal("清理计划缺少处理条目"))?;
            let root = context
                .source_roots
                .get(&target.source_id)
                .ok_or_else(|| AppError::new(ErrorCode::SourceUnavailable, "清理源未提供安全根"))?;
            stat_for_plan(root, target)?;
        }
    }

    let mut sequence = last_journal_sequence(&existing_events);
    for item in &items {
        if stop_cleanup_if_cancelling(
            db,
            job,
            Some(plan_id),
            action_id,
            actor_id,
            "cleanup.execute",
        )? {
            return Ok(());
        }
        if item.state == CleanupItemState::Quarantined {
            continue;
        }
        db.update_item(
            &item.id,
            action_id,
            CleanupItemState::Validating,
            None,
            item.journal_seq,
            None,
        )?;
        let target = entries
            .get(&item.entry_id)
            .ok_or_else(|| internal("清理动作缺少计划条目"))?;
        let root = roots.source(&item.source_id)?;
        let candidate = match open_planned_file(root, target) {
            Ok(file) => file,
            Err(error) => {
                fail_cleanup_item(db, item, action_id, &error)?;
                return Err(error);
            }
        };
        let digest = match digest_opened(&candidate) {
            Ok(digest) => digest,
            Err(error) => {
                fail_cleanup_item(db, item, action_id, &error)?;
                return Err(error);
            }
        };
        if digest != item.content_sha256 || digest != target.content_sha256 {
            let error = AppError::new(ErrorCode::FileChanged, "候选文件完整内容已变化");
            fail_cleanup_item(db, item, action_id, &error)?;
            return Err(error);
        }
        let group = payload
            .groups
            .iter()
            .find(|group| group.target_entry_ids.contains(&item.entry_id))
            .ok_or_else(|| internal("清理条目不属于计划组"))?;
        let mut surviving_copy = false;
        for keep_id in &group.keep_entry_ids {
            if stop_cleanup_if_cancelling(
                db,
                job,
                Some(plan_id),
                action_id,
                actor_id,
                "cleanup.execute",
            )? {
                return Ok(());
            }
            let keep = entries
                .get(keep_id)
                .ok_or_else(|| internal("清理计划缺少保留条目"))?;
            let keep_root = roots.source(&keep.source_id)?;
            let keep_file = match open_planned_file(keep_root, keep) {
                Ok(file) => file,
                Err(AppError {
                    code: ErrorCode::NotFound,
                    ..
                }) => continue,
                Err(error) => return Err(error),
            };
            if compare_opened(&candidate, &keep_file)? {
                surviving_copy = true;
                break;
            }
        }
        if !surviving_copy {
            let error = AppError::new(ErrorCode::NoSurvivingCopy, "没有通过完整比较的保留副本");
            fail_cleanup_item(db, item, action_id, &error)?;
            return Err(error);
        }
    }

    for item in &mut items {
        if stop_cleanup_if_cancelling(
            db,
            job,
            Some(plan_id),
            action_id,
            actor_id,
            "cleanup.execute",
        )? {
            return Ok(());
        }
        if item.state == CleanupItemState::Quarantined {
            continue;
        }
        let target = entries
            .get(&item.entry_id)
            .ok_or_else(|| internal("清理动作缺少计划条目"))?;
        let root = roots.source(&item.source_id)?;
        let quarantine = quarantine_path(action_id, &item.id);
        let quarantine_dir = ensure_quarantine_directory(root, action_id)?;
        root.fsync_dir(&quarantine_dir).map_err(fs_error)?;
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| validation("清理日志序号溢出"))?;
        db.update_item(
            &item.id,
            action_id,
            CleanupItemState::Moving,
            Some(quarantine.clone()),
            sequence,
            None,
        )?;
        write_journal(
            roots.journal_root,
            action_id,
            sequence,
            "before_move",
            &item.id,
            &item.original_path,
            Some(&quarantine),
        )?;
        if let Err(error) = root.rename_noreplace(raw_path(&target.raw_path), raw_path(&quarantine))
        {
            let mapped = fs_error(error);
            db.update_item(
                &item.id,
                action_id,
                CleanupItemState::Conflict,
                Some(quarantine.clone()),
                sequence,
                Some(mapped.message.clone()),
            )?;
            return finish_cleanup_partial(db, job, plan_id, action_id, actor_id, &mapped);
        }
        sync_move_directories(root, &target.raw_path, &quarantine)?;
        let moved = root
            .open_file(raw_path(&quarantine), OpenOptions::default())
            .map_err(fs_error)?;
        if !FileStamp::from_fd(&moved.fd)?.matches_after_rename(&target.stamp()) {
            let error = AppError::new(ErrorCode::QuarantineConflict, "隔离目标身份校验失败");
            let rollback = root.rename_noreplace(raw_path(&quarantine), raw_path(&target.raw_path));
            let state = if rollback.is_ok() {
                CleanupItemState::Failed
            } else {
                CleanupItemState::Conflict
            };
            db.update_item(
                &item.id,
                action_id,
                state,
                Some(quarantine.clone()),
                sequence,
                Some(error.message.clone()),
            )?;
            return finish_cleanup_partial(db, job, plan_id, action_id, actor_id, &error);
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| validation("清理日志序号溢出"))?;
        write_journal(
            roots.journal_root,
            action_id,
            sequence,
            "after_move",
            &item.id,
            &item.original_path,
            Some(&quarantine),
        )?;
        db.update_item(
            &item.id,
            action_id,
            CleanupItemState::Quarantined,
            Some(quarantine),
            sequence,
            None,
        )?;
    }

    db.finish(
        &job.id,
        Some(plan_id),
        action_id,
        actor_id,
        JobState::Succeeded,
        Some("completed"),
        "cleanup.execute",
        cleanup_progress(action_id, "completed"),
        None,
    )?;
    Ok(())
}

fn run_restore_job(
    db: &CleanupWriter,
    job: &Job,
    action_id: &str,
    item_id: &str,
    actor_id: &str,
    new_name: Option<&[u8]>,
    context: &RuntimeCleanupContext,
) -> AppResult<()> {
    let item = db.load_item(item_id)?;
    if item.action_id.as_deref() != Some(action_id) {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "恢复任务与隔离动作不一致",
        ));
    }
    let plan_id = db.load_item_plan_id(item_id)?;
    let plan = db.load_plan(&plan_id)?;
    if plan.actor_id != actor_id {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "恢复任务操作者与清理计划操作者不一致",
        ));
    }
    if item.state != CleanupItemState::Quarantined {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "只有 QUARANTINED 条目可以恢复",
        ));
    }
    if let Some(name) = new_name {
        validate_name_component(name)?;
    }
    gate_for_source(&context.gates, &item.source_id)?.check()?;
    if stop_cleanup_if_cancelling(db, job, None, action_id, actor_id, "cleanup.restore")? {
        return Ok(());
    }
    let roots = runtime_roots(context);
    let quarantine = item
        .quarantine_path
        .as_deref()
        .ok_or_else(|| internal("隔离条目缺少隔离路径"))?;
    let events = read_journal(roots.journal_root, action_id)?;
    if completed_journal_event(
        &events,
        "before_move",
        "after_move",
        &item.id,
        &item.original_path,
        quarantine,
    )
    .is_none()
    {
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "隔离动作日志尚未确认移动完成",
        ));
    }
    let root = roots.source(&item.source_id)?;
    let file = root
        .open_file(raw_path(quarantine), OpenOptions::default())
        .map_err(fs_error)?;
    if !FileStamp::from_fd(&file.fd)?.matches_after_rename(&item.identity) {
        return Err(AppError::new(ErrorCode::FileChanged, "隔离文件身份已变化"));
    }
    let destination = match new_name {
        Some(name) => combine_parent_name(&item.original_path, name),
        None => item.original_path.clone(),
    };
    match root.stat(raw_path(&destination)) {
        Ok(_) => {
            return Err(AppError::new(
                ErrorCode::QuarantineConflict,
                "恢复目标已存在，拒绝覆盖",
            ));
        }
        Err(FsSecureError::NotFound) => {}
        Err(error) => return Err(fs_error(error)),
    }
    let parent = parent_path(&destination);
    if !parent.is_empty() {
        ensure_restore_parent(root, &parent)?;
    }
    let sequence = next_journal_sequence(&events, item.journal_seq)?;
    write_journal(
        roots.journal_root,
        action_id,
        sequence,
        "before_restore",
        &item.id,
        &destination,
        Some(quarantine),
    )?;
    root.rename_noreplace(raw_path(quarantine), raw_path(&destination))
        .map_err(fs_error)?;
    if let Err(error) = sync_move_directories(root, quarantine, &destination) {
        let rollback = root.rename_noreplace(raw_path(&destination), raw_path(quarantine));
        if rollback.is_err() {
            return Err(AppError::new(
                ErrorCode::QuarantineConflict,
                format!("恢复后的目录同步失败且无法回滚: {}", error.message),
            ));
        }
        return Err(error);
    }
    let restored = root
        .open_file(raw_path(&destination), OpenOptions::default())
        .map_err(fs_error)?;
    if !FileStamp::from_fd(&restored.fd)?.matches_after_rename(&item.identity) {
        let rollback = root.rename_noreplace(raw_path(&destination), raw_path(quarantine));
        if rollback.is_err() {
            return Err(AppError::new(
                ErrorCode::QuarantineConflict,
                "恢复后文件身份校验失败且无法回滚",
            ));
        }
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "恢复后文件身份校验失败",
        ));
    }
    let after_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| validation("清理日志序号溢出"))?;
    if let Err(error) = write_journal(
        roots.journal_root,
        action_id,
        after_sequence,
        "after_restore",
        &item.id,
        &destination,
        None,
    ) {
        let rollback = root.rename_noreplace(raw_path(&destination), raw_path(quarantine));
        if rollback.is_err() {
            return Err(AppError::new(
                ErrorCode::QuarantineConflict,
                format!("恢复日志失败且无法回滚: {}", error.message),
            ));
        }
        return Err(error);
    }
    db.update_item(
        item_id,
        action_id,
        CleanupItemState::Restored,
        None,
        after_sequence,
        None,
    )?;
    db.finish(
        &job.id,
        None,
        action_id,
        actor_id,
        JobState::Succeeded,
        None,
        "cleanup.restore",
        cleanup_progress(action_id, "restored"),
        None,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_purge_job(
    db: &CleanupWriter,
    job: &Job,
    action_id: &str,
    plan_id: &str,
    item_id: &str,
    actor_id: &str,
    automatic: bool,
    context: &RuntimeCleanupContext,
) -> AppResult<()> {
    let signing_key = runtime_signing_key(context)?;
    if job.params_json["action_id"] != action_id {
        return Err(internal("永久清理任务 action_id 不一致"));
    }
    let item = db.load_item(item_id)?;
    if item.action_id.as_deref() != Some(action_id) {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "永久清理任务与隔离动作不一致",
        ));
    }
    if item.state != CleanupItemState::Quarantined {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "只有 QUARANTINED 条目可以永久清理",
        ));
    }
    if automatic {
        let policy = db.load_auto_purge_policy()?;
        if !policy.enabled {
            return Err(AppError::new(
                ErrorCode::ReadOnlyMode,
                "隔离区自动清理未启用",
            ));
        }
        let updated_at = db.load_item_updated_at(item_id)?;
        let quarantined_at = auth::parse_ts(&updated_at)?;
        let keep_seconds = i64::from(policy.min_keep_days)
            .checked_mul(24 * 60 * 60)
            .ok_or_else(|| validation("隔离区自动清理保留期溢出"))?;
        let cutoff = jiff::Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_secs(keep_seconds))
            .map_err(|_| internal("计算隔离区自动清理保留期失败"))?;
        if quarantined_at > cutoff {
            return Err(AppError::new(
                ErrorCode::JobStateConflict,
                "隔离文件尚未达到自动清理最短保留期",
            ));
        }
    }
    let actual_plan_id = db.load_item_plan_id(item_id)?;
    if actual_plan_id != plan_id {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "永久清理任务与清理计划不一致",
        ));
    }
    let plan = db.load_plan(plan_id)?;
    if plan.actor_id != actor_id {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "清理任务操作者与计划操作者不一致",
        ));
    }
    let payload = load_payload(&plan, signing_key)?;
    gate_for_source(&context.gates, &item.source_id)?.check()?;
    if stop_cleanup_if_cancelling(
        db,
        job,
        None,
        action_id,
        actor_id,
        if automatic {
            "cleanup.auto_purge"
        } else {
            "cleanup.purge"
        },
    )? {
        return Ok(());
    }
    let roots = runtime_roots(context);
    let root = roots.source(&item.source_id)?;
    let quarantine = item
        .quarantine_path
        .as_deref()
        .ok_or_else(|| internal("隔离条目缺少路径"))?;
    let expected_quarantine = quarantine_path(action_id, item_id);
    if quarantine != expected_quarantine.as_slice() {
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "隔离路径不是该动作生成的受控路径",
        ));
    }
    let events = read_journal(roots.journal_root, action_id)?;
    if completed_journal_event(
        &events,
        "before_move",
        "after_move",
        item_id,
        &item.original_path,
        quarantine,
    )
    .is_none()
    {
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "隔离动作日志尚未确认移动完成",
        ));
    }
    let quarantined = root
        .open_file(raw_path(quarantine), OpenOptions::default())
        .map_err(fs_error)?;
    if !FileStamp::from_fd(&quarantined.fd)?.matches_after_rename(&item.identity)
        || quarantined.stat.nlink != 1
    {
        return Err(AppError::new(ErrorCode::FileChanged, "隔离文件身份已变化"));
    }
    let entries = stored_group_map(&payload);
    let group = payload
        .groups
        .iter()
        .find(|group| group.target_entry_ids.contains(&item.entry_id))
        .ok_or_else(|| internal("隔离条目不属于计划组"))?;
    let mut surviving = false;
    for keep_id in &group.keep_entry_ids {
        let keep = entries
            .get(keep_id)
            .ok_or_else(|| internal("清理计划缺少保留项"))?;
        let keep_root = roots.source(&keep.source_id)?;
        let keep_file = match open_planned_file(keep_root, keep) {
            Ok(file) => file,
            Err(AppError {
                code: ErrorCode::NotFound,
                ..
            }) => continue,
            Err(error) => return Err(error),
        };
        if compare_opened(&quarantined, &keep_file)? {
            surviving = true;
            break;
        }
    }
    if !surviving {
        return Err(AppError::new(
            ErrorCode::NoSurvivingCopy,
            "保留副本已不存在或内容不一致",
        ));
    }
    if stop_cleanup_if_cancelling(
        db,
        job,
        None,
        action_id,
        actor_id,
        if automatic {
            "cleanup.auto_purge"
        } else {
            "cleanup.purge"
        },
    )? {
        return Ok(());
    }
    let sequence = next_journal_sequence(&events, item.journal_seq)?;
    write_journal(
        roots.journal_root,
        action_id,
        sequence,
        "before_purge",
        item_id,
        &item.original_path,
        Some(quarantine),
    )?;
    root.unlink_file(raw_path(quarantine)).map_err(fs_error)?;
    let quarantine_parent = parent_path(quarantine);
    root.fsync_dir(OsStr::from_bytes(&quarantine_parent))
        .map_err(fs_error)?;
    if !matches!(
        root.stat(raw_path(quarantine)),
        Err(FsSecureError::NotFound)
    ) {
        return Err(AppError::new(
            ErrorCode::QuarantineConflict,
            "永久清理后隔离文件仍存在",
        ));
    }
    let after_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| validation("清理日志序号溢出"))?;
    write_journal(
        roots.journal_root,
        action_id,
        after_sequence,
        "after_purge",
        item_id,
        &item.original_path,
        None,
    )?;
    db.update_item(
        item_id,
        action_id,
        CleanupItemState::Purged,
        None,
        after_sequence,
        None,
    )?;
    db.finish(
        &job.id,
        None,
        action_id,
        actor_id,
        JobState::Succeeded,
        None,
        if automatic {
            "cleanup.auto_purge"
        } else {
            "cleanup.purge"
        },
        cleanup_progress(action_id, "purged"),
        None,
    )?;
    Ok(())
}

/// Recover cleanup jobs that were marked INTERRUPTED during startup. File
/// inspection and journal reads run on the caller's dedicated blocking thread;
/// only the short SQL operations use the control writer.
pub fn recover_pending(
    writer: crate::store::DbWriter,
    config: &DeploymentConfig,
) -> AppResult<usize> {
    let db = CleanupWriter::new(writer);
    let jobs = db.load_recovery_jobs()?;
    let mut recovered = 0_usize;
    for (job, source_ids) in jobs {
        let request = CleanupJob::parse(&job.params_json)?;
        let specs = db.load_source_specs_for_ids(source_ids)?;
        let context = open_runtime_context(config, specs, None)?;
        recover_action_job(&db, &request, &context)?;
        recovered = recovered
            .checked_add(1)
            .ok_or_else(|| internal("恢复清理任务数量溢出"))?;
    }
    Ok(recovered)
}

fn recover_action_job(
    db: &CleanupWriter,
    request: &CleanupJob,
    context: &RuntimeCleanupContext,
) -> AppResult<()> {
    let (action_id, plan_id, selected_item_id) = match request {
        CleanupJob::Quarantine {
            action_id, plan_id, ..
        } => (action_id.as_str(), plan_id.clone(), None),
        CleanupJob::Restore {
            action_id, item_id, ..
        } => (
            action_id.as_str(),
            db.load_item_plan_id(item_id)?,
            Some(item_id.as_str()),
        ),
        CleanupJob::Purge {
            action_id,
            plan_id,
            item_id,
            ..
        }
        | CleanupJob::AutoPurge {
            action_id,
            plan_id,
            item_id,
            ..
        } => (action_id.as_str(), plan_id.clone(), Some(item_id.as_str())),
    };
    let restore_destination = match request {
        CleanupJob::Restore {
            actor_id,
            item_id,
            new_name,
            ..
        } => {
            let item = db.load_item(item_id)?;
            if item.action_id.as_deref() != Some(action_id) {
                return Err(AppError::new(
                    ErrorCode::JobStateConflict,
                    "恢复任务与隔离动作不一致",
                ));
            }
            let plan = db.load_plan(&plan_id)?;
            if plan.actor_id != *actor_id {
                return Err(AppError::new(
                    ErrorCode::Forbidden,
                    "恢复任务操作者与清理计划操作者不一致",
                ));
            }
            if let Some(name) = new_name {
                validate_name_component(name)?;
            }
            let destination = match new_name {
                Some(name) => combine_parent_name(&item.original_path, name),
                None => item.original_path.clone(),
            };
            Some(destination)
        }
        CleanupJob::Quarantine { actor_id, .. } => {
            let plan = db.load_plan(&plan_id)?;
            if plan.actor_id != *actor_id {
                return Err(AppError::new(
                    ErrorCode::Forbidden,
                    "清理任务操作者与清理计划操作者不一致",
                ));
            }
            None
        }
        CleanupJob::Purge {
            actor_id, item_id, ..
        }
        | CleanupJob::AutoPurge {
            actor_id, item_id, ..
        } => {
            let item = db.load_item(item_id)?;
            if item.action_id.as_deref() != Some(action_id) {
                return Err(AppError::new(
                    ErrorCode::JobStateConflict,
                    "永久清理任务与隔离动作不一致",
                ));
            }
            let actual_plan_id = db.load_item_plan_id(item_id)?;
            if actual_plan_id != plan_id {
                return Err(AppError::new(
                    ErrorCode::JobStateConflict,
                    "永久清理任务与清理计划不一致",
                ));
            }
            let plan = db.load_plan(&plan_id)?;
            if plan.actor_id != *actor_id {
                return Err(AppError::new(
                    ErrorCode::Forbidden,
                    "清理任务操作者与清理计划操作者不一致",
                ));
            }
            None
        }
    };
    let events = read_journal(&context.journal_root, action_id)?;
    let all_items = db.load_items(action_id, &plan_id)?;
    if all_items.is_empty() {
        return Err(AppError::new(
            ErrorCode::JobStateConflict,
            "清理任务未关联有效的清理条目",
        ));
    }
    for item in all_items
        .iter()
        .filter(|item| selected_item_id.is_none() || selected_item_id == Some(item.id.as_str()))
    {
        let root = context
            .source_roots
            .get(&item.source_id)
            .ok_or_else(|| AppError::new(ErrorCode::SourceUnavailable, "清理源未提供安全根"))?;
        if let RecoveryDecision::Update {
            state,
            quarantine_path,
            journal_seq,
            error,
        } = reconcile_recovery_item(
            action_id,
            root,
            item,
            &events,
            restore_destination.as_deref(),
        )? {
            db.update_item(
                &item.id,
                action_id,
                state,
                quarantine_path,
                journal_seq,
                error,
            )?;
        }
    }
    Ok(())
}

fn stat_for_recovery(root: &SecureRoot, path: &[u8]) -> AppResult<Option<StatData>> {
    match root.stat(raw_path(path)) {
        Ok(stat) => Ok(Some(stat)),
        Err(FsSecureError::NotFound) => Ok(None),
        Err(error) => Err(fs_error(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{create_admin, create_reauth_token};
    use crate::config::{
        ApprovedMount, DeploymentConfig, ResourceConfig, SamplingConfig, SecurityConfig,
        ServerConfig, StorageConfig,
    };
    use crate::store::migrate::{CONTROL_MIGRATIONS, apply};
    use std::fs;

    #[test]
    fn file_stamp_numeric_conversion_rejects_out_of_range_values() {
        assert!(
            FileStamp::from_raw_values(RawFileStamp {
                device_id: -1,
                inode_id: 0,
                size_bytes: 0,
                nlink: 1,
                mtime_sec: 0,
                mtime_nsec: 0,
                ctime_sec: 0,
                ctime_nsec: 0,
            })
            .is_err()
        );
        assert!(
            FileStamp::from_raw_values(RawFileStamp {
                device_id: 0,
                inode_id: 0,
                size_bytes: i128::from(i64::MAX) + 1,
                nlink: 1,
                mtime_sec: 0,
                mtime_nsec: 0,
                ctime_sec: 0,
                ctime_nsec: 0,
            })
            .is_err()
        );
        assert!(
            FileStamp::from_raw_values(RawFileStamp {
                device_id: 0,
                inode_id: 0,
                size_bytes: -1,
                nlink: 1,
                mtime_sec: 0,
                mtime_nsec: 0,
                ctime_sec: 0,
                ctime_nsec: 0,
            })
            .is_err()
        );
    }

    #[test]
    fn cleanup_job_parser_requires_exact_action_contract() {
        assert!(matches!(
            CleanupJob::parse(&serde_json::json!({
                "action": "quarantine",
                "action_id": "action-1",
                "plan_id": "plan-1",
                "actor_id": "actor-1"
            })),
            Ok(CleanupJob::Quarantine { .. })
        ));
        assert!(matches!(
            CleanupJob::parse(&serde_json::json!({
                "action": "restore",
                "action_id": "action-1",
                "item_id": "item-1",
                "actor_id": "actor-1",
                "new_name": null
            })),
            Ok(CleanupJob::Restore { new_name: None, .. })
        ));
        for params in [
            serde_json::json!({
                "action": "quarantine",
                "action_id": "action-1",
                "plan_id": "plan-1",
                "actor_id": "actor-1",
                "unknown": true
            }),
            serde_json::json!({
                "action": "restore",
                "action_id": "action-1",
                "item_id": "item-1",
                "actor_id": "actor-1"
            }),
            serde_json::json!({
                "action": "restore",
                "action_id": "action-1",
                "item_id": "item-1",
                "actor_id": "actor-1",
                "new_name": 7
            }),
            serde_json::json!({
                "action": "purge",
                "action_id": "action-1",
                "plan_id": "plan-1",
                "item_id": "item-1",
                "actor_id": "actor-1",
                "extra": false
            }),
            serde_json::json!({"action": "unknown"}),
            serde_json::json!(["not", "an", "object"]),
        ] {
            assert!(matches!(
                CleanupJob::parse(&params),
                Err(AppError {
                    code: ErrorCode::ValidationFailed,
                    ..
                })
            ));
        }
    }

    #[test]
    fn recovery_stat_propagates_non_not_found_filesystem_errors() {
        let temp = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(temp.path().as_os_str()).unwrap();
        let error = stat_for_recovery(&root, b"../outside").unwrap_err();
        assert_eq!(error.code, ErrorCode::PathOutsideRoot);
    }

    #[test]
    fn journal_rejects_invalid_paths_instead_of_treating_events_as_absent() {
        let temp = tempfile::tempdir().unwrap();
        let journal_path = temp
            .path()
            .join("actions/invalid-journal/journal/journal.jsonl");
        fs::create_dir_all(journal_path.parent().unwrap()).unwrap();
        fs::write(
            &journal_path,
            br#"{"seq":1,"event":"after_move","item_id":"item","original_path_b64":"%%%","quarantine_path_b64":"dGVzdA=="}
"#,
        )
        .unwrap();
        let journal = SecureRoot::open(temp.path().as_os_str()).unwrap();

        let error = read_journal(&journal, "invalid-journal").unwrap_err();
        assert_eq!(error.code, ErrorCode::Internal);
    }

    #[test]
    fn journal_rejects_empty_and_incomplete_records() {
        let records = [
            "",
            "{\"seq\":1,\"event\":\"after_move\",\"item_id\":\"item\",\"original_path_b64\":\"dGFyZ2V0\"}\n",
            "{\"seq\":1,\"event\":\"after_move\",\"item_id\":\"item\",\"original_path_b64\":\"dGFyZ2V0\",\"quarantine_path_b64\":null}\n",
            "{\"seq\":1,\"event\":\"after_move\",\"item_id\":\"item\",\"original_path_b64\":\"dGFyZ2V0\",\"quarantine_path_b64\":\"cQ==\"}\n\n",
        ];
        for record in records {
            let temp = tempfile::tempdir().unwrap();
            let journal_path = temp
                .path()
                .join("actions/invalid-journal/journal/journal.jsonl");
            fs::create_dir_all(journal_path.parent().unwrap()).unwrap();
            fs::write(&journal_path, record).unwrap();
            let journal = SecureRoot::open(temp.path().as_os_str()).unwrap();

            let error = read_journal(&journal, "invalid-journal").unwrap_err();
            assert_eq!(error.code, ErrorCode::Internal, "record: {record:?}");
        }
    }

    #[test]
    fn journal_sequence_uses_the_action_tail_for_each_item() {
        let events = vec![
            JournalEvent {
                sequence: 1,
                event: String::from("before_move"),
                item_id: String::from("item-a"),
                original_path: b"a".to_vec(),
                quarantine_path: Some(b"qa".to_vec()),
            },
            JournalEvent {
                sequence: 2,
                event: String::from("after_move"),
                item_id: String::from("item-a"),
                original_path: b"a".to_vec(),
                quarantine_path: Some(b"qa".to_vec()),
            },
            JournalEvent {
                sequence: 3,
                event: String::from("before_move"),
                item_id: String::from("item-b"),
                original_path: b"b".to_vec(),
                quarantine_path: Some(b"qb".to_vec()),
            },
            JournalEvent {
                sequence: 4,
                event: String::from("after_move"),
                item_id: String::from("item-b"),
                original_path: b"b".to_vec(),
                quarantine_path: Some(b"qb".to_vec()),
            },
        ];

        assert_eq!(next_journal_sequence(&events, 2).unwrap(), 5);
        assert_eq!(next_journal_sequence(&events, 4).unwrap(), 5);
    }

    #[test]
    fn recovery_keeps_unstarted_item_journal_sequence_at_zero() {
        let temp = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(temp.path().as_os_str()).unwrap();
        let item = ItemRow {
            id: String::from("item-b"),
            entry_id: 2,
            source_id: String::from("source"),
            original_path: b"target-b".to_vec(),
            quarantine_path: None,
            identity: FileStamp {
                device_id: 1,
                inode_id: 2,
                size_bytes: 0,
                nlink: 1,
                mtime_sec: 0,
                mtime_nsec: 0,
                ctime_sec: 0,
                ctime_nsec: 0,
            },
            content_sha256: String::from("digest"),
            state: CleanupItemState::Validating,
            journal_seq: 0,
            error: None,
            action_id: Some(String::from("action")),
        };
        let events = vec![
            JournalEvent {
                sequence: 1,
                event: String::from("before_move"),
                item_id: String::from("item-a"),
                original_path: b"target-a".to_vec(),
                quarantine_path: Some(b".nas-analyzer-quarantine/action/item-a".to_vec()),
            },
            JournalEvent {
                sequence: 2,
                event: String::from("after_move"),
                item_id: String::from("item-a"),
                original_path: b"target-a".to_vec(),
                quarantine_path: Some(b".nas-analyzer-quarantine/action/item-a".to_vec()),
            },
        ];

        let decision = reconcile_recovery_item("action", &root, &item, &events, None).unwrap();
        assert!(matches!(
            decision,
            RecoveryDecision::Update {
                state: CleanupItemState::Failed,
                journal_seq: 0,
                ..
            }
        ));
    }

    fn db() -> (Connection, String) {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let admin = create_admin(&conn, "admin", "a sufficiently long password").unwrap();
        (conn, admin.id)
    }

    fn recovery_config(
        data_dir: &std::path::Path,
        source_dir: &std::path::Path,
    ) -> DeploymentConfig {
        DeploymentConfig {
            server: ServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                default_timezone: jiff::tz::TimeZone::UTC,
                default_timezone_name: "UTC".to_string(),
                trusted_proxy_cidrs: vec![],
                allow_insecure_lan_http: true,
            },
            storage: StorageConfig {
                data_dir: data_dir.to_path_buf(),
                approved_output_roots: vec![data_dir.to_path_buf()],
                data_budget_bytes: 1024,
                hash_cache_budget_bytes: 1024,
            },
            approved_mounts: vec![ApprovedMount {
                key: "source".to_string(),
                container_path: source_dir.to_path_buf(),
                writable: true,
                allow_submounts: false,
            }],
            security: SecurityConfig {
                allow_write_operations: true,
                session_idle_minutes: 30,
                session_absolute_hours: 24,
                reauth_minutes: 5,
            },
            resources: ResourceConfig {
                max_running_scans: 1,
                max_queued_scans: 1,
                metadata_workers: 1,
                hash_workers: 1,
                hash_read_limit_mib_s: 0,
                max_open_files: 64,
                api_memory_budget_mib: 256,
                worker_memory_budget_mib: 512,
                max_parallel_exports: 1,
            },
            sampling: SamplingConfig {
                interval_minutes: 60,
                raw_retention_days: 1,
                daily_retention_days: 1,
            },
        }
    }

    fn roots<'a>(source: &'a SecureRoot, journal: &'a SecureRoot) -> CleanupRoots<'a> {
        CleanupRoots {
            source_roots: BTreeMap::from([(String::from("source"), source)]),
            journal_root: journal,
        }
    }

    fn entry(root: &SecureRoot, id: i64, name: &[u8], group: &str) -> CleanupEntry {
        let stat = root.stat(OsStr::from_bytes(name)).unwrap();
        let opened = root
            .open_file(OsStr::from_bytes(name), OpenOptions::default())
            .unwrap();
        CleanupEntry {
            entry_id: id,
            source_id: String::from("source"),
            group_id: String::from(group),
            raw_path: name.to_vec(),
            size_bytes: stat.size_bytes,
            identity: stat.identity,
            nlink: stat.nlink,
            kind: stat.kind,
            protected: false,
            content_sha256: digest_opened(&opened).unwrap(),
            mtime: stat.mtime,
            ctime: stat.ctime,
        }
    }

    fn gate(root: &SecureRoot) -> BTreeMap<String, CleanupGate> {
        BTreeMap::from([(
            String::from("source"),
            CleanupGate {
                allow_write_operations: true,
                source: SourceCleanupGate {
                    mount_writable: true,
                    source_write_enabled: true,
                    source_protected: false,
                    safe_write_capable: root.caps().supports_safe_writes(),
                },
            },
        )])
    }

    fn mark_test_source_identity(conn: &Connection, source: &SecureRoot) {
        let identity = source.stat(OsStr::new("")).unwrap().identity;
        conn.execute(
            "UPDATE sources
             SET identity_status = 'verified', identity_epoch = 1, identity_json = ?1
             WHERE id = 'source'",
            [json!({"device_id": identity.device_id.to_string()}).to_string()],
        )
        .unwrap();
    }

    #[test]
    fn runtime_cleanup_rejects_a_source_with_changed_filesystem_identity() {
        let root = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        let config = recovery_config(root.path(), source_tmp.path());
        std::fs::create_dir_all(&config.storage.data_dir).unwrap();
        let result = open_runtime_context(
            &config,
            vec![RuntimeSourceSpec {
                source_id: String::from("source"),
                mount_key: String::from("source"),
                raw_relative_root: Vec::new(),
                source_write_enabled: true,
                source_protected: false,
                identity_status: IdentityStatus::Verified,
                identity_json: json!({"device_id": "not-the-current-filesystem"}),
            }],
            None,
        );
        let error = match result {
            Ok(_) => panic!("changed source identity must block cleanup"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::SourceIdentityChanged);
    }

    fn simple_plan<'a>(
        conn: &Connection,
        actor: &str,
        source: &'a SecureRoot,
        journal: &'a SecureRoot,
    ) -> CleanupPlan {
        mark_test_source_identity(conn, source);
        let keep = entry(source, 1, b"keep", "g");
        let target = entry(source, 2, b"target", "g");
        preview(
            conn,
            "report",
            actor,
            &[CleanupGroupSelection {
                group_id: String::from("g"),
                members: vec![keep, target],
                keep_entry_ids: vec![1],
                target_entry_ids: vec![2],
            }],
            &roots(source, journal),
            b"key",
        )
        .unwrap()
    }

    #[test]
    fn preview_is_read_only_and_rejects_escape_paths() {
        let (conn, _) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same").unwrap();
        fs::write(source_tmp.path().join("target"), b"same").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        let keep = entry(&source, 1, b"keep", "g");
        let mut target = entry(&source, 2, b"target", "g");
        target.raw_path = b"../outside".to_vec();
        let result = preview(
            &conn,
            "report",
            "actor",
            &[CleanupGroupSelection {
                group_id: String::from("g"),
                members: vec![keep, target],
                keep_entry_ids: vec![1],
                target_entry_ids: vec![2],
            }],
            &roots(&source, &journal),
            b"key",
        );
        assert!(matches!(
            result,
            Err(AppError {
                code: ErrorCode::PathOutsideRoot,
                ..
            })
        ));
        assert!(source_tmp.path().join("keep").exists());
        assert!(source_tmp.path().join("target").exists());
    }

    #[test]
    fn write_gate_fails_closed_without_safe_capability() {
        let (conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same").unwrap();
        fs::write(source_tmp.path().join("target"), b"same").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        let plan = simple_plan(&conn, &actor, &source, &journal);
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let mut gates = gate(&source);
        gates.get_mut("source").unwrap().source.safe_write_capable = false;
        let result = execute_quarantine(
            &conn,
            &plan.id,
            &token,
            QUARANTINE_CONFIRMATION,
            "idempotency-1",
            &gates,
            &roots(&source, &journal),
            b"key",
        );
        assert!(matches!(
            result,
            Err(AppError {
                code: ErrorCode::UnsupportedCapability,
                ..
            })
        ));
        assert!(source_tmp.path().join("target").exists());
    }

    #[test]
    fn reservation_is_queued_idempotently_without_touching_source_files() {
        let (mut conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        let plan = simple_plan(&conn, &actor, &source, &journal);
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let reservation = reserve_quarantine(
            &mut conn,
            &plan.id,
            &actor,
            &token,
            QUARANTINE_CONFIRMATION,
            "queued-key",
            b"key",
        )
        .unwrap();

        assert!(source_tmp.path().join("target").exists());
        assert!(!source_tmp.path().join(".nas-analyzer-quarantine").exists());
        let (state, params_json): (String, String) = conn
            .query_row(
                "SELECT state, params_json FROM jobs WHERE id = ?1",
                [&reservation.job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "QUEUED");
        assert!(!params_json.contains(&token));
        assert!(!params_json.contains("password"));

        let retry_token = create_reauth_token(&conn, &actor, 5).unwrap();
        let repeated = reserve_quarantine(
            &mut conn,
            &plan.id,
            &actor,
            &retry_token,
            QUARANTINE_CONFIRMATION,
            "queued-key",
            b"key",
        )
        .unwrap();
        assert_eq!(repeated, reservation);
        assert_eq!(
            crate::auth::consume_reauth_token(&conn, &retry_token).unwrap(),
            actor
        );

        let unused = create_reauth_token(&conn, &actor, 5).unwrap();
        let conflict = reserve_quarantine(
            &mut conn,
            &plan.id,
            &actor,
            &unused,
            QUARANTINE_CONFIRMATION,
            "different-key",
            b"key",
        )
        .unwrap_err();
        assert_eq!(conflict.code, ErrorCode::JobStateConflict);
        assert_eq!(
            crate::auth::consume_reauth_token(&conn, &unused).unwrap(),
            actor
        );
    }

    #[test]
    fn full_content_change_is_rejected_before_move() {
        let (conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same").unwrap();
        fs::write(source_tmp.path().join("target"), b"same").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; content-change test skipped");
            return;
        }
        let plan = simple_plan(&conn, &actor, &source, &journal);
        fs::write(source_tmp.path().join("target"), b"changed").unwrap();
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let result = execute_quarantine(
            &conn,
            &plan.id,
            &token,
            QUARANTINE_CONFIRMATION,
            "idempotency-1",
            &gate(&source),
            &roots(&source, &journal),
            b"key",
        );
        assert!(matches!(
            result,
            Err(AppError {
                code: ErrorCode::FileChanged,
                ..
            })
        ));
        assert!(source_tmp.path().join("target").exists());
    }

    #[test]
    fn lifecycle_quarantine_restore_purge_on_supported_kernel() {
        let (conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; lifecycle test skipped");
            return;
        }
        let plan = simple_plan(&conn, &actor, &source, &journal);
        let roots = roots(&source, &journal);
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let action = execute_quarantine(
            &conn,
            &plan.id,
            &token,
            QUARANTINE_CONFIRMATION,
            "idempotency-1",
            &gate(&source),
            &roots,
            b"key",
        )
        .unwrap();
        assert_eq!(action.state, "completed");
        assert!(!source_tmp.path().join("target").exists());
        assert!(
            source_tmp
                .path()
                .join(format!(
                    ".nas-analyzer-quarantine/{}/{}",
                    action.id, action.items[0].id
                ))
                .exists()
        );
        let restored = restore(&conn, &action.items[0].id, &roots, Some(b"restored")).unwrap();
        assert_eq!(restored.state, CleanupItemState::Restored);
        assert!(source_tmp.path().join("restored").exists());
    }

    #[test]
    fn purge_requires_and_preserves_a_surviving_copy() {
        let (conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; purge test skipped");
            return;
        }
        let roots = roots(&source, &journal);
        let plan = simple_plan(&conn, &actor, &source, &journal);
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let action = execute_quarantine(
            &conn,
            &plan.id,
            &token,
            QUARANTINE_CONFIRMATION,
            "idempotency-purge",
            &gate(&source),
            &roots,
            b"key",
        )
        .unwrap();
        let item_id = action.items[0].id.clone();
        let quarantine_path = source_tmp.path().join(format!(
            ".nas-analyzer-quarantine/{}/{}",
            action.id, item_id
        ));
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let result = purge(
            &conn,
            &item_id,
            &token,
            PURGE_CONFIRMATION,
            b"key",
            &gate(&source),
            &roots,
        )
        .unwrap();
        assert_eq!(result.state, CleanupItemState::Purged);
        assert!(!quarantine_path.exists());
        assert_eq!(
            fs::read(source_tmp.path().join("keep")).unwrap(),
            b"same content"
        );
    }

    #[test]
    fn purge_reservation_does_not_consume_a_second_token_on_retry() {
        let (mut conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; purge reservation test skipped");
            return;
        }
        let roots = roots(&source, &journal);
        let plan = simple_plan(&conn, &actor, &source, &journal);
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let action = execute_quarantine(
            &conn,
            &plan.id,
            &token,
            QUARANTINE_CONFIRMATION,
            "purge-reservation-quarantine",
            &gate(&source),
            &roots,
            b"key",
        )
        .unwrap();
        let item_id = action.items[0].id.clone();
        let purge_token = create_reauth_token(&conn, &actor, 5).unwrap();
        let first = reserve_purge(
            &mut conn,
            &item_id,
            &actor,
            &purge_token,
            PURGE_CONFIRMATION,
            "purge-key",
        )
        .unwrap();
        let retry_token = create_reauth_token(&conn, &actor, 5).unwrap();
        let repeated = reserve_purge(
            &mut conn,
            &item_id,
            &actor,
            &retry_token,
            PURGE_CONFIRMATION,
            "purge-key",
        )
        .unwrap();
        assert_eq!(repeated, first);
        assert_eq!(
            crate::auth::consume_reauth_token(&conn, &retry_token).unwrap(),
            actor
        );
    }

    #[test]
    fn restore_reservation_is_idempotent_and_does_not_consume_retry_token() {
        let (mut conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; restore reservation test skipped");
            return;
        }
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, write_enabled, protected, created_at, updated_at)
             VALUES ('source', 'source', 'source', 1, 0, ?1, ?1)",
            [crate::auth::now_rfc3339()],
        )
        .unwrap();
        let roots = roots(&source, &journal);
        let plan = simple_plan(&conn, &actor, &source, &journal);
        let quarantine_token = create_reauth_token(&conn, &actor, 5).unwrap();
        let action = execute_quarantine(
            &conn,
            &plan.id,
            &quarantine_token,
            QUARANTINE_CONFIRMATION,
            "restore-reservation-quarantine",
            &gate(&source),
            &roots,
            b"key",
        )
        .unwrap();
        let item_id = action.items[0].id.clone();
        let restore_token = create_reauth_token(&conn, &actor, 5).unwrap();
        let first = reserve_restore(
            &mut conn,
            &item_id,
            &actor,
            &restore_token,
            Some(b"restored"),
            "restore-key",
        )
        .unwrap();
        assert_eq!(
            load_item(&conn, &item_id).unwrap().state,
            CleanupItemState::Quarantined
        );
        let retry_token = create_reauth_token(&conn, &actor, 5).unwrap();
        let repeated = reserve_restore(
            &mut conn,
            &item_id,
            &actor,
            &retry_token,
            Some(b"restored"),
            "restore-key",
        )
        .unwrap();
        assert_eq!(repeated, first);
        assert_eq!(
            crate::auth::consume_reauth_token(&conn, &retry_token).unwrap(),
            actor
        );
        let conflict_token = create_reauth_token(&conn, &actor, 5).unwrap();
        let conflict = reserve_restore(
            &mut conn,
            &item_id,
            &actor,
            &conflict_token,
            Some(b"different"),
            "restore-key",
        )
        .unwrap_err();
        assert_eq!(conflict.code, ErrorCode::Conflict);
        assert_eq!(
            crate::auth::consume_reauth_token(&conn, &conflict_token).unwrap(),
            actor
        );
        let params_json: String = conn
            .query_row(
                "SELECT params_json FROM jobs WHERE id = ?1",
                [&first.job_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!params_json.contains(&restore_token));
        assert!(!params_json.contains("password"));
    }

    #[test]
    fn auto_purge_enqueue_requires_opt_in_and_respects_due_items() {
        let (mut conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; auto purge enqueue test skipped");
            return;
        }
        let now = crate::auth::now_rfc3339();
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, write_enabled, protected, created_at, updated_at)
             VALUES ('source', 'source', 'source', 1, 0, ?1, ?1)",
            [&now],
        )
        .unwrap();
        let plan = simple_plan(&conn, &actor, &source, &journal);
        let quarantine_token = create_reauth_token(&conn, &actor, 5).unwrap();
        let action = execute_quarantine(
            &conn,
            &plan.id,
            &quarantine_token,
            QUARANTINE_CONFIRMATION,
            "auto-purge-quarantine",
            &gate(&source),
            &roots(&source, &journal),
            b"key",
        )
        .unwrap();
        let item_id = action.items[0].id.clone();
        conn.execute(
            "UPDATE cleanup_items SET updated_at = '2000-01-01T00:00:00.000Z' WHERE id = ?1",
            [&item_id],
        )
        .unwrap();

        assert_eq!(
            enqueue_due_auto_purges(&mut conn, &retention::QuarantineAutoPurgePolicy::default(),)
                .unwrap(),
            0
        );
        let policy = retention::QuarantineAutoPurgePolicy {
            enabled: true,
            min_keep_days: 7,
        };
        assert_eq!(enqueue_due_auto_purges(&mut conn, &policy).unwrap(), 1);
        assert_eq!(enqueue_due_auto_purges(&mut conn, &policy).unwrap(), 0);
        let queued: (String, String, String) = conn
            .query_row(
                "SELECT state, idempotency_key, json_extract(params_json, '$.action')
                 FROM jobs
                 WHERE json_extract(params_json, '$.item_id') = ?1
                   AND json_extract(params_json, '$.action') = 'auto_purge'",
                [&item_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(queued.0, "QUEUED");
        assert_eq!(queued.1, format!("auto-purge:{}:{}", action.id, item_id));
        assert_eq!(queued.2, "auto_purge");
        assert!(
            retention::validate_quarantine_auto_purge(&retention::QuarantineAutoPurgePolicy {
                enabled: true,
                min_keep_days: 6,
            })
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn auto_purge_due_job_runs_through_worker_and_purges_item() {
        let data_tmp = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(data_tmp.path().as_os_str()).unwrap();
        assert!(source.caps().supports_safe_writes());

        let db_path = data_tmp.path().join("control.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let admin = create_admin(&conn, "admin", "a sufficiently long password").unwrap();
        let now = auth::now_rfc3339();
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, write_enabled, protected, created_at, updated_at)
             VALUES ('source', 'source', 'source', 1, 0, ?1, ?1)",
            [&now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at)
             VALUES ('cleanup_signing_key', ?1, ?2)",
            params![serde_json::to_string(&hex::encode(b"key")).unwrap(), now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at)
             VALUES ('retention', ?1, ?2)",
            params![
                serde_json::json!({
                    "default_report_keep_count": 30,
                    "default_detail_keep_count": 30,
                    "quarantine_auto_purge": {
                        "enabled": true,
                        "min_keep_days": 7
                    }
                })
                .to_string(),
                auth::now_rfc3339()
            ],
        )
        .unwrap();

        let plan = simple_plan(&conn, &admin.id, &source, &journal);
        let reauth = create_reauth_token(&conn, &admin.id, 5).unwrap();
        let action = execute_quarantine(
            &conn,
            &plan.id,
            &reauth,
            QUARANTINE_CONFIRMATION,
            "auto-purge-worker-lifecycle",
            &gate(&source),
            &roots(&source, &journal),
            b"key",
        )
        .unwrap();
        let item_id = action.items[0].id.clone();
        let quarantine = quarantine_path(&action.id, &item_id);

        let enabled_policy = retention::QuarantineAutoPurgePolicy {
            enabled: true,
            min_keep_days: 7,
        };
        assert_eq!(
            enqueue_due_auto_purges(&mut conn, &retention::QuarantineAutoPurgePolicy::default())
                .unwrap(),
            0
        );
        assert_eq!(
            enqueue_due_auto_purges(&mut conn, &enabled_policy).unwrap(),
            0
        );

        conn.execute(
            "UPDATE cleanup_items SET updated_at = '2000-01-01T00:00:00.000Z' WHERE id = ?1",
            [&item_id],
        )
        .unwrap();
        assert_eq!(
            enqueue_due_auto_purges(&mut conn, &enabled_policy).unwrap(),
            1
        );

        let claimed = jobs::claim_next_operation(&mut conn).unwrap().unwrap();
        assert_eq!(claimed.job_type, JobType::CleanupAction);
        assert_eq!(claimed.state, JobState::Running);
        assert_eq!(claimed.params_json["action"], "auto_purge");
        drop(conn);

        let config = recovery_config(data_tmp.path(), source_tmp.path());
        let guard = crate::store::DbWriter::spawn(&db_path, true).unwrap();
        let writer = guard.writer.clone();
        run_job(writer.clone(), &config, &claimed).unwrap();

        let job_id = claimed.id.clone();
        let plan_id = plan.id.clone();
        let stored = writer
            .call_blocking(move |conn| {
                let job_state: String = conn
                    .query_row("SELECT state FROM jobs WHERE id = ?1", [&job_id], |row| {
                        row.get(0)
                    })
                    .unwrap();
                let plan_state: String = conn
                    .query_row(
                        "SELECT state FROM cleanup_plans WHERE id = ?1",
                        [&plan_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                let item: (String, Option<Vec<u8>>, Option<String>, i64) = conn
                    .query_row(
                        "SELECT state, raw_quarantine_path, error, journal_seq
                         FROM cleanup_items WHERE id = ?1",
                        [&item_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .unwrap();
                let completion_events: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM job_events
                         WHERE job_id = ?1 AND type = 'job.completed'",
                        [&job_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                Ok((job_state, plan_state, item, completion_events))
            })
            .unwrap();
        drop(writer);
        guard.shutdown();

        assert_eq!(stored.0, "SUCCEEDED");
        assert_eq!(stored.1, "completed");
        assert_eq!(stored.2.0, "PURGED");
        assert_eq!(stored.2.1, None);
        assert_eq!(stored.2.2, None);
        assert!(stored.2.3 > 0);
        assert_eq!(stored.3, 1);
        assert!(source_tmp.path().join("keep").exists());
        assert!(!source_tmp.path().join("target").exists());
        assert!(matches!(
            source.stat(raw_path(&quarantine)),
            Err(FsSecureError::NotFound)
        ));
    }

    #[test]
    fn recover_action_reconciles_after_move_before_state_commit() {
        let (conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; recovery test skipped");
            return;
        }

        let plan = simple_plan(&conn, &actor, &source, &journal);
        let roots = roots(&source, &journal);
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let action = execute_quarantine(
            &conn,
            &plan.id,
            &token,
            QUARANTINE_CONFIRMATION,
            "idempotency-recovery",
            &gate(&source),
            &roots,
            b"key",
        )
        .unwrap();

        let not_interrupted = recover_action(&conn, &action.id, &roots).unwrap_err();
        assert_eq!(not_interrupted.code, ErrorCode::JobStateConflict);
        let completed_state: String = conn
            .query_row(
                "SELECT state FROM jobs WHERE id = ?1",
                [&action.job_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(completed_state, "SUCCEEDED");
        conn.execute(
            "UPDATE cleanup_items SET state = 'MOVING' WHERE action_id = ?1",
            [&action.id],
        )
        .unwrap();
        conn.execute(
            "UPDATE jobs SET state = 'INTERRUPTED' WHERE id = ?1",
            [&action.job_id],
        )
        .unwrap();

        let recovered = recover_action(&conn, &action.id, &roots).unwrap();
        assert_eq!(recovered.state, "interrupted");
        let job_state: String = conn
            .query_row(
                "SELECT state FROM jobs WHERE id = ?1",
                [&action.job_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(job_state, "INTERRUPTED");
        assert_eq!(recovered.items[0].state, CleanupItemState::Quarantined);
        assert!(!source_tmp.path().join("target").exists());
        assert!(
            source_tmp
                .path()
                .join(format!(
                    ".nas-analyzer-quarantine/{}/{}",
                    action.id, action.items[0].id
                ))
                .exists()
        );
    }

    #[cfg(target_os = "linux")]
    fn prepare_interrupted_restore(
        destination: &[u8],
        write_after_restore: bool,
        replace_destination: bool,
    ) -> (
        Connection,
        tempfile::TempDir,
        tempfile::TempDir,
        SecureRoot,
        SecureRoot,
        CleanupAction,
    ) {
        let (conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            panic!("safe write capability unavailable");
        }
        let plan = simple_plan(&conn, &actor, &source, &journal);
        let roots = roots(&source, &journal);
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let action = execute_quarantine(
            &conn,
            &plan.id,
            &token,
            QUARANTINE_CONFIRMATION,
            "restore-recovery-quarantine",
            &gate(&source),
            &roots,
            b"key",
        )
        .unwrap();
        let item = load_item(&conn, &action.items[0].id).unwrap();
        let quarantine = item.quarantine_path.clone().unwrap();
        let events = read_journal(&journal, &action.id).unwrap();
        let before_sequence = next_journal_sequence(&events, item.journal_seq).unwrap();
        let after_sequence = before_sequence.checked_add(1).unwrap();
        write_journal(
            &journal,
            &action.id,
            before_sequence,
            "before_restore",
            &item.id,
            destination,
            Some(&quarantine),
        )
        .unwrap();
        source
            .rename_noreplace(raw_path(&quarantine), raw_path(destination))
            .unwrap();
        sync_move_directories(&source, &quarantine, destination).unwrap();
        if write_after_restore {
            write_journal(
                &journal,
                &action.id,
                after_sequence,
                "after_restore",
                &item.id,
                destination,
                None,
            )
            .unwrap();
        }
        if replace_destination {
            fs::remove_file(
                source_tmp
                    .path()
                    .join(std::ffi::OsStr::from_bytes(destination)),
            )
            .unwrap();
            fs::write(
                source_tmp
                    .path()
                    .join(std::ffi::OsStr::from_bytes(destination)),
                b"replacement",
            )
            .unwrap();
        }
        conn.execute(
            "UPDATE jobs SET state = 'INTERRUPTED' WHERE id = ?1",
            [&action.job_id],
        )
        .unwrap();
        (conn, source_tmp, journal_tmp, source, journal, action)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_marks_restored_only_after_destination_identity_matches() {
        let (conn, source_tmp, _journal_tmp, source, journal, action) =
            prepare_interrupted_restore(b"restored", false, false);
        let recovered = recover_action(&conn, &action.id, &roots(&source, &journal)).unwrap();
        assert_eq!(recovered.items[0].state, CleanupItemState::Restored);
        let stored: (String, Option<Vec<u8>>, Option<String>) = conn
            .query_row(
                "SELECT state, raw_quarantine_path, error FROM cleanup_items WHERE id = ?1",
                [&action.items[0].id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(stored.0, "RESTORED");
        assert!(stored.1.is_none());
        assert!(stored.2.is_none());
        assert!(source_tmp.path().join("restored").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_keeps_replaced_restore_target_in_conflict() {
        let (conn, source_tmp, _journal_tmp, source, journal, action) =
            prepare_interrupted_restore(b"restored", true, true);
        let recovered = recover_action(&conn, &action.id, &roots(&source, &journal)).unwrap();
        assert_eq!(recovered.items[0].state, CleanupItemState::Conflict);
        let stored: (String, Option<Vec<u8>>, Option<String>) = conn
            .query_row(
                "SELECT state, raw_quarantine_path, error FROM cleanup_items WHERE id = ?1",
                [&action.items[0].id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(stored.0, "CONFLICT");
        assert!(stored.1.is_some());
        assert!(stored.2.is_some());
        assert_eq!(
            fs::read(source_tmp.path().join("restored")).unwrap(),
            b"replacement"
        );
        let job_state: String = conn
            .query_row(
                "SELECT state FROM jobs WHERE id = ?1",
                [&action.job_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(job_state, "INTERRUPTED");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_rejects_a_residual_replacement_alongside_a_restored_target() {
        let (conn, source_tmp, _journal_tmp, source, journal, action) =
            prepare_interrupted_restore(b"restored", true, false);
        let item = load_item(&conn, &action.items[0].id).unwrap();
        let quarantine = item.quarantine_path.clone().unwrap();
        fs::write(
            source_tmp
                .path()
                .join(std::ffi::OsStr::from_bytes(&quarantine)),
            b"replacement",
        )
        .unwrap();
        let events = read_journal(&journal, &action.id).unwrap();
        let decision =
            reconcile_recovery_item(&action.id, &source, &item, &events, Some(b"restored"))
                .unwrap();
        assert!(matches!(
            decision,
            RecoveryDecision::Update {
                state: CleanupItemState::Conflict,
                ..
            }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_rejects_a_residual_quarantine_after_restore_completion() {
        let (conn, source_tmp, _journal_tmp, source, journal, action) =
            prepare_interrupted_restore(b"restored", true, false);
        let item = load_item(&conn, &action.items[0].id).unwrap();
        let quarantine = item.quarantine_path.as_deref().unwrap();
        std::fs::hard_link(
            source_tmp.path().join("restored"),
            source_tmp
                .path()
                .join(std::ffi::OsStr::from_bytes(quarantine)),
        )
        .unwrap();
        let recovered = recover_action(&conn, &action.id, &roots(&source, &journal)).unwrap();

        assert_eq!(recovered.items[0].state, CleanupItemState::Conflict);
        assert!(source_tmp.path().join("restored").exists());
        assert!(item.quarantine_path.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quarantined_retry_requires_completed_move_journal() {
        let (conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; quarantined retry test skipped");
            return;
        }
        let plan = simple_plan(&conn, &actor, &source, &journal);
        let roots = roots(&source, &journal);
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let action = execute_quarantine(
            &conn,
            &plan.id,
            &token,
            QUARANTINE_CONFIRMATION,
            "quarantined-retry-journal",
            &gate(&source),
            &roots,
            b"key",
        )
        .unwrap();
        let item = load_item(&conn, &action.items[0].id).unwrap();
        let journal_path = journal_tmp
            .path()
            .join(format!("actions/{}/journal/journal.jsonl", action.id));
        let first_record = fs::read_to_string(&journal_path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_owned();
        fs::write(&journal_path, format!("{first_record}\n")).unwrap();
        let events = read_journal(&journal, &action.id).unwrap();
        let error = validate_quarantined_item(&action.id, &source, &item, &events).unwrap_err();

        assert_eq!(error.code, ErrorCode::QuarantineConflict);
        assert!(
            source
                .stat(raw_path(item.quarantine_path.as_deref().unwrap()))
                .is_ok()
        );
        assert_eq!(
            load_item(&conn, &item.id).unwrap().state,
            CleanupItemState::Quarantined
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn purge_requires_before_move_evidence_in_addition_to_after_move() {
        let (conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        assert!(source.caps().supports_safe_writes());
        let roots = roots(&source, &journal);
        let plan = simple_plan(&conn, &actor, &source, &journal);
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let action = execute_quarantine(
            &conn,
            &plan.id,
            &token,
            QUARANTINE_CONFIRMATION,
            "purge-before-move",
            &gate(&source),
            &roots,
            b"key",
        )
        .unwrap();
        let item = load_item(&conn, &action.items[0].id).unwrap();
        let quarantine = item.quarantine_path.unwrap();
        let journal_path = journal_tmp
            .path()
            .join(format!("actions/{}/journal/journal.jsonl", action.id));
        let forged_after_move = serde_json::json!({
            "seq": 1,
            "event": "after_move",
            "item_id": &item.id,
            "original_path_b64": base64::engine::general_purpose::STANDARD.encode(&item.original_path),
            "quarantine_path_b64": base64::engine::general_purpose::STANDARD.encode(&quarantine),
        });
        fs::write(&journal_path, format!("{}\n", forged_after_move)).unwrap();

        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let error = purge(
            &conn,
            &item.id,
            &token,
            PURGE_CONFIRMATION,
            b"key",
            &gate(&source),
            &roots,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuarantineConflict);
        assert!(source.stat(raw_path(&quarantine)).is_ok());
    }

    #[test]
    fn recovery_does_not_mark_purge_success_without_after_purge_log() {
        let (conn, actor) = db();
        let source_tmp = tempfile::tempdir().unwrap();
        let journal_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(journal_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; purge recovery test skipped");
            return;
        }
        let plan = simple_plan(&conn, &actor, &source, &journal);
        let roots = roots(&source, &journal);
        let token = create_reauth_token(&conn, &actor, 5).unwrap();
        let action = execute_quarantine(
            &conn,
            &plan.id,
            &token,
            QUARANTINE_CONFIRMATION,
            "purge-recovery-quarantine",
            &gate(&source),
            &roots,
            b"key",
        )
        .unwrap();
        let item = load_item(&conn, &action.items[0].id).unwrap();
        let quarantine = item.quarantine_path.clone().unwrap();
        let events = read_journal(&journal, &action.id).unwrap();
        let before_sequence = next_journal_sequence(&events, item.journal_seq).unwrap();
        write_journal(
            &journal,
            &action.id,
            before_sequence,
            "before_purge",
            &item.id,
            &item.original_path,
            Some(&quarantine),
        )
        .unwrap();
        source.unlink_file(raw_path(&quarantine)).unwrap();
        source
            .fsync_dir(OsStr::from_bytes(&parent_path(&quarantine)))
            .unwrap();
        conn.execute(
            "UPDATE jobs SET state = 'INTERRUPTED' WHERE id = ?1",
            [&action.job_id],
        )
        .unwrap();

        let recovered = recover_action(&conn, &action.id, &roots).unwrap();
        assert_eq!(recovered.items[0].state, CleanupItemState::Conflict);
        let stored: (String, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT state, raw_quarantine_path FROM cleanup_items WHERE id = ?1",
                [&action.items[0].id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored.0, "CONFLICT");
        assert_eq!(stored.1.as_deref(), Some(quarantine.as_slice()));
    }

    #[test]
    fn recover_pending_reconciles_file_sqlite_and_keeps_interrupted_job_visible() {
        let data_tmp = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("target"), b"recovery content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; writer recovery test skipped");
            return;
        }
        let journal = SecureRoot::open(data_tmp.path().as_os_str()).unwrap();
        let target_stat = source.stat(OsStr::new("target")).unwrap();
        let target_file = source
            .open_file(OsStr::new("target"), OpenOptions::default())
            .unwrap();
        let identity = FileStamp::from_stat(&target_stat);
        let digest = digest_opened(&target_file).unwrap();
        let expected_digest = digest.clone();
        let action_id = "recovery-action";
        let item_id = "recovery-item";
        let plan_id = "recovery-plan";
        let job_id = "recovery-job";
        let quarantine = quarantine_path(action_id, item_id);

        let quarantine_dir = ensure_quarantine_directory(&source, action_id).unwrap();
        source.fsync_dir(&quarantine_dir).unwrap();
        write_journal(
            &journal,
            action_id,
            1,
            "before_move",
            item_id,
            b"target",
            Some(&quarantine),
        )
        .unwrap();
        source
            .rename_noreplace(raw_path(b"target"), raw_path(&quarantine))
            .unwrap();
        sync_move_directories(&source, b"target", &quarantine).unwrap();
        write_journal(
            &journal,
            action_id,
            2,
            "after_move",
            item_id,
            b"target",
            Some(&quarantine),
        )
        .unwrap();

        let db_path = data_tmp.path().join("control.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let identity_json = serde_json::to_string(&identity).unwrap();
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, write_enabled, protected, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, 0, ?4, ?4)",
            params!["source", "source", "source", "2026-09-12T00:00:00Z"],
        )
        .unwrap();
        mark_test_source_identity(&conn, &source);
        conn.execute(
            "INSERT INTO cleanup_plans
             (id, report_id, payload_json, payload_sig, expires_at, actor_id, state, created_at)
             VALUES (?1, ?2, '{}', '', ?3, ?4, 'executing', ?3)",
            params![plan_id, "report", "2099-01-01T00:00:00Z", "actor"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cleanup_items
             (id, plan_id, action_id, entry_ref, source_id, raw_original_path,
              raw_quarantine_path, identity_json, content_sha256, state, journal_seq,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, '2', ?4, ?5, ?6, ?7, ?8, 'MOVING', 2, ?9, ?9)",
            params![
                item_id,
                plan_id,
                action_id,
                "source",
                b"target".as_slice(),
                quarantine.as_slice(),
                identity_json,
                digest,
                "2026-09-12T00:00:00Z",
            ],
        )
        .unwrap();
        let job_params = serde_json::json!({
            "action": "quarantine",
            "action_id": action_id,
            "plan_id": plan_id,
            "actor_id": "actor",
        });
        conn.execute(
            "INSERT INTO jobs
             (id, type, state, params_json, requested_at, started_at, finished_at,
              heartbeat_at, error_json)
             VALUES (?1, 'cleanup', 'INTERRUPTED', ?2, ?3, ?3, ?3, ?3, ?4)",
            params![
                job_id,
                job_params.to_string(),
                "2026-09-12T00:00:00Z",
                serde_json::json!({"code": "INTERRUPTED"}).to_string(),
            ],
        )
        .unwrap();
        drop(conn);

        let config = recovery_config(data_tmp.path(), source_tmp.path());
        let guard = crate::store::DbWriter::spawn(&db_path, true).unwrap();
        let writer = guard.writer.clone();
        assert_eq!(recover_pending(writer.clone(), &config).unwrap(), 1);
        let stored = writer
            .call_blocking(move |conn| {
                let item: (String, Option<Vec<u8>>) = conn
                    .query_row(
                        "SELECT state, raw_quarantine_path FROM cleanup_items WHERE id = ?1",
                        [item_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                let job_state: String = conn
                    .query_row("SELECT state FROM jobs WHERE id = ?1", [job_id], |row| {
                        row.get(0)
                    })
                    .unwrap();
                let plan_state: String = conn
                    .query_row(
                        "SELECT state FROM cleanup_plans WHERE id = ?1",
                        [plan_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                Ok((item, job_state, plan_state))
            })
            .unwrap();
        drop(writer);
        guard.shutdown();

        assert_eq!(stored.0.0, "QUARANTINED");
        assert_eq!(stored.0.1.as_deref(), Some(quarantine.as_slice()));
        assert_eq!(stored.1, "INTERRUPTED");
        assert_eq!(stored.2, "executing");
        assert!(matches!(
            source.stat(OsStr::new("target")),
            Err(FsSecureError::NotFound)
        ));
        let isolated = source.stat(raw_path(&quarantine)).unwrap();
        assert!(FileStamp::from_stat(&isolated).matches_after_rename(&identity));
        let isolated_file = source
            .open_file(raw_path(&quarantine), OpenOptions::default())
            .unwrap();
        assert_eq!(digest_opened(&isolated_file).unwrap(), expected_digest);
    }

    #[test]
    fn recovery_does_not_skip_interrupted_cleanup_without_items() {
        let data_tmp = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        let db_path = data_tmp.path().join("control.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        conn.execute(
            "INSERT INTO cleanup_plans
             (id, report_id, payload_json, payload_sig, expires_at, actor_id, state, created_at)
             VALUES ('orphan-plan', 'report', '{}', '', '2099-01-01T00:00:00Z', 'actor',
                     'executing', '2026-09-13T00:00:00Z')",
            [],
        )
        .unwrap();
        let job_params = serde_json::json!({
            "action": "quarantine",
            "action_id": "orphan-action",
            "plan_id": "orphan-plan",
            "actor_id": "actor"
        });
        conn.execute(
            "INSERT INTO jobs (id, type, state, params_json, requested_at, error_json)
             VALUES (?1, 'cleanup', 'INTERRUPTED', ?2, ?3, ?4)",
            params![
                "orphan-job",
                job_params.to_string(),
                "2026-09-13T00:00:00Z",
                serde_json::json!({"code": "INTERRUPTED"}).to_string(),
            ],
        )
        .unwrap();
        drop(conn);

        let config = recovery_config(data_tmp.path(), source_tmp.path());
        let guard = crate::store::DbWriter::spawn(&db_path, true).unwrap();
        let writer = guard.writer.clone();
        let error = recover_pending(writer.clone(), &config).unwrap_err();
        assert_eq!(error.code, ErrorCode::JobStateConflict);
        let state = writer
            .call_blocking(|conn| {
                conn.query_row(
                    "SELECT state FROM jobs WHERE id = 'orphan-job'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .map_err(db_error)
            })
            .unwrap();
        drop(writer);
        guard.shutdown();

        assert_eq!(state, "INTERRUPTED");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn queued_cleanup_job_runs_through_claim_and_cleanup_runner() {
        let data_tmp = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(data_tmp.path().as_os_str()).unwrap();
        assert!(source.caps().supports_safe_writes());

        let db_path = data_tmp.path().join("control.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let admin = create_admin(&conn, "admin", "a sufficiently long password").unwrap();
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, write_enabled, protected, created_at, updated_at)
             VALUES ('source', 'source', 'source', 1, 0, ?1, ?1)",
            [&auth::now_rfc3339()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at)
             VALUES ('cleanup_signing_key', ?1, ?2)",
            params![
                serde_json::to_string(&hex::encode(b"key")).unwrap(),
                auth::now_rfc3339()
            ],
        )
        .unwrap();
        let plan = simple_plan(&conn, &admin.id, &source, &journal);
        let reauth = create_reauth_token(&conn, &admin.id, 5).unwrap();
        let reservation = reserve_quarantine(
            &mut conn,
            &plan.id,
            &admin.id,
            &reauth,
            QUARANTINE_CONFIRMATION,
            "supervisor-queue-key",
            b"key",
        )
        .unwrap();
        let queued_state: String = conn
            .query_row(
                "SELECT state FROM jobs WHERE id = ?1",
                [&reservation.job_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(queued_state, "QUEUED");
        let item_id: String = conn
            .query_row(
                "SELECT id FROM cleanup_items WHERE action_id = ?1",
                [&reservation.action_id],
                |row| row.get(0),
            )
            .unwrap();
        drop(conn);

        let config = recovery_config(data_tmp.path(), source_tmp.path());
        let guard = crate::store::DbWriter::spawn(&db_path, true).unwrap();
        let writer = guard.writer.clone();
        let claimed = writer
            .call_blocking(jobs::claim_next_operation)
            .unwrap()
            .unwrap();
        assert_eq!(claimed.id, reservation.job_id);
        assert_eq!(claimed.job_type, JobType::CleanupAction);
        assert_eq!(claimed.state, JobState::Running);

        run_job(writer.clone(), &config, &claimed).unwrap();
        let job_id = reservation.job_id.clone();
        let action_id = reservation.action_id.clone();
        let plan_id = plan.id.clone();
        let stored = writer
            .call_blocking(move |conn| {
                let job_state: String = conn
                    .query_row("SELECT state FROM jobs WHERE id = ?1", [&job_id], |row| {
                        row.get(0)
                    })
                    .unwrap();
                let plan_state: String = conn
                    .query_row(
                        "SELECT state FROM cleanup_plans WHERE id = ?1",
                        [&plan_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                let item_state: String = conn
                    .query_row(
                        "SELECT state FROM cleanup_items WHERE action_id = ?1",
                        [&action_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                Ok((job_state, plan_state, item_state))
            })
            .unwrap();
        drop(writer);
        guard.shutdown();

        assert_eq!(stored.0, "SUCCEEDED");
        assert_eq!(stored.1, "completed");
        assert_eq!(stored.2, "QUARANTINED");
        assert!(!source_tmp.path().join("target").exists());
        assert!(
            source_tmp
                .path()
                .join(format!(
                    ".nas-analyzer-quarantine/{}/{}",
                    reservation.action_id, item_id
                ))
                .exists()
        );
    }

    #[test]
    fn queued_restore_job_runs_through_claim_and_cleanup_runner() {
        let data_tmp = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(data_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; queued restore test skipped");
            return;
        }

        let db_path = data_tmp.path().join("control.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let admin = create_admin(&conn, "admin", "a sufficiently long password").unwrap();
        let now = auth::now_rfc3339();
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, write_enabled, protected, created_at, updated_at)
             VALUES ('source', 'source', 'source', 1, 0, ?1, ?1)",
            [&now],
        )
        .unwrap();
        mark_test_source_identity(&conn, &source);
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at)
             VALUES ('cleanup_signing_key', ?1, ?2)",
            params![serde_json::to_string(&hex::encode(b"key")).unwrap(), now],
        )
        .unwrap();
        let plan = simple_plan(&conn, &admin.id, &source, &journal);
        let quarantine_token = create_reauth_token(&conn, &admin.id, 5).unwrap();
        let quarantine = reserve_quarantine(
            &mut conn,
            &plan.id,
            &admin.id,
            &quarantine_token,
            QUARANTINE_CONFIRMATION,
            "supervisor-restore-quarantine",
            b"key",
        )
        .unwrap();
        drop(conn);

        let config = recovery_config(data_tmp.path(), source_tmp.path());
        let guard = crate::store::DbWriter::spawn(&db_path, true).unwrap();
        let writer = guard.writer.clone();
        let quarantine_job = writer
            .call_blocking(jobs::claim_next_operation)
            .unwrap()
            .unwrap();
        assert_eq!(quarantine_job.id, quarantine.job_id);
        run_job(writer.clone(), &config, &quarantine_job).unwrap();

        let action_id = quarantine.action_id.clone();
        let item_id = writer
            .call_blocking(move |conn| {
                conn.query_row(
                    "SELECT id FROM cleanup_items WHERE action_id = ?1",
                    [&action_id],
                    |row| row.get::<_, String>(0),
                )
                .map_err(db_error)
            })
            .unwrap();
        let admin_id = admin.id.clone();
        let restore_item_id = item_id.clone();
        let restore_reservation = writer
            .call_blocking(move |conn| {
                let token = create_reauth_token(conn, &admin_id, 5)?;
                reserve_restore(
                    conn,
                    &restore_item_id,
                    &admin_id,
                    &token,
                    Some(b"restored"),
                    "supervisor-restore-key",
                )
            })
            .unwrap();
        let restore_job = writer
            .call_blocking(jobs::claim_next_operation)
            .unwrap()
            .unwrap();
        assert_eq!(restore_job.id, restore_reservation.job_id);
        assert_eq!(restore_job.job_type, JobType::CleanupAction);
        assert_eq!(restore_job.state, JobState::Running);
        assert_eq!(restore_job.params_json["action"], "restore");

        run_job(writer.clone(), &config, &restore_job).unwrap();

        let restore_job_id = restore_job.id.clone();
        let final_item_id = item_id.clone();
        let final_state = writer
            .call_blocking(move |conn| {
                let job_state: String = conn
                    .query_row(
                        "SELECT state FROM jobs WHERE id = ?1",
                        [&restore_job_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                let item: (String, Option<Vec<u8>>) = conn
                    .query_row(
                        "SELECT state, raw_quarantine_path FROM cleanup_items WHERE id = ?1",
                        [&final_item_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                Ok((job_state, item.0, item.1))
            })
            .unwrap();
        drop(writer);
        guard.shutdown();

        assert_eq!(final_state.0, "SUCCEEDED");
        assert_eq!(final_state.1, "RESTORED");
        assert_eq!(final_state.2, None);
        assert!(source_tmp.path().join("restored").exists());
        assert!(!source_tmp.path().join("target").exists());
        assert!(
            !source_tmp
                .path()
                .join(format!(
                    ".nas-analyzer-quarantine/{}/{}",
                    quarantine.action_id, item_id
                ))
                .exists()
        );
    }

    #[test]
    fn cancelling_claimed_cleanup_job_finishes_cancelled_before_source_mutation() {
        let data_tmp = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(data_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; cancellation test skipped");
            return;
        }

        let db_path = data_tmp.path().join("control.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let admin = create_admin(&conn, "admin", "a sufficiently long password").unwrap();
        let now = auth::now_rfc3339();
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, write_enabled, protected, created_at, updated_at)
             VALUES ('source', 'source', 'source', 1, 0, ?1, ?1)",
            [&now],
        )
        .unwrap();
        mark_test_source_identity(&conn, &source);
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at)
             VALUES ('cleanup_signing_key', ?1, ?2)",
            params![serde_json::to_string(&hex::encode(b"key")).unwrap(), now],
        )
        .unwrap();
        let plan = simple_plan(&conn, &admin.id, &source, &journal);
        let reauth = create_reauth_token(&conn, &admin.id, 5).unwrap();
        let reservation = reserve_quarantine(
            &mut conn,
            &plan.id,
            &admin.id,
            &reauth,
            QUARANTINE_CONFIRMATION,
            "supervisor-cancel-key",
            b"key",
        )
        .unwrap();
        drop(conn);

        let config = recovery_config(data_tmp.path(), source_tmp.path());
        let guard = crate::store::DbWriter::spawn(&db_path, true).unwrap();
        let writer = guard.writer.clone();
        let claimed = writer
            .call_blocking(jobs::claim_next_operation)
            .unwrap()
            .unwrap();
        let job_id = claimed.id.clone();
        writer
            .call_blocking(move |conn| {
                jobs::control_job(conn, &job_id, jobs::JobControlAction::Cancel).map(|_| ())
            })
            .unwrap();
        run_job(writer.clone(), &config, &claimed).unwrap();

        let job_id = reservation.job_id.clone();
        let plan_id = plan.id.clone();
        let action_id = reservation.action_id.clone();
        let stored = writer
            .call_blocking(move |conn| {
                let job_state: String = conn
                    .query_row("SELECT state FROM jobs WHERE id = ?1", [&job_id], |row| {
                        row.get(0)
                    })
                    .unwrap();
                let plan_state: String = conn
                    .query_row(
                        "SELECT state FROM cleanup_plans WHERE id = ?1",
                        [&plan_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                let item_state: String = conn
                    .query_row(
                        "SELECT state FROM cleanup_items WHERE action_id = ?1",
                        [&action_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                Ok((job_state, plan_state, item_state))
            })
            .unwrap();
        drop(writer);
        guard.shutdown();

        assert_eq!(stored.0, "CANCELLED");
        assert_eq!(stored.1, "executing");
        assert_eq!(stored.2, "PLANNED");
        assert!(source_tmp.path().join("target").exists());
        assert!(!source_tmp.path().join(".nas-analyzer-quarantine").exists());
    }

    #[test]
    fn cancelling_cleanup_between_items_leaves_the_next_item_unmoved() {
        let data_tmp = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target-a"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target-b"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(data_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!(
                "note: safe write capability unavailable; mid-action cancellation test skipped"
            );
            return;
        }

        let db_path = data_tmp.path().join("control.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let admin = create_admin(&conn, "admin", "a sufficiently long password").unwrap();
        let now = auth::now_rfc3339();
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, write_enabled, protected, created_at, updated_at)
             VALUES ('source', 'source', 'source', 1, 0, ?1, ?1)",
            [&now],
        )
        .unwrap();
        mark_test_source_identity(&conn, &source);
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at)
             VALUES ('cleanup_signing_key', ?1, ?2)",
            params![serde_json::to_string(&hex::encode(b"key")).unwrap(), now],
        )
        .unwrap();
        let plan = preview(
            &conn,
            "report",
            &admin.id,
            &[CleanupGroupSelection {
                group_id: String::from("g"),
                members: vec![
                    entry(&source, 1, b"keep", "g"),
                    entry(&source, 2, b"target-a", "g"),
                    entry(&source, 3, b"target-b", "g"),
                ],
                keep_entry_ids: vec![1],
                target_entry_ids: vec![2, 3],
            }],
            &roots(&source, &journal),
            b"key",
        )
        .unwrap();
        let reauth = create_reauth_token(&conn, &admin.id, 5).unwrap();
        let reservation = reserve_quarantine(
            &mut conn,
            &plan.id,
            &admin.id,
            &reauth,
            QUARANTINE_CONFIRMATION,
            "supervisor-mid-action-cancel-key",
            b"key",
        )
        .unwrap();
        let trigger_sql = format!(
            "CREATE TRIGGER cancel_cleanup_after_first_item
             AFTER UPDATE OF state ON cleanup_items
             WHEN NEW.state = 'QUARANTINED'
             BEGIN
                 UPDATE jobs SET state = 'CANCELLING'
                 WHERE id = '{}' AND state = 'RUNNING';
             END;",
            reservation.job_id
        );
        conn.execute_batch(&trigger_sql).unwrap();
        drop(conn);

        let config = recovery_config(data_tmp.path(), source_tmp.path());
        let guard = crate::store::DbWriter::spawn(&db_path, true).unwrap();
        let writer = guard.writer.clone();
        let claimed = writer
            .call_blocking(jobs::claim_next_operation)
            .unwrap()
            .unwrap();
        run_job(writer.clone(), &config, &claimed).unwrap();

        let job_id = reservation.job_id.clone();
        let plan_id = plan.id.clone();
        let action_id = reservation.action_id.clone();
        let stored = writer
            .call_blocking(move |conn| {
                let job_state: String = conn
                    .query_row("SELECT state FROM jobs WHERE id = ?1", [&job_id], |row| {
                        row.get(0)
                    })
                    .unwrap();
                let plan_state: String = conn
                    .query_row(
                        "SELECT state FROM cleanup_plans WHERE id = ?1",
                        [&plan_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                let mut statement = conn
                    .prepare(
                        "SELECT state FROM cleanup_items
                         WHERE action_id = ?1 ORDER BY entry_ref",
                    )
                    .unwrap();
                let item_states = statement
                    .query_map([&action_id], |row| row.get::<_, String>(0))
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                Ok((job_state, plan_state, item_states))
            })
            .unwrap();
        drop(writer);
        guard.shutdown();

        assert_eq!(stored.0, "CANCELLED");
        assert_eq!(stored.1, "executing");
        assert_eq!(stored.2.len(), 2);
        assert_eq!(
            stored
                .2
                .iter()
                .filter(|state| state.as_str() == "QUARANTINED")
                .count(),
            1
        );
        assert_eq!(
            stored
                .2
                .iter()
                .filter(|state| state.as_str() == "VALIDATING")
                .count(),
            1
        );
        assert!(
            source_tmp.path().join("target-a").exists()
                ^ source_tmp.path().join("target-b").exists()
        );
    }

    #[test]
    fn cancelling_after_last_cleanup_item_keeps_plan_executing() {
        let data_tmp = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(data_tmp.path().as_os_str()).unwrap();
        if !source.caps().supports_safe_writes() {
            eprintln!(
                "note: safe write capability unavailable; last-item cancellation test skipped"
            );
            return;
        }

        let db_path = data_tmp.path().join("control.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let admin = create_admin(&conn, "admin", "a sufficiently long password").unwrap();
        let now = auth::now_rfc3339();
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, write_enabled, protected, created_at, updated_at)
             VALUES ('source', 'source', 'source', 1, 0, ?1, ?1)",
            [&now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at)
             VALUES ('cleanup_signing_key', ?1, ?2)",
            params![serde_json::to_string(&hex::encode(b"key")).unwrap(), now],
        )
        .unwrap();
        let plan = simple_plan(&conn, &admin.id, &source, &journal);
        let reauth = create_reauth_token(&conn, &admin.id, 5).unwrap();
        let reservation = reserve_quarantine(
            &mut conn,
            &plan.id,
            &admin.id,
            &reauth,
            QUARANTINE_CONFIRMATION,
            "supervisor-last-item-cancel-key",
            b"key",
        )
        .unwrap();
        let item_id: String = conn
            .query_row(
                "SELECT id FROM cleanup_items WHERE action_id = ?1",
                [&reservation.action_id],
                |row| row.get(0),
            )
            .unwrap();
        let quarantine_path = source_tmp.path().join(format!(
            ".nas-analyzer-quarantine/{}/{}",
            reservation.action_id, item_id
        ));
        let trigger_sql = format!(
            "CREATE TRIGGER cancel_cleanup_after_last_item
             AFTER UPDATE OF state ON cleanup_items
             WHEN NEW.state = 'QUARANTINED'
             BEGIN
                 UPDATE jobs SET state = 'CANCELLING'
                 WHERE id = '{}' AND state = 'RUNNING';
             END;",
            reservation.job_id
        );
        conn.execute_batch(&trigger_sql).unwrap();
        drop(conn);

        let config = recovery_config(data_tmp.path(), source_tmp.path());
        let guard = crate::store::DbWriter::spawn(&db_path, true).unwrap();
        let writer = guard.writer.clone();
        let claimed = writer
            .call_blocking(jobs::claim_next_operation)
            .unwrap()
            .unwrap();
        run_job(writer.clone(), &config, &claimed).unwrap();

        let job_id = reservation.job_id.clone();
        let plan_id = plan.id.clone();
        let action_id = reservation.action_id.clone();
        let stored = writer
            .call_blocking(move |conn| {
                let job_state: String = conn
                    .query_row("SELECT state FROM jobs WHERE id = ?1", [&job_id], |row| {
                        row.get(0)
                    })
                    .unwrap();
                let plan_state: String = conn
                    .query_row(
                        "SELECT state FROM cleanup_plans WHERE id = ?1",
                        [&plan_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                let item_state: String = conn
                    .query_row(
                        "SELECT state FROM cleanup_items WHERE action_id = ?1",
                        [&action_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                Ok((job_state, plan_state, item_state))
            })
            .unwrap();
        drop(writer);
        guard.shutdown();

        assert_eq!(stored.0, "CANCELLED");
        assert_eq!(stored.1, "executing");
        assert_eq!(stored.2, "QUARANTINED");
        assert!(!source_tmp.path().join("target").exists());
        assert!(quarantine_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_retry_skips_quarantined_items_and_continues_journal() {
        let data_tmp = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target-a"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target-b"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(data_tmp.path().as_os_str()).unwrap();
        assert!(source.caps().supports_safe_writes());

        let db_path = data_tmp.path().join("control.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let admin = create_admin(&conn, "admin", "a sufficiently long password").unwrap();
        let now = auth::now_rfc3339();
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, write_enabled, protected, created_at, updated_at)
             VALUES ('source', 'source', 'source', 1, 0, ?1, ?1)",
            [&now],
        )
        .unwrap();
        mark_test_source_identity(&conn, &source);
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at)
             VALUES ('cleanup_signing_key', ?1, ?2)",
            params![serde_json::to_string(&hex::encode(b"key")).unwrap(), now],
        )
        .unwrap();
        let plan = preview(
            &conn,
            "report",
            &admin.id,
            &[CleanupGroupSelection {
                group_id: "group".to_owned(),
                members: vec![
                    entry(&source, 1, b"keep", "group"),
                    entry(&source, 2, b"target-a", "group"),
                    entry(&source, 3, b"target-b", "group"),
                ],
                keep_entry_ids: vec![1],
                target_entry_ids: vec![2, 3],
            }],
            &roots(&source, &journal),
            b"key",
        )
        .unwrap();
        let reauth = create_reauth_token(&conn, &admin.id, 5).unwrap();
        let reservation = reserve_quarantine(
            &mut conn,
            &plan.id,
            &admin.id,
            &reauth,
            QUARANTINE_CONFIRMATION,
            "retry-quarantined-item",
            b"key",
        )
        .unwrap();
        let target_a = load_items(&conn, Some(&reservation.action_id), &plan.id)
            .unwrap()
            .into_iter()
            .find(|item| item.entry_id == 2)
            .unwrap();
        let quarantine = quarantine_path(&reservation.action_id, &target_a.id);
        let quarantine_dir = ensure_quarantine_directory(&source, &reservation.action_id).unwrap();
        source.fsync_dir(&quarantine_dir).unwrap();
        write_journal(
            &journal,
            &reservation.action_id,
            1,
            "before_move",
            &target_a.id,
            &target_a.original_path,
            Some(&quarantine),
        )
        .unwrap();
        source
            .rename_noreplace(
                OsStr::from_bytes(b"target-a"),
                OsStr::from_bytes(&quarantine),
            )
            .unwrap();
        sync_move_directories(&source, b"target-a", &quarantine).unwrap();
        write_journal(
            &journal,
            &reservation.action_id,
            2,
            "after_move",
            &target_a.id,
            &target_a.original_path,
            Some(&quarantine),
        )
        .unwrap();
        update_item(
            &conn,
            &target_a.id,
            Some(&reservation.action_id),
            CleanupItemState::Quarantined,
            Some(&quarantine),
            2,
            None,
        )
        .unwrap();
        conn.execute(
            "UPDATE jobs SET state = 'FAILED' WHERE id = ?1",
            [&reservation.job_id],
        )
        .unwrap();
        let retry = jobs::control_job(
            &mut conn,
            &reservation.job_id,
            jobs::JobControlAction::Retry,
        )
        .unwrap();
        let claimed = jobs::claim_next_operation(&mut conn).unwrap().unwrap();
        assert_eq!(claimed.id, retry.id);
        drop(conn);

        let config = recovery_config(data_tmp.path(), source_tmp.path());
        let guard = crate::store::DbWriter::spawn(&db_path, true).unwrap();
        let writer = guard.writer.clone();
        run_job(writer.clone(), &config, &claimed).unwrap();
        let stored = writer
            .call_blocking({
                let action_id = reservation.action_id.clone();
                let retry_id = retry.id.clone();
                let plan_id = plan.id.clone();
                move |conn| {
                    let job_state: String = conn
                        .query_row("SELECT state FROM jobs WHERE id = ?1", [&retry_id], |row| {
                            row.get(0)
                        })
                        .unwrap();
                    let plan_state: String = conn
                        .query_row(
                            "SELECT state FROM cleanup_plans WHERE id = ?1",
                            [&plan_id],
                            |row| row.get(0),
                        )
                        .unwrap();
                    let target_b: (String, i64, Option<Vec<u8>>) = conn
                        .query_row(
                            "SELECT state, journal_seq, raw_quarantine_path FROM cleanup_items
                             WHERE action_id = ?1 AND entry_ref = '3'",
                            [&action_id],
                            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                        )
                        .unwrap();
                    Ok((job_state, plan_state, target_b))
                }
            })
            .unwrap();
        drop(writer);
        guard.shutdown();

        assert_eq!(stored.0, "SUCCEEDED");
        assert_eq!(stored.1, "completed");
        assert_eq!(stored.2.0, "QUARANTINED");
        assert!(stored.2.1 > 2);
        assert!(!source_tmp.path().join("target-a").exists());
        assert!(!source_tmp.path().join("target-b").exists());
        assert!(
            source_tmp
                .path()
                .join(OsStr::from_bytes(stored.2.2.as_deref().unwrap(),))
                .exists()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_runtime_error_is_returned_for_supervisor_recovery() {
        let data_tmp = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("keep"), b"same content").unwrap();
        fs::write(source_tmp.path().join("target"), b"same content").unwrap();
        let source = SecureRoot::open(source_tmp.path().as_os_str()).unwrap();
        let journal = SecureRoot::open(data_tmp.path().as_os_str()).unwrap();
        assert!(source.caps().supports_safe_writes());

        let db_path = data_tmp.path().join("control.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let admin = create_admin(&conn, "admin", "a sufficiently long password").unwrap();
        let now = auth::now_rfc3339();
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, write_enabled, protected, created_at, updated_at)
             VALUES ('source', 'source', 'source', 1, 0, ?1, ?1)",
            [&now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at)
             VALUES ('cleanup_signing_key', ?1, ?2)",
            params![serde_json::to_string(&hex::encode(b"key")).unwrap(), now],
        )
        .unwrap();
        let plan = simple_plan(&conn, &admin.id, &source, &journal);
        let reauth = create_reauth_token(&conn, &admin.id, 5).unwrap();
        let reservation = reserve_quarantine(
            &mut conn,
            &plan.id,
            &admin.id,
            &reauth,
            QUARANTINE_CONFIRMATION,
            "runtime-cleanup-error",
            b"key",
        )
        .unwrap();
        let claimed = jobs::claim_next_operation(&mut conn).unwrap().unwrap();
        drop(conn);

        let mut config = recovery_config(data_tmp.path(), source_tmp.path());
        config.security.allow_write_operations = false;
        let guard = crate::store::DbWriter::spawn(&db_path, true).unwrap();
        let writer = guard.writer.clone();
        let error = run_job(writer.clone(), &config, &claimed).unwrap_err();
        let stored = writer
            .call_blocking({
                let action_id = reservation.action_id.clone();
                let job_id = reservation.job_id.clone();
                let plan_id = plan.id.clone();
                move |conn| {
                    let job_state: String = conn
                        .query_row("SELECT state FROM jobs WHERE id = ?1", [&job_id], |row| {
                            row.get(0)
                        })
                        .unwrap();
                    let plan_state: String = conn
                        .query_row(
                            "SELECT state FROM cleanup_plans WHERE id = ?1",
                            [&plan_id],
                            |row| row.get(0),
                        )
                        .unwrap();
                    let item_state: String = conn
                        .query_row(
                            "SELECT state FROM cleanup_items WHERE action_id = ?1",
                            [&action_id],
                            |row| row.get(0),
                        )
                        .unwrap();
                    Ok((job_state, plan_state, item_state))
                }
            })
            .unwrap();
        drop(writer);
        guard.shutdown();

        assert_eq!(error.code, ErrorCode::ReadOnlyMode);
        assert_eq!(stored.0, "RUNNING");
        assert_eq!(stored.1, "executing");
        assert_eq!(stored.2, "FAILED");
        assert!(source_tmp.path().join("target").exists());
    }
}
