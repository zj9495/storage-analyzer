//! Source registry (spec 4.1/4.2): registration, validation, soft delete,
//! probing and identity confirmation.
//!
//! All functions are synchronous on a `rusqlite::Connection` and are meant to
//! run inside the DB writer thread (store/mod.rs). Filesystem access to source
//! paths goes through `fssecure::SecureRoot` only; the only direct `std::fs`
//! read is `/proc/self/mountinfo` on Linux, which is a kernel interface, not a
//! source path. Probes are strictly read-only and never create test files.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use base64::Engine;
use fssecure::{FsSecureError, SecureRoot};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::config::{ApprovedMount, DeploymentConfig};
use crate::error::{AppError, AppResult, ErrorCode};

const MAX_NAME_CHARS: usize = 80;
const MAX_RELATIVE_ROOT_BYTES: usize = 4096;
const MAX_EXCLUSIONS: usize = 128;
const MAX_EXCLUSION_CHARS: usize = 512;
/// Probe directory sample cap: enough to prove traversability without
/// unbounded reads (spec 3.3 wizard diagnostics).
const PROBE_ENTRY_SAMPLE_CAP: usize = 64;

const SQL_NOW: &str = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

fn validation(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, msg)
}

fn conflict(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Conflict, msg)
}

fn not_found(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::NotFound, msg)
}

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

// ---- enums (stored as snake_case strings) ----

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }

            pub fn parse(s: &str) -> AppResult<Self> {
                match s {
                    $($text => Ok(Self::$variant),)+
                    other => Err(internal(format!(
                        "数据库中存在未知的{}取值: {other:?}",
                        stringify!($name)
                    ))),
                }
            }
        }
    };
}

string_enum!(StorageKind {
    Local => "local",
    Remote => "remote",
    Tiered => "tiered",
    Unknown => "unknown",
});

string_enum!(ReadPolicy {
    MetadataOnly => "metadata_only",
    ContentAllowed => "content_allowed",
});

string_enum!(IdentityStatus {
    Verified => "verified",
    Provisional => "provisional",
    Changed => "changed",
});

string_enum!(Availability {
    Online => "online",
    Offline => "offline",
    PermissionDenied => "permission_denied",
    Unknown => "unknown",
});

string_enum!(AtimeQuality {
    Reliable => "reliable",
    Relative => "relative",
    Disabled => "disabled",
    Unknown => "unknown",
});

// Conservative interpretation of filesystem-level shared-block risk.
// Detecting Btrfs does not provide qgroup `referenced`/`exclusive` values;
// the analyzer therefore never derives guaranteed reclaimable bytes from it.
string_enum!(BtrfsSharedBlockRisk {
    Possible => "possible",
    NotDetected => "not_detected",
    Unknown => "unknown",
});

fn btrfs_shared_block_risk(filesystem_type: Option<&str>) -> BtrfsSharedBlockRisk {
    match filesystem_type {
        Some("btrfs") => BtrfsSharedBlockRisk::Possible,
        Some(_) => BtrfsSharedBlockRisk::NotDetected,
        None => BtrfsSharedBlockRisk::Unknown,
    }
}

// ---- domain struct and DTO ----

/// A registered analysis root (spec 4.2). `raw_relative_root` is the
/// canonicalized raw-byte path beneath the approved mount; it is never
/// absolute and contains no `.`/`..` components.
#[derive(Debug, Clone)]
pub struct Source {
    pub id: String,
    pub name: String,
    pub mount_key: String,
    pub raw_relative_root: Vec<u8>,
    pub volume_id: Option<String>,
    pub storage_kind: StorageKind,
    pub read_policy: ReadPolicy,
    pub write_enabled: bool,
    pub protected: bool,
    pub exclusions: Vec<String>,
    pub identity_status: IdentityStatus,
    pub identity_epoch: i64,
    pub identity_json: serde_json::Value,
    pub availability: Availability,
    pub atime_quality: AtimeQuality,
    pub disabled_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Source {
    pub fn is_enabled(&self) -> bool {
        self.disabled_at.is_none()
    }

    pub fn to_dto(&self) -> SourceDto {
        SourceDto {
            id: self.id.clone(),
            name: self.name.clone(),
            mount_key: self.mount_key.clone(),
            relative_root_base64: base64::engine::general_purpose::STANDARD
                .encode(&self.raw_relative_root),
            relative_root_display: String::from_utf8_lossy(&self.raw_relative_root).into_owned(),
            volume_id: self.volume_id.clone(),
            storage_kind: self.storage_kind,
            read_policy: self.read_policy,
            write_enabled: self.write_enabled,
            protected: self.protected,
            exclusions: self.exclusions.clone(),
            identity_status: self.identity_status,
            identity_epoch: self.identity_epoch,
            availability: self.availability,
            atime_quality: self.atime_quality,
            disabled_at: self.disabled_at.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
        }
    }
}

/// API-facing view. Raw bytes travel base64-encoded; the display string is
/// lossy and must never be sent back to authorize file operations (spec 10.3).
#[derive(Debug, Clone, Serialize)]
pub struct SourceDto {
    pub id: String,
    pub name: String,
    pub mount_key: String,
    pub relative_root_base64: String,
    pub relative_root_display: String,
    pub volume_id: Option<String>,
    pub storage_kind: StorageKind,
    pub read_policy: ReadPolicy,
    pub write_enabled: bool,
    pub protected: bool,
    pub exclusions: Vec<String>,
    pub identity_status: IdentityStatus,
    pub identity_epoch: i64,
    pub availability: Availability,
    pub atime_quality: AtimeQuality,
    pub disabled_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct CreateSourceInput {
    pub name: String,
    pub mount_key: String,
    pub raw_relative_root: Vec<u8>,
    pub volume_id: Option<String>,
    pub storage_kind: StorageKind,
    pub read_policy: ReadPolicy,
    pub write_enabled: bool,
    pub protected: bool,
    pub exclusions: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateSourceInput {
    pub name: Option<String>,
    pub exclusions: Option<Vec<String>>,
    pub read_policy: Option<ReadPolicy>,
    pub write_enabled: Option<bool>,
}

// ---- validation helpers ----

fn validate_name(name: &str) -> AppResult<()> {
    let chars = name.chars().count();
    if !(1..=MAX_NAME_CHARS).contains(&chars) {
        return Err(validation(format!(
            "名称长度必须为 1–{MAX_NAME_CHARS} 个字符，当前为 {chars}"
        )));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(validation("名称不能包含控制字符"));
    }
    Ok(())
}

/// Canonicalize a raw relative root: reject absolute paths, `..` components,
/// control characters and overlong input; drop empty and `.` components so
/// that `a//b` and `a/./b` compare equal to `a/b`.
pub fn canonicalize_relative_root(raw: &[u8]) -> AppResult<Vec<u8>> {
    if raw.len() > MAX_RELATIVE_ROOT_BYTES {
        return Err(validation(format!(
            "相对路径过长（上限 {MAX_RELATIVE_ROOT_BYTES} 字节）"
        )));
    }
    if raw.starts_with(b"/") {
        return Err(AppError::new(
            ErrorCode::PathOutsideRoot,
            "相对路径不能是绝对路径",
        ));
    }
    let mut out: Vec<u8> = Vec::new();
    for comp in raw.split(|b| *b == b'/') {
        if comp.is_empty() || comp == b"." {
            continue;
        }
        if comp == b".." {
            return Err(AppError::new(
                ErrorCode::PathOutsideRoot,
                "相对路径不能包含 .. 越界组件",
            ));
        }
        if comp.iter().any(|b| *b < 0x20 || *b == 0x7f) {
            return Err(validation("相对路径不能包含控制字符"));
        }
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(comp);
    }
    Ok(out)
}

fn split_components(canonical: &[u8]) -> Vec<&[u8]> {
    canonical
        .split(|b| *b == b'/')
        .filter(|c| !c.is_empty())
        .collect()
}

/// Component-wise prefix overlap: true when either path is a prefix of the
/// other (equal paths included).
fn paths_overlap(a: &[u8], b: &[u8]) -> bool {
    let ca = split_components(a);
    let cb = split_components(b);
    let n = ca.len().min(cb.len());
    ca[..n] == cb[..n]
}

fn validate_exclusions(exclusions: &[String]) -> AppResult<()> {
    if exclusions.len() > MAX_EXCLUSIONS {
        return Err(validation(format!(
            "排除规则最多 {MAX_EXCLUSIONS} 条，当前 {} 条",
            exclusions.len()
        )));
    }
    for pat in exclusions {
        let chars = pat.chars().count();
        if !(1..=MAX_EXCLUSION_CHARS).contains(&chars) {
            return Err(validation(format!(
                "排除规则长度必须为 1–{MAX_EXCLUSION_CHARS} 个字符: {pat:?}"
            )));
        }
        if pat.chars().any(|c| c.is_control()) {
            return Err(validation(format!("排除规则不能包含控制字符: {pat:?}")));
        }
        globset::Glob::new(pat)
            .map_err(|e| validation(format!("排除规则不是有效的 glob: {pat:?}（{e}）")))?;
    }
    Ok(())
}

/// write_enabled=true requires all of: deployment allow_write_operations,
/// a writable approved mount, and a non-protected source (spec 13.1).
fn check_write_gate(
    cfg: &DeploymentConfig,
    mount: &ApprovedMount,
    write_enabled: bool,
    protected: bool,
) -> AppResult<()> {
    if !write_enabled {
        return Ok(());
    }
    if !cfg.security.allow_write_operations {
        return Err(AppError::new(
            ErrorCode::ReadOnlyMode,
            "部署未开启写操作总开关（security.allow_write_operations），源保持只读",
        ));
    }
    if !mount.writable {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            format!("挂载 {:?} 在部署配置中为只读，不能开启写入", mount.key),
        ));
    }
    if protected {
        return Err(AppError::new(
            ErrorCode::ProtectedFile,
            "受保护源禁止开启写入",
        ));
    }
    Ok(())
}

// ---- row mapping ----

fn row_to_source(row: &rusqlite::Row<'_>) -> rusqlite::Result<Source> {
    let exclusions_json: String = row.get("exclusions_json")?;
    let identity_json: String = row.get("identity_json")?;
    Ok(Source {
        id: row.get("id")?,
        name: row.get("name")?,
        mount_key: row.get("mount_key")?,
        raw_relative_root: row.get("raw_relative_root")?,
        volume_id: row.get("volume_id")?,
        storage_kind: StorageKind::parse(&row.get::<_, String>("storage_kind")?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        read_policy: ReadPolicy::parse(&row.get::<_, String>("read_policy")?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        write_enabled: row.get::<_, i64>("write_enabled")? != 0,
        protected: row.get::<_, i64>("protected")? != 0,
        exclusions: serde_json::from_str(&exclusions_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        identity_status: IdentityStatus::parse(&row.get::<_, String>("identity_status")?).map_err(
            |e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            },
        )?,
        identity_epoch: row.get("identity_epoch")?,
        identity_json: serde_json::from_str(&identity_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        availability: Availability::parse(&row.get::<_, String>("availability")?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        atime_quality: AtimeQuality::parse(&row.get::<_, String>("atime_quality")?).map_err(
            |e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            },
        )?,
        disabled_at: row.get("disabled_at")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

const SOURCE_COLS: &str = "id, name, mount_key, raw_relative_root, volume_id, storage_kind, \
     read_policy, write_enabled, protected, exclusions_json, identity_status, identity_epoch, \
     identity_json, availability, atime_quality, disabled_at, created_at, updated_at";

fn query_source(conn: &Connection, id: &str) -> AppResult<Option<Source>> {
    conn.query_row(
        &format!("SELECT {SOURCE_COLS} FROM sources WHERE id = ?1"),
        params![id],
        row_to_source,
    )
    .optional()
    .map_err(|e| internal(format!("读取数据源失败: {e}")))
}

/// Fetch a source by id, including soft-deleted rows (history is preserved).
pub fn get_source(conn: &Connection, id: &str) -> AppResult<Source> {
    query_source(conn, id)?.ok_or_else(|| not_found("数据源不存在"))
}

/// Fetch a source that is not soft-deleted.
pub(crate) fn get_enabled_source(conn: &Connection, id: &str) -> AppResult<Source> {
    let src = get_source(conn, id)?;
    if !src.is_enabled() {
        return Err(not_found("数据源已停用"));
    }
    Ok(src)
}

pub fn list_sources(conn: &Connection, include_disabled: bool) -> AppResult<Vec<Source>> {
    let sql = if include_disabled {
        format!("SELECT {SOURCE_COLS} FROM sources ORDER BY created_at, id")
    } else {
        format!(
            "SELECT {SOURCE_COLS} FROM sources WHERE disabled_at IS NULL ORDER BY created_at, id"
        )
    };
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| internal(format!("准备查询失败: {e}")))?;
    let rows = stmt
        .query_map([], row_to_source)
        .map_err(|e| internal(format!("列出数据源失败: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal(format!("读取数据源失败: {e}")))?;
    Ok(rows)
}

fn name_taken(conn: &Connection, name: &str, exclude_id: Option<&str>) -> AppResult<bool> {
    let mut stmt = conn
        .prepare("SELECT id FROM sources WHERE name = ?1")
        .map_err(|e| internal(format!("准备查询失败: {e}")))?;
    let ids = stmt
        .query_map(params![name], |r| r.get::<_, String>(0))
        .map_err(|e| internal(format!("检查名称唯一性失败: {e}")))?;
    for id in ids {
        let id = id.map_err(|e| internal(format!("检查名称唯一性失败: {e}")))?;
        if Some(id.as_str()) != exclude_id {
            return Ok(true);
        }
    }
    Ok(false)
}

// ---- registry operations ----

pub fn create_source(
    conn: &Connection,
    cfg: &DeploymentConfig,
    input: CreateSourceInput,
) -> AppResult<Source> {
    validate_name(&input.name)?;
    let mount = cfg
        .mount(&input.mount_key)
        .ok_or_else(|| validation(format!("未知的批准挂载键: {:?}", input.mount_key)))?;
    let canonical = canonicalize_relative_root(&input.raw_relative_root)?;
    validate_exclusions(&input.exclusions)?;
    check_write_gate(cfg, mount, input.write_enabled, input.protected)?;

    if name_taken(conn, &input.name, None)? {
        return Err(conflict("数据源名称已存在"));
    }
    if let Some(vol) = &input.volume_id {
        let exists: bool = conn
            .query_row("SELECT 1 FROM volumes WHERE id = ?1", params![vol], |_| {
                Ok(true)
            })
            .optional()
            .map_err(|e| internal(format!("检查数据卷失败: {e}")))?
            .unwrap_or(false);
        if !exists {
            return Err(validation("指定的数据卷不存在"));
        }
    }

    // Overlap / duplicate-canonical guard (spec 4.2): only enabled sources on
    // the same mount participate.
    let mut stmt = conn
        .prepare(
            "SELECT id, name, raw_relative_root FROM sources \
             WHERE mount_key = ?1 AND disabled_at IS NULL",
        )
        .map_err(|e| internal(format!("准备查询失败: {e}")))?;
    let existing = stmt
        .query_map(params![input.mount_key], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|e| internal(format!("检查路径重叠失败: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal(format!("检查路径重叠失败: {e}")))?;
    for (eid, ename, eroot) in existing {
        if eroot == canonical {
            return Err(conflict(format!("同一目录已登记为数据源 {ename:?}"))
                .with_details(serde_json::json!({"existing_source_id": eid})));
        }
        if paths_overlap(&eroot, &canonical) {
            return Err(
                conflict(format!("与已登记数据源 {ename:?} 的根路径存在父子重叠"))
                    .with_details(serde_json::json!({"existing_source_id": eid})),
            );
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    let exclusions_json = serde_json::to_string(&input.exclusions)
        .map_err(|e| internal(format!("序列化排除规则失败: {e}")))?;
    conn.execute(
        &format!(
            "INSERT INTO sources (id, name, mount_key, raw_relative_root, volume_id, \
             storage_kind, read_policy, write_enabled, protected, exclusions_json, \
             created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, {SQL_NOW}, {SQL_NOW})"
        ),
        params![
            id,
            input.name,
            input.mount_key,
            canonical,
            input.volume_id,
            input.storage_kind.as_str(),
            input.read_policy.as_str(),
            i64::from(input.write_enabled),
            i64::from(input.protected),
            exclusions_json,
        ],
    )
    .map_err(|e| {
        if matches!(
            &e,
            rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation
        ) {
            conflict("数据源名称或路径与现有登记冲突")
        } else {
            internal(format!("创建数据源失败: {e}"))
        }
    })?;
    get_source(conn, &id)
}

pub fn update_source(
    conn: &Connection,
    cfg: &DeploymentConfig,
    id: &str,
    input: UpdateSourceInput,
) -> AppResult<Source> {
    let current = get_enabled_source(conn, id)?;
    let mount = cfg.mount(&current.mount_key).ok_or_else(|| {
        internal(format!(
            "数据源引用的挂载键 {:?} 不在部署配置中",
            current.mount_key
        ))
    })?;

    let name = input.name.unwrap_or_else(|| current.name.clone());
    validate_name(&name)?;
    let exclusions = input
        .exclusions
        .unwrap_or_else(|| current.exclusions.clone());
    validate_exclusions(&exclusions)?;
    let read_policy = input.read_policy.unwrap_or(current.read_policy);
    let write_enabled = input.write_enabled.unwrap_or(current.write_enabled);
    check_write_gate(cfg, mount, write_enabled, current.protected)?;

    if name_taken(conn, &name, Some(id))? {
        return Err(conflict("数据源名称已存在"));
    }
    let exclusions_json = serde_json::to_string(&exclusions)
        .map_err(|e| internal(format!("序列化排除规则失败: {e}")))?;
    conn.execute(
        &format!(
            "UPDATE sources SET name = ?2, exclusions_json = ?3, read_policy = ?4, \
             write_enabled = ?5, updated_at = {SQL_NOW} WHERE id = ?1"
        ),
        params![
            id,
            name,
            exclusions_json,
            read_policy.as_str(),
            i64::from(write_enabled),
        ],
    )
    .map_err(|e| internal(format!("更新数据源失败: {e}")))?;
    get_source(conn, id)
}

/// Soft delete: sets disabled_at and preserves all history (spec 17.2).
pub fn soft_delete_source(conn: &Connection, id: &str) -> AppResult<Source> {
    get_enabled_source(conn, id)?;
    conn.execute(
        &format!(
            "UPDATE sources SET disabled_at = {SQL_NOW}, updated_at = {SQL_NOW} WHERE id = ?1"
        ),
        params![id],
    )
    .map_err(|e| internal(format!("停用数据源失败: {e}")))?;
    get_source(conn, id)
}

// ---- mountinfo (Linux); pure parsing is cross-platform and unit-tested ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountInfoEntry {
    pub major_minor: String,
    pub mount_point: String,
    pub mount_opts: Vec<String>,
    pub super_opts: Vec<String>,
    /// Filesystem type reported after the ` - ` separator.
    pub filesystem_type: String,
}

/// Decode mountinfo octal escapes like `\040` (space).
fn unescape_mount_field(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = &bytes[i + 1..i + 4];
            if oct.iter().all(|b| b.is_ascii_digit())
                && let Ok(v) = u8::from_str_radix(std::str::from_utf8(oct).unwrap_or(""), 8)
            {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse /proc/self/mountinfo content. Pure string handling; only the file
/// read is Linux-gated.
pub(crate) fn parse_mountinfo(content: &str) -> Vec<MountInfoEntry> {
    let mut out = Vec::new();
    for line in content.lines() {
        let Some(sep) = line.find(" - ") else {
            continue;
        };
        let pre: Vec<&str> = line[..sep].split(' ').collect();
        let post: Vec<&str> = line[sep + 3..].split(' ').collect();
        // pre: id parent major:minor root mount_point options...
        if pre.len() < 6 || post.len() < 3 {
            continue;
        }
        out.push(MountInfoEntry {
            major_minor: pre[2].to_string(),
            mount_point: unescape_mount_field(pre[4]),
            mount_opts: pre[5].split(',').map(|s| s.to_string()).collect(),
            super_opts: post[2].split(',').map(|s| s.to_string()).collect(),
            filesystem_type: post[0].to_string(),
        });
    }
    out
}

/// Find the deepest mount entry whose mount point is a component-boundary
/// prefix of `path`.
pub(crate) fn find_mount_entry<'a>(
    entries: &'a [MountInfoEntry],
    path: &std::path::Path,
) -> Option<&'a MountInfoEntry> {
    let path = path.to_string_lossy();
    entries
        .iter()
        .filter(|e| {
            let mp = e.mount_point.trim_end_matches('/');
            if mp.is_empty() {
                return path.starts_with('/');
            }
            path == mp || path.starts_with(&format!("{mp}/"))
        })
        .max_by_key(|e| e.mount_point.len())
}

fn mount_read_only(entry: &MountInfoEntry) -> Option<bool> {
    if entry.mount_opts.iter().any(|o| o == "ro") || entry.super_opts.iter().any(|o| o == "ro") {
        Some(true)
    } else if entry.mount_opts.iter().any(|o| o == "rw") {
        Some(false)
    } else {
        None
    }
}

fn mount_atime_quality(entry: &MountInfoEntry) -> AtimeQuality {
    let all = entry
        .mount_opts
        .iter()
        .chain(entry.super_opts.iter())
        .map(String::as_str);
    let mut has_relatime = false;
    for o in all {
        match o {
            "noatime" => return AtimeQuality::Disabled,
            "strictatime" => return AtimeQuality::Reliable,
            "relatime" => has_relatime = true,
            _ => {}
        }
    }
    if has_relatime {
        AtimeQuality::Relative
    } else {
        AtimeQuality::Unknown
    }
}

#[cfg(target_os = "linux")]
fn read_system_mountinfo() -> Option<String> {
    std::fs::read_to_string("/proc/self/mountinfo").ok()
}

#[cfg(not(target_os = "linux"))]
fn read_system_mountinfo() -> Option<String> {
    None
}

// ---- probing ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsIdentity {
    /// st_dev of the source root, decimal string.
    pub device_id: String,
    /// "major:minor" from mountinfo when available (Linux only).
    pub mount_fsid: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceProbe {
    pub mounted: bool,
    pub traversable: bool,
    pub sampled_entries: u32,
    pub sample_truncated: bool,
    /// None = unknown (non-Linux host or mount not found in mountinfo).
    pub read_only: Option<bool>,
    pub atime_quality: AtimeQuality,
    /// Filesystem type observed from the matched Linux mountinfo entry.
    pub filesystem_type: Option<String>,
    /// Btrfs is only a warning that shared blocks may affect allocated-byte
    /// interpretation; exact qgroup accounting is outside this application.
    pub btrfs_shared_block_risk: BtrfsSharedBlockRisk,
    pub fs_identity: Option<FsIdentity>,
    pub availability: Availability,
    /// The probe detected a filesystem identity different from the stored,
    /// previously confirmed one (spec 10.4: requires re-confirmation).
    pub identity_changed: bool,
    pub error: Option<String>,
}

fn probe_error_availability(e: &FsSecureError) -> Availability {
    match e {
        FsSecureError::NotFound => Availability::Offline,
        FsSecureError::PermissionDenied => Availability::PermissionDenied,
        _ => Availability::Unknown,
    }
}

fn probe_error_message(e: &FsSecureError) -> String {
    match e {
        FsSecureError::NotFound => "目录不存在或未解锁挂载".to_string(),
        FsSecureError::PermissionDenied => "没有读取该目录的权限".to_string(),
        FsSecureError::SymlinkNotAllowed => "路径包含符号链接，已按安全策略拒绝".to_string(),
        FsSecureError::MountCrossingNotAllowed | FsSecureError::CrossDevice => {
            "路径跨越挂载边界，已按安全策略拒绝".to_string()
        }
        FsSecureError::NotDirectory => "路径存在但不是目录".to_string(),
        other => format!("探测失败: {other}"),
    }
}

fn source_abs_path(mount: &ApprovedMount, canonical_rel: &[u8]) -> PathBuf {
    let mut p = mount.container_path.clone();
    for comp in split_components(canonical_rel) {
        p.push(OsStr::from_bytes(comp));
    }
    p
}

/// Pure filesystem part of a probe; shared with volume identity detection.
/// Never writes to the source.
pub(crate) fn run_probe(mount: &ApprovedMount, canonical_rel: &[u8]) -> SourceProbe {
    let mut probe = SourceProbe {
        mounted: false,
        traversable: false,
        sampled_entries: 0,
        sample_truncated: false,
        read_only: None,
        atime_quality: AtimeQuality::Unknown,
        filesystem_type: None,
        btrfs_shared_block_risk: BtrfsSharedBlockRisk::Unknown,
        fs_identity: None,
        availability: Availability::Unknown,
        identity_changed: false,
        error: None,
    };

    let root = match SecureRoot::open(mount.container_path.as_os_str()) {
        Ok(r) => r,
        Err(e) => {
            probe.availability = probe_error_availability(&e);
            probe.error = Some(probe_error_message(&e));
            return probe;
        }
    };
    let rel = OsStr::from_bytes(canonical_rel);
    let dir_fd = match root.open_dir(rel) {
        Ok(fd) => fd,
        Err(e) => {
            probe.availability = probe_error_availability(&e);
            // EACCES proves existence; everything else means not usable.
            probe.mounted = matches!(e, FsSecureError::PermissionDenied);
            probe.error = Some(probe_error_message(&e));
            return probe;
        }
    };
    probe.mounted = true;

    // Filesystem identity: st_dev via the secure root plus mountinfo
    // major:minor when the host provides it.
    let device_id = match root.stat(rel) {
        Ok(st) => Some(st.identity.device_id),
        Err(_) => None,
    };
    let abs = source_abs_path(mount, canonical_rel);
    let mount_entry = read_system_mountinfo()
        .map(|text| parse_mountinfo(&text))
        .and_then(|entries| find_mount_entry(&entries, &abs).cloned());
    if let Some(entry) = &mount_entry {
        probe.read_only = mount_read_only(entry);
        probe.atime_quality = mount_atime_quality(entry);
        probe.filesystem_type = Some(entry.filesystem_type.clone());
        probe.btrfs_shared_block_risk = btrfs_shared_block_risk(Some(&entry.filesystem_type));
    }
    if let Some(dev) = device_id {
        probe.fs_identity = Some(FsIdentity {
            device_id: dev.to_string(),
            mount_fsid: mount_entry.map(|e| e.major_minor),
        });
    }

    // Traversability: read a bounded sample of entries from the opened FD.
    let mut availability = Availability::Online;
    match root.read_dir(rel) {
        Ok(it) => {
            let mut count: usize = 0;
            for entry in it {
                match entry {
                    Ok(_) => {
                        count += 1;
                        if count > PROBE_ENTRY_SAMPLE_CAP {
                            probe.sample_truncated = true;
                            break;
                        }
                    }
                    Err(e) => {
                        availability = probe_error_availability(&e);
                        probe.error = Some(probe_error_message(&e));
                        break;
                    }
                }
            }
            probe.sampled_entries = count.min(PROBE_ENTRY_SAMPLE_CAP) as u32;
            probe.traversable = probe.error.is_none();
        }
        Err(e) => {
            availability = probe_error_availability(&e);
            probe.error = Some(probe_error_message(&e));
        }
    }
    probe.availability = availability;
    drop(dir_fd);
    probe
}

/// Stored identity comparison: only fields present in BOTH stored and probed
/// identity participate; absent fields degrade the check rather than fail it.
pub(crate) fn identity_differs(stored: &serde_json::Value, probed: &FsIdentity) -> bool {
    let stored_dev = stored.get("device_id").and_then(|v| v.as_str());
    let stored_fsid = stored.get("mount_fsid").and_then(|v| v.as_str());
    match (stored_dev, stored_fsid, &probed.mount_fsid) {
        (Some(d), Some(f), Some(pf)) => d != probed.device_id || f != *pf,
        (Some(d), _, _) => d != probed.device_id,
        _ => false,
    }
}

/// Read-only source diagnostic (spec 3.3, 17.2 `/sources/{id}/probe`).
/// Persists availability/atime_quality and flags identity changes; never
/// creates test files in the source.
pub fn probe_source(
    conn: &Connection,
    cfg: &DeploymentConfig,
    source_id: &str,
) -> AppResult<SourceProbe> {
    let src = get_source(conn, source_id)?;
    let mount = cfg
        .mount(&src.mount_key)
        .ok_or_else(|| validation(format!("未知的批准挂载键: {:?}", src.mount_key)))?;

    let mut probe = run_probe(mount, &src.raw_relative_root);

    if let (Some(probed), IdentityStatus::Verified | IdentityStatus::Provisional) =
        (&probe.fs_identity, src.identity_status)
        && identity_differs(&src.identity_json, probed)
    {
        probe.identity_changed = true;
    }

    conn.execute(
        &format!(
            "UPDATE sources SET availability = ?2, atime_quality = ?3, \
             identity_status = CASE WHEN ?4 THEN 'changed' ELSE identity_status END, \
             updated_at = {SQL_NOW} WHERE id = ?1"
        ),
        params![
            source_id,
            probe.availability.as_str(),
            probe.atime_quality.as_str(),
            probe.identity_changed,
        ],
    )
    .map_err(|e| internal(format!("记录探测结果失败: {e}")))?;
    Ok(probe)
}

/// Admin confirmation of the current filesystem identity (spec 4.2, 17.2
/// `/sources/{id}/confirm-identity`): increments identity_epoch, marks the
/// source verified and stores the probed identity. Cache invalidation on
/// epoch change is the caller's responsibility.
pub fn confirm_identity(
    conn: &Connection,
    cfg: &DeploymentConfig,
    source_id: &str,
) -> AppResult<Source> {
    let src = get_enabled_source(conn, source_id)?;
    let mount = cfg
        .mount(&src.mount_key)
        .ok_or_else(|| validation(format!("未知的批准挂载键: {:?}", src.mount_key)))?;

    let probe = run_probe(mount, &src.raw_relative_root);
    let identity = probe.fs_identity.ok_or_else(|| {
        AppError::new(
            ErrorCode::SourceUnavailable,
            "无法读取文件系统身份，源不可用，不能确认身份",
        )
    })?;

    let identity_json = serde_json::json!({
        "device_id": identity.device_id,
        "mount_fsid": identity.mount_fsid,
    });
    conn.execute(
        &format!(
            "UPDATE sources SET identity_status = 'verified', \
             identity_epoch = identity_epoch + 1, identity_json = ?2, \
             availability = ?3, atime_quality = ?4, updated_at = {SQL_NOW} WHERE id = ?1"
        ),
        params![
            source_id,
            identity_json.to_string(),
            probe.availability.as_str(),
            probe.atime_quality.as_str(),
        ],
    )
    .map_err(|e| internal(format!("确认源身份失败: {e}")))?;
    get_source(conn, source_id)
}

#[cfg(test)]
pub(crate) mod tests;
