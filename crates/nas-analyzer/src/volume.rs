//! Volume registry and capacity sampling (spec 4.1/4.3, 5.1, 6).
//!
//! A Volume is a logical filesystem identity used for capacity sampling; its
//! `capacity_source_id` points at the Source through which statvfs data is
//! collected. All functions are synchronous on a `rusqlite::Connection` (DB
//! writer thread); filesystem access goes through `fssecure::SecureRoot` and
//! `rustix::fs::fstatvfs` on the securely opened directory FD. Sampling never
//! fabricates zeros: failures are recorded as quality='error' rows with all
//! byte fields NULL.

use std::os::unix::ffi::OsStrExt;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::config::DeploymentConfig;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::source::{self, Source};

const MAX_NAME_CHARS: usize = 128;
const SQL_NOW: &str = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";
const SQL_NOW_MINUTE: &str = "strftime('%Y-%m-%dT%H:%M:00.000Z','now')";

fn validation(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, msg)
}

fn not_found(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::NotFound, msg)
}

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

macro_rules! string_enum_volume {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }
        impl $name {
            pub fn as_str(&self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }
            fn parse(s: &str) -> AppResult<Self> {
                match s {
                    $($text => Ok(Self::$variant),)+
                    other => Err(internal(format!("数据库中存在未知的{}取值: {other:?}", stringify!($name)))),
                }
            }
        }
    };
}

string_enum_volume!(VolumeStatus {
    Active => "active",
    Disconnected => "disconnected",
});

#[derive(Debug, Clone)]
pub struct Volume {
    pub id: String,
    pub name: String,
    pub capacity_source_id: Option<String>,
    pub identity_json: serde_json::Value,
    pub status: VolumeStatus,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct CreateVolumeInput {
    pub name: String,
    pub capacity_source_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateVolumeInput {
    pub name: Option<String>,
    pub capacity_source_id: Option<Option<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleQuality {
    Ok,
    Error,
}

impl SampleQuality {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

fn sample_quality(raw: &str) -> rusqlite::Result<SampleQuality> {
    match raw {
        "ok" => Ok(SampleQuality::Ok),
        "error" => Ok(SampleQuality::Error),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("未知容量采样质量: {other}"),
            )),
        )),
    }
}

pub(crate) fn validate_capacity_numbers(
    total: u64,
    free: u64,
    available: u64,
    used: u64,
) -> std::result::Result<(), &'static str> {
    if free > total {
        return Err("文件系统报告空闲容量大于总容量");
    }
    if available > free {
        return Err("文件系统报告当前身份可用容量大于空闲容量");
    }
    if used != total - free {
        return Err("文件系统报告已用容量与总容量、空闲容量不一致");
    }
    Ok(())
}

fn validate_sample_row(
    total: Option<u64>,
    free: Option<u64>,
    available: Option<u64>,
    used: Option<u64>,
    quality: SampleQuality,
) -> rusqlite::Result<()> {
    if quality == SampleQuality::Ok {
        let (Some(total), Some(free), Some(available), Some(used)) = (total, free, available, used)
        else {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ok 容量采样缺少字节字段",
                )),
            ));
        };
        if let Err(message) = validate_capacity_numbers(total, free, available, used) {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    message,
                )),
            ));
        }
    }
    Ok(())
}

/// One capacity sample. Byte counts are u64 in Rust; they are stored as
/// decimal strings in `volume_samples` (spec 17.1 lossless numbers).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VolumeSample {
    pub volume_id: String,
    pub sample_time: String,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    /// free - available: filesystem reserve not usable by the current
    /// identity; shown separately, never merged into `used` (spec 5.1).
    pub reserved_diff_bytes: Option<u64>,
    pub quality: SampleQuality,
    pub error: Option<String>,
    /// false when the (volume_id, sample minute) row already existed.
    pub inserted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeIdentityOutcome {
    Unchanged,
    Changed,
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeIdentityCheck {
    pub outcome: VolumeIdentityOutcome,
    pub volume: VolumeDto,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeDto {
    pub id: String,
    pub name: String,
    pub capacity_source_id: Option<String>,
    pub identity_json: serde_json::Value,
    pub status: VolumeStatus,
    pub created_at: String,
    pub updated_at: String,
}

impl Volume {
    pub fn to_dto(&self) -> VolumeDto {
        VolumeDto {
            id: self.id.clone(),
            name: self.name.clone(),
            capacity_source_id: self.capacity_source_id.clone(),
            identity_json: self.identity_json.clone(),
            status: self.status,
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
        }
    }

    /// A volume counts toward the global total only when it is active and its
    /// identity has been explicitly confirmed (spec 4.3).
    pub fn is_confirmed(&self) -> bool {
        self.status == VolumeStatus::Active
            && self.capacity_source_id.is_some()
            && self
                .identity_json
                .get("device_id")
                .and_then(|v| v.as_str())
                .is_some()
    }
}

fn row_to_volume(row: &rusqlite::Row<'_>) -> rusqlite::Result<Volume> {
    let identity_json: String = row.get("identity_json")?;
    Ok(Volume {
        id: row.get("id")?,
        name: row.get("name")?,
        capacity_source_id: row.get("capacity_source_id")?,
        identity_json: serde_json::from_str(&identity_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        status: VolumeStatus::parse(&row.get::<_, String>("status")?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

const VOLUME_COLS: &str =
    "id, name, capacity_source_id, identity_json, status, created_at, updated_at";

pub fn get_volume(conn: &Connection, id: &str) -> AppResult<Volume> {
    conn.query_row(
        &format!("SELECT {VOLUME_COLS} FROM volumes WHERE id = ?1"),
        params![id],
        row_to_volume,
    )
    .optional()
    .map_err(|e| internal(format!("读取数据卷失败: {e}")))?
    .ok_or_else(|| not_found("数据卷不存在"))
}

pub fn list_volumes(conn: &Connection) -> AppResult<Vec<Volume>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {VOLUME_COLS} FROM volumes ORDER BY created_at, id"
        ))
        .map_err(|e| internal(format!("准备查询失败: {e}")))?;
    stmt.query_map([], row_to_volume)
        .map_err(|e| internal(format!("列出数据卷失败: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal(format!("读取数据卷失败: {e}")))
}

fn validate_volume_name(name: &str) -> AppResult<()> {
    let chars = name.chars().count();
    if !(1..=MAX_NAME_CHARS).contains(&chars) {
        return Err(validation(format!(
            "卷名称长度必须为 1–{MAX_NAME_CHARS} 个字符，当前为 {chars}"
        )));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(validation("卷名称不能包含控制字符"));
    }
    Ok(())
}

/// The capacity sampling source must exist and be enabled.
fn check_capacity_source(conn: &Connection, source_id: &str) -> AppResult<()> {
    source::get_enabled_source(conn, source_id)
        .map(|_| ())
        .map_err(|e| {
            if e.code == ErrorCode::NotFound {
                validation("容量采样源不存在或已停用")
            } else {
                e
            }
        })
}

pub fn create_volume(conn: &Connection, input: CreateVolumeInput) -> AppResult<Volume> {
    validate_volume_name(&input.name)?;
    if let Some(sid) = &input.capacity_source_id {
        check_capacity_source(conn, sid)?;
    }
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        &format!(
            "INSERT INTO volumes (id, name, capacity_source_id, created_at, updated_at) \
             VALUES (?1, ?2, ?3, {SQL_NOW}, {SQL_NOW})"
        ),
        params![id, input.name, input.capacity_source_id],
    )
    .map_err(|e| internal(format!("创建数据卷失败: {e}")))?;
    get_volume(conn, &id)
}

pub fn update_volume(conn: &Connection, id: &str, input: UpdateVolumeInput) -> AppResult<Volume> {
    let current = get_volume(conn, id)?;
    let name = input.name.unwrap_or_else(|| current.name.clone());
    validate_volume_name(&name)?;
    let capacity_source_id = input
        .capacity_source_id
        .unwrap_or_else(|| current.capacity_source_id.clone());
    if let Some(sid) = &capacity_source_id {
        check_capacity_source(conn, sid)?;
    }
    // Changing the sampling source invalidates the confirmed identity: the
    // administrator must re-confirm before the volume counts again (spec 4.3).
    let identity_changed = capacity_source_id != current.capacity_source_id;
    conn.execute(
        &format!(
            "UPDATE volumes SET name = ?2, capacity_source_id = ?3, \
             identity_json = CASE WHEN ?4 THEN '{{}}' ELSE identity_json END, \
             updated_at = {SQL_NOW} WHERE id = ?1"
        ),
        params![id, name, capacity_source_id, identity_changed],
    )
    .map_err(|e| internal(format!("更新数据卷失败: {e}")))?;
    get_volume(conn, id)
}

// ---- capacity sampling ----

fn record_sample(
    conn: &Connection,
    volume_id: &str,
    numbers: Option<(u64, u64, u64, u64)>,
    error: Option<&str>,
) -> AppResult<VolumeSample> {
    let sample_time: String = conn
        .query_row(&format!("SELECT {SQL_NOW_MINUTE}"), [], |row| row.get(0))
        .map_err(|e| internal(format!("生成容量采样时间失败: {e}")))?;
    let (total, free, avail, used, quality) = match numbers {
        Some((t, f, a, u)) => (
            Some(t.to_string()),
            Some(f.to_string()),
            Some(a.to_string()),
            Some(u.to_string()),
            SampleQuality::Ok,
        ),
        None => (None, None, None, None, SampleQuality::Error),
    };
    let affected = conn
        .execute(
            "INSERT OR IGNORE INTO volume_samples \
             (volume_id, sample_time, total_bytes, free_bytes, available_bytes, used_bytes, quality, error) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                volume_id,
                sample_time,
                total,
                free,
                avail,
                used,
                quality.as_str(),
                error,
            ],
        )
        .map_err(|e| internal(format!("写入容量采样失败: {e}")))?;
    // Read back the canonical row for this minute (covers the dedupe hit).
    let sample = conn
        .query_row(
            "SELECT volume_id, sample_time, total_bytes, free_bytes, available_bytes, \
             used_bytes, quality, error FROM volume_samples \
             WHERE volume_id = ?1 AND sample_time = ?2",
            params![volume_id, sample_time],
            |row| {
                let parse = |i: usize| -> rusqlite::Result<Option<u64>> {
                    row.get::<_, Option<String>>(i)?
                        .map(|s| {
                            s.parse::<u64>().map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    i,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                )
                            })
                        })
                        .transpose()
                };
                let total = parse(2)?;
                let free = parse(3)?;
                let available = parse(4)?;
                let used = parse(5)?;
                let quality = sample_quality(&row.get::<_, String>(6)?)?;
                validate_sample_row(total, free, available, used, quality)?;
                Ok(VolumeSample {
                    volume_id: row.get(0)?,
                    sample_time: row.get(1)?,
                    reserved_diff_bytes: match (free, available) {
                        (Some(f), Some(a)) => f.checked_sub(a),
                        _ => None,
                    },
                    total_bytes: total,
                    free_bytes: free,
                    available_bytes: available,
                    used_bytes: used,
                    quality,
                    error: row.get(7)?,
                    inserted: affected > 0,
                })
            },
        )
        .map_err(|e| internal(format!("读取容量采样失败: {e}")))?;
    Ok(sample)
}

/// statvfs over the securely opened source root FD (spec 5.1). All math is
/// checked; any inconsistency becomes an error row, never a fabricated value.
fn statvfs_numbers(
    cfg: &DeploymentConfig,
    src: &Source,
) -> std::result::Result<(u64, u64, u64, u64), String> {
    let mount = cfg
        .mount(&src.mount_key)
        .ok_or_else(|| format!("未知的批准挂载键: {:?}", src.mount_key))?;
    let root = fssecure::SecureRoot::open(mount.container_path.as_os_str())
        .map_err(|e| format!("批准挂载不可用: {e}"))?;
    let rel = std::ffi::OsStr::from_bytes(&src.raw_relative_root);
    let dir = root
        .open_dir(rel)
        .map_err(|e| format!("源根目录不可用: {e}"))?;
    let st = rustix::fs::fstatvfs(&dir).map_err(|e| format!("读取容量信息失败: {e}"))?;
    let total = st
        .f_blocks
        .checked_mul(st.f_frsize)
        .ok_or_else(|| "容量计算溢出".to_string())?;
    let free = st
        .f_bfree
        .checked_mul(st.f_frsize)
        .ok_or_else(|| "容量计算溢出".to_string())?;
    let avail = st
        .f_bavail
        .checked_mul(st.f_frsize)
        .ok_or_else(|| "容量计算溢出".to_string())?;
    let used = total
        .checked_sub(free)
        .ok_or_else(|| "文件系统报告空闲大于总量，口径异常".to_string())?;
    validate_capacity_numbers(total, free, avail, used).map_err(str::to_owned)?;
    Ok((total, free, avail, used))
}

/// Collect one capacity sample for a volume through its capacity source
/// (spec 6). The sample minute is truncated and deduplicated with
/// INSERT OR IGNORE on (volume_id, sample_time).
pub fn sample_capacity(
    conn: &Connection,
    cfg: &DeploymentConfig,
    volume_id: &str,
) -> AppResult<VolumeSample> {
    let vol = get_volume(conn, volume_id)?;
    let Some(sid) = &vol.capacity_source_id else {
        return record_sample(conn, volume_id, None, Some("该卷尚未确认容量采样源"));
    };
    let src = match source::get_enabled_source(conn, sid) {
        Ok(s) => s,
        Err(e) => return record_sample(conn, volume_id, None, Some(&e.message)),
    };
    match statvfs_numbers(cfg, &src) {
        Ok(numbers) => record_sample(conn, volume_id, Some(numbers), None),
        Err(msg) => record_sample(conn, volume_id, None, Some(&msg)),
    }
}

/// Latest samples for a volume, newest first.
pub fn list_samples(
    conn: &Connection,
    volume_id: &str,
    limit: u32,
) -> AppResult<Vec<VolumeSample>> {
    get_volume(conn, volume_id)?;
    let mut stmt = conn
        .prepare(
            "SELECT volume_id, sample_time, total_bytes, free_bytes, available_bytes, \
             used_bytes, quality, error FROM volume_samples \
             WHERE volume_id = ?1 ORDER BY sample_time DESC LIMIT ?2",
        )
        .map_err(|e| internal(format!("准备查询失败: {e}")))?;
    let rows = stmt
        .query_map(params![volume_id, limit], |row| {
            let parse = |i: usize| -> rusqlite::Result<Option<u64>> {
                row.get::<_, Option<String>>(i)?
                    .map(|s| {
                        s.parse::<u64>().map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                i,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })
                    })
                    .transpose()
            };
            let total = parse(2)?;
            let free = parse(3)?;
            let available = parse(4)?;
            let used = parse(5)?;
            let quality = sample_quality(&row.get::<_, String>(6)?)?;
            validate_sample_row(total, free, available, used, quality)?;
            Ok(VolumeSample {
                volume_id: row.get(0)?,
                sample_time: row.get(1)?,
                reserved_diff_bytes: match (free, available) {
                    (Some(f), Some(a)) => f.checked_sub(a),
                    _ => None,
                },
                total_bytes: total,
                free_bytes: free,
                available_bytes: available,
                used_bytes: used,
                quality,
                error: row.get(7)?,
                inserted: false,
            })
        })
        .map_err(|e| internal(format!("读取容量采样失败: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal(format!("读取容量采样失败: {e}")))?;
    Ok(rows)
}

// ---- identity (spec 4.3) ----

fn probe_capacity_identity(
    conn: &Connection,
    cfg: &DeploymentConfig,
    vol: &Volume,
) -> AppResult<Option<source::FsIdentity>> {
    let Some(sid) = &vol.capacity_source_id else {
        return Err(validation("该卷尚未确认容量采样源"));
    };
    let src = source::get_enabled_source(conn, sid)?;
    let mount = cfg
        .mount(&src.mount_key)
        .ok_or_else(|| validation(format!("未知的批准挂载键: {:?}", src.mount_key)))?;
    Ok(source::run_probe(mount, &src.raw_relative_root).fs_identity)
}

/// Confirm the volume's current filesystem identity: stores st_dev +
/// mountinfo fsid (when available) and marks the volume active.
pub fn confirm_volume_identity(
    conn: &Connection,
    cfg: &DeploymentConfig,
    volume_id: &str,
) -> AppResult<Volume> {
    let vol = get_volume(conn, volume_id)?;
    let identity = probe_capacity_identity(conn, cfg, &vol)?.ok_or_else(|| {
        AppError::new(
            ErrorCode::SourceUnavailable,
            "无法读取文件系统身份，容量源不可用，不能确认卷身份",
        )
    })?;
    let identity_json = serde_json::json!({
        "device_id": identity.device_id,
        "mount_fsid": identity.mount_fsid,
    });
    conn.execute(
        &format!(
            "UPDATE volumes SET identity_json = ?2, status = 'active', updated_at = {SQL_NOW} \
             WHERE id = ?1"
        ),
        params![volume_id, identity_json.to_string()],
    )
    .map_err(|e| internal(format!("确认卷身份失败: {e}")))?;
    get_volume(conn, volume_id)
}

/// Re-detect the filesystem identity. A different identity never inherits the
/// old one: identity_json is left untouched and the caller gets `Changed`
/// (spec 4.3: a new device on an old path must not silently take over). When
/// the capacity source is unavailable the volume is marked disconnected and
/// history is preserved.
pub fn redetect_volume_identity(
    conn: &Connection,
    cfg: &DeploymentConfig,
    volume_id: &str,
) -> AppResult<VolumeIdentityCheck> {
    let vol = get_volume(conn, volume_id)?;
    let probed = probe_capacity_identity(conn, cfg, &vol)?;
    let Some(identity) = probed else {
        conn.execute(
            &format!(
                "UPDATE volumes SET status = 'disconnected', updated_at = {SQL_NOW} WHERE id = ?1"
            ),
            params![volume_id],
        )
        .map_err(|e| internal(format!("更新卷状态失败: {e}")))?;
        return Ok(VolumeIdentityCheck {
            outcome: VolumeIdentityOutcome::Unavailable,
            volume: get_volume(conn, volume_id)?.to_dto(),
        });
    };
    let confirmed = vol
        .identity_json
        .get("device_id")
        .and_then(|v| v.as_str())
        .is_some();
    let outcome = if !confirmed || source::identity_differs(&vol.identity_json, &identity) {
        VolumeIdentityOutcome::Changed
    } else {
        VolumeIdentityOutcome::Unchanged
    };
    Ok(VolumeIdentityCheck {
        outcome,
        volume: vol.to_dto(),
    })
}

// ---- double-count guard (spec 4.3) ----

#[derive(Debug, Clone, Serialize)]
pub struct ConfirmedVolumeTotal {
    pub volume_id: String,
    pub volume_name: String,
    pub sample_time: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
}

/// Global capacity total: sums ONLY confirmed volumes (active, identity
/// confirmed, latest quality='ok' sample). Sources not attributed to a
/// confirmed volume are reported as a count, never folded into the total —
/// the UI must show "已确认卷容量 + 未归属源数", not a fake complete sum.
#[derive(Debug, Clone, Serialize)]
pub struct UsedCapacityTotals {
    pub confirmed_volumes: Vec<ConfirmedVolumeTotal>,
    pub total_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub unattributed_source_count: u64,
}

pub fn used_capacity_totals(conn: &Connection) -> AppResult<UsedCapacityTotals> {
    let volumes = list_volumes(conn)?;
    let mut confirmed = Vec::new();
    let mut confirmed_ids = std::collections::HashSet::new();
    for vol in &volumes {
        if !vol.is_confirmed() {
            continue;
        }
        let sample: Option<(String, String, String, String, String)> = conn
            .query_row(
                "SELECT sample_time, total_bytes, free_bytes, used_bytes, available_bytes \
                 FROM volume_samples WHERE volume_id = ?1 AND quality = 'ok' \
                 ORDER BY sample_time DESC LIMIT 1",
                params![vol.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()
            .map_err(|e| internal(format!("读取容量采样失败: {e}")))?;
        let Some((sample_time, total, free, used, avail)) = sample else {
            continue;
        };
        let parse = |s: &str, what: &str| -> AppResult<u64> {
            s.parse::<u64>()
                .map_err(|_| internal(format!("容量采样数据损坏（{what}）")))
        };
        let total_bytes = parse(&total, "total")?;
        let free_bytes = parse(&free, "free")?;
        let used_bytes = parse(&used, "used")?;
        let available_bytes = parse(&avail, "available")?;
        validate_capacity_numbers(total_bytes, free_bytes, available_bytes, used_bytes)
            .map_err(internal)?;
        confirmed_ids.insert(vol.id.clone());
        confirmed.push(ConfirmedVolumeTotal {
            volume_id: vol.id.clone(),
            volume_name: vol.name.clone(),
            sample_time,
            total_bytes,
            used_bytes,
            available_bytes,
        });
    }

    let sum = |confirmed: &[ConfirmedVolumeTotal],
               f: fn(&ConfirmedVolumeTotal) -> u64|
     -> AppResult<Option<u64>> {
        let mut acc: u64 = 0;
        for v in confirmed {
            acc = acc
                .checked_add(f(v))
                .ok_or_else(|| internal("全局容量合计溢出"))?;
        }
        Ok((!confirmed.is_empty()).then_some(acc))
    };
    let total_bytes = sum(&confirmed, |v| v.total_bytes)?;
    let used_bytes = sum(&confirmed, |v| v.used_bytes)?;
    let available_bytes = sum(&confirmed, |v| v.available_bytes)?;

    // Enabled sources not attributed to a confirmed volume.
    let mut stmt = conn
        .prepare("SELECT volume_id FROM sources WHERE disabled_at IS NULL")
        .map_err(|e| internal(format!("准备查询失败: {e}")))?;
    let unattributed = stmt
        .query_map([], |r| r.get::<_, Option<String>>(0))
        .map_err(|e| internal(format!("统计未归属源失败: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal(format!("统计未归属源失败: {e}")))?
        .into_iter()
        .filter(|vid| vid.as_ref().is_none_or(|v| !confirmed_ids.contains(v)))
        .count() as u64;

    Ok(UsedCapacityTotals {
        confirmed_volumes: confirmed,
        total_bytes,
        used_bytes,
        available_bytes,
        unattributed_source_count: unattributed,
    })
}

#[cfg(test)]
mod tests;
