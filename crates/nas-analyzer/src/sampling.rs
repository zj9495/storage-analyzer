//! Capacity sampling history, daily rollups, and report snapshots.
//!
//! Raw capacity observations live in the control database's
//! `volume_samples` table. `volume_samples_daily` is a derived table: it
//! contains only successfully observed capacity values and keeps the exact
//! decimal-string min/max/last values required by the data contract.
//! Report databases receive an immutable copy in `volume_samples_snapshot`.

use std::collections::BTreeMap;

use jiff::{Timestamp, tz::TimeZone};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::config::{DeploymentConfig, SamplingConfig};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::volume::{self, SampleQuality, VolumeSample};

fn internal(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, message)
}

fn validation(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, message)
}

/// Resolution accepted by the volume history query contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleResolution {
    Raw,
    Day,
}

impl SampleResolution {
    pub fn parse(value: &str) -> AppResult<Self> {
        match value {
            "raw" => Ok(Self::Raw),
            "day" => Ok(Self::Day),
            other => Err(validation(format!("未知的容量历史 resolution: {other:?}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Day => "day",
        }
    }
}

/// A daily capacity point. Byte values are decimal strings so a value above
/// JavaScript's safe integer range remains lossless.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DailyVolumeSample {
    pub volume_id: String,
    pub day: String,
    pub used_min: Option<String>,
    pub used_max: Option<String>,
    pub used_last: Option<String>,
    pub total_min: Option<String>,
    pub total_max: Option<String>,
    pub total_last: Option<String>,
    pub free_min: Option<String>,
    pub free_max: Option<String>,
    pub free_last: Option<String>,
    pub available_min: Option<String>,
    pub available_max: Option<String>,
    pub available_last: Option<String>,
    pub sample_count: i64,
}

/// Query contract for the persisted daily history. `cursor` is the last
/// returned UTC day and therefore acts as an ascending keyset cursor. Cursor
/// signing and binding it to the complete HTTP query remain responsibilities
/// of the HTTP layer; the data layer only owns the stable day key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailySampleQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub cursor: Option<String>,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DailySamplePage {
    pub items: Vec<DailyVolumeSample>,
    pub next_cursor: Option<String>,
}

/// The two history representations use the exact columns of their backing
/// tables. Raw points retain unavailable samples; daily points contain the
/// successful observations that can form a numeric rollup.
#[derive(Debug, Clone, Serialize)]
pub enum HistoryPoint {
    Raw(VolumeSample),
    Daily(DailyVolumeSample),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SamplePruneResult {
    pub raw_deleted: u64,
    pub daily_deleted: u64,
}

fn parse_decimal(raw: Option<String>, column: &str) -> rusqlite::Result<Option<u64>> {
    raw.map(|value| {
        value.parse::<u64>().map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid decimal in {column}: {error}"),
                )),
            )
        })
    })
    .transpose()
}

fn required_decimal(raw: Option<String>, column: &str) -> AppResult<u64> {
    let raw = raw.ok_or_else(|| internal(format!("容量采样缺少 {column} 字段")))?;
    raw.parse::<u64>()
        .map_err(|error| internal(format!("容量采样 {column} 不是合法十进制数: {error}")))
}

fn update_daily_range(
    min: &mut Option<u64>,
    max: &mut Option<u64>,
    last: &mut Option<u64>,
    value: u64,
) {
    *min = Some(min.map_or(value, |current| current.min(value)));
    *max = Some(max.map_or(value, |current| current.max(value)));
    *last = Some(value);
}

fn invalid_daily_range(column: &str, index: usize) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("容量日汇总 {column} 的 min/max/last 不完整或口径异常"),
        )),
    )
}

fn validate_daily_range(
    min: Option<u64>,
    max: Option<u64>,
    last: Option<u64>,
    column: &str,
    index: usize,
) -> rusqlite::Result<()> {
    match (min, max, last) {
        (None, None, None) => Ok(()),
        (Some(min), Some(max), Some(last)) if min <= max && last >= min && last <= max => Ok(()),
        _ => Err(invalid_daily_range(column, index)),
    }
}

fn daily_accumulator_from_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<DailyAccumulator> {
    let sample_count: i64 = row.get(offset + 12)?;
    if sample_count <= 0 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            offset + 12,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "容量日汇总 sample_count 必须为正数",
            )),
        ));
    }
    let used_min = parse_decimal(row.get(offset)?, "used_min")?.ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            offset,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "容量日汇总缺少 used_min",
            )),
        )
    })?;
    let used_max = parse_decimal(row.get(offset + 1)?, "used_max")?.ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            offset + 1,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "容量日汇总缺少 used_max",
            )),
        )
    })?;
    let used_last = parse_decimal(row.get(offset + 2)?, "used_last")?.ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            offset + 2,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "容量日汇总缺少 used_last",
            )),
        )
    })?;
    let total_min = parse_decimal(row.get(offset + 3)?, "total_min")?;
    let total_max = parse_decimal(row.get(offset + 4)?, "total_max")?;
    let total_last = parse_decimal(row.get(offset + 5)?, "total_last")?;
    let free_min = parse_decimal(row.get(offset + 6)?, "free_min")?;
    let free_max = parse_decimal(row.get(offset + 7)?, "free_max")?;
    let free_last = parse_decimal(row.get(offset + 8)?, "free_last")?;
    let available_min = parse_decimal(row.get(offset + 9)?, "available_min")?;
    let available_max = parse_decimal(row.get(offset + 10)?, "available_max")?;
    let available_last = parse_decimal(row.get(offset + 11)?, "available_last")?;
    validate_daily_range(
        Some(used_min),
        Some(used_max),
        Some(used_last),
        "used",
        offset,
    )?;
    validate_daily_range(total_min, total_max, total_last, "total", offset + 3)?;
    validate_daily_range(free_min, free_max, free_last, "free", offset + 6)?;
    validate_daily_range(
        available_min,
        available_max,
        available_last,
        "available",
        offset + 9,
    )?;
    Ok(DailyAccumulator {
        used_min: Some(used_min),
        used_max: Some(used_max),
        used_last: Some(used_last),
        sample_count,
        total_min,
        total_max,
        total_last,
        free_min,
        free_max,
        free_last,
        available_min,
        available_max,
        available_last,
    })
}

fn raw_sample_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<VolumeSample> {
    let total = parse_decimal(row.get(2)?, "total_bytes")?;
    let free = parse_decimal(row.get(3)?, "free_bytes")?;
    let available = parse_decimal(row.get(4)?, "available_bytes")?;
    let used = parse_decimal(row.get(5)?, "used_bytes")?;
    let quality = match row.get::<_, String>(6)?.as_str() {
        "ok" => SampleQuality::Ok,
        "error" => SampleQuality::Error,
        value => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown sample quality: {value}"),
                )),
            ));
        }
    };
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
        if let Err(message) = volume::validate_capacity_numbers(total, free, available, used) {
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
    Ok(VolumeSample {
        volume_id: row.get(0)?,
        sample_time: row.get(1)?,
        total_bytes: total,
        free_bytes: free,
        available_bytes: available,
        used_bytes: used,
        reserved_diff_bytes: match (free, available) {
            (Some(free), Some(available)) => free.checked_sub(available),
            _ => None,
        },
        quality,
        error: row.get(7)?,
        inserted: false,
    })
}

fn ensure_volume(conn: &Connection, volume_id: &str) -> AppResult<()> {
    volume::get_volume(conn, volume_id).map(|_| ())
}

fn parse_history_timestamp(raw: &str, field: &str) -> AppResult<Timestamp> {
    raw.parse::<Timestamp>()
        .map_err(|_| validation(format!("{field} 不是合法的 RFC3339 时间")))
}

fn parse_daily_cursor(raw: Option<&str>) -> AppResult<Option<String>> {
    raw.map(|value| {
        let day = value
            .parse::<jiff::civil::Date>()
            .map_err(|_| validation("容量日汇总游标无效"))?;
        let canonical = day.to_string();
        if canonical != value {
            return Err(validation("容量日汇总游标无效"));
        }
        Ok(canonical)
    })
    .transpose()
}

struct DailyWindow {
    from_day: Option<String>,
    to_day: Option<String>,
    to_includes_day: bool,
}

fn daily_window(from: Option<&str>, to: Option<&str>) -> AppResult<DailyWindow> {
    let from_timestamp = from
        .map(|value| parse_history_timestamp(value, "from"))
        .transpose()?;
    let to_timestamp = to
        .map(|value| parse_history_timestamp(value, "to"))
        .transpose()?;
    if let (Some(from), Some(to)) = (&from_timestamp, &to_timestamp)
        && from >= to
    {
        return Err(validation("采样历史时间范围必须为半开区间 [from, to)"));
    }

    let from_day =
        from_timestamp.map(|timestamp| timestamp.to_zoned(TimeZone::UTC).date().to_string());
    let (to_day, to_includes_day) = match to_timestamp {
        Some(timestamp) => {
            let datetime = timestamp.to_zoned(TimeZone::UTC).datetime();
            let time = datetime.time();
            let includes_day = time.hour() != 0
                || time.minute() != 0
                || time.second() != 0
                || time.subsec_nanosecond() != 0;
            (Some(datetime.date().to_string()), includes_day)
        }
        None => (None, false),
    };
    Ok(DailyWindow {
        from_day,
        to_day,
        to_includes_day,
    })
}

/// Collect all volumes and take one capacity observation for each. The
/// underlying sampler records an unavailable row when a volume cannot be
/// read, so a disconnected volume remains a visible hole rather than being
/// converted to zero.
pub fn sample_all_volumes(
    conn: &Connection,
    cfg: &DeploymentConfig,
) -> AppResult<Vec<VolumeSample>> {
    volume::list_volumes(conn)?
        .into_iter()
        .map(|volume| volume::sample_capacity(conn, cfg, &volume.id))
        .collect()
}

/// Read raw observations in chronological order over the half-open window
/// `[from, to)`. `sample_time` is stored in the fixed-width UTC format used
/// by the migrations, so string comparison is chronological.
pub fn list_raw_samples(
    conn: &Connection,
    volume_id: &str,
    from: Option<&str>,
    to: Option<&str>,
    limit: u32,
) -> AppResult<Vec<VolumeSample>> {
    ensure_volume(conn, volume_id)?;
    if let (Some(from), Some(to)) = (from, to)
        && from >= to
    {
        return Err(validation("采样历史时间范围必须为半开区间 [from, to)"));
    }
    let mut stmt = conn
        .prepare(
            "SELECT volume_id, sample_time, total_bytes, free_bytes, available_bytes, \
             used_bytes, quality, error FROM volume_samples \
             WHERE volume_id = ?1 AND (?2 IS NULL OR sample_time >= ?2) \
             AND (?3 IS NULL OR sample_time < ?3) \
             ORDER BY sample_time ASC LIMIT ?4",
        )
        .map_err(|error| internal(format!("准备容量历史查询失败: {error}")))?;
    stmt.query_map(params![volume_id, from, to, limit], raw_sample_from_row)
        .map_err(|error| internal(format!("读取容量历史失败: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal(format!("解析容量历史失败: {error}")))
}

pub fn list_daily_samples(
    conn: &Connection,
    volume_id: &str,
    from: Option<&str>,
    to: Option<&str>,
    limit: u32,
) -> AppResult<Vec<DailyVolumeSample>> {
    let page = list_daily_samples_page(
        conn,
        volume_id,
        &DailySampleQuery {
            from: from.map(str::to_owned),
            to: to.map(str::to_owned),
            cursor: None,
            limit,
        },
    )?;
    Ok(page.items)
}

/// Read persisted daily rollups using an ascending day keyset page. The
/// query never reads `volume_samples`; after a daily rollup is persisted it
/// remains queryable even when raw samples have been pruned.
pub fn list_daily_samples_page(
    conn: &Connection,
    volume_id: &str,
    query: &DailySampleQuery,
) -> AppResult<DailySamplePage> {
    ensure_volume(conn, volume_id)?;
    if query.limit == 0 {
        return Err(validation("容量历史 limit 必须大于 0"));
    }
    let limit =
        usize::try_from(query.limit).map_err(|_| internal("容量历史 limit 超出当前平台范围"))?;
    let window = daily_window(query.from.as_deref(), query.to.as_deref())?;
    let cursor = parse_daily_cursor(query.cursor.as_deref())?;
    let sql_limit = i64::from(
        query
            .limit
            .checked_add(1)
            .ok_or_else(|| internal("容量历史 limit 溢出"))?,
    );
    let mut stmt = conn
        .prepare(
            "SELECT volume_id, day, used_min, used_max, used_last, total_min, total_max, total_last, free_min, free_max, free_last, available_min, available_max, available_last, sample_count \
             FROM volume_samples_daily WHERE volume_id = ?1 \
             AND (?2 IS NULL OR day >= ?2) \
             AND (?3 IS NULL OR day < ?3 OR (?4 = 1 AND day = ?3)) \
             AND (?5 IS NULL OR day > ?5) \
             ORDER BY day ASC LIMIT ?6",
        )
        .map_err(|error| internal(format!("准备日容量趋势查询失败: {error}")))?;
    let rows = stmt
        .query_map(
            params![
                volume_id,
                window.from_day,
                window.to_day,
                window.to_includes_day,
                cursor,
                sql_limit
            ],
            |row| {
                let values = daily_accumulator_from_row(row, 2)?;
                Ok(DailyVolumeSample {
                    volume_id: row.get(0)?,
                    day: row.get(1)?,
                    used_min: values.used_min.map(|value| value.to_string()),
                    used_max: values.used_max.map(|value| value.to_string()),
                    used_last: values.used_last.map(|value| value.to_string()),
                    total_min: values.total_min.map(|v| v.to_string()),
                    total_max: values.total_max.map(|v| v.to_string()),
                    total_last: values.total_last.map(|v| v.to_string()),
                    free_min: values.free_min.map(|v| v.to_string()),
                    free_max: values.free_max.map(|v| v.to_string()),
                    free_last: values.free_last.map(|v| v.to_string()),
                    available_min: values.available_min.map(|v| v.to_string()),
                    available_max: values.available_max.map(|v| v.to_string()),
                    available_last: values.available_last.map(|v| v.to_string()),
                    sample_count: values.sample_count,
                })
            },
        )
        .map_err(|error| internal(format!("读取日容量趋势失败: {error}")))?;
    let mut items = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal(format!("解析日容量趋势失败: {error}")))?;
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|item| item.day.clone())
    } else {
        None
    };
    Ok(DailySamplePage { items, next_cursor })
}

/// Read either raw points or daily points using the same history window.
pub fn list_history(
    conn: &Connection,
    volume_id: &str,
    resolution: SampleResolution,
    from: Option<&str>,
    to: Option<&str>,
    limit: u32,
) -> AppResult<Vec<HistoryPoint>> {
    match resolution {
        SampleResolution::Raw => list_raw_samples(conn, volume_id, from, to, limit)
            .map(|samples| samples.into_iter().map(HistoryPoint::Raw).collect()),
        SampleResolution::Day => list_daily_samples(conn, volume_id, from, to, limit)
            .map(|samples| samples.into_iter().map(HistoryPoint::Daily).collect()),
    }
}

#[derive(Debug, Default)]
struct DailyAccumulator {
    used_min: Option<u64>,
    used_max: Option<u64>,
    used_last: Option<u64>,
    sample_count: i64,
    total_min: Option<u64>,
    total_max: Option<u64>,
    total_last: Option<u64>,
    free_min: Option<u64>,
    free_max: Option<u64>,
    free_last: Option<u64>,
    available_min: Option<u64>,
    available_max: Option<u64>,
    available_last: Option<u64>,
}

/// Refresh the daily rollup for one volume from retained successful raw
/// observations while preserving already compacted days whose raw rows have
/// expired. Decimal strings are compared as parsed `u64` values, not with
/// SQLite's signed integer or text coercions.
pub fn aggregate_daily_samples(conn: &mut Connection, volume_id: &str) -> AppResult<u64> {
    ensure_volume(conn, volume_id)?;
    let mut grouped = BTreeMap::<String, DailyAccumulator>::new();
    let mut existing = conn
        .prepare(
            "SELECT day, used_min, used_max, used_last, total_min, total_max, total_last, free_min, free_max, free_last, available_min, available_max, available_last, sample_count \
             FROM volume_samples_daily WHERE volume_id = ?1",
        )
        .map_err(|error| internal(format!("准备读取已有容量日汇总失败: {error}")))?;
    let existing_rows = existing
        .query_map(params![volume_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                daily_accumulator_from_row(row, 1)?,
            ))
        })
        .map_err(|error| internal(format!("读取已有容量日汇总失败: {error}")))?;
    for row in existing_rows {
        let (day, values) =
            row.map_err(|error| internal(format!("解析已有容量日汇总失败: {error}")))?;
        grouped.insert(day, values);
    }
    drop(existing);

    let mut rebuilt = BTreeMap::<String, DailyAccumulator>::new();
    let mut stmt = conn
        .prepare(
            "SELECT substr(sample_time, 1, 10), total_bytes, free_bytes, available_bytes, used_bytes FROM volume_samples \
             WHERE volume_id = ?1 AND quality = 'ok' \
             ORDER BY sample_time ASC",
        )
        .map_err(|error| internal(format!("准备容量日汇总查询失败: {error}")))?;
    let rows = stmt
        .query_map(params![volume_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(|error| internal(format!("读取容量日汇总源数据失败: {error}")))?;
    for row in rows {
        let (day, total_raw, free_raw, available_raw, used_raw) =
            row.map_err(|error| internal(format!("读取容量日汇总源数据失败: {error}")))?;
        let total = required_decimal(total_raw, "total_bytes")?;
        let free = required_decimal(free_raw, "free_bytes")?;
        let available = required_decimal(available_raw, "available_bytes")?;
        let used = required_decimal(used_raw, "used_bytes")?;
        if let Err(message) = volume::validate_capacity_numbers(total, free, available, used) {
            return Err(internal(message));
        }
        let entry = rebuilt.entry(day).or_default();
        update_daily_range(
            &mut entry.total_min,
            &mut entry.total_max,
            &mut entry.total_last,
            total,
        );
        update_daily_range(
            &mut entry.free_min,
            &mut entry.free_max,
            &mut entry.free_last,
            free,
        );
        update_daily_range(
            &mut entry.available_min,
            &mut entry.available_max,
            &mut entry.available_last,
            available,
        );
        update_daily_range(
            &mut entry.used_min,
            &mut entry.used_max,
            &mut entry.used_last,
            used,
        );
        entry.sample_count = entry
            .sample_count
            .checked_add(1)
            .ok_or_else(|| internal("容量日汇总 sample_count 溢出"))?;
    }
    drop(stmt);

    for (day, values) in rebuilt {
        grouped.insert(day, values);
    }

    let tx = conn
        .transaction()
        .map_err(|error| internal(format!("开启容量日汇总事务失败: {error}")))?;
    tx.execute(
        "DELETE FROM volume_samples_daily WHERE volume_id = ?1",
        params![volume_id],
    )
    .map_err(|error| internal(format!("清理旧容量日汇总失败: {error}")))?;
    for (day, values) in &grouped {
        let used_min = values
            .used_min
            .ok_or_else(|| internal("容量日汇总缺少 used_min"))?;
        let used_max = values
            .used_max
            .ok_or_else(|| internal("容量日汇总缺少 used_max"))?;
        let used_last = values
            .used_last
            .ok_or_else(|| internal("容量日汇总缺少 used_last"))?;
        tx.execute(
            "INSERT INTO volume_samples_daily \
             (volume_id, day, used_min, used_max, used_last, total_min, total_max, total_last, free_min, free_max, free_last, available_min, available_max, available_last, sample_count) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                volume_id,
                day,
                used_min.to_string(),
                used_max.to_string(),
                used_last.to_string(),
                values.total_min.map(|v| v.to_string()), values.total_max.map(|v| v.to_string()), values.total_last.map(|v| v.to_string()), values.free_min.map(|v| v.to_string()), values.free_max.map(|v| v.to_string()), values.free_last.map(|v| v.to_string()), values.available_min.map(|v| v.to_string()), values.available_max.map(|v| v.to_string()), values.available_last.map(|v| v.to_string()),
                values.sample_count
            ],
        )
        .map_err(|error| internal(format!("写入容量日汇总失败: {error}")))?;
    }
    tx.commit()
        .map_err(|error| internal(format!("提交容量日汇总失败: {error}")))?;
    u64::try_from(grouped.len()).map_err(|_| internal("容量日汇总数量溢出"))
}

/// Rebuild all volume daily rollups. Volume identities and availability do
/// not alter historical rows, so disconnected volumes are included too.
pub fn aggregate_all_daily_samples(conn: &mut Connection) -> AppResult<u64> {
    let volume_ids = volume::list_volumes(conn)?
        .into_iter()
        .map(|volume| volume.id)
        .collect::<Vec<_>>();
    let mut days = 0_u64;
    for volume_id in volume_ids {
        days = days
            .checked_add(aggregate_daily_samples(conn, &volume_id)?)
            .ok_or_else(|| internal("容量日汇总数量溢出"))?;
    }
    Ok(days)
}

/// Delete only rows older than the configured raw/daily horizons. `now` is
/// explicit so maintenance can be tested at a fixed UTC instant and does not
/// silently depend on the host clock.
pub fn prune_history_at(
    conn: &mut Connection,
    config: &SamplingConfig,
    now: &str,
) -> AppResult<SamplePruneResult> {
    if config.raw_retention_days == 0 || config.daily_retention_days == 0 {
        return Err(validation("容量历史保留天数必须大于 0"));
    }
    let tx = conn
        .transaction()
        .map_err(|error| internal(format!("开启容量历史清理事务失败: {error}")))?;
    let raw_deleted = tx
        .execute(
            "DELETE FROM volume_samples WHERE sample_time < \
             strftime('%Y-%m-%dT%H:%M:00.000Z', \
             datetime(?1, printf('-%d days', ?2)))",
            params![now, i64::from(config.raw_retention_days)],
        )
        .map_err(|error| internal(format!("清理原始容量历史失败: {error}")))?;
    let daily_deleted = tx
        .execute(
            "DELETE FROM volume_samples_daily WHERE day < \
             strftime('%Y-%m-%d', datetime(?1, printf('-%d days', ?2)))",
            params![now, i64::from(config.daily_retention_days)],
        )
        .map_err(|error| internal(format!("清理日容量历史失败: {error}")))?;
    tx.commit()
        .map_err(|error| internal(format!("提交容量历史清理失败: {error}")))?;
    Ok(SamplePruneResult {
        raw_deleted: u64::try_from(raw_deleted).map_err(|_| internal("原始容量历史删除数溢出"))?,
        daily_deleted: u64::try_from(daily_deleted)
            .map_err(|_| internal("日容量历史删除数溢出"))?,
    })
}

/// Rebuild daily rollups before pruning raw rows, then apply both configured
/// retention horizons.
pub fn maintain_history(
    conn: &mut Connection,
    config: &SamplingConfig,
    now: &str,
) -> AppResult<SamplePruneResult> {
    aggregate_all_daily_samples(conn)?;
    prune_history_at(conn, config, now)
}

fn write_report_sample(report_conn: &Connection, sample: &VolumeSample) -> AppResult<()> {
    let quality = match sample.quality {
        SampleQuality::Ok => "ok",
        SampleQuality::Error => "error",
    };
    report_conn
        .execute(
            "INSERT OR IGNORE INTO volume_samples_snapshot \
             (volume_id, sample_time, total_bytes, free_bytes, available_bytes, used_bytes, quality) \
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
        .map_err(|error| internal(format!("写入报告容量快照失败: {error}")))?;
    Ok(())
}

/// Copy the latest raw sample for each requested volume into a report
/// database. The report database is separate from the control database and
/// therefore receives values through explicit parameters, preserving the
/// report's immutability after publication.
pub fn snapshot_latest_samples(
    control_conn: &Connection,
    report_conn: &mut Connection,
    volume_ids: &[String],
) -> AppResult<u64> {
    let mut latest = Vec::with_capacity(volume_ids.len());
    for volume_id in volume_ids {
        ensure_volume(control_conn, volume_id)?;
        let sample = control_conn
            .query_row(
                "SELECT volume_id, sample_time, total_bytes, free_bytes, available_bytes, \
                 used_bytes, quality, error FROM volume_samples WHERE volume_id = ?1 \
                 ORDER BY sample_time DESC LIMIT 1",
                params![volume_id],
                raw_sample_from_row,
            )
            .optional()
            .map_err(|error| internal(format!("读取报告容量快照源失败: {error}")))?;
        if let Some(sample) = sample {
            latest.push(sample);
        }
    }
    let tx = report_conn
        .transaction()
        .map_err(|error| internal(format!("开启报告容量快照事务失败: {error}")))?;
    for sample in &latest {
        write_report_sample(&tx, sample)?;
    }
    tx.commit()
        .map_err(|error| internal(format!("提交报告容量快照失败: {error}")))?;
    u64::try_from(latest.len()).map_err(|_| internal("报告容量快照数量溢出"))
}

/// Read the newest retained sample for each requested volume without writing
/// to the control database. The caller uses the returned values to build an
/// immutable report snapshot on a separate report connection.
pub fn latest_samples(
    control_conn: &Connection,
    volume_ids: &[String],
) -> AppResult<Vec<VolumeSample>> {
    let mut latest = Vec::with_capacity(volume_ids.len());
    for volume_id in volume_ids {
        ensure_volume(control_conn, volume_id)?;
        let sample = control_conn
            .query_row(
                "SELECT volume_id, sample_time, total_bytes, free_bytes, available_bytes, \
                 used_bytes, quality, error FROM volume_samples WHERE volume_id = ?1 \
                 ORDER BY sample_time DESC LIMIT 1",
                params![volume_id],
                raw_sample_from_row,
            )
            .optional()
            .map_err(|error| internal(format!("读取最新容量采样失败: {error}")))?;
        if let Some(sample) = sample {
            latest.push(sample);
        }
    }
    Ok(latest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;
    use crate::store::migrate::{self, CONTROL_MIGRATIONS, REPORT_MIGRATIONS};

    fn control() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate::apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        conn.execute(
            "INSERT INTO volumes (id, name, created_at, updated_at) \
             VALUES ('volume-1', '测试卷', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        conn
    }

    fn insert_sample(conn: &Connection, time: &str, used: Option<&str>, quality: &str) {
        let total = used
            .and_then(|value| value.parse::<u64>().ok())
            .map_or_else(|| "0".to_string(), |value| (value + 1).to_string());
        let free = if used.is_some() { "1" } else { "0" };
        conn.execute(
            "INSERT INTO volume_samples \
             (volume_id, sample_time, total_bytes, free_bytes, available_bytes, used_bytes, quality, error) \
             VALUES ('volume-1', ?1, ?2, ?3, '0', ?4, ?5, NULL)",
            params![time, total, free, used, quality],
        )
        .unwrap();
    }

    fn insert_ok_capacity_sample(
        conn: &Connection,
        time: &str,
        total: u64,
        free: u64,
        available: u64,
    ) {
        let used = total.checked_sub(free).unwrap();
        conn.execute(
            "INSERT INTO volume_samples \
             (volume_id, sample_time, total_bytes, free_bytes, available_bytes, used_bytes, quality, error) \
             VALUES ('volume-1', ?1, ?2, ?3, ?4, ?5, 'ok', NULL)",
            params![
                time,
                total.to_string(),
                free.to_string(),
                available.to_string(),
                used.to_string()
            ],
        )
        .unwrap();
    }

    #[test]
    fn daily_rollup_preserves_decimal_string_order_and_last_value() {
        let mut conn = control();
        insert_sample(&conn, "2026-01-02T01:00:00.000Z", Some("9"), "ok");
        insert_sample(&conn, "2026-01-02T02:00:00.000Z", Some("10"), "ok");
        insert_sample(&conn, "2026-01-02T03:00:00.000Z", None, "error");
        aggregate_daily_samples(&mut conn, "volume-1").unwrap();
        let row: (String, String, String, i64) = conn
            .query_row(
                "SELECT used_min, used_max, used_last, sample_count FROM volume_samples_daily",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(row, ("9".into(), "10".into(), "10".into(), 2));
    }

    #[test]
    fn daily_rollup_aggregates_all_capacity_ranges_and_reads_them() {
        let mut conn = control();
        insert_ok_capacity_sample(&conn, "2026-01-02T01:00:00.000Z", 100, 40, 30);
        insert_ok_capacity_sample(&conn, "2026-01-02T02:00:00.000Z", 90, 20, 10);
        insert_ok_capacity_sample(&conn, "2026-01-02T03:00:00.000Z", 110, 50, 45);

        aggregate_daily_samples(&mut conn, "volume-1").unwrap();

        assert_eq!(
            list_daily_samples(&conn, "volume-1", None, None, 10).unwrap(),
            vec![DailyVolumeSample {
                volume_id: "volume-1".to_string(),
                day: "2026-01-02".to_string(),
                used_min: Some("60".to_string()),
                used_max: Some("70".to_string()),
                used_last: Some("60".to_string()),
                total_min: Some("90".to_string()),
                total_max: Some("110".to_string()),
                total_last: Some("110".to_string()),
                free_min: Some("20".to_string()),
                free_max: Some("50".to_string()),
                free_last: Some("50".to_string()),
                available_min: Some("10".to_string()),
                available_max: Some("45".to_string()),
                available_last: Some("45".to_string()),
                sample_count: 3,
            }]
        );
    }

    #[test]
    fn daily_rollup_rejects_an_incomplete_ok_capacity_sample() {
        let mut conn = control();
        conn.execute(
            "INSERT INTO volume_samples \
             (volume_id, sample_time, total_bytes, free_bytes, available_bytes, used_bytes, quality, error) \
             VALUES ('volume-1', '2026-01-02T01:00:00.000Z', NULL, '40', '30', '60', 'ok', NULL)",
            [],
        )
        .unwrap();

        assert_eq!(
            aggregate_daily_samples(&mut conn, "volume-1")
                .unwrap_err()
                .code,
            ErrorCode::Internal
        );
        let daily_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM volume_samples_daily", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(daily_count, 0);
    }

    #[test]
    fn daily_rollup_preserves_compacted_history_after_raw_prune() {
        let mut conn = control();
        conn.execute(
            "INSERT INTO volume_samples_daily \
             (volume_id, day, used_min, used_max, used_last, sample_count) \
             VALUES ('volume-1', '2025-01-01', '1', '3', '2', 4)",
            [],
        )
        .unwrap();
        insert_sample(&conn, "2026-01-02T01:00:00.000Z", Some("10"), "ok");

        let config = SamplingConfig {
            interval_minutes: 60,
            raw_retention_days: 1,
            daily_retention_days: 1825,
        };
        maintain_history(&mut conn, &config, "2026-01-04T00:00:00.000Z").unwrap();

        let rows: Vec<(String, String, String, String, i64)> = conn
            .prepare(
                "SELECT day, used_min, used_max, used_last, sample_count \
                 FROM volume_samples_daily ORDER BY day",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("2025-01-01".into(), "1".into(), "3".into(), "2".into(), 4),
                (
                    "2026-01-02".into(),
                    "10".into(),
                    "10".into(),
                    "10".into(),
                    1
                ),
            ]
        );
        let raw_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM volume_samples", [], |row| row.get(0))
            .unwrap();
        assert_eq!(raw_count, 0);
    }

    #[test]
    fn daily_rollup_rejects_negative_raw_used_bytes() {
        let mut conn = control();
        insert_sample(&conn, "2026-01-02T01:00:00.000Z", Some("-1"), "ok");
        let error = aggregate_daily_samples(&mut conn, "volume-1").unwrap_err();
        assert_eq!(error.code, ErrorCode::Internal);
        let daily_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM volume_samples_daily WHERE volume_id = 'volume-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(daily_count, 0);
    }

    #[test]
    fn history_keeps_error_rows_and_applies_half_open_window() {
        let conn = control();
        insert_sample(&conn, "2026-01-02T01:00:00.000Z", Some("1"), "ok");
        insert_sample(&conn, "2026-01-02T02:00:00.000Z", None, "error");
        let rows = list_raw_samples(
            &conn,
            "volume-1",
            Some("2026-01-02T01:00:00.000Z"),
            Some("2026-01-02T02:00:00.000Z"),
            20,
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].used_bytes, Some(1));
    }

    #[test]
    fn daily_history_includes_a_day_when_to_is_inside_that_day() {
        let mut conn = control();
        insert_sample(&conn, "2026-01-02T02:00:00.000Z", Some("9"), "ok");
        aggregate_daily_samples(&mut conn, "volume-1").unwrap();
        let rows = list_daily_samples(
            &conn,
            "volume-1",
            Some("2026-01-02T01:00:00.000Z"),
            Some("2026-01-02T03:00:00.000Z"),
            20,
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].day, "2026-01-02");
    }

    #[test]
    fn daily_history_pages_persisted_rollups_beyond_raw_fetch_limit() {
        let mut conn = control();
        for index in 0..1001 {
            let hour = index / 60;
            let minute = index % 60;
            let time = format!("2026-01-01T{hour:02}:{minute:02}:00.000Z");
            let used = (1000 + index).to_string();
            insert_sample(&conn, &time, Some(&used), "ok");
        }
        for index in 0..1000 {
            let hour = index / 60;
            let minute = index % 60;
            let time = format!("2026-01-02T{hour:02}:{minute:02}:00.000Z");
            let used = (5000 - index).to_string();
            insert_sample(&conn, &time, Some(&used), "ok");
        }
        let raw_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM volume_samples", [], |row| row.get(0))
            .unwrap();
        assert_eq!(raw_count, 2001);

        aggregate_daily_samples(&mut conn, "volume-1").unwrap();
        conn.execute("DELETE FROM volume_samples", []).unwrap();
        let raw_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM volume_samples", [], |row| row.get(0))
            .unwrap();
        assert_eq!(raw_count, 0);

        let first = list_daily_samples_page(
            &conn,
            "volume-1",
            &DailySampleQuery {
                from: Some("2026-01-01T00:00:00Z".to_string()),
                to: Some("2026-01-03T00:00:00Z".to_string()),
                cursor: None,
                limit: 1,
            },
        )
        .unwrap();
        assert_eq!(
            first.items,
            vec![DailyVolumeSample {
                volume_id: "volume-1".to_string(),
                day: "2026-01-01".to_string(),
                used_min: Some("1000".to_string()),
                used_max: Some("2000".to_string()),
                used_last: Some("2000".to_string()),
                total_min: Some("1001".to_string()),
                total_max: Some("2001".to_string()),
                total_last: Some("2001".to_string()),
                free_min: Some("1".to_string()),
                free_max: Some("1".to_string()),
                free_last: Some("1".to_string()),
                available_min: Some("0".to_string()),
                available_max: Some("0".to_string()),
                available_last: Some("0".to_string()),
                sample_count: 1001,
            }]
        );
        assert_eq!(first.next_cursor.as_deref(), Some("2026-01-01"));

        let second = list_daily_samples_page(
            &conn,
            "volume-1",
            &DailySampleQuery {
                from: Some("2026-01-01T00:00:00Z".to_string()),
                to: Some("2026-01-03T00:00:00Z".to_string()),
                cursor: first.next_cursor,
                limit: 1,
            },
        )
        .unwrap();
        assert_eq!(
            second.items,
            vec![DailyVolumeSample {
                volume_id: "volume-1".to_string(),
                day: "2026-01-02".to_string(),
                used_min: Some("4001".to_string()),
                used_max: Some("5000".to_string()),
                used_last: Some("4001".to_string()),
                total_min: Some("4002".to_string()),
                total_max: Some("5001".to_string()),
                total_last: Some("4002".to_string()),
                free_min: Some("1".to_string()),
                free_max: Some("1".to_string()),
                free_last: Some("1".to_string()),
                available_min: Some("0".to_string()),
                available_max: Some("0".to_string()),
                available_last: Some("0".to_string()),
                sample_count: 1000,
            }]
        );
        assert_eq!(second.next_cursor, None);
    }

    #[test]
    fn daily_history_page_rejects_invalid_window_cursor_and_limit() {
        let conn = control();
        let query = |from: Option<&str>, to: Option<&str>, cursor: Option<&str>, limit| {
            list_daily_samples_page(
                &conn,
                "volume-1",
                &DailySampleQuery {
                    from: from.map(str::to_owned),
                    to: to.map(str::to_owned),
                    cursor: cursor.map(str::to_owned),
                    limit,
                },
            )
        };

        assert_eq!(
            query(None, None, None, 0).unwrap_err().code,
            ErrorCode::ValidationFailed
        );
        assert_eq!(
            query(
                Some("2026-01-02T00:00:00Z"),
                Some("2026-01-01T00:00:00Z"),
                None,
                1,
            )
            .unwrap_err()
            .code,
            ErrorCode::ValidationFailed
        );
        assert_eq!(
            query(None, None, Some("2026-01-01T00:00:00.000Z"), 1)
                .unwrap_err()
                .code,
            ErrorCode::ValidationFailed
        );
    }

    #[test]
    fn snapshot_uses_report_persistence_table() {
        let conn = control();
        insert_sample(&conn, "2026-01-02T01:00:00.000Z", Some("10"), "ok");
        let mut report = Connection::open_in_memory().unwrap();
        migrate::apply(&mut report, REPORT_MIGRATIONS).unwrap();
        assert_eq!(
            snapshot_latest_samples(&conn, &mut report, &["volume-1".into()]).unwrap(),
            1
        );
        let used: String = report
            .query_row(
                "SELECT used_bytes FROM volume_samples_snapshot WHERE volume_id = 'volume-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(used, "10");
    }
}
