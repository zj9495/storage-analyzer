//! Report exports.
//!
//! The report query layer owns the SQL and supplies an [`ExportRows`] source.
//! This module owns the wire contract and the four export encodings. Every
//! encoding consumes rows incrementally; ZIP reopens the same query for each
//! member instead of retaining the result set in memory.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::error::ErrorCode;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub type ExportResult<T> = Result<T, ExportError>;

/// Fields required in every exported row, in CSV/HTML order.
pub const BASE_EXPORT_FIELDS: [&str; 10] = [
    "report_id",
    "source_name",
    "relative_path_display",
    "owner_uid",
    "category",
    "logical_size_bytes",
    "allocated_size_estimate_bytes",
    "mtime",
    "atime",
    "status",
];

const CATEGORY_IDS: [&str; 9] = [
    "audio",
    "disk_images",
    "documents",
    "executables",
    "pictures",
    "videos",
    "web_and_code",
    "archives",
    "other",
];

pub const FULL_REPORT_SECTIONS: [ExportSection; 10] = [
    ExportSection::Volume,
    ExportSection::Folders,
    ExportSection::Owners,
    ExportSection::Quota,
    ExportSection::Categories,
    ExportSection::Duplicates,
    ExportSection::Largest,
    ExportSection::RecentlyModified,
    ExportSection::LeastAccessed,
    ExportSection::Files,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Json,
    Html,
    Zip,
}

impl ExportFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json => "json",
            Self::Html => "html",
            Self::Zip => "zip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportSection {
    Volume,
    Folders,
    Owners,
    Quota,
    Categories,
    Duplicates,
    Largest,
    RecentlyModified,
    LeastAccessed,
    Files,
    FullReport,
}

impl ExportSection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Volume => "volume",
            Self::Folders => "folders",
            Self::Owners => "owners",
            Self::Quota => "quota",
            Self::Categories => "categories",
            Self::Duplicates => "duplicates",
            Self::Largest => "largest",
            Self::RecentlyModified => "recently_modified",
            Self::LeastAccessed => "least_accessed",
            Self::Files => "files",
            Self::FullReport => "full_report",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportScope {
    Current,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    #[default]
    LogicalBytes,
    AllocatedEstimateBytes,
    FileCount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SortKey {
    #[default]
    SizeDesc,
    SizeAsc,
    MtimeDesc,
    MtimeAsc,
    AtimeDesc,
    AtimeAsc,
    NameAsc,
    CountDesc,
}

/// The query contract shared by report pages and all export formats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuerySpec {
    #[serde(default)]
    pub source_ids: Vec<String>,
    #[serde(default)]
    pub directory_entry_id: Option<String>,
    #[serde(default = "default_true")]
    pub include_descendants: bool,
    #[serde(default)]
    pub category_ids: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub owner_uids: Vec<i64>,
    #[serde(default)]
    pub name_contains: Option<String>,
    #[serde(default)]
    pub min_size_bytes: Option<String>,
    #[serde(default)]
    pub max_size_bytes: Option<String>,
    #[serde(default)]
    pub mtime_from: Option<String>,
    #[serde(default)]
    pub mtime_to: Option<String>,
    #[serde(default)]
    pub atime_from: Option<String>,
    #[serde(default)]
    pub atime_to: Option<String>,
    #[serde(default)]
    pub metric: Metric,
    #[serde(default)]
    pub sort: SortKey,
}

impl Default for QuerySpec {
    fn default() -> Self {
        Self {
            source_ids: Vec::new(),
            directory_entry_id: None,
            include_descendants: true,
            category_ids: Vec::new(),
            extensions: Vec::new(),
            owner_uids: Vec::new(),
            name_contains: None,
            min_size_bytes: None,
            max_size_bytes: None,
            mtime_from: None,
            mtime_to: None,
            atime_from: None,
            atime_to: None,
            metric: Metric::default(),
            sort: SortKey::default(),
        }
    }
}

fn default_true() -> bool {
    true
}

impl QuerySpec {
    /// Validate and canonicalize the query before it is sent to SQL or put in
    /// a manifest. Array fields are set-valued in the HTTP contract, so their
    /// canonical order is sorted and duplicates are removed.
    pub fn normalize(&self) -> ExportResult<Self> {
        let mut normalized = self.clone();
        normalized.source_ids = canonical_source_ids(&self.source_ids)?;
        normalized.category_ids = canonical_categories(&self.category_ids)?;
        normalized.extensions = canonical_extensions(&self.extensions)?;
        normalized.owner_uids = canonical_numbers(&self.owner_uids);
        normalized.directory_entry_id =
            canonical_optional_decimal(self.directory_entry_id.as_deref(), "directory_entry_id")?;
        normalized.min_size_bytes =
            canonical_optional_decimal(self.min_size_bytes.as_deref(), "min_size_bytes")?;
        normalized.max_size_bytes =
            canonical_optional_decimal(self.max_size_bytes.as_deref(), "max_size_bytes")?;
        normalized.mtime_from = canonical_optional_time(self.mtime_from.as_deref(), "mtime_from")?;
        normalized.mtime_to = canonical_optional_time(self.mtime_to.as_deref(), "mtime_to")?;
        normalized.atime_from = canonical_optional_time(self.atime_from.as_deref(), "atime_from")?;
        normalized.atime_to = canonical_optional_time(self.atime_to.as_deref(), "atime_to")?;

        if let (Some(min), Some(max)) = (
            normalized.min_size_bytes.as_deref(),
            normalized.max_size_bytes.as_deref(),
        ) && decimal_cmp(min, max) == std::cmp::Ordering::Greater
        {
            return Err(ExportError::InvalidQuery {
                field: "min_size_bytes",
                message: "不能大于 max_size_bytes".into(),
            });
        }
        if let (Some(from), Some(to)) = (
            normalized.mtime_from.as_deref(),
            normalized.mtime_to.as_deref(),
        ) && from >= to
        {
            return Err(ExportError::InvalidQuery {
                field: "mtime_from",
                message: "时间范围必须是左闭右开且 from 小于 to".into(),
            });
        }
        if let (Some(from), Some(to)) = (
            normalized.atime_from.as_deref(),
            normalized.atime_to.as_deref(),
        ) && from >= to
        {
            return Err(ExportError::InvalidQuery {
                field: "atime_from",
                message: "时间范围必须是左闭右开且 from 小于 to".into(),
            });
        }
        Ok(normalized)
    }

    /// SHA-256 of the canonical serialized QuerySpec in lowercase hex.
    pub fn query_hash(&self) -> ExportResult<String> {
        let normalized = self.normalize()?;
        let bytes = serde_json::to_vec(&normalized).map_err(ExportError::serialize)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

fn canonical_source_ids(values: &[String]) -> ExportResult<Vec<String>> {
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let id = Uuid::parse_str(value).map_err(|_| ExportError::InvalidQuery {
            field: "source_ids",
            message: "必须是 UUID".into(),
        })?;
        result.push(id.to_string());
    }
    result.sort();
    result.dedup();
    Ok(result)
}

fn canonical_numbers(values: &[i64]) -> Vec<i64> {
    let mut values = values.to_vec();
    values.sort_unstable();
    values.dedup();
    values
}

fn canonical_categories(values: &[String]) -> ExportResult<Vec<String>> {
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        if !CATEGORY_IDS.contains(&value.as_str()) {
            return Err(ExportError::InvalidQuery {
                field: "category_ids",
                message: format!("不支持的分类 ID: {value}"),
            });
        }
        result.push(value.clone());
    }
    result.sort();
    result.dedup();
    Ok(result)
}

fn canonical_extensions(values: &[String]) -> ExportResult<Vec<String>> {
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        if !value.is_ascii() {
            return Err(ExportError::InvalidQuery {
                field: "extensions",
                message: "扩展名必须是 ASCII".into(),
            });
        }
        result.push(value.to_ascii_lowercase());
    }
    result.sort();
    result.dedup();
    Ok(result)
}

fn canonical_optional_decimal(
    value: Option<&str>,
    field: &'static str,
) -> ExportResult<Option<String>> {
    value
        .map(|value| canonical_decimal(value, field))
        .transpose()
}

fn canonical_decimal(value: &str, field: &'static str) -> ExportResult<String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ExportError::InvalidQuery {
            field,
            message: "必须是非负整数十进制字符串".into(),
        });
    }
    let canonical = value.trim_start_matches('0');
    Ok(if canonical.is_empty() {
        "0".into()
    } else {
        canonical.into()
    })
}

fn decimal_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn canonical_optional_time(
    value: Option<&str>,
    field: &'static str,
) -> ExportResult<Option<String>> {
    value
        .map(|value| {
            value
                .parse::<Timestamp>()
                .map(|timestamp| timestamp.to_string())
                .map_err(|_| ExportError::InvalidQuery {
                    field,
                    message: "必须是 RFC3339 时间".into(),
                })
        })
        .transpose()
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportManifest {
    pub schema_version: u32,
    pub report_id: String,
    pub section: ExportSection,
    pub format: ExportFormat,
    pub scope: ExportScope,
    pub query: QuerySpec,
    pub query_hash: String,
    pub metric: Metric,
    pub timezone: String,
    pub truncated: bool,
    pub detail_available: bool,
}

#[derive(Debug, Clone)]
pub struct ExportManifestOptions {
    pub timezone: String,
    pub truncated: bool,
    pub detail_available: bool,
}

impl ExportManifestOptions {
    pub fn new(timezone: impl Into<String>, truncated: bool, detail_available: bool) -> Self {
        Self {
            timezone: timezone.into(),
            truncated,
            detail_available,
        }
    }
}

impl ExportManifest {
    pub fn new(
        report_id: impl Into<String>,
        section: ExportSection,
        format: ExportFormat,
        scope: ExportScope,
        query: QuerySpec,
        options: ExportManifestOptions,
    ) -> ExportResult<Self> {
        let report_id = report_id.into();
        Uuid::parse_str(&report_id).map_err(|_| ExportError::InvalidQuery {
            field: "report_id",
            message: "必须是 UUID".into(),
        })?;
        let query = query.normalize()?;
        let query_hash = query.query_hash()?;
        Ok(Self {
            schema_version: 1,
            report_id,
            section,
            format,
            scope,
            metric: query.metric,
            query,
            query_hash,
            timezone: options.timezone,
            truncated: options.truncated,
            detail_available: options.detail_available,
        })
    }
}

/// A row is an object with explicit field names. It is not a positional tuple:
/// a section column change cannot silently move data into another column.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportRow {
    values: BTreeMap<String, Value>,
}

impl ExportRow {
    pub fn from_object(values: Map<String, Value>) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }

    pub fn from_value(value: Value) -> ExportResult<Self> {
        match value {
            Value::Object(values) => Ok(Self::from_object(values)),
            _ => Err(ExportError::InvalidRow {
                message: "导出行必须是 JSON 对象".into(),
            }),
        }
    }

    pub fn values(&self) -> &BTreeMap<String, Value> {
        &self.values
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSchema {
    columns: Vec<String>,
}

impl ExportSchema {
    pub fn new(section_columns: impl IntoIterator<Item = String>) -> ExportResult<Self> {
        let mut columns = BASE_EXPORT_FIELDS
            .iter()
            .map(|field| (*field).into())
            .collect::<Vec<_>>();
        let mut seen = BASE_EXPORT_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect::<BTreeSet<_>>();
        for column in section_columns {
            if column.is_empty() || !seen.insert(column.clone()) {
                return Err(ExportError::InvalidSchema { column });
            }
            columns.push(column);
        }
        Ok(Self { columns })
    }

    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    fn validate_row(&self, row: &ExportRow) -> ExportResult<()> {
        if let Some(field) = self
            .columns
            .iter()
            .find(|field| !row.values.contains_key(*field))
        {
            return Err(ExportError::InvalidRow {
                message: format!("缺少字段 {field}"),
            });
        }
        if let Some(field) = row
            .values
            .keys()
            .find(|field| !self.columns.iter().any(|column| column == *field))
        {
            return Err(ExportError::InvalidRow {
                message: format!("未声明字段 {field}"),
            });
        }
        Ok(())
    }
}

/// A reopenable row source is required for ZIP. Each member is generated by a
/// fresh query, so no complete result set is buffered in memory.
pub trait ExportRows {
    fn open_rows(&self) -> ExportResult<Box<dyn Iterator<Item = ExportResult<ExportRow>> + '_>>;

    /// Open one report section. Single-section sources can use the default
    /// implementation; a full-report source overrides this to reopen the
    /// requested section independently for every package member.
    fn open_section(
        &self,
        _section: ExportSection,
    ) -> ExportResult<Box<dyn Iterator<Item = ExportResult<ExportRow>> + '_>> {
        self.open_rows()
    }
}

impl ExportRows for Vec<ExportRow> {
    fn open_rows(&self) -> ExportResult<Box<dyn Iterator<Item = ExportResult<ExportRow>> + '_>> {
        Ok(Box::new(self.iter().cloned().map(Ok)))
    }
}

/// Adapter for a query factory. The factory must return a new iterator for
/// each member; a one-shot iterator is not sufficient for ZIP.
pub struct FactoryRows<F>(pub F);

impl<F> ExportRows for FactoryRows<F>
where
    F: Fn() -> ExportResult<Box<dyn Iterator<Item = ExportResult<ExportRow>>>> + Send + Sync,
{
    fn open_rows(&self) -> ExportResult<Box<dyn Iterator<Item = ExportResult<ExportRow>> + '_>> {
        (self.0)()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExportLimits {
    /// Maximum encoded output bytes, including ZIP headers and central
    /// directory. This is caller supplied; there is no hidden unlimited value.
    pub max_output_bytes: u64,
    /// Deployment contract: 1..=4 concurrent exports.
    pub max_parallel_exports: usize,
}

impl ExportLimits {
    pub fn new(max_output_bytes: u64, max_parallel_exports: usize) -> ExportResult<Self> {
        if max_output_bytes == 0 {
            return Err(ExportError::InvalidLimits {
                message: "max_output_bytes 必须大于 0".into(),
            });
        }
        if !(1..=4).contains(&max_parallel_exports) {
            return Err(ExportError::InvalidLimits {
                message: "max_parallel_exports 必须在 1..=4 内".into(),
            });
        }
        Ok(Self {
            max_output_bytes,
            max_parallel_exports,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportStats {
    pub bytes_written: u64,
    pub rows_written: u64,
}

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("invalid query field {field}: {message}")]
    InvalidQuery {
        field: &'static str,
        message: String,
    },
    #[error("invalid export schema column: {column}")]
    InvalidSchema { column: String },
    #[error("invalid export row: {message}")]
    InvalidRow { message: String },
    #[error("invalid export limits: {message}")]
    InvalidLimits { message: String },
    #[error("export output exceeded the configured byte limit of {limit} bytes")]
    SizeLimitExceeded { limit: u64 },
    #[error("another export is already using all configured export slots")]
    ResourceBusy,
    #[error("report detail has expired")]
    DetailExpired,
    #[error("export I/O failed during {operation}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("export serialization failed")]
    Serialization(#[source] serde_json::Error),
    #[error("ZIP generation failed: {message}")]
    ZipFormat { message: String },
}

impl ExportError {
    fn serialize(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidQuery { .. }
            | Self::InvalidSchema { .. }
            | Self::InvalidRow { .. }
            | Self::InvalidLimits { .. } => ErrorCode::BadRequest,
            Self::SizeLimitExceeded { .. } => ErrorCode::ResourceBudgetExceeded,
            Self::ResourceBusy => ErrorCode::ResourceBusy,
            Self::DetailExpired => ErrorCode::DetailExpired,
            Self::Io { source, .. } => match source.kind() {
                io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => {
                    ErrorCode::InsufficientDataSpace
                }
                _ => ErrorCode::Internal,
            },
            Self::Serialization(_) | Self::ZipFormat { .. } => ErrorCode::Internal,
        }
    }
}

/// Shared limiter for all export formats. A permit is released when its guard
/// is dropped, including on an encoding error.
#[derive(Clone)]
pub struct ExportConcurrency {
    active: Arc<AtomicUsize>,
    max: usize,
}

impl ExportConcurrency {
    pub fn new(max_parallel_exports: usize) -> ExportResult<Self> {
        if !(1..=4).contains(&max_parallel_exports) {
            return Err(ExportError::InvalidLimits {
                message: "max_parallel_exports 必须在 1..=4 内".into(),
            });
        }
        Ok(Self {
            active: Arc::new(AtomicUsize::new(0)),
            max: max_parallel_exports,
        })
    }

    pub fn try_acquire(&self) -> ExportResult<ExportPermit> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.max {
                return Err(ExportError::ResourceBusy);
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(ExportPermit {
                        active: Arc::clone(&self.active),
                    });
                }
                Err(current) => active = current,
            }
        }
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct ExportPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for ExportPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Stream one export to `writer`. The writer is not retained by this
/// function; callers can pass a response body writer or an application file.
/// Acquire a permit from [`ExportConcurrency`] before calling this function.
pub fn write_export<W: Write, S: ExportRows>(
    writer: W,
    manifest: &ExportManifest,
    schema: &ExportSchema,
    rows: &S,
    limits: ExportLimits,
) -> ExportResult<ExportStats> {
    let mut output = LimitedWriter::new(writer, limits.max_output_bytes);
    let row_count = if manifest.section == ExportSection::FullReport {
        match manifest.format {
            ExportFormat::Csv => write_full_report_csv(&mut output, manifest, rows)?,
            ExportFormat::Json => write_full_report_json(&mut output, manifest, rows)?,
            ExportFormat::Html => write_full_report_html(&mut output, manifest, rows)?,
            ExportFormat::Zip => write_full_report_zip(&mut output, manifest, schema, rows)?,
        }
    } else {
        match manifest.format {
            ExportFormat::Csv => write_csv(&mut output, manifest, schema, rows.open_rows()?)?,
            ExportFormat::Json => write_json(&mut output, manifest, schema, rows.open_rows()?)?,
            ExportFormat::Html => write_html(&mut output, manifest, schema, rows.open_rows()?)?,
            ExportFormat::Zip => write_zip(&mut output, manifest, schema, rows)?,
        }
    };
    output.flush().map_err(|source| ExportError::Io {
        operation: "flush output",
        source,
    })?;
    Ok(ExportStats {
        bytes_written: output.bytes_written,
        rows_written: row_count,
    })
}

/// Admission-controlled variant for the HTTP/job layer. The limiter must be
/// shared by all export jobs in the process; a permit is held for the whole
/// stream and released on every return path.
pub fn write_export_with_concurrency<W: Write, S: ExportRows>(
    writer: W,
    manifest: &ExportManifest,
    schema: &ExportSchema,
    rows: &S,
    limits: ExportLimits,
    concurrency: &ExportConcurrency,
) -> ExportResult<ExportStats> {
    if concurrency.max != limits.max_parallel_exports {
        return Err(ExportError::InvalidLimits {
            message: "并发限制与导出资源配置不一致".into(),
        });
    }
    let _permit = concurrency.try_acquire()?;
    write_export(writer, manifest, schema, rows, limits)
}

/// Convenience renderer for tests and small callers. Production downloads
/// should pass their streaming writer to [`write_export`] instead.
pub fn render_export<S: ExportRows>(
    manifest: &ExportManifest,
    schema: &ExportSchema,
    rows: &S,
    limits: ExportLimits,
) -> ExportResult<(Vec<u8>, ExportStats)> {
    let mut bytes = Vec::new();
    let stats = write_export(&mut bytes, manifest, schema, rows, limits)?;
    Ok((bytes, stats))
}

fn write_csv<W: Write, I: Iterator<Item = ExportResult<ExportRow>>>(
    output: &mut W,
    _manifest: &ExportManifest,
    schema: &ExportSchema,
    rows: I,
) -> ExportResult<u64> {
    output
        .write_all(&[0xEF, 0xBB, 0xBF])
        .map_err(|source| io_error("write CSV BOM", source))?;
    write_csv_record(output, schema.columns())?;
    let mut count: u64 = 0;
    for row in rows {
        let row = row?;
        schema.validate_row(&row)?;
        write_csv_data_row(output, schema, &row)?;
        count = checked_row_count(count, "CSV")?;
    }
    Ok(count)
}

fn write_csv_data_row<W: Write>(
    output: &mut W,
    schema: &ExportSchema,
    row: &ExportRow,
) -> ExportResult<()> {
    let mut fields = Vec::with_capacity(schema.columns().len());
    for column in schema.columns() {
        fields.push(csv_safe(&value_text(row_value(row, column)?)));
    }
    write_csv_record(output, &fields)
}

fn checked_row_count(count: u64, format: &'static str) -> ExportResult<u64> {
    count.checked_add(1).ok_or_else(|| ExportError::Io {
        operation: "count export rows",
        source: io::Error::other(format!("{format} 行数溢出")),
    })
}

fn write_csv_record<W: Write>(output: &mut W, fields: &[impl AsRef<str>]) -> ExportResult<()> {
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            output
                .write_all(b",")
                .map_err(|source| io_error("write CSV separator", source))?;
        }
        let field = field.as_ref();
        output
            .write_all(quote_csv(field).as_bytes())
            .map_err(|source| io_error("write CSV field", source))?;
    }
    output
        .write_all(b"\r\n")
        .map_err(|source| io_error("write CSV line ending", source))
}

fn quote_csv(value: &str) -> String {
    if value
        .bytes()
        .any(|byte| matches!(byte, b',' | b'"' | b'\r' | b'\n'))
    {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.into()
    }
}

fn csv_safe(value: &str) -> String {
    let trimmed = value.trim_start_matches(char::is_whitespace);
    let formula = matches!(trimmed.as_bytes().first(), Some(b'=' | b'+' | b'-' | b'@'))
        || trimmed
            .bytes()
            .next()
            .is_some_and(|byte| byte < 0x20 || byte == 0x7f);
    if formula {
        format!("'{value}")
    } else {
        value.into()
    }
}

fn write_json<W: Write, I: Iterator<Item = ExportResult<ExportRow>>>(
    output: &mut W,
    manifest: &ExportManifest,
    schema: &ExportSchema,
    rows: I,
) -> ExportResult<u64> {
    output
        .write_all(b"{\"manifest\":")
        .map_err(|source| io_error("write JSON prefix", source))?;
    let manifest_bytes = serde_json::to_vec(manifest).map_err(ExportError::serialize)?;
    output
        .write_all(&manifest_bytes)
        .map_err(|source| io_error("write JSON manifest", source))?;
    output
        .write_all(b",\"columns\":")
        .map_err(|source| io_error("write JSON columns", source))?;
    let columns_bytes = serde_json::to_vec(schema.columns()).map_err(ExportError::serialize)?;
    output
        .write_all(&columns_bytes)
        .map_err(|source| io_error("write JSON columns", source))?;
    output
        .write_all(b",\"rows\":[")
        .map_err(|source| io_error("write JSON rows prefix", source))?;
    let mut count: u64 = 0;
    for row in rows {
        let row = row?;
        schema.validate_row(&row)?;
        if count != 0 {
            output
                .write_all(b",")
                .map_err(|source| io_error("write JSON separator", source))?;
        }
        let row_bytes = serde_json::to_vec(&row.values).map_err(ExportError::serialize)?;
        output
            .write_all(&row_bytes)
            .map_err(|source| io_error("write JSON row", source))?;
        count = checked_row_count(count, "JSON")?;
    }
    output
        .write_all(b"]}")
        .map_err(|source| io_error("write JSON suffix", source))?;
    Ok(count)
}

fn write_html<W: Write, I: Iterator<Item = ExportResult<ExportRow>>>(
    output: &mut W,
    manifest: &ExportManifest,
    schema: &ExportSchema,
    rows: I,
) -> ExportResult<u64> {
    output
        .write_all(
            br#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NAS Storage Analyzer Report</title><style>body{font-family:system-ui,sans-serif;margin:2rem;color:#1f2937}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border:1px solid #d1d5db;padding:.35rem .5rem;text-align:left;vertical-align:top}th{background:#f3f4f6;position:sticky;top:0}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style></head><body><h1>NAS Storage Analyzer Report</h1><dl>"#,
        )
        .map_err(|source| io_error("write HTML header", source))?;
    write_html_definition(output, "Report ID", &manifest.report_id)?;
    write_html_definition(output, "Section", manifest.section.as_str())?;
    write_html_definition(output, "Query hash", &manifest.query_hash)?;
    write_html_definition(output, "Metric", &format!("{:?}", manifest.metric))?;
    write_html_definition(output, "Timezone", &manifest.timezone)?;
    write_html_definition(output, "Truncated", &manifest.truncated.to_string())?;
    write_html_definition(
        output,
        "Detail available",
        &manifest.detail_available.to_string(),
    )?;
    output
        .write_all(b"</dl><table><thead><tr>")
        .map_err(|source| io_error("write HTML table header", source))?;
    for column in schema.columns() {
        write_html_cell(output, column, "th")?;
    }
    output
        .write_all(b"</tr></thead><tbody>")
        .map_err(|source| io_error("write HTML rows prefix", source))?;
    let mut count: u64 = 0;
    for row in rows {
        let row = row?;
        schema.validate_row(&row)?;
        output
            .write_all(b"<tr>")
            .map_err(|source| io_error("write HTML row prefix", source))?;
        for column in schema.columns() {
            let text = value_text(row_value(&row, column)?);
            write_html_cell(output, &text, "td")?;
        }
        output
            .write_all(b"</tr>")
            .map_err(|source| io_error("write HTML row suffix", source))?;
        count = checked_row_count(count, "HTML")?;
    }
    output
        .write_all(b"</tbody></table></body></html>")
        .map_err(|source| io_error("write HTML suffix", source))?;
    Ok(count)
}

fn write_html_definition<W: Write>(output: &mut W, label: &str, value: &str) -> ExportResult<()> {
    output
        .write_all(b"<dt>")
        .map_err(|source| io_error("write HTML definition", source))?;
    output
        .write_all(escape_html(label).as_bytes())
        .map_err(|source| io_error("write HTML label", source))?;
    output
        .write_all(b"</dt><dd>")
        .map_err(|source| io_error("write HTML definition separator", source))?;
    output
        .write_all(escape_html(value).as_bytes())
        .map_err(|source| io_error("write HTML definition value", source))?;
    output
        .write_all(b"</dd>")
        .map_err(|source| io_error("write HTML definition suffix", source))
}

fn write_html_cell<W: Write>(output: &mut W, value: &str, tag: &str) -> ExportResult<()> {
    output
        .write_all(format!("<{tag}>").as_bytes())
        .map_err(|source| io_error("write HTML cell prefix", source))?;
    output
        .write_all(escape_html(value).as_bytes())
        .map_err(|source| io_error("write HTML cell", source))?;
    output
        .write_all(format!("</{tag}>").as_bytes())
        .map_err(|source| io_error("write HTML cell suffix", source))
}

fn row_with_section(row: ExportRow, section: ExportSection) -> ExportRow {
    let mut values: Map<String, Value> = row.values.into_iter().collect();
    values.insert(
        "section".to_string(),
        Value::String(section.as_str().to_string()),
    );
    ExportRow::from_object(values)
}

fn full_report_schema() -> ExportResult<ExportSchema> {
    ExportSchema::new(["section".to_string()])
}

fn write_full_report_csv<W: Write, S: ExportRows>(
    output: &mut W,
    _manifest: &ExportManifest,
    rows: &S,
) -> ExportResult<u64> {
    output
        .write_all(&[0xEF, 0xBB, 0xBF])
        .map_err(|source| io_error("write full-report CSV BOM", source))?;
    let schema = full_report_schema()?;
    write_csv_record(output, schema.columns())?;
    let mut count = 0;
    for section in FULL_REPORT_SECTIONS {
        for row in rows.open_section(section)? {
            let row = row_with_section(row?, section);
            schema.validate_row(&row)?;
            write_csv_data_row(output, &schema, &row)?;
            count = checked_row_count(count, "full-report CSV")?;
        }
    }
    Ok(count)
}

fn write_full_report_json<W: Write, S: ExportRows>(
    output: &mut W,
    manifest: &ExportManifest,
    rows: &S,
) -> ExportResult<u64> {
    let schema = full_report_schema()?;
    output
        .write_all(b"{\"manifest\":")
        .map_err(|source| io_error("write full-report JSON prefix", source))?;
    let manifest_bytes = serde_json::to_vec(manifest).map_err(ExportError::serialize)?;
    output
        .write_all(&manifest_bytes)
        .map_err(|source| io_error("write full-report JSON manifest", source))?;
    output
        .write_all(b",\"columns\":")
        .map_err(|source| io_error("write full-report JSON columns prefix", source))?;
    let columns_bytes = serde_json::to_vec(schema.columns()).map_err(ExportError::serialize)?;
    output
        .write_all(&columns_bytes)
        .map_err(|source| io_error("write full-report JSON columns", source))?;
    output
        .write_all(b",\"rows\":[")
        .map_err(|source| io_error("write full-report JSON rows prefix", source))?;
    let mut count = 0;
    for section in FULL_REPORT_SECTIONS {
        for row in rows.open_section(section)? {
            let row = row_with_section(row?, section);
            schema.validate_row(&row)?;
            if count != 0 {
                output
                    .write_all(b",")
                    .map_err(|source| io_error("write full-report JSON separator", source))?;
            }
            let row_bytes = serde_json::to_vec(&row.values).map_err(ExportError::serialize)?;
            output
                .write_all(&row_bytes)
                .map_err(|source| io_error("write full-report JSON row", source))?;
            count = checked_row_count(count, "full-report JSON")?;
        }
    }
    output
        .write_all(b"]}")
        .map_err(|source| io_error("write full-report JSON suffix", source))?;
    Ok(count)
}

fn write_full_report_html<W: Write, S: ExportRows>(
    output: &mut W,
    manifest: &ExportManifest,
    rows: &S,
) -> ExportResult<u64> {
    let schema = full_report_schema()?;
    output
        .write_all(
            br#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NAS Storage Analyzer Report</title><style>body{font-family:system-ui,sans-serif;margin:2rem;color:#1f2937}table{border-collapse:collapse;width:100%;font-size:.9rem;margin-bottom:2rem}th,td{border:1px solid #d1d5db;padding:.35rem .5rem;text-align:left;vertical-align:top}th{background:#f3f4f6;position:sticky;top:0}pre{white-space:pre-wrap;overflow-wrap:anywhere}h2{margin-top:2rem}</style></head><body><h1>NAS Storage Analyzer Report</h1><dl>"#,
        )
        .map_err(|source| io_error("write full-report HTML header", source))?;
    write_html_definition(output, "Report ID", &manifest.report_id)?;
    write_html_definition(output, "Query hash", &manifest.query_hash)?;
    write_html_definition(output, "Metric", &format!("{:?}", manifest.metric))?;
    write_html_definition(output, "Timezone", &manifest.timezone)?;
    write_html_definition(output, "Scope", &format!("{:?}", manifest.scope))?;
    write_html_definition(
        output,
        "Detail available",
        &manifest.detail_available.to_string(),
    )?;
    output
        .write_all(b"</dl>")
        .map_err(|source| io_error("write full-report HTML metadata suffix", source))?;
    let mut count = 0;
    for section in FULL_REPORT_SECTIONS {
        output
            .write_all(
                format!(
                    "<h2>{}</h2><table><thead><tr>",
                    escape_html(section.as_str())
                )
                .as_bytes(),
            )
            .map_err(|source| io_error("write full-report HTML section header", source))?;
        for column in schema.columns() {
            write_html_cell(output, column, "th")?;
        }
        output
            .write_all(b"</tr></thead><tbody>")
            .map_err(|source| io_error("write full-report HTML table header", source))?;
        for row in rows.open_section(section)? {
            let row = row_with_section(row?, section);
            schema.validate_row(&row)?;
            output
                .write_all(b"<tr>")
                .map_err(|source| io_error("write full-report HTML row prefix", source))?;
            for column in schema.columns() {
                let text = value_text(row_value(&row, column)?);
                write_html_cell(output, &text, "td")?;
            }
            output
                .write_all(b"</tr>")
                .map_err(|source| io_error("write full-report HTML row suffix", source))?;
            count = checked_row_count(count, "full-report HTML")?;
        }
        output
            .write_all(b"</tbody></table>")
            .map_err(|source| io_error("write full-report HTML table suffix", source))?;
    }
    output
        .write_all(b"</body></html>")
        .map_err(|source| io_error("write full-report HTML suffix", source))?;
    Ok(count)
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn value_text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string(value).expect("JSON values are serializable")
        }
    }
}

fn row_value<'a>(row: &'a ExportRow, column: &str) -> ExportResult<&'a Value> {
    row.values
        .get(column)
        .ok_or_else(|| ExportError::InvalidRow {
            message: format!("缺少字段 {column}"),
        })
}

fn write_zip<W: Write, S: ExportRows>(
    output: &mut LimitedWriter<W>,
    manifest: &ExportManifest,
    schema: &ExportSchema,
    rows: &S,
) -> ExportResult<u64> {
    let mut zip = StreamingZip::new(output);
    let mut checksums = Vec::new();

    let manifest_name = "manifest.json";
    {
        let mut entry = zip.start_entry(manifest_name)?;
        let manifest_hash = write_hashed(&mut entry, |sink| {
            let bytes = serde_json::to_vec(manifest).map_err(ExportError::serialize)?;
            sink.write_all(&bytes)
                .map_err(|source| io_error("write ZIP manifest", source))
        })?;
        entry.finish()?;
        checksums.push((manifest_name.to_string(), manifest_hash));
    }

    let csv_name = format!("{}.csv", manifest.section.as_str());
    let csv_count = {
        let mut entry = zip.start_entry(&csv_name)?;
        let csv_rows = rows.open_rows()?;
        let (csv_hash, csv_count) = write_hashed_count(&mut entry, |sink| {
            write_csv(sink, manifest, schema, csv_rows)
        })?;
        entry.finish()?;
        checksums.push((csv_name, csv_hash));
        csv_count
    };

    let json_name = format!("{}.json", manifest.section.as_str());
    {
        let mut entry = zip.start_entry(&json_name)?;
        let json_rows = rows.open_rows()?;
        let (json_hash, _) = write_hashed_count(&mut entry, |sink| {
            write_json(sink, manifest, schema, json_rows)
        })?;
        entry.finish()?;
        checksums.push((json_name, json_hash));
    }

    let html_name = format!("{}.html", manifest.section.as_str());
    {
        let mut entry = zip.start_entry(&html_name)?;
        let html_rows = rows.open_rows()?;
        let (html_hash, _) = write_hashed_count(&mut entry, |sink| {
            write_html(sink, manifest, schema, html_rows)
        })?;
        entry.finish()?;
        checksums.push((html_name, html_hash));
    }

    let checksum_name = "checksums.sha256";
    {
        let mut entry = zip.start_entry(checksum_name)?;
        for (name, checksum) in &checksums {
            entry
                .write_all(format!("{checksum}  {name}\n").as_bytes())
                .map_err(|source| io_error("write ZIP checksums", source))?;
        }
        entry.finish()?;
    }
    zip.finish()?;
    Ok(csv_count)
}

fn write_full_report_zip<W: Write, S: ExportRows>(
    output: &mut LimitedWriter<W>,
    manifest: &ExportManifest,
    schema: &ExportSchema,
    rows: &S,
) -> ExportResult<u64> {
    let mut zip = StreamingZip::new(output);
    let mut checksums = Vec::new();

    let manifest_name = "manifest.json";
    {
        let mut entry = zip.start_entry(manifest_name)?;
        let manifest_hash = write_hashed(&mut entry, |sink| {
            let bytes = serde_json::to_vec(manifest).map_err(ExportError::serialize)?;
            sink.write_all(&bytes)
                .map_err(|source| io_error("write full-report ZIP manifest", source))
        })?;
        entry.finish()?;
        checksums.push((manifest_name.to_string(), manifest_hash));
    }

    let html_name = "full_report.html";
    {
        let mut entry = zip.start_entry(html_name)?;
        let html_hash = write_hashed_count(&mut entry, |sink| {
            write_full_report_html(sink, manifest, rows)
        })?;
        entry.finish()?;
        checksums.push((html_name.to_string(), html_hash.0));
    }

    let mut total_rows: u64 = 0;
    for section in FULL_REPORT_SECTIONS {
        let mut section_manifest = manifest.clone();
        section_manifest.section = section;

        let csv_name = format!("{}.csv", section.as_str());
        {
            let mut entry = zip.start_entry(&csv_name)?;
            let section_rows = rows.open_section(section)?;
            let (hash, count) = write_hashed_count(&mut entry, |sink| {
                write_csv(sink, &section_manifest, schema, section_rows)
            })?;
            entry.finish()?;
            checksums.push((csv_name, hash));
            total_rows = total_rows
                .checked_add(count)
                .ok_or_else(|| ExportError::Io {
                    operation: "count full-report ZIP rows",
                    source: io::Error::other("full-report ZIP 行数溢出"),
                })?;
        }

        let json_name = format!("{}.json", section.as_str());
        {
            let mut entry = zip.start_entry(&json_name)?;
            let section_rows = rows.open_section(section)?;
            let (hash, _) = write_hashed_count(&mut entry, |sink| {
                write_json(sink, &section_manifest, schema, section_rows)
            })?;
            entry.finish()?;
            checksums.push((json_name, hash));
        }
    }

    let checksum_name = "checksums.sha256";
    {
        let mut entry = zip.start_entry(checksum_name)?;
        for (name, checksum) in &checksums {
            entry
                .write_all(format!("{checksum}  {name}\n").as_bytes())
                .map_err(|source| io_error("write full-report ZIP checksums", source))?;
        }
        entry.finish()?;
    }
    zip.finish()?;
    Ok(total_rows)
}

struct StreamingZip<'a, W> {
    output: &'a mut LimitedWriter<W>,
    entries: Vec<ZipEntryMeta>,
}

struct ZipEntryMeta {
    name: String,
    crc32: u32,
    size: u64,
    offset: u64,
}

struct ZipEntry<'zip, 'output, W> {
    zip: &'zip mut StreamingZip<'output, W>,
    name: String,
    crc32: Crc32,
    size: u64,
    offset: u64,
}

impl<'a, W: Write> StreamingZip<'a, W> {
    fn new(output: &'a mut LimitedWriter<W>) -> Self {
        Self {
            output,
            entries: Vec::new(),
        }
    }

    fn start_entry<'zip>(&'zip mut self, name: &str) -> ExportResult<ZipEntry<'zip, 'a, W>> {
        let name_bytes = name.as_bytes();
        let name_len = u16::try_from(name_bytes.len()).map_err(|_| ExportError::ZipFormat {
            message: "ZIP 条目名称超过 65535 字节".into(),
        })?;
        let offset = self.output.bytes_written;
        write_u32(&mut self.output, 0x0403_4B50)?;
        write_u16(&mut self.output, 20)?;
        write_u16(&mut self.output, 0x0008)?;
        write_u16(&mut self.output, 0)?;
        write_u16(&mut self.output, 0)?;
        write_u16(&mut self.output, 0)?;
        write_u32(&mut self.output, 0)?;
        write_u32(&mut self.output, 0)?;
        write_u32(&mut self.output, 0)?;
        write_u16(&mut self.output, name_len)?;
        write_u16(&mut self.output, 0)?;
        self.output
            .write_all(name_bytes)
            .map_err(|source| io_error("write ZIP local header", source))?;
        Ok(ZipEntry {
            zip: self,
            name: name.into(),
            crc32: Crc32::new(),
            size: 0,
            offset,
        })
    }

    fn finish(mut self) -> ExportResult<()> {
        let central_offset = self.output.bytes_written;
        for entry in &self.entries {
            let name = entry.name.as_bytes();
            let name_len = u16::try_from(name.len()).map_err(|_| ExportError::ZipFormat {
                message: "ZIP 条目名称超过 65535 字节".into(),
            })?;
            let size = u32::try_from(entry.size).map_err(|_| ExportError::ZipFormat {
                message: "ZIP 条目超过 ZIP32 大小限制".into(),
            })?;
            let offset = u32::try_from(entry.offset).map_err(|_| ExportError::ZipFormat {
                message: "ZIP 偏移超过 ZIP32 大小限制".into(),
            })?;
            write_u32(&mut self.output, 0x0201_4B50)?;
            write_u16(&mut self.output, 20)?;
            write_u16(&mut self.output, 20)?;
            write_u16(&mut self.output, 0x0008)?;
            write_u16(&mut self.output, 0)?;
            write_u16(&mut self.output, 0)?;
            write_u16(&mut self.output, 0)?;
            write_u32(&mut self.output, entry.crc32)?;
            write_u32(&mut self.output, size)?;
            write_u32(&mut self.output, size)?;
            write_u16(&mut self.output, name_len)?;
            write_u16(&mut self.output, 0)?;
            write_u16(&mut self.output, 0)?;
            write_u16(&mut self.output, 0)?;
            write_u16(&mut self.output, 0)?;
            write_u32(&mut self.output, 0)?;
            write_u32(&mut self.output, offset)?;
            self.output
                .write_all(name)
                .map_err(|source| io_error("write ZIP central directory", source))?;
        }
        let central_size = self
            .output
            .bytes_written
            .checked_sub(central_offset)
            .ok_or_else(|| ExportError::ZipFormat {
                message: "ZIP 中央目录偏移计算溢出".into(),
            })?;
        let entry_count =
            u16::try_from(self.entries.len()).map_err(|_| ExportError::ZipFormat {
                message: "ZIP 条目数量超过 ZIP32 限制".into(),
            })?;
        let central_size = u32::try_from(central_size).map_err(|_| ExportError::ZipFormat {
            message: "ZIP 中央目录超过 ZIP32 限制".into(),
        })?;
        let central_offset = u32::try_from(central_offset).map_err(|_| ExportError::ZipFormat {
            message: "ZIP 偏移超过 ZIP32 大小限制".into(),
        })?;
        write_u32(&mut self.output, 0x0605_4B50)?;
        write_u16(&mut self.output, 0)?;
        write_u16(&mut self.output, 0)?;
        write_u16(&mut self.output, entry_count)?;
        write_u16(&mut self.output, entry_count)?;
        write_u32(&mut self.output, central_size)?;
        write_u32(&mut self.output, central_offset)?;
        write_u16(&mut self.output, 0)?;
        Ok(())
    }
}

impl<W: Write> Write for ZipEntry<'_, '_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.zip.output.write(buffer)?;
        self.crc32.update(&buffer[..written]);
        let written_u64 = u64::try_from(written)
            .map_err(|_| io::Error::other("ZIP 条目写入字节数超出 u64 范围"))?;
        self.size = self
            .size
            .checked_add(written_u64)
            .ok_or_else(|| io::Error::other("ZIP 条目大小溢出"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.zip.output.flush()
    }
}

impl<W: Write> ZipEntry<'_, '_, W> {
    fn finish(self) -> ExportResult<()> {
        let crc32 = self.crc32.finish();
        let size = u32::try_from(self.size).map_err(|_| ExportError::ZipFormat {
            message: "ZIP 条目超过 ZIP32 大小限制".into(),
        })?;
        write_u32(&mut self.zip.output, 0x0807_4B50)?;
        write_u32(&mut self.zip.output, crc32)?;
        write_u32(&mut self.zip.output, size)?;
        write_u32(&mut self.zip.output, size)?;
        self.zip.entries.push(ZipEntryMeta {
            name: self.name,
            crc32,
            size: self.size,
            offset: self.offset,
        });
        Ok(())
    }
}

fn write_u16<W: Write>(output: &mut W, value: u16) -> ExportResult<()> {
    output
        .write_all(&value.to_le_bytes())
        .map_err(|source| io_error("write ZIP integer", source))
}

fn write_u32<W: Write>(output: &mut W, value: u32) -> ExportResult<()> {
    output
        .write_all(&value.to_le_bytes())
        .map_err(|source| io_error("write ZIP integer", source))
}

struct Crc32(u32);

impl Crc32 {
    fn new() -> Self {
        Self(u32::MAX)
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            let mut value = (self.0 ^ u32::from(*byte)) & 0xff;
            for _ in 0..8 {
                value = if value & 1 != 0 {
                    (value >> 1) ^ 0xedb8_8320
                } else {
                    value >> 1
                };
            }
            self.0 = (self.0 >> 8) ^ value;
        }
    }

    fn finish(self) -> u32 {
        !self.0
    }
}

fn write_hashed<W, F>(output: &mut W, write: F) -> ExportResult<String>
where
    W: Write,
    F: FnOnce(&mut HashingWriter<'_, W>) -> ExportResult<()>,
{
    let mut sink = HashingWriter::new(output);
    write(&mut sink)?;
    Ok(sink.finish())
}

fn write_hashed_count<W, F>(output: &mut W, write: F) -> ExportResult<(String, u64)>
where
    W: Write,
    F: FnOnce(&mut HashingWriter<'_, W>) -> ExportResult<u64>,
{
    let mut sink = HashingWriter::new(output);
    let count = write(&mut sink)?;
    Ok((sink.finish(), count))
}

fn io_error(operation: &'static str, source: io::Error) -> ExportError {
    if let Some(limit) = source
        .get_ref()
        .and_then(|error| error.downcast_ref::<LimitReached>())
    {
        ExportError::SizeLimitExceeded { limit: limit.limit }
    } else {
        ExportError::Io { operation, source }
    }
}

struct LimitedWriter<W> {
    inner: W,
    limit: u64,
    bytes_written: u64,
}

impl<W> LimitedWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            limit,
            bytes_written: 0,
        }
    }
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let buffer_len = u64::try_from(buffer.len())
            .map_err(|_| io::Error::other("输出缓冲区大小超出 u64 范围"))?;
        let remaining = self
            .limit
            .checked_sub(self.bytes_written)
            .ok_or_else(|| io::Error::other("输出字节计数超过配置上限"))?;
        if buffer_len > remaining {
            return Err(io::Error::other(LimitReached { limit: self.limit }));
        }
        let written = self.inner.write(buffer)?;
        let written_u64 =
            u64::try_from(written).map_err(|_| io::Error::other("输出写入字节数超出 u64 范围"))?;
        self.bytes_written = self
            .bytes_written
            .checked_add(written_u64)
            .ok_or_else(|| io::Error::other("输出字节计数溢出"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug)]
struct LimitReached {
    limit: u64,
}

impl fmt::Display for LimitReached {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "output limit {} reached", self.limit)
    }
}

impl std::error::Error for LimitReached {}

struct HashingWriter<'a, W> {
    inner: &'a mut W,
    digest: Sha256,
}

impl<'a, W: Write> HashingWriter<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
        }
    }

    fn finish(self) -> String {
        hex::encode(self.digest.finalize())
    }
}

impl<W: Write> Write for HashingWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.digest.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::thread;

    fn limits(max_output_bytes: u64) -> ExportLimits {
        ExportLimits::new(max_output_bytes, 1).unwrap()
    }

    fn manifest(format: ExportFormat) -> ExportManifest {
        ExportManifest::new(
            "00000000-0000-0000-0000-000000000001",
            ExportSection::Files,
            format,
            ExportScope::Current,
            QuerySpec::default(),
            ExportManifestOptions::new("UTC", false, true),
        )
        .unwrap()
    }

    fn schema() -> ExportSchema {
        ExportSchema::new(["rank".into(), "note".into()]).unwrap()
    }

    fn row(note: &str) -> ExportRow {
        let mut values = Map::new();
        values.insert(
            "report_id".into(),
            Value::String("00000000-0000-0000-0000-000000000001".into()),
        );
        values.insert("source_name".into(), Value::String("source".into()));
        values.insert(
            "relative_path_display".into(),
            Value::String("a,b\nname".into()),
        );
        values.insert("owner_uid".into(), Value::Number(7.into()));
        values.insert("category".into(), Value::String("documents".into()));
        values.insert(
            "logical_size_bytes".into(),
            Value::String("1099511627776".into()),
        );
        values.insert(
            "allocated_size_estimate_bytes".into(),
            Value::String("4096".into()),
        );
        values.insert("mtime".into(), Value::String("2026-01-01T00:00:00Z".into()));
        values.insert("atime".into(), Value::Null);
        values.insert("status".into(), Value::String("present".into()));
        values.insert("rank".into(), Value::Number(1.into()));
        values.insert("note".into(), Value::String(note.into()));
        ExportRow::from_object(values)
    }

    fn full_report_row(section: &str) -> ExportRow {
        let mut row = row(section);
        row.values.remove("rank");
        row.values.remove("note");
        row
    }

    fn full_report_manifest(format: ExportFormat) -> ExportManifest {
        ExportManifest::new(
            "00000000-0000-0000-0000-000000000001",
            ExportSection::FullReport,
            format,
            ExportScope::Current,
            QuerySpec::default(),
            ExportManifestOptions::new("UTC", false, true),
        )
        .unwrap()
    }

    struct FullReportRows;

    impl ExportRows for FullReportRows {
        fn open_rows(
            &self,
        ) -> ExportResult<Box<dyn Iterator<Item = ExportResult<ExportRow>> + '_>> {
            Ok(Box::new(std::iter::empty()))
        }

        fn open_section(
            &self,
            section: ExportSection,
        ) -> ExportResult<Box<dyn Iterator<Item = ExportResult<ExportRow>> + '_>> {
            Ok(Box::new(std::iter::once(Ok(full_report_row(
                section.as_str(),
            )))))
        }
    }

    #[test]
    fn full_report_formats_emit_all_sections_and_tag_rows() {
        let rows = FullReportRows;
        for format in [ExportFormat::Csv, ExportFormat::Json, ExportFormat::Html] {
            let schema = ExportSchema::new(Vec::<String>::new()).unwrap();
            let (bytes, stats) = render_export(
                &full_report_manifest(format),
                &schema,
                &rows,
                limits(128 * 1024),
            )
            .unwrap();
            assert_eq!(stats.rows_written, FULL_REPORT_SECTIONS.len() as u64);
            let text = String::from_utf8(bytes.clone()).unwrap();
            for section in FULL_REPORT_SECTIONS {
                assert!(text.contains(section.as_str()), "missing {section:?}");
            }
            match format {
                ExportFormat::Csv => assert!(text.lines().next().unwrap().contains("section")),
                ExportFormat::Json => {
                    let value: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(
                        value["rows"].as_array().unwrap().len(),
                        FULL_REPORT_SECTIONS.len()
                    );
                    for (row, section) in value["rows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .zip(FULL_REPORT_SECTIONS)
                    {
                        assert_eq!(row["section"], section.as_str());
                    }
                }
                ExportFormat::Html => {
                    for section in FULL_REPORT_SECTIONS {
                        assert_eq!(
                            text.matches(&format!("<td>{}</td>", section.as_str()))
                                .count(),
                            1
                        );
                    }
                }
                ExportFormat::Zip => unreachable!(),
            }
        }
    }

    #[test]
    fn full_report_zip_contains_every_section_member_and_full_html() {
        let rows = FullReportRows;
        let schema = ExportSchema::new(Vec::<String>::new()).unwrap();
        let (bytes, stats) = render_export(
            &full_report_manifest(ExportFormat::Zip),
            &schema,
            &rows,
            limits(512 * 1024),
        )
        .unwrap();
        assert_eq!(stats.rows_written, FULL_REPORT_SECTIONS.len() as u64);
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(archive.len(), 2 + FULL_REPORT_SECTIONS.len() * 2 + 1);
        for name in ["manifest.json", "full_report.html", "checksums.sha256"] {
            assert!(archive.by_name(name).is_ok(), "missing {name}");
        }
        let mut html = String::new();
        archive
            .by_name("full_report.html")
            .unwrap()
            .read_to_string(&mut html)
            .unwrap();
        for section in FULL_REPORT_SECTIONS {
            assert!(
                archive
                    .by_name(&format!("{}.csv", section.as_str()))
                    .is_ok()
            );
            assert!(
                archive
                    .by_name(&format!("{}.json", section.as_str()))
                    .is_ok()
            );
            assert!(html.contains(&format!("<h2>{}</h2>", section.as_str())));
        }
    }

    #[test]
    fn query_normalization_and_hash_are_stable() {
        let query = QuerySpec {
            source_ids: vec![
                "00000000-0000-0000-0000-000000000003".into(),
                "00000000-0000-0000-0000-000000000002".into(),
                "00000000-0000-0000-0000-000000000002".into(),
            ],
            extensions: vec!["JPG".into(), "jpg".into()],
            min_size_bytes: Some("0009".into()),
            max_size_bytes: Some("10".into()),
            ..QuerySpec::default()
        };
        let normalized = query.normalize().unwrap();
        assert_eq!(
            normalized.source_ids,
            [
                "00000000-0000-0000-0000-000000000002",
                "00000000-0000-0000-0000-000000000003"
            ]
        );
        assert_eq!(normalized.extensions, ["jpg"]);
        assert_eq!(normalized.min_size_bytes.as_deref(), Some("9"));
        assert_eq!(
            query.query_hash().unwrap(),
            normalized.query_hash().unwrap()
        );
    }

    #[test]
    fn query_rejects_bad_range_and_unknown_category() {
        let query = QuerySpec {
            category_ids: vec!["not-a-category".into()],
            ..QuerySpec::default()
        };
        assert_eq!(query.normalize().unwrap_err().code(), ErrorCode::BadRequest);
        let query = QuerySpec {
            min_size_bytes: Some("10".into()),
            max_size_bytes: Some("9".into()),
            ..QuerySpec::default()
        };
        assert_eq!(query.normalize().unwrap_err().code(), ErrorCode::BadRequest);
    }

    #[test]
    fn csv_is_streamed_escaped_and_formula_safe() {
        let rows = vec![row(" =SUM(A1)")];
        let (bytes, stats) =
            render_export(&manifest(ExportFormat::Csv), &schema(), &rows, limits(4096)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with('\u{feff}'));
        assert!(text.contains("\"a,b\nname\""));
        assert!(text.contains("' =SUM(A1)"));
        assert!(text.ends_with("\r\n"));
        assert_eq!(stats.rows_written, 1);
    }

    #[test]
    fn json_preserves_raw_value_and_html_escapes() {
        let rows = vec![row("<script>alert(1)</script>")];
        let (json, _) = render_export(
            &manifest(ExportFormat::Json),
            &schema(),
            &rows,
            limits(4096),
        )
        .unwrap();
        let json = String::from_utf8(json).unwrap();
        assert!(json.contains("<script>alert(1)</script>"));
        let (html, _) = render_export(
            &manifest(ExportFormat::Html),
            &schema(),
            &rows,
            limits(8192),
        )
        .unwrap();
        let html = String::from_utf8(html).unwrap();
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("https://"));
    }

    #[test]
    fn zip_contains_manifest_members_and_checksums() {
        let rows = vec![row("raw")];
        let (bytes, stats) = render_export(
            &manifest(ExportFormat::Zip),
            &schema(),
            &rows,
            limits(32 * 1024),
        )
        .unwrap();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        for name in [
            "manifest.json",
            "files.csv",
            "files.json",
            "files.html",
            "checksums.sha256",
        ] {
            assert!(archive.by_name(name).is_ok(), "missing {name}");
        }
        assert_eq!(stats.rows_written, 1);
    }

    #[test]
    fn output_limit_is_a_stable_resource_error() {
        let rows = vec![row("a very long value")];
        let error =
            render_export(&manifest(ExportFormat::Csv), &schema(), &rows, limits(16)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ResourceBudgetExceeded);
        assert!(matches!(
            error,
            ExportError::SizeLimitExceeded { limit: 16 }
        ));
    }

    struct FailingWriter(io::ErrorKind);

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn capacity_write_errors_map_to_insufficient_data_space() {
        for kind in [io::ErrorKind::StorageFull, io::ErrorKind::QuotaExceeded] {
            let error = write_export(
                FailingWriter(kind),
                &manifest(ExportFormat::Csv),
                &schema(),
                &Vec::<ExportRow>::new(),
                limits(4096),
            )
            .unwrap_err();
            assert_eq!(error.code(), ErrorCode::InsufficientDataSpace);
        }
    }

    #[cfg(unix)]
    #[test]
    fn enospc_maps_to_insufficient_data_space() {
        let error = io_error("write export", io::Error::from(rustix::io::Errno::NOSPC));
        assert_eq!(error.code(), ErrorCode::InsufficientDataSpace);
    }

    #[test]
    fn concurrency_limit_releases_on_drop() {
        let concurrency = ExportConcurrency::new(1).unwrap();
        let permit = concurrency.try_acquire().unwrap();
        assert_eq!(concurrency.active(), 1);
        assert_eq!(
            concurrency.try_acquire().unwrap_err().code(),
            ErrorCode::ResourceBusy
        );
        drop(permit);
        assert_eq!(concurrency.active(), 0);
        let other = concurrency.try_acquire().unwrap();
        let join = thread::spawn(move || drop(other));
        join.join().unwrap();
        assert_eq!(concurrency.active(), 0);
    }
}
