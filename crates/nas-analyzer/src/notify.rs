//! Durable notification outbox and SMTP delivery.
//!
//! The outbox is independent from report state. A report may be successful
//! while its notification is pending or failed. The database unique key is
//! the idempotency boundary; SMTP remains at-least-once.

use base64::Engine;
use lettre::message::{Attachment, Mailbox, Message, MultiPart, SinglePart, header::ContentType};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;

use crate::auth;
use crate::error::{AppError, AppResult, ErrorCode};

const CLAIM_LEASE_MINUTES: i64 = 5;
const MAX_RETRIES: u32 = 3;
const MAX_ERROR_CHARS: usize = 1024;
const MAX_SUMMARY_ATTACHMENT_BYTES: usize = 5 * 1024 * 1024;
const SUMMARY_ATTACHMENT_FILENAME: &str = "report-summary.csv";

fn internal(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, message)
}

fn validation(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, message)
}

fn conflict(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Conflict, message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    Starttls,
    Tls,
    None,
}

/// SMTP settings. The password is never serialized or exposed through the
/// public settings view.
#[derive(Clone)]
pub struct NotificationSettings {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub tls_mode: TlsMode,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from_address: String,
    pub default_recipients: Vec<String>,
    pub subject_prefix: String,
    pub public_base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredNotificationSettings {
    enabled: bool,
    smtp_host: String,
    smtp_port: u16,
    tls_mode: TlsMode,
    username: Option<String>,
    password: Option<String>,
    from_address: String,
    default_recipients: Vec<String>,
    subject_prefix: String,
    public_base_url: Option<String>,
}

/// Load the persisted notification settings without exposing the secret
/// fields to an API response. Missing settings are normal before setup.
pub fn load_settings(conn: &Connection) -> AppResult<Option<NotificationSettings>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value_json FROM app_settings WHERE key = 'notifications'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| internal(format!("读取通知设置失败: {e}")))?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let stored: StoredNotificationSettings =
        serde_json::from_str(&raw).map_err(|e| internal(format!("通知设置数据损坏: {e}")))?;
    let settings = NotificationSettings {
        enabled: stored.enabled,
        smtp_host: stored.smtp_host,
        smtp_port: stored.smtp_port,
        tls_mode: stored.tls_mode,
        username: stored.username,
        password: stored.password,
        from_address: stored.from_address,
        default_recipients: stored.default_recipients,
        subject_prefix: stored.subject_prefix,
        public_base_url: stored.public_base_url,
    };
    settings.validate()?;
    Ok(Some(settings))
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationSettingsView {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub tls_mode: TlsMode,
    pub username: Option<String>,
    pub password_set: bool,
    pub from_address: String,
    pub default_recipients: Vec<String>,
    pub subject_prefix: String,
    pub public_base_url: Option<String>,
}

impl NotificationSettings {
    pub fn view(&self) -> NotificationSettingsView {
        NotificationSettingsView {
            enabled: self.enabled,
            smtp_host: self.smtp_host.clone(),
            smtp_port: self.smtp_port,
            tls_mode: self.tls_mode,
            username: self.username.clone(),
            password_set: self.password.is_some(),
            from_address: self.from_address.clone(),
            default_recipients: self.default_recipients.clone(),
            subject_prefix: self.subject_prefix.clone(),
            public_base_url: self.public_base_url.clone(),
        }
    }

    pub fn validate(&self) -> AppResult<()> {
        if self.smtp_host.is_empty() || contains_line_break(&self.smtp_host) {
            return Err(validation("SMTP host 不能为空且不能包含换行"));
        }
        if self.smtp_port == 0 {
            return Err(validation("SMTP port 必须在 1–65535 范围内"));
        }
        if self.tls_mode == TlsMode::None {
            return Err(AppError::new(
                ErrorCode::UnsupportedCapability,
                "通知 SMTP 必须使用 TLS 或 STARTTLS；明文模式未启用",
            ));
        }
        if contains_line_break(&self.subject_prefix) {
            return Err(validation("邮件主题前缀不能包含换行"));
        }
        validate_mailbox(&self.from_address)?;
        for recipient in &self.default_recipients {
            validate_mailbox(recipient)?;
        }
        match (&self.username, &self.password) {
            (Some(username), Some(password)) if !username.is_empty() && !password.is_empty() => {}
            (None, None) => {}
            _ => return Err(validation("SMTP 用户名和密钥必须同时提供或同时省略")),
        }
        Ok(())
    }
}

fn contains_line_break(value: &str) -> bool {
    value.contains('\r') || value.contains('\n')
}

fn validate_mailbox(value: &str) -> AppResult<Mailbox> {
    if contains_line_break(value) {
        return Err(validation("邮件地址不能包含换行"));
    }
    Mailbox::from_str(value).map_err(|_| validation("邮件地址格式无效"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailPayload {
    pub subject: String,
    pub body_text: String,
    #[serde(default)]
    pub attachment: Option<EmailAttachment>,
}

impl EmailPayload {
    fn validate(&self) -> AppResult<()> {
        if self.subject.is_empty() || contains_line_break(&self.subject) {
            return Err(validation("邮件主题不能为空且不能包含换行"));
        }
        if let Some(attachment) = &self.attachment {
            attachment.decode()?;
        }
        Ok(())
    }
}

/// A small, durable attachment embedded in the outbox payload. Only the
/// generated report summary is accepted; full report paths never enter an
/// email payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailAttachment {
    pub filename: String,
    pub content_base64: String,
}

impl EmailAttachment {
    fn decode(&self) -> AppResult<Vec<u8>> {
        if self.filename != SUMMARY_ATTACHMENT_FILENAME
            || contains_line_break(&self.filename)
            || self.filename.contains(['/', '\\'])
        {
            return Err(validation("邮件附件文件名无效"));
        }
        let content = base64::engine::general_purpose::STANDARD
            .decode(&self.content_base64)
            .map_err(|error| validation(format!("邮件附件内容不是合法 base64: {error}")))?;
        if content.len() > MAX_SUMMARY_ATTACHMENT_BYTES {
            return Err(AppError::new(
                ErrorCode::ResourceBudgetExceeded,
                "邮件摘要附件超过 5 MiB 上限",
            ));
        }
        Ok(content)
    }
}

pub fn summary_attachment(content: &[u8]) -> AppResult<EmailAttachment> {
    if content.len() > MAX_SUMMARY_ATTACHMENT_BYTES {
        return Err(AppError::new(
            ErrorCode::ResourceBudgetExceeded,
            "邮件摘要附件超过 5 MiB 上限",
        ));
    }
    Ok(EmailAttachment {
        filename: SUMMARY_ATTACHMENT_FILENAME.to_string(),
        content_base64: base64::engine::general_purpose::STANDARD.encode(content),
    })
}

fn report_meta_value(conn: &Connection, key: &str) -> AppResult<Option<String>> {
    conn.query_row(
        "SELECT value FROM report_meta WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| internal(format!("读取报告元数据 {key} 失败: {error}")))
}

fn summary_csv_cell(value: &str) -> String {
    let first = value.trim_start().chars().next();
    let formula_like = matches!(first, Some('=' | '+' | '-' | '@'))
        || matches!(first, Some(character) if character.is_control());
    let value = if formula_like {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if value
        .chars()
        .any(|character| matches!(character, ',' | '"' | '\r' | '\n'))
    {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

fn append_summary_row(output: &mut Vec<u8>, fields: &[&str]) -> AppResult<()> {
    let row = fields
        .iter()
        .map(|field| summary_csv_cell(field))
        .collect::<Vec<_>>()
        .join(",");
    let new_len = output
        .len()
        .checked_add(row.len())
        .and_then(|length| length.checked_add(2))
        .ok_or_else(|| internal("邮件摘要附件长度溢出"))?;
    if new_len > MAX_SUMMARY_ATTACHMENT_BYTES {
        return Err(AppError::new(
            ErrorCode::ResourceBudgetExceeded,
            "邮件摘要附件超过 5 MiB 上限",
        ));
    }
    output.extend_from_slice(row.as_bytes());
    output.extend_from_slice(b"\r\n");
    Ok(())
}

fn optional_summary_text(value: Option<String>) -> String {
    match value {
        Some(value) => value,
        None => "null".to_string(),
    }
}

/// Render the bounded report summary used by the optional notification
/// attachment. It deliberately contains aggregate values only and never
/// emits file paths or the immutable detail index.
pub fn render_report_summary_csv(conn: &Connection) -> AppResult<Vec<u8>> {
    let mut output = Vec::new();
    append_summary_row(&mut output, &["section", "metric", "value"])?;
    for key in [
        "report_id",
        "run_id",
        "status",
        "consistency",
        "scope_fingerprint",
        "classification_version",
        "scan_started_at",
        "scan_finished_at",
    ] {
        if let Some(value) = report_meta_value(conn, key)? {
            append_summary_row(&mut output, &["report", key, &value])?;
        }
    }

    let mut sections = conn
        .prepare(
            "SELECT section, quality, error_count, message
             FROM section_status ORDER BY section",
        )
        .map_err(|error| internal(format!("准备邮件摘要栏目查询失败: {error}")))?;
    let section_rows = sections
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|error| internal(format!("读取邮件摘要栏目失败: {error}")))?;
    for row in section_rows {
        let (section, quality, error_count, message) =
            row.map_err(|error| internal(format!("读取邮件摘要栏目行失败: {error}")))?;
        append_summary_row(&mut output, &["section_status", &section, &quality])?;
        let error_count = error_count.to_string();
        append_summary_row(&mut output, &["section_status", &section, &error_count])?;
        if let Some(message) = message {
            append_summary_row(&mut output, &["section_status", &section, &message])?;
        }
    }
    drop(sections);

    let mut volumes = conn
        .prepare(
            "SELECT volume_id, sample_time, total_bytes, free_bytes,
                    available_bytes, used_bytes, quality
             FROM volume_samples_snapshot ORDER BY volume_id, sample_time",
        )
        .map_err(|error| internal(format!("准备邮件摘要容量查询失败: {error}")))?;
    let volume_rows = volumes
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|error| internal(format!("读取邮件摘要容量失败: {error}")))?;
    for row in volume_rows {
        let (volume_id, sample_time, total, free, available, used, quality) =
            row.map_err(|error| internal(format!("读取邮件摘要容量行失败: {error}")))?;
        for (metric, value) in [
            ("sample_time", sample_time),
            ("total_bytes", optional_summary_text(total)),
            ("free_bytes", optional_summary_text(free)),
            ("available_bytes", optional_summary_text(available)),
            ("used_bytes", optional_summary_text(used)),
            ("quality", quality),
        ] {
            append_summary_row(
                &mut output,
                &["volume", &volume_id, &format!("{metric}={value}")],
            )?;
        }
    }
    drop(volumes);

    let mut folders = conn
        .prepare(
            "SELECT source_id, source_name, file_count, logical_bytes,
                    unique_logical_bytes, allocated_bytes, completeness
             FROM folder_aggregates WHERE depth = 0 ORDER BY source_id",
        )
        .map_err(|error| internal(format!("准备邮件摘要源汇总查询失败: {error}")))?;
    let folder_rows = folders
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|error| internal(format!("读取邮件摘要源汇总失败: {error}")))?;
    for row in folder_rows {
        let (source_id, source_name, file_count, logical, unique, allocated, completeness) =
            row.map_err(|error| internal(format!("读取邮件摘要源汇总行失败: {error}")))?;
        let file_count = file_count.to_string();
        let logical = match logical {
            Some(value) => value.to_string(),
            None => "null".to_string(),
        };
        let unique = match unique {
            Some(value) => value.to_string(),
            None => "null".to_string(),
        };
        let allocated = match allocated {
            Some(value) => value.to_string(),
            None => "null".to_string(),
        };
        append_summary_row(&mut output, &["source", &source_id, &source_name])?;
        for (metric, value) in [
            ("file_count", file_count),
            ("logical_bytes", logical),
            ("unique_logical_bytes", unique),
            ("allocated_bytes", allocated),
            ("completeness", completeness),
        ] {
            append_summary_row(
                &mut output,
                &["source", &source_id, &format!("{metric}={value}")],
            )?;
        }
    }
    drop(folders);

    let mut duplicates = conn
        .prepare("SELECT logical_redundancy_bytes FROM duplicate_groups ORDER BY group_id")
        .map_err(|error| internal(format!("准备邮件摘要重复查询失败: {error}")))?;
    let duplicate_rows = duplicates
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(|error| internal(format!("读取邮件摘要重复数据失败: {error}")))?;
    let mut duplicate_group_count = 0u64;
    let mut duplicate_redundancy = 0u128;
    for row in duplicate_rows {
        let value = row.map_err(|error| internal(format!("读取邮件摘要重复行失败: {error}")))?;
        let value = u128::try_from(value).map_err(|_| internal("重复逻辑冗余字节不能为负数"))?;
        duplicate_group_count = duplicate_group_count
            .checked_add(1)
            .ok_or_else(|| internal("重复组数量溢出"))?;
        duplicate_redundancy = duplicate_redundancy
            .checked_add(value)
            .ok_or_else(|| internal("重复逻辑冗余字节溢出"))?;
    }
    let duplicate_group_count = duplicate_group_count.to_string();
    let duplicate_redundancy = duplicate_redundancy.to_string();
    append_summary_row(
        &mut output,
        &["duplicates", "group_count", &duplicate_group_count],
    )?;
    append_summary_row(
        &mut output,
        &[
            "duplicates",
            "logical_redundancy_bytes",
            &duplicate_redundancy,
        ],
    )?;
    Ok(output)
}

fn email_body_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

fn report_notification_body(
    conn: &Connection,
    task_name: &str,
    report_id: &str,
    status: &str,
    public_base_url: Option<&str>,
) -> AppResult<String> {
    if task_name.is_empty() || task_name.chars().any(char::is_control) {
        return Err(validation("通知任务名称无效"));
    }
    if !matches!(status, "succeeded" | "partial" | "failed") {
        return Err(validation("通知报告状态无效"));
    }
    if let Some(stored_report_id) = report_meta_value(conn, "report_id")?
        && stored_report_id != report_id
    {
        return Err(internal("通知报告 ID 与报告元数据不一致"));
    }
    if let Some(stored_status) = report_meta_value(conn, "status")?
        && stored_status != status
    {
        return Err(internal("通知报告状态与报告元数据不一致"));
    }

    let scope = match report_meta_value(conn, "scope_snapshot")? {
        Some(value) => email_body_value(&value),
        None => "unknown".to_string(),
    };
    let started = match report_meta_value(conn, "scan_started_at")? {
        Some(value) => email_body_value(&value),
        None => "unknown".to_string(),
    };
    let finished = match report_meta_value(conn, "scan_finished_at")? {
        Some(value) => email_body_value(&value),
        None => "unknown".to_string(),
    };

    let mut body = format!(
        "任务：{}\n报告：{}\n状态：{}\n扫描范围快照：{}\n扫描开始：{}\n扫描结束：{}\n",
        email_body_value(task_name),
        email_body_value(report_id),
        status,
        scope,
        started,
        finished,
    );

    body.push_str("容量样本：\n");
    let mut volumes = conn
        .prepare(
            "SELECT volume_id, sample_time, total_bytes, free_bytes,
                    available_bytes, used_bytes, quality
             FROM volume_samples_snapshot ORDER BY volume_id, sample_time",
        )
        .map_err(|error| internal(format!("准备通知容量查询失败: {error}")))?;
    let volume_rows = volumes
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|error| internal(format!("读取通知容量失败: {error}")))?;
    let mut volume_count = 0u64;
    for row in volume_rows {
        let (volume_id, sample_time, total, free, available, used, quality) =
            row.map_err(|error| internal(format!("读取通知容量行失败: {error}")))?;
        volume_count = volume_count
            .checked_add(1)
            .ok_or_else(|| internal("通知容量样本数量溢出"))?;
        let display = |value: Option<String>| match value {
            Some(value) => email_body_value(&value),
            None => "unknown".to_string(),
        };
        body.push_str(&format!(
            "- volume_id={} sample_time={} total_bytes={} free_bytes={} available_bytes={} used_bytes={} quality={}\n",
            email_body_value(&volume_id),
            email_body_value(&sample_time),
            display(total),
            display(free),
            display(available),
            display(used),
            quality,
        ));
    }
    drop(volumes);
    if volume_count == 0 {
        body.push_str("- unknown\n");
    }

    let mut duplicates = conn
        .prepare("SELECT logical_redundancy_bytes FROM duplicate_groups ORDER BY group_id")
        .map_err(|error| internal(format!("准备通知重复查询失败: {error}")))?;
    let duplicate_rows = duplicates
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(|error| internal(format!("读取通知重复数据失败: {error}")))?;
    let mut duplicate_group_count = 0u64;
    let mut duplicate_redundancy = 0u128;
    for row in duplicate_rows {
        let value = row.map_err(|error| internal(format!("读取通知重复行失败: {error}")))?;
        let value =
            u128::try_from(value).map_err(|_| internal("通知重复逻辑冗余字节不能为负数"))?;
        duplicate_group_count = duplicate_group_count
            .checked_add(1)
            .ok_or_else(|| internal("通知重复组数量溢出"))?;
        duplicate_redundancy = duplicate_redundancy
            .checked_add(value)
            .ok_or_else(|| internal("通知重复逻辑冗余字节溢出"))?;
    }
    body.push_str(&format!(
        "重复组数量：{}\n重复逻辑冗余字节：{}\n",
        duplicate_group_count, duplicate_redundancy
    ));

    body.push_str("错误摘要：\n");
    let mut sections = conn
        .prepare(
            "SELECT section, quality, error_count, message
             FROM section_status ORDER BY section",
        )
        .map_err(|error| internal(format!("准备通知错误摘要查询失败: {error}")))?;
    let section_rows = sections
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|error| internal(format!("读取通知错误摘要失败: {error}")))?;
    let mut error_count = 0u64;
    for row in section_rows {
        let (section, quality, count, message) =
            row.map_err(|error| internal(format!("读取通知错误摘要行失败: {error}")))?;
        if quality == "complete" && count == 0 && message.is_none() {
            continue;
        }
        error_count = error_count
            .checked_add(1)
            .ok_or_else(|| internal("通知错误摘要数量溢出"))?;
        let message = match message {
            Some(message) => email_body_value(&message),
            None => "unknown".to_string(),
        };
        body.push_str(&format!(
            "- section={} quality={} error_count={} message={}\n",
            email_body_value(&section),
            quality,
            count,
            message,
        ));
    }
    if error_count == 0 {
        body.push_str("- none\n");
    }
    if let Some(base_url) = public_base_url {
        body.push_str("认证报告链接：");
        body.push_str(&email_body_value(base_url));
        body.push_str("/reports/");
        body.push_str(&email_body_value(report_id));
        body.push('\n');
    }
    Ok(body)
}

pub fn build_report_notification_payload(
    conn: &Connection,
    task_name: &str,
    report_id: &str,
    status: &str,
    public_base_url: Option<&str>,
    attach_summary: bool,
) -> AppResult<EmailPayload> {
    let body_text = report_notification_body(conn, task_name, report_id, status, public_base_url)?;
    let attachment = if attach_summary {
        Some(summary_attachment(&render_report_summary_csv(conn)?)?)
    } else {
        None
    };
    Ok(EmailPayload {
        subject: format!("报告 {task_name} {status}"),
        body_text,
        attachment,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationState {
    Pending,
    Sending,
    Sent,
    Failed,
    DeliveryUnknown,
}

impl NotificationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sending => "sending",
            Self::Sent => "sent",
            Self::Failed => "failed",
            Self::DeliveryUnknown => "delivery_unknown",
        }
    }

    fn parse(value: &str) -> AppResult<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "sending" => Ok(Self::Sending),
            "sent" => Ok(Self::Sent),
            "failed" => Ok(Self::Failed),
            "delivery_unknown" => Ok(Self::DeliveryUnknown),
            _ => Err(internal(format!("数据库中的通知状态无效: {value:?}"))),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationOutbox {
    pub id: String,
    pub report_id: Option<String>,
    pub recipient: String,
    pub kind: String,
    pub dedupe_key: String,
    pub payload_json: serde_json::Value,
    pub attempts: u32,
    pub next_attempt_at: String,
    pub state: NotificationState,
    pub last_error: Option<String>,
    pub created_at: String,
    pub sent_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NotificationClaim {
    pub item: NotificationOutbox,
    pub lease_until: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InternalNotificationSeverity {
    Info,
    Warning,
    Error,
}

impl InternalNotificationSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    fn parse(value: &str) -> AppResult<Self> {
        match value {
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            _ => Err(internal(format!(
                "数据库中的内部通知严重级别无效: {value:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InternalNotification {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub severity: InternalNotificationSeverity,
    pub read_at: Option<String>,
    pub created_at: String,
}

fn validate_internal_notification_text(value: &str, field: &str) -> AppResult<()> {
    if value.is_empty() {
        return Err(validation(format!("内部通知 {field} 不能为空")));
    }
    if value.chars().any(char::is_control) {
        return Err(validation(format!("内部通知 {field} 不能包含控制字符")));
    }
    Ok(())
}

fn validate_internal_notification_event_key(value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 512
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(validation("内部通知 event_key 无效"));
    }
    Ok(())
}

fn internal_notification_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<InternalNotification> {
    let severity_text: String = row.get("severity")?;
    let severity = InternalNotificationSeverity::parse(&severity_text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.message,
            )),
        )
    })?;
    Ok(InternalNotification {
        id: row.get("id")?,
        kind: row.get("kind")?,
        title: row.get("title")?,
        body: row.get("body")?,
        severity,
        read_at: row.get("read_at")?,
        created_at: row.get("created_at")?,
    })
}

const INTERNAL_NOTIFICATION_COLUMNS: &str = "id, kind, title, body, severity, read_at, created_at";

pub type InternalNotificationPage = (Vec<InternalNotification>, Option<(String, String)>);

fn get_internal_notification(conn: &Connection, id: &str) -> AppResult<InternalNotification> {
    conn.query_row(
        &format!(
            "SELECT {INTERNAL_NOTIFICATION_COLUMNS} \
             FROM internal_notifications WHERE id = ?1"
        ),
        params![id],
        internal_notification_from_row,
    )
    .optional()
    .map_err(|error| internal(format!("读取内部通知失败: {error}")))?
    .ok_or_else(|| internal(format!("内部通知不存在: {id}")))
}

/// Persist one notification shown in the authenticated in-app notification
/// list. It has its own table and lifecycle; SMTP delivery state remains in
/// `notification_outbox`.
pub fn create_internal_notification(
    conn: &Connection,
    kind: &str,
    title: &str,
    body: &str,
    severity: InternalNotificationSeverity,
) -> AppResult<InternalNotification> {
    validate_internal_notification_text(kind, "kind")?;
    validate_internal_notification_text(title, "title")?;
    validate_internal_notification_text(body, "body")?;
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO internal_notifications
         (id, kind, title, body, severity, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        params![id, kind, title, body, severity.as_str()],
    )
    .map_err(|error| internal(format!("写入内部通知失败: {error}")))?;
    get_internal_notification(conn, &id)
}

/// Persist one event-backed notification exactly once. The event key is the
/// consumer idempotency boundary; the generated row id is not used for event
/// ordering or deduplication.
pub fn create_internal_notification_once(
    conn: &Connection,
    event_key: &str,
    kind: &str,
    title: &str,
    body: &str,
    severity: InternalNotificationSeverity,
) -> AppResult<InternalNotification> {
    validate_internal_notification_event_key(event_key)?;
    validate_internal_notification_text(kind, "kind")?;
    validate_internal_notification_text(title, "title")?;
    validate_internal_notification_text(body, "body")?;
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO internal_notifications
         (id, event_key, kind, title, body, severity, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
         ON CONFLICT DO NOTHING",
        params![id, event_key, kind, title, body, severity.as_str()],
    )
    .map_err(|error| internal(format!("写入事件内部通知失败: {error}")))?;
    let stored_id: String = conn
        .query_row(
            "SELECT id FROM internal_notifications WHERE event_key = ?1",
            params![event_key],
            |row| row.get(0),
        )
        .map_err(|error| internal(format!("读取事件内部通知失败: {error}")))?;
    get_internal_notification(conn, &stored_id)
}

/// List newest notifications first using the same `(created_at, id)` keyset
/// used by the API cursor. `page_size + 1` is read only to determine whether
/// another page exists.
pub fn list_internal_notifications(
    conn: &Connection,
    cursor: Option<&(String, String)>,
    page_size: usize,
) -> AppResult<InternalNotificationPage> {
    if page_size == 0 {
        return Err(validation("内部通知 page_size 必须大于 0"));
    }
    let sql_limit = i64::try_from(page_size)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| internal("内部通知 page_size 超出当前平台范围"))?;
    let (cursor_created_at, cursor_id) = match cursor {
        Some((created_at, id)) => (Some(created_at.as_str()), Some(id.as_str())),
        None => (None, None),
    };
    let mut statement = conn
        .prepare(&format!(
            "SELECT {INTERNAL_NOTIFICATION_COLUMNS}
             FROM internal_notifications
             WHERE (?1 IS NULL OR created_at < ?1
                    OR (created_at = ?1 AND id < ?2))
             ORDER BY created_at DESC, id DESC LIMIT ?3"
        ))
        .map_err(|error| internal(format!("准备内部通知列表查询失败: {error}")))?;
    let rows = statement
        .query_map(
            params![cursor_created_at, cursor_id, sql_limit],
            internal_notification_from_row,
        )
        .map_err(|error| internal(format!("查询内部通知列表失败: {error}")))?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(|error| internal(format!("读取内部通知列表行失败: {error}")))?);
    }
    let has_more = items.len() > page_size;
    items.truncate(page_size);
    let next_cursor = if has_more {
        let last_returned = items
            .last()
            .ok_or_else(|| internal("内部通知分页结果为空"))?;
        Some((last_returned.created_at.clone(), last_returned.id.clone()))
    } else {
        None
    };
    Ok((items, next_cursor))
}

fn outbox_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NotificationOutbox> {
    let payload: String = row.get("payload_json")?;
    let attempts: i64 = row.get("attempts")?;
    let attempts = u32::try_from(attempts).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "notification attempts out of range",
            )),
        )
    })?;
    let state_text: String = row.get("state")?;
    let state = NotificationState::parse(&state_text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.message,
            )),
        )
    })?;
    let payload_json = serde_json::from_str(&payload).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(NotificationOutbox {
        id: row.get("id")?,
        report_id: row.get("report_id")?,
        recipient: row.get("recipient")?,
        kind: row.get("kind")?,
        dedupe_key: row.get("dedupe_key")?,
        payload_json,
        attempts,
        next_attempt_at: row.get("next_attempt_at")?,
        state,
        last_error: row.get("last_error")?,
        created_at: row.get("created_at")?,
        sent_at: row.get("sent_at")?,
    })
}

const OUTBOX_COLUMNS: &str = "id, report_id, recipient, kind, dedupe_key, payload_json, attempts, \
    next_attempt_at, state, last_error, created_at, sent_at";

fn get_by_id(conn: &Connection, id: &str) -> AppResult<NotificationOutbox> {
    conn.query_row(
        &format!("SELECT {OUTBOX_COLUMNS} FROM notification_outbox WHERE id = ?1"),
        params![id],
        outbox_from_row,
    )
    .optional()
    .map_err(|e| internal(format!("读取通知 outbox 失败: {e}")))?
    .ok_or_else(|| internal(format!("通知 outbox 行不存在: {id}")))
}

/// Construct a stable logical key without delimiter ambiguity.
pub fn logical_dedupe_key(report_id: Option<&str>, recipient: &str, kind: &str) -> String {
    let mut hasher = Sha256::new();
    match report_id {
        Some(value) => {
            hasher.update([1]);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        None => hasher.update([0]),
    }
    for component in [recipient, kind] {
        hasher.update((component.len() as u64).to_be_bytes());
        hasher.update(component.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn validate_kind(kind: &str) -> AppResult<()> {
    if kind.is_empty() || kind.len() > 128 || kind.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(validation("通知类型无效"));
    }
    Ok(())
}

pub fn enqueue(
    conn: &Connection,
    report_id: Option<&str>,
    recipient: &str,
    kind: &str,
    payload: &EmailPayload,
) -> AppResult<NotificationOutbox> {
    payload.validate()?;
    validate_kind(kind)?;
    validate_mailbox(recipient)?;
    if let Some(id) = report_id
        && id.is_empty()
    {
        return Err(validation("report_id 不能是空字符串"));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let dedupe_key = logical_dedupe_key(report_id, recipient, kind);
    let payload_json =
        serde_json::to_string(payload).map_err(|e| internal(format!("编码通知内容失败: {e}")))?;
    conn.execute(
        "INSERT INTO notification_outbox
         (id, report_id, recipient, kind, dedupe_key, payload_json, attempts,
          next_attempt_at, state, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0,
                 strftime('%Y-%m-%dT%H:%M:%fZ','now'), 'pending',
                 strftime('%Y-%m-%dT%H:%M:%fZ','now'))
         ON CONFLICT(dedupe_key) DO NOTHING",
        params![id, report_id, recipient, kind, dedupe_key, payload_json],
    )
    .map_err(|e| internal(format!("写入通知 outbox 失败: {e}")))?;
    let stored_id = conn
        .query_row(
            "SELECT id FROM notification_outbox WHERE dedupe_key = ?1",
            params![dedupe_key],
            |row| row.get::<_, String>(0),
        )
        .map_err(|e| internal(format!("读取已入队通知失败: {e}")))?;
    get_by_id(conn, &stored_id)
}

fn plus_minutes(timestamp: &str, minutes: i64) -> AppResult<String> {
    let ts = timestamp
        .parse::<jiff::Timestamp>()
        .map_err(|_| internal("通知时间戳格式损坏"))?;
    ts.checked_add(jiff::SignedDuration::from_secs(minutes.saturating_mul(60)))
        .map(|value| value.to_string())
        .map_err(|_| internal("通知时间戳计算溢出"))
}

fn retry_delay_minutes(attempt: u32) -> Option<i64> {
    match attempt {
        1 => Some(1),
        2 => Some(5),
        3 => Some(30),
        _ => None,
    }
}

pub fn claim_next(conn: &mut Connection) -> AppResult<Option<NotificationClaim>> {
    let now = auth::now_rfc3339();
    claim_next_at(conn, &now)
}

/// Claim the oldest due row. Expired `sending` leases are claimable again,
/// recovering a process stopped after claim and before its delivery result.
pub fn claim_next_at(conn: &mut Connection, now: &str) -> AppResult<Option<NotificationClaim>> {
    let lease_until = plus_minutes(now, CLAIM_LEASE_MINUTES)?;
    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("开启通知领取事务失败: {e}")))?;
    let candidate: Option<String> = tx
        .query_row(
            "SELECT id FROM notification_outbox
             WHERE (state = 'pending' OR state = 'sending') AND next_attempt_at <= ?1
             ORDER BY next_attempt_at ASC, created_at ASC, id ASC LIMIT 1",
            params![now],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| internal(format!("查询待发送通知失败: {e}")))?;
    let Some(id) = candidate else {
        tx.commit()
            .map_err(|e| internal(format!("提交空通知领取事务失败: {e}")))?;
        return Ok(None);
    };
    let changed = tx
        .execute(
            "UPDATE notification_outbox
             SET state = 'sending', next_attempt_at = ?2
             WHERE id = ?1 AND (state = 'pending' OR state = 'sending')
               AND next_attempt_at <= ?3",
            params![id, lease_until, now],
        )
        .map_err(|e| internal(format!("领取通知失败: {e}")))?;
    if changed != 1 {
        tx.commit()
            .map_err(|e| internal(format!("提交通知竞争事务失败: {e}")))?;
        return Ok(None);
    }
    let item = tx
        .query_row(
            &format!("SELECT {OUTBOX_COLUMNS} FROM notification_outbox WHERE id = ?1"),
            params![id],
            outbox_from_row,
        )
        .map_err(|e| internal(format!("读取已领取通知失败: {e}")))?;
    tx.commit()
        .map_err(|e| internal(format!("提交通知领取事务失败: {e}")))?;
    Ok(Some(NotificationClaim { item, lease_until }))
}

fn clean_error(error: &str) -> AppResult<String> {
    if error.is_empty() {
        return Err(validation("通知失败原因不能为空"));
    }
    let single_line = error.replace(['\r', '\n'], " ");
    Ok(single_line.chars().take(MAX_ERROR_CHARS).collect())
}

/// Lettre reports an SMTP negative reply separately from transport and
/// response-read failures. A network failure can happen after the message
/// body was accepted, and an unparseable response does not prove rejection;
/// both therefore leave delivery unknown. Explicit SMTP replies and errors
/// before message transmission remain ordinary failures and may use the
/// configured retry windows.
fn delivery_result_is_unknown(error: &str) -> bool {
    error.starts_with("network error:") || error.starts_with("response error:")
}

fn transition_guard(
    conn: &Connection,
    claim: &NotificationClaim,
    next_state: NotificationState,
    next_attempt_at: &str,
    last_error: Option<&str>,
    sent_at: Option<&str>,
    attempts: u32,
) -> AppResult<NotificationOutbox> {
    let changed = conn
        .execute(
            "UPDATE notification_outbox
             SET state = ?2, next_attempt_at = ?3, last_error = ?4,
                 sent_at = ?5, attempts = ?6
             WHERE id = ?1 AND state = 'sending' AND next_attempt_at = ?7
               AND attempts = ?8",
            params![
                claim.item.id,
                next_state.as_str(),
                next_attempt_at,
                last_error,
                sent_at,
                attempts,
                claim.lease_until,
                claim.item.attempts,
            ],
        )
        .map_err(|e| internal(format!("更新通知状态失败: {e}")))?;
    if changed != 1 {
        return Err(conflict("通知领取租约已失效，拒绝覆盖其他 worker 的结果"));
    }
    get_by_id(conn, &claim.item.id)
}

pub fn mark_sent(conn: &Connection, claim: &NotificationClaim) -> AppResult<NotificationOutbox> {
    let now = auth::now_rfc3339();
    transition_guard(
        conn,
        claim,
        NotificationState::Sent,
        &now,
        None,
        Some(&now),
        claim.item.attempts,
    )
}

pub fn mark_failed(
    conn: &Connection,
    claim: &NotificationClaim,
    error: &str,
) -> AppResult<NotificationOutbox> {
    if delivery_result_is_unknown(error) {
        return mark_delivery_unknown(conn, claim, error);
    }
    let now = auth::now_rfc3339();
    mark_failed_at(conn, claim, error, &now)
}

/// Record the three specified retry windows: one, five and thirty minutes.
pub fn mark_failed_at(
    conn: &Connection,
    claim: &NotificationClaim,
    error: &str,
    now: &str,
) -> AppResult<NotificationOutbox> {
    let error = clean_error(error)?;
    let attempts = claim
        .item
        .attempts
        .checked_add(1)
        .ok_or_else(|| internal("通知重试次数溢出"))?;
    let next_state = if attempts > MAX_RETRIES {
        NotificationState::Failed
    } else {
        NotificationState::Pending
    };
    let next_attempt_at = match retry_delay_minutes(attempts) {
        Some(minutes) => plus_minutes(now, minutes)?,
        None => now.to_string(),
    };
    transition_guard(
        conn,
        claim,
        next_state,
        &next_attempt_at,
        Some(&error),
        None,
        attempts,
    )
}

/// The SMTP boundary may leave delivery unknown. This state is terminal so
/// the worker never creates unbounded duplicate mail.
pub fn mark_delivery_unknown(
    conn: &Connection,
    claim: &NotificationClaim,
    error: &str,
) -> AppResult<NotificationOutbox> {
    let now = auth::now_rfc3339();
    let error = clean_error(error)?;
    let attempts = claim
        .item
        .attempts
        .checked_add(1)
        .ok_or_else(|| internal("通知重试次数溢出"))?;
    transition_guard(
        conn,
        claim,
        NotificationState::DeliveryUnknown,
        &now,
        Some(&error),
        None,
        attempts,
    )
}

/// Build one claimed email after validating all envelope/header fields. The
/// current locked dependency set exposes lettre's message builder but not its
/// SMTP transport feature; the delivery worker can pass this message to the
/// configured transport once that feature is enabled by the application
/// dependency contract.
pub fn build_message(
    claim: &NotificationClaim,
    settings: &NotificationSettings,
) -> AppResult<Message> {
    if !settings.enabled {
        return Err(AppError::new(
            ErrorCode::UnsupportedCapability,
            "通知功能未启用",
        ));
    }
    settings.validate()?;
    let payload: EmailPayload = serde_json::from_value(claim.item.payload_json.clone())
        .map_err(|e| validation(format!("通知内容格式无效: {e}")))?;
    payload.validate()?;
    let from = validate_mailbox(&settings.from_address)?;
    let to = validate_mailbox(&claim.item.recipient)?;
    let subject = format!("{}{}", settings.subject_prefix, payload.subject);
    if contains_line_break(&subject) {
        return Err(validation("邮件主题不能包含换行"));
    }
    let builder = Message::builder().from(from).to(to).subject(subject);
    let message = match payload.attachment {
        Some(attachment) => {
            let content = attachment.decode()?;
            let attachment = Attachment::new(attachment.filename).body(
                content,
                ContentType::parse("text/csv; charset=utf-8")
                    .map_err(|error| internal(format!("构造邮件附件类型失败: {error}")))?,
            );
            builder
                .multipart(
                    MultiPart::mixed()
                        .singlepart(SinglePart::plain(payload.body_text))
                        .singlepart(attachment),
                )
                .map_err(|error| internal(format!("构造带附件通知邮件失败: {error}")))?
        }
        None => builder
            .header(ContentType::TEXT_PLAIN)
            .body(payload.body_text)
            .map_err(|error| internal(format!("构造通知邮件失败: {error}")))?,
    };
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::migrate;

    fn db() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate::apply(&mut conn, migrate::CONTROL_MIGRATIONS).unwrap();
        conn
    }

    fn payload() -> EmailPayload {
        EmailPayload {
            subject: "报告完成".into(),
            body_text: "扫描已完成".into(),
            attachment: None,
        }
    }

    #[test]
    fn internal_notifications_are_durable_and_keyset_paginated() {
        let conn = db();
        conn.execute_batch(
            "INSERT INTO internal_notifications
                (id, kind, title, body, severity, created_at)
             VALUES
                ('notification-a', 'source.unavailable', '数据源不可用', 'source-a 当前不可用', 'warning', '2026-01-01T00:00:00.000Z'),
                ('notification-b', 'report.partial', '报告部分成功', 'report-b 包含不完整栏目', 'warning', '2026-01-01T00:00:00.000Z'),
                ('notification-c', 'storage.insufficient', '存储空间不足', '应用数据空间不足', 'error', '2026-01-01T00:00:00.000Z');",
        )
        .unwrap();
        let (page, cursor) = list_internal_notifications(&conn, None, 2).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].id, "notification-c");
        assert_eq!(page[1].id, "notification-b");
        assert_eq!(page[1].severity, InternalNotificationSeverity::Warning);
        let cursor = cursor.expect("page has a next cursor");
        assert_eq!(
            cursor,
            ("2026-01-01T00:00:00.000Z".into(), "notification-b".into())
        );
        let (last_page, no_cursor) = list_internal_notifications(&conn, Some(&cursor), 2).unwrap();
        assert_eq!(last_page.len(), 1);
        assert_eq!(last_page[0].id, "notification-a");
        assert!(no_cursor.is_none());
    }

    #[test]
    fn internal_notification_rejects_control_characters_in_display_fields() {
        let conn = db();
        let error = create_internal_notification(
            &conn,
            "source.unavailable",
            "标题\n",
            "正文",
            InternalNotificationSeverity::Warning,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn event_internal_notification_is_idempotent() {
        let conn = db();
        let first = create_internal_notification_once(
            &conn,
            "scan:run-1:source-unavailable:source-a",
            "source.unavailable",
            "数据源不可用",
            "任务 run-1 的数据源 source-a 当前不可用",
            InternalNotificationSeverity::Warning,
        )
        .unwrap();
        let second = create_internal_notification_once(
            &conn,
            "scan:run-1:source-unavailable:source-a",
            "source.unavailable",
            "数据源不可用",
            "任务 run-1 的数据源 source-a 当前不可用",
            InternalNotificationSeverity::Warning,
        )
        .unwrap();
        assert_eq!(first.id, second.id);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM internal_notifications", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    fn report_db() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate::apply(&mut conn, migrate::REPORT_MIGRATIONS).unwrap();
        conn
    }

    #[test]
    fn enqueue_is_idempotent_for_logical_key() {
        let conn = db();
        let first = enqueue(
            &conn,
            Some("report-1"),
            "admin@example.com",
            "succeeded",
            &payload(),
        )
        .unwrap();
        let second = enqueue(
            &conn,
            Some("report-1"),
            "admin@example.com",
            "succeeded",
            &payload(),
        )
        .unwrap();
        assert_eq!(first.id, second.id);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notification_outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn claim_retry_schedule_and_terminal_failure_are_durable() {
        let mut conn = db();
        let item = enqueue(
            &conn,
            Some("report-1"),
            "admin@example.com",
            "failed",
            &payload(),
        )
        .unwrap();
        conn.execute(
            "UPDATE notification_outbox SET next_attempt_at = '2026-01-01T00:00:00Z' WHERE id = ?1",
            params![item.id],
        )
        .unwrap();
        let claim = claim_next_at(&mut conn, "2026-01-01T00:00:00Z")
            .unwrap()
            .unwrap();
        assert_eq!(claim.item.id, item.id);
        let item =
            mark_failed_at(&conn, &claim, "temporary outage", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(item.state, NotificationState::Pending);
        assert_eq!(item.attempts, 1);
        assert_eq!(item.next_attempt_at, "2026-01-01T00:01:00Z");

        for (now, expected, state) in [
            (
                "2026-01-01T00:01:00Z",
                "2026-01-01T00:06:00Z",
                NotificationState::Pending,
            ),
            (
                "2026-01-01T00:06:00Z",
                "2026-01-01T00:36:00Z",
                NotificationState::Pending,
            ),
            (
                "2026-01-01T00:36:00Z",
                "2026-01-01T00:36:00Z",
                NotificationState::Failed,
            ),
        ] {
            let claim = claim_next_at(&mut conn, now).unwrap().unwrap();
            let item = mark_failed_at(&conn, &claim, "temporary outage", now).unwrap();
            assert_eq!(item.next_attempt_at, expected);
            assert_eq!(item.state, state);
        }
        assert!(
            claim_next_at(&mut conn, "2026-01-01T01:00:00Z")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn smtp_transport_uncertainty_is_terminal_but_explicit_rejection_retries() {
        assert!(delivery_result_is_unknown(
            "network error: connection reset while reading final response"
        ));
        assert!(delivery_result_is_unknown(
            "response error: incomplete response"
        ));
        assert!(!delivery_result_is_unknown(
            "transient error (450): mailbox busy"
        ));
        assert!(!delivery_result_is_unknown(
            "permanent error (550): mailbox unavailable"
        ));

        let mut conn = db();
        let unknown_item = enqueue(
            &conn,
            Some("report-unknown"),
            "unknown@example.com",
            "failed",
            &payload(),
        )
        .unwrap();
        conn.execute(
            "UPDATE notification_outbox SET next_attempt_at = '2026-01-01T00:00:00Z' WHERE id = ?1",
            params![unknown_item.id],
        )
        .unwrap();
        let unknown_claim = claim_next_at(&mut conn, "2026-01-01T00:00:00Z")
            .unwrap()
            .unwrap();
        let unknown = mark_failed(
            &conn,
            &unknown_claim,
            "network error: connection reset while reading final response",
        )
        .unwrap();
        assert_eq!(unknown.state, NotificationState::DeliveryUnknown);
        assert_eq!(unknown.attempts, 1);

        let failed_item = enqueue(
            &conn,
            Some("report-rejected"),
            "rejected@example.com",
            "failed",
            &payload(),
        )
        .unwrap();
        conn.execute(
            "UPDATE notification_outbox SET next_attempt_at = '2026-01-01T00:00:00Z' WHERE id = ?1",
            params![failed_item.id],
        )
        .unwrap();
        let failed_claim = claim_next_at(&mut conn, "2026-01-01T00:00:00Z")
            .unwrap()
            .unwrap();
        let retry_window_start = crate::auth::now_rfc3339();
        let failed = mark_failed(
            &conn,
            &failed_claim,
            "permanent error (550): mailbox unavailable",
        )
        .unwrap();
        let retry_window_end = crate::auth::now_rfc3339();
        assert_eq!(failed.state, NotificationState::Pending);
        assert_eq!(failed.attempts, 1);
        let retry_window_start = plus_minutes(&retry_window_start, 1)
            .unwrap()
            .parse::<jiff::Timestamp>()
            .unwrap();
        let retry_window_end = plus_minutes(&retry_window_end, 1)
            .unwrap()
            .parse::<jiff::Timestamp>()
            .unwrap();
        let next_attempt_at = failed.next_attempt_at.parse::<jiff::Timestamp>().unwrap();
        assert!(
            retry_window_start <= next_attempt_at && next_attempt_at <= retry_window_end,
            "retry window: start={retry_window_start}, end={retry_window_end}, next={next_attempt_at}"
        );
    }

    #[test]
    fn stale_claim_cannot_overwrite_reclaimed_claim() {
        let mut conn = db();
        let item = enqueue(
            &conn,
            Some("report-1"),
            "admin@example.com",
            "failed",
            &payload(),
        )
        .unwrap();
        conn.execute(
            "UPDATE notification_outbox SET next_attempt_at = '2026-01-01T00:00:00Z' WHERE id = ?1",
            params![item.id],
        )
        .unwrap();
        let old = claim_next_at(&mut conn, "2026-01-01T00:00:00Z")
            .unwrap()
            .unwrap();
        let new = claim_next_at(&mut conn, "2026-01-01T00:06:00Z")
            .unwrap()
            .unwrap();
        assert!(mark_sent(&conn, &old).is_err());
        assert!(mark_sent(&conn, &new).is_ok());
    }

    #[test]
    fn smtp_headers_and_plaintext_mode_are_rejected() {
        let settings = NotificationSettings {
            enabled: true,
            smtp_host: "smtp.example.com".into(),
            smtp_port: 587,
            tls_mode: TlsMode::None,
            username: None,
            password: None,
            from_address: "sender@example.com".into(),
            default_recipients: vec!["receiver@example.com".into()],
            subject_prefix: "[NAS]".into(),
            public_base_url: None,
        };
        assert_eq!(
            settings.validate().unwrap_err().code,
            ErrorCode::UnsupportedCapability
        );
        let mut safe = settings.clone();
        safe.tls_mode = TlsMode::Starttls;
        safe.subject_prefix = "bad\nsubject".into();
        assert_eq!(
            safe.validate().unwrap_err().code,
            ErrorCode::ValidationFailed
        );
    }

    #[test]
    fn report_summary_attachment_contains_aggregate_data_and_builds_mime_message() {
        let conn = report_db();
        conn.execute_batch(
            "INSERT INTO report_meta(key, value) VALUES
                ('report_id', 'report-1'),
                ('run_id', 'run-1'),
                ('status', 'partial'),
                ('consistency', 'live_observation'),
                ('scan_started_at', '2026-01-01T00:00:00Z'),
                ('scan_finished_at', '2026-01-01T00:01:00Z');
             INSERT INTO section_status(section, quality, error_count, message)
                VALUES ('folders', 'partial', 1, 'permission denied');
             INSERT INTO folder_aggregates
                (source_id, source_name, raw_relative_path, display_path, depth,
                 file_count, dir_count, logical_bytes, unique_logical_bytes,
                 allocated_bytes, completeness)
                VALUES ('source-1', '测试源', X'', '', 0, 2, 1, 10, 8, 10, 'complete');
             INSERT INTO duplicate_groups
                (group_id, size_bytes, sha256, member_count, listed_member_count,
                 logical_redundancy_bytes, truncated, verification)
                VALUES (1, 4, 'hash', 2, 2, 4, 0, 'hash_complete');",
        )
        .unwrap();

        let csv = render_report_summary_csv(&conn).unwrap();
        let csv_text = String::from_utf8(csv.clone()).unwrap();
        assert!(csv_text.contains("source,source-1,测试源\r\n"));
        assert!(csv_text.contains("duplicates,logical_redundancy_bytes,4\r\n"));
        assert!(!csv_text.contains("/secret/file.txt"));

        let attachment = summary_attachment(&csv).unwrap();
        let payload = EmailPayload {
            subject: "报告 partial".into(),
            body_text: "report complete".into(),
            attachment: Some(attachment),
        };
        let mut control = db();
        let item = enqueue(
            &control,
            Some("report-1"),
            "admin@example.com",
            "partial",
            &payload,
        )
        .unwrap();
        control
            .execute(
                "UPDATE notification_outbox SET next_attempt_at = '2026-01-01T00:00:00Z' WHERE id = ?1",
                params![item.id],
            )
            .unwrap();
        let claim = claim_next_at(&mut control, "2026-01-01T00:00:00Z")
            .unwrap()
            .unwrap();
        assert_eq!(claim.item.id, item.id);
        let settings = NotificationSettings {
            enabled: true,
            smtp_host: "smtp.example.com".into(),
            smtp_port: 587,
            tls_mode: TlsMode::Starttls,
            username: None,
            password: None,
            from_address: "sender@example.com".into(),
            default_recipients: vec!["admin@example.com".into()],
            subject_prefix: "[NAS] ".into(),
            public_base_url: None,
        };
        let message = build_message(&claim, &settings).unwrap();
        let formatted = String::from_utf8(message.formatted()).unwrap();
        assert!(formatted.contains("multipart/mixed"));
        assert!(formatted.contains("filename=\"report-summary.csv\""));
        assert!(formatted.contains("report complete"));
    }

    #[test]
    fn report_notification_payload_includes_required_summary_and_optional_attachment() {
        let conn = report_db();
        conn.execute_batch(
            "INSERT INTO report_meta(key, value) VALUES
                ('report_id', 'report-1'),
                ('status', 'succeeded'),
                ('scope_snapshot', '{\"mode\":\"selected\"}'),
                ('scan_started_at', '2026-01-01T00:00:00Z'),
                ('scan_finished_at', '2026-01-01T00:01:00Z');
             INSERT INTO section_status(section, quality, error_count, message)
                VALUES ('folders', 'complete', 0, NULL);",
        )
        .unwrap();

        let payload = build_report_notification_payload(
            &conn,
            "每日扫描",
            "report-1",
            "succeeded",
            Some("https://nas.example.test"),
            true,
        )
        .unwrap();
        assert!(payload.body_text.contains("每日扫描"));
        assert!(payload.body_text.contains("扫描范围快照"));
        assert!(
            payload
                .body_text
                .contains("认证报告链接：https://nas.example.test/reports/report-1")
        );
        assert!(payload.attachment.is_some());
        payload.validate().unwrap();
    }

    #[test]
    fn summary_attachment_rejects_content_over_five_mib() {
        let content = vec![b'x'; MAX_SUMMARY_ATTACHMENT_BYTES + 1];
        let error = summary_attachment(&content).unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceBudgetExceeded);
    }
}
