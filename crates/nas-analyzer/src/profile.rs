//! Persisted report profile configuration and validation.
//!
//! A profile version is an immutable JSON snapshot.  A running job stores the
//! exact snapshot it was created from, so later edits never rewrite a report's
//! scope, category rules, or duplicate policy.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult, ErrorCode};
use crate::scheduler::schedule::{ScheduleSpec, ScheduleType, next_occurrences};
use crate::source;

const SQL_NOW: &str = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

fn validation(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, message)
}

fn not_found(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::NotFound, message)
}

fn conflict(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Conflict, message)
}

fn default_true() -> bool {
    true
}

fn default_rank_limit() -> u32 {
    200
}

fn default_max_listed_files() -> u32 {
    5_000
}

fn default_min_size_bytes() -> String {
    "1".to_string()
}

fn default_schedule() -> ProfileSchedule {
    ProfileSchedule::default()
}

fn default_retention() -> ProfileRetention {
    ProfileRetention::default()
}

fn default_notifications() -> ProfileNotifications {
    ProfileNotifications::default()
}

fn default_resources() -> ProfileResources {
    ProfileResources::default()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSection {
    Volume,
    Folders,
    Owners,
    Quota,
    Categories,
    Duplicates,
    Largest,
    RecentlyModified,
    LeastAccessed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMode {
    All,
    Selected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FileKindPolicy {
    #[default]
    RegularOnly,
    AllMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateReadPolicy {
    #[default]
    RespectSourcePolicy,
    AllowRemoteRecall,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleTypeInput {
    Manual,
    Daily,
    Weekly,
    Monthly,
    Cron,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MisfirePolicyInput {
    #[default]
    Skip,
    RunOnce,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverlapPolicyInput {
    Skip,
    #[default]
    CoalesceOnce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileScope {
    pub mode: ScopeMode,
    #[serde(default)]
    pub source_ids: Vec<String>,
    #[serde(default)]
    pub include_future_registered: bool,
    #[serde(default)]
    pub include_globs: Vec<String>,
    #[serde(default)]
    pub exclude_globs: Vec<String>,
    #[serde(default)]
    pub file_kind_policy: FileKindPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDuplicates {
    pub enabled: bool,
    #[serde(default)]
    pub match_name: bool,
    #[serde(default)]
    pub match_mtime: bool,
    #[serde(default = "default_min_size_bytes")]
    pub min_size_bytes: String,
    #[serde(default)]
    pub max_size_bytes: Option<String>,
    #[serde(default = "default_max_listed_files")]
    pub max_listed_files: u32,
    #[serde(default)]
    pub hash_budget_bytes: Option<String>,
    #[serde(default)]
    pub content_read_policy: DuplicateReadPolicy,
}

impl Default for ProfileDuplicates {
    fn default() -> Self {
        Self {
            enabled: false,
            match_name: false,
            match_mtime: false,
            min_size_bytes: default_min_size_bytes(),
            max_size_bytes: None,
            max_listed_files: default_max_listed_files(),
            hash_budget_bytes: None,
            content_read_policy: DuplicateReadPolicy::RespectSourcePolicy,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSchedule {
    #[serde(rename = "type")]
    pub schedule_type: ScheduleTypeInput,
    #[serde(default)]
    pub expression: Option<String>,
    #[serde(default)]
    pub time_of_day: Option<String>,
    #[serde(default)]
    pub days_of_week: Vec<u8>,
    #[serde(default)]
    pub day_of_month: Option<u8>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub misfire_policy: MisfirePolicyInput,
    #[serde(default)]
    pub overlap_policy: OverlapPolicyInput,
}

impl ProfileSchedule {
    /// Convert the persisted profile schedule into the scheduler's validated
    /// representation. Manual profiles intentionally return no schedule.
    pub fn schedule_spec(&self) -> AppResult<Option<ScheduleSpec>> {
        let schedule_type = match self.schedule_type {
            ScheduleTypeInput::Manual => return Ok(None),
            ScheduleTypeInput::Daily => ScheduleType::Daily,
            ScheduleTypeInput::Weekly => ScheduleType::Weekly,
            ScheduleTypeInput::Monthly => ScheduleType::Monthly,
            ScheduleTypeInput::Cron => ScheduleType::Cron,
        };
        let spec = ScheduleSpec {
            schedule_type,
            cron_expression: self.expression.clone(),
            time_of_day: self.time_of_day.clone(),
            days_of_week: self.days_of_week.clone(),
            day_of_month: self.day_of_month,
            timezone: self
                .timezone
                .clone()
                .ok_or_else(|| validation("调度需要 timezone"))?,
            misfire_policy: match self.misfire_policy {
                MisfirePolicyInput::Skip => crate::scheduler::MisfirePolicy::Skip,
                MisfirePolicyInput::RunOnce => crate::scheduler::MisfirePolicy::RunOnce,
            },
            overlap_policy: match self.overlap_policy {
                OverlapPolicyInput::Skip => crate::scheduler::OverlapPolicy::Skip,
                OverlapPolicyInput::CoalesceOnce => crate::scheduler::OverlapPolicy::CoalesceOnce,
            },
        };
        spec.validate()?;
        Ok(Some(spec))
    }
}

impl Default for ProfileSchedule {
    fn default() -> Self {
        Self {
            schedule_type: ScheduleTypeInput::Manual,
            expression: None,
            time_of_day: None,
            days_of_week: Vec::new(),
            day_of_month: None,
            timezone: None,
            misfire_policy: MisfirePolicyInput::Skip,
            overlap_policy: OverlapPolicyInput::CoalesceOnce,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRetention {
    #[serde(default = "default_report_keep_count")]
    pub report_keep_count: u32,
    #[serde(default = "default_detail_keep_count")]
    pub detail_keep_count: u32,
}

fn default_report_keep_count() -> u32 {
    30
}

fn default_detail_keep_count() -> u32 {
    3
}

impl Default for ProfileRetention {
    fn default() -> Self {
        Self {
            report_keep_count: default_report_keep_count(),
            detail_keep_count: default_detail_keep_count(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileNotifications {
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default)]
    pub notify_on: Vec<String>,
    #[serde(default)]
    pub attach_summary: bool,
    #[serde(default)]
    pub public_base_url: Option<String>,
}

impl Default for ProfileNotifications {
    fn default() -> Self {
        Self {
            recipients: Vec::new(),
            notify_on: vec!["succeeded".into(), "partial".into(), "failed".into()],
            attach_summary: false,
            public_base_url: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProfileResources {
    #[serde(default)]
    pub metadata_workers: Option<u32>,
    #[serde(default)]
    pub hash_workers: Option<u32>,
    #[serde(default)]
    pub read_limit_mib_s: Option<u32>,
    #[serde(default)]
    pub io_priority: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub description: Option<String>,
    pub scope: ProfileScope,
    pub sections: Vec<ProfileSection>,
    #[serde(default)]
    pub owner_ids_to_list: Vec<i64>,
    #[serde(default = "default_duplicates")]
    pub duplicates: ProfileDuplicates,
    #[serde(default = "default_rank_limit")]
    pub rank_limit: u32,
    #[serde(default = "default_schedule")]
    pub schedule: ProfileSchedule,
    #[serde(default = "default_retention")]
    pub retention: ProfileRetention,
    #[serde(default = "default_notifications")]
    pub notifications: ProfileNotifications,
    #[serde(default = "default_resources")]
    pub resources: ProfileResources,
}

fn default_duplicates() -> ProfileDuplicates {
    ProfileDuplicates::default()
}

impl ProfileConfig {
    pub fn validate(&self, conn: &Connection) -> AppResult<()> {
        let name_len = self.name.chars().count();
        if !(1..=80).contains(&name_len) || self.name.chars().any(char::is_control) {
            return Err(validation("任务名称必须为 1–80 个非控制字符"));
        }
        if self.sections.is_empty() {
            return Err(validation("至少选择一个报告栏目"));
        }
        let mut sections = HashSet::new();
        for section in &self.sections {
            let key = serde_json::to_string(section)
                .map_err(|e| validation(format!("报告栏目无法编码: {e}")))?;
            if !sections.insert(key) {
                return Err(validation("报告栏目不能重复"));
            }
        }
        let min_size = parse_decimal(&self.duplicates.min_size_bytes, "duplicates.min_size_bytes")?;
        if let Some(max) = &self.duplicates.max_size_bytes
            && parse_decimal(max, "duplicates.max_size_bytes")? < min_size
        {
            return Err(validation(
                "duplicates.max_size_bytes 不能小于 min_size_bytes",
            ));
        }
        if !(1..=100_000).contains(&self.duplicates.max_listed_files) {
            return Err(validation("duplicates.max_listed_files 必须为 1–100000"));
        }
        if let Some(budget) = &self.duplicates.hash_budget_bytes {
            parse_decimal(budget, "duplicates.hash_budget_bytes")?;
        }
        if !(1..=10_000).contains(&self.rank_limit) {
            return Err(validation("rank_limit 必须为 1–10000"));
        }
        if self.retention.report_keep_count == 0 {
            return Err(validation("report_keep_count 必须大于 0"));
        }
        if let Some(workers) = self.resources.metadata_workers
            && !(1..=8).contains(&workers)
        {
            return Err(validation("metadata_workers 必须为 1–8"));
        }
        if let Some(workers) = self.resources.hash_workers
            && !(1..=4).contains(&workers)
        {
            return Err(validation("hash_workers 必须为 1–4"));
        }
        if let Some(priority) = &self.resources.io_priority
            && !matches!(priority.as_str(), "low" | "normal")
        {
            return Err(validation("io_priority 必须为 low 或 normal"));
        }
        for recipient in &self.notifications.recipients {
            validate_email(recipient)?;
        }
        for value in &self.notifications.notify_on {
            if !matches!(value.as_str(), "succeeded" | "partial" | "failed") {
                return Err(validation(format!("未知通知条件: {value}")));
            }
        }
        match self.scope.mode {
            ScopeMode::All => {}
            ScopeMode::Selected if self.scope.source_ids.is_empty() => {
                return Err(validation("selected 范围至少需要一个 source_id"));
            }
            ScopeMode::Selected => {}
        }
        for source_id in &self.scope.source_ids {
            let source = source::get_enabled_source(conn, source_id)?;
            if source.disabled_at.is_some() {
                return Err(validation("范围不能引用已停用数据源"));
            }
        }
        crate::scanner::RuleEngine::build(
            &self.scope.exclude_globs,
            &self.scope.include_globs,
            true,
            true,
        )?;
        self.schedule.schedule_spec()?;
        Ok(())
    }

    pub fn source_ids(
        &self,
        conn: &Connection,
        profile_created_at: &str,
    ) -> AppResult<Vec<String>> {
        match self.scope.mode {
            ScopeMode::Selected => Ok(self.scope.source_ids.clone()),
            ScopeMode::All => source::list_sources(conn, false).map(|items| {
                items
                    .into_iter()
                    .filter(|item| {
                        self.scope.include_future_registered
                            || item.created_at.as_str() <= profile_created_at
                    })
                    .map(|item| item.id)
                    .collect()
            }),
        }
    }
}

fn parse_decimal(raw: &str, field: &str) -> AppResult<u64> {
    if raw.is_empty()
        || raw.len() > 20
        || !raw.bytes().all(|byte| byte.is_ascii_digit())
        || (raw.len() > 1 && raw.starts_with('0'))
    {
        return Err(validation(format!(
            "{field} 必须是无前导零的十进制字节字符串"
        )));
    }
    raw.parse::<u64>()
        .map_err(|_| validation(format!("{field} 超出 u64 范围")))
}

fn validate_email(email: &str) -> AppResult<()> {
    if email.is_empty() || email.contains(['\r', '\n']) || email.matches('@').count() != 1 {
        return Err(validation(format!("收件人地址非法: {email:?}")));
    }
    Ok(())
}

/// Compute and serialize the next schedule cursor for a profile version.
/// Manual or disabled profiles intentionally have no next run.
pub fn next_run_at(config: &ProfileConfig, from: DateTime<Utc>) -> AppResult<Option<String>> {
    if !config.enabled {
        return Ok(None);
    }
    let Some(spec) = config.schedule.schedule_spec()? else {
        return Ok(None);
    };
    Ok(next_occurrences(&spec, from, 1)?
        .into_iter()
        .next()
        .and_then(|occurrence| occurrence.at_utc.map(|at| at.to_rfc3339())))
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileRecord {
    #[serde(flatten)]
    pub config: ProfileConfig,
    pub id: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
    pub next_run_at: Option<String>,
    pub deleted_at: Option<String>,
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProfileRecord> {
    let config_s: String = row.get("config_json")?;
    let config = serde_json::from_str(&config_s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(ProfileRecord {
        config,
        id: row.get("id")?,
        version: row.get("current_version")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        next_run_at: row.get("next_run_at")?,
        deleted_at: row.get("deleted_at")?,
    })
}

const PROFILE_SQL: &str = "SELECT p.id, p.current_version, p.created_at, p.updated_at, p.next_run_at, p.deleted_at, v.config_json FROM profiles p JOIN profile_versions v ON v.profile_id = p.id AND v.version = p.current_version";

pub fn get(conn: &Connection, id: &str, include_deleted: bool) -> AppResult<ProfileRecord> {
    let sql = if include_deleted {
        format!("{PROFILE_SQL} WHERE p.id = ?1")
    } else {
        format!("{PROFILE_SQL} WHERE p.id = ?1 AND p.deleted_at IS NULL")
    };
    conn.query_row(&sql, params![id], row_to_record)
        .optional()
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("读取任务失败: {e}")))?
        .ok_or_else(|| not_found("报告任务不存在"))
}

/// Load an immutable profile version for a queued job. The current profile
/// row is intentionally not consulted, so editing a profile cannot rewrite a
/// job that already captured an older version.
pub fn get_version(conn: &Connection, id: &str, version: i64) -> AppResult<ProfileConfig> {
    let config_json: Option<String> = conn
        .query_row(
            "SELECT v.config_json FROM profile_versions v
             JOIN profiles p ON p.id = v.profile_id
             WHERE v.profile_id = ?1 AND v.version = ?2",
            params![id, version],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("读取任务版本失败: {e}")))?;
    let Some(config_json) = config_json else {
        return Err(not_found("报告任务版本不存在"));
    };
    serde_json::from_str(&config_json)
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("任务版本配置损坏: {e}")))
}

pub fn list(conn: &Connection, include_deleted: bool) -> AppResult<Vec<ProfileRecord>> {
    let suffix = if include_deleted {
        " ORDER BY p.created_at, p.id"
    } else {
        " WHERE p.deleted_at IS NULL ORDER BY p.created_at, p.id"
    };
    let mut stmt = conn
        .prepare(&format!("{PROFILE_SQL}{suffix}"))
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("准备任务列表失败: {e}")))?;
    stmt.query_map([], row_to_record)
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("读取任务列表失败: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("读取任务列表失败: {e}")))
}

pub fn create(conn: &Connection, config: ProfileConfig) -> AppResult<ProfileRecord> {
    config.validate(conn)?;
    let scheduled_next = next_run_at(&config, Utc::now())?;
    let id = uuid::Uuid::new_v4().to_string();
    let json = serde_json::to_string(&config)
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("编码任务配置失败: {e}")))?;
    conn.execute(
        &format!("INSERT INTO profiles(id, name, enabled, current_version, created_at, updated_at, next_run_at) VALUES (?1, ?2, ?3, 1, {SQL_NOW}, {SQL_NOW}, ?4)"),
        params![id, config.name, config.enabled, scheduled_next],
    )
    .map_err(|e| AppError::new(ErrorCode::Internal, format!("创建任务失败: {e}")))?;
    conn.execute(
        &format!("INSERT INTO profile_versions(profile_id, version, config_json, created_at) VALUES (?1, 1, ?2, {SQL_NOW})"),
        params![id, json],
    )
    .map_err(|e| AppError::new(ErrorCode::Internal, format!("保存任务版本失败: {e}")))?;
    get(conn, &id, false)
}

pub fn update(
    conn: &Connection,
    id: &str,
    expected_version: i64,
    config: ProfileConfig,
) -> AppResult<ProfileRecord> {
    let current = get(conn, id, false)?;
    if current.version != expected_version {
        return Err(conflict(format!(
            "任务版本已变化，当前版本为 {}",
            current.version
        )));
    }
    config.validate(conn)?;
    let scheduled_next = next_run_at(&config, Utc::now())?;
    let next_version = current
        .version
        .checked_add(1)
        .ok_or_else(|| validation("任务版本溢出"))?;
    let json = serde_json::to_string(&config)
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("编码任务配置失败: {e}")))?;
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("更新任务事务失败: {e}")))?;
    tx.execute(
        &format!("UPDATE profiles SET name = ?2, enabled = ?3, current_version = ?4, next_run_at = ?5, updated_at = {SQL_NOW} WHERE id = ?1 AND current_version = ?6 AND deleted_at IS NULL"),
        params![id, config.name, config.enabled, next_version, scheduled_next, expected_version],
    ).map_err(|e| AppError::new(ErrorCode::Internal, format!("更新任务失败: {e}")))?;
    tx.execute(
        &format!("INSERT INTO profile_versions(profile_id, version, config_json, created_at) VALUES (?1, ?2, ?3, {SQL_NOW})"),
        params![id, next_version, json],
    ).map_err(|e| AppError::new(ErrorCode::Internal, format!("保存任务版本失败: {e}")))?;
    tx.commit()
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("提交任务更新失败: {e}")))?;
    get(conn, id, false)
}

pub fn soft_delete(conn: &Connection, id: &str) -> AppResult<()> {
    let changed = conn.execute(
        &format!("UPDATE profiles SET enabled = 0, next_run_at = NULL, deleted_at = {SQL_NOW}, updated_at = {SQL_NOW} WHERE id = ?1 AND deleted_at IS NULL"),
        params![id],
    ).map_err(|e| AppError::new(ErrorCode::Internal, format!("停用任务失败: {e}")))?;
    if changed == 0 {
        return Err(not_found("报告任务不存在或已经停用"));
    }
    Ok(())
}

pub fn clone_profile(conn: &Connection, id: &str, name: String) -> AppResult<ProfileRecord> {
    let mut config = get(conn, id, false)?.config;
    config.name = name;
    config.validate(conn)?;
    create(conn, config)
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

    fn config() -> ProfileConfig {
        ProfileConfig {
            name: "测试任务".into(),
            enabled: true,
            description: None,
            scope: ProfileScope {
                mode: ScopeMode::All,
                source_ids: vec![],
                include_future_registered: false,
                include_globs: vec![],
                exclude_globs: vec![],
                file_kind_policy: FileKindPolicy::RegularOnly,
            },
            sections: vec![ProfileSection::Folders],
            owner_ids_to_list: vec![],
            duplicates: ProfileDuplicates::default(),
            rank_limit: 200,
            schedule: ProfileSchedule::default(),
            retention: ProfileRetention::default(),
            notifications: ProfileNotifications::default(),
            resources: ProfileResources::default(),
        }
    }

    fn insert_source(
        conn: &Connection,
        id: &str,
        name: &str,
        created_at: &str,
        disabled_at: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, raw_relative_root, created_at, updated_at, disabled_at)
             VALUES (?1, ?2, 'main', CAST('' AS BLOB), ?3, ?3, ?4)",
            params![id, name, created_at, disabled_at],
        )
        .unwrap();
    }

    #[test]
    fn create_and_version_update_are_persisted() {
        let conn = db();
        let record = create(&conn, config()).unwrap();
        assert_eq!(record.version, 1);
        let mut changed = record.config.clone();
        changed.name = "新名称".into();
        let record = update(&conn, &record.id, 1, changed).unwrap();
        assert_eq!(record.version, 2);
        assert!(update(&conn, &record.id, 1, record.config.clone()).is_err());
    }

    #[test]
    fn all_scope_uses_profile_creation_cutoff_and_excludes_disabled_sources() {
        let conn = db();
        let record = create(&conn, config()).unwrap();
        insert_source(&conn, "before", "创建前", "2000-01-01T00:00:00.000Z", None);
        insert_source(&conn, "at", "创建时", &record.created_at, None);
        insert_source(&conn, "after", "创建后", "2999-01-01T00:00:00.000Z", None);
        insert_source(
            &conn,
            "disabled",
            "已停用",
            "2000-01-01T00:00:00.000Z",
            Some("2001-01-01T00:00:00.000Z"),
        );

        assert_eq!(
            record.config.source_ids(&conn, &record.created_at).unwrap(),
            vec!["before", "at"]
        );

        let mut future = record.config.clone();
        future.scope.include_future_registered = true;
        assert_eq!(
            future.source_ids(&conn, &record.created_at).unwrap(),
            vec!["before", "at", "after"]
        );
    }

    #[test]
    fn selected_scope_is_strict_and_validation_rejects_disabled_sources() {
        let conn = db();
        insert_source(&conn, "selected", "选中", "2000-01-01T00:00:00.000Z", None);
        insert_source(
            &conn,
            "unselected",
            "未选中",
            "2000-01-01T00:00:00.000Z",
            None,
        );

        let mut selected = config();
        selected.scope.mode = ScopeMode::Selected;
        selected.scope.source_ids = vec!["selected".into()];
        assert_eq!(
            selected
                .source_ids(&conn, "1999-01-01T00:00:00.000Z")
                .unwrap(),
            vec!["selected"]
        );

        insert_source(
            &conn,
            "disabled-selected",
            "停用选中",
            "2000-01-01T00:00:00.000Z",
            Some("2001-01-01T00:00:00.000Z"),
        );
        selected.scope.source_ids = vec!["disabled-selected".into()];
        assert_eq!(
            selected.validate(&conn).unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn profile_creation_time_is_unchanged_by_version_update() {
        let conn = db();
        let record = create(&conn, config()).unwrap();
        insert_source(&conn, "before", "创建前", "2000-01-01T00:00:00.000Z", None);
        insert_source(&conn, "after", "创建后", "2999-01-01T00:00:00.000Z", None);

        let mut changed = record.config.clone();
        changed.name = "更新后的任务".into();
        let updated = update(&conn, &record.id, record.version, changed).unwrap();

        assert_eq!(updated.created_at, record.created_at);
        assert_eq!(
            updated
                .config
                .source_ids(&conn, &updated.created_at)
                .unwrap(),
            vec!["before"]
        );
    }

    #[test]
    fn scheduled_next_run_is_persisted_and_disabled_profiles_clear_it() {
        let conn = db();
        let mut scheduled = config();
        scheduled.schedule = ProfileSchedule {
            schedule_type: ScheduleTypeInput::Daily,
            expression: None,
            time_of_day: Some("02:00".into()),
            days_of_week: Vec::new(),
            day_of_month: None,
            timezone: Some("UTC".into()),
            misfire_policy: MisfirePolicyInput::Skip,
            overlap_policy: OverlapPolicyInput::CoalesceOnce,
        };

        let record = create(&conn, scheduled).unwrap();
        let persisted: Option<String> = conn
            .query_row(
                "SELECT next_run_at FROM profiles WHERE id = ?1",
                [&record.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(record.next_run_at, persisted);
        assert!(record.next_run_at.is_some());

        let mut disabled = record.config.clone();
        disabled.enabled = false;
        let updated = update(&conn, &record.id, record.version, disabled).unwrap();
        assert_eq!(updated.next_run_at, None);
    }
}
