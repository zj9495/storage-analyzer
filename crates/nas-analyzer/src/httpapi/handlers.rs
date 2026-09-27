//! Route handlers for the M1 surface: health, auth, admins, mounts,
//! sources, volumes. DB access goes through the store writer thread or the
//! read pool; directory listing runs on `spawn_blocking` (spec 15.6).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path as StdPath, PathBuf};
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};

use age::secrecy::{ExposeSecret, SecretString};
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use fssecure::{EntryKind, FsSecureError, SecureRoot};
use futures_core::Stream;
use hmac::{Hmac, Mac};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_util::io::ReaderStream;

use super::{
    ApiJson, AppState, Auth, RequestId, append_cookies, client_ip, csrf_cookie, err_response,
    expired_cookie, internal, list_meta, ok_response, respond, session_cookie,
};
use crate::audit;
use crate::auth::{self, AdminUser};
use crate::backup;
use crate::category::{self, CategoryRuleset};
use crate::cleanup;
use crate::config::ApprovedMount;
use crate::diagnostics;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::export::{
    self, ExportFormat, ExportManifest, ExportManifestOptions, ExportSchema, ExportScope,
    ExportSection, FULL_REPORT_SECTIONS, Metric, QuerySpec, SortKey,
};
use crate::jobs::{self, JobControlAction, JobListFilter, JobState, JobType};
use crate::metadata_import;
use crate::notify::{self, NotificationSettings, TlsMode};
use crate::profile::{self, ProfileConfig};
use crate::retention;
use crate::sampling;
use crate::source::{
    self, Availability, CreateSourceInput, ReadPolicy, SourceDto, SourceProbe, StorageKind,
    UpdateSourceInput,
};
use crate::volume::{
    self, CreateVolumeInput, SampleQuality, UpdateVolumeInput, VolumeDto, VolumeSample,
};

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 200;
/// Upper bound on entries read from one directory level for the picker;
/// beyond this the endpoint refuses rather than buffering unboundedly.
const MAX_DIR_ENTRIES: usize = 100_000;
/// Passphrases for secret backup/restore operations are intentionally not
/// persisted. The job row records only the non-secret policy and export
/// identifier; a process restart therefore fails a secret job closed instead
/// of silently changing it into an unencrypted operation.
static SECRET_PASSPHRASES: OnceLock<parking_lot::Mutex<HashMap<String, SecretString>>> =
    OnceLock::new();

fn secret_passphrases() -> &'static parking_lot::Mutex<HashMap<String, SecretString>> {
    SECRET_PASSPHRASES.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

fn register_secret_passphrase(operation_id: &str, passphrase: String) {
    secret_passphrases()
        .lock()
        .insert(operation_id.to_owned(), SecretString::from(passphrase));
}

fn take_secret_passphrase(operation_id: &str) -> Option<String> {
    secret_passphrases()
        .lock()
        .remove(operation_id)
        .map(|passphrase| passphrase.expose_secret().to_owned())
}

fn discard_secret_passphrase(operation_id: &str) {
    secret_passphrases().lock().remove(operation_id);
}

fn discard_cancelled_secret_backup(job: &jobs::Job) -> AppResult<()> {
    if job.state == JobState::Cancelled && job.job_type == JobType::Backup {
        let export_id = job
            .params_json
            .get("export_id")
            .and_then(Value::as_str)
            .ok_or_else(|| internal("已取消备份任务缺少 export_id"))?;
        discard_secret_passphrase(export_id);
    }
    Ok(())
}

// ---- shared mappers ----

fn admin_json(a: &AdminUser) -> Value {
    json!({
        "id": a.id,
        "username": a.username,
        "enabled": a.enabled,
        "must_change_password": a.must_change_password,
        "created_at": a.created_at,
    })
}

fn source_json(d: &SourceDto) -> Value {
    json!({
        "id": d.id,
        "name": d.name,
        "mount_key": d.mount_key,
        "relative_root_base64": d.relative_root_base64,
        "relative_root": d.relative_root_display,
        "volume_id": d.volume_id,
        "storage_kind": d.storage_kind,
        "read_policy": d.read_policy,
        "write_enabled": d.write_enabled,
        "protected": d.protected,
        "exclusions": d.exclusions,
        "identity_status": d.identity_status,
        "identity_epoch": d.identity_epoch,
        "availability": d.availability,
        "atime_quality": d.atime_quality,
        "deleted_at": d.disabled_at,
        "created_at": d.created_at,
        "updated_at": d.updated_at,
    })
}

fn volume_json(v: &VolumeDto, last_sample: Option<&VolumeSample>) -> Value {
    json!({
        "id": v.id,
        "name": v.name,
        "capacity_source_id": v.capacity_source_id,
        "status": v.status,
        "identity": v.identity_json,
        "last_sample": last_sample.map(sample_json),
        "created_at": v.created_at,
        "updated_at": v.updated_at,
    })
}

fn sample_json(s: &VolumeSample) -> Value {
    let dec = |v: Option<u64>| v.map(|x| x.to_string());
    json!({
        "volume_id": s.volume_id,
        "sample_time": s.sample_time,
        "total_bytes": dec(s.total_bytes),
        "free_bytes": dec(s.free_bytes),
        "available_bytes": dec(s.available_bytes),
        "used_bytes": dec(s.used_bytes),
        "reserved_diff_bytes": dec(s.reserved_diff_bytes),
        "quality": match s.quality {
            SampleQuality::Ok => "complete",
            SampleQuality::Error => "unavailable",
        },
        "error": s.error,
    })
}

fn daily_sample_json(sample: &sampling::DailyVolumeSample) -> Value {
    json!({
        "volume_id": sample.volume_id,
        "sample_time": format!("{}T00:00:00Z", sample.day),
        "total_bytes": sample.total_last,
        "total_min_bytes": sample.total_min,
        "total_max_bytes": sample.total_max,
        "free_bytes": sample.free_last,
        "free_min_bytes": sample.free_min,
        "free_max_bytes": sample.free_max,
        "available_bytes": sample.available_last,
        "available_min_bytes": sample.available_min,
        "available_max_bytes": sample.available_max,
        "used_bytes": sample.used_last,
        "used_min_bytes": sample.used_min,
        "used_max_bytes": sample.used_max,
        "reserved_diff_bytes": null,
        "quality": "complete",
        "error": null,
    })
}

fn list_raw_samples_page(
    conn: &rusqlite::Connection,
    volume_id: &str,
    from: Option<&str>,
    to: Option<&str>,
    cursor: Option<&str>,
    limit: usize,
) -> AppResult<(Vec<VolumeSample>, bool)> {
    volume::get_volume(conn, volume_id)?;
    let sql_limit =
        i64::try_from(limit + 1).map_err(|_| internal("容量历史 page_size 超出当前平台范围"))?;
    let mut stmt = conn
        .prepare(
            "SELECT volume_id, sample_time, total_bytes, free_bytes, available_bytes, \
             used_bytes, quality, error FROM volume_samples \
             WHERE volume_id = ?1 AND (?2 IS NULL OR sample_time >= ?2) \
             AND (?3 IS NULL OR sample_time < ?3) \
             AND (?4 IS NULL OR sample_time > ?4) \
             ORDER BY sample_time ASC LIMIT ?5",
        )
        .map_err(|error| internal(format!("准备容量历史查询失败: {error}")))?;
    let rows = stmt
        .query_map(params![volume_id, from, to, cursor, sql_limit], |row| {
            let parse = |index: usize| -> rusqlite::Result<Option<u64>> {
                row.get::<_, Option<String>>(index)?
                    .map(|value| {
                        value.parse::<u64>().map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                index,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })
                    })
                    .transpose()
            };
            let total = parse(2)?;
            let free = parse(3)?;
            let available = parse(4)?;
            let used = parse(5)?;
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
                let (Some(total), Some(free), Some(available), Some(used)) =
                    (total, free, available, used)
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
                if let Err(message) =
                    volume::validate_capacity_numbers(total, free, available, used)
                {
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
        })
        .map_err(|error| internal(format!("读取容量历史失败: {error}")))?;
    let mut samples = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal(format!("解析容量历史失败: {error}")))?;
    let has_more = samples.len() > limit;
    samples.truncate(limit);
    Ok((samples, has_more))
}

fn map_fs_err(e: FsSecureError) -> AppError {
    match e {
        FsSecureError::NotFound => AppError::new(ErrorCode::NotFound, "目录不存在"),
        FsSecureError::NotDirectory => AppError::new(ErrorCode::BadRequest, "路径不是目录"),
        FsSecureError::PermissionDenied => {
            AppError::new(ErrorCode::Forbidden, "没有读取该目录的权限")
        }
        FsSecureError::PathOutsideRoot
        | FsSecureError::SymlinkNotAllowed
        | FsSecureError::MountCrossingNotAllowed
        | FsSecureError::CrossDevice => {
            AppError::new(ErrorCode::PathOutsideRoot, "路径越出批准根或被安全策略拒绝")
        }
        other => AppError::new(
            ErrorCode::SourceUnavailable,
            format!("读取目录失败: {other}"),
        ),
    }
}

fn map_report_artifact_fs_err(e: FsSecureError) -> AppError {
    match e {
        FsSecureError::NotFound => AppError::new(ErrorCode::NotFound, "报告 artifact 不存在"),
        FsSecureError::MissingCapability => AppError::new(
            ErrorCode::UnsupportedCapability,
            "当前运行环境缺少安全删除能力",
        ),
        FsSecureError::PermissionDenied => {
            AppError::new(ErrorCode::Forbidden, "没有删除报告 artifact 的权限")
        }
        FsSecureError::PathOutsideRoot
        | FsSecureError::SymlinkNotAllowed
        | FsSecureError::MountCrossingNotAllowed
        | FsSecureError::CrossDevice
        | FsSecureError::IdentityChanged => AppError::new(
            ErrorCode::PathOutsideRoot,
            "报告 artifact 路径未通过安全校验",
        ),
        FsSecureError::NotDirectory | FsSecureError::NotRegularFile => AppError::new(
            ErrorCode::ValidationFailed,
            "报告 artifact 类型不符合删除要求",
        ),
        other => AppError::new(
            ErrorCode::Internal,
            format!("删除报告 artifact 失败: {other}"),
        ),
    }
}

fn page_size(raw: Option<u32>) -> usize {
    (raw.unwrap_or(DEFAULT_PAGE_SIZE as u32) as usize).clamp(1, MAX_PAGE_SIZE)
}

fn report_page_size(raw: Option<u32>) -> AppResult<usize> {
    match raw {
        None => Ok(DEFAULT_PAGE_SIZE),
        Some(value) if (1..=MAX_PAGE_SIZE as u32).contains(&value) => Ok(value as usize),
        Some(_) => Err(AppError::new(
            ErrorCode::BadRequest,
            "page_size 必须在 1 到 200 之间",
        )),
    }
}

fn secure_cookies(st: &AppState) -> bool {
    // HTTPS 模式必须 Secure（spec 14.1）；局域网明文 HTTP 部署显式允许时才省略。
    !st.config.server.allow_insecure_lan_http
}

fn session_max_age_secs(st: &AppState) -> u64 {
    u64::from(st.config.security.session_absolute_hours) * 3600
}

fn required_idempotency_key(headers: &HeaderMap) -> AppResult<String> {
    let value = headers.get("idempotency-key").ok_or_else(|| {
        AppError::new(ErrorCode::BadRequest, "请求必须携带有效的 Idempotency-Key")
    })?;
    let value = value
        .to_str()
        .map_err(|_| AppError::new(ErrorCode::BadRequest, "请求必须携带有效的 Idempotency-Key"))?;
    if value.is_empty() || value.len() > 128 {
        return Err(AppError::new(
            ErrorCode::BadRequest,
            "请求必须携带有效的 Idempotency-Key",
        ));
    }
    Ok(value.to_owned())
}

fn job_by_idempotency_key(conn: &rusqlite::Connection, key: &str) -> AppResult<Option<jobs::Job>> {
    let id: Option<String> = conn
        .query_row(
            "SELECT id FROM jobs WHERE idempotency_key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| internal(format!("查询幂等任务失败: {e}")))?;
    id.map(|id| jobs::get_job(conn, &id)).transpose()
}

fn ensure_idempotent_job_request(
    job: &jobs::Job,
    job_type: JobType,
    fields: &[(&str, &Value)],
) -> AppResult<()> {
    if job.job_type != job_type {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Idempotency-Key 已用于其他任务类型",
        ));
    }
    let params = job
        .params_json
        .as_object()
        .ok_or_else(|| internal("幂等任务参数不是 JSON 对象"))?;
    for (field, expected) in fields {
        let actual = params
            .get(*field)
            .ok_or_else(|| internal(format!("幂等任务缺少参数字段 {field}")))?;
        if actual != *expected {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "Idempotency-Key 已用于不同的请求参数",
            ));
        }
    }
    Ok(())
}

fn job_param_string<'a>(job: &'a jobs::Job, field: &'static str) -> AppResult<&'a str> {
    job.params_json
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| internal(format!("幂等任务缺少有效的 {field} 字段")))
}

fn job_param_bool(job: &jobs::Job, field: &'static str) -> AppResult<bool> {
    job.params_json
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| internal(format!("幂等任务缺少有效的 {field} 字段")))
}

fn job_param_value(job: &jobs::Job, field: &'static str) -> AppResult<Value> {
    job.params_json
        .get(field)
        .cloned()
        .ok_or_else(|| internal(format!("幂等任务缺少 {field} 字段")))
}

// ---- health (outside /api/v1) ----

pub async fn health_live() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

/// Ready checks DB reachability; one offline source never affects readiness.
pub async fn health_ready(State(st): State<AppState>) -> Response {
    let result = st
        .readers
        .call(|conn| {
            let status = diagnostics::health_ready(conn, false, true);
            Ok(status)
        })
        .await;
    match result {
        Ok(mut status) => {
            status.initialized = st.is_initialized();
            status.status = if status.checks.database != "ok" || status.checks.config != "ok" {
                "not_ready"
            } else if status.initialized {
                "ready"
            } else {
                "initializing"
            };
            let http_status = if status.status == "not_ready" {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            };
            (http_status, Json(json!(status))).into_response()
        }
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "initialized": st.is_initialized(),
                "checks": {"database": "failed", "config": "ok"},
                "error": error.code.as_str(),
            })),
        )
            .into_response(),
    }
}

// ---- auth ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginBody {
    username: String,
    password: String,
}

pub async fn login(
    req_id: RequestId,
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<LoginBody>,
) -> Response {
    if body.username.len() > 128 || body.password.len() > 1024 {
        return err_response(
            &req_id.0,
            AppError::new(ErrorCode::BadRequest, "用户名或密码长度超限"),
        );
    }
    let ip = client_ip(&st.config.server, peer, &headers);
    if let Err(e) = st.rate_limiter.check(&ip, &body.username) {
        return err_response(&req_id.0, e);
    }
    let idle = i64::from(st.config.security.session_idle_minutes);
    let absolute = i64::from(st.config.security.session_absolute_hours);
    let username = body.username.clone();
    let result = st
        .writer
        .call(
            move |c| match auth::verify_admin_password(c, &body.username, &body.password)? {
                Some(admin) => {
                    let (token, csrf) = auth::create_session(c, &admin.id, idle, absolute)?;
                    Ok(Some((admin, token, csrf)))
                }
                None => Ok(None),
            },
        )
        .await;
    match result {
        Ok(Some((admin, token, csrf))) => {
            st.rate_limiter.record_success(&ip, &username);
            let mut resp = ok_response(
                &req_id.0,
                StatusCode::OK,
                json!({"admin": admin_json(&admin), "csrf_token": csrf}),
                json!({}),
            );
            let secure = secure_cookies(&st);
            let max_age = session_max_age_secs(&st);
            append_cookies(
                &mut resp,
                &[
                    session_cookie(&token, max_age, secure),
                    csrf_cookie(&csrf, max_age, secure),
                ],
            );
            resp
        }
        Ok(None) => {
            st.rate_limiter.record_failure(&ip, &username);
            err_response(
                &req_id.0,
                AppError::new(ErrorCode::Unauthorized, "用户名或密码错误"),
            )
        }
        Err(e) => err_response(&req_id.0, e),
    }
}

pub async fn logout(req_id: RequestId, State(st): State<AppState>, auth: Auth) -> Response {
    let result = st
        .writer
        .call(move |c| auth::revoke_session(c, &auth.token))
        .await
        .map(|_| (StatusCode::OK, json!({}), json!({})));
    let mut resp = respond(&req_id, result);
    append_cookies(
        &mut resp,
        &[
            expired_cookie(super::SESSION_COOKIE),
            expired_cookie(super::CSRF_COOKIE),
        ],
    );
    resp
}

fn find_admin_by_id(admins: &[AdminUser], id: &str) -> AppResult<AdminUser> {
    admins
        .iter()
        .find(|a| a.id == id)
        .cloned()
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "管理员账号不存在"))
}

pub async fn me(req_id: RequestId, State(st): State<AppState>, auth: Auth) -> Response {
    let allow_write = st.config.security.allow_write_operations;
    let kernel_safe = st.kernel_safe_writes;
    let result = st
        .writer
        .call(move |c| {
            let admins = auth::list_admins(c)?;
            let admin = find_admin_by_id(&admins, &auth.session.user_id)
                .map_err(|_| AppError::new(ErrorCode::Unauthorized, "会话所属管理员已不存在"))?;
            let idle = auth
                .session
                .expires_idle_at
                .parse::<jiff::Timestamp>()
                .map_err(|_| internal("数据库中的时间戳格式损坏"))?;
            let absolute = auth
                .session
                .expires_absolute_at
                .parse::<jiff::Timestamp>()
                .map_err(|_| internal("数据库中的时间戳格式损坏"))?;
            Ok((
                StatusCode::OK,
                json!({
                    "admin": admin_json(&admin),
                    "session_expires_at": idle.min(absolute).to_string(),
                    "capabilities": {
                        "write_operations_allowed": allow_write,
                        "write_operations_enabled": allow_write,
                        "kernel_safe_writes": kernel_safe,
                        "can_cleanup": allow_write && kernel_safe,
                        "initialized": true,
                    },
                }),
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordBody {
    new_password: String,
}

pub async fn change_password(
    req_id: RequestId,
    State(st): State<AppState>,
    authn: Auth,
    ApiJson(body): ApiJson<ChangePasswordBody>,
) -> Response {
    let user_id = authn.session.user_id.clone();
    let result = st
        .writer
        .call(move |c| {
            let admin = find_admin_by_id(&auth::list_admins(c)?, &user_id)?;
            auth::reset_password(c, &admin.username, &body.new_password)
        })
        .await
        .map(|_| (StatusCode::OK, json!({}), json!({})));
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReauthBody {
    password: String,
}

pub async fn reauth(
    req_id: RequestId,
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    authn: Auth,
    ApiJson(body): ApiJson<ReauthBody>,
) -> Response {
    let ip = client_ip(&st.config.server, peer, &headers);
    let user_id = authn.session.user_id.clone();
    let username = match st
        .writer
        .call(move |c| auth::list_admins(c).and_then(|admins| find_admin_by_id(&admins, &user_id)))
        .await
    {
        Ok(a) => a.username,
        Err(e) => return err_response(&req_id.0, e),
    };
    if let Err(e) = st.rate_limiter.check(&ip, &username) {
        return err_response(&req_id.0, e);
    }
    let minutes = i64::from(st.config.security.reauth_minutes);
    let uid = authn.session.user_id.clone();
    let username_rl = username.clone();
    let result = st
        .writer
        .call(
            move |c| match auth::verify_admin_password(c, &username, &body.password)? {
                Some(_) => auth::create_reauth_token(c, &uid, minutes).map(Some),
                None => Ok(None),
            },
        )
        .await;
    match result {
        Ok(Some(token)) => {
            st.rate_limiter.record_success(&ip, &username_rl);
            respond(
                &req_id,
                Ok((
                    StatusCode::OK,
                    json!({
                        "reauth_token": token,
                        "expires_at": auth::rfc3339_plus_minutes(minutes),
                    }),
                    json!({}),
                )),
            )
        }
        Ok(None) => {
            st.rate_limiter.record_failure(&ip, &username_rl);
            err_response(
                &req_id.0,
                AppError::new(ErrorCode::Unauthorized, "密码错误"),
            )
        }
        Err(e) => err_response(&req_id.0, e),
    }
}

// ---- admins ----

#[derive(Debug, Deserialize)]
pub struct ListAdminsQuery {
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn list_admins(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Query(q): Query<ListAdminsQuery>,
) -> Response {
    let limit = match report_page_size(q.page_size) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let cursor = match decode_list_position(&auth, q.cursor.as_deref(), "admins") {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let result = st
        .readers
        .call(|c| auth::list_admins(c))
        .await
        .and_then(|mut admins| {
            admins.sort_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then_with(|| left.id.cmp(&right.id))
            });
            let total = admins.len();
            let (page, truncated, next_key) =
                paginate_list(admins, limit, cursor.as_ref(), |admin| {
                    (&admin.created_at, &admin.id)
                });
            let next_cursor = next_key
                .map(|key| encode_list_cursor(&auth, "admins", vec![key.0, key.1]))
                .transpose()?;
            Ok((
                StatusCode::OK,
                json!(page.iter().map(admin_json).collect::<Vec<_>>()),
                list_meta(next_cursor, limit, Some(total), truncated),
            ))
        });
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAdminBody {
    username: String,
    password: String,
}

pub async fn create_admin(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    ApiJson(body): ApiJson<CreateAdminBody>,
) -> Response {
    let result = st
        .writer
        .call(move |c| auth::create_admin(c, &body.username, &body.password))
        .await
        .map(|a| (StatusCode::OK, admin_json(&a), json!({})));
    respond(&req_id, result)
}

pub async fn get_admin(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let result = st
        .readers
        .call(move |c| auth::list_admins(c).and_then(|admins| find_admin_by_id(&admins, &id)))
        .await
        .map(|a| (StatusCode::OK, admin_json(&a), json!({})));
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAdminBody {
    password: Option<String>,
    enabled: Option<bool>,
}

pub async fn update_admin(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<UpdateAdminBody>,
) -> Response {
    let result = st
        .writer
        .call(move |c| {
            let target = find_admin_by_id(&auth::list_admins(c)?, &id)?;
            if let Some(pw) = &body.password {
                auth::reset_password(c, &target.username, pw)?;
            }
            if let Some(enabled) = body.enabled {
                auth::set_enabled(c, &target.username, enabled)?;
            }
            find_admin_by_id(&auth::list_admins(c)?, &id)
        })
        .await
        .map(|a| (StatusCode::OK, admin_json(&a), json!({})));
    respond(&req_id, result)
}

pub async fn delete_admin(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let result = st
        .writer
        .call(move |c| {
            let target = find_admin_by_id(&auth::list_admins(c)?, &id)?;
            auth::delete_admin(c, &target.username)
        })
        .await
        .map(|_| (StatusCode::OK, json!({}), json!({})));
    respond(&req_id, result)
}

// ---- mounts ----

pub async fn list_mounts(req_id: RequestId, State(st): State<AppState>, _auth: Auth) -> Response {
    let mounts = st.config.approved_mounts.clone();
    let allow_write = st.config.security.allow_write_operations;
    let probe = tokio::task::spawn_blocking(move || {
        mounts
            .iter()
            .map(|m| {
                json!({
                    "key": m.key,
                    "container_path": m.container_path.display().to_string(),
                    "host_path_display": null,
                    "readable": SecureRoot::open(m.container_path.as_os_str()).is_ok(),
                    "writable": m.writable,
                    "allow_write_operations": allow_write,
                })
            })
            .collect::<Vec<_>>()
    })
    .await;
    match probe {
        Ok(items) => ok_response(
            &req_id.0,
            StatusCode::OK,
            json!(items),
            list_meta(None, DEFAULT_PAGE_SIZE, Some(items.len()), false),
        ),
        Err(e) => err_response(&req_id.0, internal(format!("挂载探测任务失败: {e}"))),
    }
}

#[derive(Debug, Deserialize)]
pub struct DirQuery {
    path: Option<String>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

struct DirPage {
    items: Vec<Value>,
    next_cursor: Option<String>,
    has_more: bool,
}

/// List subdirectories one level below `path` inside an approved mount.
/// Reads through fssecure (no-follow, raw bytes), sorted by raw name bytes;
/// the opaque cursor is the hex of the last returned name.
fn list_dir_page(
    mount: &ApprovedMount,
    canonical: &[u8],
    cursor: Option<Vec<u8>>,
    limit: usize,
) -> AppResult<DirPage> {
    let root = SecureRoot::open(mount.container_path.as_os_str()).map_err(map_fs_err)?;
    let rel = OsStr::from_bytes(canonical);
    let iter = root.read_dir(rel).map_err(map_fs_err)?;
    let mut names: Vec<Vec<u8>> = Vec::new();
    for entry in iter {
        let e = entry.map_err(map_fs_err)?;
        let include = match e.kind {
            EntryKind::Directory => true,
            EntryKind::Unknown => {
                let mut child = canonical.to_vec();
                if !child.is_empty() {
                    child.push(b'/');
                }
                child.extend_from_slice(e.name.as_bytes());
                matches!(
                    root.stat(OsStr::from_bytes(&child)),
                    Ok(st) if st.kind == EntryKind::Directory
                )
            }
            _ => false, // symlinks etc.: never followed, never listed as dirs
        };
        if include {
            names.push(e.name.as_bytes().to_vec());
            if names.len() > MAX_DIR_ENTRIES {
                return Err(AppError::new(
                    ErrorCode::ValidationFailed,
                    format!("目录项过多（超过 {MAX_DIR_ENTRIES}），请缩小浏览范围"),
                ));
            }
        }
    }
    names.sort();
    let start = match &cursor {
        Some(c) => names.partition_point(|n| n.as_slice() <= c.as_slice()),
        None => 0,
    };
    let mut page: Vec<&[u8]> = names[start..].iter().map(Vec::as_slice).collect();
    let has_more = page.len() > limit;
    page.truncate(limit);
    let next_cursor = if has_more {
        page.last().map(hex::encode)
    } else {
        None
    };
    let items = page
        .iter()
        .map(|name| {
            let mut rel_bytes = canonical.to_vec();
            if !rel_bytes.is_empty() {
                rel_bytes.push(b'/');
            }
            rel_bytes.extend_from_slice(name);
            json!({
                "name": String::from_utf8_lossy(name),
                "name_base64": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    name,
                ),
                "relative_path": String::from_utf8_lossy(&rel_bytes),
                "readable": true,
            })
        })
        .collect();
    Ok(DirPage {
        items,
        next_cursor,
        has_more,
    })
}

pub async fn list_mount_directories(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(key): Path<String>,
    Query(q): Query<DirQuery>,
) -> Response {
    let Some(mount) = st.config.mount(&key).cloned() else {
        return err_response(
            &req_id.0,
            AppError::new(ErrorCode::NotFound, "批准挂载键不存在"),
        );
    };
    let rel = q.path.unwrap_or_default();
    let canonical = match source::canonicalize_relative_root(rel.as_bytes()) {
        Ok(c) => c,
        Err(e) => return err_response(&req_id.0, e),
    };
    let cursor = match q.cursor.as_deref() {
        Some(c) => match hex::decode(c) {
            Ok(v) => Some(v),
            Err(_) => {
                return err_response(
                    &req_id.0,
                    AppError::new(ErrorCode::BadRequest, "无效的分页游标"),
                );
            }
        },
        None => None,
    };
    let limit = page_size(q.page_size);
    let result =
        tokio::task::spawn_blocking(move || list_dir_page(&mount, &canonical, cursor, limit))
            .await
            .unwrap_or_else(|e| Err(internal(format!("目录读取任务失败: {e}"))));
    match result {
        Ok(page) => {
            let n = page.items.len();
            ok_response(
                &req_id.0,
                StatusCode::OK,
                json!(page.items),
                list_meta(page.next_cursor, n, None, page.has_more),
            )
        }
        Err(e) => err_response(&req_id.0, e),
    }
}

// ---- sources ----

#[derive(Debug, Deserialize)]
pub struct ListSourcesQuery {
    include_disabled: Option<bool>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn list_sources(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Query(q): Query<ListSourcesQuery>,
) -> Response {
    let include_disabled = q.include_disabled.unwrap_or(false);
    let cursor_kind = if include_disabled {
        "sources:all"
    } else {
        "sources:enabled"
    };
    let limit = match report_page_size(q.page_size) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let cursor = match decode_list_position(&auth, q.cursor.as_deref(), cursor_kind) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let result = st
        .readers
        .call(move |c| source::list_sources(c, include_disabled))
        .await
        .and_then(|mut sources| {
            sources.sort_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then_with(|| left.id.cmp(&right.id))
            });
            let total = sources.len();
            let (page, truncated, next_key) =
                paginate_list(sources, limit, cursor.as_ref(), |source| {
                    (&source.created_at, &source.id)
                });
            let next_cursor = next_key
                .map(|key| encode_list_cursor(&auth, cursor_kind, vec![key.0, key.1]))
                .transpose()?;
            Ok((
                StatusCode::OK,
                json!(
                    page.iter()
                        .map(|source| source_json(&source.to_dto()))
                        .collect::<Vec<_>>()
                ),
                list_meta(next_cursor, limit, Some(total), truncated),
            ))
        });
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSourceBody {
    name: String,
    mount_key: String,
    #[serde(default)]
    relative_root: Option<String>,
    #[serde(default)]
    relative_root_base64: Option<String>,
    #[serde(default)]
    volume_id: Option<String>,
    #[serde(default)]
    storage_kind: Option<StorageKind>,
    #[serde(default)]
    read_policy: Option<ReadPolicy>,
    #[serde(default)]
    write_enabled: bool,
    #[serde(default)]
    protected: bool,
    #[serde(default)]
    exclusions: Vec<String>,
}

pub async fn create_source(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    ApiJson(body): ApiJson<CreateSourceBody>,
) -> Response {
    let raw_root = match (body.relative_root, body.relative_root_base64) {
        (Some(_), Some(_)) => {
            return err_response(
                &req_id.0,
                AppError::new(
                    ErrorCode::BadRequest,
                    "relative_root 与 relative_root_base64 只能二选一",
                ),
            );
        }
        (Some(s), None) => s.into_bytes(),
        (None, Some(b64)) => {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(b64) {
                Ok(v) => v,
                Err(_) => {
                    return err_response(
                        &req_id.0,
                        AppError::new(
                            ErrorCode::BadRequest,
                            "relative_root_base64 不是合法的 base64",
                        ),
                    );
                }
            }
        }
        (None, None) => Vec::new(),
    };
    let input = CreateSourceInput {
        name: body.name,
        mount_key: body.mount_key,
        raw_relative_root: raw_root,
        volume_id: body.volume_id,
        storage_kind: body.storage_kind.unwrap_or(StorageKind::Unknown),
        read_policy: body.read_policy.unwrap_or(ReadPolicy::MetadataOnly),
        write_enabled: body.write_enabled,
        protected: body.protected,
        exclusions: body.exclusions,
    };
    let cfg = (*st.config).clone();
    let result = st
        .writer
        .call(move |c| source::create_source(c, &cfg, input))
        .await
        .map(|s| (StatusCode::OK, source_json(&s.to_dto()), json!({})));
    respond(&req_id, result)
}

pub async fn get_source(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let result = st
        .readers
        .call(move |c| source::get_source(c, &id))
        .await
        .map(|s| (StatusCode::OK, source_json(&s.to_dto()), json!({})));
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSourceBody {
    name: Option<String>,
    read_policy: Option<ReadPolicy>,
    write_enabled: Option<bool>,
    exclusions: Option<Vec<String>>,
    // Present in the openapi SourceUpdate schema but not mutable in M1;
    // rejected loudly instead of being silently ignored.
    volume_id: Option<Value>,
    storage_kind: Option<Value>,
    protected: Option<Value>,
}

pub async fn update_source(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<UpdateSourceBody>,
) -> Response {
    for (field, present) in [
        ("volume_id", body.volume_id.is_some()),
        ("storage_kind", body.storage_kind.is_some()),
        ("protected", body.protected.is_some()),
    ] {
        if present {
            return err_response(
                &req_id.0,
                AppError::new(
                    ErrorCode::ValidationFailed,
                    format!("当前版本不支持通过 PATCH 修改 {field}"),
                ),
            );
        }
    }
    let input = UpdateSourceInput {
        name: body.name,
        exclusions: body.exclusions,
        read_policy: body.read_policy,
        write_enabled: body.write_enabled,
    };
    let cfg = (*st.config).clone();
    let result = st
        .writer
        .call(move |c| source::update_source(c, &cfg, &id, input))
        .await
        .map(|s| (StatusCode::OK, source_json(&s.to_dto()), json!({})));
    respond(&req_id, result)
}

pub async fn delete_source(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let result = st
        .writer
        .call(move |c| source::soft_delete_source(c, &id))
        .await
        .map(|s| (StatusCode::OK, source_json(&s.to_dto()), json!({})));
    respond(&req_id, result)
}

fn probe_json(probe: &SourceProbe, src: &SourceDto, mount: &ApprovedMount) -> Value {
    let can_read_content = probe.availability == Availability::Online
        && src.read_policy == ReadPolicy::ContentAllowed
        && src.storage_kind == StorageKind::Local;
    let can_write = src.write_enabled && mount.writable && probe.read_only != Some(true);
    let mut notes: Vec<String> = Vec::new();
    if let Some(true) = probe.read_only {
        notes.push("挂载为只读".to_string());
    }
    if let Some(err) = &probe.error {
        notes.push(err.clone());
    }
    if src.storage_kind != StorageKind::Local {
        notes.push("非 local 源默认禁止内容读取".to_string());
    }
    if probe.btrfs_shared_block_risk == source::BtrfsSharedBlockRisk::Possible {
        notes.push(
            "检测到 Btrfs；reflink/快照共享块未测量，已分配估算不是独占量，不提供保证释放字节"
                .to_string(),
        );
    }
    if probe.btrfs_shared_block_risk == source::BtrfsSharedBlockRisk::Unknown {
        notes.push("未识别文件系统类型，共享块语义未知，不提供保证释放字节".to_string());
    }
    json!({
        "availability": probe.availability,
        "mounted": probe.mounted,
        "traversable": probe.traversable,
        "sampled_entries": probe.sampled_entries,
        "sample_truncated": probe.sample_truncated,
        "read_only": probe.read_only,
        "fs_identity": probe.fs_identity,
        "identity_changed": probe.identity_changed,
        "error": probe.error,
        "capabilities": {
            "atime_quality": probe.atime_quality,
            "filesystem_type": probe.filesystem_type,
            "btrfs_shared_block_risk": probe.btrfs_shared_block_risk,
            "can_read_content": can_read_content,
            "can_write": can_write,
            "identity_observed": probe.fs_identity.is_some(),
            "notes": notes,
        },
    })
}

pub async fn probe_source(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let cfg = (*st.config).clone();
    let result = st
        .writer
        .call(move |c| {
            let probe = source::probe_source(c, &cfg, &id)?;
            let src = source::get_source(c, &id)?;
            let mount = cfg
                .mount(&src.mount_key)
                .cloned()
                .ok_or_else(|| internal("数据源引用的挂载键不在部署配置中"))?;
            Ok((probe, src, mount))
        })
        .await
        .map(|(probe, src, mount)| {
            (
                StatusCode::OK,
                probe_json(&probe, &src.to_dto(), &mount),
                json!({}),
            )
        });
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmIdentityBody {
    expected_identity_epoch: i64,
}

pub async fn confirm_source_identity(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ConfirmIdentityBody>,
) -> Response {
    let cfg = (*st.config).clone();
    let result = st
        .writer
        .call(move |c| {
            let current = source::get_source(c, &id)?;
            if current.disabled_at.is_none()
                && current.identity_epoch != body.expected_identity_epoch
            {
                return Err(AppError::new(
                    ErrorCode::Conflict,
                    "identity_epoch 已变化，请重新获取数据源后再确认身份",
                )
                .with_details(json!({"current_identity_epoch": current.identity_epoch})));
            }
            source::confirm_identity(c, &cfg, &id)
        })
        .await
        .map(|s| (StatusCode::OK, source_json(&s.to_dto()), json!({})));
    respond(&req_id, result)
}

// ---- volumes ----

#[derive(Debug, Deserialize)]
pub struct ListVolumesQuery {
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn list_volumes(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Query(q): Query<ListVolumesQuery>,
) -> Response {
    let limit = match report_page_size(q.page_size) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let cursor = match decode_list_position(&auth, q.cursor.as_deref(), "volumes") {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let result = st
        .readers
        .call(|c| {
            let volumes = volume::list_volumes(c)?;
            let samples = sampling::latest_samples(
                c,
                &volumes.iter().map(|v| v.id.clone()).collect::<Vec<_>>(),
            )?;
            Ok((volumes, samples))
        })
        .await
        .and_then(|(mut volumes, samples)| {
            volumes.sort_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then_with(|| left.id.cmp(&right.id))
            });
            let total = volumes.len();
            let (page, truncated, next_key) =
                paginate_list(volumes, limit, cursor.as_ref(), |volume| {
                    (&volume.created_at, &volume.id)
                });
            let next_cursor = next_key
                .map(|key| encode_list_cursor(&auth, "volumes", vec![key.0, key.1]))
                .transpose()?;
            Ok((
                StatusCode::OK,
                json!(
                    page.iter()
                        .map(|volume| volume_json(
                            &volume.to_dto(),
                            samples.iter().find(|sample| sample.volume_id == volume.id)
                        ))
                        .collect::<Vec<_>>()
                ),
                list_meta(next_cursor, limit, Some(total), truncated),
            ))
        });
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVolumeBody {
    name: String,
    #[serde(default)]
    capacity_source_id: Option<String>,
}

pub async fn create_volume(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    ApiJson(body): ApiJson<CreateVolumeBody>,
) -> Response {
    let input = CreateVolumeInput {
        name: body.name,
        capacity_source_id: body.capacity_source_id,
    };
    let result = st
        .writer
        .call(move |c| volume::create_volume(c, input))
        .await
        .map(|v| (StatusCode::OK, volume_json(&v.to_dto(), None), json!({})));
    respond(&req_id, result)
}

pub async fn get_volume(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let result = st
        .readers
        .call(move |c| volume::get_volume(c, &id))
        .await
        .map(|v| (StatusCode::OK, volume_json(&v.to_dto(), None), json!({})));
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateVolumeBody {
    name: Option<String>,
    #[serde(default)]
    capacity_source_id: Option<Option<String>>,
}

pub async fn update_volume(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<UpdateVolumeBody>,
) -> Response {
    let input = UpdateVolumeInput {
        name: body.name,
        capacity_source_id: body.capacity_source_id,
    };
    let result = st
        .writer
        .call(move |c| volume::update_volume(c, &id, input))
        .await
        .map(|v| (StatusCode::OK, volume_json(&v.to_dto(), None), json!({})));
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
pub struct SamplesQuery {
    from: Option<String>,
    to: Option<String>,
    resolution: Option<String>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

fn parse_ts_opt(raw: Option<&str>, field: &str) -> AppResult<Option<jiff::Timestamp>> {
    raw.map(|s| {
        s.parse::<jiff::Timestamp>().map_err(|_| {
            AppError::new(
                ErrorCode::BadRequest,
                format!("{field} 不是合法的 RFC3339 时间"),
            )
        })
    })
    .transpose()
}

fn raw_sample_time_bound(timestamp: &jiff::Timestamp) -> AppResult<String> {
    let minute = timestamp
        .round(
            jiff::TimestampRound::new()
                .smallest(jiff::Unit::Minute)
                .mode(jiff::RoundMode::Ceil),
        )
        .map_err(|error| internal(format!("规范化容量历史时间失败: {error}")))?;
    Ok(format!("{minute:.3}"))
}

/// GET /volumes/{id}/samples — [from, to) half-open window, resolution raw|day.
/// Daily buckets retain min/max and expose the newest sample in the existing
/// byte fields; missing observations remain null.
pub async fn list_volume_samples(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<SamplesQuery>,
) -> Response {
    let SamplesQuery {
        from,
        to,
        resolution,
        cursor,
        page_size: page_size_raw,
    } = q;
    let resolution = resolution.unwrap_or_else(|| "day".to_string());
    if resolution != "raw" && resolution != "day" {
        return err_response(
            &req_id.0,
            AppError::new(ErrorCode::BadRequest, "resolution 只支持 raw 或 day"),
        );
    }
    let from_timestamp = match parse_ts_opt(from.as_deref(), "from") {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let to_timestamp = match parse_ts_opt(to.as_deref(), "to") {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let from = from_timestamp.as_ref().map(ToString::to_string);
    let to = to_timestamp.as_ref().map(ToString::to_string);
    let raw_cursor = if resolution == "raw" {
        match parse_ts_opt(cursor.as_deref(), "cursor") {
            Ok(Some(timestamp)) => match raw_sample_time_bound(&timestamp) {
                Ok(value) => Some(value),
                Err(error) => return err_response(&req_id.0, error),
            },
            Ok(None) => None,
            Err(error) => return err_response(&req_id.0, error),
        }
    } else {
        None
    };
    let raw_from = if resolution == "raw" {
        match from_timestamp
            .as_ref()
            .map(raw_sample_time_bound)
            .transpose()
        {
            Ok(value) => value,
            Err(error) => return err_response(&req_id.0, error),
        }
    } else {
        None
    };
    let raw_to = if resolution == "raw" {
        match to_timestamp.as_ref().map(raw_sample_time_bound).transpose() {
            Ok(value) => value,
            Err(error) => return err_response(&req_id.0, error),
        }
    } else {
        None
    };
    let limit = page_size(page_size_raw);
    let (items, next_cursor, has_more) = if resolution == "day" {
        let query = sampling::DailySampleQuery {
            from,
            to,
            cursor,
            limit: limit as u32,
        };
        let result = st
            .readers
            .call(move |c| sampling::list_daily_samples_page(c, &id, &query))
            .await;
        let page = match result {
            Ok(page) => page,
            Err(e) => return err_response(&req_id.0, e),
        };
        let next_cursor = page.next_cursor;
        let has_more = next_cursor.is_some();
        let items = page.items.iter().map(daily_sample_json).collect::<Vec<_>>();
        (items, next_cursor, has_more)
    } else {
        let result = st
            .readers
            .call(move |c| {
                list_raw_samples_page(
                    c,
                    &id,
                    raw_from.as_deref(),
                    raw_to.as_deref(),
                    raw_cursor.as_deref(),
                    limit,
                )
            })
            .await;
        let (samples, has_more) = match result {
            Ok(page) => page,
            Err(e) => return err_response(&req_id.0, e),
        };
        let next_cursor = has_more
            .then(|| samples.last().map(|sample| sample.sample_time.clone()))
            .flatten();
        let items = samples.iter().map(sample_json).collect::<Vec<_>>();
        (items, next_cursor, has_more)
    };
    let n = items.len();
    let mut meta = list_meta(next_cursor, n, None, has_more);
    meta["resolution_requested"] = json!(resolution);
    meta["resolution_effective"] = json!(resolution);
    ok_response(&req_id.0, StatusCode::OK, json!(items), meta)
}

#[derive(Debug, Deserialize)]
pub struct InternalNotificationsQuery {
    cursor: Option<String>,
    page_size: Option<u32>,
}

/// GET /notifications — newest internal notifications, persisted separately
/// from the SMTP outbox and scoped to the authenticated application admin.
pub async fn list_internal_notifications(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Query(q): Query<InternalNotificationsQuery>,
) -> Response {
    let limit = match report_page_size(q.page_size) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let cursor = match decode_list_position(&auth, q.cursor.as_deref(), "internal-notifications") {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let result = st
        .readers
        .call(move |conn| notify::list_internal_notifications(conn, cursor.as_ref(), limit))
        .await;
    match result {
        Ok((items, next_key)) => {
            let next_cursor = next_key
                .map(|(created_at, id)| {
                    encode_list_cursor(&auth, "internal-notifications", vec![created_at, id])
                })
                .transpose();
            match next_cursor {
                Ok(next_cursor) => {
                    let count = items.len();
                    let has_more = next_cursor.is_some();
                    ok_response(
                        &req_id.0,
                        StatusCode::OK,
                        json!(items),
                        list_meta(next_cursor, count, None, has_more),
                    )
                }
                Err(error) => err_response(&req_id.0, error),
            }
        }
        Err(error) => err_response(&req_id.0, error),
    }
}

// ---- profiles, jobs and reports ----

fn profile_value(record: &profile::ProfileRecord) -> AppResult<Value> {
    serde_json::to_value(record).map_err(|e| internal(format!("编码报告任务响应失败: {e}")))
}

#[derive(Debug, Deserialize)]
pub struct ProfilesQuery {
    include_deleted: Option<bool>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn list_profiles(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Query(q): Query<ProfilesQuery>,
) -> Response {
    let include_deleted = q.include_deleted.unwrap_or(false);
    let limit = match report_page_size(q.page_size) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let cursor_kind = if include_deleted {
        "profiles:all"
    } else {
        "profiles:active"
    };
    let cursor = match decode_list_position(&auth, q.cursor.as_deref(), cursor_kind) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let result = st
        .readers
        .call(move |conn| profile::list(conn, include_deleted))
        .await;
    match result {
        Ok(mut records) => {
            records.sort_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then_with(|| left.id.cmp(&right.id))
            });
            let total = records.len();
            let (records, truncated, next_key) =
                paginate_list(records, limit, cursor.as_ref(), |record| {
                    (&record.created_at, &record.id)
                });
            let next_cursor = match next_key
                .map(|key| encode_list_cursor(&auth, cursor_kind, vec![key.0, key.1]))
                .transpose()
            {
                Ok(value) => value,
                Err(error) => return err_response(&req_id.0, error),
            };
            let items = records
                .into_iter()
                .map(|record| profile_value(&record))
                .collect::<AppResult<Vec<_>>>();
            match items {
                Ok(items) => ok_response(
                    &req_id.0,
                    StatusCode::OK,
                    json!(items),
                    list_meta(next_cursor, limit, Some(total), truncated),
                ),
                Err(error) => err_response(&req_id.0, error),
            }
        }
        Err(error) => err_response(&req_id.0, error),
    }
}

pub async fn create_profile(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    ApiJson(config): ApiJson<ProfileConfig>,
) -> Response {
    let result = st
        .writer
        .call(move |conn| profile::create(conn, config))
        .await
        .and_then(|record| profile_value(&record).map(|value| (StatusCode::OK, value, json!({}))));
    respond(&req_id, result)
}

pub async fn get_profile(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let result = st
        .readers
        .call(move |conn| profile::get(conn, &id, false))
        .await
        .and_then(|record| profile_value(&record).map(|value| (record.version, value)));
    match result {
        Ok((version, value)) => {
            let mut response = ok_response(&req_id.0, StatusCode::OK, value, json!({}));
            if let Ok(value) = HeaderValue::from_str(&version.to_string()) {
                response.headers_mut().insert(header::ETAG, value);
            }
            response
        }
        Err(error) => err_response(&req_id.0, error),
    }
}

pub async fn update_profile(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(config): ApiJson<ProfileConfig>,
) -> Response {
    let Some(raw) = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
    else {
        return err_response(
            &req_id.0,
            AppError::new(
                ErrorCode::BadRequest,
                "PATCH Profile 必须携带 If-Match 版本",
            ),
        );
    };
    let raw = raw.trim_matches('"');
    let expected_version = match raw.parse::<i64>() {
        Ok(version) => version,
        Err(_) => {
            return err_response(
                &req_id.0,
                AppError::new(ErrorCode::BadRequest, "If-Match 不是有效的 Profile 版本"),
            );
        }
    };
    let result = st
        .writer
        .call(move |conn| profile::update(conn, &id, expected_version, config))
        .await
        .and_then(|record| profile_value(&record).map(|value| (StatusCode::OK, value, json!({}))));
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
pub struct DeleteProfileQuery {
    purge_history: Option<bool>,
}

pub async fn delete_profile(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<DeleteProfileQuery>,
) -> Response {
    if q.purge_history.unwrap_or(false) {
        return err_response(
            &req_id.0,
            AppError::new(
                ErrorCode::UnsupportedCapability,
                "删除任务与清理历史报告必须分开执行",
            ),
        );
    }
    let result = st
        .writer
        .call(move |conn| profile::soft_delete(conn, &id))
        .await
        .map(|_| (StatusCode::OK, json!({}), json!({})));
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloneProfileBody {
    name: String,
}

pub async fn clone_profile(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<CloneProfileBody>,
) -> Response {
    let result = st
        .writer
        .call(move |conn| profile::clone_profile(conn, &id, body.name))
        .await
        .and_then(|record| profile_value(&record).map(|value| (StatusCode::OK, value, json!({}))));
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulePreviewBody {
    #[serde(flatten)]
    schedule: crate::profile::ProfileSchedule,
}

pub async fn preview_schedule(
    req_id: RequestId,
    State(_st): State<AppState>,
    _auth: Auth,
    ApiJson(body): ApiJson<SchedulePreviewBody>,
) -> Response {
    let result = body.schedule.schedule_spec()
        .and_then(|spec| spec.map_or_else(|| Ok(Vec::new()), |spec| crate::scheduler::next_occurrences(&spec, chrono::Utc::now(), 5)))
        .map(|occurrences| {
            (
                StatusCode::OK,
                json!({
                    "valid": true,
                    "next_runs": occurrences.into_iter().filter_map(|item| item.at_utc.map(|at| at.to_rfc3339())).collect::<Vec<_>>(),
                    "errors": [],
                }),
                json!({}),
            )
        });
    respond(&req_id, result)
}

pub async fn run_profile(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = st.memory_budget.admit_api("scan_request") {
        return err_response(&req_id.0, error);
    }
    let Some(idempotency_key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
    else {
        return err_response(
            &req_id.0,
            AppError::new(
                ErrorCode::BadRequest,
                "运行任务必须携带有效的 Idempotency-Key",
            ),
        );
    };
    let max_queued = st.config.resources.max_queued_scans as usize;
    let result = st
        .writer
        .call(move |conn| {
            let record = profile::get(conn, &id, false)?;
            let source_ids = record.config.source_ids(conn, &record.created_at)?;
            let profile_snapshot = record.config.clone();
            let ruleset_snapshot = category::load_current(conn)?;
            let params = json!({
                "source_ids": source_ids,
                "profile_snapshot": profile_snapshot,
                "ruleset_snapshot": ruleset_snapshot,
                "rank_limit": record.config.rank_limit,
            });
            jobs::create_scan_job(
                conn,
                &record.id,
                record.version,
                &params,
                Some(&idempotency_key),
                max_queued,
                match record.config.schedule.overlap_policy {
                    profile::OverlapPolicyInput::Skip => crate::scheduler::OverlapPolicy::Skip,
                    profile::OverlapPolicyInput::CoalesceOnce => {
                        crate::scheduler::OverlapPolicy::CoalesceOnce
                    }
                },
            )
        })
        .await
        .and_then(|job| {
            let run_id = job.run_id.ok_or_else(|| internal("运行任务缺少 run_id"))?;
            Ok((
                StatusCode::ACCEPTED,
                json!({"job_id": job.id, "run_id": run_id}),
                json!({}),
            ))
        });
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
pub struct JobsQuery {
    state: Option<JobState>,
    #[serde(rename = "type")]
    job_type: Option<JobType>,
    profile_id: Option<String>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn list_jobs(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Query(q): Query<JobsQuery>,
) -> Response {
    let filter = JobListFilter {
        state: q.state,
        job_type: q.job_type,
        profile_id: q.profile_id,
        cursor: q.cursor,
        page_size: q.page_size.map(|v| v as usize),
    };
    let result = st
        .readers
        .call(move |conn| jobs::list_jobs(conn, &filter))
        .await;
    match result {
        Ok(page) => {
            let count = page.items.len();
            ok_response(
                &req_id.0,
                StatusCode::OK,
                json!(page.items),
                list_meta(
                    page.next_cursor,
                    count,
                    page.total_known.map(|value| value as usize),
                    false,
                ),
            )
        }
        Err(error) => err_response(&req_id.0, error),
    }
}

pub async fn get_job(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let result = st
        .readers
        .call(move |conn| jobs::get_job(conn, &id))
        .await
        .and_then(|job| {
            serde_json::to_value(job)
                .map(|value| (StatusCode::OK, value, json!({})))
                .map_err(|e| internal(format!("编码任务响应失败: {e}")))
        });
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobControlBody {
    action: JobControlAction,
}

pub async fn control_job(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<JobControlBody>,
) -> Response {
    let action = body.action;
    let result = st
        .writer
        .call(move |conn| jobs::control_job(conn, &id, action))
        .await;
    match result {
        Ok(job) => {
            if action == JobControlAction::Cancel
                && let Err(error) = discard_cancelled_secret_backup(&job)
            {
                return err_response(&req_id.0, error);
            }
            match serde_json::to_value(job) {
                Ok(value) => ok_response(&req_id.0, StatusCode::OK, value, json!({})),
                Err(error) => {
                    err_response(&req_id.0, internal(format!("编码任务响应失败: {error}")))
                }
            }
        }
        Err(error) => err_response(&req_id.0, error),
    }
}

pub async fn job_events(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let after = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    let result = st
        .readers
        .call(move |conn| {
            let _ = jobs::get_job(conn, &id)?;
            jobs::list_events(conn, &id, after, jobs::MAX_EVENTS_PER_JOB as usize)
        })
        .await;
    match result {
        Ok(events) => {
            let body = events
                .into_iter()
                .map(|event| {
                    format!(
                        "id: {}\nevent: {}\ndata: {}\n\n",
                        event.sequence, event.event_type, event.payload_json
                    )
                })
                .collect::<String>();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/event-stream")],
                body,
            )
                .into_response()
        }
        Err(error) => err_response(&req_id.0, error),
    }
}

const REPORT_COLUMNS: &str = "id, run_id, profile_id, profile_version, manifest_path,
 status, consistency, scope_fingerprint, classification_version, scan_started_at,
 scan_finished_at, detail_available, pinned, detail_pinned, created_at";

fn report_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": row.get::<_, String>(0)?,
        "run_id": row.get::<_, String>(1)?,
        "profile_id": row.get::<_, Option<String>>(2)?,
        "profile_version": row.get::<_, Option<i64>>(3)?,
        "status": row.get::<_, String>(5)?,
        "consistency": row.get::<_, String>(6)?,
        "scope_fingerprint": row.get::<_, String>(7)?,
        "classification_version": row.get::<_, i64>(8)?,
        "scan_started_at": row.get::<_, Option<String>>(9)?,
        "scan_finished_at": row.get::<_, Option<String>>(10)?,
        "detail_available": row.get::<_, i64>(11)? != 0,
        "pinned": row.get::<_, i64>(12)? != 0,
        "detail_pinned": row.get::<_, i64>(13)? != 0,
        "created_at": row.get::<_, String>(14)?,
    }))
}

fn report_cursor(raw: &str) -> AppResult<(String, String)> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| AppError::new(ErrorCode::ValidationFailed, "报告分页游标无效"))?;
    let value = String::from_utf8(bytes)
        .map_err(|_| AppError::new(ErrorCode::ValidationFailed, "报告分页游标无效"))?;
    value
        .split_once('|')
        .map(|(created, id)| (created.to_owned(), id.to_owned()))
        .ok_or_else(|| AppError::new(ErrorCode::ValidationFailed, "报告分页游标无效"))
}

fn encode_report_cursor(created_at: &str, id: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{created_at}|{id}"))
}

fn decode_opaque_cursor(value: &str) -> AppResult<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::new(ErrorCode::BadRequest, "分页游标无效"))?;
    String::from_utf8(bytes).map_err(|_| AppError::new(ErrorCode::BadRequest, "分页游标无效"))
}

fn encode_opaque_cursor(value: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

type CursorMac = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListCursor {
    kind: String,
    last_values: Vec<String>,
    signature: String,
}

fn list_cursor_unsigned_bytes(cursor: &ListCursor) -> AppResult<Vec<u8>> {
    let mut unsigned = cursor.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned).map_err(|e| internal(format!("编码列表游标失败: {e}")))
}

fn encode_list_cursor(auth: &Auth, kind: &str, last_values: Vec<String>) -> AppResult<String> {
    use base64::Engine;
    let mut cursor = ListCursor {
        kind: kind.to_string(),
        last_values,
        signature: String::new(),
    };
    let bytes = list_cursor_unsigned_bytes(&cursor)?;
    let mut mac = CursorMac::new_from_slice(auth.session.csrf_secret.as_bytes())
        .map_err(|_| internal("创建列表游标签名失败"))?;
    mac.update(&bytes);
    cursor.signature = hex::encode(mac.finalize().into_bytes());
    let encoded =
        serde_json::to_vec(&cursor).map_err(|e| internal(format!("编码列表游标失败: {e}")))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded))
}

fn decode_list_cursor(auth: &Auth, raw: &str, kind: &str) -> AppResult<Vec<String>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| AppError::new(ErrorCode::Conflict, "分页游标无效或已失效"))?;
    let cursor: ListCursor = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::new(ErrorCode::Conflict, "分页游标无效或已失效"))?;
    if cursor.kind != kind {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "分页游标与当前列表查询不匹配",
        ));
    }
    let provided = hex::decode(&cursor.signature)
        .map_err(|_| AppError::new(ErrorCode::Conflict, "分页游标无效或已失效"))?;
    let unsigned = list_cursor_unsigned_bytes(&cursor)?;
    let mut mac = CursorMac::new_from_slice(auth.session.csrf_secret.as_bytes())
        .map_err(|_| internal("校验列表游标签名失败"))?;
    mac.update(&unsigned);
    mac.verify_slice(&provided)
        .map_err(|_| AppError::new(ErrorCode::Conflict, "分页游标无效或已失效"))?;
    Ok(cursor.last_values)
}

fn decode_list_position(
    auth: &Auth,
    raw: Option<&str>,
    kind: &str,
) -> AppResult<Option<(String, String)>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let values = decode_list_cursor(auth, raw, kind)?;
    if values.len() != 2 || values.iter().any(String::is_empty) {
        return Err(AppError::new(ErrorCode::Conflict, "分页游标无效或已失效"));
    }
    Ok(Some((values[0].clone(), values[1].clone())))
}

fn paginate_list<T, F>(
    items: Vec<T>,
    limit: usize,
    cursor: Option<&(String, String)>,
    key: F,
) -> (Vec<T>, bool, Option<(String, String)>)
where
    F: Fn(&T) -> (&str, &str),
{
    let total = items.len();
    let start = match cursor {
        Some(cursor) => match items.iter().position(|item| {
            let (created_at, id) = key(item);
            created_at > cursor.0.as_str()
                || (created_at == cursor.0.as_str() && id > cursor.1.as_str())
        }) {
            Some(index) => index,
            None => total,
        },
        None => 0,
    };
    let available = total - start;
    let truncated = available > limit;
    let end = (start + limit).min(total);
    let next_key = if truncated {
        let (created_at, id) = key(&items[end - 1]);
        Some((created_at.to_string(), id.to_string()))
    } else {
        None
    };
    let page = items.into_iter().skip(start).take(limit).collect();
    (page, truncated, next_key)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportCursor {
    report_id: String,
    dataset_version: String,
    query_hash: String,
    sort_key: String,
    last_values: Vec<String>,
    signature: String,
}

fn cursor_unsigned_bytes(cursor: &ReportCursor) -> AppResult<Vec<u8>> {
    let mut unsigned = cursor.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned).map_err(|e| internal(format!("编码报告游标失败: {e}")))
}

fn encode_report_query_cursor(
    auth: &Auth,
    report_id: &str,
    query_hash: &str,
    sort_key: &str,
    last_values: Vec<String>,
) -> AppResult<String> {
    use base64::Engine;
    let mut cursor = ReportCursor {
        report_id: report_id.to_string(),
        dataset_version: report_id.to_string(),
        query_hash: query_hash.to_string(),
        sort_key: sort_key.to_string(),
        last_values,
        signature: String::new(),
    };
    let bytes = cursor_unsigned_bytes(&cursor)?;
    let mut mac = CursorMac::new_from_slice(auth.session.csrf_secret.as_bytes())
        .map_err(|_| internal("创建报告游标签名失败"))?;
    mac.update(&bytes);
    cursor.signature = hex::encode(mac.finalize().into_bytes());
    let encoded =
        serde_json::to_vec(&cursor).map_err(|e| internal(format!("编码报告游标失败: {e}")))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded))
}

fn decode_report_query_cursor(
    auth: &Auth,
    raw: &str,
    report_id: &str,
    query_hash: &str,
    sort_key: &str,
) -> AppResult<Vec<String>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| AppError::new(ErrorCode::Conflict, "报告分页游标无效或已失效"))?;
    let cursor: ReportCursor = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::new(ErrorCode::Conflict, "报告分页游标无效或已失效"))?;
    if cursor.report_id != report_id
        || cursor.dataset_version != report_id
        || cursor.query_hash != query_hash
        || cursor.sort_key != sort_key
    {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "报告分页游标与当前查询不匹配",
        ));
    }
    let provided = hex::decode(&cursor.signature)
        .map_err(|_| AppError::new(ErrorCode::Conflict, "报告分页游标无效或已失效"))?;
    let unsigned = cursor_unsigned_bytes(&cursor)?;
    let mut mac = CursorMac::new_from_slice(auth.session.csrf_secret.as_bytes())
        .map_err(|_| internal("校验报告游标签名失败"))?;
    mac.update(&unsigned);
    mac.verify_slice(&provided)
        .map_err(|_| AppError::new(ErrorCode::Conflict, "报告分页游标无效或已失效"))?;
    Ok(cursor.last_values)
}

fn normalized_query(spec: QuerySpec) -> AppResult<QuerySpec> {
    spec.normalize()
        .map_err(|error| AppError::new(error.code(), error.to_string()))
}

fn report_list_meta(
    next_cursor: Option<String>,
    page_size: usize,
    truncated: bool,
    detail_available: bool,
) -> Value {
    json!({
        "next_cursor": next_cursor,
        "page_size": page_size,
        "total_known": null,
        "truncated": truncated,
        "detail_available": detail_available,
    })
}

fn query_sort_key(scope: &str, spec: &QuerySpec) -> AppResult<String> {
    let sort = serde_json::to_string(&spec.sort)
        .map_err(|e| internal(format!("编码报告排序字段失败: {e}")))?;
    Ok(format!("{scope}:{sort}"))
}

fn decimal_i64(field: &'static str, value: &str) -> AppResult<i64> {
    value.parse::<i64>().map_err(|_| {
        AppError::new(
            ErrorCode::BadRequest,
            format!("{field} 必须是 SQLite 可表示的十进制整数"),
        )
    })
}

fn timestamp_parts(field: &'static str, value: Option<&str>) -> AppResult<Option<(i64, i64)>> {
    value
        .map(|raw| {
            let timestamp = raw.parse::<jiff::Timestamp>().map_err(|_| {
                AppError::new(
                    ErrorCode::BadRequest,
                    format!("{field} 不是有效 RFC3339 时间"),
                )
            })?;
            Ok((
                timestamp.as_second(),
                i64::from(timestamp.subsec_nanosecond()),
            ))
        })
        .transpose()
}

fn metric_column(metric: Metric) -> &'static str {
    match metric {
        Metric::LogicalBytes => "logical_bytes",
        Metric::AllocatedEstimateBytes => "allocated_estimate_bytes",
        Metric::FileCount => "file_count",
    }
}

fn sort_direction(sort: SortKey) -> &'static str {
    match sort {
        SortKey::SizeAsc | SortKey::MtimeAsc | SortKey::AtimeAsc | SortKey::NameAsc => "ASC",
        SortKey::SizeDesc | SortKey::MtimeDesc | SortKey::AtimeDesc | SortKey::CountDesc => "DESC",
    }
}

fn nullable_metric_cursor(metric: Option<i64>, tie: impl ToString) -> Vec<String> {
    match metric {
        Some(value) => vec!["0".to_string(), value.to_string(), tie.to_string()],
        None => vec!["1".to_string(), String::new(), tie.to_string()],
    }
}

fn parse_nullable_metric_cursor(
    values: &[String],
    tie_field: &'static str,
) -> AppResult<(Option<i64>, i64)> {
    if values.len() != 3 {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "报告分页游标无效或已失效",
        ));
    }
    let null_rank = decimal_i64("cursor.null_metric", &values[0])?;
    let metric = match null_rank {
        0 => Some(decimal_i64("cursor.metric", &values[1])?),
        1 if values[1].is_empty() => None,
        _ => {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "报告分页游标无效或已失效",
            ));
        }
    };
    Ok((metric, decimal_i64(tie_field, &values[2])?))
}

fn validate_aggregate_sort(sort: SortKey) -> AppResult<()> {
    if matches!(
        sort,
        SortKey::MtimeDesc | SortKey::MtimeAsc | SortKey::AtimeDesc | SortKey::AtimeAsc
    ) {
        return Err(AppError::new(
            ErrorCode::BadRequest,
            "该聚合视图不支持按文件时间排序",
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct ReportsQuery {
    profile_id: Option<String>,
    status: Option<String>,
    from: Option<String>,
    to: Option<String>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn list_reports(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Query(q): Query<ReportsQuery>,
) -> Response {
    let limit = page_size(q.page_size);
    let cursor = match q.cursor.as_deref() {
        Some(value) => match report_cursor(value) {
            Ok(value) => Some(value),
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let result = st
        .readers
        .call(move |conn| {
            let (cursor_created, cursor_id) = cursor
                .as_ref()
                .map(|(created, id)| (Some(created.clone()), Some(id.clone())))
                .unwrap_or((None, None));
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {REPORT_COLUMNS} FROM reports
                     WHERE (?1 IS NULL OR profile_id = ?1)
                       AND (?2 IS NULL OR status = ?2)
                       AND (?3 IS NULL OR created_at >= ?3)
                       AND (?4 IS NULL OR created_at < ?4)
                       AND (?5 IS NULL OR created_at < ?5 OR (created_at = ?5 AND id < ?6))
                     ORDER BY created_at DESC, id DESC LIMIT ?7"
                ))
                .map_err(|e| internal(format!("准备报告列表失败: {e}")))?;
            let rows = stmt
                .query_map(
                    rusqlite::params![
                        q.profile_id,
                        q.status,
                        q.from,
                        q.to,
                        cursor_created,
                        cursor_id,
                        limit as i64 + 1,
                    ],
                    report_row,
                )
                .map_err(|e| internal(format!("读取报告列表失败: {e}")))?;
            let mut items = Vec::new();
            for row in rows {
                items.push(row.map_err(|e| internal(format!("读取报告行失败: {e}")))?);
            }
            let next_cursor = if items.len() > limit {
                let last = items.pop().ok_or_else(|| internal("报告分页结果为空"))?;
                Some(encode_report_cursor(
                    last["created_at"]
                        .as_str()
                        .ok_or_else(|| internal("报告时间字段损坏"))?,
                    last["id"]
                        .as_str()
                        .ok_or_else(|| internal("报告 id 字段损坏"))?,
                ))
            } else {
                None
            };
            Ok((items, next_cursor))
        })
        .await;
    match result {
        Ok((items, next_cursor)) => ok_response(
            &req_id.0,
            StatusCode::OK,
            json!(items),
            list_meta(next_cursor, items.len(), None, false),
        ),
        Err(error) => err_response(&req_id.0, error),
    }
}

fn report_manifest_path(conn: &rusqlite::Connection, id: &str) -> AppResult<PathBuf> {
    let path: Option<String> = conn
        .query_row(
            "SELECT manifest_path FROM reports WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| internal(format!("读取报告路径失败: {e}")))?;
    path.map(PathBuf::from)
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "报告不存在"))
}

fn report_directory_relative(
    reports_root: &StdPath,
    report_id: &str,
    manifest: &StdPath,
) -> AppResult<PathBuf> {
    let relative = manifest
        .strip_prefix(reports_root)
        .map_err(|_| AppError::new(ErrorCode::PathOutsideRoot, "报告 manifest 不在批准报告根内"))?;
    let mut components = relative.components();
    match (components.next(), components.next(), components.next()) {
        (Some(Component::Normal(directory)), Some(Component::Normal(file)), None)
            if directory == OsStr::new(report_id) && file == OsStr::new("manifest.json") =>
        {
            Ok(PathBuf::from(directory))
        }
        _ => Err(AppError::new(
            ErrorCode::PathOutsideRoot,
            "报告 manifest 路径不符合应用 artifact 布局",
        )),
    }
}

fn report_summary_state(conn: &rusqlite::Connection, id: &str) -> AppResult<(PathBuf, bool)> {
    let row: Option<(String, bool)> = conn
        .query_row(
            "SELECT manifest_path, detail_available != 0 FROM reports WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| internal(format!("读取报告明细状态失败: {e}")))?;
    let Some((manifest, detail_available)) = row else {
        return Err(AppError::new(ErrorCode::NotFound, "报告不存在"));
    };
    Ok((PathBuf::from(manifest), detail_available))
}

fn report_directory_state(
    conn: &rusqlite::Connection,
    reports_root: &StdPath,
    report_id: &str,
) -> AppResult<(PathBuf, bool)> {
    let (manifest, detail_available) = report_summary_state(conn, report_id)?;
    let directory = report_directory_relative(reports_root, report_id, &manifest)?;
    Ok((directory, detail_available))
}

fn open_report_database(
    conn: &rusqlite::Connection,
    reports_root: &StdPath,
    report_id: &str,
    artifact_name: &'static str,
    operation: &str,
) -> AppResult<(rusqlite::Connection, bool)> {
    let (directory, detail_available) = report_directory_state(conn, reports_root, report_id)?;
    if artifact_name == "index.sqlite" && !detail_available {
        return Err(AppError::new(
            ErrorCode::DetailExpired,
            "报告文件明细已过期",
        ));
    }
    let root = SecureRoot::open(reports_root.as_os_str()).map_err(map_report_artifact_fs_err)?;
    let opened = root
        .open_file(
            directory.join(artifact_name).as_os_str(),
            fssecure::OpenOptions::default(),
        )
        .map_err(map_report_artifact_fs_err)?;
    let database = crate::report::open_published_from_opened(opened, operation)?;
    Ok((database, detail_available))
}

fn enrich_report_summary(mut summary: Value, db: &rusqlite::Connection) -> AppResult<Value> {
    let mut section_quality = serde_json::Map::new();
    let mut warnings = Vec::new();
    let mut section_rows = db
        .prepare("SELECT section, quality, message FROM section_status ORDER BY section")
        .map_err(|e| internal(format!("准备报告栏目状态查询失败: {e}")))?;
    let section_iter = section_rows
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|e| internal(format!("读取报告栏目状态失败: {e}")))?;
    for row in section_iter {
        let (section, quality, message) =
            row.map_err(|e| internal(format!("解析报告栏目状态失败: {e}")))?;
        section_quality.insert(section, Value::String(quality));
        if let Some(message) = message {
            warnings.push(message);
        }
    }
    summary["section_quality"] = Value::Object(section_quality);
    summary["warnings"] = json!(warnings);

    let totals: (Option<i64>, Option<i64>, Option<i64>) = db
        .query_row(
            "SELECT SUM(file_count),
                    CASE WHEN COUNT(logical_bytes) = COUNT(*) THEN SUM(logical_bytes) END,
                    CASE WHEN COUNT(allocated_bytes) = COUNT(*) THEN SUM(allocated_bytes) END
             FROM category_aggregates",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|e| internal(format!("读取报告总计失败: {e}")))?;
    summary["totals"] = json!({
        "file_count": totals.0.map(|value| value.to_string()),
        "logical_bytes": totals.1.map(|value| value.to_string()),
        "allocated_estimate_bytes": totals.2.map(|value| value.to_string()),
    });

    let mut quota_rows = db
        .prepare(
            "SELECT principal_namespace, principal_uid, scope_kind, scope_id, metric,
                    origin, limit_state, limit_bytes, used_bytes, observed_at, expires_at,
                    provider_label, stale
             FROM quota_snapshot ORDER BY principal_namespace, principal_uid, scope_kind, scope_id, metric",
        )
        .map_err(|e| internal(format!("准备报告配额快照查询失败: {e}")))?;
    let quotas = quota_rows
        .query_map([], |row| {
            Ok(json!({
                "principal": {
                    "namespace": row.get::<_, String>(0)?,
                    "uid": row.get::<_, i64>(1)?,
                },
                "scope": {
                    "kind": row.get::<_, String>(2)?,
                    "id": row.get::<_, String>(3)?,
                },
                "metric": row.get::<_, String>(4)?,
                "origin": row.get::<_, String>(5)?,
                "limit": {
                    "state": row.get::<_, String>(6)?,
                    "bytes": row.get::<_, Option<String>>(7)?,
                },
                "used_bytes": row.get::<_, Option<String>>(8)?,
                "observed_at": row.get::<_, String>(9)?,
                "expires_at": row.get::<_, Option<String>>(10)?,
                "provider_label": row.get::<_, Option<String>>(11)?,
                "stale": row.get::<_, i64>(12)? != 0,
            }))
        })
        .map_err(|e| internal(format!("读取报告配额快照失败: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal(format!("解析报告配额快照失败: {e}")))?;
    summary["quota_snapshot"] = json!(quotas);

    for (meta_key, output_key) in [
        ("scope_snapshot", "scope_snapshot"),
        ("source_identities", "source_identities"),
    ] {
        let value: Option<String> = db
            .query_row(
                "SELECT value FROM report_meta WHERE key = ?1",
                [meta_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| internal(format!("读取报告元数据失败: {e}")))?;
        if let Some(value) = value {
            summary[output_key] = serde_json::from_str(&value)
                .map_err(|e| internal(format!("报告元数据格式损坏: {e}")))?;
        }
    }
    Ok(summary)
}

/// Normalize the first report manifest shape used by this application to the
/// public report-detail contract. Reports are immutable artifacts, so an
/// upgrade must keep already-published reports readable while new reports use
/// the current array form directly.
fn normalize_report_manifest(
    mut manifest: Value,
    reports_root: &StdPath,
    report_id: &str,
) -> AppResult<Value> {
    let Some(files) = manifest.get("files") else {
        return Err(internal("报告 manifest 缺少文件清单"));
    };
    let Value::Object(files) = files else {
        return Ok(manifest);
    };
    let directory = report_id;
    let root = SecureRoot::open(reports_root.as_os_str()).map_err(map_report_artifact_fs_err)?;
    let mut normalized = Vec::with_capacity(files.len());
    for (relative, digest) in files {
        let path = StdPath::new(relative);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(internal("报告 manifest 包含非法文件路径"));
        }
        let sha256 = digest
            .as_str()
            .ok_or_else(|| internal("报告 manifest 文件摘要格式损坏"))?;
        let relative_path = StdPath::new(directory).join(path);
        let opened = root
            .open_file(relative_path.as_os_str(), fssecure::OpenOptions::default())
            .map_err(map_report_artifact_fs_err)?;
        let size_bytes = opened.stat.size_bytes.to_string();
        normalized.push(json!({
            "path": relative,
            "size_bytes": size_bytes,
            "sha256": sha256,
        }));
    }
    let object = manifest
        .as_object_mut()
        .ok_or_else(|| internal("报告 manifest 顶层格式损坏"))?;
    if !object.contains_key("schema_version") {
        let schema_version = object
            .remove("manifest_version")
            .ok_or_else(|| internal("报告 manifest 缺少 schema_version"))?;
        object.insert("schema_version".to_string(), schema_version);
    } else {
        object.remove("manifest_version");
    }
    object
        .entry("app_version".to_string())
        .or_insert_with(|| json!(env!("CARGO_PKG_VERSION")));
    object.insert("files".to_string(), Value::Array(normalized));
    Ok(manifest)
}

pub async fn get_report(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let report_id = id.clone();
    let result = st
        .readers
        .call(move |conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {REPORT_COLUMNS} FROM reports WHERE id = ?1"
                ))
                .map_err(|e| internal(format!("准备报告详情失败: {e}")))?;
            let summary = stmt
                .query_row([report_id.as_str()], report_row)
                .optional()
                .map_err(|e| internal(format!("读取报告详情失败: {e}")))?
                .ok_or_else(|| AppError::new(ErrorCode::NotFound, "报告不存在"))?;
            let manifest_path = report_manifest_path(conn, &report_id)?;
            Ok((summary, manifest_path))
        })
        .await;
    match result {
        Ok((mut summary, manifest_path)) => {
            let reports_root = st.config.storage.data_dir.join("reports");
            let directory = match report_directory_relative(&reports_root, &id, &manifest_path) {
                Ok(directory) => directory,
                Err(error) => return err_response(&req_id.0, error),
            };
            let root = match SecureRoot::open(reports_root.as_os_str())
                .map_err(map_report_artifact_fs_err)
            {
                Ok(root) => root,
                Err(error) => return err_response(&req_id.0, error),
            };
            let manifest = match root
                .open_file(
                    directory.join("manifest.json").as_os_str(),
                    fssecure::OpenOptions::default(),
                )
                .map_err(map_report_artifact_fs_err)
                .and_then(|opened| {
                    let mut file = File::from(opened.fd);
                    let mut text = String::new();
                    file.read_to_string(&mut text)
                        .map_err(|e| AppError::from_io("读取报告 manifest 失败", e))?;
                    serde_json::from_str::<Value>(&text)
                        .map_err(|e| internal(format!("报告 manifest 格式损坏: {e}")))
                }) {
                Ok(value) => value,
                Err(error) => return err_response(&req_id.0, error),
            };
            summary["manifest"] = match normalize_report_manifest(manifest, &reports_root, &id) {
                Ok(value) => value,
                Err(error) => return err_response(&req_id.0, error),
            };
            summary["detail_path"] = match root.open_file(
                directory.join("index.sqlite").as_os_str(),
                fssecure::OpenOptions::default(),
            ) {
                Ok(_) => json!(true),
                Err(FsSecureError::NotFound) => json!(false),
                Err(error) => {
                    return err_response(&req_id.0, map_report_artifact_fs_err(error));
                }
            };
            let report_db = match root
                .open_file(
                    directory.join("report.sqlite").as_os_str(),
                    fssecure::OpenOptions::default(),
                )
                .map_err(map_report_artifact_fs_err)
                .and_then(|opened| {
                    crate::report::open_published_from_opened(opened, "打开报告摘要失败")
                }) {
                Ok(database) => database,
                Err(error) => return err_response(&req_id.0, error),
            };
            let summary = match enrich_report_summary(summary, &report_db) {
                Ok(summary) => summary,
                Err(error) => return err_response(&req_id.0, error),
            };
            ok_response(&req_id.0, StatusCode::OK, summary, json!({}))
        }
        Err(error) => err_response(&req_id.0, error),
    }
}

pub async fn delete_report(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let reports_root = st.config.storage.data_dir.join("reports");
    let result = st
        .writer
        .call(move |conn| {
            let manifest = report_manifest_path(conn, &id)?;
            let pinned: i64 = conn
                .query_row("SELECT pinned FROM reports WHERE id = ?1", [&id], |row| {
                    row.get(0)
                })
                .map_err(|e| internal(format!("读取报告固定状态失败: {e}")))?;
            if pinned != 0 {
                return Err(AppError::new(ErrorCode::Conflict, "固定报告不能删除"));
            }
            let directory = report_directory_relative(&reports_root, &id, &manifest)?;
            let tx = conn
                .transaction()
                .map_err(|e| AppError::from_sqlite("开启删除报告事务失败", e))?;
            let changed = tx
                .execute("DELETE FROM reports WHERE id = ?1", [&id])
                .map_err(|e| AppError::from_sqlite("删除报告记录失败", e))?;
            if changed == 0 {
                return Err(AppError::new(ErrorCode::NotFound, "报告不存在"));
            }
            tx.commit()
                .map_err(|e| AppError::from_sqlite("提交删除报告事务失败", e))?;
            let root = match SecureRoot::open(reports_root.as_os_str()) {
                Ok(root) => root,
                Err(FsSecureError::NotFound) => return Ok(()),
                Err(error) => return Err(map_report_artifact_fs_err(error)),
            };
            match root.remove_dir_all(directory.as_os_str()) {
                Ok(()) | Err(FsSecureError::NotFound) => {}
                Err(error) => return Err(map_report_artifact_fs_err(error)),
            }
            Ok(())
        })
        .await
        .map(|_| (StatusCode::OK, json!({}), json!({})));
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinReportBody {
    report_pinned: Option<bool>,
    detail_pinned: Option<bool>,
}

pub async fn pin_report(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<PinReportBody>,
) -> Response {
    if body.report_pinned.is_none() && body.detail_pinned.is_none() {
        return err_response(
            &req_id.0,
            AppError::new(ErrorCode::BadRequest, "至少需要提供一个固定状态"),
        );
    }
    let result = st
        .writer
        .call(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE reports SET pinned = COALESCE(?2, pinned),
                     detail_pinned = COALESCE(?3, detail_pinned) WHERE id = ?1",
                    rusqlite::params![
                        id,
                        body.report_pinned.map(i64::from),
                        body.detail_pinned.map(i64::from)
                    ],
                )
                .map_err(|e| AppError::from_sqlite("更新报告固定状态失败", e))?;
            if changed == 0 {
                return Err(AppError::new(ErrorCode::NotFound, "报告不存在"));
            }
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {REPORT_COLUMNS} FROM reports WHERE id = ?1"
                ))
                .map_err(|e| internal(format!("读取报告固定状态失败: {e}")))?;
            stmt.query_row([id.as_str()], report_row)
                .map_err(|e| internal(format!("读取报告固定状态失败: {e}")))
        })
        .await
        .map(|value| (StatusCode::OK, value, json!({})));
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
pub struct ReportFoldersQuery {
    parent_entry_id: Option<String>,
    metric: Option<Metric>,
    sort: Option<SortKey>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn report_folders(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<ReportFoldersQuery>,
) -> Response {
    let spec = match normalized_query(QuerySpec {
        directory_entry_id: q.parent_entry_id,
        metric: q.metric.unwrap_or_default(),
        sort: q.sort.unwrap_or_default(),
        ..QuerySpec::default()
    }) {
        Ok(spec) => spec,
        Err(error) => return err_response(&req_id.0, error),
    };
    let query_hash = match spec.query_hash() {
        Ok(hash) => hash,
        Err(error) => {
            return err_response(&req_id.0, AppError::new(error.code(), error.to_string()));
        }
    };
    if let Err(error) = validate_aggregate_sort(spec.sort) {
        return err_response(&req_id.0, error);
    }
    let sort_key = match query_sort_key("folders", &spec) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let cursor = match q.cursor.as_deref() {
        Some(raw) => match decode_report_query_cursor(&auth, raw, &id, &query_hash, &sort_key) {
            Ok(values) => Some(values),
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let limit = match report_page_size(q.page_size) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let parent_id = match spec.directory_entry_id.as_deref() {
        Some(value) => match decimal_i64("parent_entry_id", value) {
            Ok(value) => Some(value),
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let reports_root = st.config.storage.data_dir.join("reports");
    let result = st
        .readers
        .call(move |conn| {
            let (db, detail_available) = open_report_database(
                conn,
                &reports_root,
                &id,
                "report.sqlite",
                "打开报告摘要失败",
            )?;
            let metric_col = if matches!(spec.sort, SortKey::CountDesc) {
                "file_count"
            } else {
                metric_column(spec.metric)
            };
            let name_sort = matches!(spec.sort, SortKey::NameAsc);
            let direction = sort_direction(spec.sort);
            let mut sql = format!(
                "SELECT entry_id, source_id, parent_entry_id, name, display_path,
                        file_count, subdirectory_count, logical_bytes,
                        allocated_estimate_bytes, quality, {metric_col}
                 FROM report_folders WHERE ",
            );
            let mut values = Vec::<rusqlite::types::Value>::new();
            if let Some(parent_id) = parent_id {
                sql.push_str("parent_entry_id = ?");
                values.push(parent_id.into());
            } else {
                sql.push_str("parent_entry_id IS NULL");
            }
            if let Some(last) = cursor.as_ref() {
                if name_sort {
                    if last.len() != 2 {
                        return Err(AppError::new(
                            ErrorCode::Conflict,
                            "报告分页游标无效或已失效",
                        ));
                    }
                    let entry_id = decimal_i64("cursor.entry_id", &last[1])?;
                    sql.push_str(" AND (display_path > ? OR (display_path = ? AND entry_id > ?))");
                    values.push(last[0].clone().into());
                    values.push(last[0].clone().into());
                    values.push(entry_id.into());
                } else {
                    let (metric_value, entry_id) =
                        parse_nullable_metric_cursor(last, "cursor.entry_id")?;
                    match metric_value {
                        Some(metric_value) => {
                            let op = if direction == "DESC" { "<" } else { ">" };
                            sql.push_str(&format!(
                                " AND ({metric_col} IS NULL OR ({metric_col} IS NOT NULL AND
                                    ({metric_col} {op} ? OR ({metric_col} = ? AND entry_id > ?))))"
                            ));
                            values.push(metric_value.into());
                            values.push(metric_value.into());
                            values.push(entry_id.into());
                        }
                        None => {
                            sql.push_str(&format!(
                                " AND {metric_col} IS NULL AND entry_id > ?"
                            ));
                            values.push(entry_id.into());
                        }
                    }
                }
            }
            let order_by = if name_sort {
                "display_path ASC, entry_id ASC".to_string()
            } else {
                format!("{metric_col} IS NULL ASC, {metric_col} {direction}, entry_id ASC")
            };
            sql.push_str(&format!(" ORDER BY {order_by} LIMIT ?"));
            values.push((limit as i64 + 1).into());
            let mut stmt = db
                .prepare(&sql)
                .map_err(|e| internal(format!("准备目录视图失败: {e}")))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(values), |row| {
                    let entry_id: i64 = row.get(0)?;
                    let display_path: String = row.get(4)?;
                    let metric_value: Option<i64> = row.get(10)?;
                    Ok((
                        json!({
                            "entry_id": entry_id.to_string(),
                            "source_id": row.get::<_, String>(1)?,
                            "parent_entry_id": row.get::<_, Option<i64>>(2)?.map(|v| v.to_string()),
                            "name": row.get::<_, String>(3)?,
                            "display_path": display_path,
                            "file_count": row.get::<_, i64>(5)?.to_string(),
                            "subdirectory_count": row.get::<_, i64>(6)?.to_string(),
                            "logical_bytes": row.get::<_, Option<i64>>(7)?.map(|v| v.to_string()),
                            "allocated_estimate_bytes": row.get::<_, Option<i64>>(8)?.map(|v| v.to_string()),
                            "quality": row.get::<_, String>(9)?,
                        }),
                        if name_sort {
                            vec![display_path, entry_id.to_string()]
                        } else {
                            nullable_metric_cursor(metric_value, entry_id)
                        },
                    ))
                })
                .map_err(|e| internal(format!("读取目录视图失败: {e}")))?;
            let mut rows = rows;
            let mut page = Vec::new();
            for row in rows.by_ref().take(limit + 1) {
                page.push(row.map_err(|e| internal(format!("读取目录行失败: {e}")))?);
            }
            let truncated = page.len() > limit;
            let next_cursor = if truncated {
                let last = page.pop().ok_or_else(|| internal("目录分页结果为空"))?;
                Some(encode_report_query_cursor(
                    &auth,
                    &id,
                    &query_hash,
                    &sort_key,
                    last.1,
                )?)
            } else {
                None
            };
            let items = page.into_iter().map(|(value, _)| value).collect::<Vec<_>>();
            Ok((items, next_cursor, detail_available, truncated))
        })
        .await;
    match result {
        Ok((items, next_cursor, detail_available, truncated)) => ok_response(
            &req_id.0,
            StatusCode::OK,
            json!(items),
            report_list_meta(next_cursor, limit, truncated, detail_available),
        ),
        Err(error) => err_response(&req_id.0, error),
    }
}

#[derive(Debug, Deserialize)]
pub struct ReportOwnersQuery {
    source_id: Option<String>,
    uid: Option<i64>,
    category_id: Option<String>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

#[derive(Debug, Clone)]
struct SourceBreakdown {
    file_count: i64,
    logical_bytes: Option<i64>,
    allocated_bytes: Option<i64>,
}

#[derive(Debug)]
struct OwnerAggregateRow {
    uid: Option<i64>,
    file_count: i64,
    logical_bytes: Option<i64>,
    category_breakdown: BTreeMap<String, i64>,
    source_breakdown: BTreeMap<String, SourceBreakdown>,
}

fn owner_cursor_values(uid: Option<i64>) -> Vec<String> {
    match uid {
        None => vec!["0".into(), String::new()],
        Some(uid) => vec!["1".into(), uid.to_string()],
    }
}

fn decode_owner_cursor(values: &[String]) -> AppResult<Option<i64>> {
    if values.len() != 2 {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "报告分页游标无效或已失效",
        ));
    }
    match (values[0].as_str(), values[1].as_str()) {
        ("0", "") => Ok(None),
        ("1", value) => Ok(Some(decimal_i64("cursor.uid", value)?)),
        _ => Err(AppError::new(
            ErrorCode::Conflict,
            "报告分页游标无效或已失效",
        )),
    }
}

fn owner_json(row: &OwnerAggregateRow) -> Value {
    let category_breakdown = row
        .category_breakdown
        .iter()
        .map(|(category, count)| (category.clone(), Value::String(count.to_string())))
        .collect::<serde_json::Map<_, _>>();
    let source_breakdown = row
        .source_breakdown
        .iter()
        .map(|(source_id, source)| {
            json!({
                "source_id": source_id,
                "file_count": source.file_count.to_string(),
                "logical_bytes": source.logical_bytes.map(|value| value.to_string()),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "uid": row.uid,
        "file_count": row.file_count.to_string(),
        "logical_bytes": row.logical_bytes.map(|value| value.to_string()),
        "category_breakdown": category_breakdown,
        "source_breakdown": source_breakdown,
    })
}

pub async fn report_owners(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<ReportOwnersQuery>,
) -> Response {
    let source_ids = match q.source_id {
        Some(source_id) => vec![source_id],
        None => Vec::new(),
    };
    let spec = match normalized_query(QuerySpec {
        source_ids,
        category_ids: q.category_id.into_iter().collect(),
        owner_uids: q.uid.into_iter().collect(),
        ..QuerySpec::default()
    }) {
        Ok(spec) => spec,
        Err(error) => return err_response(&req_id.0, error),
    };
    let query_hash = match spec.query_hash() {
        Ok(hash) => hash,
        Err(error) => {
            return err_response(&req_id.0, AppError::new(error.code(), error.to_string()));
        }
    };
    let sort_key = "owners:uid_asc";
    let cursor = match q.cursor.as_deref() {
        Some(raw) => match decode_report_query_cursor(&auth, raw, &id, &query_hash, sort_key) {
            Ok(values) => match decode_owner_cursor(&values) {
                Ok(value) => Some(value),
                Err(error) => return err_response(&req_id.0, error),
            },
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let limit = match report_page_size(q.page_size) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let source_filter = spec.source_ids.first().cloned();
    let uid_filter = spec.owner_uids.first().copied();
    let category_filter = spec.category_ids.first().cloned();
    let reports_root = st.config.storage.data_dir.join("reports");
    let result = st
        .readers
        .call(move |conn| {
            let (db, detail_available) = open_report_database(
                conn,
                &reports_root,
                &id,
                "report.sqlite",
                "打开报告摘要失败",
            )?;
            let table = if category_filter.is_some() {
                "owner_category_aggregates"
            } else {
                "owner_aggregates"
            };
            let mut sql = format!(
                "SELECT uid, SUM(file_count),
                        CASE WHEN COUNT(logical_bytes) = COUNT(*) THEN SUM(logical_bytes) END
                 FROM {table} WHERE 1=1"
            );
            let mut values = Vec::<rusqlite::types::Value>::new();
            if let Some(source_id) = source_filter.as_ref() {
                sql.push_str(" AND source_id = ?");
                values.push(source_id.clone().into());
            }
            if let Some(uid) = uid_filter {
                sql.push_str(" AND uid = ?");
                values.push(uid.into());
            }
            if let Some(category_id) = category_filter.as_ref() {
                sql.push_str(" AND category_id = ?");
                values.push(category_id.clone().into());
            }
            if let Some(last) = cursor.as_ref() {
                match last {
                    None => sql.push_str(" AND uid IS NOT NULL"),
                    Some(uid) => {
                        sql.push_str(" AND uid IS NOT NULL AND uid > ?");
                        values.push((*uid).into());
                    }
                }
            }
            sql.push_str(" GROUP BY uid ORDER BY uid IS NOT NULL ASC, uid ASC LIMIT ?");
            values.push((limit as i64 + 1).into());
            let mut stmt = db
                .prepare(&sql)
                .map_err(|e| internal(format!("准备所有者视图失败: {e}")))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(values), |row| {
                    let uid: Option<i64> = row.get(0)?;
                    let file_count: i64 = row.get(1)?;
                    let logical_bytes: Option<i64> = row.get(2)?;
                    Ok((uid, file_count, logical_bytes))
                })
                .map_err(|e| internal(format!("读取所有者视图失败: {e}")))?;
            let mut page: Vec<OwnerAggregateRow> = Vec::new();
            for row in rows {
                let (uid, file_count, logical_bytes) =
                    row.map_err(|e| internal(format!("读取所有者行失败: {e}")))?;
                page.push(OwnerAggregateRow {
                    uid,
                    file_count,
                    logical_bytes,
                    category_breakdown: BTreeMap::new(),
                    source_breakdown: BTreeMap::new(),
                });
            }
            let truncated = page.len() > limit;
            let next_cursor = if truncated {
                let last = page.pop().ok_or_else(|| internal("所有者分页结果为空"))?;
                Some(encode_report_query_cursor(
                    &auth,
                    &id,
                    &query_hash,
                    sort_key,
                    owner_cursor_values(last.uid),
                )?)
            } else {
                None
            };
            for row in &mut page {
                let mut source_sql = format!(
                    "SELECT source_id, SUM(file_count),
                            CASE WHEN COUNT(logical_bytes) = COUNT(*) THEN SUM(logical_bytes) END
                     FROM {table} WHERE uid IS ?"
                );
                let mut source_values = vec![match row.uid {
                    Some(uid) => rusqlite::types::Value::Integer(uid),
                    None => rusqlite::types::Value::Null,
                }];
                if let Some(source_id) = source_filter.as_ref() {
                    source_sql.push_str(" AND source_id = ?");
                    source_values.push(source_id.clone().into());
                }
                if let Some(category_id) = category_filter.as_ref() {
                    source_sql.push_str(" AND category_id = ?");
                    source_values.push(category_id.clone().into());
                }
                source_sql.push_str(" GROUP BY source_id ORDER BY source_id");
                let mut source_stmt = db
                    .prepare(&source_sql)
                    .map_err(|e| internal(format!("准备所有者数据源分布查询失败: {e}")))?;
                let source_rows = source_stmt
                    .query_map(rusqlite::params_from_iter(source_values), |source_row| {
                        Ok((
                            source_row.get::<_, String>(0)?,
                            source_row.get::<_, i64>(1)?,
                            source_row.get::<_, Option<i64>>(2)?,
                        ))
                    })
                    .map_err(|e| internal(format!("读取所有者数据源分布失败: {e}")))?;
                for source_row in source_rows {
                    let (source_id, file_count, logical_bytes) = source_row
                        .map_err(|e| internal(format!("读取所有者数据源分布行失败: {e}")))?;
                    row.source_breakdown.insert(
                        source_id,
                        SourceBreakdown {
                            file_count,
                            logical_bytes,
                            allocated_bytes: None,
                        },
                    );
                }

                let mut category_sql =
                    "SELECT category_id, SUM(file_count) FROM owner_category_aggregates
                     WHERE uid IS ?"
                        .to_string();
                let mut category_values = vec![match row.uid {
                    Some(uid) => rusqlite::types::Value::Integer(uid),
                    None => rusqlite::types::Value::Null,
                }];
                if let Some(source_id) = source_filter.as_ref() {
                    category_sql.push_str(" AND source_id = ?");
                    category_values.push(source_id.clone().into());
                }
                if let Some(category_id) = category_filter.as_ref() {
                    category_sql.push_str(" AND category_id = ?");
                    category_values.push(category_id.clone().into());
                }
                category_sql.push_str(" GROUP BY category_id ORDER BY category_id");
                let mut category_stmt = db
                    .prepare(&category_sql)
                    .map_err(|e| internal(format!("准备所有者分类分布查询失败: {e}")))?;
                let category_rows = category_stmt
                    .query_map(
                        rusqlite::params_from_iter(category_values),
                        |category_row| {
                            Ok((
                                category_row.get::<_, String>(0)?,
                                category_row.get::<_, i64>(1)?,
                            ))
                        },
                    )
                    .map_err(|e| internal(format!("读取所有者分类分布失败: {e}")))?;
                for category_row in category_rows {
                    let (category_id, file_count) = category_row
                        .map_err(|e| internal(format!("读取所有者分类分布行失败: {e}")))?;
                    row.category_breakdown.insert(category_id, file_count);
                }
            }
            let items = page.iter().map(owner_json).collect::<Vec<_>>();
            Ok((items, next_cursor, detail_available, truncated))
        })
        .await;
    match result {
        Ok((items, next_cursor, detail_available, truncated)) => ok_response(
            &req_id.0,
            StatusCode::OK,
            json!(items),
            report_list_meta(next_cursor, limit, truncated, detail_available),
        ),
        Err(error) => err_response(&req_id.0, error),
    }
}

#[derive(Debug, Deserialize)]
pub struct ReportCategoriesQuery {
    #[serde(default)]
    source_ids: Vec<String>,
    directory_entry_id: Option<String>,
    include_descendants: Option<bool>,
    #[serde(default)]
    category_ids: Vec<String>,
    metric: Option<Metric>,
    sort: Option<SortKey>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

#[derive(Debug)]
struct CategoryAggregateRow {
    category_id: String,
    file_count: i64,
    logical_bytes: Option<i64>,
    allocated_bytes: Option<i64>,
    source_breakdown: BTreeMap<String, SourceBreakdown>,
}

fn category_metric(row: &CategoryAggregateRow, spec: &QuerySpec) -> Option<i64> {
    if matches!(spec.sort, SortKey::CountDesc) {
        Some(row.file_count)
    } else {
        match spec.metric {
            Metric::FileCount => Some(row.file_count),
            Metric::LogicalBytes => row.logical_bytes,
            Metric::AllocatedEstimateBytes => row.allocated_bytes,
        }
    }
}

fn compare_category_rows(
    left: &CategoryAggregateRow,
    right: &CategoryAggregateRow,
    spec: &QuerySpec,
) -> std::cmp::Ordering {
    if matches!(spec.sort, SortKey::NameAsc) {
        return left.category_id.cmp(&right.category_id);
    }
    let left_metric = category_metric(left, spec);
    let right_metric = category_metric(right, spec);
    let metric_order = match (left_metric, right_metric) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(left), Some(right)) => match sort_direction(spec.sort) {
            "DESC" => right.cmp(&left),
            _ => left.cmp(&right),
        },
    };
    metric_order.then_with(|| left.category_id.cmp(&right.category_id))
}

fn category_cursor_values(row: &CategoryAggregateRow, spec: &QuerySpec) -> Vec<String> {
    if matches!(spec.sort, SortKey::NameAsc) {
        vec![row.category_id.clone()]
    } else {
        nullable_metric_cursor(category_metric(row, spec), row.category_id.clone())
    }
}

fn decode_category_cursor(values: &[String], sort: SortKey) -> AppResult<(Option<i64>, String)> {
    if matches!(sort, SortKey::NameAsc) {
        if values.len() == 1 && !values[0].is_empty() {
            return Ok((None, values[0].clone()));
        }
        return Err(AppError::new(
            ErrorCode::Conflict,
            "报告分页游标无效或已失效",
        ));
    }
    if values.len() != 3 || values[2].is_empty() {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "报告分页游标无效或已失效",
        ));
    }
    let null_rank = decimal_i64("cursor.null_metric", &values[0])?;
    let metric = match null_rank {
        0 => Some(decimal_i64("cursor.metric", &values[1])?),
        1 if values[1].is_empty() => None,
        _ => {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "报告分页游标无效或已失效",
            ));
        }
    };
    Ok((metric, values[2].clone()))
}

fn category_after_cursor(
    row: &CategoryAggregateRow,
    cursor: &(Option<i64>, String),
    spec: &QuerySpec,
) -> bool {
    if matches!(spec.sort, SortKey::NameAsc) {
        return row.category_id > cursor.1;
    }
    let current_metric = category_metric(row, spec);
    let metric_order = match (current_metric, cursor.0) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(current), Some(last)) => match sort_direction(spec.sort) {
            "DESC" => last.cmp(&current),
            _ => current.cmp(&last),
        },
    };
    metric_order == std::cmp::Ordering::Greater
        || (metric_order == std::cmp::Ordering::Equal && row.category_id > cursor.1)
}

fn category_json(row: &CategoryAggregateRow) -> Value {
    let source_breakdown = row
        .source_breakdown
        .iter()
        .map(|(source_id, source)| {
            json!({
                "source_id": source_id,
                "file_count": source.file_count.to_string(),
                "logical_bytes": source.logical_bytes.map(|value| value.to_string()),
                "allocated_estimate_bytes": source.allocated_bytes.map(|value| value.to_string()),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "category_id": row.category_id,
        "file_count": row.file_count.to_string(),
        "logical_bytes": row.logical_bytes.map(|value| value.to_string()),
        "allocated_estimate_bytes": row.allocated_bytes.map(|value| value.to_string()),
        "source_breakdown": source_breakdown,
    })
}

pub async fn report_categories(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<ReportCategoriesQuery>,
) -> Response {
    let spec = match normalized_query(QuerySpec {
        source_ids: q.source_ids,
        directory_entry_id: q.directory_entry_id,
        include_descendants: q.include_descendants.unwrap_or(true),
        category_ids: q.category_ids,
        metric: q.metric.unwrap_or_default(),
        sort: q.sort.unwrap_or_default(),
        ..QuerySpec::default()
    }) {
        Ok(spec) => spec,
        Err(error) => return err_response(&req_id.0, error),
    };
    let query_hash = match spec.query_hash() {
        Ok(hash) => hash,
        Err(error) => {
            return err_response(&req_id.0, AppError::new(error.code(), error.to_string()));
        }
    };
    if let Err(error) = validate_aggregate_sort(spec.sort) {
        return err_response(&req_id.0, error);
    }
    let sort_key = match query_sort_key("categories", &spec) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let cursor = match q.cursor.as_deref() {
        Some(raw) => match decode_report_query_cursor(&auth, raw, &id, &query_hash, &sort_key) {
            Ok(values) => match decode_category_cursor(&values, spec.sort) {
                Ok(value) => Some(value),
                Err(error) => return err_response(&req_id.0, error),
            },
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let limit = match report_page_size(q.page_size) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let directory_id = match spec.directory_entry_id.as_deref() {
        Some(value) => match decimal_i64("directory_entry_id", value) {
            Ok(value) => Some(value),
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let source_filters = spec.source_ids.clone();
    let category_filters = spec.category_ids.clone();
    let metric = spec.metric;
    let sort = spec.sort;
    let include_descendants = spec.include_descendants;
    let category_spec = QuerySpec {
        metric,
        sort,
        ..QuerySpec::default()
    };
    let reports_root = st.config.storage.data_dir.join("reports");
    let result = st
        .readers
        .call(move |conn| {
            let (db, source_table, detail_available) = if directory_id.is_some() {
                let (db, detail_available) = open_report_database(
                    conn,
                    &reports_root,
                    &id,
                    "index.sqlite",
                    "打开报告明细失败",
                )?;
                (db, true, detail_available)
            } else {
                let (db, detail_available) = open_report_database(
                    conn,
                    &reports_root,
                    &id,
                    "report.sqlite",
                    "打开报告摘要失败",
                )?;
                (db, false, detail_available)
            };
            let mut sql = if source_table {
                "SELECT e.category_id, COUNT(*) AS file_count,
                        CASE WHEN COUNT(e.size_bytes) = COUNT(*) THEN SUM(e.size_bytes) END
                            AS logical_bytes,
                        CASE WHEN COUNT(e.allocated_bytes_estimate) = COUNT(*)
                             THEN SUM(e.allocated_bytes_estimate) END
                            AS allocated_estimate_bytes
                 FROM entries e
                 WHERE e.entry_kind = 'regular_file' AND e.category_id IS NOT NULL"
                    .to_string()
            } else {
                "SELECT category_id, SUM(file_count),
                        CASE WHEN COUNT(logical_bytes) = COUNT(*) THEN SUM(logical_bytes) END,
                        CASE WHEN COUNT(allocated_bytes) = COUNT(*) THEN SUM(allocated_bytes) END
                 FROM category_aggregates WHERE 1=1"
                    .to_string()
            };
            let mut values = Vec::<rusqlite::types::Value>::new();
            if !source_filters.is_empty() {
                let marks = std::iter::repeat_n("?", source_filters.len())
                    .collect::<Vec<_>>()
                    .join(",");
                if source_table {
                    sql.push_str(&format!(" AND e.source_id IN ({marks})"));
                } else {
                    sql.push_str(&format!(" AND source_id IN ({marks})"));
                }
                values.extend(source_filters.iter().cloned().map(Into::into));
            }
            if !category_filters.is_empty() {
                let marks = std::iter::repeat_n("?", category_filters.len())
                    .collect::<Vec<_>>()
                    .join(",");
                if source_table {
                    sql.push_str(&format!(" AND e.category_id IN ({marks})"));
                } else {
                    sql.push_str(&format!(" AND category_id IN ({marks})"));
                }
                values.extend(category_filters.iter().cloned().map(Into::into));
            }
            if let Some(directory_id) = directory_id {
                if !source_table {
                    return Err(internal("分类目录范围未打开明细数据库"));
                }
                if db
                    .query_row(
                        "SELECT 1 FROM entries WHERE entry_id = ?1 AND entry_kind = 'directory'",
                        [directory_id],
                        |_| Ok(()),
                    )
                    .optional()
                    .map_err(|e| internal(format!("校验分类目录范围失败: {e}")))?
                    .is_none()
                {
                    return Err(AppError::new(
                        ErrorCode::BadRequest,
                        "directory_entry_id 不是报告内目录",
                    ));
                }
                if include_descendants {
                    sql.push_str(
                        " AND e.dfs_left >= (SELECT dfs_left FROM entries WHERE entry_id = ?)
                          AND e.dfs_right <= (SELECT dfs_right FROM entries WHERE entry_id = ?)",
                    );
                    values.push(directory_id.into());
                    values.push(directory_id.into());
                } else {
                    sql.push_str(" AND e.parent_entry_id = ?");
                    values.push(directory_id.into());
                }
            }
            sql.push_str(" GROUP BY category_id");
            let mut stmt = db
                .prepare(&sql)
                .map_err(|e| internal(format!("准备分类视图失败: {e}")))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(values), |row| {
                    Ok(CategoryAggregateRow {
                        category_id: row.get(0)?,
                        file_count: row.get(1)?,
                        logical_bytes: row.get(2)?,
                        allocated_bytes: row.get(3)?,
                        source_breakdown: BTreeMap::new(),
                    })
                })
                .map_err(|e| internal(format!("读取分类视图失败: {e}")))?;
            let mut categories = Vec::new();
            for row in rows {
                categories.push(row.map_err(|e| internal(format!("读取分类行失败: {e}")))?);
            }
            categories.sort_by(|left, right| compare_category_rows(left, right, &category_spec));
            let start = match cursor.as_ref() {
                Some(cursor) => categories
                    .iter()
                    .position(|row| category_after_cursor(row, cursor, &category_spec))
                    .unwrap_or(categories.len()),
                None => 0,
            };
            let mut page = categories.into_iter().skip(start).take(limit + 1).collect::<Vec<_>>();
            let truncated = page.len() > limit;
            let next_cursor = if truncated {
                let last = page.pop().ok_or_else(|| internal("分类分页结果为空"))?;
                Some(encode_report_query_cursor(
                    &auth,
                    &id,
                    &query_hash,
                    &sort_key,
                    category_cursor_values(&last, &category_spec),
                )?)
            } else {
                None
            };
            for row in &mut page {
                let mut source_sql = if source_table {
                    "SELECT e.source_id, COUNT(*),
                            CASE WHEN COUNT(e.size_bytes) = COUNT(*) THEN SUM(e.size_bytes) END,
                            CASE WHEN COUNT(e.allocated_bytes_estimate) = COUNT(*)
                                 THEN SUM(e.allocated_bytes_estimate) END
                     FROM entries e
                     WHERE e.entry_kind = 'regular_file' AND e.category_id = ?"
                        .to_string()
                } else {
                    "SELECT source_id, SUM(file_count),
                            CASE WHEN COUNT(logical_bytes) = COUNT(*) THEN SUM(logical_bytes) END,
                            CASE WHEN COUNT(allocated_bytes) = COUNT(*) THEN SUM(allocated_bytes) END
                     FROM category_aggregates
                     WHERE category_id = ?"
                        .to_string()
                };
                let mut source_values: Vec<rusqlite::types::Value> =
                    vec![row.category_id.clone().into()];
                if !source_filters.is_empty() {
                    let marks = std::iter::repeat_n("?", source_filters.len())
                        .collect::<Vec<_>>()
                        .join(",");
                    if source_table {
                        source_sql.push_str(&format!(" AND e.source_id IN ({marks})"));
                    } else {
                        source_sql.push_str(&format!(" AND source_id IN ({marks})"));
                    }
                    source_values.extend(source_filters.iter().cloned().map(Into::into));
                }
                if let Some(directory_id) = directory_id && source_table {
                        if include_descendants {
                            source_sql.push_str(
                                " AND e.dfs_left >= (SELECT dfs_left FROM entries WHERE entry_id = ?)
                                  AND e.dfs_right <= (SELECT dfs_right FROM entries WHERE entry_id = ?)",
                            );
                            source_values.push(directory_id.into());
                            source_values.push(directory_id.into());
                        } else {
                            source_sql.push_str(" AND e.parent_entry_id = ?");
                            source_values.push(directory_id.into());
                        }
                }
                source_sql.push_str(if source_table {
                    " GROUP BY e.source_id ORDER BY e.source_id"
                } else {
                    " GROUP BY source_id ORDER BY source_id"
                });
                let mut source_stmt = db
                    .prepare(&source_sql)
                    .map_err(|e| internal(format!("准备分类数据源分布查询失败: {e}")))?;
                let source_rows = source_stmt
                    .query_map(rusqlite::params_from_iter(source_values), |source_row| {
                        Ok((
                            source_row.get::<_, String>(0)?,
                            source_row.get::<_, i64>(1)?,
                            source_row.get::<_, Option<i64>>(2)?,
                            source_row.get::<_, Option<i64>>(3)?,
                        ))
                    })
                    .map_err(|e| internal(format!("读取分类数据源分布失败: {e}")))?;
                for source_row in source_rows {
                    let (source_id, file_count, logical_bytes, allocated_bytes) = source_row
                        .map_err(|e| internal(format!("读取分类数据源分布行失败: {e}")))?;
                    row.source_breakdown.insert(
                        source_id,
                        SourceBreakdown {
                            file_count,
                            logical_bytes,
                            allocated_bytes,
                        },
                    );
                }
            }
            let items = page.iter().map(category_json).collect::<Vec<_>>();
            Ok((items, next_cursor, detail_available, truncated))
        })
        .await;
    match result {
        Ok((items, next_cursor, detail_available, truncated)) => ok_response(
            &req_id.0,
            StatusCode::OK,
            json!(items),
            report_list_meta(next_cursor, limit, truncated, detail_available),
        ),
        Err(error) => err_response(&req_id.0, error),
    }
}

#[derive(Debug, Deserialize)]
pub struct ReportFilesQuery {
    #[serde(default)]
    source_ids: Vec<String>,
    directory_entry_id: Option<String>,
    include_descendants: Option<bool>,
    #[serde(default)]
    category_ids: Vec<String>,
    #[serde(default)]
    extensions: Vec<String>,
    #[serde(default)]
    owner_uids: Vec<i64>,
    name_contains: Option<String>,
    min_size_bytes: Option<String>,
    max_size_bytes: Option<String>,
    mtime_from: Option<String>,
    mtime_to: Option<String>,
    atime_from: Option<String>,
    atime_to: Option<String>,
    metric: Option<Metric>,
    sort: Option<SortKey>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

fn json_file_time(sec: Option<i64>, nsec: Option<i64>) -> Value {
    match (sec, nsec) {
        (Some(sec), Some(nsec)) if (0..=999_999_999).contains(&nsec) => {
            let rfc3339 = jiff::Timestamp::new(sec, nsec as i32)
                .map(|timestamp| timestamp.to_string())
                .ok();
            json!({
                "rfc3339": rfc3339,
                "sec": sec.to_string(),
                "nsec": nsec,
                "unavailable_reason": Value::Null,
            })
        }
        _ => json!({
            "rfc3339": Value::Null,
            "sec": Value::Null,
            "nsec": Value::Null,
            "unavailable_reason": "timestamp_unavailable",
        }),
    }
}

pub async fn report_files(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<ReportFilesQuery>,
) -> Response {
    let spec = match normalized_query(QuerySpec {
        source_ids: q.source_ids,
        directory_entry_id: q.directory_entry_id,
        include_descendants: q.include_descendants.unwrap_or(true),
        category_ids: q.category_ids,
        extensions: q.extensions,
        owner_uids: q.owner_uids,
        name_contains: q.name_contains,
        min_size_bytes: q.min_size_bytes,
        max_size_bytes: q.max_size_bytes,
        mtime_from: q.mtime_from,
        mtime_to: q.mtime_to,
        atime_from: q.atime_from,
        atime_to: q.atime_to,
        metric: q.metric.unwrap_or_default(),
        sort: q.sort.unwrap_or_default(),
    }) {
        Ok(spec) => spec,
        Err(error) => return err_response(&req_id.0, error),
    };
    let query_hash = match spec.query_hash() {
        Ok(hash) => hash,
        Err(error) => {
            return err_response(&req_id.0, AppError::new(error.code(), error.to_string()));
        }
    };
    let sort_key = match query_sort_key("files", &spec) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let cursor = match q.cursor.as_deref() {
        Some(raw) => match decode_report_query_cursor(&auth, raw, &id, &query_hash, &sort_key) {
            Ok(values) => Some(values),
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let directory_id = match spec.directory_entry_id.as_deref() {
        Some(value) => match decimal_i64("directory_entry_id", value) {
            Ok(value) => Some(value),
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let min_size = match spec.min_size_bytes.as_deref() {
        Some(value) => match decimal_i64("min_size_bytes", value) {
            Ok(value) => Some(value),
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let max_size = match spec.max_size_bytes.as_deref() {
        Some(value) => match decimal_i64("max_size_bytes", value) {
            Ok(value) => Some(value),
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let mtime_from = match timestamp_parts("mtime_from", spec.mtime_from.as_deref()) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let mtime_to = match timestamp_parts("mtime_to", spec.mtime_to.as_deref()) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let atime_from = match timestamp_parts("atime_from", spec.atime_from.as_deref()) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let atime_to = match timestamp_parts("atime_to", spec.atime_to.as_deref()) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    if matches!(spec.sort, SortKey::CountDesc) {
        return err_response(
            &req_id.0,
            AppError::new(ErrorCode::BadRequest, "文件明细不支持 count_desc 排序"),
        );
    }
    let limit = match report_page_size(q.page_size) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let reports_root = st.config.storage.data_dir.join("reports");
    let result = st
        .readers
        .call(move |conn| {
            let (index, _) =
                open_report_database(conn, &reports_root, &id, "index.sqlite", "打开报告明细失败")?;
            if let Some(directory_id) = directory_id
                && index
                    .query_row(
                        "SELECT 1 FROM entries WHERE entry_id = ?1 AND entry_kind = 'directory'",
                        [directory_id],
                        |_| Ok(()),
                    )
                    .optional()
                    .map_err(|e| internal(format!("校验文件目录范围失败: {e}")))?
                    .is_none()
            {
                return Err(AppError::new(
                    ErrorCode::BadRequest,
                    "directory_entry_id 不是报告内目录",
                ));
            }
            let mut sql = String::from(
                "SELECT e.entry_id, e.source_id, e.parent_entry_id, e.raw_relative_path,
                        e.display_name, e.nlink, e.uid, e.gid, e.mode,
                        e.device_id, e.inode_id, e.category_id, e.extension,
                        e.size_bytes, e.allocated_bytes_estimate,
                        e.mtime_sec, e.mtime_nsec, e.atime_sec, e.atime_nsec,
                        e.ctime_sec, e.ctime_nsec, e.birthtime_sec, e.birthtime_nsec,
                        e.scan_error, e.observation_time
                 FROM entries e WHERE e.entry_kind = 'regular_file'",
            );
            let mut values = Vec::<rusqlite::types::Value>::new();
            if !spec.source_ids.is_empty() {
                let marks = std::iter::repeat_n("?", spec.source_ids.len())
                    .collect::<Vec<_>>()
                    .join(",");
                sql.push_str(&format!(" AND e.source_id IN ({marks})"));
                values.extend(spec.source_ids.iter().cloned().map(Into::into));
            }
            if !spec.category_ids.is_empty() {
                let marks = std::iter::repeat_n("?", spec.category_ids.len())
                    .collect::<Vec<_>>()
                    .join(",");
                sql.push_str(&format!(" AND e.category_id IN ({marks})"));
                values.extend(spec.category_ids.iter().cloned().map(Into::into));
            }
            if !spec.extensions.is_empty() {
                let marks = std::iter::repeat_n("?", spec.extensions.len())
                    .collect::<Vec<_>>()
                    .join(",");
                sql.push_str(&format!(" AND e.extension IN ({marks})"));
                values.extend(spec.extensions.iter().cloned().map(Into::into));
            }
            if !spec.owner_uids.is_empty() {
                let marks = std::iter::repeat_n("?", spec.owner_uids.len())
                    .collect::<Vec<_>>()
                    .join(",");
                sql.push_str(&format!(" AND e.uid IN ({marks})"));
                values.extend(spec.owner_uids.iter().map(|uid| (*uid).into()));
            }
            if let Some(name) = spec.name_contains.as_deref() {
                sql.push_str(" AND instr(e.display_name, ?) > 0");
                values.push(name.to_string().into());
            }
            if let Some(min_size) = min_size {
                sql.push_str(" AND e.size_bytes >= ?");
                values.push(min_size.into());
            }
            if let Some(max_size) = max_size {
                sql.push_str(" AND e.size_bytes <= ?");
                values.push(max_size.into());
            }
            if let Some((sec, nsec)) = mtime_from {
                sql.push_str(" AND (e.mtime_sec > ? OR (e.mtime_sec = ? AND e.mtime_nsec >= ?))");
                values.push(sec.into());
                values.push(sec.into());
                values.push(nsec.into());
            }
            if let Some((sec, nsec)) = mtime_to {
                sql.push_str(" AND (e.mtime_sec < ? OR (e.mtime_sec = ? AND e.mtime_nsec < ?))");
                values.push(sec.into());
                values.push(sec.into());
                values.push(nsec.into());
            }
            if let Some((sec, nsec)) = atime_from {
                sql.push_str(" AND (e.atime_sec > ? OR (e.atime_sec = ? AND e.atime_nsec >= ?))");
                values.push(sec.into());
                values.push(sec.into());
                values.push(nsec.into());
            }
            if let Some((sec, nsec)) = atime_to {
                sql.push_str(" AND (e.atime_sec < ? OR (e.atime_sec = ? AND e.atime_nsec < ?))");
                values.push(sec.into());
                values.push(sec.into());
                values.push(nsec.into());
            }
            if let Some(directory_id) = directory_id {
                if spec.include_descendants {
                    sql.push_str(
                        " AND e.dfs_left >= (SELECT dfs_left FROM entries WHERE entry_id = ?)
                          AND e.dfs_right <= (SELECT dfs_right FROM entries WHERE entry_id = ?)",
                    );
                    values.push(directory_id.into());
                    values.push(directory_id.into());
                } else {
                    sql.push_str(" AND e.parent_entry_id = ?");
                    values.push(directory_id.into());
                }
            }
            let direction = sort_direction(spec.sort);
            let (order_by, cursor_sql) = match spec.sort {
                SortKey::SizeDesc | SortKey::SizeAsc => (
                    format!("e.size_bytes {direction}, e.entry_id ASC"),
                    "(e.size_bytes {op} ? OR (e.size_bytes = ? AND e.entry_id > ?))",
                ),
                SortKey::MtimeDesc | SortKey::MtimeAsc => (
                    format!("e.mtime_sec {direction}, e.mtime_nsec {direction}, e.entry_id ASC"),
                    "(e.mtime_sec {op} ? OR (e.mtime_sec = ? AND e.mtime_nsec {op} ?)
                      OR (e.mtime_sec = ? AND e.mtime_nsec = ? AND e.entry_id > ?))",
                ),
                SortKey::AtimeDesc | SortKey::AtimeAsc => (
                    format!("e.atime_sec {direction}, e.atime_nsec {direction}, e.entry_id ASC"),
                    "(e.atime_sec {op} ? OR (e.atime_sec = ? AND e.atime_nsec {op} ?)
                      OR (e.atime_sec = ? AND e.atime_nsec = ? AND e.entry_id > ?))",
                ),
                SortKey::NameAsc => (
                    "e.display_name ASC, e.entry_id ASC".to_string(),
                    "(e.display_name > ? OR (e.display_name = ? AND e.entry_id > ?))",
                ),
                SortKey::CountDesc => unreachable!(),
            };
            if let Some(last) = cursor.as_ref() {
                let op = if direction == "DESC" { "<" } else { ">" };
                match spec.sort {
                    SortKey::SizeDesc | SortKey::SizeAsc => {
                        if last.len() != 2 {
                            return Err(AppError::new(
                                ErrorCode::Conflict,
                                "报告分页游标无效或已失效",
                            ));
                        }
                        sql.push_str(" AND ");
                        sql.push_str(&cursor_sql.replace("{op}", op));
                        values.push(decimal_i64("cursor.sort", &last[0])?.into());
                        values.push(decimal_i64("cursor.sort", &last[0])?.into());
                        values.push(decimal_i64("cursor.entry_id", &last[1])?.into());
                    }
                    SortKey::MtimeDesc
                    | SortKey::MtimeAsc
                    | SortKey::AtimeDesc
                    | SortKey::AtimeAsc => {
                        if last.len() != 3 {
                            return Err(AppError::new(
                                ErrorCode::Conflict,
                                "报告分页游标无效或已失效",
                            ));
                        }
                        sql.push_str(" AND ");
                        sql.push_str(&cursor_sql.replace("{op}", op));
                        let sec = decimal_i64("cursor.sec", &last[0])?;
                        let nsec = decimal_i64("cursor.nsec", &last[1])?;
                        values.push(sec.into());
                        values.push(sec.into());
                        values.push(nsec.into());
                        values.push(sec.into());
                        values.push(nsec.into());
                        values.push(decimal_i64("cursor.entry_id", &last[2])?.into());
                    }
                    SortKey::NameAsc => {
                        if last.len() != 2 {
                            return Err(AppError::new(
                                ErrorCode::Conflict,
                                "报告分页游标无效或已失效",
                            ));
                        }
                        sql.push_str(" AND ");
                        sql.push_str(cursor_sql);
                        values.push(last[0].clone().into());
                        values.push(last[0].clone().into());
                        values.push(decimal_i64("cursor.entry_id", &last[1])?.into());
                    }
                    SortKey::CountDesc => unreachable!(),
                }
            }
            sql.push_str(&format!(" ORDER BY {order_by} LIMIT ?"));
            values.push((limit as i64 + 1).into());
            let mut stmt = index
                .prepare(&sql)
                .map_err(|e| internal(format!("准备文件明细查询失败: {e}")))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(values), |row| {
                    let entry_id: i64 = row.get(0)?;
                    let source_id: String = row.get(1)?;
                    let display_name: String = row.get(4)?;
                    let size: Option<i64> = row.get(13)?;
                    let allocated: Option<i64> = row.get(14)?;
                    let mtime = (
                        row.get::<_, Option<i64>>(15)?,
                        row.get::<_, Option<i64>>(16)?,
                    );
                    let atime = (
                        row.get::<_, Option<i64>>(17)?,
                        row.get::<_, Option<i64>>(18)?,
                    );
                    let cursor_values = match spec.sort {
                        SortKey::SizeDesc | SortKey::SizeAsc => vec![
                            size.ok_or(rusqlite::Error::InvalidColumnType(
                                13,
                                "size".into(),
                                rusqlite::types::Type::Null,
                            ))?
                            .to_string(),
                            entry_id.to_string(),
                        ],
                        SortKey::MtimeDesc | SortKey::MtimeAsc => vec![
                            mtime
                                .0
                                .ok_or(rusqlite::Error::InvalidColumnType(
                                    15,
                                    "mtime_sec".into(),
                                    rusqlite::types::Type::Null,
                                ))?
                                .to_string(),
                            mtime
                                .1
                                .ok_or(rusqlite::Error::InvalidColumnType(
                                    16,
                                    "mtime_nsec".into(),
                                    rusqlite::types::Type::Null,
                                ))?
                                .to_string(),
                            entry_id.to_string(),
                        ],
                        SortKey::AtimeDesc | SortKey::AtimeAsc => vec![
                            atime
                                .0
                                .ok_or(rusqlite::Error::InvalidColumnType(
                                    17,
                                    "atime_sec".into(),
                                    rusqlite::types::Type::Null,
                                ))?
                                .to_string(),
                            atime
                                .1
                                .ok_or(rusqlite::Error::InvalidColumnType(
                                    18,
                                    "atime_nsec".into(),
                                    rusqlite::types::Type::Null,
                                ))?
                                .to_string(),
                            entry_id.to_string(),
                        ],
                        SortKey::NameAsc => vec![display_name.clone(), entry_id.to_string()],
                        SortKey::CountDesc => unreachable!(),
                    };
                    Ok((
                        json!({
                            "entry_id": entry_id.to_string(),
                            "source_id": source_id,
                            "parent_entry_id": row.get::<_, Option<i64>>(2)?.map(|v| v.to_string()),
                            "display_name": display_name,
                            "display_path": String::from_utf8_lossy(&row.get::<_, Vec<u8>>(3)?),
                            "entry_kind": "file",
                            "nlink": row.get::<_, Option<i64>>(5)?,
                            "uid": row.get::<_, Option<i64>>(6)?,
                            "gid": row.get::<_, Option<i64>>(7)?,
                            "mode": row.get::<_, Option<i64>>(8)?,
                            "device_id": row.get::<_, Option<String>>(9)?,
                            "inode_id": row.get::<_, Option<String>>(10)?,
                            "category_id": row.get::<_, Option<String>>(11)?,
                            "extension": row.get::<_, Option<String>>(12)?,
                            "size_bytes": size.map(|v| v.to_string()),
                            "allocated_estimate_bytes": allocated.map(|v| v.to_string()),
                            "mtime": json_file_time(mtime.0, mtime.1),
                            "atime": json_file_time(atime.0, atime.1),
                            "ctime": json_file_time(row.get(19)?, row.get(20)?),
                            "birthtime": json_file_time(row.get(21)?, row.get(22)?),
                            "scan_error": row.get::<_, Option<String>>(23)?,
                            "observation_time": row.get::<_, String>(24)?,
                        }),
                        cursor_values,
                    ))
                })
                .map_err(|e| internal(format!("读取文件明细失败: {e}")))?;
            let mut page = Vec::new();
            for row in rows {
                page.push(row.map_err(|e| internal(format!("读取文件明细行失败: {e}")))?);
            }
            let truncated = page.len() > limit;
            let next_cursor = if truncated {
                let last = page.pop().ok_or_else(|| internal("文件分页结果为空"))?;
                Some(encode_report_query_cursor(
                    &auth,
                    &id,
                    &query_hash,
                    &sort_key,
                    last.1,
                )?)
            } else {
                None
            };
            let items = page.into_iter().map(|(value, _)| value).collect::<Vec<_>>();
            Ok((items, next_cursor, truncated))
        })
        .await;
    match result {
        Ok((items, next_cursor, truncated)) => ok_response(
            &req_id.0,
            StatusCode::OK,
            json!(items),
            report_list_meta(next_cursor, limit, truncated, true),
        ),
        Err(error) => err_response(&req_id.0, error),
    }
}

#[derive(Debug, Deserialize)]
pub struct ReportRankingsQuery {
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn report_rankings(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Path((id, kind)): Path<(String, String)>,
    Query(q): Query<ReportRankingsQuery>,
) -> Response {
    let db_kind = match kind.as_str() {
        "largest" => "largest",
        "recent" => "recently_modified",
        "least_accessed" => "least_accessed",
        _ => {
            return err_response(
                &req_id.0,
                AppError::new(ErrorCode::BadRequest, "未知排行类型"),
            );
        }
    };
    let ranking_sort = match db_kind {
        "largest" => SortKey::SizeDesc,
        "recently_modified" => SortKey::MtimeDesc,
        "least_accessed" => SortKey::AtimeAsc,
        _ => unreachable!(),
    };
    let spec = QuerySpec {
        sort: ranking_sort,
        ..QuerySpec::default()
    };
    let query_hash = match spec.query_hash() {
        Ok(hash) => hash,
        Err(error) => {
            return err_response(&req_id.0, AppError::new(error.code(), error.to_string()));
        }
    };
    let sort_key = match query_sort_key("rankings", &spec) {
        Ok(value) => format!("{value}:{kind}"),
        Err(error) => return err_response(&req_id.0, error),
    };
    let cursor = match q.cursor.as_deref() {
        Some(raw) => match decode_report_query_cursor(&auth, raw, &id, &query_hash, &sort_key) {
            Ok(values) => Some(values),
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let limit = match report_page_size(q.page_size) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let reports_root = st.config.storage.data_dir.join("reports");
    let result = st
        .readers
        .call(move |conn| {
            let (db, detail_available) = open_report_database(
                conn,
                &reports_root,
                &id,
                "report.sqlite",
                "打开报告摘要失败",
            )?;
            let mut sql = String::from(
                "SELECT kind, rank, entry_id, source_id, display_path, display_name, uid, category_id,
                        size_bytes, allocated_bytes_estimate, mtime_sec, mtime_nsec,
                        atime_sec, atime_nsec, status
                 FROM rankings WHERE kind = ?",
            );
            let mut values = vec![rusqlite::types::Value::from(db_kind.to_string())];
            if let Some(last) = cursor.as_ref() {
                if last.len() != 1 {
                    return Err(AppError::new(ErrorCode::Conflict, "报告分页游标无效或已失效"));
                }
                sql.push_str(" AND rank > ?");
                values.push(decimal_i64("cursor.rank", &last[0])?.into());
            }
            sql.push_str(" ORDER BY rank ASC LIMIT ?");
            values.push((limit as i64 + 1).into());
            let mut stmt = db
                .prepare(&sql)
                .map_err(|e| internal(format!("准备排行查询失败: {e}")))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(values), |row| {
                    let rank: i64 = row.get(1)?;
                    let entry_id: i64 = row.get(2)?;
                    Ok((
                        json!({
                            "kind": row.get::<_, String>(0)?,
                            "rank": rank,
                            "entry_id": entry_id.to_string(),
                            "source_id": row.get::<_, String>(3)?,
                            "display_path": row.get::<_, String>(4)?,
                            "display_name": row.get::<_, String>(5)?,
                            "entry_kind": "file",
                            "uid": row.get::<_, Option<i64>>(6)?,
                            "category_id": row.get::<_, Option<String>>(7)?,
                            "size_bytes": row.get::<_, i64>(8)?.to_string(),
                            "allocated_estimate_bytes": row.get::<_, Option<i64>>(9)?.map(|v| v.to_string()),
                            "mtime": json_file_time(row.get(10)?, row.get(11)?),
                            "atime": json_file_time(row.get(12)?, row.get(13)?),
                            "status": row.get::<_, String>(14)?,
                        }),
                        vec![rank.to_string()],
                    ))
                })
                .map_err(|e| internal(format!("读取排行失败: {e}")))?;
            let mut page = Vec::new();
            for row in rows {
                page.push(row.map_err(|e| internal(format!("读取排行行失败: {e}")))?);
            }
            let truncated = page.len() > limit;
            let next_cursor = if truncated {
                let last = page.pop().ok_or_else(|| internal("排行分页结果为空"))?;
                Some(encode_report_query_cursor(
                    &auth,
                    &id,
                    &query_hash,
                    &sort_key,
                    last.1,
                )?)
            } else {
                None
            };
            let items = page.into_iter().map(|(value, _)| value).collect::<Vec<_>>();
            Ok((items, next_cursor, detail_available, truncated))
        })
        .await;
    match result {
        Ok((items, next_cursor, detail_available, truncated)) => ok_response(
            &req_id.0,
            StatusCode::OK,
            json!(items),
            report_list_meta(next_cursor, limit, truncated, detail_available),
        ),
        Err(error) => err_response(&req_id.0, error),
    }
}

#[cfg(test)]
mod report_query_tests {
    use super::*;
    use crate::auth::Session;

    fn test_auth() -> Auth {
        Auth {
            session: Session {
                token_hash: "token-hash".into(),
                user_id: "admin".into(),
                csrf_secret: "cursor-signing-secret".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                expires_idle_at: "2027-01-01T00:00:00Z".into(),
                expires_absolute_at: "2027-01-01T00:00:00Z".into(),
                last_seen_at: "2026-01-01T00:00:00Z".into(),
            },
            token: "session-token".into(),
        }
    }

    #[test]
    fn report_artifact_path_must_match_persisted_layout() {
        let reports_root = StdPath::new("/data/reports");
        assert_eq!(
            report_directory_relative(
                reports_root,
                "report-1",
                StdPath::new("/data/reports/report-1/manifest.json"),
            )
            .unwrap(),
            PathBuf::from("report-1")
        );
        for manifest in [
            "/tmp/report-1/manifest.json",
            "/data/reports/other/manifest.json",
            "/data/reports/report-1/../other/manifest.json",
        ] {
            assert_eq!(
                report_directory_relative(reports_root, "report-1", StdPath::new(manifest))
                    .unwrap_err()
                    .code,
                ErrorCode::PathOutsideRoot
            );
        }
    }

    #[test]
    fn report_query_normalizes_all_filter_fields() {
        let query = normalized_query(QuerySpec {
            source_ids: vec![
                "00000000-0000-0000-0000-000000000002".into(),
                "00000000-0000-0000-0000-000000000001".into(),
            ],
            category_ids: vec!["videos".into(), "audio".into(), "videos".into()],
            extensions: vec!["TXT".into(), ".md".into()],
            owner_uids: vec![1001, 1000, 1001],
            min_size_bytes: Some("00010".into()),
            max_size_bytes: Some("20".into()),
            mtime_from: Some("2026-01-01T00:00:00+00:00".into()),
            mtime_to: Some("2026-01-02T00:00:00Z".into()),
            ..QuerySpec::default()
        })
        .unwrap();
        assert_eq!(query.source_ids[0], "00000000-0000-0000-0000-000000000001");
        assert_eq!(query.category_ids, vec!["audio", "videos"]);
        assert_eq!(query.extensions, vec![".md", "txt"]);
        assert_eq!(query.owner_uids, vec![1000, 1001]);
        assert_eq!(query.min_size_bytes.as_deref(), Some("10"));
        assert!(query.query_hash().is_ok());
    }

    #[test]
    fn export_scope_and_unsupported_filters_follow_the_query_contract() {
        let query = QuerySpec {
            source_ids: vec!["00000000-0000-0000-0000-000000000001".into()],
            ..QuerySpec::default()
        };
        assert_eq!(
            effective_export_query(ExportScope::Current, query.clone()).unwrap(),
            query
        );
        assert_eq!(
            effective_export_query(ExportScope::All, query).unwrap(),
            QuerySpec::default()
        );

        let error = validate_export_query_for_section(
            ExportSection::FullReport,
            &QuerySpec {
                source_ids: vec!["00000000-0000-0000-0000-000000000001".into()],
                ..QuerySpec::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::BadRequest);
        assert!(error.to_string().contains("source_ids"));
    }

    #[test]
    fn export_query_rejects_values_that_do_not_fit_sqlite_i64() {
        let value = (i128::from(i64::MAX) + 1).to_string();
        let error = export_decimal_i64(Some(&value), "min_size_bytes").unwrap_err();
        assert_eq!(error.code(), ErrorCode::BadRequest);
        assert!(error.to_string().contains("有符号 64 位整数"));
    }

    #[test]
    fn report_cursor_is_opaque_signed_and_query_bound() {
        let auth = test_auth();
        let encoded = encode_report_query_cursor(
            &auth,
            "report-1",
            "query-1",
            "files:size_desc",
            vec!["100".into(), "9".into()],
        )
        .unwrap();
        assert_eq!(
            decode_report_query_cursor(&auth, &encoded, "report-1", "query-1", "files:size_desc")
                .unwrap(),
            vec!["100", "9"]
        );
        assert_eq!(
            decode_report_query_cursor(&auth, &encoded, "report-1", "query-2", "files:size_desc")
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        let mut tampered = encoded.into_bytes();
        tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert_eq!(
            decode_report_query_cursor(&auth, &tampered, "report-1", "query-1", "files:size_desc")
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
    }

    #[test]
    fn report_list_meta_exposes_detail_expiration_state() {
        let meta = report_list_meta(None, 50, false, false);
        assert_eq!(meta["page_size"], 50);
        assert_eq!(meta["detail_available"], false);
        assert_eq!(meta["next_cursor"], Value::Null);
    }

    #[test]
    fn legacy_report_manifest_is_normalized_to_detail_contract() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("report-1")).unwrap();
        std::fs::write(root.path().join("report-1/index.sqlite"), b"index").unwrap();
        let normalized = normalize_report_manifest(
            json!({
                "manifest_version": 1,
                "files": { "index.sqlite": "digest" }
            }),
            root.path(),
            "report-1",
        )
        .unwrap();
        assert_eq!(normalized["schema_version"], 1);
        assert!(normalized.get("manifest_version").is_none());
        assert!(normalized["files"].is_array());
        assert_eq!(normalized["files"][0]["path"], "index.sqlite");
        assert_eq!(normalized["files"][0]["size_bytes"], "5");
        assert_eq!(normalized["files"][0]["sha256"], "digest");
    }

    #[test]
    fn report_page_size_rejects_out_of_contract_values() {
        assert_eq!(report_page_size(None).unwrap(), 50);
        assert_eq!(report_page_size(Some(200)).unwrap(), 200);
        assert_eq!(
            report_page_size(Some(0)).unwrap_err().code,
            ErrorCode::BadRequest
        );
        assert_eq!(
            report_page_size(Some(201)).unwrap_err().code,
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn expired_report_detail_is_a_stable_410_error() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE reports (id TEXT PRIMARY KEY, manifest_path TEXT NOT NULL,
                                   detail_available INTEGER NOT NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO reports(id, manifest_path, detail_available)
             VALUES ('report-1', '/tmp/reports/report-1/manifest.json', 0)",
            [],
        )
        .unwrap();
        let error = open_report_database(
            &conn,
            StdPath::new("/tmp/reports"),
            "report-1",
            "index.sqlite",
            "打开报告明细失败",
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::DetailExpired);
        assert_eq!(error.code.http_status(), 410);
    }

    #[test]
    fn handler_write_error_mappers_preserve_capacity_semantics() {
        let sqlite_error = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            None,
        );
        assert_eq!(
            AppError::from_sqlite("保存导出排队记录失败", sqlite_error).code,
            ErrorCode::InsufficientDataSpace
        );
        for kind in [
            std::io::ErrorKind::StorageFull,
            std::io::ErrorKind::QuotaExceeded,
        ] {
            assert_eq!(
                AppError::from_io("同步导出文件失败", std::io::Error::from(kind)).code,
                ErrorCode::InsufficientDataSpace
            );
        }
    }
}

#[cfg(test)]
mod volume_sample_query_tests {
    use super::*;

    #[test]
    fn daily_sample_json_exposes_last_and_ranges_for_each_capacity_metric() {
        let value = daily_sample_json(&sampling::DailyVolumeSample {
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
        });

        for (key, expected) in [
            ("total_bytes", "110"),
            ("total_min_bytes", "90"),
            ("total_max_bytes", "110"),
            ("free_bytes", "50"),
            ("free_min_bytes", "20"),
            ("free_max_bytes", "50"),
            ("available_bytes", "45"),
            ("available_min_bytes", "10"),
            ("available_max_bytes", "45"),
            ("used_bytes", "60"),
            ("used_min_bytes", "60"),
            ("used_max_bytes", "70"),
        ] {
            assert_eq!(value[key], expected, "JSON 字段 {key} 未保留容量汇总值");
        }
        assert_eq!(value["sample_time"], "2026-01-02T00:00:00Z");
        assert_eq!(value["quality"], "complete");
    }

    #[test]
    fn raw_capacity_query_uses_fixed_minute_bounds_for_indexable_ranges() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::store::migrate::apply(&mut conn, crate::store::migrate::CONTROL_MIGRATIONS).unwrap();
        conn.execute(
            "INSERT INTO volumes (id, name, created_at, updated_at)
             VALUES ('volume-1', 'Volume 1', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        for (sample_time, used) in [
            ("2026-01-01T00:00:00.000Z", "1"),
            ("2026-01-01T00:01:00.000Z", "1"),
            ("2026-01-01T00:02:00.000Z", "1"),
        ] {
            conn.execute(
                "INSERT INTO volume_samples
                 (volume_id, sample_time, total_bytes, free_bytes, available_bytes, used_bytes, quality)
                 VALUES ('volume-1', ?1, '10', '9', '8', ?2, 'ok')",
                params![sample_time, used],
            )
            .unwrap();
        }

        let from_timestamp: jiff::Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let to_timestamp: jiff::Timestamp = "2026-01-01T00:02:00Z".parse().unwrap();
        let from = raw_sample_time_bound(&from_timestamp).unwrap();
        let to = raw_sample_time_bound(&to_timestamp).unwrap();
        assert_eq!(from, "2026-01-01T00:00:00.000Z");
        assert_eq!(to, "2026-01-01T00:02:00.000Z");

        let (items, has_more) =
            list_raw_samples_page(&conn, "volume-1", Some(&from), Some(&to), None, 50).unwrap();
        assert!(!has_more);
        assert_eq!(
            items
                .iter()
                .map(|item| item.sample_time.as_str())
                .collect::<Vec<_>>(),
            vec!["2026-01-01T00:00:00.000Z", "2026-01-01T00:01:00.000Z"]
        );

        let after_first: jiff::Timestamp = "2026-01-01T00:00:00.001Z".parse().unwrap();
        let after_first = raw_sample_time_bound(&after_first).unwrap();
        let (items, _) =
            list_raw_samples_page(&conn, "volume-1", Some(&after_first), None, None, 50).unwrap();
        assert_eq!(
            items
                .iter()
                .map(|item| item.sample_time.as_str())
                .collect::<Vec<_>>(),
            vec!["2026-01-01T00:01:00.000Z", "2026-01-01T00:02:00.000Z"]
        );
    }
}

#[cfg(test)]
mod internal_notification_query_tests {
    use super::*;
    use crate::auth::Session;

    fn test_auth() -> Auth {
        Auth {
            session: Session {
                token_hash: "token-hash".into(),
                user_id: "admin".into(),
                csrf_secret: "cursor-signing-secret".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                expires_idle_at: "2027-01-01T00:00:00Z".into(),
                expires_absolute_at: "2027-01-01T00:00:00Z".into(),
                last_seen_at: "2026-01-01T00:00:00Z".into(),
            },
            token: "session-token".into(),
        }
    }

    #[test]
    fn internal_notification_cursor_is_signed_for_the_notification_list() {
        let auth = test_auth();
        let cursor = encode_list_cursor(
            &auth,
            "internal-notifications",
            vec![
                "2026-01-01T00:00:00.000Z".to_string(),
                "notification-b".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            decode_list_position(&auth, Some(&cursor), "internal-notifications").unwrap(),
            Some((
                "2026-01-01T00:00:00.000Z".to_string(),
                "notification-b".to_string(),
            ))
        );
        assert_eq!(
            decode_list_position(&auth, Some(&cursor), "other-list")
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
    }
}

#[derive(Debug, Deserialize)]
pub struct ReportDuplicatesQuery {
    complete_only: Option<bool>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

fn duplicate_group_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let group_id: i64 = row.get(0)?;
    let size_bytes: i64 = row.get(1)?;
    let hash: String = row.get(2)?;
    let member_count: i64 = row.get(3)?;
    let listed_member_count: i64 = row.get(4)?;
    let logical_redundancy_bytes: i64 = row.get(5)?;
    let truncated: i64 = row.get(6)?;
    let verification: String = row.get(7)?;
    let logical_total_bytes = i128::from(size_bytes) * i128::from(member_count);
    Ok(json!({
        "group_id": group_id.to_string(),
        "member_count": member_count,
        "listed_member_count": listed_member_count,
        "complete": truncated == 0,
        "size_bytes": size_bytes.to_string(),
        "logical_total_bytes": logical_total_bytes.to_string(),
        "reclaimable_bytes": logical_redundancy_bytes.to_string(),
        "verification": verification,
        "hash": (verification == "hash_complete").then_some(hash),
    }))
}

fn duplicate_member_json(row: &rusqlite::Row<'_>, size_bytes: &str) -> rusqlite::Result<Value> {
    let mtime_sec: Option<i64> = row.get(5)?;
    let mtime_nsec: Option<i64> = row.get(6)?;
    Ok(json!({
        "entry_id": row.get::<_, i64>(0)?.to_string(),
        "source_id": row.get::<_, String>(1)?,
        "display_path": row.get::<_, String>(3)?,
        "size_bytes": size_bytes,
        "mtime": match (mtime_sec, mtime_nsec) {
            (Some(sec), Some(nsec)) => json!({
                "rfc3339": format!("{sec}.{nsec:09}Z"),
                "sec": sec.to_string(),
                "nsec": nsec,
                "unavailable_reason": Value::Null,
            }),
            _ => json!({
                "rfc3339": Value::Null,
                "sec": Value::Null,
                "nsec": Value::Null,
                "unavailable_reason": "not_observed",
            }),
        },
        "protected": row.get::<_, i64>(8)? != 0,
    }))
}

pub async fn report_duplicates(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<ReportDuplicatesQuery>,
) -> Response {
    let limit = page_size(q.page_size);
    let cursor = match q.cursor.as_deref() {
        Some(value) => {
            let decoded = match decode_opaque_cursor(value) {
                Ok(decoded) => decoded,
                Err(error) => return err_response(&req_id.0, error),
            };
            match decoded.parse::<i64>() {
                Ok(value) => Some(value),
                Err(_) => {
                    return err_response(
                        &req_id.0,
                        AppError::new(ErrorCode::BadRequest, "重复组分页游标无效"),
                    );
                }
            }
        }
        None => None,
    };
    let complete_only = q.complete_only.unwrap_or(false);
    let reports_root = st.config.storage.data_dir.join("reports");
    let result = st
        .readers
        .call(move |conn| {
            let (db, _) = open_report_database(
                conn,
                &reports_root,
                &id,
                "report.sqlite",
                "打开报告摘要失败",
            )?;
            let mut stmt = db
                .prepare(
                    "SELECT group_id, size_bytes, sha256, member_count,
                            listed_member_count, logical_redundancy_bytes,
                            truncated, verification
                     FROM duplicate_groups
                     WHERE (?1 = 0 OR truncated = 0)
                       AND (?2 IS NULL OR group_id > ?2)
                     ORDER BY group_id LIMIT ?3",
                )
                .map_err(|e| internal(format!("准备重复组列表失败: {e}")))?;
            let rows = stmt
                .query_map(
                    params![i64::from(complete_only), cursor, limit as i64 + 1],
                    duplicate_group_json,
                )
                .map_err(|e| internal(format!("读取重复组列表失败: {e}")))?;
            let mut items = Vec::new();
            for row in rows {
                items.push(row.map_err(|e| internal(format!("解析重复组失败: {e}")))?);
            }
            let next_cursor = if items.len() > limit {
                let last = items.pop().ok_or_else(|| internal("重复组分页结果为空"))?;
                let group_id = last["group_id"]
                    .as_str()
                    .ok_or_else(|| internal("重复组 id 字段损坏"))?;
                Some(encode_opaque_cursor(group_id))
            } else {
                None
            };
            Ok((items, next_cursor))
        })
        .await;
    match result {
        Ok((items, next_cursor)) => ok_response(
            &req_id.0,
            StatusCode::OK,
            json!(items),
            list_meta(next_cursor, items.len(), None, false),
        ),
        Err(error) => err_response(&req_id.0, error),
    }
}

pub async fn report_duplicate_group(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path((id, group_id)): Path<(String, String)>,
) -> Response {
    let group_id = match group_id.parse::<i64>() {
        Ok(value) if value >= 0 => value,
        _ => {
            return err_response(
                &req_id.0,
                AppError::new(ErrorCode::BadRequest, "group_id 必须是非负十进制整数"),
            );
        }
    };
    let reports_root = st.config.storage.data_dir.join("reports");
    let result = st
        .readers
        .call(move |conn| {
            let (db, _) = open_report_database(
                conn,
                &reports_root,
                &id,
                "report.sqlite",
                "打开报告摘要失败",
            )?;
            let group = db
                .query_row(
                    "SELECT group_id, size_bytes, sha256, member_count,
                            listed_member_count, logical_redundancy_bytes,
                            truncated, verification
                     FROM duplicate_groups WHERE group_id = ?1",
                    [group_id],
                    duplicate_group_json,
                )
                .optional()
                .map_err(|e| internal(format!("读取重复组失败: {e}")))?
                .ok_or_else(|| AppError::new(ErrorCode::NotFound, "重复组不存在"))?;
            let size_bytes = group["size_bytes"]
                .as_str()
                .ok_or_else(|| internal("重复组 size_bytes 字段损坏"))?
                .to_owned();
            let mut stmt = db
                .prepare(
                    "SELECT entry_id, source_id, raw_relative_path, display_path,
                            uid, mtime_sec, mtime_nsec, group_id, protected
                     FROM duplicate_members
                     WHERE group_id = ?1 ORDER BY entry_id",
                )
                .map_err(|e| internal(format!("准备重复成员查询失败: {e}")))?;
            let rows = stmt
                .query_map([group_id], |row| {
                    let mut value = duplicate_member_json(row, &size_bytes)?;
                    if let Some(object) = value.as_object_mut() {
                        object.insert("uid".into(), row.get::<_, Option<i64>>(4)?.into());
                    }
                    Ok(value)
                })
                .map_err(|e| internal(format!("读取重复成员失败: {e}")))?;
            let mut members = Vec::new();
            for row in rows {
                members.push(row.map_err(|e| internal(format!("解析重复成员失败: {e}")))?);
            }
            let complete = group["complete"]
                .as_bool()
                .ok_or_else(|| internal("重复组 complete 字段损坏"))?;
            Ok((
                group,
                members,
                complete,
                if complete {
                    Value::Null
                } else {
                    json!("max_listed_files")
                },
            ))
        })
        .await;
    match result {
        Ok((group, members, complete, reason)) => ok_response(
            &req_id.0,
            StatusCode::OK,
            json!({
                "group": group,
                "members": members,
                "truncated": !complete,
                "truncation_reason": reason,
            }),
            json!({}),
        ),
        Err(error) => err_response(&req_id.0, error),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompareReportsBody {
    other_report_id: String,
    mode: CompareMode,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompareMode {
    Aggregate,
    Files,
}

impl CompareMode {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Aggregate => "aggregate",
            Self::Files => "files",
        }
    }
}

struct CompareReportInfo {
    scope_fingerprint: String,
    classification_version: i64,
    detail_available: bool,
    status: String,
    profile_id: Option<String>,
    source_identities: Value,
}

pub async fn compare_reports(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<CompareReportsBody>,
) -> Response {
    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    if id == body.other_report_id {
        return err_response(
            &req_id.0,
            AppError::new(ErrorCode::BadRequest, "两个报告必须不同"),
        );
    }
    let other_report_id = body.other_report_id;
    let mode = body.mode;
    let reports_root = st.config.storage.data_dir.join("reports");
    let result = st
        .writer
        .call(move |conn| {
            let expected_report_id = Value::String(id.clone());
            let expected_other_report_id = Value::String(other_report_id.clone());
            let expected_mode = Value::String(mode.as_str().to_owned());
            if let Some(job) = job_by_idempotency_key(conn, &idempotency_key)? {
                ensure_idempotent_job_request(
                    &job,
                    JobType::Compare,
                    &[
                        ("report_id", &expected_report_id),
                        ("other_report_id", &expected_other_report_id),
                        ("mode", &expected_mode),
                    ],
                )?;
                let comparison_id = job_param_string(&job, "comparison_id")?.to_owned();
                let comparable = job_param_bool(&job, "comparable")?;
                let incompatibility_reasons = job_param_value(&job, "incompatibility_reasons")?;
                return Ok((
                    StatusCode::ACCEPTED,
                    json!({
                        "comparison_id": comparison_id,
                        "job_id": job.id,
                        "comparable": comparable,
                        "incompatibility_reasons": incompatibility_reasons,
                    }),
                    json!({}),
                ));
            }
            let read_report = |report_id: &str| -> AppResult<CompareReportInfo> {
                let row: Option<(String, i64, i64, String, Option<String>)> = conn
                    .query_row(
                        "SELECT scope_fingerprint, classification_version,
                                detail_available, status, profile_id
                         FROM reports WHERE id = ?1",
                        [report_id],
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
                    .optional()
                    .map_err(|e| internal(format!("读取比较报告失败: {e}")))?;
                let Some((scope_fingerprint, classification_version, detail, status, profile_id)) =
                    row
                else {
                    return Err(AppError::new(ErrorCode::NotFound, "比较报告不存在"));
                };
                let (report, _) = open_report_database(
                    conn,
                    &reports_root,
                    report_id,
                    "report.sqlite",
                    "打开比较报告摘要失败",
                )?;
                let identities: String = report
                    .query_row(
                        "SELECT value FROM report_meta WHERE key = 'source_identities'",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|e| internal(format!("读取比较报告源身份快照失败: {e}")))?;
                let source_identities = serde_json::from_str(&identities)
                    .map_err(|e| internal(format!("解析比较报告源身份快照失败: {e}")))?;
                Ok(CompareReportInfo {
                    scope_fingerprint,
                    classification_version,
                    detail_available: detail != 0,
                    status,
                    profile_id,
                    source_identities,
                })
            };
            let left = read_report(&id)?;
            let right = read_report(&other_report_id)?;
            if left.status == "failed" || right.status == "failed" {
                return Err(AppError::new(
                    ErrorCode::ReportIncompatible,
                    "失败报告不能参与比较",
                ));
            }
            if matches!(mode, CompareMode::Files)
                && (!left.detail_available || !right.detail_available)
            {
                return Err(AppError::new(ErrorCode::DetailExpired, "文件明细已过期"));
            }
            let mut incompatibility_reasons = Vec::new();
            if left.profile_id != right.profile_id {
                incompatibility_reasons.push("different_profile");
            }
            if left.scope_fingerprint != right.scope_fingerprint {
                incompatibility_reasons.push("scope_fingerprint_mismatch");
            }
            if left.classification_version != right.classification_version {
                incompatibility_reasons.push("classification_version_mismatch");
            }
            if left.source_identities != right.source_identities {
                incompatibility_reasons.push("source_identity_or_availability_mismatch");
            }
            if left.status != "succeeded" || right.status != "succeeded" {
                incompatibility_reasons.push("partial_report");
            }
            let comparable = incompatibility_reasons.is_empty();
            let params = json!({
                "report_id": &id,
                "other_report_id": &other_report_id,
                "mode": mode.as_str(),
                "comparable": comparable,
                "incompatibility_reasons": incompatibility_reasons,
            });
            let comparison_id = uuid::Uuid::new_v4().to_string();
            let mut params = params;
            params["comparison_id"] = json!(comparison_id);
            let tx = conn
                .transaction()
                .map_err(|e| AppError::from_sqlite("开启比较入队事务失败", e))?;
            let job = jobs::create_job(
                &tx,
                JobType::Compare,
                None,
                None,
                &params,
                Some(&idempotency_key),
                1,
            )?;
            tx.execute(
                "INSERT INTO comparisons
                 (id, job_id, left_report_id, right_report_id, mode, comparable,
                  state, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7)",
                params![
                    comparison_id,
                    job.id,
                    id,
                    other_report_id,
                    mode.as_str(),
                    i64::from(comparable),
                    auth::now_rfc3339(),
                ],
            )
            .map_err(|e| AppError::from_sqlite("保存比较排队记录失败", e))?;
            tx.commit()
                .map_err(|e| AppError::from_sqlite("提交比较入队事务失败", e))?;
            Ok((
                StatusCode::ACCEPTED,
                json!({
                    "comparison_id": comparison_id,
                    "job_id": job.id,
                    "comparable": comparable,
                    "incompatibility_reasons": params["incompatibility_reasons"],
                }),
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
pub struct ComparisonRowsQuery {
    section: Option<String>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn get_comparison(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
    Query(query): Query<ComparisonRowsQuery>,
) -> Response {
    let limit = page_size(query.page_size);
    let cursor = match query.cursor.as_deref() {
        Some(value) => {
            let decoded = match decode_opaque_cursor(value) {
                Ok(value) => value,
                Err(error) => return err_response(&req_id.0, error),
            };
            let (section, row_key) = match decoded.split_once('|') {
                Some(value) => value,
                None => {
                    return err_response(
                        &req_id.0,
                        AppError::new(ErrorCode::BadRequest, "比较结果分页游标无效"),
                    );
                }
            };
            Some((section.to_owned(), row_key.to_owned()))
        }
        None => None,
    };
    let result = st.readers.call(move |conn| {
        let comparison: (String, String, String, String, i64, String, Option<String>) = conn
            .query_row(
                "SELECT job_id, left_report_id, right_report_id, mode, comparable,
                        summary_json, error_json
                 FROM comparisons WHERE id = ?1",
                [&id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| internal(format!("读取比较结果失败: {e}")))?
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, "比较结果不存在"))?;
        let (cursor_section, cursor_key) = cursor
            .map(|(section, key)| (Some(section), Some(key)))
            .unwrap_or((None, None));
        let mut stmt = conn
            .prepare(
                "SELECT section, row_key, payload_json FROM comparison_rows
                 WHERE comparison_id = ?1
                   AND (?2 IS NULL OR section = ?2)
                   AND (?3 IS NULL OR section > ?3
                        OR (section = ?3 AND row_key > ?4))
                 ORDER BY section, row_key LIMIT ?5",
            )
            .map_err(|e| internal(format!("准备比较明细查询失败: {e}")))?;
        let rows = stmt
            .query_map(
                params![
                    id,
                    query.section,
                    cursor_section,
                    cursor_key,
                    limit as i64 + 1,
                ],
                |row| {
                    let section: String = row.get(0)?;
                    let key: String = row.get(1)?;
                    let payload: String = row.get(2)?;
                    let mut value = serde_json::from_str::<Value>(&payload).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    let object = value.as_object_mut().ok_or_else(|| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "比较明细 payload 不是对象",
                            )),
                        )
                    })?;
                    object.insert("row_key".to_owned(), Value::String(key.clone()));
                    Ok((section, key, value))
                },
            )
            .map_err(|e| internal(format!("读取比较明细失败: {e}")))?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row.map_err(|e| internal(format!("解析比较明细失败: {e}")))?);
        }
        let next_cursor = if items.len() > limit {
            items.truncate(limit);
            items
                .last()
                .map(|(section, key, _)| encode_opaque_cursor(&format!("{section}|{key}")))
        } else {
            None
        };
        let summary = serde_json::from_str::<Value>(&comparison.5)
            .map_err(|e| internal(format!("比较摘要损坏: {e}")))?;
        let mut data = json!({
            "id": id,
            "job_id": comparison.0,
            "left_report_id": comparison.1,
            "right_report_id": comparison.2,
            "mode": comparison.3,
            "comparable": comparison.4 != 0,
            "state": if comparison.6.is_some() { "failed" } else if summary != json!({}) { "succeeded" } else { "pending" },
            "summary": summary,
            "error": comparison.6.and_then(|value| serde_json::from_str::<Value>(&value).ok()),
            "rows": items.into_iter().map(|(_, _, value)| value).collect::<Vec<_>>(),
        });
        if let Some(reasons) = data["summary"].get("incompatibility_reasons").cloned() {
            data["incompatibility_reasons"] = reasons;
        }
        Ok((data, next_cursor))
    }).await;
    match result {
        Ok((data, next_cursor)) => ok_response(
            &req_id.0,
            StatusCode::OK,
            data,
            list_meta(next_cursor, limit, None, false),
        ),
        Err(error) => err_response(&req_id.0, error),
    }
}

// ---- settings, metadata, diagnostics and audit ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryRulesInput {
    rules: BTreeMap<String, Vec<String>>,
}

fn category_rules_json(ruleset: &CategoryRuleset, created_at: &str, id: &str) -> Value {
    let mut rules = BTreeMap::<String, Vec<String>>::new();
    for category_id in category::CATEGORY_IDS {
        rules.insert(category_id.to_string(), Vec::new());
    }
    for (extension, category_id) in &ruleset.mapping {
        rules
            .get_mut(category_id)
            .expect("validated category id")
            .push(extension.clone());
    }
    json!({
        "id": id,
        "version": ruleset.version,
        "rules": rules,
        "created_at": created_at,
    })
}

fn load_category_ruleset(
    conn: &rusqlite::Connection,
) -> AppResult<(CategoryRuleset, String, String)> {
    let row: Option<(String, u32, String, String)> = conn
        .query_row(
            "SELECT id, version, rules_json, created_at FROM category_rulesets WHERE is_default = 1 ORDER BY version DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|e| internal(format!("读取分类规则集失败: {e}")))?;
    let Some((id, version, rules_json, created_at)) = row else {
        let ruleset = CategoryRuleset::default_v1();
        return Ok((ruleset, "builtin-v1".to_string(), "".to_string()));
    };
    let mapping: BTreeMap<String, String> = serde_json::from_str(&rules_json)
        .map_err(|e| internal(format!("分类规则集数据损坏: {e}")))?;
    let ruleset = CategoryRuleset { version, mapping };
    ruleset.validate()?;
    Ok((ruleset, id, created_at))
}

pub async fn get_category_rules(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
) -> Response {
    let result = st
        .readers
        .call(|conn| {
            let (ruleset, id, created_at) = load_category_ruleset(conn)?;
            Ok((
                StatusCode::OK,
                category_rules_json(&ruleset, &created_at, &id),
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

pub async fn put_category_rules(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    ApiJson(body): ApiJson<CategoryRulesInput>,
) -> Response {
    let result = st.writer.call(move |conn| {
        let (base, _, _) = load_category_ruleset(conn)?;
        let mut changes = Vec::new();
        let mut seen = BTreeMap::<String, String>::new();
        for category_id in category::CATEGORY_IDS {
            let Some(extensions) = body.rules.get(category_id) else {
                return Err(AppError::new(ErrorCode::ValidationFailed, format!("缺少固定分类 {category_id}")));
            };
            for extension in extensions {
                if let Some(previous) = seen.insert(extension.to_ascii_lowercase(), category_id.to_string())
                    && previous != category_id
                {
                    return Err(AppError::new(ErrorCode::ValidationFailed, format!("扩展名 {extension:?} 不能属于多个分类")));
                }
                changes.push((extension.clone(), category_id.to_string()));
            }
        }
        let next_version = base
            .version
            .checked_add(1)
            .ok_or_else(|| AppError::new(ErrorCode::ValidationFailed, "分类规则版本已达到上限"))?;
        let removals = base.mapping.keys().filter(|extension| !seen.contains_key(*extension)).cloned().collect::<Vec<_>>();
        let ruleset = category::derive_ruleset(&base, &changes, &removals, next_version)?;
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = auth::now_rfc3339();
        let tx = conn
            .transaction()
            .map_err(|e| AppError::from_sqlite("开启分类规则事务失败", e))?;
        tx.execute("UPDATE category_rulesets SET is_default = 0 WHERE is_default = 1", [])
            .map_err(|e| AppError::from_sqlite("更新当前分类规则失败", e))?;
        tx.execute(
            "INSERT INTO category_rulesets (id, version, rules_json, is_default, created_at) VALUES (?1, ?2, ?3, 1, ?4)",
            params![id, ruleset.version, serde_json::to_string(&ruleset.mapping).map_err(|e| internal(format!("序列化分类规则失败: {e}")))?, created_at],
        )
        .map_err(|e| AppError::from_sqlite("保存分类规则失败", e))?;
        tx.commit()
            .map_err(|e| AppError::from_sqlite("提交分类规则失败", e))?;
        audit::record(conn, &auth.session.user_id, "settings.category_rules.update", Some(&id), "success", None, Some(json!({"version": ruleset.version})))?;
        Ok((StatusCode::OK, category_rules_json(&ruleset, &created_at, &id), json!({})))
    }).await;
    respond(&req_id, result)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl StoredNotificationSettings {
    fn into_domain(self) -> NotificationSettings {
        NotificationSettings {
            enabled: self.enabled,
            smtp_host: self.smtp_host,
            smtp_port: self.smtp_port,
            tls_mode: self.tls_mode,
            username: self.username,
            password: self.password,
            from_address: self.from_address,
            default_recipients: self.default_recipients,
            subject_prefix: self.subject_prefix,
            public_base_url: self.public_base_url,
        }
    }
}

fn read_setting(conn: &rusqlite::Connection, key: &str) -> AppResult<Option<String>> {
    conn.query_row(
        "SELECT value_json FROM app_settings WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| internal(format!("读取设置 {key} 失败: {e}")))
}

fn write_setting(conn: &rusqlite::Connection, key: &str, value: &Value) -> AppResult<()> {
    conn.execute(
        "INSERT INTO app_settings (key, value_json, version, updated_at) VALUES (?1, ?2, 1, ?3)
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, version = app_settings.version + 1, updated_at = excluded.updated_at",
        params![key, value.to_string(), auth::now_rfc3339()],
    )
    .map_err(|e| AppError::from_sqlite(format!("保存设置 {key} 失败"), e))?;
    Ok(())
}

fn notification_from_conn(conn: &rusqlite::Connection) -> AppResult<NotificationSettings> {
    let raw = read_setting(conn, "notifications")?
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "通知尚未配置"))?;
    let stored: StoredNotificationSettings =
        serde_json::from_str(&raw).map_err(|e| internal(format!("通知设置数据损坏: {e}")))?;
    let settings = stored.into_domain();
    settings.validate()?;
    Ok(settings)
}

pub async fn get_notification_settings(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
) -> Response {
    let result = st
        .readers
        .call(|conn| {
            let settings = notification_from_conn(conn)?;
            Ok((
                StatusCode::OK,
                serde_json::to_value(settings.view())
                    .map_err(|e| internal(format!("序列化通知设置失败: {e}")))?,
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationSettingsInput {
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

pub async fn put_notification_settings(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    ApiJson(body): ApiJson<NotificationSettingsInput>,
) -> Response {
    let result = st
        .writer
        .call(move |conn| {
            let previous = read_setting(conn, "notifications")?
                .and_then(|raw| serde_json::from_str::<StoredNotificationSettings>(&raw).ok());
            let password = match body.password {
                Some(password) if !password.is_empty() => Some(password),
                _ => previous.and_then(|settings| settings.password),
            };
            let settings = NotificationSettings {
                enabled: body.enabled,
                smtp_host: body.smtp_host,
                smtp_port: body.smtp_port,
                tls_mode: body.tls_mode,
                username: body.username,
                password,
                from_address: body.from_address,
                default_recipients: body.default_recipients,
                subject_prefix: body.subject_prefix,
                public_base_url: body.public_base_url,
            };
            settings.validate()?;
            let stored = StoredNotificationSettings {
                enabled: settings.enabled,
                smtp_host: settings.smtp_host.clone(),
                smtp_port: settings.smtp_port,
                tls_mode: settings.tls_mode,
                username: settings.username.clone(),
                password: settings.password.clone(),
                from_address: settings.from_address.clone(),
                default_recipients: settings.default_recipients.clone(),
                subject_prefix: settings.subject_prefix.clone(),
                public_base_url: settings.public_base_url.clone(),
            };
            write_setting(
                conn,
                "notifications",
                &serde_json::to_value(stored)
                    .map_err(|e| internal(format!("序列化通知设置失败: {e}")))?,
            )?;
            audit::record(
                conn,
                &auth.session.user_id,
                "settings.notifications.update",
                None,
                "success",
                None,
                Some(json!({"enabled": settings.enabled})),
            )?;
            Ok((
                StatusCode::OK,
                serde_json::to_value(settings.view())
                    .map_err(|e| internal(format!("序列化通知设置失败: {e}")))?,
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationTestInput {
    recipient: Option<String>,
}

pub async fn test_notification(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    ApiJson(body): ApiJson<NotificationTestInput>,
) -> Response {
    let request_id = req_id.0.clone();
    let result = st
        .writer
        .call(move |conn| {
            let settings = notification_from_conn(conn)?;
            let recipient = body
                .recipient
                .or_else(|| settings.default_recipients.first().cloned())
                .ok_or_else(|| AppError::new(ErrorCode::ValidationFailed, "没有测试邮件收件人"))?;
            let payload = notify::EmailPayload {
                subject: format!("{} test", settings.subject_prefix),
                body_text: "NAS Analyzer notification test".to_string(),
                attachment: None,
            };
            let kind = format!("test-{}", uuid::Uuid::new_v4());
            let _ = notify::enqueue(conn, None, &recipient, &kind, &payload)?;
            let claim = notify::claim_next_at(conn, &auth::now_rfc3339())?
                .ok_or_else(|| internal("测试通知入队后无法领取"))?;
            let message = notify::build_message(&claim, &settings)?;
            Ok((settings, claim, message, auth.session.user_id, recipient))
        })
        .await;
    match result {
        Ok((settings, claim, message, actor_id, recipient)) => {
            let transport = match settings.tls_mode {
                TlsMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.smtp_host),
                TlsMode::Starttls => {
                    AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.smtp_host)
                }
                TlsMode::None => {
                    return err_response(
                        &req_id.0,
                        AppError::new(ErrorCode::UnsupportedCapability, "SMTP 明文模式未启用"),
                    );
                }
            };
            let mut builder = match transport {
                Ok(builder) => builder.port(settings.smtp_port),
                Err(error) => {
                    return err_response(
                        &req_id.0,
                        internal(format!("创建 SMTP transport 失败: {error}")),
                    );
                }
            };
            if let (Some(username), Some(password)) = (settings.username, settings.password) {
                builder = builder.credentials(Credentials::new(username, password));
            }
            let mailer = builder.build();
            let send_result = mailer.send(message).await;
            let state_result = match send_result {
                Ok(_) => {
                    st.writer
                        .call(move |conn| {
                            let sent = notify::mark_sent(conn, &claim)?;
                            audit::record(
                                conn,
                                &actor_id,
                                "notification.test",
                                None,
                                "success",
                                Some(&request_id),
                                Some(json!({"recipient": recipient})),
                            )?;
                            Ok(sent)
                        })
                        .await
                }
                Err(error) => {
                    let text = error.to_string();
                    let _ = st
                        .writer
                        .call(move |conn| {
                            let failed = notify::mark_failed(conn, &claim, &text)?;
                            audit::record(
                                conn,
                                &actor_id,
                                "notification.test",
                                None,
                                "failed",
                                Some(&request_id),
                                Some(json!({"recipient": recipient, "state": failed.state})),
                            )?;
                            Ok(failed)
                        })
                        .await;
                    return err_response(
                        &req_id.0,
                        AppError::new(
                            ErrorCode::SourceUnavailable,
                            "测试邮件发送失败，已写入通知重试队列",
                        ),
                    );
                }
            };
            match state_result {
                Ok(_) => ok_response(
                    &req_id.0,
                    StatusCode::OK,
                    json!({"delivered": true, "detail": "测试邮件已提交 SMTP"}),
                    json!({}),
                ),
                Err(error) => err_response(&req_id.0, error),
            }
        }
        Err(error) => err_response(&req_id.0, error),
    }
}

fn storage_budget(conn: &rusqlite::Connection, deployment_max: u64) -> AppResult<u64> {
    let Some(raw) = read_setting(conn, "storage")? else {
        return Ok(deployment_max);
    };
    let value: Value =
        serde_json::from_str(&raw).map_err(|e| internal(format!("存储设置数据损坏: {e}")))?;
    let text = value
        .get("data_budget_bytes")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("存储设置缺少 data_budget_bytes"))?;
    text.parse::<u64>()
        .map_err(|_| AppError::new(ErrorCode::Internal, "存储预算不是有效十进制整数"))
}

fn storage_json(conn: &rusqlite::Connection, st: &AppState) -> AppResult<Value> {
    let budget = storage_budget(conn, st.config.storage.data_budget_bytes)?;
    let info = diagnostics::collect(conn, &st.config, st.kernel_safe_writes, &st.memory_budget)?;
    Ok(
        json!({"data_budget_bytes": budget.to_string(), "used_bytes": info.data_dir.used_bytes, "deployment_max_budget_bytes": st.config.storage.data_budget_bytes.to_string()}),
    )
}

pub async fn get_storage_settings(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
) -> Response {
    let st_for_call = st.clone();
    let result = st
        .readers
        .call(move |conn| Ok((StatusCode::OK, storage_json(conn, &st_for_call)?, json!({}))))
        .await;
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSettingsInput {
    data_budget_bytes: String,
}

pub async fn put_storage_settings(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    ApiJson(body): ApiJson<StorageSettingsInput>,
) -> Response {
    let max = st.config.storage.data_budget_bytes;
    let st_for_call = st.clone();
    let result = st
        .writer
        .call(move |conn| {
            let budget = body.data_budget_bytes.parse::<u64>().map_err(|_| {
                AppError::new(
                    ErrorCode::ValidationFailed,
                    "data_budget_bytes 必须是十进制整数",
                )
            })?;
            if budget == 0 || budget > max {
                return Err(AppError::new(
                    ErrorCode::ValidationFailed,
                    "存储预算必须大于 0 且不超过部署上限",
                ));
            }
            write_setting(
                conn,
                "storage",
                &json!({"data_budget_bytes": budget.to_string()}),
            )?;
            audit::record(
                conn,
                &auth.session.user_id,
                "settings.storage.update",
                None,
                "success",
                None,
                Some(json!({"data_budget_bytes": budget.to_string()})),
            )?;
            Ok((StatusCode::OK, storage_json(conn, &st_for_call)?, json!({})))
        })
        .await;
    respond(&req_id, result)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionSettingsStored {
    default_report_keep_count: u32,
    default_detail_keep_count: u32,
    quarantine_auto_purge: retention::QuarantineAutoPurgePolicy,
}

fn retention_settings(conn: &rusqlite::Connection) -> AppResult<RetentionSettingsStored> {
    let Some(raw) = read_setting(conn, "retention")? else {
        return Ok(RetentionSettingsStored {
            default_report_keep_count: 30,
            default_detail_keep_count: 3,
            quarantine_auto_purge: retention::QuarantineAutoPurgePolicy {
                enabled: false,
                min_keep_days: 30,
            },
        });
    };
    serde_json::from_str(&raw).map_err(|e| internal(format!("保留策略设置数据损坏: {e}")))
}

fn validate_retention(settings: &RetentionSettingsStored) -> AppResult<()> {
    if settings.default_report_keep_count == 0 {
        return Err(AppError::new(
            ErrorCode::ValidationFailed,
            "保留策略参数不符合最小保留约束",
        ));
    }
    retention::validate_quarantine_auto_purge(&settings.quarantine_auto_purge)?;
    Ok(())
}

pub async fn get_retention_settings(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
) -> Response {
    let result = st
        .readers
        .call(|conn| {
            let settings = retention_settings(conn)?;
            Ok((
                StatusCode::OK,
                serde_json::to_value(settings)
                    .map_err(|e| internal(format!("序列化保留策略失败: {e}")))?,
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

pub async fn put_retention_settings(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    ApiJson(body): ApiJson<RetentionSettingsStored>,
) -> Response {
    let result = st
        .writer
        .call(move |conn| {
            validate_retention(&body)?;
            write_setting(
                conn,
                "retention",
                &serde_json::to_value(&body)
                    .map_err(|e| internal(format!("序列化保留策略失败: {e}")))?,
            )?;
            audit::record(
                conn,
                &auth.session.user_id,
                "settings.retention.update",
                None,
                "success",
                None,
                Some(
                    serde_json::to_value(&body)
                        .map_err(|e| internal(format!("记录保留策略审计失败: {e}")))?,
                ),
            )?;
            Ok((
                StatusCode::OK,
                serde_json::to_value(body)
                    .map_err(|e| internal(format!("序列化保留策略失败: {e}")))?,
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

// ---- exports ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    section: ExportSection,
    format: ExportFormat,
    scope: ExportScope,
    #[serde(default)]
    query: QuerySpec,
}

/// Reopenable, bounded export source.  The iterator intentionally keeps only
/// one SQLite row and uses a keyset-like ordinal cursor for each member.  It
/// is owned by the background operation worker, never by the HTTP request.
struct SqlExportRows {
    report_id: String,
    reports_root: PathBuf,
    section: ExportSection,
    query: QuerySpec,
}

struct SqlExportIter {
    report_id: String,
    section: ExportSection,
    query: QuerySpec,
    directory_entry_id: Option<i64>,
    min_size_bytes: Option<i64>,
    max_size_bytes: Option<i64>,
    mtime_from: Option<(i64, i64)>,
    mtime_to: Option<(i64, i64)>,
    atime_from: Option<(i64, i64)>,
    atime_to: Option<(i64, i64)>,
    summary: rusqlite::Connection,
    index: Option<rusqlite::Connection>,
    offset: i64,
}

fn export_query_error(operation: &'static str, error: rusqlite::Error) -> export::ExportError {
    export::ExportError::Io {
        operation,
        source: std::io::Error::other(error.to_string()),
    }
}

fn export_app_error(operation: &'static str, error: AppError) -> export::ExportError {
    export::ExportError::Io {
        operation,
        source: std::io::Error::other(error.message),
    }
}

fn source_name_for_export(
    summary: &rusqlite::Connection,
    source_id: &str,
) -> Result<String, export::ExportError> {
    report_source_name(summary, source_id)
        .map_err(|error| export_app_error("read source name", error))
}

fn export_time(sec: Option<i64>, nsec: Option<i64>) -> Option<(i64, i64)> {
    sec.zip(nsec)
}

fn export_decimal_i64(
    value: Option<&str>,
    field: &'static str,
) -> export::ExportResult<Option<i64>> {
    value
        .map(|value| {
            value
                .parse::<i64>()
                .map_err(|_| export::ExportError::InvalidQuery {
                    field,
                    message: "超出 SQLite 可表示的有符号 64 位整数范围".into(),
                })
        })
        .transpose()
}

fn export_query_time(
    value: Option<&str>,
    field: &'static str,
) -> export::ExportResult<Option<(i64, i64)>> {
    value
        .map(|value| {
            let timestamp = value.parse::<jiff::Timestamp>().map_err(|_| {
                export::ExportError::InvalidQuery {
                    field,
                    message: "必须是 RFC3339 时间".into(),
                }
            })?;
            Ok((
                timestamp.as_second(),
                i64::from(timestamp.subsec_nanosecond()),
            ))
        })
        .transpose()
}

fn effective_export_query(scope: ExportScope, query: QuerySpec) -> export::ExportResult<QuerySpec> {
    let normalized = query.normalize()?;
    match scope {
        ExportScope::Current => Ok(normalized),
        ExportScope::All => QuerySpec::default().normalize(),
    }
}

fn unsupported_export_filter(section: ExportSection, field: &'static str) -> export::ExportError {
    export::ExportError::InvalidQuery {
        field,
        message: format!("{field} 不适用于 {} 导出栏目", section.as_str()),
    }
}

fn validate_export_query_for_section(
    section: ExportSection,
    query: &QuerySpec,
) -> export::ExportResult<()> {
    let reject = |field: &'static str| Err(unsupported_export_filter(section, field));
    match section {
        ExportSection::Files => Ok(()),
        ExportSection::Folders => {
            if !query.category_ids.is_empty() {
                return reject("category_ids");
            }
            if !query.extensions.is_empty() {
                return reject("extensions");
            }
            if !query.owner_uids.is_empty() {
                return reject("owner_uids");
            }
            if query.mtime_from.is_some() || query.mtime_to.is_some() {
                return reject("mtime_from");
            }
            if query.atime_from.is_some() || query.atime_to.is_some() {
                return reject("atime_from");
            }
            Ok(())
        }
        ExportSection::Owners => {
            if query.directory_entry_id.is_some() {
                return reject("directory_entry_id");
            }
            if !query.extensions.is_empty() {
                return reject("extensions");
            }
            if query.name_contains.is_some() {
                return reject("name_contains");
            }
            if query.min_size_bytes.is_some() || query.max_size_bytes.is_some() {
                return reject("min_size_bytes");
            }
            if query.mtime_from.is_some() || query.mtime_to.is_some() {
                return reject("mtime_from");
            }
            if query.atime_from.is_some() || query.atime_to.is_some() {
                return reject("atime_from");
            }
            Ok(())
        }
        ExportSection::Quota => {
            if query.directory_entry_id.is_some() {
                return reject("directory_entry_id");
            }
            if !query.category_ids.is_empty() {
                return reject("category_ids");
            }
            if !query.extensions.is_empty() {
                return reject("extensions");
            }
            if query.name_contains.is_some() {
                return reject("name_contains");
            }
            if query.min_size_bytes.is_some() || query.max_size_bytes.is_some() {
                return reject("min_size_bytes");
            }
            if query.mtime_from.is_some() || query.mtime_to.is_some() {
                return reject("mtime_from");
            }
            if query.atime_from.is_some() || query.atime_to.is_some() {
                return reject("atime_from");
            }
            Ok(())
        }
        ExportSection::Categories => {
            if !query.extensions.is_empty() {
                return reject("extensions");
            }
            if !query.owner_uids.is_empty() {
                return reject("owner_uids");
            }
            if query.name_contains.is_some() {
                return reject("name_contains");
            }
            if query.min_size_bytes.is_some() || query.max_size_bytes.is_some() {
                return reject("min_size_bytes");
            }
            if query.mtime_from.is_some() || query.mtime_to.is_some() {
                return reject("mtime_from");
            }
            if query.atime_from.is_some() || query.atime_to.is_some() {
                return reject("atime_from");
            }
            Ok(())
        }
        ExportSection::Volume | ExportSection::Duplicates => {
            if !query.source_ids.is_empty() {
                return reject("source_ids");
            }
            if query.directory_entry_id.is_some() {
                return reject("directory_entry_id");
            }
            if !query.category_ids.is_empty() {
                return reject("category_ids");
            }
            if !query.extensions.is_empty() {
                return reject("extensions");
            }
            if !query.owner_uids.is_empty() {
                return reject("owner_uids");
            }
            if query.name_contains.is_some() {
                return reject("name_contains");
            }
            if query.min_size_bytes.is_some() || query.max_size_bytes.is_some() {
                return reject("min_size_bytes");
            }
            if query.mtime_from.is_some() || query.mtime_to.is_some() {
                return reject("mtime_from");
            }
            if query.atime_from.is_some() || query.atime_to.is_some() {
                return reject("atime_from");
            }
            Ok(())
        }
        ExportSection::Largest | ExportSection::RecentlyModified | ExportSection::LeastAccessed => {
            if !query.extensions.is_empty() {
                return reject("extensions");
            }
            if query.directory_entry_id.is_some() {
                return reject("directory_entry_id");
            }
            Ok(())
        }
        ExportSection::FullReport => FULL_REPORT_SECTIONS
            .into_iter()
            .try_for_each(|section| validate_export_query_for_section(section, query)),
    }
}

fn export_section_needs_detail(section: ExportSection, query: &QuerySpec) -> bool {
    matches!(section, ExportSection::Files | ExportSection::FullReport)
        || (matches!(section, ExportSection::Categories) && query.directory_entry_id.is_some())
}

#[allow(clippy::too_many_arguments)]
fn export_candidate_matches(
    query: &QuerySpec,
    source_id: Option<&str>,
    display_name: Option<&str>,
    extension: Option<&str>,
    uid: Option<i64>,
    category: Option<&str>,
    size: Option<i64>,
    mtime: Option<(i64, i64)>,
    atime: Option<(i64, i64)>,
    min_size: Option<i64>,
    max_size: Option<i64>,
    mtime_from: Option<(i64, i64)>,
    mtime_to: Option<(i64, i64)>,
    atime_from: Option<(i64, i64)>,
    atime_to: Option<(i64, i64)>,
) -> export::ExportResult<bool> {
    if !query.source_ids.is_empty()
        && !source_id.is_some_and(|value| query.source_ids.iter().any(|id| id == value))
    {
        return Ok(false);
    }
    if !query.category_ids.is_empty()
        && !category.is_some_and(|value| query.category_ids.iter().any(|id| id == value))
    {
        return Ok(false);
    }
    if !query.extensions.is_empty()
        && !extension.is_some_and(|value| query.extensions.iter().any(|item| item == value))
    {
        return Ok(false);
    }
    if !query.owner_uids.is_empty() && !uid.is_some_and(|value| query.owner_uids.contains(&value)) {
        return Ok(false);
    }
    if let Some(needle) = query.name_contains.as_deref()
        && !display_name.is_some_and(|value| value.contains(needle))
    {
        return Ok(false);
    }
    if let Some(min) = min_size
        && !size.is_some_and(|value| value >= min)
    {
        return Ok(false);
    }
    if let Some(max) = max_size
        && !size.is_some_and(|value| value <= max)
    {
        return Ok(false);
    }
    if let Some(from) = mtime_from
        && !mtime.is_some_and(|value| value >= from)
    {
        return Ok(false);
    }
    if let Some(to) = mtime_to
        && !mtime.is_some_and(|value| value < to)
    {
        return Ok(false);
    }
    if let Some(from) = atime_from
        && !atime.is_some_and(|value| value >= from)
    {
        return Ok(false);
    }
    if let Some(to) = atime_to
        && !atime.is_some_and(|value| value < to)
    {
        return Ok(false);
    }
    Ok(true)
}

impl SqlExportRows {
    fn open_iterator(&self) -> export::ExportResult<SqlExportIter> {
        self.open_iterator_for(self.section)
    }

    fn open_iterator_for(&self, section: ExportSection) -> export::ExportResult<SqlExportIter> {
        validate_export_query_for_section(section, &self.query)?;
        let directory_entry_id = export_decimal_i64(
            self.query.directory_entry_id.as_deref(),
            "directory_entry_id",
        )?;
        let min_size_bytes =
            export_decimal_i64(self.query.min_size_bytes.as_deref(), "min_size_bytes")?;
        let max_size_bytes =
            export_decimal_i64(self.query.max_size_bytes.as_deref(), "max_size_bytes")?;
        let mtime_from = export_query_time(self.query.mtime_from.as_deref(), "mtime_from")?;
        let mtime_to = export_query_time(self.query.mtime_to.as_deref(), "mtime_to")?;
        let atime_from = export_query_time(self.query.atime_from.as_deref(), "atime_from")?;
        let atime_to = export_query_time(self.query.atime_to.as_deref(), "atime_to")?;
        let summary = crate::report::open_published_in_root(
            &self.reports_root,
            &self.report_id,
            "report.sqlite",
            "open report summary",
        )
        .map_err(|error| export_app_error("open report summary", error))?;
        let needs_index = export_section_needs_detail(section, &self.query);
        let index = if needs_index {
            Some(
                crate::report::open_published_in_root(
                    &self.reports_root,
                    &self.report_id,
                    "index.sqlite",
                    "open report detail",
                )
                .map_err(|error| export_app_error("open report detail", error))?,
            )
        } else {
            None
        };
        if let Some(directory_entry_id) = directory_entry_id
            && matches!(section, ExportSection::Files | ExportSection::Categories)
        {
            let database = index.as_ref().ok_or_else(|| export::ExportError::Io {
                operation: "validate export directory",
                source: std::io::Error::other("报告明细数据库未打开"),
            })?;
            let directory = database
                .query_row(
                    "SELECT 1 FROM entries WHERE entry_id = ?1 AND entry_kind = 'directory'",
                    [directory_entry_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(|error| export_query_error("validate export directory", error))?;
            if directory.is_none() {
                return Err(export::ExportError::InvalidQuery {
                    field: "directory_entry_id",
                    message: "不是报告内目录".into(),
                });
            }
        }
        Ok(SqlExportIter {
            report_id: self.report_id.clone(),
            section,
            query: self.query.clone(),
            directory_entry_id,
            min_size_bytes,
            max_size_bytes,
            mtime_from,
            mtime_to,
            atime_from,
            atime_to,
            summary,
            index,
            offset: 0,
        })
    }
}

impl export::ExportRows for SqlExportRows {
    fn open_rows(
        &self,
    ) -> export::ExportResult<Box<dyn Iterator<Item = export::ExportResult<export::ExportRow>> + '_>>
    {
        Ok(Box::new(self.open_iterator()?))
    }

    fn open_section(
        &self,
        section: ExportSection,
    ) -> export::ExportResult<Box<dyn Iterator<Item = export::ExportResult<export::ExportRow>> + '_>>
    {
        Ok(Box::new(self.open_iterator_for(section)?))
    }
}

impl Iterator for SqlExportIter {
    type Item = export::ExportResult<export::ExportRow>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let candidate = match self.next_candidate() {
                Ok(Some(candidate)) => candidate,
                Ok(None) => return None,
                Err(error) => return Some(Err(error)),
            };
            let matches = match candidate.matches(
                &self.query,
                self.min_size_bytes,
                self.max_size_bytes,
                self.mtime_from,
                self.mtime_to,
                self.atime_from,
                self.atime_to,
            ) {
                Ok(value) => value,
                Err(error) => return Some(Err(error)),
            };
            if matches {
                return Some(Ok(candidate.row));
            }
        }
    }
}

struct ExportCandidate {
    row: export::ExportRow,
    source_id: Option<String>,
    display_name: Option<String>,
    extension: Option<String>,
    uid: Option<i64>,
    category: Option<String>,
    size: Option<i64>,
    mtime: Option<(i64, i64)>,
    atime: Option<(i64, i64)>,
}

impl ExportCandidate {
    #[allow(clippy::too_many_arguments)]
    fn matches(
        &self,
        query: &QuerySpec,
        min_size: Option<i64>,
        max_size: Option<i64>,
        mtime_from: Option<(i64, i64)>,
        mtime_to: Option<(i64, i64)>,
        atime_from: Option<(i64, i64)>,
        atime_to: Option<(i64, i64)>,
    ) -> export::ExportResult<bool> {
        export_candidate_matches(
            query,
            self.source_id.as_deref(),
            self.display_name.as_deref(),
            self.extension.as_deref(),
            self.uid,
            self.category.as_deref(),
            self.size,
            self.mtime,
            self.atime,
            min_size,
            max_size,
            mtime_from,
            mtime_to,
            atime_from,
            atime_to,
        )
    }
}

impl SqlExportIter {
    fn next_candidate(&mut self) -> export::ExportResult<Option<ExportCandidate>> {
        let offset = self.offset;
        self.offset = self.offset.saturating_add(1);
        match self.section {
            ExportSection::Folders => {
                let sql = "WITH RECURSIVE subtree(entry_id) AS (
                               SELECT entry_id FROM report_folders WHERE entry_id = ?1
                               UNION ALL
                               SELECT child.entry_id
                               FROM report_folders child JOIN subtree parent
                                 ON child.parent_entry_id = parent.entry_id
                           )
                           SELECT entry_id, source_id, name, display_path,
                                  logical_bytes, allocated_estimate_bytes, quality
                           FROM report_folders
                           WHERE ?1 IS NULL
                              OR (?2 = 0 AND parent_entry_id = ?1)
                              OR (?2 = 1 AND entry_id IN (SELECT entry_id FROM subtree))
                           ORDER BY source_id, raw_relative_path LIMIT 1 OFFSET ?3";
                self.summary
                    .query_row(
                        sql,
                        params![
                            self.directory_entry_id,
                            i64::from(self.query.include_descendants),
                            offset
                        ],
                        |row| {
                            let source_id: String = row.get(1)?;
                            let name: String = row.get(2)?;
                            let path: String = row.get(3)?;
                            let logical: Option<i64> = row.get(4)?;
                            let allocated: Option<i64> = row.get(5)?;
                            let status: String = row.get(6)?;
                            let source_name = source_name_for_export(&self.summary, &source_id)
                                .map_err(|error| {
                                    rusqlite::Error::ToSqlConversionFailure(Box::new(
                                        std::io::Error::other(error.to_string()),
                                    ))
                                })?;
                            Ok(ExportCandidate {
                                row: export_row(
                                    self.report_id.as_str(),
                                    &source_name,
                                    &path,
                                    None,
                                    Some("folder"),
                                    logical,
                                    allocated,
                                    None,
                                    None,
                                    &status,
                                ),
                                source_id: Some(source_id),
                                display_name: Some(name),
                                extension: None,
                                uid: None,
                                category: None,
                                size: logical,
                                mtime: None,
                                atime: None,
                            })
                        },
                    )
                    .optional()
                    .map_err(|error| export_query_error("read folder export", error))
            }
            ExportSection::Owners => {
                if self.query.category_ids.is_empty() {
                    self.summary
                        .query_row(
                            "SELECT source_id, uid, file_count, logical_bytes
                             FROM owner_aggregates
                             ORDER BY source_id, uid LIMIT 1 OFFSET ?1",
                            [offset],
                            |row| {
                                let source_id: String = row.get(0)?;
                                let uid: Option<i64> = row.get(1)?;
                                let count: i64 = row.get(2)?;
                                let logical: Option<i64> = row.get(3)?;
                                let source_name = source_name_for_export(&self.summary, &source_id)
                                    .map_err(|error| {
                                        rusqlite::Error::ToSqlConversionFailure(Box::new(
                                            std::io::Error::other(error.to_string()),
                                        ))
                                    })?;
                                let path = match uid {
                                    Some(uid) => format!("owner/{uid}"),
                                    None => "owner/unknown".to_string(),
                                };
                                Ok(ExportCandidate {
                                    row: export_row(
                                        self.report_id.as_str(),
                                        &source_name,
                                        &path,
                                        uid,
                                        None,
                                        logical,
                                        None,
                                        None,
                                        None,
                                        &format!("{count} files"),
                                    ),
                                    source_id: Some(source_id),
                                    display_name: Some(path),
                                    extension: None,
                                    uid,
                                    category: None,
                                    size: logical,
                                    mtime: None,
                                    atime: None,
                                })
                            },
                        )
                        .optional()
                        .map_err(|error| export_query_error("read owner export", error))
                } else {
                    let marks = std::iter::repeat_n("?", self.query.category_ids.len())
                        .collect::<Vec<_>>()
                        .join(",");
                    let sql = format!(
                        "SELECT source_id, uid, category_id, file_count, logical_bytes
                         FROM owner_category_aggregates
                         WHERE category_id IN ({marks})
                         ORDER BY source_id, uid, category_id LIMIT 1 OFFSET ?"
                    );
                    let mut values = self
                        .query
                        .category_ids
                        .iter()
                        .cloned()
                        .map(rusqlite::types::Value::from)
                        .collect::<Vec<_>>();
                    values.push(offset.into());
                    self.summary
                        .query_row(&sql, rusqlite::params_from_iter(values), |row| {
                            let source_id: String = row.get(0)?;
                            let uid: Option<i64> = row.get(1)?;
                            let category: String = row.get(2)?;
                            let count: i64 = row.get(3)?;
                            let logical: Option<i64> = row.get(4)?;
                            let source_name = source_name_for_export(&self.summary, &source_id)
                                .map_err(|error| {
                                    rusqlite::Error::ToSqlConversionFailure(Box::new(
                                        std::io::Error::other(error.to_string()),
                                    ))
                                })?;
                            let path = match uid {
                                Some(uid) => format!("owner/{uid}/{category}"),
                                None => format!("owner/unknown/{category}"),
                            };
                            Ok(ExportCandidate {
                                row: export_row(
                                    self.report_id.as_str(),
                                    &source_name,
                                    &path,
                                    uid,
                                    Some(&category),
                                    logical,
                                    None,
                                    None,
                                    None,
                                    &format!("{count} files"),
                                ),
                                source_id: Some(source_id),
                                display_name: Some(path),
                                extension: None,
                                uid,
                                category: Some(category),
                                size: logical,
                                mtime: None,
                                atime: None,
                            })
                        })
                        .optional()
                        .map_err(|error| export_query_error("read owner export", error))
                }
            }
            ExportSection::Categories => {
                if let Some(directory_entry_id) = self.directory_entry_id {
                    let index = self.index.as_ref().ok_or_else(|| {
                        export::ExportError::Io {
                            operation: "read category export",
                            source: std::io::Error::other("报告明细数据库未打开"),
                        }
                    })?;
                    let mut sql = String::from(
                        "SELECT e.source_id, e.category_id, COUNT(*),
                                CASE WHEN COUNT(e.size_bytes) = COUNT(*) THEN SUM(e.size_bytes) END,
                                CASE WHEN COUNT(e.allocated_bytes_estimate) = COUNT(*)
                                     THEN SUM(e.allocated_bytes_estimate) END
                         FROM entries e
                         WHERE e.entry_kind = 'regular_file' AND e.category_id IS NOT NULL",
                    );
                    let mut values = Vec::<rusqlite::types::Value>::new();
                    if !self.query.source_ids.is_empty() {
                        let marks = std::iter::repeat_n("?", self.query.source_ids.len())
                            .collect::<Vec<_>>()
                            .join(",");
                        sql.push_str(&format!(" AND e.source_id IN ({marks})"));
                        values.extend(
                            self.query
                                .source_ids
                                .iter()
                                .cloned()
                                .map(rusqlite::types::Value::from),
                        );
                    }
                    if !self.query.category_ids.is_empty() {
                        let marks = std::iter::repeat_n("?", self.query.category_ids.len())
                            .collect::<Vec<_>>()
                            .join(",");
                        sql.push_str(&format!(" AND e.category_id IN ({marks})"));
                        values.extend(
                            self.query
                                .category_ids
                                .iter()
                                .cloned()
                                .map(rusqlite::types::Value::from),
                        );
                    }
                    if self.query.include_descendants {
                        sql.push_str(
                            " AND e.dfs_left >= (SELECT dfs_left FROM entries WHERE entry_id = ?)
                              AND e.dfs_right <= (SELECT dfs_right FROM entries WHERE entry_id = ?)",
                        );
                        values.push(directory_entry_id.into());
                        values.push(directory_entry_id.into());
                    } else {
                        sql.push_str(" AND e.parent_entry_id = ?");
                        values.push(directory_entry_id.into());
                    }
                    sql.push_str(" GROUP BY e.source_id, e.category_id ORDER BY e.source_id, e.category_id LIMIT 1 OFFSET ?");
                    values.push(offset.into());
                    index
                        .query_row(&sql, rusqlite::params_from_iter(values), |row| {
                            let source_id: String = row.get(0)?;
                            let category: String = row.get(1)?;
                            let count: i64 = row.get(2)?;
                            let logical: Option<i64> = row.get(3)?;
                            let allocated: Option<i64> = row.get(4)?;
                            let source_name = source_name_for_export(&self.summary, &source_id)
                                .map_err(|error| {
                                    rusqlite::Error::ToSqlConversionFailure(Box::new(
                                        std::io::Error::other(error.to_string()),
                                    ))
                                })?;
                            let path = format!("category/{category}");
                            Ok(ExportCandidate {
                                row: export_row(
                                    self.report_id.as_str(),
                                    &source_name,
                                    &path,
                                    None,
                                    Some(&category),
                                    logical,
                                    allocated,
                                    None,
                                    None,
                                    &format!("{count} files"),
                                ),
                                source_id: Some(source_id),
                                display_name: Some(path),
                                extension: None,
                                uid: None,
                                category: Some(category),
                                size: logical,
                                mtime: None,
                                atime: None,
                            })
                        })
                        .optional()
                        .map_err(|error| export_query_error("read category export", error))
                } else {
                    let mut sql = String::from(
                        "SELECT source_id, category_id, file_count, logical_bytes, allocated_bytes
                         FROM category_aggregates WHERE 1=1",
                    );
                    let mut values = Vec::<rusqlite::types::Value>::new();
                    if !self.query.source_ids.is_empty() {
                        let marks = std::iter::repeat_n("?", self.query.source_ids.len())
                            .collect::<Vec<_>>()
                            .join(",");
                        sql.push_str(&format!(" AND source_id IN ({marks})"));
                        values.extend(
                            self.query
                                .source_ids
                                .iter()
                                .cloned()
                                .map(rusqlite::types::Value::from),
                        );
                    }
                    if !self.query.category_ids.is_empty() {
                        let marks = std::iter::repeat_n("?", self.query.category_ids.len())
                            .collect::<Vec<_>>()
                            .join(",");
                        sql.push_str(&format!(" AND category_id IN ({marks})"));
                        values.extend(
                            self.query
                                .category_ids
                                .iter()
                                .cloned()
                                .map(rusqlite::types::Value::from),
                        );
                    }
                    sql.push_str(" ORDER BY source_id, category_id LIMIT 1 OFFSET ?");
                    values.push(offset.into());
                    self.summary
                        .query_row(&sql, rusqlite::params_from_iter(values), |row| {
                            let source_id: String = row.get(0)?;
                            let category: String = row.get(1)?;
                            let count: i64 = row.get(2)?;
                            let logical: Option<i64> = row.get(3)?;
                            let allocated: Option<i64> = row.get(4)?;
                            let source_name = source_name_for_export(&self.summary, &source_id)
                                .map_err(|error| {
                                    rusqlite::Error::ToSqlConversionFailure(Box::new(
                                        std::io::Error::other(error.to_string()),
                                    ))
                                })?;
                            let path = format!("category/{category}");
                            Ok(ExportCandidate {
                                row: export_row(
                                    self.report_id.as_str(),
                                    &source_name,
                                    &path,
                                    None,
                                    Some(&category),
                                    logical,
                                    allocated,
                                    None,
                                    None,
                                    &format!("{count} files"),
                                ),
                                source_id: Some(source_id),
                                display_name: Some(path),
                                extension: None,
                                uid: None,
                                category: Some(category),
                                size: logical,
                                mtime: None,
                                atime: None,
                            })
                        })
                        .optional()
                        .map_err(|error| export_query_error("read category export", error))
                }
            }
            ExportSection::Quota => self.summary.query_row(
                "SELECT principal_namespace, principal_uid, scope_kind, scope_id, metric, limit_state,
                        limit_bytes, used_bytes, stale FROM quota_snapshot
                 ORDER BY principal_namespace, principal_uid, scope_kind, scope_id LIMIT 1 OFFSET ?1",
                [offset],
                |row| {
                    let _namespace: String = row.get(0)?;
                    let uid: i64 = row.get(1)?;
                    let scope_kind: String = row.get(2)?;
                    let scope_id: String = row.get(3)?;
                    let metric: String = row.get(4)?;
                    let limit_state: String = row.get(5)?;
                    let limit_bytes: Option<String> = row.get(6)?;
                    let used_bytes: Option<String> = row.get(7)?;
                    let stale: i64 = row.get(8)?;
                    let path = format!("{scope_kind}/{scope_id}/{metric}");
                    let status = if stale == 0 { limit_state } else { "stale".into() };
                    let source_id = (scope_kind == "source").then_some(scope_id);
                    Ok(ExportCandidate { row: export_row_with_byte_strings(self.report_id.as_str(), "quota", &path, Some(uid), None, used_bytes.as_deref(), limit_bytes.as_deref(), None, None, &status), source_id, display_name: Some(path), extension: None, uid: Some(uid), category: None, size: None, mtime: None, atime: None })
                },
            ).optional().map_err(|error| export_query_error("read quota export", error)),
            ExportSection::Volume => self.summary.query_row(
                "SELECT volume_id, sample_time, total_bytes, used_bytes, quality
                 FROM volume_samples_snapshot ORDER BY sample_time DESC, volume_id LIMIT 1 OFFSET ?1",
                [offset],
                |row| {
                    let volume_id: String = row.get(0)?;
                    let sample_time: String = row.get(1)?;
                    let total: Option<String> = row.get(2)?;
                    let used: Option<String> = row.get(3)?;
                    let quality: String = row.get(4)?;
                    let path = format!("{volume_id}/{sample_time}");
                    Ok(ExportCandidate { row: export_row_with_byte_strings(self.report_id.as_str(), "volume", &path, None, None, used.as_deref(), total.as_deref(), None, None, &quality), source_id: None, display_name: Some(path), extension: None, uid: None, category: None, size: None, mtime: None, atime: None })
                },
            ).optional().map_err(|error| export_query_error("read volume export", error)),
            ExportSection::Duplicates => self.summary.query_row(
                "SELECT group_id, size_bytes, member_count, logical_redundancy_bytes, verification
                 FROM duplicate_groups ORDER BY logical_redundancy_bytes DESC, group_id LIMIT 1 OFFSET ?1",
                [offset],
                |row| {
                    let group_id: i64 = row.get(0)?;
                    let size: i64 = row.get(1)?;
                    let count: i64 = row.get(2)?;
                    let redundant: i64 = row.get(3)?;
                    let _verification: String = row.get(4)?;
                    let path = format!("group/{group_id}");
                    Ok(ExportCandidate { row: export_row(self.report_id.as_str(), "duplicates", &path, None, None, Some(redundant), Some(size), None, None, &format!("{count} members")), source_id: None, display_name: Some(path), extension: None, uid: None, category: None, size: None, mtime: None, atime: None })
                },
            ).optional().map_err(|error| export_query_error("read duplicate export", error)),
            ExportSection::Largest | ExportSection::RecentlyModified | ExportSection::LeastAccessed => {
                let kind = match self.section {
                    ExportSection::Largest => "largest",
                    ExportSection::RecentlyModified => "recently_modified",
                    ExportSection::LeastAccessed => "least_accessed",
                    _ => unreachable!(),
                };
                self.summary.query_row(
                    "SELECT source_id, display_name, display_path, uid, category_id, size_bytes, allocated_bytes_estimate,
                            mtime_sec, mtime_nsec, atime_sec, atime_nsec, status
                     FROM rankings WHERE kind = ?1 ORDER BY rank LIMIT 1 OFFSET ?2",
                    params![kind, offset],
                    |row| {
                        let source_id: String = row.get(0)?;
                        let source_name = source_name_for_export(&self.summary, &source_id)
                            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(error.to_string()))))?;
                        let name: String = row.get(1)?;
                        let path: String = row.get(2)?;
                        let uid: Option<i64> = row.get(3)?;
                        let category: Option<String> = row.get(4)?;
                        let size: i64 = row.get(5)?;
                        let allocated: Option<i64> = row.get(6)?;
                        let mtime = export_time(row.get(7)?, row.get(8)?);
                        let atime = export_time(row.get(9)?, row.get(10)?);
                        let status: String = row.get(11)?;
                        Ok(ExportCandidate { row: export_row(self.report_id.as_str(), &source_name, &path, uid, category.as_deref(), Some(size), allocated, mtime, atime, &status), source_id: Some(source_id), display_name: Some(name), extension: None, uid, category, size: Some(size), mtime, atime })
                    },
                ).optional().map_err(|error| export_query_error("read ranking export", error))
            }
            ExportSection::Files | ExportSection::FullReport => {
                let index = self.index.as_ref().ok_or_else(|| export::ExportError::Io { operation: "open report detail", source: std::io::Error::other("报告明细数据库未打开") })?;
                let order = match self.query.sort {
                    SortKey::SizeDesc => "e.size_bytes DESC, e.entry_id ASC",
                    SortKey::SizeAsc => "e.size_bytes ASC, e.entry_id ASC",
                    SortKey::MtimeDesc => "e.mtime_sec DESC, e.mtime_nsec DESC, e.entry_id ASC",
                    SortKey::MtimeAsc => "e.mtime_sec ASC, e.mtime_nsec ASC, e.entry_id ASC",
                    SortKey::AtimeDesc => "e.atime_sec DESC, e.atime_nsec DESC, e.entry_id ASC",
                    SortKey::AtimeAsc => "e.atime_sec ASC, e.atime_nsec ASC, e.entry_id ASC",
                    SortKey::NameAsc => "e.display_name ASC, e.entry_id ASC",
                    SortKey::CountDesc => "e.size_bytes DESC, e.entry_id ASC",
                };
                let sql = format!(
                    "SELECT e.source_id, e.display_name, e.raw_relative_path, e.uid, e.category_id,
                            e.extension, e.size_bytes, e.allocated_bytes_estimate,
                            e.mtime_sec, e.mtime_nsec, e.atime_sec, e.atime_nsec, e.scan_error
                     FROM entries e WHERE e.entry_kind = 'regular_file'
                       AND (?1 IS NULL OR (?2 = 0 AND e.parent_entry_id = ?1)
                            OR (?2 = 1 AND e.dfs_left >= (SELECT dfs_left FROM entries WHERE entry_id = ?1)
                                      AND e.dfs_right <= (SELECT dfs_right FROM entries WHERE entry_id = ?1)))
                     ORDER BY {order} LIMIT 1 OFFSET ?3"
                );
                index.query_row(
                    &sql,
                    params![self.directory_entry_id, i64::from(self.query.include_descendants), offset],
                    |row| {
                        let source_id: String = row.get(0)?;
                        let name: String = row.get(1)?;
                        let raw: Vec<u8> = row.get(2)?;
                        let uid: Option<i64> = row.get(3)?;
                        let category: Option<String> = row.get(4)?;
                        let extension: Option<String> = row.get(5)?;
                        let size: Option<i64> = row.get(6)?;
                        let allocated: Option<i64> = row.get(7)?;
                        let mtime = export_time(row.get(8)?, row.get(9)?);
                        let atime = export_time(row.get(10)?, row.get(11)?);
                        let error: Option<String> = row.get(12)?;
                        let source_name = source_name_for_export(&self.summary, &source_id)
                            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(error.to_string()))))?;
                        Ok(ExportCandidate { row: export_row(self.report_id.as_str(), &source_name, &String::from_utf8_lossy(&raw), uid, category.as_deref(), size, allocated, mtime, atime, error.as_deref().unwrap_or("present")), source_id: Some(source_id), display_name: Some(name), extension, uid, category, size, mtime, atime })
                    },
                ).optional().map_err(|error| export_query_error("read file export", error))
            }
        }
    }
}

fn export_error(error: export::ExportError) -> AppError {
    AppError::new(error.code(), error.to_string())
}

fn export_value(value: impl Into<Value>) -> Value {
    value.into()
}

#[allow(clippy::too_many_arguments)]
fn export_row(
    report_id: &str,
    source_name: &str,
    relative_path: &str,
    owner_uid: Option<i64>,
    category: Option<&str>,
    logical_bytes: Option<i64>,
    allocated_bytes: Option<i64>,
    mtime: Option<(i64, i64)>,
    atime: Option<(i64, i64)>,
    status: &str,
) -> export::ExportRow {
    export_row_with_byte_strings(
        report_id,
        source_name,
        relative_path,
        owner_uid,
        category,
        logical_bytes.map(|value| value.to_string()).as_deref(),
        allocated_bytes.map(|value| value.to_string()).as_deref(),
        mtime,
        atime,
        status,
    )
}

#[allow(clippy::too_many_arguments)]
fn export_row_with_byte_strings(
    report_id: &str,
    source_name: &str,
    relative_path: &str,
    owner_uid: Option<i64>,
    category: Option<&str>,
    logical_bytes: Option<&str>,
    allocated_bytes: Option<&str>,
    mtime: Option<(i64, i64)>,
    atime: Option<(i64, i64)>,
    status: &str,
) -> export::ExportRow {
    let mut map = serde_json::Map::new();
    map.insert("report_id".into(), export_value(report_id.to_string()));
    map.insert("source_name".into(), export_value(source_name.to_string()));
    map.insert(
        "relative_path_display".into(),
        export_value(relative_path.to_string()),
    );
    map.insert(
        "owner_uid".into(),
        owner_uid.map_or(Value::Null, |value| export_value(value.to_string())),
    );
    map.insert(
        "category".into(),
        category.map_or(Value::Null, |value| export_value(value.to_string())),
    );
    map.insert(
        "logical_size_bytes".into(),
        logical_bytes.map_or(Value::Null, |value| export_value(value.to_string())),
    );
    map.insert(
        "allocated_size_estimate_bytes".into(),
        allocated_bytes.map_or(Value::Null, |value| export_value(value.to_string())),
    );
    map.insert(
        "mtime".into(),
        mtime.map_or(Value::Null, |(sec, nsec)| {
            export_value(format!("{sec}.{nsec:09}Z"))
        }),
    );
    map.insert(
        "atime".into(),
        atime.map_or(Value::Null, |(sec, nsec)| {
            export_value(format!("{sec}.{nsec:09}Z"))
        }),
    );
    map.insert("status".into(), export_value(status.to_string()));
    export::ExportRow::from_object(map)
}

fn report_source_name(report: &rusqlite::Connection, source_id: &str) -> AppResult<String> {
    report
        .query_row(
            "SELECT source_name FROM folder_aggregates WHERE source_id = ?1 ORDER BY raw_relative_path LIMIT 1",
            [source_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| internal(format!("读取报告来源名称失败: {e}")))?
        .ok_or_else(|| internal(format!("报告缺少 source_id={source_id} 的名称快照")))
}

fn output_export_file(
    config: &crate::config::DeploymentConfig,
    export_id: &str,
    format: ExportFormat,
) -> AppResult<(PathBuf, File)> {
    let root_path = config
        .storage
        .approved_output_roots
        .first()
        .ok_or_else(|| internal("未配置导出输出根"))?;
    let root = SecureRoot::open(root_path.as_os_str()).map_err(map_fs_err)?;
    let directory = OsStr::new("nas-analyzer-exports");
    root.mkdir_all(directory, 0o700).map_err(map_fs_err)?;
    let relative = format!("nas-analyzer-exports/{export_id}.{}", format.as_str());
    let opened = root
        .open_file(
            OsStr::new(&relative),
            fssecure::OpenOptions {
                write: true,
                create: true,
                exclusive: true,
                truncate: true,
                noatime: false,
            },
        )
        .map_err(map_fs_err)?;
    Ok((root_path.join(&relative), File::from(opened.fd)))
}

fn remove_generated_export_file(
    config: &crate::config::DeploymentConfig,
    path: &StdPath,
) -> AppResult<()> {
    let root_path = config
        .storage
        .approved_output_roots
        .first()
        .ok_or_else(|| internal("未配置导出输出根"))?;
    let relative = path
        .strip_prefix(root_path)
        .map_err(|_| AppError::new(ErrorCode::PathOutsideRoot, "导出文件不在批准的输出根内"))?;
    let root = SecureRoot::open(root_path.as_os_str()).map_err(map_report_artifact_fs_err)?;
    match root.unlink_file(relative.as_os_str()) {
        Ok(()) | Err(FsSecureError::NotFound) => Ok(()),
        Err(error) => Err(map_report_artifact_fs_err(error)),
    }
}

fn hash_export_file(file: &mut File) -> AppResult<String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| AppError::from_io("定位导出文件校验起点失败", e))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| AppError::from_io("读取导出文件校验失败", e))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn open_generated_export_for_hash(
    config: &crate::config::DeploymentConfig,
    path: &StdPath,
) -> AppResult<File> {
    let root_path = config
        .storage
        .approved_output_roots
        .first()
        .ok_or_else(|| internal("未配置导出输出根"))?;
    let relative = path
        .strip_prefix(root_path)
        .map_err(|_| AppError::new(ErrorCode::PathOutsideRoot, "导出文件不在批准的输出根内"))?;
    if !is_generated_artifact(relative, "nas-analyzer-exports") {
        return Err(AppError::new(
            ErrorCode::PathOutsideRoot,
            "导出文件路径不符合应用 artifact 布局",
        ));
    }
    let root = SecureRoot::open(root_path.as_os_str()).map_err(map_fs_err)?;
    let opened = root
        .open_file(relative.as_os_str(), fssecure::OpenOptions::default())
        .map_err(map_fs_err)?;
    if opened.stat.kind != EntryKind::RegularFile {
        return Err(internal("导出目标不是普通文件"));
    }
    Ok(File::from(opened.fd))
}

pub(crate) fn run_export_job(state: &AppState, job: &jobs::Job) -> AppResult<()> {
    let params = job
        .params_json
        .as_object()
        .ok_or_else(|| internal("导出任务参数不是对象"))?;
    let export_id = params
        .get("export_id")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("导出任务缺少 export_id"))?
        .to_owned();
    let report_id = params
        .get("report_id")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("导出任务缺少 report_id"))?
        .to_owned();
    let section: ExportSection = serde_json::from_value(
        params
            .get("section")
            .cloned()
            .ok_or_else(|| internal("导出任务缺少 section"))?,
    )
    .map_err(|e| internal(format!("导出 section 无法解析: {e}")))?;
    let format: ExportFormat = serde_json::from_value(
        params
            .get("format")
            .cloned()
            .ok_or_else(|| internal("导出任务缺少 format"))?,
    )
    .map_err(|e| internal(format!("导出 format 无法解析: {e}")))?;
    let scope: ExportScope = serde_json::from_value(
        params
            .get("scope")
            .cloned()
            .ok_or_else(|| internal("导出任务缺少 scope"))?,
    )
    .map_err(|e| internal(format!("导出 scope 无法解析: {e}")))?;
    let requested_query: QuerySpec = serde_json::from_value::<QuerySpec>(
        params
            .get("query")
            .cloned()
            .ok_or_else(|| internal("导出任务缺少 query"))?,
    )
    .map_err(|e| internal(format!("导出 query 无法解析: {e}")))?;
    let query = effective_export_query(scope, requested_query).map_err(export_error)?;
    validate_export_query_for_section(section, &query).map_err(export_error)?;

    let reports_root = state.config.storage.data_dir.join("reports");
    state.writer.call_blocking({
        let report_id = report_id.clone();
        let reports_root = reports_root.clone();
        let needs_detail = export_section_needs_detail(section, &query);
        move |conn| {
            let _ = open_report_database(
                conn,
                &reports_root,
                &report_id,
                "report.sqlite",
                "打开报告摘要失败",
            )?;
            if needs_detail {
                let _ = open_report_database(
                    conn,
                    &reports_root,
                    &report_id,
                    "index.sqlite",
                    "打开报告明细失败",
                )?;
            }
            Ok(())
        }
    })?;
    let manifest = ExportManifest::new(
        report_id.clone(),
        section,
        format,
        scope,
        query.clone(),
        ExportManifestOptions::new(
            state.config.server.default_timezone_name.clone(),
            false,
            true,
        ),
    )
    .map_err(export_error)?;
    let schema = ExportSchema::new(Vec::<String>::new()).map_err(export_error)?;
    let rows = SqlExportRows {
        report_id: report_id.clone(),
        reports_root,
        section,
        query,
    };
    let (path, mut output) = output_export_file(&state.config, &export_id, format)?;
    let limits = export::ExportLimits::new(
        state.config.storage.data_budget_bytes,
        state.config.resources.max_parallel_exports as usize,
    )
    .map_err(export_error)?;
    let result = (|| {
        let stats = export::write_export_with_concurrency(
            &mut output,
            &manifest,
            &schema,
            &rows,
            limits,
            &state.export_concurrency,
        )
        .map_err(export_error)?;
        output
            .sync_all()
            .map_err(|e| AppError::from_io("同步导出文件失败", e))?;
        let size = output
            .metadata()
            .map_err(|e| AppError::from_io("读取导出文件大小失败", e))?
            .len();
        drop(output);
        let mut checksum_file = open_generated_export_for_hash(&state.config, &path)?;
        let checksum = hash_export_file(&mut checksum_file)?;
        Ok::<_, AppError>((stats, size, checksum))
    })();
    let (stats, size, checksum) = match result {
        Ok(value) => value,
        Err(error) => {
            let _ = remove_generated_export_file(&state.config, &path);
            let error_json = json!({"code": error.code.as_str(), "message": error.message});
            let job_id = job.id.clone();
            let export_id_for_db = export_id.clone();
            let _ = state.writer.call_blocking(move |conn| {
                conn.execute(
                    "UPDATE exports SET state = 'failed' WHERE id = ?1",
                    [&export_id_for_db],
                )
                .map_err(|e| AppError::from_sqlite("记录导出失败状态失败", e))?;
                jobs::job_finish(conn, &job_id, JobState::Failed, Some(&error_json)).map(|_| ())
            });
            return Err(error);
        }
    };
    let job_id = job.id.clone();
    state.writer.call_blocking(move |conn| {
        let progress = json!({
            "export_id": export_id,
            "rows": stats.rows_written.to_string(),
            "bytes": size.to_string(),
            "checksum_sha256": checksum,
        });
        conn.execute(
            "UPDATE exports SET state = 'ready', path = ?2, size_bytes = ?3,
             checksum_sha256 = ?4 WHERE id = ?1",
            params![
                export_id,
                path.to_string_lossy().to_string(),
                size.to_string(),
                progress["checksum_sha256"].as_str(),
            ],
        )
        .map_err(|e| AppError::from_sqlite("保存导出结果失败", e))?;
        jobs::job_heartbeat(conn, &job_id, &progress)?;
        jobs::append_event(conn, &job_id, "job.completed", &progress)?;
        jobs::job_finish(conn, &job_id, JobState::Succeeded, None)?;
        Ok(())
    })
}

pub(crate) fn run_backup_job(state: &AppState, job: &jobs::Job) -> AppResult<()> {
    let export_id = job
        .params_json
        .get("export_id")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("备份任务缺少 export_id"))?
        .to_owned();
    let include_secrets = match job_param_bool(job, "include_secrets") {
        Ok(value) => value,
        Err(error) => {
            discard_secret_passphrase(&export_id);
            return Err(error);
        }
    };
    let output = state
        .config
        .storage
        .data_dir
        .join("config-backups")
        .join(format!("{export_id}.zip"));
    let result = if include_secrets {
        let passphrase = take_secret_passphrase(&export_id)
            .ok_or_else(|| AppError::new(ErrorCode::Internal, "含秘密备份任务缺少临时口令"))?;
        backup::create_backup_with_secrets(&state.config.storage.data_dir, &output, passphrase)
    } else {
        backup::create_backup(&state.config.storage.data_dir, &output)
    };
    let summary = match result {
        Ok(summary) => summary,
        Err(error) => {
            let error_id = export_id.clone();
            let job_id = job.id.clone();
            let error_json = json!({"code": error.code.as_str(), "message": error.message});
            let _ = state.writer.call_blocking(move |conn| {
                conn.execute(
                    "UPDATE exports SET state = 'failed' WHERE id = ?1",
                    [&error_id],
                )
                .map_err(|e| AppError::from_sqlite("记录备份失败状态失败", e))?;
                jobs::job_finish(conn, &job_id, JobState::Failed, Some(&error_json)).map(|_| ())
            });
            return Err(error);
        }
    };
    let backup_root = SecureRoot::open(state.config.storage.data_dir.as_os_str())
        .map_err(map_report_artifact_fs_err)?;
    let backup_relative = StdPath::new("config-backups").join(format!("{export_id}.zip"));
    let opened = backup_root
        .open_file(
            backup_relative.as_os_str(),
            fssecure::OpenOptions::default(),
        )
        .map_err(map_report_artifact_fs_err)?;
    let size = u64::try_from(opened.stat.size_bytes)
        .map_err(|_| internal("读取备份大小失败: 文件大小不可表示"))?;
    let mut backup_file = File::from(opened.fd);
    let checksum = hash_export_file(&mut backup_file)?;
    let job_id = job.id.clone();
    state.writer.call_blocking(move |conn| {
        let progress = json!({
            "export_id": export_id,
            "bytes": size.to_string(),
            "checksum_sha256": checksum,
        });
        conn.execute(
            "UPDATE exports SET state = 'ready', path = ?2, size_bytes = ?3,
             checksum_sha256 = ?4 WHERE id = ?1",
            params![
                export_id,
                summary.output.to_string_lossy().to_string(),
                size.to_string(),
                progress["checksum_sha256"].as_str(),
            ],
        )
        .map_err(|e| AppError::from_sqlite("保存备份结果失败", e))?;
        jobs::job_heartbeat(conn, &job_id, &progress)?;
        jobs::append_event(conn, &job_id, "job.completed", &progress)?;
        jobs::job_finish(conn, &job_id, JobState::Succeeded, None)?;
        Ok(())
    })
}

fn export_record_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let format: String = row.get("format")?;
    let size: Option<String> = row.get("size_bytes")?;
    Ok(json!({
        "id": row.get::<_, String>("id")?,
        "report_id": row.get::<_, Option<String>>("report_id")?,
        "section": row.get::<_, String>("section")?,
        "format": format,
        "query_hash": row.get::<_, String>("query_hash")?,
        "state": row.get::<_, String>("state")?,
        "size_bytes": size,
        "expires_at": row.get::<_, String>("expires_at")?,
        "lease_count": row.get::<_, i64>("lease_count")?,
    }))
}

pub async fn create_export(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Path(report_id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ExportRequest>,
) -> Response {
    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    if matches!(
        body.section,
        ExportSection::Files | ExportSection::FullReport
    ) && let Err(error) = st.memory_budget.admit_api("export_request")
    {
        return err_response(&req_id.0, error);
    }
    let ExportRequest {
        section,
        format,
        scope,
        query,
    } = body;
    let query = match effective_export_query(scope, query).map_err(export_error) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    if let Err(error) = validate_export_query_for_section(section, &query).map_err(export_error) {
        return err_response(&req_id.0, error);
    }
    let expected_report_id = Value::String(report_id.clone());
    let expected_section = Value::String(section.as_str().to_owned());
    let expected_format = Value::String(format.as_str().to_owned());
    let expected_scope = Value::String(
        match scope {
            ExportScope::Current => "current",
            ExportScope::All => "all",
        }
        .to_owned(),
    );
    let expected_query = match serde_json::to_value(&query) {
        Ok(value) => value,
        Err(error) => {
            return err_response(
                &req_id.0,
                internal(format!("编码导出查询参数失败: {error}")),
            );
        }
    };
    let reports_root = st.config.storage.data_dir.join("reports");
    let result = st.writer.call(move |conn| {
        if let Some(job) = job_by_idempotency_key(conn, &idempotency_key)? {
            ensure_idempotent_job_request(
                &job,
                JobType::Export,
                &[
                    ("report_id", &expected_report_id),
                    ("section", &expected_section),
                    ("format", &expected_format),
                    ("scope", &expected_scope),
                    ("query", &expected_query),
                ],
            )?;
            let export_id = job_param_string(&job, "export_id")?.to_owned();
            return Ok((
                StatusCode::ACCEPTED,
                json!({"export_id": export_id, "job_id": job.id}),
                json!({}),
            ));
        }
        let manifest = ExportManifest::new(
            report_id.clone(),
            section,
            format,
            scope,
            query.clone(),
            ExportManifestOptions::new("UTC", false, true),
        ).map_err(export_error)?;
        let _ = open_report_database(
            conn,
            &reports_root,
            &report_id,
            "report.sqlite",
            "验证报告摘要失败",
        )?;
        if export_section_needs_detail(section, &query) {
            let _ = open_report_database(
                conn,
                &reports_root,
                &report_id,
                "index.sqlite",
                "验证报告明细失败",
            )?;
        }
        let export_id = uuid::Uuid::new_v4().to_string();
        let params_json = json!({
            "export_id": export_id,
            "report_id": &report_id,
            "section": section,
            "format": format,
            "scope": scope,
            "query": &query,
        });
        let tx = conn
            .transaction()
            .map_err(|e| AppError::from_sqlite("开启导出入队事务失败", e))?;
        let job = jobs::create_job(
            &tx,
            JobType::Export,
            None,
            None,
            &params_json,
            Some(&idempotency_key),
            1,
        )?;
        let now = auth::now_rfc3339();
        tx.execute(
            "INSERT INTO exports
             (id, report_id, query_hash, section, format, state, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7)",
            params![
                export_id,
                report_id,
                manifest.query_hash,
                section.as_str(),
                format.as_str(),
                auth::rfc3339_plus_hours(24),
                now,
            ],
        )
        .map_err(|e| AppError::from_sqlite("保存导出排队记录失败", e))?;
        tx.commit()
            .map_err(|e| AppError::from_sqlite("提交导出入队事务失败", e))?;
        audit::record(
            conn,
            &auth.session.user_id,
            "export.create",
            Some(&export_id),
            "queued",
            None,
            Some(json!({"report_id": report_id, "section": section.as_str(), "format": format.as_str()})),
        )?;
        Ok((StatusCode::ACCEPTED, json!({"export_id": export_id, "job_id": job.id}), json!({})))
    }).await;
    respond(&req_id, result)
}

pub async fn get_export(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let result = st.readers.call(move |conn| {
        conn.query_row("SELECT id, report_id, query_hash, section, format, state, path, size_bytes, checksum_sha256, lease_count, expires_at, created_at FROM exports WHERE id = ?1", [id], export_record_json)
            .optional().map_err(|e| internal(format!("读取导出记录失败: {e}")))?
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, "导出不存在"))
    }).await.map(|data| (StatusCode::OK, data, json!({})));
    respond(&req_id, result)
}

struct ExportLeaseStream<S> {
    inner: S,
    writer: crate::store::DbWriter,
    export_id: String,
    released: bool,
}

impl<S> ExportLeaseStream<S> {
    fn new(inner: S, writer: crate::store::DbWriter, export_id: String) -> Self {
        Self {
            inner,
            writer,
            export_id,
            released: false,
        }
    }

    fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let writer = self.writer.clone();
        let export_id = self.export_id.clone();
        tokio::spawn(async move {
            let _ = writer
                .call(move |conn| {
                    conn.execute(
                        "UPDATE exports SET lease_count = CASE WHEN lease_count > 0 THEN lease_count - 1 ELSE 0 END WHERE id = ?1",
                        [&export_id],
                    )
                    .map_err(|e| AppError::from_sqlite("释放导出下载租约失败", e))?;
                    Ok(())
                })
                .await;
        });
    }
}

impl<S> Stream for ExportLeaseStream<S>
where
    S: Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let result = Pin::new(&mut self.inner).poll_next(cx);
        if matches!(&result, Poll::Ready(None)) {
            self.release();
        }
        result
    }
}

impl<S> Drop for ExportLeaseStream<S> {
    fn drop(&mut self) {
        self.release();
    }
}

fn open_download_file(st: &AppState, stored_path: &str) -> AppResult<File> {
    let path = PathBuf::from(stored_path);
    for root_path in &st.config.storage.approved_output_roots {
        if let Ok(relative) = path.strip_prefix(root_path) {
            if !is_generated_artifact(relative, "nas-analyzer-exports") {
                continue;
            }
            let root = SecureRoot::open(root_path.as_os_str()).map_err(map_fs_err)?;
            let opened = root
                .open_file(relative.as_os_str(), fssecure::OpenOptions::default())
                .map_err(map_fs_err)?;
            if opened.stat.kind != EntryKind::RegularFile {
                return Err(internal("导出目标不是普通文件"));
            }
            return Ok(File::from(opened.fd));
        }
    }
    let data_dir = &st.config.storage.data_dir;
    if let Ok(relative) = path.strip_prefix(data_dir) {
        if !is_generated_artifact(relative, "config-backups") {
            return Err(AppError::new(
                ErrorCode::Forbidden,
                "下载文件不在应用生成的备份范围内",
            ));
        }
        let root = SecureRoot::open(data_dir.as_os_str()).map_err(map_fs_err)?;
        let opened = root
            .open_file(relative.as_os_str(), fssecure::OpenOptions::default())
            .map_err(map_fs_err)?;
        if opened.stat.kind != EntryKind::RegularFile {
            return Err(internal("备份目标不是普通文件"));
        }
        return Ok(File::from(opened.fd));
    }
    Err(AppError::new(
        ErrorCode::Forbidden,
        "导出文件不在应用批准的输出范围内",
    ))
}

fn is_generated_artifact(relative: &StdPath, directory: &str) -> bool {
    let mut components = relative.components();
    matches!(
        (components.next(), components.next(), components.next()),
        (
            Some(Component::Normal(first)),
            Some(Component::Normal(_)),
            None
        ) if first == directory
    )
}

pub async fn download_export(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let lease = st
        .writer
        .call({
            let id = id.clone();
            move |conn| {
                let row: Option<(Option<String>, String, String, String)> = conn
                    .query_row(
                        "SELECT path, state, expires_at, format FROM exports WHERE id = ?1",
                        [&id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .optional()
                    .map_err(|e| internal(format!("读取导出下载记录失败: {e}")))?;
                let Some((path, state, expires_at, format)) = row else {
                    return Err(AppError::new(ErrorCode::NotFound, "导出不存在"));
                };
                if state != "ready" {
                    return Err(AppError::new(ErrorCode::Conflict, "导出尚未就绪"));
                }
                let path = path.ok_or_else(|| internal("导出已就绪但缺少文件路径"))?;
                if expires_at
                    .parse::<jiff::Timestamp>()
                    .map_err(|_| internal("导出到期时间损坏"))?
                    <= jiff::Timestamp::now()
                {
                    return Err(AppError::new(ErrorCode::DetailExpired, "导出已过期"));
                }
                conn.execute(
                    "UPDATE exports SET lease_count = lease_count + 1 WHERE id = ?1",
                    [&id],
                )
                .map_err(|e| AppError::from_sqlite("创建导出下载租约失败", e))?;
                let extension = match format.as_str() {
                    "csv" | "json" | "html" | "zip" => format,
                    other => return Err(internal(format!("导出格式损坏: {other}"))),
                };
                Ok((path, format!("nas-export-{id}.{extension}")))
            }
        })
        .await;
    let (path, filename) = match lease {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let file = match open_download_file(&st, &path) {
        Ok(file) => file,
        Err(error) => {
            let export_id = id.clone();
            let _ = st.writer.call(move |conn| {
                conn.execute(
                    "UPDATE exports SET lease_count = CASE WHEN lease_count > 0 THEN lease_count - 1 ELSE 0 END WHERE id = ?1",
                    [&export_id],
                )
                .map_err(|e| AppError::from_sqlite("释放导出下载租约失败", e))?;
                Ok(())
            }).await;
            return err_response(&req_id.0, error);
        }
    };
    let stream = ExportLeaseStream::new(
        ReaderStream::new(tokio::fs::File::from_std(file)),
        st.writer.clone(),
        id,
    );
    let content_disposition =
        match HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
            Ok(value) => value,
            Err(_) => return err_response(&req_id.0, internal("导出文件名无效")),
        };
    let mut response = (StatusCode::OK, Body::from_stream(stream)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CONTENT_DISPOSITION, content_disposition);
    response
}

// ---- cleanup ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupPlanRequest {
    report_id: String,
    groups: Vec<CleanupGroupRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupGroupRequest {
    group_id: String,
    keep_entry_ids: Vec<String>,
    target_entry_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteCleanupRequest {
    reauth_token: String,
    confirmation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreQuarantineRequest {
    reauth_token: String,
    new_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeQuarantineRequest {
    reauth_token: String,
    confirmation: String,
}

fn parse_entry_ids(values: &[String], field: &str) -> AppResult<Vec<i64>> {
    values
        .iter()
        .map(|value| {
            value.parse::<i64>().map_err(|_| {
                AppError::new(ErrorCode::BadRequest, format!("{field} 必须是十进制整数"))
            })
        })
        .collect()
}

fn cleanup_reason(reason: cleanup::BlockedReason) -> &'static str {
    match reason {
        cleanup::BlockedReason::ProtectedFile => "protected_file",
        cleanup::BlockedReason::HardlinkNotAllowed => "hardlink_not_allowed",
        cleanup::BlockedReason::Symlink => "symlink",
        cleanup::BlockedReason::OutsideScope => "outside_scope",
        cleanup::BlockedReason::TieredPlaceholder => "tiered_placeholder",
        cleanup::BlockedReason::ActiveFile => "active_file",
        cleanup::BlockedReason::NotFound => "not_found",
        cleanup::BlockedReason::HashIncomplete => "hash_incomplete",
    }
}

fn cleanup_plan_json(plan: &cleanup::CleanupPlan) -> Value {
    json!({
        "id": plan.id,
        "report_id": plan.report_id,
        "state": plan.state,
        "action": "quarantine",
        "selected_count": plan.selected_count,
        "logical_total_bytes": plan.logical_total_bytes.to_string(),
        "blocked_entries": plan.blocked_entries.iter().map(|item| json!({"entry_id": item.entry_id.to_string(), "reason": cleanup_reason(item.reason)})).collect::<Vec<_>>(),
        "kept_entries": plan.kept_entries.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "risks": plan.risks,
        "validation_version": plan.validation_version,
        "confirmation_text": plan.confirmation_text,
        "expires_at": plan.expires_at,
        "created_at": plan.created_at,
    })
}

fn cleanup_identity_size(identity: &Value) -> rusqlite::Result<String> {
    identity
        .get("size_bytes")
        .and_then(Value::as_i64)
        .filter(|size| *size >= 0)
        .map(|size| size.to_string())
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn cleanup_journal_seq(state: &str, journal_seq: Option<i64>) -> rusqlite::Result<i64> {
    match journal_seq {
        Some(sequence) => Ok(sequence),
        None if state == "PLANNED" => Ok(0),
        None => Err(rusqlite::Error::InvalidQuery),
    }
}

type CleanupSourceContext = (
    BTreeMap<String, SecureRoot>,
    BTreeMap<String, cleanup::CleanupGate>,
    SecureRoot,
);

fn cleanup_signing_key(conn: &rusqlite::Connection) -> AppResult<Vec<u8>> {
    if let Some(raw) = read_setting(conn, "cleanup_signing_key")? {
        let encoded: String = serde_json::from_str(&raw)
            .map_err(|e| internal(format!("清理签名密钥设置损坏: {e}")))?;
        let key = hex::decode(encoded).map_err(|_| internal("清理签名密钥不是有效十六进制"))?;
        if key.is_empty() {
            return Err(internal("清理签名密钥为空"));
        }
        return Ok(key);
    }
    let key = uuid::Uuid::new_v4().as_bytes().to_vec();
    write_setting(
        conn,
        "cleanup_signing_key",
        &Value::String(hex::encode(&key)),
    )?;
    Ok(key)
}

fn join_cleanup_path(root: &[u8], entry: &[u8]) -> Vec<u8> {
    if root.is_empty() {
        entry.to_vec()
    } else if entry.is_empty() {
        root.to_vec()
    } else {
        let mut path = Vec::with_capacity(root.len() + entry.len() + 1);
        path.extend_from_slice(root);
        path.push(b'/');
        path.extend_from_slice(entry);
        path
    }
}

fn cleanup_entry_kind(value: &str) -> AppResult<EntryKind> {
    match value {
        "regular_file" => Ok(EntryKind::RegularFile),
        "directory" => Ok(EntryKind::Directory),
        "symlink" => Ok(EntryKind::Symlink),
        "fifo" => Ok(EntryKind::Fifo),
        "socket" => Ok(EntryKind::Socket),
        "block_device" => Ok(EntryKind::BlockDevice),
        "char_device" => Ok(EntryKind::CharDevice),
        "unknown" => Ok(EntryKind::Unknown),
        other => Err(internal(format!("报告条目类型损坏: {other}"))),
    }
}

fn cleanup_sources(
    conn: &rusqlite::Connection,
    st: &AppState,
    source_ids: &BTreeSet<String>,
) -> AppResult<CleanupSourceContext> {
    let mut roots = BTreeMap::new();
    let mut gates = BTreeMap::new();
    for source_id in source_ids {
        let (mount_key, write_enabled, protected): (String, i64, i64) = conn
            .query_row(
                "SELECT mount_key, write_enabled, protected FROM sources WHERE id = ?1 AND disabled_at IS NULL",
                [source_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|e| internal(format!("读取清理数据源失败: {e}")))?
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, "清理数据源不存在或已禁用"))?;
        let mount = st.config.mount(&mount_key).ok_or_else(|| {
            AppError::new(
                ErrorCode::SourceUnavailable,
                format!("批准挂载不存在: {mount_key}"),
            )
        })?;
        let root = SecureRoot::open(mount.container_path.as_os_str()).map_err(map_fs_err)?;
        gates.insert(
            source_id.clone(),
            cleanup::CleanupGate {
                allow_write_operations: st.config.security.allow_write_operations,
                source: cleanup::SourceCleanupGate {
                    mount_writable: mount.writable,
                    source_write_enabled: write_enabled != 0,
                    source_protected: protected != 0,
                    safe_write_capable: root.caps().supports_safe_writes(),
                },
            },
        );
        roots.insert(source_id.clone(), root);
    }
    let journal = SecureRoot::open(st.config.storage.data_dir.as_os_str()).map_err(map_fs_err)?;
    Ok((roots, gates, journal))
}

fn load_cleanup_groups(
    conn: &rusqlite::Connection,
    reports_root: &StdPath,
    report_id: &str,
    requests: &[CleanupGroupRequest],
) -> AppResult<(Vec<cleanup::CleanupGroupSelection>, BTreeSet<String>)> {
    let index = open_report_database(
        conn,
        reports_root,
        report_id,
        "index.sqlite",
        "打开清理报告明细失败",
    )?
    .0;
    let mut groups = Vec::new();
    let mut source_ids = BTreeSet::new();
    for request in requests {
        let group_id = request
            .group_id
            .parse::<i64>()
            .map_err(|_| AppError::new(ErrorCode::BadRequest, "group_id 必须是十进制整数"))?;
        let keep = parse_entry_ids(&request.keep_entry_ids, "keep_entry_ids")?;
        let targets = parse_entry_ids(&request.target_entry_ids, "target_entry_ids")?;
        let mut stmt = index
            .prepare(
                "SELECT dm.entry_id, e.source_id, e.raw_relative_path, e.entry_kind, e.device_id, e.inode_id,
                        e.nlink, e.size_bytes, e.mtime_sec, e.mtime_nsec, e.ctime_sec, e.ctime_nsec,
                        fh.sha256
                 FROM duplicate_members dm
                 JOIN entries e ON e.entry_id = dm.entry_id
                 LEFT JOIN file_hashes fh ON fh.entry_id = e.entry_id
                 WHERE dm.group_id = ?1 ORDER BY dm.entry_id",
            )
            .map_err(|e| internal(format!("准备清理重复组查询失败: {e}")))?;
        let rows = stmt
            .query_map([group_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                ))
            })
            .map_err(|e| internal(format!("读取清理重复组失败: {e}")))?;
        let mut members = Vec::new();
        for row in rows {
            let (
                entry_id,
                source_id,
                raw_path,
                kind,
                device,
                inode,
                nlink,
                size,
                mtime_sec,
                mtime_nsec,
                ctime_sec,
                ctime_nsec,
                hash,
            ) = row.map_err(|e| internal(format!("读取清理重复组行失败: {e}")))?;
            let device = device
                .ok_or_else(|| AppError::new(ErrorCode::ValidationFailed, "清理条目缺少设备身份"))?
                .parse::<u64>()
                .map_err(|_| AppError::new(ErrorCode::ValidationFailed, "清理条目设备身份损坏"))?;
            let inode = inode
                .ok_or_else(|| {
                    AppError::new(ErrorCode::ValidationFailed, "清理条目缺少 inode 身份")
                })?
                .parse::<u64>()
                .map_err(|_| {
                    AppError::new(ErrorCode::ValidationFailed, "清理条目 inode 身份损坏")
                })?;
            let nlink = nlink.ok_or_else(|| {
                AppError::new(ErrorCode::ValidationFailed, "清理条目缺少硬链接计数")
            })? as u64;
            let size = size.ok_or_else(|| {
                AppError::new(ErrorCode::ValidationFailed, "清理条目缺少文件大小")
            })?;
            let mtime = (
                mtime_sec.ok_or_else(|| internal("清理条目缺少修改时间"))?,
                mtime_nsec.ok_or_else(|| internal("清理条目缺少修改时间纳秒"))?,
            );
            let ctime = (
                ctime_sec.ok_or_else(|| internal("清理条目缺少变更时间"))?,
                ctime_nsec.ok_or_else(|| internal("清理条目缺少变更时间纳秒"))?,
            );
            let protected: i64 = conn
                .query_row(
                    "SELECT protected FROM sources WHERE id = ?1",
                    [&source_id],
                    |row| row.get(0),
                )
                .map_err(|e| internal(format!("读取清理保护状态失败: {e}")))?;
            let source_root: Vec<u8> = conn
                .query_row(
                    "SELECT raw_relative_root FROM sources WHERE id = ?1",
                    [&source_id],
                    |row| row.get(0),
                )
                .map_err(|e| internal(format!("读取清理源路径失败: {e}")))?;
            source_ids.insert(source_id.clone());
            members.push(cleanup::CleanupEntry {
                entry_id,
                source_id,
                group_id: request.group_id.clone(),
                raw_path: join_cleanup_path(&source_root, &raw_path),
                size_bytes: size,
                identity: fssecure::FileIdentity {
                    device_id: device,
                    inode_id: inode,
                },
                nlink,
                kind: cleanup_entry_kind(&kind)?,
                protected: protected != 0,
                content_sha256: hash.ok_or_else(|| {
                    AppError::new(ErrorCode::ValidationFailed, "清理条目缺少完整内容哈希")
                })?,
                mtime,
                ctime,
            });
        }
        if members.is_empty() {
            return Err(AppError::new(
                ErrorCode::NotFound,
                format!("重复组不存在: {}", request.group_id),
            ));
        }
        groups.push(cleanup::CleanupGroupSelection {
            group_id: request.group_id.clone(),
            members,
            keep_entry_ids: keep,
            target_entry_ids: targets,
        });
    }
    if groups.is_empty() {
        return Err(AppError::new(
            ErrorCode::ValidationFailed,
            "至少需要一个清理组",
        ));
    }
    Ok((groups, source_ids))
}

pub async fn create_cleanup_plan(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    ApiJson(body): ApiJson<CleanupPlanRequest>,
) -> Response {
    let st_for_call = st.clone();
    let reports_root = st.config.storage.data_dir.join("reports");
    let result = st
        .writer
        .call(move |conn| {
            let (groups, source_ids) =
                load_cleanup_groups(conn, &reports_root, &body.report_id, &body.groups)?;
            let (roots, _gates, journal) = cleanup_sources(conn, &st_for_call, &source_ids)?;
            let source_roots = roots
                .iter()
                .map(|(id, root)| (id.clone(), root))
                .collect::<BTreeMap<_, _>>();
            let roots_ref = cleanup::CleanupRoots {
                source_roots,
                journal_root: &journal,
            };
            let key = cleanup_signing_key(conn)?;
            let plan = cleanup::preview(
                conn,
                &body.report_id,
                &auth.session.user_id,
                &groups,
                &roots_ref,
                &key,
            )?;
            audit::record(
                conn,
                &auth.session.user_id,
                "cleanup.preview",
                Some(&plan.id),
                "success",
                None,
                Some(json!({"report_id": body.report_id})),
            )?;
            Ok((StatusCode::OK, cleanup_plan_json(&plan), json!({})))
        })
        .await;
    respond(&req_id, result)
}

pub async fn execute_cleanup_plan(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Path(plan_id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ExecuteCleanupRequest>,
) -> Response {
    let Some(idempotency_key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
    else {
        return err_response(
            &req_id.0,
            AppError::new(
                ErrorCode::BadRequest,
                "执行清理必须携带有效的 Idempotency-Key",
            ),
        );
    };
    let actor_id = auth.session.user_id.clone();
    let result = st
        .writer
        .call(move |conn| {
            let expected_plan_id = Value::String(plan_id.clone());
            let expected_action = Value::String("quarantine".to_string());
            if let Some(job) = job_by_idempotency_key(conn, &idempotency_key)? {
                ensure_idempotent_job_request(
                    &job,
                    JobType::CleanupAction,
                    &[("plan_id", &expected_plan_id), ("action", &expected_action)],
                )?;
                let action_id = job_param_string(&job, "action_id")?;
                return Ok((
                    StatusCode::ACCEPTED,
                    json!({"action_id": action_id, "job_id": job.id}),
                    json!({}),
                ));
            }
            let key = cleanup_signing_key(conn)?;
            let reservation = cleanup::reserve_quarantine(
                conn,
                &plan_id,
                &actor_id,
                &body.reauth_token,
                &body.confirmation,
                &idempotency_key,
                &key,
            )?;
            audit::record(
                conn,
                &actor_id,
                "cleanup.execute",
                Some(&reservation.action_id),
                "queued",
                None,
                None,
            )?;
            Ok((
                StatusCode::ACCEPTED,
                json!({"action_id": reservation.action_id, "job_id": reservation.job_id}),
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
pub struct ActionQuery {
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn get_cleanup_action(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Path(action_id): Path<String>,
    Query(q): Query<ActionQuery>,
) -> Response {
    let limit = page_size(q.page_size);
    let cursor = match q.cursor.as_deref() {
        Some(value) => match decode_opaque_cursor(value) {
            Ok(value) => Some(value),
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let result = st.readers.call(move |conn| {
        let (plan_id, job_id, state): (String, String, String) = conn
            .query_row(
                "SELECT plan_id,
                        (SELECT id FROM jobs WHERE json_extract(params_json, '$.action_id') = ?1),
                        (SELECT state FROM jobs WHERE json_extract(params_json, '$.action_id') = ?1)
                 FROM cleanup_items WHERE action_id = ?1 LIMIT 1",
                [&action_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|e| internal(format!("读取清理动作失败: {e}")))?
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, "清理动作不存在"))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, entry_ref, raw_original_path, raw_quarantine_path, state, journal_seq, error
                 FROM cleanup_items
                 WHERE action_id = ?1 AND (?2 IS NULL OR id > ?2)
                 ORDER BY id LIMIT ?3",
            )
            .map_err(|e| internal(format!("准备清理动作条目查询失败: {e}")))?;
        let rows = stmt
            .query_map(
                rusqlite::params![action_id, cursor, limit as i64 + 1],
                |row| {
                let original: Vec<u8> = row.get(2)?;
                let quarantine: Option<Vec<u8>> = row.get(3)?;
                let state: String = row.get(4)?;
                let journal_seq = cleanup_journal_seq(&state, row.get(5)?)?;
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "entry_id": row.get::<_, String>(1)?,
                    "original_display_path": String::from_utf8_lossy(&original),
                    "quarantine_display_path": quarantine.map(|path| String::from_utf8_lossy(&path).into_owned()),
                    "state": state,
                    "journal_seq": journal_seq,
                    "error": row.get::<_, Option<String>>(6)?,
                }))
                },
            )
            .map_err(|e| internal(format!("读取清理动作条目失败: {e}")))?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row.map_err(|e| internal(format!("读取清理动作条目行失败: {e}")))?);
        }
        let next_cursor = if items.len() > limit {
            let last = items.pop().ok_or_else(|| internal("清理动作分页结果为空"))?;
            let id = last["id"]
                .as_str()
                .ok_or_else(|| internal("清理动作条目 ID 损坏"))?;
            Some(encode_opaque_cursor(id))
        } else {
            None
        };
        let count = items.len();
        let truncated = next_cursor.is_some();
        Ok((
            json!({"id": action_id, "plan_id": plan_id, "job_id": job_id, "state": state.to_ascii_lowercase(), "items": items}),
            next_cursor,
            count,
            truncated,
        ))
    })
    .await;
    match result {
        Ok((data, next_cursor, count, truncated)) => ok_response(
            &req_id.0,
            StatusCode::OK,
            data,
            list_meta(next_cursor, count, None, truncated),
        ),
        Err(error) => err_response(&req_id.0, error),
    }
}

#[derive(Debug, Deserialize)]
pub struct QuarantineQuery {
    source_id: Option<String>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn list_quarantine(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Query(q): Query<QuarantineQuery>,
) -> Response {
    let limit = page_size(q.page_size);
    let cursor = match q.cursor.as_deref() {
        Some(value) => match decode_opaque_cursor(value) {
            Ok(value) => {
                let Some((updated_at, id)) = value.split_once('|') else {
                    return err_response(
                        &req_id.0,
                        AppError::new(ErrorCode::BadRequest, "分页游标无效"),
                    );
                };
                Some((updated_at.to_owned(), id.to_owned()))
            }
            Err(error) => return err_response(&req_id.0, error),
        },
        None => None,
    };
    let result = st.readers.call(move |conn| {
        let mut stmt = conn
            .prepare(
                "SELECT id, action_id, plan_id, source_id, raw_original_path, raw_quarantine_path,
                        identity_json, state, updated_at
                 FROM cleanup_items
                 WHERE state = 'QUARANTINED' AND (?1 IS NULL OR source_id = ?1)
                   AND (?2 IS NULL OR updated_at < ?2 OR (updated_at = ?2 AND id < ?3))
                 ORDER BY updated_at DESC, id DESC LIMIT ?4",
            )
            .map_err(|e| internal(format!("准备隔离区查询失败: {e}")))?;
        let (cursor_updated, cursor_id) = cursor
            .map(|(updated_at, id)| (Some(updated_at), Some(id)))
            .unwrap_or((None, None));
        let rows = stmt
            .query_map(
                rusqlite::params![q.source_id, cursor_updated, cursor_id, limit as i64 + 1],
                |row| {
                let original: Vec<u8> = row.get(4)?;
                let quarantine: Option<Vec<u8>> = row.get(5)?;
                let identity_raw: String = row.get(6)?;
                let identity: Value = serde_json::from_str(&identity_raw)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let size_bytes = cleanup_identity_size(&identity)?;
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "action_id": row.get::<_, String>(1)?,
                    "plan_id": row.get::<_, String>(2)?,
                    "source_id": row.get::<_, String>(3)?,
                    "original_display_path": String::from_utf8_lossy(&original),
                    "quarantine_display_path": quarantine.map(|path| String::from_utf8_lossy(&path).into_owned()),
                    "size_bytes": size_bytes,
                    "state": row.get::<_, String>(7)?,
                    "risks": ["已隔离，尚未释放磁盘空间"],
                    "surviving_copies": Value::Null,
                    "space_released": false,
                    "quarantined_at": row.get::<_, String>(8)?,
                }))
                },
            )
            .map_err(|e| internal(format!("读取隔离区失败: {e}")))?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row.map_err(|e| internal(format!("读取隔离区行失败: {e}")))?);
        }
        let next_cursor = if items.len() > limit {
            let last = items.pop().ok_or_else(|| internal("隔离区分页结果为空"))?;
            let id = last["id"]
                .as_str()
                .ok_or_else(|| internal("隔离项 ID 损坏"))?;
            let updated_at = last["quarantined_at"]
                .as_str()
                .ok_or_else(|| internal("隔离项时间字段损坏"))?;
            Some(encode_opaque_cursor(&format!("{updated_at}|{id}")))
        } else {
            None
        };
        Ok((items, next_cursor))
    })
    .await;
    match result {
        Ok((items, next_cursor)) => {
            let count = items.len();
            let truncated = next_cursor.is_some();
            ok_response(
                &req_id.0,
                StatusCode::OK,
                json!(items),
                list_meta(next_cursor, count, None, truncated),
            )
        }
        Err(error) => err_response(&req_id.0, error),
    }
}

pub async fn restore_quarantine_item(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Path(item_id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RestoreQuarantineRequest>,
) -> Response {
    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let actor_id = auth.session.user_id.clone();
    let reauth_token = body.reauth_token.clone();
    let new_name = body.new_name.clone();
    let result = st
        .writer
        .call(move |conn| {
            let reservation = cleanup::reserve_restore(
                conn,
                &item_id,
                &actor_id,
                &reauth_token,
                new_name.as_deref().map(str::as_bytes),
                &idempotency_key,
            )?;
            audit::record(
                conn,
                &actor_id,
                "cleanup.restore",
                Some(&item_id),
                "queued",
                None,
                None,
            )?;
            Ok((
                StatusCode::ACCEPTED,
                json!({"job_id": reservation.job_id}),
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

pub async fn purge_quarantine_item(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    Path(item_id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PurgeQuarantineRequest>,
) -> Response {
    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let actor_id = auth.session.user_id.clone();
    let result = st
        .writer
        .call(move |conn| {
            let expected_item_id = Value::String(item_id.clone());
            let expected_action = Value::String("purge".to_string());
            if let Some(job) = job_by_idempotency_key(conn, &idempotency_key)? {
                ensure_idempotent_job_request(
                    &job,
                    JobType::CleanupAction,
                    &[("item_id", &expected_item_id), ("action", &expected_action)],
                )?;
                return Ok((StatusCode::ACCEPTED, json!({"job_id": job.id}), json!({})));
            }
            let reservation = cleanup::reserve_purge(
                conn,
                &item_id,
                &actor_id,
                &body.reauth_token,
                &body.confirmation,
                &idempotency_key,
            )?;
            audit::record(
                conn,
                &actor_id,
                "cleanup.purge",
                Some(&item_id),
                "queued",
                None,
                None,
            )?;
            Ok((
                StatusCode::ACCEPTED,
                json!({"job_id": reservation.job_id}),
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

// ---- metadata import, backup/restore, diagnostics and audit ----

pub async fn preview_metadata_import(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    ApiJson(body): ApiJson<Value>,
) -> Response {
    let result = st
        .writer
        .call(move |conn| {
            let bytes = serde_json::to_vec(&body)
                .map_err(|e| internal(format!("编码元数据导入失败: {e}")))?;
            let preview = metadata_import::preview_import(
                conn,
                &bytes,
                metadata_import::DEFAULT_MAX_IMPORT_BYTES,
            )?;
            Ok((
                StatusCode::OK,
                metadata_import_preview_json(&preview),
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

fn metadata_import_preview_json(preview: &metadata_import::ImportPreview) -> Value {
    json!({
        "preview_id": preview.preview_id,
        "digest": preview.digest,
        "valid": true,
        "schema_errors": preview.errors.iter().map(|item| &item.message).collect::<Vec<_>>(),
        "scope_warnings": preview.warnings.iter().map(|item| &item.message).collect::<Vec<_>>(),
        "counts": preview.counts,
        "diff_summary": preview.diff_summary,
        "expires_at": auth::rfc3339_plus_minutes(5),
    })
}

#[cfg(test)]
mod metadata_import_response_tests {
    use super::*;

    #[test]
    fn preview_response_keeps_the_computed_diff_summary() {
        let preview = metadata_import::ImportPreview {
            preview_id: "preview-1".to_owned(),
            digest: "digest-1".to_owned(),
            counts: metadata_import::ImportCounts {
                identities: 2,
                links: 1,
                quotas: 3,
            },
            diff_summary: metadata_import::ImportDiffSummary {
                identities_added: 1,
                identities_updated: 1,
                quotas_added: 2,
                quotas_updated: 1,
            },
            warnings: Vec::new(),
            errors: Vec::new(),
        };

        assert_eq!(
            metadata_import_preview_json(&preview)["diff_summary"],
            json!({
                "identities_added": 1,
                "identities_updated": 1,
                "quotas_added": 2,
                "quotas_updated": 1,
            })
        );
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyMetadataImportRequest {
    preview_id: String,
    digest: String,
    confirmation: String,
}

pub async fn apply_metadata_import(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    ApiJson(body): ApiJson<ApplyMetadataImportRequest>,
) -> Response {
    let result = st
        .writer
        .call(move |conn| {
            if body.confirmation.is_empty() {
                return Err(AppError::new(
                    ErrorCode::ValidationFailed,
                    "导入确认文本不能为空",
                ));
            }
            let summary = metadata_import::apply_import(conn, &body.preview_id, &body.digest)?;
            audit::record(
                conn,
                &auth.session.user_id,
                "metadata.import.apply",
                Some(&body.preview_id),
                "success",
                None,
                Some(json!({"confirmation": body.confirmation})),
            )?;
            Ok((
                StatusCode::OK,
                json!({
                    "applied": true,
                    "import_id": summary.import_id,
                    "identities_applied": summary.identities_upserted,
                    "source_links_applied": summary.links_applied,
                    "quotas_applied": summary.quotas_inserted,
                    "notes": summary.notes,
                }),
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRequest {
    #[serde(default)]
    include_secrets: bool,
    secrets_passphrase: Option<String>,
}

fn backup_export_path(conn: &rusqlite::Connection, export_id: &str) -> AppResult<PathBuf> {
    let (path, state, section, expires_at): (Option<String>, String, String, String) = conn
        .query_row(
            "SELECT path, state, section, expires_at
         FROM exports WHERE id = ?1 AND format = 'zip'",
            [export_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|e| internal(format!("读取备份导出路径失败: {e}")))?
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "备份导出不存在"))?;
    if section != "config_backup" && section != "config_backup_pre_restore" {
        return Err(AppError::new(
            ErrorCode::ValidationFailed,
            "导出记录不是配置备份",
        ));
    }
    if state != "ready" {
        return Err(AppError::new(ErrorCode::Conflict, "配置备份尚未就绪"));
    }
    if expires_at
        .parse::<jiff::Timestamp>()
        .map_err(|_| internal("备份到期时间损坏"))?
        <= jiff::Timestamp::now()
    {
        return Err(AppError::new(ErrorCode::DetailExpired, "配置备份已过期"));
    }
    path.map(PathBuf::from)
        .ok_or_else(|| internal("配置备份已就绪但缺少文件路径"))
}

fn backup_job_params(export_id: &str, include_secrets: bool) -> Value {
    json!({
        "export_id": export_id,
        "include_secrets": include_secrets,
    })
}

pub async fn create_backup(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    ApiJson(body): ApiJson<BackupRequest>,
) -> Response {
    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let BackupRequest {
        include_secrets,
        secrets_passphrase,
    } = body;
    if include_secrets && secrets_passphrase.as_deref().is_none_or(str::is_empty) {
        return err_response(
            &req_id.0,
            AppError::new(ErrorCode::ValidationFailed, "含秘密备份必须提供非空口令"),
        );
    }
    if !include_secrets && secrets_passphrase.is_some() {
        return err_response(
            &req_id.0,
            AppError::new(ErrorCode::BadRequest, "不含秘密备份不能提供口令"),
        );
    }
    let result = st
        .writer
        .call(move |conn| {
            let expected_include_secrets = Value::Bool(include_secrets);
            if let Some(job) = job_by_idempotency_key(conn, &idempotency_key)? {
                ensure_idempotent_job_request(
                    &job,
                    JobType::Backup,
                    &[("include_secrets", &expected_include_secrets)],
                )?;
                let export_id = job_param_string(&job, "export_id")?;
                return Ok((
                    StatusCode::ACCEPTED,
                    json!({"job_id": job.id, "export_id": export_id}),
                    json!({}),
                ));
            }
            let export_id = uuid::Uuid::new_v4().to_string();
            let secret_passphrase = if include_secrets {
                Some(match secrets_passphrase {
                    Some(passphrase) => passphrase,
                    None => return Err(internal("含秘密备份缺少口令")),
                })
            } else {
                None
            };
            if let Some(passphrase) = secret_passphrase.as_ref() {
                register_secret_passphrase(&export_id, passphrase.clone());
            }
            let params_json = backup_job_params(&export_id, include_secrets);
            let queued = (|| -> AppResult<(StatusCode, Value, Value)> {
                let tx = conn
                    .transaction()
                    .map_err(|e| AppError::from_sqlite("开启备份入队事务失败", e))?;
                let job = jobs::create_job(
                    &tx,
                    JobType::Backup,
                    None,
                    None,
                    &params_json,
                    Some(&idempotency_key),
                    1,
                )?;
                let now = auth::now_rfc3339();
                tx.execute(
                    "INSERT INTO exports
                 (id, report_id, query_hash, section, format, state, expires_at, created_at)
                 VALUES (?1, NULL, '', 'config_backup', 'zip', 'pending', ?2, ?3)",
                    params![export_id, auth::rfc3339_plus_hours(24), now],
                )
                .map_err(|e| AppError::from_sqlite("保存备份排队记录失败", e))?;
                audit::record(
                    &tx,
                    &auth.session.user_id,
                    "backup.create",
                    Some(&export_id),
                    "queued",
                    None,
                    None,
                )?;
                tx.commit()
                    .map_err(|e| AppError::from_sqlite("提交备份入队事务失败", e))?;
                Ok((
                    StatusCode::ACCEPTED,
                    json!({"job_id": job.id, "export_id": export_id}),
                    json!({}),
                ))
            })();
            if queued.is_err() && include_secrets {
                discard_secret_passphrase(&export_id);
            }
            queued
        })
        .await;
    respond(&req_id, result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePreviewRequest {
    backup_export_id: String,
    secrets_passphrase: Option<String>,
}

fn restore_request_digest(
    actor_id: &str,
    preview_id: &str,
    confirmation: &str,
    has_secrets: bool,
) -> AppResult<String> {
    let request = serde_json::to_vec(&json!({
        "actor_id": actor_id,
        "preview_id": preview_id,
        "confirmation": confirmation,
        "has_secrets": has_secrets,
    }))
    .map_err(|e| internal(format!("编码恢复幂等请求失败: {e}")))?;
    Ok(hex::encode(Sha256::digest(request)))
}

fn existing_restore_response(
    conn: &rusqlite::Connection,
    idempotency_key: &str,
    preview_id: &str,
    request_digest: &str,
) -> AppResult<Option<Value>> {
    let existing: Option<(String, String, String)> = conn
        .query_row(
            "SELECT preview_id, request_digest, response_json
             FROM restore_operations WHERE idempotency_key = ?1",
            [idempotency_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|e| internal(format!("查询恢复幂等记录失败: {e}")))?;
    let Some((stored_preview_id, stored_digest, response_json)) = existing else {
        return Ok(None);
    };
    if stored_preview_id != preview_id || stored_digest != request_digest {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Idempotency-Key 已用于不同的恢复请求",
        ));
    }
    serde_json::from_str(&response_json)
        .map(Some)
        .map_err(|e| internal(format!("恢复幂等响应已损坏: {e}")))
}

pub async fn preview_restore(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    ApiJson(body): ApiJson<RestorePreviewRequest>,
) -> Response {
    let RestorePreviewRequest {
        backup_export_id,
        secrets_passphrase,
    } = body;
    let result = st
        .readers
        .call(move |conn| {
            let input = backup_export_path(conn, &backup_export_id)?;
            let (plan, differences) = match secrets_passphrase {
                Some(passphrase) => {
                    backup::validate_restore_scope_with_secrets(
                        &st.config.storage.data_dir,
                        &input,
                        &st.config,
                        passphrase.clone(),
                    )?;
                    backup::restore_differences_with_secrets(
                        &st.config.storage.data_dir,
                        &input,
                        conn,
                        passphrase,
                        &st.config,
                    )?
                }
                None => {
                    backup::validate_restore_scope(
                        &st.config.storage.data_dir,
                        &input,
                        &st.config,
                    )?;
                    backup::restore_differences(&st.config.storage.data_dir, &input, conn)?
                }
            };
            Ok((
                StatusCode::OK,
                json!({
                    "preview_id": backup_export_id,
                    "compatible": true,
                    "config_version": plan.schema_version,
                    "differences": differences,
                    "warnings": [],
                }),
                json!({}),
            ))
        })
        .await;
    respond(&req_id, result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyRestoreRequest {
    preview_id: String,
    reauth_token: String,
    confirmation: String,
    secrets_passphrase: Option<String>,
}

pub async fn apply_restore(
    req_id: RequestId,
    State(st): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ApplyRestoreRequest>,
) -> Response {
    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let ApplyRestoreRequest {
        preview_id,
        reauth_token,
        confirmation,
        secrets_passphrase,
    } = body;
    let request_digest = match restore_request_digest(
        &auth.session.user_id,
        &preview_id,
        &confirmation,
        secrets_passphrase.is_some(),
    ) {
        Ok(value) => value,
        Err(error) => return err_response(&req_id.0, error),
    };
    let result = st.writer.call(move |conn| {
        if let Some(response) = existing_restore_response(
            conn,
            &idempotency_key,
            &preview_id,
            &request_digest,
        )? {
            return Ok((StatusCode::OK, response, json!({})));
        }
        if confirmation.is_empty() {
            return Err(AppError::new(ErrorCode::ValidationFailed, "恢复确认文本不能为空"));
        }
        let actor = auth::consume_reauth_token(conn, &reauth_token)?;
        if actor != auth.session.user_id {
            return Err(AppError::new(ErrorCode::Forbidden, "重新认证用户不匹配"));
        }
        let input = backup_export_path(conn, &preview_id)?;
        let response = backup::restore_backup_in_connection(
            conn,
            &st.config.storage.data_dir,
            &input,
            secrets_passphrase.as_deref(),
            &st.config,
            |tx, restore| {
                let pre = restore
                    .pre_restore_backup
                    .as_ref()
                    .ok_or_else(|| internal("恢复缺少应用前备份"))?;
                let pre_id = uuid::Uuid::new_v4().to_string();
                tx.execute("INSERT INTO exports (id, report_id, query_hash, section, format, state, path, size_bytes, expires_at, created_at) VALUES (?1, NULL, '', 'config_backup_pre_restore', 'zip', 'ready', ?2, NULL, ?3, ?4)", params![pre_id, pre.to_string_lossy().to_string(), auth::rfc3339_plus_hours(24), auth::now_rfc3339()]).map_err(|e| AppError::from_sqlite("保存恢复前备份记录失败", e))?;
                let response = json!({"applied": true, "pre_restore_backup_export_id": pre_id});
                tx.execute(
                    "INSERT INTO restore_operations
                     (idempotency_key, preview_id, request_digest, response_json, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        idempotency_key,
                        preview_id,
                        request_digest,
                        response.to_string(),
                        auth::now_rfc3339(),
                    ],
                )
                .map_err(|e| AppError::from_sqlite("保存恢复幂等记录失败", e))?;
                audit::record(
                    tx,
                    &auth.session.user_id,
                    "backup.restore",
                    Some(&preview_id),
                    "success",
                    None,
                    None,
                )?;
                Ok(response)
            },
        )?;
        Ok((StatusCode::OK, response, json!({})))
    }).await;
    respond(&req_id, result)
}

pub async fn get_diagnostics(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
) -> Response {
    let st_for_call = st.clone();
    let result = st
        .readers
        .call(move |conn| {
            diagnostics::collect(
                conn,
                &st_for_call.config,
                st_for_call.kernel_safe_writes,
                &st_for_call.memory_budget,
            )
        })
        .await
        .and_then(|data| {
            serde_json::to_value(data).map_err(|e| internal(format!("编码诊断信息失败: {e}")))
        })
        .map(|data| (StatusCode::OK, data, json!({})));
    respond(&req_id, result)
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    actor_id: Option<String>,
    action: Option<String>,
    from: Option<String>,
    to: Option<String>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

pub async fn list_audit_events(
    req_id: RequestId,
    State(st): State<AppState>,
    _auth: Auth,
    Query(q): Query<AuditQuery>,
) -> Response {
    let result = st
        .readers
        .call(move |conn| {
            let filter = audit::AuditListFilter {
                actor_id: q.actor_id,
                action: q.action,
                from: q.from,
                to: q.to,
                cursor: q.cursor,
            };
            audit::list_filtered(
                conn,
                &filter,
                q.page_size.unwrap_or(DEFAULT_PAGE_SIZE as u32),
            )
        })
        .await;
    match result {
        Ok((events, cursor)) => {
            let count = events.len();
            ok_response(
                &req_id.0,
                StatusCode::OK,
                json!(events),
                list_meta(cursor, count, None, false),
            )
        }
        Err(error) => err_response(&req_id.0, error),
    }
}

// ---- unimplemented routes ----

// ---- unimplemented routes ----

// ---- unimplemented routes ----

/// Stable 404 for an API route that is not part of the implemented contract.
pub async fn not_implemented(req_id: RequestId) -> Response {
    err_response(
        &req_id.0,
        AppError::new(ErrorCode::NotFound, "该功能尚未实现"),
    )
}

#[cfg(test)]
mod cleanup_response_tests {
    use super::*;

    #[test]
    fn cleanup_sizes_are_serialized_as_decimal_strings() {
        assert_eq!(
            cleanup_identity_size(&json!({"size_bytes": 9223372036854775807i64})).unwrap(),
            "9223372036854775807"
        );
        assert!(cleanup_identity_size(&json!({"size_bytes": -1})).is_err());
        assert!(cleanup_identity_size(&json!({})).is_err());
    }

    #[test]
    fn planned_cleanup_items_have_zero_journal_sequence() {
        assert_eq!(cleanup_journal_seq("PLANNED", None).unwrap(), 0);
        assert_eq!(cleanup_journal_seq("MOVING", Some(3)).unwrap(), 3);
        assert!(cleanup_journal_seq("MOVING", None).is_err());
    }
}

#[cfg(test)]
mod export_query_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn summary_for_export() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE folder_aggregates (
                 source_id TEXT NOT NULL,
                 source_name TEXT NOT NULL,
                 raw_relative_path BLOB NOT NULL
             );
             CREATE TABLE report_folders (
                 entry_id INTEGER NOT NULL,
                 source_id TEXT NOT NULL,
                 parent_entry_id INTEGER,
                 name TEXT NOT NULL,
                 display_path TEXT NOT NULL,
                 raw_relative_path BLOB NOT NULL,
                 logical_bytes INTEGER,
                 allocated_estimate_bytes INTEGER,
                 quality TEXT NOT NULL
             );
             CREATE TABLE owner_category_aggregates (
                 source_id TEXT NOT NULL,
                 uid INTEGER,
                 category_id TEXT NOT NULL,
                 file_count INTEGER NOT NULL,
                 logical_bytes INTEGER
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO folder_aggregates(source_id, source_name, raw_relative_path)
             VALUES ('source-a', 'Source A', X'')",
            [],
        )
        .unwrap();
        conn
    }

    fn export_iterator(
        summary: rusqlite::Connection,
        index: Option<rusqlite::Connection>,
        section: ExportSection,
        query: QuerySpec,
        directory_entry_id: Option<i64>,
    ) -> SqlExportIter {
        SqlExportIter {
            report_id: "report-1".to_owned(),
            section,
            query,
            directory_entry_id,
            min_size_bytes: None,
            max_size_bytes: None,
            mtime_from: None,
            mtime_to: None,
            atime_from: None,
            atime_to: None,
            summary,
            index,
            offset: 0,
        }
    }

    fn collect_rows(iterator: SqlExportIter) -> Vec<export::ExportRow> {
        iterator.map(|row| row.unwrap()).collect()
    }

    #[test]
    fn folder_export_distinguishes_direct_children_from_descendants() {
        let summary = summary_for_export();
        for (entry_id, parent_id, name, path, bytes) in [
            (1, None, "root", "root", 100),
            (2, Some(1), "child", "root/child", 60),
            (3, Some(2), "grandchild", "root/child/grandchild", 20),
        ] {
            summary
                .execute(
                    "INSERT INTO report_folders
                     (entry_id, source_id, parent_entry_id, name, display_path,
                      raw_relative_path, logical_bytes, allocated_estimate_bytes, quality)
                     VALUES (?1, 'source-a', ?2, ?3, ?4, ?4, ?5, ?5, 'complete')",
                    rusqlite::params![entry_id, parent_id, name, path, bytes],
                )
                .unwrap();
        }

        let descendants = collect_rows(export_iterator(
            summary,
            None,
            ExportSection::Folders,
            QuerySpec {
                directory_entry_id: Some("1".into()),
                include_descendants: true,
                ..QuerySpec::default()
            },
            Some(1),
        ));
        assert_eq!(descendants.len(), 3);

        let summary = summary_for_export();
        for (entry_id, parent_id, name, path, bytes) in [
            (1, None, "root", "root", 100),
            (2, Some(1), "child", "root/child", 60),
            (3, Some(2), "grandchild", "root/child/grandchild", 20),
        ] {
            summary
                .execute(
                    "INSERT INTO report_folders
                     (entry_id, source_id, parent_entry_id, name, display_path,
                      raw_relative_path, logical_bytes, allocated_estimate_bytes, quality)
                     VALUES (?1, 'source-a', ?2, ?3, ?4, ?4, ?5, ?5, 'complete')",
                    rusqlite::params![entry_id, parent_id, name, path, bytes],
                )
                .unwrap();
        }
        let direct = collect_rows(export_iterator(
            summary,
            None,
            ExportSection::Folders,
            QuerySpec {
                directory_entry_id: Some("1".into()),
                include_descendants: false,
                ..QuerySpec::default()
            },
            Some(1),
        ));
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0].values()["relative_path_display"], "root/child");
    }

    #[test]
    fn category_export_applies_directory_scope_and_descendant_flag() {
        let make_index = || {
            let index = rusqlite::Connection::open_in_memory().unwrap();
            index
                .execute_batch(
                    "CREATE TABLE entries (
                         entry_id INTEGER PRIMARY KEY,
                         source_id TEXT NOT NULL,
                         entry_kind TEXT NOT NULL,
                         category_id TEXT,
                         size_bytes INTEGER,
                         allocated_bytes_estimate INTEGER,
                         dfs_left INTEGER NOT NULL,
                         dfs_right INTEGER NOT NULL,
                         parent_entry_id INTEGER
                     );
                     INSERT INTO entries VALUES
                       (10, 'source-a', 'directory', NULL, NULL, NULL, 1, 8, NULL),
                       (11, 'source-a', 'directory', NULL, NULL, NULL, 2, 5, 10),
                       (12, 'source-a', 'regular_file', 'documents', 5, 4, 3, 3, 10),
                       (13, 'source-a', 'regular_file', 'pictures', 6, 5, 6, 6, 10),
                       (14, 'source-a', 'regular_file', 'documents', 7, 6, 4, 4, 11);",
                )
                .unwrap();
            index
        };
        let query = QuerySpec {
            directory_entry_id: Some("10".into()),
            include_descendants: true,
            ..QuerySpec::default()
        };
        let rows = collect_rows(export_iterator(
            summary_for_export(),
            Some(make_index()),
            ExportSection::Categories,
            query,
            Some(10),
        ));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].values()["logical_size_bytes"], "12");
        assert_eq!(rows[1].values()["logical_size_bytes"], "6");

        let query = QuerySpec {
            directory_entry_id: Some("10".into()),
            include_descendants: false,
            ..QuerySpec::default()
        };
        let rows = collect_rows(export_iterator(
            summary_for_export(),
            Some(make_index()),
            ExportSection::Categories,
            query,
            Some(10),
        ));
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|row| row.values()["logical_size_bytes"] != "12")
        );
    }

    #[test]
    fn owner_category_export_keeps_one_row_per_owner_and_category() {
        let summary = summary_for_export();
        for (uid, category, count, bytes) in [
            (100, "documents", 2, 10),
            (100, "pictures", 1, 6),
            (200, "documents", 1, 4),
        ] {
            summary
                .execute(
                    "INSERT INTO owner_category_aggregates
                     (source_id, uid, category_id, file_count, logical_bytes)
                     VALUES ('source-a', ?1, ?2, ?3, ?4)",
                    rusqlite::params![uid, category, count, bytes],
                )
                .unwrap();
        }
        let rows = collect_rows(export_iterator(
            summary,
            None,
            ExportSection::Owners,
            QuerySpec {
                category_ids: vec!["documents".into(), "pictures".into()],
                ..QuerySpec::default()
            },
            None,
        ));
        assert_eq!(rows.len(), 3);
        let categories = rows
            .iter()
            .map(|row| row.values()["category"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            categories,
            BTreeSet::from(["documents".into(), "pictures".into()])
        );
    }

    #[test]
    fn quota_and_volume_exports_preserve_decimal_byte_strings() {
        let summary = summary_for_export();
        summary
            .execute_batch(
                "CREATE TABLE quota_snapshot (
                     principal_namespace TEXT NOT NULL,
                     principal_uid INTEGER NOT NULL,
                     scope_kind TEXT NOT NULL,
                     scope_id TEXT NOT NULL,
                     metric TEXT NOT NULL,
                     limit_state TEXT NOT NULL,
                     limit_bytes TEXT,
                     used_bytes TEXT,
                     stale INTEGER NOT NULL
                 );
                 INSERT INTO quota_snapshot VALUES
                   ('posix', 100, 'source', 'source-a', 'bytes', 'known',
                    '9223372036854775808', '9223372036854775809', 0);",
            )
            .unwrap();
        let rows = collect_rows(export_iterator(
            summary,
            None,
            ExportSection::Quota,
            QuerySpec::default(),
            None,
        ));
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].values()["logical_size_bytes"],
            "9223372036854775809"
        );
        assert_eq!(
            rows[0].values()["allocated_size_estimate_bytes"],
            "9223372036854775808"
        );

        let summary = summary_for_export();
        summary
            .execute_batch(
                "CREATE TABLE volume_samples_snapshot (
                     volume_id TEXT NOT NULL,
                     sample_time TEXT NOT NULL,
                     total_bytes TEXT,
                     used_bytes TEXT,
                     quality TEXT NOT NULL
                 );
                 INSERT INTO volume_samples_snapshot VALUES
                   ('volume-a', '2026-01-01T00:00:00.000Z',
                    '9223372036854775808', '9223372036854775809', 'complete');",
            )
            .unwrap();
        let rows = collect_rows(export_iterator(
            summary,
            None,
            ExportSection::Volume,
            QuerySpec::default(),
            None,
        ));
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].values()["logical_size_bytes"],
            "9223372036854775809"
        );
        assert_eq!(
            rows[0].values()["allocated_size_estimate_bytes"],
            "9223372036854775808"
        );
    }
}

#[cfg(test)]
mod backup_request_tests {
    #[cfg(target_os = "linux")]
    use std::io::Write;
    use std::time::Duration;

    use axum::http::{HeaderMap, HeaderValue, StatusCode};

    use crate::config::{
        ApprovedMount, DeploymentConfig, ResourceConfig, SamplingConfig, SecurityConfig,
        ServerConfig, StorageConfig,
    };
    use crate::store::DbWriterGuard;

    use super::*;

    fn test_deployment(data_dir: &StdPath) -> DeploymentConfig {
        DeploymentConfig {
            server: ServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                default_timezone: jiff::tz::TimeZone::UTC,
                default_timezone_name: "UTC".to_owned(),
                trusted_proxy_cidrs: Vec::new(),
                allow_insecure_lan_http: true,
            },
            storage: StorageConfig {
                data_dir: data_dir.to_path_buf(),
                approved_output_roots: vec![data_dir.join("exports")],
                data_budget_bytes: 1024 * 1024,
                hash_cache_budget_bytes: 1024 * 1024,
            },
            approved_mounts: Vec::<ApprovedMount>::new(),
            security: SecurityConfig {
                allow_write_operations: false,
                session_idle_minutes: 30,
                session_absolute_hours: 24,
                reauth_minutes: 5,
            },
            resources: ResourceConfig {
                max_running_scans: 1,
                max_queued_scans: 1,
                metadata_workers: 1,
                hash_workers: 1,
                hash_read_limit_mib_s: 1,
                max_open_files: 16,
                api_memory_budget_mib: 128,
                worker_memory_budget_mib: 128,
                max_parallel_exports: 1,
            },
            sampling: SamplingConfig {
                interval_minutes: 60,
                raw_retention_days: 30,
                daily_retention_days: 365,
            },
        }
    }

    fn test_auth(user_id: String) -> Auth {
        Auth {
            session: crate::auth::Session {
                token_hash: "test-token-hash".to_owned(),
                user_id,
                csrf_secret: "test-csrf-secret".to_owned(),
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                expires_idle_at: "2027-01-01T00:00:00Z".to_owned(),
                expires_absolute_at: "2027-01-01T00:00:00Z".to_owned(),
                last_seen_at: "2026-01-01T00:00:00Z".to_owned(),
            },
            token: "test-session-token".to_owned(),
        }
    }

    fn start_test_state() -> (tempfile::TempDir, AppState, DbWriterGuard) {
        let root = tempfile::tempdir().unwrap();
        let config = test_deployment(root.path());
        let (state, guard) = AppState::start(&config).unwrap();
        (root, state, guard)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generated_export_reopens_read_only_for_checksum() {
        let root = tempfile::tempdir().unwrap();
        let output_root = root.path().join("exports");
        std::fs::create_dir_all(&output_root).unwrap();
        let config = test_deployment(root.path());
        let (path, mut output) =
            output_export_file(&config, "checksum-regression", ExportFormat::Csv).unwrap();
        output.write_all(b"checksum payload").unwrap();
        output.sync_all().unwrap();
        drop(output);

        let mut readable = open_generated_export_for_hash(&config, &path).unwrap();
        assert_eq!(
            hash_export_file(&mut readable).unwrap(),
            "c067225cdb0af4eca591044cd6a7677107f4f5ec74d6e46c1b888d0b7c755d44"
        );
    }

    async fn backup_state(
        state: &AppState,
        export_id: &str,
        job_id: &str,
    ) -> (String, String, String) {
        state
            .readers
            .call({
                let export_id = export_id.to_owned();
                let job_id = job_id.to_owned();
                move |conn| {
                    let params_json: String = conn
                        .query_row(
                            "SELECT params_json FROM jobs WHERE id = ?1",
                            [&job_id],
                            |row| row.get(0),
                        )
                        .unwrap();
                    let audit_detail: String = conn
                        .query_row(
                            "SELECT COALESCE(redacted_detail, '') FROM audit_events
                             WHERE resource = ?1",
                            [&export_id],
                            |row| row.get(0),
                        )
                        .unwrap();
                    let export_state: String = conn
                        .query_row(
                            "SELECT state FROM exports WHERE id = ?1",
                            [&export_id],
                            |row| row.get(0),
                        )
                        .unwrap();
                    Ok((params_json, audit_detail, export_state))
                }
            })
            .await
            .unwrap()
    }

    #[test]
    fn cancelled_secret_backup_releases_the_transient_passphrase() {
        let export_id = format!("cancelled-{}", uuid::Uuid::new_v4());
        register_secret_passphrase(&export_id, "transient-secret".to_owned());
        let job = jobs::Job {
            id: "job-1".to_owned(),
            run_id: None,
            job_type: JobType::Backup,
            state: JobState::Cancelled,
            phase: None,
            profile_id: None,
            profile_version: None,
            params_json: json!({"export_id": export_id}),
            idempotency_key: None,
            retry_of: None,
            requested_at: "2026-01-01T00:00:00Z".to_owned(),
            started_at: None,
            finished_at: Some("2026-01-01T00:00:01Z".to_owned()),
            heartbeat_at: None,
            progress_json: json!({}),
            error_json: None,
        };

        discard_cancelled_secret_backup(&job).unwrap();
        assert!(take_secret_passphrase("cancelled-secret-test-never-used").is_none());
        assert!(take_secret_passphrase(job.params_json["export_id"].as_str().unwrap()).is_none());
    }

    #[test]
    fn secret_backup_job_params_exclude_the_passphrase() {
        let params = backup_job_params("export-1", true);

        assert_eq!(params["export_id"], "export-1");
        assert_eq!(params["include_secrets"], true);
        assert!(params.get("secrets_passphrase").is_none());
        assert!(!params.to_string().contains("test-secret-passphrase"));
    }

    #[test]
    fn apply_restore_request_accepts_a_secret_passphrase_without_admin_password() {
        let request: ApplyRestoreRequest = serde_json::from_value(json!({
            "preview_id": "export-1",
            "reauth_token": "reauth-1",
            "confirmation": "RESTORE",
            "secrets_passphrase": "test-secret-passphrase"
        }))
        .unwrap();

        assert_eq!(
            request.secrets_passphrase.as_deref(),
            Some("test-secret-passphrase")
        );
    }

    #[test]
    fn restore_idempotency_digest_scopes_actor_and_secret_mode_without_storing_passphrase() {
        let ordinary = restore_request_digest("admin-a", "export-1", "RESTORE", false).unwrap();
        let same = restore_request_digest("admin-a", "export-1", "RESTORE", false).unwrap();
        let other_actor = restore_request_digest("admin-b", "export-1", "RESTORE", false).unwrap();
        let secret = restore_request_digest("admin-a", "export-1", "RESTORE", true).unwrap();

        assert_eq!(ordinary, same);
        assert_ne!(ordinary, other_actor);
        assert_ne!(ordinary, secret);
        assert!(!ordinary.contains("passphrase"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn secret_backup_passphrase_is_not_persisted_by_http_enqueue() {
        let (root, state, guard) = start_test_state();
        let passphrase = "handler-secret-passphrase-unique";
        let idempotency_key = "secret-backup-persistence-test";
        let response = create_backup(
            RequestId("request-secret-backup".to_owned()),
            State(state.clone()),
            test_auth("admin".to_owned()),
            {
                let mut headers = HeaderMap::new();
                headers.insert("idempotency-key", HeaderValue::from_static(idempotency_key));
                headers
            },
            ApiJson(BackupRequest {
                include_secrets: true,
                secrets_passphrase: Some(passphrase.to_owned()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let (export_id, job_id) = state
            .readers
            .call(move |conn| {
                conn.query_row(
                    "SELECT e.id, j.id
                     FROM exports e JOIN jobs j ON json_extract(j.params_json, '$.export_id') = e.id
                     WHERE j.idempotency_key = ?1",
                    [idempotency_key],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .map_err(|error| internal(format!("读取秘密备份测试记录失败: {error}")))
            })
            .await
            .unwrap();
        let (params_json, audit_detail, export_state) =
            backup_state(&state, &export_id, &job_id).await;
        assert_eq!(export_state, "pending");
        assert!(!params_json.contains(passphrase));
        assert!(!audit_detail.contains(passphrase));
        assert!(
            !std::fs::read(root.path().join("control.sqlite"))
                .unwrap()
                .windows(passphrase.len())
                .any(|window| window == passphrase.as_bytes())
        );

        discard_secret_passphrase(&export_id);
        drop(state);
        guard.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_secret_backup_passphrase_fails_job_and_export() {
        let (_root, state, guard) = start_test_state();
        let export_id = uuid::Uuid::new_v4().to_string();
        let params_json = backup_job_params(&export_id, true);
        let job_id = state
            .writer
            .call({
                let export_id = export_id.clone();
                move |conn| {
                    let job =
                        jobs::create_job(conn, JobType::Backup, None, None, &params_json, None, 1)?;
                    conn.execute(
                        "INSERT INTO exports
                         (id, report_id, query_hash, section, format, state, expires_at, created_at)
                         VALUES (?1, NULL, '', 'config_backup', 'zip', 'pending', ?2, ?3)",
                        rusqlite::params![
                            export_id,
                            crate::auth::rfc3339_plus_hours(1),
                            crate::auth::now_rfc3339(),
                        ],
                    )
                    .map_err(|error| internal(format!("创建秘密备份测试导出失败: {error}")))?;
                    Ok(job.id)
                }
            })
            .await
            .unwrap();
        let supervisors = crate::runtime::RuntimeSupervisors::start(state.clone()).unwrap();
        let mut failed = false;
        for _ in 0..100 {
            let states = state
                .readers
                .call({
                    let export_id = export_id.clone();
                    let job_id = job_id.clone();
                    move |conn| {
                        let job_state: String = conn
                            .query_row("SELECT state FROM jobs WHERE id = ?1", [&job_id], |row| {
                                row.get(0)
                            })
                            .unwrap();
                        let export_state: String = conn
                            .query_row(
                                "SELECT state FROM exports WHERE id = ?1",
                                [&export_id],
                                |row| row.get(0),
                            )
                            .unwrap();
                        Ok((job_state, export_state))
                    }
                })
                .await
                .unwrap();
            if states == ("FAILED".to_owned(), "failed".to_owned()) {
                failed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        supervisors.shutdown();
        assert!(
            failed,
            "missing secret passphrase did not fail both records"
        );

        let params_json: String = state
            .readers
            .call(move |conn| {
                conn.query_row(
                    "SELECT params_json FROM jobs WHERE id = ?1",
                    [&job_id],
                    |row| row.get(0),
                )
                .map_err(|error| internal(format!("读取秘密备份测试任务失败: {error}")))
            })
            .await
            .unwrap();
        assert!(!params_json.contains("passphrase"));

        drop(state);
        guard.shutdown();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restore_idempotency_key_applies_configuration_once() {
        let (root, state, guard) = start_test_state();
        let admin = state
            .writer
            .call(|conn| crate::auth::create_admin(conn, "restore-admin", "a very long password"))
            .await
            .unwrap();
        let backup_path = root.path().join("config-backups/input.zip");
        backup::create_backup(root.path(), &backup_path).unwrap();
        let export_id = uuid::Uuid::new_v4().to_string();
        state
            .writer
            .call({
                let backup_path = backup_path.clone();
                let export_id = export_id.clone();
                move |conn| {
                    conn.execute(
                        "INSERT INTO exports
                         (id, report_id, query_hash, section, format, state, path, expires_at, created_at)
                         VALUES (?1, NULL, '', 'config_backup', 'zip', 'ready', ?2, ?3, ?4)",
                        rusqlite::params![
                            export_id,
                            backup_path.to_string_lossy().to_string(),
                            crate::auth::rfc3339_plus_hours(1),
                            crate::auth::now_rfc3339(),
                        ],
                    )
                    .map_err(|error| internal(format!("创建恢复幂等测试导出失败: {error}")))?;
                    Ok(())
                }
            })
            .await
            .unwrap();
        let admin_id = admin.id.clone();
        let reauth_token = state
            .writer
            .call(move |conn| crate::auth::create_reauth_token(conn, &admin_id, 5))
            .await
            .unwrap();
        let authn = test_auth(admin.id);
        let body = || {
            ApiJson(ApplyRestoreRequest {
                preview_id: export_id.clone(),
                reauth_token: reauth_token.clone(),
                confirmation: "RESTORE".to_owned(),
                secrets_passphrase: None,
            })
        };
        let headers = || {
            let mut headers = HeaderMap::new();
            headers.insert(
                "idempotency-key",
                HeaderValue::from_static("restore-once-test"),
            );
            headers
        };
        let first = apply_restore(
            RequestId("request-restore-first".to_owned()),
            State(state.clone()),
            authn.clone(),
            headers(),
            body(),
        )
        .await;
        let second = apply_restore(
            RequestId("request-restore-second".to_owned()),
            State(state.clone()),
            authn,
            headers(),
            body(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);

        let counts = state
            .readers
            .call(|conn| {
                let restore_operations: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM restore_operations
                         WHERE idempotency_key = 'restore-once-test'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let pre_restore_exports: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM exports WHERE section = 'config_backup_pre_restore'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let restore_audits: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM audit_events WHERE action = 'backup.restore'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                Ok((restore_operations, pre_restore_exports, restore_audits))
            })
            .await
            .unwrap();
        assert_eq!(counts, (1, 1, 1));

        drop(state);
        guard.shutdown();
    }
}
