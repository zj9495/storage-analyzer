//! HTTP API layer (spec 3.3, 14.1, 14.2, 17). Axum router, middleware
//! (request_id, session auth, CSRF, Origin), deployment instance lock and
//! the static SPA fallback.
//!
//! Testable entry points for integration tests:
//! - [`AppState::start`] builds the full runtime state (instance lock,
//!   migrations, control-DB writer + read pool, rate limiter) from a
//!   [`DeploymentConfig`];
//! - [`build_app`] turns that state into an Axum [`Router`]. Tests bind a
//!   `tokio::net::TcpListener` themselves and serve with
//!   `into_make_service_with_connect_info::<SocketAddr>()`.

mod handlers;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, FromRequest, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use rustix::fs::{FlockOperation, flock};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};
use tracing::Instrument;

use crate::auth::{self, RateLimiter, Session};
use crate::config::{DeploymentConfig, ServerConfig};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::export;
use crate::store::{DbReadPool, DbWriter, DbWriterGuard, migrate};

pub(crate) fn run_export_job(state: &AppState, job: &crate::jobs::Job) -> AppResult<()> {
    handlers::run_export_job(state, job)
}

pub(crate) fn run_backup_job(state: &AppState, job: &crate::jobs::Job) -> AppResult<()> {
    handlers::run_backup_job(state, job)
}

pub const SESSION_COOKIE: &str = "nas_session";
pub const CSRF_COOKIE: &str = "nas_csrf";
pub const CSRF_HEADER: &str = "x-csrf-token";
/// Default JSON body cap (spec 14.2: 限制请求体). Import/backup endpoints get
/// their own limits in later milestones.
pub const BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;
const READ_POOL_SLOTS: usize = 4;

pub(crate) fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

// ---- single-instance lock (spec 15.2) ----

/// Holds the exclusive flock on `<data_dir>/.lock` for the process lifetime.
pub struct InstanceLock {
    _file: std::fs::File,
    path: PathBuf,
}

impl InstanceLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Create `<data_dir>/.lock` and take an exclusive non-blocking flock on it.
/// A second process (or a second [`AppState`]) on the same data directory
/// fails with a clear message.
pub fn acquire_instance_lock(data_dir: &Path) -> AppResult<InstanceLock> {
    let path = data_dir.join(".lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| internal(format!("无法创建数据目录锁文件 {}: {e}", path.display())))?;
    flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
        AppError::new(
            ErrorCode::Internal,
            format!(
                "data directory is already locked by another nas-analyzer instance: {} ({e})",
                data_dir.display()
            ),
        )
    })?;
    Ok(InstanceLock { _file: file, path })
}

// ---- application state ----

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<DeploymentConfig>,
    pub writer: DbWriter,
    pub readers: Arc<DbReadPool>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Cached `initialized` flag (spec 3.3). Authoritative value lives in the
    /// control DB; the single-instance lock guarantees only this process can
    /// flip it, so the cache cannot go stale.
    pub initialized: Arc<AtomicBool>,
    /// Whether the kernel offers safe directory-relative writes (openat2).
    pub kernel_safe_writes: bool,
    pub static_dir: Option<PathBuf>,
    /// Admission control shared by all HTTP export jobs.
    pub export_concurrency: Arc<export::ExportConcurrency>,
    /// Process RSS budget monitor shared by HTTP admission, diagnostics and
    /// the active scan worker.
    pub memory_budget: Arc<crate::runtime::MemoryBudgetController>,
    /// Keeps the flock alive for the process lifetime.
    _lock: Arc<InstanceLock>,
}

impl AppState {
    /// Bring up the full runtime state for `config`: create the data dir,
    /// take the instance lock, apply control-DB migrations, spawn the writer
    /// thread and the 4-slot read pool.
    pub fn start(config: &DeploymentConfig) -> AppResult<(Self, DbWriterGuard)> {
        std::fs::create_dir_all(&config.storage.data_dir).map_err(|e| {
            internal(format!(
                "无法创建数据目录 {}: {e}",
                config.storage.data_dir.display()
            ))
        })?;
        for output_root in &config.storage.approved_output_roots {
            std::fs::create_dir_all(output_root).map_err(|e| {
                internal(format!(
                    "无法创建批准的输出目录 {}: {e}",
                    output_root.display()
                ))
            })?;
        }
        let lock = acquire_instance_lock(&config.storage.data_dir)?;
        let reports_root = config.storage.data_dir.join("reports");
        std::fs::create_dir_all(&reports_root)
            .map_err(|e| internal(format!("无法创建报告目录 {}: {e}", reports_root.display())))?;
        crate::retention::cleanup_staging(&reports_root)?;
        let db_path = config.storage.data_dir.join("control.sqlite");
        {
            let mut conn = crate::store::open_connection(&db_path, false, true)?;
            migrate::apply(&mut conn, migrate::CONTROL_MIGRATIONS)?;
            if let Err(error) =
                crate::retention::process_pending_artifact_deletions(&mut conn, &reports_root)
            {
                tracing::warn!(error = %error.message, "启动时处理报告 artifact 删除队列失败");
            }
        }
        let guard = DbWriter::spawn(&db_path, true)?;
        let writer = guard.writer.clone();
        let readers = Arc::new(DbReadPool::spawn(&db_path, READ_POOL_SLOTS)?);
        let initialized = writer.call_blocking(|c| auth::is_initialized(c))?;
        let kernel_safe_writes = fssecure::SecureRoot::open(config.storage.data_dir.as_os_str())
            .map(|r| r.caps().supports_safe_writes())
            .unwrap_or(false);
        let export_concurrency =
            export::ExportConcurrency::new(config.resources.max_parallel_exports as usize)
                .map_err(|e| internal(format!("初始化导出并发限制失败: {e}")))?;
        let memory_budget = crate::runtime::MemoryBudgetController::new(
            config.resources.api_memory_budget_mib,
            config.resources.worker_memory_budget_mib,
        )?;
        Ok((
            Self {
                config: Arc::new(config.clone()),
                writer,
                readers,
                rate_limiter: Arc::new(RateLimiter::default()),
                initialized: Arc::new(AtomicBool::new(initialized)),
                kernel_safe_writes,
                static_dir: detect_static_dir(),
                export_concurrency: Arc::new(export_concurrency),
                memory_budget: Arc::new(memory_budget),
                _lock: Arc::new(lock),
            },
            guard,
        ))
    }

    pub(crate) fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Relaxed)
    }
}

fn detect_static_dir() -> Option<PathBuf> {
    for candidate in [Path::new("/app/web"), Path::new("./web/dist")] {
        if candidate.join("index.html").is_file() {
            return Some(candidate.to_path_buf());
        }
    }
    None
}

// ---- router ----

/// Build the complete Axum router. `/health/*` sit outside the API prefix;
/// everything under `/api/v1` shares the body limit, Origin check and
/// request-id middleware; unmatched `/api/v1/*` returns the stable JSON 404
/// "该功能尚未实现" instead of fake success.
pub fn build_app(state: AppState) -> Router {
    let public = Router::new()
        .route("/setup/status", axum::routing::get(handlers::setup_status))
        .route(
            "/setup/complete",
            axum::routing::post(handlers::setup_complete),
        )
        .route("/auth/login", axum::routing::post(handlers::login));

    let authed = Router::new()
        .route("/auth/logout", axum::routing::post(handlers::logout))
        .route("/auth/me", axum::routing::get(handlers::me))
        .route("/auth/reauth", axum::routing::post(handlers::reauth))
        .route(
            "/admins",
            axum::routing::get(handlers::list_admins).post(handlers::create_admin),
        )
        .route(
            "/admins/{id}",
            axum::routing::get(handlers::get_admin)
                .patch(handlers::update_admin)
                .delete(handlers::delete_admin),
        )
        .route("/mounts", axum::routing::get(handlers::list_mounts))
        .route(
            "/mounts/{key}/directories",
            axum::routing::get(handlers::list_mount_directories),
        )
        .route(
            "/sources",
            axum::routing::get(handlers::list_sources).post(handlers::create_source),
        )
        .route(
            "/sources/{id}",
            axum::routing::get(handlers::get_source)
                .patch(handlers::update_source)
                .delete(handlers::delete_source),
        )
        .route(
            "/sources/{id}/probe",
            axum::routing::post(handlers::probe_source),
        )
        .route(
            "/sources/{id}/confirm-identity",
            axum::routing::post(handlers::confirm_source_identity),
        )
        .route(
            "/volumes",
            axum::routing::get(handlers::list_volumes).post(handlers::create_volume),
        )
        .route(
            "/volumes/{id}",
            axum::routing::get(handlers::get_volume).patch(handlers::update_volume),
        )
        .route(
            "/volumes/{id}/samples",
            axum::routing::get(handlers::list_volume_samples),
        )
        .route(
            "/notifications",
            axum::routing::get(handlers::list_internal_notifications),
        );

    let analysis = Router::new()
        .route(
            "/profiles",
            axum::routing::get(handlers::list_profiles).post(handlers::create_profile),
        )
        .route(
            "/profiles/schedule-preview",
            axum::routing::post(handlers::preview_schedule),
        )
        .route(
            "/profiles/{id}",
            axum::routing::get(handlers::get_profile)
                .patch(handlers::update_profile)
                .delete(handlers::delete_profile),
        )
        .route(
            "/profiles/{id}/clone",
            axum::routing::post(handlers::clone_profile),
        )
        .route(
            "/profiles/{id}/run",
            axum::routing::post(handlers::run_profile),
        )
        .route("/jobs", axum::routing::get(handlers::list_jobs))
        .route("/jobs/{id}", axum::routing::get(handlers::get_job))
        .route(
            "/jobs/{id}/control",
            axum::routing::post(handlers::control_job),
        )
        .route(
            "/jobs/{id}/events",
            axum::routing::get(handlers::job_events),
        )
        .route("/reports", axum::routing::get(handlers::list_reports))
        .route(
            "/reports/{id}",
            axum::routing::get(handlers::get_report).delete(handlers::delete_report),
        )
        .route(
            "/reports/{id}/pin",
            axum::routing::post(handlers::pin_report),
        )
        .route(
            "/reports/{id}/folders",
            axum::routing::get(handlers::report_folders),
        )
        .route(
            "/reports/{id}/owners",
            axum::routing::get(handlers::report_owners),
        )
        .route(
            "/reports/{id}/categories",
            axum::routing::get(handlers::report_categories),
        )
        .route(
            "/reports/{id}/files",
            axum::routing::get(handlers::report_files),
        )
        .route(
            "/reports/{id}/rankings/{kind}",
            axum::routing::get(handlers::report_rankings),
        );

    let operations = Router::new()
        .route(
            "/reports/{id}/exports",
            axum::routing::post(handlers::create_export),
        )
        .route(
            "/reports/{id}/duplicates",
            axum::routing::get(handlers::report_duplicates),
        )
        .route(
            "/reports/{id}/duplicates/{group_id}",
            axum::routing::get(handlers::report_duplicate_group),
        )
        .route(
            "/reports/{id}/compare",
            axum::routing::post(handlers::compare_reports),
        )
        .route(
            "/comparisons/{id}",
            axum::routing::get(handlers::get_comparison),
        )
        .route("/exports/{id}", axum::routing::get(handlers::get_export))
        .route(
            "/exports/{id}/download",
            axum::routing::get(handlers::download_export),
        )
        .route(
            "/cleanup/plans",
            axum::routing::post(handlers::create_cleanup_plan),
        )
        .route(
            "/cleanup/plans/{id}/execute",
            axum::routing::post(handlers::execute_cleanup_plan),
        )
        .route(
            "/cleanup/actions/{id}",
            axum::routing::get(handlers::get_cleanup_action),
        )
        .route(
            "/cleanup/quarantine",
            axum::routing::get(handlers::list_quarantine),
        )
        .route(
            "/cleanup/quarantine/{id}/restore",
            axum::routing::post(handlers::restore_quarantine_item),
        )
        .route(
            "/cleanup/quarantine/{id}/purge",
            axum::routing::post(handlers::purge_quarantine_item),
        )
        .route(
            "/settings/categories",
            axum::routing::get(handlers::get_category_rules).put(handlers::put_category_rules),
        )
        .route(
            "/settings/notifications",
            axum::routing::get(handlers::get_notification_settings)
                .put(handlers::put_notification_settings),
        )
        .route(
            "/settings/notifications/test",
            axum::routing::post(handlers::test_notification),
        )
        .route(
            "/settings/storage",
            axum::routing::get(handlers::get_storage_settings).put(handlers::put_storage_settings),
        )
        .route(
            "/settings/retention",
            axum::routing::get(handlers::get_retention_settings)
                .put(handlers::put_retention_settings),
        )
        .route(
            "/metadata/import/preview",
            axum::routing::post(handlers::preview_metadata_import),
        )
        .route(
            "/metadata/import/apply",
            axum::routing::post(handlers::apply_metadata_import),
        )
        .route(
            "/settings/backup",
            axum::routing::post(handlers::create_backup),
        )
        .route(
            "/settings/restore/preview",
            axum::routing::post(handlers::preview_restore),
        )
        .route(
            "/settings/restore/apply",
            axum::routing::post(handlers::apply_restore),
        )
        .route(
            "/diagnostics",
            axum::routing::get(handlers::get_diagnostics),
        )
        .route("/audit", axum::routing::get(handlers::list_audit_events));

    let api = public
        .merge(authed.merge(analysis).merge(operations))
        .fallback(handlers::not_implemented)
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .layer(middleware::from_fn_with_state(state.clone(), origin_guard));

    Router::new()
        .route("/health/live", axum::routing::get(handlers::health_live))
        .route("/health/ready", axum::routing::get(handlers::health_ready))
        .nest("/api/v1", api)
        .fallback(spa_fallback)
        .layer(middleware::from_fn(request_id_layer))
        .with_state(state)
}

// ---- request id ----

/// Per-request UUID, inserted by [`request_id_layer`] and echoed in every
/// response envelope and the `x-request-id` header.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

impl FromRequestParts<AppState> for RequestId {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<RequestId>()
            .cloned()
            .unwrap_or_else(|| RequestId(uuid::Uuid::new_v4().to_string())))
    }
}

async fn request_id_layer(mut req: Request, next: Next) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    req.extensions_mut().insert(RequestId(id.clone()));
    let span = tracing::info_span!(
        "http_request",
        request_id = %id,
        method = %req.method(),
        path = %req.uri().path(),
    );
    let mut resp = next.run(req).instrument(span).await;
    if let Ok(v) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

// ---- origin guard (spec 14.1: Origin 校验, CORS 默认关闭) ----

async fn origin_guard(State(_st): State<AppState>, req: Request, next: Next) -> Response {
    if !is_mutating(req.method()) {
        return next.run(req).await;
    }
    let Some(origin) = req.headers().get(header::ORIGIN).and_then(to_str) else {
        let req_id = request_id_of(req.extensions().get::<RequestId>());
        return err_response(
            &req_id,
            AppError::new(ErrorCode::Forbidden, "修改请求必须携带 Origin"),
        );
    };
    let Some(host) = req.headers().get(header::HOST).and_then(to_str) else {
        let req_id = request_id_of(req.extensions().get::<RequestId>());
        return err_response(
            &req_id,
            AppError::new(ErrorCode::Forbidden, "修改请求缺少 Host"),
        );
    };
    if !origin_matches_host(origin, host) {
        let req_id = request_id_of(req.extensions().get::<RequestId>());
        return err_response(
            &req_id,
            AppError::new(
                ErrorCode::Forbidden,
                "Origin 与请求 Host 不匹配，已拒绝跨站修改请求",
            ),
        );
    }
    next.run(req).await
}

fn origin_matches_host(origin: &str, host: &str) -> bool {
    let Some(rest) = origin.split_once("://").map(|(_, r)| r) else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    !authority.is_empty() && !host.is_empty() && authority.eq_ignore_ascii_case(host)
}

#[cfg(test)]
mod origin_tests {
    use super::origin_matches_host;

    #[test]
    fn origin_must_match_host_authority() {
        assert!(origin_matches_host("http://example.test", "example.test"));
        assert!(origin_matches_host(
            "https://EXAMPLE.TEST/path",
            "example.test"
        ));
        assert!(!origin_matches_host("https://other.test", "example.test"));
        assert!(!origin_matches_host("example.test", "example.test"));
        assert!(!origin_matches_host(
            "http://example.test:443",
            "example.test"
        ));
    }
}

// ---- session auth + CSRF extractor (spec 3.3, 14.1) ----

/// Authenticated request context. Extracting it enforces, in order:
/// SETUP_REQUIRED (503) before initialization, session presence and validity
/// (401), and — for mutating methods — the X-CSRF-Token header matching the
/// session's CSRF secret (403).
#[derive(Debug, Clone)]
pub struct Auth {
    pub session: Session,
    /// Plaintext session token from the cookie (needed by logout to revoke).
    pub token: String,
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let req_id = request_id_of(parts.extensions.get::<RequestId>());
        if !state.is_initialized() {
            return Err(err_response(
                &req_id,
                AppError::new(ErrorCode::SetupRequired, "系统尚未完成初始化"),
            ));
        }
        let Some(token) = cookie_value(&parts.headers, SESSION_COOKIE) else {
            return Err(err_response(
                &req_id,
                AppError::new(ErrorCode::Unauthorized, "未登录或会话已失效"),
            ));
        };
        let lookup_token = token.clone();
        let session = state
            .writer
            .call(move |c| auth::lookup_session(c, &lookup_token))
            .await
            .map_err(|e| err_response(&req_id, e))?;
        let Some(session) = session else {
            return Err(err_response(
                &req_id,
                AppError::new(ErrorCode::Unauthorized, "未登录或会话已失效"),
            ));
        };
        if is_mutating(&parts.method) {
            let presented = parts.headers.get(CSRF_HEADER).and_then(to_str);
            if presented != Some(session.csrf_secret.as_str()) {
                return Err(err_response(
                    &req_id,
                    AppError::new(
                        ErrorCode::Forbidden,
                        "CSRF 校验失败，请携带有效的 X-CSRF-Token",
                    ),
                ));
            }
        }
        Ok(Auth { session, token })
    }
}

fn is_mutating(method: &axum::http::Method) -> bool {
    matches!(
        *method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    )
}

// ---- JSON body extractor with envelope-shaped 400 ----

/// Like `axum::Json`, but rejections use the spec 17.1 error envelope
/// (400 BAD_REQUEST) instead of axum's plain-text default.
pub struct ApiJson<T>(pub T);

impl<T> FromRequest<AppState> for ApiJson<T>
where
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Response> {
        let req_id = request_id_of(req.extensions().get::<RequestId>());
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(rej) => Err(err_response(
                &req_id,
                AppError::new(
                    ErrorCode::BadRequest,
                    format!("请求体不是有效的 JSON 或字段不合法: {}", rej.body_text()),
                ),
            )),
        }
    }
}

// ---- envelopes (spec 17.1) ----

fn request_id_of(ext: Option<&RequestId>) -> String {
    ext.cloned()
        .map(|r| r.0)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

pub(crate) fn ok_response(req_id: &str, status: StatusCode, data: Value, meta: Value) -> Response {
    (
        status,
        Json(json!({"data": data, "meta": meta, "request_id": req_id})),
    )
        .into_response()
}

pub(crate) fn err_response(req_id: &str, err: AppError) -> Response {
    let status =
        StatusCode::from_u16(err.code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if err.code == ErrorCode::Internal {
        // Internal details must not leak paths/SQL to clients (spec 14.2);
        // the full message stays in the logs.
        tracing::error!(request_id = %req_id, error = %err.message, "internal error");
    }
    let message = if err.code == ErrorCode::Internal {
        "服务器内部错误".to_string()
    } else {
        err.message.clone()
    };
    (
        status,
        Json(json!({
            "error": {
                "code": err.code.as_str(),
                "message": message,
                "details": err.details.clone().unwrap_or_else(|| json!({})),
            },
            "request_id": req_id,
        })),
    )
        .into_response()
}

/// Collapse a handler's `AppResult<(status, data, meta)>` into a response.
pub(crate) fn respond(
    req_id: &RequestId,
    result: AppResult<(StatusCode, Value, Value)>,
) -> Response {
    match result {
        Ok((status, data, meta)) => ok_response(&req_id.0, status, data, meta),
        Err(e) => err_response(&req_id.0, e),
    }
}

/// Standard list meta (spec 17.1).
pub(crate) fn list_meta(
    next_cursor: Option<String>,
    page_size: usize,
    total_known: Option<usize>,
    truncated: bool,
) -> Value {
    json!({
        "next_cursor": next_cursor,
        "page_size": page_size,
        "total_known": total_known,
        "truncated": truncated,
        "detail_available": true,
    })
}

// ---- helpers ----

fn to_str(v: &HeaderValue) -> Option<&str> {
    v.to_str().ok()
}

pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all(header::COOKIE) {
        let Ok(s) = value.to_str() else { continue };
        for part in s.split(';') {
            if let Some((k, v)) = part.trim().split_once('=')
                && k == name
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Client IP for rate limiting: X-Forwarded-For is honored ONLY when the
/// direct peer is inside `server.trusted_proxy_cidrs` (spec 14.1).
pub(crate) fn client_ip(server: &ServerConfig, peer: SocketAddr, headers: &HeaderMap) -> String {
    if server
        .trusted_proxy_cidrs
        .iter()
        .any(|net| net.contains(&peer.ip()))
        && let Some(xff) = headers.get("x-forwarded-for").and_then(to_str)
        && let Some(first) = xff.split(',').next()
    {
        let ip = first.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    peer.ip().to_string()
}

pub(crate) fn session_cookie(token: &str, max_age_secs: u64, secure: bool) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}{}",
        if secure { "; Secure" } else { "" }
    )
}

pub(crate) fn csrf_cookie(secret: &str, max_age_secs: u64, secure: bool) -> String {
    // NOT HttpOnly: the SPA reads it and echoes it in X-CSRF-Token.
    format!(
        "{CSRF_COOKIE}={secret}; Path=/; SameSite=Lax; Max-Age={max_age_secs}{}",
        if secure { "; Secure" } else { "" }
    )
}

pub(crate) fn expired_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Max-Age=0; SameSite=Lax")
}

pub(crate) fn append_cookies(resp: &mut Response, cookies: &[String]) {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
}

/// SPA static fallback: any non-`/api` miss serves the built frontend (or a
/// plain 404 when web assets are absent). `/api/*` misses are always the JSON
/// error envelope — never index.html (spec 15.1).
async fn spa_fallback(
    req_id: RequestId,
    State(st): State<AppState>,
    req: Request<Body>,
) -> Response {
    if req.uri().path().starts_with("/api/") {
        return err_response(&req_id.0, AppError::new(ErrorCode::NotFound, "接口不存在"));
    }
    let Some(dir) = st.static_dir.clone() else {
        return (StatusCode::NOT_FOUND, "web assets are not built").into_response();
    };
    let svc = ServeDir::new(&dir).not_found_service(ServeFile::new(dir.join("index.html")));
    match svc.oneshot(req).await {
        Ok(resp) => resp.into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            format!("static asset unavailable: {e}"),
        )
            .into_response(),
    }
}
