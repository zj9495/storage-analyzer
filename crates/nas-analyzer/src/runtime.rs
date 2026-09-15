//! Long-lived service supervisors for scheduled scans, capacity history,
//! notifications and persisted non-scan jobs.
//!
//! Each loop owns only coordination. SQLite work remains on the single
//! control-db writer thread, while SMTP delivery runs on a small current
//! thread Tokio runtime created by the notification worker.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::auth;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::httpapi::AppState;
use crate::jobs::{self, Job, JobState, JobType};
use crate::notify::{self, NotificationSettings, TlsMode};
use crate::profile;
use crate::scheduler::{self, MisfirePolicy};

fn internal(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, message)
}

/// Number of consecutive one-second samples required before a soft budget
/// starts applying an admission or worker action. A single RSS sample is
/// explicitly not treated as a sustained pressure condition (spec 15.9).
pub const MEMORY_BUDGET_SUSTAINED_SAMPLES: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPressure {
    Unknown,
    WithinBudget,
    OverBudget,
}

impl MemoryPressure {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::WithinBudget => "within_budget",
            Self::OverBudget => "over_budget",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryBudgetSnapshot {
    pub process_rss_bytes: Option<u64>,
    pub cgroup_memory_current_bytes: Option<u64>,
    pub api_pressure: MemoryPressure,
    pub worker_pressure: MemoryPressure,
    pub api_over_budget_samples: u32,
    pub worker_over_budget_samples: u32,
}

impl Default for MemoryBudgetSnapshot {
    fn default() -> Self {
        Self {
            process_rss_bytes: None,
            cgroup_memory_current_bytes: None,
            api_pressure: MemoryPressure::Unknown,
            worker_pressure: MemoryPressure::Unknown,
            api_over_budget_samples: 0,
            worker_over_budget_samples: 0,
        }
    }
}

/// Shared soft-budget state. The budgets are thresholds for admission and
/// cooperative shutdown; they are not an RSS hard limit. The hard limit is
/// supplied by the deployment cgroup (spec 15.9).
#[derive(Clone)]
pub struct MemoryBudgetController {
    api_memory_budget_mib: u32,
    worker_memory_budget_mib: u32,
    api_budget_bytes: u64,
    worker_budget_bytes: u64,
    snapshot: Arc<parking_lot::Mutex<MemoryBudgetSnapshot>>,
}

impl MemoryBudgetController {
    pub fn new(api_memory_budget_mib: u32, worker_memory_budget_mib: u32) -> AppResult<Self> {
        let api_budget_bytes = mib_to_bytes(api_memory_budget_mib, "api_memory_budget_mib")?;
        let worker_budget_bytes =
            mib_to_bytes(worker_memory_budget_mib, "worker_memory_budget_mib")?;
        Ok(Self {
            api_memory_budget_mib,
            worker_memory_budget_mib,
            api_budget_bytes,
            worker_budget_bytes,
            snapshot: Arc::new(parking_lot::Mutex::new(MemoryBudgetSnapshot::default())),
        })
    }

    pub const fn api_memory_budget_mib(&self) -> u32 {
        self.api_memory_budget_mib
    }

    pub const fn worker_memory_budget_mib(&self) -> u32 {
        self.worker_memory_budget_mib
    }

    pub fn snapshot(&self) -> MemoryBudgetSnapshot {
        *self.snapshot.lock()
    }

    /// Read and publish one process RSS/cgroup sample.
    pub fn sample_now(&self) -> AppResult<()> {
        let rss = match process_rss_bytes() {
            Ok(value) => value,
            Err(error) => {
                self.record_sample(None, None);
                return Err(error);
            }
        };
        let cgroup = match cgroup_memory_current_bytes() {
            Ok(value) => value,
            Err(error) => {
                self.record_sample(rss, None);
                return Err(error);
            }
        };
        self.record_sample(rss, cgroup);
        Ok(())
    }

    fn record_sample(&self, rss: Option<u64>, cgroup: Option<u64>) {
        let mut snapshot = self.snapshot.lock();
        let api_pressure = classify_pressure(rss, self.api_budget_bytes);
        let worker_pressure = classify_pressure(rss, self.worker_budget_bytes);
        snapshot.api_over_budget_samples = next_pressure_samples(
            snapshot.api_over_budget_samples,
            api_pressure == MemoryPressure::OverBudget,
        );
        snapshot.worker_over_budget_samples = next_pressure_samples(
            snapshot.worker_over_budget_samples,
            worker_pressure == MemoryPressure::OverBudget,
        );
        snapshot.process_rss_bytes = rss;
        snapshot.cgroup_memory_current_bytes = cgroup;
        snapshot.api_pressure = api_pressure;
        snapshot.worker_pressure = worker_pressure;
    }

    pub fn admit_api(&self, operation: &str) -> AppResult<()> {
        self.sample_now()?;
        let snapshot = self.snapshot();
        if snapshot.api_over_budget_samples >= MEMORY_BUDGET_SUSTAINED_SAMPLES {
            return Err(AppError::new(
                ErrorCode::ResourceBudgetExceeded,
                format!("{operation} 被 API 内存预算暂时拒绝"),
            )
            .with_details(serde_json::json!({
                "operation": operation,
                "api_memory_budget_mib": self.api_memory_budget_mib,
                "process_rss_bytes": snapshot.process_rss_bytes,
                "api_pressure": snapshot.api_pressure.as_str(),
                "over_budget_samples": snapshot.api_over_budget_samples,
            })));
        }
        Ok(())
    }

    pub fn worker_should_stop(&self) -> bool {
        self.snapshot().worker_over_budget_samples >= MEMORY_BUDGET_SUSTAINED_SAMPLES
    }
}

fn mib_to_bytes(mib: u32, field: &str) -> AppResult<u64> {
    u64::from(mib)
        .checked_mul(1024 * 1024)
        .ok_or_else(|| internal(format!("{field} 转换为字节时溢出")))
}

fn next_pressure_samples(previous: u32, over_budget: bool) -> u32 {
    if over_budget {
        previous
            .min(MEMORY_BUDGET_SUSTAINED_SAMPLES)
            .saturating_add(1)
            .min(MEMORY_BUDGET_SUSTAINED_SAMPLES)
    } else {
        0
    }
}

fn classify_pressure(rss: Option<u64>, budget_bytes: u64) -> MemoryPressure {
    match rss {
        Some(value) if value > budget_bytes => MemoryPressure::OverBudget,
        Some(_) => MemoryPressure::WithinBudget,
        None => MemoryPressure::Unknown,
    }
}

/// Sample the shared process budget once per second. The monitor is kept in
/// the same dedicated thread as the other service supervisors so a resource
/// observation never runs in an HTTP handler.
fn memory_budget_loop(state: AppState, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::SeqCst) {
        if let Err(error) = state.memory_budget.sample_now() {
            tracing::warn!(error = %error.message, "读取内存预算观测失败");
        }
        wait_or_stop(&stop, Duration::from_secs(1));
    }
}

/// Read process RSS from the Linux proc interface. Non-Linux development
/// environments report that this optional observation is unavailable.
#[cfg(target_os = "linux")]
pub fn process_rss_bytes() -> AppResult<Option<u64>> {
    let text = match std::fs::read_to_string("/proc/self/status") {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(internal(format!("读取进程资源信息失败: {error}"))),
    };
    let Some(line) = text.lines().find(|line| line.starts_with("VmRSS:")) else {
        return Ok(None);
    };
    let mut fields = line.split_whitespace();
    let _name = fields.next();
    let value = fields
        .next()
        .ok_or_else(|| internal("进程 VmRSS 格式损坏"))?
        .parse::<u64>()
        .map_err(|_| internal("进程 VmRSS 数值损坏"))?;
    let unit = fields
        .next()
        .ok_or_else(|| internal("进程 VmRSS 单位缺失"))?;
    let bytes = match unit {
        "kB" => value
            .checked_mul(1024)
            .ok_or_else(|| internal("进程 RSS 计算溢出"))?,
        _ => return Err(internal("进程 VmRSS 单位不受支持")),
    };
    Ok(Some(bytes))
}

#[cfg(not(target_os = "linux"))]
pub fn process_rss_bytes() -> AppResult<Option<u64>> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn cgroup_memory_current_bytes() -> AppResult<Option<u64>> {
    match std::fs::read_to_string("/sys/fs/cgroup/memory.current") {
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| internal("cgroup memory.current 数值损坏")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(internal(format!(
            "读取 cgroup memory.current 失败: {error}"
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
fn cgroup_memory_current_bytes() -> AppResult<Option<u64>> {
    Ok(None)
}

/// Owns all service background loops and joins them during graceful shutdown.
pub struct RuntimeSupervisors {
    stop: Arc<AtomicBool>,
    joins: Vec<JoinHandle<()>>,
}

impl RuntimeSupervisors {
    pub fn start(state: AppState) -> AppResult<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut joins = Vec::with_capacity(6);
        for (name, loop_fn) in [
            (
                "memory-budget-monitor",
                memory_budget_loop as fn(AppState, Arc<AtomicBool>),
            ),
            (
                "schedule-supervisor",
                scheduler_loop as fn(AppState, Arc<AtomicBool>),
            ),
            ("capacity-sampler", sampler_loop),
            ("notification-worker", notification_loop),
            ("operation-supervisor", operation_loop),
            (
                "quarantine-auto-purge-supervisor",
                quarantine_auto_purge_loop,
            ),
        ] {
            let state_for_thread = state.clone();
            let stop_for_thread = stop.clone();
            let join = thread::Builder::new()
                .name(name.into())
                .spawn(move || loop_fn(state_for_thread, stop_for_thread))
                .map_err(|e| internal(format!("启动 {name} 失败: {e}")))?;
            joins.push(join);
        }
        Ok(Self { stop, joins })
    }

    pub fn shutdown(self) {
        self.stop.store(true, Ordering::SeqCst);
        for join in self.joins {
            let _ = join.join();
        }
    }
}

fn wait_or_stop(stop: &AtomicBool, duration: Duration) {
    let mut remaining = duration;
    while !stop.load(Ordering::SeqCst) && remaining > Duration::ZERO {
        let slice = remaining.min(Duration::from_secs(1));
        thread::sleep(slice);
        remaining = remaining.saturating_sub(slice);
    }
}

fn scheduler_loop(state: AppState, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::SeqCst) {
        if let Err(error) = schedule_once(&state) {
            tracing::error!(error = %error.message, "调度器执行失败");
        }
        wait_or_stop(&stop, Duration::from_secs(30));
    }
}

fn parse_schedule_time(value: &str) -> AppResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|error| internal(format!("调度 next_run_at 时间戳损坏: {error}")))
}

fn occurrence_at(
    spec: &scheduler::ScheduleSpec,
    at: DateTime<Utc>,
) -> AppResult<scheduler::Occurrence> {
    let from = at
        .checked_sub_signed(ChronoDuration::nanoseconds(1))
        .ok_or_else(|| internal("调度 next_run_at 时间戳下溢"))?;
    let occurrence = scheduler::next_occurrences(spec, from, 1)?
        .into_iter()
        .next()
        .ok_or_else(|| internal("调度 next_run_at 没有对应的逻辑触发点"))?;
    if occurrence.at_utc != Some(at) {
        return Err(internal("调度 next_run_at 与当前任务表达式不一致"));
    }
    Ok(occurrence)
}

fn persist_next_run_at(
    conn: &Connection,
    profile_id: &str,
    next_run_at: Option<&str>,
) -> AppResult<()> {
    let changed = conn
        .execute(
            "UPDATE profiles SET next_run_at = ?2 WHERE id = ?1 AND deleted_at IS NULL",
            params![profile_id, next_run_at],
        )
        .map_err(|error| internal(format!("更新任务下次运行时间失败: {error}")))?;
    if changed != 1 {
        return Err(internal("更新任务下次运行时间时任务不存在"));
    }
    Ok(())
}

fn occurrence_recorded(
    conn: &Connection,
    profile_id: &str,
    profile_version: i64,
    occurrence_key: &str,
) -> AppResult<bool> {
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM schedule_occurrences
             WHERE profile_id = ?1 AND profile_version = ?2 AND occurrence_key = ?3
         )",
        params![profile_id, profile_version, occurrence_key],
        |row| row.get(0),
    )
    .map_err(|error| internal(format!("读取调度幂等记录失败: {error}")))
}

fn schedule_once(state: &AppState) -> AppResult<()> {
    if let Err(error) = state.memory_budget.admit_api("scheduled_scan") {
        if error.code == ErrorCode::ResourceBudgetExceeded {
            return Ok(());
        }
        return Err(error);
    }
    let now = Utc::now();
    let max_queued_scans = state.config.resources.max_queued_scans as usize;
    state.writer.call_blocking(move |conn| {
        let profiles = profile::list(conn, false)?;
        for record in profiles {
            if !record.config.enabled {
                if record.next_run_at.is_some() {
                    persist_next_run_at(conn, &record.id, None)?;
                }
                continue;
            }
            let Some(spec) = record.config.schedule.schedule_spec()? else {
                if record.next_run_at.is_some() {
                    persist_next_run_at(conn, &record.id, None)?;
                }
                continue;
            };
            let Some(stored_next) = record.next_run_at.as_deref() else {
                let next = profile::next_run_at(&record.config, now)?;
                persist_next_run_at(conn, &record.id, next.as_deref())?;
                continue;
            };
            let stored_next = parse_schedule_time(stored_next)?;
            if stored_next > now {
                continue;
            }
            let skipped_from = stored_next
                .checked_sub_signed(ChronoDuration::nanoseconds(1))
                .ok_or_else(|| internal("调度跳过记录时间下溢"))?;
            let skipped = scheduler::skipped_occurrences_until(&spec, skipped_from, now)?;
            let occurrence = match spec.misfire_policy {
                MisfirePolicy::Skip => {
                    let age = now - stored_next;
                    if age <= ChronoDuration::minutes(2) {
                        Some(occurrence_at(&spec, stored_next)?)
                    } else {
                        None
                    }
                }
                MisfirePolicy::RunOnce => {
                    let window_start = now - ChronoDuration::hours(6);
                    let from = window_start
                        .checked_sub_signed(ChronoDuration::nanoseconds(1))
                        .ok_or_else(|| internal("调度错过窗口时间下溢"))?;
                    scheduler::occurrences_until(&spec, from, now)?
                        .into_iter()
                        .filter(|item| item.at_utc.is_some())
                        .max_by_key(|item| item.at_utc)
                }
            };
            let next = profile::next_run_at(&record.config, now)?;
            let Some(next) = next else {
                return Err(internal("已启用的非手动调度没有下次运行时间"));
            };
            let tx = conn
                .transaction()
                .map_err(|e| internal(format!("开启调度入队事务失败: {e}")))?;
            persist_next_run_at(&tx, &record.id, Some(&next))?;
            for skipped_occurrence in skipped {
                jobs::record_skipped_occurrence(
                    &tx,
                    &record.id,
                    record.version,
                    &skipped_occurrence.occurrence_key,
                )?;
            }
            let Some(occurrence) = occurrence else {
                tx.commit()
                    .map_err(|e| internal(format!("提交调度跳过事务失败: {e}")))?;
                continue;
            };
            if occurrence_recorded(&tx, &record.id, record.version, &occurrence.occurrence_key)? {
                tx.commit()
                    .map_err(|e| internal(format!("提交调度幂等事务失败: {e}")))?;
                continue;
            }
            let planned_at = occurrence
                .at_utc
                .ok_or_else(|| internal("调度触发点缺少 UTC 时间"))?;
            let source_ids = record.config.source_ids(&tx, &record.created_at)?;
            let ruleset = crate::category::load_current(&tx)?;
            let params = json!({
                "source_ids": source_ids,
                "profile_snapshot": record.config,
                "ruleset_snapshot": ruleset,
                "rank_limit": record.config.rank_limit,
                "scheduled_at": planned_at.to_rfc3339(),
            });
            let job = jobs::create_scan_job(
                &tx,
                &record.id,
                record.version,
                &params,
                None,
                max_queued_scans,
                spec.overlap_policy,
            )?;
            jobs::record_occurrence(
                &tx,
                &record.id,
                record.version,
                &occurrence.occurrence_key,
                &job.id,
                &planned_at.to_rfc3339(),
            )?;
            tx.commit()
                .map_err(|e| internal(format!("提交调度入队事务失败: {e}")))?;
        }
        Ok(())
    })
}

fn sampler_loop(state: AppState, stop: Arc<AtomicBool>) {
    let interval =
        Duration::from_secs(u64::from(state.config.sampling.interval_minutes).saturating_mul(60));
    while !stop.load(Ordering::SeqCst) {
        let config = state.config.clone();
        let reports_root = state.config.storage.data_dir.join("reports");
        let result = state.writer.call_blocking(move |conn| {
            let _samples = crate::sampling::sample_all_volumes(conn, &config)?;
            crate::sampling::maintain_history(conn, &config.sampling, &auth::now_rfc3339())?;
            for profile in profile::list(conn, false)? {
                crate::retention::apply_report_retention_with_artifacts(
                    conn,
                    Some(&profile.id),
                    &profile.config.retention,
                    &reports_root,
                )?;
            }
            crate::retention::process_pending_artifact_deletions(conn, &reports_root)?;
            Ok(())
        });
        if let Err(error) = result {
            tracing::error!(error = %error.message, "容量采样失败");
        }
        wait_or_stop(&stop, interval);
    }
}

fn notification_loop(state: AppState, stop: Arc<AtomicBool>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "创建通知 Tokio runtime 失败");
            return;
        }
    };
    while !stop.load(Ordering::SeqCst) {
        let claimed = state.writer.call_blocking(|conn| {
            let settings = notify::load_settings(conn)?;
            let Some(settings) = settings else {
                return Ok(None);
            };
            if !settings.enabled {
                return Ok(None);
            }
            let Some(claim) = notify::claim_next(conn)? else {
                return Ok(None);
            };
            let message = notify::build_message(&claim, &settings)?;
            Ok(Some((claim, settings, message)))
        });
        match claimed {
            Ok(Some((claim, settings, message))) => {
                let delivery = runtime.block_on(send_message(&settings, message));
                let result = state.writer.call_blocking(move |conn| match delivery {
                    Ok(()) => notify::mark_sent(conn, &claim).map(|_| ()),
                    Err(DeliveryFailure::Unknown(error)) => {
                        notify::mark_delivery_unknown(conn, &claim, &error).map(|_| ())
                    }
                    Err(DeliveryFailure::Rejected(error)) => {
                        notify::mark_failed(conn, &claim, &error).map(|_| ())
                    }
                });
                if let Err(error) = result {
                    tracing::error!(error = %error.message, "更新通知状态失败");
                }
            }
            Ok(None) => wait_or_stop(&stop, Duration::from_secs(5)),
            Err(error) => {
                tracing::error!(error = %error.message, "通知 worker 领取失败");
                wait_or_stop(&stop, Duration::from_secs(5));
            }
        }
    }
}

fn quarantine_auto_purge_loop(state: AppState, stop: Arc<AtomicBool>) {
    let interval =
        Duration::from_secs(u64::from(state.config.sampling.interval_minutes).saturating_mul(60));
    while !stop.load(Ordering::SeqCst) {
        let result = state.writer.call_blocking(|conn| {
            let policy = crate::retention::load_quarantine_auto_purge(conn)?;
            crate::cleanup::enqueue_due_auto_purges(conn, &policy)
        });
        if let Err(error) = result {
            tracing::error!(error = %error.message, "隔离区自动清理入队失败");
        }
        wait_or_stop(&stop, interval);
    }
}

enum DeliveryFailure {
    Unknown(String),
    Rejected(String),
}

fn classify_smtp_error(error: lettre::transport::smtp::Error) -> DeliveryFailure {
    let message = error.to_string();
    if error.is_transient() || error.is_permanent() || error.is_client() {
        DeliveryFailure::Rejected(message)
    } else {
        DeliveryFailure::Unknown(message)
    }
}

async fn send_message(
    settings: &NotificationSettings,
    message: lettre::Message,
) -> Result<(), DeliveryFailure> {
    let transport = match settings.tls_mode {
        TlsMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.smtp_host),
        TlsMode::Starttls => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.smtp_host)
        }
        TlsMode::None => return Err(DeliveryFailure::Rejected("SMTP 明文模式未启用".into())),
    }
    .map_err(|error| DeliveryFailure::Rejected(error.to_string()))?;
    let mut builder = transport.port(settings.smtp_port);
    if let (Some(username), Some(password)) = (&settings.username, &settings.password) {
        builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
    }
    builder
        .build()
        .send(message)
        .await
        .map(|_| ())
        .map_err(classify_smtp_error)
}

fn operation_loop(state: AppState, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::SeqCst) {
        let claimed = state.writer.call_blocking(jobs::claim_next_operation);
        match claimed {
            Ok(Some(job)) => {
                if let Err(error) = execute_operation(&state, &job) {
                    tracing::error!(job_id = %job.id, error = %error.message, "后台操作失败");
                    let update = if job.job_type == JobType::CleanupAction {
                        finish_cleanup_operation_error(&state, &job, &error)
                    } else {
                        finish_non_cleanup_operation_error(&state, &job, &error)
                    };
                    if let Err(update_error) = update {
                        tracing::error!(
                            job_id = %job.id,
                            error = %update_error.message,
                            "后台操作失败状态写入失败"
                        );
                    }
                }
            }
            Ok(None) => wait_or_stop(&stop, Duration::from_millis(500)),
            Err(error) => {
                tracing::error!(error = %error.message, "后台操作领取失败");
                wait_or_stop(&stop, Duration::from_secs(1));
            }
        }
    }
}

fn finish_cleanup_operation_error(state: &AppState, job: &Job, error: &AppError) -> AppResult<()> {
    let cleanup_request = crate::cleanup::CleanupJob::parse(&job.params_json).ok();
    let contract_is_valid = cleanup_request.is_some();
    let auto_purge_preflight_failed = matches!(
        cleanup_request,
        Some(crate::cleanup::CleanupJob::AutoPurge { .. })
    ) && matches!(
        error.code,
        ErrorCode::ReadOnlyMode | ErrorCode::JobStateConflict
    );
    let job_id = job.id.clone();
    let error_json = json!({
        "code": error.code.as_str(),
        "message": error.message,
    });
    let error_code = error.code;
    let interrupt_message = format!("清理任务执行失败: {}", error.message);
    state.writer.call_blocking(move |conn| {
        consume_operation_internal_notification(conn, &job_id, JobType::CleanupAction, error_code)?;
        let current = jobs::get_job(conn, &job_id)?;
        if current.state.is_terminal() {
            return Ok(());
        }
        if contract_is_valid {
            if current.state == JobState::Cancelling || auto_purge_preflight_failed {
                jobs::job_finish(conn, &job_id, JobState::Failed, Some(&error_json))?;
            } else {
                jobs::interrupt_job(conn, &job_id, &interrupt_message)?;
            }
        } else {
            jobs::job_finish(conn, &job_id, JobState::Failed, Some(&error_json))?;
        }
        Ok(())
    })
}

fn finish_non_cleanup_operation_error(
    state: &AppState,
    job: &Job,
    error: &AppError,
) -> AppResult<()> {
    let error_json = json!({
        "code": error.code.as_str(),
        "message": error.message,
    });
    let job_id = job.id.clone();
    let job_type = job.job_type;
    let error_code = error.code;
    let export_id = match job.job_type {
        JobType::Export | JobType::Backup => job
            .params_json
            .get("export_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    let comparison_id = job
        .params_json
        .get("comparison_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    state.writer.call_blocking(move |conn| {
        consume_operation_internal_notification(conn, &job_id, job_type, error_code)?;
        if let Some(export_id) = export_id {
            conn.execute(
                "UPDATE exports SET state = 'failed' WHERE id = ?1 AND state = 'pending'",
                [&export_id],
            )
            .map_err(|e| internal(format!("记录导出失败状态失败: {e}")))?;
        }
        if let Some(comparison_id) = comparison_id {
            conn.execute(
                "UPDATE comparisons SET state = 'failed', error_json = ?2,
                 completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE id = ?1 AND state NOT IN ('succeeded','failed')",
                params![comparison_id, error_json.to_string()],
            )
            .map_err(|e| internal(format!("记录比较失败状态失败: {e}")))?;
        }
        let current = jobs::get_job(conn, &job_id)?;
        if current.state.is_terminal() {
            Ok(())
        } else {
            jobs::job_finish(conn, &job_id, JobState::Failed, Some(&error_json)).map(|_| ())
        }
    })
}

pub(crate) fn consume_operation_internal_notification(
    conn: &Connection,
    job_id: &str,
    job_type: JobType,
    error_code: ErrorCode,
) -> AppResult<()> {
    let (kind, title, severity) = match error_code {
        ErrorCode::InsufficientDataSpace => (
            "storage.insufficient",
            "存储空间不足",
            notify::InternalNotificationSeverity::Error,
        ),
        ErrorCode::QuarantineConflict => (
            "cleanup.conflict",
            "清理操作发生冲突",
            notify::InternalNotificationSeverity::Warning,
        ),
        _ => return Ok(()),
    };
    let body = format!(
        "任务 ID：{job_id}；任务类型：{}；错误码：{}。",
        job_type.as_str(),
        error_code.as_str(),
    );
    let event_key = format!("operation:{job_id}:{}", error_code.as_str());
    notify::create_internal_notification_once(conn, &event_key, kind, title, &body, severity)?;
    Ok(())
}

fn execute_operation(state: &AppState, job: &Job) -> AppResult<()> {
    match job.job_type {
        JobType::Compare => execute_compare(state, job),
        JobType::Export => crate::httpapi::run_export_job(state, job),
        JobType::Backup => crate::httpapi::run_backup_job(state, job),
        JobType::CleanupAction => {
            crate::cleanup::run_job(state.writer.clone(), state.config.as_ref(), job)
        }
        JobType::Scan => Err(internal("操作 supervisor 收到非操作任务")),
    }
}

fn execute_compare(state: &AppState, job: &Job) -> AppResult<()> {
    let params = job
        .params_json
        .as_object()
        .ok_or_else(|| internal("比较任务参数不是对象"))?;
    let report_id = params
        .get("report_id")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("比较任务缺少 report_id"))?
        .to_owned();
    let other_report_id = params
        .get("other_report_id")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("比较任务缺少 other_report_id"))?
        .to_owned();
    let mode = params
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("比较任务缺少 mode"))?
        .to_owned();
    let comparable = params
        .get("comparable")
        .and_then(Value::as_bool)
        .ok_or_else(|| internal("比较任务缺少 comparable"))?;
    let comparison_id = params
        .get("comparison_id")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("比较任务缺少 comparison_id"))?
        .to_owned();
    let incompatibility_reasons = params.get("incompatibility_reasons").cloned();
    let job_id = job.id.clone();
    let reports_root = state.config.storage.data_dir.join("reports");
    state.writer.call_blocking(move |conn| {
        for report_id in [&report_id, &other_report_id] {
            let exists: Option<i64> = conn
                .query_row("SELECT 1 FROM reports WHERE id = ?1", [report_id], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(|e| internal(format!("读取比较报告记录失败: {e}")))?;
            if exists.is_none() {
                return Err(AppError::new(ErrorCode::NotFound, "比较报告不存在"));
            }
        }
        let left_summary = crate::report::open_published_in_root(
            &reports_root,
            &report_id,
            "report.sqlite",
            "打开比较报告摘要失败",
        )?;
        let right_summary = crate::report::open_published_in_root(
            &reports_root,
            &other_report_id,
            "report.sqlite",
            "打开比较报告摘要失败",
        )?;

        conn.execute(
            "UPDATE comparisons SET state = 'running' WHERE id = ?1 AND job_id = ?2",
            params![comparison_id, job_id],
        )
        .map_err(|e| internal(format!("开始比较任务失败: {e}")))?;

        if !comparable {
            let reasons = incompatibility_reasons
                .as_ref()
                .ok_or_else(|| internal("不可比比较任务缺少原因"))?;
            let progress = json!({
                "mode": mode,
                "report_id": report_id,
                "other_report_id": other_report_id,
                "comparable": false,
                "incompatibility_reasons": reasons,
                "summary": {"not_comparable": true},
                "counts": {},
            });
            conn.execute(
                "UPDATE comparisons SET state = 'succeeded', summary_json = ?2,
                 completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
                params![comparison_id, progress.to_string()],
            )
            .map_err(|e| internal(format!("保存不可比比较结果失败: {e}")))?;
            jobs::job_heartbeat(conn, &job_id, &progress)?;
            jobs::append_event(conn, &job_id, "job.completed", &progress)?;
            jobs::job_finish(conn, &job_id, JobState::Succeeded, None)?;
            return Ok(());
        }

        let mut counts = BTreeMap::new();
        let summary = if mode == "aggregate" {
            compare_aggregate_rows(
                conn,
                &comparison_id,
                &left_summary,
                &right_summary,
                &mut counts,
            )?
        } else if mode == "files" {
            let left_index = crate::report::open_published_in_root(
                &reports_root,
                &report_id,
                "index.sqlite",
                "打开比较报告明细失败",
            )?;
            let right_index = crate::report::open_published_in_root(
                &reports_root,
                &other_report_id,
                "index.sqlite",
                "打开比较报告明细失败",
            )?;
            compare_file_rows(conn, &comparison_id, &left_index, &right_index, &mut counts)?
        } else {
            return Err(AppError::new(
                ErrorCode::ValidationFailed,
                format!("未知比较模式: {mode}"),
            ));
        };
        let progress = json!({
            "mode": mode,
            "report_id": report_id,
            "other_report_id": other_report_id,
            "comparable": comparable,
            "incompatibility_reasons": incompatibility_reasons,
            "summary": summary,
            "counts": counts,
        });
        conn.execute(
            "UPDATE comparisons SET state = 'succeeded', summary_json = ?2,
             completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
            params![comparison_id, progress.to_string()],
        )
        .map_err(|e| internal(format!("保存比较结果失败: {e}")))?;
        jobs::job_heartbeat(conn, &job_id, &progress)?;
        jobs::append_event(conn, &job_id, "job.completed", &progress)?;
        jobs::job_finish(conn, &job_id, JobState::Succeeded, None)?;
        Ok(())
    })
}

fn comparison_delta(right: i64, left: i64) -> String {
    (i128::from(right) - i128::from(left)).to_string()
}

fn nullable_metric(value: Option<i64>) -> Value {
    value.map_or(Value::Null, |value| json!(value.to_string()))
}

fn nullable_delta(right: Option<i64>, left: Option<i64>) -> Value {
    match (right, left) {
        (Some(right), Some(left)) => json!(comparison_delta(right, left)),
        _ => Value::Null,
    }
}

fn insert_comparison_row(
    tx: &Connection,
    comparison_id: &str,
    section: &str,
    row_key: &str,
    payload: &Value,
) -> AppResult<()> {
    tx.execute(
        "INSERT INTO comparison_rows(comparison_id, section, row_key, payload_json)
         VALUES (?1, ?2, ?3, ?4)",
        params![comparison_id, section, row_key, payload.to_string()],
    )
    .map_err(|e| internal(format!("写入比较明细失败: {e}")))?;
    Ok(())
}

fn add_count(counts: &mut BTreeMap<String, i64>, section: &str, kind: &str) {
    let key = format!("{section}.{kind}");
    *counts.entry(key).or_default() += 1;
}

fn compare_aggregate_rows(
    conn: &mut Connection,
    comparison_id: &str,
    left: &Connection,
    right: &Connection,
    counts: &mut BTreeMap<String, i64>,
) -> AppResult<Value> {
    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("开启比较结果事务失败: {e}")))?;
    compare_folder_rows(&tx, comparison_id, left, right, counts)?;
    compare_owner_rows(&tx, comparison_id, left, right, counts)?;
    compare_category_rows(&tx, comparison_id, left, right, counts)?;
    tx.commit()
        .map_err(|e| internal(format!("提交比较结果事务失败: {e}")))?;
    Ok(json!({"sections": ["folders", "owners", "categories"]}))
}

fn compare_folder_rows(
    tx: &Connection,
    comparison_id: &str,
    left: &Connection,
    right: &Connection,
    counts: &mut BTreeMap<String, i64>,
) -> AppResult<()> {
    type FolderCompareRow = (i64, i64, Option<i64>, Option<i64>, Option<i64>, String);
    let mut stmt = left
        .prepare(
            "SELECT source_id, raw_relative_path, display_path, file_count, dir_count,
                    logical_bytes, unique_logical_bytes, allocated_bytes, completeness
             FROM folder_aggregates",
        )
        .map_err(|e| internal(format!("准备目录比较失败: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(|e| internal(format!("读取目录比较失败: {e}")))?;
    for row in rows {
        let (source, raw, display, files, dirs, logical, unique, allocated, completeness) =
            row.map_err(|e| internal(format!("读取目录比较行失败: {e}")))?;
        let key = format!("{source}:{}", hex::encode(&raw));
        let other: Option<FolderCompareRow> = right
            .query_row(
                "SELECT file_count, dir_count, logical_bytes, unique_logical_bytes,
                        allocated_bytes, completeness
                 FROM folder_aggregates WHERE source_id = ?1 AND raw_relative_path = ?2",
                params![source, raw],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| internal(format!("查询右侧目录比较失败: {e}")))?;
        let payload = match other {
            Some((r_files, r_dirs, r_logical, r_unique, r_allocated, r_complete))
                if (files, dirs, logical, unique, allocated, &completeness)
                    != (
                        r_files,
                        r_dirs,
                        r_logical,
                        r_unique,
                        r_allocated,
                        &r_complete,
                    ) =>
            {
                add_count(counts, "folders", "changed");
                json!({"change": "changed", "source_id": source, "relative_path_display": display,
                    "before": {"file_count": files.to_string(), "dir_count": dirs.to_string(), "logical_bytes": nullable_metric(logical), "unique_logical_bytes": nullable_metric(unique), "allocated_bytes": nullable_metric(allocated), "completeness": completeness},
                    "after": {"file_count": r_files.to_string(), "dir_count": r_dirs.to_string(), "logical_bytes": nullable_metric(r_logical), "unique_logical_bytes": nullable_metric(r_unique), "allocated_bytes": nullable_metric(r_allocated), "completeness": r_complete}})
            }
            Some(_) => continue,
            None => {
                add_count(counts, "folders", "removed");
                json!({"change": "removed", "source_id": source, "relative_path_display": display,
                    "before": {"file_count": files.to_string(), "dir_count": dirs.to_string(), "logical_bytes": nullable_metric(logical), "unique_logical_bytes": nullable_metric(unique), "allocated_bytes": nullable_metric(allocated), "completeness": completeness}})
            }
        };
        insert_comparison_row(tx, comparison_id, "folders", &key, &payload)?;
    }
    let mut stmt = right
        .prepare("SELECT source_id, raw_relative_path, display_path, file_count, dir_count, logical_bytes, unique_logical_bytes, allocated_bytes, completeness FROM folder_aggregates")
        .map_err(|e| internal(format!("准备右侧目录比较失败: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(|e| internal(format!("读取右侧目录比较失败: {e}")))?;
    for row in rows {
        let (source, raw, display, files, dirs, logical, unique, allocated, completeness) =
            row.map_err(|e| internal(format!("读取右侧目录比较行失败: {e}")))?;
        let exists: Option<i64> = left
            .query_row(
                "SELECT 1 FROM folder_aggregates WHERE source_id = ?1 AND raw_relative_path = ?2",
                params![source, raw],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| internal(format!("查询左侧目录比较失败: {e}")))?;
        if exists.is_none() {
            add_count(counts, "folders", "added");
            let key = format!("{source}:{}", hex::encode(&raw));
            insert_comparison_row(
                tx,
                comparison_id,
                "folders",
                &key,
                &json!({"change": "added", "source_id": source, "relative_path_display": display,
                    "after": {"file_count": files.to_string(), "dir_count": dirs.to_string(), "logical_bytes": nullable_metric(logical), "unique_logical_bytes": nullable_metric(unique), "allocated_bytes": nullable_metric(allocated), "completeness": completeness}}),
            )?;
        }
    }
    Ok(())
}

fn compare_owner_rows(
    tx: &Connection,
    comparison_id: &str,
    left: &Connection,
    right: &Connection,
    counts: &mut BTreeMap<String, i64>,
) -> AppResult<()> {
    let mut stmt = left
        .prepare("SELECT source_id, uid, file_count, logical_bytes FROM owner_aggregates")
        .map_err(|e| internal(format!("准备属主比较失败: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })
        .map_err(|e| internal(format!("读取属主比较失败: {e}")))?;
    for row in rows {
        let (source, uid, files, logical) =
            row.map_err(|e| internal(format!("读取属主比较行失败: {e}")))?;
        let key = format!(
            "{}:{}",
            source,
            uid.map_or_else(|| "unknown".to_string(), |value| value.to_string())
        );
        let other: Option<(i64, Option<i64>)> = right
            .query_row(
                "SELECT file_count, logical_bytes FROM owner_aggregates
                WHERE source_id = ?1 AND uid IS ?2",
                params![source, uid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| internal(format!("查询右侧属主比较失败: {e}")))?;
        let payload = match other {
            Some((r_files, r_logical)) if (files, logical) != (r_files, r_logical) => {
                add_count(counts, "owners", "changed");
                json!({"change": "changed", "source_id": source, "uid": uid,
                    "before": {"file_count": files.to_string(), "logical_bytes": nullable_metric(logical)},
                    "after": {"file_count": r_files.to_string(), "logical_bytes": nullable_metric(r_logical)},
                    "delta": {"file_count": comparison_delta(r_files, files), "logical_bytes": nullable_delta(r_logical, logical)}})
            }
            Some(_) => continue,
            None => {
                add_count(counts, "owners", "removed");
                json!({"change": "removed", "source_id": source, "uid": uid,
                    "before": {"file_count": files.to_string(), "logical_bytes": nullable_metric(logical)}})
            }
        };
        insert_comparison_row(tx, comparison_id, "owners", &key, &payload)?;
    }
    let mut stmt = right
        .prepare("SELECT source_id, uid, file_count, logical_bytes FROM owner_aggregates")
        .map_err(|e| internal(format!("准备右侧属主比较失败: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })
        .map_err(|e| internal(format!("读取右侧属主比较失败: {e}")))?;
    for row in rows {
        let (source, uid, files, logical) =
            row.map_err(|e| internal(format!("读取右侧属主比较行失败: {e}")))?;
        let exists: Option<i64> = left
            .query_row(
                "SELECT 1 FROM owner_aggregates WHERE source_id = ?1 AND uid IS ?2",
                params![source, uid],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| internal(format!("查询左侧属主比较失败: {e}")))?;
        if exists.is_none() {
            add_count(counts, "owners", "added");
            insert_comparison_row(
                tx,
                comparison_id,
                "owners",
                &format!(
                    "{}:{}",
                    source,
                    uid.map_or_else(|| "unknown".to_string(), |value| value.to_string())
                ),
                &json!({"change": "added", "source_id": source, "uid": uid,
                    "after": {"file_count": files.to_string(), "logical_bytes": nullable_metric(logical)}}),
            )?;
        }
    }
    Ok(())
}

fn compare_category_rows(
    tx: &Connection,
    comparison_id: &str,
    left: &Connection,
    right: &Connection,
    counts: &mut BTreeMap<String, i64>,
) -> AppResult<()> {
    let mut stmt = left
        .prepare("SELECT source_id, category_id, file_count, logical_bytes, allocated_bytes FROM category_aggregates")
        .map_err(|e| internal(format!("准备分类比较失败: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .map_err(|e| internal(format!("读取分类比较失败: {e}")))?;
    for row in rows {
        let (source, category, files, logical, allocated) =
            row.map_err(|e| internal(format!("读取分类比较行失败: {e}")))?;
        let key = format!("{source}:{category}");
        let other: Option<(i64, Option<i64>, Option<i64>)> = right
            .query_row(
                "SELECT file_count, logical_bytes, allocated_bytes FROM category_aggregates
                 WHERE source_id = ?1 AND category_id = ?2",
                params![source, category],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|e| internal(format!("查询右侧分类比较失败: {e}")))?;
        let payload = match other {
            Some((r_files, r_logical, r_allocated))
                if (files, logical, allocated) != (r_files, r_logical, r_allocated) =>
            {
                add_count(counts, "categories", "changed");
                json!({"change": "changed", "source_id": source, "category_id": category,
                    "before": {"file_count": files.to_string(), "logical_bytes": nullable_metric(logical), "allocated_bytes": nullable_metric(allocated)},
                    "after": {"file_count": r_files.to_string(), "logical_bytes": nullable_metric(r_logical), "allocated_bytes": nullable_metric(r_allocated)},
                    "delta": {"file_count": comparison_delta(r_files, files), "logical_bytes": nullable_delta(r_logical, logical), "allocated_bytes": nullable_delta(r_allocated, allocated)}})
            }
            Some(_) => continue,
            None => {
                add_count(counts, "categories", "removed");
                json!({"change": "removed", "source_id": source, "category_id": category,
                    "before": {"file_count": files.to_string(), "logical_bytes": nullable_metric(logical), "allocated_bytes": nullable_metric(allocated)}})
            }
        };
        insert_comparison_row(tx, comparison_id, "categories", &key, &payload)?;
    }
    let mut stmt = right
        .prepare("SELECT source_id, category_id, file_count, logical_bytes, allocated_bytes FROM category_aggregates")
        .map_err(|e| internal(format!("准备右侧分类比较失败: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .map_err(|e| internal(format!("读取右侧分类比较失败: {e}")))?;
    for row in rows {
        let (source, category, files, logical, allocated) =
            row.map_err(|e| internal(format!("读取右侧分类比较行失败: {e}")))?;
        let exists: Option<i64> = left
            .query_row(
                "SELECT 1 FROM category_aggregates WHERE source_id = ?1 AND category_id = ?2",
                params![source, category],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| internal(format!("查询左侧分类比较失败: {e}")))?;
        if exists.is_none() {
            add_count(counts, "categories", "added");
            insert_comparison_row(
                tx,
                comparison_id,
                "categories",
                &format!("{source}:{category}"),
                &json!({"change": "added", "source_id": source, "category_id": category,
                    "after": {"file_count": files.to_string(), "logical_bytes": nullable_metric(logical), "allocated_bytes": nullable_metric(allocated)}}),
            )?;
        }
    }
    Ok(())
}

fn compare_file_rows(
    conn: &mut Connection,
    comparison_id: &str,
    left: &Connection,
    right: &Connection,
    counts: &mut BTreeMap<String, i64>,
) -> AppResult<Value> {
    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("开启文件比较事务失败: {e}")))?;
    let mut stmt = left
        .prepare(
            "SELECT source_id, raw_relative_path, display_name, uid, category_id,
                    size_bytes, allocated_bytes_estimate, mtime_sec, mtime_nsec,
                    atime_sec, atime_nsec, file_identity_key
             FROM entries WHERE entry_kind = 'regular_file'",
        )
        .map_err(|e| internal(format!("准备文件比较失败: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<String>>(11)?,
            ))
        })
        .map_err(|e| internal(format!("读取文件比较失败: {e}")))?;
    for row in rows {
        let (source, raw, display, uid, category, size, allocated, ms, mn, ats, atn, identity) =
            row.map_err(|e| internal(format!("读取文件比较行失败: {e}")))?;
        let key = format!("{source}:{}", hex::encode(&raw));
        #[allow(clippy::type_complexity)]
        let other: Option<(
            String,
            Option<i64>,
            Option<String>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        )> = right
            .query_row(
                "SELECT display_name, uid, category_id, size_bytes,
                        allocated_bytes_estimate, mtime_sec, mtime_nsec,
                        atime_sec, atime_nsec, file_identity_key
                 FROM entries WHERE entry_kind = 'regular_file'
                   AND source_id = ?1 AND raw_relative_path = ?2",
                params![source, raw],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| internal(format!("查询右侧文件比较失败: {e}")))?;
        let Some((
            r_display,
            r_uid,
            r_category,
            r_size,
            r_allocated,
            r_ms,
            r_mn,
            r_ats,
            r_atn,
            r_identity,
        )) = other
        else {
            add_count(counts, "files", "removed");
            insert_comparison_row(
                &tx,
                comparison_id,
                "files",
                &key,
                &json!({"change": "removed", "source_id": source, "relative_path_display": display,
                    "before": file_snapshot(uid, category.as_deref(), size, allocated, ms, mn, ats, atn, identity.as_deref())}),
            )?;
            continue;
        };
        if (uid, &category, size, allocated, ms, mn, ats, atn, &identity)
            != (
                r_uid,
                &r_category,
                r_size,
                r_allocated,
                r_ms,
                r_mn,
                r_ats,
                r_atn,
                &r_identity,
            )
        {
            add_count(counts, "files", "changed");
            insert_comparison_row(
                &tx,
                comparison_id,
                "files",
                &key,
                &json!({"change": "changed", "source_id": source, "relative_path_display": display,
                    "before": file_snapshot(uid, category.as_deref(), size, allocated, ms, mn, ats, atn, identity.as_deref()),
                    "after": file_snapshot(r_uid, r_category.as_deref(), r_size, r_allocated, r_ms, r_mn, r_ats, r_atn, r_identity.as_deref()),
                    "other_display_name": r_display}),
            )?;
        }
    }
    let mut stmt = right
        .prepare(
            "SELECT source_id, raw_relative_path, display_name, uid, category_id,
                    size_bytes, allocated_bytes_estimate, mtime_sec, mtime_nsec,
                    atime_sec, atime_nsec, file_identity_key
             FROM entries WHERE entry_kind = 'regular_file'",
        )
        .map_err(|e| internal(format!("准备右侧文件比较失败: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<String>>(11)?,
            ))
        })
        .map_err(|e| internal(format!("读取右侧文件比较失败: {e}")))?;
    for row in rows {
        let (source, raw, display, uid, category, size, allocated, ms, mn, ats, atn, identity) =
            row.map_err(|e| internal(format!("读取右侧文件比较行失败: {e}")))?;
        let exists: Option<i64> = left
            .query_row(
                "SELECT 1 FROM entries WHERE entry_kind = 'regular_file'
                 AND source_id = ?1 AND raw_relative_path = ?2",
                params![source, raw],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| internal(format!("查询左侧文件比较失败: {e}")))?;
        if exists.is_none() {
            add_count(counts, "files", "added");
            insert_comparison_row(
                &tx,
                comparison_id,
                "files",
                &format!("{source}:{}", hex::encode(&raw)),
                &json!({"change": "added", "source_id": source, "relative_path_display": display,
                    "after": file_snapshot(uid, category.as_deref(), size, allocated, ms, mn, ats, atn, identity.as_deref())}),
            )?;
        }
    }
    tx.commit()
        .map_err(|e| internal(format!("提交文件比较事务失败: {e}")))?;
    Ok(json!({"sections": ["files"]}))
}

#[allow(clippy::too_many_arguments)]
fn file_snapshot(
    uid: Option<i64>,
    category: Option<&str>,
    size: Option<i64>,
    allocated: Option<i64>,
    mtime_sec: Option<i64>,
    mtime_nsec: Option<i64>,
    atime_sec: Option<i64>,
    atime_nsec: Option<i64>,
    identity: Option<&str>,
) -> Value {
    json!({
        "uid": uid,
        "category_id": category,
        "size_bytes": size.map(|value| value.to_string()),
        "allocated_bytes_estimate": allocated.map(|value| value.to_string()),
        "mtime_sec": mtime_sec,
        "mtime_nsec": mtime_nsec,
        "atime_sec": atime_sec,
        "atime_nsec": atime_nsec,
        "identity_key": identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ApprovedMount, DeploymentConfig, ResourceConfig, SamplingConfig, SecurityConfig,
        ServerConfig, StorageConfig,
    };
    use crate::profile::{
        FileKindPolicy, OverlapPolicyInput, ProfileConfig, ProfileDuplicates, ProfileNotifications,
        ProfileResources, ProfileRetention, ProfileSchedule, ProfileScope, ProfileSection,
        ScheduleTypeInput, ScopeMode,
    };
    use chrono::Timelike;

    fn supervisor_test_config(root: &std::path::Path) -> DeploymentConfig {
        let data_dir = root.join("data");
        let source_dir = root.join("source");
        std::fs::create_dir_all(&source_dir).unwrap();
        DeploymentConfig {
            server: ServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                default_timezone: jiff::tz::TimeZone::UTC,
                default_timezone_name: "UTC".to_owned(),
                trusted_proxy_cidrs: Vec::new(),
                allow_insecure_lan_http: true,
            },
            storage: StorageConfig {
                data_dir,
                approved_output_roots: vec![root.to_path_buf()],
                data_budget_bytes: 1024,
                hash_cache_budget_bytes: 1024,
            },
            approved_mounts: vec![ApprovedMount {
                key: "source".to_owned(),
                container_path: source_dir,
                writable: false,
                allow_submounts: false,
            }],
            security: SecurityConfig {
                allow_write_operations: false,
                setup_token_minutes: 30,
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
                max_open_files: 16,
                api_memory_budget_mib: 64,
                worker_memory_budget_mib: 128,
                max_parallel_exports: 1,
            },
            sampling: SamplingConfig {
                interval_minutes: 15,
                raw_retention_days: 1,
                daily_retention_days: 1,
            },
        }
    }

    fn insert_scope_source(conn: &Connection, id: &str, name: &str, created_at: &str) {
        conn.execute(
            "INSERT INTO sources
             (id, name, mount_key, raw_relative_root, created_at, updated_at)
             VALUES (?1, ?2, 'source', CAST('' AS BLOB), ?3, ?3)",
            params![id, name, created_at],
        )
        .unwrap();
    }

    fn scheduled_scope_profile(
        name: &str,
        include_future_registered: bool,
        time_of_day: &str,
    ) -> ProfileConfig {
        ProfileConfig {
            name: name.to_owned(),
            enabled: true,
            description: None,
            scope: ProfileScope {
                mode: ScopeMode::All,
                source_ids: Vec::new(),
                include_future_registered,
                include_globs: Vec::new(),
                exclude_globs: Vec::new(),
                file_kind_policy: FileKindPolicy::RegularOnly,
            },
            sections: vec![ProfileSection::Folders],
            owner_ids_to_list: Vec::new(),
            duplicates: ProfileDuplicates::default(),
            rank_limit: 200,
            schedule: ProfileSchedule {
                schedule_type: ScheduleTypeInput::Daily,
                expression: None,
                time_of_day: Some(time_of_day.to_owned()),
                days_of_week: Vec::new(),
                day_of_month: None,
                timezone: Some("UTC".to_owned()),
                misfire_policy: crate::profile::MisfirePolicyInput::Skip,
                overlap_policy: OverlapPolicyInput::Skip,
            },
            retention: ProfileRetention::default(),
            notifications: ProfileNotifications::default(),
            resources: ProfileResources::default(),
        }
    }

    #[test]
    fn scheduler_persists_profile_creation_scoped_source_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let mut config = supervisor_test_config(root.path());
        config.resources.max_queued_scans = 2;
        let (state, guard) = crate::httpapi::AppState::start(&config).unwrap();
        let due_at = chrono::Utc::now()
            .checked_sub_signed(ChronoDuration::minutes(1))
            .unwrap()
            .with_second(0)
            .unwrap()
            .with_nanosecond(0)
            .unwrap();
        let time_of_day = due_at.format("%H:%M").to_string();
        let due_at_text = due_at.to_rfc3339();
        let (fixed_profile_id, future_profile_id) = state
            .writer
            .call_blocking(move |conn| {
                insert_scope_source(conn, "before", "创建前", "2000-01-01T00:00:00.000Z");
                insert_scope_source(conn, "after", "创建后", "2999-01-01T00:00:00.000Z");
                insert_scope_source(conn, "disabled", "已停用", "2000-01-01T00:00:00.000Z");
                conn.execute(
                    "UPDATE sources SET disabled_at = '2001-01-01T00:00:00.000Z'
                     WHERE id = 'disabled'",
                    [],
                )
                .unwrap();
                let fixed = profile::create(
                    conn,
                    scheduled_scope_profile("固定范围", false, &time_of_day),
                )?;
                let future = profile::create(
                    conn,
                    scheduled_scope_profile("包含未来", true, &time_of_day),
                )?;
                conn.execute(
                    "UPDATE profiles SET next_run_at = ?2 WHERE id IN (?1, ?3)",
                    params![&fixed.id, due_at_text, &future.id],
                )
                .map_err(|error| internal(format!("准备调度测试到期游标失败: {error}")))?;
                Ok((fixed.id, future.id))
            })
            .unwrap();

        schedule_once(&state).unwrap();
        let snapshots = state
            .writer
            .call_blocking(move |conn| {
                let read = |profile_id: &str| -> AppResult<Value> {
                    let params_json: String = conn
                        .query_row(
                            "SELECT params_json FROM jobs WHERE profile_id = ?1",
                            [profile_id],
                            |row| row.get(0),
                        )
                        .map_err(|error| internal(format!("读取调度测试任务失败: {error}")))?;
                    serde_json::from_str(&params_json)
                        .map_err(|error| internal(format!("解析调度测试快照失败: {error}")))
                };
                Ok((read(&fixed_profile_id)?, read(&future_profile_id)?))
            })
            .unwrap();
        drop(state);
        guard.shutdown();

        assert_eq!(snapshots.0["source_ids"], json!(["before"]));
        assert_eq!(snapshots.1["source_ids"], json!(["before", "after"]));
    }

    #[test]
    fn scheduler_respects_configured_scan_queue_limit() {
        let root = tempfile::tempdir().unwrap();
        let config = supervisor_test_config(root.path());
        let (state, guard) = crate::httpapi::AppState::start(&config).unwrap();
        let due_at = chrono::Utc::now()
            .checked_sub_signed(ChronoDuration::minutes(1))
            .unwrap()
            .with_second(0)
            .unwrap()
            .with_nanosecond(0)
            .unwrap();
        let time_of_day = due_at.format("%H:%M").to_string();
        let due_at_text = due_at.to_rfc3339();
        state
            .writer
            .call_blocking(move |conn| {
                for name in ["队列一", "队列二"] {
                    let record =
                        profile::create(conn, scheduled_scope_profile(name, false, &time_of_day))?;
                    conn.execute(
                        "UPDATE profiles SET next_run_at = ?2 WHERE id = ?1",
                        params![record.id, &due_at_text],
                    )
                    .map_err(|error| internal(format!("准备队列上限测试游标失败: {error}")))?;
                }
                Ok(())
            })
            .unwrap();

        let error = schedule_once(&state).unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceBusy);
        let queued: i64 = state
            .writer
            .call_blocking(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM jobs WHERE type = 'scan' AND state = 'QUEUED'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| internal(format!("读取队列上限测试结果失败: {error}")))
            })
            .unwrap();
        drop(state);
        guard.shutdown();

        assert_eq!(queued, 1);
    }

    #[test]
    fn scheduler_persists_dst_spring_forward_skip_without_enqueuing_a_job() {
        let root = tempfile::tempdir().unwrap();
        let config = supervisor_test_config(root.path());
        let (state, guard) = crate::httpapi::AppState::start(&config).unwrap();
        let profile_id = state
            .writer
            .call_blocking(|conn| {
                let mut profile = scheduled_scope_profile("DST", false, "02:30");
                profile.schedule.timezone = Some("America/New_York".to_owned());
                let record = profile::create(conn, profile)?;
                conn.execute(
                    "UPDATE profiles SET next_run_at = '2024-03-09T07:30:00Z' WHERE id = ?1",
                    [&record.id],
                )
                .map_err(|error| internal(format!("准备 DST 调度游标失败: {error}")))?;
                Ok(record.id)
            })
            .unwrap();

        schedule_once(&state).unwrap();
        let stored = state
            .writer
            .call_blocking(move |conn| {
                conn.query_row(
                    "SELECT occurrence_key, job_id, planned_at, skipped_nonexistent
                     FROM schedule_occurrences WHERE profile_id = ?1",
                    [&profile_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .map_err(|error| internal(format!("读取 DST 跳过记录失败: {error}")))
            })
            .unwrap();
        drop(state);
        guard.shutdown();

        assert_eq!(stored.0, "2024-03-10T02:30");
        assert_eq!(stored.1, None);
        assert_eq!(stored.2, None);
        assert_eq!(stored.3, 1);
    }

    #[cfg(target_os = "linux")]
    fn cleanup_test_entry(
        root: &fssecure::SecureRoot,
        entry_id: i64,
        path: &[u8],
    ) -> crate::cleanup::CleanupEntry {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        use std::os::unix::ffi::OsStrExt;

        let raw_path = std::ffi::OsStr::from_bytes(path);
        let stat = root.stat(raw_path).unwrap();
        let opened = root
            .open_file(raw_path, fssecure::OpenOptions::default())
            .unwrap();
        let mut file = std::fs::File::from(opened.fd);
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64];
        loop {
            let count = file.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }

        crate::cleanup::CleanupEntry {
            entry_id,
            source_id: "source".to_owned(),
            group_id: "group".to_owned(),
            raw_path: path.to_vec(),
            size_bytes: stat.size_bytes,
            identity: stat.identity,
            nlink: stat.nlink,
            kind: stat.kind,
            protected: false,
            content_sha256: hex::encode(hasher.finalize()),
            mtime: stat.mtime,
            ctime: stat.ctime,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn operation_supervisor_executes_valid_queued_cleanup_job() {
        let root = tempfile::tempdir().unwrap();
        let mut config = supervisor_test_config(root.path());
        config.security.allow_write_operations = true;
        config.approved_mounts[0].writable = true;
        let source_dir = config.approved_mounts[0].container_path.clone();
        std::fs::write(source_dir.join("keep"), b"same content").unwrap();
        std::fs::write(source_dir.join("target"), b"same content").unwrap();

        let (state, guard) = crate::httpapi::AppState::start(&config).unwrap();
        let source_root = fssecure::SecureRoot::open(source_dir.as_os_str()).unwrap();
        let journal_root = fssecure::SecureRoot::open(config.storage.data_dir.as_os_str()).unwrap();
        let source_identity_json = json!({
            "device_id": source_root
                .stat(std::ffi::OsStr::new(""))
                .unwrap()
                .identity
                .device_id
                .to_string(),
        })
        .to_string();
        let keep = cleanup_test_entry(&source_root, 1, b"keep");
        let target = cleanup_test_entry(&source_root, 2, b"target");
        let reservation = state
            .writer
            .call_blocking(move |conn| {
                let admin = auth::create_admin(conn, "admin", "a sufficiently long password")?;
                let now = auth::now_rfc3339();
                conn.execute(
                    "INSERT INTO sources
                     (id, name, mount_key, write_enabled, protected, identity_status,
                      identity_epoch, identity_json, created_at, updated_at)
                     VALUES ('source', 'source', 'source', 1, 0, 'verified', 1, ?2, ?1, ?1)",
                    params![now, source_identity_json],
                )
                .map_err(|e| internal(format!("创建清理测试数据源失败: {e}")))?;
                conn.execute(
                    "INSERT INTO app_settings (key, value_json, updated_at)
                     VALUES ('cleanup_signing_key', ?1, ?2)",
                    params![serde_json::to_string(&hex::encode(b"key")).unwrap(), now],
                )
                .map_err(|e| internal(format!("创建清理测试签名密钥失败: {e}")))?;
                let roots = crate::cleanup::CleanupRoots {
                    source_roots: std::collections::BTreeMap::from([(
                        String::from("source"),
                        &source_root,
                    )]),
                    journal_root: &journal_root,
                };
                let plan = crate::cleanup::preview(
                    conn,
                    "report",
                    &admin.id,
                    &[crate::cleanup::CleanupGroupSelection {
                        group_id: String::from("group"),
                        members: vec![keep, target],
                        keep_entry_ids: vec![1],
                        target_entry_ids: vec![2],
                    }],
                    &roots,
                    b"key",
                )?;
                let reauth = auth::create_reauth_token(conn, &admin.id, 5)?;
                crate::cleanup::reserve_quarantine(
                    conn,
                    &plan.id,
                    &admin.id,
                    &reauth,
                    crate::cleanup::QUARANTINE_CONFIRMATION,
                    "runtime-supervisor-cleanup",
                    b"key",
                )
            })
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let loop_state = state.clone();
        let loop_stop = stop.clone();
        let join = std::thread::spawn(move || operation_loop(loop_state, loop_stop));

        let mut final_job = None;
        for _ in 0..100 {
            let current = state
                .writer
                .call_blocking({
                    let job_id = reservation.job_id.clone();
                    move |conn| jobs::get_job(conn, &job_id)
                })
                .unwrap();
            if current.state.is_terminal() {
                final_job = Some(current);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        stop.store(true, Ordering::SeqCst);
        join.join().unwrap();
        let final_job = final_job.expect("cleanup job did not reach a terminal state");
        let stored = state
            .writer
            .call_blocking({
                let action_id = reservation.action_id.clone();
                move |conn| {
                    let plan_state: String = conn
                        .query_row(
                            "SELECT state FROM cleanup_plans WHERE id = (
                                SELECT plan_id FROM cleanup_items WHERE action_id = ?1 LIMIT 1
                            )",
                            [&action_id],
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
                    Ok((plan_state, item_state))
                }
            })
            .unwrap();
        drop(state);
        guard.shutdown();

        assert_eq!(final_job.state, JobState::Succeeded);
        assert_eq!(stored.0, "completed");
        assert_eq!(stored.1, "QUARANTINED");
        assert!(!source_dir.join("target").exists());
        assert!(source_dir.join(".nas-analyzer-quarantine").is_dir());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn operation_supervisor_keeps_cleanup_runtime_failure_interrupted() {
        let root = tempfile::tempdir().unwrap();
        let config = supervisor_test_config(root.path());
        let source_dir = config.approved_mounts[0].container_path.clone();
        std::fs::write(source_dir.join("keep"), b"same content").unwrap();
        std::fs::write(source_dir.join("target"), b"same content").unwrap();

        let (state, guard) = crate::httpapi::AppState::start(&config).unwrap();
        let source_root = fssecure::SecureRoot::open(source_dir.as_os_str()).unwrap();
        let journal_root = fssecure::SecureRoot::open(config.storage.data_dir.as_os_str()).unwrap();
        let source_identity_json = json!({
            "device_id": source_root
                .stat(std::ffi::OsStr::new(""))
                .unwrap()
                .identity
                .device_id
                .to_string(),
        })
        .to_string();
        let keep = cleanup_test_entry(&source_root, 1, b"keep");
        let target = cleanup_test_entry(&source_root, 2, b"target");
        let reservation = state
            .writer
            .call_blocking(move |conn| {
                let admin = auth::create_admin(conn, "admin", "a sufficiently long password")?;
                let now = auth::now_rfc3339();
                conn.execute(
                    "INSERT INTO sources
                     (id, name, mount_key, write_enabled, protected, identity_status,
                      identity_epoch, identity_json, created_at, updated_at)
                     VALUES ('source', 'source', 'source', 1, 0, 'verified', 1, ?2, ?1, ?1)",
                    params![now, source_identity_json],
                )
                .map_err(|e| internal(format!("创建清理测试数据源失败: {e}")))?;
                conn.execute(
                    "INSERT INTO app_settings (key, value_json, updated_at)
                     VALUES ('cleanup_signing_key', ?1, ?2)",
                    params![serde_json::to_string(&hex::encode(b"key")).unwrap(), now],
                )
                .map_err(|e| internal(format!("创建清理测试签名密钥失败: {e}")))?;
                let roots = crate::cleanup::CleanupRoots {
                    source_roots: std::collections::BTreeMap::from([(
                        String::from("source"),
                        &source_root,
                    )]),
                    journal_root: &journal_root,
                };
                let plan = crate::cleanup::preview(
                    conn,
                    "report",
                    &admin.id,
                    &[crate::cleanup::CleanupGroupSelection {
                        group_id: String::from("group"),
                        members: vec![keep, target],
                        keep_entry_ids: vec![1],
                        target_entry_ids: vec![2],
                    }],
                    &roots,
                    b"key",
                )?;
                let reauth = auth::create_reauth_token(conn, &admin.id, 5)?;
                crate::cleanup::reserve_quarantine(
                    conn,
                    &plan.id,
                    &admin.id,
                    &reauth,
                    crate::cleanup::QUARANTINE_CONFIRMATION,
                    "runtime-supervisor-cleanup-readonly",
                    b"key",
                )
            })
            .unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let loop_state = state.clone();
        let loop_stop = stop.clone();
        let join = std::thread::spawn(move || operation_loop(loop_state, loop_stop));

        let mut final_job = None;
        for _ in 0..100 {
            let current = state
                .writer
                .call_blocking({
                    let job_id = reservation.job_id.clone();
                    move |conn| jobs::get_job(conn, &job_id)
                })
                .unwrap();
            if current.state.is_terminal() {
                final_job = Some(current);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        stop.store(true, Ordering::SeqCst);
        join.join().unwrap();
        let final_job = final_job.expect("cleanup job did not reach a terminal state");
        let stored = state
            .writer
            .call_blocking({
                let action_id = reservation.action_id.clone();
                move |conn| {
                    let plan_state: String = conn
                        .query_row(
                            "SELECT state FROM cleanup_plans WHERE id = (
                                SELECT plan_id FROM cleanup_items WHERE action_id = ?1 LIMIT 1
                            )",
                            [&action_id],
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
                    Ok((plan_state, item_state))
                }
            })
            .unwrap();
        drop(state);
        guard.shutdown();

        assert_eq!(final_job.state, JobState::Interrupted);
        assert_eq!(
            final_job
                .error_json
                .as_ref()
                .and_then(|value| value["code"].as_str()),
            Some("INTERRUPTED")
        );
        assert_eq!(stored.0, "executing");
        assert_eq!(stored.1, "FAILED");
        assert!(source_dir.join("target").exists());
    }

    #[test]
    fn operation_supervisor_dispatches_cleanup_and_finishes_invalid_job() {
        let root = tempfile::tempdir().unwrap();
        let config = supervisor_test_config(root.path());
        let (state, guard) = crate::httpapi::AppState::start(&config).unwrap();
        let job = state
            .writer
            .call_blocking(|conn| {
                jobs::create_job(
                    conn,
                    JobType::CleanupAction,
                    None,
                    None,
                    &json!({"action": "unsupported"}),
                    None,
                    1,
                )
            })
            .unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let loop_state = state.clone();
        let loop_stop = stop.clone();
        let join = std::thread::spawn(move || operation_loop(loop_state, loop_stop));

        let mut final_job = None;
        for _ in 0..100 {
            let current = state
                .writer
                .call_blocking({
                    let job_id = job.id.clone();
                    move |conn| jobs::get_job(conn, &job_id)
                })
                .unwrap();
            if current.state.is_terminal() {
                final_job = Some(current);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        stop.store(true, Ordering::SeqCst);
        join.join().unwrap();
        drop(state);
        guard.shutdown();

        let final_job = final_job.expect("cleanup job did not reach a terminal state");
        assert_eq!(final_job.state, JobState::Failed);
        assert_eq!(
            final_job
                .error_json
                .as_ref()
                .and_then(|value| value["code"].as_str()),
            Some(ErrorCode::ValidationFailed.as_str())
        );
    }

    #[test]
    fn valid_cleanup_failure_stays_interrupted_for_startup_recovery() {
        let root = tempfile::tempdir().unwrap();
        let config = supervisor_test_config(root.path());
        let (state, guard) = crate::httpapi::AppState::start(&config).unwrap();
        let job = state
            .writer
            .call_blocking(|conn| {
                jobs::create_job(
                    conn,
                    JobType::CleanupAction,
                    None,
                    None,
                    &json!({
                        "action": "quarantine",
                        "action_id": "action-1",
                        "plan_id": "plan-1",
                        "actor_id": "actor-1"
                    }),
                    None,
                    1,
                )
            })
            .unwrap();
        let claimed = state
            .writer
            .call_blocking(jobs::claim_next_operation)
            .unwrap()
            .unwrap();
        let error = AppError::new(ErrorCode::FileChanged, "清理候选文件已变化");
        finish_cleanup_operation_error(&state, &claimed, &error).unwrap();

        let stored = state
            .writer
            .call_blocking({
                let job_id = job.id.clone();
                move |conn| jobs::get_job(conn, &job_id)
            })
            .unwrap();
        drop(state);
        guard.shutdown();

        assert_eq!(stored.state, JobState::Interrupted);
        assert_eq!(stored.error_json.unwrap()["code"], "INTERRUPTED");
    }

    #[test]
    fn automatic_purge_preflight_failure_finishes_without_startup_recovery() {
        let root = tempfile::tempdir().unwrap();
        let config = supervisor_test_config(root.path());
        let (state, guard) = crate::httpapi::AppState::start(&config).unwrap();
        let job = state
            .writer
            .call_blocking(|conn| {
                jobs::create_job(
                    conn,
                    JobType::CleanupAction,
                    None,
                    None,
                    &json!({
                        "action": "auto_purge",
                        "action_id": "action-1",
                        "plan_id": "plan-1",
                        "item_id": "item-1",
                        "actor_id": "actor-1"
                    }),
                    Some("auto-purge:id:item-1"),
                    1,
                )
            })
            .unwrap();
        let claimed = state
            .writer
            .call_blocking(jobs::claim_next_operation)
            .unwrap()
            .unwrap();
        let error = AppError::new(ErrorCode::ReadOnlyMode, "自动清理未获写入许可");
        finish_cleanup_operation_error(&state, &claimed, &error).unwrap();

        let stored = state
            .writer
            .call_blocking({
                let job_id = job.id.clone();
                move |conn| jobs::get_job(conn, &job_id)
            })
            .unwrap();
        drop(state);
        guard.shutdown();

        assert_eq!(stored.state, JobState::Failed);
        assert_eq!(
            stored.error_json.unwrap()["code"],
            ErrorCode::ReadOnlyMode.as_str()
        );
    }

    #[test]
    fn cancelling_cleanup_failure_is_finished_as_cancelled() {
        let root = tempfile::tempdir().unwrap();
        let config = supervisor_test_config(root.path());
        let (state, guard) = crate::httpapi::AppState::start(&config).unwrap();
        let job = state
            .writer
            .call_blocking(|conn| {
                jobs::create_job(
                    conn,
                    JobType::CleanupAction,
                    None,
                    None,
                    &json!({
                        "action": "quarantine",
                        "action_id": "action-1",
                        "plan_id": "plan-1",
                        "actor_id": "actor-1"
                    }),
                    None,
                    1,
                )
            })
            .unwrap();
        let claimed = state
            .writer
            .call_blocking(jobs::claim_next_operation)
            .unwrap()
            .unwrap();
        state
            .writer
            .call_blocking({
                let job_id = job.id.clone();
                move |conn| jobs::control_job(conn, &job_id, jobs::JobControlAction::Cancel)
            })
            .unwrap();
        let error = AppError::new(ErrorCode::FileChanged, "清理候选文件已变化");
        finish_cleanup_operation_error(&state, &claimed, &error).unwrap();

        let stored = state
            .writer
            .call_blocking({
                let job_id = job.id.clone();
                move |conn| jobs::get_job(conn, &job_id)
            })
            .unwrap();
        drop(state);
        guard.shutdown();

        assert_eq!(stored.state, JobState::Cancelled);
    }

    #[test]
    fn sustained_pressure_requires_three_samples_and_resets() {
        let controller = MemoryBudgetController::new(64, 128).unwrap();
        let over = 128_u64 * 1024 * 1024 + 1;
        controller.record_sample(Some(over), Some(over));
        assert!(!controller.worker_should_stop());
        controller.record_sample(Some(over), Some(over));
        assert!(!controller.worker_should_stop());
        controller.record_sample(Some(over), Some(over));
        assert!(controller.worker_should_stop());

        controller.record_sample(Some(1), Some(1));
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.api_over_budget_samples, 0);
        assert_eq!(snapshot.worker_over_budget_samples, 0);
        assert_eq!(snapshot.api_pressure, MemoryPressure::WithinBudget);
        assert_eq!(snapshot.worker_pressure, MemoryPressure::WithinBudget);
    }

    #[test]
    fn missing_rss_is_reported_as_unknown_without_pressure() {
        let controller = MemoryBudgetController::new(64, 128).unwrap();
        controller.record_sample(None, None);
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.api_pressure, MemoryPressure::Unknown);
        assert_eq!(snapshot.worker_pressure, MemoryPressure::Unknown);
        assert!(!controller.worker_should_stop());
    }
}
