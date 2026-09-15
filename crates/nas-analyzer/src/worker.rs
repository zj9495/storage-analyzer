//! Supervised scan worker process and its bounded IPC protocol (spec 15.2,
//! 15.6, 16.1).
//!
//! The serving process is the only owner of the control database and the
//! data-directory instance lock.  It claims a durable scan job, snapshots all
//! control-plane inputs, and starts this same executable with the `worker`
//! subcommand.  The child receives that typed snapshot over length-bounded
//! stdin/stdout frames, writes only the run index and immutable report files,
//! and returns a typed result.  Progress is persisted by the parent and
//! pause/resume/cancel are read from the durable job state and forwarded over
//! the bounded control pipe.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufReader as StdBufReader, Read, Write};
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, bounded};
use parking_lot::Mutex;
use rusqlite::Connection;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::category::CategoryRuleset;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::httpapi::AppState;
use crate::jobs::{self, Job, JobPhase, JobState, JobType};
use crate::profile::{self, ProfileConfig};
use crate::resource::FileOpenBudget;
use crate::scanner::{self, ScanConfig, ScanControl, ScanPhase, ScanSource};
use crate::source::{self, Source};
use crate::volume::{SampleQuality, VolumeSample};

/// Maximum serialized IPC payload.  The length prefix is checked before any
/// allocation and before every write; no message can make the protocol
/// consume an unbounded frame.
pub(crate) const IPC_MAX_FRAME_BYTES: usize = 1024 * 1024;
const IPC_OUTPUT_QUEUE_BOUND: usize = 2048;
const SUPERVISOR_POLL: Duration = Duration::from_millis(100);

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

fn validation(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, msg)
}

// ---- typed wire contract -------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ParentMessage {
    Start(Box<WorkerRequest>),
    Control(WorkerCommand),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkerCommand {
    Pause,
    Resume,
    Cancel,
    Close,
}

#[derive(Debug, Serialize, Deserialize)]
enum WorkerMessage {
    Ready {
        job_id: String,
    },
    Progress {
        job_id: String,
        progress: scanner::ScanProgress,
    },
    Phase {
        job_id: String,
        phase: JobPhase,
    },
    Finished {
        result: Box<WorkerResult>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerRequest {
    pub job: WorkerJob,
    pub scan: WorkerScanConfig,
    pub profile: ProfileConfig,
    pub report_inputs: WorkerReportInputs,
    pub scope_fingerprint: String,
    pub ruleset_version: u32,
    pub runtime: WorkerRuntimeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerJob {
    pub id: String,
    pub run_id: String,
    pub profile_id: String,
    pub profile_version: i64,
    pub params_json: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerRuntimeConfig {
    pub data_dir: PathBuf,
    pub api_memory_budget_mib: u32,
    pub worker_memory_budget_mib: u32,
    pub hash_workers: u32,
    pub hash_read_limit_mib_s: u32,
    pub max_open_files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerScanConfig {
    pub sources: Vec<WorkerScanSource>,
    pub ruleset: CategoryRuleset,
    pub exclude_globs: Vec<String>,
    pub include_globs: Vec<String>,
    pub include_hidden: bool,
    pub skip_system_dirs_preset: bool,
    pub metadata_workers: u32,
    pub batch_rows: usize,
    pub frontier_memory_cap: usize,
    pub file_kind_policy: profile::FileKindPolicy,
    pub max_open_files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerScanSource {
    pub source: WorkerSource,
    pub mount_path: PathBuf,
}

/// `Source` deliberately does not implement serde because its raw-byte path
/// is not an API DTO.  This private wire snapshot preserves every field and
/// reconstructs the domain value in the child without using a display path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerSource {
    pub id: String,
    pub name: String,
    pub mount_key: String,
    pub raw_relative_root: Vec<u8>,
    pub volume_id: Option<String>,
    pub storage_kind: source::StorageKind,
    pub read_policy: source::ReadPolicy,
    pub write_enabled: bool,
    pub protected: bool,
    pub exclusions: Vec<String>,
    pub identity_status: source::IdentityStatus,
    pub identity_epoch: i64,
    pub identity_json: Value,
    pub availability: source::Availability,
    pub atime_quality: source::AtimeQuality,
    pub disabled_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerReportInputs {
    pub volume_samples: Vec<WorkerVolumeSample>,
    pub quotas: Vec<WorkerQuotaSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerVolumeSample {
    pub volume_id: String,
    pub sample_time: String,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub reserved_diff_bytes: Option<u64>,
    pub quality: WorkerSampleQuality,
    pub error: Option<String>,
    pub inserted: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WorkerSampleQuality {
    Ok,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerQuotaSnapshot {
    pub principal_namespace: String,
    pub principal_uid: i64,
    pub scope_kind: String,
    pub scope_id: String,
    pub metric: String,
    pub origin: String,
    pub limit_state: String,
    pub limit_bytes: Option<String>,
    pub used_bytes: Option<String>,
    pub observed_at: String,
    pub expires_at: Option<String>,
    pub provider_label: String,
    pub stale: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WorkerStatus {
    Succeeded,
    Partial,
    Failed,
}

impl WorkerStatus {
    fn as_report_status(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Partial => "partial",
            Self::Failed => "failed",
        }
    }

    fn as_job_state(self) -> JobState {
        match self {
            Self::Succeeded => JobState::Succeeded,
            Self::Partial => JobState::Partial,
            Self::Failed => JobState::Failed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerPublishedReport {
    pub id: String,
    pub run_id: String,
    pub manifest_path: PathBuf,
    pub status: WorkerStatus,
    pub scan_started_at: Option<String>,
    pub scan_finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerSourceUnavailable {
    pub source_id: String,
    pub error_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerResult {
    pub job_id: String,
    pub run_id: String,
    pub status: WorkerStatus,
    pub report: Option<WorkerPublishedReport>,
    pub progress: scanner::ScanProgress,
    pub error: Option<WorkerError>,
    pub resource_budget_exceeded: bool,
    #[serde(default)]
    pub source_unavailable: Vec<WorkerSourceUnavailable>,
}

impl From<&Source> for WorkerSource {
    fn from(source: &Source) -> Self {
        Self {
            id: source.id.clone(),
            name: source.name.clone(),
            mount_key: source.mount_key.clone(),
            raw_relative_root: source.raw_relative_root.clone(),
            volume_id: source.volume_id.clone(),
            storage_kind: source.storage_kind,
            read_policy: source.read_policy,
            write_enabled: source.write_enabled,
            protected: source.protected,
            exclusions: source.exclusions.clone(),
            identity_status: source.identity_status,
            identity_epoch: source.identity_epoch,
            identity_json: source.identity_json.clone(),
            availability: source.availability,
            atime_quality: source.atime_quality,
            disabled_at: source.disabled_at.clone(),
            created_at: source.created_at.clone(),
            updated_at: source.updated_at.clone(),
        }
    }
}

impl From<WorkerSource> for Source {
    fn from(source: WorkerSource) -> Self {
        Self {
            id: source.id,
            name: source.name,
            mount_key: source.mount_key,
            raw_relative_root: source.raw_relative_root,
            volume_id: source.volume_id,
            storage_kind: source.storage_kind,
            read_policy: source.read_policy,
            write_enabled: source.write_enabled,
            protected: source.protected,
            exclusions: source.exclusions,
            identity_status: source.identity_status,
            identity_epoch: source.identity_epoch,
            identity_json: source.identity_json,
            availability: source.availability,
            atime_quality: source.atime_quality,
            disabled_at: source.disabled_at,
            created_at: source.created_at,
            updated_at: source.updated_at,
        }
    }
}

impl From<&ScanConfig> for WorkerScanConfig {
    fn from(config: &ScanConfig) -> Self {
        Self {
            sources: config
                .sources
                .iter()
                .map(|scan| WorkerScanSource {
                    source: WorkerSource::from(&scan.source),
                    mount_path: scan.mount_path.clone(),
                })
                .collect(),
            ruleset: config.ruleset.clone(),
            exclude_globs: config.exclude_globs.clone(),
            include_globs: config.include_globs.clone(),
            include_hidden: config.include_hidden,
            skip_system_dirs_preset: config.skip_system_dirs_preset,
            metadata_workers: config.metadata_workers,
            batch_rows: config.batch_rows,
            frontier_memory_cap: config.frontier_memory_cap,
            file_kind_policy: config.file_kind_policy.clone(),
            max_open_files: config.max_open_files,
        }
    }
}

impl WorkerScanConfig {
    fn into_scan_config(self) -> ScanConfig {
        ScanConfig {
            sources: self
                .sources
                .into_iter()
                .map(|scan| ScanSource {
                    source: scan.source.into(),
                    mount_path: scan.mount_path,
                })
                .collect(),
            ruleset: self.ruleset,
            exclude_globs: self.exclude_globs,
            include_globs: self.include_globs,
            include_hidden: self.include_hidden,
            skip_system_dirs_preset: self.skip_system_dirs_preset,
            metadata_workers: self.metadata_workers,
            batch_rows: self.batch_rows,
            frontier_memory_cap: self.frontier_memory_cap,
            file_kind_policy: self.file_kind_policy,
            max_open_files: self.max_open_files,
            file_open_budget: None,
        }
    }
}

impl From<&VolumeSample> for WorkerVolumeSample {
    fn from(sample: &VolumeSample) -> Self {
        Self {
            volume_id: sample.volume_id.clone(),
            sample_time: sample.sample_time.clone(),
            total_bytes: sample.total_bytes,
            free_bytes: sample.free_bytes,
            available_bytes: sample.available_bytes,
            used_bytes: sample.used_bytes,
            reserved_diff_bytes: sample.reserved_diff_bytes,
            quality: match sample.quality {
                SampleQuality::Ok => WorkerSampleQuality::Ok,
                SampleQuality::Error => WorkerSampleQuality::Error,
            },
            error: sample.error.clone(),
            inserted: sample.inserted,
        }
    }
}

impl From<WorkerVolumeSample> for VolumeSample {
    fn from(sample: WorkerVolumeSample) -> Self {
        Self {
            volume_id: sample.volume_id,
            sample_time: sample.sample_time,
            total_bytes: sample.total_bytes,
            free_bytes: sample.free_bytes,
            available_bytes: sample.available_bytes,
            used_bytes: sample.used_bytes,
            reserved_diff_bytes: sample.reserved_diff_bytes,
            quality: match sample.quality {
                WorkerSampleQuality::Ok => SampleQuality::Ok,
                WorkerSampleQuality::Error => SampleQuality::Error,
            },
            error: sample.error,
            inserted: sample.inserted,
        }
    }
}

impl From<&crate::report::QuotaSnapshot> for WorkerQuotaSnapshot {
    fn from(quota: &crate::report::QuotaSnapshot) -> Self {
        Self {
            principal_namespace: quota.principal_namespace.clone(),
            principal_uid: quota.principal_uid,
            scope_kind: quota.scope_kind.clone(),
            scope_id: quota.scope_id.clone(),
            metric: quota.metric.clone(),
            origin: quota.origin.clone(),
            limit_state: quota.limit_state.clone(),
            limit_bytes: quota.limit_bytes.clone(),
            used_bytes: quota.used_bytes.clone(),
            observed_at: quota.observed_at.clone(),
            expires_at: quota.expires_at.clone(),
            provider_label: quota.provider_label.clone(),
            stale: quota.stale,
        }
    }
}

impl From<WorkerQuotaSnapshot> for crate::report::QuotaSnapshot {
    fn from(quota: WorkerQuotaSnapshot) -> Self {
        Self {
            principal_namespace: quota.principal_namespace,
            principal_uid: quota.principal_uid,
            scope_kind: quota.scope_kind,
            scope_id: quota.scope_id,
            metric: quota.metric,
            origin: quota.origin,
            limit_state: quota.limit_state,
            limit_bytes: quota.limit_bytes,
            used_bytes: quota.used_bytes,
            observed_at: quota.observed_at,
            expires_at: quota.expires_at,
            provider_label: quota.provider_label,
            stale: quota.stale,
        }
    }
}

impl WorkerReportInputs {
    fn from_values(
        volume_samples: Vec<VolumeSample>,
        quotas: Vec<crate::report::QuotaSnapshot>,
    ) -> Self {
        Self {
            volume_samples: volume_samples
                .iter()
                .map(WorkerVolumeSample::from)
                .collect(),
            quotas: quotas.iter().map(WorkerQuotaSnapshot::from).collect(),
        }
    }

    fn to_values(&self) -> (Vec<VolumeSample>, Vec<crate::report::QuotaSnapshot>) {
        (
            self.volume_samples
                .clone()
                .into_iter()
                .map(VolumeSample::from)
                .collect(),
            self.quotas
                .clone()
                .into_iter()
                .map(crate::report::QuotaSnapshot::from)
                .collect(),
        )
    }
}

// ---- bounded frame codec -------------------------------------------------

struct FrameWriter {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl FrameWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(IPC_MAX_FRAME_BYTES),
            exceeded: false,
        }
    }
}

impl Write for FrameWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > IPC_MAX_FRAME_BYTES.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "worker IPC frame exceeds configured limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_frame<T: Serialize>(value: &T) -> AppResult<Vec<u8>> {
    let mut writer = FrameWriter::new();
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if writer.exceeded {
            return Err(validation(format!(
                "worker IPC 消息超过 {} 字节上限",
                IPC_MAX_FRAME_BYTES
            )));
        }
        return Err(internal(format!("编码 worker IPC 消息失败: {error}")));
    }
    if writer.bytes.is_empty() {
        return Err(validation(format!(
            "worker IPC 消息超过 {} 字节上限",
            IPC_MAX_FRAME_BYTES
        )));
    }
    Ok(writer.bytes)
}

fn write_frame<T: Serialize, W: Write>(writer: &mut W, value: &T) -> AppResult<()> {
    let payload = encode_frame(value)?;
    let length = u32::try_from(payload.len()).map_err(|_| validation("worker IPC 帧长度溢出"))?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|_| writer.write_all(&payload))
        .and_then(|_| writer.flush())
        .map_err(|error| internal(format!("写入 worker IPC 消息失败: {error}")))
}

fn read_frame<R: Read>(reader: &mut R) -> AppResult<Option<Vec<u8>>> {
    let mut first = [0_u8; 1];
    match reader.read(&mut first) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => return Err(internal("读取 worker IPC 长度前缀失败")),
        Err(error) => return Err(internal(format!("读取 worker IPC 长度前缀失败: {error}"))),
    }
    let mut rest = [0_u8; 3];
    reader
        .read_exact(&mut rest)
        .map_err(|error| internal(format!("worker IPC 长度前缀不完整: {error}")))?;
    let length = u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]) as usize;
    if length == 0 || length > IPC_MAX_FRAME_BYTES {
        return Err(validation(format!(
            "worker IPC 帧长度 {length} 超过 {} 字节上限",
            IPC_MAX_FRAME_BYTES
        )));
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| internal(format!("worker IPC 帧内容不完整: {error}")))?;
    Ok(Some(payload))
}

fn read_message<R: Read, T: DeserializeOwned>(reader: &mut R) -> AppResult<Option<T>> {
    let Some(payload) = read_frame(reader)? else {
        return Ok(None);
    };
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|error| validation(format!("worker IPC 消息类型无效: {error}")))
}

async fn write_frame_async<T: Serialize, W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &T,
) -> AppResult<()> {
    let payload = encode_frame(value)?;
    let length = u32::try_from(payload.len()).map_err(|_| validation("worker IPC 帧长度溢出"))?;
    writer
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| internal(format!("写入 worker IPC 消息失败: {error}")))?;
    writer
        .write_all(&payload)
        .await
        .map_err(|error| internal(format!("写入 worker IPC 消息失败: {error}")))?;
    writer
        .flush()
        .await
        .map_err(|error| internal(format!("刷新 worker IPC 消息失败: {error}")))
}

async fn read_frame_async<R: AsyncRead + Unpin>(reader: &mut R) -> AppResult<Option<Vec<u8>>> {
    let mut first = [0_u8; 1];
    match reader.read(&mut first).await {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => return Err(internal("读取 worker IPC 长度前缀失败")),
        Err(error) => return Err(internal(format!("读取 worker IPC 长度前缀失败: {error}"))),
    }
    let mut rest = [0_u8; 3];
    reader
        .read_exact(&mut rest)
        .await
        .map_err(|error| internal(format!("worker IPC 长度前缀不完整: {error}")))?;
    let length = u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]) as usize;
    if length == 0 || length > IPC_MAX_FRAME_BYTES {
        return Err(validation(format!(
            "worker IPC 帧长度 {length} 超过 {} 字节上限",
            IPC_MAX_FRAME_BYTES
        )));
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|error| internal(format!("worker IPC 帧内容不完整: {error}")))?;
    Ok(Some(payload))
}

async fn read_message_async<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> AppResult<Option<T>> {
    let Some(payload) = read_frame_async(reader).await? else {
        return Ok(None);
    };
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|error| validation(format!("worker IPC 消息类型无效: {error}")))
}

// ---- parent-side supervisor ----------------------------------------------

pub struct WorkerSupervisor {
    stop: Arc<AtomicBool>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl WorkerSupervisor {
    pub async fn start(state: AppState) -> AppResult<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let join = tokio::spawn(supervisor_loop(state, thread_stop));
        Ok(Self {
            stop,
            join: Some(join),
        })
    }

    pub async fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

async fn supervisor_loop(state: AppState, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::SeqCst) {
        let claimed = state.writer.call(jobs::claim_next_scan).await;
        let job = match claimed {
            Ok(Some(job)) => job,
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            Err(error) => {
                tracing::error!(error = %error.message, "领取扫描任务失败");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        let request = match build_worker_request(&state, &job).await {
            Ok(request) => request,
            Err(error) => {
                tracing::error!(job_id = %job.id, error = %error.message, "准备 worker 输入失败");
                finish_preparation_failure(&state, &job.id, error).await;
                continue;
            }
        };

        match run_worker_child(&state, &request, &stop).await {
            Ok(WorkerChildOutcome::Completed(result)) => {
                if let Err(error) = finalize_worker_result(&state, &request, *result).await {
                    tracing::error!(
                        job_id = %job.id,
                        error = %error.message,
                        "登记 worker 结果失败"
                    );
                }
            }
            Ok(WorkerChildOutcome::Interrupted(message)) => {
                mark_worker_interrupted(&state, &job.id, &message).await;
            }
            Err(error) => {
                tracing::error!(
                    job_id = %job.id,
                    error = %error.message,
                    "worker supervisor IPC 失败"
                );
                mark_worker_interrupted(&state, &job.id, &error.message).await;
            }
        }
    }
}

async fn finish_preparation_failure(state: &AppState, job_id: &str, error: AppError) {
    let error_json = json!({
        "code": error.code.as_str(),
        "message": error.message,
    });
    let error_code = error.code;
    let id = job_id.to_owned();
    if let Err(finish_error) = state
        .writer
        .call(move |conn| {
            crate::runtime::consume_operation_internal_notification(
                conn,
                &id,
                JobType::Scan,
                error_code,
            )?;
            jobs::job_finish(conn, &id, JobState::Failed, Some(&error_json)).map(|_| ())
        })
        .await
    {
        tracing::error!(
            job_id = %job_id,
            error = %finish_error.message,
            "登记 worker 准备失败状态失败"
        );
    }
}

async fn mark_worker_interrupted(state: &AppState, job_id: &str, message: &str) {
    let id = job_id.to_owned();
    let message = message.to_owned();
    if let Err(error) = state
        .writer
        .call(move |conn| jobs::interrupt_job(conn, &id, &message).map(|_| ()))
        .await
    {
        tracing::error!(job_id = %job_id, error = %error.message, "标记 worker 中断失败");
    }
}

enum WorkerChildOutcome {
    Completed(Box<WorkerResult>),
    Interrupted(String),
}

async fn run_worker_child(
    state: &AppState,
    request: &WorkerRequest,
    stop: &AtomicBool,
) -> AppResult<WorkerChildOutcome> {
    let executable = std::env::current_exe()
        .map_err(|error| internal(format!("定位 nas-analyzer worker 可执行文件失败: {error}")))?;
    let mut child = Command::new(executable)
        .arg("worker")
        .arg("--job-id")
        .arg(&request.job.id)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| internal(format!("启动 nas-analyzer worker 子进程失败: {error}")))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| internal("worker 子进程 stdout 未连接"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| internal("worker 子进程 stdin 未连接"))?;

    let (message_tx, mut message_rx) = mpsc::channel::<WorkerMessage>(IPC_OUTPUT_QUEUE_BOUND);
    let reader_task =
        tokio::spawn(async move { read_worker_messages_async(stdout, message_tx).await });

    if let Err(error) =
        write_frame_async(&mut stdin, &ParentMessage::Start(Box::new(request.clone()))).await
    {
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = reader_task.await;
        return Err(error);
    }

    let mut ready = false;
    let mut finished = None;
    let mut last_command = None;
    let mut close_sent = false;
    let mut fatal_message = None;

    loop {
        if finished.is_none() {
            if let Err(error) = forward_persisted_control(
                state,
                &request.job.id,
                stop,
                &mut last_command,
                &mut stdin,
            )
            .await
            {
                fatal_message = Some(error.message);
                break;
            }
        } else if !close_sent {
            match write_frame_async(&mut stdin, &ParentMessage::Control(WorkerCommand::Close)).await
            {
                Ok(()) => close_sent = true,
                Err(error) => {
                    fatal_message = Some(error.message);
                    break;
                }
            }
        }

        tokio::select! {
            message = message_rx.recv() => {
                match message {
                    Some(message) => {
                        if let Err(error) = handle_worker_message(
                            state,
                            request,
                            message,
                            &mut ready,
                            &mut finished,
                        ).await {
                            fatal_message = Some(error.message);
                            break;
                        }
                    }
                    None => {
                        if finished.is_some() {
                            break;
                        } else {
                            fatal_message = Some(
                                "worker IPC stdout 在 Finished 之前关闭".to_string(),
                            );
                            break;
                        }
                    }
                }
            }
            _ = tokio::time::sleep(SUPERVISOR_POLL) => {}
        }

        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => {
                fatal_message = Some(format!("读取 worker 子进程状态失败: {error}"));
                break;
            }
        }
    }

    if fatal_message.is_some() {
        let _ = child.kill().await;
    }
    let status = child
        .wait()
        .await
        .map_err(|error| internal(format!("等待 worker 子进程失败: {error}")))?;
    drop(stdin);

    while let Some(message) = message_rx.recv().await {
        if fatal_message.is_none() {
            let _ = handle_worker_message(state, request, message, &mut ready, &mut finished).await;
        }
    }

    match reader_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => fatal_message = Some(error.message),
        Err(error) => fatal_message = Some(format!("worker IPC reader task 异常退出: {error}")),
    }

    if !ready {
        fatal_message = Some("worker 子进程未发送 Ready 消息".to_string());
    }
    if !status.success() {
        fatal_message = Some(format!(
            "worker 子进程非零退出: {}",
            exit_status_text(&status)
        ));
    }
    if let Some(message) = fatal_message {
        return Ok(WorkerChildOutcome::Interrupted(message));
    }
    let Some(result) = finished else {
        return Ok(WorkerChildOutcome::Interrupted(
            "worker 子进程退出时没有最终结果".to_string(),
        ));
    };
    Ok(WorkerChildOutcome::Completed(Box::new(result)))
}

async fn read_worker_messages_async(
    stdout: impl AsyncRead + Unpin,
    message_tx: mpsc::Sender<WorkerMessage>,
) -> AppResult<()> {
    let mut reader = BufReader::new(stdout);
    while let Some(message) = read_message_async::<_, WorkerMessage>(&mut reader).await? {
        if message_tx.send(message).await.is_err() {
            return Err(internal("worker IPC 消息队列已关闭"));
        }
    }
    Ok(())
}

async fn handle_worker_message(
    state: &AppState,
    request: &WorkerRequest,
    message: WorkerMessage,
    ready: &mut bool,
    finished: &mut Option<WorkerResult>,
) -> AppResult<()> {
    match message {
        WorkerMessage::Ready { job_id } => {
            if *ready || job_id != request.job.id {
                return Err(internal("worker IPC Ready 消息与任务不匹配"));
            }
            *ready = true;
        }
        WorkerMessage::Progress { job_id, progress } => {
            if job_id != request.job.id {
                return Err(internal("worker IPC progress 消息与任务不匹配"));
            }
            persist_progress(state, &job_id, progress).await?;
        }
        WorkerMessage::Phase { job_id, phase } => {
            if job_id != request.job.id {
                return Err(internal("worker IPC phase 消息与任务不匹配"));
            }
            persist_phase(state, &job_id, phase).await;
        }
        WorkerMessage::Finished { result } => {
            let result = *result;
            if result.job_id != request.job.id
                || result.run_id != request.job.run_id
                || finished.is_some()
            {
                return Err(internal("worker IPC finished 消息与任务不匹配"));
            }
            *finished = Some(result);
        }
    }
    Ok(())
}

fn exit_status_text(status: &ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit code {code}"),
        None => "terminated by signal".to_string(),
    }
}

async fn forward_persisted_control<W>(
    state: &AppState,
    job_id: &str,
    stop: &AtomicBool,
    last_command: &mut Option<WorkerCommand>,
    stdin: &mut W,
) -> AppResult<()>
where
    W: AsyncWrite + Unpin,
{
    let id = job_id.to_owned();
    let job = state
        .writer
        .call(move |conn| jobs::get_job(conn, &id))
        .await?;
    let command = if stop.load(Ordering::SeqCst) {
        Some(WorkerCommand::Cancel)
    } else {
        match job.state {
            JobState::Pausing => Some(WorkerCommand::Pause),
            JobState::Paused if *last_command == Some(WorkerCommand::Pause) => None,
            JobState::Running if *last_command == Some(WorkerCommand::Pause) => {
                Some(WorkerCommand::Resume)
            }
            JobState::Cancelling => Some(WorkerCommand::Cancel),
            _ => None,
        }
    };
    if let Some(command) = command
        && Some(command) != *last_command
    {
        write_frame_async(stdin, &ParentMessage::Control(command)).await?;
        *last_command = Some(command);
    }
    Ok(())
}

async fn persist_progress(
    state: &AppState,
    job_id: &str,
    progress: scanner::ScanProgress,
) -> AppResult<()> {
    let value = progress_json(&progress);
    let id = job_id.to_owned();
    state
        .writer
        .call(move |conn| {
            if progress.pause_engaged {
                let _ = jobs::job_mark_paused(conn, &id);
            }
            if let Some(phase) = progress.phase {
                let _ = jobs::job_set_phase(conn, &id, map_phase(phase));
            }
            jobs::job_heartbeat(conn, &id, &value)?;
            jobs::append_event(conn, &id, "scan.progress", &value)?;
            Ok(())
        })
        .await
}

async fn persist_phase(state: &AppState, job_id: &str, phase: JobPhase) {
    let id = job_id.to_owned();
    if let Err(error) = state
        .writer
        .call(move |conn| jobs::job_set_phase(conn, &id, phase).map(|_| ()))
        .await
    {
        tracing::warn!(job_id = %job_id, error = %error.message, "持久化 worker 阶段失败");
    }
}

fn progress_json(progress: &scanner::ScanProgress) -> Value {
    json!({
        "phase": progress.phase.map(|phase| match phase {
            ScanPhase::Traversing => "ENUMERATE",
            ScanPhase::Aggregating => "AGGREGATE",
            ScanPhase::Done => "PUBLISH",
        }),
        "source_id": progress.source_id,
        "dirs_visited": progress.dirs_visited.to_string(),
        "files_seen": progress.files_seen.to_string(),
        "logical_bytes": progress.logical_bytes.to_string(),
        "error_count": progress.error_count.to_string(),
        "vanished_count": progress.vanished_count.to_string(),
        "excluded_count": progress.excluded_count.to_string(),
        "pause_engaged": progress.pause_engaged,
    })
}

fn map_phase(phase: ScanPhase) -> JobPhase {
    match phase {
        ScanPhase::Traversing => JobPhase::Enumerate,
        ScanPhase::Aggregating => JobPhase::Aggregate,
        ScanPhase::Done => JobPhase::Publish,
    }
}

/// The child never opens the control database; it only receives the typed
/// request and writes the run index/report files.
pub fn run_worker_process(job_id: &str) -> AppResult<()> {
    let stdin = std::io::stdin();
    let mut input = StdBufReader::new(stdin);
    let Some(ParentMessage::Start(request)) = read_message(&mut input)? else {
        return Err(validation("worker 未收到 Start IPC 消息"));
    };
    let request = *request;
    if request.job.id != job_id {
        return Err(validation("worker IPC job_id 与命令行 job_id 不匹配"));
    }

    let (output_tx, output_rx) = bounded::<WorkerMessage>(IPC_OUTPUT_QUEUE_BOUND);
    let output_error = Arc::new(Mutex::new(None::<String>));
    let output_error_for_thread = output_error.clone();
    let output_writer = thread::Builder::new()
        .name("worker-ipc-output-writer".into())
        .spawn(move || {
            let stdout = std::io::stdout();
            let mut stdout = std::io::BufWriter::new(stdout);
            for message in output_rx {
                if let Err(error) = write_frame(&mut stdout, &message) {
                    *output_error_for_thread.lock() = Some(error.message);
                    break;
                }
            }
        })
        .map_err(|error| internal(format!("启动 worker IPC output writer 失败: {error}")))?;

    output_tx
        .send(WorkerMessage::Ready {
            job_id: request.job.id.clone(),
        })
        .map_err(|_| internal("worker Ready 消息队列已关闭"))?;

    let (events_tx, events_rx) = bounded(IPC_OUTPUT_QUEUE_BOUND);
    let control = Arc::new(ScanControl::with_event_sender(events_tx));
    let relay_stop = Arc::new(AtomicBool::new(false));
    let relay = start_progress_relay(
        request.job.id.clone(),
        events_rx,
        output_tx.clone(),
        relay_stop.clone(),
    );

    let execution_done = Arc::new(AtomicBool::new(false));
    let control_reader_closed = Arc::new(AtomicBool::new(false));
    let protocol_failed = Arc::new(AtomicBool::new(false));
    let control_reader_done = execution_done.clone();
    let control_reader_closed_for_thread = control_reader_closed.clone();
    let protocol_failed_for_thread = protocol_failed.clone();
    let control_for_thread = control.clone();
    let control_reader = thread::Builder::new()
        .name("worker-ipc-control-reader".into())
        .spawn(move || {
            let result =
                read_control_messages(&mut input, &control_for_thread, &control_reader_done);
            if result.is_err() {
                protocol_failed_for_thread.store(true, Ordering::SeqCst);
                control_for_thread.cancel();
            }
            control_reader_closed_for_thread.store(true, Ordering::SeqCst);
        })
        .map_err(|error| internal(format!("启动 worker IPC control reader 失败: {error}")))?;

    let execution_result = execute_worker_with_budget(&request, control.clone(), output_tx.clone());
    execution_done.store(true, Ordering::SeqCst);
    relay_stop.store(true, Ordering::SeqCst);
    if relay.join().is_err() {
        return Err(internal("worker progress relay 线程异常退出"));
    }

    let result = match execution_result {
        Ok(result) => result,
        Err(error) => {
            drop(output_tx);
            let _ = output_writer.join();
            return Err(error);
        }
    };
    output_tx
        .send(WorkerMessage::Finished {
            result: Box::new(result),
        })
        .map_err(|_| internal("worker Finished 消息队列已关闭"))?;
    drop(output_tx);
    if output_writer.join().is_err() {
        return Err(internal("worker IPC output writer 线程异常退出"));
    }

    while !control_reader_closed.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(10));
    }
    if control_reader.join().is_err() {
        return Err(internal("worker IPC control reader 线程异常退出"));
    }

    if let Some(error) = output_error.lock().clone() {
        return Err(internal(error));
    }
    if protocol_failed.load(Ordering::SeqCst) {
        return Err(internal("worker control IPC 协议失败"));
    }
    Ok(())
}

fn read_control_messages<R: Read>(
    reader: &mut R,
    control: &ScanControl,
    execution_done: &AtomicBool,
) -> AppResult<()> {
    while let Some(message) = read_message::<_, ParentMessage>(reader)? {
        match message {
            ParentMessage::Control(WorkerCommand::Pause) => control.pause(),
            ParentMessage::Control(WorkerCommand::Resume) => control.resume(),
            ParentMessage::Control(WorkerCommand::Cancel) => control.cancel(),
            ParentMessage::Control(WorkerCommand::Close) => return Ok(()),
            ParentMessage::Start(_) => return Err(validation("worker 收到重复 Start IPC 消息")),
        }
    }
    if !execution_done.load(Ordering::SeqCst) {
        control.cancel();
    }
    Ok(())
}

fn start_progress_relay(
    job_id: String,
    events: Receiver<scanner::ProgressEvent>,
    output_tx: Sender<WorkerMessage>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("worker-progress-relay".into())
        .spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match events.recv_timeout(Duration::from_millis(100)) {
                    Ok(progress) => {
                        if output_tx
                            .send(WorkerMessage::Progress {
                                job_id: job_id.clone(),
                                progress,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .expect("worker progress relay thread must start")
}

fn execute_worker_with_budget(
    request: &WorkerRequest,
    control: Arc<ScanControl>,
    output_tx: Sender<WorkerMessage>,
) -> AppResult<WorkerResult> {
    let memory_budget = crate::runtime::MemoryBudgetController::new(
        request.runtime.api_memory_budget_mib,
        request.runtime.worker_memory_budget_mib,
    )?;
    let watcher_stop = Arc::new(AtomicBool::new(false));
    let worker_budget_exceeded = Arc::new(AtomicBool::new(false));
    let watcher_stop_for_thread = watcher_stop.clone();
    let budget_for_thread = memory_budget.clone();
    let control_for_thread = control.clone();
    let exceeded_for_thread = worker_budget_exceeded.clone();
    let watcher = thread::Builder::new()
        .name("worker-memory-budget".into())
        .spawn(move || {
            while !watcher_stop_for_thread.load(Ordering::SeqCst) {
                if let Err(error) = budget_for_thread.sample_now() {
                    tracing::warn!(error = %error.message, "读取 worker 内存预算观测失败");
                }
                if budget_for_thread.worker_should_stop() {
                    exceeded_for_thread.store(true, Ordering::SeqCst);
                    control_for_thread.cancel();
                    break;
                }
                thread::sleep(Duration::from_secs(1));
            }
        })
        .map_err(|error| internal(format!("启动 worker 预算监测失败: {error}")))?;

    let result = execute_worker_job(request, &control, &worker_budget_exceeded, &output_tx);
    watcher_stop.store(true, Ordering::SeqCst);
    if watcher.join().is_err() {
        return Err(internal("worker 预算监测线程异常退出"));
    }
    result
}

fn execute_worker_job(
    request: &WorkerRequest,
    control: &ScanControl,
    worker_budget_exceeded: &AtomicBool,
    output_tx: &Sender<WorkerMessage>,
) -> AppResult<WorkerResult> {
    send_phase(output_tx, &request.job.id, JobPhase::Precheck)?;
    let file_open_budget = FileOpenBudget::new(request.runtime.max_open_files)?;
    let mut config = request.scan.clone().into_scan_config();
    config.file_open_budget = Some(Arc::clone(&file_open_budget));
    let index_path = request
        .runtime
        .data_dir
        .join("runs")
        .join(&request.job.run_id)
        .join("index.sqlite");
    let scan_result = match scanner::run_scan(&config, control, &index_path) {
        Ok(result) => result,
        Err(error) => {
            return Ok(failed_result(
                request,
                control.snapshot(),
                error,
                Vec::new(),
            ));
        }
    };
    let source_unavailable = scan_result
        .outcomes
        .iter()
        .filter(|outcome| outcome.status == scanner::SourceStatus::Unavailable)
        .map(|outcome| WorkerSourceUnavailable {
            source_id: outcome.source_id.clone(),
            error_count: outcome.error_count,
        })
        .collect::<Vec<_>>();

    let hash_result = if request.profile.duplicates.enabled {
        send_phase(output_tx, &request.job.id, JobPhase::Hash)?;
        match crate::duplicates::process_index_with_budget(
            &scan_result.index_path,
            &request.profile.duplicates,
            &config.sources,
            control,
            request.runtime.hash_workers,
            request.runtime.hash_read_limit_mib_s,
            file_open_budget,
        ) {
            Ok(result) => result,
            Err(error) => {
                return Ok(failed_result(
                    request,
                    control.snapshot(),
                    error,
                    source_unavailable.clone(),
                ));
            }
        }
    } else {
        crate::duplicates::HashStageResult {
            partial: false,
            hashed_bytes: 0,
            group_count: 0,
        }
    };

    let budget_exceeded = worker_budget_exceeded.load(Ordering::SeqCst);
    let status = if budget_exceeded
        || (scan_result.status == scanner::ScanStatus::Complete && hash_result.partial)
    {
        WorkerStatus::Partial
    } else {
        match scan_result.status {
            scanner::ScanStatus::Complete => WorkerStatus::Succeeded,
            scanner::ScanStatus::Partial | scanner::ScanStatus::Cancelled => WorkerStatus::Partial,
            scanner::ScanStatus::Failed => WorkerStatus::Failed,
        }
    };
    let error = budget_exceeded.then(|| WorkerError {
        code: ErrorCode::ResourceBudgetExceeded.as_str().to_string(),
        message: "worker 进程持续超过内存预算，已停止扩张工作并发布已提交的部分结果".to_string(),
    });
    let (volume_samples, quotas) = request.report_inputs.to_values();
    let snapshot = match load_report_snapshot(
        &config,
        &request.profile,
        &scan_result.outcomes,
        &hash_result,
        volume_samples,
        quotas,
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Ok(failed_result(
                request,
                control.snapshot(),
                error,
                source_unavailable.clone(),
            ));
        }
    };
    let source_names = config
        .sources
        .iter()
        .map(|scan| (scan.source.id.clone(), scan.source.name.clone()))
        .collect::<BTreeMap<_, _>>();
    let report_id = uuid::Uuid::new_v4().to_string();
    let profile_fingerprint = fingerprint(&request.profile, "profile")?;
    let ruleset_fingerprint = fingerprint(&config.ruleset, "ruleset")?;
    let snapshot = crate::report::ReportSnapshot {
        profile_fingerprint: Some(profile_fingerprint),
        ruleset_fingerprint: Some(ruleset_fingerprint),
        ..snapshot
    };
    let published = crate::report::publish_with_snapshot(
        &scan_result.index_path,
        &request.runtime.data_dir.join("reports"),
        &report_id,
        &request.job.run_id,
        status.as_report_status(),
        "live_observation",
        &request.scope_fingerprint,
        request.ruleset_version,
        &source_names,
        extract_rank_limit(&request.job.params_json)?,
        &snapshot,
    );
    match published {
        Ok(report) => Ok(WorkerResult {
            job_id: request.job.id.clone(),
            run_id: request.job.run_id.clone(),
            status,
            report: Some(WorkerPublishedReport {
                id: report.id,
                run_id: report.run_id,
                manifest_path: report.manifest_path,
                status,
                scan_started_at: report.scan_started_at,
                scan_finished_at: report.scan_finished_at,
            }),
            progress: control.snapshot(),
            error,
            resource_budget_exceeded: budget_exceeded,
            source_unavailable,
        }),
        Err(error) => Ok(failed_result(
            request,
            control.snapshot(),
            error,
            source_unavailable,
        )),
    }
}

fn send_phase(output_tx: &Sender<WorkerMessage>, job_id: &str, phase: JobPhase) -> AppResult<()> {
    output_tx
        .send(WorkerMessage::Phase {
            job_id: job_id.to_owned(),
            phase,
        })
        .map_err(|_| internal("worker IPC output 队列已关闭"))
}

fn failed_result(
    request: &WorkerRequest,
    progress: scanner::ScanProgress,
    error: AppError,
    source_unavailable: Vec<WorkerSourceUnavailable>,
) -> WorkerResult {
    WorkerResult {
        job_id: request.job.id.clone(),
        run_id: request.job.run_id.clone(),
        status: WorkerStatus::Failed,
        report: None,
        progress,
        error: Some(WorkerError {
            code: error.code.as_str().to_string(),
            message: error.message,
        }),
        resource_budget_exceeded: false,
        source_unavailable,
    }
}

// ---- parent request/result assembly --------------------------------------

async fn build_worker_request(state: &AppState, job: &Job) -> AppResult<WorkerRequest> {
    let (scan_config, profile_config) = load_scan_config(state, job).await?;
    let run_id = job
        .run_id
        .clone()
        .ok_or_else(|| validation("扫描任务缺少 run_id"))?;
    let profile_id = job
        .profile_id
        .clone()
        .ok_or_else(|| validation("扫描任务缺少 profile_id"))?;
    let profile_version = job
        .profile_version
        .ok_or_else(|| validation("扫描任务缺少 profile_version"))?;
    let report_inputs = load_report_inputs(state, &scan_config).await?;
    let scope_fingerprint = scope_fingerprint(&profile_config, &scan_config)?;
    let hash_read_limit_mib_s = match profile_config.resources.read_limit_mib_s {
        Some(value) => value,
        None => state.config.resources.hash_read_limit_mib_s,
    };
    let hash_workers = match profile_config.resources.hash_workers {
        Some(value) => value,
        None => state.config.resources.hash_workers,
    };
    Ok(WorkerRequest {
        job: WorkerJob {
            id: job.id.clone(),
            run_id,
            profile_id,
            profile_version,
            params_json: job.params_json.clone(),
        },
        scan: WorkerScanConfig::from(&scan_config),
        profile: profile_config,
        report_inputs,
        scope_fingerprint,
        ruleset_version: scan_config.ruleset.version,
        runtime: WorkerRuntimeConfig {
            data_dir: state.config.storage.data_dir.clone(),
            api_memory_budget_mib: state.config.resources.api_memory_budget_mib,
            worker_memory_budget_mib: state.config.resources.worker_memory_budget_mib,
            hash_workers,
            hash_read_limit_mib_s,
            max_open_files: state.config.resources.max_open_files,
        },
    })
}

async fn load_report_inputs(
    state: &AppState,
    config: &ScanConfig,
) -> AppResult<WorkerReportInputs> {
    let source_ids = config
        .sources
        .iter()
        .map(|source| source.source.id.clone())
        .collect::<Vec<_>>();
    let volume_ids = config
        .sources
        .iter()
        .filter_map(|source| source.source.volume_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let scope_ids = source_ids
        .iter()
        .map(|id| ("source", id.clone()))
        .chain(volume_ids.iter().map(|id| ("volume", id.clone())))
        .collect::<Vec<_>>();
    let sampling_config = state.config.clone();
    let (volume_samples, quotas) = state
        .writer
        .call(move |conn| {
            for volume_id in &volume_ids {
                crate::volume::sample_capacity(conn, &sampling_config, volume_id)?;
            }
            let volume_samples = crate::sampling::latest_samples(conn, &volume_ids)?;
            let quotas = load_quota_snapshots(conn, &scope_ids)?;
            Ok((volume_samples, quotas))
        })
        .await?;
    Ok(WorkerReportInputs::from_values(volume_samples, quotas))
}

async fn finalize_worker_result(
    state: &AppState,
    request: &WorkerRequest,
    result: WorkerResult,
) -> AppResult<()> {
    let job_id = request.job.id.clone();
    let profile_id = request.job.profile_id.clone();
    let profile_version = request.job.profile_version;
    let scope_fingerprint = request.scope_fingerprint.clone();
    let ruleset_version = request.ruleset_version;
    let report = result.report;
    let source_unavailable = result.source_unavailable;
    let final_state = result.status.as_job_state();
    let final_status = result.status.as_report_status().to_string();
    let final_progress = progress_json(&result.progress);
    let notification_error = result
        .error
        .as_ref()
        .map(|error| format!("{}: {}", error.code, error.message));
    let notification_error_code = result.error.as_ref().map(|error| error.code.clone());
    let error_json = result.error.map(|error| {
        json!({
            "code": error.code,
            "message": error.message,
        })
    });
    let resource_budget_exceeded = result.resource_budget_exceeded;
    let notification_config = request.profile.notifications.clone();
    let task_name = request.profile.name.clone();
    let run_id = request.job.run_id.clone();
    let source_names = request
        .scan
        .sources
        .iter()
        .map(|source| (source.source.id.clone(), source.source.name.clone()))
        .collect::<BTreeMap<_, _>>();
    let reports_root = state.config.storage.data_dir.join("reports");
    state
        .writer
        .call(move |conn| {
            if let Some(report) = report.as_ref() {
                let report_status = report.status.as_report_status();
                conn.execute(
                    "INSERT INTO reports
                 (id, run_id, profile_id, profile_version, manifest_path, status,
                  consistency, scope_fingerprint, classification_version,
                  scan_started_at, scan_finished_at, detail_available, pinned,
                  detail_pinned, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                         ?10, ?11, 1, 0, 0, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    rusqlite::params![
                        report.id.clone(),
                        report.run_id.clone(),
                        profile_id,
                        profile_version,
                        report.manifest_path.to_string_lossy().into_owned(),
                        report_status,
                        "live_observation",
                        scope_fingerprint.clone(),
                        i64::from(ruleset_version),
                        report.scan_started_at.clone(),
                        report.scan_finished_at.clone(),
                    ],
                )
                .map_err(|error| internal(format!("写入报告索引失败: {error}")))?;
            }
            jobs::job_heartbeat(conn, &job_id, &final_progress)?;
            jobs::append_event(conn, &job_id, "scan.completed", &final_progress)?;
            jobs::job_finish(conn, &job_id, final_state, error_json.as_ref())?;
            jobs::append_event(
                conn,
                &job_id,
                "job.finished",
                &json!({
                    "status": final_status,
                    "resource_budget_exceeded": resource_budget_exceeded,
                }),
            )?;
            consume_scan_internal_notifications(
                conn,
                ScanInternalNotificationContext {
                    run_id: &run_id,
                    task_name: &task_name,
                    report: report.as_ref(),
                    final_status: &final_status,
                    source_names: &source_names,
                    source_unavailable: &source_unavailable,
                    notification_error_code: notification_error_code.as_deref(),
                    resource_budget_exceeded,
                },
            )?;
            if notification_config
                .notify_on
                .iter()
                .any(|value| value == &final_status)
            {
                let report_payload = report
                    .as_ref()
                    .map(|report| {
                        let report_db = crate::report::open_published_in_root(
                            &reports_root,
                            &report.id,
                            "report.sqlite",
                            "打开报告通知摘要失败",
                        )?;
                        crate::notify::build_report_notification_payload(
                            &report_db,
                            &task_name,
                            &report.id,
                            &final_status,
                            notification_config.public_base_url.as_deref(),
                            notification_config.attach_summary,
                        )
                    })
                    .transpose()?;
                for recipient in &notification_config.recipients {
                    let (report_id, payload) = match (&report, &report_payload) {
                        (Some(report), Some(payload)) => {
                            (Some(report.id.as_str()), payload.clone())
                        }
                        (None, None) => {
                            let detail = match notification_error.as_deref() {
                                Some(error) => format!("错误摘要：{error}"),
                                None => "错误摘要：unknown".to_string(),
                            };
                            (
                                None,
                                crate::notify::EmailPayload {
                                    subject: format!("任务 {} {}", task_name, final_status),
                                    body_text: format!(
                                        "任务：{}\n状态：{}\n{}\n",
                                        task_name, final_status, detail
                                    ),
                                    attachment: None,
                                },
                            )
                        }
                        _ => return Err(internal("报告通知 payload 状态不一致")),
                    };
                    let kind = match report_id {
                        Some(_) => format!("report.{final_status}"),
                        None => format!("job.{job_id}.report.{final_status}"),
                    };
                    crate::notify::enqueue(conn, report_id, recipient, &kind, &payload)?;
                }
            }
            Ok(())
        })
        .await
}

struct ScanInternalNotificationContext<'a> {
    run_id: &'a str,
    task_name: &'a str,
    report: Option<&'a WorkerPublishedReport>,
    final_status: &'a str,
    source_names: &'a BTreeMap<String, String>,
    source_unavailable: &'a [WorkerSourceUnavailable],
    notification_error_code: Option<&'a str>,
    resource_budget_exceeded: bool,
}

fn consume_scan_internal_notifications(
    conn: &Connection,
    context: ScanInternalNotificationContext<'_>,
) -> AppResult<()> {
    let ScanInternalNotificationContext {
        run_id,
        task_name,
        report,
        final_status,
        source_names,
        source_unavailable,
        notification_error_code,
        resource_budget_exceeded,
    } = context;
    if final_status == "partial" {
        let report = report.ok_or_else(|| internal("部分成功扫描缺少已发布报告"))?;
        let body = format!(
            "任务：{task_name}；报告 ID：{}；本次结果为部分成功；不可用数据源：{} 个；资源预算超限：{}。",
            report.id,
            source_unavailable.len(),
            resource_budget_exceeded,
        );
        let event_key = format!("scan:{run_id}:report-partial");
        crate::notify::create_internal_notification_once(
            conn,
            &event_key,
            "report.partial",
            "报告部分成功",
            &body,
            crate::notify::InternalNotificationSeverity::Warning,
        )?;
    }

    for source in source_unavailable {
        let source_name = source_names
            .get(&source.source_id)
            .ok_or_else(|| internal(format!("源不可用事件引用未知数据源: {}", source.source_id)))?;
        let body = format!(
            "任务：{task_name}；数据源：{source_name}（ID：{}）；错误条目数：{}；本次扫描未取得该源的完整统计。",
            source.source_id, source.error_count
        );
        let event_key = format!("scan:{run_id}:source-unavailable:{}", source.source_id);
        crate::notify::create_internal_notification_once(
            conn,
            &event_key,
            "source.unavailable",
            "数据源不可用",
            &body,
            crate::notify::InternalNotificationSeverity::Warning,
        )?;
    }

    if notification_error_code == Some(ErrorCode::InsufficientDataSpace.as_str()) {
        let event_key = format!("scan:{run_id}:storage-insufficient");
        let body = format!(
            "任务：{task_name}；扫描结果未能完整写入应用数据目录；错误码：INSUFFICIENT_DATA_SPACE。"
        );
        crate::notify::create_internal_notification_once(
            conn,
            &event_key,
            "storage.insufficient",
            "存储空间不足",
            &body,
            crate::notify::InternalNotificationSeverity::Error,
        )?;
    }
    Ok(())
}

fn load_report_snapshot(
    config: &ScanConfig,
    profile_config: &ProfileConfig,
    source_outcomes: &[scanner::SourceScanOutcome],
    hash_result: &crate::duplicates::HashStageResult,
    volume_samples: Vec<VolumeSample>,
    quotas: Vec<crate::report::QuotaSnapshot>,
) -> AppResult<crate::report::ReportSnapshot> {
    let source_identities = config
        .sources
        .iter()
        .map(|scan| crate::report::SourceIdentitySnapshot {
            source_id: scan.source.id.clone(),
            identity_epoch: scan.source.identity_epoch,
            availability: scan.source.availability.as_str().to_string(),
        })
        .collect::<Vec<_>>();
    let section_status = build_section_status(
        source_outcomes,
        profile_config,
        volume_samples.as_slice(),
        quotas.as_slice(),
        hash_result,
    )?;
    let scope_snapshot = serde_json::to_value(&profile_config.scope)
        .map_err(|error| internal(format!("编码报告范围快照失败: {error}")))?;
    Ok(crate::report::ReportSnapshot {
        volume_samples,
        quotas,
        source_identities,
        section_status,
        scope_snapshot: Some(scope_snapshot),
        profile_fingerprint: None,
        ruleset_fingerprint: None,
        owner_ids_to_list: profile_config.owner_ids_to_list.clone(),
    })
}

pub(crate) fn load_quota_snapshots(
    conn: &Connection,
    scope_ids: &[(&str, String)],
) -> AppResult<Vec<crate::report::QuotaSnapshot>> {
    if scope_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut clauses = Vec::with_capacity(scope_ids.len());
    let mut values = Vec::<rusqlite::types::Value>::with_capacity(scope_ids.len() * 2);
    for (kind, id) in scope_ids {
        clauses.push("(scope_kind = ? AND scope_id = ?)");
        values.push((*kind).to_owned().into());
        values.push(id.clone().into());
    }
    let sql = format!(
        "SELECT id, principal_namespace, principal_uid, scope_kind, scope_id, metric,
                origin, limit_state, limit_bytes, used_bytes, observed_at, expires_at,
                provider_label
         FROM quota_records WHERE {}",
        clauses.join(" OR ")
    );
    let mut statement = conn
        .prepare(&sql)
        .map_err(|error| internal(format!("准备报告配额快照查询失败: {error}")))?;
    let now = crate::auth::now_rfc3339();
    let rows = statement
        .query_map(rusqlite::params_from_iter(values), |row| {
            let expires_at: Option<String> = row.get(11)?;
            Ok((
                row.get::<_, String>(0)?,
                crate::report::QuotaSnapshot {
                    principal_namespace: row.get(1)?,
                    principal_uid: row.get(2)?,
                    scope_kind: row.get(3)?,
                    scope_id: row.get(4)?,
                    metric: row.get(5)?,
                    origin: row.get(6)?,
                    limit_state: row.get(7)?,
                    limit_bytes: row.get(8)?,
                    used_bytes: row.get(9)?,
                    observed_at: row.get(10)?,
                    expires_at: expires_at.clone(),
                    provider_label: row.get(12)?,
                    stale: expires_at
                        .as_deref()
                        .is_some_and(|value| value <= now.as_str()),
                },
            ))
        })
        .map_err(|error| internal(format!("读取报告配额快照失败: {error}")))?;

    let mut selected = BTreeMap::<
        (String, i64, String, String, String),
        (String, crate::report::QuotaSnapshot),
    >::new();
    for row in rows {
        let (id, candidate) =
            row.map_err(|error| internal(format!("解析报告配额快照失败: {error}")))?;
        let key = (
            candidate.principal_namespace.clone(),
            candidate.principal_uid,
            candidate.scope_kind.clone(),
            candidate.scope_id.clone(),
            candidate.metric.clone(),
        );
        let replace = selected.get(&key).is_none_or(|(current_id, current)| {
            if current.stale != candidate.stale {
                return !candidate.stale;
            }
            if current.observed_at != candidate.observed_at {
                return candidate.observed_at > current.observed_at;
            }
            let candidate_rank = quota_origin_rank(&candidate.origin);
            let current_rank = quota_origin_rank(&current.origin);
            if candidate_rank != current_rank {
                return candidate_rank < current_rank;
            }
            id > *current_id
        });
        if replace {
            selected.insert(key, (id, candidate));
        }
    }
    Ok(selected.into_values().map(|(_, value)| value).collect())
}

fn quota_origin_rank(origin: &str) -> u8 {
    match origin {
        "system_imported" => 0,
        "advisory" => 1,
        "unknown" => 2,
        _ => 3,
    }
}

fn build_section_status(
    source_outcomes: &[scanner::SourceScanOutcome],
    profile_config: &ProfileConfig,
    volume_samples: &[VolumeSample],
    quotas: &[crate::report::QuotaSnapshot],
    hash_result: &crate::duplicates::HashStageResult,
) -> AppResult<Vec<crate::report::SectionStatusSnapshot>> {
    let mut source_quality = Vec::with_capacity(source_outcomes.len());
    let mut error_count = 0_i64;
    for outcome in source_outcomes {
        let quality = match outcome.status {
            scanner::SourceStatus::Complete => "complete",
            scanner::SourceStatus::Partial => "partial",
            scanner::SourceStatus::Unavailable => "unavailable",
        };
        source_quality.push(quality);
        error_count = error_count
            .checked_add(
                i64::try_from(outcome.error_count)
                    .map_err(|_| internal("报告栏目错误数超出 SQLite INTEGER 范围"))?,
            )
            .ok_or_else(|| internal("报告栏目错误数溢出"))?;
    }
    let aggregate_quality = if source_quality.is_empty() {
        ("unavailable", Some("报告没有可用的源观察状态".to_string()))
    } else if source_quality
        .iter()
        .all(|quality| *quality == "unavailable")
    {
        ("unavailable", Some("所有数据源当前不可用".to_string()))
    } else if source_quality.iter().any(|quality| *quality != "complete") {
        ("partial", Some("至少一个数据源的观察不完整".to_string()))
    } else {
        ("complete", None)
    };

    profile_config
        .sections
        .iter()
        .map(|section| {
            let section_name = serde_json::to_value(section)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(|| internal("报告栏目枚举无法编码"))?;
            let (quality, message) = match section {
                crate::profile::ProfileSection::Volume if volume_samples.is_empty() => {
                    ("unavailable", Some("没有可用的容量采样快照".to_string()))
                }
                crate::profile::ProfileSection::Volume
                    if volume_samples
                        .iter()
                        .all(|sample| sample.quality == SampleQuality::Ok) =>
                {
                    ("complete", None)
                }
                crate::profile::ProfileSection::Volume => {
                    ("partial", Some("至少一个卷容量采样不可用".to_string()))
                }
                crate::profile::ProfileSection::Quota if quotas.is_empty() => {
                    ("unavailable", Some("没有导入的配额或预算快照".to_string()))
                }
                crate::profile::ProfileSection::Quota if quotas.iter().any(|quota| quota.stale) => {
                    ("partial", Some("部分配额快照已过期".to_string()))
                }
                crate::profile::ProfileSection::Quota => ("complete", None),
                crate::profile::ProfileSection::Duplicates
                    if !profile_config.duplicates.enabled =>
                {
                    ("skipped", Some("按任务配置未启用重复检测".to_string()))
                }
                crate::profile::ProfileSection::Duplicates if hash_result.partial => (
                    "partial",
                    Some("重复检测受读取策略或预算限制，结果不完整".to_string()),
                ),
                crate::profile::ProfileSection::Duplicates => ("complete", None),
                _ => aggregate_quality.clone(),
            };
            Ok(crate::report::SectionStatusSnapshot {
                section: section_name,
                quality: quality.to_string(),
                error_count,
                message: message.or_else(|| {
                    aggregate_quality
                        .1
                        .clone()
                        .filter(|_| quality != "complete")
                }),
            })
        })
        .collect()
}

fn extract_rank_limit(params: &Value) -> AppResult<u32> {
    params
        .get("rank_limit")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| (1..=10_000).contains(value))
        .ok_or_else(|| validation("扫描任务缺少有效的 rank_limit 快照"))
}

fn fingerprint<T: serde::Serialize>(value: &T, kind: &str) -> AppResult<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| internal(format!("编码 {kind} 指纹输入失败: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn scope_fingerprint(profile_config: &ProfileConfig, config: &ScanConfig) -> AppResult<String> {
    let mut hasher = Sha256::new();
    let scope = serde_json::to_vec(&profile_config.scope)
        .map_err(|error| internal(format!("编码扫描范围指纹输入失败: {error}")))?;
    hasher.update(scope);
    let mut sources = config.sources.iter().collect::<Vec<_>>();
    sources.sort_by(|left, right| left.source.id.cmp(&right.source.id));
    for source in sources {
        hasher.update(source.source.id.as_bytes());
        hasher.update(&source.source.raw_relative_root);
        hasher.update(source.source.identity_epoch.to_le_bytes());
        hasher.update(source.source.availability.as_str().as_bytes());
    }
    Ok(hex::encode(hasher.finalize()))
}

async fn load_scan_config(state: &AppState, job: &Job) -> AppResult<(ScanConfig, ProfileConfig)> {
    let profile_id = job
        .profile_id
        .clone()
        .ok_or_else(|| validation("扫描任务缺少 profile_id"))?;
    let profile_version = job
        .profile_version
        .ok_or_else(|| validation("扫描任务缺少 profile_version"))?;
    let params = job.params_json.clone();
    let source_ids = params
        .get("source_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| validation("扫描任务缺少 source_ids 快照"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| validation("source_ids 快照包含非字符串值"))
        })
        .collect::<AppResult<Vec<_>>>()?;
    let profile_config = if let Some(snapshot) = params.get("profile_snapshot") {
        serde_json::from_value::<ProfileConfig>(snapshot.clone())
            .map_err(|error| validation(format!("profile_snapshot 无法解析: {error}")))?
    } else {
        let profile_id = profile_id.clone();
        state
            .writer
            .call(move |conn| profile::get_version(conn, &profile_id, profile_version))
            .await?
    };
    let sources = state
        .writer
        .call(move |conn| {
            source_ids
                .iter()
                .map(|id| source::get_enabled_source(conn, id))
                .collect::<AppResult<Vec<_>>>()
        })
        .await?;
    let scan_sources = sources
        .into_iter()
        .map(|source| {
            let mount = state
                .config
                .approved_mounts
                .iter()
                .find(|mount| mount.key == source.mount_key)
                .ok_or_else(|| validation(format!("数据源引用未批准挂载: {}", source.mount_key)))?;
            Ok(ScanSource {
                source,
                mount_path: mount.container_path.clone(),
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    let ruleset = if let Some(snapshot) = params.get("ruleset_snapshot") {
        let ruleset = serde_json::from_value::<CategoryRuleset>(snapshot.clone())
            .map_err(|error| validation(format!("ruleset_snapshot 无法解析: {error}")))?;
        ruleset.validate()?;
        ruleset
    } else {
        state
            .writer
            .call(|conn| crate::category::load_current(&*conn))
            .await?
    };
    let metadata_workers = match profile_config.resources.metadata_workers {
        Some(value) => value,
        None => state.config.resources.metadata_workers,
    };
    let scan_config = ScanConfig {
        sources: scan_sources,
        ruleset,
        exclude_globs: profile_config.scope.exclude_globs.clone(),
        include_globs: profile_config.scope.include_globs.clone(),
        include_hidden: true,
        skip_system_dirs_preset: true,
        metadata_workers,
        batch_rows: 1000,
        frontier_memory_cap: 4096,
        file_kind_policy: profile_config.scope.file_kind_policy.clone(),
        max_open_files: state.config.resources.max_open_files,
        file_open_budget: None,
    };
    Ok((scan_config, profile_config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_uses_machine_values_and_decimal_counters() {
        let value = progress_json(&scanner::ScanProgress {
            phase: Some(ScanPhase::Traversing),
            source_id: Some("source-1".into()),
            files_seen: 42,
            logical_bytes: 99,
            ..scanner::ScanProgress::default()
        });
        assert_eq!(value["phase"], "ENUMERATE");
        assert_eq!(value["files_seen"], "42");
        assert_eq!(value["logical_bytes"], "99");
    }

    #[test]
    fn worker_status_maps_to_terminal_job_state() {
        assert_eq!(WorkerStatus::Succeeded.as_job_state(), JobState::Succeeded);
        assert_eq!(WorkerStatus::Partial.as_job_state(), JobState::Partial);
        assert_eq!(WorkerStatus::Failed.as_job_state(), JobState::Failed);
    }

    #[test]
    fn ipc_rejects_oversized_payload_before_writing() {
        let payload = "x".repeat(IPC_MAX_FRAME_BYTES + 1);
        let error = encode_frame(&payload).unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn ipc_frame_round_trip_preserves_raw_bytes_in_source_snapshot() {
        let source = WorkerSource {
            id: "source".to_string(),
            name: "raw".to_string(),
            mount_key: "main".to_string(),
            raw_relative_root: vec![0xff, b'/', 0x80],
            volume_id: None,
            storage_kind: source::StorageKind::Local,
            read_policy: source::ReadPolicy::MetadataOnly,
            write_enabled: false,
            protected: false,
            exclusions: Vec::new(),
            identity_status: source::IdentityStatus::Verified,
            identity_epoch: 1,
            identity_json: Value::Null,
            availability: source::Availability::Online,
            atime_quality: source::AtimeQuality::Unknown,
            disabled_at: None,
            created_at: "created".to_string(),
            updated_at: "updated".to_string(),
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &source).unwrap();
        let decoded: WorkerSource = read_message(&mut bytes.as_slice()).unwrap().unwrap();
        assert_eq!(decoded.raw_relative_root, vec![0xff, b'/', 0x80]);
    }

    #[test]
    fn persisted_pause_is_forwarded_once_and_resume_is_distinct() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &ParentMessage::Control(WorkerCommand::Pause)).unwrap();
        let decoded: ParentMessage = read_message(&mut bytes.as_slice()).unwrap().unwrap();
        assert!(matches!(
            decoded,
            ParentMessage::Control(WorkerCommand::Pause)
        ));
    }
}
