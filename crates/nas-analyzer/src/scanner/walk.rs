//! Streaming BFS traversal (spec 10.1–10.5). One directory at a time is
//! listed through `fssecure::SecureRoot`; the frontier is a bounded in-memory
//! queue that spills to the run index `frontier` table when full.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{Receiver, RecvTimeoutError, SendTimeoutError, Sender, bounded};
use fssecure::{DirEntryInfo, EntryKind, FsSecureError, SecureRoot, StatData};

use crate::error::{AppError, AppResult, ErrorCode};
use crate::profile::FileKindPolicy;
use crate::resource::{FileOpenBudget, FileOpenPermit};

use super::index_writer::{IndexWriter, NewEntry};
use super::rules::{Decision, RuleEngine};
use super::{
    Cancelled, ScanConfig, ScanControl, ScanPhase, ScanSource, SourceScanOutcome, SourceStatus,
};

const FRONTIER_SPILL_BATCH: usize = 256;
const FRONTIER_SPILL_BYTES: usize = 1024 * 1024;
const CHECKPOINT_EVERY_ENTRIES: u32 = 256;
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const EXCLUDED_BUF_CAP: usize = 4096;

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

pub(crate) struct SourceWalkResult {
    pub outcome: SourceScanOutcome,
    pub cancelled: bool,
}

#[derive(Default)]
struct Accum {
    dirs_visited: u64,
    file_count: u64,
    dir_count: u64,
    logical_bytes: u64,
    error_count: u64,
    vanished_count: u64,
    excluded_count: u64,
    mount_boundary_count: u64,
}

struct MetadataRequest {
    dir_id: i64,
    child_rel: Vec<u8>,
    full_rel: Vec<u8>,
    info: DirEntryInfo,
    apply_rules_after_stat: bool,
}

struct MetadataResponse {
    dir_id: i64,
    child_rel: Vec<u8>,
    info: DirEntryInfo,
    apply_rules_after_stat: bool,
    stat: Result<StatData, FsSecureError>,
}

/// Fixed-size metadata admission pool. Each worker owns a duplicate of the
/// already-open SecureRoot; no worker re-opens a display path and no worker
/// touches SQLite. Both channels are bounded by the configured worker count.
struct MetadataPipeline {
    request_tx: Option<Sender<MetadataRequest>>,
    response_rx: Receiver<MetadataResponse>,
    workers: Vec<JoinHandle<()>>,
    worker_count: usize,
}

impl MetadataPipeline {
    fn new(
        root: &SecureRoot,
        worker_count: u32,
        file_open_budget: &Arc<FileOpenBudget>,
    ) -> AppResult<Self> {
        let worker_count = usize::try_from(worker_count)
            .map_err(|_| internal("metadata_workers 无法转换为 usize"))?;
        if worker_count == 0 {
            return Err(AppError::new(
                ErrorCode::ValidationFailed,
                "metadata_workers 必须大于 0",
            ));
        }

        let (request_tx, request_rx) = bounded::<MetadataRequest>(worker_count);
        let (response_tx, response_rx) = bounded::<MetadataResponse>(worker_count);
        let mut workers: Vec<JoinHandle<()>> = Vec::with_capacity(worker_count);
        for worker_index in 0..worker_count {
            let root_permit = file_open_budget
                .acquire(|| false)
                .ok_or_else(|| internal("元数据 worker 无法取得文件句柄许可"))?;
            let worker_root = match root.try_clone() {
                Ok(root) => root,
                Err(error) => {
                    drop(request_tx);
                    drop(response_tx);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(internal(format!("复制元数据 worker 安全根失败: {error}")));
                }
            };
            let worker_rx = request_rx.clone();
            let worker_tx = response_tx.clone();
            let worker = match thread::Builder::new()
                .name(format!("metadata-worker-{worker_index}"))
                .spawn(move || {
                    let _root_permit = root_permit;
                    while let Ok(request) = worker_rx.recv() {
                        let stat = worker_root.stat(OsStr::from_bytes(&request.full_rel));
                        let response = MetadataResponse {
                            dir_id: request.dir_id,
                            child_rel: request.child_rel,
                            info: request.info,
                            apply_rules_after_stat: request.apply_rules_after_stat,
                            stat,
                        };
                        if worker_tx.send(response).is_err() {
                            break;
                        }
                    }
                }) {
                Ok(worker) => worker,
                Err(error) => {
                    drop(request_tx);
                    drop(response_tx);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(internal(format!(
                        "启动元数据 worker {worker_index} 失败: {error}"
                    )));
                }
            };
            workers.push(worker);
        }
        drop(response_tx);
        Ok(Self {
            request_tx: Some(request_tx),
            response_rx,
            workers,
            worker_count,
        })
    }

    fn submit(&self, control: &ScanControl, mut request: MetadataRequest) -> Result<(), Abort> {
        let tx = self
            .request_tx
            .as_ref()
            .ok_or_else(|| Abort::Fatal(internal("元数据 worker 队列已关闭")))?;
        loop {
            match tx.send_timeout(request, Duration::from_millis(50)) {
                Ok(()) => return Ok(()),
                Err(SendTimeoutError::Timeout(returned)) => {
                    request = returned;
                    control.checkpoint()?;
                }
                Err(SendTimeoutError::Disconnected(_)) => {
                    return Err(Abort::Fatal(internal("元数据 worker 队列已断开")));
                }
            }
        }
    }

    fn receive(&self, control: &ScanControl) -> Result<MetadataResponse, Abort> {
        loop {
            match self.response_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(response) => return Ok(response),
                Err(RecvTimeoutError::Timeout) => control.checkpoint()?,
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(Abort::Fatal(internal("元数据 worker 结果队列已断开")));
                }
            }
        }
    }

    fn shutdown(&mut self) -> AppResult<()> {
        self.request_tx.take();
        let mut failed = false;
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                failed = true;
            }
        }
        if failed {
            Err(internal("元数据 worker 线程异常退出"))
        } else {
            Ok(())
        }
    }
}

impl Drop for MetadataPipeline {
    fn drop(&mut self) {
        self.request_tx.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

enum Abort {
    Cancelled,
    Fatal(AppError),
}

impl From<Cancelled> for Abort {
    fn from(_: Cancelled) -> Self {
        Abort::Cancelled
    }
}

impl From<AppError> for Abort {
    fn from(e: AppError) -> Self {
        Abort::Fatal(e)
    }
}

pub(crate) fn kind_str(k: EntryKind) -> &'static str {
    match k {
        EntryKind::RegularFile => "regular_file",
        EntryKind::Directory => "directory",
        EntryKind::Symlink => "symlink",
        EntryKind::Fifo => "fifo",
        EntryKind::Socket => "socket",
        EntryKind::BlockDevice => "block_device",
        EntryKind::CharDevice => "char_device",
        EntryKind::Unknown => "unknown",
    }
}

/// Best-effort errno for diagnostics; symbolic variants use the canonical
/// Linux/macos values (EACCES=13, ENOENT=2 on both).
fn errno_of(e: &FsSecureError) -> Option<i64> {
    match e {
        FsSecureError::PermissionDenied => Some(13),
        FsSecureError::NotFound => Some(2),
        FsSecureError::Io(io) => io.raw_os_error().map(i64::from),
        FsSecureError::Rustix(errno) => Some(i64::from(errno.raw_os_error())),
        _ => None,
    }
}

fn join_bytes(base: &[u8], name: &[u8]) -> Vec<u8> {
    if base.is_empty() {
        name.to_vec()
    } else {
        let mut v = Vec::with_capacity(base.len() + 1 + name.len());
        v.extend_from_slice(base);
        v.push(b'/');
        v.extend_from_slice(name);
        v
    }
}

struct SourceWalk<'a> {
    source_id: String,
    config: &'a ScanConfig,
    writer: &'a mut IndexWriter,
    control: &'a ScanControl,
    rules: RuleEngine,
    root: SecureRoot,
    metadata: MetadataPipeline,
    _root_permit: FileOpenPermit,
    file_open_budget: Arc<FileOpenBudget>,
    root_rel: Vec<u8>,
    accum: Accum,
    frontier: VecDeque<(Option<i64>, Vec<u8>)>,
    spill_buf: Vec<Vec<u8>>,
    since_checkpoint: u32,
    root_unavailable: bool,
}

pub(crate) fn scan_source(
    scan: &ScanSource,
    config: &ScanConfig,
    writer: &mut IndexWriter,
    control: &ScanControl,
    file_open_budget: &Arc<FileOpenBudget>,
) -> AppResult<SourceWalkResult> {
    control.set_phase(ScanPhase::Traversing, Some(scan.source.id.clone()));

    // Per-source engine: task globs merged with the source's own exclusions.
    let exclude: Vec<String> = config
        .exclude_globs
        .iter()
        .cloned()
        .chain(scan.source.exclusions.iter().cloned())
        .collect();
    let rules = RuleEngine::build(
        &exclude,
        &config.include_globs,
        config.include_hidden,
        config.skip_system_dirs_preset,
    )?;

    let source_id = scan.source.id.clone();
    let Some(root_permit) = file_open_budget.acquire(|| control.is_cancelled()) else {
        return Ok(SourceWalkResult {
            outcome: unavailable_outcome(source_id),
            cancelled: true,
        });
    };
    let root = match SecureRoot::open(scan.mount_path.as_os_str()) {
        Ok(r) => r,
        Err(e) => {
            writer.record_error(
                &source_id,
                None,
                errno_of(&e),
                "root_unavailable",
                &format!("source root cannot be opened: {e}"),
            )?;
            writer.record_observation(
                &source_id,
                "unavailable",
                1,
                0,
                0,
                0,
                Some(&e.to_string()),
            )?;
            return Ok(SourceWalkResult {
                outcome: unavailable_outcome(source_id),
                cancelled: false,
            });
        }
    };

    let metadata = MetadataPipeline::new(&root, config.metadata_workers, file_open_budget)?;
    let mut w = SourceWalk {
        source_id,
        config,
        writer,
        control,
        rules,
        root,
        metadata,
        _root_permit: root_permit,
        file_open_budget: Arc::clone(file_open_budget),
        root_rel: scan.source.raw_relative_root.clone(),
        accum: Accum::default(),
        frontier: VecDeque::new(),
        spill_buf: Vec::new(),
        since_checkpoint: 0,
        root_unavailable: false,
    };

    let run_result = w.run();
    let metadata_result = w.metadata.shutdown();
    match run_result {
        Ok(()) => {
            metadata_result?;
            let outcome = w.finish(false, None)?;
            Ok(SourceWalkResult {
                outcome,
                cancelled: false,
            })
        }
        Err(Abort::Cancelled) => {
            metadata_result?;
            // Consistency wrap-up before reporting cancellation (spec 15.6):
            // commit the in-flight batch and record the partial observation.
            let outcome = w.finish(true, Some("cancelled"))?;
            Ok(SourceWalkResult {
                outcome,
                cancelled: true,
            })
        }
        Err(Abort::Fatal(e)) => Err(e),
    }
}

fn unavailable_outcome(source_id: String) -> SourceScanOutcome {
    SourceScanOutcome {
        source_id,
        status: SourceStatus::Unavailable,
        file_count: 0,
        dir_count: 0,
        logical_bytes: 0,
        unique_logical_bytes: None,
        allocated_bytes: None,
        error_count: 1,
        vanished_count: 0,
        excluded_count: 0,
        mount_boundary_count: 0,
    }
}

impl SourceWalk<'_> {
    fn full_rel(&self, rel: &[u8]) -> OsString {
        OsString::from(OsStr::from_bytes(&join_bytes(&self.root_rel, rel)))
    }

    fn run(&mut self) -> Result<(), Abort> {
        // Source root itself: missing/locked root means unavailable, never a
        // silent zero (spec 10.4).
        let root_stat = match self.root.stat(OsStr::from_bytes(&self.root_rel)) {
            Ok(st) => st,
            Err(e) => {
                self.accum.error_count += 1;
                self.writer.record_error(
                    &self.source_id,
                    None,
                    errno_of(&e),
                    "root_unavailable",
                    &format!("source root unavailable: {e}"),
                )?;
                self.root_unavailable = true;
                return Ok(());
            }
        };
        let root_name = self
            .root_rel
            .rsplit(|b| *b == b'/')
            .next()
            .filter(|c| !c.is_empty())
            .unwrap_or(b"/");
        let root_entry = self.build_entry(None, Vec::new(), root_name, &root_stat, None);
        self.writer.queue_entry(root_entry);
        self.frontier.push_back((None, Vec::new()));

        while let Some((maybe_id, rel)) = self.pop_dir()? {
            self.control.checkpoint()?;
            self.accum.dirs_visited += 1;
            self.sync_progress();
            self.process_dir(maybe_id, &rel)?;
        }
        Ok(())
    }

    fn pop_dir(&mut self) -> Result<Option<(i64, Vec<u8>)>, Abort> {
        if self.frontier.is_empty() {
            self.flush_spill_buf()?;
            self.writer
                .reload_frontier(&self.source_id, &mut self.frontier)?;
            if self.frontier.is_empty() {
                return Ok(None);
            }
        }
        let (maybe_id, rel) = self.frontier.pop_front().expect("frontier non-empty");
        let id = match maybe_id {
            Some(id) => id,
            None => self
                .writer
                .dir_entry_id(&self.source_id, &rel)?
                .ok_or_else(|| internal("frontier directory missing its entries row"))?,
        };
        Ok(Some((id, rel)))
    }

    fn process_dir(&mut self, dir_id: i64, rel: &[u8]) -> Result<(), Abort> {
        let full = self.full_rel(rel);
        let Some(_dir_permit) = self
            .file_open_budget
            .acquire(|| self.control.is_cancelled())
        else {
            return Err(Abort::Cancelled);
        };
        let iter = match self.root.read_dir(&full) {
            Ok(it) => it,
            Err(e) => {
                self.handle_dir_error(dir_id, rel, &e)?;
                return Ok(());
            }
        };
        let mut pending = 0usize;
        for item in iter {
            match item {
                Ok(info) => {
                    let name = info.name.as_bytes();
                    let child_rel = join_bytes(rel, name);
                    let apply_rules_after_stat = info.kind == EntryKind::Unknown;
                    if !apply_rules_after_stat
                        && matches!(
                            self.rules
                                .decide(&child_rel, info.kind == EntryKind::Directory),
                            Decision::Exclude(_)
                        )
                    {
                        self.accum.excluded_count += 1;
                        self.writer.add_excluded(dir_id);
                    } else {
                        self.metadata.submit(
                            self.control,
                            MetadataRequest {
                                dir_id,
                                child_rel: child_rel.clone(),
                                full_rel: join_bytes(&self.root_rel, &child_rel),
                                info,
                                apply_rules_after_stat,
                            },
                        )?;
                        pending += 1;
                        if pending >= self.metadata.worker_count {
                            let response = self.metadata.receive(self.control)?;
                            self.process_metadata_response(response)?;
                            pending -= 1;
                        }
                    }
                }
                Err(e) => {
                    if matches!(e, FsSecureError::NotFound) {
                        self.accum.vanished_count += 1;
                        self.writer.record_error(
                            &self.source_id,
                            Some(rel),
                            errno_of(&e),
                            "vanished",
                            "entry vanished while listing its parent directory",
                        )?;
                    } else {
                        self.accum.error_count += 1;
                        self.writer.record_error(
                            &self.source_id,
                            Some(rel),
                            errno_of(&e),
                            "read_dir",
                            &format!("directory listing error: {e}"),
                        )?;
                    }
                }
            }
            self.pace()?;
        }
        while pending > 0 {
            let response = self.metadata.receive(self.control)?;
            self.process_metadata_response(response)?;
            pending -= 1;
            self.pace()?;
        }
        Ok(())
    }

    /// Flush pacing: commit at batch_rows, after ~1s, or when the excluded
    /// buffer grows large; pause/cancel is checked at every flush and at
    /// least every CHECKPOINT_EVERY_ENTRIES entries.
    fn pace(&mut self) -> Result<(), Abort> {
        self.since_checkpoint += 1;
        if self.writer.pending_len() >= self.config.batch_rows.max(1)
            || self.writer.since_flush() >= FLUSH_INTERVAL
            || self.writer.excluded_buf_len() >= EXCLUDED_BUF_CAP
        {
            self.writer.flush()?;
            self.sync_progress();
            self.control.emit();
            self.control.checkpoint()?;
            self.since_checkpoint = 0;
        } else if self.since_checkpoint >= CHECKPOINT_EVERY_ENTRIES {
            self.control.checkpoint()?;
            self.since_checkpoint = 0;
        }
        Ok(())
    }

    fn process_metadata_response(&mut self, response: MetadataResponse) -> Result<(), Abort> {
        let name = response.info.name.as_bytes();
        let stat = match response.stat {
            Ok(stat) => stat,
            Err(error) => {
                self.handle_entry_error(
                    response.dir_id,
                    &response.child_rel,
                    name,
                    response.info.kind,
                    &error,
                )?;
                return Ok(());
            }
        };
        if response.apply_rules_after_stat
            && matches!(
                self.rules
                    .decide(&response.child_rel, stat.kind == EntryKind::Directory),
                Decision::Exclude(_)
            )
        {
            self.accum.excluded_count += 1;
            self.writer.add_excluded(response.dir_id);
            return Ok(());
        }
        self.accept_entry(response.dir_id, response.child_rel, name, &stat)
    }

    fn accept_entry(
        &mut self,
        dir_id: i64,
        rel: Vec<u8>,
        name: &[u8],
        st: &StatData,
    ) -> Result<(), Abort> {
        let is_dir = st.kind == EntryKind::Directory;
        let is_regular = st.kind == EntryKind::RegularFile;
        if matches!(self.config.file_kind_policy, FileKindPolicy::RegularOnly)
            && !is_dir
            && !is_regular
        {
            return Ok(());
        }
        if is_regular {
            self.accum.file_count += 1;
            self.accum.logical_bytes = self
                .accum
                .logical_bytes
                .checked_add(
                    u64::try_from(st.size_bytes)
                        .map_err(|_| Abort::Fatal(internal("扫描逻辑字节数包含负数或超出 u64")))?,
                )
                .ok_or_else(|| Abort::Fatal(internal("扫描逻辑字节数溢出")))?;
        }
        let entry = self.build_entry(Some(dir_id), rel.clone(), name, st, None);
        self.writer.queue_entry(entry);
        if is_dir {
            self.accum.dir_count += 1;
            self.push_dir(rel)?;
        }
        Ok(())
    }

    fn push_dir(&mut self, rel: Vec<u8>) -> Result<(), Abort> {
        if self.frontier.len() >= self.config.frontier_memory_cap.max(16) {
            self.spill_buf.push(rel);
            let spill_bytes = self.spill_buf.iter().map(Vec::len).sum::<usize>();
            if self.spill_buf.len() >= FRONTIER_SPILL_BATCH || spill_bytes >= FRONTIER_SPILL_BYTES {
                self.flush_spill_buf()?;
            }
        } else {
            self.frontier.push_back((None, rel));
        }
        Ok(())
    }

    fn flush_spill_buf(&mut self) -> Result<(), Abort> {
        if self.spill_buf.is_empty() {
            return Ok(());
        }
        let mut buf = std::mem::take(&mut self.spill_buf);
        self.writer.spill_frontier(&self.source_id, &mut buf)?;
        self.spill_buf = buf;
        Ok(())
    }

    fn build_entry(
        &self,
        parent_entry_id: Option<i64>,
        rel: Vec<u8>,
        name: &[u8],
        st: &StatData,
        scan_error: Option<String>,
    ) -> NewEntry {
        let display_name = String::from_utf8_lossy(name).into_owned();
        let path_encoding_warning = std::str::from_utf8(&rel).is_err();
        let is_regular = st.kind == EntryKind::RegularFile;
        let (category_id, extension) = if is_regular {
            let (cat, ext) = self.config.ruleset.classify(&display_name);
            (Some(cat), ext)
        } else {
            (None, None)
        };
        NewEntry {
            source_id: self.source_id.clone(),
            parent_entry_id,
            raw_relative_path: rel,
            display_name,
            path_encoding_warning,
            entry_kind: kind_str(st.kind),
            file_identity_key: if is_regular {
                Some(format!(
                    "{}:{}",
                    st.identity.device_id, st.identity.inode_id
                ))
            } else {
                None
            },
            device_id: Some(st.identity.device_id.to_string()),
            inode_id: Some(st.identity.inode_id.to_string()),
            nlink: Some(st.nlink as i64),
            uid: Some(i64::from(st.uid)),
            gid: Some(i64::from(st.gid)),
            mode: Some(i64::from(st.mode)),
            size_bytes: is_regular.then_some(st.size_bytes),
            allocated_bytes_estimate: is_regular.then_some(st.allocated_bytes_estimate),
            mtime: Some(st.mtime),
            atime: Some(st.atime),
            ctime: Some(st.ctime),
            category_id,
            extension,
            scan_error,
        }
    }

    /// Minimal placeholder row for an entry whose stat failed (keeps the
    /// directory listing visible in the index with its error attached).
    fn minimal_entry(
        &self,
        dir_id: i64,
        rel: Vec<u8>,
        name: &[u8],
        kind: EntryKind,
        msg: &str,
    ) -> NewEntry {
        NewEntry {
            source_id: self.source_id.clone(),
            parent_entry_id: Some(dir_id),
            raw_relative_path: rel,
            display_name: String::from_utf8_lossy(name).into_owned(),
            path_encoding_warning: std::str::from_utf8(name).is_err(),
            entry_kind: kind_str(kind),
            file_identity_key: None,
            device_id: None,
            inode_id: None,
            nlink: None,
            uid: None,
            gid: None,
            mode: None,
            size_bytes: None,
            allocated_bytes_estimate: None,
            mtime: None,
            atime: None,
            ctime: None,
            category_id: None,
            extension: None,
            scan_error: Some(msg.to_string()),
        }
    }

    fn handle_entry_error(
        &mut self,
        dir_id: i64,
        rel: &[u8],
        name: &[u8],
        kind: EntryKind,
        e: &FsSecureError,
    ) -> Result<(), Abort> {
        match e {
            // File vanished between readdir and stat (spec 10.4): counted,
            // never fatal, and no entry row is created for it.
            FsSecureError::NotFound => {
                self.accum.vanished_count += 1;
                self.writer.record_error(
                    &self.source_id,
                    Some(rel),
                    errno_of(e),
                    "vanished",
                    "entry vanished between listing and stat",
                )?;
            }
            FsSecureError::MountCrossingNotAllowed => {
                // Submount: recorded but never descended (spec 10.1).
                self.accum.mount_boundary_count += 1;
                self.writer.record_error(
                    &self.source_id,
                    Some(rel),
                    errno_of(e),
                    "mount_boundary",
                    "st_dev changed below the source root; submount skipped",
                )?;
                let entry = self.minimal_entry(dir_id, rel.to_vec(), name, kind, "mount_boundary");
                self.writer.queue_entry(entry);
            }
            FsSecureError::PermissionDenied => {
                self.accum.error_count += 1;
                self.writer.record_error(
                    &self.source_id,
                    Some(rel),
                    errno_of(e),
                    "permission_denied",
                    "permission denied while reading metadata",
                )?;
                let entry =
                    self.minimal_entry(dir_id, rel.to_vec(), name, kind, "permission_denied");
                self.writer.queue_entry(entry);
            }
            other => {
                self.accum.error_count += 1;
                self.writer.record_error(
                    &self.source_id,
                    Some(rel),
                    errno_of(other),
                    "stat",
                    &format!("metadata read failed: {other}"),
                )?;
                let entry = self.minimal_entry(dir_id, rel.to_vec(), name, kind, "stat_failed");
                self.writer.queue_entry(entry);
            }
        }
        Ok(())
    }

    fn handle_dir_error(
        &mut self,
        dir_id: i64,
        rel: &[u8],
        e: &FsSecureError,
    ) -> Result<(), Abort> {
        let (category, message) = match e {
            FsSecureError::NotFound => {
                self.accum.vanished_count += 1;
                (
                    "vanished",
                    "directory vanished before it could be listed".to_string(),
                )
            }
            FsSecureError::PermissionDenied => {
                self.accum.error_count += 1;
                (
                    "permission_denied",
                    "permission denied while listing directory".to_string(),
                )
            }
            other => {
                self.accum.error_count += 1;
                ("read_dir", format!("directory listing failed: {other}"))
            }
        };
        self.writer
            .record_error(&self.source_id, Some(rel), errno_of(e), category, &message)?;
        self.writer.set_entry_scan_error(dir_id, &message)?;
        Ok(())
    }

    fn sync_progress(&self) {
        let a = &self.accum;
        self.control.update(|p| {
            p.dirs_visited = a.dirs_visited;
            p.files_seen = a.file_count;
            p.logical_bytes = a.logical_bytes;
            p.error_count = a.error_count;
            p.vanished_count = a.vanished_count;
            p.excluded_count = a.excluded_count;
        });
    }

    /// Flush everything, write the source observation, build the outcome.
    fn finish(&mut self, cancelled: bool, detail: Option<&str>) -> AppResult<SourceScanOutcome> {
        self.flush_spill_buf().map_err(|abort| match abort {
            Abort::Cancelled => internal("扫描在 frontier 落盘时取消"),
            Abort::Fatal(error) => error,
        })?;
        self.writer.flush()?;
        self.sync_progress();
        self.control.emit();

        let (unique_logical, unique_alloc) = self.writer.source_unique(&self.source_id);
        let status = if self.root_unavailable {
            SourceStatus::Unavailable
        } else if cancelled || self.accum.error_count > 0 || self.accum.vanished_count > 0 {
            SourceStatus::Partial
        } else {
            SourceStatus::Complete
        };
        self.writer.record_observation(
            &self.source_id,
            status.as_str(),
            self.accum.error_count,
            self.accum.vanished_count,
            0,
            self.accum.excluded_count,
            detail,
        )?;
        Ok(SourceScanOutcome {
            source_id: self.source_id.clone(),
            status,
            file_count: self.accum.file_count,
            dir_count: self.accum.dir_count,
            logical_bytes: self.accum.logical_bytes,
            unique_logical_bytes: unique_logical,
            allocated_bytes: unique_alloc,
            error_count: self.accum.error_count,
            vanished_count: self.accum.vanished_count,
            excluded_count: self.accum.excluded_count,
            mount_boundary_count: self.accum.mount_boundary_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{FixtureRoot, create_golden};
    use crate::source::{
        AtimeQuality, Availability, IdentityStatus, ReadPolicy, Source, StorageKind,
    };
    use serde_json::Value;
    use tempfile::tempdir;

    fn source() -> Source {
        Source {
            id: "metadata-workers-source".to_string(),
            name: "metadata-workers".to_string(),
            mount_key: "main".to_string(),
            raw_relative_root: Vec::new(),
            volume_id: None,
            storage_kind: StorageKind::Local,
            read_policy: ReadPolicy::ContentAllowed,
            write_enabled: false,
            protected: false,
            exclusions: Vec::new(),
            identity_status: IdentityStatus::Verified,
            identity_epoch: 1,
            identity_json: Value::Null,
            availability: Availability::Online,
            atime_quality: AtimeQuality::Unknown,
            disabled_at: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn metadata_workers_two_scan_with_fixed_bounded_admission() {
        let fixture = FixtureRoot::new().unwrap();
        create_golden(&fixture.root).unwrap();
        let secure_root = SecureRoot::open(fixture.root.as_os_str()).unwrap();
        let file_open_budget = FileOpenBudget::new(16).unwrap();
        let mut pipeline = MetadataPipeline::new(&secure_root, 2, &file_open_budget).unwrap();

        assert_eq!(pipeline.worker_count, 2);
        assert_eq!(pipeline.workers.len(), 2);
        assert_eq!(
            pipeline
                .workers
                .iter()
                .map(|worker| worker.thread().name())
                .collect::<Vec<_>>(),
            vec![Some("metadata-worker-0"), Some("metadata-worker-1")]
        );
        assert_eq!(pipeline.request_tx.as_ref().unwrap().capacity(), Some(2));
        assert_eq!(pipeline.response_rx.capacity(), Some(2));
        pipeline.shutdown().unwrap();

        let index_root = tempdir().unwrap();
        let index_path = index_root.path().join("index.sqlite");
        let config = ScanConfig {
            sources: vec![ScanSource {
                source: source(),
                mount_path: fixture.root.clone(),
            }],
            include_hidden: false,
            metadata_workers: 2,
            ..ScanConfig::default()
        };
        let mut writer = IndexWriter::open(&index_path).unwrap();
        let result = scan_source(
            &config.sources[0],
            &config,
            &mut writer,
            &ScanControl::new(),
            &file_open_budget,
        )
        .unwrap();

        assert!(!result.cancelled);
        assert_eq!(result.outcome.status, SourceStatus::Complete);
        assert_eq!(result.outcome.file_count, 8);
        assert_eq!(result.outcome.dir_count, 4);
    }
}
