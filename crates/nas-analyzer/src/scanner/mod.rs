//! M2 streaming scan engine core (spec 5, 8.1, 10.1–10.5, 15.6, 16.2).
//!
//! Synchronous, dedicated-thread design: `run_scan` blocks the calling worker
//! thread; it never touches the Tokio runtime. All filesystem access goes
//! through `fssecure::SecureRoot`; all index writes go through a single
//! `rusqlite::Connection` owned by the scan thread.
//!
//! Bounded-memory contract:
//! - directory frontier is an in-memory `VecDeque` capped at
//!   `ScanConfig::frontier_memory_cap` (default 4096); overflow spills to the
//!   run index `frontier` table in batches and is reloaded in batches;
//! - entries are written in transactions of `batch_rows` (default 1000) or
//!   ~1s, whichever comes first;
//! - hardlink/identity dedupe uses a SQLite TEMP table (`seen_identity`),
//!   never a Rust HashSet;
//! - DFS interval assignment and aggregates stream through SQL with keyset
//!   pagination; no query result is fully materialized in Rust memory.
//!
//! Metadata reads use a fixed-size per-source worker pool. The SQLite writer
//! and traversal frontier remain owned by the scan thread; workers only
//! perform security-root stat calls and return owned results over bounded
//! channels.

mod index_aggregates;
mod index_writer;
pub mod rules;
mod walk;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crossbeam_channel::Sender;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::category::CategoryRuleset;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::profile::FileKindPolicy;
use crate::resource::FileOpenBudget;
use crate::source::Source;

pub use rules::{Decision, ExcludeReason, RuleEngine};

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

/// One source to scan; `mount_path` is resolved by the caller from
/// `DeploymentConfig::approved_mounts` via `source.mount_key`.
#[derive(Debug, Clone)]
pub struct ScanSource {
    pub source: Source,
    pub mount_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub sources: Vec<ScanSource>,
    pub ruleset: CategoryRuleset,
    /// Task-level exclusion globs (spec 10.2); source-level
    /// `Source::exclusions` are merged in per source.
    pub exclude_globs: Vec<String>,
    /// Task-level inclusion globs; empty = include everything not excluded.
    /// Includes never prune directories (a non-matching parent may still
    /// contain matching descendants).
    pub include_globs: Vec<String>,
    /// Include dotfiles/dirs unless otherwise excluded. Default true.
    pub include_hidden: bool,
    /// Preset "skip system index & recycle" names (@eaDir, #recycle,
    /// $RECYCLE.BIN). Toggleable; default on. The system-forced exclusions
    /// (quarantine + app data dirs) are always on and cannot be disabled.
    pub skip_system_dirs_preset: bool,
    /// Fixed metadata worker admission limit (spec 15.6).
    pub metadata_workers: u32,
    /// Entries per index write transaction (also flushed after ~1s).
    pub batch_rows: usize,
    /// In-memory directory frontier cap before spilling to the index.
    pub frontier_memory_cap: usize,
    pub file_kind_policy: FileKindPolicy,
    /// Deployment-level cap for filesystem handles used by this scan.
    pub max_open_files: u32,
    /// A worker-process budget shared with the hash stage when present.
    pub(crate) file_open_budget: Option<std::sync::Arc<FileOpenBudget>>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            ruleset: CategoryRuleset::default_v1(),
            exclude_globs: Vec::new(),
            include_globs: Vec::new(),
            include_hidden: true,
            skip_system_dirs_preset: true,
            metadata_workers: 1,
            batch_rows: 1000,
            frontier_memory_cap: 4096,
            file_kind_policy: FileKindPolicy::RegularOnly,
            max_open_files: 16,
            file_open_budget: None,
        }
    }
}

/// Cooperative cancel/pause control plus progress reporting, shared via
/// `Arc<ScanControl>` between the driving thread and the scan thread.
pub struct ScanControl {
    cancelled: AtomicBool,
    paused: AtomicBool,
    progress: Mutex<ScanProgress>,
    events: Option<Sender<ProgressEvent>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    Traversing,
    Aggregating,
    Done,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanProgress {
    pub phase: Option<ScanPhase>,
    pub source_id: Option<String>,
    pub dirs_visited: u64,
    pub files_seen: u64,
    pub logical_bytes: u64,
    pub error_count: u64,
    pub vanished_count: u64,
    pub excluded_count: u64,
    /// True while the scan thread is actually blocked in a pause checkpoint.
    pub pause_engaged: bool,
}

/// Progress events are emitted on directory boundaries and write batches.
/// The bounded channel (caller's choice, 2048 recommended) is never allowed
/// to block the scan: events are dropped when full.
pub type ProgressEvent = ScanProgress;

impl Default for ScanControl {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanControl {
    pub fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            progress: Mutex::new(ScanProgress::default()),
            events: None,
        }
    }

    pub fn with_event_sender(events: Sender<ProgressEvent>) -> Self {
        Self {
            events: Some(events),
            ..Self::new()
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    pub fn snapshot(&self) -> ScanProgress {
        self.progress.lock().clone()
    }

    pub(crate) fn update(&self, f: impl FnOnce(&mut ScanProgress)) {
        f(&mut self.progress.lock());
    }

    pub(crate) fn set_phase(&self, phase: ScanPhase, source_id: Option<String>) {
        self.update(|p| {
            p.phase = Some(phase);
            p.source_id = source_id;
        });
        self.emit();
    }

    pub(crate) fn emit(&self) {
        if let Some(tx) = &self.events {
            // Never block the scan on a full progress channel.
            let _ = tx.try_send(self.progress.lock().clone());
        }
    }

    /// Cooperative checkpoint: honours pause (50ms poll) and cancel. Called
    /// at every directory boundary and every write batch (and at least every
    /// few hundred entries inside huge directories).
    pub(crate) fn checkpoint(&self) -> Result<(), Cancelled> {
        if self.is_cancelled() {
            return Err(Cancelled);
        }
        if self.is_paused() {
            self.update(|p| p.pause_engaged = true);
            loop {
                std::thread::sleep(Duration::from_millis(50));
                if self.is_cancelled() {
                    self.update(|p| p.pause_engaged = false);
                    return Err(Cancelled);
                }
                if !self.is_paused() {
                    break;
                }
            }
            self.update(|p| p.pause_engaged = false);
        }
        Ok(())
    }
}

/// Internal cancellation signal; converted into `ScanStatus::Cancelled` by
/// `run_scan` after index consistency wrap-up.
pub(crate) struct Cancelled;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus {
    Complete,
    Partial,
    Unavailable,
}

impl SourceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceScanOutcome {
    pub source_id: String,
    pub status: SourceStatus,
    /// Regular file paths counted (entry 口径; hardlink aliases included).
    pub file_count: u64,
    /// Directory entries below the source root (root itself excluded).
    pub dir_count: u64,
    pub logical_bytes: u64,
    /// Deduped by `file_identity_key` across the whole run; an object is
    /// attributed to the source where it was first seen (documented
    /// statistical convention, spec 5.2).
    pub unique_logical_bytes: Option<u64>,
    /// `st_blocks * 512`, deduped by identity like `unique_logical_bytes`.
    pub allocated_bytes: Option<u64>,
    pub error_count: u64,
    pub vanished_count: u64,
    /// Entries excluded by rules (forced/preset/glob/hidden/include).
    pub excluded_count: u64,
    /// Submounts skipped at a st_dev boundary (not descended).
    pub mount_boundary_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Complete,
    Partial,
    /// Every source was unavailable (spec 10.4: 全范围失败).
    Failed,
    Cancelled,
}

impl ScanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub status: ScanStatus,
    pub outcomes: Vec<SourceScanOutcome>,
    pub index_path: PathBuf,
}

/// Run a full scan synchronously on the current thread. `index_path` is the
/// run index file (`<runs_dir>/<run_id>/index.sqlite`); its parent directory
/// is created if missing. On cancel the in-flight batch is committed and
/// observations recorded before returning `ScanStatus::Cancelled` with a
/// consistent partial index.
pub fn run_scan(
    config: &ScanConfig,
    control: &ScanControl,
    index_path: &Path,
) -> AppResult<ScanResult> {
    // Validate glob syntax up front (per-source merges are re-validated per
    // source inside the walk).
    RuleEngine::build(
        &config.exclude_globs,
        &config.include_globs,
        config.include_hidden,
        config.skip_system_dirs_preset,
    )?;
    if let Some(parent) = index_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| internal(format!("create run dir {}: {e}", parent.display())))?;
    }
    let mut writer = index_writer::IndexWriter::open(index_path)?;
    let file_open_budget = config
        .file_open_budget
        .clone()
        .unwrap_or(FileOpenBudget::new(config.max_open_files)?);
    writer.run_meta("ruleset_version", &config.ruleset.version.to_string())?;
    writer.run_meta(
        "include_hidden",
        if config.include_hidden { "1" } else { "0" },
    )?;

    let mut outcomes = Vec::new();
    let mut cancelled = false;
    for scan_source in &config.sources {
        let res = walk::scan_source(scan_source, config, &mut writer, control, &file_open_budget)?;
        cancelled = res.cancelled;
        outcomes.push(res.outcome);
        if cancelled {
            break;
        }
    }

    let status = if cancelled {
        ScanStatus::Cancelled
    } else {
        control.set_phase(ScanPhase::Aggregating, None);
        let ids: Vec<String> = outcomes.iter().map(|o| o.source_id.clone()).collect();
        if writer.finalize(&ids, control)? {
            ScanStatus::Cancelled
        } else if !outcomes.is_empty()
            && outcomes
                .iter()
                .all(|o| o.status == SourceStatus::Unavailable)
        {
            ScanStatus::Failed
        } else if outcomes.iter().any(|o| o.status != SourceStatus::Complete) {
            ScanStatus::Partial
        } else {
            ScanStatus::Complete
        }
    };

    writer.run_meta("scan_status", status.as_str())?;
    writer.run_meta_now("scan_finished_at")?;
    writer.checkpoint_for_publication()?;
    control.set_phase(ScanPhase::Done, None);
    Ok(ScanResult {
        status,
        outcomes,
        index_path: index_path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duplicates;
    use crate::fixture::{FixtureRoot, create_golden};
    use crate::profile::{FileKindPolicy, ProfileDuplicates};
    use rusqlite::Connection;
    use serde_json::Value;
    use tempfile::tempdir;

    fn source() -> Source {
        Source {
            id: "source-frontier".to_string(),
            name: "frontier".to_string(),
            mount_key: "main".to_string(),
            raw_relative_root: Vec::new(),
            volume_id: None,
            storage_kind: crate::source::StorageKind::Local,
            read_policy: crate::source::ReadPolicy::ContentAllowed,
            write_enabled: false,
            protected: false,
            exclusions: Vec::new(),
            identity_status: crate::source::IdentityStatus::Verified,
            identity_epoch: 1,
            identity_json: Value::Null,
            availability: crate::source::Availability::Online,
            atime_quality: crate::source::AtimeQuality::Unknown,
            disabled_at: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn frontier_spill_processes_a_partial_final_batch() {
        let root = tempdir().unwrap();
        for index in 0..17 {
            let directory = root.path().join(format!("directory-{index}"));
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join("file.txt"), b"x").unwrap();
        }

        let index_root = tempdir().unwrap();
        let index_path = index_root.path().join("index.sqlite");
        let config = ScanConfig {
            sources: vec![ScanSource {
                source: source(),
                mount_path: root.path().to_path_buf(),
            }],
            frontier_memory_cap: 16,
            batch_rows: 1,
            ..ScanConfig::default()
        };
        let control = ScanControl::new();
        let result = run_scan(&config, &control, &index_path).unwrap();
        assert_eq!(result.status, ScanStatus::Complete);
        assert_eq!(result.outcomes[0].file_count, 17);

        let conn = Connection::open(index_path).unwrap();
        let indexed_files: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE entry_kind = 'regular_file'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(indexed_files, 17);
    }

    #[test]
    fn golden_fixture_scans_aggregates_and_confirms_duplicates() {
        let fixture = FixtureRoot::new().unwrap();
        create_golden(&fixture.root).unwrap();
        let index_root = tempdir().unwrap();
        let index_path = index_root.path().join("index.sqlite");
        let source = source();
        let config = ScanConfig {
            sources: vec![ScanSource {
                source,
                mount_path: fixture.root.clone(),
            }],
            include_hidden: false,
            batch_rows: 2,
            ..ScanConfig::default()
        };

        let result = run_scan(&config, &ScanControl::new(), &index_path).unwrap();
        assert_eq!(result.status, ScanStatus::Complete);
        assert_eq!(result.outcomes.len(), 1);
        assert_eq!(result.outcomes[0].file_count, 8);
        assert_eq!(result.outcomes[0].dir_count, 4);
        assert_eq!(result.outcomes[0].logical_bytes, 50);
        assert_eq!(result.outcomes[0].unique_logical_bytes, Some(44));
        assert_eq!(result.outcomes[0].excluded_count, 1);

        let conn = Connection::open(&index_path).unwrap();
        let (root_id, file_count, dir_count, logical_bytes, unique_logical_bytes): (
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = conn
            .query_row(
                "SELECT e.entry_id, a.file_count, a.dir_count, a.logical_bytes,
                        a.unique_logical_bytes
                 FROM entries e
                 JOIN directory_aggregates a ON a.entry_id = e.entry_id
                 WHERE e.source_id = ?1 AND e.parent_entry_id IS NULL",
                ["source-frontier"],
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
            .unwrap();
        assert!(root_id > 0);
        assert_eq!(
            (file_count, dir_count, logical_bytes, unique_logical_bytes),
            (8, 4, 50, 44)
        );

        for (category, expected_count, expected_bytes) in [
            ("documents", 6_i64, 33_i64),
            ("disk_images", 1, 17),
            ("other", 1, 0),
        ] {
            let actual: (i64, i64) = conn
                .query_row(
                    "SELECT file_count, logical_bytes
                     FROM category_aggregates
                     WHERE source_id = ?1 AND category_id = ?2",
                    ("source-frontier", category),
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(actual, (expected_count, expected_bytes), "{category}");
        }
        let distinct_objects: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT file_identity_key)
                 FROM entries
                 WHERE source_id = ?1 AND entry_kind = 'regular_file'",
                ["source-frontier"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(distinct_objects, 7);

        let duplicates = ProfileDuplicates {
            enabled: true,
            ..ProfileDuplicates::default()
        };
        let hash_result = duplicates::process_index(
            &index_path,
            &duplicates,
            &config.sources,
            &ScanControl::new(),
            2,
            0,
        )
        .unwrap();
        assert!(!hash_result.partial);
        assert_eq!(hash_result.group_count, 1);
        assert_eq!(hash_result.hashed_bytes, 30);

        let (group_id, member_count, listed_member_count, redundancy): (i64, i64, i64, i64) = conn
            .query_row(
                "SELECT group_id, member_count, listed_member_count,
                        logical_redundancy_bytes
                 FROM duplicate_groups",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!((member_count, listed_member_count, redundancy), (4, 4, 12));
        let hardlink_aliases: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM duplicate_members
                 WHERE group_id = ?1 AND is_hardlink_alias = 1",
                [group_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(hardlink_aliases, 1);
    }

    #[cfg(unix)]
    #[test]
    fn all_metadata_indexes_special_entry_metadata_without_reading_content() {
        use std::os::unix::fs::symlink;

        let fixture = FixtureRoot::new().unwrap();
        std::fs::write(fixture.root.join("target.txt"), b"target").unwrap();
        symlink(
            fixture.root.join("target.txt"),
            fixture.root.join("link.txt"),
        )
        .unwrap();
        let index_root = tempdir().unwrap();
        let index_path = index_root.path().join("index.sqlite");
        let config = ScanConfig {
            sources: vec![ScanSource {
                source: source(),
                mount_path: fixture.root.clone(),
            }],
            file_kind_policy: FileKindPolicy::AllMetadata,
            ..ScanConfig::default()
        };

        let result = run_scan(&config, &ScanControl::new(), &index_path).unwrap();
        assert_eq!(result.status, ScanStatus::Complete);

        let conn = Connection::open(index_path).unwrap();
        let (entry_kind, size_bytes, uid, display_name): (String, Option<i64>, i64, String) = conn
            .query_row(
                "SELECT entry_kind, size_bytes, uid, display_name
                 FROM entries WHERE raw_relative_path = ?1",
                [b"link.txt".as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(entry_kind, "symlink");
        assert_eq!(size_bytes, None);
        assert_eq!(display_name, "link.txt");
        assert!(uid >= 0);
    }
}
