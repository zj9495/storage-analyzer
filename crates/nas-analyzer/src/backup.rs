//! Configuration backup and restore.
//!
//! The archive is deliberately a configuration archive, not a copy of the
//! application directory. It contains a lossless snapshot of the non-secret
//! control tables and a manifest for every payload byte. The deployment file,
//! approved mount list, source contents, reports, indexes, quarantine,
//! passwords, sessions, and tokens are not part of this format.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use age::secrecy::{ExposeSecret, SecretString};
use base64::Engine;
use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OpenFlags, ToSql, params_from_iter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zip::CompressionMethod;
use zip::read::ZipArchive;
use zip::write::{FileOptions, ZipWriter};

use crate::config::DeploymentConfig;
use crate::error::{AppError, AppResult, ErrorCode};

const ARCHIVE_SCHEMA_VERSION: u32 = 1;
const ARCHIVE_KIND: &str = "nas-analyzer-configuration";
const MANIFEST_NAME: &str = "manifest.json";
const CONFIG_NAME: &str = "config.json";
const CONTROL_DB_NAME: &str = "control.sqlite";
const CONFIG_BACKUP_DIR: &str = "config-backups";
const AGE_HEADER: &[u8] = b"age-encryption.org/v1\n";

/// The only currently persisted secret that is eligible for a configuration
/// backup. Authentication material (`admin_users`, `sessions`, setup/reauth
/// tokens) is deliberately not restorable and is never included.
const SECRET_APP_SETTING_KEYS: &[&str] = &["notifications"];
const NON_SECRET_APP_SETTING_KEYS: &[&str] = &["storage", "retention"];

/// Tables that contain configuration or imported metadata. Authentication
/// and operational tables are intentionally absent from this list.
const CONFIG_TABLES: &[&str] = &[
    "app_settings",
    "volumes",
    "sources",
    "identity_mappings",
    "quota_records",
    "category_rulesets",
    "profiles",
    "profile_versions",
];

/// Resource limits applied before any archive payload is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupLimits {
    pub max_archive_bytes: u64,
    pub max_entries: usize,
    pub max_entry_uncompressed_bytes: u64,
    pub max_total_uncompressed_bytes: u64,
}

/// Selects the backup representation without ever becoming a job parameter or
/// an audit payload. The passphrase is held only for the duration of the
/// operation and is redacted by `age::secrecy::SecretString`.
pub struct BackupOptions {
    include_secrets: bool,
    secrets_passphrase: Option<SecretString>,
}

impl BackupOptions {
    /// Create the backwards-compatible unauthenticated configuration format.
    pub fn without_secrets() -> Self {
        Self {
            include_secrets: false,
            secrets_passphrase: None,
        }
    }

    /// Create a passphrase-protected `age` backup. An empty passphrase is not
    /// a valid request because it would not represent user authentication.
    pub fn with_secrets(passphrase: impl Into<String>) -> AppResult<Self> {
        let passphrase = passphrase.into();
        if passphrase.is_empty() {
            return Err(validation("secret backup passphrase must not be empty"));
        }
        Ok(Self {
            include_secrets: true,
            secrets_passphrase: Some(SecretString::from(passphrase)),
        })
    }

    fn secret_passphrase(&self) -> AppResult<&str> {
        match self.secrets_passphrase.as_ref() {
            Some(passphrase) => Ok(passphrase.expose_secret()),
            None => Err(validation("secret backup requires a non-empty passphrase")),
        }
    }
}

impl Default for BackupLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 128 * 1024 * 1024,
            max_entries: 16,
            max_entry_uncompressed_bytes: 32 * 1024 * 1024,
            max_total_uncompressed_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSummary {
    pub output: PathBuf,
    pub entries: usize,
    pub config_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePlan {
    pub input: PathBuf,
    pub schema_version: u32,
    pub entries: usize,
    pub total_uncompressed_bytes: u64,
    pub table_count: usize,
    pub row_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestoreDifference {
    pub key: String,
    pub change: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreResult {
    pub dry_run: bool,
    pub plan: RestorePlan,
    pub pre_restore_backup: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    archive_kind: String,
    schema_version: u32,
    created_at: String,
    entries: Vec<ManifestEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    path: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDocument {
    schema_version: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    contains_secrets: bool,
    tables: Vec<TableSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TableSnapshot {
    name: String,
    columns: Vec<String>,
    rows: Vec<Vec<Cell>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
enum Cell {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(String),
}

struct ArchivePayload {
    manifest: Manifest,
    config: ConfigDocument,
    total_uncompressed_bytes: u64,
}

/// Create a configuration backup at output.
pub fn create_backup(
    data_dir: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> AppResult<BackupSummary> {
    create_backup_with_limits(data_dir.as_ref(), output.as_ref(), BackupLimits::default())
}

/// Create a configuration backup using explicit archive limits.
pub fn create_backup_with_limits(
    data_dir: &Path,
    output: &Path,
    limits: BackupLimits,
) -> AppResult<BackupSummary> {
    create_backup_with_options(data_dir, output, &BackupOptions::without_secrets(), limits)
}

/// Create a configuration backup with an explicit secret-inclusion policy.
/// Secret backups are standard age passphrase files containing the legacy ZIP
/// as their authenticated plaintext; ordinary backups remain byte-compatible
/// with the original ZIP format.
pub fn create_backup_with_options(
    data_dir: &Path,
    output: &Path,
    options: &BackupOptions,
    limits: BackupLimits,
) -> AppResult<BackupSummary> {
    let root = open_data_root(data_dir)?;
    let output_rel = relative_path(data_dir, output, "backup output")?;
    let control = root
        .open_file(
            OsStr::new(CONTROL_DB_NAME),
            fssecure::OpenOptions::default(),
        )
        .map_err(|e| map_fs_error("open control database", e))?;
    if control.stat.kind != fssecure::EntryKind::RegularFile {
        return Err(validation("control database is not a regular file"));
    }
    let config = read_config_document_from_opened(control, options.include_secrets)?;
    let config_bytes = serde_json::to_vec_pretty(&config)
        .map_err(|e| internal(format!("serialize configuration snapshot: {e}")))?;
    let config_len = u64::try_from(config_bytes.len())
        .map_err(|_| validation("configuration snapshot is too large"))?;
    if config_len > limits.max_entry_uncompressed_bytes {
        return Err(validation("configuration snapshot exceeds the entry limit"));
    }

    let manifest = Manifest {
        archive_kind: ARCHIVE_KIND.to_string(),
        schema_version: ARCHIVE_SCHEMA_VERSION,
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        entries: vec![ManifestEntry {
            path: CONFIG_NAME.to_string(),
            size_bytes: config_len,
            sha256: sha256_hex(&config_bytes),
        }],
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| internal(format!("serialize backup manifest: {e}")))?;
    let manifest_len = u64::try_from(manifest_bytes.len())
        .map_err(|_| validation("backup manifest is too large"))?;
    let total_uncompressed = config_len
        .checked_add(manifest_len)
        .ok_or_else(|| validation("backup size arithmetic overflow"))?;
    if manifest_len > limits.max_entry_uncompressed_bytes
        || total_uncompressed > limits.max_total_uncompressed_bytes
    {
        return Err(validation("backup exceeds the configured size limit"));
    }

    let parent = output_rel
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    if !parent.as_os_str().is_empty() {
        root.mkdir_all(parent.as_os_str(), 0o700)
            .map_err(|e| map_fs_error("create backup directory", e))?;
    }
    let temp_rel = temporary_sibling(&output_rel, "backup")?;
    let zip_bytes = build_zip_archive(&config_bytes, &manifest_bytes)?;
    let archive_bytes = match options.secrets_passphrase.as_ref() {
        Some(passphrase) => encrypt_age(passphrase.expose_secret(), &zip_bytes)?,
        None if options.include_secrets => {
            return Err(validation("secret backup requires a non-empty passphrase"));
        }
        None => zip_bytes,
    };
    let archive_len = u64::try_from(archive_bytes.len())
        .map_err(|_| validation("backup archive is too large"))?;
    if archive_len > limits.max_archive_bytes {
        return Err(validation("backup archive exceeds the archive size limit"));
    }
    let result = write_archive(&root, &temp_rel, output_rel.as_os_str(), &archive_bytes);
    if let Err(error) = result {
        remove_temp_file(&root, &temp_rel)?;
        return Err(error);
    }

    root.fsync_dir(parent.as_os_str())
        .map_err(|e| map_fs_error("sync backup directory", e))?;
    let output_path = data_dir.join(&output_rel);
    let restore_passphrase = options
        .secrets_passphrase
        .as_ref()
        .map(|passphrase| passphrase.expose_secret());
    if let Err(error) = preflight_restore_with_passphrase_and_limits(
        data_dir,
        &output_path,
        restore_passphrase,
        limits,
    ) {
        remove_file_if_regular(&root, output_rel.as_os_str())?;
        return Err(error);
    }

    Ok(BackupSummary {
        output: output_path,
        entries: 2,
        config_bytes: config_len,
    })
}

/// Create a passphrase-protected configuration backup containing the eligible
/// secret settings. The passphrase is never serialized into job or audit data.
pub fn create_backup_with_secrets(
    data_dir: &Path,
    output: &Path,
    passphrase: impl Into<String>,
) -> AppResult<BackupSummary> {
    let options = BackupOptions::with_secrets(passphrase)?;
    create_backup_with_options(data_dir, output, &options, BackupLimits::default())
}

/// Validate a restore archive without writing to the data directory.
pub fn preflight_restore(
    data_dir: impl AsRef<Path>,
    input: impl AsRef<Path>,
) -> AppResult<RestorePlan> {
    preflight_restore_with_limits(data_dir.as_ref(), input.as_ref(), BackupLimits::default())
}

/// Compare a validated restore archive with the current configuration.
/// Authentication and operational tables are intentionally excluded by
/// `export_config`, matching the backup contract.
pub fn restore_differences(
    data_dir: &Path,
    input: &Path,
    current: &Connection,
) -> AppResult<(RestorePlan, Vec<RestoreDifference>)> {
    restore_differences_with_passphrase(data_dir, input, current, None, None)
}

/// Compare an authenticated configuration archive with the current
/// configuration after validating the deployment mount allowlist.
pub fn restore_differences_with_secrets(
    data_dir: &Path,
    input: &Path,
    current: &Connection,
    passphrase: impl Into<String>,
    config: &DeploymentConfig,
) -> AppResult<(RestorePlan, Vec<RestoreDifference>)> {
    let options = BackupOptions::with_secrets(passphrase)?;
    restore_differences_with_passphrase(
        data_dir,
        input,
        current,
        Some(options.secret_passphrase()?),
        Some(config),
    )
}

fn restore_differences_with_passphrase(
    data_dir: &Path,
    input: &Path,
    current: &Connection,
    passphrase: Option<&str>,
    config: Option<&DeploymentConfig>,
) -> AppResult<(RestorePlan, Vec<RestoreDifference>)> {
    let payload =
        read_archive_with_passphrase(data_dir, input, passphrase, BackupLimits::default())?;
    if let Some(config) = config {
        validate_config_mounts(&payload.config, config)?;
    }
    let plan = make_restore_plan(input, &payload);
    let current = export_config(current, passphrase.is_some())?;
    let incoming = payload
        .config
        .tables
        .into_iter()
        .map(|table| (table.name.clone(), table))
        .collect::<BTreeMap<_, _>>();
    let current = current
        .tables
        .into_iter()
        .map(|table| (table.name.clone(), table))
        .collect::<BTreeMap<_, _>>();
    let incoming_json = incoming
        .iter()
        .map(|(name, table)| {
            serde_json::to_vec(table)
                .map(|value| (name.clone(), value))
                .map_err(|e| internal(format!("serialize incoming restore comparison: {e}")))
        })
        .collect::<AppResult<BTreeMap<_, _>>>()?;
    let current_json = current
        .iter()
        .map(|(name, table)| {
            serde_json::to_vec(table)
                .map(|value| (name.clone(), value))
                .map_err(|e| internal(format!("serialize current restore comparison: {e}")))
        })
        .collect::<AppResult<BTreeMap<_, _>>>()?;
    let names = incoming
        .keys()
        .chain(current.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut differences = Vec::new();
    for name in names {
        match (current.get(&name), incoming.get(&name)) {
            (None, Some(_)) => differences.push(RestoreDifference {
                key: name,
                change: "added".to_string(),
            }),
            (Some(_), None) => differences.push(RestoreDifference {
                key: name,
                change: "removed".to_string(),
            }),
            (Some(_), Some(_)) if current_json[&name] != incoming_json[&name] => {
                differences.push(RestoreDifference {
                    key: name,
                    change: "modified".to_string(),
                });
            }
            (Some(_), Some(_)) => {}
            (None, None) => unreachable!(),
        }
    }
    Ok((plan, differences))
}

/// Validate that every source in a restore archive still belongs to the
/// deployment's approved mount boundary. The archive stores only a mount key
/// and a mount-relative byte path; the current deployment configuration is
/// the authority for whether that key remains approved.
pub fn validate_restore_scope(
    data_dir: &Path,
    input: &Path,
    config: &DeploymentConfig,
) -> AppResult<RestorePlan> {
    validate_restore_scope_internal(data_dir, input, config, None)
}

/// Validate an authenticated archive, including its authentication tag, size
/// limits, and current deployment mount allowlist.
pub fn validate_restore_scope_with_secrets(
    data_dir: &Path,
    input: &Path,
    config: &DeploymentConfig,
    passphrase: impl Into<String>,
) -> AppResult<RestorePlan> {
    let options = BackupOptions::with_secrets(passphrase)?;
    validate_restore_scope_internal(data_dir, input, config, Some(options.secret_passphrase()?))
}

fn validate_restore_scope_internal(
    data_dir: &Path,
    input: &Path,
    config: &DeploymentConfig,
    passphrase: Option<&str>,
) -> AppResult<RestorePlan> {
    let payload =
        read_archive_with_passphrase(data_dir, input, passphrase, BackupLimits::default())?;
    validate_config_mounts(&payload.config, config)?;
    Ok(make_restore_plan(input, &payload))
}

/// Validate a restore archive using explicit limits.
pub fn preflight_restore_with_limits(
    data_dir: &Path,
    input: &Path,
    limits: BackupLimits,
) -> AppResult<RestorePlan> {
    preflight_restore_with_passphrase_and_limits(data_dir, input, None, limits)
}

/// Validate either archive format using explicit size limits and, for an age
/// archive, the caller-provided passphrase.
fn preflight_restore_with_passphrase_and_limits(
    data_dir: &Path,
    input: &Path,
    passphrase: Option<&str>,
    limits: BackupLimits,
) -> AppResult<RestorePlan> {
    let payload = read_archive_with_passphrase(data_dir, input, passphrase, limits)?;
    Ok(make_restore_plan(input, &payload))
}

/// Validate an authenticated restore archive and its current deployment scope.
pub fn preflight_restore_with_secrets(
    data_dir: &Path,
    input: &Path,
    passphrase: impl Into<String>,
    config: &DeploymentConfig,
) -> AppResult<RestorePlan> {
    validate_restore_scope_with_secrets(data_dir, input, config, passphrase)
}

/// Restore a validated configuration archive. dry_run performs only the
/// complete preflight and returns its plan.
pub fn restore_backup(
    data_dir: impl AsRef<Path>,
    input: impl AsRef<Path>,
    dry_run: bool,
) -> AppResult<RestoreResult> {
    restore_backup_with_limits(
        data_dir.as_ref(),
        input.as_ref(),
        dry_run,
        BackupLimits::default(),
    )
}

/// Restore a validated configuration archive using explicit limits.
pub fn restore_backup_with_limits(
    data_dir: &Path,
    input: &Path,
    dry_run: bool,
    limits: BackupLimits,
) -> AppResult<RestoreResult> {
    restore_backup_with_passphrase_and_limits(data_dir, input, dry_run, None, None, limits)
}

/// Restore a configuration archive through an already-open service writer
/// connection.  The serving process already owns the instance lock and the
/// writer serializes all control-database mutations, so replacing the database
/// pathname here would leave the long-lived writer and reader connections
/// attached to the old inode.  This path keeps the existing connection live
/// and commits the configuration replacement as one SQLite transaction.
pub(crate) fn restore_backup_in_connection(
    conn: &mut Connection,
    data_dir: &Path,
    input: &Path,
    passphrase: Option<&str>,
    deployment: &DeploymentConfig,
    finish: impl FnOnce(&rusqlite::Transaction<'_>, &RestoreResult) -> AppResult<serde_json::Value>,
) -> AppResult<serde_json::Value> {
    let payload =
        read_archive_with_passphrase(data_dir, input, passphrase, BackupLimits::default())?;
    validate_config_mounts(&payload.config, deployment)?;
    let plan = make_restore_plan(input, &payload);
    let backup_path = data_dir
        .join(CONFIG_BACKUP_DIR)
        .join(format!("restore-pre-{}.zip", Uuid::new_v4().simple()));
    match passphrase {
        Some(passphrase) => {
            let options = BackupOptions::with_secrets(passphrase.to_owned())?;
            create_backup_with_options(data_dir, &backup_path, &options, BackupLimits::default())?;
        }
        None => {
            create_backup_with_limits(data_dir, &backup_path, BackupLimits::default())?;
        }
    }
    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("begin restore transaction: {e}")))?;
    apply_config_in_transaction(&tx, &payload.config)?;
    let restore = RestoreResult {
        dry_run: false,
        plan,
        pre_restore_backup: Some(backup_path),
    };
    let response = finish(&tx, &restore)?;
    tx.commit()
        .map_err(|e| internal(format!("commit restore transaction: {e}")))?;
    Ok(response)
}

/// Restore a legacy or authenticated configuration archive using explicit
/// limits. For a secret archive, the passphrase is required to authenticate
/// and decrypt the complete payload before restoration begins.
fn restore_backup_with_passphrase_and_limits(
    data_dir: &Path,
    input: &Path,
    dry_run: bool,
    passphrase: Option<&str>,
    deployment: Option<&DeploymentConfig>,
    limits: BackupLimits,
) -> AppResult<RestoreResult> {
    let payload = read_archive_with_passphrase(data_dir, input, passphrase, limits)?;
    if let Some(deployment) = deployment {
        validate_config_mounts(&payload.config, deployment)?;
    } else if passphrase.is_some() {
        return Err(validation(
            "authenticated restore requires deployment scope validation",
        ));
    }
    let plan = make_restore_plan(input, &payload);
    if dry_run {
        return Ok(RestoreResult {
            dry_run: true,
            plan,
            pre_restore_backup: None,
        });
    }

    let _instance_lock = crate::httpapi::acquire_instance_lock(data_dir)?;
    let root = open_data_root(data_dir)?;
    let backup_path = data_dir
        .join(CONFIG_BACKUP_DIR)
        .join(format!("restore-pre-{}.zip", Uuid::new_v4().simple()));
    match passphrase {
        Some(passphrase) => {
            let options = BackupOptions::with_secrets(passphrase.to_owned())?;
            create_backup_with_options(data_dir, &backup_path, &options, limits)?;
        }
        None => {
            create_backup_with_limits(data_dir, &backup_path, limits)?;
        }
    }

    let control_path = data_dir.join(CONTROL_DB_NAME);
    let temp_rel = temporary_sibling(Path::new(CONTROL_DB_NAME), "restore")?;
    let staging = root
        .open_file(
            &temp_rel,
            fssecure::OpenOptions {
                write: true,
                create: true,
                exclusive: true,
                truncate: true,
                noatime: false,
            },
        )
        .map_err(|e| map_fs_error("create restore staging database", e))?;
    let control = root
        .open_file(
            OsStr::new(CONTROL_DB_NAME),
            fssecure::OpenOptions::default(),
        )
        .map_err(|e| map_fs_error("open control database for restore", e))?;
    let staging = File::from(staging.fd);
    let control = File::from(control.fd);
    if let Err(error) = create_restored_database(control, staging, &payload.config) {
        remove_temp_file(&root, &temp_rel)?;
        return Err(error);
    }
    let replaced = replace_control_database(&root, &temp_rel, &control_path);
    if let Err(error) = replaced {
        remove_temp_file(&root, &temp_rel)?;
        return Err(error);
    }
    root.fsync_dir(OsStr::new(""))
        .map_err(|e| map_fs_error("sync data directory after restore", e))?;

    Ok(RestoreResult {
        dry_run: false,
        plan,
        pre_restore_backup: Some(backup_path),
    })
}

/// Restore an authenticated configuration archive after validating its current
/// deployment mount allowlist. The pre-restore backup uses the same passphrase.
pub fn restore_backup_with_secrets(
    data_dir: &Path,
    input: &Path,
    dry_run: bool,
    passphrase: impl Into<String>,
    config: &DeploymentConfig,
) -> AppResult<RestoreResult> {
    let options = BackupOptions::with_secrets(passphrase)?;
    restore_backup_with_passphrase_and_limits(
        data_dir,
        input,
        dry_run,
        Some(options.secret_passphrase()?),
        Some(config),
        BackupLimits::default(),
    )
}

/// String-based aliases for callers that already have command-line arguments.
pub fn backup(data_dir: &str, output: &str) -> AppResult<BackupSummary> {
    create_backup(Path::new(data_dir), Path::new(output))
}

pub fn restore(data_dir: &str, input: &str, dry_run: bool) -> AppResult<RestoreResult> {
    restore_backup(Path::new(data_dir), Path::new(input), dry_run)
}

fn make_restore_plan(input: &Path, payload: &ArchivePayload) -> RestorePlan {
    let row_count = payload
        .config
        .tables
        .iter()
        .map(|table| table.rows.len())
        .sum();
    RestorePlan {
        input: input.to_path_buf(),
        schema_version: payload.config.schema_version,
        entries: payload.manifest.entries.len() + 1,
        total_uncompressed_bytes: payload.total_uncompressed_bytes,
        table_count: payload.config.tables.len(),
        row_count,
    }
}

#[cfg(test)]
fn read_config_document(control_path: &Path, include_secrets: bool) -> AppResult<ConfigDocument> {
    let parent = control_path
        .parent()
        .ok_or_else(|| validation("control database path has no parent"))?;
    let name = control_path
        .file_name()
        .ok_or_else(|| validation("control database path has no file name"))?;
    let root = fssecure::SecureRoot::open(parent.as_os_str())
        .map_err(|e| map_fs_error("open control database root", e))?;
    let opened = root
        .open_file(name, fssecure::OpenOptions::default())
        .map_err(|e| map_fs_error("open control database", e))?;
    read_config_document_from_opened(opened, include_secrets)
}

fn read_config_document_from_opened(
    opened: fssecure::OpenedFile,
    include_secrets: bool,
) -> AppResult<ConfigDocument> {
    let mut conn = open_read_connection_from_file(File::from(opened.fd))?;
    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("begin configuration snapshot: {e}")))?;
    let document = export_config(&tx, include_secrets)?;
    tx.commit()
        .map_err(|e| internal(format!("commit configuration snapshot: {e}")))?;
    Ok(document)
}

fn export_config(conn: &Connection, include_secrets: bool) -> AppResult<ConfigDocument> {
    let mut tables = Vec::with_capacity(CONFIG_TABLES.len());
    for table_name in CONFIG_TABLES {
        let columns = table_columns(conn, table_name)?;
        let sql = format!(
            "SELECT * FROM {} ORDER BY rowid",
            quote_identifier(table_name)
        );
        let mut statement = conn
            .prepare(&sql)
            .map_err(|e| internal(format!("prepare configuration table {table_name}: {e}")))?;
        let mut rows = statement
            .query([])
            .map_err(|e| internal(format!("read configuration table {table_name}: {e}")))?;
        let mut values = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| internal(format!("iterate configuration table {table_name}: {e}")))?
        {
            let mut cells = Vec::with_capacity(columns.len());
            for index in 0..columns.len() {
                let value: SqlValue = row
                    .get(index)
                    .map_err(|e| internal(format!("read {table_name} column {index}: {e}")))?;
                cells.push(cell_from_sql(value)?);
            }
            if *table_name == "app_settings" {
                let key = cell_text(&cells, 0, "app_settings.key")?;
                let keep = key == "initialized"
                    || key == "timezone"
                    || NON_SECRET_APP_SETTING_KEYS.contains(&key)
                    || SECRET_APP_SETTING_KEYS.contains(&key);
                if !keep {
                    continue;
                }
                if key == "notifications" && !include_secrets {
                    sanitize_notification_setting(&mut cells)?;
                }
            }
            values.push(cells);
        }
        tables.push(TableSnapshot {
            name: (*table_name).to_string(),
            columns,
            rows: values,
        });
    }
    Ok(ConfigDocument {
        schema_version: ARCHIVE_SCHEMA_VERSION,
        contains_secrets: include_secrets,
        tables,
    })
}

fn read_archive_with_passphrase(
    data_dir: &Path,
    input: &Path,
    passphrase: Option<&str>,
    limits: BackupLimits,
) -> AppResult<ArchivePayload> {
    let root = open_data_root(data_dir)?;
    let input_rel = relative_path(data_dir, input, "restore input")?;
    let opened = root
        .open_file(input_rel.as_os_str(), fssecure::OpenOptions::default())
        .map_err(|e| map_fs_error("open restore archive", e))?;
    if opened.stat.kind != fssecure::EntryKind::RegularFile {
        return Err(validation("restore input is not a regular file"));
    }
    let archive_size = u64::try_from(opened.stat.size_bytes)
        .map_err(|_| validation("restore archive has an invalid size"))?;
    if archive_size > limits.max_archive_bytes {
        return Err(validation("restore archive exceeds the archive size limit"));
    }
    let mut file = File::from(opened.fd);
    let archive_bytes = read_bounded(&mut file, limits.max_archive_bytes, "restore archive")?;
    if archive_bytes.starts_with(AGE_HEADER) {
        let passphrase = passphrase
            .ok_or_else(|| validation("authenticated restore archive requires a passphrase"))?;
        let plaintext = decrypt_age(passphrase, &archive_bytes, limits.max_archive_bytes)?;
        read_zip_payload_bytes(&plaintext, input, limits, true)
    } else {
        if passphrase.is_some() {
            return Err(validation(
                "passphrase provided for a non-authenticated restore archive",
            ));
        }
        read_zip_payload_bytes(&archive_bytes, input, limits, false)
    }
}

fn read_zip_payload_bytes(
    bytes: &[u8],
    _input: &Path,
    limits: BackupLimits,
    authenticated: bool,
) -> AppResult<ArchivePayload> {
    let mut central_reader = std::io::Cursor::new(bytes);
    let mut archive_reader = std::io::Cursor::new(bytes);
    let mut archive = ZipArchive::new(&mut archive_reader)
        .map_err(|e| validation(format!("invalid restore ZIP: {e}")))?;
    validate_central_directory(
        &mut central_reader,
        archive.central_directory_start(),
        limits.max_entries,
    )?;
    if archive.len() > limits.max_entries {
        return Err(validation("restore archive contains too many entries"));
    }
    let mut names = HashSet::new();
    let mut manifest_bytes = None;
    let mut config_bytes = None;
    let mut total_uncompressed = 0_u64;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|e| validation(format!("read restore ZIP entry {index}: {e}")))?;
        let name = entry.name().to_string();
        validate_archive_name(&name)?;
        if !names.insert(name.clone()) {
            return Err(validation(format!("duplicate restore ZIP entry: {name}")));
        }
        if entry.is_dir() || entry.is_symlink() {
            return Err(validation(format!(
                "restore ZIP entry is not a regular file: {name}"
            )));
        }
        if entry.encrypted() {
            return Err(validation(format!(
                "encrypted restore ZIP entry is not supported: {name}"
            )));
        }
        if name != MANIFEST_NAME && name != CONFIG_NAME {
            return Err(validation(format!("unknown restore ZIP entry: {name}")));
        }
        let declared = entry.size();
        if declared > limits.max_entry_uncompressed_bytes {
            return Err(validation(format!(
                "restore ZIP entry exceeds the size limit: {name}"
            )));
        }
        total_uncompressed = total_uncompressed
            .checked_add(declared)
            .ok_or_else(|| validation("restore ZIP size arithmetic overflow"))?;
        if total_uncompressed > limits.max_total_uncompressed_bytes {
            return Err(validation("restore ZIP exceeds the total size limit"));
        }
        let data = read_entry_bounded(&mut entry, limits.max_entry_uncompressed_bytes)?;
        let actual =
            u64::try_from(data.len()).map_err(|_| validation("restore ZIP entry is too large"))?;
        if actual != declared {
            return Err(validation(format!(
                "restore ZIP entry size changed while reading: {name}"
            )));
        }
        match name.as_str() {
            MANIFEST_NAME => manifest_bytes = Some(data),
            CONFIG_NAME => config_bytes = Some(data),
            _ => unreachable!(),
        }
    }

    let manifest_bytes =
        manifest_bytes.ok_or_else(|| validation("restore ZIP lacks manifest.json"))?;
    let config_bytes = config_bytes.ok_or_else(|| validation("restore ZIP lacks config.json"))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| validation(format!("invalid restore manifest: {e}")))?;
    validate_manifest(&manifest, &config_bytes)?;
    let config: ConfigDocument = serde_json::from_slice(&config_bytes)
        .map_err(|e| validation(format!("invalid restore configuration: {e}")))?;
    validate_config_document(&config, authenticated)?;

    Ok(ArchivePayload {
        manifest,
        config,
        total_uncompressed_bytes: total_uncompressed,
    })
}

fn validate_central_directory<R: Read + Seek>(
    reader: &mut R,
    start: u64,
    max_entries: usize,
) -> AppResult<()> {
    reader
        .seek(SeekFrom::Start(start))
        .map_err(|e| validation(format!("seek restore ZIP central directory: {e}")))?;
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|e| validation(format!("read restore ZIP central directory: {e}")))?;
    let mut names = HashSet::new();
    let mut offset = 0_usize;
    let mut found_end = false;
    while offset + 4 <= bytes.len() {
        let signature = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        match signature {
            0x0201_4b50 => {
                if offset + 46 > bytes.len() {
                    return Err(validation("truncated restore ZIP central directory entry"));
                }
                let name_len = usize::from(u16::from_le_bytes(
                    bytes[offset + 28..offset + 30].try_into().unwrap(),
                ));
                let extra_len = usize::from(u16::from_le_bytes(
                    bytes[offset + 30..offset + 32].try_into().unwrap(),
                ));
                let comment_len = usize::from(u16::from_le_bytes(
                    bytes[offset + 32..offset + 34].try_into().unwrap(),
                ));
                let name_start = offset + 46;
                let end = name_start
                    .checked_add(name_len)
                    .and_then(|value| value.checked_add(extra_len))
                    .and_then(|value| value.checked_add(comment_len))
                    .ok_or_else(|| validation("restore ZIP central directory size overflow"))?;
                if end > bytes.len() {
                    return Err(validation("truncated restore ZIP central directory entry"));
                }
                let name = std::str::from_utf8(&bytes[name_start..name_start + name_len])
                    .map_err(|_| validation("restore ZIP entry name is not valid UTF-8"))?;
                validate_archive_name(name)?;
                if !names.insert(name.to_string()) {
                    return Err(validation(format!("duplicate restore ZIP entry: {name}")));
                }
                if names.len() > max_entries {
                    return Err(validation("restore archive contains too many entries"));
                }
                offset = end;
            }
            0x0605_4b50 | 0x0606_4b50 | 0x0706_4b50 => {
                found_end = true;
                break;
            }
            _ => return Err(validation("invalid restore ZIP central directory")),
        }
    }
    if !found_end {
        return Err(validation("restore ZIP lacks an end-of-directory record"));
    }
    Ok(())
}

fn validate_manifest(manifest: &Manifest, config_bytes: &[u8]) -> AppResult<()> {
    if manifest.archive_kind != ARCHIVE_KIND || manifest.schema_version != ARCHIVE_SCHEMA_VERSION {
        return Err(validation("unsupported restore archive schema"));
    }
    if manifest.entries.len() != 1 {
        return Err(validation(
            "restore manifest must contain exactly one payload entry",
        ));
    }
    let entry = &manifest.entries[0];
    if entry.path != CONFIG_NAME {
        return Err(validation("restore manifest names an unsupported payload"));
    }
    let size =
        u64::try_from(config_bytes.len()).map_err(|_| validation("configuration is too large"))?;
    if entry.size_bytes != size || entry.sha256 != sha256_hex(config_bytes) {
        return Err(validation(
            "restore manifest checksum or size does not match config.json",
        ));
    }
    Ok(())
}

fn validate_config_document(config: &ConfigDocument, authenticated: bool) -> AppResult<()> {
    if config.schema_version != ARCHIVE_SCHEMA_VERSION {
        return Err(validation("unsupported configuration schema"));
    }
    if config.contains_secrets && !authenticated {
        return Err(validation(
            "secret configuration requires an authenticated backup archive",
        ));
    }
    let mut schema = Connection::open_in_memory()
        .map_err(|e| internal(format!("open configuration schema database: {e}")))?;
    crate::store::migrate::apply(&mut schema, crate::store::migrate::CONTROL_MIGRATIONS)?;
    let mut seen_tables = HashSet::new();
    for table in &config.tables {
        if !CONFIG_TABLES.contains(&table.name.as_str()) {
            return Err(validation(format!(
                "configuration contains an unknown table: {}",
                table.name
            )));
        }
        if !seen_tables.insert(table.name.as_str()) {
            return Err(validation(format!(
                "configuration contains duplicate table: {}",
                table.name
            )));
        }
        let expected_columns = table_columns(&schema, &table.name)?;
        if table.columns != expected_columns {
            return Err(validation(format!(
                "configuration columns do not match table: {}",
                table.name
            )));
        }
        for row in &table.rows {
            if row.len() != table.columns.len() {
                return Err(validation(format!(
                    "configuration row width does not match table: {}",
                    table.name
                )));
            }
        }
        if table.name == "app_settings" {
            for row in &table.rows {
                let key = cell_text(row, 0, "app_settings.key")?;
                let allowed = key == "initialized"
                    || key == "timezone"
                    || NON_SECRET_APP_SETTING_KEYS.contains(&key)
                    || SECRET_APP_SETTING_KEYS.contains(&key);
                if !allowed {
                    return Err(validation(format!(
                        "configuration contains an unapproved app setting: {key}"
                    )));
                }
                if key == "notifications" && !config.contains_secrets {
                    validate_public_notification_setting(row)?;
                }
            }
        }
    }
    if seen_tables.len() != CONFIG_TABLES.len() {
        return Err(validation(
            "configuration does not contain every required table",
        ));
    }
    validate_source_boundaries(config)?;
    Ok(())
}

fn validate_source_boundaries(config: &ConfigDocument) -> AppResult<()> {
    let Some(sources) = config.tables.iter().find(|table| table.name == "sources") else {
        return Err(validation("configuration lacks sources table"));
    };
    for row in &sources.rows {
        let mount_key = cell_text(row, 2, "sources.mount_key")?;
        if mount_key.is_empty()
            || mount_key.len() > 64
            || !mount_key
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase())
            || !mount_key.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
            })
        {
            return Err(validation(
                "configuration contains an invalid source mount key",
            ));
        }
        let raw_root = cell_blob(row, 3, "sources.raw_relative_root")?;
        validate_relative_bytes(raw_root)?;
    }
    Ok(())
}

fn validate_config_mounts(
    document: &ConfigDocument,
    deployment: &DeploymentConfig,
) -> AppResult<()> {
    let sources = document
        .tables
        .iter()
        .find(|table| table.name == "sources")
        .ok_or_else(|| validation("configuration lacks sources table"))?;
    for row in &sources.rows {
        let mount_key = cell_text(row, 2, "sources.mount_key")?;
        if deployment.mount(mount_key).is_none() {
            return Err(AppError::new(
                ErrorCode::PathOutsideRoot,
                format!("configuration source mount is not approved: {mount_key}"),
            ));
        }
    }
    Ok(())
}

fn create_restored_database(
    source_file: File,
    mut staging: File,
    config: &ConfigDocument,
) -> AppResult<()> {
    let source = open_read_connection_from_file(source_file)?;
    let mut destination = Connection::open_in_memory()
        .map_err(|e| internal(format!("open restore staging database: {e}")))?;
    destination
        .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")
        .map_err(|e| internal(format!("configure restore staging database: {e}")))?;
    {
        let backup = rusqlite::backup::Backup::new(&source, &mut destination)
            .map_err(|e| internal(format!("snapshot control database: {e}")))?;
        backup
            .run_to_completion(128, Duration::from_millis(10), None)
            .map_err(|e| internal(format!("complete control database snapshot: {e}")))?;
    }
    apply_config(&mut destination, config)?;
    destination
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| internal(format!("checkpoint restored database: {e}")))?;
    let serialized = destination
        .serialize(rusqlite::DatabaseName::Main)
        .map_err(|e| internal(format!("serialize restored database: {e}")))?;
    staging
        .write_all(&serialized)
        .map_err(|e| internal(format!("write restored database: {e}")))?;
    staging
        .sync_all()
        .map_err(|e| internal(format!("sync restored database: {e}")))?;
    Ok(())
}

fn apply_config(conn: &mut Connection, config: &ConfigDocument) -> AppResult<()> {
    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("begin restore transaction: {e}")))?;
    apply_config_in_transaction(&tx, config)?;
    tx.commit()
        .map_err(|e| internal(format!("commit restore transaction: {e}")))?;
    Ok(())
}

fn apply_config_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    config: &ConfigDocument,
) -> AppResult<()> {
    for table_name in CONFIG_TABLES.iter().rev() {
        tx.execute(&format!("DELETE FROM {}", quote_identifier(table_name)), [])
            .map_err(|e| internal(format!("clear restore table {table_name}: {e}")))?;
    }
    for table in &config.tables {
        let columns = table
            .columns
            .iter()
            .map(|column| quote_identifier(column))
            .collect::<Vec<_>>()
            .join(", ");
        let placeholders = (1..=table.columns.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "INSERT INTO {} ({columns}) VALUES ({placeholders})",
            quote_identifier(&table.name)
        );
        for row in &table.rows {
            let values = row.iter().map(cell_to_sql).collect::<AppResult<Vec<_>>>()?;
            let refs = values.iter().map(|value| value as &dyn ToSql);
            tx.execute(&sql, params_from_iter(refs))
                .map_err(|e| internal(format!("restore table {}: {e}", table.name)))?;
        }
    }
    Ok(())
}

fn replace_control_database(
    root: &fssecure::SecureRoot,
    temp_rel: &OsStr,
    target: &Path,
) -> AppResult<()> {
    let target_name = target
        .file_name()
        .ok_or_else(|| validation("control database target has no file name"))?;
    let target_rel = target_name.to_os_string();
    match root.stat(&target_rel) {
        Ok(stat) if stat.kind != fssecure::EntryKind::RegularFile => Err(validation(
            "existing control database is not a regular file",
        )),
        Ok(_) => rustix::fs::renameat(root.root_fd(), temp_rel, root.root_fd(), &target_rel)
            .map_err(|e| internal(format!("atomically replace control database: {e}"))),
        Err(fssecure::FsSecureError::NotFound) => root
            .rename_noreplace(temp_rel, &target_rel)
            .map_err(|e| map_fs_error("publish restored control database", e)),
        Err(error) => Err(map_fs_error("inspect control database target", error)),
    }
}

fn write_archive(
    root: &fssecure::SecureRoot,
    temp_rel: &OsStr,
    output_rel: &OsStr,
    archive_bytes: &[u8],
) -> AppResult<()> {
    let opened = root
        .open_file(
            temp_rel,
            fssecure::OpenOptions {
                write: true,
                create: true,
                exclusive: true,
                truncate: true,
                noatime: false,
            },
        )
        .map_err(|e| map_fs_error("create backup staging file", e))?;
    let mut file = File::from(opened.fd);
    file.write_all(archive_bytes)
        .map_err(|e| internal(format!("write backup archive: {e}")))?;
    file.sync_all()
        .map_err(|e| internal(format!("sync backup archive: {e}")))?;
    root.rename_noreplace(temp_rel, output_rel)
        .map_err(|e| map_fs_error("publish backup archive", e))?;
    Ok(())
}

fn build_zip_archive(config_bytes: &[u8], manifest_bytes: &[u8]) -> AppResult<Vec<u8>> {
    let mut archive = Vec::new();
    let mut writer = ZipWriter::new(std::io::Cursor::new(&mut archive));
    let options = FileOptions::<()>::default().compression_method(CompressionMethod::Deflated);
    writer
        .start_file(CONFIG_NAME, options)
        .map_err(|e| internal(format!("start config archive entry: {e}")))?;
    writer
        .write_all(config_bytes)
        .map_err(|e| internal(format!("write config archive entry: {e}")))?;
    writer
        .start_file(MANIFEST_NAME, options)
        .map_err(|e| internal(format!("start manifest archive entry: {e}")))?;
    writer
        .write_all(manifest_bytes)
        .map_err(|e| internal(format!("write manifest archive entry: {e}")))?;
    writer
        .finish()
        .map_err(|e| internal(format!("finish backup archive: {e}")))?;
    Ok(archive)
}

fn encrypt_age(passphrase: &str, plaintext: &[u8]) -> AppResult<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(validation("secret backup passphrase must not be empty"));
    }
    let recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_owned()));
    age::encrypt(&recipient, plaintext)
        .map_err(|e| internal(format!("encrypt authenticated backup: {e}")))
}

fn decrypt_age(passphrase: &str, ciphertext: &[u8], max_plaintext: u64) -> AppResult<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(validation(
            "authenticated restore passphrase must not be empty",
        ));
    }
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_owned()));
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|_| validation("authenticated restore archive failed authentication"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| validation("authenticated restore archive failed authentication"))?;
    read_bounded(&mut reader, max_plaintext, "authenticated restore archive")
}

fn read_bounded<R: Read>(reader: &mut R, limit: u64, label: &str) -> AppResult<Vec<u8>> {
    let capacity = usize::try_from(limit.min(64 * 1024))
        .map_err(|_| validation(format!("{label} size limit is invalid")))?;
    let mut data = Vec::with_capacity(capacity);
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|e| validation(format!("read {label}: {e}")))?;
        if read == 0 {
            break;
        }
        let new_len = data
            .len()
            .checked_add(read)
            .ok_or_else(|| validation(format!("{label} size arithmetic overflow")))?;
        if u64::try_from(new_len).map_err(|_| validation(format!("{label} is too large")))? > limit
        {
            return Err(validation(format!("{label} exceeds the size limit")));
        }
        data.extend_from_slice(&buffer[..read]);
    }
    Ok(data)
}

fn table_columns(conn: &Connection, table_name: &str) -> AppResult<Vec<String>> {
    let sql = format!("PRAGMA table_info({})", quote_identifier(table_name));
    let mut statement = conn
        .prepare(&sql)
        .map_err(|e| internal(format!("inspect table {table_name}: {e}")))?;
    let mut rows = statement
        .query([])
        .map_err(|e| internal(format!("read table schema {table_name}: {e}")))?;
    let mut columns = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|e| internal(format!("iterate table schema {table_name}: {e}")))?
    {
        columns.push(
            row.get::<_, String>(1)
                .map_err(|e| internal(format!("read table column {table_name}: {e}")))?,
        );
    }
    if columns.is_empty() {
        return Err(validation(format!(
            "configuration table does not exist: {table_name}"
        )));
    }
    Ok(columns)
}

fn open_read_connection_from_file(file: File) -> AppResult<Connection> {
    let descriptor_path = PathBuf::from(format!("/dev/fd/{}", file.as_raw_fd()));
    let conn = Connection::open_with_flags(
        descriptor_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| internal(format!("open read-only control database: {e}")))?;
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(|e| internal(format!("configure read-only control database: {e}")))?;
    Ok(conn)
}

fn cell_from_sql(value: SqlValue) -> AppResult<Cell> {
    match value {
        SqlValue::Null => Ok(Cell::Null),
        SqlValue::Integer(value) => Ok(Cell::Integer(value)),
        SqlValue::Real(value) => Ok(Cell::Real(value)),
        SqlValue::Text(value) => Ok(Cell::Text(value)),
        SqlValue::Blob(value) => Ok(Cell::Blob(
            base64::engine::general_purpose::STANDARD.encode(value),
        )),
    }
}

fn cell_to_sql(cell: &Cell) -> AppResult<SqlValue> {
    match cell {
        Cell::Null => Ok(SqlValue::Null),
        Cell::Integer(value) => Ok(SqlValue::Integer(*value)),
        Cell::Real(value) if value.is_finite() => Ok(SqlValue::Real(*value)),
        Cell::Real(_) => Err(validation("configuration contains a non-finite real value")),
        Cell::Text(value) => Ok(SqlValue::Text(value.clone())),
        Cell::Blob(value) => base64::engine::general_purpose::STANDARD
            .decode(value)
            .map(SqlValue::Blob)
            .map_err(|e| validation(format!("configuration contains invalid blob data: {e}"))),
    }
}

fn cell_text<'a>(row: &'a [Cell], index: usize, field: &str) -> AppResult<&'a str> {
    match row.get(index) {
        Some(Cell::Text(value)) => Ok(value),
        _ => Err(validation(format!(
            "configuration field {field} is not text"
        ))),
    }
}

fn cell_blob<'a>(row: &'a [Cell], index: usize, field: &str) -> AppResult<&'a str> {
    match row.get(index) {
        Some(Cell::Blob(value)) => Ok(value),
        _ => Err(validation(format!(
            "configuration field {field} is not a blob"
        ))),
    }
}

fn sanitize_notification_setting(row: &mut [Cell]) -> AppResult<()> {
    let raw = cell_text(row, 1, "app_settings.value_json")?;
    let mut value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| validation(format!("通知设置不是有效 JSON: {e}")))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| validation("通知设置必须是 JSON 对象"))?;
    object.insert("username".to_string(), serde_json::Value::Null);
    object.insert("password".to_string(), serde_json::Value::Null);
    row[1] = Cell::Text(
        serde_json::to_string(&value).map_err(|e| internal(format!("序列化通知设置失败: {e}")))?,
    );
    Ok(())
}

fn validate_public_notification_setting(row: &[Cell]) -> AppResult<()> {
    let raw = cell_text(row, 1, "app_settings.value_json")?;
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| validation(format!("通知设置不是有效 JSON: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| validation("通知设置必须是 JSON 对象"))?;
    for key in ["username", "password"] {
        if object.get(key).is_some_and(|value| !value.is_null()) {
            return Err(validation(format!("未认证配置不能包含通知设置字段: {key}")));
        }
    }
    Ok(())
}

fn validate_relative_bytes(encoded: &str) -> AppResult<()> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| validation(format!("invalid relative path bytes: {e}")))?;
    if bytes.starts_with(b"/") || bytes.contains(&0) {
        return Err(validation(
            "source relative path is absolute or contains NUL",
        ));
    }
    for component in bytes.split(|byte| *byte == b'/') {
        if component == b".." {
            return Err(validation("source relative path contains path traversal"));
        }
    }
    Ok(())
}

fn validate_archive_name(name: &str) -> AppResult<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.contains(&0)
        || bytes.starts_with(b"/")
        || bytes.starts_with(b"\\")
        || (bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic())
        || name.contains('\\')
        || name
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(validation(format!(
            "unsafe restore ZIP entry path: {name:?}"
        )));
    }
    Ok(())
}

fn read_entry_bounded<R: Read>(reader: &mut R, limit: u64) -> AppResult<Vec<u8>> {
    read_bounded(reader, limit, "restore ZIP entry")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_false(value: &bool) -> bool {
    !value
}

fn open_data_root(data_dir: &Path) -> AppResult<fssecure::SecureRoot> {
    if !data_dir.is_absolute() {
        return Err(validation("data directory must be absolute"));
    }
    fssecure::SecureRoot::open(data_dir.as_os_str())
        .map_err(|e| map_fs_error("open data directory", e))
}

fn relative_path(data_dir: &Path, path: &Path, label: &str) -> AppResult<PathBuf> {
    if !path.is_absolute() {
        return Err(validation(format!("{label} must be absolute")));
    }
    let relative = path.strip_prefix(data_dir).map_err(|_| {
        AppError::new(
            ErrorCode::PathOutsideRoot,
            format!("{label} is outside data directory"),
        )
    })?;
    if relative.as_os_str().is_empty() {
        return Err(validation(format!(
            "{label} must name a file beneath data directory"
        )));
    }
    for component in relative.components() {
        if matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        ) {
            return Err(AppError::new(
                ErrorCode::PathOutsideRoot,
                format!("{label} escapes data directory"),
            ));
        }
    }
    Ok(relative.to_path_buf())
}

fn temporary_sibling(path: &Path, kind: &str) -> AppResult<OsString> {
    let file_name = path
        .file_name()
        .ok_or_else(|| validation("path has no file name"))?
        .to_string_lossy();
    let temp_name = format!(".{file_name}.{kind}-{}", Uuid::new_v4().simple());
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    Ok(parent.join(temp_name).into_os_string())
}

fn remove_temp_file(root: &fssecure::SecureRoot, path: &OsStr) -> AppResult<()> {
    match root.stat(path) {
        Ok(stat) if stat.kind == fssecure::EntryKind::RegularFile => root
            .unlink_file(path)
            .map_err(|e| map_fs_error("remove staging file", e)),
        Ok(_) => Err(validation("staging path is not a regular file")),
        Err(fssecure::FsSecureError::NotFound) => Ok(()),
        Err(error) => Err(map_fs_error("inspect staging file", error)),
    }
}

fn remove_file_if_regular(root: &fssecure::SecureRoot, path: &OsStr) -> AppResult<()> {
    match root.stat(path) {
        Ok(stat) if stat.kind == fssecure::EntryKind::RegularFile => root
            .unlink_file(path)
            .map_err(|e| map_fs_error("remove invalid backup archive", e)),
        Ok(_) => Err(validation(
            "invalid backup archive output is not a regular file",
        )),
        Err(fssecure::FsSecureError::NotFound) => Ok(()),
        Err(error) => Err(map_fs_error("inspect invalid backup archive", error)),
    }
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn validation(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, message)
}

fn internal(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, message)
}

fn map_fs_error(operation: &str, error: fssecure::FsSecureError) -> AppError {
    let code = match error {
        fssecure::FsSecureError::PathOutsideRoot => ErrorCode::PathOutsideRoot,
        fssecure::FsSecureError::MissingCapability => ErrorCode::UnsupportedCapability,
        fssecure::FsSecureError::AlreadyExists => ErrorCode::Conflict,
        fssecure::FsSecureError::NotFound => ErrorCode::NotFound,
        fssecure::FsSecureError::PermissionDenied => ErrorCode::Forbidden,
        _ => ErrorCode::Internal,
    };
    AppError::new(code, format!("{operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::config::{
        ApprovedMount, ResourceConfig, SamplingConfig, SecurityConfig, ServerConfig, StorageConfig,
    };

    fn make_archive(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = FileOptions::<()>::default().compression_method(CompressionMethod::Deflated);
        for (name, bytes) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }

    fn make_duplicate_archive(path: &Path, entries: &[(&str, &[u8])]) {
        let mut bytes = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let name_bytes = name.as_bytes();
            let offset = bytes.len() as u32;
            let crc = crc32(data);
            bytes.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
            bytes.extend_from_slice(&20_u16.to_le_bytes());
            bytes.extend_from_slice(&0_u16.to_le_bytes());
            bytes.extend_from_slice(&0_u16.to_le_bytes());
            bytes.extend_from_slice(&0_u16.to_le_bytes());
            bytes.extend_from_slice(&0_u16.to_le_bytes());
            bytes.extend_from_slice(&crc.to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0_u16.to_le_bytes());
            bytes.extend_from_slice(name_bytes);
            bytes.extend_from_slice(data);

            central.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
            central.extend_from_slice(&20_u16.to_le_bytes());
            central.extend_from_slice(&20_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u16.to_le_bytes());
            central.extend_from_slice(&0_u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name_bytes);
        }
        let central_offset = bytes.len() as u32;
        bytes.extend_from_slice(&central);
        bytes.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(central.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&central_offset.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        std::fs::write(path, bytes).unwrap();
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffff_u32;
        for byte in data {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn manifest_for(config: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&Manifest {
            archive_kind: ARCHIVE_KIND.to_string(),
            schema_version: ARCHIVE_SCHEMA_VERSION,
            created_at: "2026-09-10T00:00:00Z".to_string(),
            entries: vec![ManifestEntry {
                path: CONFIG_NAME.to_string(),
                size_bytes: config.len() as u64,
                sha256: sha256_hex(config),
            }],
        })
        .unwrap()
    }

    fn valid_config() -> Vec<u8> {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::store::migrate::apply(&mut conn, crate::store::migrate::CONTROL_MIGRATIONS).unwrap();
        serde_json::to_vec(&export_config(&conn, false).unwrap()).unwrap()
    }

    #[cfg(target_os = "linux")]
    fn test_deployment(data_dir: &Path) -> DeploymentConfig {
        DeploymentConfig {
            server: ServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                default_timezone: jiff::tz::TimeZone::UTC,
                default_timezone_name: "UTC".to_string(),
                trusted_proxy_cidrs: vec![],
                allow_insecure_lan_http: true,
            },
            storage: StorageConfig {
                data_dir: data_dir.to_path_buf(),
                approved_output_roots: vec![data_dir.join("exports")],
                data_budget_bytes: 1024,
                hash_cache_budget_bytes: 1024,
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

    #[cfg(target_os = "linux")]
    fn control_database(data_dir: &Path, timezone: &str) -> Connection {
        std::fs::create_dir_all(data_dir.join(CONFIG_BACKUP_DIR)).unwrap();
        let database = data_dir.join(CONTROL_DB_NAME);
        let mut conn = Connection::open(database).unwrap();
        crate::store::migrate::apply(&mut conn, crate::store::migrate::CONTROL_MIGRATIONS).unwrap();
        conn.execute(
            "INSERT INTO app_settings(key, value_json, version, updated_at)
             VALUES ('timezone', ?1, 1, '2026-01-01T00:00:00.000Z')",
            [timezone],
        )
        .unwrap();
        conn
    }

    #[cfg(target_os = "linux")]
    fn incoming_archive(target: &Path, timezone: &str) -> PathBuf {
        let incoming = tempfile::tempdir().unwrap();
        let incoming_path = incoming.path().to_path_buf();
        let _incoming_conn = control_database(&incoming_path, timezone);
        let archive = incoming_path.join(CONFIG_BACKUP_DIR).join("incoming.zip");
        create_backup(&incoming_path, &archive).unwrap();
        let target_input = target.join("incoming.zip");
        std::fs::copy(archive, &target_input).unwrap();
        target_input
    }

    #[test]
    fn preflight_rejects_zip_slip_before_any_write() {
        let data = tempfile::tempdir().unwrap();
        let input = data.path().join("input.zip");
        make_archive(&input, &[("../outside", b"x")]);
        let error = preflight_restore(data.path(), &input).unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn preflight_rejects_duplicate_and_unknown_entries() {
        let data = tempfile::tempdir().unwrap();
        let input = data.path().join("input.zip");
        let config = valid_config();
        let manifest = manifest_for(&config);
        make_duplicate_archive(
            &input,
            &[
                (CONFIG_NAME, &config),
                (CONFIG_NAME, &config),
                (MANIFEST_NAME, &manifest),
            ],
        );
        let error = preflight_restore(data.path(), &input).unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);

        let unknown = data.path().join("unknown.zip");
        make_archive(
            &unknown,
            &[
                (CONFIG_NAME, &config),
                (MANIFEST_NAME, &manifest),
                ("extra", b"x"),
            ],
        );
        let error = preflight_restore(data.path(), &unknown).unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn preflight_rejects_manifest_mismatch_and_absolute_input() {
        let data = tempfile::tempdir().unwrap();
        let input = data.path().join("input.zip");
        let config = valid_config();
        let mut manifest = manifest_for(&config);
        manifest.extend_from_slice(b"broken");
        make_archive(
            &input,
            &[(CONFIG_NAME, &config), (MANIFEST_NAME, &manifest)],
        );
        let error = preflight_restore(data.path(), &input).unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);

        let outside = tempfile::NamedTempFile::new().unwrap();
        let error = preflight_restore(data.path(), outside.path()).unwrap_err();
        assert_eq!(error.code, ErrorCode::PathOutsideRoot);
    }

    #[test]
    fn preflight_enforces_entry_and_archive_limits() {
        let data = tempfile::tempdir().unwrap();
        let input = data.path().join("input.zip");
        let config = valid_config();
        let manifest = manifest_for(&config);
        make_archive(
            &input,
            &[(CONFIG_NAME, &config), (MANIFEST_NAME, &manifest)],
        );

        let limits = BackupLimits {
            max_entries: 1,
            ..BackupLimits::default()
        };
        let error = preflight_restore_with_limits(data.path(), &input, limits).unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);

        let limits = BackupLimits {
            max_entry_uncompressed_bytes: 1,
            ..BackupLimits::default()
        };
        let error = preflight_restore_with_limits(data.path(), &input, limits).unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn dry_run_performs_preflight_without_creating_restore_backup() {
        let data = tempfile::tempdir().unwrap();
        let input = data.path().join("input.zip");
        let config = valid_config();
        let manifest = manifest_for(&config);
        make_archive(
            &input,
            &[(CONFIG_NAME, &config), (MANIFEST_NAME, &manifest)],
        );

        let result = restore_backup(data.path(), &input, true).unwrap();
        assert!(result.dry_run);
        assert!(result.pre_restore_backup.is_none());
        assert!(!data.path().join(CONFIG_BACKUP_DIR).exists());
    }

    #[test]
    fn restore_preview_reports_changed_configuration_tables() {
        let data = tempfile::tempdir().unwrap();
        let root = super::open_data_root(data.path()).unwrap();
        if !root.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; restore preview test skipped");
            return;
        }
        let db = data.path().join(CONTROL_DB_NAME);
        let mut conn = Connection::open(&db).unwrap();
        crate::store::migrate::apply(&mut conn, crate::store::migrate::CONTROL_MIGRATIONS).unwrap();
        conn.execute(
            "INSERT INTO app_settings(key, value_json, version, updated_at) VALUES ('timezone', 'UTC', 1, 'now')",
            [],
        )
        .unwrap();
        let backup_path = data.path().join(CONFIG_BACKUP_DIR).join("backup.zip");
        create_backup(data.path(), &backup_path).unwrap();
        let input = data.path().join("input.zip");
        std::fs::copy(&backup_path, &input).unwrap();
        conn.execute(
            "UPDATE app_settings SET value_json = 'Asia/Shanghai' WHERE key = 'timezone'",
            [],
        )
        .unwrap();

        let (_, differences) = restore_differences(data.path(), &input, &conn).unwrap();
        assert_eq!(
            differences,
            vec![RestoreDifference {
                key: "app_settings".to_string(),
                change: "modified".to_string(),
            }]
        );
    }

    #[test]
    fn source_paths_are_relative_and_secret_tables_are_not_exported() {
        let data = tempfile::tempdir().unwrap();
        let db = data.path().join(CONTROL_DB_NAME);
        let mut conn = Connection::open(&db).unwrap();
        crate::store::migrate::apply(&mut conn, crate::store::migrate::CONTROL_MIGRATIONS).unwrap();
        conn.execute(
            "INSERT INTO app_settings(key, value_json, version, updated_at) VALUES ('password', 'secret', 1, 'now')",
            [],
        )
        .unwrap();
        let config = read_config_document(&db, false).unwrap();
        assert!(!config.tables.iter().any(|table| table.name == "sessions"));
        let settings = config
            .tables
            .iter()
            .find(|table| table.name == "app_settings")
            .unwrap();
        assert!(settings.rows.is_empty());
        assert!(validate_config_document(&config, false).is_ok());
    }

    #[test]
    fn secret_options_require_a_non_empty_passphrase() {
        let error = match BackupOptions::with_secrets("") {
            Ok(_) => panic!("empty secret passphrase must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::ValidationFailed);

        let options = BackupOptions::with_secrets("backup passphrase").unwrap();
        assert!(options.include_secrets);
        assert_eq!(
            options.secrets_passphrase.as_ref().unwrap().expose_secret(),
            "backup passphrase"
        );
    }

    #[test]
    fn secret_export_includes_only_the_explicitly_eligible_setting() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::store::migrate::apply(&mut conn, crate::store::migrate::CONTROL_MIGRATIONS).unwrap();
        conn.execute(
            "INSERT INTO app_settings(key, value_json, version, updated_at)
             VALUES ('notifications', '{\"password\":\"smtp-secret\"}', 1, 'now')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_settings(key, value_json, version, updated_at)
             VALUES ('unapproved-secret', 'must-not-export', 1, 'now')",
            [],
        )
        .unwrap();

        let ordinary = export_config(&conn, false).unwrap();
        assert!(!ordinary.contains_secrets);
        let ordinary_bytes = serde_json::to_vec(&ordinary).unwrap();
        assert!(
            !String::from_utf8(ordinary_bytes)
                .unwrap()
                .contains("contains_secrets")
        );
        let ordinary_settings = ordinary
            .tables
            .iter()
            .find(|table| table.name == "app_settings")
            .unwrap();
        let ordinary_notifications = ordinary_settings
            .rows
            .iter()
            .find(|row| matches!(row.first(), Some(Cell::Text(key)) if key == "notifications"))
            .unwrap();
        assert!(matches!(
            ordinary_notifications.get(1),
            Some(Cell::Text(value)) if !value.contains("smtp-secret")
        ));
        let public_notification: serde_json::Value = match ordinary_notifications.get(1) {
            Some(Cell::Text(value)) => serde_json::from_str(value).unwrap(),
            _ => panic!("sanitized notifications setting must be text"),
        };
        assert!(public_notification["username"].is_null());
        assert!(public_notification["password"].is_null());

        let secret = export_config(&conn, true).unwrap();
        assert!(secret.contains_secrets);
        let settings = secret
            .tables
            .iter()
            .find(|table| table.name == "app_settings")
            .unwrap();
        assert!(
            settings.rows.iter().any(|row| {
                matches!(row.first(), Some(Cell::Text(key)) if key == "notifications")
            })
        );
        assert!(!settings.rows.iter().any(|row| {
            matches!(row.first(), Some(Cell::Text(key)) if key == "unapproved-secret")
        }));
        assert!(validate_config_document(&secret, true).is_ok());

        let config_bytes = serde_json::to_vec(&secret).unwrap();
        let manifest = manifest_for(&config_bytes);
        let zip = build_zip_archive(&config_bytes, &manifest).unwrap();
        let encrypted = encrypt_age("backup passphrase", &zip).unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains("smtp-secret"));
        let decrypted = decrypt_age("backup passphrase", &encrypted, 64 * 1024).unwrap();
        let payload = read_zip_payload_bytes(
            &decrypted,
            Path::new("/data/config-backups/backup.age"),
            BackupLimits::default(),
            true,
        )
        .unwrap();
        assert!(payload.config.contains_secrets);
    }

    #[test]
    fn authenticated_archive_round_trip_checks_tag_and_size_limit() {
        let config = valid_config();
        let manifest = manifest_for(&config);
        let plaintext = build_zip_archive(&config, &manifest).unwrap();
        let ciphertext = encrypt_age("correct horse battery staple", &plaintext).unwrap();
        assert!(ciphertext.starts_with(AGE_HEADER));

        let decrypted = decrypt_age(
            "correct horse battery staple",
            &ciphertext,
            plaintext.len() as u64,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);

        let mut tampered = ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let error = decrypt_age(
            "correct horse battery staple",
            &tampered,
            plaintext.len() as u64,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);
        assert!(!error.message.contains("correct horse battery staple"));

        let error = decrypt_age(
            "correct horse battery staple",
            &ciphertext,
            (plaintext.len() - 1) as u64,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn unauthenticated_archive_cannot_carry_secret_configuration() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::store::migrate::apply(&mut conn, crate::store::migrate::CONTROL_MIGRATIONS).unwrap();
        conn.execute(
            "INSERT INTO app_settings(key, value_json, version, updated_at)
             VALUES ('notifications', '{\"password\":\"smtp-secret\"}', 1, 'now')",
            [],
        )
        .unwrap();
        let config = export_config(&conn, true).unwrap();
        let error = validate_config_document(&config, false).unwrap_err();
        assert_eq!(error.code, ErrorCode::ValidationFailed);
        assert!(!error.message.contains("smtp-secret"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn restore_materialization_uses_open_staging_descriptor_after_path_replacement() {
        let data = tempfile::tempdir().unwrap();
        let db = data.path().join(CONTROL_DB_NAME);
        let mut conn = Connection::open(&db).unwrap();
        crate::store::migrate::apply(&mut conn, crate::store::migrate::CONTROL_MIGRATIONS).unwrap();
        conn.execute(
            "INSERT INTO app_settings(key, value_json, version, updated_at) VALUES ('timezone', 'UTC', 1, 'now')",
            [],
        )
        .unwrap();
        drop(conn);

        let config = read_config_document(&db, false).unwrap();
        let root = open_data_root(data.path()).unwrap();
        if !root.caps().supports_safe_writes() {
            eprintln!("note: safe write capability unavailable; staging FD test skipped");
            return;
        }
        let temp_rel = temporary_sibling(Path::new(CONTROL_DB_NAME), "restore-fd-test").unwrap();
        let temp_path = data.path().join(&temp_rel);
        let staging = root
            .open_file(
                &temp_rel,
                fssecure::OpenOptions {
                    write: true,
                    create: true,
                    exclusive: true,
                    truncate: true,
                    noatime: false,
                },
            )
            .unwrap();
        let observed_path = data.path().join("staging-inode.sqlite");
        std::fs::hard_link(&temp_path, &observed_path).unwrap();
        std::fs::remove_file(&temp_path).unwrap();
        std::fs::write(&temp_path, b"path replacement").unwrap();

        let source = root
            .open_file(
                OsStr::new(CONTROL_DB_NAME),
                fssecure::OpenOptions::default(),
            )
            .unwrap();
        create_restored_database(File::from(source.fd), File::from(staging.fd), &config).unwrap();

        let restored = Connection::open(&observed_path).unwrap();
        let timezone: String = restored
            .query_row(
                "SELECT value_json FROM app_settings WHERE key='timezone'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(timezone, "UTC");
        assert_eq!(std::fs::read(&temp_path).unwrap(), b"path replacement");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn backup_and_restore_publish_atomically_on_linux() {
        let data = tempfile::tempdir().unwrap();
        let db = data.path().join(CONTROL_DB_NAME);
        let mut conn = Connection::open(&db).unwrap();
        crate::store::migrate::apply(&mut conn, crate::store::migrate::CONTROL_MIGRATIONS).unwrap();
        conn.execute(
            "INSERT INTO app_settings(key, value_json, version, updated_at) VALUES ('timezone', 'UTC', 1, 'now')",
            [],
        )
        .unwrap();
        drop(conn);
        let output = data.path().join(CONFIG_BACKUP_DIR).join("backup.zip");
        let summary = create_backup(data.path(), &output).unwrap();
        assert_eq!(summary.entries, 2);
        let plan = preflight_restore(data.path(), &output).unwrap();
        assert_eq!(plan.table_count, CONFIG_TABLES.len());
        let result = restore_backup(data.path(), &output, false).unwrap();
        assert!(!result.dry_run);
        assert!(result.pre_restore_backup.unwrap().is_file());
        let restored = Connection::open(&db).unwrap();
        let timezone: String = restored
            .query_row(
                "SELECT value_json FROM app_settings WHERE key='timezone'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(timezone, "UTC");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn restore_in_connection_commits_for_existing_writer_and_new_readers() {
        let target = tempfile::tempdir().unwrap();
        let target_path = target.path().to_path_buf();
        let mut writer = control_database(&target_path, "Asia/Shanghai");
        let input = incoming_archive(&target_path, "UTC");
        let deployment = test_deployment(&target_path);

        let response = restore_backup_in_connection(
            &mut writer,
            &target_path,
            &input,
            None,
            &deployment,
            |_, restore| {
                assert!(
                    restore
                        .pre_restore_backup
                        .as_ref()
                        .is_some_and(|path| path.is_file())
                );
                Ok(serde_json::json!({"applied": true}))
            },
        )
        .unwrap();
        assert_eq!(response, serde_json::json!({"applied": true}));

        let writer_timezone: String = writer
            .query_row(
                "SELECT value_json FROM app_settings WHERE key = 'timezone'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(writer_timezone, "UTC");

        let reader = Connection::open(target_path.join(CONTROL_DB_NAME)).unwrap();
        let reader_timezone: String = reader
            .query_row(
                "SELECT value_json FROM app_settings WHERE key = 'timezone'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reader_timezone, "UTC");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn restore_in_connection_rolls_back_when_audit_write_fails() {
        let target = tempfile::tempdir().unwrap();
        let target_path = target.path().to_path_buf();
        let mut writer = control_database(&target_path, "Asia/Shanghai");
        let input = incoming_archive(&target_path, "UTC");
        let deployment = test_deployment(&target_path);

        let error = restore_backup_in_connection(
            &mut writer,
            &target_path,
            &input,
            None,
            &deployment,
            |tx, _| {
                tx.execute("DROP TABLE audit_events", [])
                    .map_err(|error| internal(format!("drop audit table: {error}")))?;
                crate::audit::record(tx, "admin-1", "backup.restore", None, "success", None, None)?;
                Ok(serde_json::json!({"applied": true}))
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Internal);

        let timezone: String = writer
            .query_row(
                "SELECT value_json FROM app_settings WHERE key = 'timezone'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(timezone, "Asia/Shanghai");
        let audit_events: i64 = writer
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(audit_events, 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn symlinked_input_is_rejected_by_secure_root() {
        let data = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), data.path().join("input.zip")).unwrap();
        let error = preflight_restore(data.path(), data.path().join("input.zip")).unwrap_err();
        assert!(matches!(
            error.code,
            ErrorCode::Internal | ErrorCode::ValidationFailed
        ));
    }
}
