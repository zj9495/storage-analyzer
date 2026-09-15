//! Health, runtime capability and redacted diagnostic information.
//!
//! Diagnostics are observational: they never probe source directories by
//! writing files, never return approved paths, and never include credentials
//! or process environment contents.

use rusqlite::Connection;
use serde::Serialize;

use crate::config::DeploymentConfig;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::runtime::MemoryBudgetController;

fn internal(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, message)
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LiveStatus {
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadyChecks {
    pub database: &'static str,
    pub config: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadyStatus {
    pub status: &'static str,
    pub initialized: bool,
    pub checks: ReadyChecks,
}

/// Process liveness does not touch SQLite, the filesystem or source state.
pub fn health_live() -> LiveStatus {
    LiveStatus { status: "ok" }
}

/// Check readiness using the same split as the HTTP contract: an
/// uninitialized but usable process is `initializing`, while a database or
/// configuration failure is `not_ready`.
pub fn health_ready(conn: &Connection, initialized: bool, config_valid: bool) -> ReadyStatus {
    let database = match conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0)) {
        Ok(1) => "ok",
        Ok(_) | Err(_) => "failed",
    };
    let config = if config_valid { "ok" } else { "failed" };
    let status = if database != "ok" || config != "ok" {
        "not_ready"
    } else if initialized {
        "ready"
    } else {
        "initializing"
    };
    ReadyStatus {
        status,
        initialized,
        checks: ReadyChecks { database, config },
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CapabilityCheck {
    pub name: &'static str,
    pub available: bool,
    pub reason: &'static str,
}

/// Capability checks are explicit and fail closed.  A missing safe-write
/// primitive is reported as unavailable; it is never replaced with a weaker
/// write implementation.
pub fn check_capabilities(
    config: &DeploymentConfig,
    kernel_safe_writes: bool,
) -> Vec<CapabilityCheck> {
    let write_enabled = config.security.allow_write_operations;
    vec![
        CapabilityCheck {
            name: "read_only_analysis",
            available: true,
            reason: "metadata and content analysis do not require source writes",
        },
        CapabilityCheck {
            name: "safe_write_resolution",
            available: kernel_safe_writes,
            reason: if kernel_safe_writes {
                "kernel provides the required directory-relative no-follow write primitive"
            } else {
                "kernel does not provide the required safe write primitive"
            },
        },
        CapabilityCheck {
            name: "write_operations",
            available: write_enabled,
            reason: if write_enabled {
                "deployment write switch is enabled"
            } else {
                "deployment write switch is disabled"
            },
        },
        CapabilityCheck {
            name: "cleanup",
            available: write_enabled && kernel_safe_writes,
            reason: if write_enabled && kernel_safe_writes {
                "deployment switch and kernel safe-write capability are present; source gates remain required"
            } else {
                "cleanup requires both the deployment switch and the kernel safe-write capability"
            },
        },
    ]
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    pub profile: &'static str,
    pub target: String,
    pub commit: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeInfo {
    pub arch: &'static str,
    pub os: &'static str,
    pub uid: u32,
    pub gid: u32,
    pub read_only_boundary: bool,
    pub capabilities: Vec<String>,
    pub memory_rss_bytes: Option<String>,
    pub uptime_sec: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SchemaMigrations {
    pub control: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataDirInfo {
    pub free_bytes: String,
    pub used_bytes: String,
    pub budget_bytes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanQueueInfo {
    pub running: u32,
    pub queued: u32,
    pub max_queue: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryBudgetInfo {
    pub api_budget_mib: u32,
    pub worker_budget_mib: u32,
    pub api_rss_bytes: Option<String>,
    pub worker_rss_bytes: Option<String>,
    pub container_memory_current_bytes: Option<String>,
    pub api_status: &'static str,
    pub worker_status: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceStatus {
    pub source_id: String,
    pub name: String,
    pub availability: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticInfo {
    pub app_version: &'static str,
    pub sqlite_version: String,
    pub schema_migrations: SchemaMigrations,
    pub build: BuildInfo,
    pub runtime: RuntimeInfo,
    pub data_dir: DataDirInfo,
    pub scan_queue: ScanQueueInfo,
    pub memory_budget: MemoryBudgetInfo,
    pub sources: Vec<SourceStatus>,
    pub note: &'static str,
}

fn data_dir_info(config: &DeploymentConfig) -> AppResult<DataDirInfo> {
    let stat = rustix::fs::statvfs(&config.storage.data_dir)
        .map_err(|e| internal(format!("读取数据目录容量失败: {e}")))?;
    let total = stat
        .f_blocks
        .checked_mul(stat.f_frsize)
        .ok_or_else(|| internal("数据目录容量计算溢出"))?;
    let free = stat
        .f_bfree
        .checked_mul(stat.f_frsize)
        .ok_or_else(|| internal("数据目录空闲容量计算溢出"))?;
    let used = total
        .checked_sub(free)
        .ok_or_else(|| internal("数据目录报告空闲容量大于总容量"))?;
    Ok(DataDirInfo {
        free_bytes: free.to_string(),
        used_bytes: used.to_string(),
        budget_bytes: config.storage.data_budget_bytes.to_string(),
    })
}

#[cfg(target_os = "linux")]
fn linux_memory_rss_bytes() -> AppResult<Option<String>> {
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
    Ok(Some(bytes.to_string()))
}

#[cfg(not(target_os = "linux"))]
fn linux_memory_rss_bytes() -> AppResult<Option<String>> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn linux_uptime_sec() -> AppResult<Option<u64>> {
    let text = match std::fs::read_to_string("/proc/uptime") {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(internal(format!("读取系统运行时间失败: {error}"))),
    };
    let first = text
        .split_whitespace()
        .next()
        .ok_or_else(|| internal("系统运行时间格式损坏"))?;
    let seconds = first
        .parse::<f64>()
        .map_err(|_| internal("系统运行时间数值损坏"))?;
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(internal("系统运行时间超出有效范围"));
    }
    Ok(Some(seconds.floor() as u64))
}

#[cfg(not(target_os = "linux"))]
fn linux_uptime_sec() -> AppResult<Option<u64>> {
    Ok(None)
}

fn capability_names(checks: &[CapabilityCheck]) -> Vec<String> {
    checks
        .iter()
        .map(|check| {
            if check.available {
                check.name.to_string()
            } else {
                format!("{}:unavailable", check.name)
            }
        })
        .collect()
}

/// Collect the complete redacted diagnostic snapshot from the control DB.
/// Source paths, usernames, environment variables, secrets and message
/// bodies are intentionally absent from the return type.
pub fn collect(
    conn: &Connection,
    config: &DeploymentConfig,
    kernel_safe_writes: bool,
    memory_budget: &MemoryBudgetController,
) -> AppResult<DiagnosticInfo> {
    memory_budget.sample_now()?;
    let memory = memory_budget.snapshot();
    let sqlite_version = conn
        .query_row("SELECT sqlite_version()", [], |row| row.get::<_, String>(0))
        .map_err(|e| internal(format!("读取 SQLite 版本失败: {e}")))?;
    let migration_version = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|e| internal(format!("读取 schema migration 版本失败: {e}")))?;
    let migration_version =
        u32::try_from(migration_version).map_err(|_| internal("schema migration 版本超出范围"))?;

    let running = conn
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE type = 'scan' AND state IN
             ('RUNNING','PAUSING','PAUSED','CANCELLING')",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|e| internal(format!("读取运行中扫描数失败: {e}")))?;
    let queued = conn
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE type = 'scan' AND state = 'QUEUED'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|e| internal(format!("读取排队扫描数失败: {e}")))?;
    let running = u32::try_from(running).map_err(|_| internal("运行中扫描数超出范围"))?;
    let queued = u32::try_from(queued).map_err(|_| internal("排队扫描数超出范围"))?;

    let mut source_stmt = conn
        .prepare("SELECT id, name, availability FROM sources ORDER BY created_at, id")
        .map_err(|e| internal(format!("准备数据源诊断查询失败: {e}")))?;
    let rows = source_stmt
        .query_map([], |row| {
            Ok(SourceStatus {
                source_id: row.get(0)?,
                name: row.get(1)?,
                availability: row.get(2)?,
            })
        })
        .map_err(|e| internal(format!("读取数据源诊断失败: {e}")))?;
    let sources = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal(format!("读取数据源诊断行失败: {e}")))?;

    let checks = check_capabilities(config, kernel_safe_writes);
    Ok(DiagnosticInfo {
        app_version: env!("CARGO_PKG_VERSION"),
        sqlite_version,
        schema_migrations: SchemaMigrations {
            control: migration_version,
        },
        build: BuildInfo {
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            commit: option_env!("GIT_COMMIT").map(str::to_owned),
        },
        runtime: RuntimeInfo {
            arch: std::env::consts::ARCH,
            os: std::env::consts::OS,
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            read_only_boundary: !config.security.allow_write_operations,
            capabilities: capability_names(&checks),
            memory_rss_bytes: linux_memory_rss_bytes()?,
            uptime_sec: linux_uptime_sec()?,
        },
        data_dir: data_dir_info(config)?,
        scan_queue: ScanQueueInfo {
            running,
            queued,
            max_queue: config.resources.max_queued_scans,
        },
        memory_budget: MemoryBudgetInfo {
            api_budget_mib: memory_budget.api_memory_budget_mib(),
            worker_budget_mib: memory_budget.worker_memory_budget_mib(),
            api_rss_bytes: memory.process_rss_bytes.map(|value| value.to_string()),
            worker_rss_bytes: memory.process_rss_bytes.map(|value| value.to_string()),
            container_memory_current_bytes: memory
                .cgroup_memory_current_bytes
                .map(|value| value.to_string()),
            api_status: memory.api_pressure.as_str(),
            worker_status: memory.worker_pressure.as_str(),
        },
        sources,
        note: "诊断信息仅包含脱敏运行元数据；不会输出凭据、token、邮件内容或宿主路径。",
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::store::migrate;
    use tempfile::tempdir;

    fn config(data: &Path, source: &Path, output: &Path) -> DeploymentConfig {
        let yaml = format!(
            r#"config_version: 2
server:
  listen: "127.0.0.1:8080"
  default_timezone: UTC
  trusted_proxy_cidrs: []
  allow_insecure_lan_http: true
storage:
  data_dir: "{}"
  approved_output_roots: ["{}"]
  data_budget_bytes: "1000000"
  hash_cache_budget_bytes: "100000"
approved_mounts:
  - key: main
    container_path: "{}"
    writable: false
    allow_submounts: false
security:
  allow_write_operations: false
  setup_token_minutes: 30
  session_idle_minutes: 30
  session_absolute_hours: 24
  reauth_minutes: 5
resources:
  max_running_scans: 1
  max_queued_scans: 20
  metadata_workers: 1
  hash_workers: 1
  hash_read_limit_mib_s: 0
  max_open_files: 16
  api_memory_budget_mib: 64
  worker_memory_budget_mib: 128
  max_parallel_exports: 1
sampling:
  interval_minutes: 15
  raw_retention_days: 1
  daily_retention_days: 1
"#,
            data.display(),
            output.display(),
            source.display()
        );
        DeploymentConfig::from_yaml_str(&yaml).unwrap()
    }

    #[test]
    fn readiness_distinguishes_initializing_from_not_ready() {
        let conn = Connection::open_in_memory().unwrap();
        let initializing = health_ready(&conn, false, true);
        assert_eq!(initializing.status, "initializing");
        assert_eq!(initializing.checks.database, "ok");
        let not_ready = health_ready(&conn, true, false);
        assert_eq!(not_ready.status, "not_ready");
        assert_eq!(not_ready.checks.config, "failed");
    }

    #[test]
    fn capability_check_fails_closed_for_writes() {
        let dir = tempdir().unwrap();
        let source = tempdir().unwrap();
        let output = tempdir().unwrap();
        let cfg = config(dir.path(), source.path(), output.path());
        let checks = check_capabilities(&cfg, false);
        let safe_write = checks
            .iter()
            .find(|c| c.name == "safe_write_resolution")
            .unwrap();
        let cleanup = checks.iter().find(|c| c.name == "cleanup").unwrap();
        assert!(!safe_write.available);
        assert!(!cleanup.available);
    }

    #[test]
    fn collect_is_redacted_and_reports_real_database_values() {
        let data = tempdir().unwrap();
        let source = tempdir().unwrap();
        let output = tempdir().unwrap();
        let cfg = config(data.path(), source.path(), output.path());
        let mut conn = Connection::open_in_memory().unwrap();
        migrate::apply(&mut conn, migrate::CONTROL_MIGRATIONS).unwrap();
        conn.execute(
            "INSERT INTO sources (id, name, mount_key, availability, created_at, updated_at)
             VALUES ('source-1', 'Media', 'main', 'online', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        ).unwrap();
        let memory_budget = MemoryBudgetController::new(
            cfg.resources.api_memory_budget_mib,
            cfg.resources.worker_memory_budget_mib,
        )
        .unwrap();
        let info = collect(&conn, &cfg, false, &memory_budget).unwrap();
        assert_eq!(info.schema_migrations.control, 9);
        assert_eq!(info.sources[0].availability, "online");
        assert_eq!(info.memory_budget.api_budget_mib, 64);
        assert!(matches!(
            info.memory_budget.worker_status,
            "unknown" | "within_budget" | "over_budget"
        ));
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("password"));
        assert!(!json.contains(data.path().to_string_lossy().as_ref()));
        assert!(!json.contains(source.path().to_string_lossy().as_ref()));
    }
}
