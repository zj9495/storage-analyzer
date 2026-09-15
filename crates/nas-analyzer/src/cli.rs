//! CLI entry points. Commands that belong to later milestones fail loudly
//! instead of pretending success.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::Path;

use crate::auth;
use crate::backup as configuration_backup;
use crate::config::DeploymentConfig;
use crate::error::AppError;
use crate::httpapi;
use crate::jobs;
use crate::store::{self, migrate};
use anyhow::{Context, Result, bail};

pub fn config_check(config: &str) -> Result<()> {
    let text = std::fs::read_to_string(config)
        .with_context(|| format!("cannot read config file: {config}"))?;
    let cfg = crate::config::DeploymentConfig::from_yaml_str(&text)?;
    cfg.validate_semantics()?;
    println!("config OK: {config} (config_version=2)");
    Ok(())
}

pub fn healthcheck(url: &str) -> Result<()> {
    let agent = ureq_agent();
    let resp = agent
        .get(url)
        .call()
        .with_context(|| format!("healthcheck request failed: {url}"))?;
    if resp.status() == 200 {
        Ok(())
    } else {
        bail!("healthcheck returned status {}", resp.status())
    }
}

fn ureq_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(5)))
        .build()
        .into()
}

// ---- serve (M1) ----

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // Structured JSON logs; secrets/tokens/passwords are never logged — the
    // HTTP layer only records request_id, method and path.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(true)
        .init();
}

pub fn serve(config: &str) -> Result<()> {
    let cfg = DeploymentConfig::from_file(Path::new(config))
        .map_err(|e| anyhow::anyhow!("invalid deployment config: {e}"))?;
    cfg.validate_semantics()
        .map_err(|e| anyhow::anyhow!("invalid deployment config: {e}"))?;
    init_tracing();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    rt.block_on(serve_with(cfg))
}

/// Async serve entry taking an already-loaded config (also used by tests).
/// Binds `config.server.listen`, serves until SIGTERM/SIGINT, then waits up
/// to 60 s for in-flight requests before forcing exit.
pub async fn serve_with(config: DeploymentConfig) -> Result<()> {
    let listen = config.server.listen;
    let (state, writer_guard) =
        httpapi::AppState::start(&config).map_err(|e| anyhow::anyhow!("startup failed: {e}"))?;
    state
        .writer
        .call(jobs::mark_interrupted)
        .await
        .map_err(|e| anyhow::anyhow!("job startup recovery failed: {e}"))?;
    let recovery_writer = state.writer.clone();
    let recovery_config = config.clone();
    let (recovery_tx, recovery_rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("cleanup-recovery".to_string())
        .spawn(move || {
            let _ = recovery_tx.send(crate::cleanup::recover_pending(
                recovery_writer,
                &recovery_config,
            ));
        })
        .map_err(|error| anyhow::anyhow!("cleanup recovery thread startup failed: {error}"))?;
    let recovered_cleanup_actions = recovery_rx
        .await
        .map_err(|_| anyhow::anyhow!("cleanup recovery thread stopped unexpectedly"))?
        .map_err(|e| anyhow::anyhow!("cleanup startup recovery failed: {e}"))?;
    if recovered_cleanup_actions > 0 {
        tracing::info!(
            actions = recovered_cleanup_actions,
            "cleanup startup recovery complete"
        );
    }
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("cannot bind {listen}"))?;
    let runtime = crate::runtime::RuntimeSupervisors::start(state.clone())
        .map_err(|e| anyhow::anyhow!("runtime startup failed: {e}"))?;
    let worker = crate::worker::WorkerSupervisor::start(state.clone())
        .await
        .map_err(|e| anyhow::anyhow!("worker startup failed: {e}"))?;
    let app = httpapi::build_app(state);
    tracing::info!(listen = %listen, "nas-analyzer serving");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("http server error")?;
    runtime.shutdown();
    worker.shutdown().await;
    writer_guard.shutdown();
    tracing::info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let sigterm = signal(SignalKind::terminate());
    match sigterm {
        Ok(mut term) => {
            tokio::select! {
                _ = term.recv() => tracing::info!("received SIGTERM, starting graceful shutdown"),
                _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT, starting graceful shutdown"),
            }
        }
        Err(e) => {
            tracing::warn!("cannot install SIGTERM handler ({e}); only SIGINT is handled");
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    // Hard stop: never hang a container shutdown longer than 60 s.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        tracing::error!("graceful shutdown exceeded 60s; forcing exit");
        std::process::exit(2);
    });
}

// ---- admin commands (M1) ----

/// Open the control DB at `data_dir` (creating dirs and applying migrations)
/// while holding the data-directory instance lock for the caller's operation.
fn open_control_db(data_dir: &str) -> Result<(rusqlite::Connection, httpapi::InstanceLock)> {
    let dir = Path::new(data_dir);
    std::fs::create_dir_all(dir)
        .with_context(|| format!("cannot create data dir {}", dir.display()))?;
    let lock = httpapi::acquire_instance_lock(dir)
        .map_err(|e| anyhow::anyhow!("cannot acquire data directory lock: {e}"))?;
    let conn = open_migrated(dir)?;
    Ok((conn, lock))
}

fn open_migrated(dir: &Path) -> Result<rusqlite::Connection> {
    let mut conn = store::open_connection(&dir.join("control.sqlite"), false, true)
        .map_err(|e| anyhow::anyhow!("cannot open control database: {e}"))?;
    migrate::apply(&mut conn, migrate::CONTROL_MIGRATIONS)
        .map_err(|e| anyhow::anyhow!("migration failed: {e}"))?;
    Ok(conn)
}

/// Generate a one-time setup token and write it to `<data-dir>/setup-token`
/// (mode 0600). The token itself is never printed to stdout/logs.
pub fn admin_setup_token(data_dir: &str) -> Result<()> {
    let (conn, _instance_lock) = open_control_db(data_dir)?;
    let token = auth::generate_setup_token(&conn, 30)
        .map_err(|e| anyhow::anyhow!("cannot generate setup token: {e}"))?;
    let path = Path::new(data_dir).join("setup-token");
    write_token_file(&path, &token)?;
    println!(
        "setup token written to {} (single use, valid 30 minutes)",
        path.display()
    );
    Ok(())
}

fn write_token_file(path: &Path, token: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    f.write_all(token.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    // Force 0600 even if the file pre-existed with looser permissions.
    let mut perms = std::fs::metadata(path)?.permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

/// Reset an admin password. The new password is read from the terminal
/// (stdin prompt), never from a CLI argument; all sessions of the user are
/// revoked by auth::reset_password.
pub fn admin_reset_password(data_dir: &str, username: &str) -> Result<()> {
    let (mut conn, _instance_lock) = open_control_db(data_dir)?;
    eprint!("请输入 {username} 的新密码（至少 12 字符，输入不回显请自行注意）: ");
    std::io::stderr().flush()?;
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .context("reading password from stdin failed")?;
    let password = password.trim_end_matches(['\n', '\r']);
    auth::reset_password(&mut conn, username, password)
        .map_err(|e| anyhow::anyhow!("cannot reset password: {e}"))?;
    println!("password reset for {username}; all existing sessions revoked");
    Ok(())
}

// ---- worker and configuration archive commands ----

/// Run the private worker protocol.  A worker never opens the control DB or
/// takes the data-directory instance lock; the serving process owns both and
/// sends the typed job snapshot over its bounded stdin/stdout IPC.
pub fn worker(config: Option<&str>, job_id: &str) -> Result<()> {
    if let Some(config) = config {
        let config = DeploymentConfig::from_file(Path::new(config))
            .map_err(|error| cli_error("invalid deployment config", error))?;
        config
            .validate_semantics()
            .map_err(|error| cli_error("invalid deployment config", error))?;
    }
    crate::worker::run_worker_process(job_id)
        .map_err(|error| cli_error("worker process failed", error))
}

pub fn backup(data_dir: &str, output: &str) -> Result<()> {
    let summary = configuration_backup::backup(data_dir, output)
        .map_err(|error| cli_error("backup failed", error))?;
    println!(
        "backup created: {} (entries={}, config_bytes={})",
        summary.output.display(),
        summary.entries,
        summary.config_bytes
    );
    Ok(())
}

pub fn restore(data_dir: &str, input: &str, dry_run: bool) -> Result<()> {
    let restored = configuration_backup::restore(data_dir, input, dry_run)
        .map_err(|error| cli_error("restore failed", error))?;
    let plan = restored.plan;
    if restored.dry_run {
        println!(
            "restore dry-run OK: {} (entries={}, tables={}, rows={}, bytes={})",
            plan.input.display(),
            plan.entries,
            plan.table_count,
            plan.row_count,
            plan.total_uncompressed_bytes
        );
    } else {
        println!(
            "restore completed: {} (entries={}, tables={}, rows={}, bytes={})",
            plan.input.display(),
            plan.entries,
            plan.table_count,
            plan.row_count,
            plan.total_uncompressed_bytes
        );
        if let Some(pre_restore_backup) = restored.pre_restore_backup {
            println!(
                "pre-restore backup created: {}",
                pre_restore_backup.display()
            );
        }
    }
    Ok(())
}

fn cli_error(context: &str, error: AppError) -> anyhow::Error {
    anyhow::anyhow!("{}: {context}", error.code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ResourceConfig, SamplingConfig, SecurityConfig, ServerConfig, StorageConfig,
    };
    use crate::error::ErrorCode;

    fn serve_test_config(data_dir: &std::path::Path) -> DeploymentConfig {
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
                approved_output_roots: vec![data_dir.to_path_buf()],
                data_budget_bytes: 1024,
                hash_cache_budget_bytes: 1024,
            },
            approved_mounts: vec![],
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
                max_open_files: 64,
                api_memory_budget_mib: 256,
                worker_memory_budget_mib: 512,
                max_parallel_exports: 1,
            },
            sampling: SamplingConfig {
                interval_minutes: 60,
                raw_retention_days: 1,
                daily_retention_days: 1,
            },
        }
    }

    #[test]
    fn cli_error_keeps_code_without_error_message_or_details() {
        let error = AppError::new(ErrorCode::NotFound, "secret value")
            .with_details(serde_json::json!({"token": "secret value"}));
        let rendered = cli_error("cannot inspect requested job", error).to_string();
        assert_eq!(rendered, "NOT_FOUND: cannot inspect requested job");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn serve_with_stops_before_supervisors_when_cleanup_recovery_fails() {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let config = serve_test_config(&data_dir);
        let database = data_dir.join("control.sqlite");
        let mut connection = rusqlite::Connection::open(&database).unwrap();
        migrate::apply(&mut connection, migrate::CONTROL_MIGRATIONS).unwrap();
        connection
            .execute(
                "INSERT INTO cleanup_plans
                 (id, report_id, payload_json, payload_sig, expires_at, actor_id, state, created_at)
                 VALUES ('startup-plan', 'report', '{}', '', '2099-01-01T00:00:00Z', 'actor',
                         'executing', '2026-09-13T00:00:00Z')",
                [],
            )
            .unwrap();
        let params = serde_json::json!({
            "action": "quarantine",
            "action_id": "startup-action",
            "plan_id": "startup-plan",
            "actor_id": "actor"
        });
        connection
            .execute(
                "INSERT INTO jobs (id, type, state, params_json, requested_at, error_json)
                 VALUES (?1, 'cleanup', 'INTERRUPTED', ?2, ?3, ?4)",
                rusqlite::params![
                    "startup-job",
                    params.to_string(),
                    "2026-09-13T00:00:00Z",
                    serde_json::json!({"code": "INTERRUPTED"}).to_string(),
                ],
            )
            .unwrap();
        drop(connection);

        let error = serve_with(config).await.unwrap_err().to_string();
        assert!(error.contains("cleanup startup recovery failed"), "{error}");

        let connection = rusqlite::Connection::open(&database).unwrap();
        let state: String = connection
            .query_row(
                "SELECT state FROM jobs WHERE id = 'startup-job'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "INTERRUPTED");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn backup_and_restore_cli_delegate_to_safe_api_with_dry_run() {
        let data = tempfile::tempdir().unwrap();
        let database = data.path().join("control.sqlite");
        let mut connection = rusqlite::Connection::open(&database).unwrap();
        migrate::apply(&mut connection, migrate::CONTROL_MIGRATIONS).unwrap();
        drop(connection);

        let archive = data.path().join("backup.zip");
        let data_dir = data.path().to_str().unwrap();
        let archive_path = archive.to_str().unwrap();
        backup(data_dir, archive_path).unwrap();
        assert!(archive.is_file());

        restore(data_dir, archive_path, true).unwrap();
        assert!(!data.path().join("config-backups").exists());
    }

    #[test]
    fn archive_cli_errors_do_not_include_underlying_secret_or_path() {
        let data = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret_path = outside.path().join("secret-token.zip");
        let error = restore(
            data.path().to_str().unwrap(),
            secret_path.to_str().unwrap(),
            true,
        )
        .unwrap_err()
        .to_string();

        assert_eq!(error, "PATH_OUTSIDE_ROOT: restore failed");
        assert!(!error.contains("secret-token"));
    }

    #[test]
    #[cfg(unix)]
    fn open_control_db_rejects_lock_contention_before_migrating() {
        let data = tempfile::tempdir().unwrap();
        let database = data.path().join("control.sqlite");
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE marker (value TEXT NOT NULL); \
                 INSERT INTO marker(value) VALUES ('unchanged');",
            )
            .unwrap();
        drop(connection);

        let _lock = httpapi::acquire_instance_lock(data.path()).unwrap();
        let error = match open_control_db(data.path().to_str().unwrap()) {
            Ok(_) => panic!("control DB opened while the instance lock was held"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("already locked"));

        let connection = rusqlite::Connection::open(&database).unwrap();
        let migration_table_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                 WHERE type = 'table' AND name = 'schema_migrations')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!migration_table_exists);
        let marker: String = connection
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(marker, "unchanged");
    }
}
