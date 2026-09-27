//! Checked SQL migrations (spec 16, 18.4). Each migration file is embedded at
//! build time; applied versions are recorded with a SHA-256 checksum. A
//! checksum mismatch for an already-applied version, or a database newer than
//! the binary, is a hard startup failure — never a silent repair.

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult, ErrorCode};

pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub sql: &'static str,
}

fn err(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

fn sqlite_err(operation: impl Into<String>, error: rusqlite::Error) -> AppError {
    AppError::from_sqlite(operation, error)
}

pub fn checksum(sql: &str) -> String {
    hex::encode(Sha256::digest(sql.as_bytes()))
}

/// Apply pending migrations in order inside transactions.
pub fn apply(conn: &mut Connection, migrations: &[Migration]) -> AppResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TEXT NOT NULL
        );",
    )
    .map_err(|e| sqlite_err("create schema_migrations", e))?;

    let max_applied: Option<u32> = conn
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })
        .map_err(|e| sqlite_err("read schema_migrations", e))?;
    let max_known = migrations.iter().map(|m| m.version).max().unwrap_or(0);
    if let Some(applied) = max_applied
        && applied > max_known
    {
        return Err(err(format!(
            "database schema version {applied} is newer than this binary supports \
             ({max_known}); refusing to start — use the matching or newer image"
        )));
    }

    for m in migrations {
        let existing: Option<(String,)> = conn
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = ?1",
                [m.version],
                |r| Ok((r.get::<_, String>(0)?,)),
            )
            .optional()
            .map_err(|e| sqlite_err(format!("read migration {}", m.version), e))?;
        let sum = checksum(m.sql);
        if let Some((recorded,)) = existing {
            if recorded != sum {
                return Err(err(format!(
                    "migration {:04}_{} checksum mismatch: database has {}, file has {}; \
                     refusing to run with modified migration history",
                    m.version, m.name, recorded, sum
                )));
            }
            continue;
        }
        let tx = conn
            .transaction()
            .map_err(|e| sqlite_err(format!("begin migration {}", m.version), e))?;
        tx.execute_batch(m.sql)
            .map_err(|e| sqlite_err(format!("apply migration {:04}_{}", m.version, m.name), e))?;
        tx.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at) \
             VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
            rusqlite::params![m.version, m.name, sum],
        )
        .map_err(|e| sqlite_err(format!("record migration {}", m.version), e))?;
        tx.commit()
            .map_err(|e| sqlite_err(format!("commit migration {}", m.version), e))?;
    }
    Ok(())
}

pub static CONTROL_MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "init",
        sql: include_str!("../../../../migrations/control/0001_init.sql"),
    },
    Migration {
        version: 2,
        name: "comparisons",
        sql: include_str!("../../../../migrations/control/0002_comparisons.sql"),
    },
    Migration {
        version: 3,
        name: "restore_operations",
        sql: include_str!("../../../../migrations/control/0003_restore_operations.sql"),
    },
    Migration {
        version: 4,
        name: "report_artifact_deletions",
        sql: include_str!("../../../../migrations/control/0004_report_artifact_deletions.sql"),
    },
    Migration {
        version: 5,
        name: "profile_next_run",
        sql: include_str!("../../../../migrations/control/0005_profile_next_run.sql"),
    },
    Migration {
        version: 6,
        name: "schedule_occurrence_skips",
        sql: include_str!("../../../../migrations/control/0006_schedule_occurrence_skips.sql"),
    },
    Migration {
        version: 7,
        name: "daily_capacity_ranges",
        sql: include_str!("../../../../migrations/control/0007_daily_capacity_ranges.sql"),
    },
    Migration {
        version: 8,
        name: "internal_notifications",
        sql: include_str!("../../../../migrations/control/0008_internal_notifications.sql"),
    },
    Migration {
        version: 9,
        name: "internal_notification_event_keys",
        sql: include_str!(
            "../../../../migrations/control/0009_internal_notification_event_keys.sql"
        ),
    },
    Migration {
        version: 10,
        name: "password_change_required",
        sql: include_str!("../../../../migrations/control/0010_password_change_required.sql"),
    },
];

pub static INDEX_MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "init",
        sql: include_str!("../../../../migrations/index/0001_init.sql"),
    },
    Migration {
        version: 2,
        name: "nullable_aggregates",
        sql: include_str!("../../../../migrations/index/0002_nullable_aggregates.sql"),
    },
];

pub static REPORT_MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "init",
        sql: include_str!("../../../../migrations/report/0001_init.sql"),
    },
    Migration {
        version: 2,
        name: "snapshot_contract",
        sql: include_str!("../../../../migrations/report/0002_snapshot_contract.sql"),
    },
    Migration {
        version: 3,
        name: "nullable_aggregates",
        sql: include_str!("../../../../migrations/report/0003_nullable_aggregates.sql"),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_and_records_checksum() {
        let mut conn = Connection::open_in_memory().unwrap();
        let ms = [Migration {
            version: 1,
            name: "t",
            sql: "CREATE TABLE t(x INTEGER);",
        }];
        apply(&mut conn, &ms).unwrap();
        // Idempotent re-apply.
        apply(&mut conn, &ms).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn checksum_mismatch_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        let m1 = [Migration {
            version: 1,
            name: "t",
            sql: "CREATE TABLE t(x INTEGER);",
        }];
        apply(&mut conn, &m1).unwrap();
        let m2 = [Migration {
            version: 1,
            name: "t",
            sql: "CREATE TABLE t(y INTEGER);",
        }];
        let e = apply(&mut conn, &m2).unwrap_err();
        assert!(e.message.contains("checksum mismatch"));
    }

    #[test]
    fn sqlite_migration_errors_remain_internal_when_not_disk_full() {
        let mut conn = Connection::open_in_memory().unwrap();
        let migrations = [Migration {
            version: 1,
            name: "missing_table",
            sql: "SELECT * FROM missing_table;",
        }];

        let e = apply(&mut conn, &migrations).unwrap_err();

        assert_eq!(e.code, ErrorCode::Internal);
    }

    #[test]
    fn sqlite_full_migration_maps_to_insufficient_data_space() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA max_page_count = 1;").unwrap();
        let migrations = [Migration {
            version: 1,
            name: "full",
            sql: "CREATE TABLE t(x INTEGER);",
        }];

        let e = apply(&mut conn, &migrations).unwrap_err();

        assert_eq!(e.code, ErrorCode::InsufficientDataSpace);
    }

    #[test]
    fn newer_database_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        let ms = [
            Migration {
                version: 1,
                name: "a",
                sql: "CREATE TABLE a(x INTEGER);",
            },
            Migration {
                version: 2,
                name: "b",
                sql: "CREATE TABLE b(x INTEGER);",
            },
        ];
        apply(&mut conn, &ms).unwrap();
        apply(&mut conn, &ms[..1]).unwrap_err();
    }

    #[test]
    fn control_migrations_apply_clean() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM sources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn password_flag_migration_preserves_existing_admin_and_sessions() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, &CONTROL_MIGRATIONS[..9]).unwrap();
        let (password_hash, password_params) =
            crate::auth::hash_password("legacy-password").unwrap();
        conn.execute(
            "INSERT INTO admin_users
             (id, username, password_hash, password_params_json, enabled, created_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5)",
            rusqlite::params![
                "legacy-admin",
                "legacy",
                password_hash,
                password_params,
                crate::auth::now_rfc3339(),
            ],
        )
        .unwrap();
        let (token, _) = crate::auth::create_session(&conn, "legacy-admin", 30, 24).unwrap();

        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();

        let admin = crate::auth::verify_admin_password(&conn, "legacy", "legacy-password")
            .unwrap()
            .unwrap();
        assert!(!admin.must_change_password);
        assert!(
            crate::auth::lookup_session(&conn, &token)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn index_and_report_migrations_apply_clean() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, INDEX_MIGRATIONS).unwrap();
        let mut conn2 = Connection::open_in_memory().unwrap();
        apply(&mut conn2, REPORT_MIGRATIONS).unwrap();
    }
}
