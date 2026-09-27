//! First-run bootstrap for the control database.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{AppError, AppResult, ErrorCode};

use super::admin::{AdminUser, insert_default_admin};
use super::{internal, now_rfc3339};

const INITIALIZED_KEY: &str = "initialized";
const TIMEZONE_KEY: &str = "timezone";

/// Whether first-run setup has completed (`app_settings.initialized`).
pub fn is_initialized(conn: &Connection) -> AppResult<bool> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value_json FROM app_settings WHERE key = ?1",
            [INITIALIZED_KEY],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| internal(format!("读取初始化状态失败: {e}")))?;
    Ok(value.as_deref() == Some("true"))
}

/// Create the fixed administrator for a brand-new data directory.
///
/// The default password is intentionally short and is accepted only by this
/// bootstrap path. The account is marked so the first authenticated session
/// can be restricted until the user chooses a normal password.
pub fn bootstrap_default_admin(conn: &mut Connection, timezone: &str) -> AppResult<AdminUser> {
    let tz = timezone.trim();
    if tz.is_empty() || tz.len() > 64 {
        return Err(AppError::new(
            ErrorCode::ValidationFailed,
            "时区名称需为 1-64 个字符",
        ));
    }
    let tz_json =
        serde_json::to_string(tz).map_err(|e| internal(format!("序列化时区失败: {e}")))?;

    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("开启事务失败: {e}")))?;
    if is_initialized(&tx)? {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "系统已完成初始化，不能重复执行",
        ));
    }
    let admin = insert_default_admin(&tx)?;
    let now = now_rfc3339();
    tx.execute(
        "INSERT INTO app_settings(key, value_json, version, updated_at) VALUES (?1, 'true', 1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value_json = 'true', version = version + 1, \
         updated_at = excluded.updated_at",
        params![INITIALIZED_KEY, now],
    )
    .map_err(|e| internal(format!("写入初始化状态失败: {e}")))?;
    tx.execute(
        "INSERT INTO app_settings(key, value_json, version, updated_at) VALUES (?1, ?2, 1, ?3) \
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, \
         version = version + 1, updated_at = excluded.updated_at",
        params![TIMEZONE_KEY, tz_json, now],
    )
    .map_err(|e| internal(format!("写入时区配置失败: {e}")))?;
    tx.commit()
        .map_err(|e| internal(format!("提交事务失败: {e}")))?;
    Ok(admin)
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use crate::store::migrate::{CONTROL_MIGRATIONS, apply};

    use super::*;

    fn test_conn() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        conn
    }

    #[test]
    fn bootstrap_creates_default_admin_and_marks_initialized() {
        let mut conn = test_conn();
        let admin = bootstrap_default_admin(&mut conn, "Asia/Shanghai").unwrap();
        assert_eq!(admin.username, "admin");
        assert!(admin.must_change_password);
        assert!(is_initialized(&conn).unwrap());

        let password: String = conn
            .query_row(
                "SELECT password_hash FROM admin_users WHERE username = 'admin'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(super::super::verify_password("admin", &password).unwrap());
        let logged_in = super::super::verify_admin_password(&conn, "admin", "admin")
            .unwrap()
            .unwrap();
        assert!(logged_in.must_change_password);
        let timezone: String = conn
            .query_row(
                "SELECT value_json FROM app_settings WHERE key = 'timezone'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(timezone, "\"Asia/Shanghai\"");
    }

    #[test]
    fn bootstrap_cannot_run_twice() {
        let mut conn = test_conn();
        bootstrap_default_admin(&mut conn, "UTC").unwrap();
        let error = bootstrap_default_admin(&mut conn, "UTC").unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
    }
}
