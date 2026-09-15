//! One-time setup tokens and first-run initialization (spec 3.3). Only the
//! SHA-256 digest of a token is stored; consuming and completing setup are
//! atomic so racing browsers cannot both succeed.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{AppError, AppResult, ErrorCode};

use super::admin::{AdminUser, insert_admin, validate_password, validate_username};
use super::{generate_token, internal, now_rfc3339, rfc3339_plus_minutes, token_hash};

const INITIALIZED_KEY: &str = "initialized";
const TIMEZONE_KEY: &str = "timezone";

/// Generate a setup token valid for `ttl_minutes`. Returns the plaintext
/// token; only its digest lands in `setup_tokens`.
pub fn generate_setup_token(conn: &Connection, ttl_minutes: i64) -> AppResult<String> {
    let token = generate_token();
    conn.execute(
        "INSERT INTO setup_tokens(token_hash, expires_at, used, created_at) \
         VALUES (?1, ?2, 0, ?3)",
        params![
            token_hash(&token),
            rfc3339_plus_minutes(ttl_minutes),
            now_rfc3339()
        ],
    )
    .map_err(|e| internal(format!("保存初始化令牌失败: {e}")))?;
    Ok(token)
}

/// Atomically consume a setup token: marks it used exactly when it exists, is
/// unused and unexpired. Returns `Unauthorized` otherwise.
pub fn consume_setup_token(conn: &Connection, token: &str) -> AppResult<()> {
    consume_setup_token_in(conn, token)
}

/// The atomic consume used both standalone and inside `complete_setup`'s
/// transaction. Takes `&Connection` so a `Transaction` (which derefs to
/// `Connection`) can be passed.
pub(crate) fn consume_setup_token_in(conn: &Connection, token: &str) -> AppResult<()> {
    let affected = conn
        .execute(
            "UPDATE setup_tokens SET used = 1 \
             WHERE token_hash = ?1 AND used = 0 AND expires_at > ?2",
            params![token_hash(token), now_rfc3339()],
        )
        .map_err(|e| internal(format!("消费初始化令牌失败: {e}")))?;
    if affected != 1 {
        return Err(AppError::new(
            ErrorCode::Unauthorized,
            "初始化令牌无效、已使用或已过期",
        ));
    }
    Ok(())
}

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

/// Complete first-run setup atomically: verify the app is not initialized,
/// consume the token, create the first admin, record timezone and mark
/// initialized — all in one transaction.
pub fn complete_setup(
    conn: &mut Connection,
    token: &str,
    username: &str,
    password: &str,
    timezone: &str,
) -> AppResult<AdminUser> {
    validate_username(username)?;
    validate_password(password)?;
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
    consume_setup_token_in(&tx, token)?;
    let admin = insert_admin(&tx, username, password)?;
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

    const PW: &str = "a very long password";

    fn test_conn() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        conn
    }

    #[test]
    fn setup_completes_exactly_once() {
        let mut conn = test_conn();
        let token = generate_setup_token(&conn, 30).unwrap();
        assert!(!is_initialized(&conn).unwrap());
        let admin = complete_setup(&mut conn, &token, "admin", PW, "Asia/Shanghai").unwrap();
        assert_eq!(admin.username, "admin");
        assert!(is_initialized(&conn).unwrap());

        // A second attempt — even with a fresh, valid token — must fail.
        let token2 = generate_setup_token(&conn, 30).unwrap();
        let e = complete_setup(&mut conn, &token2, "admin2", PW, "UTC").unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);
        // And the fresh token was not consumed by the failed attempt.
        consume_setup_token(&conn, &token2).unwrap();

        // Timezone was recorded.
        let tz: String = conn
            .query_row(
                "SELECT value_json FROM app_settings WHERE key = 'timezone'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tz, "\"Asia/Shanghai\"");
    }

    #[test]
    fn token_reuse_rejected() {
        let conn = test_conn();
        let token = generate_setup_token(&conn, 30).unwrap();
        consume_setup_token(&conn, &token).unwrap();
        let e = consume_setup_token(&conn, &token).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn expired_token_rejected() {
        let conn = test_conn();
        let token = generate_setup_token(&conn, -1).unwrap();
        let e = consume_setup_token(&conn, &token).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unauthorized);
        // Unknown tokens are rejected identically.
        let e = consume_setup_token(&conn, "deadbeef").unwrap_err();
        assert_eq!(e.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn complete_setup_with_bad_token_changes_nothing() {
        let mut conn = test_conn();
        let token = generate_setup_token(&conn, -1).unwrap();
        let e = complete_setup(&mut conn, &token, "admin", PW, "UTC").unwrap_err();
        assert_eq!(e.code, ErrorCode::Unauthorized);
        assert!(!is_initialized(&conn).unwrap());
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM admin_users", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn setup_rejects_invalid_inputs_before_touching_state() {
        let mut conn = test_conn();
        let token = generate_setup_token(&conn, 30).unwrap();
        let e = complete_setup(&mut conn, &token, "bad name", PW, "UTC").unwrap_err();
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        let e = complete_setup(&mut conn, &token, "admin", "short", "UTC").unwrap_err();
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        let e = complete_setup(&mut conn, &token, "admin", PW, "").unwrap_err();
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        // Token still unconsumed and app uninitialized.
        assert!(!is_initialized(&conn).unwrap());
        consume_setup_token(&conn, &token).unwrap();
    }
}
