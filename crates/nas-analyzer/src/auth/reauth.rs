//! Single-use re-authentication tokens for dangerous operations (spec 14.1:
//! actions require re-authentication within the last 5 minutes).

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{AppError, AppResult, ErrorCode};

use super::{generate_token, internal, now_rfc3339, rfc3339_plus_minutes, token_hash};

/// Create a single-use re-authentication token valid for `minutes`.
/// Returns the plaintext token; only its digest is stored.
pub fn create_reauth_token(conn: &Connection, user_id: &str, minutes: i64) -> AppResult<String> {
    let exists: Option<String> = conn
        .query_row("SELECT id FROM admin_users WHERE id = ?1", [user_id], |r| {
            r.get(0)
        })
        .optional()
        .map_err(|e| internal(format!("查询管理员失败: {e}")))?;
    if exists.is_none() {
        return Err(AppError::new(ErrorCode::NotFound, "管理员账号不存在"));
    }
    let token = generate_token();
    conn.execute(
        "INSERT INTO reauth_tokens(token_hash, user_id, expires_at, used) \
         VALUES (?1, ?2, ?3, 0)",
        params![token_hash(&token), user_id, rfc3339_plus_minutes(minutes)],
    )
    .map_err(|e| internal(format!("保存重新认证令牌失败: {e}")))?;
    Ok(token)
}

/// Atomically consume a re-authentication token: marked used exactly when it
/// exists, is unused and unexpired. Returns the owning user id on success.
pub fn consume_reauth_token(conn: &Connection, token: &str) -> AppResult<String> {
    let tx_hash = token_hash(token);
    let affected = conn
        .execute(
            "UPDATE reauth_tokens SET used = 1 \
             WHERE token_hash = ?1 AND used = 0 AND expires_at > ?2",
            params![tx_hash, now_rfc3339()],
        )
        .map_err(|e| internal(format!("消费重新认证令牌失败: {e}")))?;
    if affected != 1 {
        return Err(AppError::new(
            ErrorCode::Unauthorized,
            "重新认证令牌无效、已使用或已过期",
        ));
    }
    conn.query_row(
        "SELECT user_id FROM reauth_tokens WHERE token_hash = ?1",
        [tx_hash],
        |r| r.get(0),
    )
    .map_err(|e| internal(format!("读取重新认证令牌失败: {e}")))
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use crate::store::migrate::{CONTROL_MIGRATIONS, apply};

    use super::super::create_admin;
    use super::*;

    const PW: &str = "a very long password";

    fn setup() -> (Connection, String) {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        let admin = create_admin(&conn, "admin", PW).unwrap();
        (conn, admin.id)
    }

    #[test]
    fn reauth_token_single_use() {
        let (conn, uid) = setup();
        let token = create_reauth_token(&conn, &uid, 5).unwrap();
        assert_eq!(consume_reauth_token(&conn, &token).unwrap(), uid);
        let e = consume_reauth_token(&conn, &token).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn reauth_token_expired_and_unknown_rejected() {
        let (conn, uid) = setup();
        let token = create_reauth_token(&conn, &uid, -1).unwrap();
        let e = consume_reauth_token(&conn, &token).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unauthorized);
        let e = consume_reauth_token(&conn, "deadbeef").unwrap_err();
        assert_eq!(e.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn reauth_token_requires_existing_user() {
        let (conn, _) = setup();
        let e = create_reauth_token(&conn, "ghost", 5).unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
    }
}
