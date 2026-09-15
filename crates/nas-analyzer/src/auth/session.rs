//! Opaque session tokens with idle + absolute expiry (spec 14.1). Only the
//! SHA-256 digest of the token is stored; the plaintext is returned once.

use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{AppError, AppResult, ErrorCode};

use super::{generate_token, internal, now_rfc3339, now_ts, parse_ts, token_hash};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub token_hash: String,
    pub user_id: String,
    pub csrf_secret: String,
    pub created_at: String,
    pub expires_idle_at: String,
    pub expires_absolute_at: String,
    pub last_seen_at: String,
}

/// Create a session for `user_id`. Returns `(plaintext_token, csrf_secret)`.
pub fn create_session(
    conn: &Connection,
    user_id: &str,
    idle_minutes: i64,
    absolute_hours: i64,
) -> AppResult<(String, String)> {
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
    let csrf_secret = generate_token();
    conn.execute(
        "INSERT INTO sessions(token_hash, user_id, csrf_secret, created_at, \
         expires_idle_at, expires_absolute_at, last_seen_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            token_hash(&token),
            user_id,
            csrf_secret,
            now_rfc3339(),
            super::rfc3339_plus_minutes(idle_minutes),
            super::rfc3339_plus_hours(absolute_hours),
            now_rfc3339(),
        ],
    )
    .map_err(|e| internal(format!("创建会话失败: {e}")))?;
    Ok((token, csrf_secret))
}

fn row_to_session(r: &rusqlite::Row<'_>) -> rusqlite::Result<Session> {
    Ok(Session {
        token_hash: r.get(0)?,
        user_id: r.get(1)?,
        csrf_secret: r.get(2)?,
        created_at: r.get(3)?,
        expires_idle_at: r.get(4)?,
        expires_absolute_at: r.get(5)?,
        last_seen_at: r.get(6)?,
    })
}

const SESSION_COLS: &str = "token_hash, user_id, csrf_secret, created_at, expires_idle_at, expires_absolute_at, last_seen_at";

/// Look up a session by plaintext token. Enforces both idle and absolute
/// expiry: an expired row is deleted and `None` returned. A live session gets
/// `last_seen_at` bumped and its idle deadline extended by the original idle
/// span (derived from `expires_idle_at - last_seen_at`).
pub fn lookup_session(conn: &Connection, token: &str) -> AppResult<Option<Session>> {
    lookup_session_at(conn, token, now_ts())
}

pub(crate) fn lookup_session_at(
    conn: &Connection,
    token: &str,
    now: Timestamp,
) -> AppResult<Option<Session>> {
    let hash = token_hash(token);
    let session: Option<Session> = conn
        .query_row(
            &format!("SELECT {SESSION_COLS} FROM sessions WHERE token_hash = ?1"),
            [&hash],
            row_to_session,
        )
        .optional()
        .map_err(|e| internal(format!("查询会话失败: {e}")))?;
    let Some(session) = session else {
        return Ok(None);
    };

    let idle_deadline = parse_ts(&session.expires_idle_at)?;
    let absolute_deadline = parse_ts(&session.expires_absolute_at)?;
    let last_seen = parse_ts(&session.last_seen_at)?;
    let deadline = idle_deadline.min(absolute_deadline);
    if now >= deadline {
        conn.execute("DELETE FROM sessions WHERE token_hash = ?1", [&hash])
            .map_err(|e| internal(format!("删除过期会话失败: {e}")))?;
        return Ok(None);
    }

    // Extend the idle window by the span it was created with.
    let idle_span = idle_deadline
        .duration_since(last_seen)
        .max(jiff::SignedDuration::ZERO);
    let new_last_seen = now;
    let new_idle_deadline = now
        .checked_add(idle_span)
        .map(|t| t.min(absolute_deadline))
        .unwrap_or(absolute_deadline);
    conn.execute(
        "UPDATE sessions SET last_seen_at = ?1, expires_idle_at = ?2 WHERE token_hash = ?3",
        params![
            new_last_seen.to_string(),
            new_idle_deadline.to_string(),
            hash
        ],
    )
    .map_err(|e| internal(format!("更新会话失败: {e}")))?;

    Ok(Some(Session {
        last_seen_at: new_last_seen.to_string(),
        expires_idle_at: new_idle_deadline.to_string(),
        ..session
    }))
}

/// Revoke a session by plaintext token. Ok even if it does not exist.
pub fn revoke_session(conn: &Connection, token: &str) -> AppResult<()> {
    conn.execute(
        "DELETE FROM sessions WHERE token_hash = ?1",
        [token_hash(token)],
    )
    .map_err(|e| internal(format!("注销会话失败: {e}")))?;
    Ok(())
}

/// Revoke every session of a user. Returns how many were removed.
pub fn revoke_all_user_sessions(conn: &Connection, user_id: &str) -> AppResult<u64> {
    let n = conn
        .execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])
        .map_err(|e| internal(format!("注销用户会话失败: {e}")))?;
    Ok(n as u64)
}

#[cfg(test)]
mod tests {
    use jiff::SignedDuration;
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
    fn create_and_lookup_updates_last_seen() {
        let (conn, uid) = setup();
        let (token, csrf) = create_session(&conn, &uid, 30, 24).unwrap();
        assert_eq!(token.len(), 64);
        assert_eq!(csrf.len(), 64);

        let first = lookup_session(&conn, &token).unwrap().unwrap();
        assert_eq!(first.user_id, uid);
        assert_eq!(first.csrf_secret, csrf);

        // Ten minutes later: still valid, last_seen bumped, idle deadline
        // pushed out by the 30-minute idle span but capped at absolute.
        let later = now_ts()
            .checked_add(SignedDuration::from_secs(600))
            .unwrap();
        let second = lookup_session_at(&conn, &token, later).unwrap().unwrap();
        assert!(second.last_seen_at > first.last_seen_at);
        assert!(second.expires_idle_at > first.expires_idle_at);
        assert_eq!(second.expires_absolute_at, first.expires_absolute_at);
        assert!(second.expires_idle_at <= second.expires_absolute_at);
    }

    #[test]
    fn idle_expiry_deletes_row() {
        let (conn, uid) = setup();
        let (token, _) = create_session(&conn, &uid, 30, 24).unwrap();
        let later = now_ts()
            .checked_add(SignedDuration::from_secs(31 * 60))
            .unwrap();
        assert!(lookup_session_at(&conn, &token, later).unwrap().is_none());
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn absolute_expiry_wins_over_idle() {
        let (conn, uid) = setup();
        let (token, _) = create_session(&conn, &uid, 30, 1).unwrap();
        // Refresh at +20 min: idle deadline moves to +50 min.
        let t20 = now_ts()
            .checked_add(SignedDuration::from_secs(20 * 60))
            .unwrap();
        let s = lookup_session_at(&conn, &token, t20).unwrap().unwrap();
        // Refresh at +45 min: idle window would extend to +75 min, but is
        // capped at the 1-hour absolute deadline.
        let t45 = now_ts()
            .checked_add(SignedDuration::from_secs(45 * 60))
            .unwrap();
        let s2 = lookup_session_at(&conn, &token, t45).unwrap().unwrap();
        assert_eq!(s2.expires_idle_at, s2.expires_absolute_at);
        assert!(s.expires_idle_at < s2.expires_idle_at);
        // Past the 1-hour absolute deadline: gone, even with fresh activity.
        let t61 = now_ts()
            .checked_add(SignedDuration::from_secs(61 * 60))
            .unwrap();
        assert!(lookup_session_at(&conn, &token, t61).unwrap().is_none());
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn unknown_and_revoked_tokens_are_none() {
        let (conn, uid) = setup();
        let (token, _) = create_session(&conn, &uid, 30, 24).unwrap();
        assert!(lookup_session(&conn, "no-such-token").unwrap().is_none());
        revoke_session(&conn, &token).unwrap();
        assert!(lookup_session(&conn, &token).unwrap().is_none());
        // Revoking again is fine.
        revoke_session(&conn, &token).unwrap();
    }

    #[test]
    fn create_session_requires_existing_user() {
        let (conn, _) = setup();
        let e = create_session(&conn, "ghost", 30, 24).unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
    }
}
