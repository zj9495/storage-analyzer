//! Admin account CRUD with last-enabled-admin protection (spec 14.1).

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{AppError, AppResult, ErrorCode};

use super::{hash_password, internal, now_rfc3339, verify_password};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminUser {
    pub id: String,
    pub username: String,
    pub enabled: bool,
    pub must_change_password: bool,
    pub created_at: String,
}

pub(crate) fn validate_username(username: &str) -> AppResult<()> {
    let ok = !username.is_empty()
        && username.len() <= 64
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if ok {
        Ok(())
    } else {
        Err(AppError::new(
            ErrorCode::ValidationFailed,
            "用户名需为 1-64 个字符，仅允许字母、数字、下划线、点和连字符",
        ))
    }
}

pub(crate) fn validate_password(password: &str) -> AppResult<()> {
    if password.chars().count() >= 8 {
        Ok(())
    } else {
        Err(AppError::new(
            ErrorCode::ValidationFailed,
            "密码长度至少为 8 个字符",
        ))
    }
}

/// Insert a new administrator row; takes `&Connection` so it can run inside
/// an existing transaction.
pub(crate) fn insert_admin(
    conn: &Connection,
    username: &str,
    password: &str,
) -> AppResult<AdminUser> {
    validate_username(username)?;
    validate_password(password)?;
    let (encoded, params_json) = hash_password(password)?;
    let admin = AdminUser {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.to_string(),
        enabled: true,
        must_change_password: false,
        created_at: now_rfc3339(),
    };
    conn.execute(
        "INSERT INTO admin_users(id, username, password_hash, password_params_json, enabled, \
         must_change_password, created_at) VALUES (?1, ?2, ?3, ?4, 1, 0, ?5)",
        params![
            admin.id,
            admin.username,
            encoded,
            params_json,
            admin.created_at
        ],
    )
    .map_err(|e| {
        if let rusqlite::Error::SqliteFailure(err, _) = &e
            && err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
        {
            return AppError::new(ErrorCode::Conflict, "用户名已存在");
        }
        internal(format!("创建管理员失败: {e}"))
    })?;
    Ok(admin)
}

/// Insert the fixed initial account used by a brand-new data directory.
/// The short password is allowed only here; every user-supplied password goes
/// through [`validate_password`].
pub(crate) fn insert_default_admin(conn: &Connection) -> AppResult<AdminUser> {
    let (encoded, params_json) = hash_password("admin")?;
    let admin = AdminUser {
        id: uuid::Uuid::new_v4().to_string(),
        username: "admin".to_string(),
        enabled: true,
        must_change_password: true,
        created_at: now_rfc3339(),
    };
    conn.execute(
        "INSERT INTO admin_users(id, username, password_hash, password_params_json, enabled, \
         must_change_password, created_at) VALUES (?1, ?2, ?3, ?4, 1, 1, ?5)",
        params![
            admin.id,
            admin.username,
            encoded,
            params_json,
            admin.created_at
        ],
    )
    .map_err(|e| internal(format!("创建默认管理员失败: {e}")))?;
    Ok(admin)
}

pub fn create_admin(conn: &Connection, username: &str, password: &str) -> AppResult<AdminUser> {
    insert_admin(conn, username, password)
}

pub fn list_admins(conn: &Connection) -> AppResult<Vec<AdminUser>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, username, enabled, must_change_password, created_at \
             FROM admin_users ORDER BY created_at",
        )
        .map_err(|e| internal(format!("查询管理员列表失败: {e}")))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(AdminUser {
                id: r.get(0)?,
                username: r.get(1)?,
                enabled: r.get::<_, i64>(2)? != 0,
                must_change_password: r.get::<_, i64>(3)? != 0,
                created_at: r.get(4)?,
            })
        })
        .map_err(|e| internal(format!("查询管理员列表失败: {e}")))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal(format!("查询管理员列表失败: {e}")))
}

fn find_admin(conn: &Connection, username: &str) -> AppResult<Option<AdminUser>> {
    conn.query_row(
        "SELECT id, username, enabled, must_change_password, created_at FROM admin_users \
         WHERE username = ?1",
        [username],
        |r| {
            Ok(AdminUser {
                id: r.get(0)?,
                username: r.get(1)?,
                enabled: r.get::<_, i64>(2)? != 0,
                must_change_password: r.get::<_, i64>(3)? != 0,
                created_at: r.get(4)?,
            })
        },
    )
    .optional()
    .map_err(|e| internal(format!("查询管理员失败: {e}")))
}

/// Number of enabled admins excluding `exclude_user_id`.
fn other_enabled_count(conn: &Connection, exclude_user_id: &str) -> AppResult<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM admin_users WHERE enabled = 1 AND id != ?1",
        [exclude_user_id],
        |r| r.get(0),
    )
    .map_err(|e| internal(format!("统计管理员数量失败: {e}")))
}

fn require_not_last_enabled(conn: &Connection, admin: &AdminUser) -> AppResult<()> {
    if admin.enabled && other_enabled_count(conn, &admin.id)? == 0 {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "不能禁用或删除最后一个启用状态的管理员账号",
        ));
    }
    Ok(())
}

pub fn set_enabled(conn: &Connection, username: &str, enabled: bool) -> AppResult<()> {
    let admin = find_admin(conn, username)?
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "管理员账号不存在"))?;
    if !enabled {
        require_not_last_enabled(conn, &admin)?;
    }
    conn.execute(
        "UPDATE admin_users SET enabled = ?1 WHERE id = ?2",
        params![i64::from(enabled), admin.id],
    )
    .map_err(|e| internal(format!("更新管理员状态失败: {e}")))?;
    // Disabling an account also ends its sessions.
    if !enabled {
        conn.execute("DELETE FROM sessions WHERE user_id = ?1", [&admin.id])
            .map_err(|e| internal(format!("清除会话失败: {e}")))?;
    }
    Ok(())
}

pub fn delete_admin(conn: &Connection, username: &str) -> AppResult<()> {
    let admin = find_admin(conn, username)?
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "管理员账号不存在"))?;
    require_not_last_enabled(conn, &admin)?;
    // Delete sessions explicitly too: foreign keys (and thus ON DELETE
    // CASCADE) may be off on this connection.
    conn.execute("DELETE FROM sessions WHERE user_id = ?1", [&admin.id])
        .map_err(|e| internal(format!("清除会话失败: {e}")))?;
    conn.execute("DELETE FROM admin_users WHERE id = ?1", [&admin.id])
        .map_err(|e| internal(format!("删除管理员失败: {e}")))?;
    Ok(())
}

/// Reset a password and revoke all sessions of that user, atomically.
pub fn reset_password(conn: &mut Connection, username: &str, new_password: &str) -> AppResult<()> {
    validate_password(new_password)?;
    let admin = find_admin(conn, username)?
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "管理员账号不存在"))?;
    let (encoded, params_json) = hash_password(new_password)?;
    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("开启事务失败: {e}")))?;
    tx.execute(
        "UPDATE admin_users SET password_hash = ?1, password_params_json = ?2, \
         must_change_password = 0 WHERE id = ?3",
        params![encoded, params_json, admin.id],
    )
    .map_err(|e| internal(format!("重置密码失败: {e}")))?;
    tx.execute("DELETE FROM sessions WHERE user_id = ?1", [&admin.id])
        .map_err(|e| internal(format!("清除会话失败: {e}")))?;
    tx.commit()
        .map_err(|e| internal(format!("提交事务失败: {e}")))
}

/// Read whether an authenticated administrator must choose a new password.
pub fn password_change_required(conn: &Connection, user_id: &str) -> AppResult<bool> {
    conn.query_row(
        "SELECT must_change_password FROM admin_users WHERE id = ?1",
        [user_id],
        |r| Ok(r.get::<_, i64>(0)? != 0),
    )
    .optional()
    .map_err(|e| internal(format!("查询管理员密码状态失败: {e}")))?
    .ok_or_else(|| AppError::new(ErrorCode::Unauthorized, "会话所属管理员已不存在"))
}

/// Verify login credentials. Returns the admin on success; `None` when the
/// username does not exist, the account is disabled, or the password is wrong
/// (indistinguishable on purpose).
pub fn verify_admin_password(
    conn: &Connection,
    username: &str,
    password: &str,
) -> AppResult<Option<AdminUser>> {
    let row: Option<(AdminUser, String)> = conn
        .query_row(
            "SELECT id, username, enabled, must_change_password, created_at, password_hash \
             FROM admin_users \
             WHERE username = ?1",
            [username],
            |r| {
                Ok((
                    AdminUser {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        enabled: r.get::<_, i64>(2)? != 0,
                        must_change_password: r.get::<_, i64>(3)? != 0,
                        created_at: r.get(4)?,
                    },
                    r.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|e| internal(format!("查询管理员失败: {e}")))?;
    let Some((admin, hash)) = row else {
        return Ok(None);
    };
    if !admin.enabled || !verify_password(password, &hash)? {
        return Ok(None);
    }
    Ok(Some(admin))
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use crate::store::migrate::{CONTROL_MIGRATIONS, apply};

    use super::super::{create_session, delete_admin, lookup_session, revoke_all_user_sessions};
    use super::*;

    const PW: &str = "a very long password";

    fn test_conn() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        conn
    }

    #[test]
    fn create_and_list_admins() {
        let conn = test_conn();
        let a = create_admin(&conn, "admin_1", PW).unwrap();
        assert!(a.enabled);
        assert!(!a.must_change_password);
        create_admin(&conn, "ops.user-2", PW).unwrap();
        let all = list_admins(&conn).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].username, "admin_1");
        assert!(!all[0].must_change_password);
    }

    #[test]
    fn rejects_invalid_username_and_short_password() {
        let conn = test_conn();
        let e = create_admin(&conn, "bad name!", PW).unwrap_err();
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        let e = create_admin(&conn, "", PW).unwrap_err();
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        let e = create_admin(&conn, &"x".repeat(65), PW).unwrap_err();
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        let e = create_admin(&conn, "ok_user", "short").unwrap_err();
        assert_eq!(e.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn user_supplied_passwords_require_eight_characters() {
        let mut conn = test_conn();
        let e = create_admin(&conn, "admin", "1234567").unwrap_err();
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        create_admin(&conn, "admin", "12345678").unwrap();
        let e = reset_password(&mut conn, "admin", "1234567").unwrap_err();
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        reset_password(&mut conn, "admin", "12345678").unwrap();
    }

    #[test]
    fn rejects_duplicate_username() {
        let conn = test_conn();
        create_admin(&conn, "admin", PW).unwrap();
        let e = create_admin(&conn, "admin", PW).unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);
    }

    #[test]
    fn verify_admin_password_ok_and_fail() {
        let conn = test_conn();
        create_admin(&conn, "admin", PW).unwrap();
        assert!(verify_admin_password(&conn, "admin", PW).unwrap().is_some());
        assert!(
            verify_admin_password(&conn, "admin", "wrong password!")
                .unwrap()
                .is_none()
        );
        assert!(verify_admin_password(&conn, "ghost", PW).unwrap().is_none());
    }

    #[test]
    fn disabled_admin_cannot_login() {
        let conn = test_conn();
        create_admin(&conn, "admin", PW).unwrap();
        create_admin(&conn, "second", PW).unwrap();
        set_enabled(&conn, "second", false).unwrap();
        assert!(
            verify_admin_password(&conn, "second", PW)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn last_admin_cannot_be_disabled_or_deleted() {
        let conn = test_conn();
        create_admin(&conn, "admin", PW).unwrap();
        let e = set_enabled(&conn, "admin", false).unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);
        let e = delete_admin(&conn, "admin").unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);
        // Still exactly one enabled admin.
        let all = list_admins(&conn).unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].enabled);
    }

    #[test]
    fn with_two_admins_disable_and_delete_work() {
        let conn = test_conn();
        create_admin(&conn, "admin", PW).unwrap();
        create_admin(&conn, "second", PW).unwrap();
        set_enabled(&conn, "admin", false).unwrap();
        // "admin" is now disabled; deleting it is fine, and deleting the last
        // *enabled* admin ("second") is still refused.
        delete_admin(&conn, "admin").unwrap();
        let e = delete_admin(&conn, "second").unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);
        let e = set_enabled(&conn, "second", false).unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);
    }

    #[test]
    fn disable_and_delete_revoke_sessions() {
        let conn = test_conn();
        let a = create_admin(&conn, "admin", PW).unwrap();
        create_admin(&conn, "second", PW).unwrap();
        let (token, _) = create_session(&conn, &a.id, 30, 24).unwrap();
        assert!(lookup_session(&conn, &token).unwrap().is_some());
        set_enabled(&conn, "admin", false).unwrap();
        assert!(lookup_session(&conn, &token).unwrap().is_none());

        let b = create_admin(&conn, "third", PW).unwrap();
        let (token2, _) = create_session(&conn, &b.id, 30, 24).unwrap();
        delete_admin(&conn, "third").unwrap();
        assert!(lookup_session(&conn, &token2).unwrap().is_none());
    }

    #[test]
    fn reset_password_revokes_sessions() {
        let mut conn = test_conn();
        let a = create_admin(&conn, "admin", PW).unwrap();
        let (t1, _) = create_session(&conn, &a.id, 30, 24).unwrap();
        let (t2, _) = create_session(&conn, &a.id, 30, 24).unwrap();
        reset_password(&mut conn, "admin", "a brand new password").unwrap();
        assert!(lookup_session(&conn, &t1).unwrap().is_none());
        assert!(lookup_session(&conn, &t2).unwrap().is_none());
        assert!(verify_admin_password(&conn, "admin", PW).unwrap().is_none());
        assert!(
            verify_admin_password(&conn, "admin", "a brand new password")
                .unwrap()
                .is_some()
        );
        let e = reset_password(&mut conn, "ghost", "a brand new password").unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
    }

    #[test]
    fn reset_password_clears_first_change_flag() {
        let mut conn = test_conn();
        let admin = insert_default_admin(&conn).unwrap();
        let (token, _) = create_session(&conn, &admin.id, 30, 24).unwrap();
        assert!(password_change_required(&conn, &admin.id).unwrap());

        reset_password(&mut conn, "admin", "new-admin-password").unwrap();

        assert!(!password_change_required(&conn, &admin.id).unwrap());
        assert!(lookup_session(&conn, &token).unwrap().is_none());
        let logged_in = verify_admin_password(&conn, "admin", "new-admin-password")
            .unwrap()
            .unwrap();
        assert!(!logged_in.must_change_password);
    }

    #[test]
    fn revoke_all_user_sessions_counts_rows() {
        let conn = test_conn();
        let a = create_admin(&conn, "admin", PW).unwrap();
        create_session(&conn, &a.id, 30, 24).unwrap();
        create_session(&conn, &a.id, 30, 24).unwrap();
        assert_eq!(revoke_all_user_sessions(&conn, &a.id).unwrap(), 2);
        assert_eq!(revoke_all_user_sessions(&conn, &a.id).unwrap(), 0);
    }
}
