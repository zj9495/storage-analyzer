//! Audit trail (spec 14, 18.5; F18). Append-only events with secret redaction.
//!
//! Rules: never store passwords, session/reauth tokens, SMTP secrets or the
//! master key; file paths only in admin-visible audit/error detail, and
//! display-form only (no host paths outside approved mounts).

use rusqlite::Connection;
use serde::Serialize;

use crate::error::AppError;
use crate::error::{AppResult, ErrorCode};

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub id: String,
    pub actor: String,
    pub action: String,
    pub resource: Option<String>,
    pub result: String,
    pub request_id: Option<String>,
    pub redacted_detail: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct AuditListFilter {
    pub actor_id: Option<String>,
    pub action: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub cursor: Option<String>,
}

/// Substrings that must never reach audit detail.
const SECRET_MARKERS: &[&str] = &[
    "password",
    "token",
    "secret",
    "smtp_pass",
    "master_key",
    "session",
];

/// Best-effort redaction: fields whose key contains a secret marker are
/// replaced with "<redacted>". Applied to JSON values before persistence.
pub fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                let kl = k.to_ascii_lowercase();
                if SECRET_MARKERS.iter().any(|m| kl.contains(m)) {
                    *v = serde_json::Value::String("<redacted>".into());
                } else {
                    redact_json(v);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for v in items.iter_mut() {
                redact_json(v);
            }
        }
        _ => {}
    }
}

pub fn record(
    conn: &Connection,
    actor: &str,
    action: &str,
    resource: Option<&str>,
    result: &str,
    request_id: Option<&str>,
    detail: Option<serde_json::Value>,
) -> AppResult<String> {
    let mut detail = detail;
    if let Some(d) = detail.as_mut() {
        redact_json(d);
    }
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO audit_events (id, actor, action, resource, result, request_id, redacted_detail, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            id,
            actor,
            action,
            resource,
            result,
            request_id,
            detail.map(|d| d.to_string()),
            crate::auth::now_rfc3339(),
        ],
    )
    .map_err(|e| internal(format!("insert audit event: {e}")))?;
    Ok(id)
}

/// Paginated listing, newest first. Cursor = "created_at|id" base64.
pub fn list(
    conn: &Connection,
    cursor: Option<&str>,
    page_size: u32,
) -> AppResult<(Vec<AuditEvent>, Option<String>)> {
    list_filtered(
        conn,
        &AuditListFilter {
            cursor: cursor.map(str::to_owned),
            ..AuditListFilter::default()
        },
        page_size,
    )
}

pub fn list_filtered(
    conn: &Connection,
    filter: &AuditListFilter,
    page_size: u32,
) -> AppResult<(Vec<AuditEvent>, Option<String>)> {
    let page_size = page_size.clamp(1, 200);
    let (cursor_created, cursor_id) = match filter.cursor.as_deref() {
        Some(c) => {
            let decoded =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, c)
                    .map_err(|_| AppError::new(ErrorCode::BadRequest, "无效的游标"))?;
            let value = String::from_utf8(decoded)
                .map_err(|_| AppError::new(ErrorCode::BadRequest, "无效的游标"))?;
            let (created, id) = value
                .split_once('|')
                .ok_or_else(|| AppError::new(ErrorCode::BadRequest, "无效的游标"))?;
            (Some(created.to_owned()), Some(id.to_owned()))
        }
        None => (None, None),
    };
    let sql = String::from(
        "SELECT id, actor, action, resource, result, request_id, redacted_detail, created_at
         FROM audit_events
         WHERE (?1 IS NULL OR actor = ?1)
           AND (?2 IS NULL OR action = ?2)
           AND (?3 IS NULL OR created_at >= ?3)
           AND (?4 IS NULL OR created_at < ?4)
           AND (?5 IS NULL OR created_at < ?5 OR (created_at = ?5 AND id < ?6))
         ORDER BY created_at DESC, id DESC LIMIT ?7",
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| internal(format!("prepare audit list: {e}")))?;
    let rows = stmt
        .query_map(
            rusqlite::params![
                filter.actor_id.as_deref(),
                filter.action.as_deref(),
                filter.from.as_deref(),
                filter.to.as_deref(),
                cursor_created.as_deref(),
                cursor_id.as_deref(),
                (page_size + 1) as i64,
            ],
            |r| {
                Ok(AuditEvent {
                    id: r.get(0)?,
                    actor: r.get(1)?,
                    action: r.get(2)?,
                    resource: r.get(3)?,
                    result: r.get(4)?,
                    request_id: r.get(5)?,
                    redacted_detail: r.get(6)?,
                    created_at: r.get(7)?,
                })
            },
        )
        .map_err(|e| internal(format!("query audit: {e}")))?;
    let mut events = Vec::new();
    for row in rows {
        events.push(row.map_err(|e| internal(format!("row: {e}")))?);
    }
    let next = if events.len() > page_size as usize {
        let last = events.pop().expect("nonempty");
        use base64::Engine;
        Some(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(format!("{}|{}", last.created_at, last.id)),
        )
    } else {
        None
    };
    Ok((events, next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::migrate;

    fn db() -> rusqlite::Connection {
        let mut c = rusqlite::Connection::open_in_memory().unwrap();
        migrate::apply(&mut c, migrate::CONTROL_MIGRATIONS).unwrap();
        c
    }

    #[test]
    fn record_and_list_with_cursor() {
        let conn = db();
        for i in 0..5 {
            record(
                &conn,
                "admin",
                &format!("action_{i}"),
                Some("source:1"),
                "ok",
                Some("req-1"),
                None,
            )
            .unwrap();
        }
        let (page1, next) = list(&conn, None, 2).unwrap();
        assert_eq!(page1.len(), 2);
        assert!(next.is_some());
        let (page2, _) = list(&conn, next.as_deref(), 2).unwrap();
        assert_eq!(page2.len(), 2);
        assert_ne!(page1[0].id, page2[0].id);
    }

    #[test]
    fn secrets_are_redacted() {
        let conn = db();
        let detail = serde_json::json!({
            "username": "admin",
            "password": "supersecret",
            "nested": {"smtp_pass": "abc", "note": "ok"},
            "session_token": "xyz"
        });
        let id = record(&conn, "admin", "login", None, "ok", None, Some(detail)).unwrap();
        let (events, _) = list(&conn, None, 10).unwrap();
        let ev = events.iter().find(|e| e.id == id).unwrap();
        let d = ev.redacted_detail.as_ref().unwrap();
        assert!(!d.contains("supersecret"));
        assert!(!d.contains("abc"));
        assert!(!d.contains("xyz"));
        assert!(d.contains("\"note\":\"ok\""));
        assert!(d.contains("<redacted>"));
    }
}
