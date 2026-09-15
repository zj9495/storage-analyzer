//! Authentication and session management (spec 3.3, 14.1).
//!
//! Covers Argon2id password hashing with persisted parameters, admin account
//! CRUD with last-admin protection, one-time setup tokens, opaque session
//! tokens (only SHA-256 digests stored), single-use re-authentication tokens
//! and an in-process login rate limiter.
//!
//! All functions are synchronous and operate directly on a
//! [`rusqlite::Connection`]; callers run them inside the store writer thread.

mod admin;
mod password;
mod ratelimit;
mod reauth;
mod session;
mod setup;

pub use admin::{
    AdminUser, create_admin, delete_admin, list_admins, reset_password, set_enabled,
    verify_admin_password,
};
pub use password::{
    PasswordParams, default_password_params, hash_password, password_needs_upgrade, verify_password,
};
pub use ratelimit::RateLimiter;
pub use reauth::{consume_reauth_token, create_reauth_token};
pub use session::{
    Session, create_session, lookup_session, revoke_all_user_sessions, revoke_session,
};
pub use setup::{complete_setup, consume_setup_token, generate_setup_token, is_initialized};

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult, ErrorCode};

pub(crate) fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

/// Current time as an RFC3339 string (the storage format for all timestamps).
pub fn now_rfc3339() -> String {
    now_ts().to_string()
}

/// RFC3339 timestamp `minutes` into the future (negative values allowed).
pub fn rfc3339_plus_minutes(minutes: i64) -> String {
    ts_plus_secs(minutes.saturating_mul(60)).to_string()
}

/// RFC3339 timestamp `hours` into the future (negative values allowed).
pub fn rfc3339_plus_hours(hours: i64) -> String {
    ts_plus_secs(hours.saturating_mul(3600)).to_string()
}

pub(crate) fn now_ts() -> jiff::Timestamp {
    jiff::Timestamp::now()
}

pub(crate) fn ts_plus_secs(secs: i64) -> jiff::Timestamp {
    now_ts()
        .checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap_or_else(|_| jiff::Timestamp::now())
}

pub(crate) fn parse_ts(s: &str) -> AppResult<jiff::Timestamp> {
    s.parse::<jiff::Timestamp>()
        .map_err(|_| internal("数据库中的时间戳格式损坏"))
}

/// 32 bytes of OS randomness, hex-encoded (64 chars).
pub(crate) fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 digest of a plaintext token, hex-encoded. Only this is stored.
pub(crate) fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
