//! Argon2id password hashing (spec 14.1). Parameters are persisted alongside
//! the encoded hash so future parameter upgrades can be detected.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::AppResult;

use super::internal;

/// Argon2id parameters persisted in `admin_users.password_params_json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism.
    pub p_cost: u32,
}

/// Production defaults: 64 MiB memory, 3 iterations, parallelism 1.
pub fn default_password_params() -> PasswordParams {
    PasswordParams {
        m_cost: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    }
}

fn argon2_with(params: PasswordParams) -> AppResult<Argon2<'static>> {
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, None)
        .map_err(|_| internal("无效的密码散列参数"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, p))
}

/// Hash `password` with the current default parameters.
/// Returns `(encoded_hash, params_json)` for storage in `admin_users`.
pub fn hash_password(password: &str) -> AppResult<(String, String)> {
    let params = default_password_params();
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| internal("生成盐失败"))?;
    let encoded = argon2_with(params)?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| internal("密码散列计算失败"))?
        .to_string();
    let params_json =
        serde_json::to_string(&params).map_err(|e| internal(format!("序列化密码参数失败: {e}")))?;
    Ok((encoded, params_json))
}

/// Constant-time verification of `password` against an encoded Argon2id hash.
/// The parameters are read from the encoded hash itself.
pub fn verify_password(password: &str, encoded_hash: &str) -> AppResult<bool> {
    let parsed = PasswordHash::new(encoded_hash).map_err(|_| internal("存储的密码散列格式损坏"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Whether stored parameters differ from the current defaults, i.e. the hash
/// should be recomputed on next successful login. Unparseable stored params
/// count as needing an upgrade.
pub fn password_needs_upgrade(params_json: &str) -> bool {
    match serde_json::from_str::<PasswordParams>(params_json) {
        Ok(stored) => stored != default_password_params(),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    #[test]
    fn hash_and_verify_roundtrip() {
        let (encoded, params_json) = hash_password("correct horse battery staple").unwrap();
        assert!(encoded.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery staple", &encoded).unwrap());
        assert!(!verify_password("wrong password 1234", &encoded).unwrap());
        assert!(!password_needs_upgrade(&params_json));
    }

    #[test]
    fn detects_parameter_upgrade() {
        let old = serde_json::to_string(&PasswordParams {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
        })
        .unwrap();
        assert!(password_needs_upgrade(&old));
        assert!(password_needs_upgrade("not json"));
    }

    #[test]
    fn rejects_corrupt_hash() {
        assert!(
            verify_password("whatever12345", "not-a-hash")
                .unwrap_err()
                .code
                == ErrorCode::Internal
        );
    }
}
