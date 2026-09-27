//! Deployment configuration (config_version=2) parsing and strict validation.
//!
//! The deployment YAML defines only the security boundary: listen address,
//! data dir, approved mounts, write switch, resource limits, trusted proxies,
//! default timezone. Unknown fields are hard errors (never silently ignored);
//! v1 memory-limit fields are rejected with an explicit migration hint.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{AppError, AppResult, ErrorCode};

#[derive(Debug, Clone)]
pub struct DeploymentConfig {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub approved_mounts: Vec<ApprovedMount>,
    pub security: SecurityConfig,
    pub resources: ResourceConfig,
    pub sampling: SamplingConfig,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub default_timezone: jiff::tz::TimeZone,
    pub default_timezone_name: String,
    pub trusted_proxy_cidrs: Vec<ipnet::IpNet>,
    pub allow_insecure_lan_http: bool,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub approved_output_roots: Vec<PathBuf>,
    pub data_budget_bytes: u64,
    pub hash_cache_budget_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct ApprovedMount {
    pub key: String,
    pub container_path: PathBuf,
    pub writable: bool,
    pub allow_submounts: bool,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub allow_write_operations: bool,
    pub session_idle_minutes: u32,
    pub session_absolute_hours: u32,
    pub reauth_minutes: u32,
}

#[derive(Debug, Clone)]
pub struct ResourceConfig {
    pub max_running_scans: u32,
    pub max_queued_scans: u32,
    pub metadata_workers: u32,
    pub hash_workers: u32,
    pub hash_read_limit_mib_s: u32,
    pub max_open_files: u32,
    /// Soft budget/pressure threshold, MiB. NOT a hard RSS limit; the
    /// container cgroup provides the hard limit (spec 15.9).
    pub api_memory_budget_mib: u32,
    pub worker_memory_budget_mib: u32,
    pub max_parallel_exports: u32,
}

#[derive(Debug, Clone)]
pub struct SamplingConfig {
    pub interval_minutes: u32,
    pub raw_retention_days: u32,
    pub daily_retention_days: u32,
}

// ---- raw serde shape with strict unknown-field rejection ----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    config_version: u32,
    server: RawServer,
    storage: RawStorage,
    approved_mounts: Vec<RawMount>,
    security: RawSecurity,
    resources: RawResources,
    sampling: RawSampling,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    listen: String,
    default_timezone: String,
    trusted_proxy_cidrs: Vec<String>,
    allow_insecure_lan_http: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStorage {
    data_dir: String,
    approved_output_roots: Vec<String>,
    data_budget_bytes: String,
    hash_cache_budget_bytes: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMount {
    key: String,
    container_path: String,
    writable: bool,
    allow_submounts: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecurity {
    allow_write_operations: bool,
    session_idle_minutes: u32,
    session_absolute_hours: u32,
    reauth_minutes: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResources {
    max_running_scans: u32,
    max_queued_scans: u32,
    metadata_workers: u32,
    hash_workers: u32,
    hash_read_limit_mib_s: u32,
    max_open_files: u32,
    api_memory_budget_mib: u32,
    worker_memory_budget_mib: u32,
    max_parallel_exports: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSampling {
    interval_minutes: u32,
    raw_retention_days: u32,
    daily_retention_days: u32,
}

fn validation_err(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, msg)
}

fn parse_decimal_u64(field: &str, raw: &str) -> AppResult<u64> {
    if raw.is_empty()
        || raw.len() > 20
        || !raw.bytes().all(|b| b.is_ascii_digit())
        || (raw.len() > 1 && raw.starts_with('0'))
    {
        return Err(validation_err(format!(
            "{field} must be a non-negative decimal string without leading zeros, got {raw:?}"
        )));
    }
    raw.parse::<u64>()
        .map_err(|_| validation_err(format!("{field} out of range: {raw:?}")))
}

impl DeploymentConfig {
    pub fn from_yaml_str(text: &str) -> AppResult<Self> {
        // Reject v1-only fields up front with an actionable migration hint;
        // serde's unknown-field error text is less helpful for this case.
        let generic: serde_yaml::Value = serde_yaml::from_str(text)
            .map_err(|e| validation_err(format!("YAML parse error: {e}")))?;
        if let Some(v) = generic.get("config_version").and_then(|v| v.as_u64())
            && v == 1
        {
            return Err(validation_err(
                "config_version=1 is not supported: migrate to v2 — rename \
                 api_memory_limit_mib/worker_memory_limit_mib to \
                 api_memory_budget_mib/worker_memory_budget_mib (soft budgets, \
                 not RSS hard limits) and set config_version: 2",
            ));
        }
        for section in ["resources"] {
            if let Some(res) = generic.get(section).and_then(|v| v.as_mapping()) {
                for legacy in ["api_memory_limit_mib", "worker_memory_limit_mib"] {
                    if res.contains_key(serde_yaml::Value::String(legacy.into())) {
                        return Err(validation_err(format!(
                            "unknown v1 field {section}.{legacy}: rename to the v2 budget \
                             field (api_memory_budget_mib / worker_memory_budget_mib)"
                        )));
                    }
                }
            }
        }
        let raw: RawConfig = serde_yaml::from_value(generic)
            .map_err(|e| validation_err(format!("config validation error: {e}")))?;
        Self::from_raw(raw)
    }

    pub fn from_file(path: &Path) -> AppResult<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| validation_err(format!("cannot read config {}: {e}", path.display())))?;
        Self::from_yaml_str(&text)
    }

    fn from_raw(raw: RawConfig) -> AppResult<Self> {
        if raw.config_version != 2 {
            return Err(validation_err(format!(
                "config_version must be 2, got {}",
                raw.config_version
            )));
        }
        let listen: SocketAddr = raw.server.listen.parse().map_err(|_| {
            validation_err(format!(
                "server.listen is not a valid socket address: {:?}",
                raw.server.listen
            ))
        })?;
        let tz: jiff::tz::TimeZone = jiff::tz::TimeZone::get(&raw.server.default_timezone)
            .map_err(|_| {
                validation_err(format!(
                    "server.default_timezone is not a known IANA timezone: {:?}",
                    raw.server.default_timezone
                ))
            })?;
        let mut cidrs = Vec::new();
        for c in &raw.server.trusted_proxy_cidrs {
            cidrs.push(
                c.parse::<ipnet::IpNet>()
                    .map_err(|_| validation_err(format!("invalid trusted proxy CIDR: {c:?}")))?,
            );
        }

        let mut mounts = Vec::new();
        let mut seen_keys = std::collections::HashSet::new();
        for m in &raw.approved_mounts {
            if m.key.is_empty()
                || m.key.len() > 64
                || !m.key.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
                || !m
                    .key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
            {
                return Err(validation_err(format!(
                    "approved_mounts key must match ^[a-z][a-z0-9_-]{{0,63}}$: {:?}",
                    m.key
                )));
            }
            if !seen_keys.insert(m.key.clone()) {
                return Err(validation_err(format!("duplicate mount key: {:?}", m.key)));
            }
            if !m.container_path.starts_with('/') {
                return Err(validation_err(format!(
                    "mount {:?} container_path must be absolute",
                    m.key
                )));
            }
            if m.allow_submounts {
                return Err(validation_err(format!(
                    "mount {:?}: allow_submounts is fixed false in V1; register submounts as separate approved sources",
                    m.key
                )));
            }
            mounts.push(ApprovedMount {
                key: m.key.clone(),
                container_path: PathBuf::from(&m.container_path),
                writable: m.writable,
                allow_submounts: m.allow_submounts,
            });
        }
        if mounts.is_empty() {
            return Err(validation_err("at least one approved mount is required"));
        }

        let sec = &raw.security;
        if !(5..=1440).contains(&sec.session_idle_minutes) {
            return Err(validation_err(
                "security.session_idle_minutes must be 5..=1440",
            ));
        }
        if !(1..=168).contains(&sec.session_absolute_hours) {
            return Err(validation_err(
                "security.session_absolute_hours must be 1..=168",
            ));
        }
        if !(1..=5).contains(&sec.reauth_minutes) {
            return Err(validation_err("security.reauth_minutes must be 1..=5"));
        }

        let r = &raw.resources;
        if r.max_running_scans != 1 {
            return Err(validation_err(
                "resources.max_running_scans is fixed at 1 in V1",
            ));
        }
        if !(1..=100).contains(&r.max_queued_scans) {
            return Err(validation_err("resources.max_queued_scans must be 1..=100"));
        }
        if !(1..=8).contains(&r.metadata_workers) {
            return Err(validation_err("resources.metadata_workers must be 1..=8"));
        }
        if !(1..=4).contains(&r.hash_workers) {
            return Err(validation_err("resources.hash_workers must be 1..=4"));
        }
        if r.hash_read_limit_mib_s > 10000 {
            return Err(validation_err(
                "resources.hash_read_limit_mib_s must be 0..=10000 (0 = unlimited)",
            ));
        }
        if !(16..=1024).contains(&r.max_open_files) {
            return Err(validation_err("resources.max_open_files must be 16..=1024"));
        }
        if !(64..=4096).contains(&r.api_memory_budget_mib) {
            return Err(validation_err(
                "resources.api_memory_budget_mib must be 64..=4096",
            ));
        }
        if !(128..=16384).contains(&r.worker_memory_budget_mib) {
            return Err(validation_err(
                "resources.worker_memory_budget_mib must be 128..=16384",
            ));
        }
        if !(1..=4).contains(&r.max_parallel_exports) {
            return Err(validation_err(
                "resources.max_parallel_exports must be 1..=4",
            ));
        }

        let s = &raw.sampling;
        if !(15..=1440).contains(&s.interval_minutes) {
            return Err(validation_err(
                "sampling.interval_minutes must be 15..=1440",
            ));
        }
        if !(1..=3650).contains(&s.raw_retention_days) {
            return Err(validation_err(
                "sampling.raw_retention_days must be 1..=3650",
            ));
        }
        if !(1..=36500).contains(&s.daily_retention_days) {
            return Err(validation_err(
                "sampling.daily_retention_days must be 1..=36500",
            ));
        }

        let data_dir = PathBuf::from(&raw.storage.data_dir);
        if !raw.storage.data_dir.starts_with('/') {
            return Err(validation_err("storage.data_dir must be absolute"));
        }
        let mut outputs = Vec::new();
        for o in &raw.storage.approved_output_roots {
            if !o.starts_with('/') {
                return Err(validation_err(format!(
                    "approved output root must be absolute: {o:?}"
                )));
            }
            outputs.push(PathBuf::from(o));
        }
        if outputs.is_empty() {
            return Err(validation_err(
                "at least one approved output root is required",
            ));
        }

        Ok(Self {
            server: ServerConfig {
                listen,
                default_timezone: tz,
                default_timezone_name: raw.server.default_timezone,
                trusted_proxy_cidrs: cidrs,
                allow_insecure_lan_http: raw.server.allow_insecure_lan_http,
            },
            storage: StorageConfig {
                data_dir,
                approved_output_roots: outputs,
                data_budget_bytes: parse_decimal_u64(
                    "storage.data_budget_bytes",
                    &raw.storage.data_budget_bytes,
                )?,
                hash_cache_budget_bytes: parse_decimal_u64(
                    "storage.hash_cache_budget_bytes",
                    &raw.storage.hash_cache_budget_bytes,
                )?,
            },
            approved_mounts: mounts,
            security: SecurityConfig {
                allow_write_operations: sec.allow_write_operations,
                session_idle_minutes: sec.session_idle_minutes,
                session_absolute_hours: sec.session_absolute_hours,
                reauth_minutes: sec.reauth_minutes,
            },
            resources: ResourceConfig {
                max_running_scans: r.max_running_scans,
                max_queued_scans: r.max_queued_scans,
                metadata_workers: r.metadata_workers,
                hash_workers: r.hash_workers,
                hash_read_limit_mib_s: r.hash_read_limit_mib_s,
                max_open_files: r.max_open_files,
                api_memory_budget_mib: r.api_memory_budget_mib,
                worker_memory_budget_mib: r.worker_memory_budget_mib,
                max_parallel_exports: r.max_parallel_exports,
            },
            sampling: SamplingConfig {
                interval_minutes: s.interval_minutes,
                raw_retention_days: s.raw_retention_days,
                daily_retention_days: s.daily_retention_days,
            },
        })
    }

    /// Semantic checks beyond field syntax (contracts/README.md).
    pub fn validate_semantics(&self) -> AppResult<()> {
        // A writable mount while the global write switch is off is allowed
        // (per-source gate), but writes with allow_write_operations=false are
        // refused at runtime; warn only via diagnostics, not an error here.
        for m in &self.approved_mounts {
            if m.container_path.starts_with(&self.storage.data_dir)
                && m.container_path != self.storage.data_dir
                || self.storage.data_dir.starts_with(&m.container_path)
            {
                return Err(validation_err(format!(
                    "mount {:?} path overlaps data_dir; the app database must not live inside a scanned source",
                    m.key
                )));
            }
        }
        Ok(())
    }

    pub fn mount(&self, key: &str) -> Option<&ApprovedMount> {
        self.approved_mounts.iter().find(|m| m.key == key)
    }
}

#[cfg(test)]
mod tests;
