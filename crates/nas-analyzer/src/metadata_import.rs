//! Metadata import: identity mappings, source↔volume links and quota records
//! (spec 4.4, F07 quota, F16 links; contract
//! `docs/design/contracts/metadata-import.schema.json`).
//!
//! Two-phase flow: [`preview_import`] validates the payload (embedded JSON
//! Schema draft 2020-12 plus the semantic rules from `contracts/README.md`),
//! persists it into `metadata_imports` with state `preview` and writes nothing
//! else. [`apply_import`] verifies the caller-supplied digest against the
//! stored payload (tamper check), re-validates against current DB state and
//! applies everything in one transaction.
//!
//! Invariants:
//! - Applying a source↔volume link updates only `sources.volume_id`; it never
//!   touches `identity_status` / `identity_epoch` — re-confirming a source
//!   identity is a separate explicit action.
//! - Imports cannot create approved mounts: the payload has no such field and
//!   no code path here writes deployment configuration.
//! - Quota limit `0` is a valid limit (zero quota); usage must never divide
//!   by it. `used_bytes = null` means "provider did not report", not zero.
//! - Unknown quota state is returned as-is; absence of records yields `None`,
//!   never a fabricated "unlimited".

use std::collections::HashMap;
use std::sync::OnceLock;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth;
use crate::error::{AppError, AppResult, ErrorCode};

/// Default size cap for one import payload (10 MiB).
pub const DEFAULT_MAX_IMPORT_BYTES: usize = 10 * 1024 * 1024;

const SCHEMA_JSON: &str =
    include_str!("../../../docs/design/contracts/metadata-import.schema.json");

fn validation(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, msg)
}

fn conflict(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Conflict, msg)
}

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

fn schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: serde_json::Value =
            serde_json::from_str(SCHEMA_JSON).expect("embedded schema must be valid JSON");
        jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .expect("embedded schema must compile")
    })
}

/// A non-fatal finding or a validation issue attached to a payload location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportIssue {
    /// Stable machine-readable kind, e.g. `zero_limit`, `stale_in_file`.
    pub kind: String,
    /// Location inside the payload, e.g. `quotas[0].limit.bytes`.
    pub path: String,
    /// Chinese user-facing message.
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ImportCounts {
    pub identities: usize,
    pub links: usize,
    pub quotas: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ImportDiffSummary {
    pub identities_added: usize,
    pub identities_updated: usize,
    pub quotas_added: usize,
    pub quotas_updated: usize,
}

/// Result of [`preview_import`]. `errors` is always empty on success:
/// payloads with validation problems are rejected with 422 instead.
#[derive(Debug, Clone, Serialize)]
pub struct ImportPreview {
    pub preview_id: String,
    /// SHA-256 (hex) of the exact payload bytes; required for apply.
    pub digest: String,
    pub counts: ImportCounts,
    pub diff_summary: ImportDiffSummary,
    pub warnings: Vec<ImportIssue>,
    pub errors: Vec<ImportIssue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplySummary {
    pub import_id: String,
    pub identities_upserted: usize,
    /// Existing mappings whose display_name changed (audit-worthy).
    pub identities_renamed: usize,
    pub links_applied: usize,
    pub quotas_inserted: usize,
    pub notes: Vec<String>,
}

/// The effective quota for one principal/scope/metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveQuota {
    pub origin: String,
    pub limit_state: String,
    /// Decimal string; `None` unless `limit_state == "known"`.
    pub limit_bytes: Option<String>,
    /// Decimal string; `None` means the provider did not report usage.
    pub used_bytes: Option<String>,
    pub observed_at: String,
    pub expires_at: Option<String>,
    pub provider_label: String,
    /// True when the record is past `expires_at` (returned for display only).
    pub stale: bool,
}

#[derive(Debug, Deserialize)]
struct Payload {
    provider_label: String,
    identities: Vec<IdentityIn>,
    source_links: Vec<LinkIn>,
    quotas: Vec<QuotaIn>,
}

#[derive(Debug, Deserialize)]
struct IdentityIn {
    namespace: String,
    uid: u32,
    gid: Option<u32>,
    display_name: String,
    observed_at: String,
}

#[derive(Debug, Deserialize)]
struct LinkIn {
    source_id: String,
    volume_id: String,
}

#[derive(Debug, Deserialize)]
struct PrincipalIn {
    namespace: String,
    uid: u32,
}

#[derive(Debug, Deserialize)]
struct ScopeIn {
    kind: String,
    id: String,
}

#[derive(Debug, Deserialize)]
struct LimitIn {
    state: String,
    bytes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QuotaIn {
    principal: PrincipalIn,
    scope: ScopeIn,
    metric: String,
    origin: String,
    limit: LimitIn,
    used_bytes: Option<String>,
    observed_at: String,
    expires_at: Option<String>,
    provider_label: String,
}

fn issue(kind: &str, path: String, message: String) -> ImportIssue {
    ImportIssue {
        kind: kind.to_string(),
        path,
        message,
    }
}

fn issues_error(errors: Vec<ImportIssue>) -> AppError {
    let first = errors
        .first()
        .map(|e| format!("{}: {}", e.path, e.message))
        .unwrap_or_default();
    validation(format!("导入内容未通过语义校验：{first}"))
        .with_details(serde_json::json!({ "errors": errors }))
}

fn parse_decimal_u64(raw: &str, path: &str, errors: &mut Vec<ImportIssue>) -> Option<u64> {
    match raw.parse::<u64>() {
        Ok(v) => Some(v),
        Err(_) => {
            errors.push(issue(
                "bytes_range",
                path.to_string(),
                format!("十进制字节数超出 u64 可表示范围：{raw}"),
            ));
            None
        }
    }
}

fn row_exists(conn: &Connection, table: &str, id: &str) -> AppResult<bool> {
    // `table` is only ever a literal from this module.
    let sql = format!("SELECT 1 FROM {table} WHERE id = ?1");
    conn.query_row(&sql, params![id], |_| Ok(true))
        .optional()
        .map(|o| o.unwrap_or(false))
        .map_err(|e| internal(format!("校验 {table} 存在性失败: {e}")))
}

/// Schema validation (draft 2020-12, formats asserted) followed by typed
/// deserialization and the semantic rules from contracts/README.md.
fn parse_and_validate(
    conn: &Connection,
    payload_bytes: &[u8],
    max_bytes: usize,
) -> AppResult<(Payload, Vec<ImportIssue>)> {
    if payload_bytes.len() > max_bytes {
        return Err(AppError::new(
            ErrorCode::BadRequest,
            format!(
                "导入文件大小 {} 字节超过上限 {} 字节",
                payload_bytes.len(),
                max_bytes
            ),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(payload_bytes).map_err(|e| {
        AppError::new(
            ErrorCode::BadRequest,
            format!("导入内容不是有效的 JSON: {e}"),
        )
    })?;

    let validator = schema_validator();
    if !validator.is_valid(&value) {
        let errors: Vec<ImportIssue> = validator
            .iter_errors(&value)
            .map(|e| {
                let path = e.instance_path.to_string();
                issue(
                    "schema",
                    if path.is_empty() { "/".into() } else { path },
                    e.to_string(),
                )
            })
            .collect();
        let first = errors
            .first()
            .map(|e| format!("{}: {}", e.path, e.message))
            .unwrap_or_default();
        return Err(validation(format!("导入内容不符合元数据导入契约：{first}"))
            .with_details(serde_json::json!({ "errors": errors })));
    }

    let payload: Payload = serde_json::from_value(value)
        .map_err(|e| internal(format!("schema 已通过但反序列化失败: {e}")))?;
    let warnings = validate_semantics(conn, &payload)?;
    Ok((payload, warnings))
}

/// Semantic rules beyond JSON Schema (contracts/README.md, spec 4.4).
fn validate_semantics(conn: &Connection, p: &Payload) -> AppResult<Vec<ImportIssue>> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if p.provider_label.trim().is_empty() {
        errors.push(issue(
            "provider_label",
            "provider_label".into(),
            "provider_label 不能只包含空白字符".into(),
        ));
    }

    // Identities: trimmed display name; duplicate namespace+uid with
    // conflicting display names inside one file is rejected.
    let mut seen: HashMap<(&str, u32), (usize, &str)> = HashMap::new();
    for (i, idn) in p.identities.iter().enumerate() {
        if idn.display_name.trim().is_empty() {
            errors.push(issue(
                "display_name",
                format!("identities[{i}].display_name"),
                "显示名不能只包含空白字符".into(),
            ));
        }
        let key = (idn.namespace.as_str(), idn.uid);
        if let Some((first_idx, first_name)) = seen.get(&key) {
            if *first_name != idn.display_name {
                errors.push(issue(
                    "conflicting_display_name",
                    format!("identities[{i}]"),
                    format!(
                        "同一文件内 namespace={} uid={} 出现冲突显示名：'{}'（identities[{first_idx}]）与 '{}'",
                        idn.namespace, idn.uid, first_name, idn.display_name
                    ),
                ));
            }
        } else {
            seen.insert(key, (i, idn.display_name.as_str()));
        }
    }

    // Source links must reference existing rows (README: imported ids must
    // exist in the application).
    for (i, link) in p.source_links.iter().enumerate() {
        if !row_exists(conn, "sources", &link.source_id)? {
            errors.push(issue(
                "unknown_source",
                format!("source_links[{i}].source_id"),
                format!("引用的数据源不存在：{}", link.source_id),
            ));
        }
        if !row_exists(conn, "volumes", &link.volume_id)? {
            errors.push(issue(
                "unknown_volume",
                format!("source_links[{i}].volume_id"),
                format!("引用的卷不存在：{}", link.volume_id),
            ));
        }
    }

    let now = auth::now_ts();
    for (i, q) in p.quotas.iter().enumerate() {
        // Double-check the schema if/then rule: known => bytes present,
        // unlimited/unknown => bytes null.
        match q.limit.state.as_str() {
            "known" => match &q.limit.bytes {
                Some(raw) => {
                    if parse_decimal_u64(raw, &format!("quotas[{i}].limit.bytes"), &mut errors)
                        == Some(0)
                    {
                        warnings.push(issue(
                            "zero_limit",
                            format!("quotas[{i}].limit.bytes"),
                            "配额上限为 0（零额度）：界面应显示零额度/已超额状态，使用率计算不得除以零"
                                .into(),
                        ));
                    }
                }
                None => errors.push(issue(
                    "limit_bytes",
                    format!("quotas[{i}].limit.bytes"),
                    "limit.state=known 必须提供 bytes".into(),
                )),
            },
            "unlimited" | "unknown" => {
                if q.limit.bytes.is_some() {
                    errors.push(issue(
                        "limit_bytes",
                        format!("quotas[{i}].limit.bytes"),
                        format!("limit.state={} 时 bytes 必须为 null", q.limit.state),
                    ));
                }
            }
            other => errors.push(issue(
                "limit_state",
                format!("quotas[{i}].limit.state"),
                format!("未知的配额限制状态：{other}"),
            )),
        }
        if let Some(raw) = &q.used_bytes {
            parse_decimal_u64(raw, &format!("quotas[{i}].used_bytes"), &mut errors);
        }
        if let Some(exp) = &q.expires_at {
            match auth::parse_ts(exp) {
                Ok(ts) if ts < now => warnings.push(issue(
                    "stale_in_file",
                    format!("quotas[{i}].expires_at"),
                    format!("配额过期时间 {exp} 早于当前时间，导入后即为过期记录"),
                )),
                Ok(_) => {}
                Err(_) => errors.push(issue(
                    "expires_at",
                    format!("quotas[{i}].expires_at"),
                    format!("expires_at 不是有效的 RFC3339 时间：{exp}"),
                )),
            }
        }
        let table = match q.scope.kind.as_str() {
            "source" => "sources",
            "volume" => "volumes",
            other => {
                errors.push(issue(
                    "scope_kind",
                    format!("quotas[{i}].scope.kind"),
                    format!("未知的配额作用域类型：{other}"),
                ));
                continue;
            }
        };
        if !row_exists(conn, table, &q.scope.id)? {
            errors.push(issue(
                "unknown_scope",
                format!("quotas[{i}].scope.id"),
                format!("配额引用的{}不存在：{}", q.scope.kind, q.scope.id),
            ));
        }
    }

    if errors.is_empty() {
        Ok(warnings)
    } else {
        Err(issues_error(errors))
    }
}

fn import_diff_summary(conn: &Connection, payload: &Payload) -> AppResult<ImportDiffSummary> {
    let mut summary = ImportDiffSummary {
        identities_added: 0,
        identities_updated: 0,
        quotas_added: 0,
        quotas_updated: 0,
    };

    for identity in &payload.identities {
        let existing: Option<(Option<i64>, String, String, String)> = conn
            .query_row(
                "SELECT gid, display_name, source, observed_at
                 FROM identity_mappings WHERE namespace = ?1 AND uid = ?2",
                params![identity.namespace, i64::from(identity.uid)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|e| internal(format!("计算身份映射差异失败: {e}")))?;

        match existing {
            None => summary.identities_added += 1,
            Some((gid, display_name, source, observed_at)) => {
                let incoming_gid = identity.gid.map(i64::from);
                if gid != incoming_gid
                    || display_name != identity.display_name
                    || source != "import"
                    || observed_at != identity.observed_at
                {
                    summary.identities_updated += 1;
                }
            }
        }
    }

    for quota in &payload.quotas {
        let current = effective_quota(
            conn,
            &quota.principal.namespace,
            quota.principal.uid,
            &quota.scope.kind,
            &quota.scope.id,
            &quota.metric,
        )?;
        match current {
            None => summary.quotas_added += 1,
            Some(current) => {
                let same = current.origin == quota.origin
                    && current.limit_state == quota.limit.state
                    && current.limit_bytes == quota.limit.bytes
                    && current.used_bytes == quota.used_bytes
                    && current.observed_at == quota.observed_at
                    && current.expires_at == quota.expires_at
                    && current.provider_label == quota.provider_label;
                if !same {
                    summary.quotas_updated += 1;
                }
            }
        }
    }

    Ok(summary)
}

/// Validate a payload and persist it as a `preview` row in
/// `metadata_imports`. Writes nothing else — no identities, links or quotas.
pub fn preview_import(
    conn: &mut Connection,
    payload_bytes: &[u8],
    max_bytes: usize,
) -> AppResult<ImportPreview> {
    let (payload, warnings) = parse_and_validate(conn, payload_bytes, max_bytes)?;
    let diff_summary = import_diff_summary(conn, &payload)?;

    let digest = hex::encode(Sha256::digest(payload_bytes));
    let preview_id = uuid::Uuid::new_v4().to_string();
    let payload_text = std::str::from_utf8(payload_bytes)
        .map_err(|_| AppError::new(ErrorCode::BadRequest, "导入内容不是有效的 UTF-8"))?;
    conn.execute(
        "INSERT INTO metadata_imports (id, digest, payload_json, state, created_at) \
         VALUES (?1, ?2, ?3, 'preview', ?4)",
        params![preview_id, digest, payload_text, auth::now_rfc3339()],
    )
    .map_err(|e| internal(format!("保存导入预览失败: {e}")))?;

    Ok(ImportPreview {
        preview_id,
        digest,
        counts: ImportCounts {
            identities: payload.identities.len(),
            links: payload.source_links.len(),
            quotas: payload.quotas.len(),
        },
        diff_summary,
        warnings,
        errors: Vec::new(),
    })
}

/// Apply a previously previewed import. `digest` must equal the digest of the
/// stored payload (tamper check) and the row must still be in state
/// `preview`; a second apply is rejected with 409 Conflict（已应用）.
/// Everything is applied in one transaction.
pub fn apply_import(
    conn: &mut Connection,
    preview_id: &str,
    digest: &str,
) -> AppResult<ApplySummary> {
    let row: Option<(String, String, String)> = conn
        .query_row(
            "SELECT digest, payload_json, state FROM metadata_imports WHERE id = ?1",
            params![preview_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|e| internal(format!("读取导入记录失败: {e}")))?;
    let (stored_digest, payload_json, state) = row.ok_or_else(|| {
        AppError::new(ErrorCode::NotFound, format!("导入预览不存在：{preview_id}"))
    })?;
    if state != "preview" {
        return Err(conflict("该导入已应用，不能重复执行"));
    }
    if stored_digest != digest {
        return Err(conflict(
            "导入摘要不匹配：预览内容可能被篡改，请重新上传预览",
        ));
    }

    // Re-validate against current DB state before writing anything.
    let (payload, _warnings) =
        parse_and_validate(conn, payload_json.as_bytes(), DEFAULT_MAX_IMPORT_BYTES)?;

    let mut notes = Vec::new();
    let mut identities_renamed = 0usize;

    let tx = conn
        .transaction()
        .map_err(|e| internal(format!("开启导入事务失败: {e}")))?;

    for idn in &payload.identities {
        let existing: Option<String> = tx
            .query_row(
                "SELECT display_name FROM identity_mappings WHERE namespace = ?1 AND uid = ?2",
                params![idn.namespace, i64::from(idn.uid)],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| internal(format!("读取身份映射失败: {e}")))?;
        if let Some(old) = existing
            && old != idn.display_name
        {
            identities_renamed += 1;
            notes.push(format!(
                "身份映射显示名更新：namespace={} uid={} '{}' -> '{}'（导入优先于手动映射）",
                idn.namespace, idn.uid, old, idn.display_name
            ));
        }
        tx.execute(
            "INSERT INTO identity_mappings (id, namespace, uid, gid, display_name, source, observed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'import', ?6) \
             ON CONFLICT(namespace, uid) DO UPDATE SET \
                 gid = excluded.gid, display_name = excluded.display_name, \
                 source = 'import', observed_at = excluded.observed_at",
            params![
                uuid::Uuid::new_v4().to_string(),
                idn.namespace,
                i64::from(idn.uid),
                idn.gid.map(i64::from),
                idn.display_name,
                idn.observed_at,
            ],
        )
        .map_err(|e| internal(format!("写入身份映射失败: {e}")))?;
    }

    for link in &payload.source_links {
        // Only volume_id (and updated_at) change; identity_status and
        // identity_epoch are deliberately untouched.
        let changed = tx
            .execute(
                "UPDATE sources SET volume_id = ?2, updated_at = ?3 WHERE id = ?1",
                params![link.source_id, link.volume_id, auth::now_rfc3339()],
            )
            .map_err(|e| internal(format!("更新数据源卷关联失败: {e}")))?;
        if changed == 0 {
            return Err(validation(format!(
                "引用的数据源不存在：{}",
                link.source_id
            )));
        }
    }
    if !payload.source_links.is_empty() {
        notes.push(
            "卷关联已更新；源身份状态与 identity_epoch 不受影响，身份重新确认是独立操作"
                .to_string(),
        );
    }

    for q in &payload.quotas {
        tx.execute(
            "INSERT INTO quota_records (id, principal_namespace, principal_uid, scope_kind, \
             scope_id, metric, origin, limit_state, limit_bytes, used_bytes, observed_at, \
             expires_at, provider_label, import_id, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                uuid::Uuid::new_v4().to_string(),
                q.principal.namespace,
                i64::from(q.principal.uid),
                q.scope.kind,
                q.scope.id,
                q.metric,
                q.origin,
                q.limit.state,
                q.limit.bytes,
                q.used_bytes,
                q.observed_at,
                q.expires_at,
                q.provider_label,
                preview_id,
                auth::now_rfc3339(),
            ],
        )
        .map_err(|e| internal(format!("写入配额记录失败: {e}")))?;
    }

    let changed = tx
        .execute(
            "UPDATE metadata_imports SET state = 'applied', applied_at = ?2 \
             WHERE id = ?1 AND state = 'preview'",
            params![preview_id, auth::now_rfc3339()],
        )
        .map_err(|e| internal(format!("更新导入状态失败: {e}")))?;
    if changed == 0 {
        return Err(conflict("该导入已应用，不能重复执行"));
    }
    tx.commit()
        .map_err(|e| internal(format!("提交导入事务失败: {e}")))?;

    Ok(ApplySummary {
        import_id: preview_id.to_string(),
        identities_upserted: payload.identities.len(),
        identities_renamed,
        links_applied: payload.source_links.len(),
        quotas_inserted: payload.quotas.len(),
        notes,
    })
}

/// Display name for one (namespace, uid), if a mapping exists.
/// `UNIQUE(namespace, uid)` guarantees at most one row; the
/// imported > manual priority is enforced at write time (an applied import
/// overwrites manual mappings). On `None` the caller falls back to
/// `uid:<n>` — this function never fabricates a name.
pub fn identity_for_uid(conn: &Connection, namespace: &str, uid: u32) -> AppResult<Option<String>> {
    conn.query_row(
        "SELECT display_name FROM identity_mappings WHERE namespace = ?1 AND uid = ?2",
        params![namespace, i64::from(uid)],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| internal(format!("查询身份映射失败: {e}")))
}

fn origin_rank(origin: &str) -> u8 {
    match origin {
        "system_imported" => 0,
        "advisory" => 1,
        _ => 2,
    }
}

/// Latest quota record for one principal/scope/metric. Non-expired records
/// win, ordered by `observed_at` (then origin: `system_imported` before
/// `advisory`, per contracts/README "多条有效配额按来源明确解决"). If every
/// record is expired the latest one is returned with `stale = true`. No
/// records → `None` (never fabricate "unlimited").
pub fn effective_quota(
    conn: &Connection,
    namespace: &str,
    uid: u32,
    scope_kind: &str,
    scope_id: &str,
    metric: &str,
) -> AppResult<Option<EffectiveQuota>> {
    let mut stmt = conn
        .prepare(
            "SELECT origin, limit_state, limit_bytes, used_bytes, observed_at, expires_at, \
             provider_label FROM quota_records \
             WHERE principal_namespace = ?1 AND principal_uid = ?2 AND scope_kind = ?3 \
               AND scope_id = ?4 AND metric = ?5",
        )
        .map_err(|e| internal(format!("查询配额记录失败: {e}")))?;
    let rows = stmt
        .query_map(
            params![namespace, i64::from(uid), scope_kind, scope_id, metric],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, String>(6)?,
                ))
            },
        )
        .map_err(|e| internal(format!("查询配额记录失败: {e}")))?;

    let now = auth::now_ts();
    let mut fresh: Vec<EffectiveQuota> = Vec::new();
    let mut stale: Vec<EffectiveQuota> = Vec::new();
    for row in rows {
        let (origin, limit_state, limit_bytes, used_bytes, observed_at, expires_at, provider) =
            row.map_err(|e| internal(format!("读取配额记录失败: {e}")))?;
        let is_stale = match &expires_at {
            Some(exp) => auth::parse_ts(exp).map(|ts| ts <= now).unwrap_or(true),
            None => false,
        };
        let q = EffectiveQuota {
            origin,
            limit_state,
            limit_bytes,
            used_bytes,
            observed_at,
            expires_at,
            provider_label: provider,
            stale: is_stale,
        };
        if is_stale {
            stale.push(q)
        } else {
            fresh.push(q)
        }
    }

    let rank = |q: &EffectiveQuota| origin_rank(&q.origin);
    fresh.sort_by(|a, b| {
        b.observed_at
            .cmp(&a.observed_at)
            .then(rank(a).cmp(&rank(b)))
    });
    stale.sort_by(|a, b| {
        b.observed_at
            .cmp(&a.observed_at)
            .then(rank(a).cmp(&rank(b)))
    });
    Ok(fresh
        .into_iter()
        .next()
        .or_else(|| stale.into_iter().next()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::migrate::{CONTROL_MIGRATIONS, apply};

    const SOURCE_ID: &str = "11111111-1111-4111-8111-111111111111";
    const VOLUME_ID: &str = "22222222-2222-4222-8222-222222222222";
    const EXAMPLE: &str =
        include_str!("../../../docs/design/contracts/metadata-import.example.json");

    fn setup() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
        conn
    }

    fn insert_volume(conn: &Connection, id: &str) {
        conn.execute(
            "INSERT INTO volumes (id, name, created_at, updated_at) \
             VALUES (?1, ?2, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')",
            params![id, format!("vol-{id}")],
        )
        .unwrap();
    }

    fn insert_source(conn: &Connection, id: &str, volume_id: Option<&str>) {
        conn.execute(
            "INSERT INTO sources (id, name, mount_key, volume_id, created_at, updated_at) \
             VALUES (?1, ?2, 'mnt', ?3, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')",
            params![id, format!("src-{id}"), volume_id],
        )
        .unwrap();
    }

    fn fixtures(conn: &Connection) {
        insert_volume(conn, VOLUME_ID);
        insert_source(conn, SOURCE_ID, None);
    }

    fn base_payload() -> serde_json::Value {
        serde_json::from_str(EXAMPLE).unwrap()
    }

    fn preview_ok(conn: &mut Connection, payload: &serde_json::Value) -> ImportPreview {
        preview_import(
            conn,
            payload.to_string().as_bytes(),
            DEFAULT_MAX_IMPORT_BYTES,
        )
        .unwrap()
    }

    fn preview_err(conn: &mut Connection, payload: &serde_json::Value) -> AppError {
        preview_import(
            conn,
            payload.to_string().as_bytes(),
            DEFAULT_MAX_IMPORT_BYTES,
        )
        .unwrap_err()
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn example_payload_preview_and_apply() {
        let mut conn = setup();
        fixtures(&conn);
        let payload = base_payload();

        let preview = preview_ok(&mut conn, &payload);
        assert_eq!(
            preview.counts,
            ImportCounts {
                identities: 1,
                links: 1,
                quotas: 1
            }
        );
        assert!(preview.warnings.is_empty());
        assert!(preview.errors.is_empty());
        assert_eq!(preview.digest.len(), 64);
        assert_eq!(
            preview.diff_summary,
            ImportDiffSummary {
                identities_added: 1,
                identities_updated: 0,
                quotas_added: 1,
                quotas_updated: 0,
            }
        );

        // Preview persists only the metadata_imports row.
        assert_eq!(count(&conn, "identity_mappings"), 0);
        assert_eq!(count(&conn, "quota_records"), 0);
        let vol: Option<String> = conn
            .query_row(
                "SELECT volume_id FROM sources WHERE id = ?1",
                params![SOURCE_ID],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(vol, None);
        let state: String = conn
            .query_row(
                "SELECT state FROM metadata_imports WHERE id = ?1",
                params![preview.preview_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "preview");

        let summary = apply_import(&mut conn, &preview.preview_id, &preview.digest).unwrap();
        assert_eq!(summary.identities_upserted, 1);
        assert_eq!(summary.identities_renamed, 0);
        assert_eq!(summary.links_applied, 1);
        assert_eq!(summary.quotas_inserted, 1);
        assert!(summary.notes.iter().any(|n| n.contains("identity_epoch")));

        assert_eq!(count(&conn, "identity_mappings"), 1);
        assert_eq!(count(&conn, "quota_records"), 1);
        let vol: Option<String> = conn
            .query_row(
                "SELECT volume_id FROM sources WHERE id = ?1",
                params![SOURCE_ID],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(vol.as_deref(), Some(VOLUME_ID));
        let import_id: Option<String> = conn
            .query_row("SELECT import_id FROM quota_records", [], |r| r.get(0))
            .unwrap();
        assert_eq!(import_id.as_deref(), Some(preview.preview_id.as_str()));
        let state: String = conn
            .query_row(
                "SELECT state FROM metadata_imports WHERE id = ?1",
                params![preview.preview_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "applied");
    }

    #[test]
    fn schema_rejects_bad_uuid() {
        let mut conn = setup();
        fixtures(&conn);
        let mut p = base_payload();
        p["source_links"][0]["source_id"] = serde_json::json!("not-a-uuid");
        let e = preview_err(&mut conn, &p);
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        let details = e.details.unwrap().to_string();
        assert!(details.contains("source_id"), "{details}");
    }

    #[test]
    fn schema_rejects_unknown_field() {
        let mut conn = setup();
        fixtures(&conn);
        let mut p = base_payload();
        p["mount_root"] = serde_json::json!("/etc");
        let e = preview_err(&mut conn, &p);
        assert_eq!(e.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn schema_rejects_known_limit_without_bytes() {
        let mut conn = setup();
        fixtures(&conn);
        let mut p = base_payload();
        p["quotas"][0]["limit"]["bytes"] = serde_json::Value::Null;
        let e = preview_err(&mut conn, &p);
        assert_eq!(e.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn duplicate_uid_conflicting_names_rejected() {
        let mut conn = setup();
        fixtures(&conn);
        let mut p = base_payload();
        let mut dup = p["identities"][0].clone();
        dup["display_name"] = serde_json::json!("other-name");
        p["identities"].as_array_mut().unwrap().push(dup);
        let e = preview_err(&mut conn, &p);
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        assert!(e.message.contains("冲突显示名"), "{}", e.message);

        // Same name is fine.
        let mut p2 = base_payload();
        let dup2 = p2["identities"][0].clone();
        p2["identities"].as_array_mut().unwrap().push(dup2);
        let preview = preview_ok(&mut conn, &p2);
        assert_eq!(preview.counts.identities, 2);
    }

    #[test]
    fn unknown_source_id_rejected() {
        let mut conn = setup();
        fixtures(&conn);
        let mut p = base_payload();
        let unknown = "33333333-3333-4333-8333-333333333333";
        p["source_links"][0]["source_id"] = serde_json::json!(unknown);
        let e = preview_err(&mut conn, &p);
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        assert!(e.details.unwrap().to_string().contains(unknown));

        // Quota scope pointing at a missing volume is also rejected.
        let mut p2 = base_payload();
        p2["quotas"][0]["scope"] = serde_json::json!({"kind": "volume", "id": unknown});
        let e2 = preview_err(&mut conn, &p2);
        assert_eq!(e2.code, ErrorCode::ValidationFailed);
        assert!(e2.details.unwrap().to_string().contains(unknown));
    }

    #[test]
    fn decimal_range_overflow_rejected() {
        let mut conn = setup();
        fixtures(&conn);
        let mut p = base_payload();
        // u64::MAX + 1; passes the schema pattern (20 digits) but overflows.
        p["quotas"][0]["limit"]["bytes"] = serde_json::json!("18446744073709551616");
        let e = preview_err(&mut conn, &p);
        assert_eq!(e.code, ErrorCode::ValidationFailed);
        assert!(e.message.contains("u64"), "{}", e.message);

        // u64::MAX itself is accepted.
        let mut p2 = base_payload();
        p2["quotas"][0]["limit"]["bytes"] = serde_json::json!("18446744073709551615");
        preview_ok(&mut conn, &p2);
    }

    #[test]
    fn zero_limit_flagged_in_preview() {
        let mut conn = setup();
        fixtures(&conn);
        let mut p = base_payload();
        p["quotas"][0]["limit"]["bytes"] = serde_json::json!("0");
        let preview = preview_ok(&mut conn, &p);
        assert!(
            preview
                .warnings
                .iter()
                .any(|w| w.kind == "zero_limit" && w.path == "quotas[0].limit.bytes")
        );
    }

    #[test]
    fn preview_reports_existing_identity_and_quota_updates() {
        let mut conn = setup();
        fixtures(&conn);
        conn.execute(
            "INSERT INTO identity_mappings (id, namespace, uid, gid, display_name, source, observed_at)
             VALUES ('identity-1', 'posix-container', 1000, 1000, 'old-name', 'manual', '2026-09-01T00:00:00Z')",
            [],
        )
        .unwrap();
        insert_quota(
            &conn,
            1000,
            "known",
            Some("1"),
            "2026-09-01T00:00:00Z",
            None,
        );

        let preview = preview_ok(&mut conn, &base_payload());
        assert_eq!(
            preview.diff_summary,
            ImportDiffSummary {
                identities_added: 0,
                identities_updated: 1,
                quotas_added: 0,
                quotas_updated: 1,
            }
        );
    }

    #[test]
    fn expired_quota_marked_stale_in_file() {
        let mut conn = setup();
        fixtures(&conn);
        let mut p = base_payload();
        p["quotas"][0]["expires_at"] = serde_json::json!("2020-01-01T00:00:00Z");
        let preview = preview_ok(&mut conn, &p);
        assert!(
            preview
                .warnings
                .iter()
                .any(|w| w.kind == "stale_in_file" && w.path == "quotas[0].expires_at")
        );
    }

    #[test]
    fn blank_display_name_rejected() {
        let mut conn = setup();
        fixtures(&conn);
        let mut p = base_payload();
        p["identities"][0]["display_name"] = serde_json::json!("   ");
        let e = preview_err(&mut conn, &p);
        assert_eq!(e.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn oversized_payload_rejected() {
        let mut conn = setup();
        fixtures(&conn);
        let bytes = vec![b' '; 64];
        let e = preview_import(&mut conn, &bytes, 10).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadRequest);
    }

    #[test]
    fn digest_mismatch_conflict() {
        let mut conn = setup();
        fixtures(&conn);
        let preview = preview_ok(&mut conn, &base_payload());
        let e = apply_import(&mut conn, &preview.preview_id, &"0".repeat(64)).unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);
        assert!(e.message.contains("摘要"), "{}", e.message);
        // Nothing was applied.
        assert_eq!(count(&conn, "identity_mappings"), 0);
        assert_eq!(count(&conn, "quota_records"), 0);
    }

    #[test]
    fn second_apply_conflict() {
        let mut conn = setup();
        fixtures(&conn);
        let preview = preview_ok(&mut conn, &base_payload());
        apply_import(&mut conn, &preview.preview_id, &preview.digest).unwrap();
        let e = apply_import(&mut conn, &preview.preview_id, &preview.digest).unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);
        assert!(e.message.contains("已应用"), "{}", e.message);
        // Idempotency: still exactly one row each.
        assert_eq!(count(&conn, "identity_mappings"), 1);
        assert_eq!(count(&conn, "quota_records"), 1);
    }

    #[test]
    fn unknown_preview_not_found() {
        let mut conn = setup();
        let e = apply_import(&mut conn, "no-such-id", "x").unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
    }

    #[test]
    fn volume_link_preserves_identity_epoch() {
        let mut conn = setup();
        fixtures(&conn);
        conn.execute(
            "UPDATE sources SET identity_status = 'confirmed', identity_epoch = 7 WHERE id = ?1",
            params![SOURCE_ID],
        )
        .unwrap();
        let preview = preview_ok(&mut conn, &base_payload());
        apply_import(&mut conn, &preview.preview_id, &preview.digest).unwrap();
        let (status, epoch, vol): (String, i64, Option<String>) = conn
            .query_row(
                "SELECT identity_status, identity_epoch, volume_id FROM sources WHERE id = ?1",
                params![SOURCE_ID],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(status, "confirmed");
        assert_eq!(epoch, 7);
        assert_eq!(vol.as_deref(), Some(VOLUME_ID));
    }

    #[test]
    fn import_cannot_create_mounts_or_sources() {
        // The payload schema has no mount fields (additionalProperties: false)
        // and apply only UPDATEs existing sources; an import can never create
        // approved mounts or widen file access. Asserted here on the DB side:
        // source/volume counts are unchanged by preview+apply.
        let mut conn = setup();
        fixtures(&conn);
        let preview = preview_ok(&mut conn, &base_payload());
        apply_import(&mut conn, &preview.preview_id, &preview.digest).unwrap();
        assert_eq!(count(&conn, "sources"), 1);
        assert_eq!(count(&conn, "volumes"), 1);
    }

    #[test]
    fn identity_priority_import_over_manual_and_fallback() {
        let mut conn = setup();
        fixtures(&conn);
        // Manual mapping first.
        conn.execute(
            "INSERT INTO identity_mappings (id, namespace, uid, gid, display_name, source, observed_at) \
             VALUES ('m1', 'posix-container', 1000, 1000, 'manual-name', 'manual', '2026-09-01T00:00:00Z')",
            [],
        )
        .unwrap();
        assert_eq!(
            identity_for_uid(&conn, "posix-container", 1000)
                .unwrap()
                .as_deref(),
            Some("manual-name")
        );

        let preview = preview_ok(&mut conn, &base_payload());
        let summary = apply_import(&mut conn, &preview.preview_id, &preview.digest).unwrap();
        assert_eq!(summary.identities_renamed, 1);
        assert!(summary.notes.iter().any(|n| n.contains("manual-name")));
        assert_eq!(
            identity_for_uid(&conn, "posix-container", 1000)
                .unwrap()
                .as_deref(),
            Some("example-owner")
        );
        let source: String = conn
            .query_row(
                "SELECT source FROM identity_mappings WHERE namespace = 'posix-container' AND uid = 1000",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(source, "import");

        // Unknown identity: caller falls back to "uid:<n>".
        assert_eq!(
            identity_for_uid(&conn, "posix-container", 4242).unwrap(),
            None
        );
    }

    fn insert_quota(
        conn: &Connection,
        uid: i64,
        limit_state: &str,
        limit_bytes: Option<&str>,
        observed_at: &str,
        expires_at: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO quota_records (id, principal_namespace, principal_uid, scope_kind, \
             scope_id, metric, origin, limit_state, limit_bytes, used_bytes, observed_at, \
             expires_at, provider_label, created_at) \
             VALUES (?1, 'posix-container', ?2, 'source', ?3, 'logical_bytes', 'advisory', \
             ?4, ?5, NULL, ?6, ?7, 'test', '2026-09-01T00:00:00Z')",
            params![
                uuid::Uuid::new_v4().to_string(),
                uid,
                SOURCE_ID,
                limit_state,
                limit_bytes,
                observed_at,
                expires_at,
            ],
        )
        .unwrap();
    }

    #[test]
    fn effective_quota_expiry_stale_unknown() {
        let conn = setup();
        fixtures(&conn);

        // Unknown principal/scope/metric: None, never fabricated unlimited.
        assert!(
            effective_quota(
                &conn,
                "posix-container",
                1000,
                "source",
                SOURCE_ID,
                "logical_bytes"
            )
            .unwrap()
            .is_none()
        );

        // Only an expired record: returned with stale=true.
        insert_quota(
            &conn,
            1000,
            "known",
            Some("100"),
            "2026-01-01T00:00:00Z",
            Some("2026-02-01T00:00:00Z"),
        );
        let q = effective_quota(
            &conn,
            "posix-container",
            1000,
            "source",
            SOURCE_ID,
            "logical_bytes",
        )
        .unwrap()
        .unwrap();
        assert!(q.stale);
        assert_eq!(q.limit_bytes.as_deref(), Some("100"));

        // A newer non-expired record wins over the expired one.
        insert_quota(
            &conn,
            1000,
            "known",
            Some("200"),
            "2026-09-01T00:00:00Z",
            None,
        );
        let q = effective_quota(
            &conn,
            "posix-container",
            1000,
            "source",
            SOURCE_ID,
            "logical_bytes",
        )
        .unwrap()
        .unwrap();
        assert!(!q.stale);
        assert_eq!(q.limit_bytes.as_deref(), Some("200"));

        // Other metrics/scopes are independent.
        assert!(
            effective_quota(
                &conn,
                "posix-container",
                1000,
                "source",
                SOURCE_ID,
                "allocated_bytes"
            )
            .unwrap()
            .is_none()
        );
        assert!(
            effective_quota(
                &conn,
                "posix-container",
                1000,
                "volume",
                VOLUME_ID,
                "logical_bytes"
            )
            .unwrap()
            .is_none()
        );
    }
}
