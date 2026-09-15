-- Control database schema (spec 16.1). Applied by store::migrate with
-- checksum verification recorded in schema_migrations.

CREATE TABLE app_settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE admin_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_params_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    csrf_secret TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_idle_at TEXT NOT NULL,
    expires_absolute_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE setup_tokens (
    token_hash TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE reauth_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE volumes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    capacity_source_id TEXT,
    identity_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    mount_key TEXT NOT NULL,
    raw_relative_root BLOB NOT NULL DEFAULT '',
    volume_id TEXT REFERENCES volumes(id),
    storage_kind TEXT NOT NULL DEFAULT 'unknown',
    read_policy TEXT NOT NULL DEFAULT 'metadata_only',
    write_enabled INTEGER NOT NULL DEFAULT 0,
    protected INTEGER NOT NULL DEFAULT 0,
    exclusions_json TEXT NOT NULL DEFAULT '[]',
    identity_status TEXT NOT NULL DEFAULT 'provisional',
    identity_epoch INTEGER NOT NULL DEFAULT 0,
    identity_json TEXT NOT NULL DEFAULT '{}',
    availability TEXT NOT NULL DEFAULT 'unknown',
    atime_quality TEXT NOT NULL DEFAULT 'unknown',
    disabled_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE identity_mappings (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    uid INTEGER NOT NULL,
    gid INTEGER,
    display_name TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(namespace, uid)
);

CREATE TABLE quota_records (
    id TEXT PRIMARY KEY,
    principal_namespace TEXT NOT NULL,
    principal_uid INTEGER NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    origin TEXT NOT NULL,
    limit_state TEXT NOT NULL,
    limit_bytes TEXT,
    used_bytes TEXT,
    observed_at TEXT NOT NULL,
    expires_at TEXT,
    provider_label TEXT NOT NULL,
    import_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_quota_principal ON quota_records(principal_namespace, principal_uid, scope_kind, scope_id, metric);

CREATE TABLE category_rulesets (
    id TEXT PRIMARY KEY,
    version INTEGER NOT NULL UNIQUE,
    rules_json TEXT NOT NULL,
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    deleted_at TEXT,
    current_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE profile_versions (
    profile_id TEXT NOT NULL REFERENCES profiles(id),
    version INTEGER NOT NULL,
    config_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (profile_id, version)
);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    run_id TEXT UNIQUE,
    type TEXT NOT NULL,
    state TEXT NOT NULL,
    phase TEXT,
    profile_id TEXT,
    profile_version INTEGER,
    params_json TEXT NOT NULL DEFAULT '{}',
    idempotency_key TEXT UNIQUE,
    retry_of TEXT,
    requested_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    heartbeat_at TEXT,
    progress_json TEXT NOT NULL DEFAULT '{}',
    error_json TEXT
);
CREATE INDEX idx_jobs_state ON jobs(state, requested_at);
CREATE INDEX idx_jobs_profile ON jobs(profile_id, requested_at);

CREATE TABLE schedule_occurrences (
    profile_id TEXT NOT NULL,
    profile_version INTEGER NOT NULL,
    occurrence_key TEXT NOT NULL,
    job_id TEXT NOT NULL REFERENCES jobs(id),
    planned_at TEXT NOT NULL,
    UNIQUE(profile_id, profile_version, occurrence_key)
);

CREATE TABLE job_events (
    job_id TEXT NOT NULL REFERENCES jobs(id),
    sequence INTEGER NOT NULL,
    type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (job_id, sequence)
);

CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    profile_id TEXT,
    profile_version INTEGER,
    manifest_path TEXT NOT NULL,
    status TEXT NOT NULL,
    consistency TEXT NOT NULL DEFAULT 'live_observation',
    scope_fingerprint TEXT NOT NULL,
    classification_version INTEGER NOT NULL,
    scan_started_at TEXT,
    scan_finished_at TEXT,
    detail_available INTEGER NOT NULL DEFAULT 1,
    pinned INTEGER NOT NULL DEFAULT 0,
    detail_pinned INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_reports_profile ON reports(profile_id, created_at);

CREATE TABLE volume_samples (
    volume_id TEXT NOT NULL REFERENCES volumes(id),
    sample_time TEXT NOT NULL,
    total_bytes TEXT,
    free_bytes TEXT,
    available_bytes TEXT,
    used_bytes TEXT,
    quality TEXT NOT NULL DEFAULT 'ok',
    error TEXT,
    PRIMARY KEY (volume_id, sample_time)
);

CREATE TABLE volume_samples_daily (
    volume_id TEXT NOT NULL REFERENCES volumes(id),
    day TEXT NOT NULL,
    used_min TEXT,
    used_max TEXT,
    used_last TEXT,
    sample_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (volume_id, day)
);

CREATE TABLE notification_outbox (
    id TEXT PRIMARY KEY,
    report_id TEXT,
    recipient TEXT NOT NULL,
    kind TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    last_error TEXT,
    created_at TEXT NOT NULL,
    sent_at TEXT
);

CREATE TABLE exports (
    id TEXT PRIMARY KEY,
    report_id TEXT,
    query_hash TEXT NOT NULL,
    section TEXT NOT NULL,
    format TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    path TEXT,
    size_bytes TEXT,
    checksum_sha256 TEXT,
    lease_count INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE cleanup_plans (
    id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sig TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'preview',
    created_at TEXT NOT NULL
);

CREATE TABLE cleanup_items (
    id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES cleanup_plans(id),
    action_id TEXT,
    entry_ref TEXT NOT NULL,
    source_id TEXT NOT NULL,
    raw_original_path BLOB NOT NULL,
    raw_quarantine_path BLOB,
    identity_json TEXT NOT NULL,
    content_sha256 TEXT,
    state TEXT NOT NULL DEFAULT 'PLANNED',
    journal_seq INTEGER,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_cleanup_items_plan ON cleanup_items(plan_id);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT,
    result TEXT NOT NULL,
    request_id TEXT,
    redacted_detail TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_created ON audit_events(created_at);

CREATE TABLE metadata_imports (
    id TEXT PRIMARY KEY,
    digest TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'preview',
    created_at TEXT NOT NULL,
    applied_at TEXT
);

