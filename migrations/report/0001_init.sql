-- Immutable report summary database schema (spec 16.3). One file per
-- published report: /data/reports/<report_id>/report.sqlite

CREATE TABLE report_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE folder_aggregates (
    source_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    parent_path BLOB,
    raw_relative_path BLOB NOT NULL,
    display_path TEXT NOT NULL,
    depth INTEGER NOT NULL,
    file_count INTEGER NOT NULL,
    dir_count INTEGER NOT NULL,
    logical_bytes INTEGER NOT NULL,
    unique_logical_bytes INTEGER NOT NULL,
    allocated_bytes INTEGER NOT NULL,
    completeness TEXT NOT NULL,
    PRIMARY KEY (source_id, raw_relative_path)
);
CREATE INDEX idx_folder_agg_parent ON folder_aggregates(source_id, parent_path);

CREATE TABLE owner_aggregates (
    source_id TEXT NOT NULL,
    uid INTEGER NOT NULL,
    file_count INTEGER NOT NULL,
    logical_bytes INTEGER NOT NULL,
    PRIMARY KEY (source_id, uid)
);

CREATE TABLE owner_category_aggregates (
    source_id TEXT NOT NULL,
    uid INTEGER NOT NULL,
    category_id TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    logical_bytes INTEGER NOT NULL,
    PRIMARY KEY (source_id, uid, category_id)
);

CREATE TABLE category_aggregates (
    source_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    logical_bytes INTEGER NOT NULL,
    allocated_bytes INTEGER NOT NULL,
    PRIMARY KEY (source_id, category_id)
);

CREATE TABLE category_extension_aggregates (
    source_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    extension TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    logical_bytes INTEGER NOT NULL,
    PRIMARY KEY (source_id, category_id, extension)
);

CREATE TABLE rankings (
    kind TEXT NOT NULL,
    rank INTEGER NOT NULL,
    entry_id INTEGER NOT NULL,
    source_id TEXT NOT NULL,
    raw_relative_path BLOB NOT NULL,
    display_path TEXT NOT NULL,
    uid INTEGER,
    category_id TEXT,
    size_bytes INTEGER NOT NULL,
    allocated_bytes_estimate INTEGER NOT NULL,
    mtime_sec INTEGER, mtime_nsec INTEGER,
    atime_sec INTEGER, atime_nsec INTEGER,
    status TEXT NOT NULL DEFAULT 'present',
    PRIMARY KEY (kind, rank)
);

CREATE TABLE duplicate_groups (
    group_id INTEGER PRIMARY KEY,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    member_count INTEGER NOT NULL,
    listed_member_count INTEGER NOT NULL,
    logical_redundancy_bytes INTEGER NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0,
    verification TEXT NOT NULL
);

CREATE TABLE duplicate_members (
    group_id INTEGER NOT NULL REFERENCES duplicate_groups(group_id),
    entry_id INTEGER NOT NULL,
    source_id TEXT NOT NULL,
    raw_relative_path BLOB NOT NULL,
    display_path TEXT NOT NULL,
    uid INTEGER,
    mtime_sec INTEGER, mtime_nsec INTEGER,
    protected INTEGER NOT NULL DEFAULT 0,
    hardlink_alias INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, entry_id)
);

CREATE TABLE volume_samples_snapshot (
    volume_id TEXT NOT NULL,
    sample_time TEXT NOT NULL,
    total_bytes TEXT,
    free_bytes TEXT,
    available_bytes TEXT,
    used_bytes TEXT,
    quality TEXT NOT NULL,
    PRIMARY KEY (volume_id, sample_time)
);

CREATE TABLE section_status (
    section TEXT PRIMARY KEY,
    quality TEXT NOT NULL,
    error_count INTEGER NOT NULL DEFAULT 0,
    message TEXT
);

CREATE TABLE quota_snapshot (
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
    stale INTEGER NOT NULL DEFAULT 0
);

