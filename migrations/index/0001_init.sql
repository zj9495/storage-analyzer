-- Run index database schema (spec 16.2). One file per run:
-- /data/runs/<run_id>/index.sqlite

CREATE TABLE entries (
    entry_id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL,
    parent_entry_id INTEGER,
    raw_relative_path BLOB NOT NULL,
    display_name TEXT NOT NULL,
    path_encoding_warning INTEGER NOT NULL DEFAULT 0,
    entry_kind TEXT NOT NULL,
    file_identity_key TEXT,
    identity_quality TEXT NOT NULL DEFAULT 'reliable',
    device_id TEXT,
    inode_id TEXT,
    nlink INTEGER,
    uid INTEGER,
    gid INTEGER,
    mode INTEGER,
    size_bytes INTEGER CHECK(size_bytes >= 0),
    allocated_bytes_estimate INTEGER CHECK(allocated_bytes_estimate >= 0),
    mtime_sec INTEGER, mtime_nsec INTEGER,
    atime_sec INTEGER, atime_nsec INTEGER,
    ctime_sec INTEGER, ctime_nsec INTEGER,
    birthtime_sec INTEGER, birthtime_nsec INTEGER,
    category_id TEXT,
    extension TEXT,
    scan_error TEXT,
    dfs_left INTEGER,
    dfs_right INTEGER,
    observation_time TEXT NOT NULL,
    UNIQUE(source_id, raw_relative_path)
);
CREATE INDEX idx_entries_parent ON entries(parent_entry_id, entry_kind);
CREATE INDEX idx_entries_size ON entries(size_bytes DESC, entry_id);
CREATE INDEX idx_entries_uid_size ON entries(uid, size_bytes DESC, entry_id);
CREATE INDEX idx_entries_cat_size ON entries(category_id, size_bytes DESC, entry_id);
CREATE INDEX idx_entries_mtime ON entries(mtime_sec DESC, mtime_nsec DESC, entry_id);
CREATE INDEX idx_entries_atime ON entries(atime_sec, atime_nsec, entry_id);
CREATE INDEX idx_entries_identity ON entries(file_identity_key);

CREATE TABLE scan_errors (
    id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL,
    raw_relative_path BLOB,
    errno INTEGER,
    category TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE source_observations (
    source_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    error_count INTEGER NOT NULL DEFAULT 0,
    vanished_count INTEGER NOT NULL DEFAULT 0,
    unstable_count INTEGER NOT NULL DEFAULT 0,
    excluded_count INTEGER NOT NULL DEFAULT 0,
    detail TEXT
);

-- Directory frontier spill: directories pending traversal when the in-memory
-- queue is at capacity. Rebuilt from entries if the run is interrupted.
CREATE TABLE frontier (
    id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL,
    parent_entry_id INTEGER NOT NULL,
    raw_relative_path BLOB NOT NULL,
    UNIQUE(source_id, raw_relative_path)
);

CREATE TABLE duplicate_candidates (
    id INTEGER PRIMARY KEY,
    size_bytes INTEGER NOT NULL,
    candidate_key TEXT NOT NULL,
    entry_id INTEGER NOT NULL,
    sample_hash TEXT,
    full_sha256 TEXT,
    verification TEXT,
    skip_reason TEXT
);
CREATE INDEX idx_dupcand_size ON duplicate_candidates(size_bytes, candidate_key);

CREATE TABLE file_hashes (
    entry_id INTEGER PRIMARY KEY,
    algorithm TEXT NOT NULL,
    algorithm_version INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    identity_key TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mtime_sec INTEGER NOT NULL, mtime_nsec INTEGER NOT NULL,
    ctime_sec INTEGER NOT NULL, ctime_nsec INTEGER NOT NULL,
    hashed_at TEXT NOT NULL,
    source_identity_epoch INTEGER NOT NULL
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
    is_hardlink_alias INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, entry_id)
);

CREATE TABLE directory_aggregates (
    entry_id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    dir_count INTEGER NOT NULL,
    logical_bytes INTEGER NOT NULL,
    unique_logical_bytes INTEGER NOT NULL,
    allocated_bytes INTEGER NOT NULL,
    excluded_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE owner_aggregates (
    source_id TEXT NOT NULL,
    uid INTEGER NOT NULL,
    file_count INTEGER NOT NULL,
    logical_bytes INTEGER NOT NULL,
    PRIMARY KEY (source_id, uid)
);

CREATE TABLE category_aggregates (
    source_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    logical_bytes INTEGER NOT NULL,
    allocated_bytes INTEGER NOT NULL,
    PRIMARY KEY (source_id, category_id)
);

CREATE TABLE run_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

