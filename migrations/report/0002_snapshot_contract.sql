-- Report snapshot contract extensions. Report databases are immutable after
-- publication, but new reports must preserve nullable/unknown values and the
-- control-plane values that were captured for the scan.

CREATE TABLE category_extension_aggregates_new (
    source_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    extension TEXT,
    file_count INTEGER NOT NULL,
    logical_bytes INTEGER,
    PRIMARY KEY (source_id, category_id, extension)
);
INSERT INTO category_extension_aggregates_new
    (source_id, category_id, extension, file_count, logical_bytes)
SELECT source_id, category_id, extension, file_count, logical_bytes
FROM category_extension_aggregates;
DROP TABLE category_extension_aggregates;
ALTER TABLE category_extension_aggregates_new RENAME TO category_extension_aggregates;

CREATE TABLE owner_category_aggregates_new (
    source_id TEXT NOT NULL,
    uid INTEGER NOT NULL,
    category_id TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    logical_bytes INTEGER,
    PRIMARY KEY (source_id, uid, category_id)
);
INSERT INTO owner_category_aggregates_new
    (source_id, uid, category_id, file_count, logical_bytes)
SELECT source_id, uid, category_id, file_count, logical_bytes
FROM owner_category_aggregates;
DROP TABLE owner_category_aggregates;
ALTER TABLE owner_category_aggregates_new RENAME TO owner_category_aggregates;

CREATE TABLE rankings_new (
    kind TEXT NOT NULL,
    rank INTEGER NOT NULL,
    entry_id INTEGER NOT NULL,
    source_id TEXT NOT NULL,
    raw_relative_path BLOB NOT NULL,
    display_path TEXT NOT NULL,
    display_name TEXT NOT NULL,
    uid INTEGER,
    category_id TEXT,
    size_bytes INTEGER NOT NULL,
    allocated_bytes_estimate INTEGER,
    mtime_sec INTEGER, mtime_nsec INTEGER,
    atime_sec INTEGER, atime_nsec INTEGER,
    status TEXT NOT NULL DEFAULT 'present',
    PRIMARY KEY (kind, rank)
);
INSERT INTO rankings_new
    (kind, rank, entry_id, source_id, raw_relative_path, display_path,
     display_name, uid, category_id, size_bytes, allocated_bytes_estimate,
     mtime_sec, mtime_nsec, atime_sec, atime_nsec, status)
SELECT kind, rank, entry_id, source_id, raw_relative_path, display_path,
       '', uid, category_id, size_bytes, allocated_bytes_estimate,
       mtime_sec, mtime_nsec, atime_sec, atime_nsec, status
FROM rankings;
DROP TABLE rankings;
ALTER TABLE rankings_new RENAME TO rankings;

ALTER TABLE quota_snapshot ADD COLUMN expires_at TEXT;
ALTER TABLE quota_snapshot ADD COLUMN provider_label TEXT;
