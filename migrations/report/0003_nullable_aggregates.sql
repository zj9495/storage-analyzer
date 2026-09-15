-- Keep unknown aggregate values as NULL in immutable report snapshots.

CREATE TABLE folder_aggregates_new (
    source_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    parent_path BLOB,
    raw_relative_path BLOB NOT NULL,
    display_path TEXT NOT NULL,
    depth INTEGER NOT NULL,
    file_count INTEGER NOT NULL,
    dir_count INTEGER NOT NULL,
    logical_bytes INTEGER,
    unique_logical_bytes INTEGER,
    allocated_bytes INTEGER,
    completeness TEXT NOT NULL,
    PRIMARY KEY (source_id, raw_relative_path)
);
INSERT INTO folder_aggregates_new
    (source_id, source_name, parent_path, raw_relative_path, display_path,
     depth, file_count, dir_count, logical_bytes, unique_logical_bytes,
     allocated_bytes, completeness)
SELECT source_id, source_name, parent_path, raw_relative_path, display_path,
       depth, file_count, dir_count, logical_bytes, unique_logical_bytes,
       allocated_bytes, completeness
FROM folder_aggregates;
DROP TABLE folder_aggregates;
ALTER TABLE folder_aggregates_new RENAME TO folder_aggregates;
CREATE INDEX idx_folder_agg_parent ON folder_aggregates(source_id, parent_path);

CREATE TABLE owner_aggregates_new (
    source_id TEXT NOT NULL,
    uid INTEGER,
    file_count INTEGER NOT NULL,
    logical_bytes INTEGER,
    PRIMARY KEY (source_id, uid)
);
INSERT INTO owner_aggregates_new
    (source_id, uid, file_count, logical_bytes)
SELECT source_id, uid, file_count, logical_bytes
FROM owner_aggregates;
DROP TABLE owner_aggregates;
ALTER TABLE owner_aggregates_new RENAME TO owner_aggregates;

CREATE TABLE owner_category_aggregates_new (
    source_id TEXT NOT NULL,
    uid INTEGER,
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

CREATE TABLE category_aggregates_new (
    source_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    logical_bytes INTEGER,
    allocated_bytes INTEGER,
    PRIMARY KEY (source_id, category_id)
);
INSERT INTO category_aggregates_new
    (source_id, category_id, file_count, logical_bytes, allocated_bytes)
SELECT source_id, category_id, file_count, logical_bytes, allocated_bytes
FROM category_aggregates;
DROP TABLE category_aggregates;
ALTER TABLE category_aggregates_new RENAME TO category_aggregates;
