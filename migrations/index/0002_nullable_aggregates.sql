-- Preserve unknown observations in aggregate tables.  Existing rows are
-- copied unchanged; a NULL metric means the source contained an item whose
-- value could not be observed, never zero.

CREATE TABLE directory_aggregates_new (
    entry_id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    dir_count INTEGER NOT NULL,
    logical_bytes INTEGER,
    unique_logical_bytes INTEGER,
    allocated_bytes INTEGER,
    excluded_count INTEGER NOT NULL DEFAULT 0
);
INSERT INTO directory_aggregates_new
    (entry_id, source_id, file_count, dir_count, logical_bytes,
     unique_logical_bytes, allocated_bytes, excluded_count)
SELECT entry_id, source_id, file_count, dir_count, logical_bytes,
       unique_logical_bytes, allocated_bytes, excluded_count
FROM directory_aggregates;
DROP TABLE directory_aggregates;
ALTER TABLE directory_aggregates_new RENAME TO directory_aggregates;

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
