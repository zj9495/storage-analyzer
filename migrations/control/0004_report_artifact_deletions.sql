-- Durable post-commit cleanup intents for generated report artifacts.
-- The control rows are committed before any filesystem deletion.  A restart
-- can therefore resume an incomplete deletion without guessing a path.

CREATE TABLE report_artifact_deletions (
    id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL,
    manifest_path TEXT NOT NULL,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('report', 'detail')),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'deleted')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL,
    deleted_at TEXT
);

CREATE UNIQUE INDEX idx_report_artifact_deletions_identity
    ON report_artifact_deletions(report_id, manifest_path, artifact_kind);
CREATE INDEX idx_report_artifact_deletions_pending
    ON report_artifact_deletions(state, created_at);
