-- Durable comparison results.  A comparison is an operation job, but its
-- result must outlive the job progress JSON and be queryable page by page.

CREATE TABLE comparisons (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id),
    left_report_id TEXT NOT NULL REFERENCES reports(id),
    right_report_id TEXT NOT NULL REFERENCES reports(id),
    mode TEXT NOT NULL,
    comparable INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    summary_json TEXT NOT NULL DEFAULT '{}',
    error_json TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE comparison_rows (
    comparison_id TEXT NOT NULL REFERENCES comparisons(id) ON DELETE CASCADE,
    section TEXT NOT NULL,
    row_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (comparison_id, section, row_key)
);
CREATE INDEX idx_comparison_rows_page
    ON comparison_rows(comparison_id, section, row_key);
