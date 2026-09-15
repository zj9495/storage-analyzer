-- Preserve DST spring-forward skips without inventing a UTC timestamp or a
-- synthetic job. Existing fired occurrences retain their job and planned UTC
-- value; skipped rows use the local wall-clock key as planned_local_at.
CREATE TABLE schedule_occurrences_v2 (
    profile_id TEXT NOT NULL,
    profile_version INTEGER NOT NULL,
    occurrence_key TEXT NOT NULL,
    job_id TEXT REFERENCES jobs(id),
    planned_at TEXT,
    planned_local_at TEXT NOT NULL,
    skipped_nonexistent INTEGER NOT NULL DEFAULT 0
        CHECK (skipped_nonexistent IN (0, 1)),
    UNIQUE(profile_id, profile_version, occurrence_key),
    CHECK (
        (skipped_nonexistent = 0 AND job_id IS NOT NULL AND planned_at IS NOT NULL)
        OR
        (skipped_nonexistent = 1 AND job_id IS NULL AND planned_at IS NULL)
    )
);

INSERT INTO schedule_occurrences_v2
    (profile_id, profile_version, occurrence_key, job_id, planned_at,
     planned_local_at, skipped_nonexistent)
SELECT profile_id, profile_version, occurrence_key, job_id, planned_at,
       occurrence_key, 0
FROM schedule_occurrences;

DROP TABLE schedule_occurrences;
ALTER TABLE schedule_occurrences_v2 RENAME TO schedule_occurrences;
