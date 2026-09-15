-- Persist the next logical UTC schedule occurrence for each profile.
-- The value is a cursor, not a second source of schedule truth; the
-- immutable profile version remains the source of the schedule expression.
ALTER TABLE profiles ADD COLUMN next_run_at TEXT;
