-- Durable idempotency records for synchronous restore applications.  The
-- request secret is deliberately absent; only the replayable response is
-- stored so a process restart cannot turn an authenticated restore into a
-- second execution.

CREATE TABLE restore_operations (
    idempotency_key TEXT PRIMARY KEY,
    preview_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
