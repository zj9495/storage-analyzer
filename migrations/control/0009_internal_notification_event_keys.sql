ALTER TABLE internal_notifications ADD COLUMN event_key TEXT;

CREATE UNIQUE INDEX idx_internal_notifications_event_key
    ON internal_notifications(event_key)
    WHERE event_key IS NOT NULL;
