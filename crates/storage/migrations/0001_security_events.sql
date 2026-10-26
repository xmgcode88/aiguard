CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    process TEXT NOT NULL,
    risk INTEGER NOT NULL CHECK (risk >= 0 AND risk <= 100),
    rule_id TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_security_events_occurred_at
    ON security_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type
    ON security_events (event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_rule_id
    ON security_events (rule_id);
