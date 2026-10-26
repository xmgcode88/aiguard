CREATE TABLE IF NOT EXISTS event_dispositions (
    event_id INTEGER PRIMARY KEY,
    status TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY(event_id) REFERENCES security_events(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_event_dispositions_status ON event_dispositions(status, updated_at DESC);
