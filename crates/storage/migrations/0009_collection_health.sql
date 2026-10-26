CREATE TABLE IF NOT EXISTS collection_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component TEXT NOT NULL,
    status TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    message TEXT NOT NULL,
    agent_id TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
);

CREATE INDEX IF NOT EXISTS idx_collection_health_component ON collection_health(component, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_collection_health_status ON collection_health(status, checked_at DESC);
