CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    source TEXT NOT NULL,
    source_confidence TEXT NOT NULL,
    agent_id TEXT,
    session_id TEXT,
    trace_id TEXT,
    span_id TEXT,
    parent_span_id TEXT,
    project_id TEXT,
    actor_kind TEXT NOT NULL,
    actor_name TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    rule_id TEXT,
    summary TEXT NOT NULL,
    raw_payload_ref TEXT,
    raw_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY(agent_id) REFERENCES agents(agent_id),
    FOREIGN KEY(session_id) REFERENCES agent_sessions(session_id),
    FOREIGN KEY(trace_id) REFERENCES traces(trace_id),
    FOREIGN KEY(span_id) REFERENCES spans(span_id),
    FOREIGN KEY(project_id) REFERENCES projects(project_id)
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    preview TEXT,
    raw_ref TEXT,
    raw_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY(event_id) REFERENCES audit_events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_events_session ON audit_events(session_id, occurred_at ASC, id ASC);
CREATE INDEX IF NOT EXISTS idx_audit_events_trace ON audit_events(trace_id, occurred_at ASC, id ASC);
CREATE INDEX IF NOT EXISTS idx_audit_events_project ON audit_events(project_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_risk ON audit_events(risk_score DESC, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_agent ON audit_events(agent_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_rule ON audit_events(rule_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_event ON evidence(event_id);
