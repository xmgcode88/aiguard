CREATE TABLE IF NOT EXISTS traces (
    trace_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    root_span_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    summary TEXT,
    raw_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY(session_id) REFERENCES agent_sessions(session_id)
);

CREATE TABLE IF NOT EXISTS spans (
    span_id TEXT PRIMARY KEY,
    trace_id TEXT NOT NULL,
    parent_span_id TEXT,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    tool_call_id TEXT,
    raw_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY(trace_id) REFERENCES traces(trace_id),
    FOREIGN KEY(parent_span_id) REFERENCES spans(span_id)
);

CREATE INDEX IF NOT EXISTS idx_traces_session ON traces(session_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(trace_id, started_at ASC);
CREATE INDEX IF NOT EXISTS idx_spans_parent ON spans(parent_span_id);
