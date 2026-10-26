CREATE TABLE IF NOT EXISTS tool_calls (
    tool_call_id TEXT PRIMARY KEY,
    trace_id TEXT,
    span_id TEXT,
    session_id TEXT,
    agent_id TEXT,
    tool_name TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_ms INTEGER,
    exit_code INTEGER,
    stdout_preview TEXT,
    stderr_preview TEXT,
    output_size INTEGER,
    artifact_refs TEXT NOT NULL DEFAULT '[]',
    error_type TEXT,
    raw_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY(trace_id) REFERENCES traces(trace_id),
    FOREIGN KEY(span_id) REFERENCES spans(span_id),
    FOREIGN KEY(session_id) REFERENCES agent_sessions(session_id),
    FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
);

CREATE INDEX IF NOT EXISTS idx_tool_calls_session ON tool_calls(session_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_tool_calls_trace ON tool_calls(trace_id, started_at ASC);
CREATE INDEX IF NOT EXISTS idx_tool_calls_status ON tool_calls(status, started_at DESC);
