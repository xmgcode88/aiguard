"""Dump seeded security_events rows as StoredSecurityEvent JSON for the classifier verifier."""
import json
import os
import sqlite3
import sys

EVENT_COLS = [
    "risk", "event_type", "actor", "summary", "evidence", "command_line",
    "rule_id", "session_id", "project", "correlation_id", "sensitive_types", "process",
]


def resolve_db(argv):
    if len(argv) > 1:
        return argv[1]
    base = os.environ.get("AIGUARD_DATA_DIR")
    if not base:
        raise SystemExit("pass a db path or set AIGUARD_DATA_DIR")
    return os.path.join(base, "aiguard.db")


def main():
    path = resolve_db(sys.argv)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT id, created_at, " + ", ".join(EVENT_COLS)
        + " FROM security_events ORDER BY id ASC"
    ).fetchall()
    con.close()

    out = []
    for row in rows:
        event = {col: row[col] for col in EVENT_COLS}
        raw = event.get("sensitive_types")
        if isinstance(raw, str) and raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = [part for part in raw.split(",") if part]
            event["sensitive_types"] = parsed if isinstance(parsed, list) else [str(parsed)]
        elif not raw:
            event["sensitive_types"] = []
        out.append({"id": row["id"], "created_at": row["created_at"], "event": event})

    sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
