use aiguard_core::{Agent, AgentSession, AuditEvent, Project, SecurityEvent, Span, Trace};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePoolOptions, QueryBuilder, Row, Sqlite, SqlitePool};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("event serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid event timestamp: {0}")]
    Timestamp(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredSecurityEvent {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub event: SecurityEvent,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredAuditEvent {
    pub id: i64,
    pub event: AuditEvent,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EventSearch {
    pub project_id: Option<String>,
    pub session_id: Option<String>,
    pub trace_id: Option<String>,
    pub agent_id: Option<String>,
    pub event_type: Option<String>,
    pub rule_id: Option<String>,
    pub min_risk: Option<u8>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
}

/// Per-event triage state recorded by the operator from the security overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDisposition {
    pub event_id: i64,
    /// One of `pending`, `acknowledged`, `resolved`, `ignored`.
    pub status: String,
    pub note: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CollectionHealthRecord {
    pub id: i64,
    pub component: String,
    pub status: String,
    pub checked_at: DateTime<Utc>,
    pub message: String,
    pub agent_id: Option<String>,
    pub details_json: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DashboardCounts {
    pub total: i64,
    pub input: i64,
    pub sensitive_input: i64,
    pub sensitive_outbound: i64,
    pub dangerous: i64,
    pub warning: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LicenseState {
    pub status: String,
    pub license_id: Option<String>,
    pub expires_at: Option<String>,
    pub offline_until: Option<String>,
    pub last_server_time: Option<String>,
    pub updated_at: String,
}

#[async_trait]
pub trait SecurityEventRepository: Send + Sync {
    async fn append(
        &self,
        occurred_at: DateTime<Utc>,
        event: &SecurityEvent,
    ) -> Result<i64, StorageError>;
    async fn append_batch(
        &self,
        events: &[(DateTime<Utc>, SecurityEvent)],
    ) -> Result<(), StorageError>;
    async fn recent(&self, limit: u32) -> Result<Vec<StoredSecurityEvent>, StorageError>;
    async fn since(
        &self,
        since: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<StoredSecurityEvent>, StorageError>;
    async fn dashboard_counts(&self, since: DateTime<Utc>)
        -> Result<DashboardCounts, StorageError>;
}

#[async_trait]
pub trait AuditEventRepository: Send + Sync {
    async fn append_audit_event(&self, event: &AuditEvent) -> Result<i64, StorageError>;
    async fn append_audit_events(&self, events: &[AuditEvent]) -> Result<(), StorageError>;
    async fn list_sessions(&self, limit: u32) -> Result<Vec<AgentSession>, StorageError>;
    async fn session_timeline(
        &self,
        session_id: &str,
        limit: u32,
    ) -> Result<Vec<StoredAuditEvent>, StorageError>;
    async fn trace_events(
        &self,
        trace_id: &str,
        limit: u32,
    ) -> Result<Vec<StoredAuditEvent>, StorageError>;
    async fn event_detail(&self, event_id: &str) -> Result<Option<StoredAuditEvent>, StorageError>;
    async fn search_audit_events(
        &self,
        search: EventSearch,
    ) -> Result<Vec<StoredAuditEvent>, StorageError>;
    async fn collection_health(
        &self,
        limit: u32,
    ) -> Result<Vec<CollectionHealthRecord>, StorageError>;
}

#[derive(Clone)]
pub struct SqliteEventRepository {
    pool: SqlitePool,
}

impl SqliteEventRepository {
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect(database_url)
            .await?;
        Self::from_pool(pool).await
    }

    pub async fn connect_path(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?;
        Self::from_pool(pool).await
    }

    pub async fn in_memory() -> Result<Self, StorageError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        Self::from_pool(pool).await
    }

    async fn from_pool(pool: SqlitePool) -> Result<Self, StorageError> {
        sqlx::query("PRAGMA foreign_keys = ON;")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA journal_mode = WAL;")
            .execute(&pool)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        repair_legacy_mojibake(&pool).await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn license_state(&self) -> Result<LicenseState, StorageError> {
        let row = sqlx::query(
            "SELECT status, license_id, expires_at, offline_until, last_server_time, updated_at FROM license_state WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(LicenseState {
            status: row.try_get("status")?,
            license_id: row.try_get("license_id")?,
            expires_at: row.try_get("expires_at")?,
            offline_until: row.try_get("offline_until")?,
            last_server_time: row.try_get("last_server_time")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    pub async fn update_license_state(
        &self,
        status: &str,
        license_id: Option<&str>,
        expires_at: Option<&str>,
        offline_until: Option<&str>,
        last_server_time: Option<&str>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE license_state SET status = ?, license_id = ?, expires_at = ?, offline_until = ?, last_server_time = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = 1",
        )
        .bind(status)
        .bind(license_id)
        .bind(expires_at)
        .bind(offline_until)
        .bind(last_server_time)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_agent(&self, agent: &Agent) -> Result<(), StorageError> {
        let raw_json = serde_json::to_string(agent)?;
        sqlx::query(
            "INSERT INTO agents (agent_id, name, version, executable_path, raw_json)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(agent_id) DO UPDATE SET
                name = excluded.name,
                version = excluded.version,
                executable_path = excluded.executable_path,
                raw_json = excluded.raw_json,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(&agent.agent_id)
        .bind(&agent.name)
        .bind(&agent.version)
        .bind(&agent.executable_path)
        .bind(raw_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_project(&self, project: &Project) -> Result<(), StorageError> {
        let raw_json = serde_json::to_string(project)?;
        sqlx::query(
            "INSERT INTO projects (project_id, name, root_path, raw_json)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(project_id) DO UPDATE SET
                name = excluded.name,
                root_path = excluded.root_path,
                raw_json = excluded.raw_json,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(&project.project_id)
        .bind(&project.name)
        .bind(&project.root_path)
        .bind(raw_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_session(&self, session: &AgentSession) -> Result<(), StorageError> {
        let raw_json = serde_json::to_string(session)?;
        sqlx::query(
            "INSERT INTO agent_sessions (session_id, agent_id, project_id, started_at, ended_at, raw_json)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(session_id) DO UPDATE SET
                agent_id = excluded.agent_id,
                project_id = excluded.project_id,
                started_at = excluded.started_at,
                ended_at = excluded.ended_at,
                raw_json = excluded.raw_json,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(&session.session_id)
        .bind(&session.agent_id)
        .bind(&session.project_id)
        .bind(&session.started_at)
        .bind(&session.ended_at)
        .bind(raw_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_trace(&self, trace: &Trace) -> Result<(), StorageError> {
        let raw_json = serde_json::to_string(trace)?;
        sqlx::query(
            "INSERT INTO traces (trace_id, session_id, root_span_id, started_at, summary, raw_json)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(trace_id) DO UPDATE SET
                session_id = excluded.session_id,
                root_span_id = excluded.root_span_id,
                started_at = excluded.started_at,
                summary = excluded.summary,
                raw_json = excluded.raw_json,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(&trace.trace_id)
        .bind(&trace.session_id)
        .bind(&trace.root_span_id)
        .bind(&trace.started_at)
        .bind(&trace.summary)
        .bind(raw_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_span(&self, span: &Span) -> Result<(), StorageError> {
        let raw_json = serde_json::to_string(span)?;
        sqlx::query(
            "INSERT INTO spans (span_id, trace_id, parent_span_id, kind, name, started_at, ended_at, tool_call_id, raw_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(span_id) DO UPDATE SET
                trace_id = excluded.trace_id,
                parent_span_id = excluded.parent_span_id,
                kind = excluded.kind,
                name = excluded.name,
                started_at = excluded.started_at,
                ended_at = excluded.ended_at,
                tool_call_id = excluded.tool_call_id,
                raw_json = excluded.raw_json,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(&span.span_id)
        .bind(&span.trace_id)
        .bind(&span.parent_span_id)
        .bind(json_name(&span.kind)?)
        .bind(&span.name)
        .bind(&span.started_at)
        .bind(&span.ended_at)
        .bind(&span.tool_call_id)
        .bind(raw_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Upserts the operator triage state for one security event. Passing
    /// `pending` clears the record so the event returns to the unhandled feed.
    pub async fn set_event_disposition(
        &self,
        event_id: i64,
        status: &str,
        note: &str,
    ) -> Result<(), StorageError> {
        if status == "pending" {
            sqlx::query("DELETE FROM event_dispositions WHERE event_id = ?")
                .bind(event_id)
                .execute(&self.pool)
                .await?;
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO event_dispositions (event_id, status, note, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(event_id) DO UPDATE SET status = excluded.status, note = excluded.note, updated_at = excluded.updated_at",
        )
        .bind(event_id)
        .bind(status)
        .bind(note)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn event_dispositions(&self) -> Result<Vec<EventDisposition>, StorageError> {
        let rows = sqlx::query(
            "SELECT event_id, status, note, updated_at FROM event_dispositions ORDER BY updated_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let updated_at_raw: String = row.try_get("updated_at")?;
                Ok(EventDisposition {
                    event_id: row.try_get("event_id")?,
                    status: row.try_get("status")?,
                    note: row.try_get("note")?,
                    updated_at: DateTime::parse_from_rfc3339(&updated_at_raw)
                        .map_err(|error| StorageError::Timestamp(error.to_string()))?
                        .with_timezone(&Utc),
                })
            })
            .collect()
    }

    pub async fn record_collection_health(
        &self,
        component: &str,
        status: &str,
        checked_at: DateTime<Utc>,
        message: &str,
        agent_id: Option<&str>,
        details_json: &str,
    ) -> Result<i64, StorageError> {
        let result = sqlx::query(
            "INSERT INTO collection_health (component, status, checked_at, message, agent_id, details_json)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(component)
        .bind(status)
        .bind(checked_at.to_rfc3339())
        .bind(message)
        .bind(agent_id)
        .bind(details_json)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }
}

const LEGACY_MOJIBAKE_REPLACEMENTS: &[(&str, &str)] = &[
    ("闁矮绠熼悘鐢电垳", "通义灵码"),
    ("閺傚洣娆㈢化鑽ょ埠", "文件系统"),
    ("Agent 閺傚洣娆㈤崣妯绘纯", "Agent 文件变更"),
    (
        "鐟欏倸鐧傞崚?Agent 閺佺増宓侀惄顔肩秿閺傚洣娆㈤崣妯哄",
        "观察到 Agent 数据目录文件变化",
    ),
    ("鏉╂稓鈻奸崥顖氬З", "进程启动"),
];

async fn repair_legacy_mojibake(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    for (legacy, corrected) in LEGACY_MOJIBAKE_REPLACEMENTS {
        sqlx::query(
            "UPDATE security_events
             SET actor = replace(actor, ?, ?),
                 process = replace(process, ?, ?),
                 raw_json = replace(raw_json, ?, ?)
             WHERE actor LIKE '%' || ? || '%'
                OR process LIKE '%' || ? || '%'
                OR raw_json LIKE '%' || ? || '%'",
        )
        .bind(legacy)
        .bind(corrected)
        .bind(legacy)
        .bind(corrected)
        .bind(legacy)
        .bind(corrected)
        .bind(legacy)
        .bind(legacy)
        .bind(legacy)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            "UPDATE audit_events
             SET actor_name = replace(actor_name, ?, ?),
                 summary = replace(summary, ?, ?),
                 raw_json = replace(raw_json, ?, ?)
             WHERE actor_name LIKE '%' || ? || '%'
                OR summary LIKE '%' || ? || '%'
                OR raw_json LIKE '%' || ? || '%'",
        )
        .bind(legacy)
        .bind(corrected)
        .bind(legacy)
        .bind(corrected)
        .bind(legacy)
        .bind(corrected)
        .bind(legacy)
        .bind(legacy)
        .bind(legacy)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await
}

#[async_trait]
impl SecurityEventRepository for SqliteEventRepository {
    async fn append(
        &self,
        occurred_at: DateTime<Utc>,
        event: &SecurityEvent,
    ) -> Result<i64, StorageError> {
        let raw_json = serde_json::to_string(event)?;
        let result = sqlx::query(
            "INSERT INTO security_events (occurred_at, event_type, actor, process, risk, rule_id, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(occurred_at.to_rfc3339())
        .bind(&event.event_type)
        .bind(&event.actor)
        .bind(&event.process)
        .bind(i64::from(event.risk))
        .bind(&event.rule_id)
        .bind(raw_json)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    async fn append_batch(
        &self,
        events: &[(DateTime<Utc>, SecurityEvent)],
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await?;
        for (occurred_at, event) in events {
            let raw_json = serde_json::to_string(event)?;
            sqlx::query(
                "INSERT INTO security_events (occurred_at, event_type, actor, process, risk, rule_id, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(occurred_at.to_rfc3339())
            .bind(&event.event_type)
            .bind(&event.actor)
            .bind(&event.process)
            .bind(i64::from(event.risk))
            .bind(&event.rule_id)
            .bind(raw_json)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn recent(&self, limit: u32) -> Result<Vec<StoredSecurityEvent>, StorageError> {
        let rows = sqlx::query("SELECT id, occurred_at, raw_json FROM security_events ORDER BY occurred_at DESC, id DESC LIMIT ?")
            .bind(i64::from(limit.max(1)))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(decode_row).collect()
    }

    async fn since(
        &self,
        since: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<StoredSecurityEvent>, StorageError> {
        let rows = sqlx::query("SELECT id, occurred_at, raw_json FROM security_events WHERE occurred_at >= ? ORDER BY occurred_at DESC, id DESC LIMIT ?")
            .bind(since.to_rfc3339())
            .bind(i64::from(limit.max(1)))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(decode_row).collect()
    }

    async fn dashboard_counts(
        &self,
        since: DateTime<Utc>,
    ) -> Result<DashboardCounts, StorageError> {
        let row = sqlx::query(
            "SELECT COUNT(*),\
                SUM(CASE WHEN event_type = 'UserInput' THEN 1 ELSE 0 END),\
                SUM(CASE WHEN event_type = 'UserInput' AND rule_id = 'INPUT.SENSITIVE' THEN 1 ELSE 0 END),\
                SUM(CASE WHEN rule_id = 'DATA.SECRET.EXFIL' THEN 1 ELSE 0 END),\
                SUM(CASE WHEN risk >= 70 AND event_type <> 'UserInput' THEN 1 ELSE 0 END),\
                SUM(CASE WHEN risk >= 60 AND risk < 70 AND event_type <> 'UserInput' THEN 1 ELSE 0 END)\
             FROM security_events WHERE occurred_at >= ?",
        )
        .bind(since.to_rfc3339())
        .fetch_one(&self.pool)
        .await?;
        Ok(DashboardCounts {
            total: row.try_get(0)?,
            input: row.try_get(1)?,
            sensitive_input: row.try_get(2)?,
            sensitive_outbound: row.try_get(3)?,
            dangerous: row.try_get(4)?,
            warning: row.try_get(5)?,
        })
    }
}

#[async_trait]
impl AuditEventRepository for SqliteEventRepository {
    async fn append_audit_event(&self, event: &AuditEvent) -> Result<i64, StorageError> {
        insert_audit_event(&self.pool, event).await
    }

    async fn append_audit_events(&self, events: &[AuditEvent]) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await?;
        for event in events {
            insert_audit_event_tx(&mut transaction, event).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn list_sessions(&self, limit: u32) -> Result<Vec<AgentSession>, StorageError> {
        let rows =
            sqlx::query("SELECT raw_json FROM agent_sessions ORDER BY started_at DESC LIMIT ?")
                .bind(i64::from(limit.clamp(1, 500)))
                .fetch_all(&self.pool)
                .await?;
        rows.into_iter()
            .map(|row| {
                Ok(serde_json::from_str(
                    &row.try_get::<String, _>("raw_json")?,
                )?)
            })
            .collect()
    }

    async fn session_timeline(
        &self,
        session_id: &str,
        limit: u32,
    ) -> Result<Vec<StoredAuditEvent>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, raw_json FROM audit_events
             WHERE session_id = ?
             ORDER BY occurred_at ASC, id ASC
             LIMIT ?",
        )
        .bind(session_id)
        .bind(i64::from(limit.clamp(1, 1000)))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(decode_audit_row).collect()
    }

    async fn trace_events(
        &self,
        trace_id: &str,
        limit: u32,
    ) -> Result<Vec<StoredAuditEvent>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, raw_json FROM audit_events
             WHERE trace_id = ?
             ORDER BY occurred_at ASC, id ASC
             LIMIT ?",
        )
        .bind(trace_id)
        .bind(i64::from(limit.clamp(1, 1000)))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(decode_audit_row).collect()
    }

    async fn event_detail(&self, event_id: &str) -> Result<Option<StoredAuditEvent>, StorageError> {
        let row = sqlx::query("SELECT id, raw_json FROM audit_events WHERE event_id = ?")
            .bind(event_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(decode_audit_row).transpose()
    }

    async fn search_audit_events(
        &self,
        search: EventSearch,
    ) -> Result<Vec<StoredAuditEvent>, StorageError> {
        let mut query: QueryBuilder<'_, Sqlite> =
            QueryBuilder::new("SELECT id, raw_json FROM audit_events WHERE 1 = 1");
        if let Some(value) = search.project_id {
            query.push(" AND project_id = ").push_bind(value);
        }
        if let Some(value) = search.session_id {
            query.push(" AND session_id = ").push_bind(value);
        }
        if let Some(value) = search.trace_id {
            query.push(" AND trace_id = ").push_bind(value);
        }
        if let Some(value) = search.agent_id {
            query.push(" AND agent_id = ").push_bind(value);
        }
        if let Some(value) = search.event_type {
            query.push(" AND event_type = ").push_bind(value);
        }
        if let Some(value) = search.rule_id {
            query.push(" AND rule_id = ").push_bind(value);
        }
        if let Some(value) = search.min_risk {
            query
                .push(" AND risk_score >= ")
                .push_bind(i64::from(value));
        }
        if let Some(value) = search.since {
            query
                .push(" AND occurred_at >= ")
                .push_bind(value.to_rfc3339());
        }
        if let Some(value) = search.until {
            query
                .push(" AND occurred_at <= ")
                .push_bind(value.to_rfc3339());
        }
        query
            .push(" ORDER BY occurred_at DESC, id DESC LIMIT ")
            .push_bind(i64::from(search.limit.unwrap_or(100).clamp(1, 1000)));
        let rows = query.build().fetch_all(&self.pool).await?;
        rows.into_iter().map(decode_audit_row).collect()
    }

    async fn collection_health(
        &self,
        limit: u32,
    ) -> Result<Vec<CollectionHealthRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, component, status, checked_at, message, agent_id, details_json
             FROM collection_health
             ORDER BY checked_at DESC, id DESC
             LIMIT ?",
        )
        .bind(i64::from(limit.clamp(1, 500)))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(decode_health_row).collect()
    }
}

async fn insert_audit_event(pool: &SqlitePool, event: &AuditEvent) -> Result<i64, StorageError> {
    let mut transaction = pool.begin().await?;
    let id = insert_audit_event_tx(&mut transaction, event).await?;
    transaction.commit().await?;
    Ok(id)
}

async fn insert_audit_event_tx(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    event: &AuditEvent,
) -> Result<i64, StorageError> {
    let raw_json = serde_json::to_string(event)?;
    let result = sqlx::query(
        "INSERT OR REPLACE INTO audit_events (
            event_id, event_type, occurred_at, source, source_confidence,
            agent_id, session_id, trace_id, span_id, parent_span_id, project_id,
            actor_kind, actor_name, risk_score, risk_level, rule_id, summary,
            raw_payload_ref, raw_json
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&event.event_id)
    .bind(json_name(&event.event_type)?)
    .bind(&event.occurred_at)
    .bind(json_name(&event.source)?)
    .bind(json_name(&event.source_confidence)?)
    .bind(&event.agent_id)
    .bind(&event.session_id)
    .bind(&event.trace_id)
    .bind(&event.span_id)
    .bind(&event.parent_span_id)
    .bind(&event.project_id)
    .bind(json_name(&event.actor.kind)?)
    .bind(&event.actor.name)
    .bind(i64::from(event.risk.score))
    .bind(&event.risk.level)
    .bind(&event.risk.rule_id)
    .bind(&event.summary)
    .bind(&event.raw_payload_ref)
    .bind(raw_json)
    .execute(&mut **transaction)
    .await?;

    sqlx::query("DELETE FROM evidence WHERE event_id = ?")
        .bind(&event.event_id)
        .execute(&mut **transaction)
        .await?;
    for evidence in &event.evidence_refs {
        let raw_json = serde_json::to_string(evidence)?;
        sqlx::query(
            "INSERT INTO evidence (evidence_id, event_id, kind, preview, raw_json)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&evidence.evidence_id)
        .bind(&event.event_id)
        .bind(&evidence.kind)
        .bind(&evidence.preview)
        .bind(raw_json)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(result.last_insert_rowid())
}

fn decode_row(row: sqlx::sqlite::SqliteRow) -> Result<StoredSecurityEvent, StorageError> {
    let occurred_at_raw: String = row.try_get("occurred_at")?;
    let occurred_at = DateTime::parse_from_rfc3339(&occurred_at_raw)
        .map_err(|error| StorageError::Timestamp(error.to_string()))?
        .with_timezone(&Utc);
    Ok(StoredSecurityEvent {
        id: row.try_get("id")?,
        occurred_at,
        event: serde_json::from_str(&row.try_get::<String, _>("raw_json")?)?,
    })
}

fn decode_audit_row(row: sqlx::sqlite::SqliteRow) -> Result<StoredAuditEvent, StorageError> {
    Ok(StoredAuditEvent {
        id: row.try_get("id")?,
        event: serde_json::from_str(&row.try_get::<String, _>("raw_json")?)?,
    })
}

fn decode_health_row(row: sqlx::sqlite::SqliteRow) -> Result<CollectionHealthRecord, StorageError> {
    let checked_at_raw: String = row.try_get("checked_at")?;
    let checked_at = DateTime::parse_from_rfc3339(&checked_at_raw)
        .map_err(|error| StorageError::Timestamp(error.to_string()))?
        .with_timezone(&Utc);
    Ok(CollectionHealthRecord {
        id: row.try_get("id")?,
        component: row.try_get("component")?,
        status: row.try_get("status")?,
        checked_at,
        message: row.try_get("message")?,
        agent_id: row.try_get("agent_id")?,
        details_json: row.try_get("details_json")?,
    })
}

fn json_name(value: &impl Serialize) -> Result<String, StorageError> {
    Ok(serde_json::to_string(value)?.trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiguard_core::{
        classify_user_input, ActorKind, AuditActor, AuditEventType, EventSource, RiskAssessment,
        SourceConfidence, SpanKind,
    };

    fn time(day: u32, hour: u32) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("2026-01-{day:02}T{hour:02}:00:00Z"))
            .expect("test timestamp")
            .with_timezone(&Utc)
    }

    #[tokio::test]
    async fn migrates_and_round_trips_events() {
        let repository = SqliteEventRepository::in_memory().await.expect("database");
        let event = classify_user_input("hello");
        let id = repository.append(time(1, 8), &event).await.expect("insert");
        assert_eq!(id, 1);
        let events = repository.recent(10).await.expect("query");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, 1);
        assert_eq!(events[0].event.rule_id, "INPUT.USER");
        assert_eq!(events[0].occurred_at, time(1, 8));
    }

    #[tokio::test]
    async fn dispositions_round_trip_and_clear_on_pending() {
        let repository = SqliteEventRepository::in_memory().await.expect("database");
        let id = repository
            .append(time(1, 8), &classify_user_input("hello"))
            .await
            .expect("insert");

        repository
            .set_event_disposition(id, "resolved", "rotated the key")
            .await
            .expect("mark resolved");
        let stored = repository.event_dispositions().await.expect("query");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].event_id, id);
        assert_eq!(stored[0].status, "resolved");
        assert_eq!(stored[0].note, "rotated the key");

        // Re-marking the same event updates in place rather than duplicating.
        repository
            .set_event_disposition(id, "ignored", "false positive")
            .await
            .expect("mark ignored");
        let stored = repository.event_dispositions().await.expect("query");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].status, "ignored");
        assert_eq!(stored[0].note, "false positive");

        // `pending` clears the mark so the event returns to the unhandled feed.
        repository
            .set_event_disposition(id, "pending", "")
            .await
            .expect("clear");
        assert!(repository
            .event_dispositions()
            .await
            .expect("query")
            .is_empty());
    }

    #[tokio::test]
    async fn batch_insert_and_since_are_parameterized() {
        let repository = SqliteEventRepository::in_memory().await.expect("database");
        let events = vec![
            (time(1, 8), classify_user_input("first")),
            (time(2, 8), classify_user_input("second")),
        ];
        repository
            .append_batch(&events)
            .await
            .expect("batch insert");
        let recent = repository.since(time(2, 0), 10).await.expect("range query");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].event.command_line, "second");
    }

    #[tokio::test]
    async fn dashboard_counts_use_stable_event_fields() {
        let repository = SqliteEventRepository::in_memory().await.expect("database");
        let mut sensitive = classify_user_input("OPENAI_API_KEY=sk-abcdefghijkl");
        sensitive.event_type = "UserInput".into();
        let mut outbound = classify_user_input("hello");
        outbound.event_type = "AgentCommand".into();
        outbound.rule_id = "DATA.SECRET.EXFIL".into();
        outbound.risk = 94;
        repository
            .append_batch(&[(time(1, 8), sensitive), (time(1, 9), outbound)])
            .await
            .expect("batch insert");
        let counts = repository
            .dashboard_counts(time(1, 0))
            .await
            .expect("counts");
        assert_eq!(
            counts,
            DashboardCounts {
                total: 2,
                input: 1,
                sensitive_input: 1,
                sensitive_outbound: 1,
                dangerous: 1,
                warning: 0
            }
        );
    }

    #[tokio::test]
    async fn reads_default_license_state() {
        let repository = SqliteEventRepository::in_memory().await.expect("database");
        let state = repository.license_state().await.expect("license state");
        assert_eq!(state.status, "Unactivated");
        assert!(state.license_id.is_none());
    }

    fn audit_event(
        event_id: &str,
        event_type: AuditEventType,
        span_id: &str,
        parent_span_id: Option<&str>,
    ) -> AuditEvent {
        let risk_score = if matches!(event_type, AuditEventType::CommandExecuted) {
            80
        } else {
            10
        };
        AuditEvent {
            event_id: event_id.into(),
            event_type,
            occurred_at: "2026-08-19T08:00:00Z".into(),
            source: EventSource::AgentHook,
            source_confidence: SourceConfidence::High,
            agent_id: Some("agent_codex".into()),
            session_id: Some("sess_1".into()),
            trace_id: Some("trace_1".into()),
            span_id: Some(span_id.into()),
            parent_span_id: parent_span_id.map(str::to_string),
            project_id: Some("proj_1".into()),
            actor: AuditActor {
                kind: ActorKind::Agent,
                name: "Codex".into(),
            },
            risk: RiskAssessment {
                score: risk_score,
                level: "Warning".into(),
                rule_id: Some("TEST.RULE".into()),
                explanation: Some("test".into()),
            },
            summary: "test event".into(),
            evidence_refs: Vec::new(),
            raw_payload_ref: None,
        }
    }

    #[tokio::test]
    async fn repairs_legacy_mojibake_in_security_and_audit_events() {
        let repository = SqliteEventRepository::in_memory().await.expect("database");
        let mut security = classify_user_input("C:/Users/test/.codex/session.jsonl");
        security.process = "閺傚洣娆㈢化鑽ょ埠".into();
        security.category = "閺傚洣娆㈢化鑽ょ埠".into();
        security.rule = "Agent 閺傚洣娆㈤崣妯绘纯".into();
        security.summary = "鐟欏倸鐧傞崚?Agent 閺佺増宓侀惄顔肩秿閺傚洣娆㈤崣妯哄".into();
        repository
            .append(time(1, 8), &security)
            .await
            .expect("security event");

        let mut audit = audit_event("evt_legacy", AuditEventType::FileAccessed, "span_1", None);
        audit.agent_id = None;
        audit.session_id = None;
        audit.trace_id = None;
        audit.span_id = None;
        audit.project_id = None;
        audit.actor.name = "闁矮绠熼悘鐢电垳".into();
        audit.summary = "鏉╂稓鈻奸崥顖氬З".into();
        repository
            .append_audit_event(&audit)
            .await
            .expect("audit event");

        repair_legacy_mojibake(repository.pool())
            .await
            .expect("repair");

        let security = repository.recent(1).await.expect("security query");
        assert_eq!(security[0].event.process, "文件系统");
        assert_eq!(security[0].event.rule, "Agent 文件变更");
        assert_eq!(security[0].event.summary, "观察到 Agent 数据目录文件变化");
        let audit = repository
            .event_detail("evt_legacy")
            .await
            .expect("audit query")
            .expect("audit row");
        assert_eq!(audit.event.actor.name, "通义灵码");
        assert_eq!(audit.event.summary, "进程启动");
    }

    async fn seed_audit_graph(repository: &SqliteEventRepository) {
        repository
            .upsert_agent(&Agent {
                agent_id: "agent_codex".into(),
                name: "Codex".into(),
                version: Some("1.0.0".into()),
                executable_path: None,
            })
            .await
            .expect("agent");
        repository
            .upsert_project(&Project {
                project_id: "proj_1".into(),
                name: "AIGuard".into(),
                root_path: "D:/mycode/hx/AIGuard".into(),
            })
            .await
            .expect("project");
        repository
            .upsert_session(&AgentSession {
                session_id: "sess_1".into(),
                agent_id: "agent_codex".into(),
                project_id: Some("proj_1".into()),
                started_at: "2026-08-19T08:00:00Z".into(),
                ended_at: None,
            })
            .await
            .expect("session");
        repository
            .upsert_trace(&Trace {
                trace_id: "trace_1".into(),
                session_id: "sess_1".into(),
                root_span_id: "span_user".into(),
                started_at: "2026-08-19T08:00:00Z".into(),
                summary: Some("user to command".into()),
            })
            .await
            .expect("trace");
        for span in [
            Span {
                span_id: "span_user".into(),
                trace_id: "trace_1".into(),
                parent_span_id: None,
                kind: SpanKind::UserInput,
                name: "prompt".into(),
                started_at: "2026-08-19T08:00:00Z".into(),
                ended_at: None,
                tool_call_id: None,
            },
            Span {
                span_id: "span_tool".into(),
                trace_id: "trace_1".into(),
                parent_span_id: Some("span_user".into()),
                kind: SpanKind::Tool,
                name: "shell".into(),
                started_at: "2026-08-19T08:00:01Z".into(),
                ended_at: None,
                tool_call_id: Some("tool_1".into()),
            },
        ] {
            repository.upsert_span(&span).await.expect("span");
        }
    }

    #[tokio::test]
    async fn migrates_new_audit_tables_and_round_trips_timeline() {
        let repository = SqliteEventRepository::in_memory().await.expect("database");
        seed_audit_graph(&repository).await;
        let events = vec![
            audit_event("evt_1", AuditEventType::UserInput, "span_user", None),
            audit_event(
                "evt_2",
                AuditEventType::ToolCallRequested,
                "span_tool",
                Some("span_user"),
            ),
        ];
        repository
            .append_audit_events(&events)
            .await
            .expect("events");

        let sessions = repository.list_sessions(10).await.expect("sessions");
        assert_eq!(sessions[0].session_id, "sess_1");

        let timeline = repository
            .session_timeline("sess_1", 10)
            .await
            .expect("timeline");
        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[0].event.event_id, "evt_1");
    }

    #[tokio::test]
    async fn filters_audit_events_by_trace_and_risk() {
        let repository = SqliteEventRepository::in_memory().await.expect("database");
        seed_audit_graph(&repository).await;
        repository
            .append_audit_event(&audit_event(
                "evt_cmd",
                AuditEventType::CommandExecuted,
                "span_tool",
                Some("span_user"),
            ))
            .await
            .expect("event");

        let trace = repository.trace_events("trace_1", 10).await.expect("trace");
        assert_eq!(trace.len(), 1);

        let found = repository
            .search_audit_events(EventSearch {
                trace_id: Some("trace_1".into()),
                min_risk: Some(70),
                limit: Some(20),
                ..EventSearch::default()
            })
            .await
            .expect("search");
        assert_eq!(found[0].event.event_id, "evt_cmd");

        let detail = repository
            .event_detail("evt_cmd")
            .await
            .expect("detail")
            .expect("event");
        assert_eq!(detail.event.event_type, AuditEventType::CommandExecuted);
    }

    #[tokio::test]
    async fn records_collection_health() {
        let repository = SqliteEventRepository::in_memory().await.expect("database");
        repository
            .record_collection_health("codex", "warning", time(1, 8), "hook missing", None, "{}")
            .await
            .expect("health");
        let health = repository.collection_health(10).await.expect("health");
        assert_eq!(health[0].component, "codex");
        assert_eq!(health[0].status, "warning");
    }
}
