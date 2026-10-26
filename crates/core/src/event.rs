use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum AuditEventType {
    UserInput,
    AgentDetected,
    SessionStarted,
    SessionEnded,
    ToolCallRequested,
    ToolCallStarted,
    ToolCallCompleted,
    ToolCallFailed,
    CommandExecuted,
    FileAccessed,
    NetworkAccessed,
    McpConnected,
    McpToolCalled,
    RiskDetected,
    CollectionHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum EventSource {
    AgentHook,
    McpGateway,
    ProcessSensor,
    FileSensor,
    NetworkSensor,
    UserInput,
    LogParser,
    SystemInference,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum SourceConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum ActorKind {
    User,
    Agent,
    Tool,
    System,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditActor {
    pub kind: ActorKind,
    pub name: String,
}

impl AuditActor {
    pub fn unknown() -> Self {
        Self {
            kind: ActorKind::Unknown,
            name: "unknown".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskAssessment {
    pub score: u8,
    pub level: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

impl RiskAssessment {
    pub fn none() -> Self {
        Self {
            score: 0,
            level: "None".into(),
            rule_id: None,
            explanation: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRef {
    pub evidence_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_id: String,
    pub event_type: AuditEventType,
    pub occurred_at: String,
    pub source: EventSource,
    pub source_confidence: SourceConfidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    pub actor: AuditActor,
    pub risk: RiskAssessment,
    pub summary: String,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_payload_ref: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_stable_audit_event_shape() {
        let event = AuditEvent {
            event_id: "evt_1".into(),
            event_type: AuditEventType::UserInput,
            occurred_at: "2026-08-19T00:00:00Z".into(),
            source: EventSource::UserInput,
            source_confidence: SourceConfidence::High,
            agent_id: Some("agent_codex".into()),
            session_id: Some("sess_1".into()),
            trace_id: Some("trace_1".into()),
            span_id: Some("span_1".into()),
            parent_span_id: None,
            project_id: Some("proj_1".into()),
            actor: AuditActor {
                kind: ActorKind::User,
                name: "local-user".into(),
            },
            risk: RiskAssessment::none(),
            summary: "Recorded user input.".into(),
            evidence_refs: vec![EvidenceRef {
                evidence_id: "evd_1".into(),
                kind: "prompt".into(),
                preview: Some("hello".into()),
            }],
            raw_payload_ref: None,
        };

        let json = serde_json::to_string(&event).expect("json");
        assert!(json.contains("\"event_type\":\"UserInput\""));
        assert!(json.contains("\"source_confidence\":\"High\""));
        assert!(!json.contains("parent_span_id"));
        assert!(!json.contains("raw_payload_ref"));
    }

    #[test]
    fn missing_optional_fields_deserialize() {
        let json = r#"{
            "event_id":"evt_1",
            "event_type":"CollectionHealth",
            "occurred_at":"2026-08-19T00:00:00Z",
            "source":"Internal",
            "source_confidence":"Medium",
            "actor":{"kind":"System","name":"aiguard"},
            "risk":{"score":0,"level":"None"},
            "summary":"health check"
        }"#;

        let event: AuditEvent = serde_json::from_str(json).expect("event");
        assert_eq!(event.event_type, AuditEventType::CollectionHealth);
        assert!(event.agent_id.is_none());
        assert!(event.evidence_refs.is_empty());
    }

    #[test]
    fn event_type_round_trips() {
        let kinds = [
            AuditEventType::UserInput,
            AuditEventType::AgentDetected,
            AuditEventType::SessionStarted,
            AuditEventType::SessionEnded,
            AuditEventType::ToolCallRequested,
            AuditEventType::ToolCallStarted,
            AuditEventType::ToolCallCompleted,
            AuditEventType::ToolCallFailed,
            AuditEventType::CommandExecuted,
            AuditEventType::FileAccessed,
            AuditEventType::NetworkAccessed,
            AuditEventType::McpConnected,
            AuditEventType::McpToolCalled,
            AuditEventType::RiskDetected,
            AuditEventType::CollectionHealth,
        ];

        for kind in kinds {
            let json = serde_json::to_string(&kind).expect("json");
            let decoded: AuditEventType = serde_json::from_str(&json).expect("decoded");
            assert_eq!(decoded, kind);
        }
    }
}
