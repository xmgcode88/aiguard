use serde::{Deserialize, Serialize};

use crate::event::{AuditEvent, AuditEventType};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Agent {
    pub agent_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Project {
    pub project_id: String,
    pub name: String,
    pub root_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSession {
    pub session_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Trace {
    pub trace_id: String,
    pub session_id: String,
    pub root_span_id: String,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum SpanKind {
    UserInput,
    Model,
    Tool,
    Command,
    File,
    Network,
    Mcp,
    Guardrail,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Span {
    pub span_id: String,
    pub trace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub kind: SpanKind,
    pub name: String,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl Span {
    pub fn contains_event(&self, event: &AuditEvent) -> bool {
        event.trace_id.as_deref() == Some(self.trace_id.as_str())
            && event.span_id.as_deref() == Some(self.span_id.as_str())
    }
}

pub fn validate_event_chain(events: &[AuditEvent]) -> bool {
    if events.iter().any(|event| {
        event.session_id.is_none() || event.trace_id.is_none() || event.span_id.is_none()
    }) {
        return false;
    }

    events.windows(2).all(|pair| {
        let previous = &pair[0];
        let current = &pair[1];
        previous.session_id == current.session_id
            && previous.trace_id == current.trace_id
            && current.parent_span_id == previous.span_id
    })
}

pub fn is_tool_to_command_chain(events: &[AuditEvent]) -> bool {
    matches!(
        events,
        [
            AuditEvent {
                event_type: AuditEventType::UserInput,
                ..
            },
            AuditEvent {
                event_type: AuditEventType::ToolCallRequested,
                ..
            },
            AuditEvent {
                event_type: AuditEventType::CommandExecuted,
                ..
            }
        ]
    ) && validate_event_chain(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ActorKind, AuditActor, EventSource, RiskAssessment, SourceConfidence};

    fn event(
        event_id: &str,
        event_type: AuditEventType,
        span_id: &str,
        parent_span_id: Option<&str>,
    ) -> AuditEvent {
        AuditEvent {
            event_id: event_id.into(),
            event_type,
            occurred_at: "2026-08-19T00:00:00Z".into(),
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
            risk: RiskAssessment::none(),
            summary: "event".into(),
            evidence_refs: Vec::new(),
            raw_payload_ref: None,
        }
    }

    #[test]
    fn serializes_relationship_types_without_losing_ids() {
        let session = AgentSession {
            session_id: "sess_1".into(),
            agent_id: "agent_codex".into(),
            project_id: Some("proj_1".into()),
            started_at: "2026-08-19T00:00:00Z".into(),
            ended_at: None,
        };
        let json = serde_json::to_string(&session).expect("json");
        let decoded: AgentSession = serde_json::from_str(&json).expect("decoded");
        assert_eq!(decoded.session_id, "sess_1");
        assert_eq!(decoded.project_id.as_deref(), Some("proj_1"));
    }

    #[test]
    fn constructs_user_tool_command_chain() {
        let user = event("evt_1", AuditEventType::UserInput, "span_user", None);
        let tool = event(
            "evt_2",
            AuditEventType::ToolCallRequested,
            "span_tool",
            Some("span_user"),
        );
        let command = event(
            "evt_3",
            AuditEventType::CommandExecuted,
            "span_command",
            Some("span_tool"),
        );

        assert!(is_tool_to_command_chain(&[user, tool, command]));
    }

    #[test]
    fn rejects_time_only_chain_without_ids() {
        let mut user = event("evt_1", AuditEventType::UserInput, "span_user", None);
        let mut tool = event(
            "evt_2",
            AuditEventType::ToolCallRequested,
            "span_tool",
            Some("span_user"),
        );
        user.trace_id = None;
        tool.trace_id = None;

        assert!(!validate_event_chain(&[user, tool]));
    }

    #[test]
    fn span_matches_explicit_event_ids() {
        let span = Span {
            span_id: "span_tool".into(),
            trace_id: "trace_1".into(),
            parent_span_id: Some("span_user".into()),
            kind: SpanKind::Tool,
            name: "shell".into(),
            started_at: "2026-08-19T00:00:00Z".into(),
            ended_at: None,
            tool_call_id: Some("tool_1".into()),
        };
        let event = event(
            "evt_2",
            AuditEventType::ToolCallRequested,
            "span_tool",
            Some("span_user"),
        );

        assert!(span.contains_event(&event));
    }
}
