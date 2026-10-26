use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::{
    ActorKind, AuditActor, AuditEvent, AuditEventType, EventSource, RiskAssessment,
    SourceConfidence,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentEnvironment {
    pub installed_commands: HashSet<String>,
    pub existing_paths: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDetection {
    pub agent_id: String,
    pub display_name: String,
    pub installed: bool,
    pub version: Option<String>,
    pub config_locations: Vec<String>,
    pub status: AdapterStatus,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum AdapterStatus {
    NotInstalled,
    Found,
    ConfigMissing,
    HookMissing,
    Healthy,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorCheck {
    pub name: String,
    pub status: DoctorStatus,
    pub message: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum DoctorStatus {
    Pass,
    Warning,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookPayload {
    pub agent_id: String,
    pub session_id: Option<String>,
    pub tool_name: Option<String>,
    pub command: Option<String>,
    pub cwd: Option<String>,
    pub timestamp: String,
    pub raw_payload_ref: Option<String>,
}

pub trait AgentAdapter {
    fn agent_id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn detect(&self, env: &AgentEnvironment) -> AgentDetection;
    fn version(&self, env: &AgentEnvironment) -> Option<String>;
    fn config_locations(&self) -> Vec<String>;
    fn health_check(&self, env: &AgentEnvironment) -> Vec<DoctorCheck>;
    fn parse_event(&self, payload: &HookPayload) -> AuditEvent;
}

#[derive(Debug, Clone, Copy)]
pub struct StaticAgentAdapter {
    agent_id: &'static str,
    display_name: &'static str,
    command: &'static str,
    config_path: &'static str,
    hook_marker: &'static str,
}

impl StaticAgentAdapter {
    pub const fn new(
        agent_id: &'static str,
        display_name: &'static str,
        command: &'static str,
        config_path: &'static str,
        hook_marker: &'static str,
    ) -> Self {
        Self {
            agent_id,
            display_name,
            command,
            config_path,
            hook_marker,
        }
    }
}

impl AgentAdapter for StaticAgentAdapter {
    fn agent_id(&self) -> &'static str {
        self.agent_id
    }

    fn display_name(&self) -> &'static str {
        self.display_name
    }

    fn detect(&self, env: &AgentEnvironment) -> AgentDetection {
        let installed = env.installed_commands.contains(self.command);
        let config_exists = env.existing_paths.contains(self.config_path);
        let hook_exists = env.existing_paths.contains(self.hook_marker);
        let status = if !installed {
            AdapterStatus::NotInstalled
        } else if !config_exists {
            AdapterStatus::ConfigMissing
        } else if !hook_exists {
            AdapterStatus::HookMissing
        } else {
            AdapterStatus::Healthy
        };
        AgentDetection {
            agent_id: self.agent_id.into(),
            display_name: self.display_name.into(),
            installed,
            version: self.version(env),
            config_locations: self.config_locations(),
            message: adapter_message(&status),
            status,
        }
    }

    fn version(&self, env: &AgentEnvironment) -> Option<String> {
        env.installed_commands
            .contains(self.command)
            .then(|| "detected".into())
    }

    fn config_locations(&self) -> Vec<String> {
        vec![self.config_path.into(), self.hook_marker.into()]
    }

    fn health_check(&self, env: &AgentEnvironment) -> Vec<DoctorCheck> {
        vec![
            check(
                "agent installed",
                env.installed_commands.contains(self.command),
                "Agent executable found",
                "Install the Agent CLI and make it available on PATH",
            ),
            check(
                "config exists",
                env.existing_paths.contains(self.config_path),
                "Agent config path exists",
                "Create or repair the Agent config",
            ),
            check(
                "hook enabled",
                env.existing_paths.contains(self.hook_marker),
                "AIGuard hook marker exists",
                "Enable AIGuard hook for this Agent",
            ),
        ]
    }

    fn parse_event(&self, payload: &HookPayload) -> AuditEvent {
        let summary = payload
            .command
            .as_ref()
            .map(|command| format!("{} requested command: {command}", self.display_name))
            .unwrap_or_else(|| format!("{} hook event", self.display_name));
        AuditEvent {
            event_id: format!("evt_{}_{}", self.agent_id, stable_suffix(&summary)),
            event_type: if payload.command.is_some() {
                AuditEventType::CommandExecuted
            } else {
                AuditEventType::ToolCallRequested
            },
            occurred_at: payload.timestamp.clone(),
            source: EventSource::AgentHook,
            source_confidence: SourceConfidence::High,
            agent_id: Some(self.agent_id.into()),
            session_id: payload.session_id.clone(),
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            project_id: payload.cwd.clone(),
            actor: AuditActor {
                kind: ActorKind::Agent,
                name: self.display_name.into(),
            },
            risk: RiskAssessment::none(),
            summary,
            evidence_refs: Vec::new(),
            raw_payload_ref: payload.raw_payload_ref.clone(),
        }
    }
}

pub fn builtin_adapters() -> Vec<StaticAgentAdapter> {
    vec![
        StaticAgentAdapter::new(
            "codex",
            "Codex",
            "codex",
            "~/.codex",
            "~/.codex/aiguard-hook",
        ),
        StaticAgentAdapter::new(
            "claude_code",
            "Claude Code",
            "claude",
            "~/.claude",
            "~/.claude/aiguard-hook",
        ),
        StaticAgentAdapter::new(
            "cursor",
            "Cursor",
            "cursor",
            "~/.cursor",
            "~/.cursor/aiguard-hook",
        ),
        StaticAgentAdapter::new("generic_cli", "Generic CLI", "sh", ".", ".aiguard-hook"),
    ]
}

pub fn doctor_collection_event(
    adapter: &impl AgentAdapter,
    checks: &[DoctorCheck],
    occurred_at: &str,
) -> AuditEvent {
    let failed = checks
        .iter()
        .filter(|check| check.status == DoctorStatus::Fail)
        .count();
    AuditEvent {
        event_id: format!("evt_health_{}", adapter.agent_id()),
        event_type: AuditEventType::CollectionHealth,
        occurred_at: occurred_at.into(),
        source: EventSource::Internal,
        source_confidence: SourceConfidence::High,
        agent_id: Some(adapter.agent_id().into()),
        session_id: None,
        trace_id: None,
        span_id: None,
        parent_span_id: None,
        project_id: None,
        actor: AuditActor {
            kind: ActorKind::System,
            name: "AIGuard".into(),
        },
        risk: RiskAssessment {
            score: if failed == 0 { 0 } else { 30 },
            level: if failed == 0 { "None" } else { "Warning" }.into(),
            rule_id: Some("COLLECTION.HEALTH".into()),
            explanation: Some(format!("{failed} failed checks")),
        },
        summary: format!("{} adapter health checked", adapter.display_name()),
        evidence_refs: Vec::new(),
        raw_payload_ref: None,
    }
}

fn check(name: &str, passed: bool, ok: &str, suggestion: &str) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status: if passed {
            DoctorStatus::Pass
        } else {
            DoctorStatus::Fail
        },
        message: if passed { ok } else { suggestion }.into(),
        suggestion: (!passed).then(|| suggestion.into()),
    }
}

fn adapter_message(status: &AdapterStatus) -> String {
    match status {
        AdapterStatus::NotInstalled => "Agent not installed",
        AdapterStatus::Found => "Agent found",
        AdapterStatus::ConfigMissing => "Agent config missing",
        AdapterStatus::HookMissing => "AIGuard hook missing",
        AdapterStatus::Healthy => "Agent adapter healthy",
        AdapterStatus::Error => "Agent adapter error",
    }
    .into()
}

fn stable_suffix(value: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(commands: &[&str], paths: &[&str]) -> AgentEnvironment {
        AgentEnvironment {
            installed_commands: commands.iter().map(|value| (*value).into()).collect(),
            existing_paths: paths.iter().map(|value| (*value).into()).collect(),
        }
    }

    #[test]
    fn not_installed_agent_is_not_error() {
        let codex = builtin_adapters()[0];
        let detection = codex.detect(&env(&[], &[]));
        assert_eq!(detection.status, AdapterStatus::NotInstalled);
        assert!(!detection.installed);
    }

    #[test]
    fn config_missing_is_explicit_status() {
        let codex = builtin_adapters()[0];
        let detection = codex.detect(&env(&["codex"], &[]));
        assert_eq!(detection.status, AdapterStatus::ConfigMissing);
        assert_eq!(detection.config_locations.len(), 2);
    }

    #[test]
    fn doctor_reports_hook_failure_with_suggestion() {
        let codex = builtin_adapters()[0];
        let checks = codex.health_check(&env(&["codex"], &["~/.codex"]));
        assert_eq!(checks[2].status, DoctorStatus::Fail);
        assert!(checks[2].suggestion.is_some());
    }

    #[test]
    fn simulated_hook_payload_becomes_audit_event() {
        let codex = builtin_adapters()[0];
        let event = codex.parse_event(&HookPayload {
            agent_id: "codex".into(),
            session_id: Some("sess_1".into()),
            tool_name: Some("shell".into()),
            command: Some("git status".into()),
            cwd: Some("proj_1".into()),
            timestamp: "2026-08-19T00:00:00Z".into(),
            raw_payload_ref: Some("raw_1".into()),
        });
        assert_eq!(event.event_type, AuditEventType::CommandExecuted);
        assert_eq!(event.agent_id.as_deref(), Some("codex"));
        assert_eq!(event.session_id.as_deref(), Some("sess_1"));
    }

    #[test]
    fn doctor_result_can_be_collection_health_event() {
        let codex = builtin_adapters()[0];
        let checks = codex.health_check(&env(&["codex"], &["~/.codex"]));
        let event = doctor_collection_event(&codex, &checks, "2026-08-19T00:00:00Z");
        assert_eq!(event.event_type, AuditEventType::CollectionHealth);
        assert_eq!(event.risk.score, 30);
    }
}
