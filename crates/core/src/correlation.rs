use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationInput {
    pub event_id: String,
    pub occurred_at_ms: i64,
    pub session_id: Option<String>,
    pub trace_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationResult {
    pub event_id: String,
    pub related_event_id: Option<String>,
    pub confidence: CorrelationConfidence,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum CorrelationConfidence {
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceCorrelator {
    time_window_ms: i64,
}

impl Default for TraceCorrelator {
    fn default() -> Self {
        Self {
            time_window_ms: 5_000,
        }
    }
}

impl TraceCorrelator {
    pub fn new(time_window_ms: i64) -> Self {
        Self { time_window_ms }
    }

    pub fn correlate(
        &self,
        event: &CorrelationInput,
        candidates: &[CorrelationInput],
    ) -> CorrelationResult {
        if let Some(candidate) = candidates.iter().find(|candidate| {
            explicit_match(event.session_id.as_deref(), candidate.session_id.as_deref())
                || explicit_match(event.trace_id.as_deref(), candidate.trace_id.as_deref())
                || explicit_match(
                    event.tool_call_id.as_deref(),
                    candidate.tool_call_id.as_deref(),
                )
        }) {
            return result(event, candidate, CorrelationConfidence::High, "explicit id");
        }

        if let Some(candidate) = candidates.iter().find(|candidate| {
            event.parent_process_id.is_some()
                && event.parent_process_id == candidate.process_id
                && event.cwd.is_some()
                && event.cwd == candidate.cwd
        }) {
            return result(
                event,
                candidate,
                CorrelationConfidence::Medium,
                "process and cwd",
            );
        }

        if let Some(candidate) = candidates
            .iter()
            .filter(|candidate| {
                (event.occurred_at_ms - candidate.occurred_at_ms).abs() <= self.time_window_ms
            })
            .min_by_key(|candidate| (event.occurred_at_ms - candidate.occurred_at_ms).abs())
        {
            return result(event, candidate, CorrelationConfidence::Low, "time window");
        }

        CorrelationResult {
            event_id: event.event_id.clone(),
            related_event_id: None,
            confidence: CorrelationConfidence::None,
            reason: "unrelated".into(),
        }
    }
}

fn explicit_match(left: Option<&str>, right: Option<&str>) -> bool {
    left.is_some() && left == right
}

fn result(
    event: &CorrelationInput,
    candidate: &CorrelationInput,
    confidence: CorrelationConfidence,
    reason: &str,
) -> CorrelationResult {
    CorrelationResult {
        event_id: event.event_id.clone(),
        related_event_id: Some(candidate.event_id.clone()),
        confidence,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(event_id: &str, occurred_at_ms: i64) -> CorrelationInput {
        CorrelationInput {
            event_id: event_id.into(),
            occurred_at_ms,
            session_id: None,
            trace_id: None,
            tool_call_id: None,
            process_id: None,
            parent_process_id: None,
            cwd: None,
        }
    }

    #[test]
    fn explicit_ids_win_with_high_confidence() {
        let mut event = input("cmd", 10_000);
        event.trace_id = Some("trace_1".into());
        let mut candidate = input("prompt", 1);
        candidate.trace_id = Some("trace_1".into());

        let result = TraceCorrelator::default().correlate(&event, &[candidate]);
        assert_eq!(result.related_event_id.as_deref(), Some("prompt"));
        assert_eq!(result.confidence, CorrelationConfidence::High);
    }

    #[test]
    fn process_and_cwd_are_medium_confidence() {
        let mut event = input("child", 10_000);
        event.parent_process_id = Some(7);
        event.cwd = Some("D:/repo".into());
        let mut candidate = input("parent", 1);
        candidate.process_id = Some(7);
        candidate.cwd = Some("D:/repo".into());

        let result = TraceCorrelator::default().correlate(&event, &[candidate]);
        assert_eq!(result.confidence, CorrelationConfidence::Medium);
    }

    #[test]
    fn time_window_is_low_confidence_fallback() {
        let result =
            TraceCorrelator::new(100).correlate(&input("later", 1_050), &[input("earlier", 1_000)]);
        assert_eq!(result.related_event_id.as_deref(), Some("earlier"));
        assert_eq!(result.confidence, CorrelationConfidence::Low);
    }

    #[test]
    fn unrelated_events_are_kept_without_match() {
        let result =
            TraceCorrelator::new(100).correlate(&input("later", 10_000), &[input("old", 1_000)]);
        assert!(result.related_event_id.is_none());
        assert_eq!(result.confidence, CorrelationConfidence::None);
    }
}
