use chrono::{DateTime, Utc};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptRecord {
    pub actor: String,
    pub text: String,
    pub session_id: Option<String>,
    pub project: Option<String>,
    pub occurred_at: Option<DateTime<Utc>>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandRecord {
    pub status: String,
    pub raw: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileChangeRecord {
    pub path: String,
    pub kind: String,
}

#[derive(Debug, Default)]
pub struct EventDeduplicator {
    seen: HashMap<u64, u64>,
}

#[derive(Debug)]
pub struct BoundedQueue<T> {
    items: VecDeque<T>,
    capacity: usize,
    dropped: u64,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            items: VecDeque::with_capacity(capacity),
            capacity: capacity.max(1),
            dropped: 0,
        }
    }

    pub fn push(&mut self, item: T) {
        if self.items.len() >= self.capacity {
            self.items.pop_front();
            self.dropped += 1;
        }
        self.items.push_back(item);
    }

    pub fn take_batch(&mut self, limit: usize) -> Vec<T> {
        (0..limit.min(self.items.len()))
            .filter_map(|_| self.items.pop_front())
            .collect()
    }

    pub fn restore_front(&mut self, items: Vec<T>) {
        for item in items.into_iter().rev() {
            self.items.push_front(item);
        }
        while self.items.len() > self.capacity {
            self.items.pop_back();
            self.dropped += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[derive(Debug, Clone)]
struct CorrelationEntry {
    session_id: Option<String>,
    project: Option<String>,
    correlation_id: String,
    seen_at: u64,
}

#[derive(Debug, Clone, Default)]
pub struct CorrelationTracker {
    latest: HashMap<String, CorrelationEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationMatch {
    pub session_id: Option<String>,
    pub project: Option<String>,
    pub correlation_id: String,
}

impl CorrelationTracker {
    pub fn register_prompt(&mut self, record: &PromptRecord) -> CorrelationMatch {
        use std::hash::{Hash, Hasher};
        let now = unix_seconds();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        record.actor.hash(&mut hasher);
        record.session_id.hash(&mut hasher);
        record.text.hash(&mut hasher);
        now.hash(&mut hasher);
        let matched = CorrelationMatch {
            session_id: record.session_id.clone(),
            project: record.project.clone(),
            correlation_id: format!("corr-{:016x}", hasher.finish()),
        };
        self.latest.insert(
            record.actor.clone(),
            CorrelationEntry {
                session_id: matched.session_id.clone(),
                project: matched.project.clone(),
                correlation_id: matched.correlation_id.clone(),
                seen_at: now,
            },
        );
        matched
    }

    pub fn correlate_command(&self, actor: &str) -> Option<CorrelationMatch> {
        let entry = self.latest.get(actor)?;
        if unix_seconds().saturating_sub(entry.seen_at) > 30 * 60 {
            return None;
        }
        Some(CorrelationMatch {
            session_id: entry.session_id.clone(),
            project: entry.project.clone(),
            correlation_id: entry.correlation_id.clone(),
        })
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl EventDeduplicator {
    pub fn accept(
        &mut self,
        actor: &str,
        event_type: &str,
        command_line: &str,
        evidence: &str,
    ) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let bucket = now / 10;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        actor.hash(&mut hasher);
        event_type.hash(&mut hasher);
        command_line.hash(&mut hasher);
        evidence.hash(&mut hasher);
        let key = hasher.finish();
        self.seen
            .retain(|_, seen_bucket| bucket.saturating_sub(*seen_bucket) <= 6);
        if self.seen.contains_key(&key) {
            return false;
        }
        self.seen.insert(key, bucket);
        true
    }
}

pub struct FileChangeWatcher {
    _watcher: RecommendedWatcher,
    receiver: Receiver<Result<Event, notify::Error>>,
}

impl FileChangeWatcher {
    pub fn start(paths: &[PathBuf]) -> Result<Self, MonitorError> {
        let (sender, receiver) = mpsc::channel();
        let mut watcher = RecommendedWatcher::new(sender, Config::default())
            .map_err(|error| MonitorError::Notify(error.to_string()))?;
        for path in paths.iter().filter(|path| path.is_dir()) {
            watcher
                .watch(path, RecursiveMode::Recursive)
                .map_err(|error| MonitorError::Notify(error.to_string()))?;
        }
        Ok(Self {
            _watcher: watcher,
            receiver,
        })
    }

    pub fn drain(&self) -> Vec<FileChangeRecord> {
        let mut records = Vec::new();
        while let Ok(result) = self.receiver.try_recv() {
            let Ok(event) = result else {
                continue;
            };
            let kind = match event.kind {
                EventKind::Create(_) => "Created",
                EventKind::Modify(_) => "Changed",
                EventKind::Remove(_) => "Deleted",
                _ => "Observed",
            };
            records.extend(event.paths.into_iter().map(|path| FileChangeRecord {
                path: path.to_string_lossy().into_owned(),
                kind: kind.into(),
            }));
        }
        records
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReaderState {
    offsets: HashMap<PathBuf, u64>,
    markers: HashMap<PathBuf, String>,
}

#[derive(Debug, Clone)]
pub struct CodexCommandSource {
    pub path: PathBuf,
}

impl CodexCommandSource {
    pub fn read_new(&self, state: &mut ReaderState) -> Result<Vec<CommandRecord>, MonitorError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let mut file = File::open(&self.path)?;
        let length = file.metadata()?.len();
        let offset = state.offsets.entry(self.path.clone()).or_insert(0);
        if length < *offset {
            *offset = 0;
        }
        file.seek(SeekFrom::Start(*offset))?;
        let mut reader = BufReader::new(file);
        let mut records = Vec::new();
        loop {
            let mut bytes = Vec::new();
            if reader.read_until(b'\n', &mut bytes)? == 0 {
                break;
            }
            *offset = reader.stream_position()?;
            let line = String::from_utf8_lossy(&bytes);
            let Some((status, raw)) = line.trim().split_once(':') else {
                continue;
            };
            let status = status.trim().to_uppercase();
            if !matches!(status.as_str(), "START" | "SUCCESS" | "FAILURE") || raw.trim().is_empty()
            {
                continue;
            }
            records.push(CommandRecord {
                status,
                raw: raw.trim().to_string(),
                source: "Codex sandbox_commands.rust.log".into(),
            });
        }
        Ok(records)
    }

    pub fn prime(&self, state: &mut ReaderState) -> Result<(), MonitorError> {
        let offset = if self.path.exists() {
            std::fs::metadata(&self.path)?.len()
        } else {
            0
        };
        state.offsets.insert(self.path.clone(), offset);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct OpenHandsSource {
    pub root: PathBuf,
}

impl OpenHandsSource {
    pub fn prime(&self, state: &mut ReaderState) -> Result<(), MonitorError> {
        if !self.root.exists() {
            return Ok(());
        }
        let mut files = Vec::new();
        collect_json_files(&self.root, &mut files)?;
        for path in files {
            let metadata = std::fs::metadata(&path)?;
            let marker = format!(
                "{}:{}",
                metadata.len(),
                metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |duration| duration.as_nanos())
            );
            state.markers.insert(path, marker);
        }
        Ok(())
    }

    pub fn read_new(&self, state: &mut ReaderState) -> Result<Vec<PromptRecord>, MonitorError> {
        let mut records = Vec::new();
        if !self.root.exists() {
            return Ok(records);
        }
        let mut files = Vec::new();
        collect_json_files(&self.root, &mut files)?;
        for path in files {
            let metadata = std::fs::metadata(&path)?;
            let marker = format!(
                "{}:{}",
                metadata.len(),
                metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |duration| duration.as_nanos())
            );
            if state.markers.get(&path) == Some(&marker) {
                continue;
            }
            state.markers.insert(path.clone(), marker);
            let bytes = std::fs::read(&path)?;
            let raw = String::from_utf8_lossy(&bytes);
            let Ok(value) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            if value.get("kind").and_then(Value::as_str) != Some("MessageEvent")
                || value.get("source").and_then(Value::as_str) != Some("user")
                || value.get("role").and_then(Value::as_str) != Some("user")
            {
                continue;
            }
            let Some(text) = value
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
            else {
                continue;
            };
            records.push(PromptRecord {
                actor: "OpenHands".into(),
                text: text.into(),
                session_id: path
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    .map(str::to_string),
                project: None,
                occurred_at: value.get("timestamp").and_then(parse_time),
                source: "OpenHands MessageEvent".into(),
            });
        }
        Ok(records)
    }
}

fn collect_json_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), MonitorError> {
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_json_files(&path, files)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            files.push(path);
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("monitor I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("monitor watcher failed: {0}")]
    Notify(String),
}

#[derive(Debug, Clone)]
pub struct JsonlPromptSource {
    pub path: PathBuf,
    pub actor: String,
    pub text_key: String,
    pub session_key: String,
    pub project_key: Option<String>,
    pub time_key: String,
    pub source: String,
}

impl JsonlPromptSource {
    pub fn prime(&self, state: &mut ReaderState) -> Result<(), MonitorError> {
        let offset = if self.path.exists() {
            std::fs::metadata(&self.path)?.len()
        } else {
            0
        };
        state.offsets.insert(self.path.clone(), offset);
        Ok(())
    }

    pub fn read_new(&self, state: &mut ReaderState) -> Result<Vec<PromptRecord>, MonitorError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let mut file = File::open(&self.path)?;
        let length = file.metadata()?.len();
        let offset = state.offsets.entry(self.path.clone()).or_insert(0);
        if length < *offset {
            *offset = 0;
        }
        file.seek(SeekFrom::Start(*offset))?;
        let mut reader = BufReader::new(file);
        let mut records = Vec::new();
        loop {
            let mut bytes = Vec::new();
            if reader.read_until(b'\n', &mut bytes)? == 0 {
                break;
            }
            let after = reader.stream_position()?;
            *offset = after;
            let line = String::from_utf8_lossy(&bytes);
            let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
                continue;
            };
            let Some(text) = value
                .get(&self.text_key)
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
            else {
                continue;
            };
            records.push(PromptRecord {
                actor: self.actor.clone(),
                text: text.to_string(),
                session_id: value
                    .get(&self.session_key)
                    .and_then(Value::as_str)
                    .map(str::to_string),
                project: self
                    .project_key
                    .as_ref()
                    .and_then(|key| value.get(key))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                occurred_at: value.get(&self.time_key).and_then(parse_time),
                source: self.source.clone(),
            });
        }
        Ok(records)
    }
}

fn parse_time(value: &Value) -> Option<DateTime<Utc>> {
    value
        .as_str()
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map(|time| time.with_timezone(&Utc))
        .or_else(|| {
            value
                .as_i64()
                .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        })
}

pub fn codex_source(path: impl AsRef<Path>) -> JsonlPromptSource {
    JsonlPromptSource {
        path: path.as_ref().to_path_buf(),
        actor: "Codex".into(),
        text_key: "text".into(),
        session_key: "session_id".into(),
        project_key: None,
        time_key: "ts".into(),
        source: "Codex history.jsonl".into(),
    }
}

pub fn claude_source(path: impl AsRef<Path>) -> JsonlPromptSource {
    JsonlPromptSource {
        path: path.as_ref().to_path_buf(),
        actor: "Claude Code".into(),
        text_key: "display".into(),
        session_key: "sessionId".into(),
        project_key: Some("project".into()),
        time_key: "timestamp".into(),
        source: "Claude Code history.jsonl".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_file() -> PathBuf {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("aiguard-monitor-{id}.jsonl"))
    }

    #[test]
    fn reads_only_new_jsonl_records() {
        let path = temp_file();
        let mut file = File::create(&path).unwrap();
        writeln!(
            file,
            r#"{{"text":"first","session_id":"s1","ts":"2026-08-18T00:00:00Z"}}"#
        )
        .unwrap();
        let source = codex_source(&path);
        let mut state = ReaderState::default();
        assert_eq!(source.read_new(&mut state).unwrap().len(), 1);
        assert!(source.read_new(&mut state).unwrap().is_empty());
        writeln!(file, r#"{{"text":"second","session_id":"s1"}}"#).unwrap();
        file.flush().unwrap();
        assert_eq!(source.read_new(&mut state).unwrap()[0].text, "second");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn resets_offset_after_log_truncation_and_skips_bad_lines() {
        let path = temp_file();
        fs::write(&path, "not-json\n{\"display\":\"before\"}\n").unwrap();
        let source = claude_source(&path);
        let mut state = ReaderState::default();
        assert_eq!(source.read_new(&mut state).unwrap().len(), 1);
        fs::write(&path, "{\"display\":\"after\"}\n").unwrap();
        assert_eq!(source.read_new(&mut state).unwrap()[0].text, "after");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn reads_codex_command_status_lines() {
        let path = temp_file();
        fs::write(
            &path,
            "START: git status\nignored line\nFAILURE: git reset --hard HEAD\n",
        )
        .unwrap();
        let source = CodexCommandSource { path: path.clone() };
        let mut state = ReaderState::default();
        let records = source.read_new(&mut state).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].status, "FAILURE");
        assert_eq!(records[1].raw, "git reset --hard HEAD");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn reads_openhands_user_message() {
        let root = std::env::temp_dir().join(format!(
            "aiguard-openhands-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let session = root.join("session-1");
        fs::create_dir_all(&session).unwrap();
        fs::write(session.join("event.json"), r#"{"kind":"MessageEvent","source":"user","role":"user","text":"inspect the repo","timestamp":"2026-08-18T00:00:00Z"}"#).unwrap();
        let source = OpenHandsSource { root: root.clone() };
        let mut state = ReaderState::default();
        let records = source.read_new(&mut state).unwrap();
        assert_eq!(records[0].actor, "OpenHands");
        assert_eq!(records[0].session_id.as_deref(), Some("session-1"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bounded_queue_survives_event_burst() {
        let mut queue = BoundedQueue::new(1_000);
        for value in 0..10_000 {
            queue.push(value);
        }
        assert_eq!(queue.len(), 1_000);
        assert_eq!(queue.dropped(), 9_000);
        let batch = queue.take_batch(500);
        assert_eq!(batch.len(), 500);
        queue.restore_front(batch);
        assert_eq!(queue.len(), 1_000);
    }

    #[test]
    fn correlates_recent_command_with_prompt() {
        let mut tracker = CorrelationTracker::default();
        let record = PromptRecord {
            actor: "Codex".into(),
            text: "inspect".into(),
            session_id: Some("session-1".into()),
            project: Some("repo".into()),
            occurred_at: None,
            source: "test".into(),
        };
        let prompt = tracker.register_prompt(&record);
        let command = tracker.correlate_command("Codex").unwrap();
        assert_eq!(prompt.correlation_id, command.correlation_id);
        assert_eq!(command.session_id.as_deref(), Some("session-1"));
    }
}
