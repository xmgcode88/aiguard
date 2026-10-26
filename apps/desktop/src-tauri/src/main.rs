use aiguard_core::{
    apply_custom_sensitive_rules, classify_command, classify_model_output, classify_user_input,
    SecurityContext, SecurityEvent,
};
use aiguard_diagnostics::{
    diagnose, local_ai_diagnose, network_diagnose, AiDiagnosis, NetworkCheck, WorkspaceDiagnosis,
};
use aiguard_license::{
    evaluate_stored_certificate, save_protected_text, verify_update_manifest, ActivateRequest,
    DeviceIdentity, LicenseApiClient, LicenseStatus, UpdateManifest,
};
use aiguard_gateway::{Channel, ChannelInput, ChannelTestResult, Gateway, DEFAULT_LISTEN_ADDR};
use aiguard_monitor::{
    claude_source, codex_source, BoundedQueue, CodexCommandSource, CorrelationTracker,
    FileChangeRecord, FileChangeWatcher, JsonlPromptSource, OpenHandsSource, PromptRecord,
    ReaderState,
};
use aiguard_platform::{
    windows::{WindowsProcessEventSource, WindowsProcessService, WindowsSystemSampler},
    ProcessOperationResult, ProcessService, SystemSampler, SystemSnapshot,
};
use aiguard_storage::{
    AuditEventRepository, CollectionHealthRecord, DashboardCounts, EventDisposition, EventSearch,
    LicenseState, SecurityEventRepository, SqliteEventRepository, StoredAuditEvent,
    StoredSecurityEvent,
};
use chrono::{DateTime, Local, NaiveDate, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};
use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
    Emitter, Manager,
};

struct AppState {
    events: SqliteEventRepository,
    sampler: WindowsSystemSampler,
    processes: WindowsProcessService,
    data_dir: PathBuf,
    monitor_state: Mutex<ReaderState>,
    file_watcher: Mutex<FileChangeWatcher>,
    process_pids: Mutex<HashSet<u32>>,
    deduplicator: Mutex<aiguard_monitor::EventDeduplicator>,
    correlation_tracker: Mutex<CorrelationTracker>,
    process_events: Mutex<WindowsProcessEventSource>,
    event_queue: Mutex<BoundedQueue<(chrono::DateTime<Utc>, SecurityEvent)>>,
    model_usage: Mutex<ModelUsageCollector>,
    model_usage_cache: Mutex<ModelUsageStats>,
    agent_outputs: Mutex<AgentOutputCollector>,
    settings: Mutex<AppSettings>,
    gateway: Gateway,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct AppSettings {
    autostart: bool,
    minimize_to_tray: bool,
    notifications_enabled: bool,
    update_server_url: String,
    update_channel: String,
    sensitive_keywords: Vec<String>,
    sensitive_paths: Vec<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            autostart: false,
            minimize_to_tray: true,
            notifications_enabled: true,
            update_server_url: String::new(),
            update_channel: "stable".into(),
            sensitive_keywords: default_sensitive_keywords(),
            sensitive_paths: default_sensitive_paths(),
        }
    }
}

fn default_sensitive_keywords() -> Vec<String> {
    [
        "密码是",
        "密码为",
        "支付密码",
        "短信验证码",
        "身份证号",
        "银行卡号",
        "银行账号",
        "信用卡号",
        "CVV",
        "家庭住址",
        "开户地址",
        "护照号",
        "社保号",
        "病历号",
        "API_KEY",
        "API key",
        "access_token",
        "refresh_token",
        "client_secret",
        "数据库密码",
        "生产环境密码",
        "私钥",
        "助记词",
        "恢复短语",
        "内部仓库地址",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_sensitive_paths() -> Vec<String> {
    [
        ".env",
        "credentials",
        "id_rsa",
        "id_ed25519",
        ".npmrc",
        ".pypirc",
        "kubeconfig",
        "secrets.yml",
        "application-prod.yml",
        "wallet.dat",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_local_data_dir()
        .map(|dir| dir.join("settings.json"))
        .map_err(|error| error.to_string())
}

fn read_settings(app: &tauri::AppHandle) -> Result<AppSettings, String> {
    let path = settings_path(app)?;
    match fs::read(path) {
        Ok(bytes) => {
            let value = String::from_utf8_lossy(&bytes);
            serde_json::from_str(&value).map_err(|error| error.to_string())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(AppSettings::default()),
        Err(error) => Err(error.to_string()),
    }
}

fn write_settings(app: &tauri::AppHandle, settings: &AppSettings) -> Result<(), String> {
    let path = settings_path(app)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let value = serde_json::to_vec_pretty(settings).map_err(|error| error.to_string())?;
    fs::write(path, value).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn apply_autostart(enabled: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    let result = if enabled {
        std::process::Command::new("reg.exe")
            .args(["ADD", key, "/v", "AIGuard", "/t", "REG_SZ", "/d"])
            .arg(exe)
            .args(["/f"])
            .output()
    } else {
        std::process::Command::new("reg.exe")
            .args(["DELETE", key, "/v", "AIGuard", "/f"])
            .output()
    }
    .map_err(|error| error.to_string())?;
    if result.status.success() || (!enabled && result.status.code() == Some(1)) {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&result.stderr).trim().to_string())
    }
}

#[cfg(not(windows))]
fn apply_autostart(_enabled: bool) -> Result<(), String> {
    Err("当前平台暂不支持开机启动".into())
}

#[tauri::command]
fn get_app_settings(app: tauri::AppHandle) -> Result<AppSettings, String> {
    let mut settings = read_settings(&app)?;
    #[cfg(windows)]
    {
        if let Ok(output) = std::process::Command::new("reg.exe")
            .args([
                "QUERY",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "AIGuard",
            ])
            .output()
        {
            settings.autostart = output.status.success();
        }
    }
    Ok(settings)
}

#[tauri::command]
fn update_app_settings(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    mut settings: AppSettings,
) -> Result<AppSettings, String> {
    apply_autostart(settings.autostart)?;
    settings.minimize_to_tray = true;
    if settings.update_channel.trim().is_empty() {
        settings.update_channel = "stable".into();
    }
    settings.update_server_url = settings.update_server_url.trim_end_matches('/').to_string();
    normalize_sensitive_entries(&mut settings.sensitive_keywords);
    normalize_sensitive_entries(&mut settings.sensitive_paths);
    write_settings(&app, &settings)?;
    *state
        .settings
        .lock()
        .map_err(|_| "settings lock poisoned".to_string())? = settings.clone();
    Ok(settings)
}

fn normalize_sensitive_entries(entries: &mut Vec<String>) {
    entries
        .iter_mut()
        .for_each(|item| *item = item.trim().to_string());
    entries.retain(|item| !item.is_empty());
    entries.sort_by_key(|item| item.to_lowercase());
    entries.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    entries.truncate(500);
}

fn apply_configured_sensitive_rules(
    state: &tauri::State<'_, AppState>,
    event: &mut SecurityEvent,
    text: &str,
) -> Result<(), String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "settings lock poisoned".to_string())?;
    apply_custom_sensitive_rules(
        event,
        text,
        &settings.sensitive_keywords,
        &settings.sensitive_paths,
    );
    Ok(())
}

fn main_window(app: &tauri::AppHandle) -> Result<tauri::WebviewWindow, String> {
    app.get_webview_window("main")
        .ok_or_else(|| "main window not found".to_string())
}

#[tauri::command]
fn minimize_main_window(app: tauri::AppHandle) -> Result<(), String> {
    main_window(&app)?
        .minimize()
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn toggle_maximize_main_window(app: tauri::AppHandle) -> Result<(), String> {
    let window = main_window(&app)?;
    let maximized = window.is_maximized().map_err(|error| error.to_string())?;
    if maximized {
        window.unmaximize().map_err(|error| error.to_string())
    } else {
        window.maximize().map_err(|error| error.to_string())
    }
}

#[tauri::command]
fn hide_main_window(app: tauri::AppHandle) -> Result<(), String> {
    main_window(&app)?.hide().map_err(|error| error.to_string())
}

#[tauri::command]
fn show_main_window(app: tauri::AppHandle) -> Result<(), String> {
    let window = main_window(&app)?;
    window.show().map_err(|error| error.to_string())?;
    window.set_focus().map_err(|error| error.to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeSecurityAlertRequest {
    risk: u8,
    title: String,
    message: String,
    event_id: u64,
}

#[tauri::command]
fn raise_native_security_alert(
    app: tauri::AppHandle,
    request: NativeSecurityAlertRequest,
) -> Result<bool, String> {
    let _event_id = request.event_id;
    let window = main_window(&app)?;
    window.show().map_err(|error| error.to_string())?;
    window
        .set_always_on_top(true)
        .map_err(|error| error.to_string())?;
    window.set_focus().map_err(|error| error.to_string())?;
    let result = native_security_alert(&window, &request)?;
    window
        .set_always_on_top(false)
        .map_err(|error| error.to_string())?;
    Ok(result)
}

#[cfg(windows)]
fn native_security_alert(
    window: &tauri::WebviewWindow,
    request: &NativeSecurityAlertRequest,
) -> Result<bool, String> {
    use windows_sys::Win32::{
        System::Diagnostics::Debug::MessageBeep,
        UI::WindowsAndMessaging::{
            FlashWindowEx, MessageBoxW, FLASHWINFO, FLASHW_ALL, FLASHW_TIMERNOFG, IDYES,
            MB_ICONERROR, MB_TOPMOST, MB_YESNO,
        },
    };
    let hwnd =
        window.hwnd().map_err(|error| error.to_string())?.0 as windows_sys::Win32::Foundation::HWND;
    let flash = FLASHWINFO {
        cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
        hwnd,
        dwFlags: FLASHW_ALL | FLASHW_TIMERNOFG,
        uCount: 6,
        dwTimeout: 0,
    };
    unsafe {
        let _ = FlashWindowEx(&flash);
        let _ = MessageBeep(MB_ICONERROR);
    }
    let title = widestring(&request.title);
    let message = widestring(&format!(
        "风险等级：{}\n\n{}\n\n点击“是”请求拦截，点击“否”仅确认。",
        request.risk, request.message
    ));
    let answer = unsafe {
        MessageBoxW(
            hwnd,
            message.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_ICONERROR | MB_TOPMOST,
        )
    };
    Ok(answer == IDYES)
}

#[cfg(not(windows))]
fn native_security_alert(
    _window: &tauri::WebviewWindow,
    _request: &NativeSecurityAlertRequest,
) -> Result<bool, String> {
    Err("Windows native alert is only available on Windows".into())
}

#[cfg(windows)]
fn widestring(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[tauri::command]
fn record_security_interception(
    state: tauri::State<'_, AppState>,
    event_id: u64,
    reason: String,
) -> Result<(), String> {
    let event = SecurityEvent {
        risk: 100,
        actor: "AIGuard".into(),
        process: "native security alert".into(),
        category: "Security Response".into(),
        rule: "Interception requested".into(),
        rule_id: "RESPONSE.INTERCEPT".into(),
        summary: format!("Interception requested for event {event_id}: {reason}"),
        command_line: String::new(),
        evidence: reason,
        sensitive_types: String::new(),
        secret_fingerprint: String::new(),
        event_type: "SecurityResponse".into(),
        session_id: None,
        project: None,
        correlation_id: None,
    };
    tauri::async_runtime::block_on(state.events.append(chrono::Utc::now(), &event))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Records how the operator triaged a risk item shown on the security overview.
/// `status` accepts `pending` (clears the mark), `acknowledged`, `resolved` or
/// `ignored`; anything else is rejected so the UI and store stay in sync.
#[tauri::command]
async fn set_event_disposition(
    state: tauri::State<'_, AppState>,
    event_id: i64,
    status: String,
    note: Option<String>,
) -> Result<Vec<EventDisposition>, String> {
    if !matches!(
        status.as_str(),
        "pending" | "acknowledged" | "resolved" | "ignored"
    ) {
        return Err(format!("unsupported disposition status: {status}"));
    }
    state
        .events
        .set_event_disposition(event_id, &status, note.unwrap_or_default().trim())
        .await
        .map_err(|error| error.to_string())?;
    state
        .events
        .event_dispositions()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn get_event_dispositions(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<EventDisposition>, String> {
    state
        .events
        .event_dispositions()
        .await
        .map_err(|error| error.to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckUpdateRequest {
    server_url: String,
    channel: String,
}

#[derive(Debug, Serialize)]
struct UpdateCheckResult {
    current_version: &'static str,
    update_available: bool,
    verified: bool,
    manifest: UpdateManifest,
}

#[tauri::command]
async fn check_app_update(request: CheckUpdateRequest) -> Result<UpdateCheckResult, String> {
    let server_url = request.server_url.trim();
    if server_url.is_empty() {
        return Err("Update server URL cannot be empty".into());
    }
    let channel = if request.channel.trim().is_empty() {
        "stable"
    } else {
        request.channel.trim()
    };
    let client = LicenseApiClient::new(server_url).map_err(|error| error.to_string())?;
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let signing_key = client
        .signing_key()
        .await
        .map_err(|error| error.to_string())?;
    let manifest = client
        .latest_update(&platform, channel)
        .await
        .map_err(|error| error.to_string())?;
    verify_update_manifest(&manifest, &signing_key.key_id, &signing_key.public_key)
        .map_err(|error| error.to_string())?;
    Ok(UpdateCheckResult {
        current_version: env!("CARGO_PKG_VERSION"),
        update_available: compare_versions(&manifest.version, env!("CARGO_PKG_VERSION"))
            == std::cmp::Ordering::Greater,
        verified: true,
        manifest,
    })
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let parse = |value: &str| {
        value
            .split('.')
            .take(3)
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let mut left_parts = parse(left);
    let mut right_parts = parse(right);
    left_parts.resize(3, 0);
    right_parts.resize(3, 0);
    left_parts.cmp(&right_parts)
}

#[derive(Debug, Clone, Serialize)]
struct Health {
    app_version: &'static str,
    platform: &'static str,
    build_profile: &'static str,
}

#[tauri::command]
fn health_check() -> Health {
    Health {
        app_version: env!("CARGO_PKG_VERSION"),
        platform: std::env::consts::OS,
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    }
}

#[derive(Debug, Deserialize)]
struct ClassifyCommandRequest {
    process: String,
    command_line: String,
    actor: String,
    pid: u32,
    parent_pid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TerminateProcessRequest {
    pid: u32,
    expected_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivateLicenseRequest {
    server_url: String,
    activation_code: String,
}

#[derive(Debug, Clone, Serialize)]
struct MonitorPollResult {
    discovered: u32,
    persisted: u32,
    queued: u32,
    dropped: u64,
}

#[derive(Debug, Clone, Serialize)]
struct DashboardFrame {
    health: Health,
    snapshot: SystemSnapshot,
    summary: DashboardCounts,
    events: Vec<StoredSecurityEvent>,
    license: LicenseState,
    monitor: MonitorStatus,
    poll: MonitorPollResult,
    usage: ModelUsageStats,
    dispositions: Vec<EventDisposition>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct ModelUsageStats {
    today_input_tokens: u64,
    today_cached_input_tokens: u64,
    today_output_tokens: u64,
    today_reasoning_output_tokens: u64,
    today_total_tokens: u64,
    today_requests: u64,
    active_models: Vec<UsageModelRow>,
    recent_requests: Vec<UsageRequestRow>,
    agent_status: Vec<UsageAgentStatus>,
    daily: Vec<UsageDailyRow>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct UsageDailyRow {
    date: String,
    total_tokens: u64,
    requests: u64,
}

#[derive(Debug, Clone, Serialize)]
struct UsageAgentStatus {
    agent: String,
    detected: bool,
    has_usage: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
struct UsageModelRow {
    model: String,
    provider: String,
    input_tokens: u64,
    cached_input_tokens: u64,
    output_tokens: u64,
    reasoning_output_tokens: u64,
    total_tokens: u64,
    requests: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
struct UsageRequestRow {
    occurred_at: String,
    provider: String,
    model: String,
    session_id: Option<String>,
    input_tokens: u64,
    cached_input_tokens: u64,
    output_tokens: u64,
    reasoning_output_tokens: u64,
    total_tokens: u64,
}

#[derive(Debug, Clone, Default)]
struct UsageFileState {
    offset: u64,
    length: u64,
    modified: Option<SystemTime>,
    current_model: String,
    current_provider: String,
    current_session: Option<String>,
    seen_usage_signatures: HashSet<String>,
}

#[derive(Debug, Clone)]
struct AgentOutputRecord {
    actor: String,
    text: String,
    session_id: Option<String>,
}

#[derive(Debug, Default)]
struct AgentOutputCollector {
    offsets: BTreeMap<PathBuf, u64>,
    discovered_files: Vec<(String, PathBuf)>,
    last_discovery: Option<Instant>,
    dirty_files: HashSet<PathBuf>,
    last_fallback_check: Option<Instant>,
}

impl AgentOutputCollector {
    fn track_file(&mut self, actor: String, file: PathBuf) {
        if !file
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
        {
            return;
        }
        if !self
            .discovered_files
            .iter()
            .any(|(_, existing)| existing == &file)
        {
            self.offsets.insert(file.clone(), 0);
            self.discovered_files.push((actor, file.clone()));
        }
        self.dirty_files.insert(file);
    }

    fn collect(&mut self, home: &Path) -> Result<Vec<AgentOutputRecord>, String> {
        let mut records = Vec::new();
        if self
            .last_discovery
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(60))
        {
            self.discovered_files.clear();
            for (agent, root) in model_usage_sources(home) {
                let mut files = Vec::new();
                collect_recent_jsonl_files(&root, &mut files)?;
                self.discovered_files.extend(
                    files
                        .into_iter()
                        .filter(|file| {
                            file.extension()
                                .and_then(|ext| ext.to_str())
                                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
                        })
                        .map(|file| (agent.to_string(), file)),
                );
            }
            self.discovered_files.sort_by_key(|(_, file)| {
                std::cmp::Reverse(
                    file.metadata()
                        .and_then(|metadata| metadata.modified())
                        .ok(),
                )
            });
            self.discovered_files.truncate(256);
            for (_, file) in &self.discovered_files {
                self.offsets
                    .entry(file.clone())
                    .or_insert_with(|| file.metadata().map(|metadata| metadata.len()).unwrap_or(0));
            }
            self.last_discovery = Some(Instant::now());
        }
        if self
            .last_fallback_check
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(10))
        {
            for (_, file) in &self.discovered_files {
                let length = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
                if self
                    .offsets
                    .get(file)
                    .is_none_or(|offset| *offset != length)
                {
                    self.dirty_files.insert(file.clone());
                }
            }
            self.last_fallback_check = Some(Instant::now());
        }
        let dirty = self.dirty_files.drain().collect::<Vec<_>>();
        for file in dirty {
            let actor = self
                .discovered_files
                .iter()
                .find(|(_, candidate)| candidate == &file)
                .map(|(actor, _)| actor.clone())
                .unwrap_or_else(|| agent_from_path(&file.to_string_lossy()));
            self.collect_file(&actor, &file, &mut records)?;
        }
        records.sort_by(|left, right| left.actor.cmp(&right.actor));
        records.truncate(200);
        Ok(records)
    }

    fn collect_file(
        &mut self,
        actor: &str,
        file: &Path,
        records: &mut Vec<AgentOutputRecord>,
    ) -> Result<(), String> {
        let input = match fs::File::open(file) {
            Ok(input) => input,
            Err(_) => return Ok(()),
        };
        let length = input.metadata().map_err(|error| error.to_string())?.len();
        let Some(offset) = self.offsets.get(file).copied() else {
            self.offsets.insert(file.to_path_buf(), length);
            return Ok(());
        };
        let offset = if offset > length { 0 } else { offset };
        let mut reader = BufReader::new(input);
        reader
            .seek(SeekFrom::Start(offset.min(length)))
            .map_err(|error| error.to_string())?;
        if offset > 0 {
            let mut partial = Vec::new();
            reader
                .read_until(b'\n', &mut partial)
                .map_err(|error| error.to_string())?;
        }
        loop {
            let mut bytes = Vec::new();
            if reader
                .read_until(b'\n', &mut bytes)
                .map_err(|error| error.to_string())?
                == 0
            {
                break;
            }
            let line = String::from_utf8_lossy(&bytes);
            if let Ok(value) = serde_json::from_str::<Value>(line.trim_end()) {
                if let Some(text) = extract_assistant_output(&value) {
                    records.push(AgentOutputRecord {
                        actor: actor.into(),
                        text: text.chars().take(32_000).collect(),
                        session_id: extract_string(
                            &value,
                            &[
                                "/sessionId",
                                "/session_id",
                                "/session_id",
                                "/payload/session_id",
                            ],
                        )
                        .or_else(|| session_id_from_path(file)),
                    });
                }
            }
        }
        self.offsets.insert(
            file.to_path_buf(),
            reader
                .stream_position()
                .map_err(|error| error.to_string())?,
        );
        Ok(())
    }
}

#[derive(Debug, Default)]
struct ModelUsageCollector {
    day: Option<NaiveDate>,
    last_refresh: Option<Instant>,
    files: BTreeMap<PathBuf, UsageFileState>,
    rows: BTreeMap<(String, String), UsageModelRow>,
    recent_requests: Vec<UsageRequestRow>,
    detected_agents: HashSet<String>,
    discovered_files: Vec<(String, PathBuf)>,
    last_discovery: Option<Instant>,
    opencode_seen: HashSet<String>,
}

impl ModelUsageCollector {
    fn track_file(&mut self, agent: String, file: PathBuf) {
        if !file
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                matches!(ext.to_ascii_lowercase().as_str(), "jsonl" | "json" | "log")
            })
            || self
                .discovered_files
                .iter()
                .any(|(_, existing)| existing == &file)
        {
            return;
        }
        self.discovered_files.push((agent, file));
    }

    fn collect(&mut self, home: &Path) -> Result<ModelUsageStats, String> {
        let today = Local::now().date_naive();
        if self.day == Some(today)
            && self
                .last_refresh
                .is_some_and(|last_refresh| last_refresh.elapsed() < Duration::from_secs(3))
        {
            return Ok(self.stats());
        }
        if self.day != Some(today) {
            self.reset(today);
        }

        if self
            .last_discovery
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(60))
        {
            self.discovered_files.clear();
            let mut scanned_roots = HashSet::new();
            for (agent, root) in model_usage_sources(home) {
                if root.exists() {
                    self.detected_agents.insert(agent.into());
                }
                if !scanned_roots.insert(root.clone()) {
                    continue;
                }
                let mut files = Vec::new();
                collect_recent_jsonl_files(&root, &mut files)?;
                self.discovered_files
                    .extend(files.into_iter().map(|file| (agent.to_string(), file)));
            }
            self.last_discovery = Some(Instant::now());
        }
        for (agent, file) in self.discovered_files.clone() {
            self.collect_file(&file, today, &agent)?;
        }
        self.discovered_files.sort_by_key(|(_, file)| {
            std::cmp::Reverse(
                file.metadata()
                    .and_then(|metadata| metadata.modified())
                    .ok(),
            )
        });
        self.discovered_files.truncate(256);
        self.collect_opencode(home, today);
        self.last_refresh = Some(Instant::now());

        Ok(self.stats())
    }

    fn reset(&mut self, day: NaiveDate) {
        self.day = Some(day);
        self.last_refresh = None;
        self.files.clear();
        self.rows.clear();
        self.recent_requests.clear();
        self.detected_agents.clear();
        self.discovered_files.clear();
        self.last_discovery = None;
        self.opencode_seen.clear();
    }

    fn collect_file(&mut self, file: &Path, today: NaiveDate, agent: &str) -> Result<(), String> {
        let mut file_state = self
            .files
            .get(file)
            .cloned()
            .unwrap_or_else(|| UsageFileState {
                current_model: "Unknown model".into(),
                current_provider: agent.into(),
                current_session: session_id_from_path(file),
                ..UsageFileState::default()
            });
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(_) => return Ok(()),
        };
        let length = metadata.len();
        let modified = metadata.modified().ok();
        if file_state.length == length && file_state.modified == modified {
            return Ok(());
        }
        let input = match fs::File::open(file) {
            Ok(input) => input,
            Err(_) => return Ok(()),
        };
        if file
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            if let Ok(value) = serde_json::from_reader::<_, Value>(input) {
                self.inspect_usage_value(&value, &mut file_state, today, 0);
            }
            file_state.length = length;
            file_state.modified = modified;
            self.files.insert(file.to_path_buf(), file_state);
            return Ok(());
        }
        let mut reader = BufReader::new(input);
        reader
            .seek(SeekFrom::Start(file_state.offset))
            .map_err(|error| error.to_string())?;
        loop {
            let mut bytes = Vec::new();
            let read = reader
                .read_until(b'\n', &mut bytes)
                .map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&bytes);
            let Ok(value) = serde_json::from_str::<Value>(line.trim_end()) else {
                continue;
            };
            self.inspect_usage_value(&value, &mut file_state, today, 0);
        }
        file_state.offset = reader
            .stream_position()
            .map_err(|error| error.to_string())?;
        file_state.length = length;
        file_state.modified = modified;
        self.files.insert(file.to_path_buf(), file_state);
        Ok(())
    }

    fn inspect_usage_value(
        &mut self,
        value: &Value,
        file_state: &mut UsageFileState,
        today: NaiveDate,
        depth: usize,
    ) {
        if depth > 8 {
            return;
        }
        if let Some(session_id) = extract_string(
            value,
            &[
                "/payload/session_id",
                "/payload/id",
                "/sessionId",
                "/session_id",
                "/conversation_id",
                "/thread_id",
            ],
        ) {
            file_state.current_session = Some(session_id);
        }
        if let Some(model) = extract_string(
            value,
            &[
                "/payload/thread_settings/model",
                "/payload/model",
                "/model",
                "/message/model",
                "/modelID",
                "/modelId",
                "/model_name",
                "/metadata/model",
                "/response/model",
            ],
        ) {
            file_state.current_model = model;
        }
        if is_token_count(value) {
            self.add_token_count(value, file_state, today);
            return;
        }
        match value {
            Value::Array(values) => {
                for child in values {
                    self.inspect_usage_value(child, file_state, today, depth + 1);
                }
            }
            Value::Object(values) => {
                for child in values.values() {
                    if child.is_array() || child.is_object() {
                        self.inspect_usage_value(child, file_state, today, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }

    fn add_token_count(
        &mut self,
        value: &Value,
        file_state: &mut UsageFileState,
        today: NaiveDate,
    ) {
        let Some(occurred_at) = usage_occurred_at(value) else {
            return;
        };
        if occurred_at.date_naive() < today - chrono::Duration::days(29) {
            return;
        }
        let Some(usage) = usage_value(value) else {
            return;
        };
        let signature = format!(
            "{}:{}",
            occurred_at.timestamp_millis(),
            value
                .pointer("/payload/info/total_token_usage")
                .map(usage_signature)
                .unwrap_or_else(|| usage_signature(usage))
        );
        if !file_state.seen_usage_signatures.insert(signature) {
            return;
        }
        let input_tokens = number_field(usage, "input_tokens");
        let cached_input_tokens = number_field(usage, "cached_input_tokens");
        let output_tokens = number_field(usage, "output_tokens");
        let reasoning_output_tokens = number_field(usage, "reasoning_output_tokens");
        let total_tokens = number_field(usage, "total_tokens")
            .max(input_tokens + output_tokens + reasoning_output_tokens);
        if total_tokens == 0 {
            return;
        }

        let key = (
            file_state.current_provider.clone(),
            file_state.current_model.clone(),
        );
        let row = self.rows.entry(key).or_insert_with(|| UsageModelRow {
            provider: file_state.current_provider.clone(),
            model: file_state.current_model.clone(),
            ..UsageModelRow::default()
        });
        row.input_tokens += input_tokens;
        row.cached_input_tokens += cached_input_tokens;
        row.output_tokens += output_tokens;
        row.reasoning_output_tokens += reasoning_output_tokens;
        row.total_tokens += total_tokens;
        row.requests += 1;
        self.recent_requests.push(UsageRequestRow {
            occurred_at: occurred_at.to_rfc3339(),
            provider: file_state.current_provider.clone(),
            model: file_state.current_model.clone(),
            session_id: file_state.current_session.clone(),
            input_tokens,
            cached_input_tokens,
            output_tokens,
            reasoning_output_tokens,
            total_tokens,
        });
    }

    fn collect_opencode(&mut self, home: &Path, today: NaiveDate) {
        let path = home
            .join(".local")
            .join("share")
            .join("opencode")
            .join("opencode.db");
        if path.exists() {
            self.detected_agents.insert("OpenCode".into());
        }
        let Ok(connection) = Connection::open(path) else {
            return;
        };
        let Ok(mut statement) = connection
            .prepare("SELECT time_updated, session_id, data FROM message WHERE time_updated >= ?1")
        else {
            return;
        };
        let since = (today - chrono::Duration::days(29))
            .and_hms_opt(0, 0, 0)
            .map(|time| time.and_utc().timestamp_millis())
            .unwrap_or_default();
        let rows = statement.query_map([since], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        });
        let Ok(rows) = rows else { return };
        for row in rows.flatten() {
            let (millis, session_id, data) = row;
            let Ok(message) = serde_json::from_str::<Value>(&data) else {
                continue;
            };
            if message.get("role").and_then(Value::as_str) != Some("assistant") {
                continue;
            }
            let model = message
                .get("modelID")
                .and_then(Value::as_str)
                .unwrap_or("Unknown model")
                .to_string();
            let Some(tokens) = message.get("tokens") else {
                continue;
            };
            let Some(occurred_at) = DateTime::<Utc>::from_timestamp_millis(millis)
                .map(|time| time.with_timezone(&Local))
            else {
                continue;
            };
            let input = number_field(tokens, "input");
            let cached = tokens
                .pointer("/cache/read")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let output = number_field(tokens, "output");
            let reasoning = number_field(tokens, "reasoning");
            let total = number_field(tokens, "total").max(input + output + reasoning);
            if total == 0 {
                continue;
            }
            let signature = format!("{session_id}:{millis}:{model}:{total}");
            if !self.opencode_seen.insert(signature) {
                continue;
            }
            let key = ("OpenCode".to_string(), model.clone());
            let aggregate = self.rows.entry(key).or_insert_with(|| UsageModelRow {
                provider: "OpenCode".into(),
                model: model.clone(),
                ..UsageModelRow::default()
            });
            aggregate.input_tokens += input;
            aggregate.cached_input_tokens += cached;
            aggregate.output_tokens += output;
            aggregate.reasoning_output_tokens += reasoning;
            aggregate.total_tokens += total;
            aggregate.requests += 1;
            self.recent_requests.push(UsageRequestRow {
                occurred_at: occurred_at.to_rfc3339(),
                provider: "OpenCode".into(),
                model,
                session_id: Some(session_id),
                input_tokens: input,
                cached_input_tokens: cached,
                output_tokens: output,
                reasoning_output_tokens: reasoning,
                total_tokens: total,
            });
        }
    }

    fn stats(&self) -> ModelUsageStats {
        let mut active_models = self.rows.values().cloned().collect::<Vec<_>>();
        active_models.sort_by(|left, right| right.total_tokens.cmp(&left.total_tokens));
        let mut recent_requests = self.recent_requests.clone();
        recent_requests.sort_by(|left, right| right.occurred_at.cmp(&left.occurred_at));
        let agents_with_usage = active_models
            .iter()
            .map(|row| row.provider.as_str())
            .collect::<HashSet<_>>();
        let agent_status = SUPPORTED_MODEL_USAGE_AGENTS
            .iter()
            .map(|agent| UsageAgentStatus {
                agent: (*agent).into(),
                detected: self.detected_agents.contains(*agent),
                has_usage: agents_with_usage.contains(agent),
            })
            .collect();
        let today = self.day.unwrap_or_else(|| Local::now().date_naive());
        let mut daily_map = BTreeMap::<NaiveDate, UsageDailyRow>::new();
        for request in &recent_requests {
            let Ok(timestamp) = DateTime::parse_from_rfc3339(&request.occurred_at) else { continue };
            let date = timestamp.with_timezone(&Local).date_naive();
            if date < today - chrono::Duration::days(29) || date > today { continue; }
            let row = daily_map.entry(date).or_insert_with(|| UsageDailyRow { date: date.to_string(), ..UsageDailyRow::default() });
            row.total_tokens += request.total_tokens;
            row.requests += 1;
        }
        let daily = (0..30).rev().map(|offset| {
            let date = today - chrono::Duration::days(offset);
            daily_map.get(&date).cloned().unwrap_or_else(|| UsageDailyRow { date: date.to_string(), ..UsageDailyRow::default() })
        }).collect::<Vec<_>>();
        let today_row = daily.last().cloned().unwrap_or_default();
        let today_requests = recent_requests.iter().filter(|request| DateTime::parse_from_rfc3339(&request.occurred_at).ok().map(|ts| ts.with_timezone(&Local).date_naive() == today).unwrap_or(false)).collect::<Vec<_>>();
        ModelUsageStats {
            today_input_tokens: today_requests.iter().map(|row| row.input_tokens).sum(),
            today_cached_input_tokens: today_requests.iter().map(|row| row.cached_input_tokens).sum(),
            today_output_tokens: today_requests.iter().map(|row| row.output_tokens).sum(),
            today_reasoning_output_tokens: today_requests.iter().map(|row| row.reasoning_output_tokens).sum(),
            today_total_tokens: today_row.total_tokens,
            today_requests: today_row.requests,
            active_models,
            recent_requests,
            agent_status,
            daily,
        }
    }
}

const SUPPORTED_MODEL_USAGE_AGENTS: &[&str] = &[
    "Codex",
    "Claude Code",
    "OpenCode",
    "Gemini CLI",
    "Qwen Code",
    "Kimi Code",
    "GitHub Copilot",
    "GitHub Copilot CLI",
    "Cursor",
    "Windsurf",
    "Cline",
    "Roo Code",
    "Continue",
    "Kiro",
    "Trae",
    "DeepSeek Harness",
    "WorkBuddy",
    "OpenHands",
    "Goose",
    "Aider",
    "Amazon Q",
    "通义灵码",
    "CodeGeeX",
];

#[derive(Debug, Clone, Serialize)]
struct MonitorStatus {
    codex_history: bool,
    claude_history: bool,
    codex_commands: bool,
    openhands: bool,
    wmi_active: bool,
    queue_depth: usize,
    dropped: u64,
}

#[tauri::command]
fn get_monitor_status(state: tauri::State<'_, AppState>) -> Result<MonitorStatus, String> {
    let home = monitor_home();
    let queue = state
        .event_queue
        .lock()
        .map_err(|_| "event queue lock poisoned".to_string())?;
    let wmi_active = state
        .process_events
        .lock()
        .map_err(|_| "process event source lock poisoned".to_string())?
        .is_active();
    Ok(MonitorStatus {
        codex_history: readable_file(home.join(".codex").join("history.jsonl")),
        claude_history: readable_file(home.join(".claude").join("history.jsonl")),
        codex_commands: readable_file(home.join(".codex").join("sandbox_commands.rust.log")),
        openhands: home.join(".openhands").join("v1_conversations").is_dir(),
        wmi_active,
        queue_depth: queue.len(),
        dropped: queue.dropped(),
    })
}

fn readable_file(path: PathBuf) -> bool {
    fs::File::open(path).is_ok()
}

#[tauri::command]
async fn get_workspace_diagnostics() -> Result<WorkspaceDiagnosis, String> {
    tauri::async_runtime::spawn_blocking(|| diagnose(std::env::current_dir().unwrap_or_default()))
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn get_network_diagnostics() -> Result<Vec<NetworkCheck>, String> {
    tauri::async_runtime::spawn_blocking(network_diagnose)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn get_ai_diagnosis() -> Result<AiDiagnosis, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let workspace = diagnose(std::env::current_dir().unwrap_or_default());
        let network = network_diagnose();
        local_ai_diagnose(&workspace, &network)
    })
    .await
    .map_err(|error| error.to_string())
}

fn monitor_sources() -> Vec<JsonlPromptSource> {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    vec![
        codex_source(home.join(".codex").join("history.jsonl")),
        claude_source(home.join(".claude").join("history.jsonl")),
    ]
}

fn monitor_home() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[tauri::command]
fn get_model_usage_stats(state: tauri::State<'_, AppState>) -> Result<ModelUsageStats, String> {
    state
        .model_usage_cache
        .lock()
        .map_err(|_| "model usage cache lock poisoned".to_string())
        .map(|usage| usage.clone())
}

#[allow(dead_code)]
fn collect_model_usage_stats(home: &Path) -> Result<ModelUsageStats, String> {
    let sessions_root = home.join(".codex").join("sessions");
    let mut files = Vec::new();
    collect_recent_jsonl_files(&sessions_root, &mut files)?;
    let since = Local::now().date_naive() - chrono::Duration::days(29);
    let mut rows: BTreeMap<(String, String), UsageModelRow> = BTreeMap::new();
    let mut recent_requests = Vec::new();

    for file in files {
        let Ok(input) = fs::File::open(&file) else {
            continue;
        };
        let mut current_model = String::from("Unknown model");
        let mut current_provider = String::from("Codex");
        let mut current_session = session_id_from_path(&file);
        let mut reader = BufReader::new(input);
        loop {
            let mut bytes = Vec::new();
            let read = reader
                .read_until(b'\n', &mut bytes)
                .map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&bytes);
            let Ok(value) = serde_json::from_str::<Value>(line.trim_end()) else {
                continue;
            };
            if let Some(session_id) = extract_string(
                &value,
                &["/payload/session_id", "/payload/id", "/sessionId"],
            ) {
                current_session = Some(session_id);
            }
            if let Some(provider) = extract_string(
                &value,
                &[
                    "/payload/thread_settings/model_provider_id",
                    "/payload/model_provider",
                ],
            ) {
                current_provider = provider;
            }
            if let Some(model) = extract_string(
                &value,
                &["/payload/thread_settings/model", "/payload/model", "/model"],
            ) {
                current_model = model;
            }
            if !is_token_count(&value) {
                continue;
            }
            let Some(occurred_at) = value
                .get("timestamp")
                .and_then(Value::as_str)
                .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
                .map(|time| time.with_timezone(&Local))
            else {
                continue;
            };
            if occurred_at.date_naive() < since {
                continue;
            }
            let usage = value
                .pointer("/payload/info/last_token_usage")
                .or_else(|| value.pointer("/payload/info/total_token_usage"));
            let Some(usage) = usage else {
                continue;
            };
            let input_tokens = number_field(usage, "input_tokens");
            let cached_input_tokens = number_field(usage, "cached_input_tokens");
            let output_tokens = number_field(usage, "output_tokens");
            let reasoning_output_tokens = number_field(usage, "reasoning_output_tokens");
            let total_tokens =
                number_field(usage, "total_tokens").max(input_tokens + output_tokens);
            if total_tokens == 0 {
                continue;
            }

            let key = (current_provider.clone(), current_model.clone());
            let row = rows.entry(key).or_insert_with(|| UsageModelRow {
                provider: current_provider.clone(),
                model: current_model.clone(),
                ..UsageModelRow::default()
            });
            row.input_tokens += input_tokens;
            row.cached_input_tokens += cached_input_tokens;
            row.output_tokens += output_tokens;
            row.reasoning_output_tokens += reasoning_output_tokens;
            row.total_tokens += total_tokens;
            row.requests += 1;
            recent_requests.push(UsageRequestRow {
                occurred_at: occurred_at.to_rfc3339(),
                provider: current_provider.clone(),
                model: current_model.clone(),
                session_id: current_session.clone(),
                input_tokens,
                cached_input_tokens,
                output_tokens,
                reasoning_output_tokens,
                total_tokens,
            });
        }
    }

    recent_requests.sort_by(|left, right| right.occurred_at.cmp(&left.occurred_at));
    recent_requests.truncate(40);
    let mut active_models = rows.into_values().collect::<Vec<_>>();
    active_models.sort_by(|left, right| right.total_tokens.cmp(&left.total_tokens));
    Ok(ModelUsageStats {
        today_input_tokens: active_models.iter().map(|row| row.input_tokens).sum(),
        today_cached_input_tokens: active_models
            .iter()
            .map(|row| row.cached_input_tokens)
            .sum(),
        today_output_tokens: active_models.iter().map(|row| row.output_tokens).sum(),
        today_reasoning_output_tokens: active_models
            .iter()
            .map(|row| row.reasoning_output_tokens)
            .sum(),
        today_total_tokens: active_models.iter().map(|row| row.total_tokens).sum(),
        today_requests: active_models.iter().map(|row| row.requests).sum(),
        active_models,
        recent_requests,
        agent_status: Vec::new(),
        daily: Vec::new(),
    })
}

fn model_usage_sources(home: &Path) -> Vec<(&'static str, PathBuf)> {
    let mut sources = vec![
        ("Codex", home.join(".codex").join("sessions")),
        ("Claude Code", home.join(".claude").join("projects")),
        ("Gemini CLI", home.join(".gemini")),
        ("Qwen Code", home.join(".qwen")),
        ("Kimi Code", home.join(".kimi")),
        ("GitHub Copilot CLI", home.join(".copilot")),
        ("Goose", home.join(".local").join("share").join("goose")),
        (
            "OpenHands",
            home.join(".openhands").join("v1_conversations"),
        ),
        ("Aider", home.join(".aider")),
        ("Cursor", home.join(".cursor")),
        ("Windsurf", home.join(".codeium").join("windsurf")),
        ("Kiro", home.join(".kiro")),
        ("Trae", home.join(".trae")),
        ("Amazon Q", home.join(".aws").join("amazonq")),
        ("CodeGeeX", home.join(".codegeex")),
        ("通义灵码", home.join(".lingma")),
        ("DeepSeek Harness", home.join(".deepseek-harness")),
        ("DeepSeek Harness", home.join(".deepseek")),
        ("WorkBuddy", home.join(".workbuddy")),
        ("WorkBuddy", home.join(".openclaw")),
        ("WorkBuddy", home.join(".lobster")),
    ];
    if let Some(app_data) = std::env::var_os("APPDATA").map(PathBuf::from) {
        for product in ["Code", "Cursor", "Windsurf", "Kiro", "Trae"] {
            let global = app_data.join(product).join("User").join("globalStorage");
            sources.extend([
                ("Cline", global.join("saoudrizwan.claude-dev")),
                ("Roo Code", global.join("rooveterinaryinc.roo-cline")),
                ("Continue", global.join("continue.continue")),
                ("GitHub Copilot", global.join("github.copilot-chat")),
                ("Cursor", global.join("cursor")),
                ("Windsurf", global.join("codeium.codeium")),
                ("通义灵码", global.join("alibaba-cloud.tongyi-lingma")),
                ("CodeGeeX", global.join("aminer.codegeex")),
                ("Amazon Q", global.join("amazonwebservices.amazon-q-vscode")),
            ]);
        }
        sources.extend([
            ("DeepSeek Harness", app_data.join("DeepSeek Harness")),
            ("WorkBuddy", app_data.join("WorkBuddy")),
            ("WorkBuddy", app_data.join("OpenClaw")),
        ]);
    }
    sources
}

fn collect_recent_jsonl_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    if !root.is_dir() {
        return Ok(());
    }
    let since = Local::now().date_naive() - chrono::Duration::days(29);
    for entry in fs::read_dir(root).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() {
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    matches!(
                        name.to_ascii_lowercase().as_str(),
                        "node_modules" | "cache" | "cacheddata" | "target"
                    )
                })
            {
                continue;
            }
            collect_recent_jsonl_files(&path, files)?;
            continue;
        }
        let supported = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                matches!(ext.to_ascii_lowercase().as_str(), "jsonl" | "json" | "log")
            });
        if !supported {
            continue;
        }
        let modified_recently = path.metadata().ok().is_some_and(|metadata| {
            metadata.len() <= 64 * 1024 * 1024
                && metadata
                    .modified()
                    .ok()
                    .map(DateTime::<Local>::from)
                    .is_some_and(|modified| modified.date_naive() >= since)
        });
        if modified_recently {
            files.push(path);
        }
    }
    Ok(())
}

fn extract_string(value: &Value, paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| value.pointer(path).and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
}

fn extract_assistant_output(value: &Value) -> Option<String> {
    let role = extract_string(value, &["/payload/role", "/message/role", "/role"])?;
    if role != "assistant" {
        return None;
    }
    let content = value
        .pointer("/payload/content")
        .or_else(|| value.pointer("/message/content"))
        .or_else(|| value.get("content"))?;
    let mut parts = Vec::new();
    collect_output_text(content, &mut parts, 0);
    let text = parts.join("\n").trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn collect_output_text(value: &Value, parts: &mut Vec<String>, depth: usize) {
    if depth > 6 {
        return;
    }
    match value {
        Value::String(text) => parts.push(text.clone()),
        Value::Array(values) => {
            for value in values {
                collect_output_text(value, parts, depth + 1);
            }
        }
        Value::Object(values) => {
            let kind = values
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if matches!(kind, "text" | "output_text") {
                if let Some(text) = values.get("text").and_then(Value::as_str) {
                    parts.push(text.into());
                    return;
                }
            }
            if let Some(content) = values.get("content") {
                collect_output_text(content, parts, depth + 1);
            }
        }
        _ => {}
    }
}

fn is_token_count(value: &Value) -> bool {
    usage_value(value).is_some_and(|usage| {
        number_field(usage, "input_tokens")
            + number_field(usage, "output_tokens")
            + number_field(usage, "reasoning_output_tokens")
            + number_field(usage, "total_tokens")
            > 0
    })
}

fn usage_value(value: &Value) -> Option<&Value> {
    [
        "/payload/info/last_token_usage",
        "/payload/info/total_token_usage",
        "/message/usage",
        "/response/usage",
        "/metadata/usage",
        "/token_usage",
        "/tokenUsage",
        "/usage",
        "/tokens",
    ]
    .iter()
    .find_map(|path| value.pointer(path))
}

fn usage_occurred_at(value: &Value) -> Option<DateTime<Local>> {
    for path in [
        "/timestamp",
        "/created_at",
        "/createdAt",
        "/occurred_at",
        "/time/created",
        "/time/completed",
        "/message/time/created",
        "/metadata/timestamp",
    ] {
        let Some(raw) = value.pointer(path) else {
            continue;
        };
        if let Some(raw) = raw.as_str() {
            if let Ok(time) = DateTime::parse_from_rfc3339(raw) {
                return Some(time.with_timezone(&Local));
            }
        }
        if let Some(raw) = raw.as_i64() {
            let time = if raw > 10_000_000_000 {
                DateTime::<Utc>::from_timestamp_millis(raw)
            } else {
                DateTime::<Utc>::from_timestamp(raw, 0)
            };
            if let Some(time) = time {
                return Some(time.with_timezone(&Local));
            }
        }
    }
    None
}

fn number_field(value: &Value, field: &str) -> u64 {
    if let Some(value) = value.get(field).and_then(Value::as_u64) {
        return value;
    }
    let aliases: &[&str] = match field {
        "input_tokens" => &[
            "prompt_tokens",
            "input",
            "promptTokenCount",
            "inputTokenCount",
        ],
        "output_tokens" => &[
            "completion_tokens",
            "output",
            "candidatesTokenCount",
            "outputTokenCount",
        ],
        "reasoning_output_tokens" => &[
            "reasoning_tokens",
            "reasoning",
            "thoughtsTokenCount",
            "thinking_tokens",
        ],
        "total_tokens" => &["total", "totalTokenCount", "token_count"],
        _ => &[],
    };
    if let Some(value) = aliases
        .iter()
        .find_map(|alias| value.get(alias).and_then(Value::as_u64))
    {
        return value;
    }
    if field == "cached_input_tokens" {
        return value
            .get("cache_read_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            + value
                .get("cache_creation_input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0)
            + value
                .get("cachedContentTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0)
            + value
                .pointer("/cache/read")
                .and_then(Value::as_u64)
                .unwrap_or(0)
            + value
                .pointer("/cache/write")
                .and_then(Value::as_u64)
                .unwrap_or(0);
    }
    0
}

fn usage_signature(value: &Value) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        number_field(value, "input_tokens"),
        number_field(value, "cached_input_tokens"),
        number_field(value, "output_tokens"),
        number_field(value, "reasoning_output_tokens"),
        number_field(value, "total_tokens")
    )
}

fn session_id_from_path(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|value| value.to_str())
        .and_then(|name| name.rsplit('-').next())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[tauri::command]
async fn poll_agent_inputs(state: tauri::State<'_, AppState>) -> Result<MonitorPollResult, String> {
    poll_agent_inputs_inner(state, None).await
}

async fn poll_agent_inputs_inner(
    state: tauri::State<'_, AppState>,
    snapshot: Option<SystemSnapshot>,
) -> Result<MonitorPollResult, String> {
    let sources = monitor_sources();
    let home = monitor_home();
    let command_source = CodexCommandSource {
        path: home.join(".codex").join("sandbox_commands.rust.log"),
    };
    let openhands_source = OpenHandsSource {
        root: home.join(".openhands").join("v1_conversations"),
    };
    let (records, command_records): (Vec<PromptRecord>, Vec<aiguard_monitor::CommandRecord>) = {
        let mut monitor_state = state
            .monitor_state
            .lock()
            .map_err(|_| "monitor state lock poisoned".to_string())?;
        let mut records = Vec::new();
        for source in sources {
            records.extend(
                source
                    .read_new(&mut monitor_state)
                    .map_err(|error| error.to_string())?,
            );
        }
        let command_records = command_source
            .read_new(&mut monitor_state)
            .map_err(|error| error.to_string())?;
        records.extend(
            openhands_source
                .read_new(&mut monitor_state)
                .map_err(|error| error.to_string())?,
        );
        (records, command_records)
    };
    let output_records = state
        .agent_outputs
        .lock()
        .map_err(|_| "agent output collector lock poisoned".to_string())?
        .collect(&home)?;
    let discovered = (records.len() + command_records.len() + output_records.len()) as u32;
    let mut events = {
        let mut tracker = state
            .correlation_tracker
            .lock()
            .map_err(|_| "correlation tracker lock poisoned".to_string())?;
        let mut events = records
            .iter()
            .map(|record| {
                let correlation = tracker.register_prompt(record);
                let mut event = classify_user_input(&record.text);
                event.actor = record.actor.clone();
                event.process = record.actor.clone();
                event.event_type = "UserInput".into();
                event.session_id = correlation.session_id;
                event.project = correlation.project;
                event.correlation_id = Some(correlation.correlation_id);
                (Utc::now(), event)
            })
            .collect::<Vec<_>>();
        events.extend(command_records.into_iter().map(|record| {
            let context = SecurityContext {
                process: "codex tool".into(),
                command_line: record.raw.clone(),
                actor: "Codex".into(),
                pid: 0,
                parent_pid: 0,
            };
            let mut event =
                classify_command(&context).unwrap_or_else(|| classify_user_input(&record.raw));
            event.actor = "Codex".into();
            event.process = "Codex tool".into();
            event.event_type = "AgentCommand".into();
            event.evidence = format!("{}; status={}", record.source, record.status);
            if let Some(correlation) = tracker.correlate_command("Codex") {
                event.session_id = correlation.session_id;
                event.project = correlation.project;
                event.correlation_id = Some(correlation.correlation_id);
            }
            (Utc::now(), event)
        }));
        events.extend(output_records.into_iter().map(|record| {
            let mut event = classify_model_output(&record.text);
            event.actor = record.actor.clone();
            event.process = format!("{} model", record.actor);
            event.session_id = record.session_id;
            if let Some(correlation) = tracker.correlate_command(&record.actor) {
                event.project = correlation.project;
                event.correlation_id = Some(correlation.correlation_id);
            }
            (Utc::now(), event)
        }));
        events
    };
    for (_, event) in &mut events {
        let text = format!(
            "{} {} {}",
            event.command_line, event.evidence, event.summary
        );
        apply_configured_sensitive_rules(&state, event, &text)?;
    }
    let file_changes = state
        .file_watcher
        .lock()
        .map_err(|_| "file watcher lock poisoned".to_string())?
        .drain();
    for change in &file_changes {
        let path = PathBuf::from(&change.path);
        let actor = agent_from_path(&change.path);
        if let Ok(mut collector) = state.agent_outputs.try_lock() {
            collector.track_file(actor.clone(), path.clone());
        }
        if let Ok(mut collector) = state.model_usage.try_lock() {
            collector.track_file(actor, path);
        }
    }
    events.extend(
        file_changes
            .into_iter()
            .map(|change| (Utc::now(), file_change_event(change))),
    );
    let (wmi_active, wmi_started) = {
        let source = state
            .process_events
            .lock()
            .map_err(|_| "process event source lock poisoned".to_string())?;
        (source.is_active(), source.drain())
    };
    let started = if wmi_active {
        let sampled_processes = snapshot
            .as_ref()
            .map(|snapshot| snapshot.processes.as_slice())
            .unwrap_or_default();
        wmi_started
            .into_iter()
            .map(|process| {
                let sampled = sampled_processes
                    .iter()
                    .find(|sampled| sampled.pid == process.pid);
                (
                    process.pid,
                    process.process_name,
                    sampled.and_then(|sampled| sampled.command_line.clone()),
                    sampled.and_then(|sampled| sampled.path.clone()),
                )
            })
            .collect::<Vec<_>>()
    } else {
        let snapshot = if let Some(snapshot) = snapshot {
            snapshot
        } else {
            state
                .sampler
                .snapshot()
                .await
                .map_err(|error| error.to_string())?
        };
        let mut known = state
            .process_pids
            .lock()
            .map_err(|_| "process state lock poisoned".to_string())?;
        let current: HashSet<u32> = snapshot
            .processes
            .iter()
            .map(|process| process.pid)
            .collect();
        let started = snapshot
            .processes
            .iter()
            .filter(|process| !known.contains(&process.pid))
            .map(|process| {
                (
                    process.pid,
                    process.name.clone(),
                    process.command_line.clone(),
                    process.path.clone(),
                )
            })
            .collect::<Vec<_>>();
        *known = current;
        started
    };
    events.extend(started.into_iter().map(|(pid, name, command_line, path)| {
        let raw = command_line.unwrap_or_default();
        let agent = agent_from_process(&name, &raw);
        if !raw.is_empty() {
            let actor = agent.clone().unwrap_or_else(|| "Local User".into());
            let context = SecurityContext {
                process: name.clone(),
                command_line: raw.clone(),
                actor: actor.clone(),
                pid,
                parent_pid: 0,
            };
            if let Some(mut event) = classify_command(&context) {
                event.actor = actor;
                event.process = name;
                event.event_type = if agent.is_some() {
                    "AgentCommand".into()
                } else {
                    "UserAction".into()
                };
                event.evidence = path.unwrap_or_else(|| format!("PID {pid}"));
                return (Utc::now(), event);
            }
        }
        let mut event = classify_user_input(&name);
        event.risk = 15;
        event.actor = agent.unwrap_or_else(|| "System".into());
        event.process = name;
        event.category = "Process".into();
        event.rule = "进程启动".into();
        event.rule_id = "PROCESS.STARTED".into();
        event.summary = "Observed a newly started system process".into();
        event.command_line = raw;
        event.evidence = path.unwrap_or_else(|| format!("PID {pid}"));
        event.event_type = "ProcessObserved".into();
        (Utc::now(), event)
    }));
    let before_dedup = events.len();
    {
        let mut deduplicator = state
            .deduplicator
            .lock()
            .map_err(|_| "deduplicator lock poisoned".to_string())?;
        events.retain(|(_, event)| {
            deduplicator.accept(
                &event.actor,
                &event.event_type,
                &event.command_line,
                &event.evidence,
            )
        });
    }
    let discovered = discovered + (before_dedup.saturating_sub(events.len())) as u32;
    let batch = {
        let mut queue = state
            .event_queue
            .lock()
            .map_err(|_| "event queue lock poisoned".to_string())?;
        for event in events {
            queue.push(event);
        }
        queue.take_batch(500)
    };
    let persisted = batch.len() as u32;
    if !batch.is_empty() {
        if let Err(error) = state.events.append_batch(&batch).await {
            state
                .event_queue
                .lock()
                .map_err(|_| "event queue lock poisoned".to_string())?
                .restore_front(batch);
            return Err(error.to_string());
        }
    }
    let queue = state
        .event_queue
        .lock()
        .map_err(|_| "event queue lock poisoned".to_string())?;
    Ok(MonitorPollResult {
        discovered,
        persisted,
        queued: queue.len() as u32,
        dropped: queue.dropped(),
    })
}

async fn collect_dashboard_frame(app: tauri::AppHandle) -> Result<DashboardFrame, String> {
    let state = app.state::<AppState>();
    let health = health_check();
    let snapshot = state
        .sampler
        .snapshot()
        .await
        .map_err(|error| error.to_string())?;
    let poll = poll_agent_inputs_inner(state.clone(), Some(snapshot.clone())).await?;
    let since = Utc::now() - chrono::Duration::hours(24);
    let monitor = get_monitor_status(app.state::<AppState>())?;
    let usage = state
        .model_usage_cache
        .lock()
        .map_err(|_| "model usage cache lock poisoned".to_string())?
        .clone();
    let (summary, events, license, dispositions) = futures::try_join!(
        async {
            state
                .events
                .dashboard_counts(since)
                .await
                .map_err(|error| error.to_string())
        },
        async {
            state
                .events
                .recent(400)
                .await
                .map_err(|error| error.to_string())
        },
        get_license_state(state.clone()),
        async {
            state
                .events
                .event_dispositions()
                .await
                .map_err(|error| error.to_string())
        },
    )?;
    Ok(DashboardFrame {
        health,
        snapshot,
        summary,
        events,
        license,
        monitor,
        poll,
        usage,
        dispositions,
    })
}

#[tauri::command]
async fn get_dashboard_frame(app: tauri::AppHandle) -> Result<DashboardFrame, String> {
    collect_dashboard_frame(app).await
}

#[tauri::command]
fn set_active_view(view: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let process_interval = if view == "processes" {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(30)
    };
    state
        .sampler
        .set_process_refresh_interval(process_interval)
        .map_err(|error| error.to_string())?;
    let port_interval = if view == "ports" {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(30)
    };
    state
        .sampler
        .set_port_refresh_interval(port_interval)
        .map_err(|error| error.to_string())
}

fn agent_from_path(path: &str) -> String {
    let normalized = path.to_ascii_lowercase();
    if normalized.contains(".codex") {
        "Codex".into()
    } else if normalized.contains(".claude") {
        "Claude Code".into()
    } else if normalized.contains("opencode") {
        "OpenCode".into()
    } else if normalized.contains(".gemini") {
        "Gemini CLI".into()
    } else if normalized.contains(".qwen") {
        "Qwen Code".into()
    } else if normalized.contains(".kimi") {
        "Kimi Code".into()
    } else if normalized.contains("copilot") {
        "GitHub Copilot".into()
    } else if normalized.contains("roo-cline") {
        "Roo Code".into()
    } else if normalized.contains("claude-dev") || normalized.contains("cline") {
        "Cline".into()
    } else if normalized.contains("continue.continue") {
        "Continue".into()
    } else if normalized.contains("cursor") {
        "Cursor".into()
    } else if normalized.contains("windsurf") || normalized.contains("codeium") {
        "Windsurf".into()
    } else if normalized.contains(".kiro") {
        "Kiro".into()
    } else if normalized.contains(".trae") {
        "Trae".into()
    } else if normalized.contains("deepseek") {
        "DeepSeek Harness".into()
    } else if normalized.contains("workbuddy")
        || normalized.contains("openclaw")
        || normalized.contains("lobster")
    {
        "WorkBuddy".into()
    } else if normalized.contains("goose") {
        "Goose".into()
    } else if normalized.contains("aider") {
        "Aider".into()
    } else if normalized.contains(".openhands") {
        "OpenHands".into()
    } else if normalized.contains("lingma") {
        "通义灵码".into()
    } else if normalized.contains("codegeex") {
        "CodeGeeX".into()
    } else if normalized.contains("amazonq") || normalized.contains("amazon-q") {
        "Amazon Q".into()
    } else {
        "Configured workspace".into()
    }
}

fn agent_from_process(name: &str, command_line: &str) -> Option<String> {
    let value = format!("{name} {command_line}").to_ascii_lowercase();
    [
        ("Claude Code", &["claude", "anthropic"][..]),
        ("Codex", &["codex"][..]),
        ("OpenCode", &["opencode"][..]),
        ("Gemini CLI", &["gemini"][..]),
        ("Qwen Code", &["qwen-code", "qwen code"][..]),
        ("Kimi Code", &["kimi-cli", "kimi code"][..]),
        (
            "DeepSeek Harness",
            &["deepseek-harness", "deepseek harness"][..],
        ),
        ("WorkBuddy", &["workbuddy", "openclaw", "lobster"][..]),
        ("Cursor", &["cursor"][..]),
        ("Windsurf", &["windsurf", "codeium"][..]),
        ("Cline", &["cline", "claude-dev"][..]),
        ("Roo Code", &["roo-cline", "roo code"][..]),
        ("Continue", &["continue.continue"][..]),
        ("OpenHands", &["openhands"][..]),
        ("Goose", &["goose"][..]),
        ("Aider", &["aider"][..]),
    ]
    .into_iter()
    .find(|(_, patterns)| patterns.iter().any(|pattern| value.contains(pattern)))
    .map(|(agent, _)| agent.into())
}

#[tauri::command]
fn classify_security_command(request: ClassifyCommandRequest) -> Option<SecurityEvent> {
    classify_command(&SecurityContext {
        process: request.process,
        command_line: request.command_line,
        actor: request.actor,
        pid: request.pid,
        parent_pid: request.parent_pid,
    })
}

#[tauri::command]
async fn classify_security_input(
    text: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityEvent, String> {
    let event = classify_user_input(&text);
    state
        .events
        .append(Utc::now(), &event)
        .await
        .map_err(|error| error.to_string())?;
    Ok(event)
}

#[tauri::command]
async fn get_security_events(
    limit: u32,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<StoredSecurityEvent>, String> {
    state
        .events
        .recent(limit)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn get_security_summary(
    since: String,
    state: tauri::State<'_, AppState>,
) -> Result<DashboardCounts, String> {
    let since = chrono::DateTime::parse_from_rfc3339(&since)
        .map_err(|error| format!("invalid since timestamp: {error}"))?
        .with_timezone(&Utc);
    state
        .events
        .dashboard_counts(since)
        .await
        .map_err(|error| error.to_string())
}

fn storage_error_cn(action: &str, error: impl std::fmt::Display) -> String {
    format!("{action}失败：{error}")
}

#[tauri::command]
async fn get_sessions(
    limit: u32,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<aiguard_core::AgentSession>, String> {
    state
        .events
        .list_sessions(limit.clamp(1, 500))
        .await
        .map_err(|error| storage_error_cn("查询会话", error))
}

#[tauri::command]
async fn get_session_timeline(
    session_id: String,
    limit: u32,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<StoredAuditEvent>, String> {
    if session_id.trim().is_empty() {
        return Err("查询会话时间线失败：session_id 不能为空".into());
    }
    state
        .events
        .session_timeline(session_id.trim(), limit.clamp(1, 1000))
        .await
        .map_err(|error| storage_error_cn("查询会话时间线", error))
}

#[tauri::command]
async fn get_trace(
    trace_id: String,
    limit: u32,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<StoredAuditEvent>, String> {
    if trace_id.trim().is_empty() {
        return Err("查询 Trace 失败：trace_id 不能为空".into());
    }
    state
        .events
        .trace_events(trace_id.trim(), limit.clamp(1, 1000))
        .await
        .map_err(|error| storage_error_cn("查询 Trace", error))
}

#[tauri::command]
async fn get_event_detail(
    event_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Option<StoredAuditEvent>, String> {
    if event_id.trim().is_empty() {
        return Err("查询事件详情失败：event_id 不能为空".into());
    }
    state
        .events
        .event_detail(event_id.trim())
        .await
        .map_err(|error| storage_error_cn("查询事件详情", error))
}

#[tauri::command]
async fn search_events(
    request: EventSearch,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<StoredAuditEvent>, String> {
    state
        .events
        .search_audit_events(request)
        .await
        .map_err(|error| storage_error_cn("搜索事件", error))
}

#[tauri::command]
async fn get_collection_health(
    limit: u32,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<CollectionHealthRecord>, String> {
    state
        .events
        .collection_health(limit.clamp(1, 500))
        .await
        .map_err(|error| storage_error_cn("查询采集健康", error))
}

#[tauri::command]
async fn get_license_state(state: tauri::State<'_, AppState>) -> Result<LicenseState, String> {
    let current = state
        .events
        .license_state()
        .await
        .map_err(|error| error.to_string())?;
    let Some(public_key_base64) = option_env!("AIGUARD_LICENSE_PUBLIC_KEY") else {
        return Ok(current);
    };
    let key_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        public_key_base64,
    )
    .map_err(|error| error.to_string())?;
    let public_key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "invalid compiled license public key")?;
    let certificate_path = state.data_dir.join("license-certificate.bin");
    if !certificate_path.exists() {
        return Ok(current);
    }
    let last_seen = current
        .last_server_time
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc));
    let status =
        evaluate_stored_certificate(&certificate_path, &public_key, Utc::now(), last_seen, false)
            .map_err(|error| error.to_string())?;
    let status_text = match status {
        LicenseStatus::Active => "Active",
        LicenseStatus::GracePeriod => "GracePeriod",
        LicenseStatus::Expired => "Expired",
        LicenseStatus::Revoked => "Revoked",
        LicenseStatus::ClockRollbackDetected => "ClockRollbackDetected",
        LicenseStatus::DeviceMismatch | LicenseStatus::InvalidSignature => "Invalid",
    };
    if current.status != status_text {
        state
            .events
            .update_license_state(
                status_text,
                current.license_id.as_deref(),
                current.expires_at.as_deref(),
                current.offline_until.as_deref(),
                current.last_server_time.as_deref(),
            )
            .await
            .map_err(|error| error.to_string())?;
    }
    state
        .events
        .license_state()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn activate_license(
    request: ActivateLicenseRequest,
    state: tauri::State<'_, AppState>,
) -> Result<LicenseState, String> {
    let identity_path = state.data_dir.join("device-identity.json");
    let certificate_path = state.data_dir.join("license-certificate.bin");
    let identity =
        DeviceIdentity::load_or_create(identity_path).map_err(|error| error.to_string())?;
    let client = LicenseApiClient::new(&request.server_url).map_err(|error| error.to_string())?;
    let response = client
        .activate(&ActivateRequest {
            activation_code: request.activation_code,
            device_public_key: identity.public_key_base64(),
            device_fingerprint: identity.public_key_hash(),
            platform: std::env::consts::OS.to_string(),
            client_version: env!("CARGO_PKG_VERSION").to_string(),
        })
        .await
        .map_err(|error| error.to_string())?;
    save_protected_text(certificate_path, &response.license_certificate)
        .map_err(|error| error.to_string())?;
    state
        .events
        .update_license_state(
            "Active",
            Some(&response.license_id),
            None,
            Some(&response.offline_until.to_rfc3339()),
            Some(&response.server_time.to_rfc3339()),
        )
        .await
        .map_err(|error| error.to_string())?;
    state
        .events
        .license_state()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn get_system_snapshot(state: tauri::State<'_, AppState>) -> Result<SystemSnapshot, String> {
    state
        .sampler
        .snapshot()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn terminate_process(
    request: TerminateProcessRequest,
    state: tauri::State<'_, AppState>,
) -> Result<ProcessOperationResult, String> {
    state
        .processes
        .terminate(request.pid, &request.expected_name)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_gateway_channels(state: tauri::State<'_, AppState>) -> Result<Vec<Channel>, String> {
    state.gateway.list_channels().map_err(|error| error.to_string())
}

#[tauri::command]
fn save_gateway_channel(
    input: ChannelInput,
    state: tauri::State<'_, AppState>,
) -> Result<Channel, String> {
    state.gateway.save_channel(input).map_err(|error| error.to_string())
}

#[tauri::command]
fn delete_gateway_channel(id: i64, state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.gateway.delete_channel(id).map_err(|error| error.to_string())
}

#[tauri::command]
async fn test_gateway_channel(
    id: i64,
    model: String,
    state: tauri::State<'_, AppState>,
) -> Result<ChannelTestResult, String> {
    state.gateway.test_channel(id, model).await.map_err(|error| error.to_string())
}

#[tauri::command]
async fn fetch_gateway_models(id: i64, state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    state.gateway.fetch_channel_models(id).await.map_err(|error| error.to_string())
}

#[tauri::command]
async fn fetch_gateway_models_preview(input: ChannelInput, state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    state.gateway.fetch_models_for_input(&input).await.map_err(|error| error.to_string())
}

#[tauri::command]
fn get_gateway_info() -> serde_json::Value {
    serde_json::json!({
        "address": format!("http://{DEFAULT_LISTEN_ADDR}/v1"),
        "api_key": "aiguard-local",
        "listen_address": DEFAULT_LISTEN_ADDR,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let show = MenuItemBuilder::with_id("show", "打开 AIGuard").build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "退出").build(app)?;
            let tray_menu = MenuBuilder::new(app).items(&[&show, &quit]).build()?;
            let tray = TrayIconBuilder::new()
                .menu(&tray_menu)
                .show_menu_on_left_click(false)
                .tooltip("AIGuard 安全监控")
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::DoubleClick { .. } = event {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;
            let _ = tray;
            let data_dir = app
                .path()
                .app_local_data_dir()
                .map_err(|error| error.to_string())?;
            fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;
            let database_path = data_dir.join("aiguard.sqlite3");
            let events =
                tauri::async_runtime::block_on(SqliteEventRepository::connect_path(&database_path))
                    .map_err(|error| error.to_string())?;
            let gateway = Gateway::open(&database_path).map_err(|error| error.to_string())?;
            let settings = read_settings(app.handle()).unwrap_or_default();
            let mut monitor_state = ReaderState::default();
            for source in monitor_sources() {
                source
                    .prime(&mut monitor_state)
                    .map_err(|error| error.to_string())?;
            }
            let home = monitor_home();
            CodexCommandSource {
                path: home.join(".codex").join("sandbox_commands.rust.log"),
            }
            .prime(&mut monitor_state)
            .map_err(|error| error.to_string())?;
            OpenHandsSource {
                root: home.join(".openhands").join("v1_conversations"),
            }
            .prime(&mut monitor_state)
            .map_err(|error| error.to_string())?;
            let watcher_paths = model_usage_sources(&home)
                .into_iter()
                .map(|(_, path)| path)
                .collect::<Vec<_>>();
            let file_watcher =
                FileChangeWatcher::start(&watcher_paths).map_err(|error| error.to_string())?;
            let sampler = WindowsSystemSampler::new();
            let process_pids = tauri::async_runtime::block_on(sampler.snapshot())
                .map(|snapshot| {
                    snapshot
                        .processes
                        .into_iter()
                        .map(|process| process.pid)
                        .collect()
                })
                .unwrap_or_default();
            app.manage(AppState {
                events,
                sampler,
                processes: WindowsProcessService::new(),
                data_dir,
                monitor_state: Mutex::new(monitor_state),
                file_watcher: Mutex::new(file_watcher),
                process_pids: Mutex::new(process_pids),
                deduplicator: Mutex::new(aiguard_monitor::EventDeduplicator::default()),
                correlation_tracker: Mutex::new(CorrelationTracker::default()),
                process_events: Mutex::new(WindowsProcessEventSource::start()),
                event_queue: Mutex::new(BoundedQueue::new(10_000)),
                model_usage: Mutex::new(ModelUsageCollector::default()),
                model_usage_cache: Mutex::new(ModelUsageStats::default()),
                agent_outputs: Mutex::new(AgentOutputCollector::default()),
                settings: Mutex::new(settings),
                gateway: gateway.clone(),
            });
            tauri::async_runtime::spawn(async move {
                if let Err(error) = gateway.serve(DEFAULT_LISTEN_ADDR).await {
                    eprintln!("AIGuard 网关停止：{error}");
                }
            });
            let recovery_gateway = app.state::<AppState>().gateway.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    recovery_gateway.recover_unavailable_channels().await;
                }
            });
            let usage_app_handle = app.handle().clone();
            std::thread::spawn(move || loop {
                let state = usage_app_handle.state::<AppState>();
                let result = state
                    .model_usage
                    .lock()
                    .ok()
                    .and_then(|mut collector| collector.collect(&monitor_home()).ok());
                if let Some(usage) = result {
                    if let Ok(mut cache) = state.model_usage_cache.lock() {
                        *cache = usage;
                    }
                }
                std::thread::sleep(Duration::from_secs(3));
            });
            let process_app_handle = app.handle().clone();
            std::thread::spawn(move || loop {
                let state = process_app_handle.state::<AppState>();
                let _ = state.sampler.refresh_processes_if_due();
                let _ = state.sampler.refresh_ports_if_due();
                std::thread::sleep(Duration::from_millis(250));
            });
            let app_handle = app.handle().clone();
            std::thread::spawn(move || loop {
                if let Ok(frame) =
                    tauri::async_runtime::block_on(collect_dashboard_frame(app_handle.clone()))
                {
                    let _ = app_handle.emit("dashboard:update", frame);
                }
                std::thread::sleep(Duration::from_millis(1000));
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            health_check,
            classify_security_command,
            classify_security_input,
            get_security_events,
            get_security_summary,
            get_sessions,
            get_session_timeline,
            get_trace,
            get_event_detail,
            search_events,
            get_collection_health,
            get_license_state,
            activate_license,
            poll_agent_inputs,
            get_dashboard_frame,
            set_active_view,
            get_model_usage_stats,
            get_monitor_status,
            get_workspace_diagnostics,
            get_network_diagnostics,
            get_ai_diagnosis,
            get_app_settings,
            update_app_settings,
            raise_native_security_alert,
            record_security_interception,
            set_event_disposition,
            get_event_dispositions,
            minimize_main_window,
            toggle_maximize_main_window,
            hide_main_window,
            show_main_window,
            check_app_update,
            get_system_snapshot,
            terminate_process
            ,get_gateway_channels
            ,save_gateway_channel
            ,delete_gateway_channel
            ,test_gateway_channel
            ,fetch_gateway_models
            ,fetch_gateway_models_preview
            ,get_gateway_info
        ])
        .run(tauri::generate_context!())
        .expect("error while running AIGuard");
}

fn main() {
    run();
}

fn file_change_event(change: FileChangeRecord) -> SecurityEvent {
    let mut event = classify_user_input(&change.path);
    event.risk = 15;
    event.actor = agent_from_path(&change.path);
    event.process = "文件系统".into();
    event.category = "文件系统".into();
    event.rule = "Agent 文件变更".into();
    event.rule_id = "FILE.OBSERVED".into();
    event.summary = "观察到 Agent 数据目录文件变化".into();
    event.command_line.clear();
    event.evidence = format!("{}: {}", change.kind, change.path);
    event.event_type = "FileChange".into();
    event
}

#[cfg(test)]
mod usage_tests {
    use super::*;

    #[test]
    fn parses_common_agent_token_schemas() {
        let usage = serde_json::json!({
            "promptTokenCount": 1_200,
            "candidatesTokenCount": 300,
            "thoughtsTokenCount": 40,
            "cachedContentTokenCount": 500,
            "totalTokenCount": 2_040
        });
        assert_eq!(number_field(&usage, "input_tokens"), 1_200);
        assert_eq!(number_field(&usage, "output_tokens"), 300);
        assert_eq!(number_field(&usage, "reasoning_output_tokens"), 40);
        assert_eq!(number_field(&usage, "cached_input_tokens"), 500);
        assert_eq!(number_field(&usage, "total_tokens"), 2_040);
    }

    #[test]
    fn catalog_contains_requested_mainstream_agents() {
        let agents = model_usage_sources(Path::new("C:/Users/test"))
            .into_iter()
            .map(|(agent, _)| agent)
            .collect::<HashSet<_>>();
        for agent in [
            "Codex",
            "Claude Code",
            "OpenCode",
            "Gemini CLI",
            "Qwen Code",
            "Kimi Code",
            "Cursor",
            "Cline",
            "Roo Code",
            "Continue",
            "DeepSeek Harness",
            "WorkBuddy",
            "通义灵码",
        ] {
            if agent != "OpenCode" {
                assert!(agents.contains(agent), "missing {agent}");
            }
        }
    }

    #[test]
    fn file_change_event_uses_valid_chinese_labels() {
        let event = file_change_event(FileChangeRecord {
            path: "C:/Users/test/.codex/session.jsonl".into(),
            kind: "modify".into(),
        });

        assert_eq!(event.process, "文件系统");
        assert_eq!(event.category, "文件系统");
        assert_eq!(event.rule, "Agent 文件变更");
        assert_eq!(event.summary, "观察到 Agent 数据目录文件变化");
    }

    #[test]
    fn output_collector_primes_existing_file_at_eof() {
        let path = std::env::temp_dir().join(format!(
            "aiguard-output-prime-{}-{}.jsonl",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::write(&path, "{\"type\":\"message\",\"text\":\"historical\"}\n").expect("fixture");
        let expected_offset = fs::metadata(&path).expect("metadata").len();
        let mut collector = AgentOutputCollector::default();
        let mut records = Vec::new();

        collector
            .collect_file("Codex", &path, &mut records)
            .expect("prime");

        assert!(records.is_empty());
        assert_eq!(collector.offsets.get(&path), Some(&expected_offset));
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn usage_collector_skips_unchanged_file() {
        let path = std::env::temp_dir().join(format!(
            "aiguard-usage-incremental-{}-{}.jsonl",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let fixture = format!(
            "{{\"timestamp\":\"{}\",\"model\":\"test-model\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":5,\"total_tokens\":15}}}}\n",
            Utc::now().to_rfc3339()
        );
        fs::write(&path, fixture).expect("fixture");
        let mut collector = ModelUsageCollector::default();
        let today = Local::now().date_naive();

        collector
            .collect_file(&path, today, "Codex")
            .expect("first collect");
        let first = collector.stats().today_requests;
        collector
            .collect_file(&path, today, "Codex")
            .expect("second collect");

        assert_eq!(first, 1);
        assert_eq!(collector.stats().today_requests, first);
        fs::remove_file(path).expect("cleanup");
    }
}
