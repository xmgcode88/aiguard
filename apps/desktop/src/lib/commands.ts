import { invoke } from "@tauri-apps/api/core";

export type Health = {
  app_version: string;
  platform: string;
  build_profile: string;
};

export type ProcessSnapshot = {
  pid: number;
  parent_pid: number | null;
  name: string;
  path: string | null;
  command_line: string | null;
  cpu_usage: number;
  memory: number;
  protected: boolean;
  protection_reason: string | null;
};

export type PortSnapshot = {
  protocol: string;
  address: string;
  port: number;
  pid: number | null;
  process_name: string | null;
  listening: boolean;
};

export type SystemSnapshot = {
  cpu_usage: number;
  memory_used: number;
  memory_total: number;
  disks: Array<{ name: string; mount_point: string; total: number; available: number }>;
  processes: ProcessSnapshot[];
  ports: PortSnapshot[];
  capabilities: Record<string, string>;
};

export type SecurityEvent = {
  risk: number;
  actor: string;
  process: string;
  category: string;
  rule: string;
  rule_id: string;
  summary: string;
  command_line: string;
  evidence: string;
  sensitive_types: string;
  secret_fingerprint?: string;
  event_type: string;
  session_id?: string | null;
  project?: string | null;
  correlation_id?: string | null;
};

export type StoredSecurityEvent = {
  id: number;
  occurred_at: string;
  event: SecurityEvent;
};

export type AuditEvent = {
  event_id: string;
  event_type: string;
  occurred_at: string;
  source: string;
  source_confidence: string;
  agent_id?: string | null;
  session_id?: string | null;
  trace_id?: string | null;
  span_id?: string | null;
  parent_span_id?: string | null;
  project_id?: string | null;
  actor: { kind: string; name: string };
  risk: { score: number; level: string; rule_id?: string | null; explanation?: string | null };
  summary: string;
  evidence_refs: Array<{ evidence_id: string; kind: string; preview?: string | null }>;
  raw_payload_ref?: string | null;
};

export type StoredAuditEvent = {
  id: number;
  event: AuditEvent;
};

export type AgentSession = {
  session_id: string;
  agent_id: string;
  project_id?: string | null;
  started_at: string;
  ended_at?: string | null;
};

export type EventSearch = {
  projectId?: string | null;
  sessionId?: string | null;
  traceId?: string | null;
  agentId?: string | null;
  eventType?: string | null;
  ruleId?: string | null;
  minRisk?: number | null;
  since?: string | null;
  until?: string | null;
  limit?: number | null;
};

export type CollectionHealthRecord = {
  id: number;
  component: string;
  status: string;
  checked_at: string;
  message: string;
  agent_id?: string | null;
  details_json: string;
};

export type DispositionStatus = "pending" | "acknowledged" | "resolved" | "ignored";

export type EventDisposition = {
  event_id: number;
  status: DispositionStatus;
  note: string;
  updated_at: string;
};

export type DashboardCounts = {
  total: number;
  input: number;
  sensitive_input: number;
  sensitive_outbound: number;
  dangerous: number;
  warning: number;
};

export type LicenseState = {
  status: string;
  license_id: string | null;
  expires_at: string | null;
  offline_until: string | null;
  last_server_time: string | null;
  updated_at: string;
};

export type ProcessOperationResult = {
  success: boolean;
  pid: number;
  process_name: string;
  message: string;
};

export type MonitorPollResult = {
  discovered: number;
  persisted: number;
  queued: number;
  dropped: number;
};

export type UsageModelRow = {
  model: string;
  provider: string;
  input_tokens: number;
  cached_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
  total_tokens: number;
  requests: number;
};

export type UsageRequestRow = {
  occurred_at: string;
  provider: string;
  model: string;
  session_id: string | null;
  input_tokens: number;
  cached_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
  total_tokens: number;
};

export type ModelUsageStats = {
  today_input_tokens: number;
  today_cached_input_tokens: number;
  today_output_tokens: number;
  today_reasoning_output_tokens: number;
  today_total_tokens: number;
  today_requests: number;
  active_models: UsageModelRow[];
  recent_requests: UsageRequestRow[];
  agent_status: { agent: string; detected: boolean; has_usage: boolean }[];
  daily: { date: string; total_tokens: number; requests: number }[];
};

export type DashboardFrame = {
  health: Health;
  snapshot: SystemSnapshot;
  summary: DashboardCounts;
  events: StoredSecurityEvent[];
  license: LicenseState;
  monitor: MonitorStatus;
  poll: MonitorPollResult;
  usage: ModelUsageStats;
  dispositions: EventDisposition[];
};

export type NativeSecurityAlertRequest = {
  eventId: number;
  risk: number;
  title: string;
  message: string;
};
export type MonitorStatus = { codex_history: boolean; claude_history: boolean; codex_commands: boolean; openhands: boolean; wmi_active: boolean; queue_depth: number; dropped: number };

export type RuntimeInfo = { kind: string; command: string; version: string | null; executable: string | null; available: boolean; issue: string | null; project: string | null };
export type ToolInfo = { name: string; command: string; version: string | null; executable: string | null; available: boolean; issue: string | null };
export type ProjectTopology = { name: string; root: string; runtimes: string[]; state: string; issue: string | null };
export type WorkspaceDiagnosis = { project_root: string | null; projects: ProjectTopology[]; runtimes: RuntimeInfo[]; tools: ToolInfo[]; path_issues: string[]; issues: string[] };
export type NetworkCheck = { layer: string; name: string; state: string; detail: string; latency_ms: number | null; healthy: boolean; warning: boolean };
export type AiDiagnosis = { title: string; priority: string; evidence: string[]; actions: string[] };
export type AppSettings = {
  autostart: boolean;
  minimize_to_tray: boolean;
  notifications_enabled: boolean;
  update_server_url: string;
  update_channel: string;
  sensitive_keywords: string[];
  sensitive_paths: string[];
};
export type GatewayChannel = {
  id: number;
  name: string;
  base_url: string;
  api_key: string;
  protocol: string;
  models: string[];
  priority: number;
  weight: number;
  enabled: boolean;
  available: boolean;
  consecutive_failures: number;
  latency_ms: number | null;
  last_test_at: string | null;
  last_error: string | null;
};
export type GatewayChannelInput = Omit<GatewayChannel, "id" | "protocol" | "available" | "consecutive_failures" | "latency_ms" | "last_test_at" | "last_error"> & { id?: number | null; protocol?: string };
export type GatewayChannelTestResult = { success: boolean; latency_ms: number; message: string; model: string };
export type GatewayInfo = { address: string; api_key: string; listen_address: string };
export type UpdateManifest = { version: string; channel: string; platform: string; minimum_license_version: string; download_url: string; sha256: string; signature: string; released_at: string };
export type UpdateCheckResult = { current_version: string; update_available: boolean; verified: boolean; manifest: UpdateManifest };

export const commands = {
  health: () => invoke<Health>("health_check"),
  snapshot: () => invoke<SystemSnapshot>("get_system_snapshot"),
  events: (limit = 50) => invoke<StoredSecurityEvent[]>("get_security_events", { limit }),
  summary: (since: string) => invoke<DashboardCounts>("get_security_summary", { since }),
  sessions: (limit = 100) => invoke<AgentSession[]>("get_sessions", { limit }),
  sessionTimeline: (sessionId: string, limit = 200) =>
    invoke<StoredAuditEvent[]>("get_session_timeline", { sessionId, limit }),
  trace: (traceId: string, limit = 200) =>
    invoke<StoredAuditEvent[]>("get_trace", { traceId, limit }),
  eventDetail: (eventId: string) =>
    invoke<StoredAuditEvent | null>("get_event_detail", { eventId }),
  searchEvents: (request: EventSearch) =>
    invoke<StoredAuditEvent[]>("search_events", { request }),
  collectionHealth: (limit = 100) =>
    invoke<CollectionHealthRecord[]>("get_collection_health", { limit }),
  terminateProcess: (pid: number, expectedName: string) =>
    invoke<ProcessOperationResult>("terminate_process", { request: { pid, expectedName } }),
  licenseState: () => invoke<LicenseState>("get_license_state"),
  activateLicense: (serverUrl: string, activationCode: string) =>
    invoke<LicenseState>("activate_license", { request: { serverUrl, activationCode } }),
  pollAgentInputs: () => invoke<MonitorPollResult>("poll_agent_inputs"),
  monitorStatus: () => invoke<MonitorStatus>("get_monitor_status"),
  dashboardFrame: () => invoke<DashboardFrame>("get_dashboard_frame"),
  setActiveView: (view: string) => invoke<void>("set_active_view", { view }),
  modelUsageStats: () => invoke<ModelUsageStats>("get_model_usage_stats"),
  diagnostics: () => invoke<WorkspaceDiagnosis>("get_workspace_diagnostics"),
  networkDiagnostics: () => invoke<NetworkCheck[]>("get_network_diagnostics"),
  aiDiagnosis: () => invoke<AiDiagnosis>("get_ai_diagnosis"),
  appSettings: () => invoke<AppSettings>("get_app_settings"),
  updateAppSettings: (settings: AppSettings) => invoke<AppSettings>("update_app_settings", { settings }),
  minimizeMainWindow: () => invoke<void>("minimize_main_window"),
  toggleMaximizeMainWindow: () => invoke<void>("toggle_maximize_main_window"),
  hideMainWindow: () => invoke<void>("hide_main_window"),
  showMainWindow: () => invoke<void>("show_main_window"),
  raiseNativeSecurityAlert: (request: NativeSecurityAlertRequest) => invoke<boolean>("raise_native_security_alert", { request }),
  recordInterception: (eventId: number, reason: string) => invoke<void>("record_security_interception", { eventId, reason }),
  setEventDisposition: (eventId: number, status: DispositionStatus, note = "") =>
    invoke<EventDisposition[]>("set_event_disposition", { eventId, status, note }),
  eventDispositions: () => invoke<EventDisposition[]>("get_event_dispositions"),
  checkAppUpdate: (serverUrl: string, channel: string) =>
    invoke<UpdateCheckResult>("check_app_update", { request: { serverUrl, channel } }),
  gatewayChannels: () => invoke<GatewayChannel[]>("get_gateway_channels"),
  saveGatewayChannel: (input: GatewayChannelInput) => invoke<GatewayChannel>("save_gateway_channel", { input }),
  deleteGatewayChannel: (id: number) => invoke<void>("delete_gateway_channel", { id }),
  testGatewayChannel: (id: number, model: string) => invoke<GatewayChannelTestResult>("test_gateway_channel", { id, model }),
  fetchGatewayModels: (id: number) => invoke<string[]>("fetch_gateway_models", { id }),
  fetchGatewayModelsPreview: (input: GatewayChannelInput) => invoke<string[]>("fetch_gateway_models_preview", { input }),
  gatewayInfo: () => invoke<GatewayInfo>("get_gateway_info"),
};
