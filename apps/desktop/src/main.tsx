import React from "react";
import ReactDOM from "react-dom/client";
import { Activity, ArrowDown, ArrowUp, BarChart3, Bot, CheckCircle2, ChevronRight, CircleAlert, Copy, Cpu, FileWarning, FlaskConical, HardDrive, KeyRound, LayoutDashboard, ListTree, LockKeyhole, MemoryStick, MessageSquare, Minus, Network, Pencil, Play, Plus, RefreshCw, Search, Settings, ShieldAlert, ShieldCheck, Square, Trash2, UserRound, X, type LucideIcon } from "lucide-react";
import { listen } from "@tauri-apps/api/event";
import { commands, AppSettings, AgentSession, CollectionHealthRecord, DashboardCounts, DashboardFrame, DispositionStatus, EventDisposition, GatewayChannel, GatewayChannelInput, GatewayChannelTestResult, GatewayInfo, Health, LicenseState, ModelUsageStats, MonitorStatus, PortSnapshot, ProcessSnapshot, StoredAuditEvent, StoredSecurityEvent, SystemSnapshot, WorkspaceDiagnosis } from "./lib/commands";
import "./styles.css";

type View = "security" | "channels" | "channel-keys" | "resources" | "usage" | "processes" | "ports" | "agents" | "timeline" | "mcp" | "diagnostics" | "settings";
type DataState = {
  health: Health | null;
  snapshot: SystemSnapshot | null;
  summary: DashboardCounts | null;
  events: StoredSecurityEvent[];
  license: LicenseState | null;
  usage: ModelUsageStats | null;
  monitor: MonitorStatus | null;
  poll: { discovered: number; persisted: number; queued: number; dropped: number } | null;
  collections: CollectionHealthRecord[];
  dispositions: EventDisposition[];
};
type HistoryPoint = { cpu: number; memory: number; disk: number };
const browserMode = typeof window !== "undefined" && !("__TAURI_INTERNALS__" in window);
const emptyState: DataState = { health: null, snapshot: null, summary: null, events: [], license: null, usage: null, monitor: null, poll: null, collections: [], dispositions: [] };
const defaultSettings: AppSettings = { autostart: false, minimize_to_tray: true, notifications_enabled: true, update_server_url: "", update_channel: "stable", sensitive_keywords: [], sensitive_paths: [] };

function linesToList(value: string): string[] {
  return [...new Set(value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))];
}

function App() {
  const [view, setView] = React.useState<View>("security");
  const [data, setData] = React.useState<DataState>(emptyState);
  const [history, setHistory] = React.useState<HistoryPoint[]>([]);
  const [appSettings, setAppSettings] = React.useState<AppSettings>(defaultSettings);
  const appSettingsRef = React.useRef<AppSettings>(defaultSettings);
  const notifiedEvents = React.useRef<Set<number>>(new Set());
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => { appSettingsRef.current = appSettings; }, [appSettings]);
  const applyDashboardFrame = React.useCallback((frame: DashboardFrame, collections: CollectionHealthRecord[] = []) => {
    const disk = frame.snapshot.disks[0];
    React.startTransition(() => {
      setHistory((current) => {
        const next = { cpu: frame.snapshot.cpu_usage, memory: percent(frame.snapshot.memory_used, frame.snapshot.memory_total), disk: disk ? percent(disk.total - disk.available, disk.total) : 0 };
        const last = current[current.length - 1];
        if (last && last.cpu === next.cpu && last.memory === next.memory && last.disk === next.disk) return current;
        return [...current, next].slice(-30);
      });
      setData((current) => ({
        ...current,
        health: frame.health,
        snapshot: frame.snapshot,
        summary: frame.summary,
        events: frame.events,
        license: frame.license,
        usage: frame.usage,
        monitor: frame.monitor,
        poll: frame.poll,
        collections: collections.length ? collections : current.collections,
        dispositions: frame.dispositions ?? current.dispositions,
      }));
      setError(null);
      setLoading(false);
    });
    notifyRiskEvents(frame.events, notifiedEvents.current, appSettingsRef.current.notifications_enabled);
  }, []);
  const refresh = React.useCallback(async () => {
    if (browserMode) { setLoading(false); setError(null); return; }
    setLoading(true);
    try {
      const [frame, collections] = await Promise.all([commands.dashboardFrame(), commands.collectionHealth(24)]);
      applyDashboardFrame(frame, collections);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : String(reason));
      setLoading(false);
    }
  }, [applyDashboardFrame]);
  React.useEffect(() => {
    let disposed = false;
    let unlisten: (() => void | Promise<void>) | null = null;
    if (browserMode) return () => { disposed = true; };
    void listen<DashboardFrame>("dashboard:update", ({ payload }) => {
      if (disposed) return;
      applyDashboardFrame(payload);
    })
      .then((stop) => {
        if (disposed) {
          void stop();
          return;
        }
        unlisten = stop;
      })
      .catch(() => undefined);
    return () => {
      disposed = true;
      if (unlisten) {
        void unlisten();
      }
    };
  }, [applyDashboardFrame]);
  React.useEffect(() => { if (!browserMode) void commands.appSettings().then(setAppSettings).catch(() => undefined); }, []);
  React.useEffect(() => { void refresh(); }, [refresh]);
  React.useEffect(() => { if (!browserMode) void commands.setActiveView(view); }, [view]);
  const nav: Array<[View, string, LucideIcon]> = [["security", "安全总览", ShieldCheck], ["channels", "渠道管理", Network], ["channel-keys", "渠道密钥", KeyRound], ["resources", "资源总览", LayoutDashboard], ["usage", "Token 消耗", BarChart3], ["processes", "进程", ListTree], ["ports", "监听端口", CheckCircle2], ["agents", "Agent 检测", Bot], ["timeline", "会话时间线", Activity], ["mcp", "MCP 与工具", Network], ["diagnostics", "工作站诊断", FileWarning], ["settings", "设置", Settings]];
  return <div className="app-shell">
    <header className="app-header" data-tauri-drag-region><div className="brand" data-tauri-drag-region><img src="/aiguard-logo.png" alt="" /><strong>AIGuard</strong></div><nav aria-label="主导航">{nav.map(([key, label, Icon]) => <button key={key} className={view === key ? "nav-item active" : "nav-item"} onClick={() => setView(key)}><Icon size={18} /><span>{label}</span></button>)}</nav><div className="header-space" data-tauri-drag-region /><div className="window-controls" onPointerDown={(event) => event.stopPropagation()}><button type="button" title="最小化" onClick={() => void commands.minimizeMainWindow()}><Minus size={17} /></button><button type="button" title="最大化/还原" onClick={() => void commands.toggleMaximizeMainWindow()}><Square size={14} /></button><button type="button" className="close" title="关闭到托盘" onClick={() => void commands.hideMainWindow()}><X size={17} /></button></div></header>
    <main className="workspace">
      {error && <div className="notice error">运行时连接失败：{error}<button onClick={() => void refresh()}>重试</button></div>}
      {!error && loading && !data.snapshot && <div className="loading-panel">正在读取本机状态...</div>}
      {view === "security" && <SecurityOverview events={data.events} monitor={data.monitor} dispositions={data.dispositions} onDispositions={(dispositions) => setData((current) => ({ ...current, dispositions }))} />}
      {view === "channels" && <GatewayChannelsPage />}
      {view === "channel-keys" && <GatewayChannelsPage keysOnly />}
      {view === "resources" && <ResourceDashboard snapshot={data.snapshot} summary={data.summary} events={data.events} history={history} />}
      {view === "usage" && <UsageDashboard usage={data.usage} />}
      {view === "processes" && <PagePanel title="进程列表"><ProcessTable processes={data.snapshot?.processes ?? []} /></PagePanel>}
      {view === "ports" && <PagePanel title="监听端口"><ManagedPortTable ports={data.snapshot?.ports ?? []} /></PagePanel>}
      {view === "agents" && <AgentDetectionPage events={data.events} monitor={data.monitor} usage={data.usage} collections={data.collections} />}
      {view === "timeline" && <SessionTimelinePage />}
      {view === "mcp" && <McpToolsPage />}
      {view === "diagnostics" && <><DiagnosticsPage /><DiagnosticsExtras /></>}
      {view === "settings" && <SettingsPage health={data.health} license={data.license} onActivated={(license) => setData((current) => ({ ...current, license }))} onSettingsChanged={setAppSettings} />}
    </main><footer><span><i />本地监控运行中</span><span>版本 {data.health?.app_version ?? "0.1.0"}</span></footer>
  </div>;
}

function notifyRiskEvents(events: StoredSecurityEvent[], notified: Set<number>, enabled: boolean) {
  if (!enabled) return;
  const target = events.find((item) => item.event.risk >= 90 && isFreshEvent(item) && !notified.has(item.id));
  if (!target) return;
  notified.add(target.id);
  if (shouldInterrupt(target)) {
    void commands.raiseNativeSecurityAlert({
      eventId: target.id,
      risk: target.event.risk,
      title: "AIGuard 紧急安全事件",
      message: `${securityText(target.event.summary || target.event.rule)}${target.event.sensitive_types ? `\n敏感类型：${securityText(target.event.sensitive_types)}` : ""}`,
    }).then((intercept) => intercept ? commands.recordInterception(target.id, "用户通过紧急弹窗请求拦截") : undefined).catch(() => undefined);
  }
  if (!("Notification" in window)) return;
  if (Notification.permission === "granted") {
    new Notification("AIGuard 高危安全事件", { body: securityText(target.event.summary || target.event.rule) });
    return;
  }
  if (Notification.permission === "default") {
    void Notification.requestPermission().then((permission) => {
      if (permission === "granted") new Notification("AIGuard 高危安全事件", { body: securityText(target.event.summary || target.event.rule) });
    });
  }
}

function SecurityOverview({ events, monitor, dispositions, onDispositions }: { events: StoredSecurityEvent[]; monitor: MonitorStatus | null; dispositions: EventDisposition[]; onDispositions: (next: EventDisposition[]) => void }) {
  const [dismissedAlertIds, setDismissedAlertIds] = React.useState<Set<number>>(() => new Set());
  const [selected, setSelected] = React.useState<number | null>(null);
  const [statusFilter, setStatusFilter] = React.useState<StatusFilter>("all");
  const [category, setCategory] = React.useState<string>("all");
  const [query, setQuery] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [toast, setToast] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);
  const dispositionMap = React.useMemo(() => new Map(dispositions.map((item) => [item.event_id, item])), [dispositions]);
  const rows = React.useMemo(() => buildRiskRows(events, dispositionMap), [events, dispositionMap]);
  const counts = React.useMemo(() => riskCounts(rows), [rows]);
  const categoryCounts = React.useMemo(() => {
    const map = new Map<string, number>();
    for (const row of rows) map.set(row.category.key, (map.get(row.category.key) ?? 0) + 1);
    return map;
  }, [rows]);
  const visible = React.useMemo(() => filterRiskRows(rows, statusFilter, category, query), [rows, statusFilter, category, query]);
  const pageCount = Math.max(1, Math.ceil(visible.length / FEED_PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const pageRows = visible.slice(currentPage * FEED_PAGE_SIZE, currentPage * FEED_PAGE_SIZE + FEED_PAGE_SIZE);
  const active = selected === null ? null : rows.find((row) => row.item.id === selected) ?? null;
  const alert = rows.find((row) => row.danger && row.status === "pending" && shouldInterrupt(row.item) && isFreshEvent(row.item) && !dismissedAlertIds.has(row.item.id)) ?? null;
  React.useEffect(() => { setPage(0); }, [statusFilter, category, query]);
  React.useEffect(() => { if (!toast) return; const timer = window.setTimeout(() => setToast(null), 2600); return () => window.clearTimeout(timer); }, [toast]);
  const applyDisposition = React.useCallback(async (eventId: number, status: DispositionStatus, note: string) => {
    setSaving(true);
    try {
      const next = await commands.setEventDisposition(eventId, status, note);
      onDispositions(next);
      setToast(status === "pending" ? "已恢复为未处理" : `已标记为${dispositionText(status)}`);
      setSelected(null);
    } catch (reason: unknown) {
      setToast(`标记未成功：${reason instanceof Error ? reason.message : String(reason)}`);
    } finally {
      setSaving(false);
    }
  }, [onDispositions]);
  return <div className="risk-center">
    <section className="risk-center-head">
      <div><span className="risk-eyebrow"><i />实时监控</span><h2>智能体对话与操作记录</h2><p>所有智能体对话、你发给大模型的内容和本地操作都在这里。危险的行为（智能体操作微信、读取本地密钥、删改敏感文件等）会高亮标出。点任意一条查看详情，可以标记处理，也可以不处理。</p></div>
      <div className="risk-head-stats">
        <RiskStat label="全部记录" value={counts.total} tone="blue" active={statusFilter === "all"} onClick={() => setStatusFilter("all")} />
        <RiskStat label="需处理" value={counts.attention} tone="red" active={statusFilter === "attention"} onClick={() => setStatusFilter("attention")} />
        <RiskStat label="高危" value={counts.criticalPending} tone="amber" active={statusFilter === "critical"} onClick={() => setStatusFilter("critical")} />
        <RiskStat label="已处理" value={counts.resolved} tone="green" active={statusFilter === "resolved"} onClick={() => setStatusFilter("resolved")} />
        <RiskStat label="已忽略" value={counts.ignored} tone="grey" active={statusFilter === "ignored"} onClick={() => setStatusFilter("ignored")} />
      </div>
    </section>

    <section className="risk-toolbar">
      <div className="risk-category-tabs">
        <button className={category === "all" ? "active" : ""} onClick={() => setCategory("all")}>全部类别<em>{counts.total}</em></button>
        {RISK_CATEGORIES.map((entry) => <button key={entry.key} className={category === entry.key ? "active" : ""} onClick={() => setCategory(entry.key)} title={entry.hint}><entry.icon size={13} />{entry.label}<em>{categoryCounts.get(entry.key) ?? 0}</em></button>)}
      </div>
      <label className="risk-search"><Search size={14} /><input value={query} onChange={(entry) => setQuery(entry.target.value)} placeholder="搜索内容、进程、规则或智能体" /></label>
      <span className="risk-collect-state"><i className={monitor?.wmi_active ? "ok" : "warn"} />采集{monitor?.wmi_active ? "正常" : "降级"} · 队列 {monitor?.queue_depth ?? 0}</span>
    </section>

    <section className="risk-list-panel">
      <div className="risk-list-head"><h3>{statusFilterLabel(statusFilter)}{category === "all" ? "" : ` · ${categoryLabel(category)}`}</h3><span>共 {visible.length} 条{visible.length > FEED_PAGE_SIZE ? ` · 第 ${currentPage + 1}/${pageCount} 页` : ""}</span></div>
      <div className="risk-list">
        {pageRows.length ? pageRows.map((row) => <RiskRow key={row.item.id} row={row} onOpen={() => setSelected(row.item.id)} />) : <Empty text={statusFilter === "all" ? "还没有采集到对话或操作记录" : "没有符合条件的记录"} />}
      </div>
      {pageCount > 1 && <div className="risk-pager">
        <button type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>上一页</button>
        <span>第 {currentPage + 1} / {pageCount} 页</span>
        <button type="button" disabled={currentPage >= pageCount - 1} onClick={() => setPage(currentPage + 1)}>下一页</button>
      </div>}
    </section>

    {active && <RiskDetailModal row={active} saving={saving} onClose={() => setSelected(null)} onDisposition={(status, note) => void applyDisposition(active.item.id, status, note)} />}
    {alert && <div className="risk-alert-backdrop"><section className="risk-alert" role="alertdialog" aria-modal="true" aria-labelledby="risk-alert-title"><span className="risk-alert-icon"><ShieldAlert size={28} /></span><div><small>紧急安全提醒 · {alert.category.label}</small><h2 id="risk-alert-title">{securityText(alert.item.event.rule || "检测到紧急操作")}</h2><p>{securityText(alert.item.event.summary)}</p>{isSensitiveEvent(alert.item) && <p className="risk-alert-sensitive">敏感信息：{alert.item.event.command_line || alert.item.event.evidence || alert.item.event.summary}</p>}<div className="risk-alert-meta"><span>风险 {alert.item.event.risk}</span><span>{securityText(alert.item.event.sensitive_types || "高危行为")}</span><span>{alert.item.event.actor || alert.item.event.process || "本地事件"}</span><span>{formatDateTime(alert.item.occurred_at)}</span></div></div><div className="risk-alert-actions"><button onClick={() => setDismissedAlertIds((current) => new Set(current).add(alert.item.id))}>稍后处理</button><button onClick={() => { setDismissedAlertIds((current) => new Set(current).add(alert.item.id)); setSelected(alert.item.id); }}>查看详情</button><button className="primary" disabled={saving} onClick={() => { setDismissedAlertIds((current) => new Set(current).add(alert.item.id)); void applyDisposition(alert.item.id, "acknowledged", "在紧急提醒中确认"); }}>确认并记录</button></div></section></div>}
    {toast && <div className="audit-toast"><CheckCircle2 size={16} />{toast}</div>}
  </div>;
}


type RiskCategory = { key: string; label: string; hint: string; icon: LucideIcon };
type StatusFilter = "all" | "attention" | "critical" | "resolved" | "ignored";
type RiskRowData = { item: StoredSecurityEvent; category: RiskCategory; status: DispositionStatus; disposition: EventDisposition | null; danger: boolean };
const FEED_PAGE_SIZE = 20;

const RISK_CATEGORIES: RiskCategory[] = [
  { key: "app", label: "应用与通讯操作", hint: "智能体操作微信、QQ、邮件等应用发送消息", icon: MessageSquare },
  { key: "secret", label: "密钥与凭据", hint: "读取本地密钥、Token、账号密码等凭据", icon: KeyRound },
  { key: "file", label: "敏感文件删改", hint: "删除、改写、移动敏感文件与目录", icon: FileWarning },
  { key: "prompt", label: "发给大模型的内容", hint: "你自己输入或粘贴给智能体的内容", icon: UserRound },
  { key: "command", label: "智能体命令", hint: "智能体执行的命令、脚本与工具调用", icon: Bot },
  { key: "outbound", label: "数据外发", hint: "敏感数据外发、上传与网络请求", icon: Network },
  { key: "system", label: "系统与数据库", hint: "磁盘、进程、数据库等破坏性操作", icon: HardDrive },
  { key: "other", label: "其他风险", hint: "其他需要人工确认的行为", icon: CircleAlert },
];
const RISK_CATEGORY_MAP = new Map(RISK_CATEGORIES.map((entry) => [entry.key, entry]));
/** Categories surfaced regardless of the numeric risk score assigned by the rules. */
/** Categories always treated as dangerous regardless of the score the rules assigned. */
const ALWAYS_SHOWN_CATEGORIES = new Set(["app", "secret", "outbound"]);
const APP_OPERATION_PATTERN = /(?:wechat|weixin|微信|wxwork|企业微信|\bqq\b|tim\.exe|dingtalk|钉钉|feishu|飞书|lark|telegram|whatsapp|slack|discord|outlook|thunderbird|邮件|sendmail|smtp|uiautomation|pyautogui|autohotkey|\bsendkeys\b|nircmd|adb\s+shell|appium|playwright|puppeteer|selenium)/i;
const OUTBOUND_PATTERN = /(?:EXFIL|OUTBOUND|\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|\bscp\b|\brsync\b|\bftp\b|requests\.post|upload)/i;
const SYSTEM_PATTERN = /(?:^DB\.|^DISK\.|^PROCESS\.|^POWERSHELL\.|drop\s+table|truncate\s+table|delete\s+from|format\s+[a-z]:|diskpart|taskkill|Stop-Process|reg\s+delete|bcdedit|vssadmin)/i;
const FILE_PATTERN = /(?:^FILE\.|FileChange|\brm\s+-rf\b|Remove-Item|\bdel\s+\/|unlink\(|shutil\.rmtree|\bmv\s+|\bcp\s+)/i;
const SECRET_PATTERN = /(?:SECRET|CREDENTIAL|\bkey\b|token|password|passwd|api[_-]?key|\.pem\b|\.ppk\b|\.env\b|id_rsa|credentials|keychain|密钥|凭据|密码)/i;

/** Buckets one event into the category shown on the overview. Order is priority order. */
function classifyRisk(item: StoredSecurityEvent): RiskCategory {
  const { event } = item;
  const haystack = `${event.rule_id} ${event.rule} ${event.command_line} ${event.evidence} ${event.process} ${event.actor} ${event.summary} ${event.sensitive_types}`;
  const pick = (key: string) => RISK_CATEGORY_MAP.get(key) ?? RISK_CATEGORIES[RISK_CATEGORIES.length - 1];
  if (APP_OPERATION_PATTERN.test(haystack)) return pick("app");
  if (event.event_type === "UserInput") return pick("prompt");
  if (event.rule_id === "DATA.SECRET.EXFIL" || OUTBOUND_PATTERN.test(haystack)) return pick("outbound");
  if (event.secret_fingerprint || SECRET_PATTERN.test(haystack)) return pick("secret");
  if (SYSTEM_PATTERN.test(haystack)) return pick("system");
  if (event.event_type === "FileChange" || FILE_PATTERN.test(haystack)) return pick("file");
  if (event.event_type === "AgentCommand" || event.event_type === "ModelOutput" || event.event_type === "UserAction") return pick("command");
  return pick("other");
}

/**
 * Flags an event as dangerous so the feed can highlight it. This is a badge, not
 * a filter: every conversation and operation stays in the list either way.
 * Category matters as well as score -- an agent driving WeChat/QQ or reading a key
 * file only scores 25 under ACTIVITY.AGENT, yet it is exactly what the operator
 * asked to be warned about, so those categories bypass the numeric floor.
 */
function needsAttention(item: StoredSecurityEvent, category: RiskCategory) {
  if (ALWAYS_SHOWN_CATEGORIES.has(category.key)) return true;
  return item.event.risk >= 40 || isSensitiveEvent(item) || isDangerousEvent(item);
}

function buildRiskRows(events: StoredSecurityEvent[], dispositions: Map<number, EventDisposition>): RiskRowData[] {
  return events
    // AIGuard's own audit trail of the operator's own marks is not a conversation.
    .filter(({ event }) => event.event_type !== "SecurityResponse")
    .map((item) => {
      const disposition = dispositions.get(item.id) ?? null;
      const category = classifyRisk(item);
      return { item, category, status: (disposition?.status ?? "pending") as DispositionStatus, disposition, danger: needsAttention(item, category) };
    })
    .sort((left, right) => Date.parse(right.item.occurred_at) - Date.parse(left.item.occurred_at) || right.item.id - left.item.id);
}

function riskCounts(rows: RiskRowData[]) {
  return {
    total: rows.length,
    attention: rows.filter((row) => row.danger && row.status === "pending").length,
    criticalPending: rows.filter((row) => row.danger && row.status === "pending" && row.item.event.risk >= 70).length,
    resolved: rows.filter((row) => row.status === "resolved" || row.status === "acknowledged").length,
    ignored: rows.filter((row) => row.status === "ignored").length,
  };
}

function filterRiskRows(rows: RiskRowData[], status: StatusFilter, category: string, query: string) {
  const needle = query.trim().toLowerCase();
  return rows.filter((row) => {
    if (status === "attention" && !(row.danger && row.status === "pending")) return false;
    if (status === "critical" && !(row.danger && row.status === "pending" && row.item.event.risk >= 70)) return false;
    if (status === "resolved" && row.status !== "resolved" && row.status !== "acknowledged") return false;
    if (status === "ignored" && row.status !== "ignored") return false;
    if (category !== "all" && row.category.key !== category) return false;
    if (!needle) return true;
    const { event } = row.item;
    return `${event.rule} ${event.rule_id} ${event.summary} ${event.command_line} ${event.evidence} ${event.process} ${event.actor} ${event.sensitive_types}`.toLowerCase().includes(needle);
  });
}

function dispositionText(status: DispositionStatus) {
  return status === "resolved" ? "已处理" : status === "ignored" ? "已忽略" : status === "acknowledged" ? "已确认待跟进" : "未处理";
}
function statusFilterLabel(status: StatusFilter) {
  return status === "attention" ? "需处理的危险提示" : status === "critical" ? "高危待处理" : status === "resolved" ? "已处理与已确认" : status === "ignored" ? "已忽略" : "全部对话与操作";
}

function categoryLabel(key: string) { return RISK_CATEGORY_MAP.get(key)?.label ?? key; }
function riskActor(item: StoredSecurityEvent) {
  const { event } = item;
  if (event.event_type === "UserInput") return "你的输入";
  return event.actor || event.process || "本地操作";
}


function RiskStat({ label, value, tone, active, onClick }: { label: string; value: number; tone: string; active: boolean; onClick: () => void }) {
  return <button type="button" className={`risk-stat ${tone}${active ? " active" : ""}`} onClick={onClick} aria-pressed={active}><strong>{value}</strong><span>{label}</span></button>;
}

function RiskRow({ row, onOpen }: { row: RiskRowData; onOpen: () => void }) {
  const { item, category, status, danger } = row;
  const { event } = item;
  const Icon = category.icon;
  const tone = danger ? riskTone(event.risk) : "safe";
  const detail = isSensitiveEvent(item) ? sensitivePreview(event) : securityText(eventOperation(event));
  const classes = ["risk-row", tone, danger ? "danger" : "", status === "pending" ? "" : "handled"].filter(Boolean).join(" ");
  return <button type="button" className={classes} onClick={onOpen}>
    <span className={`risk-row-icon ${tone}`}><Icon size={16} /></span>
    <div className="risk-row-body">
      <div className="risk-row-title">
        <strong>{securityText(event.rule || event.rule_id || category.label)}</strong>
        <span className="risk-row-cat">{category.label}</span>
        {danger && status === "pending" && <span className="risk-row-flag"><ShieldAlert size={11} />需处理</span>}
        {status !== "pending" && <span className={`risk-row-state ${status}`}>{dispositionText(status)}</span>}
      </div>
      <p>{detail}</p>
      <small>{riskActor(item)} · {eventTypeLabel(event.event_type)}{event.sensitive_types ? ` · ${securityText(event.sensitive_types)}` : ""} · {formatDateTime(item.occurred_at)}</small>
    </div>
    <div className="risk-row-risk">{danger ? <><b className={tone}>{event.risk}</b><small>{riskLabel(event.risk)}</small></> : <><b className="safe">{event.risk}</b><small>正常</small></>}</div>
    <ChevronRight size={16} className="risk-row-arrow" />
  </button>;
}

function RiskDetailModal({ row, saving, onClose, onDisposition }: { row: RiskRowData; saving: boolean; onClose: () => void; onDisposition: (status: DispositionStatus, note: string) => void }) {
  const { item, category, status, disposition } = row;
  const { event } = item;
  const [note, setNote] = React.useState(disposition?.note ?? "");
  const [revealed, setRevealed] = React.useState(false);
  React.useEffect(() => { setNote(disposition?.note ?? ""); setRevealed(false); }, [item.id, disposition?.note]);
  const raw = event.command_line || event.evidence || event.summary || "未提供原始内容";
  const sensitive = isSensitiveEvent(item);
  const shown = sensitive && !revealed ? sensitivePreview(event) : raw;
  return <div className="finding-modal-backdrop" onMouseDown={(entry) => { if (entry.target === entry.currentTarget) onClose(); }}>
    <section className="finding-modal risk-modal" role="dialog" aria-modal="true" aria-labelledby="risk-modal-title">
      <header>
        <div><span className={`finding-modal-kind ${riskTone(event.risk)}`}>{category.label}</span><h2 id="risk-modal-title">{securityText(event.rule || event.rule_id || "检测到异常行为")}</h2></div>
        <button aria-label="关闭详情" onClick={onClose}><X size={18} /></button>
      </header>
      <div className="finding-modal-risk"><strong className={riskTone(event.risk)}>{event.risk}</strong><span>{riskLabel(event.risk)} · {formatDateTime(item.occurred_at)} · 当前状态：{dispositionText(status)}</span></div>
      <p className="finding-modal-summary">{securityText(event.summary || "检测到需要关注的本地行为。")}</p>
      <dl className="finding-modal-facts">
        <div><dt>谁触发的</dt><dd>{riskActor(item)}</dd></div>
        <div><dt>相关进程</dt><dd>{event.process || "--"}</dd></div>
        <div><dt>行为类型</dt><dd>{eventTypeLabel(event.event_type)}</dd></div>
        <div><dt>命中规则</dt><dd>{securityText(event.rule || event.rule_id || "--")}</dd></div>
        <div><dt>敏感类型</dt><dd>{securityText(event.sensitive_types || "无")}</dd></div>
        <div><dt>会话 / 项目</dt><dd>{event.session_id || "--"}{event.project ? ` · ${event.project}` : ""}</dd></div>
      </dl>
      <section className="finding-modal-raw">
        <h3>原始内容{sensitive && <button type="button" className="risk-reveal" onClick={() => setRevealed((current) => !current)}>{revealed ? "隐藏敏感内容" : "显示完整内容"}</button>}</h3>
        <pre>{shown}</pre>
        {event.evidence && event.evidence !== raw && <pre className="risk-evidence">{event.evidence}</pre>}
      </section>
      <section className="finding-modal-advice"><h3>建议处理</h3><p>{handlingAdvice(event)}</p></section>
      <section className="risk-note">
        <h3>处理备注（可留空）</h3>
        <textarea value={note} rows={2} maxLength={500} placeholder="例：已轮换该密钥 / 确认是我本人操作" onChange={(entry) => setNote(entry.target.value)} />
        {disposition && <small>上次标记：{dispositionText(disposition.status)} · {formatDateTime(disposition.updated_at)}</small>}
      </section>
      <footer>
        {status !== "pending" && <button type="button" disabled={saving} onClick={() => onDisposition("pending", "")}>恢复为未处理</button>}
        <button type="button" disabled={saving} onClick={() => onDisposition("acknowledged", note)}>先确认，稍后跟进</button>
        <button type="button" disabled={saving} onClick={() => onDisposition("ignored", note)}>忽略（误报）</button>
        <button type="button" className="finding-modal-close" disabled={saving} onClick={() => onDisposition("resolved", note)}>标记已处理</button>
      </footer>
    </section>
  </div>;
}

function EmergencyCenter({ events, onOpenEvents }: { events: StoredSecurityEvent[]; onOpenEvents: (eventId?: number) => void }) {
  if (!events.length) return <section className="emergency-center clear"><span><ShieldCheck size={21} /></span><div><strong>当前无紧急事件</strong><p>实时检测正常，未发现风险 80 以上事件。</p></div></section>;
  const top = events[0];
  return <section className={`emergency-center ${top.event.risk >= 95 ? "critical" : "warning"}`}>
    <span className="emergency-icon"><ShieldAlert size={24} /></span>
    <div className="emergency-primary"><small>紧急安全消息 · {events.length} 项待关注</small><h2>{securityText(top.event.rule || top.event.rule_id)}</h2><p>{securityText(top.event.summary)}</p>{isSensitiveEvent(top) && <div className="emergency-sensitive"><KeyRound size={14} /><b>{securityText(top.event.sensitive_types)}</b><code>{top.event.command_line || top.event.evidence || top.event.summary}</code></div>}</div>
    <div className="emergency-score"><strong>{top.event.risk}</strong><span>{riskLabel(top.event.risk)}</span></div>
    <div className="emergency-list">{events.slice(1, 4).map((item) => <div key={item.id}><i className={riskTone(item.event.risk)} /><span><b>{securityText(item.event.rule || item.event.rule_id)}</b><small>{item.event.sensitive_types ? securityText(item.event.sensitive_types) : formatTime(item.occurred_at)}</small></span><strong>{item.event.risk}</strong></div>)}</div>
    <button onClick={() => onOpenEvents(top.id)}>查看并处置<ChevronRight size={15} /></button>
  </section>;
}

function isSensitiveEvent({ event }: StoredSecurityEvent) { return Boolean(event.sensitive_types || event.secret_fingerprint || event.rule_id.includes("SENSITIVE") || event.rule_id === "DATA.SECRET.EXFIL"); }
function shouldInterrupt(item: StoredSecurityEvent) { return item.event.risk >= 95 || item.event.rule_id === "DATA.SECRET.EXFIL"; }
function isFreshEvent(item: StoredSecurityEvent) { const age = Date.now() - Date.parse(item.occurred_at); return age >= 0 && age <= 30_000; }
function isDangerousEvent(item: StoredSecurityEvent) { return item.event.risk >= 70 || /(?:DELETE|PUSH|RESET|EXFIL|DESTRUCTIVE|DANGEROUS|SENSITIVE)/i.test(item.event.rule_id); }
function handlingAdvice(event: StoredSecurityEvent["event"]) {
  const text = `${event.sensitive_types} ${event.rule_id} ${event.summary}`.toLowerCase();
  if (/password|密码|account/.test(text)) return "立即修改相关账号密码，退出其他登录会话，并开启多因素认证。";
  if (/token|key|secret|credential|私钥|密钥|凭据/.test(text)) return "立即撤销并轮换密钥/Token，检查使用范围和访问日志。";
  if (/bank|card|payment|银行|银行卡|支付/.test(text)) return "联系银行或支付平台冻结/换卡，核对近期交易。";
  if (/id card|身份证|identity|passport|社保/.test(text)) return "确认信息是否已外泄，联系相关机构并加强身份验证。";
  if (/git\.reset|reset\.hard|重置/.test(text)) return "停止继续提交；用 git reflog 找到重置前提交，再创建恢复分支或执行 git reset 恢复。";
  if (/git\.push\.force|force push|强推/.test(text)) return "通知协作者暂停推送，从远端备份或 reflog 找回提交，再恢复被覆盖分支。";
  if (/delete|删除/.test(text)) return "确认删除范围；优先从回收站、快照或最近备份恢复受影响文件/数据。";
  if (/exfil|外发|upload/.test(text)) return "立即停止外发，撤销已泄露凭据，并检查接收端、代理和访问日志。";
  return "确认操作来源和目标；保留证据后，按最小权限原则修复配置。";
}
function eventOperation(event: StoredSecurityEvent["event"]) {
  return event.command_line || event.evidence || event.process || event.event_type || "未提供操作信息";
}
function securityText(value: string) {
  return value
    .replace(/Model output contains sensitive information/gi, "智能体输出包含敏感信息")
    .replace(/The model produced sensitive information that requires review\.?/gi, "智能体生成了敏感信息，需要人工检查。")
    .replace(/Custom sensitive rule matched/gi, "自定义敏感规则命中")
    .replace(/A configured sensitive keyword or path was detected\.?/gi, "检测到已配置的敏感关键词或路径。")
    .replace(/Custom Sensitive Rule/gi, "自定义敏感规则")
    .replace(/Custom Sensitive Information/gi, "自定义敏感信息")
    .replace(/Sensitive information observed/gi, "检测到敏感信息")
    .replace(/Sensitive information was observed but outbound transmission was not confirmed\.?/gi, "检测到敏感信息，但尚未确认外发")
    .replace(/User input contains high-risk credential/gi, "用户输入包含高风险凭据")
    .replace(/User input contains sensitive information/gi, "用户输入包含敏感信息")
    .replace(/The user supplied a credential that should be rotated immediately\.?/gi, "用户输入了高风险凭据，应立即更换。")
    .replace(/The user supplied sensitive information to an agent\.?/gi, "用户向智能体输入了敏感信息。")
    .replace(/Recorded user input sent to an agent\.?/gi, "已记录发送给智能体的用户输入。")
    .replace(/Model output contains sensitive information/gi, "智能体输出包含敏感信息")
    .replace(/Database Credential/gi, "数据库凭据")
    .replace(/Account Password/gi, "账号密码")
    .replace(/AI\/API Key/gi, "AI/API 密钥")
    .replace(/Access Token/gi, "访问令牌")
    .replace(/Private Key\/Cloud Credential/gi, "私钥/云凭据")
    .replace(/Payment Key/gi, "支付密钥")
    .replace(/Chinese ID Card/gi, "身份证号码")
    .replace(/Bank Card/gi, "银行卡号")
    .replace(/Phone Number/gi, "手机号码")
    .replace(/Email Address/gi, "电子邮箱")
    .replace(/Daily Privacy/gi, "日常隐私")
    .replace(/Developer Secret/gi, "开发者密钥")
    .replace(/Banking Information/gi, "银行信息")
    .replace(/Custom Keyword/gi, "自定义敏感关键词")
    .replace(/Custom Sensitive Path/gi, "自定义敏感路径")
    .replace(/Sensitive types/gi, "敏感类型")
    .replace(/Dangerous operation/gi, "危险操作");
}
function eventTypeLabel(value: string) {
  return value === "UserInput" ? "用户输入" : value === "ModelOutput" ? "智能体输出" : value === "AgentCommand" ? "智能体命令" : value === "UserAction" ? "用户操作" : value === "FileChange" ? "文件变更" : value === "SecurityResponse" ? "安全处置" : securityText(value || "未知");
}
function prioritizedEvents(events: StoredSecurityEvent[]) {
  const closed = new Set<number>();
  for (const { event } of events) {
    if (event.event_type !== "SecurityResponse" || !/disposition:(?:false-positive|resolved)/.test(event.evidence)) continue;
    const target = event.summary.match(/event (\d+)/)?.[1];
    if (target) closed.add(Number(target));
  }
  return [...events]
    .filter(({ id, event }) => event.event_type !== "SecurityResponse" && !closed.has(id))
    .sort((left, right) => right.event.risk - left.event.risk || Date.parse(right.occurred_at) - Date.parse(left.occurred_at));
}
function sensitivePreview(event: StoredSecurityEvent["event"]) {
  const raw = event.command_line || event.evidence || event.summary || "已检测到敏感信息";
  const masked = maskSensitive(raw);
  if (masked !== raw.slice(0, 110)) return masked;
  const chars = raw.trim().slice(0, 110);
  if (chars.length <= 8) return "****";
  return `${chars.slice(0, 4)}${"*".repeat(Math.min(24, Math.max(8, chars.length - 8)))}${chars.slice(-4)}`;
}

function PanelHead({ title, subtitle, badge }: { title: string; subtitle: string; badge?: string }) { return <div className="live-panel-head"><div><h3>{title}</h3><p>{subtitle}</p></div>{badge && <span>{badge}</span>}</div>; }

function SecurityStat({ title, value, tone }: { title: string; value: number; tone: "blue" | "green" }) { return <article className={`security-stat ${tone}`}><span>{title}</span><strong>{value}</strong><Sparkline values={[value, value * .8, value * .9, value * .65, value * .85, value]} /></article>; }
function ApiSummary({ item }: { item?: StoredSecurityEvent }) {
  const masked = item ? sensitivePreview(item.event) : "暂无敏感凭据记录";
  return <aside className="api-summary"><div className="api-title"><h2>API 访问摘要</h2><button>更多</button></div>{item ? <><dl><div><dt>发现时间</dt><dd>{formatDateTime(item.occurred_at)}</dd></div><div><dt>来源</dt><dd>{item.event.actor || item.event.process || "本地事件"}</dd></div><div><dt>发生什么</dt><dd>{item.event.summary}</dd></div><div><dt>建议</dt><dd className="advice">立即审查并轮换相关凭据</dd></div></dl><div className="masked-input"><span>相关输入（摘要已脱敏）</span><div>{masked}<button title="复制脱敏摘要" onClick={() => void navigator.clipboard.writeText(masked)}><Copy size={15} /></button></div></div><div className="api-status"><span>状态</span><strong><i />未处理</strong></div></> : <Empty text="暂无 API 或敏感凭据事件" />}</aside>;
}
function RiskFlow({ score, signals }: { score: number; signals: number }) { return <section className="risk-flow"><div className="flow-lines left"><span>用户输入</span></div><div className={`risk-score ${riskTone(score)}`} style={{ "--risk": score } as React.CSSProperties}><div><strong>{score}</strong><span>API Risk</span><b>{riskLabel(score)}</b><small>共 {signals} 个风险信号</small></div></div><div className="flow-lines right"><span>智能体执行</span></div></section>; }
function SecurityPanel({ title, action, children }: { title: string; action: string; children: React.ReactNode }) { return <section className="security-panel"><div className="security-panel-head"><h2>{title}</h2><button>{action}<span>⌄</span></button></div>{children}</section>; }
function AgentList({ agents }: { agents: Array<{ name: string; last: string }> }) { return <div className="agent-list">{agents.length ? agents.map((agent) => <div key={agent.name}><i /><span className="agent-avatar">{agent.name.slice(0, 2).toUpperCase()}</span><p><strong>{agent.name}</strong><small>已记录｜最近活动 {formatTime(agent.last)}</small></p><b>活跃</b></div>) : <Empty text="暂无智能体活动" />}</div>; }
function IssueList({ issues }: { issues: StoredSecurityEvent[] }) { return <div className="issue-list">{issues.length ? issues.map(({ id, occurred_at, event }) => <div key={id}><span className={`risk-tag ${riskTone(event.risk)}`}>{riskLabel(event.risk)}</span><time>{formatTime(occurred_at)}</time><strong>{event.actor || event.process || "本地"}</strong><b>{event.rule}</b><p>{event.summary}</p><ChevronRight size={16} /></div>) : <Empty text="暂无重点问题" />}</div>; }
function AuditSummary({ prompt, commands, network }: { prompt: number; commands: number; network: number }) { const total = prompt + commands + network; return <div className="audit-summary"><div className="audit-ring" style={{ "--audit": `${Math.min(total * 8, 100)}%` } as React.CSSProperties}><strong>{total}</strong><span>总数</span></div><div className="audit-legend"><p><i className="blue" />Prompt 风险：用户输入 <strong>{prompt}</strong></p><p><i className="cyan" />本地工具与命令 <strong>{commands}</strong></p><p><i className="purple" />网络与外发信号 <strong>{network}</strong></p></div></div>; }
function RecordPanel({ title, icon: Icon, items }: { title: string; icon: LucideIcon; items: StoredSecurityEvent[] }) { return <section className="record-panel"><div className="record-title"><h2><Icon size={16} />{title}</h2><button>更多</button></div><div>{items.length ? items.map(({ id, occurred_at, event }) => <article key={id}><time>{formatTime(occurred_at)}</time><strong>{event.actor || event.process || "本地"}</strong><span>{event.rule || event.summary}</span><b className={riskTone(event.risk)}>{riskLabel(event.risk)}</b></article>) : <Empty text="暂无记录" />}</div></section>; }
function uniqueAgents(events: StoredSecurityEvent[]) { const map = new Map<string, string>(); for (const item of events) { const name = item.event.actor || (item.event.event_type !== "UserInput" ? item.event.process : ""); if (name && !map.has(name)) map.set(name, item.occurred_at); } return Array.from(map, ([name, last]) => ({ name, last })); }
function maskSensitive(value: string) {
  if (!value) return "已脱敏";
  return value
    .replace(/-----BEGIN [^-]+-----[\s\S]*?(?:-----END [^-]+-----|$)/g, "[私钥内容已脱敏]")
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+\/-]+/gi, "$1********")
    .replace(/\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret|private[_-]?key)\s*[:=]\s*)[^\s,;]+/gi, "$1********")
    .replace(/((?:密码|口令|验证码|银行卡号|银行账号|信用卡号|身份证号)\s*(?:是|为|[:=])\s*)[^\s,，。；;]+/g, "$1********")
    .replace(/([a-z][a-z0-9+.-]*:\/\/[^\s/:]+:)[^\s@]+@/gi, "$1********@")
    .replace(/sk-[A-Za-z0-9_-]+/g, (token) => `${token.slice(0, 3)}${"*".repeat(Math.min(token.length - 5, 20))}${token.slice(-2)}`)
    .replace(/\b\d{6}\d{8}\d{3}[\dXx]\b/g, (token) => `${token.slice(0, 3)}***********${token.slice(-4)}`)
    .replace(/\b\d{11,19}\b/g, (token) => `${token.slice(0, 3)}******${token.slice(-2)}`)
    .replace(/\b([\w.%+-]{2})[\w.%+-]*(@[\w.-]+\.[A-Za-z]{2,})\b/g, "$1***$2")
    .slice(0, 110);
}
function formatDateTime(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? "--" : date.toLocaleString(); }
function fuzzyMatch(value: string | null | undefined, query: string) {
  if (!query) return true;
  const source = (value ?? "").toLowerCase();
  return query.toLowerCase().split(/\s+/).every((term) => { let cursor = 0; return [...term].every((char) => { const index = source.indexOf(char, cursor); if (index < 0) return false; cursor = index + 1; return true; }); });
}
function processMatches(process: ProcessSnapshot, query: string) { if (!query) return true; if (/^\d+$/.test(query)) return String(process.pid) === query || String(process.parent_pid ?? "") === query; return fuzzyMatch(`${process.name} ${process.path ?? ""} ${process.command_line ?? ""}`, query); }
function portMatches(port: PortSnapshot, query: string) { if (!query) return true; if (/^\d+$/.test(query)) return String(port.port) === query || String(port.pid ?? "") === query; return fuzzyMatch(`${port.protocol} ${port.address} ${port.process_name ?? ""}`, query); }

const emptyGatewayChannel: GatewayChannelInput = { name: "", base_url: "", api_key: "", protocol: "openai", models: [], priority: 0, weight: 100, enabled: true };
const gatewayChannelsStorageKey = "aiguard.gateway.channels";
const gatewayClientKeyStorageKey = "aiguard.gateway.client-key";
function generateChannelKey() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return `aiguard-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
function displayChannelKey(value: string) {
  const key = value.trim();
  if (!key) return "未配置";
  if (key.length <= 8) return `${key.slice(0, 2)}••••${key.slice(-2)}`;
  return `${key.slice(0, 4)}••••••${key.slice(-4)}`;
}

function GatewayChannelsPage({ keysOnly = false }: { keysOnly?: boolean } = {}) {
  const [channels, setChannels] = React.useState<GatewayChannel[]>([]);
  const [info, setInfo] = React.useState<GatewayInfo | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [editing, setEditing] = React.useState<GatewayChannelInput | null>(null);
  const [testing, setTesting] = React.useState<GatewayChannel | null>(null);
  const [testModel, setTestModel] = React.useState("");
  const [testResult, setTestResult] = React.useState<GatewayChannelTestResult | null>(null);
  const [working, setWorking] = React.useState(false);
  const [modelMessage, setModelMessage] = React.useState<string | null>(null);
  const [clientKey, setClientKey] = React.useState(() => localStorage.getItem(gatewayClientKeyStorageKey) || "aiguard-local");
  const saveClientKey = (value: string) => { const next = value.trim() || generateChannelKey(); setClientKey(next); localStorage.setItem(gatewayClientKeyStorageKey, next); };
  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      if (browserMode) {
        const rows = JSON.parse(localStorage.getItem(gatewayChannelsStorageKey) || "[]") as GatewayChannel[];
        setChannels(rows); setInfo({ address: "http://127.0.0.1:18766/v1", api_key: clientKey, listen_address: "127.0.0.1:18766" }); setError(null); return;
      }
      const [rows, gatewayInfo] = await Promise.all([commands.gatewayChannels(), commands.gatewayInfo()]); setChannels(rows); setInfo(gatewayInfo); setClientKey(gatewayInfo.api_key); setError(null);
    }
    catch (reason: unknown) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setLoading(false); }
  }, []);
  React.useEffect(() => { void load(); }, [load]);
  const save = async () => { if (!editing) return; setWorking(true); try { const base_url=editing.base_url.trim(); const inferredProtocol=/anthropic\.com|claude/i.test(`${editing.name} ${base_url}`) ? "anthropic" : /generativelanguage\.googleapis\.com|gemini/i.test(`${editing.name} ${base_url}`) ? "gemini" : (editing.protocol ?? "openai"); const input = { ...editing, protocol: inferredProtocol, name: editing.name.trim(), base_url, api_key: editing.api_key.trim(), models: editing.models.flatMap((item) => item.split(/[,\n]/)).map((item) => item.trim()).filter(Boolean) }; if (browserMode) { const next = input.id ? channels.map((item) => item.id === input.id ? { ...item, ...input, id: item.id, available: true, consecutive_failures: 0, latency_ms: null, last_test_at: null, last_error: null } as GatewayChannel : item) : [...channels, { ...input, id: Date.now(), available: true, consecutive_failures: 0, latency_ms: null, last_test_at: null, last_error: null } as GatewayChannel]; localStorage.setItem(gatewayChannelsStorageKey, JSON.stringify(next)); setEditing(null); await load(); return; } await commands.saveGatewayChannel(input); setEditing(null); await load(); } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : String(reason)); } finally { setWorking(false); } };
  const toggle = async (channel: GatewayChannel) => { if (browserMode) { const next = channels.map((item) => item.id === channel.id ? { ...item, enabled: !item.enabled } : item); localStorage.setItem(gatewayChannelsStorageKey, JSON.stringify(next)); await load(); return; } await commands.saveGatewayChannel({ id: channel.id, name: channel.name, base_url: channel.base_url, api_key: channel.api_key, protocol: channel.protocol, models: channel.models, priority: channel.priority, weight: channel.weight, enabled: !channel.enabled }); await load(); };
  const remove = async (channel: GatewayChannel) => { if (!window.confirm(`确认删除渠道“${channel.name}”？`)) return; if (browserMode) { const next = channels.filter((item) => item.id !== channel.id); localStorage.setItem(gatewayChannelsStorageKey, JSON.stringify(next)); await load(); return; } await commands.deleteGatewayChannel(channel.id); await load(); };
  const updateChannelNumber = async (channel: GatewayChannel, field: "priority" | "weight", value: number) => {
    const next = field === "weight" ? Math.max(0, Math.round(value)) : Math.round(value);
    setChannels((current) => current.map((item) => item.id === channel.id ? { ...item, [field]: next } : item));
    try {
      if (browserMode) { const nextRows = channels.map((item) => item.id === channel.id ? { ...item, [field]: next } : item); localStorage.setItem(gatewayChannelsStorageKey, JSON.stringify(nextRows)); return; }
      await commands.saveGatewayChannel({ id: channel.id, name: channel.name, base_url: channel.base_url, api_key: channel.api_key, protocol: channel.protocol, models: channel.models, priority: field === "priority" ? next : channel.priority, weight: field === "weight" ? next : channel.weight, enabled: channel.enabled });
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : String(reason));
      await load();
    }
  };
  const runTest = async () => { if (!testing) return; setWorking(true); setTestResult(null); try { const result = await commands.testGatewayChannel(testing.id, testModel); setTestResult(result); await load(); } catch (reason: unknown) { setTestResult({ success: false, latency_ms: 0, model: testModel, message: reason instanceof Error ? reason.message : String(reason) }); } finally { setWorking(false); } };
  const fetchModels = async () => {
    if (!editing) return;
    if (!editing.base_url.trim() || !editing.api_key.trim()) {
      setModelMessage("请先填写基础地址和 API 密钥");
      return;
    }
    setWorking(true);
    setModelMessage(null);
    try {
      const models = editing.id ? await commands.fetchGatewayModels(editing.id) : await commands.fetchGatewayModelsPreview(editing);
      setEditing({ ...editing, models });
      setModelMessage(`已获取 ${models.length} 个模型`);
    } catch (reason: unknown) {
      setModelMessage(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setWorking(false);
    }
  };
  const available = channels.filter((channel) => channel.enabled && channel.available).length;
  return <div className="gateway-page">
    {editing && <ChannelModal editing={editing} setEditing={setEditing} save={save} fetchModels={fetchModels} clearModels={() => setEditing({ ...editing, models: [] })} modelMessage={modelMessage} working={working} />}
    <section className="gateway-endpoint"><div><span className="gateway-label"><i />本地统一网关</span><h2>一个地址调用全部渠道</h2><p>按模型筛选渠道，优先使用高优先级渠道；同优先级按权重分配，失败后自动切换。</p></div><div className="gateway-address"><label>接口地址</label><div><code>{info?.address ?? "正在读取..."}</code><button type="button" title="复制接口地址" onClick={() => info && void navigator.clipboard.writeText(info.address)}><Copy size={16} /></button></div><label className="gateway-key-label">网关客户端密钥</label><div className="gateway-key-editor"><input value={clientKey} onChange={(event) => saveClientKey(event.target.value)} /><button type="button" title="生成新密钥" onClick={() => saveClientKey(generateChannelKey())}><KeyRound size={15} />生成</button><button type="button" title="复制客户端密钥" onClick={() => void navigator.clipboard.writeText(clientKey)}><Copy size={15} /></button></div><small>调用统一网关时使用此密钥；渠道 API 密钥在渠道编辑框中单独管理。</small></div></section>
    <section className="gateway-summary"><div><strong>{channels.length}</strong><span>全部渠道</span></div><div><strong>{available}</strong><span>当前可用</span></div><div><strong>{new Set(channels.flatMap((channel) => channel.models)).size}</strong><span>可用模型</span></div><div><strong>{channels.filter((channel) => !channel.available).length}</strong><span>异常渠道</span></div></section>
    <section className="gateway-manager"><header><div><h2>{keysOnly ? "渠道密钥管理" : "渠道列表"}</h2><p>{keysOnly ? "每个渠道使用独立的上游 API 密钥，点击密钥即可编辑。" : "优先级越大越先使用；同优先级中，权重越大获得的请求越多。"}</p></div><button className="primary-command" onClick={() => setEditing({ ...emptyGatewayChannel })}><Plus size={16} />添加渠道</button></header>
      {error && <div className="notice error">{error}</div>}
      {loading && !channels.length ? <div className="loading-panel">正在读取渠道...</div> : <div className="gateway-table-wrap"><table className="gateway-table"><thead><tr><th>渠道</th><th>支持模型</th><th>渠道密钥</th><th>优先级</th><th>权重</th><th>可用状态</th><th>延迟</th><th>操作</th></tr></thead><tbody>{channels.length ? channels.map((channel) => <tr key={channel.id}><td><div className="channel-name"><i className={channel.enabled && channel.available ? "ok" : "bad"} /><span><strong>{channel.name}</strong><small>{channel.base_url}</small></span></div></td><td><div className="channel-models">{channel.models.length ? channel.models.slice(0, 3).map((model) => <span key={model}>{model}</span>) : <span>全部模型</span>}{channel.models.length > 3 && <b>+{channel.models.length - 3}</b>}</div></td><td><button className={`channel-key-status ${channel.api_key ? "configured" : "missing"}`} title="打开此渠道密钥管理" onClick={() => setEditing({ id: channel.id, name: channel.name, base_url: channel.base_url, api_key: channel.api_key, protocol: channel.protocol, models: channel.models, priority: channel.priority, weight: channel.weight, enabled: channel.enabled })}><KeyRound size={13} />{displayChannelKey(channel.api_key)}</button></td><td><input className="channel-number-input" type="number" value={channel.priority} aria-label={`${channel.name} 优先级`} onChange={(event) => setChannels((current) => current.map((item) => item.id === channel.id ? { ...item, priority: Number(event.target.value) } : item))} onBlur={(event) => void updateChannelNumber(channel, "priority", Number(event.target.value))} onKeyDown={(event) => { if (event.key === "Enter") event.currentTarget.blur(); }} /></td><td><input className="channel-number-input" type="number" min="0" value={channel.weight} aria-label={`${channel.name} 权重`} onChange={(event) => setChannels((current) => current.map((item) => item.id === channel.id ? { ...item, weight: Number(event.target.value) } : item))} onBlur={(event) => void updateChannelNumber(channel, "weight", Number(event.target.value))} onKeyDown={(event) => { if (event.key === "Enter") event.currentTarget.blur(); }} /></td><td><button className={`channel-toggle ${channel.enabled ? "on" : ""}`} onClick={() => void toggle(channel)}><i />{!channel.enabled ? "已停用" : channel.available ? "可用" : "不可用"}</button>{channel.last_error && <small className="channel-error" title={channel.last_error}>{channel.last_error}</small>}</td><td>{channel.latency_ms != null ? `${channel.latency_ms} 毫秒` : "未测试"}</td><td><div className="channel-actions"><button title="测试模型" onClick={() => { setTesting(channel); setTestModel(channel.models[0] ?? ""); setTestResult(null); }}><FlaskConical size={15} /></button><button title="编辑渠道" onClick={() => setEditing({ id: channel.id, name: channel.name, base_url: channel.base_url, api_key: channel.api_key, protocol: channel.protocol, models: channel.models, priority: channel.priority, weight: channel.weight, enabled: channel.enabled })}><Pencil size={15} /></button><button className="danger" title="删除渠道" onClick={() => void remove(channel)}><Trash2 size={15} /></button></div></td></tr>) : <tr><td colSpan={8}><Empty text="尚未添加渠道" /></td></tr>}</tbody></table></div>}
    </section>
    {testing && <div className="modal-backdrop"><section className="channel-test-dialog"><header><div><h2>测试渠道模型</h2><p>{testing.name} · {testing.base_url}</p></div><button title="关闭" onClick={() => setTesting(null)}><X size={17} /></button></header><label><span>测试模型</span><input list="gateway-models" value={testModel} onChange={(event) => setTestModel(event.target.value)} placeholder="输入模型名称" /><datalist id="gateway-models">{testing.models.map((model) => <option value={model} key={model} />)}</datalist></label>{testResult && <div className={`channel-test-result ${testResult.success ? "success" : "failed"}`}><strong>{testResult.success ? "测试成功" : "测试失败"}</strong><span>{testResult.latency_ms} 毫秒</span><p>{testResult.message}</p></div>}<footer><button onClick={() => setTesting(null)}>关闭</button><button className="primary-command" disabled={working || !testModel.trim()} onClick={() => void runTest()}>{working ? "测试中..." : "开始测试"}</button></footer></section></div>}
  </div>;
}

function ChannelModal({ editing, setEditing, save, fetchModels, clearModels, modelMessage, working }: { editing: GatewayChannelInput; setEditing: (value: GatewayChannelInput | null) => void; save: () => Promise<void>; fetchModels: () => Promise<void>; clearModels: () => void; modelMessage: string | null; working: boolean }) {
  const set = (patch: Partial<GatewayChannelInput>) => setEditing({ ...editing, ...patch });
  const required = !editing.name.trim() || !editing.base_url.trim() || !editing.api_key.trim();
  const canFetchModels = Boolean(editing.base_url.trim() && editing.api_key.trim());
  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setEditing(null); }}><section className="channel-modal-v2" role="dialog" aria-modal="true">
    <header><div><span>渠道配置</span><h2>{editing.id ? "编辑渠道" : "新增渠道"}</h2></div><button type="button" title="关闭" onClick={() => setEditing(null)}><X size={18} /></button></header>
    <div className="channel-modal-body">
      <label className="modal-field full"><span>渠道类型 <em>必选</em></span><select value={editing.protocol ?? "openai"} onChange={(event) => set({ protocol: event.target.value })}><optgroup label="国外渠道"><option value="openai">OpenAI / Azure / OpenRouter</option><option value="anthropic">Claude / Anthropic</option><option value="gemini">Google Gemini</option><option value="openai">AWS Bedrock</option><option value="openai">Mistral / Cohere / Perplexity / xAI</option></optgroup><optgroup label="国内渠道"><option value="openai">DeepSeek</option><option value="openai">通义千问</option><option value="openai">智谱 GLM</option><option value="openai">月之暗面 Kimi</option><option value="openai">豆包 / 火山引擎</option><option value="openai">百度文心 / 讯飞星火 / 腾讯混元</option><option value="openai">MiniMax / 硅基流动 / 百川 / 零一万物</option><option value="openai">其他 OpenAI 兼容渠道</option></optgroup></select></label>
      <label className="modal-field"><span>渠道名称 <em>必填</em></span><input value={editing.name} onChange={(event) => set({ name: event.target.value })} placeholder="例如：DeepSeek 主渠道" /></label>
      <label className="modal-field"><span>基础地址 <em>必填</em></span><input value={editing.base_url} onChange={(event) => set({ base_url: event.target.value })} placeholder="https://api.example.com/v1" /></label>
      <label className="modal-field full"><span>上游渠道 API 密钥 <em>必填</em></span><div className="modal-key-row"><input type="password" value={editing.api_key} onChange={(event) => set({ api_key: event.target.value })} placeholder="仅填写当前渠道的密钥" /><button type="button" title="为自建上游生成随机密钥" onClick={() => set({ api_key: generateChannelKey() })}><KeyRound size={14} />生成密钥</button></div><small className="modal-hint">每个渠道单独保存密钥；OpenAI、Claude、Gemini 不共用。公共平台密钥必须从对应平台获取，随机密钥仅适用于自建上游。</small></label>
      <div className="modal-model-head"><span>支持的模型</span><div><button type="button" onClick={() => void fetchModels()} disabled={working} title={canFetchModels ? "从渠道读取模型列表" : "请先填写基础地址和 API 密钥"}>自动获取模型</button><button type="button" onClick={clearModels}>清除全部模型</button></div></div>
      <textarea className="modal-models" value={editing.models.join("\n")} onChange={(event) => set({ models: event.target.value.split(/[,\n]/) })} placeholder="每行一个模型；留空表示接受全部模型" />
      {modelMessage ? <small className="modal-message">{modelMessage}</small> : !canFetchModels ? <small className="modal-hint">填写基础地址和 API 密钥后可自动获取模型</small> : null}
      <label className="modal-field"><span>优先级</span><input type="number" value={editing.priority} onChange={(event) => set({ priority: Number(event.target.value) })} /></label>
      <label className="modal-field"><span>权重</span><input type="number" min="0" value={editing.weight} onChange={(event) => set({ weight: Math.max(0, Number(event.target.value)) })} /></label>
      <label className="modal-switch"><input type="checkbox" checked={editing.enabled} onChange={(event) => set({ enabled: event.target.checked })} /><span>启用渠道</span></label>
    </div>
    <footer><button type="button" onClick={() => setEditing(null)}>取消</button><button type="button" className="primary-command" disabled={working || required} onClick={() => void save()}>{working ? "保存中..." : "保存渠道"}</button></footer>
  </section></div>;
}

function ResourceDashboard({ snapshot, summary, events, history }: { snapshot: SystemSnapshot | null; summary: DashboardCounts | null; events: StoredSecurityEvent[]; history: HistoryPoint[] }) {
  const disk = snapshot?.disks[0]; const memoryPercent = snapshot ? percent(snapshot.memory_used, snapshot.memory_total) : 0; const diskPercent = disk ? percent(disk.total - disk.available, disk.total) : 0; const topProcesses = (snapshot?.processes ?? []).slice().sort((a, b) => b.memory - a.memory).slice(0, 5);
  return <div className="dashboard"><section className="resource-grid"><ResourceCard icon={Cpu} label="CPU 使用率" value={snapshot ? `${snapshot.cpu_usage.toFixed(1)}%` : "--"} percent={snapshot?.cpu_usage ?? 0} color="green" history={history.map((p) => p.cpu)} /><ResourceCard icon={MemoryStick} label="内存使用" value={snapshot ? `${formatBytes(snapshot.memory_used)} / ${formatBytes(snapshot.memory_total)}` : "--"} percent={memoryPercent} color="blue" history={history.map((p) => p.memory)} /><ResourceCard icon={HardDrive} label={`磁盘使用 ${disk ? `(${disk.mount_point})` : ""}`} value={disk ? `${diskPercent.toFixed(0)}%` : "--"} detail={disk ? `${formatBytes(disk.total - disk.available)} / ${formatBytes(disk.total)}` : "暂无磁盘数据"} percent={diskPercent} color="purple" history={history.map((p) => p.disk)} /><NetworkCard /></section><section className="overview-grid"><Panel title="安全概况" subtitle="过去 24 小时" action="查看日志"><div className="security-overview"><div className="shield-visual"><ShieldCheck size={55} /><span /></div><SecurityCount icon={ShieldCheck} value={summary?.sensitive_input ?? 0} label="敏感输入" /><SecurityCount icon={CircleAlert} value={summary?.dangerous ?? 0} label="高风险事件" /><SecurityCount icon={CheckCircle2} value={summary?.sensitive_outbound ?? 0} label="疑似外发" /><SecurityCount icon={ShieldCheck} value={summary?.warning ?? 0} label="告警" /></div></Panel><Panel title="资源使用趋势" subtitle="最近采样"><TrendChart history={history} /></Panel></section><section className="overview-grid lower"><Panel title="高关注进程" action="查看全部"><ProcessTable processes={topProcesses} compact /></Panel><Panel title="最近安全事件" action="查看全部"><EventTable events={events.slice(0, 5)} compact /></Panel></section></div>;
}
function ResourceCard({ icon: Icon, label, value, detail, percent: valuePercent, color, history }: { icon: LucideIcon; label: string; value: string; detail?: string; percent: number; color: string; history: number[] }) { return <article className={`resource-card ${color}`}><div className="resource-main"><div className="gauge" style={{ "--value": `${clamp(valuePercent)}%` } as React.CSSProperties}><Icon size={25} /></div><div className="resource-copy"><span>{label}</span><strong>{value}</strong><small>{detail ?? `${clamp(valuePercent).toFixed(0)}% 当前占用`}</small></div></div><Sparkline values={history} /></article>; }
function NetworkCard() { return <article className="resource-card orange"><div className="network-head"><span className="icon-box"><Network size={24} /></span><div><span>网络速率</span><strong>暂不可用</strong></div></div><div className="network-values"><span><ArrowUp size={15} />-- MB/s</span><span><ArrowDown size={15} />-- MB/s</span></div><div className="network-placeholder" /></article>; }
function Panel({ title, subtitle, action, children }: { title: string; subtitle?: string; action?: string; children: React.ReactNode }) { return <section className="panel"><div className="panel-heading"><div><h2>{title}</h2>{subtitle && <span>{subtitle}</span>}</div>{action && <button>{action}<span>›</span></button>}</div>{children}</section>; }
function PagePanel({ children }: { title?: string; children: React.ReactNode }) { return <section className="panel page-panel">{children}</section>; }
function SecurityCount({ icon: Icon, value, label }: { icon: LucideIcon; value: number; label: string }) { return <div className="security-count"><Icon size={25} /><strong>{value}</strong><span>{label}</span></div>; }
function TrendChart({ history }: { history: HistoryPoint[] }) { const points = history.length ? history : [{ cpu: 0, memory: 0, disk: 0 }]; return <div className="trend"><div className="legend"><span className="cpu">CPU (%)</span><span className="memory">内存 (%)</span><span className="disk">磁盘 (%)</span></div><svg viewBox="0 0 640 160" preserveAspectRatio="none" aria-label="资源使用趋势"><g className="grid-lines"><line x1="0" y1="20" x2="640" y2="20" /><line x1="0" y1="70" x2="640" y2="70" /><line x1="0" y1="120" x2="640" y2="120" /></g><polyline className="line memory" points={chartPoints(points.map((p) => p.memory))} /><polyline className="line cpu" points={chartPoints(points.map((p) => p.cpu))} /><polyline className="line disk" points={chartPoints(points.map((p) => p.disk))} /></svg></div>; }
function Sparkline({ values }: { values: number[] }) { return <svg className="sparkline" viewBox="0 0 260 50" preserveAspectRatio="none" aria-hidden="true"><polyline points={smallChartPoints(values.length ? values : [0])} /></svg>; }
function ProcessTable({ processes, compact = false }: { processes: ProcessSnapshot[]; compact?: boolean }) {
  const [query, setQuery] = React.useState("");
  const [selectedPid, setSelectedPid] = React.useState<number | null>(null);
  const [confirming, setConfirming] = React.useState<ProcessSnapshot | null>(null);
  const [operation, setOperation] = React.useState<string | null>(null);
  const normalized = query.trim().toLowerCase();
  const filtered = processes.filter((process) => processMatches(process, normalized));
  const selected = processes.find((process) => process.pid === selectedPid) ?? null;
  const terminate = async (process: ProcessSnapshot) => {
    const result = await commands.terminateProcess(process.pid, process.name);
    setOperation(result.message);
    setConfirming(null);
  };
  if (compact) return <div className="table-wrap"><ProcessRows processes={processes} compact onSelect={() => undefined} /></div>;
  return <div className="process-explorer"><div className="list-toolbar"><label><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索进程、PID 或路径" /></label><span>{filtered.length} 个进程</span></div><div className="process-layout"><div className="table-wrap"><ProcessRows processes={filtered} onSelect={(process) => setSelectedPid(process.pid)} selectedPid={selectedPid} /></div><aside className="process-detail">{selected ? <><div className="detail-title"><span className="process-icon large">{selected.name.slice(0, 1).toUpperCase()}</span><div><h3>{selected.name}</h3><p>PID {selected.pid}</p></div></div><dl><div><dt>父进程 PID</dt><dd>{selected.parent_pid ?? "--"}</dd></div><div><dt>CPU</dt><dd>{selected.cpu_usage.toFixed(1)}%</dd></div><div><dt>内存</dt><dd>{formatBytes(selected.memory)}</dd></div><div><dt>可执行文件</dt><dd title={selected.path ?? ""}>{selected.path ?? "不可读取"}</dd></div><div><dt>命令行</dt><dd title={selected.command_line ?? ""}>{selected.command_line ?? "不可读取"}</dd></div></dl>{selected.protected ? <div className="protected-note"><LockKeyhole size={16} />{selected.protection_reason ?? "系统保护进程"}</div> : <button className="danger-button" onClick={() => setConfirming(selected)}><Trash2 size={15} />终止进程</button>}{operation && <p className="operation-result">{operation}</p>}</> : <Empty text="选择一个进程查看详情" />}</aside></div>{confirming && <div className="modal-backdrop"><div className="confirm-dialog"><span className="confirm-icon"><CircleAlert size={25} /></span><h3>确认终止进程？</h3><p>即将终止 <strong>{confirming.name}</strong>（PID {confirming.pid}）。未保存的数据可能丢失。</p><div><button onClick={() => setConfirming(null)}>取消</button><button className="danger" onClick={() => void terminate(confirming)}>确认终止</button></div></div></div>}</div>;
}
function ProcessRows({ processes, compact = false, onSelect, selectedPid }: { processes: ProcessSnapshot[]; compact?: boolean; onSelect: (process: ProcessSnapshot) => void; selectedPid?: number | null }) { return <table><thead><tr><th>进程</th><th>PID</th><th>CPU</th><th>内存</th>{!compact && <th>状态</th>}</tr></thead><tbody>{processes.length ? processes.map((process) => <tr key={`${process.pid}-${process.name}`} className={selectedPid === process.pid ? "selected-row" : ""} onClick={() => onSelect(process)}><td><span className="process-icon">{process.name.slice(0, 1).toUpperCase()}</span><strong>{process.name}</strong></td><td>{process.pid}</td><td>{process.cpu_usage.toFixed(1)}%</td><td>{formatBytes(process.memory)}</td>{!compact && <td>{process.protected ? <span className="status-pill protected">受保护</span> : <span className="status-pill ok">可管理</span>}</td>}</tr>) : <tr><td colSpan={compact ? 4 : 5}><Empty text="暂无进程数据" /></td></tr>}</tbody></table>; }
function PortTable({ ports }: { ports: PortSnapshot[] }) { const [query, setQuery] = React.useState(""); const normalized = query.trim().toLowerCase(); const filtered = ports.filter((port) => !normalized || port.protocol.includes(normalized) || port.address.toLowerCase().includes(normalized) || String(port.port).includes(normalized) || String(port.pid ?? "").includes(normalized)); return <div><div className="list-toolbar"><label><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索端口、地址、PID 或协议" /></label><span>{filtered.length} 个监听项</span></div><div className="table-wrap"><table><thead><tr><th>协议</th><th>地址</th><th>端口</th><th>PID</th><th>状态</th></tr></thead><tbody>{filtered.length ? filtered.map((port) => <tr key={`${port.protocol}-${port.address}-${port.port}-${port.pid}`}><td>{port.protocol.toUpperCase()}</td><td>{port.address}</td><td>{port.port}</td><td>{port.pid ?? "--"}</td><td><span className="status-pill ok">监听中</span></td></tr>) : <tr><td colSpan={5}><Empty text="没有匹配的监听端口" /></td></tr>}</tbody></table></div></div>; }
function ManagedPortTable({ ports }: { ports: PortSnapshot[] }) {
  const [query, setQuery] = React.useState("");
  const [confirming, setConfirming] = React.useState<PortSnapshot | null>(null);
  const normalized = query.trim().toLowerCase();
  const filtered = ports.filter((port) => portMatches(port, normalized));
  const terminate = async (port: PortSnapshot) => { if (port.pid == null || !port.process_name) return; await commands.terminateProcess(port.pid, port.process_name); setConfirming(null); };
  return <div className="port-explorer"><div className="list-toolbar"><label><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索端口、应用名、PID、地址或协议" /></label><span>{filtered.length} 个监听项</span></div><div className="table-wrap"><table><thead><tr><th>协议</th><th>地址</th><th>端口</th><th>PID</th><th>应用</th><th>状态</th><th>操作</th></tr></thead><tbody>{filtered.length ? filtered.map((port) => <tr key={`${port.protocol}-${port.address}-${port.port}-${port.pid}`}><td>{port.protocol.toUpperCase()}</td><td>{port.address}</td><td><strong>{port.port}</strong></td><td>{port.pid ?? "--"}</td><td>{port.process_name ?? "未知进程"}</td><td><span className="status-pill ok">监听中</span></td><td><button className="table-action danger" disabled={port.pid == null || !port.process_name} onClick={() => setConfirming(port)}><Square size={13} />结束进程</button></td></tr>) : <tr><td colSpan={7}><Empty text="没有匹配的监听端口" /></td></tr>}</tbody></table></div>{confirming && <div className="modal-backdrop"><div className="confirm-dialog"><h3>确认结束端口进程？</h3><p>{confirming.process_name}（PID {confirming.pid}）将被结束。</p><div><button onClick={() => setConfirming(null)}>取消</button><button className="danger" onClick={() => void terminate(confirming)}>确认结束</button></div></div></div>}</div>;
}
function SecurityEventsPage({ events, settings, focusedEventId, onSettingsChanged }: { events: StoredSecurityEvent[]; settings: AppSettings; focusedEventId: number | null; onSettingsChanged: (settings: AppSettings) => void }) {
  const [keywords, setKeywords] = React.useState(settings.sensitive_keywords.join("\n"));
  const [paths, setPaths] = React.useState(settings.sensitive_paths.join("\n"));
  const [saving, setSaving] = React.useState(false);
  const [message, setMessage] = React.useState<string | null>(null);
  React.useEffect(() => { setKeywords(settings.sensitive_keywords.join("\n")); setPaths(settings.sensitive_paths.join("\n")); }, [settings]);
  const save = async () => {
    setSaving(true); setMessage(null);
    try {
      const saved = await commands.updateAppSettings({ ...settings, sensitive_keywords: linesToList(keywords), sensitive_paths: linesToList(paths) });
      onSettingsChanged(saved); setMessage("规则已保存，新事件立即使用。历史事件不会重新扫描。");
    } catch (reason: unknown) { setMessage(`保存失败：${reason instanceof Error ? reason.message : String(reason)}`); }
    finally { setSaving(false); }
  };
  const sensitiveCount = events.filter(isSensitiveEvent).length;
  const dangerousCount = events.filter(isDangerousEvent).length;
  return <div className="security-events-page">
    <section className="event-summary-strip"><div><KeyRound size={18} /><span>敏感信息<strong>{sensitiveCount}</strong></span></div><div><ShieldAlert size={18} /><span>危险操作<strong>{dangerousCount}</strong></span></div><div><CircleAlert size={18} /><span>高危待处理<strong>{events.filter(({ event }) => event.risk >= 90).length}</strong></span></div><button onClick={() => document.getElementById("security-rule-config")?.scrollIntoView({ behavior: "smooth" })}><Settings size={15} />配置检测规则</button></section>
    <PagePanel title="安全事件"><EventTable events={events} focusedEventId={focusedEventId} /></PagePanel>
    <section className="panel event-rule-config" id="security-rule-config"><div className="panel-heading"><div><h2>安全事件检测配置</h2><span>关键词与敏感路径每行一项，保存后立即生效</span></div><span className="status-pill info">{linesToList(keywords).length + linesToList(paths).length} 条</span></div><div className="sensitive-settings-fields"><label><span>敏感关键词</span><textarea value={keywords} disabled={saving} onChange={(event) => setKeywords(event.target.value)} placeholder={"密码是\n银行卡号\nAPI_KEY\n生产环境密码"} /></label><label><span>敏感文件或路径</span><textarea value={paths} disabled={saving} onChange={(event) => setPaths(event.target.value)} placeholder={".env\ncredentials\nid_rsa\nsecrets.yml"} /></label></div><div className="sensitive-settings-actions"><p>{message ?? "覆盖日常隐私、账号凭据、技术开发、银行金融；敏感值仅展示脱敏摘要。"}</p><button onClick={() => void save()} disabled={saving}><ShieldCheck size={15} />{saving ? "保存中" : "保存检测规则"}</button></div></section>
  </div>;
}

function EventTable({ events, compact = false, focusedEventId = null }: { events: StoredSecurityEvent[]; compact?: boolean; focusedEventId?: number | null }) {
  const visibleEvents = events.filter(({ event }) => event.event_type !== "SecurityResponse");
  const [selectedId, setSelectedId] = React.useState<number | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [localDisposition, setLocalDisposition] = React.useState<Record<number, string>>({});
  React.useEffect(() => { if (focusedEventId != null) setSelectedId(focusedEventId); }, [focusedEventId]);
  const disposition = React.useMemo(() => {
    const result: Record<number, string> = {};
    for (const { event } of events) {
      if (event.event_type !== "SecurityResponse") continue;
      const target = event.summary.match(/event (\d+)/)?.[1];
      const status = event.evidence.match(/disposition:(reviewed|false-positive|resolved)/)?.[1];
      if (target && status) result[Number(target)] = status;
    }
    return { ...result, ...localDisposition };
  }, [events, localDisposition]);
  if (compact) return <div className="event-list">{visibleEvents.length ? visibleEvents.map(({ id, occurred_at, event }) => <article className="event-row" key={id}><i className={`event-dot ${riskTone(event.risk)}`} /><time>{formatTime(occurred_at)}</time><div><strong>{securityText(event.rule || event.rule_id)}</strong></div><span className="event-process">{event.process || event.actor || "本地事件"}</span><span className={`status-pill ${riskTone(event.risk)}`}>{riskLabel(event.risk)}</span></article>) : <Empty text="暂无安全事件" />}</div>;
  const selected = visibleEvents.find((item) => item.id === selectedId) ?? null;
  const setDisposition = async (status: "reviewed" | "false-positive" | "resolved") => {
    if (!selected) return;
    setSaving(true);
    try {
      await commands.recordInterception(selected.id, `disposition:${status}`);
      setLocalDisposition((current) => ({ ...current, [selected.id]: status }));
    } finally { setSaving(false); }
  };
  return <div className="security-event-explorer">
    <div className="event-list">{visibleEvents.length ? visibleEvents.map((item) => {
      const { id, occurred_at, event } = item;
      const sensitive = isSensitiveEvent(item);
      return <button className={`${selectedId === id ? "event-row selected" : "event-row"}${sensitive ? " sensitive" : ""}`} key={id} onClick={() => setSelectedId(id)}>
        <i className={`event-dot ${riskTone(event.risk)}`} /><time>{formatTime(occurred_at)}</time>
        <div><strong>{securityText(event.rule || event.rule_id)}</strong><p>{securityText(event.summary)}</p>{sensitive && <small className="sensitive-event-mark"><KeyRound size={11} />{securityText(event.sensitive_types || "敏感信息")} · {sensitivePreview(event)}</small>}</div>
        <span className="event-process">{event.process || event.actor || "本地事件"}</span>
        <span className={`status-pill ${riskTone(event.risk)}`}>{disposition[id] ? dispositionLabel(disposition[id]) : riskLabel(event.risk)}</span>
      </button>;
    }) : <Empty text="暂无安全事件" />}</div>
    {selected && <aside className="event-drawer">
      <div className="event-drawer-head"><div><span className={`status-pill ${riskTone(selected.event.risk)}`}>{riskLabel(selected.event.risk)} · {selected.event.risk}</span><h2>{securityText(selected.event.rule || selected.event.rule_id)}</h2><p>{securityText(selected.event.summary)}</p></div><button title="关闭详情" onClick={() => setSelectedId(null)}><X size={17} /></button></div>
      <div className="event-facts"><div><span>触发规则</span><strong>{securityText(selected.event.rule || "未标记")}</strong></div><div><span>事件类型</span><strong>{eventTypeLabel(selected.event.event_type)}</strong></div><div><span>来源</span><strong>{selected.event.actor || selected.event.process || "本地"}</strong></div><div><span>发现时间</span><strong>{formatDateTime(selected.occurred_at)}</strong></div><div><span>敏感类型</span><strong>{securityText(selected.event.sensitive_types || "未命中")}</strong></div><div><span>处置状态</span><strong>{dispositionLabel(disposition[selected.id])}</strong></div></div>
      {isSensitiveEvent(selected) && <section className="sensitive-event-detail"><div><KeyRound size={18} /><span><small>检测到的敏感信息</small><strong>{securityText(selected.event.sensitive_types || "敏感信息")}</strong></span></div><pre>{selected.event.command_line || selected.event.evidence || selected.event.summary}</pre><p>指纹：<code>{selected.event.secret_fingerprint || "历史事件未生成指纹"}</code></p></section>}
      <section className="event-proof"><h3>触发安全机制</h3><p>{selected.event.rule_id} · {securityText(selected.event.rule || selected.event.summary)}</p></section>
      <section className="event-proof"><h3>具体信息 / 操作</h3><pre>{eventOperation(selected.event)}</pre></section>
      <section className="event-proof"><h3>检测证据</h3><pre>{maskSensitive(selected.event.evidence || "无独立证据")}</pre></section>
      <section className="event-remediation"><div><ShieldCheck size={18} /><span><small>建议如何处理</small><strong>{handlingAdvice(selected.event)}</strong></span></div><p>此处只提供处理建议并记录用户状态，不会终止进程或自动修改系统。</p></section>
      <div className="event-disposition"><button disabled={saving} onClick={() => void setDisposition("reviewed")}><CheckCircle2 size={14} />已查看建议</button><button disabled={saving} onClick={() => void setDisposition("false-positive")}><CircleAlert size={14} />标记误报</button><button className="primary" disabled={saving} onClick={() => void setDisposition("resolved")}><ShieldCheck size={14} />已按建议处理</button></div>
      <small className="event-audit-note">仅写入本地处置记录，不执行 kill、删除、恢复或密码修改。</small>
    </aside>}
  </div>;
}
function dispositionLabel(status?: string) { return status === "reviewed" ? "已查看建议" : status === "false-positive" ? "误报" : status === "resolved" ? "已按建议处理" : "未处理"; }

function McpToolsPage() {
  const [events, setEvents] = React.useState<StoredAuditEvent[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [query, setQuery] = React.useState("");
  const [selectedId, setSelectedId] = React.useState<string | null>(null);
  const loadingRef = React.useRef(false);
  const load = React.useCallback(async (background = false) => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    if (!background) setLoading(true);
    try {
      const rows = await commands.searchEvents({ limit: 500 });
      setEvents(rows.filter(({ event }) => ["ToolCallRequested", "ToolCallStarted", "ToolCallCompleted", "ToolCallFailed", "McpToolCalled"].includes(event.event_type)));
    } finally { loadingRef.current = false; setLoading(false); }
  }, []);
  React.useEffect(() => { void load(); }, [load]);
  React.useEffect(() => {
    const timer = window.setInterval(() => void load(true), 2000);
    return () => window.clearInterval(timer);
  }, [load]);
  const filtered = events.filter(({ event }) => !query.trim() || `${event.summary} ${event.actor.name} ${event.source} ${event.risk.rule_id ?? ""}`.toLowerCase().includes(query.trim().toLowerCase()));
  const selected = filtered.find(({ event }) => event.event_id === selectedId) ?? null;
  const counts = { total: filtered.length, failed: filtered.filter(({ event }) => event.event_type === "ToolCallFailed").length, risky: filtered.filter(({ event }) => event.risk.score >= 60).length, servers: new Set(filtered.map(({ event }) => event.source)).size };
  return <div className="mcp-page"><section className="mcp-hero"><div><span className="eyebrow">MCP · TOOL OBSERVABILITY</span><h2>MCP 与工具</h2><p>查看 Agent 连接的工具调用、执行状态、风险等级与本地证据。只读展示，不会重新执行工具。</p></div><div className="mcp-kpis"><div><strong>{counts.servers}</strong><span>来源</span></div><div><strong>{counts.total}</strong><span>调用事件</span></div><div><strong>{counts.risky}</strong><span>风险调用</span></div><div><strong>{counts.failed}</strong><span>失败</span></div></div></section><section className="mcp-toolbar"><label className="audit-search"><Search size={14} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索 Server、Tool、Agent 或规则" /></label><button onClick={() => void load()} disabled={loading}><RefreshCw size={14} className={loading ? "spin" : ""} />刷新</button><span>本地审计数据</span></section><section className="mcp-layout"><div className="mcp-list">{loading && !events.length ? <div className="loading-panel">正在读取工具调用...</div> : filtered.length ? filtered.map(({ event }) => <button className={selectedId === event.event_id ? "mcp-call selected" : "mcp-call"} key={event.event_id} onClick={() => setSelectedId(event.event_id)}><span className={`mcp-call-icon ${event.risk.score >= 90 ? "danger" : event.risk.score >= 60 ? "warning" : ""}`}><Play size={14} /></span><div><strong>{toolName(event)}</strong><small>{event.actor.name} · {event.source}</small><p>{event.summary}</p></div><time>{formatDateTime(event.occurred_at)}</time><b className={event.risk.score >= 60 ? "warning" : "ok"}>{toolStatus(event.event_type)}</b></button>) : <Empty text="暂无 MCP 或工具调用事件" />}</div>{selected && <aside className="mcp-detail"><div className="mcp-detail-head"><div><span className={`status-pill ${selected.event.risk.score >= 90 ? "blocked" : selected.event.risk.score >= 60 ? "warning" : "ok"}`}>{selected.event.risk.level} · {selected.event.risk.score}</span><h3>{toolName(selected.event)}</h3><p>{selected.event.summary}</p></div><button onClick={() => setSelectedId(null)}><X size={16} /></button></div><dl><div><dt>调用类型</dt><dd>{selected.event.event_type}</dd></div><div><dt>Agent</dt><dd>{selected.event.actor.name}</dd></div><div><dt>Server / 来源</dt><dd>{selected.event.source}</dd></div><div><dt>规则</dt><dd>{selected.event.risk.rule_id ?? "未命中"}</dd></div><div><dt>Session</dt><dd>{selected.event.session_id ?? "--"}</dd></div><div><dt>Trace</dt><dd>{selected.event.trace_id ?? "--"}</dd></div></dl><div className="mcp-evidence"><strong>工具结果与证据</strong><p>{selected.event.risk.explanation || selected.event.summary}</p>{selected.event.evidence_refs.length ? selected.event.evidence_refs.map((ref) => <div key={ref.evidence_id}><span>{ref.kind}</span><small>{ref.evidence_id}{ref.preview ? ` · ${maskSensitive(ref.preview)}` : ""}</small></div>) : <small>暂无独立证据引用</small>}</div></aside>}</section></div>;
}
function toolName(event: StoredAuditEvent["event"]) { const match = event.summary.match(/(?:tool|工具)[:： ]+([^\s,，]+)/i); return match?.[1] ?? event.risk.rule_id ?? event.event_type; }
function toolStatus(type: string) { return type === "ToolCallFailed" ? "失败" : type === "ToolCallCompleted" ? "完成" : type === "ToolCallStarted" ? "执行中" : "请求"; }
function DiagnosticsPage() {
  const [diagnosis, setDiagnosis] = React.useState<WorkspaceDiagnosis | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const run = React.useCallback(async () => {
    setLoading(true); setError(null);
    try { setDiagnosis(await commands.diagnostics()); } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : String(reason)); } finally { setLoading(false); }
  }, []);
  React.useEffect(() => { void run(); }, [run]);
  return <div className="diagnostics-page"><div className="diagnostic-actions"><span>{diagnosis?.project_root ?? "尚未识别项目根目录"}</span><button onClick={() => void run()} disabled={loading}><RefreshCw size={15} className={loading ? "spin" : ""} />{loading ? "诊断中" : "重新诊断"}</button></div>{error && <div className="notice error">诊断失败：{error}</div>}<section className="diagnostic-grid"><Panel title="Runtime 环境" subtitle="版本与可执行路径"><DiagnosticRows items={diagnosis?.runtimes ?? []} label={(item) => item.kind} detail={(item) => item.version ?? item.issue ?? "未检测"} path={(item) => item.executable} /></Panel><Panel title="Toolchain 工具链" subtitle="命令可用性"><DiagnosticRows items={diagnosis?.tools ?? []} label={(item) => item.name} detail={(item) => item.version ?? item.issue ?? "未检测"} path={(item) => item.executable} /></Panel></section><section className="panel"><div className="panel-heading"><div><h2>项目拓扑</h2><span>{diagnosis?.projects.length ?? 0} 个项目</span></div></div>{diagnosis?.projects.length ? <div className="project-topology">{diagnosis.projects.map((project) => <article className="project-topology-row" key={project.root}><div><strong>{project.name}</strong><small title={project.root}>{project.root}</small></div><span className={`status-pill ${project.state === "ready" ? "ok" : "warning"}`}>{project.state === "ready" ? "就绪" : project.state}</span><p>Runtime：{project.runtimes.length ? project.runtimes.join("、") : "未关联"}{project.issue ? `；${project.issue}` : ""}</p></article>)}</div> : <Empty text="未发现项目" />}</section><section className="panel"><div className="panel-heading"><div><h2>诊断问题</h2><span>{diagnosis?.issues.length ?? 0} 项</span></div></div>{diagnosis?.issues.length ? <ul className="diagnostic-issues">{diagnosis.issues.map((issue) => <li key={issue}><CircleAlert size={15} />{issue}</li>)}</ul> : <p className="settings-note"><CheckCircle2 size={18} />未发现明显环境问题。</p>}</section></div>;
}

function DiagnosticRows<T extends { available: boolean }>({ items, label, detail, path }: { items: T[]; label: (item: T) => string; detail: (item: T) => string; path: (item: T) => string | null }) { return <div className="diagnostic-rows">{items.length ? items.map((item) => <div className="diagnostic-row" key={label(item)}><span className={`diagnostic-dot ${item.available ? "ok" : "bad"}`} /><strong>{label(item)}</strong><span>{detail(item)}</span><small>{path(item) ?? "--"}</small></div>) : <Empty text="暂无诊断数据" />}</div>; }

function DiagnosticsExtras() {
  const [network, setNetwork] = React.useState<import("./lib/commands").NetworkCheck[]>([]);
  const [ai, setAi] = React.useState<import("./lib/commands").AiDiagnosis | null>(null);
  const [loading, setLoading] = React.useState(false);
  const run = async () => { setLoading(true); try { const [networkResult, aiResult] = await Promise.all([commands.networkDiagnostics(), commands.aiDiagnosis()]); setNetwork(networkResult); setAi(aiResult); } finally { setLoading(false); } };
  React.useEffect(() => { void run(); }, []);
  return <section className="diagnostic-grid"><Panel title="网络诊断" subtitle="连接与代理"><div className="network-checks">{network.map((check) => <div className="network-check" key={`${check.layer}-${check.name}`}><span className={`diagnostic-dot ${check.healthy ? "ok" : "bad"}`} /><strong>{check.name}</strong><span>{check.detail}</span><small>{check.latency_ms == null ? "--" : `${check.latency_ms} ms`}</small></div>)}<button className="diagnostic-run" onClick={() => void run()} disabled={loading}><RefreshCw size={14} />{loading ? "诊断中" : "复测网络与 AI"}</button></div></Panel><Panel title="本地 AI 诊断" subtitle={ai?.priority ? `优先级：${ai.priority}` : "规则摘要"}><div className="ai-diagnosis"><strong>{ai?.title ?? "等待诊断"}</strong>{ai?.evidence.map((item) => <p key={item}><CircleAlert size={14} />{item}</p>)}{ai?.actions.map((item) => <p className="action" key={item}><CheckCircle2 size={14} />{item}</p>)}</div></Panel></section>;
}

function AgentDetectionPage({ events, monitor, usage, collections }: { events: StoredSecurityEvent[]; monitor: MonitorStatus | null; usage: ModelUsageStats | null; collections: CollectionHealthRecord[] }) {
  const rows = React.useMemo(() => buildAgentAccessRows(monitor, usage), [monitor, usage]);
  const inputEvents = events.filter(({ event }) => event.event_type === "UserInput");
  const outputEvents = events.filter(({ event }) => event.event_type === "ModelOutput");
  const actionEvents = events.filter(({ event }) => event.event_type === "AgentCommand" || event.event_type === "UserAction");
  const riskCount = events.filter(({ event }) => (event.event_type === "UserInput" || event.event_type === "ModelOutput" || event.event_type === "AgentCommand") && event.risk >= 60).length;
  const detected = rows.filter((row) => row.detected).length;
  return <div className="agent-detection-page">
    <section className="agent-detection-hero"><div><span className="eyebrow">AGENT DETECTION · LIVE</span><h2>Agent 检测</h2><p>实时展示智能体收到的输入、生成的输出与本地执行动作。内容默认脱敏，风险事件同步进入审计。</p><div className="agent-live-badges"><span><i />每秒刷新</span><span>{monitor?.wmi_active ? "进程采集在线" : "进程采集降级"}</span><span>队列 {monitor?.queue_depth ?? 0}</span></div></div><div className="agent-hero-stats"><div><strong>{detected}</strong><span>已发现</span></div><div><strong>{inputEvents.length}</strong><span>输入</span></div><div><strong>{outputEvents.length}</strong><span>输出</span></div><div><strong>{riskCount}</strong><span>风险</span></div></div></section>
    <section className="agent-detection-grid"><AgentSignalPanel title="智能体输入" subtitle="用户 Prompt / 会话消息" icon={MessageSquare} tone="blue" items={inputEvents} empty="等待智能体输入" /><AgentSignalPanel title="智能体输出" subtitle="模型回复 / 输出内容" icon={Bot} tone="teal" items={outputEvents} empty="等待智能体输出" /></section>
    <section className="agent-detection-bottom"><div className="agent-action-panel"><div className="agent-panel-head"><div><h3>智能体本地动作</h3><p>命令、工具调用与文件操作</p></div><b>{actionEvents.length} 条</b></div><div className="agent-action-list">{actionEvents.slice(0, 10).map((item) => <AgentSignalRow key={item.id} item={item} compact />)}{!actionEvents.length && <Empty text="暂无本地动作" />}</div></div><div className="agent-catalog-panel"><div className="agent-panel-head"><div><h3>检测目录</h3><p>主流智能体本机运行状态</p></div><b>{detected}/{rows.length}</b></div><div className="agent-catalog-list">{rows.map((row) => <div key={row.agent}><i className={row.detected ? "online" : ""} /><strong>{row.agent}</strong><span>{row.detected ? "已发现活动" : "未发现活动"}</span></div>)}</div></div></section>
  </div>;
}
function AgentSignalPanel({ title, subtitle, icon: Icon, tone, items, empty }: { title: string; subtitle: string; icon: LucideIcon; tone: "blue" | "teal"; items: StoredSecurityEvent[]; empty: string }) { return <section className={`agent-signal-panel ${tone}`}><div className="agent-panel-head"><div><h3><Icon size={16} />{title}</h3><p>{subtitle}</p></div><b><i />实时</b></div><div className="agent-signal-list">{items.slice(0, 10).map((item) => <AgentSignalRow key={item.id} item={item} />)}{!items.length && <Empty text={empty} />}</div></section>; }
function AgentSignalRow({ item, compact = false }: { item: StoredSecurityEvent; compact?: boolean }) { const { event } = item; const preview = isSensitiveEvent(item) ? event.command_line || event.evidence || event.summary : event.command_line || event.evidence || event.summary || "无内容"; return <article className="agent-signal-row"><i className={riskTone(event.risk)} /><time>{formatTime(item.occurred_at)}</time><div><strong>{event.actor || event.process || "本地智能体"}</strong><p>{compact ? securityText(event.rule || event.summary) : preview}</p>{!compact && <small>{securityText(event.rule || event.rule_id)}</small>}</div><span className={`agent-risk ${riskTone(event.risk)}`}>{event.risk >= 60 ? riskLabel(event.risk) : "正常"}</span></article>; }

function AgentAccessPage({ monitor, usage, collections }: { monitor: MonitorStatus | null; usage: ModelUsageStats | null; collections: CollectionHealthRecord[] }) {
  const rows = React.useMemo(() => buildAgentAccessRows(monitor, usage), [monitor, usage]);
  const detected = rows.filter((row) => row.detected).length;
  const withUsage = rows.filter((row) => row.hasUsage).length;
  const queueDepth = monitor?.queue_depth ?? 0;
  const dropped = monitor?.dropped ?? 0;
  const recentHealth = collections.slice(0, 8);
  return <div className="audit-center">
    <section className="audit-hero">
      <div>
        <span className="eyebrow">AGENT ACCESS</span>
        <h2>Agent 接入</h2>
        <p>直接读取本机监控与采集健康，不做云端转发。</p>
      </div>
      <div className="audit-hero-metrics">
        <div><strong>{detected}</strong><span>已接入</span></div>
        <div><strong>{withUsage}</strong><span>有用量</span></div>
        <div><strong>{queueDepth}</strong><span>待写队列</span></div>
      </div>
    </section>
    <div className="audit-grid">
      <section className="audit-panel audit-health">
        <div className="audit-panel-title">
          <div><h3>接入目录</h3><small>监控来源、用量和接入状态</small></div>
        </div>
        <div className="health-grid">
          {rows.length ? rows.map((row) => <div key={row.agent}><i className={row.detected ? "health-ok" : "health-warning"} /><strong>{row.agent}</strong><span>{row.detail}</span><time>{row.status}</time></div>) : <Empty text="暂无接入数据" />}
        </div>
        <p className="settings-note"><Activity size={16} />队列丢弃 {dropped} 条，状态来自本地采集结果。</p>
      </section>
      <section className="audit-panel audit-health">
        <div className="audit-panel-title">
          <div><h3>采集健康</h3><small>最近本地检查结果</small></div>
        </div>
        <div className="health-grid">
          {recentHealth.length ? recentHealth.map((item) => <div key={item.id}><i className={item.status === "ok" ? "health-ok" : "health-warning"} /><strong>{item.component}</strong><span>{item.message}</span><time>{formatTime(item.checked_at)}</time></div>) : <Empty text="暂无采集健康记录" />}
        </div>
      </section>
    </div>
  </div>;
}

function buildAgentAccessRows(monitor: MonitorStatus | null, usage: ModelUsageStats | null) {
  const usageRows = new Map((usage?.agent_status ?? []).map((item) => [item.agent, item]));
  const baseRows = [
    {
      agent: "Codex",
      detected: Boolean(monitor?.codex_history || monitor?.codex_commands || usageRows.get("Codex")?.detected),
      detail: monitor?.codex_commands ? "命令日志已接入" : monitor?.codex_history ? "历史文件已接入" : "未发现接入痕迹",
      status: usageRows.get("Codex")?.has_usage ? "有用量" : "监控中",
      hasUsage: usageRows.get("Codex")?.has_usage ?? false,
    },
    {
      agent: "Claude Code",
      detected: Boolean(monitor?.claude_history || usageRows.get("Claude Code")?.detected),
      detail: monitor?.claude_history ? "历史文件已接入" : "未发现接入痕迹",
      status: usageRows.get("Claude Code")?.has_usage ? "有用量" : "监控中",
      hasUsage: usageRows.get("Claude Code")?.has_usage ?? false,
    },
    {
      agent: "OpenHands",
      detected: Boolean(monitor?.openhands || usageRows.get("OpenHands")?.detected),
      detail: monitor?.openhands ? "会话文件已接入" : "未发现接入痕迹",
      status: usageRows.get("OpenHands")?.has_usage ? "有用量" : "监控中",
      hasUsage: usageRows.get("OpenHands")?.has_usage ?? false,
    },
    {
      agent: "Cursor",
      detected: usageRows.get("Cursor")?.detected ?? false,
      detail: usageRows.get("Cursor")?.has_usage ? "存在用量记录" : "等待发现本地数据",
      status: usageRows.get("Cursor")?.has_usage ? "有用量" : "待接入",
      hasUsage: usageRows.get("Cursor")?.has_usage ?? false,
    },
    {
      agent: "Gemini CLI",
      detected: usageRows.get("Gemini CLI")?.detected ?? false,
      detail: usageRows.get("Gemini CLI")?.has_usage ? "存在用量记录" : "等待发现本地数据",
      status: usageRows.get("Gemini CLI")?.has_usage ? "有用量" : "待接入",
      hasUsage: usageRows.get("Gemini CLI")?.has_usage ?? false,
    },
  ];
  const extras = (usage?.agent_status ?? [])
    .filter((item) => !baseRows.some((row) => row.agent === item.agent))
    .map((item) => ({
      agent: item.agent,
      detected: item.detected,
      detail: item.has_usage ? "已发现用量记录" : "已发现但暂无用量",
      status: item.has_usage ? "有用量" : "已发现",
      hasUsage: item.has_usage,
    }));
  return [...baseRows, ...extras].sort((left, right) => Number(right.detected) - Number(left.detected) || left.agent.localeCompare(right.agent, "zh-CN"));
}

function SessionTimelinePage() {
  const [sessions, setSessions] = React.useState<AgentSession[]>([]);
  const [selectedSessionId, setSelectedSessionId] = React.useState<string | null>(null);
  const [events, setEvents] = React.useState<StoredAuditEvent[]>([]);
  const [selectedEventId, setSelectedEventId] = React.useState<string | null>(null);
  const [activeTraceId, setActiveTraceId] = React.useState<string | null>(null);
  const [mode, setMode] = React.useState<"session" | "trace">("session");
  const [query, setQuery] = React.useState("");
  const [eventType, setEventType] = React.useState("all");
  const [riskOnly, setRiskOnly] = React.useState(false);
  const [loadingSessions, setLoadingSessions] = React.useState(false);
  const [loadingEvents, setLoadingEvents] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const sessionsLoadingRef = React.useRef(false);
  const eventsLoadingRef = React.useRef(false);
  const loadSessions = React.useCallback(async (background = false) => {
    if (sessionsLoadingRef.current) return;
    sessionsLoadingRef.current = true;
    if (!background) setLoadingSessions(true);
    try {
      const rows = await commands.sessions(120);
      setSessions(rows);
      setSelectedSessionId((current) => current ?? rows[0]?.session_id ?? null);
      setError(null);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      sessionsLoadingRef.current = false;
      setLoadingSessions(false);
    }
  }, []);

  const loadSessionTimeline = React.useCallback(async (sessionId: string, background = false) => {
    if (eventsLoadingRef.current) return;
    eventsLoadingRef.current = true;
    if (!background) setLoadingEvents(true);
    try {
      const rows = await commands.sessionTimeline(sessionId, 300);
      setMode("session");
      setEvents(rows);
      setActiveTraceId(rows.find((item) => item.event.trace_id)?.event.trace_id ?? null);
      setSelectedEventId((current) => current && rows.some(({ event }) => event.event_id === current) ? current : rows[0]?.event.event_id ?? null);
      setError(null);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      eventsLoadingRef.current = false;
      setLoadingEvents(false);
    }
  }, []);

  const loadTraceTimeline = React.useCallback(async (traceId: string, background = false) => {
    if (eventsLoadingRef.current) return;
    eventsLoadingRef.current = true;
    if (!background) setLoadingEvents(true);
    try {
      const rows = await commands.trace(traceId, 300);
      setMode("trace");
      setEvents(rows);
      setActiveTraceId(traceId);
      setSelectedEventId((current) => current && rows.some(({ event }) => event.event_id === current) ? current : rows[0]?.event.event_id ?? null);
      setError(null);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      eventsLoadingRef.current = false;
      setLoadingEvents(false);
    }
  }, []);

  React.useEffect(() => { void loadSessions(); }, [loadSessions]);
  React.useEffect(() => {
    if (selectedSessionId) {
      void loadSessionTimeline(selectedSessionId);
    }
  }, [selectedSessionId, loadSessionTimeline]);
  React.useEffect(() => {
    const timer = window.setInterval(() => {
      void loadSessions(true);
      if (mode === "trace" && activeTraceId) void loadTraceTimeline(activeTraceId, true);
      else if (selectedSessionId) void loadSessionTimeline(selectedSessionId, true);
    }, 2000);
    return () => window.clearInterval(timer);
  }, [activeTraceId, loadSessionTimeline, loadSessions, loadTraceTimeline, mode, selectedSessionId]);

  const selectedSession = sessions.find((session) => session.session_id === selectedSessionId) ?? null;
  const filteredEvents = React.useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return events.filter(({ event }) => {
      if (eventType !== "all" && event.event_type !== eventType) return false;
      if (riskOnly && event.risk.score < 60) return false;
      const text = [
        event.event_id,
        event.event_type,
        event.actor.kind,
        event.actor.name,
        event.summary,
        event.risk.rule_id ?? "",
        event.risk.level,
        event.source,
        event.session_id ?? "",
        event.trace_id ?? "",
        event.span_id ?? "",
        event.parent_span_id ?? "",
      ].join(" ").toLowerCase();
      return !normalized || text.includes(normalized);
    });
  }, [events, query, eventType, riskOnly]);
  const selectedEvent = filteredEvents.find((item) => item.event.event_id === selectedEventId) ?? filteredEvents[0] ?? null;
  const summary = React.useMemo(() => {
    const traceCount = new Set(filteredEvents.map((item) => item.event.trace_id).filter(Boolean)).size;
    const spanCount = new Set(filteredEvents.map((item) => item.event.span_id).filter(Boolean)).size;
    const maxRisk = filteredEvents.reduce((highest, item) => Math.max(highest, item.event.risk.score), 0);
    const count = (type: string) => filteredEvents.filter(({ event }) => event.event_type === type).length;
    return { traceCount, spanCount, maxRisk, inputs: count("UserInput"), outputs: count("ModelOutput"), tools: count("ToolCallRequested"), commands: count("CommandExecuted") };
  }, [filteredEvents]);

  return <div className="audit-center">
    <section className="audit-hero">
      <div>
        <span className="eyebrow">SESSION TRACE</span>
        <h2>会话时间线</h2>
        <p>按本地 session 和 trace 还原用户输入、工具、命令和证据链。</p>
      </div>
      <div className="audit-hero-metrics">
        <div><strong>{filteredEvents.length}</strong><span>事件</span></div>
        <div><strong>{summary.traceCount}</strong><span>Trace</span></div>
        <div><strong>{summary.maxRisk}</strong><span>最高风险</span></div>
      </div>
    </section>
    <div className="audit-grid">
      <section className="audit-panel audit-sessions">
        <div className="audit-panel-title">
          <div><h3>会话列表</h3><small>{sessions.length} 个本地会话</small></div>
          <button onClick={() => void loadSessions()} disabled={loadingSessions}><RefreshCw size={14} className={loadingSessions ? "spin" : ""} /></button>
        </div>
        {sessions.length ? sessions.map((session) => <button key={session.session_id} className={session.session_id === selectedSessionId ? "audit-session active" : "audit-session"} onClick={() => setSelectedSessionId(session.session_id)}><span>{session.agent_id}</span><strong>{session.session_id}</strong><small>{formatDateTime(session.started_at)}{session.project_id ? ` · ${session.project_id}` : ""}</small></button>) : <Empty text="暂无会话数据" />}
      </section>
      <section className="audit-panel">
        <div className="audit-panel-title">
          <div>
            <h3>{mode === "trace" ? "Trace 视图" : "会话视图"}</h3>
            <small>{selectedSession ? `${selectedSession.agent_id} · ${selectedSession.session_id}` : "尚未选择会话"}</small>
          </div>
          <div className="audit-toolbar">
            <label className="audit-search"><Search size={14} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索事件、风险、证据" /></label>
            <select className="audit-select" value={eventType} onChange={(event) => setEventType(event.target.value)}><option value="all">全部类型</option><option value="UserInput">用户输入</option><option value="ModelOutput">Agent 输出</option><option value="ToolCallRequested">Tool Call</option><option value="CommandExecuted">命令</option><option value="FileChange">文件</option><option value="NetworkRequest">网络</option></select>
            <button className={riskOnly ? "active" : ""} onClick={() => setRiskOnly((value) => !value)}>仅风险</button>
            <button onClick={() => selectedSessionId && void loadSessionTimeline(selectedSessionId)} disabled={loadingEvents}>会话</button>
            <button onClick={() => activeTraceId && void loadTraceTimeline(activeTraceId)} disabled={!activeTraceId || loadingEvents}>Trace</button>
          </div>
        </div>
        {error && <div className="notice error">时间线读取失败：{error}</div>}
        <div className="timeline-summary"><span>输入 <strong>{summary.inputs}</strong></span><span>输出 <strong>{summary.outputs}</strong></span><span>工具 <strong>{summary.tools}</strong></span><span>命令 <strong>{summary.commands}</strong></span><span>Span <strong>{summary.spanCount}</strong></span></div>
        {loadingEvents && !events.length && <div className="loading-panel">正在读取时间线...</div>}
        {!loadingEvents && !filteredEvents.length ? <Empty text="暂无时间线事件" /> : <div className="audit-event-list">{filteredEvents.map((item) => <article className="audit-event" key={item.event.event_id} onClick={() => setSelectedEventId(item.event.event_id)}><i className={`audit-dot ${item.event.risk.level.toLowerCase().includes("high") || item.event.risk.score >= 90 ? "blocked" : item.event.risk.score >= 70 ? "warning" : ""}`} /><div><div className="audit-event-meta"><strong>{item.event.event_type}</strong><span>{item.event.actor.kind}</span><span>{item.event.actor.name}</span><time>{formatDateTime(item.event.occurred_at)}</time></div><p>{item.event.summary}</p><small>{item.event.source} · {item.event.source_confidence}{item.event.risk.rule_id ? ` · ${item.event.risk.rule_id}` : ""}</small></div><b>{item.event.risk.level}</b></article>)}</div>}
        {selectedEvent && <div className="audit-detail">
          <div className="audit-panel-title">
            <div><h3>事件详情</h3><small>{selectedEvent.event.event_id}</small></div>
            <div className="audit-toolbar">
              {selectedEvent.event.trace_id && <button onClick={() => void loadTraceTimeline(selectedEvent.event.trace_id!)}>查看 Trace</button>}
              {mode === "trace" && <button onClick={() => selectedSessionId && void loadSessionTimeline(selectedSessionId)}>回到会话</button>}
            </div>
          </div>
          <div className="health-grid">
            <div><i className="health-ok" /><strong>风险</strong><span>{selectedEvent.event.risk.score} / {selectedEvent.event.risk.level}</span><time>{selectedEvent.event.risk.rule_id ?? "--"}</time></div>
            <div><i className="health-ok" /><strong>来源</strong><span>{selectedEvent.event.source}</span><time>{selectedEvent.event.source_confidence}</time></div>
            <div><i className="health-ok" /><strong>Actor</strong><span>{selectedEvent.event.actor.kind}</span><time>{selectedEvent.event.actor.name}</time></div>
            <div><i className="health-ok" /><strong>链路</strong><span>{selectedEvent.event.session_id ?? "--"}</span><time>{selectedEvent.event.trace_id ?? "--"}</time></div>
          </div>
          <div className="audit-evidence">
            <strong>证据</strong>
            <p>{selectedEvent.event.summary}</p>
            {selectedEvent.event.evidence_refs.length ? selectedEvent.event.evidence_refs.map((evidence) => <div key={evidence.evidence_id}><span>{evidence.kind}</span><small>{evidence.evidence_id}{evidence.preview ? ` · ${maskSensitive(evidence.preview)}` : ""}</small></div>) : <small>无独立证据引用</small>}
            {selectedEvent.event.evidence_refs.length ? selectedEvent.event.evidence_refs.map((ref) => <div key={ref.evidence_id}><span>{ref.kind}</span><small>{ref.preview ?? ref.evidence_id}</small></div>) : <Empty text="暂无证据引用" />}
          </div>
        </div>}
      </section>
    </div>
  </div>;
}

function SettingsPage({ health, license, onActivated, onSettingsChanged }: { health: Health | null; license: LicenseState | null; onActivated: (state: LicenseState) => void; onSettingsChanged: (settings: AppSettings) => void }) {
  const [serverUrl, setServerUrl] = React.useState("");
  const [activationCode, setActivationCode] = React.useState("");
  const [activating, setActivating] = React.useState(false);
  const [message, setMessage] = React.useState<string | null>(null);
  const [settings, setSettings] = React.useState<AppSettings>(defaultSettings);
  const [sensitiveKeywords, setSensitiveKeywords] = React.useState("");
  const [sensitivePaths, setSensitivePaths] = React.useState("");
  const [settingsLoading, setSettingsLoading] = React.useState(true);
  const [updateChecking, setUpdateChecking] = React.useState(false);
  const [updateResult, setUpdateResult] = React.useState<import("./lib/commands").UpdateCheckResult | null>(null);
  const active = license?.status === "Active";
  React.useEffect(() => { void commands.appSettings().then((value) => { setSettings(value); setSensitiveKeywords(value.sensitive_keywords.join("\n")); setSensitivePaths(value.sensitive_paths.join("\n")); onSettingsChanged(value); }).catch((reason: unknown) => setMessage(`读取设置失败：${reason instanceof Error ? reason.message : String(reason)}`)).finally(() => setSettingsLoading(false)); }, [onSettingsChanged]);
  const saveSettings = async (next: AppSettings) => {
    setSettingsLoading(true); setMessage(null);
    try { const saved = await commands.updateAppSettings(next); setSettings(saved); setSensitiveKeywords(saved.sensitive_keywords.join("\n")); setSensitivePaths(saved.sensitive_paths.join("\n")); onSettingsChanged(saved); setMessage("设置已保存"); }
    catch (reason: unknown) { setMessage(`保存设置失败：${reason instanceof Error ? reason.message : String(reason)}`); }
    finally { setSettingsLoading(false); }
  };
  const activate = async () => {
    if (!serverUrl.trim() || !activationCode.trim()) { setMessage("请输入服务端地址和激活码"); return; }
    setActivating(true); setMessage(null);
    try { onActivated(await commands.activateLicense(serverUrl.trim(), activationCode.trim())); setActivationCode(""); setMessage("激活成功，许可证已保存"); }
    catch (reason: unknown) { setMessage(`激活失败：${reason instanceof Error ? reason.message : String(reason)}`); }
    finally { setActivating(false); }
  };
  const checkUpdate = async () => {
    setUpdateChecking(true); setMessage(null);
    try { setUpdateResult(await commands.checkAppUpdate(settings.update_server_url, settings.update_channel)); setMessage("更新清单验签通过"); }
    catch (reason: unknown) { setMessage(`检查更新失败：${reason instanceof Error ? reason.message : String(reason)}`); }
    finally { setUpdateChecking(false); }
  };
  return <div className="settings-grid">
    <section className="panel"><div className="panel-heading"><div><h2>应用信息</h2></div></div><dl><div><dt>版本</dt><dd>{health?.app_version ?? "--"}</dd></div><div><dt>平台</dt><dd>{health?.platform ?? "--"}</dd></div><div><dt>构建</dt><dd>{health?.build_profile ?? "--"}</dd></div></dl><div className="settings-options"><label><input type="checkbox" checked={settings.autostart} disabled={settingsLoading} onChange={(event) => void saveSettings({ ...settings, autostart: event.target.checked })} /><span>开机启动</span></label><small>登录 Windows 后自动启动 AIGuard 并持续监控。</small><label><input type="checkbox" checked={settings.notifications_enabled} disabled={settingsLoading} onChange={(event) => void saveSettings({ ...settings, notifications_enabled: event.target.checked })} /><span>高危事件通知</span></label><small>发现高危安全事件时发送系统通知。</small><label><input type="checkbox" checked disabled /><span>关闭窗口时隐藏到托盘</span></label><small>托盘菜单可重新打开或退出应用。</small></div></section>
    <section className="panel"><div className="panel-heading"><div><h2>授权状态</h2><span className={`status-pill ${active ? "ok" : "warning"}`}>{license?.status ?? "读取中"}</span></div></div><dl><div><dt>许可证</dt><dd>{license?.license_id ?? "未激活"}</dd></div><div><dt>有效期</dt><dd>{license?.expires_at ? formatDate(license.expires_at) : "--"}</dd></div><div><dt>离线可用至</dt><dd>{license?.offline_until ? formatDate(license.offline_until) : "--"}</dd></div></dl><div className="license-form"><input value={serverUrl} onChange={(event) => setServerUrl(event.target.value)} placeholder="License Server 地址" /><input value={activationCode} onChange={(event) => setActivationCode(event.target.value)} placeholder="激活码" /><button onClick={() => void activate()} disabled={activating}><KeyRound size={15} />{activating ? "激活中" : "在线激活"}</button></div>{message && <p className="settings-note">{message}</p>}<p className="settings-note"><LockKeyhole size={18} />证书使用 Windows DPAPI 保存，SQLite 只保存授权元数据。</p></section>
    <section className="panel"><div className="panel-heading"><div><h2>更新发布</h2><span>{updateResult?.verified ? "签名已验证" : "等待检查"}</span></div></div><div className="update-form"><input value={settings.update_server_url} onChange={(event) => setSettings({ ...settings, update_server_url: event.target.value })} placeholder="更新服务地址" /><input value={settings.update_channel} onChange={(event) => setSettings({ ...settings, update_channel: event.target.value })} placeholder="stable" /><button onClick={() => void saveSettings(settings)} disabled={settingsLoading}>保存</button><button onClick={() => void checkUpdate()} disabled={updateChecking}><RefreshCw size={15} className={updateChecking ? "spin" : ""} />检查更新</button></div>{updateResult && <dl><div><dt>当前版本</dt><dd>{updateResult.current_version}</dd></div><div><dt>最新版本</dt><dd>{updateResult.manifest.version}</dd></div><div><dt>状态</dt><dd>{updateResult.update_available ? "可更新" : "已是最新"}</dd></div></dl>}<p className="settings-note"><ShieldCheck size={18} />更新清单必须通过 Ed25519 验签，安装包下载后还需做 SHA-256 校验。</p></section>
    <section className="panel"><div className="panel-heading"><div><h2>监控状态</h2></div></div><p className="settings-note"><Activity size={18} />本地采集与 SQLite 持久化正常运行。</p></section>
    <section className="panel sensitive-settings"><div className="panel-heading"><div><h2>敏感信息规则</h2><span>覆盖日常隐私、账号凭据、技术开发、银行金融；每行一项</span></div><span className="status-pill info">{linesToList(sensitiveKeywords).length + linesToList(sensitivePaths).length} 条</span></div><div className="sensitive-settings-fields"><label><span>敏感关键词</span><textarea value={sensitiveKeywords} disabled={settingsLoading} onChange={(event) => setSensitiveKeywords(event.target.value)} placeholder={"密码是\n银行卡号\nAPI_KEY\n生产环境密码"} /></label><label><span>敏感文件或路径</span><textarea value={sensitivePaths} disabled={settingsLoading} onChange={(event) => setSensitivePaths(event.target.value)} placeholder={".env\ncredentials\nid_rsa\nsecrets.yml"} /></label></div><div className="sensitive-settings-actions"><p>命中后进入安全事件；界面仅展示脱敏预览和指纹，不展示原始敏感值。</p><button onClick={() => void saveSettings({ ...settings, sensitive_keywords: linesToList(sensitiveKeywords), sensitive_paths: linesToList(sensitivePaths) })} disabled={settingsLoading}><ShieldCheck size={15} />保存敏感规则</button></div></section>
  </div>;
}
function Empty({ text }: { text: string }) { return <div className="empty">{text}</div>; }
function UsageDashboard({ usage }: { usage: ModelUsageStats | null }) {
  const models = usage?.active_models ?? [];
  const recent = usage?.recent_requests ?? [];
  const daily = usage?.daily ?? [];
  const [range, setRange] = React.useState<5 | 15 | 30>(5);
  const points = daily.slice(-range);
  const totalFor = (days: number) => daily.slice(-days).reduce((sum, item) => sum + item.total_tokens, 0);
  return <div className="usage-dashboard">
    <section className="usage-hero">
      <div><span className="eyebrow">MODEL USAGE</span><h2>今日 Token 消耗</h2><p>查看今日 AI 请求、Token 输入输出、缓存与模型分布。</p></div>
      <div className="usage-total"><strong>{formatNumber(usage?.today_total_tokens ?? 0)}</strong><span>今日 Token</span></div>
    </section>
    <section className="resource-grid usage-kpis">
      <UsageKpi icon={MessageSquare} label="今日请求" value={formatNumber(usage?.today_requests ?? 0)} detail="实时请求次数" />
      <UsageKpi icon={ArrowDown} label="今日输入 Token" value={formatNumber(usage?.today_input_tokens ?? 0)} detail="用户输入与上下文" />
      <UsageKpi icon={ArrowUp} label="今日输出 Token" value={formatNumber(usage?.today_output_tokens ?? 0)} detail="模型输出" />
      <UsageKpi icon={Cpu} label="今日缓存 Token" value={formatNumber(usage?.today_cached_input_tokens ?? 0)} detail="已复用上下文" />
    </section>
    <section className="panel usage-history"><div className="panel-heading"><div><h2>历史 Token 用量</h2><span>按天汇总，含今日</span></div><div className="usage-presets">{([5, 15, 30] as const).map((days) => <button key={days} className={range === days ? "active" : ""} onClick={() => setRange(days)}>{days} 天</button>)}</div></div><div className="history-totals"><div><span>近 5 天</span><strong>{formatNumber(totalFor(5))}</strong></div><div><span>近 15 天</span><strong>{formatNumber(totalFor(15))}</strong></div><div><span>近 30 天</span><strong>{formatNumber(totalFor(30))}</strong></div></div><svg className="usage-line-chart" viewBox="0 0 640 180" preserveAspectRatio="none" aria-label="历史 Token 折线图"><g className="grid-lines"><line x1="0" y1="20" x2="640" y2="20" /><line x1="0" y1="80" x2="640" y2="80" /><line x1="0" y1="140" x2="640" y2="140" /></g><polyline className="line usage-line" points={usageChartPoints(points.map((item) => item.total_tokens))} /></svg><div className="usage-axis">{points.map((item) => <span key={item.date}>{item.date.slice(5)}</span>)}</div></section>
    <section className="panel"><div className="panel-heading"><div><h2>活跃模型</h2><span>{models.length} 个模型</span></div></div>{models.length ? <div className="event-list">{models.map((model) => <article className="event-row usage-row" key={`${model.provider}-${model.model}`}><i className="event-dot info" /><time>{formatNumber(model.requests)} 次</time><div><strong>{model.model}</strong><p>{model.provider} · 总 Token {formatNumber(model.total_tokens)}</p></div><span className="event-process">输入 {formatNumber(model.input_tokens)} / 输出 {formatNumber(model.output_tokens)}</span><span className="status-pill ok">活跃</span></article>)}</div> : <Empty text="暂无模型用量数据" />}</section>
    <section className="panel"><div className="panel-heading"><div><h2>最近请求</h2><span>保留最近 40 条记录</span></div></div>{recent.length ? <div className="event-list">{recent.slice(0, 40).map((item, index) => <article className="event-row usage-row" key={`${item.occurred_at}-${item.session_id ?? index}`}><i className="event-dot info" /><time>{formatTime(item.occurred_at)}</time><div><strong>{item.model}</strong><p>{item.provider} · Token {formatNumber(item.total_tokens)}</p></div><span className="event-process">输入 {formatNumber(item.input_tokens)} / 输出 {formatNumber(item.output_tokens)}</span><span className="status-pill info">已记录</span></article>)}</div> : <Empty text="暂无最近请求" />}</section>
  </div>;
}
function usageChartPoints(values: number[]) { const width = 640; const height = 160; const max = Math.max(...values, 1); return values.map((value, index) => `${values.length === 1 ? width / 2 : index / (values.length - 1) * width},${height - value / max * 130}`).join(" "); }
function UsageKpi({ icon: Icon, label, value, detail }: { icon: LucideIcon; label: string; value: string; detail: string }) { return <article className="resource-card usage-kpi"><div className="resource-main"><span className="icon-box"><Icon size={24} /></span><div className="resource-copy"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div></div></article>; }
function formatNumber(value: number) {
  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(1)} M`;
  }
  return new Intl.NumberFormat("zh-CN").format(value);
}
function formatBytes(bytes: number) { if (!bytes) return "0 B"; const units = ["B", "KB", "MB", "GB", "TB"]; const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1); return `${(bytes / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`; }
function formatTime(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? "--" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); }
function formatDate(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? "--" : date.toLocaleDateString(); }
function percent(value: number, total: number) { return total > 0 ? value / total * 100 : 0; }
function clamp(value: number) { return Math.max(0, Math.min(100, value)); }
function riskTone(risk: number) { return risk >= 90 ? "blocked" : risk >= 70 ? "warning" : "info"; }
function riskLabel(risk: number) { return risk >= 90 ? "高危" : risk >= 70 ? "警告" : "信息"; }
function chartPoints(values: number[]) { const width = 640; const height = 140; return values.map((value, index) => `${values.length === 1 ? width : index / (values.length - 1) * width},${height - clamp(value) / 100 * 120}`).join(" "); }
function smallChartPoints(values: number[]) { const width = 260; const height = 42; const max = Math.max(...values, 1); return values.map((value, index) => `${values.length === 1 ? 0 : index / (values.length - 1) * width},${height - value / max * 34}`).join(" "); }
ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
