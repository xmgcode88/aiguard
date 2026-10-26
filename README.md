# AIGuard · AI 安全卫士

**看清楚：你给 AI 说了什么，AI 做了什么，哪些地方有风险。**

本地优先的 AI 编程智能体行为审计与风险防护桌面工具。面向使用 Codex / Claude Code / Cursor / OpenHands 等 AI 工具的开发者，把 AI 的每一步操作记录下来、解释清楚、标出风险，默认不拦截、数据不出本机。

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)](#平台支持)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-v2-24C8DB.svg?logo=tauri)](https://tauri.app/)

![AIGuard 安全总览](assets/screenshots/overview.png)

---

## 项目初衷

这个项目最初叫 **DevSentinel**，想解决的是一个很具体的问题：一台 Windows 开发机上同时跑着 IDE、Node 服务、Docker、WSL 和好几个 Python 环境时，**到底是谁在拖慢电脑、为什么服务起不来、哪些进程可以安全结束**。那时它是个"开发者工作站守护智能体"，做的是把 `node.exe` 翻译成"商城前端 · Vite Dev Server · 端口 5173"。

转折发生在 AI 编程工具真正开始动手之后。当 Codex、Claude Code、Cursor 能**直接在你自己的机器上**执行命令、改写文件、安装依赖、读取配置，甚至把内容发到外部地址时，让人不安的已经不是 CPU 占用率，而是另一件事：

> **它在我的机器上做了什么？我又是在哪一步把钥匙递给它的？**

而这个过程当时完全是黑箱：终端滚过去了、文件被改了、`.env` 被读进上下文了、请求发出去了 —— 事后既无法复盘，也无法证明"没有出事"。

于是方向转了：保留原有的进程 / 端口 / 资源归因能力，把重心移到**审计链路**上 —— 记录 AI 的每一次输入、命令、文件操作、进程启动和网络外发，用本地规则解释风险，并把判断依据（命令原文、命中规则、敏感信息类型、时间）原样摆出来。

三条底线决定了它现在的样子：

- **本地优先**：采集、规则判断、数据存储全部在本机完成，不设远程中转，不上报遥测。
- **默认只观察、不拦截**：先让你看清，再谈保护。误伤正常工作流比漏报更劝退用户。
- **证据优先**：每条风险都必须能点开看到原始证据和判定原因，而不是甩一个"高风险"标签。

AIGuard 做的是：**观察、记录、分析、提醒、保护。**

不做：自动攻击、漏洞利用、密码爆破、C2 控制、通用漏洞扫描平台。

---

## 核心能力

### 1. 记录 AI 做了什么

| 维度 | 采集方式 |
| --- | --- |
| 执行的命令 | Codex `sandbox_commands` 日志、进程启动事件（WMI `Win32_ProcessStartTrace`，不可用时降级为快照差分） |
| 文件读写删改 | `notify` 文件系统监听 |
| 启动/结束的进程 | 平台层进程快照与事件源 |
| 访问的网络目标 | 命令语义解析出的外发目标 |
| MCP Server / 工具调用 | 工具调用事件（`tool_calls` 表） |
| 工具执行结果 | 成功/失败、耗时、输出摘要、错误信息 |

### 2. 记录你给 AI 说了什么

- 用户提示词与复制给 AI 的日志/配置/代码片段
- 所属项目、会话、AI 工具与模型
- 来源可信度区分：`Codex` / `Claude Code` / `Cursor` / `MCP` / 日志 / 系统推断
- Codex 与 Claude Code 的 `history.jsonl` 增量读取，OpenHands `MessageEvent` 支持

### 3. 自动发现敏感信息

识别 API Key、Token、密码、数据库连接串、SSH 私钥、云平台凭据、Git 凭据、银行卡号、身份证号、手机号，以及 `.env`、云配置、Docker 配置、Agent 凭据文件。

界面统一脱敏为 `sk-****abcd`，同时保存 16 位**指纹**用于跨事件聚合 —— 报告里能看出"同一个密钥被用了几次"，但看不到密钥本身。支持用户自定义敏感关键词与敏感目录。

### 4. 自动发现危险行为

内置规则引擎对命令做语义解析（而非字符串匹配），当前规则：

| 规则 ID | 含义 |
| --- | --- |
| `GIT.RESET.HARD` | `git reset --hard` 丢弃未提交改动 |
| `GIT.PUSH.FORCE` | 强制推送覆盖远端历史 |
| `GIT.CHECKOUT.OVERWRITE` | checkout 覆盖本地修改 |
| `DB.DELETE.UNSCOPED` | 无 WHERE 条件的批量删除 |
| `DB.DDL.DESTRUCTIVE` | `DROP` / `TRUNCATE` 等破坏性 DDL |
| `FILE.DELETE.RECURSIVE` | 递归删除目录 |
| `FILE.SENSITIVE.ACCESS` | 读取 `.env`、私钥等敏感文件 |
| `CODE.DYNAMIC.EXEC` | `eval` / `iex` / `python -c` 等动态执行 |
| `CODE.DOWNLOAD.EXEC` | 下载后直接执行远程脚本 |
| `DATA.SECRET.EXFIL` | 把密钥类数据发往外部 |
| `NETWORK.OUTBOUND` | 非预期外联行为 |

风险分值 0–100，按 低风险 / 警告 / 高风险 / 严重风险 分档，每条命中都附带**判定原因**（不只是"高风险"三个字）。

### 5. 让风险看得懂、处置得了

- 完整安全时间线：`输入密码 → 读取配置 → 启动数据库工具 → 执行删除 → 外发数据`
- 统一事件模型：`Session → Trace → Span → ToolCall → Evidence`，支持按会话或按 Trace 回放一次任务的完整链路
- 关联分析：把「用户输入 → 工具调用 → 命令执行」串成一条因果链，而不是孤立的告警
- 事件处置：标记为 已查看 / 误报 / 已处理，保留处置人与备注
- 只回放记录，绝不重新执行命令

### 6. 采集健康自检

自动发现本机装了哪些 AI 工具、是否成功接入、MCP Server 是否在线、最近有没有真的收到事件；配置错误、权限不足、版本不兼容都会提示，避免"装了个瞎子审计器"。

### 7. 工作站诊断

运行时与工具链探测、项目服务拓扑、PATH 问题、端口/PID 归属查询，以及**网络分层诊断**：网卡 → 网关 → DNS → 代理 → TLS → 目标站点 → 应用工具，逐层定位断点。附带本地规则式 AI 诊断，生成摘要不依赖任何云端模型。

### 8. 本地 AI 渠道网关（实验性）

桌面端启动时会在 `127.0.0.1:18766` 开放一个**仅本机可访问**的 OpenAI 兼容网关。把 Codex / Claude Code / Cursor 的 Base URL 指过来，就能：

- 多渠道统一入口，按 **优先级 + 权重** 路由到不同上游
- 上游故障自动**故障转移**到下一个可用渠道
- 协议互转：Anthropic `/v1/messages`、Gemini `:generateContent` 与 OpenAI `chat/completions` 双向归一
- `/v1/models` 聚合所有可用渠道的模型并去重
- 渠道可用性、连续失败次数、延迟在「渠道管理」页可视

### 9. Token 与用量统计

按模型聚合今日输入 / 缓存 / 输出 / 推理 Token、请求数、每日趋势与最近请求明细。

---

## 界面预览

| 风险详情与处置 | 资源总览 |
| --- | --- |
| ![风险详情](assets/screenshots/risk-detail.png) | ![资源总览](assets/screenshots/resources.png) |
| 点开任意一条记录查看判定原因、原始证据、敏感信息类型，并给出处置建议：确认、忽略误报或标记已处理。 | CPU / 内存 / 磁盘实时占用、24 小时安全概况、资源趋势、高关注进程与最近事件。 |

| Token 消耗 | Agent 检测 |
| --- | --- |
| ![Token 消耗](assets/screenshots/usage.png) | ![Agent 检测](assets/screenshots/agents.png) |
| 今日请求数、输入 / 输出 / 缓存 Token、5–30 天历史趋势与按模型分布。 | 每个 AI 工具的接入状态、采集健康度，以及实时的输入 / 输出 / 本地动作面板。 |

| 进程 | 监听端口 |
| --- | --- |
| ![进程](assets/screenshots/processes.png) | ![监听端口](assets/screenshots/ports.png) |
| 进程列表与归属链路：父进程、可执行文件、命令行、CPU / 内存；系统关键进程标记为受保护。 | TCP / UDP 监听端口及其占用进程，可直接定位是谁占了端口。 |

| 渠道管理 | 新增上游渠道 |
| --- | --- |
| ![渠道管理](assets/screenshots/gateway-channels.png) | ![新增渠道](assets/screenshots/gateway-channel-form.png) |
| 本地统一网关入口，一个地址调用全部渠道；按优先级与权重调度，失败自动切换。 | 配置上游渠道：协议类型、Base URL、API Key、支持的模型、优先级与权重。 |

---

## 架构

```text
Codex / Claude Code / Cursor / OpenHands
   │  history.jsonl · sandbox 日志 · MCP · 文件变更 · 进程启动
   ▼
aiguard-monitor      增量读取 · 事件去重(60s) · 有界队列 · 输入↔命令关联
   ▼
aiguard-core         命令语义解析 · 风险规则引擎 · 敏感信息识别 · Trace 关联
   ▼
aiguard-storage      SQLite(WAL) · audit_events / sessions / traces / spans / evidence
   ▼
Tauri IPC (41 个 command)
   ▼
React 界面           安全总览 · 时间线 · Agent 检测 · 诊断 · 渠道管理
```

| Crate | 职责 |
| --- | --- |
| `crates/core` | 纯 Rust 领域内核：命令解析、规则引擎、敏感信息检测、事件/Trace 模型、Agent 适配器目录。无平台依赖，可单测 |
| `crates/monitor` | AI 工具行为采集：JSONL 增量读取、沙箱命令日志、OpenHands 会话、文件监听、去重与有界队列 |
| `crates/platform` | 平台抽象 + Windows 实现（CPU/内存/磁盘、进程、端口、WMI 事件、进程终止） |
| `crates/storage` | SQLite 持久化（sqlx + WAL + 外键），事件/审计/证据/采集健康/许可证状态 |
| `crates/diagnostics` | 工作站体检：运行时、工具链、项目拓扑、PATH、网络分层、本地 AI 摘要 |
| `crates/license` | 许可证客户端：Ed25519 验签、离线租约与时间回拨检测、设备身份、DPAPI 加密存储 |
| `crates/gateway` | 本地多渠道 AI 网关：协议归一、优先级/权重路由、故障转移 |
| `apps/desktop` | Tauri v2 应用层（命令注册、托盘、通知、开机启动）+ React 前端 |
| `server/` | 可选自建服务端：激活码签发、设备绑定、更新清单签名、管理后台 |

本地数据库：`%LOCALAPPDATA%\com.aiguard.desktop\aiguard.sqlite3`

---

## 快速开始

**前置条件**：Rust stable、Node.js 20+、Windows 10/11（需要 WebView2，Win11 自带）。

```powershell
cd apps/desktop
npm install
npm run tauri dev
```

打包安装程序：

```powershell
cd apps/desktop
npm run tauri build
```

产物在 `apps/desktop/src-tauri/target/release/bundle/`（NSIS `.exe` 安装包 + MSI）。

### 检查与测试

```powershell
# 前端
cd apps/desktop
npm run typecheck
npm run build

# Rust
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

国内网络可用仓库内 `.cargo/config.toml`（crates.io 走 rsproxy 镜像）。

---

## 隐私与安全边界

- **数据不出本机**：所有事件落本地 SQLite，没有任何遥测上报。
- **脱敏在出口做**：界面与查询结果只给 `sk-****abcd`，原文与指纹分开存储，指纹不可逆。
- **默认可观测、不拦截**：只记录与提醒，不阻断你的正常工作流。执行前拦截属于第四阶段路线。
- **会主动出网的只有三处**：许可证激活/刷新、更新清单检查、以及你自己配置的上游 AI 渠道（经由本地网关代理）。

> ⚠️ **已知限制**：网关渠道的 API Key 目前以明文存放在本地 SQLite 中（`gateway_channels.api_key`），尚未接入许可证模块使用的 Windows DPAPI 加密。如果你在多用户共享的机器上使用，请留意该数据库文件的访问权限。计划在后续版本改为 DPAPI 保护。

---

## 许可证服务端（可选）

`server/` 是一个独立可自建的 Rust 服务，用于商业化授权与更新分发。**不开源使用也完全不影响桌面端本地审计功能。**

技术栈：Axum + PostgreSQL + Redis（可选，用于分布式限流）+ Ed25519 签名 + TOTP 管理员 MFA。

```powershell
cd server
copy .env.example .env      # 按需填写
$env:DATABASE_URL = "postgres://postgres:postgres@localhost:5432/aiguard"
$env:LICENSE_SIGNING_SEED_BASE64 = "<自行生成的 32 字节随机种子 base64>"
cargo run -p license-api
```

提供的能力：许可证 激活 / 刷新 / 吊销、设备绑定与数量上限、激活码 CRUD、更新清单发布与 Ed25519 签名验证、`/health` `/ready` `/metrics`、管理员后台 `http://127.0.0.1:18765/admin`。

**安全约定：**

- 所有密钥只从环境变量读取，仓库内不含任何真实值（`.env` 已在 `.gitignore` 中）
- `LICENSE_SIGNING_SEED_BASE64`、`ADMIN_TOKEN`、`ADMIN_MFA_SECRET` 必须自行生成，**绝不要提交**
- 生产部署必须配置 HTTPS 反向代理；客户端的公钥通过编译期 `AIGUARD_LICENSE_PUBLIC_KEY` 固定，不接受运行时下发的公钥

详见 [server/README.md](./server/README.md)。

---

## 仓库结构

```text
apps/desktop/          Tauri v2 桌面端（Rust + React + TypeScript）
crates/                可复用的 Rust 领域 crate
  core/ monitor/ platform/ storage/ diagnostics/ license/ gateway/
server/                可选的许可证与更新服务端
assets/screenshots/    README 配图
scripts/               规则校验与调试辅助脚本
```

---

## 路线图

| 阶段 | 目标 | 状态 |
| --- | --- | --- |
| 一 · 记录下来 | 回答"AI 做了什么"：多工具接入、提示词/命令/文件/网络/MCP 记录、安全时间线、本地脱敏存储 | ✅ 已实现 |
| 二 · 发现风险 | 回答"哪里有问题、为什么"：敏感信息与危险命令识别、外发检测、风险解释、搜索筛选、采集健康、提醒 | ✅ 已实现 |
| 三 · 帮助处置 | 回答"怎么处理"：处置状态、会话回放、跨 Agent 数据流、Token 与费用、团队策略 | 🚧 进行中 |
| 四 · 主动保护 | 执行前提醒/确认/拦截、暂停与终止工具、签名规则热更新 | 📋 规划中 |

其他规划：macOS 平台适配、网关请求回灌审计链路、网关入站鉴权。

---

## 平台支持

| 平台 | 状态 |
| --- | --- |
| Windows 10 / 11 | ✅ 已实现（进程、端口、WMI 事件、DPAPI、开机启动、托盘） |
| macOS | 🚧 规划中（`crates/platform` 目前仅有 Windows 实现） |

---

## 贡献

欢迎 Issue 与 PR。提交前请确保：

1. `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings` 通过
2. `cargo test --workspace` 与 `npm run typecheck` 通过
3. **不要提交任何真实密钥、许可证种子、生产数据库连接串或个人路径**
4. 新增风险规则请同时补单元测试，并在代码中写清判定依据

---

## 许可证

[MIT](./LICENSE)
