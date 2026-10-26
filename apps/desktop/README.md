# AIGuard Desktop

AIGuard 桌面端：Tauri v2 + Rust + React + TypeScript。

## 前置条件

- Node.js 20+
- Rust stable + Cargo
- Tauri v2 系统依赖

## 开发

```powershell
npm install
npm run tauri dev
```

## 本地 AI 渠道网关

桌面端启动后会同时启动仅本机可访问的 OpenAI 兼容网关：

```text
http://127.0.0.1:18766/v1
```

在“渠道管理”中添加 OpenAI 兼容渠道、支持模型、优先级和权重。优先级数值越大越先使用；同优先级按权重分配，请求失败时自动尝试其他可用渠道。

## 检查

```powershell
npm run typecheck
npm run build
cd src-tauri
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

业务采集、许可证校验与本地网关的业务逻辑在仓库根目录的 `crates/` 下，本目录只负责 Tauri 应用层（命令注册、托盘、通知、窗口）与 React 界面。
