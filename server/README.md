# License server

## Run

```powershell
$env:DATABASE_URL = "postgres://postgres:postgres@localhost:5432/aiguard"
$env:LICENSE_SIGNING_SEED_BASE64 = "<32-byte-base64-seed>"
cargo run -p license-api --manifest-path server/Cargo.toml
```

Migrations run automatically on startup. Never commit `LICENSE_SIGNING_SEED_BASE64`.

Endpoints: `activate`, `refresh`, `deactivate`, `status`, `updates/latest`, `health`.

Rollback: restore PostgreSQL backup, then revert migration/API deployment. Migration is additive and does not drop existing data.

### 更新服务

管理员发布版本：

```http
POST /api/v1/admin/updates/publish
X-Admin-Token: <ADMIN_TOKEN>
```

公开查询：

```http
GET /api/v1/updates/latest?platform=windows-x64&channel=stable
GET /api/v1/updates/signing-key
```

签名覆盖版本、渠道、平台、最低许可证版本、下载地址、SHA-256、发布时间和 `key_id`。客户端安装前必须验证 Ed25519 签名与 SHA-256。

Admin UI: `http://127.0.0.1:18765/admin`. Set `X-Admin-Token` and MFA code in page. Configure `REDIS_URL` to enable distributed rate limiting; configure `ADMIN_MFA_SECRET` (Base32) to require TOTP.

当前服务端阶段已具备：许可证激活/刷新/吊销、设备管理、授权码管理、版本发布、健康检查、就绪检查、Prometheus 指标和管理员 MFA/Redis 限流边界。生产部署前必须配置 PostgreSQL、`LICENSE_SIGNING_SEED_BASE64`、`ADMIN_TOKEN`，并通过 HTTPS 反向代理暴露 API。

Desktop offline verification uses compile-time `AIGUARD_LICENSE_PUBLIC_KEY`; set it to the base64 Ed25519 public key before release builds. Without it, client keeps local metadata state but does not trust a runtime-supplied key.

TASK-LICENSE-008 endpoints: `/ready` and `/metrics`. Backup/restore scripts: `server/scripts/backup.ps1`, `server/scripts/restore.ps1`.

Production config audit:

```http
GET /api/v1/admin/config/audit
Authorization: Bearer <admin-session-token>
```

Publish update manifest:

```powershell
.\server\scripts\publish-update.ps1 `
  -PackageFile .\release\AIGuard_0.2.0_x64-setup.exe `
  -Version 0.2.0 `
  -DownloadUrl https://download.example.com/AIGuard_0.2.0_x64-setup.exe `
  -ServerUrl https://license.example.com `
  -Platform windows-x86_64
```

### 激活码管理

登录后接口：

```text
GET    /api/v1/admin/license-codes
GET    /api/v1/admin/license-codes/{id}
POST   /api/v1/admin/license-codes
PATCH  /api/v1/admin/license-codes/{id}
POST   /api/v1/admin/license-codes/{id}/enable
POST   /api/v1/admin/license-codes/{id}/disable
DELETE /api/v1/admin/license-codes/{id}
```

激活码状态：`available`、`disabled`、`expired`、`redeemed`。列表返回 `redeemed_at`、`redeemed_license_id`，用于判断是否已使用。已兑换激活码禁止删除；已兑换激活码禁止修改兑换后有效天数和设备上限。
