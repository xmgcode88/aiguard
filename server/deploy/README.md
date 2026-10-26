# TASK-LICENSE-008

## Runtime endpoints

- `/health`: process liveness; no dependency check.
- `/ready`: PostgreSQL and configured Redis readiness.
- `/metrics`: Prometheus text metrics for request/error counters.

Configure Prometheus to scrape `/metrics`; alert on readiness failures, 5xx rate, activation failures, and latency.

## Backup

```powershell
$env:DATABASE_URL = "postgres://postgres:postgres@127.0.0.1:5432/aiguard"
./server/scripts/backup.ps1
```

Use `restore.ps1 -BackupFile <path>` only during a maintenance window. Store dumps outside the application host, encrypt them, and retain at least 14 daily copies. Test restore monthly in a separate database.

## Deployment rules

- Run at least two stateless API instances behind Nginx/Caddy.
- Keep PostgreSQL private; permit API security-group access only.
- Keep `LICENSE_SIGNING_SEED_BASE64` and `ADMIN_MFA_SECRET` in a secret manager.
- Redis is shared by API instances for distributed rate limiting.
- TLS terminates at the reverse proxy; forward `X-Forwarded-For`.
- Rollback: stop new instances, restore previous image, keep additive migrations; restore DB only after backup verification.
