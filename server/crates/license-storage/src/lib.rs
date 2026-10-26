use chrono::{DateTime, Utc};
use license_domain::{LicenseStatus, Plan};
use license_signing::hash_device_key;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("invalid data: {0}")]
    Data(String),
}
#[derive(Clone)]
pub struct Repository {
    pub pool: PgPool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseRecord {
    pub id: Uuid,
    pub license_no: String,
    pub plan: Plan,
    pub status: LicenseStatus,
    pub expires_at: Option<DateTime<Utc>>,
    pub offline_until: DateTime<Utc>,
    pub max_version: String,
    pub features: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: Uuid,
    pub license_id: Uuid,
    pub device_public_key: String,
    pub device_fingerprint: String,
    pub platform: String,
    pub status: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminLicenseSummary {
    pub id: Uuid,
    pub license_no: String,
    pub plan: String,
    pub status: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub offline_until: DateTime<Utc>,
    pub device_count: i64,
    pub created_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCodeSummary {
    pub id: Uuid,
    pub plan: String,
    pub duration_days: i32,
    pub max_devices: i32,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub redeemed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub redeemed_license_id: Option<Uuid>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminDeviceSummary {
    pub id: Uuid,
    pub license_id: Uuid,
    pub license_no: String,
    pub device_public_key: String,
    pub device_fingerprint: String,
    pub platform: String,
    pub status: String,
    pub first_activated_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminDashboard {
    pub licenses_total: i64,
    pub licenses_active: i64,
    pub codes_available: i64,
    pub devices_total: i64,
    pub devices_active: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRecord {
    pub version: String,
    pub channel: String,
    pub platform: String,
    pub minimum_license_version: String,
    pub download_url: String,
    pub sha256: String,
    pub signature: String,
    pub released_at: DateTime<Utc>,
}

struct ActivationLogEntry<'a> {
    license_id: Uuid,
    device_id: Uuid,
    action: &'a str,
    result: &'a str,
    client_version: &'a str,
    now: DateTime<Utc>,
}

pub struct PublishVersionInput<'a> {
    pub version: &'a str,
    pub channel: &'a str,
    pub platform: &'a str,
    pub minimum_license_version: &'a str,
    pub download_url: &'a str,
    pub sha256: &'a str,
    pub signature: &'a str,
    pub released_at: DateTime<Utc>,
}

impl Repository {
    pub async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await?;
        sqlx::migrate!("../../migrations").run(&pool).await?;
        Ok(Self { pool })
    }
    pub async fn find_code(
        &self,
        code_hash: &str,
    ) -> Result<Option<(Uuid, Plan, i32, i32)>, StorageError> {
        let row = sqlx::query("SELECT id, plan, duration_days, max_devices FROM license_codes WHERE code_hash=$1 AND status='available' AND (expires_at IS NULL OR expires_at > NOW()) FOR UPDATE").bind(code_hash).fetch_optional(&self.pool).await?;
        row.map(|r| {
            let plan = match r.get::<String, _>("plan").as_str() {
                "trial" => Plan::Trial,
                "perpetual" => Plan::Perpetual,
                _ => Plan::Subscription,
            };
            Ok((
                r.get("id"),
                plan,
                r.get("duration_days"),
                r.get("max_devices"),
            ))
        })
        .transpose()
    }
    pub async fn activate(
        &self,
        code_hash: &str,
        public_key: &str,
        fingerprint: &str,
        platform: &str,
        client_version: &str,
        now: DateTime<Utc>,
    ) -> Result<(LicenseRecord, DeviceRecord), StorageError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT id, plan, duration_days, max_devices FROM license_codes WHERE code_hash=$1 AND status='available' AND (expires_at IS NULL OR expires_at > NOW()) FOR UPDATE").bind(code_hash).fetch_optional(&mut *tx).await?.ok_or_else(|| StorageError::Data("LICENSE_NOT_FOUND".into()))?;
        let code_id: Uuid = row.get("id");
        let plan = match row.get::<String, _>("plan").as_str() {
            "trial" => Plan::Trial,
            "perpetual" => Plan::Perpetual,
            _ => Plan::Subscription,
        };
        let duration: i32 = row.get("duration_days");
        let _max_devices: i32 = row.get("max_devices");
        let license_id = Uuid::new_v4();
        let license_no = format!("lic_{}", license_id.simple());
        let expires = match plan {
            Plan::Perpetual => None,
            _ => Some(now + chrono::Duration::days(i64::from(duration))),
        };
        let offline = now
            + chrono::Duration::days(if matches!(plan, Plan::Perpetual) {
                180
            } else {
                30
            });
        sqlx::query("INSERT INTO licenses (id,license_no,plan,status,issued_at,expires_at,offline_until,max_version,features_json) VALUES ($1,$2,$3,'active',$4,$5,$6,'999.999.999',$7)").bind(license_id).bind(&license_no).bind(match plan {Plan::Trial=>"trial",Plan::Subscription=>"subscription",Plan::Perpetual=>"perpetual"}).bind(now).bind(expires).bind(offline).bind(serde_json::json!(["basic"])).execute(&mut *tx).await?;
        let device_id = Uuid::new_v4();
        sqlx::query("INSERT INTO license_devices (id,license_id,device_public_key,device_fingerprint,platform,first_activated_at,last_seen_at,status) VALUES ($1,$2,$3,$4,$5,$6,$6,'active')").bind(device_id).bind(license_id).bind(public_key).bind(fingerprint).bind(platform).bind(now).execute(&mut *tx).await?;
        sqlx::query("UPDATE license_codes SET status='redeemed',redeemed_at=$1,redeemed_license_id=$3,updated_at=NOW() WHERE id=$2")
            .bind(now)
            .bind(code_id)
            .execute(&mut *tx)
            .await?;
        self.log_tx(
            &mut tx,
            ActivationLogEntry {
                license_id,
                device_id,
                action: "activate",
                result: "success",
                client_version,
                now,
            },
        )
        .await?;
        tx.commit().await?;
        Ok((
            LicenseRecord {
                id: license_id,
                license_no,
                plan,
                status: LicenseStatus::Active,
                expires_at: expires,
                offline_until: offline,
                max_version: "999.999.999".into(),
                features: serde_json::json!(["basic"]),
            },
            DeviceRecord {
                id: device_id,
                license_id,
                device_public_key: public_key.into(),
                device_fingerprint: fingerprint.into(),
                platform: platform.into(),
                status: "active".into(),
            },
        ))
    }
    async fn log_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        entry: ActivationLogEntry<'_>,
    ) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO activation_logs (id,license_id,device_id,action,result,ip_hash,client_version,created_at) VALUES ($1,$2,$3,$4,$5,'redacted',$6,$7)")
            .bind(Uuid::new_v4())
            .bind(entry.license_id)
            .bind(entry.device_id)
            .bind(entry.action)
            .bind(entry.result)
            .bind(entry.client_version)
            .bind(entry.now)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
    pub async fn get_license(&self, id: Uuid) -> Result<(LicenseRecord, i64), StorageError> {
        let r=sqlx::query("SELECT id,license_no,plan,status,expires_at,offline_until,max_version,features_json FROM licenses WHERE id=$1").bind(id).fetch_optional(&self.pool).await?.ok_or_else(||StorageError::Data("LICENSE_NOT_FOUND".into()))?;
        let l = LicenseRecord {
            id: r.get("id"),
            license_no: r.get("license_no"),
            plan: parse_plan(&r.get::<String, _>("plan")),
            status: parse_status(&r.get::<String, _>("status")),
            expires_at: r.get("expires_at"),
            offline_until: r.get("offline_until"),
            max_version: r.get("max_version"),
            features: r.get("features_json"),
        };
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM license_devices WHERE license_id=$1 AND status='active'",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        Ok((l, count))
    }
    pub async fn find_device(
        &self,
        license_id: Uuid,
        public_key: &str,
    ) -> Result<DeviceRecord, StorageError> {
        let r=sqlx::query("SELECT id,license_id,device_public_key,device_fingerprint,platform,status FROM license_devices WHERE license_id=$1 AND device_public_key=$2").bind(license_id).bind(public_key).fetch_optional(&self.pool).await?.ok_or_else(||StorageError::Data("CERTIFICATE_DEVICE_MISMATCH".into()))?;
        Ok(DeviceRecord {
            id: r.get("id"),
            license_id: r.get("license_id"),
            device_public_key: r.get("device_public_key"),
            device_fingerprint: r.get("device_fingerprint"),
            platform: r.get("platform"),
            status: r.get("status"),
        })
    }
    pub async fn deactivate(&self, license_id: Uuid, public_key: &str) -> Result<(), StorageError> {
        sqlx::query("UPDATE license_devices SET status='deactivated',last_seen_at=NOW() WHERE license_id=$1 AND device_public_key=$2 AND status='active'").bind(license_id).bind(public_key).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn create_codes(
        &self,
        plan: &Plan,
        duration_days: i32,
        max_devices: i32,
        quantity: i32,
    ) -> Result<Vec<(Uuid, String)>, StorageError> {
        let mut tx = self.pool.begin().await?;
        let mut result = Vec::with_capacity(quantity as usize);
        for _ in 0..quantity {
            let id = Uuid::new_v4();
            let code = format_code(id);
            sqlx::query("INSERT INTO license_codes (id, code_hash, plan, duration_days, max_devices, expires_at) VALUES ($1,$2,$3,$4,$5,$6)")
                .bind(id).bind(code_hash(&code)).bind(plan_name(plan)).bind(duration_days).bind(max_devices).bind(Option::<DateTime<Utc>>::None)
                .execute(&mut *tx).await?;
            result.push((id, code));
        }
        tx.commit().await?;
        Ok(result)
    }
    pub async fn revoke_license(&self, id: Uuid) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE licenses SET status='revoked', updated_at=NOW() WHERE id=$1 AND status <> 'revoked'")
            .bind(id).execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Data("LICENSE_NOT_FOUND".into()));
        }
        Ok(())
    }
    pub async fn force_deactivate_device(
        &self,
        license_id: Uuid,
        device_id: Uuid,
    ) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE license_devices SET status='deactivated', last_seen_at=NOW() WHERE id=$1 AND license_id=$2")
            .bind(device_id).bind(license_id).execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Data("DEVICE_NOT_FOUND".into()));
        }
        Ok(())
    }
    pub async fn publish_version(
        &self,
        input: PublishVersionInput<'_>,
    ) -> Result<Uuid, StorageError> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO product_versions (id,channel,platform,version,minimum_license_version,download_url,sha256,signature,released_at,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'published')")
            .bind(id).bind(input.channel).bind(input.platform).bind(input.version).bind(input.minimum_license_version).bind(input.download_url).bind(input.sha256).bind(input.signature).bind(input.released_at)
            .execute(&self.pool).await?;
        Ok(id)
    }
    pub async fn admin_dashboard(&self) -> Result<AdminDashboard, StorageError> {
        let licenses_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM licenses")
            .fetch_one(&self.pool)
            .await?;
        let licenses_active: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM licenses WHERE status='active'")
                .fetch_one(&self.pool)
                .await?;
        let codes_available: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM license_codes WHERE status='available'")
                .fetch_one(&self.pool)
                .await?;
        let devices_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM license_devices")
            .fetch_one(&self.pool)
            .await?;
        let devices_active: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM license_devices WHERE status='active'")
                .fetch_one(&self.pool)
                .await?;
        Ok(AdminDashboard {
            licenses_total,
            licenses_active,
            codes_available,
            devices_total,
            devices_active,
        })
    }
    pub async fn admin_licenses(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AdminLicenseSummary>, StorageError> {
        let rows = sqlx::query("SELECT l.id,l.license_no,l.plan,l.status,l.expires_at,l.offline_until,COUNT(d.id) FILTER (WHERE d.status='active') AS device_count,l.created_at FROM licenses l LEFT JOIN license_devices d ON d.license_id=l.id GROUP BY l.id ORDER BY l.created_at DESC LIMIT $1 OFFSET $2")
            .bind(limit.clamp(1, 200)).bind(offset.max(0)).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|r| AdminLicenseSummary {
                id: r.get("id"),
                license_no: r.get("license_no"),
                plan: r.get("plan"),
                status: r.get("status"),
                expires_at: r.get("expires_at"),
                offline_until: r.get("offline_until"),
                device_count: r.get("device_count"),
                created_at: r.get("created_at"),
            })
            .collect())
    }
    pub async fn admin_codes(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AdminCodeSummary>, StorageError> {
        let rows = sqlx::query("SELECT id,plan,duration_days,max_devices,status,created_at,redeemed_at,expires_at,redeemed_license_id,updated_at FROM license_codes ORDER BY created_at DESC LIMIT $1 OFFSET $2").bind(limit.clamp(1,200)).bind(offset.max(0)).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|r| AdminCodeSummary {
                id: r.get("id"),
                plan: r.get("plan"),
                duration_days: r.get("duration_days"),
                max_devices: r.get("max_devices"),
                status: r.get("status"),
                created_at: r.get("created_at"),
                redeemed_at: r.get("redeemed_at"),
                expires_at: r.get("expires_at"),
                redeemed_license_id: r.get("redeemed_license_id"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }
    pub async fn admin_devices(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AdminDeviceSummary>, StorageError> {
        let rows = sqlx::query("SELECT d.id,d.license_id,l.license_no,d.device_public_key,d.device_fingerprint,d.platform,d.status,d.first_activated_at,d.last_seen_at FROM license_devices d JOIN licenses l ON l.id=d.license_id ORDER BY d.last_seen_at DESC LIMIT $1 OFFSET $2").bind(limit.clamp(1,200)).bind(offset.max(0)).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|r| AdminDeviceSummary {
                id: r.get("id"),
                license_id: r.get("license_id"),
                license_no: r.get("license_no"),
                device_public_key: r.get("device_public_key"),
                device_fingerprint: r.get("device_fingerprint"),
                platform: r.get("platform"),
                status: r.get("status"),
                first_activated_at: r.get("first_activated_at"),
                last_seen_at: r.get("last_seen_at"),
            })
            .collect())
    }
    pub async fn admin_code(&self, id: Uuid) -> Result<AdminCodeSummary, StorageError> {
        let row = sqlx::query("SELECT id,plan,duration_days,max_devices,status,created_at,redeemed_at,expires_at,redeemed_license_id,updated_at FROM license_codes WHERE id=$1").bind(id).fetch_optional(&self.pool).await?.ok_or_else(|| StorageError::Data("CODE_NOT_FOUND".into()))?;
        Ok(AdminCodeSummary {
            id: row.get("id"),
            plan: row.get("plan"),
            duration_days: row.get("duration_days"),
            max_devices: row.get("max_devices"),
            status: code_effective_status(&row.get::<String, _>("status"), row.get("expires_at")),
            created_at: row.get("created_at"),
            redeemed_at: row.get("redeemed_at"),
            expires_at: row.get("expires_at"),
            redeemed_license_id: row.get("redeemed_license_id"),
            updated_at: row.get("updated_at"),
        })
    }
    pub async fn update_code(
        &self,
        id: Uuid,
        duration_days: Option<i32>,
        max_devices: Option<i32>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<AdminCodeSummary, StorageError> {
        let current = self.admin_code(id).await?;
        if current.redeemed_at.is_some() && (duration_days.is_some() || max_devices.is_some()) {
            return Err(StorageError::Data("CODE_ALREADY_REDEEMED".into()));
        }
        if duration_days.is_some_and(|v| v < 0) || max_devices.is_some_and(|v| v < 1) {
            return Err(StorageError::Data("INVALID_REQUEST".into()));
        }
        sqlx::query("UPDATE license_codes SET duration_days=COALESCE($2,duration_days),max_devices=COALESCE($3,max_devices),expires_at=COALESCE($4,expires_at),updated_at=NOW() WHERE id=$1").bind(id).bind(duration_days).bind(max_devices).bind(expires_at).execute(&self.pool).await?;
        self.admin_code(id).await
    }
    pub async fn set_code_status(
        &self,
        id: Uuid,
        status: &str,
    ) -> Result<AdminCodeSummary, StorageError> {
        if status != "available" && status != "disabled" {
            return Err(StorageError::Data("INVALID_REQUEST".into()));
        }
        let current = self.admin_code(id).await?;
        if current.redeemed_at.is_some() {
            return Err(StorageError::Data("CODE_ALREADY_REDEEMED".into()));
        }
        if status == "available" && current.expires_at.is_some_and(|v| v <= Utc::now()) {
            return Err(StorageError::Data("CODE_EXPIRED".into()));
        }
        sqlx::query("UPDATE license_codes SET status=$2,updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(status)
            .execute(&self.pool)
            .await?;
        self.admin_code(id).await
    }
    pub async fn delete_code(&self, id: Uuid) -> Result<(), StorageError> {
        let current = self.admin_code(id).await?;
        if current.redeemed_at.is_some() {
            return Err(StorageError::Data("CODE_ALREADY_REDEEMED".into()));
        }
        sqlx::query("DELETE FROM license_codes WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn latest_version(
        &self,
        platform: &str,
        channel: &str,
    ) -> Result<VersionRecord, StorageError> {
        let r=sqlx::query("SELECT version,channel,platform,minimum_license_version,download_url,sha256,signature,released_at FROM product_versions WHERE platform=$1 AND channel=$2 AND status='published' ORDER BY released_at DESC LIMIT 1").bind(platform).bind(channel).fetch_optional(&self.pool).await?.ok_or_else(||StorageError::Data("UPDATE_NOT_FOUND".into()))?;
        Ok(VersionRecord {
            version: r.get("version"),
            channel: r.get("channel"),
            platform: r.get("platform"),
            minimum_license_version: r.get("minimum_license_version"),
            download_url: r.get("download_url"),
            sha256: r.get("sha256"),
            signature: r.get("signature"),
            released_at: r.get("released_at"),
        })
    }
}
fn code_effective_status(status: &str, expires_at: Option<DateTime<Utc>>) -> String {
    if status == "available" && expires_at.is_some_and(|v| v <= Utc::now()) {
        "expired".into()
    } else {
        status.into()
    }
}
fn parse_plan(v: &str) -> Plan {
    match v {
        "trial" => Plan::Trial,
        "perpetual" => Plan::Perpetual,
        _ => Plan::Subscription,
    }
}
fn parse_status(v: &str) -> LicenseStatus {
    match v {
        "revoked" => LicenseStatus::Revoked,
        "expired" => LicenseStatus::Expired,
        _ => LicenseStatus::Active,
    }
}
fn plan_name(plan: &Plan) -> &'static str {
    match plan {
        Plan::Trial => "trial",
        Plan::Subscription => "subscription",
        Plan::Perpetual => "perpetual",
    }
}
fn format_code(id: Uuid) -> String {
    let raw = id.simple().to_string().to_uppercase();
    format!(
        "{}-{}-{}-{}",
        &raw[0..4],
        &raw[4..8],
        &raw[8..12],
        &raw[12..16]
    )
}
pub fn code_hash(code: &str) -> String {
    hash_device_key(code)
}
