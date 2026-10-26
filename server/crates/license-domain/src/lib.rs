use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    Trial,
    Subscription,
    Perpetual,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LicenseStatus {
    Active,
    Expired,
    Revoked,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Deactivated,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub license_id: Uuid,
    pub device_public_key_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub offline_until: DateTime<Utc>,
    pub max_version: String,
    pub features: serde_json::Value,
    pub key_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseCertificate {
    pub payload: LicensePayload,
    pub signature: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LicenseError {
    #[error("license not found")]
    NotFound,
    #[error("license expired")]
    Expired,
    #[error("license revoked")]
    Revoked,
    #[error("device limit reached")]
    DeviceLimitReached,
    #[error("device blocked")]
    DeviceBlocked,
    #[error("invalid certificate")]
    InvalidCertificate,
    #[error("certificate device mismatch")]
    CertificateDeviceMismatch,
    #[error("offline lease expired")]
    OfflineLeaseExpired,
    #[error("client version not allowed")]
    ClientVersionNotAllowed,
}

pub fn issue_payload(
    id: Uuid,
    device_key_hash: String,
    plan: &Plan,
    duration_days: i32,
    max_version: String,
    features: serde_json::Value,
    now: DateTime<Utc>,
) -> LicensePayload {
    let expires_at = match plan {
        Plan::Perpetual => None,
        _ => Some(now + Duration::days(i64::from(duration_days))),
    };
    let offline_days = match plan {
        Plan::Trial | Plan::Subscription => 30,
        Plan::Perpetual => 180,
    };
    LicensePayload {
        license_id: id,
        device_public_key_hash: device_key_hash,
        issued_at: now,
        expires_at,
        offline_until: now + Duration::days(offline_days),
        max_version,
        features,
        key_id: "default".into(),
    }
}

pub fn validate_license(
    status: LicenseStatus,
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<(), LicenseError> {
    match status {
        LicenseStatus::Revoked => Err(LicenseError::Revoked),
        LicenseStatus::Expired => Err(LicenseError::Expired),
        LicenseStatus::Active if expires_at.is_some_and(|x| x <= now) => Err(LicenseError::Expired),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subscription_expires_and_trial_has_offline_lease() {
        let now = Utc::now();
        let p = issue_payload(
            Uuid::new_v4(),
            "hash".into(),
            &Plan::Subscription,
            30,
            "1.0.0".into(),
            serde_json::json!({"basic":true}),
            now,
        );
        assert!(p.expires_at.is_some());
        assert_eq!((p.offline_until - now).num_days(), 30);
    }
    #[test]
    fn perpetual_has_no_expiry() {
        let p = issue_payload(
            Uuid::new_v4(),
            "hash".into(),
            &Plan::Perpetual,
            0,
            "1.0.0".into(),
            serde_json::json!({}),
            Utc::now(),
        );
        assert!(p.expires_at.is_none());
    }
}
