use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicensePayload {
    pub license_id: String,
    pub device_public_key_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub offline_until: DateTime<Utc>,
    pub max_version: String,
    pub features: Vec<String>,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseCertificate {
    pub payload: LicensePayload,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseStatus {
    Active,
    GracePeriod,
    Expired,
    Revoked,
    DeviceMismatch,
    InvalidSignature,
    ClockRollbackDetected,
}

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("invalid base64 in license signature")]
    InvalidSignatureEncoding(#[from] base64::DecodeError),
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("invalid Ed25519 signature")]
    InvalidSignature,
    #[error("license payload serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid license timestamp: {0}")]
    Timestamp(#[from] chrono::ParseError),
    #[error("secure storage is unavailable: {0}")]
    SecureStorage(String),
    #[error("device identity file is invalid")]
    InvalidDeviceIdentity,
    #[error("device identity I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredDeviceIdentity {
    public_key: String,
    protected_private_key: String,
}

#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    signing_key: SigningKey,
}

impl DeviceIdentity {
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, LicenseError> {
        let path = path.as_ref();
        if path.exists() {
            let raw = fs::read_to_string(path)?;
            let stored: StoredDeviceIdentity = serde_json::from_str(&raw)?;
            let public_key = BASE64
                .decode(stored.public_key)
                .map_err(|_| LicenseError::InvalidDeviceIdentity)?;
            let protected = BASE64
                .decode(stored.protected_private_key)
                .map_err(|_| LicenseError::InvalidDeviceIdentity)?;
            let private = unprotect(&protected)?;
            let private: [u8; 32] = private
                .try_into()
                .map_err(|_| LicenseError::InvalidDeviceIdentity)?;
            let signing_key = SigningKey::from_bytes(&private);
            if signing_key.verifying_key().to_bytes().as_slice() != public_key.as_slice() {
                return Err(LicenseError::InvalidDeviceIdentity);
            }
            return Ok(Self { signing_key });
        }

        let signing_key = SigningKey::generate(&mut OsRng);
        let protected = protect(&signing_key.to_bytes())?;
        let stored = StoredDeviceIdentity {
            public_key: BASE64.encode(signing_key.verifying_key().to_bytes()),
            protected_private_key: BASE64.encode(protected),
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(&stored)?)?;
        Ok(Self { signing_key })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.public_key())
    }

    pub fn public_key_hash(&self) -> String {
        let digest = Sha256::digest(self.public_key());
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivateRequest {
    pub activation_code: String,
    pub device_public_key: String,
    pub device_fingerprint: String,
    pub platform: String,
    pub client_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefreshRequest {
    pub license_id: String,
    pub device_public_key: String,
    pub device_fingerprint: String,
    pub client_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeactivateRequest {
    pub license_id: String,
    pub device_public_key: String,
    pub device_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LicenseApiResponse {
    pub license_certificate: String,
    pub license_id: String,
    pub offline_until: DateTime<Utc>,
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpdateManifest {
    pub version: String,
    pub channel: String,
    pub platform: String,
    pub minimum_license_version: String,
    pub download_url: String,
    pub sha256: String,
    pub signature: String,
    pub released_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SigningKeyResponse {
    pub key_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LicenseApiErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum LicenseApiError {
    #[error("invalid license API base URL")]
    InvalidBaseUrl,
    #[error("license API request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("license API returned HTTP {status}: {message}")]
    Http { status: u16, message: String },
}

#[derive(Clone)]
pub struct LicenseApiClient {
    base_url: String,
    client: reqwest::Client,
}

impl LicenseApiClient {
    pub fn new(base_url: &str) -> Result<Self, LicenseApiError> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let parsed = reqwest::Url::parse(&base_url).map_err(|_| LicenseApiError::InvalidBaseUrl)?;
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(LicenseApiError::InvalidBaseUrl);
        }
        Ok(Self {
            base_url,
            client: reqwest::Client::new(),
        })
    }

    pub async fn activate(
        &self,
        request: &ActivateRequest,
    ) -> Result<LicenseApiResponse, LicenseApiError> {
        self.post("/api/v1/licenses/activate", request).await
    }

    pub async fn refresh(
        &self,
        request: &RefreshRequest,
    ) -> Result<LicenseApiResponse, LicenseApiError> {
        self.post("/api/v1/licenses/refresh", request).await
    }

    pub async fn deactivate(&self, request: &DeactivateRequest) -> Result<(), LicenseApiError> {
        let response = self
            .client
            .post(format!(
                "{}{}",
                self.base_url, "/api/v1/licenses/deactivate"
            ))
            .json(request)
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(parse_api_error(response).await)
        }
    }

    pub async fn latest_update(
        &self,
        platform: &str,
        channel: &str,
    ) -> Result<UpdateManifest, LicenseApiError> {
        self.client
            .get(format!(
                "{}/api/v1/updates/latest?platform={}&channel={}",
                self.base_url, platform, channel
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(LicenseApiError::Request)
    }

    pub async fn signing_key(&self) -> Result<SigningKeyResponse, LicenseApiError> {
        self.client
            .get(format!("{}/api/v1/updates/signing-key", self.base_url))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(LicenseApiError::Request)
    }

    async fn post<T: Serialize>(
        &self,
        path: &str,
        request: &T,
    ) -> Result<LicenseApiResponse, LicenseApiError> {
        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(request)
            .send()
            .await?;
        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(parse_api_error(response).await)
        }
    }
}

pub fn verify_update_manifest(
    manifest: &UpdateManifest,
    key_id: &str,
    public_key_base64: &str,
) -> Result<(), LicenseError> {
    if manifest.sha256.len() != 64 || !manifest.sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(LicenseError::InvalidSignature);
    }
    let unsigned = serde_json::json!({
        "version": manifest.version,
        "channel": manifest.channel,
        "platform": manifest.platform,
        "minimum_license_version": manifest.minimum_license_version,
        "download_url": manifest.download_url,
        "sha256": manifest.sha256,
        "released_at": manifest.released_at,
        "key_id": key_id
    });
    let payload = serde_json::to_vec(&unsigned)?;
    let key_bytes: [u8; 32] = BASE64
        .decode(public_key_base64)?
        .try_into()
        .map_err(|_| LicenseError::InvalidPublicKey)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| LicenseError::InvalidPublicKey)?;
    let signature_bytes = BASE64.decode(&manifest.signature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| LicenseError::InvalidSignature)?;
    key.verify(&payload, &signature)
        .map_err(|_| LicenseError::InvalidSignature)
}

async fn parse_api_error(response: reqwest::Response) -> LicenseApiError {
    let status = response.status().as_u16();
    match response.json::<LicenseApiErrorBody>().await {
        Ok(body) => LicenseApiError::Http {
            status,
            message: format!("{}: {}", body.code, body.message),
        },
        Err(_) => LicenseApiError::Http {
            status,
            message: "unknown license API error".into(),
        },
    }
}

#[cfg(windows)]
fn protect(value: &[u8]) -> Result<Vec<u8>, LicenseError> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: value.len() as u32,
        pbData: value.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            null(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(LicenseError::SecureStorage("DPAPI protect failed".into()));
    }
    let encrypted =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(output.pbData.cast());
    }
    Ok(encrypted)
}

#[cfg(windows)]
fn unprotect(value: &[u8]) -> Result<Vec<u8>, LicenseError> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    let input = CRYPT_INTEGER_BLOB {
        cbData: value.len() as u32,
        pbData: value.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(LicenseError::SecureStorage("DPAPI unprotect failed".into()));
    }
    let decrypted =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(output.pbData.cast());
    }
    Ok(decrypted)
}

#[cfg(not(windows))]
fn protect(_: &[u8]) -> Result<Vec<u8>, LicenseError> {
    Err(LicenseError::SecureStorage(
        "DPAPI is only available on Windows; use Keychain on macOS".into(),
    ))
}

#[cfg(not(windows))]
fn unprotect(_: &[u8]) -> Result<Vec<u8>, LicenseError> {
    Err(LicenseError::SecureStorage(
        "secure storage adapter is not implemented for this platform".into(),
    ))
}

pub fn save_protected_text(path: impl AsRef<Path>, value: &str) -> Result<(), LicenseError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, protect(value.as_bytes())?)?;
    Ok(())
}

pub fn load_protected_text(path: impl AsRef<Path>) -> Result<String, LicenseError> {
    let bytes = fs::read(path)?;
    String::from_utf8(unprotect(&bytes)?)
        .map_err(|_| LicenseError::SecureStorage("stored certificate is not UTF-8".into()))
}

pub fn evaluate_stored_certificate(
    path: impl AsRef<Path>,
    public_key: &[u8; 32],
    now: DateTime<Utc>,
    last_seen: Option<DateTime<Utc>>,
    revoked: bool,
) -> Result<LicenseStatus, LicenseError> {
    let encoded = load_protected_text(path)?;
    let bytes = BASE64.decode(encoded)?;
    let certificate: LicenseCertificate = serde_json::from_slice(&bytes)?;
    certificate.verify(public_key)?;
    Ok(certificate.evaluate(now, last_seen, revoked))
}
impl LicenseCertificate {
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), LicenseError> {
        let key =
            VerifyingKey::from_bytes(public_key).map_err(|_| LicenseError::InvalidPublicKey)?;
        let signature_bytes = BASE64.decode(&self.signature)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| LicenseError::InvalidSignature)?;
        let payload = serde_json::to_vec(&self.payload)?;
        key.verify(&payload, &signature)
            .map_err(|_| LicenseError::InvalidSignature)
    }

    pub fn evaluate(
        &self,
        now: DateTime<Utc>,
        last_seen: Option<DateTime<Utc>>,
        revoked: bool,
    ) -> LicenseStatus {
        if revoked {
            return LicenseStatus::Revoked;
        }
        if last_seen.is_some_and(|seen| now < seen) {
            return LicenseStatus::ClockRollbackDetected;
        }
        if self
            .payload
            .expires_at
            .is_some_and(|expires| now >= expires)
        {
            return LicenseStatus::Expired;
        }
        if now >= self.payload.offline_until {
            return LicenseStatus::GracePeriod;
        }
        LicenseStatus::Active
    }
}

pub fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, LicenseError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, TimeZone};
    use ed25519_dalek::{Signer, SigningKey};

    fn payload() -> LicensePayload {
        LicensePayload {
            license_id: "lic_test".into(),
            device_public_key_hash: "device_hash".into(),
            issued_at: Utc.with_ymd_and_hms(2026, 8, 18, 0, 0, 0).unwrap(),
            expires_at: Some(Utc.with_ymd_and_hms(2027, 8, 18, 0, 0, 0).unwrap()),
            offline_until: Utc.with_ymd_and_hms(2026, 9, 17, 0, 0, 0).unwrap(),
            max_version: "1.x".into(),
            features: vec!["monitoring".into()],
            key_id: "test-key".into(),
        }
    }

    #[test]
    fn verifies_signed_certificate() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let payload = payload();
        let bytes = serde_json::to_vec(&payload).unwrap();
        let certificate = LicenseCertificate {
            payload,
            signature: BASE64.encode(signing_key.sign(&bytes).to_bytes()),
        };
        certificate
            .verify(&signing_key.verifying_key().to_bytes())
            .unwrap();
    }

    #[test]
    fn verifies_update_manifest_signature() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let released_at = Utc.with_ymd_and_hms(2026, 8, 19, 0, 0, 0).unwrap();
        let unsigned = serde_json::json!({
            "version": "0.2.0",
            "channel": "stable",
            "platform": "windows-x86_64",
            "minimum_license_version": "0.1.0",
            "download_url": "https://example.com/aiguard.exe",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "released_at": released_at,
            "key_id": "k1"
        });
        let signature = BASE64.encode(
            signing_key
                .sign(&serde_json::to_vec(&unsigned).unwrap())
                .to_bytes(),
        );
        let manifest = UpdateManifest {
            version: "0.2.0".into(),
            channel: "stable".into(),
            platform: "windows-x86_64".into(),
            minimum_license_version: "0.1.0".into(),
            download_url: "https://example.com/aiguard.exe".into(),
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            signature,
            released_at,
        };
        verify_update_manifest(
            &manifest,
            "k1",
            &BASE64.encode(signing_key.verifying_key().to_bytes()),
        )
        .unwrap();
    }

    #[test]
    fn rejects_clock_rollback_and_expiry() {
        let certificate = LicenseCertificate {
            payload: payload(),
            signature: String::new(),
        };
        let current = Utc.with_ymd_and_hms(2026, 8, 20, 0, 0, 0).unwrap();
        assert_eq!(
            certificate.evaluate(current, Some(current + chrono::Duration::hours(1)), false),
            LicenseStatus::ClockRollbackDetected
        );
        let expired = Utc.with_ymd_and_hms(2027, 8, 19, 0, 0, 0).unwrap();
        assert_eq!(
            certificate.evaluate(expired, None, false),
            LicenseStatus::Expired
        );
    }

    #[test]
    fn parses_rfc3339_timestamp() {
        assert_eq!(
            parse_timestamp("2026-08-18T00:00:00Z").unwrap().year(),
            2026
        );
    }

    #[test]
    fn validates_api_base_url() {
        assert!(LicenseApiClient::new("https://license.example.com/").is_ok());
        assert!(matches!(
            LicenseApiClient::new("file:///tmp"),
            Err(LicenseApiError::InvalidBaseUrl)
        ));
    }

    #[test]
    fn serializes_activation_contract() {
        let request = ActivateRequest {
            activation_code: "TEST-CODE".into(),
            device_public_key: "public".into(),
            device_fingerprint: "fingerprint".into(),
            platform: "windows-x64".into(),
            client_version: "0.1.0".into(),
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["activation_code"], "TEST-CODE");
        assert_eq!(value["device_public_key"], "public");
    }
}
