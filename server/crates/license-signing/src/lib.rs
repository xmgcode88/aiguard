use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use license_domain::{LicenseCertificate, LicensePayload};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("invalid signing key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("certificate encoding failed")]
    Encoding(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct LicenseSigner {
    key_id: String,
    signing_key: SigningKey,
}
impl LicenseSigner {
    pub fn from_seed(key_id: impl Into<String>, seed: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            signing_key: SigningKey::from_bytes(&seed),
        }
    }
    pub fn from_base64(key_id: impl Into<String>, value: &str) -> Result<Self, SigningError> {
        let bytes = STANDARD
            .decode(value)
            .map_err(|_| SigningError::InvalidKey)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| SigningError::InvalidKey)?;
        Ok(Self::from_seed(key_id, seed))
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.signing_key.verifying_key().to_bytes())
    }
    pub fn sign_bytes(&self, bytes: &[u8]) -> String {
        STANDARD.encode(self.signing_key.sign(bytes).to_bytes())
    }
    pub fn sign(&self, mut payload: LicensePayload) -> Result<LicenseCertificate, SigningError> {
        payload.key_id = self.key_id.clone();
        let bytes = serde_json::to_vec(&payload)?;
        let sig = self.signing_key.sign(&bytes);
        Ok(LicenseCertificate {
            payload,
            signature: STANDARD.encode(sig.to_bytes()),
        })
    }
    pub fn verify(
        certificate: &LicenseCertificate,
        public_key_base64: &str,
    ) -> Result<(), SigningError> {
        let key_bytes: [u8; 32] = STANDARD
            .decode(public_key_base64)
            .map_err(|_| SigningError::InvalidKey)?
            .try_into()
            .map_err(|_| SigningError::InvalidKey)?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| SigningError::InvalidKey)?;
        let sig_bytes: [u8; 64] = STANDARD
            .decode(&certificate.signature)
            .map_err(|_| SigningError::InvalidSignature)?
            .try_into()
            .map_err(|_| SigningError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        let bytes = serde_json::to_vec(&certificate.payload)?;
        key.verify(&bytes, &sig)
            .map_err(|_| SigningError::InvalidSignature)
    }
}
pub fn hash_device_key(public_key: &str) -> String {
    let mut h = Sha256::new();
    h.update(public_key.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use license_domain::{issue_payload, Plan};
    use uuid::Uuid;
    #[test]
    fn sign_and_verify() {
        let signer = LicenseSigner::from_seed("k1", [7; 32]);
        let p = issue_payload(
            Uuid::new_v4(),
            hash_device_key("device"),
            &Plan::Trial,
            7,
            "1.0.0".into(),
            serde_json::json!({}),
            Utc::now(),
        );
        let c = signer.sign(p).unwrap();
        LicenseSigner::verify(&c, &signer.public_key_base64()).unwrap();
    }
}
