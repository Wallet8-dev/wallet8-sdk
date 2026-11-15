//! # wallet8-holder-contracts - the holder service contracts
//!
//! The wallet8-holder service's wire contracts (the facade re-exports
//! them as `wallet8::holder::contracts`): the credential-vault rows,
//! the device-key registrations, and the presentation history the
//! reference wallet (and any vertical's wallet) consumes through the
//! BFF proxy.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One stored credential (the vault row view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// The row id.
    pub id: Uuid,
    /// The credential format (`mso_mdoc` / `dc+sd-jwt`).
    pub format: String,
    /// The mdoc doctype (`mso_mdoc` rows).
    #[serde(default)]
    pub doctype: Option<String>,
    /// The sd-jwt vct (`dc+sd-jwt` rows).
    #[serde(default)]
    pub vct: Option<String>,
    /// The display name (the configuration's display or the doctype).
    pub display_name: String,
    /// The issuer host the credential came from.
    pub issuer: String,
    /// The issuance timestamp.
    pub issued_at: chrono::DateTime<chrono::Utc>,
    /// The expiry timestamp when the format carries one.
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The credential-store payload (the vault's at-rest member): the
/// credential string is SECRET-REFERENCE-ONLY at the API surface - the
/// raw credential material never leaves the service (the wallet
/// fetches it per-presentation through the BFF's scoped read).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPayload {
    /// The credential string reference (`vault://credential/{id}` -
    /// resolved in-service).
    pub reference: String,
}

/// One registered device key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKey {
    /// The row id.
    pub id: Uuid,
    /// The RFC 7638 thumbprint (the key's stable identifier).
    pub thumbprint: String,
    /// The JWK (public).
    pub jwk: serde_json::Value,
    /// The registration timestamp.
    pub registered_at: chrono::DateTime<chrono::Utc>,
}

/// One presentation-history row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationRecord {
    /// The row id.
    pub id: Uuid,
    /// The verifier's client_id.
    pub verifier_client_id: String,
    /// The verifier's host (display).
    pub verifier_host: String,
    /// The disclosed claims (the element identifiers).
    pub disclosed_claims: Vec<String>,
    /// The presented credential formats.
    pub formats: Vec<String>,
    /// The presentation timestamp.
    pub presented_at: chrono::DateTime<chrono::Utc>,
}
