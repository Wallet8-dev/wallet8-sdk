//! # wallet8-oid4vci-client - the OID4VCI wallet client
//!
//! The wallet-role credential issuance client (OID4VCI 1.0 Final): the
//! reusable driver any vertical's wallet embeds. The flow surfaces:
//!
//! 1. **Metadata resolution** - `GET /.well-known/openid-credential-issuer`
//!    against the issuer host (`resolve_issuer_metadata`); the
//!    credential-configuration catalog drives every later step.
//! 2. **Offer intake** - the issuer-initiated credential offer (by
//!    value: inline JSON; by reference: a `credential_offer_uri`
//!    fetch) - `parse_credential_offer`.
//! 3. **The authorization-code flow** - the wallet drives the OAuth
//!    authorize round with the credential configuration's `scope`
//!    (the PKCE pair minted here), exchanging the code at the token
//!    endpoint (`authorize_for_credential`).
//! 4. **Proof minting** - the `openid4vci-proof+jwt` JWS: `typ`
//!    openid4vci-proof+jwt, ES256 over the wallet's P-256 device key,
//!    the JWK in the header, `iss` = client_id, `aud` = the issuer,
//!    `iat` + the `c_nonce` (the `/oauth/nonce` pre-flight, Final
//!    §8.1) - `mint_jwt_proof`.
//! 5. **Issuance** - `POST /oauth/credential` with the credential
//!    request (the configuration id + the proofs); the `credentials`
//!    array response parses to the wallet's credential store entries
//!    (the `mso_mdoc` entries decode to the mdoc IssuerSigned; the
//!    `dc+sd-jwt` entries stay compact) - `request_credential`.
//! 6. **Batch + deferred** - N proofs mint N credentials (§7.3); a
//!    `transaction_id` answer polls `/oauth/deferred_credential`
//!    (§8.2) - `poll_deferred`.
//!
//! The client is transport-thin: every call takes the issuer base URL
//! and returns the parsed wire value - the host app owns the UI and
//! the credential-store persistence (the wallet8-holder contracts).
//!
//! # Examples
//!
//! Mint a proof for a c_nonce:
//!
//! ```
//! use wallet8_oid4vci_client::mint_jwt_proof;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
//!     &mut p256::elliptic_curve::rand_core::OsRng));
//! let jwt = mint_jwt_proof(&key, "wallet-client-id", "https://issuer", Some("c-nonce"))?;
//! assert!(jwt.split('.').count() == 3);
//! # Ok(())
//! # }
//! ```

use base64::Engine;
use p256::ecdsa::signature::Signer;
use serde::{Deserialize, Serialize};

/// The b64url encoder used across every wire member.
fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The credential-issuer metadata (the `credential_configurations_supported`
/// subset the wallet drives).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerMetadata {
    /// The `credential_issuer` member.
    pub credential_issuer: String,
    /// The `credential_endpoint`.
    pub credential_endpoint: String,
    /// The `nonce_endpoint` (Final §8.1) when present.
    #[serde(default)]
    pub nonce_endpoint: Option<String>,
    /// The authorization server's endpoints (discovery-derived when
    /// absent per Final §4.2).
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// The credential catalog: id -> configuration.
    pub credential_configurations_supported:
        std::collections::BTreeMap<String, serde_json::Value>,
}

/// One credential configuration's wire view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    /// The `format` (`mso_mdoc` / `dc+sd-jwt`).
    pub format: String,
    /// The configuration's `scope` (the authorize round's scope).
    #[serde(default)]
    pub scope: Option<String>,
    /// The mdoc `doctype` (the `mso_mdoc` configs).
    #[serde(default)]
    pub doctype: Option<String>,
}

/// The credential-offer wire form (by value or by reference).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    /// The offered configuration ids.
    #[serde(default)]
    pub credential_configuration_ids: Vec<String>,
    /// The issuer (inherited from the landing when absent).
    #[serde(default)]
    pub credential_issuer: Option<String>,
    /// The pre-authorized grant (the PIN flow) when present.
    #[serde(default)]
    pub grants: serde_json::Value,
}

/// A minted credential entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintedCredential {
    /// The `format` member (`mso_mdoc` / `dc+sd-jwt`).
    pub format: String,
    /// The credential string (the mdoc IssuerSigned base64url or the
    /// compact sd-jwt).
    pub credential: String,
}

/// Resolve the issuer metadata (GET the well-known).
///
/// # Errors
/// Transport + parse failures with a descriptive message.
pub async fn resolve_issuer_metadata(
    http: &reqwest::Client,
    issuer_base: &str,
) -> Result<IssuerMetadata, String> {
    let url = format!(
        "{}/.well-known/openid-credential-issuer",
        issuer_base.trim_end_matches('/')
    );
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("issuer metadata fetch: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("issuer metadata read: {e}"))?;
    if !status.is_success() {
        return Err(format!("issuer metadata: HTTP {status}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("issuer metadata parse: {e}"))
}

/// Parse a credential offer (the by-value JSON or the by-reference
/// URI's fetched body - the caller fetches the URI).
///
/// # Errors
/// A malformed offer.
pub fn parse_credential_offer(body: &str) -> Result<CredentialOffer, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("offer parse: {e}"))?;
    // The by-value form nests under `credential_offer` when carried in
    // the offer landing's query parameter.
    let offer = if let Some(inner) = v.get("credential_offer") {
        inner.clone()
    } else {
        v
    };
    serde_json::from_value(offer).map_err(|e| format!("offer shape: {e}"))
}

/// The JWK (JSON) form of the wallet's P-256 device key.
pub fn device_key_jwk(key: &p256::ecdsa::VerifyingKey) -> serde_json::Value {
    let point = key.to_encoded_point(false);
    let bytes = point.as_bytes();
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(&bytes[1..33]),
        "y": b64u(&bytes[33..65]),
    })
}

/// Mint the `openid4vci-proof+jwt` JWS (Final §7.2/§8): ES256 over the
/// wallet's device key, the PUBLIC JWK in the header (the issuer's
/// device-key-match check reads it), `iss` = client_id, `aud` = the
/// issuer, `iat`, and the c_nonce when the nonce pre-flight issued one.
///
/// # Errors
/// Signing failures (a descriptive string).
pub fn mint_jwt_proof(
    key: &p256::ecdsa::SigningKey,
    client_id: &str,
    issuer: &str,
    c_nonce: Option<&str>,
) -> Result<String, String> {
    let jwk = device_key_jwk(&key.verifying_key());
    let header = serde_json::json!({
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
        "jwk": jwk,
    });
    let now = chrono::Utc::now().timestamp();
    let mut claims = serde_json::json!({
        "iss": client_id,
        "aud": issuer,
        "iat": now,
    });
    if let Some(n) = c_nonce {
        claims["nonce"] = serde_json::json!(n);
    }
    let header_b64 = b64u(serde_json::to_vec(&header).map_err(|e| e.to_string())?.as_slice());
    let payload_b64 = b64u(serde_json::to_vec(&claims).map_err(|e| e.to_string())?.as_slice());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64u(&sig.to_bytes())))
}

/// The authorization-round target for a configuration (the authorize
/// URL + PKCE pair): the wallet opens this in the system browser.
///
/// # Errors
/// None in practice (the Result keeps the signature stable).
pub fn authorize_url(
    issuer_base: &str,
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
) -> (String, String, String) {
    // The PKCE pair: a fresh verifier + its S256 challenge.
    let verifier = uuid::Uuid::new_v4().simple().to_string()
        + &uuid::Uuid::new_v4().simple().to_string();
    use sha2::Digest;
    let challenge = b64u(&sha2::Sha256::digest(verifier.as_bytes()));
    let state = uuid::Uuid::new_v4().simple().to_string();
    let _ = issuer_base;
    let url = format!(
        "{authorization_endpoint}?response_type=code&client_id={client_id}\
&redirect_uri={}&scope={}&state={state}&code_challenge={challenge}\
&code_challenge_method=S256",
        urlencode(redirect_uri),
        urlencode(scope),
    );
    (url, state, verifier)
}

/// URL-encode a query member.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The credential request (Final §7.2): the configuration id + the
/// proofs array.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialRequestBody {
    /// The `credential_configuration_id`.
    pub credential_configuration_id: String,
    /// The `proofs`: `{jwt: [<proof>...]}` (one per signing key; N
    /// proofs mint N credentials - the batch form, Final §7.3).
    pub proofs: serde_json::Value,
}

/// POST the credential request; parse the `credentials` array.
///
/// # Errors
/// Transport + the issuer's error envelope (a descriptive string).
pub async fn request_credential(
    http: &reqwest::Client,
    credential_endpoint: &str,
    access_token: &str,
    body: &CredentialRequestBody,
) -> Result<Vec<MintedCredential>, String> {
    let resp = http
        .post(credential_endpoint)
        .bearer_auth(access_token)
        .json(body)
        .send()
        .await
        .map_err(|e| format!("credential request: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("credential response read: {e}"))?;
    if !status.is_success() {
        return Err(format!("credential request: HTTP {status}: {text}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("credential response parse: {e}"))?;
    // The immediate form: the credentials array; the deferred form: a
    // transaction_id (the caller polls).
    let creds = v
        .get("credentials")
        .and_then(|c| c.as_array())
        .ok_or_else(|| {
            format!("the response carries no credentials array: {text}")
        })?;
    let mut out = Vec::new();
    for entry in creds {
        let format = entry
            .get("format")
            .and_then(|f| f.as_str())
            .unwrap_or_default()
            .to_string();
        let credential = entry
            .get("credential")
            .and_then(|c| c.as_str())
            .ok_or("a credentials entry carries no credential string")?
            .to_string();
        out.push(MintedCredential { format, credential });
    }
    Ok(out)
}

/// The deferred-issuance answer: the credentials or a pending marker.
#[derive(Debug, Clone)]
pub enum DeferredAnswer {
    /// The issuance completed.
    Issued(Vec<MintedCredential>),
    /// Still pending - poll again after `interval` seconds.
    Pending { transaction_id: String },
}

/// Poll a deferred transaction (Final §8.2).
///
/// # Errors
/// Transport + parse failures.
pub async fn poll_deferred(
    http: &reqwest::Client,
    deferred_endpoint: &str,
    access_token: &str,
    transaction_id: &str,
) -> Result<DeferredAnswer, String> {
    let resp = http
        .post(deferred_endpoint)
        .bearer_auth(access_token)
        .json(&serde_json::json!({ "transaction_id": transaction_id }))
        .send()
        .await
        .map_err(|e| format!("deferred poll: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("deferred response read: {e}"))?;
    if status.as_u16() == 400 {
        // The pending form answers the error envelope
        // {error: issuance_pending}.
        if text.contains("issuance_pending") {
            return Ok(DeferredAnswer::Pending {
                transaction_id: transaction_id.to_string(),
            });
        }
        return Err(format!("deferred poll: HTTP 400: {text}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("deferred parse: {e}"))?;
    if let Some(creds) = v.get("credentials") {
        let mut out = Vec::new();
        for entry in creds.as_array().unwrap_or(&vec![]) {
            out.push(MintedCredential {
                format: entry
                    .get("format")
                    .and_then(|f| f.as_str())
                    .unwrap_or_default()
                    .to_string(),
                credential: entry
                    .get("credential")
                    .and_then(|c| c.as_str())
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        return Ok(DeferredAnswer::Issued(out));
    }
    Err(format!("deferred answer carries no credentials: {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_shape() {
        let key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        let jwt = mint_jwt_proof(&key, "cid", "https://issuer", Some("n0")).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[0])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["typ"], "openid4vci-proof+jwt");
        assert!(header["jwk"]["x"].is_string());
    }

    #[test]
    fn offer_parses_both_forms() {
        let by_value = parse_credential_offer(
            r#"{"credential_configuration_ids":["eu.europa.ec.eudi.pid.mdoc.1"],"credential_issuer":"https://i"}"#,
        )
        .unwrap();
        assert_eq!(by_value.credential_configuration_ids.len(), 1);
        let nested = parse_credential_offer(
            r#"{"credential_offer":{"credential_configuration_ids":["a","b"]}}"#,
        )
        .unwrap();
        assert_eq!(nested.credential_configuration_ids.len(), 2);
    }

    #[test]
    fn authorize_url_carries_pkce() {
        let (url, _state, verifier) = authorize_url(
            "https://i",
            "https://i/oauth/authorize",
            "cid",
            "https://w/cb",
            "eudi.pid.mdoc.1",
        );
        assert!(url.contains("code_challenge_method=S256"));
        assert!(!verifier.is_empty());
    }
}
