// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Wallet8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # wallet8-oid4vci-client - the OID4VCI 1.0 wallet client
//!
//! The wallet-role credential issuance client implementing
//! **OpenID for Verifiable Credential Issuance 1.0** (Final, 16 Sep 2025)
//! - every function cites its spec section: the OIDF conformance
//! suite verifies the behavior, but the CONTRACT is the specification.
//!
//! ## The flows (OID4VCI §3.3.3)
//!
//! - **Authorization Code Flow** (§3.4): the wallet pushes the
//!   authorization request (PAR recommended, §5.1.4) with either the
//!   `authorization_details` parameter (type `openid_credential`,
//!   §5.1.1) or the `scope` (§5.1.2), completes the browser round,
//!   exchanges the code (§6.1), then requests the credential (§8.2).
//! - **Pre-Authorized Code Flow** (§3.5): the offer carries the
//!   `pre-authorized_code` (§4.1.1); the wallet exchanges it directly
//!   at the token endpoint - no Authorization Endpoint round. The
//!   optional `tx_code` (the offer declares its input_mode/length)
//!   rides the exchange.
//! - **Deferred issuance** (§9): a `transaction_id` + `interval`
//!   answer polls the Deferred Credential Endpoint.
//! - **Notification** (§11): the wallet reports `credential_accepted`
//!   / `credential_failure` / `credential_deleted` per
//!   `notification_id`.
//!
//! ## Offer intake (OID4VCI §4.1)
//!
//! The offer arrives by value (`credential_offer` query parameter,
//! §4.1.2) or by reference (`credential_offer_uri`, §4.1.3), under the
//! `openid-credential-offer://` custom scheme or an https URL. The
//! wallet MUST NOT trust the offer's contents (§13.5) - the issuer
//! metadata re-resolves and every later step validates against it.
//!
//! # Examples
//!
//! Mint a jwt proof (Appendix F.1):
//!
//! ```
//! use wallet8_oid4vci_client::mint_jwt_proof;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
//!     &mut p256::elliptic_curve::rand_core::OsRng));
//! // iss omitted: the anonymous pre-authorized form (Appendix F.1 -
//! // iss MUST be omitted when the access token came from an
//! // anonymous pre-authorized exchange).
//! let jwt = mint_jwt_proof(&key, None, "https://issuer", Some("c-nonce"))?;
//! assert!(jwt.split('.').count() == 3);
//! # Ok(())
//! # }
//! ```

use base64::Engine;
use p256::ecdsa::signature::Signer;
use serde::{Deserialize, Serialize};

fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// URL-encode a query member (RFC 3986 unreserved kept).
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

// ── Credential Offer (OID4VCI §4.1.1) ───────────────────────────────

/// The Transaction Code requirements (the offer's `tx_code` object,
/// §4.1.1): present (even empty) = the End-User must provide one.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TxCode {
    /// `input_mode`: `numeric` (default) | `text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<String>,
    /// `length`: the expected code length (UI hint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    /// `description` (<= 300 chars): how the Holder obtains the code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// One grant of the Credential Offer (the `grants` member, §4.1.1).
#[derive(Debug, Clone)]
pub enum OfferGrant {
    /// The Authorization Code grant: `issuer_state` binds the
    /// authorize round to the offer's context.
    AuthorizationCode {
        /// The offer's `issuer_state` (rides the authorize request,
        /// §5.1.3).
        issuer_state: Option<String>,
        /// The `authorization_server` hint (§4.1.1) - selects one of
        /// the metadata's `authorization_servers`.
        authorization_server: Option<String>,
    },
    /// The Pre-Authorized Code grant (§3.5): the offer carries the
    /// code; the wallet exchanges it directly (§6.1).
    PreAuthorizedCode {
        /// The `pre-authorized_code` (REQUIRED, short-lived, single
        /// use).
        pre_authorized_code: String,
        /// The `tx_code` requirements when the issuer demands one.
        tx_code: Option<TxCode>,
        /// The `authorization_server` hint.
        authorization_server: Option<String>,
    },
}

/// The Credential Offer object (OID4VCI §4.1.1).
#[derive(Debug, Clone)]
pub struct CredentialOffer {
    /// `credential_issuer` (REQUIRED): the issuer identifier - the
    /// wallet resolves its metadata (§12.2.2).
    pub credential_issuer: String,
    /// `credential_configuration_ids` (REQUIRED, non-empty, unique):
    /// keys into the issuer's `credential_configurations_supported`.
    pub credential_configuration_ids: Vec<String>,
    /// The offered grants (§4.1.1). Empty = the wallet determines the
    /// grant types from the metadata.
    pub grants: Vec<OfferGrant>,
}

/// The offer-intake source (§4.1.2/§4.1.3): the scanned URL carries
/// the offer by value or by reference.
#[derive(Debug, Clone)]
pub enum OfferIntake {
    /// The `credential_offer` query parameter (URL-encoded JSON).
    ByValue(String),
    /// The `credential_offer_uri` query parameter - fetch to obtain
    /// the offer object (`application/json`, §4.1.3).
    ByReference(String),
}

/// Parse the scanned offer URL into the intake form (§4.1.2/§4.1.3).
/// Accepts the `openid-credential-offer://` custom scheme and plain
/// https URLs; exactly one of `credential_offer` /
/// `credential_offer_uri` rides the query.
///
/// # Errors
/// A descriptive string for a malformed intake URL.
pub fn parse_offer_url(url: &str) -> Result<OfferIntake, String> {
    // Strip the custom scheme to a query string; https URLs parse the
    // same way (the query is what matters).
    let query = match url.split_once('?') {
        Some((_, q)) => q,
        None => return Err("the offer URL carries no query parameters".into()),
    };
    let mut by_value: Option<String> = None;
    let mut by_reference: Option<String> = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').ok_or("a malformed query pair")?;
        let decoded = percent_decode(v);
        match k {
            "credential_offer" => by_value = Some(decoded),
            "credential_offer_uri" => by_reference = Some(decoded),
            _ => {}
        }
    }
    match (by_value, by_reference) {
        (Some(v), None) => Ok(OfferIntake::ByValue(v)),
        (None, Some(r)) => Ok(OfferIntake::ByReference(r)),
        (Some(_), Some(_)) => Err(
            "credential_offer and credential_offer_uri are mutually exclusive (§4.1)".into(),
        ),
        (None, None) => Err("the offer carries neither parameter (§4.1)".into()),
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the Credential Offer object JSON (§4.1.1).
///
/// # Errors
/// A descriptive string for a non-conformant offer: a missing
/// `credential_issuer`, an empty/duplicated
/// `credential_configuration_ids`, or a malformed `grants` entry.
pub fn parse_credential_offer(body: &str) -> Result<CredentialOffer, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("offer parse: {e}"))?;
    let credential_issuer = v
        .get("credential_issuer")
        .and_then(|c| c.as_str())
        .ok_or("the offer carries no credential_issuer (§4.1.1 REQUIRED)")?
        .to_string();
    let ids: Vec<String> = v
        .get("credential_configuration_ids")
        .and_then(|c| c.as_array())
        .ok_or("the offer carries no credential_configuration_ids (§4.1.1 REQUIRED)")?
        .iter()
        .filter_map(|id| id.as_str().map(str::to_string))
        .collect();
    if ids.is_empty() {
        return Err("credential_configuration_ids is empty (§4.1.1 non-empty)".into());
    }
    if ids.len() != ids.iter().collect::<std::collections::HashSet<_>>().len() {
        return Err("credential_configuration_ids carries duplicates (§4.1.1 unique)".into());
    }
    let mut grants = Vec::new();
    if let Some(grants_obj) = v.get("grants").and_then(|g| g.as_object()) {
        for (name, value) in grants_obj {
            match name.as_str() {
                "authorization_code" => grants.push(OfferGrant::AuthorizationCode {
                    issuer_state: value
                        .get("issuer_state")
                        .and_then(|s| s.as_str())
                        .map(str::to_string),
                    authorization_server: value
                        .get("authorization_server")
                        .and_then(|s| s.as_str())
                        .map(str::to_string),
                }),
                "urn:ietf:params:oauth:grant-type:pre-authorized_code" => {
                    grants.push(OfferGrant::PreAuthorizedCode {
                        pre_authorized_code: value
                            .get("pre-authorized_code")
                            .and_then(|c| c.as_str())
                            .ok_or("the pre-authorized grant carries no pre-authorized_code (§4.1.1 REQUIRED)")?
                            .to_string(),
                        tx_code: value.get("tx_code").map(|t| TxCode {
                            input_mode: t.get("input_mode").and_then(|m| m.as_str()).map(str::to_string),
                            length: t.get("length").and_then(|l| l.as_u64()).map(|l| l as u32),
                            description: t.get("description").and_then(|d| d.as_str()).map(str::to_string),
                        }),
                        authorization_server: value
                            .get("authorization_server")
                            .and_then(|s| s.as_str())
                            .map(str::to_string),
                    })
                }
                // When multiple grants are present, the wallet chooses
                // (§4.1.1); unknown grant types are ignored.
                _ => {}
            }
        }
    }
    Ok(CredentialOffer {
        credential_issuer,
        credential_configuration_ids: ids,
        grants,
    })
}

// ── Credential Issuer Metadata (OID4VCI §12.2) ─────────────────────

/// The Credential Issuer metadata (§12.2.4) - the members the wallet
/// drives; unknown members are ignored (§12.2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerMetadata {
    /// `credential_issuer` (REQUIRED, §12.2.4) - MUST equal the
    /// identifier the metadata was fetched from (§12.2.2).
    pub credential_issuer: String,
    /// `authorization_servers` (OPTIONAL): the AS identifiers; absent
    /// = the issuer acts as its own AS (§12.2.4).
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// `credential_endpoint` (REQUIRED).
    pub credential_endpoint: String,
    /// `nonce_endpoint` (OPTIONAL): present = proofs MUST carry the
    /// `c_nonce` (§8.2, App. F.1).
    #[serde(default)]
    pub nonce_endpoint: Option<String>,
    /// `deferred_credential_endpoint` (OPTIONAL, §9).
    #[serde(default)]
    pub deferred_credential_endpoint: Option<String>,
    /// `notification_endpoint` (OPTIONAL, §11).
    #[serde(default)]
    pub notification_endpoint: Option<String>,
    /// `batch_credential_issuance` (OPTIONAL): `batch_size` >= 2.
    #[serde(default)]
    pub batch_credential_issuance: Option<serde_json::Value>,
    /// `display` (OPTIONAL): the issuer's display properties.
    #[serde(default)]
    pub display: Vec<serde_json::Value>,
    /// `credential_configurations_supported` (REQUIRED): id ->
    /// configuration (§12.2.4; the format profiles ride the entries,
    /// App. A).
    pub credential_configurations_supported:
        std::collections::BTreeMap<String, serde_json::Value>,
}

/// The RFC 8414 Authorization Server metadata (§12.2.4): the AS
/// endpoints resolve from the `oauth-authorization-server`
/// well-known of the AS identifier - never guessed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsMetadata {
    /// `authorization_endpoint` (RFC 8414).
    pub authorization_endpoint: String,
    /// `token_endpoint` (RFC 8414).
    pub token_endpoint: String,
    /// `pushed_authorization_request_endpoint` (RFC 9126).
    #[serde(default)]
    pub pushed_authorization_request_endpoint: Option<String>,
    /// `challenge_endpoint` (HAIP): when advertised, the client MUST GET
    /// a fresh attestation challenge before EVERY client-attestation
    /// protected endpoint and echo it in the PoP `challenge` claim.
    #[serde(default)]
    pub challenge_endpoint: Option<String>,
    /// `pre-authorized_grant_anonymous_access_supported` (§12.3):
    /// true = the pre-authorized token request carries NO client_id.
    #[serde(default)]
    pub pre_authorized_grant_anonymous_access_supported: bool,
}

/// Resolve the Credential Issuer metadata (§12.2.2): GET
/// `{issuer}/.well-known/openid-credential-issuer`, then verify the
/// returned `credential_issuer` equals the identifier the metadata
/// was fetched from (a mismatch MUST NOT be used, §12.2.4).
///
/// # Errors
/// Transport + parse failures, or the identity mismatch.
pub async fn resolve_issuer_metadata(
    http: &reqwest::Client,
    issuer_identifier: &str,
) -> Result<IssuerMetadata, String> {
    let base = issuer_identifier.trim_end_matches('/');
    let url = format!("{base}/.well-known/openid-credential-issuer");
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
    let metadata: IssuerMetadata =
        serde_json::from_str(&body).map_err(|e| format!("issuer metadata parse: {e}"))?;
    if metadata.credential_issuer != issuer_identifier {
        return Err(format!(
            "the metadata credential_issuer {} does not match the requested identifier {} (§12.2.2)",
            metadata.credential_issuer, issuer_identifier
        ));
    }
    Ok(metadata)
}

/// Resolve the Authorization Server metadata (§12.2.4 + RFC 8414):
/// GET `{as}/.well-known/oauth-authorization-server`.
///
/// # Errors
/// Transport + parse failures.
pub async fn resolve_as_metadata(
    http: &reqwest::Client,
    as_identifier: &str,
) -> Result<AsMetadata, String> {
    let base = as_identifier.trim_end_matches('/');
    let url = format!("{base}/.well-known/oauth-authorization-server");
    fetch_as_metadata(http, &url).await
}

/// Fetch a fresh attestation challenge from the AS's advertised
/// `challenge_endpoint` (HAIP): a POST with an empty body (the suite's
/// mock + the HAIP draft require POST). The response body is either
/// `{ "attestation_challenge": "..." }` or a bare string.
///
/// # Errors
/// Transport + parse failures or a non-2xx status.
pub async fn fetch_attestation_challenge(
    http: &reqwest::Client,
    challenge_endpoint: &str,
) -> Result<String, String> {
    let resp = http
        .post(challenge_endpoint)
        .send()
        .await
        .map_err(|e| format!("challenge fetch: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("challenge read: {e}"))?;
    if !status.is_success() {
        return Err(format!("challenge endpoint: HTTP {status}"));
    }
    let value: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("challenge parse: {e}"))?;
    if let Some(c) = value.get("attestation_challenge").and_then(|v| v.as_str()) {
        return Ok(c.to_string());
    }
    if let Some(c) = value.as_str() {
        return Ok(c.to_string());
    }
    Err("challenge endpoint: no attestation_challenge in the response".into())
}

/// Fetch the issuer metadata from an EXPLICIT URL (the conformance
/// campaign override: the suite hosts the RFC8414 form whose path
/// carries the instance prefix - the `{issuer}/.well-known/...`
/// derivation would target the wrong path). Performs the §12.2.2
/// credential_issuer identity check exactly like the derived form.
///
/// # Errors
/// Transport + parse failures, or the identity mismatch.
pub async fn fetch_issuer_metadata(
    http: &reqwest::Client,
    metadata_url: &str,
    issuer_identifier: &str,
) -> Result<IssuerMetadata, String> {
    let resp = http
        .get(metadata_url)
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
    let metadata: IssuerMetadata =
        serde_json::from_str(&body).map_err(|e| format!("issuer metadata parse: {e}"))?;
    if metadata.credential_issuer != issuer_identifier {
        return Err(format!(
            "the metadata credential_issuer {} does not match the requested identifier {} (§12.2.2)",
            metadata.credential_issuer, issuer_identifier
        ));
    }
    Ok(metadata)
}

/// Fetch the AS metadata from an EXPLICIT URL (the campaign override).
///
/// # Errors
/// Transport + parse failures.
pub async fn fetch_as_metadata(
    http: &reqwest::Client,
    metadata_url: &str,
) -> Result<AsMetadata, String> {
    let resp = http
        .get(metadata_url)
        .send()
        .await
        .map_err(|e| format!("as metadata fetch: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("as metadata read: {e}"))?;
    if !status.is_success() {
        return Err(format!("as metadata: HTTP {status}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("as metadata parse: {e}"))
}

/// The AS identifier for an issuance (§12.2.4): the offer's
/// `authorization_server` hint when the metadata lists multiple, else
/// the first entry, else the issuer itself.
///
/// # Errors
/// A hint that matches no `authorization_servers` entry aborts the
/// flow (§12.2.4 MUST NOT proceed).
pub fn select_authorization_server(
    metadata: &IssuerMetadata,
    hint: Option<&str>,
) -> Result<String, String> {
    match (metadata.authorization_servers.as_slice(), hint) {
        ([], _) => Ok(metadata.credential_issuer.clone()),
        ([first], None) => Ok(first.clone()),
        ([only], Some(h)) if h == only => Ok(only.clone()),
        (many, Some(h)) => {
            if many.iter().any(|m| m == h) {
                Ok(h.to_string())
            } else {
                Err(format!(
                    "the offer's authorization_server {h} matches no authorization_servers entry (§12.2.4)"
                ))
            }
        }
        (many, None) => Ok(many
            .first()
            .cloned()
            .ok_or("the authorization_servers list is empty")?),
    }
}

// ── The Authorization Code Flow (OID4VCI §5-§6) ────────────────────

/// The PKCE pair (RFC 7636).
pub struct PkcePair {
    /// The verifier.
    pub verifier: String,
    /// The S256 challenge.
    pub challenge: String,
}

/// Mint a PKCE pair (RFC 7636 §4.2: 43-128 chars, S256).
pub fn pkce_pair() -> PkcePair {
    use sha2::Digest;
    let verifier = uuid::Uuid::new_v4().simple().to_string()
        + &uuid::Uuid::new_v4().simple().to_string();
    let challenge = b64u(&sha2::Sha256::digest(verifier.as_bytes()));
    PkcePair { verifier, challenge }
}

/// The `authorization_details` of type `openid_credential` (§5.1.1):
/// `type` + `credential_configuration_id` (+ optional `claims`
/// descriptions + `locations` when the metadata lists multiple
/// `authorization_servers`).
pub fn authorization_details(
    configuration_id: &str,
    locations: Option<&str>,
    claims: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "type": "openid_credential",
        "credential_configuration_id": configuration_id,
    });
    if let Some(loc) = locations {
        entry["locations"] = serde_json::json!([loc]);
    }
    if let Some(c) = claims {
        entry["claims"] = c.clone();
    }
    serde_json::json!([entry])
}

/// The PAR push (RFC 9126, recommended by §5.1.4): the authorization
/// request parameters ride the push; the browser round carries only
/// `client_id` + `request_uri`.
///
/// The offered grant's `issuer_state` (§5.1.3) rides the push when
/// present.
///
/// Returns `(request_uri, state, pkce)`.
///
/// # Errors
/// Transport + the PAR error envelope.
pub async fn push_authorization_request(
    http: &reqwest::Client,
    par_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    details: &serde_json::Value,
    issuer_state: Option<&str>,
    client_assertion: Option<&str>,
    scope: Option<&str>,
    client_attestation: Option<&ClientAttestation>,
) -> Result<(String, String, PkcePair), String> {
    let pkce = pkce_pair();
    let state = uuid::Uuid::new_v4().simple().to_string();
    let mut form: Vec<(&str, String)> = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("state", state.clone()),
        ("code_challenge", pkce.challenge.clone()),
        ("code_challenge_method", "S256".to_string()),
        (
            "authorization_details",
            serde_json::to_string(details).map_err(|e| e.to_string())?,
        ),
        (
            "scope",
            scope.as_deref().unwrap_or("openid").to_string(),
        ),
    ];
    if let Some(iss_state) = issuer_state {
        form.push(("issuer_state", iss_state.to_string()));
    }
    if let Some(assertion) = client_assertion {
        form.push(("client_assertion", assertion.to_string()));
        form.push(("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string()));
    }
    let mut req = http.post(par_endpoint).form(&form);
    if let Some(att) = client_attestation {
        req = req
            .header("OAuth-Client-Attestation", &att.attestation)
            .header("OAuth-Client-Attestation-PoP", &att.pop);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("par push: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("par read: {e}"))?;
    if !status.is_success() {
        return Err(format!("par push: HTTP {status}: {text}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("par parse: {e}"))?;
    let request_uri = v
        .get("request_uri")
        .and_then(|r| r.as_str())
        .ok_or("the PAR response carries no request_uri (RFC 9126 §2.2)")?
        .to_string();
    Ok((request_uri, state, pkce))
}

/// The authorize URL after a PAR push (RFC 9126 §5).
pub fn par_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    request_uri: &str,
) -> String {
    format!(
        "{authorization_endpoint}?client_id={}&request_uri={}",
        urlencode(client_id),
        urlencode(request_uri),
    )
}

/// The Token Request (authorization_code grant, §6.1): the code + the
/// PKCE verifier + the redirect_uri.
///
/// # Errors
/// Transport + the token error envelope (§6.3).
pub async fn exchange_code(
    http: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
    client_assertion: Option<&str>,
) -> Result<serde_json::Value, String> {
    let grant_form: Vec<(&str, String)> = {
        let mut f: Vec<(&str, String)> = vec![
            ("grant_type", "authorization_code".to_string()),
            ("client_id", client_id.to_string()),
            ("redirect_uri", redirect_uri.to_string()),
            ("code", code.to_string()),
            ("code_verifier", verifier.to_string()),
        ];
        if let Some(assertion) = client_assertion {
            f.push(("client_assertion", assertion.to_string()));
            f.push((
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
            ));
        }
        f
    };
    let resp = http
        .post(token_endpoint)
        .form(&grant_form)
        .send()
        .await
        .map_err(|e| format!("token exchange: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("token read: {e}"))?;
    if !status.is_success() {
        return Err(format!("token exchange: HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("token parse: {e}"))
}

/// The Pre-Authorized Code exchange (§6.1): the grant type
/// `urn:ietf:params:oauth:grant-type:pre-authorized_code` + the offer's
/// code + the `tx_code` when the offer demanded one (§4.1.1: a
/// present `tx_code` object - even empty - makes the token request's
/// `tx_code` REQUIRED).
///
/// The `client_id` rides the request unless the AS advertises
/// `pre-authorized_grant_anonymous_access_supported` (§12.3) - the
/// anonymous form then MUST omit it (and the proof's `iss` too,
/// App. F.1).
///
/// # Errors
/// Transport + the token error envelope (§6.3: `invalid_request` for
/// a missing/unexpected tx_code, `invalid_grant` for a wrong/expired
/// code).
pub async fn exchange_pre_authorized(
    http: &reqwest::Client,
    token_endpoint: &str,
    client_id: Option<&str>,
    pre_authorized_code: &str,
    tx_code: Option<&str>,
) -> Result<serde_json::Value, String> {
    let mut form: Vec<(&str, String)> = vec![(
        "grant_type",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
    )];
    if let Some(cid) = client_id {
        form.push(("client_id", cid.to_string()));
    }
    form.push(("pre-authorized_code", pre_authorized_code.to_string()));
    if let Some(tx) = tx_code {
        form.push(("tx_code", tx.to_string()));
    }
    let resp = http
        .post(token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("pre-authorized exchange: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("pre-authorized read: {e}"))?;
    if !status.is_success() {
        return Err(format!("pre-authorized exchange: HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("token parse: {e}"))
}

/// The `credential_identifiers` of a Token Response (§6.2): the
/// `authorization_details` entries of type `openid_credential` carry
/// the identifiers the Credential Request then uses.
///
/// Returns None when the token response carries no
/// `authorization_details` (the credential request then uses the
/// `credential_configuration_id`, §8.2).
pub fn credential_identifiers(token_response: &serde_json::Value) -> Option<Vec<String>> {
    token_response
        .get("authorization_details")
        .and_then(|d| d.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("openid_credential"))
                .filter_map(|e| e.get("credential_identifiers"))
                .flat_map(|ids| ids.as_array().cloned().unwrap_or_default())
                .filter_map(|id| id.as_str().map(str::to_string))
                .collect()
        })
}

// ── The Nonce Endpoint (OID4VCI §7) ────────────────────────────────

/// Fetch a fresh `c_nonce` (§7.1: an unprotected POST). Present
/// `nonce_endpoint` in the metadata = the proof MUST carry it
/// (§8.2/App. F.1).
///
/// # Errors
/// Transport + parse failures.
pub async fn fetch_nonce(http: &reqwest::Client, nonce_endpoint: &str) -> Result<String, String> {
    let resp = http
        .post(nonce_endpoint)
        .send()
        .await
        .map_err(|e| format!("nonce fetch: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("nonce read: {e}"))?;
    if !status.is_success() {
        return Err(format!("nonce fetch: HTTP {status}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("nonce parse: {e}"))?;
    v.get("c_nonce")
        .and_then(|n| n.as_str())
        .map(str::to_string)
        .ok_or_else(|| "the nonce response carries no c_nonce (§7.2)".to_string())
}

// ── Proofs (OID4VCI §8.2 + Appendix F) ─────────────────────────────

/// The DPoP proof (RFC 9449 §4.2): the JWT binding the HTTP request
/// to the wallet's key - the sender-constraining the token and every
/// access-token-bearing call carries. Header `typ: dpop+jwt`,
/// `alg: ES256`, and the PUBLIC `jwk` (no private material); the
/// claims are the FLAT form the RFC mandates: `htm` + `htu` (the
/// full request URL, scheme + host + path, no query/fragment), `iat`
/// + `exp`, a fresh `jti` per attempt, and `ath` (the base64url
/// SHA-256 of the access token) ONLY when the request presents one -
/// a token-endpoint proof NEVER carries `ath` (RFC 9449 §4.2).
///
/// # Errors
/// Signing failures.
pub fn mint_dpop_proof(
    key: &p256::ecdsa::SigningKey,
    method: &str,
    uri: &str,
    ath: Option<&str>,
    dpop_nonce: Option<&str>,
) -> Result<String, String> {
    use p256::ecdsa::signature::Signer;
    use sha2::Digest;
    // The htu (RFC 9449 §4.2): the ASCII serialization of the
    // request's target without query/fragment.
    let htu = uri
        .split(['?', '#'])
        .next()
        .unwrap_or(uri)
        .to_string();
    let now = chrono::Utc::now().timestamp();
    let mut claims = serde_json::json!({
        "htm": method,
        "htu": htu,
        "iat": now,
        "exp": now + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(token) = ath {
        claims["ath"] = serde_json::json!(b64u(&sha2::Sha256::digest(token.as_bytes())));
    }
    if let Some(nonce) = dpop_nonce {
        claims["nonce"] = serde_json::json!(nonce);
    }
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": device_key_jwk(&key.verifying_key()),
    });
    let header_b64 = b64u(serde_json::to_vec(&header).map_err(|e| e.to_string())?.as_slice());
    let claims_b64 = b64u(serde_json::to_vec(&claims).map_err(|e| e.to_string())?.as_slice());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64u(&sig.to_bytes())))
}

/// The `DPoP-Nonce` challenge (RFC 9449): the endpoint's response
/// header carrying the nonce the RETRY must present. Both postures
/// are challenges, never terminal failures:
/// - the AS form (§5): 400 + JSON body `error: use_dpop_nonce` +
///   `DPoP-Nonce`;
/// - the resource form (§6.1): 401 + `DPoP-Nonce` (+ the
///   WWW-Authenticate: DPoP error scheme) - an UNAUTHORIZED response
///   with a DPoP-Nonce is the resource server demanding the nonce.
/// Returns None when neither posture applies (the response then
/// carries its normal error for the caller).
///
/// # Errors
/// Transport-typed reads only - the header parse never fails.
pub async fn dpop_nonce_from_response(resp: &reqwest::Response) -> Option<String> {
    let status = resp.status();
    let has_nonce_header = resp
        .headers()
        .contains_key(reqwest::header::HeaderName::from_static("dpop-nonce"));
    let is_challenge = has_nonce_header
        && (status == reqwest::StatusCode::BAD_REQUEST
            || status == reqwest::StatusCode::UNAUTHORIZED);
    if !is_challenge {
        return None;
    }
    resp.headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// The DPoP session (RFC 9449 §5): the wallet's per-issuance state
/// driving the token exchange and every access-token-bearing call -
/// one device key (the AS binds the token to its thumbprint, §5;
/// the resource proofs MUST present the same key), the endpoint-
/// scoped nonce cache (the AS and each resource server mint
/// INDEPENDENT nonces), and the challenge-retry wrappers.
///
/// The wrappers transparently handle the `use_dpop_nonce` posture:
/// the first call goes out with the cached nonce (or none), a 400
/// `use_dpop_nonce` + `DPoP-Nonce` response is a CHALLENGE (not a
/// failure) - the session caches the nonce and retries ONCE with a
/// fresh proof carrying it (RFC 9449 §8.2: the retried request MUST
/// be accepted when the presented nonce matches; a second challenge
/// is a defect).
pub struct DpopSession {
    key: p256::ecdsa::SigningKey,
    nonces: std::collections::BTreeMap<String, String>,
}

impl DpopSession {
    /// Bind the session to the wallet's device key.
    pub fn new(key: p256::ecdsa::SigningKey) -> Self {
        Self { key, nonces: Default::default() }
    }

    /// The session's proof key: the SAME key every DPoP proof this
    /// session signs with (the token + resource proofs share it - the
    /// AS's `cnf.jkt` binding means the resource validation compares
    /// the proof `jwk` against the token's bound thumbprint).
    /// The OID4VCI jwt proof (App. F) reuses it - the issuer's bound
    /// key and the DPoP key are one wallet device key.
    pub fn proof_key(&self) -> &p256::ecdsa::SigningKey {
        &self.key
    }

    /// The endpoint-scoped cached nonce (AS + resource servers keep
    /// separate challenges).
    fn nonce_for(&self, endpoint: &str) -> Option<String> {
        self.nonces.get(endpoint).cloned()
    }

    fn learn_nonce(&mut self, endpoint: &str, nonce: String) {
        self.nonces.insert(endpoint.to_string(), nonce);
    }

    /// The retry loop proper (RFC 9449 §5/§6.1): each attempt builds
    /// the form FRESH via the builder (a nonce retry re-mints mutable
    /// parts - the RFC 7523 client assertion gets a new `jti`, RFC
    /// 7523 §4.3), signs a fresh DPoP proof, and on a
    /// DPoP-Nonce-carrying 400/401 challenge retries ONCE with the
    /// learned nonce.
    async fn post_form_with_dpop_builder<F>(
        &mut self,
        http: &reqwest::Client,
        endpoint: &str,
        mut form_builder: F,
        attestation_minter: Option<&(dyn Fn() -> Result<ClientAttestation, String> + Send + Sync)>,
        ath: Option<&str>,
    ) -> Result<(reqwest::StatusCode, String, Option<String>), String>
    where
        F: FnMut() -> Result<Vec<(String, String)>, String>,
    {
        self.retry(http, endpoint, &mut form_builder, attestation_minter, ath)
            .await
    }

    /// The challenge-retry body shared by both forms of call.
    async fn retry<F>(
        &mut self,
        http: &reqwest::Client,
        endpoint: &str,
        form_builder: &mut F,
        attestation_minter: Option<&(dyn Fn() -> Result<ClientAttestation, String> + Send + Sync)>,
        ath: Option<&str>,
    ) -> Result<(reqwest::StatusCode, String, Option<String>), String>
    where
        F: FnMut() -> Result<Vec<(String, String)>, String>,
    {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let form = form_builder()?;
            let mut req = http.post(endpoint).form(&form);
            if let Some(minter) = attestation_minter {
                let att = minter()?;
                req = req
                    .header("OAuth-Client-Attestation", &att.attestation)
                    .header("OAuth-Client-Attestation-PoP", &att.pop);
            }
            let proof = mint_dpop_proof(
                &self.key,
                "POST",
                endpoint,
                ath,
                self.nonce_for(endpoint).as_deref(),
            )?;
            let resp = req
                .header("DPoP", proof)
                .send()
                .await
                .map_err(|e| format!("dpop post: {e}"))?;
            let status = resp.status();
            if let Some(nonce) = dpop_nonce_from_response(&resp).await {
                let body = resp.text().await.map_err(|e| format!("dpop read: {e}"))?;
                if attempt == 1 {
                    self.learn_nonce(endpoint, nonce);
                    continue;
                }
                return Ok((status, body, Some(nonce)));
            }
            let body = resp.text().await.map_err(|e| format!("dpop read: {e}"))?;
            return Ok((status, body, None));
        }
    }

    /// The authorization-code token exchange with the DPoP binding
    /// (RFC 9449 §5): the code + PKCE + the client assertion + the
    /// proof (NO `ath` - the token call presents no access token).
    /// The `client_assertion_audience` (Some = private_key_jwt): the
    /// session MINTS a fresh RFC 7523 assertion PER ATTEMPT - the
    /// challenge-retry round MUST NOT replay an assertion's `jti`
    /// (RFC 7523 §4.3 + the suite's CheckForClientAssertionJtiReuse).
    /// Returns the parsed token response; the access token is bound
    /// to this session's key thumbprint (`cnf.jkt`).
    ///
    /// # Errors
    /// Transport + the token error envelope (§6.3) after the retry.
    pub async fn exchange_code(
        &mut self,
        http: &reqwest::Client,
        token_endpoint: &str,
        client_id: &str,
        redirect_uri: &str,
        code: &str,
        verifier: &str,
        client_assertion_audience: Option<&str>,
        attestation_minter: Option<&(dyn Fn() -> Result<ClientAttestation, String> + Send + Sync)>,
    ) -> Result<serde_json::Value, String> {
        // The FULL form rebuilds PER ATTEMPT inside the session (a
        // nonce challenge retry re-mints the assertion with a fresh
        // jti - RFC 7523 §4.3 replay defense). The key clones OUT of
        // self so the builder owns it (the borrow checker).
        let key_for_assertion = self.key.clone();
        let client_id_owned = client_id.to_string();
        let form_builder = move || {
            let mut form: Vec<(String, String)> = vec![
                ("grant_type".into(), "authorization_code".into()),
                ("client_id".into(), client_id_owned.clone()),
                ("redirect_uri".into(), redirect_uri.into()),
                ("code".into(), code.into()),
                ("code_verifier".into(), verifier.into()),
            ];
            if let Some(audience) = client_assertion_audience {
                let assertion = mint_client_assertion(&key_for_assertion, &client_id_owned, audience)?;
                form.push(("client_assertion".into(), assertion));
                form.push((
                    "client_assertion_type".into(),
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
                ));
            }
            Ok::<Vec<(String, String)>, String>(form)
        };
        let (status, body, _) = self
            .post_form_with_dpop_builder(http, token_endpoint, form_builder, attestation_minter, None)
            .await?;
        if !status.is_success() {
            return Err(format!("token exchange: HTTP {status}: {body}"));
        }
        serde_json::from_str(&body).map_err(|e| format!("token parse: {e}"))
    }

    /// POST an access-token-bearing protected-resource call with the
    /// DPoP binding (the credential §8.2, deferred §9, and
    /// notification §11 endpoints): `Authorization: DPoP` (the
    /// sender-constrained scheme, RFC 9449 §7.1) + the proof carrying
    /// `ath` (the access-token hash) + the resource endpoint's own
    /// nonce when challenged (the AS and the resource servers keep
    /// INDEPENDENT nonces).
    ///
    /// # Errors
    /// Transport + the endpoint's error envelope after the retry.
    pub async fn post_protected_json(
        &mut self,
        http: &reqwest::Client,
        endpoint: &str,
        access_token: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let (status, body_text, _) = self
            .post_form_with_dpop_raw(
                http,
                endpoint,
                access_token,
                Some(serde_json::to_string(body).map_err(|e| e.to_string())?),
            )
            .await?;
        if !status.is_success() {
            return Err(format!("protected call: HTTP {status}: {body_text}"));
        }
        serde_json::from_str(&body_text).map_err(|e| format!("protected parse: {e}"))
    }

    /// The same protected call, returning the RAW body text - the
    /// credential endpoint's JWE response form is not JSON.
    ///
    /// # Errors
    /// Transport + a non-2xx status after the retry.
    pub async fn post_protected_text(
        &mut self,
        http: &reqwest::Client,
        endpoint: &str,
        access_token: &str,
        body: &serde_json::Value,
    ) -> Result<String, String> {
        let (status, body_text, _) = self
            .post_form_with_dpop_raw(
                http,
                endpoint,
                access_token,
                Some(serde_json::to_string(body).map_err(|e| e.to_string())?),
            )
            .await?;
        if !status.is_success() {
            return Err(format!("protected call: HTTP {status}: {body_text}"));
        }
        Ok(body_text)
    }

    /// The fire-and-forget protected call (§11 notifications): the
    /// same DPoP binding; the HTTP status decides.
    ///
    /// # Errors
    /// Transport + a non-2xx status after the retry.
    pub async fn post_protected_notify(
        &mut self,
        http: &reqwest::Client,
        endpoint: &str,
        access_token: &str,
        body: &serde_json::Value,
    ) -> Result<(), String> {
        let (status, body_text, _) = self
            .post_form_with_dpop_raw(
                http,
                endpoint,
                access_token,
                Some(serde_json::to_string(body).map_err(|e| e.to_string())?),
            )
            .await?;
        if !status.is_success() {
            return Err(format!("notification: HTTP {status}: {body_text}"));
        }
        Ok(())
    }

    async fn post_form_with_dpop_raw(
        &mut self,
        http: &reqwest::Client,
        endpoint: &str,
        access_token: &str,
        json_body: Option<String>,
    ) -> Result<(reqwest::StatusCode, String, Option<String>), String> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let proof = mint_dpop_proof(
                &self.key,
                "POST",
                endpoint,
                Some(access_token),
                self.nonce_for(endpoint).as_deref(),
            )?;
            // The DPoP access token rides the DPoP auth scheme
            // (RFC 9449 §7.1: `Authorization: DPoP <token>` - the
            // suite's ExtractDpopAccessTokenFromHeader gates on the
            // scheme; Bearer is the NON-sender-constrained form).
            let mut req = http
                .post(endpoint)
                .header("DPoP", proof)
                .header("Authorization", format!("DPoP {access_token}"));
            if let Some(b) = &json_body {
                req = req.header("Content-Type", "application/json").body(b.clone());
            }
            let resp = req.send().await.map_err(|e| format!("dpop post: {e}"))?;
            let status = resp.status();
            if let Some(nonce) = dpop_nonce_from_response(&resp).await {
                let body = resp.text().await.map_err(|e| format!("dpop read: {e}"))?;
                // RFC 9449 5/6.1: any DPoP-Nonce-carrying 400/401 is
                // the challenge - the FIRST one retries with the
                // nonce; a second challenge on the SAME nonce is a
                // defect (RFC 9449 8.2) and surfaces as the error.
                if attempt == 1 {
                    self.learn_nonce(endpoint, nonce);
                    continue;
                }
                return Ok((status, body, Some(nonce)));
            }
            let body = resp.text().await.map_err(|e| format!("dpop read: {e}"))?;
            return Ok((status, body, None));
        }
    }
}

/// The Key Attestation (OID4VCI App. D.1): the `key-attestation+jwt`
/// binding the attested key(s) to the storage/user-authentication
/// properties. The proof's header carries it (App. F.1) when the
/// configuration's `key_attestations_required` is present - the
/// attestation's `nonce` = the c_nonce (App. D.1's freshness).
///
/// # Errors
/// Signing failures.
pub fn mint_key_attestation(
    signing_key: &p256::ecdsa::SigningKey,
    attested_jwk: serde_json::Value,
    c_nonce: Option<&str>,
    key_storage: Option<&[&str]>,
    user_authentication: Option<&[&str]>,
) -> Result<String, String> {
    use base64::Engine;
    use p256::ecdsa::signature::Signer;
    let b64 = |b: &[u8]| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    };
    let now = chrono::Utc::now().timestamp();
    let mut claims = serde_json::json!({
        "iat": now,
        // App. D.1: exp MUST be present when used with the jwt proof type.
        "exp": now + 600,
        "attested_keys": [attested_jwk],
    });
    if let Some(nonce) = c_nonce {
        claims["nonce"] = serde_json::json!(nonce);
    }
    if let Some(storage) = key_storage {
        claims["key_storage"] = serde_json::json!(storage);
    }
    if let Some(auth) = user_authentication {
        claims["user_authentication"] = serde_json::json!(auth);
    }
    let header = serde_json::json!({
        "typ": "key-attestation+jwt",
        "alg": "ES256",
        "jwk": device_key_jwk(&signing_key.verifying_key()),
    });
    let header_b64 = b64(serde_json::to_vec(&header).map_err(|e| e.to_string())?.as_slice());
    let claims_b64 = b64(serde_json::to_vec(&claims).map_err(|e| e.to_string())?.as_slice());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64(&sig.to_bytes())))
}

/// The OAuth Client Attestation minting (HAIP; the campaign's
/// `client_attestation` client-auth variant): the pair of JWTs the
/// draft carries on the `OAuth-Client-Attestation` /
/// `OAuth-Client-Attestation-PoP` request headers at the token and
/// PAR endpoints.
///
/// - the ATTESTATION: `typ: oauth-client-attestation+jwt`, ES256
///   signed by the ATTESTER's key (the x5c header carries the
///   attester's certificate chain - the verification trust); claims
///   `iss` (the attester's trust-domain identifier),
///   `sub` (the client_id being authenticated), `iat`/`nbf`/`exp`,
///   and `cnf.jwk` = the CLIENT's proof key (the key the PoP shows).
/// - the PoP: `typ: oauth-client-attestation-pop+jwt`, ES256 signed
///   by the attested CLIENT key; claims `iss` (the client_id),
///   `aud` (the attestation issuer - the same trust domain),
///   `iat`, `nbf`, `exp`, fresh `jti` (the replay defense), and
///   `challenge` when the AS advertises a challenge endpoint (None =
///   absent; the suite's ProofJwtChallenge condition self-skips).
#[derive(Debug, Clone)]
pub struct ClientAttestation {
    /// The `OAuth-Client-Attestation` header value (the attestation
    /// JWT).
    pub attestation: String,
    /// The `OAuth-Client-Attestation-PoP` header value (the PoP JWT).
    pub pop: String,
}

/// Mint the client-attestation pair (HAIP client_attestation auth).
///
/// The signer separation matters: `attester_key` is the TRUST-DOMAIN
/// key (its x5c chain is what the verifier re-derives the attester
/// identity from), `client_key` is the CLIENT instance key the
/// attestation's `cnf.jwk` binds - the PoP MUST verify against it.
///
/// # Errors
/// Signing / serialization failures.
pub fn mint_client_attestation(
    attester_key: &p256::ecdsa::SigningKey,
    attester_x5c: &[String],
    attestation_issuer: &str,
    client_id: &str,
    client_key: &p256::ecdsa::SigningKey,
    audience: &str,
    challenge: Option<&str>,
    lifetime_seconds: i64,
) -> Result<ClientAttestation, String> {
    let now = chrono::Utc::now().timestamp();
    // (1) The attestation JWT (typ oauth-client-attestation+jwt).
    let att_header = serde_json::json!({
        "typ": "oauth-client-attestation+jwt",
        "alg": "ES256",
        "x5c": attester_x5c,
    });
    let att_claims = serde_json::json!({
        "iss": attestation_issuer,
        "sub": client_id,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime_seconds,
        "cnf": { "jwk": device_key_jwk(&client_key.verifying_key()) },
    });
    let attestation = assemble_es256_jwt(&att_header, &att_claims, attester_key)?;
    // (2) The PoP JWT (typ oauth-client-attestation-pop+jwt).
    let pop_header = serde_json::json!({
        "typ": "oauth-client-attestation-pop+jwt",
        "alg": "ES256",
    });
    let mut pop_claims = serde_json::json!({
        "iss": client_id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime_seconds,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(c) = challenge {
        pop_claims["challenge"] = serde_json::json!(c);
    }
    let pop = assemble_es256_jwt(&pop_header, &pop_claims, client_key)?;
    Ok(ClientAttestation { attestation, pop })
}

/// Assemble a compact ES256 JWT from header/claims values.
fn assemble_es256_jwt(
    header: &serde_json::Value,
    claims: &serde_json::Value,
    key: &p256::ecdsa::SigningKey,
) -> Result<String, String> {
    use p256::ecdsa::signature::Signer;
    let header_b64 = b64u(serde_json::to_vec(header).map_err(|e| e.to_string())?.as_slice());
    let payload_b64 = b64u(serde_json::to_vec(claims).map_err(|e| e.to_string())?.as_slice());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64u(&sig.to_bytes())))
}

/// The JWK form of the wallet's P-256 key (RFC 7517).
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

/// The RFC 7523 private_key_jwt Client Assertion (§9 - the
/// token_endpoint_auth method the mock issuer validates at PAR + token;
/// the ES256 signature over the RFC 7523 §2.2 claims). The `jti` is a
/// fresh UUID (the replay defense); `aud` = the issuer identifier; the
/// `sub`/`iss` = the client_id.
///
/// # Errors
/// Signing failures.
pub fn mint_client_assertion(
    key: &p256::ecdsa::SigningKey,
    client_id: &str,
    audience: &str,
) -> Result<String, String> {
    use base64::Engine;
    use p256::ecdsa::signature::Signer;
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": format!("{}-key", client_id),
        "jwk": device_key_jwk(&key.verifying_key()),
    });
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": chrono::Utc::now().timestamp(),
        "exp": chrono::Utc::now().timestamp() + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let header_b64 = b64(serde_json::to_vec(&header).map_err(|e| e.to_string())?.as_slice());
    let claims_b64 = b64(serde_json::to_vec(&claims).map_err(|e| e.to_string())?.as_slice());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64(&sig.to_bytes())))
}

/// Mint the `openid4vci-proof+jwt` (Appendix F.1): `typ`
/// openid4vci-proof+jwt, an asymmetric `alg` (never none), the key in
/// exactly ONE of `kid`/`jwk`/`x5c` (the jwk form here), optional
/// `key_attestation` in the header (App. D). Claims: `iss` =
/// client_id (OPTIONAL - MUST be omitted for the anonymous
/// pre-authorized form), `aud` = the Credential Issuer Identifier
/// (REQUIRED), `iat` (REQUIRED), `nonce` = the c_nonce (REQUIRED when
/// the issuer has a Nonce Endpoint, §8.2).
///
/// # Errors
/// Signing failures.
pub fn mint_jwt_proof(
    key: &p256::ecdsa::SigningKey,
    client_id: Option<&str>,
    issuer_identifier: &str,
    c_nonce: Option<&str>,
) -> Result<String, String> {
    mint_jwt_proof_attested(key, client_id, issuer_identifier, c_nonce, None, None, None)
}

/// The [`mint_jwt_proof`] form carrying a Key Attestation (App. D -
/// the `key_attestations_required` configuration demand): the
/// attestation rides the JOSE header; the attested keys MUST include
/// the proof's key (the binding the issuer checks).
///
/// # Errors
/// Signing failures (the attestation + the proof).
pub fn mint_jwt_proof_attested(
    key: &p256::ecdsa::SigningKey,
    client_id: Option<&str>,
    issuer_identifier: &str,
    c_nonce: Option<&str>,
    attestation_signing_key: Option<&p256::ecdsa::SigningKey>,
    key_storage: Option<&[&str]>,
    user_authentication: Option<&[&str]>,
) -> Result<String, String> {
    let mut header = serde_json::json!({
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
        "jwk": device_key_jwk(&key.verifying_key()),
    });
    if let (Some(attester), Some(nonce)) = (attestation_signing_key, c_nonce) {
        let attestation = mint_key_attestation(
            attester,
            device_key_jwk(&key.verifying_key()),
            Some(nonce),
            key_storage,
            user_authentication,
        )?;
        header["key_attestation"] = serde_json::json!(attestation);
    }
    let now = chrono::Utc::now().timestamp();
    let mut claims = serde_json::json!({
        "aud": issuer_identifier,
        "iat": now,
    });
    if let Some(cid) = client_id {
        claims["iss"] = serde_json::json!(cid);
    }
    if let Some(n) = c_nonce {
        claims["nonce"] = serde_json::json!(n);
    }
    let header_b64 = b64u(serde_json::to_vec(&header).map_err(|e| e.to_string())?.as_slice());
    let payload_b64 = b64u(serde_json::to_vec(&claims).map_err(|e| e.to_string())?.as_slice());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64u(&sig.to_bytes())))
}

// ── The Credential Endpoint (OID4VCI §8) ───────────────────────────

/// The Credential Request's identifier member (§8.2): exactly one of
/// `credential_identifier` (when the token response returned
/// `authorization_details.credential_identifiers`) or
/// `credential_configuration_id` (otherwise).
#[derive(Debug, Clone)]
pub enum CredentialRequestTarget {
    /// The `credential_identifier` from the token response
    /// (§6.2/§3.3.4).
    Identifier(String),
    /// The `credential_configuration_id`.
    ConfigurationId(String),
}

impl CredentialRequestTarget {
    /// The serde view of the identifier member.
    fn body_member(&self) -> serde_json::Value {
        match self {
            Self::Identifier(id) => serde_json::json!({ "credential_identifier": id }),
            Self::ConfigurationId(id) => {
                serde_json::json!({ "credential_configuration_id": id })
            }
        }
    }
}

/// The Credential Request body (§8.2): exactly one identifier member
/// + the `proofs` object keyed by proof type (+ the optional
/// `credential_response_encryption` members).
#[derive(Debug, Clone)]
pub struct CredentialRequestBody {
    /// The identifier member (§8.2).
    pub target: CredentialRequestTarget,
    /// The `proofs` object: `{jwt: [proof...]}` (App. F.1) - REQUIRED
    /// when the configuration's `proof_types_supported` is present
    /// (§8.2); N proofs mint N credentials (the batch, §3.3.2).
    pub proofs: serde_json::Value,
    /// The optional `credential_response_encryption` (§8.2:
    /// `{jwk, enc, zip?}`).
    pub credential_response_encryption: Option<serde_json::Value>,
}

impl serde::Serialize for CredentialRequestBody {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = serde_json::Map::new();
        for (k, v) in self.target.body_member().as_object().cloned().unwrap_or_default() {
            map.insert(k, v);
        }
        map.insert("proofs".into(), self.proofs.clone());
        if let Some(enc) = &self.credential_response_encryption {
            map.insert("credential_response_encryption".into(), enc.clone());
        }
        serde_json::Value::Object(map).serialize(s)
    }
}

/// The credential-response encryption material (§8.2): the wallet's
/// EPHEMERAL P-256 key - the request carries the public JWK + the
/// alg/enc; the issuer wraps the response as a JWE the wallet opens.
pub struct ResponseEncryption {
    /// The ephemeral private key (the ECDH shared secret side).
    pub sk: p256::ecdsa::SigningKey,
    /// The public JWK form (RFC 7517) the request carries.
    pub jwk: serde_json::Value,
    /// The advertised alg (ECDH-ES = direct CEK agreement).
    pub alg: &'static str,
    /// The advertised enc (A256GCM).
    pub enc: &'static str,
}

/// Mint the response-encryption material: a fresh P-256 key + its JWK.
pub fn mint_response_encryption() -> ResponseEncryption {
    let sk = p256::ecdsa::SigningKey::random(&mut p256::ecdsa::signature::rand_core::OsRng);
    let jwk = device_key_jwk(&sk.verifying_key());
    ResponseEncryption {
        sk,
        jwk,
        alg: "ECDH-ES",
        enc: "A256GCM",
    }
}

/// Open an ECDH-ES + A256GCM JWE (the 5-part compact form) with the
/// wallet's ephemeral key.
///
/// # Errors
/// Malformed JWE, an unexpected alg/enc, or an AEAD failure.
pub fn decrypt_ecdh_es_a256gcm(
    jwe: &str,
    sk: &p256::ecdsa::SigningKey,
) -> Result<serde_json::Value, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use p256::ecdsa::signature::rand_core::OsRng as _OsRngUnused;
    let _ = _OsRngUnused;
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(format!("the JWE carries {} parts (want 5)", parts.len()));
    }
    let header = b64d(parts[0])?;
    let header_v: serde_json::Value = serde_json::from_slice(&header)
        .map_err(|e| format!("jwe header parse: {e}"))?;
    let alg = header_v.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let enc = header_v.get("enc").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "ECDH-ES" || enc != "A256GCM" {
        return Err(format!("unsupported JWE alg/enc {alg}/{enc}"));
    }
    let epk = header_v
        .get("epk")
        .and_then(|v| v.get("x"))
        .and_then(|x| x.as_str())
        .ok_or("no epk.x in the JWE header")?;
    let epk_y = header_v
        .get("epk")
        .and_then(|v| v.get("y"))
        .and_then(|y| y.as_str())
        .ok_or("no epk.y in the JWE header")?;
    let sender_pk = ecdh_point(epk, epk_y)?;
    let shared = p256::ecdh::diffie_hellman(
        sk.as_nonzero_scalar(),
        sender_pk.as_affine(),
    );
    // ConcatKDF (NIST SP 800-56A §5.8.1) as a single round: the alg
    // header + the ASCII secret + the 32-byte length marker.
    let cek = concat_kdf(shared.raw_secret_bytes(), b"A256GCM", 32);
    let iv = b64d(parts[2])?;
    let ct_tag = b64d(parts[3])?;
    let tag = b64d(parts[4])?;
    let mut ciphertext = ct_tag;
    ciphertext.extend_from_slice(&tag);
    let aad = parts[0].as_bytes();
    let key_bytes: [u8; 32] = cek[..32].try_into().map_err(|_| "cek length".to_string())?;
    let cipher = aes_gcm::Aes256Gcm::new(&key_bytes.into());
    let mut nonce_buf = [0u8; 12];
    nonce_buf.copy_from_slice(&iv[..12.min(iv.len())]);
    let nonce: aes_gcm::Nonce<aes_gcm::aead::consts::U12> = nonce_buf.into();
    let plain = cipher
        .decrypt(&nonce, aes_gcm::aead::Payload { msg: &ciphertext, aad })
        .map_err(|_| "the JWE AEAD verification FAILED".to_string())?;
    serde_json::from_slice(&plain).map_err(|e| format!("jwe payload parse: {e}"))
}

/// The NIST ConcatKDF for the CEK derivation (one round; SHA-256).
fn concat_kdf(z: &[u8], alg: &[u8], length: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(length);
    let mut counter = 1u32;
    while out.len() < length {
        let mut h = Sha256::new();
        h.update(counter.to_be_bytes());
        h.update(z);
        h.update(alg);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(length);
    out
}

/// Rebuild the sender's public key from its JWK x/y (base64url).
fn ecdh_point(x_b64: &str, y_b64: &str) -> Result<p256::PublicKey, String> {
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    let x = b64d(x_b64)?;
    let y = b64d(y_b64)?;
    let mut point = vec![0x04];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    let encoded = p256::EncodedPoint::from_bytes(&point).map_err(|_| "bad epk POINT".to_string())?;
    p256::PublicKey::from_encoded_point(&encoded)
        .into_option()
        .ok_or_else(|| "the epk is not on the curve".into())
}

/// Standard base64url decode (no padding requirement).
fn b64d(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("b64url decode: {e}"))
}

/// Decode a Credential Response value (§8.3) into the enum the
/// request path returns - the shared form the DpopSession-protected
/// call and the plain call both land on.
///
/// # Errors
/// Neither credentials nor transaction_id (§8.3).
pub fn parse_credential_response(v: &serde_json::Value) -> Result<CredentialResponse, String> {
    if let Some(creds) = v.get("credentials").and_then(|c| c.as_array()) {
        let mut out = Vec::new();
        for entry in creds {
            out.push(MintedCredential {
                credential: entry
                    .get("credential")
                    .and_then(|c| c.as_str())
                    .ok_or("a credentials entry carries no credential (§8.3)")?
                    .to_string(),
            });
        }
        return Ok(CredentialResponse::Issued {
            credentials: out,
            notification_id: v
                .get("notification_id")
                .and_then(|n| n.as_str())
                .map(str::to_string),
        });
    }
    if let Some(tx) = v.get("transaction_id").and_then(|t| t.as_str()) {
        let interval = v.get("interval").and_then(|i| i.as_u64()).unwrap_or(0);
        return Ok(CredentialResponse::Deferred {
            transaction_id: tx.to_string(),
            interval,
            notification_id: v
                .get("notification_id")
                .and_then(|n| n.as_str())
                .map(str::to_string),
        });
    }
    Err("the response carries neither credentials nor transaction_id (§8.3)".into())
}

/// A minted credential entry (§8.3 + App. A: the mdoc credential is
/// the base64url IssuerSigned CBOR (A.2.4); the dc+sd-jwt credential
/// is the compact SD-JWT string (A.3.4); the jwt_vc_json credential
/// is the JWT string (A.1.1.4)).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintedCredential {
    /// The credential string.
    pub credential: String,
}

/// The Credential Response (§8.3): the immediate form (`credentials`)
/// or the deferred form (`transaction_id` + `interval`).
#[derive(Debug, Clone)]
pub enum CredentialResponse {
    /// The 200 immediate form: the `credentials` array (+ the
    /// `notification_id` when the issuer uses notifications, ss11.4).
    Issued {
        /// The minted credentials.
        credentials: Vec<MintedCredential>,
        /// The `notification_id` when the issuer uses notifications.
        notification_id: Option<String>,
    },
    /// The 202 deferred form (§9): poll after `interval` seconds.
    Deferred {
        /// The transaction id.
        transaction_id: String,
        /// The minimum poll interval (seconds).
        interval: u64,
        /// The `notification_id` when the issuer uses notifications.
        notification_id: Option<String>,
    },
}

/// POST the Credential Request (§8.2) and parse the response per
/// §8.3: 200 = the credentials array; 202 = the deferred
/// transaction.
///
/// # Errors
/// Transport + the Credential Error Response (§8.3.1.2:
/// `invalid_credential_request`, `unknown_credential_configuration`,
/// `unknown_credential_identifier`, `invalid_proof`, `invalid_nonce`,
/// `invalid_encryption_parameters`, `credential_request_denied`).
/// Perform the credential request (§8.2) and decode the response -
/// the JSON form or a compact JWE (when the request carried the
/// encryption material, the issuer MAY return the 5-part JWE; the
/// wallet opens it with its ephemeral key).
///
/// # Errors
/// Transport, HTTP, parse, or the error envelope.
pub async fn request_credential(
    http: &reqwest::Client,
    credential_endpoint: &str,
    access_token: &str,
    body: &CredentialRequestBody,
    encryption: Option<&ResponseEncryption>,
) -> Result<CredentialResponse, String> {
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
    let v: serde_json::Value = if text.trim_start().starts_with('{') {
        serde_json::from_str(&text).map_err(|e| format!("credential response parse: {e}"))?
    } else if text.split('.').count() == 5 {
        let enc = encryption
            .ok_or("the JWE response arrived but the request carried no encryption material")?;
        decrypt_ecdh_es_a256gcm(text.trim(), &enc.sk)?
    } else {
        return Err(format!(
            "credential response is neither JSON nor a JWE ({} chars)",
            text.len()
        ));
    };
    if let Some(creds) = v.get("credentials").and_then(|c| c.as_array()) {
        let mut out = Vec::new();
        for entry in creds {
            out.push(MintedCredential {
                credential: entry
                    .get("credential")
                    .and_then(|c| c.as_str())
                    .ok_or("a credentials entry carries no credential (§8.3)")?
                    .to_string(),
            });
        }
        return Ok(CredentialResponse::Issued {
            credentials: out,
            notification_id: v
                .get("notification_id")
                .and_then(|n| n.as_str())
                .map(str::to_string),
        });
    }
    if let Some(tx) = v.get("transaction_id").and_then(|t| t.as_str()) {
        let interval = v.get("interval").and_then(|i| i.as_u64()).unwrap_or(0);
        return Ok(CredentialResponse::Deferred {
            transaction_id: tx.to_string(),
            interval,
            notification_id: v
                .get("notification_id")
                .and_then(|n| n.as_str())
                .map(str::to_string),
        });
    }
    Err("the response carries neither credentials nor transaction_id (§8.3)".into())
}

// ── The Deferred Credential Endpoint (OID4VCI §9) ───────────────────

/// The Deferred Credential answer (§9.2): the issued credentials or
/// the still-pending marker.
#[derive(Debug, Clone)]
pub enum DeferredAnswer {
    /// The 200 form: the credentials landed.
    Issued(Vec<MintedCredential>),
    /// The 202 form: poll again after `interval` seconds with the
    /// SAME transaction_id.
    Pending {
        /// The transaction id.
        transaction_id: String,
        /// The interval (seconds).
        interval: u64,
    },
}

/// Poll the Deferred Credential Endpoint (§9.1): the transaction_id +
/// the same access token.
///
/// # Errors
/// Transport + the error envelope (§9.3: `invalid_transaction_id`,
/// `credential_request_denied` - the latter is terminal).
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
    if !status.is_success() {
        return Err(format!("deferred poll: HTTP {status}: {text}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("deferred parse: {e}"))?;
    if let Some(creds) = v.get("credentials").and_then(|c| c.as_array()) {
        let mut out = Vec::new();
        for entry in creds {
            out.push(MintedCredential {
                credential: entry
                    .get("credential")
                    .and_then(|c| c.as_str())
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        return Ok(DeferredAnswer::Issued(out));
    }
    if let Some(tx) = v.get("transaction_id").and_then(|t| t.as_str()) {
        let interval = v.get("interval").and_then(|i| i.as_u64()).unwrap_or(0);
        return Ok(DeferredAnswer::Pending {
            transaction_id: tx.to_string(),
            interval,
        });
    }
    Err("the deferred response carries neither credentials nor transaction_id (§9.2)".into())
}

// ── The Notification Endpoint (OID4VCI §11) ─────────────────────────

/// The notification events (§11.1).
#[derive(Debug, Clone, Copy)]
pub enum NotificationEvent {
    /// The credentials were stored in the wallet.
    CredentialAccepted,
    /// The issuance failed (non-user-action causes).
    CredentialFailure,
    /// The user deleted the credential / rejected the issuance.
    CredentialDeleted,
}

impl NotificationEvent {
    /// The wire value.
    pub fn code(self) -> &'static str {
        match self {
            Self::CredentialAccepted => "credential_accepted",
            Self::CredentialFailure => "credential_failure",
            Self::CredentialDeleted => "credential_deleted",
        }
    }
}

/// Send the issuance notification (§11.1): the `notification_id` from
/// the Credential Response + the event. The issuer treats
/// notifications as idempotent (§11).
///
/// # Errors
/// Transport + the error envelope (§11.3:
/// `invalid_notification_id`, `invalid_notification_request`).
pub async fn send_notification(
    http: &reqwest::Client,
    notification_endpoint: &str,
    access_token: &str,
    notification_id: &str,
    event: NotificationEvent,
    description: Option<&str>,
) -> Result<(), String> {
    let mut body = serde_json::json!({
        "notification_id": notification_id,
        "event": event.code(),
    });
    if let Some(d) = description {
        body["event_description"] = serde_json::json!(d);
    }
    let resp = http
        .post(notification_endpoint)
        .bearer_auth(access_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("notification: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("notification: HTTP {status}: {text}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_shape_and_iss_policy() {
        let key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ));
        // The anonymous form: no iss (App. F.1).
        let anon = mint_jwt_proof(&key, None, "https://issuer", Some("n0")).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(anon.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(claims.get("iss").is_none());
        assert_eq!(claims["aud"], "https://issuer");
        assert_eq!(claims["nonce"], "n0");
        // The authenticated form: iss = client_id.
        let auth = mint_jwt_proof(&key, Some("cid"), "https://issuer", None).unwrap();
        let claims2: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(auth.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims2["iss"], "cid");
    }

    #[test]
    fn offer_intake_forms() {
        let by_value = parse_offer_url(
            "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fi%22%2C%22credential_configuration_ids%22%3A%5B%22a%22%5D%7D",
        )
        .unwrap();
        let OfferIntake::ByValue(json) = by_value else { panic!("by value") };
        let offer = parse_credential_offer(&json).unwrap();
        assert_eq!(offer.credential_issuer, "https://i");
        assert_eq!(offer.credential_configuration_ids, vec!["a"]);
        let by_ref = parse_offer_url(
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fi%2Foffer%2Fabc",
        )
        .unwrap();
        assert!(matches!(by_ref, OfferIntake::ByReference(uri) if uri == "https://i/offer/abc"));
        // Both parameters = a spec violation (§4.1).
        assert!(parse_offer_url("x?credential_offer=%7B%7D&credential_offer_uri=https%3A%2F%2Fi").is_err());
    }

    #[test]
    fn offer_grants_parse() {
        let offer = parse_credential_offer(
            r#"{
                "credential_issuer": "https://i",
                "credential_configuration_ids": ["a", "b"],
                "grants": {
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                        "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
                        "tx_code": { "length": 4, "input_mode": "numeric" }
                    }
                }
            }"#,
        )
        .unwrap();
        match &offer.grants[0] {
            OfferGrant::PreAuthorizedCode { pre_authorized_code, tx_code, .. } => {
                assert_eq!(pre_authorized_code, "oaKazRN8I0IbtZ0C7JuMn5");
                assert_eq!(tx_code.as_ref().unwrap().length, Some(4));
            }
            _ => panic!("the pre-authorized grant"),
        }
        // Duplicated ids reject (§4.1.1 unique).
        assert!(parse_credential_offer(
            r#"{"credential_issuer": "https://i", "credential_configuration_ids": ["a", "a"]}"#
        )
        .is_err());
    }

    #[test]
    fn credential_identifier_selection() {
        let token = serde_json::json!({
            "access_token": "t",
            "authorization_details": [
                { "type": "openid_credential",
                  "credential_configuration_id": "cfg",
                  "credential_identifiers": ["id-1", "id-2"] }
            ]
        });
        let ids = credential_identifiers(&token).unwrap();
        assert_eq!(ids, vec!["id-1", "id-2"]);
        assert!(credential_identifiers(&serde_json::json!({"access_token": "t"})).is_none());
    }

    #[test]
    fn authorization_server_selection() {
        let meta: IssuerMetadata = serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://i",
            "credential_endpoint": "https://i/credential",
            "credential_configurations_supported": {}
        }))
        .unwrap();
        // No authorization_servers: the issuer IS the AS (§12.2.4).
        assert_eq!(select_authorization_server(&meta, None).unwrap(), "https://i");
        let mut multi = meta.clone();
        multi.authorization_servers = vec!["https://as1".into(), "https://as2".into()];
        assert_eq!(
            select_authorization_server(&multi, Some("https://as2")).unwrap(),
            "https://as2"
        );
        assert!(select_authorization_server(&multi, Some("https://evil")).is_err());
    }

    #[test]
    fn credential_request_body_shape() {
        let body = CredentialRequestBody {
            target: CredentialRequestTarget::ConfigurationId("cfg-1".into()),
            proofs: serde_json::json!({ "jwt": ["p"] }),
            credential_response_encryption: None,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["credential_configuration_id"], "cfg-1");
        assert!(json.get("credential_identifier").is_none());
        assert_eq!(json["proofs"]["jwt"][0], "p");
        let body2 = CredentialRequestBody {
            target: CredentialRequestTarget::Identifier("id-1".into()),
            proofs: serde_json::json!({ "jwt": [] }),
            credential_response_encryption: None,
        };
        let json2 = serde_json::to_value(&body2).unwrap();
        assert_eq!(json2["credential_identifier"], "id-1");
        assert!(json2.get("credential_configuration_id").is_none());
    }
}
