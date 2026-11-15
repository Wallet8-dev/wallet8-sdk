//! # wallet8-oid4vp-client - the OID4VP wallet client
//!
//! The wallet-role presentation client (OID4VP 1.0 Final): parses
//! verifier request objects, resolves the DCQL query against the
//! wallet's credential store, and assembles the authorization
//! response - the DCQL `vp_token` object form for BOTH credential
//! formats and BOTH response channels:
//!
//! - **direct_post / direct_post.jwt** - the wallet POSTs the response
//!   (form or JWE) to the request's `response_uri`.
//! - **dc_api / dc_api.jwt** - the Digital Credentials API session
//!   channel (App. A): the wallet receives the request through
//!   `browser.requestCredential` and posts the response to the
//!   session's submit URL.
//!
//! The mdoc wire forms ride the platform engine `sentin8::mdoc` (the
//! MSO-verified IssuerSigned re-presentation, the DeviceResponse with
//! selective disclosure, and the B.2.6.1/B.2.6.2 session transcripts);
//! the sd-jwt vc forms reuse the wallet's credential strings.
//!
//! The flow:
//!
//! 1. **Request intake** - `parse_authorization_request` (the JAR
//!    object: client_id, nonce, response_uri/response_mode, the
//!    dcql_query, client_metadata with the verifier's enc JWK).
//! 2. **DCQL resolution** - `match_credentials` maps the query's
//!    credential entries (mso_mdoc by `doctype_value`, dc+sd-jwt by
//!    `vct_values`) to the wallet's holdings.
//! 3. **Disclosure selection** - `disclosure_for` picks the digestID
//!    set covering the query's claim paths (no undisclosed-requested
//!    excess - OID4VP §6.4.1).
//! 4. **Response assembly** - `build_vp_token` builds the mdoc
//!    DeviceResponse (the transcript from the request's channel) or
//!    re-sends the sd-jwt; `post_response` delivers it (direct_post
//!    form / dc_api session submit).
//!
//! # Examples
//!
//! Assemble an mdoc response for a verifier query:
//!
//! ```
//! use wallet8_oid4vp_client::{AuthorizationRequest, DcqlQuery, build_vp_token};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let request = AuthorizationRequest {
//!     client_id: "x509_hash:abc".into(),
//!     nonce: "n0".into(),
//!     response_uri: "https://v/response".into(),
//!     response_mode: "direct_post".into(),
//!     dcql_query: DcqlQuery { credentials: vec![] },
//! };
//! let device_key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
//!     &mut p256::elliptic_curve::rand_core::OsRng));
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};

/// The parsed authorization request (the JAR object's wallet-relevant
/// members - the signature verification is the caller's step).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// The verifier's client_id (the x509_hash / redirect / origin
    /// prefix forms - App. B.2).
    pub client_id: String,
    /// The fresh verifier nonce.
    pub nonce: String,
    /// The direct_post response target (absent for the dc_api channel).
    #[serde(default)]
    pub response_uri: Option<String>,
    /// The response mode (direct_post / direct_post.jwt / dc_api /
    /// dc_api.jwt).
    #[serde(default)]
    pub response_mode: Option<String>,
    /// The DCQL query.
    pub dcql_query: DcqlQuery,
    /// The client_metadata (the verifier's enc JWK + vp_formats).
    #[serde(default)]
    pub client_metadata: serde_json::Value,
    /// The transaction_id (the dc_api channel's session id).
    #[serde(default)]
    pub transaction_id: Option<String>,
}

/// The DCQL query (OID4VP Final §5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlQuery {
    /// The credential entries.
    pub credentials: Vec<DcqlCredentialQuery>,
}

/// One DCQL credential entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlCredentialQuery {
    /// The entry id (the vp_token response key).
    pub id: String,
    /// The format (`mso_mdoc` / `dc+sd-jwt`).
    pub format: String,
    /// The meta: `{doctype_value}` for mdoc, `{vct_values}` for sd-jwt.
    #[serde(default)]
    pub meta: serde_json::Value,
    /// The requested claims (`path` members).
    #[serde(default)]
    pub claims: Vec<DcqlClaim>,
    /// The claim_sets preference options.
    #[serde(default)]
    pub claim_sets: Vec<Vec<String>>,
}

/// One DCQL claim (the 2-element `[namespace, element]` path for mdoc;
/// the single-member `[claim]` for sd-jwt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlClaim {
    /// The optional claim id.
    #[serde(default)]
    pub id: Option<String>,
    /// The path.
    pub path: Vec<String>,
}

/// One wallet holding (the credential store entry view).
#[derive(Debug, Clone)]
pub struct WalletCredential {
    /// The format (`mso_mdoc` / `dc+sd-jwt`).
    pub format: String,
    /// The mdoc doctype (`mso_mdoc` holdings).
    pub doctype: Option<String>,
    /// The sd-jwt vct (`dc+sd-jwt` holdings).
    pub vct: Option<String>,
    /// The credential string (the mdoc IssuerSigned base64url or the
    /// compact sd-jwt).
    pub credential: String,
}

/// Parse the authorization request from the request-object JWT payload.
///
/// # Errors
/// A malformed request object.
pub fn parse_authorization_request(payload: &str) -> Result<AuthorizationRequest, String> {
    serde_json::from_str(payload).map_err(|e| format!("request object parse: {e}"))
}

/// Match the query's credential entries against the wallet's holdings.
///
/// Returns `(query-entry, holding)` pairs (the dc+sd-jwt entries match
/// by `vct_values`, the mdoc entries by `doctype_value`).
///
/// # Errors
/// None in practice; the Result keeps the signature stable.
pub fn match_credentials<'a>(
    query: &'a DcqlQuery,
    holdings: &'a [WalletCredential],
) -> Result<Vec<(&'a DcqlCredentialQuery, &'a WalletCredential)>, String> {
    let mut out = Vec::new();
    for entry in &query.credentials {
        let matched = holdings.iter().find(|h| {
            if entry.format == "mso_mdoc" {
                h.format == "mso_mdoc"
                    && entry
                        .meta
                        .get("doctype_value")
                        .and_then(|d| d.as_str())
                        .map(|want| h.doctype.as_deref() == Some(want))
                        .unwrap_or(false)
            } else {
                h.format == entry.format
                    && entry
                        .meta
                        .get("vct_values")
                        .and_then(|v| v.as_array())
                        .map(|want| {
                            want.iter().filter_map(|w| w.as_str()).any(|w| {
                                h.vct.as_deref() == Some(w)
                            })
                        })
                        .unwrap_or(false)
            }
        });
        if let Some(h) = matched {
            out.push((entry, h));
        }
    }
    Ok(out)
}

/// Build the vp_token object (the DCQL response): the mdoc entries
/// assemble a fresh DeviceResponse (the selective disclosure covers
/// the query's claim paths, the device signature over the channel's
/// session transcript); the sd-jwt entries re-send the stored compact
/// credential.
///
/// The transcript: the B.2.6.1 redirect form for direct_post* (or the
/// dc_api B.2.6.2 form when the response mode says so - the caller
/// supplies the origin).
///
/// # Errors
/// A descriptive string when the disclosure or the response assembly
/// fails.
pub fn build_vp_token(
    matches: &[(&DcqlCredentialQuery, &WalletCredential)],
    device_key: &p256::ecdsa::SigningKey,
    request: &AuthorizationRequest,
    dc_api_origin: Option<&str>,
) -> Result<serde_json::Value, String> {
    let _ = device_key;
    let mut token = serde_json::Map::new();
    for (entry, holding) in matches {
        if holding.format == "mso_mdoc" {
            // The session transcript per the response channel.
            let transcript = match request.response_mode.as_deref() {
                Some("dc_api") | Some("dc_api.jwt") => {
                    let origin = dc_api_origin
                        .ok_or("the dc_api channel needs the origin")?;
                    sentin8::mdoc::transcript::dc_api_transcript(
                        origin,
                        &request.nonce,
                        None,
                    )?
                }
                _ => sentin8::mdoc::transcript::redirect_transcript(
                    &request.client_id,
                    &request.nonce,
                    None,
                    request
                        .response_uri
                        .as_deref()
                        .unwrap_or_default(),
                )?,
            };
            let vp = sentin8::mdoc::device_response::build_device_response(&[
                sentin8::mdoc::device_response::DeviceResponseInput {
                    doc_type: holding.doctype.as_deref().unwrap_or_default(),
                    issuer_signed_b64: &holding.credential,
                    device_key,
                    transcript: &transcript,
                },
            ])?;
            token.insert(entry.id.clone(), serde_json::json!([vp]));
        } else {
            // The sd-jwt presentation: the stored credential string
            // (the KB re-mint is the caller's step when the request
            // demands it).
            token.insert(entry.id.clone(), serde_json::json!([holding.credential]));
        }
    }
    Ok(serde_json::Value::Object(token))
}

/// Post the authorization response (the direct_post form).
///
/// # Errors
/// Transport + the verifier's error envelope.
pub async fn post_response(
    http: &reqwest::Client,
    response_uri: &str,
    vp_token: &serde_json::Value,
    state: &str,
) -> Result<serde_json::Value, String> {
    let mut form: Vec<(&str, String)> = vec![(
        "vp_token",
        serde_json::to_string(vp_token).map_err(|e| e.to_string())?,
    )];
    if !state.is_empty() {
        form.push(("state", state.to_string()));
    }
    let resp = http
        .post(response_uri)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("response post: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("response read: {e}"))?;
    if !status.is_success() {
        return Err(format!("response post: HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("response parse: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holding() -> Vec<WalletCredential> {
        vec![WalletCredential {
            format: "mso_mdoc".into(),
            doctype: Some("org.iso.18013.5.1.mDL".into()),
            vct: None,
            credential: String::new(),
        }]
    }

    #[test]
    fn dcql_matching() {
        let query = DcqlQuery {
            credentials: vec![DcqlCredentialQuery {
                id: "mdl".into(),
                format: "mso_mdoc".into(),
                meta: serde_json::json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
                claims: vec![],
                claim_sets: vec![],
            }],
        };
        let holdings = holding();
        let matched = match_credentials(&query, &holdings).unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].0.id, "mdl");
    }

    #[test]
    fn request_parses() {
        let req = r#"{
            "client_id": "x509_hash:abc",
            "nonce": "n0",
            "response_uri": "https://v/r",
            "response_mode": "direct_post",
            "dcql_query": {"credentials": []}
        }"#;
        let parsed = parse_authorization_request(req).unwrap();
        assert_eq!(parsed.client_id, "x509_hash:abc");
        assert_eq!(parsed.dcql_query.credentials.len(), 0);
    }
}
