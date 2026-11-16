//! # wallet8-oid4vp-client - the OpenID4VP 1.0 wallet client
//!
//! The wallet-role presentation client implementing **OpenID for
//! Verifiable Presentations 1.0** (Final, 9 Jul 2025) - every function
//! cites its spec section. The OIDF suite verifies; the specification
//! is the contract.
//!
//! ## The flow (OID4VP §3)
//!
//! 1. **Request intake** (§5): the scanned URL carries the authorize
//!    request - either URL-encoded parameters (§5.4 opt. 1), a
//!    `request` object by value, or a `request_uri` (+ the optional
//!    `request_uri_method=post` carrying `wallet_metadata` + a fresh
//!    `wallet_nonce`, §5.10). The Client Identifier Prefix (§5.9)
//!    decides how the Verifier is authenticated (`redirect_uri`,
//!    `x509_san_dns`, `x509_hash`, `verifier_attestation`, DIDs, ...).
//! 2. **DCQL evaluation** (§6.4): the credential/claim selection per
//!    the exact §6.4.1/§6.4.2 rules (`claim_sets` preference order,
//!    `credential_sets` options, `multiple`, the `values`
//!    best-effort matching).
//! 3. **Presentation assembly** (§8.1 + App. B): the vp_token JSON
//!    object keyed by credential-query id; the mdoc entries are the
//!    base64url DeviceResponse (B.2.5) with the SessionTranscript per
//!    the invocation channel (B.2.6.1 redirects / B.2.6.2 DC API); the
//!    SD-JWT entries are the SD-JWT + Key Binding JWT (B.3.6: KB `aud`
//!    = client_id or `origin:<origin>`, `nonce` = the request nonce,
//!    `sd_hash` over the SD-JWT).
//! 4. **Delivery** (§8.2/§8.3 + App. A): `direct_post` / the DC API
//!    promise; `dc_api.jwt`/`direct_post.jwt` = the JWE-encrypted
//!    `response` form.
//! 5. **The errors** (§8.5): `invalid_request`, `access_denied`,
//!    `vp_formats_not_supported`, `invalid_request_uri_method`,
//!    `invalid_transaction_data`, `wallet_unavailable` - with the
//!    §15.4.1/§15.9 privacy care (no value-leaking).
//!
//! # Examples
//!
//! Parse a request-object payload and check its shape (the wallet's
//! first gate, §5.2):
//!
//! ```
//! use wallet8_oid4vp_client::{parse_request, check_request_shape};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let request = parse_request(
//!     r#"{"client_id": "redirect_uri:https://v/r", "response_type": "vp_token",
//!         "response_mode": "direct_post", "response_uri": "https://v/r",
//!         "nonce": "n-0S6_WzA2Mj",
//!         "dcql_query": {"credentials": []}}"#)?;
//! check_request_shape(&request)?;
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};

pub mod verification;
pub use verification::{verify_request_object, VerificationError, Verified, VerifierTrust};

pub mod encryption;
pub use encryption::{encrypt_response, EncryptionError};

pub mod status;
pub use status::{
    check_status, decode_status_reference, entry_value, fetch_status_list,
    inflate_status_list, parse_status_list_token, StatusList, StatusReference, StatusValue,
};

// ── The Authorization Request (OID4VP §5) ──────────────────────────

/// The parsed Authorization Request (the request object's payload -
/// the JAR signature verify is the caller's step, per the Client
/// Identifier Prefix rules §5.9).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// The Verifier's full Client Identifier (§5.9.1: the prefix rides
    /// within - the wallet MUST always use the full value, §14.8).
    pub client_id: String,
    /// The response type (§5.6: `vp_token`).
    #[serde(default)]
    pub response_type: Option<String>,
    /// The response mode (§5.2): the default for `vp_token` is
    /// `fragment`; `direct_post`/`direct_post.jwt` (§8.2/§8.3.1);
    /// `dc_api`/`dc_api.jwt` over the DC API (App. A).
    #[serde(default)]
    pub response_mode: Option<String>,
    /// The `response_uri` (§8.2: REQUIRED with direct_post; the
    /// `redirect_uri` MUST NOT also be present).
    #[serde(default)]
    pub response_uri: Option<String>,
    /// The `redirect_uri` (§5.2; absent for response_uri flows).
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// The fresh verifier nonce (§5.2 REQUIRED - ASCII URL-safe).
    #[serde(default)]
    pub nonce: String,
    /// The `state` (§5.2: REQUIRED when any presentation is without
    /// Holder Binding, §5.3).
    #[serde(default)]
    pub state: Option<String>,
    /// The DCQL query (§6) - or None when the `scope` alias is used
    /// (§5.5; exactly one of the two, §5.1).
    #[serde(default)]
    pub dcql_query: Option<DcqlQuery>,
    /// The scope alias (§5.5).
    #[serde(default)]
    pub scope: Option<String>,
    /// The Verifier metadata (§5.1: `jwks` + `vp_formats_supported` +
    /// `encrypted_response_enc_values_supported`).
    #[serde(default)]
    pub client_metadata: serde_json::Value,
    /// The `transaction_data` entries (§8.4 - a wallet that does not
    /// support it MUST reject, §5.1).
    #[serde(default)]
    pub transaction_data: Vec<String>,
    /// The `verifier_info` attestations (§5.11 - MAY enrich consent;
    /// ignored when unsupported).
    #[serde(default)]
    pub verifier_info: Vec<serde_json::Value>,
    /// The `expected_origins` (App. A.2: REQUIRED for signed DC API
    /// requests; the wallet MUST compare against the platform-provided
    /// Origin).
    #[serde(default)]
    pub expected_origins: Vec<String>,
}

/// Parse the request-object payload (§5.4).
///
/// # Errors
/// A malformed payload.
pub fn parse_request(payload: &str) -> Result<AuthorizationRequest, String> {
    serde_json::from_str(payload).map_err(|e| format!("request object parse: {e}"))
}

/// The wallet's request-shape gate (§5.1/§5.2/§8.2): the nonce present;
/// exactly one of dcql_query/scope; the response_mode/response_uri
/// pairing; the redirect/response-uri exclusivity; the
/// transaction_data rejection (§5.1 - a wallet that does not support
/// it MUST reject). The Client Identifier Prefix and signature
/// checks belong to [`verification::verify_request_object`]
/// (§5.9's per-prefix rules).
///
/// # Errors
/// A descriptive string per violated requirement (§8.5's
/// `invalid_request` family).
pub fn check_request_shape(request: &AuthorizationRequest) -> Result<(), String> {
    if request.nonce.is_empty() {
        return Err("the request carries no nonce (§5.2 REQUIRED)".into());
    }
    // §8.4 + §5.1: the wallet does not support transaction_data - a
    // request carrying it MUST reject, never a partial pass.
    if !request.transaction_data.is_empty() {
        return Err(
            "the request carries transaction_data the wallet does not support (§5.1)".into(),
        );
    }
    match (&request.dcql_query, &request.scope) {
        (Some(_), Some(_)) => {
            return Err("the request carries both dcql_query and scope (§5.1)".into())
        }
        (None, None) => {
            return Err("the request carries neither dcql_query nor a scope alias (§5.1)".into())
        }
        _ => {}
    }
    match request.response_mode.as_deref() {
        Some("direct_post") | Some("direct_post.jwt") => {
            if request.response_uri.is_none() {
                return Err("direct_post requires a response_uri (§8.2)".into());
            }
            if request.redirect_uri.is_some() {
                return Err("response_uri and redirect_uri are exclusive (§8.2)".into());
            }
        }
        Some("dc_api") | Some("dc_api.jwt") | None | Some("fragment") => {}
        Some(other) => {
            return Err(format!("unknown response_mode {other}"));
        }
    }
    Ok(())
}

/// The `expected_origins` check (App. A.2): the platform-asserted
/// origin MUST be among the allow-list on a signed DC API request -
/// the replay defense across the DC API channel. An empty array
/// (the unsigned form) passes trivially.
///
/// # Errors
/// `invalid_request` (the §8.5 code) on a mismatch or a missing
/// platform origin.
pub fn check_expected_origins(
    request: &AuthorizationRequest,
    platform_origin: Option<&str>,
) -> Result<(), String> {
    if request.expected_origins.is_empty() {
        return Ok(());
    }
    let Some(origin) = platform_origin else {
        return Err(
            "the request demands expected_origins but no platform origin is available (App. A.2)"
                .into(),
        );
    };
    if request.expected_origins.iter().any(|o| o == origin) {
        Ok(())
    } else {
        Err(format!(
            "the platform origin {origin:?} matches no expected_origins entry (App. A.2)"
        ))
    }
}

/// The scope alias resolution (§5.5): every scope value maps to a
/// DCQL query the wallet's metadata defines. An unknown scope =
/// `invalid_scope` (§8.5) - never a silent pass. The resolved
/// request carries the mapped dcql_query (the caller then runs the
/// shape gate + the evaluation over the resolved form).
///
/// # Errors
/// A descriptive string naming the unknown alias or the empty set.
pub fn resolve_scope_alias(
    request: &AuthorizationRequest,
    registry: &std::collections::BTreeMap<String, DcqlQuery>,
) -> Result<AuthorizationRequest, String> {
    let Some(scope) = request.scope.as_deref() else {
        return Ok(request.clone());
    };
    let mut resolved = request.clone();
    let mut query = DcqlQuery { credentials: vec![], credential_sets: vec![] };
    for alias in scope.split_whitespace() {
        let Some(mapped) = registry.get(alias) else {
            return Err(format!(
                "the scope value {alias:?} maps to no DCQL query the wallet defines (§5.5)"
            ));
        };
        query.credentials.extend(mapped.credentials.iter().cloned());
        query.credential_sets.extend(mapped.credential_sets.iter().cloned());
    }
    if query.credentials.is_empty() {
        return Err("the scope resolved to no credential queries (§5.5)".into());
    }
    resolved.dcql_query = Some(query);
    Ok(resolved)
}

// ── DCQL (OID4VP §6) ────────────────────────────────────────────────

/// The DCQL query (§6): the `credentials` array (REQUIRED, non-empty)
/// + the optional `credential_sets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlQuery {
    /// The Credential Queries (§6.1).
    pub credentials: Vec<CredentialQuery>,
    /// The Credential Set Queries (§6.2).
    #[serde(default)]
    pub credential_sets: Vec<CredentialSetQuery>,
}

/// One Credential Query (§6.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialQuery {
    /// The `id` (§6.1 REQUIRED - alphanumeric/_/-, unique per request;
    /// the vp_token response key).
    pub id: String,
    /// The `format` (§6.1 REQUIRED - the Credential Format Identifier,
    /// App. B).
    pub format: String,
    /// The `meta` (§6.1 REQUIRED - the format-specific constraints:
    /// `doctype_value` (B.2.3), `vct_values` (B.3.5),
    /// `type_values` (B.1.1)).
    #[serde(default)]
    pub meta: serde_json::Value,
    /// The `claims` (§6.3 - never the same claim twice).
    #[serde(default)]
    pub claims: Vec<ClaimsQuery>,
    /// The `claim_sets` (§6.1/§6.4.1: the preferred combinations - the
    /// FIRST satisfiable wins).
    #[serde(default)]
    pub claim_sets: Vec<Vec<String>>,
    /// The `multiple` flag (§6.1: true = several presentations in the
    /// response array).
    #[serde(default)]
    pub multiple: bool,
    /// The `require_cryptographic_holder_binding` (§6.1: default true
    /// - the Verifiable Presentation MUST carry the proof).
    #[serde(default = "default_true")]
    pub require_cryptographic_holder_binding: bool,
    /// The `trusted_authorities` (§6.1.1: aki/etsi_tl/openid_federation).
    #[serde(default)]
    pub trusted_authorities: Vec<serde_json::Value>,
}

fn default_true() -> bool {
    true
}

/// One Claims Query (§6.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsQuery {
    /// The `id` (REQUIRED when claim_sets present; unique per array).
    #[serde(default)]
    pub id: Option<String>,
    /// The `path` (§7 claims path pointer: `[namespace, element]` for
    /// mdocs; the JSON pointer for the sd-jwt/vc formats).
    pub path: Vec<serde_json::Value>,
    /// The `values` (§6.3: the best-effort value matching - treated as
    /// non-existent when mismatched, §6.4.1).
    #[serde(default)]
    pub values: Vec<serde_json::Value>,
    /// The `intent_to_retain` (B.2.4, mdoc-specific).
    #[serde(default)]
    pub intent_to_retain: Option<bool>,
}

/// One Credential Set Query (§6.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSetQuery {
    /// The `options` (§6.2: each option = a set of credential-query
    /// ids satisfying the use case).
    pub options: Vec<Vec<String>>,
    /// The `required` (§6.2: default true).
    #[serde(default = "default_true")]
    pub required: bool,
}

/// One wallet holding (the credential store's view).
#[derive(Debug, Clone)]
pub struct WalletCredential {
    /// The format identifier (App. B: `mso_mdoc`, `dc+sd-jwt`, ...).
    pub format: String,
    /// The mdoc doctype.
    pub doctype: Option<String>,
    /// The SD-JWT vct.
    pub vct: Option<String>,
    /// The credential material (the mdoc IssuerSigned b64url / the
    /// compact sd-jwt).
    pub credential: String,
    /// The disclosed-claim values the `values` matching reads
    /// (the path -> value map, §6.4.1; empty = no value matching).
    pub claim_values: std::collections::BTreeMap<String, serde_json::Value>,
}

/// The DCQL evaluation result (§6.4): the selected credentials with
/// the claim subsets to disclose.
#[derive(Debug, Clone)]
pub struct DcqlMatch {
    /// The credential query the match satisfies.
    pub query: CredentialQuery,
    /// The matched holding.
    pub credential: WalletCredential,
    /// The selected claim paths (the §6.4.1 rules applied: all when
    /// no claim_sets; the FIRST satisfiable option otherwise).
    pub selected_claim_paths: Vec<Vec<serde_json::Value>>,
}

/// Evaluate the DCQL query against the holdings (§6.4).
///
/// The §6.4.2 credential-set rules: without `credential_sets` every
/// query must match; with them, all REQUIRED sets must be satisfiable
/// (the wallet returns one option per set). Credentials not matching
/// a query's constraints MUST NOT be returned (§6.4.2) - an
/// unsatisfiable REQUIRED set or an unmatchable REQUIRED query means
/// the whole request fails (no partial vp_token, §6.4.2).
///
/// # Errors
/// A descriptive string when a required query/set is unsatisfiable.
pub fn evaluate_dcql<'a>(
    query: &DcqlQuery,
    holdings: &'a [WalletCredential],
) -> Result<Vec<DcqlMatch>, String> {
    let mut matches: Vec<DcqlMatch> = Vec::new();
    let mut match_for = |q: &CredentialQuery,
                         matches: &mut Vec<DcqlMatch>|
     -> Result<bool, String> {
        for holding in holdings {
            if format_matches(q, holding) && value_rules_ok(q, holding) {
                let selected = select_claims(q, holding)?;
                matches.push(DcqlMatch {
                    query: q.clone(),
                    credential: holding_clone(holding),
                    selected_claim_paths: selected,
                });
                return Ok(true);
            }
        }
        Ok(false)
    };
    if query.credential_sets.is_empty() {
        // §6.4.2: every Credential Query must be satisfied.
        for q in &query.credentials {
            if !match_for(q, &mut matches)? {
                return Err(format!(
                    "no credential satisfies the required query {} (§6.4.2)",
                    q.id
                ));
            }
        }
        return Ok(matches);
    }
    // §6.4.2: the credential_sets drive the selection.
    let mut matched_ids: std::collections::HashSet<String> = Default::default();
    for set in &query.credential_sets {
        let mut satisfied = false;
        for option in &set.options {
            let mut all_ok = true;
            let mut option_ids = Vec::new();
            for id in option {
                if let Some(q) = query.credentials.iter().find(|c| &c.id == id) {
                    option_ids.push(q);
                } else {
                    all_ok = false;
                    break;
                }
            }
            if !all_ok {
                continue;
            }
            let mut option_matches = Vec::new();
            let mut ids_ok = true;
            for q in option_ids {
                if matched_ids.contains(&q.id) {
                    continue;
                }
                if !match_for(q, &mut option_matches)? {
                    ids_ok = false;
                    break;
                }
            }
            if ids_ok {
                for m in option_matches {
                    matched_ids.insert(m.query.id.clone());
                    matches.push(m);
                }
                satisfied = true;
                break;
            }
        }
        if !satisfied && set.required {
            return Err(
                "a required credential set is unsatisfiable (§6.4.2)".into(),
            );
        }
    }
    Ok(matches)
}

fn holding_clone(h: &WalletCredential) -> WalletCredential {
    WalletCredential {
        format: h.format.clone(),
        doctype: h.doctype.clone(),
        vct: h.vct.clone(),
        credential: h.credential.clone(),
        claim_values: h.claim_values.clone(),
    }
}

/// The format + meta matching (§6.1: `doctype_value` B.2.3,
/// `vct_values` B.3.5 - inheritance out of scope here).
fn format_matches(q: &CredentialQuery, holding: &WalletCredential) -> bool {
    if q.format != holding.format {
        return false;
    }
    match q.format.as_str() {
        "mso_mdoc" => {
            let want = q.meta.get("doctype_value").and_then(|d| d.as_str());
            want.map(|w| holding.doctype.as_deref() == Some(w))
                .unwrap_or(true)
        }
        "dc+sd-jwt" => {
            let wants = q
                .meta
                .get("vct_values")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if wants.is_empty() {
                return true;
            }
            wants
                .iter()
                .filter_map(|w| w.as_str())
                .any(|w| holding.vct.as_deref() == Some(w))
        }
        _ => true,
    }
}

/// The `values` best-effort rule (§6.4.1): a mismatched claim behaves
/// as non-existent. The wallet cannot always read pre-disclosure -
/// when the holding carries no value map the rule is skipped (the
/// verifier MUST NOT rely on it, §6.4.1).
fn value_rules_ok(q: &CredentialQuery, holding: &WalletCredential) -> bool {
    for claim in &q.claims {
        if claim.values.is_empty() {
            continue;
        }
        let key = path_key(&claim.path);
        if let Some(v) = holding.claim_values.get(&key) {
            let matched = claim.values.iter().any(|want| {
                serde_json::to_string(want).ok() == serde_json::to_string(v).ok()
            });
            if !matched {
                return false;
            }
        }
    }
    true
}

/// The §6.4.1 claim selection: no claims = only the format's
/// mandatory surface; claims without claim_sets = all listed; with
/// claim_sets = the FIRST satisfiable option (else NONE for the
/// credential, §6.4.1).
fn select_claims(
    q: &CredentialQuery,
    holding: &WalletCredential,
) -> Result<Vec<Vec<serde_json::Value>>, String> {
    if q.claims.is_empty() {
        return Ok(Vec::new());
    }
    if q.claim_sets.is_empty() {
        return Ok(q.claims.iter().map(|c| c.path.clone()).collect());
    }
    let available: std::collections::HashSet<String> = holding
        .claim_values
        .keys()
        .cloned()
        .collect();
    for option in &q.claim_sets {
        let mut all = true;
        for claim_id in option {
            let Some(claim) = q.claims.iter().find(|c| c.id.as_deref() == Some(claim_id)) else {
                all = false;
                break;
            };
            let key = path_key(&claim.path);
            if !available.contains(&key) {
                all = false;
                break;
            }
        }
        if all {
            let mut paths = Vec::new();
            for claim_id in option {
                if let Some(claim) = q
                    .claims
                    .iter()
                    .find(|c| c.id.as_deref() == Some(claim_id))
                {
                    paths.push(claim.path.clone());
                }
            }
            return Ok(paths);
        }
    }
    Err("no claim_set option is satisfiable (§6.4.1)".into())
}

fn path_key(path: &[serde_json::Value]) -> String {
    path.iter()
        .map(|p| match p {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => "*".into(),
            n => n.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The human-readable form of a claims path (the consent preview's
/// display): the §7 pointer joined with `/` (the mdoc form is
/// already `namespace/element`).
pub fn claim_path_display(path: &[serde_json::Value]) -> String {
    path_key(path)
}

// ── The VP Token assembly (OID4VP §8.1 + App. B) ────────────────────

/// The audience for the Holder Binding proofs (§14.1.2 + App. A.4):
/// the full Client Identifier - or `origin:<origin>` over the DC API.
pub fn binding_audience(client_id: &str, dc_api_origin: Option<&str>) -> String {
    match dc_api_origin {
        Some(origin) => format!("origin:{origin}"),
        None => client_id.to_string(),
    }
}

/// Build the vp_token JSON object (§8.1): the query id -> the
/// presentations array.
///
/// - mso_mdoc (B.2.5): the base64url DeviceResponse built over the
///   B.2.6.1 (redirects: `redirect_uri`/`response_uri` + the request
///   `client_id`/`nonce`) or the B.2.6.2 (DC API: the bare origin, no
///   `origin:` prefix) SessionTranscript. The third HandoverInfo
///   element is the RFC 7638 thumbprint of the Verifier's response-
///   encryption JWK when the response is encrypted (§8.3), else null.
/// - dc+sd-jwt (B.3.6): the SD-JWT + the Key Binding JWT - `nonce` =
///   the request nonce, `aud` = the full client_id (or
///   `origin:<origin>` per App. A.4), `sd_hash` = the base64url
///   SHA-256 over the SD-JWT.
///
/// # Errors
/// Descriptive strings on decode/sign/encode failures.
pub fn build_vp_token(
    matches: &[DcqlMatch],
    device_key: &p256::ecdsa::SigningKey,
    request: &AuthorizationRequest,
    dc_api_origin: Option<&str>,
) -> Result<serde_json::Value, String> {
    let mut token = serde_json::Map::new();
    for m in matches {
        let entry = match m.credential.format.as_str() {
            "mso_mdoc" => mdoc_entry(m, device_key, request, dc_api_origin)?,
            "dc+sd-jwt" => sd_jwt_entry(m, device_key, request, dc_api_origin)?,
            other => {
                return Err(format!(
                    "the {other} presenter is not implemented in this client"
                ))
            }
        };
        token.insert(m.query.id.clone(), serde_json::Value::Array(vec![entry]));
    }
    Ok(serde_json::Value::Object(token))
}

/// The mdoc presentation (B.2.5 + B.2.6.x): the DeviceResponse.
fn mdoc_entry(
    m: &DcqlMatch,
    device_key: &p256::ecdsa::SigningKey,
    request: &AuthorizationRequest,
    dc_api_origin: Option<&str>,
) -> Result<serde_json::Value, String> {
    let encryption_thumbprint = response_encryption_thumbprint(request)?;
    let transcript = match dc_api_origin {
        Some(origin) => sentin8::mdoc::dc_api_transcript(
            origin,
            &request.nonce,
            encryption_thumbprint.as_deref(),
        )?,
        None => {
            let response_uri = request
                .response_uri
                .as_deref()
                .or(request.redirect_uri.as_deref())
                .ok_or("no response_uri/redirect_uri for the transcript (B.2.6.1)")?;
            sentin8::mdoc::redirect_transcript(
                &request.client_id,
                &request.nonce,
                encryption_thumbprint.as_deref(),
                response_uri,
            )?
        }
    };
    let input = sentin8::mdoc::DeviceResponseInput {
        doc_type: m
            .credential
            .doctype
            .as_deref()
            .ok_or("an mdoc holding without a doctype")?,
        issuer_signed_b64: &m.credential.credential,
        device_key,
        transcript: &transcript,
    };
    Ok(serde_json::Value::String(sentin8::mdoc::build_device_response(
        &[input],
    )?))
}

/// The RFC 7638 thumbprint RAW BYTES for the B.2.6.x third
/// HandoverInfo element: the Verifier's response-encryption JWK when
/// `client_metadata.jwks` carries one (§8.3), else None.
fn response_encryption_thumbprint(
    request: &AuthorizationRequest,
) -> Result<Option<Vec<u8>>, String> {
    let Some(keys) = request
        .client_metadata
        .get("jwks")
        .and_then(|j| j.get("keys"))
        .and_then(|k| k.as_array())
    else {
        return Ok(None);
    };
    // The Verifier's encryption JWK (§8.3: the alg/enc selection).
    let mut candidates: Vec<&serde_json::Value> = keys
        .iter()
        .filter(|k| {
            k.get("use")
                .and_then(|u| u.as_str())
                .map(|u| u == "enc")
                .unwrap_or(false)
        })
        .collect();
    if candidates.is_empty() {
        return Ok(None);
    }
    let jwk = candidates.swap_remove(0);
    let thumbprint = sentin8::mdoc::jwk_thumbprint_raw(jwk)?;
    Ok(Some(thumbprint.to_vec()))
}

/// The SD-JWT presentation (B.3.6): the SD-JWT + KB-JWT chain.
fn sd_jwt_entry(
    m: &DcqlMatch,
    device_key: &p256::ecdsa::SigningKey,
    request: &AuthorizationRequest,
    dc_api_origin: Option<&str>,
) -> Result<serde_json::Value, String> {
    let kb = mint_kb_jwt(
        device_key,
        &request.nonce,
        &binding_audience(&request.client_id, dc_api_origin),
        &m.credential.credential,
    )?;
    Ok(serde_json::Value::String(format!(
        "{}{}",
        m.credential.credential, kb
    )))
}

/// The Key Binding JWT (B.3.6): header `{"alg": "ES256", "typ":
/// "kb+jwt"}`, payload `{nonce, aud, iat, sd_hash}` - `sd_hash` = the
/// base64url-unpadded SHA-256 over the SD-JWT's bytes.
pub fn mint_kb_jwt(
    device_key: &p256::ecdsa::SigningKey,
    nonce: &str,
    audience: &str,
    sd_jwt: &str,
) -> Result<String, String> {
    use base64::Engine;
    use p256::ecdsa::signature::Signer;
    use sha2::Digest as _;
    let b64 = |b: &[u8]| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    };
    let header = b64(br#"{"alg":"ES256","typ":"kb+jwt"}"#.as_slice());
    let sd_hash = b64(&sha2::Sha256::digest(sd_jwt.as_bytes()));

    let payload = serde_json::json!({
        "nonce": nonce,
        "aud": audience,
        "iat": chrono::Utc::now().timestamp(),
        "sd_hash": sd_hash,
    });
    let claims = b64(serde_json::to_string(&payload).unwrap().as_bytes());
    let signing_input = format!("{header}.{claims}");
    let sig: p256::ecdsa::Signature = device_key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64(&sig.to_bytes())))
}

/// The direct_post delivery (§8.2): the form-encoded POST to the
/// `response_uri`; a 200 JSON response MAY carry `redirect_uri` (the
/// wallet app MUST open it in the browser).
///
/// # Errors
/// Transport failures (the caller renders its own error screen).
pub async fn post_response(
    http: &reqwest::Client,
    response_uri: &str,
    vp_token: &serde_json::Value,
    state: Option<&str>,
) -> Result<DirectPostResult, String> {
    let mut body = form_urlencoded(&[
        ("vp_token", &serde_json::to_string(vp_token).unwrap()),
    ]);
    if let Some(s) = state {
        body.push('&');
        body.push_str(&form_urlencoded_one("state", s));
    }
    let resp = http
        .post(response_uri)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await
        .map_err(|e| format!("direct_post transport: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("the response uri answered {}", resp.status()));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("the response uri body: {e}"))?;
    Ok(DirectPostResult {
        redirect_uri: json
            .get("redirect_uri")
            .and_then(|r| r.as_str())
            .map(str::to_string),
    })
}

/// The `direct_post.jwt` delivery (§8.3.1): the Authorization
/// Response parameters (vp_token + state) encrypt to the verifier's
/// ephemeral key (§8.3) and POST as `response=<JWE>`.
///
/// # Errors
/// The encryption failures (no usable recipient key - the caller MAY
/// fall back to the unencrypted §8.2 form per §8.3.1) + transport.
pub async fn post_response_encrypted(
    http: &reqwest::Client,
    response_uri: &str,
    vp_token: &serde_json::Value,
    state: Option<&str>,
    client_metadata: &serde_json::Value,
) -> Result<DirectPostResult, String> {
    let mut payload = serde_json::json!({"vp_token": vp_token});
    if let Some(s) = state {
        payload["state"] = serde_json::json!(s);
    }
    let jwe = encryption::encrypt_response(&payload, client_metadata)
        .map_err(|e| format!("the response encryption: {e}"))?;
    let body = form_urlencoded_one("response", &jwe);
    let resp = http
        .post(response_uri)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await
        .map_err(|e| format!("direct_post.jwt transport: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("the response uri answered {}", resp.status()));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("the response uri body: {e}"))?;
    Ok(DirectPostResult {
        redirect_uri: json
            .get("redirect_uri")
            .and_then(|r| r.as_str())
            .map(str::to_string),
    })
}

/// The dc_api delivery (App. A.4): the response returns to the
/// promise (the app resolves it) - NO back-channel POST. The
/// `dc_api.jwt` form encrypts (§8.3 via App. A.2's channel).
///
/// # Errors
/// The encryption failures on the `.jwt` form.
pub fn dc_api_response(
    vp_token: &serde_json::Value,
    state: Option<&str>,
    client_metadata: Option<&serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let mut payload = serde_json::json!({"vp_token": vp_token});
    if let Some(s) = state {
        payload["state"] = serde_json::json!(s);
    }
    match client_metadata {
        // The dc_api.jwt form: the response parameter carries the JWE.
        Some(metadata) => {
            let jwe = encryption::encrypt_response(&payload, metadata)
                .map_err(|e| format!("the response encryption: {e}"))?;
            Ok(serde_json::json!({"response": jwe}))
        }
        // The plain dc_api form: the parameters ride the promise.
        None => Ok(payload),
    }
}

fn form_urlencoded(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| form_urlencoded_one(k, v))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_urlencoded_one(key: &str, value: &str) -> String {
    let mut out = String::new();
    for b in key.as_bytes() {
        url_encode_byte(*b, &mut out);
    }
    out.push('=');
    for b in value.as_bytes() {
        url_encode_byte(*b, &mut out);
    }
    out
}

fn url_encode_byte(b: u8, out: &mut String) {
    match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
            out.push(b as char)
        }
        _ => out.push_str(&format!("%{b:02X}")),
    }
}

/// The §8.2 direct_post outcome: the optional browser redirect.
#[derive(Debug, Clone)]
pub struct DirectPostResult {
    /// The `redirect_uri` the wallet app MUST open in the browser
    /// (§8.2).
    pub redirect_uri: Option<String>,
}

/// The wallet's error response (§8.5) - the OAuth error object; never
/// an empty/partial vp_token (§6.4.2).
pub fn error_response(error: WalletError, description: &str, state: Option<&str>) -> serde_json::Value {
    let mut v = serde_json::json!({
        "error": error.code(),
        "error_description": description,
    });
    if let Some(s) = state {
        v["state"] = serde_json::json!(s);
    }
    v
}

/// The wallet's error vocabulary (§8.5).
#[derive(Debug, Clone, Copy)]
pub enum WalletError {
    /// The malformed request (§8.5 invalid_request family).
    InvalidRequest,
    /// The request's scope is unknown (§8.5).
    InvalidScope,
    /// No matching credential / the user denied (§8.5 access_denied).
    AccessDenied,
    /// No format overlap (§8.5).
    VpFormatsNotSupported,
    /// A bad request_uri_method (§8.5).
    InvalidRequestUriMethod,
    /// A bad transaction_data structure (§8.5).
    InvalidTransactionData,
}

impl WalletError {
    /// The wire code.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::VpFormatsNotSupported => "vp_formats_not_supported",
            Self::InvalidRequestUriMethod => "invalid_request_uri_method",
            Self::InvalidTransactionData => "invalid_transaction_data",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mdl_holding() -> WalletCredential {
        WalletCredential {
            format: "mso_mdoc".into(),
            doctype: Some("org.iso.18013.5.1.mDL".into()),
            vct: None,
            credential: String::new(),
            claim_values: [
                ("org.iso.18013.5.1/given_name".to_string(), serde_json::json!("Jane")),
                ("org.iso.18013.5.1/family_name".to_string(), serde_json::json!("Doe")),
                ("org.iso.18013.5.1/birth_date".to_string(), serde_json::json!("1990-01-01")),
            ]
            .into_iter()
            .collect(),
        }
    }

    fn mdl_query(claims: Vec<ClaimsQuery>, claim_sets: Vec<Vec<String>>) -> DcqlQuery {
        DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "mdl".into(),
                format: "mso_mdoc".into(),
                meta: serde_json::json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
                claims,
                claim_sets,
                multiple: false,
                require_cryptographic_holder_binding: true,
                trusted_authorities: vec![],
            }],
            credential_sets: vec![],
        }
    }

    #[test]
    fn request_shape_gate() {
        let mut req = parse_request(
            r#"{"client_id": "redirect_uri:https://v/cb", "response_type": "vp_token",
                "response_mode": "direct_post", "response_uri": "https://v/r",
                "nonce": "n-0S6_WzA2Mj", "redirect_uri": "https://v/cb",
                "dcql_query": {"credentials": []}}"#,
        )
        .unwrap();
        // response_uri + redirect_uri = §8.2 violation.
        assert!(check_request_shape(&req).is_err());
        req.redirect_uri = None;
        assert!(check_request_shape(&req).is_ok());
        // Missing nonce = §5.2 violation.
        req.nonce = String::new();
        assert!(check_request_shape(&req)
            .unwrap_err()
            .contains("no nonce"));
    }

    #[test]
    fn dcql_claim_set_preference() {
        // §6.4.1: the FIRST satisfiable claim_set option wins.
        let query = mdl_query(
            vec![
                ClaimsQuery { id: Some("a".into()), path: vec![serde_json::json!("org.iso.18013.5.1"), serde_json::json!("family_name")], values: vec![], intent_to_retain: None },
                ClaimsQuery { id: Some("b".into()), path: vec![serde_json::json!("org.iso.18013.5.1"), serde_json::json!("given_name")], values: vec![], intent_to_retain: None },
                ClaimsQuery { id: Some("c".into()), path: vec![serde_json::json!("org.iso.18013.5.1"), serde_json::json!("un_distinguishing_sign")], values: vec![], intent_to_retain: None },
            ],
            vec![vec!["a".into(), "c".into()], vec!["a".into(), "b".into()]],
        );
        let holdings = [mdl_holding()];
        let matches = evaluate_dcql(&query, &holdings).unwrap();
        assert_eq!(matches.len(), 1);
        // Option 1 (a+c) fails (no un_distinguishing_sign in the
        // holding); option 2 (a+b) satisfies.
        assert_eq!(matches[0].selected_claim_paths.len(), 2);
    }

    #[test]
    fn dcql_values_rule() {
        // §6.4.1: a mismatched `values` claim = the credential does
        // not exist for this query.
        let query = mdl_query(
            vec![ClaimsQuery {
                id: None,
                path: vec![serde_json::json!("org.iso.18013.5.1"), serde_json::json!("family_name")],
                values: vec![serde_json::json!("NotDoe")],
                intent_to_retain: None,
            }],
            vec![],
        );
        let holdings = [mdl_holding()];
        assert!(evaluate_dcql(&query, &holdings).is_err());
        // A matching value passes.
        let query2 = mdl_query(
            vec![ClaimsQuery {
                id: None,
                path: vec![serde_json::json!("org.iso.18013.5.1"), serde_json::json!("family_name")],
                values: vec![serde_json::json!("Doe")],
                intent_to_retain: None,
            }],
            vec![],
        );
        assert!(evaluate_dcql(&query2, &holdings).is_ok());
    }

    #[test]
    fn dcql_unsatisfiable_no_partial() {
        // §6.4.2: a required query without a match = the whole
        // evaluation fails (never a partial vp_token).
        let query = DcqlQuery {
            credentials: vec![
                CredentialQuery {
                    id: "mdl".into(),
                    format: "mso_mdoc".into(),
                    meta: serde_json::json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
                    claims: vec![],
                    claim_sets: vec![],
                    multiple: false,
                    require_cryptographic_holder_binding: true,
                    trusted_authorities: vec![],
                },
                CredentialQuery {
                    id: "missing".into(),
                    format: "mso_mdoc".into(),
                    meta: serde_json::json!({"doctype_value": "org.iso.unknown"}),
                    claims: vec![],
                    claim_sets: vec![],
                    multiple: false,
                    require_cryptographic_holder_binding: true,
                    trusted_authorities: vec![],
                },
            ],
            credential_sets: vec![],
        };
        let holdings = [mdl_holding()];
        let err = evaluate_dcql(&query, &holdings).unwrap_err();
        assert!(err.contains("missing"));
    }

    #[test]
    fn binding_audience_forms() {
        // §14.1.2 + App. A.4.
        assert_eq!(binding_audience("x509_san_dns:v.example", None), "x509_san_dns:v.example");
        assert_eq!(
            binding_audience("x509_san_dns:v.example", Some("https://verifier.example.com/")),
            "origin:https://verifier.example.com/"
        );
    }
}
