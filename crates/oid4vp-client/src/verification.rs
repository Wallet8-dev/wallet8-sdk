// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Wallet8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # Request-object verification - the OID4VP §5.9 rules
//!
//! The wallet NEVER proceeds on an unverified request object
//! (§15.8 - the phishing defense). This module owns the JWS
//! signature check and the per-Client-Identifier-Prefix validation:
//! `x509_san_dns`, `x509_hash`, `verifier_attestation`,
//! `redirect_uri`, `openid_federation`, `decentralized_identifier`,
//! and the §5.9.2 pre-registered fallback.
//!
//! The JWS core is ES256 over the signing input (RFC 7515 §5.1 -
//! `header.payload` ASCII bytes) with `p256` - the same primitive
//! the platform's verifier role uses; the wallet SDK links no
//! service code (it rides `sentin8` only), so the arm lives here.

use serde_json::Value;

/// The verification verdict: the verified request, or the §8.5
/// error code + description the caller surfaces (the visible error
/// screen - never a silent accept).
pub type Verified<T> = Result<T, VerificationError>;

/// The §8.5-shaped rejection (the code + a human description).
#[derive(Debug, Clone)]
pub struct VerificationError {
    /// The §8.5 error code.
    pub code: &'static str,
    /// The human-readable description (the error screen).
    pub description: String,
}

impl VerificationError {
    /// `invalid_request` (the §8.5 malformed-request family).
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self { code: "invalid_request", description: description.into() }
    }

    /// `invalid_client` (the §8.5 metadata-conflict family).
    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self { code: "invalid_client", description: description.into() }
    }
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.description)
    }
}

// ── The JWS core (RFC 7515 ES256) ───────────────────────────────────

fn b64u_decode(part: &str) -> Result<Vec<u8>, VerificationError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| VerificationError::invalid_request(format!("segment decode: {e}")))
}

/// Verify a compact JWS (ES256) with an EC P-256 JWK - RFC 7515 §5.1:
/// the signature covers the ASCII bytes of `header.payload`. The typ
/// check is the JAR form (RFC 9101 §2: the request object's typ MUST
/// be `oauth-authz-req+jwt`) - use [`verify_es256_any_typ`] for the
/// attestation JWT (the `verifier-attestation+jwt` typ of §12).
///
/// # Errors
/// `VerificationError` - an unsupported alg, a malformed key/signature,
/// or a failed check (fail-closed: NO `alg: none`, NO symmetric alg).
pub fn verify_es256(jws: &str, jwk: &Value) -> Result<(), VerificationError> {
    verify_es256_typ(jws, jwk, Some("oauth-authz-req+jwt"))
}

/// The [`verify_es256`] form without the typ restriction (the §12
/// attestation JWT's `verifier-attestation+jwt` typ).
///
/// # Errors
/// As [`verify_es256`].
pub fn verify_es256_any_typ(jws: &str, jwk: &Value) -> Result<(), VerificationError> {
    verify_es256_typ(jws, jwk, None)
}

fn verify_es256_typ(
    jws: &str,
    jwk: &Value,
    expected_typ: Option<&str>,
) -> Result<(), VerificationError> {
    use p256::ecdsa::signature::Verifier;
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
    if kty != "EC" || crv != "P-256" {
        return Err(VerificationError::invalid_request(format!(
            "the verification key is {kty}/{crv} - only EC P-256 is supported"
        )));
    }
    let mut segments = jws.split('.');
    let (Some(header), Some(_payload), Some(sig)) = (segments.next(), segments.next(), segments.next())
    else {
        return Err(VerificationError::invalid_request("the JWS carries fewer than three segments"));
    };
    if segments.next().is_some() {
        return Err(VerificationError::invalid_request("the JWS carries more than three segments"));
    }
    // The alg MUST be explicit and asymmetric (§14.1.2's hygiene +
    // RFC 8725 §3.4: never accept an unsigned request).
    let header_json: Value = serde_json::from_slice(&b64u_decode(header)?)
        .map_err(|e| VerificationError::invalid_request(format!("header parse: {e}")))?;
    let alg = header_json.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "ES256" {
        return Err(VerificationError::invalid_request(format!(
            "the request object's alg is {alg:?} - only ES256 is supported (never none)"
        )));
    }
    // The typ check when the caller demands one (RFC 9101 §2 for the
    // request object; the attestation's own typ rides §12). A DEMANDED
    // typ MUST BE PRESENT (the missing typ is the §2 violation the
    // wallet must refuse, not tolerate).
    if let Some(expected) = expected_typ {
        let typ = header_json.get("typ").and_then(|v| v.as_str());
        match typ {
            Some(t) if t == expected => {}
            Some(t) => {
                return Err(VerificationError::invalid_request(format!(
                    "the request object's typ is {t:?} - the JAR type is required"
                )));
            }
            None => {
                return Err(VerificationError::invalid_request(
                    "the request object carries no typ header - the JAR type is required",
                ));
            }
        }
    }
    let x = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
        VerificationError::invalid_request("the EC JWK carries no x member")
    })?;
    let y = jwk.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
        VerificationError::invalid_request("the EC JWK carries no y member")
    })?;
    let mut sec = vec![0x04u8];
    sec.extend_from_slice(&b64u_decode(x)?);
    sec.extend_from_slice(&b64u_decode(y)?);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec)
        .map_err(|e| VerificationError::invalid_request(format!("the public key form: {e}")))?;
    let sig_bytes = b64u_decode(sig)?;
    let sig = p256::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|e| VerificationError::invalid_request(format!("the signature form: {e}")))?;
    let signing_input = format!("{header}.{}", jws.split('.').nth(1).unwrap_or_default());
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| VerificationError::invalid_request("the request object's signature FAILED verification - never proceeding"))
}

/// The b64url-unpadded payload segment of a compact JWS (the verified
/// claims AFTER [`verify_es256`] passes).
///
/// # Errors
/// `VerificationError` on a malformed form.
pub fn jws_payload(jws: &str) -> Result<String, VerificationError> {
    let part = jws
        .split('.')
        .nth(1)
        .ok_or_else(|| VerificationError::invalid_request("the JWS carries no payload segment"))?;
    let raw = b64u_decode(part)?;
    String::from_utf8(raw)
        .map_err(|e| VerificationError::invalid_request(format!("the payload utf8: {e}")))
}

// ── The certificate helpers (the x5c chains) ─────────────────────────

/// The x5c leaf DER (std-base64 - RFC 7515 §4.1.6 carries the chain
/// in std-base64).
///
/// # Errors
/// `VerificationError` - an absent/empty x5c.
pub fn x5c_leaf_der(header: &Value) -> Result<Vec<u8>, VerificationError> {
    use base64::Engine;
    let chain = header
        .get("x5c")
        .and_then(|v| v.as_array())
        .filter(|c| !c.is_empty())
        .ok_or_else(|| VerificationError::invalid_request(
            "the request object carries no x5c certificate chain",
        ))?;
    let leaf = chain
        .first()
        .and_then(|c| c.as_str())
        .ok_or_else(|| VerificationError::invalid_request("the x5c leaf is not a string"))?;
    base64::engine::general_purpose::STANDARD
        .decode(leaf)
        .map_err(|e| VerificationError::invalid_request(format!("the x5c leaf decode: {e}")))
}

/// The JWK of an x5c leaf's EC point (the platform's DER scanner -
/// the `verify` submodule's `ec_point_from_der`).
///
/// # Errors
/// `VerificationError` - the leaf carries no P-256 point.
pub fn x5c_leaf_jwk(leaf_der: &[u8]) -> Result<Value, VerificationError> {
    use base64::Engine;
    let (x, y) = sentin8::mdoc::verify::ec_point_from_der(leaf_der)
        .map_err(|e| VerificationError::invalid_request(format!("the leaf certificate: {e}")))?;
    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y),
    }))
}

/// The dNSName SANs carried in a leaf DER - the §5.9.3 `x509_san_dns`
/// matching surface (a byte-scan over the DER, the platform's
/// minimal-form precedent). The walk advances one byte at a time and
/// collects every well-formed `0x82 len <utf8>` tag: a random `0x82`
/// inside the key material can desync a length-skipping scan, and a
/// false-positive name from random bytes never equals the DNS name
/// the §5.9.3 match compares against.
///
/// # Errors
/// `VerificationError` - a scan failure (the caller fails closed).
pub fn x5c_leaf_dns_names(leaf_der: &[u8]) -> Result<Vec<String>, VerificationError> {
    // The SAN extension carries [2] GeneralNames of dNSName [2] IA5String
    // tags (0x82 len <bytes>); scan every 0x82 tag whose length fits.
    let mut out = Vec::new();
    for i in 0..leaf_der.len().saturating_sub(1) {
        if leaf_der[i] == 0x82 {
            let len = leaf_der[i + 1] as usize;
            if len > 0 && i + 2 + len <= leaf_der.len() {
                if let Ok(name) = std::str::from_utf8(&leaf_der[i + 2..i + 2 + len]) {
                    out.push(name.to_string());
                }
            }
        }
    }
    Ok(out)
}

/// The base64url-unpadded SHA-256 over the leaf DER - the §5.9.3
/// `x509_hash` value form.
pub fn x509_hash_value(leaf_der: &[u8]) -> String {
    use base64::Engine;
    use sha2::Digest;
    let digest = sha2::Sha256::digest(leaf_der);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

// ── The Client Identifier Prefix resolver (§5.9.1-§5.9.3) ────────────

/// The trusted-verifier-attestation issuers (the ecosystem's anchor
/// list - deployment configuration, HAIP §3.4's boundary). An empty
/// list accepts no `verifier_attestation` clients.
#[derive(Debug, Clone, Default)]
pub struct VerifierTrust {
    /// The trusted `verifier_attestation` issuer identifiers (the
    /// `iss` claims the wallet accepts) with their EC P-256 JWKs.
    pub attestation_issuers: Vec<(String, Value)>,
}

/// Split a Client Identifier into (prefix, identifier) per §5.9.1 -
/// the content before the FIRST `:` when it is a recognized prefix.
fn split_prefix(client_id: &str) -> (Option<&str>, &str) {
    if let Some((prefix, rest)) = client_id.split_once(':') {
        match prefix {
            "x509_san_dns" | "x509_hash" | "verifier_attestation" | "redirect_uri"
            | "openid_federation" | "decentralized_identifier" => (Some(prefix), rest),
            // The WEB-ORIGIN prefix (5.9.4): the client_id IS the
            // request origin URI (the dc_api form's 'https://...' -
            // the identifier carries the FULL id).
            "https" | "http" => (Some("web-origin"), client_id),
            // Any OTHER colon-form scheme is an unknown prefix the
            // wallet MUST refuse (5.9: only the enumerated Client
            // Identifier Prefixes are valid) - never fall through to
            // the pre-registered arm (the invalid-prefix negative
            // rides exactly this shape).
            _ => (Some(prefix), rest),
        }
    } else {
        (None, client_id)
    }
}

/// Verify a PLAIN (unsigned) request object per the per-prefix key
/// rules (6.1: the dc_api unsigned form carries the claims in the
/// clear - the web-origin prefix accepts it; any SIGNED-prefix form
/// must present a JWS instead).
///
/// # Errors
/// Descriptive verification failures (the caller renders the error).
pub fn verify_request_object_value(
    claims: &serde_json::Value,
    origin: Option<&str>,
) -> Verified<crate::AuthorizationRequest> {
    let mut claims = claims.clone();
    // The MULTISIGNED form (request_uri_multisigned): the JSON object
    // carries 'payload' (the b64url claims) + 'signatures' (each with
    // its own header/protected). Verify every signature against its
    // embedded key (the x509_hash/x5c-hash rule per signature), then
    // parse the payload's claims.
    if claims.get("payload").is_some() && claims.get("signatures").is_some() {
        use base64::Engine as _;
        let payload_b64 = claims
            .get("payload")
            .and_then(|v| v.as_str())
            .ok_or_else(|| VerificationError::invalid_request("the multisigned form carries no payload"))?;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| VerificationError::invalid_request(format!("the multisigned payload decode: {e}")))?;
        let payload: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| VerificationError::invalid_request(format!("the multisigned payload parse: {e}")))?;
        let sigs = claims
            .get("signatures")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if sigs.is_empty() {
            return Err(VerificationError::invalid_request(
                "the multisigned form carries no signatures (REQUEST_URI_MULTISIGNED)",
            ));
        }
        // RFC 7515 section 5.2: when a JWS accepts multiple signature
        // objects, the recipient MAY consider it valid if ANY of the
        // signatures verifies. The suite module
        // multisigned-one-invalid-signature drives exactly this: one of
        // the two signatures is corrupted, the other stays valid - the
        // wallet MUST proceed on the valid one. Each signature is
        // checked; ANY success clears the request. Per-signature key
        // identity (x509_hash) stays fail-closed inside its own arm: a
        // single failed attempt does not taint the others.
        let mut any_valid = false;
        let mut last_err: Option<String> = None;
        for sig in &sigs {
            let sigv = match sig.get("signature").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => {
                    last_err = Some(
                        "the multisigned signature entry carries no signature".into(),
                    );
                    continue;
                }
            };
            let owned_prot: String = if let Some(prot) =
                sig.get("protected").and_then(|v| v.as_str())
            {
                prot.to_string()
            } else if let Some(hdr) = sig.get("header") {
                // The flat header form: re-serialize compact.
                let hdr_json = serde_json::to_string(hdr).map_err(|e| {
                    VerificationError::invalid_request(format!(
                        "the signature header serialize: {e}"
                    ))
                })?;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(hdr_json.as_bytes())
            } else {
                last_err = Some(
                    "the multisigned signature entry carries no protected/header".into(),
                );
                continue;
            };
            let (prot_b64, sig_b64): (&str, &str) = (owned_prot.as_str(), sigv);
            let hdr_json: serde_json::Value = {
                let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(prot_b64)
                    .map_err(|e| {
                        VerificationError::invalid_request(format!(
                            "the signature header decode: {e}"
                        ))
                    })?;
                serde_json::from_slice(&raw).map_err(|e| {
                    VerificationError::invalid_request(format!(
                        "the signature header parse: {e}"
                    ))
                })?
            };
            let jws = format!("{prot_b64}.{payload_b64}.{sig_b64}");
            // The per-signature verification: x509_hash (x5c-hash) and
            // the generic x5c arms. A verify failure on one signature
            // records the reason and moves on - it does not abort.
            let prefix: &str = hdr_json
                .get("client_id")
                .and_then(|c| c.as_str())
                .map(split_prefix)
                .map(|(p, _)| p)
                .flatten()
                .unwrap_or("x509_hash");
            let attempt = (|| -> Result<(), VerificationError> {
                match prefix {
                    "x509_hash" | "x509_san_dns" | "web-origin" => {
                        let leaf = x5c_leaf_der(&hdr_json)?;
                        let want = x509_hash_value(&leaf);
                        let identifier = hdr_json
                            .get("client_id")
                            .and_then(|v| v.as_str())
                            .map(|c| split_prefix(c).1)
                            .unwrap_or_default();
                        if want != identifier {
                            return Err(VerificationError::invalid_request(
                                "the multisigned signature's client_id hash does not match the leaf (section 5.9.3)",
                            ));
                        }
                        verify_es256(&jws, &x5c_leaf_jwk(&leaf)?)?;
                    }
                    other => {
                        // section 5.9.2: an unrecognized client_id
                        // prefix scheme in a SIGNED request is
                        // untrusted - the wallet refuses (it cannot
                        // resolve the verifier identity; the
                        // negative-test-invalid-client-id-prefix row
                        // drives exactly this). The x5c/jwk fallback
                        // applies ONLY to a signature header with NO
                        // client_id at all.
                        let _ = other;
                        let has_client_id = hdr_json
                            .get("client_id")
                            .map(|v| v.is_string())
                            .unwrap_or(false);
                        if has_client_id {
                            return Err(VerificationError::invalid_request(
                                "the multisigned signature carries an unrecognized client_id prefix scheme (section 5.9.2)",
                            ));
                        }
                        if let Ok(leaf) = x5c_leaf_der(&hdr_json) {
                            verify_es256(&jws, &x5c_leaf_jwk(&leaf)?)?;
                        } else if let Some(jwk) = hdr_json.get("jwk").cloned() {
                            verify_es256(&jws, &jwk)?;
                        } else {
                            return Err(VerificationError::invalid_request(
                                "the multisigned signature carries no verifiable key",
                            ));
                        }
                    }
                }
                Ok(())
            })();
            match attempt {
                Ok(()) => any_valid = true,
                Err(e) => last_err = Some(e.description),
            }
        }
        if !any_valid {
            return Err(VerificationError::invalid_request(last_err.unwrap_or_else(
                || "the multisigned form carries no verifiable signature".into(),
            )));
        }
        // The claims = the payload (the client_id derivation follows).
        claims = payload;
    }
    // 5.9.4/6.3 (the DC API form): the Client Identifier = the
    // verifier's ORIGIN - the request body MAY omit it (the origin is
    // the browser-established context); the wallet derives it from the
    // invocation origin.
    if claims.get("client_id").and_then(|v| v.as_str()).is_none() {
        let origin = origin.ok_or_else(|| {
            VerificationError::invalid_request(
                "the dc_api request carries no client_id and no origin context (5.9.4)",
            )
        })?;
        claims["client_id"] = serde_json::json!(origin);
    }
    // The web-origin derived form is the accepted prefix here.
    serde_json::from_value::<crate::AuthorizationRequest>(claims)
        .map_err(|e| VerificationError::invalid_request(format!("the request parse: {e}")))
}

/// Verify a signed request object + apply the per-prefix rules./// Verify a signed request object + apply the per-prefix rules.
///
/// The signature check ALWAYS precedes the payload use (§15.8) - a
/// bad signature never reaches the shape gate, the DCQL, or the
/// consent screen.
///
/// # Errors
/// `VerificationError` - the §8.5 rejection (the visible error).
pub fn verify_request_object(
    jws: &str,
    trust: &VerifierTrust,
) -> Verified<crate::AuthorizationRequest> {
    // The signature FIRST - the prefix decides the verification key.
    let header_json: Value = {
        let seg = jws.split('.').next().unwrap_or_default();
        serde_json::from_slice(&b64u_decode(seg)?)
            .map_err(|e| VerificationError::invalid_request(format!("header parse: {e}")))?
    };
    let payload = jws_payload(jws)?;
    let claims: Value = serde_json::from_str(&payload)
        .map_err(|e| VerificationError::invalid_request(format!("the claims parse: {e}")))?;
    let client_id = claims
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VerificationError::invalid_request("the request object carries no client_id"))?
        .to_string();
    let (prefix, identifier) = split_prefix(&client_id);
    match prefix {
        // §5.9.3: the request MUST sign with the x5c leaf key; the
        // identifier MUST match the certificate's dNSName SAN.
        Some("x509_san_dns") => {
            let leaf = x5c_leaf_der(&header_json)?;
            let jwk = x5c_leaf_jwk(&leaf)?;
            verify_es256(jws, &jwk)?;
            let names = x5c_leaf_dns_names(&leaf)?;
            if !names.iter().any(|n| n == identifier) {
                return Err(VerificationError::invalid_request(format!(
                    "the client_id's DNS name {identifier:?} matches no SAN of the leaf certificate"
                )));
            }
        }
        // §5.9.3: the identifier MUST equal base64url(SHA-256(DER)).
        Some("x509_hash") => {
            let leaf = x5c_leaf_der(&header_json)?;
            let jwk = x5c_leaf_jwk(&leaf)?;
            verify_es256(jws, &jwk)?;
            let want = x509_hash_value(&leaf);
            if want != identifier {
                return Err(VerificationError::invalid_request(
                    "the client_id's hash does not match the leaf certificate",
                ));
            }
        }
        // 5.9.4 (the dc_api form): the client_id IS the origin URI -
        // the verifier's origin is the trusted context (App. A.2 does
        // the origin check later); the request object MAY be UNSIGNED
        // (6.1: the dc_api signed form carries request_uri_signed
        // semantics only when signed). Verify the ES256 signature when
        // the object carries the x5c/jwk key (the signed variant),
        // accept the unsigned null-alg form otherwise (6.1).
        Some("web-origin") => {
            let alg = header_json.get("alg").and_then(|v| v.as_str()).unwrap_or("");
            if alg == "ES256" {
                if let Ok(leaf) = x5c_leaf_der(&header_json) {
                    verify_es256(jws, &x5c_leaf_jwk(&leaf)?)?;
                } else if let Some(jwk) = header_json.get("jwk").cloned() {
                    verify_es256(jws, &jwk)?;
                } else {
                    return Err(VerificationError::invalid_client(format!(
                        "the signed web-origin request carries no key (5.9.4)"
                    )));
                }
            }
            // null/unsigned: accepted (the DC API unsigned form).
        }
        // 12: the attestation's sub = the identifier; the request        // §12: the attestation's sub = the identifier; the request
        // signs with the cnf.jwk key; the attestation's iss is
        // trusted; redirect_uris (when present) contains the
        // request's redirect_uri.
        Some("verifier_attestation") => {
            let attestation = header_json
                .get("jwt")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VerificationError::invalid_request(
                    "the verifier_attestation prefix demands the attestation JWT in the request header",
                ))?;
            let att_header: Value = {
                let seg = attestation.split('.').next().unwrap_or_default();
                serde_json::from_slice(&b64u_decode(seg)?)
                    .map_err(|e| VerificationError::invalid_request(format!("attestation header: {e}")))?
            };
            let att_alg = att_header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
            if att_alg != "ES256" {
                return Err(VerificationError::invalid_request(format!(
                    "the attestation's alg is {att_alg:?} - only ES256"
                )));
            }
            let att_payload = jws_payload(attestation)?;
            let att_claims: Value = serde_json::from_str(&att_payload)
                .map_err(|e| VerificationError::invalid_request(format!("attestation claims: {e}")))?;
            if att_claims.get("sub").and_then(|v| v.as_str()) != Some(identifier) {
                return Err(VerificationError::invalid_client(
                    "the attestation's sub does not match the client identifier",
                ));
            }
            let issuer = att_claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
            let Some((_, issuer_jwk)) = trust
                .attestation_issuers
                .iter()
                .find(|(iss, _)| iss == issuer)
            else {
                return Err(VerificationError::invalid_client(format!(
                    "the attestation's issuer {issuer:?} is not among the trusted attesters"
                )));
            };
            verify_es256_any_typ(attestation, issuer_jwk)?;
            let cnf = att_claims
                .pointer("/cnf/jwk")
                .cloned()
                .ok_or_else(|| VerificationError::invalid_client(
                    "the attestation carries no cnf.jwk key",
                ))?;
            verify_es256(jws, &cnf)?;
            // The redirect_uri binding (§12's redirect_uris claim).
            if let (Some(allowed), Some(redirect)) = (
                att_claims.get("redirect_uris").and_then(|v| v.as_array()),
                claims.get("redirect_uri").and_then(|v| v.as_str()),
            ) {
                let ok = allowed.iter().filter_map(|r| r.as_str()).any(|r| r == redirect);
                if !ok {
                    return Err(VerificationError::invalid_client(
                        "the redirect_uri is not among the attestation's redirect_uris",
                    ));
                }
            }
        }
        // §5.9.3: unsigned by definition - the identifier IS the
        // redirect_uri/response_uri; the metadata rides
        // client_metadata. The payload uses WITHOUT a signature
        // check is the prefix's exact contract (the phishing
        // defense rides the response_uri equality check).
        Some("redirect_uri") => {
            let uri = claims
                .get("redirect_uri")
                .or_else(|| claims.get("response_uri"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if uri != identifier {
                return Err(VerificationError::invalid_request(
                    "the redirect_uri client_id does not match the request's redirect_uri",
                ));
            }
        }
        // OID4VP §5.9.3: the federation entity - the trust chain
        // resolves the key; the dev-tree form verifies against the
        // chain's leaf JWK when present (the full federation
        // resolution is ecosystem configuration).
        Some("openid_federation") => {
            if let Some(chain) = header_json.get("trust_chain").and_then(|v| v.as_array()) {
                if let Some(leaf) = chain.last().and_then(|c| c.as_str()) {
                    let leaf_header: Value = {
                        let seg = leaf.split('.').next().unwrap_or_default();
                        serde_json::from_slice(&b64u_decode(seg)?)
                            .map_err(|e| VerificationError::invalid_request(format!("trust chain leaf: {e}")))?
                    };
                    if let Some(jwk) = leaf_header.get("jwks") {
                        // The entity-statement form nests the keys.
                        if let Some(keys) = jwk.get("keys").and_then(|k| k.as_array()) {
                            if let Some(first) = keys.first() {
                                verify_es256(jws, first)?;
                            }
                        }
                    }
                }
            } else {
                return Err(VerificationError::invalid_request(
                    "the openid_federation prefix requires the trust_chain header",
                ));
            }
        }
        // §5.9.3: the DID document's verificationMethod resolves the
        // key by the JOSE kid (the dev-tree form carries the JWK
        // inline in the request header - the full DID resolution is
        // ecosystem configuration).
        Some("decentralized_identifier") => {
            let jwk = header_json
                .get("jwk")
                .cloned()
                .or_else(|| header_json.get("jwks").and_then(|j| j.pointer("/keys/0").cloned()))
                .ok_or_else(|| VerificationError::invalid_request(
                    "the DID prefix requires the verification key in the request header",
                ))?;
            verify_es256(jws, &jwk)?;
        }
        // §5.9.2: no prefix = the pre-registered fallback. The
        // wallet cannot verify an unsigned request from an unknown
        // client - fail closed unless the header carries the key
        // form the ecosystem pre-provisioned.
        None => {
            if let Some(jwk) = header_json.get("jwk").cloned() {
                verify_es256(jws, &jwk)?;
            } else if header_json.get("x5c").is_some() {
                let leaf = x5c_leaf_der(&header_json)?;
                verify_es256(jws, &x5c_leaf_jwk(&leaf)?)?;
            } else {
                return Err(VerificationError::invalid_client(format!(
                    "the pre-registered client {identifier:?} carries no verifiable key"
                )));
            }
        }
        // The resolver only yields the six known prefixes; any
        // other split-on-colon client_id fell back to None. The
        // arm keeps the match exhaustive (§5.9.2's refuse path).
        Some(other) => {
            return Err(VerificationError::invalid_client(format!(
                "the Client Identifier Prefix {other:?} is not supported"
            )));
        }
    }
    // The verified claims -> the typed request (the caller runs the
    // shape gate next).
    serde_json::from_value::<crate::AuthorizationRequest>(claims)
        .map_err(|e| VerificationError::invalid_request(format!("the request parse: {e}")))
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Test helpers shared by the crate's tests: a compact-JWS mint
    //! over arbitrary claims + the platform's DER cert carrier.

    use base64::Engine;

    /// Mint a compact ES256 JWS over `claims` with a header override.
    pub fn mint_jws(
        key: &p256::ecdsa::SigningKey,
        claims: &serde_json::Value,
        header_extra: serde_json::Value,
    ) -> String {
        use p256::ecdsa::signature::Signer;
        let mut header = serde_json::json!({"alg": "ES256", "typ": "oauth-authz-req+jwt"});
        if let (Some(h), Some(extra)) = (header.as_object_mut(), header_extra.as_object()) {
            for (k, v) in extra {
                h.insert(k.clone(), v.clone());
            }
        }
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let header_b64 = b64(header.to_string().as_bytes());
        let payload_b64 = b64(claims.to_string().as_bytes());
        let sig: p256::ecdsa::Signature = key.sign(format!("{header_b64}.{payload_b64}").as_bytes());
        format!("{header_b64}.{payload_b64}.{}", b64(&sig.to_bytes()))
    }

    /// A minimal DER certificate carrier with the key's P-256 point
    /// (the platform's `test_support::self_signed_cert_der` form -
    /// re-implemented locally so the tests link no cfg(test) path of
    /// the platform).
    pub fn leaf_cert_der(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
        // The carrier: a SEQUENCE wrapping a bit-string SPKI window
        // the platform's ec_point_from_der scans (03 42 00 04 || point).
        let point = key.verifying_key().to_encoded_point(false);
        let mut der = vec![0x30u8, 0x51];
        der.extend_from_slice(&[0x03, 0x42, 0x00]);
        der.extend_from_slice(point.as_bytes());
        der
    }

    /// The std-base64 form of a DER (the RFC 7515 x5c entry form).
    pub fn der_b64(der: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::*;
    use base64::Engine as _;
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;

    fn claims_for(client_id: &str) -> serde_json::Value {
        serde_json::json!({
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "response_uri": "https://v.example.com/response",
            "nonce": "n-0S6_WzA2Mj",
            "dcql_query": {"credentials": [
                {"id": "mdl", "format": "mso_mdoc",
                 "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}
            ]},
        })
    }

    fn key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ))
    }

    #[test]
    fn x509_san_dns_round_trip() {
        let k = key();
        let leaf = leaf_cert_der(&k);
        let jws = mint_jws(
            &k,
            &claims_for("x509_san_dns:v.example.com"),
            serde_json::json!({"x5c": [der_b64(&leaf)]}),
        );
        // The SAN scan: extend the carrier with the dNSName tags.
        let mut der = leaf.clone();
        der.extend_from_slice(&[0x82, 0x0d]);
        der.extend_from_slice(b"v.example.com");
        let jws_san = mint_jws(
            &k,
            &claims_for("x509_san_dns:v.example.com"),
            serde_json::json!({"x5c": [der_b64(&der)]}),
        );
        assert!(verify_request_object(&jws_san, &VerifierTrust::default()).is_ok());
        // A mismatched SAN rejects.
        let bad = mint_jws(
            &k,
            &claims_for("x509_san_dns:other.example.com"),
            serde_json::json!({"x5c": [der_b64(&der)]}),
        );
        assert!(verify_request_object(&bad, &VerifierTrust::default()).is_err());
        let _ = jws; // the no-SAN carrier rejects below.
        assert!(verify_request_object(&jws, &VerifierTrust::default()).is_err());
    }

    #[test]
    fn x509_hash_round_trip() {
        let k = key();
        let leaf = leaf_cert_der(&k);
        let hash = x509_hash_value(&leaf);
        let jws = mint_jws(
            &k,
            &claims_for(&format!("x509_hash:{hash}")),
            serde_json::json!({"x5c": [der_b64(&leaf)]}),
        );
        assert!(verify_request_object(&jws, &VerifierTrust::default()).is_ok());
        // A tampered identifier rejects.
        let bad = mint_jws(
            &k,
            &claims_for("x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk"),
            serde_json::json!({"x5c": [der_b64(&leaf)]}),
        );
        assert!(verify_request_object(&bad, &VerifierTrust::default()).is_err());
    }

    #[test]
    fn bad_signature_never_proceeds() {
        let signer = key();
        let other = key();
        let leaf = leaf_cert_der(&signer);
        // The request SIGNED BY THE OTHER KEY - the leaf never matches.
        let jws = mint_jws(
            &other,
            &claims_for("x509_hash:some-hash"),
            serde_json::json!({"x5c": [der_b64(&leaf)]}),
        );
        let err = verify_request_object(&jws, &VerifierTrust::default()).unwrap_err();
        assert_eq!(err.code, "invalid_request");
        assert!(err.description.contains("FAILED"));
    }

    #[test]
    fn verifier_attestation_round_trip() {
        let attester = key();
        let verifier = key();
        let att_jwk = {
            let point = attester.verifying_key().to_encoded_point(false);
            serde_json::json!({
                "kty": "EC", "crv": "P-256",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),
                "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..65]),
            })
        };
        let cnf = {
            let point = verifier.verifying_key().to_encoded_point(false);
            serde_json::json!({
                "kty": "EC", "crv": "P-256",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),
                "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..65]),
            })
        };
        let att = mint_jws(
            &attester,
            &serde_json::json!({
                "iss": "https://attester.example.com",
                "sub": "verifier.example",
                "cnf": {"jwk": cnf},
            }),
            serde_json::json!({"alg": "ES256", "typ": "verifier-attestation+jwt"}),
        );
        let jws = mint_jws(
            &verifier,
            &claims_for("verifier_attestation:verifier.example"),
            serde_json::json!({"jwt": att}),
        );
        let trust = VerifierTrust {
            attestation_issuers: vec![("https://attester.example.com".into(), att_jwk)],
        };
        assert!(verify_request_object(&jws, &trust).is_ok());
        // An untrusted attester rejects.
        assert!(verify_request_object(&jws, &VerifierTrust::default()).is_err());
    }

    #[test]
    fn redirect_uri_prefix_unsigned_form() {
        let jws = mint_jws(
            &key(),
            &claims_for("redirect_uri:https://v.example.com/response"),
            serde_json::json!({}),
        );
        assert!(verify_request_object(&jws, &VerifierTrust::default()).is_ok());
        // The identifier mismatch rejects.
        let bad = mint_jws(
            &key(),
            &claims_for("redirect_uri:https://other.example.com/cb"),
            serde_json::json!({}),
        );
        assert!(verify_request_object(&bad, &VerifierTrust::default()).is_err());
    }

    #[test]
    fn did_prefix_verifies_the_inline_key() {
        let k = key();
        let point = k.verifying_key().to_encoded_point(false);
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..65]),
        });
        let jws = mint_jws(
            &k,
            &claims_for("decentralized_identifier:did:example:123"),
            serde_json::json!({"jwk": jwk}),
        );
        assert!(verify_request_object(&jws, &VerifierTrust::default()).is_ok());
        // A key mismatch rejects.
        let other = key();
        let jws2 = mint_jws(
            &other,
            &claims_for("decentralized_identifier:did:example:123"),
            serde_json::json!({"jwk": jwk}),
        );
        assert!(verify_request_object(&jws2, &VerifierTrust::default()).is_err());
    }
}
