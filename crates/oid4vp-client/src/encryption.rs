// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Wallet8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # Encrypted responses (OID4VP §8.3) - `direct_post.jwt`/`dc_api.jwt`
//!
//! The Authorization Response encrypted at the application layer:
//! an unsigned JWE (RFC 7516 §5.1 compact form) carrying the
//! response parameters as its payload. ECDH-ES key agreement with
//! the verifier's ephemeral `use: enc` JWK from
//! `client_metadata.jwks` (§8.3); `A128GCM` content encryption by
//! default (§5.1) or any of `encrypted_response_enc_values_supported`.
//!
//! This mirrors the platform's `sentin8_auth_server::jwe` mint (the
//! issuer-side credential-response encryption) - the same JOSE
//! form, byte for byte: the five-segment compact serialization,
//! zero-length `apu`/`apv`, AAD = the protected header.
//!
//! # Examples
//!
//! ```
//! # use base64::Engine;
//! # use p256::elliptic_curve::sec1::ToEncodedPoint as _;
//! # fn b64u(b: &[u8]) -> String {
//! #     base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
//! # }
//! use wallet8_oid4vp_client::encryption::*;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // The verifier's ephemeral encryption key (the client_metadata.jwks entry).
//! let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
//! let point = secret.public_key().to_encoded_point(false);
//! let jwk = serde_json::json!({
//!     "kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES", "kid": "1",
//!     "x": b64u(&point.as_bytes()[1..33]),
//!     "y": b64u(&point.as_bytes()[33..65]),
//! });
//! let metadata = serde_json::json!({"jwks": {"keys": [jwk]},
//!     "encrypted_response_enc_values_supported": ["A128GCM"]});
//! let jwe = encrypt_response(&serde_json::json!({"vp_token": {}}), &metadata)?;
//! assert_eq!(jwe.split('.').count(), 5);
//! # Ok(())
//! # }
//! ```

use serde_json::Value;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;

fn b64u(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The encryption failure (the §8.5 `invalid_request` family - the
/// wallet MAY fall back to the unencrypted §8.2 post when it cannot
/// encrypt; the holder chooses per-spec).
#[derive(Debug)]
pub struct EncryptionError(pub String);

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "response encryption: {}", self.0)
    }
}

impl std::error::Error for EncryptionError {}

/// The recipient selection (§8.3): the verifier's `use: enc` JWK
/// from `client_metadata.jwks` - the ECDH-ES `alg` JWK. The FIRST
/// matching key wins (§8.3: the wallet selects on kty/use/alg).
///
/// # Errors
/// `EncryptionError` - no usable encryption key in the metadata.
fn recipient_jwk(client_metadata: &Value) -> Result<Value, EncryptionError> {
    let keys = client_metadata
        .pointer("/jwks/keys")
        .and_then(|k| k.as_array())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| EncryptionError("the client_metadata carries no jwks keys".into()))?;
    for key in keys {
        // The `use` filter: an EXPLICIT use=sig disqualifies the key
        // (RFC 7517 4.2); an ABSENT use = unrestricted (RFC 7517
        // 4.3) - the verifier's metadata MAY omit it (the suite's
        // WithoutUseEnc mint variant does exactly that).
        let use_ = key.get("use").and_then(|v| v.as_str()).unwrap_or("");
        if use_ == "sig" {
            continue;
        }
        let kty = key.get("kty").and_then(|v| v.as_str()).unwrap_or("");
        let crv = key.get("crv").and_then(|v| v.as_str()).unwrap_or("");
        let alg = key.get("alg").and_then(|v| v.as_str()).unwrap_or("ECDH-ES");
        if kty == "EC" && crv == "P-256" && alg == "ECDH-ES" {
            return Ok(key.clone());
        }
    }
    Err(EncryptionError(
        "no EC P-256 ECDH-ES encryption key in the verifier metadata".into(),
    ))
}

/// The `enc` selection (§8.3): `encrypted_response_enc_values_supported`'s
/// first supported value; the default `A128GCM` (§5.1).
fn select_enc(client_metadata: &Value) -> &'static str {
    let supported = client_metadata
        .get("encrypted_response_enc_values_supported")
        .and_then(|v| v.as_array());
    if let Some(values) = supported {
        for v in values {
            match v.as_str().unwrap_or("") {
                "A128GCM" => return "A128GCM",
                "A256GCM" => return "A256GCM",
                _ => {}
            }
        }
    }
    "A128GCM"
}

/// The ECDH-ES ConcatKDF (RFC 7518 §4.6.2) - the key derivation for
/// direct key agreement. The platform's form: the SHA-256 KDF over
/// the shared secret, the algorithm-id, the apu/apv, and the key
/// length. Mirrored to the byte (the round-trip against the
/// platform's `decrypt_credential_request` demands it).
fn concat_cek(
    shared: &[u8],
    enc: &str,
    apu: &[u8],
    apv: &[u8],
    key_len: usize,
) -> Vec<u8> {
    use sha2::Digest;
    let algorithm_id = enc.as_bytes().to_vec();
    // RFC 7518 §4.6.1: SuppPubInfo carries the KEY LENGTH IN BITS
    // (uint32) - bytes here breaks every nimbus-side decrypt (the
    // conformance suite's DecryptResponse lands Tag mismatch).
    let mut info = Vec::new();
    info.extend_from_slice(&(algorithm_id.len() as u32).to_be_bytes());
    info.extend_from_slice(&algorithm_id);
    info.extend_from_slice(&(apu.len() as u32).to_be_bytes());
    info.extend_from_slice(apu);
    info.extend_from_slice(&(apv.len() as u32).to_be_bytes());
    info.extend_from_slice(apv);
    info.extend_from_slice(&((key_len * 8) as u32).to_be_bytes());
    let mut out = Vec::new();
    // RFC 7518 §4.6.1: H(counter || Z || OtherInfo) - the 4-byte
    // iteration counter comes FIRST, then the shared secret, then
    // OtherInfo (the platform's earlier shared||counter form broke
    // every nimbus-side decrypt with Tag mismatch).
    let mut counter: u32 = 1;
    while out.len() < key_len {
        let mut block = Vec::with_capacity(shared.len() + info.len() + 4);
        block.extend_from_slice(&counter.to_be_bytes());
        block.extend_from_slice(shared);
        block.extend_from_slice(&info);
        let digest = sha2::Sha256::digest(&block);
        out.extend_from_slice(&digest);
        counter += 1;
    }
    out.truncate(key_len);
    out
}

/// The EC P-256 recipient JWK → the public key (SEC1 uncompressed).
fn jwk_to_p256(jwk: &Value) -> Result<p256::PublicKey, EncryptionError> {
    use base64::Engine;
    let x = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
        EncryptionError("the recipient JWK carries no x".into())
    })?;
    let y = jwk.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
        EncryptionError("the recipient JWK carries no y".into())
    })?;
    let xb = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| EncryptionError(format!("x decode: {e}")))?;
    let yb = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|e| EncryptionError(format!("y decode: {e}")))?;
    let mut point = vec![0x04u8];
    point.extend_from_slice(&xb);
    point.extend_from_slice(&yb);
    p256::PublicKey::from_sec1_bytes(&point)
        .map_err(|e| EncryptionError(format!("the public point: {e}")))
}

/// Build the encrypted Authorization Response (§8.3): a compact JWE
/// (ECDH-ES + A128GCM/A256GCM) whose payload is the response
/// parameters JSON. The verifier decrypts with its ephemeral private
/// key - the response never rides the front channel in the clear.
///
/// # Errors
/// `EncryptionError` - no usable recipient key or an AES-GCM failure.
pub fn encrypt_response(
    response_json: &Value,
    client_metadata: &Value,
) -> Result<String, EncryptionError> {
    encrypt_response_alg(response_json, client_metadata, "ECDH-ES")
}

/// The [`encrypt_response`] entry with an explicit `alg` (the
/// ECDH-ES arm; the direct form).
///
/// # Errors
/// `EncryptionError` - as the parent.
pub fn encrypt_response_alg(
    response_json: &Value,
    client_metadata: &Value,
    alg: &str,
) -> Result<String, EncryptionError> {
    if alg != "ECDH-ES" {
        return Err(EncryptionError(format!(
            "the response encryption alg {alg:?} is unsupported (ECDH-ES only)"
        )));
    }
    let recipient = recipient_jwk(client_metadata)?;
    let enc = select_enc(client_metadata);
    let public = jwk_to_p256(&recipient)?;
    // The recipient's kid rides the protected header (RFC 7516 4.1.4;
    // the verifier's DecryptResponse selects THIS key by kid).
    let recipient_kid = recipient.get("kid").and_then(|v| v.as_str()).map(str::to_owned);
    // The ephemeral key pair (the wallet's side of the agreement).
    let epk_secret =
        p256::elliptic_curve::ecdh::EphemeralSecret::<p256::NistP256>::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        );
    let epk_point = epk_secret.public_key().to_encoded_point(false);
    let epk = serde_json::json!({
        "kty": "EC", "crv": "P-256",
        "x": b64u(&epk_point.as_ref()[1..33]),
        "y": b64u(&epk_point.as_ref()[33..65]),
    });
    // Party descriptors: absent → zero-length (the platform's form).
    let apu: Vec<u8> = Vec::new();
    let apv: Vec<u8> = Vec::new();
    let mut protected = serde_json::json!({
        "alg": alg,
        "enc": enc,
        "epk": epk,
        "apu": b64u(&apu),
        "apv": b64u(&apv),
    });
    if let Some(kid) = recipient_kid {
        protected["kid"] = serde_json::json!(kid);
    }
    let protected_json = protected.to_string();
    let protected_b64 = b64u(protected_json.as_bytes());
    // ECDH: the shared secret derives the CEK via the ConcatKDF.
    let shared = epk_secret.diffie_hellman(&public);
    let key_len = if enc == "A256GCM" { 32 } else { 16 };
    let cek = concat_cek(shared.raw_secret_bytes(), enc, &apu, &apv, key_len);
    // The AES-GCM content encryption (RFC 7518 §5.2/§5.3): the IV is
    // 96-bit random; the AAD is the ASCII(protected header). The
    // platform's form: OsRng via the elliptic-curve rand_core
    // facade (the u8 stream).
    let iv: Vec<u8> = {
        use p256::elliptic_curve::rand_core::RngCore as _;
        let mut bytes = [0u8; 12];
        p256::elliptic_curve::rand_core::OsRng.fill_bytes(&mut bytes);
        bytes.to_vec()
    };
    let plaintext = response_json.to_string();
    let (ciphertext, tag) = aes_gcm_seal(&cek, &iv, plaintext.as_bytes(), protected_b64.as_bytes())
        .map_err(|e| EncryptionError(format!("the AES-GCM seal: {e}")))?;
    // The compact five-part form: header, EMPTY encrypted key (the
    // direct agreement), IV, ciphertext, tag.
    Ok(format!(
        "{}..{}.{}.{}",
        protected_b64,
        b64u(&iv),
        b64u(&ciphertext),
        b64u(&tag),
    ))
}

/// The AES-GCM seal (the platform's `aes-gcm` crate arm) - the
/// ciphertext + the trailing tag split.
fn aes_gcm_seal(
    cek: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload, array::Array};
    use aes_gcm::{Aes128Gcm, Aes256Gcm};
    // The 96-bit IV (RFC 7518 §5.2) as Array<[u8; 12]> (the size the
    // cipher infers from its own NonceSize; the tested form -
    // aes-gcm 0.11's own aes128gcm/aes256gcm tests). Fail-closed on a
    // wrong length (the callers always carry exactly 12 bytes).
    if iv.len() != 12 {
        return Err(format!("the IV length {} is not the 96-bit form", iv.len()));
    }
    let iv: [u8; 12] = iv.try_into().unwrap();
    let nonce = Array(iv);
    let sealed: Vec<u8> = match cek.len() {
        16 => Aes128Gcm::new_from_slice(cek)
            .map_err(|e| format!("the A128GCM key: {e}"))?
            .encrypt(&nonce, Payload { msg: plaintext, aad }),
        32 => Aes256Gcm::new_from_slice(cek)
            .map_err(|e| format!("the A256GCM key: {e}"))?
            .encrypt(&nonce, Payload { msg: plaintext, aad }),
        n => return Err(format!("the CEK length {n} matches no AES-GCM form")),
    }
    .map_err(|e| format!("the AES-GCM encryption: {e}"))?;
    let tag_at = sealed.len().saturating_sub(16);
    let (ct, tag) = sealed.split_at(tag_at);
    Ok((ct.to_vec(), tag.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;

    fn recipient_metadata(public: &p256::PublicKey) -> Value {
        let point = public.to_encoded_point(false);
        serde_json::json!({
            "jwks": {"keys": [serde_json::json!({
                "kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES", "kid": "1",
                "x": b64u(&point.as_bytes()[1..33]),
                "y": b64u(&point.as_bytes()[33..65]),
            })]},
            "encrypted_response_enc_values_supported": ["A128GCM"],
        })
    }

    #[test]
    fn jwe_round_trip_against_the_platform_form() {
        // The wallet mint -> a local decrypt mirroring the platform's
        // `decrypt_credential_request` (the ECDH-ES recipient side).
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let metadata = recipient_metadata(&secret.public_key());
        let payload = serde_json::json!({"vp_token": {"mdl": ["ompp"]}, "state": "s"});
        let jwe = encrypt_response(&payload, &metadata).unwrap();
        assert_eq!(jwe.split('.').count(), 5);
        // The header parses + the enc selection honors the metadata.
        let header: Value = {
            use base64::Engine;
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwe.split('.').next().unwrap())
                .unwrap();
            serde_json::from_slice(&raw).unwrap()
        };
        assert_eq!(header["alg"], "ECDH-ES");
        assert_eq!(header["enc"], "A128GCM");
        // The full decrypt round trip (the recipient side).
        let decrypted = decrypt_response(&jwe, &secret).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn a256gcm_selection() {
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let mut metadata = recipient_metadata(&secret.public_key());
        metadata["encrypted_response_enc_values_supported"] =
            serde_json::json!(["A256GCM"]);
        let jwe = encrypt_response(&serde_json::json!({"vp_token": {}}), &metadata).unwrap();
        let header: Value = {
            use base64::Engine;
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwe.split('.').next().unwrap())
                .unwrap();
            serde_json::from_slice(&raw).unwrap()
        };
        assert_eq!(header["enc"], "A256GCM");
        assert!(decrypt_response(&jwe, &secret).is_ok());
    }

    #[test]
    fn no_recipient_key_rejects() {
        let metadata = serde_json::json!({"jwks": {"keys": []}});
        assert!(encrypt_response(&serde_json::json!({}), &metadata).is_err());
    }

    // ── The test-only recipient side (mirrors the platform decrypt) ──

    /// Decrypt a compact ECDH-ES JWE with the recipient's private key
    /// (the platform's `decrypt_credential_request` form - the
    /// round-trip check).
    fn decrypt_response(jwe: &str, secret: &p256::SecretKey) -> Result<Value, String> {
        use base64::Engine;
        let b64d = |s: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .map_err(|e| e.to_string())
        };
        let parts: Vec<&str> = jwe.split('.').collect();
        let header: Value = serde_json::from_slice(&b64d(parts[0])?).map_err(|e| e.to_string())?;
        let epk = header.pointer("/epk").ok_or("no epk")?;
        let epk_public = {
            let mut point = vec![0x04u8];
            point.extend_from_slice(&b64d(epk.get("x").and_then(|v| v.as_str()).unwrap())?);
            point.extend_from_slice(&b64d(epk.get("y").and_then(|v| v.as_str()).unwrap())?);
            p256::PublicKey::from_sec1_bytes(&point).map_err(|e| e.to_string())?
        };
        let shared = p256::elliptic_curve::ecdh::diffie_hellman(
            secret.to_nonzero_scalar(),
            epk_public.as_affine(),
        );
        let enc = header.get("enc").and_then(|v| v.as_str()).unwrap_or("A128GCM");
        let key_len = if enc == "A256GCM" { 32 } else { 16 };
        let cek = concat_cek(shared.raw_secret_bytes(), enc, &[], &[], key_len);
        let iv = b64d(parts[2])?;
        let ct = b64d(parts[3])?;
        let tag = b64d(parts[4])?;
        let mut sealed = ct;
        sealed.extend_from_slice(&tag);
        let plaintext = aes_gcm_open(&cek, &iv, &sealed, parts[0].as_bytes())?;
        serde_json::from_slice(&plaintext).map_err(|e| e.to_string())
    }

    fn aes_gcm_open(cek: &[u8], iv: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        use aes_gcm::aead::{Aead, KeyInit, Payload, array::Array};
        use aes_gcm::{Aes128Gcm, Aes256Gcm};
        if iv.len() != 12 {
            return Err(format!("the IV length {} is not the 96-bit form", iv.len()));
        }
        let iv: [u8; 12] = iv.try_into().unwrap();
        let nonce = Array(iv);
        let plaintext: Vec<u8> = match cek.len() {
            16 => Aes128Gcm::new_from_slice(cek)
                .map_err(|e| e.to_string())?
                .decrypt(&nonce, Payload { msg: sealed, aad }),
            32 => Aes256Gcm::new_from_slice(cek)
                .map_err(|e| e.to_string())?
                .decrypt(&nonce, Payload { msg: sealed, aad }),
            n => return Err(format!("cek len {n}")),
        }
        .map_err(|e| format!("open: {e}"))?;
        Ok(plaintext)
    }
}
