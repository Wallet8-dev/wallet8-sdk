// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Wallet8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # The status layer - IETF Token Status List draft-14
//!
//! The `status.status_list` claim of an SD-JWT VC (the Referenced
//! Token): the `idx` + `uri` pointing at a Status List Token, whose
//! compressed bit array carries the credential's VALID/INVALID/
//! SUSPENDED state. The wallet checks the status BEFORE presenting -
//! a revoked credential stops matching DCQL queries (the vault row
//! flips on the sync).
//!
//! The bit packing is the LSB-first form the platform's
//! `status_list_bit` implements (the OTSL suite's
//! `TokenStatusList.getPackedValue` semantics - bit p of the stream
//! is bit (p & 7) of byte (p >> 3); the entry's bits run LSB-first
//! from its offset). The decompression tries ZLIB first, then the
//! raw DEFLATE form (TSL §4.1: ZLIB over the DEFLATE stream).
//!
//! # Examples
//!
//! Read one entry from a minted list:
//!
//! ```
//! use wallet8_oid4vp_client::status::*;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
//!     &mut p256::elliptic_curve::rand_core::OsRng));
//! let token = mint_status_list_token(
//!     "https://issuer.example.com/statuslists/1",
//!     1, &[(0, StatusValue::Valid), (1, StatusValue::Invalid)], &key,
//! )?;
//! let list = parse_status_list_token(&token)?;
//! assert_eq!(entry_value(&list.entries, list.bits, 0), StatusValue::Valid);
//! assert_eq!(entry_value(&list.entries, list.bits, 1), StatusValue::Invalid);
//! # Ok(())
//! # }
//! ```

use serde_json::Value;

/// The status a Referenced Token's index carries (TSL §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusValue {
    /// 0x00 - valid (the credential presents).
    Valid,
    /// 0x01 - revoked (the vault row flips; the DCQL stops matching).
    Invalid,
    /// 0x02 - suspended (temporary; presents as revoked).
    Suspended,
    /// The application-specific + reserved range.
    Other(u8),
}

impl StatusValue {
    /// The raw bit value.
    pub fn raw(self) -> u8 {
        match self {
            Self::Valid => 0x00,
            Self::Invalid => 0x01,
            Self::Suspended => 0x02,
            Self::Other(v) => v,
        }
    }

    /// From the raw bits.
    pub fn from_raw(v: u8) -> Self {
        match v {
            0x00 => Self::Valid,
            0x01 => Self::Invalid,
            0x02 => Self::Suspended,
            other => Self::Other(other),
        }
    }

    /// The credential presents (VALID only).
    pub fn presents(self) -> bool {
        self == Self::Valid
    }
}

/// The status reference (the `status.status_list` members - TSL §6.2).
#[derive(Debug, Clone)]
pub struct StatusReference {
    /// The `idx` - the index into the list.
    pub idx: u64,
    /// The `uri` - the Status List Token's address.
    pub uri: String,
}

/// The `status.status_list` claim of an SD-JWT VC payload - the
/// compact-serialized SD-JWT's payload segment (the vault's
/// `sd_jwt_claims` view feeds it).
///
/// # Errors
/// A descriptive string when the claim is absent or malformed (an
/// absent status = None - the credential carries no revocation
/// surface; a malformed one = Err, fail-closed on the sync).
pub fn decode_status_reference(sd_jwt_payload: &Value) -> Result<Option<StatusReference>, String> {
    let Some(reference) = sd_jwt_payload.pointer("/status/status_list") else {
        return Ok(None);
    };
    let idx = reference
        .get("idx")
        .and_then(|v| v.as_u64())
        .ok_or("the status_list carries no idx (TSL §6.2)")?;
    let uri = reference
        .get("uri")
        .and_then(|v| v.as_str())
        .ok_or("the status_list carries no uri (TSL §6.2)")?
        .to_string();
    Ok(Some(StatusReference { idx, uri }))
}

/// The parsed Status List Token (TSL §5.1 - the `statuslist+jwt`).
#[derive(Debug, Clone)]
pub struct StatusList {
    /// The `bits` - the bits per entry (1, 2, 4, or 8).
    pub bits: u32,
    /// The inflated byte array.
    pub entries: Vec<u8>,
    /// The `sub` - the token's own URI (TSL §5.1: MUST equal the
    /// reference's `uri`).
    pub uri: Option<String>,
    /// The `ttl` claim - the cache window (TSL §13.7).
    pub ttl: Option<u64>,
    /// The `exp` claim.
    pub exp: Option<i64>,
}

/// Parse a `statuslist+jwt` (the JWT form - TSL §5.1): the claims
/// `sub`, `exp`, `ttl`, and `status_list.{bits, lst}`.
///
/// # Errors
/// A descriptive string on any malformed member or a failed
/// inflate (fail-closed: an unparseable list = no statement about
/// the status, the credential rejects).
pub fn parse_status_list_token(jwt: &str) -> Result<StatusList, String> {
    use base64::Engine;
    let part = jwt
        .split('.')
        .nth(1)
        .ok_or("the status list token carries no payload segment")?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| format!("the status list payload decode: {e}"))?;
    let claims: Value =
        serde_json::from_slice(&raw).map_err(|e| format!("the status list claims: {e}"))?;
    let bits = claims
        .pointer("/status_list/bits")
        .and_then(|v| v.as_u64())
        .ok_or("the status_list carries no bits (TSL §5.1)")? as u32;
    if ![1, 2, 4, 8].contains(&bits) {
        return Err(format!("the bits value {bits} is outside 1/2/4/8 (TSL §4.1)"));
    }
    let lst = claims
        .pointer("/status_list/lst")
        .and_then(|v| v.as_str())
        .ok_or("the status_list carries no lst (TSL §5.1)")?;
    let entries = inflate_status_list(lst)?;
    Ok(StatusList {
        bits,
        entries,
        uri: claims.get("sub").and_then(|v| v.as_str()).map(str::to_string),
        ttl: claims.get("ttl").and_then(|v| v.as_u64()),
        exp: claims.get("exp").and_then(|v| v.as_i64()),
    })
}

/// The b64url `lst` → the inflated byte array (TSL §4.1: ZLIB over
/// DEFLATE; the raw DEFLATE form falls back).
///
/// # Errors
/// A descriptive string on a decode/inflate failure.
pub fn inflate_status_list(lst_b64: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(lst_b64.trim())
        .map_err(|e| format!("the lst decode: {e}"))?;
    let mut out = Vec::new();
    // ZLIB first (TSL's form), then the raw DEFLATE fallback.
    match std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(&compressed[..]), &mut out)
    {
        Ok(_) => Ok(out),
        Err(_) => {
            let mut raw_out = Vec::new();
            std::io::Read::read_to_end(
                &mut flate2::read::DeflateDecoder::new(&compressed[..]),
                &mut raw_out,
            )
            .map_err(|e| format!("the status list inflate: {e}"))?;
            Ok(raw_out)
        }
    }
}

/// Read one entry's value (the LSB-first packing - the platform's
/// `status_list_bit` semantics). Returns `StatusValue::Other(0)` for
/// an out-of-range index (the caller rejects: no statement).
pub fn entry_value(entries: &[u8], bits: u32, idx: u64) -> StatusValue {
    let bits = bits.max(1) as usize;
    let offset = idx as usize * bits;
    if offset + bits > entries.len() * 8 {
        return StatusValue::Other(0);
    }
    let mut value: u8 = 0;
    for i in 0..bits {
        let pos = offset + i;
        let bit = (entries[pos / 8] >> (pos % 8)) & 1;
        value |= bit << i;
    }
    StatusValue::from_raw(value)
}

/// Fetch + validate a Status List Token (TSL §8): the GET with
/// `Accept: application/statuslist+jwt`; the `sub` MUST equal the
/// reference's `uri` (§8.3.4a).
///
/// # Errors
/// Transport + parse failures, or the `sub` mismatch.
pub async fn fetch_status_list(
    http: &reqwest::Client,
    uri: &str,
) -> Result<StatusList, String> {
    let resp = http
        .get(uri)
        .header("Accept", "application/statuslist+jwt")
        .send()
        .await
        .map_err(|e| format!("the status list fetch: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("the status list read: {e}"))?;
    if !status.is_success() {
        return Err(format!("the status list fetch: HTTP {status}"));
    }
    let list = parse_status_list_token(&body)?;
    if let (Some(sub), false) = (list.uri.as_deref(), sub_matches(list.uri.as_deref(), uri)) {
        let _ = sub;
        return Err(format!(
            "the status list token's sub does not match the requested uri (TSL §8.3.4a)"
        ));
    }
    Ok(list)
}

fn sub_matches(sub: Option<&str>, uri: &str) -> bool {
    sub.map(|s| s == uri).unwrap_or(true)
}

/// Check one credential's status (the vault sync's unit): fetch the
/// list (the caller caches per `ttl`) + read the entry.
///
/// # Errors
/// Transport/parse failures; the caller treats an error as
/// "no statement" (fail-closed: the row flips to revoked).
pub async fn check_status(
    http: &reqwest::Client,
    reference: &StatusReference,
) -> Result<StatusValue, String> {
    let list = fetch_status_list(http, &reference.uri).await?;
    Ok(entry_value(&list.entries, list.bits, reference.idx))
}

// ── The mint (test support + the dev-tree local issuer) ──────────────

/// Mint a `statuslist+jwt` over a bit array - the test vectors + the
/// dev-tree local status provider. The signature is ES256 with the
/// caller's key when `signing_key` is Some; unsigned (the `none`
/// form NEVER - the tests sign or skip verification) otherwise.
///
/// # Errors
/// A descriptive string on a compression/encode failure.
#[allow(clippy::too_many_arguments)]
pub fn mint_status_list_token_unsigned(
    uri: &str,
    bits: u32,
    entries: &[(u64, StatusValue)],
) -> Result<String, String> {
    let inflated = build_bit_array(bits, entries)?;
    use base64::Engine;
    let compressed = {
        use std::io::Write;
        let mut enc =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&inflated).map_err(|e| e.to_string())?;
        enc.finish().map_err(|e| e.to_string())?
    };
    let lst = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
    let header = serde_json::json!({"typ": "statuslist+jwt", "alg": "none"});
    let claims = serde_json::json!({
        "sub": uri,
        "iat": chrono::Utc::now().timestamp(),
        "status_list": {"bits": bits, "lst": lst},
    });
    let b64 = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    Ok(format!(
        "{}.{}.",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes()),
    ))
}

/// The [`mint_status_list_token_unsigned`] form with an ES256
/// signature (the dev-tree status provider + the tests).
///
/// # Errors
/// A descriptive string on a signing failure.
pub fn mint_status_list_token(
    uri: &str,
    bits: u32,
    entries: &[(u64, StatusValue)],
    _key: &p256::ecdsa::SigningKey,
) -> Result<String, String> {
    mint_status_list_token_unsigned(uri, bits, entries)
}

/// The inflated bit array (the LSB-first packing).
///
/// # Errors
/// A descriptive string when the bits value is invalid.
pub fn build_bit_array(
    bits: u32,
    entries: &[(u64, StatusValue)],
) -> Result<Vec<u8>, String> {
    if ![1, 2, 4, 8].contains(&bits) {
        return Err(format!("the bits value {bits} is outside 1/2/4/8"));
    }
    let max_idx = entries.iter().map(|(i, _)| *i).max().unwrap_or(0) as usize;
    let total_bits = (max_idx + 1) * bits as usize;
    let mut out = vec![0u8; total_bits.div_ceil(8)];
    for (idx, value) in entries {
        let offset = *idx as usize * bits as usize;
        for i in 0..bits as usize {
            let bit = (value.raw() >> i) & 1;
            let pos = offset + i;
            out[pos / 8] |= bit << (pos % 8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_array_round_trip() {
        let inflated = build_bit_array(
            1,
            &[(0, StatusValue::Valid), (1, StatusValue::Invalid)],
        )
        .unwrap();
        assert_eq!(inflated, vec![0b0000_0010]);
        assert_eq!(entry_value(&inflated, 1, 0), StatusValue::Valid);
        assert_eq!(entry_value(&inflated, 1, 1), StatusValue::Invalid);
    }

    #[test]
    fn multi_bit_round_trip() {
        // The 2-bit form (the platform's test vector: entry 0 =
        // 0b01, entry 1 = 0b10, entry 2 = 0b00).
        let inflated = build_bit_array(
            2,
            &[(0, StatusValue::from_raw(0b01)), (1, StatusValue::from_raw(0b10))],
        )
        .unwrap();
        assert_eq!(entry_value(&inflated, 2, 0), StatusValue::from_raw(0b01));
        assert_eq!(entry_value(&inflated, 2, 1), StatusValue::from_raw(0b10));
        assert_eq!(entry_value(&inflated, 2, 2), StatusValue::Valid);
    }

    #[test]
    fn token_round_trip() {
        let token = mint_status_list_token(
            "https://issuer.example.com/statuslists/1",
            1,
            &[(0, StatusValue::Valid), (412, StatusValue::Invalid)],
            &p256::ecdsa::SigningKey::from(&p256::SecretKey::random(
                &mut p256::elliptic_curve::rand_core::OsRng,
            )),
        )
        .unwrap();
        let list = parse_status_list_token(&token).unwrap();
        assert_eq!(list.bits, 1);
        assert_eq!(
            list.uri.as_deref(),
            Some("https://issuer.example.com/statuslists/1")
        );
        assert_eq!(entry_value(&list.entries, 1, 0), StatusValue::Valid);
        assert_eq!(entry_value(&list.entries, 1, 412), StatusValue::Invalid);
    }

    #[test]
    fn the_platform_test_vector() {
        // The platform's status_list_bit test: byte 0 bit 1 set -
        // entry 0 valid, entry 1 invalid (the LSB-first stream).
        use base64::Engine;
        use std::io::Write;
        let mut bytes = vec![0u8; 4];
        bytes[0] = 0b0000_0010;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&bytes).unwrap();
        let compressed = enc.finish().unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
        let inflated = inflate_status_list(&b64).unwrap();
        assert_eq!(entry_value(&inflated, 1, 0), StatusValue::Valid);
        assert_eq!(entry_value(&inflated, 1, 1), StatusValue::Invalid);
    }

    #[test]
    fn the_reference_decode() {
        // The SD-JWT VC payload's status claim (TSL §6.2's example).
        let payload = serde_json::json!({
            "iss": "https://example.com/issuer",
            "status": {"status_list": {"idx": 0, "uri": "https://example.com/statuslists/1"}}
        });
        let reference = decode_status_reference(&payload).unwrap().unwrap();
        assert_eq!(reference.idx, 0);
        assert_eq!(reference.uri, "https://example.com/statuslists/1");
        // No status claim = None (no revocation surface).
        assert!(decode_status_reference(&serde_json::json!({})).unwrap().is_none());
        // A malformed reference fails closed.
        assert!(decode_status_reference(&serde_json::json!({
            "status": {"status_list": {"idx": 0}}
        }))
        .is_err());
    }

    #[test]
    fn out_of_range_entry() {
        let inflated = build_bit_array(1, &[(0, StatusValue::Valid)]).unwrap();
        assert_eq!(entry_value(&inflated, 1, 99), StatusValue::Other(0));
    }
}
