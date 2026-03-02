//! ISO 18013-5 mDoc credential format (`mso_mdoc`).
//!
//! Constructs CBOR-encoded mDoc credentials with COSE_Sign1 issuer
//! authentication, replacing the previous JSON placeholder implementation.
//!
//! Structure: IssuerSigned { nameSpaces, issuerAuth(COSE_Sign1(MSO)) }

use ciborium::Value as CborValue;
use coset::{
    iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable,
};
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::types::{CredentialClaims, IssuerKey, SignedCredential};

// ── CBOR tag number for `encoded-cbor` (tag 24, RFC 8949 §3.4.5.1) ──
// Used for tagged CBOR byte strings inside IssuerSignedItem and issuerAuth.
const CBOR_TAG_ENCODED_CBOR: u64 = 24;

/// Sign an mDoc credential.
///
/// Produces a CBOR-encoded `IssuerSigned` structure containing:
///   - `nameSpaces`: `IssuerSignedItem` entries per namespace
///   - `issuerAuth`: COSE_Sign1(MobileSecurityObject)
///
/// The resulting credential is base64url-encoded for transport.
pub fn sign_mdoc(
    issuer_key: &IssuerKey,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    let jwk: ssi::jwk::JWK = serde_json::from_str(&issuer_key.jwk_json)
        .map_err(|e| Oid4vciError::KeyError(format!("Invalid issuer JWK: {}", e)))?;

    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();

    // Determine docType and namespace
    let doc_type = claims
        .mdoc_doctype
        .as_deref()
        .unwrap_or("org.iso.18013.5.1.mDL");
    let namespace = claims
        .mdoc_namespace
        .as_deref()
        .unwrap_or("org.iso.18013.5.1");

    // 1. Build IssuerSignedItems and collect digests for the MSO
    let mut issuer_signed_items = Vec::new();
    let mut value_digests = Vec::new(); // (digest_id, sha256_digest)

    for (i, (claim_name, claim_value)) in claims.claims.iter().enumerate() {
        let digest_id = i as u64;

        // Generate 32 bytes of random salt
        let mut salt = [0u8; 32];
        rand::thread_rng().fill(&mut salt);

        // Build IssuerSignedItem as a CBOR map
        let item = build_issuer_signed_item(digest_id, &salt, claim_name, claim_value)?;

        // CBOR-encode the item and compute its digest
        let item_bytes = cbor_encode(&item)?;
        let digest = Sha256::digest(&item_bytes).to_vec();

        value_digests.push((digest_id, digest));
        issuer_signed_items.push(CborValue::Tag(CBOR_TAG_ENCODED_CBOR, Box::new(CborValue::Bytes(item_bytes))));
    }

    // 2. Build the MobileSecurityObject
    let validity_days = claims.expiration_seconds.map(|s| s / 86400).unwrap_or(365);
    let valid_until = now + chrono::Duration::days(validity_days);

    let mso = build_mobile_security_object(
        doc_type,
        namespace,
        &value_digests,
        &now,
        &valid_until,
    )?;

    let mso_bytes = cbor_encode(&mso)?;

    // 3. Sign the MSO with COSE_Sign1
    let issuer_auth = sign_cose_sign1(&mso_bytes, &jwk, issuer_key)?;

    // 4. Assemble IssuerSigned = { nameSpaces, issuerAuth }
    let name_spaces = CborValue::Map(vec![(
        CborValue::Text(namespace.to_string()),
        CborValue::Array(issuer_signed_items),
    )]);

    let issuer_signed = CborValue::Map(vec![
        (CborValue::Text("nameSpaces".into()), name_spaces),
        (
            CborValue::Text("issuerAuth".into()),
            CborValue::Bytes(issuer_auth),
        ),
    ]);

    let result_bytes = cbor_encode(&issuer_signed)?;
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &result_bytes,
    );

    Ok(SignedCredential::MsoMdoc {
        issuer_signed_b64: encoded,
        credential_id,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────

/// Build a single `IssuerSignedItem` (CBOR map) per ISO 18013-5 §9.1.2.4.
///
/// ```text
/// IssuerSignedItem = {
///   "digestID"     : uint,
///   "random"       : bstr,
///   "elementIdentifier" : tstr,
///   "elementValue" : any,
/// }
/// ```
fn build_issuer_signed_item(
    digest_id: u64,
    salt: &[u8],
    element_identifier: &str,
    element_value: &serde_json::Value,
) -> Oid4vciResult<CborValue> {
    let cbor_value = json_to_cbor(element_value)?;

    Ok(CborValue::Map(vec![
        (
            CborValue::Text("digestID".into()),
            CborValue::Integer(digest_id.into()),
        ),
        (
            CborValue::Text("random".into()),
            CborValue::Bytes(salt.to_vec()),
        ),
        (
            CborValue::Text("elementIdentifier".into()),
            CborValue::Text(element_identifier.into()),
        ),
        (
            CborValue::Text("elementValue".into()),
            cbor_value,
        ),
    ]))
}

/// Build MobileSecurityObject (MSO) per ISO 18013-5 §9.1.2.4.
///
/// ```text
/// MobileSecurityObject = {
///   "version"         : tstr,
///   "digestAlgorithm" : tstr,
///   "valueDigests"    : { tstr => { uint => bstr } },
///   "docType"         : tstr,
///   "validityInfo"    : ValidityInfo,
/// }
/// ```
fn build_mobile_security_object(
    doc_type: &str,
    namespace: &str,
    value_digests: &[(u64, Vec<u8>)],
    signed_at: &chrono::DateTime<chrono::Utc>,
    valid_until: &chrono::DateTime<chrono::Utc>,
) -> Oid4vciResult<CborValue> {
    // Build the per-namespace digest map: { digestID => digest_bytes }
    let ns_digests = CborValue::Map(
        value_digests
            .iter()
            .map(|(id, digest)| {
                (
                    CborValue::Integer((*id).into()),
                    CborValue::Bytes(digest.clone()),
                )
            })
            .collect(),
    );

    let all_digests = CborValue::Map(vec![(CborValue::Text(namespace.into()), ns_digests)]);

    // ValidityInfo
    let validity_info = CborValue::Map(vec![
        (
            CborValue::Text("signed".into()),
            cbor_date_time(signed_at),
        ),
        (
            CborValue::Text("validFrom".into()),
            cbor_date_time(signed_at),
        ),
        (
            CborValue::Text("validUntil".into()),
            cbor_date_time(valid_until),
        ),
    ]);

    Ok(CborValue::Map(vec![
        (
            CborValue::Text("version".into()),
            CborValue::Text("1.0".into()),
        ),
        (
            CborValue::Text("digestAlgorithm".into()),
            CborValue::Text("SHA-256".into()),
        ),
        (
            CborValue::Text("valueDigests".into()),
            all_digests,
        ),
        (
            CborValue::Text("docType".into()),
            CborValue::Text(doc_type.into()),
        ),
        (
            CborValue::Text("validityInfo".into()),
            validity_info,
        ),
    ]))
}

/// Sign a payload with COSE_Sign1 using the issuer's JWK.
///
/// Returns the serialized COSE_Sign1 bytes.
fn sign_cose_sign1(
    payload: &[u8],
    jwk: &ssi::jwk::JWK,
    issuer_key: &IssuerKey,
) -> Oid4vciResult<Vec<u8>> {
    use ssi::crypto::{AlgorithmInstance, SecretKey};
    use ssi::jwk::Params;

    let alg = match issuer_key.algorithm {
        crate::types::SigningAlgorithm::ES256 => iana::Algorithm::ES256,
        crate::types::SigningAlgorithm::EdDSA => iana::Algorithm::EdDSA,
        crate::types::SigningAlgorithm::ES256K => {
            return Err(Oid4vciError::MdocError(
                "ES256K is not supported for mDoc COSE signing".into(),
            ));
        }
        crate::types::SigningAlgorithm::ES384 => iana::Algorithm::ES384,
        crate::types::SigningAlgorithm::RS256 => iana::Algorithm::PS256,
    };

    // Build protected header
    let protected = HeaderBuilder::new()
        .algorithm(alg)
        .build();

    // Build the COSE_Sign1 without signature to get the TBS data
    let cose_for_tbs = CoseSign1Builder::new()
        .protected(protected.clone())
        .payload(payload.to_vec())
        .build();
    let tbs = cose_for_tbs.tbs_data(&[]);

    // Extract secret key from JWK (same pattern as jwt_vc.rs)
    let secret_key = match &jwk.params {
        Params::OKP(params) => {
            let d = params
                .private_key
                .as_ref()
                .ok_or_else(|| Oid4vciError::KeyError("Missing Ed25519 private key".into()))?;
            SecretKey::new_ed25519(&d.0)
                .map_err(|e| Oid4vciError::KeyError(format!("Invalid Ed25519 key: {:?}", e)))
        }
        Params::EC(params) => {
            let d = params
                .ecc_private_key
                .as_ref()
                .ok_or_else(|| Oid4vciError::KeyError("Missing EC private key".into()))?;
            match params.curve.as_deref() {
                Some("P-256") => SecretKey::new_p256(&d.0)
                    .map_err(|e| Oid4vciError::KeyError(format!("Invalid P-256 key: {:?}", e))),
                Some(curve) => Err(Oid4vciError::KeyError(format!(
                    "Unsupported EC curve for COSE: {}", curve
                ))),
                None => Err(Oid4vciError::KeyError("Missing curve in EC JWK".into())),
            }
        }
        _ => Err(Oid4vciError::KeyError("Unsupported key type for COSE signing".into())),
    }?;

    let ssi_alg = match issuer_key.algorithm {
        crate::types::SigningAlgorithm::ES256 => AlgorithmInstance::ES256,
        crate::types::SigningAlgorithm::EdDSA => AlgorithmInstance::EdDSA,
        crate::types::SigningAlgorithm::ES384 => AlgorithmInstance::ES384,
        _ => {
            return Err(Oid4vciError::MdocError(
                "Algorithm not supported for COSE signing".into(),
            ));
        }
    };

    let signature = secret_key
        .sign(ssi_alg, &tbs)
        .map_err(|e| Oid4vciError::MdocError(format!("COSE signing failed: {:?}", e)))?;

    // Build final COSE_Sign1 with signature
    let cose_sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .signature(signature)
        .build();

    // Serialize the COSE_Sign1 to tagged CBOR bytes
    cose_sign1.to_tagged_vec().map_err(|e| {
        Oid4vciError::MdocError(format!("COSE serialization failed: {:?}", e))
    })
}

/// CBOR-encode a CborValue into bytes.
fn cbor_encode(value: &CborValue) -> Oid4vciResult<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| Oid4vciError::MdocError(format!("CBOR encoding failed: {}", e)))?;
    Ok(buf)
}

/// Convert a serde_json::Value into a ciborium CborValue.
fn json_to_cbor(value: &serde_json::Value) -> Oid4vciResult<CborValue> {
    match value {
        serde_json::Value::Null => Ok(CborValue::Null),
        serde_json::Value::Bool(b) => Ok(CborValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(CborValue::Integer(i.into()))
            } else if let Some(f) = n.as_f64() {
                Ok(CborValue::Float(f))
            } else {
                Err(Oid4vciError::MdocError(format!(
                    "Unsupported numeric value: {}",
                    n
                )))
            }
        }
        serde_json::Value::String(s) => {
            // Check if this looks like a date (YYYY-MM-DD) and wrap as CBOR tag 0
            if is_date_string(s) {
                Ok(CborValue::Tag(0, Box::new(CborValue::Text(s.clone()))))
            } else {
                Ok(CborValue::Text(s.clone()))
            }
        }
        serde_json::Value::Array(arr) => {
            let items: Result<Vec<_>, _> = arr.iter().map(json_to_cbor).collect();
            Ok(CborValue::Array(items?))
        }
        serde_json::Value::Object(obj) => {
            let pairs: Result<Vec<_>, _> = obj
                .iter()
                .map(|(k, v)| json_to_cbor(v).map(|cv| (CborValue::Text(k.clone()), cv)))
                .collect();
            Ok(CborValue::Map(pairs?))
        }
    }
}

/// Crude check for ISO 8601 date strings (used for mDL date elements).
fn is_date_string(s: &str) -> bool {
    // Matches YYYY-MM-DD or full ISO 8601 datetime
    s.len() >= 10
        && s.as_bytes()[4] == b'-'
        && s.as_bytes()[7] == b'-'
        && s[0..4].parse::<u16>().is_ok()
}

/// Convert a chrono DateTime to a CBOR tagged date-time string (tag 0).
fn cbor_date_time(dt: &chrono::DateTime<chrono::Utc>) -> CborValue {
    CborValue::Tag(
        0,
        Box::new(CborValue::Text(dt.to_rfc3339_opts(
            chrono::SecondsFormat::Secs,
            true,
        ))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SigningAlgorithm;

    fn test_p256_key() -> IssuerKey {
        let jwk = ssi::jwk::JWK::generate_p256();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        IssuerKey {
            issuer_id: "did:example:issuer".into(),
            jwk_json,
            algorithm: SigningAlgorithm::ES256,
        }
    }

    #[test]
    fn test_json_to_cbor_primitives() {
        let null = json_to_cbor(&serde_json::json!(null)).unwrap();
        assert!(matches!(null, CborValue::Null));

        let num = json_to_cbor(&serde_json::json!(42)).unwrap();
        assert!(matches!(num, CborValue::Integer(_)));

        let text = json_to_cbor(&serde_json::json!("hello")).unwrap();
        assert!(matches!(text, CborValue::Text(_)));

        let date = json_to_cbor(&serde_json::json!("1990-01-15")).unwrap();
        assert!(matches!(date, CborValue::Tag(0, _)));
    }

    #[test]
    fn test_build_issuer_signed_item() {
        let salt = [0u8; 32];
        let item = build_issuer_signed_item(
            0,
            &salt,
            "family_name",
            &serde_json::json!("Smith"),
        )
        .unwrap();

        // Should be a CBOR map with 4 entries
        if let CborValue::Map(entries) = item {
            assert_eq!(entries.len(), 4);
        } else {
            panic!("Expected CBOR map");
        }
    }

    #[test]
    fn test_sign_mdoc_basic() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "mDL".into(),
            claims: [
                ("family_name".into(), serde_json::json!("Smith")),
                ("given_name".into(), serde_json::json!("John")),
                ("birth_date".into(), serde_json::json!("1990-01-15")),
            ]
            .into(),
            expiration_seconds: Some(365 * 86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let result = sign_mdoc(&key, &claims).unwrap();
        match result {
            SignedCredential::MsoMdoc {
                issuer_signed_b64,
                credential_id,
            } => {
                assert!(!issuer_signed_b64.is_empty(), "Should produce non-empty output");
                assert!(credential_id.starts_with("urn:uuid:"));

                // Decode and verify it's valid CBOR
                let bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    &issuer_signed_b64,
                )
                .unwrap();
                let decoded: CborValue = ciborium::from_reader(&bytes[..]).unwrap();
                if let CborValue::Map(entries) = decoded {
                    let keys: Vec<_> = entries
                        .iter()
                        .filter_map(|(k, _)| {
                            if let CborValue::Text(t) = k {
                                Some(t.as_str())
                            } else {
                                None
                            }
                        })
                        .collect();
                    assert!(keys.contains(&"nameSpaces"));
                    assert!(keys.contains(&"issuerAuth"));
                } else {
                    panic!("Expected CBOR map at top level");
                }
            }
            _ => panic!("Expected MsoMdoc"),
        }
    }
}
