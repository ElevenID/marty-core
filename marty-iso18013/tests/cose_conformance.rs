//! COSE (CBOR Object Signing and Encryption) conformance tests (RFC 9052).
//!
//! Tests cover:
//!   - §4    COSE_Sign1 structure: protected header, header, payload, signature
//!   - §6    COSE_Mac0 structure
//!   - §3.1  Header parameter encoding
//!   - Round-trip build/parse for COSE structures used in ISO 18013-5 mDocs
//!     (COSE_Sign1 for IssuerAuth, COSE_Mac0 for DeviceMac)
//!
//! Uses the `coset` crate which is a dependency of marty-iso18013.

use coset::{
    cbor::Value, iana, CborSerializable, CoseMac0, CoseMac0Builder, CoseSign1, CoseSign1Builder,
    Header, HeaderBuilder, Label, RegisteredLabel, TaggedCborSerializable,
};

// ── COSE_Sign1 tests ─────────────────────────────────────────────────────────

/// RFC 9052 §4.2: A COSE_Sign1 has four components:
/// [protected, unprotected, payload, signature]
#[test]
fn cose_sign1_structure_has_four_components() {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();

    let payload = b"test payload".to_vec();

    // Build without an actual cryptographic signature (untagged, nil signature)
    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.clone())
        .create_signature(&[], |_to_sign| vec![0u8; 64]) // mock 64-byte signature
        .build();

    // Serialize and deserialize round-trip
    let bytes = cose.to_vec().expect("COSE_Sign1 serialize");
    let decoded = CoseSign1::from_slice(&bytes).expect("COSE_Sign1 deserialize");

    // Payload is preserved
    assert_eq!(decoded.payload, Some(payload));
    // Protected header algorithm is preserved
    let alg = decoded
        .protected
        .header
        .alg
        .as_ref()
        .expect("algorithm header");
    assert_eq!(*alg, coset::Algorithm::Assigned(iana::Algorithm::ES256));
}

/// RFC 9052 §3.1: Content type header parameter (label 3)
#[test]
fn cose_sign1_content_type_header() {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .content_type("application/1+cbor".to_string())
        .build();

    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(b"mdoc content".to_vec())
        .create_signature(&[], |_| vec![0u8; 64])
        .build();

    let bytes = cose.to_vec().expect("serialize");
    let decoded = CoseSign1::from_slice(&bytes).expect("deserialize");

    assert!(decoded.protected.header.content_type.is_some());
}

/// ISO 18013-5 uses ES256 (ECDSA P-256 + SHA-256) for IssuerAuth.
/// Verify that the algorithm label -7 (ES256) round-trips correctly.
#[test]
fn cose_sign1_es256_algorithm_roundtrip() {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();

    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(b"IssuerAuth payload".to_vec())
        .create_signature(&[], |_| vec![0u8; 64])
        .build();

    let bytes = cose.to_vec().unwrap();
    let decoded = CoseSign1::from_slice(&bytes).unwrap();

    let alg = decoded.protected.header.alg.as_ref().unwrap();
    // ES256 has COSE algorithm value -7
    assert_eq!(
        alg,
        &coset::Algorithm::Assigned(iana::Algorithm::ES256),
        "Algorithm should round-trip as ES256"
    );
}

/// RFC 9052 §4.2: nil payload (detached content case).
/// ISO 18013-5 §9.1.3 uses detached payload for DeviceAuthentication.
#[test]
fn cose_sign1_nil_payload_detached_content() {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();

    let cose = CoseSign1Builder::new()
        .protected(protected)
        // No .payload() call → nil payload (detached)
        .create_signature(&[], |_| vec![0u8; 64])
        .build();

    let bytes = cose.to_vec().unwrap();
    let decoded = CoseSign1::from_slice(&bytes).unwrap();

    assert!(
        decoded.payload.is_none(),
        "Detached COSE_Sign1 should have nil payload"
    );
}

/// Key ID header parameter (label 4) is preserved.
#[test]
fn cose_sign1_key_id_roundtrip() {
    let kid = b"issuer-key-1".to_vec();
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(kid.clone())
        .build();

    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(b"payload".to_vec())
        .create_signature(&[], |_| vec![0u8; 64])
        .build();

    let bytes = cose.to_vec().unwrap();
    let decoded = CoseSign1::from_slice(&bytes).unwrap();

    assert_eq!(decoded.protected.header.key_id, kid);
}

// ── COSE_Mac0 tests ───────────────────────────────────────────────────────────

/// RFC 9052 §6.3: A COSE_Mac0 has four components:
/// [protected, unprotected, payload, tag]
#[test]
fn cose_mac0_structure_has_four_components() {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::HMAC_256_256)
        .build();

    let cose = CoseMac0Builder::new()
        .protected(protected)
        .payload(b"mac payload".to_vec())
        .create_tag(&[], |_| vec![0u8; 32]) // mock 32-byte HMAC-SHA-256 tag
        .build();

    let bytes = cose.to_vec().expect("COSE_Mac0 serialize");
    let decoded = CoseMac0::from_slice(&bytes).expect("COSE_Mac0 deserialize");

    assert_eq!(decoded.payload, Some(b"mac payload".to_vec()));
}

/// ISO 18013-5 §9.1.4 uses HMAC-256 for DeviceMac.
#[test]
fn cose_mac0_hmac256_algorithm_roundtrip() {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::HMAC_256_256)
        .build();

    let cose = CoseMac0Builder::new()
        .protected(protected)
        .payload(b"DeviceMac test".to_vec())
        .create_tag(&[], |_| vec![0u8; 32])
        .build();

    let bytes = cose.to_vec().unwrap();
    let decoded = CoseMac0::from_slice(&bytes).unwrap();

    let alg = decoded.protected.header.alg.as_ref().unwrap();
    assert_eq!(
        alg,
        &coset::Algorithm::Assigned(iana::Algorithm::HMAC_256_256)
    );
}

// ── Custom header parameters ──────────────────────────────────────────────────

/// RFC 9052 §3.1: custom (private-use) header parameters are preserved.
/// ISO 18013-5 uses custom parameters for x5chain (certificate chain).
#[test]
fn cose_sign1_custom_header_parameter_preserved() {
    // x5chain label is 33 per RFC 9360
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .value(33, Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef])) // mock cert bytes
        .build();

    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(b"cert chain test".to_vec())
        .create_signature(&[], |_| vec![0u8; 64])
        .build();

    let bytes = cose.to_vec().unwrap();
    let decoded = CoseSign1::from_slice(&bytes).unwrap();

    // x5chain label 33 should be in rest
    let x5chain = decoded
        .protected
        .header
        .rest
        .iter()
        .find(|(k, _)| *k == Label::Int(33));
    assert!(
        x5chain.is_some(),
        "x5chain header parameter should be preserved"
    );
}
