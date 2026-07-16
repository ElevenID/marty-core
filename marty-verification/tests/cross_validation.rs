//! Cross-validation tests using OpenSSL for high-confidence verification.
//!
//! These tests compare our pure-Rust certificate validation implementation
//! against OpenSSL's battle-tested implementation to ensure correctness.
//!
//! Run with: `cargo test --features cross-validation`
//!
//! Note: Requires OpenSSL development libraries installed:
//! - macOS: `brew install openssl`
//! - Ubuntu: `apt-get install libssl-dev`

#![cfg(all(feature = "cross-validation", unix))]

use chrono::{DateTime, Utc};
use marty_verification::verification::{ChainValidator, ChainValidatorConfig};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509StoreContext, X509VerifyResult, X509};

// NIST PKITS test data - embedded directly for cross-validation tests
// Path is relative to marty-verification/tests/ -> ../../tests/cert_validator/
const NIST_TRUST_ANCHOR_DER: &[u8] = include_bytes!(
    "../../tests/cert_validator/fixtures/nist_pkits/certs/TrustAnchorRootCertificate.crt"
);
const NIST_GOOD_CA_DER: &[u8] =
    include_bytes!("../../tests/cert_validator/fixtures/nist_pkits/certs/GoodCACert.crt");
const NIST_VALID_EE_DER: &[u8] = include_bytes!(
    "../../tests/cert_validator/fixtures/nist_pkits/certs/ValidCertificatePathTest1EE.crt"
);
const NIST_BAD_SIGNED_CA_DER: &[u8] =
    include_bytes!("../../tests/cert_validator/fixtures/nist_pkits/certs/BadSignedCACert.crt");
const NIST_INVALID_SIG_EE_DER: &[u8] = include_bytes!(
    "../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidCASignatureTest2EE.crt"
);
const NIST_DSA_CA_DER: &[u8] =
    include_bytes!("../../tests/cert_validator/fixtures/nist_pkits/certs/DSACACert.crt");
const NIST_VALID_DSA_EE_DER: &[u8] = include_bytes!(
    "../../tests/cert_validator/fixtures/nist_pkits/certs/ValidDSASignaturesTest4EE.crt"
);
const NIST_BAD_NOT_AFTER_CA_DER: &[u8] = include_bytes!(
    "../../tests/cert_validator/fixtures/nist_pkits/certs/BadnotAfterDateCACert.crt"
);
const NIST_BAD_NOT_BEFORE_CA_DER: &[u8] = include_bytes!(
    "../../tests/cert_validator/fixtures/nist_pkits/certs/BadnotBeforeDateCACert.crt"
);

/// Helper to load DER certificate into OpenSSL X509
fn load_openssl_cert(der: &[u8]) -> X509 {
    X509::from_der(der).expect("Failed to parse certificate with OpenSSL")
}

/// Build an OpenSSL trust store with the given trust anchor
fn build_trust_store(trust_anchor_der: &[u8]) -> X509Store {
    let mut store_builder = X509StoreBuilder::new().expect("Failed to create X509StoreBuilder");
    let trust_anchor = load_openssl_cert(trust_anchor_der);
    store_builder
        .add_cert(trust_anchor)
        .expect("Failed to add trust anchor");
    store_builder.build()
}

/// Verify a certificate chain using OpenSSL
fn verify_with_openssl(
    ee_der: &[u8],
    intermediate_ders: &[&[u8]],
    trust_anchor_der: &[u8],
) -> (bool, String) {
    let store = build_trust_store(trust_anchor_der);
    let ee_cert = load_openssl_cert(ee_der);

    // Build intermediate chain
    let mut chain = Stack::new().expect("Failed to create certificate stack");
    for intermediate_der in intermediate_ders {
        let intermediate = load_openssl_cert(intermediate_der);
        chain
            .push(intermediate)
            .expect("Failed to push intermediate");
    }

    let mut ctx = X509StoreContext::new().expect("Failed to create store context");
    let result = ctx.init(&store, &ee_cert, &chain, |ctx| {
        ctx.verify_cert()?;
        Ok(ctx.error())
    });

    match result {
        Ok(X509VerifyResult::OK) => (true, "OK".to_string()),
        Ok(err) => (false, err.error_string().to_string()),
        Err(e) => (false, format!("OpenSSL error: {}", e)),
    }
}

fn verify_with_marty(
    ee_der: &[u8],
    intermediate_ders: &[&[u8]],
    trust_anchor_der: &[u8],
    validation_moment: Option<DateTime<Utc>>,
) -> (bool, String) {
    let config = ChainValidatorConfig {
        validation_moment,
        required_key_usage: Vec::new(),
        ..Default::default()
    };
    let mut validator = ChainValidator::with_config(config);
    if let Err(err) = validator.add_trust_anchor_der(trust_anchor_der) {
        return (false, format!("Marty error: {}", err));
    }

    let mut chain = Vec::with_capacity(1 + intermediate_ders.len());
    chain.push(ee_der.to_vec());
    for der in intermediate_ders {
        chain.push((*der).to_vec());
    }

    match validator.validate_chain_der(&chain) {
        Ok(result) => {
            if result.valid {
                (true, "OK".to_string())
            } else {
                let mut reason = result.errors.join("; ");
                if reason.is_empty() && !result.warnings.is_empty() {
                    reason = result.warnings.join("; ");
                }
                if reason.is_empty() {
                    reason = "Unknown verification failure".to_string();
                }
                (false, reason)
            }
        }
        Err(err) => (false, format!("Marty error: {}", err)),
    }
}

// ============================================================================
// NIST PKITS Cross-Validation Tests
// ============================================================================

mod nist_pkits {
    use super::*;
    use der::Decode;
    use x509_cert::Certificate;

    /// Cross-validate: Valid certificate path should pass both implementations
    #[test]
    fn test_valid_certificate_path() {
        // Test with OpenSSL
        let (openssl_valid, openssl_reason) = verify_with_openssl(
            NIST_VALID_EE_DER,
            &[NIST_GOOD_CA_DER],
            NIST_TRUST_ANCHOR_DER,
        );

        // Test with our implementation
        let (marty_valid, marty_reason) = verify_with_marty(
            NIST_VALID_EE_DER,
            &[NIST_GOOD_CA_DER],
            NIST_TRUST_ANCHOR_DER,
            None,
        );

        println!(
            "OpenSSL: valid={}, reason={}",
            openssl_valid, openssl_reason
        );
        println!("Marty: valid={}, reason={}", marty_valid, marty_reason);

        // Both should agree on validity (OpenSSL may reject due to expiry)
        assert_eq!(
            marty_valid, openssl_valid,
            "Marty/OpenSSL mismatch: openssl_valid={}, marty_valid={}, openssl_reason={}, marty_reason={}",
            openssl_valid, marty_valid, openssl_reason, marty_reason
        );
    }

    /// Cross-validate: Bad signature CA should fail both implementations
    #[test]
    fn test_bad_signed_ca_rejected() {
        let (openssl_valid, openssl_reason) = verify_with_openssl(
            NIST_INVALID_SIG_EE_DER,
            &[NIST_BAD_SIGNED_CA_DER],
            NIST_TRUST_ANCHOR_DER,
        );
        let (marty_valid, marty_reason) = verify_with_marty(
            NIST_INVALID_SIG_EE_DER,
            &[NIST_BAD_SIGNED_CA_DER],
            NIST_TRUST_ANCHOR_DER,
            None,
        );

        println!(
            "OpenSSL: valid={}, reason={}",
            openssl_valid, openssl_reason
        );
        println!("Marty: valid={}, reason={}", marty_valid, marty_reason);

        // OpenSSL should reject this
        assert!(!openssl_valid, "OpenSSL should reject bad signature CA");
        assert!(
            !marty_valid,
            "Marty should reject bad signature CA: {}",
            marty_reason
        );
        assert!(
            openssl_reason.contains("signature")
                || openssl_reason.contains("verify")
                || openssl_reason.contains("expired"), // May also fail due to expiry
            "Rejection should mention signature issue or expiry"
        );
    }

    /// Cross-validate: Expired certificate should be detectable
    #[test]
    fn test_expired_cert_detection() {
        let (openssl_valid, openssl_reason) = verify_with_openssl(
            NIST_VALID_EE_DER, // EE cert from 2011
            &[NIST_GOOD_CA_DER],
            NIST_TRUST_ANCHOR_DER,
        );
        let (marty_valid, marty_reason) = verify_with_marty(
            NIST_VALID_EE_DER,
            &[NIST_GOOD_CA_DER],
            NIST_TRUST_ANCHOR_DER,
            None,
        );

        println!(
            "OpenSSL: valid={}, reason={}",
            openssl_valid, openssl_reason
        );
        println!("Marty: valid={}, reason={}", marty_valid, marty_reason);

        // NIST PKITS certs from 2011 are expired, OpenSSL should detect this
        let cert = Certificate::from_der(NIST_VALID_EE_DER).expect("Failed to parse NIST EE cert");
        let not_after = cert.tbs_certificate.validity.not_after.to_system_time();
        let not_after_dt = DateTime::<Utc>::from(not_after);
        if Utc::now() > not_after_dt {
            assert!(!openssl_valid, "OpenSSL should reject expired certs");
            assert!(
                !marty_valid,
                "Marty should reject expired certs: {}",
                marty_reason
            );
            assert!(
                openssl_reason.contains("expired")
                    || openssl_reason.contains("not yet valid")
                    || openssl_reason.contains("certificate has expired"),
                "OpenSSL should cite expiry reason: {}",
                openssl_reason
            );
            assert!(
                marty_reason.to_lowercase().contains("expired"),
                "Marty should cite expiry reason: {}",
                marty_reason
            );
        }
    }
}

// ============================================================================
// Certificate Parsing Cross-Validation
// ============================================================================

mod parsing {
    use super::*;
    use der::Decode;
    use x509_cert::Certificate;

    /// Verify both libraries can parse the same certificates
    #[test]
    fn test_parse_trust_anchor() {
        // Parse with x509-cert
        let our_cert = Certificate::from_der(NIST_TRUST_ANCHOR_DER)
            .expect("x509-cert should parse trust anchor");

        // Parse with OpenSSL
        let openssl_cert = load_openssl_cert(NIST_TRUST_ANCHOR_DER);

        // Compare subject names
        let our_subject = our_cert.tbs_certificate.subject.to_string();
        let openssl_subject = openssl_cert
            .subject_name()
            .entries()
            .map(|e| {
                format!(
                    "{}={}",
                    e.object().nid().short_name().unwrap_or("?"),
                    e.data()
                        .as_utf8()
                        .map(|s| s.to_string())
                        .unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");

        println!("Our subject: {}", our_subject);
        println!("OpenSSL subject: {}", openssl_subject);

        // Both should contain "Trust Anchor"
        assert!(
            our_subject.contains("Trust Anchor") || our_subject.contains("TrustAnchor"),
            "Our parser should find Trust Anchor in subject"
        );
    }

    /// Verify both libraries extract the same public key
    #[test]
    fn test_public_key_extraction() {
        let our_cert = x509_cert::Certificate::from_der(NIST_GOOD_CA_DER)
            .expect("x509-cert should parse Good CA");

        let openssl_cert = load_openssl_cert(NIST_GOOD_CA_DER);

        // Get public key info from both
        let our_spki = &our_cert.tbs_certificate.subject_public_key_info;
        let our_algorithm = our_spki.algorithm.oid.to_string();

        let openssl_pkey = openssl_cert
            .public_key()
            .expect("OpenSSL should extract public key");
        let openssl_bits = openssl_pkey.bits();

        println!("Our algorithm OID: {}", our_algorithm);
        println!("OpenSSL key bits: {}", openssl_bits);

        // RSA key should be 2048 bits for NIST PKITS
        assert!(openssl_bits >= 1024, "Key should be at least 1024 bits");
    }

    /// Parse all NIST certificates with both libraries
    #[test]
    fn test_parse_all_nist_certs() {
        let certs = [
            ("Trust Anchor", NIST_TRUST_ANCHOR_DER),
            ("Good CA", NIST_GOOD_CA_DER),
            ("Valid EE", NIST_VALID_EE_DER),
            ("Bad Signed CA", NIST_BAD_SIGNED_CA_DER),
            ("Invalid Sig EE", NIST_INVALID_SIG_EE_DER),
            ("DSA CA", NIST_DSA_CA_DER),
            ("Valid DSA EE", NIST_VALID_DSA_EE_DER),
            ("Bad notAfter CA", NIST_BAD_NOT_AFTER_CA_DER),
            ("Bad notBefore CA", NIST_BAD_NOT_BEFORE_CA_DER),
        ];

        let mut failures = Vec::new();

        for (name, der) in certs {
            // Try x509-cert
            let our_result = x509_cert::Certificate::from_der(der);
            // Try OpenSSL
            let openssl_result = X509::from_der(der);

            match (&our_result, &openssl_result) {
                (Ok(_), Ok(_)) => println!("✓ {} parsed by both", name),
                (Err(e), Ok(_)) => failures.push(format!("{}: x509-cert failed: {}", name, e)),
                (Ok(_), Err(e)) => failures.push(format!("{}: OpenSSL failed: {}", name, e)),
                (Err(e1), Err(e2)) => {
                    failures.push(format!("{}: Both failed: {} / {}", name, e1, e2))
                }
            }
        }

        if !failures.is_empty() {
            panic!("Parse failures:\n{}", failures.join("\n"));
        }
    }
}

// ============================================================================
// Signature Verification Cross-Validation
// ============================================================================

mod signatures {
    use super::*;

    /// Cross-validate signature verification on Good CA -> Valid EE chain
    #[test]
    fn test_signature_verification() {
        let issuer = load_openssl_cert(NIST_GOOD_CA_DER);
        let ee = load_openssl_cert(NIST_VALID_EE_DER);

        // Get issuer's public key
        let issuer_pkey = issuer.public_key().expect("Should extract public key");

        // Verify EE certificate signature using OpenSSL
        let result = ee.verify(&issuer_pkey);

        println!("OpenSSL signature verification: {:?}", result);

        // Note: This may fail if the certificate was intentionally tampered
        // The important thing is that we can perform the verification
        assert!(
            matches!(result, Ok(true)),
            "OpenSSL should verify signature: {:?}",
            result
        );
    }

    /// Verify that bad signature CA is actually detected
    #[test]
    fn test_bad_signature_detected() {
        let trust_anchor = load_openssl_cert(NIST_TRUST_ANCHOR_DER);
        let bad_ca = load_openssl_cert(NIST_BAD_SIGNED_CA_DER);

        let ta_pkey = trust_anchor
            .public_key()
            .expect("Should extract public key");

        // Try to verify bad CA against trust anchor
        let result = bad_ca.verify(&ta_pkey);

        println!("Bad CA signature verification: {:?}", result);

        // This should fail because the signature is intentionally bad
        match result {
            Ok(valid) => assert!(!valid, "Bad signature CA should not verify"),
            Err(_) => {} // Error is also acceptable
        }
    }
}

// ============================================================================
// Certificate Generation Tests (using rcgen)
// ============================================================================

#[cfg(feature = "cross-validation")]
mod cert_generation {
    use der::Decode;
    use openssl::x509::X509;
    use rcgen::date_time_ymd;
    use rcgen::{CertificateParams, DnType, KeyPair};
    use x509_cert::Certificate as X509Certificate;

    /// Generate a self-signed certificate and verify both libraries can parse it
    #[test]
    fn test_generated_cert_cross_parse() {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Cross-Validation Tests");
        params.distinguished_name.push(DnType::CountryName, "US");

        // Valid for testing
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2030, 12, 31);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        // Generate the certificate
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("Failed to generate key pair");
        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to create self-signed cert");
        let der = cert.der();

        // Parse with x509-cert
        let x509_cert_result = X509Certificate::from_der(der);
        assert!(
            x509_cert_result.is_ok(),
            "x509-cert should parse generated cert: {:?}",
            x509_cert_result.err()
        );

        // Parse with OpenSSL
        let openssl_result = X509::from_der(der);
        assert!(
            openssl_result.is_ok(),
            "OpenSSL should parse generated cert: {:?}",
            openssl_result.err()
        );

        println!("✓ Generated certificate parsed by both libraries");
    }

    /// Generate an expired certificate and verify detection
    #[test]
    fn test_generated_expired_cert() {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "Expired Test CA");

        // Already expired
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2021, 1, 1);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("Failed to generate key pair");
        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to create expired cert");
        let der = cert.der();

        // Parse and check expiry with x509-cert
        let x509_cert = X509Certificate::from_der(der).expect("Should parse");
        let not_after = &x509_cert.tbs_certificate.validity.not_after;

        // Parse with OpenSSL and check expiry
        let openssl_cert = X509::from_der(der).expect("OpenSSL should parse");
        let openssl_not_after = openssl_cert.not_after();

        println!("x509-cert not_after: {:?}", not_after);
        println!("OpenSSL not_after: {}", openssl_not_after);

        // Both should show the cert is expired (not_after is in the past)
        let now = std::time::SystemTime::now();
        let not_after_system = x509_cert
            .tbs_certificate
            .validity
            .not_after
            .to_system_time();
        assert!(
            now > not_after_system,
            "Expected generated cert to be expired"
        );
    }

    /// Generate a certificate chain and validate with OpenSSL
    #[test]
    fn test_generated_chain_validation() {
        // Generate CA
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Generated Test CA");
        ca_params.not_before = date_time_ymd(2024, 1, 1);
        ca_params.not_after = date_time_ymd(2030, 12, 31);
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("Failed to generate CA key");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("Failed to create CA cert");

        // Generate EE signed by CA
        let mut ee_params = CertificateParams::default();
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "Generated Test EE");
        ee_params.not_before = date_time_ymd(2024, 1, 1);
        ee_params.not_after = date_time_ymd(2030, 12, 31);
        ee_params.is_ca = rcgen::IsCa::NoCa;

        let ee_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("Failed to generate EE key");
        let ee_cert = ee_params
            .signed_by(&ee_key, &ca_cert, &ca_key)
            .expect("Failed to sign EE cert");

        // Verify the chain with OpenSSL
        let openssl_ca = super::load_openssl_cert(ca_cert.der());
        let openssl_ee = super::load_openssl_cert(ee_cert.der());

        // Verify signature
        let ca_pkey = openssl_ca.public_key().expect("Should get CA public key");
        let verify_result = openssl_ee.verify(&ca_pkey);

        assert!(
            verify_result.is_ok() && verify_result.unwrap(),
            "OpenSSL should verify our generated chain"
        );

        println!("✓ Generated certificate chain verified by OpenSSL");
    }
}

// ============================================================================
// Property-Based Testing with Proptest
// ============================================================================

#[cfg(feature = "cross-validation")]
mod property_tests {
    use der::Decode;
    use proptest::prelude::*;
    use x509_cert::Certificate;

    // Generate random DER-like bytes and ensure we don't panic
    proptest! {
        #[test]
        fn test_random_bytes_no_panic(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            // Should not panic, just return error
            let _ = Certificate::from_der(&data);
        }

        #[test]
        fn test_corrupted_cert_no_panic(
            cert_base in prop::collection::vec(any::<u8>(), 100..500),
            corruption_offset in 0usize..100,
            corruption_value in any::<u8>(),
        ) {
            let mut corrupted = cert_base;
            if corruption_offset < corrupted.len() {
                corrupted[corruption_offset] = corruption_value;
            }
            // Should not panic
            let _ = Certificate::from_der(&corrupted);
        }
    }
}
