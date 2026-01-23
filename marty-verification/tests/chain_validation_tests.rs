//! Integration tests for certificate chain validation.
//!
//! These tests use rcgen to generate test certificate hierarchies
//! and verify various validation scenarios.

use marty_verification::verification::{ChainValidator, ChainValidatorConfig, KeyUsage};

/// Test valid self-signed certificate validation.
#[test]
fn test_self_signed_ca_validation() {
    use rcgen::{CertificateParams, DnType, KeyPair};

    // Generate a self-signed CA certificate
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Integration Test Root CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    // Validate
    let mut validator = ChainValidator::new();
    validator.add_trust_anchor_pem(&ca_pem).unwrap();

    let result = validator.validate_chain(&[ca_pem]).unwrap();
    assert!(
        result.valid,
        "Self-signed CA should validate: {:?}",
        result.errors
    );
    assert_eq!(result.chain_depth, 1);
    assert!(result.subject.unwrap().contains("Integration Test Root CA"));
}

/// Test two-level certificate chain (CA -> End Entity).
#[test]
fn test_two_level_chain_validation() {
    use rcgen::{CertificateParams, DnType, KeyPair};

    // Generate CA
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Two-Level Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    // Generate End Entity
    let mut ee_params = CertificateParams::default();
    ee_params
        .distinguished_name
        .push(DnType::CommonName, "End Entity Certificate");
    ee_params.is_ca = rcgen::IsCa::NoCa;

    let ee_key = KeyPair::generate().unwrap();
    let ee_cert = ee_params.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();
    let ee_pem = ee_cert.pem();

    // Validate chain
    let mut validator = ChainValidator::new();
    validator.add_trust_anchor_pem(&ca_pem).unwrap();

    let result = validator.validate_chain(&[ee_pem, ca_pem]).unwrap();
    assert!(
        result.valid,
        "Two-level chain should validate: {:?}",
        result.errors
    );
    assert_eq!(result.chain_depth, 2);
}

/// Test three-level certificate chain (Root CA -> Intermediate CA -> End Entity).
#[test]
fn test_three_level_chain_validation() {
    use rcgen::{CertificateParams, DnType, KeyPair};

    // Generate Root CA
    let mut root_params = CertificateParams::default();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Three-Level Root CA");
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let root_key = KeyPair::generate().unwrap();
    let root_cert = root_params.self_signed(&root_key).unwrap();
    let root_pem = root_cert.pem();

    // Generate Intermediate CA
    let mut int_params = CertificateParams::default();
    int_params
        .distinguished_name
        .push(DnType::CommonName, "Three-Level Intermediate CA");
    int_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));

    let int_key = KeyPair::generate().unwrap();
    let int_cert = int_params
        .signed_by(&int_key, &root_cert, &root_key)
        .unwrap();
    let int_pem = int_cert.pem();

    // Generate End Entity
    let mut ee_params = CertificateParams::default();
    ee_params
        .distinguished_name
        .push(DnType::CommonName, "Three-Level End Entity");
    ee_params.is_ca = rcgen::IsCa::NoCa;

    let ee_key = KeyPair::generate().unwrap();
    let ee_cert = ee_params.signed_by(&ee_key, &int_cert, &int_key).unwrap();
    let ee_pem = ee_cert.pem();

    // Validate chain
    let mut validator = ChainValidator::new();
    validator.add_trust_anchor_pem(&root_pem).unwrap();

    let result = validator
        .validate_chain(&[ee_pem, int_pem, root_pem])
        .unwrap();
    assert!(
        result.valid,
        "Three-level chain should validate: {:?}",
        result.errors
    );
    assert_eq!(result.chain_depth, 3);
}

/// Test expired certificate detection.
#[test]
fn test_expired_certificate_detection() {
    use rcgen::{CertificateParams, DnType, KeyPair};

    // Generate CA with long validity
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Expired Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    // Generate expired end-entity certificate
    let mut ee_params = CertificateParams::default();
    ee_params
        .distinguished_name
        .push(DnType::CommonName, "Expired Certificate");
    ee_params.is_ca = rcgen::IsCa::NoCa;
    ee_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(365);
    ee_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);

    let ee_key = KeyPair::generate().unwrap();
    let ee_cert = ee_params.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();
    let ee_pem = ee_cert.pem();

    // Validate - should fail
    let mut validator = ChainValidator::new();
    validator.add_trust_anchor_pem(&ca_pem).unwrap();

    let result = validator.validate_chain(&[ee_pem, ca_pem]).unwrap();
    assert!(!result.valid, "Expired certificate should fail validation");
    assert!(result.errors.iter().any(|e| e.contains("expired")));
}

/// Test untrusted chain detection.
#[test]
fn test_untrusted_chain_detection() {
    use rcgen::{CertificateParams, DnType, KeyPair};

    // Generate two different CAs
    let mut ca1_params = CertificateParams::default();
    ca1_params
        .distinguished_name
        .push(DnType::CommonName, "Untrusted CA");
    ca1_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let ca1_key = KeyPair::generate().unwrap();
    let ca1_cert = ca1_params.self_signed(&ca1_key).unwrap();
    let ca1_pem = ca1_cert.pem();

    let mut ca2_params = CertificateParams::default();
    ca2_params
        .distinguished_name
        .push(DnType::CommonName, "Trusted CA");
    ca2_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let ca2_key = KeyPair::generate().unwrap();
    let ca2_cert = ca2_params.self_signed(&ca2_key).unwrap();
    let ca2_pem = ca2_cert.pem();

    // Generate EE signed by CA1
    let mut ee_params = CertificateParams::default();
    ee_params
        .distinguished_name
        .push(DnType::CommonName, "EE from Untrusted CA");
    ee_params.is_ca = rcgen::IsCa::NoCa;

    let ee_key = KeyPair::generate().unwrap();
    let ee_cert = ee_params.signed_by(&ee_key, &ca1_cert, &ca1_key).unwrap();
    let ee_pem = ee_cert.pem();

    // Validate with CA2 as trust anchor - should fail
    let mut validator = ChainValidator::new();
    validator.add_trust_anchor_pem(&ca2_pem).unwrap();

    let result = validator.validate_chain(&[ee_pem, ca1_pem]).unwrap();
    assert!(!result.valid, "Chain from untrusted CA should fail");
    assert!(result.errors.iter().any(|e| e.contains("trust anchor")));
}

/// Test validation with custom config.
#[test]
fn test_validation_with_custom_config() {
    use rcgen::{CertificateParams, DnType, KeyPair};

    // Generate CA
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Config Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    // Generate EE
    let mut ee_params = CertificateParams::default();
    ee_params
        .distinguished_name
        .push(DnType::CommonName, "Config Test EE");
    ee_params.is_ca = rcgen::IsCa::NoCa;

    let ee_key = KeyPair::generate().unwrap();
    let ee_cert = ee_params.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();
    let ee_pem = ee_cert.pem();

    // Create validator with custom config
    let config = ChainValidatorConfig {
        check_crl: true,
        check_ocsp: false,
        revocation_mode: "soft_fail".to_string(),
        validation_moment: None,
        required_key_usage: vec![KeyUsage::DigitalSignature],
    };

    let mut validator = ChainValidator::with_config(config);
    validator.add_trust_anchor_pem(&ca_pem).unwrap();

    let result = validator.validate_chain(&[ee_pem, ca_pem]).unwrap();
    assert!(
        result.valid,
        "Chain should validate with soft_fail CRL mode: {:?}",
        result.errors
    );
}

/// Test point-in-time validation.
#[test]
fn test_point_in_time_validation() {
    use chrono::{Duration, Utc};
    use rcgen::{CertificateParams, DnType, KeyPair};

    // Generate CA
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Point-in-Time Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(365);
    ca_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * 10);

    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    // Generate EE that was valid 6 months ago but is expired now
    let mut ee_params = CertificateParams::default();
    ee_params
        .distinguished_name
        .push(DnType::CommonName, "Past Valid EE");
    ee_params.is_ca = rcgen::IsCa::NoCa;
    ee_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(365);
    ee_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(30);

    let ee_key = KeyPair::generate().unwrap();
    let ee_cert = ee_params.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();
    let ee_pem = ee_cert.pem();

    // Validate at current time - should fail
    let mut validator_now = ChainValidator::new();
    validator_now.add_trust_anchor_pem(&ca_pem).unwrap();

    let result_now = validator_now
        .validate_chain(&[ee_pem.clone(), ca_pem.clone()])
        .unwrap();
    assert!(!result_now.valid, "Should be expired at current time");

    // Validate at past time - should pass
    let past_moment = Utc::now() - Duration::days(180);
    let config = ChainValidatorConfig {
        validation_moment: Some(past_moment),
        ..Default::default()
    };

    let mut validator_past = ChainValidator::with_config(config);
    validator_past.add_trust_anchor_pem(&ca_pem).unwrap();

    let result_past = validator_past.validate_chain(&[ee_pem, ca_pem]).unwrap();
    assert!(
        result_past.valid,
        "Should be valid at past validation moment: {:?}",
        result_past.errors
    );
}

// =============================================================================
// cert_builder integration tests - test certificate chain creation with each key type
// =============================================================================

#[cfg(feature = "cert-builder")]
mod cert_builder_integration {
    // Use marty_crypto for cert_builder and keygen (instead of embedded crypto module)
    use marty_crypto::cert_builder::{
        create_ca_certificate, CertProfile, CertificateBuilderConfig, DistinguishedName,
    };
    use marty_crypto::keygen::KeyType;
    use marty_verification::verification::ChainValidator;

    /// Helper to convert DER to PEM format for chain validation.
    fn der_to_pem(der: &[u8]) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            lines.join("\n")
        )
    }

    /// Test ECDSA P-256 certificate chain: CA -> End Entity.
    #[test]
    fn test_ecdsa_p256_chain() {
        // Create CA certificate
        let (ca_der, ca_key_pem) =
            create_ca_certificate("P-256 Test CA", Some("US"), 365, KeyType::EcdsaP256)
                .expect("Failed to create P-256 CA");

        // Create end-entity certificate signed by CA
        let (ee_der, _ee_key_pem) = CertificateBuilderConfig::new()
            .subject(DistinguishedName::new().cn("P-256 End Entity"))
            .validity_days(365)
            .profile(CertProfile::EndEntity)
            .key_type(KeyType::EcdsaP256)
            .build_signed_by(&ca_der, &ca_key_pem)
            .expect("Failed to create P-256 end entity");

        // Convert to PEM
        let ca_pem = der_to_pem(&ca_der);
        let ee_pem = der_to_pem(&ee_der);

        // Validate chain
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&ca_pem).unwrap();

        let result = validator
            .validate_chain(&[ee_pem.clone(), ca_pem.clone()])
            .unwrap();
        assert!(
            result.valid,
            "P-256 chain should validate: {:?}",
            result.errors
        );
        assert_eq!(result.chain_depth, 2);
    }

    /// Test ECDSA P-384 certificate chain: CA -> End Entity.
    #[test]
    fn test_ecdsa_p384_chain() {
        // Create CA certificate
        let (ca_der, ca_key_pem) =
            create_ca_certificate("P-384 Test CA", Some("US"), 365, KeyType::EcdsaP384)
                .expect("Failed to create P-384 CA");

        // Create end-entity certificate signed by CA
        let (ee_der, _ee_key_pem) = CertificateBuilderConfig::new()
            .subject(DistinguishedName::new().cn("P-384 End Entity"))
            .validity_days(365)
            .profile(CertProfile::EndEntity)
            .key_type(KeyType::EcdsaP384)
            .build_signed_by(&ca_der, &ca_key_pem)
            .expect("Failed to create P-384 end entity");

        // Convert to PEM
        let ca_pem = der_to_pem(&ca_der);
        let ee_pem = der_to_pem(&ee_der);

        // Validate chain
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&ca_pem).unwrap();

        let result = validator
            .validate_chain(&[ee_pem.clone(), ca_pem.clone()])
            .unwrap();
        assert!(
            result.valid,
            "P-384 chain should validate: {:?}",
            result.errors
        );
        assert_eq!(result.chain_depth, 2);
    }

    /// Test RSA-2048 certificate chain: CA -> End Entity.
    #[test]
    fn test_rsa_2048_chain() {
        // Create CA certificate (RSA is slow, use shorter validity for test speed)
        let (ca_der, ca_key_pem) =
            create_ca_certificate("RSA-2048 Test CA", Some("US"), 365, KeyType::Rsa2048)
                .expect("Failed to create RSA-2048 CA");

        // Create end-entity certificate signed by CA
        let (ee_der, _ee_key_pem) = CertificateBuilderConfig::new()
            .subject(DistinguishedName::new().cn("RSA-2048 End Entity"))
            .validity_days(365)
            .profile(CertProfile::EndEntity)
            .key_type(KeyType::Rsa2048)
            .build_signed_by(&ca_der, &ca_key_pem)
            .expect("Failed to create RSA-2048 end entity");

        // Convert to PEM
        let ca_pem = der_to_pem(&ca_der);
        let ee_pem = der_to_pem(&ee_der);

        // Validate chain
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&ca_pem).unwrap();

        let result = validator
            .validate_chain(&[ee_pem.clone(), ca_pem.clone()])
            .unwrap();
        assert!(
            result.valid,
            "RSA-2048 chain should validate: {:?}",
            result.errors
        );
        assert_eq!(result.chain_depth, 2);
    }

    /// Test Ed25519 certificate chain: CA -> End Entity.
    #[test]
    fn test_ed25519_chain() {
        // Create CA certificate
        let (ca_der, ca_key_pem) =
            create_ca_certificate("Ed25519 Test CA", Some("US"), 365, KeyType::Ed25519)
                .expect("Failed to create Ed25519 CA");

        // Create end-entity certificate signed by CA
        let (ee_der, _ee_key_pem) = CertificateBuilderConfig::new()
            .subject(DistinguishedName::new().cn("Ed25519 End Entity"))
            .validity_days(365)
            .profile(CertProfile::EndEntity)
            .key_type(KeyType::Ed25519)
            .build_signed_by(&ca_der, &ca_key_pem)
            .expect("Failed to create Ed25519 end entity");

        // Convert to PEM
        let ca_pem = der_to_pem(&ca_der);
        let ee_pem = der_to_pem(&ee_der);

        // Validate chain
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&ca_pem).unwrap();

        let result = validator
            .validate_chain(&[ee_pem.clone(), ca_pem.clone()])
            .unwrap();
        assert!(
            result.valid,
            "Ed25519 chain should validate: {:?}",
            result.errors
        );
        assert_eq!(result.chain_depth, 2);
    }

    /// Test three-level chain with ECDSA P-256: Root CA -> Intermediate CA -> End Entity.
    #[test]
    fn test_three_level_p256_chain() {
        // Create Root CA (no country to keep naming consistent)
        let (root_der, root_key_pem) = create_ca_certificate(
            "P-256 Root CA",
            None, // No country to keep subject/issuer consistent
            3650, // 10 years
            KeyType::EcdsaP256,
        )
        .expect("Failed to create P-256 Root CA");

        // Create Intermediate CA signed by Root (use SubCa profile, not Ca)
        let (int_der, int_key_pem) = CertificateBuilderConfig::new()
            .subject(DistinguishedName::new().cn("P-256 Intermediate CA"))
            .validity_days(1825) // 5 years
            .profile(CertProfile::SubCa { path_length: 0 })
            .key_type(KeyType::EcdsaP256)
            .build_signed_by(&root_der, &root_key_pem)
            .expect("Failed to create P-256 Intermediate CA");

        // Create End Entity signed by Intermediate
        let (ee_der, _ee_key_pem) = CertificateBuilderConfig::new()
            .subject(DistinguishedName::new().cn("P-256 End Entity"))
            .validity_days(365)
            .profile(CertProfile::EndEntity)
            .key_type(KeyType::EcdsaP256)
            .build_signed_by(&int_der, &int_key_pem)
            .expect("Failed to create P-256 End Entity");

        // Convert to PEM
        let root_pem = der_to_pem(&root_der);
        let int_pem = der_to_pem(&int_der);
        let ee_pem = der_to_pem(&ee_der);

        // Validate full chain
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&root_pem).unwrap();

        let result = validator
            .validate_chain(&[ee_pem, int_pem, root_pem])
            .unwrap();
        assert!(
            result.valid,
            "Three-level P-256 chain should validate: {:?}",
            result.errors
        );
        assert_eq!(result.chain_depth, 3);
    }

    /// Test mixed key type chain: P-256 CA -> P-384 End Entity.
    #[test]
    fn test_mixed_key_chain() {
        // Create P-256 CA
        let (ca_der, ca_key_pem) =
            create_ca_certificate("P-256 CA (mixed)", Some("US"), 365, KeyType::EcdsaP256)
                .expect("Failed to create P-256 CA");

        // Create P-384 end-entity certificate signed by P-256 CA
        let (ee_der, _ee_key_pem) = CertificateBuilderConfig::new()
            .subject(DistinguishedName::new().cn("P-384 End Entity"))
            .validity_days(365)
            .profile(CertProfile::EndEntity)
            .key_type(KeyType::EcdsaP384)
            .build_signed_by(&ca_der, &ca_key_pem)
            .expect("Failed to create P-384 end entity with P-256 CA");

        // Convert to PEM
        let ca_pem = der_to_pem(&ca_der);
        let ee_pem = der_to_pem(&ee_der);

        // Validate chain
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&ca_pem).unwrap();

        let result = validator.validate_chain(&[ee_pem, ca_pem]).unwrap();
        assert!(
            result.valid,
            "Mixed key type chain should validate: {:?}",
            result.errors
        );
        assert_eq!(result.chain_depth, 2);
    }
}
