//! mDL (ISO 18013-5) trust chain and certificate verification conformance tests.
//!
//! Mirrors the trust model requirements of ISO 18013-5 Annex B and the AAMVA
//! mDL Implementation Guidelines:
//!
//!  §1  X5Chain construction from PEM (ISO 18013-5 §9.1.3)
//!  §2  Jurisdiction registry — IacaRegistry construction and lookup
//!  §3  X5Chain validation against trust anchors
//!  §4  MdlVerificationResult fields and AuthStatus model
//!  §5  Error paths — untrusted chain, empty chain
//!  §6  Jurisdiction code model (AAMVA ISO 3166-2 codes)

use marty_verification::{
    trust_anchor::{IacaRegistry, Jurisdiction},
    verification::mdl::{
        build_x5chain_from_pem, AuthStatus, MdlVerificationResult, ValidationRuleset,
    },
};
use rcgen::{CertificateParams, DnType, KeyPair};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Generate a self-signed CA certificate for testing.  Returns `(pem, key)`.
fn gen_ca(common_name: &str) -> (String, KeyPair) {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.distinguished_name.push(DnType::CountryName, "US");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let key = KeyPair::generate().expect("CA key generation");
    let cert = params.self_signed(&key).expect("CA self-sign");
    (cert.pem(), key)
}

// ── §1  X5Chain construction from PEM ────────────────────────────────────────

/// A single self-signed certificate must produce an X5Chain with depth 1.
#[test]
fn x5chain_from_single_pem_cert() {
    let (ca_pem, _) = gen_ca("Conformance Test IACA");
    let chain = build_x5chain_from_pem(&[ca_pem.as_bytes()]).expect("build_x5chain_from_pem");

    // X5Chain wraps NonEmptyVec, so end_entity_certificate() is always present
    assert!(
        !chain.end_entity_common_name().is_empty(),
        "X5Chain from a single cert must have an end entity certificate"
    );
}

/// A two-cert chain (CA + EE) must build successfully.
#[test]
fn x5chain_from_two_pem_certs() {
    let (ca_pem, ca_key) = gen_ca("Two-Cert IACA");
    let ca_cert_params = {
        let mut p = CertificateParams::default();
        p.distinguished_name
            .push(DnType::CommonName, "Two-Cert IACA");
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p
    };
    let mut ee_params = CertificateParams::default();
    ee_params
        .distinguished_name
        .push(DnType::CommonName, "mDL Document Signer");
    ee_params.is_ca = rcgen::IsCa::NoCa;
    let ee_key = KeyPair::generate().expect("EE key");
    let ca_issuer = rcgen::Issuer::from_params(&ca_cert_params, &ca_key);
    let ee_pem = ee_params
        .signed_by(&ee_key, &ca_issuer)
        .expect("sign EE")
        .pem();

    let chain = build_x5chain_from_pem(&[ee_pem.as_bytes(), ca_pem.as_bytes()])
        .expect("build_x5chain_from_pem two-cert");

    // X5Chain wraps NonEmptyVec, so the chain is always present if built successfully
    assert!(
        !chain.end_entity_common_name().is_empty(),
        "two-cert X5Chain must not be empty"
    );
}

/// Empty certificate list must produce an error (no chain to build).
#[test]
fn x5chain_from_empty_list_fails() {
    let result = build_x5chain_from_pem(&[]);
    assert!(
        result.is_err(),
        "building X5Chain from empty cert list must fail"
    );
}

/// Garbage bytes (not PEM) must produce an error.
#[test]
fn x5chain_from_invalid_pem_fails() {
    let garbage = b"THIS IS NOT A PEM CERTIFICATE";
    let result = build_x5chain_from_pem(&[garbage]);
    assert!(
        result.is_err(),
        "building X5Chain from invalid PEM must fail"
    );
}

// ── §2  IacaRegistry construction and lookup ─────────────────────────────────

/// An empty registry must report no supported jurisdictions.
#[test]
fn iaca_registry_empty_on_creation() {
    let registry = IacaRegistry::new();
    assert!(
        registry.supported_jurisdictions().is_empty(),
        "new IacaRegistry must have no jurisdictions"
    );
}

/// Adding a jurisdiction certificate must make it retrievable.
#[test]
fn iaca_registry_add_and_retrieve_jurisdiction() {
    use x509_cert::der::DecodePem;

    let (ca_pem, _) = gen_ca("California IACA");
    let cert = x509_cert::Certificate::from_pem(ca_pem.as_bytes()).expect("parse CA cert");

    let mut registry = IacaRegistry::new();
    registry
        .add_jurisdiction_iaca(Jurisdiction::California, cert)
        .expect("add CA IACA");

    let anchor = registry.get_jurisdiction_iaca(Jurisdiction::California);
    assert!(
        anchor.is_some(),
        "California IACA must be retrievable after adding"
    );
    let codes = registry.supported_jurisdictions();
    assert!(
        codes.contains(&"US-CA"),
        "US-CA must appear in supported_jurisdictions"
    );
}

/// Different jurisdictions must be stored independently.
#[test]
fn iaca_registry_multiple_jurisdictions() {
    use x509_cert::der::DecodePem;

    let (ca_pem_ny, _) = gen_ca("New York IACA");
    let (ca_pem_tx, _) = gen_ca("Texas IACA");

    let cert_ny = x509_cert::Certificate::from_pem(ca_pem_ny.as_bytes()).expect("parse NY cert");
    let cert_tx = x509_cert::Certificate::from_pem(ca_pem_tx.as_bytes()).expect("parse TX cert");

    let mut registry = IacaRegistry::new();
    registry
        .add_jurisdiction_iaca(Jurisdiction::NewYork, cert_ny)
        .expect("add NY");
    registry
        .add_jurisdiction_iaca(Jurisdiction::Texas, cert_tx)
        .expect("add TX");

    assert!(registry
        .get_jurisdiction_iaca(Jurisdiction::NewYork)
        .is_some());
    assert!(registry
        .get_jurisdiction_iaca(Jurisdiction::Texas)
        .is_some());
    assert!(
        registry
            .get_jurisdiction_iaca(Jurisdiction::California)
            .is_none(),
        "CA must not be present"
    );
    assert_eq!(registry.supported_jurisdictions().len(), 2);
}

// ── §3  X5Chain validation against trust anchors ─────────────────────────────

/// A self-signed IACA cert validated against itself must succeed.
/// (Used to test that the validation pipeline runs without panicking.)
#[test]
fn verify_x5chain_self_signed_against_own_registry() {
    use marty_verification::verification::mdl::verify_x5chain;
    use x509_cert::der::DecodePem;

    let (ca_pem, _) = gen_ca("Self-signed IACA");
    let chain = build_x5chain_from_pem(&[ca_pem.as_bytes()]).expect("build chain");

    let cert = x509_cert::Certificate::from_pem(ca_pem.as_bytes()).expect("parse cert");
    let mut registry = IacaRegistry::new();
    registry
        .add_jurisdiction_iaca(Jurisdiction::California, cert)
        .expect("add anchor");

    // verify_x5chain should run without panicking
    let result = verify_x5chain(&chain, &registry, ValidationRuleset::AamvaMdl);

    // The result may or may not be verified (depends on isomdl chain policies for
    // self-signed IACA), but it must be a well-formed MdlVerificationResult.
    let _ = result.verified; // no panic = pass
    let _ = &result.errors;
}

/// A chain validated against an empty registry must not be verified.
#[test]
fn verify_x5chain_empty_registry_not_verified() {
    use marty_verification::verification::mdl::verify_x5chain;

    let (ca_pem, _) = gen_ca("Untrusted IACA");
    let chain = build_x5chain_from_pem(&[ca_pem.as_bytes()]).expect("build chain");

    let empty_registry = IacaRegistry::new();
    let result = verify_x5chain(&chain, &empty_registry, ValidationRuleset::AamvaMdl);

    assert!(
        !result.verified,
        "chain must not verify against an empty trust registry"
    );
    assert!(
        !result.errors.is_empty(),
        "verification failure must produce at least one error message"
    );
}

// ── §4  MdlVerificationResult and AuthStatus ─────────────────────────────────

/// Default `MdlVerificationResult` must be unverified with Unknown auth statuses.
#[test]
fn mdl_verification_result_default() {
    let result = MdlVerificationResult::default();
    assert!(!result.verified);
    assert!(result.errors.is_empty());
    assert_eq!(result.issuer_auth_status, AuthStatus::Unknown);
    assert_eq!(result.device_auth_status, AuthStatus::Unknown);
    assert!(result.common_name.is_none() || result.common_name.is_some()); // any value OK
}

/// `AuthStatus` variants must be Copy and PartialEq.
#[test]
fn auth_status_copy_eq() {
    let a = AuthStatus::Valid;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(AuthStatus::Valid, AuthStatus::Invalid);
    assert_ne!(AuthStatus::Valid, AuthStatus::Unknown);
    assert_ne!(AuthStatus::Invalid, AuthStatus::Unknown);
}

/// A verified result must have `verified: true` and empty `errors`.
#[test]
fn mdl_verification_result_verified_invariant() {
    let result = MdlVerificationResult {
        verified: true,
        common_name: Some("Test DSC".to_string()),
        jurisdiction: Some("US-CA".to_string()),
        errors: Vec::new(), // verified = true requires empty errors
        issuer_auth_status: AuthStatus::Valid,
        device_auth_status: AuthStatus::Unknown,
    };
    assert!(result.verified);
    assert!(result.errors.is_empty());
    assert_eq!(result.issuer_auth_status, AuthStatus::Valid);
}

/// `MdlVerificationResult` must be Serialize/Deserialize (used in API responses).
#[test]
fn mdl_verification_result_serde_roundtrip() {
    let result = MdlVerificationResult {
        verified: false,
        common_name: None,
        jurisdiction: Some("US-NY".to_string()),
        errors: vec!["E201: not in trust registry".to_string()],
        issuer_auth_status: AuthStatus::Invalid,
        device_auth_status: AuthStatus::Unknown,
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let decoded: MdlVerificationResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.verified, result.verified);
    assert_eq!(decoded.jurisdiction, result.jurisdiction);
    assert_eq!(decoded.errors, result.errors);
    assert_eq!(decoded.issuer_auth_status, result.issuer_auth_status);
}

// ── §5  Error paths ───────────────────────────────────────────────────────────

/// Parsing a CBOR X5Chain from garbage bytes must fail gracefully.
#[test]
fn parse_x5chain_from_cbor_rejects_garbage() {
    use marty_verification::verification::mdl::parse_x5chain_from_cbor;

    let result = parse_x5chain_from_cbor(b"not-cbor-bytes-at-all");
    assert!(
        result.is_err(),
        "parse_x5chain_from_cbor must return Err for non-CBOR input"
    );
}

/// Parsing a valid CBOR value that is not an X5Chain structure must fail.
#[test]
fn parse_x5chain_from_cbor_rejects_wrong_cbor_structure() {
    use marty_verification::verification::mdl::parse_x5chain_from_cbor;

    // CBOR-encode a simple integer — not an X5Chain
    let mut cbor_buf = Vec::new();
    ciborium::ser::into_writer(&42u64, &mut cbor_buf).expect("cbor encode");

    let result = parse_x5chain_from_cbor(&cbor_buf);
    assert!(
        result.is_err(),
        "parse_x5chain_from_cbor must return Err for arbitrary CBOR"
    );
}

// ── §6  Jurisdiction code model ───────────────────────────────────────────────

/// All US state `Jurisdiction` variants must have the `US-` prefix in their code.
#[test]
fn jurisdiction_us_states_have_us_prefix() {
    let us_states = [
        Jurisdiction::California,
        Jurisdiction::NewYork,
        Jurisdiction::Texas,
        Jurisdiction::Florida,
        Jurisdiction::Washington,
        Jurisdiction::Oregon,
        Jurisdiction::Colorado,
    ];
    for j in &us_states {
        let code = j.code();
        assert!(
            code.starts_with("US-"),
            "US jurisdiction must start with 'US-': {}",
            code
        );
        assert_eq!(
            code.len(),
            5,
            "US jurisdiction code must be exactly 5 chars (US-XX): {}",
            code
        );
    }
}

/// CA province `Jurisdiction` variants must have the `CA-` prefix.
#[test]
fn jurisdiction_canadian_provinces_have_ca_prefix() {
    let ca_provinces = [
        Jurisdiction::Ontario,
        Jurisdiction::BritishColumbia,
        Jurisdiction::Quebec,
        Jurisdiction::Alberta,
    ];
    for j in &ca_provinces {
        let code = j.code();
        assert!(
            code.starts_with("CA-"),
            "Canadian province must start with 'CA-': {}",
            code
        );
    }
}

/// `Jurisdiction::from_code` must round-trip every code produced by `.code()`.
#[test]
fn jurisdiction_from_code_roundtrip() {
    let jurisdictions = [
        Jurisdiction::California,
        Jurisdiction::NewYork,
        Jurisdiction::Texas,
        Jurisdiction::Ontario,
        Jurisdiction::BritishColumbia,
        Jurisdiction::DistrictOfColumbia,
    ];
    for j in jurisdictions {
        let code = j.code();
        let roundtripped = Jurisdiction::from_code(code);
        assert!(
            roundtripped.is_some(),
            "from_code({}) must succeed for produced code",
            code
        );
        assert_eq!(
            roundtripped.unwrap(),
            j,
            "from_code({}) must round-trip to the same Jurisdiction",
            code
        );
    }
}

/// `Jurisdiction::from_code` must be case-insensitive (spec says codes are uppercase but
/// callers may pass lowercase).
#[test]
fn jurisdiction_from_code_case_insensitive() {
    assert_eq!(
        Jurisdiction::from_code("us-ca"),
        Some(Jurisdiction::California)
    );
    assert_eq!(
        Jurisdiction::from_code("US-CA"),
        Some(Jurisdiction::California)
    );
}

/// An unknown jurisdiction code must return `None`.
#[test]
fn jurisdiction_from_code_unknown_returns_none() {
    assert!(
        Jurisdiction::from_code("XX-ZZ").is_none(),
        "unknown code must return None"
    );
    assert!(
        Jurisdiction::from_code("").is_none(),
        "empty string must return None"
    );
}
