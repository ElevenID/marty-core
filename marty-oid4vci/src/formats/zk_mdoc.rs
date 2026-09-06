use crate::error::{Oid4vciError, Oid4vciResult};
use crate::formats::mdoc;
use crate::signer::CredentialSigner;
#[cfg(test)]
use crate::types::IssuerKey;
use crate::types::{CredentialClaims, SignedCredential, ZkPredicateBinding};

use super::ZK_PROOF_TYPE_LIGERO;

/// Sign a ZK-enabled mDoc credential.
///
/// Creates a standard mDoc credential via [`mdoc::sign_mdoc`] and wraps it
/// with ZK capability metadata.  The credential itself is structurally
/// identical to a plain `mso_mdoc` — the ZK metadata tells wallets and
/// verifiers which claims support predicate proofs and which predicates are
/// available for each claim.
///
/// # ZK Predicate Bindings
///
/// `CredentialClaims::zk_predicate_claims` is a `Vec<ZkPredicateBinding>`.
/// Each binding names an issuer-signed boolean predicate claim (for example,
/// `"age_over_18": true`) and must list that exact claim identifier as its
/// sole supported predicate. Longfellow proves inclusion of this signed value;
/// it does not derive age from a hidden birth date.
#[cfg(test)]
pub fn sign_zk_mdoc(
    issuer_key: &IssuerKey,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    validate_zk_predicate_claims(claims)?;

    let bindings: Vec<ZkPredicateBinding> = claims.zk_predicate_claims.clone();

    // Delegate actual mDoc construction to the standard signer.
    let mdoc_result = mdoc::sign_mdoc(issuer_key, claims)?;

    match mdoc_result {
        SignedCredential::MsoMdoc {
            issuer_signed_b64,
            credential_id,
        } => Ok(SignedCredential::ZkMdoc {
            issuer_signed_b64,
            zk_predicate_bindings: bindings,
            zk_proof_type: ZK_PROOF_TYPE_LIGERO.to_string(),
            credential_id,
        }),
        _ => Err(Oid4vciError::SigningError(
            "Internal error: mdoc signer returned unexpected format".into(),
        )),
    }
}

/// Sign a ZK-enabled mDoc credential using any [`CredentialSigner`].
///
/// Production callers provide a [`CredentialSigner`] implementation that
/// delegates to their remote KMS/HSM. Local JWK signing exists only in the
/// crate's fixture-only `cfg(test)` path.
///
/// The ZK wrapping (predicate bindings + proof type) is applied identically to
/// the fixture path; only the underlying mDoc COSE signing is delegated to the
/// external signer.
pub fn sign_zk_mdoc_with_signer(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    validate_zk_predicate_claims(claims)?;

    let bindings: Vec<ZkPredicateBinding> = claims.zk_predicate_claims.clone();

    // Delegate actual mDoc COSE signing to the external signer.
    let mdoc_result = mdoc::sign_mdoc_with_signer(signer, claims)?;

    match mdoc_result {
        SignedCredential::MsoMdoc {
            issuer_signed_b64,
            credential_id,
        } => Ok(SignedCredential::ZkMdoc {
            issuer_signed_b64,
            zk_predicate_bindings: bindings,
            zk_proof_type: ZK_PROOF_TYPE_LIGERO.to_string(),
            credential_id,
        }),
        _ => Err(Oid4vciError::SigningError(
            "Internal error: mdoc signer returned unexpected format".into(),
        )),
    }
}

fn validate_zk_predicate_claims(claims: &CredentialClaims) -> Oid4vciResult<()> {
    if claims.zk_predicate_claims.is_empty() {
        return Err(Oid4vciError::ConfigError(
            "ZK mDoc requires at least one ZkPredicateBinding in zk_predicate_claims.".into(),
        ));
    }

    for binding in &claims.zk_predicate_claims {
        let Some(value) = claims.claims.get(&binding.claim_name) else {
            return Err(Oid4vciError::ConfigError(format!(
                "ZK predicate binding references claim '{}' which is not \
                 present in credential claims. Available claims: {:?}",
                binding.claim_name,
                claims.claims.keys().collect::<Vec<_>>()
            )));
        };
        if !value.is_boolean() {
            return Err(Oid4vciError::ConfigError(format!(
                "ZK predicate claim '{}' must be an issuer-computed boolean",
                binding.claim_name
            )));
        }
        if binding.supported_predicates.as_slice() != [binding.claim_name.as_str()]
            || !matches!(
                marty_zkp::ZkPredicate::from_id(&binding.claim_name),
                marty_zkp::ZkPredicate::AgeOver(18 | 21)
            )
        {
            return Err(Oid4vciError::ConfigError(format!(
                "ZK predicate binding '{}' must name one registered, identically named age_over_N boolean claim",
                binding.claim_name
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SigningAlgorithm;
    use ssi_jwk::JWK;

    fn test_p256_key() -> IssuerKey {
        let jwk = JWK::generate_p256();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        IssuerKey {
            issuer_id: "did:example:issuer".into(),
            jwk_json,
            algorithm: SigningAlgorithm::ES256,
        }
    }

    fn age_over_18_binding() -> ZkPredicateBinding {
        ZkPredicateBinding::single("age_over_18", "age_over_18")
    }

    #[test]
    fn test_sign_zk_mdoc_with_signed_age_predicate() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: [
                ("birth_date".into(), serde_json::json!("1990-01-15")),
                ("age_over_18".into(), serde_json::json!(true)),
                ("family_name".into(), serde_json::json!("Smith")),
                ("given_name".into(), serde_json::json!("Alice")),
            ]
            .into(),
            expiration_seconds: Some(86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![age_over_18_binding()],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let result = sign_zk_mdoc(&key, &claims).unwrap();
        match result {
            SignedCredential::ZkMdoc {
                issuer_signed_b64,
                zk_predicate_bindings,
                zk_proof_type,
                credential_id,
            } => {
                assert!(!issuer_signed_b64.is_empty());
                assert_eq!(zk_predicate_bindings.len(), 1);
                assert_eq!(zk_predicate_bindings[0].claim_name, "age_over_18");
                assert!(zk_predicate_bindings[0]
                    .supported_predicates
                    .contains(&"age_over_18".to_string()));
                assert_eq!(zk_proof_type, ZK_PROOF_TYPE_LIGERO);
                assert!(credential_id.starts_with("urn:uuid:"));
            }
            _ => panic!("Expected ZkMdoc"),
        }
    }

    #[test]
    fn test_sign_zk_mdoc_invalid_claim() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: None,
            credential_type: "TestCred".into(),
            claims: [("name".into(), serde_json::json!("Alice"))].into(),
            expiration_seconds: None,
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![ZkPredicateBinding::single(
                "nonexistent_claim",
                "age_over_18",
            )],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let err = sign_zk_mdoc(&key, &claims).unwrap_err();
        assert!(err.to_string().contains("nonexistent_claim"));
    }

    #[test]
    fn rejects_legacy_birth_date_derivation_and_unregistered_thresholds() {
        let key = test_p256_key();
        let base_claims = || CredentialClaims {
            subject_id: None,
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: [("birth_date".into(), serde_json::json!("1990-01-15"))].into(),
            expiration_seconds: None,
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![ZkPredicateBinding::single("birth_date", "age_over_18")],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let error = sign_zk_mdoc(&key, &base_claims()).unwrap_err();
        assert!(error.to_string().contains("issuer-computed boolean"));

        let mut unsupported = base_claims();
        unsupported
            .claims
            .insert("age_over_17".into(), serde_json::json!(true));
        unsupported.zk_predicate_claims =
            vec![ZkPredicateBinding::single("age_over_17", "age_over_17")];
        let error = sign_zk_mdoc(&key, &unsupported).unwrap_err();
        assert!(error.to_string().contains("registered"));
    }

    #[test]
    fn test_sign_zk_mdoc_no_zk_claims() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: None,
            credential_type: "GenericCred".into(),
            claims: [("name".into(), serde_json::json!("Alice"))].into(),
            expiration_seconds: None,
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let err = sign_zk_mdoc(&key, &claims).unwrap_err();
        assert!(err.to_string().contains("at least one ZkPredicateBinding"));
    }

    // -------------------------------------------------------------------------
    // sign_zk_mdoc_with_signer tests (GAP-001)
    // -------------------------------------------------------------------------

    /// A minimal CredentialSigner backed by a fresh P-256 JWK, used to test
    /// the external-signer path without pulling in KMS infrastructure.
    struct TestP256Signer {
        jwk: JWK,
    }

    impl std::fmt::Debug for TestP256Signer {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("TestP256Signer([redacted])")
        }
    }

    impl TestP256Signer {
        fn new() -> Self {
            Self {
                jwk: JWK::generate_p256(),
            }
        }
    }

    impl crate::signer::CredentialSigner for TestP256Signer {
        fn sign(&self, message: &[u8]) -> crate::error::Oid4vciResult<Vec<u8>> {
            crate::signer::sign_with_jwk(&self.jwk, message)
        }

        fn algorithm(&self) -> crate::types::SigningAlgorithm {
            crate::types::SigningAlgorithm::ES256
        }

        fn issuer_id(&self) -> &str {
            "did:example:kms-issuer"
        }

        fn kid_url(&self) -> String {
            "did:example:kms-issuer#key-1".into()
        }
    }

    #[test]
    fn test_p256_signer_debug_is_stably_redacted() {
        let signer = TestP256Signer::new();
        let private_jwk = serde_json::to_value(&signer.jwk).unwrap();
        let private_d = private_jwk
            .get("d")
            .and_then(serde_json::Value::as_str)
            .unwrap();
        let diagnostic = format!("{signer:#?}");

        assert_eq!(diagnostic, "TestP256Signer([redacted])");
        assert!(!diagnostic.contains(private_d));
    }

    #[test]
    fn test_sign_zk_mdoc_with_signer_produces_zk_mdoc() {
        let signer = TestP256Signer::new();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: [
                ("birth_date".into(), serde_json::json!("1985-07-04")),
                ("age_over_18".into(), serde_json::json!(true)),
                ("family_name".into(), serde_json::json!("KmsUser")),
            ]
            .into(),
            expiration_seconds: Some(86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![age_over_18_binding()],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let result = sign_zk_mdoc_with_signer(&signer, &claims).unwrap();
        match result {
            SignedCredential::ZkMdoc {
                issuer_signed_b64,
                zk_predicate_bindings,
                zk_proof_type,
                credential_id,
            } => {
                assert!(
                    !issuer_signed_b64.is_empty(),
                    "issuer_signed_b64 should not be empty"
                );
                assert_eq!(zk_predicate_bindings.len(), 1);
                assert_eq!(zk_predicate_bindings[0].claim_name, "age_over_18");
                assert!(zk_predicate_bindings[0]
                    .supported_predicates
                    .contains(&"age_over_18".to_string()));
                assert_eq!(zk_proof_type, ZK_PROOF_TYPE_LIGERO);
                assert!(credential_id.starts_with("urn:uuid:"));
            }
            _ => panic!("Expected ZkMdoc, got a different SignedCredential variant"),
        }
    }

    #[test]
    fn test_sign_zk_mdoc_with_signer_rejects_missing_claim() {
        let signer = TestP256Signer::new();
        let claims = CredentialClaims {
            subject_id: None,
            credential_type: "TestCred".into(),
            claims: [("name".into(), serde_json::json!("Alice"))].into(),
            expiration_seconds: None,
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![ZkPredicateBinding::single("age_over_18", "age_over_18")],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let err = sign_zk_mdoc_with_signer(&signer, &claims).unwrap_err();
        assert!(err.to_string().contains("age_over_18"));
    }

    #[test]
    fn test_sign_zk_mdoc_with_signer_rejects_empty_bindings() {
        let signer = TestP256Signer::new();
        let claims = CredentialClaims {
            subject_id: None,
            credential_type: "GenericCred".into(),
            claims: [("name".into(), serde_json::json!("Alice"))].into(),
            expiration_seconds: None,
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let err = sign_zk_mdoc_with_signer(&signer, &claims).unwrap_err();
        assert!(err.to_string().contains("at least one ZkPredicateBinding"));
    }
}
