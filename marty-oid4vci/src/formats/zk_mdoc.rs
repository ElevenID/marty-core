use crate::error::{Oid4vciError, Oid4vciResult};
use crate::formats::mdoc;
use crate::signer::CredentialSigner;
use crate::types::{CredentialClaims, IssuerKey, SignedCredential, ZkPredicateBinding};

/// The ZK proof protocol identifier used by Longfellow/Ligero.
pub const ZK_PROOF_TYPE_LIGERO: &str = "longfellow-zk-ligero";

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
/// Each binding names an mDoc claim (e.g. `"birth_date"`) and lists the
/// predicates the wallet may prove from it (e.g. `["age_over_18", "age_over_21"]`).
/// Adding new predicates requires only updating the binding at issuance time
/// and ensuring `marty-zkp` implements the matching circuit.
pub fn sign_zk_mdoc(
    issuer_key: &IssuerKey,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    // Validate: every bound claim must exist in the credential.
    for binding in &claims.zk_predicate_claims {
        if !claims.claims.contains_key(&binding.claim_name) {
            return Err(Oid4vciError::ConfigError(format!(
                "ZK predicate binding references claim '{}' which is not \
                 present in credential claims. Available claims: {:?}",
                binding.claim_name,
                claims.claims.keys().collect::<Vec<_>>()
            )));
        }
        if binding.supported_predicates.is_empty() {
            return Err(Oid4vciError::ConfigError(format!(
                "ZK predicate binding for claim '{}' must list at least \
                 one supported predicate.",
                binding.claim_name
            )));
        }
    }

    if claims.zk_predicate_claims.is_empty() {
        return Err(Oid4vciError::ConfigError(
            "ZK mDoc requires at least one ZkPredicateBinding in \
             zk_predicate_claims."
                .into(),
        ));
    }

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
/// This is the BYOK-aware variant of [`sign_zk_mdoc`]. For local JWK signing,
/// pass an `&IssuerKey`. For remote/KMS signing, pass a custom
/// [`CredentialSigner`] implementation.
///
/// The ZK wrapping (predicate bindings + proof type) is applied identically to
/// [`sign_zk_mdoc`] — only the underlying mDoc COSE signing is delegated to the
/// external signer.
pub fn sign_zk_mdoc_with_signer(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    // Apply the same predicate-binding validation as the local-key path.
    for binding in &claims.zk_predicate_claims {
        if !claims.claims.contains_key(&binding.claim_name) {
            return Err(Oid4vciError::ConfigError(format!(
                "ZK predicate binding references claim '{}' which is not \
                 present in credential claims. Available claims: {:?}",
                binding.claim_name,
                claims.claims.keys().collect::<Vec<_>>()
            )));
        }
        if binding.supported_predicates.is_empty() {
            return Err(Oid4vciError::ConfigError(format!(
                "ZK predicate binding for claim '{}' must list at least \
                 one supported predicate.",
                binding.claim_name
            )));
        }
    }

    if claims.zk_predicate_claims.is_empty() {
        return Err(Oid4vciError::ConfigError(
            "ZK mDoc requires at least one ZkPredicateBinding in \
             zk_predicate_claims."
                .into(),
        ));
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SigningAlgorithm;
    use ssi::jwk::JWK;

    fn test_p256_key() -> IssuerKey {
        let jwk = JWK::generate_p256();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        IssuerKey {
            issuer_id: "did:example:issuer".into(),
            jwk_json,
            algorithm: SigningAlgorithm::ES256,
        }
    }

    fn birth_date_binding() -> ZkPredicateBinding {
        ZkPredicateBinding::multi(
            "birth_date",
            vec!["age_over_18".into(), "age_over_21".into()],
        )
    }

    #[test]
    fn test_sign_zk_mdoc_with_birth_date() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: [
                ("birth_date".into(), serde_json::json!("1990-01-15")),
                ("family_name".into(), serde_json::json!("Smith")),
                ("given_name".into(), serde_json::json!("Alice")),
            ]
            .into(),
            expiration_seconds: Some(86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![birth_date_binding()],
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
                assert_eq!(zk_predicate_bindings[0].claim_name, "birth_date");
                assert!(zk_predicate_bindings[0]
                    .supported_predicates
                    .contains(&"age_over_18".to_string()));
                assert!(zk_predicate_bindings[0]
                    .supported_predicates
                    .contains(&"age_over_21".to_string()));
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
    #[derive(Debug)]
    struct TestP256Signer {
        jwk: JWK,
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
    fn test_sign_zk_mdoc_with_signer_produces_zk_mdoc() {
        let signer = TestP256Signer::new();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: [
                ("birth_date".into(), serde_json::json!("1985-07-04")),
                ("family_name".into(), serde_json::json!("KmsUser")),
            ]
            .into(),
            expiration_seconds: Some(86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![birth_date_binding()],
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
                assert_eq!(zk_predicate_bindings[0].claim_name, "birth_date");
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
            zk_predicate_claims: vec![ZkPredicateBinding::single("birth_date", "age_over_18")],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let err = sign_zk_mdoc_with_signer(&signer, &claims).unwrap_err();
        assert!(err.to_string().contains("birth_date"));
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
