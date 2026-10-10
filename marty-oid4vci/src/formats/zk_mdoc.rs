use crate::error::{Oid4vciError, Oid4vciResult};
use crate::formats::mdoc;
use crate::signer::CredentialSigner;
use crate::types::{CredentialClaims, SignedCredential, ZkPredicateBinding};

use super::ZK_PROOF_TYPE_LIGERO;

/// Sign a ZK-enabled mDoc credential using any [`CredentialSigner`].
///
/// Production callers provide a [`CredentialSigner`] implementation that
/// delegates to their remote KMS/HSM.
///
/// The ZK wrapping adds predicate bindings and proof type to a remotely
/// signed mDoc credential.
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

    #[test]
    fn rejects_legacy_birth_date_derivation_and_unregistered_thresholds() {
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

        let error = validate_zk_predicate_claims(&base_claims()).unwrap_err();
        assert!(error.to_string().contains("issuer-computed boolean"));

        let mut unsupported = base_claims();
        unsupported
            .claims
            .insert("age_over_17".into(), serde_json::json!(true));
        unsupported.zk_predicate_claims =
            vec![ZkPredicateBinding::single("age_over_17", "age_over_17")];
        let error = validate_zk_predicate_claims(&unsupported).unwrap_err();
        assert!(error.to_string().contains("registered"));
    }

    #[test]
    fn accepts_registered_boolean_binding() {
        let mut claims = CredentialClaims {
            subject_id: None,
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: [("age_over_18".into(), serde_json::json!(true))].into(),
            expiration_seconds: None,
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };
        claims.zk_predicate_claims = vec![ZkPredicateBinding::single("age_over_18", "age_over_18")];
        assert!(validate_zk_predicate_claims(&claims).is_ok());
    }

    #[test]
    fn rejects_missing_claim() {
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

        let err = validate_zk_predicate_claims(&claims).unwrap_err();
        assert!(err.to_string().contains("age_over_18"));
    }

    #[test]
    fn rejects_empty_bindings() {
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

        let err = validate_zk_predicate_claims(&claims).unwrap_err();
        assert!(err.to_string().contains("at least one ZkPredicateBinding"));
    }
}
