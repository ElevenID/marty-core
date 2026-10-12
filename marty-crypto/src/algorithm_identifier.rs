//! Parameter-aware verification for ASN.1 signature algorithm identifiers.

use const_oid::ObjectIdentifier;
use der::asn1::AnyRef;
use rsa::pkcs1::RsaPssParams;
use spki::AlgorithmIdentifierOwned;

use crate::{CryptoError, CryptoResult, SignatureAlgorithm};

const RSA_PSS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const MGF1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const SHA512_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// Verify a signature using both the OID and parameters in an ASN.1
/// `AlgorithmIdentifier`.
///
/// RSASSA-PSS uses one OID for every digest and salt length, so dispatching on
/// the OID alone is ambiguous. This function validates the PSS hash, MGF1
/// digest, salt length, and trailer field before selecting the verifier. Other
/// supported algorithms retain the canonical OID-based dispatch.
pub fn verify_signature_with_algorithm_identifier(
    algorithm_identifier: &AlgorithmIdentifierOwned,
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    if algorithm_identifier.oid != RSA_PSS_OID {
        let algorithm = SignatureAlgorithm::from_oid(&algorithm_identifier.oid.to_string())?;
        return crate::verify_signature(algorithm, public_key_der, message, signature);
    }

    verify_rsa_pss_algorithm_identifier(algorithm_identifier, public_key_der, message, signature)
}

fn verify_rsa_pss_algorithm_identifier(
    algorithm_identifier: &AlgorithmIdentifierOwned,
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let encoded_parameters = algorithm_identifier
        .parameters
        .as_ref()
        .ok_or_else(|| CryptoError::unsupported_algorithm("RSASSA-PSS parameters are required"))?;
    let parameters = encoded_parameters
        .decode_as::<RsaPssParams<'_>>()
        .map_err(|error| {
            CryptoError::der_error(format!("invalid RSASSA-PSS parameters: {error}"))
        })?;

    validate_digest_parameters("RSASSA-PSS hash", parameters.hash.parameters)?;

    if parameters.mask_gen.oid != MGF1_OID {
        return Err(CryptoError::unsupported_algorithm(format!(
            "unsupported RSASSA-PSS mask generation function: {}",
            parameters.mask_gen.oid
        )));
    }
    let mask_hash = parameters.mask_gen.parameters.as_ref().ok_or_else(|| {
        CryptoError::unsupported_algorithm("RSASSA-PSS MGF1 hash parameters are required")
    })?;
    validate_digest_parameters("RSASSA-PSS MGF1 hash", mask_hash.parameters)?;
    if mask_hash.oid != parameters.hash.oid {
        return Err(CryptoError::unsupported_algorithm(format!(
            "RSASSA-PSS hash {} does not match MGF1 hash {}",
            parameters.hash.oid, mask_hash.oid
        )));
    }

    let salt_len = usize::from(parameters.salt_len);
    match parameters.hash.oid {
        SHA256_OID => crate::rsa::verify_pss_sha256_with_salt_len(
            public_key_der,
            message,
            signature,
            salt_len,
        ),
        SHA384_OID => crate::rsa::verify_pss_sha384_with_salt_len(
            public_key_der,
            message,
            signature,
            salt_len,
        ),
        SHA512_OID => crate::rsa::verify_pss_sha512_with_salt_len(
            public_key_der,
            message,
            signature,
            salt_len,
        ),
        oid => Err(CryptoError::unsupported_algorithm(format!(
            "unsupported RSASSA-PSS hash algorithm: {oid}"
        ))),
    }
}

fn validate_digest_parameters(label: &str, parameters: Option<AnyRef<'_>>) -> CryptoResult<()> {
    if parameters.is_some_and(|value| !value.is_null()) {
        return Err(CryptoError::unsupported_algorithm(format!(
            "{label} parameters must be absent or NULL"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use der::{asn1::Any, Decode, Encode};
    use sha2::{Sha256, Sha384, Sha512};
    use spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef};

    use super::*;

    fn pss_identifier(parameters: &RsaPssParams<'_>) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: RSA_PSS_OID,
            parameters: Some(Any::from_der(&parameters.to_der().unwrap()).unwrap()),
        }
    }

    fn public_vectors() -> [serde_json::Value; 3] {
        serde_json::from_str(include_str!(
            "../tests/fixtures/pss_algorithm_identifier_public.json"
        ))
        .unwrap()
    }

    fn signed_case(vector: &serde_json::Value) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            hex::decode(vector["public_key_der_hex"].as_str().unwrap()).unwrap(),
            vector["message_utf8"].as_str().unwrap().as_bytes().to_vec(),
            hex::decode(vector["signature_hex"].as_str().unwrap()).unwrap(),
        )
    }

    #[test]
    fn verifies_sha256_pss_with_declared_non_default_salt() {
        let [vector, _, _] = public_vectors();
        assert_eq!(vector["digest"], "SHA256");
        assert_eq!(vector["salt_len"], 17);
        let (public_der, message, signature) = signed_case(&vector);
        let identifier = pss_identifier(&RsaPssParams::new::<Sha256>(17));

        assert!(verify_signature_with_algorithm_identifier(
            &identifier,
            &public_der,
            &message,
            &signature,
        )
        .unwrap());

        let wrong_salt = pss_identifier(&RsaPssParams::new::<Sha256>(18));
        assert!(!verify_signature_with_algorithm_identifier(
            &wrong_salt,
            &public_der,
            &message,
            &signature,
        )
        .unwrap());
    }

    #[test]
    fn verifies_sha384_and_sha512_pss_parameters() {
        let [_, ps384, ps512] = public_vectors();
        assert_eq!(ps384["digest"], "SHA384");
        assert_eq!(ps384["salt_len"], 29);
        let (public_der, message, signature) = signed_case(&ps384);
        assert!(verify_signature_with_algorithm_identifier(
            &pss_identifier(&RsaPssParams::new::<Sha384>(29)),
            &public_der,
            &message,
            &signature,
        )
        .unwrap());

        assert_eq!(ps512["digest"], "SHA512");
        assert_eq!(ps512["salt_len"], 33);
        let (public_der, message, signature) = signed_case(&ps512);
        assert!(verify_signature_with_algorithm_identifier(
            &pss_identifier(&RsaPssParams::new::<Sha512>(33)),
            &public_der,
            &message,
            &signature,
        )
        .unwrap());
    }

    #[test]
    fn rejects_missing_sha1_and_mismatched_mgf_parameters() {
        let missing = AlgorithmIdentifierOwned {
            oid: RSA_PSS_OID,
            parameters: None,
        };
        let error =
            verify_signature_with_algorithm_identifier(&missing, &[], &[], &[]).unwrap_err();
        assert!(error.to_string().contains("parameters are required"));

        let sha1_defaults = pss_identifier(&RsaPssParams::default());
        let error =
            verify_signature_with_algorithm_identifier(&sha1_defaults, &[], &[], &[]).unwrap_err();
        assert!(error.to_string().contains("unsupported RSASSA-PSS hash"));

        let mut mismatched = RsaPssParams::new::<Sha256>(32);
        mismatched.mask_gen.parameters = Some(AlgorithmIdentifierRef {
            oid: SHA384_OID,
            parameters: Some(der::asn1::AnyRef::NULL),
        });
        let error =
            verify_signature_with_algorithm_identifier(&pss_identifier(&mismatched), &[], &[], &[])
                .unwrap_err();
        assert!(error.to_string().contains("does not match MGF1 hash"));

        let mut invalid_hash_parameters = RsaPssParams::new::<Sha256>(32);
        invalid_hash_parameters.hash.parameters =
            Some(der::asn1::AnyRef::new(der::Tag::OctetString, b"unexpected").unwrap());
        let error = verify_signature_with_algorithm_identifier(
            &pss_identifier(&invalid_hash_parameters),
            &[],
            &[],
            &[],
        )
        .unwrap_err();
        assert!(error.to_string().contains("must be absent or NULL"));
    }
}
