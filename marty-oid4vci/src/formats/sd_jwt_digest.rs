//! SD-JWT digest selection and explicit admission, separate from JWS algorithms.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{Oid4vciError, Oid4vciResult};

pub use sd_jwt_rs::SDJWTDigestAlgorithm as SdJwtDigestAlgorithm;

pub(super) const DEFAULT_DIGEST_ALGORITHMS: &[SdJwtDigestAlgorithm] =
    &[SdJwtDigestAlgorithm::Sha256];

pub(crate) fn admitted_digest_algorithm(
    payload: &serde_json::Value,
    admitted: &[SdJwtDigestAlgorithm],
) -> Oid4vciResult<SdJwtDigestAlgorithm> {
    let selected = match payload.get("_sd_alg") {
        None => SdJwtDigestAlgorithm::Sha256,
        Some(serde_json::Value::String(name)) => match name.as_str() {
            "sha-256" => SdJwtDigestAlgorithm::Sha256,
            "sha-384" => SdJwtDigestAlgorithm::Sha384,
            "sha-512" => SdJwtDigestAlgorithm::Sha512,
            _ => return Err(digest_policy_error()),
        },
        Some(_) => return Err(digest_policy_error()),
    };
    if !admitted.contains(&selected) {
        return Err(digest_policy_error());
    }
    Ok(selected)
}

pub(super) fn digest_policy_error() -> Oid4vciError {
    Oid4vciError::SdJwtError("SD-JWT digest algorithm is not admitted by policy".into())
}

pub(super) fn digest_base64(algorithm: SdJwtDigestAlgorithm, input: &[u8]) -> String {
    match algorithm {
        SdJwtDigestAlgorithm::Sha256 => URL_SAFE_NO_PAD.encode(Sha256::digest(input)),
        SdJwtDigestAlgorithm::Sha384 => URL_SAFE_NO_PAD.encode(Sha384::digest(input)),
        SdJwtDigestAlgorithm::Sha512 => URL_SAFE_NO_PAD.encode(Sha512::digest(input)),
    }
}

#[cfg(any(test, feature = "issuer"))]
pub(super) fn executor_algorithm(
    algorithm: SdJwtDigestAlgorithm,
) -> isomdl::definitions::DigestAlgorithm {
    match algorithm {
        SdJwtDigestAlgorithm::Sha256 => isomdl::definitions::DigestAlgorithm::SHA256,
        SdJwtDigestAlgorithm::Sha384 => isomdl::definitions::DigestAlgorithm::SHA384,
        SdJwtDigestAlgorithm::Sha512 => isomdl::definitions::DigestAlgorithm::SHA512,
    }
}

#[cfg(any(test, feature = "issuer"))]
pub(super) fn digest_length(algorithm: SdJwtDigestAlgorithm) -> usize {
    match algorithm {
        SdJwtDigestAlgorithm::Sha256 => 32,
        SdJwtDigestAlgorithm::Sha384 => 48,
        SdJwtDigestAlgorithm::Sha512 => 64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn digest_admission_defaults_to_sha256_and_never_falls_back_on_invalid_selectors() {
        assert_eq!(
            admitted_digest_algorithm(&json!({}), DEFAULT_DIGEST_ALGORITHMS).unwrap(),
            SdJwtDigestAlgorithm::Sha256
        );
        for value in [
            json!(null),
            json!(1),
            json!(false),
            json!([]),
            json!({}),
            json!("SHA-256"),
            json!("sha-1"),
            json!("private-selector-canary"),
        ] {
            let error = admitted_digest_algorithm(
                &json!({"_sd_alg": value}),
                &[
                    SdJwtDigestAlgorithm::Sha256,
                    SdJwtDigestAlgorithm::Sha384,
                    SdJwtDigestAlgorithm::Sha512,
                ],
            )
            .unwrap_err();
            assert!(!error.to_string().contains("private-selector-canary"));
        }
        for algorithm in [
            SdJwtDigestAlgorithm::Sha256,
            SdJwtDigestAlgorithm::Sha384,
            SdJwtDigestAlgorithm::Sha512,
        ] {
            let payload = json!({"_sd_alg": algorithm.name()});
            assert_eq!(
                admitted_digest_algorithm(&payload, &[algorithm]).unwrap(),
                algorithm
            );
            assert!(admitted_digest_algorithm(&payload, &[]).is_err());
            assert_eq!(
                admitted_digest_algorithm(&payload, DEFAULT_DIGEST_ALGORITHMS).is_ok(),
                algorithm == SdJwtDigestAlgorithm::Sha256
            );
        }
    }
}
