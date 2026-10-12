//! DIDComm v2.1 public-recipient anoncrypt support.
//!
//! Credential-delivery sender authentication uses the native remote-KMS
//! boundary. This crate never accepts a long-lived sender or recipient private
//! key. Anonymous encryption creates only an ephemeral sender agreement key.

use affinidi_messaging_didcomm::crypto::key_agreement::{Curve, PublicKeyAgreement};
use affinidi_messaging_didcomm::jwe::encrypt;

use crate::error::{DidcommError, DidcommResult};
use crate::types::DidDocument;

/// Largest plaintext accepted for one DIDComm encrypted envelope.
pub const MAX_DIDCOMM_PLAINTEXT_BYTES: usize = 1024 * 1024;
/// Largest recipient set accepted in one DIDComm encrypted envelope.
pub const MAX_DIDCOMM_RECIPIENTS: usize = 128;

/// Encrypt a DIDComm plaintext message for the first compatible X25519 key in
/// the resolved recipient DID Document.
///
/// The resulting JWE uses DIDComm v2.1 anoncrypt (`ECDH-ES+A256KW`) with the
/// required `A256CBC-HS512` content-encryption algorithm.  The ephemeral key,
/// recipient hash (`apv`), algorithm, and media type are integrity protected.
pub fn encrypt_for_recipient(
    plaintext: &str,
    recipient_did_doc: &DidDocument,
) -> DidcommResult<String> {
    if plaintext.len() > MAX_DIDCOMM_PLAINTEXT_BYTES {
        return Err(DidcommError::PackError(
            "DIDComm plaintext exceeds the configured size limit".into(),
        ));
    }
    let recipient_keys = authorized_x25519_methods(recipient_did_doc)?;
    let recipients = public_keys(&recipient_keys, "recipient")?;
    let recipient_refs = recipients
        .iter()
        .map(|(kid, key)| (kid.as_str(), key))
        .collect::<Vec<_>>();

    encrypt::anoncrypt(plaintext.as_bytes(), &recipient_refs)
        .map_err(|error| DidcommError::Crypto(format!("DIDComm anoncrypt failed: {error}")))
}

fn authorized_x25519_methods(document: &DidDocument) -> DidcommResult<Vec<(String, [u8; 32])>> {
    let methods = document.x25519_key_agreement_methods().map_err(|reason| {
        DidcommError::ResolutionFailed {
            did: document.id.clone(),
            reason,
        }
    })?;
    if methods.len() > MAX_DIDCOMM_RECIPIENTS {
        Err(DidcommError::ResolutionFailed {
            did: document.id.clone(),
            reason: "DID document authorizes too many X25519 recipient methods".into(),
        })
    } else if methods.is_empty() {
        Err(DidcommError::NoKeyAgreementKey {
            did: document.id.clone(),
        })
    } else {
        Ok(methods)
    }
}

fn public_keys(
    methods: &[(String, [u8; 32])],
    role: &str,
) -> DidcommResult<Vec<(String, PublicKeyAgreement)>> {
    methods
        .iter()
        .map(|(kid, key)| {
            PublicKeyAgreement::from_raw_bytes(Curve::X25519, key)
                .map(|public| (kid.clone(), public))
                .map_err(|error| {
                    DidcommError::Crypto(format!("invalid {role} X25519 key: {error}"))
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn public_recipient_document() -> DidDocument {
        // The X25519 generator point is public data; no recipient private key
        // is constructed by this test or by the anoncrypt API.
        let mut point = [0u8; 32];
        point[0] = 9;
        let x = URL_SAFE_NO_PAD.encode(point);
        serde_json::from_value(serde_json::json!({
            "id": "did:example:bob",
            "verificationMethod": [{
                "id": "did:example:bob#x25519-1",
                "type": "JsonWebKey2020",
                "controller": "did:example:bob",
                "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": x}
            }],
            "keyAgreement": ["did:example:bob#x25519-1"]
        }))
        .unwrap()
    }

    #[test]
    fn public_recipient_anoncrypt_has_normative_protected_profile() {
        let document = public_recipient_document();
        let envelope =
            encrypt_for_recipient(r#"{"id":"message-1","type":"test"}"#, &document).unwrap();
        let jwe: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        let protected = URL_SAFE_NO_PAD
            .decode(jwe["protected"].as_str().unwrap())
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&protected).unwrap();
        assert_eq!(header["typ"], "application/didcomm-encrypted+json");
        assert_eq!(header["alg"], "ECDH-ES+A256KW");
        assert_eq!(header["enc"], "A256CBC-HS512");
        assert_eq!(header["epk"]["kty"], "OKP");
        assert_eq!(header["epk"]["crv"], "X25519");
        assert!(header["apv"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(header.get("apu").is_none());
        assert!(header.get("skid").is_none());
        assert_eq!(
            jwe["recipients"][0]["header"]["kid"],
            "did:example:bob#x25519-1"
        );
    }

    #[test]
    fn public_recipient_anoncrypt_rejects_missing_authorization_and_oversize() {
        let mut document = public_recipient_document();
        assert!(
            encrypt_for_recipient(&"x".repeat(MAX_DIDCOMM_PLAINTEXT_BYTES + 1), &document).is_err()
        );
        document.key_agreement.clear();
        assert!(encrypt_for_recipient("message", &document).is_err());
    }
}
