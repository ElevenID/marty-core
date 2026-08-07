//! DIDComm v2.1 encrypted-envelope support.
//!
//! Marty deliberately delegates JOSE envelope construction to the maintained
//! `affinidi-messaging-didcomm` implementation.  Keeping a second, partial
//! implementation here previously allowed Marty-produced messages to decrypt
//! with Marty while omitting DIDComm's protected `epk` and `apv` headers.
//!
//! The public Marty API remains intentionally narrow: credential delivery uses
//! anonymous encryption for one resolved holder DID. The dependency supplies
//! the envelope primitives Marty uses and provides an upgrade path for
//! authcrypt. Signed envelopes, mediator routing, and broader curve/algorithm
//! support remain explicit product capabilities to implement and test rather
//! than implied claims of this wrapper.

use affinidi_messaging_didcomm::crypto::key_agreement::{
    Curve, PrivateKeyAgreement, PublicKeyAgreement,
};
use affinidi_messaging_didcomm::jwe::{decrypt, encrypt};

use crate::error::{DidcommError, DidcommResult};
use crate::types::DidDocument;

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
    let recipient_key_bytes = recipient_did_doc.x25519_key_agreement().ok_or_else(|| {
        DidcommError::NoKeyAgreementKey {
            did: recipient_did_doc.id.clone(),
        }
    })?;
    let recipient_kid =
        recipient_did_doc
            .x25519_key_id()
            .ok_or_else(|| DidcommError::NoKeyAgreementKey {
                did: recipient_did_doc.id.clone(),
            })?;
    let recipient_public = PublicKeyAgreement::from_raw_bytes(Curve::X25519, &recipient_key_bytes)
        .map_err(|error| DidcommError::Crypto(format!("invalid recipient X25519 key: {error}")))?;

    encrypt::anoncrypt(
        plaintext.as_bytes(),
        &[(recipient_kid.as_str(), &recipient_public)],
    )
    .map_err(|error| DidcommError::Crypto(format!("DIDComm anoncrypt failed: {error}")))
}

/// Decrypt a single-recipient DIDComm v2.1 anoncrypt JWE.
///
/// This compatibility entry point retains the existing Python/Rust API while
/// delegating all protected-header, key-derivation, key-wrap, and content-
/// authentication validation to the maintained DIDComm implementation.
pub fn decrypt_jwe(jwe_json: &str, recipient_private_key: &[u8; 32]) -> DidcommResult<String> {
    let jwe: serde_json::Value = serde_json::from_str(jwe_json)
        .map_err(|error| DidcommError::UnpackError(format!("invalid JWE JSON: {error}")))?;
    let recipient_kid = jwe
        .get("recipients")
        .and_then(serde_json::Value::as_array)
        .and_then(|recipients| recipients.first())
        .and_then(|recipient| recipient.pointer("/header/kid"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| DidcommError::UnpackError("missing recipient kid".into()))?;

    let recipient_private =
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, recipient_private_key).map_err(
            |error| DidcommError::Crypto(format!("invalid recipient X25519 key: {error}")),
        )?;
    let decrypted = decrypt::decrypt(jwe_json, recipient_kid, &recipient_private, None)
        .map_err(|error| DidcommError::UnpackError(format!("DIDComm decrypt failed: {error}")))?;

    if decrypted.authenticated || decrypted.sender_kid.is_some() {
        return Err(DidcommError::UnpackError(
            "authenticated DIDComm envelope is not valid for the anoncrypt API".into(),
        ));
    }

    String::from_utf8(decrypted.plaintext)
        .map_err(|error| DidcommError::UnpackError(format!("plaintext is not UTF-8: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // DIDComm Messaging 2.1 Appendix C, X25519 authcrypt example. Keep this
    // fixture byte-for-byte aligned with the published normative vector:
    // https://identity.foundation/didcomm-messaging/spec/v2.1/#appendix-c-encrypted-message-examples
    const OFFICIAL_AUTHCRYPT_X25519_A256CBC: &str = r#"
{
    "ciphertext": "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
    "protected": "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
    "recipients": [{
            "encrypted_key": "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
            "header": {
                "kid": "did:example:bob#key-x25519-1"
            }
        },{
            "encrypted_key": "rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
            "header": {
                "kid": "did:example:bob#key-x25519-2"
            }
        },{
            "encrypted_key": "aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
            "header": {
                "kid": "did:example:bob#key-x25519-3"
            }
        }],
    "tag": "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
    "iv": "o02OXDQ6_-sKz2PX_6oyJg"
}
"#;

    const OFFICIAL_PLAINTEXT: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "from": "did:example:alice",
    "to": ["did:example:bob"],
    "created_time": 1516269022,
    "expires_time": 1516385931,
    "body": {"messagespecificattribute": "and its value"}
}
"#;

    fn recipient_fixture() -> (DidDocument, [u8; 32]) {
        let recipient_private = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient_private_bytes = match &recipient_private {
            PrivateKeyAgreement::X25519(secret) => secret.to_bytes(),
            _ => unreachable!("fixture explicitly generates an X25519 key"),
        };
        let recipient_public = recipient_private.public_key();
        let recipient_public_jwk = recipient_public.to_jwk();

        let did_doc = DidDocument {
            id: "did:example:bob".into(),
            context: serde_json::json!("https://www.w3.org/ns/did/v1"),
            authentication: vec![],
            key_agreement: vec![],
            verification_method: vec![crate::types::VerificationMethod {
                id: "did:example:bob#key-x25519-1".into(),
                r#type: "JsonWebKey2020".into(),
                controller: "did:example:bob".into(),
                public_key_jwk: Some(crate::types::Jwk {
                    kty: "OKP".into(),
                    crv: Some("X25519".into()),
                    x: recipient_public_jwk
                        .get("x")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                    y: None,
                    d: None,
                    kid: None,
                }),
                public_key_multibase: None,
                public_key_base58: None,
            }],
            service: vec![],
        };

        (did_doc, recipient_private_bytes)
    }

    fn decode_protected_header(jwe: &serde_json::Value) -> serde_json::Value {
        let protected = jwe["protected"]
            .as_str()
            .expect("JWE must have a protected header");
        let decoded = URL_SAFE_NO_PAD
            .decode(protected)
            .expect("protected header must be base64url");
        serde_json::from_slice(&decoded).expect("protected header must be JSON")
    }

    #[test]
    fn encrypts_with_normative_didcomm_v2_1_headers() {
        let (did_doc, _) = recipient_fixture();
        let encrypted = encrypt_for_recipient(r#"{"id":"message-1","type":"test"}"#, &did_doc)
            .expect("DIDComm encryption must succeed");
        let jwe: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
        let protected = decode_protected_header(&jwe);

        assert_eq!(protected["typ"], "application/didcomm-encrypted+json");
        assert_eq!(protected["alg"], "ECDH-ES+A256KW");
        assert_eq!(protected["enc"], "A256CBC-HS512");
        assert_eq!(protected["epk"]["kty"], "OKP");
        assert_eq!(protected["epk"]["crv"], "X25519");
        assert!(protected["apv"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(protected.get("apu").is_none());
        assert_eq!(
            jwe["recipients"][0]["header"]["kid"],
            "did:example:bob#key-x25519-1"
        );
        assert!(jwe["recipients"][0]["header"].get("epk").is_none());
    }

    #[test]
    fn underlying_engine_decrypts_unmodified_official_didcomm_v2_1_vector() {
        let recipient_private_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode("b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0")
            .expect("official Bob private key must be base64url")
            .try_into()
            .expect("official Bob X25519 private key must be 32 bytes");
        let recipient_private =
            PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &recipient_private_bytes).unwrap();
        let sender_public = PublicKeyAgreement::from_jwk(&serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
        }))
        .unwrap();

        let decrypted = decrypt::decrypt(
            OFFICIAL_AUTHCRYPT_X25519_A256CBC,
            "did:example:bob#key-x25519-1",
            &recipient_private,
            Some(&sender_public),
        )
        .expect("the published DIDComm 2.1 vector must decrypt");
        let actual: serde_json::Value = serde_json::from_slice(&decrypted.plaintext).unwrap();
        let expected: serde_json::Value = serde_json::from_str(OFFICIAL_PLAINTEXT).unwrap();

        assert_eq!(actual, expected);
        assert!(decrypted.authenticated);
        assert_eq!(
            decrypted.sender_kid.as_deref(),
            Some("did:example:alice#key-x25519-1")
        );
        assert!(!decrypted.legacy_kek_used);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_uses_standards_envelope() {
        let (did_doc, recipient_private) = recipient_fixture();
        let plaintext = r#"{"id":"message-1","type":"https://didcomm.org/issue-credential/3.0/issue-credential","body":{}}"#;

        let encrypted = encrypt_for_recipient(plaintext, &did_doc).unwrap();
        let decrypted = decrypt_jwe(&encrypted, &recipient_private).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_wrong_recipient_key() {
        let (did_doc, _) = recipient_fixture();
        let encrypted = encrypt_for_recipient("secret message", &did_doc).unwrap();
        let (_, wrong_private) = recipient_fixture();

        assert!(decrypt_jwe(&encrypted, &wrong_private).is_err());
    }

    #[test]
    fn rejects_missing_normative_apv() {
        let (did_doc, recipient_private) = recipient_fixture();
        let encrypted = encrypt_for_recipient("secret message", &did_doc).unwrap();
        let mut jwe: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
        let mut protected = decode_protected_header(&jwe);
        protected.as_object_mut().unwrap().remove("apv");
        jwe["protected"] = serde_json::Value::String(
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap()),
        );

        assert!(decrypt_jwe(&serde_json::to_string(&jwe).unwrap(), &recipient_private).is_err());
    }
}
