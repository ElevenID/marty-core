//! DIDComm v2.1 encrypted-envelope support.
//!
//! Marty deliberately delegates JOSE envelope construction to the maintained
//! `affinidi-messaging-didcomm` implementation.  Keeping a second, partial
//! implementation here previously allowed Marty-produced messages to decrypt
//! with Marty while omitting DIDComm's protected `epk` and `apv` headers.
//!
//! Marty exposes one-recipient-DID X25519 anoncrypt and authcrypt profiles. Each
//! envelope includes every compatible method that the recipient DID document
//! explicitly authorizes through `keyAgreement`; key IDs and key material are
//! selected atomically. Signed envelopes, mediator routing, multi-DID delivery,
//! and broader curve/algorithm support remain explicit product capabilities to
//! implement and test rather than implied claims of this wrapper.

use affinidi_messaging_didcomm::crypto::key_agreement::{
    Curve, PrivateKeyAgreement, PublicKeyAgreement,
};
use affinidi_messaging_didcomm::jwe::{decrypt, encrypt};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{DidcommError, DidcommResult};
use crate::types::DidDocument;

const DIDCOMM_ENCRYPTED_MEDIA_TYPE: &str = "application/didcomm-encrypted+json";
const DIDCOMM_CONTENT_ENCRYPTION: &str = "A256CBC-HS512";
const ANONCRYPT_ALGORITHM: &str = "ECDH-ES+A256KW";
const AUTHCRYPT_ALGORITHM: &str = "ECDH-1PU+A256KW";

/// Strict sender-authenticated decryption result for the key that opened the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedDecryption {
    pub plaintext: String,
    pub sender_kid: String,
    pub recipient_kid: String,
}

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
    let recipient_keys = authorized_x25519_methods(recipient_did_doc)?;
    let recipients = public_keys(&recipient_keys, "recipient")?;
    let recipient_refs = recipients
        .iter()
        .map(|(kid, key)| (kid.as_str(), key))
        .collect::<Vec<_>>();

    encrypt::anoncrypt(plaintext.as_bytes(), &recipient_refs)
        .map_err(|error| DidcommError::Crypto(format!("DIDComm anoncrypt failed: {error}")))
}

/// Encrypt a DIDComm plaintext message with sender-authenticated encryption.
///
/// The sender private key must match an X25519 verification method explicitly
/// authorized by the sender DID document's `keyAgreement` relationship. The
/// plaintext `from` and `to` values are bound to the sender and recipient DIDs
/// before ECDH-1PU encryption is attempted.
pub fn encrypt_for_recipient_authenticated(
    plaintext: &str,
    sender_did_doc: &DidDocument,
    sender_private_key: &[u8; 32],
    recipient_did_doc: &DidDocument,
) -> DidcommResult<String> {
    validate_plaintext_parties(plaintext, sender_did_doc, recipient_did_doc)
        .map_err(DidcommError::PackError)?;
    let (sender_kid, sender_private) =
        private_key_bound_to_document(sender_private_key, sender_did_doc, "sender")?;
    let recipient_keys = authorized_x25519_methods(recipient_did_doc)?;
    let recipients = public_keys(&recipient_keys, "recipient")?;
    let recipient_refs = recipients
        .iter()
        .map(|(kid, key)| (kid.as_str(), key))
        .collect::<Vec<_>>();

    encrypt::authcrypt(
        plaintext.as_bytes(),
        &sender_kid,
        &sender_private,
        &recipient_refs,
    )
    .map_err(|error| DidcommError::Crypto(format!("DIDComm authcrypt failed: {error}")))
}

/// Decrypt a single-recipient DIDComm v2.1 anoncrypt JWE.
///
/// This compatibility entry point retains the existing Python/Rust API while
/// delegating all protected-header, key-derivation, key-wrap, and content-
/// authentication validation to the maintained DIDComm implementation.
pub fn decrypt_jwe(jwe_json: &str, recipient_private_key: &[u8; 32]) -> DidcommResult<String> {
    let jwe: serde_json::Value = serde_json::from_str(jwe_json)
        .map_err(|error| DidcommError::UnpackError(format!("invalid JWE JSON: {error}")))?;
    let recipients = jwe
        .get("recipients")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| DidcommError::UnpackError("missing recipients".into()))?;
    if recipients.is_empty() {
        return Err(DidcommError::UnpackError(
            "anoncrypt envelope has no recipients".into(),
        ));
    }
    let recipient_kids = recipients
        .iter()
        .map(|recipient| {
            recipient
                .pointer("/header/kid")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| DidcommError::UnpackError("missing recipient kid".into()))
        })
        .collect::<DidcommResult<Vec<_>>>()?;

    let recipient_private =
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, recipient_private_key).map_err(
            |error| DidcommError::Crypto(format!("invalid recipient X25519 key: {error}")),
        )?;
    let decrypted = recipient_kids
        .into_iter()
        .find_map(|recipient_kid| {
            decrypt::decrypt(jwe_json, recipient_kid, &recipient_private, None).ok()
        })
        .ok_or_else(|| {
            DidcommError::UnpackError("DIDComm decrypt failed for every envelope recipient".into())
        })?;

    if decrypted.authenticated || decrypted.sender_kid.is_some() {
        return Err(DidcommError::UnpackError(
            "authenticated DIDComm envelope is not valid for the anoncrypt API".into(),
        ));
    }
    validate_protected_profile(
        decrypted.header.typ.as_deref(),
        &decrypted.header.alg,
        &decrypted.header.enc,
        ANONCRYPT_ALGORITHM,
    )?;

    String::from_utf8(decrypted.plaintext)
        .map_err(|error| DidcommError::UnpackError(format!("plaintext is not UTF-8: {error}")))
}

/// Decrypt and authenticate a one-recipient DIDComm authcrypt envelope.
///
/// This API rejects anoncrypt downgrade, non-normative/legacy ECDH-1PU key
/// derivation, sender KID substitution, private-key/document mismatch, and a
/// plaintext `from` or `to` value that disagrees with the authenticated DIDs.
pub fn decrypt_authenticated_jwe(
    jwe_json: &str,
    recipient_private_key: &[u8; 32],
    recipient_did_doc: &DidDocument,
    sender_did_doc: &DidDocument,
) -> DidcommResult<AuthenticatedDecryption> {
    let envelope: serde_json::Value = serde_json::from_str(jwe_json)
        .map_err(|error| DidcommError::UnpackError(format!("invalid JWE JSON: {error}")))?;
    let sender_kid = protected_sender_kid(&envelope)?;
    let sender_key_bytes = authorized_x25519_methods(sender_did_doc)?
        .into_iter()
        .find_map(|(kid, key)| (kid == sender_kid).then_some(key))
        .ok_or_else(|| {
            DidcommError::UnpackError(
                "sender kid is not authorized by the sender DID document".into(),
            )
        })?;
    let sender_public = PublicKeyAgreement::from_raw_bytes(Curve::X25519, &sender_key_bytes)
        .map_err(|error| DidcommError::Crypto(format!("invalid sender X25519 key: {error}")))?;
    let (recipient_kid, recipient_private) =
        private_key_bound_to_document(recipient_private_key, recipient_did_doc, "recipient")?;

    let recipients = envelope
        .get("recipients")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| DidcommError::UnpackError("missing recipients".into()))?;
    if recipients.is_empty() {
        return Err(DidcommError::UnpackError(
            "authcrypt envelope has no recipients".into(),
        ));
    }
    if !recipients.iter().any(|recipient| {
        recipient
            .pointer("/header/kid")
            .and_then(serde_json::Value::as_str)
            == Some(recipient_kid.as_str())
    }) {
        return Err(DidcommError::UnpackError(
            "recipient kid is not authorized by the recipient DID document".into(),
        ));
    }

    let decrypted = decrypt::decrypt(
        jwe_json,
        &recipient_kid,
        &recipient_private,
        Some(&sender_public),
    )
    .map_err(|error| DidcommError::UnpackError(format!("DIDComm decrypt failed: {error}")))?;
    validate_protected_profile(
        decrypted.header.typ.as_deref(),
        &decrypted.header.alg,
        &decrypted.header.enc,
        AUTHCRYPT_ALGORITHM,
    )?;
    if !decrypted.authenticated || decrypted.legacy_kek_used {
        return Err(DidcommError::UnpackError(
            "authcrypt envelope is not standards-conformant ECDH-1PU".into(),
        ));
    }
    if decrypted.header.skid.as_deref() != Some(sender_kid.as_str())
        || decrypted.sender_kid.as_deref() != Some(sender_kid.as_str())
    {
        return Err(DidcommError::UnpackError(
            "sender kid is not authorized by the sender DID document".into(),
        ));
    }

    let plaintext = String::from_utf8(decrypted.plaintext)
        .map_err(|error| DidcommError::UnpackError(format!("plaintext is not UTF-8: {error}")))?;
    validate_plaintext_parties(&plaintext, sender_did_doc, recipient_did_doc)
        .map_err(DidcommError::UnpackError)?;
    Ok(AuthenticatedDecryption {
        plaintext,
        sender_kid,
        recipient_kid,
    })
}

fn authorized_x25519_methods(document: &DidDocument) -> DidcommResult<Vec<(String, [u8; 32])>> {
    let methods = document.x25519_key_agreement_methods();
    if methods.is_empty() {
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

fn private_key_bound_to_document(
    private_key: &[u8; 32],
    document: &DidDocument,
    role: &str,
) -> DidcommResult<(String, PrivateKeyAgreement)> {
    let private = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, private_key)
        .map_err(|error| DidcommError::Crypto(format!("invalid {role} X25519 key: {error}")))?;
    let actual_public = private.public_key().to_jwk();
    for (kid, expected_key) in authorized_x25519_methods(document)? {
        let expected = PublicKeyAgreement::from_raw_bytes(Curve::X25519, &expected_key)
            .map_err(|error| DidcommError::Crypto(format!("invalid {role} X25519 key: {error}")))?;
        if actual_public == expected.to_jwk() {
            return Ok((kid, private));
        }
    }
    Err(DidcommError::Crypto(format!(
        "{role} private key does not match the authorized DID document method"
    )))
}

fn protected_sender_kid(envelope: &serde_json::Value) -> DidcommResult<String> {
    let protected = envelope
        .get("protected")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| DidcommError::UnpackError("missing protected header".into()))?;
    let protected_bytes = URL_SAFE_NO_PAD
        .decode(protected)
        .map_err(|error| DidcommError::UnpackError(format!("invalid protected header: {error}")))?;
    let header: serde_json::Value = serde_json::from_slice(&protected_bytes)
        .map_err(|error| DidcommError::UnpackError(format!("invalid protected header: {error}")))?;
    let sender_kid = header
        .get("skid")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| DidcommError::UnpackError("authcrypt header is missing skid".into()))?;
    let apu = header
        .get("apu")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| DidcommError::UnpackError("authcrypt header is missing apu".into()))?;
    let apu = URL_SAFE_NO_PAD
        .decode(apu)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| DidcommError::UnpackError("authcrypt header has invalid apu".into()))?;
    if apu != sender_kid {
        return Err(DidcommError::UnpackError(
            "authcrypt skid and apu identify different sender keys".into(),
        ));
    }
    Ok(sender_kid.to_string())
}

fn validate_plaintext_parties(
    plaintext: &str,
    sender_did_doc: &DidDocument,
    recipient_did_doc: &DidDocument,
) -> Result<(), String> {
    let message: crate::types::DidcommMessage = serde_json::from_str(plaintext)
        .map_err(|error| format!("invalid DIDComm plaintext: {error}"))?;
    if message.from.as_deref() != Some(sender_did_doc.id.as_str()) {
        return Err("plaintext from does not match the authenticated sender DID".into());
    }
    if message.to.as_deref() != Some(std::slice::from_ref(&recipient_did_doc.id)) {
        return Err("plaintext to must contain exactly the encrypted recipient DID".into());
    }
    Ok(())
}

fn validate_protected_profile(
    media_type: Option<&str>,
    algorithm: &str,
    content_encryption: &str,
    expected_algorithm: &str,
) -> DidcommResult<()> {
    if media_type != Some(DIDCOMM_ENCRYPTED_MEDIA_TYPE)
        || algorithm != expected_algorithm
        || content_encryption != DIDCOMM_CONTENT_ENCRYPTION
    {
        return Err(DidcommError::UnpackError(
            "encrypted envelope does not use the required DIDComm profile".into(),
        ));
    }
    Ok(())
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

    fn party_fixture(did: &str) -> (DidDocument, [u8; 32]) {
        let recipient_private = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient_private_bytes = match &recipient_private {
            PrivateKeyAgreement::X25519(secret) => secret.to_bytes(),
            _ => unreachable!("fixture explicitly generates an X25519 key"),
        };
        let recipient_public = recipient_private.public_key();
        let recipient_public_jwk = recipient_public.to_jwk();
        let key_id = format!("{did}#key-x25519-1");

        let did_doc = DidDocument {
            id: did.into(),
            context: serde_json::json!("https://www.w3.org/ns/did/v1"),
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![serde_json::Value::String(key_id.clone())],
            verification_method: vec![crate::types::VerificationMethod {
                id: key_id,
                r#type: "JsonWebKey2020".into(),
                controller: did.into(),
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
                    additional_properties: serde_json::Map::new(),
                }),
                public_key_multibase: None,
                public_key_base58: None,
                additional_properties: serde_json::Map::new(),
            }],
            service: vec![],
            additional_properties: serde_json::Map::new(),
        };

        (did_doc, recipient_private_bytes)
    }

    fn recipient_fixture() -> (DidDocument, [u8; 32]) {
        party_fixture("did:example:bob")
    }

    fn plaintext(sender: &str, recipient: &str) -> String {
        serde_json::json!({
            "id": "message-1",
            "type": "https://didcomm.org/issue-credential/3.0/issue-credential",
            "from": sender,
            "to": [recipient],
            "body": {}
        })
        .to_string()
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
    fn rejects_x25519_verification_method_without_key_agreement_authorization() {
        let (mut did_doc, _) = recipient_fixture();
        did_doc.key_agreement.clear();

        let error = encrypt_for_recipient("secret", &did_doc).unwrap_err();
        assert!(matches!(error, DidcommError::NoKeyAgreementKey { .. }));
    }

    #[test]
    fn selects_key_id_and_material_from_the_same_authorized_method() {
        let (mut did_doc, private) = recipient_fixture();
        let (mut unrelated_doc, _) = party_fixture("did:example:bob");
        let mut unrelated = unrelated_doc.verification_method.remove(0);
        unrelated.id = "did:example:bob#key-x25519-unrelated".into();
        did_doc.verification_method.insert(0, unrelated);

        let encrypted = encrypt_for_recipient("secret", &did_doc).unwrap();
        let jwe: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
        assert_eq!(
            jwe["recipients"][0]["header"]["kid"],
            "did:example:bob#key-x25519-1"
        );
        assert_eq!(decrypt_jwe(&encrypted, &private).unwrap(), "secret");
    }

    #[test]
    fn encrypts_for_every_authorized_key_of_one_recipient_did() {
        let (mut did_doc, _) = recipient_fixture();
        let (mut second_doc, second_private) = party_fixture("did:example:bob");
        let mut second_method = second_doc.verification_method.remove(0);
        second_method.id = "did:example:bob#key-x25519-2".into();
        did_doc
            .key_agreement
            .push(serde_json::json!(second_method.id.clone()));
        did_doc.verification_method.push(second_method);

        let encrypted = encrypt_for_recipient("secret", &did_doc).unwrap();
        let jwe: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
        assert_eq!(jwe["recipients"].as_array().unwrap().len(), 2);
        assert_eq!(
            jwe["recipients"][1]["header"]["kid"],
            "did:example:bob#key-x25519-2"
        );
        assert_eq!(decrypt_jwe(&encrypted, &second_private).unwrap(), "secret");
    }

    #[test]
    fn authcrypt_roundtrip_binds_sender_recipient_and_normative_headers() {
        let (sender_doc, sender_private) = party_fixture("did:example:alice");
        let (recipient_doc, recipient_private) = recipient_fixture();
        let message = plaintext(&sender_doc.id, &recipient_doc.id);

        let encrypted = encrypt_for_recipient_authenticated(
            &message,
            &sender_doc,
            &sender_private,
            &recipient_doc,
        )
        .unwrap();
        let jwe: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
        let protected = decode_protected_header(&jwe);
        assert_eq!(protected["alg"], AUTHCRYPT_ALGORITHM);
        assert_eq!(protected["enc"], DIDCOMM_CONTENT_ENCRYPTION);
        assert_eq!(protected["skid"], "did:example:alice#key-x25519-1");

        let decrypted =
            decrypt_authenticated_jwe(&encrypted, &recipient_private, &recipient_doc, &sender_doc)
                .unwrap();
        assert_eq!(decrypted.plaintext, message);
        assert_eq!(decrypted.sender_kid, "did:example:alice#key-x25519-1");
        assert_eq!(decrypted.recipient_kid, "did:example:bob#key-x25519-1");
    }

    #[test]
    fn authcrypt_rejects_spoofed_plaintext_sender() {
        let (sender_doc, sender_private) = party_fixture("did:example:alice");
        let (recipient_doc, _) = recipient_fixture();
        let message = plaintext("did:example:mallory", &recipient_doc.id);

        let error = encrypt_for_recipient_authenticated(
            &message,
            &sender_doc,
            &sender_private,
            &recipient_doc,
        )
        .unwrap_err();
        assert!(error.to_string().contains("plaintext from"));
    }

    #[test]
    fn authcrypt_rejects_private_key_not_bound_to_sender_document() {
        let (sender_doc, _) = party_fixture("did:example:alice");
        let (_, wrong_private) = party_fixture("did:example:mallory");
        let (recipient_doc, _) = recipient_fixture();
        let message = plaintext(&sender_doc.id, &recipient_doc.id);

        let error = encrypt_for_recipient_authenticated(
            &message,
            &sender_doc,
            &wrong_private,
            &recipient_doc,
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn authenticated_decrypt_rejects_anoncrypt_downgrade() {
        let (sender_doc, _) = party_fixture("did:example:alice");
        let (recipient_doc, recipient_private) = recipient_fixture();
        let message = plaintext(&sender_doc.id, &recipient_doc.id);
        let encrypted = encrypt_for_recipient(&message, &recipient_doc).unwrap();

        assert!(decrypt_authenticated_jwe(
            &encrypted,
            &recipient_private,
            &recipient_doc,
            &sender_doc,
        )
        .is_err());
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

        let (mut sender_doc, _) = party_fixture("did:example:alice");
        sender_doc.verification_method[0]
            .public_key_jwk
            .as_mut()
            .unwrap()
            .x = sender_public
            .to_jwk()
            .get("x")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let (mut recipient_doc, _) = recipient_fixture();
        recipient_doc.verification_method[0]
            .public_key_jwk
            .as_mut()
            .unwrap()
            .x = recipient_private
            .public_key()
            .to_jwk()
            .get("x")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);

        let strict = decrypt_authenticated_jwe(
            OFFICIAL_AUTHCRYPT_X25519_A256CBC,
            &recipient_private_bytes,
            &recipient_doc,
            &sender_doc,
        )
        .expect("the strict public API must accept the published DIDComm 2.1 vector");
        let actual: serde_json::Value = serde_json::from_str(&strict.plaintext).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(strict.sender_kid, "did:example:alice#key-x25519-1");
        assert_eq!(strict.recipient_kid, "did:example:bob#key-x25519-1");
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
