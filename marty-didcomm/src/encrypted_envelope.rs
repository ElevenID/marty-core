//! DIDComm v2.1 public-recipient anoncrypt support.
//!
//! Credential-delivery sender authentication uses the native remote-KMS
//! boundary. This crate never accepts a long-lived sender or recipient private
//! key. Anonymous encryption creates only an ephemeral sender agreement key.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use marty_crypto::{ecdh::X25519KeyPair, kdf::concat_kdf_sha256, symmetric};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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
    let ephemeral = X25519KeyPair::generate();
    let ephemeral_public = ephemeral.public_key_bytes();
    let peers = recipient_keys
        .iter()
        .map(|(_, key)| key.as_slice())
        .collect::<Vec<_>>();
    let shared = ephemeral.agree_many(&peers).map_err(crypto_error)?;

    // DIDComm v2.1: APV is SHA-256(sorted recipient KIDs joined with '.').
    let mut kids = recipient_keys
        .iter()
        .map(|(kid, _)| kid.as_str())
        .collect::<Vec<_>>();
    kids.sort_unstable();
    let apv = Sha256::digest(kids.join(".").as_bytes());
    let header = serde_json::json!({
        "typ": "application/didcomm-encrypted+json",
        "alg": "ECDH-ES+A256KW",
        "enc": "A256CBC-HS512",
        "apv": URL_SAFE_NO_PAD.encode(apv),
        "epk": {"kty": "OKP", "crv": "X25519", "x": URL_SAFE_NO_PAD.encode(ephemeral_public)},
    });
    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)
            .map_err(|_| DidcommError::PackError("could not encode DIDComm header".into()))?,
    );

    let mut cek = Zeroizing::new([0u8; 64]);
    let mut iv = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut *cek)
        .map_err(|_| DidcommError::Crypto("DIDComm entropy unavailable".into()))?;
    OsRng
        .try_fill_bytes(&mut iv)
        .map_err(|_| DidcommError::Crypto("DIDComm entropy unavailable".into()))?;
    let ciphertext = symmetric::aes_256_cbc_encrypt(&cek[32..], &iv, plaintext.as_bytes())
        .map_err(crypto_error)?;
    let aad_bits = (protected.len() as u64) * 8;
    let mac_input = [
        protected.as_bytes(),
        &iv,
        &ciphertext,
        &aad_bits.to_be_bytes(),
    ]
    .concat();
    let tag = symmetric::hmac_sha512(&cek[..32], &mac_input).map_err(crypto_error)?;

    let mut recipients = Vec::with_capacity(recipient_keys.len());
    for ((kid, _), secret) in recipient_keys.iter().zip(shared) {
        let kek = concat_kdf_sha256(secret.as_ref(), b"ECDH-ES+A256KW", &[], &apv, 32)
            .map_err(crypto_error)?;
        let wrapper = aes_kw::KekAes256::try_from(kek.as_slice())
            .map_err(|_| DidcommError::Crypto("invalid DIDComm wrapping key length".into()))?;
        let wrapped = wrapper
            .wrap_vec(cek.as_ref())
            .map_err(|_| DidcommError::Crypto("DIDComm key wrap failed".into()))?;
        recipients.push(serde_json::json!({
            "header": {"kid": kid}, "encrypted_key": URL_SAFE_NO_PAD.encode(wrapped),
        }));
    }
    serde_json::to_string(&serde_json::json!({
        "protected": protected, "recipients": recipients,
        "iv": URL_SAFE_NO_PAD.encode(iv), "ciphertext": URL_SAFE_NO_PAD.encode(ciphertext),
        "tag": URL_SAFE_NO_PAD.encode(&tag[..32]),
    }))
    .map_err(|_| DidcommError::PackError("could not encode DIDComm envelope".into()))
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

fn crypto_error(error: marty_crypto::CryptoError) -> DidcommError {
    DidcommError::Crypto(format!("DIDComm anoncrypt failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn public_recipient_document() -> DidDocument {
        // Public RFC7748 Bob/Alice agreement points; no private key is imported.
        let x = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08";
        let mut document = serde_json::json!({
            "id": "did:example:bob",
            "verificationMethod": [{
                "id": "did:example:bob#x25519-1",
                "type": "JsonWebKey2020",
                "controller": "did:example:bob",
                "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": x}
            }, {
                "id": "did:example:bob#x25519-2",
                "type": "JsonWebKey2020", "controller": "did:example:bob",
                "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}
            }],
            "keyAgreement": ["did:example:bob#x25519-1", "did:example:bob#x25519-2"]

        });
        if let Ok(public_keys) = std::env::var("MARTY_DIDCOMM_INTEROP_PUBLIC_KEYS") {
            let public_keys: [String; 2] = serde_json::from_str(&public_keys).unwrap();
            for (method, public) in document["verificationMethod"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .zip(public_keys)
            {
                method["publicKeyJwk"]["x"] = public.into();
            }
        }
        serde_json::from_value(document).unwrap()
    }

    #[test]
    fn public_recipient_anoncrypt_has_normative_protected_profile() {
        let document = public_recipient_document();
        let envelope =
            encrypt_for_recipient(r#"{"id":"message-1","type":"test"}"#, &document).unwrap();
        // Only the focused interoperability driver requests this public ciphertext.
        if std::env::var_os("MARTY_DIDCOMM_INTEROP_STDOUT").is_some() {
            println!("DIDCOMM_INTEROP {envelope}");
        }
        let jwe: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        assert_eq!(jwe["recipients"].as_array().unwrap().len(), 2);
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
    #[test]
    fn public_recipient_anoncrypt_rejects_non_contributory_x25519_keys() {
        for first_byte in [0u8, 1u8] {
            let mut document = public_recipient_document();
            let mut key = [0u8; 32];
            key[0] = first_byte;
            let mut json = serde_json::to_value(&document).unwrap();
            json["verificationMethod"][0]["publicKeyJwk"]["x"] = URL_SAFE_NO_PAD.encode(key).into();
            document = serde_json::from_value(json).unwrap();
            assert!(encrypt_for_recipient("message", &document).is_err());
        }
    }
}
