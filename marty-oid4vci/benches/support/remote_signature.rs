use marty_oid4vci::{
    formats::mdoc::{assemble_mdoc, PreparedMdoc},
    types::SignedCredential,
    Oid4vciResult,
};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};

use crate::signed_preparation::{PreparedAssembly, SignedPreparation};

const FIXTURE_PUBLIC_JWK: &str = r#"{"kty":"EC","crv":"P-256","alg":"ES256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}"#;

pub fn issuer_public_jwk() -> &'static str {
    FIXTURE_PUBLIC_JWK
}

pub fn sign_es256(message: &[u8]) -> Vec<u8> {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let key =
        SigningKey::from_slice(&scalar).expect("fixed benchmark-only P-256 key must be valid");
    let signature: Signature = key.sign(message);
    signature.to_bytes().to_vec()
}

pub fn assemble_es256_mdoc(prepared: PreparedMdoc) -> Oid4vciResult<SignedCredential> {
    SignedPreparation::try_sign(prepared, |payload| Ok(sign_es256(payload)))?.assemble()
}

impl PreparedAssembly for PreparedMdoc {
    type Output = Oid4vciResult<SignedCredential>;

    fn signing_payload(&self) -> &[u8] {
        PreparedMdoc::signing_payload(self)
    }

    fn assemble(self, signature: &[u8]) -> Self::Output {
        assemble_mdoc(self, signature)
    }
}
