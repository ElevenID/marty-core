use marty_oid4vci::{
    formats::mdoc::{assemble_mdoc, PreparedMdoc},
    types::SignedCredential,
    Oid4vciResult,
};
#[path = "openbao_signer.rs"]
mod openbao_signer;

use crate::signed_preparation::{PreparedAssembly, SignedPreparation};

pub fn issuer_public_jwk() -> &'static str {
    openbao_signer::public_jwk()
}

pub fn sign_es256(message: &[u8]) -> Vec<u8> {
    openbao_signer::sign(message)
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
