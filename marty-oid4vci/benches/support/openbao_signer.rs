//! One non-exportable issuer key per benchmark process. Initialization runs
//! outside Criterion's measured signing operations.

#[path = "../../tests/support/openbao_transit.rs"]
#[allow(dead_code)]
mod openbao_transit;

use std::sync::OnceLock;

fn signer() -> &'static openbao_transit::ScopedTransitSigner {
    static SIGNER: OnceLock<openbao_transit::ScopedTransitSigner> = OnceLock::new();
    SIGNER.get_or_init(|| {
        openbao_transit::DisposableOpenBao::from_marked_env().create_es256_for_benchmark()
    })
}

pub fn public_jwk() -> &'static str {
    signer().public_jwk()
}

pub fn sign(message: &[u8]) -> Vec<u8> {
    signer().sign(message).expect("scoped OpenBao signing")
}

#[allow(dead_code)]
pub fn verifying_key() -> &'static p256::ecdsa::VerifyingKey {
    static VERIFYING_KEY: OnceLock<p256::ecdsa::VerifyingKey> = OnceLock::new();
    VERIFYING_KEY.get_or_init(|| signer().verifying_key())
}
