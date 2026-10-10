//! `rcgen` adapter backed by a disposable, non-exportable OpenBao Transit key.
//! Only test code can depend on this non-publishable crate.

use crate::openbao_transit::{DisposableOpenBao, ScopedTransitSigner};
use der::Decode;
use rcgen::{PublicKeyData, SigningKey};
use spki::SubjectPublicKeyInfoOwned;

#[derive(Clone, Copy, Debug)]
pub enum RemoteCertificateAlgorithm {
    Es256,
    Es384,
    Rs256,
    Ed25519,
}

pub struct RemoteCertificateKey {
    signer: ScopedTransitSigner,
    algorithm: RemoteCertificateAlgorithm,
    public_key: Vec<u8>,
}

impl RemoteCertificateKey {
    pub fn new(algorithm: RemoteCertificateAlgorithm) -> Self {
        let provider = DisposableOpenBao::from_marked_env();
        let signer = match algorithm {
            RemoteCertificateAlgorithm::Es256 => provider.create_es256(),
            RemoteCertificateAlgorithm::Es384 => provider.create_es384(),
            RemoteCertificateAlgorithm::Rs256 => provider.create_rsa2048(),
            RemoteCertificateAlgorithm::Ed25519 => provider.create_ed25519(),
        };
        let spki = SubjectPublicKeyInfoOwned::from_der(signer.public_key_spki_der())
            .expect("OpenBao public key must be valid SPKI");
        let public_key = spki
            .subject_public_key
            .as_bytes()
            .expect("OpenBao public key must be byte-aligned")
            .to_vec();
        Self {
            signer,
            algorithm,
            public_key,
        }
    }

    pub fn public_key_spki_der(&self) -> &[u8] {
        self.signer.public_key_spki_der()
    }
}

impl PublicKeyData for RemoteCertificateKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self.algorithm {
            RemoteCertificateAlgorithm::Es256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            RemoteCertificateAlgorithm::Es384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            RemoteCertificateAlgorithm::Rs256 => &rcgen::PKCS_RSA_SHA256,
            RemoteCertificateAlgorithm::Ed25519 => &rcgen::PKCS_ED25519,
        }
    }
}

impl SigningKey for RemoteCertificateKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let result = match self.algorithm {
            RemoteCertificateAlgorithm::Es256 => self.signer.sign_der(message),
            RemoteCertificateAlgorithm::Es384 => self.signer.sign_es384_der(message),
            RemoteCertificateAlgorithm::Rs256 => self.signer.sign_rsa_pkcs1(message),
            RemoteCertificateAlgorithm::Ed25519 => self.signer.sign_ed25519(message),
        };
        result.map_err(|_| rcgen::Error::RemoteKeyError)
    }
}
