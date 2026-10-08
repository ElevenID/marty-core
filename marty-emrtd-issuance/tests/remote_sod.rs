use der::Decode;
use marty_crypto_test_support::openbao_transit::{DisposableOpenBao, ScopedTransitSigner};
use marty_emrtd_issuance::{prepare_sod, SodError, SodSignatureAlgorithm};
use rcgen::{CertificateParams, DnType, PublicKeyData, SigningKey};
use spki::SubjectPublicKeyInfoOwned;

struct RemoteCertificateKey {
    signer: ScopedTransitSigner,
    algorithm: SodSignatureAlgorithm,
    public_key: Vec<u8>,
}

impl PublicKeyData for RemoteCertificateKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self.algorithm {
            SodSignatureAlgorithm::Es256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            SodSignatureAlgorithm::Es384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            SodSignatureAlgorithm::Rs256 => &rcgen::PKCS_RSA_SHA256,
            SodSignatureAlgorithm::Ed25519 => &rcgen::PKCS_ED25519,
        }
    }
}

impl SigningKey for RemoteCertificateKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let result = match self.algorithm {
            SodSignatureAlgorithm::Es256 => self.signer.sign_der(message),
            SodSignatureAlgorithm::Es384 => self.signer.sign_es384_der(message),
            SodSignatureAlgorithm::Rs256 => self.signer.sign_rsa_pkcs1(message),
            SodSignatureAlgorithm::Ed25519 => self.signer.sign_ed25519(message),
        };
        result.map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

fn remote_document_signer(algorithm: SodSignatureAlgorithm) -> (Vec<u8>, RemoteCertificateKey) {
    let provider = DisposableOpenBao::from_marked_env();
    let signer = match algorithm {
        SodSignatureAlgorithm::Es256 => provider.create_es256(),
        SodSignatureAlgorithm::Es384 => provider.create_es384(),
        SodSignatureAlgorithm::Rs256 => provider.create_rsa2048(),
        SodSignatureAlgorithm::Ed25519 => provider.create_ed25519(),
    };
    let spki = SubjectPublicKeyInfoOwned::from_der(signer.public_key_spki_der())
        .expect("OpenBao public key must be valid SPKI");
    let public_key = spki.subject_public_key.as_bytes().unwrap().to_vec();
    let remote_key = RemoteCertificateKey {
        signer,
        algorithm,
        public_key,
    };
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Synthetic Remote Document Signer");
    let certificate = params.self_signed(&remote_key).unwrap();
    (certificate.der().to_vec(), remote_key)
}

fn groups() -> Vec<(u8, Vec<u8>)> {
    vec![
        (2, b"synthetic-face".to_vec()),
        (1, b"synthetic-mrz".to_vec()),
    ]
}

#[test]
#[ignore = "requires marked disposable OpenBao Transit and scoped document signer"]
fn remote_es256_signature_assembles_a_verifiable_icao_sod() {
    let (certificate, signer) = remote_document_signer(SodSignatureAlgorithm::Es256);
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Es256).unwrap();
    let signature = signer.sign(prepared.signing_input()).unwrap();
    let sod = prepared.assemble(&signature).unwrap();

    assert!(marty_verification::asn1::sod::verify_sod_signature(&sod).unwrap());
    assert!(
        marty_verification::asn1::sod::verify_data_group_hash_from_sod(&sod, 1, b"synthetic-mrz")
            .unwrap()
    );
    assert!(
        !marty_verification::asn1::sod::verify_data_group_hash_from_sod(&sod, 2, b"wrong-face")
            .unwrap()
    );
}

#[test]
#[ignore = "requires marked disposable OpenBao Transit and scoped document signer"]
fn remote_es384_rs256_and_ed25519_signatures_are_verifiable() {
    let (certificate, signer) = remote_document_signer(SodSignatureAlgorithm::Es384);
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Es384).unwrap();
    let signature = signer.sign(prepared.signing_input()).unwrap();
    let sod = prepared.assemble(&signature).unwrap();
    assert!(marty_verification::asn1::sod::verify_sod_signature(&sod).unwrap());

    let (certificate, signer) = remote_document_signer(SodSignatureAlgorithm::Rs256);
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Rs256).unwrap();
    let signature = signer.sign(prepared.signing_input()).unwrap();
    let sod = prepared.assemble(&signature).unwrap();
    assert!(marty_verification::asn1::sod::verify_sod_signature(&sod).unwrap());

    let (certificate, signer) = remote_document_signer(SodSignatureAlgorithm::Ed25519);
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Ed25519).unwrap();
    let signature = signer.sign(prepared.signing_input()).unwrap();
    let sod = prepared.assemble(&signature).unwrap();
    assert!(marty_verification::asn1::sod::verify_sod_signature(&sod).unwrap());
}

#[test]
#[ignore = "requires marked disposable OpenBao Transit and scoped document signer"]
fn wrong_or_malformed_remote_signature_never_produces_a_sod() {
    let (certificate, signer) = remote_document_signer(SodSignatureAlgorithm::Es256);
    let wrong_input = signer.sign(b"not the CMS signed attributes").unwrap();
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Es256).unwrap();
    assert!(matches!(
        prepared.assemble(&wrong_input),
        Err(SodError::InvalidSignature)
    ));
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Es256).unwrap();
    assert!(matches!(
        prepared.assemble(&[0, 1, 2]),
        Err(SodError::InvalidSignature)
    ));
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Es384).unwrap();
    let signature = signer.sign(prepared.signing_input()).unwrap();
    assert!(matches!(
        prepared.assemble(&signature),
        Err(SodError::InvalidSignature)
    ));

    let (other_certificate, _) = remote_document_signer(SodSignatureAlgorithm::Es256);
    let prepared =
        prepare_sod(&groups(), &other_certificate, SodSignatureAlgorithm::Es256).unwrap();
    let signature = signer.sign(prepared.signing_input()).unwrap();
    // The test signer above was created with a different key than this DSC.
    assert!(matches!(
        prepared.assemble(&signature),
        Err(SodError::InvalidSignature)
    ));
}

#[test]
#[ignore = "requires marked disposable OpenBao Transit and scoped document signer"]
fn data_group_and_certificate_input_are_bounded() {
    let (certificate, _) = remote_document_signer(SodSignatureAlgorithm::Es256);
    assert!(prepare_sod(
        &[(17, b"extension".to_vec()), (20, b"extension".to_vec())],
        &certificate,
        SodSignatureAlgorithm::Es256,
    )
    .is_ok());
    for input in [vec![], vec![(1, vec![]), (1, vec![])], vec![(21, vec![])]] {
        assert!(matches!(
            prepare_sod(&input, &certificate, SodSignatureAlgorithm::Es256),
            Err(SodError::InvalidDataGroups)
        ));
    }
    assert!(matches!(
        prepare_sod(
            &groups(),
            b"not a certificate",
            SodSignatureAlgorithm::Es256
        ),
        Err(SodError::InvalidCertificate)
    ));
}

#[test]
fn issuer_profile_algorithm_names_are_exact() {
    for (name, expected) in [
        ("ES256", SodSignatureAlgorithm::Es256),
        ("ES384", SodSignatureAlgorithm::Es384),
        ("RS256", SodSignatureAlgorithm::Rs256),
        ("EdDSA", SodSignatureAlgorithm::Ed25519),
    ] {
        assert_eq!(SodSignatureAlgorithm::try_from(name).unwrap(), expected);
        assert_eq!(expected.as_str(), name);
    }
    assert!(matches!(
        SodSignatureAlgorithm::try_from("PS256"),
        Err(SodError::UnsupportedAlgorithm)
    ));
}

#[test]
#[ignore = "requires marked disposable OpenBao Transit and scoped document signer"]
fn data_groups_are_canonical() {
    let (certificate, _) = remote_document_signer(SodSignatureAlgorithm::Es256);
    let reversed = groups();
    let ordered = vec![reversed[1].clone(), reversed[0].clone()];
    let first = prepare_sod(&reversed, &certificate, SodSignatureAlgorithm::Es256).unwrap();
    let second = prepare_sod(&ordered, &certificate, SodSignatureAlgorithm::Es256).unwrap();
    assert_eq!(first.signing_input(), second.signing_input());
}
