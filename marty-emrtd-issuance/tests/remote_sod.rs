use marty_emrtd_issuance::{prepare_sod, SodError, SodSignatureAlgorithm};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rsa::signature::SignatureEncoding;
use sha2::Sha256;

fn synthetic_document_signer() -> (Vec<u8>, SigningKey) {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Synthetic Document Signer");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let signer = SigningKey::from_pkcs8_der(key.serialized_der()).unwrap();
    (certificate.der().to_vec(), signer)
}

fn groups() -> Vec<(u8, Vec<u8>)> {
    vec![
        (2, b"synthetic-face".to_vec()),
        (1, b"synthetic-mrz".to_vec()),
    ]
}

fn certificate_and_key(algorithm: &'static rcgen::SignatureAlgorithm) -> (Vec<u8>, KeyPair) {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Synthetic Remote Signer");
    let key = KeyPair::generate_for(algorithm).unwrap();
    let certificate = params.self_signed(&key).unwrap();
    (certificate.der().to_vec(), key)
}

#[test]
fn remote_es256_signature_assembles_a_verifiable_icao_sod() {
    let (certificate, signer) = synthetic_document_signer();
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Es256).unwrap();
    let signature: Signature = signer.sign(prepared.signing_input());
    let sod = prepared.assemble(signature.to_der().as_bytes()).unwrap();

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
fn remote_es384_rs256_and_ed25519_signatures_are_verifiable() {
    let (certificate, key) = certificate_and_key(&rcgen::PKCS_ECDSA_P384_SHA384);
    let signer = p384::ecdsa::SigningKey::from_pkcs8_der(key.serialized_der()).unwrap();
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Es384).unwrap();
    let signature: p384::ecdsa::Signature = signer.sign(prepared.signing_input());
    let sod = prepared.assemble(signature.to_der().as_bytes()).unwrap();
    assert!(marty_verification::asn1::sod::verify_sod_signature(&sod).unwrap());

    let (certificate, key) = certificate_and_key(&rcgen::PKCS_RSA_SHA256);
    let signer = rsa::RsaPrivateKey::from_pkcs8_der(key.serialized_der()).unwrap();
    let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(signer);
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Rs256).unwrap();
    let signature = signer.sign(prepared.signing_input());
    let sod = prepared.assemble(&signature.to_vec()).unwrap();
    assert!(marty_verification::asn1::sod::verify_sod_signature(&sod).unwrap());

    let (certificate, key) = certificate_and_key(&rcgen::PKCS_ED25519);
    let signer = ed25519_dalek::SigningKey::from_pkcs8_der(key.serialized_der()).unwrap();
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Ed25519).unwrap();
    let signature = signer.sign(prepared.signing_input());
    let sod = prepared.assemble(&signature.to_bytes()).unwrap();
    assert!(marty_verification::asn1::sod::verify_sod_signature(&sod).unwrap());
}

#[test]
fn wrong_or_malformed_remote_signature_never_produces_a_sod() {
    let (certificate, signer) = synthetic_document_signer();
    let wrong_input: Signature = signer.sign(b"not the CMS signed attributes");
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Es256).unwrap();
    assert!(matches!(
        prepared.assemble(wrong_input.to_der().as_bytes()),
        Err(SodError::InvalidSignature)
    ));
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Es256).unwrap();
    assert!(matches!(
        prepared.assemble(&[0, 1, 2]),
        Err(SodError::InvalidSignature)
    ));
    let prepared = prepare_sod(&groups(), &certificate, SodSignatureAlgorithm::Es384).unwrap();
    let signature: Signature = signer.sign(prepared.signing_input());
    assert!(matches!(
        prepared.assemble(signature.to_der().as_bytes()),
        Err(SodError::InvalidSignature)
    ));

    let (other_certificate, _) = synthetic_document_signer();
    let prepared =
        prepare_sod(&groups(), &other_certificate, SodSignatureAlgorithm::Es256).unwrap();
    let signature: Signature = signer.sign(prepared.signing_input());
    // The test signer above was created with a different key than this DSC.
    assert!(matches!(
        prepared.assemble(signature.to_der().as_bytes()),
        Err(SodError::InvalidSignature)
    ));
}

#[test]
fn data_group_and_certificate_input_are_bounded() {
    let (certificate, _) = synthetic_document_signer();
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
fn issuer_profile_algorithm_names_are_exact_and_data_groups_canonical() {
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

    let (certificate, _) = synthetic_document_signer();
    let reversed = groups();
    let ordered = vec![reversed[1].clone(), reversed[0].clone()];
    let first = prepare_sod(&reversed, &certificate, SodSignatureAlgorithm::Es256).unwrap();
    let second = prepare_sod(&ordered, &certificate, SodSignatureAlgorithm::Es256).unwrap();
    assert_eq!(first.signing_input(), second.signing_input());
}
