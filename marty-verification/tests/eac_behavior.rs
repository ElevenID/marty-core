use marty_verification::eac::{generate_ephemeral_keypair, EacAlgorithm, EacSecureMessaging};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    secure_messaging: SecureMessagingVector,
    unsupported_algorithms: Vec<String>,
}

#[derive(Deserialize)]
struct SecureMessagingVector {
    algorithm: String,
    shared_secret: String,
    iv: String,
    plaintext: String,
    mac_key: String,
    encryption_key: String,
    protected: String,
}

#[test]
fn rust_matches_shared_eac_behavior() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/eac_behavior.json")).unwrap();
    let vector = fixture.secure_messaging;
    let algorithm = EacAlgorithm::parse(&vector.algorithm).unwrap();
    let mut channel =
        EacSecureMessaging::new(&hex::decode(vector.shared_secret).unwrap(), algorithm).unwrap();
    let (mac_key, encryption_key) = channel.keys();
    assert_eq!(hex::encode_upper(mac_key), vector.mac_key);
    assert_eq!(hex::encode_upper(encryption_key), vector.encryption_key);
    let protected = channel
        .encrypt_with_iv(
            &hex::decode(vector.plaintext.clone()).unwrap(),
            &hex::decode(vector.iv).unwrap(),
        )
        .unwrap();
    assert_eq!(hex::encode_upper(&protected), vector.protected);
    assert_eq!(
        hex::encode_upper(channel.decrypt(&protected).unwrap()),
        vector.plaintext
    );

    let mut tampered = protected;
    tampered[0] ^= 1;
    assert!(channel.decrypt(&tampered).is_err());
    for unsupported in fixture.unsupported_algorithms {
        let algorithm = EacAlgorithm::parse(&unsupported).unwrap();
        assert!(generate_ephemeral_keypair(algorithm).is_err());
    }
}
