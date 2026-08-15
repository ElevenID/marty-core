use marty_verification::chip_io::{derive_bac_base_keys, ApduCommand, BacHandshake, MrzKeyInfo};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    bac_annex_d: BacVector,
    active_authentication: ActiveAuthenticationVector,
}

#[derive(Deserialize)]
struct ActiveAuthenticationVector {
    challenge_hex: String,
    expected_command_apdu: String,
    successful_response: String,
    expected_signature: String,
    error_responses: Vec<String>,
    invalid_challenge_sizes_bits: Vec<usize>,
}

#[derive(Deserialize)]
struct BacVector {
    passport_number: String,
    date_of_birth: String,
    date_of_expiry: String,
    chip_challenge: String,
    reader_challenge: String,
    reader_key: String,
    base_seed: String,
    base_encryption_key: String,
    base_mac_key: String,
    authentication_command_data: String,
    authentication_response_data: String,
    session_encryption_key: String,
    session_mac_key: String,
    initial_ssc: String,
    plain_select_ef_com: String,
    protected_select_ef_com: String,
}

#[test]
fn rust_matches_shared_icao_bac_vector() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/passport_chip_behavior.json")).unwrap();
    let vector = fixture.bac_annex_d;
    let mrz = MrzKeyInfo::from_mrz_fields(
        &vector.passport_number,
        &vector.date_of_birth,
        &vector.date_of_expiry,
    );
    let keys = derive_bac_base_keys(&mrz).unwrap();
    assert_eq!(hex::encode_upper(keys.k_seed), vector.base_seed);
    assert_eq!(hex::encode_upper(keys.k_enc), vector.base_encryption_key);
    assert_eq!(hex::encode_upper(keys.k_mac), vector.base_mac_key);

    let handshake = BacHandshake::begin_with_random(
        &mrz,
        &hex::decode(vector.chip_challenge).unwrap(),
        hex::decode(vector.reader_challenge)
            .unwrap()
            .try_into()
            .unwrap(),
        hex::decode(vector.reader_key).unwrap().try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(
        hex::encode_upper(handshake.command_data().unwrap()),
        vector.authentication_command_data
    );
    let mut session = handshake
        .complete(&hex::decode(vector.authentication_response_data).unwrap())
        .unwrap();
    assert_eq!(
        hex::encode_upper(session.encryption_key()),
        vector.session_encryption_key
    );
    assert_eq!(hex::encode_upper(session.mac_key()), vector.session_mac_key);
    assert_eq!(
        hex::encode_upper(session.send_sequence_counter()),
        vector.initial_ssc
    );
    let command =
        ApduCommand::from_bytes(&hex::decode(vector.plain_select_ef_com).unwrap()).unwrap();
    assert_eq!(
        hex::encode_upper(session.protect_command(&command).unwrap().to_bytes()),
        vector.protected_select_ef_com
    );
}

#[test]
fn rust_matches_shared_active_authentication_behavior() {
    use marty_verification::active_authentication::{
        build_internal_authenticate_apdu, generate_challenge, parse_internal_authenticate_response,
    };

    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/passport_chip_behavior.json")).unwrap();
    let vector = fixture.active_authentication;
    let challenge = hex::decode(vector.challenge_hex).unwrap();
    assert_eq!(
        hex::encode_upper(build_internal_authenticate_apdu(&challenge).unwrap()),
        vector.expected_command_apdu
    );
    assert_eq!(
        hex::encode_upper(
            parse_internal_authenticate_response(&hex::decode(vector.successful_response).unwrap())
                .unwrap()
        ),
        vector.expected_signature
    );
    for response in vector.error_responses {
        assert!(parse_internal_authenticate_response(&hex::decode(response).unwrap()).is_err());
    }
    for key_size in vector.invalid_challenge_sizes_bits {
        assert!(generate_challenge(key_size).is_err());
    }
}
