use marty_verification::chip_io::{derive_bac_base_keys, ApduCommand, BacHandshake, MrzKeyInfo};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    bac_annex_d: BacVector,
    active_authentication: ActiveAuthenticationVector,
    pace_compatibility: PaceCompatibilityVector,
    apdu: ApduVector,
}

#[derive(Deserialize)]
struct ApduVector {
    commands: Vec<ApduCommandVector>,
    extended: ExtendedApduVector,
    read_length: usize,
    read_offset: usize,
    read_commands: Vec<String>,
    responses: Vec<ApduResponseVector>,
}

#[derive(Deserialize)]
struct ApduCommandVector {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Option<String>,
    le: Option<usize>,
    encoded: String,
}

#[derive(Deserialize)]
struct ExtendedApduVector {
    data_byte: u8,
    data_length: usize,
    encoded_length: usize,
    prefix: String,
}

#[derive(Deserialize)]
struct ApduResponseVector {
    encoded: String,
    success: bool,
    warning: bool,
    error: bool,
    description: String,
}

#[derive(Deserialize)]
struct PaceCompatibilityVector {
    password: String,
    password_key: String,
    nonce: String,
    encrypted_nonce: String,
    reader_private_key: String,
    reader_public_key: String,
    chip_public_key: String,
    session_encryption_key: String,
    session_mac_key: String,
    ssc: String,
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

#[test]
fn rust_matches_shared_pace_compatibility_behavior() {
    use marty_verification::chip_io::{
        derive_compatibility_pace_password_key, PaceCompatibilityHandshake,
    };

    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/passport_chip_behavior.json")).unwrap();
    let vector = fixture.pace_compatibility;
    assert_eq!(
        hex::encode_upper(derive_compatibility_pace_password_key(&vector.password).unwrap()),
        vector.password_key
    );
    let handshake = PaceCompatibilityHandshake::begin_with_private_key(
        &vector.password,
        &hex::decode(vector.encrypted_nonce).unwrap(),
        &hex::decode(vector.reader_private_key).unwrap(),
    )
    .unwrap();
    assert_eq!(
        hex::encode_upper(handshake.public_key()),
        vector.reader_public_key
    );
    assert_eq!(hex::encode_upper(handshake.decrypted_nonce()), vector.nonce);
    let session = handshake
        .complete(&hex::decode(vector.chip_public_key).unwrap())
        .unwrap();
    assert_eq!(
        hex::encode_upper(session.encryption_key()),
        vector.session_encryption_key
    );
    assert_eq!(hex::encode_upper(session.mac_key()), vector.session_mac_key);
    assert_eq!(
        hex::encode_upper(session.send_sequence_counter()),
        vector.ssc
    );
}

#[test]
fn rust_matches_shared_apdu_behavior() {
    use marty_verification::chip_io::{
        build_read_binary_commands, encode_apdu_command, ApduResponse,
    };

    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/passport_chip_behavior.json")).unwrap();
    let vector = fixture.apdu;
    for command in vector.commands {
        let data = command.data.map(|value| hex::decode(value).unwrap());
        let encoded = encode_apdu_command(
            command.cla,
            command.ins,
            command.p1,
            command.p2,
            data.as_deref(),
            command.le,
        )
        .unwrap();
        assert_eq!(hex::encode_upper(encoded), command.encoded);
    }
    let extended_data = vec![vector.extended.data_byte; vector.extended.data_length];
    let encoded = encode_apdu_command(0, 0xDA, 0, 0, Some(&extended_data), None).unwrap();
    assert_eq!(encoded.len(), vector.extended.encoded_length);
    assert_eq!(
        hex::encode_upper(&encoded[..vector.extended.prefix.len() / 2]),
        vector.extended.prefix
    );
    assert_eq!(
        build_read_binary_commands(vector.read_length, vector.read_offset)
            .unwrap()
            .iter()
            .map(|command| hex::encode_upper(command.to_bytes()))
            .collect::<Vec<_>>(),
        vector.read_commands
    );
    for expected in vector.responses {
        let response = ApduResponse::from_bytes(&hex::decode(expected.encoded).unwrap()).unwrap();
        assert_eq!(response.is_success(), expected.success);
        assert_eq!(response.is_warning(), expected.warning);
        assert_eq!(response.is_error(), expected.error);
        assert_eq!(response.status_description(), expected.description);
    }
}
