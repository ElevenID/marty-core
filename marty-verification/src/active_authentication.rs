//! ICAO eMRTD Active Authentication protocol helpers.
//!
//! This module owns challenge generation, INTERNAL AUTHENTICATE APDU framing,
//! response validation, and exact challenge verification. Transport remains a
//! caller concern so the same kernel can be used by PC/SC, mobile NFC, and
//! simulator adapters.

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::chip_io::{ApduCommand, ApduResponse};
use crate::error::{VerificationError, VerificationResult};
use marty_crypto::iso9796::{
    iso9796_recover_message, iso9796_verify, Iso9796HashAlgorithm, Iso9796Scheme,
};

/// Successful or failed Active Authentication verification details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveAuthenticationVerification {
    pub is_valid: bool,
    pub recovered_message: Option<Vec<u8>>,
}

/// Generate a cryptographically random challenge of an exact bit length.
pub fn generate_challenge(key_size_bits: usize) -> VerificationResult<Vec<u8>> {
    if key_size_bits == 0 || !key_size_bits.is_multiple_of(8) {
        return Err(VerificationError::internal(
            "Active Authentication challenge size must be a non-zero multiple of 8 bits",
        ));
    }
    let byte_len = key_size_bits / 8;
    if byte_len > u8::MAX as usize {
        return Err(VerificationError::internal(
            "Active Authentication challenge exceeds short APDU capacity",
        ));
    }
    let mut challenge = vec![0u8; byte_len];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    Ok(challenge)
}

/// Build an ISO/IEC 7816-4 INTERNAL AUTHENTICATE short command APDU.
pub fn build_internal_authenticate_apdu(challenge: &[u8]) -> VerificationResult<Vec<u8>> {
    if challenge.is_empty() {
        return Err(VerificationError::internal(
            "Active Authentication challenge must not be empty",
        ));
    }
    if challenge.len() > u8::MAX as usize {
        return Err(VerificationError::internal(
            "Active Authentication challenge exceeds short APDU capacity",
        ));
    }
    Ok(ApduCommand {
        cla: 0x00,
        ins: 0x88,
        p1: 0x00,
        p2: 0x00,
        data: challenge.to_vec(),
        le: Some(0),
    }
    .to_bytes())
}

/// Parse a successful INTERNAL AUTHENTICATE response and return its signature.
pub fn parse_internal_authenticate_response(response: &[u8]) -> VerificationResult<Vec<u8>> {
    let response = ApduResponse::from_bytes(response)?;
    if !response.is_success() {
        return Err(VerificationError::internal(format!(
            "Active Authentication command failed with status {:04x}",
            response.status_word()
        )));
    }
    if response.data.is_empty() {
        return Err(VerificationError::internal(
            "Active Authentication response contains no signature",
        ));
    }
    Ok(response.data)
}

/// Verify that the signature recovers exactly the challenge that was sent.
pub fn verify_challenge(
    public_key_der: &[u8],
    challenge: &[u8],
    signature: &[u8],
    hash_algorithm: Iso9796HashAlgorithm,
) -> VerificationResult<ActiveAuthenticationVerification> {
    if challenge.is_empty() {
        return Err(VerificationError::internal(
            "Active Authentication challenge must not be empty",
        ));
    }

    let is_valid = iso9796_verify(
        public_key_der,
        challenge,
        signature,
        Iso9796Scheme::Scheme1,
        hash_algorithm,
    )?;
    if !is_valid {
        return Ok(ActiveAuthenticationVerification {
            is_valid: false,
            recovered_message: None,
        });
    }

    let recovered =
        iso9796_recover_message(public_key_der, signature, Iso9796Scheme::Scheme1, None)?;
    let exact_match = recovered == challenge;
    Ok(ActiveAuthenticationVerification {
        is_valid: exact_match,
        recovered_message: exact_match.then_some(recovered),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_crypto::iso9796::iso9796_scheme1_sign;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use rsa::RsaPrivateKey;

    #[test]
    fn builds_and_parses_internal_authenticate_apdus() {
        let challenge = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(
            hex::encode(build_internal_authenticate_apdu(&challenge).unwrap()),
            "008800001000112233445566778899aabbccddeeff00"
        );
        assert_eq!(
            parse_internal_authenticate_response(&[0xaa, 0xbb, 0x90, 0x00]).unwrap(),
            [0xaa, 0xbb]
        );
        assert!(parse_internal_authenticate_response(&[0xaa, 0xbb, 0x69, 0x82]).is_err());
        assert!(parse_internal_authenticate_response(&[0x90, 0x00]).is_err());
    }

    #[test]
    fn verifies_only_the_exact_challenge() {
        let private_key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
        let private_der = private_key.to_pkcs8_der().unwrap();
        let public_der = private_key.to_public_key().to_public_key_der().unwrap();
        let challenge = b"0123456789abcdef";
        let signature = iso9796_scheme1_sign(private_der.as_bytes(), challenge).unwrap();

        let valid = verify_challenge(
            public_der.as_bytes(),
            challenge,
            &signature,
            Iso9796HashAlgorithm::Sha256,
        )
        .unwrap();
        assert!(valid.is_valid);
        assert_eq!(
            valid.recovered_message.as_deref(),
            Some(challenge.as_slice())
        );

        let contained_but_not_exact = b"xx0123456789abcdefyy";
        let signature =
            iso9796_scheme1_sign(private_der.as_bytes(), contained_but_not_exact).unwrap();
        assert!(
            !verify_challenge(
                public_der.as_bytes(),
                challenge,
                &signature,
                Iso9796HashAlgorithm::Sha256,
            )
            .unwrap()
            .is_valid
        );
    }
}
