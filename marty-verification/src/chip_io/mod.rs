//! Chip/NFC I/O helpers for eMRTD passports.
//!
//! This module provides:
//! - A `PassportReader` abstraction for high-level SOD + DG reading.
//! - A `PassportChip` abstraction for low-level APDU communication.
//! - BAC (Basic Access Control) session key derivation and secure messaging
//!   per ICAO 9303 Part 11 §9.
//! - PACE (Password Authenticated Connection Establishment) key derivation and
//!   AES-CBC secure messaging per ICAO 9303 Part 11 Annex G / BSI TR-03110.
//!
//! # Chip Communication Architecture
//!
//! ```text
//! NFC hardware                ← implement PassportChip (transceive)
//! │
//! ├─ BacSession::establish()  ← derives session keys, runs EXTERNAL AUTHENTICATE
//! │   └─ SecureMessagingSession (3DES-CBC + Retail-MAC)
//! │
//! └─ PaceSession::establish() ← derives keys from password, runs GENERAL AUTHENTICATE
//!     └─ SecureMessagingSession (AES-CBC-nopad + AES-CMAC)
//! ```

use std::collections::HashMap;

use crate::error::{VerificationError, VerificationResult};
use crate::trust_anchor::CscaRegistry;
use crate::verification::emrtd::{verify_emrtd, SecurityObject};

// ─── APDU primitives ──────────────────────────────────────────────────────────

/// ISO/IEC 7816-4 command APDU.
#[derive(Debug, Clone)]
pub struct ApduCommand {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    /// Command data (Lc is derived from `data.len()`).
    pub data: Vec<u8>,
    /// Expected response length (`Le`).  `None` = no Le byte.
    pub le: Option<usize>,
}

impl ApduCommand {
    /// Parse an ISO/IEC 7816-4 short command APDU.
    pub fn from_bytes(raw: &[u8]) -> VerificationResult<Self> {
        if raw.len() < 4 {
            return Err(VerificationError::internal(
                "APDU command must contain CLA INS P1 P2".to_string(),
            ));
        }
        let (cla, ins, p1, p2) = (raw[0], raw[1], raw[2], raw[3]);
        if raw.len() == 4 {
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: None,
            });
        }
        if raw.len() == 5 {
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: Some(raw[4] as usize),
            });
        }
        if raw[4] != 0 {
            let lc = raw[4] as usize;
            let data_end = 5usize.checked_add(lc).ok_or_else(|| {
                VerificationError::internal("APDU command length overflow".to_string())
            })?;
            if raw.len() != data_end && raw.len() != data_end + 1 {
                return Err(VerificationError::internal(
                    "APDU command has inconsistent short-form Lc/Le".to_string(),
                ));
            }
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: raw[5..data_end].to_vec(),
                le: (raw.len() == data_end + 1).then(|| raw[data_end] as usize),
            });
        }
        if raw.len() == 7 {
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: Some(u16::from_be_bytes([raw[5], raw[6]]) as usize),
            });
        }
        if raw.len() < 7 {
            return Err(VerificationError::internal(
                "Extended APDU is missing its two-byte length",
            ));
        }
        let lc = u16::from_be_bytes([raw[5], raw[6]]) as usize;
        let data_end = 7usize
            .checked_add(lc)
            .ok_or_else(|| VerificationError::internal("Extended APDU command length overflow"))?;
        if raw.len() != data_end && raw.len() != data_end + 2 {
            return Err(VerificationError::internal(
                "APDU command has inconsistent extended Lc/Le",
            ));
        }
        Ok(Self {
            cla,
            ins,
            p1,
            p2,
            data: raw[7..data_end].to_vec(),
            le: (raw.len() == data_end + 2)
                .then(|| u16::from_be_bytes([raw[data_end], raw[data_end + 1]]) as usize),
        })
    }

    /// Serialise to ISO/IEC 7816-4 byte wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_apdu_command(
            self.cla,
            self.ins,
            self.p1,
            self.p2,
            (!self.data.is_empty()).then_some(self.data.as_slice()),
            self.le,
        )
        .expect("validated APDU command")
    }
}

/// Encode short or extended ISO/IEC 7816-4 command APDU fields.
pub fn encode_apdu_command(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Option<&[u8]>,
    le: Option<usize>,
) -> VerificationResult<Vec<u8>> {
    let data_len = data.map_or(0, <[u8]>::len);
    if data_len > u16::MAX as usize {
        return Err(VerificationError::internal(
            "APDU command data exceeds extended-length capacity",
        ));
    }
    if le.is_some_and(|value| value > u16::MAX as usize) {
        return Err(VerificationError::internal(
            "APDU Le exceeds extended-length capacity",
        ));
    }

    let mut encoded = vec![cla, ins, p1, p2];
    match (data, le) {
        (None, None) => {}
        (None, Some(expected)) if expected <= u8::MAX as usize => {
            encoded.push(expected as u8);
        }
        (None, Some(expected)) => {
            encoded.push(0);
            encoded.extend_from_slice(&(expected as u16).to_be_bytes());
        }
        (Some(value), expected) if value.len() <= u8::MAX as usize => {
            encoded.push(value.len() as u8);
            encoded.extend_from_slice(value);
            if let Some(expected) = expected {
                if expected > u8::MAX as usize {
                    return Err(VerificationError::internal(
                        "Short APDU data cannot be combined with extended Le",
                    ));
                }
                encoded.push(expected as u8);
            }
        }
        (Some(value), expected) => {
            encoded.push(0);
            encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
            encoded.extend_from_slice(value);
            if let Some(expected) = expected {
                encoded.extend_from_slice(&(expected as u16).to_be_bytes());
            }
        }
    }
    Ok(encoded)
}

/// ISO/IEC 7816-4 response APDU.
#[derive(Debug, Clone)]
pub struct ApduResponse {
    /// Response data (before status word).
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl ApduResponse {
    /// Parse raw response bytes (last two bytes are SW1/SW2).
    pub fn from_bytes(raw: &[u8]) -> VerificationResult<Self> {
        if raw.len() < 2 {
            return Err(VerificationError::internal(
                "APDU response too short (need at least SW1 SW2)".to_string(),
            ));
        }
        let (data, sw) = raw.split_at(raw.len() - 2);
        Ok(Self {
            data: data.to_vec(),
            sw1: sw[0],
            sw2: sw[1],
        })
    }

    /// 16-bit status word.
    #[inline]
    pub fn status_word(&self) -> u16 {
        ((self.sw1 as u16) << 8) | self.sw2 as u16
    }

    /// `true` when SW = 0x9000.
    #[inline]
    pub fn is_success(&self) -> bool {
        self.status_word() == 0x9000
    }

    pub fn is_warning(&self) -> bool {
        matches!(self.sw1, 0x62 | 0x63)
    }

    pub fn is_error(&self) -> bool {
        self.sw1 >= 0x64
    }

    pub fn status_description(&self) -> String {
        let description = match self.status_word() {
            0x9000 => Some("Success"),
            0x6100 => Some("Response bytes available"),
            0x6281 => Some("Part of returned data corrupted"),
            0x6282 => Some("End of file reached"),
            0x6283 => Some("Selected file invalidated"),
            0x6284 => Some("File control information not formatted"),
            0x6300 => Some("Authentication failed"),
            0x6381 => Some("File filled up by last write"),
            0x6400 => Some("Execution error"),
            0x6581 => Some("Memory failure"),
            0x6700 => Some("Wrong length"),
            0x6800 => Some("Functions in CLA not supported"),
            0x6900 => Some("Command not allowed"),
            0x6A00 => Some("Wrong parameters P1-P2"),
            0x6A80 => Some("Incorrect parameters in data field"),
            0x6A81 => Some("Function not supported"),
            0x6A82 => Some("File not found"),
            0x6A83 => Some("Record not found"),
            0x6A84 => Some("Not enough memory space"),
            0x6A86 => Some("Incorrect parameters P1-P2"),
            0x6A88 => Some("Referenced data not found"),
            0x6B00 => Some("Wrong parameters P1-P2"),
            0x6C00 => Some("Wrong Le field"),
            0x6D00 => Some("Instruction code not supported"),
            0x6E00 => Some("Class not supported"),
            0x6F00 => Some("No precise diagnosis"),
            _ => None,
        };
        if let Some(description) = description {
            return description.to_string();
        }
        let masked = self.status_word() & 0xFF00;
        let masked_description = match masked {
            0x6100 => Some("Response bytes available"),
            0x6200 => Some("Warning: state unchanged"),
            0x6300 => Some("Warning: state changed"),
            0x6C00 => Some("Wrong Le field"),
            _ => None,
        };
        masked_description.map_or_else(
            || format!("Unknown status: 0x{:04X}", self.status_word()),
            |value| format!("{value} (0x{:04X})", self.status_word()),
        )
    }
}

pub fn build_read_binary_commands(
    length: usize,
    offset: usize,
) -> VerificationResult<Vec<ApduCommand>> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| VerificationError::internal("APDU read range overflow"))?;
    if end > u16::MAX as usize + 1 {
        return Err(VerificationError::internal(
            "APDU read range exceeds READ BINARY offset capacity",
        ));
    }
    let mut commands = Vec::with_capacity(length.div_ceil(255));
    let mut bytes_read = 0;
    while bytes_read < length {
        let chunk = (length - bytes_read).min(255);
        let current = offset + bytes_read;
        commands.push(ApduCommand {
            cla: 0,
            ins: 0xB0,
            p1: (current >> 8) as u8,
            p2: current as u8,
            data: Vec::new(),
            le: Some(chunk),
        });
        bytes_read += chunk;
    }
    Ok(commands)
}

pub fn passport_data_group_file_id(data_group: u8) -> VerificationResult<u16> {
    match data_group {
        1..=4 => Ok(0x0100 + u16::from(data_group)),
        14 => Ok(0x010E),
        15 => Ok(0x010F),
        _ => Err(VerificationError::internal(format!(
            "Unsupported passport data group: {data_group}"
        ))),
    }
}

// ─── Low-level chip transport ─────────────────────────────────────────────────

/// Low-level APDU transport towards an NFC chip.
///
/// Implement this trait using your NFC driver (PC/SC, Android HCE, etc.).
/// The easiest way to test is via `MockPassportChip`.
pub trait PassportChip: Send + Sync {
    /// Send one command APDU and receive a response APDU.
    fn transceive(&mut self, cmd: &ApduCommand) -> VerificationResult<ApduResponse>;
}

/// In-memory mock chip for unit testing — replays a fixed response sequence.
pub struct MockPassportChip {
    responses: Vec<ApduResponse>,
    cursor: usize,
}

impl MockPassportChip {
    /// Create a mock that returns `responses` in order.
    pub fn new(responses: Vec<ApduResponse>) -> Self {
        Self {
            responses,
            cursor: 0,
        }
    }
}

impl PassportChip for MockPassportChip {
    fn transceive(&mut self, _cmd: &ApduCommand) -> VerificationResult<ApduResponse> {
        if self.cursor >= self.responses.len() {
            return Err(VerificationError::internal(
                "MockPassportChip: no more responses".to_string(),
            ));
        }
        let resp = self.responses[self.cursor].clone();
        self.cursor += 1;
        Ok(resp)
    }
}

// ─── High-level reader (existing interface, unchanged) ───────────────────────

/// Result of reading a passport chip.
#[derive(Debug, Clone)]
pub struct ReadResult {
    /// Raw EF.SOD bytes.
    pub sod: Vec<u8>,
    /// Data group contents keyed by DG number (e.g., 1 for DG1).
    pub data_groups: HashMap<u8, Vec<u8>>,
    /// Optional country hint (ISO 3166).
    pub country: Option<String>,
}

/// Passport reader abstraction.
pub trait PassportReader: Send + Sync {
    /// Read passport data (SOD + DGs) from the chip.
    fn read_passport(&self) -> VerificationResult<ReadResult>;
}

/// Simple mock reader useful for tests or injected data.
pub struct MockPassportReader {
    data: ReadResult,
}

impl MockPassportReader {
    /// Create a mock reader from pre-parsed data.
    pub fn new(sod: Vec<u8>, data_groups: HashMap<u8, Vec<u8>>, country: Option<String>) -> Self {
        Self {
            data: ReadResult {
                sod,
                data_groups,
                country,
            },
        }
    }
}

impl PassportReader for MockPassportReader {
    fn read_passport(&self) -> VerificationResult<ReadResult> {
        Ok(self.data.clone())
    }
}

/// Read from a passport reader and verify using the CSCA registry.
pub fn verify_from_reader<R: PassportReader>(
    reader: &R,
    registry: &CscaRegistry,
) -> crate::verification::emrtd::EmrtdVerificationResult {
    match reader.read_passport() {
        Ok(read) => {
            let security_object = match SecurityObject::from_sod_der(&read.sod, read.country) {
                Ok(so) => so,
                Err(e) => {
                    let mut result = crate::verification::emrtd::EmrtdVerificationResult::default();
                    result.errors.push(e.to_string());
                    return result;
                }
            };
            verify_emrtd(&security_object, &read.data_groups, registry)
        }
        Err(e) => {
            let mut result = crate::verification::emrtd::EmrtdVerificationResult::default();
            result.errors.push(e.to_string());
            result
        }
    }
}

// ─── BAC — Basic Access Control ──────────────────────────────────────────────
//
// Reference: ICAO 9303-11 §9 and Annex D.

/// MRZ key information required to derive BAC session keys.
///
/// Extract these three fields from the Machine Readable Zone (TD-3 layout):
/// - Document Number: MRZ chars 1–9, check digit at char 10.
/// - Date of Birth: MRZ chars 62–67, check digit at char 68.
/// - Date of Expiry: MRZ chars 92–97, check digit at char 98.
#[derive(Debug, Clone)]
pub struct MrzKeyInfo {
    /// Document number (9 chars) + check digit (1 char) = 10 chars.
    pub doc_number_with_check: String,
    /// Date of birth YYMMDD (6 chars) + check digit (1 char) = 7 chars.
    pub dob_with_check: String,
    /// Date of expiry YYMMDD (6 chars) + check digit (1 char) = 7 chars.
    pub expiry_with_check: String,
}

impl MrzKeyInfo {
    /// Construct from the three MRZ key fields (without check digits) and
    /// compute the Luhn-style check digits automatically.
    ///
    /// Use [`MrzKeyInfo { … }`] directly if you already have check digits.
    pub fn from_mrz_fields(doc_number: &str, dob: &str, expiry: &str) -> Self {
        let doc_cd = mrz_check_digit(doc_number.as_bytes()) as char;
        let dob_cd = mrz_check_digit(dob.as_bytes()) as char;
        let exp_cd = mrz_check_digit(expiry.as_bytes()) as char;
        Self {
            doc_number_with_check: format!("{}{}", doc_number, doc_cd),
            dob_with_check: format!("{}{}", dob, dob_cd),
            expiry_with_check: format!("{}{}", expiry, exp_cd),
        }
    }
}

/// Derived BAC session keys.
#[derive(Clone)]
pub struct BacKeys {
    /// 16-byte 3DES encryption key (K1‖K2).
    pub k_enc: [u8; 16],
    /// 16-byte 3DES MAC key (K1‖K2).
    pub k_mac: [u8; 16],
    /// First 16 bytes of SHA-1(MRZ information).
    pub k_seed: [u8; 16],
}

impl std::fmt::Debug for BacKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BacKeys { … }")
    }
}

impl BacKeys {
    pub fn from_parts(k_enc: [u8; 16], k_mac: [u8; 16], k_seed: [u8; 16]) -> Self {
        Self {
            k_enc,
            k_mac,
            k_seed,
        }
    }
}

/// Established BAC secure-messaging session.
///
/// After [`BacSession::establish`] succeeds, use
/// [`protect_command`](BacSession::protect_command) /
/// [`unprotect_response`](BacSession::unprotect_response) for all subsequent
/// APDU exchanges with the chip.
pub struct BacSession {
    /// Session encryption key (KSenc).
    k_enc: [u8; 16],
    /// Session MAC key (KSmac).
    k_mac: [u8; 16],
    /// Send Sequence Counter (8 bytes, big-endian).
    ssc: [u8; 8],
}

/// In-progress BAC mutual-authentication exchange.
pub struct BacHandshake {
    base_keys: BacKeys,
    rnd_ifd: [u8; 8],
    k_ifd: [u8; 16],
    rnd_ic: [u8; 8],
}

impl BacHandshake {
    /// Start a BAC exchange with cryptographically random reader material.
    pub fn begin(mrz: &MrzKeyInfo, rnd_ic: &[u8]) -> VerificationResult<Self> {
        use rand::RngCore;

        let mut rnd_ifd = [0u8; 8];
        let mut k_ifd = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut rnd_ifd);
        rand::rngs::OsRng.fill_bytes(&mut k_ifd);
        Self::begin_with_random(mrz, rnd_ic, rnd_ifd, k_ifd)
    }

    /// Start a BAC exchange from previously derived base keys.
    pub fn begin_with_keys(base_keys: BacKeys, rnd_ic: &[u8]) -> VerificationResult<Self> {
        use rand::RngCore;

        let mut rnd_ifd = [0u8; 8];
        let mut k_ifd = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut rnd_ifd);
        rand::rngs::OsRng.fill_bytes(&mut k_ifd);
        let rnd_ic = rnd_ic.try_into().map_err(|_| {
            VerificationError::internal("BAC: chip challenge must be exactly 8 bytes".to_string())
        })?;
        Ok(Self {
            base_keys,
            rnd_ifd,
            k_ifd,
            rnd_ic,
        })
    }

    /// Start a deterministic BAC exchange for conformance-vector testing.
    pub fn begin_with_random(
        mrz: &MrzKeyInfo,
        rnd_ic: &[u8],
        rnd_ifd: [u8; 8],
        k_ifd: [u8; 16],
    ) -> VerificationResult<Self> {
        let rnd_ic: [u8; 8] = rnd_ic.try_into().map_err(|_| {
            VerificationError::internal("BAC: chip challenge must be exactly 8 bytes".to_string())
        })?;
        Ok(Self {
            base_keys: derive_bac_base_keys(mrz)?,
            rnd_ifd,
            k_ifd,
            rnd_ic,
        })
    }

    /// Build `E.IFD || M.IFD`, the 40-byte EXTERNAL AUTHENTICATE data field.
    pub fn command_data(&self) -> VerificationResult<Vec<u8>> {
        let mut plaintext = Vec::with_capacity(32);
        plaintext.extend_from_slice(&self.rnd_ifd);
        plaintext.extend_from_slice(&self.rnd_ic);
        plaintext.extend_from_slice(&self.k_ifd);
        let encrypted = marty_crypto::des::tdes_cbc_encrypt(
            &extend_to_24_bytes(&self.base_keys.k_enc),
            &[0u8; 8],
            &plaintext,
        )
        .map_err(|error| VerificationError::internal(format!("BAC encrypt failed: {error}")))?;
        let mac = retail_mac_3des(&self.base_keys.k_mac, &encrypted)?;
        let mut result = encrypted;
        result.extend_from_slice(&mac);
        Ok(result)
    }

    /// Verify the chip response and establish secure-messaging keys.
    pub fn complete(self, response: &[u8]) -> VerificationResult<BacSession> {
        if response.len() != 40 {
            return Err(VerificationError::internal(format!(
                "BAC: response must be exactly 40 bytes, got {}",
                response.len()
            )));
        }
        let (encrypted, received_mac) = response.split_at(32);
        let expected_mac = retail_mac_3des(&self.base_keys.k_mac, encrypted)?;
        if !constant_time_eq(&expected_mac, received_mac) {
            return Err(VerificationError::internal(
                "BAC: chip response MAC verification failed".to_string(),
            ));
        }
        let plaintext = marty_crypto::des::tdes_cbc_decrypt(
            &extend_to_24_bytes(&self.base_keys.k_enc),
            &[0u8; 8],
            encrypted,
        )
        .map_err(|error| VerificationError::internal(format!("BAC decrypt failed: {error}")))?;
        if plaintext[..8] != self.rnd_ic {
            return Err(VerificationError::internal(
                "BAC: reflected Rnd.IC mismatch".to_string(),
            ));
        }
        if plaintext[8..16] != self.rnd_ifd {
            return Err(VerificationError::internal(
                "BAC: reflected Rnd.IFD mismatch".to_string(),
            ));
        }
        derive_bac_session_keys(&self.k_ifd, &plaintext[16..32], &self.rnd_ic, &self.rnd_ifd)
    }
}

impl BacSession {
    /// Restore a BAC secure-messaging session from established key material.
    pub fn from_session_keys(k_enc: [u8; 16], k_mac: [u8; 16], ssc: [u8; 8]) -> Self {
        Self { k_enc, k_mac, ssc }
    }

    pub fn encryption_key(&self) -> &[u8; 16] {
        &self.k_enc
    }

    pub fn mac_key(&self) -> &[u8; 16] {
        &self.k_mac
    }

    pub fn send_sequence_counter(&self) -> &[u8; 8] {
        &self.ssc
    }

    /// Perform the full BAC handshake with the chip.
    ///
    /// Sends `GET CHALLENGE` followed by `EXTERNAL AUTHENTICATE` to the chip,
    /// then derives shared session keys.
    ///
    /// # Errors
    /// Returns an error when:
    /// - An APDU command fails (chip rejected, wrong SW).
    /// - The chip's response MAC is invalid.
    /// - The reflected nonces don't match.
    pub fn establish(chip: &mut dyn PassportChip, mrz: &MrzKeyInfo) -> VerificationResult<Self> {
        // ── Step 1: Select eMRTD AID ─────────────────────────────────────────
        let aid: &[u8] = &[0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];
        let select = ApduCommand {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x0C,
            data: aid.to_vec(),
            le: None,
        };
        let resp = chip.transceive(&select)?;
        if !resp.is_success() {
            return Err(VerificationError::internal(format!(
                "BAC: SELECT AID failed with SW {:04X}",
                resp.status_word()
            )));
        }

        // ── Step 2: GET CHALLENGE → Rnd.IC (8 bytes) ─────────────────────────
        let get_challenge = ApduCommand {
            cla: 0x00,
            ins: 0x84,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
            le: Some(8),
        };
        let resp = chip.transceive(&get_challenge)?;
        if !resp.is_success() || resp.data.len() != 8 {
            return Err(VerificationError::internal(format!(
                "BAC: GET CHALLENGE failed (SW {:04X}, {} bytes)",
                resp.status_word(),
                resp.data.len()
            )));
        }
        let handshake = BacHandshake::begin(mrz, &resp.data)?;

        // ── Step 3: Generate Rnd.IFD + KID.IFD ───────────────────────────────

        // ── Step 4: E_IFD = 3DES-CBC(K_ENC, 0, Rnd.IFD‖Rnd.IC‖KID.IFD) ─────

        // ── Step 5: M_IFD = Retail-MAC(K_MAC, E_IFD) ─────────────────────────

        // ── Step 6: EXTERNAL AUTHENTICATE ────────────────────────────────────
        let auth_data = handshake.command_data()?;

        let ext_auth = ApduCommand {
            cla: 0x00,
            ins: 0x82,
            p1: 0x00,
            p2: 0x00,
            data: auth_data,
            le: Some(40),
        };
        let resp = chip.transceive(&ext_auth)?;
        if !resp.is_success() {
            return Err(VerificationError::internal(format!(
                "BAC: EXTERNAL AUTHENTICATE failed with SW {:04X}",
                resp.status_word()
            )));
        }
        if resp.data.len() != 40 {
            return Err(VerificationError::internal(format!(
                "BAC: unexpected EXTERNAL AUTHENTICATE response length {}",
                resp.data.len()
            )));
        }

        // ── Step 7: Verify and decrypt chip response ──────────────────────────
        handshake.complete(&resp.data)

        // ── Step 8: Derive session keys ───────────────────────────────────────
    }

    /// Protect a plaintext command APDU with 3DES-CBC + Retail-MAC secure messaging.
    ///
    /// Increments the internal Send Sequence Counter.  The returned command
    /// carries the DO'87 (encrypted data) and DO'8E (MAC) objects.
    pub fn protect_command(&mut self, cmd: &ApduCommand) -> VerificationResult<ApduCommand> {
        increment_ssc(&mut self.ssc);

        // Build protected data object (DO'87) when command has data
        let mut do87: Vec<u8> = Vec::new();
        if !cmd.data.is_empty() {
            let padded = iso7816_pad(&cmd.data);
            let k24 = extend_to_24_bytes(&self.k_enc);
            let enc = marty_crypto::des::tdes_cbc_encrypt(&k24, &[0u8; 8], &padded)
                .map_err(|e| VerificationError::internal(format!("SM encrypt: {}", e)))?;
            // DO'87 = tag 87, length, 01 (padding indicator), ciphertext
            let do87_len = u8::try_from(enc.len() + 1).map_err(|_| {
                VerificationError::internal(
                    "DO87 data exceeds short-form TLV limit (254)".to_string(),
                )
            })?;
            do87.push(0x87);
            do87.push(do87_len);
            do87.push(0x01); // padding indicator
            do87.extend_from_slice(&enc);
        }

        // Build expected length object (DO'97) when cmd has Le
        let do97 = if let Some(le) = cmd.le {
            vec![0x97, 0x01, le as u8]
        } else {
            Vec::new()
        };

        // MAC input: SSC || header bytes (masked) || DO'87 || DO'97
        let masked_header = [
            cmd.cla | 0x0C,
            cmd.ins,
            cmd.p1,
            cmd.p2,
            0x80,
            0x00,
            0x00,
            0x00,
        ];
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&self.ssc);
        mac_input.extend_from_slice(&masked_header);
        mac_input.extend_from_slice(&do87);
        mac_input.extend_from_slice(&do97);

        let mac = retail_mac_3des(&self.k_mac, &mac_input)?;

        // DO'8E = tag 8E, length 08, mac
        let mut sm_data = Vec::new();
        sm_data.extend_from_slice(&do87);
        sm_data.extend_from_slice(&do97);
        sm_data.push(0x8E);
        sm_data.push(0x08);
        sm_data.extend_from_slice(&mac);

        Ok(ApduCommand {
            cla: cmd.cla | 0x0C, // set secure messaging bit
            ins: cmd.ins,
            p1: cmd.p1,
            p2: cmd.p2,
            data: sm_data,
            le: Some(0),
        })
    }

    /// Strip and verify 3DES-MAC secure messaging from a chip response.
    pub fn unprotect_response(&mut self, resp: &ApduResponse) -> VerificationResult<ApduResponse> {
        increment_ssc(&mut self.ssc);

        // Parse TLV objects from response data
        let data = &resp.data;
        let mut plain_data = Vec::new();
        let mut received_mac = [0u8; 8];
        let mut do87_bytes = Vec::<u8>::new();
        let mut do99_bytes = Vec::<u8>::new();
        let mut status = None;
        let mut has_mac = false;

        let mut i = 0;
        while i < data.len() {
            let tag = data[i];
            if i + 1 >= data.len() {
                break;
            }
            let len = data[i + 1] as usize;
            if i + 2 + len > data.len() {
                break;
            }
            let value = &data[i + 2..i + 2 + len];
            match tag {
                0x87 => {
                    // Encrypted data (first byte is padding indicator)
                    do87_bytes = data[i..i + 2 + len].to_vec();
                    if !value.is_empty() && value[0] == 0x01 {
                        let ciphertext = &value[1..];
                        let k24 = extend_to_24_bytes(&self.k_enc);
                        let decrypted =
                            marty_crypto::des::tdes_cbc_decrypt(&k24, &[0u8; 8], ciphertext)
                                .map_err(|e| {
                                    VerificationError::internal(format!("SM decrypt: {}", e))
                                })?;
                        plain_data = iso7816_unpad(&decrypted)?;
                    }
                }
                0x99 if len == 2 => {
                    do99_bytes = data[i..i + 2 + len].to_vec();
                    status = Some((value[0], value[1]));
                }
                0x8E if len == 8 => {
                    received_mac.copy_from_slice(value);
                    has_mac = true;
                }
                _ => {}
            }
            i += 2 + len;
        }

        if !has_mac || do99_bytes.is_empty() {
            return Err(VerificationError::internal(
                "BAC SM: protected response missing DO99 or DO8E".to_string(),
            ));
        }
        // Verify MAC: SSC || DO'87 || DO'99
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&self.ssc);
        mac_input.extend_from_slice(&do87_bytes);
        mac_input.extend_from_slice(&do99_bytes);

        let expected = retail_mac_3des(&self.k_mac, &mac_input)?;
        if !constant_time_eq(&expected, &received_mac) {
            return Err(VerificationError::internal(
                "BAC SM: response MAC verification failed".to_string(),
            ));
        }

        let (sw1, sw2) = status.expect("status checked above");
        Ok(ApduResponse {
            data: plain_data,
            sw1,
            sw2,
        })
    }
}

// ─── PACE — Password Authenticated Connection Establishment ──────────────────
//
// Reference: ICAO 9303-11 Annex G; BSI TR-03110.
//
// PACE replaces BAC on all modern ePassports (LDS v1.8+).  It uses
// Elliptic-Curve Diffie-Hellman with a mapped generator to derive session keys
// that are independent of the static password and forward-secret.
//
// This implementation provides:
//   1. The KDF to decrypt the chip-provided nonce.
//   2. Session key derivation from the shared ECDH secret.
//   3. AES-CBC + AES-CMAC secure messaging for subsequent APDUs.
//
// The actual ECDH ephemeral exchange is performed by the caller (steps 3-4 of
// the PACE protocol), since it requires the NFC chip as an oracle.

/// Password type for PACE key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacePassword {
    /// 6-digit Card Access Number (printed on the card).
    Can(String),
    /// Machine Readable Zone string (composite, see ICAO 9303).
    Mrz(String),
    /// Personal Identification Number.
    Pin(String),
}

impl PacePassword {
    fn as_bytes(&self) -> &[u8] {
        match self {
            PacePassword::Can(s) | PacePassword::Mrz(s) | PacePassword::Pin(s) => s.as_bytes(),
        }
    }
}

/// Native state for the pre-v1 two-message PACE compatibility API.
///
/// This preserves the established application contract while ensuring its
/// password processing, nonce decryption, ECDH, and session derivation have a
/// single Rust implementation. New protocol integrations should use the full
/// [`PaceSession`] state machine as it evolves rather than reproducing these
/// compatibility steps in another language.
pub struct PaceCompatibilityHandshake {
    private_key: [u8; 32],
    public_key: Vec<u8>,
    nonce: Vec<u8>,
}

impl PaceCompatibilityHandshake {
    pub fn begin(password: &str, encrypted_nonce: &[u8]) -> VerificationResult<Self> {
        let (private_key, _) = marty_crypto::ecdh::p256_generate_keypair();
        Self::begin_with_private_key(password, encrypted_nonce, &private_key)
    }

    pub fn begin_with_private_key(
        password: &str,
        encrypted_nonce: &[u8],
        private_key: &[u8],
    ) -> VerificationResult<Self> {
        if encrypted_nonce.is_empty() || !encrypted_nonce.len().is_multiple_of(8) {
            return Err(VerificationError::internal(
                "PACE encrypted nonce must be non-empty and block aligned",
            ));
        }
        let private_key: [u8; 32] = private_key
            .try_into()
            .map_err(|_| VerificationError::internal("PACE P-256 private key must be 32 bytes"))?;
        let key = derive_compatibility_pace_password_key(password)?;
        let decrypted = marty_crypto::des::tdes_cbc_decrypt(
            &extend_to_24_bytes(&key),
            &[0u8; 8],
            encrypted_nonce,
        )
        .map_err(|error| VerificationError::internal(format!("PACE nonce decrypt: {error}")))?;
        let nonce = iso7816_unpad(&decrypted)?;
        if nonce.is_empty() {
            return Err(VerificationError::internal(
                "PACE decrypted nonce must not be empty",
            ));
        }
        let key_pair = marty_crypto::ecdh::P256KeyPair::from_secret_key(&private_key)?;
        Ok(Self {
            private_key,
            public_key: key_pair.public_key_uncompressed(),
            nonce,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn decrypted_nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn complete(mut self, chip_public_key: &[u8]) -> VerificationResult<BacSession> {
        use sha2::{Digest, Sha256};
        use zeroize::Zeroize;

        let shared_secret = marty_crypto::ecdh::p256_agree(&self.private_key, chip_public_key)?;
        self.private_key.zeroize();
        let mut input = shared_secret;
        input.extend_from_slice(&self.nonce);
        let digest = Sha256::digest(&input);
        let seed = &digest[..16];
        let k_enc = bac_kdf_16(seed, 1)?;
        let k_mac = bac_kdf_16(seed, 2)?;
        let mut ssc = [0u8; 8];
        ssc.copy_from_slice(&digest[digest.len() - 8..]);
        Ok(BacSession { k_enc, k_mac, ssc })
    }
}

/// Derive the 3DES password key used by the established compatibility API.
pub fn derive_compatibility_pace_password_key(password: &str) -> VerificationResult<[u8; 16]> {
    use sha1::{Digest, Sha1};

    let seed = if password.chars().all(|value| value.is_ascii_digit())
        && (6..=10).contains(&password.len())
    {
        Sha1::digest(password.as_bytes())[..16].to_vec()
    } else {
        let parsed = crate::mrz::parser::parse_mrz_string(password).map_err(|error| {
            VerificationError::internal(format!("Unsupported PACE password format: {error}"))
        })?;
        let normalized: String = parsed
            .document_number
            .to_ascii_uppercase()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(9)
            .collect();
        let document_number = format!("{normalized:<9}").replace(' ', "<");
        let information = format!(
            "{}{}{}{}{}{}",
            document_number,
            mrz_check_digit(document_number.as_bytes()) as char,
            parsed.date_of_birth,
            mrz_check_digit(parsed.date_of_birth.as_bytes()) as char,
            parsed.date_of_expiry,
            mrz_check_digit(parsed.date_of_expiry.as_bytes()) as char,
        );
        Sha1::digest(information.as_bytes())[..16].to_vec()
    };
    let mut key: [u8; 16] = seed.try_into().expect("SHA-1 prefix is 16 bytes");
    adjust_des_parity(&mut key);
    Ok(key)
}

/// PACE-specific symmetric keys.
#[derive(Clone)]
pub struct PaceKeys {
    /// Encryption key (KSenc) — 16 bytes for AES-128.
    pub k_enc: [u8; 16],
    /// MAC key (KSmac) — 16 bytes for AES-128.
    pub k_mac: [u8; 16],
}

impl std::fmt::Debug for PaceKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PaceKeys { … }")
    }
}

/// Established PACE secure-messaging session (AES-128-CBC + AES-CMAC).
pub struct PaceSession {
    k_enc: [u8; 16],
    k_mac: [u8; 16],
    /// Send Sequence Counter (16 bytes, big-endian for AES).
    ssc: [u8; 16],
}

impl PaceSession {
    /// Derive the initial password-encryption key for decrypting the chip nonce.
    ///
    /// Call this after `GET NONCE` to decrypt `enc_nonce`:
    /// ```text
    /// s = AES-128-CBC-decrypt(KPwd, enc_nonce, IV=0)
    /// ```
    /// The caller then performs the generator mapping (DH) and ECDH exchange
    /// before calling [`PaceSession::from_shared_secret`].
    pub fn derive_nonce_key(password: &PacePassword) -> [u8; 16] {
        pace_kdf_16(password.as_bytes(), 3)
    }

    /// Decrypt the chip nonce using the password-derived key.
    ///
    /// `enc_nonce` is the 16-byte encrypted nonce from the chip's GET NONCE response.
    pub fn decrypt_chip_nonce(
        password: &PacePassword,
        enc_nonce: &[u8],
    ) -> VerificationResult<Vec<u8>> {
        let kpwd = Self::derive_nonce_key(password);
        marty_crypto::symmetric::aes_128_cbc_decrypt_nopad(&kpwd, &[0u8; 16], enc_nonce)
            .map_err(|e| VerificationError::internal(format!("PACE nonce decrypt: {}", e)))
    }

    /// Derive PACE session keys from the ECDH shared secret `h`.
    ///
    /// Call this after the Diffie-Hellman exchange is complete.
    /// Then use the session for protecting subsequent APDU exchanges.
    pub fn from_shared_secret(shared_secret: &[u8]) -> Self {
        let k_enc = pace_kdf_16(shared_secret, 1);
        let k_mac = pace_kdf_16(shared_secret, 2);
        Self {
            k_enc,
            k_mac,
            ssc: [0u8; 16],
        }
    }

    /// Protect a plaintext command APDU with AES-128-CBC + AES-CMAC secure messaging.
    pub fn protect_command(&mut self, cmd: &ApduCommand) -> VerificationResult<ApduCommand> {
        increment_ssc_16(&mut self.ssc);

        let mut do87: Vec<u8> = Vec::new();
        if !cmd.data.is_empty() {
            let padded = iso7816_pad(&cmd.data);
            let enc =
                marty_crypto::symmetric::aes_128_cbc_encrypt_nopad(&self.k_enc, &self.ssc, &padded)
                    .map_err(|e| VerificationError::internal(format!("PACE SM encrypt: {}", e)))?;
            let do87_len = u8::try_from(enc.len() + 1).map_err(|_| {
                VerificationError::internal(
                    "PACE DO87 data exceeds short-form TLV limit (254)".to_string(),
                )
            })?;
            do87.push(0x87);
            do87.push(do87_len);
            do87.push(0x01);
            do87.extend_from_slice(&enc);
        }

        let do97 = if let Some(le) = cmd.le {
            vec![0x97, 0x01, le as u8]
        } else {
            Vec::new()
        };

        let masked_header = [
            cmd.cla | 0x0C,
            cmd.ins,
            cmd.p1,
            cmd.p2,
            0x80,
            0x00,
            0x00,
            0x00,
        ];
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&self.ssc);
        mac_input.extend_from_slice(&masked_header);
        mac_input.extend_from_slice(&do87);
        mac_input.extend_from_slice(&do97);

        let mac = marty_crypto::symmetric::aes_128_cmac(&self.k_mac, &mac_input)
            .map_err(|e| VerificationError::internal(format!("PACE CMAC: {}", e)))?;

        let mut sm_data = Vec::new();
        sm_data.extend_from_slice(&do87);
        sm_data.extend_from_slice(&do97);
        sm_data.push(0x8E);
        sm_data.push(0x08);
        sm_data.extend_from_slice(&mac[..8]); // use first 8 bytes of 16-byte CMAC

        Ok(ApduCommand {
            cla: cmd.cla | 0x0C,
            ins: cmd.ins,
            p1: cmd.p1,
            p2: cmd.p2,
            data: sm_data,
            le: Some(0),
        })
    }

    /// Strip and verify AES-CMAC secure messaging from a chip response.
    pub fn unprotect_response(&mut self, resp: &ApduResponse) -> VerificationResult<ApduResponse> {
        increment_ssc_16(&mut self.ssc);

        let data = &resp.data;
        let mut plain_data = Vec::new();
        let mut received_mac = [0u8; 8];
        let mut do87_bytes = Vec::<u8>::new();

        let mut i = 0;
        while i < data.len() {
            let tag = data[i];
            if i + 1 >= data.len() {
                break;
            }
            let len = data[i + 1] as usize;
            if i + 2 + len > data.len() {
                break;
            }
            let value = &data[i + 2..i + 2 + len];
            match tag {
                0x87 => {
                    do87_bytes = data[i..i + 2 + len].to_vec();
                    if !value.is_empty() && value[0] == 0x01 {
                        let ciphertext = &value[1..];
                        let decrypted = marty_crypto::symmetric::aes_128_cbc_decrypt_nopad(
                            &self.k_enc,
                            &self.ssc,
                            ciphertext,
                        )
                        .map_err(|e| {
                            VerificationError::internal(format!("PACE SM decrypt: {}", e))
                        })?;
                        plain_data = iso7816_unpad(&decrypted)?;
                    }
                }
                0x8E if len >= 8 => received_mac.copy_from_slice(&value[..8]),
                _ => {}
            }
            i += 2 + len;
        }

        let sw_bytes = [resp.sw1, resp.sw2];
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&self.ssc);
        mac_input.extend_from_slice(&do87_bytes);
        mac_input.extend_from_slice(&sw_bytes);

        let expected_full = marty_crypto::symmetric::aes_128_cmac(&self.k_mac, &mac_input)
            .map_err(|e| VerificationError::internal(format!("PACE CMAC: {}", e)))?;

        if !constant_time_eq(&expected_full[..8], &received_mac) {
            return Err(VerificationError::internal(
                "PACE SM: response MAC verification failed".to_string(),
            ));
        }

        Ok(ApduResponse {
            data: plain_data,
            sw1: resp.sw1,
            sw2: resp.sw2,
        })
    }
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

/// Derive BAC base keys from MRZ key information.
///
/// Following ICAO 9303-11 §9.7.3:
/// 1. `MRZ_info` = doc_number_check (10) ‖ dob_check (7) ‖ expiry_check (7) = 24 bytes
/// 2. `Kseed` = SHA-1(MRZ_info)[0..16]
/// 3. `K_ENC` = adjust_parity(SHA-1(Kseed ‖ 0x00000001)[0..16])
/// 4. `K_MAC` = adjust_parity(SHA-1(Kseed ‖ 0x00000002)[0..16])
pub fn derive_bac_base_keys(mrz: &MrzKeyInfo) -> VerificationResult<BacKeys> {
    use sha1::{Digest, Sha1};

    let mrz_info = format!(
        "{}{}{}",
        mrz.doc_number_with_check, mrz.dob_with_check, mrz.expiry_with_check
    );

    if mrz_info.len() != 24 {
        return Err(VerificationError::internal(format!(
            "BAC: MRZ key info must be 24 chars (doc10+dob7+exp7), got {}",
            mrz_info.len()
        )));
    }

    let hash = Sha1::digest(mrz_info.as_bytes());
    let kseed = &hash[..16];

    let k_enc = bac_kdf_16(kseed, 1)?;
    let k_mac = bac_kdf_16(kseed, 2)?;

    let mut k_seed = [0u8; 16];
    k_seed.copy_from_slice(kseed);
    Ok(BacKeys {
        k_enc,
        k_mac,
        k_seed,
    })
}

/// Derive BAC secure-messaging keys from authenticated reader/chip material.
pub fn derive_bac_session_keys(
    k_ifd: &[u8],
    k_ic: &[u8],
    rnd_ic: &[u8],
    rnd_ifd: &[u8],
) -> VerificationResult<BacSession> {
    let k_ifd: [u8; 16] = k_ifd.try_into().map_err(|_| {
        VerificationError::internal("BAC: K.IFD must be exactly 16 bytes".to_string())
    })?;
    let k_ic: [u8; 16] = k_ic.try_into().map_err(|_| {
        VerificationError::internal("BAC: K.ICC must be exactly 16 bytes".to_string())
    })?;
    let rnd_ic: [u8; 8] = rnd_ic.try_into().map_err(|_| {
        VerificationError::internal("BAC: Rnd.IC must be exactly 8 bytes".to_string())
    })?;
    let rnd_ifd: [u8; 8] = rnd_ifd.try_into().map_err(|_| {
        VerificationError::internal("BAC: Rnd.IFD must be exactly 8 bytes".to_string())
    })?;
    let mut seed = [0u8; 16];
    for index in 0..16 {
        seed[index] = k_ifd[index] ^ k_ic[index];
    }
    let k_enc = bac_kdf_16(&seed, 1)?;
    let k_mac = bac_kdf_16(&seed, 2)?;
    let mut ssc = [0u8; 8];
    ssc[..4].copy_from_slice(&rnd_ic[4..]);
    ssc[4..].copy_from_slice(&rnd_ifd[4..]);
    Ok(BacSession { k_enc, k_mac, ssc })
}

/// BAC / PACE KDF — derives a 16-byte key.
///
/// `seed` can be 8 or 16 bytes; `counter` is 1 for KEnc, 2 for KMac, 3 for password key.
fn bac_kdf_16(seed: &[u8], counter: u8) -> VerificationResult<[u8; 16]> {
    use sha1::{Digest, Sha1};
    let mut input = seed.to_vec();
    input.extend_from_slice(&[0x00, 0x00, 0x00, counter]);
    let hash = Sha1::digest(&input);
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash[..16]);
    adjust_des_parity(&mut key);
    Ok(key)
}

/// PACE KDF — SHA-256 based, derives a 16-byte AES key.
fn pace_kdf_16(seed: &[u8], counter: u8) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut input = seed.to_vec();
    input.extend_from_slice(&[0x00, 0x00, 0x00, counter]);
    let hash = Sha256::digest(&input);
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash[..16]);
    key
}

/// Set DES parity bits on each byte so that each byte has an odd number of 1-bits.
fn adjust_des_parity(key: &mut [u8]) {
    for byte in key.iter_mut() {
        let count = byte.count_ones();
        if count % 2 == 0 {
            *byte ^= 0x01; // flip LSB to make parity odd
        }
    }
}

/// Extend a 16-byte 2-key 3DES key to the 24-byte 3-key form K1‖K2‖K1.
fn extend_to_24_bytes(key16: &[u8; 16]) -> [u8; 24] {
    let mut k24 = [0u8; 24];
    k24[..8].copy_from_slice(&key16[..8]);
    k24[8..16].copy_from_slice(&key16[8..]);
    k24[16..].copy_from_slice(&key16[..8]);
    k24
}

/// ISO/IEC 9797-1 Padding Method 2: append 0x80 then 0x00..0x00 to
/// the next 8-byte boundary.
fn iso7816_pad(data: &[u8]) -> Vec<u8> {
    let mut padded = data.to_vec();
    padded.push(0x80);
    while !padded.len().is_multiple_of(8) {
        padded.push(0x00);
    }
    padded
}

/// Remove ISO/IEC 7816-4 padding.
fn iso7816_unpad(data: &[u8]) -> VerificationResult<Vec<u8>> {
    for i in (0..data.len()).rev() {
        if data[i] == 0x80 {
            return Ok(data[..i].to_vec());
        }
        if data[i] != 0x00 {
            break;
        }
    }
    Err(VerificationError::internal(
        "SM: invalid ISO 7816-4 padding".to_string(),
    ))
}

/// ISO/IEC 9797-1 Algorithm 3 (Retail-MAC) with ISO 7816-4 Padding Method 2.
///
/// Used in BAC secure messaging.  `key16` is the 16-byte MAC key [K1‖K2].
fn retail_mac_3des(key16: &[u8; 16], data: &[u8]) -> VerificationResult<[u8; 8]> {
    let padded = iso7816_pad(data);
    let n = padded.len() / 8;

    // 3DES key = K1‖K1‖K1 acts as single DES with K1 for intermediate blocks
    let k1_only = extend_single_des(&key16[..8]);
    let k_full = extend_to_24_bytes(key16);

    let iv = [0u8; 8];

    // CBC-MAC of all blocks except last under single-DES(K1)
    let intermediate = if n > 1 {
        let prefix = &padded[..(n - 1) * 8];
        let cbc = marty_crypto::des::tdes_cbc_encrypt(&k1_only, &iv, prefix)
            .map_err(|e| VerificationError::internal(format!("Retail-MAC single-DES: {}", e)))?;
        let mut s = [0u8; 8];
        s.copy_from_slice(&cbc[cbc.len() - 8..]);
        s
    } else {
        iv
    };

    // XOR with last block then encrypt under 3DES(K1‖K2‖K1)
    let last_block = &padded[(n - 1) * 8..];
    let mut xored = [0u8; 8];
    for i in 0..8 {
        xored[i] = intermediate[i] ^ last_block[i];
    }
    let final_mac = marty_crypto::des::tdes_cbc_encrypt(&k_full, &iv, &xored)
        .map_err(|e| VerificationError::internal(format!("Retail-MAC 3DES: {}", e)))?;

    let mut result = [0u8; 8];
    result.copy_from_slice(&final_mac[..8]);
    Ok(result)
}

/// Build a 24-byte key K‖K‖K so `tdes_cbc_encrypt` acts as single DES.
fn extend_single_des(k8: &[u8]) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[..8].copy_from_slice(k8);
    out[8..16].copy_from_slice(k8);
    out[16..].copy_from_slice(k8);
    out
}

/// Increment an 8-byte big-endian counter.
fn increment_ssc(ssc: &mut [u8; 8]) {
    for i in (0..8).rev() {
        ssc[i] = ssc[i].wrapping_add(1);
        if ssc[i] != 0 {
            break;
        }
    }
}

/// Increment a 16-byte big-endian counter (PACE).
fn increment_ssc_16(ssc: &mut [u8; 16]) {
    for i in (0..16).rev() {
        ssc[i] = ssc[i].wrapping_add(1);
        if ssc[i] != 0 {
            break;
        }
    }
}

/// Constant-time byte slice comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Compute the ICAO MRZ Luhn-style check digit for `data`.
pub fn mrz_check_digit(data: &[u8]) -> u8 {
    const WEIGHTS: [u32; 3] = [7, 3, 1];
    let sum: u32 = data
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let v = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'A'..=b'Z' => (b - b'A' + 10) as u32,
                b'<' => 0,
                _ => 0,
            };
            v * WEIGHTS[i % 3]
        })
        .sum();
    b'0' + (sum % 10) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mrz_check_digit_known() {
        // From ICAO 9303 Part 3 Annex A sample
        // "L898902C3" → check digit 6
        assert_eq!(mrz_check_digit(b"L898902C3"), b'6');
        // "740812" (DOB) → check digit 2  (not 5 — verified via ICAO algorithm)
        assert_eq!(mrz_check_digit(b"740812"), b'2');
        // "120415" (expiry) → check digit 9
        assert_eq!(mrz_check_digit(b"120415"), b'9');
    }

    #[test]
    fn test_retail_mac_deterministic() {
        let key = [
            0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F,
            0x76, 0xF2,
        ];
        let data = b"Hello World, ICAO 9303";
        let mac1 = retail_mac_3des(&key, data).unwrap();
        let mac2 = retail_mac_3des(&key, data).unwrap();
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_bac_key_derivation_icao_sample() {
        // ICAO 9303-11 Annex D sample values
        let mrz = MrzKeyInfo {
            doc_number_with_check: "L898902C<3".to_string(),
            dob_with_check: "6908061".to_string(),
            expiry_with_check: "9406236".to_string(),
        };
        let keys = derive_bac_base_keys(&mrz).unwrap();
        assert_eq!(
            hex::encode_upper(keys.k_seed),
            "239AB9CB282DAF66231DC5A4DF6BFBAE"
        );
        assert_eq!(
            hex::encode_upper(keys.k_enc),
            "AB94FDECF2674FDFB9B391F85D7F76F2"
        );
        assert_eq!(
            hex::encode_upper(keys.k_mac),
            "7962D9ECE03D1ACD4C76089DCE131543"
        );
    }

    #[test]
    fn bac_handshake_matches_icao_annex_d() {
        let mrz = MrzKeyInfo {
            doc_number_with_check: "L898902C<3".to_string(),
            dob_with_check: "6908061".to_string(),
            expiry_with_check: "9406236".to_string(),
        };
        let handshake = BacHandshake::begin_with_random(
            &mrz,
            &hex::decode("4608F91988702212").unwrap(),
            hex::decode("781723860C06C226").unwrap().try_into().unwrap(),
            hex::decode("0B795240CB7049B01C19B33E32804F0B")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode_upper(handshake.command_data().unwrap()),
            "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7"
        );
        let response = hex::decode(
            "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449",
        )
        .unwrap();
        let mut session = handshake.complete(&response).unwrap();
        assert_eq!(
            hex::encode_upper(session.encryption_key()),
            "979EC13B1CBFE9DCD01AB0FED307EAE5"
        );
        assert_eq!(
            hex::encode_upper(session.mac_key()),
            "F1CB1F1FB5ADF208806B89DC579DC1F8"
        );
        assert_eq!(
            hex::encode_upper(session.send_sequence_counter()),
            "887022120C06C226"
        );
        let select_ef_com =
            ApduCommand::from_bytes(&hex::decode("00A4020C02011E").unwrap()).unwrap();
        assert_eq!(
            hex::encode_upper(session.protect_command(&select_ef_com).unwrap().to_bytes()),
            "0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800"
        );
    }

    #[test]
    fn test_from_mrz_fields_check_digits() {
        let mrz = MrzKeyInfo::from_mrz_fields("L898902C3", "740812", "120415");
        assert_eq!(mrz.doc_number_with_check, "L898902C36");
        assert_eq!(mrz.dob_with_check, "7408122");
        assert_eq!(mrz.expiry_with_check, "1204159");
    }

    #[test]
    fn test_iso7816_pad_unpad_roundtrip() {
        let original = b"Hello World";
        let padded = iso7816_pad(original);
        assert_eq!(padded.len() % 8, 0);
        let unpadded = iso7816_unpad(&padded).unwrap();
        assert_eq!(unpadded, original);
    }

    #[test]
    fn test_increment_ssc_overflow() {
        let mut ssc = [0xFF; 8];
        increment_ssc(&mut ssc);
        assert_eq!(ssc, [0x00; 8]);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
