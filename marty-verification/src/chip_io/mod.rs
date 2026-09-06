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
//! └─ PaceCompatibilityHandshake ← derives keys from password and consumes
//!     the ephemeral agreement state while the caller runs GENERAL AUTHENTICATE
//!     └─ BacSession (opaque AES-CBC-nopad + AES-CMAC state)
//! ```

use std::collections::HashMap;

use crate::error::{VerificationError, VerificationResult};
use crate::trust_anchor::CscaRegistry;
use crate::verification::emrtd::{verify_emrtd, SecurityObject};

#[cfg(not(feature = "ephemeral-session-keys"))]
/// Marker for passive eMRTD builds that can parse APDUs and verify passport
/// evidence but cannot create or retain reader-side BAC/PACE session secrets.
///
/// ```compile_fail
/// let _ = marty_verification::chip_io::BacHandshake::begin;
/// ```
///
/// ```compile_fail
/// let _ = marty_verification::chip_io::PaceSession::derive_password_key;
/// ```
pub struct NoEphemeralSessionKeys;

#[cfg(feature = "ephemeral-session-keys")]
/// Marker documenting raw BAC/PACE key APIs excluded from production session builds.
///
/// ```compile_fail
/// use marty_verification::chip_io::{BacKeys, PaceKeys, PacePassword, PaceSession};
/// ```
/// ```compile_fail
/// let _ = marty_verification::chip_io::derive_bac_base_keys;
/// ```
/// ```compile_fail
/// let _ = marty_verification::chip_io::derive_bac_session_keys;
/// ```
/// ```compile_fail
/// let _ = marty_verification::chip_io::BacHandshake::begin_with_keys;
/// ```
/// ```compile_fail
/// let _ = marty_verification::chip_io::BacHandshake::begin_with_random;
/// ```
/// ```compile_fail
/// let _ = marty_verification::chip_io::BacSession::from_session_keys;
/// ```
/// ```compile_fail
/// let _ = marty_verification::chip_io::BacSession::encryption_key;
/// ```
/// ```compile_fail
/// let _ = marty_verification::chip_io::BacSession::mac_key;
/// ```
/// ```compile_fail
/// let _ = marty_verification::chip_io::BacSession::send_sequence_counter;
/// ```
/// ```compile_fail
/// let _ = marty_verification::chip_io::derive_compatibility_pace_password_key;
/// ```
/// ```compile_fail
/// let _ = marty_verification::chip_io::PaceCompatibilityHandshake::begin_with_private_key;
/// ```
/// ```compile_fail
/// let _ = marty_verification::chip_io::PaceCompatibilityHandshake::decrypted_nonce;
/// ```
pub struct NoRawSessionKeyApis;

// ─── APDU primitives ──────────────────────────────────────────────────────────

/// Maximum data carried by an ISO/IEC 7816-4 extended APDU.
pub const MAX_APDU_DATA_BYTES: usize = u16::MAX as usize;
/// Largest plaintext command that always fits after BAC secure-messaging overhead.
pub const MAX_BAC_COMMAND_DATA_BYTES: usize = 65_511;
/// Largest protected BAC response accepted by a live secure-messaging session.
pub const MAX_BAC_PROTECTED_RESPONSE_BYTES: usize = MAX_APDU_DATA_BYTES;

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
    pub fn to_bytes(&self) -> VerificationResult<Vec<u8>> {
        encode_apdu_command(
            self.cla,
            self.ins,
            self.p1,
            self.p2,
            (!self.data.is_empty()).then_some(self.data.as_slice()),
            self.le,
        )
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
    if data_len > MAX_APDU_DATA_BYTES {
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
        if raw.len() > MAX_APDU_DATA_BYTES + 2 {
            return Err(VerificationError::internal(
                "APDU response data exceeds extended-length capacity",
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
#[derive(Clone)]
#[cfg(any(test, feature = "ephemeral-session-keys"))]
pub struct MrzKeyInfo {
    /// Document number (9 chars) + check digit (1 char) = 10 chars.
    doc_number_with_check: String,
    /// Date of birth YYMMDD (6 chars) + check digit (1 char) = 7 chars.
    dob_with_check: String,
    /// Date of expiry YYMMDD (6 chars) + check digit (1 char) = 7 chars.
    expiry_with_check: String,
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl std::fmt::Debug for MrzKeyInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MrzKeyInfo([REDACTED])")
    }
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl Drop for MrzKeyInfo {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.doc_number_with_check.zeroize();
        self.dob_with_check.zeroize();
        self.expiry_with_check.zeroize();
    }
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl MrzKeyInfo {
    /// Construct from the three MRZ key fields (without check digits) and
    /// compute the Luhn-style check digits automatically.
    ///
    /// Use this validated constructor (or a validated MRZ parser) rather than
    /// retaining raw MRZ/check-digit material in application code.
    pub fn try_from_mrz_fields(
        doc_number: &str,
        dob: &str,
        expiry: &str,
    ) -> VerificationResult<Self> {
        if doc_number.len() != 9
            || !doc_number
                .bytes()
                .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit() || value == b'<')
        {
            return Err(VerificationError::internal(
                "BAC document number must be exactly 9 uppercase MRZ characters",
            ));
        }
        if dob.len() != 6
            || expiry.len() != 6
            || !dob.bytes().all(|value| value.is_ascii_digit())
            || !expiry.bytes().all(|value| value.is_ascii_digit())
        {
            return Err(VerificationError::internal(
                "BAC dates must be exactly 6 ASCII digits",
            ));
        }
        let doc_cd = mrz_check_digit(doc_number.as_bytes()) as char;
        let dob_cd = mrz_check_digit(dob.as_bytes()) as char;
        let exp_cd = mrz_check_digit(expiry.as_bytes()) as char;
        Ok(Self {
            doc_number_with_check: format!("{}{}", doc_number, doc_cd),
            dob_with_check: format!("{}{}", dob, dob_cd),
            expiry_with_check: format!("{}{}", expiry, exp_cd),
        })
    }

    #[cfg(test)]
    pub fn from_mrz_fields(doc_number: &str, dob: &str, expiry: &str) -> Self {
        Self::try_from_mrz_fields(doc_number, dob, expiry).expect("valid MRZ test fields")
    }
}

/// Derived BAC session keys.
#[derive(Clone)]
#[cfg(any(test, feature = "ephemeral-session-keys"))]
pub struct BacKeys {
    /// 16-byte 3DES encryption key (K1‖K2).
    pub(crate) k_enc: [u8; 16],
    /// 16-byte 3DES MAC key (K1‖K2).
    pub(crate) k_mac: [u8; 16],
    /// First 16 bytes of SHA-1(MRZ information).
    #[cfg(test)]
    pub(crate) k_seed: [u8; 16],
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl std::fmt::Debug for BacKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BacKeys { … }")
    }
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl Drop for BacKeys {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.k_enc);
        zeroize::Zeroize::zeroize(&mut self.k_mac);
        #[cfg(test)]
        zeroize::Zeroize::zeroize(&mut self.k_seed);
    }
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl BacKeys {
    #[cfg(test)]
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
#[cfg(any(test, feature = "ephemeral-session-keys"))]
pub struct BacSession {
    /// Session encryption key (KSenc).
    k_enc: [u8; 16],
    /// Session MAC key (KSmac).
    k_mac: [u8; 16],
    /// Send Sequence Counter (8 bytes, big-endian).
    ssc: [u8; 8],
}

/// In-progress BAC mutual-authentication exchange.
#[cfg(any(test, feature = "ephemeral-session-keys"))]
pub struct BacHandshake {
    base_keys: BacKeys,
    rnd_ifd: [u8; 8],
    k_ifd: [u8; 16],
    rnd_ic: [u8; 8],
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl Drop for BacHandshake {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.rnd_ifd);
        zeroize::Zeroize::zeroize(&mut self.k_ifd);
        zeroize::Zeroize::zeroize(&mut self.rnd_ic);
    }
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl BacHandshake {
    /// Start a BAC exchange with cryptographically random reader material.
    pub fn begin(mrz: &MrzKeyInfo, rnd_ic: &[u8]) -> VerificationResult<Self> {
        use rand::RngCore;

        let mut rnd_ifd = [0u8; 8];
        let mut k_ifd = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut rnd_ifd);
        rand::rngs::OsRng.fill_bytes(&mut k_ifd);
        Self::begin_with_random_inner(mrz, rnd_ic, rnd_ifd, k_ifd)
    }

    /// Start a BAC exchange from previously derived base keys.
    #[cfg(test)]
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
    #[cfg(test)]
    pub fn begin_with_random(
        mrz: &MrzKeyInfo,
        rnd_ic: &[u8],
        rnd_ifd: [u8; 8],
        k_ifd: [u8; 16],
    ) -> VerificationResult<Self> {
        Self::begin_with_random_inner(mrz, rnd_ic, rnd_ifd, k_ifd)
    }

    fn begin_with_random_inner(
        mrz: &MrzKeyInfo,
        rnd_ic: &[u8],
        rnd_ifd: [u8; 8],
        k_ifd: [u8; 16],
    ) -> VerificationResult<Self> {
        let rnd_ic: [u8; 8] = rnd_ic.try_into().map_err(|_| {
            VerificationError::internal("BAC: chip challenge must be exactly 8 bytes".to_string())
        })?;
        Ok(Self {
            base_keys: derive_bac_base_keys_inner(mrz)?,
            rnd_ifd,
            k_ifd,
            rnd_ic,
        })
    }

    /// Build `E.IFD || M.IFD`, the 40-byte EXTERNAL AUTHENTICATE data field.
    pub fn command_data(&self) -> VerificationResult<Vec<u8>> {
        let mut plaintext = zeroize::Zeroizing::new(Vec::with_capacity(32));
        plaintext.extend_from_slice(&self.rnd_ifd);
        plaintext.extend_from_slice(&self.rnd_ic);
        plaintext.extend_from_slice(&self.k_ifd);
        let iv = icao_3des_cbc_iv();
        let k24 = extend_to_24_bytes(&self.base_keys.k_enc);
        let encrypted = marty_crypto::des::tdes_cbc_encrypt(&k24[..], &iv, &plaintext)
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
        let iv = icao_3des_cbc_iv();
        let k24 = extend_to_24_bytes(&self.base_keys.k_enc);
        let plaintext = zeroize::Zeroizing::new(
            marty_crypto::des::tdes_cbc_decrypt(&k24[..], &iv, encrypted).map_err(|error| {
                VerificationError::internal(format!("BAC decrypt failed: {error}"))
            })?,
        );
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
        derive_bac_session_keys_inner(&self.k_ifd, &plaintext[16..32], &self.rnd_ic, &self.rnd_ifd)
    }
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl BacSession {
    /// Restore a BAC secure-messaging session from established key material.
    #[cfg(test)]
    pub fn from_session_keys(k_enc: [u8; 16], k_mac: [u8; 16], ssc: [u8; 8]) -> Self {
        Self { k_enc, k_mac, ssc }
    }

    #[cfg(test)]
    pub fn encryption_key(&self) -> &[u8; 16] {
        &self.k_enc
    }

    #[cfg(test)]
    pub fn mac_key(&self) -> &[u8; 16] {
        &self.k_mac
    }

    #[cfg(test)]
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
        if cmd.data.len() > MAX_BAC_COMMAND_DATA_BYTES {
            return Err(VerificationError::internal(format!(
                "BAC SM command data exceeds {MAX_BAC_COMMAND_DATA_BYTES} bytes"
            )));
        }
        if cmd.le.is_some_and(|le| le > 256) {
            return Err(VerificationError::internal(
                "BAC SM supports only short-form Le values up to 256",
            ));
        }
        let next_ssc = checked_next_ssc(&self.ssc)?;

        // Build protected data object (DO'87) when command has data
        let mut do87: Vec<u8> = Vec::new();
        if !cmd.data.is_empty() {
            let padded = iso7816_pad(&cmd.data);
            let k24 = extend_to_24_bytes(&self.k_enc);
            let iv = icao_3des_cbc_iv();
            let enc = marty_crypto::des::tdes_cbc_encrypt(&k24[..], &iv, &padded)
                .map_err(|e| VerificationError::internal(format!("SM encrypt: {}", e)))?;
            // DO'87 = tag 87, BER length, 01 (padding indicator), ciphertext.
            let mut value = Vec::with_capacity(enc.len() + 1);
            value.push(0x01);
            value.extend_from_slice(&enc);
            push_ber_tlv(0x87, &value, &mut do87)?;
        }

        // Build expected length object (DO'97) when cmd has Le
        let do97 = if let Some(le) = cmd.le {
            vec![0x97, 0x01, if le == 256 { 0 } else { le as u8 }]
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
        mac_input.extend_from_slice(&next_ssc);
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
        if sm_data.len() > MAX_APDU_DATA_BYTES {
            return Err(VerificationError::internal(
                "BAC SM protected command exceeds extended APDU capacity",
            ));
        }

        let protected = ApduCommand {
            cla: cmd.cla | 0x0C, // set secure messaging bit
            ins: cmd.ins,
            p1: cmd.p1,
            p2: cmd.p2,
            data: sm_data,
            le: Some(0),
        };
        self.ssc = next_ssc;
        Ok(protected)
    }

    /// Strip and verify 3DES-MAC secure messaging from a chip response.
    pub fn unprotect_response(&mut self, resp: &ApduResponse) -> VerificationResult<ApduResponse> {
        if resp.data.len() > MAX_BAC_PROTECTED_RESPONSE_BYTES {
            return Err(VerificationError::internal(format!(
                "BAC SM protected response exceeds {MAX_BAC_PROTECTED_RESPONSE_BYTES} bytes"
            )));
        }
        let next_ssc = checked_next_ssc(&self.ssc)?;

        let data = &resp.data;
        let mut received_mac = None;
        let mut do87_bytes = None;
        let mut encrypted_data = None;
        let mut do99_bytes = None;
        let mut status = None;

        let mut offset = 0;
        while offset < data.len() {
            let tlv = next_ber_tlv(data, &mut offset, "BAC SM")?;
            match tlv.tag {
                0x87 => {
                    if do87_bytes.is_some()
                        || tlv.value.first() != Some(&0x01)
                        || tlv.value.len() <= 1
                        || !(tlv.value.len() - 1).is_multiple_of(8)
                    {
                        return Err(VerificationError::internal(
                            "BAC SM: malformed protected response",
                        ));
                    }
                    do87_bytes = Some(tlv.encoded);
                    encrypted_data = Some(&tlv.value[1..]);
                }
                0x99 if tlv.value.len() == 2 && do99_bytes.is_none() => {
                    do99_bytes = Some(tlv.encoded);
                    status = Some((tlv.value[0], tlv.value[1]));
                }
                0x8E if tlv.value.len() == 8 && received_mac.is_none() => {
                    received_mac = Some(tlv.value);
                }
                _ => {
                    return Err(VerificationError::internal(
                        "BAC SM: malformed protected response",
                    ))
                }
            }
        }

        let Some(do99_bytes) = do99_bytes else {
            return Err(VerificationError::internal(
                "BAC SM: protected response missing DO99 or DO8E".to_string(),
            ));
        };
        let received_mac = received_mac.ok_or_else(|| {
            VerificationError::internal("BAC SM: protected response missing DO99 or DO8E")
        })?;
        // Verify MAC: SSC || DO'87 || DO'99
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&next_ssc);
        if let Some(do87_bytes) = do87_bytes {
            mac_input.extend_from_slice(do87_bytes);
        }
        mac_input.extend_from_slice(do99_bytes);

        let expected = retail_mac_3des(&self.k_mac, &mac_input)?;
        if !constant_time_eq(&expected, received_mac) {
            return Err(VerificationError::internal(
                "BAC SM: response MAC verification failed".to_string(),
            ));
        }

        let plain_data = if let Some(ciphertext) = encrypted_data {
            let k24 = extend_to_24_bytes(&self.k_enc);
            let iv = icao_3des_cbc_iv();
            let decrypted = zeroize::Zeroizing::new(
                marty_crypto::des::tdes_cbc_decrypt(&k24[..], &iv, ciphertext)
                    .map_err(|e| VerificationError::internal(format!("SM decrypt: {e}")))?,
            );
            iso7816_unpad(&decrypted)?
        } else {
            Vec::new()
        };
        let (sw1, sw2) = status.ok_or_else(|| {
            VerificationError::internal("BAC SM: protected response missing DO99")
        })?;
        let plaintext = ApduResponse {
            data: plain_data,
            sw1,
            sw2,
        };
        self.ssc = next_ssc;
        Ok(plaintext)
    }
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl Drop for BacSession {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.k_enc);
        zeroize::Zeroize::zeroize(&mut self.k_mac);
        zeroize::Zeroize::zeroize(&mut self.ssc);
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
#[cfg(test)]
pub enum PacePassword {
    /// 6-digit Card Access Number (printed on the card).
    Can(String),
    /// Machine Readable Zone string (composite, see ICAO 9303).
    Mrz(String),
    /// Personal Identification Number.
    Pin(String),
}

#[cfg(test)]
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
/// single Rust implementation. New protocol integrations should use this
/// opaque, one-use handshake flow rather than reproducing its compatibility
/// steps or retaining derived keys in another language.
#[cfg(any(test, feature = "ephemeral-session-keys"))]
pub struct PaceCompatibilityHandshake {
    key_pair: Option<PaceKeyPair>,
    public_key: Vec<u8>,
    nonce: Vec<u8>,
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
enum PaceKeyPair {
    Ephemeral(marty_crypto::ecdh::P256KeyPair),
    #[cfg(test)]
    Deterministic(p256::SecretKey),
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl PaceKeyPair {
    fn public_key(&self) -> Vec<u8> {
        match self {
            Self::Ephemeral(key) => key.public_key_uncompressed(),
            #[cfg(test)]
            Self::Deterministic(key) => {
                use elliptic_curve::sec1::ToEncodedPoint;
                key.public_key().to_encoded_point(false).as_bytes().to_vec()
            }
        }
    }

    fn agree(self, peer_public_key: &[u8]) -> VerificationResult<zeroize::Zeroizing<Vec<u8>>> {
        match self {
            Self::Ephemeral(key) => key.agree(peer_public_key).map_err(Into::into),
            #[cfg(test)]
            Self::Deterministic(key) => {
                let peer = p256::PublicKey::from_sec1_bytes(peer_public_key).map_err(|error| {
                    VerificationError::internal(format!("Invalid P-256 peer key: {error}"))
                })?;
                Ok(zeroize::Zeroizing::new(
                    p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine())
                        .raw_secret_bytes()
                        .to_vec(),
                ))
            }
        }
    }
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl Drop for PaceCompatibilityHandshake {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.nonce);
    }
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
impl PaceCompatibilityHandshake {
    pub fn begin(password: &str, encrypted_nonce: &[u8]) -> VerificationResult<Self> {
        Self::begin_with_key(
            password,
            encrypted_nonce,
            PaceKeyPair::Ephemeral(marty_crypto::ecdh::P256KeyPair::generate()),
        )
    }

    #[cfg(test)]
    pub fn begin_with_private_key(
        password: &str,
        encrypted_nonce: &[u8],
        private_key: &[u8],
    ) -> VerificationResult<Self> {
        let private_key = p256::SecretKey::from_slice(private_key).map_err(|error| {
            VerificationError::internal(format!("Invalid PACE P-256 private key: {error}"))
        })?;
        Self::begin_with_key(
            password,
            encrypted_nonce,
            PaceKeyPair::Deterministic(private_key),
        )
    }

    fn begin_with_key(
        password: &str,
        encrypted_nonce: &[u8],
        key_pair: PaceKeyPair,
    ) -> VerificationResult<Self> {
        if encrypted_nonce.len() != 16 {
            return Err(VerificationError::internal(
                "PACE encrypted nonce must be exactly 16 bytes",
            ));
        }
        let key = zeroize::Zeroizing::new(derive_compatibility_pace_password_key_inner(password)?);
        let expanded_key = extend_to_24_bytes(&key);
        let iv = icao_3des_cbc_iv();
        let decrypted = zeroize::Zeroizing::new(
            marty_crypto::des::tdes_cbc_decrypt(&expanded_key[..], &iv, encrypted_nonce).map_err(
                |error| VerificationError::internal(format!("PACE nonce decrypt: {error}")),
            )?,
        );
        let nonce = zeroize::Zeroizing::new(iso7816_unpad(&decrypted)?);
        if nonce.is_empty() {
            return Err(VerificationError::internal(
                "PACE decrypted nonce must not be empty",
            ));
        }
        let public_key = key_pair.public_key();
        Ok(Self {
            key_pair: Some(key_pair),
            public_key,
            nonce: nonce.to_vec(),
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    #[cfg(test)]
    pub fn decrypted_nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn complete(mut self, chip_public_key: &[u8]) -> VerificationResult<BacSession> {
        use sha2::{Digest, Sha256};
        let shared_secret = self
            .key_pair
            .take()
            .ok_or_else(|| VerificationError::internal("PACE handshake already consumed"))?
            .agree(chip_public_key)?;
        let mut input = zeroize::Zeroizing::new(shared_secret.to_vec());
        input.extend_from_slice(&self.nonce);
        let digest = zeroize::Zeroizing::new(Sha256::digest(&input));
        let seed = &digest[..16];
        let k_enc = bac_kdf_16(seed, 1)?;
        let k_mac = bac_kdf_16(seed, 2)?;
        let mut ssc = [0u8; 8];
        ssc.copy_from_slice(&digest[digest.len() - 8..]);
        Ok(BacSession { k_enc, k_mac, ssc })
    }
}

/// Derive the 3DES password key used by the established compatibility API.
#[cfg(test)]
pub fn derive_compatibility_pace_password_key(password: &str) -> VerificationResult<[u8; 16]> {
    derive_compatibility_pace_password_key_inner(password)
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn derive_compatibility_pace_password_key_inner(password: &str) -> VerificationResult<[u8; 16]> {
    use sha1::{Digest, Sha1};

    if password.len() > 128 {
        return Err(VerificationError::internal(
            "PACE password or MRZ input must not exceed 128 bytes",
        ));
    }

    let seed = zeroize::Zeroizing::new(
        if password.chars().all(|value| value.is_ascii_digit())
            && (6..=10).contains(&password.len())
        {
            Sha1::digest(password.as_bytes())[..16].to_vec()
        } else {
            let parsed = crate::mrz::parser::parse_mrz_string(password).map_err(|error| {
                VerificationError::internal(format!("Unsupported PACE password format: {error}"))
            })?;
            let normalized = zeroize::Zeroizing::new(
                parsed
                    .document_number
                    .to_ascii_uppercase()
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .take(9)
                    .collect::<String>(),
            );
            let document_number =
                zeroize::Zeroizing::new(format!("{:<9}", normalized.as_str()).replace(' ', "<"));
            let information = zeroize::Zeroizing::new(format!(
                "{}{}{}{}{}{}",
                document_number.as_str(),
                mrz_check_digit(document_number.as_bytes()) as char,
                parsed.date_of_birth,
                mrz_check_digit(parsed.date_of_birth.as_bytes()) as char,
                parsed.date_of_expiry,
                mrz_check_digit(parsed.date_of_expiry.as_bytes()) as char,
            ));
            Sha1::digest(information.as_bytes())[..16].to_vec()
        },
    );
    let mut key = [0u8; 16];
    key.copy_from_slice(&seed);
    adjust_des_parity(&mut key);
    Ok(key)
}

/// PACE-specific symmetric keys.
#[derive(Clone)]
#[cfg(test)]
pub struct PaceKeys {
    /// Encryption key (KSenc) — 16 bytes for AES-128.
    pub k_enc: [u8; 16],
    /// MAC key (KSmac) — 16 bytes for AES-128.
    pub k_mac: [u8; 16],
}

#[cfg(test)]
impl std::fmt::Debug for PaceKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PaceKeys { … }")
    }
}

#[cfg(test)]
impl Drop for PaceKeys {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.k_enc);
        zeroize::Zeroize::zeroize(&mut self.k_mac);
    }
}

/// Established PACE secure-messaging session (AES-128-CBC + AES-CMAC).
#[cfg(test)]
pub struct PaceSession {
    k_enc: [u8; 16],
    k_mac: [u8; 16],
    /// Send Sequence Counter (16 bytes, big-endian for AES).
    ssc: [u8; 16],
}

#[cfg(test)]
impl Drop for PaceSession {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.k_enc);
        zeroize::Zeroize::zeroize(&mut self.k_mac);
        zeroize::Zeroize::zeroize(&mut self.ssc);
    }
}

#[cfg(test)]
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
        let kpwd = zeroize::Zeroizing::new(Self::derive_nonce_key(password));
        marty_crypto::symmetric::aes_128_cbc_decrypt_nopad(&kpwd[..], &[0u8; 16], enc_nonce)
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
            let iv = pace_encryption_iv(&self.k_enc, &self.ssc)?;
            let enc = marty_crypto::symmetric::aes_128_cbc_encrypt_nopad(&self.k_enc, &iv, &padded)
                .map_err(|e| VerificationError::internal(format!("PACE SM encrypt: {e}")))?;
            let mut value = Vec::with_capacity(enc.len() + 1);
            value.push(0x01);
            value.extend_from_slice(&enc);
            push_ber_tlv(0x87, &value, &mut do87)?;
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
        let mut received_mac = None;
        let mut do87_bytes = None;
        let mut encrypted_data = None;
        let mut do99_bytes = None;
        let mut status = None;

        let mut offset = 0;
        while offset < data.len() {
            let tlv = next_ber_tlv(data, &mut offset, "PACE SM")?;
            match tlv.tag {
                0x87 => {
                    if do87_bytes.is_some()
                        || tlv.value.first() != Some(&0x01)
                        || tlv.value.len() <= 1
                        || !(tlv.value.len() - 1).is_multiple_of(16)
                    {
                        return Err(VerificationError::internal(
                            "PACE SM: malformed protected response",
                        ));
                    }
                    do87_bytes = Some(tlv.encoded);
                    encrypted_data = Some(&tlv.value[1..]);
                }
                0x99 if tlv.value.len() == 2 && do99_bytes.is_none() => {
                    do99_bytes = Some(tlv.encoded);
                    status = Some((tlv.value[0], tlv.value[1]));
                }
                0x8E if tlv.value.len() == 8 && received_mac.is_none() => {
                    received_mac = Some(tlv.value);
                }
                _ => {
                    return Err(VerificationError::internal(
                        "PACE SM: malformed protected response",
                    ))
                }
            }
        }

        let do99_bytes = do99_bytes.ok_or_else(|| {
            VerificationError::internal("PACE SM: protected response missing DO99 or DO8E")
        })?;
        let received_mac = received_mac.ok_or_else(|| {
            VerificationError::internal("PACE SM: protected response missing DO99 or DO8E")
        })?;
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&self.ssc);
        if let Some(do87_bytes) = do87_bytes {
            mac_input.extend_from_slice(do87_bytes);
        }
        mac_input.extend_from_slice(do99_bytes);

        let expected_full = marty_crypto::symmetric::aes_128_cmac(&self.k_mac, &mac_input)
            .map_err(|e| VerificationError::internal(format!("PACE CMAC: {}", e)))?;

        if !constant_time_eq(&expected_full[..8], received_mac) {
            return Err(VerificationError::internal(
                "PACE SM: response MAC verification failed".to_string(),
            ));
        }

        let plain_data = if let Some(ciphertext) = encrypted_data {
            let iv = pace_encryption_iv(&self.k_enc, &self.ssc)?;
            let decrypted = zeroize::Zeroizing::new(
                marty_crypto::symmetric::aes_128_cbc_decrypt_nopad(&self.k_enc, &iv, ciphertext)
                    .map_err(|e| VerificationError::internal(format!("PACE SM decrypt: {e}")))?,
            );
            iso7816_unpad(&decrypted)?
        } else {
            Vec::new()
        };
        let (sw1, sw2) = status.expect("status checked above");
        Ok(ApduResponse {
            data: plain_data,
            sw1,
            sw2,
        })
    }
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

#[cfg(any(test, feature = "ephemeral-session-keys"))]
struct BerTlv<'a> {
    tag: u8,
    encoded: &'a [u8],
    value: &'a [u8],
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn next_ber_tlv<'a>(
    data: &'a [u8],
    offset: &mut usize,
    context: &str,
) -> VerificationResult<BerTlv<'a>> {
    let malformed = || VerificationError::internal(format!("{context}: malformed BER-TLV"));
    let start = *offset;
    let tag = *data.get(start).ok_or_else(&malformed)?;
    let first_length = *data.get(start + 1).ok_or_else(&malformed)?;
    let (header_length, value_length) = match first_length {
        0..=0x7f => (2, usize::from(first_length)),
        0x81 => {
            let value = usize::from(*data.get(start + 2).ok_or_else(&malformed)?);
            if value < 0x80 {
                return Err(VerificationError::internal(format!(
                    "{context}: non-canonical BER-TLV length"
                )));
            }
            (3, value)
        }
        0x82 => {
            let bytes = data.get(start + 2..start + 4).ok_or_else(&malformed)?;
            let value = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
            if value <= 0xff {
                return Err(VerificationError::internal(format!(
                    "{context}: non-canonical BER-TLV length"
                )));
            }
            (4, value)
        }
        _ => {
            return Err(VerificationError::internal(format!(
                "{context}: unsupported BER-TLV length"
            )))
        }
    };
    let value_start = start.checked_add(header_length).ok_or_else(&malformed)?;
    let end = value_start
        .checked_add(value_length)
        .ok_or_else(&malformed)?;
    let encoded = data.get(start..end).ok_or_else(&malformed)?;
    let value = data.get(value_start..end).ok_or_else(&malformed)?;
    *offset = end;
    Ok(BerTlv {
        tag,
        encoded,
        value,
    })
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn push_ber_tlv(tag: u8, value: &[u8], output: &mut Vec<u8>) -> VerificationResult<()> {
    output.push(tag);
    match value.len() {
        0..=0x7f => output.push(value.len() as u8),
        0x80..=0xff => {
            output.push(0x81);
            output.push(value.len() as u8);
        }
        0x100..=0xffff => {
            output.push(0x82);
            output.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        _ => {
            return Err(VerificationError::internal(
                "Secure-messaging TLV value is too large",
            ))
        }
    }
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
fn pace_encryption_iv(k_enc: &[u8; 16], ssc: &[u8; 16]) -> VerificationResult<[u8; 16]> {
    let encrypted = marty_crypto::symmetric::aes_128_cbc_encrypt_nopad(k_enc, &[0u8; 16], ssc)
        .map_err(|error| VerificationError::internal(format!("PACE IV derivation: {error}")))?;
    encrypted
        .try_into()
        .map_err(|_| VerificationError::internal("PACE IV derivation returned the wrong length"))
}

/// Derive BAC base keys from MRZ key information.
///
/// Following ICAO 9303-11 §9.7.3:
/// 1. `MRZ_info` = doc_number_check (10) ‖ dob_check (7) ‖ expiry_check (7) = 24 bytes
/// 2. `Kseed` = SHA-1(MRZ_info)[0..16]
/// 3. `K_ENC` = adjust_parity(SHA-1(Kseed ‖ 0x00000001)[0..16])
/// 4. `K_MAC` = adjust_parity(SHA-1(Kseed ‖ 0x00000002)[0..16])
#[cfg(test)]
pub fn derive_bac_base_keys(mrz: &MrzKeyInfo) -> VerificationResult<BacKeys> {
    derive_bac_base_keys_inner(mrz)
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn derive_bac_base_keys_inner(mrz: &MrzKeyInfo) -> VerificationResult<BacKeys> {
    use sha1::{Digest, Sha1};

    let mrz_info = zeroize::Zeroizing::new(format!(
        "{}{}{}",
        mrz.doc_number_with_check, mrz.dob_with_check, mrz.expiry_with_check
    ));

    if mrz_info.len() != 24 {
        return Err(VerificationError::internal(format!(
            "BAC: MRZ key info must be 24 chars (doc10+dob7+exp7), got {}",
            mrz_info.len()
        )));
    }

    let hash = zeroize::Zeroizing::new(Sha1::digest(mrz_info.as_bytes()));
    let kseed = &hash[..16];

    let k_enc = bac_kdf_16(kseed, 1)?;
    let k_mac = bac_kdf_16(kseed, 2)?;

    #[cfg(test)]
    let k_seed = {
        let mut value = [0u8; 16];
        value.copy_from_slice(kseed);
        value
    };
    Ok(BacKeys {
        k_enc,
        k_mac,
        #[cfg(test)]
        k_seed,
    })
}

/// Derive BAC secure-messaging keys from authenticated reader/chip material.
#[cfg(test)]
pub fn derive_bac_session_keys(
    k_ifd: &[u8],
    k_ic: &[u8],
    rnd_ic: &[u8],
    rnd_ifd: &[u8],
) -> VerificationResult<BacSession> {
    derive_bac_session_keys_inner(k_ifd, k_ic, rnd_ic, rnd_ifd)
}

#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn derive_bac_session_keys_inner(
    k_ifd: &[u8],
    k_ic: &[u8],
    rnd_ic: &[u8],
    rnd_ifd: &[u8],
) -> VerificationResult<BacSession> {
    let k_ifd = zeroize::Zeroizing::new(<[u8; 16]>::try_from(k_ifd).map_err(|_| {
        VerificationError::internal("BAC: K.IFD must be exactly 16 bytes".to_string())
    })?);
    let k_ic = zeroize::Zeroizing::new(<[u8; 16]>::try_from(k_ic).map_err(|_| {
        VerificationError::internal("BAC: K.ICC must be exactly 16 bytes".to_string())
    })?);
    let rnd_ic: [u8; 8] = rnd_ic.try_into().map_err(|_| {
        VerificationError::internal("BAC: Rnd.IC must be exactly 8 bytes".to_string())
    })?;
    let rnd_ifd: [u8; 8] = rnd_ifd.try_into().map_err(|_| {
        VerificationError::internal("BAC: Rnd.IFD must be exactly 8 bytes".to_string())
    })?;
    let mut seed = zeroize::Zeroizing::new([0u8; 16]);
    for index in 0..16 {
        seed[index] = k_ifd[index] ^ k_ic[index];
    }
    let k_enc = bac_kdf_16(seed.as_slice(), 1)?;
    let k_mac = bac_kdf_16(seed.as_slice(), 2)?;
    let mut ssc = [0u8; 8];
    ssc[..4].copy_from_slice(&rnd_ic[4..]);
    ssc[4..].copy_from_slice(&rnd_ifd[4..]);
    Ok(BacSession { k_enc, k_mac, ssc })
}

/// BAC / PACE KDF — derives a 16-byte key.
///
/// `seed` can be 8 or 16 bytes; `counter` is 1 for KEnc, 2 for KMac, 3 for password key.
#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn bac_kdf_16(seed: &[u8], counter: u8) -> VerificationResult<[u8; 16]> {
    use sha1::{Digest, Sha1};
    let mut input = zeroize::Zeroizing::new(seed.to_vec());
    input.extend_from_slice(&[0x00, 0x00, 0x00, counter]);
    let hash = zeroize::Zeroizing::new(Sha1::digest(&input));
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash[..16]);
    adjust_des_parity(&mut key);
    Ok(key)
}

/// PACE KDF — SHA-256 based, derives a 16-byte AES key.
#[cfg(test)]
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
#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn adjust_des_parity(key: &mut [u8]) {
    for byte in key.iter_mut() {
        let count = byte.count_ones();
        if count % 2 == 0 {
            *byte ^= 0x01; // flip LSB to make parity odd
        }
    }
}

/// Extend a 16-byte 2-key 3DES key to the 24-byte 3-key form K1‖K2‖K1.
#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn extend_to_24_bytes(key16: &[u8; 16]) -> zeroize::Zeroizing<[u8; 24]> {
    let mut k24 = [0u8; 24];
    k24[..8].copy_from_slice(&key16[..8]);
    k24[8..16].copy_from_slice(&key16[8..]);
    k24[16..].copy_from_slice(&key16[..8]);
    zeroize::Zeroizing::new(k24)
}

/// ICAO Doc 9303 BAC/secure-messaging and the compatibility PACE exchange
/// mandate an all-zero 3DES CBC IV. It is a public protocol constant, not a
/// secret or caller-configurable cryptographic value.
#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn icao_3des_cbc_iv() -> [u8; 8] {
    Default::default()
}

/// ISO/IEC 9797-1 Padding Method 2: append 0x80 then 0x00..0x00 to
/// the next 8-byte boundary.
#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn iso7816_pad(data: &[u8]) -> Vec<u8> {
    let mut padded = data.to_vec();
    padded.push(0x80);
    while !padded.len().is_multiple_of(8) {
        padded.push(0x00);
    }
    padded
}

/// Remove ISO/IEC 7816-4 padding.
#[cfg(any(test, feature = "ephemeral-session-keys"))]
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
#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn retail_mac_3des(key16: &[u8; 16], data: &[u8]) -> VerificationResult<[u8; 8]> {
    let padded = iso7816_pad(data);
    let n = padded.len() / 8;

    // 3DES key = K1‖K1‖K1 acts as single DES with K1 for intermediate blocks
    let k1_only = extend_single_des(&key16[..8]);
    let k_full = extend_to_24_bytes(key16);

    let iv = icao_3des_cbc_iv();

    // CBC-MAC of all blocks except last under single-DES(K1)
    let intermediate = if n > 1 {
        let prefix = &padded[..(n - 1) * 8];
        let cbc = marty_crypto::des::tdes_cbc_encrypt(&k1_only[..], &iv, prefix)
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
    let final_mac = marty_crypto::des::tdes_cbc_encrypt(&k_full[..], &iv, &xored)
        .map_err(|e| VerificationError::internal(format!("Retail-MAC 3DES: {}", e)))?;

    let mut result = [0u8; 8];
    result.copy_from_slice(&final_mac[..8]);
    Ok(result)
}

/// Build a 24-byte key K‖K‖K so `tdes_cbc_encrypt` acts as single DES.
#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn extend_single_des(k8: &[u8]) -> zeroize::Zeroizing<[u8; 24]> {
    let mut out = [0u8; 24];
    out[..8].copy_from_slice(k8);
    out[8..16].copy_from_slice(k8);
    out[16..].copy_from_slice(k8);
    zeroize::Zeroizing::new(out)
}

/// Return the next 8-byte big-endian counter without permitting wraparound.
#[cfg(any(test, feature = "ephemeral-session-keys"))]
fn checked_next_ssc(ssc: &[u8; 8]) -> VerificationResult<[u8; 8]> {
    let mut next = *ssc;
    for i in (0..8).rev() {
        if next[i] != u8::MAX {
            next[i] += 1;
            return Ok(next);
        }
        next[i] = 0;
    }
    Err(VerificationError::internal(
        "BAC secure-messaging counter exhausted",
    ))
}

/// Increment a 16-byte big-endian counter (PACE).
#[cfg(test)]
fn increment_ssc_16(ssc: &mut [u8; 16]) {
    for i in (0..16).rev() {
        ssc[i] = ssc[i].wrapping_add(1);
        if ssc[i] != 0 {
            break;
        }
    }
}

/// Constant-time byte slice comparison.
#[cfg(any(test, feature = "ephemeral-session-keys"))]
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
            hex::encode_upper(
                session
                    .protect_command(&select_ef_com)
                    .unwrap()
                    .to_bytes()
                    .unwrap()
            ),
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
    fn session_inputs_are_bounded_before_parsing_or_crypto() {
        use rand::{distributions::Alphanumeric, Rng};

        let test_password: String = rand::rngs::OsRng
            .sample_iter(&Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();
        assert!(MrzKeyInfo::try_from_mrz_fields("TOO-LONG-1", "740812", "120415").is_err());
        assert!(MrzKeyInfo::try_from_mrz_fields("L898902C3", "74081", "120415").is_err());
        assert!(PaceCompatibilityHandshake::begin(&test_password, &[0u8; 8]).is_err());
        assert!(PaceCompatibilityHandshake::begin(&"A".repeat(129), &[0u8; 16]).is_err());
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
        assert!(checked_next_ssc(&[0xFF; 8]).is_err());
        assert_eq!(checked_next_ssc(&[0; 8]).unwrap(), [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn bac_command_bounds_and_counter_updates_are_transactional() {
        let initial_ssc = [0x33; 8];
        let mut session = BacSession::from_session_keys([0x11; 16], [0x22; 16], initial_ssc);
        let maximum = ApduCommand {
            cla: 0,
            ins: 0xa4,
            p1: 0,
            p2: 0,
            data: vec![0x5a; MAX_BAC_COMMAND_DATA_BYTES],
            le: Some(256),
        };
        let protected = session.protect_command(&maximum).unwrap();
        assert!(protected.data.len() <= MAX_APDU_DATA_BYTES);
        assert!(protected.to_bytes().is_ok());
        assert_eq!(
            session.send_sequence_counter(),
            &checked_next_ssc(&initial_ssc).unwrap()
        );

        let stable_ssc = *session.send_sequence_counter();
        let oversized = ApduCommand {
            data: vec![0; MAX_BAC_COMMAND_DATA_BYTES + 1],
            ..maximum.clone()
        };
        assert!(session.protect_command(&oversized).is_err());
        assert_eq!(session.send_sequence_counter(), &stable_ssc);

        let unsupported_le = ApduCommand {
            data: Vec::new(),
            le: Some(257),
            ..maximum
        };
        assert!(session.protect_command(&unsupported_le).is_err());
        assert_eq!(session.send_sequence_counter(), &stable_ssc);

        let mut exhausted = BacSession::from_session_keys([0x11; 16], [0x22; 16], [0xff; 8]);
        let valid = ApduCommand {
            cla: 0,
            ins: 0xa4,
            p1: 0,
            p2: 0,
            data: Vec::new(),
            le: None,
        };
        assert!(exhausted.protect_command(&valid).is_err());
        assert_eq!(exhausted.send_sequence_counter(), &[0xff; 8]);
    }

    #[test]
    fn bac_response_bound_rejection_preserves_counter() {
        let initial_ssc = [0x44; 8];
        let mut session = BacSession::from_session_keys([0x11; 16], [0x22; 16], initial_ssc);
        let oversized = ApduResponse {
            data: vec![0; MAX_BAC_PROTECTED_RESPONSE_BYTES + 1],
            sw1: 0x90,
            sw2: 0,
        };
        assert!(session.unprotect_response(&oversized).is_err());
        assert_eq!(session.send_sequence_counter(), &initial_ssc);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn secure_messaging_authenticates_before_cbc_decryption() {
        let mut malformed_bac = vec![0x87, 0x09, 0x01];
        malformed_bac.extend_from_slice(&[0u8; 8]);
        malformed_bac.extend_from_slice(&[0x99, 0x02, 0x90, 0x00, 0x8e, 0x08]);
        malformed_bac.extend_from_slice(&[0u8; 8]);
        let mut bac = BacSession::from_session_keys([0x11; 16], [0x22; 16], [0x33; 8]);
        let initial_bac_ssc = *bac.send_sequence_counter();
        let error = bac
            .unprotect_response(&ApduResponse {
                data: malformed_bac,
                sw1: 0x90,
                sw2: 0x00,
            })
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("response MAC verification failed"));
        assert!(!error.to_string().contains("padding"));
        assert_eq!(bac.send_sequence_counter(), &initial_bac_ssc);

        let mut malformed_pace = vec![0x87, 0x11, 0x01];
        malformed_pace.extend_from_slice(&[0u8; 16]);
        malformed_pace.extend_from_slice(&[0x99, 0x02, 0x90, 0x00, 0x8e, 0x08]);
        malformed_pace.extend_from_slice(&[0u8; 8]);
        let mut pace = PaceSession::from_shared_secret(b"shared secret");
        let error = pace
            .unprotect_response(&ApduResponse {
                data: malformed_pace,
                sw1: 0x90,
                sw2: 0x00,
            })
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("response MAC verification failed"));
        assert!(!error.to_string().contains("padding"));
    }

    #[test]
    fn pace_iv_and_response_status_encoding_match_normative_construction() {
        let key: [u8; 16] = hex::decode("000102030405060708090A0B0C0D0E0F")
            .unwrap()
            .try_into()
            .unwrap();
        let ssc: [u8; 16] = hex::decode("00112233445566778899AABBCCDDEEFF")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode_upper(pace_encryption_iv(&key, &ssc).unwrap()),
            "69C4E0D86A7B0430D8CDB78070B4C55A"
        );

        let mut encoded = Vec::new();
        push_ber_tlv(0x99, &[0x90, 0x00], &mut encoded).unwrap();
        assert_eq!(encoded, [0x99, 0x02, 0x90, 0x00]);
    }

    #[test]
    fn secure_messaging_uses_canonical_ber_lengths() {
        let mut encoded = Vec::new();
        push_ber_tlv(0x87, &[0u8; 128], &mut encoded).unwrap();
        assert_eq!(&encoded[..3], &[0x87, 0x81, 0x80]);
        let mut offset = 0;
        let parsed = next_ber_tlv(&encoded, &mut offset, "test").unwrap();
        assert_eq!(parsed.value.len(), 128);
        assert_eq!(offset, encoded.len());
    }
}
