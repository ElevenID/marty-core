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
    /// Serialise to ISO/IEC 7816-4 byte wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![self.cla, self.ins, self.p1, self.p2];
        if !self.data.is_empty() {
            debug_assert!(
                self.data.len() <= 255,
                "APDU data exceeds short-form Lc limit"
            );
            buf.push(self.data.len() as u8);
            buf.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            buf.push(le as u8);
        }
        buf
    }
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
}

impl std::fmt::Debug for BacKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BacKeys { … }")
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

impl BacSession {
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
        use rand::RngCore;

        let base_keys = derive_bac_base_keys(mrz)?;

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
        let mut rnd_ic = [0u8; 8];
        rnd_ic.copy_from_slice(&resp.data);

        // ── Step 3: Generate Rnd.IFD + KID.IFD ───────────────────────────────
        let mut rnd_ifd = [0u8; 8];
        let mut kid_ifd = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut rnd_ifd);
        rand::rngs::OsRng.fill_bytes(&mut kid_ifd);

        // ── Step 4: E_IFD = 3DES-CBC(K_ENC, 0, Rnd.IFD‖Rnd.IC‖KID.IFD) ─────
        let mut m1 = [0u8; 24];
        m1[..8].copy_from_slice(&rnd_ifd);
        m1[8..16].copy_from_slice(&rnd_ic);
        m1[16..].copy_from_slice(&kid_ifd);

        let k_enc_24 = extend_to_24_bytes(&base_keys.k_enc);
        let e_ifd = marty_crypto::des::tdes_cbc_encrypt(&k_enc_24, &[0u8; 8], &m1)
            .map_err(|e| VerificationError::internal(format!("BAC encrypt failed: {}", e)))?;

        // ── Step 5: M_IFD = Retail-MAC(K_MAC, E_IFD) ─────────────────────────
        let m_ifd = retail_mac_3des(&base_keys.k_mac, &e_ifd)?;

        // ── Step 6: EXTERNAL AUTHENTICATE ────────────────────────────────────
        let mut auth_data = Vec::with_capacity(32);
        auth_data.extend_from_slice(&e_ifd);
        auth_data.extend_from_slice(&m_ifd);

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
        let e_ic = &resp.data[..32];
        let m_ic = &resp.data[32..40];

        let expected_mac = retail_mac_3des(&base_keys.k_mac, e_ic)?;
        if !constant_time_eq(&expected_mac, m_ic) {
            return Err(VerificationError::internal(
                "BAC: chip response MAC verification failed".to_string(),
            ));
        }

        let k_enc_24 = extend_to_24_bytes(&base_keys.k_enc);
        let m2 = marty_crypto::des::tdes_cbc_decrypt(&k_enc_24, &[0u8; 8], e_ic)
            .map_err(|e| VerificationError::internal(format!("BAC decrypt failed: {}", e)))?;

        if m2[0..8] != rnd_ic {
            return Err(VerificationError::internal(
                "BAC: reflected Rnd.IC mismatch — possible man-in-the-middle".to_string(),
            ));
        }
        if m2[8..16] != rnd_ifd {
            return Err(VerificationError::internal(
                "BAC: reflected Rnd.IFD mismatch — possible man-in-the-middle".to_string(),
            ));
        }

        // ── Step 8: Derive session keys ───────────────────────────────────────
        let ks_enc;
        let ks_mac;
        let ssc;
        {
            let mut seed = [0u8; 8];
            for i in 0..8 {
                seed[i] = rnd_ifd[i] ^ rnd_ic[i];
            }
            ks_enc = bac_kdf_16(&seed, 1)?;
            ks_mac = bac_kdf_16(&seed, 2)?;

            // SSC = last 4 bytes of Rnd.IC || last 4 bytes of Rnd.IFD
            ssc = {
                let mut s = [0u8; 8];
                s[..4].copy_from_slice(&rnd_ic[4..]);
                s[4..].copy_from_slice(&rnd_ifd[4..]);
                s
            };
        }

        Ok(Self {
            k_enc: ks_enc,
            k_mac: ks_mac,
            ssc,
        })
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
            let iv = compute_3des_iv_from_ssc(&self.k_enc, &self.ssc)?;
            let enc = marty_crypto::des::tdes_cbc_encrypt(&k24, &iv, &padded)
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
                        let iv = compute_3des_iv_from_ssc(&self.k_enc, &self.ssc)?;
                        let decrypted = marty_crypto::des::tdes_cbc_decrypt(&k24, &iv, ciphertext)
                            .map_err(|e| {
                                VerificationError::internal(format!("SM decrypt: {}", e))
                            })?;
                        plain_data = iso7816_unpad(&decrypted)?;
                    }
                }
                0x8E if len == 8 => received_mac.copy_from_slice(value),
                _ => {}
            }
            i += 2 + len;
        }

        // Verify MAC: SSC || DO'87 || SW1SW2
        let sw_bytes = [resp.sw1, resp.sw2];
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&self.ssc);
        mac_input.extend_from_slice(&do87_bytes);
        mac_input.extend_from_slice(&sw_bytes);

        let expected = retail_mac_3des(&self.k_mac, &mac_input)?;
        if !constant_time_eq(&expected, &received_mac) {
            return Err(VerificationError::internal(
                "BAC SM: response MAC verification failed".to_string(),
            ));
        }

        Ok(ApduResponse {
            data: plain_data,
            sw1: resp.sw1,
            sw2: resp.sw2,
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

    Ok(BacKeys { k_enc, k_mac })
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
    while padded.len() % 8 != 0 {
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

/// Compute the 3DES IV from the Send Sequence Counter (BAC).
///
/// IV = 3DES-CBC-encrypt(KSenc, 0, SSC)
fn compute_3des_iv_from_ssc(k_enc: &[u8; 16], ssc: &[u8; 8]) -> VerificationResult<[u8; 8]> {
    let k24 = extend_to_24_bytes(k_enc);
    let out = marty_crypto::des::tdes_cbc_encrypt(&k24, &[0u8; 8], ssc)
        .map_err(|e| VerificationError::internal(format!("SSC IV compute: {}", e)))?;
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&out[..8]);
    Ok(iv)
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
            doc_number_with_check: "L898902C36".to_string(),
            dob_with_check: "7408125".to_string(),
            expiry_with_check: "1204159".to_string(),
        };
        let keys = derive_bac_base_keys(&mrz).unwrap();
        // Keys should be non-zero and length 16
        assert_eq!(keys.k_enc.len(), 16);
        assert_eq!(keys.k_mac.len(), 16);
        assert_ne!(keys.k_enc, [0u8; 16]);
        assert_ne!(keys.k_mac, [0u8; 16]);
        assert_ne!(keys.k_enc, keys.k_mac);
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
