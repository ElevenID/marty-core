//! eMRTD (ePassport) issuance infrastructure.
//!
//! This module is used by **government issuing authorities** to:
//! 1. Operate a Country Signing Certificate Authority (CSCA).
//! 2. Issue Document Signer Certificates (DSC) from the CSCA.
//! 3. Personalise eMRTD chips: produce a signed EF.SOD containing the
//!    document's data group hashes.
//!
//! # ICAO 9303 Role Mapping
//!
//! | ICAO term          | This module                     |
//! |--------------------|---------------------------------|
//! | CSCA (root CA)     | [`CscaAuthority`]               |
//! | DSC (batch CA)     | [`DocumentSignerAuthority`]     |
//! | EF.SOD production  | [`PassportPersonalizer`]        |
//! | Personalised chip  | [`PersonalizedPassport`]        |
//!
//! # Example
//!
//! ```rust,ignore
//! use marty_verification::issuance::{CscaAuthority, PersonalizedPassport};
//!
//! // Set up the country CA hierarchy
//! let csca = CscaAuthority::new("DEU", "Federal Republic of Germany", 3650)?;
//! let dsc  = csca.issue_dsc("DEU Document Signer Batch 1", 90)?;
//!
//! // Produce EF.SOD for an individual passport
//! let mrz_dg1 = b"P<DEUTMUSTER<<ERIKA\
//!                 L898902C36DEU7408125F1204159<<<<<<<<<<<<<<<6";
//! let face_dg2 = include_bytes!("path/to/face.jp2");
//!
//! let passport = dsc.personalizer()
//!     .set_mrz(mrz_dg1)
//!     .set_face_image(face_dg2)
//!     .build()?;
//!
//! // Write `passport.sod_der` to EF.SOD on chip
//! // Write `passport.data_groups[&1]` to EF.DG1, etc.
//! println!("EF.SOD is {} bytes", passport.sod_der.len());
//! ```

use std::collections::HashMap;

pub use marty_crypto::sod_builder::EmrtdSodBuilder;

use crate::{VerificationError, VerificationResult};

// ─── CSCA ─────────────────────────────────────────────────────────────────────

/// Country Signing Certificate Authority (CSCA).
///
/// The CSCA is a country's root trust anchor for eMRTD.  Per ICAO 9303 Part 12
/// each country maintains one or more CSCAs with validity up to ~20 years.
///
/// The private key **must never leave the HSM/offline system**.  In production,
/// replace `new` with an HSM-backed variant and use `from_cert_der_only` when
/// the private key is managed externally.
pub struct CscaAuthority {
    /// DER-encoded self-signed CSCA certificate (public).
    pub cert_der: Vec<u8>,
    /// PKCS#8 PEM private signing key.  Keep offline/in HSM.
    private_key_pem: String,
    /// ISO 3166-1 alpha-3 country code (e.g. `"DEU"`).
    pub country: String,
}

impl CscaAuthority {
    /// Generate a new CSCA: creates keypair + self-signed certificate.
    ///
    /// # Arguments
    /// * `country`       – ISO 3166-1 alpha-3 country code (e.g. `"DEU"`)
    /// * `organization`  – Full organisation name
    /// * `validity_days` – Certificate validity in days (recommend ≥ 10 years)
    pub fn new(country: &str, organization: &str, validity_days: u32) -> VerificationResult<Self> {
        let (cert_der, private_key_pem) = marty_crypto::cert_builder::create_csca_certificate(
            country,
            organization,
            validity_days,
            marty_crypto::keygen::KeyType::EcdsaP256,
        )
        .map_err(|e| VerificationError::internal(e.to_string()))?;

        Ok(Self {
            cert_der,
            private_key_pem,
            country: country.to_string(),
        })
    }

    /// Load a CSCA from an existing certificate + private key PEM.
    ///
    /// Use this when the key material was generated externally (e.g. HSM export).
    pub fn from_pem(country: &str, cert_der: Vec<u8>, private_key_pem: String) -> Self {
        Self {
            cert_der,
            private_key_pem,
            country: country.to_string(),
        }
    }

    /// Issue a Document Signer Certificate signed by this CSCA.
    ///
    /// # Arguments
    /// * `subject_label` – Free-text identifier for the DSC (e.g. `"DEU DSC Batch 2026-Q1"`)
    /// * `validity_days` – DSC validity in days (ICAO recommends ≤ 3 months)
    pub fn issue_dsc(
        &self,
        subject_label: &str,
        validity_days: u32,
    ) -> VerificationResult<DocumentSignerAuthority> {
        let (dsc_der, dsc_key_pem) = marty_crypto::cert_builder::create_dsc_certificate(
            &self.country,
            subject_label,
            &self.cert_der,
            &self.private_key_pem,
            validity_days,
            marty_crypto::keygen::KeyType::EcdsaP256,
        )
        .map_err(|e| VerificationError::internal(e.to_string()))?;

        Ok(DocumentSignerAuthority {
            cert_der: dsc_der,
            private_key_pem: dsc_key_pem,
            csca_cert_der: self.cert_der.clone(),
            country: self.country.clone(),
        })
    }

    /// Certificate as PEM string.
    pub fn cert_pem(&self) -> VerificationResult<String> {
        marty_crypto::certificate::der_to_pem(&self.cert_der)
            .map_err(|e| VerificationError::internal(e.to_string()))
    }

    /// Raw DER certificate bytes.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }
}

// ─── DSC ──────────────────────────────────────────────────────────────────────

/// Document Signer Certificate (DSC) authority.
///
/// The DSC is issued by the CSCA and used to sign EF.SOD during passport
/// personalisation.  A new DSC batch should be issued every 3 months per
/// ICAO 9303 recommendation.
pub struct DocumentSignerAuthority {
    /// DER-encoded DSC certificate.
    pub cert_der: Vec<u8>,
    /// PKCS#8 PEM signing key.
    private_key_pem: String,
    /// DER-encoded CSCA certificate that issued this DSC.
    pub csca_cert_der: Vec<u8>,
    /// Country code.
    pub country: String,
}

impl DocumentSignerAuthority {
    /// Build a `PassportPersonalizer` pre-loaded with this DSC's signing material.
    pub fn personalizer(&self) -> PassportPersonalizer {
        PassportPersonalizer {
            dsc_cert_der: self.cert_der.clone(),
            dsc_private_key_pem: self.private_key_pem.clone(),
            data_groups: HashMap::new(),
        }
    }

    /// Certificate as PEM string.
    pub fn cert_pem(&self) -> VerificationResult<String> {
        marty_crypto::certificate::der_to_pem(&self.cert_der)
            .map_err(|e| VerificationError::internal(e.to_string()))
    }

    /// Raw DER certificate bytes.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }
}

// ─── Personalizer ─────────────────────────────────────────────────────────────

/// Builds a signed EF.SOD for a single passport.
///
/// Add all data groups using the builder methods, then call [`build`](Self::build)
/// to produce the [`PersonalizedPassport`].
pub struct PassportPersonalizer {
    dsc_cert_der: Vec<u8>,
    dsc_private_key_pem: String,
    /// DG number → raw EF.DG byte content.
    data_groups: HashMap<u8, Vec<u8>>,
}

impl PassportPersonalizer {
    /// Add or replace a data group.
    ///
    /// * `dg_number` – ICAO data group number (1–16, or 17–20 for extensions)
    /// * `content`   – Raw data group bytes (full EF.DG TLV content)
    pub fn set_data_group(mut self, dg_number: u8, content: Vec<u8>) -> Self {
        self.data_groups.insert(dg_number, content);
        self
    }

    /// Set DG1 — Machine Readable Zone.
    ///
    /// `mrz_bytes` should contain the complete MRZ TLV structure that will be
    /// stored as EF.DG1 on the chip (the raw LDS data group, not just the zone
    /// string itself).
    pub fn set_mrz(self, mrz_bytes: &[u8]) -> Self {
        self.set_data_group(1, mrz_bytes.to_vec())
    }

    /// Set DG2 — Encoded face image (JPEG-2000 or JPEG per ICAO 9303).
    pub fn set_face_image(self, image_bytes: &[u8]) -> Self {
        self.set_data_group(2, image_bytes.to_vec())
    }

    /// Set DG3 — Encoded fingerprint(s).  Requires EAC on the chip.
    pub fn set_fingerprints(self, fingerprint_bytes: &[u8]) -> Self {
        self.set_data_group(3, fingerprint_bytes.to_vec())
    }

    /// Set DG7 — Displayed signature or usual mark.
    pub fn set_signature_image(self, sig_bytes: &[u8]) -> Self {
        self.set_data_group(7, sig_bytes.to_vec())
    }

    /// Build and sign the EF.SOD.
    ///
    /// Hashes each data group with SHA-256, embeds them in an
    /// `LDSSecurityObject`, and produces a CMS `SignedData` blob signed by
    /// the DSC key.
    ///
    /// # Errors
    /// Returns an error if:
    /// - No data groups were added.
    /// - The DSC key PEM is invalid.
    /// - CMS signing fails.
    pub fn build(self) -> VerificationResult<PersonalizedPassport> {
        if self.data_groups.is_empty() {
            return Err(VerificationError::internal(
                "PassportPersonalizer: at least one data group must be set before build()"
                    .to_string(),
            ));
        }

        let mut builder = EmrtdSodBuilder::new();
        for (&dg_num, content) in &self.data_groups {
            builder = builder.add_data_group(dg_num, content.clone());
        }

        let sod_der = builder
            .build(&self.dsc_cert_der, &self.dsc_private_key_pem)
            .map_err(|e| VerificationError::internal(format!("EF.SOD build failed: {}", e)))?;

        Ok(PersonalizedPassport {
            sod_der,
            dsc_cert_der: self.dsc_cert_der,
            data_groups: self.data_groups,
        })
    }
}

// ─── Result ───────────────────────────────────────────────────────────────────

/// A fully personalised passport ready to be written to an eMRTD chip.
#[derive(Debug, Clone)]
pub struct PersonalizedPassport {
    /// DER-encoded `ContentInfo` (`CMS SignedData`) — write to `EF.SOD`.
    pub sod_der: Vec<u8>,
    /// DER-encoded Document Signer Certificate embedded in the SOD.
    pub dsc_cert_der: Vec<u8>,
    /// Data groups to write to the chip (`EF.DG{n}`).
    pub data_groups: HashMap<u8, Vec<u8>>,
}

impl PersonalizedPassport {
    /// Size of the EF.SOD in bytes.
    pub fn sod_size(&self) -> usize {
        self.sod_der.len()
    }

    /// List of data group numbers present in this passport.
    pub fn data_group_numbers(&self) -> Vec<u8> {
        let mut nums: Vec<u8> = self.data_groups.keys().copied().collect();
        nums.sort_unstable();
        nums
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csca_dsc_issuance_chain() {
        let csca = CscaAuthority::new("TST", "Test Country Government", 3650).unwrap();
        assert!(!csca.cert_der.is_empty());
        assert_eq!(csca.country, "TST");

        let dsc = csca.issue_dsc("TST DSC Batch 1", 90).unwrap();
        assert!(!dsc.cert_der.is_empty());
        assert_eq!(dsc.csca_cert_der, csca.cert_der);
    }

    #[test]
    fn test_personalize_minimal_passport() {
        let csca = CscaAuthority::new("TST", "Test Country Government", 3650).unwrap();
        let dsc = csca.issue_dsc("TST DSC Batch 1", 90).unwrap();

        let mrz = b"P<TSTMUSTER<<ERIKA<<<<<<<<<<<<<<<<<<<<<<<<<<<L898902C36TST7408125F1204159<<<<<<<<<<<<<<<6";
        let face = [0xFFu8; 64]; // dummy face image

        let passport = dsc
            .personalizer()
            .set_mrz(mrz)
            .set_face_image(&face)
            .build()
            .unwrap();

        assert!(!passport.sod_der.is_empty());
        assert_eq!(passport.data_group_numbers(), vec![1, 2]);
        assert_eq!(passport.data_groups[&1], mrz.to_vec());
    }

    #[test]
    fn test_personalizer_empty_fails() {
        let csca = CscaAuthority::new("TST", "Test Country", 365).unwrap();
        let dsc = csca.issue_dsc("TST DSC", 30).unwrap();
        let err = dsc.personalizer().build();
        assert!(err.is_err());
    }

    #[test]
    fn test_cert_pem_round_trip() {
        let csca = CscaAuthority::new("TST", "Test Country", 365).unwrap();
        let pem = csca.cert_pem().unwrap();
        assert!(pem.contains("CERTIFICATE"));
    }

    // ── from_pem round-trip ─────────────────────────────────────────────

    #[test]
    fn test_csca_from_pem_re_issues_dsc() {
        // Generate a CSCA, extract its cert+key, reload via from_pem, and
        // verify it can still issue a DSC.
        let original = CscaAuthority::new("TST", "Test Country", 365).unwrap();
        let cert_der = original.cert_der.clone();
        let key_pem = original.private_key_pem.clone();

        let reloaded = CscaAuthority::from_pem("TST", cert_der.clone(), key_pem);
        assert_eq!(reloaded.country, "TST");
        assert_eq!(reloaded.cert_der, cert_der);

        // Must still be able to issue a DSC.
        let dsc = reloaded.issue_dsc("TST DSC via from_pem", 30).unwrap();
        assert!(!dsc.cert_der.is_empty());
        assert_eq!(dsc.csca_cert_der, cert_der);
    }

    // ── data_group_numbers ordering / sod_size ──────────────────────────

    #[test]
    fn test_data_group_numbers_sorted_non_sequential() {
        let csca = CscaAuthority::new("TST", "Test Country", 365).unwrap();
        let dsc = csca.issue_dsc("TST DSC", 30).unwrap();

        let passport = dsc
            .personalizer()
            .set_mrz(b"MRZ_DG1") // DG1
            .set_signature_image(b"SIG") // DG7
            .set_data_group(14, b"AA_CHIP_AUTH".to_vec()) // DG14
            .build()
            .unwrap();

        assert_eq!(passport.data_group_numbers(), vec![1, 7, 14]);
    }

    #[test]
    fn test_sod_size_nonzero() {
        let csca = CscaAuthority::new("TST", "Test Country", 365).unwrap();
        let dsc = csca.issue_dsc("TST DSC", 30).unwrap();
        let passport = dsc.personalizer().set_mrz(b"MRZ").build().unwrap();
        assert!(passport.sod_size() > 0);
        assert_eq!(passport.sod_size(), passport.sod_der.len());
    }

    #[test]
    fn test_dsc_cert_pem_contains_certificate() {
        let csca = CscaAuthority::new("TST", "Test Country", 365).unwrap();
        let dsc = csca.issue_dsc("TST DSC", 30).unwrap();
        let pem = dsc.cert_pem().unwrap();
        assert!(pem.contains("CERTIFICATE"));
    }

    #[test]
    fn test_personalized_passport_clone_is_independent() {
        let csca = CscaAuthority::new("TST", "Test Country", 365).unwrap();
        let dsc = csca.issue_dsc("TST DSC", 30).unwrap();
        let passport = dsc.personalizer().set_mrz(b"MRZ").build().unwrap();
        let cloned = passport.clone();
        assert_eq!(cloned.sod_der, passport.sod_der);
        assert_eq!(cloned.dsc_cert_der, passport.dsc_cert_der);
    }

    // ── Issuance → Verification round-trip ──────────────────────────────

    #[test]
    fn test_issue_then_verify_emrtd_round_trip() {
        use der::Decode;
        use x509_cert::Certificate;

        use crate::trust_anchor::CscaRegistry;
        use crate::verification::emrtd::{verify_emrtd, SecurityObject};

        // 1. Build CSCA → DSC → PersonalizedPassport
        let csca = CscaAuthority::new("TST", "Test Issuance Country", 3650).unwrap();
        let dsc = csca.issue_dsc("TST DSC Batch Round-trip", 90).unwrap();

        let mrz = b"P<TSTMUSTER<<ERIKA<<<<<<<<<<<<<<<<<<<<<<<<<<<L898902C36TST7408125F1204159<<<<<<<<<<<<<<<6";
        let face = [0x01u8; 32];
        let passport = dsc
            .personalizer()
            .set_mrz(mrz)
            .set_face_image(&face)
            .build()
            .unwrap();

        assert!(!passport.sod_der.is_empty(), "SOD must be non-empty");

        // 2. Build a CscaRegistry containing the issuing CSCA
        let csca_cert =
            Certificate::from_der(&csca.cert_der).expect("CSCA cert_der must be valid DER");
        let mut registry = CscaRegistry::new();
        registry
            .add_country_csca("TST", csca_cert)
            .expect("adding CSCA to registry must succeed");

        // 3. Parse the SOD and verify
        let sod = SecurityObject::from_sod_der(&passport.sod_der, Some("TST".to_string()))
            .expect("SecurityObject::from_sod_der must succeed on freshly issued passport");

        let result = verify_emrtd(&sod, &passport.data_groups, &registry);

        assert!(
            result.verified,
            "Freshly issued passport must pass full eMRTD verification; errors: {:?}",
            result.errors
        );
        assert_eq!(
            result.dsc_chain_status,
            crate::verification::emrtd::ChainStatus::Valid
        );
        assert_eq!(
            result.dg_hash_status,
            crate::verification::emrtd::HashStatus::Valid
        );
        assert_eq!(
            result.sod_signature_status,
            crate::verification::emrtd::SignatureStatus::Valid
        );
    }

    #[test]
    fn test_verify_fails_with_tampered_data_group() {
        use der::Decode;
        use x509_cert::Certificate;

        use crate::trust_anchor::CscaRegistry;
        use crate::verification::emrtd::{verify_emrtd, HashStatus, SecurityObject};

        let csca = CscaAuthority::new("TST", "Tamper Test Country", 365).unwrap();
        let dsc = csca.issue_dsc("TST DSC Tamper", 30).unwrap();
        let mrz = b"P<TSTTEST<<NAME<<<<<<<<<<<<<<<<<<<<<<<<<<<<<L898902C36TST7408125F1204159<<<<<<<<<<<<<<<6";
        let passport = dsc.personalizer().set_mrz(mrz).build().unwrap();

        let csca_cert = Certificate::from_der(&csca.cert_der).unwrap();
        let mut registry = CscaRegistry::new();
        registry.add_country_csca("TST", csca_cert).unwrap();

        let sod = SecurityObject::from_sod_der(&passport.sod_der, Some("TST".to_string())).unwrap();

        // Tamper: replace DG1 with different bytes
        let mut tampered_dgs = passport.data_groups.clone();
        tampered_dgs.insert(1, b"TAMPERED MRZ DATA".to_vec());

        let result = verify_emrtd(&sod, &tampered_dgs, &registry);

        assert!(!result.verified, "Tampered passport must not verify");
        assert_eq!(result.dg_hash_status, HashStatus::Invalid);
    }
}
