//! EF.SOD (Document Security Object) builder for ICAO 9303-compliant eMRTDs.
//!
//! The SOD (`EF.SOD`) is the Document Security Object stored on an eMRTD chip.
//! It is a CMS `SignedData` structure (PKCS#7/RFC 5652) containing:
//! - `LDSSecurityObject`: SHA-256 hashes of all data groups
//! - `Document Signer Certificate` (DSC)
//! - ECDSA-SHA256 signature from the DSC
//!
//! Per ICAO 9303 Part 10 (LDS and PKI Maintenance).
//!
//! # Example
//!
//! ```ignore
//! use marty_crypto::cert_builder::{create_csca_certificate, create_dsc_certificate, KeyType};
//! use marty_crypto::sod_builder::EmrtdSodBuilder;
//!
//! let (csca_der, csca_key) = create_csca_certificate("DEU", "Germany", 3650, KeyType::EcdsaP256)?;
//! let (dsc_der, dsc_key) = create_dsc_certificate("DEU", "Germany", &csca_der, &csca_key, 730, KeyType::EcdsaP256)?;
//!
//! let dg1 = b"P<DEUTMUSTER<<ERIKA<<<<<<<<<<<<<<<<<<<<<<<<\
//!             L898902C36DEU7408125F1204159<<<<<<<<<<<<<<<6";
//!
//! let sod_der = EmrtdSodBuilder::new()
//!     .add_data_group(1, dg1.to_vec())
//!     .build(&dsc_der, &dsc_key)?;
//! ```

#[cfg(feature = "sod-builder")]
mod inner {
    use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
    use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
    use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
    use const_oid::ObjectIdentifier;
    use der::asn1::{OctetString, SequenceOf};
    use der::{Any, Decode, Encode, Sequence, Tag};
    use p256::pkcs8::DecodePrivateKey;
    use sha2::{Digest, Sha256};
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::Certificate;

    use crate::{CryptoError, CryptoResult};

    // ============================================================================
    // ICAO 9303 OIDs
    // ============================================================================

    /// OID for ICAO 9303 LDS Security Object: `id-icao-ldsSecurityObject`
    /// (`2.23.136.1.1.1`)
    const ID_ICAO_LDS_SECURITY_OBJECT: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.23.136.1.1.1");

    /// OID for SHA-256 (`2.16.840.1.101.3.4.2.1`)
    const ID_SHA_256: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

    // ============================================================================
    // ASN.1 types for LDSSecurityObject
    // ============================================================================

    /// ASN.1 `DataGroupHash` per ICAO 9303-10.
    ///
    /// ```asn1
    /// DataGroupHash ::= SEQUENCE {
    ///   dataGroupNumber    DataGroupNumber,   -- INTEGER 1..16
    ///   dataGroupHashValue OCTET STRING
    /// }
    /// ```
    #[derive(Clone, Debug, Sequence)]
    struct AsnDataGroupHash {
        data_group_number: u8,
        data_group_hash_value: OctetString,
    }

    /// ASN.1 `LDSSecurityObject` per ICAO 9303-10 (version 0, LDS v1.7).
    ///
    /// ```asn1
    /// LDSSecurityObject ::= SEQUENCE {
    ///   version              LDSSecurityObjectVersion,  -- 0
    ///   hashAlgorithm        AlgorithmIdentifier,
    ///   dataGroupHashValues  SEQUENCE OF DataGroupHash
    /// }
    /// ```
    ///
    /// Up to 20 data groups supported (covers DG1–DG16 + DG17–DG20 extensions).
    #[derive(Clone, Debug, Sequence)]
    struct AsnLdsSecurityObject {
        version: u8,
        hash_algorithm: AlgorithmIdentifierOwned,
        data_group_hash_values: SequenceOf<AsnDataGroupHash, 20>,
    }

    // ============================================================================
    // SOD Builder
    // ============================================================================

    /// Builder for ICAO 9303 `EF.SOD` (Document Security Object) structures.
    ///
    /// Produces a DER-encoded CMS `ContentInfo` (`SignedData`) that passes
    /// `marty_verification::asn1::sod::verify_sod_signature`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let sod_der = EmrtdSodBuilder::new()
    ///     .add_data_group(1, dg1_bytes)
    ///     .add_data_group(2, dg2_bytes)
    ///     .build(&dsc_cert_der, &dsc_key_pem)?;
    /// ```
    pub struct EmrtdSodBuilder {
        data_groups: Vec<(u8, Vec<u8>)>,
    }

    impl EmrtdSodBuilder {
        /// Create a new empty builder.
        pub fn new() -> Self {
            Self {
                data_groups: Vec::new(),
            }
        }

        /// Add a data group.
        ///
        /// - `number` — ICAO data group number (1–16, or 17–20 for extensions)
        /// - `content` — raw data group bytes (the full EF.DG content)
        pub fn add_data_group(mut self, number: u8, content: Vec<u8>) -> Self {
            self.data_groups.push((number, content));
            self
        }

        /// Build the EF.SOD DER bytes, signing with `dsc_key_pem`.
        ///
        /// # Arguments
        /// - `dsc_cert_der` — DER-encoded Document Signer Certificate (X.509 v3)
        /// - `dsc_key_pem`  — PKCS#8 PEM private key for the DSC (P-256 ECDSA)
        ///
        /// # Returns
        /// DER-encoded `ContentInfo` (CMS `SignedData`).
        pub fn build(self, dsc_cert_der: &[u8], dsc_key_pem: &str) -> CryptoResult<Vec<u8>> {
            build_emrtd_sod_der(&self.data_groups, dsc_cert_der, dsc_key_pem)
        }
    }

    impl Default for EmrtdSodBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    // ============================================================================
    // Public builder function
    // ============================================================================

    /// Build an ICAO 9303 `EF.SOD` as a DER-encoded `ContentInfo`.
    ///
    /// # Arguments
    /// - `data_groups` — `(dg_number, raw_dg_content)` pairs; the content is
    ///   hashed internally with SHA-256
    /// - `dsc_cert_der` — DER-encoded Document Signer Certificate
    /// - `dsc_key_pem`  — PKCS#8 PEM private key for the DSC (P-256 ECDSA)
    ///
    /// # Returns
    /// DER-encoded `ContentInfo` wrapping a CMS `SignedData`.
    pub fn build_emrtd_sod_der(
        data_groups: &[(u8, Vec<u8>)],
        dsc_cert_der: &[u8],
        dsc_key_pem: &str,
    ) -> CryptoResult<Vec<u8>> {
        // ── Step 1: SHA-256 hash each data group ──────────────────────────────
        let dg_hashes: Vec<(u8, Vec<u8>)> = data_groups
            .iter()
            .map(|(num, content)| (*num, Sha256::digest(content).to_vec()))
            .collect();

        // ── Step 2: Build LDSSecurityObject ASN.1 DER ─────────────────────────
        let lds_so_der = build_lds_security_object_der(&dg_hashes)?;

        // ── Step 3: Wrap in EncapsulatedContentInfo ───────────────────────────
        // RFC 5652 §5.2: eContent is an OCTET STRING containing the value bytes.
        // Any::value() returns the OCTET STRING value, which is what the digest
        // is computed over (and what the verifier calls `.value()` on).
        let econtent = Any::new(Tag::OctetString, lds_so_der)
            .map_err(|e| CryptoError::der(format!("eContent Any construction: {e}")))?;
        let eci = EncapsulatedContentInfo {
            econtent_type: ID_ICAO_LDS_SECURITY_OBJECT,
            econtent: Some(econtent),
        };

        // ── Step 4: Parse DSC certificate for SignerIdentifier ────────────────
        let dsc_cert = Certificate::from_der(dsc_cert_der)
            .map_err(|e| CryptoError::der(format!("DSC certificate parse: {e}")))?;
        let issuer = dsc_cert.tbs_certificate.issuer.clone();
        let serial = dsc_cert.tbs_certificate.serial_number.clone();
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer,
            serial_number: serial,
        });

        // ── Step 5: Load DSC signing key ──────────────────────────────────────
        let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(dsc_key_pem)
            .map_err(|e| CryptoError::invalid_key(format!("DSC PKCS#8 PEM parse: {e}")))?;

        // ── Step 6: Build SignerInfo ───────────────────────────────────────────
        let digest_algorithm = AlgorithmIdentifierOwned {
            oid: ID_SHA_256,
            parameters: None,
        };
        let sib = SignerInfoBuilder::new(
            &signing_key,
            sid,
            digest_algorithm.clone(),
            &eci,
            None,
        )
        .map_err(|e| CryptoError::der(format!("SignerInfoBuilder::new: {e}")))?;

        // ── Step 7: Assemble SignedData ────────────────────────────────────────
        let mut sd_builder = SignedDataBuilder::new(&eci);
        sd_builder
            .add_digest_algorithm(digest_algorithm)
            .map_err(|e| CryptoError::der(format!("add_digest_algorithm: {e}")))?
            .add_certificate(CertificateChoices::Certificate(dsc_cert))
            .map_err(|e| CryptoError::der(format!("add_certificate: {e}")))?
            .add_signer_info::<p256::ecdsa::SigningKey, p256::ecdsa::DerSignature>(sib)
            .map_err(|e| CryptoError::der(format!("add_signer_info: {e}")))?;

        let content_info = sd_builder
            .build()
            .map_err(|e| CryptoError::der(format!("SignedDataBuilder::build: {e}")))?;

        // ── Step 8: DER-encode ContentInfo ────────────────────────────────────
        content_info
            .to_der()
            .map_err(|e| CryptoError::der(format!("ContentInfo to_der: {e}")))
    }

    // ============================================================================
    // LDSSecurityObject DER construction
    // ============================================================================

    /// Build the DER-encoded `LDSSecurityObject` structure.
    fn build_lds_security_object_der(dg_hashes: &[(u8, Vec<u8>)]) -> CryptoResult<Vec<u8>> {
        let hash_algorithm = AlgorithmIdentifierOwned {
            oid: ID_SHA_256,
            parameters: None,
        };

        let mut dg_hash_seq: SequenceOf<AsnDataGroupHash, 20> = SequenceOf::new();
        for (num, hash) in dg_hashes {
            let entry = AsnDataGroupHash {
                data_group_number: *num,
                data_group_hash_value: OctetString::new(hash.clone())
                    .map_err(|e| CryptoError::der(format!("DataGroupHash OctetString: {e}")))?,
            };
            dg_hash_seq
                .add(entry)
                .map_err(|e| CryptoError::der(format!("SequenceOf too many entries: {e}")))?;
        }

        let lds_so = AsnLdsSecurityObject {
            version: 0,
            hash_algorithm,
            data_group_hash_values: dg_hash_seq,
        };

        lds_so
            .to_der()
            .map_err(|e| CryptoError::der(format!("LDSSecurityObject to_der: {e}")))
    }
} // mod inner

// ── Public re-exports (gated on sod-builder feature) ──────────────────────────

#[cfg(feature = "sod-builder")]
pub use inner::{build_emrtd_sod_der, EmrtdSodBuilder};
