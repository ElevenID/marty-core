//! Complete ISO 18013-5 issuer and holder authentication.
//!
//! This is the single reusable Rust implementation used by native services and
//! language bindings. Trust inputs are verifier-owned public certificates and
//! the session transcript is derived from verifier-owned request state.

use std::collections::HashMap;

use coset::{cbor::value::Value as CoseValue, iana, Label, RegisteredLabelWithPrivate};
use der::Decode;
use isomdl::definitions::device_response::{DeviceResponse, Status};
use isomdl::definitions::x509::x5chain::{X5Chain, X5CHAIN_COSE_HEADER_LABEL};
use isomdl::definitions::{DigestAlgorithm, Mso};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    mdoc::parse_device_response,
    verification::{
        mdl::{
            validate_document_signer_certificate_der, verify_document_device_signature,
            verify_issuer_mso,
        },
        ChainValidator, ChainValidatorConfig,
    },
};

/// References copied from the exact signature-authenticated MSO. These carry
/// no fetched status, signer-trust decision, or permission to perform network I/O.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum MdocStatusReference {
    StatusList {
        uri: String,
        index: u64,
        certificate_der: Option<Vec<u8>>,
    },
    IdentifierList {
        uri: String,
        identifier: Vec<u8>,
        certificate_der: Option<Vec<u8>>,
    },
}

/// Signature-authenticated evidence for one mdoc document.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MdocDocumentVerificationEvidence {
    pub document_type: String,
    pub signature_algorithm: String,
    pub digest_algorithm: String,
    pub signed_at: String,
    pub valid_from: String,
    pub valid_until: String,
    pub issuer_certificate_sha256: String,
    /// Signed references only; offline verification still leaves revocation unchecked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status_references: Vec<MdocStatusReference>,
    pub validity_checked: bool,
    pub valid_at_verification_time: bool,
    /// Offline verification does not invent revocation evidence.
    pub revocation_checked: bool,
    pub not_revoked: Option<bool>,
}

/// Certificate-trust failures are independent from issuer and device signatures.
/// These verifier-owned diagnostics do not make a rejected credential trusted.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MdocCertificateTrustFailure {
    MissingTrustAnchors,
    InvalidTrustConfiguration,
    CertificateChainRejected,
}

/// Result of issuer-only authentication for a stored mdoc credential.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MdocIssuerVerificationResult {
    pub signature_valid: bool,
    pub issuer_trusted: bool,
    /// Typed trust-stage diagnostics; never inferred from a signature failure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_trust_failures: Vec<MdocCertificateTrustFailure>,
    pub document_types: Vec<String>,
    pub document_evidence: Vec<MdocDocumentVerificationEvidence>,
    pub revocation_checked: bool,
    pub not_revoked: Option<bool>,
    pub error: Option<String>,
}

/// Result of complete OpenID4VP mdoc presentation authentication.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MdocPresentationVerificationResult {
    pub issuer_signature_valid: bool,
    pub issuer_trusted: bool,
    /// Typed trust-stage diagnostics; never inferred from a signature failure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_trust_failures: Vec<MdocCertificateTrustFailure>,
    pub device_authentication_valid: bool,
    pub document_types: Vec<String>,
    pub document_evidence: Vec<MdocDocumentVerificationEvidence>,
    pub revocation_checked: bool,
    pub not_revoked: Option<bool>,
    pub error: Option<String>,
}

/// Authenticate issuer signatures and certificate chains at the current time.
#[must_use]
pub fn verify_mdoc_issuer(
    mdoc_bytes: &[u8],
    trusted_root_certs_pem: &[String],
    pinned_issuer_certs_pem: &[String],
) -> MdocIssuerVerificationResult {
    verify_mdoc_issuer_at(
        mdoc_bytes,
        trusted_root_certs_pem,
        pinned_issuer_certs_pem,
        OffsetDateTime::now_utc(),
    )
}

/// Authenticate issuer signatures and certificate chains at an explicit time.
#[must_use]
pub fn verify_mdoc_issuer_at(
    mdoc_bytes: &[u8],
    trusted_root_certs_pem: &[String],
    pinned_issuer_certs_pem: &[String],
    verification_time: OffsetDateTime,
) -> MdocIssuerVerificationResult {
    let issuer = verify_issuer_authentication(
        mdoc_bytes,
        trusted_root_certs_pem,
        pinned_issuer_certs_pem,
        verification_time,
    );
    MdocIssuerVerificationResult {
        signature_valid: issuer.signature_valid,
        issuer_trusted: issuer.issuer_trusted,
        certificate_trust_failures: issuer.certificate_trust_failures,
        document_types: issuer.document_types,
        document_evidence: issuer.document_evidence,
        revocation_checked: false,
        not_revoked: None,
        error: issuer.error,
    }
}

/// Authenticate issuer and holder proofs at the current time.
#[must_use]
pub fn verify_mdoc_presentation(
    mdoc_bytes: &[u8],
    session_transcript_cbor: &[u8],
    trusted_root_certs_pem: &[String],
    pinned_issuer_certs_pem: &[String],
) -> MdocPresentationVerificationResult {
    verify_mdoc_presentation_at(
        mdoc_bytes,
        session_transcript_cbor,
        trusted_root_certs_pem,
        pinned_issuer_certs_pem,
        OffsetDateTime::now_utc(),
    )
}

/// Authenticate issuer and holder proofs at an explicit verifier-owned time.
#[must_use]
pub fn verify_mdoc_presentation_at(
    mdoc_bytes: &[u8],
    session_transcript_cbor: &[u8],
    trusted_root_certs_pem: &[String],
    pinned_issuer_certs_pem: &[String],
    verification_time: OffsetDateTime,
) -> MdocPresentationVerificationResult {
    let issuer = verify_issuer_authentication(
        mdoc_bytes,
        trusted_root_certs_pem,
        pinned_issuer_certs_pem,
        verification_time,
    );
    let mut errors = issuer.error.into_iter().collect::<Vec<_>>();
    // Every holder proof is checked with the MSO returned by issuer
    // authentication for that document. A failed issuer signature cannot supply
    // an attacker-controlled replacement device key to the complete verifier.
    let mut device_authentication_valid = !issuer.authenticated_documents.is_empty()
        && issuer.authenticated_documents.len() == issuer.document_types.len();
    for authenticated in &issuer.authenticated_documents {
        if let Err(error) = verify_document_device_signature(
            &authenticated.document,
            &authenticated.mso,
            session_transcript_cbor,
        ) {
            device_authentication_valid = false;
            errors.push(format!("Holder device authentication failed: {error}"));
        }
    }

    MdocPresentationVerificationResult {
        issuer_signature_valid: issuer.signature_valid,
        issuer_trusted: issuer.issuer_trusted,
        certificate_trust_failures: issuer.certificate_trust_failures,
        device_authentication_valid,
        document_types: issuer.document_types,
        document_evidence: issuer.document_evidence,
        revocation_checked: false,
        not_revoked: None,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

/// Opaque authority for one exact MSO status reference. Only full issuer,
/// governed certificate trust and holder authentication can construct this.
/// This is not a revocation verdict or permission to fetch the reference URL.
pub struct AuthenticatedMdocStatusRequest {
    reference: MdocStatusReference,
    status_authority_certificate_der: Vec<u8>,
    document_index: usize,
    prepared_at: OffsetDateTime,
    valid_until: OffsetDateTime,
    presentation: std::sync::Arc<[u8]>,
    transcript: std::sync::Arc<[u8]>,
    roots: std::sync::Arc<[String]>,
    pins: std::sync::Arc<[String]>,
}

impl std::fmt::Debug for AuthenticatedMdocStatusRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedMdocStatusRequest")
            .finish_non_exhaustive()
    }
}

impl AuthenticatedMdocStatusRequest {
    #[must_use]
    pub fn reference(&self) -> &MdocStatusReference {
        &self.reference
    }

    /// Exact signed delegation, or the uniquely selected governed IACA.
    /// These public bytes alone are not a reusable authority capability.
    #[must_use]
    pub fn status_authority_certificate_der(&self) -> &[u8] {
        &self.status_authority_certificate_der
    }

    /// Bind downstream status to this exact presentation/document/reference and
    /// frozen authority inputs. Current governance authorization is additional.
    #[must_use]
    pub fn source_binding_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        fn part(hash: &mut Sha256, bytes: &[u8]) {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        let mut hash = Sha256::new();
        hash.update(b"marty:authenticated-mdoc-status-source:v1");
        part(&mut hash, &self.presentation);
        part(&mut hash, &self.transcript);
        part(&mut hash, &(self.document_index as u64).to_be_bytes());
        part(&mut hash, &self.status_authority_certificate_der);
        match &self.reference {
            MdocStatusReference::StatusList { uri, index, .. } => {
                part(&mut hash, b"status_list");
                part(&mut hash, uri.as_bytes());
                part(&mut hash, &index.to_be_bytes());
            }
            MdocStatusReference::IdentifierList {
                uri, identifier, ..
            } => {
                part(&mut hash, b"identifier_list");
                part(&mut hash, uri.as_bytes());
                part(&mut hash, identifier);
            }
        }
        part(&mut hash, &(self.roots.len() as u64).to_be_bytes());
        for root in self.roots.iter() {
            part(&mut hash, root.as_bytes());
        }
        part(&mut hash, &(self.pins.len() as u64).to_be_bytes());
        for pin in self.pins.iter() {
            part(&mut hash, pin.as_bytes());
        }
        hash.finalize().into()
    }

    #[must_use]
    pub fn document_index(&self) -> usize {
        self.document_index
    }

    #[must_use]
    pub fn valid_until(&self) -> OffsetDateTime {
        self.valid_until
    }

    /// Recheck the original complete presentation after awaited status work.
    /// The caller must also recheck token, signer-chain and CRL deadlines and
    /// obtain current owner/governance authorization. Frozen roots/pins do not
    /// detect subsequent owner removal or policy revision.
    pub fn revalidate_at(&self, now: OffsetDateTime) -> Result<(), String> {
        if now < self.prepared_at || now >= self.valid_until {
            return Err("mdoc status authority is outside its validity window".into());
        }
        let verified = verify_mdoc_presentation_at(
            &self.presentation,
            &self.transcript,
            &self.roots,
            &self.pins,
            now,
        );
        if !verified.issuer_signature_valid
            || !verified.issuer_trusted
            || !verified.device_authentication_valid
        {
            return Err("mdoc status authority no longer authenticates".into());
        }
        Ok(())
    }
}

/// Prepare references from the original fully authenticated presentation.
/// Public/JSON evidence cannot be promoted into this non-deserializable type.
/// No network I/O is performed, and no revocation verdict is manufactured.
pub fn prepare_mdoc_status_requests_at(
    presentation: &[u8],
    transcript: &[u8],
    roots: &[String],
    pins: &[String],
    now: OffsetDateTime,
) -> Result<Vec<AuthenticatedMdocStatusRequest>, String> {
    if presentation.len() > 2 * 1024 * 1024
        || transcript.len() > 64 * 1024
        || roots.len() > 32
        || pins.len() > 32
        || roots.iter().chain(pins).any(|pem| pem.len() > 128 * 1024)
    {
        return Err("mdoc status preparation exceeds resource limits".into());
    }
    // Bound certificate/profile work before cryptographic verification. This
    // preflight parses no authority; every admitted reference is authenticated
    // again below from the complete original response.
    let parsed: DeviceResponse = isomdl::cbor::from_slice(presentation)
        .map_err(|_| "Malformed mdoc status presentation".to_owned())?;
    let documents = parsed
        .documents
        .ok_or_else(|| "No mdoc documents".to_owned())?
        .into_inner();
    if documents.len() > 8 {
        return Err("Too many mdoc status documents".into());
    }
    for document in documents {
        let auth = &document.issuer_signed.issuer_auth;
        let chains: Vec<_> = auth
            .protected
            .header
            .rest
            .iter()
            .chain(auth.unprotected.rest.iter())
            .filter(|(label, _)| label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL))
            .collect();
        if chains.len() != 1 {
            return Err("mdoc issuer chain is ambiguous".into());
        }
        let chain = certificate_chain_der(&chains[0].1).map_err(str::to_owned)?;
        if chain.len() > 8 || chain.iter().any(|der| der.len() > 64 * 1024) {
            return Err("mdoc status issuer chain exceeds resource limits".into());
        }
    }
    let verified = verify_mdoc_presentation_at(presentation, transcript, roots, pins, now);
    if !verified.issuer_signature_valid
        || !verified.issuer_trusted
        || !verified.device_authentication_valid
    {
        return Err("mdoc status requires complete authenticated presentation".into());
    }
    let authenticated = verify_issuer_authentication(presentation, roots, pins, now);
    if !authenticated.signature_valid || !authenticated.issuer_trusted {
        return Err("mdoc status issuer authentication failed".into());
    }
    let presentation = std::sync::Arc::<[u8]>::from(presentation);
    let transcript = std::sync::Arc::<[u8]>::from(transcript);
    let roots_snapshot = std::sync::Arc::<[String]>::from(roots);
    let pins_snapshot = std::sync::Arc::<[String]>::from(pins);
    let mut requests = Vec::new();
    for (document_index, document) in authenticated.authenticated_documents.iter().enumerate() {
        let references = authenticated_status_references(&document.mso)?;
        if references.is_empty() {
            continue;
        }
        let auth = &document.document.issuer_signed.issuer_auth;
        let chains: Vec<_> = auth
            .protected
            .header
            .rest
            .iter()
            .chain(auth.unprotected.rest.iter())
            .filter(|(label, _)| label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL))
            .collect();
        if chains.len() != 1 {
            return Err("mdoc issuer chain is ambiguous".into());
        }
        let chain = certificate_chain_der(&chains[0].1).map_err(str::to_owned)?;
        let mut document_deadline = document.mso.validity_info.valid_until;
        for certificate in &chain {
            document_deadline = document_deadline.min(certificate_deadline(certificate, now)?);
        }
        let mut selected_iaca = None;
        for reference in references {
            let delegated = match &reference {
                MdocStatusReference::StatusList {
                    certificate_der, ..
                }
                | MdocStatusReference::IdentifierList {
                    certificate_der, ..
                } => certificate_der,
            };
            let authority = if let Some(certificate) = delegated {
                certificate.clone()
            } else {
                if selected_iaca.is_none() {
                    selected_iaca = Some(select_mdoc_iaca(&chain, roots, now)?);
                }
                selected_iaca.as_ref().expect("selected above").clone()
            };
            let valid_until = document_deadline.min(certificate_deadline(&authority, now)?);
            if now >= valid_until {
                return Err("mdoc status authority expired".into());
            }
            requests.push(AuthenticatedMdocStatusRequest {
                reference,
                status_authority_certificate_der: authority,
                document_index,
                prepared_at: now,
                valid_until,
                presentation: presentation.clone(),
                transcript: transcript.clone(),
                roots: roots_snapshot.clone(),
                pins: pins_snapshot.clone(),
            });
        }
    }
    Ok(requests)
}

fn certificate_deadline(der: &[u8], now: OffsetDateTime) -> Result<OffsetDateTime, String> {
    let certificate = x509_cert::Certificate::from_der(der)
        .map_err(|_| "Invalid mdoc status authority certificate".to_owned())?;
    let validity = certificate.tbs_certificate.validity;
    let from = OffsetDateTime::from_unix_timestamp(
        validity.not_before.to_unix_duration().as_secs() as i64,
    )
    .map_err(|_| "Invalid certificate validity".to_owned())?;
    let until =
        OffsetDateTime::from_unix_timestamp(validity.not_after.to_unix_duration().as_secs() as i64)
            .map_err(|_| "Invalid certificate validity".to_owned())?;
    if now < from || now >= until {
        return Err("mdoc status authority certificate is not current".into());
    }
    Ok(until)
}

fn select_mdoc_iaca(
    chain: &[Vec<u8>],
    roots: &[String],
    now: OffsetDateTime,
) -> Result<Vec<u8>, String> {
    let mut candidates = std::collections::BTreeSet::new();
    for pem in roots {
        let der = certificate_der_from_pem(pem)?;
        if !candidates.insert(der) {
            continue;
        }
    }
    let mut matched = Vec::new();
    for der in candidates {
        // A directly pinned DSC, even if also listed as a general trust anchor,
        // cannot silently acquire IACA status-list delegation authority.
        use const_oid::AssociatedOid;
        use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
        let certificate = x509_cert::Certificate::from_der(&der)
            .map_err(|_| "Invalid governed mdoc IACA".to_owned())?;
        let extensions = certificate
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or_default();
        let constraints: Vec<_> = extensions
            .iter()
            .filter(|ext| ext.extn_id == BasicConstraints::OID)
            .collect();
        let usages: Vec<_> = extensions
            .iter()
            .filter(|ext| ext.extn_id == KeyUsage::OID)
            .collect();
        if constraints.len() != 1 || usages.len() != 1 {
            continue;
        }
        let ca = BasicConstraints::from_der(constraints[0].extn_value.as_bytes())
            .map_err(|_| "Invalid governed mdoc IACA constraints".to_owned())?;
        let usage = KeyUsage::from_der(usages[0].extn_value.as_bytes())
            .map_err(|_| "Invalid governed mdoc IACA key usage".to_owned())?;
        if !ca.ca || !usage.0.contains(KeyUsages::KeyCertSign) {
            continue;
        }
        let mut validator = ChainValidator::with_config(certificate_validation_config(now)?);
        validator
            .add_trust_anchor_der(&der)
            .map_err(|_| "Invalid governed mdoc IACA".to_owned())?;
        // Include this exact configured candidate in constraint validation;
        // the generic validator's omitted-anchor fast path otherwise checks
        // only its subject/signature. Preserve every original chain byte.
        let mut completed_chain = chain.to_vec();
        if completed_chain.last() != Some(&der) {
            completed_chain.push(der.clone());
        }
        if validator
            .validate_chain_der(&completed_chain)
            .is_ok_and(|result| result.valid)
        {
            matched.push(der);
        }
    }
    if matched.len() != 1 {
        return Err("mdoc status requires one unambiguous governed IACA".into());
    }
    Ok(matched.remove(0))
}

/// Extract disclosed fields only after the caller has authenticated the mdoc.
pub fn disclosed_claims(mdoc_bytes: &[u8]) -> Result<serde_json::Value, String> {
    let response = parse_valid_device_response(mdoc_bytes)?;
    Ok(disclosed_claims_from_response(&response))
}

fn disclosed_claims_from_response(response: &crate::mdoc::DeviceResponse) -> serde_json::Value {
    let fields = response.get_disclosed_fields();
    let mut element_counts: HashMap<&str, usize> = HashMap::new();
    for field in &fields {
        *element_counts
            .entry(field.element_identifier.as_str())
            .or_default() += 1;
    }

    let mut claims = serde_json::Map::new();
    for field in &fields {
        if element_counts.get(field.element_identifier.as_str()) == Some(&1) {
            claims.insert(
                field.element_identifier.clone(),
                field.element_value.clone(),
            );
        }
    }
    let documents = response
        .documents
        .iter()
        .map(|document| {
            let namespaces = document
                .namespaces
                .iter()
                .map(|(namespace, items)| {
                    let elements = items
                        .iter()
                        .map(|item| (item.element_identifier.clone(), item.element_value.clone()))
                        .collect::<serde_json::Map<_, _>>();
                    (namespace.clone(), serde_json::Value::Object(elements))
                })
                .collect::<serde_json::Map<_, _>>();
            serde_json::json!({
                "doc_type": document.doc_type,
                "namespaces": namespaces,
            })
        })
        .collect::<Vec<_>>();
    claims.insert(
        "_mdoc".to_string(),
        serde_json::json!({"documents": documents}),
    );
    serde_json::Value::Object(claims)
}

/// Parse and validate the ISO-compatible DeviceResponse envelope.
pub fn parse_valid_device_response(
    mdoc_bytes: &[u8],
) -> Result<crate::mdoc::DeviceResponse, String> {
    let response = parse_device_response(mdoc_bytes)
        .map_err(|error| format!("Failed to parse mdoc DeviceResponse: {error}"))?;
    if response.version != "1.0" || response.status != 0 {
        return Err("mdoc DeviceResponse version or status is invalid".to_string());
    }
    if response.documents.is_empty() {
        return Err("mdoc DeviceResponse contains no documents".to_string());
    }
    Ok(response)
}

struct IssuerAuthenticationResult {
    signature_valid: bool,
    issuer_trusted: bool,
    certificate_trust_failures: Vec<MdocCertificateTrustFailure>,
    document_types: Vec<String>,
    document_evidence: Vec<MdocDocumentVerificationEvidence>,
    authenticated_documents: Vec<AuthenticatedDocument>,
    error: Option<String>,
}

struct AuthenticatedDocument {
    document: isomdl::definitions::device_response::Document,
    mso: Mso,
}

fn verify_issuer_authentication(
    mdoc_bytes: &[u8],
    trusted_root_certs_pem: &[String],
    pinned_issuer_certs_pem: &[String],
    verification_time: OffsetDateTime,
) -> IssuerAuthenticationResult {
    let response: DeviceResponse = match isomdl::cbor::from_slice(mdoc_bytes) {
        Ok(response) => response,
        Err(error) => {
            return issuer_failure(format!("Failed to parse mdoc DeviceResponse: {error}"));
        }
    };
    if response.version != DeviceResponse::VERSION || !matches!(response.status, Status::OK) {
        return issuer_failure("mdoc DeviceResponse version or status is invalid");
    }
    let Some(documents) = response.documents else {
        return issuer_failure("mdoc DeviceResponse contains no documents");
    };
    let document_types = documents
        .iter()
        .map(|document| document.doc_type.clone())
        .collect::<Vec<_>>();

    let validation_config = match certificate_validation_config(verification_time) {
        Ok(config) => config,
        Err(error) => return issuer_failure(error),
    };
    let mut root_validator = ChainValidator::with_config(validation_config);
    let mut trust_configuration_valid =
        !trusted_root_certs_pem.is_empty() || !pinned_issuer_certs_pem.is_empty();
    let mut errors = Vec::new();
    let mut certificate_trust_failures = Vec::new();
    if !trust_configuration_valid {
        certificate_trust_failures.push(MdocCertificateTrustFailure::MissingTrustAnchors);
        errors.push("No trusted issuer certificates were configured".to_string());
    }
    for trusted_cert in trusted_root_certs_pem {
        if let Err(error) = root_validator.add_trust_anchor_pem(trusted_cert) {
            trust_configuration_valid = false;
            errors.push(format!("Invalid mdoc root certificate: {error}"));
        }
    }
    let mut pinned_issuer_certs_der = Vec::with_capacity(pinned_issuer_certs_pem.len());
    for pinned_cert in pinned_issuer_certs_pem {
        match certificate_der_from_pem(pinned_cert) {
            Ok(certificate) => match x509_cert::Certificate::from_der(&certificate) {
                Ok(_) => pinned_issuer_certs_der.push(certificate),
                Err(error) => {
                    trust_configuration_valid = false;
                    errors.push(format!("Invalid pinned mdoc issuer certificate: {error}"));
                }
            },
            Err(error) => {
                trust_configuration_valid = false;
                errors.push(format!("Invalid pinned mdoc issuer certificate: {error}"));
            }
        }
    }

    if !trust_configuration_valid && certificate_trust_failures.is_empty() {
        certificate_trust_failures.push(MdocCertificateTrustFailure::InvalidTrustConfiguration);
    }

    let mut all_signatures_valid = true;
    let mut issuer_trusted = trust_configuration_valid;
    let mut document_evidence = Vec::with_capacity(documents.len());
    let mut authenticated_documents = Vec::with_capacity(documents.len());
    for document in documents.into_inner() {
        let issuer_auth = &document.issuer_signed.issuer_auth;
        let x5chain_value = issuer_auth
            .protected
            .header
            .rest
            .iter()
            .chain(issuer_auth.unprotected.rest.iter())
            .find_map(|(label, value)| {
                (label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL)).then_some(value)
            });
        let Some(x5chain_value) = x5chain_value else {
            all_signatures_valid = false;
            issuer_trusted = false;
            errors.push(format!(
                "No issuer certificate chain in issuerAuth for {}",
                document.doc_type
            ));
            continue;
        };
        let certificate_chain = match certificate_chain_der(x5chain_value) {
            Ok(chain) => chain,
            Err(error) => {
                all_signatures_valid = false;
                issuer_trusted = false;
                errors.push(format!(
                    "Invalid issuer certificate chain for {}: {error}",
                    document.doc_type
                ));
                continue;
            }
        };
        let x5chain = match X5Chain::from_cbor(x5chain_value.clone()) {
            Ok(chain) => chain,
            Err(error) => {
                all_signatures_valid = false;
                issuer_trusted = false;
                errors.push(format!(
                    "Invalid issuer x5chain for {}: {error}",
                    document.doc_type
                ));
                continue;
            }
        };
        let mso = match verify_issuer_mso(&x5chain, &document.issuer_signed) {
            Ok(mso) => mso,
            Err(error) => {
                all_signatures_valid = false;
                issuer_trusted = false;
                errors.push(format!(
                    "Signature verification failed for {}: {error}",
                    document.doc_type
                ));
                continue;
            }
        };
        if trust_configuration_valid {
            if let Err(error) = verify_issuer_trust(
                &certificate_chain,
                &root_validator,
                &pinned_issuer_certs_der,
                verification_time,
            ) {
                issuer_trusted = false;
                if !certificate_trust_failures
                    .contains(&MdocCertificateTrustFailure::CertificateChainRejected)
                {
                    certificate_trust_failures
                        .push(MdocCertificateTrustFailure::CertificateChainRejected);
                }
                errors.push(format!(
                    "Issuer certificate trust validation failed for {}: {error}",
                    document.doc_type
                ));
            }
        } else {
            issuer_trusted = false;
        }
        match authenticated_document_evidence(
            &document,
            &mso,
            &certificate_chain[0],
            verification_time,
        ) {
            Ok(evidence) => document_evidence.push(evidence),
            Err(error) => {
                all_signatures_valid = false;
                issuer_trusted = false;
                errors.push(format!(
                    "Authenticated MSO evidence is invalid for {}: {error}",
                    document.doc_type
                ));
            }
        }
        authenticated_documents.push(AuthenticatedDocument { document, mso });
    }

    IssuerAuthenticationResult {
        signature_valid: all_signatures_valid,
        issuer_trusted,
        certificate_trust_failures,
        document_types,
        document_evidence,
        authenticated_documents,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

fn authenticated_document_evidence(
    document: &isomdl::definitions::device_response::Document,
    authenticated_mso: &Mso,
    issuer_certificate_der: &[u8],
    verification_time: OffsetDateTime,
) -> Result<MdocDocumentVerificationEvidence, String> {
    let signature_algorithm = match document
        .issuer_signed
        .issuer_auth
        .protected
        .header
        .alg
        .as_ref()
    {
        Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256)) => "ES256",
        Some(_) => return Err("unsupported issuer signature algorithm".to_string()),
        None => return Err("issuer signature algorithm is not protected".to_string()),
    };
    validated_mso_evidence(
        authenticated_mso,
        &document.doc_type,
        signature_algorithm,
        issuer_certificate_der,
        verification_time,
    )
}

fn validated_mso_evidence(
    mso: &Mso,
    authenticated_document_type: &str,
    signature_algorithm: &str,
    issuer_certificate_der: &[u8],
    verification_time: OffsetDateTime,
) -> Result<MdocDocumentVerificationEvidence, String> {
    if mso.version != "1.0" {
        return Err(format!("unsupported MSO version {}", mso.version));
    }
    if mso.doc_type != authenticated_document_type {
        return Err("MSO document type does not match the authenticated document".to_string());
    }
    if mso.validity_info.signed > mso.validity_info.valid_from
        || mso.validity_info.valid_from > mso.validity_info.valid_until
    {
        return Err("MSO validity window is contradictory".to_string());
    }
    if verification_time < mso.validity_info.valid_from {
        return Err("MSO is not yet valid".to_string());
    }
    if verification_time > mso.validity_info.valid_until {
        return Err("MSO is expired".to_string());
    }

    let digest_algorithm = match mso.digest_algorithm {
        DigestAlgorithm::SHA256 => "SHA-256",
        DigestAlgorithm::SHA384 => "SHA-384",
        DigestAlgorithm::SHA512 => "SHA-512",
    };
    let format_time = |value: OffsetDateTime| {
        value
            .format(&Rfc3339)
            .map_err(|error| format!("unable to format MSO validity timestamp: {error}"))
    };
    let certificate_digest = marty_crypto::hashing::hash_sha256(issuer_certificate_der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    Ok(MdocDocumentVerificationEvidence {
        status_references: authenticated_status_references(mso)?,
        document_type: authenticated_document_type.to_string(),
        signature_algorithm: signature_algorithm.to_string(),
        digest_algorithm: digest_algorithm.to_string(),
        signed_at: format_time(mso.validity_info.signed)?,
        valid_from: format_time(mso.validity_info.valid_from)?,
        valid_until: format_time(mso.validity_info.valid_until)?,
        issuer_certificate_sha256: certificate_digest,
        validity_checked: true,
        valid_at_verification_time: true,
        revocation_checked: false,
        not_revoked: None,
    })
}

fn authenticated_status_references(mso: &Mso) -> Result<Vec<MdocStatusReference>, String> {
    let Some(status) = &mso.status else {
        return Ok(Vec::new());
    };
    // These are representation bounds, not authority or transport policy.
    fn uri(value: &str) -> Result<String, String> {
        if value.is_empty() || value.len() > 4096 {
            return Err("MSO status URI exceeds the representation bound".into());
        }
        Ok(value.into())
    }
    fn certificate(value: Option<&[u8]>) -> Result<Option<Vec<u8>>, String> {
        match value {
            Some(bytes) if bytes.is_empty() || bytes.len() > 65536 => {
                Err("MSO status certificate exceeds the representation bound".into())
            }
            value => Ok(value.map(<[u8]>::to_vec)),
        }
    }
    let mut references = Vec::new();
    if let Some(list) = &status.status_list {
        references.push(MdocStatusReference::StatusList {
            uri: uri(&list.uri)?,
            index: list.idx,
            certificate_der: certificate(list.certificate.as_ref().map(|v| v.as_ref()))?,
        });
    }
    if let Some(list) = &status.identifier_list {
        let identifier: &[u8] = list.id.as_ref();
        if identifier.is_empty() || identifier.len() > 1024 {
            return Err("MSO status identifier exceeds the representation bound".into());
        }
        references.push(MdocStatusReference::IdentifierList {
            uri: uri(&list.uri)?,
            identifier: identifier.to_vec(),
            certificate_der: certificate(list.certificate.as_ref().map(|v| v.as_ref()))?,
        });
    }
    Ok(references)
}

fn certificate_der_from_pem(pem: &str) -> Result<Vec<u8>, String> {
    let (label, der) = pem_rfc7468::decode_vec(pem.as_bytes())
        .map_err(|error| format!("invalid PEM encoding: {error}"))?;
    if label != "CERTIFICATE" {
        return Err(format!("expected CERTIFICATE PEM label, found {label}"));
    }
    if der.is_empty() {
        return Err("certificate DER is empty".to_string());
    }
    Ok(der)
}

fn certificate_validation_config(
    verification_time: OffsetDateTime,
) -> Result<ChainValidatorConfig, String> {
    ChainValidatorConfig::default()
        .with_validation_unix_nanos(verification_time.unix_timestamp_nanos())
        .map_err(|_| "Certificate verification time is out of platform range".to_string())
}

fn verify_issuer_trust(
    certificate_chain: &[Vec<u8>],
    root_validator: &ChainValidator,
    pinned_issuer_certs_der: &[Vec<u8>],
    verification_time: OffsetDateTime,
) -> Result<(), String> {
    let Some(leaf_certificate) = certificate_chain.first() else {
        return Err("issuer certificate chain is empty".to_string());
    };
    validate_document_signer_certificate_der(leaf_certificate)
        .map_err(|error| format!("invalid mdoc document-signer certificate profile: {error}"))?;

    if pinned_issuer_certs_der
        .iter()
        .any(|pinned| pinned == leaf_certificate)
    {
        let mut direct_pin_validator = ChainValidator::with_config(ChainValidatorConfig {
            required_key_usage: Vec::new(),
            ..certificate_validation_config(verification_time)?
        });
        direct_pin_validator
            .add_trust_anchor_der(
                certificate_chain
                    .last()
                    .expect("non-empty certificate chain checked above"),
            )
            .map_err(|error| format!("invalid direct-pin chain terminus: {error}"))?;
        return match direct_pin_validator.validate_chain_der(certificate_chain) {
            Ok(validation) if validation.valid => Ok(()),
            Ok(validation) => Err(format!(
                "directly pinned issuer certificate is invalid: {}",
                validation.errors.join("; ")
            )),
            Err(error) => Err(format!(
                "directly pinned issuer certificate validation failed: {error}"
            )),
        };
    }

    match root_validator.validate_chain_der(certificate_chain) {
        Ok(validation) if validation.valid => Ok(()),
        Ok(validation) => Err(format!(
            "certificate chain does not validate to a configured root: {}",
            validation.errors.join("; ")
        )),
        Err(error) => Err(format!("certificate chain validation failed: {error}")),
    }
}

fn issuer_failure(error: impl Into<String>) -> IssuerAuthenticationResult {
    IssuerAuthenticationResult {
        signature_valid: false,
        issuer_trusted: false,
        certificate_trust_failures: Vec::new(),
        document_types: Vec::new(),
        document_evidence: Vec::new(),
        authenticated_documents: Vec::new(),
        error: Some(error.into()),
    }
}

fn certificate_chain_der(value: &CoseValue) -> Result<Vec<Vec<u8>>, &'static str> {
    match value {
        CoseValue::Bytes(certificate) if !certificate.is_empty() => Ok(vec![certificate.clone()]),
        CoseValue::Array(certificates) if !certificates.is_empty() => certificates
            .iter()
            .map(|certificate| match certificate {
                CoseValue::Bytes(bytes) if !bytes.is_empty() => Ok(bytes.clone()),
                _ => Err("x5chain entries must be non-empty byte strings"),
            })
            .collect(),
        _ => Err("x5chain must be a byte string or non-empty array"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdoc::{DeviceResponse as ParsedDeviceResponse, Document, IssuerSignedItem};
    use base64::{engine::general_purpose, Engine as _};
    use isomdl::definitions::session::SessionTranscript;
    use serde_json::Value as JsonValue;

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(transparent)]
    struct FixtureTranscript(ciborium::Value);

    impl SessionTranscript for FixtureTranscript {}

    #[test]
    fn certificate_chain_accepts_single_or_multiple_der_certificates() {
        assert_eq!(
            certificate_chain_der(&CoseValue::Bytes(vec![1, 2, 3])),
            Ok(vec![vec![1, 2, 3]])
        );
        assert_eq!(
            certificate_chain_der(&CoseValue::Array(vec![
                CoseValue::Bytes(vec![1]),
                CoseValue::Bytes(vec![2]),
            ])),
            Ok(vec![vec![1], vec![2]])
        );
    }

    #[test]
    fn certificate_chain_rejects_empty_or_non_binary_values() {
        assert!(certificate_chain_der(&CoseValue::Bytes(vec![])).is_err());
        assert!(certificate_chain_der(&CoseValue::Array(vec![])).is_err());
        assert!(certificate_chain_der(&CoseValue::Array(vec![CoseValue::Null])).is_err());
    }

    fn mso_with_validity(valid_from: OffsetDateTime, valid_until: OffsetDateTime) -> Mso {
        use isomdl::definitions::device_key::cose_key::EC2Y;
        use isomdl::definitions::{DeviceKeyInfo, ValidityInfo};
        use std::collections::BTreeMap;

        Mso {
            version: "1.0".to_string(),
            digest_algorithm: DigestAlgorithm::SHA256,
            value_digests: BTreeMap::new(),
            device_key_info: DeviceKeyInfo {
                device_key: isomdl::definitions::device_key::CoseKey::EC2 {
                    crv: isomdl::definitions::device_key::EC2Curve::P256,
                    x: vec![1; 32],
                    y: EC2Y::Value(vec![2; 32]),
                },
                key_authorizations: None,
                key_info: None,
            },
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            validity_info: ValidityInfo {
                signed: valid_from - time::Duration::minutes(1),
                valid_from,
                valid_until,
                expected_update: None,
            },
            status: None,
        }
    }

    #[test]
    fn signed_status_and_identifier_references_are_projected_without_status_verdicts() {
        use isomdl::definitions::{IdentifierListInfo, StatusListInfo};
        let now = OffsetDateTime::parse("2026-08-09T12:00:00Z", &Rfc3339).unwrap();
        let mut mso = mso_with_validity(
            now - time::Duration::hours(1),
            now + time::Duration::hours(1),
        );
        mso.status = Some(isomdl::definitions::Status {
            status_list: Some(StatusListInfo {
                idx: 17,
                uri: "https://status.example/list".into(),
                certificate: Some(vec![1, 2, 3].into()),
            }),
            identifier_list: Some(IdentifierListInfo {
                id: vec![4, 5, 6].into(),
                uri: "https://status.example/identifiers".into(),
                certificate: None,
            }),
        });
        let evidence = validated_mso_evidence(&mso, &mso.doc_type, "ES256", b"cert", now).unwrap();
        assert_eq!(
            evidence.status_references,
            vec![
                MdocStatusReference::StatusList {
                    uri: "https://status.example/list".into(),
                    index: 17,
                    certificate_der: Some(vec![1, 2, 3])
                },
                MdocStatusReference::IdentifierList {
                    uri: "https://status.example/identifiers".into(),
                    identifier: vec![4, 5, 6],
                    certificate_der: None
                },
            ]
        );
        assert!(!evidence.revocation_checked);
        assert_eq!(evidence.not_revoked, None);
        let restored: MdocDocumentVerificationEvidence =
            serde_json::from_value(serde_json::to_value(&evidence).unwrap()).unwrap();
        assert_eq!(restored, evidence);
    }

    #[test]
    fn status_reference_projection_bounds_uri_identifier_and_certificate() {
        use isomdl::definitions::IdentifierListInfo;
        let now = OffsetDateTime::parse("2026-08-09T12:00:00Z", &Rfc3339).unwrap();
        let original = mso_with_validity(
            now - time::Duration::hours(1),
            now + time::Duration::hours(1),
        );
        for (uri, id, certificate) in [
            ("".into(), vec![1], None),
            ("x".repeat(4097), vec![1], None),
            ("https://status.example/list".into(), vec![], None),
            ("https://status.example/list".into(), vec![1; 1025], None),
            ("https://status.example/list".into(), vec![1], Some(vec![])),
            (
                "https://status.example/list".into(),
                vec![1],
                Some(vec![1; 65537]),
            ),
        ] {
            let mut mso = original.clone();
            mso.status = Some(isomdl::definitions::Status {
                status_list: None,
                identifier_list: Some(IdentifierListInfo {
                    uri,
                    id: id.into(),
                    certificate: certificate.map(Into::into),
                }),
            });
            assert!(validated_mso_evidence(&mso, &mso.doc_type, "ES256", b"cert", now).is_err());
        }
    }

    #[test]
    fn authenticated_mso_evidence_is_typed_without_inventing_revocation() {
        let now = OffsetDateTime::parse("2026-08-09T12:00:00Z", &Rfc3339).unwrap();
        let mso = mso_with_validity(
            now - time::Duration::hours(1),
            now + time::Duration::hours(1),
        );

        let evidence = validated_mso_evidence(
            &mso,
            "org.iso.18013.5.1.mDL",
            "ES256",
            b"issuer-certificate",
            now,
        )
        .unwrap();

        assert_eq!(evidence.document_type, "org.iso.18013.5.1.mDL");
        assert_eq!(evidence.signature_algorithm, "ES256");
        assert_eq!(evidence.digest_algorithm, "SHA-256");
        assert_eq!(evidence.signed_at, "2026-08-09T10:59:00Z");
        assert_eq!(evidence.valid_from, "2026-08-09T11:00:00Z");
        assert_eq!(evidence.valid_until, "2026-08-09T13:00:00Z");
        assert_eq!(evidence.issuer_certificate_sha256.len(), 64);
        assert!(evidence
            .issuer_certificate_sha256
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()));
        assert!(evidence.validity_checked);
        assert!(evidence.valid_at_verification_time);
        assert!(!evidence.revocation_checked);
        assert_eq!(evidence.not_revoked, None);
        assert!(evidence.status_references.is_empty());
        let value = serde_json::to_value(&evidence).unwrap();
        assert!(value.get("status_references").is_none());
        assert_eq!(
            serde_json::from_value::<MdocDocumentVerificationEvidence>(value).unwrap(),
            evidence
        );
    }

    #[test]
    fn authenticated_mso_evidence_rejects_type_and_validity_failures() {
        let now = OffsetDateTime::parse("2026-08-09T12:00:00Z", &Rfc3339).unwrap();
        let valid = mso_with_validity(
            now - time::Duration::hours(1),
            now + time::Duration::hours(1),
        );
        assert!(validated_mso_evidence(&valid, "wrong.type", "ES256", b"cert", now).is_err());

        let future = mso_with_validity(
            now + time::Duration::seconds(1),
            now + time::Duration::hours(1),
        );
        assert!(
            validated_mso_evidence(&future, "org.iso.18013.5.1.mDL", "ES256", b"cert", now,)
                .unwrap_err()
                .contains("not yet valid")
        );

        let expired = mso_with_validity(
            now - time::Duration::hours(1),
            now - time::Duration::seconds(1),
        );
        assert!(
            validated_mso_evidence(&expired, "org.iso.18013.5.1.mDL", "ES256", b"cert", now,)
                .unwrap_err()
                .contains("expired")
        );

        let mut contradictory = valid;
        contradictory.validity_info.signed =
            contradictory.validity_info.valid_from + time::Duration::seconds(1);
        assert!(validated_mso_evidence(
            &contradictory,
            "org.iso.18013.5.1.mDL",
            "ES256",
            b"cert",
            now,
        )
        .unwrap_err()
        .contains("validity window is contradictory"));
    }

    #[test]
    fn migrated_credentials_direct_pin_requires_a_certificate_pem_block() {
        let certificate = pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            b"public-certificate",
        )
        .unwrap();
        assert_eq!(
            certificate_der_from_pem(&certificate).unwrap(),
            b"public-certificate"
        );
        let public_key =
            pem_rfc7468::encode_string("PUBLIC KEY", pem_rfc7468::LineEnding::LF, b"public")
                .unwrap();
        assert!(certificate_der_from_pem(&public_key).is_err());
        assert!(certificate_der_from_pem("not pem").is_err());
    }

    #[test]
    fn migrated_credentials_mso_rejects_inverted_validity_window() {
        let now = OffsetDateTime::parse("2026-08-09T12:00:00Z", &Rfc3339).unwrap();
        let mso = mso_with_validity(
            now + time::Duration::hours(1),
            now - time::Duration::hours(1),
        );
        assert!(
            validated_mso_evidence(&mso, "org.iso.18013.5.1.mDL", "ES256", b"cert", now)
                .unwrap_err()
                .contains("validity window is contradictory")
        );
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped certificate signer"]
    fn direct_pin_requires_a_valid_mdoc_document_signer_profile() {
        use marty_crypto_test_support::remote_certificate::{
            RemoteCertificateAlgorithm, RemoteCertificateKey,
        };
        use rcgen::{CertificateParams, DnType, KeyUsagePurpose};

        fn certificate(
            name: &str,
            is_ca: rcgen::IsCa,
            key_usages: Vec<KeyUsagePurpose>,
        ) -> (Vec<u8>, String) {
            let key = RemoteCertificateKey::new(RemoteCertificateAlgorithm::Es256);
            let mut params = CertificateParams::default();
            params.distinguished_name.push(DnType::CommonName, name);
            params.is_ca = is_ca;
            params.key_usages = key_usages;
            let certificate = params.self_signed(&key).unwrap();
            (certificate.der().to_vec(), certificate.pem())
        }

        let (_, unrelated_root_pem) = certificate(
            "Unrelated mdoc root",
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        );
        let mut validator = crate::verification::ChainValidator::new();
        validator.add_trust_anchor_pem(&unrelated_root_pem).unwrap();
        let (valid_der, valid_pem) = certificate(
            "Pinned mdoc document signer",
            rcgen::IsCa::ExplicitNoCa,
            vec![KeyUsagePurpose::DigitalSignature],
        );
        let direct_pin = certificate_der_from_pem(&valid_pem).unwrap();
        let valid = verify_issuer_trust(
            std::slice::from_ref(&valid_der),
            &validator,
            &[direct_pin],
            OffsetDateTime::now_utc(),
        );
        assert!(
            valid.is_ok(),
            "valid document signer was rejected: {valid:?}"
        );

        let (ca_der, _) = certificate(
            "Pinned CA is not a document signer",
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        );
        let error = verify_issuer_trust(
            std::slice::from_ref(&ca_der),
            &validator,
            std::slice::from_ref(&ca_der),
            OffsetDateTime::now_utc(),
        )
        .unwrap_err();
        assert!(error.contains("must not be a CA"));

        let (issuer_usage_der, _) = certificate(
            "Pinned IACA usage is not a document signer",
            rcgen::IsCa::ExplicitNoCa,
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        );
        let error = verify_issuer_trust(
            std::slice::from_ref(&issuer_usage_der),
            &validator,
            std::slice::from_ref(&issuer_usage_der),
            OffsetDateTime::now_utc(),
        )
        .unwrap_err();
        assert!(error.contains("DigitalSignature only"));

        let (missing_usage_der, _) = certificate(
            "Pinned certificate without key usage",
            rcgen::IsCa::ExplicitNoCa,
            Vec::new(),
        );
        let error = verify_issuer_trust(
            std::slice::from_ref(&missing_usage_der),
            &validator,
            std::slice::from_ref(&missing_usage_der),
            OffsetDateTime::now_utc(),
        )
        .unwrap_err();
        assert!(error.contains("Required extension 2.5.29.15 missing"));

        let (incompatible_usage_der, _) = certificate(
            "Pinned certificate with mixed key usage",
            rcgen::IsCa::ExplicitNoCa,
            vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ],
        );
        let error = verify_issuer_trust(
            std::slice::from_ref(&incompatible_usage_der),
            &validator,
            std::slice::from_ref(&incompatible_usage_der),
            OffsetDateTime::now_utc(),
        )
        .unwrap_err();
        assert!(error.contains("DigitalSignature only"));

        assert!(verify_issuer_trust(
            std::slice::from_ref(&valid_der),
            &validator,
            &[vec![1, 2, 3]],
            OffsetDateTime::now_utc()
        )
        .is_err());
    }

    #[test]
    fn disclosed_claims_include_dtc_fields_and_structured_paths() {
        let response = ParsedDeviceResponse {
            version: "1.0".to_string(),
            documents: vec![Document {
                doc_type: "com.icao.dtc".to_string(),
                namespaces: HashMap::from([(
                    "com.icao.dtc".to_string(),
                    vec![IssuerSignedItem {
                        digest_id: 7,
                        random: vec![1],
                        element_identifier: "document_number".to_string(),
                        element_value: serde_json::json!("PMB09A5929"),
                    }],
                )]),
                mso: None,
                issuer_cert_chain: Vec::new(),
            }],
            status: 0,
        };

        assert_eq!(
            disclosed_claims_from_response(&response),
            serde_json::json!({
                "document_number": "PMB09A5929",
                "_mdoc": {
                    "documents": [{
                        "doc_type": "com.icao.dtc",
                        "namespaces": {
                            "com.icao.dtc": {
                                "document_number": "PMB09A5929"
                            }
                        }
                    }]
                }
            })
        );
    }

    #[test]
    fn disclosed_claims_omit_ambiguous_flat_keys() {
        let item = |value| IssuerSignedItem {
            digest_id: 0,
            random: Vec::new(),
            element_identifier: "document_number".to_string(),
            element_value: serde_json::json!(value),
        };
        let response = ParsedDeviceResponse {
            version: "1.0".to_string(),
            documents: vec![Document {
                doc_type: "example.document".to_string(),
                namespaces: HashMap::from([
                    ("example.one".to_string(), vec![item("one")]),
                    ("example.two".to_string(), vec![item("two")]),
                ]),
                mso: None,
                issuer_cert_chain: Vec::new(),
            }],
            status: 0,
        };

        let claims = disclosed_claims_from_response(&response);
        assert!(claims.get("document_number").is_none());
        assert_eq!(
            claims["_mdoc"]["documents"][0]["namespaces"]["example.one"]["document_number"],
            "one"
        );
        assert_eq!(
            claims["_mdoc"]["documents"][0]["namespaces"]["example.two"]["document_number"],
            "two"
        );
    }

    fn authenticated_presentation_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, String, JsonValue) {
        let contract: JsonValue = serde_json::from_str(include_str!(
            "../../../tests/vectors/mdoc_presentation_verification.json"
        ))
        .unwrap();
        let signed: JsonValue = serde_json::from_str(include_str!(
            "../../../tests/vectors/mdoc_presentation_signed_public.json"
        ))
        .unwrap();
        let decode = |field| {
            general_purpose::STANDARD
                .decode(signed[field].as_str().unwrap())
                .unwrap()
        };
        (
            decode("response_b64"),
            decode("transcript_b64"),
            decode("device_signature_b64"),
            signed["certificate_pem"].as_str().unwrap().to_owned(),
            contract,
        )
    }
    #[test]
    fn direct_pin_certificate_validity_uses_the_explicit_verifier_clock() {
        let (_, _, _, pem, _) = authenticated_presentation_fixture();
        let der = certificate_der_from_pem(&pem).unwrap();
        let certificate = x509_cert::Certificate::from_der(&der).unwrap();
        let validity = certificate.tbs_certificate.validity;
        let start = validity.not_before.to_unix_duration().as_secs() as i64;
        let end = validity.not_after.to_unix_duration().as_secs() as i64;
        let inside = OffsetDateTime::from_unix_timestamp(start + (end - start) / 2).unwrap();
        let outside = OffsetDateTime::from_unix_timestamp(end + 60).unwrap();
        let validator = ChainValidator::with_config(certificate_validation_config(inside).unwrap());
        assert!(verify_issuer_trust(
            std::slice::from_ref(&der),
            &validator,
            std::slice::from_ref(&der),
            inside
        )
        .is_ok());
        assert!(verify_issuer_trust(
            std::slice::from_ref(&der),
            &validator,
            std::slice::from_ref(&der),
            outside
        )
        .is_err());
        let before = OffsetDateTime::from_unix_timestamp(start - 60).unwrap();
        assert!(verify_issuer_trust(
            std::slice::from_ref(&der),
            &validator,
            std::slice::from_ref(&der),
            before
        )
        .is_err());
        assert_eq!(
            certificate_validation_config(inside)
                .unwrap()
                .validation_moment
                .unwrap()
                .timestamp(),
            inside.unix_timestamp()
        );
    }

    #[test]
    fn iaca_selection_checks_exact_completed_chain_and_deduplicates_governed_roots() {
        use der::Encode;
        let public: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/mdoc_status_authority_public_chain.json"
        ))
        .unwrap();
        let root = general_purpose::STANDARD
            .decode(public["root_der_base64"].as_str().unwrap())
            .unwrap();
        let leaf = general_purpose::STANDARD
            .decode(public["leaf_der_base64"].as_str().unwrap())
            .unwrap();
        let cert = x509_cert::Certificate::from_der(&leaf).unwrap();
        let start = cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs() as i64;
        let now = OffsetDateTime::from_unix_timestamp(start + 120).unwrap();
        let pem =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &root).unwrap();
        assert_eq!(
            select_mdoc_iaca(
                std::slice::from_ref(&leaf),
                &[pem.clone(), pem.clone()],
                now
            )
            .unwrap(),
            root
        );
        assert_eq!(
            select_mdoc_iaca(
                &[leaf.clone(), root.clone()],
                std::slice::from_ref(&pem),
                now
            )
            .unwrap(),
            root
        );
        let mut constrained = x509_cert::Certificate::from_der(&root).unwrap();
        constrained
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(x509_cert::ext::Extension {
                extn_id: const_oid::ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7"),
                critical: true,
                extn_value: der::asn1::OctetString::new(vec![0x05, 0x00]).unwrap(),
            });
        let constrained = constrained.to_der().unwrap();
        let mut legacy = ChainValidator::with_config(certificate_validation_config(now).unwrap());
        legacy.add_trust_anchor_der(&constrained).unwrap();
        assert!(
            legacy
                .validate_chain_der(std::slice::from_ref(&leaf))
                .unwrap()
                .valid,
            "test must expose the omitted-anchor constraint fast path"
        );
        let pem =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &constrained)
                .unwrap();
        assert!(
            select_mdoc_iaca(std::slice::from_ref(&leaf), std::slice::from_ref(&pem), now).is_err()
        );
        assert!(select_mdoc_iaca(&[leaf, constrained], &[pem], now).is_err());
    }

    #[test]
    fn status_preparation_requires_full_authentication_and_does_not_infer_iaca_from_dsc() {
        let (response, transcript, _, certificate, _) = authenticated_presentation_fixture();
        let now = OffsetDateTime::now_utc();
        let requests = prepare_mdoc_status_requests_at(
            &response,
            &transcript,
            &[],
            std::slice::from_ref(&certificate),
            now,
        )
        .unwrap();
        assert!(
            requests.is_empty(),
            "absence of a declared reference must remain not-applicable"
        );
        assert!(prepare_mdoc_status_requests_at(&response, &transcript, &[], &[], now).is_err());
        assert!(prepare_mdoc_status_requests_at(
            &response,
            b"wrong transcript",
            &[],
            std::slice::from_ref(&certificate),
            now
        )
        .is_err());
        let der = certificate_der_from_pem(&certificate).unwrap();
        assert!(select_mdoc_iaca(std::slice::from_ref(&der), &[], now).is_err());
        assert!(
            select_mdoc_iaca(
                std::slice::from_ref(&der),
                &[certificate.clone(), certificate],
                now
            )
            .is_err(),
            "a DSC repeated in governed roots is still not an IACA"
        );
        assert!(prepare_mdoc_status_requests_at(
            &vec![0; 2 * 1024 * 1024 + 1],
            &transcript,
            &[],
            &[],
            now
        )
        .is_err());
    }

    #[test]
    fn unsigned_mso_status_mutation_cannot_produce_authenticated_references() {
        use isomdl::definitions::{helpers::Tag24, StatusListInfo};
        let (response, transcript, _, certificate, _) = authenticated_presentation_fixture();
        let mut parsed: DeviceResponse = isomdl::cbor::from_slice(&response).unwrap();
        let mut documents = parsed.documents.take().unwrap().into_inner();
        let issuer_auth = &mut documents[0].issuer_signed.issuer_auth;
        let encoded_mso = issuer_auth.payload.as_ref().unwrap();
        let mut mso = isomdl::cbor::from_slice::<Tag24<Mso>>(encoded_mso)
            .unwrap()
            .into_inner();
        mso.status = Some(isomdl::definitions::Status {
            status_list: Some(StatusListInfo {
                idx: 0,
                uri: "https://attacker.example/list".into(),
                certificate: None,
            }),
            identifier_list: None,
        });
        issuer_auth.payload = Some(isomdl::cbor::to_vec(&Tag24::new(mso).unwrap()).unwrap());
        parsed.documents = Some(documents.try_into().unwrap());
        let tampered = isomdl::cbor::to_vec(&parsed).unwrap();
        let result = verify_mdoc_presentation(
            &tampered,
            &transcript,
            &[],
            std::slice::from_ref(&certificate),
        );
        assert!(!result.issuer_signature_valid);
        assert!(result.document_evidence.is_empty());
        assert!(!result.revocation_checked);
        assert_eq!(result.not_revoked, None);
        assert!(prepare_mdoc_status_requests_at(
            &tampered,
            &transcript,
            &[],
            &[certificate],
            OffsetDateTime::now_utc()
        )
        .is_err());
    }

    #[test]
    fn certificate_trust_diagnostics_preserve_old_json_defaults_and_trusted_shape() {
        let (response, transcript, _, certificate, _) = authenticated_presentation_fixture();
        let trusted = verify_mdoc_presentation(
            &response,
            &transcript,
            &[],
            std::slice::from_ref(&certificate),
        );
        assert!(trusted.issuer_trusted);
        let old_shape = serde_json::to_value(&trusted).unwrap();
        assert!(old_shape.get("certificate_trust_failures").is_none());
        assert_eq!(
            serde_json::from_value::<MdocPresentationVerificationResult>(old_shape).unwrap(),
            trusted,
        );
        let issuer = verify_mdoc_issuer(&response, &[], &[certificate]);
        assert!(issuer.issuer_trusted);
        let old_shape = serde_json::to_value(&issuer).unwrap();
        assert!(old_shape.get("certificate_trust_failures").is_none());
        assert_eq!(
            serde_json::from_value::<MdocIssuerVerificationResult>(old_shape).unwrap(),
            issuer,
        );
        // New readers accept old JSON; this does not promise old strict readers
        // accept the new nonempty diagnostic field on rejected credentials.
    }

    #[test]
    fn certificate_trust_diagnostics_preserve_real_signature_and_device_verdicts() {
        let (response, transcript, _, pinned_certificate, _) = authenticated_presentation_fixture();
        let trusted = verify_mdoc_presentation(
            &response,
            &transcript,
            &[],
            std::slice::from_ref(&pinned_certificate),
        );
        assert!(trusted.issuer_signature_valid);
        assert!(trusted.issuer_trusted);
        assert!(trusted.device_authentication_valid);
        assert!(trusted.certificate_trust_failures.is_empty());
        assert_eq!(trusted.document_evidence.len(), 1);

        // Public, independently signed NIST CA; no credential issuer private key.
        // This valid configured root cannot authenticate the fixture's DSC chain.
        let foreign_root = pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            include_bytes!(
                "../../../tests/cert_validator/fixtures/nist_pkits/certs/TrustAnchorRootCertificate.crt"
            ),
        )
        .unwrap();
        let untrusted = verify_mdoc_presentation(
            &response,
            &transcript,
            std::slice::from_ref(&foreign_root),
            &[],
        );
        assert!(untrusted.issuer_signature_valid);
        assert!(untrusted.device_authentication_valid);
        assert!(!untrusted.issuer_trusted);
        assert_eq!(
            untrusted.certificate_trust_failures,
            [MdocCertificateTrustFailure::CertificateChainRejected]
        );
        assert_eq!(untrusted.document_evidence, trusted.document_evidence);
        assert!(!untrusted.revocation_checked);
        assert_eq!(untrusted.not_revoked, None);
        assert_eq!(
            serde_json::to_value(&untrusted).unwrap()["certificate_trust_failures"],
            serde_json::json!(["CERTIFICATE_CHAIN_REJECTED"])
        );
        // Issuer-only and interactive verification share the same trust stage.
        let issuer = verify_mdoc_issuer(&response, &[foreign_root], &[]);
        assert!(issuer.signature_valid);
        assert_eq!(
            issuer.certificate_trust_failures,
            untrusted.certificate_trust_failures
        );

        let malformed =
            verify_mdoc_presentation(&response, &transcript, &["not a certificate".into()], &[]);
        assert!(malformed.issuer_signature_valid);
        assert!(malformed.device_authentication_valid);
        assert!(!malformed.issuer_trusted);
        assert_eq!(
            malformed.certificate_trust_failures,
            [MdocCertificateTrustFailure::InvalidTrustConfiguration]
        );
        let malformed_pin = pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            b"not a DER certificate",
        )
        .unwrap();
        let malformed_pin = verify_mdoc_presentation(&response, &transcript, &[], &[malformed_pin]);
        assert!(malformed_pin.issuer_signature_valid);
        assert!(!malformed_pin.issuer_trusted);
        assert_eq!(
            malformed_pin.certificate_trust_failures,
            [MdocCertificateTrustFailure::InvalidTrustConfiguration]
        );
        let missing = verify_mdoc_presentation(&response, &transcript, &[], &[]);
        assert_eq!(
            missing.certificate_trust_failures,
            [MdocCertificateTrustFailure::MissingTrustAnchors]
        );

        let mut corrupted: DeviceResponse = isomdl::cbor::from_slice(&response).unwrap();
        let mut documents = corrupted.documents.take().unwrap().into_inner();
        documents[0].issuer_signed.issuer_auth.signature[0] ^= 1;
        corrupted.documents = Some(documents.try_into().unwrap());
        let corrupted = isomdl::cbor::to_vec(&corrupted).unwrap();
        let invalid_signature =
            verify_mdoc_presentation(&corrupted, &transcript, &[], &[pinned_certificate]);
        assert!(!invalid_signature.issuer_signature_valid);
        assert!(!invalid_signature.issuer_trusted);
        assert!(invalid_signature.document_evidence.is_empty());
        // Signature failure is not reclassified as rejection of a foreign CA.
        assert!(invalid_signature.certificate_trust_failures.is_empty());
    }

    #[test]
    fn complete_presentation_authentication_matches_the_language_neutral_vector() {
        let (response, transcript, device_signature, pinned_certificate, contract) =
            authenticated_presentation_fixture();
        let result = verify_mdoc_presentation(
            &response,
            &transcript,
            &[],
            std::slice::from_ref(&pinned_certificate),
        );
        let expected = &contract["expected"];
        assert_eq!(
            result.issuer_signature_valid,
            expected["issuer_signature_valid"].as_bool().unwrap()
        );
        assert_eq!(
            result.issuer_trusted,
            expected["issuer_trusted"].as_bool().unwrap()
        );
        assert_eq!(
            result.device_authentication_valid,
            expected["device_authentication_valid"].as_bool().unwrap()
        );
        assert_eq!(
            result.document_types.len(),
            expected["document_count"].as_u64().unwrap() as usize
        );
        assert_eq!(result.document_evidence.len(), 1);
        assert!(!result.revocation_checked);
        assert_eq!(result.not_revoked, None);
        assert_eq!(result.error, None);
        let claims = disclosed_claims(&response).unwrap();
        assert_eq!(claims["family_name"], contract["claims"]["family_name"]);
        assert_eq!(claims["given_name"], contract["claims"]["given_name"]);

        let changed_transcript =
            isomdl::cbor::to_vec(&FixtureTranscript(ciborium::Value::Array(vec![
                ciborium::Value::Null,
                ciborium::Value::Null,
                ciborium::Value::Array(vec![
                    ciborium::Value::Text("OpenID4VPHandover".into()),
                    ciborium::Value::Bytes(vec![2_u8; 32]),
                ]),
            ])))
            .unwrap();
        let changed = verify_mdoc_presentation(
            &response,
            &changed_transcript,
            &[],
            std::slice::from_ref(&pinned_certificate),
        );
        assert!(!changed.device_authentication_valid);

        let signature_offset = response
            .windows(device_signature.len())
            .position(|window| window == device_signature)
            .expect("fixture must contain the device signature bytes");
        let mut changed_response = response.clone();
        changed_response[signature_offset] ^= 1;
        let changed = verify_mdoc_presentation(
            &changed_response,
            &transcript,
            &[],
            std::slice::from_ref(&pinned_certificate),
        );
        assert!(!changed.device_authentication_valid);

        let untrusted = verify_mdoc_presentation(&response, &transcript, &[], &[]);
        assert!(!untrusted.issuer_trusted);
    }

    #[test]
    fn complete_presentation_requires_an_authenticated_mso_for_every_holder_proof() {
        let (response, transcript, _, pinned_certificate, _) = authenticated_presentation_fixture();
        let mut parsed: DeviceResponse = isomdl::cbor::from_slice(&response).unwrap();
        let mut documents = parsed.documents.take().unwrap().into_inner();
        let mut unauthenticated = documents[0].clone();
        unauthenticated.issuer_signed.issuer_auth.signature[0] ^= 1;
        documents.push(unauthenticated);
        parsed.documents = Some(documents.try_into().unwrap());
        let response = isomdl::cbor::to_vec(&parsed).unwrap();

        // Both public holder signatures still match. The proof-only API does
        // not authenticate the issuer and cannot replace complete verification.
        assert!(
            crate::verify_device_authentication(&response, &transcript)
                .unwrap()
                .verified
        );
        let result = verify_mdoc_presentation(
            &response,
            &transcript,
            &[],
            std::slice::from_ref(&pinned_certificate),
        );
        assert!(!result.issuer_signature_valid);
        assert!(!result.device_authentication_valid);
        assert!(!result.issuer_trusted);
        assert_eq!(result.document_types.len(), 2);
        assert_eq!(result.document_evidence.len(), 1);
        assert!(!result.revocation_checked);
        assert_eq!(result.not_revoked, None);
    }

    #[test]
    fn authenticated_mso_holder_path_preserves_nonpreferred_transcript_encoding() {
        let (response, canonical, _, pinned_certificate, _) = authenticated_presentation_fixture();
        let mut parsed: DeviceResponse = isomdl::cbor::from_slice(&response).unwrap();
        let public_vectors: JsonValue = serde_json::from_str(include_str!(
            "../verification/fixtures/mdl_device_public_responses.json"
        ))
        .unwrap();
        let nonpreferred_response: DeviceResponse = isomdl::cbor::from_slice(
            &general_purpose::STANDARD
                .decode(
                    public_vectors["nonpreferred_response_cbor_base64"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        let mut documents = parsed.documents.take().unwrap().into_inner();
        documents[0].device_signed = nonpreferred_response
            .documents
            .unwrap()
            .into_inner()
            .remove(0)
            .device_signed;
        parsed.documents = Some(documents.try_into().unwrap());
        let response = isomdl::cbor::to_vec(&parsed).unwrap();
        let mut nonpreferred = canonical.clone();
        let null_offset = nonpreferred.iter().position(|byte| *byte == 0xf6).unwrap();
        nonpreferred.splice(null_offset..=null_offset, [0xf8, 0x16]);

        let exact = verify_mdoc_presentation(
            &response,
            &nonpreferred,
            &[],
            std::slice::from_ref(&pinned_certificate),
        );
        assert!(exact.issuer_signature_valid);
        assert!(exact.issuer_trusted);
        assert!(exact.device_authentication_valid);
        assert_eq!(exact.error, None);
        let reencoded = verify_mdoc_presentation(
            &response,
            &canonical,
            &[],
            std::slice::from_ref(&pinned_certificate),
        );
        assert!(reencoded.issuer_signature_valid);
        assert!(!reencoded.device_authentication_valid);
    }

    #[test]
    fn passive_presentation_verification_refuses_device_mac() {
        let (response, transcript, _, pinned_certificate, _) = authenticated_presentation_fixture();
        let mut parsed: DeviceResponse = isomdl::cbor::from_slice(&response).unwrap();
        let mut documents = parsed.documents.take().unwrap().into_inner();
        documents[0].device_signed.device_auth = isomdl::definitions::DeviceAuth::DeviceMac(
            isomdl::cose::MaybeTagged::new(false, coset::CoseMac0Builder::new().build()),
        );
        parsed.documents = Some(documents.try_into().unwrap());
        let response = isomdl::cbor::to_vec(&parsed).unwrap();

        assert!(crate::verify_device_authentication(&response, &transcript).is_err());
        let result = verify_mdoc_presentation(
            &response,
            &transcript,
            &[],
            std::slice::from_ref(&pinned_certificate),
        );
        assert!(result.issuer_signature_valid);
        assert!(result.issuer_trusted);
        assert!(!result.device_authentication_valid);
        assert!(!result.revocation_checked);
        assert_eq!(result.not_revoked, None);
    }

    #[test]
    fn malformed_presentations_fail_closed_without_panicking() {
        let result = verify_mdoc_presentation(&[0xff], &[0x83, 0xf6, 0xf6, 0x82, 0x71], &[], &[]);
        assert!(!result.issuer_signature_valid);
        assert!(!result.issuer_trusted);
        assert!(!result.device_authentication_valid);
        assert!(result.document_evidence.is_empty());
        assert!(!result.revocation_checked);
        assert_eq!(result.not_revoked, None);
        assert!(result.error.is_some());
    }

    #[test]
    fn disclosed_claims_preserve_paths_and_omit_ambiguous_flat_keys() {
        let item = |namespace: &str, value: &str| IssuerSignedItem {
            digest_id: 0,
            random: Vec::new(),
            element_identifier: "document_number".to_string(),
            element_value: serde_json::json!(format!("{namespace}:{value}")),
        };
        let response = ParsedDeviceResponse {
            version: "1.0".to_string(),
            documents: vec![Document {
                doc_type: "com.icao.dtc".to_string(),
                namespaces: HashMap::from([
                    ("example.one".to_string(), vec![item("one", "1")]),
                    ("example.two".to_string(), vec![item("two", "2")]),
                ]),
                mso: None,
                issuer_cert_chain: Vec::new(),
            }],
            status: 0,
        };
        let fields = response.get_disclosed_fields();
        assert_eq!(fields.len(), 2);
        let mut counts = HashMap::new();
        for field in fields {
            *counts.entry(field.element_identifier).or_insert(0) += 1;
        }
        assert_eq!(counts["document_number"], 2);
    }

    #[test]
    fn certificate_chain_shape_is_bounded_to_binary_entries() {
        assert_eq!(
            certificate_chain_der(&CoseValue::Bytes(vec![1, 2, 3])),
            Ok(vec![vec![1, 2, 3]])
        );
        assert!(certificate_chain_der(&CoseValue::Array(vec![])).is_err());
        assert!(certificate_chain_der(&CoseValue::Array(vec![CoseValue::Null])).is_err());
    }
}
