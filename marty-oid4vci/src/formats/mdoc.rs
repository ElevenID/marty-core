//! ISO 18013-5 mDoc credential format (`mso_mdoc`).
//!
//! Constructs CBOR-encoded mDoc credentials with COSE_Sign1 issuer
//! authentication, replacing the previous JSON placeholder implementation.
//!
//! Structure: IssuerSigned { nameSpaces, issuerAuth(COSE_Sign1(MSO)) }

use std::collections::BTreeMap;

use ciborium::Value as CborValue;
use coset::{
    cbor::value::Value as CosetValue, iana, CborSerializable, CoseSign1Builder, HeaderBuilder,
};
use isomdl::{
    definitions::DigestAlgorithm,
    digest_executor::{DigestExecutor, DigestJob, DigestResult, SerialDigestExecutor},
};
use rand::Rng;
#[cfg(test)]
use sha2::{Digest, Sha256};

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::signer::CredentialSigner;
use crate::types::{CredentialClaims, IssuerKey, SignedCredential};

// ── CBOR tag number for `encoded-cbor` (tag 24, RFC 8949 §3.4.5.1) ──
// Used for tagged CBOR byte strings inside IssuerSignedItem and issuerAuth.
const CBOR_TAG_ENCODED_CBOR: u64 = 24;
// RFC 8943 full-date (YYYY-MM-DD), used by ISO 18013-5 date elements.
const CBOR_TAG_FULL_DATE: u64 = 1004;
const COSE_HEADER_X5CHAIN_LABEL: i64 = 33;
const MDOC_X5C_CLAIM_KEY: &str = "_mdoc_x5c";
const SINGLE_MDOC_DIGEST_CREDENTIAL_ID: u64 = 0;
const SHA256_DIGEST_LENGTH: usize = 32;
const MDOC_DIGEST_EXECUTION_FAILED: &str = "mdoc digest execution failed";

/// Sign an mDoc credential.
///
/// Produces a CBOR-encoded `IssuerSigned` structure containing:
///   - `nameSpaces`: `IssuerSignedItem` entries per namespace
///   - `issuerAuth`: COSE_Sign1(MobileSecurityObject)
///
/// The resulting credential is base64url-encoded for transport.
pub fn sign_mdoc(
    issuer_key: &IssuerKey,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    let jwk: ssi_jwk::JWK = serde_json::from_str(&issuer_key.jwk_json)
        .map_err(|e| Oid4vciError::KeyError(format!("Invalid issuer JWK: {}", e)))?;

    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();

    // Determine docType and namespace
    let doc_type = claims
        .mdoc_doctype
        .as_deref()
        .unwrap_or("org.iso.18013.5.1.mDL");
    let namespace = claims
        .mdoc_namespace
        .as_deref()
        .unwrap_or("org.iso.18013.5.1");
    let x5chain_der = extract_mdoc_x5chain_from_claims(claims)?;

    // 1. Plan and execute IssuerSignedItem digests through the same serial
    // boundary used by split/BYOK signing.
    let issuer_claims = claims
        .claims
        .iter()
        .filter(|(claim_name, _)| claim_name.as_str() != MDOC_X5C_CLAIM_KEY)
        .map(|(claim_name, claim_value)| (claim_name.as_str(), claim_value));
    let digest_plan = plan_mdoc_digests(issuer_claims, || rand::thread_rng().gen())?;
    let digest_results = execute_mdoc_digest_plan(&digest_plan, &SerialDigestExecutor)?;
    let MdocDigestAssembly {
        issuer_signed_items,
        value_digests,
    } = assemble_mdoc_digest_plan(digest_plan, digest_results)?;

    // 2. Build the MobileSecurityObject
    let validity_days = claims.expiration_seconds.map(|s| s / 86400).unwrap_or(365);
    let valid_until = now + chrono::Duration::days(validity_days);

    let mso = build_mobile_security_object(
        doc_type,
        namespace,
        &value_digests,
        &now,
        &valid_until,
        None,
    )?;

    let mobile_security_object_bytes = encode_mobile_security_object_bytes(&mso)?;

    // 3. Sign MobileSecurityObjectBytes with COSE_Sign1.
    let issuer_auth = sign_cose_sign1(
        &mobile_security_object_bytes,
        &jwk,
        issuer_key,
        &x5chain_der,
    )?;

    // 4. Assemble IssuerSigned = { nameSpaces, issuerAuth }
    // issuerAuth must be the COSE_Sign1 CBOR structure (array), NOT a byte
    // string wrapping the serialized structure.  ISO 18013-5 §9.1.2.4 defines
    // IssuerAuth = COSE_Sign1 which is a CBOR array [protected, unprotected,
    // payload, signature].  Wallet implementations (e.g. Walt.id) expect the
    // array directly in the IssuerSigned map.
    let issuer_auth_cbor: CborValue = ciborium::from_reader(&issuer_auth[..])
        .map_err(|e| Oid4vciError::MdocError(format!("Failed to parse issuer_auth CBOR: {e}")))?;

    let name_spaces = CborValue::Map(vec![(
        CborValue::Text(namespace.to_string()),
        CborValue::Array(issuer_signed_items),
    )]);

    let issuer_signed = CborValue::Map(vec![
        (CborValue::Text("nameSpaces".into()), name_spaces),
        (CborValue::Text("issuerAuth".into()), issuer_auth_cbor),
    ]);

    let result_bytes = cbor_encode(&issuer_signed)?;
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &result_bytes,
    );

    Ok(SignedCredential::MsoMdoc {
        issuer_signed_b64: encoded,
        credential_id,
    })
}

/// Sign an mDoc credential using any [`CredentialSigner`].
///
/// This is the BYOK-aware variant. For local JWK signing, pass an `&IssuerKey`.
/// For remote/KMS signing, pass a custom `CredentialSigner` implementation.
pub fn sign_mdoc_with_signer(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    let prepared = prepare_mdoc(signer, claims)?;
    let signature = signer.sign(&prepared.tbs_data)?;
    assemble_mdoc(prepared, &signature)
}

/// Intermediate state between mDoc preparation and signing.
///
/// Returned by [`prepare_mdoc()`] — the caller signs `tbs_data` and
/// passes the result to [`assemble_mdoc()`].
pub struct PreparedMdoc {
    /// The COSE_Sign1 to-be-signed bytes.
    pub tbs_data: Vec<u8>,
    /// The credential ID (urn:uuid:...) assigned during preparation.
    pub credential_id: String,
    /// Serialized COSE protected header.
    protected_header: coset::Header,
    /// Serialized COSE unprotected header. ISO 18013-5 requires the issuer
    /// certificate chain here while keeping the signing algorithm protected.
    unprotected_header: coset::Header,
    /// Tag 24-wrapped MobileSecurityObjectBytes payload (for assembly).
    mobile_security_object_bytes: Vec<u8>,
    /// Namespace and IssuerSignedItems for assembly.
    namespace: String,
    /// The tagged CBOR IssuerSignedItem entries.
    issuer_signed_items: Vec<CborValue>,
}

#[derive(Clone)]
struct MdocDigestPlanEntry {
    credential_id: u64,
    job_id: u64,
    ordinal: usize,
    digest_id: u64,
    issuer_signed_item_bytes: CborValue,
}

#[derive(Clone)]
struct MdocDigestPlan {
    entries: Vec<MdocDigestPlanEntry>,
    jobs: Vec<DigestJob>,
}

struct MdocDigestAssembly {
    issuer_signed_items: Vec<CborValue>,
    value_digests: Vec<(u64, Vec<u8>)>,
}

/// Prepare an mDoc credential for signing.
///
/// Builds the MSO and COSE_Sign1 structure, returning a [`PreparedMdoc`]
/// whose `tbs_data` field must be signed externally.
pub fn prepare_mdoc(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<PreparedMdoc> {
    prepare_mdoc_with_credential_id(signer, claims, None)
}

/// Prepare an mDoc while preserving an issuer-reserved credential identifier.
///
/// Issuance services reserve a deterministic identifier before remote signing
/// so retries cannot mint a second credential. The identifier is deliberately
/// not supplied by a wallet-facing request.
pub fn prepare_mdoc_with_credential_id(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
    reserved_credential_id: Option<&str>,
) -> Oid4vciResult<PreparedMdoc> {
    prepare_mdoc_with_credential_id_and_device_key(signer, claims, reserved_credential_id, None)
}

/// Prepare an mDoc bound to the holder public key proven during OID4VCI.
///
/// The public JWK is encoded as the MSO `deviceKeyInfo.deviceKey` COSE_Key.
/// It is used later to verify holder DeviceAuthentication; it is not an
/// issuer signing key and no holder private key is accepted or retained.
pub fn prepare_mdoc_with_credential_id_and_device_key(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
    reserved_credential_id: Option<&str>,
    holder_public_jwk: Option<&serde_json::Value>,
) -> Oid4vciResult<PreparedMdoc> {
    let credential_id = match reserved_credential_id {
        Some(value) => {
            let uuid_value = value.strip_prefix("urn:uuid:").ok_or_else(|| {
                Oid4vciError::MdocError(
                    "reserved credential ID must use the urn:uuid scheme".into(),
                )
            })?;
            uuid::Uuid::parse_str(uuid_value).map_err(|_| {
                Oid4vciError::MdocError("reserved credential ID contains an invalid UUID".into())
            })?;
            value.to_owned()
        }
        None => format!("urn:uuid:{}", uuid::Uuid::new_v4()),
    };
    let now = chrono::Utc::now();
    let issuer_claims = claims
        .claims
        .iter()
        .filter(|(claim_name, _)| claim_name.as_str() != MDOC_X5C_CLAIM_KEY)
        .map(|(claim_name, claim_value)| (claim_name.as_str(), claim_value));

    prepare_mdoc_with_inputs(
        signer,
        claims,
        credential_id,
        holder_public_jwk,
        now,
        issuer_claims,
        || rand::thread_rng().gen(),
    )
}

/// Prepare an mdoc from an already ordered claim plan and a caller-owned salt
/// source. Production supplies its existing `HashMap` iteration order, current
/// time, random salts, and credential ID; tests can replay the exact same path
/// with immutable inputs.
fn prepare_mdoc_with_inputs<'a>(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
    credential_id: String,
    holder_public_jwk: Option<&serde_json::Value>,
    now: chrono::DateTime<chrono::Utc>,
    issuer_claims: impl IntoIterator<Item = (&'a str, &'a serde_json::Value)>,
    next_salt: impl FnMut() -> [u8; 32],
) -> Oid4vciResult<PreparedMdoc> {
    prepare_mdoc_with_inputs_and_digest_executor(
        signer,
        claims,
        credential_id,
        holder_public_jwk,
        now,
        issuer_claims,
        next_salt,
        &SerialDigestExecutor,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_mdoc_with_inputs_and_digest_executor<'a>(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
    credential_id: String,
    holder_public_jwk: Option<&serde_json::Value>,
    now: chrono::DateTime<chrono::Utc>,
    issuer_claims: impl IntoIterator<Item = (&'a str, &'a serde_json::Value)>,
    next_salt: impl FnMut() -> [u8; 32],
    digest_executor: &dyn DigestExecutor,
) -> Oid4vciResult<PreparedMdoc> {
    let doc_type = claims
        .mdoc_doctype
        .as_deref()
        .unwrap_or("org.iso.18013.5.1.mDL");
    let namespace = claims
        .mdoc_namespace
        .as_deref()
        .unwrap_or("org.iso.18013.5.1");
    let x5chain_der = extract_mdoc_x5chain_from_claims(claims)?;

    // Allocate salts and encode every IssuerSignedItem on the caller before
    // crossing the digest boundary. Executors receive only identified bytes to
    // hash and never receive a signer or signing key.
    let digest_plan = plan_mdoc_digests(issuer_claims, next_salt)?;
    let digest_results = execute_mdoc_digest_plan(&digest_plan, digest_executor)?;
    let digest_assembly = assemble_mdoc_digest_plan(digest_plan, digest_results)?;

    // Build MSO
    let validity_days = claims.expiration_seconds.map(|s| s / 86400).unwrap_or(365);
    let valid_until = now + chrono::Duration::days(validity_days);
    let device_key = holder_public_jwk.map(jwk_to_cose_device_key).transpose()?;
    let mso = build_mobile_security_object(
        doc_type,
        namespace,
        &digest_assembly.value_digests,
        &now,
        &valid_until,
        device_key,
    )?;
    let mobile_security_object_bytes = encode_mobile_security_object_bytes(&mso)?;

    // Build COSE_Sign1 protected header
    let alg = match signer.algorithm() {
        crate::types::SigningAlgorithm::ES256 => iana::Algorithm::ES256,
        crate::types::SigningAlgorithm::EdDSA => iana::Algorithm::EdDSA,
        crate::types::SigningAlgorithm::ES256K => {
            return Err(Oid4vciError::MdocError(
                "ES256K is not supported for mDoc COSE signing".into(),
            ));
        }
        crate::types::SigningAlgorithm::ES384 => iana::Algorithm::ES384,
        crate::types::SigningAlgorithm::RS256 => iana::Algorithm::PS256,
    };

    let protected = build_protected_header(alg);
    let unprotected = build_unprotected_header(&x5chain_der);

    // Compute TBS data
    let cose_for_tbs = CoseSign1Builder::new()
        .protected(protected.clone())
        .unprotected(unprotected.clone())
        .payload(mobile_security_object_bytes.clone())
        .build();
    let tbs = cose_for_tbs.tbs_data(&[]);

    Ok(PreparedMdoc {
        tbs_data: tbs,
        credential_id,
        protected_header: protected,
        unprotected_header: unprotected,
        mobile_security_object_bytes,
        namespace: namespace.to_string(),
        issuer_signed_items: digest_assembly.issuer_signed_items,
    })
}

/// Assemble a signed mDoc from the prepared data and a raw COSE signature.
pub fn assemble_mdoc(prepared: PreparedMdoc, signature: &[u8]) -> Oid4vciResult<SignedCredential> {
    let cose_sign1 = CoseSign1Builder::new()
        .protected(prepared.protected_header)
        .unprotected(prepared.unprotected_header)
        .payload(prepared.mobile_security_object_bytes)
        .signature(signature.to_vec())
        .build();

    let issuer_auth = cose_sign1
        .to_vec()
        .map_err(|e| Oid4vciError::MdocError(format!("COSE serialization failed: {:?}", e)))?;

    // Deserialize COSE_Sign1 bytes back to a CborValue so issuerAuth is
    // embedded as the COSE_Sign1 array structure, not as a byte string.
    let issuer_auth_cbor: CborValue = ciborium::from_reader(&issuer_auth[..])
        .map_err(|e| Oid4vciError::MdocError(format!("Failed to parse issuer_auth CBOR: {e}")))?;

    let name_spaces = CborValue::Map(vec![(
        CborValue::Text(prepared.namespace),
        CborValue::Array(prepared.issuer_signed_items),
    )]);

    let issuer_signed = CborValue::Map(vec![
        (CborValue::Text("nameSpaces".into()), name_spaces),
        (CborValue::Text("issuerAuth".into()), issuer_auth_cbor),
    ]);

    let result_bytes = cbor_encode(&issuer_signed)?;
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &result_bytes,
    );

    Ok(SignedCredential::MsoMdoc {
        issuer_signed_b64: encoded,
        credential_id: prepared.credential_id,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────

/// Build a single `IssuerSignedItem` (CBOR map) per ISO 18013-5 §9.1.2.4.
///
/// ```text
/// IssuerSignedItem = {
///   "digestID"     : uint,
///   "random"       : bstr,
///   "elementIdentifier" : tstr,
///   "elementValue" : any,
/// }
/// ```
fn build_issuer_signed_item(
    digest_id: u64,
    salt: &[u8],
    element_identifier: &str,
    element_value: &serde_json::Value,
) -> Oid4vciResult<CborValue> {
    let cbor_value = json_to_cbor(element_value)?;

    Ok(CborValue::Map(vec![
        (
            CborValue::Text("digestID".into()),
            CborValue::Integer(digest_id.into()),
        ),
        (
            CborValue::Text("random".into()),
            CborValue::Bytes(salt.to_vec()),
        ),
        (
            CborValue::Text("elementIdentifier".into()),
            CborValue::Text(element_identifier.into()),
        ),
        (CborValue::Text("elementValue".into()), cbor_value),
    ]))
}

/// Test-only scalar oracle for the former inline item commitment path.
///
/// Production deliberately separates encoding from digest execution. This
/// helper retains the old construction-and-hash operation so regression tests
/// can prove that the serial plan commits the identical tag 24 wrapper bytes.
#[cfg(test)]
fn build_issuer_signed_item_bytes(
    digest_id: u64,
    random: &[u8],
    element_identifier: &str,
    element_value: &serde_json::Value,
) -> Oid4vciResult<(CborValue, Vec<u8>)> {
    let (issuer_signed_item_bytes, encoded_issuer_signed_item_bytes) =
        encode_issuer_signed_item_bytes(digest_id, random, element_identifier, element_value)?;
    let digest = Sha256::digest(encoded_issuer_signed_item_bytes).to_vec();
    Ok((issuer_signed_item_bytes, digest))
}

fn encode_issuer_signed_item_bytes(
    digest_id: u64,
    random: &[u8],
    element_identifier: &str,
    element_value: &serde_json::Value,
) -> Oid4vciResult<(CborValue, Vec<u8>)> {
    let item = build_issuer_signed_item(digest_id, random, element_identifier, element_value)?;
    let encoded_item = cbor_encode(&item)?;
    let issuer_signed_item_bytes = CborValue::Tag(
        CBOR_TAG_ENCODED_CBOR,
        Box::new(CborValue::Bytes(encoded_item.clone())),
    );
    let encoded_issuer_signed_item_bytes = cbor_encode(&issuer_signed_item_bytes)?;
    Ok((issuer_signed_item_bytes, encoded_issuer_signed_item_bytes))
}

fn plan_mdoc_digests<'a>(
    issuer_claims: impl IntoIterator<Item = (&'a str, &'a serde_json::Value)>,
    mut next_salt: impl FnMut() -> [u8; 32],
) -> Oid4vciResult<MdocDigestPlan> {
    let mut entries = Vec::new();
    let mut jobs = Vec::new();

    for (ordinal, (claim_name, claim_value)) in issuer_claims.into_iter().enumerate() {
        let digest_id = u64::try_from(ordinal).map_err(|_| mdoc_digest_execution_error())?;
        let salt = next_salt();
        let (issuer_signed_item_bytes, digest_input) =
            encode_issuer_signed_item_bytes(digest_id, &salt, claim_name, claim_value)?;
        entries.push(MdocDigestPlanEntry {
            credential_id: SINGLE_MDOC_DIGEST_CREDENTIAL_ID,
            job_id: digest_id,
            ordinal,
            digest_id,
            issuer_signed_item_bytes,
        });
        jobs.push(DigestJob {
            credential_id: SINGLE_MDOC_DIGEST_CREDENTIAL_ID,
            job_id: digest_id,
            ordinal,
            algorithm: DigestAlgorithm::SHA256,
            input: digest_input,
        });
    }

    Ok(MdocDigestPlan { entries, jobs })
}

fn execute_mdoc_digest_plan(
    plan: &MdocDigestPlan,
    digest_executor: &dyn DigestExecutor,
) -> Oid4vciResult<Vec<DigestResult>> {
    digest_executor
        .execute(&plan.jobs)
        .map_err(|_| mdoc_digest_execution_error())
}

fn assemble_mdoc_digest_plan(
    plan: MdocDigestPlan,
    results: Vec<DigestResult>,
) -> Oid4vciResult<MdocDigestAssembly> {
    if results.len() != plan.entries.len() {
        return Err(mdoc_digest_execution_error());
    }

    let mut results_by_identity = BTreeMap::new();
    for result in results {
        if result.digest.len() != SHA256_DIGEST_LENGTH
            || results_by_identity
                .insert((result.credential_id, result.job_id), result)
                .is_some()
        {
            return Err(mdoc_digest_execution_error());
        }
    }

    let mut issuer_signed_items = Vec::with_capacity(plan.entries.len());
    let mut value_digests = Vec::with_capacity(plan.entries.len());
    for entry in plan.entries {
        let result = results_by_identity
            .remove(&(entry.credential_id, entry.job_id))
            .ok_or_else(mdoc_digest_execution_error)?;
        if result.ordinal != entry.ordinal {
            return Err(mdoc_digest_execution_error());
        }
        issuer_signed_items.push(entry.issuer_signed_item_bytes);
        value_digests.push((entry.digest_id, result.digest));
    }

    if !results_by_identity.is_empty() {
        return Err(mdoc_digest_execution_error());
    }

    Ok(MdocDigestAssembly {
        issuer_signed_items,
        value_digests,
    })
}

fn mdoc_digest_execution_error() -> Oid4vciError {
    Oid4vciError::MdocError(MDOC_DIGEST_EXECUTION_FAILED.into())
}

/// Build MobileSecurityObject (MSO) per ISO 18013-5 §9.1.2.4.
///
/// ```text
/// MobileSecurityObject = {
///   "version"         : tstr,
///   "digestAlgorithm" : tstr,
///   "valueDigests"    : { tstr => { uint => bstr } },
///   "docType"         : tstr,
///   "validityInfo"    : ValidityInfo,
/// }
/// ```
fn build_mobile_security_object(
    doc_type: &str,
    namespace: &str,
    value_digests: &[(u64, Vec<u8>)],
    signed_at: &chrono::DateTime<chrono::Utc>,
    valid_until: &chrono::DateTime<chrono::Utc>,
    device_key: Option<CborValue>,
) -> Oid4vciResult<CborValue> {
    // Build the per-namespace digest map: { digestID => digest_bytes }
    let ns_digests = CborValue::Map(
        value_digests
            .iter()
            .map(|(id, digest)| {
                (
                    CborValue::Integer((*id).into()),
                    CborValue::Bytes(digest.clone()),
                )
            })
            .collect(),
    );

    let all_digests = CborValue::Map(vec![(CborValue::Text(namespace.into()), ns_digests)]);

    // ValidityInfo
    let validity_info = CborValue::Map(vec![
        (CborValue::Text("signed".into()), cbor_date_time(signed_at)),
        (
            CborValue::Text("validFrom".into()),
            cbor_date_time(signed_at),
        ),
        (
            CborValue::Text("validUntil".into()),
            cbor_date_time(valid_until),
        ),
    ]);

    let mut entries = vec![
        (
            CborValue::Text("version".into()),
            CborValue::Text("1.0".into()),
        ),
        (
            CborValue::Text("digestAlgorithm".into()),
            CborValue::Text("SHA-256".into()),
        ),
        (CborValue::Text("valueDigests".into()), all_digests),
        (
            CborValue::Text("docType".into()),
            CborValue::Text(doc_type.into()),
        ),
        (CborValue::Text("validityInfo".into()), validity_info),
    ];
    if let Some(device_key) = device_key {
        entries.push((
            CborValue::Text("deviceKeyInfo".into()),
            CborValue::Map(vec![(CborValue::Text("deviceKey".into()), device_key)]),
        ));
    }

    Ok(CborValue::Map(entries))
}

/// Convert a holder EC public JWK to the COSE_Key embedded in DeviceKeyInfo.
///
/// ISO 18013-5 DeviceAuthentication currently uses EC2 keys in the supported
/// Marty profiles. Only public coordinates are encoded, even if a caller
/// accidentally supplies other JWK members.
fn jwk_to_cose_device_key(jwk: &serde_json::Value) -> Oid4vciResult<CborValue> {
    use base64::Engine;

    let object = jwk
        .as_object()
        .ok_or_else(|| Oid4vciError::MdocError("holder public JWK must be a JSON object".into()))?;
    if object.get("kty").and_then(serde_json::Value::as_str) != Some("EC") {
        return Err(Oid4vciError::MdocError(
            "mDoc holder public JWK must use EC key type".into(),
        ));
    }

    let curve = object
        .get("crv")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Oid4vciError::MdocError("mDoc holder public JWK is missing crv".into()))?;
    let (curve_id, coordinate_len) = match curve {
        "P-256" => (1i64, 32usize),
        "P-384" => (2i64, 48usize),
        curve => {
            return Err(Oid4vciError::MdocError(format!(
                "unsupported mDoc holder JWK curve: {curve}"
            )))
        }
    };

    let decode_coordinate = |name: &str| -> Oid4vciResult<Vec<u8>> {
        let encoded = object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Oid4vciError::MdocError(format!("mDoc holder public JWK is missing {name}"))
            })?;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| {
                Oid4vciError::MdocError(format!("mDoc holder public JWK has invalid {name}"))
            })?;
        if decoded.len() != coordinate_len {
            return Err(Oid4vciError::MdocError(format!(
                "mDoc holder public JWK {name} must contain {coordinate_len} bytes"
            )));
        }
        Ok(decoded)
    };

    let x = decode_coordinate("x")?;
    let y = decode_coordinate("y")?;
    let mut encoded_point = Vec::with_capacity(1 + 2 * coordinate_len);
    encoded_point.push(0x04);
    encoded_point.extend_from_slice(&x);
    encoded_point.extend_from_slice(&y);
    let is_valid_point = match curve {
        "P-256" => p256::PublicKey::from_sec1_bytes(&encoded_point).is_ok(),
        "P-384" => p384::PublicKey::from_sec1_bytes(&encoded_point).is_ok(),
        _ => unreachable!("supported curves were checked above"),
    };
    if !is_valid_point {
        return Err(Oid4vciError::MdocError(format!(
            "mDoc holder public JWK coordinates are not a valid {curve} point"
        )));
    }

    Ok(CborValue::Map(vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
        (
            CborValue::Integer((-1i64).into()),
            CborValue::Integer(curve_id.into()),
        ),
        (CborValue::Integer((-2i64).into()), CborValue::Bytes(x)),
        (CborValue::Integer((-3i64).into()), CborValue::Bytes(y)),
    ]))
}

/// Sign a payload with COSE_Sign1 using the issuer's JWK.
///
/// Returns the serialized COSE_Sign1 bytes.
fn sign_cose_sign1(
    payload: &[u8],
    jwk: &ssi_jwk::JWK,
    issuer_key: &IssuerKey,
    x5chain_der: &[Vec<u8>],
) -> Oid4vciResult<Vec<u8>> {
    use ssi_crypto::{AlgorithmInstance, SecretKey};
    use ssi_jwk::Params;

    let alg = match issuer_key.algorithm {
        crate::types::SigningAlgorithm::ES256 => iana::Algorithm::ES256,
        crate::types::SigningAlgorithm::EdDSA => iana::Algorithm::EdDSA,
        crate::types::SigningAlgorithm::ES256K => {
            return Err(Oid4vciError::MdocError(
                "ES256K is not supported for mDoc COSE signing".into(),
            ));
        }
        crate::types::SigningAlgorithm::ES384 => iana::Algorithm::ES384,
        crate::types::SigningAlgorithm::RS256 => iana::Algorithm::PS256,
    };

    // ISO 18013-5 section 9.1.2.4 puts alg in the protected header and
    // x5chain in the unprotected header.
    let protected = build_protected_header(alg);
    let unprotected = build_unprotected_header(x5chain_der);

    // Build the COSE_Sign1 without signature to get the TBS data
    let cose_for_tbs = CoseSign1Builder::new()
        .protected(protected.clone())
        .unprotected(unprotected.clone())
        .payload(payload.to_vec())
        .build();
    let tbs = cose_for_tbs.tbs_data(&[]);

    // Extract secret key from JWK (same pattern as jwt_vc.rs)
    let secret_key = match &jwk.params {
        Params::OKP(params) => {
            let d = params
                .private_key
                .as_ref()
                .ok_or_else(|| Oid4vciError::KeyError("Missing Ed25519 private key".into()))?;
            SecretKey::new_ed25519(&d.0)
                .map_err(|e| Oid4vciError::KeyError(format!("Invalid Ed25519 key: {:?}", e)))
        }
        Params::EC(params) => {
            let d = params
                .ecc_private_key
                .as_ref()
                .ok_or_else(|| Oid4vciError::KeyError("Missing EC private key".into()))?;
            match params.curve.as_deref() {
                Some("P-256") => SecretKey::new_p256(&d.0)
                    .map_err(|e| Oid4vciError::KeyError(format!("Invalid P-256 key: {:?}", e))),
                Some(curve) => Err(Oid4vciError::KeyError(format!(
                    "Unsupported EC curve for COSE: {}",
                    curve
                ))),
                None => Err(Oid4vciError::KeyError("Missing curve in EC JWK".into())),
            }
        }
        _ => Err(Oid4vciError::KeyError(
            "Unsupported key type for COSE signing".into(),
        )),
    }?;

    let ssi_alg = match issuer_key.algorithm {
        crate::types::SigningAlgorithm::ES256 => AlgorithmInstance::ES256,
        crate::types::SigningAlgorithm::EdDSA => AlgorithmInstance::EdDSA,
        crate::types::SigningAlgorithm::ES384 => AlgorithmInstance::ES384,
        _ => {
            return Err(Oid4vciError::MdocError(
                "Algorithm not supported for COSE signing".into(),
            ));
        }
    };

    let signature = secret_key
        .sign(ssi_alg, &tbs)
        .map_err(|e| Oid4vciError::MdocError(format!("COSE signing failed: {:?}", e)))?;

    // Build final COSE_Sign1 with signature
    let cose_sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload.to_vec())
        .signature(signature)
        .build();

    // IssuerAuth is embedded as the COSE_Sign1 array. An optional outer COSE
    // tag 18 is not used because ISO mdoc consumers parse the array directly.
    cose_sign1
        .to_vec()
        .map_err(|e| Oid4vciError::MdocError(format!("COSE serialization failed: {:?}", e)))
}

fn build_protected_header(alg: iana::Algorithm) -> coset::Header {
    HeaderBuilder::new().algorithm(alg).build()
}

fn build_unprotected_header(x5chain_der: &[Vec<u8>]) -> coset::Header {
    let mut builder = HeaderBuilder::new();
    if !x5chain_der.is_empty() {
        let chain = if x5chain_der.len() == 1 {
            CosetValue::Bytes(x5chain_der[0].clone())
        } else {
            CosetValue::Array(
                x5chain_der
                    .iter()
                    .map(|cert| CosetValue::Bytes(cert.clone()))
                    .collect(),
            )
        };
        builder = builder.value(COSE_HEADER_X5CHAIN_LABEL, chain);
    }
    builder.build()
}

fn extract_mdoc_x5chain_from_claims(claims: &CredentialClaims) -> Oid4vciResult<Vec<Vec<u8>>> {
    let raw = match claims.claims.get(MDOC_X5C_CLAIM_KEY) {
        Some(value) => value,
        None => return Ok(Vec::new()),
    };

    let entries = raw.as_array().ok_or_else(|| {
        Oid4vciError::MdocError(format!(
            "{MDOC_X5C_CLAIM_KEY} must be an array of base64-encoded DER certificates"
        ))
    })?;

    let mut chain = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let encoded = entry.as_str().ok_or_else(|| {
            Oid4vciError::MdocError(format!(
                "{MDOC_X5C_CLAIM_KEY}[{index}] must be a base64 string"
            ))
        })?;

        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .or_else(|_| {
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, encoded)
            })
            .map_err(|_| {
                Oid4vciError::MdocError(format!(
                    "{MDOC_X5C_CLAIM_KEY}[{index}] is not valid base64-encoded DER"
                ))
            })?;

        chain.push(decoded);
    }

    Ok(chain)
}

/// CBOR-encode a CborValue into bytes.
fn cbor_encode(value: &CborValue) -> Oid4vciResult<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| Oid4vciError::MdocError(format!("CBOR encoding failed: {}", e)))?;
    Ok(buf)
}

/// Encode `MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)`.
fn encode_mobile_security_object_bytes(mso: &CborValue) -> Oid4vciResult<Vec<u8>> {
    let encoded_mso = cbor_encode(mso)?;
    cbor_encode(&CborValue::Tag(
        CBOR_TAG_ENCODED_CBOR,
        Box::new(CborValue::Bytes(encoded_mso)),
    ))
}

/// Convert a serde_json::Value into a ciborium CborValue.
fn json_to_cbor(value: &serde_json::Value) -> Oid4vciResult<CborValue> {
    match value {
        serde_json::Value::Null => Ok(CborValue::Null),
        serde_json::Value::Bool(b) => Ok(CborValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(CborValue::Integer(i.into()))
            } else if let Some(f) = n.as_f64() {
                Ok(CborValue::Float(f))
            } else {
                Err(Oid4vciError::MdocError(format!(
                    "Unsupported numeric value: {}",
                    n
                )))
            }
        }
        serde_json::Value::String(s) => {
            // CBOR tag 0 is an RFC 3339 date-time, not an ISO full-date.
            // mDL elements such as birth_date use RFC 8943 tag 1004 instead.
            if is_full_date_string(s) {
                Ok(CborValue::Tag(
                    CBOR_TAG_FULL_DATE,
                    Box::new(CborValue::Text(s.clone())),
                ))
            } else if chrono::DateTime::parse_from_rfc3339(s).is_ok() {
                Ok(CborValue::Tag(0, Box::new(CborValue::Text(s.clone()))))
            } else {
                Ok(CborValue::Text(s.clone()))
            }
        }
        serde_json::Value::Array(arr) => {
            let items: Result<Vec<_>, _> = arr.iter().map(json_to_cbor).collect();
            Ok(CborValue::Array(items?))
        }
        serde_json::Value::Object(obj) => {
            let pairs: Result<Vec<_>, _> = obj
                .iter()
                .map(|(k, v)| json_to_cbor(v).map(|cv| (CborValue::Text(k.clone()), cv)))
                .collect();
            Ok(CborValue::Map(pairs?))
        }
    }
}

/// Return true only for a valid RFC 3339 full-date (`YYYY-MM-DD`).
fn is_full_date_string(s: &str) -> bool {
    s.len() == 10 && chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
}

/// Convert a chrono DateTime to a CBOR tagged date-time string (tag 0).
fn cbor_date_time(dt: &chrono::DateTime<chrono::Utc>) -> CborValue {
    CborValue::Tag(
        0,
        Box::new(CborValue::Text(
            dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SigningAlgorithm;
    use isomdl::digest_executor::DigestExecutionError;
    use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

    #[derive(Debug)]
    struct SignerMustRemainUnused;

    impl CredentialSigner for SignerMustRemainUnused {
        fn sign(&self, _message: &[u8]) -> Oid4vciResult<Vec<u8>> {
            panic!("digest failure must stop before signing")
        }

        fn algorithm(&self) -> SigningAlgorithm {
            panic!("digest failure must stop before signer inspection")
        }

        fn issuer_id(&self) -> &str {
            panic!("digest failure must stop before signer inspection")
        }

        fn kid_url(&self) -> String {
            panic!("digest failure must stop before signer inspection")
        }
    }

    struct SeededShufflingDigestExecutor(u64);

    impl DigestExecutor for SeededShufflingDigestExecutor {
        fn execute(&self, jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError> {
            let mut results = SerialDigestExecutor.execute(jobs)?;
            results.shuffle(&mut StdRng::seed_from_u64(self.0));
            Ok(results)
        }
    }

    #[derive(Clone, Copy)]
    enum DigestExecutorFault {
        Execution,
        Missing,
        Duplicate,
        UnexpectedCredential,
        UnexpectedJob,
        WrongOrdinal,
        WrongDigestLength,
    }

    struct FaultingDigestExecutor(DigestExecutorFault);

    impl DigestExecutor for FaultingDigestExecutor {
        fn execute(&self, jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError> {
            if matches!(self.0, DigestExecutorFault::Execution) {
                return Err(DigestExecutionError);
            }

            let mut results = SerialDigestExecutor.execute(jobs)?;
            match self.0 {
                DigestExecutorFault::Execution => unreachable!(),
                DigestExecutorFault::Missing => {
                    results.pop();
                }
                DigestExecutorFault::Duplicate => {
                    results[1] = results[0].clone();
                }
                DigestExecutorFault::UnexpectedCredential => {
                    results[0].credential_id += 1;
                }
                DigestExecutorFault::UnexpectedJob => {
                    results[0].job_id += 1_000;
                }
                DigestExecutorFault::WrongOrdinal => {
                    results[0].ordinal += 1;
                }
                DigestExecutorFault::WrongDigestLength => {
                    results[0].digest.pop();
                }
            }
            Ok(results)
        }
    }

    fn replay_digest_plan() -> MdocDigestPlan {
        let claims = [
            ("family_name", serde_json::json!("Sensitive Smith")),
            ("given_name", serde_json::json!("Sensitive Alice")),
            ("birth_date", serde_json::json!("1990-01-15")),
        ];
        let salts = [
            std::array::from_fn(|index| index as u8),
            std::array::from_fn(|index| 0x40 + index as u8),
            std::array::from_fn(|index| 0xff - index as u8),
        ];
        let mut salt_tape = salts.into_iter();
        let plan = plan_mdoc_digests(claims.iter().map(|(name, value)| (*name, value)), || {
            salt_tape.next().expect("one salt per planned digest")
        })
        .unwrap();
        assert!(salt_tape.next().is_none());
        plan
    }

    fn test_p256_key() -> IssuerKey {
        let jwk = ssi_jwk::JWK::generate_p256();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        IssuerKey {
            issuer_id: "did:example:issuer".into(),
            jwk_json,
            algorithm: SigningAlgorithm::ES256,
        }
    }

    fn test_mdoc_claims(
        entries: impl IntoIterator<Item = (String, serde_json::Value)>,
    ) -> CredentialClaims {
        CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: entries.into_iter().collect(),
            expiration_seconds: Some(365 * 86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        }
    }

    fn assert_mobile_security_object_bytes(issuer_signed_b64: &str) {
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            issuer_signed_b64,
        )
        .unwrap();
        let issuer_signed: CborValue = ciborium::from_reader(&bytes[..]).unwrap();
        let issuer_auth = match issuer_signed {
            CborValue::Map(entries) => entries
                .into_iter()
                .find_map(|(key, value)| {
                    (key == CborValue::Text("issuerAuth".into())).then_some(value)
                })
                .expect("issuerAuth present"),
            _ => panic!("IssuerSigned must be a CBOR map"),
        };
        let cose_parts = match issuer_auth {
            CborValue::Array(parts) => parts,
            CborValue::Tag(18, _) => {
                panic!("issuerAuth must not use optional outer COSE tag 18")
            }
            _ => panic!("issuerAuth must be a COSE_Sign1 array"),
        };
        let payload = match cose_parts.get(2) {
            Some(CborValue::Bytes(payload)) => payload,
            _ => panic!("issuerAuth payload must contain MobileSecurityObjectBytes"),
        };
        let mobile_security_object_bytes: CborValue = ciborium::from_reader(&payload[..]).unwrap();
        let encoded_mso = match mobile_security_object_bytes {
            CborValue::Tag(CBOR_TAG_ENCODED_CBOR, value) => match *value {
                CborValue::Bytes(encoded_mso) => encoded_mso,
                _ => panic!("MobileSecurityObjectBytes tag must contain a byte string"),
            },
            _ => panic!("issuerAuth payload must be tag 24 MobileSecurityObjectBytes"),
        };
        let mso: CborValue = ciborium::from_reader(&encoded_mso[..]).unwrap();
        assert!(matches!(mso, CborValue::Map(_)));
    }

    fn assert_issuer_value_digests(issuer_signed_b64: &str) {
        use isomdl::definitions::IssuerSigned;

        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            issuer_signed_b64,
        )
        .unwrap();
        let issuer_signed: IssuerSigned = isomdl::cbor::from_slice(&bytes).unwrap();
        let encoded_mso: CborValue =
            isomdl::cbor::from_slice(issuer_signed.issuer_auth.payload.as_ref().unwrap()).unwrap();
        let CborValue::Tag(CBOR_TAG_ENCODED_CBOR, encoded_mso) = encoded_mso else {
            panic!("issuerAuth payload must be MobileSecurityObjectBytes");
        };
        let CborValue::Bytes(encoded_mso) = *encoded_mso else {
            panic!("MobileSecurityObjectBytes must contain a byte string");
        };
        let CborValue::Map(mso) = isomdl::cbor::from_slice(&encoded_mso).unwrap() else {
            panic!("MobileSecurityObject must be a CBOR map");
        };
        let CborValue::Map(value_digests) = mso
            .iter()
            .find_map(|(key, value)| {
                (key == &CborValue::Text("valueDigests".to_string())).then_some(value)
            })
            .unwrap()
        else {
            panic!("MobileSecurityObject must contain valueDigests");
        };

        for (namespace, items) in issuer_signed.namespaces.unwrap().iter() {
            let CborValue::Map(expected_digests) = value_digests
                .iter()
                .find_map(|(key, value)| {
                    (key == &CborValue::Text(namespace.clone())).then_some(value)
                })
                .unwrap()
            else {
                panic!("namespace digest collection must be a CBOR map");
            };
            assert_eq!(
                expected_digests.len(),
                items.len(),
                "each issued item must have exactly one valueDigest",
            );
            for tagged_item in items.iter() {
                let digest_id = serde_json::to_value(tagged_item.as_ref().digest_id)
                    .unwrap()
                    .as_u64()
                    .unwrap();
                let CborValue::Bytes(expected) = expected_digests
                    .iter()
                    .find_map(|(key, value)| {
                        (key == &CborValue::Integer(digest_id.into())).then_some(value)
                    })
                    .unwrap()
                else {
                    panic!("issuer value digest must be a byte string");
                };
                let encoded_wrapper = isomdl::cbor::to_vec(tagged_item).unwrap();
                let computed = Sha256::digest(encoded_wrapper);
                assert_eq!(computed.as_slice(), expected);

                let encoded_item = isomdl::cbor::to_vec(tagged_item.as_ref()).unwrap();
                let inner_item_digest = Sha256::digest(encoded_item);
                assert_ne!(inner_item_digest.as_slice(), expected);
            }
        }
    }

    #[test]
    fn test_json_to_cbor_primitives() {
        let null = json_to_cbor(&serde_json::json!(null)).unwrap();
        assert!(matches!(null, CborValue::Null));

        let num = json_to_cbor(&serde_json::json!(42)).unwrap();
        assert!(matches!(num, CborValue::Integer(_)));

        let text = json_to_cbor(&serde_json::json!("hello")).unwrap();
        assert!(matches!(text, CborValue::Text(_)));

        let date = json_to_cbor(&serde_json::json!("1990-01-15")).unwrap();
        assert!(matches!(date, CborValue::Tag(CBOR_TAG_FULL_DATE, _)));

        let date_time = json_to_cbor(&serde_json::json!("2026-07-21T12:00:00Z")).unwrap();
        assert!(matches!(date_time, CborValue::Tag(0, _)));

        let invalid_date = json_to_cbor(&serde_json::json!("2026-02-30")).unwrap();
        assert!(matches!(invalid_date, CborValue::Text(_)));

        let unicode_text = json_to_cbor(&serde_json::json!("\u{1F5D3} 2026-07-21")).unwrap();
        assert!(matches!(unicode_text, CborValue::Text(_)));
    }

    #[test]
    fn test_build_issuer_signed_item() {
        let salt = [0u8; 32];
        let item =
            build_issuer_signed_item(0, &salt, "family_name", &serde_json::json!("Smith")).unwrap();

        // Should be a CBOR map with 4 entries
        if let CborValue::Map(entries) = item {
            assert_eq!(entries.len(), 4);
        } else {
            panic!("Expected CBOR map");
        }
    }

    #[test]
    fn test_issuer_signed_item_digest_commits_tagged_wrapper() {
        let salt: [u8; 32] = std::array::from_fn(|index| index as u8);
        let (tagged_item, digest) =
            build_issuer_signed_item_bytes(3, &salt, "family_name", &serde_json::json!("Smith"))
                .unwrap();

        let encoded_wrapper = cbor_encode(&tagged_item).unwrap();
        assert_eq!(
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                &encoded_wrapper,
            ),
            "2BhYZaRoZGlnZXN0SUQDZnJhbmRvbVggAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9xZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVsZWxlbWVudFZhbHVlZVNtaXRo",
            "IssuerSignedItemBytes encoding is part of the signed digest contract",
        );
        assert_eq!(
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &digest,),
            "9Nmg3ahEZR98_UVEmU5kjPtv4wltp1h5taEr0C2LMvA",
            "MSO valueDigest must remain byte-for-byte stable for the fixture",
        );
        assert_eq!(Sha256::digest(encoded_wrapper).as_slice(), digest);

        let CborValue::Tag(CBOR_TAG_ENCODED_CBOR, wrapped_item) = tagged_item else {
            panic!("IssuerSignedItemBytes must use tag 24");
        };
        let CborValue::Bytes(encoded_item) = *wrapped_item else {
            panic!("IssuerSignedItemBytes must contain an encoded CBOR byte string");
        };
        assert_ne!(Sha256::digest(encoded_item).as_slice(), digest);
    }

    #[test]
    fn serial_mdoc_digest_plan_matches_the_inline_digest_oracle() {
        let salt: [u8; 32] = std::array::from_fn(|index| 0x80 + index as u8);
        let value = serde_json::json!("Sensitive Smith");
        let expected = build_issuer_signed_item_bytes(0, &salt, "family_name", &value).unwrap();
        let plan = plan_mdoc_digests([("family_name", &value)], || salt).unwrap();
        let results = execute_mdoc_digest_plan(&plan, &SerialDigestExecutor).unwrap();
        let actual = assemble_mdoc_digest_plan(plan, results).unwrap();

        assert_eq!(actual.issuer_signed_items, [expected.0]);
        assert_eq!(actual.value_digests, [(0, expected.1)]);
    }

    #[test]
    fn empty_mdoc_digest_plan_consumes_no_salt_and_preserves_empty_mso() {
        let key = test_p256_key();
        let claims = test_mdoc_claims([]);
        let signed_at = chrono::DateTime::parse_from_rfc3339("2026-08-29T12:34:56Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let prepared = prepare_mdoc_with_inputs(
            &key,
            &claims,
            "urn:uuid:961d492d-ffb7-59f9-b2cf-66a84c47d07c".into(),
            None,
            signed_at,
            std::iter::empty::<(&str, &serde_json::Value)>(),
            || panic!("empty mdoc preparation must not request a salt"),
        )
        .unwrap();

        assert!(prepared.issuer_signed_items.is_empty());
        let encoded_mso: CborValue =
            ciborium::from_reader(&prepared.mobile_security_object_bytes[..]).unwrap();
        let CborValue::Tag(CBOR_TAG_ENCODED_CBOR, encoded_mso) = encoded_mso else {
            panic!("prepared payload must contain MobileSecurityObjectBytes");
        };
        let CborValue::Bytes(encoded_mso) = *encoded_mso else {
            panic!("MobileSecurityObjectBytes must contain encoded CBOR");
        };
        let CborValue::Map(mso) = ciborium::from_reader(&encoded_mso[..]).unwrap() else {
            panic!("MobileSecurityObject must be a map");
        };
        let CborValue::Map(value_digests) = mso
            .iter()
            .find_map(|(key, value)| {
                (key == &CborValue::Text("valueDigests".into())).then_some(value)
            })
            .unwrap()
        else {
            panic!("MobileSecurityObject must contain valueDigests");
        };
        let CborValue::Map(namespace_digests) = value_digests
            .iter()
            .find_map(|(key, value)| {
                (key == &CborValue::Text("org.iso.18013.5.1".into())).then_some(value)
            })
            .unwrap()
        else {
            panic!("valueDigests must contain the planned namespace");
        };
        assert!(namespace_digests.is_empty());
    }

    #[test]
    fn mdoc_digest_plan_restores_reordered_results_by_identity() {
        let serial_plan = replay_digest_plan();
        let serial_results = execute_mdoc_digest_plan(&serial_plan, &SerialDigestExecutor).unwrap();
        let expected = assemble_mdoc_digest_plan(serial_plan, serial_results).unwrap();

        for seed in 0..64 {
            let plan = replay_digest_plan();
            let executor = SeededShufflingDigestExecutor(0x4344_4c41_4d44_4f43 ^ seed);
            let results = execute_mdoc_digest_plan(&plan, &executor).unwrap();
            let actual = assemble_mdoc_digest_plan(plan, results).unwrap();
            assert_eq!(
                actual.issuer_signed_items, expected.issuer_signed_items,
                "result schedule changed item output for seed {seed}"
            );
            assert_eq!(
                actual.value_digests, expected.value_digests,
                "result schedule changed digest output for seed {seed}"
            );
        }
    }

    #[test]
    fn mdoc_digest_plan_fails_closed_with_one_redacted_error() {
        let faults = [
            DigestExecutorFault::Execution,
            DigestExecutorFault::Missing,
            DigestExecutorFault::Duplicate,
            DigestExecutorFault::UnexpectedCredential,
            DigestExecutorFault::UnexpectedJob,
            DigestExecutorFault::WrongOrdinal,
            DigestExecutorFault::WrongDigestLength,
        ];

        for fault in faults {
            let plan = replay_digest_plan();
            let result = execute_mdoc_digest_plan(&plan, &FaultingDigestExecutor(fault))
                .and_then(|results| assemble_mdoc_digest_plan(plan, results));
            let error = match result {
                Ok(_) => panic!("faulty digest execution must fail closed"),
                Err(error) => error,
            };
            let Oid4vciError::MdocError(message) = error else {
                panic!("digest lane failures must use the mdoc error boundary");
            };
            assert_eq!(message, MDOC_DIGEST_EXECUTION_FAILED);
            for sensitive in ["Sensitive", "family_name", "given_name", "birth_date"] {
                assert!(!message.contains(sensitive));
            }
        }
    }

    #[test]
    fn digest_executor_failure_stops_before_preparation_uses_the_signer() {
        let claims =
            test_mdoc_claims([("family_name".into(), serde_json::json!("Sensitive Smith"))]);
        let signed_at = chrono::DateTime::parse_from_rfc3339("2026-08-29T12:34:56Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let issuer_claims = claims
            .claims
            .iter()
            .map(|(name, value)| (name.as_str(), value));
        let result = prepare_mdoc_with_inputs_and_digest_executor(
            &SignerMustRemainUnused,
            &claims,
            "urn:uuid:961d492d-ffb7-59f9-b2cf-66a84c47d07c".into(),
            None,
            signed_at,
            issuer_claims,
            || rand::thread_rng().gen(),
            &FaultingDigestExecutor(DigestExecutorFault::Execution),
        );

        let error = match result {
            Ok(_) => panic!("digest execution failure must abort preparation"),
            Err(error) => error,
        };
        let Oid4vciError::MdocError(message) = error else {
            panic!("digest lane failures must use the mdoc error boundary");
        };
        assert_eq!(message, MDOC_DIGEST_EXECUTION_FAILED);
    }

    #[test]
    fn test_split_mdoc_signing_matches_deterministic_byte_fixture() {
        let key = test_p256_key();
        let certificate = [0x30, 0x82, 0x01, 0x0a];
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: [
                ("family_name".into(), serde_json::json!("Smith")),
                ("given_name".into(), serde_json::json!("Alice")),
                ("birth_date".into(), serde_json::json!("1990-01-15")),
                (
                    MDOC_X5C_CLAIM_KEY.into(),
                    serde_json::json!([base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        certificate,
                    )]),
                ),
            ]
            .into(),
            expiration_seconds: Some(365 * 86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };
        let holder_public_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        });
        let claim_order = ["given_name", "birth_date", "family_name"];
        let ordered_claims: Vec<_> = claim_order
            .iter()
            .map(|name| (*name, claims.claims.get(*name).unwrap()))
            .collect();
        let salts = [
            std::array::from_fn(|index| index as u8),
            std::array::from_fn(|index| 0x80 + index as u8),
            std::array::from_fn(|index| 0xff - index as u8),
        ];
        let expected_items: Vec<_> = ordered_claims
            .iter()
            .enumerate()
            .map(|(digest_id, (name, value))| {
                build_issuer_signed_item_bytes(digest_id as u64, &salts[digest_id], name, value)
                    .unwrap()
                    .0
            })
            .collect();
        let signed_at = chrono::DateTime::parse_from_rfc3339("2026-08-29T12:34:56Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut salt_tape = salts.into_iter();
        let prepared = prepare_mdoc_with_inputs(
            &key,
            &claims,
            "urn:uuid:961d492d-ffb7-59f9-b2cf-66a84c47d07c".into(),
            Some(&holder_public_jwk),
            signed_at,
            ordered_claims.iter().map(|(name, value)| (*name, *value)),
            || salt_tape.next().expect("one salt per issued claim"),
        )
        .unwrap();
        assert!(salt_tape.next().is_none(), "all planned salts must be used");
        assert_eq!(prepared.issuer_signed_items, expected_items);

        let recomputed_tbs = CoseSign1Builder::new()
            .protected(prepared.protected_header.clone())
            .unprotected(prepared.unprotected_header.clone())
            .payload(prepared.mobile_security_object_bytes.clone())
            .build()
            .tbs_data(&[]);
        assert_eq!(prepared.tbs_data, recomputed_tbs);

        let encode = |bytes: &[u8]| {
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
        };
        assert_eq!(
            encode(&prepared.mobile_security_object_bytes),
            "2BhZAZ2mZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2bHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGjAFggCrd9jjrGFalL2zBUAN84dv7Ll7Fe6QSKCHoexeMIVRgBWCDWaKsW1N5cBKM9W_ak9Rzgy4LYycYoA3q_Arww2-55IAJYIF-JSo0GE0_QW8CWhGErxpkDDd4tztzX--uMhqlR_v07Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI2LTA4LTI5VDEyOjM0OjU2Wml2YWxpZEZyb23AdDIwMjYtMDgtMjlUMTI6MzQ6NTZaanZhbGlkVW50aWzAdDIwMjctMDgtMjlUMTI6MzQ6NTZabWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpYiWCBP40Li_hp_m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q",
            "MobileSecurityObjectBytes must remain stable for the replay fixture",
        );
        assert_eq!(
            encode(&prepared.tbs_data),
            "hGpTaWduYXR1cmUxQ6EBJkBZAaLYGFkBnaZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMaMAWCAKt32OOsYVqUvbMFQA3zh2_suXsV7pBIoIeh7F4whVGAFYINZoqxbU3lwEoz1b9qT1HODLgtjJxigDer8CvDDb7nkgAlggX4lKjQYTT9BbwJaEYSvGmQMN3i3O3Nf764yGqVH-_TtnZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjYtMDgtMjlUMTI6MzQ6NTZaaXZhbGlkRnJvbcB0MjAyNi0wOC0yOVQxMjozNDo1NlpqdmFsaWRVbnRpbMB0MjAyNy0wOC0yOVQxMjozNDo1NlptZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCBrF9Hy4SxCR_i85uVjpEDydwN9gS3rM6D0oTlF2JjCliJYIE_jQuL-Gn-bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1",
            "COSE Sig_structure bytes must remain stable for remote signing",
        );

        let signed = assemble_mdoc(prepared, &[0xa5; 64]).unwrap();
        let SignedCredential::MsoMdoc {
            issuer_signed_b64,
            credential_id,
        } = signed
        else {
            panic!("Expected MsoMdoc");
        };

        assert_eq!(
            issuer_signed_b64,
            "ompuYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYPYGFhkpGhkaWdlc3RJRABmcmFuZG9tWCAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eH3FlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1lbGVsZW1lbnRWYWx1ZWVBbGljZdgYWGykaGRpZ2VzdElEAWZyYW5kb21YIICBgoOEhYaHiImKi4yNjo-QkZKTlJWWl5iZmpucnZ6fcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVl2QPsajE5OTAtMDEtMTXYGFhlpGhkaWdlc3RJRAJmcmFuZG9tWCD__v38-_r5-Pf29fTz8vHw7-7t7Ovq6ejn5uXk4-Lh4HFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVlU21pdGhqaXNzdWVyQXV0aIRDoQEmoRghRDCCAQpZAaLYGFkBnaZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMaMAWCAKt32OOsYVqUvbMFQA3zh2_suXsV7pBIoIeh7F4whVGAFYINZoqxbU3lwEoz1b9qT1HODLgtjJxigDer8CvDDb7nkgAlggX4lKjQYTT9BbwJaEYSvGmQMN3i3O3Nf764yGqVH-_TtnZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjYtMDgtMjlUMTI6MzQ6NTZaaXZhbGlkRnJvbcB0MjAyNi0wOC0yOVQxMjozNDo1NlpqdmFsaWRVbnRpbMB0MjAyNy0wOC0yOVQxMjozNDo1NlptZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCBrF9Hy4SxCR_i85uVjpEDydwN9gS3rM6D0oTlF2JjCliJYIE_jQuL-Gn-bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1WEClpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWl",
            "IssuerSigned assembly must preserve the planned item order",
        );
        assert_eq!(
            credential_id,
            "urn:uuid:961d492d-ffb7-59f9-b2cf-66a84c47d07c"
        );
    }

    #[test]
    fn test_sign_mdoc_basic() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "mDL".into(),
            claims: [
                ("family_name".into(), serde_json::json!("Smith")),
                ("given_name".into(), serde_json::json!("John")),
                ("birth_date".into(), serde_json::json!("1990-01-15")),
            ]
            .into(),
            expiration_seconds: Some(365 * 86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let result = sign_mdoc(&key, &claims).unwrap();
        match result {
            SignedCredential::MsoMdoc {
                issuer_signed_b64,
                credential_id,
            } => {
                assert!(
                    !issuer_signed_b64.is_empty(),
                    "Should produce non-empty output"
                );
                assert!(credential_id.starts_with("urn:uuid:"));
                assert_mobile_security_object_bytes(&issuer_signed_b64);
                assert_issuer_value_digests(&issuer_signed_b64);

                // Decode and verify it's valid CBOR
                let bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    &issuer_signed_b64,
                )
                .unwrap();
                let decoded: CborValue = ciborium::from_reader(&bytes[..]).unwrap();
                if let CborValue::Map(entries) = decoded {
                    let keys: Vec<_> = entries
                        .iter()
                        .filter_map(|(k, _)| {
                            if let CborValue::Text(t) = k {
                                Some(t.as_str())
                            } else {
                                None
                            }
                        })
                        .collect();
                    assert!(keys.contains(&"nameSpaces"));
                    assert!(keys.contains(&"issuerAuth"));
                } else {
                    panic!("Expected CBOR map at top level");
                }
            }
            _ => panic!("Expected MsoMdoc"),
        }
    }

    #[test]
    fn test_split_mdoc_signing_uses_mobile_security_object_bytes() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "mDL".into(),
            claims: [("family_name".into(), serde_json::json!("Smith"))].into(),
            expiration_seconds: Some(365 * 86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let prepared = prepare_mdoc(&key, &claims).unwrap();
        let signature = key.sign(&prepared.tbs_data).unwrap();
        let result = assemble_mdoc(prepared, &signature).unwrap();
        let SignedCredential::MsoMdoc {
            issuer_signed_b64, ..
        } = result
        else {
            panic!("Expected MsoMdoc");
        };

        assert_mobile_security_object_bytes(&issuer_signed_b64);
        assert_issuer_value_digests(&issuer_signed_b64);
    }

    #[test]
    fn test_prepare_mdoc_preserves_reserved_credential_id() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: [("family_name".into(), serde_json::json!("Smith"))].into(),
            expiration_seconds: Some(86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };
        let reserved = "urn:uuid:961d492d-ffb7-59f9-b2cf-66a84c47d07c";

        let prepared = prepare_mdoc_with_credential_id(&key, &claims, Some(reserved)).unwrap();

        assert_eq!(prepared.credential_id, reserved);
    }

    #[test]
    fn test_prepare_mdoc_binds_holder_public_jwk_as_device_key() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: [("family_name".into(), serde_json::json!("Smith"))].into(),
            expiration_seconds: Some(86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };
        let x = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        )
        .unwrap();
        let y = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        )
        .unwrap();
        let holder_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                &x,
            ),
            "y": base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                &y,
            ),
            "d": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
        });

        let prepared =
            prepare_mdoc_with_credential_id_and_device_key(&key, &claims, None, Some(&holder_jwk))
                .unwrap();
        let wrapped: CborValue =
            ciborium::from_reader(&prepared.mobile_security_object_bytes[..]).unwrap();
        let encoded_mso = match wrapped {
            CborValue::Tag(CBOR_TAG_ENCODED_CBOR, value) => match *value {
                CborValue::Bytes(bytes) => bytes,
                _ => panic!("MobileSecurityObjectBytes must wrap bytes"),
            },
            _ => panic!("MobileSecurityObjectBytes must use tag 24"),
        };
        let mso: CborValue = ciborium::from_reader(&encoded_mso[..]).unwrap();
        let device_key_info = match mso {
            CborValue::Map(entries) => entries
                .into_iter()
                .find_map(|(name, value)| {
                    (name == CborValue::Text("deviceKeyInfo".into())).then_some(value)
                })
                .expect("deviceKeyInfo present"),
            _ => panic!("MSO must be a map"),
        };
        let device_key = match device_key_info {
            CborValue::Map(entries) => entries
                .into_iter()
                .find_map(|(name, value)| {
                    (name == CborValue::Text("deviceKey".into())).then_some(value)
                })
                .expect("deviceKey present"),
            _ => panic!("deviceKeyInfo must be a map"),
        };

        assert_eq!(
            device_key,
            CborValue::Map(vec![
                (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
                (
                    CborValue::Integer((-1i64).into()),
                    CborValue::Integer(1.into()),
                ),
                (CborValue::Integer((-2i64).into()), CborValue::Bytes(x)),
                (CborValue::Integer((-3i64).into()), CborValue::Bytes(y)),
            ])
        );
    }

    #[test]
    fn test_prepare_mdoc_rejects_incomplete_holder_public_jwk() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: None,
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: Default::default(),
            expiration_seconds: Some(86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };
        let incomplete = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "ERERERERERERERERERERERERERERERERERERERERERE"
        });

        let error =
            prepare_mdoc_with_credential_id_and_device_key(&key, &claims, None, Some(&incomplete))
                .err()
                .expect("missing y must fail");

        assert!(error.to_string().contains("missing y"));
    }

    #[test]
    fn test_prepare_mdoc_rejects_off_curve_holder_public_jwk() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: None,
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: Default::default(),
            expiration_seconds: Some(86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        for (curve, coordinate_len) in [("P-256", 32), ("P-384", 48)] {
            let invalid = serde_json::json!({
                "kty": "EC",
                "crv": curve,
                "x": base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    vec![0x11; coordinate_len],
                ),
                "y": base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    vec![0x22; coordinate_len],
                ),
            });

            let error =
                prepare_mdoc_with_credential_id_and_device_key(&key, &claims, None, Some(&invalid))
                    .err()
                    .expect("off-curve holder key must fail");

            assert!(error.to_string().contains("not a valid"));
        }
    }

    #[test]
    fn test_prepare_mdoc_accepts_valid_p384_holder_public_jwk() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: None,
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: Default::default(),
            expiration_seconds: Some(86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };
        let holder_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-384",
            "x": "qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3",
            "y": "NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f",
        });

        prepare_mdoc_with_credential_id_and_device_key(&key, &claims, None, Some(&holder_jwk))
            .expect("valid P-384 holder key must prepare");
    }

    #[test]
    fn test_sign_mdoc_includes_x5chain_header_when_present() {
        let key = test_p256_key();
        let cert_a = vec![0x30, 0x82, 0x01, 0x0a];
        let cert_b = vec![0x30, 0x82, 0x01, 0x0b];
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "mDL".into(),
            claims: [
                ("family_name".into(), serde_json::json!("Smith")),
                (
                    MDOC_X5C_CLAIM_KEY.into(),
                    serde_json::json!([
                        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_a),
                        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_b),
                    ]),
                ),
            ]
            .into(),
            expiration_seconds: Some(365 * 86400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let result = sign_mdoc(&key, &claims).unwrap();
        let issuer_signed_b64 = match result {
            SignedCredential::MsoMdoc {
                issuer_signed_b64, ..
            } => issuer_signed_b64,
            _ => panic!("Expected MsoMdoc"),
        };

        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &issuer_signed_b64,
        )
        .unwrap();
        let top: CborValue = ciborium::from_reader(&bytes[..]).unwrap();

        let issuer_auth = match top {
            CborValue::Map(entries) => entries
                .into_iter()
                .find_map(|(k, v)| match k {
                    CborValue::Text(key) if key == "issuerAuth" => Some(v),
                    _ => None,
                })
                .expect("issuerAuth present"),
            _ => panic!("Expected top-level map"),
        };

        let parts = match issuer_auth {
            CborValue::Array(parts) => parts,
            CborValue::Tag(_, boxed) => match *boxed {
                CborValue::Array(parts) => parts,
                _ => panic!("issuerAuth tagged value should wrap a COSE array"),
            },
            _ => panic!("issuerAuth should be a COSE array"),
        };
        let protected_bstr = match parts.first() {
            Some(CborValue::Bytes(b)) => b,
            _ => panic!("COSE protected header bytes missing"),
        };
        let unprotected = match parts.get(1) {
            Some(CborValue::Map(headers)) => headers,
            _ => panic!("COSE unprotected header map missing"),
        };

        let protected: CborValue = ciborium::from_reader(&protected_bstr[..]).unwrap();
        let mut protected_has_alg = false;
        if let CborValue::Map(headers) = protected {
            for (k, v) in headers {
                if k == CborValue::Integer(1.into()) {
                    protected_has_alg = true;
                    assert_eq!(v, CborValue::Integer((-7).into()));
                }
                if k == CborValue::Integer(COSE_HEADER_X5CHAIN_LABEL.into()) {
                    panic!("ISO 18013-5 x5chain must not be in the protected header");
                }
            }
        }
        assert!(protected_has_alg, "Expected alg in protected COSE header");

        let x5chain = unprotected
            .iter()
            .find_map(|(key, value)| {
                (key == &CborValue::Integer(COSE_HEADER_X5CHAIN_LABEL.into())).then_some(value)
            })
            .expect("Expected x5chain in unprotected COSE header");
        assert_eq!(
            x5chain,
            &CborValue::Array(vec![CborValue::Bytes(cert_a), CborValue::Bytes(cert_b),])
        );
    }
}
