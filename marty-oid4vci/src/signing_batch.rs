//! Fail-closed serial batching for complete ES256 credential signatures.
//!
//! A batch is bound to one exact [`CredentialSigner`] reference. The scope
//! freezes the signer's public routing metadata, canonical format preparation
//! runs on the caller, and the private executor receives only borrowed complete
//! signing payloads plus that same signer reference. Results are restored by a
//! per-call identity envelope instead of executor return order.
//!
//! The serial executor is intentionally the only production executor. A future
//! concurrent implementation requires a separate, explicit signer capability:
//! [`Send`] and [`Sync`] alone do not authorize concurrent backend requests.
//! The signer owner must also keep the key bound to `issuer_id` and `kid_url`
//! immutable for the lifetime of a scope. Metadata checks cannot detect a
//! backend key rotation that preserves those values.

use std::collections::HashMap;
use std::fmt;

use crate::formats::jwt_vc::{assemble_jwt_vc, prepare_jwt_vc, PreparedJwtVc};
use crate::formats::mdoc::{assemble_mdoc, prepare_mdoc, PreparedMdoc};
use crate::signer::CredentialSigner;
use crate::types::{CredentialClaims, SignedCredential, SigningAlgorithm};

const ES256_SIGNATURE_LENGTH: usize = 64;

/// An opaque caller-assigned identity for one route in a signing batch.
///
/// Route identities need only be unique within one call to
/// [`Es256SignerScope::sign_batch`]. Duplicate identities are rejected before
/// credential preparation or signing begins.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SigningRouteId(u64);

impl SigningRouteId {
    /// Construct an opaque route identity from a caller-owned integer.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SigningRouteId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigningRouteId([redacted])")
    }
}

/// One owned JWT-VC input for an ES256 signing batch.
pub struct JwtVcSigningBatchInput {
    route_id: SigningRouteId,
    claims: CredentialClaims,
}

impl JwtVcSigningBatchInput {
    /// Bind owned JWT-VC claims to a batch-local route identity.
    #[must_use]
    pub fn new(route_id: SigningRouteId, claims: CredentialClaims) -> Self {
        Self { route_id, claims }
    }

    /// Return this input's opaque route identity.
    #[must_use]
    pub const fn route_id(&self) -> SigningRouteId {
        self.route_id
    }
}

impl fmt::Debug for JwtVcSigningBatchInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JwtVcSigningBatchInput([redacted])")
    }
}

/// One owned mdoc input for an ES256 signing batch.
pub struct MdocSigningBatchInput {
    route_id: SigningRouteId,
    claims: CredentialClaims,
}

impl MdocSigningBatchInput {
    /// Bind owned mdoc claims to a batch-local route identity.
    #[must_use]
    pub fn new(route_id: SigningRouteId, claims: CredentialClaims) -> Self {
        Self { route_id, claims }
    }

    /// Return this input's opaque route identity.
    #[must_use]
    pub const fn route_id(&self) -> SigningRouteId {
        self.route_id
    }
}

impl fmt::Debug for MdocSigningBatchInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MdocSigningBatchInput([redacted])")
    }
}

/// One owned credential input accepted by an [`Es256SignerScope`].
///
/// Prepared credential states are deliberately not accepted here. The scope
/// invokes the canonical preparation function for each variant itself so a
/// caller cannot substitute a payload prepared for another signer identity.
pub enum Es256SigningBatchInput {
    /// Prepare and sign a W3C JWT-VC.
    JwtVc(JwtVcSigningBatchInput),
    /// Prepare and sign an ISO mdoc.
    Mdoc(MdocSigningBatchInput),
}

impl From<JwtVcSigningBatchInput> for Es256SigningBatchInput {
    fn from(input: JwtVcSigningBatchInput) -> Self {
        Self::JwtVc(input)
    }
}

impl From<MdocSigningBatchInput> for Es256SigningBatchInput {
    fn from(input: MdocSigningBatchInput) -> Self {
        Self::Mdoc(input)
    }
}

impl fmt::Debug for Es256SigningBatchInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JwtVc(_) => formatter.write_str("Es256SigningBatchInput::JwtVc([redacted])"),
            Self::Mdoc(_) => formatter.write_str("Es256SigningBatchInput::Mdoc([redacted])"),
        }
    }
}

impl Es256SigningBatchInput {
    fn route_id(&self) -> SigningRouteId {
        match self {
            Self::JwtVc(input) => input.route_id,
            Self::Mdoc(input) => input.route_id,
        }
    }
}

/// Stable, non-sensitive categories returned by the ES256 signing batch API.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SigningBatchErrorKind {
    /// The signer cannot form a valid ES256 scope.
    InvalidScope,
    /// Two inputs reused one batch-local route identity.
    DuplicateRoute,
    /// Canonical credential preparation failed.
    PreparationFailed,
    /// Signer metadata changed after the scope was frozen.
    SignerMetadataChanged,
    /// The private executor or signing backend failed.
    ExecutorFailed,
    /// Executor results did not form the expected identity bijection.
    InvalidExecutorResults,
    /// A result was not one structurally valid raw 64-byte ES256 P1363 signature.
    ///
    /// Valid high-S signatures remain accepted and are forwarded unchanged for
    /// compatibility with the scalar signing paths.
    InvalidSignature,
    /// Credential assembly failed.
    AssemblyFailed,
}

impl SigningBatchErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidScope => "ES256 signing batch scope is invalid",
            Self::DuplicateRoute => "ES256 signing batch contains a duplicate route",
            Self::PreparationFailed => "ES256 signing batch preparation failed",
            Self::SignerMetadataChanged => "ES256 signing batch signer metadata changed",
            Self::ExecutorFailed => "ES256 signing batch execution failed",
            Self::InvalidExecutorResults => "ES256 signing batch results are invalid",
            Self::InvalidSignature => "ES256 signing batch signature is invalid",
            Self::AssemblyFailed => "ES256 signing batch assembly failed",
        }
    }
}

impl fmt::Debug for SigningBatchErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidScope => "InvalidScope",
            Self::DuplicateRoute => "DuplicateRoute",
            Self::PreparationFailed => "PreparationFailed",
            Self::SignerMetadataChanged => "SignerMetadataChanged",
            Self::ExecutorFailed => "ExecutorFailed",
            Self::InvalidExecutorResults => "InvalidExecutorResults",
            Self::InvalidSignature => "InvalidSignature",
            Self::AssemblyFailed => "AssemblyFailed",
        })
    }
}

impl fmt::Display for SigningBatchErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// A fail-closed and redacted ES256 signing batch error.
///
/// The optional ordinal is the input's zero-based caller position. Backend
/// errors, claims, key identifiers, issuer identifiers, routes, payloads, and
/// signatures are never retained.
pub struct SigningBatchError {
    kind: SigningBatchErrorKind,
    item_ordinal: Option<usize>,
}

impl SigningBatchError {
    fn batch(kind: SigningBatchErrorKind) -> Self {
        Self {
            kind,
            item_ordinal: None,
        }
    }

    fn item(kind: SigningBatchErrorKind, item_ordinal: usize) -> Self {
        Self {
            kind,
            item_ordinal: Some(item_ordinal),
        }
    }

    /// Return the stable error category.
    #[must_use]
    pub const fn kind(&self) -> SigningBatchErrorKind {
        self.kind
    }

    /// Return the lowest affected caller ordinal when the category is item-specific.
    #[must_use]
    pub const fn item_ordinal(&self) -> Option<usize> {
        self.item_ordinal
    }
}

impl fmt::Debug for SigningBatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningBatchError")
            .field("kind", &self.kind)
            .field("item_ordinal", &self.item_ordinal)
            .finish()
    }
}

impl fmt::Display for SigningBatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, formatter)
    }
}

impl std::error::Error for SigningBatchError {}

/// A batch scope bound to one exact ES256 signer reference and frozen metadata.
///
/// Construct a new scope if the backend key or its issuer/key identifiers
/// change. The public API always uses the private serial executor and makes no
/// concurrency promise to the signer implementation.
pub struct Es256SignerScope<'s> {
    signer: &'s dyn CredentialSigner,
    identity: FrozenSignerIdentity,
    scope_id: uuid::Uuid,
}

impl fmt::Debug for Es256SignerScope<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Es256SignerScope([redacted])")
    }
}

impl<'s> Es256SignerScope<'s> {
    /// Freeze one signer's ES256 algorithm, issuer identifier, and key identifier.
    pub fn new(signer: &'s dyn CredentialSigner) -> Result<Self, SigningBatchError> {
        let identity = FrozenSignerIdentity::capture(signer)?;
        Ok(Self {
            signer,
            identity,
            scope_id: uuid::Uuid::new_v4(),
        })
    }

    /// Prepare, serially sign, validate, and assemble a caller-ordered batch.
    ///
    /// Every input is prepared before the first signing call. Successful
    /// execution invokes the exact signer once per item and returns credentials
    /// in input order. Structurally valid raw 64-byte P1363 signatures,
    /// including valid high-S signatures, are forwarded byte-for-byte without
    /// normalization to preserve the scalar route contract. Any failure returns
    /// no credential outputs.
    pub fn sign_batch(
        &self,
        inputs: Vec<Es256SigningBatchInput>,
    ) -> Result<Vec<SignedCredential>, SigningBatchError> {
        self.sign_batch_with_components(inputs, &SerialSigningExecutor, &CanonicalAssembler)
    }

    fn sign_batch_with_components(
        &self,
        inputs: Vec<Es256SigningBatchInput>,
        executor: &dyn SigningExecutor,
        assembler: &dyn BatchAssembler,
    ) -> Result<Vec<SignedCredential>, SigningBatchError> {
        self.identity.validate()?;
        validate_unique_routes(&inputs)?;

        let prepared = PreparedSigningBatch::prepare(self, inputs)?;

        // Run only after complete preparation so preparation failures have
        // deterministic precedence and no backend call has occurred.
        if !self.identity.matches(self.signer) {
            return Err(SigningBatchError::batch(
                SigningBatchErrorKind::SignerMetadataChanged,
            ));
        }

        let signatures = {
            let jobs = prepared.jobs();
            let results =
                executor
                    .execute(self.signer, &jobs)
                    .map_err(|error| match error.item_ordinal {
                        Some(ordinal) => {
                            SigningBatchError::item(SigningBatchErrorKind::ExecutorFailed, ordinal)
                        }
                        None => SigningBatchError::batch(SigningBatchErrorKind::ExecutorFailed),
                    })?;
            validate_executor_results(&jobs, results)?
        };

        assemble_credentials(prepared, signatures, assembler)
    }
}

fn validate_unique_routes(inputs: &[Es256SigningBatchInput]) -> Result<(), SigningBatchError> {
    let mut first_ordinals = HashMap::with_capacity(inputs.len());
    let mut lowest_affected_ordinal = None;
    for (ordinal, input) in inputs.iter().enumerate() {
        if let Some(first_ordinal) = first_ordinals.get(&input.route_id()).copied() {
            lowest_affected_ordinal = Some(
                lowest_affected_ordinal
                    .map_or(first_ordinal, |lowest: usize| lowest.min(first_ordinal)),
            );
        } else {
            first_ordinals.insert(input.route_id(), ordinal);
        }
    }
    match lowest_affected_ordinal {
        Some(ordinal) => Err(SigningBatchError::item(
            SigningBatchErrorKind::DuplicateRoute,
            ordinal,
        )),
        None => Ok(()),
    }
}

struct FrozenSignerIdentity {
    algorithm: SigningAlgorithm,
    issuer_id: String,
    kid_url: String,
}

impl FrozenSignerIdentity {
    fn capture(signer: &dyn CredentialSigner) -> Result<Self, SigningBatchError> {
        let algorithm = signer.algorithm();
        let issuer_id = signer.issuer_id().to_owned();
        let kid_url = signer.kid_url();
        let identity = Self {
            algorithm,
            issuer_id,
            kid_url,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), SigningBatchError> {
        if self.algorithm != SigningAlgorithm::ES256
            || self.issuer_id.trim().is_empty()
            || self.kid_url.trim().is_empty()
        {
            return Err(SigningBatchError::batch(
                SigningBatchErrorKind::InvalidScope,
            ));
        }
        Ok(())
    }

    fn matches(&self, signer: &dyn CredentialSigner) -> bool {
        signer.algorithm() == self.algorithm
            && signer.issuer_id() == self.issuer_id
            && signer.kid_url() == self.kid_url
    }

    fn preparation_signer(&self) -> FrozenPreparationSigner<'_> {
        FrozenPreparationSigner { identity: self }
    }
}

struct FrozenPreparationSigner<'a> {
    identity: &'a FrozenSignerIdentity,
}

impl fmt::Debug for FrozenPreparationSigner<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenPreparationSigner([redacted])")
    }
}

impl CredentialSigner for FrozenPreparationSigner<'_> {
    fn sign(&self, _message: &[u8]) -> crate::Oid4vciResult<Vec<u8>> {
        Err(crate::Oid4vciError::SigningError(
            "batch preparation cannot sign".into(),
        ))
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.identity.algorithm
    }

    fn issuer_id(&self) -> &str {
        &self.identity.issuer_id
    }

    fn kid_url(&self) -> String {
        self.identity.kid_url.clone()
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct SigningJobIdentity {
    scope_id: uuid::Uuid,
    batch_id: uuid::Uuid,
    route_id: SigningRouteId,
    job_id: u64,
}

struct PreparedJwtVcBatchItem {
    prepared: PreparedJwtVc,
}

struct PreparedMdocBatchItem {
    prepared: Box<PreparedMdoc>,
}

enum PreparedCredential {
    JwtVc(PreparedJwtVcBatchItem),
    Mdoc(PreparedMdocBatchItem),
}

impl PreparedCredential {
    fn signing_payload(&self) -> &[u8] {
        match self {
            Self::JwtVc(item) => item.prepared.signing_payload(),
            Self::Mdoc(item) => item.prepared.signing_payload(),
        }
    }
}

struct PreparedSigningItem {
    identity: SigningJobIdentity,
    credential: PreparedCredential,
}

struct PreparedSigningBatch {
    items: Vec<PreparedSigningItem>,
}

impl PreparedSigningBatch {
    fn prepare(
        scope: &Es256SignerScope<'_>,
        inputs: Vec<Es256SigningBatchInput>,
    ) -> Result<Self, SigningBatchError> {
        let batch_id = uuid::Uuid::new_v4();
        let preparation_signer = scope.identity.preparation_signer();
        let mut items = Vec::with_capacity(inputs.len());

        for (ordinal, input) in inputs.into_iter().enumerate() {
            let job_id = u64::try_from(ordinal).map_err(|_| {
                SigningBatchError::item(SigningBatchErrorKind::PreparationFailed, ordinal)
            })?;
            let route_id = input.route_id();
            let credential = match input {
                Es256SigningBatchInput::JwtVc(input) => {
                    prepare_jwt_vc(&preparation_signer, &input.claims).map(|prepared| {
                        PreparedCredential::JwtVc(PreparedJwtVcBatchItem { prepared })
                    })
                }
                Es256SigningBatchInput::Mdoc(input) => {
                    prepare_mdoc(&preparation_signer, &input.claims).map(|prepared| {
                        PreparedCredential::Mdoc(PreparedMdocBatchItem {
                            prepared: Box::new(prepared),
                        })
                    })
                }
            }
            .map_err(|_| {
                SigningBatchError::item(SigningBatchErrorKind::PreparationFailed, ordinal)
            })?;

            items.push(PreparedSigningItem {
                identity: SigningJobIdentity {
                    scope_id: scope.scope_id,
                    batch_id,
                    route_id,
                    job_id,
                },
                credential,
            });
        }

        Ok(Self { items })
    }

    fn jobs(&self) -> Vec<SigningJob<'_>> {
        self.items
            .iter()
            .map(|item| SigningJob {
                identity: item.identity,
                payload: item.credential.signing_payload(),
            })
            .collect()
    }
}

struct SigningJob<'a> {
    identity: SigningJobIdentity,
    payload: &'a [u8],
}

struct SigningResult {
    identity: SigningJobIdentity,
    signature: Vec<u8>,
}

struct SigningExecutionError {
    // The private serial executor always knows the failing caller ordinal.
    // `None` remains reserved for a genuinely batch-wide executor failure.
    item_ordinal: Option<usize>,
}

// Module privacy seals this boundary. No public API can select an alternate or
// concurrent executor.
trait SigningExecutor {
    fn execute(
        &self,
        signer: &dyn CredentialSigner,
        jobs: &[SigningJob<'_>],
    ) -> Result<Vec<SigningResult>, SigningExecutionError>;
}

struct SerialSigningExecutor;

impl SigningExecutor for SerialSigningExecutor {
    fn execute(
        &self,
        signer: &dyn CredentialSigner,
        jobs: &[SigningJob<'_>],
    ) -> Result<Vec<SigningResult>, SigningExecutionError> {
        let mut results = Vec::with_capacity(jobs.len());
        for (ordinal, job) in jobs.iter().enumerate() {
            let signature = signer
                .sign(job.payload)
                .map_err(|_| SigningExecutionError {
                    item_ordinal: Some(ordinal),
                })?;
            results.push(SigningResult {
                identity: job.identity,
                signature,
            });
        }
        Ok(results)
    }
}

struct ValidatedSignature([u8; ES256_SIGNATURE_LENGTH]);

fn validate_executor_results(
    jobs: &[SigningJob<'_>],
    results: Vec<SigningResult>,
) -> Result<Vec<ValidatedSignature>, SigningBatchError> {
    if results.len() != jobs.len() {
        return Err(SigningBatchError::batch(
            SigningBatchErrorKind::InvalidExecutorResults,
        ));
    }

    // Validate the complete result envelope before examining signature bytes.
    // Executor-controlled metadata is used only as an opaque full identity;
    // no result-reported ordinal is trusted for indexing or error selection.
    let mut expected = HashMap::with_capacity(jobs.len());
    for (ordinal, job) in jobs.iter().enumerate() {
        if expected.insert(job.identity, ordinal).is_some() {
            return Err(SigningBatchError::batch(
                SigningBatchErrorKind::InvalidExecutorResults,
            ));
        }
    }

    let mut signatures: Vec<Option<Vec<u8>>> =
        std::iter::repeat_with(|| None).take(jobs.len()).collect();
    for result in results {
        let Some(ordinal) = expected.remove(&result.identity) else {
            return Err(SigningBatchError::batch(
                SigningBatchErrorKind::InvalidExecutorResults,
            ));
        };
        if signatures[ordinal].replace(result.signature).is_some() {
            return Err(SigningBatchError::batch(
                SigningBatchErrorKind::InvalidExecutorResults,
            ));
        }
    }
    if !expected.is_empty() || signatures.iter().any(Option::is_none) {
        return Err(SigningBatchError::batch(
            SigningBatchErrorKind::InvalidExecutorResults,
        ));
    }

    signatures
        .into_iter()
        .enumerate()
        .map(|(ordinal, signature)| {
            let signature = signature.expect("the complete envelope was validated");
            let raw: [u8; ES256_SIGNATURE_LENGTH] = signature.try_into().map_err(|_| {
                SigningBatchError::item(SigningBatchErrorKind::InvalidSignature, ordinal)
            })?;
            p256::ecdsa::Signature::from_slice(&raw).map_err(|_| {
                SigningBatchError::item(SigningBatchErrorKind::InvalidSignature, ordinal)
            })?;
            Ok(ValidatedSignature(raw))
        })
        .collect()
}

trait BatchAssembler {
    fn assemble(
        &self,
        ordinal: usize,
        prepared: PreparedCredential,
        signature: &ValidatedSignature,
    ) -> Result<SignedCredential, ()>;
}

struct CanonicalAssembler;

impl BatchAssembler for CanonicalAssembler {
    fn assemble(
        &self,
        _ordinal: usize,
        prepared: PreparedCredential,
        signature: &ValidatedSignature,
    ) -> Result<SignedCredential, ()> {
        match prepared {
            PreparedCredential::JwtVc(item) => Ok(assemble_jwt_vc(item.prepared, &signature.0)),
            PreparedCredential::Mdoc(item) => {
                assemble_mdoc(*item.prepared, &signature.0).map_err(|_| ())
            }
        }
    }
}

fn assemble_credentials(
    prepared: PreparedSigningBatch,
    signatures: Vec<ValidatedSignature>,
    assembler: &dyn BatchAssembler,
) -> Result<Vec<SignedCredential>, SigningBatchError> {
    let mut credentials = Vec::with_capacity(prepared.items.len());
    for (ordinal, (item, signature)) in prepared.items.into_iter().zip(signatures).enumerate() {
        let credential = assembler
            .assemble(ordinal, item.credential, &signature)
            .map_err(|()| {
                SigningBatchError::item(SigningBatchErrorKind::AssemblyFailed, ordinal)
            })?;
        credentials.push(credential);
    }
    Ok(credentials)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::signature::{Signer as _, Verifier as _};

    use super::*;
    use crate::error::{Oid4vciError, Oid4vciResult};
    use crate::types::CredentialPayloadFormat;

    const RAW_ES256_SIGNATURE: [u8; ES256_SIGNATURE_LENGTH] = [1; ES256_SIGNATURE_LENGTH];
    const BACKEND_SECRET: &str = "kms-tenant-secret-route-91";
    const CLAIM_SECRET: &str = "credential-claim-canary";
    const ISSUER_SECRET: &str = "did:example:issuer-private-canary";
    const KID_SECRET: &str = "did:example:issuer-private-canary#key-private-canary";

    struct RecordingSigner {
        calls: Mutex<Vec<Vec<u8>>>,
        metadata_state: AtomicUsize,
        fail_at: Option<usize>,
        initial_algorithm: SigningAlgorithm,
    }

    impl RecordingSigner {
        fn es256() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                metadata_state: AtomicUsize::new(0),
                fail_at: None,
                initial_algorithm: SigningAlgorithm::ES256,
            }
        }

        fn failing_at(ordinal: usize) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                metadata_state: AtomicUsize::new(0),
                fail_at: Some(ordinal),
                initial_algorithm: SigningAlgorithm::ES256,
            }
        }

        fn with_algorithm(algorithm: SigningAlgorithm) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                metadata_state: AtomicUsize::new(0),
                fail_at: None,
                initial_algorithm: algorithm,
            }
        }

        fn drift(&self, metadata_state: usize) {
            self.metadata_state.store(metadata_state, Ordering::SeqCst);
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl fmt::Debug for RecordingSigner {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("RecordingSigner([redacted])")
        }
    }

    impl CredentialSigner for RecordingSigner {
        fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
            let mut calls = self.calls.lock().unwrap();
            let ordinal = calls.len();
            calls.push(message.to_vec());
            if self.fail_at == Some(ordinal) {
                return Err(Oid4vciError::SigningError(BACKEND_SECRET.into()));
            }
            Ok(RAW_ES256_SIGNATURE.to_vec())
        }

        fn algorithm(&self) -> SigningAlgorithm {
            if self.metadata_state.load(Ordering::SeqCst) == 1 {
                SigningAlgorithm::EdDSA
            } else {
                self.initial_algorithm
            }
        }

        fn issuer_id(&self) -> &str {
            if self.metadata_state.load(Ordering::SeqCst) == 2 {
                "did:example:changed"
            } else {
                ISSUER_SECRET
            }
        }

        fn kid_url(&self) -> String {
            if self.metadata_state.load(Ordering::SeqCst) == 3 {
                "did:example:changed#key-2".into()
            } else {
                KID_SECRET.into()
            }
        }
    }

    struct HighSEs256Signer {
        signing_key: p256::ecdsa::SigningKey,
        calls: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    }

    impl HighSEs256Signer {
        fn new() -> Self {
            Self {
                signing_key: p256::ecdsa::SigningKey::from_slice(&[0x42; 32]).unwrap(),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl fmt::Debug for HighSEs256Signer {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("HighSEs256Signer([redacted])")
        }
    }

    impl CredentialSigner for HighSEs256Signer {
        fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
            let signature: p256::ecdsa::Signature = self.signing_key.sign(message);
            let high_s = if signature.normalize_s().is_some() {
                signature
            } else {
                let (r, s) = signature.split_scalars();
                p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-s).to_bytes()).unwrap()
            };
            assert!(
                high_s.normalize_s().is_some(),
                "the compatibility fixture must produce a valid high-S signature"
            );
            let raw = high_s.to_bytes().to_vec();
            self.calls
                .lock()
                .unwrap()
                .push((message.to_vec(), raw.clone()));
            Ok(raw)
        }

        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::ES256
        }

        fn issuer_id(&self) -> &str {
            ISSUER_SECRET
        }

        fn kid_url(&self) -> String {
            KID_SECRET.into()
        }
    }

    fn jwt_claims(label: &str) -> CredentialClaims {
        CredentialClaims {
            subject_id: Some(format!("did:example:holder-{label}")),
            credential_type: format!("{label}Credential"),
            claims: [("label".into(), serde_json::json!(label))].into(),
            expiration_seconds: Some(3_600),
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: CredentialPayloadFormat::W3cVcdmV2JwtVc,
            w3c_context: vec![],
            w3c_types: vec![],
        }
    }

    fn mdoc_claims(label: &str) -> CredentialClaims {
        CredentialClaims {
            subject_id: Some(format!("did:example:holder-{label}")),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: [
                ("family_name".into(), serde_json::json!(label)),
                ("secret".into(), serde_json::json!(CLAIM_SECRET)),
            ]
            .into(),
            expiration_seconds: Some(86_400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: CredentialPayloadFormat::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        }
    }

    fn invalid_mdoc_claims() -> CredentialClaims {
        let mut claims = mdoc_claims("invalid");
        claims
            .claims
            .insert("_mdoc_x5c".into(), serde_json::json!(CLAIM_SECRET));
        claims
    }

    fn jwt_input(route: u64, label: &str) -> Es256SigningBatchInput {
        JwtVcSigningBatchInput::new(SigningRouteId::new(route), jwt_claims(label)).into()
    }

    fn mdoc_input(route: u64, label: &str) -> Es256SigningBatchInput {
        MdocSigningBatchInput::new(SigningRouteId::new(route), mdoc_claims(label)).into()
    }

    fn invalid_mdoc_input(route: u64) -> Es256SigningBatchInput {
        MdocSigningBatchInput::new(SigningRouteId::new(route), invalid_mdoc_claims()).into()
    }

    fn two_jwt_inputs() -> Vec<Es256SigningBatchInput> {
        vec![jwt_input(10, "first"), jwt_input(20, "second")]
    }

    fn assert_error(
        result: Result<Vec<SignedCredential>, SigningBatchError>,
        kind: SigningBatchErrorKind,
        ordinal: Option<usize>,
    ) -> SigningBatchError {
        let error = result.expect_err("batch must fail");
        assert_eq!(error.kind(), kind);
        assert_eq!(error.item_ordinal(), ordinal);
        error
    }

    #[test]
    fn jwt_and_mdoc_sign_complete_payloads_and_preserve_raw_p1363_bytes() {
        let signer = RecordingSigner::es256();
        let scope = Es256SignerScope::new(&signer).unwrap();
        let credentials = scope
            .sign_batch(vec![jwt_input(1, "jwt"), mdoc_input(2, "mdoc")])
            .unwrap();
        let payloads = signer.calls.lock().unwrap();

        assert_eq!(
            payloads.len(),
            2,
            "the signer must run exactly once per item"
        );

        let SignedCredential::JwtVcJson { jwt, .. } = &credentials[0] else {
            panic!("caller order was not preserved")
        };
        let segments: Vec<_> = jwt.split('.').collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(
            payloads[0],
            format!("{}.{}", segments[0], segments[1]).as_bytes()
        );
        assert_eq!(
            URL_SAFE_NO_PAD.decode(segments[2]).unwrap(),
            RAW_ES256_SIGNATURE
        );
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], KID_SECRET);
        assert_eq!(payload["iss"], ISSUER_SECRET);

        let SignedCredential::MsoMdoc {
            issuer_signed_b64, ..
        } = &credentials[1]
        else {
            panic!("caller order was not preserved")
        };
        let issuer_signed_bytes = URL_SAFE_NO_PAD.decode(issuer_signed_b64).unwrap();
        let issuer_signed: isomdl::definitions::IssuerSigned =
            isomdl::cbor::from_slice(&issuer_signed_bytes).unwrap();
        assert_eq!(issuer_signed.issuer_auth.tbs_data(&[]), payloads[1]);
        assert_eq!(issuer_signed.issuer_auth.signature, RAW_ES256_SIGNATURE);
    }

    #[test]
    fn valid_high_s_p1363_signatures_are_preserved_for_jwt_and_mdoc() {
        let signer = HighSEs256Signer::new();
        let scope = Es256SignerScope::new(&signer).unwrap();
        let credentials = scope
            .sign_batch(vec![jwt_input(1, "jwt"), mdoc_input(2, "mdoc")])
            .unwrap();
        let calls = signer.calls.lock().unwrap();

        assert_eq!(calls.len(), 2);
        for (payload, raw_signature) in calls.iter() {
            let signature = p256::ecdsa::Signature::from_slice(raw_signature).unwrap();
            assert!(
                signature.normalize_s().is_some(),
                "the batch must retain the signer's high-S representation"
            );
            signer
                .signing_key
                .verifying_key()
                .verify(payload, &signature)
                .unwrap();
        }

        let SignedCredential::JwtVcJson { jwt, .. } = &credentials[0] else {
            panic!("expected JWT-VC in caller order")
        };
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(jwt.rsplit('.').next().unwrap())
                .unwrap(),
            calls[0].1,
            "JWT assembly must not normalize a valid high-S signature"
        );

        let SignedCredential::MsoMdoc {
            issuer_signed_b64, ..
        } = &credentials[1]
        else {
            panic!("expected mdoc in caller order")
        };
        let issuer_signed_bytes = URL_SAFE_NO_PAD.decode(issuer_signed_b64).unwrap();
        let issuer_signed: isomdl::definitions::IssuerSigned =
            isomdl::cbor::from_slice(&issuer_signed_bytes).unwrap();
        assert_eq!(
            issuer_signed.issuer_auth.signature, calls[1].1,
            "mdoc assembly must not normalize a valid high-S signature"
        );
    }

    #[test]
    fn empty_batch_is_a_noop() {
        let signer = RecordingSigner::failing_at(0);
        let scope = Es256SignerScope::new(&signer).unwrap();
        assert!(scope.sign_batch(vec![]).unwrap().is_empty());
        assert_eq!(signer.call_count(), 0);
    }

    #[test]
    fn invalid_scope_and_duplicate_routes_precede_preparation() {
        let wrong_algorithm = RecordingSigner::with_algorithm(SigningAlgorithm::EdDSA);
        let error =
            Es256SignerScope::new(&wrong_algorithm).expect_err("non-ES256 signer must be rejected");
        assert_eq!(error.kind(), SigningBatchErrorKind::InvalidScope);

        let signer = RecordingSigner::es256();
        let scope = Es256SignerScope::new(&signer).unwrap();
        let error = assert_error(
            scope.sign_batch(vec![invalid_mdoc_input(7), jwt_input(7, "duplicate")]),
            SigningBatchErrorKind::DuplicateRoute,
            Some(0),
        );
        assert_eq!(signer.call_count(), 0);
        assert!(!format!("{error:?}").contains(CLAIM_SECRET));
    }

    #[test]
    fn duplicate_routes_report_the_lowest_first_affected_ordinal() {
        let signer = RecordingSigner::es256();
        let scope = Es256SignerScope::new(&signer).unwrap();

        assert_error(
            scope.sign_batch(vec![
                jwt_input(10, "earliest-group-first"),
                jwt_input(20, "later-group-first"),
                jwt_input(30, "unique"),
                jwt_input(20, "later-group-duplicate"),
                jwt_input(10, "earliest-group-duplicate"),
            ]),
            SigningBatchErrorKind::DuplicateRoute,
            Some(0),
        );
        assert_eq!(signer.call_count(), 0);
    }

    #[test]
    fn all_preparation_completes_before_signing_and_lowest_failure_wins() {
        let signer = RecordingSigner::es256();
        let scope = Es256SignerScope::new(&signer).unwrap();
        assert_error(
            scope.sign_batch(vec![
                jwt_input(1, "valid"),
                invalid_mdoc_input(2),
                invalid_mdoc_input(3),
            ]),
            SigningBatchErrorKind::PreparationFailed,
            Some(1),
        );
        assert_eq!(signer.call_count(), 0);
    }

    #[test]
    fn preparation_failure_precedes_pre_sign_metadata_drift() {
        let signer = RecordingSigner::es256();
        let scope = Es256SignerScope::new(&signer).unwrap();
        signer.drift(1);

        assert_error(
            scope.sign_batch(vec![invalid_mdoc_input(1)]),
            SigningBatchErrorKind::PreparationFailed,
            Some(0),
        );
        assert_error(
            scope.sign_batch(vec![jwt_input(2, "valid")]),
            SigningBatchErrorKind::SignerMetadataChanged,
            None,
        );
        assert_eq!(signer.call_count(), 0);
    }

    #[test]
    fn algorithm_issuer_and_kid_drift_are_all_rejected_before_signing() {
        for metadata_state in 1..=3 {
            let signer = RecordingSigner::es256();
            let scope = Es256SignerScope::new(&signer).unwrap();
            signer.drift(metadata_state);

            assert_error(
                scope.sign_batch(vec![jwt_input(1, "valid")]),
                SigningBatchErrorKind::SignerMetadataChanged,
                None,
            );
            assert_eq!(signer.call_count(), 0);
        }
    }

    #[test]
    fn backend_failure_is_redacted_and_returns_no_partial_outputs() {
        let signer = RecordingSigner::failing_at(1);
        let scope = Es256SignerScope::new(&signer).unwrap();
        let error = assert_error(
            scope.sign_batch(two_jwt_inputs()),
            SigningBatchErrorKind::ExecutorFailed,
            Some(1),
        );

        assert_eq!(signer.call_count(), 2, "the serial executor must not retry");
        let display = error.to_string();
        let debug = format!("{error:?}");
        for secret in [BACKEND_SECRET, CLAIM_SECRET, ISSUER_SECRET, KID_SECRET] {
            assert!(!display.contains(secret));
            assert!(!debug.contains(secret));
        }
    }

    struct BatchFailingExecutor;

    impl SigningExecutor for BatchFailingExecutor {
        fn execute(
            &self,
            _signer: &dyn CredentialSigner,
            _jobs: &[SigningJob<'_>],
        ) -> Result<Vec<SigningResult>, SigningExecutionError> {
            Err(SigningExecutionError { item_ordinal: None })
        }
    }

    #[test]
    fn genuinely_batch_wide_executor_failure_has_no_item_ordinal() {
        let signer = RecordingSigner::es256();
        let scope = Es256SignerScope::new(&signer).unwrap();
        assert_error(
            scope.sign_batch_with_components(
                two_jwt_inputs(),
                &BatchFailingExecutor,
                &CanonicalAssembler,
            ),
            SigningBatchErrorKind::ExecutorFailed,
            None,
        );
        assert_eq!(signer.call_count(), 0);
    }

    #[derive(Clone, Copy)]
    enum ResultFault {
        Missing,
        Duplicate,
        Unexpected,
        WrongScope,
        WrongBatch,
        WrongRoute,
        Reordered,
        WrongLength,
        WrongEncoding,
        TwoInvalidSignatures,
        InvalidSignatureAndDuplicateIdentity,
    }

    struct FaultingExecutor(ResultFault);

    impl SigningExecutor for FaultingExecutor {
        fn execute(
            &self,
            signer: &dyn CredentialSigner,
            jobs: &[SigningJob<'_>],
        ) -> Result<Vec<SigningResult>, SigningExecutionError> {
            let mut results = SerialSigningExecutor.execute(signer, jobs)?;
            match self.0 {
                ResultFault::Missing => {
                    results.pop();
                }
                ResultFault::Duplicate => {
                    results[1].identity = results[0].identity;
                }
                ResultFault::Unexpected => {
                    results[0].identity.job_id = u64::MAX;
                }
                ResultFault::WrongScope => {
                    results[0].identity.scope_id = uuid::Uuid::nil();
                }
                ResultFault::WrongBatch => {
                    results[0].identity.batch_id = uuid::Uuid::nil();
                }
                ResultFault::WrongRoute => {
                    results[0].identity.route_id = SigningRouteId::new(u64::MAX);
                }
                ResultFault::Reordered => results.reverse(),
                ResultFault::WrongLength => {
                    results[0].signature.pop();
                }
                ResultFault::WrongEncoding => {
                    results[0].signature.fill(0);
                }
                ResultFault::TwoInvalidSignatures => {
                    results[1].signature.pop();
                    results[2].signature.clear();
                    results.reverse();
                }
                ResultFault::InvalidSignatureAndDuplicateIdentity => {
                    results[0].signature.clear();
                    results[1].identity = results[0].identity;
                }
            }
            Ok(results)
        }
    }

    #[test]
    fn executor_result_envelope_rejects_missing_duplicate_unexpected_and_wrong_identity() {
        for fault in [
            ResultFault::Missing,
            ResultFault::Duplicate,
            ResultFault::Unexpected,
            ResultFault::WrongScope,
            ResultFault::WrongBatch,
            ResultFault::WrongRoute,
            ResultFault::InvalidSignatureAndDuplicateIdentity,
        ] {
            let signer = RecordingSigner::es256();
            let scope = Es256SignerScope::new(&signer).unwrap();
            assert_error(
                scope.sign_batch_with_components(
                    two_jwt_inputs(),
                    &FaultingExecutor(fault),
                    &CanonicalAssembler,
                ),
                SigningBatchErrorKind::InvalidExecutorResults,
                None,
            );
        }
    }

    #[test]
    fn reordered_executor_results_restore_caller_order() {
        let signer = RecordingSigner::es256();
        let scope = Es256SignerScope::new(&signer).unwrap();
        let credentials = scope
            .sign_batch_with_components(
                vec![mdoc_input(1, "first"), jwt_input(2, "second")],
                &FaultingExecutor(ResultFault::Reordered),
                &CanonicalAssembler,
            )
            .unwrap();
        assert!(matches!(credentials[0], SignedCredential::MsoMdoc { .. }));
        assert!(matches!(credentials[1], SignedCredential::JwtVcJson { .. }));
    }

    #[test]
    fn signature_validation_runs_after_envelope_and_in_expected_order() {
        for fault in [ResultFault::WrongLength, ResultFault::WrongEncoding] {
            let signer = RecordingSigner::es256();
            let scope = Es256SignerScope::new(&signer).unwrap();
            assert_error(
                scope.sign_batch_with_components(
                    two_jwt_inputs(),
                    &FaultingExecutor(fault),
                    &CanonicalAssembler,
                ),
                SigningBatchErrorKind::InvalidSignature,
                Some(0),
            );
        }

        let signer = RecordingSigner::es256();
        let scope = Es256SignerScope::new(&signer).unwrap();
        assert_error(
            scope.sign_batch_with_components(
                vec![
                    jwt_input(1, "valid"),
                    jwt_input(2, "invalid-first"),
                    jwt_input(3, "invalid-second"),
                ],
                &FaultingExecutor(ResultFault::TwoInvalidSignatures),
                &CanonicalAssembler,
            ),
            SigningBatchErrorKind::InvalidSignature,
            Some(1),
        );
    }

    struct FailingAssembler {
        fail_at: HashSet<usize>,
        calls: AtomicUsize,
    }

    impl BatchAssembler for FailingAssembler {
        fn assemble(
            &self,
            ordinal: usize,
            prepared: PreparedCredential,
            signature: &ValidatedSignature,
        ) -> Result<SignedCredential, ()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_at.contains(&ordinal) {
                Err(())
            } else {
                CanonicalAssembler.assemble(ordinal, prepared, signature)
            }
        }
    }

    #[test]
    fn assembly_reports_lowest_ordinal_and_returns_no_partial_outputs() {
        let signer = RecordingSigner::es256();
        let scope = Es256SignerScope::new(&signer).unwrap();
        let assembler = FailingAssembler {
            fail_at: [1, 2].into(),
            calls: AtomicUsize::new(0),
        };
        assert_error(
            scope.sign_batch_with_components(
                vec![
                    jwt_input(1, "assembled"),
                    jwt_input(2, "first-failure"),
                    jwt_input(3, "later-failure"),
                ],
                &SerialSigningExecutor,
                &assembler,
            ),
            SigningBatchErrorKind::AssemblyFailed,
            Some(1),
        );
        assert_eq!(assembler.calls.load(Ordering::SeqCst), 2);
        assert_eq!(signer.call_count(), 3);
    }

    #[test]
    fn public_diagnostics_are_fixed_and_redacted() {
        let signer = RecordingSigner::es256();
        let scope = Es256SignerScope::new(&signer).unwrap();
        let route = SigningRouteId::new(91);
        let jwt = JwtVcSigningBatchInput::new(route, jwt_claims(CLAIM_SECRET));
        let mdoc = MdocSigningBatchInput::new(route, mdoc_claims(CLAIM_SECRET));
        let enum_input = jwt_input(92, CLAIM_SECRET);

        assert_eq!(format!("{scope:?}"), "Es256SignerScope([redacted])");
        assert_eq!(format!("{route:?}"), "SigningRouteId([redacted])");
        assert_eq!(format!("{jwt:?}"), "JwtVcSigningBatchInput([redacted])");
        assert_eq!(format!("{mdoc:?}"), "MdocSigningBatchInput([redacted])");
        assert_eq!(
            format!("{enum_input:?}"),
            "Es256SigningBatchInput::JwtVc([redacted])"
        );

        for (kind, debug, display) in [
            (
                SigningBatchErrorKind::InvalidScope,
                "InvalidScope",
                "ES256 signing batch scope is invalid",
            ),
            (
                SigningBatchErrorKind::DuplicateRoute,
                "DuplicateRoute",
                "ES256 signing batch contains a duplicate route",
            ),
            (
                SigningBatchErrorKind::PreparationFailed,
                "PreparationFailed",
                "ES256 signing batch preparation failed",
            ),
            (
                SigningBatchErrorKind::SignerMetadataChanged,
                "SignerMetadataChanged",
                "ES256 signing batch signer metadata changed",
            ),
            (
                SigningBatchErrorKind::ExecutorFailed,
                "ExecutorFailed",
                "ES256 signing batch execution failed",
            ),
            (
                SigningBatchErrorKind::InvalidExecutorResults,
                "InvalidExecutorResults",
                "ES256 signing batch results are invalid",
            ),
            (
                SigningBatchErrorKind::InvalidSignature,
                "InvalidSignature",
                "ES256 signing batch signature is invalid",
            ),
            (
                SigningBatchErrorKind::AssemblyFailed,
                "AssemblyFailed",
                "ES256 signing batch assembly failed",
            ),
        ] {
            assert_eq!(format!("{kind:?}"), debug);
            assert_eq!(kind.to_string(), display);
        }

        let error = SigningBatchError::item(SigningBatchErrorKind::PreparationFailed, 4);
        assert_eq!(error.to_string(), "ES256 signing batch preparation failed");
        assert_eq!(
            format!("{error:?}"),
            "SigningBatchError { kind: PreparationFailed, item_ordinal: Some(4) }"
        );

        let diagnostics =
            format!("{scope:?} {route:?} {jwt:?} {mdoc:?} {enum_input:?} {error:?} {error}");
        for secret in [
            CLAIM_SECRET,
            ISSUER_SECRET,
            KID_SECRET,
            BACKEND_SECRET,
            "91",
            "92",
        ] {
            assert!(!diagnostics.contains(secret));
        }
    }
}
