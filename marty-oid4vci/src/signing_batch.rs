//! Fail-closed batching for complete ES256 credential signatures.
//!
//! A batch is bound to one exact [`CredentialSigner`] reference. The scope
//! freezes the signer's public routing metadata, canonical format preparation
//! runs on the caller, and the private executor receives only borrowed complete
//! signing payloads plus that same signer reference. Results are restored by a
//! per-call identity envelope instead of executor return order.
//!
//! [`Es256SignerScope`] remains the serial default. Native callers may opt into
//! `ConcurrentEs256SignerScope` only with a signer that explicitly implements
//! `BoundedConcurrentCredentialSigner`. [`Send`] and [`Sync`] alone never
//! authorize concurrent backend requests. The signer owner must also keep the
//! key bound to `issuer_id` and `kid_url` immutable for the lifetime of either
//! scope. Metadata checks cannot detect a backend key rotation that preserves
//! those values.

use std::collections::HashMap;
use std::fmt;

#[cfg(not(target_family = "wasm"))]
use std::cell::Cell;
#[cfg(not(target_family = "wasm"))]
use std::marker::PhantomData;
#[cfg(not(target_family = "wasm"))]
use std::num::NonZeroUsize;
#[cfg(not(target_family = "wasm"))]
use std::panic::{catch_unwind, resume_unwind};
#[cfg(not(target_family = "wasm"))]
use std::sync::Mutex;

use crate::formats::jwt_vc::{assemble_jwt_vc, prepare_jwt_vc, PreparedJwtVc};
use crate::formats::mdoc::{assemble_mdoc, prepare_mdoc, PreparedMdoc};
use crate::signer::CredentialSigner;
use crate::types::{CredentialClaims, SignedCredential, SigningAlgorithm};

const ES256_SIGNATURE_LENGTH: usize = 64;

/// The library-level ceiling for native concurrent signing workers.
///
/// A signer may authorize fewer workers. The executor never starts more than
/// the signer's frozen authorization, this ceiling, or the number of jobs.
#[cfg(not(target_family = "wasm"))]
pub const MAX_CONCURRENT_SIGNING_WORKERS: usize = 64;

/// Explicit authorization for bounded concurrent calls to a credential signer.
///
/// This trait has deliberately no blanket implementation. Implementing it is a
/// stronger promise than [`Send`] + [`Sync`]: `sign` supports simultaneous calls
/// up to the returned bound, shared access is unwind-safe, and the signing key
/// plus ES256 issuer/key identity remain immutable while a
/// [`ConcurrentEs256SignerScope`] exclusively borrows the signer.
/// Backend-specific aliases that reach the same key, queue, session, or rate
/// limit must enforce their own shared bound.
///
/// A signer panic is outside the redacted [`SigningBatchError`] contract. A
/// capability implementation must not place secrets in panic messages or
/// payloads because Rust's panic hook observes them before this library can
/// perform scoped-worker cleanup.
///
/// [`crate::types::IssuerKey`] is intentionally not opted in automatically.
/// Callers that have audited a signer implementation and its backend may expose
/// this capability through an owned newtype.
///
/// The concurrent path is native-only. WebAssembly callers continue to use the
/// serial [`Es256SignerScope`].
#[cfg(not(target_family = "wasm"))]
pub trait BoundedConcurrentCredentialSigner: CredentialSigner + std::panic::RefUnwindSafe {
    /// Authorize the maximum number of simultaneous `sign` calls.
    fn max_concurrent_signing_workers(&self) -> NonZeroUsize;
}

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

        let prepared = PreparedSigningBatch::prepare(&self.identity, self.scope_id, inputs)?;

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

/// A native, explicitly authorized concurrent ES256 signing scope.
///
/// This scope is bound to the exact [`BoundedConcurrentCredentialSigner`]
/// reference supplied to [`Self::new`]. Its algorithm, issuer identifier, key
/// identifier, and worker authorization are frozen once. Constructing this
/// type does not change [`Es256SignerScope`]'s serial behavior.
///
/// The exclusive borrow and non-[`Sync`] scope enforce one aggregate bound for
/// this signer object in safe Rust. Distinct signer objects that alias the same
/// backend cannot be detected by this library; enforcing their shared global
/// limit is part of the capability implementation's contract.
///
/// Two scopes cannot lease the same signer at once:
///
/// ```compile_fail
/// use marty_oid4vci::signing_batch::{
///     BoundedConcurrentCredentialSigner, ConcurrentEs256SignerScope,
/// };
///
/// fn overlapping_scopes(signer: &mut dyn BoundedConcurrentCredentialSigner) {
///     let first = ConcurrentEs256SignerScope::new(signer).unwrap();
///     let second = ConcurrentEs256SignerScope::new(signer).unwrap();
///     drop((first, second));
/// }
/// ```
///
/// A scope also cannot be shared between caller threads:
///
/// ```compile_fail
/// use marty_oid4vci::signing_batch::ConcurrentEs256SignerScope;
///
/// fn require_sync<T: Sync>() {}
/// fn scope_is_not_sync() {
///     require_sync::<ConcurrentEs256SignerScope<'static>>();
/// }
/// ```
#[cfg(not(target_family = "wasm"))]
pub struct ConcurrentEs256SignerScope<'s> {
    signer: &'s mut dyn BoundedConcurrentCredentialSigner,
    identity: FrozenSignerIdentity,
    scope_id: uuid::Uuid,
    worker_limit: NonZeroUsize,
    // The exclusive signer borrow prevents a second safe scope. This marker
    // additionally prevents sharing one scope between caller threads, so its
    // frozen worker limit is also the aggregate limit for that signer lease.
    _not_sync: PhantomData<Cell<()>>,
}

#[cfg(not(target_family = "wasm"))]
impl fmt::Debug for ConcurrentEs256SignerScope<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConcurrentEs256SignerScope([redacted])")
    }
}

#[cfg(not(target_family = "wasm"))]
impl<'s> ConcurrentEs256SignerScope<'s> {
    /// Exclusively lease one explicitly concurrent signer and freeze its identity
    /// and worker bound.
    ///
    /// The mutable borrow prevents another safe serial or concurrent scope from
    /// using this exact signer until the returned scope is dropped. The scope is
    /// intentionally not [`Sync`], preventing simultaneous batch invocations
    /// from multiplying the frozen worker limit.
    pub fn new(
        signer: &'s mut dyn BoundedConcurrentCredentialSigner,
    ) -> Result<Self, SigningBatchError> {
        let identity = FrozenSignerIdentity::capture(&*signer)?;
        let authorized_workers = signer.max_concurrent_signing_workers().get();
        let worker_limit =
            NonZeroUsize::new(authorized_workers.min(MAX_CONCURRENT_SIGNING_WORKERS))
                .expect("the signer authorization and library ceiling are non-zero");
        Ok(Self {
            signer,
            identity,
            scope_id: uuid::Uuid::new_v4(),
            worker_limit,
            _not_sync: PhantomData,
        })
    }

    /// Prepare, concurrently sign, validate, and assemble a caller-ordered batch.
    ///
    /// Canonical preparation of every item completes on the caller before a
    /// worker starts. At most the frozen authorized worker count runs at once.
    /// When every `sign` call returns normally, each submitted job receives
    /// exactly one call even when another call returns an error; all workers are
    /// scoped and joined before this method returns. Results are collected in
    /// arbitrary completion order, validated as a complete identity bijection,
    /// and restored to caller order before signature validation or assembly.
    /// Any returned failure produces no credentials, with the deterministic
    /// lowest affected caller ordinal.
    ///
    /// A signer panic is outside the returned-error and metadata-error
    /// precedence contract. In unwind-enabled builds, the executor stops
    /// dispatching work after observing a panic, joins every worker, and resumes
    /// the first captured panic. Already in-flight calls may finish, while jobs
    /// not yet started may remain uncalled. Neither the panic hook nor its
    /// payload is redacted by this API. A `panic=abort` build cannot perform
    /// this cleanup.
    pub fn sign_batch_concurrently(
        &self,
        inputs: Vec<Es256SigningBatchInput>,
    ) -> Result<Vec<SignedCredential>, SigningBatchError> {
        self.sign_batch_with_components(inputs, &CanonicalAssembler)
    }

    fn sign_batch_with_components(
        &self,
        inputs: Vec<Es256SigningBatchInput>,
        assembler: &dyn BatchAssembler,
    ) -> Result<Vec<SignedCredential>, SigningBatchError> {
        self.identity.validate()?;
        validate_unique_routes(&inputs)?;

        let prepared = PreparedSigningBatch::prepare(&self.identity, self.scope_id, inputs)?;

        // Canonical preparation has deterministic precedence and has completed
        // before either metadata validation or worker creation.
        let signer: &dyn BoundedConcurrentCredentialSigner = &*self.signer;
        if !self.identity.matches(signer) {
            return Err(SigningBatchError::batch(
                SigningBatchErrorKind::SignerMetadataChanged,
            ));
        }

        let signatures = {
            let jobs = prepared.jobs();
            let executor = ConcurrentSigningExecutor {
                signer,
                worker_limit: self.worker_limit,
            };
            let execution = executor.execute(signer, &jobs);

            // The capability promises immutable identity. Re-check after every
            // scoped worker has joined so observable drift fails closed without
            // cancelling or retrying any submitted job. Drift has precedence
            // even when execution itself failed.
            if !self.identity.matches(signer) {
                return Err(SigningBatchError::batch(
                    SigningBatchErrorKind::SignerMetadataChanged,
                ));
            }

            let results = execution.map_err(|error| match error.item_ordinal {
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
        identity: &FrozenSignerIdentity,
        scope_id: uuid::Uuid,
        inputs: Vec<Es256SigningBatchInput>,
    ) -> Result<Self, SigningBatchError> {
        let batch_id = uuid::Uuid::new_v4();
        let preparation_signer = identity.preparation_signer();
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
                    scope_id,
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
    outcome: SigningOutcome,
}

enum SigningOutcome {
    Signature(Vec<u8>),
    #[cfg_attr(target_family = "wasm", allow(dead_code))]
    Failed,
}

struct SigningExecutionError {
    // Serial failures know their caller ordinal. `None` is reserved for a
    // genuinely batch-wide private-executor failure.
    item_ordinal: Option<usize>,
}

// Module privacy seals this boundary. Public callers select only the serial
// default or the explicitly capable bounded-concurrent scope.
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
                outcome: SigningOutcome::Signature(signature),
            });
        }
        Ok(results)
    }
}

#[cfg(not(target_family = "wasm"))]
struct ConcurrentSigningExecutor<'s> {
    // Holding the explicitly capable signer here makes the authorization exact:
    // this executor cannot be constructed from an arbitrary CredentialSigner.
    signer: &'s dyn BoundedConcurrentCredentialSigner,
    worker_limit: NonZeroUsize,
}

#[cfg(not(target_family = "wasm"))]
impl SigningExecutor for ConcurrentSigningExecutor<'_> {
    fn execute(
        &self,
        _signer: &dyn CredentialSigner,
        jobs: &[SigningJob<'_>],
    ) -> Result<Vec<SigningResult>, SigningExecutionError> {
        if jobs.is_empty() {
            return Ok(Vec::new());
        }

        let worker_count = self.worker_limit.get().min(jobs.len());
        let execution_state = ConcurrentExecutionState::new();

        let results = std::thread::scope(|scope| {
            // The caller is always one worker. Fallible scoped spawning may
            // reduce parallelism, but cannot strand jobs or detach work.
            let mut handles = Vec::with_capacity(worker_count.saturating_sub(1));
            for _ in 1..worker_count {
                if let Ok(handle) = std::thread::Builder::new()
                    .name("marty-es256-signing".into())
                    .spawn_scoped(scope, || {
                        execute_concurrent_signing_worker_boundary(
                            self.signer,
                            jobs,
                            &execution_state,
                        )
                    })
                {
                    handles.push(handle);
                }
            }

            let mut results =
                execute_concurrent_signing_worker_boundary(self.signer, jobs, &execution_state);
            for handle in handles {
                match handle.join() {
                    Ok(mut worker_results) => results.append(&mut worker_results),
                    // The boundary catches the complete worker body. Retain a
                    // defensive join path so an unexpected wrapper panic still
                    // stops dispatch and is resumed only after every join.
                    Err(payload) => execution_state.record_panic(payload),
                }
            }

            results
        });

        if let Some(payload) = execution_state.take_first_panic() {
            // `resume_unwind` does not run the panic hook a second time. The
            // original hook already ran at the signer boundary and is outside
            // this API's redacted Result contract.
            resume_unwind(payload);
        }

        Ok(results)
    }
}

#[cfg(not(target_family = "wasm"))]
struct ConcurrentExecutionState {
    inner: Mutex<ConcurrentExecutionStateInner>,
}

#[cfg(not(target_family = "wasm"))]
struct ConcurrentExecutionStateInner {
    next_ordinal: usize,
    stopped: bool,
    first_panic: Option<Box<dyn std::any::Any + Send + 'static>>,
}

#[cfg(not(target_family = "wasm"))]
impl ConcurrentExecutionState {
    fn new() -> Self {
        Self {
            inner: Mutex::new(ConcurrentExecutionStateInner {
                next_ordinal: 0,
                stopped: false,
                first_panic: None,
            }),
        }
    }

    fn claim(&self, job_count: usize) -> Option<usize> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inner.stopped || inner.next_ordinal >= job_count {
            return None;
        }
        let ordinal = inner.next_ordinal;
        inner.next_ordinal += 1;
        Some(ordinal)
    }

    fn record_panic(&self, payload: Box<dyn std::any::Any + Send + 'static>) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.stopped = true;
        if inner.first_panic.is_none() {
            inner.first_panic = Some(payload);
        }
    }

    fn take_first_panic(&self) -> Option<Box<dyn std::any::Any + Send + 'static>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .first_panic
            .take()
    }
}

#[cfg(not(target_family = "wasm"))]
fn execute_concurrent_signing_worker_boundary(
    signer: &dyn BoundedConcurrentCredentialSigner,
    jobs: &[SigningJob<'_>],
    execution_state: &ConcurrentExecutionState,
) -> Vec<SigningResult> {
    match catch_unwind(|| execute_concurrent_signing_worker(signer, jobs, execution_state)) {
        Ok(results) => results,
        Err(payload) => {
            // Catch only at the complete worker boundary: the panicking worker
            // is never reused. Linearized dispatch stops immediately, while
            // already-claimed calls in other workers are allowed to finish.
            execution_state.record_panic(payload);
            Vec::new()
        }
    }
}

#[cfg(not(target_family = "wasm"))]
fn execute_concurrent_signing_worker(
    signer: &dyn BoundedConcurrentCredentialSigner,
    jobs: &[SigningJob<'_>],
    execution_state: &ConcurrentExecutionState,
) -> Vec<SigningResult> {
    let mut results = Vec::new();
    while let Some(ordinal) = execution_state.claim(jobs.len()) {
        let job = &jobs[ordinal];

        // Do not cancel or retry: each claimed job crosses the signer boundary
        // exactly once. Ordinary returned errors do not stop dispatch. A panic
        // unwinds this whole worker to the outer cleanup boundary, so this
        // signer reference is not used again by the panicking worker.
        let outcome = match signer.sign(job.payload) {
            Ok(signature) => SigningOutcome::Signature(signature),
            Err(_) => SigningOutcome::Failed,
        };
        results.push(SigningResult {
            identity: job.identity,
            outcome,
        });
    }
    results
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

    let mut outcomes: Vec<Option<SigningOutcome>> =
        std::iter::repeat_with(|| None).take(jobs.len()).collect();
    for result in results {
        let Some(ordinal) = expected.remove(&result.identity) else {
            return Err(SigningBatchError::batch(
                SigningBatchErrorKind::InvalidExecutorResults,
            ));
        };
        if outcomes[ordinal].replace(result.outcome).is_some() {
            return Err(SigningBatchError::batch(
                SigningBatchErrorKind::InvalidExecutorResults,
            ));
        }
    }
    if !expected.is_empty() || outcomes.iter().any(Option::is_none) {
        return Err(SigningBatchError::batch(
            SigningBatchErrorKind::InvalidExecutorResults,
        ));
    }

    // Interpret executor outcomes only after validating the complete identity
    // envelope. Backend failures have category precedence and are reported at
    // the lowest expected ordinal independent of worker completion order.
    if let Some(ordinal) = outcomes
        .iter()
        .position(|outcome| matches!(outcome, Some(SigningOutcome::Failed)))
    {
        return Err(SigningBatchError::item(
            SigningBatchErrorKind::ExecutorFailed,
            ordinal,
        ));
    }

    outcomes
        .into_iter()
        .enumerate()
        .map(|(ordinal, outcome)| {
            let Some(SigningOutcome::Signature(signature)) = outcome else {
                unreachable!("the complete envelope and backend outcomes were validated")
            };
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

    #[cfg(not(target_family = "wasm"))]
    use std::num::NonZeroUsize;
    #[cfg(not(target_family = "wasm"))]
    use std::sync::atomic::AtomicBool;
    #[cfg(not(target_family = "wasm"))]
    use std::sync::Arc;
    #[cfg(not(target_family = "wasm"))]
    use std::time::{Duration, Instant};

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::signature::{Signer as _, Verifier as _};

    use super::*;
    use crate::error::{Oid4vciError, Oid4vciResult};
    use crate::types::CredentialPayloadFormat;

    const RAW_ES256_SIGNATURE: [u8; ES256_SIGNATURE_LENGTH] = [1; ES256_SIGNATURE_LENGTH];
    const BACKEND_SECRET: &str = "kms-tenant-secret-route-91";
    #[cfg(not(target_family = "wasm"))]
    const TEST_SIGNER_PANIC: &str = "intentional concurrent signer test panic";
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

    #[cfg(not(target_family = "wasm"))]
    impl BoundedConcurrentCredentialSigner for HighSEs256Signer {
        fn max_concurrent_signing_workers(&self) -> NonZeroUsize {
            NonZeroUsize::new(2).unwrap()
        }
    }

    #[cfg(not(target_family = "wasm"))]
    struct ActiveCallGuard<'a>(&'a AtomicUsize);

    #[cfg(not(target_family = "wasm"))]
    impl Drop for ActiveCallGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[cfg(not(target_family = "wasm"))]
    struct ConcurrentTestSigner {
        signing_key: p256::ecdsa::SigningKey,
        calls: Mutex<Vec<Vec<u8>>>,
        active_calls: AtomicUsize,
        peak_calls: AtomicUsize,
        metadata_state: Arc<AtomicUsize>,
        max_workers: NonZeroUsize,
        schedule_seed: u64,
        fail_labels: HashSet<&'static str>,
        failure_completion: Mutex<Vec<String>>,
        drift_on_call: Option<usize>,
    }

    #[cfg(not(target_family = "wasm"))]
    impl ConcurrentTestSigner {
        fn new(max_workers: usize, schedule_seed: u64) -> Self {
            Self {
                signing_key: p256::ecdsa::SigningKey::from_slice(&[0x24; 32]).unwrap(),
                calls: Mutex::new(Vec::new()),
                active_calls: AtomicUsize::new(0),
                peak_calls: AtomicUsize::new(0),
                metadata_state: Arc::new(AtomicUsize::new(0)),
                max_workers: NonZeroUsize::new(max_workers).unwrap(),
                schedule_seed,
                fail_labels: HashSet::new(),
                failure_completion: Mutex::new(Vec::new()),
                drift_on_call: None,
            }
        }

        fn with_fail_labels(mut self, labels: impl IntoIterator<Item = &'static str>) -> Self {
            self.fail_labels.extend(labels);
            self
        }

        fn with_drift_on_call(mut self, call: usize) -> Self {
            self.drift_on_call = Some(call);
            self
        }

        fn metadata_handle(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.metadata_state)
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn unique_call_count(&self) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .collect::<HashSet<_>>()
                .len()
        }

        fn peak_calls(&self) -> usize {
            self.peak_calls.load(Ordering::SeqCst)
        }
    }

    #[cfg(not(target_family = "wasm"))]
    impl fmt::Debug for ConcurrentTestSigner {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("ConcurrentTestSigner([redacted])")
        }
    }

    #[cfg(not(target_family = "wasm"))]
    fn jwt_label_from_signing_payload(message: &[u8]) -> Option<String> {
        let message = std::str::from_utf8(message).ok()?;
        let payload = message.split('.').nth(1)?;
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        payload["vc"]["credentialSubject"]["label"]
            .as_str()
            .map(str::to_owned)
    }

    #[cfg(not(target_family = "wasm"))]
    impl CredentialSigner for ConcurrentTestSigner {
        fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
            let active = self.active_calls.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak_calls.fetch_max(active, Ordering::SeqCst);
            let _active_call = ActiveCallGuard(&self.active_calls);

            let call_number = {
                let mut calls = self.calls.lock().unwrap();
                calls.push(message.to_vec());
                calls.len()
            };
            if self.drift_on_call == Some(call_number) {
                self.metadata_state.store(2, Ordering::SeqCst);
            }

            let label = jwt_label_from_signing_payload(message);
            let mut schedule = self.schedule_seed;
            for byte in message.iter().step_by(17) {
                schedule = schedule.rotate_left(5) ^ u64::from(*byte);
                schedule = schedule.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            }
            let delay_ms = match label.as_deref() {
                Some("failure-2") => 20,
                Some("failure-7") => 0,
                _ => 1 + schedule % 3,
            };
            if delay_ms == 0 {
                std::thread::yield_now();
            } else {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }

            if label
                .as_deref()
                .is_some_and(|label| self.fail_labels.contains(label))
            {
                self.failure_completion.lock().unwrap().push(label.unwrap());
                return Err(Oid4vciError::SigningError(BACKEND_SECRET.into()));
            }

            let signature: p256::ecdsa::Signature = self.signing_key.sign(message);
            Ok(signature.to_bytes().to_vec())
        }

        fn algorithm(&self) -> SigningAlgorithm {
            if self.metadata_state.load(Ordering::SeqCst) == 1 {
                SigningAlgorithm::EdDSA
            } else {
                SigningAlgorithm::ES256
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

    #[cfg(not(target_family = "wasm"))]
    impl BoundedConcurrentCredentialSigner for ConcurrentTestSigner {
        fn max_concurrent_signing_workers(&self) -> NonZeroUsize {
            self.max_workers
        }
    }

    #[cfg(not(target_family = "wasm"))]
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum PanickingWorker {
        Caller,
        Spawned,
    }

    #[cfg(not(target_family = "wasm"))]
    struct PanickingConcurrentSigner {
        signing_key: p256::ecdsa::SigningKey,
        calls: Mutex<Vec<Vec<u8>>>,
        active_calls: AtomicUsize,
        peak_calls: AtomicUsize,
        max_workers: NonZeroUsize,
        panicking_worker: PanickingWorker,
        panic_once: AtomicBool,
        caller_started: AtomicBool,
        spawned_started: AtomicBool,
        peer_completed: AtomicBool,
    }

    #[cfg(not(target_family = "wasm"))]
    impl PanickingConcurrentSigner {
        fn new(panicking_worker: PanickingWorker, max_workers: usize) -> Self {
            Self {
                signing_key: p256::ecdsa::SigningKey::from_slice(&[0x35; 32]).unwrap(),
                calls: Mutex::new(Vec::new()),
                active_calls: AtomicUsize::new(0),
                peak_calls: AtomicUsize::new(0),
                max_workers: NonZeroUsize::new(max_workers).unwrap(),
                panicking_worker,
                panic_once: AtomicBool::new(true),
                caller_started: AtomicBool::new(false),
                spawned_started: AtomicBool::new(false),
                peer_completed: AtomicBool::new(false),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn unique_call_count(&self) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .collect::<HashSet<_>>()
                .len()
        }

        fn peak_calls(&self) -> usize {
            self.peak_calls.load(Ordering::SeqCst)
        }

        fn wait_for_peer(&self, peer_started: &AtomicBool) {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !peer_started.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert!(
                peer_started.load(Ordering::SeqCst),
                "both concurrent test workers must enter the signer"
            );
        }
    }

    #[cfg(not(target_family = "wasm"))]
    impl fmt::Debug for PanickingConcurrentSigner {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("PanickingConcurrentSigner([redacted])")
        }
    }

    #[cfg(not(target_family = "wasm"))]
    impl CredentialSigner for PanickingConcurrentSigner {
        fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
            let active = self.active_calls.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak_calls.fetch_max(active, Ordering::SeqCst);
            let _active_call = ActiveCallGuard(&self.active_calls);
            self.calls.lock().unwrap().push(message.to_vec());
            let is_spawned_worker = std::thread::current().name() == Some("marty-es256-signing");

            if is_spawned_worker {
                self.spawned_started.store(true, Ordering::SeqCst);
                self.wait_for_peer(&self.caller_started);
            } else if self.max_workers.get() > 1 {
                self.caller_started.store(true, Ordering::SeqCst);
                self.wait_for_peer(&self.spawned_started);
            } else {
                self.caller_started.store(true, Ordering::SeqCst);
            }

            let should_panic = matches!(
                (self.panicking_worker, is_spawned_worker),
                (PanickingWorker::Caller, false) | (PanickingWorker::Spawned, true)
            );
            if should_panic && self.panic_once.swap(false, Ordering::SeqCst) {
                panic!("{TEST_SIGNER_PANIC}");
            }

            // Keep the peer call in flight until the selected worker has
            // unwound into the executor boundary. The API must join this call
            // before it resumes the selected panic.
            std::thread::sleep(Duration::from_millis(25));
            let signature: p256::ecdsa::Signature = self.signing_key.sign(message);
            self.peer_completed.store(true, Ordering::SeqCst);
            Ok(signature.to_bytes().to_vec())
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

    #[cfg(not(target_family = "wasm"))]
    impl BoundedConcurrentCredentialSigner for PanickingConcurrentSigner {
        fn max_concurrent_signing_workers(&self) -> NonZeroUsize {
            self.max_workers
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

    #[cfg(not(target_family = "wasm"))]
    fn jwt_inputs(batch_size: usize, prefix: &str) -> Vec<Es256SigningBatchInput> {
        (0..batch_size)
            .map(|ordinal| jwt_input(ordinal as u64, &format!("{prefix}-{ordinal}")))
            .collect()
    }

    #[cfg(not(target_family = "wasm"))]
    fn normalized_jwt_semantics(credential: &SignedCredential) -> serde_json::Value {
        let SignedCredential::JwtVcJson { jwt, .. } = credential else {
            panic!("expected JWT-VC")
        };
        let segments = jwt.split('.').collect::<Vec<_>>();
        assert_eq!(segments.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
        let payload_object = payload.as_object_mut().unwrap();
        for field in ["iat", "nbf", "exp", "jti"] {
            payload_object.remove(field);
        }
        let vc = payload_object["vc"].as_object_mut().unwrap();
        for field in [
            "id",
            "validFrom",
            "validUntil",
            "issuanceDate",
            "expirationDate",
        ] {
            vc.remove(field);
        }
        serde_json::json!({ "header": header, "payload": payload })
    }

    #[cfg(not(target_family = "wasm"))]
    fn verify_signed_credential(
        credential: &SignedCredential,
        verifying_key: &p256::ecdsa::VerifyingKey,
    ) {
        match credential {
            SignedCredential::JwtVcJson { jwt, .. } => {
                let segments = jwt.split('.').collect::<Vec<_>>();
                assert_eq!(segments.len(), 3);
                let signature = p256::ecdsa::Signature::from_slice(
                    &URL_SAFE_NO_PAD.decode(segments[2]).unwrap(),
                )
                .unwrap();
                verifying_key
                    .verify(
                        format!("{}.{}", segments[0], segments[1]).as_bytes(),
                        &signature,
                    )
                    .unwrap();
            }
            SignedCredential::MsoMdoc {
                issuer_signed_b64, ..
            } => {
                let issuer_signed: isomdl::definitions::IssuerSigned =
                    isomdl::cbor::from_slice(&URL_SAFE_NO_PAD.decode(issuer_signed_b64).unwrap())
                        .unwrap();
                let signature =
                    p256::ecdsa::Signature::from_slice(&issuer_signed.issuer_auth.signature)
                        .unwrap();
                verifying_key
                    .verify(&issuer_signed.issuer_auth.tbs_data(&[]), &signature)
                    .unwrap();
            }
            other => panic!("unexpected signed credential format: {other:?}"),
        }
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

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn randomized_serial_concurrent_jwt_differential_covers_required_batch_sizes() {
        for (batch_size, schedule_seed) in [
            (1, 0x0123_4567_89ab_cdef),
            (8, 0xfedc_ba98_7654_3210),
            (32, 0x55aa_0ff0_33cc_9696),
            (256, 0xdead_beef_cafe_babe),
        ] {
            let serial_signer = ConcurrentTestSigner::new(1, schedule_seed);
            let serial_credentials = Es256SignerScope::new(&serial_signer)
                .unwrap()
                .sign_batch(jwt_inputs(batch_size, "differential"))
                .unwrap();

            let mut concurrent_signer = ConcurrentTestSigner::new(8, schedule_seed);
            let concurrent_credentials = {
                let scope = ConcurrentEs256SignerScope::new(&mut concurrent_signer).unwrap();
                scope
                    .sign_batch_concurrently(jwt_inputs(batch_size, "differential"))
                    .unwrap()
            };

            assert_eq!(serial_credentials.len(), batch_size);
            assert_eq!(concurrent_credentials.len(), batch_size);
            for (serial, concurrent) in serial_credentials.iter().zip(&concurrent_credentials) {
                assert_eq!(
                    normalized_jwt_semantics(serial),
                    normalized_jwt_semantics(concurrent),
                    "serial and concurrent paths must preserve the same caller-ordered semantics"
                );
                verify_signed_credential(serial, serial_signer.signing_key.verifying_key());
                verify_signed_credential(concurrent, concurrent_signer.signing_key.verifying_key());
            }

            assert_eq!(serial_signer.call_count(), batch_size);
            assert_eq!(concurrent_signer.call_count(), batch_size);
            assert_eq!(concurrent_signer.unique_call_count(), batch_size);
            assert!(concurrent_signer.peak_calls() <= batch_size.min(8));
            if batch_size > 1 {
                assert!(
                    concurrent_signer.peak_calls() > 1,
                    "the schedule must exercise overlapping calls"
                );
            }
        }
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn concurrent_mixed_formats_restore_order_and_preserve_valid_signatures() {
        let inputs = (0..8)
            .map(|ordinal| {
                if ordinal % 2 == 0 {
                    jwt_input(ordinal, &format!("mixed-{ordinal}"))
                } else {
                    mdoc_input(ordinal, &format!("mixed-{ordinal}"))
                }
            })
            .collect();
        let mut signer = ConcurrentTestSigner::new(4, 0x1357_9bdf_2468_ace0);
        let credentials = {
            let scope = ConcurrentEs256SignerScope::new(&mut signer).unwrap();
            scope.sign_batch_concurrently(inputs).unwrap()
        };

        assert_eq!(credentials.len(), 8);
        for (ordinal, credential) in credentials.iter().enumerate() {
            if ordinal % 2 == 0 {
                assert!(matches!(credential, SignedCredential::JwtVcJson { .. }));
            } else {
                assert!(matches!(credential, SignedCredential::MsoMdoc { .. }));
            }
            verify_signed_credential(credential, signer.signing_key.verifying_key());
        }
        assert_eq!(signer.call_count(), 8);
        assert_eq!(signer.unique_call_count(), 8);
        assert!(signer.peak_calls() <= 4);
        assert!(signer.peak_calls() > 1);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn concurrent_path_preserves_valid_high_s_p1363_bytes() {
        let mut signer = HighSEs256Signer::new();
        let credentials = {
            let scope = ConcurrentEs256SignerScope::new(&mut signer).unwrap();
            scope
                .sign_batch_concurrently(vec![jwt_input(1, "jwt"), mdoc_input(2, "mdoc")])
                .unwrap()
        };
        let calls = signer.calls.lock().unwrap();

        assert_eq!(calls.len(), 2);
        for (payload, raw_signature) in calls.iter() {
            let signature = p256::ecdsa::Signature::from_slice(raw_signature).unwrap();
            assert!(signature.normalize_s().is_some());
            signer
                .signing_key
                .verifying_key()
                .verify(payload, &signature)
                .unwrap();
        }

        let SignedCredential::JwtVcJson { jwt, .. } = &credentials[0] else {
            panic!("expected JWT-VC in caller order")
        };
        let emitted_jwt_signature = URL_SAFE_NO_PAD
            .decode(jwt.rsplit('.').next().unwrap())
            .unwrap();
        let SignedCredential::MsoMdoc {
            issuer_signed_b64, ..
        } = &credentials[1]
        else {
            panic!("expected mdoc in caller order")
        };
        let issuer_signed: isomdl::definitions::IssuerSigned =
            isomdl::cbor::from_slice(&URL_SAFE_NO_PAD.decode(issuer_signed_b64).unwrap()).unwrap();
        assert!(calls.iter().any(|(_, raw)| raw == &emitted_jwt_signature));
        assert!(calls
            .iter()
            .any(|(_, raw)| raw == &issuer_signed.issuer_auth.signature));
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn concurrent_worker_bounds_cover_empty_single_one_and_library_ceiling() {
        let mut empty_signer = ConcurrentTestSigner::new(8, 1);
        let empty = {
            let scope = ConcurrentEs256SignerScope::new(&mut empty_signer).unwrap();
            scope.sign_batch_concurrently(Vec::new()).unwrap()
        };
        assert!(empty.is_empty());
        assert_eq!(empty_signer.call_count(), 0);
        assert_eq!(empty_signer.peak_calls(), 0);

        let mut single_signer = ConcurrentTestSigner::new(8, 2);
        let single = {
            let scope = ConcurrentEs256SignerScope::new(&mut single_signer).unwrap();
            scope
                .sign_batch_concurrently(jwt_inputs(1, "single"))
                .unwrap()
        };
        assert_eq!(single.len(), 1);
        assert_eq!(single_signer.call_count(), 1);
        assert_eq!(single_signer.peak_calls(), 1);

        let mut one_worker_signer = ConcurrentTestSigner::new(1, 3);
        let one_worker = {
            let scope = ConcurrentEs256SignerScope::new(&mut one_worker_signer).unwrap();
            scope
                .sign_batch_concurrently(jwt_inputs(8, "one-worker"))
                .unwrap()
        };
        assert_eq!(one_worker.len(), 8);
        assert_eq!(one_worker_signer.call_count(), 8);
        assert_eq!(one_worker_signer.peak_calls(), 1);

        let mut below_limit_signer = ConcurrentTestSigner::new(8, 4);
        let below_limit = {
            let scope = ConcurrentEs256SignerScope::new(&mut below_limit_signer).unwrap();
            scope
                .sign_batch_concurrently(jwt_inputs(2, "below-limit"))
                .unwrap()
        };
        assert_eq!(below_limit.len(), 2);
        assert_eq!(below_limit_signer.peak_calls(), 2);

        let mut ceiling_signer = ConcurrentTestSigner::new(usize::MAX, 5);
        {
            let scope = ConcurrentEs256SignerScope::new(&mut ceiling_signer).unwrap();
            assert_eq!(scope.worker_limit.get(), MAX_CONCURRENT_SIGNING_WORKERS);
            assert_eq!(
                format!("{scope:?}"),
                "ConcurrentEs256SignerScope([redacted])"
            );
        }
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn concurrent_errors_finish_all_jobs_and_choose_lowest_caller_ordinal() {
        let mut signer = ConcurrentTestSigner::new(4, 0xa5a5_5a5a_f0f0_0f0f)
            .with_fail_labels(["failure-2", "failure-7"]);
        let error = {
            let scope = ConcurrentEs256SignerScope::new(&mut signer).unwrap();
            assert_error(
                scope.sign_batch_concurrently(jwt_inputs(12, "failure")),
                SigningBatchErrorKind::ExecutorFailed,
                Some(2),
            )
        };

        assert_eq!(signer.call_count(), 12);
        assert_eq!(signer.unique_call_count(), 12);
        assert!(signer.peak_calls() <= 4);
        assert!(signer.peak_calls() > 1);
        assert_eq!(
            signer.failure_completion.lock().unwrap().as_slice(),
            ["failure-7", "failure-2"],
            "completion order must not select the reported failure"
        );
        assert!(!error.to_string().contains(BACKEND_SECRET));
        assert!(!format!("{error:?}").contains(BACKEND_SECRET));
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn concurrent_signer_panics_propagate_only_after_every_worker_is_joined() {
        let mut single_signer = PanickingConcurrentSigner::new(PanickingWorker::Caller, 1);
        let single_outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let scope = ConcurrentEs256SignerScope::new(&mut single_signer).unwrap();
            scope.sign_batch_concurrently(jwt_inputs(8, "single-caller"))
        }));
        let single_payload = match single_outcome {
            Err(payload) => payload,
            Ok(_) => panic!("the caller worker's signer panic must propagate"),
        };
        let single_message = single_payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| single_payload.downcast_ref::<String>().map(String::as_str));
        assert_eq!(single_message, Some(TEST_SIGNER_PANIC));
        assert_eq!(single_signer.active_calls.load(Ordering::SeqCst), 0);
        assert_eq!(single_signer.call_count(), 1);
        assert_eq!(single_signer.unique_call_count(), 1);
        assert_eq!(single_signer.peak_calls(), 1);

        for (panicking_worker, label) in [
            (PanickingWorker::Caller, "caller"),
            (PanickingWorker::Spawned, "spawned"),
        ] {
            let mut signer = PanickingConcurrentSigner::new(panicking_worker, 2);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let scope = ConcurrentEs256SignerScope::new(&mut signer).unwrap();
                scope.sign_batch_concurrently(jwt_inputs(8, label))
            }));
            let payload = match outcome {
                Err(payload) => payload,
                Ok(_) => panic!("a signer panic must remain outside the Result contract"),
            };
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str));

            assert_eq!(message, Some(TEST_SIGNER_PANIC));
            assert!(!signer.panic_once.load(Ordering::SeqCst));
            assert!(signer.caller_started.load(Ordering::SeqCst));
            assert!(signer.spawned_started.load(Ordering::SeqCst));
            assert!(
                signer.peer_completed.load(Ordering::SeqCst),
                "panic propagation must wait for the already-in-flight peer"
            );
            assert_eq!(signer.active_calls.load(Ordering::SeqCst), 0);
            assert_eq!(signer.call_count(), 2);
            assert_eq!(signer.unique_call_count(), 2);
            assert_eq!(signer.peak_calls(), 2);
        }
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn post_join_metadata_drift_precedes_a_returned_backend_error() {
        let mut failing_signer = ConcurrentTestSigner::new(4, 0x1212_3434_5656_7878)
            .with_fail_labels(["failure-2"])
            .with_drift_on_call(1);
        {
            let scope = ConcurrentEs256SignerScope::new(&mut failing_signer).unwrap();
            assert_error(
                scope.sign_batch_concurrently(jwt_inputs(8, "failure")),
                SigningBatchErrorKind::SignerMetadataChanged,
                None,
            );
        }
        assert_eq!(failing_signer.call_count(), 8);
        assert_eq!(failing_signer.unique_call_count(), 8);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn concurrent_duplicate_preparation_and_metadata_drift_fail_closed() {
        let mut duplicate_signer = ConcurrentTestSigner::new(4, 11);
        {
            let scope = ConcurrentEs256SignerScope::new(&mut duplicate_signer).unwrap();
            assert_error(
                scope.sign_batch_concurrently(vec![invalid_mdoc_input(7), jwt_input(7, "dup")]),
                SigningBatchErrorKind::DuplicateRoute,
                Some(0),
            );
        }
        assert_eq!(duplicate_signer.call_count(), 0);

        let mut preparation_signer = ConcurrentTestSigner::new(4, 12);
        {
            let scope = ConcurrentEs256SignerScope::new(&mut preparation_signer).unwrap();
            assert_error(
                scope.sign_batch_concurrently(vec![jwt_input(1, "valid"), invalid_mdoc_input(2)]),
                SigningBatchErrorKind::PreparationFailed,
                Some(1),
            );
        }
        assert_eq!(preparation_signer.call_count(), 0);

        for metadata_state in 1..=3 {
            let mut signer = ConcurrentTestSigner::new(4, metadata_state as u64);
            let state = signer.metadata_handle();
            {
                let scope = ConcurrentEs256SignerScope::new(&mut signer).unwrap();
                state.store(metadata_state, Ordering::SeqCst);
                assert_error(
                    scope.sign_batch_concurrently(jwt_inputs(4, "pre-drift")),
                    SigningBatchErrorKind::SignerMetadataChanged,
                    None,
                );
            }
            assert_eq!(signer.call_count(), 0);
        }

        let mut during_signer = ConcurrentTestSigner::new(4, 13).with_drift_on_call(1);
        {
            let scope = ConcurrentEs256SignerScope::new(&mut during_signer).unwrap();
            assert_error(
                scope.sign_batch_concurrently(jwt_inputs(16, "during-drift")),
                SigningBatchErrorKind::SignerMetadataChanged,
                None,
            );
        }
        assert_eq!(during_signer.call_count(), 16);
        assert_eq!(during_signer.unique_call_count(), 16);
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
        BackendFailureAndDuplicateIdentity,
    }

    struct FaultingExecutor(ResultFault);

    fn signature_bytes_mut(result: &mut SigningResult) -> &mut Vec<u8> {
        let SigningOutcome::Signature(signature) = &mut result.outcome else {
            panic!("the serial fixture must produce a signature")
        };
        signature
    }

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
                    signature_bytes_mut(&mut results[0]).pop();
                }
                ResultFault::WrongEncoding => {
                    signature_bytes_mut(&mut results[0]).fill(0);
                }
                ResultFault::TwoInvalidSignatures => {
                    signature_bytes_mut(&mut results[1]).pop();
                    signature_bytes_mut(&mut results[2]).clear();
                    results.reverse();
                }
                ResultFault::InvalidSignatureAndDuplicateIdentity => {
                    signature_bytes_mut(&mut results[0]).clear();
                    results[1].identity = results[0].identity;
                }
                ResultFault::BackendFailureAndDuplicateIdentity => {
                    results[0].outcome = SigningOutcome::Failed;
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
            ResultFault::BackendFailureAndDuplicateIdentity,
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
