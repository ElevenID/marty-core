# Presentation-policy evidence contract

The service evaluator accepts facts from a trusted protocol verifier. These facts
are not a public endpoint for a wallet to assert its own verification results.
Cryptographic verification and policy evaluation remain separate operations.

## Credential and trust identity

`VerifiedCredentialFacts.credential_types` contains exact authenticated credential
types (`vct`, document type, or VC types). Requested template IDs are not evidence
of credential type. The service adapter resolves and matches governed templates
before assigning `credential_template_ids`. Core independently enforces the
policy's `accepted_credential_types` and each claim's optional `credential_type`.

`trust_profile_id` identifies the profile actually evaluated for that credential.
A successful boolean without this identity cannot satisfy a profile requirement.
The requirement's explicit profile overrides the policy-level default. A producer
may supply separate candidates for the same credential evaluated under different
profiles; each candidate must carry that evaluation's trust level and attributes.
Presentation counts describe real presentations, not the number of trust checks.

Linked authorization results belong in the candidate's `external_authorization`.
A denial excludes that candidate without vetoing an independently permitted
alternative. The request-level authorization remains available for genuinely
global obligations. Missing linked policies must be represented as failed or
unevaluated authorization, never silently omitted by the producer. Authorization
evaluation errors cannot accompany an allow decision.

The compatibility `PolicyEvaluationInput` also requires `trust_profile_id` when a
profile is configured. JSON that omits it still deserializes but cannot authorize
against a required profile. `IssuerConstraintChecker::check_issuer` retains its
legacy signature and fails closed for configured profiles; callers with scoped
evidence use `check_issuer_for_profile`.

## Predicate capability

`validate_service_policy` is the common create/activate/evaluate validator.
Evaluation repeats validation so persisted policies receive the same protection.

The raw-value fallback supports the protocol's `EQUALITY`, `INEQUALITY`,
`MEMBERSHIP`, `NON_MEMBERSHIP`, and `RANGE_PROOF` parameters. Unknown predicates,
fallbacks, and malformed parameters are rejected. Range comparisons require JSON
numbers and preserve integer precision; they do not coerce strings to numbers.

Claim-level fallback and circuit settings override policy-level settings. With
`ACCEPT_RAW`, the authenticated raw value must satisfy the comparison. With
`DENY`, a raw value cannot satisfy the predicate. The service contract currently
has no authenticated zero-knowledge predicate-evidence input, so
`REQUIRE_PREDICATE` is an explicit unsupported-policy error at validation and
evaluation. A boolean claim or `accept_derived` flag does not establish a ZK proof.

## Consumer rollout

Update Core pins and the matching service projection together. Producers must
populate authenticated types and evaluated trust identities and preserve policy
fallback/circuit fields. Old producers can receive non-allow decisions after this
update; do not restore acceptance by copying requested identifiers into facts.

Focused regression coverage includes wrong credential types, mismatched and
missing trust identities, two different required profiles, inherited predicate
fallbacks, false boolean claims, range boundaries, and unsupported proof paths.
