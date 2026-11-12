# Versioned JWT VC2 securing profiles

Core distinguishes the credential's content profile from the mechanism that
secures it. `open_badge_v3` is a content selection; it does not select a JOSE
representation or establish an issuer's authority. Existing Rust request
structs, entrypoints, format names and serialized receipts retain their
historical contract. New entrypoints require an explicit `JwtVcSecuringProfile`.
There is no default profile, loose alias, payload-shape inference or fallback.

## Pinned contracts

| Contract | Protected header | Credential / presentation payload | Time semantics |
| --- | --- | --- | --- |
| `marty_nested_vc2_jwt_v1` | Historical VC `JWT` or `vc+jwt`; VP `JWT` | VC2 inside `vc`; VP2 inside `vp`, with compact credential strings | Existing issuance options retain their original meaning. New explicit verification checks both JWT times and any VC validity dates. |
| `w3c_vc2_jose_2026_v1` | Required `vc+jwt` / `vp+jwt`; optional `cty` must be `vc` / `vp` | Direct VC2 / VP2 claims; no `vc` or `vp` claim. Inner credentials use VC2 envelopes. | Signature `iat` / `exp` and VC `validFrom` / `validUntil` are independent. This deployment profile rejects `nbf`. |
| Open Badges 3.0 document 1.4.5 JWT proof rules | Allowed `alg`, `kid`, `jwk`, `typ`; `typ`, when present, is `JWT` | Governed by the OB3 JWT proof section | `iss`, `jti`, `nbf`, `sub` required; `nbf` / `exp` map to credential validity. |

The direct profile pins [W3C Securing Verifiable Credentials using JOSE and
COSE, Recommendation 13 October 2026](https://www.w3.org/TR/2026/REC-vc-jose-cose-20261013/).
That specification uses the VC/VP itself as the claims set and prohibits the
legacy `vc`/`vp` container properties. Its JOSE times concern the securing
mechanism, separately from the credential's validity dates. This implementation
makes some optional/recommended choices mandatory as a bounded deployment
profile; it is not a general verifier for every permitted W3C representation.

[Open Badges 3.0 document 1.4.5, 29 June 2026](https://www.imsglobal.org/spec/ob/v3p0/),
sections 8.2.3 and 8.2.4, uses different JWT header and claim rules. Passing
Core's OB3 **content** checks under the direct W3C profile does **not** establish
OB3 JWT proof conformance or 1EdTech certification. The historical Marty profile
also describes deployed compatibility behavior, not a newly asserted standards
certification. Do not relabel existing artifacts as either new conformance.

## Explicit negotiation

`JwtVcProfileBinding` binds the exact profile name and credential format:

| Securing profile | Credential format | Configuration identifier |
| --- | --- | --- |
| `marty_nested_vc2_jwt_v1` | `jwt_vc_json` | Existing identifier |
| `w3c_vc2_jose_2026_v1` | `application/vc+jwt` | Existing identifier plus `#vc2-jose-2026-v1` |

`profile_jwt_vc_configuration` creates a new configuration value from an
existing typed configuration, with a `marty_securing_profile` extension.
`admit_profiled_jwt_vc_configuration` requires that explicit extension, exact
format and consistent configuration identifier. It does not add the new profile
to existing issuer metadata automatically. The application must bind the
selected configuration/profile to its offer and authorization transaction.

`build_profiled_jwt_vc_query` and `profiled_jwt_vc_query_binding` apply the same
pair to a DCQL credential query, using `meta.marty_securing_profile`. Missing
markers, unsupported versions, mixed pairs and downgrade requests fail. The
holder-binding selection remains explicit in the query. Use the presentation
API when holder proof is required; verification of a bare credential does not
satisfy that requirement.

The new media-type format and metadata extension are deployment-defined. They
are not aliases for the existing `jwt_vc_json` appendix format. See
[OID4VCI 1.0 Final, 16 September 2025, Appendix A](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A)
and [OID4VP 1.0 Final, 9 July 2025, Appendix B](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B).
Those specifications permit deployment format profiles; their historical JWT
appendix definitions do not silently become this direct VC2 profile.

## Issuance and custody

Use `prepare_remote_jwt_vc_with_profile` or
`formats::jwt_vc::prepare_jwt_vc_with_profile`. The direct selection contains a
`JwtVcProfileTiming` with explicit signature issuance/expiration and credential
validity dates. Set the historical request's `expiration_seconds` to `None` for
direct issuance; supplying both forms is an error. Direct low-level preparation
also rejects `include_nbf`. Credential dates may legitimately precede or follow
signature issuance and retain fractional seconds.

The direct deployment profile requires a VC2 context first, a credential ID,
an issuer ID, one object subject with an ID, and `validFrom`. IDs are absolute
ASCII URIs without raw whitespace, control characters, forbidden URI characters
or malformed percent escapes. Valid percent escapes and the original identifier
case are preserved. `validUntil` is optional and must follow `validFrom`. Signature expiration
is required and must follow signature issuance. Issuer/id/subject JWT aliases
must agree with the credential. The OB3 builder still requires a complete
achievement and criteria when that content profile is selected. Retired OB2
content is rejected.

Preparation returns opaque state and exact bytes for the existing remote
signer. `complete` verifies the supplied signature against those bytes and the
selected public key before returning `SignedProfiledJwtVc`, which retains its
binding. No API creates, exports or accepts issuer private keys. Caller code
must not reserialize the header or payload between preparation and completion.

Historical preparation retains its established options, including historical
generic credentials that omitted `vc.id`. Explicit verification requires an
unambiguous credential ID and issuer/subject binding. An incomplete historical
artifact can therefore be rejected; its signed claims are never repaired.
Reissuance creates a new signed artifact and requires the application's normal
authorization and lifecycle handling.

## Verification and authenticated views

`verify_jwt_vc_with_profile` accepts an independently selected issuer-key
resolver, expected profile and evaluation instant. The resolver's exact issuer,
key ID and algorithm tuple must match the signed token. Embedded issuer keys
and key-fetch URLs do not substitute for that resolver. Unique JSON members,
canonical base64url, size limits and unsupported critical headers are checked
before cryptographic verification. Alias conflicts and mixed profiles fail.
Both explicit profiles require the VC2 context first and reject VC1 date
properties; selecting the historical nested profile never admits a VC1 payload.

`AuthenticatedJwtVc` is only constructible inside the verifier. It exposes the
exact authenticated claims, credential content, artifact hash, selected profile
and time intervals. Both signature validity and credential validity use the
same caller-supplied instant. Missing historical optional validity dates remain
unspecified; they are not invented. `Debug` output redacts credential contents.

The verification-only crate exposes
`verify_vcdm_jwt_with_profile_json[_async]` and
`verify_open_badge_v3_jwt_with_profile_json[_async]`. Requests require `token`,
`expected_issuer`, `expected_algorithm`, `issuer_public_jwk`,
`expected_securing_profile` and `evaluated_at`, with optional
`expected_verification_method`. Unknown/duplicate fields are rejected. These
wrappers reuse the existing SSI ES256/EdDSA verification backend without
enabling additional issuer/wallet role features. They share the profile/alias/
date rules with the typed wallet API and withhold claims on every failure.

Success is scoped to `issuer_signature_and_securing_profile`. Issuer trust,
status, holder possession, schema certification and relying-party acceptance
remain separate checks. The JSON response explicitly reports trust, status and
holder binding as `not_checked`; a bare credential is not a holder proof.
The public `decode_unverified_jwt_vc` and
`validate_unsigned_jwt_vc_profile_claims` helpers return **unauthenticated**
parsing/checking results, never the authenticated type or acceptance evidence.

## Presentations and exact envelopes

`prepare_verified_jwt_vc_presentation_with_profile` authenticates the credential
before preparing a holder proof. It requires the same selected profile and a
self-certifying `did:key` or `did:jwk` subject bound to the holder's public key.
The holder signs through the existing opaque remote signer. The resulting
presentation retains the binding, nonce, audience and exact credential bytes.

For the direct profile, the VC2 presentation contains exactly one
`EnvelopedVerifiableCredential` with its VC2 context and an `id` of
`data:application/vc+jwt,<original compact token>`. The verifier rejects raw
string credentials, altered media types, extra envelope members, multiple
credentials and historical nested credentials inside a direct envelope.
Holder `iss`, `sub`, `holder`, key identity, and presentation `id`/`jti` must
agree. The credential and short-lived presentation use one evaluation instant;
the prepared proof expires no later than the issuer JWT or credential validity.
For a historical presentation, any `nbf` must also permit that exact instant.

`verify_jwt_vc_presentation_with_profile` adds issuer signature/profile and
holder transaction proof checks. Its OB3 variant additionally checks content.
`presented_jwt_vc_with_profile` is only an untrusted issuer-key-selection hint.
Neither replaces issuer authority, credential status or application policy.

## Tests and rollout boundary

Parser/negotiation and public-key-only preparation regressions run in the
existing native library and `remote_jwt_vc_boundary` targets. Genuine signed
positive and negative cases run in the existing marked-disposable OpenBao
harness, `bash scripts/test_remote_issuer_live_kms.sh`: the
`wallet_jwt_vc::tests` and `vcdm::tests` modules are already collected there.
They exercise exact claims, separate validity intervals, both profiles,
alias conflicts, invalid signatures, envelope/profile crossovers and one clock.
The live cases remain explicitly ignored outside that harness; compilation or
running the non-ignored tests alone is not evidence that they executed.

This Core batch supplies opt-in primitives and does not migrate existing
issuer offers, UI, Authenticator, Verifier or external wallets automatically.
Product adoption must bind the negotiated version to stored credential and
transaction metadata, preserve historical artifact bytes, use the new
authenticated view, and separately compose its normal trust/status/policy
checks. Independent external-wallet qualification remains a separate gate.
