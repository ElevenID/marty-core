//! Explicit securing profiles for JWT credentials and presentations.
//!
//! `jwt_vc_json` retains Marty's historical nested VC2 representation. The
//! opt-in direct profile follows W3C VC JOSE 13 October 2026. It is a bounded
//! Marty deployment profile, not a claim of Open Badges JWT proof conformance:
//! Open Badges 3.0 document 1.4.5 has different header and time-claim rules.
//! See `docs/vc2-jose-profiles.md` for the pinned specifications and negotiation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Oid4vciError, Oid4vciResult};

/// A caller-selected, versioned wire contract. There is deliberately no default
/// and no loose/shape-based parser: a transaction must select one profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum JwtVcSecuringProfile {
    /// Existing Marty VC2-in-`vc` / VP-in-`vp` representation.
    #[serde(rename = "marty_nested_vc2_jwt_v1")]
    MartyNestedVc2JwtV1,
    /// Direct VC2/VP2 claims using the W3C 2026 JOSE securing mechanism.
    #[serde(rename = "w3c_vc2_jose_2026_v1")]
    W3cVc2Jose2026V1,
}

impl JwtVcSecuringProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MartyNestedVc2JwtV1 => "marty_nested_vc2_jwt_v1",
            Self::W3cVc2Jose2026V1 => "w3c_vc2_jose_2026_v1",
        }
    }

    /// The new media-type identifier is a deployment-defined OID4VC profile;
    /// it is never silently aliased to the OID4VP `jwt_vc_json` profile.
    pub const fn credential_format(self) -> &'static str {
        match self {
            Self::MartyNestedVc2JwtV1 => "jwt_vc_json",
            Self::W3cVc2Jose2026V1 => "application/vc+jwt",
        }
    }

    pub const fn credential_media_type(self) -> &'static str {
        "application/vc+jwt"
    }

    pub const fn presentation_media_type(self) -> &'static str {
        match self {
            Self::MartyNestedVc2JwtV1 => "application/jwt",
            Self::W3cVc2Jose2026V1 => "application/vp+jwt",
        }
    }

    /// A distinct configuration ID prevents reinterpreting an already issued
    /// offer or authorization as the new securing profile.
    pub fn configuration_id(self, historical_id: &str) -> Oid4vciResult<String> {
        if historical_id.is_empty()
            || historical_id.len() > 1024
            || historical_id.trim() != historical_id
            || historical_id.chars().any(char::is_control)
            || historical_id.contains('#')
        {
            return Err(profile_error(
                "invalid base credential configuration identifier",
            ));
        }
        Ok(match self {
            Self::MartyNestedVc2JwtV1 => historical_id.to_owned(),
            Self::W3cVc2Jose2026V1 => format!("{historical_id}#vc2-jose-2026-v1"),
        })
    }
}

impl std::fmt::Display for JwtVcSecuringProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for JwtVcSecuringProfile {
    type Err = Oid4vciError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "marty_nested_vc2_jwt_v1" => Ok(Self::MartyNestedVc2JwtV1),
            "w3c_vc2_jose_2026_v1" => Ok(Self::W3cVc2Jose2026V1),
            _ => Err(profile_error("unsupported JWT credential securing profile")),
        }
    }
}

/// The exact profile/format pair selected by an offer or presentation request.
/// This records negotiation, not signature, trust, or policy evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct JwtVcProfileBinding {
    securing_profile: JwtVcSecuringProfile,
    credential_format: &'static str,
}

impl JwtVcProfileBinding {
    pub const fn new(securing_profile: JwtVcSecuringProfile) -> Self {
        Self {
            securing_profile,
            credential_format: securing_profile.credential_format(),
        }
    }

    /// Both advertised values are mandatory. Unknown names, aliases and
    /// cross-profile combinations fail instead of selecting another format.
    pub fn negotiate(profile: &str, format: &str) -> Oid4vciResult<Self> {
        let selected: JwtVcSecuringProfile = profile.parse()?;
        if format != selected.credential_format() {
            return Err(profile_error(
                "securing profile and credential format conflict",
            ));
        }
        Ok(Self::new(selected))
    }

    pub const fn securing_profile(self) -> JwtVcSecuringProfile {
        self.securing_profile
    }

    pub const fn credential_format(self) -> &'static str {
        self.credential_format
    }
}

/// Independent signature and credential time intervals for the new profile.
/// All fields are validated before preparation; no process clock is substituted.
/// A finite signature interval is required by this bounded deployment profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtVcProfileTiming {
    signature_issued_at: i64,
    signature_expires_at: i64,
    credential_valid_from: DateTime<Utc>,
    credential_valid_until: Option<DateTime<Utc>>,
}

impl JwtVcProfileTiming {
    pub fn new(
        signature_issued_at: i64,
        signature_expires_at: i64,
        credential_valid_from: DateTime<Utc>,
        credential_valid_until: Option<DateTime<Utc>>,
    ) -> Oid4vciResult<Self> {
        let timing = Self {
            signature_issued_at,
            signature_expires_at,
            credential_valid_from,
            credential_valid_until,
        };
        timing.validate()?;
        Ok(timing)
    }

    pub const fn signature_issued_at(self) -> i64 {
        self.signature_issued_at
    }

    pub const fn signature_expires_at(self) -> i64 {
        self.signature_expires_at
    }

    pub const fn credential_valid_from(self) -> DateTime<Utc> {
        self.credential_valid_from
    }

    pub const fn credential_valid_until(self) -> Option<DateTime<Utc>> {
        self.credential_valid_until
    }

    pub(crate) fn validate(self) -> Oid4vciResult<()> {
        if self.signature_issued_at < 0
            || self.signature_expires_at <= self.signature_issued_at
            || DateTime::from_timestamp(self.signature_issued_at, 0).is_none()
            || DateTime::from_timestamp(self.signature_expires_at, 0).is_none()
            || self
                .credential_valid_until
                .is_some_and(|until| until <= self.credential_valid_from)
        {
            return Err(profile_error(
                "invalid signature or credential validity interval",
            ));
        }
        Ok(())
    }
}

/// An explicit preparation policy without adding fields to historical public
/// request structs. Historical calls keep using `expiration_seconds`; direct
/// calls must instead provide the two independent intervals.
#[derive(Clone, Copy, Debug)]
pub enum JwtVcPreparationProfile {
    HistoricalNested,
    DirectVc2Jose(JwtVcProfileTiming),
}

impl JwtVcPreparationProfile {
    pub const fn securing_profile(self) -> JwtVcSecuringProfile {
        match self {
            Self::HistoricalNested => JwtVcSecuringProfile::MartyNestedVc2JwtV1,
            Self::DirectVc2Jose(_) => JwtVcSecuringProfile::W3cVc2Jose2026V1,
        }
    }
}

/// Prepared bytes and their explicit profile, awaiting an opaque issuer signer.
/// The state cannot be reconstructed from caller-supplied signing bytes.
#[cfg(any(test, feature = "issuer"))]
pub struct PreparedProfiledJwtVc {
    pub(crate) prepared: crate::formats::jwt_vc::PreparedJwtVc,
    pub(crate) binding: JwtVcProfileBinding,
}

#[cfg(any(test, feature = "issuer"))]
impl std::fmt::Debug for PreparedProfiledJwtVc {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedProfiledJwtVc")
            .field("binding", &self.binding)
            .field("contents", &"[redacted]")
            .finish()
    }
}

#[cfg(any(test, feature = "issuer"))]
impl PreparedProfiledJwtVc {
    pub const fn binding(&self) -> JwtVcProfileBinding {
        self.binding
    }

    pub fn signing_input(&self) -> &str {
        self.prepared.signing_input()
    }

    pub fn credential_id(&self) -> &str {
        self.prepared.credential_id()
    }

    pub fn algorithm(&self) -> crate::types::SigningAlgorithm {
        self.prepared.algorithm()
    }

    /// Verify the remote signature over exactly the prepared bytes before
    /// returning the credential and its selected wire/profile binding.
    pub fn complete(self, signature: &[u8]) -> Oid4vciResult<SignedProfiledJwtVc> {
        let crate::types::SignedCredential::JwtVcJson { jwt, credential_id } =
            crate::formats::jwt_vc::assemble_jwt_vc(self.prepared, signature)?
        else {
            return Err(profile_error("unexpected credential assembly format"));
        };
        Ok(SignedProfiledJwtVc {
            credential: jwt,
            credential_id,
            binding: self.binding,
        })
    }
}

/// An issuer-signed artifact. This is not verifier trust, status or acceptance
/// evidence. Its exact bytes must remain unchanged in storage and transport.
#[cfg(any(test, feature = "issuer"))]
pub struct SignedProfiledJwtVc {
    credential: String,
    credential_id: String,
    binding: JwtVcProfileBinding,
}

#[cfg(any(test, feature = "issuer"))]
impl std::fmt::Debug for SignedProfiledJwtVc {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedProfiledJwtVc")
            .field("binding", &self.binding)
            .field("contents", &"[redacted]")
            .finish()
    }
}

#[cfg(any(test, feature = "issuer"))]
impl SignedProfiledJwtVc {
    pub const fn binding(&self) -> JwtVcProfileBinding {
        self.binding
    }

    pub fn credential(&self) -> &str {
        &self.credential
    }

    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }
}

/// Strict bounded parsing for an explicitly chosen credential profile. These
/// values are UNAUTHENTICATED key-selection hints; this performs no signature,
/// issuer trust, status or policy verification. No crypto role is enabled.
pub fn decode_unverified_jwt_vc(
    compact: &str,
    profile: JwtVcSecuringProfile,
) -> Oid4vciResult<(serde_json::Value, serde_json::Value)> {
    let (header, claims) = crate::bounded_jwt::decode_unverified_compact_jwt(compact)?;
    validate_profile_header(profile, &header, false)?;
    if ["jwk", "jku", "x5c", "x5u"]
        .iter()
        .any(|name| header.get(*name).is_some())
    {
        return Err(profile_error("embedded issuer keys are not allowed"));
    }
    selected_credential(profile, &claims)?;
    Ok((header, claims))
}

/// Structural/time checks only. This type contains UNAUTHENTICATED data and
/// cannot be used as an `AuthenticatedJwtVc`. Verification implementations must
/// authenticate the exact original compact bytes before exposing its contents.
/// Public fields are intentional: this is a parsing result, never proof.
pub struct UnauthenticatedJwtVcProfile<'a> {
    pub credential: &'a serde_json::Value,
    pub issuer: &'a str,
    pub credential_id: &'a str,
    pub subject_id: &'a str,
    pub signature_issued_at: i64,
    pub signature_expires_at: i64,
    pub credential_valid_from: Option<DateTime<Utc>>,
    pub credential_valid_until: Option<DateTime<Utc>>,
}

/// Apply the same profile, alias and time rules to already parsed claims.
/// This pure check does NOT authenticate a signature. Its separate name/type
/// lets verifier-only crates reuse the rules without enabling issuer or wallet
/// capabilities. The typed authenticated wallet API calls it after JOSE.
pub fn validate_unsigned_jwt_vc_profile_claims(
    claims: &serde_json::Value,
    evaluated_at: i64,
    profile: JwtVcSecuringProfile,
) -> Oid4vciResult<UnauthenticatedJwtVcProfile<'_>> {
    use serde_json::Value;
    fn text<'a>(value: &'a Value, name: &str) -> Oid4vciResult<&'a str> {
        value
            .get(name)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty() && text.trim() == *text)
            .ok_or_else(|| profile_error("missing or invalid credential identity claim"))
    }
    let future_limit = evaluated_at
        .checked_add(30)
        .filter(|_| evaluated_at > 0)
        .ok_or_else(|| profile_error("invalid evaluation instant"))?;
    let issued = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| profile_error("signature issued-at is required"))?;
    let expires = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| profile_error("signature expiration is required"))?;
    if issued < 0
        || issued > future_limit
        || expires <= evaluated_at
        || expires <= issued
        || DateTime::from_timestamp(issued, 0).is_none()
        || DateTime::from_timestamp(expires, 0).is_none()
    {
        return Err(profile_error(
            "JWT is outside its signature validity interval",
        ));
    }
    if let Some(value) = claims.get("nbf") {
        let not_before = value
            .as_i64()
            .filter(|value| *value >= 0 && *value <= evaluated_at)
            .ok_or_else(|| profile_error("invalid JWT not-before claim"))?;
        if not_before >= expires {
            return Err(profile_error("invalid JWT not-before interval"));
        }
    }
    let credential = selected_credential(profile, claims)?;
    if !contains_type(credential, "VerifiableCredential")
        || crate::formats::jwt_vc::has_retired_open_badges_profile(credential)
    {
        return Err(profile_error("invalid credential content type"));
    }
    if contains_type(credential, "OpenBadgeCredential") {
        crate::formats::jwt_vc::validate_open_badge_v3_profile(credential)?;
    }
    let issuer = text(claims, "iss")?;
    let credential_id = text(claims, "jti")?;
    let vc_issuer = credential.get("issuer").and_then(|value| {
        value
            .as_str()
            .or_else(|| value.get("id").and_then(Value::as_str))
    });
    let subject_id = text(
        credential
            .get("credentialSubject")
            .ok_or_else(|| profile_error("credential subject is required"))?,
        "id",
    )?;
    if vc_issuer != Some(issuer)
        || text(credential, "id")? != credential_id
        || claims
            .get("sub")
            .is_some_and(|value| value.as_str() != Some(subject_id))
    {
        return Err(profile_error(
            "JWT and credential identity aliases conflict",
        ));
    }
    let (credential_valid_from, credential_valid_until) = check_credential_dates(
        credential,
        evaluated_at,
        profile == JwtVcSecuringProfile::W3cVc2Jose2026V1,
    )?;
    Ok(UnauthenticatedJwtVcProfile {
        credential,
        issuer,
        credential_id,
        subject_id,
        signature_issued_at: issued,
        signature_expires_at: expires,
        credential_valid_from,
        credential_valid_until,
    })
}

pub(crate) fn profile_error(message: &str) -> Oid4vciError {
    Oid4vciError::InvalidRequest(format!("JWT credential profile: {message}"))
}

pub(crate) const VC2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

pub(crate) fn validate_profile_header(
    profile: JwtVcSecuringProfile,
    header: &serde_json::Value,
    presentation: bool,
) -> Oid4vciResult<()> {
    // This profile implements no critical JOSE extension or unencoded compact
    // payload. Unknown noncritical members retain normal JOSE semantics.
    if header.get("crit").is_some()
        || header
            .get("b64")
            .is_some_and(|value| value.as_bool() != Some(true))
    {
        return Err(profile_error(
            "unsupported critical or unencoded JOSE header",
        ));
    }
    let typ = header.get("typ").and_then(serde_json::Value::as_str);
    let cty = header.get("cty").and_then(serde_json::Value::as_str);
    let (required_type, content_type) = if presentation {
        ("vp+jwt", "vp")
    } else {
        ("vc+jwt", "vc")
    };
    match profile {
        JwtVcSecuringProfile::W3cVc2Jose2026V1 => {
            if typ != Some(required_type)
                || header.get("cty").is_some() && cty != Some(content_type)
            {
                return Err(profile_error(
                    "protected JOSE type conflicts with selected profile",
                ));
            }
        }
        JwtVcSecuringProfile::MartyNestedVc2JwtV1 => {
            let valid_type = if presentation {
                typ == Some("JWT")
            } else {
                matches!(typ, Some("JWT" | "vc+jwt"))
            };
            if header.get("typ").is_some() && !valid_type
                || header.get("cty").is_some() && cty != Some(content_type)
            {
                return Err(profile_error(
                    "protected JOSE type conflicts with historical profile",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn selected_credential(
    profile: JwtVcSecuringProfile,
    claims: &serde_json::Value,
) -> Oid4vciResult<&serde_json::Value> {
    match profile {
        JwtVcSecuringProfile::MartyNestedVc2JwtV1 => {
            if [
                "vp",
                "@context",
                "type",
                "issuer",
                "credentialSubject",
                "validFrom",
                "validUntil",
            ]
            .iter()
            .any(|name| claims.get(*name).is_some())
            {
                return Err(profile_error(
                    "direct or mixed claims conflict with historical profile",
                ));
            }
            let credential = claims
                .get("vc")
                .filter(|value| value.is_object())
                .ok_or_else(|| profile_error("historical profile requires its signed vc object"))?;
            validate_vc2_credential_content(credential)?;
            Ok(credential)
        }
        JwtVcSecuringProfile::W3cVc2Jose2026V1 => {
            if ["vc", "vp", "nbf", "_sd", "_sd_alg", "vct"]
                .iter()
                .any(|name| claims.get(*name).is_some())
            {
                return Err(profile_error(
                    "nested or conflicting claims in direct JOSE profile",
                ));
            }
            validate_direct_credential_shape(claims)?;
            Ok(claims)
        }
    }
}

fn validate_vc2_credential_content(credential: &serde_json::Value) -> Oid4vciResult<()> {
    use serde_json::Value;
    if crate::formats::jwt_vc::has_retired_open_badges_profile(credential) {
        return Err(profile_error("Open Badges 2 is retired"));
    }
    if credential
        .get("@context")
        .and_then(Value::as_array)
        .and_then(|contexts| contexts.first())
        .and_then(Value::as_str)
        != Some(VC2_CONTEXT)
        || !contains_type(credential, "VerifiableCredential")
        || contains_type(credential, "VerifiablePresentation")
        || contains_type(credential, "EnvelopedVerifiableCredential")
        || ["vc", "vp", "issuanceDate", "expirationDate"]
            .iter()
            .any(|name| credential.get(*name).is_some())
    {
        return Err(profile_error(
            "selected profile requires unambiguous VCDM2 credential content",
        ));
    }
    Ok(())
}

pub(crate) fn validate_direct_credential_shape(
    credential: &serde_json::Value,
) -> Oid4vciResult<()> {
    use serde_json::Value;
    validate_vc2_credential_content(credential)?;
    for identifier in [
        credential.get("id").and_then(Value::as_str),
        credential.get("issuer").and_then(|value| {
            value
                .as_str()
                .or_else(|| value.get("id").and_then(Value::as_str))
        }),
        credential
            .get("credentialSubject")
            .filter(|value| value.is_object())
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str),
    ] {
        let identifier = identifier
            .filter(|value| !value.is_empty() && value.trim() == *value)
            .ok_or_else(|| {
                profile_error("direct profile requires credential, issuer and subject identifiers")
            })?;
        validate_direct_identifier(identifier)?;
    }
    credential_dates(credential, true)?;
    Ok(())
}

pub(crate) fn validate_direct_identifier(identifier: &str) -> Oid4vciResult<()> {
    // URL parsing can repair characters, malformed percent escapes or raw
    // Unicode. Validate the signed URI spelling without requiring normalized
    // case, escaping or scheme-specific spelling.
    if identifier.is_empty()
        || !identifier.is_ascii()
        || identifier
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(profile_error(
            "direct profile identifiers must be ASCII URIs without whitespace or control characters",
        ));
    }
    let invalid_syntax = std::cell::Cell::new(false);
    url::Url::options()
        .syntax_violation_callback(Some(&|violation| {
            if matches!(
                violation,
                url::SyntaxViolation::Backslash
                    | url::SyntaxViolation::NonUrlCodePoint
                    | url::SyntaxViolation::PercentDecode
                    | url::SyntaxViolation::UnencodedAtSign
            ) {
                invalid_syntax.set(true);
            }
        }))
        .parse(identifier)
        .map_err(|_| profile_error("direct profile identifiers must be absolute URIs"))?;
    if invalid_syntax.get() {
        return Err(profile_error(
            "direct profile identifiers contain invalid raw URI syntax",
        ));
    }
    Ok(())
}

pub(crate) fn contains_type(value: &serde_json::Value, expected: &str) -> bool {
    match value.get("type") {
        Some(serde_json::Value::String(kind)) => kind == expected,
        Some(serde_json::Value::Array(kinds)) => {
            kinds.iter().all(serde_json::Value::is_string)
                && kinds.iter().any(|kind| kind.as_str() == Some(expected))
        }
        _ => false,
    }
}

type CredentialValidityDates = (Option<DateTime<Utc>>, Option<DateTime<Utc>>);

pub(crate) fn credential_dates(
    credential: &serde_json::Value,
    required_from: bool,
) -> Oid4vciResult<CredentialValidityDates> {
    let parse = |name: &str| -> Oid4vciResult<Option<DateTime<Utc>>> {
        match credential.get(name) {
            None => Ok(None),
            Some(value) => {
                let raw = value
                    .as_str()
                    .ok_or_else(|| profile_error("credential validity must be RFC3339 text"))?;
                DateTime::parse_from_rfc3339(raw)
                    .map(|time| Some(time.with_timezone(&Utc)))
                    .map_err(|_| profile_error("credential validity must be RFC3339 text"))
            }
        }
    };
    let from = parse("validFrom")?;
    let until = parse("validUntil")?;
    if required_from && from.is_none() || from.zip(until).is_some_and(|(from, until)| until <= from)
    {
        return Err(profile_error("invalid credential validity interval"));
    }
    Ok((from, until))
}

pub(crate) fn check_credential_dates(
    credential: &serde_json::Value,
    evaluated_at: i64,
    required_from: bool,
) -> Oid4vciResult<CredentialValidityDates> {
    let evaluated = DateTime::from_timestamp(evaluated_at, 0)
        .ok_or_else(|| profile_error("invalid evaluation instant"))?;
    let dates = credential_dates(credential, required_from)?;
    if dates.0.is_some_and(|from| from > evaluated)
        || dates.1.is_some_and(|until| until <= evaluated)
    {
        return Err(profile_error("credential is outside its validity interval"));
    }
    Ok(dates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_and_negotiation_are_exact_and_versioned() {
        for profile in [
            JwtVcSecuringProfile::MartyNestedVc2JwtV1,
            JwtVcSecuringProfile::W3cVc2Jose2026V1,
        ] {
            assert_eq!(
                profile.as_str().parse::<JwtVcSecuringProfile>().unwrap(),
                profile
            );
            assert_eq!(
                JwtVcProfileBinding::negotiate(profile.as_str(), profile.credential_format())
                    .unwrap()
                    .securing_profile(),
                profile
            );
            let other = if profile == JwtVcSecuringProfile::MartyNestedVc2JwtV1 {
                JwtVcSecuringProfile::W3cVc2Jose2026V1
            } else {
                JwtVcSecuringProfile::MartyNestedVc2JwtV1
            };
            assert!(
                JwtVcProfileBinding::negotiate(profile.as_str(), other.credential_format())
                    .is_err()
            );
        }
        for unknown in [
            "",
            "jwt_vc_json",
            "vc+jwt",
            "W3C_VC2_JOSE_2026_V1",
            "w3c_vc2_jose_2026_v2",
            " w3c_vc2_jose_2026_v1",
        ] {
            assert!(unknown.parse::<JwtVcSecuringProfile>().is_err());
            assert!(
                serde_json::from_value::<JwtVcSecuringProfile>(serde_json::json!(unknown)).is_err()
            );
        }
        assert_ne!(
            JwtVcSecuringProfile::MartyNestedVc2JwtV1
                .configuration_id("Badge")
                .unwrap(),
            JwtVcSecuringProfile::W3cVc2Jose2026V1
                .configuration_id("Badge")
                .unwrap()
        );
        assert!(JwtVcSecuringProfile::W3cVc2Jose2026V1
            .configuration_id("Badge#other")
            .is_err());
    }

    #[test]
    fn independent_intervals_do_not_require_equal_start_or_end() {
        let from = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let until = from + chrono::Duration::days(365);
        let timing =
            JwtVcProfileTiming::new(1_700_000_100, 1_700_003_700, from, Some(until)).unwrap();
        assert_ne!(
            timing.signature_issued_at(),
            timing.credential_valid_from().timestamp()
        );
        assert_ne!(
            timing.signature_expires_at(),
            timing.credential_valid_until().unwrap().timestamp()
        );
        assert!(JwtVcProfileTiming::new(100, 100, from, None).is_err());
        assert!(JwtVcProfileTiming::new(100, 200, until, Some(from)).is_err());
    }

    #[test]
    fn issuance_and_presentation_negotiation_bind_the_same_explicit_profile() {
        use crate::metadata::{
            admit_profiled_jwt_vc_configuration, profile_jwt_vc_configuration,
            CredentialConfiguration,
        };
        use crate::presentation_request::{
            build_profiled_jwt_vc_query, profiled_jwt_vc_query_binding,
        };
        use serde_json::json;
        let source: CredentialConfiguration = serde_json::from_value(json!({
            "format": "jwt_vc_json",
            "cryptographic_binding_methods_supported": ["did:jwk"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {},
            "credential_definition": {"type": ["VerifiableCredential", "OpenBadgeCredential"]},
        }))
        .unwrap();
        let profile = JwtVcSecuringProfile::W3cVc2Jose2026V1;
        let configuration = profile_jwt_vc_configuration("Badge", profile, &source).unwrap();
        assert_eq!(configuration.id(), "Badge#vc2-jose-2026-v1");
        let binding =
            admit_profiled_jwt_vc_configuration(configuration.id(), configuration.metadata())
                .unwrap();
        assert_eq!(binding, configuration.binding());
        assert!(admit_profiled_jwt_vc_configuration("Badge", configuration.metadata()).is_err());
        let query = build_profiled_jwt_vc_query(
            "badge",
            binding,
            vec![vec!["OpenBadgeCredential".into()]],
            true,
        )
        .unwrap();
        assert_eq!(profiled_jwt_vc_query_binding(&query).unwrap(), binding);
        for field in ["format", "marty_securing_profile"] {
            let mut metadata = configuration.metadata().clone();
            metadata.as_object_mut().unwrap().remove(field);
            assert!(admit_profiled_jwt_vc_configuration(configuration.id(), &metadata).is_err());
        }
        let mut downgrade = query.clone();
        downgrade["format"] = json!("jwt_vc_json");
        assert!(profiled_jwt_vc_query_binding(&downgrade).is_err());
        let mut missing = query;
        missing["meta"]
            .as_object_mut()
            .unwrap()
            .remove("marty_securing_profile");
        assert!(profiled_jwt_vc_query_binding(&missing).is_err());
    }
}
