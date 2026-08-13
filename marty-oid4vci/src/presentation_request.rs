//! Canonical construction of OID4VP Presentation Exchange and DCQL requests.
//!
//! Service callers fetch policy and credential-template records, then pass the
//! resulting data to this module. Format families, algorithm policy, claim
//! paths, application-profile aliases, and fail-closed validation live here so
//! Python and mobile adapters cannot produce divergent request objects.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::formats::credential_profile_presentation_metadata;

const MAX_REQUIREMENTS: usize = 64;
const MAX_WALLET_FORMATS: usize = 32;
const MAX_CLAIMS_PER_REQUIREMENT: usize = 256;
const MAX_TEXT_BYTES: usize = 2_048;

/// Application data needed to build one credential request.
#[derive(Debug, Clone, Deserialize)]
pub struct PresentationRequirementInput {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub credential_type: Option<String>,
    #[serde(default)]
    pub credential_vct: Option<String>,
    #[serde(default)]
    pub credential_doctype: Option<String>,
    pub supported_formats: Vec<String>,
    #[serde(default)]
    pub requested_claims: Vec<RequestedClaimInput>,
    #[serde(default)]
    pub mdoc_claims: Vec<MdocClaimInput>,
}

/// One policy claim request.
#[derive(Debug, Clone, Deserialize)]
pub struct RequestedClaimInput {
    pub claim_name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub intent_to_retain: bool,
}

/// ISO 18013 namespace/element mapping supplied by a credential template.
#[derive(Debug, Clone, Deserialize)]
pub struct MdocClaimInput {
    pub claim_name: String,
    pub namespace: String,
    pub element_identifier: String,
}

/// Complete deterministic input for request construction.
#[derive(Debug, Clone, Deserialize)]
pub struct PresentationRequestBuildInput {
    pub id: String,
    pub requirements: Vec<PresentationRequirementInput>,
    pub wallet_formats: Vec<String>,
}

/// Both interoperable query representations generated from one decision.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PresentationRequestArtifacts {
    pub presentation_definition: Value,
    pub dcql_query: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FormatFamily {
    SdJwt,
    Mdoc,
    JwtVc,
    LdpVc,
}

/// Build equivalent Presentation Exchange and DCQL credential queries.
pub fn build_presentation_request(
    input: PresentationRequestBuildInput,
) -> Oid4vciResult<PresentationRequestArtifacts> {
    validate_text("presentation definition id", &input.id)?;
    if input.requirements.is_empty() {
        return Err(config_error(
            "OID4VP request requires at least one credential requirement",
        ));
    }
    if input.requirements.len() > MAX_REQUIREMENTS {
        return Err(config_error(format!(
            "OID4VP request exceeds {MAX_REQUIREMENTS} credential requirements"
        )));
    }

    let wallet_formats = normalize_wallet_formats(&input.wallet_formats)?;
    let mut descriptor_ids = HashSet::new();
    let mut descriptors = Vec::with_capacity(input.requirements.len());
    let mut dcql_credentials = Vec::with_capacity(input.requirements.len());
    let mut top_formats = Map::new();

    for (index, requirement) in input.requirements.into_iter().enumerate() {
        let descriptor_id = non_empty_or(requirement.id.as_deref(), format!("descriptor-{index}"));
        validate_text("descriptor id", &descriptor_id)?;
        if !descriptor_ids.insert(descriptor_id.clone()) {
            return Err(config_error(format!(
                "duplicate OID4VP descriptor id: {descriptor_id}"
            )));
        }
        if requirement.requested_claims.len() > MAX_CLAIMS_PER_REQUIREMENT {
            return Err(config_error(format!(
                "descriptor {descriptor_id} exceeds {MAX_CLAIMS_PER_REQUIREMENT} requested claims"
            )));
        }

        let selected_formats = select_formats(
            &requirement.supported_formats,
            &wallet_formats,
            &descriptor_id,
        )?;
        let first_format = selected_formats
            .first()
            .expect("format selection returns at least one value");
        let first_family = format_family(first_format)?;

        let display_name = non_empty_or(
            requirement.display_name.as_deref(),
            format!("Credential {}", index + 1),
        );
        let purpose = non_empty_or(
            requirement.description.as_deref(),
            format!("Present {display_name}"),
        );
        validate_text("descriptor display name", &display_name)?;
        validate_text("descriptor purpose", &purpose)?;

        let credential_type = trimmed(requirement.credential_type.as_deref());
        let credential_vct = trimmed(requirement.credential_vct.as_deref());
        let credential_doctype = trimmed(requirement.credential_doctype.as_deref());
        let profile = credential_type
            .filter(|value| value.eq_ignore_ascii_case("open_badge"))
            .map(|_| "open_badge");
        let profile_metadata = profile
            .map(|profile| {
                credential_profile_presentation_metadata(
                    profile,
                    first_format,
                    credential_vct.unwrap_or_default(),
                )
            })
            .transpose()?;

        let effective_type = if let Some(metadata) = profile_metadata.as_ref() {
            metadata["meta"]["type_values"]
                .as_array()
                .and_then(|sets| sets.first())
                .and_then(Value::as_array)
                .and_then(|values| values.last())
                .and_then(Value::as_str)
                .or(credential_type)
        } else {
            credential_type
        };

        let mut fields = credential_selector_fields(
            first_family,
            effective_type,
            credential_vct,
            credential_doctype,
            profile_metadata.as_ref(),
        )?;
        let mdoc_mappings = validate_mdoc_mappings(&requirement.mdoc_claims)?;
        let requested_claims = validate_requested_claims(&requirement.requested_claims)?;
        for claim in &requested_claims {
            fields.push(presentation_exchange_claim(claim));
        }

        let mut format_object = Map::new();
        for format in &selected_formats {
            let requirement = format_requirement(format)?;
            top_formats
                .entry(format.clone())
                .or_insert_with(|| requirement.clone());
            format_object.insert(format.clone(), requirement);
        }

        let mut constraints = Map::new();
        constraints.insert("fields".into(), Value::Array(fields));
        if first_family == FormatFamily::SdJwt {
            constraints.insert("limit_disclosure".into(), Value::String("required".into()));
        }
        let descriptor = json!({
            "id": descriptor_id,
            "name": display_name,
            "purpose": purpose,
            "format": format_object,
            "constraints": constraints,
        });

        let canonical_format = profile_metadata
            .as_ref()
            .and_then(|metadata| metadata["format"].as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| dcql_format(first_family).to_owned());
        let meta = dcql_meta(
            first_family,
            effective_type,
            credential_vct,
            credential_doctype,
            profile_metadata.as_ref(),
        )?;
        let claims = dcql_claims(
            first_family,
            &requested_claims,
            &mdoc_mappings,
            &descriptor_id,
        )?;
        let mut dcql_entry = Map::new();
        dcql_entry.insert("id".into(), Value::String(descriptor_id));
        dcql_entry.insert("format".into(), Value::String(canonical_format));
        dcql_entry.insert("meta".into(), meta);
        if !claims.is_empty() {
            dcql_entry.insert("claims".into(), Value::Array(claims));
        }

        descriptors.push(descriptor);
        dcql_credentials.push(Value::Object(dcql_entry));
    }

    Ok(PresentationRequestArtifacts {
        presentation_definition: json!({
            "id": input.id,
            "format": top_formats,
            "input_descriptors": descriptors,
        }),
        dcql_query: json!({"credentials": dcql_credentials}),
    })
}

fn normalize_wallet_formats(values: &[String]) -> Oid4vciResult<Vec<String>> {
    if values.is_empty() {
        return Err(config_error("OID4VP wallet format registry is empty"));
    }
    if values.len() > MAX_WALLET_FORMATS {
        return Err(config_error(format!(
            "OID4VP wallet format registry exceeds {MAX_WALLET_FORMATS} entries"
        )));
    }
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for value in values {
        let normalized = value.trim().to_ascii_lowercase();
        validate_text("wallet format", &normalized)?;
        format_family(&normalized)?;
        if seen.insert(normalized.clone()) {
            result.push(normalized);
        }
    }
    if result.is_empty() {
        return Err(config_error("OID4VP wallet format registry is empty"));
    }
    Ok(result)
}

fn select_formats(
    template_formats: &[String],
    wallet_formats: &[String],
    descriptor_id: &str,
) -> Oid4vciResult<Vec<String>> {
    if template_formats.is_empty() {
        return Err(config_error(format!(
            "descriptor {descriptor_id} has no credential formats"
        )));
    }
    let mut families = HashSet::new();
    for format in template_formats {
        families.insert(format_family(format)?);
    }
    let selected: Vec<String> = wallet_formats
        .iter()
        .filter_map(|format| {
            format_family(format)
                .ok()
                .filter(|family| families.contains(family))
                .map(|_| format.clone())
        })
        .collect();
    if selected.is_empty() {
        return Err(Oid4vciError::UnsupportedFormat(format!(
            "descriptor {descriptor_id} has no wallet-compatible credential format"
        )));
    }
    Ok(selected)
}

fn format_family(value: &str) -> Oid4vciResult<FormatFamily> {
    match value.trim().to_ascii_lowercase().as_str() {
        "sd_jwt_vc" | "vc+sd-jwt" | "dc+sd-jwt" => Ok(FormatFamily::SdJwt),
        "mso_mdoc" | "mdoc" => Ok(FormatFamily::Mdoc),
        "jwt_vp" | "jwt_vc" | "jwt_vc_json" => Ok(FormatFamily::JwtVc),
        "ldp_vp" | "ldp_vc" => Ok(FormatFamily::LdpVc),
        _ => Err(Oid4vciError::UnsupportedFormat(format!(
            "unsupported OID4VP credential format: {value}"
        ))),
    }
}

fn format_requirement(value: &str) -> Oid4vciResult<Value> {
    Ok(match format_family(value)? {
        FormatFamily::SdJwt => json!({
            "sd-jwt_alg_values": ["ES256", "EdDSA"],
            "kb-jwt_alg_values": ["ES256", "EdDSA"],
        }),
        FormatFamily::Mdoc => json!({"alg": ["ES256", "ES384"]}),
        FormatFamily::JwtVc => json!({"alg": ["ES256", "EdDSA"]}),
        FormatFamily::LdpVc => json!({"proof_type": ["Ed25519Signature2020"]}),
    })
}

fn credential_selector_fields(
    family: FormatFamily,
    credential_type: Option<&str>,
    credential_vct: Option<&str>,
    credential_doctype: Option<&str>,
    profile_metadata: Option<&Value>,
) -> Oid4vciResult<Vec<Value>> {
    match family {
        FormatFamily::Mdoc => {
            let doctype = credential_doctype.or(credential_type).ok_or_else(|| {
                config_error("mDoc request requires a doctype or credential type")
            })?;
            Ok(vec![json!({
                "path": ["$.mdoc.docType", "$.docType"],
                "filter": {"type": "string", "const": doctype},
            })])
        }
        FormatFamily::SdJwt => {
            let vct_values = profile_metadata
                .and_then(|metadata| metadata["meta"]["vct_values"].as_array())
                .cloned()
                .unwrap_or_else(|| {
                    credential_vct
                        .or(credential_type)
                        .map(|value| vec![Value::String(value.to_owned())])
                        .unwrap_or_default()
                });
            if vct_values.is_empty() {
                return Err(config_error("SD-JWT request requires a vct"));
            }
            let mut fields = vec![json!({
                "path": ["$.vct"],
                "filter": string_filter(vct_values),
            })];
            if let Some(credential_type) = credential_type {
                fields.push(type_filter(credential_type, true));
            }
            Ok(fields)
        }
        FormatFamily::JwtVc | FormatFamily::LdpVc => {
            let credential_type = credential_type
                .ok_or_else(|| config_error("W3C credential request requires a type"))?;
            Ok(vec![type_filter(credential_type, false)])
        }
    }
}

fn type_filter(credential_type: &str, optional: bool) -> Value {
    let mut field = json!({
        "path": ["$.vc.type", "$.type"],
        "filter": {
            "anyOf": [
                {"type": "array", "contains": {"const": credential_type}},
                {"type": "string", "const": credential_type},
            ],
        },
    });
    if optional {
        field["optional"] = Value::Bool(true);
    }
    field
}

fn string_filter(values: Vec<Value>) -> Value {
    if values.len() == 1 {
        json!({"type": "string", "const": values[0]})
    } else {
        json!({"type": "string", "enum": values})
    }
}

fn validate_requested_claims(
    claims: &[RequestedClaimInput],
) -> Oid4vciResult<Vec<RequestedClaimInput>> {
    let mut seen = HashSet::new();
    let mut result = Vec::with_capacity(claims.len());
    for claim in claims {
        validate_claim_name(&claim.claim_name)?;
        if !seen.insert(claim.claim_name.clone()) {
            return Err(config_error(format!(
                "duplicate requested claim: {}",
                claim.claim_name
            )));
        }
        if let Some(value) = claim.display_name.as_deref() {
            validate_text("claim display name", value)?;
        }
        if let Some(value) = claim.purpose.as_deref() {
            validate_text("claim purpose", value)?;
        }
        result.push(claim.clone());
    }
    Ok(result)
}

fn validate_mdoc_mappings(
    mappings: &[MdocClaimInput],
) -> Oid4vciResult<HashMap<String, (&str, &str)>> {
    let mut result = HashMap::new();
    for mapping in mappings {
        validate_claim_name(&mapping.claim_name)?;
        validate_text("mDoc namespace", &mapping.namespace)?;
        validate_text("mDoc element identifier", &mapping.element_identifier)?;
        if result
            .insert(
                mapping.claim_name.clone(),
                (
                    mapping.namespace.as_str(),
                    mapping.element_identifier.as_str(),
                ),
            )
            .is_some()
        {
            return Err(config_error(format!(
                "duplicate mDoc claim mapping: {}",
                mapping.claim_name
            )));
        }
    }
    Ok(result)
}

fn presentation_exchange_claim(claim: &RequestedClaimInput) -> Value {
    let display_name = claim
        .display_name
        .clone()
        .unwrap_or_else(|| title_case_claim(&claim.claim_name));
    let purpose = claim
        .purpose
        .clone()
        .unwrap_or_else(|| format!("Share {display_name}"));
    json!({
        "name": display_name,
        "purpose": purpose,
        "path": [
            format!("$.vc.credentialSubject.{}", claim.claim_name),
            format!("$.credentialSubject.{}", claim.claim_name),
            format!("$.{}", claim.claim_name),
        ],
        "intent_to_retain": claim.intent_to_retain,
        "optional": !claim.required,
    })
}

fn dcql_meta(
    family: FormatFamily,
    credential_type: Option<&str>,
    credential_vct: Option<&str>,
    credential_doctype: Option<&str>,
    profile_metadata: Option<&Value>,
) -> Oid4vciResult<Value> {
    if let Some(metadata) = profile_metadata {
        return Ok(metadata["meta"].clone());
    }
    match family {
        FormatFamily::Mdoc => Ok(json!({
            "doctype_value": credential_doctype.or(credential_type).ok_or_else(|| {
                config_error("mDoc DCQL query requires a doctype or credential type")
            })?,
        })),
        FormatFamily::SdJwt => Ok(json!({
            "vct_values": [credential_vct.or(credential_type).ok_or_else(|| {
                config_error("SD-JWT DCQL query requires a vct")
            })?],
        })),
        FormatFamily::JwtVc | FormatFamily::LdpVc => Ok(json!({
            "type_values": [[
                "VerifiableCredential",
                credential_type.ok_or_else(|| {
                    config_error("W3C DCQL query requires a credential type")
                })?,
            ]],
        })),
    }
}

fn dcql_claims(
    family: FormatFamily,
    claims: &[RequestedClaimInput],
    mdoc_mappings: &HashMap<String, (&str, &str)>,
    descriptor_id: &str,
) -> Oid4vciResult<Vec<Value>> {
    if family == FormatFamily::Mdoc {
        return claims
            .iter()
            .map(|claim| {
                let (namespace, element) =
                    mdoc_mappings.get(&claim.claim_name).ok_or_else(|| {
                        config_error(format!(
                            "descriptor {descriptor_id} is missing the mDoc mapping for {}",
                            claim.claim_name
                        ))
                    })?;
                Ok(json!({
                    "id": claim_id(&claim.claim_name),
                    "path": [namespace, element],
                    "intent_to_retain": claim.intent_to_retain,
                }))
            })
            .collect();
    }

    let has_required = claims.iter().any(|claim| claim.required);
    Ok(claims
        .iter()
        .filter(|claim| !has_required || claim.required)
        .map(|claim| {
            json!({
                "id": claim_id(&claim.claim_name),
                "path": [claim.claim_name],
            })
        })
        .collect())
}

fn dcql_format(family: FormatFamily) -> &'static str {
    match family {
        FormatFamily::SdJwt => "dc+sd-jwt",
        FormatFamily::Mdoc => "mso_mdoc",
        FormatFamily::JwtVc => "jwt_vc_json",
        FormatFamily::LdpVc => "ldp_vc",
    }
}

fn claim_id(value: &str) -> String {
    format!(
        "claim_{}",
        value
            .chars()
            .map(|character| match character {
                '-' | '.' => '_',
                other => other,
            })
            .collect::<String>()
    )
}

fn title_case_claim(value: &str) -> String {
    value
        .split(['_', '-', '.'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            match characters.next() {
                Some(first) => first.to_uppercase().chain(characters).collect(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_claim_name(value: &str) -> Oid4vciResult<()> {
    validate_text("claim name", value)?;
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "_-.".contains(character))
    {
        return Err(config_error(format!("invalid claim name: {value}")));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str) -> Oid4vciResult<()> {
    if value.trim().is_empty() {
        return Err(config_error(format!("{label} must not be empty")));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(config_error(format!(
            "{label} exceeds {MAX_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn non_empty_or(value: Option<&str>, fallback: String) -> String {
    trimmed(value).map(str::to_owned).unwrap_or(fallback)
}

fn config_error(message: impl Into<String>) -> Oid4vciError {
    Oid4vciError::ConfigError(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(name: &str, required: bool) -> RequestedClaimInput {
        RequestedClaimInput {
            claim_name: name.into(),
            display_name: None,
            purpose: None,
            required,
            intent_to_retain: false,
        }
    }

    fn requirement(format: &str) -> PresentationRequirementInput {
        PresentationRequirementInput {
            id: Some("member".into()),
            display_name: Some("Member credential".into()),
            description: Some("Verify membership".into()),
            credential_type: Some("MemberCredential".into()),
            credential_vct: Some("https://issuer.example/member".into()),
            credential_doctype: None,
            supported_formats: vec![format.into()],
            requested_claims: vec![claim("email", true), claim("nickname", false)],
            mdoc_claims: vec![],
        }
    }

    #[test]
    fn sd_jwt_request_has_one_canonical_policy_decision() {
        let result = build_presentation_request(PresentationRequestBuildInput {
            id: "pd-1".into(),
            requirements: vec![requirement("sd_jwt_vc")],
            wallet_formats: vec!["dc+sd-jwt".into(), "mso_mdoc".into()],
        })
        .unwrap();

        let descriptor = &result.presentation_definition["input_descriptors"][0];
        assert_eq!(descriptor["constraints"]["limit_disclosure"], "required");
        assert_eq!(
            descriptor["format"]["dc+sd-jwt"]["sd-jwt_alg_values"],
            json!(["ES256", "EdDSA"])
        );
        assert_eq!(result.dcql_query["credentials"][0]["format"], "dc+sd-jwt");
        assert_eq!(
            result.dcql_query["credentials"][0]["claims"],
            json!([{"id": "claim_email", "path": ["email"]}])
        );
    }

    #[test]
    fn shared_golden_vector_matches_the_rust_builder() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/vectors/oid4vp_request_builder.json"
        ))
        .unwrap();
        for vector in fixture["valid"].as_array().unwrap() {
            let request: PresentationRequestBuildInput =
                serde_json::from_value(vector["request"].clone()).unwrap();
            let result = build_presentation_request(request).unwrap();
            assert_eq!(serde_json::to_value(result).unwrap(), vector["expected"]);
        }
        for vector in fixture["invalid"].as_array().unwrap() {
            let request: PresentationRequestBuildInput =
                serde_json::from_value(vector["request"].clone()).unwrap();
            let error = build_presentation_request(request).unwrap_err();
            assert!(error
                .to_string()
                .contains(vector["error_contains"].as_str().unwrap()));
        }
    }

    #[test]
    fn open_badge_aliases_are_resolved_in_rust() {
        let mut open_badge = requirement("dc+sd-jwt");
        open_badge.credential_type = Some("open_badge".into());
        open_badge.credential_vct =
            Some("https://beta.elevenidllc.com/credentials/marty-verified-member-badge".into());
        let result = build_presentation_request(PresentationRequestBuildInput {
            id: "pd-badge".into(),
            requirements: vec![open_badge],
            wallet_formats: vec!["dc+sd-jwt".into()],
        })
        .unwrap();

        assert_eq!(
            result.dcql_query["credentials"][0]["meta"]["vct_values"],
            json!([
                "https://beta.elevenidllc.com/credentials/marty-verified-member-badge",
                "https://marty.example/credentials/open_badge"
            ])
        );
    }

    #[test]
    fn mdoc_claims_use_template_namespace_mappings() {
        let mut mdoc = requirement("mso_mdoc");
        mdoc.credential_type = Some("org.iso.18013.5.1.mDL".into());
        mdoc.credential_doctype = Some("org.iso.18013.5.1.mDL".into());
        mdoc.requested_claims = vec![claim("family_name", true)];
        mdoc.mdoc_claims = vec![MdocClaimInput {
            claim_name: "family_name".into(),
            namespace: "org.iso.18013.5.1".into(),
            element_identifier: "family_name".into(),
        }];
        let result = build_presentation_request(PresentationRequestBuildInput {
            id: "pd-mdoc".into(),
            requirements: vec![mdoc],
            wallet_formats: vec!["mso_mdoc".into()],
        })
        .unwrap();

        assert_eq!(
            result.dcql_query["credentials"][0],
            json!({
                "id": "member",
                "format": "mso_mdoc",
                "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                "claims": [{
                    "id": "claim_family_name",
                    "path": ["org.iso.18013.5.1", "family_name"],
                    "intent_to_retain": false
                }]
            })
        );
    }

    #[test]
    fn missing_or_unsupported_inputs_fail_closed() {
        let empty = build_presentation_request(PresentationRequestBuildInput {
            id: "pd-empty".into(),
            requirements: vec![],
            wallet_formats: vec!["dc+sd-jwt".into()],
        });
        assert!(empty.is_err());

        let no_intersection = build_presentation_request(PresentationRequestBuildInput {
            id: "pd-no-match".into(),
            requirements: vec![requirement("mso_mdoc")],
            wallet_formats: vec!["dc+sd-jwt".into()],
        });
        assert!(no_intersection.is_err());

        let unknown = build_presentation_request(PresentationRequestBuildInput {
            id: "pd-unknown".into(),
            requirements: vec![requirement("made-up-format")],
            wallet_formats: vec!["dc+sd-jwt".into()],
        });
        assert!(unknown.is_err());
    }
}
