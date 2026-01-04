use std::collections::HashMap;

use ssi::json_ld::ContextLoader;

use crate::error::{VerificationError, VerificationResult};

const CONTEXT_OPENBADGES_V2: &str = "https://w3id.org/openbadges/v2";
const CONTEXT_OPENBADGES_V3: &str = "https://purl.imsglobal.org/spec/ob/v3p0/context.json";
const CONTEXT_OPENBADGES_V3_ALIAS: &str = "https://w3id.org/openbadges/v3";
const CONTEXT_VC_V1: &str = "https://www.w3.org/2018/credentials/v1";
const CONTEXT_VC_V2: &str = "https://www.w3.org/ns/credentials/v2";
const CONTEXT_DATA_INTEGRITY_V2: &str = "https://w3id.org/security/data-integrity/v2";
const CONTEXT_SECURITY_V1: &str = "https://w3id.org/security/v1";
const CONTEXT_SECURITY_V2: &str = "https://w3id.org/security/v2";
const CONTEXT_SECURITY_ED25519_2020: &str = "https://w3id.org/security/suites/ed25519-2020/v1";
const CONTEXT_SECURITY_JWS_2020: &str = "https://w3id.org/security/suites/jws-2020/v1";

const CONTEXT_FILE_OPENBADGES_V2: &str = include_str!("contexts/openbadges-v2.jsonld");
const CONTEXT_FILE_OPENBADGES_V3: &str = include_str!("contexts/openbadges-v3.jsonld");
const CONTEXT_FILE_VC_V1: &str = include_str!("contexts/credentials-v1.jsonld");
const CONTEXT_FILE_VC_V2: &str = include_str!("contexts/credentials-v2.jsonld");
const CONTEXT_FILE_DATA_INTEGRITY_V2: &str = include_str!("contexts/security-data-integrity-v2.jsonld");
const CONTEXT_FILE_SECURITY_V1: &str = include_str!("contexts/security-v1.jsonld");
const CONTEXT_FILE_SECURITY_V2: &str = include_str!("contexts/security-v2.jsonld");
const CONTEXT_FILE_SECURITY_ED25519_2020: &str = include_str!("contexts/security-ed25519-2020.jsonld");
const CONTEXT_FILE_SECURITY_JWS_2020: &str = include_str!("contexts/security-jws-2020.jsonld");

pub fn open_badges_context_loader() -> VerificationResult<ContextLoader> {
    let mut context_map = HashMap::new();

    context_map.insert(CONTEXT_OPENBADGES_V2.to_string(), CONTEXT_FILE_OPENBADGES_V2.to_string());
    context_map.insert(CONTEXT_OPENBADGES_V3.to_string(), CONTEXT_FILE_OPENBADGES_V3.to_string());
    context_map.insert(
        CONTEXT_OPENBADGES_V3_ALIAS.to_string(),
        CONTEXT_FILE_OPENBADGES_V3.to_string(),
    );
    context_map.insert(CONTEXT_VC_V1.to_string(), CONTEXT_FILE_VC_V1.to_string());
    context_map.insert(CONTEXT_VC_V2.to_string(), CONTEXT_FILE_VC_V2.to_string());
    context_map.insert(
        CONTEXT_DATA_INTEGRITY_V2.to_string(),
        CONTEXT_FILE_DATA_INTEGRITY_V2.to_string(),
    );
    context_map.insert(CONTEXT_SECURITY_V1.to_string(), CONTEXT_FILE_SECURITY_V1.to_string());
    context_map.insert(CONTEXT_SECURITY_V2.to_string(), CONTEXT_FILE_SECURITY_V2.to_string());
    context_map.insert(
        CONTEXT_SECURITY_ED25519_2020.to_string(),
        CONTEXT_FILE_SECURITY_ED25519_2020.to_string(),
    );
    context_map.insert(
        CONTEXT_SECURITY_JWS_2020.to_string(),
        CONTEXT_FILE_SECURITY_JWS_2020.to_string(),
    );

    // Use only pinned contexts so OB3+VC v2 compatibility tweaks take effect.
    ContextLoader::empty()
        .with_context_map_from(context_map)
        .map_err(|e| VerificationError::open_badges(format!("Failed to build context loader: {}", e)))
}

pub fn ob2_context_uri() -> &'static str {
    CONTEXT_OPENBADGES_V2
}

pub fn ob3_context_uri() -> &'static str {
    CONTEXT_OPENBADGES_V3
}

pub fn security_v2_context_uri() -> &'static str {
    CONTEXT_SECURITY_V2
}
