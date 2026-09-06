use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const PRIVATE_JWK_MEMBERS: [&str; 9] = ["d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const MODELED_JWK_MEMBERS: [&str; 5] = ["kty", "crv", "x", "y", "kid"];
const MODELED_DID_DOCUMENT_MEMBERS: [&str; 7] = [
    "id",
    "@context",
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "verificationMethod",
    "service",
];
const MODELED_VERIFICATION_METHOD_MEMBERS: [&str; 6] = [
    "id",
    "type",
    "controller",
    "publicKeyJwk",
    "publicKeyMultibase",
    "publicKeyBase58",
];
const PRIVATE_VERIFICATION_METHOD_MEMBERS: [&str; 5] = [
    "privateKeyJwk",
    "privateKeyPem",
    "privateKeyBase58",
    "privateKeyMultibase",
    "privateKeyHex",
];

fn reject_modeled_collisions(
    extensions: &serde_json::Map<String, serde_json::Value>,
    modeled: &[&str],
    kind: &str,
) -> Result<(), String> {
    if let Some(member) = modeled
        .iter()
        .find(|member| extensions.contains_key(**member))
    {
        return Err(format!(
            "{kind} extension collides with modeled member '{member}'"
        ));
    }
    Ok(())
}

fn deserialize_public_jwk_extensions<'de, D>(
    deserializer: D,
) -> Result<serde_json::Map<String, serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let extensions = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
    if let Some(member) = PRIVATE_JWK_MEMBERS
        .iter()
        .find(|member| extensions.contains_key(**member))
    {
        return Err(serde::de::Error::custom(format!(
            "DID verification methods must not contain private JWK member '{member}'"
        )));
    }
    Ok(extensions)
}

fn validate_private_key_extensions(
    extensions: &serde_json::Map<String, serde_json::Value>,
    kind: &str,
) -> Result<(), String> {
    if let Some(member) = PRIVATE_VERIFICATION_METHOD_MEMBERS
        .iter()
        .find(|member| extensions.contains_key(**member))
    {
        return Err(format!(
            "{kind} must not contain private key member '{member}'"
        ));
    }
    Ok(())
}

fn deserialize_verification_method_extensions<'de, D>(
    deserializer: D,
) -> Result<serde_json::Map<String, serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let extensions = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
    validate_private_key_extensions(&extensions, "DID verification methods")
        .map_err(serde::de::Error::custom)?;
    Ok(extensions)
}

fn deserialize_did_document_extensions<'de, D>(
    deserializer: D,
) -> Result<serde_json::Map<String, serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let extensions = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
    validate_private_key_extensions(&extensions, "DID documents")
        .map_err(serde::de::Error::custom)?;
    Ok(extensions)
}

fn validate_verification_relationships(relationships: &[serde_json::Value]) -> Result<(), String> {
    for relationship in relationships {
        match relationship {
            serde_json::Value::String(_) => {}
            serde_json::Value::Object(_) => {
                serde_json::from_value::<VerificationMethod>(relationship.clone())
                    .map_err(|error| format!("invalid DID verification relationship: {error}"))?;
            }
            _ => {
                return Err(
                    "DID verification relationships must be method references or inline methods"
                        .into(),
                )
            }
        }
    }
    Ok(())
}

fn deserialize_verification_relationships<'de, D>(
    deserializer: D,
) -> Result<Vec<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let relationships = Vec::<serde_json::Value>::deserialize(deserializer)?;
    validate_verification_relationships(&relationships).map_err(serde::de::Error::custom)?;
    Ok(relationships)
}

/// W3C DID Document (simplified for DIDComm v2 use cases).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    #[serde(default)]
    pub id: String,

    #[serde(default, rename = "@context")]
    pub context: serde_json::Value,

    #[serde(default, deserialize_with = "deserialize_verification_relationships")]
    pub(crate) authentication: Vec<serde_json::Value>,

    #[serde(default, deserialize_with = "deserialize_verification_relationships")]
    pub(crate) assertion_method: Vec<serde_json::Value>,

    #[serde(default, deserialize_with = "deserialize_verification_relationships")]
    pub(crate) key_agreement: Vec<serde_json::Value>,

    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,

    #[serde(default)]
    pub service: Vec<ServiceEntry>,

    #[serde(
        default,
        flatten,
        deserialize_with = "deserialize_did_document_extensions"
    )]
    pub(crate) additional_properties: serde_json::Map<String, serde_json::Value>,
}

impl DidDocument {
    /// Construct an empty DID document with no unchecked extension members.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            context: serde_json::Value::Null,
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            verification_method: Vec::new(),
            service: Vec::new(),
            additional_properties: serde_json::Map::new(),
        }
    }

    /// Return extension members without permitting unchecked external mutation.
    pub fn additional_properties(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.additional_properties
    }

    /// Return the validated authentication relationships.
    pub fn authentication(&self) -> &[serde_json::Value] {
        &self.authentication
    }

    /// Replace authentication relationships after validating inline methods.
    pub fn set_authentication(
        &mut self,
        relationships: Vec<serde_json::Value>,
    ) -> Result<(), String> {
        validate_verification_relationships(&relationships)?;
        self.authentication = relationships;
        Ok(())
    }

    /// Return the validated assertion-method relationships.
    pub fn assertion_methods(&self) -> &[serde_json::Value] {
        &self.assertion_method
    }

    /// Replace assertion-method relationships after validating inline methods.
    pub fn set_assertion_methods(
        &mut self,
        relationships: Vec<serde_json::Value>,
    ) -> Result<(), String> {
        validate_verification_relationships(&relationships)?;
        self.assertion_method = relationships;
        Ok(())
    }

    /// Return the validated key-agreement relationships.
    pub fn key_agreements(&self) -> &[serde_json::Value] {
        &self.key_agreement
    }

    /// Replace key-agreement relationships after validating inline methods.
    pub fn set_key_agreements(
        &mut self,
        relationships: Vec<serde_json::Value>,
    ) -> Result<(), String> {
        validate_verification_relationships(&relationships)?;
        self.key_agreement = relationships;
        Ok(())
    }

    /// Add extensions after rejecting collisions with modeled DID document members.
    pub fn with_additional_properties(
        mut self,
        additional_properties: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Self, String> {
        reject_modeled_collisions(
            &additional_properties,
            &MODELED_DID_DOCUMENT_MEMBERS,
            "DID document",
        )?;
        validate_private_key_extensions(&additional_properties, "DID documents")?;
        self.additional_properties = additional_properties;
        Ok(self)
    }

    /// Find the first DIDCommMessaging service endpoint URI.
    pub fn didcomm_endpoint(&self) -> Option<&str> {
        for svc in &self.service {
            if svc.r#type == "DIDCommMessaging" {
                return Some(svc.service_endpoint.uri());
            }
        }
        None
    }

    /// Find all X25519 methods explicitly authorized by `keyAgreement`.
    ///
    /// The method ID and public key are selected atomically so a JWE `kid`
    /// cannot identify a different verification method than the key material
    /// used for encryption. Verification methods that merely appear in
    /// `verificationMethod` are not authorized for key agreement.
    pub fn x25519_key_agreement_methods(&self) -> Result<Vec<(String, [u8; 32])>, String> {
        let mut registry = HashMap::new();
        for method in &self.verification_method {
            let method_id = canonical_method_id(&self.id, &method.id)
                .ok_or_else(|| format!("invalid verification method id '{}'", method.id))?;
            if registry.insert(method_id.clone(), method).is_some() {
                return Err(format!(
                    "duplicate verification method id '{method_id}' in DID document"
                ));
            }
        }

        let mut methods = Vec::new();
        let mut authorized_ids = HashSet::new();
        for relationship in &self.key_agreement {
            let method = if let Some(reference) = relationship.as_str() {
                let reference = canonical_method_id(&self.id, reference)
                    .ok_or_else(|| format!("invalid keyAgreement reference '{reference}'"))?;
                if !authorized_ids.insert(reference.clone()) {
                    return Err(format!("duplicate keyAgreement method '{reference}'"));
                }
                registry.get(&reference).copied().ok_or_else(|| {
                    format!("keyAgreement reference '{reference}' has no verification method")
                })?
            } else {
                let method = serde_json::from_value::<VerificationMethod>(relationship.clone())
                    .map_err(|error| format!("invalid inline keyAgreement method: {error}"))?;
                let method_id = canonical_method_id(&self.id, &method.id)
                    .ok_or_else(|| format!("invalid inline method id '{}'", method.id))?;
                if registry.contains_key(&method_id) {
                    return Err(format!(
                        "inline keyAgreement method '{method_id}' conflicts with verificationMethod"
                    ));
                }
                if !authorized_ids.insert(method_id.clone()) {
                    return Err(format!("duplicate keyAgreement method '{method_id}'"));
                }
                if let Some(result) = authorized_x25519_method(&self.id, &method)? {
                    methods.push(result);
                }
                continue;
            };

            if let Some(result) = authorized_x25519_method(&self.id, method)? {
                methods.push(result);
            }
        }

        Ok(methods)
    }

    /// Find the first X25519 method explicitly authorized by `keyAgreement`.
    pub fn x25519_key_agreement_method(&self) -> Result<Option<(String, [u8; 32])>, String> {
        Ok(self.x25519_key_agreement_methods()?.into_iter().next())
    }

    /// Find the first authorized X25519 key agreement key (raw public key bytes).
    pub fn x25519_key_agreement(&self) -> Result<Option<Vec<u8>>, String> {
        Ok(self
            .x25519_key_agreement_method()?
            .map(|(_, key)| key.to_vec()))
    }

    /// Get the key ID for the first authorized X25519 key agreement key.
    pub fn x25519_key_id(&self) -> Result<Option<String>, String> {
        Ok(self.x25519_key_agreement_method()?.map(|(id, _)| id))
    }
}

/// Verification method in a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    #[serde(default)]
    pub public_key_jwk: Option<Jwk>,
    #[serde(default)]
    pub public_key_multibase: Option<String>,
    #[serde(default)]
    pub public_key_base58: Option<String>,
    #[serde(
        default,
        flatten,
        deserialize_with = "deserialize_verification_method_extensions"
    )]
    pub(crate) additional_properties: serde_json::Map<String, serde_json::Value>,
}

impl VerificationMethod {
    /// Construct a typed verification method with no unchecked extensions.
    pub fn new(
        id: impl Into<String>,
        method_type: impl Into<String>,
        controller: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            r#type: method_type.into(),
            controller: controller.into(),
            public_key_jwk: None,
            public_key_multibase: None,
            public_key_base58: None,
            additional_properties: serde_json::Map::new(),
        }
    }

    /// Return extension members without permitting unchecked external mutation.
    pub fn additional_properties(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.additional_properties
    }

    /// Add extensions after rejecting collisions with modeled verification members.
    pub fn with_additional_properties(
        mut self,
        additional_properties: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Self, String> {
        reject_modeled_collisions(
            &additional_properties,
            &MODELED_VERIFICATION_METHOD_MEMBERS,
            "verification method",
        )?;
        validate_private_key_extensions(&additional_properties, "DID verification methods")?;
        self.additional_properties = additional_properties;
        Ok(self)
    }
}

/// Public JSON Web Key (subset needed for DIDComm key agreement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    pub kid: Option<String>,
    #[serde(
        default,
        flatten,
        deserialize_with = "deserialize_public_jwk_extensions"
    )]
    additional_properties: serde_json::Map<String, serde_json::Value>,
}

impl Jwk {
    /// Construct a public JWK with no extension members.
    pub fn new_public(
        kty: impl Into<String>,
        crv: Option<String>,
        x: Option<String>,
        y: Option<String>,
        kid: Option<String>,
    ) -> Self {
        Self {
            kty: kty.into(),
            crv,
            x,
            y,
            kid,
            additional_properties: serde_json::Map::new(),
        }
    }

    /// Add public extension members after rejecting every registered private member.
    pub fn with_additional_properties(
        mut self,
        additional_properties: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Self, String> {
        if let Some(member) = PRIVATE_JWK_MEMBERS
            .iter()
            .find(|member| additional_properties.contains_key(**member))
        {
            return Err(format!(
                "DID verification methods must not contain private JWK member '{member}'"
            ));
        }
        if let Some(member) = MODELED_JWK_MEMBERS
            .iter()
            .find(|member| additional_properties.contains_key(**member))
        {
            return Err(format!(
                "DID JWK extension collides with modeled member '{member}'"
            ));
        }
        self.additional_properties = additional_properties;
        Ok(self)
    }

    /// Return validated public extension members without permitting mutation.
    pub fn additional_properties(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.additional_properties
    }
}

#[cfg(test)]
mod extension_collision_tests {
    use super::*;

    #[test]
    fn outer_did_types_reject_key_bearing_modeled_collisions() {
        let method: VerificationMethod = serde_json::from_value(serde_json::json!({
            "id":"did:example:1#key",
            "type":"JsonWebKey2020",
            "controller":"did:example:1"
        }))
        .unwrap();
        for member in ["publicKeyJwk", "publicKeyMultibase", "publicKeyBase58"] {
            let mut extensions = serde_json::Map::new();
            extensions.insert(member.into(), serde_json::json!({"d":"secret"}));
            assert!(method
                .clone()
                .with_additional_properties(extensions)
                .is_err());
        }

        let document: DidDocument = serde_json::from_value(serde_json::json!({
            "id":"did:example:1"
        }))
        .unwrap();
        for member in [
            "verificationMethod",
            "keyAgreement",
            "authentication",
            "assertionMethod",
        ] {
            let mut extensions = serde_json::Map::new();
            extensions.insert(member.into(), serde_json::json!({"d":"secret"}));
            assert!(document
                .clone()
                .with_additional_properties(extensions)
                .is_err());
        }
    }
}

#[cfg(test)]
mod key_agreement_boundary_tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    fn method(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "type": "JsonWebKey2020",
            "controller": "did:example:alice",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "X25519",
                "x": URL_SAFE_NO_PAD.encode([7_u8; 32])
            }
        })
    }

    fn document(
        methods: Vec<serde_json::Value>,
        agreements: Vec<serde_json::Value>,
    ) -> DidDocument {
        serde_json::from_value(serde_json::json!({
            "id": "did:example:alice",
            "verificationMethod": methods,
            "keyAgreement": agreements
        }))
        .unwrap()
    }

    #[test]
    fn selection_rejects_duplicate_registry_and_inline_ids() {
        let duplicate = document(
            vec![method("#key-1"), method("did:example:alice#key-1")],
            vec![serde_json::json!("#key-1")],
        );
        assert!(duplicate.x25519_key_agreement_methods().is_err());

        let inline_conflict = document(
            vec![method("#key-1")],
            vec![method("did:example:alice#key-1")],
        );
        assert!(inline_conflict.x25519_key_agreement_methods().is_err());
    }

    #[test]
    fn selection_requires_exactly_one_well_shaped_public_material() {
        let mut ambiguous = method("#key-1");
        ambiguous["publicKeyBase58"] = serde_json::json!(bs58::encode([8_u8; 32]).into_string());
        assert!(document(vec![ambiguous], vec![serde_json::json!("#key-1")])
            .x25519_key_agreement_methods()
            .is_err());

        let mut malformed = method("#key-1");
        malformed["publicKeyJwk"]["y"] = serde_json::json!(URL_SAFE_NO_PAD.encode([9_u8; 32]));
        assert!(document(vec![malformed], vec![serde_json::json!("#key-1")])
            .x25519_key_agreement_methods()
            .is_err());

        let valid = document(vec![method("#key-1")], vec![serde_json::json!("#key-1")]);
        let selected = valid.x25519_key_agreement_methods().unwrap();
        assert_eq!(
            selected,
            vec![("did:example:alice#key-1".into(), [7_u8; 32])]
        );
    }
}

/// DID Document service entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEntry {
    pub id: String,
    pub r#type: String,
    pub service_endpoint: ServiceEndpoint,
    #[serde(default, flatten)]
    pub additional_properties: serde_json::Map<String, serde_json::Value>,
}

/// Service endpoint — can be a plain URI string or a structured object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceEndpoint {
    Uri(String),
    Object(ServiceEndpointObject),
}

impl ServiceEndpoint {
    pub fn uri(&self) -> &str {
        match self {
            ServiceEndpoint::Uri(s) => s.as_str(),
            ServiceEndpoint::Object(o) => o.uri.as_str(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEndpointObject {
    pub uri: String,
    #[serde(default)]
    pub accept: Vec<String>,
    #[serde(default)]
    pub routing_keys: Vec<String>,
    #[serde(default, flatten)]
    pub additional_properties: serde_json::Map<String, serde_json::Value>,
}

/// A DIDComm v2 plaintext message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidcommMessage {
    pub id: String,
    pub r#type: String,
    pub from: Option<String>,
    pub to: Option<Vec<String>>,
    #[serde(default)]
    pub created_time: Option<u64>,
    #[serde(default)]
    pub expires_time: Option<u64>,
    #[serde(default)]
    pub body: serde_json::Value,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    #[serde(default)]
    pub thid: Option<String>,
    #[serde(default)]
    pub pthid: Option<String>,
}

/// DIDComm attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    pub data: AttachmentData,
}

/// Attachment data — base64 or inline JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentData {
    #[serde(default)]
    pub base64: Option<String>,
    #[serde(default)]
    pub json: Option<serde_json::Value>,
    #[serde(default)]
    pub links: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn base64_url_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64url decode error: {e}"))
}

fn canonical_method_id(document_id: &str, method_id: &str) -> Option<String> {
    if document_id.is_empty() || method_id.is_empty() {
        return None;
    }
    if method_id.starts_with('#') {
        return Some(format!("{document_id}{method_id}"));
    }
    if method_id
        .strip_prefix(document_id)
        .is_some_and(|suffix| suffix.starts_with('#') && suffix.len() > 1)
    {
        return Some(method_id.to_string());
    }
    None
}

fn authorized_x25519_method(
    document_id: &str,
    method: &VerificationMethod,
) -> Result<Option<(String, [u8; 32])>, String> {
    let method_id = canonical_method_id(document_id, &method.id)
        .ok_or_else(|| format!("invalid verification method id '{}'", method.id))?;
    if method.controller != document_id
        || !matches!(
            method.r#type.as_str(),
            "JsonWebKey2020" | "X25519KeyAgreementKey2019" | "X25519KeyAgreementKey2020"
        )
    {
        return Ok(None);
    }

    let material_count = usize::from(method.public_key_jwk.is_some())
        + usize::from(method.public_key_multibase.is_some())
        + usize::from(method.public_key_base58.is_some());
    if material_count != 1 {
        return Err(format!(
            "X25519 verification method '{method_id}' must contain exactly one public key material"
        ));
    }

    let bytes = if let Some(jwk) = &method.public_key_jwk {
        if jwk.kty != "OKP"
            || jwk.crv.as_deref() != Some("X25519")
            || jwk.y.is_some()
            || jwk.x.as_deref().is_none_or(str::is_empty)
        {
            return Err(format!(
                "X25519 verification method '{method_id}' has an invalid public JWK"
            ));
        }
        base64_url_decode(jwk.x.as_deref().expect("validated"))?
    } else if let Some(multibase) = &method.public_key_multibase {
        decode_multibase_x25519(multibase).ok_or_else(|| {
            format!("X25519 verification method '{method_id}' has invalid multibase material")
        })?
    } else if let Some(base58) = &method.public_key_base58 {
        bs58::decode(base58).into_vec().map_err(|error| {
            format!("X25519 verification method '{method_id}' has invalid base58: {error}")
        })?
    } else {
        unreachable!("exactly one material was checked")
    };
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        format!("X25519 verification method '{method_id}' must contain exactly 32 key bytes")
    })?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(format!(
            "X25519 verification method '{method_id}' contains an invalid all-zero key"
        ));
    }
    Ok(Some((method_id, key)))
}

fn decode_multibase_x25519(mb: &str) -> Option<Vec<u8>> {
    // Multibase z-prefix = base58btc
    if !mb.starts_with('z') {
        return None;
    }
    let decoded = bs58::decode(&mb[1..]).into_vec().ok()?;
    // Multicodec prefix for X25519: 0xEC01
    if decoded.len() == 34 && decoded[0] == 0xEC && decoded[1] == 0x01 {
        Some(decoded[2..].to_vec())
    } else {
        None
    }
}
