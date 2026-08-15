use serde::{Deserialize, Serialize};

/// W3C DID Document (simplified for DIDComm v2 use cases).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    #[serde(default)]
    pub id: String,

    #[serde(default, rename = "@context")]
    pub context: serde_json::Value,

    #[serde(default)]
    pub authentication: Vec<serde_json::Value>,

    #[serde(default)]
    pub assertion_method: Vec<serde_json::Value>,

    #[serde(default)]
    pub key_agreement: Vec<serde_json::Value>,

    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,

    #[serde(default)]
    pub service: Vec<ServiceEntry>,

    #[serde(default, flatten)]
    pub additional_properties: serde_json::Map<String, serde_json::Value>,
}

impl DidDocument {
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
    pub fn x25519_key_agreement_methods(&self) -> Vec<(String, [u8; 32])> {
        let mut methods = Vec::new();
        for relationship in &self.key_agreement {
            let method = if let Some(reference) = relationship.as_str() {
                let Some(reference) = canonical_method_id(&self.id, reference) else {
                    continue;
                };
                let Some(method) = self.verification_method.iter().find(|candidate| {
                    canonical_method_id(&self.id, &candidate.id).as_deref()
                        == Some(reference.as_str())
                }) else {
                    continue;
                };
                method
            } else {
                // Inline relationship entries are themselves verification
                // methods; malformed entries are not authorization grants.
                match serde_json::from_value::<VerificationMethod>(relationship.clone()) {
                    Ok(method) => {
                        if let Some(result) = authorized_x25519_method(&self.id, &method) {
                            if !methods.iter().any(|(id, _)| id == &result.0) {
                                methods.push(result);
                            }
                        }
                        continue;
                    }
                    Err(_) => continue,
                }
            };

            if let Some(result) = authorized_x25519_method(&self.id, method) {
                if !methods.iter().any(|(id, _)| id == &result.0) {
                    methods.push(result);
                }
            }
        }

        methods
    }

    /// Find the first X25519 method explicitly authorized by `keyAgreement`.
    pub fn x25519_key_agreement_method(&self) -> Option<(String, [u8; 32])> {
        self.x25519_key_agreement_methods().into_iter().next()
    }

    /// Find the first authorized X25519 key agreement key (raw public key bytes).
    pub fn x25519_key_agreement(&self) -> Option<Vec<u8>> {
        self.x25519_key_agreement_method()
            .map(|(_, key)| key.to_vec())
    }

    /// Get the key ID for the first authorized X25519 key agreement key.
    pub fn x25519_key_id(&self) -> Option<String> {
        self.x25519_key_agreement_method().map(|(id, _)| id)
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
    #[serde(default, flatten)]
    pub additional_properties: serde_json::Map<String, serde_json::Value>,
}

/// JSON Web Key (subset needed for DIDComm key agreement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    #[serde(default)]
    pub d: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default, flatten)]
    pub additional_properties: serde_json::Map<String, serde_json::Value>,
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
) -> Option<(String, [u8; 32])> {
    let method_id = canonical_method_id(document_id, &method.id)?;
    if method.controller != document_id
        || !matches!(
            method.r#type.as_str(),
            "JsonWebKey2020" | "X25519KeyAgreementKey2019" | "X25519KeyAgreementKey2020"
        )
    {
        return None;
    }

    let bytes = if let Some(jwk) = &method.public_key_jwk {
        if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("X25519") {
            return None;
        }
        base64_url_decode(jwk.x.as_deref()?).ok()?
    } else if let Some(multibase) = &method.public_key_multibase {
        decode_multibase_x25519(multibase)?
    } else if let Some(base58) = &method.public_key_base58 {
        bs58::decode(base58).into_vec().ok()?
    } else {
        return None;
    };
    let key: [u8; 32] = bytes.try_into().ok()?;
    Some((method_id, key))
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
