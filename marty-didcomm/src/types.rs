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
    pub key_agreement: Vec<serde_json::Value>,

    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,

    #[serde(default)]
    pub service: Vec<ServiceEntry>,
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

    /// Find the first X25519 key agreement key (raw public key bytes).
    pub fn x25519_key_agreement(&self) -> Option<Vec<u8>> {
        for vm in &self.verification_method {
            if vm.r#type == "X25519KeyAgreementKey2020"
                || vm.r#type == "JsonWebKey2020"
                || vm.r#type == "X25519KeyAgreementKey2019"
            {
                if let Some(ref jwk) = vm.public_key_jwk {
                    if jwk.crv.as_deref() == Some("X25519") {
                        if let Some(ref x) = jwk.x {
                            return base64_url_decode(x).ok();
                        }
                    }
                }
                if let Some(ref mb) = vm.public_key_multibase {
                    return decode_multibase_x25519(mb);
                }
            }
        }

        // Also check inline keyAgreement entries
        for ka in &self.key_agreement {
            if let Ok(vm) = serde_json::from_value::<VerificationMethod>(ka.clone()) {
                if let Some(ref jwk) = vm.public_key_jwk {
                    if jwk.crv.as_deref() == Some("X25519") {
                        if let Some(ref x) = jwk.x {
                            return base64_url_decode(x).ok();
                        }
                    }
                }
            }
        }

        None
    }

    /// Get the key ID for the first X25519 key agreement key.
    pub fn x25519_key_id(&self) -> Option<String> {
        for vm in &self.verification_method {
            if vm.r#type == "X25519KeyAgreementKey2020"
                || vm.r#type == "JsonWebKey2020"
                || vm.r#type == "X25519KeyAgreementKey2019"
            {
                if let Some(ref jwk) = vm.public_key_jwk {
                    if jwk.crv.as_deref() == Some("X25519") {
                        return Some(vm.id.clone());
                    }
                }
                if vm.public_key_multibase.is_some() {
                    return Some(vm.id.clone());
                }
            }
        }
        // Check inline keyAgreement
        for ka in &self.key_agreement {
            if let Some(s) = ka.as_str() {
                return Some(s.to_string());
            }
            if let Ok(vm) = serde_json::from_value::<VerificationMethod>(ka.clone()) {
                if let Some(ref jwk) = vm.public_key_jwk {
                    if jwk.crv.as_deref() == Some("X25519") {
                        return Some(vm.id.clone());
                    }
                }
            }
        }
        None
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
}

/// DID Document service entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEntry {
    pub id: String,
    pub r#type: String,
    pub service_endpoint: ServiceEndpoint,
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

fn decode_multibase_x25519(mb: &str) -> Option<Vec<u8>> {
    // Multibase z-prefix = base58btc
    if !mb.starts_with('z') {
        return None;
    }
    let decoded = bs58::decode(&mb[1..]).into_vec().ok()?;
    // Multicodec prefix for X25519: 0xEC01
    if decoded.len() >= 34 && decoded[0] == 0xEC && decoded[1] == 0x01 {
        Some(decoded[2..].to_vec())
    } else {
        None
    }
}
