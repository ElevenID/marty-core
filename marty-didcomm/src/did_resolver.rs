//! DID resolution for did:key, did:web, did:peer, and did:jwk.
//!
//! Ledger-based methods (did:ion, did:ethr, did:sov) are NOT supported.
//! For those, proxy through the DIF Universal Resolver and configure the
//! result URL as an environment variable.

use crate::error::{DidcommError, DidcommResult};
use crate::types::{DidDocument, Jwk, ServiceEntry, VerificationMethod};

/// DID Resolver supporting non-ledger DID methods.
pub struct DidResolver {
    /// Optional URL for a Universal Resolver (e.g. `https://resolver.example.com/1.0/identifiers/`).
    /// When set, methods not natively supported will be resolved via HTTP GET.
    universal_resolver_url: Option<String>,
}

impl DidResolver {
    /// Create a resolver with no universal resolver fallback.
    pub fn new() -> Self {
        Self {
            universal_resolver_url: None,
        }
    }

    /// Create a resolver with a Universal Resolver HTTP fallback for unknown methods.
    pub fn with_universal_resolver(url: impl Into<String>) -> Self {
        Self {
            universal_resolver_url: Some(url.into()),
        }
    }

    /// Resolve a DID to its DID Document.
    pub async fn resolve(&self, did: &str) -> DidcommResult<DidDocument> {
        let method = extract_method(did)?;
        match method {
            "key" => resolve_did_key(did),
            "jwk" => resolve_did_jwk(did),
            "peer" => resolve_did_peer(did),
            #[cfg(feature = "did_web")]
            "web" => resolve_did_web(did).await,
            _ => {
                // Try universal resolver fallback
                if let Some(ref base_url) = self.universal_resolver_url {
                    #[cfg(feature = "did_web")]
                    {
                        return resolve_via_universal_resolver(base_url, did).await;
                    }
                    #[cfg(not(feature = "did_web"))]
                    {
                        let _ = base_url;
                        return Err(DidcommError::UnsupportedMethod {
                            method: method.to_string(),
                        });
                    }
                }
                Err(DidcommError::UnsupportedMethod {
                    method: method.to_string(),
                })
            }
        }
    }
}

impl Default for DidResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_method(did: &str) -> DidcommResult<&str> {
    if !did.starts_with("did:") {
        return Err(DidcommError::InvalidDid(did.to_string()));
    }
    let parts: Vec<&str> = did.splitn(3, ':').collect();
    if parts.len() < 3 {
        return Err(DidcommError::InvalidDid(did.to_string()));
    }
    Ok(parts[1])
}

// ---------------------------------------------------------------------------
// did:key — Ed25519 / X25519 from multicodec-prefixed base58btc
// ---------------------------------------------------------------------------

fn resolve_did_key(did: &str) -> DidcommResult<DidDocument> {
    // did:key:z<base58btc multicodec+pubkey>
    let multibase = did
        .strip_prefix("did:key:")
        .ok_or_else(|| DidcommError::InvalidDid(did.to_string()))?;

    if !multibase.starts_with('z') {
        return Err(DidcommError::InvalidDid(format!(
            "did:key must use z (base58btc) prefix: {did}"
        )));
    }

    let decoded =
        bs58::decode(&multibase[1..])
            .into_vec()
            .map_err(|e| DidcommError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("base58btc decode: {e}"),
            })?;

    if decoded.len() < 2 {
        return Err(DidcommError::InvalidDid(did.to_string()));
    }

    let (key_type, pub_key) = match (decoded[0], decoded[1]) {
        // Ed25519 public key: multicodec 0xED01
        (0xED, 0x01) if decoded.len() == 34 => ("Ed25519", &decoded[2..]),
        // X25519 public key: multicodec 0xEC01
        (0xEC, 0x01) if decoded.len() == 34 => ("X25519", &decoded[2..]),
        // P-256 compressed public key: multicodec 0x8024 (varint: 0x80 0x24)
        (0x80, 0x24) if decoded.len() == 35 => ("P-256", &decoded[2..]),
        _ => {
            return Err(DidcommError::ResolutionFailed {
                did: did.to_string(),
                reason: format!(
                    "unsupported multicodec prefix: 0x{:02X}{:02X}",
                    decoded[0], decoded[1]
                ),
            });
        }
    };

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let x_b64 = URL_SAFE_NO_PAD.encode(pub_key);

    // Build verification methods
    let mut vms = Vec::new();
    let mut ka = Vec::new();

    match key_type {
        "Ed25519" => {
            // Ed25519 signing key
            vms.push(VerificationMethod {
                id: format!("{did}#{multibase}"),
                r#type: "JsonWebKey2020".to_string(),
                controller: did.to_string(),
                public_key_jwk: Some(Jwk {
                    kty: "OKP".to_string(),
                    crv: Some("Ed25519".to_string()),
                    x: Some(x_b64.clone()),
                    y: None,
                    d: None,
                    kid: Some(format!("{did}#{multibase}")),
                }),
                public_key_multibase: None,
                public_key_base58: None,
            });
            // Derive X25519 key agreement key from Ed25519
            if let Some(x25519_pub) = ed25519_to_x25519(pub_key) {
                let x25519_b64 = URL_SAFE_NO_PAD.encode(&x25519_pub);
                let x25519_multibase = format!("z{}", bs58_encode_x25519(&x25519_pub));
                let ka_id = format!("{did}#{x25519_multibase}");
                let ka_vm = VerificationMethod {
                    id: ka_id.clone(),
                    r#type: "X25519KeyAgreementKey2020".to_string(),
                    controller: did.to_string(),
                    public_key_jwk: Some(Jwk {
                        kty: "OKP".to_string(),
                        crv: Some("X25519".to_string()),
                        x: Some(x25519_b64),
                        y: None,
                        d: None,
                        kid: Some(ka_id.clone()),
                    }),
                    public_key_multibase: None,
                    public_key_base58: None,
                };
                vms.push(ka_vm);
                ka.push(serde_json::json!(ka_id));
            }
        }
        "X25519" => {
            let ka_id = format!("{did}#{multibase}");
            let vm = VerificationMethod {
                id: ka_id.clone(),
                r#type: "X25519KeyAgreementKey2020".to_string(),
                controller: did.to_string(),
                public_key_jwk: Some(Jwk {
                    kty: "OKP".to_string(),
                    crv: Some("X25519".to_string()),
                    x: Some(x_b64),
                    y: None,
                    d: None,
                    kid: Some(ka_id.clone()),
                }),
                public_key_multibase: None,
                public_key_base58: None,
            };
            vms.push(vm);
            ka.push(serde_json::json!(ka_id));
        }
        "P-256" => {
            // For compressed P-256 keys in did:key — provide the JWK
            vms.push(VerificationMethod {
                id: format!("{did}#{multibase}"),
                r#type: "JsonWebKey2020".to_string(),
                controller: did.to_string(),
                public_key_jwk: Some(Jwk {
                    kty: "EC".to_string(),
                    crv: Some("P-256".to_string()),
                    x: Some(x_b64),
                    y: None,
                    d: None,
                    kid: Some(format!("{did}#{multibase}")),
                }),
                public_key_multibase: None,
                public_key_base58: None,
            });
        }
        _ => {}
    }

    Ok(DidDocument {
        id: did.to_string(),
        context: serde_json::json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ]),
        authentication: vec![serde_json::json!(format!("{did}#{multibase}"))],
        key_agreement: ka,
        verification_method: vms,
        service: vec![],
    })
}

/// Convert Ed25519 public key bytes to X25519 public key bytes.
fn ed25519_to_x25519(ed_pub: &[u8]) -> Option<Vec<u8>> {
    use ed25519_dalek::VerifyingKey;
    let vk = VerifyingKey::from_bytes(ed_pub.try_into().ok()?).ok()?;
    let montgomery = vk.to_montgomery();
    Some(montgomery.as_bytes().to_vec())
}

fn bs58_encode_x25519(pub_key: &[u8]) -> String {
    let mut prefixed = vec![0xEC, 0x01];
    prefixed.extend_from_slice(pub_key);
    bs58::encode(prefixed).into_string()
}

// ---------------------------------------------------------------------------
// did:jwk — JWK encoded directly in the DID
// ---------------------------------------------------------------------------

fn resolve_did_jwk(did: &str) -> DidcommResult<DidDocument> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let encoded = did
        .strip_prefix("did:jwk:")
        .ok_or_else(|| DidcommError::InvalidDid(did.to_string()))?;

    let jwk_bytes =
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| DidcommError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("base64url decode: {e}"),
            })?;

    let jwk: Jwk = serde_json::from_slice(&jwk_bytes)?;

    let vm_id = format!("{did}#0");
    let is_key_agreement = jwk.crv.as_deref() == Some("X25519");

    let vm = VerificationMethod {
        id: vm_id.clone(),
        r#type: "JsonWebKey2020".to_string(),
        controller: did.to_string(),
        public_key_jwk: Some(jwk),
        public_key_multibase: None,
        public_key_base58: None,
    };

    let ka = if is_key_agreement {
        vec![serde_json::json!(vm_id)]
    } else {
        vec![]
    };

    Ok(DidDocument {
        id: did.to_string(),
        context: serde_json::json!(["https://www.w3.org/ns/did/v1"]),
        authentication: vec![serde_json::json!(vm_id)],
        key_agreement: ka,
        verification_method: vec![vm],
        service: vec![],
    })
}

// ---------------------------------------------------------------------------
// did:peer — method 0 (inline key) and method 2 (multi-purpose)
// ---------------------------------------------------------------------------

fn resolve_did_peer(did: &str) -> DidcommResult<DidDocument> {
    let peer_id = did
        .strip_prefix("did:peer:")
        .ok_or_else(|| DidcommError::InvalidDid(did.to_string()))?;

    match peer_id.chars().next() {
        Some('0') => resolve_did_peer_0(did, &peer_id[1..]),
        Some('2') => resolve_did_peer_2(did, &peer_id[1..]),
        _ => Err(DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "only did:peer method 0 and 2 are supported".to_string(),
        }),
    }
}

fn resolve_did_peer_0(did: &str, multibase: &str) -> DidcommResult<DidDocument> {
    // did:peer:0z<multibase key> — single inline key, treated as did:key
    let key_did = format!("did:key:z{multibase}");
    let mut doc = resolve_did_key(&key_did)?;
    doc.id = did.to_string();
    // Rewrite verification method controllers
    for vm in &mut doc.verification_method {
        vm.controller = did.to_string();
    }
    Ok(doc)
}

fn resolve_did_peer_2(did: &str, elements: &str) -> DidcommResult<DidDocument> {
    // did:peer:2.<purpose><z-multibase>.<purpose><z-multibase>...
    // Purpose: V = verification, E = key agreement, S = service
    let mut vms = Vec::new();
    let mut ka = Vec::new();
    let mut auth = Vec::new();
    let mut services = Vec::new();

    for segment in elements.split('.') {
        if segment.is_empty() {
            continue;
        }
        let purpose = &segment[..1];
        let data = &segment[1..];

        match purpose {
            "V" => {
                // Verification key
                if data.starts_with('z') {
                    let temp_did = format!("did:key:{data}");
                    if let Ok(temp_doc) = resolve_did_key(&temp_did) {
                        for vm in temp_doc.verification_method {
                            let vm_id =
                                format!("{}#{}", did, &data[..std::cmp::min(data.len(), 16)]);
                            auth.push(serde_json::json!(vm_id.clone()));
                            vms.push(VerificationMethod {
                                id: vm_id,
                                controller: did.to_string(),
                                ..vm
                            });
                        }
                    }
                }
            }
            "E" => {
                // Key agreement key
                if data.starts_with('z') {
                    let temp_did = format!("did:key:{data}");
                    if let Ok(temp_doc) = resolve_did_key(&temp_did) {
                        for vm in temp_doc.verification_method {
                            let vm_id =
                                format!("{}#{}", did, &data[..std::cmp::min(data.len(), 16)]);
                            ka.push(serde_json::json!(vm_id.clone()));
                            vms.push(VerificationMethod {
                                id: vm_id,
                                controller: did.to_string(),
                                ..vm
                            });
                        }
                    }
                }
            }
            "S" => {
                // Service endpoint — base64url-encoded JSON
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use base64::Engine;
                if let Ok(decoded) = URL_SAFE_NO_PAD.decode(data) {
                    if let Ok(svc) = serde_json::from_slice::<ServiceEntry>(&decoded) {
                        services.push(svc);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(DidDocument {
        id: did.to_string(),
        context: serde_json::json!(["https://www.w3.org/ns/did/v1"]),
        authentication: auth,
        key_agreement: ka,
        verification_method: vms,
        service: services,
    })
}

// ---------------------------------------------------------------------------
// did:web — HTTP resolution
// ---------------------------------------------------------------------------

#[cfg(feature = "did_web")]
async fn resolve_did_web(did: &str) -> DidcommResult<DidDocument> {
    let stripped = did
        .strip_prefix("did:web:")
        .ok_or_else(|| DidcommError::InvalidDid(did.to_string()))?;

    // did:web:example.com → https://example.com/.well-known/did.json
    // did:web:example.com:path:to → https://example.com/path/to/did.json
    let decoded = urlencoding::decode(stripped).unwrap_or(stripped.into());
    let parts: Vec<&str> = decoded.split(':').collect();

    let url = if parts.len() == 1 {
        format!("https://{}/.well-known/did.json", parts[0])
    } else {
        let host = parts[0];
        let path = parts[1..].join("/");
        format!("https://{host}/{path}/did.json")
    };

    fetch_did_document(&url, did).await
}

#[cfg(feature = "did_web")]
async fn resolve_via_universal_resolver(base_url: &str, did: &str) -> DidcommResult<DidDocument> {
    let url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        urlencoding::encode(did)
    );
    fetch_did_document(&url, did).await
}

#[cfg(feature = "did_web")]
async fn fetch_did_document(url: &str, did: &str) -> DidcommResult<DidDocument> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| DidcommError::Http(e.to_string()))?;

    let response = client
        .get(url)
        .header("Accept", "application/did+json, application/json")
        .send()
        .await
        .map_err(|e| DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: format!("HTTP request to {url} failed: {e}"),
        })?;

    if !response.status().is_success() {
        return Err(DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: format!("HTTP {} from {url}", response.status()),
        });
    }

    let body = response
        .text()
        .await
        .map_err(|e| DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: format!("failed to read response body: {e}"),
        })?;

    // Universal Resolver wraps in { didDocument: {...} }, did:web returns raw
    let parsed: serde_json::Value = serde_json::from_str(&body)?;
    if let Some(inner) = parsed.get("didDocument") {
        Ok(serde_json::from_value(inner.clone())?)
    } else {
        Ok(serde_json::from_str(&body)?)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_did_key_ed25519() {
        // Well-known did:key for Alice from DIDComm spec
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let doc = resolve_did_key(did).unwrap();
        assert_eq!(doc.id, did);
        assert!(!doc.verification_method.is_empty());
        // Should have derived X25519 key agreement
        assert!(doc.x25519_key_agreement().is_some());
    }

    #[test]
    fn test_resolve_did_jwk() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
        });
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_string(&jwk).unwrap().as_bytes());
        let did = format!("did:jwk:{encoded}");
        let doc = resolve_did_jwk(&did).unwrap();
        assert_eq!(doc.id, did);
        assert!(!doc.key_agreement.is_empty());
    }

    #[test]
    fn test_unsupported_method() {
        let resolver = DidResolver::new();
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(resolver.resolve("did:ethr:0x1234"));
        assert!(result.is_err());
        if let Err(DidcommError::UnsupportedMethod { method }) = result {
            assert_eq!(method, "ethr");
        }
    }

    #[test]
    fn test_extract_method() {
        assert_eq!(extract_method("did:key:z123").unwrap(), "key");
        assert_eq!(extract_method("did:web:example.com").unwrap(), "web");
        assert!(extract_method("not-a-did").is_err());
    }
}
