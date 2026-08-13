//! Controlled DID resolution for did:key, did:web, did:peer, and did:jwk.
//!
//! Ledger-based methods (did:ion, did:ethr, did:sov) are NOT supported.
//! Network-backed methods use an explicitly configured managed resolver by
//! default. Direct did:web egress requires an exact deployment host allowlist.

use crate::error::{DidcommError, DidcommResult};
use crate::types::{DidDocument, Jwk, ServiceEntry, VerificationMethod};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "did_web")]
use std::collections::{HashMap, HashSet};

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};

const MAX_DID_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_DID_DOCUMENT_DEPTH: usize = 32;

/// A resolved DID document together with integrity and source provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidResolutionResult {
    pub document: DidDocument,
    pub source: String,
    pub retrieved_at: String,
    pub content_sha256: String,
}

/// DID Resolver supporting non-ledger DID methods.
pub struct DidResolver {
    /// Optional URL for a Universal Resolver (e.g. `https://resolver.example.com/1.0/identifiers/`).
    /// When set, network-backed and otherwise unsupported methods are resolved through it.
    universal_resolver_url: Option<String>,
    /// Deployment-owned HTTP(S) bases that serve `did:web` documents at the
    /// standard path without contacting the public DID host.
    #[cfg(feature = "did_web")]
    did_web_internal_base_urls: Vec<String>,
    /// Exact hosts that may be contacted directly for `did:web` resolution.
    /// Empty by default so resolving untrusted DIDs cannot create ambient egress.
    #[cfg(feature = "did_web")]
    did_web_allowed_hosts: HashSet<String>,
}

impl DidResolver {
    /// Create a resolver with no universal resolver fallback.
    pub fn new() -> Self {
        Self {
            universal_resolver_url: None,
            #[cfg(feature = "did_web")]
            did_web_internal_base_urls: Vec::new(),
            #[cfg(feature = "did_web")]
            did_web_allowed_hosts: HashSet::new(),
        }
    }

    /// Create a resolver with a Universal Resolver HTTP fallback for unknown methods.
    pub fn with_universal_resolver(url: impl Into<String>) -> Self {
        Self {
            universal_resolver_url: Some(url.into()),
            #[cfg(feature = "did_web")]
            did_web_internal_base_urls: Vec::new(),
            #[cfg(feature = "did_web")]
            did_web_allowed_hosts: HashSet::new(),
        }
    }

    /// Add deployment-owned bases that mirror standard `did:web` document
    /// paths. Bases are tried in order before any public or Universal Resolver
    /// route.
    #[cfg(feature = "did_web")]
    pub fn with_did_web_internal_base_urls<I, S>(mut self, urls: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.did_web_internal_base_urls.extend(
            urls.into_iter()
                .map(Into::into)
                .map(|url: String| url.trim_end_matches('/').to_string())
                .filter(|url| !url.is_empty()),
        );
        self
    }

    /// Permit direct `did:web` resolution for an exact set of deployment-owned hosts.
    ///
    /// Public network access is denied unless a host is explicitly listed. Prefer a
    /// deployment-managed Universal Resolver when arbitrary holder DIDs are accepted.
    #[cfg(feature = "did_web")]
    pub fn with_did_web_allowed_hosts<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::new().allow_did_web_hosts(hosts)
    }

    /// Add exact direct-resolution hosts to an existing resolver configuration.
    #[cfg(feature = "did_web")]
    pub fn allow_did_web_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.did_web_allowed_hosts.extend(
            hosts
                .into_iter()
                .map(Into::into)
                .map(|host: String| host.trim_end_matches('.').to_ascii_lowercase())
                .filter(|host| !host.is_empty()),
        );
        self
    }

    /// Resolve a DID to its DID Document.
    pub async fn resolve(&self, did: &str) -> DidcommResult<DidDocument> {
        self.resolve_with_source(did)
            .await
            .map(|(document, _)| document)
    }

    async fn resolve_with_source(&self, did: &str) -> DidcommResult<(DidDocument, &'static str)> {
        let method = extract_method(did)?;
        match method {
            "key" => resolve_did_key(did).map(|document| (document, "embedded:did:key")),
            "jwk" => resolve_did_jwk(did).map(|document| (document, "embedded:did:jwk")),
            "peer" => resolve_did_peer(did).map(|document| (document, "embedded:did:peer")),
            #[cfg(feature = "did_web")]
            "web" => {
                for base_url in &self.did_web_internal_base_urls {
                    let url = internal_did_web_url(base_url, did)?;
                    if let Ok(document) = fetch_did_document(url, did, false).await {
                        return Ok((document, "configured_internal_resolver"));
                    }
                }
                let host = did_web_host(did)?;
                if self.did_web_allowed_hosts.contains(&host) {
                    resolve_did_web(did, &self.did_web_allowed_hosts)
                        .await
                        .map(|document| (document, "allowlisted_public_did_web"))
                } else if let Some(ref base_url) = self.universal_resolver_url {
                    resolve_via_universal_resolver(base_url, did)
                        .await
                        .map(|document| (document, "configured_internal_resolver"))
                } else {
                    Err(DidcommError::ResolutionFailed {
                        did: did.to_string(),
                        reason: "configured internal DID resolution failed and direct did:web resolution is disabled; configure a managed resolver or an exact host allowlist".to_string(),
                    })
                }
            }
            _ => {
                // Try universal resolver fallback
                if let Some(ref base_url) = self.universal_resolver_url {
                    #[cfg(feature = "did_web")]
                    {
                        return resolve_via_universal_resolver(base_url, did)
                            .await
                            .map(|document| (document, "configured_internal_resolver"));
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

    /// Resolve a DID and return stable provenance generated by the native
    /// resolver. Callers do not need to recreate document hashing or infer
    /// which network policy path was used.
    pub async fn resolve_with_metadata(&self, did: &str) -> DidcommResult<DidResolutionResult> {
        let (document, source) = self.resolve_with_source(did).await?;
        let canonical = canonical_json_bytes(&serde_json::to_value(&document)?)?;
        let content_sha256 = format!("{:x}", Sha256::digest(&canonical));

        Ok(DidResolutionResult {
            document,
            source: source.to_string(),
            retrieved_at: chrono::Utc::now().to_rfc3339(),
            content_sha256,
        })
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

fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, serde_json::Error> {
    fn sorted(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(object) => {
                let mut entries = object.iter().collect::<Vec<_>>();
                entries.sort_unstable_by_key(|(key, _)| *key);
                serde_json::Value::Object(
                    entries
                        .into_iter()
                        .map(|(key, value)| (key.clone(), sorted(value)))
                        .collect(),
                )
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(sorted).collect())
            }
            _ => value.clone(),
        }
    }

    serde_json::to_vec(&sorted(value))
}

fn json_depth(value: &serde_json::Value, depth: usize) -> usize {
    if depth > MAX_DID_DOCUMENT_DEPTH {
        return depth;
    }
    match value {
        serde_json::Value::Object(object) => object
            .values()
            .map(|value| json_depth(value, depth + 1))
            .max()
            .unwrap_or(depth),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|value| json_depth(value, depth + 1))
            .max()
            .unwrap_or(depth),
        _ => depth,
    }
}

fn enforce_json_depth(value: &serde_json::Value, subject: &str) -> DidcommResult<()> {
    if json_depth(value, 0) > MAX_DID_DOCUMENT_DEPTH {
        return Err(DidcommError::InvalidDid(format!(
            "{subject} exceeds the JSON nesting limit"
        )));
    }
    Ok(())
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
                    additional_properties: serde_json::Map::new(),
                }),
                public_key_multibase: None,
                public_key_base58: None,
                additional_properties: serde_json::Map::new(),
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
                        additional_properties: serde_json::Map::new(),
                    }),
                    public_key_multibase: None,
                    public_key_base58: None,
                    additional_properties: serde_json::Map::new(),
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
                    additional_properties: serde_json::Map::new(),
                }),
                public_key_multibase: None,
                public_key_base58: None,
                additional_properties: serde_json::Map::new(),
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
                    additional_properties: serde_json::Map::new(),
                }),
                public_key_multibase: None,
                public_key_base58: None,
                additional_properties: serde_json::Map::new(),
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
        assertion_method: vec![serde_json::json!(format!("{did}#{multibase}"))],
        key_agreement: ka,
        verification_method: vms,
        service: vec![],
        additional_properties: serde_json::Map::new(),
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

    if URL_SAFE_NO_PAD.encode(&jwk_bytes) != encoded {
        return Err(DidcommError::InvalidDid(
            "did:jwk payload is not canonical base64url".to_string(),
        ));
    }
    let raw_jwk = parse_json_without_duplicate_members(&jwk_bytes)?;
    enforce_json_depth(&raw_jwk, "did:jwk payload")?;
    let jwk: Jwk = serde_json::from_value(raw_jwk)?;
    if !valid_public_jwk(&jwk) {
        return Err(DidcommError::InvalidDid(
            "did:jwk payload is not a supported public JWK".to_string(),
        ));
    }

    let vm_id = format!("{did}#0");
    let is_key_agreement = jwk.crv.as_deref() == Some("X25519");

    let vm = VerificationMethod {
        id: vm_id.clone(),
        r#type: "JsonWebKey2020".to_string(),
        controller: did.to_string(),
        public_key_jwk: Some(jwk),
        public_key_multibase: None,
        public_key_base58: None,
        additional_properties: serde_json::Map::new(),
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
        assertion_method: vec![serde_json::json!(vm_id)],
        key_agreement: ka,
        verification_method: vec![vm],
        service: vec![],
        additional_properties: serde_json::Map::new(),
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
        assertion_method: vec![],
        key_agreement: ka,
        verification_method: vms,
        service: services,
        additional_properties: serde_json::Map::new(),
    })
}

// ---------------------------------------------------------------------------
// did:web — HTTP resolution
// ---------------------------------------------------------------------------

#[cfg(feature = "did_web")]
fn did_web_host(did: &str) -> DidcommResult<String> {
    let stripped = did
        .strip_prefix("did:web:")
        .ok_or_else(|| DidcommError::InvalidDid(did.to_string()))?;
    let authority = decode_did_web_component(stripped.split(':').next().unwrap_or_default(), did)?;
    let authority_url = url::Url::parse(&format!("https://{authority}/")).map_err(|_| {
        DidcommError::InvalidDid(format!("did:web contains an invalid authority: {did}"))
    })?;
    if !authority_url.username().is_empty()
        || authority_url.password().is_some()
        || authority_url.port_or_known_default() != Some(443)
        || authority_url.path() != "/"
        || authority_url.query().is_some()
        || authority_url.fragment().is_some()
    {
        return Err(DidcommError::InvalidDid(format!(
            "did:web contains an unsafe authority: {did}"
        )));
    }
    authority_url
        .host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .ok_or_else(|| DidcommError::InvalidDid(format!("did:web has no host: {did}")))
}

#[cfg(feature = "did_web")]
fn did_web_path_parts(did: &str) -> DidcommResult<Vec<String>> {
    let stripped = did
        .strip_prefix("did:web:")
        .ok_or_else(|| DidcommError::InvalidDid(did.to_string()))?;
    let mut encoded_parts = stripped.split(':');
    let _authority = encoded_parts.next();
    let path_parts = encoded_parts
        .map(|part| decode_did_web_component(part, did))
        .collect::<DidcommResult<Vec<_>>>()?;
    if path_parts.iter().any(|part| {
        part.is_empty()
            || part == "."
            || part == ".."
            || part.contains('/')
            || part.contains('\\')
            || part.contains('?')
            || part.contains('#')
            || part.chars().any(char::is_control)
    }) {
        return Err(DidcommError::InvalidDid(format!(
            "did:web contains an unsafe path component: {did}"
        )));
    }
    Ok(path_parts)
}

#[cfg(feature = "did_web")]
async fn resolve_did_web(did: &str, allowed_hosts: &HashSet<String>) -> DidcommResult<DidDocument> {
    let stripped = did
        .strip_prefix("did:web:")
        .ok_or_else(|| DidcommError::InvalidDid(did.to_string()))?;

    // did:web:example.com → https://example.com/.well-known/did.json
    // did:web:example.com:path:to → https://example.com/path/to/did.json
    let authority = decode_did_web_component(stripped.split(':').next().unwrap_or_default(), did)?;
    let authority_url = url::Url::parse(&format!("https://{authority}/")).map_err(|_| {
        DidcommError::InvalidDid(format!("did:web contains an invalid authority: {did}"))
    })?;
    let host = did_web_host(did)?;

    if !authority_url.username().is_empty()
        || authority_url.password().is_some()
        || authority_url.port_or_known_default() != Some(443)
        || authority_url.path() != "/"
        || authority_url.query().is_some()
        || authority_url.fragment().is_some()
        || !allowed_hosts.contains(&host)
    {
        return Err(DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "did:web host is not in the exact deployment allowlist".to_string(),
        });
    }

    let path_parts = did_web_path_parts(did)?;

    let mut document_url = authority_url;
    if path_parts.is_empty() {
        document_url.set_path("/.well-known/did.json");
    } else {
        let mut segments = document_url.path_segments_mut().map_err(|_| {
            DidcommError::InvalidDid(format!("did:web cannot be represented as a URL: {did}"))
        })?;
        segments.clear();
        for part in path_parts {
            segments.push(&part);
        }
        segments.push("did.json");
    }

    fetch_did_document(document_url, did, true).await
}

#[cfg(feature = "did_web")]
fn internal_did_web_url(base_url: &str, did: &str) -> DidcommResult<url::Url> {
    did_web_host(did)?;
    let path_parts = did_web_path_parts(did)?;
    let mut url = url::Url::parse(base_url).map_err(|_| DidcommError::ResolutionFailed {
        did: did.to_string(),
        reason: "managed did:web base URL is invalid".to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "managed did:web base must be an HTTP(S) URL without credentials, query, or fragment".to_string(),
        });
    }
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "managed did:web base cannot accept a document path".to_string(),
        })?;
    segments.pop_if_empty();
    if path_parts.is_empty() {
        segments.push(".well-known");
    } else {
        for part in path_parts {
            segments.push(&part);
        }
    }
    segments.push("did.json");
    drop(segments);
    Ok(url)
}

#[cfg(feature = "did_web")]
async fn resolve_via_universal_resolver(base_url: &str, did: &str) -> DidcommResult<DidDocument> {
    let mut url = url::Url::parse(base_url).map_err(|_| DidcommError::ResolutionFailed {
        did: did.to_string(),
        reason: "managed resolver URL is invalid".to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "managed resolver URL must be an HTTP(S) base URL without credentials, query, or fragment".to_string(),
        });
    }
    url.path_segments_mut()
        .map_err(|_| DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "managed resolver URL cannot accept a DID path".to_string(),
        })?
        .pop_if_empty()
        .push(did);
    fetch_did_document(url, did, false).await
}

#[cfg(feature = "did_web")]
fn decode_did_web_component(component: &str, did: &str) -> DidcommResult<String> {
    urlencoding::decode(component)
        .map(|value| value.into_owned())
        .map_err(|_| DidcommError::InvalidDid(format!("did:web has invalid encoding: {did}")))
}

#[cfg(feature = "did_web")]
async fn fetch_did_document(
    url: url::Url,
    did: &str,
    require_public_destination: bool,
) -> DidcommResult<DidDocument> {
    let host = url
        .host_str()
        .ok_or_else(|| DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "resolution URL has no host".to_string(),
        })?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "resolution URL has no usable port".to_string(),
        })?;

    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none());

    if require_public_destination {
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| DidcommError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("did:web host could not be resolved: {e}"),
            })?
            .collect::<Vec<_>>();
        if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
            return Err(DidcommError::ResolutionFailed {
                did: did.to_string(),
                reason: "did:web host does not resolve exclusively to public addresses".to_string(),
            });
        }
        // Environment proxies resolve the destination independently and would
        // bypass the address set validated and pinned above.
        builder = builder.no_proxy().resolve_to_addrs(host, &addresses);
    }

    let client = builder
        .build()
        .map_err(|e| DidcommError::Http(e.to_string()))?;

    let mut response = client
        .get(url.clone())
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

    let media_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !matches!(
        media_type,
        Some(
            "application/did+json"
                | "application/did+ld+json"
                | "application/ld+json"
                | "application/json"
        )
    ) {
        return Err(DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "resolver returned an unsupported media type".to_string(),
        });
    }

    if response
        .content_length()
        .is_some_and(|length| length > MAX_DID_DOCUMENT_BYTES as u64)
    {
        return Err(DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "resolver response exceeds the 1 MiB limit".to_string(),
        });
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: format!("failed to read resolver response: {e}"),
        })?
    {
        if body.len().saturating_add(chunk.len()) > MAX_DID_DOCUMENT_BYTES {
            return Err(DidcommError::ResolutionFailed {
                did: did.to_string(),
                reason: "resolver response exceeds the 1 MiB limit".to_string(),
            });
        }
        body.extend_from_slice(&chunk);
    }

    // Universal Resolver wraps in { didDocument: {...} }, did:web returns raw
    let parsed = parse_json_without_duplicate_members(&body)?;
    enforce_json_depth(&parsed, "DID document")?;
    let document = if let Some(inner) = parsed.get("didDocument") {
        serde_json::from_value(inner.clone())?
    } else {
        serde_json::from_value(parsed)?
    };
    validate_resolved_document(&document, did)?;
    Ok(document)
}

fn parse_json_without_duplicate_members(
    body: &[u8],
) -> Result<serde_json::Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = UniqueJsonValue.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

struct UniqueJsonValue;

impl<'de> DeserializeSeed<'de> for UniqueJsonValue {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonValueVisitor)
    }
}

struct UniqueJsonValueVisitor;

impl<'de> Visitor<'de> for UniqueJsonValueVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UniqueJsonValue.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(UniqueJsonValue)? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!(
                    "duplicate JSON object member: {key}"
                )));
            }
            values.insert(key, object.next_value_seed(UniqueJsonValue)?);
        }
        Ok(serde_json::Value::Object(values))
    }
}

#[cfg(feature = "did_web")]
fn is_public_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            let octets = address.octets();
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
                || octets[0] == 0
                || octets[0] >= 240
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)))
        }
        std::net::IpAddr::V6(address) => {
            if let Some(embedded) = address.to_ipv4() {
                return is_public_ip(std::net::IpAddr::V4(embedded));
            }
            let segments = address.segments();
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_multicast()
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] == 0x0064
                    && segments[1] == 0xff9b
                    && (segments[2] == 0 || segments[2] == 1))
                || segments[0] == 0x2002
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

#[cfg(feature = "did_web")]
fn validate_resolved_document(document: &DidDocument, did: &str) -> DidcommResult<()> {
    if document.id != did {
        return Err(DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "resolved DID document id does not match the requested DID".to_string(),
        });
    }

    if document.verification_method.is_empty() {
        return Err(DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "DID document has no verification methods".to_string(),
        });
    }

    let mut methods = HashMap::new();
    for method in &document.verification_method {
        let Some(method_id) = absolute_method_id(did, &method.id) else {
            return Err(DidcommError::ResolutionFailed {
                did: did.to_string(),
                reason: "DID document contains a foreign verification method".to_string(),
            });
        };
        if !valid_verification_method(method, did)
            || methods
                .insert(method_id, serde_json::to_value(method)?)
                .is_some()
        {
            return Err(DidcommError::ResolutionFailed {
                did: did.to_string(),
                reason:
                    "DID document contains a duplicate, foreign, or invalid verification method"
                        .to_string(),
            });
        }
    }

    if document.authentication.is_empty() && document.assertion_method.is_empty() {
        return Err(DidcommError::ResolutionFailed {
            did: did.to_string(),
            reason: "DID document has no authentication or assertion relationship".to_string(),
        });
    }

    for relationship in document
        .authentication
        .iter()
        .chain(document.assertion_method.iter())
        .chain(document.key_agreement.iter())
    {
        if let Some(reference) = relationship.as_str() {
            if absolute_method_id(did, reference).is_none_or(|id| !methods.contains_key(&id)) {
                return Err(DidcommError::ResolutionFailed {
                    did: did.to_string(),
                    reason: "DID document references an unknown verification method".to_string(),
                });
            }
        } else {
            let method: VerificationMethod =
                serde_json::from_value(relationship.clone()).map_err(|_| {
                    DidcommError::ResolutionFailed {
                        did: did.to_string(),
                        reason: "DID document contains an invalid inline verification method"
                            .to_string(),
                    }
                })?;
            if !valid_verification_method(&method, did) {
                return Err(DidcommError::ResolutionFailed {
                    did: did.to_string(),
                    reason: "DID document contains a foreign inline verification method"
                        .to_string(),
                });
            }
            let serialized = serde_json::to_value(&method)?;
            let Some(method_id) = absolute_method_id(did, &method.id) else {
                return Err(DidcommError::ResolutionFailed {
                    did: did.to_string(),
                    reason: "DID document contains a foreign inline verification method"
                        .to_string(),
                });
            };
            if methods
                .get(&method_id)
                .is_some_and(|existing| existing != &serialized)
            {
                return Err(DidcommError::ResolutionFailed {
                    did: did.to_string(),
                    reason:
                        "DID document contains conflicting verification methods with the same id"
                            .to_string(),
                });
            }
            methods.entry(method_id).or_insert(serialized);
        }
    }

    let mut service_ids = HashSet::new();
    for service in &document.service {
        let service_id = absolute_method_id(did, &service.id);
        if service_id
            .as_ref()
            .is_none_or(|service_id| !service_ids.insert(service_id.clone()))
        {
            return Err(DidcommError::ResolutionFailed {
                did: did.to_string(),
                reason: "DID document contains a duplicate, foreign, or invalid service"
                    .to_string(),
            });
        }
    }

    Ok(())
}

#[cfg(feature = "did_web")]
fn absolute_method_id(did: &str, value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else if value.starts_with('#') {
        Some(format!("{did}{value}"))
    } else if value == did || value.starts_with(&format!("{did}#")) {
        Some(value.to_string())
    } else {
        None
    }
}

#[cfg(feature = "did_web")]
fn valid_verification_method(method: &VerificationMethod, did: &str) -> bool {
    let key_material_count = usize::from(method.public_key_jwk.is_some())
        + usize::from(method.public_key_multibase.is_some())
        + usize::from(method.public_key_base58.is_some());
    let public_jwk = method.public_key_jwk.as_ref().is_none_or(valid_public_jwk);

    !method.id.is_empty()
        && method.controller == did
        && absolute_method_id(did, &method.id).is_some()
        && !method.r#type.is_empty()
        && key_material_count == 1
        && public_jwk
}

fn valid_public_jwk(jwk: &Jwk) -> bool {
    const PRIVATE_MEMBERS: [&str; 7] = ["p", "q", "dp", "dq", "qi", "oth", "k"];
    if jwk.d.is_some()
        || PRIVATE_MEMBERS
            .iter()
            .any(|member| jwk.additional_properties.contains_key(*member))
    {
        return false;
    }

    let present = |value: Option<&str>| value.is_some_and(|value| !value.is_empty());
    match jwk.kty.as_str() {
        "OKP" => present(jwk.crv.as_deref()) && present(jwk.x.as_deref()),
        "EC" => {
            present(jwk.crv.as_deref()) && present(jwk.x.as_deref()) && present(jwk.y.as_deref())
        }
        "RSA" => {
            present(
                jwk.additional_properties
                    .get("n")
                    .and_then(serde_json::Value::as_str),
            ) && present(
                jwk.additional_properties
                    .get("e")
                    .and_then(serde_json::Value::as_str),
            )
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "did_web")]
    fn empty_document(did: &str) -> DidDocument {
        DidDocument {
            id: did.to_string(),
            context: serde_json::json!(["https://www.w3.org/ns/did/v1"]),
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            verification_method: vec![],
            service: vec![],
            additional_properties: serde_json::Map::new(),
        }
    }

    #[cfg(feature = "did_web")]
    fn x25519_method(did: &str, fragment: &str) -> VerificationMethod {
        VerificationMethod {
            id: format!("{did}#{fragment}"),
            r#type: "JsonWebKey2020".to_string(),
            controller: did.to_string(),
            public_key_jwk: Some(Jwk {
                kty: "OKP".to_string(),
                crv: Some("X25519".to_string()),
                x: Some("avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs".to_string()),
                y: None,
                d: None,
                kid: None,
                additional_properties: serde_json::Map::new(),
            }),
            public_key_multibase: None,
            public_key_base58: None,
            additional_properties: serde_json::Map::new(),
        }
    }

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
    fn did_jwk_rejects_private_duplicate_and_incomplete_keys() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        for raw in [
            r#"{"kty":"OKP","crv":"Ed25519","x":"public","d":"private"}"#,
            r#"{"kty":"OKP","kty":"EC","crv":"Ed25519","x":"public"}"#,
            r#"{"kty":"EC","crv":"P-256","x":"public"}"#,
            r#"{"kty":"oct","k":"secret"}"#,
        ] {
            let did = format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(raw));
            assert!(resolve_did_jwk(&did).is_err(), "accepted {raw}");
        }
    }

    #[test]
    fn did_jwk_preserves_supported_rsa_members() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let raw = r#"{"kty":"RSA","n":"modulus","e":"AQAB","use":"sig"}"#;
        let did = format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(raw));
        let document = resolve_did_jwk(&did).unwrap();
        let jwk = document.verification_method[0]
            .public_key_jwk
            .as_ref()
            .unwrap();

        assert_eq!(jwk.additional_properties["n"], "modulus");
        assert_eq!(jwk.additional_properties["e"], "AQAB");
        assert_eq!(jwk.additional_properties["use"], "sig");
        assert_eq!(document.assertion_method, document.authentication);
    }

    #[tokio::test]
    async fn resolution_metadata_is_native_and_stable() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let raw = r#"{"kty":"OKP","crv":"Ed25519","x":"public"}"#;
        let did = format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(raw));
        let first = DidResolver::new()
            .resolve_with_metadata(&did)
            .await
            .unwrap();
        let second = DidResolver::new()
            .resolve_with_metadata(&did)
            .await
            .unwrap();

        assert_eq!(first.source, "embedded:did:jwk");
        assert_eq!(first.content_sha256, second.content_sha256);
        assert_eq!(first.content_sha256.len(), 64);
        assert!(!first.retrieved_at.is_empty());
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

    #[cfg(feature = "did_web")]
    #[tokio::test]
    async fn direct_did_web_resolution_is_denied_by_default() {
        let error = DidResolver::new()
            .resolve("did:web:example.com")
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("direct did:web resolution is disabled"));
    }

    #[cfg(feature = "did_web")]
    #[tokio::test]
    async fn managed_resolver_configuration_is_validated_before_network_access() {
        let error = DidResolver::with_universal_resolver("file:///tmp/resolver")
            .resolve("did:web:example.com")
            .await
            .unwrap_err();

        assert!(error.to_string().contains("must be an HTTP(S) base URL"));
    }

    #[cfg(feature = "did_web")]
    #[tokio::test]
    async fn internal_did_web_base_preserves_path_and_reports_actual_source() {
        use std::io::{Read, Write};

        let did = "did:web:issuer.example:orgs:tenant-a";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let document = serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": "#key-1",
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "public"}
            }],
            "assertionMethod": ["#key-1"]
        })
        .to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            assert!(request.starts_with("GET /base/orgs/tenant-a/did.json "));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/did+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                document.len(),
                document
            )
            .unwrap();
        });

        let result = DidResolver::new()
            .with_did_web_internal_base_urls([format!("http://{address}/base")])
            .resolve_with_metadata(did)
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(result.source, "configured_internal_resolver");
        assert_eq!(result.document.verification_method[0].id, "#key-1");
        assert_eq!(result.document.assertion_method[0], "#key-1");
    }

    #[cfg(feature = "did_web")]
    #[tokio::test]
    async fn did_web_rejects_unsafe_path_before_network_access() {
        let resolver = DidResolver::with_did_web_allowed_hosts(["example.com"]);
        let error = resolver
            .resolve("did:web:example.com:%2e%2e:admin")
            .await
            .unwrap_err();

        assert!(error.to_string().contains("unsafe path component"));
    }

    #[cfg(feature = "did_web")]
    #[tokio::test]
    async fn did_web_rejects_encoded_authority_components_before_network_access() {
        let resolver = DidResolver::with_did_web_allowed_hosts(["example.com"]);
        for did in [
            "did:web:example.com%2Fadmin",
            "did:web:example.com%3Ftarget=internal",
            "did:web:example.com%23fragment",
        ] {
            let error = resolver.resolve(did).await.unwrap_err();
            assert!(error.to_string().contains("unsafe authority"), "{error}");
        }
    }

    #[cfg(feature = "did_web")]
    #[test]
    fn resolved_document_must_match_requested_did() {
        let document = empty_document("did:web:other.example");
        let error = validate_resolved_document(&document, "did:web:example.com").unwrap_err();

        assert!(error.to_string().contains("does not match"));
    }

    #[cfg(feature = "did_web")]
    #[test]
    fn resolved_document_rejects_duplicate_verification_methods() {
        let did = "did:web:example.com";
        let method = x25519_method(did, "key-1");
        let mut document = empty_document(did);
        document.verification_method = vec![method.clone(), method];

        let error = validate_resolved_document(&document, did).unwrap_err();
        assert!(error.to_string().contains("duplicate, foreign, or invalid"));
    }

    #[cfg(feature = "did_web")]
    #[test]
    fn resolved_document_rejects_conflicting_inline_verification_methods() {
        let did = "did:web:example.com";
        let method = x25519_method(did, "key-1");
        let mut conflicting = method.clone();
        conflicting.public_key_jwk.as_mut().unwrap().x =
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
        let mut document = empty_document(did);
        document.verification_method = vec![method.clone()];
        document.authentication = vec![serde_json::json!(method.id)];
        document.key_agreement = vec![serde_json::to_value(conflicting).unwrap()];

        let error = validate_resolved_document(&document, did).unwrap_err();
        assert!(error
            .to_string()
            .contains("conflicting verification methods"));
    }

    #[cfg(feature = "did_web")]
    #[test]
    fn resolved_document_requires_verification_methods_and_relationships() {
        let did = "did:web:example.com";
        let mut document = empty_document(did);
        let error = validate_resolved_document(&document, did).unwrap_err();
        assert!(error.to_string().contains("no verification methods"));

        document.verification_method = vec![x25519_method(did, "key-1")];
        let error = validate_resolved_document(&document, did).unwrap_err();
        assert!(error
            .to_string()
            .contains("no authentication or assertion relationship"));
    }

    #[test]
    fn resolver_json_rejects_excessive_nesting() {
        let mut value = serde_json::Value::Null;
        for _ in 0..=MAX_DID_DOCUMENT_DEPTH {
            value = serde_json::json!({"nested": value});
        }
        assert!(enforce_json_depth(&value, "DID document").is_err());
    }

    #[cfg(feature = "did_web")]
    #[test]
    fn resolved_document_rejects_private_or_ambiguous_key_material() {
        let did = "did:web:example.com";
        let mut private = x25519_method(did, "private");
        private.public_key_jwk.as_mut().unwrap().d = Some("secret".to_string());
        let mut ambiguous = x25519_method(did, "ambiguous");
        ambiguous.public_key_multibase = Some("z6LSdummy".to_string());

        for method in [private, ambiguous] {
            let mut document = empty_document(did);
            document.verification_method = vec![method];
            let error = validate_resolved_document(&document, did).unwrap_err();
            assert!(error.to_string().contains("duplicate, foreign, or invalid"));
        }
    }

    #[cfg(feature = "did_web")]
    #[test]
    fn resolver_json_rejects_duplicate_members() {
        let error = parse_json_without_duplicate_members(
            br#"{"id":"did:web:example.com","id":"did:web:attacker.example"}"#,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("duplicate JSON object member: id"));
    }

    #[cfg(feature = "did_web")]
    #[test]
    fn public_destination_policy_rejects_non_public_ranges() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "2002:7f00:1::1",
            "fec0::1",
        ] {
            assert!(
                !is_public_ip(address.parse().unwrap()),
                "accepted {address}"
            );
        }
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}
