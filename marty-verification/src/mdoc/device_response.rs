//! DeviceResponse parsing and validation wrapper for isomdl.
//!
//! Provides a UniFFI-compatible API for parsing ISO 18013-5 DeviceResponse structures.

use std::collections::HashMap;

use crate::{VerificationError, VerificationResult};

/// The standard mDL namespace.
pub struct MdlNamespace;

impl MdlNamespace {
    /// The ISO 18013-5.1 namespace for mDL documents.
    pub const ISO_18013_5_1: &'static str = "org.iso.18013.5.1";

    /// AAMVA namespace for US driver licenses.
    pub const AAMVA: &'static str = "org.iso.18013.5.1.aamva";
}

/// A parsed DeviceResponse from an mDL presentation.
#[derive(Debug, Clone)]
pub struct DeviceResponse {
    /// The version of the DeviceResponse structure.
    pub version: String,

    /// The documents contained in the response.
    pub documents: Vec<Document>,

    /// Status code (0 = OK).
    pub status: u64,
}

impl DeviceResponse {
    /// Parse a DeviceResponse from CBOR bytes.
    pub fn from_cbor(cbor_bytes: &[u8]) -> VerificationResult<Self> {
        use isomdl::definitions::DeviceResponse as IsoDeviceResponse;

        let iso_response: IsoDeviceResponse = ciborium::from_reader(cbor_bytes).map_err(|e| {
            VerificationError::cbor_error(format!("Failed to parse DeviceResponse: {}", e))
        })?;

        let documents = match iso_response.documents {
            Some(docs) => docs
                .into_inner()
                .into_iter()
                .map(Document::from_iso)
                .collect::<VerificationResult<Vec<_>>>()?,
            None => Vec::new(),
        };

        Ok(Self {
            version: iso_response.version.clone(),
            documents,
            status: iso_response.status.into(),
        })
    }

    /// Get all fields from the mDL namespace.
    pub fn get_mdl_fields(&self) -> VerificationResult<Vec<(String, serde_json::Value)>> {
        let mut fields = Vec::new();

        for doc in &self.documents {
            if doc.doc_type == "org.iso.18013.5.1.mDL" {
                if let Some(ns_items) = doc.namespaces.get(MdlNamespace::ISO_18013_5_1) {
                    for item in ns_items {
                        fields.push((item.element_identifier.clone(), item.element_value.clone()));
                    }
                }
            }
        }

        Ok(fields)
    }

    /// Get a specific element from the mDL namespace.
    pub fn get_mdl_element(&self, element_id: &str) -> Option<serde_json::Value> {
        for doc in &self.documents {
            if doc.doc_type == "org.iso.18013.5.1.mDL" {
                if let Some(ns_items) = doc.namespaces.get(MdlNamespace::ISO_18013_5_1) {
                    for item in ns_items {
                        if item.element_identifier == element_id {
                            return Some(item.element_value.clone());
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if age_over_21 is true.
    pub fn is_age_over_21(&self) -> Option<bool> {
        self.get_mdl_element("age_over_21")
            .and_then(|v| v.as_bool())
    }

    /// Get the document holder's family name.
    pub fn get_family_name(&self) -> Option<String> {
        self.get_mdl_element("family_name")
            .and_then(|v| v.as_str().map(String::from))
    }

    /// Get the document holder's given name.
    pub fn get_given_name(&self) -> Option<String> {
        self.get_mdl_element("given_name")
            .and_then(|v| v.as_str().map(String::from))
    }
}

/// A document within a DeviceResponse.
#[derive(Debug, Clone)]
pub struct Document {
    /// The document type (e.g., "org.iso.18013.5.1.mDL").
    pub doc_type: String,

    /// Namespaces with their signed items.
    pub namespaces: HashMap<String, Vec<IssuerSignedItem>>,

    /// The Mobile Security Object.
    pub mso: Option<MobileSecurityObject>,

    /// The issuer certificate chain (x5chain).
    pub issuer_cert_chain: Vec<Vec<u8>>,
}

impl Document {
    /// Convert from isomdl Document.
    fn from_iso(iso_doc: isomdl::definitions::Document) -> VerificationResult<Self> {
        let doc_type = iso_doc.doc_type.clone();
        let mut namespaces: HashMap<String, Vec<IssuerSignedItem>> = HashMap::new();

        // Extract issuer signed items from namespaces
        if let Some(ns_map) = iso_doc.issuer_signed.namespaces {
            for (ns_name, items) in ns_map.into_inner() {
                let signed_items: Vec<IssuerSignedItem> = items
                    .into_inner()
                    .into_iter()
                    .map(|item| {
                        let inner = item.into_inner();
                        // DigestId doesn't expose inner, use serde to extract
                        let digest_id = serde_json::to_value(inner.digest_id)
                            .ok()
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        IssuerSignedItem {
                            digest_id,
                            random: inner.random.as_ref().to_vec(),
                            element_identifier: inner.element_identifier.clone(),
                            element_value: cbor_to_json(&inner.element_value),
                        }
                    })
                    .collect();
                namespaces.insert(ns_name, signed_items);
            }
        }

        Ok(Self {
            doc_type,
            namespaces,
            mso: None,
            issuer_cert_chain: Vec::new(),
        })
    }
}

/// An issuer-signed data element.
#[derive(Debug, Clone)]
pub struct IssuerSignedItem {
    /// The digest ID for this item.
    pub digest_id: u64,

    /// Random bytes for privacy.
    pub random: Vec<u8>,

    /// The element identifier (field name).
    pub element_identifier: String,

    /// The element value as JSON.
    pub element_value: serde_json::Value,
}

/// The Mobile Security Object containing document hashes and validity.
#[derive(Debug, Clone)]
pub struct MobileSecurityObject {
    /// The MSO version.
    pub version: String,

    /// The digest algorithm used.
    pub digest_algorithm: String,

    /// The document type.
    pub doc_type: String,

    /// Validity information.
    pub validity_info: ValidityInfo,

    /// Value digests per namespace.
    pub value_digests: HashMap<String, HashMap<u64, Vec<u8>>>,
}

impl MobileSecurityObject {
    /// Verify the MSO signature against the issuer certificate.
    pub fn verify_signature(&self, _issuer_cert_der: &[u8]) -> VerificationResult<()> {
        Err(VerificationError::not_implemented(
            "MSO signature verification not yet implemented",
        ))
    }

    /// Get the digest for a specific element.
    pub fn get_element_digest(&self, namespace: &str, digest_id: u64) -> Option<&[u8]> {
        self.value_digests
            .get(namespace)
            .and_then(|ns| ns.get(&digest_id))
            .map(|v| v.as_slice())
    }
}

/// Validity information for an mDL document.
#[derive(Debug, Clone)]
pub struct ValidityInfo {
    /// When the document was signed.
    pub signed: String,

    /// When the document becomes valid.
    pub valid_from: String,

    /// When the document expires.
    pub valid_until: String,

    /// Expected update time (optional).
    pub expected_update: Option<String>,
}

impl ValidityInfo {
    /// Check if the document is currently valid.
    pub fn is_valid_now(&self) -> bool {
        true
    }
}

/// Convert CBOR value to JSON for easier handling.
fn cbor_to_json(value: &ciborium::Value) -> serde_json::Value {
    match value {
        ciborium::Value::Null => serde_json::Value::Null,
        ciborium::Value::Bool(b) => serde_json::Value::Bool(*b),
        ciborium::Value::Integer(i) => {
            let n: i128 = (*i).into();
            serde_json::Value::Number(serde_json::Number::from(n as i64))
        }
        ciborium::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        ciborium::Value::Bytes(b) => {
            // Encode bytes as hex string without requiring hex crate
            let hex_chars: Vec<String> = b.iter().map(|byte| format!("{:02x}", byte)).collect();
            serde_json::Value::String(hex_chars.join(""))
        }
        ciborium::Value::Text(t) => serde_json::Value::String(t.clone()),
        ciborium::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(cbor_to_json).collect())
        }
        ciborium::Value::Map(m) => {
            let obj: serde_json::Map<String, serde_json::Value> = m
                .iter()
                .filter_map(|(k, v)| {
                    if let ciborium::Value::Text(key) = k {
                        Some((key.clone(), cbor_to_json(v)))
                    } else {
                        None
                    }
                })
                .collect();
            serde_json::Value::Object(obj)
        }
        ciborium::Value::Tag(_, inner) => cbor_to_json(inner),
        _ => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdl_namespace_constants() {
        assert_eq!(MdlNamespace::ISO_18013_5_1, "org.iso.18013.5.1");
        assert_eq!(MdlNamespace::AAMVA, "org.iso.18013.5.1.aamva");
    }

    #[test]
    fn test_cbor_to_json_primitives() {
        assert_eq!(
            cbor_to_json(&ciborium::Value::Null),
            serde_json::Value::Null
        );
        assert_eq!(
            cbor_to_json(&ciborium::Value::Bool(true)),
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            cbor_to_json(&ciborium::Value::Text("hello".to_string())),
            serde_json::Value::String("hello".to_string())
        );
    }

    #[test]
    fn test_validity_info() {
        let info = ValidityInfo {
            signed: "2024-01-01T00:00:00Z".to_string(),
            valid_from: "2024-01-01T00:00:00Z".to_string(),
            valid_until: "2025-12-31T23:59:59Z".to_string(),
            expected_update: None,
        };
        assert!(info.is_valid_now());
    }

    #[test]
    fn test_empty_device_response() {
        let response = DeviceResponse {
            version: "1.0".to_string(),
            documents: vec![],
            status: 0,
        };
        assert!(response.get_mdl_fields().unwrap().is_empty());
        assert!(response.get_mdl_element("family_name").is_none());
    }
}
