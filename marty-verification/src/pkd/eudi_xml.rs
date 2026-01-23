//! ETSI TS 119 612 XML data structures for EU Trusted Lists (LoTL/TL).
//!
//! This module provides namespace-aware parsing for the European Union's
//! List of Trusted Lists (LoTL) and member state Trusted Lists (TL).
//!
//! Key namespaces:
//! - `http://uri.etsi.org/02231/v2#` (tsl): Trust Service Status List
//! - `http://www.w3.org/2000/09/xmldsig#` (ds): XML Digital Signature

use serde::Deserialize;

/// XML namespace constants
pub const TSL_NS: &str = "http://uri.etsi.org/02231/v2#";
pub const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Root element of a Trust Service Status List (LoTL or member state TL).
#[derive(Debug, Deserialize)]
#[serde(rename = "TrustServiceStatusList")]
pub struct TrustServiceStatusList {
    #[serde(rename = "SchemeInformation")]
    pub scheme_information: SchemeInformation,
    
    /// Present in LoTL only - points to member state TLs
    #[serde(rename = "PointersToOtherTSL", default)]
    pub pointers: Option<PointersToOtherTSL>,
    
    /// Present in member state TLs - contains trust service providers
    #[serde(rename = "TrustServiceProviderList", default)]
    pub tsp_list: Option<TrustServiceProviderList>,
}

/// Scheme information - metadata about the list
#[derive(Debug, Deserialize)]
pub struct SchemeInformation {
    #[serde(rename = "TSLSequenceNumber")]
    pub sequence_number: u64,
    
    #[serde(rename = "SchemeTerritory")]
    pub territory: String,
    
    #[serde(rename = "ListIssueDateTime")]
    pub issue_date: String,
    
    #[serde(rename = "NextUpdate", default)]
    pub next_update: Option<NextUpdate>,
    
    #[serde(rename = "TSLType")]
    pub tsl_type: String,
}

#[derive(Debug, Deserialize)]
pub struct NextUpdate {
    #[serde(rename = "dateTime")]
    pub date_time: Option<String>,
}

/// Pointers to other TSLs (present in LoTL)
#[derive(Debug, Deserialize)]
pub struct PointersToOtherTSL {
    #[serde(rename = "OtherTSLPointer")]
    pub pointers: Vec<OtherTSLPointer>,
}

/// Pointer to a member state's TL
#[derive(Debug, Deserialize)]
pub struct OtherTSLPointer {
    #[serde(rename = "ServiceDigitalIdentities", default)]
    pub identities: Option<ServiceDigitalIdentities>,
    
    #[serde(rename = "TSLLocation")]
    pub location: String,
    
    #[serde(rename = "AdditionalInformation", default)]
    pub additional_info: Option<AdditionalInformation>,
}

/// Digital identities (certificates) for a service
#[derive(Debug, Deserialize)]
pub struct ServiceDigitalIdentities {
    #[serde(rename = "ServiceDigitalIdentity")]
    pub identities: Vec<ServiceDigitalIdentity>,
}

#[derive(Debug, Deserialize)]
pub struct ServiceDigitalIdentity {
    #[serde(rename = "DigitalId")]
    pub digital_id: Vec<DigitalId>,
}

/// Digital identifier containing an X.509 certificate or key info
#[derive(Debug, Deserialize)]
pub struct DigitalId {
    /// Base64-encoded X.509 certificate
    #[serde(rename = "X509Certificate", default)]
    pub x509_certificate: Option<String>,
    
    /// Subject name (alternative to certificate)
    #[serde(rename = "X509SubjectName", default)]
    pub x509_subject_name: Option<String>,
}

/// Additional information about a TL pointer
#[derive(Debug, Deserialize)]
pub struct AdditionalInformation {
    #[serde(rename = "TextualInformation", default)]
    pub textual_info: Option<TextualInformation>,
    
    #[serde(rename = "OtherInformation", default)]
    pub other_info: Vec<OtherInformation>,
}

#[derive(Debug, Deserialize)]
pub struct TextualInformation {
    #[serde(rename = "$value")]
    pub text: Vec<String>,
}

/// Other information field - can contain various data
#[derive(Debug, Deserialize)]
pub struct OtherInformation {
    #[serde(rename = "SchemeTerritory", default)]
    pub territory: Option<String>,
    
    #[serde(rename = "SchemeOperatorName", default)]
    pub operator_name: Option<SchemeOperatorName>,
    
    #[serde(rename = "MimeType", default)]
    pub mime_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SchemeOperatorName {
    #[serde(rename = "Name")]
    pub names: Vec<LocalizedName>,
}

/// Localized text with language tag
#[derive(Debug, Deserialize, Clone)]
pub struct LocalizedName {
    #[serde(rename = "$value")]
    pub text: String,
    
    #[serde(rename = "lang", default)]
    pub lang: Option<String>,
}

/// List of trust service providers (in member state TL)
#[derive(Debug, Deserialize)]
pub struct TrustServiceProviderList {
    #[serde(rename = "TrustServiceProvider")]
    pub providers: Vec<XmlTrustServiceProvider>,
}

/// A trust service provider with its services
#[derive(Debug, Deserialize)]
pub struct XmlTrustServiceProvider {
    #[serde(rename = "TSPInformation")]
    pub info: TspInformation,
    
    #[serde(rename = "TSPServices")]
    pub services: TspServices,
}

/// TSP information (name, address, etc.)
#[derive(Debug, Deserialize)]
pub struct TspInformation {
    #[serde(rename = "TSPName")]
    pub name: MultiLangString,
    
    #[serde(rename = "TSPTradeName", default)]
    pub trade_name: Option<MultiLangString>,
}

/// Multi-language string
#[derive(Debug, Deserialize)]
pub struct MultiLangString {
    #[serde(rename = "Name")]
    pub names: Vec<LocalizedName>,
}

/// Services provided by a TSP
#[derive(Debug, Deserialize)]
pub struct TspServices {
    #[serde(rename = "TSPService")]
    pub services: Vec<XmlTspService>,
}

/// A single trust service
#[derive(Debug, Deserialize)]
pub struct XmlTspService {
    #[serde(rename = "ServiceInformation")]
    pub info: ServiceInformation,
}

/// Service information including type, name, status, and certificates
#[derive(Debug, Deserialize)]
pub struct ServiceInformation {
    #[serde(rename = "ServiceTypeIdentifier")]
    pub service_type: String,
    
    #[serde(rename = "ServiceName")]
    pub name: MultiLangString,
    
    #[serde(rename = "ServiceStatus")]
    pub status: String,
    
    #[serde(rename = "StatusStartingTime")]
    pub status_starting_time: String,
    
    #[serde(rename = "ServiceDigitalIdentity")]
    pub digital_identity: ServiceDigitalIdentity,
}

impl LocalizedName {
    /// Get the text content, preferring English if available
    pub fn get_best_text(names: &[LocalizedName]) -> String {
        names
            .iter()
            .find(|n| n.lang.as_deref() == Some("en"))
            .or_else(|| names.first())
            .map(|n| n.text.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_localized_name_best_text() {
        let names = vec![
            LocalizedName {
                text: "Nom français".to_string(),
                lang: Some("fr".to_string()),
            },
            LocalizedName {
                text: "English name".to_string(),
                lang: Some("en".to_string()),
            },
        ];
        
        assert_eq!(LocalizedName::get_best_text(&names), "English name");
    }

    #[test]
    fn test_localized_name_fallback() {
        let names = vec![LocalizedName {
            text: "Deutscher Name".to_string(),
            lang: Some("de".to_string()),
        }];
        
        assert_eq!(LocalizedName::get_best_text(&names), "Deutscher Name");
    }
}
