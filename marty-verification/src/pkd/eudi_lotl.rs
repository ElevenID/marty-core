//! EUDI LoTL (List of Trusted Lists) client.
//!
//! This module provides an async client for fetching trust anchors from
//! the EU List of Trusted Lists and member state Trusted Lists.
//!
//! Implements ETSI TS 119 612 XML parsing with namespace-aware deserialization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::error::{VerificationError, VerificationResult};
use crate::trust_anchor::eudi::{
    EuMemberState, EudiRegistry, TrustService, TrustServiceProvider, TspStatus,
};

#[cfg(feature = "eudi-client")]
use crate::pkd::eudi_xml::{LocalizedName, TrustServiceStatusList};

/// Default EU LoTL URL.
pub const DEFAULT_LOTL_URL: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

/// Maximum decoded size of a LoTL or member-state trusted-list XML response.
///
/// Trusted lists carry certificate chains and can be materially larger than
/// ordinary registry metadata, so this limit leaves headroom while preventing
/// an untrusted server from growing the response buffer without bound.
#[cfg(feature = "eudi-client")]
const MAX_TRUST_LIST_XML_BYTES: usize = 16 * 1024 * 1024;

#[cfg(feature = "eudi-client")]
const INITIAL_TRUST_LIST_XML_CAPACITY: usize = 64 * 1024;

/// EUDI LoTL client for fetching trust lists.
pub struct EudiLotlClient {
    /// LoTL root URL.
    lotl_url: String,
    /// Optional filter for specific member states.
    member_state_filter: Option<Vec<EuMemberState>>,
    /// HTTP client for async requests.
    #[cfg(feature = "eudi-client")]
    http_client: reqwest::Client,
}

/// Trusted List metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedListInfo {
    /// Member state territory (e.g., "DE", "FR").
    pub scheme_territory: String,
    /// Trust list URL.
    pub url: String,
    /// List issue date.
    pub list_issue_date: DateTime<Utc>,
    /// Next update date.
    pub next_update: DateTime<Utc>,
}

/// Result of a sync operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LotlSyncResult {
    /// Number of trust anchors added.
    pub anchors_added: usize,
    /// Number of QTSPs discovered.
    pub qtsps_discovered: usize,
    /// Member states synced.
    pub member_states: Vec<String>,
    /// LoTL version/sequence number.
    pub version: String,
    /// Sync timestamp.
    pub synced_at: DateTime<Utc>,
}

#[cfg(feature = "eudi-client")]
async fn read_bounded_xml_response(
    response: reqwest::Response,
    endpoint: &str,
    list_name: &str,
    max_bytes: usize,
) -> VerificationResult<String> {
    use futures::StreamExt;

    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(VerificationError::pkd_fetch(
            endpoint,
            format!("{list_name} response exceeds the {max_bytes}-byte limit"),
        ));
    }

    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default()
        .min(max_bytes)
        .min(INITIAL_TRUST_LIST_XML_CAPACITY);
    let mut body = Vec::with_capacity(initial_capacity);
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|error| {
            VerificationError::pkd_fetch(
                endpoint,
                format!("Failed to read {list_name} response: {error}"),
            )
        })?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(VerificationError::pkd_fetch(
                endpoint,
                format!("{list_name} response exceeds the {max_bytes}-byte limit"),
            ));
        }
        body.extend_from_slice(&chunk);
    }

    // Preserve reqwest's no-charset `Response::text` behavior while keeping
    // ownership of the bounded byte buffer.
    Ok(String::from_utf8_lossy(&body).into_owned())
}

impl EudiLotlClient {
    /// Create a new client with the default LoTL URL.
    pub fn new() -> Self {
        Self {
            lotl_url: DEFAULT_LOTL_URL.to_string(),
            member_state_filter: None,
            #[cfg(feature = "eudi-client")]
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }

    /// Create a client with a custom LoTL URL.
    pub fn with_url(url: impl Into<String>) -> Self {
        Self {
            lotl_url: url.into(),
            member_state_filter: None,
            #[cfg(feature = "eudi-client")]
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }

    /// Filter to only fetch specific member states.
    pub fn with_member_states(mut self, states: Vec<EuMemberState>) -> Self {
        self.member_state_filter = Some(states);
        self
    }

    /// Fetch the LoTL and return member state trusted list info.
    #[cfg(feature = "eudi-client")]
    pub async fn fetch_lotl(&self) -> VerificationResult<Vec<TrustedListInfo>> {
        let response = self
            .http_client
            .get(&self.lotl_url)
            .send()
            .await
            .map_err(|e| {
                VerificationError::pkd_fetch(&self.lotl_url, format!("Failed to fetch LoTL: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(VerificationError::pkd_fetch(
                &self.lotl_url,
                format!("LoTL fetch failed: HTTP {}", response.status()),
            ));
        }

        let xml =
            read_bounded_xml_response(response, &self.lotl_url, "LoTL", MAX_TRUST_LIST_XML_BYTES)
                .await?;

        self.parse_lotl_xml(&xml)
    }

    /// Parse LoTL XML and extract member state TL pointers.
    #[cfg(feature = "eudi-client")]
    fn parse_lotl_xml(&self, xml: &str) -> VerificationResult<Vec<TrustedListInfo>> {
        use quick_xml::de::from_str;

        let tsl: TrustServiceStatusList = from_str(xml).map_err(|e| {
            *VerificationError::der_error(format!("Failed to parse LoTL XML: {}", e))
        })?;

        let mut results = Vec::new();

        if let Some(pointers) = tsl.pointers {
            for pointer in pointers.pointers {
                // Extract territory from AdditionalInformation
                let territory = pointer
                    .additional_info
                    .and_then(|ai| ai.other_info.iter().find_map(|oi| oi.territory.clone()))
                    .unwrap_or_default();

                // Apply member state filter if set
                if let Some(filter) = &self.member_state_filter {
                    if let Some(state) = EuMemberState::from_code(&territory) {
                        if !filter.contains(&state) {
                            continue;
                        }
                    } else {
                        continue; // Skip unknown territories
                    }
                }

                // Parse dates from scheme information
                let issue_date =
                    chrono::DateTime::parse_from_rfc3339(&tsl.scheme_information.issue_date)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(Utc::now);

                let next_update = tsl
                    .scheme_information
                    .next_update
                    .as_ref()
                    .and_then(|nu| nu.date_time.as_ref())
                    .and_then(|dt| chrono::DateTime::parse_from_rfc3339(dt).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|| Utc::now() + chrono::Duration::days(7));

                results.push(TrustedListInfo {
                    scheme_territory: territory,
                    url: pointer.location,
                    list_issue_date: issue_date,
                    next_update,
                });
            }
        }

        tracing::info!("Parsed LoTL: {} member state TLs found", results.len());
        Ok(results)
    }

    /// Fetch a member state's trusted list.
    #[cfg(feature = "eudi-client")]
    pub async fn fetch_member_state_tl(
        &self,
        member_state: EuMemberState,
    ) -> VerificationResult<Vec<TrustServiceProvider>> {
        // First get the TL URL from LoTL
        let tl_infos = self.fetch_lotl().await?;
        let tl_info = tl_infos
            .iter()
            .find(|ti| ti.scheme_territory == member_state.code())
            .ok_or_else(|| {
                *VerificationError::io_error(format!(
                    "No TL found for member state {}",
                    member_state.code()
                ))
            })?;

        // Fetch the member state TL
        let response = self
            .http_client
            .get(&tl_info.url)
            .send()
            .await
            .map_err(|e| {
                VerificationError::pkd_fetch(&tl_info.url, format!("Failed to fetch TL: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(VerificationError::pkd_fetch(
                &tl_info.url,
                format!("TL fetch failed: HTTP {}", response.status()),
            ));
        }

        let xml = read_bounded_xml_response(response, &tl_info.url, "TL", MAX_TRUST_LIST_XML_BYTES)
            .await?;

        self.parse_tl_xml(&xml, member_state)
    }

    /// Parse member state TL XML and extract trust service providers.
    #[cfg(feature = "eudi-client")]
    fn parse_tl_xml(
        &self,
        xml: &str,
        member_state: EuMemberState,
    ) -> VerificationResult<Vec<TrustServiceProvider>> {
        use quick_xml::de::from_str;

        let tsl: TrustServiceStatusList = from_str(xml)
            .map_err(|e| *VerificationError::der_error(format!("Failed to parse TL XML: {}", e)))?;

        let mut providers = Vec::new();

        if let Some(tsp_list) = tsl.tsp_list {
            for xml_tsp in tsp_list.providers {
                let name = LocalizedName::get_best_text(&xml_tsp.info.name.names);

                let mut trust_services = Vec::new();
                for xml_svc in xml_tsp.services.services {
                    // Extract service status implicitly from status URI
                    let _status = Self::parse_service_status(&xml_svc.info.status);

                    // Extract certificates from digital identity
                    let certificates: Vec<String> = xml_svc
                        .info
                        .digital_identity
                        .digital_id
                        .iter()
                        .filter_map(|di| di.x509_certificate.clone())
                        .collect();

                    let svc_name = LocalizedName::get_best_text(&xml_svc.info.name.names);

                    trust_services.push(TrustService {
                        name: svc_name,
                        service_type: xml_svc.info.service_type.clone(),
                        status: xml_svc.info.status.clone(),
                        certificates,
                    });
                }

                // Determine overall TSP status from services
                let tsp_status = if trust_services
                    .iter()
                    .any(|s| s.status.contains("granted") || s.status.contains("Granted"))
                {
                    TspStatus::Granted
                } else if trust_services
                    .iter()
                    .any(|s| s.status.contains("withdrawn") || s.status.contains("Withdrawn"))
                {
                    TspStatus::Withdrawn
                } else if trust_services
                    .iter()
                    .any(|s| s.status.contains("suspended") || s.status.contains("Suspended"))
                {
                    TspStatus::Suspended
                } else {
                    TspStatus::Unknown
                };

                providers.push(TrustServiceProvider {
                    id: format!("{}-{}", member_state.code(), providers.len()),
                    name,
                    member_state,
                    status: tsp_status,
                    trust_services,
                });
            }
        }

        tracing::info!(
            "Parsed TL for {}: {} TSPs with {} total services",
            member_state.code(),
            providers.len(),
            providers
                .iter()
                .map(|p| p.trust_services.len())
                .sum::<usize>()
        );

        Ok(providers)
    }

    /// Parse service status URI into TspStatus enum.
    #[cfg(feature = "eudi-client")]
    fn parse_service_status(status_uri: &str) -> TspStatus {
        if status_uri.contains("granted") || status_uri.contains("Granted") {
            TspStatus::Granted
        } else if status_uri.contains("withdrawn") || status_uri.contains("Withdrawn") {
            TspStatus::Withdrawn
        } else if status_uri.contains("suspended") || status_uri.contains("Suspended") {
            TspStatus::Suspended
        } else {
            TspStatus::Unknown
        }
    }

    /// Sync all trust anchors from LoTL into a registry.
    #[cfg(feature = "eudi-client")]
    pub async fn sync_registry(
        &self,
        registry: &mut EudiRegistry,
    ) -> VerificationResult<LotlSyncResult> {
        use base64::Engine;
        use der::Decode;
        use x509_cert::Certificate;

        let tl_infos = self.fetch_lotl().await?;
        let mut anchors_added = 0;
        let mut qtsps_discovered = 0;
        let mut member_states = Vec::new();

        for tl_info in &tl_infos {
            let Some(member_state) = EuMemberState::from_code(&tl_info.scheme_territory) else {
                tracing::warn!("Unknown member state: {}", tl_info.scheme_territory);
                continue;
            };

            match self.fetch_member_state_tl(member_state).await {
                Ok(providers) => {
                    for provider in providers {
                        qtsps_discovered += 1;

                        // Extract and add certificates as trust anchors
                        for service in &provider.trust_services {
                            for cert_b64 in &service.certificates {
                                // Decode base64 certificate
                                let cert_der = base64::engine::general_purpose::STANDARD
                                    .decode(cert_b64)
                                    .map_err(|e| {
                                        *VerificationError::der_error(format!(
                                            "Invalid base64 cert: {}",
                                            e
                                        ))
                                    })?;

                                match Certificate::from_der(&cert_der) {
                                    Ok(cert) => {
                                        // Determine trust purpose from service type
                                        let trust_purpose =
                                            if service.service_type.contains("QCertESig")
                                                || service.service_type.contains("QCertESeal")
                                                || service.service_type.contains("QWAC")
                                                || service.service_type.contains("PID")
                                            {
                                                crate::trust_anchor::TrustPurpose::EudiIssuer
                                            } else if service.service_type.contains("TSA")
                                                || service.service_type.contains("QTSP")
                                            {
                                                crate::trust_anchor::TrustPurpose::EudiQtsp
                                            } else if service.service_type.contains("Wallet") {
                                                crate::trust_anchor::TrustPurpose::EudiWallet
                                            } else {
                                                crate::trust_anchor::TrustPurpose::EudiIssuer
                                            };

                                        registry.add_member_state_anchor(
                                            member_state,
                                            cert,
                                            trust_purpose,
                                        );
                                        anchors_added += 1;
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to parse cert for {} / {}: {}",
                                            provider.name,
                                            service.name,
                                            e
                                        );
                                    }
                                }
                            }
                        }

                        // Add QTSP to registry cache
                        registry.add_qtsp(provider);
                    }
                    member_states.push(tl_info.scheme_territory.clone());
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch TL for {}: {}", tl_info.scheme_territory, e);
                }
            }
        }

        // Update registry version from LoTL sequence number
        let version = tl_infos
            .first()
            .map(|ti| format!("seq-{}", ti.list_issue_date.timestamp()))
            .unwrap_or_else(|| "unknown".to_string());
        registry.set_lotl_version(version.clone());

        tracing::info!(
            "EUDI LoTL sync complete: {} anchors from {} QTSPs across {} member states",
            anchors_added,
            qtsps_discovered,
            member_states.len()
        );

        Ok(LotlSyncResult {
            anchors_added,
            qtsps_discovered,
            member_states,
            version,
            synced_at: Utc::now(),
        })
    }

    /// Check if LoTL is available (connectivity test).
    #[cfg(feature = "eudi-client")]
    pub async fn is_available(&self) -> bool {
        match self.http_client.head(&self.lotl_url).send().await {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    /// Fetch a delta update since a specific version.
    #[cfg(feature = "eudi-client")]
    pub async fn fetch_delta(&self, _since_version: &str) -> VerificationResult<LotlSyncResult> {
        // TODO: Implement delta sync logic
        tracing::warn!("EUDI LoTL delta sync not yet implemented");
        self.sync_registry(&mut EudiRegistry::new()).await
    }
}

impl Default for EudiLotlClient {
    fn default() -> Self {
        Self::new()
    }
}

// Stub implementations for non-client builds
#[cfg(not(feature = "eudi-client"))]
impl EudiLotlClient {
    pub async fn fetch_lotl(&self) -> VerificationResult<Vec<TrustedListInfo>> {
        Err(VerificationError::NotSupported(
            "EUDI client feature not enabled".to_string(),
        ))
    }

    pub async fn fetch_member_state_tl(
        &self,
        _member_state: EuMemberState,
    ) -> VerificationResult<Vec<TrustServiceProvider>> {
        Err(VerificationError::NotSupported(
            "EUDI client feature not enabled".to_string(),
        ))
    }

    pub async fn sync_registry(
        &self,
        _registry: &mut EudiRegistry,
    ) -> VerificationResult<LotlSyncResult> {
        Err(VerificationError::NotSupported(
            "EUDI client feature not enabled".to_string(),
        ))
    }

    pub async fn is_available(&self) -> bool {
        false
    }

    pub async fn fetch_delta(&self, _since_version: &str) -> VerificationResult<LotlSyncResult> {
        Err(VerificationError::NotSupported(
            "EUDI client feature not enabled".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "eudi-client")]
    fn serve_raw_http_response(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(&response).unwrap();
        });

        (format!("http://{address}/trusted-list.xml"), server)
    }

    #[cfg(feature = "eudi-client")]
    async fn request_raw_http_response(
        response: Vec<u8>,
    ) -> (reqwest::Response, std::thread::JoinHandle<()>) {
        let (url, server) = serve_raw_http_response(response);
        let response = reqwest::Client::new().get(url).send().await.unwrap();
        (response, server)
    }

    const SAMPLE_LOTL_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <SchemeInformation>
        <TSLSequenceNumber>377</TSLSequenceNumber>
        <SchemeTerritory>EU</SchemeTerritory>
        <ListIssueDateTime>2024-01-15T10:00:00Z</ListIssueDateTime>
        <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType>
    </SchemeInformation>
    <PointersToOtherTSL>
        <OtherTSLPointer>
            <TSLLocation>https://example.de/tsl-de.xml</TSLLocation>
            <AdditionalInformation>
                <OtherInformation>
                    <SchemeTerritory>DE</SchemeTerritory>
                </OtherInformation>
            </AdditionalInformation>
        </OtherTSLPointer>
        <OtherTSLPointer>
            <TSLLocation>https://example.fr/tsl-fr.xml</TSLLocation>
            <AdditionalInformation>
                <OtherInformation>
                    <SchemeTerritory>FR</SchemeTerritory>
                </OtherInformation>
            </AdditionalInformation>
        </OtherTSLPointer>
    </PointersToOtherTSL>
</TrustServiceStatusList>"#;

    const SAMPLE_TL_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
    <SchemeInformation>
        <TSLSequenceNumber>42</TSLSequenceNumber>
        <SchemeTerritory>DE</SchemeTerritory>
        <ListIssueDateTime>2024-01-10T08:00:00Z</ListIssueDateTime>
        <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
    </SchemeInformation>
    <TrustServiceProviderList>
        <TrustServiceProvider>
            <TSPInformation>
                <TSPName>
                    <Name lang="en">Example QTSP DE</Name>
                    <Name lang="de">Beispiel QTSP DE</Name>
                </TSPName>
            </TSPInformation>
            <TSPServices>
                <TSPService>
                    <ServiceInformation>
                        <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                        <ServiceName>
                            <Name lang="en">Qualified Certificate Service</Name>
                        </ServiceName>
                        <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
                        <StatusStartingTime>2023-01-01T00:00:00Z</StatusStartingTime>
                        <ServiceDigitalIdentity>
                            <DigitalId>
                                <X509Certificate>MIICpzCCAY8CAQEwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIVGVzdCBDQSAwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjATMREwDwYDVQQDDAhUZXN0IENBIDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANrouw==</X509Certificate>
                            </DigitalId>
                        </ServiceDigitalIdentity>
                    </ServiceInformation>
                </TSPService>
            </TSPServices>
        </TrustServiceProvider>
    </TrustServiceProviderList>
</TrustServiceStatusList>"#;

    #[test]
    fn test_client_creation() {
        let client = EudiLotlClient::new();
        assert_eq!(client.lotl_url, DEFAULT_LOTL_URL);
    }

    #[test]
    fn test_client_with_custom_url() {
        let client = EudiLotlClient::with_url("https://custom.example.com/lotl.xml");
        assert_eq!(client.lotl_url, "https://custom.example.com/lotl.xml");
    }

    #[test]
    fn test_member_state_filter() {
        let client =
            EudiLotlClient::new().with_member_states(vec![EuMemberState::DE, EuMemberState::FR]);
        assert_eq!(client.member_state_filter.unwrap().len(), 2);
    }

    #[cfg(feature = "eudi-client")]
    #[test]
    fn test_parse_lotl_xml() {
        let client = EudiLotlClient::new();
        let result = client.parse_lotl_xml(SAMPLE_LOTL_XML);
        assert!(result.is_ok(), "Failed to parse LoTL: {:?}", result.err());

        let tl_infos = result.unwrap();
        assert_eq!(tl_infos.len(), 2);
        assert_eq!(tl_infos[0].scheme_territory, "DE");
        assert_eq!(tl_infos[1].scheme_territory, "FR");
        assert!(tl_infos[0].url.contains("tsl-de.xml"));
    }

    #[cfg(feature = "eudi-client")]
    #[test]
    fn test_parse_lotl_with_filter() {
        let client = EudiLotlClient::new().with_member_states(vec![EuMemberState::DE]);
        let result = client.parse_lotl_xml(SAMPLE_LOTL_XML);
        assert!(result.is_ok());

        let tl_infos = result.unwrap();
        assert_eq!(tl_infos.len(), 1); // Only DE, FR filtered out
        assert_eq!(tl_infos[0].scheme_territory, "DE");
    }

    #[cfg(feature = "eudi-client")]
    #[test]
    fn test_parse_tl_xml() {
        let client = EudiLotlClient::new();
        let result = client.parse_tl_xml(SAMPLE_TL_XML, EuMemberState::DE);
        assert!(result.is_ok(), "Failed to parse TL: {:?}", result.err());

        let providers = result.unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name, "Example QTSP DE");
        assert_eq!(providers[0].member_state, EuMemberState::DE);
        assert_eq!(providers[0].status, TspStatus::Granted);
        assert_eq!(providers[0].trust_services.len(), 1);
        assert_eq!(
            providers[0].trust_services[0].name,
            "Qualified Certificate Service"
        );
    }

    #[cfg(feature = "eudi-client")]
    #[test]
    fn test_parse_service_status() {
        assert_eq!(
            EudiLotlClient::parse_service_status(
                "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
            ),
            TspStatus::Granted
        );
        assert_eq!(
            EudiLotlClient::parse_service_status(
                "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
            ),
            TspStatus::Withdrawn
        );
        assert_eq!(
            EudiLotlClient::parse_service_status(
                "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/suspended"
            ),
            TspStatus::Suspended
        );
        assert_eq!(
            EudiLotlClient::parse_service_status("http://unknown.status"),
            TspStatus::Unknown
        );
    }

    #[cfg(feature = "eudi-client")]
    #[tokio::test]
    async fn bounded_xml_reader_accepts_response_at_limit() {
        let body = b"0123456789abcdef";
        let mut raw_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw_response.extend_from_slice(body);
        let (response, server) = request_raw_http_response(raw_response).await;

        let xml = read_bounded_xml_response(response, "test endpoint", "LoTL", body.len())
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(xml, String::from_utf8_lossy(body));
    }

    #[cfg(feature = "eudi-client")]
    #[tokio::test]
    async fn fetch_lotl_preserves_valid_xml_behavior() {
        let body = SAMPLE_LOTL_XML.as_bytes();
        let mut raw_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw_response.extend_from_slice(body);
        let (url, server) = serve_raw_http_response(raw_response);

        let trusted_lists = EudiLotlClient::with_url(url).fetch_lotl().await.unwrap();
        server.join().unwrap();

        assert_eq!(trusted_lists.len(), 2);
        assert_eq!(trusted_lists[0].scheme_territory, "DE");
        assert_eq!(trusted_lists[1].scheme_territory, "FR");
    }

    #[cfg(feature = "eudi-client")]
    #[tokio::test]
    async fn bounded_xml_reader_rejects_declared_oversized_response() {
        let body = b"0123456789abcdefg";
        let mut raw_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw_response.extend_from_slice(body);
        let (response, server) = request_raw_http_response(raw_response).await;

        let error = read_bounded_xml_response(response, "test endpoint", "LoTL", body.len() - 1)
            .await
            .unwrap_err();
        server.join().unwrap();

        assert!(error
            .to_string()
            .contains("LoTL response exceeds the 16-byte limit"));
    }

    #[cfg(feature = "eudi-client")]
    #[tokio::test]
    async fn bounded_xml_reader_rejects_chunked_oversized_response() {
        let raw_response = b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n11\r\n0123456789abcdefg\r\n0\r\n\r\n".to_vec();
        let (response, server) = request_raw_http_response(raw_response).await;

        let error = read_bounded_xml_response(response, "test endpoint", "TL", 16)
            .await
            .unwrap_err();
        server.join().unwrap();

        assert!(error
            .to_string()
            .contains("TL response exceeds the 16-byte limit"));
    }
}
