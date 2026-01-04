//! AAMVA Digital Trust Service (DTS) client.
//!
//! This module provides an async client for fetching IACA certificates
//! from the AAMVA Digital Trust Service.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::error::{VerificationError, VerificationResult};
use crate::trust_anchor::{IacaRegistry, Jurisdiction, TrustAnchor, TrustPurpose, TrustRegistry};

/// AAMVA DTS client configuration.
#[derive(Debug, Clone)]
pub struct AamvaDtsConfig {
    /// Base URL for the DTS API.
    pub base_url: String,
    /// OAuth client ID.
    pub client_id: String,
    /// OAuth client secret.
    pub client_secret: String,
    /// Token endpoint for OAuth.
    pub token_endpoint: String,
}

impl Default for AamvaDtsConfig {
    fn default() -> Self {
        Self {
            // These would be the actual AAMVA DTS endpoints
            base_url: "https://dts.aamva.org/api/v1".to_string(),
            client_id: String::new(),
            client_secret: String::new(),
            token_endpoint: "https://dts.aamva.org/oauth/token".to_string(),
        }
    }
}

impl AamvaDtsConfig {
    /// Create config from environment variables.
    pub fn from_env() -> VerificationResult<Self> {
        Ok(Self {
            base_url: std::env::var("AAMVA_DTS_BASE_URL")
                .unwrap_or_else(|_| "https://dts.aamva.org/api/v1".to_string()),
            client_id: std::env::var("AAMVA_DTS_CLIENT_ID")
                .map_err(|_| VerificationError::PkdAuthError {
                    reason: "AAMVA_DTS_CLIENT_ID environment variable not set. Set this to your AAMVA DTS OAuth client ID.".to_string(),
                    code: crate::error::codes::PKD_AUTH_ERROR,
                })?,
            client_secret: std::env::var("AAMVA_DTS_CLIENT_SECRET")
                .map_err(|_| VerificationError::PkdAuthError {
                    reason: "AAMVA_DTS_CLIENT_SECRET environment variable not set. Set this to your AAMVA DTS OAuth client secret.".to_string(),
                    code: crate::error::codes::PKD_AUTH_ERROR,
                })?,
            token_endpoint: std::env::var("AAMVA_DTS_TOKEN_ENDPOINT")
                .unwrap_or_else(|_| "https://dts.aamva.org/oauth/token".to_string()),
        })
    }
}

/// AAMVA DTS client for fetching IACA certificates.
pub struct AamvaDtsClient {
    config: AamvaDtsConfig,
    http_client: reqwest::Client,
    access_token: Option<String>,
}

/// VICAL (Verifier IACA Certificate Authority List) response.
#[derive(Debug, Deserialize)]
pub struct VicalResponse {
    /// VICAL version for delta sync.
    pub version: String,
    /// List of IACA certificates.
    pub certificates: Vec<VicalCertificate>,
}

/// Individual certificate in VICAL.
#[derive(Debug, Deserialize)]
pub struct VicalCertificate {
    /// Jurisdiction code (e.g., "US-CA").
    pub jurisdiction: String,
    /// PEM-encoded certificate.
    pub certificate_pem: String,
    /// Certificate status.
    pub status: String,
    /// Valid from date.
    pub valid_from: Option<String>,
    /// Valid until date.
    pub valid_until: Option<String>,
}

/// OAuth token response.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

impl AamvaDtsClient {
    /// Create a new AAMVA DTS client.
    pub fn new(config: AamvaDtsConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
            access_token: None,
        }
    }

    /// Create a client from environment variables.
    pub fn from_env() -> VerificationResult<Self> {
        Ok(Self::new(AamvaDtsConfig::from_env()?))
    }

    /// Authenticate with the DTS OAuth endpoint.
    async fn authenticate(&mut self) -> VerificationResult<()> {
        use crate::error::codes;

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let response = self
            .http_client
            .post(&self.config.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| VerificationError::PkdAuthError {
                reason: format!(
                    "OAuth request to {} failed: {}. Check network connectivity and endpoint URL.",
                    self.config.token_endpoint, e
                ),
                code: codes::PKD_AUTH_ERROR,
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VerificationError::PkdAuthError {
                reason: format!("OAuth authentication failed with status {}: {}. Verify client_id and client_secret are correct.",
                    status, body),
                code: codes::PKD_AUTH_ERROR,
            });
        }

        let token: TokenResponse = response.json().await
            .map_err(|e| VerificationError::PkdAuthError {
                reason: format!("Failed to parse OAuth token response: {}. The DTS endpoint may have changed its response format.", e),
                code: codes::PKD_AUTH_ERROR,
            })?;

        self.access_token = Some(token.access_token);
        Ok(())
    }

    /// Ensure we have a valid access token.
    async fn ensure_authenticated(&mut self) -> VerificationResult<&str> {
        if self.access_token.is_none() {
            self.authenticate().await?;
        }
        Ok(self.access_token.as_ref().unwrap())
    }

    /// Fetch the complete VICAL (Verifier IACA Certificate Authority List).
    pub async fn fetch_vical(&mut self) -> VerificationResult<VicalResponse> {
        use crate::error::codes;

        let token = self.ensure_authenticated().await?.to_string();
        let endpoint = format!("{}/vical", self.config.base_url);

        let response = self
            .http_client
            .get(&endpoint)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| VerificationError::PkdFetchError {
                endpoint: endpoint.clone(),
                reason: format!("Network request failed: {}. Check DTS connectivity.", e),
                code: codes::PKD_FETCH_ERROR,
                source: None,
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VerificationError::PkdFetchError {
                endpoint,
                reason: format!("HTTP {} - {}. The access token may have expired or the DTS service is unavailable.", 
                    status, body),
                code: codes::PKD_FETCH_ERROR,
                source: None,
            });
        }

        response
            .json()
            .await
            .map_err(|e| VerificationError::PkdFetchError {
                endpoint,
                reason: format!(
                    "Invalid VICAL JSON response: {}. The DTS response format may have changed.",
                    e
                ),
                code: codes::PKD_FETCH_ERROR,
                source: None,
            })
    }

    /// Fetch IACA certificate for a specific jurisdiction.
    pub async fn fetch_jurisdiction_iaca(
        &mut self,
        jurisdiction: &str,
    ) -> VerificationResult<VicalCertificate> {
        let token = self.ensure_authenticated().await?.to_string();

        let response = self
            .http_client
            .get(format!("{}/iaca/{}", self.config.base_url, jurisdiction))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| VerificationError::PkdFetchError {
                reason: format!("IACA fetch failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(VerificationError::PkdFetchError {
                reason: format!(
                    "IACA fetch for {} failed: {}",
                    jurisdiction,
                    response.status()
                ),
            });
        }

        response
            .json()
            .await
            .map_err(|e| VerificationError::PkdFetchError {
                reason: format!("Failed to parse IACA response: {}", e),
            })
    }

    /// Fetch delta updates since a specific VICAL version.
    pub async fn fetch_vical_delta(
        &mut self,
        since_version: &str,
    ) -> VerificationResult<VicalResponse> {
        let token = self.ensure_authenticated().await?.to_string();

        let response = self
            .http_client
            .get(format!("{}/vical/delta", self.config.base_url))
            .query(&[("since", since_version)])
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| VerificationError::PkdFetchError {
                reason: format!("VICAL delta fetch failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(VerificationError::PkdFetchError {
                reason: format!("VICAL delta fetch failed: {}", response.status()),
            });
        }

        response
            .json()
            .await
            .map_err(|e| VerificationError::PkdFetchError {
                reason: format!("Failed to parse VICAL delta response: {}", e),
            })
    }

    /// Sync an IACA registry with the latest VICAL.
    ///
    /// Returns the number of certificates added/updated.
    pub async fn sync_registry(
        &mut self,
        registry: &mut IacaRegistry,
    ) -> VerificationResult<usize> {
        use der::DecodePem;

        let vical = if let Some(version) = registry.vical_version() {
            self.fetch_vical_delta(version).await?
        } else {
            self.fetch_vical().await?
        };

        let mut count = 0;
        for cert_info in vical.certificates {
            if cert_info.status != "active" {
                continue;
            }

            match Certificate::from_pem(&cert_info.certificate_pem) {
                Ok(cert) => {
                    let anchor = TrustAnchor {
                        certificate: cert,
                        purpose: TrustPurpose::Iaca,
                        jurisdiction: Some(cert_info.jurisdiction.clone()),
                    };

                    // Remove existing anchor for this jurisdiction first
                    let _ = registry.remove_anchor(&cert_info.jurisdiction);

                    registry.add_anchor(anchor)?;
                    count += 1;

                    tracing::info!(
                        "Added/updated IACA for jurisdiction: {}",
                        cert_info.jurisdiction
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to parse IACA for {}: {}", cert_info.jurisdiction, e);
                }
            }
        }

        registry.set_vical_version(vical.version);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AamvaDtsConfig::default();
        assert!(!config.base_url.is_empty());
    }
}
