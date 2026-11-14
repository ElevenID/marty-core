//! AAMVA Digital Trust Service (DTS) client.
//!
//! This module provides an async client for fetching IACA certificates
//! from the AAMVA Digital Trust Service.

use serde::Deserialize;
use std::time::{Duration, Instant};
use x509_cert::Certificate;

use crate::error::{VerificationError, VerificationResult};
use crate::trust_anchor::{IacaRegistry, TrustAnchor, TrustPurpose, TrustRegistry};

const DEFAULT_DTS_BASE_URL: &str = "https://dts.aamva.org/api/v1";
const DEFAULT_DTS_TOKEN_ENDPOINT: &str = "https://dts.aamva.org/oauth/token";

/// AAMVA DTS client configuration.
#[derive(Clone)]
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

impl std::fmt::Debug for AamvaDtsConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AamvaDtsConfig")
            .field("base_url", &self.base_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("token_endpoint", &self.token_endpoint)
            .finish()
    }
}

impl Default for AamvaDtsConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_DTS_BASE_URL.to_string(),
            client_id: String::new(),
            client_secret: String::new(),
            token_endpoint: DEFAULT_DTS_TOKEN_ENDPOINT.to_string(),
        }
    }
}

impl AamvaDtsConfig {
    /// Create config from environment variables.
    pub fn from_env() -> VerificationResult<Self> {
        Ok(Self {
            base_url: std::env::var("AAMVA_DTS_BASE_URL")
                .unwrap_or_else(|_| DEFAULT_DTS_BASE_URL.to_string()),
            client_id: std::env::var("AAMVA_DTS_CLIENT_ID")
                .map_err(|_| VerificationError::pkd_auth(
                    "AAMVA_DTS_CLIENT_ID environment variable not set. Set this to your AAMVA DTS OAuth client ID."
                ))?,
            client_secret: std::env::var("AAMVA_DTS_CLIENT_SECRET")
                .map_err(|_| VerificationError::pkd_auth(
                    "AAMVA_DTS_CLIENT_SECRET environment variable not set. Set this to your AAMVA DTS OAuth client secret."
                ))?,
            token_endpoint: std::env::var("AAMVA_DTS_TOKEN_ENDPOINT")
                .unwrap_or_else(|_| DEFAULT_DTS_TOKEN_ENDPOINT.to_string()),
        })
    }
}

/// AAMVA DTS client for fetching IACA certificates.
pub struct AamvaDtsClient {
    config: AamvaDtsConfig,
    http_client: reqwest::Client,
    access_token: Option<CachedAccessToken>,
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
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

struct CachedAccessToken {
    value: String,
    expires_at: Instant,
}

impl CachedAccessToken {
    fn from_response(token: TokenResponse, requested_at: Instant) -> VerificationResult<Self> {
        if token.access_token.trim().is_empty()
            || !token.token_type.eq_ignore_ascii_case("Bearer")
            || token.expires_in == 0
        {
            return Err(VerificationError::pkd_auth(
                "OAuth response must contain a non-empty Bearer token with a positive lifetime",
            ));
        }
        let expires_at = requested_at
            .checked_add(Duration::from_secs(token.expires_in))
            .ok_or_else(|| VerificationError::pkd_auth("OAuth token lifetime is out of range"))?;
        Ok(Self {
            value: token.access_token,
            expires_at,
        })
    }

    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
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
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        // Starting the lifetime before the request is conservative about time
        // spent waiting for the token endpoint's response.
        let requested_at = Instant::now();
        let response = self
            .http_client
            .post(&self.config.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                VerificationError::pkd_auth(format!(
                    "OAuth request to {} failed: {}. Check network connectivity and endpoint URL.",
                    self.config.token_endpoint, e
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(VerificationError::pkd_auth(format!(
                "OAuth authentication failed with status {}. Verify client_id and client_secret are correct.",
                status
            )));
        }

        let token: TokenResponse = response.json().await
            .map_err(|e| VerificationError::pkd_auth(format!(
                "Failed to parse OAuth token response: {}. The DTS endpoint may have changed its response format.", e
            )))?;

        let token = CachedAccessToken::from_response(token, requested_at)?;
        if token.is_expired(Instant::now()) {
            return Err(VerificationError::pkd_auth(
                "OAuth access token expired before its response was received",
            ));
        }
        self.access_token = Some(token);
        Ok(())
    }

    /// Ensure we have a valid access token.
    async fn ensure_authenticated(&mut self) -> VerificationResult<&str> {
        if self
            .access_token
            .as_ref()
            .is_none_or(|token| token.is_expired(Instant::now()))
        {
            self.access_token = None;
            self.authenticate().await?;
        }
        self.access_token
            .as_ref()
            .map(|token| token.value.as_str())
            .ok_or_else(|| VerificationError::pkd_auth("OAuth access token is unavailable"))
    }

    /// Fetch the complete VICAL (Verifier IACA Certificate Authority List).
    pub async fn fetch_vical(&mut self) -> VerificationResult<VicalResponse> {
        let token = self.ensure_authenticated().await?.to_string();
        let endpoint = format!("{}/vical", self.config.base_url);

        let response = self
            .http_client
            .get(&endpoint)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| {
                VerificationError::pkd_fetch(
                    &endpoint,
                    format!("Network request failed: {}. Check DTS connectivity.", e),
                )
            })?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(VerificationError::pkd_fetch(
                endpoint,
                format!(
                    "HTTP {}. The access token may have expired or the DTS service is unavailable.",
                    status
                ),
            ));
        }

        let endpoint_clone = endpoint.clone();
        response.json().await.map_err(|e| {
            VerificationError::pkd_fetch(
                endpoint_clone,
                format!(
                    "Invalid VICAL JSON response: {}. The DTS response format may have changed.",
                    e
                ),
            )
        })
    }

    /// Fetch IACA certificate for a specific jurisdiction.
    pub async fn fetch_jurisdiction_iaca(
        &mut self,
        jurisdiction: &str,
    ) -> VerificationResult<VicalCertificate> {
        let token = self.ensure_authenticated().await?.to_string();
        let endpoint = format!("{}/iaca/{}", self.config.base_url, jurisdiction);

        let response = self
            .http_client
            .get(&endpoint)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| {
                VerificationError::pkd_fetch(&endpoint, format!("IACA fetch failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(VerificationError::pkd_fetch(
                &endpoint,
                format!(
                    "IACA fetch for {} failed: {}",
                    jurisdiction,
                    response.status()
                ),
            ));
        }

        let endpoint_clone = endpoint.clone();
        response.json().await.map_err(|e| {
            VerificationError::pkd_fetch(
                endpoint_clone,
                format!("Failed to parse IACA response: {}", e),
            )
        })
    }

    /// Fetch delta updates since a specific VICAL version.
    pub async fn fetch_vical_delta(
        &mut self,
        since_version: &str,
    ) -> VerificationResult<VicalResponse> {
        let token = self.ensure_authenticated().await?.to_string();
        let endpoint = format!("{}/vical/delta", self.config.base_url);

        let response = self
            .http_client
            .get(&endpoint)
            .query(&[("since", since_version)])
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| {
                VerificationError::pkd_fetch(&endpoint, format!("VICAL delta fetch failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(VerificationError::pkd_fetch(
                &endpoint,
                format!("VICAL delta fetch failed: {}", response.status()),
            ));
        }

        let endpoint_clone = endpoint.clone();
        response.json().await.map_err(|e| {
            VerificationError::pkd_fetch(
                endpoint_clone,
                format!("Failed to parse VICAL delta response: {}", e),
            )
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_default_config() {
        let config = AamvaDtsConfig::default();
        assert!(!config.base_url.is_empty());
    }

    #[test]
    fn config_debug_redacts_oauth_secret() {
        let config = AamvaDtsConfig {
            client_secret: "synthetic-client-secret".into(),
            ..AamvaDtsConfig::default()
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("synthetic-client-secret"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn cached_token_expires_at_the_advertised_boundary() {
        let issued_at = Instant::now();
        let token = CachedAccessToken::from_response(
            TokenResponse {
                access_token: "synthetic-token".into(),
                token_type: "bearer".into(),
                expires_in: 60,
            },
            issued_at,
        )
        .unwrap();
        assert!(!token.is_expired(issued_at + Duration::from_secs(59)));
        assert!(token.is_expired(issued_at + Duration::from_secs(60)));
        assert!(token.is_expired(issued_at + Duration::from_secs(61)));
    }

    #[test]
    fn unusable_token_responses_are_rejected_without_echoing_the_token() {
        for (value, kind, lifetime) in [
            ("", "Bearer", 60),
            ("  ", "Bearer", 60),
            ("synthetic-token", "MAC", 60),
            ("synthetic-token", "Bearer", 0),
            ("synthetic-token", "Bearer", u64::MAX),
        ] {
            let result = CachedAccessToken::from_response(
                TokenResponse {
                    access_token: value.into(),
                    token_type: kind.into(),
                    expires_in: lifetime,
                },
                Instant::now(),
            );
            let error = result.err().expect("invalid token response must fail");
            assert!(!error.to_string().contains("synthetic-token"));
        }
    }

    struct HttpExchange {
        path: &'static str,
        authorization: Option<&'static str>,
        status: &'static str,
        body: &'static str,
    }

    async fn client_with_server(
        exchanges: Vec<HttpExchange>,
    ) -> (AamvaDtsClient, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for exchange in exchanges {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 1024];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0, "request closed before its headers");
                    bytes.extend_from_slice(&buffer[..count]);
                    assert!(
                        bytes.len() <= 16 * 1024,
                        "request headers exceeded test bound"
                    );
                    if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                assert!(request.lines().next().unwrap().contains(exchange.path));
                let header_end = request.find("\r\n\r\n").unwrap() + 4;
                let content_length = request[..header_end]
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
                let mut received = request.len() - header_end;
                while received < content_length {
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0, "request closed before its body");
                    received += count;
                }
                if let Some(authorization) = exchange.authorization {
                    assert!(request[..header_end]
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .any(|(name, value)| name.eq_ignore_ascii_case("authorization")
                            && value.trim() == authorization));
                }
                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    exchange.status,
                    exchange.body.len(),
                    exchange.body,
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        let mut client = AamvaDtsClient::new(AamvaDtsConfig {
            base_url: base.clone(),
            token_endpoint: format!("{base}/oauth/token"),
            client_id: "test-client".into(),
            client_secret: "synthetic-client-secret".into(),
        });
        client.http_client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        (client, server)
    }

    fn token_exchange(value: &'static str) -> HttpExchange {
        HttpExchange {
            path: "/oauth/token",
            authorization: None,
            status: "200 OK",
            body: value,
        }
    }

    fn vical_exchange(authorization: &'static str) -> HttpExchange {
        HttpExchange {
            path: "/vical",
            authorization: Some(authorization),
            status: "200 OK",
            body: r#"{"version":"1","certificates":[]}"#,
        }
    }

    #[tokio::test]
    async fn client_reuses_live_tokens_and_refreshes_expired_tokens() {
        let (mut client, server) = client_with_server(vec![
            token_exchange(r#"{"access_token":"first","token_type":"Bearer","expires_in":60}"#),
            vical_exchange("Bearer first"),
            vical_exchange("Bearer first"),
            token_exchange(r#"{"access_token":"second","token_type":"Bearer","expires_in":60}"#),
            vical_exchange("Bearer second"),
        ])
        .await;
        client.fetch_vical().await.unwrap();
        client.fetch_vical().await.unwrap();
        client.access_token.as_mut().unwrap().expires_at = Instant::now();
        client.fetch_vical().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn authentication_errors_do_not_expose_response_bodies_or_cache_tokens() {
        let (mut client, server) = client_with_server(vec![HttpExchange {
            path: "/oauth/token",
            authorization: None,
            status: "401 Unauthorized",
            body: r#"{"secret":"synthetic-client-secret"}"#,
        }])
        .await;
        let error = client.fetch_vical().await.unwrap_err().to_string();
        assert!(error.contains("401"));
        assert!(!error.contains("synthetic-client-secret"));
        assert!(client.access_token.is_none());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn vical_errors_do_not_expose_response_bodies() {
        let (mut client, server) = client_with_server(vec![
            token_exchange(r#"{"access_token":"first","token_type":"Bearer","expires_in":60}"#),
            HttpExchange {
                path: "/vical",
                authorization: Some("Bearer first"),
                status: "503 Service Unavailable",
                body: r#"{"secret":"synthetic-provider-secret"}"#,
            },
        ])
        .await;
        let error = client.fetch_vical().await.unwrap_err().to_string();
        assert!(error.contains("503"));
        assert!(!error.contains("synthetic-provider-secret"));
        server.await.unwrap();
    }
}
