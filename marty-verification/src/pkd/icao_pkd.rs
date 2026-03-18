//! ICAO PKD (Public Key Directory) client.
//!
//! This module provides an async client for fetching CSCA/DSC certificates
//! from the ICAO Public Key Directory for eMRTD verification.

use std::path::PathBuf;

use x509_cert::Certificate;

use crate::error::{VerificationError, VerificationResult};
use crate::trust_anchor::CscaRegistry;

#[cfg(feature = "icao-client")]
use ldap3::{LdapConnAsync, Scope, SearchEntry};

/// ICAO PKD client configuration.
#[derive(Debug, Clone)]
pub struct IcaoPkdConfig {
    /// Base URL for the PKD download service.
    pub base_url: String,
    /// Username for PKD access.
    pub username: Option<String>,
    /// Password for PKD access.
    pub password: Option<String>,
    /// Optional local PKD cache directory (existing pattern for offline/secure storage).
    pub offline_dir: Option<PathBuf>,
}

impl Default for IcaoPkdConfig {
    fn default() -> Self {
        Self {
            base_url: "https://pkddownloadsg.icao.int".to_string(),
            username: None,
            password: None,
            offline_dir: None,
        }
    }
}

impl IcaoPkdConfig {
    /// Create config from environment variables.
    pub fn from_env() -> Self {
        Self {
            base_url: std::env::var("ICAO_PKD_BASE_URL")
                .unwrap_or_else(|_| "https://pkddownloadsg.icao.int".to_string()),
            username: std::env::var("ICAO_PKD_USERNAME").ok(),
            password: std::env::var("ICAO_PKD_PASSWORD").ok(),
            offline_dir: std::env::var("ICAO_PKD_DIR").ok().map(PathBuf::from),
        }
    }
}

/// ICAO PKD client for fetching CSCA/DSC certificates.
pub struct IcaoPkdClient {
    config: IcaoPkdConfig,
    http_client: reqwest::Client,
}

/// Master List entry.
#[derive(Debug, Clone)]
pub struct MasterListEntry {
    /// Country code (ISO 3166-1 alpha-2).
    pub country: String,
    /// DER-encoded CSCA certificate.
    pub certificate_der: Vec<u8>,
    /// Certificate serial number.
    pub serial_number: String,
}

/// DSC (Document Signer Certificate) entry.
#[derive(Debug, Clone)]
pub struct DscEntry {
    /// Country code (ISO 3166-1 alpha-2).
    pub country: String,
    /// DER-encoded DSC certificate.
    pub certificate_der: Vec<u8>,
    /// Issuer country (should match country).
    pub issuer_country: String,
}

/// CRL (Certificate Revocation List) entry.
#[derive(Debug, Clone)]
pub struct CrlEntry {
    /// Country code.
    pub country: String,
    /// DER-encoded CRL.
    pub crl_der: Vec<u8>,
    /// Next update time.
    pub next_update: Option<String>,
}

impl IcaoPkdClient {
    /// Create a new ICAO PKD client.
    pub fn new(config: IcaoPkdConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }

    /// Create a client from environment variables.
    pub fn from_env() -> Self {
        Self::new(IcaoPkdConfig::from_env())
    }

    /// Fetch the CSCA Master List.
    ///
    /// The Master List contains all trusted CSCA certificates.
    pub async fn fetch_master_list(&self) -> VerificationResult<Vec<MasterListEntry>> {
        #[cfg(not(feature = "icao-client"))]
        {
            tracing::warn!("ICAO PKD client feature not enabled");
            return Ok(Vec::new());
        }

        #[cfg(feature = "icao-client")]
        {
            self.fetch_master_list_ldap().await
        }
    }

    #[cfg(feature = "icao-client")]
    async fn fetch_master_list_ldap(&self) -> VerificationResult<Vec<MasterListEntry>> {
        // ICAO PKD uses LDAP/LDIF format
        let ldap_url = format!("ldap://{}:389", self.config.base_url.replace("https://", ""));
        let base_dn = "ou=CSCA,dc=pkd,dc=icao,dc=int";

        let (conn, mut ldap) = LdapConnAsync::new(&ldap_url)
            .await
            .map_err(|e| VerificationError::pkd_fetch(&ldap_url, format!("LDAP connection failed: {}", e)))?;

        ldap3::drive!(conn);

        // Bind
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            let bind_dn = format!("uid={},{}", username, base_dn);
            ldap.simple_bind(&bind_dn, password)
                .await
                .map_err(|e| VerificationError::pkd_fetch(&ldap_url, format!("LDAP bind failed: {}", e)))?;
        } else {
            ldap.simple_bind("", "")
                .await
                .map_err(|e| VerificationError::pkd_fetch(&ldap_url, format!("LDAP anonymous bind failed: {}", e)))?;
        }

        // Search for CSCA certificates
        let (rs, _res) = ldap
            .search(
                base_dn,
                Scope::Subtree,
                "(objectClass=pkiCA)",
                vec!["cACertificate", "c", "serialNumber"],
            )
            .await
            .map_err(|e| VerificationError::pkd_fetch(&ldap_url, format!("LDAP search failed: {}", e)))?
            .success()
            .map_err(|e| VerificationError::pkd_fetch(&ldap_url, format!("LDAP search result failed: {:?}", e)))?;

        let mut entries = Vec::new();

        for entry in rs {
            let search_entry = SearchEntry::construct(entry);

            // Extract country code
            let country = search_entry
                .attrs
                .get("c")
                .and_then(|v| v.first())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "XX".to_string());

            // Extract serial number
            let serial_number = search_entry
                .attrs
                .get("serialNumber")
                .and_then(|v| v.first())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            // Extract certificate (DER-encoded binary)
            if let Some(cert_values) = search_entry.bin_attrs.get("cACertificate") {
                for cert_der in cert_values {
                    entries.push(MasterListEntry {
                        country: country.clone(),
                        certificate_der: cert_der.clone(),
                        serial_number: serial_number.clone(),
                    });
                }
            }
        }

        let _ = ldap.unbind().await;

        tracing::info!("Fetched {} CSCA certificates from ICAO PKD", entries.len());
        Ok(entries)
    }

    #[cfg(feature = "icao-client")]
    #[allow(dead_code)]
    async fn fetch_country_dsc_ldap(&self, country: &str) -> VerificationResult<Vec<DscEntry>> {
        let ldap_url = format!("ldap://{}:389", self.config.base_url.replace("https://", ""));
        let base_dn = "ou=DSC,dc=pkd,dc=icao,dc=int";

        let (conn, mut ldap) = LdapConnAsync::new(&ldap_url)
            .await
            .map_err(|e| VerificationError::pkd_fetch(&ldap_url, format!("LDAP connection failed: {}", e)))?;

        ldap3::drive!(conn);

        // Bind
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            let bind_dn = format!("uid={},{}", username, base_dn);
            ldap.simple_bind(&bind_dn, password)
                .await
                .map_err(|e| VerificationError::pkd_fetch(&ldap_url, format!("LDAP bind failed: {}", e)))?;
        } else {
            ldap.simple_bind("", "")
                .await
                .map_err(|e| VerificationError::pkd_fetch(&ldap_url, format!("LDAP anonymous bind failed: {}", e)))?;
        }

        // Search for DSC certificates for this country
        let filter = format!("(&(objectClass=pkiUser)(c={}))", country.to_uppercase());
        let (rs, _res) = ldap
            .search(
                base_dn,
                Scope::Subtree,
                &filter,
                vec!["userCertificate", "c"],
            )
            .await
            .map_err(|e| VerificationError::pkd_fetch(&ldap_url, format!("LDAP search failed: {}", e)))?
            .success()
            .map_err(|e| VerificationError::pkd_fetch(&ldap_url, format!("LDAP search result failed: {:?}", e)))?;

        let mut entries = Vec::new();

        for entry in rs {
            let search_entry = SearchEntry::construct(entry);

            let country_code = search_entry
                .attrs
                .get("c")
                .and_then(|v| v.first())
                .map(|s| s.to_string())
                .unwrap_or_else(|| country.to_string());

            if let Some(cert_values) = search_entry.bin_attrs.get("userCertificate") {
                for cert_der in cert_values {
                    entries.push(DscEntry {
                        country: country_code.clone(),
                        certificate_der: cert_der.clone(),
                        issuer_country: country_code.clone(),
                    });
                }
            }
        }

        let _ = ldap.unbind().await;

        tracing::info!("Fetched {} DSC certificates for country {} from ICAO PKD", entries.len(), country);
        Ok(entries)
    }

    /// Fetch DSC certificates for a specific country.
    ///
    /// When the `icao-client` feature is enabled (LDAP), uses the ICAO PKD
    /// LDAP directory.  Falls back to a no-op warning when LDAP is unavailable.
    pub async fn fetch_country_dsc(&self, country: &str) -> VerificationResult<Vec<DscEntry>> {
        #[cfg(feature = "icao-client")]
        {
            return self.fetch_country_dsc_ldap(country).await;
        }

        #[allow(unreachable_code)]
        {
            tracing::warn!(
                "icao-client feature not enabled; cannot fetch DSC for country {}",
                country
            );
            Ok(Vec::new())
        }
    }

    /// Fetch CRL for a specific country and parse it into a [`CrlEntry`].
    ///
    /// Returns `Ok(None)` when no CRL is published for the country (HTTP 404)
    /// or when the payload cannot be parsed (a warning is logged).
    pub async fn fetch_country_crl(&self, country: &str) -> VerificationResult<Option<CrlEntry>> {
        let endpoint = format!("{}/crl/{}", self.config.base_url, country);

        let response = self.http_client.get(&endpoint).send().await.map_err(|e| {
            VerificationError::pkd_fetch(
                &endpoint,
                format!("CRL fetch for {} failed: {}", country, e),
            )
        })?;

        if response.status().is_success() {
            let crl_der = response
                .bytes()
                .await
                .map_err(|e| {
                    VerificationError::pkd_fetch(
                        &endpoint,
                        format!("Failed to read CRL bytes for {}: {}", country, e),
                    )
                })?
                .to_vec();

            match crate::asn1::crl::parse_crl(&crl_der) {
                Ok(info) => {
                    let next_update = info.next_update.map(|dt| dt.to_rfc3339());
                    tracing::info!(
                        "Fetched and parsed CRL for country {} (next update: {:?})",
                        country,
                        next_update
                    );
                    Ok(Some(CrlEntry {
                        country: country.to_string(),
                        crl_der,
                        next_update,
                    }))
                }
                Err(e) => {
                    tracing::warn!("Failed to parse CRL for {}: {}", country, e);
                    Ok(None)
                }
            }
        } else if response.status().as_u16() == 404 {
            // No CRL available for this country
            Ok(None)
        } else {
            Err(VerificationError::pkd_fetch(
                endpoint,
                format!("CRL fetch for {} failed: {}", country, response.status()),
            ))
        }
    }

    /// Sync a CSCA registry with the latest Master List.
    ///
    /// Returns the number of certificates added/updated.
    pub async fn sync_registry(&self, registry: &mut CscaRegistry) -> VerificationResult<usize> {
        use der::Decode;

        // First, prefer local/offline PKD cache when configured (existing pattern).
        if let Some(dir) = &self.config.offline_dir {
            if dir.exists() {
                let added = registry.merge_from_directory(dir)?;
                registry.set_master_list_version("offline-cache".to_string());
                tracing::info!(
                    "Loaded {} CSCA certificates from offline PKD cache at {}",
                    added,
                    dir.display()
                );
                return Ok(added);
            } else {
                tracing::warn!(
                    "Configured ICAO_PKD_DIR {} does not exist; falling back to remote fetch",
                    dir.display()
                );
            }
        }

        let master_list = self.fetch_master_list().await?;
        let mut count = 0;

        for entry in master_list {
            match Certificate::from_der(&entry.certificate_der) {
                Ok(cert) => {
                    registry.add_country_csca(&entry.country, cert)?;
                    count += 1;

                    tracing::info!("Added/updated CSCA for country: {}", entry.country);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse CSCA for {}: {}", entry.country, e);
                }
            }
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = IcaoPkdConfig::default();
        assert!(!config.base_url.is_empty());
    }
}
