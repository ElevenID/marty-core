//! Canonical trust-registry catalog and synchronization decisions.
//!
//! Network transport and durable storage intentionally remain outside this
//! module. Everything that decides whether remote registry data may alter
//! effective trust is implemented here and fails closed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::{Host, Url};
use uuid::Uuid;

pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PAGES: usize = 100;
pub const MAX_ENTRIES_PER_PAGE: usize = 10_000;
pub const SYNC_PROTOCOL: &str = "MARTY_TRUST_REGISTRY_SYNC_V1";

/// Language-neutral behavior vectors used by Rust and adapter suites.
pub fn behavior_fixture_json() -> &'static str {
    include_str!("../tests/fixtures/trust_registry_sync_behavior.json")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustSyncError {
    code: &'static str,
    message: String,
}

impl TrustSyncError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TrustSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "TRUST_REGISTRY.{}: {}", self.code, self.message)
    }
}

impl std::error::Error for TrustSyncError {}

pub type TrustSyncResult<T> = Result<T, TrustSyncError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistryType {
    IcaoPkd,
    EuTrustList,
    Aamva,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustFramework {
    Icao,
    Eudi,
    Aamva,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialFormat {
    Mdoc,
    SdJwtVc,
    VcJwt,
    JsonLd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryConfig {
    pub registry_type: RegistryType,
    pub registry_name: &'static str,
    pub registry_url: &'static str,
    pub supported_frameworks: &'static [TrustFramework],
    pub supported_formats: &'static [CredentialFormat],
    pub sync_interval_hours: u16,
    pub description: &'static str,
    pub issuer_type_filter: &'static str,
}

const ICAO_FRAMEWORKS: &[TrustFramework] = &[TrustFramework::Icao];
const EUDI_FRAMEWORKS: &[TrustFramework] = &[TrustFramework::Eudi];
const AAMVA_FRAMEWORKS: &[TrustFramework] = &[TrustFramework::Aamva];
const ICAO_FORMATS: &[CredentialFormat] = &[CredentialFormat::Mdoc];
const EUDI_FORMATS: &[CredentialFormat] = &[CredentialFormat::SdJwtVc, CredentialFormat::VcJwt];
const AAMVA_FORMATS: &[CredentialFormat] = &[CredentialFormat::Mdoc, CredentialFormat::SdJwtVc];

pub const REGISTRY_CATALOG: &[RegistryConfig] = &[
    RegistryConfig {
        registry_type: RegistryType::IcaoPkd,
        registry_name: "ICAO Public Key Directory",
        registry_url: "https://pkd.icao.int",
        supported_frameworks: ICAO_FRAMEWORKS,
        supported_formats: ICAO_FORMATS,
        sync_interval_hours: 24,
        description: "International Civil Aviation Organization Public Key Directory for ePassports and travel documents",
        issuer_type_filter: "DOCUMENT_SIGNER",
    },
    RegistryConfig {
        registry_type: RegistryType::EuTrustList,
        registry_name: "EU List of Trusted Lists (LoTL)",
        registry_url: "https://ec.europa.eu/digital-building-blocks/web-redirect/en/eu-trusted-lists-xml",
        supported_frameworks: EUDI_FRAMEWORKS,
        supported_formats: EUDI_FORMATS,
        sync_interval_hours: 24,
        description: "European Union's centralized Trust List containing trusted certificate and credential issuers",
        issuer_type_filter: "CREDENTIAL_ISSUER",
    },
    RegistryConfig {
        registry_type: RegistryType::Aamva,
        registry_name: "American Association of Motor Vehicle Administrators",
        registry_url: "https://www.aamva.org/standards",
        supported_frameworks: AAMVA_FRAMEWORKS,
        supported_formats: AAMVA_FORMATS,
        sync_interval_hours: 24,
        description: "AAMVA database of trusted issuers for mobile driver licenses and travel documents",
        issuer_type_filter: "MDOC_ISSUER",
    },
];

pub fn registry_catalog(framework: Option<TrustFramework>) -> Vec<&'static RegistryConfig> {
    REGISTRY_CATALOG
        .iter()
        .filter(|config| framework.is_none_or(|value| config.supported_frameworks.contains(&value)))
        .collect()
}

pub fn registry_config(registry_type: RegistryType) -> &'static RegistryConfig {
    REGISTRY_CATALOG
        .iter()
        .find(|config| config.registry_type == registry_type)
        .expect("the static registry catalog contains every RegistryType")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportDecision {
    pub registry: &'static RegistryConfig,
    pub formats: Vec<CredentialFormat>,
    pub sync_interval_hours: u16,
    pub next_sync_at: DateTime<Utc>,
}

pub fn decide_import(
    registry_type: RegistryType,
    requested_formats: Option<Vec<CredentialFormat>>,
    sync_interval_hours: Option<u16>,
    now: DateTime<Utc>,
) -> TrustSyncResult<ImportDecision> {
    let registry = registry_config(registry_type);
    let interval = sync_interval_hours.unwrap_or(registry.sync_interval_hours);
    if !(1..=8760).contains(&interval) {
        return Err(TrustSyncError::new(
            "INVALID_SYNC_INTERVAL",
            "registry sync interval must be between 1 and 8760 hours",
        ));
    }

    let formats = requested_formats.unwrap_or_else(|| registry.supported_formats.to_vec());
    if formats.is_empty() {
        return Err(TrustSyncError::new(
            "MISSING_FORMAT",
            "at least one registry credential format is required",
        ));
    }
    let mut unique = Vec::with_capacity(formats.len());
    for format in formats {
        if !registry.supported_formats.contains(&format) {
            return Err(TrustSyncError::new(
                "UNSUPPORTED_FORMAT",
                "the registry does not support the requested credential format",
            ));
        }
        if !unique.contains(&format) {
            unique.push(format);
        }
    }
    let next_sync_at = now
        .checked_add_signed(chrono::Duration::hours(i64::from(interval)))
        .ok_or_else(|| TrustSyncError::new("TIME_OVERFLOW", "next sync time overflowed"))?;
    Ok(ImportDecision {
        registry,
        formats: unique,
        sync_interval_hours: interval,
        next_sync_at,
    })
}

pub fn validate_registry_url(url: &str) -> TrustSyncResult<String> {
    let parsed = Url::parse(url)
        .map_err(|_| TrustSyncError::new("INVALID_URL", "registry URL is invalid"))?;
    if parsed.scheme() != "https" {
        return Err(TrustSyncError::new(
            "INVALID_URL",
            "registry URL must use HTTPS",
        ));
    }
    if parsed.host().is_none() {
        return Err(TrustSyncError::new(
            "INVALID_URL",
            "registry URL must include a hostname",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(TrustSyncError::new(
            "INVALID_URL",
            "registry URL must not contain credentials",
        ));
    }
    if parsed.port().is_some_and(|port| port != 443) {
        return Err(TrustSyncError::new(
            "INVALID_URL",
            "registry URL must use the standard HTTPS port",
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(TrustSyncError::new(
            "INVALID_URL",
            "registry URL must not contain a query or fragment",
        ));
    }
    Ok(url.to_owned())
}

pub fn parse_private_host_allowlist(configured: &str) -> TrustSyncResult<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for raw in configured.split(',') {
        let host = raw.trim().to_ascii_lowercase();
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            continue;
        }
        if IpAddr::from_str(host).is_ok() {
            return Err(TrustSyncError::new(
                "INVALID_ALLOWLIST",
                "TRUST_REGISTRY_PRIVATE_HOST_ALLOWLIST accepts exact DNS hostnames, not IP addresses",
            ));
        }
        if host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(TrustSyncError::new(
                "INVALID_ALLOWLIST",
                "TRUST_REGISTRY_PRIVATE_HOST_ALLOWLIST contains an invalid DNS hostname",
            ));
        }
        result.insert(host.to_owned());
    }
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DestinationDecision {
    pub hostname: String,
    pub authority: String,
    pub address: String,
}

pub fn validate_destination(
    url: &str,
    addresses: &[String],
    private_host_allowlist: &str,
) -> TrustSyncResult<DestinationDecision> {
    validate_registry_url(url)?;
    let parsed = Url::parse(url)
        .map_err(|_| TrustSyncError::new("INVALID_URL", "registry URL is invalid"))?;
    let hostname = match parsed.host() {
        Some(Host::Domain(host)) => host.trim_end_matches('.').to_ascii_lowercase(),
        Some(Host::Ipv4(address)) => address.to_string(),
        Some(Host::Ipv6(address)) => address.to_string(),
        None => {
            return Err(TrustSyncError::new(
                "INVALID_URL",
                "registry URL must include a hostname",
            ))
        }
    };
    let allowlist = parse_private_host_allowlist(private_host_allowlist)?;
    if addresses.is_empty() {
        return Err(TrustSyncError::new(
            "DNS_EMPTY",
            "registry hostname resolved to no addresses",
        ));
    }
    let mut normalized = BTreeSet::new();
    for raw in addresses {
        let address = raw.parse::<IpAddr>().map_err(|_| {
            TrustSyncError::new("INVALID_ADDRESS", "registry resolved an invalid IP address")
        })?;
        let explicitly_allowed_private = allowlist.contains(&hostname) && is_private(address);
        if !is_global(address) && !explicitly_allowed_private {
            return Err(TrustSyncError::new(
                "NON_PUBLIC_DESTINATION",
                "registry hostname resolves to a non-public network address",
            ));
        }
        normalized.insert(address.to_string());
    }
    let address = normalized
        .into_iter()
        .next()
        .expect("non-empty address set was validated");
    let authority = parsed[url::Position::BeforeHost..url::Position::AfterPort].to_owned();
    Ok(DestinationDecision {
        hostname,
        authority,
        address,
    })
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => value.is_private(),
        IpAddr::V6(value) => (value.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn is_global(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => is_global_v4(value),
        IpAddr::V6(value) => is_global_v6(value),
    }
}

fn is_global_v4(value: Ipv4Addr) -> bool {
    let octets = value.octets();
    !(octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 192 && octets[1] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 224)
}

fn is_global_v6(value: Ipv6Addr) -> bool {
    if value.is_unspecified() || value.is_loopback() || value.is_multicast() {
        return false;
    }
    let first = value.segments()[0];
    if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
        return false;
    }
    let segments = value.segments();
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    (first & 0xe000) == 0x2000
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestPlan {
    pub request_url: String,
    pub host_header: String,
    pub sni_hostname: String,
}

pub fn plan_request(
    url: &str,
    token: Option<&str>,
    address: Option<&str>,
) -> TrustSyncResult<RequestPlan> {
    validate_registry_url(url)?;
    if token.is_some_and(|value| value.is_empty() || value.len() > 2048) {
        return Err(TrustSyncError::new(
            "INVALID_SYNC_TOKEN",
            "registry sync token must contain between 1 and 2048 bytes",
        ));
    }
    let mut parsed = Url::parse(url)
        .map_err(|_| TrustSyncError::new("INVALID_URL", "registry URL is invalid"))?;
    if let Some(value) = token {
        parsed.query_pairs_mut().append_pair("since", value);
    }
    let hostname = parsed
        .host_str()
        .ok_or_else(|| TrustSyncError::new("INVALID_URL", "registry URL must include a hostname"))?
        .to_owned();
    let host_header = parsed[url::Position::BeforeHost..url::Position::AfterPort].to_owned();
    if let Some(raw_address) = address {
        let parsed_address = raw_address.parse::<IpAddr>().map_err(|_| {
            TrustSyncError::new("INVALID_ADDRESS", "registry destination address is invalid")
        })?;
        parsed.set_ip_host(parsed_address).map_err(|_| {
            TrustSyncError::new("INVALID_ADDRESS", "registry destination address is invalid")
        })?;
    }
    Ok(RequestPlan {
        request_url: parsed.to_string(),
        host_header,
        sni_hostname: hostname,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnchorType {
    Csca,
    Dsc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistryOperation {
    Add,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistrySource {
    IcaoPkd,
    Aamva,
    EudiLotl,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    pub entry_id: String,
    pub anchor_type: AnchorType,
    pub operation: RegistryOperation,
    pub country_code: String,
    #[serde(default)]
    pub certificate_pem: Option<String>,
    #[serde(default)]
    pub subject_key_id: Option<String>,
    #[serde(default)]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default)]
    pub not_after: Option<DateTime<Utc>>,
    pub source: RegistrySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryFeed {
    pub sync_token: String,
    pub sequence: u64,
    #[serde(default)]
    pub entries: Vec<RegistryEntry>,
    #[serde(default)]
    pub has_more: bool,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedRegistryEntry {
    pub entry_id: String,
    pub anchor_type: AnchorType,
    pub country_code: String,
    pub certificate_pem: String,
    pub source: RegistrySource,
    #[serde(default)]
    pub subject_key_id: Option<String>,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RegistryImportState {
    #[serde(default)]
    pub sync_token: Option<String>,
    #[serde(default)]
    pub sequence: u64,
    #[serde(default)]
    pub entries: BTreeMap<String, ImportedRegistryEntry>,
    #[serde(default)]
    pub synchronized_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryEvaluation {
    pub complete: bool,
    pub pages: usize,
    pub next_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<RegistryImportState>,
}

pub fn parse_feed_json(raw: &str) -> TrustSyncResult<RegistryFeed> {
    let feed: RegistryFeed = serde_json::from_str(raw).map_err(|_| {
        TrustSyncError::new(
            "INVALID_FEED",
            "registry response violates the sync contract",
        )
    })?;
    validate_feed(&feed)?;
    Ok(feed)
}

pub fn parse_state_json(raw: &str) -> TrustSyncResult<RegistryImportState> {
    let state: RegistryImportState = serde_json::from_str(raw)
        .map_err(|_| TrustSyncError::new("INVALID_STATE", "stored registry state is invalid"))?;
    validate_state_shape(&state)?;
    Ok(state)
}

fn validate_feed(feed: &RegistryFeed) -> TrustSyncResult<()> {
    if feed.sync_token.is_empty() || feed.sync_token.len() > 2048 {
        return Err(TrustSyncError::new(
            "INVALID_SYNC_TOKEN",
            "registry sync token must contain between 1 and 2048 bytes",
        ));
    }
    if feed.entries.len() > MAX_ENTRIES_PER_PAGE {
        return Err(TrustSyncError::new(
            "TOO_MANY_ENTRIES",
            "registry page exceeds the entry limit",
        ));
    }
    for entry in &feed.entries {
        validate_remote_entry_shape(entry)?;
    }
    Ok(())
}

fn validate_remote_entry_shape(entry: &RegistryEntry) -> TrustSyncResult<()> {
    Uuid::parse_str(&entry.entry_id)
        .map_err(|_| TrustSyncError::new("INVALID_ENTRY", "registry entry_id must be a UUID"))?;
    validate_country(&entry.country_code)?;
    if entry
        .subject_key_id
        .as_ref()
        .is_some_and(|value| value.len() > 512)
    {
        return Err(TrustSyncError::new(
            "INVALID_ENTRY",
            "registry subject_key_id exceeds the size limit",
        ));
    }
    match entry.operation {
        RegistryOperation::Add => {
            let pem = entry.certificate_pem.as_ref().ok_or_else(|| {
                TrustSyncError::new(
                    "MISSING_CERTIFICATE",
                    "ADD registry entries require certificate_pem",
                )
            })?;
            if pem.len() > 64 * 1024 {
                return Err(TrustSyncError::new(
                    "CERTIFICATE_TOO_LARGE",
                    "registry certificate exceeds the size limit",
                ));
            }
        }
        RegistryOperation::Remove if entry.certificate_pem.is_some() => {
            return Err(TrustSyncError::new(
                "UNEXPECTED_CERTIFICATE",
                "REMOVE registry entries must not include certificate_pem",
            ));
        }
        RegistryOperation::Remove => {}
    }
    Ok(())
}

fn validate_country(country: &str) -> TrustSyncResult<()> {
    if !(2..=3).contains(&country.len()) || !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(TrustSyncError::new(
            "INVALID_COUNTRY",
            "registry country_code must contain 2 or 3 uppercase ASCII letters",
        ));
    }
    Ok(())
}

fn validate_state_shape(state: &RegistryImportState) -> TrustSyncResult<()> {
    if state
        .sync_token
        .as_ref()
        .is_some_and(|token| token.is_empty() || token.len() > 2048)
    {
        return Err(TrustSyncError::new(
            "INVALID_STATE",
            "stored registry sync token is invalid",
        ));
    }
    for (storage_id, entry) in &state.entries {
        if storage_id != &entry.entry_id || Uuid::parse_str(storage_id).is_err() {
            return Err(TrustSyncError::new(
                "INVALID_STATE",
                "stored registry entry identity is inconsistent",
            ));
        }
        validate_country(&entry.country_code).map_err(|_| {
            TrustSyncError::new("INVALID_STATE", "stored registry entry is invalid")
        })?;
        if entry.certificate_pem.len() > 64 * 1024 {
            return Err(TrustSyncError::new(
                "INVALID_STATE",
                "stored registry entry is invalid",
            ));
        }
    }
    Ok(())
}

pub fn evaluate_pages(
    previous: &RegistryImportState,
    pages: &[RegistryFeed],
    now: DateTime<Utc>,
) -> TrustSyncResult<RegistryEvaluation> {
    validate_state_shape(previous)?;
    if pages.is_empty() {
        return Err(TrustSyncError::new(
            "MISSING_PAGE",
            "registry synchronization requires at least one page",
        ));
    }
    if pages.len() > MAX_PAGES {
        return Err(TrustSyncError::new(
            "PAGE_LIMIT",
            "registry pagination exceeded the page limit",
        ));
    }

    let initial_sync = previous.sync_token.is_none();
    let mut entries = if initial_sync {
        BTreeMap::new()
    } else {
        previous.entries.clone()
    };
    let mut current_sequence = previous.sequence;
    let mut previous_page_token: Option<&str> = None;
    let mut seen = BTreeSet::new();

    for (index, feed) in pages.iter().enumerate() {
        validate_feed(feed)?;
        if index + 1 < pages.len() && !feed.has_more {
            return Err(TrustSyncError::new(
                "UNEXPECTED_PAGE",
                "registry supplied a page after synchronization completed",
            ));
        }
        if feed.sequence < current_sequence {
            return Err(TrustSyncError::new(
                "SEQUENCE_ROLLBACK",
                "registry sequence rollback was rejected",
            ));
        }
        if index == 0
            && !initial_sync
            && !feed.entries.is_empty()
            && feed.sequence == previous.sequence
        {
            return Err(TrustSyncError::new(
                "SEQUENCE_NOT_ADVANCED",
                "registry changes did not advance the sequence",
            ));
        }
        if previous_page_token.is_some_and(|token| token == feed.sync_token) {
            return Err(TrustSyncError::new(
                "REPEATED_TOKEN",
                "registry repeated a pagination token",
            ));
        }

        for remote in &feed.entries {
            if !seen.insert(remote.entry_id.clone()) {
                return Err(TrustSyncError::new(
                    "DUPLICATE_ENTRY",
                    "registry sync contains a duplicate entry",
                ));
            }
            match remote.operation {
                RegistryOperation::Remove => {
                    if initial_sync {
                        return Err(TrustSyncError::new(
                            "INITIAL_REMOVAL",
                            "initial registry sync contains a removal",
                        ));
                    }
                    if entries.remove(&remote.entry_id).is_none() {
                        return Err(TrustSyncError::new(
                            "UNKNOWN_REMOVAL",
                            "registry removed an unknown source entry",
                        ));
                    }
                }
                RegistryOperation::Add => {
                    entries.insert(remote.entry_id.clone(), validate_certificate(remote, now)?);
                }
            }
        }
        current_sequence = feed.sequence;
        previous_page_token = Some(&feed.sync_token);
    }

    let last = pages.last().expect("pages was checked as non-empty");
    if last.has_more {
        if pages.len() == MAX_PAGES {
            return Err(TrustSyncError::new(
                "PAGE_LIMIT",
                "registry pagination exceeded the page limit",
            ));
        }
        return Ok(RegistryEvaluation {
            complete: false,
            pages: pages.len(),
            next_token: last.sync_token.clone(),
            state: None,
        });
    }

    let entries = revalidate_entries(&entries, now)?;
    Ok(RegistryEvaluation {
        complete: true,
        pages: pages.len(),
        next_token: last.sync_token.clone(),
        state: Some(RegistryImportState {
            sync_token: Some(last.sync_token.clone()),
            sequence: current_sequence,
            entries,
            synchronized_at: Some(now),
        }),
    })
}

pub fn revalidate_entries(
    entries: &BTreeMap<String, ImportedRegistryEntry>,
    now: DateTime<Utc>,
) -> TrustSyncResult<BTreeMap<String, ImportedRegistryEntry>> {
    let mut validated = BTreeMap::new();
    for (storage_id, imported) in entries {
        if storage_id != &imported.entry_id {
            return Err(TrustSyncError::new(
                "INVALID_STATE",
                "stored registry entry identity is inconsistent",
            ));
        }
        let candidate = RegistryEntry {
            entry_id: imported.entry_id.clone(),
            anchor_type: imported.anchor_type,
            operation: RegistryOperation::Add,
            country_code: imported.country_code.clone(),
            certificate_pem: Some(imported.certificate_pem.clone()),
            subject_key_id: imported.subject_key_id.clone(),
            not_before: parse_optional_time(imported.not_before.as_deref())?,
            not_after: parse_optional_time(imported.not_after.as_deref())?,
            source: imported.source,
        };
        validate_remote_entry_shape(&candidate).map_err(|_| {
            TrustSyncError::new("INVALID_STATE", "stored registry entry is invalid")
        })?;
        validated.insert(storage_id.clone(), validate_certificate(&candidate, now)?);
    }
    Ok(validated)
}

fn parse_optional_time(value: Option<&str>) -> TrustSyncResult<Option<DateTime<Utc>>> {
    value
        .map(|raw| {
            DateTime::parse_from_rfc3339(raw)
                .map(|time| time.with_timezone(&Utc))
                .map_err(|_| {
                    TrustSyncError::new("INVALID_STATE", "stored registry entry is invalid")
                })
        })
        .transpose()
}

fn validate_certificate(
    entry: &RegistryEntry,
    now: DateTime<Utc>,
) -> TrustSyncResult<ImportedRegistryEntry> {
    let pem = entry
        .certificate_pem
        .as_ref()
        .expect("ADD entry shape validation guarantees certificate material");
    let der = marty_crypto::certificate::load_certificate_pem(pem).map_err(|_| {
        TrustSyncError::new(
            "INVALID_CERTIFICATE",
            "registry entry contains an invalid certificate",
        )
    })?;
    let info = marty_crypto::certificate::get_certificate_info(&der).map_err(|_| {
        TrustSyncError::new(
            "INVALID_CERTIFICATE",
            "registry entry contains an invalid certificate",
        )
    })?;
    let not_before = DateTime::parse_from_rfc3339(&info.not_before)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| {
            TrustSyncError::new("INVALID_CERTIFICATE", "certificate validity is invalid")
        })?;
    let not_after = DateTime::parse_from_rfc3339(&info.not_after)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| {
            TrustSyncError::new("INVALID_CERTIFICATE", "certificate validity is invalid")
        })?;
    if now < not_before || now >= not_after {
        return Err(TrustSyncError::new(
            "CERTIFICATE_NOT_CURRENT",
            "registry entry certificate is not currently valid",
        ));
    }
    if entry
        .not_before
        .is_some_and(|expected| (expected - not_before).num_milliseconds().abs() > 1_000)
    {
        return Err(TrustSyncError::new(
            "CERTIFICATE_TIME_MISMATCH",
            "registry entry not_before does not match its certificate",
        ));
    }
    if entry
        .not_after
        .is_some_and(|expected| (expected - not_after).num_milliseconds().abs() > 1_000)
    {
        return Err(TrustSyncError::new(
            "CERTIFICATE_TIME_MISMATCH",
            "registry entry not_after does not match its certificate",
        ));
    }
    let has_key_cert_sign = info.key_usage.iter().any(|usage| usage == "keyCertSign");
    let has_digital_signature = info
        .key_usage
        .iter()
        .any(|usage| usage == "digitalSignature");
    match entry.anchor_type {
        AnchorType::Csca if !info.is_ca || !has_key_cert_sign => {
            return Err(TrustSyncError::new(
                "INVALID_CSCA_PROFILE",
                "CSCA entry is not a certificate-signing CA",
            ));
        }
        AnchorType::Dsc if info.is_ca || !has_digital_signature => {
            return Err(TrustSyncError::new(
                "INVALID_DSC_PROFILE",
                "DSC entry is not a document-signing certificate",
            ));
        }
        _ => {}
    }

    Ok(ImportedRegistryEntry {
        entry_id: entry.entry_id.clone(),
        anchor_type: entry.anchor_type,
        country_code: entry.country_code.clone(),
        certificate_pem: pem.clone(),
        source: entry.source,
        subject_key_id: entry.subject_key_id.clone(),
        not_before: Some(not_before.to_rfc3339()),
        not_after: Some(not_after.to_rfc3339()),
    })
}

fn parse_named<T>(value: &str, field: &'static str) -> TrustSyncResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(|_| {
        TrustSyncError::new(
            "INVALID_ENUM",
            format!("unsupported trust-registry {field}: {value}"),
        )
    })
}

fn to_json<T: Serialize>(value: &T) -> TrustSyncResult<String> {
    serde_json::to_string(value).map_err(|_| {
        TrustSyncError::new(
            "SERIALIZATION_FAILURE",
            "trust-registry result could not be serialized",
        )
    })
}

/// Return the canonical registry catalog as JSON.
pub fn registry_catalog_json(framework: Option<&str>) -> TrustSyncResult<String> {
    let framework = framework
        .map(|value| parse_named::<TrustFramework>(value, "framework"))
        .transpose()?;
    to_json(&registry_catalog(framework))
}

/// Validate an import request and return its canonical scheduling decision.
pub fn import_decision_json(
    registry_type: &str,
    requested_formats_json: Option<&str>,
    sync_interval_hours: Option<u16>,
    now_rfc3339: &str,
) -> TrustSyncResult<String> {
    let registry_type = parse_named(registry_type, "registry type")?;
    let requested_formats = requested_formats_json
        .map(|raw| {
            serde_json::from_str::<Vec<CredentialFormat>>(raw).map_err(|_| {
                TrustSyncError::new(
                    "INVALID_FORMAT",
                    "requested registry formats must be a JSON array of supported format names",
                )
            })
        })
        .transpose()?;
    let now = DateTime::parse_from_rfc3339(now_rfc3339)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| {
            TrustSyncError::new(
                "INVALID_TIME",
                "registry scheduling time must be RFC 3339 with an offset",
            )
        })?;
    to_json(&decide_import(
        registry_type,
        requested_formats,
        sync_interval_hours,
        now,
    )?)
}

/// Validate resolved destination addresses and return the pinned destination.
pub fn destination_decision_json(
    url: &str,
    addresses_json: &str,
    private_host_allowlist: &str,
) -> TrustSyncResult<String> {
    let addresses: Vec<String> = serde_json::from_str(addresses_json).map_err(|_| {
        TrustSyncError::new(
            "INVALID_ADDRESS",
            "resolved registry addresses must be a JSON array of IP address strings",
        )
    })?;
    to_json(&validate_destination(
        url,
        &addresses,
        private_host_allowlist,
    )?)
}

/// Return the HTTPS request URL, original Host header, and SNI hostname.
pub fn request_plan_json(
    url: &str,
    token: Option<&str>,
    address: Option<&str>,
) -> TrustSyncResult<String> {
    to_json(&plan_request(url, token, address)?)
}

/// Parse a remote feed with the strict native schema and normalize it as JSON.
pub fn validate_feed_json(raw: &str) -> TrustSyncResult<String> {
    to_json(&parse_feed_json(raw)?)
}

/// Parse persisted state with the strict native schema and normalize it.
pub fn validate_state_json(raw: &str) -> TrustSyncResult<String> {
    to_json(&parse_state_json(raw)?)
}

/// Evaluate all fetched pages against the previous state without mutating it.
pub fn evaluate_pages_json(
    previous_state_json: &str,
    pages_json: &str,
    now_rfc3339: &str,
) -> TrustSyncResult<String> {
    let previous = parse_state_json(previous_state_json)?;
    let raw_pages: Vec<serde_json::Value> = serde_json::from_str(pages_json).map_err(|_| {
        TrustSyncError::new(
            "INVALID_FEED",
            "registry pages must be a JSON array of sync feeds",
        )
    })?;
    let pages = raw_pages
        .iter()
        .map(|page| parse_feed_json(&page.to_string()))
        .collect::<TrustSyncResult<Vec<_>>>()?;
    let now = DateTime::parse_from_rfc3339(now_rfc3339)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| {
            TrustSyncError::new(
                "INVALID_TIME",
                "registry synchronization time must be RFC 3339 with an offset",
            )
        })?;
    to_json(&evaluate_pages(&previous, &pages, now)?)
}

/// Revalidate every persisted certificate before it can influence trust.
pub fn revalidate_state_json(state_json: &str, now_rfc3339: &str) -> TrustSyncResult<String> {
    let mut state = parse_state_json(state_json)?;
    let now = DateTime::parse_from_rfc3339(now_rfc3339)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| {
            TrustSyncError::new(
                "INVALID_TIME",
                "registry validation time must be RFC 3339 with an offset",
            )
        })?;
    state.entries = revalidate_entries(&state.entries, now)?;
    to_json(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    const NOW: &str = "2026-08-07T12:00:00Z";
    const ENTRY_ID: &str = "c6d7e8f9-a0b1-4234-9678-901234abcdef";

    fn now() -> DateTime<Utc> {
        NOW.parse().unwrap()
    }

    fn certificate(ca: bool) -> String {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.not_before = time::OffsetDateTime::from_unix_timestamp(1_754_000_000).unwrap();
        params.not_after = time::OffsetDateTime::from_unix_timestamp(1_817_000_000).unwrap();
        params.is_ca = if ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::ExplicitNoCa
        };
        params.key_usages = if ca {
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]
        } else {
            vec![KeyUsagePurpose::DigitalSignature]
        };
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    fn add_feed(ca: bool) -> RegistryFeed {
        RegistryFeed {
            sync_token: "1".to_owned(),
            sequence: 1,
            entries: vec![RegistryEntry {
                entry_id: ENTRY_ID.to_owned(),
                anchor_type: if ca {
                    AnchorType::Csca
                } else {
                    AnchorType::Dsc
                },
                operation: RegistryOperation::Add,
                country_code: "US".to_owned(),
                certificate_pem: Some(certificate(ca)),
                subject_key_id: None,
                not_before: None,
                not_after: None,
                source: RegistrySource::Manual,
            }],
            has_more: false,
            generated_at: now(),
        }
    }

    #[test]
    fn catalog_and_import_decisions_are_canonical() {
        assert_eq!(registry_catalog(Some(TrustFramework::Icao)).len(), 1);
        let decision = decide_import(RegistryType::Aamva, None, Some(12), now()).unwrap();
        assert_eq!(decision.formats, AAMVA_FORMATS);
        assert_eq!(decision.next_sync_at, now() + chrono::Duration::hours(12));
    }

    #[test]
    fn unsafe_urls_and_destinations_fail_closed() {
        assert!(validate_registry_url("http://registry.example/sync").is_err());
        assert!(validate_destination(
            "https://registry.example/sync",
            &["127.0.0.1".to_owned()],
            ""
        )
        .is_err());
        assert!(validate_destination(
            "https://registry.example/sync",
            &["10.0.0.8".to_owned()],
            "registry.example"
        )
        .is_ok());
    }

    #[test]
    fn initial_sync_validates_certificate_profile() {
        let result =
            evaluate_pages(&RegistryImportState::default(), &[add_feed(true)], now()).unwrap();
        assert!(result.complete);
        assert_eq!(result.state.unwrap().entries.len(), 1);

        let mut wrong = add_feed(false);
        wrong.entries[0].anchor_type = AnchorType::Csca;
        assert_eq!(
            evaluate_pages(&RegistryImportState::default(), &[wrong], now())
                .unwrap_err()
                .code(),
            "INVALID_CSCA_PROFILE"
        );
    }

    #[test]
    fn delta_removal_and_rollback_are_atomic() {
        let initial = evaluate_pages(&RegistryImportState::default(), &[add_feed(true)], now())
            .unwrap()
            .state
            .unwrap();
        let removal = RegistryFeed {
            sync_token: "2".to_owned(),
            sequence: 2,
            entries: vec![RegistryEntry {
                entry_id: ENTRY_ID.to_owned(),
                anchor_type: AnchorType::Csca,
                operation: RegistryOperation::Remove,
                country_code: "US".to_owned(),
                certificate_pem: None,
                subject_key_id: None,
                not_before: None,
                not_after: None,
                source: RegistrySource::Manual,
            }],
            has_more: false,
            generated_at: now(),
        };
        let result = evaluate_pages(&initial, &[removal], now()).unwrap();
        assert!(result.state.unwrap().entries.is_empty());

        let rollback = RegistryFeed {
            sync_token: "old".to_owned(),
            sequence: 0,
            entries: Vec::new(),
            has_more: false,
            generated_at: now(),
        };
        assert_eq!(
            evaluate_pages(&initial, &[rollback], now())
                .unwrap_err()
                .code(),
            "SEQUENCE_ROLLBACK"
        );
        assert_eq!(initial.entries.len(), 1);
    }
}
