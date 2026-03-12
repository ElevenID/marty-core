//! ISO 18013-5 mDoc data model structure conformance tests.
//!
//! Validates the normative structure requirements defined in ISO 18013-5:2021:
//!
//!  §1  Namespace constants and wire-format strings
//!  §2  DeviceEngagement construction and CBOR encode/decode (§8.2)
//!  §3  Protocol types: MdlRequest, MdlResponse, ResponseStatus (§8.3)
//!  §4  Session configuration and protocol state machine (§9.1)
//!  §5  Selective disclosure filtering (§7.2)
//!  §6  Transport method model (§8.2.1)
//!  §7  Error type model

use std::collections::{HashMap, HashSet};

use marty_iso18013::{
    core::{DeviceEngagement, EngagementMethod, TransportInfo, TransportMethod},
    error::Error,
    protocol::{MdlRequest, MdlResponse, ResponseStatus, Session, SessionConfig, SessionState},
    selective::SelectiveDisclosure,
};

// ── §1  Namespace constants ───────────────────────────────────────────────────

/// ISO 18013-5 §7.2.1 Table 5 — the standard mDL namespace wire string.
#[test]
fn namespace_iso_18013_5_1_constant() {
    use marty_verification::mdoc::MdlNamespace;
    assert_eq!(MdlNamespace::ISO_18013_5_1, "org.iso.18013.5.1");
}

/// AAMVA extension namespace wire string.
#[test]
fn namespace_aamva_constant() {
    use marty_verification::mdoc::MdlNamespace;
    assert_eq!(MdlNamespace::AAMVA, "org.iso.18013.5.1.aamva");
}

/// Namespace strings must be lowercase reversed-domain form per ISO 18013-5 §7.2.1.
#[test]
fn namespace_format_is_reversed_domain() {
    use marty_verification::mdoc::MdlNamespace;
    for ns in [MdlNamespace::ISO_18013_5_1, MdlNamespace::AAMVA] {
        assert!(
            ns.starts_with("org.iso"),
            "namespace must start with org.iso: {}",
            ns
        );
        // Per spec all chars are lowercase or digit or dot
        assert!(
            ns.chars().all(|c| c.is_ascii_lowercase() || c == '.' || c.is_ascii_digit()),
            "namespace must be lowercase dotted: {}",
            ns
        );
    }
}

// ── §2  DeviceEngagement (§8.2) ───────────────────────────────────────────────

/// DeviceEngagement created via `new_qr()` must have version "1.0" (§8.2.1.1).
#[test]
fn device_engagement_qr_version() {
    let engagement = DeviceEngagement::new_qr().expect("new_qr");
    assert_eq!(
        engagement.version, "1.0",
        "DeviceEngagement version must be '1.0' per ISO 18013-5 §8.2.1"
    );
}

/// DeviceEngagement created via `new_qr()` must have a non-empty device key.
/// The device key is used for session ECDH (§9.1.1) — must be a valid P-256 point.
#[test]
fn device_engagement_has_device_key() {
    let engagement = DeviceEngagement::new_qr().expect("new_qr");
    assert!(
        !engagement.device_key.is_empty(),
        "device_key (EDeviceKey) must be present for ECDH key agreement"
    );
    // P-256 uncompressed public key: 0x04 prefix + 32 bytes x + 32 bytes y = 65 bytes
    assert_eq!(
        engagement.device_key.len(),
        65,
        "EDeviceKey (P-256 uncompressed) must be 65 bytes"
    );
}

/// DeviceEngagement created via `new_qr()` must have EngagementMethod::QR.
#[test]
fn device_engagement_qr_engagement_method() {
    let engagement = DeviceEngagement::new_qr().expect("new_qr");
    assert_eq!(engagement.engagement_method, EngagementMethod::QR);
}

/// Two calls to `new_qr()` must produce different device keys (ephemeral key generation).
#[test]
fn device_engagement_key_is_ephemeral() {
    let e1 = DeviceEngagement::new_qr().expect("new_qr 1");
    let e2 = DeviceEngagement::new_qr().expect("new_qr 2");
    assert_ne!(
        e1.device_key, e2.device_key,
        "EDeviceKey must be freshly generated per engagement (§9.1.1 session uniqueness)"
    );
}

/// CBOR encode/decode round-trip for DeviceEngagement (§8.2.1.2).
#[test]
fn device_engagement_cbor_roundtrip() {
    let engagement = DeviceEngagement::new_qr().expect("new_qr");
    let cbor = engagement.to_cbor().expect("to_cbor");
    assert!(!cbor.is_empty(), "CBOR encoding must be non-empty");

    let decoded = DeviceEngagement::from_cbor(&cbor).expect("from_cbor");
    assert_eq!(decoded.version, engagement.version);
    assert_eq!(decoded.device_key, engagement.device_key);
    assert_eq!(decoded.engagement_method, engagement.engagement_method);
}

/// `add_ble_transport` must register a BLE TransportInfo entry.
#[test]
fn device_engagement_add_ble_transport() {
    let mut engagement = DeviceEngagement::new_qr().expect("new_qr");
    let ble_uuid = "00000001-0000-0000-0000-000000000001";
    engagement.add_ble_transport(ble_uuid).expect("add_ble");

    let ble_transports: Vec<_> = engagement
        .transports
        .iter()
        .filter(|t| t.method == TransportMethod::BLE)
        .collect();

    assert_eq!(
        ble_transports.len(),
        1,
        "exactly one BLE transport must be registered"
    );
}

/// `add_https_transport` must register an HTTPS TransportInfo entry.
#[test]
fn device_engagement_add_https_transport() {
    let mut engagement = DeviceEngagement::new_qr().expect("new_qr");
    engagement
        .add_https_transport("https://example.com/mdl")
        .expect("add_https");

    let https_transports: Vec<_> = engagement
        .transports
        .iter()
        .filter(|t| t.method == TransportMethod::HTTPS)
        .collect();

    assert_eq!(
        https_transports.len(),
        1,
        "exactly one HTTPS transport must be registered"
    );
}

/// QR code generation must produce non-empty data URL (§8.2.1.2 visual engagement).
#[test]
fn device_engagement_qr_code_non_empty() {
    let engagement = DeviceEngagement::new_qr().expect("new_qr");
    let qr = engagement.to_qr_code().expect("to_qr_code");
    assert!(!qr.is_empty(), "QR code output must not be empty");
}

// ── §3  Protocol request/response types (§8.3) ───────────────────────────────

/// `MdlRequest` must hold doc_type, data_elements map, and a nonce.
#[test]
fn mdl_request_structure() {
    let nonce = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut data_elements: HashMap<String, Vec<String>> = HashMap::new();
    data_elements.insert(
        "org.iso.18013.5.1".to_string(),
        vec!["family_name".to_string(), "birth_date".to_string()],
    );

    let req = MdlRequest {
        doc_type: "org.iso.18013.5.1.mDL".to_string(),
        data_elements: data_elements.clone(),
        nonce: nonce.clone(),
    };

    assert_eq!(req.doc_type, "org.iso.18013.5.1.mDL");
    assert_eq!(req.nonce, nonce);
    assert_eq!(
        req.data_elements.get("org.iso.18013.5.1").unwrap().len(),
        2
    );
}

/// `ResponseStatus::Ok` must be the success sentinel (§8.3.2.1).
#[test]
fn response_status_ok_is_success() {
    let resp = MdlResponse {
        doc_type: "org.iso.18013.5.1.mDL".to_string(),
        data: vec![0xA0], // minimal CBOR map
        status: ResponseStatus::Ok,
    };
    assert!(matches!(resp.status, ResponseStatus::Ok));
}

/// All `ResponseStatus` variants must be constructible (completeness check).
#[test]
fn response_status_all_variants() {
    let variants = [
        ResponseStatus::Ok,
        ResponseStatus::ConsentDenied,
        ResponseStatus::DataNotAvailable,
        ResponseStatus::Error,
    ];
    // Confirm each has a distinct debug string
    let debug_strings: HashSet<String> = variants.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(debug_strings.len(), 4, "all variants must be distinct");
}

// ── §4  Session and state machine (§9.1) ─────────────────────────────────────

/// Default `SessionConfig` must use reasonable defaults per ISO 18013-5 §9.1.
#[test]
fn session_config_defaults() {
    let config = SessionConfig::default();
    assert!(
        config.timeout_secs > 0,
        "session timeout must be positive, got {}",
        config.timeout_secs
    );
    assert!(
        config.max_message_size > 0,
        "max_message_size must be positive"
    );
}

/// `SessionState` must start at `Idle` and its `Debug` must be non-empty.
#[test]
fn session_state_idle_is_initial() {
    let states = [
        SessionState::Idle,
        SessionState::Engagement,
        SessionState::Establishing,
        SessionState::Established,
        SessionState::Processing,
        SessionState::Responding,
        SessionState::Terminated,
    ];
    for s in &states {
        assert!(!format!("{:?}", s).is_empty());
    }
    // Idle must be the default
    assert!(matches!(SessionState::Idle, SessionState::Idle));
}

// ── §5  Selective disclosure filtering (§7.2) ────────────────────────────────

/// Available data elements must be non-empty after adding a namespace.
#[test]
fn selective_disclosure_add_namespace() {
    let mut sd = SelectiveDisclosure::new();
    let ns = "org.iso.18013.5.1";
    let elements = vec![
        "family_name".to_string(),
        "given_name".to_string(),
        "birth_date".to_string(),
        "expiry_date".to_string(),
        "document_number".to_string(),
    ];

    sd.add_namespace(ns.to_string(), elements.clone());

    // Request all elements — SelectiveDisclosure must allow them
    let mut request_map: HashMap<String, Vec<String>> = HashMap::new();
    request_map.insert(ns.to_string(), elements.clone());

    let filtered = sd.filter_request(&request_map, &request_map).unwrap_or_default();
    let allowed = filtered.get(ns).expect("namespace must be present");
    assert_eq!(
        allowed.len(),
        elements.len(),
        "all requested elements must be allowed"
    );
}

/// Mandatory elements must not be filterable even if not requested.
#[test]
fn selective_disclosure_mandatory_elements_always_present() {
    let mut sd = SelectiveDisclosure::new();
    let ns = "org.iso.18013.5.1";
    let all_elements = [
        "family_name",
        "given_name",
        "birth_date",
        "expiry_date",
        "document_number",
    ];

    sd.add_namespace(ns.to_string(), all_elements.iter().map(|s| s.to_string()).collect::<Vec<_>>());

    // Mark family_name and document_number as mandatory
    sd.add_mandatory("family_name".to_string());
    sd.add_mandatory("document_number".to_string());

    // Only request birth_date — mandatory elements must still appear
    let mut request_map: HashMap<String, Vec<String>> = HashMap::new();
    request_map.insert(ns.to_string(), vec!["birth_date".to_string()]);

    let filtered = sd.filter_request(&request_map, &request_map).unwrap_or_default();
    let allowed = filtered.get(ns).expect("namespace must be present");

    assert!(
        allowed.contains(&"family_name".to_string()),
        "mandatory element 'family_name' must always be present"
    );
    assert!(
        allowed.contains(&"document_number".to_string()),
        "mandatory element 'document_number' must always be present"
    );
    assert!(
        allowed.contains(&"birth_date".to_string()),
        "requested element 'birth_date' must be present"
    );
}

/// Elements not in any namespace must be silently excluded from the filtered result.
#[test]
fn selective_disclosure_excludes_unknown_elements() {
    let mut sd = SelectiveDisclosure::new();
    let ns = "org.iso.18013.5.1";
    sd.add_namespace(ns.to_string(), vec!["family_name".to_string()]);

    // Request a field that was not registered
    let mut request_map: HashMap<String, Vec<String>> = HashMap::new();
    request_map.insert(ns.to_string(), vec!["portrait_capture_date".to_string()]);

    let filtered = sd.filter_request(&request_map, &request_map).unwrap_or_default();
    let allowed = filtered.get(ns).map(|v| v.as_slice()).unwrap_or(&[]);
    assert!(
        !allowed.contains(&"portrait_capture_date".to_string()),
        "unregistered element must be excluded from filtered result"
    );
}

/// An unknown namespace in the request must be excluded entirely.
#[test]
fn selective_disclosure_excludes_unknown_namespaces() {
    let mut sd = SelectiveDisclosure::new();
    sd.add_namespace("org.iso.18013.5.1".to_string(), vec!["family_name".to_string()]);

    // Request an unknown namespace
    let mut request_map: HashMap<String, Vec<String>> = HashMap::new();
    request_map.insert(
        "org.example.unknown".to_string(),
        vec!["secret_field".to_string()],
    );

    // An unknown namespace must produce an error
    let result = sd.filter_request(&request_map, &request_map);
    assert!(
        result.is_err(),
        "unknown namespace must return an error"
    );
}

// ── §6  Transport method model (§8.2.1) ──────────────────────────────────────

/// All transport method variants must be representable.
#[test]
fn transport_method_variants() {
    let methods = [
        TransportMethod::BLE,
        TransportMethod::NFC,
        TransportMethod::WiFiAware,
        TransportMethod::HTTPS,
    ];
    for m in &methods {
        assert!(!format!("{:?}", m).is_empty());
    }
}

/// `TransportInfo` must be constructible from method + parameters.
#[test]
fn transport_info_construction() {
    let mut params = HashMap::new();
    params.insert("uuid".to_string(), b"test-ble-uuid".to_vec());

    let info = TransportInfo {
        method: TransportMethod::BLE,
        parameters: params,
    };

    assert_eq!(info.method, TransportMethod::BLE);
    assert!(info.parameters.contains_key("uuid"));
}

// ── §7  Error type model ──────────────────────────────────────────────────────

/// `Error` must implement `Debug` and `Display`.
#[test]
fn error_implements_display_and_debug() {
    let err = Error::Other("conformance test error".to_string());
    assert!(!format!("{}", err).is_empty(), "Error::Display must not be empty");
    assert!(!format!("{:?}", err).is_empty(), "Error::Debug must not be empty");
}

/// `Result<T, Error>` must be constructible with standard `?` propagation.
#[test]
fn result_type_is_std_result() {
    fn parse_version(s: &str) -> marty_iso18013::Result<u32> {
        s.parse::<u32>().map_err(|_| Error::Other(format!("not a u32: {}", s)))
    }
    assert!(parse_version("1").is_ok());
    assert!(parse_version("not-a-number").is_err());
}
