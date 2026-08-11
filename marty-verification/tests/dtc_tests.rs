use chrono::{Duration, Utc};
use marty_verification::dtc::{
    assemble_dtc_signature_json, create_dtc_json, prepare_dtc_signing_json, sign_dtc_json,
    verify_dtc_json, verify_dtc_json_with_status, ArtifactProvenance, AuthenticatedDtcStatus,
    DtcCurrentStatus, StatusAuthorityProvenance,
};

const SIGNING_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiNW7Kf1E+H1DeG4s
2D38+6hJbAnf4fy5s6RJFuMAcMWhRANCAAQsKlSJSUKItZlFvKAJnjZob3Q6r98t
fYIH6foa373wsHSHktdpDZmb7fe0E3MFc3TvrWlCg/nPMlQNMU41xr4M
-----END PRIVATE KEY-----"#;

const SIGNER_PUBLIC_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELCpUiUlCiLWZRbygCZ42aG90Oq/f
LX2CB+n6Gt+98LB0h5LXaQ2Zm+33tBNzBXN0761pQoP5zzJUDTFONca+DA==
-----END PUBLIC KEY-----"#;

const DTC_SIGNER_EKU_OID: &str = "2.23.136.1.1.12.1";

fn add_test_trust_material(
    verify_env: &mut serde_json::Value,
    signing_key_pem: &str,
    dtc_signer_eku: Option<(&str, bool)>,
) {
    use const_oid::ObjectIdentifier;
    use der::Encode;
    use rcgen::{BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, KeyPair};
    use x509_cert::ext::pkix::ExtendedKeyUsage;

    let signer_key = KeyPair::from_pem(signing_key_pem).expect("failed to parse signer key");
    let signer_public_pem = signer_key.public_key_pem();

    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "DTC Test CSCA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("failed to generate CSCA key");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("failed to generate CSCA certificate");
    let ca_pem = ca_cert.pem();

    let mut signer_params = CertificateParams::default();
    signer_params
        .distinguished_name
        .push(DnType::CommonName, "DTC Test Signer");
    signer_params.is_ca = IsCa::NoCa;
    if let Some((oid, critical)) = dtc_signer_eku {
        let eku = ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(oid)]);
        let mut extension = CustomExtension::from_oid_content(
            &[2, 5, 29, 37],
            eku.to_der().expect("failed to encode DTC Signer EKU"),
        );
        extension.set_criticality(critical);
        signer_params.custom_extensions.push(extension);
    }
    let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let signer_cert = signer_params
        .signed_by(&signer_key, &ca_issuer)
        .expect("failed to generate DTC Signer certificate");

    let object = verify_env
        .as_object_mut()
        .expect("DTC verification envelope must be an object");
    object.insert(
        "signer_public_key_pem".to_string(),
        signer_public_pem.into(),
    );
    object.insert("trust_anchors_pem".to_string(), serde_json::json!([ca_pem]));
    object.insert(
        "certificate_chain_pem".to_string(),
        serde_json::json!([signer_cert.pem()]),
    );
}

fn sample_create_request() -> String {
    serde_json::json!({
        "passport_number": "P1234567",
        "issuing_authority": "USA",
        "issue_date": "2024-01-01",
        "expiry_date": "2030-01-01",
        "personal_details": {
            "first_name": "JOHN",
            "last_name": "DOE",
            "date_of_birth": "1990-01-01",
            "gender": "M",
            "nationality": "USA",
            "portrait": "cG9ydHJhaXQ=", // "portrait"
            "signature": "c2lnbmF0dXJl" // "signature"
        },
        "data_groups": [
            {"dg_number": 1, "data": "ZGcx", "data_type": "MRZ"} // "dg1"
        ],
        "dtc_type": 4, // TYPE1
        "type1_profile": {
            "mrz_line1": "P<USADOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<",
            "mrz_line2": "1234567890USA8504031M3504027<<<<<<<6",
            "sod_hash": "",
            "issuing_state": "USA",
            "passive_auth_ok": true
        }
    })
    .to_string()
}

fn status_authority_provenance() -> StatusAuthorityProvenance {
    let artifact = |id: &str, byte: char| {
        ArtifactProvenance::new(id, "1", format!("sha256:{}", byte.to_string().repeat(64)))
            .expect("valid status provenance")
    };
    StatusAuthorityProvenance::new(
        artifact("dtc-status-trust-profile", 'a'),
        artifact("dtc-status-resolver", 'b'),
        artifact("marty-verification", 'c'),
    )
}

fn signed_verification_envelope(request: &str) -> serde_json::Value {
    let created = create_dtc_json(request).expect("create failed");
    let mut signing_envelope = serde_json::from_str::<serde_json::Value>(&created).unwrap();
    let object = signing_envelope.as_object_mut().unwrap();
    object.insert("signing_key_pem".to_string(), SIGNING_KEY_PEM.into());
    object.insert("signer_id".to_string(), "rust-dtc".into());
    let signed = sign_dtc_json(&signing_envelope.to_string()).expect("sign failed");
    let mut verify_envelope = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    add_test_trust_material(
        &mut verify_envelope,
        SIGNING_KEY_PEM,
        Some((DTC_SIGNER_EKU_OID, true)),
    );
    verify_envelope
}

fn current_status(
    envelope: &serde_json::Value,
    status: DtcCurrentStatus,
    checked_at: chrono::DateTime<Utc>,
    fresh_until: chrono::DateTime<Utc>,
) -> AuthenticatedDtcStatus {
    AuthenticatedDtcStatus::new(
        envelope["dtc_id"].as_str().expect("DTC ID"),
        envelope["passport_number"].as_str().map(str::to_string),
        status,
        checked_at,
        fresh_until,
        "urn:marty:test:dtc-lifecycle-status",
        status_authority_provenance(),
    )
    .expect("valid current status context")
}

fn revocation_check(value: &serde_json::Value) -> &serde_json::Value {
    value["verification_results"]
        .as_array()
        .and_then(|checks| {
            checks.iter().find(|check| {
                check.get("check_name").and_then(|name| name.as_str()) == Some("RevocationStatus")
            })
        })
        .expect("RevocationStatus check")
}

#[test]
fn create_normalizes_and_fills_sod_hash() {
    let req = sample_create_request();
    let created = create_dtc_json(&req).expect("create failed");
    let v: serde_json::Value = serde_json::from_str(&created).unwrap();
    let t1 = v
        .get("type1_profile")
        .and_then(|p| p.get("sod_hash"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    assert!(!t1.is_empty(), "expected sod_hash to be filled");
}

#[test]
fn external_signer_round_trip_uses_canonical_rust_payload() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;

    let created = create_dtc_json(&sample_create_request()).expect("create failed");
    let prepared = prepare_dtc_signing_json(&created).expect("prepare failed");
    let prepared: serde_json::Value = serde_json::from_str(&prepared).unwrap();
    assert_eq!(prepared["signature_encoding"], "DER_BASE64");
    assert_eq!(
        prepared["supported_algorithms"],
        serde_json::json!(["ES256", "ES384"])
    );

    let signing_input = STANDARD
        .decode(prepared["signing_input_base64"].as_str().unwrap())
        .unwrap();
    let signing_key = SigningKey::from_pkcs8_pem(SIGNING_KEY_PEM).unwrap();
    let signature: Signature = signing_key.sign(&signing_input);
    let assembled = assemble_dtc_signature_json(
        &serde_json::json!({
            "dtc": prepared["dtc"],
            "signature_base64": STANDARD.encode(signature.to_der().as_bytes()),
            "signer_id": "external-test-signer",
            "signer_public_key_pem": format!("{SIGNER_PUBLIC_PEM}\n"),
            "signature_date": "2026-08-11T00:00:00Z"
        })
        .to_string(),
    )
    .expect("assemble failed");
    let assembled: serde_json::Value = serde_json::from_str(&assembled).unwrap();

    assert_eq!(assembled["is_signed"], true);
    assert_eq!(assembled["signature_info"]["is_valid"], true);
    assert_eq!(
        assembled["signature_info"]["signer_id"],
        "external-test-signer"
    );
    assert_eq!(
        assembled["signature_info"]["signer_public_key_pem"],
        SIGNER_PUBLIC_PEM
    );
}

#[test]
fn external_signer_output_fails_closed_when_payload_or_signature_is_invalid() {
    let created = create_dtc_json(&sample_create_request()).expect("create failed");
    let prepared = prepare_dtc_signing_json(&created).expect("prepare failed");
    let mut prepared: serde_json::Value = serde_json::from_str(&prepared).unwrap();
    prepared["dtc"]["passport_number"] = "TAMPERED".into();

    let invalid = serde_json::json!({
        "dtc": prepared["dtc"],
        "signature_base64": "AA==",
        "signer_id": "external-test-signer",
        "signer_public_key_pem": SIGNER_PUBLIC_PEM
    });
    assert!(assemble_dtc_signature_json(&invalid.to_string()).is_err());

    let missing_key = serde_json::json!({
        "dtc": prepared["dtc"],
        "signature_base64": "AA==",
        "signer_id": "external-test-signer"
    });
    assert!(assemble_dtc_signature_json(&missing_key.to_string()).is_err());
}

#[test]
fn verify_rejects_signature_without_governed_trust_material() {
    let req = sample_create_request();
    let created = create_dtc_json(&req).expect("create failed");
    let with_key = serde_json::json!({
        "signing_key_pem": SIGNING_KEY_PEM,
        "signer_id": "rust-dtc",
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(
        serde_json::from_str::<serde_json::Value>(&created).unwrap(),
        |mut acc, (k, v)| {
            if let Some(obj) = acc.as_object_mut() {
                obj.insert(k.clone(), v.clone());
            }
            acc
        },
    );
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let verify_env = serde_json::json!({
        "signer_public_key_pem": SIGNER_PUBLIC_PEM
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(
        serde_json::from_str::<serde_json::Value>(&signed).unwrap(),
        |mut acc, (k, v)| {
            if let Some(obj) = acc.as_object_mut() {
                obj.insert(k.clone(), v.clone());
            }
            acc
        },
    );

    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();
    assert!(!v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(true));
    let trust_check = v
        .get("verification_results")
        .and_then(|checks| checks.as_array())
        .and_then(|checks| {
            checks.iter().find(|check| {
                check.get("check_name").and_then(|name| name.as_str()) == Some("TrustChain")
            })
        })
        .expect("missing TrustChain check");
    assert_eq!(
        trust_check.get("passed").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert!(v
        .get("error_codes")
        .and_then(|codes| codes.as_array())
        .is_some_and(|codes| codes.iter().any(|code| code.as_str() == Some("E806"))));
}

#[test]
fn verify_respects_trust_chain() {
    use rcgen::KeyPair;

    let req = sample_create_request();
    let created = create_dtc_json(&req).expect("create failed");
    let signer_key = KeyPair::generate().expect("failed to generate signer key");
    let signer_private_pem = signer_key.serialize_pem();
    let mut signed_env = serde_json::from_str::<serde_json::Value>(&created).unwrap();
    if let Some(obj) = signed_env.as_object_mut() {
        obj.insert(
            "signing_key_pem".to_string(),
            signer_private_pem.clone().into(),
        );
        obj.insert("signer_id".to_string(), "rust-dtc".into());
    }
    let signed = sign_dtc_json(&signed_env.to_string()).expect("sign failed");

    // Supply a governed CSCA separately from the leaf-only signer chain.
    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    add_test_trust_material(
        &mut verify_env,
        &signer_private_pem,
        Some((DTC_SIGNER_EKU_OID, true)),
    );
    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();
    assert!(
        v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(false),
        "verification failed: {:?}",
        v
    );
}

#[test]
fn verify_rejects_partial_trust_material() {
    let created = create_dtc_json(&sample_create_request()).expect("create failed");
    let mut signing_envelope = serde_json::from_str::<serde_json::Value>(&created).unwrap();
    let object = signing_envelope.as_object_mut().unwrap();
    object.insert("signing_key_pem".to_string(), SIGNING_KEY_PEM.into());
    object.insert("signer_id".to_string(), "rust-dtc".into());
    let signed = sign_dtc_json(&signing_envelope.to_string()).expect("sign failed");

    for missing_field in ["trust_anchors_pem", "certificate_chain_pem"] {
        let mut verify_envelope = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
        add_test_trust_material(
            &mut verify_envelope,
            SIGNING_KEY_PEM,
            Some((DTC_SIGNER_EKU_OID, true)),
        );
        verify_envelope
            .as_object_mut()
            .unwrap()
            .remove(missing_field);

        let verified = verify_dtc_json(&verify_envelope.to_string()).expect("verify failed");
        let result: serde_json::Value = serde_json::from_str(&verified).unwrap();
        assert_eq!(
            result.get("is_valid").and_then(|value| value.as_bool()),
            Some(false)
        );
        assert!(result
            .get("error_codes")
            .and_then(|codes| codes.as_array())
            .is_some_and(|codes| codes.iter().any(|code| code.as_str() == Some("E806"))));
    }
}

#[test]
fn verify_rejects_signer_certificate_without_dtc_signer_eku() {
    let created = create_dtc_json(&sample_create_request()).expect("create failed");
    let mut signing_envelope = serde_json::from_str::<serde_json::Value>(&created).unwrap();
    let object = signing_envelope.as_object_mut().unwrap();
    object.insert("signing_key_pem".to_string(), SIGNING_KEY_PEM.into());
    object.insert("signer_id".to_string(), "rust-dtc".into());
    let signed = sign_dtc_json(&signing_envelope.to_string()).expect("sign failed");

    let mut verify_envelope = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    add_test_trust_material(&mut verify_envelope, SIGNING_KEY_PEM, None);
    let verified = verify_dtc_json(&verify_envelope.to_string()).expect("verify failed");
    let result: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert_eq!(
        result.get("is_valid").and_then(|value| value.as_bool()),
        Some(false)
    );
    assert!(result
        .get("errors")
        .and_then(|errors| errors.as_array())
        .is_some_and(|errors| errors.iter().any(|error| error
            .as_str()
            .is_some_and(|message| message.contains("missing extended key usage")))));
    assert!(result
        .get("error_codes")
        .and_then(|codes| codes.as_array())
        .is_some_and(|codes| codes.iter().any(|code| code.as_str() == Some("E806"))));
}

#[test]
fn verify_rejects_noncritical_dtc_signer_eku() {
    let created = create_dtc_json(&sample_create_request()).expect("create failed");
    let mut signing_envelope = serde_json::from_str::<serde_json::Value>(&created).unwrap();
    let object = signing_envelope.as_object_mut().unwrap();
    object.insert("signing_key_pem".to_string(), SIGNING_KEY_PEM.into());
    object.insert("signer_id".to_string(), "rust-dtc".into());
    let signed = sign_dtc_json(&signing_envelope.to_string()).expect("sign failed");

    let mut verify_envelope = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    add_test_trust_material(
        &mut verify_envelope,
        SIGNING_KEY_PEM,
        Some((DTC_SIGNER_EKU_OID, false)),
    );
    let verified = verify_dtc_json(&verify_envelope.to_string()).expect("verify failed");
    let result: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert_eq!(
        result.get("is_valid").and_then(|value| value.as_bool()),
        Some(false)
    );
    assert!(result
        .get("errors")
        .and_then(|errors| errors.as_array())
        .is_some_and(|errors| errors.iter().any(|error| error
            .as_str()
            .is_some_and(|message| message.contains("must be marked critical")))));
    assert!(result
        .get("error_codes")
        .and_then(|codes| codes.as_array())
        .is_some_and(|codes| codes.iter().any(|code| code.as_str() == Some("E806"))));
}

#[test]
fn verify_rejects_wrong_dtc_signer_eku() {
    let created = create_dtc_json(&sample_create_request()).expect("create failed");
    let mut signing_envelope = serde_json::from_str::<serde_json::Value>(&created).unwrap();
    let object = signing_envelope.as_object_mut().unwrap();
    object.insert("signing_key_pem".to_string(), SIGNING_KEY_PEM.into());
    object.insert("signer_id".to_string(), "rust-dtc".into());
    let signed = sign_dtc_json(&signing_envelope.to_string()).expect("sign failed");

    let mut verify_envelope = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    add_test_trust_material(
        &mut verify_envelope,
        SIGNING_KEY_PEM,
        Some(("1.3.6.1.5.5.7.3.3", true)),
    );
    let verified = verify_dtc_json(&verify_envelope.to_string()).expect("verify failed");
    let result: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert_eq!(
        result.get("is_valid").and_then(|value| value.as_bool()),
        Some(false)
    );
    assert!(result
        .get("errors")
        .and_then(|errors| errors.as_array())
        .is_some_and(|errors| errors.iter().any(|error| error
            .as_str()
            .is_some_and(|message| message.contains("not authorized for DTC signing")))));
    assert!(result
        .get("error_codes")
        .and_then(|codes| codes.as_array())
        .is_some_and(|codes| codes.iter().any(|code| code.as_str() == Some("E806"))));
}

#[test]
fn verify_rejects_tampered_payload() {
    let req = sample_create_request();
    let created = create_dtc_json(&req).expect("create failed");
    let with_key = serde_json::json!({
        "signing_key_pem": SIGNING_KEY_PEM,
        "signer_id": "rust-dtc",
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(
        serde_json::from_str::<serde_json::Value>(&created).unwrap(),
        |mut acc, (k, v)| {
            if let Some(obj) = acc.as_object_mut() {
                obj.insert(k.clone(), v.clone());
            }
            acc
        },
    );
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut tampered = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = tampered.as_object_mut() {
        obj.insert("passport_number".to_string(), "P9999999".into());
        obj.insert(
            "signer_public_key_pem".to_string(),
            SIGNER_PUBLIC_PEM.into(),
        );
    }

    let verified = verify_dtc_json(&tampered.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();
    assert!(
        !v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(true),
        "tampered payload should be invalid: {:?}",
        v
    );
}

#[test]
fn verify_rejects_wrong_public_key() {
    use rcgen::KeyPair;

    let req = sample_create_request();
    let created = create_dtc_json(&req).expect("create failed");
    let with_key = serde_json::json!({
        "signing_key_pem": SIGNING_KEY_PEM,
        "signer_id": "rust-dtc",
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(
        serde_json::from_str::<serde_json::Value>(&created).unwrap(),
        |mut acc, (k, v)| {
            if let Some(obj) = acc.as_object_mut() {
                obj.insert(k.clone(), v.clone());
            }
            acc
        },
    );
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let wrong_key = KeyPair::generate().expect("failed to generate wrong key");
    let wrong_public_pem = wrong_key.public_key_pem();

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert("signer_public_key_pem".to_string(), wrong_public_pem.into());
    }

    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();
    assert!(
        !v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(true),
        "verification should fail with wrong public key: {:?}",
        v
    );
}

#[test]
fn verify_rejects_mismatched_cert_chain() {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    let req = sample_create_request();
    let created = create_dtc_json(&req).expect("create failed");
    let signer_key = KeyPair::generate().expect("failed to generate signer key");
    let signer_private_pem = signer_key.serialize_pem();
    let signer_public_pem = signer_key.public_key_pem();
    let mut signed_env = serde_json::from_str::<serde_json::Value>(&created).unwrap();
    if let Some(obj) = signed_env.as_object_mut() {
        obj.insert(
            "signing_key_pem".to_string(),
            signer_private_pem.clone().into(),
        );
        obj.insert("signer_id".to_string(), "rust-dtc".into());
    }
    let signed = sign_dtc_json(&signed_env.to_string()).expect("sign failed");

    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "DTC Mismatch Root CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("failed to generate CA key");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("failed to generate CA cert");
    let ca_pem = ca_cert.pem();

    let mut ee_params = CertificateParams::default();
    ee_params
        .distinguished_name
        .push(DnType::CommonName, "DTC Mismatch Leaf");
    ee_params.is_ca = IsCa::NoCa;
    let other_key = KeyPair::generate().expect("failed to generate mismatched key");
    let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let ee_cert = ee_params
        .signed_by(&other_key, &ca_issuer)
        .expect("failed to generate EE cert");
    let ee_pem = ee_cert.pem();

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert(
            "signer_public_key_pem".to_string(),
            signer_public_pem.into(),
        );
        obj.insert("trust_anchors_pem".to_string(), serde_json::json!([ca_pem]));
        obj.insert(
            "certificate_chain_pem".to_string(),
            serde_json::json!([ee_pem, ca_pem]),
        );
    }
    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();
    assert!(
        !v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(true),
        "mismatched certificate chain should fail: {:?}",
        v
    );
}

#[test]
fn verify_rejects_expired_dtc() {
    let expired_req = serde_json::json!({
        "passport_number": "P1234567",
        "issuing_authority": "USA",
        "issue_date": "2020-01-01",
        "expiry_date": "2020-12-31", // Expired in the past
        "personal_details": {
            "first_name": "JOHN",
            "last_name": "DOE",
            "date_of_birth": "1990-01-01",
            "gender": "M",
            "nationality": "USA"
        },
        "data_groups": [
            {"dg_number": 1, "data": "ZGcx", "data_type": "MRZ"}
        ],
        "dtc_type": 4,
        "type1_profile": {
            "mrz_line1": "P<USADOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<",
            "mrz_line2": "1234567890USA8504031M3504027<<<<<<<6",
            "sod_hash": "",
            "issuing_state": "USA",
            "passive_auth_ok": true
        }
    });

    let created = create_dtc_json(&expired_req.to_string()).expect("create failed");
    let with_key = serde_json::json!({
        "signing_key_pem": SIGNING_KEY_PEM,
        "signer_id": "rust-dtc",
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(
        serde_json::from_str::<serde_json::Value>(&created).unwrap(),
        |mut acc, (k, v)| {
            if let Some(obj) = acc.as_object_mut() {
                obj.insert(k.clone(), v.clone());
            }
            acc
        },
    );
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    add_test_trust_material(
        &mut verify_env,
        SIGNING_KEY_PEM,
        Some((DTC_SIGNER_EKU_OID, true)),
    );

    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert!(
        !v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(true),
        "expired DTC should be invalid: {:?}",
        v
    );

    // Check that the error code is E807 (DTC_EXPIRED)
    let error_codes = v.get("error_codes").and_then(|c| c.as_array()).unwrap();
    assert!(
        error_codes.iter().any(|c| c.as_str() == Some("E807")),
        "expected E807 (DTC_EXPIRED) in error_codes: {:?}",
        error_codes
    );
}

#[test]
fn verify_rejects_not_yet_valid_dtc() {
    let future_req = serde_json::json!({
        "passport_number": "P1234567",
        "issuing_authority": "USA",
        "issue_date": "2024-01-01",
        "expiry_date": "2099-01-01",
        "dtc_valid_from": "2099-01-01", // Valid from far in the future
        "personal_details": {
            "first_name": "JOHN",
            "last_name": "DOE",
            "date_of_birth": "1990-01-01",
            "gender": "M",
            "nationality": "USA"
        },
        "data_groups": [
            {"dg_number": 1, "data": "ZGcx", "data_type": "MRZ"}
        ],
        "dtc_type": 4,
        "type1_profile": {
            "mrz_line1": "P<USADOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<",
            "mrz_line2": "1234567890USA8504031M3504027<<<<<<<6",
            "sod_hash": "",
            "issuing_state": "USA",
            "passive_auth_ok": true
        }
    });

    let created = create_dtc_json(&future_req.to_string()).expect("create failed");
    let with_key = serde_json::json!({
        "signing_key_pem": SIGNING_KEY_PEM,
        "signer_id": "rust-dtc",
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(
        serde_json::from_str::<serde_json::Value>(&created).unwrap(),
        |mut acc, (k, v)| {
            if let Some(obj) = acc.as_object_mut() {
                obj.insert(k.clone(), v.clone());
            }
            acc
        },
    );
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    add_test_trust_material(
        &mut verify_env,
        SIGNING_KEY_PEM,
        Some((DTC_SIGNER_EKU_OID, true)),
    );

    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert!(
        !v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(true),
        "not-yet-valid DTC should be invalid: {:?}",
        v
    );

    // Check that the error code is E808 (DTC_NOT_YET_VALID)
    let error_codes = v.get("error_codes").and_then(|c| c.as_array()).unwrap();
    assert!(
        error_codes.iter().any(|c| c.as_str() == Some("E808")),
        "expected E808 (DTC_NOT_YET_VALID) in error_codes: {:?}",
        error_codes
    );
}

#[test]
fn verify_rejects_revoked_dtc() {
    let revoked_req = serde_json::json!({
        "passport_number": "P1234567",
        "issuing_authority": "USA",
        "issue_date": "2024-01-01",
        "expiry_date": "2030-01-01",
        "is_revoked": true, // Marked as revoked
        "personal_details": {
            "first_name": "JOHN",
            "last_name": "DOE",
            "date_of_birth": "1990-01-01",
            "gender": "M",
            "nationality": "USA"
        },
        "data_groups": [
            {"dg_number": 1, "data": "ZGcx", "data_type": "MRZ"}
        ],
        "dtc_type": 4,
        "type1_profile": {
            "mrz_line1": "P<USADOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<",
            "mrz_line2": "1234567890USA8504031M3504027<<<<<<<6",
            "sod_hash": "",
            "issuing_state": "USA",
            "passive_auth_ok": true
        }
    });

    let verify_env = signed_verification_envelope(&revoked_req.to_string());
    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert!(
        !v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(true),
        "revoked DTC should be invalid: {:?}",
        v
    );

    // Check that the error code is E809 (DTC_REVOKED)
    let error_codes = v.get("error_codes").and_then(|c| c.as_array()).unwrap();
    assert!(
        error_codes.iter().any(|c| c.as_str() == Some("E809")),
        "expected E809 (DTC_REVOKED) in error_codes: {:?}",
        error_codes
    );
    assert_eq!(v["revocation_status"], "REVOKED");
    assert_eq!(revocation_check(&v)["outcome"], "FAILED");
    assert_eq!(revocation_check(&v)["passed"], false);
}

#[test]
fn signed_not_revoked_without_live_status_is_explicitly_not_performed() {
    let verify_env = signed_verification_envelope(&sample_create_request());
    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let value: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert_eq!(
        value["is_valid"], true,
        "cryptographic validity is separate"
    );
    assert_eq!(value["revocation_status"], "UNKNOWN");
    assert!(value["revocation_evidence"].is_null());
    assert_eq!(revocation_check(&value)["outcome"], "NOT_PERFORMED");
    assert_eq!(revocation_check(&value)["passed"], false);
    assert_eq!(revocation_check(&value)["error_code"], "E810");
    assert!(value["error_codes"]
        .as_array()
        .expect("error codes")
        .is_empty());
}

#[test]
fn authenticated_fresh_current_good_status_can_pass() {
    let verify_env = signed_verification_envelope(&sample_create_request());
    let now = Utc::now();
    let evidence = current_status(
        &verify_env,
        DtcCurrentStatus::Good,
        now - Duration::seconds(1),
        now + Duration::minutes(5),
    );

    let verified = verify_dtc_json_with_status(&verify_env.to_string(), Some(&evidence))
        .expect("verify failed");
    let value: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert_eq!(value["is_valid"], true);
    assert_eq!(value["revocation_status"], "GOOD");
    assert_eq!(revocation_check(&value)["outcome"], "PASSED");
    assert_eq!(revocation_check(&value)["passed"], true);
    assert_eq!(
        value["revocation_evidence"]["source"],
        "urn:marty:test:dtc-lifecycle-status"
    );
}

#[test]
fn authenticated_current_revoked_status_fails_closed() {
    let verify_env = signed_verification_envelope(&sample_create_request());
    let now = Utc::now();
    let evidence = current_status(
        &verify_env,
        DtcCurrentStatus::Revoked,
        now - Duration::seconds(1),
        now + Duration::minutes(5),
    );

    let verified = verify_dtc_json_with_status(&verify_env.to_string(), Some(&evidence))
        .expect("verify failed");
    let value: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert_eq!(value["is_valid"], false);
    assert_eq!(value["revocation_status"], "REVOKED");
    assert_eq!(revocation_check(&value)["outcome"], "FAILED");
    assert_eq!(revocation_check(&value)["error_code"], "E809");
}

#[test]
fn stale_current_status_is_unknown_without_erasing_cryptographic_validity() {
    let verify_env = signed_verification_envelope(&sample_create_request());
    let now = Utc::now();
    let evidence = current_status(
        &verify_env,
        DtcCurrentStatus::Good,
        now - Duration::minutes(10),
        now - Duration::minutes(1),
    );

    let verified = verify_dtc_json_with_status(&verify_env.to_string(), Some(&evidence))
        .expect("verify failed");
    let value: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert_eq!(value["is_valid"], true);
    assert_eq!(value["revocation_status"], "UNKNOWN");
    assert!(value["revocation_evidence"].is_null());
    assert_eq!(revocation_check(&value)["outcome"], "ERROR");
    assert_eq!(revocation_check(&value)["passed"], false);
    assert_eq!(revocation_check(&value)["error_code"], "E811");
}

#[test]
fn mismatched_current_status_cannot_upgrade_the_credential() {
    let verify_env = signed_verification_envelope(&sample_create_request());
    let now = Utc::now();
    let evidence = AuthenticatedDtcStatus::new(
        verify_env["dtc_id"].as_str().expect("DTC ID"),
        Some("DIFFERENT-DOCUMENT".to_string()),
        DtcCurrentStatus::Good,
        now - Duration::seconds(1),
        now + Duration::minutes(5),
        "urn:marty:test:dtc-lifecycle-status",
        status_authority_provenance(),
    )
    .expect("well-formed but mismatched evidence");

    let verified = verify_dtc_json_with_status(&verify_env.to_string(), Some(&evidence))
        .expect("verify failed");
    let value: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert_eq!(value["is_valid"], true);
    assert_eq!(value["revocation_status"], "UNKNOWN");
    assert_eq!(revocation_check(&value)["outcome"], "ERROR");
    assert!(value["revocation_evidence"].is_null());
}

#[test]
fn current_status_for_another_dtc_cannot_upgrade_the_credential() {
    let verify_env = signed_verification_envelope(&sample_create_request());
    let now = Utc::now();
    let evidence = AuthenticatedDtcStatus::new(
        "DTC-FOR-A-DIFFERENT-CREDENTIAL",
        verify_env["passport_number"].as_str().map(str::to_string),
        DtcCurrentStatus::Good,
        now - Duration::seconds(1),
        now + Duration::minutes(5),
        "urn:marty:test:dtc-lifecycle-status",
        status_authority_provenance(),
    )
    .expect("well-formed but mismatched evidence");

    let verified = verify_dtc_json_with_status(&verify_env.to_string(), Some(&evidence))
        .expect("verify failed");
    let value: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert_eq!(value["is_valid"], true);
    assert_eq!(value["revocation_status"], "UNKNOWN");
    assert_eq!(revocation_check(&value)["outcome"], "ERROR");
    assert!(value["revocation_evidence"].is_null());
}

#[test]
fn malformed_current_status_context_is_rejected_before_verification() {
    let now = Utc::now();
    let malformed_source = AuthenticatedDtcStatus::new(
        "DTC-1",
        Some("P1234567".to_string()),
        DtcCurrentStatus::Good,
        now,
        now + Duration::minutes(5),
        "not an absolute IRI",
        status_authority_provenance(),
    );
    assert_eq!(
        malformed_source.expect_err("malformed source must be rejected"),
        "DTC status source must be a bounded, non-empty absolute IRI without surrounding whitespace"
    );

    let invalid_freshness = AuthenticatedDtcStatus::new(
        "DTC-1",
        Some("P1234567".to_string()),
        DtcCurrentStatus::Good,
        now,
        now,
        "urn:marty:test:dtc-lifecycle-status",
        status_authority_provenance(),
    );
    assert_eq!(
        invalid_freshness.expect_err("invalid freshness must be rejected"),
        "DTC status fresh_until must be later than checked_at"
    );
}

#[test]
fn verify_type2_profile_validates_required_fields() {
    let type2_req = serde_json::json!({
        "passport_number": "P1234567",
        "issuing_authority": "USA",
        "issue_date": "2024-01-01",
        "expiry_date": "2030-01-01",
        "personal_details": {
            "first_name": "JOHN",
            "last_name": "DOE",
            "date_of_birth": "1990-01-01",
            "gender": "M",
            "nationality": "USA"
        },
        "data_groups": [
            {"dg_number": 1, "data": "ZGcx", "data_type": "MRZ"}
        ],
        "dtc_type": 5, // TYPE2
        "type2_profile": {
            "chip_auth_public_key": "MDQwCQYDK2VuBQADKAAE", // sample key bytes
            "device_public_key": "MDQwCQYDK2VuBQADKAAF",
            "attestation_cert_hash": "abc123",
            "passive_auth_ok": true
        }
    });

    let created = create_dtc_json(&type2_req.to_string()).expect("create failed");
    let with_key = serde_json::json!({
        "signing_key_pem": SIGNING_KEY_PEM,
        "signer_id": "rust-dtc",
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(
        serde_json::from_str::<serde_json::Value>(&created).unwrap(),
        |mut acc, (k, v)| {
            if let Some(obj) = acc.as_object_mut() {
                obj.insert(k.clone(), v.clone());
            }
            acc
        },
    );
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    add_test_trust_material(
        &mut verify_env,
        SIGNING_KEY_PEM,
        Some((DTC_SIGNER_EKU_OID, true)),
    );

    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert!(
        v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(false),
        "valid Type2 DTC should pass verification: {:?}",
        v
    );
}

#[test]
fn verify_type2_profile_rejects_missing_fields() {
    let incomplete_type2_req = serde_json::json!({
        "passport_number": "P1234567",
        "issuing_authority": "USA",
        "issue_date": "2024-01-01",
        "expiry_date": "2030-01-01",
        "personal_details": {
            "first_name": "JOHN",
            "last_name": "DOE",
            "date_of_birth": "1990-01-01",
            "gender": "M",
            "nationality": "USA"
        },
        "data_groups": [
            {"dg_number": 1, "data": "ZGcx", "data_type": "MRZ"}
        ],
        "dtc_type": 5, // TYPE2
        "type2_profile": {
            "chip_auth_public_key": "", // Missing
            "device_public_key": "",    // Missing
            "passive_auth_ok": false
        }
    });

    let created = create_dtc_json(&incomplete_type2_req.to_string()).expect("create failed");
    let with_key = serde_json::json!({
        "signing_key_pem": SIGNING_KEY_PEM,
        "signer_id": "rust-dtc",
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(
        serde_json::from_str::<serde_json::Value>(&created).unwrap(),
        |mut acc, (k, v)| {
            if let Some(obj) = acc.as_object_mut() {
                obj.insert(k.clone(), v.clone());
            }
            acc
        },
    );
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert(
            "signer_public_key_pem".to_string(),
            SIGNER_PUBLIC_PEM.into(),
        );
    }

    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert!(
        !v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(true),
        "Type2 DTC with missing fields should be invalid: {:?}",
        v
    );
}

#[test]
fn verify_type3_profile_validates_required_fields() {
    let type3_req = serde_json::json!({
        "passport_number": "P1234567",
        "issuing_authority": "USA",
        "issue_date": "2024-01-01",
        "expiry_date": "2030-01-01",
        "personal_details": {
            "first_name": "JOHN",
            "last_name": "DOE",
            "date_of_birth": "1990-01-01",
            "gender": "M",
            "nationality": "USA"
        },
        "data_groups": [
            {"dg_number": 1, "data": "ZGcx", "data_type": "MRZ"}
        ],
        "dtc_type": 6, // TYPE3
        "type3_profile": {
            "remote_attestation_report": "eyJhdHRlc3RhdGlvbiI6InJlcG9ydCJ9",
            "device_binding_id": "device-123-abc",
            "ephemeral_public_key": "MDQwCQYDK2VuBQADKAAG",
            "session_id": "session-456",
            "attestation_cert_hash": "def456"
        }
    });

    let created = create_dtc_json(&type3_req.to_string()).expect("create failed");
    let with_key = serde_json::json!({
        "signing_key_pem": SIGNING_KEY_PEM,
        "signer_id": "rust-dtc",
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(
        serde_json::from_str::<serde_json::Value>(&created).unwrap(),
        |mut acc, (k, v)| {
            if let Some(obj) = acc.as_object_mut() {
                obj.insert(k.clone(), v.clone());
            }
            acc
        },
    );
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    add_test_trust_material(
        &mut verify_env,
        SIGNING_KEY_PEM,
        Some((DTC_SIGNER_EKU_OID, true)),
    );

    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert!(
        v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(false),
        "valid Type3 DTC should pass verification: {:?}",
        v
    );
}

#[test]
fn verify_type3_profile_rejects_missing_fields() {
    let incomplete_type3_req = serde_json::json!({
        "passport_number": "P1234567",
        "issuing_authority": "USA",
        "issue_date": "2024-01-01",
        "expiry_date": "2030-01-01",
        "personal_details": {
            "first_name": "JOHN",
            "last_name": "DOE",
            "date_of_birth": "1990-01-01",
            "gender": "M",
            "nationality": "USA"
        },
        "data_groups": [
            {"dg_number": 1, "data": "ZGcx", "data_type": "MRZ"}
        ],
        "dtc_type": 6, // TYPE3
        "type3_profile": {
            "remote_attestation_report": "", // Missing
            "device_binding_id": "",          // Missing
            "ephemeral_public_key": "",
            "session_id": ""
        }
    });

    let created = create_dtc_json(&incomplete_type3_req.to_string()).expect("create failed");
    let with_key = serde_json::json!({
        "signing_key_pem": SIGNING_KEY_PEM,
        "signer_id": "rust-dtc",
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(
        serde_json::from_str::<serde_json::Value>(&created).unwrap(),
        |mut acc, (k, v)| {
            if let Some(obj) = acc.as_object_mut() {
                obj.insert(k.clone(), v.clone());
            }
            acc
        },
    );
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert(
            "signer_public_key_pem".to_string(),
            SIGNER_PUBLIC_PEM.into(),
        );
    }

    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();

    assert!(
        !v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(true),
        "Type3 DTC with missing fields should be invalid: {:?}",
        v
    );
}
