use marty_verification::dtc::{create_dtc_json, sign_dtc_json, verify_dtc_json};

const SIGNING_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiNW7Kf1E+H1DeG4s
2D38+6hJbAnf4fy5s6RJFuMAcMWhRANCAAQsKlSJSUKItZlFvKAJnjZob3Q6r98t
fYIH6foa373wsHSHktdpDZmb7fe0E3MFc3TvrWlCg/nPMlQNMU41xr4M
-----END PRIVATE KEY-----"#;

const SIGNER_PUBLIC_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELCpUiUlCiLWZRbygCZ42aG90Oq/f
LX2CB+n6Gt+98LB0h5LXaQ2Zm+33tBNzBXN0761pQoP5zzJUDTFONca+DA==
-----END PUBLIC KEY-----"#;


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
fn sign_and_verify_round_trip() {
    let req = sample_create_request();
    let created = create_dtc_json(&req).expect("create failed");
    let with_key = serde_json::json!({
        "signing_key_pem": SIGNING_KEY_PEM,
        "signer_id": "rust-dtc",
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(serde_json::from_str::<serde_json::Value>(&created).unwrap(), |mut acc, (k, v)| {
        if let Some(obj) = acc.as_object_mut() {
            obj.insert(k.clone(), v.clone());
        }
        acc
    });
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let verify_env = serde_json::json!({
        "signer_public_key_pem": SIGNER_PUBLIC_PEM
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(serde_json::from_str::<serde_json::Value>(&signed).unwrap(), |mut acc, (k, v)| {
        if let Some(obj) = acc.as_object_mut() {
            obj.insert(k.clone(), v.clone());
        }
        acc
    });

    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();
    assert!(
        v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(false),
        "verification failed: {:?}",
        v
    );
}

#[test]
fn verify_respects_trust_chain() {
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
        .push(DnType::CommonName, "DTC Test Root CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("failed to generate CA key");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("failed to generate CA cert");
    let ca_pem = ca_cert.pem();

    let mut ee_params = CertificateParams::default();
    ee_params
        .distinguished_name
        .push(DnType::CommonName, "DTC Test Leaf");
    ee_params.is_ca = IsCa::NoCa;
    let ee_cert = ee_params
        .signed_by(&signer_key, &ca_cert, &ca_key)
        .expect("failed to generate EE cert");
    let ee_pem = ee_cert.pem();

    // Supply trust anchors and chain; expect signature to pass and trust check to succeed
    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert(
            "signer_public_key_pem".to_string(),
            signer_public_pem.into(),
        );
        obj.insert(
            "trust_anchors_pem".to_string(),
            serde_json::json!([ca_pem]),
        );
        obj.insert(
            "certificate_chain_pem".to_string(),
            serde_json::json!([ee_pem, ca_pem]),
        );
    }
    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();
    assert!(
        v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(false),
        "verification failed: {:?}",
        v
    );
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
    .fold(serde_json::from_str::<serde_json::Value>(&created).unwrap(), |mut acc, (k, v)| {
        if let Some(obj) = acc.as_object_mut() {
            obj.insert(k.clone(), v.clone());
        }
        acc
    });
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
    .fold(serde_json::from_str::<serde_json::Value>(&created).unwrap(), |mut acc, (k, v)| {
        if let Some(obj) = acc.as_object_mut() {
            obj.insert(k.clone(), v.clone());
        }
        acc
    });
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let wrong_key = KeyPair::generate().expect("failed to generate wrong key");
    let wrong_public_pem = wrong_key.public_key_pem();

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert(
            "signer_public_key_pem".to_string(),
            wrong_public_pem.into(),
        );
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
    let ee_cert = ee_params
        .signed_by(&other_key, &ca_cert, &ca_key)
        .expect("failed to generate EE cert");
    let ee_pem = ee_cert.pem();

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert(
            "signer_public_key_pem".to_string(),
            signer_public_pem.into(),
        );
        obj.insert(
            "trust_anchors_pem".to_string(),
            serde_json::json!([ca_pem]),
        );
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
    .fold(serde_json::from_str::<serde_json::Value>(&created).unwrap(), |mut acc, (k, v)| {
        if let Some(obj) = acc.as_object_mut() {
            obj.insert(k.clone(), v.clone());
        }
        acc
    });
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert("signer_public_key_pem".to_string(), SIGNER_PUBLIC_PEM.into());
    }

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
    .fold(serde_json::from_str::<serde_json::Value>(&created).unwrap(), |mut acc, (k, v)| {
        if let Some(obj) = acc.as_object_mut() {
            obj.insert(k.clone(), v.clone());
        }
        acc
    });
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert("signer_public_key_pem".to_string(), SIGNER_PUBLIC_PEM.into());
    }

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

    let created = create_dtc_json(&revoked_req.to_string()).expect("create failed");
    let with_key = serde_json::json!({
        "signing_key_pem": SIGNING_KEY_PEM,
        "signer_id": "rust-dtc",
    })
    .as_object()
    .unwrap()
    .iter()
    .fold(serde_json::from_str::<serde_json::Value>(&created).unwrap(), |mut acc, (k, v)| {
        if let Some(obj) = acc.as_object_mut() {
            obj.insert(k.clone(), v.clone());
        }
        acc
    });
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert("signer_public_key_pem".to_string(), SIGNER_PUBLIC_PEM.into());
    }

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
    .fold(serde_json::from_str::<serde_json::Value>(&created).unwrap(), |mut acc, (k, v)| {
        if let Some(obj) = acc.as_object_mut() {
            obj.insert(k.clone(), v.clone());
        }
        acc
    });
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert("signer_public_key_pem".to_string(), SIGNER_PUBLIC_PEM.into());
    }

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
    .fold(serde_json::from_str::<serde_json::Value>(&created).unwrap(), |mut acc, (k, v)| {
        if let Some(obj) = acc.as_object_mut() {
            obj.insert(k.clone(), v.clone());
        }
        acc
    });
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert("signer_public_key_pem".to_string(), SIGNER_PUBLIC_PEM.into());
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
    .fold(serde_json::from_str::<serde_json::Value>(&created).unwrap(), |mut acc, (k, v)| {
        if let Some(obj) = acc.as_object_mut() {
            obj.insert(k.clone(), v.clone());
        }
        acc
    });
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert("signer_public_key_pem".to_string(), SIGNER_PUBLIC_PEM.into());
    }

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
    .fold(serde_json::from_str::<serde_json::Value>(&created).unwrap(), |mut acc, (k, v)| {
        if let Some(obj) = acc.as_object_mut() {
            obj.insert(k.clone(), v.clone());
        }
        acc
    });
    let signed = sign_dtc_json(&with_key.to_string()).expect("sign failed");

    let mut verify_env = serde_json::from_str::<serde_json::Value>(&signed).unwrap();
    if let Some(obj) = verify_env.as_object_mut() {
        obj.insert("signer_public_key_pem".to_string(), SIGNER_PUBLIC_PEM.into());
    }

    let verified = verify_dtc_json(&verify_env.to_string()).expect("verify failed");
    let v: serde_json::Value = serde_json::from_str(&verified).unwrap();
    
    assert!(
        !v.get("is_valid").and_then(|b| b.as_bool()).unwrap_or(true),
        "Type3 DTC with missing fields should be invalid: {:?}",
        v
    );
}
