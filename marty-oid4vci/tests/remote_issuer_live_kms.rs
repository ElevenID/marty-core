//! Opt-in positive issuance against disposable OpenBao Transit.
//! Issuer private keys are generated and retained only by OpenBao.

use std::{collections::HashMap, sync::Mutex};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use marty_oid4vci::{
    formats::{
        jwt_vc::sign_jwt_vc_with_signer,
        mdoc::{
            assemble_mdoc, prepare_mdoc_with_credential_id_and_device_key, sign_mdoc_with_signer,
        },
        sd_jwt::{
            assemble_sd_jwt, prepare_sd_jwt_with_options, sign_sd_jwt_with_signer, verify_sd_jwt,
            SdJwtPreparationOptions,
        },
    },
    jose::verify_compact_jwt_with_public_jwk,
    proof::verify_jwt_proof,
    signer::CredentialSigner,
    types::{CredentialClaims, CredentialPayloadFormat, SignedCredential, SigningAlgorithm},
    wallet::WalletEngine,
    Oid4vciError, Oid4vciResult,
};
use reqwest::{blocking::Client, Url};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ISSUER_DID: &str = "did:web:issuer.example";

struct OpenBaoSigner {
    client: Client,
    base: String,
    token: String,
    key_name: String,
    algorithm: SigningAlgorithm,
    public_jwk: String,
    payloads: Mutex<Vec<Vec<u8>>>,
    signatures: Mutex<Vec<Vec<u8>>>,
}

impl std::fmt::Debug for OpenBaoSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OpenBaoSigner([redacted])")
    }
}

impl CredentialSigner for OpenBaoSigner {
    fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
        self.payloads.lock().unwrap().push(message.to_vec());
        let (input, prehashed) = match self.algorithm {
            SigningAlgorithm::ES256 => (STANDARD.encode(Sha256::digest(message)), true),
            SigningAlgorithm::EdDSA => (STANDARD.encode(message), false),
            _ => unreachable!("the live fixture creates only ES256 and EdDSA keys"),
        };
        let mut body = json!({"input": input, "prehashed": prehashed});
        if prehashed {
            body["hash_algorithm"] = json!("sha2-256");
        }
        let response: Value = self
            .client
            .post(format!("{}/v1/transit/sign/{}", self.base, self.key_name))
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::json)
            .map_err(|_| Oid4vciError::SigningError("remote signer unavailable".into()))?;
        let encoded = response["data"]["signature"]
            .as_str()
            .and_then(|value| value.rsplit(':').next())
            .ok_or_else(|| Oid4vciError::SigningError("remote signature is missing".into()))?;
        let signature = STANDARD
            .decode(encoded)
            .map_err(|_| Oid4vciError::SigningError("remote signature is invalid".into()))?;
        let signature = if self.algorithm == SigningAlgorithm::ES256 {
            marty_crypto::ecdsa::normalize_signature(&signature, "ES256")
                .map_err(|_| Oid4vciError::SigningError("remote signature is invalid".into()))?
        } else {
            signature
        };
        self.signatures.lock().unwrap().push(signature.clone());
        Ok(signature)
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    fn issuer_id(&self) -> &str {
        ISSUER_DID
    }

    fn kid_url(&self) -> String {
        format!("{ISSUER_DID}#{}", self.key_name)
    }

    fn public_jwk(&self) -> Oid4vciResult<String> {
        Ok(self.public_jwk.clone())
    }
}

fn disposable_openbao() -> (Client, String, String) {
    let base = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let parsed = Url::parse(&base).expect("OpenBao URL syntax");
    assert_eq!(parsed.scheme(), "http");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert!(parsed.port().is_some());
    let root_token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable root token");
    let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE")
        .expect("disposable OpenBao marker nonce");
    assert!(nonce.len() >= 16);
    let client = Client::builder().no_proxy().build().unwrap();
    let marker: Value = client
        .get(format!("{base}/v1/secret/data/marty-test-disposable-guard"))
        .header("X-Vault-Token", &root_token)
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(marker["data"]["data"]["nonce"], nonce);
    (client, base.trim_end_matches('/').into(), root_token)
}

fn create_signer(
    client: &Client,
    base: &str,
    root_token: &str,
    key_type: &str,
    algorithm: SigningAlgorithm,
) -> OpenBaoSigner {
    let key_name = format!("marty-core-issuer-{}", uuid::Uuid::new_v4().simple());
    client
        .post(format!("{base}/v1/transit/keys/{key_name}"))
        .header("X-Vault-Token", root_token)
        .json(&json!({
            "type": key_type,
            "exportable": false,
            "allow_plaintext_backup": false
        }))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap();
    let metadata: Value = client
        .get(format!("{base}/v1/transit/keys/{key_name}"))
        .header("X-Vault-Token", root_token)
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(metadata["data"]["exportable"], false);
    assert_eq!(metadata["data"]["allow_plaintext_backup"], false);
    let root_export = client
        .get(format!("{base}/v1/transit/export/signing-key/{key_name}"))
        .header("X-Vault-Token", root_token)
        .send()
        .unwrap();
    assert!(!root_export.status().is_success());
    let public_key = metadata["data"]["keys"]["1"]["public_key"]
        .as_str()
        .unwrap();
    let public_jwk = if key_type == "ed25519" {
        let raw = STANDARD.decode(public_key).unwrap();
        assert_eq!(raw.len(), 32);
        json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(raw)}).to_string()
    } else {
        marty_crypto::jwk::public_key_pem_to_jwk(public_key)
            .unwrap()
            .to_json()
            .unwrap()
    };

    let policy_name = format!("marty-core-issuer-{}", uuid::Uuid::new_v4().simple());
    let policy = format!("path \"transit/sign/{key_name}\" {{ capabilities = [\"update\"] }}");
    client
        .put(format!("{base}/v1/sys/policies/acl/{policy_name}"))
        .header("X-Vault-Token", root_token)
        .json(&json!({"policy":policy}))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap();
    let token: Value = client
        .post(format!("{base}/v1/auth/token/create"))
        .header("X-Vault-Token", root_token)
        .json(&json!({"policies":[policy_name],"no_default_policy":true,"ttl":"10m"}))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    let scoped_token = token["auth"]["client_token"].as_str().unwrap();
    let denied = client
        .get(format!("{base}/v1/transit/export/signing-key/{key_name}"))
        .header("X-Vault-Token", scoped_token)
        .send()
        .unwrap();
    assert_eq!(denied.status().as_u16(), 403);
    OpenBaoSigner {
        client: client.clone(),
        base: base.into(),
        token: scoped_token.into(),
        key_name,
        algorithm,
        public_jwk,
        payloads: Mutex::new(Vec::new()),
        signatures: Mutex::new(Vec::new()),
    }
}

fn claims(format: CredentialPayloadFormat) -> CredentialClaims {
    CredentialClaims {
        credential_type: "EmployeeCredential".into(),
        claims: HashMap::from([
            ("given_name".into(), json!("Alice")),
            ("family_name".into(), json!("Smith")),
        ]),
        subject_id: Some("did:example:holder".into()),
        expiration_seconds: Some(3_600),
        credential_payload_format: format,
        selective_disclosure_claims: vec![],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

#[test]
#[ignore = "requires a marked disposable loopback OpenBao with Transit mounted"]
fn issuer_formats_use_remote_non_exportable_keys() {
    let (client, base, root_token) = disposable_openbao();
    let es256 = create_signer(
        &client,
        &base,
        &root_token,
        "ecdsa-p256",
        SigningAlgorithm::ES256,
    );
    let eddsa = create_signer(
        &client,
        &base,
        &root_token,
        "ed25519",
        SigningAlgorithm::EdDSA,
    );
    let unrelated_eddsa = create_signer(
        &client,
        &base,
        &root_token,
        "ed25519",
        SigningAlgorithm::EdDSA,
    );
    let wrong_key = client
        .post(format!("{base}/v1/transit/sign/{}", eddsa.key_name))
        .header("X-Vault-Token", &es256.token)
        .json(&json!({"input":STANDARD.encode(b"wrong-key")}))
        .send()
        .unwrap();
    assert_eq!(wrong_key.status().as_u16(), 403);

    for signer in [&es256, &eddsa] {
        let signed =
            sign_jwt_vc_with_signer(signer, &claims(CredentialPayloadFormat::W3cVcdmV2JwtVc))
                .unwrap();
        let SignedCredential::JwtVcJson { jwt, credential_id } = signed else {
            panic!("expected JWT-VC")
        };
        let segments: Vec<_> = jwt.split('.').collect();
        assert_eq!(segments.len(), 3);
        let payloads = signer.payloads.lock().unwrap();
        let signatures = signer.signatures.lock().unwrap();
        assert_eq!(payloads.len(), 1);
        assert_eq!(signatures.len(), 1);
        assert_eq!(
            payloads[0],
            format!("{}.{}", segments[0], segments[1]).as_bytes()
        );
        assert_eq!(signatures[0], URL_SAFE_NO_PAD.decode(segments[2]).unwrap());
        assert!(credential_id.starts_with("urn:uuid:"));
        let verified =
            verify_compact_jwt_with_public_jwk(&jwt, &signer.public_jwk, signer.algorithm.as_str())
                .unwrap();
        assert_eq!(verified.header["alg"], signer.algorithm.as_str());
        assert_eq!(
            verified.claims["vc"]["credentialSubject"]["given_name"],
            "Alice"
        );
        let other_algorithm = if signer.algorithm == SigningAlgorithm::ES256 {
            "EdDSA"
        } else {
            "ES256"
        };
        assert!(
            verify_compact_jwt_with_public_jwk(&jwt, &signer.public_jwk, other_algorithm).is_err()
        );
        assert_eq!(format!("{signer:?}"), "OpenBaoSigner([redacted])");
    }

    let mut mdoc_claims = claims(CredentialPayloadFormat::default());
    mdoc_claims.credential_type = "org.iso.18013.5.1.mDL".into();
    mdoc_claims.mdoc_namespace = Some("org.iso.18013.5.1".into());
    mdoc_claims.mdoc_doctype = Some("org.iso.18013.5.1.mDL".into());
    let signed = sign_mdoc_with_signer(&es256, &mdoc_claims).unwrap();
    let SignedCredential::MsoMdoc {
        issuer_signed_b64,
        credential_id,
    } = signed
    else {
        panic!("expected mDoc")
    };
    assert!(credential_id.starts_with("urn:uuid:"));
    let issuer_signed_bytes = URL_SAFE_NO_PAD.decode(issuer_signed_b64).unwrap();
    let issuer_signed: isomdl::definitions::IssuerSigned =
        isomdl::cbor::from_slice(&issuer_signed_bytes).unwrap();
    let payloads = es256.payloads.lock().unwrap();
    let signatures = es256.signatures.lock().unwrap();
    assert_eq!(payloads.len(), 2);
    assert_eq!(signatures.len(), 2);
    assert_eq!(issuer_signed.issuer_auth.tbs_data(&[]), payloads[1]);
    assert_eq!(issuer_signed.issuer_auth.signature, signatures[1]);
    drop(payloads);
    drop(signatures);

    for signer in [&es256, &eddsa] {
        let mut sd_claims = claims(CredentialPayloadFormat::IetfSdJwt);
        sd_claims.selective_disclosure_claims = vec!["given_name".into()];
        let signed = sign_sd_jwt_with_signer(signer, &sd_claims).unwrap();
        let SignedCredential::SdJwt {
            compact,
            credential_id,
        } = signed
        else {
            panic!("expected SD-JWT")
        };
        assert!(credential_id.starts_with("urn:uuid:"));
        uuid::Uuid::parse_str(credential_id.trim_start_matches("urn:uuid:")).unwrap();
        let (jws, disclosure) = compact.split_once('~').unwrap();
        assert!(!disclosure.is_empty());
        let segments: Vec<_> = jws.split('.').collect();
        assert_eq!(segments.len(), 3);
        let issued_payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
        assert_eq!(issued_payload["jti"], credential_id);
        let payloads = signer.payloads.lock().unwrap();
        let signatures = signer.signatures.lock().unwrap();
        let index = if signer.algorithm == SigningAlgorithm::ES256 {
            2
        } else {
            1
        };
        assert_eq!(payloads.len(), index + 1);
        assert_eq!(signatures.len(), index + 1);
        assert_eq!(
            payloads[index],
            format!("{}.{}", segments[0], segments[1]).as_bytes()
        );
        assert_eq!(
            signatures[index],
            URL_SAFE_NO_PAD.decode(segments[2]).unwrap()
        );
        drop(payloads);
        drop(signatures);

        let verified = verify_sd_jwt(&compact, &signer.public_jwk, None, None).unwrap();
        assert_eq!(verified["given_name"], "Alice");
        assert_eq!(verified["family_name"], "Smith");

        let mut tampered_signature = URL_SAFE_NO_PAD.decode(segments[2]).unwrap();
        tampered_signature[0] ^= 0x01;
        let tampered = format!(
            "{}.{}.{}~{}",
            segments[0],
            segments[1],
            URL_SAFE_NO_PAD.encode(tampered_signature),
            disclosure
        );
        assert!(verify_sd_jwt(&tampered, &signer.public_jwk, None, None).is_err());
        assert!(verify_sd_jwt(
            &compact,
            &signer.public_jwk,
            Some("https://verifier.example/response".into()),
            Some("nonce-1".into()),
        )
        .is_err());
        if signer.algorithm == SigningAlgorithm::EdDSA {
            assert!(verify_sd_jwt(&compact, &unrelated_eddsa.public_jwk, None, None).is_err());
        }

        let mut w3c_claims = claims(CredentialPayloadFormat::W3cVcdmV2SdJwt);
        w3c_claims.selective_disclosure_claims = vec!["given_name".into()];
        w3c_claims.w3c_types = vec!["EmployeeCredential".into()];
        let SignedCredential::SdJwt { compact, .. } =
            sign_sd_jwt_with_signer(signer, &w3c_claims).unwrap()
        else {
            panic!("expected W3C SD-JWT")
        };
        let verified = verify_sd_jwt(&compact, &signer.public_jwk, None, None).unwrap();
        assert_eq!(verified["credentialSubject"]["given_name"], "Alice");
        assert_eq!(verified["credentialSubject"]["family_name"], "Smith");

        let SignedCredential::SdJwt { compact, .. } =
            sign_sd_jwt_with_signer(signer, &claims(CredentialPayloadFormat::IetfSdJwt)).unwrap()
        else {
            panic!("expected no-disclosure SD-JWT")
        };
        assert!(compact.ends_with('~'));
        assert_eq!(compact.split('~').count(), 2);
        let verified = verify_sd_jwt(&compact, &signer.public_jwk, None, None).unwrap();
        assert_eq!(verified["given_name"], "Alice");
        assert_eq!(verified["family_name"], "Smith");

        let mut two_disclosures = claims(CredentialPayloadFormat::IetfSdJwt);
        two_disclosures.selective_disclosure_claims =
            vec!["given_name".into(), "family_name".into()];
        let SignedCredential::SdJwt { compact, .. } =
            sign_sd_jwt_with_signer(signer, &two_disclosures).unwrap()
        else {
            panic!("expected two-disclosure SD-JWT")
        };
        assert_eq!(
            compact.split('~').filter(|part| !part.is_empty()).count(),
            3
        );
        let verified = verify_sd_jwt(&compact, &signer.public_jwk, None, None).unwrap();
        assert_eq!(verified["given_name"], "Alice");
        assert_eq!(verified["family_name"], "Smith");
    }
}

#[test]
#[ignore = "requires a marked disposable loopback OpenBao with Transit mounted"]
fn holder_proof_binds_remote_issuer_sd_jwt_without_private_key_transfer() {
    let (client, base, root_token) = disposable_openbao();
    let issuer = create_signer(
        &client,
        &base,
        &root_token,
        "ecdsa-p256",
        SigningAlgorithm::ES256,
    );
    let holder = create_signer(
        &client,
        &base,
        &root_token,
        "ecdsa-p256",
        SigningAlgorithm::ES256,
    );
    assert_ne!(issuer.public_jwk, holder.public_jwk);
    let nonce = uuid::Uuid::new_v4().to_string();
    let audience = "https://issuer.example.test";
    let prepared_proof = WalletEngine::new()
        .prepare_proof_jwt(
            "did:example:remote-holder",
            &nonce,
            audience,
            &holder.public_jwk,
        )
        .unwrap();
    let holder_signature = holder.sign(prepared_proof.signing_input()).unwrap();
    let proof = prepared_proof.complete(&holder_signature).unwrap();
    assert!(verify_jwt_proof(&proof, audience, Some("wrong-nonce"), 300).is_err());
    let mut tampered = proof.split('.').map(str::to_owned).collect::<Vec<_>>();
    let mut signature = URL_SAFE_NO_PAD.decode(&tampered[2]).unwrap();
    signature[0] ^= 1;
    tampered[2] = URL_SAFE_NO_PAD.encode(signature);
    assert!(verify_jwt_proof(&tampered.join("."), audience, Some(&nonce), 300).is_err());
    assert!(issuer.payloads.lock().unwrap().is_empty());

    let verified = verify_jwt_proof(&proof, audience, Some(&nonce), 300).unwrap();
    let holder_public = serde_json::to_value(verified.holder_jwk.unwrap().to_public()).unwrap();
    assert_eq!(holder_public["kty"], "EC");
    assert!(holder_public.get("d").is_none());
    let mut bound_claims = claims(CredentialPayloadFormat::W3cVcdmV2SdJwt);
    bound_claims.selective_disclosure_claims = vec!["given_name".into()];
    bound_claims.w3c_types = vec!["EmployeeCredential".into()];
    let prepared = prepare_sd_jwt_with_options(
        &issuer,
        &bound_claims,
        SdJwtPreparationOptions {
            confirmation: Some(json!({"jwk":holder_public})),
            ..SdJwtPreparationOptions::default()
        },
    )
    .unwrap();
    let issuer_signature = issuer.sign(prepared.signing_payload()).unwrap();
    let SignedCredential::SdJwt { compact, .. } =
        assemble_sd_jwt(prepared, &issuer_signature).unwrap()
    else {
        panic!("expected proof-bound SD-JWT")
    };
    let verified_credential = verify_sd_jwt(&compact, &issuer.public_jwk, None, None).unwrap();
    assert_eq!(verified_credential["cnf"], json!({"jwk":holder_public}));
    assert_eq!(
        verified_credential["credentialSubject"]["given_name"],
        "Alice"
    );
    assert_eq!(issuer.payloads.lock().unwrap().len(), 1);

    let mut mdoc_claims = claims(CredentialPayloadFormat::default());
    mdoc_claims.credential_type = "org.iso.18013.5.1.mDL".into();
    mdoc_claims.mdoc_namespace = Some("org.iso.18013.5.1".into());
    mdoc_claims.mdoc_doctype = Some("org.iso.18013.5.1.mDL".into());
    let prepared_mdoc = prepare_mdoc_with_credential_id_and_device_key(
        &issuer,
        &mdoc_claims,
        None,
        Some(&holder_public),
    )
    .unwrap();
    let mdoc_signature = issuer.sign(prepared_mdoc.signing_payload()).unwrap();
    let SignedCredential::MsoMdoc {
        issuer_signed_b64, ..
    } = assemble_mdoc(prepared_mdoc, &mdoc_signature).unwrap()
    else {
        panic!("expected holder-bound mDoc")
    };
    let bytes = URL_SAFE_NO_PAD.decode(issuer_signed_b64).unwrap();
    let issuer_signed: isomdl::definitions::IssuerSigned =
        isomdl::cbor::from_slice(&bytes).unwrap();
    assert_eq!(issuer_signed.issuer_auth.signature, mdoc_signature);
    let payloads = issuer.payloads.lock().unwrap();
    assert_eq!(payloads.len(), 2);
    assert_eq!(issuer_signed.issuer_auth.tbs_data(&[]), payloads[1]);
    drop(payloads);

    let tagged_mso: isomdl::definitions::helpers::Tag24<isomdl::definitions::Mso> =
        isomdl::cbor::from_slice(issuer_signed.issuer_auth.payload.as_ref().unwrap()).unwrap();
    let mso = tagged_mso.into_inner();
    assert_eq!(
        mso.device_key_info.device_key,
        isomdl::definitions::CoseKey::EC2 {
            crv: isomdl::definitions::EC2Curve::P256,
            x: URL_SAFE_NO_PAD
                .decode(holder_public["x"].as_str().unwrap())
                .unwrap(),
            y: isomdl::definitions::EC2Y::Value(
                URL_SAFE_NO_PAD
                    .decode(holder_public["y"].as_str().unwrap())
                    .unwrap()
            ),
        }
    );
    assert!(mso.device_key_info.key_authorizations.is_none());
    assert!(mso.device_key_info.key_info.is_none());
}
