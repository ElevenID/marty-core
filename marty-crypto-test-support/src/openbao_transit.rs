// Test-only scoped signers for the marked disposable OpenBao runner.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use reqwest::{blocking::Client, Url};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use std::time::Duration;

pub struct DisposableOpenBao {
    client: Client,
    base: String,
    root_token: String,
}

#[derive(Debug, Clone, Copy)]
pub struct TransitError;

impl std::fmt::Display for TransitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("disposable OpenBao Transit signing failed")
    }
}

impl std::error::Error for TransitError {}

impl DisposableOpenBao {
    pub fn from_marked_env() -> Self {
        let base = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
        let url = Url::parse(&base).expect("OpenBao URL syntax");
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!(url.port().is_some());
        assert_eq!(url.path(), "/");
        assert!(url.username().is_empty() && url.password().is_none());
        let root_token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable root token");
        let nonce =
            std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE").expect("disposable marker nonce");
        assert!(nonce.len() >= 16);
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
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
        Self {
            client,
            base: base.trim_end_matches('/').into(),
            root_token,
        }
    }

    pub fn create_es256(&self) -> ScopedTransitSigner {
        self.create_key("ecdsa-p256", TestKeyType::Es256, "10m")
    }

    // This shared support module also compiles in unit-test binaries, where
    // the benchmark-only longer lease is intentionally unused.
    #[allow(dead_code)]
    pub fn create_es256_for_benchmark(&self) -> ScopedTransitSigner {
        self.create_key("ecdsa-p256", TestKeyType::Es256, "1h")
    }

    pub fn create_es384(&self) -> ScopedTransitSigner {
        self.create_key("ecdsa-p384", TestKeyType::Es384, "10m")
    }

    pub fn create_ed25519(&self) -> ScopedTransitSigner {
        self.create_key("ed25519", TestKeyType::Ed25519, "10m")
    }

    pub fn create_rsa2048(&self) -> ScopedTransitSigner {
        self.create_key("rsa-2048", TestKeyType::Rsa2048, "10m")
    }

    fn create_key(
        &self,
        key_type: &str,
        algorithm: TestKeyType,
        token_ttl: &str,
    ) -> ScopedTransitSigner {
        let name = format!("marty-core-batch-{}", uuid::Uuid::new_v4().simple());
        self.client
            .post(format!("{}/v1/transit/keys/{name}", self.base))
            .header("X-Vault-Token", &self.root_token)
            .json(&json!({
                "type": key_type,
                "exportable": false,
                "allow_plaintext_backup": false
            }))
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();
        let metadata: Value = self
            .client
            .get(format!("{}/v1/transit/keys/{name}", self.base))
            .header("X-Vault-Token", &self.root_token)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(metadata["data"]["exportable"], false);
        assert_eq!(metadata["data"]["allow_plaintext_backup"], false);
        let public_key = metadata["data"]["keys"]["1"]["public_key"]
            .as_str()
            .expect("OpenBao public key");
        let (public_jwk, public_key_spki) = if algorithm == TestKeyType::Ed25519 {
            let raw = STANDARD.decode(public_key).unwrap();
            assert_eq!(raw.len(), 32);
            let spki = marty_crypto::serialization::raw_public_key_to_spki(&raw, "Ed25519")
                .expect("Ed25519 public SPKI");
            (
                json!({"kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(raw)})
                    .to_string(),
                spki,
            )
        } else {
            (
                marty_crypto::jwk::public_key_pem_to_jwk(public_key)
                    .unwrap()
                    .to_json()
                    .unwrap(),
                marty_crypto::serialization::load_public_key_pem(public_key)
                    .expect("OpenBao public SPKI"),
            )
        };
        let export_path = format!("{}/v1/transit/export/signing-key/{name}", self.base);
        assert!(!self
            .client
            .get(&export_path)
            .header("X-Vault-Token", &self.root_token)
            .send()
            .unwrap()
            .status()
            .is_success());

        let policy_name = format!("marty-core-batch-{}", uuid::Uuid::new_v4().simple());
        let policy = format!("path \"transit/sign/{name}\" {{ capabilities = [\"update\"] }}");
        self.client
            .put(format!("{}/v1/sys/policies/acl/{policy_name}", self.base))
            .header("X-Vault-Token", &self.root_token)
            .json(&json!({"policy": policy}))
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();
        let token: Value = self
            .client
            .post(format!("{}/v1/auth/token/create", self.base))
            .header("X-Vault-Token", &self.root_token)
            .json(&json!({"policies": [policy_name], "no_default_policy": true, "ttl": token_ttl}))
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .unwrap();
        let token = token["auth"]["client_token"]
            .as_str()
            .expect("scoped signing token")
            .to_owned();
        assert_eq!(
            self.client
                .get(export_path)
                .header("X-Vault-Token", &token)
                .send()
                .unwrap()
                .status()
                .as_u16(),
            403
        );
        ScopedTransitSigner {
            client: self.client.clone(),
            base: self.base.clone(),
            token,
            name,
            public_jwk,
            public_key_spki,
            algorithm,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestKeyType {
    Es256,
    Es384,
    Ed25519,
    Rsa2048,
}

#[derive(Clone)]
pub struct ScopedTransitSigner {
    client: Client,
    base: String,
    token: String,
    name: String,
    public_jwk: String,
    public_key_spki: Vec<u8>,
    algorithm: TestKeyType,
}

impl std::fmt::Debug for ScopedTransitSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScopedTransitSigner([redacted])")
    }
}

impl ScopedTransitSigner {
    pub fn key_id(&self, issuer_did: &str) -> String {
        format!("{issuer_did}#{}", self.name)
    }

    pub fn public_jwk(&self) -> &str {
        &self.public_jwk
    }

    pub fn public_key_spki_der(&self) -> &[u8] {
        &self.public_key_spki
    }

    pub fn verifying_key(&self) -> ecdsa_core::VerifyingKey<p256::NistP256> {
        assert_eq!(self.algorithm, TestKeyType::Es256);
        let public: Value = serde_json::from_str(&self.public_jwk).unwrap();
        let mut point = vec![0x04];
        point.extend(
            URL_SAFE_NO_PAD
                .decode(public["x"].as_str().unwrap())
                .unwrap(),
        );
        point.extend(
            URL_SAFE_NO_PAD
                .decode(public["y"].as_str().unwrap())
                .unwrap(),
        );
        ecdsa_core::VerifyingKey::<p256::NistP256>::from_sec1_bytes(&point).unwrap()
    }

    pub fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, TransitError> {
        if self.algorithm != TestKeyType::Es256 {
            return Err(TransitError);
        }
        self.sign_hashed(Sha256::digest(message).as_slice(), "sha2-256", None)
    }

    pub fn sign_es256(&self, message: &[u8]) -> Result<Vec<u8>, TransitError> {
        let signature = self.sign_der(message)?;
        marty_crypto::ecdsa::normalize_signature(&signature, "ES256").map_err(|_| TransitError)
    }

    pub fn sign_es384_der(&self, message: &[u8]) -> Result<Vec<u8>, TransitError> {
        if self.algorithm != TestKeyType::Es384 {
            return Err(TransitError);
        }
        self.sign_hashed(Sha384::digest(message).as_slice(), "sha2-384", None)
    }

    pub fn sign_es384(&self, message: &[u8]) -> Result<Vec<u8>, TransitError> {
        let signature = self.sign_es384_der(message)?;
        marty_crypto::ecdsa::normalize_signature(&signature, "ES384").map_err(|_| TransitError)
    }

    pub fn sign_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, TransitError> {
        if self.algorithm != TestKeyType::Ed25519 {
            return Err(TransitError);
        }
        self.request_signature(json!({"input": STANDARD.encode(message)}))
    }

    pub fn sign_rsa_pss(&self, message: &[u8], algorithm: &str) -> Result<Vec<u8>, TransitError> {
        if self.algorithm != TestKeyType::Rsa2048 {
            return Err(TransitError);
        }
        match algorithm {
            "PS256" => {
                self.sign_hashed(Sha256::digest(message).as_slice(), "sha2-256", Some("pss"))
            }
            "PS384" => {
                self.sign_hashed(Sha384::digest(message).as_slice(), "sha2-384", Some("pss"))
            }
            "PS512" => {
                self.sign_hashed(Sha512::digest(message).as_slice(), "sha2-512", Some("pss"))
            }
            _ => Err(TransitError),
        }
    }

    pub fn sign_rsa_pkcs1(&self, message: &[u8]) -> Result<Vec<u8>, TransitError> {
        if self.algorithm != TestKeyType::Rsa2048 {
            return Err(TransitError);
        }
        self.sign_hashed(
            Sha256::digest(message).as_slice(),
            "sha2-256",
            Some("pkcs1v15"),
        )
    }

    fn sign_hashed(
        &self,
        digest: &[u8],
        hash_algorithm: &str,
        rsa_signature_algorithm: Option<&str>,
    ) -> Result<Vec<u8>, TransitError> {
        let mut body = json!({
            "input": STANDARD.encode(digest),
            "prehashed": true,
            "hash_algorithm": hash_algorithm
        });
        if let Some(signature_algorithm) = rsa_signature_algorithm {
            body["signature_algorithm"] = json!(signature_algorithm);
            if signature_algorithm == "pss" {
                // JOSE PS* uses a hash-length salt; OpenBao's "auto" default is maximal.
                body["salt_length"] = json!("hash");
            }
        }
        self.request_signature(body)
    }

    fn request_signature(&self, body: Value) -> Result<Vec<u8>, TransitError> {
        let response: Value = self
            .client
            .post(format!("{}/v1/transit/sign/{}", self.base, self.name))
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::json)
            .map_err(|_| TransitError)?;
        let encoded = response["data"]["signature"]
            .as_str()
            .and_then(|value| value.rsplit(':').next())
            .ok_or(TransitError)?;
        STANDARD.decode(encoded).map_err(|_| TransitError)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TransitError> {
        let signature = self.sign_der(message)?;
        marty_crypto::ecdsa::normalize_signature(&signature, "ES256").map_err(|_| TransitError)
    }
}
