// Test-only scoped ES256 signer for the marked disposable OpenBao runner.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{blocking::Client, Url};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::time::Duration;

pub struct DisposableOpenBao {
    client: Client,
    base: String,
    root_token: String,
}

impl DisposableOpenBao {
    pub fn from_marked_env() -> Self {
        let base = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
        let url = Url::parse(&base).expect("OpenBao URL syntax");
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!(url.port().is_some());
        assert_eq!(url.path(), "/");
        assert!(url.username().is_empty() && url.password().is_none());
        let root_token =
            std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable root token");
        let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE")
            .expect("disposable marker nonce");
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

    pub fn create_es256(&self) -> ScopedEs256Signer {
        let name = format!("marty-core-batch-{}", uuid::Uuid::new_v4().simple());
        self.client
            .post(format!("{}/v1/transit/keys/{name}", self.base))
            .header("X-Vault-Token", &self.root_token)
            .json(&json!({
                "type": "ecdsa-p256",
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
        let public_pem = metadata["data"]["keys"]["1"]["public_key"]
            .as_str()
            .expect("OpenBao public key");
        let public_jwk = marty_crypto::jwk::public_key_pem_to_jwk(public_pem)
            .unwrap()
            .to_json()
            .unwrap();
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
            .json(&json!({"policies": [policy_name], "no_default_policy": true, "ttl": "10m"}))
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
        ScopedEs256Signer {
            client: self.client.clone(),
            base: self.base.clone(),
            token,
            name,
            public_jwk,
        }
    }
}

#[derive(Clone)]
pub struct ScopedEs256Signer {
    client: Client,
    base: String,
    token: String,
    name: String,
    public_jwk: String,
}

impl std::fmt::Debug for ScopedEs256Signer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScopedEs256Signer([redacted])")
    }
}

impl ScopedEs256Signer {
    pub fn key_id(&self, issuer_did: &str) -> String {
        format!("{issuer_did}#{}", self.name)
    }

    pub fn public_jwk(&self) -> &str {
        &self.public_jwk
    }

    pub fn verifying_key(&self) -> p256::ecdsa::VerifyingKey {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let public: Value = serde_json::from_str(&self.public_jwk).unwrap();
        let mut point = vec![0x04];
        point.extend(URL_SAFE_NO_PAD.decode(public["x"].as_str().unwrap()).unwrap());
        point.extend(URL_SAFE_NO_PAD.decode(public["y"].as_str().unwrap()).unwrap());
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap()
    }

    pub fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, ()> {
        let response: Value = self
            .client
            .post(format!("{}/v1/transit/sign/{}", self.base, self.name))
            .header("X-Vault-Token", &self.token)
            .json(&json!({
                "input": STANDARD.encode(Sha256::digest(message)),
                "prehashed": true,
                "hash_algorithm": "sha2-256"
            }))
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::json)
            .map_err(|_| ())?;
        let encoded = response["data"]["signature"]
            .as_str()
            .and_then(|value| value.rsplit(':').next())
            .ok_or(())?;
        STANDARD.decode(encoded).map_err(|_| ())
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ()> {
        let signature = self.sign_der(message)?;
        marty_crypto::ecdsa::normalize_signature(&signature, "ES256").map_err(|_| ())
    }
}
