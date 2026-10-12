//! Local signer agent: authenticated OS IPC in, remote KMS HTTPS out.

use std::time::Duration;

use base64::Engine as _;
use marty_test_wallet::signer_ipc::{
    receive_request, send_response, LocalListener, ReplayCache, SignerAuthenticationKey,
    VerifiedSignRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const MAX_KMS_RESPONSE_BYTES: usize = 16 * 1024;
const ALLOWED_KMS_ALGORITHM: &str = "ES256";

#[derive(Serialize)]
struct KmsSignRequest<'a> {
    algorithm: &'a str,
    key_id: &'a str,
    signing_input: String,
}

#[derive(Deserialize)]
struct KmsSignResponse {
    signature: String,
}

#[derive(Deserialize)]
struct OpenBaoSignResponse {
    data: KmsSignResponse,
}

#[derive(Clone, Copy)]
enum KmsProvider {
    Generic,
    OpenBaoTransit,
}

struct RemoteKms {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    bearer_token: Option<Zeroizing<String>>,
    allowed_key_id: Zeroizing<String>,
    provider: KmsProvider,
}

impl RemoteKms {
    fn from_env() -> Result<Self, String> {
        let endpoint = required_env("MARTY_TEST_SIGNER_AGENT_KMS_URL")?
            .parse::<reqwest::Url>()
            .map_err(|_| "MARTY_TEST_SIGNER_AGENT_KMS_URL must be a valid URL".to_string())?;
        if endpoint.scheme() != "https" || endpoint.cannot_be_a_base() {
            return Err("MARTY_TEST_SIGNER_AGENT_KMS_URL must use HTTPS".into());
        }
        let provider = match std::env::var("MARTY_TEST_SIGNER_AGENT_KMS_PROVIDER")
            .unwrap_or_else(|_| "generic".into())
            .as_str()
        {
            "generic" => KmsProvider::Generic,
            "openbao-transit" => KmsProvider::OpenBaoTransit,
            _ => return Err("unsupported signer agent KMS provider".into()),
        };
        if matches!(provider, KmsProvider::OpenBaoTransit) {
            let segments = endpoint
                .path_segments()
                .ok_or("OpenBao Transit endpoint must be an exact sign route")?
                .collect::<Vec<_>>();
            if segments.len() != 4
                || segments[..3] != ["v1", "transit", "sign"]
                || segments[3].is_empty()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
            {
                return Err("OpenBao Transit endpoint must be an exact sign route".into());
            }
        }
        let mut client_builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
        if let Ok(path) = std::env::var("MARTY_TEST_SIGNER_AGENT_KMS_CA_CERT_PEM") {
            let pem =
                std::fs::read(path).map_err(|_| "KMS CA certificate is unavailable".to_string())?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|_| "KMS CA certificate is invalid".to_string())?;
            client_builder = client_builder.add_root_certificate(certificate);
        }
        let client = client_builder
            .build()
            .map_err(|_| "failed to configure the KMS client".to_string())?;
        let bearer_token = std::env::var("MARTY_TEST_SIGNER_AGENT_KMS_BEARER_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(Zeroizing::new);
        let allowed_key_id =
            Zeroizing::new(required_env("MARTY_TEST_SIGNER_AGENT_ALLOWED_KEY_ID")?);
        if matches!(provider, KmsProvider::OpenBaoTransit) && bearer_token.is_none() {
            return Err("OpenBao Transit requires an agent-scoped token".into());
        }
        Ok(Self {
            client,
            endpoint,
            bearer_token,
            allowed_key_id,
            provider,
        })
    }

    async fn sign(&self, request: &VerifiedSignRequest) -> Result<Vec<u8>, String> {
        self.sign_bound(&request.algorithm, &request.key_id, &request.signing_input)
            .await
    }

    async fn sign_bound(
        &self,
        algorithm: &str,
        key_id: &str,
        signing_input: &[u8],
    ) -> Result<Vec<u8>, String> {
        if algorithm != ALLOWED_KMS_ALGORITHM || key_id != self.allowed_key_id.as_str() {
            return Err("signing request does not match the agent KMS policy".into());
        }
        let mut builder = match self.provider {
            KmsProvider::Generic => self.client.post(self.endpoint.clone()).json(&KmsSignRequest {
                algorithm: ALLOWED_KMS_ALGORITHM,
                key_id: self.allowed_key_id.as_str(),
                signing_input: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(signing_input),
            }),
            KmsProvider::OpenBaoTransit => self.client.post(self.endpoint.clone()).json(&serde_json::json!({
                "input": base64::engine::general_purpose::STANDARD.encode(Sha256::digest(signing_input)),
                "prehashed": true,
                "hash_algorithm": "sha2-256",
            })),
        };
        if let Some(token) = self.bearer_token.as_ref() {
            builder = match self.provider {
                KmsProvider::Generic => builder.bearer_auth(token.as_str()),
                KmsProvider::OpenBaoTransit => builder.header("X-Vault-Token", token.as_str()),
            };
        }
        let mut response = builder
            .send()
            .await
            .map_err(|_| "remote KMS is unavailable".to_string())?
            .error_for_status()
            .map_err(|_| "remote KMS rejected the signing request".to_string())?;
        let mut encoded = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "remote KMS returned invalid data".to_string())?
        {
            if encoded.len().saturating_add(chunk.len()) > MAX_KMS_RESPONSE_BYTES {
                return Err("remote KMS response exceeds its size limit".into());
            }
            encoded.extend_from_slice(&chunk);
        }
        let signature = match self.provider {
            KmsProvider::Generic => {
                let response: KmsSignResponse = serde_json::from_slice(&encoded)
                    .map_err(|_| "remote KMS returned invalid JSON".to_string())?;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(response.signature)
                    .map_err(|_| "remote KMS returned invalid base64url".to_string())?
            }
            KmsProvider::OpenBaoTransit => {
                let response: OpenBaoSignResponse = serde_json::from_slice(&encoded)
                    .map_err(|_| "OpenBao returned invalid JSON".to_string())?;
                let encoded = response.data.signature;
                let (version, signature) = encoded
                    .strip_prefix("vault:v")
                    .and_then(|rest| rest.split_once(':'))
                    .ok_or("OpenBao returned an invalid signature envelope")?;
                if version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err("OpenBao returned an invalid signature version".into());
                }
                let der = base64::engine::general_purpose::STANDARD
                    .decode(signature)
                    .map_err(|_| "OpenBao returned invalid base64".to_string())?;
                marty_crypto::ecdsa::normalize_signature(&der, ALLOWED_KMS_ALGORITHM)
                    .map_err(|_| "OpenBao returned an invalid ES256 signature".to_string())?
            }
        };
        if signature.len() != 64 {
            return Err("remote KMS returned an invalid ES256 signature".into());
        }
        Ok(signature)
    }
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} must be configured"))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let endpoint = required_env("MARTY_TEST_WALLET_HOLDER_SIGNER_ENDPOINT")
        .expect("signer IPC endpoint is required");
    let encoded_authentication_key = Zeroizing::new(
        required_env("MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY")
            .expect("signer IPC authentication key is required"),
    );
    let authentication_key = SignerAuthenticationKey::from_base64url(&encoded_authentication_key)
        .expect("signer IPC authentication key must encode exactly 32 bytes");
    let remote_kms = RemoteKms::from_env().expect("remote KMS configuration is required");
    let listener = LocalListener::bind(&endpoint).expect("failed to bind signer IPC endpoint");
    #[cfg(windows)]
    let mut listener = listener;
    let mut replay_cache = ReplayCache::default();

    loop {
        let accepted = listener.accept().await;
        let mut stream = match accepted {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%error, "signer IPC accept failed");
                continue;
            }
        };
        let request = match tokio::time::timeout(
            Duration::from_secs(15),
            receive_request(&mut stream, &authentication_key, &mut replay_cache),
        )
        .await
        {
            Ok(Ok(request)) => request,
            Ok(Err(error)) => {
                tracing::warn!(%error, "rejected signer IPC request");
                continue;
            }
            Err(_) => {
                tracing::warn!("timed out reading signer IPC request");
                continue;
            }
        };
        let signature = match remote_kms.sign(&request).await {
            Ok(signature) => signature,
            Err(error) => {
                tracing::warn!(%error, "remote KMS signing failed");
                continue;
            }
        };
        if let Err(error) =
            send_response(&mut stream, &authentication_key, &request, &signature).await
        {
            tracing::warn!(%error, "signer IPC response failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;
    use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
    use tokio::net::TcpListener;

    async fn count_request(State(requests): State<Arc<AtomicUsize>>) -> &'static str {
        requests.fetch_add(1, Ordering::SeqCst);
        r#"{"signature":"unused"}"#
    }

    async fn transit_sign(
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        assert_eq!(headers["X-Vault-Token"], "issuer-scope-token");
        assert_eq!(body["prehashed"], true);
        assert_eq!(body["hash_algorithm"], "sha2-256");
        assert_eq!(
            body["input"],
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b"exact-payload"))
        );
        let mut der = vec![0x30, 0x44, 0x02, 0x20];
        der.extend([1u8; 32]);
        der.extend([0x02, 0x20]);
        der.extend([2u8; 32]);
        Json(serde_json::json!({
            "data": {"signature": format!("vault:v7:{}", base64::engine::general_purpose::STANDARD.encode(der))}
        }))
    }

    #[tokio::test]
    async fn openbao_transit_hashes_exact_input_and_normalizes_der() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/v1/transit/sign/issuer", post(transit_sign)),
            )
            .await
            .unwrap();
        });
        let kms = RemoteKms {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            endpoint: format!("http://{address}/v1/transit/sign/issuer")
                .parse()
                .unwrap(),
            bearer_token: Some(Zeroizing::new("issuer-scope-token".to_owned())),
            allowed_key_id: Zeroizing::new("issuer-kid".to_owned()),
            provider: KmsProvider::OpenBaoTransit,
        };
        let signature = kms
            .sign_bound("ES256", "issuer-kid", b"exact-payload")
            .await
            .unwrap();
        assert_eq!(signature.len(), 64);
        assert_eq!(&signature[..32], &[1u8; 32]);
        assert_eq!(&signature[32..], &[2u8; 32]);
        server.abort();
    }

    #[tokio::test]
    async fn mismatched_agent_policy_makes_zero_outbound_requests() {
        let requests = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/", post(count_request))
            .with_state(Arc::clone(&requests));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let kms = RemoteKms {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            endpoint: format!("http://{address}/").parse().unwrap(),
            bearer_token: None,
            allowed_key_id: Zeroizing::new("agent-owned-holder-key".to_owned()),
            provider: KmsProvider::Generic,
        };
        assert!(kms
            .sign_bound(
                ALLOWED_KMS_ALGORITHM,
                "different-key",
                b"attacker-selected input",
            )
            .await
            .is_err());
        assert!(kms
            .sign_bound(
                "ES384",
                "agent-owned-holder-key",
                b"attacker-selected input",
            )
            .await
            .is_err());
        tokio::task::yield_now().await;
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        server.abort();
    }
}
