//! Local signer agent: authenticated OS IPC in, remote KMS HTTPS out.

use std::time::Duration;

use base64::Engine as _;
use marty_test_wallet::signer_ipc::{
    receive_request, send_response, LocalListener, ReplayCache, SignerAuthenticationKey,
    VerifiedSignRequest,
};
use serde::{Deserialize, Serialize};
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

struct RemoteKms {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    bearer_token: Option<Zeroizing<String>>,
    allowed_key_id: Zeroizing<String>,
}

impl RemoteKms {
    fn from_env() -> Result<Self, String> {
        let endpoint = required_env("MARTY_TEST_SIGNER_AGENT_KMS_URL")?
            .parse::<reqwest::Url>()
            .map_err(|_| "MARTY_TEST_SIGNER_AGENT_KMS_URL must be a valid URL".to_string())?;
        if endpoint.scheme() != "https" || endpoint.cannot_be_a_base() {
            return Err("MARTY_TEST_SIGNER_AGENT_KMS_URL must use HTTPS".into());
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "failed to configure the KMS client".to_string())?;
        let bearer_token = std::env::var("MARTY_TEST_SIGNER_AGENT_KMS_BEARER_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(Zeroizing::new);
        let allowed_key_id =
            Zeroizing::new(required_env("MARTY_TEST_SIGNER_AGENT_ALLOWED_KEY_ID")?);
        Ok(Self {
            client,
            endpoint,
            bearer_token,
            allowed_key_id,
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
        let body = KmsSignRequest {
            algorithm: ALLOWED_KMS_ALGORITHM,
            key_id: self.allowed_key_id.as_str(),
            signing_input: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_input),
        };
        let mut builder = self.client.post(self.endpoint.clone()).json(&body);
        if let Some(token) = self.bearer_token.as_ref() {
            builder = builder.bearer_auth(token.as_str());
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
        let response: KmsSignResponse = serde_json::from_slice(&encoded)
            .map_err(|_| "remote KMS returned invalid JSON".to_string())?;
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(response.signature)
            .map_err(|_| "remote KMS returned invalid base64url".to_string())?;
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
    let mut listener = LocalListener::bind(&endpoint).expect("failed to bind signer IPC endpoint");
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
    use axum::{extract::State, routing::post, Router};
    use tokio::net::TcpListener;

    async fn count_request(State(requests): State<Arc<AtomicUsize>>) -> &'static str {
        requests.fetch_add(1, Ordering::SeqCst);
        r#"{"signature":"unused"}"#
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
