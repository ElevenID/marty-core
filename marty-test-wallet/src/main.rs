use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header::SET_COOKIE, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use marty_oid4vci::types::{CredentialFormat, SigningAlgorithm};
use marty_oid4vci::wallet::{DcqlCredentialQuery, WalletEngine};
use marty_oid4vci::{ResolvedSdJwtIssuerKey, TrustedSdJwtIssuerKeys};
use marty_test_wallet::holder_signing_probe::{probe_holder_signing, HolderSigningReadiness};
use marty_test_wallet::signer_ipc::{request_signature, SignerAuthenticationKey};
use marty_test_wallet::wallet_sessions::{
    session_cookie, SessionError, SessionLease, WalletSessions, SESSION_COOKIE,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

#[derive(Clone)]
struct AppState {
    engine: Arc<WalletEngine>,
    holder_signer: Arc<RemoteHolderSigner>,
    issuer_resolver: Arc<TrustedSdJwtIssuerKeys>,
    wallet: Arc<RwLock<WalletData>>,
    sessions: Arc<WalletSessions<WalletData>>,
}

#[derive(Default)]
struct WalletData {
    credentials: Vec<StoredCredential>,
}

struct RemoteHolderSigner {
    endpoint: String,
    key_id: String,
    public_jwk_json: String,
    authentication_key: SignerAuthenticationKey,
    readiness: Arc<HolderSigningReadiness>,
}

#[derive(Deserialize)]
struct TrustedIssuerKeyConfig {
    issuer: String,
    key_id: Option<String>,
    algorithm: String,
    public_jwk: Value,
}

#[derive(Clone)]
struct StoredCredential {
    id: String,
    credential_configuration_id: String,
    format: CredentialFormat,
    raw: String,
    vct: Option<String>,
    claim_names: Vec<String>,
    received_at: String,
}

#[derive(Debug, Serialize)]
struct CredentialSummary {
    id: String,
    credential_configuration_id: String,
    format: String,
    vct: Option<String>,
    claim_names: Vec<String>,
    received_at: String,
}

impl From<&StoredCredential> for CredentialSummary {
    fn from(credential: &StoredCredential) -> Self {
        Self {
            id: credential.id.clone(),
            credential_configuration_id: credential.credential_configuration_id.clone(),
            format: credential.format.as_str().to_string(),
            vct: credential.vct.clone(),
            claim_names: credential.claim_names.clone(),
            received_at: credential.received_at.clone(),
        }
    }
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} must be configured"))
}

fn validate_public_jwk_json(value: &str, label: &str) -> Result<(), String> {
    if value.len() > marty_oid4vci::jose::MAX_PUBLIC_JWK_BYTES {
        return Err(format!("{label} exceeds its size limit"));
    }
    let jwk: Value =
        serde_json::from_str(value).map_err(|_| format!("{label} is not valid JSON"))?;
    let object = jwk
        .as_object()
        .ok_or_else(|| format!("{label} must be a JSON object"))?;
    for member in ["d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        if object.contains_key(member) {
            return Err(format!("{label} must not contain private key material"));
        }
    }
    Ok(())
}

impl RemoteHolderSigner {
    fn from_env() -> Result<Self, String> {
        let endpoint = required_env("MARTY_TEST_WALLET_HOLDER_SIGNER_ENDPOINT")?;
        let key_id = required_env("MARTY_TEST_WALLET_HOLDER_KID")?;
        let public_jwk_json = required_env("MARTY_TEST_WALLET_HOLDER_PUBLIC_JWK")?;
        let encoded_authentication_key = Zeroizing::new(required_env(
            "MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY",
        )?);
        let authentication_key = SignerAuthenticationKey::from_base64url(
            &encoded_authentication_key,
        )
        .map_err(|_| {
            "MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY must be canonical base64url for exactly 32 bytes".to_string()
        })?;
        validate_public_jwk_json(&public_jwk_json, "holder public JWK")?;
        let jwk: Value = serde_json::from_str(&public_jwk_json).unwrap();
        if jwk.get("kty").and_then(Value::as_str) != Some("EC")
            || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        {
            return Err("holder public JWK must be an EC P-256 key".into());
        }
        Ok(Self {
            endpoint,
            key_id,
            public_jwk_json,
            authentication_key,
            readiness: Arc::new(HolderSigningReadiness::default()),
        })
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, AppError> {
        let result = request_signature(
            &self.endpoint,
            &self.authentication_key,
            "ES256",
            &self.key_id,
            signing_input,
        )
        .await;
        if result.is_err() {
            self.readiness.invalidate().await;
        }
        result.map_err(|_| AppError::unprocessable("Opaque holder signer rejected the request"))
    }

    async fn check_readiness(self: &Arc<Self>, fresh: bool) -> Result<(), AppError> {
        let signer = self.clone();
        self.readiness
            .check(fresh, move || async move {
                probe_holder_signing(
                    &signer.endpoint,
                    &signer.authentication_key,
                    &signer.key_id,
                    &signer.public_jwk_json,
                )
                .await
                .map(|_| ())
            })
            .await
            .map_err(|_| AppError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                message: "Holder signing is unavailable".into(),
            })
    }
}

fn trusted_issuer_keys_from_env() -> Result<TrustedSdJwtIssuerKeys, String> {
    let encoded = required_env("MARTY_TEST_WALLET_TRUSTED_ISSUER_KEYS")?;
    let configured: Vec<TrustedIssuerKeyConfig> = serde_json::from_str(&encoded)
        .map_err(|_| "MARTY_TEST_WALLET_TRUSTED_ISSUER_KEYS must be a JSON array".to_string())?;
    if configured.is_empty() {
        return Err("MARTY_TEST_WALLET_TRUSTED_ISSUER_KEYS must not be empty".into());
    }
    let keys = configured
        .into_iter()
        .map(|entry| {
            let algorithm = match entry.algorithm.as_str() {
                "ES256" => SigningAlgorithm::ES256,
                "ES384" => SigningAlgorithm::ES384,
                "EdDSA" => SigningAlgorithm::EdDSA,
                "RS256" => SigningAlgorithm::RS256,
                _ => return Err("trusted issuer key uses an unsupported algorithm".to_string()),
            };
            let public_jwk_json = entry.public_jwk.to_string();
            Ok(ResolvedSdJwtIssuerKey::new(
                entry.issuer,
                entry.key_id,
                algorithm,
                public_jwk_json,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    TrustedSdJwtIssuerKeys::new(keys).map_err(|error| error.to_string())
}

#[derive(Debug, Deserialize)]
struct ReceiveRequest {
    offer_uri: String,
    tx_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PresentRequest {
    request_uri: String,
}

#[derive(Debug, Serialize)]
struct PresentResponse {
    ok: bool,
    redirect_uri: Option<String>,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unprocessable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(serde_json::json!({"error": self.message})),
        )
            .into_response()
    }
}

impl From<SessionError> for AppError {
    fn from(error: SessionError) -> Self {
        let status = match error {
            SessionError::InvalidRunId | SessionError::InvalidCookie => StatusCode::BAD_REQUEST,
            SessionError::Missing => StatusCode::GONE,
            SessionError::DuplicateRun => StatusCode::CONFLICT,
            SessionError::Capacity => StatusCode::TOO_MANY_REQUESTS,
            SessionError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        Self {
            status,
            message: error.to_string(),
        }
    }
}

impl AppState {
    async fn session_for(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<SessionLease<WalletData>>, AppError> {
        if headers.get_all("x-marty-wallet-run-id").iter().count() > 1 {
            return Err(AppError::bad_request("Ambiguous wallet run ID"));
        }
        let run_id = headers
            .get("x-marty-wallet-run-id")
            .map(|value| value.to_str())
            .transpose()
            .map_err(|_| AppError::bad_request("Malformed wallet run ID"))?;
        match session_cookie(headers)? {
            Some(token) => {
                let session = self.sessions.get(token).await?;
                if run_id.is_some_and(|run_id| run_id != session.info.run_id) {
                    return Err(AppError {
                        status: StatusCode::FORBIDDEN,
                        message: "The wallet session belongs to another run".into(),
                    });
                }
                Ok(Some(session))
            }
            None if run_id.is_some() => Err(SessionError::Missing.into()),
            None => Ok(None),
        }
    }

    async fn wallet_for(&self, headers: &HeaderMap) -> Result<WalletAccess, AppError> {
        Ok(self
            .session_for(headers)
            .await?
            .map(WalletAccess::Owned)
            .unwrap_or_else(|| WalletAccess::Interactive(Arc::clone(&self.wallet))))
    }
}

enum WalletAccess {
    Interactive(Arc<RwLock<WalletData>>),
    Owned(SessionLease<WalletData>),
}

impl std::ops::Deref for WalletAccess {
    type Target = RwLock<WalletData>;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Interactive(wallet) => wallet,
            Self::Owned(session) => session,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSession {
    run_id: String,
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSession>,
) -> Result<impl IntoResponse, AppError> {
    if session_cookie(&headers)?.is_some() {
        return Err(AppError {
            status: StatusCode::CONFLICT,
            message: "Close the existing isolated wallet session before creating another".into(),
        });
    }
    let (info, token) = state.sessions.create(&request.run_id)?;
    // Keep the cookie for the browser context's lifetime. Server expiry must
    // reject it, not make the browser silently select the interactive wallet.
    let cookie = format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/");
    Ok((StatusCode::CREATED, [(SET_COOKIE, cookie)], Json(info)))
}

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let wallet = state
        .session_for(&headers)
        .await?
        .ok_or(SessionError::Missing)?;
    let mut value = serde_json::to_value(&wallet.info).expect("session info is serializable");
    value["credential_count"] = wallet.read().await.credentials.len().into();
    Ok(Json(value))
}

async fn close_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let token = session_cookie(&headers)?.ok_or(SessionError::Missing)?;
    // End this authorization lease before waiting for the exclusive close.
    drop(
        state
            .session_for(&headers)
            .await?
            .ok_or(SessionError::Missing)?,
    );
    state.sessions.close(token).await?;
    Ok((
        StatusCode::NO_CONTENT,
        [(
            SET_COOKIE,
            format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
        )],
    ))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "marty_test_wallet=info".into()),
        )
        .init();

    let engine = Arc::new(WalletEngine::new());
    let holder_signer = Arc::new(
        RemoteHolderSigner::from_env().expect("opaque holder signer configuration is required"),
    );
    let issuer_resolver = Arc::new(
        trusted_issuer_keys_from_env().expect("trusted issuer key configuration is required"),
    );
    let state = AppState {
        wallet: Arc::new(RwLock::new(WalletData {
            credentials: Vec::new(),
        })),
        engine,
        holder_signer,
        issuer_resolver,
        sessions: Arc::new(WalletSessions::default()),
    };
    let app = wallet_router(state);
    let address =
        std::env::var("MARTY_TEST_WALLET_ADDRESS").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .expect("test wallet listener bind failed");
    tracing::info!(%address, "browser test wallet ready");
    axum::serve(listener, app)
        .await
        .expect("test wallet server failed");
}

fn wallet_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/ready", get(ready))
        .route("/api/sessions", post(create_session))
        .route("/api/session", get(get_session).delete(close_session))
        .route("/api/credentials", get(list_credentials))
        .route("/api/receive", post(receive_credential))
        .route("/api/present", post(present_credential))
        .route("/api/reset", post(reset_wallet))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn ready(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    state.holder_signer.check_readiness(false).await?;
    Ok(Json(
        serde_json::json!({"status": "ready", "instance_id": state.sessions.instance_id(),
        "features": {"isolated_sessions": 1, "holder_signing_preflight": 1}}),
    ))
}

async fn list_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<CredentialSummary>>, AppError> {
    let wallet = state.wallet_for(&headers).await?;
    let wallet = wallet.read().await;
    Ok(Json(
        wallet
            .credentials
            .iter()
            .map(CredentialSummary::from)
            .collect(),
    ))
}

async fn reset_wallet(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let wallet = state.wallet_for(&headers).await?;
    let mut wallet = wallet.write().await;
    wallet.credentials.clear();
    Ok(StatusCode::NO_CONTENT)
}

async fn receive_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ReceiveRequest>,
) -> Result<(StatusCode, Json<CredentialSummary>), AppError> {
    let wallet = state.wallet_for(&headers).await?;
    let offer = state
        .engine
        .parse_credential_offer(request.offer_uri.trim())
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let grant = offer.grants.pre_authorized_code.as_ref().ok_or_else(|| {
        AppError::unprocessable("The test wallet requires a pre-authorized code offer")
    })?;
    if grant.tx_code.is_some() && request.tx_code.as_deref().unwrap_or_default().is_empty() {
        return Err(AppError::unprocessable(
            "This credential offer requires a transaction code",
        ));
    }
    let configuration_id = offer
        .credential_configuration_ids
        .first()
        .cloned()
        .ok_or_else(|| AppError::bad_request("Credential offer contains no configuration"))?;
    let metadata = state
        .engine
        .fetch_issuer_metadata(&offer.credential_issuer)
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let configuration = metadata
        .credential_configurations_supported
        .get(&configuration_id)
        .ok_or_else(|| {
            AppError::unprocessable(format!(
                "Issuer metadata does not publish configuration {configuration_id}"
            ))
        })?;
    let format_name = configuration
        .get("format")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::unprocessable("Credential configuration has no format"))?;
    let format = CredentialFormat::from_str_loose(format_name).ok_or_else(|| {
        AppError::unprocessable(format!("Unsupported credential format {format_name}"))
    })?;
    if !matches!(
        format,
        CredentialFormat::SdJwt | CredentialFormat::JwtVcJson
    ) {
        return Err(AppError::unprocessable(
            "The browser test wallet accepts SD-JWT VC and W3C VC-JWT credentials only",
        ));
    }
    let token_endpoint = state
        .engine
        .resolve_token_endpoint(&metadata)
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    // Detect an already unavailable signer before consuming a one-use offer.
    // This fresh proof intentionally does not trust the routine /ready cache.
    state.holder_signer.check_readiness(true).await?;
    let token = state
        .engine
        .exchange_pre_auth_code(
            &token_endpoint,
            &grant.pre_authorized_code,
            request.tx_code.as_deref(),
        )
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let nonce_endpoint = metadata
        .nonce_endpoint
        .as_deref()
        .ok_or_else(|| AppError::unprocessable("Issuer metadata omitted the nonce endpoint"))?;
    let nonce_response = state
        .engine
        .fetch_nonce(nonce_endpoint)
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let prepared_proof = state
        .engine
        .prepare_proof_jwt(
            &state.holder_signer.key_id,
            &nonce_response.c_nonce,
            &offer.credential_issuer,
            &state.holder_signer.public_jwk_json,
        )
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let proof_signature = state
        .holder_signer
        .sign(prepared_proof.signing_input())
        .await?;
    let proof = prepared_proof
        .complete(&proof_signature)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let response = state
        .engine
        .request_credential(
            &metadata.credential_endpoint,
            &token.access_token,
            &configuration_id,
            &proof,
        )
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let raw = extract_credential(&response).ok_or_else(|| {
        AppError::unprocessable("Credential response contained no credential value")
    })?;
    let payload = decode_credential_payload(&raw, &format)?;
    let vct = credential_vct(&payload);
    let claim_names = credential_claim_names(&raw, &format, &payload);
    let credential = StoredCredential {
        id: uuid::Uuid::new_v4().to_string(),
        credential_configuration_id: configuration_id,
        format,
        vct,
        claim_names,
        raw,
        received_at: chrono::Utc::now().to_rfc3339(),
    };
    let summary = CredentialSummary::from(&credential);
    wallet.write().await.credentials.push(credential);
    Ok((StatusCode::CREATED, Json(summary)))
}

async fn present_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PresentRequest>,
) -> Result<axum::response::Response, AppError> {
    let wallet = state.wallet_for(&headers).await?;
    let presentation_request = state
        .engine
        .parse_presentation_request(request.request_uri.trim())
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let dcql = presentation_request.dcql_query.as_ref().ok_or_else(|| {
        AppError::unprocessable("The browser test wallet requires a DCQL presentation request")
    })?;
    let credentials = wallet.read().await.credentials.clone();
    let mut presentations = HashMap::new();
    for query in &dcql.credentials {
        let requested_format =
            CredentialFormat::from_str_loose(&query.format).ok_or_else(|| {
                AppError::unprocessable(format!(
                    "Unsupported DCQL credential format {}",
                    query.format
                ))
            })?;
        if !matches!(
            requested_format,
            CredentialFormat::SdJwt | CredentialFormat::JwtVcJson
        ) {
            return Err(AppError::unprocessable(format!(
                "Unsupported DCQL credential format {}",
                query.format
            )));
        }
        let credential = credentials
            .iter()
            .find(|credential| credential_matches_query(credential, query, &requested_format))
            .ok_or_else(|| {
                AppError::unprocessable(format!(
                    "No stored credential satisfies DCQL query {}",
                    query.id
                ))
            })?;
        let claims = query
            .claims
            .iter()
            .filter_map(|claim| claim.path.first().cloned())
            .collect::<Vec<_>>();
        let presentation = match requested_format {
            CredentialFormat::SdJwt => {
                let prepared = state
                    .engine
                    .prepare_verified_sd_jwt_presentation(
                        &credential.raw,
                        &claims,
                        &presentation_request.nonce,
                        &presentation_request.client_id,
                        &state.holder_signer.public_jwk_json,
                        state.issuer_resolver.as_ref(),
                    )
                    .map_err(|error| AppError::bad_request(error.to_string()))?;
                let signature = state.holder_signer.sign(prepared.signing_input()).await?;
                prepared
                    .complete(&signature)
                    .map_err(|error| AppError::bad_request(error.to_string()))?
            }
            CredentialFormat::JwtVcJson => credential.raw.clone(),
            _ => unreachable!("unsupported formats are rejected before selection"),
        };
        presentations.insert(query.id.clone(), presentation);
    }
    let (vp_token, submission) = state
        .engine
        .build_presentation_for_request(&presentation_request, presentations)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let response = state
        .engine
        .submit_presentation_for_request(&presentation_request, &vp_token, submission.as_ref())
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    Ok(presentation_response(response))
}

fn presentation_response(
    response: marty_oid4vci::PresentationResponse,
) -> axum::response::Response {
    if !response.ok {
        // Retain the real rejection. A submitted negative presentation is not
        // a successful verification, nor a network failure. The demo must also
        // corroborate its expected denial against the fresh verifier session.
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": response.error_description.as_deref().or(response.error.as_deref())
                    .unwrap_or("Verifier rejected the presentation"),
                "submission": {
                    "submitted": true,
                    "verifier_http_status": response.http_status,
                    "verifier_error": response.error,
                }
            })),
        )
            .into_response();
    }
    Json(PresentResponse {
        ok: true,
        redirect_uri: response.redirect_uri,
    })
    .into_response()
}

fn extract_credential(response: &marty_oid4vci::types::CredentialResponse) -> Option<String> {
    response
        .credential
        .as_ref()
        .and_then(credential_value)
        .or_else(|| {
            response
                .credentials
                .as_ref()
                .and_then(|credentials| credentials.first())
                .and_then(credential_value)
        })
}

fn credential_value(value: &Value) -> Option<String> {
    value.as_str().map(str::to_string).or_else(|| {
        value
            .get("credential")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

fn decode_credential_payload(raw: &str, format: &CredentialFormat) -> Result<Value, AppError> {
    let (jwt, label) = match format {
        CredentialFormat::SdJwt => (raw.split('~').next().unwrap_or_default(), "SD-JWT"),
        CredentialFormat::JwtVcJson => (raw, "VC-JWT"),
        _ => {
            return Err(AppError::unprocessable(
                "Unsupported credential payload format",
            ))
        }
    };
    let payload = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| AppError::bad_request(format!("Issued {label} has no JWT payload")))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| AppError::bad_request(format!("Invalid {label} payload: {error}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| AppError::bad_request(format!("Invalid {label} claims: {error}")))
}

fn credential_vct(payload: &Value) -> Option<String> {
    payload
        .get("vct")
        .or_else(|| payload.pointer("/vc/credentialSchema/id"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn credential_claim_names(raw: &str, format: &CredentialFormat, payload: &Value) -> Vec<String> {
    let mut claims = match format {
        CredentialFormat::SdJwt => disclosed_claim_names(raw),
        CredentialFormat::JwtVcJson => payload
            .pointer("/vc/credentialSubject")
            .and_then(Value::as_object)
            .map(|subject| subject.keys().cloned().collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    claims.sort();
    claims.dedup();
    claims
}

fn credential_matches_query(
    credential: &StoredCredential,
    query: &DcqlCredentialQuery,
    requested_format: &CredentialFormat,
) -> bool {
    if &credential.format != requested_format {
        return false;
    }
    match requested_format {
        CredentialFormat::SdJwt => {
            let accepted_vcts = query
                .meta
                .as_ref()
                .and_then(|meta| meta.get("vct_values"))
                .and_then(Value::as_array)
                .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .unwrap_or_default();
            accepted_vcts.is_empty()
                || credential
                    .vct
                    .as_deref()
                    .is_some_and(|vct| accepted_vcts.contains(&vct))
        }
        CredentialFormat::JwtVcJson => jwt_vc_matches_type_values(&credential.raw, query),
        _ => false,
    }
}

fn jwt_vc_matches_type_values(raw: &str, query: &DcqlCredentialQuery) -> bool {
    let accepted_type_sets = query
        .meta
        .as_ref()
        .and_then(|meta| meta.get("type_values"))
        .and_then(Value::as_array)
        .map(|sets| {
            sets.iter()
                .filter_map(Value::as_array)
                .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .filter(|values| !values.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if accepted_type_sets.is_empty() {
        return true;
    }
    let Ok(payload) = decode_credential_payload(raw, &CredentialFormat::JwtVcJson) else {
        return false;
    };
    let credential_types = payload
        .pointer("/vc/type")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    accepted_type_sets.iter().any(|required| {
        required
            .iter()
            .all(|value| credential_types.contains(value))
    })
}

fn disclosed_claim_names(raw: &str) -> Vec<String> {
    let mut claims = raw
        .split('~')
        .skip(1)
        .filter_map(|disclosure| {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(disclosure)
                .ok()?;
            let value: Value = serde_json::from_slice(&decoded).ok()?;
            value.get(1)?.as_str().map(str::to_string)
        })
        .collect::<Vec<_>>();
    claims.sort();
    claims.dedup();
    claims
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verifier_rejection_retains_transport_evidence_without_success() {
        let response = presentation_response(marty_oid4vci::PresentationResponse {
            ok: false,
            http_status: Some(400),
            redirect_uri: None,
            error: Some("invalid_presentation".into()),
            error_description: None,
        });
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"], "invalid_presentation");
        assert_eq!(body["submission"]["submitted"], true);
        assert_eq!(body["submission"]["verifier_http_status"], 400);
        assert_eq!(body["submission"]["verifier_error"], "invalid_presentation");
    }

    fn test_state() -> AppState {
        // These in-memory records test storage isolation; they are deliberately
        // not cryptographic issuance or production-wallet qualification evidence.
        let public_jwk = serde_json::json!({"kty":"EC", "crv":"P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hex::decode(
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296").unwrap()),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hex::decode(
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap())});
        AppState {
            engine: Arc::new(WalletEngine::new()),
            holder_signer: Arc::new(RemoteHolderSigner {
                endpoint: "/unused-test-signer.sock".into(),
                key_id: "test-holder".into(),
                public_jwk_json: public_jwk.to_string(),
                authentication_key: SignerAuthenticationKey::from_base64url(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]),
                )
                .unwrap(),
                readiness: Arc::new(HolderSigningReadiness::default()),
            }),
            issuer_resolver: Arc::new(
                TrustedSdJwtIssuerKeys::new(vec![ResolvedSdJwtIssuerKey::new(
                    "https://issuer.example",
                    None,
                    SigningAlgorithm::ES256,
                    public_jwk.to_string(),
                )])
                .unwrap(),
            ),
            wallet: Arc::new(RwLock::new(WalletData::default())),
            sessions: Arc::new(WalletSessions::default()),
        }
    }

    #[tokio::test]
    async fn unavailable_signer_blocks_readiness_and_preserves_one_use_offer() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let token_requests = Arc::new(AtomicUsize::new(0));
        let metadata_requests = Arc::new(AtomicUsize::new(0));
        let issuer_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", issuer_listener.local_addr().unwrap());
        let metadata = serde_json::json!({
            "credential_issuer": issuer, "token_endpoint": format!("{issuer}/token"),
            "credential_endpoint": format!("{issuer}/credential"),
            "credential_configurations_supported": {"owned": {"format":"vc+sd-jwt"}}
        });
        let metadata_counter = metadata_requests.clone();
        let token_counter = token_requests.clone();
        let issuer_app = Router::new()
            .route(
                "/.well-known/openid-credential-issuer",
                get(move || {
                    metadata_counter.fetch_add(1, Ordering::SeqCst);
                    let value = metadata.clone();
                    async move { Json(value) }
                }),
            )
            .route(
                "/token",
                post(move || {
                    token_counter.fetch_add(1, Ordering::SeqCst);
                    async { StatusCode::INTERNAL_SERVER_ERROR }
                }),
            );
        let issuer_server = tokio::spawn(async move {
            axum::serve(issuer_listener, issuer_app).await.unwrap();
        });
        let state = test_state();
        let wallet_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let wallet = format!("http://{}", wallet_listener.local_addr().unwrap());
        let app = wallet_router(state.clone());
        let wallet_server = tokio::spawn(async move {
            axum::serve(wallet_listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let ready = client.get(format!("{wallet}/ready")).send().await.unwrap();
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            ready.json::<Value>().await.unwrap(),
            serde_json::json!({"error":"Holder signing is unavailable"})
        );
        let offer = serde_json::json!({"credential_issuer":issuer,
            "credential_configuration_ids":["owned"],
            "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":uuid::Uuid::new_v4().to_string()}}});
        let mut offer_uri = reqwest::Url::parse("https://offer.invalid/").unwrap();
        offer_uri
            .query_pairs_mut()
            .append_pair("credential_offer", &offer.to_string());
        let response = client
            .post(format!("{wallet}/api/receive"))
            .json(&serde_json::json!({"offer_uri":offer_uri.as_str()}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(metadata_requests.load(Ordering::SeqCst), 1);
        assert_eq!(token_requests.load(Ordering::SeqCst), 0);
        assert!(state.wallet.read().await.credentials.is_empty());
        wallet_server.abort();
        let _ = wallet_server.await;
        issuer_server.abort();
        let _ = issuer_server.await;
    }

    #[tokio::test]
    async fn wallet_sessions_http_bind_run_ownership_and_preserve_other_wallets() {
        let state = test_state();
        let record = |id: &str| StoredCredential {
            id: id.into(),
            credential_configuration_id: "isolation-test".into(),
            format: CredentialFormat::SdJwt,
            raw: "not-a-real-credential".into(),
            vct: None,
            claim_names: vec![],
            received_at: "2026-01-01T00:00:00Z".into(),
        };
        state
            .wallet
            .write()
            .await
            .credentials
            .push(record("interactive"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = wallet_router(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::new();
        let mut cookies = Vec::new();
        for run in ["run-a", "run-b"] {
            let response = client
                .post(format!("{base}/api/sessions"))
                .json(&serde_json::json!({"run_id":run}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
            let header = response.headers()[SET_COOKIE].to_str().unwrap().to_string();
            assert!(header.contains("HttpOnly") && header.contains("SameSite=Strict"));
            assert!(!header.contains("Max-Age"));
            let cookie = header.split(';').next().unwrap().to_string();
            let token = uuid::Uuid::parse_str(cookie.split('=').nth(1).unwrap()).unwrap();
            let public_info: Value = response.json().await.unwrap();
            assert_eq!(public_info["run_id"], run);
            assert!(!public_info.to_string().contains(&token.to_string()));
            state
                .sessions
                .get(token)
                .await
                .unwrap()
                .write()
                .await
                .credentials
                .push(record(run));
            cookies.push(cookie);
        }
        let reset = |cookie: Option<String>, run: &str| {
            let mut request = client
                .post(format!("{base}/api/reset"))
                .header("x-marty-wallet-run-id", run);
            if let Some(cookie) = cookie {
                request = request.header("cookie", cookie);
            }
            request.send()
        };
        assert_eq!(
            reset(Some(cookies[0].clone()), "run-b")
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            reset(None, "run-a").await.unwrap().status(),
            StatusCode::GONE
        );
        assert_eq!(
            reset(Some(format!("{}; {}", cookies[0], cookies[1])), "run-a")
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            reset(Some(cookies[0].clone()), "run-a")
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        let inventory: Vec<Value> = client
            .get(format!("{base}/api/credentials"))
            .header("cookie", &cookies[1])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0]["id"], "run-b");
        assert_eq!(
            client
                .delete(format!("{base}/api/session"))
                .header("cookie", &cookies[1])
                .header("x-marty-wallet-run-id", "run-a")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .delete(format!("{base}/api/session"))
                .header("cookie", &cookies[0])
                .header("x-marty-wallet-run-id", "run-a")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            reset(Some(cookies[0].clone()), "run-a")
                .await
                .unwrap()
                .status(),
            StatusCode::GONE
        );
        assert_eq!(state.wallet.read().await.credentials[0].id, "interactive");
        server.abort();
    }

    #[test]
    fn credential_value_accepts_canonical_single_and_batch_values() {
        assert_eq!(
            credential_value(&Value::String("jwt".into())).as_deref(),
            Some("jwt")
        );
        assert_eq!(
            credential_value(&serde_json::json!({"format": "dc+sd-jwt", "credential": "sd-jwt"}))
                .as_deref(),
            Some("sd-jwt")
        );
    }

    #[test]
    fn private_credential_material_is_not_serialized_in_summary() {
        let stored = StoredCredential {
            id: "id-1".into(),
            credential_configuration_id: "member".into(),
            format: CredentialFormat::SdJwt,
            raw: "sensitive.raw.credential".into(),
            vct: Some("https://issuer.example/member".into()),
            claim_names: vec!["email".into()],
            received_at: "2026-01-01T00:00:00Z".into(),
        };
        let serialized = serde_json::to_string(&CredentialSummary::from(&stored)).unwrap();
        assert!(!serialized.contains("sensitive.raw.credential"));
    }

    fn jwt(payload: Value) -> String {
        format!(
            "header.{}.signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string())
        )
    }

    #[test]
    fn vc_jwt_payload_exposes_subject_claim_names() {
        let raw = jwt(serde_json::json!({
            "vc": {
                "type": ["VerifiableCredential", "open_badge"],
                "credentialSubject": {"email": "holder@example.test", "role": "member"}
            }
        }));
        let payload = decode_credential_payload(&raw, &CredentialFormat::JwtVcJson).unwrap();

        assert_eq!(
            credential_claim_names(&raw, &CredentialFormat::JwtVcJson, &payload),
            vec!["email", "role"]
        );
    }

    #[test]
    fn vc_jwt_matches_dcql_type_values_fail_closed() {
        let raw = jwt(serde_json::json!({
            "vc": {
                "type": ["VerifiableCredential", "open_badge"],
                "credentialSubject": {"email": "holder@example.test"}
            }
        }));
        let credential = StoredCredential {
            id: "id-1".into(),
            credential_configuration_id: "OpenBadgeCredential#jwt-vc".into(),
            format: CredentialFormat::JwtVcJson,
            raw,
            vct: None,
            claim_names: vec!["email".into()],
            received_at: "2026-01-01T00:00:00Z".into(),
        };
        let matching = DcqlCredentialQuery {
            id: "badge".into(),
            format: "jwt_vc_json".into(),
            meta: Some(serde_json::json!({
                "type_values": [["VerifiableCredential", "open_badge"]]
            })),
            claims: Vec::new(),
        };
        let wrong = DcqlCredentialQuery {
            meta: Some(serde_json::json!({
                "type_values": [["VerifiableCredential", "EmployeeCredential"]]
            })),
            ..matching.clone()
        };

        assert!(credential_matches_query(
            &credential,
            &matching,
            &CredentialFormat::JwtVcJson
        ));
        assert!(!credential_matches_query(
            &credential,
            &wrong,
            &CredentialFormat::JwtVcJson
        ));
    }

    #[test]
    fn sd_jwt_vct_matching_remains_strict() {
        let credential = StoredCredential {
            id: "id-1".into(),
            credential_configuration_id: "MemberCredential#sd-jwt".into(),
            format: CredentialFormat::SdJwt,
            raw: "issuer.payload.signature~disclosure".into(),
            vct: Some("https://issuer.example/member".into()),
            claim_names: vec!["email".into()],
            received_at: "2026-01-01T00:00:00Z".into(),
        };
        let matching = DcqlCredentialQuery {
            id: "member".into(),
            format: "dc+sd-jwt".into(),
            meta: Some(serde_json::json!({
                "vct_values": ["https://issuer.example/member"]
            })),
            claims: Vec::new(),
        };
        let wrong = DcqlCredentialQuery {
            meta: Some(serde_json::json!({
                "vct_values": ["https://issuer.example/employee"]
            })),
            ..matching.clone()
        };

        assert!(credential_matches_query(
            &credential,
            &matching,
            &CredentialFormat::SdJwt
        ));
        assert!(!credential_matches_query(
            &credential,
            &wrong,
            &CredentialFormat::SdJwt
        ));
    }
}
