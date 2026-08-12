use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use marty_oid4vci::types::CredentialFormat;
use marty_oid4vci::wallet::{DcqlCredentialQuery, HolderKeyMaterial, WalletEngine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;

#[derive(Clone)]
struct AppState {
    engine: Arc<WalletEngine>,
    wallet: Arc<RwLock<WalletData>>,
}

struct WalletData {
    holder: HolderKeyMaterial,
    credentials: Vec<StoredCredential>,
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "marty_test_wallet=info".into()),
        )
        .init();

    let engine = Arc::new(WalletEngine::new());
    let state = AppState {
        wallet: Arc::new(RwLock::new(WalletData {
            holder: engine.generate_holder_key(),
            credentials: Vec::new(),
        })),
        engine,
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/ready", get(ready))
        .route("/api/credentials", get(list_credentials))
        .route("/api/receive", post(receive_credential))
        .route("/api/present", post(present_credential))
        .route("/api/reset", post(reset_wallet))
        .with_state(state);
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

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn ready() -> Json<Value> {
    Json(serde_json::json!({"status": "ready"}))
}

async fn list_credentials(State(state): State<AppState>) -> Json<Vec<CredentialSummary>> {
    let wallet = state.wallet.read().await;
    Json(
        wallet
            .credentials
            .iter()
            .map(CredentialSummary::from)
            .collect(),
    )
}

async fn reset_wallet(State(state): State<AppState>) -> StatusCode {
    let mut wallet = state.wallet.write().await;
    wallet.holder = state.engine.generate_holder_key();
    wallet.credentials.clear();
    StatusCode::NO_CONTENT
}

async fn receive_credential(
    State(state): State<AppState>,
    Json(request): Json<ReceiveRequest>,
) -> Result<(StatusCode, Json<CredentialSummary>), AppError> {
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
    let holder = {
        let wallet = state.wallet.read().await;
        wallet.holder.clone()
    };
    let proof = state
        .engine
        .create_proof_jwt(
            &format!("{}#{}", holder.holder_id, holder.holder_id),
            &nonce_response.c_nonce,
            &offer.credential_issuer,
            &holder.private_jwk,
        )
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
    state.wallet.write().await.credentials.push(credential);
    Ok((StatusCode::CREATED, Json(summary)))
}

async fn present_credential(
    State(state): State<AppState>,
    Json(request): Json<PresentRequest>,
) -> Result<Json<PresentResponse>, AppError> {
    let presentation_request = state
        .engine
        .parse_presentation_request(request.request_uri.trim())
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let dcql = presentation_request.dcql_query.as_ref().ok_or_else(|| {
        AppError::unprocessable("The browser test wallet requires a DCQL presentation request")
    })?;
    let wallet = state.wallet.read().await;
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
        let credential = wallet
            .credentials
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
            CredentialFormat::SdJwt => state
                .engine
                .create_sd_jwt_presentation(
                    &credential.raw,
                    &claims,
                    &presentation_request.nonce,
                    &presentation_request.client_id,
                    &wallet.holder.private_jwk,
                )
                .map_err(|error| AppError::bad_request(error.to_string()))?,
            CredentialFormat::JwtVcJson => credential.raw.clone(),
            _ => unreachable!("unsupported formats are rejected before selection"),
        };
        presentations.insert(query.id.clone(), presentation);
    }
    drop(wallet);
    let (vp_token, submission) = state
        .engine
        .build_presentation_for_request(&presentation_request, presentations)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let response = state
        .engine
        .submit_presentation_for_request(&presentation_request, &vp_token, submission.as_ref())
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    if !response.ok {
        return Err(AppError::bad_request(
            response
                .error_description
                .or(response.error)
                .unwrap_or_else(|| "Verifier rejected the presentation".to_string()),
        ));
    }
    Ok(Json(PresentResponse {
        ok: true,
        redirect_uri: response.redirect_uri,
    }))
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
