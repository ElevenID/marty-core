//! Authenticated local IPC for the test wallet's remote-KMS signer agent.

use std::collections::HashMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const PROTOCOL_VERSION: u8 = 1;
const MAX_FRAME_BYTES: usize = 96 * 1024;
const MAX_SIGNING_INPUT_BYTES: usize = 64 * 1024;
const MAX_KEY_ID_BYTES: usize = 512;
const MAX_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_REPLAY_ENTRIES: usize = 4096;
const REQUEST_DOMAIN: &[u8] = b"marty-test-wallet/signer-request/v1\0";
const RESPONSE_DOMAIN: &[u8] = b"marty-test-wallet/signer-response/v1\0";
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum SignerIpcError {
    #[error("signer IPC endpoint is invalid")]
    InvalidEndpoint,
    #[error("signer IPC authentication key is invalid")]
    InvalidAuthenticationKey,
    #[error("signer IPC request is malformed")]
    InvalidRequest,
    #[error("signer IPC response is malformed")]
    InvalidResponse,
    #[error("signer IPC authentication failed")]
    AuthenticationFailed,
    #[error("signer IPC request is stale")]
    StaleRequest,
    #[error("signer IPC request was replayed")]
    ReplayedRequest,
    #[error("signer IPC frame exceeds its size limit")]
    FrameTooLarge,
    #[error("signer IPC request timed out")]
    Timeout,
    #[error("signer IPC transport failed")]
    Transport(#[from] io::Error),
    #[error("signer IPC connection failed")]
    Connection(io::Error),
}

pub struct SignerAuthenticationKey(Zeroizing<[u8; 32]>);

impl SignerAuthenticationKey {
    pub fn from_base64url(encoded: &str) -> Result<Self, SignerIpcError> {
        let decoded = Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| SignerIpcError::InvalidAuthenticationKey)?,
        );
        if decoded.len() != 32
            || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*decoded) != encoded
        {
            return Err(SignerIpcError::InvalidAuthenticationKey);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(Self(Zeroizing::new(key)))
    }

    #[cfg(test)]
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn mac(&self, domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
        let mut mac =
            HmacSha256::new_from_slice(self.0.as_ref()).expect("HMAC accepts every 256-bit key");
        mac.update(domain);
        for field in fields {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        mac.finalize().into_bytes().into()
    }

    fn verify(
        &self,
        domain: &[u8],
        fields: &[&[u8]],
        supplied: &[u8],
    ) -> Result<(), SignerIpcError> {
        let mut mac =
            HmacSha256::new_from_slice(self.0.as_ref()).expect("HMAC accepts every 256-bit key");
        mac.update(domain);
        for field in fields {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        mac.verify_slice(supplied)
            .map_err(|_| SignerIpcError::AuthenticationFailed)
    }
}

impl std::fmt::Debug for SignerAuthenticationKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SignerAuthenticationKey([redacted])")
    }
}

impl Drop for SignerAuthenticationKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthenticatedSignRequest {
    version: u8,
    nonce: String,
    issued_at: i64,
    algorithm: String,
    key_id: String,
    signing_input: String,
    authentication_tag: String,
}

impl Drop for AuthenticatedSignRequest {
    fn drop(&mut self) {
        self.key_id.zeroize();
        self.signing_input.zeroize();
        self.authentication_tag.zeroize();
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthenticatedSignResponse {
    version: u8,
    nonce: String,
    signature: String,
    authentication_tag: String,
}

pub struct VerifiedSignRequest {
    pub algorithm: String,
    pub key_id: String,
    pub signing_input: Zeroizing<Vec<u8>>,
    nonce: Uuid,
}

impl std::fmt::Debug for VerifiedSignRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedSignRequest")
            .field("algorithm", &self.algorithm)
            .field("key_id", &"[redacted]")
            .field("signing_input", &"[redacted]")
            .finish()
    }
}

#[derive(Default)]
pub struct ReplayCache {
    accepted: HashMap<Uuid, i64>,
}

impl ReplayCache {
    fn accept(&mut self, nonce: Uuid, issued_at: i64, now: i64) -> Result<(), SignerIpcError> {
        self.accepted
            .retain(|_, timestamp| now.saturating_sub(*timestamp) <= MAX_CLOCK_SKEW_SECONDS);
        if self.accepted.contains_key(&nonce) {
            return Err(SignerIpcError::ReplayedRequest);
        }
        if self.accepted.len() >= MAX_REPLAY_ENTRIES {
            return Err(SignerIpcError::FrameTooLarge);
        }
        self.accepted.insert(nonce, issued_at);
        Ok(())
    }
}

fn unix_timestamp() -> Result<i64, SignerIpcError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SignerIpcError::StaleRequest)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| SignerIpcError::StaleRequest)
}

fn decode_canonical(
    value: &str,
    invalid: fn() -> SignerIpcError,
) -> Result<Vec<u8>, SignerIpcError> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid())?;
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(invalid());
    }
    Ok(decoded)
}

fn build_request(
    key: &SignerAuthenticationKey,
    algorithm: &str,
    key_id: &str,
    signing_input: &[u8],
    nonce: Uuid,
    issued_at: i64,
) -> Result<AuthenticatedSignRequest, SignerIpcError> {
    if algorithm != "ES256"
        || key_id.is_empty()
        || key_id.len() > MAX_KEY_ID_BYTES
        || signing_input.is_empty()
        || signing_input.len() > MAX_SIGNING_INPUT_BYTES
    {
        return Err(SignerIpcError::InvalidRequest);
    }
    let nonce_text = nonce.hyphenated().to_string();
    let issued_at_bytes = issued_at.to_be_bytes();
    let signing_input = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_input);
    let tag = key.mac(
        REQUEST_DOMAIN,
        &[
            &[PROTOCOL_VERSION],
            nonce_text.as_bytes(),
            &issued_at_bytes,
            algorithm.as_bytes(),
            key_id.as_bytes(),
            signing_input.as_bytes(),
        ],
    );
    Ok(AuthenticatedSignRequest {
        version: PROTOCOL_VERSION,
        nonce: nonce_text,
        issued_at,
        algorithm: algorithm.to_owned(),
        key_id: key_id.to_owned(),
        signing_input,
        authentication_tag: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag),
    })
}

fn verify_request(
    key: &SignerAuthenticationKey,
    replay_cache: &mut ReplayCache,
    request: AuthenticatedSignRequest,
    now: i64,
) -> Result<VerifiedSignRequest, SignerIpcError> {
    if request.version != PROTOCOL_VERSION
        || request.algorithm != "ES256"
        || request.key_id.is_empty()
        || request.key_id.len() > MAX_KEY_ID_BYTES
    {
        return Err(SignerIpcError::InvalidRequest);
    }
    let nonce = Uuid::parse_str(&request.nonce).map_err(|_| SignerIpcError::InvalidRequest)?;
    if nonce.hyphenated().to_string() != request.nonce {
        return Err(SignerIpcError::InvalidRequest);
    }
    let tag = decode_canonical(&request.authentication_tag, || {
        SignerIpcError::AuthenticationFailed
    })?;
    let issued_at_bytes = request.issued_at.to_be_bytes();
    key.verify(
        REQUEST_DOMAIN,
        &[
            &[request.version],
            request.nonce.as_bytes(),
            &issued_at_bytes,
            request.algorithm.as_bytes(),
            request.key_id.as_bytes(),
            request.signing_input.as_bytes(),
        ],
        &tag,
    )?;
    if now.abs_diff(request.issued_at) > MAX_CLOCK_SKEW_SECONDS as u64 {
        return Err(SignerIpcError::StaleRequest);
    }
    let signing_input = Zeroizing::new(decode_canonical(&request.signing_input, || {
        SignerIpcError::InvalidRequest
    })?);
    if signing_input.is_empty() || signing_input.len() > MAX_SIGNING_INPUT_BYTES {
        return Err(SignerIpcError::InvalidRequest);
    }
    replay_cache.accept(nonce, request.issued_at, now)?;
    Ok(VerifiedSignRequest {
        algorithm: request.algorithm.clone(),
        key_id: request.key_id.clone(),
        signing_input,
        nonce,
    })
}

fn build_response(
    key: &SignerAuthenticationKey,
    request: &VerifiedSignRequest,
    signature: &[u8],
) -> Result<AuthenticatedSignResponse, SignerIpcError> {
    if signature.len() != 64 {
        return Err(SignerIpcError::InvalidResponse);
    }
    let nonce = request.nonce.hyphenated().to_string();
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
    let tag = key.mac(
        RESPONSE_DOMAIN,
        &[&[PROTOCOL_VERSION], nonce.as_bytes(), signature.as_bytes()],
    );
    Ok(AuthenticatedSignResponse {
        version: PROTOCOL_VERSION,
        nonce,
        signature,
        authentication_tag: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag),
    })
}

fn verify_response(
    key: &SignerAuthenticationKey,
    expected_nonce: Uuid,
    response: AuthenticatedSignResponse,
) -> Result<Vec<u8>, SignerIpcError> {
    let expected_nonce = expected_nonce.hyphenated().to_string();
    if response.version != PROTOCOL_VERSION || response.nonce != expected_nonce {
        return Err(SignerIpcError::InvalidResponse);
    }
    let tag = decode_canonical(&response.authentication_tag, || {
        SignerIpcError::AuthenticationFailed
    })?;
    key.verify(
        RESPONSE_DOMAIN,
        &[
            &[response.version],
            response.nonce.as_bytes(),
            response.signature.as_bytes(),
        ],
        &tag,
    )?;
    let signature = decode_canonical(&response.signature, || SignerIpcError::InvalidResponse)?;
    if signature.len() != 64 {
        return Err(SignerIpcError::InvalidResponse);
    }
    Ok(signature)
}

async fn write_json_frame<W: AsyncWrite + Unpin, T: Serialize>(
    stream: &mut W,
    value: &T,
) -> Result<(), SignerIpcError> {
    let encoded = serde_json::to_vec(value).map_err(|_| SignerIpcError::InvalidRequest)?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(SignerIpcError::FrameTooLarge);
    }
    stream.write_u32(encoded.len() as u32).await?;
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_json_frame<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    stream: &mut R,
) -> Result<T, SignerIpcError> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(SignerIpcError::FrameTooLarge);
    }
    let mut encoded = Zeroizing::new(vec![0u8; length]);
    stream.read_exact(&mut encoded).await?;
    serde_json::from_slice(&encoded).map_err(|_| SignerIpcError::InvalidRequest)
}

#[cfg(windows)]
pub type LocalStream = tokio::net::windows::named_pipe::NamedPipeClient;
#[cfg(unix)]
pub type LocalStream = tokio::net::UnixStream;

#[cfg(windows)]
async fn connect(endpoint: &str) -> Result<LocalStream, SignerIpcError> {
    if !endpoint.starts_with(r"\\.\pipe\marty-test-wallet-") {
        return Err(SignerIpcError::InvalidEndpoint);
    }
    tokio::net::windows::named_pipe::ClientOptions::new()
        .open(endpoint)
        .map_err(SignerIpcError::Connection)
}

#[cfg(unix)]
async fn connect(endpoint: &str) -> Result<LocalStream, SignerIpcError> {
    let path = std::path::Path::new(endpoint);
    if !path.is_absolute() {
        return Err(SignerIpcError::InvalidEndpoint);
    }
    tokio::net::UnixStream::connect(path)
        .await
        .map_err(SignerIpcError::Connection)
}

pub async fn request_signature(
    endpoint: &str,
    key: &SignerAuthenticationKey,
    algorithm: &str,
    key_id: &str,
    signing_input: &[u8],
) -> Result<Vec<u8>, SignerIpcError> {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let nonce = Uuid::new_v4();
        let request = build_request(
            key,
            algorithm,
            key_id,
            signing_input,
            nonce,
            unix_timestamp()?,
        )?;
        let mut stream = connect(endpoint).await?;
        write_json_frame(&mut stream, &request).await?;
        let response: AuthenticatedSignResponse = read_json_frame(&mut stream).await?;
        verify_response(key, nonce, response)
    })
    .await
    .map_err(|_| SignerIpcError::Timeout)?
}

#[cfg(unix)]
pub struct LocalListener {
    listener: tokio::net::UnixListener,
    path: std::path::PathBuf,
}

#[cfg(unix)]
impl LocalListener {
    pub fn bind(endpoint: &str) -> Result<Self, SignerIpcError> {
        use std::os::unix::fs::PermissionsExt as _;

        let path = std::path::PathBuf::from(endpoint);
        let parent = path.parent().ok_or(SignerIpcError::InvalidEndpoint)?;
        let metadata = std::fs::metadata(parent).map_err(SignerIpcError::Transport)?;
        if !path.is_absolute() || metadata.permissions().mode() & 0o077 != 0 || path.exists() {
            return Err(SignerIpcError::InvalidEndpoint);
        }
        let listener = tokio::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { listener, path })
    }

    pub async fn accept(&self) -> Result<tokio::net::UnixStream, SignerIpcError> {
        let (stream, _) = self.listener.accept().await?;
        Ok(stream)
    }
}

#[cfg(unix)]
impl Drop for LocalListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(windows)]
pub struct LocalListener {
    endpoint: String,
    pending: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
}

#[cfg(windows)]
impl LocalListener {
    pub fn bind(endpoint: &str) -> Result<Self, SignerIpcError> {
        if !endpoint.starts_with(r"\\.\pipe\marty-test-wallet-") {
            return Err(SignerIpcError::InvalidEndpoint);
        }
        let pending = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(endpoint)?;
        Ok(Self {
            endpoint: endpoint.to_owned(),
            pending: Some(pending),
        })
    }

    pub async fn accept(
        &mut self,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, SignerIpcError> {
        let server = self.pending.take().ok_or(SignerIpcError::InvalidEndpoint)?;
        server.connect().await?;
        let next = tokio::net::windows::named_pipe::ServerOptions::new()
            .reject_remote_clients(true)
            .create(&self.endpoint)?;
        self.pending = Some(next);
        Ok(server)
    }
}

pub async fn receive_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    key: &SignerAuthenticationKey,
    replay_cache: &mut ReplayCache,
) -> Result<VerifiedSignRequest, SignerIpcError> {
    let request: AuthenticatedSignRequest = read_json_frame(stream).await?;
    verify_request(key, replay_cache, request, unix_timestamp()?)
}

pub async fn send_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    key: &SignerAuthenticationKey,
    request: &VerifiedSignRequest,
    signature: &[u8],
) -> Result<(), SignerIpcError> {
    let response = build_response(key, request, signature)?;
    write_json_frame(stream, &response).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> (String, Option<std::path::PathBuf>) {
        #[cfg(windows)]
        {
            (
                format!(r"\\.\pipe\marty-test-wallet-test-{}", Uuid::new_v4()),
                None,
            )
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let directory = std::env::temp_dir().join(format!(
                "marty-test-wallet-{}-{}",
                std::process::id(),
                Uuid::new_v4()
            ));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            (
                directory.join("signer.sock").to_string_lossy().into_owned(),
                Some(directory),
            )
        }
    }

    #[tokio::test]
    async fn authenticated_local_ipc_round_trip_has_no_skipped_transport() {
        let (endpoint, cleanup) = endpoint();
        let mut listener = LocalListener::bind(&endpoint).unwrap();
        let server_key = SignerAuthenticationKey::from_bytes([0x5a; 32]);
        let server = tokio::spawn(async move {
            #[cfg(windows)]
            let mut stream = listener.accept().await.unwrap();
            #[cfg(unix)]
            let mut stream = listener.accept().await.unwrap();
            let mut replay = ReplayCache::default();
            let request = receive_request(&mut stream, &server_key, &mut replay)
                .await
                .unwrap();
            assert_eq!(request.algorithm, "ES256");
            assert_eq!(&*request.signing_input, b"header.payload");
            send_response(&mut stream, &server_key, &request, &[0x33; 64])
                .await
                .unwrap();
        });

        let client_key = SignerAuthenticationKey::from_bytes([0x5a; 32]);
        let signature = request_signature(
            &endpoint,
            &client_key,
            "ES256",
            "kms/key/holder",
            b"header.payload",
        )
        .await
        .unwrap();
        assert_eq!(signature, vec![0x33; 64]);
        server.await.unwrap();
        drop(cleanup.map(std::fs::remove_dir));
    }

    #[tokio::test]
    async fn local_ipc_rejects_wrong_authentication_key_end_to_end() {
        let (endpoint, cleanup) = endpoint();
        let mut listener = LocalListener::bind(&endpoint).unwrap();
        let server_key = SignerAuthenticationKey::from_bytes([0x5a; 32]);
        let server = tokio::spawn(async move {
            #[cfg(windows)]
            let mut stream = listener.accept().await.unwrap();
            #[cfg(unix)]
            let mut stream = listener.accept().await.unwrap();
            let error = receive_request(&mut stream, &server_key, &mut ReplayCache::default())
                .await
                .unwrap_err();
            assert!(matches!(error, SignerIpcError::AuthenticationFailed));
        });

        let wrong_client_key = SignerAuthenticationKey::from_bytes([0x6b; 32]);
        assert!(request_signature(
            &endpoint,
            &wrong_client_key,
            "ES256",
            "kms/key/holder",
            b"header.payload",
        )
        .await
        .is_err());
        server.await.unwrap();
        drop(cleanup.map(std::fs::remove_dir));
    }

    #[test]
    fn wrong_key_and_replay_are_rejected() {
        let good = SignerAuthenticationKey::from_bytes([0x11; 32]);
        let wrong = SignerAuthenticationKey::from_bytes([0x22; 32]);
        let nonce = Uuid::new_v4();
        let now = unix_timestamp().unwrap();
        let request = build_request(&good, "ES256", "key", b"payload", nonce, now).unwrap();
        let serialized = serde_json::to_vec(&request).unwrap();
        let forged: AuthenticatedSignRequest = serde_json::from_slice(&serialized).unwrap();
        assert!(matches!(
            verify_request(&wrong, &mut ReplayCache::default(), forged, now),
            Err(SignerIpcError::AuthenticationFailed)
        ));

        let first: AuthenticatedSignRequest = serde_json::from_slice(&serialized).unwrap();
        let replayed: AuthenticatedSignRequest = serde_json::from_slice(&serialized).unwrap();
        let mut cache = ReplayCache::default();
        verify_request(&good, &mut cache, first, now).unwrap();
        assert!(matches!(
            verify_request(&good, &mut cache, replayed, now),
            Err(SignerIpcError::ReplayedRequest)
        ));
    }

    #[test]
    fn stale_request_is_rejected() {
        let key = SignerAuthenticationKey::from_bytes([0x44; 32]);
        let now = unix_timestamp().unwrap();
        let request = build_request(
            &key,
            "ES256",
            "key",
            b"payload",
            Uuid::new_v4(),
            now - MAX_CLOCK_SKEW_SECONDS - 1,
        )
        .unwrap();
        assert!(matches!(
            verify_request(&key, &mut ReplayCache::default(), request, now),
            Err(SignerIpcError::StaleRequest)
        ));
    }

    #[test]
    fn missing_authentication_tag_is_rejected() {
        let key = SignerAuthenticationKey::from_bytes([0x77; 32]);
        let mut request = serde_json::to_value(
            build_request(
                &key,
                "ES256",
                "key",
                b"payload",
                Uuid::new_v4(),
                unix_timestamp().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        request
            .as_object_mut()
            .unwrap()
            .remove("authentication_tag");
        assert!(serde_json::from_value::<AuthenticatedSignRequest>(request).is_err());
    }

    #[test]
    fn response_is_bound_to_request_nonce_and_signature() {
        let key = SignerAuthenticationKey::from_bytes([0x29; 32]);
        let nonce = Uuid::new_v4();
        let now = unix_timestamp().unwrap();
        let request = build_request(&key, "ES256", "key", b"payload", nonce, now).unwrap();
        let verified = verify_request(&key, &mut ReplayCache::default(), request, now).unwrap();

        let mut wrong_nonce = build_response(&key, &verified, &[0x31; 64]).unwrap();
        wrong_nonce.nonce = Uuid::new_v4().hyphenated().to_string();
        assert!(verify_response(&key, nonce, wrong_nonce).is_err());

        let mut tampered = build_response(&key, &verified, &[0x31; 64]).unwrap();
        tampered.signature.replace_range(0..1, "A");
        assert!(matches!(
            verify_response(&key, nonce, tampered),
            Err(SignerIpcError::AuthenticationFailed)
        ));
    }

    #[test]
    fn authentication_key_requires_canonical_32_byte_encoding() {
        assert!(SignerAuthenticationKey::from_base64url("").is_err());
        assert!(SignerAuthenticationKey::from_base64url("AA").is_err());
        let canonical = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42; 32]);
        assert!(SignerAuthenticationKey::from_base64url(&canonical).is_ok());
        assert!(SignerAuthenticationKey::from_base64url(&format!("{canonical}=")).is_err());
    }
}
