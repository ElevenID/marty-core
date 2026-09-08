//! Authenticated local IPC for the test wallet's remote-KMS signer agent.

use std::collections::HashMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
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

pub struct SignerAuthenticationKey {
    key: Option<hmac::Key>,
    #[cfg(test)]
    cleanup_observer: Option<AuthenticationKeyCleanupObserver>,
}

#[cfg(test)]
#[derive(Clone, Default)]
struct AuthenticationKeyCleanupObserver(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(test)]
impl AuthenticationKeyCleanupObserver {
    fn cleanup_count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

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
        Ok(Self {
            key: Some(hmac::Key::new(hmac::HMAC_SHA256, &decoded)),
            #[cfg(test)]
            cleanup_observer: None,
        })
    }

    #[cfg(test)]
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key: Some(hmac::Key::new(hmac::HMAC_SHA256, &bytes)),
            cleanup_observer: None,
        }
    }

    #[cfg(test)]
    fn from_bytes_with_cleanup_observer(
        bytes: [u8; 32],
        observer: AuthenticationKeyCleanupObserver,
    ) -> Self {
        Self {
            key: Some(hmac::Key::new(hmac::HMAC_SHA256, &bytes)),
            cleanup_observer: Some(observer),
        }
    }

    fn backend_key(&self) -> &hmac::Key {
        self.key
            .as_ref()
            .expect("signer authentication key must exist before drop")
    }

    fn framed_message(domain: &[u8], fields: &[&[u8]]) -> Zeroizing<Vec<u8>> {
        let capacity = domain.len()
            + fields
                .iter()
                .map(|field| 8usize.saturating_add(field.len()))
                .sum::<usize>();
        let mut message = Zeroizing::new(Vec::with_capacity(capacity));
        message.extend_from_slice(domain);
        for field in fields {
            message.extend_from_slice(&(field.len() as u64).to_be_bytes());
            message.extend_from_slice(field);
        }
        message
    }

    fn mac(&self, domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
        let message = Self::framed_message(domain, fields);
        hmac::sign(self.backend_key(), &message)
            .as_ref()
            .try_into()
            .expect("HMAC-SHA-256 produces a 32-byte tag")
    }

    fn verify(
        &self,
        domain: &[u8],
        fields: &[&[u8]],
        supplied: &[u8],
    ) -> Result<(), SignerIpcError> {
        let message = Self::framed_message(domain, fields);
        hmac::verify(self.backend_key(), &message, supplied)
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
        self.key = None;
        #[cfg(test)]
        if let Some(observer) = &self.cleanup_observer {
            observer.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
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
        // The DACL authenticates the exact logon session; the signer still
        // receives no identity or impersonation capability from the client.
        .security_qos_flags(0) // SECURITY_ANONYMOUS
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
fn current_windows_logon_sid() -> std::io::Result<String> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenGroups, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const SE_GROUP_LOGON_ID_MASK: u32 = 0xc000_0000;

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: this owns the real token handle returned by
                // OpenProcessToken, not the current-process pseudo handle.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    let mut token = ptr::null_mut();
    // SAFETY: `token` is a valid output pointer and GetCurrentProcess returns
    // a process pseudo handle valid for the duration of this call.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let token = OwnedHandle(token);

    let mut required = 0u32;
    // The first call obtains the variable TOKEN_GROUPS buffer size.
    unsafe {
        GetTokenInformation(token.0, TokenGroups, ptr::null_mut(), 0, &mut required);
    }
    if required < u32::try_from(std::mem::size_of::<TOKEN_GROUPS>()).unwrap() {
        return Err(std::io::Error::last_os_error());
    }
    let words = usize::try_from(required)
        .expect("Windows token group length fits usize")
        .div_ceil(std::mem::size_of::<usize>());
    let mut token_information = vec![0usize; words];
    // SAFETY: the word buffer is suitably aligned and has `required` writable
    // bytes for the TOKEN_GROUPS returned by GetTokenInformation.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenGroups,
            token_information.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: GetTokenInformation initialized the buffer as TOKEN_GROUPS.
    let groups = unsafe { &*token_information.as_ptr().cast::<TOKEN_GROUPS>() };
    let entry_count = usize::try_from(groups.GroupCount)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid group count"))?;
    let initialized_bytes = std::mem::offset_of!(TOKEN_GROUPS, Groups)
        .checked_add(
            entry_count
                .checked_mul(std::mem::size_of::<SID_AND_ATTRIBUTES>())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid group count")
                })?,
        )
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid group count")
        })?;
    if initialized_bytes > usize::try_from(required).expect("Windows token group length fits usize")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows token group buffer is truncated",
        ));
    }
    // SAFETY: the validated GroupCount fits within the initialized buffer.
    let entries = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), entry_count) };
    let logon = entries
        .iter()
        .find(|entry| entry.Attributes & SE_GROUP_LOGON_ID_MASK == SE_GROUP_LOGON_ID_MASK)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "current Windows token has no logon SID",
            )
        })?;

    let mut string_sid = ptr::null_mut();
    // SAFETY: the group SID points into the live token-information buffer, and
    // `string_sid` is a valid output pointer.
    if unsafe { ConvertSidToStringSidW(logon.Sid, &mut string_sid) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut length = 0usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated LocalAlloc string.
    unsafe {
        while *string_sid.add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: the scan above established exactly `length` initialized units.
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(string_sid, length) })
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid logon SID"));
    // SAFETY: the string was allocated by ConvertSidToStringSidW with LocalAlloc.
    unsafe {
        LocalFree(string_sid.cast());
    }
    sid
}

#[cfg(windows)]
fn current_logon_pipe_sddl(logon_sid: &str) -> String {
    format!("D:P(A;;GA;;;{logon_sid})")
}

#[cfg(windows)]
fn create_current_owner_pipe(
    endpoint: &str,
    first_instance: bool,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::ffi::c_void;
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    // A protected DACL grants full control only to the exact logon session.
    // An account-level user ACE would be additive and would admit a different
    // interactive or remote session owned by the same account.
    let logon_sid = current_windows_logon_sid()?;
    let sddl: Vec<u16> = format!("{}\0", current_logon_pipe_sddl(&logon_sid))
        .encode_utf16()
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES size fits u32"),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first_instance)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                endpoint,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
    };
    unsafe {
        LocalFree(descriptor);
    }
    result
}

#[cfg(windows)]
impl LocalListener {
    pub fn bind(endpoint: &str) -> Result<Self, SignerIpcError> {
        if !endpoint.starts_with(r"\\.\pipe\marty-test-wallet-") {
            return Err(SignerIpcError::InvalidEndpoint);
        }
        let pending = create_current_owner_pipe(endpoint, true)?;
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
        let next = create_current_owner_pipe(&self.endpoint, false)?;
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

    #[test]
    fn authentication_hmac_matches_kat_rejects_bad_tag_and_drops_backend_key() {
        let observer = AuthenticationKeyCleanupObserver::default();
        let key =
            SignerAuthenticationKey::from_bytes_with_cleanup_observer([0x0b; 32], observer.clone());
        let tag = hmac::sign(key.backend_key(), b"Hi There");
        assert_eq!(
            hex::encode(tag.as_ref()),
            "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7"
        );
        assert!(hmac::verify(key.backend_key(), b"Hi There", tag.as_ref()).is_ok());
        let mut forged = tag.as_ref().to_vec();
        forged[0] ^= 1;
        assert!(hmac::verify(key.backend_key(), b"Hi There", &forged).is_err());
        drop(key);
        assert_eq!(observer.cleanup_count(), 1);

        let unwind_observer = AuthenticationKeyCleanupObserver::default();
        let unwind = std::panic::catch_unwind({
            let observer = unwind_observer.clone();
            move || {
                let key =
                    SignerAuthenticationKey::from_bytes_with_cleanup_observer([0xa5; 32], observer);
                assert_eq!(key.mac(b"test-domain", &[b"test-field"]).len(), 32);
                panic!("injected signer HMAC unwind")
            }
        });
        assert!(unwind.is_err());
        assert_eq!(unwind_observer.cleanup_count(), 1);
    }

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
            use std::os::unix::fs::DirBuilderExt as _;
            // macOS permits fewer bytes in a Unix-domain socket path than Linux.
            // Keep this real transport fixture short while retaining a private,
            // unpredictable parent directory for the socket.
            let directory =
                std::path::Path::new("/tmp").join(format!("mw-{}", Uuid::new_v4().simple()));
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(&directory).unwrap();
            (
                directory.join("signer.sock").to_string_lossy().into_owned(),
                Some(directory),
            )
        }
    }

    #[cfg(unix)]
    #[test]
    fn local_ipc_test_endpoint_fits_the_portable_unix_socket_path_budget() {
        use std::os::unix::fs::PermissionsExt as _;

        let (endpoint, cleanup) = endpoint();
        let directory = cleanup.expect("Unix endpoint must own a private directory");
        assert!(std::path::Path::new(&endpoint).is_absolute());
        assert!(
            endpoint.as_bytes().len() <= 90,
            "Unix socket fixture path exceeds the conservative portable budget: {endpoint}"
        );
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700,
            "Unix socket fixture directory was not created privately"
        );
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_pipe_dacl_is_limited_to_the_exact_logon_session() {
        use std::ptr;
        use windows_sys::Win32::Foundation::{LocalFree, LUID};
        use windows_sys::Win32::Security::Authorization::{
            AuthzAccessCheck, AuthzAddSidsToContext, AuthzFreeContext, AuthzFreeResourceManager,
            AuthzInitializeContextFromSid, AuthzInitializeResourceManager,
            ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
            AUTHZ_ACCESS_REPLY, AUTHZ_ACCESS_REQUEST, AUTHZ_RM_FLAG_NO_AUDIT,
            AUTHZ_SKIP_TOKEN_GROUPS, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, PSID, SID_AND_ATTRIBUTES};

        unsafe fn parse_sid(sid: &str) -> PSID {
            let sid: Vec<u16> = format!("{sid}\0").encode_utf16().collect();
            let mut parsed_sid = ptr::null_mut();
            // SAFETY: `sid` is NUL-terminated and parsed_sid is a valid output pointer.
            assert_ne!(
                unsafe { ConvertStringSidToSidW(sid.as_ptr(), &mut parsed_sid) },
                0
            );
            parsed_sid
        }

        unsafe fn access_granted(
            descriptor: PSECURITY_DESCRIPTOR,
            user_sid: PSID,
            logon_sid: PSID,
        ) -> bool {
            let mut resource_manager = ptr::null_mut();
            // SAFETY: callbacks are absent for a local, non-auditing test
            // resource manager, and the output pointer is valid.
            assert_ne!(
                unsafe {
                    AuthzInitializeResourceManager(
                        AUTHZ_RM_FLAG_NO_AUDIT,
                        None,
                        None,
                        None,
                        ptr::null(),
                        &mut resource_manager,
                    )
                },
                0
            );
            let mut base_context = ptr::null_mut();
            // SAFETY: the parsed SID and resource manager remain live, and the
            // context intentionally starts without ambient token groups.
            assert_ne!(
                unsafe {
                    AuthzInitializeContextFromSid(
                        AUTHZ_SKIP_TOKEN_GROUPS,
                        user_sid,
                        resource_manager,
                        ptr::null(),
                        LUID::default(),
                        ptr::null(),
                        &mut base_context,
                    )
                },
                0
            );
            let logon_group = SID_AND_ATTRIBUTES {
                Sid: logon_sid,
                Attributes: 4, // SE_GROUP_ENABLED
            };
            let mut context = ptr::null_mut();
            // SAFETY: the base context and enabled SID entry remain live.
            assert_ne!(
                unsafe {
                    AuthzAddSidsToContext(
                        base_context,
                        &logon_group,
                        1,
                        ptr::null(),
                        0,
                        &mut context,
                    )
                },
                0
            );
            let request = AUTHZ_ACCESS_REQUEST {
                // FILE_WRITE_DATA is granted by GA but is not an implicit
                // owner right, so the owner SID cannot create a false positive.
                DesiredAccess: 0x0000_0002,
                ..Default::default()
            };
            let mut granted = 0;
            let mut evaluation = 0;
            let mut error = 0;
            let mut reply = AUTHZ_ACCESS_REPLY {
                ResultListLength: 1,
                GrantedAccessMask: &mut granted,
                SaclEvaluationResults: &mut evaluation,
                Error: &mut error,
            };
            // SAFETY: the contexts, descriptor, request, and single-result
            // reply storage all remain live for this authorization check.
            let checked = unsafe {
                AuthzAccessCheck(
                    0,
                    context,
                    &request,
                    ptr::null_mut(),
                    descriptor,
                    ptr::null(),
                    0,
                    &mut reply,
                    ptr::null_mut(),
                )
            };
            assert_ne!(checked, 0, "{}", std::io::Error::last_os_error());
            let allowed = error == 0 && granted & 0x0000_0002 != 0;
            // SAFETY: all three handles were created above and are freed once.
            unsafe {
                AuthzFreeContext(context);
                AuthzFreeContext(base_context);
                AuthzFreeResourceManager(resource_manager);
            }
            allowed
        }

        let allowed_logon = "S-1-5-5-100-200";
        let same_user = "S-1-5-21-1000-1000-1000-1001";
        let different_logon = "S-1-5-5-100-201";
        let sddl = current_logon_pipe_sddl(allowed_logon);
        assert_eq!(sddl, "D:P(A;;GA;;;S-1-5-5-100-200)");
        for broad_principal in [";;;WD", ";;;AU", ";;;BU", ";;;BA"] {
            assert!(!sddl.contains(broad_principal));
        }

        // AuthzAccessCheck requires an owner. It also has no object-specific
        // generic mapping, so evaluate FILE_WRITE_DATA using the production
        // DACL's exact trustee with an equivalent concrete access bit.
        let encoded: Vec<u16> =
            format!("O:{same_user}D:P(A;;0x00000002;;;{allowed_logon})\0")
                .encode_utf16()
                .collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: encoded is NUL-terminated and descriptor is a valid output pointer.
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    encoded.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0
        );
        // Use Windows' authorization engine with the same user SID and one
        // enabled logon group at a time. Only the exact session may receive GA.
        let parsed_user = unsafe { parse_sid(same_user) };
        let parsed_allowed_logon = unsafe { parse_sid(allowed_logon) };
        let parsed_different_logon = unsafe { parse_sid(different_logon) };
        assert!(unsafe { access_granted(descriptor, parsed_user, parsed_allowed_logon) });
        assert!(!unsafe { access_granted(descriptor, parsed_user, parsed_different_logon) });
        // SAFETY: these allocations came from Windows conversion routines.
        unsafe {
            LocalFree(parsed_different_logon.cast());
            LocalFree(parsed_allowed_logon.cast());
            LocalFree(parsed_user.cast());
            LocalFree(descriptor.cast());
        }

        let logon_sid = current_windows_logon_sid().unwrap();
        assert!(
            logon_sid.starts_with("S-1-5-5-"),
            "token group selected as logon SID has the wrong authority: {logon_sid}"
        );
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
