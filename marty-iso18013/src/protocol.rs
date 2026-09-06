//! ISO 18013-5 protocol state machine and message handling
//!
//! This module implements the protocol flows for session establishment,
//! request/response exchange, and session termination.

use crate::core::DeviceEngagement;
use crate::error::{Error, Result};
use crate::session::{SessionEncryption, SessionKeyAgreement};
use isomdl::definitions::helpers::Tag24;
use isomdl::definitions::session::{Handover, SessionTranscript180135};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[cfg(feature = "python")]
use pyo3::prelude::*;

const MAX_SESSION_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_SESSION_TIMEOUT_SECS: u64 = 60 * 60;

/// Session state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass(skip_from_py_object))]
pub enum SessionState {
    /// Initial state - not yet engaged
    Idle,
    /// Device engagement shared
    Engagement,
    /// Session establishment in progress
    Establishing,
    /// Session established, ready for requests
    Established,
    /// Processing a request
    Processing,
    /// Sending response
    Responding,
    /// Session terminated
    Terminated,
}

/// Session configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "python", pyclass(from_py_object))]
pub struct SessionConfig {
    /// Session timeout in seconds
    pub timeout_secs: u64,

    /// Maximum message size in bytes
    pub max_message_size: usize,

    /// Enable verbose logging
    pub verbose: bool,
}

#[cfg(feature = "python")]
#[pymethods]
impl SessionConfig {
    #[new]
    #[pyo3(signature = (timeout_secs=300, max_message_size=1048576, verbose=false))]
    fn py_new(timeout_secs: u64, max_message_size: usize, verbose: bool) -> PyResult<Self> {
        let config = Self {
            timeout_secs,
            max_message_size: max_message_size.min(MAX_SESSION_MESSAGE_BYTES),
            verbose,
        };
        config.validate().map_err(Into::<PyErr>::into)?;
        Ok(config)
    }

    #[getter]
    fn get_timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    #[setter]
    fn set_timeout_secs(&mut self, value: u64) -> PyResult<()> {
        Self::validate_timeout(value).map_err(Into::<PyErr>::into)?;
        self.timeout_secs = value;
        Ok(())
    }

    #[getter]
    fn get_max_message_size(&self) -> usize {
        self.max_message_size
    }

    #[setter]
    fn set_max_message_size(&mut self, value: usize) {
        self.max_message_size = value.min(MAX_SESSION_MESSAGE_BYTES);
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 300,             // 5 minutes
            max_message_size: 1024 * 1024, // 1 MB
            verbose: false,
        }
    }
}

impl SessionConfig {
    fn validate_timeout(timeout_secs: u64) -> Result<()> {
        if !(1..=MAX_SESSION_TIMEOUT_SECS).contains(&timeout_secs) {
            return Err(Error::InvalidRequest(format!(
                "Session timeout must be between 1 and {MAX_SESSION_TIMEOUT_SECS} seconds"
            )));
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        Self::validate_timeout(self.timeout_secs)
    }
}

/// ISO 18013-5 session
#[cfg_attr(feature = "python", pyclass)]
pub struct Session {
    /// Session state
    state: Arc<RwLock<SessionState>>,

    /// Session encryption
    encryption: Arc<RwLock<Option<SessionEncryption>>>,

    /// Key agreement
    key_agreement: Arc<RwLock<SessionKeyAgreement>>,

    /// Configuration
    config: SessionConfig,

    /// Monotonic deadline checked before every ephemeral secret operation.
    deadline: Instant,

    role: SessionRole,
    engagement_bytes: Vec<u8>,
    engagement_device_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionRole {
    Device,
    Reader,
}

#[cfg(feature = "python")]
#[pymethods]
impl Session {
    #[staticmethod]
    fn from_engagement_py(
        engagement: &DeviceEngagement,
        config: Option<SessionConfig>,
    ) -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))?;
        runtime
            .block_on(Self::from_engagement(
                engagement,
                config.unwrap_or_default(),
            ))
            .map_err(Into::into)
    }

    #[staticmethod]
    fn reader_from_engagement_py(
        engagement: &DeviceEngagement,
        config: Option<SessionConfig>,
    ) -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))?;
        runtime
            .block_on(Self::reader_from_engagement(
                engagement,
                config.unwrap_or_default(),
            ))
            .map_err(Into::into)
    }

    fn state_py(&self) -> PyResult<SessionState> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))?;
        Ok(runtime.block_on(self.state()))
    }

    fn public_key_py(&self) -> PyResult<Vec<u8>> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))?;
        runtime.block_on(self.public_key()).map_err(Into::into)
    }

    fn establish_py(&self, peer_public_key: &[u8]) -> PyResult<()> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))?;
        runtime
            .block_on(self.establish(peer_public_key))
            .map_err(Into::into)
    }

    fn send_encrypted_py(&self, message: &[u8]) -> PyResult<Vec<u8>> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))?;
        runtime
            .block_on(self.send_encrypted(message))
            .map_err(Into::into)
    }

    fn receive_encrypted_py(&self, ciphertext: &[u8]) -> PyResult<Vec<u8>> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))?;
        runtime
            .block_on(self.receive_encrypted(ciphertext))
            .map_err(Into::into)
    }

    fn terminate_py(&self) -> PyResult<()> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))?;
        runtime.block_on(self.terminate()).map_err(Into::into)
    }
}

impl Session {
    /// Create a new session from device engagement
    pub async fn from_engagement(
        engagement: &DeviceEngagement,
        config: SessionConfig,
    ) -> Result<Self> {
        config.validate()?;
        let key_agreement =
            SessionKeyAgreement::from_key_pair(engagement.take_ephemeral_key_pair()?);
        if key_agreement.public_key() != engagement.device_key {
            return Err(Error::InvalidEngagement(
                "DeviceEngagement public key does not match its private key".to_string(),
            ));
        }
        Self::new_for_role(engagement, config, key_agreement, SessionRole::Device)
    }

    /// Create a reader-side session bound to the advertised EDeviceKey.
    pub async fn reader_from_engagement(
        engagement: &DeviceEngagement,
        config: SessionConfig,
    ) -> Result<Self> {
        config.validate()?;
        Self::new_for_role(
            engagement,
            config,
            SessionKeyAgreement::new()?,
            SessionRole::Reader,
        )
    }

    fn new_for_role(
        engagement: &DeviceEngagement,
        config: SessionConfig,
        key_agreement: SessionKeyAgreement,
        role: SessionRole,
    ) -> Result<Self> {
        config.validate()?;
        let engagement_bytes = engagement.to_cbor()?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(config.timeout_secs))
            .ok_or_else(|| Error::InvalidRequest("Session timeout is too large".to_string()))?;

        Ok(Self {
            state: Arc::new(RwLock::new(SessionState::Engagement)),
            encryption: Arc::new(RwLock::new(None)),
            key_agreement: Arc::new(RwLock::new(key_agreement)),
            config,
            deadline,
            role,
            engagement_bytes,
            engagement_device_key: engagement.device_key.clone(),
        })
    }

    /// Get current session state
    pub async fn state(&self) -> SessionState {
        let _ = self.ensure_not_expired().await;
        *self.state.read().await
    }

    /// Return this session's ephemeral public key for peer establishment.
    pub async fn public_key(&self) -> Result<Vec<u8>> {
        self.ensure_not_expired().await?;
        if *self.state.read().await == SessionState::Terminated {
            return Err(Error::InvalidState("Session is terminated".to_string()));
        }
        let key_agreement = self.key_agreement.read().await;
        if Instant::now() >= self.deadline {
            drop(key_agreement);
            self.expire_session().await;
            return Err(Error::Timeout);
        }
        Ok(key_agreement.public_key())
    }

    /// Establish secure session
    pub async fn establish(&self, peer_public_key: &[u8]) -> Result<()> {
        self.ensure_not_expired().await?;
        let mut state = self.state.write().await;

        if *state != SessionState::Engagement {
            return Err(Error::InvalidState(
                "Cannot establish from current state".to_string(),
            ));
        }

        if self.role == SessionRole::Reader && peer_public_key != self.engagement_device_key {
            return Err(Error::SessionEstablishment(
                "peer key does not match DeviceEngagement EDeviceKey".to_string(),
            ));
        }

        // Set peer key and derive shared secret.
        let mut ka = self.key_agreement.write().await;
        ka.validate_and_set_peer_key(peer_public_key.to_vec())?;
        let our_public_key = ka.public_key();
        let shared_secret = ka.derive_shared_secret()?;
        let reader_public_key = match self.role {
            SessionRole::Device => peer_public_key,
            SessionRole::Reader => our_public_key.as_slice(),
        };
        let session_transcript =
            Self::build_session_transcript(&self.engagement_bytes, reader_public_key)?;
        let encryption = SessionEncryption::new_directional(
            &shared_secret,
            &session_transcript,
            self.role == SessionRole::Device,
        )?;

        if Instant::now() >= self.deadline {
            ka.clear_private_state();
            drop(ka);
            *state = SessionState::Terminated;
            *self.encryption.write().await = None;
            return Err(Error::Timeout);
        }

        *self.encryption.write().await = Some(encryption);
        *state = SessionState::Established;

        Ok(())
    }

    /// Encrypt and send a message
    pub async fn send_encrypted(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.ensure_not_expired().await?;
        if *self.state.read().await != SessionState::Established {
            return Err(Error::InvalidState(
                "Cannot send outside an established session".to_string(),
            ));
        }
        let maximum_message_size = self.config.max_message_size.min(MAX_SESSION_MESSAGE_BYTES);
        if message.len() > maximum_message_size {
            return Err(Error::InvalidRequest(format!(
                "Message exceeds {} byte session limit",
                maximum_message_size
            )));
        }
        let mut encryption = self.encryption.write().await;
        if Instant::now() >= self.deadline {
            *encryption = None;
            drop(encryption);
            self.expire_session().await;
            return Err(Error::Timeout);
        }
        let encryption = encryption
            .as_mut()
            .ok_or_else(|| Error::InvalidState("Session not established".to_string()))?;

        encryption.encrypt(message)
    }

    /// Receive and decrypt a message
    pub async fn receive_encrypted(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.ensure_not_expired().await?;
        if *self.state.read().await != SessionState::Established {
            return Err(Error::InvalidState(
                "Cannot receive outside an established session".to_string(),
            ));
        }
        let maximum_ciphertext_size = self
            .config
            .max_message_size
            .min(MAX_SESSION_MESSAGE_BYTES)
            .saturating_add(16);
        if ciphertext.len() > maximum_ciphertext_size {
            return Err(Error::InvalidResponse(format!(
                "Encrypted message exceeds {maximum_ciphertext_size} byte session limit"
            )));
        }
        let mut encryption = self.encryption.write().await;
        if Instant::now() >= self.deadline {
            *encryption = None;
            drop(encryption);
            self.expire_session().await;
            return Err(Error::Timeout);
        }
        let encryption = encryption
            .as_mut()
            .ok_or_else(|| Error::InvalidState("Session not established".to_string()))?;

        encryption.decrypt(ciphertext)
    }

    /// Terminate the session
    pub async fn terminate(&self) -> Result<()> {
        let mut state = self.state.write().await;
        *state = SessionState::Terminated;
        *self.encryption.write().await = None;
        self.key_agreement.write().await.clear_private_state();
        Ok(())
    }

    async fn ensure_not_expired(&self) -> Result<()> {
        if Instant::now() < self.deadline {
            return Ok(());
        }
        self.expire_session().await;
        Err(Error::Timeout)
    }

    async fn expire_session(&self) {
        let mut state = self.state.write().await;
        *state = SessionState::Terminated;
        *self.encryption.write().await = None;
        self.key_agreement.write().await.clear_private_state();
    }

    /// Build ISO 18013-5 `SessionTranscriptBytes`:
    /// `#6.24(bstr .cbor [DeviceEngagementBytes, EReaderKeyBytes, null])`.
    fn build_session_transcript(
        engagement_bytes: &[u8],
        reader_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        let engagement =
            Tag24::<isomdl::definitions::DeviceEngagement>::from_bytes(engagement_bytes.to_vec())
                .map_err(|error| Error::InvalidEngagement(error.to_string()))?;
        let reader_key = Tag24::new(DeviceEngagement::cose_key_from_sec1(reader_public_key)?)
            .map_err(|error| Error::SessionEstablishment(error.to_string()))?;
        let transcript = Tag24::new(SessionTranscript180135(
            engagement,
            reader_key,
            Handover::QR,
        ))
        .map_err(|error| Error::SessionEstablishment(error.to_string()))?;
        isomdl::cbor::to_vec(&transcript)
            .map_err(|error| Error::SessionEstablishment(error.to_string()))
    }
}

/// mDL request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass(skip_from_py_object))]
pub struct MdlRequest {
    /// Document type being requested
    pub doc_type: String,

    /// Requested data elements by namespace
    pub data_elements: std::collections::HashMap<String, Vec<String>>,

    /// Request nonce
    pub nonce: Vec<u8>,
}

/// mDL response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass(skip_from_py_object))]
pub struct MdlResponse {
    /// Document type
    pub doc_type: String,

    /// Provided data elements
    pub data: Vec<u8>, // CBOR-encoded DeviceResponse

    /// Response status
    pub status: ResponseStatus,
}

/// Response status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass(from_py_object))]
pub enum ResponseStatus {
    /// Success
    Ok,
    /// User consent denied
    ConsentDenied,
    /// Requested data not available
    DataNotAvailable,
    /// Internal error
    Error,
}

#[cfg(feature = "python")]
#[pymethods]
impl MdlRequest {
    #[new]
    #[pyo3(signature = (doc_type, data_elements, nonce=None))]
    fn py_new(
        doc_type: String,
        data_elements: std::collections::HashMap<String, Vec<String>>,
        nonce: Option<Vec<u8>>,
    ) -> Self {
        use rand::RngCore;
        let nonce = nonce.unwrap_or_else(|| {
            let mut generated = vec![0_u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut generated);
            generated
        });
        Self {
            doc_type,
            data_elements,
            nonce,
        }
    }

    #[getter]
    fn doc_type(&self) -> String {
        self.doc_type.clone()
    }

    #[getter]
    fn data_elements(&self) -> std::collections::HashMap<String, Vec<String>> {
        self.data_elements.clone()
    }

    #[getter]
    fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(self, &mut encoded)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
        Ok(encoded)
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        ciborium::de::from_reader(data)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))
    }
}

#[cfg(feature = "python")]
#[pymethods]
impl MdlResponse {
    #[new]
    #[pyo3(signature = (doc_type, data, status=None))]
    fn py_new(doc_type: String, data: Vec<u8>, status: Option<ResponseStatus>) -> Self {
        Self {
            doc_type,
            data,
            status: status.unwrap_or(ResponseStatus::Ok),
        }
    }

    #[getter]
    fn doc_type(&self) -> String {
        self.doc_type.clone()
    }

    #[getter]
    fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    #[getter]
    fn status(&self) -> ResponseStatus {
        self.status
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(self, &mut encoded)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
        Ok(encoded)
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        ciborium::de::from_reader(data)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // SessionState
    // ====================================================================

    #[test]
    fn test_session_state_variants() {
        let states = [
            SessionState::Idle,
            SessionState::Engagement,
            SessionState::Establishing,
            SessionState::Established,
            SessionState::Processing,
            SessionState::Responding,
            SessionState::Terminated,
        ];
        // Verify all states are distinct
        for (i, a) in states.iter().enumerate() {
            for (j, b) in states.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_session_state_serialization() {
        let json = serde_json::to_string(&SessionState::Established).unwrap();
        let deserialized: SessionState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, SessionState::Established);
    }

    #[test]
    fn test_session_state_clone() {
        let state = SessionState::Processing;
        let cloned = state;
        assert_eq!(state, cloned);
    }

    // ====================================================================
    // SessionConfig
    // ====================================================================

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.timeout_secs, 300);
        assert_eq!(config.max_message_size, 1024 * 1024);
        assert!(!config.verbose);
    }

    #[test]
    fn test_session_config_custom() {
        let config = SessionConfig {
            timeout_secs: 60,
            max_message_size: 512,
            verbose: true,
        };
        assert_eq!(config.timeout_secs, 60);
        assert_eq!(config.max_message_size, 512);
        assert!(config.verbose);
    }

    #[tokio::test]
    async fn session_rejects_pathological_timeouts_before_consuming_engagement_key() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        for timeout_secs in [0, MAX_SESSION_TIMEOUT_SECS + 1] {
            let config = SessionConfig {
                timeout_secs,
                ..SessionConfig::default()
            };
            assert!(Session::from_engagement(&engagement, config).await.is_err());
        }
        assert!(
            Session::from_engagement(&engagement, SessionConfig::default())
                .await
                .is_ok()
        );
    }

    // ====================================================================
    // ResponseStatus
    // ====================================================================

    #[test]
    fn test_response_status_equality() {
        assert_eq!(ResponseStatus::Ok, ResponseStatus::Ok);
        assert_ne!(ResponseStatus::Ok, ResponseStatus::Error);
        assert_ne!(
            ResponseStatus::ConsentDenied,
            ResponseStatus::DataNotAvailable
        );
    }

    #[test]
    fn test_response_status_serialization() {
        let json = serde_json::to_string(&ResponseStatus::ConsentDenied).unwrap();
        let deserialized: ResponseStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ResponseStatus::ConsentDenied);
    }

    // ====================================================================
    // MdlRequest
    // ====================================================================

    #[test]
    fn test_mdl_request_serialization() {
        let mut data_elements = std::collections::HashMap::new();
        data_elements.insert(
            "org.iso.18013.5.1".to_string(),
            vec!["family_name".to_string(), "birth_date".to_string()],
        );

        let request = MdlRequest {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            data_elements,
            nonce: vec![1, 2, 3, 4],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: MdlRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.doc_type, "org.iso.18013.5.1.mDL");
        assert_eq!(
            deserialized.data_elements["org.iso.18013.5.1"],
            vec!["family_name", "birth_date"]
        );
        assert_eq!(deserialized.nonce, vec![1, 2, 3, 4]);

        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&request, &mut cbor).unwrap();
        let cbor_deserialized: MdlRequest = ciborium::de::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(cbor_deserialized.doc_type, request.doc_type);
    }

    // ====================================================================
    // MdlResponse
    // ====================================================================

    #[test]
    fn test_mdl_response_serialization() {
        let response = MdlResponse {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            data: vec![0xA1, 0x01],
            status: ResponseStatus::Ok,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: MdlResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.status, ResponseStatus::Ok);
        assert_eq!(deserialized.data, vec![0xA1, 0x01]);
    }

    // ====================================================================
    // Session (async tests)
    // ====================================================================

    #[tokio::test]
    async fn test_session_terminate() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let config = SessionConfig::default();
        let session = Session::from_engagement(&engagement, config).await.unwrap();

        assert_eq!(session.state().await, SessionState::Engagement);
        assert!(session.key_agreement.read().await.has_private_state());

        session.terminate().await.unwrap();
        assert_eq!(session.state().await, SessionState::Terminated);
        assert!(!session.key_agreement.read().await.has_private_state());
        assert!(session.public_key().await.is_err());
    }

    #[tokio::test]
    async fn test_session_send_encrypted_before_established() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let session = Session::from_engagement(&engagement, SessionConfig::default())
            .await
            .unwrap();

        let result = session.send_encrypted(b"hello").await;
        assert!(result.is_err(), "should fail when session not established");
    }

    #[tokio::test]
    async fn test_session_receive_encrypted_before_established() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let session = Session::from_engagement(&engagement, SessionConfig::default())
            .await
            .unwrap();

        let result = session.receive_encrypted(b"cipher").await;
        assert!(result.is_err(), "should fail when session not established");
    }

    #[tokio::test]
    async fn expired_session_terminates_and_clears_encryption_keys() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let expiring_config = SessionConfig {
            timeout_secs: 1,
            ..SessionConfig::default()
        };
        let pre_establishment =
            Session::reader_from_engagement(&engagement, expiring_config.clone())
                .await
                .unwrap();
        assert!(pre_establishment
            .key_agreement
            .read()
            .await
            .has_private_state());
        let session = Session::from_engagement(&engagement, expiring_config)
            .await
            .unwrap();
        let peer = SessionKeyAgreement::new().unwrap();
        session.establish(&peer.public_key()).await.unwrap();
        assert!(session.encryption.read().await.is_some());

        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(matches!(
            pre_establishment.public_key().await,
            Err(Error::Timeout)
        ));
        assert!(!pre_establishment
            .key_agreement
            .read()
            .await
            .has_private_state());
        assert!(matches!(
            session.send_encrypted(b"expired").await,
            Err(Error::Timeout)
        ));
        assert_eq!(session.state().await, SessionState::Terminated);
        assert!(session.encryption.read().await.is_none());
        assert!(matches!(session.public_key().await, Err(Error::Timeout)));
    }

    #[tokio::test]
    async fn test_two_sessions_exchange_directional_messages() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let device = Session::from_engagement(&engagement, SessionConfig::default())
            .await
            .unwrap();
        let reader = Session::reader_from_engagement(&engagement, SessionConfig::default())
            .await
            .unwrap();
        let device_key = device.public_key().await.unwrap();
        let reader_key = reader.public_key().await.unwrap();

        device.establish(&reader_key).await.unwrap();
        reader.establish(&device_key).await.unwrap();

        let device_message = device.send_encrypted(b"device to reader").await.unwrap();
        assert_eq!(
            reader.receive_encrypted(&device_message).await.unwrap(),
            b"device to reader"
        );

        let reader_message = reader.send_encrypted(b"reader to device").await.unwrap();
        assert_eq!(
            device.receive_encrypted(&reader_message).await.unwrap(),
            b"reader to device"
        );
    }

    #[tokio::test]
    async fn reader_rejects_a_peer_key_not_bound_to_engagement() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let reader = Session::reader_from_engagement(&engagement, SessionConfig::default())
            .await
            .unwrap();
        let unrelated = SessionKeyAgreement::new().unwrap().public_key();

        assert!(reader.establish(&unrelated).await.is_err());
        assert_eq!(reader.state().await, SessionState::Engagement);
    }

    #[test]
    fn session_transcript_is_tagged_and_binds_engagement_and_reader_key() {
        let engagement_a = DeviceEngagement::new_qr().unwrap();
        let engagement_b = DeviceEngagement::new_qr().unwrap();
        let reader_a = SessionKeyAgreement::new().unwrap().public_key();
        let reader_b = SessionKeyAgreement::new().unwrap().public_key();

        let transcript =
            Session::build_session_transcript(&engagement_a.to_cbor().unwrap(), &reader_a).unwrap();
        assert_eq!(&transcript[..2], &[0xd8, 0x18]);
        assert_ne!(
            transcript,
            Session::build_session_transcript(&engagement_b.to_cbor().unwrap(), &reader_a).unwrap()
        );
        assert_ne!(
            transcript,
            Session::build_session_transcript(&engagement_a.to_cbor().unwrap(), &reader_b).unwrap()
        );
    }
}
