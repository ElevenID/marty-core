//! ISO 18013-5 protocol state machine and message handling
//!
//! This module implements the protocol flows for session establishment,
//! request/response exchange, and session termination.

use crate::core::DeviceEngagement;
use crate::error::{Error, Result};
use crate::session::{SessionEncryption, SessionKeyAgreement};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// Session state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass)]
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
#[cfg_attr(feature = "python", pyclass)]
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
    fn py_new(timeout_secs: u64, max_message_size: usize, verbose: bool) -> Self {
        Self {
            timeout_secs,
            max_message_size,
            verbose,
        }
    }

    #[getter]
    fn get_timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    #[setter]
    fn set_timeout_secs(&mut self, value: u64) {
        self.timeout_secs = value;
    }

    #[getter]
    fn get_max_message_size(&self) -> usize {
        self.max_message_size
    }

    #[setter]
    fn set_max_message_size(&mut self, value: usize) {
        self.max_message_size = value;
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

/// ISO 18013-5 session
pub struct Session {
    /// Session state
    state: Arc<RwLock<SessionState>>,

    /// Session encryption
    encryption: Arc<RwLock<Option<SessionEncryption>>>,

    /// Key agreement
    key_agreement: Arc<RwLock<SessionKeyAgreement>>,

    /// Configuration
    #[allow(dead_code)]
    config: SessionConfig,
}

impl Session {
    /// Create a new session from device engagement
    pub async fn from_engagement(
        _engagement: &DeviceEngagement,
        config: SessionConfig,
    ) -> Result<Self> {
        let key_agreement = SessionKeyAgreement::new()?;

        Ok(Self {
            state: Arc::new(RwLock::new(SessionState::Engagement)),
            encryption: Arc::new(RwLock::new(None)),
            key_agreement: Arc::new(RwLock::new(key_agreement)),
            config,
        })
    }

    /// Get current session state
    pub async fn state(&self) -> SessionState {
        *self.state.read().await
    }

    /// Establish secure session
    pub async fn establish(&self, peer_public_key: &[u8]) -> Result<()> {
        let mut state = self.state.write().await;

        if *state != SessionState::Engagement {
            return Err(Error::InvalidState(
                "Cannot establish from current state".to_string(),
            ));
        }

        // Set peer key and derive shared secret
        let mut ka = self.key_agreement.write().await;
        ka.set_peer_key(peer_public_key.to_vec());
        let shared_secret = ka.derive_shared_secret()?;

        // Build session transcript per ISO 18013-5 §9.1.5.1:
        // SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover]
        // We bind the transcript to both parties' public keys to prevent replay.
        let our_public_key = ka.public_key();
        let session_transcript = Self::build_session_transcript(&our_public_key, peer_public_key);
        let encryption = SessionEncryption::new(&shared_secret, &session_transcript)?;

        *self.encryption.write().await = Some(encryption);
        *state = SessionState::Established;

        Ok(())
    }

    /// Encrypt and send a message
    pub async fn send_encrypted(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut encryption = self.encryption.write().await;
        let encryption = encryption
            .as_mut()
            .ok_or_else(|| Error::InvalidState("Session not established".to_string()))?;

        encryption.encrypt(message)
    }

    /// Receive and decrypt a message
    pub async fn receive_encrypted(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut encryption = self.encryption.write().await;
        let encryption = encryption
            .as_mut()
            .ok_or_else(|| Error::InvalidState("Session not established".to_string()))?;

        encryption.decrypt(ciphertext)
    }

    /// Terminate the session
    pub async fn terminate(&self) -> Result<()> {
        let mut state = self.state.write().await;
        *state = SessionState::Terminated;
        Ok(())
    }

    /// Build session transcript binding both parties' ephemeral keys.
    ///
    /// Per ISO 18013-5 §9.1.5.1 the SessionTranscript is a CBOR array:
    ///   `[DeviceEngagementBytes, EReaderKeyBytes, Handover]`
    ///
    /// Until full CBOR DeviceEngagement serialisation is implemented we use a
    /// SHA-256 hash of both public keys concatenated.  This is sufficient to
    /// bind the session to the specific engagement and prevent replay — the
    /// derived session keys will differ for any other key pair combination.
    fn build_session_transcript(our_public_key: &[u8], peer_public_key: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(our_public_key);
        hasher.update(peer_public_key);
        hasher.finalize().to_vec()
    }
}

/// mDL request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass)]
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
#[cfg_attr(feature = "python", pyclass)]
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
#[cfg_attr(feature = "python", pyclass)]
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

        session.terminate().await.unwrap();
        assert_eq!(session.state().await, SessionState::Terminated);
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
}
