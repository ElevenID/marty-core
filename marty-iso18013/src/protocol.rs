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
            timeout_secs: 300, // 5 minutes
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
            return Err(Error::InvalidState("Cannot establish from current state".to_string()));
        }
        
        // Set peer key and derive shared secret
        let mut ka = self.key_agreement.write().await;
        ka.set_peer_key(peer_public_key.to_vec());
        let shared_secret = ka.derive_shared_secret()?;
        
        // Create session encryption
        let session_transcript = b"session_transcript"; // TODO: Actual transcript
        let encryption = SessionEncryption::new(&shared_secret, session_transcript)?;
        
        *self.encryption.write().await = Some(encryption);
        *state = SessionState::Established;
        
        Ok(())
    }

    /// Encrypt and send a message
    pub async fn send_encrypted(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut encryption = self.encryption.write().await;
        let encryption = encryption.as_mut()
            .ok_or_else(|| Error::InvalidState("Session not established".to_string()))?;
        
        encryption.encrypt(message)
    }

    /// Receive and decrypt a message
    pub async fn receive_encrypted(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut encryption = self.encryption.write().await;
        let encryption = encryption.as_mut()
            .ok_or_else(|| Error::InvalidState("Session not established".to_string()))?;
        
        encryption.decrypt(ciphertext)
    }

    /// Terminate the session
    pub async fn terminate(&self) -> Result<()> {
        let mut state = self.state.write().await;
        *state = SessionState::Terminated;
        Ok(())
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
