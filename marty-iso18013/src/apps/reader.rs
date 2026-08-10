//! mDL Reader/Verifier application
//!
//! Initiates sessions, sends requests, and verifies mDL presentations.

use crate::{DeviceEngagement, Result, Session, SessionConfig};

/// mDL Reader/Verifier application
pub struct Reader {
    config: SessionConfig,
}

impl Reader {
    /// Create a new reader instance
    pub fn new() -> Self {
        Self {
            config: SessionConfig::default(),
        }
    }

    /// Create a reader with explicit session limits.
    pub fn with_config(config: SessionConfig) -> Self {
        Self { config }
    }

    /// Parse a QR `mdoc:` payload and create a reader-side session bound to
    /// the advertised EDeviceKey.
    pub async fn begin_qr_session(&self, qr_uri: &str) -> Result<(DeviceEngagement, Session)> {
        let engagement = DeviceEngagement::from_qr_uri(qr_uri)?;
        let session = Session::reader_from_engagement(&engagement, self.config.clone()).await?;
        Ok((engagement, session))
    }
}

impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reader_session_is_bound_to_scanned_engagement() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let uri = engagement.to_qr_uri().unwrap();
        let (decoded, reader) = Reader::new().begin_qr_session(&uri).await.unwrap();
        assert_eq!(decoded.device_key, engagement.device_key);
        assert_ne!(reader.public_key().await, decoded.device_key);
    }
}
