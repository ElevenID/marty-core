//! mDL Holder application
//!
//! Manages mDL credentials, handles consent, and creates presentations.

use crate::{DeviceEngagement, Result, Session, SessionConfig};

/// mDL Holder application
pub struct Holder {
    config: SessionConfig,
}

impl Holder {
    /// Create a new holder instance
    pub fn new() -> Self {
        Self {
            config: SessionConfig::default(),
        }
    }

    /// Create a holder with explicit session limits.
    pub fn with_config(config: SessionConfig) -> Self {
        Self { config }
    }

    /// Create a fresh QR engagement and the holder-side session that owns its
    /// EDeviceKey. Keeping these together prevents accidental key mismatch.
    pub async fn begin_qr_engagement(&self) -> Result<(DeviceEngagement, Session)> {
        let engagement = DeviceEngagement::new_qr()?;
        let session = Session::from_engagement(&engagement, self.config.clone()).await?;
        Ok((engagement, session))
    }
}

impl Default for Holder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn holder_engagement_session_uses_advertised_device_key() {
        let (engagement, session) = Holder::new().begin_qr_engagement().await.unwrap();
        assert_eq!(session.public_key().await, engagement.device_key);
    }
}
