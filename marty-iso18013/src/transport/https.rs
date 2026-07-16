//! HTTPS transport implementation

use super::{Result, Transport};
use async_trait::async_trait;
use reqwest::Client;

/// HTTPS transport
pub struct HttpsTransport {
    client: Client,
    url: String,
    connected: bool,
}

impl HttpsTransport {
    /// Create a new HTTPS transport
    pub fn new(url: String) -> Self {
        Self {
            client: Client::new(),
            url,
            connected: false,
        }
    }
}

#[async_trait]
impl Transport for HttpsTransport {
    async fn connect(&mut self) -> Result<()> {
        // For HTTPS, connection is established on first request
        self.connected = true;
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected {
            return Err(crate::error::Error::ConnectionFailed(
                "Not connected".to_string(),
            ));
        }

        let response = self
            .client
            .post(&self.url)
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| crate::error::Error::SendFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::Error::SendFailed(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        if !self.connected {
            return Err(crate::error::Error::ConnectionFailed(
                "Not connected".to_string(),
            ));
        }

        let response = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| crate::error::Error::ReceiveFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::Error::ReceiveFailed(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| crate::error::Error::ReceiveFailed(e.to_string()))
    }

    async fn close(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}
