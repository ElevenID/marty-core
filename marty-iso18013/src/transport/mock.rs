//! Mock transport for testing

use super::{Result, Transport};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Mock transport for testing
pub struct MockTransport {
    connected: bool,
    send_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    receive_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl MockTransport {
    /// Create a new mock transport
    pub fn new() -> Self {
        Self {
            connected: false,
            send_queue: Arc::new(Mutex::new(VecDeque::new())),
            receive_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Add data to the receive queue (simulating incoming data)
    pub async fn queue_receive(&self, data: Vec<u8>) {
        self.receive_queue.lock().await.push_back(data);
    }

    /// Get sent data from the send queue
    pub async fn get_sent(&self) -> Option<Vec<u8>> {
        self.send_queue.lock().await.pop_front()
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn connect(&mut self) -> Result<()> {
        self.connected = true;
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected {
            return Err(crate::error::Error::ConnectionFailed(
                "Not connected".to_string(),
            ));
        }
        self.send_queue.lock().await.push_back(data.to_vec());
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        if !self.connected {
            return Err(crate::error::Error::ConnectionFailed(
                "Not connected".to_string(),
            ));
        }

        self.receive_queue
            .lock()
            .await
            .pop_front()
            .ok_or_else(|| crate::error::Error::ReceiveFailed("No data available".to_string()))
    }

    async fn close(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}
