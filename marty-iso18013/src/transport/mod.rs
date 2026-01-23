//! Transport layer abstractions
//!
//! Provides a unified interface for different transport methods (BLE, NFC, HTTPS).

use crate::error::Result;
use async_trait::async_trait;

pub mod mock;
pub mod ble;
pub mod nfc;
pub mod https;

// Re-export transport implementations
pub use mock::MockTransport;
pub use https::HttpsTransport;

#[cfg(feature = "ble")]
pub use ble::BleTransport;

#[cfg(feature = "nfc")]
pub use nfc::NfcTransport;

/// Transport layer trait for sending and receiving messages
#[async_trait]
pub trait Transport: Send + Sync {
    /// Connect to the transport
    async fn connect(&mut self) -> Result<()>;
    
    /// Send data over the transport
    async fn send(&mut self, data: &[u8]) -> Result<()>;
    
    /// Receive data from the transport
    async fn receive(&mut self) -> Result<Vec<u8>>;
    
    /// Close the transport connection
    async fn close(&mut self) -> Result<()>;
    
    /// Check if the transport is connected
    fn is_connected(&self) -> bool;
}
