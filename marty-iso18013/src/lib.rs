//! ISO 18013-5 mobile driving license protocol implementation
//!
//! This crate provides a complete implementation of the ISO 18013-5 standard
//! for mobile driving licenses (mDL), including:
//!
//! - Device engagement and QR code generation
//! - Session establishment with ECDH key agreement
//! - Secure session encryption (AES-256-GCM)
//! - Request and response protocol flows
//! - Selective disclosure
//! - Multiple transport layers (BLE, NFC, HTTPS)
//! - Holder and Reader applications
//!
//! ## Features
//!
//! - `python`: Enable PyO3 bindings for Python integration
//! - `ble`: Enable Bluetooth Low Energy transport
//! - `nfc`: Enable Near Field Communication transport
//! - `all-transports`: Enable all transport layers
//!
//! ## Example
//!
//! ```rust,no_run
//! use marty_iso18013::{DeviceEngagement, Session, SessionConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create device engagement
//! let engagement = DeviceEngagement::new_qr()?;
//! let qr_code = engagement.to_qr_code()?;
//!
//! // Establish session
//! let config = SessionConfig::default();
//! let session = Session::from_engagement(&engagement, config).await?;
//!
//! // Create and send response
//! // ...
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "python")]
use pyo3::prelude::*;

// Re-export marty-types for convenience
pub use marty_types as types;

// Core protocol modules
pub mod core;
pub mod protocol;
pub mod selective;
pub mod session;

// Transport layers
pub mod transport;

// Applications
pub mod apps;

// Error types
pub mod error;

// Convenience re-exports
pub use core::{DeviceEngagement, EngagementMethod, TransportMethod};
pub use error::{Error, Result};
pub use protocol::{MdlRequest, MdlResponse, Session, SessionConfig, SessionState};
pub use selective::SelectiveDisclosure;
pub use transport::Transport;

#[cfg(feature = "python")]
#[pymodule]
fn marty_iso18013(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Core types
    m.add_class::<DeviceEngagement>()?;
    m.add_class::<core::TransportMethod>()?;
    m.add_class::<core::EngagementMethod>()?;

    // Session types
    m.add_class::<SessionConfig>()?;
    m.add_class::<protocol::SessionState>()?;

    // Request/Response types
    m.add_class::<MdlRequest>()?;
    m.add_class::<MdlResponse>()?;
    m.add_class::<protocol::ResponseStatus>()?;

    // Submodules
    let transport_module = PyModule::new_bound(m.py(), "transport")?;
    m.add_submodule(&transport_module)?;

    Ok(())
}
