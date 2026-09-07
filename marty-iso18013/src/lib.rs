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
//! # #[cfg(all(feature = "session-protocol", feature = "qr-render"))]
//! use marty_iso18013::{DeviceEngagement, Session, SessionConfig};
//!
//! # #[cfg(all(feature = "session-protocol", feature = "qr-render"))]
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

#[cfg(not(feature = "session-protocol"))]
/// Marker for passive verifier builds that cannot create or retain ISO 18013
/// holder/reader session secrets.
///
/// ```compile_fail
/// use marty_iso18013::{DeviceEngagement, Session};
/// ```
///
/// ```compile_fail
/// let _ = marty_iso18013::session::SessionKeyAgreement::new();
/// ```
pub struct NoSessionProtocol;

// Re-export marty-types for full holder/reader applications.
#[cfg(feature = "session-protocol")]
pub use marty_types as types;

// Core protocol modules
#[cfg(feature = "session-protocol")]
pub mod core;
#[cfg(feature = "verifier")]
pub mod openid4vp;
#[cfg(feature = "session-protocol")]
pub mod protocol;
#[cfg(feature = "session-protocol")]
pub mod selective;
#[cfg(feature = "session-protocol")]
pub mod session;

// Transport layers
#[cfg(feature = "session-protocol")]
pub mod transport;
#[cfg(feature = "python")]
mod transport_bindings;

// Applications
#[cfg(feature = "session-protocol")]
pub mod apps;

// Error types
pub mod error;

// Convenience re-exports
#[cfg(feature = "session-protocol")]
pub use core::{DeviceEngagement, EngagementMethod, TransportMethod};
pub use error::{Error, Result};
#[cfg(feature = "session-protocol")]
pub use protocol::{MdlRequest, MdlResponse, Session, SessionConfig, SessionState};
#[cfg(feature = "session-protocol")]
pub use selective::SelectiveDisclosure;
#[cfg(feature = "session-protocol")]
pub use transport::Transport;

// Keep the imported session compliance source unchanged while compiling it
// inside the crate, where test-only compatibility helpers are available.
#[cfg(all(test, feature = "session-protocol"))]
extern crate self as marty_iso18013;
#[cfg(all(test, feature = "session-protocol"))]
#[path = "../tests/session_conformance.rs"]
mod session_conformance;

#[cfg(feature = "python")]
#[pymodule]
fn marty_iso18013(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Core types
    m.add_class::<DeviceEngagement>()?;
    m.add_class::<core::TransportMethod>()?;
    m.add_class::<core::EngagementMethod>()?;

    // Session types
    m.add_class::<SessionConfig>()?;
    m.add_class::<Session>()?;
    m.add_class::<protocol::SessionState>()?;

    // Request/Response types
    m.add_class::<MdlRequest>()?;
    m.add_class::<MdlResponse>()?;
    m.add_class::<protocol::ResponseStatus>()?;
    m.add_class::<SelectiveDisclosure>()?;

    // Submodules
    let transport_module = PyModule::new(m.py(), "transport")?;
    transport_bindings::register(m)?;
    transport_bindings::register(&transport_module)?;
    m.add_submodule(&transport_module)?;

    Ok(())
}
