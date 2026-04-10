//! Marty Biometrics
//!
//! Biometric verification for the Marty ecosystem.
//! Supports facial verification with pluggable provider architecture.
//!
//! # Features
//!
//! - `native` - Enables async runtime and image processing for native builds
//! - `python` - Enables Python bindings via PyO3
//! - `wasm` - Enables WebAssembly bindings via wasm-bindgen
//! - `liveness` - Enables liveness challenge signing/validation
//! - `opencv` - Local OpenCV-based face matching (placeholder)
//! - `sita`, `nec`, `idemia` - Commercial provider integrations (placeholder)
//!
//! # Example
//!
//! ```rust,ignore
//! use marty_biometrics::{BiometricProvider, FaceVerifier, FaceVerificationRequest};
//!
//! let provider = BiometricProvider::mock();
//! let request = FaceVerificationRequest {
//!     reference_image: "base64_encoded_image".to_string(),
//!     probe_image: "base64_encoded_live_capture".to_string(),
//!     threshold: Some(0.7),
//!     ..Default::default()
//! };
//!
//! let result = provider.verify(request).await?;
//! println!("Verified: {}", result.verified);
//! ```

mod error;
mod types;

// Async trait and provider require tokio - native/python only
#[cfg(any(feature = "native", feature = "python"))]
mod provider;
#[cfg(any(feature = "native", feature = "python"))]
mod traits;

pub use error::BiometricError;
pub use types::*;

#[cfg(any(feature = "native", feature = "python"))]
pub use provider::{BiometricProvider, LocalProvider, MockProvider};
#[cfg(any(feature = "native", feature = "python"))]
pub use traits::FaceVerifier;

// ONNX Runtime inference (face detection, recognition, age, liveness, deepfake)
#[cfg(feature = "onnx")]
pub mod onnx;
#[cfg(feature = "onnx")]
pub use onnx::OnnxProvider;

// Liveness challenge validation
#[cfg(feature = "liveness")]
mod liveness;
#[cfg(feature = "liveness")]
pub use liveness::*;

// Python bindings
#[cfg(feature = "python")]
mod python;
#[cfg(feature = "python")]
pub use python::_marty_biometrics;

// WASM bindings
#[cfg(feature = "wasm")]
pub mod wasm;
