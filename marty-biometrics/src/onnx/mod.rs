//! ONNX Runtime inference engine for biometric models.
//!
//! This module provides low-level model management and inference
//! for the biometric pipeline: face detection (SCRFD), face recognition
//! (ArcFace), age estimation, passive liveness, and deepfake detection.

mod models;
mod pipeline;
mod preprocessing;
mod provider;

pub use models::{ModelConfig, ModelKind, ModelRegistry};
pub use pipeline::BiometricPipeline;
pub use provider::OnnxProvider;
