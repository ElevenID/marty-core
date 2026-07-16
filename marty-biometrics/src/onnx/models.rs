//! Model configuration and registry for ONNX biometric models.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::BiometricError;

/// Kinds of models in the biometric pipeline
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum ModelKind {
    /// Face detection (SCRFD variants)
    FaceDetection,
    /// Face recognition / embedding (ArcFace variants)
    FaceRecognition,
    /// Age and gender estimation
    AgeGender,
    /// Passive anti-spoof / liveness
    AntiSpoof,
    /// Deepfake / synthetic face detection
    DeepfakeDetection,
}

/// Configuration for a single ONNX model
#[derive(Debug, Clone)]
pub struct ModelConfig {
    /// Model kind
    pub kind: ModelKind,
    /// Path to the .onnx file
    pub path: PathBuf,
    /// Expected input width
    pub input_width: u32,
    /// Expected input height
    pub input_height: u32,
    /// Human-readable model name
    pub name: String,
}

/// Registry of available biometric models
#[derive(Debug)]
pub struct ModelRegistry {
    models: HashMap<ModelKind, ModelConfig>,
    base_dir: PathBuf,
}

impl ModelRegistry {
    /// Create a new registry with models in the given directory.
    ///
    /// Scans for known model filenames within `base_dir`.
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            models: HashMap::new(),
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }

    /// Register a model configuration
    pub fn register(&mut self, config: ModelConfig) {
        self.models.insert(config.kind, config);
    }

    /// Get configured model for a given kind
    pub fn get(&self, kind: ModelKind) -> Option<&ModelConfig> {
        self.models.get(&kind)
    }

    /// Check if a model kind is available (file exists)
    pub fn is_available(&self, kind: ModelKind) -> bool {
        self.models.get(&kind).map_or(false, |c| c.path.exists())
    }

    /// Base directory for model files
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Load the default model set from a directory.
    ///
    /// Looks for well-known filenames:
    /// - `det_2.5g.onnx` — SCRFD-2.5GF face detection
    /// - `w600k_r50.onnx` — ArcFace-R50 face recognition
    /// - `genderage.onnx` — Age/gender estimation
    /// - `2.7_80x80_MiniFASNetV2.onnx` — MiniFASNet anti-spoof
    /// - `deepfake_efficientnet.onnx` — Deepfake detection
    pub fn load_defaults(base_dir: impl AsRef<Path>) -> Self {
        let base = base_dir.as_ref();
        let mut registry = Self::new(base);

        let defaults: &[(ModelKind, &str, &str, u32, u32)] = &[
            (
                ModelKind::FaceDetection,
                "det_2.5g.onnx",
                "SCRFD-2.5GF",
                640,
                640,
            ),
            (
                ModelKind::FaceRecognition,
                "w600k_r50.onnx",
                "ArcFace-R50",
                112,
                112,
            ),
            (
                ModelKind::AgeGender,
                "genderage.onnx",
                "InsightFace-AgeGender",
                112,
                112,
            ),
            (
                ModelKind::AntiSpoof,
                "2.7_80x80_MiniFASNetV2.onnx",
                "MiniFASNetV2",
                80,
                80,
            ),
            (
                ModelKind::DeepfakeDetection,
                "deepfake_efficientnet.onnx",
                "EfficientNet-Deepfake",
                224,
                224,
            ),
        ];

        for &(kind, filename, name, w, h) in defaults {
            let path = base.join(filename);
            registry.register(ModelConfig {
                kind,
                path,
                input_width: w,
                input_height: h,
                name: name.to_string(),
            });
        }

        registry
    }

    /// Validate that required models are present on disk.
    ///
    /// Returns a list of missing models on failure.
    pub fn validate_required(&self, required: &[ModelKind]) -> Result<(), BiometricError> {
        let missing: Vec<String> = required
            .iter()
            .filter(|k| !self.is_available(**k))
            .map(|k| format!("{:?}", k))
            .collect();

        if missing.is_empty() {
            Ok(())
        } else {
            Err(BiometricError::ModelError(format!(
                "Missing required models: {}",
                missing.join(", ")
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_new() {
        let registry = ModelRegistry::new("/tmp/models");
        assert!(registry.get(ModelKind::FaceDetection).is_none());
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = ModelRegistry::new("/tmp/models");
        registry.register(ModelConfig {
            kind: ModelKind::FaceDetection,
            path: PathBuf::from("/tmp/models/det.onnx"),
            input_width: 640,
            input_height: 640,
            name: "SCRFD".to_string(),
        });
        assert!(registry.get(ModelKind::FaceDetection).is_some());
        assert!(registry.get(ModelKind::FaceRecognition).is_none());
    }

    #[test]
    fn test_load_defaults_populates_all_kinds() {
        let registry = ModelRegistry::load_defaults("/tmp/models");
        assert!(registry.get(ModelKind::FaceDetection).is_some());
        assert!(registry.get(ModelKind::FaceRecognition).is_some());
        assert!(registry.get(ModelKind::AgeGender).is_some());
        assert!(registry.get(ModelKind::AntiSpoof).is_some());
        assert!(registry.get(ModelKind::DeepfakeDetection).is_some());
    }

    #[test]
    fn test_is_available_false_for_missing_file() {
        let registry = ModelRegistry::load_defaults("/nonexistent/path");
        assert!(!registry.is_available(ModelKind::FaceDetection));
    }

    #[test]
    fn test_validate_required_missing() {
        let registry = ModelRegistry::load_defaults("/nonexistent/path");
        let result = registry.validate_required(&[ModelKind::FaceDetection]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("FaceDetection"));
    }

    #[test]
    fn test_validate_required_empty() {
        let registry = ModelRegistry::load_defaults("/nonexistent/path");
        assert!(registry.validate_required(&[]).is_ok());
    }
}
