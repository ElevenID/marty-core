//! OnnxProvider — implements FaceVerifier using the ONNX BiometricPipeline.

use std::path::Path;
use std::time::Instant;

use crate::error::BiometricError;
use crate::traits::FaceVerifier;
use crate::types::*;

use super::models::ModelRegistry;
use super::pipeline::BiometricPipeline;
use super::preprocessing::cosine_similarity;

/// Biometric provider backed by ONNX Runtime models.
///
/// Uses the InsightFace model ecosystem:
/// - SCRFD for face detection
/// - ArcFace for face recognition (512-d embeddings)
/// - InsightFace genderage for age estimation
/// - MiniFASNet for passive anti-spoof
/// - EfficientNet for deepfake detection
pub struct OnnxProvider {
    pipeline: BiometricPipeline,
    default_threshold: f32,
    document_match_threshold: f32,
}

impl OnnxProvider {
    /// Create a new provider loading models from the given directory.
    ///
    /// Expects ONNX model files with standard InsightFace naming.
    /// Face detection and recognition are required; other models are optional.
    pub fn new(models_dir: impl AsRef<Path>) -> Result<Self, BiometricError> {
        let registry = ModelRegistry::load_defaults(models_dir);
        let pipeline = BiometricPipeline::new(registry)?;
        Ok(Self {
            pipeline,
            default_threshold: 0.4,
            document_match_threshold: 0.3,
        })
    }

    /// Create a provider with a custom model registry.
    pub fn from_registry(registry: ModelRegistry) -> Result<Self, BiometricError> {
        let pipeline = BiometricPipeline::new(registry)?;
        Ok(Self {
            pipeline,
            default_threshold: 0.4,
            document_match_threshold: 0.3,
        })
    }

    /// Set the default similarity threshold.
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.default_threshold = threshold;
        self
    }

    /// Set the document-to-selfie match threshold.
    ///
    /// Document photos are typically lower quality, older, and have different
    /// lighting conditions, so a lower threshold is appropriate.
    pub fn with_document_threshold(mut self, threshold: f32) -> Self {
        self.document_match_threshold = threshold;
        self
    }
}

impl FaceVerifier for OnnxProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            name: "marty-onnx".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            supports_verification: true,
            supports_quality: true,
            supports_templates: true,
            supports_liveness: true,
            offline_capable: true,
        }
    }

    fn extended_capabilities(&self) -> ExtendedCapabilities {
        ExtendedCapabilities {
            supports_age_estimation: true,
            supports_passive_liveness: true,
            supports_deepfake_detection: true,
            supports_search: true,
            supports_document_match: true,
            supports_pad: true,
        }
    }

    async fn verify(
        &self,
        request: FaceVerificationRequest,
    ) -> Result<FaceVerificationResult, BiometricError> {
        let start = Instant::now();
        let threshold = request.threshold.unwrap_or(self.default_threshold);

        let (ref_emb, _ref_face) = self.pipeline.extract_embedding(&request.reference_image)?;
        let (probe_emb, _probe_face) = self.pipeline.extract_embedding(&request.probe_image)?;

        let elapsed = start.elapsed().as_millis() as u64;
        Ok(self.pipeline.verify_embeddings(
            &ref_emb,
            &probe_emb,
            threshold,
            "marty-onnx",
            elapsed,
        ))
    }

    async fn assess_quality(
        &self,
        image: &str,
    ) -> Result<FaceQualityAssessment, BiometricError> {
        let faces = self.pipeline.detect_faces(image)?;
        let face = faces.first().ok_or(BiometricError::FaceNotDetected)?;

        let (rgb, width, height) =
            super::preprocessing::decode_base64_image(image)?;
        let (crop_rgb, crop_w, crop_h) =
            super::pipeline::crop_face_region(&rgb, width, height, &face.bbox);
        let quality = super::preprocessing::compute_image_quality(&crop_rgb, crop_w, crop_h);

        let bounds = face.to_face_bounds(width, height);
        let face_size = bounds.width * bounds.height;

        // Overall score: weighted combination of all factors
        let overall = 0.3 * quality.sharpness
            + 0.15 * (1.0 - (quality.brightness - 0.5).abs() * 2.0).max(0.0)
            + 0.15 * quality.contrast
            + 0.2 * face_size.min(1.0)
            + 0.2 * face.score;

        Ok(FaceQualityAssessment {
            overall_score: overall.clamp(0.0, 1.0),
            face_detected: true,
            face_count: faces.len() as u32,
            face_bounds: Some(bounds),
            factors: FaceQualityFactors {
                sharpness: quality.sharpness,
                brightness: quality.brightness,
                contrast: quality.contrast,
                face_size,
                pose: face.score,
            },
        })
    }

    async fn extract_template(
        &self,
        image: &str,
    ) -> Result<FaceTemplate, BiometricError> {
        let (embedding, face) = self.pipeline.extract_embedding(image)?;

        // Encode the 512-d embedding as base64 for portable storage
        let bytes: Vec<u8> = embedding
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();
        let data = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &bytes,
        );

        Ok(FaceTemplate {
            data,
            version: "arcface-r50-v1".to_string(),
            provider: "marty-onnx".to_string(),
            quality_score: face.score,
        })
    }

    async fn compare_templates(
        &self,
        reference: &FaceTemplate,
        probe: &FaceTemplate,
    ) -> Result<f32, BiometricError> {
        let ref_emb = decode_template_embedding(&reference.data)?;
        let probe_emb = decode_template_embedding(&probe.data)?;

        Ok(cosine_similarity(&ref_emb, &probe_emb))
    }

    async fn estimate_age(
        &self,
        image: &str,
    ) -> Result<AgeEstimate, BiometricError> {
        self.pipeline.estimate_age(image)
    }

    async fn detect_passive_liveness(
        &self,
        frames: &[String],
    ) -> Result<PassiveLivenessResult, BiometricError> {
        if frames.is_empty() {
            return Err(BiometricError::ImageProcessing(
                "no frames provided".into(),
            ));
        }

        let start = Instant::now();
        let mut pad_scores = Vec::new();

        for frame in frames {
            let pad = self.pipeline.detect_spoof(frame)?;
            pad_scores.push(pad);
        }

        // Fuse: majority vote on attack detection
        let attack_count = pad_scores.iter().filter(|p| p.attack_detected).count();
        let is_live = attack_count * 2 < frames.len(); // Less than half flagged

        let avg_confidence: f32 = pad_scores.iter().map(|p| p.confidence).sum::<f32>()
            / pad_scores.len() as f32;

        Ok(PassiveLivenessResult {
            is_live,
            confidence: avg_confidence,
            pad: pad_scores.into_iter().next(),
            frames_analyzed: frames.len() as u32,
            processing_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    async fn detect_deepfake(
        &self,
        image: &str,
    ) -> Result<DeepfakeAnalysis, BiometricError> {
        self.pipeline.detect_deepfake(image)
    }

    async fn search(
        &self,
        probe: &FaceTemplate,
        gallery: &[FaceTemplate],
        top_k: usize,
    ) -> Result<Vec<SearchMatch>, BiometricError> {
        let probe_emb = decode_template_embedding(&probe.data)?;

        let mut matches: Vec<SearchMatch> = gallery
            .iter()
            .enumerate()
            .filter_map(|(i, template)| {
                let emb = decode_template_embedding(&template.data).ok()?;
                let sim = cosine_similarity(&probe_emb, &emb);
                Some(SearchMatch {
                    index: i,
                    similarity: sim,
                    template_id: format!("{}-{}", template.provider, i),
                })
            })
            .collect();

        // Sort by similarity descending
        matches.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        matches.truncate(top_k);

        Ok(matches)
    }

    async fn match_face_to_document(
        &self,
        selfie: &str,
        document_photo: &str,
    ) -> Result<FaceVerificationResult, BiometricError> {
        let start = Instant::now();

        let (selfie_emb, _) = self.pipeline.extract_embedding(selfie)?;
        let (doc_emb, _) = self.pipeline.extract_embedding(document_photo)?;

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(self.pipeline.verify_embeddings(
            &selfie_emb,
            &doc_emb,
            self.document_match_threshold,
            "marty-onnx",
            elapsed,
        ))
    }
}

/// Decode a base64-encoded f32 embedding from a FaceTemplate.
fn decode_template_embedding(base64_data: &str) -> Result<Vec<f32>, BiometricError> {
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        base64_data,
    )
    .map_err(|e| BiometricError::TemplateExtraction(format!("base64: {e}")))?;

    if bytes.len() % 4 != 0 {
        return Err(BiometricError::TemplateExtraction(
            "invalid embedding length".into(),
        ));
    }

    Ok(bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_template_roundtrip() {
        let embedding: Vec<f32> = vec![0.1, 0.2, 0.3, -0.4, 0.5];
        let bytes: Vec<u8> = embedding.iter().flat_map(|f| f.to_le_bytes()).collect();
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &bytes,
        );

        let decoded = decode_template_embedding(&encoded).unwrap();
        for (a, b) in embedding.iter().zip(decoded.iter()) {
            assert!((a - b).abs() < 1e-7);
        }
    }

    #[test]
    fn test_decode_template_bad_base64() {
        assert!(decode_template_embedding("!!!not-base64!!!").is_err());
    }

    #[test]
    fn test_decode_template_wrong_length() {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &[1, 2, 3], // Not divisible by 4
        );
        assert!(decode_template_embedding(&encoded).is_err());
    }
}
