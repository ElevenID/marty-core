//! Biometric inference pipeline.
//!
//! Orchestrates ONNX Runtime sessions for the detection → alignment →
//! recognition pipeline, plus optional age, liveness, and deepfake models.

use std::sync::Mutex;

use ort::session::Session;
use ort::value::Tensor;

use crate::error::BiometricError;
use crate::types::*;

use super::models::{ModelKind, ModelRegistry};
use super::preprocessing::{
    align_face_112x112, cosine_similarity, decode_base64_image, normalize_embedding,
    prepare_detection_input, prepare_recognition_input, DetectedFace,
};

/// The full biometric inference pipeline backed by ONNX Runtime.
pub struct BiometricPipeline {
    detection: Mutex<Session>,
    recognition: Mutex<Session>,
    age_gender: Option<Mutex<Session>>,
    anti_spoof: Option<Mutex<Session>>,
    deepfake: Option<Mutex<Session>>,
    registry: ModelRegistry,
}

impl BiometricPipeline {
    /// Build a pipeline from a model registry.
    ///
    /// Face detection and recognition are required. Age, anti-spoof, and
    /// deepfake models are loaded if present.
    pub fn new(registry: ModelRegistry) -> Result<Self, BiometricError> {
        registry.validate_required(&[ModelKind::FaceDetection, ModelKind::FaceRecognition])?;

        let detection =
            Self::load_session(registry.get(ModelKind::FaceDetection).ok_or_else(|| {
                BiometricError::Configuration("FaceDetection model not registered".into())
            })?)?;
        let recognition =
            Self::load_session(registry.get(ModelKind::FaceRecognition).ok_or_else(|| {
                BiometricError::Configuration("FaceRecognition model not registered".into())
            })?)?;

        let age_gender = registry
            .get(ModelKind::AgeGender)
            .filter(|c| c.path.exists())
            .map(|c| Self::load_session(c))
            .transpose()?;

        let anti_spoof = registry
            .get(ModelKind::AntiSpoof)
            .filter(|c| c.path.exists())
            .map(|c| Self::load_session(c))
            .transpose()?;

        let deepfake = registry
            .get(ModelKind::DeepfakeDetection)
            .filter(|c| c.path.exists())
            .map(|c| Self::load_session(c))
            .transpose()?;

        Ok(Self {
            detection: Mutex::new(detection),
            recognition: Mutex::new(recognition),
            age_gender: age_gender.map(Mutex::new),
            anti_spoof: anti_spoof.map(Mutex::new),
            deepfake: deepfake.map(Mutex::new),
            registry,
        })
    }

    /// Detect faces in a base64 image. Returns detected faces sorted by score descending.
    pub fn detect_faces(&self, base64_image: &str) -> Result<Vec<DetectedFace>, BiometricError> {
        let (rgb, width, height) = decode_base64_image(base64_image)?;

        let det_config = self.registry.get(ModelKind::FaceDetection).ok_or_else(|| {
            BiometricError::Configuration("FaceDetection model not registered".into())
        })?;
        let input_tensor = prepare_detection_input(
            &rgb,
            width,
            height,
            det_config.input_width,
            det_config.input_height,
        )?;

        let ort_input = Tensor::from_array(input_tensor)
            .map_err(|e| BiometricError::ModelError(format!("input tensor: {e}")))?;

        let mut det_session = self
            .detection
            .lock()
            .map_err(|e| BiometricError::ModelError(format!("lock: {e}")))?;
        let outputs = det_session
            .run(ort::inputs![ort_input])
            .map_err(|e| BiometricError::ModelError(format!("detection inference: {e}")))?;

        // Parse SCRFD output format: scores + bboxes + landmarks
        let faces = parse_scrfd_output(
            &outputs,
            det_config.input_width,
            det_config.input_height,
            width,
            height,
        )?;

        Ok(faces)
    }

    /// Extract a 512-d face embedding from a base64 image.
    ///
    /// Detects the largest face, aligns to 112x112, and runs ArcFace.
    pub fn extract_embedding(
        &self,
        base64_image: &str,
    ) -> Result<(Vec<f32>, DetectedFace), BiometricError> {
        let faces = self.detect_faces(base64_image)?;
        let face = faces.first().ok_or(BiometricError::FaceNotDetected)?;

        if faces.len() > 1 {
            #[cfg(feature = "tracing")]
            tracing::warn!("Multiple faces detected, using highest-confidence face");
        }

        let (rgb, width, height) = decode_base64_image(base64_image)?;
        let aligned = align_face_112x112(&rgb, width, height, &face.landmarks)?;
        let input = prepare_recognition_input(&aligned)?;

        let ort_input = Tensor::from_array(input)
            .map_err(|e| BiometricError::ModelError(format!("input tensor: {e}")))?;

        let mut rec_session = self
            .recognition
            .lock()
            .map_err(|e| BiometricError::ModelError(format!("lock: {e}")))?;
        let outputs = rec_session
            .run(ort::inputs![ort_input])
            .map_err(|e| BiometricError::ModelError(format!("recognition inference: {e}")))?;

        let (_, raw_slice) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| BiometricError::ModelError(format!("embedding extract: {e}")))?;
        let raw_embedding: Vec<f32> = raw_slice.to_vec();

        Ok((normalize_embedding(&raw_embedding), face.clone()))
    }

    /// Estimate age from a base64 face image.
    pub fn estimate_age(&self, base64_image: &str) -> Result<AgeEstimate, BiometricError> {
        let session = self
            .age_gender
            .as_ref()
            .ok_or_else(|| BiometricError::NotSupported("age model not loaded".into()))?;

        let (rgb, width, height) = decode_base64_image(base64_image)?;
        let faces = self.detect_faces(base64_image)?;
        let face = faces.first().ok_or(BiometricError::FaceNotDetected)?;

        let aligned = align_face_112x112(&rgb, width, height, &face.landmarks)?;
        let input = prepare_recognition_input(&aligned)?;

        let ort_input = Tensor::from_array(input)
            .map_err(|e| BiometricError::ModelError(format!("input tensor: {e}")))?;

        let mut age_session = session
            .lock()
            .map_err(|e| BiometricError::ModelError(format!("lock: {e}")))?;
        let outputs = age_session
            .run(ort::inputs![ort_input])
            .map_err(|e| BiometricError::ModelError(format!("age inference: {e}")))?;

        // InsightFace genderage model output: [gender, age] logits
        let (_, raw_slice) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| BiometricError::ModelError(format!("age output extract: {e}")))?;
        let raw: Vec<f32> = raw_slice.to_vec();

        // Age is typically at index 2 (or the last value)
        // The model outputs [gender_logit_female, gender_logit_male, age_value]
        let age_raw = if raw.len() >= 3 {
            raw[2]
        } else if !raw.is_empty() {
            raw[raw.len() - 1]
        } else {
            return Err(BiometricError::ModelError("empty age output".into()));
        };

        let estimated_age = age_raw.round().clamp(0.0, 100.0) as u8;
        let margin = 5u8;
        let lower = estimated_age.saturating_sub(margin);
        let upper = estimated_age.saturating_add(margin).min(100);

        Ok(AgeEstimate {
            estimated_age,
            confidence: face.score,
            age_range: (lower, upper),
        })
    }

    /// Passive anti-spoof analysis on a single face image.
    pub fn detect_spoof(&self, base64_image: &str) -> Result<PadScore, BiometricError> {
        let session = self
            .anti_spoof
            .as_ref()
            .ok_or_else(|| BiometricError::NotSupported("anti-spoof model not loaded".into()))?;

        let (rgb, width, height) = decode_base64_image(base64_image)?;
        let faces = self.detect_faces(base64_image)?;
        let face = faces.first().ok_or(BiometricError::FaceNotDetected)?;

        let spoof_config = self.registry.get(ModelKind::AntiSpoof).ok_or_else(|| {
            BiometricError::Configuration("AntiSpoof model not registered".into())
        })?;

        // Crop face region and resize to model input
        let crop = crop_face_region(&rgb, width, height, &face.bbox);
        let input = prepare_detection_input(
            &crop.0,
            crop.1,
            crop.2,
            spoof_config.input_width,
            spoof_config.input_height,
        )?;

        let ort_input = Tensor::from_array(input)
            .map_err(|e| BiometricError::ModelError(format!("input tensor: {e}")))?;

        let mut spoof_session = session
            .lock()
            .map_err(|e| BiometricError::ModelError(format!("lock: {e}")))?;
        let outputs = spoof_session
            .run(ort::inputs![ort_input])
            .map_err(|e| BiometricError::ModelError(format!("spoof inference: {e}")))?;

        let (_, raw_slice) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| BiometricError::ModelError(format!("spoof output: {e}")))?;
        let raw: Vec<f32> = raw_slice.to_vec();

        // Binary classification: [live_score, spoof_score]
        let spoof_score = if raw.len() >= 2 { raw[1] } else { raw[0] };
        let is_attack = spoof_score > 0.5;

        Ok(PadScore {
            attack_detected: is_attack,
            attack_type: if is_attack {
                Some(classify_spoof_attack(&raw))
            } else {
                None
            },
            confidence: if is_attack {
                spoof_score
            } else {
                1.0 - spoof_score
            },
        })
    }

    /// Deepfake / synthetic face analysis.
    pub fn detect_deepfake(&self, base64_image: &str) -> Result<DeepfakeAnalysis, BiometricError> {
        let session = self
            .deepfake
            .as_ref()
            .ok_or_else(|| BiometricError::NotSupported("deepfake model not loaded".into()))?;

        let (rgb, width, height) = decode_base64_image(base64_image)?;
        let deepfake_config = self
            .registry
            .get(ModelKind::DeepfakeDetection)
            .ok_or_else(|| {
                BiometricError::Configuration("DeepfakeDetection model not registered".into())
            })?;

        let input = prepare_detection_input(
            &rgb,
            width,
            height,
            deepfake_config.input_width,
            deepfake_config.input_height,
        )?;

        let ort_input = Tensor::from_array(input)
            .map_err(|e| BiometricError::ModelError(format!("input tensor: {e}")))?;

        let mut df_session = session
            .lock()
            .map_err(|e| BiometricError::ModelError(format!("lock: {e}")))?;
        let outputs = df_session
            .run(ort::inputs![ort_input])
            .map_err(|e| BiometricError::ModelError(format!("deepfake inference: {e}")))?;

        let (_, raw_slice) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| BiometricError::ModelError(format!("deepfake output: {e}")))?;
        let raw: Vec<f32> = raw_slice.to_vec();

        let synthetic_score = if raw.len() >= 2 { raw[1] } else { raw[0] };
        let is_synthetic = synthetic_score > 0.5;

        Ok(DeepfakeAnalysis {
            is_synthetic,
            confidence: if is_synthetic {
                synthetic_score
            } else {
                1.0 - synthetic_score
            },
            attack_type: if is_synthetic {
                Some(AttackType::Deepfake)
            } else {
                None
            },
        })
    }

    /// Compare two embeddings, returning a FaceVerificationResult.
    pub fn verify_embeddings(
        &self,
        ref_embedding: &[f32],
        probe_embedding: &[f32],
        threshold: f32,
        provider_name: &str,
        elapsed_ms: u64,
    ) -> FaceVerificationResult {
        let similarity = cosine_similarity(ref_embedding, probe_embedding);
        FaceVerificationResult {
            verified: similarity >= threshold,
            similarity,
            threshold,
            reference_quality: None,
            probe_quality: None,
            processing_time_ms: elapsed_ms,
            provider: provider_name.to_string(),
            liveness: None,
        }
    }

    // ====================================================================
    // Internal helpers
    // ====================================================================

    fn load_session(config: &super::models::ModelConfig) -> Result<Session, BiometricError> {
        Session::builder()
            .map_err(|e| BiometricError::ModelError(format!("session builder: {e}")))?
            .commit_from_file(&config.path)
            .map_err(|e| {
                BiometricError::ModelError(format!(
                    "load model '{}' from {}: {e}",
                    config.name,
                    config.path.display()
                ))
            })
    }
}

// ========================================================================
// SCRFD output parsing
// ========================================================================

/// Parse SCRFD detection model outputs into detected faces.
///
/// SCRFD outputs vary by model variant but generally produce:
/// - Score maps at multiple strides (8, 16, 32)
/// - Bounding box deltas
/// - 5-point landmark deltas
fn parse_scrfd_output(
    outputs: &ort::session::SessionOutputs,
    model_width: u32,
    model_height: u32,
    img_width: u32,
    img_height: u32,
) -> Result<Vec<DetectedFace>, BiometricError> {
    // SCRFD models typically output 9 tensors (3 strides × {scores, bboxes, landmarks}).
    // For simplicity, we parse the first output as concatenated results
    // and rely on the model exporting in the "simplified" ONNX format.
    //
    // A production implementation would handle stride-specific anchors.
    // This is structured to work with `scrfd_2.5g_bnkps.onnx` from InsightFace.

    let num_outputs = outputs.len();

    // Simplified: if model has a single output with shape [N, 15+]
    // (score, x1, y1, x2, y2, lm0_x, lm0_y, ... lm4_x, lm4_y)
    if num_outputs == 1 {
        return parse_scrfd_single_output(
            outputs,
            model_width,
            model_height,
            img_width,
            img_height,
        );
    }

    // Multi-output (stride-based): parse per-stride
    parse_scrfd_multi_output(outputs, model_width, model_height, img_width, img_height)
}

fn parse_scrfd_single_output(
    outputs: &ort::session::SessionOutputs,
    model_width: u32,
    model_height: u32,
    img_width: u32,
    img_height: u32,
) -> Result<Vec<DetectedFace>, BiometricError> {
    let (_, raw_data) = outputs[0]
        .try_extract_tensor::<f32>()
        .map_err(|e| BiometricError::ModelError(format!("scrfd output: {e}")))?;
    let raw: Vec<f32> = raw_data.to_vec();

    let scale_x = img_width as f32 / model_width as f32;
    let scale_y = img_height as f32 / model_height as f32;

    let stride = 15; // score + 4 bbox + 10 landmarks
    let mut faces = Vec::new();

    for chunk in raw.chunks_exact(stride) {
        let score = chunk[0];
        if score < 0.5 {
            continue;
        }

        let bbox = [
            chunk[1] * scale_x,
            chunk[2] * scale_y,
            chunk[3] * scale_x,
            chunk[4] * scale_y,
        ];

        let mut landmarks = [[0f32; 2]; 5];
        for i in 0..5 {
            landmarks[i][0] = chunk[5 + i * 2] * scale_x;
            landmarks[i][1] = chunk[6 + i * 2] * scale_y;
        }

        faces.push(DetectedFace {
            bbox,
            score,
            landmarks,
        });
    }

    faces.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(faces)
}

fn parse_scrfd_multi_output(
    outputs: &ort::session::SessionOutputs,
    model_width: u32,
    model_height: u32,
    img_width: u32,
    img_height: u32,
) -> Result<Vec<DetectedFace>, BiometricError> {
    // Multi-stride SCRFD: outputs come in groups of 3 per stride
    // [scores_8, bboxes_8, landmarks_8, scores_16, bboxes_16, landmarks_16, ...]
    //
    // SCRFD uses `num_anchors` per spatial location. The anchor count varies
    // by stride: typically 2 for strides 8 and 16, 2 for stride 32
    // (SCRFD-2.5GF uses 2 anchors at all strides).
    // Total scores length = sum over strides of (feat_h * feat_w * num_anchors).
    let scale_x = img_width as f32 / model_width as f32;
    let scale_y = img_height as f32 / model_height as f32;
    let strides = [8u32, 16, 32];
    let score_threshold = 0.5f32;

    let mut faces = Vec::new();

    for (stride_idx, &stride) in strides.iter().enumerate() {
        let base = stride_idx * 3;
        if base + 2 >= outputs.len() {
            break;
        }

        let (_, scores_data) = outputs[base]
            .try_extract_tensor::<f32>()
            .map_err(|e| BiometricError::ModelError(format!("scores: {e}")))?;
        let scores: Vec<f32> = scores_data.to_vec();
        let (_, bboxes_data) = outputs[base + 1]
            .try_extract_tensor::<f32>()
            .map_err(|e| BiometricError::ModelError(format!("bboxes: {e}")))?;
        let bboxes: Vec<f32> = bboxes_data.to_vec();
        let (_, lms_data) = outputs[base + 2]
            .try_extract_tensor::<f32>()
            .map_err(|e| BiometricError::ModelError(format!("landmarks: {e}")))?;
        let lms: Vec<f32> = lms_data.to_vec();

        let feat_h = model_height / stride;
        let feat_w = model_width / stride;
        let grid_size = (feat_h * feat_w) as usize;

        // Infer num_anchors from the ratio of scores length to grid size.
        // SCRFD flattens as [batch, num_anchors * feat_h * feat_w] for scores
        // and [batch, num_anchors * feat_h * feat_w, 4] for bboxes.
        let num_anchors = if grid_size > 0 {
            (scores.len() / grid_size).max(1)
        } else {
            1
        };

        for (idx, &score) in scores.iter().enumerate() {
            if score < score_threshold {
                continue;
            }

            // Map flat index back to (row, col, anchor)
            let spatial_idx = idx / num_anchors;
            let row = spatial_idx as u32 / feat_w;
            let col = spatial_idx as u32 % feat_w;
            let cx = (col as f32 + 0.5) * stride as f32;
            let cy = (row as f32 + 0.5) * stride as f32;

            let bi = idx * 4;
            if bi + 3 >= bboxes.len() {
                continue;
            }
            let bbox = [
                (cx - bboxes[bi] * stride as f32) * scale_x,
                (cy - bboxes[bi + 1] * stride as f32) * scale_y,
                (cx + bboxes[bi + 2] * stride as f32) * scale_x,
                (cy + bboxes[bi + 3] * stride as f32) * scale_y,
            ];

            let li = idx * 10;
            let mut landmarks = [[0f32; 2]; 5];
            if li + 9 < lms.len() {
                for j in 0..5 {
                    landmarks[j][0] = (cx + lms[li + j * 2] * stride as f32) * scale_x;
                    landmarks[j][1] = (cy + lms[li + j * 2 + 1] * stride as f32) * scale_y;
                }
            }

            faces.push(DetectedFace {
                bbox,
                score,
                landmarks,
            });
        }
    }

    // NMS (simple greedy)
    faces.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let faces = nms(&faces, 0.4);

    Ok(faces)
}

/// Simple greedy non-maximum suppression
fn nms(faces: &[DetectedFace], iou_threshold: f32) -> Vec<DetectedFace> {
    let mut keep = Vec::new();
    let mut suppressed = vec![false; faces.len()];

    for i in 0..faces.len() {
        if suppressed[i] {
            continue;
        }
        keep.push(faces[i].clone());
        for j in (i + 1)..faces.len() {
            if !suppressed[j] && iou(&faces[i].bbox, &faces[j].bbox) > iou_threshold {
                suppressed[j] = true;
            }
        }
    }
    keep
}

fn iou(a: &[f32; 4], b: &[f32; 4]) -> f32 {
    let x1 = a[0].max(b[0]);
    let y1 = a[1].max(b[1]);
    let x2 = a[2].min(b[2]);
    let y2 = a[3].min(b[3]);

    let inter = (x2 - x1).max(0.0) * (y2 - y1).max(0.0);
    let area_a = (a[2] - a[0]) * (a[3] - a[1]);
    let area_b = (b[2] - b[0]) * (b[3] - b[1]);
    let union = area_a + area_b - inter;

    if union < 1e-10 {
        0.0
    } else {
        inter / union
    }
}

/// Crop a face region from raw RGB data given pixel-space bbox [x1,y1,x2,y2].
pub fn crop_face_region(
    rgb: &[u8],
    img_width: u32,
    img_height: u32,
    bbox: &[f32; 4],
) -> (Vec<u8>, u32, u32) {
    let x1 = (bbox[0].max(0.0) as u32).min(img_width.saturating_sub(1));
    let y1 = (bbox[1].max(0.0) as u32).min(img_height.saturating_sub(1));
    let x2 = (bbox[2].max(0.0) as u32).min(img_width);
    let y2 = (bbox[3].max(0.0) as u32).min(img_height);

    let crop_w = x2.saturating_sub(x1).max(1);
    let crop_h = y2.saturating_sub(y1).max(1);

    let mut crop = Vec::with_capacity((crop_w * crop_h * 3) as usize);
    for row in y1..y2 {
        let start = ((row * img_width + x1) * 3) as usize;
        let end = ((row * img_width + x2) * 3) as usize;
        if end <= rgb.len() {
            crop.extend_from_slice(&rgb[start..end]);
        }
    }

    (crop, crop_w, crop_h)
}

/// Classify the type of presentation attack from anti-spoof model output.
///
/// MiniFASNet outputs a binary live/spoof signal. Since the model doesn't
/// directly classify attack type, we infer from the score distribution:
/// - Very high spoof confidence (>0.9) with sharp output → likely Print/Screen
/// - Moderate confidence (0.5–0.9) → likely 3D Mask (harder to detect)
/// - When additional model outputs are available (multi-class models),
///   use the argmax of class logits instead.
fn classify_spoof_attack(raw: &[f32]) -> AttackType {
    // Multi-class model: outputs > 2 values → use argmax over attack classes
    // Convention: [live, print, screen, mask3d, ...]
    if raw.len() > 2 {
        let attack_classes = &raw[1..]; // skip live score
        let (max_idx, _) = attack_classes
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or((0, &0.0));
        return match max_idx {
            0 => AttackType::Print,
            1 => AttackType::Screen,
            2 => AttackType::Mask3D,
            _ => AttackType::Print,
        };
    }

    // Binary model: infer from confidence level
    let spoof_score = if raw.len() >= 2 { raw[1] } else { raw[0] };
    if spoof_score > 0.9 {
        // Very confident → flat media (print or screen replay)
        AttackType::Print
    } else if spoof_score > 0.7 {
        AttackType::Screen
    } else {
        // Lower confidence → harder attack (3D mask)
        AttackType::Mask3D
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iou_identical() {
        let a = [0.0, 0.0, 10.0, 10.0];
        assert!((iou(&a, &a) - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_iou_no_overlap() {
        let a = [0.0, 0.0, 10.0, 10.0];
        let b = [20.0, 20.0, 30.0, 30.0];
        assert!(iou(&a, &b).abs() < 1e-5);
    }

    #[test]
    fn test_iou_partial() {
        let a = [0.0, 0.0, 10.0, 10.0];
        let b = [5.0, 5.0, 15.0, 15.0];
        // intersection = 5*5=25, union = 100+100-25=175
        let expected = 25.0 / 175.0;
        assert!((iou(&a, &b) - expected).abs() < 1e-3);
    }

    #[test]
    fn test_nms_suppresses_overlapping() {
        let faces = vec![
            DetectedFace {
                bbox: [0.0, 0.0, 10.0, 10.0],
                score: 0.9,
                landmarks: [[0.0; 2]; 5],
            },
            DetectedFace {
                bbox: [1.0, 1.0, 11.0, 11.0],
                score: 0.8,
                landmarks: [[0.0; 2]; 5],
            },
            DetectedFace {
                bbox: [50.0, 50.0, 60.0, 60.0],
                score: 0.85,
                landmarks: [[0.0; 2]; 5],
            },
        ];
        let kept = nms(&faces, 0.3);
        assert_eq!(kept.len(), 2); // First and third kept
        assert!((kept[0].score - 0.9).abs() < 1e-5);
        assert!((kept[1].score - 0.85).abs() < 1e-5);
    }

    #[test]
    fn test_crop_face_region() {
        // 4x4 RGB image
        let rgb: Vec<u8> = (0..4 * 4 * 3).map(|i| i as u8).collect();
        let (crop, w, h) = crop_face_region(&rgb, 4, 4, &[1.0, 1.0, 3.0, 3.0]);
        assert_eq!(w, 2);
        assert_eq!(h, 2);
        assert_eq!(crop.len(), (2 * 2 * 3) as usize);
    }

    #[test]
    fn test_classify_spoof_binary_high_confidence() {
        // Very high spoof score → Print
        let raw = vec![0.05, 0.95];
        assert!(matches!(classify_spoof_attack(&raw), AttackType::Print));
    }

    #[test]
    fn test_classify_spoof_binary_medium_confidence() {
        // Medium spoof score → Screen
        let raw = vec![0.2, 0.8];
        assert!(matches!(classify_spoof_attack(&raw), AttackType::Screen));
    }

    #[test]
    fn test_classify_spoof_binary_low_confidence() {
        // Lower spoof score → Mask3D
        let raw = vec![0.4, 0.6];
        assert!(matches!(classify_spoof_attack(&raw), AttackType::Mask3D));
    }

    #[test]
    fn test_classify_spoof_multiclass() {
        // Multi-class: [live=0.1, print=0.2, screen=0.6, mask=0.1]
        let raw = vec![0.1, 0.2, 0.6, 0.1];
        assert!(matches!(classify_spoof_attack(&raw), AttackType::Screen));
    }

    #[test]
    fn test_classify_spoof_multiclass_mask() {
        // Multi-class: [live=0.05, print=0.1, screen=0.05, mask=0.8]
        let raw = vec![0.05, 0.1, 0.05, 0.8];
        assert!(matches!(classify_spoof_attack(&raw), AttackType::Mask3D));
    }
}
