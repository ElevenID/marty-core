//! Image preprocessing for ONNX model input.
//!
//! Handles base64 decoding, image loading, face alignment via
//! 5-point landmark affine transformation, and tensor construction.

use ndarray::Array4;

use crate::error::BiometricError;
use crate::types::FaceBounds;

/// Decoded face detection from SCRFD output
#[derive(Debug, Clone)]
pub struct DetectedFace {
    /// Bounding box in pixel coordinates
    pub bbox: [f32; 4],
    /// Detection confidence
    pub score: f32,
    /// 5-point landmarks: left eye, right eye, nose, left mouth, right mouth
    pub landmarks: [[f32; 2]; 5],
}

impl DetectedFace {
    /// Convert pixel-space bbox to normalized FaceBounds
    pub fn to_face_bounds(&self, img_width: u32, img_height: u32) -> FaceBounds {
        let w = img_width as f32;
        let h = img_height as f32;
        FaceBounds {
            x: self.bbox[0] / w,
            y: self.bbox[1] / h,
            width: (self.bbox[2] - self.bbox[0]) / w,
            height: (self.bbox[3] - self.bbox[1]) / h,
        }
    }
}

/// Standard 112x112 alignment reference points for ArcFace.
///
/// These are the target landmark positions after affine alignment,
/// matching InsightFace's reference implementation.
pub const ARCFACE_REFERENCE_LANDMARKS: [[f32; 2]; 5] = [
    [38.2946, 51.6963],  // left eye
    [73.5318, 51.5014],  // right eye
    [56.0252, 71.7366],  // nose tip
    [41.5493, 92.3655],  // left mouth corner
    [70.7299, 92.2041],  // right mouth corner
];

/// Decode a base64 image string into raw RGB bytes and dimensions.
pub fn decode_base64_image(
    base64_data: &str,
) -> Result<(Vec<u8>, u32, u32), BiometricError> {
    // Strip optional data URI prefix
    let data = if let Some(pos) = base64_data.find(",") {
        &base64_data[pos + 1..]
    } else {
        base64_data
    };

    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        data,
    )
    .map_err(|e| BiometricError::ImageProcessing(format!("base64 decode: {e}")))?;

    let img = image::load_from_memory(&bytes)
        .map_err(|e| BiometricError::ImageProcessing(format!("image decode: {e}")))?;

    let rgb = img.to_rgb8();
    let (w, h) = (rgb.width(), rgb.height());
    Ok((rgb.into_raw(), w, h))
}

/// Resize raw RGB bytes to the target size and produce a CHW f32 tensor.
///
/// Produces shape `[1, 3, height, width]` with pixel values in [0, 255]
/// (no normalization — model-specific normalization is applied separately).
pub fn prepare_detection_input(
    rgb: &[u8],
    src_width: u32,
    src_height: u32,
    target_width: u32,
    target_height: u32,
) -> Result<Array4<f32>, BiometricError> {
    let img = image::RgbImage::from_raw(src_width, src_height, rgb.to_vec())
        .ok_or_else(|| BiometricError::ImageProcessing("invalid RGB buffer".into()))?;

    let resized = image::imageops::resize(
        &img,
        target_width,
        target_height,
        image::imageops::FilterType::Triangle,
    );

    let mut tensor = Array4::<f32>::zeros((1, 3, target_height as usize, target_width as usize));

    for y in 0..target_height as usize {
        for x in 0..target_width as usize {
            let pixel = resized.get_pixel(x as u32, y as u32);
            tensor[[0, 0, y, x]] = pixel[0] as f32; // R
            tensor[[0, 1, y, x]] = pixel[1] as f32; // G
            tensor[[0, 2, y, x]] = pixel[2] as f32; // B
        }
    }

    Ok(tensor)
}

/// Compute a 2x3 affine transform from detected landmarks to reference landmarks,
/// then extract an aligned 112x112 face crop.
///
/// Returns raw RGB bytes for the aligned face.
pub fn align_face_112x112(
    rgb: &[u8],
    src_width: u32,
    src_height: u32,
    landmarks: &[[f32; 2]; 5],
) -> Result<Vec<u8>, BiometricError> {
    let reference = &ARCFACE_REFERENCE_LANDMARKS;

    // Estimate similarity transform using Umeyama algorithm (simplified).
    // We compute the optimal rotation, scale, and translation from
    // source landmarks to reference landmarks.
    let (src_mean, dst_mean) = compute_means(landmarks, reference);
    let (rot, scale) = estimate_rigid_transform(landmarks, reference, &src_mean, &dst_mean);

    let img = image::RgbImage::from_raw(src_width, src_height, rgb.to_vec())
        .ok_or_else(|| BiometricError::ImageProcessing("invalid RGB buffer".into()))?;

    // Apply inverse mapping to produce 112x112 aligned output
    let mut aligned = image::RgbImage::new(112, 112);

    for dst_y in 0..112u32 {
        for dst_x in 0..112u32 {
            let dx = dst_x as f32 - dst_mean[0];
            let dy = dst_y as f32 - dst_mean[1];

            // Inverse transform: source = inv(R*s) * (dst - dst_mean) + src_mean
            let inv_scale = 1.0 / scale;
            let src_x = inv_scale * (rot[0] * dx + rot[1] * dy) + src_mean[0];
            let src_y = inv_scale * (-rot[1] * dx + rot[0] * dy) + src_mean[1];

            // Bilinear interpolation
            let px = bilinear_sample(&img, src_x, src_y);
            aligned.put_pixel(dst_x, dst_y, image::Rgb(px));
        }
    }

    Ok(aligned.into_raw())
}

/// Prepare an aligned 112x112 face as a NCHW tensor (for ArcFace/age models).
///
/// Applies standard InsightFace normalization: (pixel - 127.5) / 127.5
pub fn prepare_recognition_input(
    aligned_rgb: &[u8],
) -> Result<Array4<f32>, BiometricError> {
    if aligned_rgb.len() != 112 * 112 * 3 {
        return Err(BiometricError::ImageProcessing(format!(
            "expected 112x112x3={} bytes, got {}",
            112 * 112 * 3,
            aligned_rgb.len()
        )));
    }

    let mut tensor = Array4::<f32>::zeros((1, 3, 112, 112));
    for y in 0..112 {
        for x in 0..112 {
            let idx = (y * 112 + x) * 3;
            tensor[[0, 0, y, x]] = (aligned_rgb[idx] as f32 - 127.5) / 127.5;
            tensor[[0, 1, y, x]] = (aligned_rgb[idx + 1] as f32 - 127.5) / 127.5;
            tensor[[0, 2, y, x]] = (aligned_rgb[idx + 2] as f32 - 127.5) / 127.5;
        }
    }

    Ok(tensor)
}

/// Compute L2-normalized 512-d embedding vector from raw model output
pub fn normalize_embedding(embedding: &[f32]) -> Vec<f32> {
    let norm: f32 = embedding.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm < 1e-10 {
        return embedding.to_vec();
    }
    embedding.iter().map(|v| v / norm).collect()
}

/// Cosine similarity between two L2-normalized embeddings
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

// ========================================================================
// Internal helpers
// ========================================================================

fn compute_means(src: &[[f32; 2]; 5], dst: &[[f32; 2]; 5]) -> ([f32; 2], [f32; 2]) {
    let mut src_mean = [0f32; 2];
    let mut dst_mean = [0f32; 2];
    for i in 0..5 {
        src_mean[0] += src[i][0];
        src_mean[1] += src[i][1];
        dst_mean[0] += dst[i][0];
        dst_mean[1] += dst[i][1];
    }
    src_mean[0] /= 5.0;
    src_mean[1] /= 5.0;
    dst_mean[0] /= 5.0;
    dst_mean[1] /= 5.0;
    (src_mean, dst_mean)
}

/// Estimate rotation (cos, sin) and uniform scale from centered point pairs.
fn estimate_rigid_transform(
    src: &[[f32; 2]; 5],
    dst: &[[f32; 2]; 5],
    src_mean: &[f32; 2],
    dst_mean: &[f32; 2],
) -> ([f32; 2], f32) {
    let mut num_cos = 0.0f32;
    let mut num_sin = 0.0f32;
    let mut denom = 0.0f32;

    for i in 0..5 {
        let sx = src[i][0] - src_mean[0];
        let sy = src[i][1] - src_mean[1];
        let dx = dst[i][0] - dst_mean[0];
        let dy = dst[i][1] - dst_mean[1];

        num_cos += sx * dx + sy * dy;
        num_sin += sx * dy - sy * dx;
        denom += sx * sx + sy * sy;
    }

    if denom < 1e-10 {
        return ([1.0, 0.0], 1.0);
    }

    let cos_theta = num_cos / denom;
    let sin_theta = num_sin / denom;
    let scale = (cos_theta * cos_theta + sin_theta * sin_theta).sqrt();
    let rot = [cos_theta / scale, sin_theta / scale];

    (rot, scale)
}

fn bilinear_sample(img: &image::RgbImage, x: f32, y: f32) -> [u8; 3] {
    let (w, h) = (img.width() as f32, img.height() as f32);
    let x = x.clamp(0.0, w - 1.0);
    let y = y.clamp(0.0, h - 1.0);

    let x0 = x.floor() as u32;
    let y0 = y.floor() as u32;
    let x1 = (x0 + 1).min(img.width() - 1);
    let y1 = (y0 + 1).min(img.height() - 1);

    let fx = x - x0 as f32;
    let fy = y - y0 as f32;

    let p00 = img.get_pixel(x0, y0).0;
    let p10 = img.get_pixel(x1, y0).0;
    let p01 = img.get_pixel(x0, y1).0;
    let p11 = img.get_pixel(x1, y1).0;

    let mut out = [0u8; 3];
    for c in 0..3 {
        let v = (1.0 - fx) * (1.0 - fy) * p00[c] as f32
            + fx * (1.0 - fy) * p10[c] as f32
            + (1.0 - fx) * fy * p01[c] as f32
            + fx * fy * p11[c] as f32;
        out[c] = v.round().clamp(0.0, 255.0) as u8;
    }
    out
}

// ========================================================================
// Image quality metrics
// ========================================================================

/// Results of pixel-level image quality analysis on a face region.
#[derive(Debug, Clone)]
pub struct ImageQualityMetrics {
    /// Sharpness score (0.0–1.0) based on Laplacian variance.
    pub sharpness: f32,
    /// Mean brightness (0.0–1.0) from luminance channel. 0.5 = ideal.
    pub brightness: f32,
    /// RMS contrast (0.0–1.0) of luminance channel.
    pub contrast: f32,
}

/// Compute pixel-level quality metrics on a face crop.
///
/// Operates on raw RGB bytes for the cropped face region.
/// - **Sharpness**: Laplacian variance (discrete 2D Laplacian kernel) mapped to [0,1].
/// - **Brightness**: Mean luminance (BT.601) normalized to [0,1].
/// - **Contrast**: RMS deviation of luminance normalized to [0,1].
pub fn compute_image_quality(
    rgb: &[u8],
    width: u32,
    height: u32,
) -> ImageQualityMetrics {
    let w = width as usize;
    let h = height as usize;
    let npixels = w * h;

    if npixels == 0 || rgb.len() < npixels * 3 {
        return ImageQualityMetrics {
            sharpness: 0.0,
            brightness: 0.0,
            contrast: 0.0,
        };
    }

    // Convert to luminance (BT.601: Y = 0.299R + 0.587G + 0.114B)
    let lum: Vec<f32> = (0..npixels)
        .map(|i| {
            let r = rgb[i * 3] as f32;
            let g = rgb[i * 3 + 1] as f32;
            let b = rgb[i * 3 + 2] as f32;
            0.299 * r + 0.587 * g + 0.114 * b
        })
        .collect();

    // Mean brightness [0,1]
    let mean_lum: f32 = lum.iter().sum::<f32>() / npixels as f32;
    let brightness = mean_lum / 255.0;

    // RMS contrast: std_dev of luminance / 255
    let variance: f32 =
        lum.iter().map(|&l| (l - mean_lum) * (l - mean_lum)).sum::<f32>() / npixels as f32;
    let contrast = (variance.sqrt() / 127.5).min(1.0); // Normalize: max std_dev ≈ 127.5

    // Laplacian variance for sharpness
    // Kernel: [0 -1 0; -1 4 -1; 0 -1 0]
    let mut laplacian_sum = 0.0f64;
    let mut laplacian_count = 0u64;
    for y in 1..h.saturating_sub(1) {
        for x in 1..w.saturating_sub(1) {
            let c = lum[y * w + x];
            let lap = 4.0 * c
                - lum[(y - 1) * w + x]
                - lum[(y + 1) * w + x]
                - lum[y * w + (x - 1)]
                - lum[y * w + (x + 1)];
            laplacian_sum += (lap as f64) * (lap as f64);
            laplacian_count += 1;
        }
    }

    // Map Laplacian variance to [0,1] with a sigmoid-like curve.
    // Empirically, variance < 100 is blurry, > 1000 is sharp.
    let lap_var = if laplacian_count > 0 {
        laplacian_sum / laplacian_count as f64
    } else {
        0.0
    };
    // Logistic sigmoid: 1 / (1 + exp(-k*(x - midpoint)))
    // midpoint=500, k=0.008 gives good separation
    let sharpness = (1.0 / (1.0 + (-0.008 * (lap_var - 500.0)).exp())) as f32;

    ImageQualityMetrics {
        sharpness,
        brightness,
        contrast,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_embedding_unit() {
        let emb = vec![3.0, 4.0];
        let norm = normalize_embedding(&emb);
        assert!((norm[0] - 0.6).abs() < 1e-6);
        assert!((norm[1] - 0.8).abs() < 1e-6);
    }

    #[test]
    fn test_normalize_embedding_zero() {
        let emb = vec![0.0, 0.0, 0.0];
        let norm = normalize_embedding(&emb);
        assert_eq!(norm, vec![0.0, 0.0, 0.0]);
    }

    #[test]
    fn test_cosine_similarity_identical() {
        let a = normalize_embedding(&[1.0, 2.0, 3.0]);
        let sim = cosine_similarity(&a, &a);
        assert!((sim - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = normalize_embedding(&[1.0, 0.0]);
        let b = normalize_embedding(&[0.0, 1.0]);
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-5);
    }

    #[test]
    fn test_detected_face_to_face_bounds() {
        let face = DetectedFace {
            bbox: [100.0, 50.0, 300.0, 250.0],
            score: 0.99,
            landmarks: [[0.0; 2]; 5],
        };
        let bounds = face.to_face_bounds(640, 480);
        assert!((bounds.x - 100.0 / 640.0).abs() < 1e-5);
        assert!((bounds.width - 200.0 / 640.0).abs() < 1e-5);
    }

    #[test]
    fn test_prepare_recognition_input_bad_size() {
        let bad = vec![0u8; 100];
        assert!(prepare_recognition_input(&bad).is_err());
    }

    #[test]
    fn test_prepare_recognition_input_normalization() {
        // All pixels at 127.5 → should normalize to ~0.0
        let aligned = vec![128u8; 112 * 112 * 3];
        let tensor = prepare_recognition_input(&aligned).unwrap();
        let val = tensor[[0, 0, 0, 0]];
        assert!((val - (128.0 - 127.5) / 127.5).abs() < 1e-5);
    }

    #[test]
    fn test_compute_means() {
        let src: [[f32; 2]; 5] = [[0.0, 0.0], [2.0, 0.0], [4.0, 0.0], [0.0, 2.0], [4.0, 2.0]];
        let (src_mean, _) = compute_means(&src, &ARCFACE_REFERENCE_LANDMARKS);
        assert!((src_mean[0] - 2.0).abs() < 1e-5);
        assert!((src_mean[1] - 0.8).abs() < 1e-5);
    }

    #[test]
    fn test_quality_uniform_mid_gray() {
        // Uniform 128 gray → high brightness (~0.5), zero contrast, low sharpness
        let rgb = vec![128u8; 10 * 10 * 3];
        let q = compute_image_quality(&rgb, 10, 10);
        assert!((q.brightness - 128.0 / 255.0).abs() < 0.01);
        assert!(q.contrast < 0.01, "uniform image should have ~0 contrast");
        assert!(q.sharpness < 0.1, "uniform image should be blurry");
    }

    #[test]
    fn test_quality_bright_image() {
        let rgb = vec![250u8; 10 * 10 * 3];
        let q = compute_image_quality(&rgb, 10, 10);
        assert!(q.brightness > 0.9, "bright image brightness should be > 0.9");
    }

    #[test]
    fn test_quality_dark_image() {
        let rgb = vec![10u8; 10 * 10 * 3];
        let q = compute_image_quality(&rgb, 10, 10);
        assert!(q.brightness < 0.1, "dark image brightness should be < 0.1");
    }

    #[test]
    fn test_quality_high_contrast() {
        // Checkerboard pattern = high contrast
        let mut rgb = vec![0u8; 10 * 10 * 3];
        for y in 0..10 {
            for x in 0..10 {
                let v = if (x + y) % 2 == 0 { 255 } else { 0 };
                let idx = (y * 10 + x) * 3;
                rgb[idx] = v;
                rgb[idx + 1] = v;
                rgb[idx + 2] = v;
            }
        }
        let q = compute_image_quality(&rgb, 10, 10);
        assert!(q.contrast > 0.5, "checkerboard should have high contrast: {}", q.contrast);
    }

    #[test]
    fn test_quality_sharp_edges() {
        // Strong vertical edges = sharp
        let mut rgb = vec![0u8; 20 * 20 * 3];
        for y in 0..20 {
            for x in 0..20 {
                let v = if x < 10 { 0 } else { 255 };
                let idx = (y * 20 + x) * 3;
                rgb[idx] = v;
                rgb[idx + 1] = v;
                rgb[idx + 2] = v;
            }
        }
        let q = compute_image_quality(&rgb, 20, 20);
        assert!(q.sharpness > 0.5, "sharp edges should score high: {}", q.sharpness);
    }

    #[test]
    fn test_quality_empty_image() {
        let q = compute_image_quality(&[], 0, 0);
        assert_eq!(q.sharpness, 0.0);
        assert_eq!(q.brightness, 0.0);
        assert_eq!(q.contrast, 0.0);
    }
}
