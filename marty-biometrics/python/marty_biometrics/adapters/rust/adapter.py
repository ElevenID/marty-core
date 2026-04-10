"""
Rust FFI adapter for face verification.

This adapter wraps the _marty_biometrics Rust module and converts
between Python types and Rust types.
"""

from typing import List, Optional

from marty_biometrics.ports.types import (
    FaceBounds,
    FaceVerificationRequest,
    FaceVerificationResult,
    FaceQualityAssessment,
    FaceQualityFactors,
    LivenessResult,
    LivenessScores,
    ProviderCapabilities,
)


def _get_rust_module():
    """Lazy import of Rust bindings."""
    try:
        import _marty_biometrics

        return _marty_biometrics
    except ImportError:
        raise RuntimeError(
            "marty-biometrics Rust bindings not available. "
            "Install with: pip install marty-biometrics[ffi] "
            "or build with: cd marty-biometrics && maturin develop --features python"
        )


def _convert_face_bounds(rust_bounds) -> Optional[FaceBounds]:
    """Convert Rust FaceBounds to Python FaceBounds."""
    if rust_bounds is None:
        return None
    return FaceBounds(
        x=rust_bounds.x,
        y=rust_bounds.y,
        width=rust_bounds.width,
        height=rust_bounds.height,
    )


def _convert_liveness(rust_liveness) -> Optional[LivenessResult]:
    """Convert Rust LivenessResult to Python LivenessResult."""
    if rust_liveness is None:
        return None
    return LivenessResult(
        passed=rust_liveness.passed,
        fused_score=rust_liveness.fused_score,
        decision=rust_liveness.decision,
        errors=rust_liveness.errors if rust_liveness.errors else [],
    )


class RustFaceVerifier:
    """
    Face verifier backed by Rust FFI bindings.

    This class wraps the Rust marty-biometrics library and provides
    a Python-friendly interface for face verification.
    """

    def __init__(self, inner):
        """
        Initialize with a Rust FaceVerifier instance.

        Use the class methods `mock()`, `local()`, or `onnx()` to create instances.
        """
        self._inner = inner

    @classmethod
    def mock(cls) -> "RustFaceVerifier":
        """
        Create a mock verifier for testing.

        The mock verifier returns consistent results without
        actually performing biometric verification.

        Returns:
            A RustFaceVerifier configured with the mock provider.
        """
        rust = _get_rust_module()
        inner = rust.FaceVerifier.mock()
        return cls(inner)

    @classmethod
    def local(cls) -> "RustFaceVerifier":
        """
        Create a local verifier.

        The local verifier uses on-device processing for
        biometric verification.

        Returns:
            A RustFaceVerifier configured with the local provider.

        Raises:
            RuntimeError: If the local provider is not available.
        """
        rust = _get_rust_module()
        inner = rust.FaceVerifier.local()
        return cls(inner)

    @classmethod
    def onnx(cls, models_dir: str) -> "RustFaceVerifier":
        """
        Create an ONNX-backed verifier.

        Requires the Rust library to be compiled with the ``onnx`` feature.

        Args:
            models_dir: Path to directory containing ONNX model files.

        Returns:
            A RustFaceVerifier configured with the ONNX provider.

        Raises:
            RuntimeError: If ONNX support is not compiled in.
        """
        rust = _get_rust_module()
        if not hasattr(rust.FaceVerifier, "onnx"):
            raise RuntimeError(
                "ONNX support not available. "
                "Rebuild with: maturin develop --features python,onnx"
            )
        inner = rust.FaceVerifier.onnx(models_dir)
        return cls(inner)

    def capabilities(self) -> ProviderCapabilities:
        """
        Get provider capabilities.

        Returns:
            ProviderCapabilities describing what this provider supports.
        """
        caps = self._inner.capabilities()
        return ProviderCapabilities(
            name=caps.name,
            version=caps.version,
            supports_verification=caps.supports_verification,
            supports_quality=caps.supports_quality,
            supports_templates=caps.supports_templates,
            supports_liveness=caps.supports_liveness,
            offline_capable=caps.offline_capable,
        )

    def verify(self, request: FaceVerificationRequest) -> FaceVerificationResult:
        """
        Verify that probe image matches reference image.

        Args:
            request: Verification request with reference and probe images.

        Returns:
            Verification result with similarity score.

        Raises:
            RuntimeError: If verification could not be performed.
        """
        rust = _get_rust_module()

        # Convert Python request to Rust request
        rust_request = rust.FaceVerificationRequest(
            reference_image=request.reference_image,
            probe_image=request.probe_image,
            threshold=request.threshold,
        )

        # Call Rust verification
        rust_result = self._inner.verify(rust_request)

        # Convert Rust result to Python result
        return FaceVerificationResult(
            verified=rust_result.verified,
            similarity=rust_result.similarity,
            threshold=rust_result.threshold,
            reference_quality=rust_result.reference_quality,
            probe_quality=rust_result.probe_quality,
            processing_time_ms=rust_result.processing_time_ms,
            provider=rust_result.provider,
            liveness=_convert_liveness(rust_result.liveness),
        )

    def assess_quality(self, image: str) -> FaceQualityAssessment:
        """
        Assess image quality for face verification.

        Args:
            image: Base64 encoded image.

        Returns:
            Quality assessment with scores.

        Raises:
            RuntimeError: If assessment could not be performed.
        """
        rust_result = self._inner.assess_quality(image)

        return FaceQualityAssessment(
            overall_score=rust_result.overall_score,
            face_detected=rust_result.face_detected,
            face_count=rust_result.face_count,
            face_bounds=_convert_face_bounds(rust_result.face_bounds),
            factors=FaceQualityFactors(
                sharpness=rust_result.sharpness,
                brightness=rust_result.brightness,
                contrast=rust_result.contrast,
                face_size=rust_result.face_size,
                pose=rust_result.pose,
            ),
        )

    def extract_template(self, image: str):
        """Extract a face template from an image."""
        return self._inner.extract_template(image)

    def compare_templates(self, reference, probe) -> float:
        """Compare two face templates, returning a similarity score."""
        return self._inner.compare_templates(reference, probe)

    def estimate_age(self, image: str):
        """Estimate the age of the subject in the image."""
        return self._inner.estimate_age(image)

    def detect_passive_liveness(self, frames: List[str]):
        """Passive liveness detection from multiple frames."""
        return self._inner.detect_passive_liveness(frames)

    def detect_deepfake(self, image: str):
        """Deepfake / synthetic face analysis."""
        return self._inner.detect_deepfake(image)

    def match_face_to_document(self, selfie: str, document_photo: str):
        """Match a selfie against a document photo."""
        return self._inner.match_face_to_document(selfie, document_photo)
