"""
Rust FFI adapter for face verification.

This adapter wraps the _marty_biometrics Rust module and converts
between Python types and Rust types.
"""

from typing import Optional

from marty_biometrics.ports.types import (
    FaceVerificationRequest,
    FaceVerificationResult,
    FaceQualityAssessment,
    FaceQualityFactors,
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


class RustFaceVerifier:
    """
    Face verifier backed by Rust FFI bindings.

    This class wraps the Rust marty-biometrics library and provides
    a Python-friendly interface for face verification.
    """

    def __init__(self, inner):
        """
        Initialize with a Rust FaceVerifier instance.

        Use the class methods `mock()` or `local()` to create instances.
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
            liveness=None,  # TODO: Convert liveness result
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
            face_bounds=None,  # TODO: Convert face bounds
            factors=FaceQualityFactors(
                sharpness=rust_result.sharpness,
                brightness=rust_result.brightness,
                contrast=rust_result.contrast,
                face_size=rust_result.face_size,
                pose=rust_result.pose,
            ),
        )
