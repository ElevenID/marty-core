"""
Marty Biometrics - Biometric verification for the Marty ecosystem.

This package provides face verification capabilities with a pluggable
provider architecture. It follows a hexagonal (ports and adapters)
architecture pattern.

Usage:
    from marty_biometrics import IFaceVerifier, FaceVerificationRequest
    from marty_biometrics.adapters.rust import RustFaceVerifier

    verifier = RustFaceVerifier.mock()
    request = FaceVerificationRequest(
        reference_image="base64_encoded_image",
        probe_image="base64_encoded_live_capture",
        threshold=0.7,
    )
    result = verifier.verify(request)
    print(f"Verified: {result.verified}, Similarity: {result.similarity}")
"""

from marty_biometrics.ports import (
    FaceVerificationRequest,
    FaceVerificationResult,
    FaceQualityAssessment,
    ProviderCapabilities,
    IFaceVerifier,
)

__all__ = [
    # Types
    "FaceVerificationRequest",
    "FaceVerificationResult",
    "FaceQualityAssessment",
    "ProviderCapabilities",
    # Interfaces
    "IFaceVerifier",
]

__version__ = "0.1.0"


def get_rust_bindings():
    """
    Lazy import of Rust bindings.

    Returns:
        The _marty_biometrics module.

    Raises:
        RuntimeError: If the Rust bindings are not available.
    """
    try:
        import _marty_biometrics

        return _marty_biometrics
    except ImportError:
        raise RuntimeError(
            "marty-biometrics Rust bindings not available. "
            "Install with: pip install marty-biometrics[ffi] "
            "or build with: cd marty-biometrics && maturin develop --features python"
        )
