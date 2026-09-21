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

from importlib.metadata import PackageNotFoundError, version

from marty_biometrics._native import get_rust_bindings
from marty_biometrics.ports import (
    FaceQualityAssessment,
    FaceVerificationRequest,
    FaceVerificationResult,
    IFaceVerifier,
    ProviderCapabilities,
)

__all__ = [
    # Types
    "FaceVerificationRequest",
    "FaceVerificationResult",
    "FaceQualityAssessment",
    "ProviderCapabilities",
    # Interfaces
    "IFaceVerifier",
    "get_rust_bindings",
]

try:
    __version__ = version("marty-biometrics")
except PackageNotFoundError:
    __version__ = "unknown"
