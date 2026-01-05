"""
Face verifier interface (port).

This module defines the abstract interface for face verification providers.
Adapters implement this interface to provide different verification backends.
"""

from typing import Protocol

from marty_biometrics.ports.types import (
    FaceVerificationRequest,
    FaceVerificationResult,
    FaceQualityAssessment,
    ProviderCapabilities,
)


class IFaceVerifier(Protocol):
    """
    Face verification provider interface.

    Implement this protocol to create a new biometric provider adapter.
    """

    def capabilities(self) -> ProviderCapabilities:
        """
        Get provider capabilities.

        Returns:
            ProviderCapabilities describing what this provider supports.
        """
        ...

    def verify(self, request: FaceVerificationRequest) -> FaceVerificationResult:
        """
        Verify that probe image matches reference image.

        Args:
            request: Verification request with reference and probe images.

        Returns:
            Verification result with similarity score.

        Raises:
            BiometricError: If verification could not be performed.
        """
        ...

    def assess_quality(self, image: str) -> FaceQualityAssessment:
        """
        Assess image quality for face verification.

        Args:
            image: Base64 encoded image.

        Returns:
            Quality assessment with scores.

        Raises:
            BiometricError: If assessment could not be performed.
        """
        ...
