"""
Face verifier interface (port).

This module defines the abstract interface for face verification providers.
Adapters implement this interface to provide different verification backends.
"""

from typing import List, Protocol

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

    def extract_template(self, image: str):
        """Extract a face template from an image."""
        ...

    def compare_templates(self, reference, probe) -> float:
        """Compare two face templates, returning a similarity score."""
        ...

    def estimate_age(self, image: str):
        """Estimate the age of the subject in the image."""
        ...

    def detect_passive_liveness(self, frames: List[str]):
        """Passive liveness detection from multiple frames."""
        ...

    def detect_deepfake(self, image: str):
        """Deepfake / synthetic face analysis."""
        ...

    def match_face_to_document(self, selfie: str, document_photo: str):
        """Match a selfie against a document photo."""
        ...
