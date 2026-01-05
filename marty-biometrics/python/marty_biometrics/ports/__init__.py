"""
Ports (interfaces) for marty-biometrics.

This module defines the abstract interfaces (Protocol classes) that
adapters must implement. Following hexagonal architecture, these
ports define the contract between the domain and external systems.
"""

from marty_biometrics.ports.types import (
    FaceVerificationRequest,
    FaceVerificationResult,
    FaceQualityAssessment,
    FaceQualityFactors,
    FaceBounds,
    ProviderCapabilities,
    LivenessChallenge,
    LivenessStep,
    LivenessStepType,
    LivenessMode,
    LivenessResult,
    LivenessScores,
    LivenessThresholds,
)
from marty_biometrics.ports.face_verifier import IFaceVerifier

__all__ = [
    # Types
    "FaceVerificationRequest",
    "FaceVerificationResult",
    "FaceQualityAssessment",
    "FaceQualityFactors",
    "FaceBounds",
    "ProviderCapabilities",
    "LivenessChallenge",
    "LivenessStep",
    "LivenessStepType",
    "LivenessMode",
    "LivenessResult",
    "LivenessScores",
    "LivenessThresholds",
    # Interfaces
    "IFaceVerifier",
]
