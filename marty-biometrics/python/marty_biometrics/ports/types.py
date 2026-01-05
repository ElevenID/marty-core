"""
Data types for biometric verification.

These types mirror the Rust types in marty-biometrics and are used
throughout the Python API.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class LivenessMode(Enum):
    """Supported liveness execution modes."""

    UNKNOWN = "Unknown"
    ON_DEVICE = "OnDevice"
    NETWORK = "Network"


class LivenessStepType(Enum):
    """Types of liveness challenge steps."""

    UNKNOWN = "Unknown"
    HEAD_POSE = "HeadPose"
    BLINK = "Blink"
    PHRASE = "Phrase"


@dataclass
class FaceBounds:
    """Face bounding box (normalized 0.0 - 1.0)."""

    x: float
    y: float
    width: float
    height: float


@dataclass
class FaceQualityFactors:
    """Face quality factors."""

    sharpness: float
    """Sharpness/blur (0.0 - 1.0)."""

    brightness: float
    """Brightness (0.0 - 1.0, 0.5 = ideal)."""

    contrast: float
    """Contrast (0.0 - 1.0)."""

    face_size: float
    """Face size relative to image (0.0 - 1.0)."""

    pose: float
    """Head pose quality (0.0 - 1.0, 1.0 = frontal)."""


@dataclass
class LivenessStep:
    """Individual liveness step definition."""

    step_id: str
    """Unique step identifier."""

    step_type: LivenessStepType
    """Type of challenge."""

    prompt: Optional[str] = None
    """User-facing prompt."""

    pose_direction: Optional[str] = None
    """Direction for head pose (e.g., 'left', 'right', 'up', 'down')."""

    time_limit_ms: Optional[int] = None
    """Time limit for completing step."""


@dataclass
class LivenessChallenge:
    """Signed liveness challenge metadata passed from the caller."""

    challenge_id: str
    """Unique challenge identifier."""

    nonce: str
    """Random nonce for replay protection."""

    session_id: str
    """Session identifier."""

    steps: list[LivenessStep]
    """Challenge steps to complete."""

    issued_at: str
    """When challenge was issued (ISO 8601)."""

    expires_at: str
    """When challenge expires (ISO 8601)."""

    signature: str
    """Cryptographic signature over challenge data."""

    preferred_mode: Optional[LivenessMode] = None
    """Preferred execution mode."""

    allow_network_fallback: bool = False
    """Allow fallback to network mode."""

    accessibility_mode: bool = False
    """Enable accessibility adjustments."""


@dataclass
class LivenessScores:
    """Component scores for liveness."""

    pad_score: float
    """Presentation attack detection score."""

    pose_score: float
    """Head pose verification score."""

    speech_score: float
    """Speech verification score (for voice challenges)."""

    voice_spoof_score: float
    """Voice spoof detection score."""

    av_sync_score: float
    """Audio-visual synchronization score."""


@dataclass
class LivenessThresholds:
    """Thresholds applied to each component and fused decision."""

    min_pad_score: float
    min_pose_score: float
    min_speech_score: float
    min_voice_spoof_score: float
    min_av_sync_score: float
    fused_threshold: float


@dataclass
class LivenessResult:
    """Result from a liveness evaluation."""

    passed: bool
    """Whether liveness check passed."""

    fused_score: float
    """Fused score from all components."""

    scores: Optional[LivenessScores] = None
    """Individual component scores."""

    thresholds: Optional[LivenessThresholds] = None
    """Thresholds used for decision."""

    mode_used: Optional[LivenessMode] = None
    """Mode used for evaluation."""

    errors: list[str] = field(default_factory=list)
    """Any errors encountered."""

    decision: Optional[str] = None
    """Decision rationale."""

    audit_clip_ttl_seconds: Optional[int] = None
    """TTL for audit clip if retained."""


@dataclass
class FaceVerificationRequest:
    """Face verification request."""

    reference_image: str
    """Reference image (from credential, base64 encoded)."""

    probe_image: str
    """Probe image (live capture, base64 encoded)."""

    threshold: Optional[float] = None
    """Minimum similarity threshold (0.0 - 1.0)."""

    liveness_challenge: Optional[LivenessChallenge] = None
    """Optional liveness challenge metadata."""

    preferred_liveness_mode: Optional[LivenessMode] = None
    """Preferred liveness mode (on-device vs network)."""

    allow_network_fallback: bool = False
    """Allow fallback to alternate mode if preferred mode unavailable."""

    accessibility_mode: bool = False
    """Enable accessibility adjustments."""

    retain_audit_clip: bool = False
    """Request retention of a short audit clip."""

    audit_clip_ttl_seconds: Optional[int] = None
    """Optional TTL for audit clip retention (seconds)."""


@dataclass
class FaceVerificationResult:
    """Face verification result."""

    verified: bool
    """Verification passed."""

    similarity: float
    """Similarity score (0.0 - 1.0)."""

    threshold: float
    """Threshold used."""

    processing_time_ms: int
    """Processing time in milliseconds."""

    provider: str
    """Provider used."""

    reference_quality: Optional[float] = None
    """Reference face quality score (0.0 - 1.0)."""

    probe_quality: Optional[float] = None
    """Probe face quality score (0.0 - 1.0)."""

    liveness: Optional[LivenessResult] = None
    """Liveness decision and component scores (if evaluated)."""


@dataclass
class FaceQualityAssessment:
    """Face quality assessment."""

    overall_score: float
    """Overall quality score (0.0 - 1.0)."""

    face_detected: bool
    """Face detected."""

    face_count: int
    """Number of faces detected."""

    factors: FaceQualityFactors
    """Individual quality factors."""

    face_bounds: Optional[FaceBounds] = None
    """Face position (normalized bounding box)."""


@dataclass
class ProviderCapabilities:
    """Biometric provider capabilities."""

    name: str
    """Provider name."""

    version: str
    """Provider version."""

    supports_verification: bool
    """Supports 1:1 verification."""

    supports_quality: bool
    """Supports quality assessment."""

    supports_templates: bool
    """Supports template extraction."""

    supports_liveness: bool
    """Supports liveness detection."""

    offline_capable: bool
    """Works offline."""
