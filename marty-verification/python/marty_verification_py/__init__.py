"""
marty-verification-py - Python bindings for marty-verification

Provides cryptographic verification, Open Badges, mDoc/mDL, eMRTD, 
and certificate operations through Rust FFI.
"""

from ._marty_verification import (
    # Open Badges
    open_badge_ob2_issue,
    open_badge_ob2_verify,
    open_badge_ob3_issue,
    open_badge_ob3_verify,
)

# Try to import ZK verification if available
try:
    from ._marty_verification import verify_age_zkp
    _has_zkp = True
except ImportError:
    verify_age_zkp = None
    _has_zkp = False

__version__ = "0.1.0"

__all__ = [
    # Open Badges
    "open_badge_ob2_issue",
    "open_badge_ob2_verify",
    "open_badge_ob3_issue",
    "open_badge_ob3_verify",
]

if _has_zkp:
    __all__.append("verify_age_zkp")
