"""
Adapters for marty-biometrics.

This module contains concrete implementations of the port interfaces.
"""

from marty_biometrics.adapters.rust import RustFaceVerifier

__all__ = ["RustFaceVerifier"]
