"""
Rust adapter for face verification.

This module provides a Python wrapper around the Rust FFI bindings.
"""

from marty_biometrics.adapters.rust.adapter import RustFaceVerifier

__all__ = ["RustFaceVerifier"]
