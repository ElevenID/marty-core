"""Canonical Python surface for the native Marty verification bindings."""

from marty_verification_py._marty_verification import *  # noqa: F401,F403

try:
    from importlib.metadata import version

    __version__ = version("marty-verification-py")
except Exception:  # pragma: no cover - editable development builds
    __version__ = "unknown"
