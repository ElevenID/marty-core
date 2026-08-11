"""Marty RS — Python bindings for Marty Core cryptographic operations."""

class NativeBackendUnavailable(RuntimeError):
    """The required Marty Rust extension could not be loaded."""


try:
    from marty_rs._marty_rs import *  # noqa: F401,F403
except (ImportError, OSError) as error:
    raise NativeBackendUnavailable(
        "The required Marty Rust backend is unavailable"
    ) from error
