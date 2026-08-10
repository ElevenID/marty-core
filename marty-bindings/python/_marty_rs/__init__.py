"""Canonical Python surface for the Marty credential native bindings."""

from marty_rs._marty_rs import *  # noqa: F401,F403

try:
    from importlib.metadata import version

    __version__ = version("marty-rs")
except Exception:  # pragma: no cover - editable development builds
    __version__ = "unknown"
