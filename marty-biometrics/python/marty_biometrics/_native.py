"""Single lazy-loading boundary for the packaged biometrics extension."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType


def get_rust_bindings() -> ModuleType:
    """Load the extension from its package-relative Maturin location."""
    try:
        return import_module("._marty_biometrics", package="marty_biometrics")
    except (ImportError, OSError) as error:
        raise RuntimeError(
            "marty-biometrics Rust bindings not available. "
            "Install with: pip install marty-biometrics[ffi] "
            "or build with: cd marty-biometrics && maturin develop --features python"
        ) from error
