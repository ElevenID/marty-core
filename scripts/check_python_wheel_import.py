#!/usr/bin/env python3
"""Import a built Marty wheel's native extension and reject Python-only shells."""

from __future__ import annotations

import argparse
import importlib
import importlib.machinery
from pathlib import Path


EXTENSION_MODULES = {
    "marty-bindings": "marty_rs._marty_rs",
    "marty-biometrics": "marty_biometrics._marty_biometrics",
    "marty-iso18013": "marty_iso18013",
    "marty-verification": "marty_verification_py._marty_verification",
}


def import_native_extension(package: str) -> Path:
    """Import the package's native module and return its extension path."""
    try:
        module_name = EXTENSION_MODULES[package]
    except KeyError as error:
        choices = ", ".join(sorted(EXTENSION_MODULES))
        raise ValueError(
            f"unknown wheel package {package!r}; expected one of {choices}"
        ) from error

    module = importlib.import_module(module_name)
    location = getattr(module, "__file__", None)
    if not isinstance(location, str) or not location:
        raise RuntimeError(f"{module_name} did not expose an extension module path")
    if not any(
        location.endswith(suffix) for suffix in importlib.machinery.EXTENSION_SUFFIXES
    ):
        raise RuntimeError(f"{module_name} resolved to non-native module {location}")
    return Path(location).resolve()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", choices=sorted(EXTENSION_MODULES))
    args = parser.parse_args()
    location = import_native_extension(args.package)
    print(f"wheel-import: {args.package} loaded {location}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
