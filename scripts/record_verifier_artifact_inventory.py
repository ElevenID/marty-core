#!/usr/bin/env python3
"""Inventory the already-built verifier Python release artifacts.

This is an artifact handoff check, not a product qualification or public
registry installation test. It never builds, publishes, or downloads packages.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

WHEEL_COUNT = 5  # Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64.
EXPECTED_PLATFORMS = {
    "linux-x86_64",
    "linux-aarch64",
    "macos-x86_64",
    "macos-arm64",
    "windows-x86_64",
}
NAME = "marty_verification_py"
OUTPUT_NAME = "marty-verification-python-artifact-inventory.json"


def digest_file(path: Path) -> str:
    sha256 = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            sha256.update(block)
    return sha256.hexdigest()


def wheel_platform(filename: str) -> str:
    tag = filename.removesuffix(".whl").rsplit("-", 1)[-1]
    if "manylinux" in tag and tag.endswith("x86_64"):
        return "linux-x86_64"
    if "manylinux" in tag and tag.endswith("aarch64"):
        return "linux-aarch64"
    if tag.startswith("macosx_") and tag.endswith("x86_64"):
        return "macos-x86_64"
    if tag.startswith("macosx_") and tag.endswith("arm64"):
        return "macos-arm64"
    if tag == "win_amd64":
        return "windows-x86_64"
    raise ValueError(f"unexpected verifier wheel platform tag: {tag}")


def build_inventory(assets: Path, tag: str, commit: str) -> dict[str, object]:
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError("tag must be a stable vMAJOR.MINOR.PATCH version")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be a full lowercase Git SHA")
    if not assets.is_dir():
        raise ValueError("release assets directory is missing")

    version = tag[1:]
    # Workspace PyO3 enables abi3-py311 and the package declares >=3.11.
    # A cp311-cp311 wheel would silently narrow installation to Python 3.11.
    wheel_pattern = re.compile(rf"{NAME}-{re.escape(version)}-cp311-abi3-[^-]+\.whl")
    sdist_name = f"{NAME}-{version}.tar.gz"
    candidates = sorted(
        path
        for path in assets.iterdir()
        if path.name.startswith(f"{NAME}-")
        and (path.name.endswith(".whl") or path.name.endswith(".tar.gz"))
    )
    wheels = [path for path in candidates if path.name.endswith(".whl")]
    sdists = [path for path in candidates if path.name.endswith(".tar.gz")]
    if len(wheels) != WHEEL_COUNT or len(sdists) != 1:
        raise ValueError("expected exactly five verifier wheels and one sdist")
    if any(not wheel_pattern.fullmatch(path.name) for path in wheels):
        raise ValueError("verifier wheel name, version, or Python ABI is invalid")
    if sdists[0].name != sdist_name:
        raise ValueError("verifier sdist name or version does not match release tag")
    platforms = [wheel_platform(path.name) for path in wheels]
    if set(platforms) != EXPECTED_PLATFORMS or len(set(platforms)) != WHEEL_COUNT:
        raise ValueError("verifier wheel platform matrix is incomplete or duplicated")

    records: list[dict[str, object]] = []
    for path in candidates:
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError(
                f"verifier artifact is absent, empty, or a symlink: {path.name}"
            )
        record = {
            "filename": path.name,
            "kind": "wheel" if path.name.endswith(".whl") else "sdist",
            "sha256": digest_file(path),
            "size_bytes": path.stat().st_size,
        }
        if path.name.endswith(".whl"):
            record["platform"] = wheel_platform(path.name)
        records.append(record)

    return {
        "schema_version": 1,
        "distribution": "marty-verification-py",
        "qualification": "unqualified-artifact-inventory",
        "tag": tag,
        "commit": commit,
        "artifacts": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    output = args.assets / OUTPUT_NAME
    if output.exists():
        parser.error(f"refusing to overwrite existing inventory: {output}")
    try:
        inventory = build_inventory(args.assets, args.tag, args.commit)
    except ValueError as error:
        parser.error(str(error))
    output.write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
