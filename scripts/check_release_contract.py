#!/usr/bin/env python3
"""Check release metadata and the append-only release-asset policy."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_EXTENSIONS = (
    "marty-bindings",
    "marty-biometrics",
    "marty-verification",
    "marty-iso18013",
)
RELEASE_DELETION_PATTERNS = (
    re.compile(r"\bdeleteReleaseAsset\b", re.IGNORECASE),
    re.compile(r"\bdelete_release_asset\b", re.IGNORECASE),
    re.compile(r"\bdeleteRelease\b", re.IGNORECASE),
    re.compile(r"\bdelete_release\b", re.IGNORECASE),
    re.compile(r"\bgh\s+release\s+delete\b", re.IGNORECASE),
    re.compile(
        r"(?:-X|--request)\s+DELETE[^\r\n]*(?:/releases(?:/|\b)|release[-_ ]assets?)",
        re.IGNORECASE,
    ),
    re.compile(r"\bDELETE\s+/repos/[^\r\n]+/releases(?:/|\b)", re.IGNORECASE),
)


def load_toml(path: Path) -> dict[str, object]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def cargo_version_source(package_dir: Path) -> str | None:
    cargo = load_toml(package_dir / "Cargo.toml")
    package = cargo.get("package")
    if not isinstance(package, dict):
        return None

    version = package.get("version")
    if isinstance(version, str) and version:
        return version
    if isinstance(version, dict) and version.get("workspace") is True:
        workspace = load_toml(ROOT / "Cargo.toml").get("workspace")
        if not isinstance(workspace, dict):
            return None
        workspace_package = workspace.get("package")
        if not isinstance(workspace_package, dict):
            return None
        workspace_version = workspace_package.get("version")
        if isinstance(workspace_version, str) and workspace_version:
            return f"workspace:{workspace_version}"
    return None


def check_python_versions() -> list[str]:
    errors: list[str] = []
    for package_name in PYTHON_EXTENSIONS:
        package_dir = ROOT / package_name
        pyproject = load_toml(package_dir / "pyproject.toml")
        project = pyproject.get("project")
        build_system = pyproject.get("build-system")
        tool = pyproject.get("tool")
        maturin = tool.get("maturin") if isinstance(tool, dict) else None

        if not isinstance(project, dict):
            errors.append(f"{package_name}: missing [project]")
            continue
        if "version" in project:
            errors.append(f"{package_name}: [project].version must not be hard-coded")
        dynamic = project.get("dynamic")
        if not isinstance(dynamic, list) or "version" not in dynamic:
            errors.append(f'{package_name}: [project].dynamic must include "version"')
        if (
            not isinstance(build_system, dict)
            or build_system.get("build-backend") != "maturin"
        ):
            errors.append(f"{package_name}: build backend must be Maturin")
        if not isinstance(maturin, dict):
            errors.append(f"{package_name}: missing [tool.maturin]")
        if cargo_version_source(package_dir) is None:
            errors.append(
                f"{package_name}: Cargo.toml has no resolvable package version"
            )
    return errors


def check_release_asset_policy() -> list[str]:
    errors: list[str] = []
    workflow_dir = ROOT / ".github" / "workflows"
    workflows = sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))
    for workflow in workflows:
        contents = workflow.read_text(encoding="utf-8")
        for pattern in RELEASE_DELETION_PATTERNS:
            if pattern.search(contents):
                errors.append(
                    f"{workflow.relative_to(ROOT)}: release deletion operation matches "
                    f"{pattern.pattern!r}"
                )
        if re.search(r"\bmethod:\s*DELETE\b", contents, re.IGNORECASE) and re.search(
            r"/releases(?:/|\b)", contents, re.IGNORECASE
        ):
            errors.append(
                f"{workflow.relative_to(ROOT)}: DELETE request targets the GitHub Releases API"
            )
    return errors


def main() -> int:
    errors = [*check_python_versions(), *check_release_asset_policy()]
    if errors:
        for error in errors:
            print(f"release-contract: {error}", file=sys.stderr)
        return 1

    resolved = ", ".join(
        f"{name}={cargo_version_source(ROOT / name)}" for name in PYTHON_EXTENSIONS
    )
    print(f"release-contract: Cargo-derived Python versions verified ({resolved})")
    print("release-contract: workflows contain no release-asset deletion operations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
