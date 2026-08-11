#!/usr/bin/env python3
"""Check release metadata and the append-only release-asset policy."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from datetime import date
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
CAPABILITY_LIFECYCLE = ROOT / "capability-lifecycle.json"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
PREPARE_STABLE_WORKFLOW = ROOT / ".github" / "workflows" / "prepare-stable-tag.yml"
STABLE_TAG_POLICY = ROOT / ".github" / "stable-tag-policy.json"


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


def check_native_build_cache_scope() -> list[str]:
    workflow = ROOT / ".github" / "workflows" / "ci.yml"
    contents = workflow.read_text(encoding="utf-8")
    target_key = next(
        (line.strip() for line in contents.splitlines() if "cargo-build-target" in line),
        "",
    )
    required_contexts = ("runner.os", "runner.arch", "env.RUSTUP_TOOLCHAIN")
    missing = [context for context in required_contexts if context not in target_key]
    if not target_key:
        return [".github/workflows/ci.yml: missing Cargo target cache key"]
    if missing:
        return [
            ".github/workflows/ci.yml: Cargo target cache must be scoped by OS, "
            f"architecture, and Rust toolchain; missing {', '.join(missing)}"
        ]
    return []


def check_release_checksum_policy(workflow_text: str | None = None) -> list[str]:
    contents = (
        workflow_text
        if workflow_text is not None
        else RELEASE_WORKFLOW.read_text(encoding="utf-8")
    )
    errors: list[str] = []
    if "find release-assets -mindepth 2 -type f -print0" not in contents or (
        'destination="release-assets/$(basename "$file")"' not in contents
    ):
        errors.append(
            ".github/workflows/release.yml: release assets must be flattened before "
            "checksumming so downloaded manifest paths resolve"
        )
    if "find . -type f ! -name SHA256SUMS -print0" not in contents:
        errors.append(
            ".github/workflows/release.yml: checksum manifest must exclude itself"
        )
    if "find . -type f -print0" in contents:
        errors.append(
            ".github/workflows/release.yml: unfiltered checksum discovery includes the manifest"
        )
    if "sha256sum --check --strict SHA256SUMS" not in contents:
        errors.append(
            ".github/workflows/release.yml: checksum manifest must verify before publication"
        )
    return errors


def check_stable_tag_gate() -> list[str]:
    errors: list[str] = []
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    prepare = PREPARE_STABLE_WORKFLOW.read_text(encoding="utf-8")
    policy = json.loads(STABLE_TAG_POLICY.read_text(encoding="utf-8"))
    required_paths = {
        item.get("path")
        for item in policy.get("required_workflows", [])
        if isinstance(item, dict)
    }
    expected_paths = {
        ".github/workflows/ci.yml",
        ".github/workflows/open-source-policy.yml",
        ".github/workflows/organization-quality.yml",
        ".github/workflows/license-compliance.yml",
        ".github/workflows/mip-release-wallet.yml",
        "dynamic/github-code-scanning/codeql",
    }
    if policy.get("schema") != "elevenid.stable-tag-preparation/v1":
        errors.append(".github/stable-tag-policy.json: invalid schema")
    if required_paths != expected_paths:
        errors.append(".github/stable-tag-policy.json: required workflow set is incomplete")
    for marker in (
        "scripts/stable_tag_gate.py prepare",
        "git tag -a",
        "git ls-remote --tags",
        "stable-tag-evidence-${{ inputs.tag }}",
        "gh workflow run release.yml --ref",
    ):
        if marker not in prepare:
            errors.append(f"prepare-stable-tag.yml: missing {marker!r}")
    for marker in (
        "scripts/stable_tag_gate.py validate-release",
        "gh run download",
        "actions: read",
        "Run the release workflow from the exact prepared tag ref",
    ):
        if marker not in release:
            errors.append(f"release.yml: missing {marker!r}")
    return errors


def check_capability_lifecycle(as_of: date | None = None) -> list[str]:
    errors: list[str] = []
    today = as_of or date.today()
    try:
        document = json.loads(CAPABILITY_LIFECYCLE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"capability-lifecycle.json: cannot load lifecycle policy: {error}"]

    if document.get("schema") != "elevenid.capability-lifecycle/v1":
        errors.append("capability-lifecycle.json: unsupported or missing schema")
    capabilities = document.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        return [*errors, "capability-lifecycle.json: capabilities must be a non-empty list"]

    identifiers: set[str] = set()
    by_id: dict[str, dict[str, object]] = {}
    for index, capability in enumerate(capabilities):
        prefix = f"capability-lifecycle.json: capabilities[{index}]"
        if not isinstance(capability, dict):
            errors.append(f"{prefix} must be an object")
            continue
        identifier = capability.get("id")
        if not isinstance(identifier, str) or not identifier:
            errors.append(f"{prefix}.id must be a non-empty string")
            continue
        if identifier in identifiers:
            errors.append(f"{prefix}.id duplicates {identifier!r}")
        identifiers.add(identifier)
        by_id[identifier] = capability

        status = capability.get("status")
        if status not in {"current", "temporary", "retired"}:
            errors.append(f"{prefix}.status must be current, temporary, or retired")
        if not isinstance(capability.get("default"), bool):
            errors.append(f"{prefix}.default must be a boolean")
        interfaces = capability.get("public_interfaces")
        if not isinstance(interfaces, list) or not interfaces or not all(
            isinstance(value, str) and value for value in interfaces
        ):
            errors.append(f"{prefix}.public_interfaces must contain non-empty strings")

        if status != "temporary":
            continue
        if capability.get("default") is not False:
            errors.append(f"{prefix}: a temporary capability cannot be the default")
        if not isinstance(capability.get("successor"), str) or not capability.get("successor"):
            errors.append(f"{prefix}.successor is required for a temporary capability")
        tracking_issue = capability.get("tracking_issue")
        if not isinstance(tracking_issue, str) or not re.fullmatch(
            r"https://github\.com/ElevenID/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*",
            tracking_issue,
        ):
            errors.append(f"{prefix}.tracking_issue must be an ElevenID GitHub issue URL")

        dates: dict[str, date] = {}
        for field in ("review_on", "target_removal"):
            value = capability.get(field)
            if not isinstance(value, str):
                errors.append(f"{prefix}.{field} must be an ISO calendar date")
                continue
            try:
                dates[field] = date.fromisoformat(value)
            except ValueError:
                errors.append(f"{prefix}.{field} must be an ISO calendar date")
        if len(dates) == 2:
            if dates["review_on"] > dates["target_removal"]:
                errors.append(f"{prefix}: review_on must not follow target_removal")
            if today > dates["target_removal"]:
                errors.append(
                    f"{prefix}: temporary support expired on {dates['target_removal'].isoformat()}"
                )

    for identifier, capability in by_id.items():
        if capability.get("status") != "temporary":
            continue
        successor = capability.get("successor")
        if isinstance(successor, str) and successor not in by_id:
            errors.append(
                f"capability-lifecycle.json: {identifier} names unknown successor {successor!r}"
            )

    ob2 = by_id.get("open-badges-2")
    if not ob2 or ob2.get("status") != "temporary" or ob2.get("default") is not False:
        errors.append(
            "capability-lifecycle.json: Open Badges 2 must remain an explicit non-default temporary capability"
        )
    ob3 = by_id.get("open-badges-3")
    if not ob3 or ob3.get("status") != "current" or ob3.get("default") is not True:
        errors.append(
            "capability-lifecycle.json: Open Badges 3 must remain the current default capability"
        )
    return errors


def main() -> int:
    errors = [
        *check_python_versions(),
        *check_release_asset_policy(),
        *check_native_build_cache_scope(),
        *check_release_checksum_policy(),
        *check_stable_tag_gate(),
        *check_capability_lifecycle(),
    ]
    if errors:
        for error in errors:
            print(f"release-contract: {error}", file=sys.stderr)
        return 1

    resolved = ", ".join(
        f"{name}={cargo_version_source(ROOT / name)}" for name in PYTHON_EXTENSIONS
    )
    print(f"release-contract: Cargo-derived Python versions verified ({resolved})")
    print("release-contract: workflows contain no release-asset deletion operations")
    print("release-contract: Cargo target caches are platform and toolchain scoped")
    print(
        "release-contract: checksum manifest excludes itself and verifies listed assets"
    )
    print("release-contract: stable tags require exact-main preparation evidence")
    print("release-contract: temporary capability lifecycle policy is current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
