#!/usr/bin/env python3
"""Check release metadata and the append-only release-asset policy."""

from __future__ import annotations

import hashlib
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


def check_native_build_cache_scope(workflow_text: str | None = None) -> list[str]:
    contents = (
        workflow_text
        if workflow_text is not None
        else (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    sccache_requirements = (
        "mozilla-actions/sccache-action@fc920bf0ec8de6ee65d409111f7ec508035751ba",
        "RUSTC_WRAPPER: sccache",
        'SCCACHE_GHA_ENABLED: "true"',
    )
    if all(requirement in contents for requirement in sccache_requirements):
        return []
    target_key = next(
        (line.strip() for line in contents.splitlines() if "cargo-build-target" in line),
        "",
    )
    required_contexts = ("runner.os", "runner.arch", "env.RUSTUP_TOOLCHAIN")
    missing = [context for context in required_contexts if context not in target_key]
    if not target_key:
        return [
            ".github/workflows/ci.yml: missing a pinned sccache configuration or "
            "Cargo target cache key"
        ]
    if missing:
        return [
            ".github/workflows/ci.yml: Cargo target cache must be scoped by OS, "
            f"architecture, and Rust toolchain; missing {', '.join(missing)}"
        ]
    return []


def _workflow_step_blocks(job_block: str) -> list[str]:
    starts = list(re.finditer(r"^      - \S", job_block, re.MULTILINE))
    return [
        job_block[
            match.start() : starts[index + 1].start()
            if index + 1 < len(starts)
            else len(job_block)
        ]
        for index, match in enumerate(starts)
    ]


def _yaml_step_key_pattern(key: str) -> str:
    escaped = re.escape(key)
    return rf'(?:{escaped}|"{escaped}"|\'{escaped}\')\s*:'


def _has_escaped_yaml_mapping_key(block: str) -> bool:
    return re.search(
        r'^\s*(?:-\s+)?"[^"\r\n]*\\[^"\r\n]*"\s*:',
        block,
        re.MULTILINE,
    ) is not None


def _step_has_key(step: str, key: str) -> bool:
    return re.search(
        rf"^(?:      - |        ){_yaml_step_key_pattern(key)}\s*",
        step,
        re.MULTILINE,
    ) is not None


def _step_mapping_has_exact_value(
    step: str, mapping: str, key: str, value: str
) -> bool:
    lines = step.splitlines()
    mapping_line = f"        {mapping}:"
    expected = f"          {key}: {value}"
    for index, line in enumerate(lines):
        if line != mapping_line:
            continue
        for nested in lines[index + 1 :]:
            if nested.strip() and len(nested) - len(nested.lstrip()) <= 8:
                break
            if nested == expected:
                return True
    return False


def _job_has_key(job: str, key: str) -> bool:
    return re.search(
        rf"^    {_yaml_step_key_pattern(key)}\s*", job, re.MULTILINE
    ) is not None


def _step_uses_action(step: str, action: str) -> bool:
    uses_action = re.search(
        rf"^(?:      - |        ){_yaml_step_key_pattern('uses')}"
        rf"\s*{re.escape(action)}\s*$",
        step,
        re.MULTILINE,
    )
    return (
        uses_action is not None
        and not _step_has_key(step, "run")
        and not _step_has_key(step, "if")
    )


def _step_action_value(step: str) -> str | None:
    action = re.search(
        rf"^(?:      - |        ){_yaml_step_key_pattern('uses')}\s*([^\s#]+)\s*$",
        step,
        re.MULTILINE,
    )
    return action.group(1) if action is not None else None


def _normalized_step(step: str) -> str:
    return "\n".join(line.rstrip() for line in step.splitlines()).rstrip()


def _step_run_commands(step: str) -> list[str]:
    lines = step.splitlines()
    for index, line in enumerate(lines):
        run = re.match(
            rf"^(?:      - |        ){_yaml_step_key_pattern('run')}\s*(.*)$",
            line,
        )
        if run is None:
            continue
        value = run.group(1).strip()
        if value and value[0] not in "|>" and not value.startswith("#"):
            return [value]
        if not value or value[0] not in "|>":
            continue
        commands: list[str] = []
        for command in lines[index + 1 :]:
            stripped = command.strip()
            if stripped and len(command) - len(command.lstrip()) <= 8:
                break
            if stripped and (value[0] == ">" or not stripped.startswith("#")):
                commands.append(stripped)
        return [" ".join(commands)] if value[0] == ">" and commands else commands
    return []


def _step_run_matches(step: str, command_pattern: re.Pattern[str]) -> bool:
    return any(
        command_pattern.match(command) is not None
        for command in _step_run_commands(step)
    )


def _step_runs_cargo(step: str) -> bool:
    return _step_run_matches(step, re.compile(r"\bcargo(?:\s|\+)"))


def _step_runs_cargo_test(step: str) -> bool:
    return _step_run_matches(
        step,
        re.compile(r"\bcargo(?:\+\S+|\s+\+\S+)?\s+test\b"),
    )


def _cargo_test_commands(step: str) -> list[str]:
    cargo_test = re.compile(r"\bcargo(?:\+\S+|\s+\+\S+)?\s+test\b")
    return [
        command
        for command in _step_run_commands(step)
        if cargo_test.match(command) is not None
    ]


WASM_SECURITY_TEST_COMMANDS = {
    "oid4vci-wasm-security": (
        "cargo test --locked -p marty-oid4vci --target wasm32-unknown-unknown "
        "--no-default-features --features verifier --test wasm_crypto_provider "
        "-- --nocapture",
    ),
    "crypto-wasm-security": (
        "cargo test --locked -p marty-crypto --target wasm32-unknown-unknown "
        "--no-default-features --features kdf,symmetric --lib "
        "wasm_hmac_and_hkdf_match_kats_and_wipe_returned_error_state -- --nocapture",
        "cargo test --locked -p marty-crypto --target wasm32-unknown-unknown "
        "--no-default-features --features kdf,symmetric --test wasm_key_derivation "
        "-- --nocapture",
    ),
}
WASM_BINDGEN_INSTALLER_ACTION = (
    "taiki-e/install-action@fcf5432d9f50d67e37ee6e29bdb7a224ff67b4a7"
)
WASM_BINDGEN_TOOL = "wasm-bindgen-cli@0.2.126"
WASM_TEST_RUNNER_ENV = "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER"
WASM_TEST_RUNNER = "wasm-bindgen-test-runner"
WASM_SECURITY_ACTIONS = (
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4",
    "mozilla-actions/sccache-action@fc920bf0ec8de6ee65d409111f7ec508035751ba",
    WASM_BINDGEN_INSTALLER_ACTION,
)
WASM_SECURITY_ACTION_STEPS = (
    """      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false""",
    """      - uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4
        with:
          toolchain: 1.97.1
          targets: wasm32-unknown-unknown""",
    """      - name: Enable compiler cache
        uses: mozilla-actions/sccache-action@fc920bf0ec8de6ee65d409111f7ec508035751ba
        with:
          version: v0.16.0""",
    """      - name: Install wasm-bindgen test runner
        uses: taiki-e/install-action@fcf5432d9f50d67e37ee6e29bdb7a224ff67b4a7
        with:
          tool: wasm-bindgen-cli@0.2.126""",
)
WASM_SECURITY_JOB_PREAMBLES = {
    "oid4vci-wasm-security": """  oid4vci-wasm-security:
    name: OID4VCI WASM Security
    runs-on: ubuntu-latest""",
    "crypto-wasm-security": """  crypto-wasm-security:
    name: Crypto WASM Security
    runs-on: ubuntu-latest""",
}
WASM_SECURITY_JOB_PROPERTIES = {
    "oid4vci-wasm-security": (
        "name: OID4VCI WASM Security",
        "runs-on: ubuntu-latest",
        "steps:",
    ),
    "crypto-wasm-security": (
        "name: Crypto WASM Security",
        "runs-on: ubuntu-latest",
        "steps:",
    ),
}
WASM_SECURITY_TEST_STEPS = {
    "oid4vci-wasm-security": (
        """      - name: Test browser cryptographic provider policy
        env:
          CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER: wasm-bindgen-test-runner
        run: >-
          cargo test --locked -p marty-oid4vci
          --target wasm32-unknown-unknown
          --no-default-features --features verifier
          --test wasm_crypto_provider
          -- --nocapture""",
    ),
    "crypto-wasm-security": (
        """      - name: Test browser key derivation and cleanup
        env:
          CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER: wasm-bindgen-test-runner
        run: |
          cargo test --locked -p marty-crypto --target wasm32-unknown-unknown --no-default-features --features kdf,symmetric --lib wasm_hmac_and_hkdf_match_kats_and_wipe_returned_error_state -- --nocapture
          cargo test --locked -p marty-crypto --target wasm32-unknown-unknown --no-default-features --features kdf,symmetric --test wasm_key_derivation -- --nocapture""",
    ),
}
CI_GATE_SHA256 = "b27d57803fcafb19cf4171fb39101a8fd4cc27bd34de9d57c225b02b4bd46895"
ZKP_NATIVE_SECURITY_JOB_SHA256 = (
    "d230b5ab4c6c5ba18c2a5874332467cb879ff51b84de2d2f95ea73504ac1987e"
)
WASM_SECURITY_WORKFLOW_ENV = """env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1
  RUSTUP_TOOLCHAIN: 1.97.1
  RUSTC_WRAPPER: sccache
  SCCACHE_GHA_ENABLED: "true"
  # Merge-queue and Dependabot refs create large, short-lived cache namespaces.
  # They still read the default/PR cache but do not duplicate compiler objects.
  SCCACHE_GHA_RW_MODE: ${{ (github.event_name == 'merge_group' || github.actor == 'dependabot[bot]') && 'READ_ONLY' || 'READ_WRITE' }}"""
WASM_SECURITY_WORKFLOW_PREFIX = (
    """name: CI

on:
  pull_request:
    branches: [main]
  merge_group:
    types: [checks_requested]
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.event.merge_group.head_sha || github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

permissions:
  contents: read

"""
    + WASM_SECURITY_WORKFLOW_ENV
)


def _workflow_env_block(contents: str) -> str | None:
    env_header = re.search(r"^env:\s*$", contents, re.MULTILINE)
    if env_header is None:
        return None
    next_root_key = re.search(
        r"^[A-Za-z0-9_-]+:\s*", contents[env_header.end() :], re.MULTILINE
    )
    env_end = (
        env_header.end() + next_root_key.start()
        if next_root_key is not None
        else len(contents)
    )
    return _normalized_step(contents[env_header.start() : env_end])


def _workflow_shell_injection_env(contents: str) -> str | None:
    env_header = re.search(r"^env:\s*$", contents, re.MULTILINE)
    if env_header is None:
        return None
    next_root_key = re.search(r"^[A-Za-z0-9_-]+:\s*", contents[env_header.end() :], re.MULTILINE)
    env_end = (
        env_header.end() + next_root_key.start()
        if next_root_key is not None
        else len(contents)
    )
    env_block = contents[env_header.end() : env_end]
    dangerous = re.search(
        r"^  (BASH_ENV|ENV|PATH|CARGO|RUSTC|RUSTUP_HOME|CARGO_HOME|SHELLOPTS):",
        env_block,
        re.MULTILINE,
    )
    return dangerous.group(1) if dangerous is not None else None


def check_wasm_security_cache_setup(workflow_text: str | None = None) -> list[str]:
    contents = (
        workflow_text
        if workflow_text is not None
        else (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    errors: list[str] = []
    jobs_header = re.search(r"^jobs:\s*$", contents, re.MULTILINE)
    job_header = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.MULTILINE)
    matches = list(job_header.finditer(contents))
    if jobs_header is not None:
        noncanonical_job_keys = [
            line
            for line in contents[jobs_header.end() :].splitlines()
            if line.startswith("  ")
            and not line.startswith("    ")
            and line[2:].strip()
            and not line[2:].lstrip().startswith("#")
            and re.fullmatch(r"[A-Za-z0-9_-]+:\s*", line[2:]) is None
        ]
        if noncanonical_job_keys:
            errors.append(
                ".github/workflows/ci.yml: jobs must use canonical plain block keys"
            )
    blocks = {
        match.group(1): contents[
            match.start() : matches[index + 1].start()
            if index + 1 < len(matches)
            else len(contents)
        ]
        for index, match in enumerate(matches)
    }
    pinned_sccache = (
        "mozilla-actions/sccache-action@fc920bf0ec8de6ee65d409111f7ec508035751ba"
    )
    workflow_prefix = (
        _normalized_step(contents[: jobs_header.start()])
        if jobs_header is not None
        else None
    )
    if workflow_prefix != WASM_SECURITY_WORKFLOW_PREFIX:
        errors.append(
            ".github/workflows/ci.yml: WASM security jobs require the exact "
            "approved workflow preamble"
        )
    if jobs_header is not None and re.search(
        r"^(?![ \t#\r\n])\S", contents[jobs_header.end() :], re.MULTILINE
    ):
        errors.append(
            ".github/workflows/ci.yml: WASM security jobs forbid root mappings "
            "after the canonical jobs key"
        )
    if _workflow_env_block(contents) != WASM_SECURITY_WORKFLOW_ENV:
        errors.append(
            ".github/workflows/ci.yml: WASM security jobs require the exact "
            "approved workflow environment"
        )
    shell_injection_env = _workflow_shell_injection_env(contents)
    if shell_injection_env is not None:
        errors.append(
            ".github/workflows/ci.yml: WASM security jobs must not inherit "
            f"workflow shell-injection variable {shell_injection_env}"
        )
    if re.search(
        rf"^{_yaml_step_key_pattern('defaults')}\s*", contents, re.MULTILINE
    ):
        errors.append(
            ".github/workflows/ci.yml: WASM security jobs require the "
            "failure-enforcing workflow default shell"
        )
    for job in ("oid4vci-wasm-security", "crypto-wasm-security"):
        if sum(match.group(1) == job for match in matches) != 1:
            errors.append(
                f".github/workflows/ci.yml: {job} must appear exactly once"
            )
        block = blocks.get(job)
        if block is None:
            errors.append(f".github/workflows/ci.yml: missing required {job} job")
            continue
        if _has_escaped_yaml_mapping_key(block):
            errors.append(
                f".github/workflows/ci.yml: {job} must not use escaped YAML "
                "mapping keys"
            )
            continue
        steps_header = block.find("    steps:")
        job_preamble = _normalized_step(
            block if steps_header < 0 else block[:steps_header]
        )
        if job_preamble != WASM_SECURITY_JOB_PREAMBLES[job]:
            errors.append(
                f".github/workflows/ci.yml: {job} must use its exact approved "
                "job configuration"
            )
        job_properties = tuple(
            line.strip()
            for line in block.splitlines()
            if line.startswith("    ")
            and not line.startswith("     ")
            and line.strip()
            and not line.lstrip().startswith("#")
        )
        if job_properties != WASM_SECURITY_JOB_PROPERTIES[job]:
            errors.append(
                f".github/workflows/ci.yml: {job} must use its exact top-level "
                "job mapping"
            )
        if _job_has_key(block, "if"):
            errors.append(
                f".github/workflows/ci.yml: {job} must run unconditionally"
            )
        if _job_has_key(block, "continue-on-error"):
            errors.append(
                f".github/workflows/ci.yml: {job} must not tolerate test failures"
            )
        if _job_has_key(block, "defaults"):
            errors.append(
                f".github/workflows/ci.yml: {job} must not override its default shell"
            )
        for execution_override in ("container", "services", "env"):
            if _job_has_key(block, execution_override):
                errors.append(
                    f".github/workflows/ci.yml: {job} must not use a job-level "
                    f"{execution_override} override"
                )
        steps = _workflow_step_blocks(block)
        if re.search(r"^      -\s*$", block, re.MULTILINE) or any(
            re.match(r"^      - (?:name|uses|run):", step) is None for step in steps
        ):
            errors.append(
                f".github/workflows/ci.yml: {job} must use canonical "
                "block-style steps"
            )
        observed_run_commands = tuple(
            command for step in steps for command in _step_run_commands(step)
        )
        if observed_run_commands != WASM_SECURITY_TEST_COMMANDS[job]:
            errors.append(
                f".github/workflows/ci.yml: {job} must use its exact approved "
                "Cargo test script"
            )
        observed_actions = tuple(
            action
            for step in steps
            if (action := _step_action_value(step)) is not None
        )
        if observed_actions != WASM_SECURITY_ACTIONS:
            errors.append(
                f".github/workflows/ci.yml: {job} must use its exact approved "
                "action sequence"
            )
        observed_action_steps = tuple(
            _normalized_step(step)
            for step in steps
            if _step_action_value(step) is not None
        )
        if observed_action_steps != WASM_SECURITY_ACTION_STEPS:
            errors.append(
                f".github/workflows/ci.yml: {job} must use its exact approved "
                "action configuration"
            )
        cache_index = next(
            (
                index
                for index, step in enumerate(steps)
                if _step_uses_action(step, pinned_sccache)
            ),
            None,
        )
        cargo_index = next(
            (index for index, step in enumerate(steps) if _step_runs_cargo(step)),
            None,
        )
        cargo_test_indices = [
            index for index, step in enumerate(steps) if _step_runs_cargo_test(step)
        ]
        observed_test_steps = tuple(
            _normalized_step(steps[index]) for index in cargo_test_indices
        )
        if observed_test_steps != WASM_SECURITY_TEST_STEPS[job]:
            errors.append(
                f".github/workflows/ci.yml: {job} must use its exact approved "
                "test-step configuration"
            )
        installer_index = next(
            (
                index
                for index, step in enumerate(steps)
                if _step_uses_action(step, WASM_BINDGEN_INSTALLER_ACTION)
                and _step_mapping_has_exact_value(
                    step, "with", "tool", WASM_BINDGEN_TOOL
                )
            ),
            None,
        )
        if cache_index is None:
            errors.append(
                f".github/workflows/ci.yml: {job} inherits RUSTC_WRAPPER=sccache "
                "without installing pinned sccache"
            )
        elif cargo_index is not None and cache_index > cargo_index:
            errors.append(
                f".github/workflows/ci.yml: {job} must install pinned sccache "
                "before its first cargo command"
            )
        if not cargo_test_indices:
            errors.append(
                f".github/workflows/ci.yml: {job} must execute a cargo test command"
            )
        if installer_index is None:
            errors.append(
                f".github/workflows/ci.yml: {job} must install the pinned "
                "wasm-bindgen test runner"
            )
        elif cargo_test_indices and installer_index > min(cargo_test_indices):
            errors.append(
                f".github/workflows/ci.yml: {job} must install wasm-bindgen "
                "before its first cargo test"
            )
        for cargo_test_index in cargo_test_indices:
            cargo_test_step = steps[cargo_test_index]
            if _step_has_key(cargo_test_step, "if"):
                errors.append(
                    f".github/workflows/ci.yml: {job} must execute every cargo "
                    "test step unconditionally"
                )
            if _step_has_key(cargo_test_step, "continue-on-error"):
                errors.append(
                    f".github/workflows/ci.yml: {job} must not tolerate cargo "
                    "test failures"
                )
            if _step_has_key(cargo_test_step, "shell"):
                errors.append(
                    f".github/workflows/ci.yml: {job} cargo test steps must use "
                    "the failure-enforcing default shell"
                )
            if not _step_mapping_has_exact_value(
                cargo_test_step, "env", WASM_TEST_RUNNER_ENV, WASM_TEST_RUNNER
            ):
                errors.append(
                    f".github/workflows/ci.yml: {job} cargo test steps must use "
                    "the exact wasm-bindgen test runner"
                )
            for command in _cargo_test_commands(cargo_test_step):
                if re.search(r"(?:^|\s)(?:--no-run|--help|--list|-h)(?:\s|=|$)", command):
                    errors.append(
                        f".github/workflows/ci.yml: {job} cargo test commands "
                        "must execute tests"
                    )
                if re.search(r"\|\||[;&]", command):
                    errors.append(
                        f".github/workflows/ci.yml: {job} cargo test commands "
                        "must directly enforce their exit status"
                    )
    if sum(match.group(1) == "ci-gate" for match in matches) != 1:
        errors.append(".github/workflows/ci.yml: ci-gate must appear exactly once")
    ci_gate = blocks.get("ci-gate")
    if ci_gate is None:
        errors.append(".github/workflows/ci.yml: missing required ci-gate job")
    else:
        gate_digest = hashlib.sha256(
            _normalized_step(ci_gate).encode("utf-8")
        ).hexdigest()
        if gate_digest != CI_GATE_SHA256:
            errors.append(
                ".github/workflows/ci.yml: ci-gate must use its exact approved "
                "needs, result bindings, permissions, and assertions"
            )
    return errors


def check_zkp_native_security_tests(workflow_text: str | None = None) -> list[str]:
    """Require the complete native Longfellow regression suite in Marty CI."""
    contents = (
        workflow_text
        if workflow_text is not None
        else (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    job_matches = list(
        re.finditer(r"^  zkp-native-security:\s*$", contents, re.MULTILINE)
    )
    if len(job_matches) != 1:
        return [
            ".github/workflows/ci.yml: zkp-native-security must appear exactly once"
        ]

    start = job_matches[0].start()
    next_job = re.search(
        r"^  [A-Za-z0-9_-]+:\s*$", contents[job_matches[0].end() :], re.MULTILINE
    )
    end = (
        job_matches[0].end() + next_job.start()
        if next_job is not None
        else len(contents)
    )
    block = contents[start:end].replace("\r\n", "\n")
    approved_test_step = """      - name: Test vendored Longfellow security regressions
        run: |
          set -euo pipefail
          cmake -S marty-zkp/vendor/longfellow-zk/lib -B target/longfellow-parser-test -DCMAKE_BUILD_TYPE=Release
          cmake --build target/longfellow-parser-test --target host_decoder_test mdoc_parser_test mdoc_zk_test mso2_test --parallel 2
          require_gtest_count() {
            local binary="$1" expected="$2" log="$3"
            "$binary" --gtest_color=no 2>&1 | tee "$log"
            grep -Fq "[  PASSED  ] $expected tests." "$log"
            if grep -Fq "[  SKIPPED ]" "$log"; then
              return 1
            fi
          }
          require_gtest_count target/longfellow-parser-test/cbor/host_decoder_test 12 target/host_decoder_test.log
          require_gtest_count target/longfellow-parser-test/circuits/mdoc/mdoc_parser_test 9 target/mdoc_parser_test.log
          require_gtest_count target/longfellow-parser-test/circuits/mdoc/mdoc_zk_test 11 target/mdoc_zk_test.log
          require_gtest_count target/longfellow-parser-test/circuits/cbor_parser/mso2_test 4 target/mso2_test.log
"""
    errors: list[str] = []
    if block.count(approved_test_step) != 1:
        errors.append(
            ".github/workflows/ci.yml: zkp-native-security must build and directly "
            "execute the exact approved Longfellow decoder, parser, proof, and MSO tests"
        )
    job_digest = hashlib.sha256(_normalized_step(block).encode("utf-8")).hexdigest()
    if job_digest != ZKP_NATIVE_SECURITY_JOB_SHA256:
        errors.append(
            ".github/workflows/ci.yml: zkp-native-security must use its exact "
            "approved native job mapping, environment, steps, and count assertions"
        )
    if "continue-on-error:" in block or re.search(r"^    if:", block, re.MULTILINE):
        errors.append(
            ".github/workflows/ci.yml: zkp-native-security must unconditionally enforce "
            "native regression test failures"
        )
    required_gate_fragments = (
        "      - zkp-native-security\n",
        "      ZKP_NATIVE_SECURITY: ${{ needs.zkp-native-security.result }}\n",
    )
    normalized_contents = contents.replace("\r\n", "\n")
    if any(fragment not in normalized_contents for fragment in required_gate_fragments):
        errors.append(
            ".github/workflows/ci.yml: CI Gate must require zkp-native-security"
        )
    return errors


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


def check_stable_tag_policy(policy: dict[str, object]) -> list[str]:
    errors: list[str] = []
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
    for item in policy.get("required_workflows", []):
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        event = item.get("event")
        expected_event = (
            "dynamic"
            if path == "dynamic/github-code-scanning/codeql"
            else "workflow_dispatch"
        )
        if event != expected_event:
            errors.append(
                f".github/stable-tag-policy.json: {path} must use {expected_event} evidence"
            )
        if expected_event == "workflow_dispatch" and isinstance(path, str):
            workflow = ROOT / path
            if not workflow.is_file() or "workflow_dispatch:" not in workflow.read_text(
                encoding="utf-8"
            ):
                errors.append(f"{path}: required release gate is not dispatchable")
    return errors


def check_stable_tag_gate() -> list[str]:
    errors: list[str] = []
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    prepare = PREPARE_STABLE_WORKFLOW.read_text(encoding="utf-8")
    policy = json.loads(STABLE_TAG_POLICY.read_text(encoding="utf-8"))
    errors.extend(check_stable_tag_policy(policy))
    for marker in (
        'gh workflow run "$workflow" --ref main',
        "scripts/stable_tag_gate.py check-workflows",
        "scripts/stable_tag_gate.py prepare",
        "git tag -a",
        "git ls-remote --tags",
        'test "$protected_main" = "$COMMIT"',
        "refs/remotes/origin/main^{commit}",
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
        *check_wasm_security_cache_setup(),
        *check_zkp_native_security_tests(),
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
    print("release-contract: WASM security jobs provide their configured Rust wrapper")
    print("release-contract: native ZKP security suite executes every approved binary")
    print(
        "release-contract: checksum manifest excludes itself and verifies listed assets"
    )
    print("release-contract: stable tags require exact-main preparation evidence")
    print("release-contract: temporary capability lifecycle policy is current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
